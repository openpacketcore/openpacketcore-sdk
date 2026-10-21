//! One non-renewable budget for a local parent/child status exchange.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use super::{
    QUALIFICATION_CONCURRENT_CONTROL_DELIVERY_MILLIS,
    QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MILLIS,
};

/// Deadline for a traffic-status refresh in a child on the parent's host.
///
/// Both processes use the host's monotonic clock, in the same time namespace.
/// Passing an absolute clock value consumes pipe delivery and command-queue
/// time instead of granting a fresh duration when the child receives it.
/// The existing control-delivery allowance remains inside the parent's phase
/// deadline, and the existing watch-reconciliation limit still caps backend work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationTrafficStatusBudget {
    deadline_monotonic_nanos: u64,
}

impl QualificationTrafficStatusBudget {
    /// Derive the child work deadline from the caller's existing phase deadline.
    ///
    /// The monotonic sample precedes the `Instant` sample: time spent sampling
    /// can only shorten the transmitted budget. A missing clock or exhausted
    /// delivery allowance produces an already-expired work budget.
    pub fn from_parent_deadline(parent_deadline: Instant) -> Self {
        let Some(monotonic_now) = monotonic_nanos() else {
            return Self {
                deadline_monotonic_nanos: 0,
            };
        };
        Self::from_samples(
            monotonic_now,
            parent_deadline.saturating_duration_since(Instant::now()),
        )
    }

    fn from_samples(monotonic_now: u64, parent_remaining: Duration) -> Self {
        let work = parent_remaining
            .saturating_sub(Duration::from_millis(
                QUALIFICATION_CONCURRENT_CONTROL_DELIVERY_MILLIS,
            ))
            .min(Duration::from_millis(
                QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MILLIS,
            ));
        Self {
            deadline_monotonic_nanos: u64::try_from(work.as_nanos())
                .ok()
                .and_then(|work| monotonic_now.checked_add(work))
                .unwrap_or(monotonic_now),
        }
    }

    /// Remaining backend time; expired commands must not start a backend call.
    ///
    /// Sample the consumer's local `Instant` before calling this method, then
    /// add the returned duration to that sample. That order cannot move the
    /// local deadline beyond the transmitted one. Even a malformed remote
    /// value cannot grant more than the existing reconciliation allowance.
    pub fn remaining(self) -> Duration {
        monotonic_nanos().map_or(Duration::ZERO, |now| self.remaining_at(now))
    }

    fn remaining_at(self, monotonic_now: u64) -> Duration {
        Duration::from_nanos(self.deadline_monotonic_nanos.saturating_sub(monotonic_now)).min(
            Duration::from_millis(QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MILLIS),
        )
    }
}

#[cfg(unix)]
fn monotonic_nanos() -> Option<u64> {
    let now = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(now.tv_sec)
        .ok()?
        .checked_mul(1_000_000_000)?
        .checked_add(u64::try_from(now.tv_nsec).ok()?)
}

#[cfg(not(unix))]
fn monotonic_nanos() -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traffic_status_budget_consumes_delivery_and_never_renews_at_receive() {
        let started = 10_000_000_000;
        let budget =
            QualificationTrafficStatusBudget::from_samples(started, Duration::from_millis(4_519));
        assert_eq!(budget.remaining_at(started), Duration::from_millis(3_519));
        let wire = serde_json::to_vec(&budget).expect("serialize control budget");
        let received: QualificationTrafficStatusBudget =
            serde_json::from_slice(&wire).expect("receive identical deadline");
        assert_eq!(
            received.remaining_at(started + 519_000_000),
            Duration::from_secs(3)
        );
        assert_eq!(
            received.remaining_at(started + 3_519_000_000),
            Duration::ZERO
        );
        assert_eq!(
            received.remaining_at(started + 4_519_000_000),
            Duration::ZERO
        );
    }

    #[test]
    fn traffic_status_budget_reserves_delivery_at_the_exact_boundary() {
        let started = 10_000_000_000;
        let delivery = Duration::from_millis(QUALIFICATION_CONCURRENT_CONTROL_DELIVERY_MILLIS);
        for remaining in [Duration::ZERO, delivery - Duration::from_nanos(1), delivery] {
            let budget = QualificationTrafficStatusBudget::from_samples(started, remaining);
            assert_eq!(budget.remaining_at(started), Duration::ZERO);
        }
        let budget = QualificationTrafficStatusBudget::from_samples(
            started,
            delivery + Duration::from_nanos(1),
        );
        assert_eq!(budget.remaining_at(started), Duration::from_nanos(1));
        assert_eq!(budget.remaining_at(started + 1), Duration::ZERO);
    }

    #[test]
    fn traffic_status_budget_preserves_the_existing_cap_and_fails_closed_on_overflow() {
        let cap = Duration::from_millis(QUALIFICATION_TRAFFIC_WATCH_RECONCILIATION_MILLIS);
        let budget = QualificationTrafficStatusBudget::from_samples(10, Duration::MAX);
        assert_eq!(budget.remaining_at(10), cap);
        let overflowing = QualificationTrafficStatusBudget::from_samples(u64::MAX, Duration::MAX);
        assert_eq!(overflowing.remaining_at(u64::MAX), Duration::ZERO);
        let malformed = QualificationTrafficStatusBudget {
            deadline_monotonic_nanos: u64::MAX,
        };
        assert_eq!(malformed.remaining_at(0), cap);
    }
}
