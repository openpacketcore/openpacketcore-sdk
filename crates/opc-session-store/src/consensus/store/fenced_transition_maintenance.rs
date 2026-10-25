//! Bounded leader-owned maintenance lane for V2 fenced-transition history.
//!
//! The V2 journal rotates its writable receipt epoch only through one
//! replicated operator maintenance command. Before this lane, an epoch filled
//! to `FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES` and every further binding was
//! refused with `FencedTransitionHistoryFull` until an external maintainer
//! happened to run (#1377 folded #1112). The lane supplies the same existing
//! maintenance command promptly and repeatedly:
//!
//! * one observation per fast tick and one proposal in flight at a time;
//! * a proactive rotation window keeps
//!   [`FENCED_TRANSITION_V2_PREEMPTIVE_ROTATION_HEADROOM`] binding slots free,
//!   so a continuous healthy bind stream reaches the successor before the
//!   active epoch is full;
//! * once the retained-epoch bound is reached, the same command advances the
//!   existing bounded reclaim batches only after the oldest epoch's exact
//!   retention window expires;
//! * exponential back-off while a turn makes no lifecycle progress, so the
//!   lane cannot busy-loop when every retained epoch is still inside its
//!   replay window and therefore genuinely required;
//! * every submission outcome other than store teardown is a bounded skip.
//!
//! The lane changes no replay, idempotency, stale-fence or retirement
//! semantics: it only schedules the pre-existing maintenance command earlier.

// The lane is compiled in every configuration so its scheduling policy and
// tests stay host-testable; on test-control-only builds the driver is not
// spawned, so its helpers are intentionally unreferenced there.
#![allow(dead_code)]

use super::*;

/// Base observation delay for the V2 history-maintenance lane.
const V2_MAINTENANCE_TICK: Duration = Duration::from_millis(250);

/// Maximum back-off after consecutive turns that changed no lifecycle state.
const V2_MAINTENANCE_MAX_BACKOFF: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct V2MaintenanceBackoff {
    delay: Duration,
}

impl Default for V2MaintenanceBackoff {
    fn default() -> Self {
        Self {
            delay: V2_MAINTENANCE_TICK,
        }
    }
}

impl V2MaintenanceBackoff {
    const fn delay(self) -> Duration {
        self.delay
    }

    fn reset(&mut self) {
        *self = Self::default();
    }

    fn grew(self) -> Self {
        Self {
            delay: self
                .delay
                .checked_mul(2)
                .unwrap_or(V2_MAINTENANCE_MAX_BACKOFF)
                .min(V2_MAINTENANCE_MAX_BACKOFF),
        }
    }
}

/// Whether one history state is at a point where the existing maintenance
/// command can rotate a successor or advance a bounded reclaim batch.
fn v2_history_maintenance_due(state: &FencedTransitionV2HistoryState) -> bool {
    let retained_epochs = match (state.active_epoch(), state.retired_through()) {
        (Some(active), Some(retired)) => active.get().saturating_sub(retired.get()),
        // Epoch numbers are one-based and a fresh history has retired_through
        // equal to zero, so the authoritative retained count is the active
        // epoch itself (the applied path computes `active - retired_through`).
        (Some(active), None) => active.get(),
        _ => 0,
    };
    let maximum_retained_epochs =
        u64::try_from(crate::fenced_transition::FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS + 1)
            .unwrap_or(u64::MAX);
    state.bound_entries() >= crate::fenced_transition::fenced_transition_v2_rotation_high_water()
        || retained_epochs >= maximum_retained_epochs
        || state.reclaim_epoch().is_some()
}

/// Whether one completed maintenance turn changed any replicated lifecycle
/// counter. A turn that only resets the projection clock or is a deterministic
/// no-op grows the back-off instead of spinning.
fn v2_maintenance_progressed(
    before: &FencedTransitionV2HistoryState,
    after: &FencedTransitionV2HistoryState,
) -> bool {
    before.generation() != after.generation()
        || before.active_epoch() != after.active_epoch()
        || before.retired_through() != after.retired_through()
        || before.reclaim_epoch() != after.reclaim_epoch()
        || before.bound_entries() != after.bound_entries()
        || before.reclaimed_entries() != after.reclaimed_entries()
}

#[cfg(not(any(test, feature = "test-control")))]
pub(super) fn start(inner: Weak<ConsensusSessionStoreInner>) {
    // The lane runs through the store's public history-state and maintenance
    // methods so it reuses their admission, leadership and deadline paths.
    tokio::spawn(run_store_lane(inner));
}

#[cfg(not(any(test, feature = "test-control")))]
async fn run_store_lane(inner: Weak<ConsensusSessionStoreInner>) {
    let mut backoff = V2MaintenanceBackoff::default();
    loop {
        let Some(inner) = inner.upgrade() else {
            return;
        };
        let store = ConsensusSessionStore {
            inner: Arc::clone(&inner),
        };
        drop(inner);
        // Tick-only scheduling: each due observation is awaited, so at most one
        // maintenance proposal is in flight and no external wake signal is
        // needed or left unarmed.
        tokio::time::sleep(backoff.delay()).await;
        let state = match store.fenced_transition_v2_history_state().await {
            Ok(state) => state,
            Err(_) => {
                backoff = backoff.grew();
                continue;
            }
        };
        if !v2_history_maintenance_due(&state) {
            backoff.reset();
            continue;
        }
        let next = store.maintain_fenced_transition_v2_history(state).await;
        match next {
            Ok(after) if v2_maintenance_progressed(&state, &after) => backoff.reset(),
            Ok(_) | Err(_) => backoff = backoff.grew(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_due_is_derived_from_the_shared_preemptive_window() {
        let high = crate::fenced_transition::fenced_transition_v2_rotation_high_water();
        // A non-initial active epoch below the high-water mark is not due.
        let epoch = crate::FencedTransitionV2HistoryEpoch::new(3).expect("epoch");
        let below =
            crate::FencedTransitionV2HistoryState::new(Some(epoch), None, None, 0, 0, high - 1, 0)
                .expect("below high water");
        assert!(!v2_history_maintenance_due(&below));
        let at = crate::FencedTransitionV2HistoryState::new(Some(epoch), None, None, 0, 0, high, 0)
            .expect("at high water");
        assert!(v2_history_maintenance_due(&at));
        assert!(crate::fenced_transition::fenced_transition_v2_preemptive_rotation_due(high));
        assert!(!crate::fenced_transition::fenced_transition_v2_preemptive_rotation_due(high - 1));
    }

    #[test]
    fn retained_epoch_count_uses_the_active_epoch_when_retired_through_is_zero() {
        // Regression: the authoritative retained count is
        // `active_epoch - retired_through`; with a one-based epoch and
        // `retired_through == None` (zero), active=8 already retains the full
        // eight-epoch window even when the active epoch is below high water.
        let active = crate::FencedTransitionV2HistoryEpoch::new(8).expect("active epoch");
        let full_window =
            crate::FencedTransitionV2HistoryState::new(Some(active), None, None, 0, 0, 1, 0)
                .expect("full retained window");
        assert!(v2_history_maintenance_due(&full_window));
        let seven = crate::FencedTransitionV2HistoryEpoch::new(7).expect("active epoch");
        let below_window =
            crate::FencedTransitionV2HistoryState::new(Some(seven), None, None, 0, 0, 1, 0)
                .expect("below retained window");
        assert!(!v2_history_maintenance_due(&below_window));
    }

    #[test]
    fn backoff_is_bounded_and_resets_on_progress() {
        let mut backoff = V2MaintenanceBackoff::default();
        backoff = backoff.grew();
        backoff = backoff.grew();
        backoff = backoff.grew();
        assert!(backoff.delay() > V2_MAINTENANCE_TICK);
        assert!(backoff.delay() <= V2_MAINTENANCE_MAX_BACKOFF);
        backoff.reset();
        assert_eq!(backoff.delay(), V2_MAINTENANCE_TICK);
    }
}
