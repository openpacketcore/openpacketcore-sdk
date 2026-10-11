//! Bounded scheduling only. These clocks grant no ownership or absence proof.

use std::time::Duration;
use tokio::time::Instant;

/// Fixed, identifier-free observations for automatic cleanup supervision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CleanupProgress {
    /// Saturating number of admitted attempts, including the active attempt.
    pub attempts: u64,
    /// Age of the first failed attempt; another retry never resets this age.
    pub first_failure_age: Option<Duration>,
}
/// Monotonic pacing shared by scoped reset and per-operation convergence.
pub struct CleanupSchedule {
    attempts: u64,
    first_failure: Option<Instant>,
    next: Instant,
}
impl Default for CleanupSchedule {
    fn default() -> Self {
        Self {
            attempts: 0,
            first_failure: None,
            next: Instant::now(),
        }
    }
}
/// A ten-second attempt budget, checked between bounded kernel exchanges.
#[derive(Clone, Copy)]
pub struct CleanupAttempt {
    deadline: Instant,
}
impl CleanupAttempt {
    /// Whether this attempt may begin another bounded exchange. Expiry never
    /// authorizes detachment, key reuse, closure loss or observer publication.
    pub fn has_budget(&self) -> bool {
        Instant::now() < self.deadline
    }
}
impl CleanupSchedule {
    /// Deadline for the next attempt, without granting authority at that time.
    pub fn next_attempt(&self) -> Instant {
        self.next
    }
    /// Begin one attempt after pacing permits it. Returns `None` during delay.
    pub fn begin(&mut self) -> Option<CleanupAttempt> {
        if Instant::now() < self.next {
            return None;
        }
        self.attempts = self.attempts.saturating_add(1);
        Some(CleanupAttempt {
            deadline: Instant::now() + Duration::from_secs(10),
        })
    }
    /// Record failure and schedule another attempt. `jitter` is random input;
    /// it selects the upper half of exponential 100-ms-to-one-second pacing.
    pub fn failed(&mut self, jitter: u64) {
        let now = Instant::now();
        self.first_failure.get_or_insert(now);
        let shift = self.attempts.saturating_sub(1).min(4) as u32;
        let cap = (100_u64 << shift).min(1000);
        let floor = cap / 2;
        self.next = now + Duration::from_millis(floor + jitter % (cap - floor + 1));
    }
    /// Observe attempts and first-failure age without extending any authority.
    pub fn progress(&self) -> CleanupProgress {
        CleanupProgress {
            attempts: self.attempts,
            first_failure_age: self
                .first_failure
                .map(|at| Instant::now().saturating_duration_since(at)),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(start_paused = true)]
    async fn ten_second_budget_never_extends_with_retries() {
        let mut schedule = CleanupSchedule::default();
        let first = schedule.begin().unwrap();
        tokio::time::advance(Duration::from_millis(9_999)).await;
        assert!(first.has_budget());
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(!first.has_budget());
        schedule.failed(0);
        assert!(schedule.begin().is_none());
        tokio::time::advance(Duration::from_millis(50)).await;
        assert!(schedule.begin().unwrap().has_budget());
        assert!(!first.has_budget());
    }
    #[tokio::test(start_paused = true)]
    async fn jitter_is_paced_and_first_failure_age_survives_every_retry() {
        let mut schedule = CleanupSchedule::default();
        let start = Instant::now();
        let mut elapsed = Duration::ZERO;
        for attempt in 1_u64..=10 {
            schedule.begin().unwrap();
            schedule.failed(0);
            let delay = schedule.next_attempt() - Instant::now();
            let cap = (100_u64.saturating_mul(1_u64 << (attempt - 1).min(4))).min(1000);
            assert_eq!(delay, Duration::from_millis(cap / 2));
            assert_eq!(schedule.progress().attempts, attempt);
            assert_eq!(schedule.progress().first_failure_age, Some(elapsed));
            tokio::time::advance(delay).await;
            elapsed += delay;
        }
        assert_eq!(Instant::now() - start, elapsed);
        assert!(elapsed >= Duration::from_secs(3));
    }
}
