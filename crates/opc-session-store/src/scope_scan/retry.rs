//! Finite resource-recovery policy for one coherent scope restore.
//!
//! Backoff controls local work only. It never changes authority, claim ownership
//! or a persisted floor, and a completed page does not create a new budget.

use std::{fmt, time::Duration};

const CAUSE_COUNT: usize = 8;
const MAX_PAGE_ROWS: usize = 1_024;

/// A retryable operational fault, distinct from a final item verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeScanRetryCause {
    /// The current operation could not read an available serving node.
    Unavailable,
    /// The client left its retained view idle for too long.
    IdleExpired,
    /// The serving backend restarted and lost its local captures.
    BackendRestarted,
    /// Snapshot installation invalidated the retained capture.
    SnapshotInstalled,
    /// The capture's configuration admission is no longer usable.
    ConfigurationChanged,
    /// No complete item fit within the operation's work budget.
    WorkBudgetExceeded,
    /// Retention capacity is occupied by already admitted views.
    AdmissionPressure,
    /// The retained handle was explicitly closed or lost without a finer cause.
    ViewEnded,
}

impl ScopeScanRetryCause {
    const fn index(self) -> usize {
        match self {
            Self::Unavailable => 0,
            Self::IdleExpired => 1,
            Self::BackendRestarted => 2,
            Self::SnapshotInstalled => 3,
            Self::ConfigurationChanged => 4,
            Self::WorkBudgetExceeded => 5,
            Self::AdmissionPressure => 6,
            Self::ViewEnded => 7,
        }
    }
}

/// Validated recovery budget for the lifetime of one restore operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeScanRetryPolicy {
    max_attempts: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
}

/// Invalid retry configuration is refused before admitting a restore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeScanRetryPolicyError {
    /// At least one bounded recovery attempt must be allowed.
    ZeroAttempts,
    /// Backoff must be positive and its cap at least the initial delay.
    InvalidBackoff,
    /// A page must request between one and 1,024 items.
    InvalidPageLimit,
}

impl fmt::Display for ScopeScanRetryPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZeroAttempts => "scope restore recovery attempts must be positive",
            Self::InvalidBackoff => "scope restore backoff bounds are invalid",
            Self::InvalidPageLimit => "scope restore page limit is invalid",
        })
    }
}

impl std::error::Error for ScopeScanRetryPolicyError {}

impl ScopeScanRetryPolicy {
    /// Construct a bounded retry policy; no delay is an ownership lease.
    pub fn new(
        max_attempts: u32,
        initial_backoff: Duration,
        max_backoff: Duration,
    ) -> Result<Self, ScopeScanRetryPolicyError> {
        if max_attempts == 0 {
            return Err(ScopeScanRetryPolicyError::ZeroAttempts);
        }
        if initial_backoff.is_zero() || initial_backoff > max_backoff {
            return Err(ScopeScanRetryPolicyError::InvalidBackoff);
        }
        Ok(Self {
            max_attempts,
            initial_backoff,
            max_backoff,
        })
    }
}

impl Default for ScopeScanRetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 16,
            initial_backoff: Duration::from_millis(25),
            max_backoff: Duration::from_secs(1),
        }
    }
}

/// Final exhaustion of a restore's recovery budget, with bounded diagnostics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeRestoreStalled {
    cause: ScopeScanRetryCause,
    attempts: u32,
    by_cause: [u32; CAUSE_COUNT],
}

impl ScopeRestoreStalled {
    /// Fault which exhausted the recovery budget.
    pub const fn cause(&self) -> ScopeScanRetryCause {
        self.cause
    }
    /// Total failed attempts across every cause in this restore.
    pub const fn attempts(&self) -> u32 {
        self.attempts
    }
    /// Attempts attributable to one cause, without an unbounded history.
    pub const fn attempts_for(&self, cause: ScopeScanRetryCause) -> u32 {
        self.by_cause[cause.index()]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetryDecision {
    Retry {
        attempt: u32,
        row_limit: usize,
        delay: Duration,
        reopen: bool,
    },
    Stalled(ScopeRestoreStalled),
}

pub(crate) struct RestoreRetryState {
    policy: ScopeScanRetryPolicy,
    row_limit: usize,
    attempts: u32,
    by_cause: [u32; CAUSE_COUNT],
    next_delay: Duration,
    stalled: Option<ScopeRestoreStalled>,
}

impl RestoreRetryState {
    pub(crate) fn new(
        policy: ScopeScanRetryPolicy,
        row_limit: usize,
    ) -> Result<Self, ScopeScanRetryPolicyError> {
        if !(1..=MAX_PAGE_ROWS).contains(&row_limit) {
            return Err(ScopeScanRetryPolicyError::InvalidPageLimit);
        }
        Ok(Self {
            policy,
            row_limit,
            attempts: 0,
            by_cause: [0; CAUSE_COUNT],
            next_delay: policy.initial_backoff,
            stalled: None,
        })
    }

    pub(crate) fn failed(&mut self, cause: ScopeScanRetryCause) -> RetryDecision {
        if let Some(stalled) = self.stalled {
            return RetryDecision::Stalled(stalled);
        }
        self.attempts = self.attempts.saturating_add(1);
        self.by_cause[cause.index()] = self.by_cause[cause.index()].saturating_add(1);
        if self.attempts >= self.policy.max_attempts {
            let stalled = ScopeRestoreStalled {
                cause,
                attempts: self.attempts,
                by_cause: self.by_cause,
            };
            self.stalled = Some(stalled);
            return RetryDecision::Stalled(stalled);
        }
        if cause == ScopeScanRetryCause::WorkBudgetExceeded {
            self.row_limit = (self.row_limit / 2).max(1);
        }
        let delay = self.next_delay;
        self.next_delay = self
            .next_delay
            .saturating_mul(2)
            .min(self.policy.max_backoff);
        RetryDecision::Retry {
            attempt: self.attempts,
            row_limit: self.row_limit,
            delay,
            reopen: matches!(
                cause,
                ScopeScanRetryCause::IdleExpired
                    | ScopeScanRetryCause::BackendRestarted
                    | ScopeScanRetryCause::SnapshotInstalled
                    | ScopeScanRetryCause::ConfigurationChanged
                    | ScopeScanRetryCause::ViewEnded
            ),
        }
    }
}

#[cfg(test)]
#[path = "retry_tests.rs"]
mod tests;
