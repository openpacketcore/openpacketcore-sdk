//! Activity-based retention for local captures, independent of scope authority.

use std::time::{Duration, Instant};

/// These are the only explicit reasons a live view can be invalidated.
/// Resource pressure is intentionally absent: new admissions wait instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ViewInvalidation {
    BackendRestarted,
    SnapshotInstalled,
    ConfigurationChanged,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ViewState {
    Retained,
    IdleExpired,
    Invalidated(ViewInvalidation),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActivityError {
    ZeroIdleTimeout,
    Ended(ViewState),
    UnbalancedFinish,
    OperationCountOverflow,
}

pub(crate) struct ViewActivity {
    idle_timeout: Duration,
    last_activity: Instant,
    in_flight: usize,
    terminal: Option<ViewState>,
}

impl ViewActivity {
    pub(crate) fn new(idle_timeout: Duration, now: Instant) -> Result<Self, ActivityError> {
        if idle_timeout.is_zero() {
            return Err(ActivityError::ZeroIdleTimeout);
        }
        Ok(Self {
            idle_timeout,
            last_activity: now,
            in_flight: 0,
            terminal: None,
        })
    }

    /// Call at request acceptance, before it waits in the operation queue.
    pub(crate) fn begin(&mut self, now: Instant) -> Result<(), ActivityError> {
        let state = self.state(now);
        if state != ViewState::Retained {
            return Err(ActivityError::Ended(state));
        }
        self.in_flight = self
            .in_flight
            .checked_add(1)
            .ok_or(ActivityError::OperationCountOverflow)?;
        self.last_activity = self.last_activity.max(now);
        Ok(())
    }

    /// Completion and cancellation balance acceptance, even after invalidation.
    pub(crate) fn finish(&mut self, now: Instant) -> Result<(), ActivityError> {
        self.in_flight = self
            .in_flight
            .checked_sub(1)
            .ok_or(ActivityError::UnbalancedFinish)?;
        self.last_activity = self.last_activity.max(now);
        Ok(())
    }

    pub(crate) fn invalidate(&mut self, reason: ViewInvalidation) {
        self.terminal.get_or_insert(ViewState::Invalidated(reason));
    }

    pub(crate) fn idle_age(&self, now: Instant) -> Option<Duration> {
        (self.in_flight == 0 && self.terminal.is_none())
            .then(|| now.saturating_duration_since(self.last_activity))
    }

    pub(crate) fn state(&mut self, now: Instant) -> ViewState {
        if let Some(state) = self.terminal {
            return state;
        }
        if self.in_flight == 0
            && now.saturating_duration_since(self.last_activity) >= self.idle_timeout
        {
            self.terminal = Some(ViewState::IdleExpired);
            return ViewState::IdleExpired;
        }
        ViewState::Retained
    }
}

#[cfg(test)]
#[path = "activity_tests.rs"]
mod tests;
