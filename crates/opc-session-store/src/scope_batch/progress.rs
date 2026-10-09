//! Bounded retry progress and diagnostic completion ages.

use std::time::{Duration, Instant};

use super::SCOPE_BATCH_LANES;

/// Liveness-only decision after a guarded request has definitively failed.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum GuardRetryDecision {
    Delay(Duration),
    Stalled,
}

/// Counts only resolved revision conflicts, never transport uncertainty.
pub(super) struct GuardRetryProgress {
    resolved: u8,
    delay: Duration,
}

impl Default for GuardRetryProgress {
    fn default() -> Self {
        Self {
            resolved: 0,
            delay: Duration::from_millis(25),
        }
    }
}

impl GuardRetryProgress {
    /// The caller must first reconcile or cancel every submitted copy.
    pub(super) fn resolved_conflict(&mut self) -> GuardRetryDecision {
        if self.resolved >= 16 {
            return GuardRetryDecision::Stalled;
        }
        self.resolved += 1;
        if self.resolved == 16 {
            return GuardRetryDecision::Stalled;
        }
        let delay = self.delay;
        self.delay = self.delay.saturating_mul(2).min(Duration::from_secs(1));
        GuardRetryDecision::Delay(delay)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum CompletionAgeError {
    InvalidLane,
    Occupied,
}

#[derive(Clone, Copy)]
struct Observation {
    // The canonical digest binds namespace, stamp, lane, sequence and ID.
    digest: [u8; 32],
    started: Instant,
}

/// One diagnostic interval per occupied lane, independent of durable clocks.
pub(super) struct CompletionAges {
    observations: [Option<Observation>; SCOPE_BATCH_LANES],
}

impl Default for CompletionAges {
    fn default() -> Self {
        Self {
            observations: [None; SCOPE_BATCH_LANES],
        }
    }
}

impl CompletionAges {
    pub(super) fn observe(
        &mut self,
        lane: u8,
        digest: [u8; 32],
        now: Instant,
    ) -> Result<(), CompletionAgeError> {
        let slot = self
            .observations
            .get_mut(usize::from(lane))
            .ok_or(CompletionAgeError::InvalidLane)?;
        match slot {
            Some(before) if before.digest != digest => Err(CompletionAgeError::Occupied),
            Some(_) => Ok(()),
            None => {
                *slot = Some(Observation {
                    digest,
                    started: now,
                });
                Ok(())
            }
        }
    }

    pub(super) fn ack(&mut self, lane: u8, digest: &[u8; 32]) -> bool {
        let Some(slot) = self.observations.get_mut(usize::from(lane)) else {
            return false;
        };
        if slot.as_ref().is_some_and(|entry| &entry.digest == digest) {
            *slot = None;
            true
        } else {
            false
        }
    }

    pub(super) fn ages(&self, now: Instant) -> [Option<Duration>; SCOPE_BATCH_LANES] {
        std::array::from_fn(|lane| {
            self.observations[lane].map(|entry| now.saturating_duration_since(entry.started))
        })
    }
}

#[cfg(test)]
#[path = "progress_tests.rs"]
mod tests;
