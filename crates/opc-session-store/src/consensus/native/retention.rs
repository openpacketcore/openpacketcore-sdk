//! Bounded rolling retention for append-only native sequences.
//!
//! Native state stores one row per append-only sequence for several independent
//! families (keys, ordinary receipts, generic receipts, notifications). Each
//! family has its own hard `MAX_ITEMS` admission cap, but a row that can never
//! be useful again must be retired so a long-lived store does not stop at that
//! cap.
//!
//! This primitive derives a retention floor from the *committed* sequence
//! alone: [`PrefixRetention::floor`] is `sequence - retained`, and
//! [`PrefixRetention::retained_count`] is `min(sequence, retained)`. No local
//! clock, observer state, acknowledgement or delivery tracker participates.
//! Every voter that applied the same committed sequence therefore derives the
//! exact same floor, snapshots already carry the sequence, and no persisted
//! format field is required. A consumer whose cursor is below the floor must
//! resynchronise from the floor: retention is a bounded backlog, not delivery
//! tracking.
//!
//! Families adopt the primitive by deriving the floor from their committed
//! sequence, retiring the front prefix on publication, validating
//! `stored == retained_count` and rendering a typed stale-cursor answer for
//! below-floor readers. Ordinary receipt and key retention can adopt the same
//! exact helper without a new format change.
//!
//! The sequence zero case is deliberate: nothing is retired before the first
//! row, so a fresh store and every existing below-bound state keep floor zero
//! and byte-identical behavior.

use std::io;

/// Production notification backlog retained for watch replay.
///
/// This is a bounded backlog, not delivery tracking: a watcher below the
/// derived floor receives `StoreError::ReplicationLogCursorCompacted` and
/// resynchronises from the returned sequence. The value is deliberately much
/// smaller than the hard `MAX_ITEMS` admission cap so notification retirement
/// bounds resident memory and snapshot work instead of only removing the
/// lifetime stop.
pub(crate) const RETAINED_NOTIFICATIONS: u64 = 65_536;

/// One append-only sequence family's bounded retention window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PrefixRetention {
    retained: u64,
}

impl PrefixRetention {
    pub(super) const fn new(retained: u64) -> Self {
        Self { retained }
    }

    /// Configured backlog size.
    #[cfg(test)]
    pub(super) const fn retained(self) -> u64 {
        self.retained
    }

    /// Number of leading rows retired at this committed sequence.
    ///
    /// Depends only on the committed sequence, so every voter derives the same
    /// floor at the same log index.
    pub(super) const fn floor(self, sequence: u64) -> u64 {
        sequence.saturating_sub(self.retained)
    }

    /// Number of rows that must exist at this committed sequence.
    pub(super) const fn retained_count(self, sequence: u64) -> u64 {
        if sequence < self.retained {
            sequence
        } else {
            self.retained
        }
    }

    /// Raw sequence of the stored row at a zero-based ordinal of the retained
    /// window.
    pub(super) fn sequence(self, ordinal: usize, sequence: u64) -> io::Result<u64> {
        self.floor(sequence)
            .checked_add(ordinal as u64)
            .and_then(|row| row.checked_add(1))
            .ok_or_else(|| invalid("native retention sequence overflow"))
    }

    /// Validate one stored vector against this family's committed sequence.
    #[cfg(test)]
    pub(super) fn validate_count(self, sequence: u64, stored: usize) -> io::Result<()> {
        if u64::try_from(stored).ok() != Some(self.retained_count(sequence)) {
            return Err(invalid("native retained row count differs"));
        }
        Ok(())
    }

    /// Number of candidate rows to retire so exactly `retained_count` remain.
    pub(super) fn retire_count(self, sequence: u64, candidate: usize) -> io::Result<usize> {
        let candidate = u64::try_from(candidate)
            .map_err(|_| invalid("native retention candidate count overflow"))?;
        let retained = self.retained_count(sequence);
        if candidate < retained {
            return Err(invalid("native retention candidate below window"));
        }
        usize::try_from(candidate - retained)
            .map_err(|_| invalid("native retention retire count overflow"))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Notification family retention, with a test-only override so the same
/// production code paths can exercise a floor above zero without publishing
/// 65,536 notifying mutations.
pub(super) fn notification_retention() -> PrefixRetention {
    #[cfg(test)]
    if let Some(retained) = tests_support::retained_override() {
        return PrefixRetention::new(retained);
    }
    PrefixRetention::new(RETAINED_NOTIFICATIONS)
}

#[cfg(test)]
pub(crate) mod tests_support {
    use std::cell::Cell;

    thread_local! {
        // A thread-local override keeps unrelated tests on the production
        // window; native publication runs on the calling test thread.
        static RETAINED: Cell<Option<u64>> = const { Cell::new(None) };
    }

    pub(crate) struct RetentionOverride {
        previous: Option<u64>,
    }

    impl Drop for RetentionOverride {
        fn drop(&mut self) {
            RETAINED.with(|retained| retained.set(self.previous));
        }
    }

    /// Run this thread's native retention window at `retained`.
    ///
    /// The returned guard restores the previous override on drop so a panic
    /// cannot leak the reduced window into later assertions.
    pub(crate) fn override_retained_for_test(retained: u64) -> RetentionOverride {
        assert!(retained > 0, "a test retention window must be positive");
        let previous = RETAINED.with(|current| current.replace(Some(retained)));
        RetentionOverride { previous }
    }

    pub(super) fn retained_override() -> Option<u64> {
        RETAINED.with(Cell::get)
    }
}

#[cfg(test)]
mod tests {
    use super::{notification_retention, PrefixRetention, RETAINED_NOTIFICATIONS};

    #[test]
    fn prefix_retention_derives_a_committed_floor() {
        let retention = PrefixRetention::new(4);
        assert_eq!(retention.floor(0), 0);
        assert_eq!(retention.retained_count(0), 0);
        assert_eq!(retention.floor(3), 0);
        assert_eq!(retention.retained_count(3), 3);
        assert_eq!(retention.floor(4), 0);
        assert_eq!(retention.retained_count(4), 4);
        assert_eq!(retention.floor(5), 1);
        assert_eq!(retention.retained_count(5), 4);
        assert_eq!(retention.floor(1_048_576), 1_048_572);
        assert_eq!(retention.retained_count(1_048_576), 4);
        assert_eq!(retention.floor(u64::MAX), u64::MAX - 4);
        assert_eq!(retention.sequence(0, 5).unwrap(), 2);
        assert_eq!(retention.sequence(3, 5).unwrap(), 5);
        assert!(retention.sequence(usize::MAX, u64::MAX).is_err());
    }

    #[test]
    fn prefix_retention_validates_retained_counts_and_retirement() {
        let retention = PrefixRetention::new(4);
        retention.validate_count(2, 2).unwrap();
        retention.validate_count(5, 4).unwrap();
        retention.validate_count(1_048_576, 4).unwrap();
        assert!(retention.validate_count(5, 3).is_err());
        assert!(retention.validate_count(5, 5).is_err());
        assert_eq!(retention.retire_count(5, 5).unwrap(), 1);
        assert_eq!(retention.retire_count(5, 8).unwrap(), 4);
        assert_eq!(retention.retire_count(2, 2).unwrap(), 0);
        assert!(retention.retire_count(5, 2).is_err());
        assert_eq!(retention.retained(), 4);
        assert_eq!(
            notification_retention().retained(),
            RETAINED_NOTIFICATIONS,
            "the notification family keeps its documented backlog"
        );
        const {
            assert!(
                RETAINED_NOTIFICATIONS <= 1_048_576,
                "the rolling backlog stays inside the hard admission cap"
            );
        }
    }
}
