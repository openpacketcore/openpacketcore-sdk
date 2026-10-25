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
//! below-floor readers. Key retention can adopt the same exact helper without a
//! new format change.
//!
//! Ordinary command receipts are a keyed map rather than an append-only vector,
//! so they use [`OrdinaryReceiptRetention`]: the same committed-state principle
//! with a committed application-sequence activation point and a committed
//! logical-time window. Below activation nothing is retired (byte-identical
//! behavior); once active, an exact retry outside the window receives the typed
//! outcome-unavailable answer instead of re-execution, and a bounded capacity
//! backstop protects the fixed image admission cap.
//!
//! The sequence zero case is deliberate: nothing is retired before the first
//! row, so a fresh store and every existing below-bound state keep floor zero
//! and byte-identical behavior.

use super::Timestamp;
use std::io;

/// Production notification backlog retained for watch replay.
///
/// This is a row-count bound, not a byte budget: each retained notification
/// row keeps its bounded payload and metadata, so the resident notification
/// footprint is at most this many rows. It is a bounded replay backlog, not
/// delivery tracking: a watcher below the derived floor receives
/// `StoreError::ReplicationLogCursorCompacted` and resynchronises from the
/// returned sequence. The value is deliberately much smaller than the hard
/// `MAX_ITEMS` admission cap so notification retirement bounds resident rows
/// and snapshot work instead of only removing the lifetime stop.
pub(crate) const RETAINED_NOTIFICATIONS: u64 = 65_536;

/// Production retained fence window for touched native keys.
///
/// A key entry is logically retired when it is provably non-authoritative (no
/// record, lease or reservation) and its fence is below
/// `next_fence - RETAINED_KEY_FENCES`. The floor is derived from committed
/// state only, so every voter derives the same value and floor zero keeps
/// fresh/below-window state byte-identical. Key rows are not sequence-ordered;
/// retirement decisions therefore use the per-key fence window and the
/// committed key set, not a sequence prefix.
pub(crate) const RETAINED_KEY_FENCES: u64 = 65_536;

/// Derive the protected-credential floor from the committed global fence
/// counter. Credentials issued strictly below this floor are logically retired.
pub(super) fn key_retirement_floor(next_fence: u64) -> u64 {
    PrefixRetention::new(RETAINED_KEY_FENCES).floor(next_fence)
}

/// Test-only production-parity retained fence window override.
#[cfg(test)]
pub(crate) fn key_retention_floor_with(retained_fences: u64, next_fence: u64) -> u64 {
    PrefixRetention::new(retained_fences).floor(next_fence)
}

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

/// Committed application sequence after which ordinary-command receipt
/// retention becomes active.
///
/// Below this committed sequence every ordinary receipt is retained exactly as
/// before this rule existed, so existing stores and every below-bound fixture
/// stay byte-identical. Once active, the rule below is a pure function of
/// committed state: no wall clock, local observer, acknowledgement or delivery
/// tracker participates.
pub(crate) const ORDINARY_RECEIPT_RETENTION_ACTIVE_AFTER: u64 = 65_536;

/// Committed logical-time window during which a retired ordinary-command
/// outcome may still be requested by an exact retry.
///
/// A retry replays the original command bytes, so `command.logical_time` is
/// the submission time that was committed with the receipt. A retry whose
/// committed submission time is at or before `frontiers.logical_time - window`
/// (the boundary is inclusive) is outside retention and receives a typed
/// outcome-unavailable answer instead of being executed again.
pub(crate) const ORDINARY_RECEIPT_RETENTION_WINDOW_SECONDS: i64 = 120;

/// Hard retained-receipt admission bound before the fail-closed capacity
/// answer. Kept below [`super::validation::MAX_ITEMS`] so new bindings cannot
/// grow the receipt map to the fixed image admission cap.
///
/// The bound is enforced on every ordinary apply while the rule is active,
/// including mid-delta: a command is refused whenever the resident map is at or
/// above this bound, even when expired rows are reclaimable at the next
/// publication. Reclamation happens only at publication, so "reclaimable
/// exists" is not permission to grow the current delta; a committed delta has
/// no RPC cap, and a window-crossing batch must not be able to bypass the
/// bound. A rejected command may still advance the committed logical clock
/// (the pre-existing deterministic `clock_response` behavior), but it never
/// binds a receipt.
pub(crate) const MAX_RETAINED_ORDINARY_RECEIPTS: usize = 1_044_480;

/// Ordinary-command receipt retention rule, derived only from committed state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct OrdinaryReceiptRetention {
    active_after: u64,
    window_seconds: i64,
    capacity: usize,
}

impl OrdinaryReceiptRetention {
    const fn new(active_after: u64, window_seconds: i64, capacity: usize) -> Self {
        Self {
            active_after,
            window_seconds,
            capacity,
        }
    }

    /// Whether retirement and the typed placeholder answer are active at this
    /// committed application sequence.
    pub(super) const fn active(self, sequence: u64) -> bool {
        sequence > self.active_after
    }

    /// First committed logical time whose receipts are outside retention.
    /// `None` means the committed clock is too close to its representable
    /// minimum for any receipt to have expired yet.
    pub(super) fn expired_before(self, now: Timestamp) -> Option<Timestamp> {
        now.add_seconds(-self.window_seconds)
    }

    /// Whether a receipt carrying this committed response logical time is
    /// outside the retained window.
    pub(super) fn expired(self, response_time: Option<Timestamp>, now: Timestamp) -> bool {
        response_time.is_some_and(|time| {
            self.expired_before(now)
                .is_some_and(|horizon| time <= horizon)
        })
    }

    /// Whether an exact retry of a commit whose submission logical time is
    /// `command_time` is outside retention at committed time `now`.
    pub(super) fn retry_outside_retention(self, command_time: Timestamp, now: Timestamp) -> bool {
        self.expired_before(now)
            .is_some_and(|horizon| command_time <= horizon)
    }

    pub(super) const fn capacity(self) -> usize {
        self.capacity
    }
}

/// Production ordinary-receipt retention, with a test-only override so the
/// reduced-window regressions exercise the same production paths without
/// publishing 65,536 commands.
pub(super) fn ordinary_receipt_retention() -> OrdinaryReceiptRetention {
    #[cfg(test)]
    if let Some((active_after, window_seconds, capacity)) =
        tests_support::ordinary_receipt_override()
    {
        return OrdinaryReceiptRetention::new(active_after, window_seconds, capacity);
    }
    OrdinaryReceiptRetention::new(
        ORDINARY_RECEIPT_RETENTION_ACTIVE_AFTER,
        ORDINARY_RECEIPT_RETENTION_WINDOW_SECONDS,
        MAX_RETAINED_ORDINARY_RECEIPTS,
    )
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
    use std::cell::Cell as KeyCapacityCell;

    thread_local! {
        static KEY_CAPACITY_LIMIT: KeyCapacityCell<Option<usize>> = const { KeyCapacityCell::new(None) };
    }

    /// Test-only override of the native key admission cap so a batch boundary can
    /// be exercised without materializing a million keys.
    pub(crate) struct KeyCapacityLimitOverride {
        previous: Option<usize>,
    }

    impl KeyCapacityLimitOverride {
        pub(crate) fn new(limit: usize) -> Self {
            let previous = KEY_CAPACITY_LIMIT.with(|current| current.replace(Some(limit)));
            Self { previous }
        }
    }

    impl Drop for KeyCapacityLimitOverride {
        fn drop(&mut self) {
            KEY_CAPACITY_LIMIT.with(|current| current.set(self.previous));
        }
    }

    pub(crate) fn key_capacity_limit_override() -> Option<usize> {
        KEY_CAPACITY_LIMIT.with(|current| current.get())
    }

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

    thread_local! {
        // Ordinary-receipt active-sequence threshold, logical-time window and
        // admission capacity.
        static ORDINARY_RECEIPT: Cell<Option<(u64, i64, usize)>> = const { Cell::new(None) };
    }

    pub(crate) struct OrdinaryReceiptOverride {
        previous: Option<(u64, i64, usize)>,
    }

    impl Drop for OrdinaryReceiptOverride {
        fn drop(&mut self) {
            ORDINARY_RECEIPT.with(|value| value.set(self.previous));
        }
    }

    /// Run this thread's ordinary-receipt retention at a reduced activation
    /// sequence and window. The guard restores the production rule on drop so
    /// a panic cannot leak the reduced rule into later assertions.
    pub(crate) fn override_ordinary_receipt_retention_for_test(
        active_after: u64,
        window_seconds: i64,
    ) -> OrdinaryReceiptOverride {
        override_ordinary_receipt_retention_with_capacity_for_test(
            active_after,
            window_seconds,
            super::MAX_RETAINED_ORDINARY_RECEIPTS,
        )
    }

    /// Reduced rule including the admission capacity, so a regression can drive
    /// the capacity answer without publishing a million receipts.
    pub(crate) fn override_ordinary_receipt_retention_with_capacity_for_test(
        active_after: u64,
        window_seconds: i64,
        capacity: usize,
    ) -> OrdinaryReceiptOverride {
        assert!(window_seconds > 0, "a test receipt window must be positive");
        assert!(capacity > 0, "a test receipt capacity must be positive");
        let previous = ORDINARY_RECEIPT
            .with(|value| value.replace(Some((active_after, window_seconds, capacity))));
        OrdinaryReceiptOverride { previous }
    }

    pub(super) fn ordinary_receipt_override() -> Option<(u64, i64, usize)> {
        ORDINARY_RECEIPT.with(Cell::get)
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

    #[test]
    fn key_retirement_floor_is_derived_and_keeps_floor_zero_byte_identical() {
        assert_eq!(super::key_retirement_floor(0), 0);
        assert_eq!(
            super::key_retirement_floor(super::RETAINED_KEY_FENCES),
            0,
            "a fresh or below-window store keeps floor zero"
        );
        assert_eq!(
            super::key_retirement_floor(super::RETAINED_KEY_FENCES + 7),
            7
        );
        assert_eq!(super::key_retention_floor_with(4, 10), 6);
    }
}
