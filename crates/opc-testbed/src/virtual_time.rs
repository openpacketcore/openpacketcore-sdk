//! Virtual time and controllable clock (RFC 012 §7, compatible with RFC 008).
//!
//! Enables deterministic timer behavior for NAS, PFCP, NRF heartbeats, etc.
//! without real-time sleeps in tests.

use opc_types::Timestamp;
use std::time::{Duration as StdDuration, Instant};
use time::OffsetDateTime;

/// Controllable virtual clock for test scenarios.
/// Implements a simple monotonic + wall clock that can be advanced manually.
///
/// `now()` is fully deterministic for a given sequence of advances (no real
/// time).  `monotonic()` is deterministic *within a single run* — relative
/// ordering and deltas are stable — but absolute values may differ across
/// process restarts because `mono_base` is anchored to `Instant::now()` at
/// construction or reset.
#[derive(Debug, Clone)]
pub struct VirtualClock {
    base: OffsetDateTime,
    offset: time::Duration,
    /// Base monotonic instant captured at construction (or reset).
    mono_base: Instant,
}

impl VirtualClock {
    pub fn new(start: Timestamp) -> Self {
        let now_mono = Instant::now();
        Self {
            base: *start.as_offset_datetime(),
            offset: time::Duration::ZERO,
            mono_base: now_mono,
        }
    }

    pub fn now(&self) -> Timestamp {
        Timestamp::from_offset_datetime(self.base + self.offset)
    }

    /// Advance virtual time by the given duration. Used by scenario executor
    /// and timer drivers to make progress without real sleeps.
    ///
    /// # Panics
    ///
    /// Panics if `d` is negative — the virtual clock must not go backwards.
    pub fn advance(&mut self, d: time::Duration) {
        assert!(
            !d.is_negative(),
            "virtual clock cannot go backwards (advance duration was negative)"
        );
        self.offset += d;
    }

    /// Reset to a specific wall time (primarily for test setup). Also resets
    /// the monotonic base so subsequent monotonic() calls remain consistent.
    pub fn reset_to(&mut self, t: Timestamp) {
        self.base = *t.as_offset_datetime();
        self.offset = time::Duration::ZERO;
        self.mono_base = Instant::now();
    }

    /// Current virtual monotonic instant (deterministic relative to advances).
    pub fn monotonic(&self) -> Instant {
        // Synthesize by adding the virtual offset (as std Duration) to mono_base.
        // The offset is guaranteed non-negative by advance().
        let nanos = u64::try_from(self.offset.whole_nanoseconds())
            .expect("virtual offset overflow in monotonic()");
        self.mono_base + StdDuration::from_nanos(nanos)
    }
}

/// Clock trait mirroring the RFC 008 abstraction for compatibility.
/// Both production runtime clocks and VirtualClock for tests implement it.
pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
    fn monotonic(&self) -> Instant;
}

impl Clock for VirtualClock {
    fn now(&self) -> Timestamp {
        self.now()
    }

    fn monotonic(&self) -> Instant {
        self.monotonic()
    }
}
