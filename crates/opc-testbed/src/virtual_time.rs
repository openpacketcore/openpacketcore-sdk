//! Virtual time and controllable clock (RFC 012 §7, compatible with RFC 008).
//!
//! Enables deterministic timer behavior for NAS, PFCP, NRF heartbeats, etc.
//! without real-time sleeps in tests.

use opc_types::Timestamp;
use std::sync::OnceLock;
use std::time::{Duration as StdDuration, Instant};
use time::OffsetDateTime;

/// Controllable virtual clock for test scenarios.
/// Implements a simple monotonic + wall clock that can be advanced manually.
///
/// `now()` is fully deterministic for a given sequence of advances (no real
/// time). `monotonic()` uses a process-wide base instant so clocks with the
/// same advance sequence produce equal instants within a process. Absolute
/// `Instant` values remain process-local; use [`Self::monotonic_elapsed`] for
/// reproducible absolute assertions.
#[derive(Debug, Clone)]
pub struct VirtualClock {
    base: OffsetDateTime,
    offset: time::Duration,
    /// Process-wide base monotonic instant.
    mono_base: Instant,
}

impl VirtualClock {
    #[must_use]
    pub fn new(start: Timestamp) -> Self {
        Self {
            base: *start.as_offset_datetime(),
            offset: time::Duration::ZERO,
            mono_base: process_monotonic_base(),
        }
    }

    #[must_use]
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

    /// Reset to a specific wall time (primarily for test setup).
    pub fn reset_to(&mut self, t: Timestamp) {
        self.base = *t.as_offset_datetime();
        self.offset = time::Duration::ZERO;
        self.mono_base = process_monotonic_base();
    }

    /// Current virtual monotonic elapsed duration from the synthetic base.
    #[must_use]
    pub fn monotonic_elapsed(&self) -> StdDuration {
        std_duration_saturating(self.offset)
    }

    /// Current virtual monotonic instant (deterministic relative to advances).
    #[must_use]
    pub fn monotonic(&self) -> Instant {
        let mut elapsed = self.monotonic_elapsed();
        while self.mono_base.checked_add(elapsed).is_none() {
            let next = halve_duration(elapsed);
            if next == elapsed {
                return self.mono_base;
            }
            elapsed = next;
        }
        if let Some(instant) = self.mono_base.checked_add(elapsed) {
            instant
        } else {
            self.mono_base
        }
    }
}

fn process_monotonic_base() -> Instant {
    static BASE: OnceLock<Instant> = OnceLock::new();
    *BASE.get_or_init(Instant::now)
}

fn std_duration_saturating(duration: time::Duration) -> StdDuration {
    if duration.is_negative() {
        return StdDuration::ZERO;
    }

    let seconds = duration.whole_seconds();
    let subsecond = duration - time::Duration::seconds(seconds);
    let nanos = subsecond.whole_nanoseconds();

    let seconds = u64::try_from(seconds).unwrap_or(u64::MAX);
    let nanos = u32::try_from(nanos).unwrap_or(999_999_999);
    StdDuration::new(seconds, nanos)
}

fn halve_duration(duration: StdDuration) -> StdDuration {
    let half_secs = duration.as_secs() / 2;
    let carry_nanos = if duration.as_secs().is_multiple_of(2) {
        0
    } else {
        500_000_000
    };
    StdDuration::new(half_secs, (duration.subsec_nanos() / 2) + carry_nanos)
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
