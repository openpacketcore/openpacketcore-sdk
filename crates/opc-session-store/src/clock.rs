//! Injectable time sources for TTL and lease-expiry decisions.
//!
//! Backends and the quorum coordinator never call `Timestamp::now_utc`
//! directly; they go through a `Clock` so tests can drive record TTLs and
//! lease expiry deterministically (e.g. "owner pauses past its lease TTL")
//! with tokio's paused virtual time instead of real sleeps.

use std::sync::OnceLock;
use std::time::Instant;

use opc_types::Timestamp;

/// Injectable clock source for session expiration and leases.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Return the current UTC timestamp.
    fn now_utc(&self) -> Timestamp;
}

/// A UTC clock derived from a wall-time anchor plus monotonic elapsed time.
///
/// This avoids lease liveness decisions moving backward or jumping forward
/// when the host wall clock is stepped after the clock is created. The
/// timestamp remains suitable for persisted UTC deadlines, but expiration
/// comparisons advance according to [`Instant`].
#[derive(Debug, Clone)]
pub struct MonotonicClock {
    anchor_time: time::OffsetDateTime,
    anchor_instant: Instant,
}

impl MonotonicClock {
    /// Anchor at the current system wall time and current monotonic instant.
    pub fn new() -> Self {
        Self::anchored_at(Timestamp::now_utc())
    }

    /// Anchor at a caller-supplied UTC wall time and current monotonic instant.
    pub fn anchored_at(anchor: Timestamp) -> Self {
        Self {
            anchor_time: *anchor.as_offset_datetime(),
            anchor_instant: Instant::now(),
        }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MonotonicClock {
    fn now_utc(&self) -> Timestamp {
        let elapsed = self.anchor_instant.elapsed();
        let current_time = self.anchor_time + time::Duration::seconds_f64(elapsed.as_secs_f64());
        Timestamp::from_offset_datetime(current_time)
    }
}

/// A clock implementation using real wall time only for its process-wide
/// anchor, then advancing from the monotonic system timer.
#[derive(Debug, Clone, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_utc(&self) -> Timestamp {
        static CLOCK: OnceLock<MonotonicClock> = OnceLock::new();
        CLOCK.get_or_init(MonotonicClock::new).now_utc()
    }
}

/// A clock that integrates with tokio virtual time in tests.
#[derive(Debug, Clone)]
pub struct TokioVirtualClock {
    base_time: time::OffsetDateTime,
    base_instant: tokio::time::Instant,
}

impl TokioVirtualClock {
    /// Anchor the clock at the current wall-clock time and the current
    /// `tokio::time::Instant`.
    ///
    /// Subsequent `now_utc` calls report the anchor plus tokio's elapsed
    /// time, so under `tokio::time::pause`/`advance` the clock jumps exactly
    /// as far as the test advances the runtime — letting TTL and lease-expiry
    /// paths be exercised without real waiting. Must be created inside a
    /// tokio runtime context.
    pub fn new() -> Self {
        Self {
            base_time: *Timestamp::now_utc().as_offset_datetime(),
            base_instant: tokio::time::Instant::now(),
        }
    }
}

impl Default for TokioVirtualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for TokioVirtualClock {
    fn now_utc(&self) -> Timestamp {
        let elapsed = tokio::time::Instant::now().duration_since(self.base_instant);
        let current_time = self.base_time + time::Duration::seconds_f64(elapsed.as_secs_f64());
        Timestamp::from_offset_datetime(current_time)
    }
}
