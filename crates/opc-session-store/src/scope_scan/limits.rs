//! Validated node-wide retention configuration.

use super::admission::RetentionLimits;
use std::time::Duration;

/// Local resource use shared by every scan service in one backend generation.
/// Observations may change immediately; they do not grant admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeScanMetrics {
    /// Admitted views, including resources draining after invalidation.
    pub active_views: usize,
    /// Opens waiting fairly for retention capacity.
    pub waiting_views: usize,
    /// Reserved native view context and bounded page memory; excludes shared storage roots.
    pub native_bytes: u64,
    /// Dedicated retained SQLite readers, including readers still draining.
    pub sqlite_readers: usize,
    /// Latest shared WAL descriptor measurement, never summed per reader.
    /// `None` means the measurement is unavailable.
    pub retained_wal_bytes: Option<u64>,
    /// Longest current idle interval; queued or executing work is active.
    pub oldest_idle_age: Option<Duration>,
}

/// Retention limits shared by all scope-scan services on one serving node.
/// Pressure queues new views and never evicts an admitted active view.
#[derive(Clone, Copy, Debug)]
pub struct ScopeScanLimits {
    pub(crate) retention: RetentionLimits,
    pub(crate) idle_timeout: Duration,
}

/// Invalid retention configuration, refused before opening a backend generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ScopeScanLimitsError {
    /// Every capacity must be positive; SQLite readers cannot exceed all views.
    #[error("scope scan retention capacities are invalid")]
    InvalidCapacity,
    /// The local idle interval must be positive.
    #[error("scope scan idle interval must be positive")]
    InvalidIdleTimeout,
}

impl ScopeScanLimits {
    /// Construct validated capacities and the local resource cleanup interval.
    pub fn new(
        max_views: usize,
        sqlite_readers: usize,
        native_bytes: u64,
        wal_high_water: u64,
        idle_timeout: Duration,
    ) -> Result<Self, ScopeScanLimitsError> {
        let retention =
            RetentionLimits::new(max_views, sqlite_readers, native_bytes, wal_high_water)
                .map_err(|_| ScopeScanLimitsError::InvalidCapacity)?;
        if idle_timeout.is_zero() {
            return Err(ScopeScanLimitsError::InvalidIdleTimeout);
        }
        Ok(Self {
            retention,
            idle_timeout,
        })
    }

    /// Maximum simultaneous retained views on this node.
    pub const fn max_views(&self) -> usize {
        self.retention.max_views
    }
    /// Maximum dedicated retained SQLite readers on this node.
    pub const fn sqlite_readers(&self) -> usize {
        self.retention.sqlite_readers
    }
    /// Maximum native view context and page reservation in bytes.
    pub const fn native_bytes(&self) -> u64 {
        self.retention.native_bytes
    }
    /// Shared WAL high-water mark for admitting another reader, in bytes.
    pub const fn wal_high_water(&self) -> u64 {
        self.retention.wal_high_water
    }
    /// Idle interval for local resource cleanup, never an authority expiry.
    pub const fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }
}

impl Default for ScopeScanLimits {
    fn default() -> Self {
        Self {
            retention: RetentionLimits::default(),
            idle_timeout: Duration::from_secs(30),
        }
    }
}
