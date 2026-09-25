//! Value-free observations of the protected selector coordinator.
//!
//! Observations carry no authority and never change an operation's outcome.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Fixed protected selector operation boundaries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GtpuSelectorPhase {
    /// Wait for the process-local namespace worker.
    WorkerWait,
    /// Poll the owned worker through its terminal result.
    WorkerHold,
    /// Acquire a durable namespace lease.
    LeaseAcquire,
    /// Renew the exact durable lease.
    LeaseRenew,
    /// Release the exact durable lease.
    LeaseRelease,
    /// Read the complete protected ledger, including mutation readback.
    LedgerRead,
    /// Submit a fenced ledger compare-and-set.
    LedgerWrite,
    /// Validate the backend's complete operation-stamp inventory.
    BackendInventory,
    /// Apply an authorized grouped installation.
    BackendInstall,
    /// Read an exact authorized group.
    BackendRead,
    /// Apply an authorized grouped removal.
    BackendRemove,
    /// Decode and validate one complete authenticated ledger snapshot.
    LedgerDecode,
    /// Validate and encode one complete proposed ledger replacement.
    LedgerEncode,
    /// Derive the complete operation-stamp inventory from protected state.
    InventoryDerive,
}

impl GtpuSelectorPhase {
    const ALL: [Self; 14] = [
        Self::WorkerWait,
        Self::WorkerHold,
        Self::LeaseAcquire,
        Self::LeaseRenew,
        Self::LeaseRelease,
        Self::LedgerRead,
        Self::LedgerWrite,
        Self::BackendInventory,
        Self::BackendInstall,
        Self::BackendRead,
        Self::BackendRemove,
        Self::LedgerDecode,
        Self::LedgerEncode,
        Self::InventoryDerive,
    ];

    /// Stable label containing no request or authority information.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkerWait => "worker_wait",
            Self::WorkerHold => "worker_hold",
            Self::LeaseAcquire => "lease_acquire",
            Self::LeaseRenew => "lease_renew",
            Self::LeaseRelease => "lease_release",
            Self::LedgerRead => "ledger_read",
            Self::LedgerWrite => "ledger_write",
            Self::BackendInventory => "backend_inventory",
            Self::BackendInstall => "backend_install",
            Self::BackendRead => "backend_read",
            Self::BackendRemove => "backend_remove",
            Self::LedgerDecode => "ledger_decode",
            Self::LedgerEncode => "ledger_encode",
            Self::InventoryDerive => "inventory_derive",
        }
    }
}

/// Outcome at the observed future boundary, not a lifecycle proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GtpuSelectorOutcome {
    /// The observed future returned `Ok`.
    Completed,
    /// The observed future returned `Err`.
    Error,
    /// The observed future was dropped before returning.
    Cancelled,
}

impl GtpuSelectorOutcome {
    const ALL: [Self; 3] = [Self::Completed, Self::Error, Self::Cancelled];

    /// Stable label independent of error text or receipt contents.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Error => "error",
            Self::Cancelled => "cancelled",
        }
    }
}

/// Disjoint duration bucket bounds in microseconds; these are not deadlines.
pub const GTPU_SELECTOR_DURATION_BUCKETS_US: [u64; 10] = [
    100, 500, 1_000, 5_000, 10_000, 25_000, 50_000, 100_000, 500_000, 5_000_000,
];

/// Process-lifetime fixed-category selector coordinator observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GtpuSelectorDurationSnapshot {
    /// Fixed observed operation boundary.
    pub phase: GtpuSelectorPhase,
    /// Fixed completion category.
    pub outcome: GtpuSelectorOutcome,
    /// Disjoint buckets, followed by an overflow bucket.
    pub bucket_counts: [u64; 11],
    /// Saturating observation count.
    pub count: u64,
    /// Saturating elapsed microseconds, including queueing within the future.
    pub sum_microseconds: u64,
}

struct Histogram {
    bins: [AtomicU64; 11],
    sum_microseconds: AtomicU64,
}

impl Histogram {
    const fn new() -> Self {
        Self {
            bins: [const { AtomicU64::new(0) }; 11],
            sum_microseconds: AtomicU64::new(0),
        }
    }
}

const SERIES: usize = GtpuSelectorPhase::ALL.len() * GtpuSelectorOutcome::ALL.len();
static HISTOGRAMS: [Histogram; SERIES] = [const { Histogram::new() }; SERIES];

fn add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
        Some(current.saturating_add(value))
    });
}

/// Snapshot fixed counters without reading a store, backend, or authority.
///
/// Enclosing worker and nested call durations overlap and must not be summed
/// into a request timeline. Concurrent observations are not a transactional
/// snapshot. Counts describe calls, not Raft proposals or successful effects.
pub fn gtpu_selector_duration_snapshot() -> [GtpuSelectorDurationSnapshot; SERIES] {
    std::array::from_fn(|index| {
        let cell = &HISTOGRAMS[index];
        let bins = std::array::from_fn(|bin| cell.bins[bin].load(Ordering::Relaxed));
        GtpuSelectorDurationSnapshot {
            phase: GtpuSelectorPhase::ALL[index / GtpuSelectorOutcome::ALL.len()],
            outcome: GtpuSelectorOutcome::ALL[index % GtpuSelectorOutcome::ALL.len()],
            count: bins.into_iter().fold(0, u64::saturating_add),
            bucket_counts: bins,
            sum_microseconds: cell.sum_microseconds.load(Ordering::Relaxed),
        }
    })
}

struct Observation {
    phase: GtpuSelectorPhase,
    outcome: GtpuSelectorOutcome,
    started: Instant,
}

impl Drop for Observation {
    fn drop(&mut self) {
        let elapsed = u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let cell = &HISTOGRAMS
            [self.phase as usize * GtpuSelectorOutcome::ALL.len() + self.outcome as usize];
        let bin = GTPU_SELECTOR_DURATION_BUCKETS_US
            .iter()
            .position(|bound| elapsed <= *bound)
            .unwrap_or(GTPU_SELECTOR_DURATION_BUCKETS_US.len());
        add(&cell.sum_microseconds, elapsed);
        add(&cell.bins[bin], 1);
    }
}

pub(super) async fn observe<T, E>(
    phase: GtpuSelectorPhase,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let mut observation = Observation {
        phase,
        outcome: GtpuSelectorOutcome::Cancelled,
        started: Instant::now(),
    };
    let result = future.await;
    observation.outcome = if result.is_ok() {
        GtpuSelectorOutcome::Completed
    } else {
        GtpuSelectorOutcome::Error
    };
    result
}

pub(super) fn observe_sync<T, E>(
    phase: GtpuSelectorPhase,
    operation: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let mut observation = Observation {
        phase,
        outcome: GtpuSelectorOutcome::Cancelled,
        started: Instant::now(),
    };
    let result = operation();
    observation.outcome = if result.is_ok() {
        GtpuSelectorOutcome::Completed
    } else {
        GtpuSelectorOutcome::Error
    };
    result
}
