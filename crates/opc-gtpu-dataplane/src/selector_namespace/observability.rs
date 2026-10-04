//! Value-free observations of the protected selector coordinator.
//!
//! Observations carry no authority and never change an operation's outcome.

use std::future::Future;
use std::ops::{Deref, DerefMut};
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
    /// Wait for complete group, parent, PAA and TEID conflict reservations.
    ConflictWait,
    /// Retain the complete conflict reservation through owned settlement.
    ConflictHold,
    /// Wait for cohort membership and exact acquire/release ordering.
    CohortWait,
    /// Retain cohort membership ordering, including acquisition or release.
    CohortHold,
    /// Wait for an authenticated ledger transition.
    TransitionWait,
    /// Retain authenticated transition ordering through exact readback.
    TransitionHold,
    /// Wait for the sole exact durable lease credential.
    CredentialWait,
    /// Retain the credential across renewal or a fenced write and readback.
    CredentialHold,
}

impl GtpuSelectorPhase {
    const ALL: [Self; 22] = [
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
        Self::ConflictWait,
        Self::ConflictHold,
        Self::CohortWait,
        Self::CohortHold,
        Self::TransitionWait,
        Self::TransitionHold,
        Self::CredentialWait,
        Self::CredentialHold,
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
            Self::ConflictWait => "conflict_wait",
            Self::ConflictHold => "conflict_hold",
            Self::CohortWait => "cohort_wait",
            Self::CohortHold => "cohort_hold",
            Self::TransitionWait => "transition_wait",
            Self::TransitionHold => "transition_hold",
            Self::CredentialWait => "credential_wait",
            Self::CredentialHold => "credential_hold",
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

/// Value-free activity at one fixed observed boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GtpuSelectorActivitySnapshot {
    /// Fixed observed boundary; wait phases describe queue occupancy.
    pub phase: GtpuSelectorPhase,
    /// Currently polled observations that have not returned or been dropped.
    pub current: u64,
    /// Largest observed concurrent count since process start.
    pub peak: u64,
}

struct Activity {
    current: AtomicU64,
    peak: AtomicU64,
}

impl Activity {
    const fn new() -> Self {
        Self {
            current: AtomicU64::new(0),
            peak: AtomicU64::new(0),
        }
    }
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
struct Recorder {
    histograms: [Histogram; SERIES],
    activity: [Activity; GtpuSelectorPhase::ALL.len()],
}

impl Recorder {
    const fn new() -> Self {
        Self {
            histograms: [const { Histogram::new() }; SERIES],
            activity: [const { Activity::new() }; GtpuSelectorPhase::ALL.len()],
        }
    }

    fn start(&self, phase: GtpuSelectorPhase, outcome: GtpuSelectorOutcome) -> Observation<'_> {
        let activity = &self.activity[phase as usize];
        let current = activity.current.fetch_add(1, Ordering::Relaxed) + 1;
        activity.peak.fetch_max(current, Ordering::Relaxed);
        Observation {
            recorder: self,
            phase,
            outcome,
            started: Instant::now(),
        }
    }
}

static RECORDER: Recorder = Recorder::new();

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
        let cell = &RECORDER.histograms[index];
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

/// Snapshot activity without retaining or reading any selector authority.
///
/// Nested phases overlap. This is not a transactional snapshot or an admission
/// limit; a queue's peak is useful only with its measurement interval stated.
pub fn gtpu_selector_activity_snapshot(
) -> [GtpuSelectorActivitySnapshot; GtpuSelectorPhase::ALL.len()] {
    std::array::from_fn(|index| GtpuSelectorActivitySnapshot {
        phase: GtpuSelectorPhase::ALL[index],
        current: RECORDER.activity[index].current.load(Ordering::Relaxed),
        peak: RECORDER.activity[index].peak.load(Ordering::Relaxed),
    })
}

struct Observation<'a> {
    recorder: &'a Recorder,
    phase: GtpuSelectorPhase,
    outcome: GtpuSelectorOutcome,
    started: Instant,
}

impl Drop for Observation<'_> {
    fn drop(&mut self) {
        let elapsed = u64::try_from(self.started.elapsed().as_micros()).unwrap_or(u64::MAX);
        let cell = &self.recorder.histograms
            [self.phase as usize * GtpuSelectorOutcome::ALL.len() + self.outcome as usize];
        let bin = GTPU_SELECTOR_DURATION_BUCKETS_US
            .iter()
            .position(|bound| elapsed <= *bound)
            .unwrap_or(GTPU_SELECTOR_DURATION_BUCKETS_US.len());
        add(&cell.sum_microseconds, elapsed);
        add(&cell.bins[bin], 1);
        self.recorder.activity[self.phase as usize]
            .current
            .fetch_sub(1, Ordering::Relaxed);
    }
}

pub(super) async fn observe<T, E>(
    phase: GtpuSelectorPhase,
    future: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let mut observation = RECORDER.start(phase, GtpuSelectorOutcome::Cancelled);
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
    let mut observation = RECORDER.start(phase, GtpuSelectorOutcome::Cancelled);
    let result = operation();
    observation.outcome = if result.is_ok() {
        GtpuSelectorOutcome::Completed
    } else {
        GtpuSelectorOutcome::Error
    };
    result
}

pub(super) struct ObservedGuard<'a, T> {
    guard: T,
    // Fields drop in declaration order: the actual reservation is released
    // before the hold duration is recorded. Completed means released, not that
    // the enclosing operation succeeded.
    _hold: Observation<'a>,
}

impl<T> Deref for ObservedGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T> DerefMut for ObservedGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

async fn record_guard<T>(
    recorder: &Recorder,
    wait: GtpuSelectorPhase,
    hold: GtpuSelectorPhase,
    future: impl Future<Output = T>,
) -> ObservedGuard<'_, T> {
    let mut observation = recorder.start(wait, GtpuSelectorOutcome::Cancelled);
    let guard = future.await;
    observation.outcome = GtpuSelectorOutcome::Completed;
    drop(observation);
    ObservedGuard {
        guard,
        _hold: recorder.start(hold, GtpuSelectorOutcome::Completed),
    }
}

pub(super) async fn observe_guard<T>(
    wait: GtpuSelectorPhase,
    hold: GtpuSelectorPhase,
    future: impl Future<Output = T>,
) -> ObservedGuard<'static, T> {
    record_guard(&RECORDER, wait, hold, future).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::task::Poll;

    #[tokio::test]
    async fn queue_drop_and_guard_release_record_separate_activity_and_outcomes() {
        let recorder = Recorder::new();
        let wait = GtpuSelectorPhase::ConflictWait;
        let hold = GtpuSelectorPhase::ConflictHold;
        let lock = tokio::sync::Mutex::new(());
        let held = record_guard(&recorder, wait, hold, lock.lock()).await;
        assert_eq!(
            recorder.activity[hold as usize]
                .current
                .load(Ordering::Relaxed),
            1
        );
        let mut queued = Box::pin(record_guard(&recorder, wait, hold, lock.lock()));
        assert!(
            std::future::poll_fn(|cx| Poll::Ready(queued.as_mut().poll(cx).is_pending())).await
        );
        assert_eq!(
            recorder.activity[wait as usize]
                .current
                .load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            recorder.activity[hold as usize]
                .peak
                .load(Ordering::Relaxed),
            1
        );
        drop(queued);
        assert_eq!(
            recorder.activity[wait as usize]
                .current
                .load(Ordering::Relaxed),
            0
        );
        assert!(lock.try_lock().is_err());
        drop(held);
        assert!(lock.try_lock().is_ok());
        assert_eq!(
            recorder.activity[hold as usize]
                .current
                .load(Ordering::Relaxed),
            0
        );
        let count = |phase, outcome| {
            recorder.histograms[phase as usize * 3 + outcome as usize]
                .bins
                .iter()
                .map(|value| value.load(Ordering::Relaxed))
                .sum::<u64>()
        };
        assert_eq!(count(wait, GtpuSelectorOutcome::Completed), 1);
        assert_eq!(count(wait, GtpuSelectorOutcome::Cancelled), 1);
        assert_eq!(count(hold, GtpuSelectorOutcome::Completed), 1);
        assert_eq!(count(hold, GtpuSelectorOutcome::Cancelled), 0);
    }
}
