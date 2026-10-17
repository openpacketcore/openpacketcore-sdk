//! Per-store snapshot attempt limits and cancellation ownership.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub(super) const SNAPSHOT_BUILD_STALL_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const SNAPSHOT_PRESSURE_TIMEOUT: Duration = Duration::from_secs(5);
pub(super) const SNAPSHOT_RETRY_DELAY: Duration = Duration::from_secs(1);

pub(super) struct SnapshotBuildControl {
    attempt_millis: AtomicU64,
    pressure_millis: AtomicU64,
    #[cfg(test)]
    retries: AtomicU64,
    stopped: tokio::sync::watch::Sender<bool>,
    #[cfg(test)]
    next_publication: std::sync::Mutex<Option<std::sync::Arc<super::SnapshotArtifactGate>>>,
    #[cfg(test)]
    owner: std::sync::Mutex<std::sync::Weak<super::ConsensusStorageShutdownGuard>>,
}

impl Default for SnapshotBuildControl {
    fn default() -> Self {
        Self {
            attempt_millis: AtomicU64::new(SNAPSHOT_BUILD_STALL_TIMEOUT.as_millis() as u64),
            pressure_millis: AtomicU64::new(SNAPSHOT_PRESSURE_TIMEOUT.as_millis() as u64),
            #[cfg(test)]
            retries: AtomicU64::new(0),
            stopped: tokio::sync::watch::channel(false).0,
            #[cfg(test)]
            next_publication: std::sync::Mutex::new(None),
            #[cfg(test)]
            owner: std::sync::Mutex::new(std::sync::Weak::new()),
        }
    }
}

impl SnapshotBuildControl {
    #[cfg(test)]
    pub(super) fn observe_owner(&self, owner: &Arc<super::ConsensusStorageShutdownGuard>) {
        *self.owner.lock().expect("snapshot owner observation") = Arc::downgrade(owner);
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn owner(&self) -> SnapshotOwnerObservation {
        SnapshotOwnerObservation(
            self.owner
                .lock()
                .expect("snapshot owner observation")
                .clone(),
        )
    }

    pub(super) fn stop(&self) {
        self.stopped.send_replace(true);
    }

    pub(super) async fn stopped(&self) {
        let mut stopped = self.stopped.subscribe();
        let _ = stopped.wait_for(|stopped| *stopped).await;
    }

    pub(super) fn attempt_timeout(&self) -> Duration {
        Duration::from_millis(self.attempt_millis.load(Ordering::Acquire))
    }

    pub(super) fn pressure_timeout(&self) -> Duration {
        Duration::from_millis(self.pressure_millis.load(Ordering::Acquire))
    }

    #[cfg(test)]
    pub(super) fn record_retry(&self) {
        self.retries.fetch_add(1, Ordering::AcqRel);
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn set_limits(&self, attempt: Duration, pressure: Duration) {
        assert!(!attempt.is_zero() && attempt <= SNAPSHOT_BUILD_STALL_TIMEOUT);
        assert!(!pressure.is_zero() && pressure <= SNAPSHOT_PRESSURE_TIMEOUT);
        self.attempt_millis
            .store(attempt.as_millis() as u64, Ordering::Release);
        self.pressure_millis
            .store(pressure.as_millis() as u64, Ordering::Release);
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn retries(&self) -> u64 {
        self.retries.load(Ordering::Acquire)
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn pause_next_publication(&self, gate: std::sync::Arc<super::SnapshotArtifactGate>) {
        let mut next = self.next_publication.lock().expect("snapshot attempt gate");
        assert!(next.is_none(), "only one next-attempt gate");
        *next = Some(gate);
    }

    #[cfg(test)]
    pub(super) async fn before_publication(&self) {
        let gate = self
            .next_publication
            .lock()
            .expect("snapshot attempt gate")
            .take();
        if let Some(gate) = gate {
            gate.block_if_armed().await;
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
pub(crate) struct SnapshotOwnerObservation(std::sync::Weak<super::ConsensusStorageShutdownGuard>);

#[cfg(all(test, target_os = "linux"))]
impl SnapshotOwnerObservation {
    pub(crate) fn is_retained(&self) -> bool {
        self.0.strong_count() != 0
    }

    pub(crate) fn is_same_owner(&self, other: &Self) -> bool {
        self.0.ptr_eq(&other.0)
    }
}

/// Revocation belongs to the async attempt; blocking workers only observe it.
/// Their gate, descriptors and shutdown ownership retire on actual completion.
pub(super) struct SnapshotBuildAttempt {
    stall_timeout: Duration,
    deadline: std::sync::Mutex<Option<tokio::time::Instant>>,
    changed: tokio::sync::Notify,
    cancelled: AtomicBool,
    expired: AtomicBool,
    published: AtomicBool,
}

impl SnapshotBuildAttempt {
    pub(super) fn new(timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            stall_timeout: timeout,
            deadline: std::sync::Mutex::new(None),
            changed: tokio::sync::Notify::new(),
            cancelled: AtomicBool::new(false),
            expired: AtomicBool::new(false),
            published: AtomicBool::new(false),
        })
    }

    /// Gate contention is not work. Arm only once the prior physical owner
    /// has retired and this attempt has acquired its worker gate.
    pub(super) fn start(&self) -> std::io::Result<()> {
        self.progress()
    }

    fn expire(&self) {
        self.expired.store(true, Ordering::Release);
        self.cancelled.store(true, Ordering::Release);
    }

    pub(super) fn expired(&self) -> bool {
        self.expired.load(Ordering::Acquire)
    }

    pub(super) fn published(&self) -> bool {
        self.published.load(Ordering::Acquire)
    }

    pub(super) fn complete_publication(&self) {
        self.published.store(true, Ordering::Release);
    }

    pub(super) fn cancelled(&self) -> bool {
        let deadline = self.deadline.lock().expect("snapshot progress deadline");
        if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            self.expire();
        }
        self.cancelled.load(Ordering::Acquire)
    }

    /// Renew only after real work or when entering a newly measured phase.
    /// Opaque whole-file operations (fs-verity, sync and validation) receive
    /// one second per MiB and per 1,000 captured rows, plus the stall grace.
    /// These are conservative work allowances, not a total build deadline:
    /// every completed export/hash unit renews them, with no elapsed-time cap.
    pub(super) fn sized_phase(&self, bytes: u64, rows: u64) -> std::io::Result<()> {
        let allowance = Duration::from_secs(bytes / (1024 * 1024))
            + Duration::from_nanos((bytes % (1024 * 1024)) * 1_000_000_000 / (1024 * 1024))
            + Duration::from_millis(rows);
        let mut deadline = self.deadline.lock().expect("snapshot progress deadline");
        let now = tokio::time::Instant::now();
        if deadline.is_some_and(|deadline| now >= deadline) {
            self.expire();
        }
        if self.cancelled.load(Ordering::Acquire) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "snapshot attempt expired or was cancelled",
            ));
        }
        let next = now + self.stall_timeout + allowance;
        let wake = deadline.is_none_or(|previous| next < previous);
        *deadline = Some(next);
        if wake {
            self.changed.notify_one();
        }
        Ok(())
    }

    pub(super) fn progress(&self) -> std::io::Result<()> {
        self.sized_phase(0, 0)
    }

    pub(super) async fn stalled(&self) {
        loop {
            let changed = self.changed.notified();
            let deadline = *self.deadline.lock().expect("snapshot progress deadline");
            match deadline {
                Some(deadline) => tokio::select! {
                    () = changed => {},
                    () = tokio::time::sleep_until(deadline) => {
                        // Progress can race the old timer. Recheck under the
                        // same lock that renews the deadline before revoking.
                        if self.cancelled() { return; }
                    },
                },
                None => changed.await,
            }
        }
    }

    pub(super) fn check(&self) -> std::io::Result<()> {
        if self.cancelled() {
            Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "snapshot attempt expired or was cancelled",
            ))
        } else {
            Ok(())
        }
    }
}

pub(super) struct CancelSnapshotAttempt(pub(super) Arc<SnapshotBuildAttempt>);

impl Drop for CancelSnapshotAttempt {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn waiting_for_worker_does_not_consume_the_stall_budget() {
        let attempt = SnapshotBuildAttempt::new(Duration::from_millis(100));
        let stalled = attempt.stalled();
        tokio::pin!(stalled);
        assert!(futures_util::poll!(&mut stalled).is_pending());
        tokio::time::advance(Duration::from_secs(120)).await;
        assert!(futures_util::poll!(&mut stalled).is_pending());
        assert!(!attempt.cancelled());
        attempt.start().unwrap();
        assert!(futures_util::poll!(&mut stalled).is_pending());
        tokio::time::advance(Duration::from_millis(101)).await;
        stalled.await;
        assert!(attempt.expired());
    }

    #[tokio::test(start_paused = true)]
    async fn progress_survives_old_timers_without_a_total_build_limit() {
        let attempt = SnapshotBuildAttempt::new(Duration::from_millis(100));
        attempt.start().unwrap();
        let stalled = attempt.stalled();
        tokio::pin!(stalled);
        for _ in 0..200 {
            assert!(futures_util::poll!(&mut stalled).is_pending());
            tokio::time::advance(Duration::from_millis(50)).await;
            attempt.progress().unwrap();
        }
        assert!(!attempt.expired());
        tokio::time::advance(Duration::from_millis(101)).await;
        stalled.await;
        assert!(
            attempt.progress().is_err(),
            "late progress cannot resurrect a revoked attempt"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn opaque_work_scales_with_bytes_and_rows_then_returns_to_stall_grace() {
        let attempt = SnapshotBuildAttempt::new(Duration::from_millis(100));
        attempt.start().unwrap();
        let stalled = attempt.stalled();
        tokio::pin!(stalled);
        assert!(futures_util::poll!(&mut stalled).is_pending());
        attempt.sized_phase(64 * 1024 * 1024, 10_000).unwrap();
        tokio::time::advance(Duration::from_secs(70)).await;
        assert!(futures_util::poll!(&mut stalled).is_pending());
        assert!(!attempt.cancelled());
        attempt.progress().unwrap();
        // Completing the large phase shortens its outstanding timer. A later
        // stalled publication still gets only the ordinary stall grace.
        assert!(futures_util::poll!(&mut stalled).is_pending());
        tokio::time::advance(Duration::from_millis(101)).await;
        stalled.await;
        assert!(attempt.sized_phase(u32::MAX.into(), 100_000).is_err());
    }
}
