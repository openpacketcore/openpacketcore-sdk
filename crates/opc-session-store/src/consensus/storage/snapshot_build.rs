//! Per-store snapshot attempt limits and cancellation ownership.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub(super) const SNAPSHOT_BUILD_TIMEOUT: Duration = Duration::from_secs(60);
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
            attempt_millis: AtomicU64::new(SNAPSHOT_BUILD_TIMEOUT.as_millis() as u64),
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
        assert!(!attempt.is_zero() && attempt <= SNAPSHOT_BUILD_TIMEOUT);
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
    deadline: tokio::time::Instant,
    cancelled: AtomicBool,
    expired: AtomicBool,
    published: AtomicBool,
}

impl SnapshotBuildAttempt {
    pub(super) fn new(timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            deadline: tokio::time::Instant::now() + timeout,
            cancelled: AtomicBool::new(false),
            expired: AtomicBool::new(false),
            published: AtomicBool::new(false),
        })
    }

    pub(super) fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }

    pub(super) fn expire(&self) {
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
        if tokio::time::Instant::now() >= self.deadline {
            self.expire();
        }
        self.cancelled.load(Ordering::Acquire)
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
