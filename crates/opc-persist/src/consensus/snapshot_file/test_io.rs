//! Per-directory storage latency for real-file snapshot regressions.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

tokio::task_local! {
    static WATCHDOG_PROGRESS: Weak<std::sync::mpsc::Sender<std::time::Instant>>;
}

/// A counter observed by snapshot regressions. Only actual increments report
/// progress; polling the counter or waking a future cannot hide a stall.
#[derive(Default)]
pub(crate) struct ProgressCounter {
    value: AtomicU64,
    watchdog: WatchdogProgress,
}

impl ProgressCounter {
    pub(crate) fn load(&self, ordering: Ordering) -> u64 {
        self.value.load(ordering)
    }

    pub(crate) fn fetch_add(&self, value: u64, ordering: Ordering) -> u64 {
        let previous = self.value.fetch_add(value, ordering);
        if value != 0 {
            self.watchdog.record();
        }
        previous
    }
}

struct WatchdogProgress(Weak<std::sync::mpsc::Sender<std::time::Instant>>);

impl Default for WatchdogProgress {
    fn default() -> Self {
        Self(WATCHDOG_PROGRESS.try_with(Weak::clone).unwrap_or_default())
    }
}

impl WatchdogProgress {
    fn record(&self) {
        if let Some(progress) = self.0.upgrade() {
            let _ = progress.send(std::time::Instant::now());
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    Read,
    Sync,
    Envelope,
    Backup,
}

struct Hooks {
    phase: Phase,
    progress: mpsc::UnboundedSender<oneshot::Sender<()>>,
    verifications: ProgressCounter,
}

static REGISTRY: OnceLock<Mutex<BTreeMap<PathBuf, Weak<Hooks>>>> = OnceLock::new();

pub(crate) struct Latency {
    root: PathBuf,
    hooks: Arc<Hooks>,
    pub(crate) progress: mpsc::UnboundedReceiver<oneshot::Sender<()>>,
}

impl Latency {
    pub(crate) fn new(root: &Path, phase: Phase) -> Self {
        let root = std::fs::canonicalize(root).unwrap();
        let (progress, receiver) = mpsc::unbounded_channel();
        let hooks = Arc::new(Hooks {
            phase,
            progress,
            verifications: ProgressCounter::default(),
        });
        assert!(REGISTRY
            .get_or_init(Mutex::default)
            .lock()
            .unwrap()
            .insert(root.clone(), Arc::downgrade(&hooks))
            .is_none());
        Self {
            root,
            hooks,
            progress: receiver,
        }
    }

    pub(crate) fn verifications(&self) -> u64 {
        self.hooks.verifications.load(Ordering::Acquire)
    }

    pub(crate) async fn run<T>(
        &mut self,
        delay: Duration,
        operation: impl Future<Output = T>,
    ) -> T {
        tokio::pin!(operation);
        loop {
            tokio::select! {
                result = &mut operation => return result,
                step = self.progress.recv() => {
                    let step = step.expect("registered latency source stays open");
                    // All actual file I/O runs on real time. Advance only while
                    // this explicit storage gate holds the next bounded read.
                    tokio::time::pause();
                    tokio::time::advance(delay).await;
                    tokio::time::resume();
                    let _ = step.send(());
                }
            }
        }
    }
}

impl Drop for Latency {
    fn drop(&mut self) {
        REGISTRY.get().unwrap().lock().unwrap().remove(&self.root);
        // Dropping queued acknowledgements releases readers even on assertion
        // failure, so a failed regression cannot strand an engine worker.
        self.progress.close();
        while self.progress.try_recv().is_ok() {}
    }
}

fn hooks(path: &Path) -> Option<Arc<Hooks>> {
    // Production paths are relative to a pinned /proc/self/fd directory.
    // Resolve the directory only, so an opened stream can remain registered
    // even after publication has retired and unlinked its file name.
    let path = std::fs::canonicalize(path.parent()?)
        .ok()?
        .join(path.file_name()?);
    REGISTRY
        .get()?
        .lock()
        .unwrap()
        .iter()
        .find_map(|(root, weak)| path.starts_with(root).then(|| weak.upgrade()).flatten())
}

pub(crate) fn gate(path: &Path, phase: Phase) -> Option<oneshot::Receiver<()>> {
    let hooks = hooks(path).filter(|hooks| hooks.phase == phase)?;
    let (release, released) = oneshot::channel();
    hooks.progress.send(release).ok()?;
    hooks.verifications.watchdog.record();
    Some(released)
}

pub(crate) async fn step(path: &Path, phase: Phase) {
    if let Some(gate) = gate(path, phase) {
        let _ = gate.await;
    }
}

pub(crate) fn blocking_step(path: &Path, phase: Phase) {
    if let Some(gate) = gate(path, phase) {
        let _ = gate.blocking_recv();
    }
}

pub(crate) fn verification(path: &Path) {
    if let Some(hooks) = hooks(path) {
        hooks.verifications.fetch_add(1, Ordering::AcqRel);
    }
}

pub(crate) async fn watchdog<T>(operation: impl Future<Output = T>) -> T {
    let (release, held) = std::sync::mpsc::channel::<std::time::Instant>();
    let release = Arc::new(release);
    let (finished, mut timeout) = oneshot::channel();
    let started = std::time::Instant::now();
    let worker = std::thread::spawn(move || {
        let mut last_progress = started;
        let result = loop {
            let remaining = Duration::from_secs(30).saturating_sub(last_progress.elapsed());
            match held.recv_timeout(remaining) {
                // Use observation time, not receive time: queued events cannot
                // extend a stall when this worker was temporarily descheduled.
                Ok(observed) => last_progress = last_progress.max(observed),
                Err(error) => break Err::<(), _>(error),
            }
        };
        let _ = finished.send(result);
    });
    // Weak handles cross engine/SQLite workers with the observed counters and
    // directory hooks. Another test's activity cannot refresh this guard, and
    // retained hooks cannot prevent the completion disconnect below.
    let operation = WATCHDOG_PROGRESS.scope(Arc::downgrade(&release), operation);
    let result = tokio::select! {
        biased;
        result = &mut timeout => panic!("snapshot progress watchdog expired: {result:?}"),
        result = operation => result,
    };
    drop(release);
    assert!(matches!(
        timeout.await.unwrap(),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
    ));
    worker.join().unwrap();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::FutureExt;
    use std::panic::AssertUnwindSafe;

    #[tokio::test]
    async fn watchdog_allows_slow_observable_progress_beyond_thirty_seconds() {
        let started = std::time::Instant::now();
        watchdog(async {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("snapshot");
            let mut latency = Latency::new(directory.path(), Phase::Read);
            let counters = crate::consensus::storage::SnapshotTestHooks::default();

            // Slow the real observations, not Tokio's virtual clock. Each
            // interval is healthy, but their sum exceeds a total-time bound.
            tokio::time::sleep(Duration::from_secs(11)).await;
            verification(&path);
            assert_eq!(latency.verifications(), 1);
            eprintln!("verification progress at {:?}", started.elapsed());

            tokio::time::sleep(Duration::from_secs(11)).await;
            counters.reads_started.fetch_add(1, Ordering::AcqRel);
            assert_eq!(counters.reads_started.load(Ordering::Acquire), 1);
            eprintln!("reader counter progress at {:?}", started.elapsed());

            tokio::time::sleep(Duration::from_secs(11)).await;
            let released = gate(&path, Phase::Read).unwrap();
            latency.progress.recv().await.unwrap().send(()).unwrap();
            released.await.unwrap();
            assert_eq!(latency.verifications(), 1);
            eprintln!("read gate progress at {:?}", started.elapsed());
        })
        .await;
        assert!(started.elapsed() >= Duration::from_secs(33));
    }

    #[tokio::test]
    async fn watchdog_rejects_a_stall_despite_unrelated_progress() {
        // Created outside the guarded operation: this activity must never
        // refresh that operation's independent stall window.
        let directory = tempfile::tempdir().unwrap();
        let foreign = Latency::new(directory.path(), Phase::Read);
        let path = directory.path().join("unrelated");
        let unrelated = tokio::spawn(async move {
            loop {
                verification(&path);
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        let started = std::time::Instant::now();
        let result = AssertUnwindSafe(watchdog(async {
            let counters = crate::consensus::storage::SnapshotTestHooks::default();
            counters.reads_started.fetch_add(1, Ordering::AcqRel);
            std::future::pending::<()>().await;
        }))
        .catch_unwind()
        .await;
        unrelated.abort();
        assert!(unrelated.await.unwrap_err().is_cancelled());
        assert!(foreign.verifications() > 0);
        let panic = result.expect_err("a genuine stall must expire");
        let message = panic.downcast_ref::<String>().unwrap();
        assert!(message.contains("snapshot progress watchdog expired: Ok(Err(Timeout))"));
        assert!(started.elapsed() >= Duration::from_secs(30));
        eprintln!("true stall rejected after {:?}", started.elapsed());
    }

    #[tokio::test]
    async fn watchdog_disconnects_with_observed_hooks_still_alive() {
        let counters = watchdog(async {
            let counters = crate::consensus::storage::SnapshotTestHooks::default();
            counters.reads_started.fetch_add(1, Ordering::AcqRel);
            counters
        })
        .await;
        assert_eq!(counters.reads_started.load(Ordering::Acquire), 1);
    }
}
