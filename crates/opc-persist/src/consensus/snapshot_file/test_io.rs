//! Per-directory storage latency for real-file snapshot regressions.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

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
    verifications: AtomicU64,
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
            verifications: AtomicU64::new(0),
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
    let (release, held) = std::sync::mpsc::channel::<()>();
    let (finished, mut timeout) = oneshot::channel();
    let worker = std::thread::spawn(move || {
        let _ = finished.send(held.recv_timeout(Duration::from_secs(30)));
    });
    let result = tokio::select! {
        result = operation => result,
        result = &mut timeout => panic!("snapshot progress watchdog expired: {result:?}"),
    };
    drop(release);
    assert!(matches!(
        timeout.await.unwrap(),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
    ));
    worker.join().unwrap();
    result
}
