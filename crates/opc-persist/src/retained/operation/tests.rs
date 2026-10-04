use super::*;
use crate::{
    ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId,
    ConfigConsensusIdentity, ConfigConsensusNodeId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Condvar, Mutex};
use std::task::Poll;

// Each case has a private process-wide gate, independent of other lib tests.
// The child runs exactly the selected case; no global fixture or production
// environment variable can enable these private unit-test hooks.
fn isolated(name: &str, sentinel: &str, body: impl Future<Output = ()>) {
    const CASE: &str = "OPC_RETAINED_OPERATION_TEST_CASE";
    if std::env::var(CASE).as_deref() != Ok(name) {
        let output = std::process::Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", name, "--nocapture", "--test-threads=1"])
            .env(CASE, name)
            .output()
            .expect("isolated retained operation test");
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        assert!(output.status.success(), "{sentinel}: isolated child failed");
        return;
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime")
        .block_on(body);
}

fn options(path: &Path) -> RetainedConfigOptions {
    let node = ConfigConsensusNodeId::new(1).expect("node");
    let topology = ConfigConsensusTopology::try_new(
        ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::from_bytes([0x31; 32]),
            ConfigConsensusConfigurationId::from_bytes([0x32; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
        ),
        node,
        BTreeSet::from([node]),
    )
    .expect("topology");
    RetainedConfigOptions::new(
        path,
        RetainedConfigBinding::new(topology, [0x41; 32], [0x42; 32]).expect("binding"),
        RetainedConfigDurability::Ephemeral,
        16 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .expect("options")
}

fn key() -> AuditKey {
    AuditKey::new([0x71; 32]).expect("key")
}

fn work(options: &RetainedConfigOptions) -> AdmissionWork {
    AdmissionWork {
        cancelled: AtomicBool::new(false),
        mutated: AtomicBool::new(false),
        deadline: Instant::now() + options.operation_timeout,
        hook: None,
        lock_hook: None,
        completion_hook: None,
    }
}

async fn provision(path: &Path) {
    let backend = SqliteBackend::provision_config_authority(options(path), key())
        .await
        .expect("provision fixture");
    dispose(backend).await;
}

async fn dispose(backend: SqliteBackend) {
    tokio::task::spawn_blocking(move || drop(backend))
        .await
        .expect("dispose fixture backend");
}

fn files(path: &Path) -> BTreeMap<std::ffi::OsString, Vec<u8>> {
    std::fs::read_dir(path)
        .expect("fixture directory")
        .map(|entry| {
            let entry = entry.expect("fixture entry");
            (
                entry.file_name(),
                std::fs::read(entry.path()).expect("fixture bytes"),
            )
        })
        .collect()
}

struct Pause {
    entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    released: Mutex<bool>,
    changed: Condvar,
}

impl Pause {
    fn block(&self) {
        if let Some(entered) = self.entered.lock().expect("entered lock").take() {
            let _ = entered.send(());
        }
        let released = self.released.lock().expect("release lock");
        drop(
            self.changed
                .wait_while(released, |released| !*released)
                .expect("release wait"),
        );
    }

    fn release(&self) {
        *self.released.lock().expect("release lock") = true;
        self.changed.notify_all();
    }
}

struct Hold {
    pause: Arc<Pause>,
    entered: tokio::sync::oneshot::Receiver<()>,
}

impl Hold {
    fn new() -> Self {
        let (entered, receiver) = tokio::sync::oneshot::channel();
        Self {
            pause: Arc::new(Pause {
                entered: Mutex::new(Some(entered)),
                released: Mutex::new(false),
                changed: Condvar::new(),
            }),
            entered: receiver,
        }
    }

    async fn entered(&mut self) {
        tokio::time::timeout(Duration::from_secs(10), &mut self.entered)
            .await
            .expect("held work was not reached")
            .expect("held work signal");
    }

    fn release(&self) {
        self.pause.release();
    }

    fn hook(&self, target: &'static str) -> AdmissionTestHook {
        let pause = Arc::clone(&self.pause);
        Arc::new(move |_, stage| {
            if stage == target {
                pause.block();
            }
        })
    }
}

impl Drop for Hold {
    fn drop(&mut self) {
        self.release();
    }
}

async fn poll_once<F: Future>(mut future: Pin<&mut F>) -> Poll<F::Output> {
    std::future::poll_fn(|cx| Poll::Ready(future.as_mut().poll(cx))).await
}

fn lock_held(path: &Path) -> bool {
    let file = open_file(&lock_path(path), true, false).expect("admission file");
    match AdmissionFileLock::acquire(file) {
        Ok(lock) => {
            drop(lock);
            false
        }
        Err(RetainedConfigError::InUse) => true,
        Err(error) => panic!("unexpected lock probe: {error}"),
    }
}

// Independent cleanup is deliberate: removal controls may falsely report
// retirement. Do not rely on the method under test to clean up their workers.
async fn drain(operation: &mut RetainedConfigOpen) {
    operation.cancel();
    let state = std::mem::replace(
        &mut operation.state,
        OpenState::Retired(RetainedConfigOpenRetirement::Released {
            admission_error: RetainedConfigError::Indeterminate,
        }),
    );
    match state {
        OpenState::Opening(worker) => {
            let output = worker.await.expect("cleanup opening worker");
            tokio::task::spawn_blocking(move || drop(output))
                .await
                .expect("cleanup opening output");
        }
        OpenState::Discarding(worker) => worker.await.expect("cleanup disposal worker"),
        OpenState::Retired(_) => {}
    }
}

fn cleanup_marker(path: &Path, marker: &str) {
    assert_eq!(
        ADMISSION_GATE.available_permits(),
        4,
        "cleanup: all slots released"
    );
    assert!(!lock_held(path), "cleanup: retained lock released");
    eprintln!("{marker}");
}

#[test]
fn cancelled_wait_and_join_keep_live_admission() {
    isolated(
        "retained::operation::tests::cancelled_wait_and_join_keep_live_admission",
        "RETAINED_WAIT_JOIN_SENTINEL",
        async {
            let dir = tempfile::tempdir().expect("storage");
            let path = dir.path().join("retained.sqlite");
            provision(&path).await;
            let before = files(dir.path());
            let options = options(&path);
            let mut admission = work(&options);
            let mut hold = Hold::new();
            admission.hook = Some(hold.hook("before_original_open"));
            let mut operation =
                RetainedConfigOpen::start(options, key(), OpenIntent::Reopen, Arc::new(admission))
                    .expect("begin held reopen");
            hold.entered().await;
            let held = lock_held(&path) && ADMISSION_GATE.available_permits() == 3;
            let wait_pending = {
                let mut wait = Box::pin(operation.wait());
                poll_once(wait.as_mut()).await.is_pending()
            };
            let cancellation_requested = operation.work.cancelled.load(Ordering::Acquire);
            // Avoid a second wait in the removed-cancellation control; record
            // the failed contract, then still release and join real work.
            let denied = cancellation_requested
                && matches!(
                    operation.wait().await,
                    Err(RetainedConfigError::Indeterminate)
                );
            let join_pending = {
                let mut shutdown = Box::pin(operation.cancel_and_join());
                poll_once(shutdown.as_mut()).await.is_pending()
            };
            let retry_owned =
                matches!(&operation.state, OpenState::Opening(worker) if !worker.is_finished());
            let still_held = lock_held(&path) && ADMISSION_GATE.available_permits() == 3;
            hold.release();
            let report = operation.cancel_and_join().await;
            let repeated = operation.cancel_and_join().await;
            drain(&mut operation).await;
            let unchanged = before == files(dir.path());
            cleanup_marker(&path, "RETAINED_WAIT_JOIN_CLEANUP_COMPLETE");
            assert!(
                held && wait_pending
                    && cancellation_requested
                    && denied
                    && join_pending
                    && retry_owned
                    && still_held
                    && unchanged
                    && report == repeated
                    && report
                        == RetainedConfigOpenRetirement::Released {
                            admission_error: RetainedConfigError::AdmissionBound,
                        },
                "RETAINED_WAIT_JOIN_SENTINEL"
            );
            eprintln!("RETAINED_WAIT_JOIN_PASS");
        },
    );
}

#[test]
fn expired_wait_keeps_actual_worker_until_join() {
    isolated(
        "retained::operation::tests::expired_wait_keeps_actual_worker_until_join",
        "RETAINED_DEADLINE_SENTINEL",
        async {
            let dir = tempfile::tempdir().expect("storage");
            let path = dir.path().join("retained.sqlite");
            provision(&path).await;
            let before = files(dir.path());
            let options = options(&path);
            let mut admission = work(&options);
            let original_deadline = admission.deadline;
            let mut hold = Hold::new();
            admission.hook = Some(hold.hook("before_original_open"));
            let mut operation =
                RetainedConfigOpen::start(options, key(), OpenIntent::Reopen, Arc::new(admission))
                    .expect("begin expiring reopen");
            hold.entered().await;
            // Keep the fixture's original thirty-second admission deadline.
            let elapsed = matches!(
                operation.wait().await,
                Err(RetainedConfigError::Indeterminate)
            ) && Instant::now() >= original_deadline;
            let cancelled = operation.work.cancelled.load(Ordering::Acquire);
            let held = lock_held(&path) && ADMISSION_GATE.available_permits() == 3;
            let join_pending = {
                let mut shutdown = Box::pin(operation.cancel_and_join());
                poll_once(shutdown.as_mut()).await.is_pending()
            };
            hold.release();
            let report = operation.cancel_and_join().await;
            drain(&mut operation).await;
            let unchanged = before == files(dir.path());
            cleanup_marker(&path, "RETAINED_DEADLINE_CLEANUP_COMPLETE");
            assert!(
                elapsed
                    && cancelled
                    && held
                    && join_pending
                    && unchanged
                    && report
                        == RetainedConfigOpenRetirement::Released {
                            admission_error: RetainedConfigError::AdmissionBound,
                        },
                "RETAINED_DEADLINE_SENTINEL"
            );
            eprintln!("RETAINED_DEADLINE_PASS");
        },
    );
}

struct CloseProbe {
    path: PathBuf,
    pause: Option<Arc<Pause>>,
    saw_lock: Arc<AtomicBool>,
    off_runtime: Arc<AtomicBool>,
    runtime_thread: std::thread::ThreadId,
}

impl Drop for CloseProbe {
    fn drop(&mut self) {
        self.saw_lock
            .store(lock_held(&self.path), Ordering::Release);
        self.off_runtime.store(
            std::thread::current().id() != self.runtime_thread,
            Ordering::Release,
        );
        if let Some(pause) = &self.pause {
            pause.block();
        }
    }
}

fn close_probe(
    path: &Path,
    hold: Option<&Hold>,
) -> (
    AdmissionCompletionTestHook,
    Arc<AtomicBool>,
    Arc<AtomicBool>,
) {
    let path = path.to_path_buf();
    let pause = hold.map(|hold| Arc::clone(&hold.pause));
    let saw_lock = Arc::new(AtomicBool::new(false));
    let off_runtime = Arc::new(AtomicBool::new(false));
    let observed_lock = Arc::clone(&saw_lock);
    let observed_thread = Arc::clone(&off_runtime);
    let runtime_thread = std::thread::current().id();
    let hook: AdmissionCompletionTestHook = Arc::new(move |backend| {
        let probe = CloseProbe {
            path: path.clone(),
            pause: pause.clone(),
            saw_lock: Arc::clone(&observed_lock),
            off_runtime: Arc::clone(&observed_thread),
            runtime_thread,
        };
        // The existing BackendConnection must keep its admission even after
        // rusqlite removes this authorizer at the beginning of SQLite close.
        backend
            .conn()
            .blocking_lock()
            .authorizer(Some(move |_: rusqlite::hooks::AuthContext<'_>| {
                let _ = &probe;
                rusqlite::hooks::Authorization::Allow
            }))
            .expect("close observer");
    });
    (hook, saw_lock, off_runtime)
}

#[test]
fn late_success_is_discarded_before_retirement() {
    isolated(
        "retained::operation::tests::late_success_is_discarded_before_retirement",
        "RETAINED_LATE_SUCCESS_SENTINEL",
        async {
            let dir = tempfile::tempdir().expect("storage");
            let path = dir.path().join("retained.sqlite");
            provision(&path).await;
            let options = options(&path);
            let mut admission = work(&options);
            // Inject cancellation at the exact result-transfer boundary after
            // a real successful open, rather than fabricate a backend result.
            admission.hook = Some(Arc::new(|work, stage| {
                if stage == "before_transfer" {
                    work.cancelled.store(true, Ordering::Release);
                }
            }));
            let (hook, saw_lock, off_runtime) = close_probe(&path, None);
            admission.completion_hook = Some(hook);
            let mut operation =
                RetainedConfigOpen::start(options, key(), OpenIntent::Reopen, Arc::new(admission))
                    .expect("begin real reopen");
            let denied = match operation.wait().await {
                Ok(backend) => {
                    // The removal control must clean up its escaped capability
                    // before failing the late-success sentinel.
                    dispose(backend).await;
                    false
                }
                Err(error) => error == RetainedConfigError::Indeterminate,
            };
            let report = operation.cancel_and_join().await;
            drain(&mut operation).await;
            cleanup_marker(&path, "RETAINED_LATE_SUCCESS_CLEANUP_COMPLETE");
            assert!(
                denied
                    && saw_lock.load(Ordering::Acquire)
                    && off_runtime.load(Ordering::Acquire)
                    && report
                        == RetainedConfigOpenRetirement::Released {
                            admission_error: RetainedConfigError::Indeterminate,
                        },
                "RETAINED_LATE_SUCCESS_SENTINEL"
            );
            eprintln!("RETAINED_LATE_SUCCESS_PASS");
        },
    );
}

#[test]
fn cancelled_disposal_join_keeps_connection_lock_and_slot() {
    isolated(
        "retained::operation::tests::cancelled_disposal_join_keeps_connection_lock_and_slot",
        "RETAINED_DISPOSAL_JOIN_SENTINEL",
        async {
            let dir = tempfile::tempdir().expect("storage");
            let path = dir.path().join("retained.sqlite");
            provision(&path).await;
            let options = options(&path);
            let mut admission = work(&options);
            let mut opened = Hold::new();
            admission.hook = Some(opened.hook("worker_succeeded"));
            let inherited = Arc::new(Mutex::new(None));
            let inherited_target = Arc::clone(&inherited);
            admission.lock_hook = Some(Arc::new(move |file| {
                *inherited_target.lock().expect("inherited lock") =
                    Some(file.try_clone().expect("inherited descriptor"));
            }));
            let mut closing = Hold::new();
            let (hook, saw_lock, off_runtime) = close_probe(&path, Some(&closing));
            admission.completion_hook = Some(hook);
            let mut operation =
                RetainedConfigOpen::start(options, key(), OpenIntent::Reopen, Arc::new(admission))
                    .expect("begin real successful reopen");
            opened.entered().await;
            let opened_held = lock_held(&path) && ADMISSION_GATE.available_permits() == 3;
            opened.release();
            let returned_early = {
                let mut shutdown = Box::pin(operation.cancel_and_join());
                tokio::select! {
                    biased;
                    _ = closing.entered() => false,
                    _ = &mut shutdown => true,
                }
            };
            let cleanup_owned = matches!(&operation.state, OpenState::Discarding(_));
            let close_held = lock_held(&path) && ADMISSION_GATE.available_permits() == 3;
            let retry_pending = {
                let mut shutdown = Box::pin(operation.cancel_and_join());
                poll_once(shutdown.as_mut()).await.is_pending()
            };
            closing.release();
            let report = operation.cancel_and_join().await;
            drain(&mut operation).await;
            // Keep the duplicated file description alive through the probe:
            // successful disposal must explicitly unlock despite that owner.
            let released_with_duplicate = !lock_held(&path);
            drop(inherited.lock().expect("inherited lock").take());
            cleanup_marker(&path, "RETAINED_DISPOSAL_JOIN_CLEANUP_COMPLETE");
            assert!(
                opened_held
                    && !returned_early
                    && cleanup_owned
                    && close_held
                    && retry_pending
                    && released_with_duplicate
                    && saw_lock.load(Ordering::Acquire)
                    && off_runtime.load(Ordering::Acquire)
                    && report
                        == RetainedConfigOpenRetirement::Released {
                            admission_error: RetainedConfigError::Indeterminate,
                        },
                "RETAINED_DISPOSAL_JOIN_SENTINEL"
            );
            eprintln!("RETAINED_DISPOSAL_JOIN_PASS");
        },
    );
}

#[test]
fn owned_open_preserves_provision_repair_and_existing_only_outcomes() {
    isolated(
        "retained::operation::tests::owned_open_preserves_provision_repair_and_existing_only_outcomes",
        "RETAINED_LIFECYCLE_SENTINEL",
        async {
            let dir = tempfile::tempdir().expect("storage");
            let path = dir.path().join("retained.sqlite");
            let mut creation = SqliteBackend::begin_provision_config_authority(options(&path), key())
                .expect("begin provision");
            let backend = creation.wait().await.expect("provision authority");
            let granted = creation.cancel_and_join().await
                == RetainedConfigOpenRetirement::BackendReturned;
            let still_held = lock_held(&path);
            let mut duplicate = SqliteBackend::begin_reopen_config_authority(options(&path), key())
                .expect("begin duplicate");
            let in_use = matches!(duplicate.wait().await, Err(RetainedConfigError::InUse));
            let _ = duplicate.cancel_and_join().await;
            dispose(backend).await;
            let mut reopen = SqliteBackend::begin_reopen_config_authority(options(&path), key())
                .expect("begin reopen");
            let backend = reopen.wait().await.expect("reopen authority");
            let authority = !backend.retained_repair_only;
            dispose(backend).await;
            let _ = reopen.cancel_and_join().await;
            let exists = matches!(
                SqliteBackend::provision_config_authority(options(&path), key()).await,
                Err(RetainedConfigError::AlreadyExists)
            );
            let repair_path = dir.path().join("repair.sqlite");
            let mut repair = SqliteBackend::begin_provision_config_member_repair(
                options(&repair_path),
                key(),
            )
            .expect("begin member repair");
            let backend = repair.wait().await.expect("provision repair member");
            let repair_only = backend.retained_repair_only;
            dispose(backend).await;
            let _ = repair.cancel_and_join().await;
            let backend = SqliteBackend::reopen_config_authority(options(&repair_path), key())
                .await
                .expect("ordinary repair reopen");
            let repair_preserved = backend.retained_repair_only;
            dispose(backend).await;
            let missing_path = dir.path().join("missing.sqlite");
            let mut missing = SqliteBackend::begin_reopen_config_authority(
                options(&missing_path),
                key(),
            )
            .expect("begin existing-only missing reopen");
            let missing_rejected = matches!(
                missing.wait().await,
                Err(RetainedConfigError::RecoveryRequired)
            );
            let _ = missing.cancel_and_join().await;
            let before = files(dir.path());
            let mut wrong = options(&path);
            wrong.binding.backing_identity = [0x43; 32];
            let rejected = matches!(
                SqliteBackend::reopen_config_authority(wrong, key()).await,
                Err(RetainedConfigError::Rejected)
            );
            let unchanged = before == files(dir.path());
            cleanup_marker(&path, "RETAINED_LIFECYCLE_CLEANUP_COMPLETE");
            assert!(
                granted && still_held && in_use && authority && exists && repair_only
                    && repair_preserved && missing_rejected && !missing_path.exists()
                    && !lock_path(&missing_path).exists() && rejected && unchanged,
                "RETAINED_LIFECYCLE_SENTINEL"
            );
            eprintln!("RETAINED_LIFECYCLE_PASS");
        },
    );
}

#[test]
fn four_held_workers_exhaust_admission_until_actual_retirement() {
    isolated(
        "retained::operation::tests::four_held_workers_exhaust_admission_until_actual_retirement",
        "RETAINED_FOUR_SLOT_SENTINEL",
        async {
            let dir = tempfile::tempdir().expect("storage");
            let mut operations = Vec::new();
            let mut holds = Vec::new();
            let mut paths = Vec::new();
            for member in 0..4 {
                let path = dir.path().join(format!("retained-{member}.sqlite"));
                provision(&path).await;
                let options = options(&path);
                let mut admission = work(&options);
                let mut hold = Hold::new();
                admission.hook = Some(hold.hook("before_original_open"));
                let operation = RetainedConfigOpen::start(
                    options,
                    key(),
                    OpenIntent::Reopen,
                    Arc::new(admission),
                )
                .expect("begin bounded worker");
                hold.entered().await;
                paths.push(path);
                holds.push(hold);
                operations.push(operation);
            }
            let all_held =
                ADMISSION_GATE.available_permits() == 0 && paths.iter().all(|path| lock_held(path));
            for operation in &operations {
                operation.cancel();
            }
            let overflow_path = dir.path().join("overflow.sqlite");
            let denied = match SqliteBackend::begin_provision_config_authority(
                options(&overflow_path),
                key(),
            ) {
                Err(error) => error == RetainedConfigError::AdmissionBound,
                Ok(mut unexpected) => {
                    unexpected.cancel();
                    let _ = unexpected.cancel_and_join().await;
                    drain(&mut unexpected).await;
                    false
                }
            };
            let mut joins_pending = true;
            for operation in &mut operations {
                let mut shutdown = Box::pin(operation.cancel_and_join());
                joins_pending &= poll_once(shutdown.as_mut()).await.is_pending();
            }
            let charged_after_cancel = ADMISSION_GATE.available_permits() == 0;
            for hold in &holds {
                hold.release();
            }
            for operation in &mut operations {
                let _ = operation.cancel_and_join().await;
                drain(operation).await;
            }
            let all_released = paths.iter().all(|path| !lock_held(path));
            cleanup_marker(&paths[0], "RETAINED_FOUR_SLOT_CLEANUP_COMPLETE");
            assert!(
                all_held
                    && denied
                    && joins_pending
                    && charged_after_cancel
                    && all_released
                    && !overflow_path.exists()
                    && !lock_path(&overflow_path).exists(),
                "RETAINED_FOUR_SLOT_SENTINEL"
            );
            eprintln!("RETAINED_FOUR_SLOT_PASS");
        },
    );
}
