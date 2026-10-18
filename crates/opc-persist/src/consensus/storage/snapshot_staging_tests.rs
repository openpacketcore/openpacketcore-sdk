//! Runtime teardown at the actual SQLite commit authorization boundary.

use std::collections::BTreeSet;
use std::time::Duration;

use opc_consensus::engine::{CommittedLeaderId, EntryPayload, Membership};
use tokio::runtime::{Builder, Runtime};

use super::*;
use crate::consensus::{
    ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId,
};

const WATCHDOG: Duration = Duration::from_secs(10);

fn runtime() -> Runtime {
    Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("snapshot runtime")
}

fn identity() -> ConsensusIdentity {
    ConsensusIdentity::new(
        ConfigConsensusClusterId::new("snapshot-staging-owner-tests").expect("cluster"),
        ConfigConsensusConfigurationId::from_bytes([0x74; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
    )
}

fn node() -> ConsensusNodeId {
    ConsensusNodeId::new(1).expect("voter")
}

fn members() -> BTreeSet<ConsensusNodeId> {
    BTreeSet::from([node()])
}

fn log_id(index: u64) -> LogId<ConsensusNodeId> {
    LogId::new(CommittedLeaderId::new(1, node()), index)
}

fn membership() -> Entry<ConfigRaftTypeConfig> {
    Entry {
        log_id: log_id(0),
        payload: EntryPayload::Membership(Membership::new(vec![members()], members())),
    }
}

fn blank() -> Entry<ConfigRaftTypeConfig> {
    Entry {
        log_id: log_id(1),
        payload: EntryPayload::Blank,
    }
}

async fn backend(path: &Path) -> SqliteBackend {
    SqliteBackend::open_with_audit_key(
        path,
        true,
        0,
        crate::AuditKey::new([0x74; 32]).expect("audit key"),
    )
    .await
    .expect("config backend")
}

fn files(path: &Path) -> BTreeSet<String> {
    std::fs::read_dir(path)
        .expect("snapshot directory")
        .map(|entry| {
            entry
                .expect("snapshot entry")
                .file_name()
                .into_string()
                .expect("fixture filename")
        })
        .collect()
}

fn runtime_drop_during_commit(install: bool, probe_ongoing_commit: bool) {
    let temp = tempfile::tempdir().expect("snapshot fixture");
    let database = temp.path().join("config.sqlite");
    let snapshots = temp.path().join("snapshots");
    let old_runtime = runtime();
    let config_backend = old_runtime.block_on(backend(&database));
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let (task, mut owner, previous) = old_runtime.block_on(async {
        let (_, mut machine, _) = open(&config_backend, &snapshots, identity(), members())
            .await
            .expect("initial snapshot owner");
        machine.apply([membership()]).await.expect("membership");
        let previous = machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("previous published snapshot");
        let previous = previous
            .snapshot
            .path()
            .file_name()
            .expect("previous filename")
            .to_str()
            .expect("previous filename UTF-8")
            .to_owned();
        let incoming = if install {
            let source_backend = backend(&temp.path().join("source.sqlite")).await;
            let (_, mut source, _) = open(
                &source_backend,
                temp.path().join("source-snapshots"),
                identity(),
                members(),
            )
            .await
            .expect("source snapshot owner");
            source
                .apply([membership(), blank()])
                .await
                .expect("incoming snapshot state");
            let mut snapshot = source
                .get_snapshot_builder()
                .await
                .build_snapshot()
                .await
                .expect("incoming snapshot");
            let mut receiving = machine.begin_receiving_snapshot().await.expect("receiver");
            tokio::io::copy(&mut snapshot.snapshot, &mut receiving)
                .await
                .expect("snapshot transport");
            Some((snapshot.meta, receiving))
        } else {
            machine.apply([blank()]).await.expect("new build cut");
            None
        };
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        *machine
            .core
            .snapshot_test_hooks
            .before_snapshot_commit
            .lock()
            .expect("commit pause slot") = Some(Box::new(move || {
            entered_tx.send(()).expect("commit pause observer");
            resume_rx
                .recv_timeout(WATCHDOG)
                .expect("bounded commit release");
        }));
        let owner = machine.core.storage_shutdown_observer();
        let task = tokio::spawn(async move {
            if let Some((meta, incoming)) = incoming {
                machine.install_snapshot(&meta, incoming).await
            } else {
                machine
                    .get_snapshot_builder()
                    .await
                    .build_snapshot()
                    .await
                    .map(drop)
            }
        });
        tokio::time::timeout(WATCHDOG, entered_rx)
            .await
            .expect("commit reached within watchdog")
            .expect("SQLite authorized the commit");
        (task, owner, previous)
    });
    let staged = files(&snapshots)
        .into_iter()
        .find(|name| name.starts_with("snapshot-") && name.ends_with(".opc") && name != &previous)
        .expect("new snapshot staged before commit");
    let expected_bytes = std::fs::read(snapshots.join(&staged)).expect("staged snapshot bytes");
    let expected_digest = Sha256::digest(&expected_bytes);

    // This consumes the actual runtime, cancelling its async tasks while the
    // authorized SQLite worker is still inside the real commit hook.
    old_runtime.shutdown_background();
    let next_runtime = runtime();
    next_runtime.block_on(async {
        let cancelled = tokio::time::timeout(WATCHDOG, task)
            .await
            .expect("runtime cancellation is bounded")
            .expect_err("runtime teardown must drop the snapshot future");
        assert!(cancelled.is_cancelled());
        if probe_ongoing_commit {
            let competing = tokio::time::timeout(
                WATCHDOG,
                open(&config_backend, &snapshots, identity(), members()),
            )
            .await
            .expect("a live commit owner must be rejected without waiting for SQLite");
            assert!(matches!(
                competing,
                Err(ConfigConsensusStorageError::BackendUnavailable)
            ));
            assert!(
                snapshots.join(&staged).is_file(),
                "the detached commit worker still owns the staged publication"
            );
        }
        resume_tx.send(()).expect("release authorized commit");
        assert!(
            tokio::time::timeout(WATCHDOG, owner.changed())
                .await
                .expect("blocking commit worker must finish")
                .is_err(),
            "every old storage owner must release before reopen"
        );
    });
    drop(config_backend);
    let before_open = files(&snapshots);
    eprintln!("install={install}: after runtime drop: {before_open:?}; committed={staged}");
    next_runtime.block_on(async {
        let reopened_backend = backend(&database).await;
        let reopened = tokio::time::timeout(
            WATCHDOG,
            open(&reopened_backend, &snapshots, identity(), members()),
        )
        .await
        .expect("next open is bounded");
        let after_open = files(&snapshots);
        eprintln!(
            "install={install}: next open error={:?}; files={after_open:?}",
            reopened.as_ref().err()
        );
        let (_, mut machine, _) = reopened.expect("next open must retain the committed snapshot");
        let mut published = machine
            .get_current_snapshot()
            .await
            .expect("read reopened snapshot")
            .expect("published snapshot survives runtime drop");
        let mut actual_bytes = Vec::new();
        published
            .snapshot
            .read_to_end(&mut actual_bytes)
            .await
            .expect("published bytes");
        assert_eq!(Some(log_id(1)), published.meta.last_log_id);
        assert_eq!(expected_digest, Sha256::digest(&actual_bytes));
        assert_eq!(
            BTreeSet::from([staged]),
            after_open,
            "stale staging is swept"
        );
    });
}

#[test]
fn runtime_drop_during_build_commit_recovers_staging() {
    runtime_drop_during_commit(false, false);
}

#[test]
fn runtime_drop_during_install_commit_recovers_staging() {
    runtime_drop_during_commit(true, false);
}

#[test]
fn runtime_drop_keeps_committing_workers_directory_owned() {
    runtime_drop_during_commit(false, true);
    runtime_drop_during_commit(true, true);
}

#[tokio::test]
async fn next_open_does_not_remove_a_live_owners_staging() {
    let temp = tempfile::tempdir().expect("snapshot fixture");
    let config_backend = backend(&temp.path().join("config.sqlite")).await;
    let snapshots = temp.path().join("snapshots");
    let (_, mut owner, _) = open(&config_backend, &snapshots, identity(), members())
        .await
        .expect("live snapshot owner");
    let mut staging = owner
        .begin_receiving_snapshot()
        .await
        .expect("live staging");
    staging
        .write_all(b"live snapshot transfer")
        .await
        .expect("write live staging");
    staging.sync_all().await.expect("flush live staging");
    let path = snapshots.join(staging.path().file_name().expect("staging filename"));
    let reopened = tokio::time::timeout(
        WATCHDOG,
        open(&config_backend, &snapshots, identity(), members()),
    )
    .await
    .expect("live-owner admission must remain bounded");
    assert!(
        path.is_file(),
        "another open must not remove a live owner's staging"
    );
    assert_eq!(
        b"live snapshot transfer",
        std::fs::read(&path).expect("live staging read").as_slice()
    );
    drop(reopened);
    drop(staging);
    assert!(
        !path.exists(),
        "the live owner still removes its own staging"
    );
}

#[tokio::test]
async fn snapshot_receiver_retains_ownership_after_its_core_is_dropped() {
    let temp = tempfile::tempdir().expect("snapshot fixture");
    let config_backend = backend(&temp.path().join("config.sqlite")).await;
    let snapshots = temp.path().join("snapshots");
    let (log, mut machine, _) = open(&config_backend, &snapshots, identity(), members())
        .await
        .expect("initial snapshot owner");
    let mut released = machine.core.storage_shutdown_observer();
    let mut staging = machine.begin_receiving_snapshot().await.expect("receiver");
    staging
        .write_all(b"owned transfer")
        .await
        .expect("transfer");
    staging.sync_all().await.expect("persist transfer");
    let path = snapshots.join(staging.path().file_name().expect("staging filename"));
    drop(log);
    drop(machine);
    assert!(
        released.has_changed().is_ok(),
        "receiver remains a storage owner"
    );
    let competing = tokio::time::timeout(
        WATCHDOG,
        open(&config_backend, &snapshots, identity(), members()),
    )
    .await
    .expect("owner exclusion is bounded");
    assert!(matches!(
        competing,
        Err(ConfigConsensusStorageError::BackendUnavailable)
    ));
    assert_eq!(
        b"owned transfer",
        std::fs::read(&path).expect("owned file").as_slice()
    );
    drop(staging);
    assert!(tokio::time::timeout(WATCHDOG, released.changed())
        .await
        .expect("receiver release is bounded")
        .is_err());
    assert!(
        !path.exists(),
        "receiver cleanup retains a usable directory descriptor"
    );
    open(&config_backend, &snapshots, identity(), members())
        .await
        .expect("dead owner releases admission automatically");
    assert!(files(&snapshots).is_empty());
}

#[tokio::test(start_paused = true)]
async fn stalled_snapshot_directory_io_remains_bounded() {
    let started = tokio::time::Instant::now();
    let error = snapshot_directory_io(std::future::pending::<io::Result<()>>())
        .await
        .expect_err("stalled cleanup must time out");
    assert_eq!(ConfigConsensusStorageError::BackendUnavailable, error);
    assert_eq!(SNAPSHOT_OPERATION_TIMEOUT, started.elapsed());
}

async fn interrupt_startup_sweep_repeatedly(expire: bool) {
    let temp = tempfile::tempdir().expect("snapshot fixture");
    let backend_a = backend(&temp.path().join("a.sqlite")).await;
    let backend_b = backend(&temp.path().join("b.sqlite")).await;
    let snapshots_a = temp.path().join("a-snapshots");
    let snapshots_b = temp.path().join("b-snapshots");
    let (log, mut machine, _) = open(&backend_b, &snapshots_b, identity(), members())
        .await
        .expect("initial B owner");
    machine
        .apply([membership(), blank()])
        .await
        .expect("published state");
    let published = machine
        .get_snapshot_builder()
        .await
        .build_snapshot()
        .await
        .expect("published B snapshot");
    let filename = published
        .snapshot
        .path()
        .file_name()
        .expect("published name")
        .to_owned();
    let expected_bytes = std::fs::read(snapshots_b.join(&filename)).expect("published bytes");
    let expected_meta = published.meta.clone();
    drop(published);
    drop(log);
    drop(machine);

    for _ in 0..3 {
        // Initialize exactly as open does, then pause its real startup sweep
        // immediately before the blocking unlink. No global hook or FD changes.
        let admitted = admit_snapshot_directory(&backend_a, snapshots_a.clone())
            .expect("A directory admission");
        std::fs::write(snapshots_a.join(&filename), &expected_bytes).expect("orphan in A");
        let core = sqlite::ConfigConsensusCore::initialize(
            &backend_a,
            admitted,
            identity(),
            members(),
            Arc::new(ConfigDurableProgress::default()),
            None,
        )
        .await
        .expect("A initialization before startup sweep");
        let mut released = core.storage_shutdown_observer();
        let (entered, started) = tokio::sync::oneshot::channel();
        let (resume, paused) = std::sync::mpsc::channel();
        *core
            .snapshot_test_hooks
            .before_snapshot_remove
            .lock()
            .expect("unlink hook") = Some(Box::new(move || {
            entered.send(()).expect("unlink started");
            paused.recv_timeout(WATCHDOG).expect("resume unlink");
        }));
        let task = tokio::spawn(async move { validate_and_clean_snapshot_directory(&core).await });
        tokio::time::timeout(WATCHDOG, started)
            .await
            .expect("startup unlink starts within watchdog")
            .expect("unlink hook entered");
        if expire {
            tokio::time::pause();
            // Cross the timer's millisecond rounding: the blocked filesystem
            // worker intentionally prevents Tokio's automatic clock advance.
            tokio::time::advance(SNAPSHOT_OPERATION_TIMEOUT + Duration::from_millis(1)).await;
            let result = task.await.expect("timed out startup task");
            tokio::time::resume();
            assert_eq!(Err(ConfigConsensusStorageError::BackendUnavailable), result);
        } else {
            task.abort();
            assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        }

        // Reopening B exercises normal descriptor allocation while A's actual
        // filesystem operation is still in flight after its caller has gone.
        let (live_log, mut live_b, _) = open(&backend_b, &snapshots_b, identity(), members())
            .await
            .expect("B can reopen while A's unlink is pending");
        let competing_a = tokio::time::timeout(
            WATCHDOG,
            open(&backend_a, &snapshots_a, identity(), members()),
        )
        .await
        .expect("A admission remains bounded");
        assert!(
            matches!(
                competing_a,
                Err(ConfigConsensusStorageError::BackendUnavailable)
            ),
            "cancelled startup must retain A admission until its actual unlink finishes"
        );
        assert!(
            matches!(
                open(&backend_b, &snapshots_b, identity(), members()).await,
                Err(ConfigConsensusStorageError::BackendUnavailable)
            ),
            "B is a live owner"
        );
        assert!(
            released.has_changed().is_ok(),
            "the detached unlink remains an owner"
        );
        resume.send(()).expect("release cancelled startup unlink");
        assert!(tokio::time::timeout(WATCHDOG, released.changed())
            .await
            .expect("actual unlink finishes within watchdog")
            .is_err());
        assert!(
            !snapshots_a.join(&filename).exists(),
            "late unlink cleans A's orphan"
        );
        assert_eq!(
            expected_bytes,
            std::fs::read(snapshots_b.join(&filename))
                .expect("A's cancelled sweep must preserve B's published snapshot")
        );
        let current = live_b
            .get_current_snapshot()
            .await
            .expect("live B read")
            .expect("live B publication");
        assert_eq!(expected_meta, current.meta);
        drop(current);
        drop(live_log);
        drop(live_b);
        let (_, mut reopened_b, _) = open(&backend_b, &snapshots_b, identity(), members())
            .await
            .expect("B reopens after A's late unlink");
        assert_eq!(
            expected_meta,
            reopened_b
                .get_current_snapshot()
                .await
                .expect("reopened B read")
                .expect("reopened B publication")
                .meta
        );
        open(&backend_a, &snapshots_a, identity(), members())
            .await
            .expect("A restarts without manual cleanup");
        assert!(files(&snapshots_a).is_empty());
    }
}

#[tokio::test]
async fn cancelled_startup_sweeps_keep_ownership_and_other_published_snapshots() {
    interrupt_startup_sweep_repeatedly(false).await;
}

#[tokio::test]
async fn timed_out_startup_sweeps_keep_ownership_and_other_published_snapshots() {
    interrupt_startup_sweep_repeatedly(true).await;
}

#[tokio::test]
async fn admission_reader_does_not_retain_a_retired_snapshot_owner() {
    let temp = tempfile::tempdir().expect("snapshot fixture");
    let config_backend = backend(&temp.path().join("config.sqlite")).await;
    let snapshots = temp.path().join("snapshots");
    let (log, machine, _) = open(&config_backend, &snapshots, identity(), members())
        .await
        .expect("initial snapshot owner");
    let reader = machine.core.clone_for_admission_reader();
    let mut released = machine.core.storage_shutdown_observer();
    drop(log);
    drop(machine);
    assert!(tokio::time::timeout(WATCHDOG, released.changed())
        .await
        .expect("engine owner drain is bounded")
        .is_err());
    let reopened = open(&config_backend, &snapshots, identity(), members())
        .await
        .expect("a retained admission reader cannot prevent restart");
    assert_eq!(reader.identity, reopened.0.core.identity);
    assert!(reader.snapshot_directory_owner().is_err());
}

#[tokio::test]
async fn staging_creation_finishing_after_cancellation_removes_its_file() {
    let temp = tempfile::tempdir().expect("snapshot fixture");
    let config_backend = backend(&temp.path().join("config.sqlite")).await;
    let snapshots = temp.path().join("snapshots");
    let (log, machine, _) = open(&config_backend, &snapshots, identity(), members())
        .await
        .expect("snapshot owner");
    let mut released = machine.core.storage_shutdown_observer();
    let path = machine.core.snapshot_dir.join("promote-delayed.part");
    let owner = machine.core.snapshot_directory_owner().expect("live owner");
    let (entered, started) = tokio::sync::oneshot::channel();
    let (resume, paused) = std::sync::mpsc::channel();
    let task = tokio::spawn(StagingArtifact::create_with_hook(
        path,
        false,
        owner,
        Some(Box::new(move || {
            entered.send(()).expect("creation started");
            paused.recv_timeout(WATCHDOG).expect("resume creation");
        })),
    ));
    tokio::time::timeout(WATCHDOG, started)
        .await
        .expect("creation starts within watchdog")
        .expect("creation hook");
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    drop(log);
    drop(machine);
    assert!(matches!(
        open(&config_backend, &snapshots, identity(), members()).await,
        Err(ConfigConsensusStorageError::BackendUnavailable)
    ));
    assert!(!snapshots.join("promote-delayed.part").exists());
    resume
        .send(())
        .expect("complete creation after cancellation");
    assert!(tokio::time::timeout(WATCHDOG, released.changed())
        .await
        .expect("creation releases ownership within watchdog")
        .is_err());
    assert!(files(&snapshots).is_empty(), "late creation cleans itself");
    open(&config_backend, &snapshots, identity(), members())
        .await
        .expect("restart after cancelled creation");
}

#[tokio::test]
async fn refused_staging_creation_preserves_an_existing_file() {
    let temp = tempfile::tempdir().expect("snapshot fixture");
    let config_backend = backend(&temp.path().join("config.sqlite")).await;
    let (_, machine, _) = open(
        &config_backend,
        temp.path().join("snapshots"),
        identity(),
        members(),
    )
    .await
    .expect("snapshot owner");
    let path = machine.core.snapshot_dir.join("incoming-existing.part");
    std::fs::write(&path, b"existing owner").expect("existing file");
    let result = StagingArtifact::create(
        path.clone(),
        false,
        machine.core.snapshot_directory_owner().expect("live owner"),
    )
    .await;
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::AlreadyExists));
    assert_eq!(
        std::fs::read(path).expect("existing file"),
        b"existing owner"
    );
}

#[cfg(unix)]
fn queued_snapshot_write_retains_owner(runtime_drop: bool, staging: bool) {
    use std::io::{Read as _, Seek as _};
    const BYTES: &[u8] = b"write queued before owner cancellation";
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("incoming-queued.part");
    let old_runtime = Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    let (task, blocker, resume, mut receiver, mut observed) = old_runtime.block_on(async {
        let dir = Arc::new(std::fs::File::open(directory.path()).unwrap());
        let lock =
            crate::local_sqlite::AdmissionFileLock::acquire(dir.try_clone().unwrap()).unwrap();
        let (sender, receiver) = tokio::sync::watch::channel(());
        let owner = Arc::new(SnapshotDirectoryOwner::new(dir, Arc::new(lock), sender));
        let (file, cleanup): (Box<dyn tokio::io::AsyncWrite + Unpin + Send>, _) = if staging {
            let (file, cleanup) = StagingArtifact::create(path.clone(), false, owner)
                .await
                .unwrap();
            (Box::new(file), Some(cleanup))
        } else {
            (
                Box::new(
                    ConfigSnapshotFile::create_owned(path.clone(), owner)
                        .await
                        .unwrap(),
                ),
                None,
            )
        };
        let observed = std::fs::File::open(&path).unwrap();
        let (entered, started) = tokio::sync::oneshot::channel();
        let (resume, paused) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            entered.send(()).unwrap();
            paused
                .recv_timeout(WATCHDOG)
                .expect("release the sole blocking worker");
        });
        tokio::time::timeout(WATCHDOG, started)
            .await
            .unwrap()
            .unwrap();
        let (queued, queued_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _cleanup = cleanup;
            let mut file = file;
            file.write_all(BYTES).await.unwrap();
            queued.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        tokio::time::timeout(WATCHDOG, queued_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            observed.metadata().unwrap().len(),
            0,
            "physical write is still queued"
        );
        (task, blocker, resume, receiver, observed)
    });
    let next_runtime = if runtime_drop {
        old_runtime.shutdown_background();
        runtime()
    } else {
        task.abort();
        old_runtime
    };
    next_runtime.block_on(async {
        assert!(tokio::time::timeout(WATCHDOG, task)
            .await
            .unwrap()
            .unwrap_err()
            .is_cancelled());
    });
    let closed_while_queued = receiver.has_changed().is_err();
    let admitted_while_queued = crate::local_sqlite::AdmissionFileLock::acquire(
        std::fs::File::open(directory.path()).unwrap(),
    )
    .is_ok();
    assert_eq!(
        observed.metadata().unwrap().len(),
        0,
        "write remains causally blocked"
    );
    resume.send(()).unwrap();
    next_runtime.block_on(async {
        tokio::time::timeout(WATCHDOG, blocker)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(WATCHDOG, async {
            while receiver.changed().await.is_ok() {}
        })
        .await
        .unwrap();
    });
    // Tokio's original queued write also executes after owner release. Wait for
    // it before the RED assertion so the failed test leaves no blocked worker.
    let deadline = std::time::Instant::now() + WATCHDOG;
    while observed.metadata().unwrap().len() == 0 && std::time::Instant::now() < deadline {
        std::thread::yield_now();
    }
    observed.rewind().unwrap();
    let mut bytes = Vec::new();
    observed.read_to_end(&mut bytes).unwrap();
    assert_eq!(
        bytes, BYTES,
        "the queued physical write completed after cancellation"
    );
    assert!(!path.exists(), "cancelled unpublished artifact is removed");
    assert!(crate::local_sqlite::AdmissionFileLock::acquire(
        std::fs::File::open(directory.path()).unwrap()
    )
    .is_ok());
    assert!(
        !closed_while_queued,
        "shutdown accounting must retain queued file work"
    );
    assert!(
        !admitted_while_queued,
        "queued file work must retain directory admission"
    );
}

#[test]
#[cfg(unix)]
fn queued_snapshot_receiver_write_retains_owner_after_task_abort() {
    queued_snapshot_write_retains_owner(false, false);
}

#[test]
#[cfg(unix)]
fn queued_snapshot_receiver_write_retains_owner_after_runtime_drop() {
    queued_snapshot_write_retains_owner(true, false);
}

#[test]
#[cfg(unix)]
fn queued_snapshot_staging_write_retains_owner_after_task_abort() {
    queued_snapshot_write_retains_owner(false, true);
}

#[test]
#[cfg(unix)]
fn queued_snapshot_staging_write_retains_owner_after_runtime_drop() {
    queued_snapshot_write_retains_owner(true, true);
}

#[test]
#[cfg(unix)]
fn queued_snapshot_staging_file_operations_retain_owner_after_cancellation() {
    use std::future::Future as _;
    use std::task::Poll;
    for runtime_drop in [false, true] {
        for operation in ["sync", "metadata", "permissions"] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("staged-operation.part");
            let old_runtime = Builder::new_current_thread()
                .enable_all()
                .max_blocking_threads(1)
                .build()
                .unwrap();
            let (task, blocker, resume, mut receiver) = old_runtime.block_on(async {
                let dir = Arc::new(std::fs::File::open(directory.path()).unwrap());
                let lock =
                    crate::local_sqlite::AdmissionFileLock::acquire(dir.try_clone().unwrap())
                        .unwrap();
                let (sender, receiver) = tokio::sync::watch::channel(());
                let owner = Arc::new(SnapshotDirectoryOwner::new(dir, Arc::new(lock), sender));
                let (mut file, cleanup) = StagingArtifact::create(path.clone(), false, owner)
                    .await
                    .unwrap();
                let permissions = std::fs::metadata(&path).unwrap().permissions();
                let (entered, started) = tokio::sync::oneshot::channel();
                let (resume, paused) = std::sync::mpsc::channel();
                let blocker = tokio::task::spawn_blocking(move || {
                    entered.send(()).unwrap();
                    paused
                        .recv_timeout(WATCHDOG)
                        .expect("release the sole blocking worker");
                });
                tokio::time::timeout(WATCHDOG, started)
                    .await
                    .unwrap()
                    .unwrap();
                let (queued, queued_rx) = tokio::sync::oneshot::channel();
                let task = tokio::spawn(async move {
                    let _cleanup = cleanup;
                    let mut work = Box::pin(async {
                        match operation {
                            "sync" => file.sync_all().await,
                            "metadata" => file.metadata().await.map(|_| ()),
                            "permissions" => file.set_permissions(permissions).await,
                            _ => unreachable!(),
                        }
                    });
                    std::future::poll_fn(|cx| {
                        assert!(
                            work.as_mut().poll(cx).is_pending(),
                            "operation must queue behind the blocker"
                        );
                        Poll::Ready(())
                    })
                    .await;
                    queued.send(()).unwrap();
                    std::future::pending::<()>().await;
                });
                tokio::time::timeout(WATCHDOG, queued_rx)
                    .await
                    .unwrap()
                    .unwrap();
                (task, blocker, resume, receiver)
            });
            let next_runtime = if runtime_drop {
                old_runtime.shutdown_background();
                runtime()
            } else {
                task.abort();
                old_runtime
            };
            next_runtime.block_on(async {
                assert!(tokio::time::timeout(WATCHDOG, task)
                    .await
                    .unwrap()
                    .unwrap_err()
                    .is_cancelled());
            });
            let closed_while_queued = receiver.has_changed().is_err();
            let admitted_while_queued = crate::local_sqlite::AdmissionFileLock::acquire(
                std::fs::File::open(directory.path()).unwrap(),
            )
            .is_ok();
            resume.send(()).unwrap();
            next_runtime.block_on(async {
                tokio::time::timeout(WATCHDOG, blocker)
                    .await
                    .unwrap()
                    .unwrap();
                tokio::time::timeout(WATCHDOG, async {
                    while receiver.changed().await.is_ok() {}
                })
                .await
                .unwrap();
            });
            assert!(!path.exists());
            assert!(
                !closed_while_queued,
                "queued {operation} must remain in the shutdown drain"
            );
            assert!(
                !admitted_while_queued,
                "queued {operation} must retain directory admission"
            );
            assert!(crate::local_sqlite::AdmissionFileLock::acquire(
                std::fs::File::open(directory.path()).unwrap()
            )
            .is_ok());
        }
    }
}

#[test]
#[cfg(unix)]
fn staged_legacy_cleanup_retains_its_own_directory_owner() {
    let directory = tempfile::tempdir().unwrap();
    let dir = Arc::new(std::fs::File::open(directory.path()).unwrap());
    let lock = crate::local_sqlite::AdmissionFileLock::acquire(dir.try_clone().unwrap()).unwrap();
    let (sender, receiver) = tokio::sync::watch::channel(());
    let owner = Arc::new(SnapshotDirectoryOwner::new(dir, Arc::new(lock), sender));
    let path = directory.path().join("approved-legacy-owned.sqlite");
    for suffix in ["", "-journal", "-wal", "-shm"] {
        std::fs::write(format!("{}{suffix}", path.display()), b"staging").unwrap();
    }
    let recovery = sqlite::StagedLegacyRecovery {
        approval: ApprovedLegacyConfigRecovery::new(
            &path,
            [1; 32],
            opc_types::TxId::new(),
            opc_types::ConfigVersion::new(1),
            crate::LegacyConfigTailDisposition::DiscardUnknownAppendedSuffix,
        )
        .unwrap(),
        path: path.clone(),
        _owner: owner.clone(),
    };
    drop(owner);
    assert!(
        receiver.has_changed().is_ok(),
        "cleanup guard owns shutdown accounting"
    );
    assert!(crate::local_sqlite::AdmissionFileLock::acquire(
        std::fs::File::open(directory.path()).unwrap()
    )
    .is_err());
    drop(recovery);
    assert!(
        files(directory.path()).is_empty(),
        "guard removes database and all sidecars"
    );
    assert!(receiver.has_changed().is_err());
    assert!(crate::local_sqlite::AdmissionFileLock::acquire(
        std::fs::File::open(directory.path()).unwrap()
    )
    .is_ok());
}
