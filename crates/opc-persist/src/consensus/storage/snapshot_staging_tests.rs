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
