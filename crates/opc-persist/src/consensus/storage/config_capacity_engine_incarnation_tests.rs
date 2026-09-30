//! Engine-claim ownership at actual startup and detached SQLite boundaries.
//! Bounded controls use native retained admission. The explicitly labeled
//! Legacy initializer control uses its existing before-commit test hook only
//! to isolate the shared lifetime mechanism; it does not qualify that profile
//! as a bounded authority or add a retained-schema validation bypass.

use super::*;
use crate::consensus::{
    ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId,
    ConfigConsensusTopology,
};
use crate::{
    ConfigConsensusOpenError, ConsensusConfigStore, RetainedConfigBinding,
    RetainedConfigDurability, RetainedConfigError, RetainedConfigOptions,
};
use std::collections::{BTreeMap, BTreeSet};
use std::future::{poll_fn, Future};
use std::task::Poll;
use std::time::Duration;

fn topology() -> ConfigConsensusTopology {
    let node = ConsensusNodeId::new(1).expect("synthetic node");
    ConfigConsensusTopology::try_new(
        ConsensusIdentity::new(
            ConfigConsensusClusterId::from_bytes([0xA1; 32]),
            ConfigConsensusConfigurationId::from_bytes([0xA2; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
        ),
        node,
        BTreeSet::from([node]),
    )
    .expect("singleton topology")
}

fn key() -> AuditKey {
    AuditKey::new([0xA3; 32]).expect("synthetic audit key")
}

fn disk_fixture() -> PathBuf {
    let scratch = std::env::var_os("TMPDIR")
        .or_else(|| {
            (std::env::var("GITHUB_ACTIONS").ok().as_deref() == Some("true"))
                .then(|| std::env::var_os("RUNNER_TEMP"))
                .flatten()
        })
        .expect("explicit disk scratch root");
    let root = tempfile::Builder::new()
        .prefix("config-engine-worker-")
        .tempdir_in(scratch)
        .expect("private disk fixture")
        .keep();
    let filesystem = std::process::Command::new("findmnt")
        .args(["-n", "-o", "FSTYPE", "-T"])
        .arg(&root)
        .output()
        .expect("filesystem detector");
    assert!(filesystem.status.success());
    let filesystem = std::str::from_utf8(&filesystem.stdout)
        .expect("filesystem name")
        .trim();
    assert!(!filesystem.is_empty() && !matches!(filesystem, "tmpfs" | "ramfs"));
    root
}

fn options(root: &Path) -> RetainedConfigOptions {
    RetainedConfigOptions::new(
        root.join("config.sqlite"),
        RetainedConfigBinding::new(topology(), [0xA4; 32], [0xA5; 32])
            .expect("synthetic binding")
            .with_capacity_profile(ConfigCapacityProfile::BoundedV1),
        RetainedConfigDurability::Durable {
            min_free_bytes: 128 * 1024 * 1024,
        },
        256 * 1024 * 1024,
        Duration::from_secs(10),
    )
    .expect("retained limits")
}

async fn provision(root: &Path) -> SqliteBackend {
    SqliteBackend::provision_config_authority(options(root), key())
        .await
        .expect("native bounded retained backend")
}

async fn engine(
    root: &Path,
    backend: SqliteBackend,
) -> Result<ConsensusConfigStore, ConfigConsensusOpenError> {
    ConsensusConfigStore::open(topology(), backend, root.join("snapshots"), BTreeMap::new()).await
}

#[tokio::test]
async fn config_capacity_957_admitted_backend_clone_cannot_claim_another_engine() {
    let root = disk_fixture();
    let backend = provision(&root).await;
    let admitted = backend
        .clone()
        .claim_config_consensus_engine()
        .expect("first claim");
    assert!(matches!(
        admitted.clone().claim_config_consensus_engine(),
        Err(ConfigConsensusStorageError::BackendUnavailable)
    ));
    assert!(matches!(
        engine(&root, admitted.clone()).await,
        Err(ConfigConsensusOpenError::StorageUnavailable)
    ));
    drop(admitted);
    let store = engine(&root, backend).await.expect("claim released");
    store.shutdown().await.expect("native shutdown");
}

#[tokio::test]
async fn config_capacity_957_cancelled_bounded_startup_releases_pending_claim() {
    let root = disk_fixture();
    let backend = provision(&root).await;
    let held = backend
        .config_consensus_worker_gate()
        .acquire_owned()
        .await
        .expect("startup gate");
    let mut startup = Box::pin(engine(&root, backend.clone()));
    poll_fn(|context| {
        assert!(
            startup.as_mut().poll(context).is_pending(),
            "startup waits for native admission"
        );
        Poll::Ready(())
    })
    .await;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    assert!(matches!(
        tokio::time::timeout_at(deadline, engine(&root, backend.clone()))
            .await
            .expect("duplicate open must refuse before SQLite admission"),
        Err(ConfigConsensusOpenError::StorageUnavailable)
    ));
    drop(startup);
    drop(held);
    let store = tokio::time::timeout_at(deadline, engine(&root, backend))
        .await
        .expect("retry inside unchanged startup bound")
        .expect("cancelled startup releases pending claim");
    store.shutdown().await.expect("native shutdown");
}

#[tokio::test]
async fn config_capacity_957_cancelled_bounded_worker_retains_engine_until_native_release() {
    let root = disk_fixture();
    let backend = provision(&root).await;
    let admitted = backend
        .clone()
        .claim_config_consensus_engine()
        .expect("engine claim");
    let (log, machine, progress) = open(
        &admitted,
        root.join("snapshots"),
        topology().identity(),
        topology().members().clone(),
    )
    .await
    .expect("native storage adapters");
    let released = progress
        .storage_release_observer()
        .expect("non-owning release observer");
    let core = log.core.clone();
    drop(log);
    drop(machine);
    drop(progress);
    drop(admitted);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (cancelled_tx, cancelled_rx) = tokio::sync::oneshot::channel();
    let caller = tokio::spawn(async move {
        core.run_sqlite_cancellable_until(deadline, move |conn, cancellation| {
            let rows = conn
                .query_row("SELECT COUNT(*) FROM config_history", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(|_| sqlite::invalid_data("native worker read failed"))?;
            started_tx
                .send(rows)
                .map_err(|_| sqlite::invalid_data("worker observer dropped"))?;
            release_rx
                .recv_timeout(
                    deadline
                        .into_std()
                        .saturating_duration_since(std::time::Instant::now()),
                )
                .map_err(|_| sqlite::invalid_data("native release gate failed"))?;
            cancelled_tx
                .send(cancellation.is_cancelled())
                .map_err(|_| sqlite::invalid_data("cancellation observer dropped"))?;
            cancellation.check_io()
        })
        .await
    });
    assert_eq!(
        tokio::time::timeout_at(deadline, started_rx)
            .await
            .expect("native worker enters")
            .expect("worker start signal"),
        0
    );
    caller.abort();
    assert!(caller
        .await
        .expect_err("cancelled original caller")
        .is_cancelled());
    // Only the detached worker now owns this engine claim. In particular the
    // observer has neither a core, progress value, backend nor pool owner.
    let refused_live_claim = matches!(
        backend.clone().claim_config_consensus_engine(),
        Err(ConfigConsensusStorageError::BackendUnavailable)
    );
    // If ownership is missing, record the defect without starting another
    // engine against the still-blocked worker. The named detector runs only
    // after that original worker and the complete cleanup lifecycle finish.
    if refused_live_claim {
        assert!(matches!(
            tokio::time::timeout_at(deadline, engine(&root, backend.clone()))
                .await
                .expect("clone must refuse while native worker remains"),
            Err(ConfigConsensusOpenError::StorageUnavailable)
        ));
    }
    drop(backend);
    assert_eq!(
        tokio::time::timeout_at(
            deadline,
            SqliteBackend::reopen_config_authority(options(&root), key()),
        )
        .await
        .expect("live-worker retained refusal inside original operation bound")
        .err(),
        Some(RetainedConfigError::InUse)
    );
    release_tx.send(()).expect("release original native worker");
    assert!(tokio::time::timeout_at(deadline, cancelled_rx)
        .await
        .expect("native cancellation observed")
        .expect("cancellation signal"));
    tokio::time::timeout_at(deadline, released.wait())
        .await
        .expect("final native owner released");
    let backend = tokio::time::timeout_at(
        deadline,
        SqliteBackend::reopen_config_authority(options(&root), key()),
    )
    .await
    .expect("retained reopen completes inside the original operation bound")
    .expect("native file admission released");
    let store = tokio::time::timeout_at(deadline, engine(&root, backend))
        .await
        .expect("next engine opens inside the original operation bound")
        .expect("next engine after actual owner drain");
    let reservations: Vec<_> = (0..8)
        .map(|_| {
            store
                .try_reserve_config_preparation()
                .expect("next preparation")
                .expect("bounded preparation")
        })
        .collect();
    assert!(store.try_reserve_config_preparation().is_err());
    tokio::time::timeout_at(deadline, store.shutdown())
        .await
        .expect("next shutdown finishes inside the original operation bound")
        .expect("next native shutdown");
    drop(reservations);
    drop(store);
    assert!(
        tokio::time::Instant::now() < deadline,
        "original cleanup deadline"
    );
    println!("CONFIG_CAPACITY_ENGINE_NATIVE_OWNER_CLEANUP original_caller_joined=true cancellation_observed=true native_owner_drained=true retained_reopened=true next_engine_shutdown=true original_deadline_met=true");
    assert!(
        refused_live_claim,
        "CONFIG_CAPACITY_ENGINE_NATIVE_OWNER_RED: detached native worker must retain the engine claim"
    );
}

#[tokio::test]
async fn config_capacity_957_cancelled_backend_worker_retains_engine_until_native_release() {
    let root = disk_fixture();
    let backend = provision(&root).await;
    let admitted = backend
        .clone()
        .claim_config_consensus_engine()
        .expect("engine claim");
    let mut released = {
        let conn = backend.conn();
        let conn = conn.lock().await;
        conn.release_observer()
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (cancelled_tx, cancelled_rx) = tokio::sync::oneshot::channel();
    let caller = tokio::spawn(async move {
        // Backend-only startup/history work has no storage owner. This closure
        // deliberately captures neither the backend nor its engine claim.
        sqlite::run_backend_sqlite_with_timeout(
            &admitted,
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            move |conn, cancellation| {
                let rows = conn
                    .query_row("SELECT COUNT(*) FROM config_history", [], |row| {
                        row.get::<_, i64>(0)
                    })
                    .map_err(|_| sqlite::invalid_data("backend worker read failed"))?;
                started_tx
                    .send(rows)
                    .map_err(|_| sqlite::invalid_data("worker observer dropped"))?;
                release_rx
                    .recv_timeout(
                        deadline
                            .into_std()
                            .saturating_duration_since(std::time::Instant::now()),
                    )
                    .map_err(|_| sqlite::invalid_data("backend release gate failed"))?;
                cancelled_tx
                    .send(cancellation.is_cancelled())
                    .map_err(|_| sqlite::invalid_data("cancellation observer dropped"))?;
                cancellation.check_io()
            },
        )
        .await
    });
    assert_eq!(
        tokio::time::timeout_at(deadline, started_rx)
            .await
            .expect("native backend worker enters")
            .expect("worker start signal"),
        0
    );
    caller.abort();
    assert!(caller
        .await
        .expect_err("cancelled original caller")
        .is_cancelled());
    let refused_live_claim = matches!(
        backend.clone().claim_config_consensus_engine(),
        Err(ConfigConsensusStorageError::BackendUnavailable)
    );
    if refused_live_claim {
        assert!(matches!(
            tokio::time::timeout_at(deadline, engine(&root, backend.clone()))
                .await
                .expect("clone must refuse before SQLite admission"),
            Err(ConfigConsensusOpenError::StorageUnavailable)
        ));
    }
    drop(backend);
    assert_eq!(
        tokio::time::timeout_at(
            deadline,
            SqliteBackend::reopen_config_authority(options(&root), key()),
        )
        .await
        .expect("live-worker retained refusal inside original operation bound")
        .err(),
        Some(RetainedConfigError::InUse)
    );
    release_tx
        .send(())
        .expect("release original backend worker");
    assert!(tokio::time::timeout_at(deadline, cancelled_rx)
        .await
        .expect("native cancellation observed")
        .expect("cancellation signal"));
    // The cancellation signal precedes hook/connection cleanup. The final
    // connection-drop observer owns neither the claim nor any connection, and
    // closes after SQLite and FileAdmission even if the claim was omitted.
    tokio::time::timeout_at(deadline, released.changed())
        .await
        .expect("actual backend worker releases retained file admission")
        .expect_err("final connection drop closes the non-owning observer");
    let backend = tokio::time::timeout_at(
        deadline,
        SqliteBackend::reopen_config_authority(options(&root), key()),
    )
    .await
    .expect("retained reopen completes inside the original operation bound")
    .expect("one retained reopen after actual backend worker destruction");
    let store = tokio::time::timeout_at(deadline, engine(&root, backend))
        .await
        .expect("next engine opens inside the original operation bound")
        .expect("next engine after backend-only worker drain");
    tokio::time::timeout_at(deadline, store.shutdown())
        .await
        .expect("next shutdown finishes inside the original operation bound")
        .expect("next native shutdown");
    drop(store);
    assert!(
        tokio::time::Instant::now() < deadline,
        "original cleanup deadline"
    );
    println!("CONFIG_CAPACITY_ENGINE_BACKEND_WORKER_CLEANUP original_caller_joined=true cancellation_observed=true native_owner_drained=true retained_reopened=true next_engine_shutdown=true original_deadline_met=true");
    assert!(
        refused_live_claim,
        "CONFIG_CAPACITY_ENGINE_BACKEND_WORKER_RED: detached backend-only worker must retain the engine claim"
    );
}

#[tokio::test]
async fn config_capacity_957_cancelled_initializer_retains_claim_white_box() {
    let root = disk_fixture();
    let backend = SqliteBackend::open_with_audit_key(
        root.join("config.sqlite"),
        false,
        128 * 1024 * 1024,
        key(),
    )
    .await
    .expect("native legacy initializer fixture");
    // Only Legacy initialization has the existing before-commit test hook.
    // Install the real claim primitive explicitly to observe ownership across
    // that worker boundary, without changing the production profile selector.
    let admitted = backend
        .clone()
        .claim_config_engine_for_initialization_control()
        .expect("white-box lifetime claim");
    let directory =
        admit_snapshot_directory(&admitted, root.join("snapshots")).expect("snapshot directory");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (cancelled_tx, cancelled_rx) = tokio::sync::oneshot::channel();
    let caller = tokio::spawn(async move {
        sqlite::ConfigConsensusCore::initialize_with_test_timeout(
            &admitted,
            directory,
            topology().identity(),
            topology().members().clone(),
            Arc::new(ConfigDurableProgress::default()),
            None,
            Duration::from_secs(10),
            move |cancellation| {
                started_tx.send(()).expect("initializer start signal");
                release_rx
                    .recv_timeout(
                        deadline
                            .into_std()
                            .saturating_duration_since(std::time::Instant::now()),
                    )
                    .expect("initializer release gate");
                cancelled_tx
                    .send(cancellation.is_cancelled())
                    .expect("initializer cancellation signal");
            },
        )
        .await
    });
    tokio::time::timeout_at(deadline, started_rx)
        .await
        .expect("native initializer enters")
        .expect("start signal");
    caller.abort();
    assert!(caller
        .await
        .err()
        .expect("cancelled initializer caller")
        .is_cancelled());
    assert!(
        matches!(
            backend
                .clone()
                .claim_config_engine_for_initialization_control(),
            Err(ConfigConsensusStorageError::BackendUnavailable)
        ),
        "CONFIG_CAPACITY_ENGINE_INITIALIZER_RED: detached initialization still owns the actual claim"
    );
    release_tx.send(()).expect("release original initializer");
    assert!(tokio::time::timeout_at(deadline, cancelled_rx)
        .await
        .expect("initializer observes cancellation")
        .expect("cancellation signal"));
    let retried = tokio::time::timeout_at(deadline, async {
        loop {
            match backend
                .clone()
                .claim_config_engine_for_initialization_control()
            {
                Ok(retried) => break retried,
                Err(ConfigConsensusStorageError::BackendUnavailable) => {
                    tokio::task::yield_now().await
                }
                Err(error) => panic!("unexpected retry refusal: {error:?}"),
            }
        }
    })
    .await
    .expect("actual initializer releases its last claim");
    {
        let conn = backend.conn();
        let conn = conn.lock().await;
        let rows: i64 = conn.query_row("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='config_raft_identity'", [], |row| row.get(0)).expect("rollback check");
        assert_eq!(rows, 0, "cancelled initializer cannot leave authority");
    }
    let (log, machine, progress) = open(
        &retried,
        root.join("snapshots"),
        topology().identity(),
        topology().members().clone(),
    )
    .await
    .expect("real initialization retry after native drain");
    drop((log, machine, progress, retried));
}
