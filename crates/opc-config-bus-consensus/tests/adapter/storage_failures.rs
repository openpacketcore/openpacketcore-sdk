use super::*;
use opc_persist::PersistErrorKind;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

async fn backend(path: &Path) -> SqliteBackend {
    SqliteBackend::open_with_audit_key(path, true, 0, AuditKey::new([0x71; 32]).unwrap())
        .await
        .unwrap()
}

async fn seed(backend: &SqliteBackend) {
    let adapter = Arc::new(PersistManagedDatastore::<TestConfig, _>::new(Arc::new(
        backend.clone(),
    )));
    EncryptingManagedDatastore::new(adapter, provider())
        .append_commit_write(CommitWrite::new(record(TxId::new(), "stored")))
        .await
        .unwrap();
}

async fn startup_error(backend: SqliteBackend, code: StoreErrorCode, cause: &str) {
    let adapter = Arc::new(PersistManagedDatastore::<TestConfig, _>::new(Arc::new(
        backend,
    )));
    let encrypted = Arc::new(EncryptingManagedDatastore::new(adapter, provider()));
    let error = match ConfigBus::restore_or_new_dev_only(
        TestConfig {
            name: "fallback".into(),
        },
        encrypted,
    )
    .await
    {
        Ok(_) => panic!("failed stored read must fence startup"),
        Err(error) => error,
    };
    assert_eq!(error.code, code);
    let alarms = error.alarm_manager().unwrap().active_alarms();
    assert_eq!(alarms.len(), 1);
    assert_eq!(format!("{:?}", alarms[0].probable_cause), cause);
    assert_eq!(format!("{:?}", alarms[0].severity), "Critical");
}

async fn missing_history_authority_row(table: &str) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.sqlite");
    let persistence = backend(&path).await;
    let node = ConfigConsensusNodeId::new(1).unwrap();
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("config-storage-failures").unwrap(),
        ConfigConsensusConfigurationId::from_bytes([0x70; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let topology =
        ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).unwrap();
    let consensus = Arc::new(
        ConsensusConfigStore::open_with_operation_timeout(
            topology,
            persistence.clone(),
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Duration::from_secs(3),
        )
        .await
        .unwrap(),
    );
    consensus.initialize_cluster().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while consensus.probe_durable_readiness().await.is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    EncryptingManagedDatastore::new(
        Arc::new(RaftManagedDatastore::<TestConfig>::new(consensus.clone())),
        provider(),
    )
    .append_commit_write(CommitWrite::new(record(TxId::new(), "stored")))
    .await
    .unwrap();
    consensus.shutdown().await.unwrap();
    let conn = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        conn.execute(&format!("DELETE FROM {table}"), []).unwrap(),
        1
    );
    let failure = ConfigStore::load_latest(&persistence).await.unwrap_err();
    let adapter = Arc::new(PersistManagedDatastore::<TestConfig, _>::new(Arc::new(
        persistence,
    )));
    let startup = match ConfigBus::restore_or_new_dev_only(
        TestConfig {
            name: "fallback".into(),
        },
        Arc::new(EncryptingManagedDatastore::new(adapter, provider())),
    )
    .await
    {
        Ok(_) => panic!("missing stored authority must fence startup"),
        Err(error) => error,
    };
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM config_history", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    let alarms = startup.alarm_manager().unwrap().active_alarms();
    assert_eq!(alarms.len(), 1);
    assert_eq!(
        (
            matches!(failure.kind(), PersistErrorKind::CorruptBlob),
            startup.code,
            format!("{:?}", alarms[0].probable_cause),
            format!("{:?}", alarms[0].severity),
        ),
        (
            true,
            StoreErrorCode::Crypto,
            "StorageCorruption".to_owned(),
            "Critical".to_owned(),
        ),
        "{table}: {failure:?}"
    );
}

#[tokio::test]
async fn missing_history_retention_row_keeps_corruption_alarm() {
    missing_history_authority_row("config_raft_history_retention").await;
}

#[tokio::test]
async fn missing_history_identity_row_keeps_corruption_alarm() {
    missing_history_authority_row("config_raft_identity").await;
}

async fn missing_runtime_authority_row(table: &str) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.sqlite");
    let persistence = backend(&path).await;
    let node = ConfigConsensusNodeId::new(1).unwrap();
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("runtime-storage-failures").unwrap(),
        ConfigConsensusConfigurationId::from_bytes([0x70; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let topology =
        ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).unwrap();
    let consensus = Arc::new(
        ConsensusConfigStore::open_with_operation_timeout(
            topology,
            persistence.clone(),
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Duration::from_secs(3),
        )
        .await
        .unwrap(),
    );
    consensus.initialize_cluster().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while consensus.probe_durable_readiness().await.is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let source = Arc::new(EncryptingManagedDatastore::new(
        Arc::new(RaftManagedDatastore::<TestConfig>::new_local_authority(
            consensus.clone(),
        )),
        provider(),
    ));
    source
        .append_commit_write(CommitWrite::new(record(TxId::new(), "stored")))
        .await
        .unwrap();
    let bus = ConfigBus::restore_or_new_dev_only(
        TestConfig {
            name: "fallback".into(),
        },
        source,
    )
    .await
    .unwrap();
    let initial_name = bus.load().name.clone();
    let conn = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        conn.execute(&format!("DELETE FROM {table}"), []).unwrap(),
        1
    );
    let error = bus
        .submit(
            CommitRequest::commit(
                RequestId::new(),
                principal(),
                TransportType::Internal,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                TestConfig {
                    name: "refused".into(),
                },
                Vec::new(),
                Instant::now() + Duration::from_secs(10),
            )
            .with_base_version(ConfigVersion::new(1)),
        )
        .await
        .unwrap_err();
    let read = ConfigStore::load_latest(&persistence).await;
    let alarms = bus.alarm_manager().active_alarms();
    assert_eq!(alarms.len(), 1);
    assert_eq!(bus.load().name, initial_name);
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM config_history", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        1
    );
    // The damaged consensus engine can already be stopped after apply rejects it.
    let _ = consensus.shutdown().await;
    assert_eq!(
        (
            error.code,
            format!("{:?}", alarms[0].severity),
            format!("{:?}", alarms[0].probable_cause),
            matches!(&read, Err(error) if matches!(error.kind(), PersistErrorKind::CorruptBlob)),
        ),
        (
            opc_config_model::CommitErrorCode::StateMachineFault,
            "Major".to_owned(),
            "StorageCorruption".to_owned(),
            true,
        ),
        "{table}: {read:?}"
    );
}

#[tokio::test]
async fn missing_runtime_machine_row_keeps_corruption_alarm() {
    missing_runtime_authority_row("config_raft_machine").await;
}

#[tokio::test]
async fn missing_runtime_membership_row_keeps_corruption_alarm() {
    missing_runtime_authority_row("config_raft_membership").await;
}

#[tokio::test]
async fn missing_runtime_audit_row_keeps_corruption_alarm() {
    missing_runtime_authority_row("config_raft_management_audit").await;
}

#[tokio::test]
async fn rejected_stored_digest_length_keeps_corruption_alarm() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.sqlite");
    let backend = backend(&path).await;
    seed(&backend).await;
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "PRAGMA ignore_check_constraints=ON; UPDATE config_history SET plaintext_digest=x'01';",
    )
    .unwrap();
    startup_error(backend, StoreErrorCode::Crypto, "StorageCorruption").await;
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM config_history", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn rejected_history_root_page_keeps_corruption_alarm() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.sqlite");
    let original = backend(&path).await;
    seed(&original).await;
    drop(original);
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
        .unwrap();
    let page: u64 = conn
        .query_row(
            "SELECT rootpage FROM sqlite_schema WHERE name='config_history'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let page_size: u64 = conn
        .query_row("PRAGMA page_size", [], |row| row.get(0))
        .unwrap();
    drop(conn);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    file.seek(SeekFrom::Start((page - 1) * page_size)).unwrap();
    file.write_all(&[0xff]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    let damaged = backend(&path).await;
    let error = ConfigStore::load_latest(&damaged).await.unwrap_err();
    assert!(
        matches!(error.kind(), PersistErrorKind::CorruptBlob),
        "{error:?}"
    );
    startup_error(damaged, StoreErrorCode::Crypto, "StorageCorruption").await;
}

#[tokio::test]
async fn empty_store_without_encrypting_adapter_is_local_failure() {
    let directory = tempfile::tempdir().unwrap();
    let persistence = Arc::new(backend(&directory.path().join("config.sqlite")).await);
    let adapter = Arc::new(PersistManagedDatastore::<TestConfig, _>::new(
        persistence.clone(),
    ));
    let error = match ConfigBus::restore_or_new_dev_only(
        SealedConfig::<TestConfig>::new(SchemaDigest::from_bytes([0x25; 32])),
        adapter,
    )
    .await
    {
        Ok(_) => panic!("unsealed composition must be refused"),
        Err(error) => error,
    };
    assert_eq!(error.code, StoreErrorCode::Internal);
    assert!(ConfigStore::load_latest(persistence.as_ref())
        .await
        .unwrap()
        .is_none());
    let alarms = error.alarm_manager().unwrap().active_alarms();
    assert_eq!(alarms.len(), 1);
    assert_eq!(
        format!("{:?}", alarms[0].probable_cause),
        "ConfigApplyFailed"
    );
}

// SQLite's heap limit is process-global and SQL can only lower it. Isolate
// this fixture so parallel tests cannot inherit the outage, then verify repair
// from the parent after the child exits. No unsafe FFI is needed.
#[test]
fn consensus_history_heap_outage_is_retryable_without_changing_bytes() {
    const CHILD: &str = "OPC_CONFIG_HEAP_OUTAGE_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(heap_outage_child(Path::new(&path)));
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "storage_failures::consensus_history_heap_outage_is_retryable_without_changing_bytes",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(CHILD, directory.path())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(String::from_utf8_lossy(&child.stdout)
        .contains("test result: ok. 1 passed; 0 failed; 0 ignored;"));
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let repaired = backend(&directory.path().join("config.sqlite")).await;
        assert!(ConfigStore::load_latest(&repaired).await.unwrap().is_some());
        let adapter = Arc::new(PersistManagedDatastore::<TestConfig, _>::new(Arc::new(
            repaired,
        )));
        let bus = ConfigBus::restore_or_new_dev_only(
            TestConfig {
                name: "fallback".into(),
            },
            Arc::new(EncryptingManagedDatastore::new(adapter, provider())),
        )
        .await
        .unwrap();
        assert_eq!(bus.load().name, "ciphertext-only-config");
    });
}

async fn heap_outage_child(directory: &Path) {
    let path = directory.join("config.sqlite");
    let backend = backend(&path).await;
    let node = ConfigConsensusNodeId::new(1).unwrap();
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("config-storage-failures").unwrap(),
        ConfigConsensusConfigurationId::from_bytes([0x70; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let topology =
        ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).unwrap();
    let consensus = Arc::new(
        ConsensusConfigStore::open_with_operation_timeout(
            topology,
            backend.clone(),
            directory.join("snapshots"),
            BTreeMap::new(),
            Duration::from_secs(3),
        )
        .await
        .unwrap(),
    );
    consensus.initialize_cluster().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while consensus.probe_durable_readiness().await.is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let encrypted = EncryptingManagedDatastore::new(
        Arc::new(RaftManagedDatastore::<TestConfig>::new(consensus.clone())),
        provider(),
    );
    let row = record(TxId::new(), "stored");
    let tx_id = row.tx_id;
    encrypted
        .append_commit_write(CommitWrite::new(row))
        .await
        .unwrap();
    consensus.shutdown().await.unwrap();
    // The real consensus-created history and schema remain, with background
    // writers reaped before comparing bytes and exhausting SQLite's heap.
    let conn = rusqlite::Connection::open(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    let wal = path.with_extension("sqlite-wal");
    let wal_before = std::fs::read(&wal).unwrap_or_default();
    let _ = conn.execute_batch("PRAGMA hard_heap_limit=1");
    let probe = conn
        .query_row("SELECT COUNT(*) FROM config_history", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap_err();
    assert_eq!(
        probe.sqlite_error_code(),
        Some(rusqlite::ErrorCode::OutOfMemory)
    );
    let errors = [
        ConfigStore::load_latest(&backend).await.unwrap_err(),
        ConfigStore::load_committed_latest(&backend)
            .await
            .unwrap_err(),
        ConfigStore::retained_history_floor(&backend)
            .await
            .unwrap_err(),
        ConfigStore::load_rollback(&backend, PersistRollbackTarget::ByTxId(tx_id))
            .await
            .unwrap_err(),
        ConfigStore::load_by_replay_lookup_digest(&backend, &"0".repeat(64))
            .await
            .unwrap_err(),
        ConfigStore::load_since(&backend, ConfigVersion::INITIAL, 1)
            .await
            .unwrap_err(),
    ];
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(std::fs::read(&wal).unwrap_or_default(), wal_before);
    for error in errors {
        assert!(
            matches!(error.kind(), PersistErrorKind::Unavailable),
            "{error:?}"
        );
    }
    startup_error(backend, StoreErrorCode::Unavailable, "ConfigApplyFailed").await;
}

#[tokio::test]
async fn rejected_stored_scalar_shapes_keep_corruption_alarm() {
    let mut observed = Vec::new();
    for sql in [
        "UPDATE config_history SET audit_count=-1",
        "UPDATE config_history SET principal=x'ff'",
        "UPDATE audit_trail SET sequence=-1",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("config.sqlite");
        let persistence = backend(&path).await;
        seed(&persistence).await;
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        conn.execute_batch(sql).unwrap();
        let adapter = PersistManagedDatastore::<TestConfig, _>::new(Arc::new(persistence));
        observed.push(adapter.load_latest().await.err().unwrap().code);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM config_history", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
    assert_eq!(observed, vec![StoreErrorCode::Crypto; 3]);
}

async fn dropped_history_table_is_permanent(table: &str) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.sqlite");
    let persistence = backend(&path).await;
    seed(&persistence).await;
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch("PRAGMA foreign_keys=OFF").unwrap();
    conn.execute_batch(&format!("DROP TABLE {table}")).unwrap();
    let error = ConfigStore::load_latest(&persistence).await.unwrap_err();
    assert!(
        matches!(error.kind(), PersistErrorKind::InconsistentState(_)),
        "{error:?}"
    );
    startup_error(persistence, StoreErrorCode::Internal, "ConfigApplyFailed").await;
}

#[tokio::test]
async fn dropped_config_history_table_is_not_retryable() {
    dropped_history_table_is_permanent("config_history").await;
}

#[tokio::test]
async fn dropped_audit_trail_table_is_not_retryable() {
    dropped_history_table_is_permanent("audit_trail").await;
}
