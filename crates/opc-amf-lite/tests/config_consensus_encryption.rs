use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use opc_amf_lite::AmfConfig;
use opc_config_bus::{
    CommitWrite, EncryptingManagedDatastore, ManagedDatastore, StoreErrorCode, StoredConfig,
    StoredRequestFingerprint, StoredRequestMode,
};
use opc_config_bus_consensus::RaftManagedDatastore;
use opc_config_model::{
    ApplyPlan, ConfigOperation, IdempotencyKey, RequestId, RequestSource, RollbackTarget,
    TransportType, TrustedPrincipal, WorkloadIdentity, YangPath,
};
use opc_key::{
    KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose, MemoryKeyProvider, Zeroizing,
    AES_256_GCM_SIV_KEY_LEN,
};
use opc_persist::ConfigStore;
use opc_types::{ConfigVersion, TenantId, TxId};

mod config_consensus_common;
use config_consensus_common::ConfigCluster;

const FIRST_PLAINTEXT: &[u8] = b"HKMS-PLAINTEXT-FIRST-MUST-NOT-REACH-RAFT";
const SECOND_PLAINTEXT: &[u8] = b"HKMS-PLAINTEXT-SECOND-MUST-NOT-REACH-RAFT";
const FIRST_KEY_MATERIAL: [u8; AES_256_GCM_SIV_KEY_LEN] = [0xC1; 32];
const SECOND_KEY_MATERIAL: [u8; AES_256_GCM_SIV_KEY_LEN] = [0xD2; 32];
const AUDIT_KEY_MATERIAL: [u8; 32] = [0x55; 32];
const PROVIDER_ENDPOINT_CANARY: &[u8] = b"hkms+unix:///provider-credential-must-not-persist";
const OPAQUE_HANDLE_CANARY: &[u8] = b"HKMS-OPAQUE-PROVIDER-HANDLE-MUST-NOT-PERSIST";
const RAW_IDEMPOTENCY_CANARY: &[u8] = b"RAW-IDEMPOTENCY-KEY-MUST-NOT-REACH-RAFT";
const REPLAY_FINGERPRINT_CANARY: &[u8] = b"replay-fingerprint-must-not-reach-raft";
const REQUEST_ID_CANARY: &[u8] = b"f7a35c21-9c72-4e9b-83f8-c1453d205f92";

struct CountingKeyProvider {
    inner: MemoryKeyProvider,
    calls: AtomicUsize,
}

impl CountingKeyProvider {
    fn new() -> Self {
        Self {
            inner: MemoryKeyProvider::new(),
            calls: AtomicUsize::new(0),
        }
    }

    fn insert_active_key(&self, key_id: &str, tenant: &TenantId, material: [u8; 32]) {
        self.inner
            .insert_active_key(
                KeyId::new(key_id).expect("key ID"),
                KeyPurpose::Config,
                tenant.clone(),
                Zeroizing::new(material),
            )
            .expect("insert active key");
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::Acquire)
    }
}

#[async_trait]
impl KeyProvider for CountingKeyProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.inner.get_active_key(purpose, tenant).await
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.inner.get_key_by_id(key_id).await
    }

    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        self.inner.rotate_key(purpose, tenant).await
    }
}

fn principal(tenant: TenantId) -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::Internal("config-writer".to_owned()),
        tenant,
    )
}

fn assert_forbidden_bytes_absent(location: &str, bytes: &[u8]) {
    for (description, forbidden) in [
        ("first plaintext", FIRST_PLAINTEXT),
        ("second plaintext", SECOND_PLAINTEXT),
        ("first raw key", FIRST_KEY_MATERIAL.as_slice()),
        ("second raw key", SECOND_KEY_MATERIAL.as_slice()),
        ("raw audit key", AUDIT_KEY_MATERIAL.as_slice()),
        ("provider endpoint", PROVIDER_ENDPOINT_CANARY),
        ("opaque provider handle", OPAQUE_HANDLE_CANARY),
        ("raw idempotency key", RAW_IDEMPOTENCY_CANARY),
        ("request fingerprint", REPLAY_FINGERPRINT_CANARY),
        ("request ID", REQUEST_ID_CANARY),
    ] {
        assert!(
            !bytes
                .windows(forbidden.len())
                .any(|window| window == forbidden),
            "{description} reached {location}"
        );
    }
}

fn assert_forbidden_absent(path: &Path) {
    if path.is_dir() {
        for entry in std::fs::read_dir(path).expect("read artifact directory") {
            assert_forbidden_absent(&entry.expect("artifact entry").path());
        }
        return;
    }
    let Ok(bytes) = std::fs::read(path) else {
        return;
    };
    assert_forbidden_bytes_absent(&path.display().to_string(), &bytes);
}

fn assert_consensus_rows_forbidden_absent(database: &Path) {
    let conn = rusqlite::Connection::open(database).expect("open live config database");
    for (label, query) in [
        (
            "config raft log row",
            "SELECT entry_json FROM config_raft_log",
        ),
        (
            "config request payload digest",
            "SELECT payload_digest FROM config_raft_request_outcomes",
        ),
        (
            "config request outcome",
            "SELECT response_json FROM config_raft_request_outcomes",
        ),
        (
            "sealed config history",
            "SELECT encrypted_blob FROM config_history",
        ),
    ] {
        let mut statement = conn.prepare(query).expect("prepare artifact scan");
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .expect("query artifact rows");
        for row in rows {
            assert_forbidden_bytes_absent(label, &row.expect("artifact row"));
        }
    }
}

fn assert_live_config_logs_are_non_vacuous_and_forbidden_absent(root: &Path) {
    for index in 0..3 {
        let database = root.join(format!("config-{index}.sqlite"));
        let conn = rusqlite::Connection::open(database).expect("open live config database");
        let has_append_commit: bool = conn
            .query_row(
                r#"SELECT EXISTS(
                       SELECT 1
                       FROM config_raft_log
                       WHERE json_type(
                           CAST(entry_json AS TEXT),
                           '$.payload.Normal.intent.AppendCommit'
                       ) IS NOT NULL
                   )"#,
                [],
                |row| row.get(0),
            )
            .expect("inspect config append log rows");
        assert!(
            has_append_commit,
            "raw config log scan must cover a sealed append entry"
        );

        let mut statement = conn
            .prepare("SELECT entry_json FROM config_raft_log")
            .expect("prepare config log scan");
        let rows = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .expect("query config log rows");
        for row in rows {
            assert_forbidden_bytes_absent("config raft log row", &row.expect("config log row"));
        }
    }
}

fn assert_live_artifacts_forbidden_absent(root: &Path, cluster: &ConfigCluster) {
    let frames = cluster.captured_frames();
    assert!(
        !frames.is_empty(),
        "real shared consensus wire was not exercised"
    );
    for (index, frame) in frames.iter().enumerate() {
        assert_forbidden_bytes_absent(&format!("shared consensus wire frame {index}"), frame);
    }
    for index in 0..3 {
        let database = root.join(format!("config-{index}.sqlite"));
        assert_consensus_rows_forbidden_absent(&database);
        for suffix in ["", "-wal", "-shm"] {
            let artifact = Path::new(&format!("{}{}", database.display(), suffix)).to_path_buf();
            if artifact.exists() {
                assert_forbidden_absent(&artifact);
            }
        }
        assert_forbidden_absent(&root.join(format!("snapshots-{index}")));
    }
}

#[tokio::test]
async fn hkms_boundary_survives_rotation_followers_snapshots_and_restart() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut cluster = ConfigCluster::start(temp.path()).await;
    let tenant = TenantId::new("tenant-a").expect("tenant");
    let provider = Arc::new(CountingKeyProvider::new());
    provider.insert_active_key("config-key-a", &tenant, FIRST_KEY_MATERIAL);
    let raw = Arc::new(RaftManagedDatastore::<AmfConfig>::new(Arc::new(
        cluster.stores[0].clone(),
    )));
    let encrypted = EncryptingManagedDatastore::new(raw.clone(), provider.clone());

    let first_tx = TxId::new();
    let idempotency_key =
        IdempotencyKey::new(String::from_utf8_lossy(RAW_IDEMPOTENCY_CANARY).into_owned())
            .expect("idempotency key");
    let fingerprint_path = YangPath::new(format!(
        "/amf/{}",
        String::from_utf8_lossy(REPLAY_FINGERPRINT_CANARY)
    ))
    .expect("fingerprint path");
    let apply_plan = ApplyPlan::default_hot(vec![fingerprint_path.clone()], None);
    let request_fingerprint = StoredRequestFingerprint {
        operation: ConfigOperation::Replace,
        mode: StoredRequestMode::Commit,
        transport: TransportType::Internal,
        changed_paths: vec![fingerprint_path],
        base_version: Some(ConfigVersion::new(0)),
    };
    let request_id: RequestId = String::from_utf8_lossy(REQUEST_ID_CANARY)
        .parse()
        .expect("request ID");
    let mut first = StoredConfig::new(
        first_tx,
        ConfigVersion::new(1),
        principal(tenant.clone()),
        RequestSource::Northbound,
        AmfConfig {
            hostname: String::from_utf8_lossy(FIRST_PLAINTEXT).into_owned(),
            nrf_endpoint: format!(
                "{}|{}",
                String::from_utf8_lossy(PROVIDER_ENDPOINT_CANARY),
                String::from_utf8_lossy(OPAQUE_HANDLE_CANARY)
            ),
            ..AmfConfig::default()
        },
    );
    first.committed_at = opc_types::Timestamp::now_utc();
    first.idempotency_key = Some(idempotency_key.clone());
    first.apply_plan = Some(apply_plan.clone());
    first.request_fingerprint = Some(request_fingerprint.clone());
    first.request_id = Some(request_id);
    encrypted
        .append_commit_write(CommitWrite::new(first))
        .await
        .expect("first encrypted quorum commit");
    assert_eq!(
        1,
        provider.call_count(),
        "followers must not resolve the leader's key"
    );

    provider.insert_active_key("config-key-b", &tenant, SECOND_KEY_MATERIAL);
    let second_tx = TxId::new();
    let mut second = StoredConfig::new(
        second_tx,
        ConfigVersion::new(2),
        principal(tenant.clone()),
        RequestSource::Northbound,
        AmfConfig {
            hostname: String::from_utf8_lossy(SECOND_PLAINTEXT).into_owned(),
            ..AmfConfig::default()
        },
    );
    second.parent_tx_id = Some(first_tx);
    encrypted
        .append_commit_write(CommitWrite::new(second))
        .await
        .expect("rotated-key quorum commit");
    assert_eq!(
        2,
        provider.call_count(),
        "one leader-side key resolution is allowed per encryption"
    );

    for store in &cluster.stores {
        let latest = store
            .load_latest()
            .await
            .expect("follower load")
            .expect("record");
        assert_eq!(second_tx, latest.record.tx_id);
        assert!(!latest.record.encrypted_blob.is_empty());
    }
    assert_live_config_logs_are_non_vacuous_and_forbidden_absent(temp.path());
    assert_eq!(
        2,
        provider.call_count(),
        "follower application and sealed reads must make zero provider calls"
    );

    let historical = encrypted
        .load_rollback(RollbackTarget::TxId(first_tx))
        .await
        .expect("historical key remains readable");
    assert_eq!(
        3,
        provider.call_count(),
        "historical unseal resolves one key"
    );
    assert_eq!(
        String::from_utf8_lossy(FIRST_PLAINTEXT),
        historical.config.hostname
    );
    let latest = encrypted
        .load_latest()
        .await
        .expect("latest decrypt")
        .expect("latest record");
    assert_eq!(4, provider.call_count(), "latest unseal resolves one key");
    assert_eq!(
        String::from_utf8_lossy(SECOND_PLAINTEXT),
        latest.config.hostname
    );

    let missing_provider = Arc::new(CountingKeyProvider::new());
    missing_provider.insert_active_key("config-key-b", &tenant, SECOND_KEY_MATERIAL);
    let missing_historical = EncryptingManagedDatastore::new(raw.clone(), missing_provider.clone());
    let error = missing_historical
        .load_rollback(RollbackTarget::TxId(first_tx))
        .await
        .err()
        .expect("missing historical key must fail closed");
    assert_eq!(StoreErrorCode::Crypto, error.code);
    assert_eq!(
        1,
        missing_provider.call_count(),
        "missing historical unseal performs one bounded lookup"
    );
    assert_eq!(
        second_tx,
        missing_historical
            .load_latest()
            .await
            .expect("current key read")
            .expect("current record")
            .tx_id
    );
    assert_eq!(
        2,
        missing_provider.call_count(),
        "current-key unseal performs one additional lookup"
    );

    let replay = encrypted
        .load_by_idempotency_key(&idempotency_key)
        .await
        .expect("authoritative replay lookup")
        .expect("replay record");
    assert_eq!(first_tx, replay.tx_id);
    assert_eq!(Some(idempotency_key.clone()), replay.idempotency_key);
    assert_eq!(Some(apply_plan.clone()), replay.apply_plan);
    assert_eq!(
        Some(request_fingerprint.clone()),
        replay.request_fingerprint
    );
    assert_eq!(Some(request_id), replay.request_id);

    let calls_before_maintenance = provider.call_count();
    let missing_calls_before_maintenance = missing_provider.call_count();
    let (one, two, three) = tokio::join!(
        cluster.stores[0].trigger_snapshot(),
        cluster.stores[1].trigger_snapshot(),
        cluster.stores[2].trigger_snapshot(),
    );
    one.expect("leader snapshot trigger");
    two.expect("follower snapshot trigger");
    three.expect("follower snapshot trigger");
    assert_eq!(calls_before_maintenance, provider.call_count());
    assert_eq!(
        missing_calls_before_maintenance,
        missing_provider.call_count()
    );
    assert_live_artifacts_forbidden_absent(temp.path(), &cluster);

    cluster.shutdown().await.expect("shutdown config cluster");
    drop(cluster);
    let mut restarted = ConfigCluster::start(temp.path()).await;
    for store in &restarted.stores {
        assert_eq!(
            second_tx,
            store
                .load_latest()
                .await
                .expect("recovered sealed read")
                .expect("recovered record")
                .record
                .tx_id
        );
    }
    assert_eq!(
        calls_before_maintenance,
        provider.call_count(),
        "Openraft replay/recovery must make zero provider calls"
    );
    assert_eq!(
        missing_calls_before_maintenance,
        missing_provider.call_count(),
        "Openraft recovery must not consult an unrelated provider"
    );
    let restarted_raw = Arc::new(RaftManagedDatastore::<AmfConfig>::new(Arc::new(
        restarted.stores[0].clone(),
    )));
    let restarted_encrypted = EncryptingManagedDatastore::new(restarted_raw, Arc::clone(&provider));
    let restarted_replay = restarted_encrypted
        .load_by_idempotency_key(&idempotency_key)
        .await
        .expect("restarted authoritative replay lookup")
        .expect("restarted replay record");
    assert_eq!(first_tx, restarted_replay.tx_id);
    assert_eq!(Some(idempotency_key), restarted_replay.idempotency_key);
    assert_eq!(Some(apply_plan), restarted_replay.apply_plan);
    assert_eq!(
        Some(request_fingerprint),
        restarted_replay.request_fingerprint
    );
    assert_eq!(Some(request_id), restarted_replay.request_id);
    assert_live_artifacts_forbidden_absent(temp.path(), &restarted);
    restarted
        .shutdown()
        .await
        .expect("shutdown restarted config cluster");
    drop(restarted);

    assert_forbidden_absent(temp.path());
}
