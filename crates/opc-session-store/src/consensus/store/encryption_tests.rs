use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use opc_consensus::{
    derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
    DURABLE_CONSENSUS_TIMING_PROFILE,
};
use opc_key::{
    EncryptedPayload, EnvelopeAad, KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose,
    MemoryKeyProvider, MemoryRemoteSealProvider, RemoteSealProvider, Zeroizing,
    AES_256_GCM_SIV_KEY_LEN,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

use super::ConsensusSessionStore;
use crate::backend::{
    CompareAndSet, CompareAndSetResult, EncryptingSessionBackend, RemoteSealingSessionBackend,
    SessionBackend, SessionOp,
};
use crate::consensus::{
    SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcHandler, SessionConsensusWireRequest, SessionConsensusWireResponse,
};
use crate::lease::SessionLeaseManager;
use crate::model::{Generation, OwnerId, SessionKey, SessionKeyType, StateClass, StateType};
use crate::record::{EncryptedSessionPayload, SessionPayloadEncoding, StoredSessionRecord};
use crate::restore::RestoreScanRequest;
use crate::sqlite::SqliteSessionBackend;
use crate::topology::{
    QuorumReplicaDescriptor, QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint,
    ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, ValidatedQuorumTopology,
};
use opc_crypto::CryptoEnvelopeV1;
use tempfile::TempDir;

const ENCRYPTION_NAMESPACE: &str = "consensus-snapshot-boundary-qualification";
const PLAINTEXT_BEFORE_ROTATION: &[u8] = b"snapshot-restart-plaintext-canary-before-key-rotation";
const PLAINTEXT_AFTER_ROTATION: &[u8] = b"snapshot-restart-plaintext-canary-after-key-rotation";
const RAW_KEY_MATERIAL: &[u8; AES_256_GCM_SIV_KEY_LEN] = &[0x6b; AES_256_GCM_SIV_KEY_LEN];
const SNAPSHOT_FOOTER_BYTES: usize = 8 + 8 + 32;
const CONSENSUS_READY_TIMEOUT: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE
        .election_timeout_max_millis
        .saturating_mul(2)
        .saturating_add(DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis),
);

struct CountingKeyProvider {
    inner: Arc<MemoryKeyProvider>,
    active_key_calls: AtomicUsize,
    key_by_id_calls: AtomicUsize,
    rotation_calls: AtomicUsize,
}

impl CountingKeyProvider {
    fn new(inner: Arc<MemoryKeyProvider>) -> Self {
        Self {
            inner,
            active_key_calls: AtomicUsize::new(0),
            key_by_id_calls: AtomicUsize::new(0),
            rotation_calls: AtomicUsize::new(0),
        }
    }

    fn call_counts(&self) -> (usize, usize, usize) {
        (
            self.active_key_calls.load(Ordering::SeqCst),
            self.key_by_id_calls.load(Ordering::SeqCst),
            self.rotation_calls.load(Ordering::SeqCst),
        )
    }
}

#[async_trait]
impl KeyProvider for CountingKeyProvider {
    async fn get_active_key(
        &self,
        purpose: KeyPurpose,
        tenant: &TenantId,
    ) -> Result<KeyHandle, KeyError> {
        self.active_key_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_active_key(purpose, tenant).await
    }

    async fn get_key_by_id(&self, key_id: &KeyId) -> Result<KeyHandle, KeyError> {
        self.key_by_id_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_key_by_id(key_id).await
    }

    async fn rotate_key(&self, purpose: KeyPurpose, tenant: &TenantId) -> Result<KeyId, KeyError> {
        self.rotation_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.rotate_key(purpose, tenant).await
    }
}

fn tenant() -> TenantId {
    TenantId::new("consensus-snapshot-tenant").expect("tenant")
}

fn provider() -> Arc<CountingKeyProvider> {
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("snapshot-boundary-key-2026-07").expect("key ID"),
            KeyPurpose::Session,
            tenant(),
            Zeroizing::new(*RAW_KEY_MATERIAL),
        )
        .expect("install qualification key");
    Arc::new(CountingKeyProvider::new(provider))
}

fn replica_id() -> ReplicaId {
    ReplicaId::new("consensus-snapshot-singleton").expect("replica ID")
}

fn descriptor() -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        replica_id(),
        ReplicaEndpoint::new("consensus-snapshot.invalid", 7443).expect("endpoint"),
        ReplicaTlsIdentity::new("spiffe://test/session/consensus-snapshot").expect("TLS identity"),
        ReplicaFailureDomain::new("consensus-snapshot-zone").expect("failure domain"),
        ReplicaBackingIdentity::new("consensus-snapshot-disk").expect("backing identity"),
    )
}

fn identity() -> ConsensusIdentity {
    let descriptor = descriptor();
    let cluster_id =
        ConsensusClusterId::new("session-consensus-snapshot-tests").expect("cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
    let configuration_id =
        derive_configuration_id(cluster_id, epoch, &[descriptor.configuration_fingerprint()]);
    ConsensusIdentity::new(cluster_id, configuration_id, epoch)
}

fn topology() -> ValidatedQuorumTopology {
    ValidatedQuorumTopology::try_new_consensus_lab_singleton(
        replica_id(),
        vec![descriptor()],
        identity(),
    )
    .expect("consensus singleton topology")
}

async fn open_store(database: &Path, snapshots: &Path) -> ConsensusSessionStore {
    let backend = SqliteSessionBackend::open(database).expect("open consensus SQLite backend");
    let store = ConsensusSessionStore::open(topology(), backend, snapshots, BTreeMap::new())
        .await
        .expect("open consensus singleton");
    store
        .initialize_cluster()
        .await
        .expect("initialize consensus singleton");
    // Readiness evidence follows the shared election/operation timing profile
    // rather than racing the election minimum.
    tokio::time::timeout(CONSENSUS_READY_TIMEOUT, async {
        loop {
            if store.probe_durable_readiness().await.is_ready() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("consensus singleton readiness");
    store
}

fn key(label: &'static [u8]) -> SessionKey {
    SessionKey {
        tenant: tenant(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(label)
            .try_into()
            .expect("valid stable ID"),
    }
}

fn record(
    key: SessionKey,
    lease: &crate::lease::LeaseGuard,
    plaintext: &[u8],
) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(1),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("snapshot-encryption-boundary"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(plaintext),
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn json_contains_bytes(value: &serde_json::Value, needle: &[u8]) -> bool {
    match value {
        serde_json::Value::Array(values) => {
            let encoded_bytes = values
                .iter()
                .map(|value| value.as_u64().and_then(|byte| u8::try_from(byte).ok()))
                .collect::<Option<Vec<_>>>();
            encoded_bytes
                .as_deref()
                .is_some_and(|bytes| contains_bytes(bytes, needle))
                || values
                    .iter()
                    .any(|value| json_contains_bytes(value, needle))
        }
        serde_json::Value::Object(values) => values
            .values()
            .any(|value| json_contains_bytes(value, needle)),
        serde_json::Value::String(value) => contains_bytes(value.as_bytes(), needle),
        _ => false,
    }
}

fn assert_bytes_are_sealed(label: &str, bytes: &[u8]) {
    for canary in [
        PLAINTEXT_BEFORE_ROTATION,
        PLAINTEXT_AFTER_ROTATION,
        RAW_KEY_MATERIAL.as_slice(),
    ] {
        assert!(
            !contains_bytes(bytes, canary),
            "secret material crossed the encryption boundary into {label}"
        );
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(bytes) {
            assert!(
                !json_contains_bytes(&value, canary),
                "JSON-encoded secret material crossed the encryption boundary into {label}"
            );
        }
    }
}

fn assert_sqlite_authority_is_sealed(database: &Path) {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open SQLite authority for qualification");
    for (table, column, is_json) in [
        ("session_records", "payload", false),
        ("session_replication_log", "entry_json", true),
        ("consensus_log", "entry_json", true),
        ("consensus_request_outcomes", "response_json", true),
    ] {
        let query = format!("SELECT CAST({column} AS BLOB) FROM {table}");
        let mut statement = connection.prepare(&query).expect("prepare authority scan");
        let values = statement
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .expect("query authority bytes");
        for value in values {
            let bytes = value.expect("read authority bytes");
            assert_bytes_are_sealed("SQLite authority", &bytes);
            if is_json {
                let value: serde_json::Value =
                    serde_json::from_slice(&bytes).expect("authority JSON");
                for canary in [
                    PLAINTEXT_BEFORE_ROTATION,
                    PLAINTEXT_AFTER_ROTATION,
                    RAW_KEY_MATERIAL.as_slice(),
                ] {
                    assert!(
                        !json_contains_bytes(&value, canary),
                        "secret material was encoded into SQLite consensus authority"
                    );
                }
            }
        }
    }
}

fn assert_file_tree_is_sealed(root: &Path) {
    for entry in std::fs::read_dir(root).expect("read durable artifact directory") {
        let path = entry.expect("durable artifact entry").path();
        if path.is_dir() {
            assert_file_tree_is_sealed(&path);
        } else if path.is_file() {
            let bytes = std::fs::read(&path).expect("read durable artifact");
            assert_bytes_are_sealed("durable file", &bytes);
        }
    }
}

fn snapshot_paths(snapshot_dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(snapshot_dir)
        .expect("read snapshot directory")
        .filter_map(|entry| {
            let path = entry.expect("snapshot entry").path();
            (path.extension().and_then(|extension| extension.to_str()) == Some("opc"))
                .then_some(path)
        })
        .collect()
}

fn assert_snapshot_state_is_sealed(snapshot: &Path, inspection_path: &Path) {
    let bytes = std::fs::read(snapshot).expect("read snapshot envelope");
    assert_bytes_are_sealed("snapshot envelope", &bytes);
    assert!(bytes.len() > SNAPSHOT_FOOTER_BYTES);
    let length_offset = bytes.len() - SNAPSHOT_FOOTER_BYTES + 8;
    let encoded_length: [u8; 8] = bytes[length_offset..length_offset + 8]
        .try_into()
        .expect("snapshot length");
    let payload_length =
        usize::try_from(u64::from_be_bytes(encoded_length)).expect("snapshot length fits memory");
    assert_eq!(payload_length + SNAPSHOT_FOOTER_BYTES, bytes.len());
    std::fs::write(inspection_path, &bytes[..payload_length])
        .expect("write snapshot inspection DB");
    assert_sqlite_authority_is_sealed(inspection_path);
    std::fs::remove_file(inspection_path).expect("remove snapshot inspection DB");
}

fn consensus_authority_counts(database: &Path) -> (u64, u64, u64, u64) {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("open consensus authority counters");
    connection
        .query_row(
            "SELECT machine.application_sequence,
                    machine.watch_sequence,
                    (SELECT COUNT(*) FROM session_records),
                    (SELECT COUNT(*) FROM consensus_log)
             FROM consensus_machine AS machine
             WHERE machine.singleton = 1",
            [],
            |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, u64>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, u64>(3)?,
                ))
            },
        )
        .expect("read consensus authority counters")
}

#[tokio::test]
async fn invalid_consensus_batch_is_rejected_before_log_or_key_provider_work() {
    let directory = tempfile::tempdir().expect("qualification directory");
    let database = directory.path().join("sessions.sqlite");
    let snapshots = directory.path().join("snapshots");
    let provider = provider();
    let store = open_store(&database, &snapshots).await;
    let encrypted = EncryptingSessionBackend::new(
        Arc::new(store.clone()),
        Arc::clone(&provider),
        "consensus-expiry-preflight",
    );

    let valid_key = key(b"expiry-preflight-valid");
    let invalid_key = key(b"expiry-preflight-invalid");
    let valid_lease = encrypted
        .acquire(
            &valid_key,
            OwnerId::new("expiry-preflight-valid-owner").expect("owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("valid lease");
    let invalid_lease = encrypted
        .acquire(
            &invalid_key,
            OwnerId::new("expiry-preflight-invalid-owner").expect("owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("invalid lease");
    let valid = record(valid_key.clone(), &valid_lease, b"valid-plaintext");
    let mut invalid = record(invalid_key.clone(), &invalid_lease, b"invalid-plaintext");
    invalid.expires_at = Some(Timestamp::from_offset_datetime(
        Timestamp::now_utc()
            .as_offset_datetime()
            .checked_add(time::Duration::days(366))
            .expect("far-future expiry"),
    ));
    let before = consensus_authority_counts(&database);

    assert_eq!(
        encrypted
            .batch(vec![
                SessionOp::CompareAndSet(CompareAndSet {
                    key: valid_key,
                    lease: valid_lease,
                    expected_generation: None,
                    new_record: valid,
                }),
                SessionOp::CompareAndSet(CompareAndSet {
                    key: invalid_key,
                    lease: invalid_lease,
                    expected_generation: None,
                    new_record: invalid,
                }),
            ])
            .await,
        Err(crate::StoreError::InvalidRecordExpiry)
    );
    assert_eq!(provider.call_counts(), (0, 0, 0));
    assert_eq!(consensus_authority_counts(&database), before);
}

#[tokio::test]
async fn actual_encryption_wrapper_survives_snapshot_restart_and_key_rotation() {
    let directory = tempfile::tempdir().expect("qualification directory");
    let database = directory.path().join("sessions.sqlite");
    let snapshots = directory.path().join("snapshots");
    let provider = provider();
    let store = open_store(&database, &snapshots).await;
    let encrypted = EncryptingSessionBackend::new(
        Arc::new(store.clone()),
        Arc::clone(&provider),
        ENCRYPTION_NAMESPACE,
    );

    let before_key = key(b"snapshot-before-rotation");
    let before_lease = encrypted
        .acquire(
            &before_key,
            OwnerId::new("snapshot-owner-before").expect("owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire pre-rotation lease");
    assert_eq!(
        encrypted
            .compare_and_set(CompareAndSet {
                key: before_key.clone(),
                lease: before_lease.clone(),
                expected_generation: None,
                new_record: record(before_key.clone(), &before_lease, PLAINTEXT_BEFORE_ROTATION,),
            })
            .await
            .expect("encrypted pre-rotation write"),
        CompareAndSetResult::Success
    );

    provider
        .rotate_key(KeyPurpose::Session, &tenant())
        .await
        .expect("rotate active data key");
    let after_key = key(b"snapshot-after-rotation");
    let after_lease = encrypted
        .acquire(
            &after_key,
            OwnerId::new("snapshot-owner-after").expect("owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire post-rotation lease");
    assert_eq!(
        encrypted
            .compare_and_set(CompareAndSet {
                key: after_key.clone(),
                lease: after_lease.clone(),
                expected_generation: None,
                new_record: record(after_key.clone(), &after_lease, PLAINTEXT_AFTER_ROTATION,),
            })
            .await
            .expect("encrypted post-rotation write"),
        CompareAndSetResult::Success
    );
    assert_eq!(provider.call_counts(), (2, 0, 1));

    for (key, plaintext) in [
        (&before_key, PLAINTEXT_BEFORE_ROTATION),
        (&after_key, PLAINTEXT_AFTER_ROTATION),
    ] {
        let durable = store
            .get(key)
            .await
            .expect("raw consensus read")
            .expect("durable record");
        assert_eq!(
            durable.payload.encoding(),
            SessionPayloadEncoding::EnvelopeV1
        );
        assert!(!contains_bytes(durable.payload.as_bytes(), plaintext));
    }
    assert_eq!(
        provider.call_counts(),
        (2, 0, 1),
        "Openraft and SQLite must not call the key provider"
    );

    let snapshot_log_id = store
        .inner
        .raft
        .metrics()
        .borrow()
        .last_applied
        .expect("applied log before snapshot");
    store
        .inner
        .raft
        .trigger()
        .snapshot()
        .await
        .expect("trigger snapshot");
    store
        .inner
        .raft
        .wait(Some(Duration::from_secs(5)))
        .snapshot(snapshot_log_id, "encryption-boundary snapshot")
        .await
        .expect("snapshot completes");
    assert_eq!(
        provider.call_counts(),
        (2, 0, 1),
        "snapshot construction must not call the key provider"
    );

    let snapshot_paths = snapshot_paths(&snapshots);
    assert_eq!(snapshot_paths.len(), 1);
    assert_snapshot_state_is_sealed(
        &snapshot_paths[0],
        &directory.path().join("snapshot-inspection.sqlite"),
    );
    assert_sqlite_authority_is_sealed(&database);
    assert_file_tree_is_sealed(directory.path());

    drop(encrypted);
    store
        .inner
        .raft
        .shutdown()
        .await
        .expect("shutdown original consensus node");
    drop(store);
    assert_eq!(provider.call_counts(), (2, 0, 1));

    let restarted = open_store(&database, &snapshots).await;
    assert_eq!(
        provider.call_counts(),
        (2, 0, 1),
        "restart and snapshot recovery must not call the key provider"
    );
    let reader = EncryptingSessionBackend::new(
        Arc::new(restarted.clone()),
        Arc::clone(&provider),
        ENCRYPTION_NAMESPACE,
    );
    for (key, plaintext) in [
        (&before_key, PLAINTEXT_BEFORE_ROTATION),
        (&after_key, PLAINTEXT_AFTER_ROTATION),
    ] {
        let restored = reader
            .get(key)
            .await
            .expect("decrypt after restart")
            .expect("restored record");
        assert_eq!(
            restored.payload.encoding(),
            SessionPayloadEncoding::Plaintext
        );
        assert_eq!(restored.payload.as_bytes(), plaintext);
    }
    assert_eq!(provider.call_counts(), (2, 2, 1));

    let missing_key_reader = EncryptingSessionBackend::new(
        Arc::new(restarted.clone()),
        Arc::new(MemoryKeyProvider::new()),
        ENCRYPTION_NAMESPACE,
    );
    let error = missing_key_reader
        .get(&before_key)
        .await
        .expect_err("missing historical key must fail closed");
    let rendered = format!("{error} {error:?}");
    assert!(!contains_bytes(
        rendered.as_bytes(),
        PLAINTEXT_BEFORE_ROTATION
    ));

    drop(reader);
    drop(missing_key_reader);
    restarted
        .inner
        .raft
        .shutdown()
        .await
        .expect("shutdown restarted consensus node");
}

const REMOTE_ROTATION_MEMBER_COUNT: usize = 3;
const REMOTE_ROTATION_POLL_INTERVAL: Duration = Duration::from_millis(20);
const REMOTE_ROTATION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
struct RemoteRotationPeer {
    target: SessionConsensusNodeId,
    handler: Arc<tokio::sync::RwLock<Option<Arc<dyn SessionConsensusRpcHandler>>>>,
    enabled: Arc<AtomicBool>,
}

impl RemoteRotationPeer {
    fn new(target: SessionConsensusNodeId) -> Self {
        Self {
            target,
            handler: Arc::new(tokio::sync::RwLock::new(None)),
            enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    async fn install(&self, handler: Arc<dyn SessionConsensusRpcHandler>) {
        *self.handler.write().await = Some(handler);
    }

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
    }
}

impl fmt::Debug for RemoteRotationPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteRotationPeer")
            .field("target", &self.target)
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SessionConsensusPeer for RemoteRotationPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.target
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        if !self.enabled.load(Ordering::SeqCst) {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(SessionConsensusPeerError::Unavailable)?;
        Ok(handler.handle(request.sender, request).await)
    }
}

fn remote_rotation_replica_id(index: usize) -> ReplicaId {
    ReplicaId::new(format!("remote-rotation-{index}")).expect("replica ID")
}

fn remote_rotation_member(index: usize) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        remote_rotation_replica_id(index),
        ReplicaEndpoint::new(format!("remote-rotation-{index}.invalid"), 7443).expect("endpoint"),
        ReplicaTlsIdentity::new(format!("spiffe://test/session/remote-rotation/{index}"))
            .expect("TLS identity"),
        ReplicaFailureDomain::new(format!("remote-rotation-zone-{index}")).expect("failure domain"),
        ReplicaBackingIdentity::new(format!("remote-rotation-disk-{index}"))
            .expect("backing identity"),
    )
}

fn remote_rotation_identity(members: &[QuorumReplicaDescriptor]) -> ConsensusIdentity {
    let cluster_id = ConsensusClusterId::new("session-remote-rotation-tests").expect("cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
    let fingerprints = members
        .iter()
        .map(QuorumReplicaDescriptor::configuration_fingerprint)
        .collect::<Vec<_>>();
    let configuration_id = derive_configuration_id(cluster_id, epoch, &fingerprints);
    ConsensusIdentity::new(cluster_id, configuration_id, epoch)
}

struct RemoteRotationCluster {
    directory: TempDir,
    backends: Vec<SqliteSessionBackend>,
    stores: Vec<ConsensusSessionStore>,
    paths: BTreeMap<(usize, usize), Arc<RemoteRotationPeer>>,
}

impl RemoteRotationCluster {
    async fn start() -> Self {
        Self::open(tempfile::tempdir().expect("create remote rotation directory")).await
    }

    async fn open(directory: TempDir) -> Self {
        let backends = (0..REMOTE_ROTATION_MEMBER_COUNT)
            .map(|index| {
                SqliteSessionBackend::open(directory.path().join(format!("node-{index}.sqlite")))
                    .expect("open remote rotation SQLite node")
            })
            .collect::<Vec<_>>();
        let members = (0..REMOTE_ROTATION_MEMBER_COUNT)
            .map(remote_rotation_member)
            .collect::<Vec<_>>();
        let identity = remote_rotation_identity(&members);
        let topologies = (0..REMOTE_ROTATION_MEMBER_COUNT)
            .map(|index| {
                ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                    remote_rotation_replica_id(index),
                    members.clone(),
                    identity,
                ))
                .expect("validate remote rotation topology")
            })
            .collect::<Vec<_>>();
        let node_ids = topologies
            .iter()
            .map(|topology| {
                topology
                    .local_consensus_node_id()
                    .expect("consensus node ID")
            })
            .collect::<Vec<_>>();

        let mut paths = BTreeMap::new();
        for source in 0..REMOTE_ROTATION_MEMBER_COUNT {
            for (target, node_id) in node_ids.iter().copied().enumerate() {
                if source != target {
                    paths.insert((source, target), Arc::new(RemoteRotationPeer::new(node_id)));
                }
            }
        }

        let mut stores = Vec::with_capacity(REMOTE_ROTATION_MEMBER_COUNT);
        for index in 0..REMOTE_ROTATION_MEMBER_COUNT {
            let peers = (0..REMOTE_ROTATION_MEMBER_COUNT)
                .filter(|target| *target != index)
                .map(|target| {
                    let peer: Arc<dyn SessionConsensusPeer> =
                        paths.get(&(index, target)).expect("loopback path").clone();
                    (node_ids[target], peer)
                })
                .collect::<BTreeMap<_, _>>();
            let store = ConsensusSessionStore::open(
                topologies[index].clone(),
                backends[index].clone(),
                directory.path().join(format!("snapshots-{index}")),
                peers,
            )
            .await
            .expect("open remote rotation consensus node");
            stores.push(store);
        }

        for ((_, target), path) in &paths {
            path.install(stores[*target].rpc_handler()).await;
        }
        let results = futures_util::future::join_all(
            stores.iter().map(ConsensusSessionStore::initialize_cluster),
        )
        .await;
        for result in results {
            result.expect("initialize remote rotation membership");
        }

        let cluster = Self {
            directory,
            backends,
            stores,
            paths,
        };
        cluster.wait_all_ready().await;
        cluster
    }

    async fn wait_all_ready(&self) {
        tokio::time::timeout(REMOTE_ROTATION_TIMEOUT, async {
            loop {
                let reports = futures_util::future::join_all(
                    self.stores
                        .iter()
                        .map(ConsensusSessionStore::probe_durable_readiness),
                )
                .await;
                if reports.iter().all(|report| report.is_ready()) {
                    return;
                }
                tokio::time::sleep(REMOTE_ROTATION_POLL_INTERVAL).await;
            }
        })
        .await
        .expect("remote rotation cluster reaches readiness");
    }

    async fn wait_surviving_majority_ready(&self) {
        tokio::time::timeout(REMOTE_ROTATION_TIMEOUT, async {
            loop {
                let reports = futures_util::future::join_all(
                    self.stores[1..]
                        .iter()
                        .map(ConsensusSessionStore::probe_durable_readiness),
                )
                .await;
                if reports.iter().all(|report| report.is_ready()) {
                    return;
                }
                tokio::time::sleep(REMOTE_ROTATION_POLL_INTERVAL).await;
            }
        })
        .await
        .expect("surviving remote rotation majority reaches readiness");
    }

    fn isolate(&self, node: usize) {
        for peer in 0..REMOTE_ROTATION_MEMBER_COUNT {
            if peer != node {
                self.paths
                    .get(&(node, peer))
                    .expect("outbound path")
                    .set_enabled(false);
                self.paths
                    .get(&(peer, node))
                    .expect("inbound path")
                    .set_enabled(false);
            }
        }
    }

    fn heal(&self, node: usize) {
        for peer in 0..REMOTE_ROTATION_MEMBER_COUNT {
            if peer != node {
                self.paths
                    .get(&(node, peer))
                    .expect("outbound path")
                    .set_enabled(true);
                self.paths
                    .get(&(peer, node))
                    .expect("inbound path")
                    .set_enabled(true);
            }
        }
    }

    async fn snapshot_surviving_majority(&self, lagging_applied: u64) {
        for store in &self.stores[1..] {
            let applied = store
                .inner
                .raft
                .metrics()
                .borrow()
                .last_applied
                .expect("applied log before snapshot");
            store
                .inner
                .raft
                .trigger()
                .snapshot()
                .await
                .expect("trigger remote rotation snapshot");
            store
                .inner
                .raft
                .wait(Some(Duration::from_secs(10)))
                .snapshot(applied, "remote rotation snapshot")
                .await
                .expect("remote rotation snapshot completes");
            store
                .inner
                .raft
                .trigger()
                .purge_log(applied.index)
                .await
                .expect("purge logs covered by remote rotation snapshot");
        }

        tokio::time::timeout(REMOTE_ROTATION_TIMEOUT, async {
            loop {
                let compacted = self.stores[1..].iter().all(|store| {
                    let metrics = store.inner.raft.metrics();
                    let metrics = metrics.borrow();
                    metrics
                        .purged
                        .is_some_and(|log_id| log_id.index > lagging_applied)
                        && metrics.snapshot.is_some()
                });
                if compacted {
                    return;
                }
                tokio::time::sleep(REMOTE_ROTATION_POLL_INTERVAL).await;
            }
        })
        .await
        .expect("surviving majority compacts beyond isolated follower");
    }

    async fn shutdown_and_restart(self) -> Self {
        let results = futures_util::future::join_all(
            self.stores.iter().map(|store| store.inner.raft.shutdown()),
        )
        .await;
        for result in results {
            result.expect("shut down remote rotation member");
        }
        let Self {
            directory,
            backends,
            stores,
            paths,
        } = self;
        drop(paths);
        drop(stores);
        drop(backends);
        Self::open(directory).await
    }

    async fn shutdown(&self) {
        let results = futures_util::future::join_all(
            self.stores.iter().map(|store| store.inner.raft.shutdown()),
        )
        .await;
        assert!(results.into_iter().all(|result| result.is_ok()));
    }
}

struct CountingRemoteSealProvider {
    inner: Arc<MemoryRemoteSealProvider>,
    seal_calls: AtomicUsize,
    unseal_calls: AtomicUsize,
}

impl CountingRemoteSealProvider {
    fn new(inner: Arc<MemoryRemoteSealProvider>) -> Self {
        Self {
            inner,
            seal_calls: AtomicUsize::new(0),
            unseal_calls: AtomicUsize::new(0),
        }
    }

    fn call_counts(&self) -> (usize, usize) {
        (
            self.seal_calls.load(Ordering::SeqCst),
            self.unseal_calls.load(Ordering::SeqCst),
        )
    }
}

#[async_trait]
impl RemoteSealProvider for CountingRemoteSealProvider {
    async fn seal(
        &self,
        aad: &EnvelopeAad,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, KeyError> {
        self.seal_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.seal(aad, plaintext).await
    }

    async fn unseal(
        &self,
        key_id: &KeyId,
        aad: &EnvelopeAad,
        ciphertext_and_tag: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        self.unseal_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.unseal(key_id, aad, ciphertext_and_tag).await
    }
}

#[tokio::test]
async fn remote_seal_rotation_survives_three_node_snapshot_install_and_restart() {
    let cluster = RemoteRotationCluster::start().await;
    let lagging_applied = cluster.stores[0]
        .inner
        .raft
        .metrics()
        .borrow()
        .last_applied
        .expect("initial follower applied log")
        .index;
    cluster.isolate(0);
    cluster.wait_surviving_majority_ready().await;

    let material = Arc::new(MemoryRemoteSealProvider::new(
        KeyId::new("consensus-remote-key-2026-01").expect("key ID"),
        KeyPurpose::Session,
        tenant(),
        Zeroizing::new(*RAW_KEY_MATERIAL),
    ));
    let provider = Arc::new(CountingRemoteSealProvider::new(Arc::clone(&material)));
    let writer = RemoteSealingSessionBackend::new(
        Arc::new(cluster.stores[1].clone()),
        Arc::clone(&provider),
        ENCRYPTION_NAMESPACE,
    );

    let before_key = key(b"remote-before-rotation");
    let before_lease = writer
        .acquire(
            &before_key,
            OwnerId::new("remote-owner-before").expect("owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("pre-rotation lease");
    assert_eq!(
        writer
            .compare_and_set(CompareAndSet {
                key: before_key.clone(),
                lease: before_lease.clone(),
                expected_generation: None,
                new_record: record(before_key.clone(), &before_lease, PLAINTEXT_BEFORE_ROTATION,),
            })
            .await
            .expect("pre-rotation remote seal"),
        CompareAndSetResult::Success
    );
    let old_key_id = material.active_key_id().await.expect("old key ID");

    let new_key_id = material.rotate_key().await.expect("rotate remote seal key");
    let after_key = key(b"remote-after-rotation");
    let after_lease = writer
        .acquire(
            &after_key,
            OwnerId::new("remote-owner-after").expect("owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("post-rotation lease");
    assert_eq!(
        writer
            .compare_and_set(CompareAndSet {
                key: after_key.clone(),
                lease: after_lease.clone(),
                expected_generation: None,
                new_record: record(after_key.clone(), &after_lease, PLAINTEXT_AFTER_ROTATION,),
            })
            .await
            .expect("post-rotation remote seal"),
        CompareAndSetResult::Success
    );
    assert_ne!(old_key_id, new_key_id);
    assert_eq!(provider.call_counts(), (2, 0));

    cluster.snapshot_surviving_majority(lagging_applied).await;
    assert_eq!(
        provider.call_counts(),
        (2, 0),
        "replication or snapshot construction called remote provider"
    );

    cluster.heal(0);
    cluster.wait_all_ready().await;
    let recovered_metrics = cluster.stores[0].inner.raft.metrics();
    let recovered_metrics = recovered_metrics.borrow();
    assert!(recovered_metrics
        .snapshot
        .is_some_and(|log_id| log_id.index > lagging_applied));
    assert!(recovered_metrics
        .last_applied
        .is_some_and(|log_id| log_id.index > lagging_applied));
    drop(recovered_metrics);
    for (session_key, expected_key_id, plaintext) in [
        (&before_key, &old_key_id, PLAINTEXT_BEFORE_ROTATION),
        (&after_key, &new_key_id, PLAINTEXT_AFTER_ROTATION),
    ] {
        let raw = cluster.stores[0]
            .get(session_key)
            .await
            .expect("raw read after snapshot install")
            .expect("snapshot-installed record");
        let envelope = CryptoEnvelopeV1::decode(raw.payload.as_bytes()).expect("envelope");
        assert_eq!(&envelope.key_id, expected_key_id);
        assert!(!contains_bytes(raw.payload.as_bytes(), plaintext));
    }
    assert_eq!(
        provider.call_counts(),
        (2, 0),
        "snapshot install or raw consensus read called remote provider"
    );
    assert_file_tree_is_sealed(cluster.directory.path());

    drop(writer);
    let cluster = cluster.shutdown_and_restart().await;
    assert_eq!(
        provider.call_counts(),
        (2, 0),
        "shutdown, replay, quorum formation, or recovery called remote provider"
    );
    let reader = RemoteSealingSessionBackend::new(
        Arc::new(cluster.stores[1].clone()),
        Arc::clone(&provider),
        ENCRYPTION_NAMESPACE,
    );
    let restored = reader
        .scan_restore_records(RestoreScanRequest::all(16))
        .await
        .expect("restore both remote key epochs");
    assert_eq!(restored.loaded_count, 2);
    for (session_key, expected) in [
        (&before_key, PLAINTEXT_BEFORE_ROTATION),
        (&after_key, PLAINTEXT_AFTER_ROTATION),
    ] {
        let restored_record = restored
            .records
            .iter()
            .find(|record| &record.key == session_key)
            .expect("restored material epoch");
        assert_eq!(restored_record.payload.as_bytes(), expected);
    }
    assert_eq!(
        provider.call_counts(),
        (2, 2),
        "only outer restore unseal may call remote provider"
    );

    drop(reader);
    cluster.shutdown().await;
}
