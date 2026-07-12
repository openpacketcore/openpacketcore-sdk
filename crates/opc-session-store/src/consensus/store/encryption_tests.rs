use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use opc_consensus::{
    derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
};
use opc_key::{
    KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose, MemoryKeyProvider, Zeroizing,
    AES_256_GCM_SIV_KEY_LEN,
};
use opc_types::{NetworkFunctionKind, TenantId};

use super::ConsensusSessionStore;
use crate::backend::{
    CompareAndSet, CompareAndSetResult, EncryptingSessionBackend, SessionBackend,
};
use crate::lease::SessionLeaseManager;
use crate::model::{Generation, OwnerId, SessionKey, SessionKeyType, StateClass, StateType};
use crate::record::{EncryptedSessionPayload, SessionPayloadEncoding, StoredSessionRecord};
use crate::sqlite::SqliteSessionBackend;
use crate::topology::{
    QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaTlsIdentity, ValidatedQuorumTopology,
};

const ENCRYPTION_NAMESPACE: &str = "consensus-snapshot-boundary-qualification";
const PLAINTEXT_BEFORE_ROTATION: &[u8] = b"snapshot-restart-plaintext-canary-before-key-rotation";
const PLAINTEXT_AFTER_ROTATION: &[u8] = b"snapshot-restart-plaintext-canary-after-key-rotation";
const RAW_KEY_MATERIAL: &[u8; AES_256_GCM_SIV_KEY_LEN] = &[0x6b; AES_256_GCM_SIV_KEY_LEN];
const SNAPSHOT_FOOTER_BYTES: usize = 8 + 8 + 32;

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
    tokio::time::timeout(Duration::from_secs(5), async {
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
        stable_id: Bytes::from_static(label),
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
