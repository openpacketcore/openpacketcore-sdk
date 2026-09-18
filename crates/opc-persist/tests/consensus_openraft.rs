mod management_audit_authority;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use opc_consensus::{
    ConsensusPeer, ConsensusPeerError, ConsensusRpcFamily, ConsensusRpcHandler,
    ConsensusWireRequest, ConsensusWireResponse, DURABLE_CONSENSUS_TIMING_PROFILE,
};
use opc_crypto::{encrypt_attested_envelope_with_handle_and_nonce, AuthenticatedEnvelope};
use opc_key::{
    ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose, Zeroizing, AES_256_GCM_SIV_KEY_LEN,
    AES_256_GCM_SIV_NONCE_LEN,
};
#[cfg(feature = "dangerous-test-hooks")]
use opc_persist::ConfirmedCommitResolution;
use opc_persist::{
    ApprovedLegacyConfigRecovery, AttestedConfigCommit, AuditKey, AuditOpType, AuditRecord,
    CommitRecord, CommitSource, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, ConfigConsensusNodeId,
    ConfigConsensusRequestId, ConfigConsensusTopology, ConfigStore, ConsensusConfigStore,
    LegacyConfigTailDisposition, PersistErrorKind, RetainedConfigBinding, RetainedConfigDurability,
    RetainedConfigOptions, RollbackTarget, SqliteBackend,
};
use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};
use sha2::{Digest, Sha256};

const PLAINTEXT_CANARY: &[u8] = b"CONFIG-PLAINTEXT-MUST-NEVER-CROSS-RAFT";
const PROVIDER_ENDPOINT_CANARY: &[u8] = b"hkms+unix:///must-not-cross-raft/provider.sock";
const OPAQUE_HANDLE_CANARY: &[u8] = b"HKMS-OPAQUE-HANDLE-MUST-NOT-CROSS-RAFT";
const RAW_KEY_MATERIAL_CANARY: &[u8] = &[0x55; 32];
// Admit one complete resampled election after a split vote, followed by one
// complete profiled operation. Cluster formation and survivor-election
// evidence must follow the shared timing authority.
const CLUSTER_TRANSITION_TIMEOUT: Duration = Duration::from_millis(
    DURABLE_CONSENSUS_TIMING_PROFILE
        .election_timeout_max_millis
        .saturating_mul(2)
        .saturating_add(DURABLE_CONSENSUS_TIMING_PROFILE.operation_timeout_millis),
);

const FORBIDDEN_RAFT_ARTIFACTS: &[(&str, &[u8])] = &[
    ("configuration plaintext", PLAINTEXT_CANARY),
    ("HKMS provider endpoint", PROVIDER_ENDPOINT_CANARY),
    ("opaque HKMS handle", OPAQUE_HANDLE_CANARY),
    ("raw audit key material", RAW_KEY_MATERIAL_CANARY),
];

#[derive(Clone)]
struct LoopbackPeer {
    target: ConfigConsensusNodeId,
    handler: Arc<tokio::sync::RwLock<Option<Arc<dyn ConsensusRpcHandler>>>>,
    enabled: Arc<AtomicBool>,
    drop_forward_responses: Arc<AtomicUsize>,
    stall_forward_mutation: Arc<AtomicBool>,
    stall_read_barrier: Arc<AtomicBool>,
    pause_forward_response: Arc<AtomicBool>,
    forward_response_ready: Arc<tokio::sync::Notify>,
    release_forward_response: Arc<tokio::sync::Notify>,
    captured_payloads: Arc<StdMutex<Vec<Vec<u8>>>>,
}

impl LoopbackPeer {
    fn new(target: ConfigConsensusNodeId) -> Self {
        Self {
            target,
            handler: Arc::new(tokio::sync::RwLock::new(None)),
            enabled: Arc::new(AtomicBool::new(true)),
            drop_forward_responses: Arc::new(AtomicUsize::new(0)),
            stall_forward_mutation: Arc::new(AtomicBool::new(false)),
            stall_read_barrier: Arc::new(AtomicBool::new(false)),
            pause_forward_response: Arc::new(AtomicBool::new(false)),
            forward_response_ready: Arc::new(tokio::sync::Notify::new()),
            release_forward_response: Arc::new(tokio::sync::Notify::new()),
            captured_payloads: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    async fn install(&self, handler: Arc<dyn ConsensusRpcHandler>) {
        *self.handler.write().await = Some(handler);
    }

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
    }

    fn drop_forward_responses(&self, count: usize) {
        self.drop_forward_responses.store(count, Ordering::SeqCst);
    }

    fn stall_family(&self, family: ConsensusRpcFamily, stalled: bool) {
        match family {
            ConsensusRpcFamily::ForwardMutation => {
                self.stall_forward_mutation.store(stalled, Ordering::SeqCst);
            }
            ConsensusRpcFamily::ReadBarrier => {
                self.stall_read_barrier.store(stalled, Ordering::SeqCst);
            }
            _ => panic!("unsupported stalled family"),
        }
    }
}

impl fmt::Debug for LoopbackPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackPeer")
            .field("target", &self.target)
            .field("enabled", &self.enabled.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl ConsensusPeer for LoopbackPeer {
    fn node_id(&self) -> ConfigConsensusNodeId {
        self.target
    }

    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        if !self.enabled.load(Ordering::SeqCst) {
            return Err(ConsensusPeerError::Unavailable);
        }
        self.captured_payloads
            .lock()
            .expect("capture mutex")
            .push(request.payload.clone());
        let stalled = match request.family {
            ConsensusRpcFamily::ForwardMutation => {
                self.stall_forward_mutation.load(Ordering::SeqCst)
            }
            ConsensusRpcFamily::ReadBarrier => self.stall_read_barrier.load(Ordering::SeqCst),
            _ => false,
        };
        if stalled {
            std::future::pending::<()>().await;
            unreachable!("stalled consensus peer resumed");
        }
        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(ConsensusPeerError::Unavailable)?;
        let sender = request.sender;
        let family = request.family;
        let response = handler.handle(sender, request).await;
        if family == ConsensusRpcFamily::ForwardMutation
            && self.pause_forward_response.load(Ordering::SeqCst)
        {
            self.forward_response_ready.notify_one();
            self.release_forward_response.notified().await;
        }
        if family == ConsensusRpcFamily::ForwardMutation
            && self
                .drop_forward_responses
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
        {
            return Err(ConsensusPeerError::Unavailable);
        }
        Ok(response)
    }
}

#[derive(Clone, Copy)]
enum FixtureStorage {
    Legacy,
    RetainedNew,
    RetainedRepair,
}

struct ThreeNodeCluster {
    _directory: tempfile::TempDir,
    stores: Vec<ConsensusConfigStore>,
    paths: BTreeMap<(usize, usize), Arc<LoopbackPeer>>,
}

impl ThreeNodeCluster {
    async fn start() -> Self {
        let cluster = Self::build([[0x55; 32]; 3]).await;
        let (one, two, three) = tokio::join!(
            cluster.stores[0].initialize_cluster(),
            cluster.stores[1].initialize_cluster(),
            cluster.stores[2].initialize_cluster(),
        );
        one.expect("initialize node one");
        two.expect("initialize node two");
        three.expect("initialize node three");
        cluster.wait_ready().await;
        cluster
    }

    async fn build(audit_key_material: [[u8; 32]; 3]) -> Self {
        Self::build_with_storage(audit_key_material, FixtureStorage::Legacy).await
    }

    async fn build_with_storage(
        audit_key_material: [[u8; 32]; 3],
        lifecycle: FixtureStorage,
    ) -> Self {
        let directory = tempfile::tempdir().expect("cluster directory");
        let nodes = [1_u64, 2, 3].map(|value| ConfigConsensusNodeId::new(value).expect("node ID"));
        let members = nodes.into_iter().collect::<BTreeSet<_>>();
        let cluster =
            ConfigConsensusClusterId::new("opc-persist-three-node-tests").expect("cluster ID");
        let epoch = ConfigConsensusConfigurationEpoch::new(1).expect("epoch");
        let identity = ConfigConsensusIdentity::new(
            cluster,
            ConfigConsensusConfigurationId::from_bytes([0x99; 32]),
            epoch,
        );
        let topologies = nodes.map(|node| {
            ConfigConsensusTopology::try_new(identity, node, members.clone()).expect("topology")
        });
        let mut paths = BTreeMap::new();
        for source in 0..3 {
            for (target, target_node) in nodes.iter().copied().enumerate() {
                if source != target {
                    paths.insert((source, target), Arc::new(LoopbackPeer::new(target_node)));
                }
            }
        }
        let mut stores = Vec::new();
        for (index, topology) in topologies.iter().cloned().enumerate() {
            let backend = if matches!(lifecycle, FixtureStorage::RetainedRepair) {
                SqliteBackend::provision_config_member_repair(
                    retained_options(
                        &directory.path().join(format!("node-{index}.sqlite")),
                        topology.clone(),
                        index as u8 + 1,
                    ),
                    AuditKey::new(audit_key_material[index]).expect("audit key"),
                )
                .await
                .expect("repair backend")
            } else if matches!(lifecycle, FixtureStorage::RetainedNew) {
                SqliteBackend::provision_config_authority(
                    retained_options(
                        &directory.path().join(format!("node-{index}.sqlite")),
                        topology.clone(),
                        index as u8 + 1,
                    ),
                    AuditKey::new(audit_key_material[index]).expect("audit key"),
                )
                .await
                .expect("retained backend")
            } else {
                SqliteBackend::open_with_audit_key(
                    directory.path().join(format!("node-{index}.sqlite")),
                    true,
                    0,
                    AuditKey::new(audit_key_material[index]).expect("audit key"),
                )
                .await
                .expect("backend")
            };
            let peers = (0..3)
                .filter(|target| *target != index)
                .map(|target| {
                    let peer: Arc<dyn ConsensusPeer> =
                        paths.get(&(index, target)).expect("path").clone();
                    (nodes[target], peer)
                })
                .collect();
            stores.push(
                ConsensusConfigStore::open_with_operation_timeout(
                    topology,
                    backend,
                    directory.path().join(format!("snapshots-{index}")),
                    peers,
                    Duration::from_secs(3),
                )
                .await
                .expect("store"),
            );
        }
        for ((_, target), path) in &paths {
            path.install(stores[*target].rpc_handler()).await;
        }
        Self {
            _directory: directory,
            stores,
            paths,
        }
    }

    async fn wait_ready(&self) {
        tokio::time::timeout(CLUSTER_TRANSITION_TIMEOUT, async {
            loop {
                let (one, two, three) = tokio::join!(
                    self.stores[0].probe_durable_readiness(),
                    self.stores[1].probe_durable_readiness(),
                    self.stores[2].probe_durable_readiness(),
                );
                if one.is_ok() && two.is_ok() && three.is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("cluster ready");
    }

    fn leader(&self) -> usize {
        let leader = self
            .stores
            .iter()
            .find_map(|store| store.status().leader_id)
            .expect("known leader");
        self.stores
            .iter()
            .position(|store| store.status().node_id == leader)
            .expect("leader index")
    }

    fn database_path(&self, node: usize) -> std::path::PathBuf {
        self._directory.path().join(format!("node-{node}.sqlite"))
    }

    fn isolate(&self, node: usize) {
        for peer in 0..3 {
            if peer != node {
                self.paths
                    .get(&(node, peer))
                    .expect("path")
                    .set_enabled(false);
                self.paths
                    .get(&(peer, node))
                    .expect("path")
                    .set_enabled(false);
            }
        }
    }

    fn heal(&self, node: usize) {
        for peer in 0..3 {
            if peer != node {
                self.paths
                    .get(&(node, peer))
                    .expect("path")
                    .set_enabled(true);
                self.paths
                    .get(&(peer, node))
                    .expect("path")
                    .set_enabled(true);
            }
        }
    }

    async fn shutdown(&self) {
        let _ = tokio::join!(
            self.stores[0].shutdown(),
            self.stores[1].shutdown(),
            self.stores[2].shutdown(),
        );
    }
}

fn topology() -> ConfigConsensusTopology {
    let node = ConfigConsensusNodeId::new(1).expect("node ID");
    let cluster = ConfigConsensusClusterId::new("opc-persist-openraft-tests").expect("cluster");
    let epoch = ConfigConsensusConfigurationEpoch::new(1).expect("epoch");
    let identity = ConfigConsensusIdentity::new(
        cluster,
        ConfigConsensusConfigurationId::from_bytes([0x42; 32]),
        epoch,
    );
    ConfigConsensusTopology::try_new(identity, node, BTreeSet::from([node])).expect("topology")
}

fn audit_key() -> AuditKey {
    AuditKey::new([0x55; 32]).expect("audit key")
}

fn envelope(
    seed: u8,
    tx_id: TxId,
    parent: Option<TxId>,
    version: u64,
    committed_at: Timestamp,
    principal: &str,
    schema_digest: SchemaDigest,
) -> AuthenticatedEnvelope {
    let key_id = KeyId::new(format!("config-key-{seed}")).expect("key ID");
    let aad = EnvelopeAad::config(
        opc_types::TenantId::from_static("tenant-a"),
        version,
        ConfigAad::new(
            tx_id,
            parent,
            committed_at,
            principal,
            schema_digest,
            "running",
        )
        .expect("config AAD"),
    );
    let handle = KeyHandle::new(
        key_id,
        KeyPurpose::Config,
        opc_types::TenantId::from_static("tenant-a"),
        Zeroizing::new([seed; AES_256_GCM_SIV_KEY_LEN]),
    );
    encrypt_attested_envelope_with_handle_and_nonce(
        &handle,
        &aad,
        &[seed; 32],
        [seed; AES_256_GCM_SIV_NONCE_LEN],
    )
    .expect("authenticated envelope")
}

fn commit(tx_id: TxId, parent: Option<TxId>, version: u64, seed: u8) -> CommitRecord {
    let committed_at = Timestamp::now_utc();
    let principal =
        "spiffe://test.example/tenant/tenant-a/ns/core/sa/config/nf/amf/instance/a".to_string();
    let schema_digest = SchemaDigest::from_bytes([seed; 32]);
    let envelope = envelope(
        seed,
        tx_id,
        parent,
        version,
        committed_at,
        &principal,
        schema_digest,
    );
    CommitRecord {
        tx_id,
        parent_tx_id: parent,
        version: ConfigVersion::new(version),
        committed_at,
        principal: principal.clone(),
        source: CommitSource::Gnmi,
        schema_digest,
        plaintext_digest: Sha256::digest([seed; 32]).to_vec(),
        encrypted_blob: envelope.encoded().to_vec(),
        rollback_point: false,
        confirmed_deadline: None,
    }
}

fn attested(record: CommitRecord, audit: Vec<AuditRecord>) -> AttestedConfigCommit {
    let seed = record.schema_digest.as_bytes()[0];
    let envelope = envelope(
        seed,
        record.tx_id,
        record.parent_tx_id,
        record.version.get(),
        record.committed_at,
        &record.principal,
        record.schema_digest,
    );
    AttestedConfigCommit::try_new(record, audit, envelope.claim().expect("fresh claim"))
        .expect("attested config commit")
}

#[cfg(feature = "dangerous-test-hooks")]
fn fenced_attested(mut record: CommitRecord, audit: Vec<AuditRecord>) -> AttestedConfigCommit {
    let seed = record.schema_digest.as_bytes()[0];
    let aad_principal = record.principal.clone();
    let envelope = envelope(
        seed,
        record.tx_id,
        record.parent_tx_id,
        record.version.get(),
        record.committed_at,
        &aad_principal,
        record.schema_digest,
    );
    record.principal = serde_json::json!({
        "principal": aad_principal,
        "recovery_required": true,
    })
    .to_string();
    AttestedConfigCommit::try_new(record, audit, envelope.claim().expect("fresh fenced claim"))
        .expect("attested fenced config commit")
}

#[cfg(feature = "dangerous-test-hooks")]
fn attested_resolving(
    record: CommitRecord,
    audit: Vec<AuditRecord>,
    resolution: ConfirmedCommitResolution,
) -> AttestedConfigCommit {
    let seed = record.schema_digest.as_bytes()[0];
    let envelope = envelope(
        seed,
        record.tx_id,
        record.parent_tx_id,
        record.version.get(),
        record.committed_at,
        &record.principal,
        record.schema_digest,
    );
    AttestedConfigCommit::try_new_resolving(
        record,
        audit,
        envelope.claim().expect("fresh claim"),
        resolution,
    )
    .expect("attested resolving config commit")
}

fn audit(tx_id: TxId) -> Vec<AuditRecord> {
    let sensitive_value = format!(
        "{}|{}|{}",
        String::from_utf8_lossy(PLAINTEXT_CANARY),
        String::from_utf8_lossy(PROVIDER_ENDPOINT_CANARY),
        String::from_utf8_lossy(OPAQUE_HANDLE_CANARY),
    );
    vec![AuditRecord {
        tx_id,
        sequence: 0,
        yang_path: "/system/config/hostname".into(),
        op_type: AuditOpType::Replace,
        previous_value: Some(sensitive_value.clone()),
        new_value: Some(sensitive_value),
        redaction_applied: false,
        previous_hash: [0; 32],
        entry_hmac: [0; 32],
    }]
}

async fn open_singleton(
    database: &std::path::Path,
    snapshots: &std::path::Path,
) -> (ConsensusConfigStore, SqliteBackend) {
    let backend = SqliteBackend::open_with_audit_key(database, true, 0, audit_key())
        .await
        .expect("backend");
    let bypass = backend.clone();
    let store = ConsensusConfigStore::open(topology(), backend, snapshots, BTreeMap::new())
        .await
        .expect("consensus store");
    store.initialize_cluster().await.expect("initialize");
    (store, bypass)
}

// SDK #802: a real committed-history prune must produce the typed floor while
// preserving the exact encrypted successor lineage and request outcome.
#[tokio::test]
async fn acknowledged_history_retention_produces_real_compacted_cursor() {
    let directory = tempfile::tempdir().expect("test directory");
    let database = directory.path().join("config.db");
    let (store, backend) = open_singleton(&database, &directory.path().join("snapshots")).await;
    let transactions: Vec<_> = (0..6).map(|_| TxId::new()).collect();
    for (index, tx_id) in transactions.iter().copied().enumerate() {
        let parent = index.checked_sub(1).map(|index| transactions[index]);
        store
            .append_attested_commit(attested(
                commit(tx_id, parent, index as u64 + 1, 0x62),
                vec![],
            ))
            .await
            .expect("commit complete encrypted configuration");
    }
    let decision = opc_persist::ConfigHistoryRetention::new(
        transactions[5],
        ConfigVersion::new(6),
        ConfigVersion::new(3),
        ConfigVersion::new(4),
        opc_persist::ConfigHistoryLimits::new(4, 1_048_576).expect("bounds"),
    )
    .expect("acknowledged boundary");
    let request = ConfigConsensusRequestId::from_bytes([0xC2; 16]);
    let outcome = store
        .retain_history_idempotent(request, decision.clone())
        .await;
    // Always reap this real engine, including the preserved pre-fix detector.
    if let Err(error) = outcome {
        store
            .shutdown()
            .await
            .expect("stop engine after rejected retention");
        panic!("production retained-history decision did not apply: {error}");
    }
    let compacted = store
        .load_since(ConfigVersion::new(2), 8)
        .await
        .expect_err("pruned successor");
    assert!(matches!(
        compacted.kind(),
        PersistErrorKind::ConfigHistoryCompacted
    ));
    let retained = store
        .load_since(ConfigVersion::new(3), 8)
        .await
        .expect("exact retained boundary");
    assert_eq!(
        retained
            .iter()
            .map(|entry| entry.record.version.get())
            .collect::<Vec<_>>(),
        vec![4, 5, 6]
    );
    assert_eq!(retained[0].record.parent_tx_id, Some(transactions[2]));
    assert_eq!(retained[0].record.tx_id, transactions[3]);
    store
        .retain_history_idempotent(request, decision)
        .await
        .expect("exact retention replay");
    let reader = rusqlite::Connection::open(&database).expect("independent database observation");
    let count: i64 = reader
        .query_row("SELECT COUNT(*) FROM config_history", [], |row| row.get(0))
        .expect("retained row count");
    assert_eq!(count, 3);
    drop(reader);
    store.shutdown().await.expect("stop engine");
    drop(store);
    drop(backend);
}

fn retention(
    head: TxId,
    version: u64,
    from: u64,
    records: u32,
    bytes: u64,
) -> opc_persist::ConfigHistoryRetention {
    opc_persist::ConfigHistoryRetention::new(
        head,
        ConfigVersion::new(version),
        ConfigVersion::new(from - 1),
        ConfigVersion::new(from),
        opc_persist::ConfigHistoryLimits::new(records, bytes).expect("history bounds"),
    )
    .expect("history decision")
}

#[tokio::test]
async fn history_retention_caps_are_atomic_and_outcomes_survive_pruning() {
    let dir = tempfile::tempdir().expect("directory");
    let path = dir.path().join("config.sqlite");
    let (store, backend) = open_singleton(&path, &dir.path().join("snapshots")).await;
    let ids: Vec<_> = (0..7).map(|_| TxId::new()).collect();
    let original = commit(ids[0], None, 1, 0x62);
    let original_request = ConfigConsensusRequestId::from_bytes([0xE0; 16]);
    store
        .append_commit_idempotent(original_request, attested(original.clone(), audit(ids[0])))
        .await
        .expect("first commit");
    for index in 1..4 {
        store
            .append_attested_commit(attested(
                commit(ids[index], Some(ids[index - 1]), index as u64 + 1, 0x62),
                audit(ids[index]),
            ))
            .await
            .expect("complete configuration");
    }
    let decision = retention(ids[3], 4, 3, 3, 1_048_576);
    let request = ConfigConsensusRequestId::from_bytes([0xE1; 16]);
    store
        .retain_history_idempotent(request, decision.clone())
        .await
        .expect("prune acknowledged prefix");
    store
        .append_commit_idempotent(original_request, attested(original, audit(ids[0])))
        .await
        .expect("exact outcome remains after its history was acknowledged");
    assert_eq!(
        store
            .load_latest()
            .await
            .expect("head")
            .expect("record")
            .record
            .tx_id,
        ids[3]
    );
    store
        .append_attested_commit(attested(
            commit(ids[4], Some(ids[3]), 5, 0x62),
            audit(ids[4]),
        ))
        .await
        .expect("last admitted row");
    let over_request = ConfigConsensusRequestId::from_bytes([0xE2; 16]);
    let over_record = commit(ids[5], Some(ids[4]), 6, 0x62);
    let error = store
        .append_commit_idempotent(over_request, attested(over_record.clone(), audit(ids[5])))
        .await
        .expect_err("hard record bound");
    assert!(matches!(error.kind(), PersistErrorKind::ConfigHistoryFull));
    assert_eq!(
        store
            .load_latest()
            .await
            .expect("head")
            .expect("record")
            .record
            .tx_id,
        ids[4]
    );
    // The original decision remains idempotent even after the head advances.
    store
        .retain_history_idempotent(request, decision.clone())
        .await
        .expect("retention outcome replay");
    let stale = store
        .retain_history_idempotent(ConfigConsensusRequestId::from_bytes([0xE3; 16]), decision)
        .await
        .expect_err("new request cannot reuse a stale exact head");
    assert!(matches!(
        stale.kind(),
        PersistErrorKind::ConstraintViolation(_)
    ));
    let too_small = store
        .retain_history_idempotent(
            ConfigConsensusRequestId::from_bytes([0xE4; 16]),
            retention(ids[4], 5, 4, 3, 1),
        )
        .await
        .expect_err("encoded byte bound");
    assert!(matches!(
        too_small.kind(),
        PersistErrorKind::ConfigHistoryFull
    ));
    assert_eq!(
        store
            .load_since(ConfigVersion::new(2), 8)
            .await
            .expect("failed prune preserves floor")
            .len(),
        3
    );
    store
        .retain_history_idempotent(
            ConfigConsensusRequestId::from_bytes([0xE5; 16]),
            retention(ids[4], 5, 4, 3, 1_048_576),
        )
        .await
        .expect("next acknowledged window");
    // A rejected request keeps its definite result, even after capacity returns.
    assert!(matches!(
        store
            .append_commit_idempotent(over_request, attested(over_record, audit(ids[5])))
            .await
            .expect_err("replay capacity rejection")
            .kind(),
        PersistErrorKind::ConfigHistoryFull
    ));
    store
        .append_attested_commit(attested(
            commit(ids[6], Some(ids[4]), 6, 0x62),
            audit(ids[6]),
        ))
        .await
        .expect("fresh operation after explicit retention");
    assert!(matches!(
        store
            .load_since(ConfigVersion::new(2), 8)
            .await
            .expect_err("advanced floor")
            .kind(),
        PersistErrorKind::ConfigHistoryCompacted
    ));
    assert_eq!(
        store
            .load_since(ConfigVersion::new(3), 8)
            .await
            .expect("exact boundary")[0]
            .record
            .parent_tx_id,
        Some(ids[2])
    );
    store
        .trigger_snapshot()
        .await
        .expect("pruned snapshot validates original AEAD lineage");
    store.shutdown().await.expect("shutdown");
    drop(store);
    drop(backend);
}

#[cfg(feature = "dangerous-test-hooks")]
#[tokio::test]
async fn history_retention_protects_rollback_pending_and_publication_predecessors() {
    for protected in ["rollback", "pending", "recovery"] {
        let dir = tempfile::tempdir().expect("directory");
        let (store, _) = open_singleton(
            &dir.path().join("config.sqlite"),
            &dir.path().join("snapshots"),
        )
        .await;
        let ids: Vec<_> = (0..3).map(|_| TxId::new()).collect();
        for index in 0..3 {
            let mut value = commit(
                ids[index],
                index.checked_sub(1).map(|previous| ids[previous]),
                index as u64 + 1,
                0x62,
            );
            if index == 2 && protected == "pending" {
                value.confirmed_deadline = Some(Timestamp::now_utc());
            }
            let sealed = if index == 2 && protected == "recovery" {
                fenced_attested(value, audit(ids[index]))
            } else {
                attested(value, audit(ids[index]))
            };
            store
                .append_attested_commit(sealed)
                .await
                .expect("complete history");
        }
        if protected == "rollback" {
            store
                .create_rollback_point(ids[0], Some("retained-release".to_owned()))
                .await
                .expect("named rollback reference");
        }
        let decision = retention(ids[2], 3, 2, 2, 1_048_576);
        // The head's unresolved predecessor is v2 and remains; v1 is the
        // rollback predecessor of the latest confirmed configuration while v3
        // is pending. Neither recovery nor confirmation may lose that chain.
        let result = store
            .retain_history_idempotent(ConfigConsensusRequestId::from_bytes([0xE6; 16]), decision)
            .await;
        if protected == "rollback" {
            assert!(matches!(
                result.expect_err("named rollback protected").kind(),
                PersistErrorKind::ConfigHistoryProtected
            ));
            assert_eq!(
                store
                    .load_rollback(RollbackTarget::ByLabel("retained-release".to_owned()))
                    .await
                    .expect("rollback remains")
                    .record
                    .tx_id,
                ids[0]
            );
        } else if protected == "pending" {
            assert!(matches!(
                result
                    .expect_err("previous resolved rollback target protected")
                    .kind(),
                PersistErrorKind::ConfigHistoryProtected
            ));
            assert_eq!(
                store
                    .load_rollback(RollbackTarget::Previous)
                    .await
                    .expect("pending rollback predecessor")
                    .record
                    .tx_id,
                ids[0]
            );
        } else {
            result.expect("exact unresolved predecessor retained");
            assert_eq!(
                store
                    .load_since(ConfigVersion::new(1), 8)
                    .await
                    .expect("publication-safe prefix")[0]
                    .record
                    .tx_id,
                ids[1]
            );
        }
        store.shutdown().await.expect("shutdown");
    }
}

#[cfg(feature = "dangerous-test-hooks")]
#[tokio::test]
async fn history_retention_releases_acknowledged_rolled_back_pending_commit() {
    let dir = tempfile::tempdir().expect("directory");
    let (store, _) = open_singleton(
        &dir.path().join("config.sqlite"),
        &dir.path().join("snapshots"),
    )
    .await;
    let ids: Vec<_> = (0..5).map(|_| TxId::new()).collect();
    for index in 0..5 {
        let mut value = commit(
            ids[index],
            index.checked_sub(1).map(|previous| ids[previous]),
            index as u64 + 1,
            0x62,
        );
        if index == 2 {
            value.confirmed_deadline = Some(Timestamp::now_utc());
        }
        let sealed = if index == 3 {
            attested_resolving(
                value,
                audit(ids[index]),
                ConfirmedCommitResolution::Rollback {
                    pending_tx_id: ids[2],
                },
            )
        } else {
            attested(value, audit(ids[index]))
        };
        store
            .append_attested_commit(sealed)
            .await
            .expect("committed rollback resolves the current pending decision");
    }
    let result = store
        .retain_history_idempotent(
            ConfigConsensusRequestId::from_bytes([0xED; 16]),
            retention(ids[4], 5, 4, 2, 1_048_576),
        )
        .await;
    let retained = store.load_since(ConfigVersion::new(3), 8).await;
    let rollback = store.load_rollback(RollbackTarget::Previous).await;
    store.shutdown().await.expect("shutdown");
    result.expect("historical pending marker is resolved by its committed rollback");
    let retained = retained.expect("retained exact suffix");
    assert_eq!(retained.len(), 2);
    assert_eq!(retained[0].record.tx_id, ids[3]);
    assert_eq!(retained[0].record.parent_tx_id, Some(ids[2]));
    assert_eq!(retained[1].record.tx_id, ids[4]);
    assert_eq!(rollback.expect("live rollback target").record.tx_id, ids[3]);
}

#[tokio::test]
async fn history_retention_authenticated_boundary_rejects_missing_or_tampered_state() {
    for mutation in ["floor", "anchor", "record"] {
        let dir = tempfile::tempdir().expect("directory");
        let database = dir.path().join("config.sqlite");
        let (store, _) = open_singleton(&database, &dir.path().join("snapshots")).await;
        let ids: Vec<_> = (0..4).map(|_| TxId::new()).collect();
        for index in 0..4 {
            store
                .append_attested_commit(attested(
                    commit(
                        ids[index],
                        index.checked_sub(1).map(|previous| ids[previous]),
                        index as u64 + 1,
                        0x62,
                    ),
                    vec![],
                ))
                .await
                .expect("configuration");
        }
        store
            .retain_history_idempotent(
                ConfigConsensusRequestId::from_bytes([0xE7; 16]),
                retention(ids[3], 4, 3, 3, 1_048_576),
            )
            .await
            .expect("real prune");
        // SQL is only the adversarial corruptor, never the positive producer.
        let attacker = rusqlite::Connection::open(&database).expect("corruption fixture");
        match mutation {
            "floor" => {
                attacker.execute("UPDATE config_raft_history_retention SET state_json = json_set(CAST(state_json AS TEXT), '$.boundary.first.version', 1)", []).expect("tamper floor without HMAC");
            }
            "anchor" => {
                attacker
                    .execute("DELETE FROM config_raft_history_retention", [])
                    .expect("remove authenticated boundary");
            }
            "record" => {
                attacker
                    .execute_batch("PRAGMA foreign_keys = OFF")
                    .expect("adversarial offline deletion");
                attacker
                    .execute("DELETE FROM config_history WHERE version = 3", [])
                    .expect("remove retained predecessor");
            }
            _ => unreachable!(),
        }
        assert!(
            store.load_latest().await.is_err(),
            "{mutation}: no snapshot authority from corruption"
        );
        let error = store
            .load_since(ConfigVersion::new(1), 8)
            .await
            .expect_err("corruption is not intentional compaction");
        assert!(!matches!(
            error.kind(),
            PersistErrorKind::ConfigHistoryCompacted
        ));
        store.shutdown().await.expect("shutdown");
    }
}

#[tokio::test]
async fn history_retention_refuses_to_erase_corrupt_acknowledged_prefix() {
    for mutation in [
        "audit",
        "audit_anchor",
        "envelope",
        "ciphertext",
        "ciphertext_then_append",
    ] {
        let dir = tempfile::tempdir().expect("directory");
        let database = dir.path().join("config.sqlite");
        let (store, _) = open_singleton(&database, &dir.path().join("snapshots")).await;
        let ids: Vec<_> = (0..5).map(|_| TxId::new()).collect();
        for index in 0..5 {
            store
                .append_attested_commit(attested(
                    commit(
                        ids[index],
                        index.checked_sub(1).map(|previous| ids[previous]),
                        index as u64 + 1,
                        0x62,
                    ),
                    audit(ids[index]),
                ))
                .await
                .expect("complete encrypted history");
        }
        let observer = rusqlite::Connection::open(&database).expect("adversarial connection");
        if mutation == "audit" || mutation == "audit_anchor" {
            observer
                .execute(
                    "DELETE FROM audit_trail WHERE tx_id = (SELECT tx_id FROM config_history WHERE version = 1)",
                    [],
                )
                .expect("remove one required audit entry");
            if mutation == "audit_anchor" {
                observer
                    .execute("UPDATE config_history SET audit_count = 0, audit_terminal_hash = zeroblob(32) WHERE version = 1", [])
                    .expect("also remove the unauthenticated row audit anchor");
            }
        } else if mutation == "envelope" {
            observer
                .execute(
                    "UPDATE config_history SET encrypted_blob = x'01' WHERE version = 1",
                    [],
                )
                .expect("malformed older envelope");
        } else {
            let mut blob: Vec<u8> = observer
                .query_row(
                    "SELECT encrypted_blob FROM config_history WHERE version = 1",
                    [],
                    |row| row.get(0),
                )
                .expect("older complete envelope");
            *blob.last_mut().expect("ciphertext tag") ^= 1;
            opc_crypto::CryptoEnvelopeV1::decode(&blob).expect("still a well-formed envelope");
            observer
                .execute(
                    "UPDATE config_history SET encrypted_blob = ?1 WHERE version = 1",
                    [blob],
                )
                .expect("modified older ciphertext");
        }
        if mutation == "ciphertext_then_append" {
            let next = TxId::new();
            store
                .append_attested_commit(attested(commit(next, Some(ids[4]), 6, 0x62), audit(next)))
                .await
                .expect_err("damaged prior ciphertext refuses append before mutation");
        }
        let version = ids.len() as u64;
        let result = store
            .retain_history_idempotent(
                ConfigConsensusRequestId::from_bytes([0xEE; 16]),
                retention(
                    *ids.last().expect("head"),
                    version,
                    version - 1,
                    2,
                    1_048_576,
                ),
            )
            .await;
        let count: i64 = observer
            .query_row("SELECT COUNT(*) FROM config_history", [], |row| row.get(0))
            .expect("independent retained-row readback");
        let state: Vec<u8> = observer
            .query_row(
                "SELECT state_json FROM config_raft_history_retention",
                [],
                |row| row.get(0),
            )
            .expect("unchanged boundary readback");
        drop(observer);
        store.shutdown().await.expect("shutdown");
        assert!(
            result.is_err(),
            "{mutation}: corruption cannot be legitimized by pruning"
        );
        assert_eq!(
            count as u64, version,
            "{mutation}: no acknowledged row was removed"
        );
        let state: serde_json::Value = serde_json::from_slice(&state).expect("state shape");
        assert!(
            state["boundary"].is_null(),
            "no authenticated compaction permission was minted"
        );
    }
}

#[tokio::test]
async fn history_ciphertext_corruption_is_refused_on_explicit_reopen() {
    let dir = tempfile::tempdir().expect("directory");
    let path = dir.path().join("retained.sqlite");
    let backend = SqliteBackend::provision_config_authority(
        retained_options(&path, topology(), 1),
        audit_key(),
    )
    .await
    .expect("explicit provision");
    let store = ConsensusConfigStore::open(
        topology(),
        backend,
        dir.path().join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .expect("store");
    store.initialize_cluster().await.expect("initialize");
    let ids: Vec<_> = (0..5).map(|_| TxId::new()).collect();
    for index in 0..5 {
        store
            .append_attested_commit(attested(
                commit(
                    ids[index],
                    index.checked_sub(1).map(|i| ids[i]),
                    index as u64 + 1,
                    0x62,
                ),
                audit(ids[index]),
            ))
            .await
            .expect("encrypted configuration");
    }
    store
        .retain_history_idempotent(
            ConfigConsensusRequestId::from_bytes([0xEF; 16]),
            retention(ids[4], 5, 3, 3, 1_048_576),
        )
        .await
        .expect("keep versions three through five");
    store.shutdown().await.expect("shutdown");
    drop(store);
    let attacker = rusqlite::Connection::open(&path).expect("offline corruptor");
    let mut blob: Vec<u8> = attacker
        .query_row(
            "SELECT encrypted_blob FROM config_history WHERE version = 4",
            [],
            |row| row.get(0),
        )
        .expect("middle ciphertext, neither head nor boundary");
    *blob.last_mut().expect("ciphertext tag") ^= 1;
    opc_crypto::CryptoEnvelopeV1::decode(&blob).expect("framing remains valid");
    attacker
        .execute(
            "UPDATE config_history SET encrypted_blob = ?1 WHERE version = 4",
            [blob],
        )
        .expect("modify middle ciphertext only");
    drop(attacker);
    assert!(matches!(
        SqliteBackend::reopen_config_authority(retained_options(&path, topology(), 1), audit_key())
            .await,
        Err(opc_persist::RetainedConfigError::Rejected)
    ));
}

#[tokio::test]
async fn retained_history_floor_limits_and_outcomes_survive_explicit_reopen() {
    let dir = tempfile::tempdir().expect("directory");
    let path = dir.path().join("retained.sqlite");
    let backend = SqliteBackend::provision_config_authority(
        retained_options(&path, topology(), 1),
        audit_key(),
    )
    .await
    .expect("explicit provision");
    let store = ConsensusConfigStore::open(
        topology(),
        backend,
        dir.path().join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .expect("store");
    store.initialize_cluster().await.expect("initialize");
    let ids: Vec<_> = (0..4).map(|_| TxId::new()).collect();
    for index in 0..4 {
        store
            .append_attested_commit(attested(
                commit(
                    ids[index],
                    index.checked_sub(1).map(|previous| ids[previous]),
                    index as u64 + 1,
                    0x62,
                ),
                audit(ids[index]),
            ))
            .await
            .expect("configuration");
    }
    let decision = retention(ids[3], 4, 3, 2, 1_048_576);
    let request = ConfigConsensusRequestId::from_bytes([0xE8; 16]);
    store
        .retain_history_idempotent(request, decision.clone())
        .await
        .expect("real prune");
    store.trigger_snapshot().await.expect("snapshot");
    store.shutdown().await.expect("shutdown");
    drop(store);
    let backend =
        SqliteBackend::reopen_config_authority(retained_options(&path, topology(), 1), audit_key())
            .await
            .expect("explicit retained reopen");
    let store = ConsensusConfigStore::open(
        topology(),
        backend,
        dir.path().join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .expect("restore");
    store.initialize_cluster().await.expect("readmit");
    store
        .retain_history_idempotent(request, decision)
        .await
        .expect("retained outcome");
    assert!(matches!(
        store
            .load_since(ConfigVersion::new(1), 8)
            .await
            .expect_err("old cursor after reopen")
            .kind(),
        PersistErrorKind::ConfigHistoryCompacted
    ));
    let retained = store
        .load_since(ConfigVersion::new(2), 8)
        .await
        .expect("exact restored boundary");
    assert_eq!(retained.len(), 2);
    assert_eq!(retained[0].record.parent_tx_id, Some(ids[1]));
    let new_id = TxId::new();
    assert!(matches!(
        store
            .append_attested_commit(attested(commit(new_id, Some(ids[3]), 5, 0x62), vec![]))
            .await
            .expect_err("bound survives reopen")
            .kind(),
        PersistErrorKind::ConfigHistoryFull
    ));
    store.shutdown().await.expect("shutdown restored");
}

#[tokio::test]
async fn history_retention_survives_natural_leader_change_and_member_snapshot_install() {
    let mut cluster =
        ThreeNodeCluster::build_with_storage([[0x55; 32]; 3], FixtureStorage::RetainedNew).await;
    let (a, b, c) = tokio::join!(
        cluster.stores[0].initialize_cluster(),
        cluster.stores[1].initialize_cluster(),
        cluster.stores[2].initialize_cluster()
    );
    a.expect("first");
    b.expect("second");
    c.expect("third");
    cluster.wait_ready().await;
    let original_leader = cluster.leader();
    let ids: Vec<_> = (0..5).map(|_| TxId::new()).collect();
    for index in 0..4 {
        cluster.stores[original_leader]
            .append_attested_commit(attested(
                commit(
                    ids[index],
                    index.checked_sub(1).map(|previous| ids[previous]),
                    index as u64 + 1,
                    0x62,
                ),
                vec![],
            ))
            .await
            .expect("quorum configuration");
    }
    let decision = retention(ids[3], 4, 3, 3, 1_048_576);
    let request = ConfigConsensusRequestId::from_bytes([0xEB; 16]);
    cluster.stores[original_leader]
        .retain_history_idempotent(request, decision.clone())
        .await
        .expect("quorum retention");
    // Real replayed commands move Raft beyond its production retained-log
    // window without inflating canonical history or weakening the profile.
    for _ in 0..opc_consensus::DURABLE_OPENRAFT_PROFILE.retained_logs + 16 {
        cluster.stores[original_leader]
            .retain_history_idempotent(request, decision.clone())
            .await
            .expect("stable retention outcome");
    }
    cluster.wait_ready().await;
    for store in &cluster.stores {
        store.trigger_snapshot().await.expect("production snapshot");
    }
    tokio::time::timeout(CLUSTER_TRANSITION_TIMEOUT, async {
        loop {
            let mut complete = true;
            for index in 0..3 {
                let observer = rusqlite::Connection::open(cluster.database_path(index))
                    .expect("snapshot observation");
                let purged: bool = observer
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM config_raft_purged WHERE log_index > 0)",
                        [],
                        |row| row.get(0),
                    )
                    .expect("purged prefix");
                complete &= purged;
            }
            if complete {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("actual production log compaction");
    let old_id = cluster.stores[original_leader].status().node_id;
    let old_term = cluster.stores[original_leader].status().term;
    cluster.isolate(original_leader);
    cluster.stores[original_leader]
        .shutdown()
        .await
        .expect("old leader stopped");
    let replacement = tokio::time::timeout(CLUSTER_TRANSITION_TIMEOUT, async {
        loop {
            for index in 0..3 {
                if index == original_leader {
                    continue;
                }
                let state = cluster.stores[index].status();
                if state.term > old_term
                    && state.leader_id == Some(state.node_id)
                    && state.node_id != old_id
                {
                    return index;
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("natural surviving-quorum election");
    cluster.stores[replacement]
        .retain_history_idempotent(request, decision.clone())
        .await
        .expect("outcome under replacement leader");
    assert!(matches!(
        cluster.stores[replacement]
            .load_since(ConfigVersion::new(1), 8)
            .await
            .expect_err("floor after election")
            .kind(),
        PersistErrorKind::ConfigHistoryCompacted
    ));
    cluster.stores[replacement]
        .append_attested_commit(attested(commit(ids[4], Some(ids[3]), 5, 0x62), vec![]))
        .await
        .expect("next canonical revision");
    let nodes = [1, 2, 3].map(|id| ConfigConsensusNodeId::new(id).expect("node"));
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("opc-persist-three-node-tests").expect("cluster"),
        ConfigConsensusConfigurationId::from_bytes([0x99; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
    );
    let topology = ConfigConsensusTopology::try_new(
        identity,
        nodes[original_leader],
        nodes.into_iter().collect(),
    )
    .expect("repair topology");
    let repair_path = cluster._directory.path().join("retention-repaired.sqlite");
    let backend = SqliteBackend::provision_config_member_repair(
        retained_options(&repair_path, topology.clone(), 9),
        audit_key(),
    )
    .await
    .expect("explicit member repair");
    let peers = (0..3)
        .filter(|index| *index != original_leader)
        .map(|index| {
            let peer: Arc<dyn ConsensusPeer> = cluster.paths[&(original_leader, index)].clone();
            (nodes[index], peer)
        })
        .collect();
    let repair = ConsensusConfigStore::open_with_operation_timeout(
        topology,
        backend,
        cluster._directory.path().join("retention-repair-snapshots"),
        peers,
        Duration::from_secs(30),
    )
    .await
    .expect("repair store");
    for ((_, target), path) in &cluster.paths {
        if *target == original_leader {
            path.install(repair.rpc_handler()).await;
        }
    }
    cluster.stores[original_leader] = repair;
    cluster.heal(original_leader);
    cluster.stores[original_leader]
        .initialize_cluster()
        .await
        .expect("snapshot-backed member recovery");
    cluster.wait_ready().await;
    let observer =
        rusqlite::Connection::open(&repair_path).expect("installed snapshot observation");
    let snapshot_installed: bool = observer
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM config_raft_snapshot)",
            [],
            |row| row.get(0),
        )
        .expect("snapshot state");
    assert!(
        snapshot_installed,
        "repair must have installed a snapshot beyond the purged log prefix"
    );
    drop(observer);
    let page = cluster.stores[original_leader]
        .load_since(ConfigVersion::new(2), 8)
        .await
        .expect("repaired exact boundary");
    assert_eq!(
        page.iter()
            .map(|entry| entry.record.version.get())
            .collect::<Vec<_>>(),
        vec![3, 4, 5]
    );
    assert_eq!(page[0].record.parent_tx_id, Some(ids[1]));
    assert!(matches!(
        cluster.stores[original_leader]
            .load_since(ConfigVersion::new(1), 8)
            .await
            .expect_err("installed authenticated floor")
            .kind(),
        PersistErrorKind::ConfigHistoryCompacted
    ));
    cluster.stores[original_leader]
        .retain_history_idempotent(request, decision)
        .await
        .expect("installed outcome replay");
    cluster.shutdown().await;
}

#[cfg(feature = "dangerous-test-hooks")]
#[tokio::test]
async fn history_capacity_rejection_rolls_back_pending_confirmation_atomically() {
    let dir = tempfile::tempdir().expect("directory");
    let database = dir.path().join("config.sqlite");
    let (store, _) = open_singleton(&database, &dir.path().join("snapshots")).await;
    let ids: Vec<_> = (0..5).map(|_| TxId::new()).collect();
    for index in 0..3 {
        store
            .append_attested_commit(attested(
                commit(
                    ids[index],
                    index.checked_sub(1).map(|previous| ids[previous]),
                    index as u64 + 1,
                    0x62,
                ),
                vec![],
            ))
            .await
            .expect("history");
    }
    store
        .retain_history_idempotent(
            ConfigConsensusRequestId::from_bytes([0xEA; 16]),
            retention(ids[2], 3, 2, 3, 1_048_576),
        )
        .await
        .expect("bounded history");
    let mut pending = commit(ids[3], Some(ids[2]), 4, 0x62);
    pending.confirmed_deadline = Some(Timestamp::now_utc());
    store
        .append_attested_commit(attested(pending, audit(ids[3])))
        .await
        .expect("pending fills cap");
    let error = store
        .append_attested_commit(attested_resolving(
            commit(ids[4], Some(ids[3]), 5, 0x62),
            audit(ids[4]),
            ConfirmedCommitResolution::Confirm {
                pending_tx_id: ids[3],
            },
        ))
        .await
        .expect_err("capacity after attempted resolution");
    assert!(matches!(error.kind(), PersistErrorKind::ConfigHistoryFull));
    assert_eq!(
        store
            .load_latest()
            .await
            .expect("head")
            .expect("record")
            .record
            .tx_id,
        ids[3]
    );
    let observer = rusqlite::Connection::open(&database).expect("readback");
    let confirmed: Option<String> = observer
        .query_row(
            "SELECT confirmed_at FROM config_history WHERE version = 4",
            [],
            |row| row.get(0),
        )
        .expect("pending readback");
    let lifecycle: i64 = observer
        .query_row("SELECT COUNT(*) FROM config_lifecycle_audit", [], |row| {
            row.get(0)
        })
        .expect("lifecycle readback");
    assert!(
        confirmed.is_none(),
        "rejected append cannot resolve its predecessor"
    );
    assert_eq!(
        lifecycle, 0,
        "rejected resolution cannot leave an audit side effect"
    );
    drop(observer);
    store.shutdown().await.expect("shutdown");
}

async fn assert_all_direct_mutations_are_fenced(backend: &SqliteBackend, current_tx_id: TxId) {
    let appended_tx_id = TxId::new();
    for result in [
        backend
            .append_commit(
                commit(appended_tx_id, Some(current_tx_id), 2, 2),
                audit(appended_tx_id),
            )
            .await,
        backend.mark_confirmed(current_tx_id).await,
        backend
            .create_rollback_point(current_tx_id, Some("forbidden".to_owned()))
            .await,
    ] {
        let error = result.expect_err("direct mutation must remain fenced");
        assert!(matches!(
            error.kind(),
            PersistErrorKind::InconsistentState(_)
        ));
    }
}

fn assert_forbidden_artifacts_absent(path: &std::path::Path) {
    if let Ok(bytes) = std::fs::read(path) {
        for (description, forbidden) in FORBIDDEN_RAFT_ARTIFACTS {
            assert!(
                !bytes
                    .windows(forbidden.len())
                    .any(|window| window == *forbidden),
                "{description} reached {}",
                path.display()
            );
        }
    }
}

fn file_sha256(path: &std::path::Path) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(std::fs::read(path).expect("snapshot bytes")).into()
}

#[derive(Debug, PartialEq, Eq)]
struct DeterministicAuthorityRowIds {
    audit: Vec<(i64, Vec<u8>, i64)>,
    lifecycle: Vec<(i64, Vec<u8>, String)>,
}

fn deterministic_authority_row_ids(database: &std::path::Path) -> DeterministicAuthorityRowIds {
    let conn = rusqlite::Connection::open(database).expect("open authority database");
    let mut audit = conn
        .prepare("SELECT id, tx_id, sequence FROM audit_trail ORDER BY tx_id, sequence")
        .expect("prepare audit IDs");
    let audit_ids = audit
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query audit IDs")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect audit IDs");
    drop(audit);
    let mut lifecycle = conn
        .prepare("SELECT id, tx_id, action FROM config_lifecycle_audit ORDER BY tx_id, action, id")
        .expect("prepare lifecycle IDs");
    let lifecycle_ids = lifecycle
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .expect("query lifecycle IDs")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect lifecycle IDs");
    DeterministicAuthorityRowIds {
        audit: audit_ids,
        lifecycle: lifecycle_ids,
    }
}

fn assert_legacy_target_unclaimed(path: &std::path::Path, expected_tx_id: TxId) {
    let conn = rusqlite::Connection::open(path).expect("open target for inspection");
    let raft_identity_tables: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'config_raft_identity'",
            [],
            |row| row.get(0),
        )
        .expect("identity table count");
    assert_eq!(
        0, raft_identity_tables,
        "failed recovery must not claim authority"
    );
    let latest_tx: Vec<u8> = conn
        .query_row(
            "SELECT tx_id FROM config_history ORDER BY version DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .expect("legacy target head");
    assert_eq!(
        expected_tx_id.as_uuid().as_bytes().as_slice(),
        latest_tx.as_slice(),
        "failed recovery must not alter the legacy target"
    );
}

async fn create_checkpointed_legacy(
    path: &std::path::Path,
    tx_id: TxId,
    seed: u8,
) -> SqliteBackend {
    let backend = SqliteBackend::open_with_audit_key(path, true, 0, audit_key())
        .await
        .expect("legacy backend");
    backend
        .append_commit(commit(tx_id, None, 1, seed), audit(tx_id))
        .await
        .expect("legacy commit");
    rusqlite::Connection::open(path)
        .expect("open legacy checkpoint connection")
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint legacy database");
    backend
}

#[tokio::test]
async fn singleton_commit_is_idempotent_fenced_and_ciphertext_only() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database = temp.path().join("config.sqlite");
    let snapshots = temp.path().join("snapshots");
    let (store, bypass) = open_singleton(&database, &snapshots).await;
    store.probe_durable_readiness().await.expect("ready");

    let tx_id = TxId::new();
    let request_id = ConfigConsensusRequestId::from_bytes([7; 16]);
    let record = commit(tx_id, None, 1, 1);
    let expected_ciphertext = record.encrypted_blob.clone();
    let records_audit = audit(tx_id);
    store
        .append_commit_idempotent(request_id, attested(record.clone(), records_audit.clone()))
        .await
        .expect("first commit");
    store
        .append_commit_idempotent(request_id, attested(record.clone(), records_audit.clone()))
        .await
        .expect("response-loss replay");

    let colliding_tx_id = TxId::new();
    let collision = store
        .append_commit_idempotent(
            request_id,
            attested(
                commit(colliding_tx_id, Some(tx_id), 2, 2),
                audit(colliding_tx_id),
            ),
        )
        .await
        .expect_err("same request ID with a different payload must fail closed");
    assert!(matches!(
        collision.kind(),
        PersistErrorKind::RequestIdCollision
    ));
    store
        .append_commit_idempotent(request_id, attested(record.clone(), records_audit.clone()))
        .await
        .expect("collision must not destroy original response recovery");
    let conflicting_tx_id = TxId::new();
    let ordinary_conflict = store
        .append_commit_idempotent(
            ConfigConsensusRequestId::from_bytes([8; 16]),
            attested(
                commit(conflicting_tx_id, None, 1, 3),
                audit(conflicting_tx_id),
            ),
        )
        .await
        .expect_err("ordinary version conflict");
    assert!(matches!(
        ordinary_conflict.kind(),
        PersistErrorKind::ConstraintViolation(_)
    ));

    let stored = store.load_latest().await.expect("load").expect("stored");
    assert_eq!(stored.record.tx_id, tx_id);
    assert_eq!(stored.record.encrypted_blob, expected_ciphertext);
    assert_eq!(
        stored.audit[0].previous_value.as_deref(),
        Some("\"<redacted>\"")
    );
    assert_eq!(stored.audit[0].new_value.as_deref(), Some("\"<redacted>\""));

    assert_all_direct_mutations_are_fenced(&bypass, tx_id).await;
    let reopened = SqliteBackend::open_with_audit_key(&database, true, 0, audit_key())
        .await
        .expect("freshly reopened backend");
    assert_all_direct_mutations_are_fenced(&reopened, tx_id).await;

    store.trigger_snapshot().await.expect("snapshot");
    assert_forbidden_artifacts_absent(&database);
    assert_forbidden_artifacts_absent(&database.with_extension("sqlite-wal"));
    assert_forbidden_artifacts_absent(&database.with_extension("sqlite-shm"));
    for entry in std::fs::read_dir(&snapshots).expect("snapshot directory") {
        assert_forbidden_artifacts_absent(&entry.expect("snapshot entry").path());
    }

    store.shutdown().await.expect("shutdown");
    drop(store);
    drop(bypass);

    let (restarted, _) = open_singleton(&database, &snapshots).await;
    restarted
        .append_commit_idempotent(request_id, attested(record, records_audit))
        .await
        .expect("durable response replay after restart and compaction");
    assert_eq!(
        restarted
            .load_latest()
            .await
            .expect("restart load")
            .expect("restart record")
            .record
            .tx_id,
        tx_id
    );
    restarted.shutdown().await.expect("restart shutdown");
}

#[tokio::test]
async fn raw_append_and_wrong_audit_key_fail_before_consensus_authority() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database = temp.path().join("config.sqlite");
    let snapshots = temp.path().join("snapshots");
    let (store, _) = open_singleton(&database, &snapshots).await;
    let tx_id = TxId::new();
    let raw = store
        .append_commit(commit(tx_id, None, 1, 0x31), audit(tx_id))
        .await
        .expect_err("raw ciphertext without a fresh encryption claim must fail");
    assert!(matches!(
        raw.kind(),
        PersistErrorKind::ConstraintViolation(_)
    ));
    assert!(store.load_latest().await.expect("empty read").is_none());
    let oversized_tx = TxId::new();
    let oversized = store
        .append_attested_commit(attested(
            commit(oversized_tx, None, i64::MAX as u64 + 1, 0x32),
            audit(oversized_tx),
        ))
        .await
        .expect_err("SQLite one-over version must fail before proposal");
    assert!(matches!(
        oversized.kind(),
        PersistErrorKind::ConstraintViolation(_)
    ));
    assert!(store.load_latest().await.expect("still empty").is_none());

    store
        .append_attested_commit(attested(
            commit(tx_id, None, 1, 0x31),
            vec![AuditRecord {
                tx_id,
                sequence: 0,
                yang_path: "/interfaces/interface[name='supi-001010123456789']/enabled".into(),
                op_type: AuditOpType::Replace,
                previous_value: None,
                new_value: None,
                redaction_applied: false,
                previous_hash: [0; 32],
                entry_hmac: [0; 32],
            }],
        ))
        .await
        .expect("attested write");
    let loaded = store.load_latest().await.expect("load").expect("record");
    assert!(!loaded.audit[0].yang_path.contains("001010123456789"));
    assert!(loaded.audit[0].yang_path.contains("hmac-sha256:"));
    store.shutdown().await.expect("shutdown");
    drop(store);

    let wrong_backend = SqliteBackend::open_with_audit_key(
        &database,
        true,
        0,
        AuditKey::new_with_epoch([0x56; 32], 1).expect("wrong audit key"),
    )
    .await
    .expect("base SQLite open does not claim consensus authority");
    let error = ConsensusConfigStore::open(topology(), wrong_backend, &snapshots, BTreeMap::new())
        .await
        .expect_err("wrong audit key fingerprint must reject durable authority");
    assert_eq!(
        opc_persist::ConfigConsensusOpenError::DurableIdentityMismatch,
        error
    );

    let wrong_epoch_backend = SqliteBackend::open_with_audit_key(
        &database,
        true,
        0,
        AuditKey::new_with_epoch([0x55; 32], 2).expect("wrong audit epoch"),
    )
    .await
    .expect("base SQLite open");
    let error =
        ConsensusConfigStore::open(topology(), wrong_epoch_backend, &snapshots, BTreeMap::new())
            .await
            .expect_err("wrong audit key epoch must reject durable authority");
    assert_eq!(
        opc_persist::ConfigConsensusOpenError::DurableIdentityMismatch,
        error
    );
}

#[tokio::test]
async fn current_consensus_audit_hmac_tampering_rejects_restart() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database = temp.path().join("config.sqlite");
    let snapshots = temp.path().join("snapshots");
    let (store, _) = open_singleton(&database, &snapshots).await;
    let tx_id = TxId::new();
    store
        .append_attested_commit(attested(commit(tx_id, None, 1, 0x37), audit(tx_id)))
        .await
        .expect("attested commit");
    assert_eq!(1, store.status().audit_key_epoch);
    assert_ne!([0; 32], store.status().audit_key_fingerprint);
    store.shutdown().await.expect("shutdown");
    drop(store);

    rusqlite::Connection::open(&database)
        .expect("maintenance connection")
        .execute(
            "UPDATE audit_trail SET entry_hmac = zeroblob(32) WHERE tx_id = ?1 AND sequence = 0",
            [tx_id.as_uuid().as_bytes().as_slice()],
        )
        .expect("tamper current audit HMAC");
    let backend = SqliteBackend::open_with_audit_key(&database, true, 0, audit_key())
        .await
        .expect("backend");
    let error = ConsensusConfigStore::open(topology(), backend, &snapshots, BTreeMap::new())
        .await
        .expect_err("current-state audit HMAC tampering must reject authority");
    assert_eq!(
        opc_persist::ConfigConsensusOpenError::DurableIdentityMismatch,
        error
    );
}

#[tokio::test]
async fn unknown_config_owned_schema_object_rejects_restart() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database = temp.path().join("config.sqlite");
    let snapshots = temp.path().join("snapshots");
    let (store, _) = open_singleton(&database, &snapshots).await;
    store.shutdown().await.expect("shutdown");
    drop(store);
    rusqlite::Connection::open(&database)
        .expect("maintenance connection")
        .execute(
            "CREATE TABLE config_raft_unknown_authority (value BLOB)",
            [],
        )
        .expect("inject unknown owned object");
    let backend = SqliteBackend::open_with_audit_key(&database, true, 0, audit_key())
        .await
        .expect("backend");
    let error = ConsensusConfigStore::open(topology(), backend, &snapshots, BTreeMap::new())
        .await
        .expect_err("unknown config-owned object must fail exact manifest admission");
    assert_eq!(
        opc_persist::ConfigConsensusOpenError::DurableIdentityMismatch,
        error
    );
}

#[tokio::test]
async fn nonempty_legacy_authority_fails_closed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let database = temp.path().join("legacy.sqlite");
    let backend = SqliteBackend::open_with_audit_key(&database, true, 0, audit_key())
        .await
        .expect("backend");
    let tx_id = TxId::new();
    backend
        .append_commit(commit(tx_id, None, 1, 3), Vec::new())
        .await
        .expect("legacy commit");

    let error = ConsensusConfigStore::open(
        topology(),
        backend,
        temp.path().join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .expect_err("legacy authority must not be silently adopted");
    assert_eq!(
        error,
        opc_persist::ConfigConsensusOpenError::RecoveryRequired
    );
}

#[tokio::test]
async fn approved_applied_snapshot_replaces_unknown_legacy_tail_atomically() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_path = temp.path().join("approved.sqlite");
    let source = SqliteBackend::open_with_audit_key(&source_path, true, 0, audit_key())
        .await
        .expect("source backend");
    let approved_tx = TxId::new();
    source
        .append_commit(commit(approved_tx, None, 1, 21), audit(approved_tx))
        .await
        .expect("approved applied commit");
    rusqlite::Connection::open(&source_path)
        .expect("open approved checkpoint connection")
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint approved database");
    drop(source);

    let target_path = temp.path().join("target.sqlite");
    let target = SqliteBackend::open_with_audit_key(&target_path, true, 0, audit_key())
        .await
        .expect("target backend");
    let unknown_tail_tx = TxId::new();
    target
        .append_commit(commit(unknown_tail_tx, None, 1, 22), audit(unknown_tail_tx))
        .await
        .expect("unknown legacy tail");
    let approval = ApprovedLegacyConfigRecovery::new(
        &source_path,
        file_sha256(&source_path),
        approved_tx,
        ConfigVersion::new(1),
        LegacyConfigTailDisposition::DiscardUnknownAppendedSuffix,
    )
    .expect("approval");
    let store = ConsensusConfigStore::open_with_legacy_recovery(
        topology(),
        target,
        temp.path().join("recovery-snapshots"),
        BTreeMap::new(),
        approval.clone(),
    )
    .await
    .expect("approved recovery open");
    store
        .initialize_cluster()
        .await
        .expect("initialize recovered store");
    let latest = store.load_latest().await.expect("load").expect("record");
    assert_eq!(latest.record.tx_id, approved_tx);
    assert_ne!(latest.record.tx_id, unknown_tail_tx);
    assert_eq!(latest.audit[0].new_value.as_deref(), Some("\"<redacted>\""));
    store.shutdown().await.expect("shutdown");
    drop(store);

    std::fs::remove_file(&source_path).expect("remove consumed approval source");
    let recovered = SqliteBackend::open_with_audit_key(&target_path, true, 0, audit_key())
        .await
        .expect("reopen recovered backend");
    let continued = ConsensusConfigStore::open_with_legacy_recovery(
        topology(),
        recovered,
        temp.path().join("recovery-snapshots"),
        BTreeMap::new(),
        approval,
    )
    .await
    .expect("exact postcommit recovery retry continues without source snapshot");
    continued
        .initialize_cluster()
        .await
        .expect("re-admit recovered authority");
    assert_eq!(
        continued
            .load_latest()
            .await
            .expect("continued load")
            .expect("continued record")
            .record
            .tx_id,
        approved_tx
    );
    continued.shutdown().await.expect("continued shutdown");
}

#[tokio::test]
async fn legacy_recovery_rejects_wrong_checksum_and_head_without_claiming_target() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_path = temp.path().join("approved.sqlite");
    let approved_tx = TxId::new();
    let source = create_checkpointed_legacy(&source_path, approved_tx, 41).await;
    drop(source);
    let checksum = file_sha256(&source_path);

    let checksum_target_path = temp.path().join("checksum-target.sqlite");
    let checksum_tail = TxId::new();
    let checksum_target =
        create_checkpointed_legacy(&checksum_target_path, checksum_tail, 42).await;
    let mut wrong_checksum = checksum;
    wrong_checksum[0] ^= 0xff;
    let approval = ApprovedLegacyConfigRecovery::new(
        &source_path,
        wrong_checksum,
        approved_tx,
        ConfigVersion::new(1),
        LegacyConfigTailDisposition::DiscardUnknownAppendedSuffix,
    )
    .expect("checksum approval shape");
    let error = ConsensusConfigStore::open_with_legacy_recovery(
        topology(),
        checksum_target,
        temp.path().join("checksum-snapshots"),
        BTreeMap::new(),
        approval,
    )
    .await
    .expect_err("wrong approved checksum must fail closed");
    assert_eq!(
        error,
        opc_persist::ConfigConsensusOpenError::DurableIdentityMismatch
    );
    assert_legacy_target_unclaimed(&checksum_target_path, checksum_tail);

    let head_target_path = temp.path().join("head-target.sqlite");
    let head_tail = TxId::new();
    let head_target = create_checkpointed_legacy(&head_target_path, head_tail, 43).await;
    let approval = ApprovedLegacyConfigRecovery::new(
        &source_path,
        checksum,
        TxId::new(),
        ConfigVersion::new(1),
        LegacyConfigTailDisposition::DiscardUnknownAppendedSuffix,
    )
    .expect("head approval shape");
    let error = ConsensusConfigStore::open_with_legacy_recovery(
        topology(),
        head_target,
        temp.path().join("head-snapshots"),
        BTreeMap::new(),
        approval,
    )
    .await
    .expect_err("wrong approved head must fail closed");
    assert_eq!(
        error,
        opc_persist::ConfigConsensusOpenError::DurableIdentityMismatch
    );
    assert_legacy_target_unclaimed(&head_target_path, head_tail);
}

#[tokio::test]
async fn legacy_recovery_rejects_non_linear_history_without_claiming_target() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source_path = temp.path().join("non-linear-source.sqlite");
    let source = SqliteBackend::open_with_audit_key(&source_path, true, 0, audit_key())
        .await
        .expect("source backend");
    let first_tx = TxId::new();
    let head_tx = TxId::new();
    source
        .append_commit(commit(first_tx, None, 17, 0x61), audit(first_tx))
        .await
        .expect("arbitrary-version chain origin");
    source
        .append_commit(commit(head_tx, Some(first_tx), 18, 0x62), audit(head_tx))
        .await
        .expect("linear source head");
    drop(source);

    let source_conn = rusqlite::Connection::open(&source_path).expect("open source for tamper");
    source_conn
        .execute_batch("PRAGMA foreign_keys = OFF;")
        .expect("permit malformed external recovery fixture");
    source_conn
        .execute(
            "UPDATE config_history SET parent_tx_id = ?1 WHERE tx_id = ?2",
            rusqlite::params![
                TxId::new().as_uuid().as_bytes().as_slice(),
                head_tx.as_uuid().as_bytes().as_slice(),
            ],
        )
        .expect("inject orphaned history head");
    source_conn
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint non-linear source");
    drop(source_conn);

    let target_path = temp.path().join("non-linear-target.sqlite");
    let target_tail = TxId::new();
    let target = create_checkpointed_legacy(&target_path, target_tail, 0x63).await;
    let approval = ApprovedLegacyConfigRecovery::new(
        &source_path,
        file_sha256(&source_path),
        head_tx,
        ConfigVersion::new(18),
        LegacyConfigTailDisposition::DiscardUnknownAppendedSuffix,
    )
    .expect("non-linear approval shape");
    let error = ConsensusConfigStore::open_with_legacy_recovery(
        topology(),
        target,
        temp.path().join("non-linear-snapshots"),
        BTreeMap::new(),
        approval,
    )
    .await
    .expect_err("non-linear history must fail before target mutation");
    assert_eq!(
        opc_persist::ConfigConsensusOpenError::DurableIdentityMismatch,
        error
    );
    assert_legacy_target_unclaimed(&target_path, target_tail);
}

#[tokio::test]
async fn legacy_recovery_rejects_online_wal_and_invalid_audit_without_claiming_target() {
    let temp = tempfile::tempdir().expect("tempdir");

    let online_source_path = temp.path().join("online-source.sqlite");
    let online_tx = TxId::new();
    let online_source = create_checkpointed_legacy(&online_source_path, online_tx, 44).await;
    drop(online_source);
    let online_writer = rusqlite::Connection::open(&online_source_path).expect("online writer");
    online_writer
        .execute_batch("PRAGMA wal_autocheckpoint=0;")
        .expect("disable source auto-checkpoint");
    online_writer
        .execute(
            "UPDATE config_history SET confirmed_at = '2026-01-01T00:00:00Z' WHERE tx_id = ?1",
            [online_tx.as_uuid().as_bytes().as_slice()],
        )
        .expect("leave online WAL content");
    let wal_path = std::path::PathBuf::from(format!("{}-wal", online_source_path.display()));
    assert!(wal_path.metadata().expect("online WAL metadata").len() > 0);

    let online_target_path = temp.path().join("online-target.sqlite");
    let online_tail = TxId::new();
    let online_target = create_checkpointed_legacy(&online_target_path, online_tail, 45).await;
    let approval = ApprovedLegacyConfigRecovery::new(
        &online_source_path,
        file_sha256(&online_source_path),
        online_tx,
        ConfigVersion::new(1),
        LegacyConfigTailDisposition::DiscardUnknownAppendedSuffix,
    )
    .expect("online approval shape");
    let error = ConsensusConfigStore::open_with_legacy_recovery(
        topology(),
        online_target,
        temp.path().join("online-snapshots"),
        BTreeMap::new(),
        approval,
    )
    .await
    .expect_err("online WAL source must fail closed");
    assert_eq!(
        error,
        opc_persist::ConfigConsensusOpenError::RecoveryRequired
    );
    assert_legacy_target_unclaimed(&online_target_path, online_tail);
    drop(online_writer);

    let corrupt_source_path = temp.path().join("corrupt-source.sqlite");
    let corrupt_tx = TxId::new();
    let corrupt_source = create_checkpointed_legacy(&corrupt_source_path, corrupt_tx, 46).await;
    drop(corrupt_source);
    let corrupt_conn =
        rusqlite::Connection::open(&corrupt_source_path).expect("open corrupt source connection");
    corrupt_conn
        .execute(
            "UPDATE audit_trail SET entry_hmac = zeroblob(32) WHERE tx_id = ?1",
            [corrupt_tx.as_uuid().as_bytes().as_slice()],
        )
        .expect("corrupt source audit");
    corrupt_conn
        .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .expect("checkpoint corrupt source");
    drop(corrupt_conn);

    let corrupt_target_path = temp.path().join("corrupt-target.sqlite");
    let corrupt_tail = TxId::new();
    let corrupt_target = create_checkpointed_legacy(&corrupt_target_path, corrupt_tail, 47).await;
    let approval = ApprovedLegacyConfigRecovery::new(
        &corrupt_source_path,
        file_sha256(&corrupt_source_path),
        corrupt_tx,
        ConfigVersion::new(1),
        LegacyConfigTailDisposition::DiscardUnknownAppendedSuffix,
    )
    .expect("corrupt approval shape");
    let error = ConsensusConfigStore::open_with_legacy_recovery(
        topology(),
        corrupt_target,
        temp.path().join("corrupt-snapshots"),
        BTreeMap::new(),
        approval,
    )
    .await
    .expect_err("invalid audit source must fail closed");
    assert_eq!(
        error,
        opc_persist::ConfigConsensusOpenError::DurableIdentityMismatch
    );
    assert_legacy_target_unclaimed(&corrupt_target_path, corrupt_tail);
}

#[cfg(unix)]
#[tokio::test]
async fn legacy_recovery_rejects_symlinked_source_without_claiming_target() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let source_path = temp.path().join("source.sqlite");
    let source_tx = TxId::new();
    drop(create_checkpointed_legacy(&source_path, source_tx, 0x48).await);
    let linked_source = temp.path().join("linked-source.sqlite");
    symlink(&source_path, &linked_source).expect("legacy source symlink");

    let target_path = temp.path().join("target.sqlite");
    let target_tail = TxId::new();
    let target = create_checkpointed_legacy(&target_path, target_tail, 0x49).await;
    let approval = ApprovedLegacyConfigRecovery::new(
        &linked_source,
        file_sha256(&source_path),
        source_tx,
        ConfigVersion::new(1),
        LegacyConfigTailDisposition::DiscardUnknownAppendedSuffix,
    )
    .expect("symlink approval shape");
    ConsensusConfigStore::open_with_legacy_recovery(
        topology(),
        target,
        temp.path().join("snapshots"),
        BTreeMap::new(),
        approval,
    )
    .await
    .expect_err("legacy source symlink must fail before target mutation");
    assert_legacy_target_unclaimed(&target_path, target_tail);
}

#[tokio::test]
async fn pristine_noncanonical_node_waits_and_fails_closed_without_bootstrap_authority() {
    let cluster = ThreeNodeCluster::build([[0x55; 32]; 3]).await;
    let error = cluster.stores[1]
        .initialize_cluster()
        .await
        .expect_err("noncanonical pristine node cannot bootstrap alone");
    assert_eq!(
        opc_persist::ConfigConsensusOpenError::ClusterFormationRejected,
        error
    );

    let (one, two, three) = tokio::join!(
        cluster.stores[0].initialize_cluster(),
        cluster.stores[1].initialize_cluster(),
        cluster.stores[2].initialize_cluster(),
    );
    one.expect("initialize canonical node");
    two.expect("admit second node");
    three.expect("admit third node");
    cluster.wait_ready().await;
    cluster.shutdown().await;
}

#[tokio::test]
async fn fresh_fleet_rejects_mismatched_audit_key_compatibility() {
    let cluster = ThreeNodeCluster::build([[0x55; 32], [0x55; 32], [0x56; 32]]).await;
    let (one, two, three) = tokio::join!(
        cluster.stores[0].initialize_cluster(),
        cluster.stores[1].initialize_cluster(),
        cluster.stores[2].initialize_cluster(),
    );
    for result in [one, two, three] {
        assert_eq!(
            Err(opc_persist::ConfigConsensusOpenError::ClusterFormationRejected),
            result
        );
    }
    assert!(cluster.stores.iter().all(|store| !store.status().admitted));
    cluster.shutdown().await;
}

#[tokio::test]
async fn three_nodes_fail_over_replay_lost_responses_and_converge() {
    let cluster = ThreeNodeCluster::start().await;
    let first_id = TxId::new();
    cluster.stores[0]
        .append_attested_commit(attested(commit(first_id, None, 1, 10), audit(first_id)))
        .await
        .expect("replicated first commit");

    let old_leader = cluster.leader();
    let old_leader_id = cluster.stores[old_leader].status().node_id;
    let old_term = cluster.stores[old_leader].status().term;
    cluster.isolate(old_leader);
    let survivors = (0..3)
        .filter(|index| *index != old_leader)
        .collect::<Vec<_>>();
    let (new_leader_id, new_term) = tokio::time::timeout(CLUSTER_TRANSITION_TIMEOUT, async {
        loop {
            let statuses = survivors
                .iter()
                .map(|index| cluster.stores[*index].status())
                .collect::<Vec<_>>();
            if let Some(new_leader_id) = statuses.first().and_then(|status| status.leader_id) {
                let new_term = statuses.first().expect("survivor status").term;
                if new_leader_id != old_leader_id
                    && new_term > old_term
                    && statuses.iter().all(|status| {
                        status.leader_id == Some(new_leader_id) && status.term == new_term
                    })
                {
                    return (new_leader_id, new_term);
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("survivor leader election");
    assert_ne!(new_leader_id, old_leader_id);
    assert!(new_term > old_term);

    let second_id = TxId::new();
    cluster.stores[survivors[0]]
        .append_attested_commit(attested(
            commit(second_id, Some(first_id), 2, 11),
            audit(second_id),
        ))
        .await
        .expect("survivor quorum commit");
    assert!(cluster.stores[old_leader]
        .probe_durable_readiness()
        .await
        .is_err());
    cluster.heal(old_leader);
    cluster.wait_ready().await;

    let leader = cluster.leader();
    let follower = (0..3).find(|index| *index != leader).expect("follower");
    for target in 0..3 {
        if target != follower {
            cluster
                .paths
                .get(&(follower, target))
                .expect("forward path")
                .drop_forward_responses(usize::MAX);
        }
    }
    let third_id = TxId::new();
    let request_id = ConfigConsensusRequestId::from_bytes([0x33; 16]);
    let third_record = commit(third_id, Some(second_id), 3, 12);
    let third_audit = audit(third_id);
    let third_error = cluster.stores[follower]
        .append_commit_idempotent(
            request_id,
            attested(third_record.clone(), third_audit.clone()),
        )
        .await
        .expect_err("lost forwarded response is ambiguous");
    assert!(matches!(
        third_error.kind(),
        PersistErrorKind::OutcomeUnknown
    ));
    for target in 0..3 {
        if target != follower {
            cluster
                .paths
                .get(&(follower, target))
                .expect("forward path")
                .drop_forward_responses(0);
        }
    }
    cluster.stores[follower]
        .append_commit_idempotent(request_id, attested(third_record, third_audit))
        .await
        .expect("recover committed response");

    for target in 0..3 {
        if target != follower {
            cluster
                .paths
                .get(&(follower, target))
                .expect("forward path")
                .drop_forward_responses(usize::MAX);
        }
    }
    let fourth_id = TxId::new();
    let mut fourth_record = commit(fourth_id, Some(third_id), 4, 13);
    fourth_record.confirmed_deadline = Some(Timestamp::now_utc());
    let fourth_audit = audit(fourth_id);
    let fourth_error = cluster.stores[follower]
        .append_attested_commit(attested(fourth_record.clone(), fourth_audit.clone()))
        .await
        .expect_err("lost derived-ID response is ambiguous");
    assert!(matches!(
        fourth_error.kind(),
        PersistErrorKind::OutcomeUnknown
    ));
    for target in 0..3 {
        if target != follower {
            cluster
                .paths
                .get(&(follower, target))
                .expect("forward path")
                .drop_forward_responses(0);
        }
    }
    cluster.stores[follower]
        .append_attested_commit(attested(fourth_record, fourth_audit))
        .await
        .expect("normal ConfigStore path recovers its durable response");
    cluster.stores[follower]
        .mark_confirmed(fourth_id)
        .await
        .expect("deterministic confirm audit");
    cluster.stores[follower]
        .create_rollback_point(fourth_id, Some("stable-fourth".to_owned()))
        .await
        .expect("deterministic rollback audit");

    cluster.wait_ready().await;
    let reference_model = [
        (ConfigVersion::new(1), first_id),
        (ConfigVersion::new(2), second_id),
        (ConfigVersion::new(3), third_id),
        (ConfigVersion::new(4), fourth_id),
    ];
    for store in &cluster.stores {
        let latest = store.load_latest().await.expect("load").expect("latest");
        assert_eq!(latest.record.tx_id, fourth_id);
        assert_eq!(latest.record.version, ConfigVersion::new(4));
        let committed_page = store
            .load_since(ConfigVersion::INITIAL, 64)
            .await
            .expect("follower-local committed history after leader change");
        assert_eq!(reference_model.len(), committed_page.len());
        for (record, (expected_version, expected_tx_id)) in
            committed_page.iter().zip(reference_model)
        {
            assert_eq!(expected_version, record.record.version);
            assert_eq!(expected_tx_id, record.record.tx_id);
        }
        for (version, expected_tx_id) in reference_model {
            let modeled = store
                .load_rollback(RollbackTarget::ByVersion(version))
                .await
                .expect("reference-model history entry");
            assert_eq!(modeled.record.version, version);
            assert_eq!(modeled.record.tx_id, expected_tx_id);
        }
    }
    for path in cluster.paths.values() {
        for payload in path.captured_payloads.lock().expect("capture mutex").iter() {
            for (description, forbidden) in FORBIDDEN_RAFT_ARTIFACTS {
                assert!(
                    !payload
                        .windows(forbidden.len())
                        .any(|window| window == *forbidden),
                    "{description} reached a shared consensus frame"
                );
            }
        }
    }
    let reference_ids = deterministic_authority_row_ids(&cluster.database_path(0));
    assert!(!reference_ids.audit.is_empty());
    assert_eq!(2, reference_ids.lifecycle.len());
    for node in 1..3 {
        assert_eq!(
            reference_ids,
            deterministic_authority_row_ids(&cluster.database_path(node)),
            "replicas must assign identical deterministic authority row IDs"
        );
    }
    cluster.shutdown().await;
}

#[tokio::test]
async fn follower_committed_history_is_served_from_local_applied_state() {
    let cluster = ThreeNodeCluster::start().await;
    let leader = cluster.leader();
    let follower = (0..3).find(|node| *node != leader).expect("follower");

    let first_id = TxId::new();
    cluster.stores[leader]
        .append_attested_commit(attested(commit(first_id, None, 1, 0xA1), audit(first_id)))
        .await
        .expect("first quorum commit");

    tokio::time::timeout(CLUSTER_TRANSITION_TIMEOUT, async {
        loop {
            if cluster.stores[follower]
                .load_committed_latest()
                .await
                .expect("follower-local head")
                .is_some_and(|record| record.record.version == ConfigVersion::new(1))
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first commit applied on follower");

    let wait_store = cluster.stores[follower].clone();
    let wait = tokio::spawn(async move {
        wait_store
            .wait_for_committed_change(ConfigVersion::new(1))
            .await
    });
    tokio::task::yield_now().await;

    let second_id = TxId::new();
    cluster.stores[leader]
        .append_attested_commit(attested(
            commit(second_id, Some(first_id), 2, 0xA2),
            audit(second_id),
        ))
        .await
        .expect("second quorum commit");
    tokio::time::timeout(CLUSTER_TRANSITION_TIMEOUT, wait)
        .await
        .expect("follower apply notification")
        .expect("notification task")
        .expect("notification succeeds");

    cluster.isolate(follower);
    let local_head = tokio::time::timeout(
        Duration::from_millis(250),
        cluster.stores[follower].load_committed_latest(),
    )
    .await
    .expect("local committed head must not enter a leader/read-index path")
    .expect("local committed head")
    .expect("local head exists");
    assert_eq!(ConfigVersion::new(2), local_head.record.version);

    let local_page = tokio::time::timeout(
        Duration::from_millis(250),
        cluster.stores[follower].load_since(ConfigVersion::INITIAL, 64),
    )
    .await
    .expect("local history page must not enter a leader/read-index path")
    .expect("local history page");
    assert_eq!(2, local_page.len());
    assert_eq!(ConfigVersion::new(1), local_page[0].record.version);
    assert_eq!(ConfigVersion::new(2), local_page[1].record.version);

    cluster.shutdown().await;
}

#[cfg(feature = "dangerous-test-hooks")]
#[tokio::test]
async fn leader_change_never_exposes_a_fenced_committed_tail() {
    let cluster = ThreeNodeCluster::start().await;
    let old_leader = cluster.leader();
    let witness = (0..3)
        .find(|node| *node != old_leader)
        .expect("follower witness");
    let first_id = TxId::new();
    cluster.stores[0]
        .append_attested_commit(attested(commit(first_id, None, 1, 0xB1), audit(first_id)))
        .await
        .expect("publish-safe quorum commit");
    let wait_store = cluster.stores[witness].clone();
    let mut publish_safe_wait = tokio::spawn(async move {
        wait_store
            .wait_for_committed_change(ConfigVersion::new(1))
            .await
    });
    tokio::task::yield_now().await;
    let fenced_id = TxId::new();
    cluster.stores[0]
        .append_attested_commit(fenced_attested(
            commit(fenced_id, Some(first_id), 2, 0xB2),
            audit(fenced_id),
        ))
        .await
        .expect("fenced quorum commit");
    let skipped_id = TxId::new();
    let skipped = cluster.stores[0]
        .append_attested_commit(attested(
            commit(skipped_id, Some(fenced_id), 3, 0xB3),
            audit(skipped_id),
        ))
        .await
        .expect_err("consensus must reject a successor past the publication fence");
    assert!(matches!(
        skipped.kind(),
        PersistErrorKind::ConstraintViolation(_)
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut publish_safe_wait)
            .await
            .is_err(),
        "an applied but fenced append must not satisfy the publish-safe wait"
    );

    for store in &cluster.stores {
        let durable = store
            .load_latest()
            .await
            .expect("linearizable durable head")
            .expect("fenced durable head");
        assert_eq!(fenced_id, durable.record.tx_id);
        let visible = store
            .load_committed_latest()
            .await
            .expect("local publish-safe head")
            .expect("cleared prefix");
        assert_eq!(first_id, visible.record.tx_id);
        assert!(store
            .load_since(ConfigVersion::new(1), 64)
            .await
            .expect("local publish-safe tail")
            .is_empty());
    }

    let old_leader_id = cluster.stores[old_leader].status().node_id;
    let old_term = cluster.stores[old_leader].status().term;
    cluster.isolate(old_leader);
    let survivors = (0..3)
        .filter(|node| *node != old_leader)
        .collect::<Vec<_>>();
    cluster.stores[survivors[0]]
        .trigger_election_for_test()
        .await
        .expect("caught-up survivor starts a normal Openraft campaign");
    tokio::time::timeout(CLUSTER_TRANSITION_TIMEOUT, async {
        loop {
            let statuses = survivors
                .iter()
                .map(|node| cluster.stores[*node].status())
                .collect::<Vec<_>>();
            if statuses.iter().all(|status| {
                status
                    .leader_id
                    .is_some_and(|leader| leader != old_leader_id)
                    && status.term > old_term
                    && status.leader_id == statuses[0].leader_id
            }) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("replacement leader election");

    for survivor in &survivors {
        assert_eq!(
            first_id,
            cluster.stores[*survivor]
                .load_committed_latest()
                .await
                .expect("survivor publish-safe head")
                .expect("cleared survivor prefix")
                .record
                .tx_id
        );
    }
    cluster.stores[survivors[0]]
        .clear_recovery_required(fenced_id)
        .await
        .expect("replacement leader clears publication fence");
    tokio::time::timeout(CLUSTER_TRANSITION_TIMEOUT, &mut publish_safe_wait)
        .await
        .expect("clear apply wakes publish-safe waiter")
        .expect("publish-safe waiter task")
        .expect("publish-safe waiter succeeds");
    for survivor in &survivors {
        tokio::time::timeout(CLUSTER_TRANSITION_TIMEOUT, async {
            loop {
                if cluster.stores[*survivor]
                    .load_committed_latest()
                    .await
                    .expect("survivor publish-safe head")
                    .is_some_and(|record| record.record.tx_id == fenced_id)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cleared tail applies on survivor");
    }

    cluster.heal(old_leader);
    cluster.wait_ready().await;
    for store in &cluster.stores {
        assert_eq!(
            fenced_id,
            store
                .load_committed_latest()
                .await
                .expect("healed publish-safe head")
                .expect("healed cleared tail")
                .record
                .tx_id
        );
    }
    cluster.shutdown().await;
}

#[cfg(feature = "dangerous-test-hooks")]
#[tokio::test]
async fn lost_commit_ack_is_outcome_unknown_and_same_id_replays_after_leader_loss() {
    let cluster = ThreeNodeCluster::start().await;
    let leader = cluster.leader();
    let follower = (0..3).find(|node| *node != leader).expect("follower");
    let request_id = ConfigConsensusRequestId::from_bytes([0xA4; 16]);
    let tx_id = TxId::new();
    let record = commit(tx_id, None, 1, 0xA4);
    let records_audit = audit(tx_id);

    for target in 0..3 {
        if target != follower {
            cluster
                .paths
                .get(&(follower, target))
                .expect("forward path")
                .drop_forward_responses(usize::MAX);
        }
    }
    let error = cluster.stores[follower]
        .append_commit_idempotent(request_id, attested(record.clone(), records_audit.clone()))
        .await
        .expect_err("a lost post-commit acknowledgement must be explicit");
    assert!(matches!(error.kind(), PersistErrorKind::OutcomeUnknown));

    let authoritative = cluster.stores[follower]
        .load_latest()
        .await
        .expect("authoritative read resolves ambiguous outcome")
        .expect("ambiguous write committed");
    assert_eq!(tx_id, authoritative.record.tx_id);
    assert_eq!(ConfigVersion::new(1), authoritative.record.version);

    let old_leader_id = cluster.stores[leader].status().node_id;
    let old_term = cluster.stores[leader].status().term;
    cluster.isolate(leader);
    for target in 0..3 {
        if target != follower {
            cluster
                .paths
                .get(&(follower, target))
                .expect("forward path")
                .drop_forward_responses(0);
        }
    }
    let survivors = (0..3).filter(|node| *node != leader).collect::<Vec<_>>();
    cluster.stores[follower]
        .trigger_election_for_test()
        .await
        .expect("caught-up survivor starts a normal Openraft campaign");
    tokio::time::timeout(CLUSTER_TRANSITION_TIMEOUT, async {
        loop {
            let statuses = survivors
                .iter()
                .map(|node| cluster.stores[*node].status())
                .collect::<Vec<_>>();
            if statuses.iter().all(|status| {
                status
                    .leader_id
                    .is_some_and(|new_leader| new_leader != old_leader_id)
                    && status.term > old_term
                    && status.leader_id == statuses[0].leader_id
                    && status.term == statuses[0].term
            }) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("survivors elect replacement leader");

    cluster.stores[follower]
        .append_commit_idempotent(request_id, attested(record, records_audit))
        .await
        .expect("same durable request ID replays committed outcome");
    for survivor in &survivors {
        let latest = cluster.stores[*survivor]
            .load_latest()
            .await
            .expect("survivor read")
            .expect("survivor head");
        assert_eq!(tx_id, latest.record.tx_id);
        assert_eq!(ConfigVersion::new(1), latest.record.version);
    }

    cluster.heal(leader);
    cluster.wait_ready().await;
    for store in &cluster.stores {
        let latest = store
            .load_latest()
            .await
            .expect("converged read")
            .expect("converged head");
        assert_eq!(tx_id, latest.record.tx_id);
        assert_eq!(ConfigVersion::new(1), latest.record.version);
    }
    cluster.shutdown().await;
}

#[cfg(feature = "dangerous-test-hooks")]
#[tokio::test]
async fn replacement_leader_cannot_flip_an_atomic_confirmed_commit_decision() {
    let cluster = ThreeNodeCluster::start().await;
    let pending_tx_id = TxId::new();
    let mut pending = commit(pending_tx_id, None, 1, 0xB1);
    pending.confirmed_deadline = Some(Timestamp::now_utc());
    cluster.stores[0]
        .append_attested_commit(attested(pending, audit(pending_tx_id)))
        .await
        .expect("replicate pending commit");

    let old_leader = cluster.leader();
    let old_leader_id = cluster.stores[old_leader].status().node_id;
    let old_term = cluster.stores[old_leader].status().term;
    let survivors = (0..3)
        .filter(|node| *node != old_leader)
        .collect::<Vec<_>>();
    cluster.isolate(old_leader);

    let confirm_tx_id = TxId::new();
    let confirm_record = commit(confirm_tx_id, Some(pending_tx_id), 2, 0xB2);
    let confirm_audit = audit(confirm_tx_id);
    let isolated_store = cluster.stores[old_leader].clone();
    let attempted_record = confirm_record.clone();
    let attempted_audit = confirm_audit.clone();
    let isolated_confirm = tokio::spawn(async move {
        isolated_store
            .append_attested_commit(attested_resolving(
                attempted_record,
                attempted_audit,
                ConfirmedCommitResolution::Confirm { pending_tx_id },
            ))
            .await
    });

    cluster.stores[survivors[0]]
        .trigger_election_for_test()
        .await
        .expect("caught-up survivor starts a normal Openraft campaign");

    let replacement = tokio::time::timeout(CLUSTER_TRANSITION_TIMEOUT, async {
        loop {
            let statuses = survivors
                .iter()
                .map(|node| cluster.stores[*node].status())
                .collect::<Vec<_>>();
            if let Some(replacement_id) = statuses[0].leader_id {
                if replacement_id != old_leader_id
                    && statuses.iter().all(|status| {
                        status.leader_id == Some(replacement_id)
                            && status.term > old_term
                            && status.term == statuses[0].term
                    })
                {
                    return survivors
                        .iter()
                        .copied()
                        .find(|node| cluster.stores[*node].status().node_id == replacement_id)
                        .expect("replacement leader index");
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("survivors elect replacement leader");

    let rollback_tx_id = TxId::new();
    let rollback_record = commit(rollback_tx_id, Some(pending_tx_id), 2, 0xB3);
    cluster.stores[replacement]
        .append_attested_commit(attested_resolving(
            rollback_record,
            audit(rollback_tx_id),
            ConfirmedCommitResolution::Rollback { pending_tx_id },
        ))
        .await
        .expect("replacement leader commits rollback decision");

    let isolated_result = isolated_confirm.await.expect("isolated proposal task");
    assert!(
        isolated_result.is_err(),
        "isolated leader cannot commit confirm"
    );
    cluster.heal(old_leader);
    cluster.wait_ready().await;

    let stale_confirm = cluster.stores[replacement]
        .append_attested_commit(attested_resolving(
            confirm_record,
            confirm_audit,
            ConfirmedCommitResolution::Confirm { pending_tx_id },
        ))
        .await
        .expect_err("committed rollback decision cannot be flipped after healing");
    assert!(matches!(
        stale_confirm.kind(),
        PersistErrorKind::ConstraintViolation(_)
    ));
    for store in &cluster.stores {
        let latest = store
            .load_latest()
            .await
            .expect("converged decision read")
            .expect("converged decision head");
        assert_eq!(rollback_tx_id, latest.record.tx_id);
        assert_eq!(ConfigVersion::new(2), latest.record.version);
    }
    cluster.shutdown().await;
}

#[tokio::test]
async fn stalled_forwarded_write_and_read_return_within_the_declared_operation_budget() {
    const DECLARED: Duration = Duration::from_secs(3);
    const TEST_CEILING: Duration = Duration::from_millis(3_250);

    let cluster = ThreeNodeCluster::start().await;
    let leader = cluster.leader();
    let follower = (0..3).find(|node| *node != leader).expect("follower");
    let path = cluster
        .paths
        .get(&(follower, leader))
        .expect("follower-to-leader path");

    path.stall_family(ConsensusRpcFamily::ForwardMutation, true);
    let tx_id = TxId::new();
    let started = tokio::time::Instant::now();
    let write = tokio::time::timeout(
        TEST_CEILING,
        cluster.stores[follower]
            .append_attested_commit(attested(commit(tx_id, None, 1, 0xD1), audit(tx_id))),
    )
    .await
    .expect("stalled forwarded write exceeded caller budget");
    assert!(write.is_err());
    let elapsed = started.elapsed();
    assert!(elapsed >= DECLARED - Duration::from_millis(250));
    assert!(elapsed < TEST_CEILING, "write elapsed {elapsed:?}");
    path.stall_family(ConsensusRpcFamily::ForwardMutation, false);

    path.stall_family(ConsensusRpcFamily::ReadBarrier, true);
    let started = tokio::time::Instant::now();
    let read = tokio::time::timeout(TEST_CEILING, cluster.stores[follower].load_latest())
        .await
        .expect("stalled forwarded read exceeded caller budget");
    assert!(read.is_err());
    let elapsed = started.elapsed();
    assert!(elapsed >= DECLARED - Duration::from_millis(250));
    assert!(elapsed < TEST_CEILING, "read elapsed {elapsed:?}");
    path.stall_family(ConsensusRpcFamily::ReadBarrier, false);

    cluster.shutdown().await;
}

#[tokio::test]
async fn voter_subset_is_rejected_without_changing_epoch_membership() {
    let cluster = ThreeNodeCluster::start().await;
    let leader = cluster.leader();
    let leader_id = cluster.stores[leader].status().node_id;
    cluster.stores[leader]
        .change_membership(BTreeSet::from([leader_id]))
        .await
        .expect_err("a voter subset must require a new coordinated epoch");
    assert!(cluster.stores[leader]
        .probe_durable_readiness()
        .await
        .is_ok());
    for store in &cluster.stores {
        assert!(store.status().admitted);
        assert!(store.probe_durable_readiness().await.is_ok());
    }
    let tx_id = TxId::new();
    cluster.stores[leader]
        .append_attested_commit(attested(commit(tx_id, None, 1, 31), audit(tx_id)))
        .await
        .expect("write under unchanged exact membership");
    cluster.stores[leader]
        .trigger_snapshot()
        .await
        .expect("snapshot exact membership");
    cluster.shutdown().await;
}

fn retained_options(
    path: &std::path::Path,
    topology: ConfigConsensusTopology,
    backing: u8,
) -> RetainedConfigOptions {
    RetainedConfigOptions::new(
        path,
        RetainedConfigBinding::new(topology, [backing; 32], [0x61; 32]).expect("binding"),
        RetainedConfigDurability::Ephemeral,
        64 * 1024 * 1024,
        Duration::from_secs(30),
    )
    .expect("retained options")
}

#[tokio::test]
async fn retained_consensus_snapshot_and_reopen_preserve_committed_history() {
    let dir = tempfile::tempdir().expect("storage");
    let path = dir.path().join("retained.sqlite");
    let backend = SqliteBackend::provision_config_authority(
        retained_options(&path, topology(), 1),
        audit_key(),
    )
    .await
    .expect("provision");
    let store = ConsensusConfigStore::open(
        topology(),
        backend,
        dir.path().join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .expect("store");
    store.initialize_cluster().await.expect("initialize");
    let tx = TxId::new();
    store
        .append_commit_idempotent(
            ConfigConsensusRequestId::from_bytes([0x31; 16]),
            attested(commit(tx, None, 1, 1), audit(tx)),
        )
        .await
        .expect("commit");
    store.trigger_snapshot().await.expect("snapshot");
    store.shutdown().await.expect("shutdown");
    drop(store);
    let backend =
        SqliteBackend::reopen_config_authority(retained_options(&path, topology(), 1), audit_key())
            .await
            .expect("reopen");
    let store = ConsensusConfigStore::open(
        topology(),
        backend,
        dir.path().join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .expect("restore");
    store.initialize_cluster().await.expect("readmit");
    assert_eq!(
        store
            .load_latest()
            .await
            .expect("load")
            .expect("head")
            .record
            .tx_id,
        tx
    );
    store.shutdown().await.expect("shutdown restored");
}

#[tokio::test]
async fn retained_member_repair_recovers_from_surviving_quorum() {
    let mut cluster =
        ThreeNodeCluster::build_with_storage([[0x55; 32]; 3], FixtureStorage::RetainedNew).await;
    let (a, b, c) = tokio::join!(
        cluster.stores[0].initialize_cluster(),
        cluster.stores[1].initialize_cluster(),
        cluster.stores[2].initialize_cluster()
    );
    a.expect("first");
    b.expect("second");
    c.expect("third");
    cluster.wait_ready().await;
    let tx = TxId::new();
    cluster.stores[cluster.leader()]
        .append_commit_idempotent(
            ConfigConsensusRequestId::from_bytes([0x32; 16]),
            attested(commit(tx, None, 1, 1), audit(tx)),
        )
        .await
        .expect("commit");
    // The canonical bootstrap voter is deliberately repaired: repair must
    // never execute its normal first-formation genesis path.
    cluster.stores[0]
        .shutdown()
        .await
        .expect("stop canonical voter");
    for ((_, target), peer) in &cluster.paths {
        if *target == 0 {
            *peer.handler.write().await = None;
        }
    }
    let nodes = [1, 2, 3].map(|id| ConfigConsensusNodeId::new(id).expect("node"));
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("opc-persist-three-node-tests").expect("cluster"),
        ConfigConsensusConfigurationId::from_bytes([0x99; 32]),
        ConfigConsensusConfigurationEpoch::new(1).expect("epoch"),
    );
    let topology =
        ConfigConsensusTopology::try_new(identity, nodes[0], nodes.into_iter().collect())
            .expect("topology");
    let path = cluster._directory.path().join("replacement.sqlite");
    assert!(SqliteBackend::reopen_config_authority(
        retained_options(&path, topology.clone(), 9),
        audit_key()
    )
    .await
    .is_err());
    assert!(!path.exists());
    let backend = SqliteBackend::provision_config_member_repair(
        retained_options(&path, topology.clone(), 9),
        audit_key(),
    )
    .await
    .expect("explicit repair");
    let peers = (1..3)
        .map(|target| {
            let peer: Arc<dyn ConsensusPeer> = cluster.paths[&(0, target)].clone();
            (nodes[target], peer)
        })
        .collect();
    let replacement = ConsensusConfigStore::open_with_operation_timeout(
        topology,
        backend,
        cluster._directory.path().join("replacement-snapshots"),
        peers,
        Duration::from_secs(30),
    )
    .await
    .expect("replacement store");
    for ((_, target), peer) in &cluster.paths {
        if *target == 0 {
            peer.install(replacement.rpc_handler()).await;
        }
    }
    cluster.stores[0] = replacement;
    cluster.stores[0]
        .initialize_cluster()
        .await
        .expect("recover exact membership");
    cluster.wait_ready().await;
    assert_eq!(
        cluster.stores[0]
            .load_latest()
            .await
            .expect("load repaired")
            .expect("retained head")
            .record
            .tx_id,
        tx
    );
    cluster.shutdown().await;
}

#[tokio::test]
async fn retained_whole_group_repair_cannot_form_new_genesis() {
    let cluster =
        ThreeNodeCluster::build_with_storage([[0x55; 32]; 3], FixtureStorage::RetainedRepair).await;
    let (a, b, c) = tokio::join!(
        cluster.stores[0].initialize_cluster(),
        cluster.stores[1].initialize_cluster(),
        cluster.stores[2].initialize_cluster()
    );
    assert!(a.is_err() && b.is_err() && c.is_err());
    for store in &cluster.stores {
        assert!(!store.status().admitted);
        assert!(store.status().applied_index.is_none());
    }
    cluster.shutdown().await;
}

#[tokio::test]
async fn retained_committed_wal_crash_child() {
    let Some(root) = std::env::var_os("OPC_RETAINED_COMMIT_CRASH_DIRECTORY") else {
        return;
    };
    let root = std::path::Path::new(&root);
    let path = root.join("retained.sqlite");
    let backend = SqliteBackend::provision_config_authority(
        retained_options(&path, topology(), 1),
        audit_key(),
    )
    .await
    .expect("provision");
    let store =
        ConsensusConfigStore::open(topology(), backend, root.join("snapshots"), BTreeMap::new())
            .await
            .expect("store");
    store.initialize_cluster().await.expect("initialize");
    let tx = TxId::new();
    store
        .append_commit_idempotent(
            ConfigConsensusRequestId::from_bytes([0x33; 16]),
            attested(commit(tx, None, 1, 1), audit(tx)),
        )
        .await
        .expect("committed");
    // Process exit intentionally skips SQLite Drop/checkpoint. The parent
    // verifies the original ciphertext after ordinary WAL-aware reopening.
    std::process::exit(91);
}

#[tokio::test]
async fn retained_reopen_recovers_committed_wal_after_process_loss() {
    let dir = tempfile::tempdir().expect("storage");
    let output = std::process::Command::new(std::env::current_exe().expect("binary"))
        .args([
            "--exact",
            "retained_committed_wal_crash_child",
            "--nocapture",
        ])
        .env("OPC_RETAINED_COMMIT_CRASH_DIRECTORY", dir.path())
        .output()
        .expect("crash child");
    assert_eq!(output.status.code(), Some(91));
    assert!(
        std::fs::metadata(dir.path().join("retained.sqlite-wal"))
            .expect("uncheckpointed WAL")
            .len()
            > 0
    );
    let path = dir.path().join("retained.sqlite");
    let backend =
        SqliteBackend::reopen_config_authority(retained_options(&path, topology(), 1), audit_key())
            .await
            .expect("reopen WAL");
    let store = ConsensusConfigStore::open(
        topology(),
        backend,
        dir.path().join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .expect("restore");
    store.initialize_cluster().await.expect("readmit");
    let head = store
        .load_latest()
        .await
        .expect("load")
        .expect("committed head");
    assert_eq!(head.record.version, ConfigVersion::new(1));
    assert_eq!(
        head.record.plaintext_digest,
        Sha256::digest([1; 32]).to_vec()
    );
    store.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn live_history_schema_cannot_change_unrelated_protected_references() {
    let dir = tempfile::tempdir().expect("directory");
    let database = dir.path().join("config.sqlite");
    let (store, _) = open_singleton(&database, &dir.path().join("snapshots")).await;
    let ids: Vec<_> = (0..5).map(|_| TxId::new()).collect();
    for index in 0..ids.len() {
        store
            .append_attested_commit(attested(
                commit(
                    ids[index],
                    index.checked_sub(1).map(|previous| ids[previous]),
                    index as u64 + 1,
                    0x62,
                ),
                audit(ids[index]),
            ))
            .await
            .expect("complete encrypted history");
    }
    store
        .create_rollback_point(ids[0], None)
        .await
        .expect("protect the oldest revision");
    let observer = rusqlite::Connection::open(&database).expect("independent fixture connection");
    // A schema-only fault leaves every authenticated row unchanged until the
    // next ordinary lifecycle operation. Checking only the prior record chain
    // must not authorize side effects on an unrelated protected revision.
    observer
        .execute_batch(
            "CREATE TRIGGER fixture_unexpected_lifecycle \
             AFTER UPDATE OF rollback_point ON config_history \
             WHEN NEW.version = 5 BEGIN \
             UPDATE config_history SET rollback_point = 0 WHERE version = 1; END;",
        )
        .expect("install isolated schema fault");
    let changed_current = store.create_rollback_point(ids[4], None).await;
    observer
        .execute_batch("DROP TRIGGER fixture_unexpected_lifecycle")
        .expect("remove isolated schema fault");
    let retention_result = store
        .retain_history_idempotent(
            ConfigConsensusRequestId::from_bytes([0xE4; 16]),
            retention(ids[4], 5, 4, 2, 1_048_576),
        )
        .await;
    let (count, protected): (i64, i64) = observer
        .query_row(
            "SELECT COUNT(*), COALESCE(SUM(CASE WHEN version = 1 THEN rollback_point ELSE 0 END), 0) FROM config_history",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("independent protected-history readback");
    store.shutdown().await.expect("shutdown");
    assert!(
        changed_current.is_err(),
        "unexpected executable schema must refuse the lifecycle operation"
    );
    assert!(
        retention_result.is_err(),
        "an ordinary lifecycle update cannot authenticate unrelated reference loss"
    );
    assert_eq!(count, 5, "every original revision remains retained");
    assert_eq!(
        protected, 1,
        "the unrelated rollback reference remains intact"
    );
}

#[tokio::test]
async fn live_history_reads_refuse_unexpected_schema() {
    for schema_fault in [
        "CREATE TRIGGER fixture_unexpected_read_guard AFTER UPDATE ON config_history BEGIN SELECT 1; END;",
        "CREATE INDEX fixture_unexpected_index ON config_history(source);",
        "ALTER TABLE rollback_labels ADD COLUMN fixture_unexpected_reference TEXT;",
    ] {
        let dir = tempfile::tempdir().expect("directory");
        let database = dir.path().join("config.sqlite");
        let (store, _) = open_singleton(&database, &dir.path().join("snapshots")).await;
        let tx_id = TxId::new();
        store
            .append_attested_commit(attested(commit(tx_id, None, 1, 0x62), audit(tx_id)))
            .await
            .expect("complete encrypted history");
        let observer = rusqlite::Connection::open(&database).expect("independent fixture connection");
        observer
            .execute_batch(schema_fault)
            .expect("change only the isolated schema");
        let latest = store.load_latest().await;
        let published = store.load_committed_latest().await;
        let tail = store.load_since(ConfigVersion::new(0), 4).await;
        let floor = store.retained_history_floor().await;
        store.shutdown().await.expect("shutdown");
        assert!(latest.is_err(), "latest read refuses an unadmitted schema");
        assert!(published.is_err(), "publication refuses an unadmitted schema");
        assert!(tail.is_err(), "tail read refuses an unadmitted schema");
        assert!(floor.is_err(), "floor read refuses an unadmitted schema");
    }
}

#[tokio::test]
async fn history_retention_refuses_damaged_mutable_references() {
    for mutation in [
        "rollback_flag",
        "rollback_flag_then_append",
        "rollback_flag_then_lifecycle",
        "pending_deadline",
        "named_label",
        "lifecycle_row",
        "plaintext_digest",
    ] {
        let dir = tempfile::tempdir().expect("directory");
        let database = dir.path().join("config.sqlite");
        let (store, _) = open_singleton(&database, &dir.path().join("snapshots")).await;
        let total = if mutation == "pending_deadline" { 3 } else { 5 };
        let ids: Vec<_> = (0..total).map(|_| TxId::new()).collect();
        for index in 0..total {
            let mut record = commit(
                ids[index],
                index.checked_sub(1).map(|previous| ids[previous]),
                index as u64 + 1,
                0x62,
            );
            if mutation == "pending_deadline" && index == total - 1 {
                record.confirmed_deadline = Some(Timestamp::now_utc());
            }
            store
                .append_attested_commit(attested(record, audit(ids[index])))
                .await
                .expect("complete encrypted history");
        }
        if mutation.starts_with("rollback_flag") {
            store
                .create_rollback_point(ids[0], None)
                .await
                .expect("explicit protected reference");
        } else if mutation == "named_label" || mutation == "lifecycle_row" {
            store
                .create_rollback_point(ids[total - 1], Some("retained-current".to_owned()))
                .await
                .expect("current named rollback reference");
        }
        let observer = rusqlite::Connection::open(&database).expect("adversarial connection");
        let sql = match mutation {
            "rollback_flag" | "rollback_flag_then_append" | "rollback_flag_then_lifecycle" =>
                "UPDATE config_history SET rollback_point = 0 WHERE version = 1",
            "pending_deadline" => "UPDATE config_history SET confirmed_deadline = NULL WHERE version = 3",
            "named_label" => "UPDATE rollback_labels SET label = 'substituted-current' WHERE label = 'retained-current'",
            "lifecycle_row" => "DELETE FROM config_lifecycle_audit",
            "plaintext_digest" => "UPDATE config_history SET plaintext_digest = zeroblob(32) WHERE version = 1",
            _ => unreachable!("closed mutation list"),
        };
        assert_eq!(
            observer
                .execute(sql, [])
                .expect("damage exactly one reference"),
            1
        );
        if mutation == "rollback_flag_then_append" {
            let next = TxId::new();
            store
                .append_attested_commit(attested(
                    commit(next, Some(ids[total - 1]), total as u64 + 1, 0x62),
                    audit(next),
                ))
                .await
                .expect_err("damaged admission metadata refuses append before mutation");
        } else if mutation == "rollback_flag_then_lifecycle" {
            // This ordinary operation may refuse the damaged prior state. If
            // it proceeds, it must never reauthenticate unrelated corruption.
            let _ = store.create_rollback_point(ids[total - 1], None).await;
        }
        let version = ids.len() as u64;
        let result = store
            .retain_history_idempotent(
                ConfigConsensusRequestId::from_bytes([0xD7; 16]),
                retention(
                    *ids.last().expect("head"),
                    version,
                    version - 1,
                    2,
                    1_048_576,
                ),
            )
            .await;
        let count: i64 = observer
            .query_row("SELECT COUNT(*) FROM config_history", [], |row| row.get(0))
            .expect("independent row readback");
        let encoded: Vec<u8> = observer
            .query_row(
                "SELECT state_json FROM config_raft_history_retention",
                [],
                |row| row.get(0),
            )
            .expect("unchanged boundary readback");
        drop(observer);
        store.shutdown().await.expect("shutdown");
        assert!(
            result.is_err(),
            "{mutation}: damaged lifecycle/reference metadata cannot authorize pruning"
        );
        assert_eq!(
            count as u64, version,
            "{mutation}: every original row survives"
        );
        let state: serde_json::Value = serde_json::from_slice(&encoded).expect("state shape");
        assert!(
            state["boundary"].is_null(),
            "no compaction permission minted over damaged references"
        );
    }
}

// SDK #802: a live read must authenticate mutable publication/rollback metadata,
// including a negative lookup, rather than waiting for pruning or reopening.
#[cfg(feature = "dangerous-test-hooks")]
#[tokio::test]
async fn live_history_reads_refuse_unauthenticated_lifecycle_metadata() {
    let mut accepted = Vec::new();
    for mutation in ["publication_fence", "pending_deadline", "named_target"] {
        let dir = tempfile::tempdir().expect("directory");
        let database = dir.path().join("config.sqlite");
        let (store, _) = open_singleton(&database, &dir.path().join("snapshots")).await;
        let ids = [TxId::new(), TxId::new(), TxId::new()];
        for index in 0..ids.len() {
            let mut record = commit(
                ids[index],
                index.checked_sub(1).map(|previous| ids[previous]),
                index as u64 + 1,
                0x63,
            );
            if mutation == "pending_deadline" && index == 2 {
                record.confirmed_deadline = Some(Timestamp::now_utc());
            }
            let prepared = if mutation == "publication_fence" && index == 2 {
                fenced_attested(record, audit(ids[index]))
            } else {
                attested(record, audit(ids[index]))
            };
            store
                .append_attested_commit(prepared)
                .await
                .expect("authenticated history");
        }
        store
            .create_rollback_point(ids[0], Some("retained-target".to_owned()))
            .await
            .expect("authenticated named target");
        assert!(store.load_latest().await.expect("valid latest").is_some());
        assert!(store
            .load_committed_latest()
            .await
            .expect("valid visible head")
            .is_some());
        let absent_digest = "01".repeat(32);
        assert!(store
            .load_by_replay_lookup_digest(&absent_digest)
            .await
            .expect("authenticated negative lookup")
            .is_none());

        let observer = rusqlite::Connection::open(&database).expect("adversarial connection");
        let changed = match mutation {
            "publication_fence" => observer.execute(
                "UPDATE config_history SET principal = replace(principal, '\"recovery_required\":true', '\"recovery_required\":false') WHERE version = 3",
                [],
            ),
            "pending_deadline" => observer.execute(
                "UPDATE config_history SET confirmed_deadline = NULL WHERE version = 3",
                [],
            ),
            "named_target" => observer.execute(
                "UPDATE rollback_labels SET tx_id = ?1 WHERE label = 'retained-target'",
                [ids[1].as_uuid().as_bytes().as_slice()],
            ),
            _ => unreachable!("closed mutation list"),
        }
        .expect("alter one mutable field");
        assert_eq!(changed, 1);
        for (operation, refused) in [
            ("latest", store.load_latest().await.is_err()),
            ("published", store.load_committed_latest().await.is_err()),
            (
                "tail",
                store.load_since(ConfigVersion::new(1), 64).await.is_err(),
            ),
            ("floor", store.retained_history_floor().await.is_err()),
            (
                "rollback",
                store
                    .load_rollback(RollbackTarget::ByLabel("retained-target".to_owned()))
                    .await
                    .is_err(),
            ),
            (
                "negative_replay_lookup",
                store
                    .load_by_replay_lookup_digest(&absent_digest)
                    .await
                    .is_err(),
            ),
        ] {
            if !refused {
                accepted.push((mutation, operation));
            }
        }
        drop(observer);
        store.shutdown().await.expect("shutdown");
    }
    assert!(
        accepted.is_empty(),
        "unauthenticated live reads: {accepted:?}"
    );
}

#[tokio::test]
async fn live_history_append_refuses_a_cleared_pending_deadline() {
    let dir = tempfile::tempdir().expect("directory");
    let database = dir.path().join("config.sqlite");
    let (store, _) = open_singleton(&database, &dir.path().join("snapshots")).await;
    let ids = [TxId::new(), TxId::new(), TxId::new()];
    store
        .append_attested_commit(attested(commit(ids[0], None, 1, 0x63), audit(ids[0])))
        .await
        .expect("first commit");
    let mut pending = commit(ids[1], Some(ids[0]), 2, 0x63);
    pending.confirmed_deadline = Some(Timestamp::now_utc());
    store
        .append_attested_commit(attested(pending, audit(ids[1])))
        .await
        .expect("pending commit");
    let observer = rusqlite::Connection::open(&database).expect("adversarial connection");
    assert_eq!(
        observer
            .execute(
                "UPDATE config_history SET confirmed_deadline = NULL WHERE version = 2",
                []
            )
            .expect("clear pending marker"),
        1
    );
    let result = store
        .append_attested_commit(attested(
            commit(ids[2], Some(ids[1]), 3, 0x63),
            audit(ids[2]),
        ))
        .await;
    let count: i64 = observer
        .query_row("SELECT COUNT(*) FROM config_history", [], |row| row.get(0))
        .expect("independent mutation readback");
    drop(observer);
    store.shutdown().await.expect("shutdown");
    assert!(
        result.is_err(),
        "altered pending metadata cannot admit a new commit"
    );
    assert_eq!(
        count, 2,
        "no new canonical record after damaged admission state"
    );
}

#[tokio::test]
async fn live_history_missing_identity_never_becomes_standalone() {
    let dir = tempfile::tempdir().expect("directory");
    let database = dir.path().join("config.sqlite");
    let backend = SqliteBackend::provision_config_authority(
        retained_options(&database, topology(), 1),
        audit_key(),
    )
    .await
    .expect("explicit retained authority");
    let store = ConsensusConfigStore::open(
        topology(),
        backend,
        dir.path().join("snapshots"),
        BTreeMap::new(),
    )
    .await
    .expect("store");
    store.initialize_cluster().await.expect("initialize");
    let ids: Vec<_> = (0..5).map(|_| TxId::new()).collect();
    for index in 0..5 {
        store
            .append_attested_commit(attested(
                commit(
                    ids[index],
                    index.checked_sub(1).map(|i| ids[i]),
                    index as u64 + 1,
                    0x63,
                ),
                audit(ids[index]),
            ))
            .await
            .expect("complete history");
    }
    store
        .retain_history_idempotent(
            ConfigConsensusRequestId::from_bytes([0xDA; 16]),
            retention(ids[4], 5, 3, 3, 1_048_576),
        )
        .await
        .expect("authenticated floor");
    assert_eq!(
        store.retained_history_floor().await.expect("floor"),
        Some(ConfigVersion::new(2))
    );
    let observer = rusqlite::Connection::open(&database).expect("adversarial connection");
    observer
        .execute_batch("DROP TABLE config_raft_identity")
        .expect("remove identity only");
    let refused = [
        store.retained_history_floor().await.is_err(),
        store.load_latest().await.is_err(),
        store.load_committed_latest().await.is_err(),
        store.load_since(ConfigVersion::new(2), 64).await.is_err(),
    ];
    drop(observer);
    store.shutdown().await.expect("shutdown");
    assert!(
        refused.into_iter().all(|value| value),
        "lost identity must not authorize standalone reads"
    );
}

#[tokio::test]
async fn live_history_claim_survives_removal_of_all_consensus_tables() {
    let dir = tempfile::tempdir().expect("directory");
    let database = dir.path().join("config.sqlite");
    let (store, bypass) = open_singleton(&database, &dir.path().join("snapshots")).await;
    let tx_id = TxId::new();
    store
        .append_attested_commit(attested(commit(tx_id, None, 1, 0x64), audit(tx_id)))
        .await
        .expect("authenticated history");
    let observer = rusqlite::Connection::open(&database).expect("independent connection");
    let tables: Vec<String> = observer
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name GLOB 'config_raft_*'",
        )
        .expect("table inventory")
        .query_map([], |row| row.get(0))
        .expect("table names")
        .collect::<Result<_, _>>()
        .expect("closed schema");
    assert!(!tables.is_empty());
    for table in tables {
        observer
            .execute_batch(&format!("DROP TABLE \"{}\"", table.replace('"', "\"\"")))
            .expect("remove consensus metadata");
    }
    // The clone predates the claim. It must still remember the same requirement
    // when no on-disk marker remains; neither reads nor direct writes reopen.
    let refused = [
        bypass.load_latest().await.is_err(),
        bypass.retained_history_floor().await.is_err(),
        bypass.create_rollback_point(tx_id, None).await.is_err(),
        store.load_committed_latest().await.is_err(),
    ];
    let rollback: bool = observer
        .query_row(
            "SELECT rollback_point FROM config_history WHERE version = 1",
            [],
            |row| row.get(0),
        )
        .expect("independent no-mutation readback");
    drop(observer);
    store.shutdown().await.expect("shutdown");
    assert!(refused.into_iter().all(|value| value));
    assert!(
        !rollback,
        "erased authority never re-enables direct mutation"
    );
}

#[tokio::test]
async fn retained_history_lifecycle_metadata_is_authenticated_on_reopen() {
    for mutation in ["rollback_flag", "named_label", "lifecycle_row"] {
        let dir = tempfile::tempdir().expect("directory");
        let path = dir.path().join("retained.sqlite");
        let backend = SqliteBackend::provision_config_authority(
            retained_options(&path, topology(), 1),
            audit_key(),
        )
        .await
        .expect("explicit provision");
        let store = ConsensusConfigStore::open(
            topology(),
            backend,
            dir.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("store");
        store.initialize_cluster().await.expect("initialize");
        let ids: Vec<_> = (0..5).map(|_| TxId::new()).collect();
        for index in 0..5 {
            store
                .append_attested_commit(attested(
                    commit(
                        ids[index],
                        index.checked_sub(1).map(|i| ids[i]),
                        index as u64 + 1,
                        0x62,
                    ),
                    audit(ids[index]),
                ))
                .await
                .expect("encrypted configuration");
        }
        store
            .retain_history_idempotent(
                ConfigConsensusRequestId::from_bytes([0xD8; 16]),
                retention(ids[4], 5, 3, 3, 1_048_576),
            )
            .await
            .expect("retained prefix");
        store
            .create_rollback_point(ids[4], Some("retained-current".to_owned()))
            .await
            .expect("legitimate lifecycle change after pruning");
        store.shutdown().await.expect("shutdown");
        drop(store);
        let clean = SqliteBackend::reopen_config_authority(
            retained_options(&path, topology(), 1),
            audit_key(),
        )
        .await
        .expect("legitimate lifecycle mutation survives retained reopen");
        drop(clean);
        let attacker = rusqlite::Connection::open(&path).expect("offline corruptor");
        let (read, damage, repair) = match mutation {
            "rollback_flag" => (
                "SELECT rollback_point FROM config_history WHERE version = 5",
                "UPDATE config_history SET rollback_point = 0 WHERE version = 5",
                "UPDATE config_history SET rollback_point = ?1 WHERE version = 5",
            ),
            "named_label" => (
                "SELECT label, tx_id, created_at FROM rollback_labels WHERE label = 'retained-current'",
                "DELETE FROM rollback_labels WHERE label = 'retained-current'",
                "INSERT INTO rollback_labels (label, tx_id, created_at) VALUES (?1, ?2, ?3)",
            ),
            "lifecycle_row" => (
                "SELECT id, tx_id, action, principal, occurred_at, details FROM config_lifecycle_audit",
                "DELETE FROM config_lifecycle_audit",
                "INSERT INTO config_lifecycle_audit (id, tx_id, action, principal, occurred_at, details) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            ),
            _ => unreachable!("closed mutation list"),
        };
        let original = attacker
            .query_row(read, [], |row| {
                (0..row.as_ref().column_count())
                    .map(|index| row.get::<_, rusqlite::types::Value>(index))
                    .collect::<rusqlite::Result<Vec<_>>>()
            })
            .expect("preserve the exact synthetic metadata before damage");
        assert_eq!(
            attacker
                .execute(damage, [])
                .expect("damage one retained reference"),
            1
        );
        drop(attacker);
        assert!(
            matches!(
                SqliteBackend::reopen_config_authority(
                    retained_options(&path, topology(), 1),
                    audit_key(),
                )
                .await,
                Err(opc_persist::RetainedConfigError::Rejected)
            ),
            "{mutation}: retained reopen must reject unauthenticated lifecycle changes"
        );
        let repair_connection =
            rusqlite::Connection::open(&path).expect("restore only the damaged row");
        assert_eq!(
            repair_connection
                .execute(repair, rusqlite::params_from_iter(original.iter()))
                .expect("restore original metadata without changing the authenticated digest"),
            1
        );
        drop(repair_connection);
        SqliteBackend::reopen_config_authority(retained_options(&path, topology(), 1), audit_key())
            .await
            .expect("exact metadata restoration restores admission");
    }
}
