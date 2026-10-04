//! Synthetic three-voter required-audit fixture; never a production provider.
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use opc_config_bus::{EncryptingManagedDatastore, StoredConfig};
use opc_config_bus_consensus::RaftManagedDatastore;
use opc_config_model::{
    ConfigError, OpcConfig, RequestSource, TrustedPrincipal, ValidationContext, ValidationError,
    WorkloadIdentity, YangPath,
};
use opc_consensus::{
    ConsensusPeer, ConsensusPeerError, ConsensusRpcHandler, ConsensusWireRequest,
    ConsensusWireResponse, DURABLE_CONSENSUS_OPERATION_TIMEOUT,
};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_persist::audit_authority::continuity::{
    AuditCheckpoint, AuditCheckpointAdvance, AuditCheckpointPort,
};
use opc_persist::audit_authority::{AuditAuthorityError, AuditPrivacyKey};
use opc_persist::{
    AuditKey, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, ConfigConsensusNodeId,
    ConfigConsensusTopology, ConsensusConfigStore, SqliteBackend,
};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, TxId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct TestConfig {
    pub(super) name: String,
}

impl OpcConfig for TestConfig {
    type Delta = String;

    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_bytes([0x25; 32])
    }

    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        if self == previous {
            Ok(Vec::new())
        } else {
            Ok(vec![self.name.clone()])
        }
    }

    fn changed_paths(
        &self,
        _previous: &Self,
        deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        if deltas.is_empty() {
            Ok(Vec::new())
        } else {
            YangPath::new("/system/name")
                .map(|path| vec![path])
                .map_err(|error| ConfigError::new("changed-path", error.message()))
        }
    }

    fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
        self.name = delta;
        Ok(())
    }

    fn validate_syntax(&self) -> Result<(), ValidationError> {
        if self.name == "invalid-test-candidate" {
            return Err(ValidationError::syntax("synthetic candidate rejected"));
        }
        Ok(())
    }

    fn validate_semantics(
        &self,
        _context: &ValidationContext<Self>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }
}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").expect("test tenant")
}

pub(super) fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::Internal("config-writer".to_owned()),
        tenant(),
    )
}

pub(super) fn provider() -> Arc<MemoryKeyProvider> {
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("config-key").expect("test key ID"),
            KeyPurpose::Config,
            tenant(),
            Zeroizing::new([0xA5; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("insert test key");
    provider
}

#[derive(Clone)]
struct LoopbackPeer {
    target: ConfigConsensusNodeId,
    handler: Arc<tokio::sync::RwLock<Option<Arc<dyn ConsensusRpcHandler>>>>,
    enabled: Arc<AtomicBool>,
}

impl LoopbackPeer {
    fn new(target: ConfigConsensusNodeId) -> Self {
        Self {
            target,
            handler: Arc::new(tokio::sync::RwLock::new(None)),
            enabled: Arc::new(AtomicBool::new(true)),
        }
    }

    async fn install(&self, handler: Arc<dyn ConsensusRpcHandler>) {
        *self.handler.write().await = Some(handler);
    }
}

impl fmt::Debug for LoopbackPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackPeer")
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl ConsensusPeer for LoopbackPeer {
    fn node_id(&self) -> ConfigConsensusNodeId {
        self.target
    }

    async fn call(
        &self,
        request: ConsensusWireRequest,
    ) -> Result<ConsensusWireResponse, ConsensusPeerError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(ConsensusPeerError::Unavailable);
        }
        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(ConsensusPeerError::Unavailable)?;
        Ok(handler.handle(request.sender, request).await)
    }
}

pub(super) struct ProjectionCluster {
    _directory: tempfile::TempDir,
    pub(super) stores: Vec<Arc<ConsensusConfigStore>>,
}

impl ProjectionCluster {
    pub(super) async fn start_with_continuity(
        checkpoints: Option<Arc<dyn opc_persist::audit_authority::continuity::AuditCheckpointPort>>,
    ) -> Self {
        let directory = tempfile::tempdir().expect("projection cluster directory");
        let nodes = [1_u64, 2, 3]
            .map(|value| ConfigConsensusNodeId::new(value).expect("projection cluster node ID"));
        let members = nodes.into_iter().collect::<BTreeSet<_>>();
        let identity = ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::new("config-bus-projection-tests").expect("cluster ID"),
            ConfigConsensusConfigurationId::from_bytes([0x70; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("configuration epoch"),
        );
        let mut paths = BTreeMap::new();
        for source in 0..3 {
            for (target, target_node) in nodes.iter().copied().enumerate() {
                if source != target {
                    paths.insert((source, target), Arc::new(LoopbackPeer::new(target_node)));
                }
            }
        }

        let mut stores = Vec::new();
        for (index, node) in nodes.iter().copied().enumerate() {
            let peers = (0..3)
                .filter(|target| *target != index)
                .map(|target| {
                    let peer: Arc<dyn ConsensusPeer> = paths
                        .get(&(index, target))
                        .expect("projection cluster path")
                        .clone();
                    (nodes[target], peer)
                })
                .collect();
            let backend = SqliteBackend::open_with_audit_key(
                directory.path().join(format!("node-{index}.sqlite")),
                true,
                0,
                AuditKey::new([0x71; 32]).expect("audit key"),
            )
            .await
            .expect("projection cluster backend");
            let topology = ConfigConsensusTopology::try_new(identity, node, members.clone())
                .expect("projection cluster topology");
            let snapshots = directory.path().join(format!("snapshots-{index}"));
            let store = if let Some(checkpoints) = &checkpoints {
                use opc_persist::audit_authority::continuity::{
                    AuditContinuityPolicy, AuditKeyRing, AuditSigningKey,
                };
                let keys = AuditKeyRing::new(vec![
                    AuditSigningKey::new(1, [0x91; 32]).expect("separate signing key")
                ])
                .expect("key ring");
                ConsensusConfigStore::open_with_audit_continuity(
                    topology,
                    backend,
                    snapshots,
                    peers,
                    AuditContinuityPolicy::new(keys, Arc::clone(checkpoints), 1, 1)
                        .expect("continuity policy"),
                )
                .await
            } else {
                ConsensusConfigStore::open_with_operation_timeout(
                    topology,
                    backend,
                    snapshots,
                    peers,
                    DURABLE_CONSENSUS_OPERATION_TIMEOUT,
                )
                .await
            };
            stores.push(Arc::new(store.expect("projection cluster store")));
        }
        for ((_, target), path) in &paths {
            path.install(stores[*target].rpc_handler()).await;
        }

        let cluster = Self {
            _directory: directory,
            stores,
        };
        let (one, two, three) = tokio::join!(
            cluster.stores[0].initialize_cluster(),
            cluster.stores[1].initialize_cluster(),
            cluster.stores[2].initialize_cluster(),
        );
        one.expect("initialize projection node one");
        two.expect("initialize projection node two");
        three.expect("initialize projection node three");
        if checkpoints.is_some() {
            // Required audit readiness deliberately stays closed until the
            // separate ledger/checkpoint provisioning below the fixture.
            tokio::time::timeout(Duration::from_secs(10), async {
                while !cluster
                    .stores
                    .iter()
                    .any(|store| store.status().leader_id.is_some())
                {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .expect("projection cluster leader before audit provisioning");
        } else {
            cluster.wait_ready().await;
        }
        cluster
    }

    pub(super) async fn wait_ready(&self) {
        tokio::time::timeout(Duration::from_secs(10), async {
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
        .expect("projection cluster ready");
    }

    pub(super) fn leader(&self) -> usize {
        let leader = self
            .stores
            .iter()
            .find_map(|store| store.status().leader_id)
            .expect("projection cluster leader");
        self.stores
            .iter()
            .position(|store| store.status().node_id == leader)
            .expect("projection leader index")
    }

    pub(super) async fn shutdown(&self) {
        let _ = tokio::join!(
            self.stores[0].shutdown(),
            self.stores[1].shutdown(),
            self.stores[2].shutdown(),
        );
    }
}

pub(super) fn projection_record(
    tx_id: TxId,
    parent_tx_id: Option<TxId>,
    version: u64,
    name: &str,
) -> StoredConfig<TestConfig> {
    let mut record = StoredConfig::new(
        tx_id,
        ConfigVersion::new(version),
        principal(),
        RequestSource::Internal,
        TestConfig {
            name: name.to_owned(),
        },
    );
    record.parent_tx_id = parent_tx_id;
    record
}

pub(super) fn audited_source(
    store: Arc<ConsensusConfigStore>,
    privacy: Arc<AuditPrivacyKey>,
) -> Arc<EncryptingManagedDatastore<TestConfig, MemoryKeyProvider, RaftManagedDatastore<TestConfig>>>
{
    Arc::new(EncryptingManagedDatastore::new(
        Arc::new(RaftManagedDatastore::new_audited_local_authority(
            store,
            opc_config_bus_consensus::ConfigAuditPolicy::new(privacy, Duration::from_secs(60))
                .expect("audit policy"),
        )),
        provider(),
    ))
}

// Synthetic separately owned monotonic authority, never a production provider.
#[derive(Default)]
pub(super) struct CheckpointFixture {
    value: std::sync::Mutex<Option<AuditCheckpoint>>,
    pub(super) unavailable: AtomicBool,
    pub(super) advance_unavailable: AtomicBool,
    advance_attempts: AtomicUsize,
    pub(super) refuse_from_sequence: AtomicU64,
    lose_next_ack: AtomicBool,
    pub(super) pause_at_sequence: AtomicU64,
    pub(super) entered: tokio::sync::Notify,
    pub(super) resume: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl AuditCheckpointPort for CheckpointFixture {
    async fn load(
        &self,
        _: ConfigConsensusIdentity,
    ) -> Result<Option<AuditCheckpoint>, AuditAuthorityError> {
        if self.unavailable.load(Ordering::Acquire) {
            return Err(AuditAuthorityError::Unavailable);
        }
        Ok(self.value.lock().expect("checkpoint lock").clone())
    }

    async fn compare_advance(
        &self,
        _: ConfigConsensusIdentity,
        expected: Option<AuditCheckpoint>,
        next: AuditCheckpoint,
    ) -> Result<AuditCheckpointAdvance, AuditAuthorityError> {
        self.advance_attempts.fetch_add(1, Ordering::AcqRel);
        if self.unavailable.load(Ordering::Acquire)
            || self.advance_unavailable.load(Ordering::Acquire)
            || (self.refuse_from_sequence.load(Ordering::Acquire) != 0
                && next.sequence() >= self.refuse_from_sequence.load(Ordering::Acquire))
        {
            return Err(AuditAuthorityError::Unavailable);
        }
        if self.pause_at_sequence.load(Ordering::Acquire) != 0
            && self.pause_at_sequence.load(Ordering::Acquire) == next.sequence()
        {
            self.entered.notify_one();
            self.resume.notified().await;
        }
        let mut current = self.value.lock().expect("checkpoint lock");
        if *current != expected
            || current
                .as_ref()
                .is_some_and(|old| old.sequence() >= next.sequence())
        {
            return Ok(AuditCheckpointAdvance::Conflict);
        }
        *current = Some(next);
        Ok(if self.lose_next_ack.swap(false, Ordering::AcqRel) {
            AuditCheckpointAdvance::Unknown
        } else {
            AuditCheckpointAdvance::Applied
        })
    }
}

impl CheckpointFixture {
    pub(super) fn sequence(&self) -> u64 {
        self.value
            .lock()
            .expect("checkpoint lock")
            .as_ref()
            .expect("provisioned checkpoint")
            .sequence()
    }
}
