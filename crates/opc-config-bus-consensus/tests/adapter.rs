use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use opc_config_bus::{
    CommitWrite, CommittedRevisionSource, ConfigBus, ConfigSnapshot, EncryptingManagedDatastore,
    ManagedDatastore, SealedConfig, StoreErrorCode, StoredConfig,
};
use opc_config_bus_consensus::{
    ConsensusConfigAuthority, ConsensusConfigBusProjection, PersistManagedDatastore,
    RaftManagedDatastore,
};
use opc_config_model::{
    CommitMode, CommitRequest, ConfigError, ConfigOperation, OpcConfig, RequestId, RequestSource,
    RollbackTarget, TransportType, TrustedPrincipal, ValidationContext, ValidationError,
    WorkloadIdentity, YangPath,
};
use opc_consensus::{
    ConsensusPeer, ConsensusPeerError, ConsensusRpcHandler, ConsensusWireRequest,
    ConsensusWireResponse, DURABLE_CONSENSUS_OPERATION_TIMEOUT,
};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_persist::{
    AuditKey, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, ConfigConsensusNodeId,
    ConfigConsensusTopology, ConfigStore, ConsensusConfigStore, MockConfigStore,
    RollbackTarget as PersistRollbackTarget, SqliteBackend,
};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TestConfig {
    name: String,
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

fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::Internal("config-writer".to_owned()),
        tenant(),
    )
}

fn record(tx_id: TxId, label: &str) -> StoredConfig<TestConfig> {
    StoredConfig {
        tx_id,
        parent_tx_id: None,
        version: ConfigVersion::new(1),
        committed_at: Timestamp::from_str("2026-07-16T00:00:00Z").expect("fixed timestamp"),
        principal: principal(),
        source: RequestSource::Internal,
        schema_digest: SchemaDigest::from_bytes([0x25; 32]),
        plaintext_digest: None,
        config: TestConfig {
            name: "ciphertext-only-config".to_owned(),
        },
        encrypted_blob: Vec::new(),
        idempotency_key: None,
        apply_plan: None,
        request_fingerprint: None,
        request_id: None,
        recovery_required: false,
        confirmed_deadline: None,
        rollback_label: Some(label.to_owned()),
    }
}

fn provider() -> Arc<MemoryKeyProvider> {
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

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
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

struct ProjectionCluster {
    _directory: tempfile::TempDir,
    stores: Vec<Arc<ConsensusConfigStore>>,
    paths: BTreeMap<(usize, usize), Arc<LoopbackPeer>>,
}

impl ProjectionCluster {
    async fn start() -> Self {
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
            stores.push(Arc::new(
                ConsensusConfigStore::open_with_operation_timeout(
                    ConfigConsensusTopology::try_new(identity, node, members.clone())
                        .expect("projection cluster topology"),
                    backend,
                    directory.path().join(format!("snapshots-{index}")),
                    peers,
                    DURABLE_CONSENSUS_OPERATION_TIMEOUT,
                )
                .await
                .expect("projection cluster store"),
            ));
        }
        for ((_, target), path) in &paths {
            path.install(stores[*target].rpc_handler()).await;
        }

        let cluster = Self {
            _directory: directory,
            stores,
            paths,
        };
        let (one, two, three) = tokio::join!(
            cluster.stores[0].initialize_cluster(),
            cluster.stores[1].initialize_cluster(),
            cluster.stores[2].initialize_cluster(),
        );
        one.expect("initialize projection node one");
        two.expect("initialize projection node two");
        three.expect("initialize projection node three");
        cluster.wait_ready().await;
        cluster
    }

    async fn wait_ready(&self) {
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

    fn leader(&self) -> usize {
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

    fn isolate(&self, node: usize) {
        for peer in 0..3 {
            if peer != node {
                self.paths
                    .get(&(node, peer))
                    .expect("outbound isolation path")
                    .set_enabled(false);
                self.paths
                    .get(&(peer, node))
                    .expect("inbound isolation path")
                    .set_enabled(false);
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

fn projection_record(
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

#[tokio::test]
async fn named_rollback_label_and_root_audit_are_persisted_atomically() {
    let persistence = Arc::new(MockConfigStore::new());
    let sealed = Arc::new(PersistManagedDatastore::<TestConfig, _>::new(Arc::clone(
        &persistence,
    )));
    let encrypted = EncryptingManagedDatastore::new(sealed, provider());
    let tx_id = TxId::new();

    encrypted
        .append_commit_write(CommitWrite::new(record(tx_id, "release-candidate")))
        .await
        .expect("append encrypted named rollback point");

    let persisted = persistence
        .load_rollback(PersistRollbackTarget::ByLabel(
            "release-candidate".to_owned(),
        ))
        .await
        .expect("load persisted named rollback point");
    assert_eq!(tx_id, persisted.record.tx_id);
    assert!(persisted.record.rollback_point);
    assert_eq!(1, persisted.audit.len());
    assert_eq!("/", persisted.audit[0].yang_path);
    assert!(persisted.audit[0].redaction_applied);
    let encoded = serde_json::to_string(&persisted).expect("persisted fixture JSON");
    assert!(!encoded.contains("ciphertext-only-config"));

    let restored = encrypted
        .load_rollback(RollbackTarget::Label("release-candidate".to_owned()))
        .await
        .expect("restore named rollback point");
    assert_eq!(
        Some("release-candidate"),
        restored.rollback_label.as_deref()
    );
    assert_eq!("ciphertext-only-config", restored.config.name);
}

#[test]
fn raft_adapter_port_is_statically_ciphertext_only() {
    fn assert_sealed_port<T: ManagedDatastore<SealedConfig<TestConfig>>>() {}
    fn assert_committed_source<T: CommittedRevisionSource<SealedConfig<TestConfig>>>() {}
    assert_sealed_port::<RaftManagedDatastore<TestConfig>>();
    assert_committed_source::<RaftManagedDatastore<TestConfig>>();
}

#[tokio::test]
async fn unavailable_persistence_maps_to_retryable_store_error() {
    #[derive(Debug)]
    struct UnavailableStore;

    #[async_trait::async_trait]
    impl ConfigStore for UnavailableStore {
        async fn load_latest(
            &self,
        ) -> Result<Option<opc_persist::StoredConfig>, opc_persist::PersistError> {
            Err(opc_persist::PersistError::unavailable())
        }

        async fn load_rollback(
            &self,
            _target: PersistRollbackTarget,
        ) -> Result<opc_persist::StoredConfig, opc_persist::PersistError> {
            Err(opc_persist::PersistError::unavailable())
        }

        async fn append_commit(
            &self,
            _record: opc_persist::CommitRecord,
            _audit: Vec<opc_persist::AuditRecord>,
        ) -> Result<(), opc_persist::PersistError> {
            Err(opc_persist::PersistError::unavailable())
        }

        async fn mark_confirmed(&self, _tx_id: TxId) -> Result<(), opc_persist::PersistError> {
            Err(opc_persist::PersistError::unavailable())
        }

        async fn create_rollback_point(
            &self,
            _tx_id: TxId,
            _label: Option<String>,
        ) -> Result<(), opc_persist::PersistError> {
            Err(opc_persist::PersistError::unavailable())
        }

        async fn preflight(
            &self,
        ) -> Result<opc_persist::PersistCapabilities, opc_persist::PersistError> {
            Err(opc_persist::PersistError::unavailable())
        }
    }

    let adapter = PersistManagedDatastore::<TestConfig, _>::new(Arc::new(UnavailableStore));
    let error = match adapter.load_latest().await {
        Ok(_) => panic!("unavailable backend must fail closed"),
        Err(error) => error,
    };
    assert_eq!(StoreErrorCode::Unavailable, error.code);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn promoted_follower_reconciles_the_live_bus_before_writing() {
    let cluster = ProjectionCluster::start().await;
    let original_leader = cluster.leader();
    let sources = cluster
        .stores
        .iter()
        .map(|store| {
            Arc::new(EncryptingManagedDatastore::new(
                Arc::new(RaftManagedDatastore::<TestConfig>::new_local_authority(
                    Arc::clone(store),
                )),
                provider(),
            ))
        })
        .collect::<Vec<_>>();

    let genesis_tx = TxId::new();
    sources[original_leader]
        .append_commit(projection_record(genesis_tx, None, 1, "revision-one"))
        .await
        .expect("leader appends revision one");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut caught_up = true;
            for source in &sources {
                caught_up &= source
                    .load_committed_latest()
                    .await
                    .expect("load revision one")
                    .is_some_and(|stored| stored.version == ConfigVersion::new(1));
            }
            if caught_up {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("revision one reaches every applied state machine");

    let follower = (0..cluster.stores.len())
        .find(|index| *index != original_leader)
        .expect("projection cluster follower");
    let rejected = sources[follower]
        .append_commit(projection_record(
            TxId::new(),
            Some(genesis_tx),
            2,
            "forwarding-is-forbidden",
        ))
        .await
        .expect_err("Raft config-bus adapter must not forward follower writes");
    assert_eq!(StoreErrorCode::Unavailable, rejected.code);
    assert_eq!(
        Some(genesis_tx),
        sources[original_leader]
            .load_committed_latest()
            .await
            .expect("load unchanged durable head")
            .map(|stored| stored.tx_id)
    );

    let mut projections = Vec::new();
    for (store, source) in cluster.stores.iter().zip(&sources) {
        let bus = Arc::new(
            ConfigBus::restore_or_new_dev_only(
                TestConfig {
                    name: "unused-fallback".to_owned(),
                },
                Arc::clone(source),
            )
            .await
            .expect("restore one live bus per voter"),
        );
        projections.push(ConsensusConfigBusProjection::new(
            bus,
            Arc::clone(source),
            ConsensusConfigAuthority::new(Arc::clone(store)),
        ));
    }

    let revision_two_tx = TxId::new();
    sources[original_leader]
        .append_commit(projection_record(
            revision_two_tx,
            Some(genesis_tx),
            2,
            "revision-two",
        ))
        .await
        .expect("leader advances the durable head behind live projections");
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let mut caught_up = true;
            for source in &sources {
                caught_up &= source
                    .load_committed_latest()
                    .await
                    .expect("load revision two")
                    .is_some_and(|stored| stored.version == ConfigVersion::new(2));
            }
            if caught_up {
                return;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("revision two reaches every durable follower");
    assert!(projections
        .iter()
        .all(|projection| projection.bus().version() == ConfigVersion::new(1)));

    let original_leader_id = cluster.stores[original_leader].status().node_id;
    cluster.isolate(original_leader);
    cluster.stores[original_leader]
        .shutdown()
        .await
        .expect("stop original leader before survivor election");
    let promoted = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let promoted = cluster
                .stores
                .iter()
                .enumerate()
                .filter(|(index, _)| *index != original_leader)
                .find(|(_, store)| {
                    store
                        .status()
                        .leader_id
                        .is_some_and(|leader| leader != original_leader_id)
                        && store.status().leader_id == Some(store.status().node_id)
                })
                .map(|(index, _)| index);
            if let Some(promoted) = promoted {
                return promoted;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "surviving quorum failed to elect a new leader: {:?}",
            cluster
                .stores
                .iter()
                .map(|store| store.status())
                .collect::<Vec<_>>()
        )
    });

    let reconciled = projections[promoted]
        .reconcile_and_open()
        .await
        .expect("promoted follower reconciles without rebuilding the bus");
    assert_eq!(reconciled.tx_id(), Some(revision_two_tx));
    assert_eq!(reconciled.version(), ConfigVersion::new(2));
    assert_eq!(projections[promoted].bus().load().name, "revision-two");

    projections[promoted]
        .bus()
        .submit(
            CommitRequest::new(
                RequestId::new(),
                principal(),
                TransportType::Internal,
                RequestSource::Internal,
                ConfigOperation::Replace,
                CommitMode::Commit,
                Instant::now() + Duration::from_secs(5),
                Some(TestConfig {
                    name: "revision-three".to_owned(),
                }),
                Vec::new(),
            )
            .with_base_version(ConfigVersion::new(2)),
        )
        .await
        .expect("promoted reconciled bus commits revision three");
    assert_eq!(projections[promoted].bus().version(), ConfigVersion::new(3));

    let rejected = projections[original_leader]
        .bus()
        .submit(
            CommitRequest::new(
                RequestId::new(),
                principal(),
                TransportType::Internal,
                RequestSource::Internal,
                ConfigOperation::Replace,
                CommitMode::Commit,
                Instant::now() + Duration::from_secs(5),
                Some(TestConfig {
                    name: "isolated-writer".to_owned(),
                }),
                Vec::new(),
            )
            .with_base_version(ConfigVersion::new(1)),
        )
        .await
        .expect_err("deposed authority fails closed before mutation");
    assert_eq!(
        rejected.code,
        opc_config_model::CommitErrorCode::AdmissionRejected
    );

    cluster.shutdown().await;
}
