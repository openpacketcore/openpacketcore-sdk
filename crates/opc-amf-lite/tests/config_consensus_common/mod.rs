#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use opc_consensus::{
    ConsensusPeer, ConsensusPeerError, ConsensusRpcHandler, ConsensusWireRequest,
    ConsensusWireResponse, DURABLE_CONSENSUS_TIMING_PROFILE,
};
use opc_persist::{
    AuditKey, ConfigConsensusClusterId, ConfigConsensusConfigurationEpoch,
    ConfigConsensusConfigurationId, ConfigConsensusIdentity, ConfigConsensusNodeId,
    ConfigConsensusTopology, ConsensusConfigStore, SqliteBackend,
};

pub(super) fn cluster_transition_timeout() -> Duration {
    let profile = DURABLE_CONSENSUS_TIMING_PROFILE;
    // Admit one complete resampled election after a split vote, followed by
    // one complete profiled durable-readiness operation. This is a bounded
    // test-evidence ceiling derived from the shared timing authority, not an
    // operator-tunable production deadline.
    Duration::from_millis(profile.election_timeout_max_millis.saturating_mul(2))
        .saturating_add(profile.operation_timeout())
}

#[derive(Clone)]
struct LoopbackPeer {
    target: ConfigConsensusNodeId,
    handler: Arc<tokio::sync::RwLock<Option<Arc<dyn ConsensusRpcHandler>>>>,
    enabled: Arc<AtomicBool>,
    captured_frames: Arc<StdMutex<Vec<Vec<u8>>>>,
}

impl LoopbackPeer {
    fn new(target: ConfigConsensusNodeId, captured_frames: Arc<StdMutex<Vec<Vec<u8>>>>) -> Self {
        Self {
            target,
            handler: Arc::new(tokio::sync::RwLock::new(None)),
            enabled: Arc::new(AtomicBool::new(true)),
            captured_frames,
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
        if !self.enabled.load(Ordering::Acquire) {
            return Err(ConsensusPeerError::Unavailable);
        }
        self.captured_frames.lock().expect("capture mutex").push(
            opc_consensus::encode_bounded(&request).map_err(|_| ConsensusPeerError::Protocol)?,
        );
        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(ConsensusPeerError::Unavailable)?;
        Ok(handler.handle(request.sender, request).await)
    }
}

pub struct ConfigCluster {
    pub stores: Vec<ConsensusConfigStore>,
    paths: BTreeMap<(usize, usize), Arc<LoopbackPeer>>,
    captured_frames: Arc<StdMutex<Vec<Vec<u8>>>>,
}

impl ConfigCluster {
    pub async fn start(root: &Path) -> Self {
        let nodes = [1_u64, 2, 3].map(|value| ConfigConsensusNodeId::new(value).expect("node ID"));
        let members = nodes.into_iter().collect::<BTreeSet<_>>();
        let identity = ConfigConsensusIdentity::new(
            ConfigConsensusClusterId::new("amf-config-encryption-openraft").expect("cluster ID"),
            ConfigConsensusConfigurationId::from_bytes([0xA7; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("configuration epoch"),
        );
        let topologies = nodes.map(|node| {
            ConfigConsensusTopology::try_new(identity, node, members.clone()).expect("topology")
        });
        let captured_frames = Arc::new(StdMutex::new(Vec::new()));
        let mut paths = BTreeMap::new();
        for source in 0..3 {
            for (target, target_node) in nodes.iter().copied().enumerate() {
                if source != target {
                    paths.insert(
                        (source, target),
                        Arc::new(LoopbackPeer::new(target_node, captured_frames.clone())),
                    );
                }
            }
        }

        let mut stores = Vec::new();
        for (index, topology) in topologies.iter().cloned().enumerate() {
            let backend = SqliteBackend::open_with_audit_key(
                root.join(format!("config-{index}.sqlite")),
                true,
                0,
                AuditKey::new([0x55; 32]).expect("audit key"),
            )
            .await
            .expect("config backend");
            let peers = (0..3)
                .filter(|target| *target != index)
                .map(|target| {
                    let peer: Arc<dyn ConsensusPeer> =
                        paths.get(&(index, target)).expect("peer path").clone();
                    (nodes[target], peer)
                })
                .collect();
            stores.push(
                ConsensusConfigStore::open_with_operation_timeout(
                    topology,
                    backend,
                    root.join(format!("snapshots-{index}")),
                    peers,
                    Duration::from_secs(5),
                )
                .await
                .expect("consensus store"),
            );
        }
        for ((_, target), path) in &paths {
            path.install(stores[*target].rpc_handler()).await;
        }
        let (one, two, three) = tokio::join!(
            stores[0].initialize_cluster(),
            stores[1].initialize_cluster(),
            stores[2].initialize_cluster(),
        );
        one.expect("initialize node one");
        two.expect("initialize node two");
        three.expect("initialize node three");
        let cluster = Self {
            stores,
            paths,
            captured_frames,
        };
        cluster.wait_ready().await;
        cluster
    }

    pub async fn wait_ready(&self) {
        tokio::time::timeout(cluster_transition_timeout(), async {
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
        .expect("config cluster ready");
    }

    pub fn leader(&self) -> usize {
        let leader = self
            .stores
            .iter()
            .find_map(|store| store.status().leader_id)
            .expect("known config leader");
        self.stores
            .iter()
            .position(|store| store.status().node_id == leader)
            .expect("config leader index")
    }

    pub fn captured_frames(&self) -> Vec<Vec<u8>> {
        self.captured_frames.lock().expect("capture mutex").clone()
    }

    pub fn isolate(&self, node: usize) {
        for peer in 0..self.stores.len() {
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

    pub async fn wait_for_survivor_leader(&self, excluded: usize) -> usize {
        tokio::time::timeout(cluster_transition_timeout(), async {
            loop {
                if let Some(index) = (0..self.stores.len()).find(|index| {
                    *index != excluded
                        && self.stores[*index]
                            .status()
                            .leader_id
                            .is_some_and(|leader| leader != self.stores[excluded].status().node_id)
                }) {
                    if self.stores[index].probe_durable_readiness().await.is_ok() {
                        return index;
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("survivor config leader")
    }

    pub async fn shutdown(&self) {
        let _ = tokio::join!(
            self.stores[0].shutdown(),
            self.stores[1].shutdown(),
            self.stores[2].shutdown(),
        );
    }
}
