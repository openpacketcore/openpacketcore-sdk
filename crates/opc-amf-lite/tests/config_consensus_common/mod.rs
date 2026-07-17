#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigNodeLifecycle {
    Running,
    Stopping,
    Stopped,
    ReopeningDisconnected,
    ReopenedDisconnected,
    Reconnecting,
    Finalizing,
    Shutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigClusterLifecycleError {
    InvalidNode,
    InvalidState {
        expected: ConfigNodeLifecycle,
        actual: ConfigNodeLifecycle,
    },
    TransportStillConnected,
    DeadlineExceeded(&'static str),
    OperationFailed(&'static str),
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

    async fn uninstall(&self) {
        *self.handler.write().await = None;
    }

    fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Release);
    }

    fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire)
    }

    async fn has_handler(&self) -> bool {
        self.handler.read().await.is_some()
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
    root: PathBuf,
    identity: ConfigConsensusIdentity,
    nodes: [ConfigConsensusNodeId; 3],
    lifecycle: [ConfigNodeLifecycle; 3],
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
            root: root.to_path_buf(),
            identity,
            nodes,
            lifecycle: [ConfigNodeLifecycle::Running; 3],
            paths,
            captured_frames,
        };
        cluster.wait_ready().await;
        cluster
    }

    pub const fn identity(&self) -> ConfigConsensusIdentity {
        self.identity
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

    pub fn database_path(&self, node: usize) -> PathBuf {
        self.root.join(format!("config-{node}.sqlite"))
    }

    pub fn node_lifecycle(
        &self,
        node: usize,
    ) -> Result<ConfigNodeLifecycle, ConfigClusterLifecycleError> {
        self.lifecycle
            .get(node)
            .copied()
            .ok_or(ConfigClusterLifecycleError::InvalidNode)
    }

    fn require_node_lifecycle(
        &self,
        node: usize,
        expected: ConfigNodeLifecycle,
    ) -> Result<(), ConfigClusterLifecycleError> {
        let actual = self.node_lifecycle(node)?;
        if actual != expected {
            return Err(ConfigClusterLifecycleError::InvalidState { expected, actual });
        }
        Ok(())
    }

    fn set_node_lifecycle(
        &mut self,
        node: usize,
        next: ConfigNodeLifecycle,
    ) -> Result<(), ConfigClusterLifecycleError> {
        *self
            .lifecycle
            .get_mut(node)
            .ok_or(ConfigClusterLifecycleError::InvalidNode)? = next;
        Ok(())
    }

    async fn disconnect_node_transport(&self, node: usize) {
        for peer in 0..self.stores.len() {
            if peer != node {
                self.paths
                    .get(&(node, peer))
                    .expect("outbound cluster path")
                    .set_enabled(false);
                let inbound = self.paths.get(&(peer, node)).expect("inbound cluster path");
                inbound.set_enabled(false);
                inbound.uninstall().await;
            }
        }
    }

    async fn inspect_node_transport_disconnected(&self, node: usize) -> bool {
        for peer in 0..self.stores.len() {
            if peer != node {
                let outbound = self
                    .paths
                    .get(&(node, peer))
                    .expect("outbound cluster path");
                let inbound = self.paths.get(&(peer, node)).expect("inbound cluster path");
                if outbound.is_enabled() || inbound.is_enabled() || inbound.has_handler().await {
                    return false;
                }
            }
        }
        true
    }

    pub async fn node_transport_is_disconnected(
        &self,
        node: usize,
    ) -> Result<bool, ConfigClusterLifecycleError> {
        self.node_lifecycle(node)?;
        tokio::time::timeout(
            cluster_transition_timeout(),
            self.inspect_node_transport_disconnected(node),
        )
        .await
        .map_err(|_| ConfigClusterLifecycleError::DeadlineExceeded("transport-state inspection"))
    }

    async fn require_node_transport_disconnected(
        &self,
        node: usize,
        operation: &'static str,
    ) -> Result<(), ConfigClusterLifecycleError> {
        match self.node_transport_is_disconnected(node).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(ConfigClusterLifecycleError::TransportStillConnected),
            Err(ConfigClusterLifecycleError::DeadlineExceeded(_)) => {
                Err(ConfigClusterLifecycleError::DeadlineExceeded(operation))
            }
            Err(error) => Err(error),
        }
    }

    pub async fn stop_node(&mut self, node: usize) -> Result<(), ConfigClusterLifecycleError> {
        self.require_node_lifecycle(node, ConfigNodeLifecycle::Running)?;
        self.set_node_lifecycle(node, ConfigNodeLifecycle::Stopping)?;
        let result = tokio::time::timeout(cluster_transition_timeout(), async {
            self.disconnect_node_transport(node).await;
            self.stores[node]
                .shutdown()
                .await
                .map_err(|_| ConfigClusterLifecycleError::OperationFailed("node shutdown"))
        })
        .await;
        match result {
            Ok(Ok(())) => {
                self.set_node_lifecycle(node, ConfigNodeLifecycle::Stopped)?;
                Ok(())
            }
            Ok(Err(error)) => Err(error),
            Err(_) => Err(ConfigClusterLifecycleError::DeadlineExceeded(
                "node shutdown",
            )),
        }
    }

    pub async fn reopen_node_disconnected(
        &mut self,
        node: usize,
    ) -> Result<(), ConfigClusterLifecycleError> {
        self.require_node_lifecycle(node, ConfigNodeLifecycle::Stopped)?;
        self.set_node_lifecycle(node, ConfigNodeLifecycle::ReopeningDisconnected)?;
        if let Err(error) = self
            .require_node_transport_disconnected(node, "disconnected node reopen precondition")
            .await
        {
            self.set_node_lifecycle(node, ConfigNodeLifecycle::Stopped)?;
            return Err(error);
        }
        let members = self.nodes.iter().copied().collect::<BTreeSet<_>>();
        let topology = ConfigConsensusTopology::try_new(self.identity, self.nodes[node], members)
            .expect("reopened topology");
        let database = self.database_path(node);
        let snapshots = self.root.join(format!("snapshots-{node}"));
        let peers = self
            .nodes
            .iter()
            .copied()
            .enumerate()
            .filter(|(target, _)| *target != node)
            .map(|(target, target_node)| {
                let peer = self
                    .paths
                    .get(&(node, target))
                    .expect("reopened peer path")
                    .clone();
                let peer: Arc<dyn ConsensusPeer> = peer;
                (target_node, peer)
            })
            .collect();
        let reopened = tokio::time::timeout(cluster_transition_timeout(), async {
            let backend = SqliteBackend::open_with_audit_key(
                database,
                true,
                0,
                AuditKey::new([0x55; 32]).expect("reopened audit key"),
            )
            .await
            .map_err(|_| ConfigClusterLifecycleError::OperationFailed("reopened config backend"))?;
            ConsensusConfigStore::open_with_operation_timeout(
                topology,
                backend,
                snapshots,
                peers,
                Duration::from_secs(5),
            )
            .await
            .map_err(|_| ConfigClusterLifecycleError::OperationFailed("reopened consensus store"))
        })
        .await;
        let reopened = match reopened {
            Ok(Ok(store)) => store,
            Ok(Err(error)) => {
                self.set_node_lifecycle(node, ConfigNodeLifecycle::Stopped)?;
                return Err(error);
            }
            Err(_) => {
                self.set_node_lifecycle(node, ConfigNodeLifecycle::Stopped)?;
                return Err(ConfigClusterLifecycleError::DeadlineExceeded(
                    "disconnected node reopen",
                ));
            }
        };
        if let Err(error) = self
            .require_node_transport_disconnected(node, "disconnected node reopen verification")
            .await
        {
            match tokio::time::timeout(cluster_transition_timeout(), reopened.shutdown()).await {
                Ok(Ok(())) => {
                    self.set_node_lifecycle(node, ConfigNodeLifecycle::Stopped)?;
                    return Err(error);
                }
                Ok(Err(_)) => {
                    return Err(ConfigClusterLifecycleError::OperationFailed(
                        "failed reopened-node quarantine",
                    ))
                }
                Err(_) => {
                    return Err(ConfigClusterLifecycleError::DeadlineExceeded(
                        "reopened-node quarantine",
                    ));
                }
            }
        }
        self.stores[node] = reopened;
        self.set_node_lifecycle(node, ConfigNodeLifecycle::ReopenedDisconnected)
    }

    pub async fn reconnect_node(&mut self, node: usize) -> Result<(), ConfigClusterLifecycleError> {
        self.require_node_lifecycle(node, ConfigNodeLifecycle::ReopenedDisconnected)?;
        self.set_node_lifecycle(node, ConfigNodeLifecycle::Reconnecting)?;
        if let Err(error) = self
            .require_node_transport_disconnected(node, "node reconnect precondition")
            .await
        {
            self.set_node_lifecycle(node, ConfigNodeLifecycle::ReopenedDisconnected)?;
            return Err(error);
        }
        let result = tokio::time::timeout(cluster_transition_timeout(), async {
            let handler = self.stores[node].rpc_handler();
            for peer in 0..self.stores.len() {
                if peer != node {
                    self.paths
                        .get(&(peer, node))
                        .ok_or(ConfigClusterLifecycleError::OperationFailed(
                            "missing inbound reconnect path",
                        ))?
                        .install(handler.clone())
                        .await;
                }
            }
            for peer in 0..self.stores.len() {
                if peer != node {
                    self.paths
                        .get(&(node, peer))
                        .ok_or(ConfigClusterLifecycleError::OperationFailed(
                            "missing outbound reconnect path",
                        ))?
                        .set_enabled(true);
                    self.paths
                        .get(&(peer, node))
                        .ok_or(ConfigClusterLifecycleError::OperationFailed(
                            "missing inbound reconnect path",
                        ))?
                        .set_enabled(true);
                }
            }
            self.stores[node]
                .initialize_cluster()
                .await
                .map_err(|_| ConfigClusterLifecycleError::OperationFailed("node re-admission"))
        })
        .await;
        match result {
            Ok(Ok(())) => self.set_node_lifecycle(node, ConfigNodeLifecycle::Running),
            Ok(Err(error)) => {
                if tokio::time::timeout(
                    cluster_transition_timeout(),
                    self.disconnect_node_transport(node),
                )
                .await
                .is_ok()
                {
                    self.set_node_lifecycle(node, ConfigNodeLifecycle::ReopenedDisconnected)?;
                }
                Err(error)
            }
            Err(_) => {
                if tokio::time::timeout(
                    cluster_transition_timeout(),
                    self.disconnect_node_transport(node),
                )
                .await
                .is_ok()
                {
                    self.set_node_lifecycle(node, ConfigNodeLifecycle::ReopenedDisconnected)?;
                }
                Err(ConfigClusterLifecycleError::DeadlineExceeded(
                    "node reconnect",
                ))
            }
        }
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

    pub async fn shutdown(&mut self) -> Result<(), ConfigClusterLifecycleError> {
        let mut active = [false; 3];
        for (node, is_active) in active.iter_mut().enumerate().take(self.stores.len()) {
            let state = self.node_lifecycle(node)?;
            match state {
                ConfigNodeLifecycle::Running | ConfigNodeLifecycle::ReopenedDisconnected => {
                    *is_active = true;
                }
                ConfigNodeLifecycle::Stopped | ConfigNodeLifecycle::Shutdown => {}
                actual => {
                    return Err(ConfigClusterLifecycleError::InvalidState {
                        expected: ConfigNodeLifecycle::Running,
                        actual,
                    });
                }
            }
        }
        for (node, is_active) in active.iter().copied().enumerate() {
            if is_active {
                self.set_node_lifecycle(node, ConfigNodeLifecycle::Finalizing)?;
            }
        }
        let result = tokio::time::timeout(cluster_transition_timeout(), async {
            tokio::join!(
                async {
                    if active[0] {
                        self.stores[0].shutdown().await
                    } else {
                        Ok(())
                    }
                },
                async {
                    if active[1] {
                        self.stores[1].shutdown().await
                    } else {
                        Ok(())
                    }
                },
                async {
                    if active[2] {
                        self.stores[2].shutdown().await
                    } else {
                        Ok(())
                    }
                },
            )
        })
        .await;
        let outcomes = match result {
            Ok(outcomes) => outcomes,
            Err(_) => {
                return Err(ConfigClusterLifecycleError::DeadlineExceeded(
                    "final shutdown",
                ))
            }
        };
        let mut first_error = None;
        for (node, outcome) in [outcomes.0, outcomes.1, outcomes.2].into_iter().enumerate() {
            if active[node] {
                if outcome.is_ok() {
                    self.set_node_lifecycle(node, ConfigNodeLifecycle::Shutdown)?;
                } else {
                    first_error.get_or_insert(ConfigClusterLifecycleError::OperationFailed(
                        "final shutdown",
                    ));
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}
