#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use async_trait::async_trait;
use opc_consensus::engine::raft::{VoteRequest, VoteResponse};
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
    // Preserve the bounded fixture ceiling derived from the shared timing
    // authority. Random election retries have no fixed upper bound; fixtures
    // that force a split schedule the follow-up campaign explicitly within
    // this ceiling. This is not an operator-tunable production deadline.
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

#[derive(Clone, Debug, Default)]
struct SplitVoteProgress {
    votes: BTreeMap<ConfigConsensusNodeId, VoteRequest<ConfigConsensusNodeId>>,
    rejected: usize,
    failure: Option<String>,
}

pub struct SplitVoteGate {
    requests: tokio::sync::Barrier,
    progress: tokio::sync::watch::Sender<SplitVoteProgress>,
}

impl SplitVoteGate {
    fn new() -> Self {
        Self {
            requests: tokio::sync::Barrier::new(2),
            progress: tokio::sync::watch::channel(SplitVoteProgress::default()).0,
        }
    }

    fn record_vote(
        &self,
        sender: ConfigConsensusNodeId,
        vote: VoteRequest<ConfigConsensusNodeId>,
    ) -> Result<(), &'static str> {
        let mut duplicate = false;
        self.progress
            .send_modify(|progress| match progress.votes.entry(sender) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(vote);
                }
                std::collections::btree_map::Entry::Occupied(_) => duplicate = true,
            });
        if duplicate {
            Err("one initial vote per survivor")
        } else {
            Ok(())
        }
    }

    fn fail(&self, error: String) {
        eprintln!("HA_SPLIT_FAILURE {error}");
        self.progress.send_modify(|progress| {
            progress.failure.get_or_insert(error);
        });
    }

    async fn wait_for_rejections(&self) -> Result<SplitVoteProgress, String> {
        let mut progress = self.progress.subscribe();
        let observed = progress
            .wait_for(|progress| progress.failure.is_some() || progress.rejected == 2)
            .await
            .map_err(|error| format!("split vote observation closed: {error}"))?;
        match &observed.failure {
            Some(error) => Err(error.clone()),
            None => Ok(observed.clone()),
        }
    }
}

struct SplitVoteAttempt {
    gate: Arc<SplitVoteGate>,
    sender: ConfigConsensusNodeId,
    target: ConfigConsensusNodeId,
    started: std::time::Instant,
    phase: &'static str,
    completed: bool,
}

impl SplitVoteAttempt {
    fn new(
        gate: Arc<SplitVoteGate>,
        sender: ConfigConsensusNodeId,
        target: ConfigConsensusNodeId,
    ) -> Self {
        Self {
            gate,
            sender,
            target,
            started: std::time::Instant::now(),
            phase: "request decode",
            completed: false,
        }
    }

    fn fail(&mut self, error: impl fmt::Display) {
        self.completed = true;
        self.gate.fail(format!(
            "sender={:?} target={:?} phase={} elapsed_ms={}: {error}",
            self.sender,
            self.target,
            self.phase,
            self.started.elapsed().as_millis(),
        ));
    }
}

impl Drop for SplitVoteAttempt {
    fn drop(&mut self) {
        if !self.completed {
            // Barrier arrivals are not withdrawn when the engine's vote RPC
            // deadline cancels this future. Wake the test waiter immediately.
            self.fail("initial vote RPC cancelled");
        }
    }
}

#[derive(Clone)]
struct LoopbackPeer {
    target: ConfigConsensusNodeId,
    handler: Arc<tokio::sync::RwLock<Option<Arc<dyn ConsensusRpcHandler>>>>,
    enabled: Arc<AtomicBool>,
    captured_frames: Arc<StdMutex<Vec<Vec<u8>>>>,
    first_vote_gate: Arc<StdMutex<Option<Arc<SplitVoteGate>>>>,
}

impl LoopbackPeer {
    fn new(target: ConfigConsensusNodeId, captured_frames: Arc<StdMutex<Vec<Vec<u8>>>>) -> Self {
        Self {
            target,
            handler: Arc::new(tokio::sync::RwLock::new(None)),
            enabled: Arc::new(AtomicBool::new(true)),
            captured_frames,
            first_vote_gate: Arc::new(StdMutex::new(None)),
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
        let vote_sender =
            (request.family == opc_consensus::ConsensusRpcFamily::Vote).then_some(request.sender);
        let mut first_vote = None;
        if let Some(sender) = vote_sender {
            first_vote = self
                .first_vote_gate
                .lock()
                .expect("vote gate")
                .take()
                .map(|gate| SplitVoteAttempt::new(gate, sender, self.target));
            let vote = opc_consensus::decode_bounded::<(u16, VoteRequest<ConfigConsensusNodeId>)>(
                &request.payload,
            )
            .map(|(_, vote)| vote);
            eprintln!(
                "HA_VOTE sender={sender:?} target={:?} request={vote:?}",
                self.target
            );
            if let Some(attempt) = &mut first_vote {
                match vote {
                    Ok(vote) => match attempt.gate.record_vote(sender, vote) {
                        Ok(()) => {
                            attempt.phase = "split barrier";
                            attempt.gate.requests.wait().await;
                        }
                        Err(error) => attempt.fail(error),
                    },
                    Err(error) => attempt.fail(format!("decode diagnostic vote: {error:?}")),
                }
            }
        }
        if let Some(attempt) = &mut first_vote {
            attempt.phase = "vote handler";
        }
        let Some(handler) = self.handler.read().await.clone() else {
            if let Some(attempt) = &mut first_vote {
                attempt.fail("first survivor vote has no handler");
            }
            return Err(ConsensusPeerError::Unavailable);
        };
        let response = handler.handle(request.sender, request).await;
        if let Some(sender) = vote_sender {
            type Reply = Result<
                VoteResponse<ConfigConsensusNodeId>,
                opc_consensus::engine::error::RaftError<ConfigConsensusNodeId>,
            >;
            let reply = response
                .result
                .as_ref()
                .map_err(|error| format!("first survivor vote peer error: {error:?}"))
                .and_then(|payload| {
                    let (_, reply): (u16, Reply) = opc_consensus::decode_bounded(payload)
                        .map_err(|error| format!("decode diagnostic vote reply: {error:?}"))?;
                    reply.map_err(|error| format!("first survivor vote engine error: {error:?}"))
                });
            eprintln!(
                "HA_VOTE_REPLY sender={sender:?} target={:?} reply={reply:?}",
                self.target
            );
            if let Some(attempt) = first_vote.as_mut().filter(|attempt| !attempt.completed) {
                match reply {
                    Ok(vote) if !vote.vote_granted => {
                        attempt.completed = true;
                        attempt
                            .gate
                            .progress
                            .send_modify(|progress| progress.rejected += 1);
                    }
                    Ok(_) => attempt.fail("both survivors must have voted for themselves"),
                    Err(error) => attempt.fail(error),
                }
            }
        }
        Ok(response)
    }
}

pub struct ConfigCluster {
    pub stores: Vec<ConsensusConfigStore>,
    root: PathBuf,
    identity: ConfigConsensusIdentity,
    nodes: [ConfigConsensusNodeId; 3],
    lifecycle: [ConfigNodeLifecycle; 3],
    disconnected_backends: [Option<SqliteBackend>; 3],
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
            disconnected_backends: [None, None, None],
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

    pub fn disconnected_backend(
        &self,
        node: usize,
    ) -> Result<SqliteBackend, ConfigClusterLifecycleError> {
        self.require_node_lifecycle(node, ConfigNodeLifecycle::ReopenedDisconnected)?;
        self.disconnected_backends[node].clone().ok_or(
            ConfigClusterLifecycleError::OperationFailed("missing disconnected backend"),
        )
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
        let stopped_status = self.stores[node].status();
        let expected_applied_index = stopped_status.applied_index;
        let expected_committed_index = stopped_status.committed_index;
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
            let retained_backend = backend.clone();
            let store = ConsensusConfigStore::open_with_operation_timeout(
                topology,
                backend,
                snapshots,
                peers,
                Duration::from_secs(5),
            )
            .await
            .map_err(|_| {
                ConfigClusterLifecycleError::OperationFailed("reopened consensus store")
            })?;
            Ok((store, retained_backend))
        })
        .await;
        let (reopened, retained_backend) = match reopened {
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
        if !tokio::time::timeout(
            cluster_transition_timeout(),
            reopened.wait_for_raft_status_for_test(|status| {
                status.applied_index == expected_applied_index
                    && status.committed_index == expected_committed_index
            }),
        )
        .await
        .is_ok_and(|result| result.is_ok())
        {
            match tokio::time::timeout(cluster_transition_timeout(), reopened.shutdown()).await {
                Ok(Ok(())) => {
                    self.set_node_lifecycle(node, ConfigNodeLifecycle::Stopped)?;
                    return Err(ConfigClusterLifecycleError::DeadlineExceeded(
                        "reopened durable-status restoration",
                    ));
                }
                Ok(Err(_)) => {
                    return Err(ConfigClusterLifecycleError::OperationFailed(
                        "failed reopened-node quarantine",
                    ));
                }
                Err(_) => {
                    return Err(ConfigClusterLifecycleError::DeadlineExceeded(
                        "reopened-node quarantine",
                    ));
                }
            }
        }
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
        self.disconnected_backends[node] = Some(retained_backend);
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
            Ok(Ok(())) => {
                self.disconnected_backends[node] = None;
                self.set_node_lifecycle(node, ConfigNodeLifecycle::Running)
            }
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

    pub fn prepare_survivor_split_vote(&self, node: usize) -> Arc<SplitVoteGate> {
        let survivors = (0..self.stores.len())
            .filter(|index| *index != node)
            .collect::<Vec<_>>();
        assert_eq!(survivors.len(), 2);
        let gate = Arc::new(SplitVoteGate::new());
        for (source, target) in [(survivors[0], survivors[1]), (survivors[1], survivors[0])] {
            *self.paths[&(source, target)]
                .first_vote_gate
                .lock()
                .expect("vote gate") = Some(gate.clone());
        }
        gate
    }

    pub async fn wait_for_survivor_after_split(
        &self,
        excluded: usize,
        split: Arc<SplitVoteGate>,
    ) -> usize {
        let deadline = tokio::time::Instant::now() + cluster_transition_timeout();
        tokio::time::timeout_at(deadline, async {
            let split_progress = split.wait_for_rejections().await.unwrap_or_else(|error| {
                panic!(
                    "split survivor election: {error}; state={:?}",
                    split.progress.borrow()
                )
            });
            // This fixture proves recovery through a real elected quorum.
            // Force the split first, then start one normal campaign rather
            // than letting repeated random election samples decide whether
            // the AMF recovery assertions run before their unchanged deadline.
            // The engine still owns the vote, persistence and quorum proof.
            let candidate = split_progress
                .votes
                .iter()
                .max_by_key(|(_, vote)| vote.last_log_id)
                .map(|(node, _)| *node)
                .expect("survivor with the freshest log");
            let index = self
                .nodes
                .iter()
                .position(|node| *node == candidate)
                .expect("survivor node index");
            assert_ne!(index, excluded);
            self.stores[index]
                .trigger_election_for_test()
                .await
                .expect("survivor starts a normal Openraft campaign after the split");
        })
        .await
        .unwrap_or_else(|error| {
            panic!(
                "split survivor election: {error}; state={:?}",
                split.progress.borrow(),
            )
        });
        self.wait_for_survivor_leader_until(excluded, deadline)
            .await
    }

    async fn wait_for_survivor_leader_until(
        &self,
        excluded: usize,
        deadline: tokio::time::Instant,
    ) -> usize {
        let started = std::time::Instant::now();
        let mut last_status = None;
        let mut last_readiness = None;
        tokio::time::timeout_at(deadline, async {
            loop {
                let statuses = self
                    .stores
                    .iter()
                    .map(|store| {
                        let status = store.status();
                        (
                            status.node_id,
                            status.term,
                            status.leader_id,
                            status.applied_index,
                            status.committed_index,
                            status.admitted,
                        )
                    })
                    .collect::<Vec<_>>();
                if last_status.as_ref() != Some(&statuses) {
                    eprintln!(
                        "HA_ELECTION elapsed_ms={} excluded={excluded} states={statuses:?}",
                        started.elapsed().as_millis()
                    );
                    last_status = Some(statuses);
                }
                if let Some(index) = (0..self.stores.len()).find(|index| {
                    *index != excluded
                        && self.stores[*index]
                            .status()
                            .leader_id
                            .is_some_and(|leader| leader != self.stores[excluded].status().node_id)
                }) {
                    match self.stores[index].probe_durable_readiness().await {
                        Ok(()) => return index,
                        Err(error) => {
                            last_readiness = Some((index, error));
                            eprintln!(
                                "HA_READINESS elapsed_ms={} result={last_readiness:?}",
                                started.elapsed().as_millis()
                            );
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|error| {
            panic!(
                "survivor config leader: {error}; states={last_status:?}; readiness={last_readiness:?}"
            )
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use opc_consensus::engine::Vote;

    #[derive(Debug)]
    struct RecordingHandler {
        response: ConsensusWireResponse,
        requests: StdMutex<Vec<(ConfigConsensusNodeId, ConsensusWireRequest)>>,
    }

    #[async_trait]
    impl ConsensusRpcHandler for RecordingHandler {
        async fn handle(
            &self,
            sender: ConfigConsensusNodeId,
            request: ConsensusWireRequest,
        ) -> ConsensusWireResponse {
            self.requests
                .lock()
                .expect("record requests")
                .push((sender, request));
            self.response.clone()
        }
    }

    fn vote_request(payload: Vec<u8>) -> ConsensusWireRequest {
        ConsensusWireRequest::try_new(
            opc_consensus::ConsensusIdentity::new(
                opc_consensus::ConsensusClusterId::from_bytes([1; 32]),
                opc_consensus::ConsensusConfigurationId::from_bytes([2; 32]),
                opc_consensus::ConsensusConfigurationEpoch::new(1).expect("epoch"),
            ),
            ConfigConsensusNodeId::new(1).expect("sender"),
            opc_consensus::ConsensusRpcFamily::Vote,
            payload,
        )
        .expect("bounded vote request")
    }

    fn valid_vote_request() -> ConsensusWireRequest {
        let sender = ConfigConsensusNodeId::new(1).expect("sender");
        vote_request(
            opc_consensus::encode_bounded(&(1_u16, VoteRequest::new(Vote::new(2, sender), None)))
                .expect("encode vote request"),
        )
    }

    fn vote_response(granted: bool) -> ConsensusWireResponse {
        let target = ConfigConsensusNodeId::new(2).expect("target");
        let reply: Result<_, opc_consensus::engine::error::RaftError<ConfigConsensusNodeId>> =
            Ok(VoteResponse::new(Vote::new(2, target), None, granted));
        ConsensusWireResponse {
            result: Ok(opc_consensus::encode_bounded(&(1_u16, reply)).expect("encode vote reply")),
        }
    }

    async fn peer_with_response(
        response: ConsensusWireResponse,
    ) -> (LoopbackPeer, Arc<RecordingHandler>) {
        let handler = Arc::new(RecordingHandler {
            response,
            requests: StdMutex::new(Vec::new()),
        });
        let peer = LoopbackPeer::new(
            ConfigConsensusNodeId::new(2).expect("target"),
            Arc::new(StdMutex::new(Vec::new())),
        );
        peer.install(handler.clone()).await;
        (peer, handler)
    }

    #[tokio::test]
    async fn malformed_vote_diagnostics_preserve_request_delivery() {
        let expected = vote_response(false);
        let (peer, handler) = peer_with_response(expected.clone()).await;
        let request = vote_request(Vec::new());
        assert_eq!(
            peer.call(request.clone()).await.expect("deliver request"),
            expected
        );
        assert_eq!(
            *handler.requests.lock().expect("recorded requests"),
            vec![(request.sender, request)],
        );
    }

    #[tokio::test]
    async fn malformed_vote_diagnostics_preserve_response_delivery() {
        let expected = ConsensusWireResponse {
            result: Ok(Vec::new()),
        };
        let (peer, handler) = peer_with_response(expected.clone()).await;
        let request = valid_vote_request();
        assert_eq!(
            peer.call(request.clone()).await.expect("deliver response"),
            expected
        );
        assert_eq!(
            *handler.requests.lock().expect("recorded requests"),
            vec![(request.sender, request)],
        );
    }

    async fn split_failure(gate: &SplitVoteGate) -> String {
        tokio::time::timeout(Duration::from_secs(1), gate.wait_for_rejections())
            .await
            .expect("split failure must wake the waiter without the election deadline")
            .expect_err("split vote must fail")
    }

    #[tokio::test]
    async fn split_vote_request_decode_failure_wakes_waiter() {
        let expected = vote_response(false);
        let (peer, handler) = peer_with_response(expected.clone()).await;
        let gate = Arc::new(SplitVoteGate::new());
        *peer.first_vote_gate.lock().expect("vote gate") = Some(gate.clone());
        let request = vote_request(Vec::new());
        assert_eq!(
            peer.call(request.clone()).await.expect("deliver request"),
            expected,
        );
        assert!(split_failure(&gate)
            .await
            .contains("decode diagnostic vote"));
        assert_eq!(
            *handler.requests.lock().expect("recorded requests"),
            vec![(request.sender, request)],
        );
    }

    #[tokio::test]
    async fn split_vote_reply_failures_wake_waiter() {
        let engine_error: Result<
            VoteResponse<ConfigConsensusNodeId>,
            opc_consensus::engine::error::RaftError<ConfigConsensusNodeId>,
        > = Err(opc_consensus::engine::error::RaftError::Fatal(
            opc_consensus::engine::error::Fatal::Stopped,
        ));
        for (expected, message) in [
            (
                vote_response(true),
                "both survivors must have voted for themselves",
            ),
            (
                ConsensusWireResponse {
                    result: Err(ConsensusPeerError::Protocol),
                },
                "peer error: Protocol",
            ),
            (
                ConsensusWireResponse {
                    result: Ok(Vec::new()),
                },
                "decode diagnostic vote reply",
            ),
            (
                ConsensusWireResponse {
                    result: Ok(opc_consensus::encode_bounded(&(1_u16, engine_error))
                        .expect("encode engine error")),
                },
                "engine error:",
            ),
        ] {
            let (peer, handler) = peer_with_response(expected.clone()).await;
            let gate = Arc::new(SplitVoteGate::new());
            *peer.first_vote_gate.lock().expect("vote gate") = Some(gate.clone());
            let request = valid_vote_request();
            let (response, _) = tokio::time::timeout(Duration::from_secs(1), async {
                tokio::join!(peer.call(request.clone()), gate.requests.wait())
            })
            .await
            .expect("release diagnostic vote barrier");
            assert_eq!(response.expect("deliver response"), expected);
            assert!(split_failure(&gate).await.contains(message));
            assert_eq!(
                *handler.requests.lock().expect("recorded requests"),
                vec![(request.sender, request)],
            );
        }
    }

    #[tokio::test]
    async fn cancelled_split_vote_wakes_waiter() {
        let (peer, handler) = peer_with_response(vote_response(false)).await;
        let gate = Arc::new(SplitVoteGate::new());
        *peer.first_vote_gate.lock().expect("vote gate") = Some(gate.clone());
        let mut progress = gate.progress.subscribe();
        let call = tokio::spawn(async move { peer.call(valid_vote_request()).await });
        tokio::time::timeout(
            Duration::from_secs(1),
            progress.wait_for(|progress| progress.votes.len() == 1),
        )
        .await
        .expect("vote must reach split barrier")
        .expect("observe first vote");
        call.abort();
        assert!(call.await.expect_err("cancel vote call").is_cancelled());
        let error = split_failure(&gate).await;
        assert!(error.contains("initial vote RPC cancelled"), "{error}");
        assert!(error.contains("phase=split barrier"), "{error}");
        assert!(error.contains("elapsed_ms="), "{error}");
        assert!(handler
            .requests
            .lock()
            .expect("recorded requests")
            .is_empty());
    }
}
