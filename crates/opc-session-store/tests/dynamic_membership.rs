use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::future::join_all;
use opc_consensus::{
    derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
};
use opc_crypto::CryptoEnvelopeV1;
use opc_key::{
    serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyId, SessionAad, AEAD_TAG_LEN,
    AES_256_GCM_SIV_NONCE_LEN,
};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, ConsensusSessionStore, EncryptedSessionPayload, Generation,
    OwnerId, QuorumReplicaDescriptor, QuorumTopologyConfig, ReplicaBackingIdentity,
    ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity, SessionBackend,
    SessionConsensusIdentity, SessionConsensusNodeId, SessionConsensusPeer,
    SessionConsensusPeerError, SessionConsensusRpcFamily, SessionConsensusRpcHandler,
    SessionConsensusStorageAnchor, SessionConsensusWireRequest, SessionConsensusWireResponse,
    SessionKey, SessionKeyType, SessionLeaseManager, SessionTopologyAbortAdmissionProof,
    SessionTopologyCandidateBootstrap, SessionTopologyCandidateRetirementProof,
    SessionTopologyJointCommitAdmissionProof, SessionTopologyLearnersReadyAdmissionProof,
    SessionTopologyPrePrepareUnstageProof, SessionTopologyTransitionError,
    SessionTopologyTransitionId, SessionTopologyTransitionPeers, SessionTopologyTransitionPhase,
    SessionTopologyTransitionRequest, SessionTopologyTransportAdmission,
    SessionTopologyTransportAdmissionError, SessionTopologyUniformCommitAdmissionProof,
    SqliteSessionBackend, StateClass, StateType, StoredSessionRecord, ValidatedQuorumTopology,
};
use opc_types::{NetworkFunctionKind, TenantId};
use tempfile::TempDir;

const INITIAL_MEMBER_COUNT: usize = 3;
const EXPANDED_MEMBER_COUNT: usize = 5;
const STORE_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const TRANSITION_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const TEST_DEADLINE: Duration = Duration::from_secs(90);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

type LoopbackHandler = Arc<tokio::sync::RwLock<Option<Arc<dyn SessionConsensusRpcHandler>>>>;

#[derive(Clone)]
struct LoopbackPeer {
    target: SessionConsensusNodeId,
    scope: SessionConsensusIdentity,
    handler: LoopbackHandler,
    enabled: Arc<AtomicBool>,
    topology_response_drops_remaining: Arc<AtomicUsize>,
    topology_responses_dropped: Arc<AtomicUsize>,
}

impl fmt::Debug for LoopbackPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackPeer")
            .field("target", &self.target)
            .field("scope", &self.scope)
            .field("enabled", &self.enabled.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SessionConsensusPeer for LoopbackPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.target
    }

    fn scope_identity(&self) -> Option<SessionConsensusIdentity> {
        Some(self.scope)
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        if request.identity != self.scope {
            return Err(SessionConsensusPeerError::ScopeMismatch);
        }
        let family = request.family;
        let Some(handler) = self.handler.read().await.clone() else {
            return Err(SessionConsensusPeerError::Unavailable);
        };
        let response = handler.handle(request.sender, request).await;
        if family == SessionConsensusRpcFamily::TopologyAdmissionBarrier
            && self
                .topology_response_drops_remaining
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
        {
            self.topology_responses_dropped
                .fetch_add(1, Ordering::AcqRel);
            return Err(SessionConsensusPeerError::Unavailable);
        }
        Ok(response)
    }
}

struct LoopbackNetwork {
    node_ids: Vec<SessionConsensusNodeId>,
    handlers: Vec<LoopbackHandler>,
    links: Vec<Vec<Arc<AtomicBool>>>,
    topology_response_drops_remaining: Vec<Vec<Arc<AtomicUsize>>>,
    topology_responses_dropped: Vec<Vec<Arc<AtomicUsize>>>,
}

impl LoopbackNetwork {
    fn new(node_ids: Vec<SessionConsensusNodeId>) -> Self {
        let handlers = node_ids
            .iter()
            .map(|_| Arc::new(tokio::sync::RwLock::new(None)))
            .collect::<Vec<_>>();
        let links = node_ids
            .iter()
            .map(|_| {
                node_ids
                    .iter()
                    .map(|_| Arc::new(AtomicBool::new(true)))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let topology_response_drops_remaining = atomic_usize_matrix(node_ids.len());
        let topology_responses_dropped = atomic_usize_matrix(node_ids.len());
        Self {
            node_ids,
            handlers,
            links,
            topology_response_drops_remaining,
            topology_responses_dropped,
        }
    }

    async fn install(&self, index: usize, handler: Arc<dyn SessionConsensusRpcHandler>) {
        *self.handlers[index].write().await = Some(handler);
    }

    async fn retire_incarnation(&mut self, index: usize) {
        *self.handlers[index].write().await = None;
        for target in 0..self.node_ids.len() {
            if target == index {
                continue;
            }
            let retired = std::mem::replace(
                &mut self.links[index][target],
                Arc::new(AtomicBool::new(true)),
            );
            retired.store(false, Ordering::Release);
        }
    }

    fn peers_for_indices(
        &self,
        source: usize,
        scope: SessionConsensusIdentity,
        targets: impl IntoIterator<Item = usize>,
    ) -> SessionTopologyTransitionPeers {
        targets
            .into_iter()
            .filter(|target| *target != source)
            .map(|target| {
                let peer: Arc<dyn SessionConsensusPeer> = Arc::new(LoopbackPeer {
                    target: self.node_ids[target],
                    scope,
                    handler: Arc::clone(&self.handlers[target]),
                    enabled: Arc::clone(&self.links[source][target]),
                    topology_response_drops_remaining: Arc::clone(
                        &self.topology_response_drops_remaining[source][target],
                    ),
                    topology_responses_dropped: Arc::clone(
                        &self.topology_responses_dropped[source][target],
                    ),
                });
                (self.node_ids[target], peer)
            })
            .collect()
    }

    fn peers_for_request(
        &self,
        source: usize,
        request: &SessionTopologyTransitionRequest,
    ) -> SessionTopologyTransitionPeers {
        let desired = request.desired_consensus_node_ids();
        self.peers_for_indices(
            source,
            request.desired_identity(),
            self.node_ids
                .iter()
                .enumerate()
                .filter_map(|(index, node_id)| desired.contains(node_id).then_some(index)),
        )
    }

    fn isolate(&self, index: usize) {
        for peer in 0..self.node_ids.len() {
            if peer != index {
                self.links[index][peer].store(false, Ordering::Release);
                self.links[peer][index].store(false, Ordering::Release);
            }
        }
    }

    fn heal(&self, index: usize) {
        for peer in 0..self.node_ids.len() {
            if peer != index {
                self.links[index][peer].store(true, Ordering::Release);
                self.links[peer][index].store(true, Ordering::Release);
            }
        }
    }

    fn drop_next_topology_response(&self, source: usize, target: usize) {
        self.topology_response_drops_remaining[source][target].store(1, Ordering::Release);
    }

    fn dropped_topology_responses(&self, source: usize, target: usize) -> usize {
        self.topology_responses_dropped[source][target].load(Ordering::Acquire)
    }
}

fn atomic_usize_matrix(size: usize) -> Vec<Vec<Arc<AtomicUsize>>> {
    (0..size)
        .map(|_| (0..size).map(|_| Arc::new(AtomicUsize::new(0))).collect())
        .collect()
}

#[derive(Debug)]
struct RecordingTransportAdmission {
    voting_admissions: AtomicUsize,
    finalizations: AtomicUsize,
    aborts: AtomicUsize,
    block_next_finalization: AtomicBool,
    finalization_entered: AtomicBool,
    finalization_entered_notify: tokio::sync::Notify,
    finalization_release: tokio::sync::Semaphore,
}

impl Default for RecordingTransportAdmission {
    fn default() -> Self {
        Self {
            voting_admissions: AtomicUsize::new(0),
            finalizations: AtomicUsize::new(0),
            aborts: AtomicUsize::new(0),
            block_next_finalization: AtomicBool::new(false),
            finalization_entered: AtomicBool::new(false),
            finalization_entered_notify: tokio::sync::Notify::new(),
            finalization_release: tokio::sync::Semaphore::new(0),
        }
    }
}

impl RecordingTransportAdmission {
    fn voting_admissions(&self) -> usize {
        self.voting_admissions.load(Ordering::Acquire)
    }

    fn finalizations(&self) -> usize {
        self.finalizations.load(Ordering::Acquire)
    }

    fn block_next_finalization(&self) {
        assert!(
            self.block_next_finalization
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
            "a finalization block is already armed"
        );
        self.finalization_entered.store(false, Ordering::Release);
    }

    async fn wait_for_blocked_finalization(&self) {
        loop {
            let notified = self.finalization_entered_notify.notified();
            if self.finalization_entered.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    fn release_finalization(&self) {
        self.finalization_release.add_permits(1);
    }
}

#[async_trait]
impl SessionTopologyTransportAdmission for RecordingTransportAdmission {
    async fn unstage_successor_before_prepare(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyPrePrepareUnstageProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        if !proof.validates_request(request) {
            return Err(SessionTopologyTransportAdmissionError::Rejected);
        }
        Ok(())
    }

    async fn retire_aborted_candidate(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyCandidateRetirementProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        if !proof.validates_request(request) {
            return Err(SessionTopologyTransportAdmissionError::Rejected);
        }
        Ok(())
    }

    async fn admit_successor_voting(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyJointCommitAdmissionProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        if !proof.validates_request(request) {
            return Err(SessionTopologyTransportAdmissionError::Rejected);
        }
        self.voting_admissions.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    async fn finalize_successor(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyUniformCommitAdmissionProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        if !proof.validates_request(request) {
            return Err(SessionTopologyTransportAdmissionError::Rejected);
        }
        self.finalizations.fetch_add(1, Ordering::AcqRel);
        if self.block_next_finalization.swap(false, Ordering::AcqRel) {
            self.finalization_entered.store(true, Ordering::Release);
            self.finalization_entered_notify.notify_waiters();
            self.finalization_release
                .acquire()
                .await
                .map_err(|_| SessionTopologyTransportAdmissionError::Unavailable)?
                .forget();
        }
        Ok(())
    }

    async fn abort_successor(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyAbortAdmissionProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError> {
        if !proof.validates_request(request) {
            return Err(SessionTopologyTransportAdmissionError::Rejected);
        }
        self.aborts.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

struct DynamicFleet {
    _directory: TempDir,
    _backends: Vec<SqliteSessionBackend>,
    members: Vec<QuorumReplicaDescriptor>,
    stores: Vec<ConsensusSessionStore>,
    network: LoopbackNetwork,
    transports: Vec<Arc<RecordingTransportAdmission>>,
    cluster_id: ConsensusClusterId,
}

impl DynamicFleet {
    async fn start_three() -> Self {
        let directory = tempfile::tempdir().expect("create dynamic-membership directory");
        let members = (0..EXPANDED_MEMBER_COUNT).map(member).collect::<Vec<_>>();
        let cluster_id =
            ConsensusClusterId::new("dynamic-membership-integration").expect("cluster identity");
        let initial_identity = consensus_identity(&members[..INITIAL_MEMBER_COUNT], cluster_id, 1);
        let initial_topologies = (0..INITIAL_MEMBER_COUNT)
            .map(|index| {
                ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                    replica_id(index),
                    members[..INITIAL_MEMBER_COUNT].to_vec(),
                    initial_identity,
                ))
                .expect("initial topology")
            })
            .collect::<Vec<_>>();
        let node_ids = members
            .iter()
            .map(|descriptor| {
                initial_topologies[0]
                    .consensus_node_id(descriptor.replica_id())
                    .unwrap_or_else(|| {
                        opc_consensus::derive_node_id(
                            cluster_id,
                            descriptor.replica_id().as_str().as_bytes(),
                        )
                        .expect("candidate node ID")
                    })
            })
            .collect::<Vec<_>>();
        let network = LoopbackNetwork::new(node_ids);
        let backends = (0..EXPANDED_MEMBER_COUNT)
            .map(|index| {
                SqliteSessionBackend::open(directory.path().join(format!("node-{index}.sqlite")))
                    .expect("open SQLite node")
            })
            .collect::<Vec<_>>();

        let mut stores = Vec::with_capacity(EXPANDED_MEMBER_COUNT);
        for index in 0..INITIAL_MEMBER_COUNT {
            let peers = network.peers_for_indices(index, initial_identity, 0..INITIAL_MEMBER_COUNT);
            let store = ConsensusSessionStore::open_with_operation_timeout(
                initial_topologies[index].clone(),
                backends[index].clone(),
                directory.path().join(format!("snapshots-{index}")),
                peers,
                STORE_OPERATION_TIMEOUT,
            )
            .await
            .expect("open initial consensus member");
            network.install(index, store.rpc_handler()).await;
            stores.push(store);
        }
        let results = join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster)).await;
        for result in results {
            result.expect("initialize initial cluster");
        }
        wait_ready(&stores, &(0..INITIAL_MEMBER_COUNT).collect::<Vec<_>>()).await;

        Self {
            _directory: directory,
            _backends: backends,
            members,
            stores,
            network,
            transports: Vec::new(),
            cluster_id,
        }
    }

    fn transition_request(
        &self,
        expected_epoch: u64,
        desired_indices: &[usize],
        transition_seed: u8,
    ) -> SessionTopologyTransitionRequest {
        SessionTopologyTransitionRequest::try_new(
            SessionTopologyTransitionId::from_bytes([transition_seed; 16]),
            self.cluster_id,
            ConsensusConfigurationEpoch::new(expected_epoch).expect("expected epoch"),
            ConsensusConfigurationEpoch::new(expected_epoch + 1).expect("desired epoch"),
            desired_indices
                .iter()
                .map(|index| self.members[*index].clone())
                .collect(),
            TRANSITION_OPERATION_TIMEOUT,
        )
        .expect("valid topology transition")
    }

    async fn add_candidates(
        &mut self,
        current_topology: &ValidatedQuorumTopology,
        request: &SessionTopologyTransitionRequest,
    ) {
        let storage_anchor: SessionConsensusStorageAnchor = self.stores[0].storage_anchor();
        let current_identity = current_topology
            .consensus_identity()
            .expect("candidate predecessor identity");
        let current_members = current_topology.members().to_vec();
        for index in INITIAL_MEMBER_COUNT..EXPANDED_MEMBER_COUNT {
            let bootstrap = SessionTopologyCandidateBootstrap::try_new(
                storage_anchor,
                current_identity,
                current_members.clone(),
                request.clone(),
                self.members[index].clone(),
            )
            .expect("validate candidate bootstrap");
            let store = ConsensusSessionStore::open_membership_candidate(
                bootstrap,
                self._backends[index].clone(),
                self._directory.path().join(format!("snapshots-{index}")),
                self.network.peers_for_request(index, request),
            )
            .await
            .expect("open membership candidate");
            self.network.install(index, store.rpc_handler()).await;
            self.stores.push(store);
        }
    }

    async fn provision_expansion(&mut self, request: &SessionTopologyTransitionRequest) {
        let initial_topology =
            ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                replica_id(0),
                self.members[..INITIAL_MEMBER_COUNT].to_vec(),
                consensus_identity(
                    &self.members[..INITIAL_MEMBER_COUNT],
                    self.cluster_id,
                    request.expected_epoch().get(),
                ),
            ))
            .expect("initial topology for candidate admission");
        self.add_candidates(&initial_topology, request).await;
        self.bind_transport_admission();
        self.stage_on_all(request);
    }

    async fn restart_retained_member(
        &mut self,
        index: usize,
        request: &SessionTopologyTransitionRequest,
    ) -> SessionConsensusNodeId {
        let topology = ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
            replica_id(index),
            self.members[..INITIAL_MEMBER_COUNT].to_vec(),
            consensus_identity(
                &self.members[..INITIAL_MEMBER_COUNT],
                self.cluster_id,
                request.expected_epoch().get(),
            ),
        ))
        .expect("restart predecessor topology");

        self.network.retire_incarnation(index).await;
        let placeholder_index = (0..INITIAL_MEMBER_COUNT)
            .find(|candidate| *candidate != index)
            .expect("retained restart placeholder");
        let placeholder = self.stores[placeholder_index].clone();
        let retired = std::mem::replace(&mut self.stores[index], placeholder);
        drop(retired);
        // The topology supervisor only holds weak store references. Give the
        // retired incarnation a scheduling turn to observe its final drop
        // before opening the same durable Raft state.
        tokio::time::sleep(Duration::from_millis(100)).await;

        let successor = tokio::time::timeout(TEST_DEADLINE, async {
            loop {
                if let Some(status) = (0..INITIAL_MEMBER_COUNT)
                    .filter(|candidate| *candidate != index)
                    .map(|candidate| self.stores[candidate].status())
                    .find(|status| status.leader_id == Some(status.node_id))
                {
                    return status.node_id;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .expect("retained voters elect a successor while the old leader is down");

        let peers = self.network.peers_for_indices(
            index,
            topology
                .consensus_identity()
                .expect("restart predecessor identity"),
            0..INITIAL_MEMBER_COUNT,
        );
        let reopened = ConsensusSessionStore::open_with_operation_timeout(
            topology,
            self._backends[index].clone(),
            self._directory.path().join(format!("snapshots-{index}")),
            peers,
            STORE_OPERATION_TIMEOUT,
        )
        .await
        .expect("reopen retained consensus member from durable state");
        self.network.install(index, reopened.rpc_handler()).await;
        let transport = Arc::new(RecordingTransportAdmission::default());
        let binding: Arc<dyn SessionTopologyTransportAdmission> = transport.clone();
        reopened
            .bind_topology_transport_admission(binding)
            .expect("bind restarted transport admission");
        reopened
            .stage_topology_transition_peers(
                request,
                self.network.peers_for_request(index, request),
            )
            .expect("restage exact transition peers after restart");
        self.transports[index] = transport;
        self.stores[index] = reopened;
        successor
    }

    async fn restart_member_in_scope(
        &mut self,
        index: usize,
        active_indices: &[usize],
        identity: SessionConsensusIdentity,
        request: &SessionTopologyTransitionRequest,
    ) {
        self.network.retire_incarnation(index).await;
        let placeholder_index = active_indices
            .iter()
            .copied()
            .find(|candidate| *candidate != index)
            .expect("restart placeholder");
        let placeholder = self.stores[placeholder_index].clone();
        let retired = std::mem::replace(&mut self.stores[index], placeholder);
        drop(retired);
        tokio::time::sleep(Duration::from_millis(100)).await;

        let topology = ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
            replica_id(index),
            active_indices
                .iter()
                .map(|member| self.members[*member].clone())
                .collect(),
            identity,
        ))
        .expect("restart active topology");
        let peers = self
            .network
            .peers_for_indices(index, identity, active_indices.iter().copied());
        let reopened = ConsensusSessionStore::open_with_operation_timeout(
            topology,
            self._backends[index].clone(),
            self._directory.path().join(format!("snapshots-{index}")),
            peers,
            STORE_OPERATION_TIMEOUT,
        )
        .await
        .expect("reopen member from incomplete terminal state");
        self.network.install(index, reopened.rpc_handler()).await;
        let transport = Arc::new(RecordingTransportAdmission::default());
        let binding: Arc<dyn SessionTopologyTransportAdmission> = transport.clone();
        reopened
            .bind_topology_transport_admission(binding)
            .expect("bind restarted transport admission");
        reopened
            .stage_topology_transition_peers(
                request,
                self.network.peers_for_request(index, request),
            )
            .expect("reconstruct exact incomplete terminal staging after restart");
        self.transports[index] = transport;
        self.stores[index] = reopened;
    }

    fn bind_transport_admission(&mut self) {
        self.transports = self
            .stores
            .iter()
            .map(|store| {
                let transport = Arc::new(RecordingTransportAdmission::default());
                let binding: Arc<dyn SessionTopologyTransportAdmission> = transport.clone();
                store
                    .bind_topology_transport_admission(binding)
                    .expect("bind topology transport admission");
                transport
            })
            .collect();
    }

    fn stage_on_all(&self, request: &SessionTopologyTransitionRequest) {
        for (index, store) in self.stores.iter().enumerate() {
            store
                .stage_topology_transition_peers(
                    request,
                    self.network.peers_for_request(index, request),
                )
                .expect("stage exact desired peers");
        }
    }

    async fn prepare(
        &self,
        request: &SessionTopologyTransitionRequest,
        desired_indices: &[usize],
    ) -> SessionTopologyLearnersReadyAdmissionProof {
        tokio::time::timeout(TEST_DEADLINE, async {
            loop {
                let Some(caller) = self.transition_caller(desired_indices) else {
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                };
                match self.stores[caller]
                    .prepare_topology_transition(
                        request,
                        self.network.peers_for_request(caller, request),
                    )
                    .await
                {
                    Ok(proof) => return proof,
                    Err(
                        SessionTopologyTransitionError::NotLeader
                        | SessionTopologyTransitionError::Unavailable
                        | SessionTopologyTransitionError::DeadlineExceededResumable,
                    ) => {
                        tokio::time::sleep(POLL_INTERVAL).await;
                    }
                    Err(error) => panic!("prepare transition failed: {error:?}"),
                }
            }
        })
        .await
        .expect("prepare transition deadline")
    }

    async fn commit(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyLearnersReadyAdmissionProof,
        desired_indices: &[usize],
    ) {
        tokio::time::timeout(TEST_DEADLINE, async {
            loop {
                let Some(caller) = self.transition_caller(desired_indices) else {
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                };
                match self.stores[caller]
                    .commit_topology_transition(request, proof)
                    .await
                {
                    Ok(status) if status.phase() == SessionTopologyTransitionPhase::Completed => {
                        return;
                    }
                    Ok(status) => panic!("commit returned nonterminal status: {status:?}"),
                    Err(
                        SessionTopologyTransitionError::NotLeader
                        | SessionTopologyTransitionError::Unavailable
                        | SessionTopologyTransitionError::DeadlineExceededResumable,
                    ) => tokio::time::sleep(POLL_INTERVAL).await,
                    Err(error) => panic!("commit transition failed: {error:?}"),
                }
            }
        })
        .await
        .expect("commit transition deadline");
    }

    async fn abort(&self, request: &SessionTopologyTransitionRequest, current_indices: &[usize]) {
        let aborted = tokio::time::timeout(TEST_DEADLINE, async {
            loop {
                let Some(caller) = self.transition_caller(current_indices) else {
                    tokio::time::sleep(POLL_INTERVAL).await;
                    continue;
                };
                match self.stores[caller].abort_topology_transition(request).await {
                    Ok(status) if status.phase() == SessionTopologyTransitionPhase::Aborted => {
                        return;
                    }
                    Ok(status) => panic!("abort returned nonterminal status: {status:?}"),
                    Err(
                        SessionTopologyTransitionError::NotLeader
                        | SessionTopologyTransitionError::Unavailable
                        | SessionTopologyTransitionError::DeadlineExceededResumable,
                    ) => tokio::time::sleep(POLL_INTERVAL).await,
                    Err(error) => panic!("abort transition failed: {error:?}"),
                }
            }
        })
        .await;
        if aborted.is_err() {
            for (index, store) in self.stores.iter().enumerate() {
                eprintln!(
                    "abort node {index}: transition={:?}, consensus={:?}",
                    store.topology_transition_status(request).await,
                    store.status()
                );
            }
            panic!("abort transition deadline elapsed");
        }
    }

    fn transition_caller(&self, desired_indices: &[usize]) -> Option<usize> {
        let maximum_observed_term = desired_indices
            .iter()
            .map(|index| self.stores[*index].status().term)
            .max()?;
        desired_indices
            .iter()
            .map(|index| (*index, self.stores[*index].status()))
            .find(|(_, status)| {
                status.term == maximum_observed_term && status.leader_id == Some(status.node_id)
            })
            .map(|(index, _)| index)
    }

    async fn wait_transition_caller(&self, desired_indices: &[usize]) -> usize {
        tokio::time::timeout(TEST_DEADLINE, async {
            loop {
                if let Some(caller) = self.transition_caller(desired_indices) {
                    return caller;
                }
                tokio::time::sleep(POLL_INTERVAL).await;
            }
        })
        .await
        .expect("active membership elects one highest-term leader")
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn live_three_to_five_to_three_preserves_quorum_and_fences_removed_voters() {
    let mut fleet = DynamicFleet::start_three().await;
    prove_read_write_on_every_active_store(&fleet.stores, &[0, 1, 2], "epoch-1").await;

    let expand = fleet.transition_request(1, &[0, 1, 2, 3, 4], 0x35);
    fleet.provision_expansion(&expand).await;
    let expand_proof = fleet.prepare(&expand, &[0, 1, 2, 3, 4]).await;
    fleet.commit(&expand, &expand_proof, &[0, 1, 2, 3, 4]).await;
    wait_completed_and_admitted(&fleet.stores, &expand, &[0, 1, 2, 3, 4], &[]).await;
    prove_read_write_on_every_active_store(&fleet.stores, &[0, 1, 2, 3, 4], "epoch-2").await;

    let leader = fleet.stores[0].status().leader_id.expect("expanded leader");
    let unavailable = (0..EXPANDED_MEMBER_COUNT)
        .filter(|index| fleet.network.node_ids[*index] != leader)
        .take(2)
        .collect::<Vec<_>>();
    for index in &unavailable {
        fleet.network.isolate(*index);
    }
    let available = (0..EXPANDED_MEMBER_COUNT)
        .filter(|index| !unavailable.contains(index))
        .collect::<Vec<_>>();
    prove_read_write_on_every_active_store(&fleet.stores, &available, "epoch-2-two-down").await;
    for index in unavailable {
        fleet.network.heal(index);
    }
    wait_ready(&fleet.stores, &[0, 1, 2, 3, 4]).await;

    let contract = fleet.transition_request(2, &[0, 1, 2], 0x53);
    fleet.stage_on_all(&contract);
    let contract_proof = fleet.prepare(&contract, &[0, 1, 2]).await;
    fleet.commit(&contract, &contract_proof, &[0, 1, 2]).await;
    wait_completed_and_admitted(&fleet.stores, &contract, &[0, 1, 2], &[3, 4]).await;
    prove_read_write_on_every_active_store(&fleet.stores, &[0, 1, 2], "epoch-3").await;

    let contracted_leader = fleet.stores[0]
        .status()
        .leader_id
        .expect("contracted leader");
    let unavailable = (0..INITIAL_MEMBER_COUNT)
        .find(|index| fleet.network.node_ids[*index] != contracted_leader)
        .expect("nonleader retained voter");
    fleet.network.isolate(unavailable);
    let available = (0..INITIAL_MEMBER_COUNT)
        .filter(|index| *index != unavailable)
        .collect::<Vec<_>>();
    prove_read_write_on_every_active_store(&fleet.stores, &available, "epoch-3-one-down").await;
    fleet.network.heal(unavailable);
    wait_ready(&fleet.stores, &[0, 1, 2]).await;

    for index in 0..EXPANDED_MEMBER_COUNT {
        assert!(
            fleet.transports[index].voting_admissions() > 0,
            "node {index} never admitted a store-issued joint-voting proof"
        );
        assert!(
            fleet.transports[index].finalizations() > 0,
            "node {index} never admitted a store-issued uniform proof"
        );
    }
    for index in [3, 4] {
        assert!(
            fleet.stores[index]
                .get(&session_key(b"removed-voter-read"))
                .await
                .is_err(),
            "removed voter {index} retained application read authority"
        );
    }

    let retained_id_conflict = fleet.transition_request(3, &[0, 1, 2, 3, 4], 0x35);
    assert_eq!(
        fleet.stores[0]
            .topology_transition_status(&retained_id_conflict)
            .await,
        Err(SessionTopologyTransitionError::IdempotencyConflict),
        "durable status lookup ignored a transition ID retained in history"
    );
    assert_eq!(
        fleet.stores[0].stage_topology_transition_peers(
            &retained_id_conflict,
            fleet.network.peers_for_request(0, &retained_id_conflict),
        ),
        Err(SessionTopologyTransitionError::IdempotencyConflict),
        "process-local route staging accepted a transition ID retained in durable history"
    );
    let leader = fleet.wait_transition_caller(&[0, 1, 2]).await;
    assert_eq!(
        fleet.stores[leader]
            .prepare_topology_transition(
                &retained_id_conflict,
                fleet
                    .network
                    .peers_for_request(leader, &retained_id_conflict),
            )
            .await,
        Err(SessionTopologyTransitionError::IdempotencyConflict),
        "a transition ID retained in durable history accepted a different request digest"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn terminal_first_abort_retries_lost_candidate_ack_and_restores_old_authority() {
    let mut fleet = DynamicFleet::start_three().await;
    let request = fleet.transition_request(1, &[0, 1, 2, 3, 4], 0xAB);
    fleet.provision_expansion(&request).await;
    let _proof = fleet.prepare(&request, &[0, 1, 2, 3, 4]).await;

    let leader = fleet.wait_transition_caller(&[0, 1, 2]).await;
    fleet.network.drop_next_topology_response(leader, 3);
    fleet.abort(&request, &[0, 1, 2]).await;
    assert_eq!(
        fleet.network.dropped_topology_responses(leader, 3),
        1,
        "candidate applied the abort decision but its first acknowledgement was not lost"
    );

    // Exact terminal retry must neither repeat unsafe work nor reject the
    // caller-owned transition identity.
    fleet.abort(&request, &[0, 1, 2]).await;
    wait_aborted_and_admitted(&fleet.stores, &request, &[0, 1, 2], &[3, 4]).await;
    prove_read_write_on_every_active_store(&fleet.stores, &[0, 1, 2], "aborted-epoch-1").await;
    for index in [3, 4] {
        assert!(
            fleet.stores[index]
                .get(&session_key(b"aborted-candidate-read"))
                .await
                .is_err(),
            "aborted candidate {index} retained application authority"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn finalizing_transition_blocks_successor_staging_until_exact_resume() {
    let mut fleet = DynamicFleet::start_three().await;
    let expanded = (0..EXPANDED_MEMBER_COUNT).collect::<Vec<_>>();
    let first = fleet.transition_request(1, &expanded, 0xF1);
    fleet.provision_expansion(&first).await;
    let first_proof = fleet.prepare(&first, &expanded).await;

    // Stop the incumbent after desired-uniform membership has committed but
    // before it can publish the durable Finalize control. Releasing this hook
    // while the leader is isolated forces the exact resumable window: local
    // routes have cut over, while durable terminal evidence is Finalizing.
    let incumbent = fleet.wait_transition_caller(&[0, 1, 2]).await;
    let incumbent_transport = Arc::clone(&fleet.transports[incumbent]);
    incumbent_transport.block_next_finalization();
    let commit_store = fleet.stores[incumbent].clone();
    let commit_request = first.clone();
    let commit_proof = first_proof.clone();
    let incumbent_commit = tokio::spawn(async move {
        commit_store
            .commit_topology_transition(&commit_request, &commit_proof)
            .await
    });

    tokio::time::timeout(
        TEST_DEADLINE,
        incumbent_transport.wait_for_blocked_finalization(),
    )
    .await
    .expect("incumbent reaches uniform transport cutover");
    assert_eq!(
        fleet.stores[incumbent]
            .topology_transition_status(&first)
            .await
            .expect("read incumbent transition status")
            .expect("first transition has durable evidence")
            .phase(),
        SessionTopologyTransitionPhase::Finalizing,
        "transport cutover was reached outside the durable Finalizing window"
    );

    fleet.network.isolate(incumbent);
    incumbent_transport.release_finalization();
    let retained = expanded
        .iter()
        .copied()
        .filter(|index| *index != incumbent)
        .collect::<Vec<_>>();
    let successor = fleet.wait_transition_caller(&retained).await;
    assert_ne!(
        successor, incumbent,
        "isolated incumbent remained the transition caller"
    );
    assert_eq!(
        fleet.stores[successor]
            .topology_transition_status(&first)
            .await
            .expect("read successor transition status")
            .expect("successor observes first transition evidence")
            .phase(),
        SessionTopologyTransitionPhase::Finalizing,
        "successor did not inherit the incomplete terminal transition"
    );

    let restarted = retained
        .iter()
        .copied()
        .find(|candidate| *candidate != successor)
        .expect("non-leader retained member to restart");
    fleet
        .restart_member_in_scope(restarted, &expanded, first.desired_identity(), &first)
        .await;

    let second = fleet.transition_request(2, &[0, 1, 2], 0xF2);
    assert_eq!(
        fleet.stores[successor].stage_topology_transition_peers(
            &second,
            fleet.network.peers_for_request(successor, &second),
        ),
        Err(SessionTopologyTransitionError::TransitionInProgress),
        "process-local staging overwrote an incomplete durable terminal"
    );
    assert_eq!(
        fleet.stores[successor]
            .prepare_topology_transition(
                &second,
                fleet.network.peers_for_request(successor, &second),
            )
            .await,
        Err(SessionTopologyTransitionError::TransitionInProgress),
        "durable Prepare admitted a successor before terminal quiescence"
    );

    let completed = fleet.stores[successor]
        .commit_topology_transition(&first, &first_proof)
        .await
        .expect("successor resumes the exact first transition");
    assert_eq!(completed.phase(), SessionTopologyTransitionPhase::Completed);
    fleet.network.heal(incumbent);
    let _ = tokio::time::timeout(TEST_DEADLINE, incumbent_commit)
        .await
        .expect("incumbent commit task terminates after exact resume")
        .expect("incumbent commit task remains live");
    wait_completed_and_admitted(&fleet.stores, &first, &expanded, &[]).await;

    fleet.stores[successor]
        .stage_topology_transition_peers(
            &second,
            fleet.network.peers_for_request(successor, &second),
        )
        .expect("successor stages only after the first terminal is complete");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pure_removal_pre_joint_abort_uses_terminal_control_without_membership_churn() {
    let mut fleet = DynamicFleet::start_three().await;
    let expanded = (0..EXPANDED_MEMBER_COUNT).collect::<Vec<_>>();
    let expand = fleet.transition_request(1, &expanded, 0x5A);
    fleet.provision_expansion(&expand).await;
    let expand_proof = fleet.prepare(&expand, &expanded).await;
    fleet.commit(&expand, &expand_proof, &expanded).await;
    wait_completed_and_admitted(&fleet.stores, &expand, &expanded, &[]).await;

    // Retain the live leader so this proof exercises abort cleanup rather
    // than leadership transfer. Every desired voter already belongs to the
    // current five-voter topology, so the prepared transition has no learners.
    let leader = fleet.wait_transition_caller(&expanded).await;
    let mut retained = std::iter::once(leader)
        .chain(
            (0..EXPANDED_MEMBER_COUNT)
                .filter(|index| *index != leader)
                .take(2),
        )
        .collect::<Vec<_>>();
    retained.sort_unstable();
    let request = fleet.transition_request(2, &retained, 0xA5);
    fleet.stage_on_all(&request);
    prove_read_write_on_every_active_store(&fleet.stores, &expanded, "pure-removal-staged").await;
    let _proof = fleet.prepare(&request, &retained).await;

    let abort_leader = fleet.wait_transition_caller(&retained).await;
    let before_abort = fleet.stores[abort_leader].status();
    let before_abort_log = before_abort
        .last_log_index
        .expect("prepared pure-removal log index");
    let first_abort = fleet.stores[abort_leader]
        .abort_topology_transition(&request)
        .await;
    assert!(
        first_abort
            .as_ref()
            .is_ok_and(|status| status.phase() == SessionTopologyTransitionPhase::Aborted),
        "pure-removal abort failed with {first_abort:?}"
    );
    let after_abort = fleet.stores[abort_leader].status();
    assert_eq!(
        after_abort.term, before_abort.term,
        "pure-removal proof unexpectedly changed leader term"
    );
    assert_eq!(
        after_abort.last_log_index,
        before_abort_log.checked_add(2),
        "pre-joint abort must append only Abort and AbortCleanup controls, not an empty membership change"
    );

    fleet.abort(&request, &retained).await;
    assert_eq!(
        fleet.stores[abort_leader].status().last_log_index,
        after_abort.last_log_index,
        "exact terminal abort retry appended new durable work"
    );
    wait_aborted_and_admitted(&fleet.stores, &request, &expanded, &[]).await;
    prove_read_write_on_every_active_store(&fleet.stores, &expanded, "pure-removal-aborted").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prepared_transition_survives_retained_leader_restart_and_exact_restage() {
    let mut fleet = DynamicFleet::start_three().await;
    let durable_key = session_key(b"leader-restart-persisted-record");
    let durable_lease = fleet.stores[0]
        .acquire(
            &durable_key,
            owner("leader-restart-owner".to_owned()),
            Duration::from_secs(30),
        )
        .await
        .expect("acquire before leader restart");
    let durable_record = sealed_record(
        durable_key.clone(),
        &durable_lease,
        b"leader-restart-payload",
    );
    assert_eq!(
        fleet.stores[1]
            .compare_and_set(CompareAndSet {
                key: durable_key.clone(),
                lease: durable_lease,
                expected_generation: None,
                new_record: durable_record.clone(),
            })
            .await
            .expect("commit record before leader restart"),
        CompareAndSetResult::Success
    );

    let request = fleet.transition_request(1, &[0, 1, 2, 3, 4], 0x71);
    fleet.provision_expansion(&request).await;
    let proof = fleet.prepare(&request, &[0, 1, 2, 3, 4]).await;
    wait_application_authority_fenced(&fleet.stores).await;

    let retired_leader = fleet.wait_transition_caller(&[0, 1, 2]).await;
    let retired_leader_id = fleet.network.node_ids[retired_leader];
    let successor = fleet
        .restart_retained_member(retired_leader, &request)
        .await;
    assert_ne!(
        successor, retired_leader_id,
        "restart proof did not force a retained-voter leader change"
    );
    assert!(
        !fleet.stores[retired_leader].status().admitted,
        "reopened member leaked application authority before terminal cutover"
    );
    assert!(
        fleet.stores[retired_leader]
            .get(&durable_key)
            .await
            .is_err(),
        "reopened member served application state during a nonterminal transition"
    );

    fleet.commit(&request, &proof, &[0, 1, 2, 3, 4]).await;
    wait_completed_and_admitted(&fleet.stores, &request, &[0, 1, 2, 3, 4], &[]).await;
    for store in &fleet.stores {
        assert_eq!(
            store.get(&durable_key).await.expect("read after restart"),
            Some(durable_record.clone())
        );
    }
    prove_read_write_on_every_active_store(&fleet.stores, &[0, 1, 2, 3, 4], "post-leader-restart")
        .await;
}

#[derive(Clone, Copy)]
enum LostJointQuorum {
    Old,
    Desired,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joint_transition_blocks_without_each_required_quorum_then_resumes_after_heal() {
    for (case, seed) in [
        (LostJointQuorum::Old, 0xA1),
        (LostJointQuorum::Desired, 0xA2),
    ] {
        run_lost_joint_quorum_case(case, seed).await;
    }
}

async fn run_lost_joint_quorum_case(case: LostJointQuorum, seed: u8) {
    let mut fleet = DynamicFleet::start_three().await;
    let request = fleet.transition_request(1, &[0, 1, 2, 3, 4], seed);
    fleet.provision_expansion(&request).await;
    let proof = fleet.prepare(&request, &[0, 1, 2, 3, 4]).await;
    let leader = fleet.wait_transition_caller(&[0, 1, 2]).await;
    let isolated = match case {
        LostJointQuorum::Old => (0..INITIAL_MEMBER_COUNT)
            .filter(|index| *index != leader)
            .collect::<Vec<_>>(),
        LostJointQuorum::Desired => {
            let other_old = (0..INITIAL_MEMBER_COUNT)
                .find(|index| *index != leader)
                .expect("old follower");
            vec![other_old, 3, 4]
        }
    };
    for index in &isolated {
        fleet.network.isolate(*index);
    }

    let commit = fleet.stores[leader].commit_topology_transition(&request, &proof);
    tokio::pin!(commit);
    tokio::select! {
        result = &mut commit => panic!("transition completed without both joint quorums: {result:?}"),
        () = tokio::time::sleep(Duration::from_millis(500)) => {}
    }
    let phase = fleet.stores[leader]
        .topology_transition_status(&request)
        .await
        .expect("read blocked transition status")
        .expect("prepared transition evidence")
        .phase();
    assert!(
        matches!(
            phase,
            SessionTopologyTransitionPhase::LearnersReady
                | SessionTopologyTransitionPhase::LearnersCatchingUp
                | SessionTopologyTransitionPhase::AuthorityFenced
        ),
        "transition crossed joint consensus without both quorums: {phase:?}"
    );

    for index in isolated {
        fleet.network.heal(index);
    }
    let result = tokio::time::timeout(TEST_DEADLINE, &mut commit)
        .await
        .expect("healed transition deadline");
    match result {
        Ok(status) => assert_eq!(status.phase(), SessionTopologyTransitionPhase::Completed),
        Err(
            SessionTopologyTransitionError::NotLeader
            | SessionTopologyTransitionError::Unavailable
            | SessionTopologyTransitionError::DeadlineExceededResumable,
        ) => {
            fleet.commit(&request, &proof, &[0, 1, 2, 3, 4]).await;
        }
        Err(error) => panic!("healed transition failed: {error:?}"),
    }
    wait_completed_and_admitted(&fleet.stores, &request, &[0, 1, 2, 3, 4], &[]).await;
}

async fn wait_ready(stores: &[ConsensusSessionStore], active: &[usize]) {
    tokio::time::timeout(TEST_DEADLINE, async {
        loop {
            let reports = join_all(
                active
                    .iter()
                    .map(|index| stores[*index].probe_durable_readiness()),
            )
            .await;
            if reports.iter().all(|report| report.is_ready()) {
                return;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("active membership reaches durable readiness");
}

async fn wait_application_authority_fenced(stores: &[ConsensusSessionStore]) {
    tokio::time::timeout(TEST_DEADLINE, async {
        loop {
            if stores.iter().all(|store| !store.status().admitted) {
                return;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("all members fence application authority before joint consensus");
}

async fn wait_completed_and_admitted(
    stores: &[ConsensusSessionStore],
    request: &SessionTopologyTransitionRequest,
    active: &[usize],
    removed: &[usize],
) {
    let converged = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let statuses = join_all(
                active
                    .iter()
                    .map(|index| stores[*index].topology_transition_status(request)),
            )
            .await;
            let completed = statuses.iter().all(|status| {
                status
                    .as_ref()
                    .ok()
                    .and_then(Option::as_ref)
                    .is_some_and(|status| {
                        status.phase() == SessionTopologyTransitionPhase::Completed
                    })
            });
            let active_admitted = active.iter().all(|index| stores[*index].status().admitted);
            let removed_fenced = removed
                .iter()
                .all(|index| !stores[*index].status().admitted);
            if completed && active_admitted && removed_fenced {
                break;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await;
    if converged.is_err() {
        for (index, store) in stores.iter().enumerate() {
            eprintln!(
                "node {index}: transition={:?}, consensus={:?}",
                store.topology_transition_status(request).await,
                store.status()
            );
        }
        panic!("uniform membership and admission did not converge");
    }
    wait_ready(stores, active).await;
}

async fn wait_aborted_and_admitted(
    stores: &[ConsensusSessionStore],
    request: &SessionTopologyTransitionRequest,
    active: &[usize],
    candidates: &[usize],
) {
    tokio::time::timeout(TEST_DEADLINE, async {
        loop {
            let statuses = join_all(
                active
                    .iter()
                    .map(|index| stores[*index].topology_transition_status(request)),
            )
            .await;
            let aborted = statuses.iter().all(|status| {
                status
                    .as_ref()
                    .ok()
                    .and_then(Option::as_ref)
                    .is_some_and(|status| status.phase() == SessionTopologyTransitionPhase::Aborted)
            });
            let active_admitted = active.iter().all(|index| stores[*index].status().admitted);
            let candidates_fenced = candidates
                .iter()
                .all(|index| !stores[*index].status().admitted);
            if aborted && active_admitted && candidates_fenced {
                return;
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("aborted topology restores only predecessor authority");
    wait_ready(stores, active).await;
}

async fn prove_read_write_on_every_active_store(
    stores: &[ConsensusSessionStore],
    active: &[usize],
    label: &str,
) {
    for (position, actor) in active.iter().copied().enumerate() {
        let key = session_key(format!("{label}-{actor}").as_bytes());
        let lease = stores[actor]
            .acquire(
                &key,
                owner(format!("{label}-owner-{actor}")),
                Duration::from_secs(30),
            )
            .await
            .expect("acquire through active member");
        let record = sealed_record(key.clone(), &lease, label.as_bytes());
        let writer = active[(position + 1) % active.len()];
        assert_eq!(
            stores[writer]
                .compare_and_set(CompareAndSet {
                    key: key.clone(),
                    lease,
                    expected_generation: None,
                    new_record: record.clone(),
                })
                .await
                .expect("CAS through active member"),
            CompareAndSetResult::Success
        );
        let reads = join_all(active.iter().map(|index| stores[*index].get(&key))).await;
        for read in reads {
            assert_eq!(
                read.expect("read through active member"),
                Some(record.clone())
            );
        }
    }
}

fn replica_id(index: usize) -> ReplicaId {
    ReplicaId::new(format!("dynamic-member-{index}")).expect("replica ID")
}

fn member(index: usize) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        replica_id(index),
        ReplicaEndpoint::new(format!("dynamic-member-{index}.invalid"), 7443)
            .expect("replica endpoint"),
        ReplicaTlsIdentity::new(format!("spiffe://test/session/dynamic/{index}"))
            .expect("TLS identity"),
        ReplicaFailureDomain::new(format!("dynamic-zone-{index}")).expect("failure domain"),
        ReplicaBackingIdentity::new(format!("dynamic-disk-{index}")).expect("backing identity"),
    )
}

fn consensus_identity(
    members: &[QuorumReplicaDescriptor],
    cluster_id: ConsensusClusterId,
    epoch: u64,
) -> ConsensusIdentity {
    let epoch = ConsensusConfigurationEpoch::new(epoch).expect("configuration epoch");
    let fingerprints = members
        .iter()
        .map(QuorumReplicaDescriptor::configuration_fingerprint)
        .collect::<Vec<_>>();
    ConsensusIdentity::new(
        cluster_id,
        derive_configuration_id(cluster_id, epoch, &fingerprints),
        epoch,
    )
}

fn session_key(label: &[u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("dynamic-membership-test").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(label)
            .try_into()
            .expect("bounded stable ID"),
    }
}

fn owner(label: String) -> OwnerId {
    OwnerId::new(label).expect("owner")
}

fn sealed_record(
    key: SessionKey,
    lease: &opc_session_store::LeaseGuard,
    payload: &[u8],
) -> StoredSessionRecord {
    let mut record = StoredSessionRecord {
        key,
        generation: Generation::new(1),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("dynamic-membership-proof"),
        expires_at: None,
        payload: EncryptedSessionPayload::new([]),
    };
    let key_id = KeyId::new("synthetic-dynamic-membership-key").expect("key ID");
    let aad = EnvelopeAad::session(
        record.key.tenant.clone(),
        1,
        SessionAad::new(
            record.key.nf_kind.as_str(),
            "dynamic-membership-session-digest",
            record.state_type.as_str(),
            record.generation.get(),
            record.fence.get(),
            "dynamic-membership-test-backend",
        )
        .expect("session AAD"),
    );
    let mut ciphertext_and_tag = payload.to_vec();
    ciphertext_and_tag.extend_from_slice(&[0xA5; AEAD_TAG_LEN]);
    let envelope = CryptoEnvelopeV1 {
        algorithm: AeadAlgorithm::Aes256GcmSiv,
        key_id: key_id.clone(),
        nonce: vec![0x42; AES_256_GCM_SIV_NONCE_LEN],
        aad: serialize_bound_aad(&aad, &key_id).expect("bound AAD"),
        ciphertext_and_tag,
    }
    .encode()
    .expect("test envelope");
    record.payload = EncryptedSessionPayload::try_envelope(envelope).expect("valid envelope");
    record
}
