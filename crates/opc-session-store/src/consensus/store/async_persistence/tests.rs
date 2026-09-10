//! Ordinary public openers and real multi-voter recovery/operation boundaries.

use std::panic::AssertUnwindSafe;
use std::sync::atomic::AtomicU64;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{future::join_all, FutureExt};
use opc_consensus::engine::raft::{AppendEntriesRequest, AppendEntriesResponse, VoteRequest};
use opc_consensus::engine::{CommittedLeaderId, Vote};
use opc_consensus::{ConsensusClusterId, ConsensusConfigurationEpoch};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_types::{NetworkFunctionKind, TenantId};

use super::*;
use crate::fenced_transition::{
    FencedTransitionLease, FencedTransitionMutation, FencedTransitionMutationResult,
    FencedTransitionV2CallerNonce,
};
use crate::model::{FenceToken, Generation, SessionKeyType, StateClass, StateType};
use crate::record::EncryptedSessionPayload;
use crate::topology::{
    QuorumReplicaDescriptor, QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint,
    ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
};
use crate::{SessionAsyncRecoveryState, SnapshotIntegrityPolicy};

mod admission;
mod bootstrap;
mod races;
mod snapshots;
mod writer;

type GenerationHook = Arc<dyn Fn() -> std::io::Result<()> + Send + Sync>;
const OPERATION_BOUND: Duration = Duration::from_millis(800);

struct Peer {
    node: SessionConsensusNodeId,
    identity: SessionConsensusIdentity,
    handler: tokio::sync::RwLock<Option<Arc<dyn SessionConsensusRpcHandler>>>,
    engine_calls: Mutex<BTreeMap<SessionConsensusNodeId, u64>>,
    successful_appends: AtomicU64,
    last_cut: Mutex<Option<ColdQuorumCut>>,
    blocked_senders: Mutex<BTreeSet<SessionConsensusNodeId>>,
    blocked_append_above: Mutex<Option<(SessionConsensusNodeId, u64)>>,
    held_reply: Mutex<Option<Arc<races::ReplyHold>>>,
    cut_mutation: Mutex<Option<admission::CutMutation>>,
}

impl fmt::Debug for Peer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AsyncPersistenceTestPeer")
    }
}

#[async_trait]
impl SessionConsensusPeer for Peer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.node
    }
    fn scope_identity(&self) -> Option<SessionConsensusIdentity> {
        Some(self.identity)
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        if self
            .blocked_senders
            .lock()
            .unwrap()
            .contains(&request.sender)
        {
            return Err(SessionConsensusPeerError::Unavailable);
        }
        let append_limit = *self.blocked_append_above.lock().unwrap();
        if let Some((sender, limit)) = append_limit {
            if request.sender == sender
                && races::append_request(&request)
                    .and_then(|append| races::append_last(&append))
                    .is_some_and(|last| last.index > limit)
            {
                return Err(SessionConsensusPeerError::Unavailable);
            }
        }
        let family = request.family;
        if matches!(
            family,
            SessionConsensusRpcFamily::Vote
                | SessionConsensusRpcFamily::AppendEntries
                | SessionConsensusRpcFamily::AppendEntriesRoster
                | SessionConsensusRpcFamily::InstallSnapshot
        ) {
            *self
                .engine_calls
                .lock()
                .unwrap()
                .entry(request.sender)
                .or_default() += 1;
        }
        let hold = self.held_reply.lock().unwrap().clone();
        let held_request = hold.as_ref().map(|_| request.clone());
        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(SessionConsensusPeerError::Unavailable)?;
        let mut response = handler.handle(request.sender, request).await;
        // A cached network response must not retain the predecessor store
        // while the test closes and reopens that ordinary public owner.
        drop(handler);
        if let (Some(hold), Some(request)) = (hold, held_request) {
            hold.after_response(request, &response).await;
        }
        if let Ok(payload) = &response.result {
            if let Ok(payload) =
                persistence_protocol::unwrap_payload(SessionPersistenceMode::Async, payload)
            {
                if matches!(
                    family,
                    SessionConsensusRpcFamily::AppendEntries
                        | SessionConsensusRpcFamily::AppendEntriesRoster
                ) && matches!(
                    decode_bounded::<
                        Result<
                            AppendEntriesResponse<SessionConsensusNodeId>,
                            RaftError<SessionConsensusNodeId>,
                        >,
                    >(payload),
                    Ok(Ok(AppendEntriesResponse::Success))
                ) {
                    self.successful_appends.fetch_add(1, Ordering::AcqRel);
                }
                if family == SessionConsensusRpcFamily::ReadBarrier {
                    if let Ok(cut) = decode_bounded::<ColdQuorumCut>(payload) {
                        *self.last_cut.lock().unwrap() = Some(cut);
                    }
                }
            }
        }
        if family == SessionConsensusRpcFamily::ReadBarrier {
            if let Some(mutation) = *self.cut_mutation.lock().unwrap() {
                mutation.alter(&mut response);
            }
        }
        Ok(response)
    }
}

struct Fleet {
    directory: tempfile::TempDir,
    topologies: Vec<ValidatedQuorumTopology>,
    peers: Vec<Arc<Peer>>,
    stores: Vec<Option<ConsensusSessionStore>>,
}

impl Fleet {
    fn new(voters: usize) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let members = (0..voters)
            .map(|index| {
                QuorumReplicaDescriptor::new(
                    ReplicaId::new(format!("async-public-{index}")).unwrap(),
                    ReplicaEndpoint::new(format!("async-public-{index}.invalid"), 7443).unwrap(),
                    ReplicaTlsIdentity::new(format!("spiffe://test/async-public/{index}")).unwrap(),
                    ReplicaFailureDomain::new(format!("zone-{index}")).unwrap(),
                    ReplicaBackingIdentity::new(format!("disk-{index}")).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let placement = PlacementResiliencePolicy::AllowReducedResilience;
        let identity = crate::derive_fixed_durable_quorum_consensus_identity(
            ConsensusClusterId::new("async-public-fixed").unwrap(),
            ConsensusConfigurationEpoch::new(1).unwrap(),
            &members
                .iter()
                .map(QuorumReplicaDescriptor::configuration_fingerprint)
                .collect::<Vec<_>>(),
            placement,
        );
        let topologies = members
            .iter()
            .map(|member| {
                ValidatedQuorumTopology::try_from_fixed_durable_quorum_with_placement_policy(
                    QuorumTopologyConfig::new_consensus(
                        member.replica_id().clone(),
                        members.clone(),
                        identity,
                    ),
                    placement,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let peers = topologies
            .iter()
            .map(|topology| {
                Arc::new(Peer {
                    node: topology.local_consensus_node_id().unwrap(),
                    identity,
                    handler: tokio::sync::RwLock::new(None),
                    engine_calls: Mutex::new(BTreeMap::new()),
                    successful_appends: AtomicU64::new(0),
                    last_cut: Mutex::new(None),
                    blocked_senders: Mutex::new(BTreeSet::new()),
                    blocked_append_above: Mutex::new(None),
                    held_reply: Mutex::new(None),
                    cut_mutation: Mutex::new(None),
                })
            })
            .collect();
        Self {
            directory,
            topologies,
            peers,
            stores: vec![None; voters],
        }
    }

    fn store(&self, index: usize) -> &ConsensusSessionStore {
        self.stores[index].as_ref().unwrap()
    }

    fn set_link(&self, sender: usize, target: usize, enabled: bool) {
        let mut blocked = self.peers[target].blocked_senders.lock().unwrap();
        if enabled {
            blocked.remove(&self.peers[sender].node);
        } else {
            blocked.insert(self.peers[sender].node);
        }
    }

    async fn open(
        &mut self,
        index: usize,
        mode: SessionPersistenceMode,
    ) -> Result<(), ConsensusSessionStoreOpenError> {
        self.open_with_hook(index, mode, None).await
    }

    async fn open_with_hook(
        &mut self,
        index: usize,
        mode: SessionPersistenceMode,
        hook: Option<GenerationHook>,
    ) -> Result<(), ConsensusSessionStoreOpenError> {
        self.open_with_hooks(index, mode, hook, None).await
    }

    async fn open_with_hooks(
        &mut self,
        index: usize,
        mode: SessionPersistenceMode,
        hook: Option<GenerationHook>,
        root_hook: Option<crate::sqlite::consensus::wal::owner::RootHookForTest>,
    ) -> Result<(), ConsensusSessionStoreOpenError> {
        assert!(self.stores[index].is_none());
        let backend =
            SqliteSessionBackend::open(self.directory.path().join(format!("node-{index}.sqlite")))
                .unwrap();
        if let Some(hook) = hook {
            backend
                .native_owner
                .as_ref()
                .unwrap()
                .set_generation_hook_for_test(hook);
        }
        if let Some(hook) = root_hook {
            backend
                .native_owner
                .as_ref()
                .unwrap()
                .set_root_hook_for_test(hook);
        }
        let peers = self
            .peers
            .iter()
            .enumerate()
            .filter(|(peer, _)| *peer != index)
            .map(|(_, peer)| {
                let transport: Arc<dyn SessionConsensusPeer> = peer.clone();
                (peer.node, transport)
            })
            .collect();
        let store = ConsensusSessionStore::open_fixed_quorum_with_clock_and_persistence(
            self.topologies[index].clone(),
            backend,
            self.directory.path().join(format!("snapshots-{index}")),
            peers,
            Arc::new(SystemClock),
            OPERATION_BOUND,
            SnapshotIntegrityPolicy::PortableVerified,
            mode,
        )
        .await?;
        assert_eq!(store.persistence_mode(), mode);
        assert_eq!(store.inner.operation_timeout, OPERATION_BOUND);
        *self.peers[index].handler.write().await = Some(store.rpc_handler());
        self.stores[index] = Some(store);
        Ok(())
    }

    async fn start(&mut self) {
        for index in 0..self.stores.len() {
            self.open(index, SessionPersistenceMode::Async)
                .await
                .unwrap();
        }
        self.form().await;
    }

    async fn form(&self) {
        let results = join_all(
            self.stores
                .iter()
                .flatten()
                .map(ConsensusSessionStore::initialize_cluster),
        )
        .await;
        assert!(
            results.iter().all(Result::is_ok),
            "ordinary formation: {results:?}"
        );
        self.ready().await;
    }

    async fn ready(&self) {
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let ready = join_all(
                    self.stores
                        .iter()
                        .flatten()
                        .map(ConsensusSessionStore::probe_fixed_quorum_readiness),
                )
                .await;
                if ready
                    .iter()
                    .all(|report| report.traffic_authority().is_granted())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("ordinary quorum readiness");
    }

    fn leader(&self) -> usize {
        self.stores
            .iter()
            .position(|store| {
                store.as_ref().is_some_and(|store| {
                    let status = store.status();
                    status.leader_id == Some(status.node_id)
                })
            })
            .expect("live quorum leader")
    }

    fn engine_calls_from(&self, sender: SessionConsensusNodeId) -> u64 {
        self.peers
            .iter()
            .map(|peer| {
                peer.engine_calls
                    .lock()
                    .unwrap()
                    .get(&sender)
                    .copied()
                    .unwrap_or(0)
            })
            .sum()
    }

    fn selector(&self, index: usize) -> Vec<u8> {
        std::fs::read(
            self.directory
                .path()
                .join(format!("node-{index}.sqlite.native-wal/CURRENT")),
        )
        .unwrap()
    }

    async fn close(&mut self, index: usize) {
        self.close_result(index).await.unwrap();
    }

    async fn close_result(&mut self, index: usize) -> Result<(), StoreError> {
        *self.peers[index].handler.write().await = None;
        if let Some(store) = self.stores[index].take() {
            return store.shutdown().await;
        }
        Ok(())
    }

    async fn close_all(&mut self) {
        let mut results = Vec::new();
        for index in 0..self.stores.len() {
            results.push(self.close_result(index).await);
        }
        assert!(
            results.iter().all(Result::is_ok),
            "ordinary shutdown: {results:?}"
        );
    }
}

fn provider() -> Arc<MemoryKeyProvider> {
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("async-public-key").unwrap(),
            KeyPurpose::Session,
            TenantId::new("async-public").unwrap(),
            Zeroizing::new([0x74; 32]),
        )
        .unwrap();
    provider
}

async fn create_request(
    store: &ConsensusSessionStore,
    index: usize,
    provider: &MemoryKeyProvider,
) -> FencedTransitionV2Request {
    let key = SessionKey {
        tenant: TenantId::new("async-public").unwrap(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(format!("async-public-{index}"))
            .try_into()
            .unwrap(),
    };
    let fence = store
        .observe_fenced_transition(&key)
        .await
        .unwrap_or_else(|error| panic!("ordinary fence observation {index}: {error:?}"))
        .current_fence();
    let owner = OwnerId::new(format!("async-public-owner-{index}")).unwrap();
    let lease =
        FencedTransitionLease::acquire(key.clone(), owner.clone(), fence, Duration::from_secs(60))
            .unwrap();
    let mut record = StoredSessionRecord {
        key,
        generation: Generation::new(1),
        owner,
        fence: FenceToken::new(fence.get() + 1),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("async-public"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(b"ordinary async quorum data"),
    };
    record.payload = EncryptedSessionPayload::encrypt(provider, &record, "async-public")
        .await
        .unwrap();
    FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(1).unwrap(),
        FencedTransitionV2CallerNonce::from_bytes((index as u128).to_be_bytes()),
        lease,
        FencedTransitionMutation::create(record),
    )
    .unwrap()
}

async fn create(
    store: &ConsensusSessionStore,
    request: &FencedTransitionV2Request,
) -> FencedTransitionOutcome {
    let mut result = store
        .fenced_transition_v2_batch(vec![request.clone()])
        .await
        .unwrap();
    assert_eq!(result.len(), 1);
    let outcome = result.remove(0).unwrap();
    assert!(outcome.matches_v2_request(request));
    assert_eq!(outcome.mutation(), FencedTransitionMutationResult::Created);
    assert_eq!(outcome.committed_generation(), Generation::new(1));
    outcome
}

async fn assert_recorded(
    store: &ConsensusSessionStore,
    request: &FencedTransitionV2Request,
    outcome: &FencedTransitionOutcome,
) {
    let status = store.fenced_transition_v2_status(request).await.unwrap();
    assert!(
        matches!(status, FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(outcome.clone()))
    );
}

fn wire<T: Serialize>(
    store: &ConsensusSessionStore,
    sender: SessionConsensusNodeId,
    mode: SessionPersistenceMode,
    family: SessionConsensusRpcFamily,
    body: &T,
) -> SessionConsensusWireRequest {
    let payload = persistence_protocol::wrap_payload(
        mode,
        encode_bounded(body).unwrap(),
        family.max_request_payload_bytes(),
    )
    .unwrap();
    SessionConsensusWireRequest::try_new(store.inner.storage_identity, sender, family, payload)
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_persistence_public_reopen_requires_live_cut_and_local_application() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        let leader = fleet.leader();
        let follower = (leader + 1) % 3;
        let provider = provider();
        let first = create_request(fleet.store(leader), 1, &provider).await;
        let first_outcome = create(fleet.store(leader), &first).await;
        // V2 activation does not establish the separate V1 certificate used
        // by observe_fenced_transition. Establish that public startup fact
        // while all voters are present before testing quorum-only traffic.
        assert!(!fleet
            .store(leader)
            .activated_fenced_transition_scope_is_current()
            .await
            .unwrap());
        fleet
            .store(leader)
            .activate_fenced_transition_capability()
            .await
            .unwrap();
        assert!(fleet
            .store(leader)
            .activated_fenced_transition_scope_is_current()
            .await
            .unwrap());
        for store in fleet.stores.iter().flatten() {
            assert_recorded(store, &first, &first_outcome).await;
            assert_eq!(
                store.probe_durable_readiness().await.state(),
                DurableReadinessState::PersistenceNotDurable
            );
            assert_eq!(
                store
                    .probe_fixed_durable_quorum_readiness()
                    .await
                    .traffic_authority(),
                FixedQuorumTrafficAuthority::PersistenceNotDurable
            );
            let health = store.drain_async_persistence().await.unwrap();
            assert!(health.asynchronous.unwrap().completed_generation > 0);
        }
        fleet.close(follower).await;
        let second = create_request(fleet.store(leader), 2, &provider).await;
        let second_outcome = create(fleet.store(leader), &second).await;
        fleet
            .open(follower, SessionPersistenceMode::Async)
            .await
            .unwrap();
        let cold = fleet.store(follower).clone();
        assert_eq!(
            cold.persistence_health().recovery,
            Some(SessionAsyncRecoveryState::AwaitingLiveQuorum)
        );
        assert!(!cold.status().admitted);
        assert_eq!(
            cold.probe_fixed_quorum_readiness()
                .await
                .traffic_authority(),
            FixedQuorumTrafficAuthority::RecoveryRequired
        );
        assert!(cold.fenced_transition_v2_status(&second).await.is_err());
        let previous_vote = cold.inner.raft.metrics().borrow().vote;
        let sender = fleet.peers[leader].node;
        let vote = VoteRequest {
            vote: Vote::new(previous_vote.leader_id.term + 20, sender),
            last_log_id: cold.inner.raft.metrics().borrow().last_applied,
        };
        let response = cold
            .rpc_handler()
            .handle(
                sender,
                wire(
                    &cold,
                    sender,
                    SessionPersistenceMode::Async,
                    SessionConsensusRpcFamily::Vote,
                    &vote,
                ),
            )
            .await;
        assert_eq!(response.result, Err(SessionConsensusPeerError::Rejected));
        assert_eq!(cold.inner.raft.metrics().borrow().vote, previous_vote);
        let held_apply = Arc::clone(&cold.inner.backend.consensus_apply_gate)
            .acquire_owned()
            .await
            .unwrap();
        let appends = fleet.peers[follower]
            .successful_appends
            .load(Ordering::Acquire);
        let before_index = fleet
            .store(leader)
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index;
        let initialized = {
            let cold = cold.clone();
            tokio::spawn(async move { cold.initialize_cluster().await })
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if cold.persistence_health().recovery == Some(SessionAsyncRecoveryState::CatchingUp)
                    && fleet.peers[follower]
                        .successful_appends
                        .load(Ordering::Acquire)
                        > appends
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("real matching append while application is held");
        assert!(!cold.inner.persistence_protocol.is_active());
        assert!(!cold.status().admitted);
        assert!(!cold
            .activate_caught_up_async_before(
                cold.operation_deadline_from(tokio::time::Instant::now())
            )
            .await
            .unwrap());
        let cut = fleet.peers[leader].last_cut.lock().unwrap().unwrap();
        assert!(Some(cut.barrier.index) > before_index);
        assert_eq!(cut.requester, cold.inner.local_node_id);
        assert_eq!(
            cut.vote,
            fleet.store(leader).inner.raft.metrics().borrow().vote
        );
        drop(held_apply);
        initialized.await.unwrap().unwrap();
        assert_eq!(
            cold.persistence_health().recovery,
            Some(SessionAsyncRecoveryState::Active)
        );
        assert!(cold
            .probe_fixed_quorum_readiness()
            .await
            .traffic_authority()
            .is_granted());
        assert_recorded(&cold, &first, &first_outcome).await;
        assert_recorded(&cold, &second, &second_outcome).await;
        let drained = cold
            .drain_async_persistence()
            .await
            .unwrap()
            .asynchronous
            .unwrap();
        assert!(drained
            .completed_applied_index
            .is_some_and(|index| index >= cut.barrier.index));
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_persistence_all_cold_roots_withhold_votes_and_restored_leader_traffic() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        fleet.start().await;
        let leader = fleet.leader();
        let former_leader = fleet.peers[leader].node;
        for store in fleet.stores.iter().flatten() {
            store.drain_async_persistence().await.unwrap();
        }
        fleet.close_all().await;
        let before = fleet.engine_calls_from(former_leader);
        for index in 0..3 {
            fleet
                .open(index, SessionPersistenceMode::Async)
                .await
                .unwrap();
        }
        let restored = fleet.store(leader);
        assert_eq!(
            restored
                .inner
                .raft
                .metrics()
                .borrow()
                .vote
                .leader_id
                .voted_for(),
            Some(former_leader)
        );
        assert!(restored.inner.raft.metrics().borrow().vote.is_committed());
        restored.inner.raft.trigger().elect().await.unwrap();
        let results = join_all(
            fleet
                .stores
                .iter()
                .flatten()
                .map(ConsensusSessionStore::initialize_cluster),
        )
        .await;
        assert!(
            results
                .iter()
                .all(|result| *result == Err(ConsensusSessionStoreOpenError::RecoveryRequired)),
            "all-cold results: {results:?}"
        );
        assert_eq!(
            fleet.engine_calls_from(former_leader),
            before,
            "restored leader/manual campaign must not reach live peers"
        );
        for store in fleet.stores.iter().flatten() {
            assert!(!store.status().admitted);
            assert_eq!(
                store.persistence_health().recovery,
                Some(SessionAsyncRecoveryState::AwaitingLiveQuorum)
            );
            assert_eq!(
                store
                    .probe_fixed_quorum_readiness()
                    .await
                    .traffic_authority(),
                FixedQuorumTrafficAuthority::RecoveryRequired
            );
        }
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_persistence_public_mode_isolation_precedes_engine_and_control_mutation() {
    let _timing = crate::acquire_consensus_timing_test_permit().await;
    let mut fleet = Fleet::new(3);
    let result = AssertUnwindSafe(async {
        for (index, mode) in [
            SessionPersistenceMode::Async,
            SessionPersistenceMode::Durable,
            SessionPersistenceMode::Async,
        ]
        .into_iter()
        .enumerate()
        {
            fleet.open(index, mode).await.unwrap();
        }
        for (target, source) in [(0, 1), (1, 0)] {
            let store = fleet.store(target);
            let sender = fleet.peers[source].node;
            let wrong_mode = fleet.store(source).persistence_mode();
            let previous = store.inner.raft.metrics().borrow().clone();
            let vote = VoteRequest {
                vote: Vote::new(90, sender),
                last_log_id: Some(LogId::new(CommittedLeaderId::new(89, sender), 50)),
            };
            let response = store
                .rpc_handler()
                .handle(
                    sender,
                    wire(
                        store,
                        sender,
                        wrong_mode,
                        SessionConsensusRpcFamily::Vote,
                        &vote,
                    ),
                )
                .await;
            assert_eq!(
                response.result,
                Err(SessionConsensusPeerError::ScopeMismatch)
            );
            let response = store
                .rpc_handler()
                .handle(
                    sender,
                    wire(
                        store,
                        sender,
                        wrong_mode,
                        SessionConsensusRpcFamily::ReadBarrier,
                        &ReadBarrierRequest,
                    ),
                )
                .await;
            assert_eq!(
                response.result,
                Err(SessionConsensusPeerError::ScopeMismatch)
            );
            assert_eq!(store.inner.raft.metrics().borrow().vote, previous.vote);
            assert_eq!(
                store.inner.raft.metrics().borrow().last_log_index,
                previous.last_log_index
            );
        }
        assert_eq!(
            fleet.store(1).drain_async_persistence().await,
            Err(SessionPersistenceDrainError::NotAsync)
        );
        fleet.close_all().await;
        for (index, wrong) in [
            (0, SessionPersistenceMode::Durable),
            (1, SessionPersistenceMode::Async),
        ] {
            let selector = fleet.selector(index);
            assert_eq!(
                fleet.open(index, wrong).await,
                Err(ConsensusSessionStoreOpenError::PersistenceModeMismatch)
            );
            assert_eq!(fleet.selector(index), selector);
        }
    })
    .catch_unwind()
    .await;
    fleet.close_all().await;
    result.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
}

#[tokio::test]
async fn async_persistence_wire_bounds_full_lineage_and_attempt_replacement() {
    let fleet = Fleet::new(3);
    let leader = fleet.peers[0].node;
    let protocol = PersistenceProtocol::new(SessionPersistenceMode::Async, true);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let first = protocol.quarantine_before(deadline).await.unwrap();
    let encoded = encode_bounded(&first).unwrap();
    assert!(encoded.starts_with(persistence_protocol::COLD_BARRIER_WIRE));
    assert!(decode_bounded::<ReadBarrierRequest>(&encoded).is_err());
    let family = SessionConsensusRpcFamily::ReadBarrier;
    let durable = persistence_protocol::wrap_payload(
        SessionPersistenceMode::Durable,
        encoded.clone(),
        family.max_request_payload_bytes(),
    )
    .unwrap();
    assert_eq!(durable, encoded, "Durable payload bytes are unchanged");
    let tagged = persistence_protocol::wrap_payload(
        SessionPersistenceMode::Async,
        encoded.clone(),
        family.max_request_payload_bytes(),
    )
    .unwrap();
    assert_eq!(
        persistence_protocol::unwrap_payload(SessionPersistenceMode::Async, &tagged).unwrap(),
        encoded
    );
    assert!(
        persistence_protocol::unwrap_payload(SessionPersistenceMode::Durable, &tagged).is_err()
    );
    assert!(decode_bounded::<VoteRequest<SessionConsensusNodeId>>(&tagged).is_err());
    let overhead = tagged.len() - encoded.len();
    let largest = vec![0; family.max_request_payload_bytes() - overhead];
    assert!(persistence_protocol::payload_fits(
        SessionPersistenceMode::Async,
        family,
        largest.len()
    ));
    assert_eq!(
        persistence_protocol::wrap_payload(
            SessionPersistenceMode::Async,
            largest,
            family.max_request_payload_bytes()
        )
        .unwrap()
        .len(),
        family.max_request_payload_bytes()
    );
    assert!(!persistence_protocol::payload_fits(
        SessionPersistenceMode::Async,
        family,
        family.max_request_payload_bytes() - overhead + 1
    ));
    assert!(persistence_protocol::wrap_payload(
        SessionPersistenceMode::Async,
        vec![0; family.max_request_payload_bytes() - overhead + 1],
        family.max_request_payload_bytes()
    )
    .is_err());
    let cut = ColdQuorumCut {
        identity: fleet.peers[0].identity,
        request: first,
        requester: fleet.peers[1].node,
        voters: [0; 32],
        membership: None,
        vote: Vote::new_committed(8, leader),
        barrier: LogId::new(CommittedLeaderId::new(8, leader), 100),
    };
    protocol.accept_cut_before(cut, deadline).await.unwrap();
    let guard = protocol.engine_before(deadline).await.unwrap();
    assert!(!guard.permits_vote());
    for wrong in [
        LogId::new(CommittedLeaderId::new(9, leader), 7),
        LogId::new(CommittedLeaderId::new(9, leader), 100),
        LogId::new(CommittedLeaderId::new(8, leader), 99),
    ] {
        assert!(!persistence_protocol::covers(wrong, cut.barrier));
        assert!(!guard.permits_append(&AppendEntriesRequest {
            vote: cut.vote,
            prev_log_id: Some(cut.barrier),
            entries: vec![],
            leader_commit: Some(wrong)
        }));
        guard.confirm_append(Some(wrong));
    }
    // A request ending before the barrier cannot enlarge its matched range
    // merely by advertising a later leader_commit.
    let short = LogId::new(CommittedLeaderId::new(8, leader), 99);
    assert!(guard.permits_append(&AppendEntriesRequest {
        vote: cut.vote,
        prev_log_id: Some(short),
        entries: vec![],
        leader_commit: Some(cut.barrier)
    }));
    guard.confirm_append(Some(short));
    drop(guard);
    assert!(!protocol
        .activate_before(deadline, |_| async { true })
        .await
        .unwrap());
    let old = protocol.engine_before(deadline).await.unwrap();
    old.confirm_append(Some(cut.barrier));
    // Replacement cannot pass accepted work's owned read fence.
    let replacement = protocol.quarantine_before(deadline);
    tokio::pin!(replacement);
    assert!(futures_util::poll!(replacement.as_mut()).is_pending());
    drop(old);
    let second = replacement.await.unwrap();
    assert!(
        first.incarnation == second.incarnation
            && second.attempt == first.attempt + 1
            && first.nonce != second.nonce
    );
    assert!(protocol.accept_cut_before(cut, deadline).await.is_err());
    protocol
        .accept_cut_before(
            ColdQuorumCut {
                request: second,
                ..cut
            },
            deadline,
        )
        .await
        .unwrap();
    assert!(
        !protocol
            .activate_before(deadline, |_| async { true })
            .await
            .unwrap(),
        "old confirmation cannot activate the replacement attempt"
    );
}
