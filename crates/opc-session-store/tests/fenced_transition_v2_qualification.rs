//! Long-running SDK-702 V2 history qualification.
//!
//! This is deliberately ignored in ordinary CI.  It uses three real fixed
//! durable-quorum voters and their public proposal/apply APIs; it never seeds
//! the receipt table or invokes a private state-machine helper.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::StreamExt;
use opc_consensus::{
    ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
    DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_session_store::{
    derive_fixed_durable_quorum_consensus_identity, fenced_transition_v2_profile_digest, Clock,
    ConsensusSessionStore, EncryptedSessionPayload, FenceToken, FencedTransitionLease,
    FencedTransitionMutation, FencedTransitionMutationResult, FencedTransitionOutcome,
    FencedTransitionV2CallerNonce, FencedTransitionV2HistoryEpoch, FencedTransitionV2HistoryState,
    FencedTransitionV2Request, FencedTransitionV2Status, Generation, OwnerId,
    PlacementResiliencePolicy, QuorumReplicaDescriptor, QuorumTopologyConfig,
    ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
    SessionBackend, SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcHandler, SessionConsensusWireRequest, SessionConsensusWireResponse,
    SessionKey, SessionKeyType, SqliteSessionBackend, StateClass, StateType, StoreError,
    StoredSessionRecord, Timestamp, ValidatedQuorumTopology,
    FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES, FENCED_TRANSITION_V2_RECLAIM_BATCH,
    FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET,
};
use opc_types::{NetworkFunctionKind, TenantId};

const VOTERS: usize = 3;
const QUALIFICATION_SESSIONS: usize = 50_000;
const QUALIFICATION_TRANSITIONS: usize = FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES + 1;
const QUALIFICATION_HEADROOM_TRANSITIONS: usize =
    FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET;
const RECLAIM_BATCHES: usize =
    FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES / FENCED_TRANSITION_V2_RECLAIM_BATCH;
// Match the fixed durable quorum's bounded proposal-admission capacity. This
// represents a small, realistic client burst while leaving consensus itself to
// serialize and durably apply every proposal on the three voters.
const QUALIFICATION_IN_FLIGHT_CLIENTS: usize = DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS;
const QUALIFICATION_TRANSIENT_RETRY_LIMIT: usize = 16;
const FIXED_V2_PROFILE_DIGEST: [u8; 32] = [
    0xbf, 0x22, 0x10, 0xe0, 0x9a, 0x84, 0xb4, 0x17, 0xb7, 0x27, 0x06, 0x46, 0x82, 0x1b, 0x87, 0xa7,
    0x3d, 0x1a, 0x87, 0x50, 0x38, 0x21, 0xfc, 0x44, 0x92, 0x2d, 0xb2, 0x2e, 0x04, 0x87, 0x9d, 0x15,
];

#[derive(Debug, Clone)]
struct MutableClock(Arc<Mutex<Timestamp>>);

impl MutableClock {
    fn new(now: Timestamp) -> Self {
        Self(Arc::new(Mutex::new(now)))
    }

    fn set(&self, now: Timestamp) {
        *self.0.lock().expect("qualification clock mutex") = now;
    }
}

impl Clock for MutableClock {
    fn now_utc(&self) -> Timestamp {
        *self.0.lock().expect("qualification clock mutex")
    }
}

async fn retry_exact_consensus_operation<T, Operation, OperationFuture>(
    transient_retries: &AtomicU64,
    mut operation: Operation,
) -> Result<T, StoreError>
where
    Operation: FnMut() -> OperationFuture,
    OperationFuture: Future<Output = Result<T, StoreError>>,
{
    for attempt in 0..=QUALIFICATION_TRANSIENT_RETRY_LIMIT {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(StoreError::BackendUnavailable(_) | StoreError::FencedTransitionOutcomeUnknown)
                if attempt < QUALIFICATION_TRANSIENT_RETRY_LIMIT =>
            {
                transient_retries.fetch_add(1, Ordering::Relaxed);
                // The operation-level deadline has already expired. Yield a
                // fresh scheduling turn before repeating the same read or the
                // exact same self-authenticating request ID. An ambiguous
                // write is never replaced with a new ID.
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("the bounded retry loop returns on its final attempt")
}

/// Retry an ambiguous lifecycle CAS only after a fresh linearized history read
/// proves whether that exact CAS changed durable state.  Maintenance has no
/// caller-supplied request ID, so replaying it blindly after a lost reply could
/// run the next ordered batch instead of the original one.
async fn maintain_exact_history_batch(
    store: &ConsensusSessionStore,
    expected: FencedTransitionV2HistoryState,
    transient_retries: &AtomicU64,
) -> Result<FencedTransitionV2HistoryState, StoreError> {
    for attempt in 0..=QUALIFICATION_TRANSIENT_RETRY_LIMIT {
        match store.maintain_fenced_transition_v2_history(expected).await {
            Ok(state) => return Ok(state),
            // `EpochNotActive` can be the post-commit observation of this
            // exact expected state after its reply was lost.  This helper is
            // used only for the eligible retirement sequence below; it never
            // treats that error itself as success.
            Err(
                StoreError::BackendUnavailable(_)
                | StoreError::FencedTransitionHistoryEpochNotActive,
            ) if attempt < QUALIFICATION_TRANSIENT_RETRY_LIMIT => {
                transient_retries.fetch_add(1, Ordering::Relaxed);
                let observed = retry_exact_consensus_operation(transient_retries, || {
                    store.fenced_transition_v2_history_state()
                })
                .await?;
                if observed != expected {
                    return Ok(observed);
                }
                // The linearized state is unchanged, so this is still the
                // same lifecycle CAS, not an inferred successful batch.
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("the bounded maintenance retry loop returns on its final attempt")
}

#[derive(Clone)]
struct ScopedLoopbackPeer {
    node_id: SessionConsensusNodeId,
    identity: ConsensusIdentity,
    handler: Arc<tokio::sync::RwLock<Option<Arc<dyn SessionConsensusRpcHandler>>>>,
}

impl ScopedLoopbackPeer {
    fn new(node_id: SessionConsensusNodeId, identity: ConsensusIdentity) -> Self {
        Self {
            node_id,
            identity,
            handler: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    async fn install(&self, handler: Arc<dyn SessionConsensusRpcHandler>) {
        *self.handler.write().await = Some(handler);
    }
}

impl fmt::Debug for ScopedLoopbackPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScopedLoopbackPeer")
            .field("node_id", &self.node_id)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SessionConsensusPeer for ScopedLoopbackPeer {
    fn node_id(&self) -> SessionConsensusNodeId {
        self.node_id
    }

    fn scope_identity(&self) -> Option<ConsensusIdentity> {
        Some(self.identity)
    }

    async fn call(
        &self,
        request: SessionConsensusWireRequest,
    ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
        let handler = self
            .handler
            .read()
            .await
            .clone()
            .ok_or(SessionConsensusPeerError::Unavailable)?;
        Ok(handler.handle(request.sender, request).await)
    }
}

fn replica_id(index: usize) -> ReplicaId {
    ReplicaId::new(format!("sdk-702-qualification-voter-{index}")).expect("replica ID")
}

fn members() -> Vec<QuorumReplicaDescriptor> {
    (0..VOTERS)
        .map(|index| {
            QuorumReplicaDescriptor::new(
                replica_id(index),
                ReplicaEndpoint::new(format!("sdk-702-qualification-voter-{index}.invalid"), 7443)
                    .expect("endpoint"),
                ReplicaTlsIdentity::new(format!(
                    "spiffe://test/session/sdk-702-qualification/{index}"
                ))
                .expect("TLS identity"),
                ReplicaFailureDomain::new(format!("sdk-702-qualification-zone-{index}"))
                    .expect("failure domain"),
                ReplicaBackingIdentity::new(format!("sdk-702-qualification-disk-{index}"))
                    .expect("backing identity"),
            )
        })
        .collect()
}

fn fixed_identity(
    members: &[QuorumReplicaDescriptor],
    placement_policy: PlacementResiliencePolicy,
) -> ConsensusIdentity {
    let cluster_id = ConsensusClusterId::new("sdk-702-v2-qualification").expect("cluster ID");
    let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
    let fingerprints = members
        .iter()
        .map(QuorumReplicaDescriptor::configuration_fingerprint)
        .collect::<Vec<_>>();
    derive_fixed_durable_quorum_consensus_identity(
        cluster_id,
        epoch,
        &fingerprints,
        placement_policy,
    )
}

fn fixed_topology(
    local_index: usize,
    members: Vec<QuorumReplicaDescriptor>,
    placement_policy: PlacementResiliencePolicy,
) -> ValidatedQuorumTopology {
    let identity = fixed_identity(&members, placement_policy);
    ValidatedQuorumTopology::try_from_fixed_durable_quorum_with_placement_policy(
        QuorumTopologyConfig::new_consensus(replica_id(local_index), members, identity),
        placement_policy,
    )
    .expect("fixed durable quorum topology")
}

async fn fixed_cluster(
    directory: &Path,
    clock: Arc<dyn Clock>,
) -> (
    Vec<ConsensusSessionStore>,
    Vec<std::path::PathBuf>,
    Vec<std::path::PathBuf>,
) {
    let placement_policy = PlacementResiliencePolicy::default();
    let members = members();
    let identity = fixed_identity(&members, placement_policy);
    let topologies = (0..VOTERS)
        .map(|index| fixed_topology(index, members.clone(), placement_policy))
        .collect::<Vec<_>>();
    let node_ids = topologies
        .iter()
        .map(|topology| topology.local_consensus_node_id().expect("node ID"))
        .collect::<Vec<_>>();
    let database_paths = (0..VOTERS)
        .map(|index| directory.join(format!("voter-{index}.sqlite")))
        .collect::<Vec<_>>();
    let snapshot_paths = (0..VOTERS)
        .map(|index| directory.join(format!("snapshots-{index}")))
        .collect::<Vec<_>>();
    let mut paths = BTreeMap::new();
    for source in 0..VOTERS {
        for (target, node_id) in node_ids.iter().copied().enumerate() {
            if source != target {
                paths.insert(
                    (source, target),
                    Arc::new(ScopedLoopbackPeer::new(node_id, identity)),
                );
            }
        }
    }

    let mut stores = Vec::with_capacity(VOTERS);
    for source in 0..VOTERS {
        let peers = (0..VOTERS)
            .filter(|target| *target != source)
            .map(|target| {
                let peer: Arc<dyn SessionConsensusPeer> = paths
                    .get(&(source, target))
                    .expect("exact fixed peer")
                    .clone();
                (node_ids[target], peer)
            })
            .collect::<BTreeMap<_, _>>();
        stores.push(
            ConsensusSessionStore::open_fixed_durable_quorum_with_clock(
                topologies[source].clone(),
                SqliteSessionBackend::open(&database_paths[source]).expect("SQLite voter"),
                &snapshot_paths[source],
                peers,
                Arc::clone(&clock),
                Duration::from_secs(10),
            )
            .await
            .expect("open fixed voter"),
        );
    }
    for ((_, target), peer) in &paths {
        peer.install(stores[*target].rpc_handler()).await;
    }
    for result in
        futures_util::future::join_all(stores.iter().map(ConsensusSessionStore::initialize_cluster))
            .await
    {
        result.expect("initialize fixed durable quorum");
    }
    (stores, database_paths, snapshot_paths)
}

async fn ready_leader(stores: &[ConsensusSessionStore]) -> usize {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let readiness = futures_util::future::join_all(
                stores
                    .iter()
                    .map(ConsensusSessionStore::probe_durable_readiness),
            )
            .await;
            let statuses = stores
                .iter()
                .map(ConsensusSessionStore::status)
                .collect::<Vec<_>>();
            if readiness.iter().all(|report| report.is_ready())
                && statuses.iter().all(|status| status.admitted)
                && statuses
                    .first()
                    .and_then(|status| status.leader_id)
                    .is_some_and(|leader| {
                        statuses
                            .iter()
                            .all(|status| status.leader_id == Some(leader))
                    })
            {
                let leader = statuses[0].leader_id.expect("known fixed-quorum leader");
                return statuses
                    .iter()
                    .position(|status| status.node_id == leader)
                    .expect("leader is an exact fixed voter");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fixed quorum reaches durable readiness and elects a leader")
}

fn key(index: usize) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("sdk-702-v2-qualification").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(format!("unique-transition-{index}"))
            .try_into()
            .expect("stable ID"),
    }
}

fn owner() -> OwnerId {
    OwnerId::new("sdk-702-v2-qualification-owner").expect("owner")
}

fn sealing_provider() -> MemoryKeyProvider {
    let provider = MemoryKeyProvider::new();
    provider
        .insert_active_key(
            KeyId::new("sdk-702-v2-qualification-key").expect("key ID"),
            KeyPurpose::Session,
            TenantId::new("sdk-702-v2-qualification").expect("tenant"),
            Zeroizing::new([0x72; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("active session key");
    provider
}

async fn create_request(
    index: usize,
    history_epoch: FencedTransitionV2HistoryEpoch,
    key: SessionKey,
    fence: FenceToken,
    provider: &MemoryKeyProvider,
) -> FencedTransitionV2Request {
    let owner = owner();
    let lease =
        FencedTransitionLease::acquire(key.clone(), owner.clone(), fence, Duration::from_secs(60))
            .expect("acquire request");
    let mut record = StoredSessionRecord {
        key,
        generation: Generation::new(1),
        owner,
        fence: FenceToken::new(fence.get() + 1),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("sdk-702-v2-qualification"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"qualification")),
    };
    record.payload =
        EncryptedSessionPayload::encrypt(provider, &record, "sdk-702-v2-qualification")
            .await
            .expect("seal qualification transition payload");
    let nonce = FencedTransitionV2CallerNonce::from_bytes((index as u128).to_be_bytes());
    FencedTransitionV2Request::new(
        history_epoch,
        nonce,
        lease,
        FencedTransitionMutation::create(record),
    )
    .expect("self-authenticating request")
}

async fn renew_update_request(
    index: usize,
    history_epoch: FencedTransitionV2HistoryEpoch,
    previous: &FencedTransitionOutcome,
    provider: &MemoryKeyProvider,
) -> FencedTransitionV2Request {
    let key = previous.lease().key().clone();
    let owner = previous.lease().owner().clone();
    let fence = previous.lease().fence();
    let expected_generation = previous.committed_generation();
    let generation = expected_generation
        .next()
        .expect("qualification generation has headroom");
    let lease = FencedTransitionLease::renew(previous.lease().clone(), Duration::from_secs(60))
        .expect("renew request");
    let mut record = StoredSessionRecord {
        key,
        generation,
        owner,
        fence,
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("sdk-702-v2-qualification"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"qualification-update")),
    };
    record.payload =
        EncryptedSessionPayload::encrypt(provider, &record, "sdk-702-v2-qualification")
            .await
            .expect("seal qualification update payload");
    let nonce = FencedTransitionV2CallerNonce::from_bytes((index as u128).to_be_bytes());
    FencedTransitionV2Request::new(
        history_epoch,
        nonce,
        lease,
        FencedTransitionMutation::update(expected_generation, record),
    )
    .expect("self-authenticating update request")
}

fn request_with_changed_body(request: &FencedTransitionV2Request) -> FencedTransitionV2Request {
    let mut encoded = serde_json::to_value(request).expect("serialize retained V2 request");
    let record = encoded
        .get_mut("mutation")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|mutation| mutation.get_mut("create"))
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|create| create.get_mut("record"))
        .and_then(serde_json::Value::as_object_mut)
        .expect("V2 create request record");
    record.insert(
        "state_type".to_owned(),
        serde_json::Value::String("sdk-702-v2-qualification-altered".to_owned()),
    );
    serde_json::from_value(encoded).expect("deserialize altered V2 request")
}

fn directory_bytes(path: &Path) -> u64 {
    std::fs::read_dir(path)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .map(|entry| {
            let path = entry.path();
            let metadata = entry.metadata().expect("qualification file metadata");
            if metadata.is_dir() {
                directory_bytes(&path)
            } else {
                metadata.len()
            }
        })
        .sum()
}

fn sqlite_database_family_bytes(path: &Path) -> u64 {
    ["", "-wal", "-shm", "-journal"]
        .into_iter()
        .filter_map(|suffix| {
            let mut candidate = path.as_os_str().to_os_string();
            candidate.push(suffix);
            std::fs::metadata(std::path::PathBuf::from(candidate))
                .ok()
                .map(|metadata| metadata.len())
        })
        .sum()
}

#[tokio::test]
async fn fixed_quorum_first_v2_transition_activates_and_applies_on_every_voter() {
    let directory = tempfile::tempdir().expect("fixed-quorum V2 directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("fixed-quorum V2 start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (stores, _, _) = fixed_cluster(directory.path(), clock).await;
    let leader = ready_leader(&stores).await;
    let provider = sealing_provider();
    let key = key(0);
    let observation = stores[leader]
        .observe_fenced_transition(&key)
        .await
        .expect("fixed-quorum fence observation");
    let transition = create_request(
        0,
        FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch"),
        key,
        observation.current_fence(),
        &provider,
    )
    .await;
    let outcome = stores[leader]
        .fenced_transition_v2(transition.clone())
        .await
        .expect("first fixed-quorum V2 transition");
    assert!(matches!(
        outcome.mutation(),
        FencedTransitionMutationResult::Created
    ));

    for voter in &stores {
        let history = voter
            .fenced_transition_v2_history_state()
            .await
            .expect("V2 history on every voter");
        assert_eq!(history.bound_entries(), 1);
        assert!(matches!(
            voter
                .fenced_transition_v2_status(&transition)
                .await
                .expect("V2 receipt on every voter"),
            FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(outcome.clone())
        ));
    }
}

/// Release qualification for V2 capacity and retired-history reclamation.
/// Its shared injected clock advances through a consensus read barrier, never
/// by SQLite mutation or a wall-clock sleep.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "131,073 real fixed-quorum consensus transitions are release qualification"]
async fn sustained_131073_unique_v2_transitions_bind_exact_epoch_capacity() {
    let started = Instant::now();
    let directory = tempfile::tempdir().expect("qualification directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("qualification start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (stores, database_paths, snapshot_paths) =
        fixed_cluster(directory.path(), clock.clone()).await;
    let store = &stores[ready_leader(&stores).await];
    let provider = sealing_provider();
    let transient_retries = Arc::new(AtomicU64::new(0));
    assert_eq!(
        fenced_transition_v2_profile_digest(),
        FIXED_V2_PROFILE_DIGEST
    );
    assert_eq!(
        FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET,
        QUALIFICATION_SESSIONS * 2,
        "the downstream contract is two unique transitions for each of 50,000 sessions"
    );
    assert_eq!(
        QUALIFICATION_HEADROOM_TRANSITIONS, 31_072,
        "qualification must exercise every declared transition of headroom"
    );
    let first_epoch = FencedTransitionV2HistoryEpoch::new(1).expect("first epoch");

    // Activate the versioned capability with one ordinary session before the
    // bounded client burst. This keeps the first activation's unanimous proof
    // and durable certificate single-valued while still sending every request
    // through the same public three-voter consensus/apply path.
    let first_key = key(0);
    let first_observation = retry_exact_consensus_operation(&transient_retries, || {
        store.observe_fenced_transition(&first_key)
    })
    .await
    .expect("initial real consensus fence observation");
    let first_request = create_request(
        0,
        first_epoch,
        first_key,
        first_observation.current_fence(),
        &provider,
    )
    .await;
    let first_outcome = retry_exact_consensus_operation(&transient_retries, || {
        store.fenced_transition_v2(first_request.clone())
    })
    .await
    .expect("initial capability-activating transition must commit through quorum apply");
    assert!(matches!(
        first_outcome.mutation(),
        FencedTransitionMutationResult::Created
    ));
    let first_update = renew_update_request(1, first_epoch, &first_outcome, &provider).await;
    let first_updated = retry_exact_consensus_operation(&transient_retries, || {
        store.fenced_transition_v2(first_update.clone())
    })
    .await
    .expect("initial session update must commit through quorum apply");
    assert!(matches!(
        first_updated.mutation(),
        FencedTransitionMutationResult::Updated
    ));

    // Exercise the production contract: exactly two distinct committed
    // transitions for each of 50,000 durable sessions. The second operation is
    // a real lease renewal plus record update, not a disposable-key shortcut
    // around the state machine. Remaining independent sessions are admitted as
    // a bounded client burst; each task still performs its observation,
    // proposal, and three-voter durable apply through the public API. Sorting
    // the completed tasks restores deterministic session indexing for the
    // delayed-retry exemplar and the subsequent headroom updates.
    let mut remaining_session_states = futures_util::stream::iter(1..QUALIFICATION_SESSIONS)
        .map(|session_index| {
            let provider = &provider;
            let transient_retries = Arc::clone(&transient_retries);
            async move {
                let key = key(session_index);
                let observation = retry_exact_consensus_operation(&transient_retries, || {
                    store.observe_fenced_transition(&key)
                })
                .await
                .expect("real consensus fence observation");
                let create_index = session_index * 2;
                let create = create_request(
                    create_index,
                    first_epoch,
                    key,
                    observation.current_fence(),
                    provider,
                )
                .await;
                let created = retry_exact_consensus_operation(&transient_retries, || {
                    store.fenced_transition_v2(create.clone())
                })
                .await
                .expect("session create must commit through quorum apply");
                assert!(matches!(
                    created.mutation(),
                    FencedTransitionMutationResult::Created
                ));

                let update =
                    renew_update_request(create_index + 1, first_epoch, &created, provider).await;
                let updated = retry_exact_consensus_operation(&transient_retries, || {
                    store.fenced_transition_v2(update.clone())
                })
                .await
                .expect("session update must commit through quorum apply");
                assert!(matches!(
                    updated.mutation(),
                    FencedTransitionMutationResult::Updated
                ));
                (session_index, create, created, updated)
            }
        })
        .buffer_unordered(QUALIFICATION_IN_FLIGHT_CLIENTS)
        .collect::<Vec<_>>()
        .await;
    let mut session_states = vec![(0, first_request, first_outcome, first_updated)];
    session_states.append(&mut remaining_session_states);
    session_states.sort_unstable_by_key(|(session_index, _, _, _)| *session_index);
    assert_eq!(
        session_states.len(),
        QUALIFICATION_SESSIONS,
        "every session must complete its create and update through fixed quorum"
    );
    let (first_session_index, first_request, first_outcome, _) = &session_states[0];
    assert_eq!(
        *first_session_index, 0,
        "the delayed-retry exemplar must remain the deterministic first session"
    );
    let (first_request, first_outcome) = (first_request.clone(), first_outcome.clone());
    let headroom_states = session_states
        .iter()
        .take(QUALIFICATION_HEADROOM_TRANSITIONS)
        .map(|(_, _, _, updated)| updated.clone())
        .collect::<Vec<_>>();
    let target_history = retry_exact_consensus_operation(&transient_retries, || {
        store.fenced_transition_v2_history_state()
    })
    .await
    .expect("read history at the downstream operational target");
    assert_eq!(
        target_history.bound_entries(),
        FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET,
        "100,000 transitions for 50,000 sessions must commit before using headroom"
    );
    assert_eq!(target_history.active_epoch(), Some(first_epoch));

    // Consume all 31,072 declared transitions of operational headroom with a
    // third real update on retained sessions.
    let mut completed_headroom_states =
        futures_util::stream::iter(headroom_states.into_iter().enumerate())
            .map(|(headroom_index, state)| {
                let provider = &provider;
                let transient_retries = Arc::clone(&transient_retries);
                async move {
                    let request_index =
                        FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET + headroom_index;
                    let update =
                        renew_update_request(request_index, first_epoch, &state, provider).await;
                    let updated = retry_exact_consensus_operation(&transient_retries, || {
                        store.fenced_transition_v2(update.clone())
                    })
                    .await
                    .expect("headroom update must commit through quorum apply");
                    assert!(matches!(
                        updated.mutation(),
                        FencedTransitionMutationResult::Updated
                    ));
                    (headroom_index, updated)
                }
            })
            .buffer_unordered(QUALIFICATION_IN_FLIGHT_CLIENTS)
            .collect::<Vec<_>>()
            .await;
    completed_headroom_states.sort_unstable_by_key(|(headroom_index, _)| *headroom_index);
    assert_eq!(
        completed_headroom_states.len(),
        QUALIFICATION_HEADROOM_TRANSITIONS,
        "every declared transition of headroom must commit through fixed quorum"
    );
    let headroom_states = completed_headroom_states
        .into_iter()
        .map(|(_, state)| state)
        .collect::<Vec<_>>();

    // The exact one-over request is another valid update for a live session.
    // Capacity admission must precede every lease, record, and watch-visible
    // effect.
    let one_over_state = &headroom_states[0];
    let one_over_key = one_over_state.lease().key().clone();
    let record_before_rejection =
        retry_exact_consensus_operation(&transient_retries, || store.get(&one_over_key))
            .await
            .expect("read one-over record before rejection")
            .expect("one-over session remains live");
    let fence_before_rejection = retry_exact_consensus_operation(&transient_retries, || {
        store.observe_fenced_transition(&one_over_key)
    })
    .await
    .expect("read one-over fence before rejection")
    .current_fence();
    let one_over_request = renew_update_request(
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
        first_epoch,
        one_over_state,
        &provider,
    )
    .await;
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2(one_over_request.clone())
        })
        .await,
        Err(StoreError::FencedTransitionHistoryFull),
        "one-over request must not execute"
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || store.get(&one_over_key))
            .await
            .expect("read one-over record after rejection"),
        Some(record_before_rejection),
        "one-over history rejection must not mutate the business record"
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.observe_fenced_transition(&one_over_key)
        })
        .await
        .expect("read one-over fence after rejection")
        .current_fence(),
        fence_before_rejection,
        "one-over history rejection must not renew a lease or advance the fence"
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2_status(&one_over_request)
        })
        .await
        .expect("read one-over request status"),
        FencedTransitionV2Status::HistoryFull,
        "one-over request must have no retained result"
    );

    let history = retry_exact_consensus_operation(&transient_retries, || {
        store.fenced_transition_v2_history_state()
    })
    .await
    .expect("read durable history counter");
    assert_eq!(
        history.bound_entries(),
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
    );
    assert_eq!(history.active_epoch(), Some(first_epoch));

    let (old_request, old_outcome) = (first_request, first_outcome);
    let old_record_before_retries = retry_exact_consensus_operation(&transient_retries, || {
        store.get(old_request.lease().key())
    })
    .await
    .expect("read old request record before delayed retries")
    .expect("old request session remains live");
    assert!(matches!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2_status(&old_request)
        })
        .await
        .expect("old request remains recorded before retirement"),
        FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(old_outcome.clone())
    ));
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2(old_request.clone())
        })
        .await
        .expect("delayed exact retry before retirement"),
        old_outcome,
        "an old exact retry must replay its original outcome after later session updates"
    );

    let changed_old_request = request_with_changed_body(&old_request);
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2_status(&changed_old_request)
        })
        .await
        .expect("altered old request status before retirement"),
        FencedTransitionV2Status::RequestConflict
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2(changed_old_request.clone())
        })
        .await,
        Err(StoreError::FencedTransitionRequestConflict),
        "an altered old body must conflict before retirement"
    );
    clock.set(
        start
            .add_seconds(24 * 60 * 60 + 1)
            .expect("retention-boundary qualification time"),
    );
    let mut history = retry_exact_consensus_operation(&transient_retries, || {
        store.fenced_transition_v2_history_state()
    })
    .await
    .expect("commit advanced logical time through a public read barrier");
    history = maintain_exact_history_batch(store, history, &transient_retries)
        .await
        .expect("first fixed-quorum retirement batch");
    assert_eq!(history.active_epoch(), None);
    assert_eq!(history.retired_through(), Some(first_epoch));
    assert_eq!(history.reclaim_epoch(), Some(first_epoch));
    assert_eq!(
        history.reclaim_remaining(),
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - FENCED_TRANSITION_V2_RECLAIM_BATCH
    );

    let next_epoch = FencedTransitionV2HistoryEpoch::new(2).expect("next epoch");
    let next_key = key(QUALIFICATION_TRANSITIONS + 1);
    let next_observation = retry_exact_consensus_operation(&transient_retries, || {
        store.observe_fenced_transition(&next_key)
    })
    .await
    .expect("next-epoch fence observation");
    let next_request = create_request(
        QUALIFICATION_TRANSITIONS + 1,
        next_epoch,
        next_key.clone(),
        next_observation.current_fence(),
        &provider,
    )
    .await;
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2_status(&old_request)
        })
        .await
        .expect("retired old retry status during reclaim"),
        FencedTransitionV2Status::Retired
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2_status(&changed_old_request)
        })
        .await
        .expect("altered old retry status during reclaim"),
        FencedTransitionV2Status::RequestConflict
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2(old_request.clone())
        })
        .await,
        Err(StoreError::FencedTransitionHistoryEpochRetired),
        "a delayed exact retry is terminal as soon as the replicated floor advances"
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2(changed_old_request.clone())
        })
        .await,
        Err(StoreError::FencedTransitionRequestConflict),
        "body conflict must take precedence over a retired floor during reclamation"
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2_status(&next_request)
        })
        .await
        .expect("next epoch status during reclaim"),
        FencedTransitionV2Status::EpochNotActive
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2(next_request.clone())
        })
        .await,
        Err(StoreError::FencedTransitionHistoryEpochNotActive),
        "next epoch must have no effect while reclamation is active"
    );
    assert!(
        retry_exact_consensus_operation(&transient_retries, || store.get(&next_key))
            .await
            .expect("read next epoch key during reclaim")
            .is_none(),
        "inactive next epoch must not install a business record"
    );

    assert_eq!(
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES % FENCED_TRANSITION_V2_RECLAIM_BATCH,
        0,
        "qualification assumes ordered full reclamation batches"
    );
    for batch in 1..RECLAIM_BATCHES {
        history = maintain_exact_history_batch(store, history, &transient_retries)
            .await
            .expect("ordered fixed-quorum retirement batch");
        if batch + 1 < RECLAIM_BATCHES {
            assert_eq!(history.active_epoch(), None);
            assert_eq!(history.reclaim_epoch(), Some(first_epoch));
            assert_eq!(
                history.reclaim_remaining(),
                FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
                    - (batch + 1) * FENCED_TRANSITION_V2_RECLAIM_BATCH
            );
        }
    }
    assert_eq!(history.active_epoch(), Some(next_epoch));
    assert_eq!(history.retired_through(), Some(first_epoch));
    assert_eq!(history.reclaim_epoch(), None);
    assert_eq!(history.reclaim_remaining(), 0);
    assert_eq!(history.bound_entries(), 0);
    assert_eq!(
        history.reclaimed_entries(),
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u64
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2_status(&old_request)
        })
        .await
        .expect("retired old retry status after final batch"),
        FencedTransitionV2Status::Retired
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2_status(&changed_old_request)
        })
        .await
        .expect("altered old retry status after final batch"),
        FencedTransitionV2Status::RequestConflict
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2(old_request.clone())
        })
        .await,
        Err(StoreError::FencedTransitionHistoryEpochRetired),
        "physical deletion must not make an exact old retry executable"
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2(changed_old_request.clone())
        })
        .await,
        Err(StoreError::FencedTransitionRequestConflict),
        "physical deletion must preserve altered-body conflict classification"
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.get(old_request.lease().key())
        })
        .await
        .expect("read old request record after delayed retries"),
        Some(old_record_before_retries),
        "replay, retirement, and altered-body conflict must not duplicate or roll back business state"
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2_status(&next_request)
        })
        .await
        .expect("next epoch status after final batch"),
        FencedTransitionV2Status::NotFound
    );
    let next_outcome = retry_exact_consensus_operation(&transient_retries, || {
        store.fenced_transition_v2(next_request.clone())
    })
    .await
    .expect("next epoch must execute after final reclamation batch");
    assert!(matches!(
        next_outcome.mutation(),
        FencedTransitionMutationResult::Created
    ));

    let database_bytes = database_paths
        .iter()
        .map(|path| sqlite_database_family_bytes(path))
        .sum::<u64>();
    let snapshot_bytes = snapshot_paths
        .iter()
        .map(|path| directory_bytes(path))
        .sum::<u64>();
    eprintln!(
        "sdk-702 v2 qualification: elapsed={:?} committed={} reclaimed={} transient_exact_retries={} db_bytes={} snapshot_bytes={}",
        started.elapsed(),
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES + 1,
        history.reclaimed_entries(),
        transient_retries.load(Ordering::Relaxed),
        database_bytes,
        snapshot_bytes,
    );
    assert!(
        database_bytes > 0,
        "qualification must persist all voter state"
    );
    assert!(
        snapshot_bytes > 0,
        "qualification must produce measurable bounded snapshot state"
    );
}
