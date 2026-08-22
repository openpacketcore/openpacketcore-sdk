//! Long-running SDK-702 V2 history qualification.
//!
//! This is deliberately ignored in ordinary CI.  It uses three real fixed
//! durable-quorum voters and their public proposal/apply APIs; it never seeds
//! the receipt table or invokes a private state-machine helper.

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{FutureExt, StreamExt};
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
    SessionConsensusRpcHandler, SessionConsensusStatus, SessionConsensusWireRequest,
    SessionConsensusWireResponse, SessionKey, SessionKeyType, SqliteSessionBackend, StateClass,
    StateType, StoreError, StoredSessionRecord, Timestamp, ValidatedQuorumTopology,
    FENCED_TRANSITION_V2_MAX_ACTIVE_EPOCHS, FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
    FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS, FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_BYTES,
    FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES, FENCED_TRANSITION_V2_RECLAIM_BATCH,
    FENCED_TRANSITION_V2_REQUIRED_OPERATIONAL_TARGET,
};
use opc_types::{NetworkFunctionKind, TenantId};

const VOTERS: usize = 3;
const QUALIFICATION_SESSIONS: usize = 50_000;
const QUALIFICATION_SUSTAINED_RATE: usize = 500;
const QUALIFICATION_SUSTAINED_SECONDS: usize = 30 * 60;
const QUALIFICATION_BURST_RATE: usize = 1_000;
const QUALIFICATION_BURST_SECONDS: usize = 60;
const QUALIFICATION_SUSTAINED_TRANSITIONS: usize =
    QUALIFICATION_SUSTAINED_RATE * QUALIFICATION_SUSTAINED_SECONDS;
const QUALIFICATION_BURST_TRANSITIONS: usize =
    QUALIFICATION_BURST_RATE * QUALIFICATION_BURST_SECONDS;
const QUALIFICATION_RELEASE_TRANSITIONS: usize =
    QUALIFICATION_SESSIONS + QUALIFICATION_SUSTAINED_TRANSITIONS + QUALIFICATION_BURST_TRANSITIONS;
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
const QUALIFICATION_PRELOAD_BATCH_OPERATIONS: usize = 256;
// At 500 operations/second, an eight-item batch has a 16 ms formation window.
// That leaves real budget for quorum apply while measuring each item's full
// scheduled-arrival-to-completion latency against the 25 ms p99 contract.
const QUALIFICATION_PACED_BATCH_OPERATIONS: usize = 8;
// The isolated qualification voters contain only this feature's state. These
// fixed physical regression envelopes deliberately exceed the immutable
// semantic receipt maximum to allow SQLite pages/indexes and one bounded WAL,
// while still making accidental unbounded retention fail the release gate.
const QUALIFICATION_PER_VOTER_DATABASE_CEILING_BYTES: u64 =
    FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_BYTES * 3;
const QUALIFICATION_PER_VOTER_SNAPSHOT_CEILING_BYTES: u64 =
    FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_BYTES * 2;
#[cfg(target_os = "linux")]
const QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB: u64 = 2 * 1024 * 1024;
const _: () = {
    assert!(QUALIFICATION_IN_FLIGHT_CLIENTS >= 1);
    assert!(FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_BYTES > 0);
};
const FIXED_V2_PROFILE_DIGEST: [u8; 32] = [
    0x8a, 0x0b, 0x70, 0xb5, 0x46, 0x54, 0xc7, 0x25, 0x0c, 0xf5, 0x46, 0x9d, 0xb6, 0xe1, 0xe5, 0x45,
    0xf3, 0x5e, 0x38, 0xe9, 0x77, 0x8d, 0x5f, 0x50, 0x0f, 0xea, 0x67, 0x06, 0x96, 0xc4, 0xbd, 0xc3,
];

#[derive(Default)]
struct ReleaseLatencySamples {
    batch: Vec<Duration>,
    item_scheduled_to_completion: Vec<Duration>,
}

impl ReleaseLatencySamples {
    fn record_batch(&mut self, elapsed: Duration, item_scheduled_at: &[Instant]) {
        self.batch.push(elapsed);
        let completed = Instant::now();
        self.item_scheduled_to_completion.extend(
            item_scheduled_at
                .iter()
                .map(|scheduled_at| completed.duration_since(*scheduled_at)),
        );
    }

    fn percentile(samples: &mut [Duration], numerator: usize, denominator: usize) -> Duration {
        assert!(!samples.is_empty(), "release latency samples must be real");
        samples.sort_unstable();
        let index = (samples.len() * numerator)
            .div_ceil(denominator)
            .saturating_sub(1);
        samples[index]
    }

    fn p99_and_p999(&mut self) -> (Duration, Duration, Duration, Duration) {
        (
            Self::percentile(&mut self.batch, 99, 100),
            Self::percentile(&mut self.batch, 999, 1_000),
            Self::percentile(&mut self.item_scheduled_to_completion, 99, 100),
            Self::percentile(&mut self.item_scheduled_to_completion, 999, 1_000),
        )
    }
}

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
    stores: &[ConsensusSessionStore],
    expected: FencedTransitionV2HistoryState,
    transient_retries: &AtomicU64,
    post_commit_reply_loss: Option<&AtomicUsize>,
) -> Result<FencedTransitionV2HistoryState, StoreError> {
    for attempt in 0..=QUALIFICATION_TRANSIENT_RETRY_LIMIT {
        // Unlike ordinary application operations, operator maintenance is a
        // deliberately local-leader-only boundary and is never forwarded.
        // A release workload can span several election terms, so never cache
        // the leader selected before the 131k-transition phase.
        let store = &stores[ready_leader(stores).await];
        let result = store.maintain_fenced_transition_v2_history(expected).await;
        // This fault is deliberately after the public local-leader method
        // completed successfully: it models only the caller losing that
        // successful reply, never a pre-proposal or pre-commit failure. The
        // bounded one-shot counter keeps unrelated qualification calls on
        // their ordinary production path.
        let result = match result {
            Ok(_)
                if post_commit_reply_loss.is_some_and(|remaining| {
                    remaining
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                            count.checked_sub(1)
                        })
                        .is_ok()
                }) =>
            {
                Err(StoreError::BackendUnavailable(
                    "test-only post-commit V2 maintenance reply loss".into(),
                ))
            }
            result => result,
        };
        match result {
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
                let observation_store = &stores[ready_leader(stores).await];
                let observed = retry_exact_consensus_operation(transient_retries, || {
                    observation_store.fenced_transition_v2_history_state()
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

#[test]
fn maintenance_leader_selection_replaces_a_stale_self_reported_three_voter_leader() {
    let placement_policy = PlacementResiliencePolicy::default();
    let quorum_members = members();
    let node_ids = (0..VOTERS)
        .map(|index| {
            fixed_topology(index, quorum_members.clone(), placement_policy)
                .local_consensus_node_id()
                .expect("fixed voter node ID")
        })
        .collect::<Vec<_>>();
    let status = |node_id, term, leader_id| SessionConsensusStatus {
        node_id,
        term,
        leader_id: Some(leader_id),
        last_log_index: None,
        applied_index: None,
        admitted: true,
    };

    let initial_term = [
        status(node_ids[0], 7, node_ids[0]),
        status(node_ids[1], 7, node_ids[0]),
        status(node_ids[2], 7, node_ids[0]),
    ];
    assert_eq!(
        current_local_maintenance_leader_from_statuses(&initial_term),
        Some(0)
    );

    // This is the deterministic status shape during a term change: voter 0
    // has a stale self-report, while the newly elected voter 1 and its peer
    // have observed the later term. The selector must not retain voter 0.
    let reselected_term = [
        status(node_ids[0], 7, node_ids[0]),
        status(node_ids[1], 8, node_ids[1]),
        status(node_ids[2], 8, node_ids[1]),
    ];
    assert_eq!(
        current_local_maintenance_leader_from_statuses(&reselected_term),
        Some(1)
    );
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
    let mutation = encoded
        .get_mut("mutation")
        .and_then(serde_json::Value::as_object_mut)
        .expect("V2 request mutation");
    let mutation_body = if mutation.contains_key("create") {
        mutation.get_mut("create")
    } else {
        mutation.get_mut("update")
    };
    let record = mutation_body
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|mutation| mutation.get_mut("record"))
        .and_then(serde_json::Value::as_object_mut)
        .expect("V2 create or update request record");
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

fn assert_voter_resource_ceiling(label: &str, values: &[u64], ceiling: u64) {
    assert_eq!(values.len(), VOTERS, "{label} must cover every voter");
    assert!(
        values.iter().all(|value| *value > 0 && *value <= ceiling),
        "{label} must be nonzero and no greater than {ceiling} bytes per voter: {values:?}",
    );
}

#[cfg(target_os = "linux")]
fn process_peak_rss_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status")
        .expect("read Linux process status for release resource qualification");
    status
        .lines()
        .find_map(|line| {
            line.strip_prefix("VmHWM:")?
                .split_whitespace()
                .next()?
                .parse::<u64>()
                .ok()
        })
        .expect("Linux process status contains VmHWM")
}

#[cfg(not(target_os = "linux"))]
fn process_peak_rss_kib() -> u64 {
    0
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

#[tokio::test(flavor = "multi_thread")]
async fn fixed_quorum_v2_batch_preserves_input_order_and_independent_statuses() {
    let directory = tempfile::tempdir().expect("fixed-quorum V2 batch directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("fixed-quorum V2 batch start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (stores, _, _) = fixed_cluster(directory.path(), clock).await;
    let leader = ready_leader(&stores).await;
    let store = &stores[leader];
    let provider = sealing_provider();
    let epoch = FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch");

    // Activation remains the existing singleton transition. The following
    // independent create and renewal exercise the public bounded coalescing
    // API and prove that each item retains its own exact status identity.
    let first_key = key(0);
    let first_observation = store
        .observe_fenced_transition(&first_key)
        .await
        .expect("singleton activation observation");
    let first_request = create_request(
        0,
        epoch,
        first_key,
        first_observation.current_fence(),
        &provider,
    )
    .await;
    let first_outcome = store
        .fenced_transition_v2(first_request.clone())
        .await
        .expect("singleton V2 activation");

    let second_key = key(1);
    let second_observation = store
        .observe_fenced_transition(&second_key)
        .await
        .expect("batch create observation");
    let second_request = create_request(
        1,
        epoch,
        second_key,
        second_observation.current_fence(),
        &provider,
    )
    .await;
    let renewal_request = renew_update_request(2, epoch, &first_outcome, &provider).await;
    let requests = vec![second_request.clone(), renewal_request.clone()];
    let outcomes = store
        .fenced_transition_v2_batch(requests.clone())
        .await
        .expect("public bounded V2 batch");
    assert_eq!(outcomes.len(), requests.len());
    let second_outcome = outcomes[0].clone().expect("first batch item result");
    let renewal_outcome = outcomes[1].clone().expect("second batch item result");
    assert!(matches!(
        second_outcome.mutation(),
        FencedTransitionMutationResult::Created
    ));
    assert!(matches!(
        renewal_outcome.mutation(),
        FencedTransitionMutationResult::Updated
    ));

    for voter in &stores {
        let history = voter
            .fenced_transition_v2_history_state()
            .await
            .expect("V2 batch history on every voter");
        assert_eq!(history.bound_entries(), 3);
        for (request, outcome) in [
            (&first_request, &first_outcome),
            (&second_request, &second_outcome),
            (&renewal_request, &renewal_outcome),
        ] {
            assert!(matches!(
                voter
                    .fenced_transition_v2_status(request)
                    .await
                    .expect("V2 batch item status on every voter"),
                FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(outcome.clone())
            ));
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn fixed_quorum_history_maintenance_reselects_the_local_leader() {
    let directory = tempfile::tempdir().expect("fixed-quorum V2 maintenance directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("fixed-quorum V2 maintenance start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (stores, _, _) = fixed_cluster(directory.path(), clock.clone()).await;
    let leader = ready_leader(&stores).await;
    let provider = sealing_provider();
    let key = key(0);
    let observation = stores[leader]
        .observe_fenced_transition(&key)
        .await
        .expect("fixed-quorum maintenance fence observation");
    let transition = create_request(
        0,
        FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch"),
        key,
        observation.current_fence(),
        &provider,
    )
    .await;
    stores[leader]
        .fenced_transition_v2(transition)
        .await
        .expect("fixed-quorum maintenance transition");

    clock.set(
        start
            .add_seconds(24 * 60 * 60 + 1)
            .expect("maintenance retention boundary"),
    );
    let leader = ready_leader(&stores).await;
    let expected = stores[leader]
        .fenced_transition_v2_history_state()
        .await
        .expect("linearized maintenance history");
    let follower = (leader + 1) % stores.len();
    assert!(matches!(
        stores[follower]
            .maintain_fenced_transition_v2_history(expected)
            .await,
        Err(StoreError::BackendUnavailable(_))
    ));

    let transient_retries = AtomicU64::new(0);
    let maintained = maintain_exact_history_batch(&stores, expected, &transient_retries, None)
        .await
        .expect("maintenance reselects the current local leader");
    // Maintenance is a no-op until the active epoch is full. A one-entry
    // epoch cannot be retired merely because the result window elapsed: the
    // first full epoch opens its successor while retaining the old replay
    // epoch above the still-empty retirement floor.
    assert_eq!(maintained.retired_through(), None);
    assert_eq!(
        maintained.active_epoch(),
        Some(FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch"))
    );
    assert_eq!(maintained.reclaim_epoch(), None);
    assert_eq!(maintained.reclaim_remaining(), 0);
    assert_eq!(maintained.bound_entries(), 1);
    assert_eq!(maintained.reclaimed_entries(), 0);
}

/// Release qualification for V2 capacity and retired-history reclamation.
/// Its shared injected clock advances through a consensus read barrier, never
/// by SQLite mutation or a wall-clock sleep.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "131,074 attempted / 131,073 committed real fixed-quorum consensus transitions are release qualification"]
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
    let observation_before_rejection = retry_exact_consensus_operation(&transient_retries, || {
        store.observe_fenced_transition(&one_over_key)
    })
    .await
    .expect("read one-over record and fence before rejection");
    let record_before_rejection = observation_before_rejection
        .record()
        .cloned()
        .expect("one-over session remains live");
    let fence_before_rejection = observation_before_rejection.current_fence();
    let one_over_request = renew_update_request(
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
        first_epoch,
        one_over_state,
        &provider,
    )
    .await;
    let replication_before_rejection =
        retry_exact_consensus_operation(&transient_retries, || store.max_replication_sequence())
            .await
            .expect("read application sequence before one-over rejection");
    let mut one_over_watch = retry_exact_consensus_operation(&transient_retries, || {
        store.watch(replication_before_rejection + 1)
    })
    .await
    .expect("open live watch before one-over rejection");
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2(one_over_request.clone())
        })
        .await,
        Err(StoreError::FencedTransitionHistoryFull),
        "one-over request must not execute"
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2(one_over_request.clone())
        })
        .await,
        Err(StoreError::FencedTransitionHistoryFull),
        "exact one-over retry must remain a deterministic no-effect rejection"
    );
    let changed_one_over_request = request_with_changed_body(&one_over_request);
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2(changed_one_over_request.clone())
        })
        .await,
        Err(StoreError::FencedTransitionRequestConflict),
        "same full ID with a changed update body must not acquire capacity or a lease"
    );
    let observation_after_rejection = retry_exact_consensus_operation(&transient_retries, || {
        store.observe_fenced_transition(&one_over_key)
    })
    .await
    .expect("read one-over record and fence after all rejected retries");
    assert_eq!(
        observation_after_rejection, observation_before_rejection,
        "one-over rejection must preserve the complete public record and durable fence observation"
    );
    assert_eq!(
        observation_after_rejection.record(),
        Some(&record_before_rejection),
        "one-over history rejection must not mutate the business record"
    );
    assert_eq!(
        observation_after_rejection.current_fence(),
        fence_before_rejection,
        "one-over history rejection must not renew a lease or advance the fence"
    );
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            store.max_replication_sequence()
        })
        .await
        .expect("read application sequence after one-over rejections"),
        replication_before_rejection,
        "one-over rejection and both retries must not apply an application entry"
    );
    assert!(
        one_over_watch.next().now_or_never().is_none(),
        "one-over rejection and both retries must not emit a watch event"
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
    history = maintain_exact_history_batch(&stores, history, &transient_retries, None)
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
        history = maintain_exact_history_batch(&stores, history, &transient_retries, None)
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

    let database_bytes_by_voter = database_paths
        .iter()
        .map(|path| sqlite_database_family_bytes(path))
        .collect::<Vec<_>>();
    let snapshot_bytes_by_voter = snapshot_paths
        .iter()
        .map(|path| directory_bytes(path))
        .collect::<Vec<_>>();
    let database_bytes = database_bytes_by_voter.iter().sum::<u64>();
    let snapshot_bytes = snapshot_bytes_by_voter.iter().sum::<u64>();
    let peak_rss_kib = process_peak_rss_kib();
    eprintln!(
        "sdk-702 v2 qualification: elapsed={:?} committed={} reclaimed={} transient_exact_retries={} db_bytes_by_voter={database_bytes_by_voter:?} db_bytes={} snapshot_bytes_by_voter={snapshot_bytes_by_voter:?} snapshot_bytes={} peak_rss_kib={peak_rss_kib}",
        started.elapsed(),
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES + 1,
        history.reclaimed_entries(),
        transient_retries.load(Ordering::Relaxed),
        database_bytes,
        snapshot_bytes,
    );
    assert_voter_resource_ceiling(
        "post-reclaim SQLite database family",
        &database_bytes_by_voter,
        QUALIFICATION_PER_VOTER_DATABASE_CEILING_BYTES,
    );
    assert_voter_resource_ceiling(
        "post-reclaim snapshot directory",
        &snapshot_bytes_by_voter,
        QUALIFICATION_PER_VOTER_SNAPSHOT_CEILING_BYTES,
    );
    #[cfg(target_os = "linux")]
    assert!(
        peak_rss_kib <= QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB,
        "three-voter peak RSS {peak_rss_kib} KiB exceeds the fixed {} KiB ceiling",
        QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB,
    );
}

/// Pace a real request stream without hiding a quorum that cannot keep up.
///
/// The sleep only applies while the fixed quorum is ahead of the requested
/// rate. A slower quorum therefore makes the measured rate truthful rather
/// than dropping requests, seeding state, or hiding client backlog.
async fn pace_release_phase(phase_started: Instant, submitted: usize, per_second: usize) {
    let due = phase_started + Duration::from_secs_f64(submitted as f64 / per_second as f64);
    let now = Instant::now();
    if due > now {
        tokio::time::sleep(due - now).await;
    }
}

/// Full SDK-702 release workload through a real three-voter OpenRaft quorum.
///
/// This is intentionally ignored: it submits the real 1,010,000 operations
/// (50,000 preload, 500/s for 30 minutes, then 1,000/s for 60 seconds) using
/// the public V2 API.  It does not substitute generic batches, seed receipts,
/// or call SQLite/state-machine internals. The pacing assertions cover both
/// requested finite-window rates and emit only fixed-dimension, redaction-safe
/// release evidence.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "SDK-702 real 1,010,000-operation three-voter release qualification"]
async fn release_1010000_operation_successor_scale_is_bounded_and_recoverable() {
    let started = Instant::now();
    let directory = tempfile::tempdir().expect("SDK-702 release qualification directory");
    let start = Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("SDK-702 release qualification start"),
    );
    let clock = Arc::new(MutableClock::new(start));
    let (mut stores, database_paths, snapshot_paths) =
        fixed_cluster(directory.path(), clock.clone()).await;
    let provider = sealing_provider();
    let transient_retries = AtomicU64::new(0);
    let first_epoch = FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch");

    assert_eq!(
        QUALIFICATION_RELEASE_TRANSITIONS, 1_010_000,
        "the release envelope is 50k + (500/s * 30m) + (1k/s * 60s)"
    );
    assert_eq!(FENCED_TRANSITION_V2_MAX_ACTIVE_EPOCHS, 1);
    assert_eq!(FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS, 7);
    assert_eq!(
        FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES,
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
            * (FENCED_TRANSITION_V2_MAX_ACTIVE_EPOCHS + FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS),
        "the public fixed resource contract must remain exactly eight epochs"
    );

    // The first V2 effect is deliberately singleton activation.  Every later
    // preload create is submitted through the public bounded coalescing API;
    // no receipt, database, or private-apply shortcut exists in this path.
    // Keep the original request/outcome as an attestation exemplar for each
    // epoch; later updates exercise independent lease renewal paths.
    let leader = ready_leader(&stores).await;
    let store = &stores[leader];
    let first_key = key(0);
    let first_observation = retry_exact_consensus_operation(&transient_retries, || {
        store.observe_fenced_transition(&first_key)
    })
    .await
    .expect("singleton activation fence observation");
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
    .expect("singleton V2 activation");
    let mut sessions = vec![(first_request, first_outcome)];
    for chunk_start in (1..QUALIFICATION_SESSIONS).step_by(QUALIFICATION_PRELOAD_BATCH_OPERATIONS) {
        let chunk_end =
            (chunk_start + QUALIFICATION_PRELOAD_BATCH_OPERATIONS).min(QUALIFICATION_SESSIONS);
        let mut requests = Vec::with_capacity(chunk_end - chunk_start);
        for session_index in chunk_start..chunk_end {
            let session_key = key(session_index);
            let observation = retry_exact_consensus_operation(&transient_retries, || {
                store.observe_fenced_transition(&session_key)
            })
            .await
            .expect("preload batch fence observation");
            requests.push(
                create_request(
                    session_index,
                    first_epoch,
                    session_key,
                    observation.current_fence(),
                    &provider,
                )
                .await,
            );
        }
        let outcomes = retry_exact_consensus_operation(&transient_retries, || {
            store.fenced_transition_v2_batch(requests.clone())
        })
        .await
        .expect("preload bounded V2 batch");
        assert_eq!(outcomes.len(), requests.len());
        for (request, outcome) in requests.into_iter().zip(outcomes) {
            let outcome = outcome.expect("preload item result");
            assert!(matches!(
                outcome.mutation(),
                FencedTransitionMutationResult::Created
            ));
            sessions.push((request, outcome));
        }
    }
    assert_eq!(sessions.len(), QUALIFICATION_SESSIONS);
    let mut representatives = vec![sessions[0].clone()];
    let mut active_epoch = first_epoch;
    let mut active_entries = QUALIFICATION_SESSIONS;
    let mut nonce = QUALIFICATION_SESSIONS;
    let mut rotations = 0usize;

    // Keep exactly 50,000 representative sessions in memory. The retained
    // receipt resource itself is bounded by the public eight-epoch contract
    // asserted above, not by this test-side cache.
    for (phase_name, target_rate, operations) in [
        (
            "sustained-500-per-second",
            QUALIFICATION_SUSTAINED_RATE,
            QUALIFICATION_SUSTAINED_TRANSITIONS,
        ),
        (
            "burst-1000-per-second",
            QUALIFICATION_BURST_RATE,
            QUALIFICATION_BURST_TRANSITIONS,
        ),
    ] {
        let phase_started = Instant::now();
        let mut latency = ReleaseLatencySamples::default();
        let mut submitted = 0usize;
        while submitted < operations {
            if active_entries == FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES {
                let leader = current_local_maintenance_leader(&stores).await;
                let before = retry_exact_consensus_operation(&transient_retries, || {
                    stores[leader].fenced_transition_v2_history_state()
                })
                .await
                .expect("linearized full active epoch before successor rotation");
                assert_eq!(before.active_epoch(), Some(active_epoch));
                assert_eq!(
                    before.bound_entries(),
                    FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
                );
                assert!(
                    rotations < FENCED_TRANSITION_V2_MAX_REPLAY_EPOCHS,
                    "the 1.01m envelope must require exactly seven successors, never a ninth epoch"
                );
                let after = maintain_exact_history_batch(&stores, before, &transient_retries, None)
                    .await
                    .expect("open bounded successor through local-leader maintenance");
                rotations += 1;
                active_epoch = FencedTransitionV2HistoryEpoch::new(active_epoch.get() + 1)
                    .expect("representable successor epoch");
                assert_eq!(after.active_epoch(), Some(active_epoch));
                assert_eq!(after.retired_through(), None);
                assert_eq!(after.reclaim_epoch(), None);
                assert_eq!(after.bound_entries(), 0);
                active_entries = 0;

                // Every earlier epoch remains publicly attestable and exactly
                // replayable before the 24-hour floor/reclaim boundary.
                for (request, outcome) in &representatives {
                    assert!(matches!(
                        retry_exact_consensus_operation(&transient_retries, || {
                            stores[leader].fenced_transition_v2_status(request)
                        })
                        .await
                        .expect("pre-floor representative status"),
                        FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(outcome.clone())
                    ));
                    assert_eq!(
                        retry_exact_consensus_operation(&transient_retries, || {
                            stores[leader].fenced_transition_v2(request.clone())
                        })
                        .await
                        .expect("pre-floor exact replay"),
                        *outcome
                    );
                    let changed = request_with_changed_body(request);
                    assert_eq!(
                        retry_exact_consensus_operation(&transient_retries, || {
                            stores[leader].fenced_transition_v2_status(&changed)
                        })
                        .await
                        .expect("pre-floor changed-body status"),
                        FencedTransitionV2Status::RequestConflict
                    );
                }
            }

            let leader = ready_leader(&stores).await;
            let batch_len = QUALIFICATION_PACED_BATCH_OPERATIONS
                .min(operations - submitted)
                .min(FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - active_entries);
            let mut requests = Vec::with_capacity(batch_len);
            let mut session_slots = Vec::with_capacity(batch_len);
            let mut scheduled_at = Vec::with_capacity(batch_len);
            let successor_first_item = active_entries == 0;
            for batch_offset in 0..batch_len {
                pace_release_phase(phase_started, submitted + batch_offset, target_rate).await;
                scheduled_at.push(
                    phase_started
                        + Duration::from_secs_f64(
                            (submitted + batch_offset) as f64 / target_rate as f64,
                        ),
                );
                // Each batch updates distinct independently fenced sessions.
                // Its first item after a rotation is retained as that epoch's
                // exact replay representative. A physical batch is
                // coalescing only; it has no inter-item conditional or
                // all-or-nothing meaning.
                let slot = nonce % sessions.len();
                let update =
                    renew_update_request(nonce, active_epoch, &sessions[slot].1, &provider).await;
                requests.push(update);
                session_slots.push(slot);
                nonce += 1;
            }
            let batch_started = Instant::now();
            let outcomes = retry_exact_consensus_operation(&transient_retries, || {
                stores[leader].fenced_transition_v2_batch(requests.clone())
            })
            .await
            .expect("paced bounded V2 batch");
            latency.record_batch(batch_started.elapsed(), &scheduled_at);
            assert_eq!(outcomes.len(), requests.len());
            for (batch_offset, ((request, outcome), slot)) in requests
                .into_iter()
                .zip(outcomes)
                .zip(session_slots)
                .enumerate()
            {
                let outcome = outcome.expect("paced V2 item result");
                if successor_first_item && batch_offset == 0 {
                    representatives.push((request.clone(), outcome.clone()));
                }
                sessions[slot].1 = outcome;
            }
            active_entries += batch_len;
            submitted += batch_len;
        }
        let elapsed = phase_started.elapsed();
        let batch_samples = latency.batch.len();
        let item_samples = latency.item_scheduled_to_completion.len();
        let (batch_p99, batch_p999, item_p99, item_p999) = latency.p99_and_p999();
        let achieved_ops_per_second = operations as f64 / elapsed.as_secs_f64();
        eprintln!(
            "sdk-702 successor phase: name={phase_name} offered_ops_per_second={target_rate} achieved_ops_per_second={achieved_ops_per_second:.6} operations={operations} batch_samples={batch_samples} item_samples={item_samples} batch_p99_us={} batch_p999_us={} item_p99_us={} item_p999_us={} elapsed_ms={}",
            batch_p99.as_micros(),
            batch_p999.as_micros(),
            item_p99.as_micros(),
            item_p999.as_micros(),
            elapsed.as_millis(),
        );
        assert!(
            achieved_ops_per_second >= target_rate as f64 * 0.999,
            "the truthful finite-window completion rate must remain within 0.1% of the offered release target"
        );
        assert!(item_p99 <= Duration::from_millis(25));
        assert!(item_p999 <= Duration::from_millis(100));
    }

    assert_eq!(
        nonce, QUALIFICATION_RELEASE_TRANSITIONS,
        "the paced workload must use exactly its declared 1,010,000 unique V2 IDs"
    );
    assert_eq!(sessions.len(), QUALIFICATION_SESSIONS);
    assert_eq!(rotations, 7, "the 1.01m envelope crosses seven successors");
    let leader = ready_leader(&stores).await;
    let history = retry_exact_consensus_operation(&transient_retries, || {
        stores[leader].fenced_transition_v2_history_state()
    })
    .await
    .expect("history after 1.01m real operations");
    assert_eq!(
        history.active_epoch(),
        Some(FencedTransitionV2HistoryEpoch::new(8).expect("epoch 8"))
    );
    assert_eq!(history.retired_through(), None);
    assert_eq!(history.reclaim_epoch(), None);
    assert_eq!(
        history.bound_entries(),
        QUALIFICATION_RELEASE_TRANSITIONS % FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
    );
    assert_eq!(representatives.len(), 8);

    // A restart after seven rotations uses only the public constructor and
    // durable voter files. It proves the replay interval was recovered, not
    // reconstructed through a direct receipt-table inspection.
    drop(stores);
    let (stores_after_restart, _, _) = fixed_cluster(directory.path(), clock.clone()).await;
    stores = stores_after_restart;
    let leader = ready_leader(&stores).await;
    for (request, outcome) in &representatives {
        assert!(matches!(
            retry_exact_consensus_operation(&transient_retries, || {
                stores[leader].fenced_transition_v2_status(request)
            })
            .await
            .expect("restart exact status"),
            FencedTransitionV2Status::Recorded(result) if result.as_ref() == &Ok(outcome.clone())
        ));
        assert_eq!(
            retry_exact_consensus_operation(&transient_retries, || {
                stores[leader].fenced_transition_v2(request.clone())
            })
            .await
            .expect("restart exact replay"),
            *outcome
        );
        let changed = request_with_changed_body(request);
        assert_eq!(
            retry_exact_consensus_operation(&transient_retries, || {
                stores[leader].fenced_transition_v2_status(&changed)
            })
            .await
            .expect("restart changed-body status"),
            FencedTransitionV2Status::RequestConflict
        );
    }

    let database_bytes_before_reclaim_by_voter = database_paths
        .iter()
        .map(|path| sqlite_database_family_bytes(path))
        .collect::<Vec<_>>();
    let snapshot_bytes_before_reclaim_by_voter = snapshot_paths
        .iter()
        .map(|path| directory_bytes(path))
        .collect::<Vec<_>>();
    assert_voter_resource_ceiling(
        "pre-reclaim SQLite database family",
        &database_bytes_before_reclaim_by_voter,
        QUALIFICATION_PER_VOTER_DATABASE_CEILING_BYTES,
    );
    assert_voter_resource_ceiling(
        "pre-reclaim snapshot directory",
        &snapshot_bytes_before_reclaim_by_voter,
        QUALIFICATION_PER_VOTER_SNAPSHOT_CEILING_BYTES,
    );

    // Logical-time acceleration crosses the 24-hour boundary without a
    // wall-clock day. The first reclaim must advance only the oldest floor,
    // delete at most one ordered batch, and leave epoch 8 writable.
    clock.set(
        start
            .add_seconds(24 * 60 * 60 + 1)
            .expect("retention boundary"),
    );
    let before_floor = retry_exact_consensus_operation(&transient_retries, || {
        stores[leader].fenced_transition_v2_history_state()
    })
    .await
    .expect("linearized history before floor advancement");
    // Discard exactly one already-successful public maintenance reply. This
    // is post-commit reply loss only: the helper must reconcile by a fresh
    // linearized state read, never retry the stale expected-state CAS.
    let post_commit_reply_loss = AtomicUsize::new(1);
    let after_floor = maintain_exact_history_batch(
        &stores,
        before_floor,
        &transient_retries,
        Some(&post_commit_reply_loss),
    )
    .await
    .expect("reconcile an accepted oldest-floor advancement after reply loss");
    assert_eq!(
        post_commit_reply_loss.load(Ordering::SeqCst),
        0,
        "the test must discard exactly one successful maintenance reply"
    );
    let epoch_one = FencedTransitionV2HistoryEpoch::new(1).expect("epoch one");
    let epoch_eight = FencedTransitionV2HistoryEpoch::new(8).expect("epoch eight");
    assert_eq!(after_floor.generation(), before_floor.generation() + 1);
    assert_eq!(after_floor.active_epoch(), Some(epoch_eight));
    assert_eq!(after_floor.active_epoch(), before_floor.active_epoch());
    assert_eq!(before_floor.retired_through(), None);
    assert_eq!(after_floor.retired_through(), Some(epoch_one));
    assert_eq!(after_floor.reclaim_epoch(), Some(epoch_one));
    assert_eq!(
        after_floor.reclaim_remaining(),
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - FENCED_TRANSITION_V2_RECLAIM_BATCH
    );
    assert_eq!(
        after_floor.reclaimed_entries(),
        before_floor.reclaimed_entries() + FENCED_TRANSITION_V2_RECLAIM_BATCH as u64,
        "the ordered reclaim cursor advances by exactly one bounded batch"
    );
    let observed_after_reply_loss = retry_exact_consensus_operation(&transient_retries, || {
        stores[leader].fenced_transition_v2_history_state()
    })
    .await
    .expect("linearized history reconstructed after maintenance reply loss");
    assert_eq!(observed_after_reply_loss, after_floor);
    assert_eq!(
        stores[current_local_maintenance_leader(&stores).await]
            .maintain_fenced_transition_v2_history(before_floor)
            .await,
        Err(StoreError::FencedTransitionHistoryEpochNotActive),
        "the exact stale expected state is deterministic and cannot reclaim a second batch"
    );
    let observed_after_stale_retry = retry_exact_consensus_operation(&transient_retries, || {
        stores[leader].fenced_transition_v2_history_state()
    })
    .await
    .expect("linearized history after stale maintenance retry");
    assert_eq!(
        observed_after_stale_retry, after_floor,
        "the stale expected-state retry has no second lifecycle, floor, or cursor effect"
    );
    // The public restart above proves durable replay recovery; the exact
    // SQLite snapshot companion is
    // `fenced_transition_v2_snapshot_during_reclaim_preserves_cursor_and_rejects_regression`.
    let (oldest, _) = &representatives[0];
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            stores[leader].fenced_transition_v2_status(oldest)
        })
        .await
        .expect("oldest status at floor"),
        FencedTransitionV2Status::Retired
    );
    let changed_oldest = request_with_changed_body(oldest);
    assert_eq!(
        retry_exact_consensus_operation(&transient_retries, || {
            stores[leader].fenced_transition_v2_status(&changed_oldest)
        })
        .await
        .expect("oldest changed-body status at floor"),
        FencedTransitionV2Status::RequestConflict
    );

    let active_slot = nonce % sessions.len();
    let active_update =
        renew_update_request(nonce, epoch_eight, &sessions[active_slot].1, &provider).await;
    let active_outcome = retry_exact_consensus_operation(&transient_retries, || {
        stores[leader].fenced_transition_v2_batch(vec![active_update.clone()])
    })
    .await
    .expect("active successor remains writable during reclaim")
    .into_iter()
    .next()
    .expect("one active batch outcome")
    .expect("active batch item result");
    sessions[active_slot].1 = active_outcome;
    let during_reclaim = retry_exact_consensus_operation(&transient_retries, || {
        stores[leader].fenced_transition_v2_history_state()
    })
    .await
    .expect("linearized state after active mutation during reclaim");
    let after_second_reclaim =
        maintain_exact_history_batch(&stores, during_reclaim, &transient_retries, None)
            .await
            .expect("continue bounded reclaim without allocating epoch nine");
    assert_eq!(after_second_reclaim.active_epoch(), Some(epoch_eight));
    assert_eq!(after_second_reclaim.retired_through(), Some(epoch_one));
    assert_eq!(after_second_reclaim.reclaim_epoch(), Some(epoch_one));
    assert_eq!(
        after_second_reclaim.reclaim_remaining(),
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - 2 * FENCED_TRANSITION_V2_RECLAIM_BATCH,
        "the physical residual occupies the eighth slot; maintenance cannot allocate epoch nine"
    );

    let database_bytes_by_voter = database_paths
        .iter()
        .map(|path| sqlite_database_family_bytes(path))
        .collect::<Vec<_>>();
    let snapshot_bytes_by_voter = snapshot_paths
        .iter()
        .map(|path| directory_bytes(path))
        .collect::<Vec<_>>();
    let peak_rss_kib = process_peak_rss_kib();
    eprintln!(
        "sdk-702 successor qualification: elapsed_ms={} topology_voters={} release_operations_committed={} active_reclaim_operations_committed=1 total_operations_committed={} rotations={} semantic_history_ceiling_bytes={} transient_exact_retries={} pre_reclaim_db_bytes_by_voter={database_bytes_before_reclaim_by_voter:?} pre_reclaim_snapshot_bytes_by_voter={snapshot_bytes_before_reclaim_by_voter:?} post_reclaim_db_bytes_by_voter={database_bytes_by_voter:?} post_reclaim_snapshot_bytes_by_voter={snapshot_bytes_by_voter:?} reclaimed_entries={} reclaim_remaining={} peak_rss_kib={peak_rss_kib}",
        started.elapsed().as_millis(),
        stores.len(),
        QUALIFICATION_RELEASE_TRANSITIONS,
        QUALIFICATION_RELEASE_TRANSITIONS + 1,
        rotations,
        FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_BYTES,
        transient_retries.load(Ordering::Relaxed),
        after_second_reclaim.reclaimed_entries(),
        after_second_reclaim.reclaim_remaining(),
    );
    assert_voter_resource_ceiling(
        "post-reclaim SQLite database family",
        &database_bytes_by_voter,
        QUALIFICATION_PER_VOTER_DATABASE_CEILING_BYTES,
    );
    assert_voter_resource_ceiling(
        "post-reclaim snapshot directory",
        &snapshot_bytes_by_voter,
        QUALIFICATION_PER_VOTER_SNAPSHOT_CEILING_BYTES,
    );
    #[cfg(target_os = "linux")]
    assert!(
        peak_rss_kib <= QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB,
        "three-voter peak RSS {peak_rss_kib} KiB exceeds the fixed {} KiB ceiling",
        QUALIFICATION_PROCESS_PEAK_RSS_CEILING_KIB,
    );
}
