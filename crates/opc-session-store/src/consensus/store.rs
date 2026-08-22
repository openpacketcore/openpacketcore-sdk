//! Production session store coordinated exclusively by Openraft.
//!
//! Session payload sealing remains an outer adapter concern. Commands admitted
//! here contain only already-enveloped records; the consensus engine, network,
//! log store, snapshots, and state machine never receive an HKMS provider,
//! plaintext key, or plaintext session payload.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

#[cfg(test)]
use std::sync::{LazyLock, Mutex};

use async_trait::async_trait;
use futures_util::stream::{self, BoxStream, StreamExt};
use opc_consensus::engine::error::{ClientWriteError, InitializeError, RaftError};
use opc_consensus::engine::{EmptyNode, LogId, StoredMembership};
use opc_consensus::{
    decode_bounded, durable_openraft_config, encode_bounded, DurableOpenraftDomain,
    EnsureLinearizableOutcome, EnsureLinearizableSupervisor, LinearizableReadBarrier,
    LinearizableReadBarrierError, LinearizableReadLease, DURABLE_CONSENSUS_OPERATION_TIMEOUT,
    DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY, DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
};
use opc_types::Timestamp;
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::raft_adapter::{
    FixedQuorumEngineAdmission, SessionRaftAdapterError, SessionRaftNetworkFactory,
    SessionRaftPeerDirectory, SessionRaftRpcHandler,
};
use super::storage::{self, SessionConsensusStorageError};
use super::types::{
    fenced_transition_v2_batch_outer_request_id, fenced_transition_voter_set_digest,
    validate_fenced_transition_v2_batch,
};
use super::{
    SessionConsensusCommand, SessionConsensusConfigurationEpoch, SessionConsensusIdentity,
    SessionConsensusNodeId, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRequestId, SessionConsensusResponse, SessionConsensusRpcFamily,
    SessionConsensusRpcHandler, SessionConsensusWireRequest, SessionConsensusWireResponse,
    SessionMutationIntent, SessionMutationOutcome, SessionRaft, SessionRaftTypeConfig,
    SessionTopologyMemberBinding, SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
    SESSION_CONSENSUS_SCHEMA_VERSION,
};
use crate::backend::{
    record_expiry_preflights, validate_record_expiry_preflights_at,
    validate_record_expiry_preflights_profile, validate_replication_log_page_owned,
    validate_replication_prefix_owned, BackendInstanceIdentity, CompareAndSet, CompareAndSetResult,
    RecordExpiryPreflight, ReplicationEntry, ReplicationLogRange, SessionBackend, SessionOp,
    SessionOpResult, MAX_RECORD_EXPIRY_PREFLIGHTS,
};
use crate::capability::{BackendCapabilities, SessionStorePlatformProfile};
use crate::clock::{Clock, SystemClock};
use crate::consumer::{
    consumer_request_commitment, derive_consumer_consensus_request_id,
    derive_consumer_fenced_transition_request, derive_consumer_request_binding_id,
    SessionConsumerAuthorizationManifest, SessionConsumerBatchResult, SessionConsumerChange,
    SessionConsumerFencedTransitionError, SessionConsumerIdentity, SessionConsumerOperation,
    SessionConsumerOutcomeUnknown, SessionConsumerRejection, SessionConsumerRequest,
    SessionConsumerResponse, SessionConsumerScope, SessionConsumerStoreError,
    SessionConsumerV2FencedTransitionBatchError, SessionConsumerV2FencedTransitionBatchResult,
    SessionConsumerV2FencedTransitionError, SessionConsumerV2FencedTransitionStatus,
    SessionConsumerV2Operation, SessionConsumerV2Request, SessionConsumerV2Response,
    SessionQuorumConsumer, MAX_SESSION_CONSUMER_BATCH_RESPONSE_BYTES,
};
use crate::error::{LeaseError, StoreError};
use crate::fenced_transition::{
    AtomicFencedTransitionCapability, FencedTransitionExecuteError, FencedTransitionObservation,
    FencedTransitionOutcome, FencedTransitionRequest, FencedTransitionStatus,
    FencedTransitionV2Capability, FencedTransitionV2Effect, FencedTransitionV2HistoryEpoch,
    FencedTransitionV2HistoryState, FencedTransitionV2Request, FencedTransitionV2Status,
    PreparedFencedTransition, PreparedFencedTransitionProtection, FENCED_TRANSITION_SCHEMA_V1,
    FENCED_TRANSITION_SCHEMA_V2, FENCED_TRANSITION_V2_CONSENSUS_SCHEMA_VERSION,
    FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES, FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES,
    FENCED_TRANSITION_V2_MIN_CONSENSUS_RPC_PAYLOAD_BYTES,
    FENCED_TRANSITION_V2_MIN_DURABLE_LOG_ENTRY_BYTES,
};
use crate::lease::{LeaseGuard, SessionLeaseManager};
use crate::model::{OwnerId, SessionKey};
use crate::readiness::{
    DurableReadinessReport, DurableReadinessState, DurableRecoveryProgress, DurableRecoveryState,
    FixedQuorumReadinessReport, FixedQuorumTrafficAuthority, PlacementResiliencePolicy,
    PlacementResilienceReport, ReplicaReadinessObservation, ReplicaReadinessOutcome,
};
use crate::record::StoredSessionRecord;
use crate::restore::{RestoreScanPage, RestoreScanRequest};
use crate::sqlite::SqliteSessionBackend;
use crate::topology::{QuorumTopologyMode, QuorumTopologySummary, ValidatedQuorumTopology};
use crate::topology_attestation::{
    TopologyAttestationSummary, TopologyAttestationTime, VerifiedQuorumTopologyAttestation,
};
use crate::ttl::{
    checked_session_deadline, validate_session_ttl, validate_stored_record_expiry_at,
};

/// Validate a physical fenced-transition request before it crosses the
/// consensus boundary.
///
/// This is deliberately narrower than the SQLite implementation: consumers
/// and protection adapters need the same physical-record admission rule
/// without gaining access to SQLite internals.
#[doc(hidden)]
pub fn validate_consensus_physical_fenced_transition_request(
    request: &FencedTransitionRequest,
) -> Result<(), StoreError> {
    request.validate()?;
    if let Some(record) = request.mutation().record() {
        crate::sqlite::validate_consensus_record(record)?;
    }
    Ok(())
}

mod membership;

use membership::SessionTopologyCoordinatorState;
pub use membership::{
    SessionConsensusStorageAnchor, SessionTopologyCandidateBootstrap,
    SessionTopologyTransitionPeers, SessionTopologyTransportAdmission,
    SessionTopologyTransportAdmissionError,
};

/// Default complete client-operation deadline, including leader discovery,
/// forwarding, quorum confirmation, commit, and local apply.
pub const DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT: Duration =
    DURABLE_CONSENSUS_OPERATION_TIMEOUT;

const SESSION_CONSENSUS_ROUTE_RETRY_BACKOFF: Duration = Duration::from_millis(50);
const FENCED_TRANSITION_V2_STATUS_LEADER_COLLECTION_WINDOW: Duration = Duration::from_micros(500);
const CONSUMER_WATCH_SCOPE_RECHECK_INTERVAL: Duration = Duration::from_millis(50);
const GENERIC_WATCH_AUTHORITY_RECHECK_INTERVAL: Duration = Duration::from_millis(50);
const TOPOLOGY_ENDPOINT_BINDING_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-endpoint-binding/v1\0";
const TOPOLOGY_TLS_BINDING_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-tls-binding/v1\0";
const TOPOLOGY_BACKING_BINDING_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-backing-binding/v1\0";
/// Derive the fixed-width generic consensus envelope ID from V2's complete,
/// authoritative 56-byte request ID.  V1 IDs are never used as input here;
/// the domain separation keeps their collision namespaces distinct even though
/// the outer consensus receipt slot is only 16 bytes wide.
fn fenced_transition_v2_outer_request_id(
    request: &FencedTransitionV2Request,
) -> SessionConsensusRequestId {
    SessionConsensusRequestId::from_bytes(
        crate::fenced_transition::fenced_transition_v2_outer_request_id(request.request_id()),
    )
}

/// Derive the sole outer consensus ID for an ordered V2 transition batch.
///
/// The shared profile helper binds every complete self-authenticating ID in
/// caller order.  It deliberately has no consumer-controlled batch nonce:
/// an exact retry of the same ordered bodies must recover the same one
/// durable command outcome, while any reorder or body commitment change is a
/// distinct command.
fn fenced_transition_v2_batch_request_id(
    requests: &[FencedTransitionV2Request],
) -> Result<SessionConsensusRequestId, StoreError> {
    fenced_transition_v2_batch_outer_request_id(requests).map(SessionConsensusRequestId::from_bytes)
}

fn topology_node_bindings(
    topology: &ValidatedQuorumTopology,
) -> BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding> {
    topology
        .members()
        .iter()
        .filter_map(|descriptor| {
            let node_id = topology.consensus_node_id(descriptor.replica_id())?;
            let mut endpoint = Sha256::new();
            endpoint.update(TOPOLOGY_ENDPOINT_BINDING_DOMAIN);
            endpoint.update(Sha256::digest(descriptor.endpoint().host().as_bytes()));
            endpoint.update(descriptor.endpoint().port().to_be_bytes());
            let mut tls = Sha256::new();
            tls.update(TOPOLOGY_TLS_BINDING_DOMAIN);
            tls.update(Sha256::digest(
                descriptor.tls_identity().as_str().as_bytes(),
            ));
            let mut backing = Sha256::new();
            backing.update(TOPOLOGY_BACKING_BINDING_DOMAIN);
            backing.update(descriptor.backing_identity().fingerprint());
            Some((
                node_id,
                SessionTopologyMemberBinding::new(
                    descriptor.configuration_fingerprint(),
                    endpoint.finalize().into(),
                    tls.finalize().into(),
                    backing.finalize().into(),
                ),
            ))
        })
        .collect()
}

fn attestation_deadline_from_verification_start(
    verification_started_at: tokio::time::Instant,
    valid_for: Duration,
) -> Option<tokio::time::Instant> {
    verification_started_at.checked_add(valid_for)
}

/// Fail-closed construction or cluster-formation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConsensusSessionStoreOpenError {
    /// Dynamic consensus requires Linux descriptor-pinned SQLite handling and
    /// is unsupported on this platform.
    #[error("dynamic session consensus is unsupported on this platform")]
    DynamicConsensusUnsupportedPlatform,
    /// The topology was not a consensus-scoped HA or consensus singleton.
    #[error("session consensus topology is invalid")]
    InvalidTopology,
    /// The exact remote consensus peer set did not match admitted membership.
    #[error("session consensus peer set does not match topology")]
    PeerSetMismatch,
    /// Legacy or corrupt durable authority requires an explicit recovery
    /// workflow before this member may join.
    #[error("session consensus durable recovery is required")]
    RecoveryRequired,
    /// Persisted identity/schema does not match this deployment.
    #[error("session consensus durable identity does not match configuration")]
    DurableIdentityMismatch,
    /// Durable storage could not be opened or validated.
    #[error("session consensus durable storage is unavailable")]
    StorageUnavailable,
    /// Fixed durable quorum snapshots require Linux descriptor-pinned SQLite
    /// handling and are unsupported on this platform.
    #[error("fixed durable quorum is unsupported on this platform")]
    FixedQuorumUnsupportedPlatform,
    /// The fixed SDK Openraft runtime profile was invalid.
    #[error("session consensus runtime configuration is invalid")]
    InvalidRuntimeConfiguration,
    /// Openraft could not start or stopped fatally.
    #[error("session consensus engine is unavailable")]
    EngineUnavailable,
    /// Cluster formation or exact live voter admission did not converge.
    #[error("session consensus cluster formation or membership admission was rejected")]
    ClusterFormationRejected,
    /// This exact joining-candidate transition was durably cancelled.
    #[error("session consensus candidate transition was cancelled")]
    CandidateTransitionCancelled,
}

/// Redaction-safe current Openraft observation for readiness and operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct SessionConsensusStatus {
    /// Local canonical node ID.
    pub node_id: SessionConsensusNodeId,
    /// Current Openraft term.
    pub term: u64,
    /// Current leader, when known.
    pub leader_id: Option<SessionConsensusNodeId>,
    /// Highest local log index, whether committed or not.
    pub last_log_index: Option<u64>,
    /// Highest locally applied log index.
    pub applied_index: Option<u64>,
    /// Whether exact configured membership has been admitted and remains live.
    pub admitted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperatorRecoveryCommitError {
    NotLocalLeader,
    Rejected,
    Unavailable,
}

impl From<SessionConsensusStorageError> for ConsensusSessionStoreOpenError {
    fn from(error: SessionConsensusStorageError) -> Self {
        match error {
            SessionConsensusStorageError::UnsupportedPlatform => {
                Self::DynamicConsensusUnsupportedPlatform
            }
            SessionConsensusStorageError::RecoveryRequired
            | SessionConsensusStorageError::CorruptState => Self::RecoveryRequired,
            SessionConsensusStorageError::IdentityMismatch
            | SessionConsensusStorageError::SchemaVersionMismatch
            | SessionConsensusStorageError::InvalidIdentity => Self::DurableIdentityMismatch,
            SessionConsensusStorageError::BackendUnavailable => Self::StorageUnavailable,
        }
    }
}

impl From<SessionRaftAdapterError> for ConsensusSessionStoreOpenError {
    fn from(_: SessionRaftAdapterError) -> Self {
        Self::PeerSetMismatch
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ForwardMutationRequest {
    request_id: SessionConsensusRequestId,
    intent: SessionMutationIntent,
    /// The exact consumer scope whose check must remain valid through leader
    /// admission. Ordinary in-process store callers carry no consumer scope.
    required_consumer_scope: ForwardConsumerScope,
}

impl fmt::Debug for ForwardMutationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ForwardMutationRequest(<redacted>)")
    }
}

/// Explicitly distinguishes an internal forwarding call from one made for a
/// stateless consumer. This is deliberately not an `Option`: a peer which
/// does not understand consumer scope must fail decoding instead of treating a
/// missing field as an internal request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ForwardConsumerScope {
    Internal,
    Consumer(Box<SessionConsensusIdentity>),
}

impl fmt::Debug for ForwardConsumerScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ForwardConsumerScope(<redacted>)")
    }
}

impl ForwardConsumerScope {
    fn from_optional(scope: Option<SessionConsensusIdentity>) -> Self {
        scope.map_or(Self::Internal, |scope| Self::Consumer(Box::new(scope)))
    }

    fn consumer_scope(&self) -> Option<&SessionConsensusIdentity> {
        match self {
            Self::Internal => None,
            Self::Consumer(scope) => Some(scope),
        }
    }

    fn is_consumer_scoped(&self) -> bool {
        matches!(self, Self::Consumer(_))
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ForwardRequest {
    Mutation(ForwardMutationRequest),
    /// Ask the current leader to join one exact-scope V2 status logical-time
    /// cohort.  This is deliberately a separate forwarding shape: forwarding
    /// a raw `AdvanceLogicalTime` from every voter would recreate one proposal
    /// per node before the leader had an opportunity to coalesce arrivals.
    FencedTransitionV2StatusLogicalTimeTicket {
        required_consumer_scope: Box<SessionConsensusIdentity>,
    },
    RecordExpiryPreflight {
        preflights: BoundedRecordExpiryPreflights,
        /// The consumer scope that must remain valid through the leader's
        /// logical-time proposal. Internal callers do not carry this scope.
        required_consumer_scope: ForwardConsumerScope,
    },
}

impl fmt::Debug for ForwardRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ForwardRequest(<redacted>)")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
struct BoundedRecordExpiryPreflights(Vec<RecordExpiryPreflight>);

impl BoundedRecordExpiryPreflights {
    fn try_from_slice(preflights: &[RecordExpiryPreflight]) -> Result<Self, StoreError> {
        validate_record_expiry_preflights_profile(preflights)?;
        Ok(Self(preflights.to_vec()))
    }

    fn into_inner(self) -> Vec<RecordExpiryPreflight> {
        self.0
    }
}

struct BoundedRecordExpiryPreflightsVisitor;

impl<'de> Visitor<'de> for BoundedRecordExpiryPreflightsVisitor {
    type Value = BoundedRecordExpiryPreflights;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "at most {MAX_RECORD_EXPIRY_PREFLIGHTS} record-expiry descriptors"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence
            .size_hint()
            .is_some_and(|size| size > MAX_RECORD_EXPIRY_PREFLIGHTS)
        {
            return Err(serde::de::Error::custom(
                "record-expiry preflight exceeds the operation limit",
            ));
        }
        let mut preflights = Vec::with_capacity(
            sequence
                .size_hint()
                .unwrap_or(0)
                .min(MAX_RECORD_EXPIRY_PREFLIGHTS),
        );
        while let Some(preflight) = sequence.next_element()? {
            if preflights.len() == MAX_RECORD_EXPIRY_PREFLIGHTS {
                return Err(serde::de::Error::custom(
                    "record-expiry preflight exceeds the operation limit",
                ));
            }
            preflights.push(preflight);
        }
        Ok(BoundedRecordExpiryPreflights(preflights))
    }
}

impl<'de> Deserialize<'de> for BoundedRecordExpiryPreflights {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedRecordExpiryPreflightsVisitor)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ForwardMutationReply {
    Applied(Box<SessionConsensusResponse>),
    RecordExpiryPreflight(Result<(), StoreError>),
    NotLeader {
        leader: Option<SessionConsensusNodeId>,
    },
    /// A forwarded write or local proposal crossed a boundary after which the
    /// command may exist and must be resolved by its retained ID.
    OutcomeUnknown,
    Unavailable,
}

/// One committed logical-time fence returned by the leader-owned V2 status
/// cohort.  The exact scope travels with the receipt so a caller can never
/// apply a ticket obtained for one authority epoch to another epoch's local
/// SQLite acceptance read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FencedTransitionV2StatusLogicalTimeTicket {
    required_consumer_scope: SessionConsensusIdentity,
    raft_log_index: u64,
    logical_time: Timestamp,
}

impl FencedTransitionV2StatusLogicalTimeTicket {
    fn try_from_response(
        required_consumer_scope: SessionConsensusIdentity,
        response: SessionConsensusResponse,
    ) -> Result<Self, StoreError> {
        match response.result? {
            SessionMutationOutcome::Unit => {}
            _ => return Err(consensus_unavailable()),
        }
        if response.raft_log_index == 0 {
            return Err(consensus_unavailable());
        }
        let logical_time = response.logical_time.ok_or_else(consensus_unavailable)?;
        Ok(Self {
            required_consumer_scope,
            raft_log_index: response.raft_log_index,
            logical_time,
        })
    }
}

/// Bounded leader ticket result for the consumer-only logical-time cohort.
///
/// It intentionally contains no authority snapshot or status result.  The
/// ingress node waits for its own application index then performs the
/// existing fresh atomic scope/recovery/activation/status read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum FencedTransitionV2StatusLogicalTimeTicketReply {
    Ticket(Box<FencedTransitionV2StatusLogicalTimeTicket>),
    Rejected(StoreError),
    NotLeader {
        leader: Option<SessionConsensusNodeId>,
    },
    Unavailable,
}

impl fmt::Debug for ForwardMutationReply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ForwardMutationReply(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConsensusPeerCallFailure {
    BeforeTransmission,
    AfterTransmission,
}

/// Proven placement of a mutation relative to the leader proposal boundary.
///
/// This stays internal so legacy callers retain their `StoreError` contract,
/// while the protected V2 adapter can make the one cleanup decision that the
/// old error-only surface could not express.
enum ConsensusSubmissionEffect {
    /// No peer received the request and the local leader did not accept it.
    NotTransmitted(StoreError),
    /// A forwarding write or a leader proposal may have been accepted.
    OutcomeUnknown,
    /// A committed response was authenticated and correlated to the intent.
    Committed(SessionConsensusResponse),
    /// A deterministic rejection was authenticated before any proposal.
    Rejected(SessionConsensusResponse),
}

#[derive(Clone, Copy)]
struct LocalProposalAuthority {
    origin: SessionConsensusNodeId,
    allows_operator_recovery: bool,
    /// An activated raw V2 mutation already consumed the final fixed-quorum
    /// authority, recovery, activation, and logical-time snapshot after its
    /// direct leader barrier. No asynchronous authority read may be inserted
    /// between that snapshot and `client_write_ff`.
    fixed_raw_v2_snapshot: bool,
}

/// Local resources owned through one proposal's completion.  The optional
/// freeze marker is used exclusively by the leader-owned V2 status ticket
/// cohort and is set immediately before Openraft accepts the command.
struct LocalProposalExecution {
    proposal_permit: tokio::sync::OwnedSemaphorePermit,
    operation_guard: tokio::sync::OwnedRwLockReadGuard<()>,
    cohort_freeze: Option<Arc<AtomicBool>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct ReadBarrierRequest;

/// Store-application feature probe carried over the already authenticated
/// internal read family. Older peers reject this non-unit payload, which is
/// the required fail-closed answer for a mixed-version membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FencedTransitionCapabilityProbe {
    schema_version: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum FencedTransitionCapabilityReply {
    V1,
    Unsupported,
}

/// V2's exact-profile probe is a separate payload from V1's frozen probe.
/// A peer that only understands V1 rejects this payload during decoding, which
/// is an intentionally fail-closed V2 capability answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FencedTransitionV2CapabilityProbe {
    schema_version: u16,
    profile_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum FencedTransitionV2CapabilityReply {
    /// The exact immutable V2 profile this voter implements.
    V2 {
        profile_digest: [u8; 32],
    },
    Unsupported,
}

fn fenced_transition_v2_capability_probe_reply(
    probe: FencedTransitionV2CapabilityProbe,
    local_capability: Option<FencedTransitionV2Capability>,
) -> FencedTransitionV2CapabilityReply {
    let local_profile = crate::fenced_transition::fenced_transition_v2_profile_digest();
    if probe.schema_version == FENCED_TRANSITION_SCHEMA_V2
        && probe.profile_digest == local_profile
        && local_capability == Some(FencedTransitionV2Capability::V2)
    {
        FencedTransitionV2CapabilityReply::V2 {
            profile_digest: local_profile,
        }
    } else {
        FencedTransitionV2CapabilityReply::Unsupported
    }
}

/// Exact V1 admission at one linearizable membership scope.
///
/// A fresh proof is intentionally not cached: only a committed activation
/// certificate lets later requests use normal Raft quorum availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FencedTransitionCapabilityAdmission {
    Activated,
    FreshUnanimous,
}

/// Exact V2 admission at one linearizable membership scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FencedTransitionV2CapabilityAdmission {
    Activated,
    FreshUnanimous,
}

/// One consumer scope validated while holding the topology read gate.
///
/// The guard remains owned by the admission until the local operation returns,
/// preventing a topology transition from invalidating its scope mid-work.
struct ConsumerScopeAdmission {
    required_scope: SessionConsensusIdentity,
    _operation_guard: tokio::sync::OwnedRwLockReadGuard<()>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ReadBarrierReply {
    Ready(Option<LogId<SessionConsensusNodeId>>),
    NotLeader {
        leader: Option<SessionConsensusNodeId>,
    },
    RecoveryRequired,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinearizableBarrierFailure {
    RecoveryRequired,
    Unavailable,
}

/// Fixed-cardinality, redaction-safe diagnostic counters for one consensus
/// store instance.
///
/// This snapshot deliberately contains only failure-stage totals. It never
/// carries a peer, scope, path, SQL statement, or backend error value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ConsensusStoreDiagnosticSnapshot {
    /// SQLite operation-worker admissions that exhausted their deadline.
    pub sqlite_worker_permit_deadline: u64,
    /// SQLite connection-lock acquisitions that exhausted their deadline.
    pub sqlite_connection_lock_deadline: u64,
    /// SQLite operations that exhausted their execution deadline.
    pub sqlite_execution_deadline: u64,
    /// Consensus proposal-permit acquisitions that exhausted their deadline.
    pub proposal_permit_deadline: u64,
    /// Raw V2 read barriers rejected as unavailable before proposal.
    pub raw_read_barrier_unavailable: u64,
    /// Raw V2 read barriers that exhausted their deadline before proposal.
    pub raw_read_barrier_deadline: u64,
    /// Atomic V2 authority snapshots rejected by the durable backend.
    pub atomic_v2_authority_snapshot_backend_error: u64,
    /// Atomic V2 authority snapshots that exhausted their deadline.
    pub atomic_v2_authority_snapshot_deadline: u64,
    /// V2 mutations rejected before OpenRaft accepted the command.
    pub client_write_ff_preaccept_failure: u64,
    /// Forwarding routes that exhausted their deadline.
    pub route_deadline: u64,
    /// Forwarding routes whose OpenRaft metrics watch closed unexpectedly.
    pub route_metrics_watch_closed: u64,
    /// V2 status requests admitted at this local store.
    pub status_local_requests: u64,
    /// V2 status requests admitted by the node-local cohort.
    pub status_ingress_requests: u64,
    /// V2 status requests admitted by the leader-owned cohort.
    pub status_leader_cohort_requests: u64,
    /// Node-local V2 status representatives sent toward the leader.
    pub status_representatives: u64,
    /// Logical-time proposals issued for V2 status cohorts.
    pub status_proposals: u64,
    /// Final durable ingress admissions that exhausted their deadline.
    pub final_durable_ingress_admission_deadline: u64,
    /// Aggregate nanoseconds spent in final durable ingress admission.
    pub final_durable_ingress_admission_duration_nanos: u64,
}

#[derive(Default)]
pub(crate) struct ConsensusStoreDiagnosticCounters {
    sqlite_worker_permit_deadline: AtomicU64,
    sqlite_connection_lock_deadline: AtomicU64,
    sqlite_execution_deadline: AtomicU64,
    proposal_permit_deadline: AtomicU64,
    raw_read_barrier_unavailable: AtomicU64,
    raw_read_barrier_deadline: AtomicU64,
    atomic_v2_authority_snapshot_backend_error: AtomicU64,
    atomic_v2_authority_snapshot_deadline: AtomicU64,
    client_write_ff_preaccept_failure: AtomicU64,
    route_deadline: AtomicU64,
    route_metrics_watch_closed: AtomicU64,
    status_local_requests: AtomicU64,
    status_ingress_requests: AtomicU64,
    status_leader_cohort_requests: AtomicU64,
    status_representatives: AtomicU64,
    status_proposals: AtomicU64,
    final_durable_ingress_admission_deadline: AtomicU64,
    final_durable_ingress_admission_duration_nanos: AtomicU64,
}

impl ConsensusStoreDiagnosticCounters {
    pub(crate) fn increment_sqlite_worker_permit_deadline(&self) {
        self.sqlite_worker_permit_deadline
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_sqlite_connection_lock_deadline(&self) {
        self.sqlite_connection_lock_deadline
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn increment_sqlite_execution_deadline(&self) {
        self.sqlite_execution_deadline
            .fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> ConsensusStoreDiagnosticSnapshot {
        ConsensusStoreDiagnosticSnapshot {
            sqlite_worker_permit_deadline: self
                .sqlite_worker_permit_deadline
                .load(Ordering::Relaxed),
            sqlite_connection_lock_deadline: self
                .sqlite_connection_lock_deadline
                .load(Ordering::Relaxed),
            sqlite_execution_deadline: self.sqlite_execution_deadline.load(Ordering::Relaxed),
            proposal_permit_deadline: self.proposal_permit_deadline.load(Ordering::Relaxed),
            raw_read_barrier_unavailable: self.raw_read_barrier_unavailable.load(Ordering::Relaxed),
            raw_read_barrier_deadline: self.raw_read_barrier_deadline.load(Ordering::Relaxed),
            atomic_v2_authority_snapshot_backend_error: self
                .atomic_v2_authority_snapshot_backend_error
                .load(Ordering::Relaxed),
            atomic_v2_authority_snapshot_deadline: self
                .atomic_v2_authority_snapshot_deadline
                .load(Ordering::Relaxed),
            client_write_ff_preaccept_failure: self
                .client_write_ff_preaccept_failure
                .load(Ordering::Relaxed),
            route_deadline: self.route_deadline.load(Ordering::Relaxed),
            route_metrics_watch_closed: self.route_metrics_watch_closed.load(Ordering::Relaxed),
            status_local_requests: self.status_local_requests.load(Ordering::Relaxed),
            status_ingress_requests: self.status_ingress_requests.load(Ordering::Relaxed),
            status_leader_cohort_requests: self
                .status_leader_cohort_requests
                .load(Ordering::Relaxed),
            status_representatives: self.status_representatives.load(Ordering::Relaxed),
            status_proposals: self.status_proposals.load(Ordering::Relaxed),
            final_durable_ingress_admission_deadline: self
                .final_durable_ingress_admission_deadline
                .load(Ordering::Relaxed),
            final_durable_ingress_admission_duration_nanos: self
                .final_durable_ingress_admission_duration_nanos
                .load(Ordering::Relaxed),
        }
    }
}

struct ConsensusSessionStoreInner {
    raft: SessionRaft,
    raft_handler: SessionRaftRpcHandler,
    backend: SqliteSessionBackend,
    storage_identity: SessionConsensusIdentity,
    local_node_id: SessionConsensusNodeId,
    peer_directory: SessionRaftPeerDirectory,
    topology_coordinator: Arc<SessionTopologyCoordinatorState>,
    bootstrap_members: BTreeSet<SessionConsensusNodeId>,
    bootstrap_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    topology: QuorumTopologySummary,
    clock: Arc<dyn Clock>,
    operation_timeout: Duration,
    admitted: Arc<AtomicBool>,
    topology_attestation_time_high_water: AtomicU64,
    linearizability: EnsureLinearizableSupervisor<SessionRaftTypeConfig>,
    read_barrier: LinearizableReadBarrier<SessionRaftTypeConfig>,
    raw_v2_read_barrier: LinearizableReadBarrier<SessionRaftTypeConfig>,
    logical_read_time: LogicalReadTimeSupervisor,
    fenced_transition_v2_status_logical_time_ingress:
        FencedTransitionV2StatusLogicalTimeIngressSupervisor,
    fenced_transition_v2_status_logical_time: FencedTransitionV2StatusLogicalTimeSupervisor,
    fenced_transition_v2_status_batch: FencedTransitionV2StatusBatchSupervisor,
    proposal_admission: Arc<tokio::sync::Semaphore>,
    diagnostics: Arc<ConsensusStoreDiagnosticCounters>,
}

/// Test-only result injection at the post-acceptance `client_write_ff`
/// receiver boundary. The real Raft receiver remains supervised so this seam
/// preserves the production proposal-admission lifetime while making the
/// caller-visible receiver result deterministic.
#[cfg(test)]
#[derive(Clone, Copy)]
enum AcceptedClientWriteReceiverTestOutcome {
    ForwardToLeader,
}

#[cfg(test)]
static ACCEPTED_RECEIVER_TEST_OUTCOMES: LazyLock<
    Mutex<VecDeque<AcceptedClientWriteReceiverTestOutcome>>,
> = LazyLock::new(|| Mutex::new(VecDeque::new()));

/// One bounded status response awaiting a shared exact-scope acceptance read.
struct FencedTransitionV2StatusBatchRequest {
    scope: SessionConsensusIdentity,
    profile_digest: [u8; 32],
    placement_policy: PlacementResiliencePolicy,
    request: FencedTransitionV2Request,
    deadline: tokio::time::Instant,
    reply: tokio::sync::oneshot::Sender<Result<FencedTransitionV2Status, StoreError>>,
    _admission: tokio::sync::OwnedSemaphorePermit,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct FencedTransitionV2StatusBatchKey {
    scope: SessionConsensusIdentity,
    profile_digest: [u8; 32],
    placement_policy: PlacementResiliencePolicy,
}

impl From<&FencedTransitionV2StatusBatchRequest> for FencedTransitionV2StatusBatchKey {
    fn from(request: &FencedTransitionV2StatusBatchRequest) -> Self {
        Self {
            scope: request.scope,
            profile_digest: request.profile_digest,
            placement_policy: request.placement_policy,
        }
    }
}

/// Node-local bounded V2 status batches.
///
/// A batch retains request bodies through the shared logical-time ticket and
/// local apply wait, then consumes them in exactly one fresh SQLite snapshot.
/// It is only keyed by immutable exact-scope acceptance inputs; it does not
/// cache an authority or status answer beyond the immediate reply fanout.
#[derive(Clone)]
struct FencedTransitionV2StatusBatchSupervisor {
    requests: tokio::sync::mpsc::Sender<FencedTransitionV2StatusBatchRequest>,
    admission: Arc<tokio::sync::Semaphore>,
}

impl FencedTransitionV2StatusBatchSupervisor {
    fn new() -> (
        Self,
        tokio::sync::mpsc::Receiver<FencedTransitionV2StatusBatchRequest>,
    ) {
        let (requests, receiver) =
            tokio::sync::mpsc::channel(DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY);
        (
            Self {
                requests,
                admission: Arc::new(tokio::sync::Semaphore::new(
                    DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY,
                )),
            },
            receiver,
        )
    }

    fn start(
        receiver: tokio::sync::mpsc::Receiver<FencedTransitionV2StatusBatchRequest>,
        store: Weak<ConsensusSessionStoreInner>,
    ) {
        tokio::spawn(run_fenced_transition_v2_status_batch_supervisor(
            receiver, store,
        ));
    }

    async fn status_before(
        &self,
        scope: SessionConsensusIdentity,
        profile_digest: [u8; 32],
        placement_policy: PlacementResiliencePolicy,
        request: FencedTransitionV2Request,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionV2Status, StoreError> {
        let admission =
            tokio::time::timeout_at(deadline, Arc::clone(&self.admission).acquire_owned())
                .await
                .map_err(|_| consensus_unavailable())?
                .map_err(|_| consensus_unavailable())?;
        let (reply, response) = tokio::sync::oneshot::channel();
        let request = FencedTransitionV2StatusBatchRequest {
            scope,
            profile_digest,
            placement_policy,
            request,
            deadline,
            reply,
            _admission: admission,
        };
        tokio::time::timeout_at(deadline, self.requests.send(request))
            .await
            .map_err(|_| consensus_unavailable())?
            .map_err(|_| consensus_unavailable())?;
        tokio::time::timeout_at(deadline, response)
            .await
            .map_err(|_| consensus_unavailable())?
            .map_err(|_| consensus_unavailable())?
    }
}

async fn run_fenced_transition_v2_status_batch_supervisor(
    mut requests: tokio::sync::mpsc::Receiver<FencedTransitionV2StatusBatchRequest>,
    store: Weak<ConsensusSessionStoreInner>,
) {
    let mut deferred = VecDeque::with_capacity(DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY);
    loop {
        let first = match deferred.pop_front() {
            Some(request) => request,
            None => match requests.recv().await {
                Some(request) => request,
                None => return,
            },
        };
        let key = FencedTransitionV2StatusBatchKey::from(&first);
        let mut cohort = vec![first];
        while let Ok(request) = requests.try_recv() {
            if FencedTransitionV2StatusBatchKey::from(&request) == key {
                cohort.push(request);
            } else {
                deferred.push_back(request);
            }
        }
        let deadline = cohort
            .iter()
            .map(|request| request.deadline)
            .max()
            .unwrap_or_else(tokio::time::Instant::now);
        let requests = cohort
            .iter()
            .map(|request| request.request.clone())
            .collect();
        let result = match store.upgrade() {
            Some(inner) => {
                ConsensusSessionStore { inner }
                    .fenced_transition_v2_status_batch_at_scope(key, requests, deadline)
                    .await
            }
            None => Err(consensus_unavailable()),
        };
        match result {
            Ok(statuses) if statuses.len() == cohort.len() => {
                for (request, status) in cohort.into_iter().zip(statuses) {
                    let _ = request.reply.send(Ok(status));
                }
            }
            Ok(_) => {
                for request in cohort {
                    let _ = request.reply.send(Err(consensus_unavailable()));
                }
            }
            Err(error) => {
                for request in cohort {
                    let _ = request.reply.send(Err(error.clone()));
                }
            }
        }
    }
}

/// One caller awaiting a shared committed logical-time advance.
///
/// The owned admission permit bounds both queued and in-progress waiters. A
/// dropped caller only drops its reply receiver; it cannot cancel a cohort
/// that has already begun its consensus proposal.
struct LogicalReadTimeRequest {
    required_consumer_scope: Option<SessionConsensusIdentity>,
    deadline: tokio::time::Instant,
    reply: tokio::sync::oneshot::Sender<Result<SessionConsensusResponse, StoreError>>,
    _admission: tokio::sync::OwnedSemaphorePermit,
}

/// Fixed, cancellation-safe coalescing for logical read time advances.
///
/// A cohort contains only callers with the same exact consumer authority
/// scope. The single worker owns the actual proposal, so a disconnected
/// caller cannot leave an accepted logical-time command unsupervised. The
/// worker captures only a weak store reference; dropping all stores closes
/// the channel rather than creating an owner cycle or a permanent task.
#[derive(Clone)]
struct LogicalReadTimeSupervisor {
    requests: tokio::sync::mpsc::Sender<LogicalReadTimeRequest>,
    admission: Arc<tokio::sync::Semaphore>,
}

impl LogicalReadTimeSupervisor {
    fn new() -> (Self, tokio::sync::mpsc::Receiver<LogicalReadTimeRequest>) {
        let (requests, receiver) =
            tokio::sync::mpsc::channel(DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY);
        (
            Self {
                requests,
                admission: Arc::new(tokio::sync::Semaphore::new(
                    DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY,
                )),
            },
            receiver,
        )
    }

    fn start(
        receiver: tokio::sync::mpsc::Receiver<LogicalReadTimeRequest>,
        store: Weak<ConsensusSessionStoreInner>,
    ) {
        tokio::spawn(run_logical_read_time_supervisor(receiver, store));
    }

    async fn logical_read_time_before(
        &self,
        required_consumer_scope: Option<SessionConsensusIdentity>,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsensusResponse, StoreError> {
        let admission =
            tokio::time::timeout_at(deadline, Arc::clone(&self.admission).acquire_owned())
                .await
                .map_err(|_| consensus_unavailable())?
                .map_err(|_| consensus_unavailable())?;
        let (reply, response) = tokio::sync::oneshot::channel();
        let request = LogicalReadTimeRequest {
            required_consumer_scope,
            deadline,
            reply,
            _admission: admission,
        };
        tokio::time::timeout_at(deadline, self.requests.send(request))
            .await
            .map_err(|_| consensus_unavailable())?
            .map_err(|_| consensus_unavailable())?;
        tokio::time::timeout_at(deadline, response)
            .await
            .map_err(|_| consensus_unavailable())?
            .map_err(|_| consensus_unavailable())?
    }
}

async fn run_logical_read_time_supervisor(
    mut requests: tokio::sync::mpsc::Receiver<LogicalReadTimeRequest>,
    store: Weak<ConsensusSessionStoreInner>,
) {
    let mut deferred = VecDeque::with_capacity(DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY);
    loop {
        let first = match deferred.pop_front() {
            Some(request) => request,
            None => match requests.recv().await {
                Some(request) => request,
                None => return,
            },
        };
        let scope = first.required_consumer_scope;
        let mut cohort = vec![first];

        // Snapshot the already-admitted bounded queue. Later arrivals form a
        // later committed cohort unless they are received before the active
        // proposal crosses its causal boundary.
        append_same_scope_logical_read_requests(scope, &mut deferred, &mut cohort);
        while cohort.len() + deferred.len() < DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY {
            match requests.try_recv() {
                Ok(request) if request.required_consumer_scope == scope => cohort.push(request),
                Ok(request) => deferred.push_back(request),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty)
                | Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        let deadline = cohort
            .iter()
            .map(|request| request.deadline)
            .max()
            .unwrap_or_else(tokio::time::Instant::now);
        let result = match store.upgrade() {
            Some(inner) => {
                let store = ConsensusSessionStore { inner };
                store
                    .submit_request_before(
                        SessionConsensusRequestId::new(),
                        SessionMutationIntent::AdvanceLogicalTime,
                        scope,
                        deadline,
                    )
                    .await
                    .map_err(|error| match error {
                        // A shared logical-time advance has no caller-visible
                        // mutation. Its unresolved result remains a transient
                        // read failure, exactly as the direct path did.
                        StoreError::BackendOperationOutcomeUnavailable => consensus_unavailable(),
                        error => error,
                    })
            }
            None => Err(consensus_unavailable()),
        };
        for request in cohort {
            let _ = request.reply.send(result.clone());
        }
    }
}

/// One status caller admitted to a bounded logical-time ticket cohort.
///
/// The permit remains owned by the supervisor after an ingress future is
/// cancelled.  This keeps a ticket that may already have reached the leader
/// bounded and supervised through the accepted Raft proposal.
struct FencedTransitionV2StatusLogicalTimeRequest {
    required_consumer_scope: SessionConsensusIdentity,
    deadline: tokio::time::Instant,
    reply: tokio::sync::oneshot::Sender<FencedTransitionV2StatusLogicalTimeTicketReply>,
    _admission: tokio::sync::OwnedSemaphorePermit,
}

/// Membership of one active exact-scope cohort.
///
/// `frozen` is the causal boundary: `propose_on_local_leader` flips it in the
/// instruction sequence immediately before `client_write_ff`.  A request
/// that acquires this membership before that flip shares the ticket; one that
/// observes it after the flip is retained for a later proposal.
struct FencedTransitionV2StatusLogicalTimeCohort {
    frozen: Arc<AtomicBool>,
    members: tokio::sync::Mutex<Vec<FencedTransitionV2StatusLogicalTimeRequest>>,
}

impl FencedTransitionV2StatusLogicalTimeCohort {
    fn new(first: FencedTransitionV2StatusLogicalTimeRequest) -> Arc<Self> {
        Arc::new(Self {
            frozen: Arc::new(AtomicBool::new(false)),
            members: tokio::sync::Mutex::new(vec![first]),
        })
    }

    async fn try_join(
        &self,
        request: FencedTransitionV2StatusLogicalTimeRequest,
    ) -> Result<(), FencedTransitionV2StatusLogicalTimeRequest> {
        if self.frozen.load(Ordering::Acquire) {
            return Err(request);
        }
        let mut members = self.members.lock().await;
        if self.frozen.load(Ordering::Acquire) {
            return Err(request);
        }
        members.push(request);
        Ok(())
    }

    async fn close_and_take(&self) -> Vec<FencedTransitionV2StatusLogicalTimeRequest> {
        self.frozen.store(true, Ordering::Release);
        std::mem::take(&mut *self.members.lock().await)
    }
}

/// Fixed-capacity, leader-owned exact-scope tickets for fixed-quorum V2
/// status reads.  Every node's ingress cohort contributes at most one member
/// to this supervisor, which is the sole owner of an `AdvanceLogicalTime`
/// proposal.
#[derive(Clone)]
struct FencedTransitionV2StatusLogicalTimeSupervisor {
    requests: tokio::sync::mpsc::Sender<FencedTransitionV2StatusLogicalTimeRequest>,
    admission: Arc<tokio::sync::Semaphore>,
}

impl FencedTransitionV2StatusLogicalTimeSupervisor {
    fn new() -> (
        Self,
        tokio::sync::mpsc::Receiver<FencedTransitionV2StatusLogicalTimeRequest>,
    ) {
        let (requests, receiver) =
            tokio::sync::mpsc::channel(DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY);
        (
            Self {
                requests,
                admission: Arc::new(tokio::sync::Semaphore::new(
                    DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY,
                )),
            },
            receiver,
        )
    }

    fn start(
        receiver: tokio::sync::mpsc::Receiver<FencedTransitionV2StatusLogicalTimeRequest>,
        store: Weak<ConsensusSessionStoreInner>,
    ) {
        tokio::spawn(
            run_fenced_transition_v2_status_logical_time_cohort_supervisor_with_collection_window(
                receiver,
                FENCED_TRANSITION_V2_STATUS_LEADER_COLLECTION_WINDOW,
                move |scope, deadline, cohort_freeze| {
                    let store = store.clone();
                    async move {
                        let Some(inner) = store.upgrade() else {
                            return FencedTransitionV2StatusLogicalTimeTicketReply::Unavailable;
                        };
                        ConsensusSessionStore { inner }
                            .fenced_transition_v2_status_logical_time_on_local_leader(
                                scope,
                                deadline,
                                cohort_freeze,
                            )
                            .await
                    }
                },
            ),
        );
    }

    async fn ticket_before(
        &self,
        required_consumer_scope: SessionConsensusIdentity,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionV2StatusLogicalTimeTicketReply, StoreError> {
        let admission =
            tokio::time::timeout_at(deadline, Arc::clone(&self.admission).acquire_owned())
                .await
                .map_err(|_| consensus_unavailable())?
                .map_err(|_| consensus_unavailable())?;
        let (reply, response) = tokio::sync::oneshot::channel();
        let request = FencedTransitionV2StatusLogicalTimeRequest {
            required_consumer_scope,
            deadline,
            reply,
            _admission: admission,
        };
        tokio::time::timeout_at(deadline, self.requests.send(request))
            .await
            .map_err(|_| consensus_unavailable())?
            .map_err(|_| consensus_unavailable())?;
        tokio::time::timeout_at(deadline, response)
            .await
            .map_err(|_| consensus_unavailable())?
            .map_err(|_| consensus_unavailable())
    }
}

/// Fixed-capacity node-local ingress for V2 status tickets.
///
/// Each fixed-quorum voter admits its own callers here before resolving the
/// leader.  It forwards exactly one authenticated ticket request for every
/// frozen local cohort.  The leader's local representative enters the
/// separate leader-owned supervisor above, so it cannot recurse into this
/// ingress queue or wait on itself.
#[derive(Clone)]
struct FencedTransitionV2StatusLogicalTimeIngressSupervisor {
    requests: tokio::sync::mpsc::Sender<FencedTransitionV2StatusLogicalTimeRequest>,
    admission: Arc<tokio::sync::Semaphore>,
}

impl FencedTransitionV2StatusLogicalTimeIngressSupervisor {
    fn new() -> (
        Self,
        tokio::sync::mpsc::Receiver<FencedTransitionV2StatusLogicalTimeRequest>,
    ) {
        let (requests, receiver) =
            tokio::sync::mpsc::channel(DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY);
        (
            Self {
                requests,
                admission: Arc::new(tokio::sync::Semaphore::new(
                    DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY,
                )),
            },
            receiver,
        )
    }

    fn start(
        receiver: tokio::sync::mpsc::Receiver<FencedTransitionV2StatusLogicalTimeRequest>,
        store: Weak<ConsensusSessionStoreInner>,
    ) {
        tokio::spawn(
            run_fenced_transition_v2_status_logical_time_cohort_supervisor(
                receiver,
                move |scope, deadline, cohort_freeze| {
                    let store = store.clone();
                    async move {
                        let Some(inner) = store.upgrade() else {
                            return FencedTransitionV2StatusLogicalTimeTicketReply::Unavailable;
                        };
                        ConsensusSessionStore { inner }
                            .fenced_transition_v2_status_logical_time_ticket_representative(
                                scope,
                                deadline,
                                cohort_freeze,
                            )
                            .await
                    }
                },
            ),
        );
    }

    async fn ticket_before(
        &self,
        required_consumer_scope: SessionConsensusIdentity,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionV2StatusLogicalTimeTicketReply, StoreError> {
        let admission =
            tokio::time::timeout_at(deadline, Arc::clone(&self.admission).acquire_owned())
                .await
                .map_err(|_| consensus_unavailable())?
                .map_err(|_| consensus_unavailable())?;
        let (reply, response) = tokio::sync::oneshot::channel();
        let request = FencedTransitionV2StatusLogicalTimeRequest {
            required_consumer_scope,
            deadline,
            reply,
            _admission: admission,
        };
        tokio::time::timeout_at(deadline, self.requests.send(request))
            .await
            .map_err(|_| consensus_unavailable())?
            .map_err(|_| consensus_unavailable())?;
        tokio::time::timeout_at(deadline, response)
            .await
            .map_err(|_| consensus_unavailable())?
            .map_err(|_| consensus_unavailable())
    }
}

/// Run one bounded exact-scope cohort scheduler.
///
/// The representative callback owns the causal freeze boundary.  The leader
/// callback freezes immediately before Openraft accepts its proposal; the
/// ingress callback freezes immediately before it calls the authenticated
/// leader ticket endpoint.  The scheduler retains every permit and reply
/// sender through completion, so dropped callers cannot abandon accepted work.
async fn run_fenced_transition_v2_status_logical_time_cohort_supervisor<F, Fut>(
    requests: tokio::sync::mpsc::Receiver<FencedTransitionV2StatusLogicalTimeRequest>,
    representative: F,
) where
    F: Fn(SessionConsensusIdentity, tokio::time::Instant, Arc<AtomicBool>) -> Fut + Send + Sync,
    Fut: Future<Output = FencedTransitionV2StatusLogicalTimeTicketReply> + Send,
{
    run_fenced_transition_v2_status_logical_time_cohort_supervisor_with_collection_window(
        requests,
        Duration::ZERO,
        representative,
    )
    .await;
}

async fn run_fenced_transition_v2_status_logical_time_cohort_supervisor_with_collection_window<
    F,
    Fut,
>(
    mut requests: tokio::sync::mpsc::Receiver<FencedTransitionV2StatusLogicalTimeRequest>,
    collection_window: Duration,
    representative: F,
) where
    F: Fn(SessionConsensusIdentity, tokio::time::Instant, Arc<AtomicBool>) -> Fut + Send + Sync,
    Fut: Future<Output = FencedTransitionV2StatusLogicalTimeTicketReply> + Send,
{
    let mut deferred = VecDeque::with_capacity(DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY);
    loop {
        let first = match deferred.pop_front() {
            Some(request) => request,
            None => match requests.recv().await {
                Some(request) => request,
                None => return,
            },
        };
        let scope = first.required_consumer_scope;
        let deadline = first.deadline;
        let cohort = FencedTransitionV2StatusLogicalTimeCohort::new(first);

        // Drain only requests already admitted to the bounded queue before
        // polling the representative. Incompatible scopes retain FIFO order;
        // later matching arrivals may still join until the callback freezes
        // the causal boundary.
        append_same_scope_fenced_transition_v2_status_requests(scope, &mut deferred, &cohort).await;
        while let Ok(request) = requests.try_recv() {
            if request.required_consumer_scope == scope {
                match cohort.try_join(request).await {
                    Ok(()) => {}
                    Err(request) => deferred.push_back(request),
                }
            } else {
                deferred.push_back(request);
            }
        }

        // Only the leader-owned supervisor supplies a nonzero window. It is
        // absolute, never extended by arrivals, and capped by the first
        // request's deadline. This gives the fixed set of voter ingress
        // representatives one bounded same-host transport interval to join
        // before the proposal is created, without holding the topology gate
        // or moving either causal freeze boundary.
        if !collection_window.is_zero() {
            let collection_deadline = tokio::time::Instant::now()
                .checked_add(collection_window)
                .map_or(deadline, |candidate| candidate.min(deadline));
            if tokio::time::Instant::now() < collection_deadline {
                tokio::time::sleep_until(collection_deadline).await;
            }
            append_same_scope_fenced_transition_v2_status_requests(scope, &mut deferred, &cohort)
                .await;
            while let Ok(request) = requests.try_recv() {
                if request.required_consumer_scope == scope {
                    match cohort.try_join(request).await {
                        Ok(()) => {}
                        Err(request) => deferred.push_back(request),
                    }
                } else {
                    deferred.push_back(request);
                }
            }
        }

        let proposal_cohort = Arc::clone(&cohort);
        let proposal = representative(scope, deadline, proposal_cohort.frozen.clone());
        tokio::pin!(proposal);
        let mut requests_open = true;

        let result = loop {
            tokio::select! {
                result = &mut proposal => break result,
                request = requests.recv(), if requests_open => match request {
                    Some(request) if request.required_consumer_scope == scope => {
                        match cohort.try_join(request).await {
                            Ok(()) => {}
                            Err(request) => deferred.push_back(request),
                        }
                    }
                    Some(request) => deferred.push_back(request),
                    None => requests_open = false,
                },
            }
        };
        for request in cohort.close_and_take().await {
            let _ = request.reply.send(result.clone());
        }
    }
}

/// Move already-deferred same-scope ticket requests into the active cohort.
///
/// Every incompatible request is put back in its original relative order.
/// This is only called before the representative is created, so a matching
/// request cannot observe a completed ticket or a frozen cohort here.
async fn append_same_scope_fenced_transition_v2_status_requests(
    scope: SessionConsensusIdentity,
    deferred: &mut VecDeque<FencedTransitionV2StatusLogicalTimeRequest>,
    cohort: &FencedTransitionV2StatusLogicalTimeCohort,
) {
    let deferred_len = deferred.len();
    for _ in 0..deferred_len {
        let Some(request) = deferred.pop_front() else {
            break;
        };
        if request.required_consumer_scope == scope {
            match cohort.try_join(request).await {
                Ok(()) => {}
                Err(request) => deferred.push_back(request),
            }
        } else {
            // Preserve the FIFO order of every incompatible authority scope.
            deferred.push_back(request);
        }
    }
}

/// Move one exact-authority cohort out of the deferred FIFO while preserving
/// the relative order of every incompatible scope for later cohorts.
fn append_same_scope_logical_read_requests(
    scope: Option<SessionConsensusIdentity>,
    deferred: &mut VecDeque<LogicalReadTimeRequest>,
    cohort: &mut Vec<LogicalReadTimeRequest>,
) {
    let deferred_len = deferred.len();
    for _ in 0..deferred_len {
        let Some(request) = deferred.pop_front() else {
            break;
        };
        if request.required_consumer_scope == scope {
            cohort.push(request);
        } else {
            // Preserve FIFO order for every incompatible authority scope.
            deferred.push_back(request);
        }
    }
}

/// SQLite session state coordinated by the SDK's single Openraft engine.
///
/// Call [`Self::open`] first, start the consensus-only network listener using
/// [`Self::rpc_handler`], then call [`Self::initialize_cluster`] on every
/// member. On clean first formation the method lets only the canonical lowest
/// node initialize Openraft while the other pristine nodes wait for replicated
/// membership. Restarted members with durable Openraft state skip bootstrap.
#[derive(Clone)]
pub struct ConsensusSessionStore {
    inner: Arc<ConsensusSessionStoreInner>,
}

/// Quorum-side adapter exposing only typed stateless consumer operations.
///
/// This adapter owns a [`ConsensusSessionStore`] rather than an arbitrary
/// backend port, so every mutation retains the store's leader forwarding,
/// durable request identity, exact-membership admission, and stale-lease
/// fencing behavior. It cannot express a vote, topology transition, snapshot,
/// raw replication append, or rebuild operation.
#[derive(Clone)]
pub struct ConsensusSessionConsumerService {
    store: ConsensusSessionStore,
}

impl fmt::Debug for ConsensusSessionConsumerService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsensusSessionConsumerService(<redacted>)")
    }
}

impl fmt::Debug for ConsensusSessionStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ConsensusSessionStore(<redacted>)")
    }
}

impl ConsensusSessionStore {
    /// Return fixed, redaction-safe diagnostic counters for this store.
    pub fn diagnostic_snapshot(&self) -> ConsensusStoreDiagnosticSnapshot {
        self.inner.diagnostics.snapshot()
    }

    #[cfg(test)]
    fn inject_accepted_client_write_receiver_outcome(
        &self,
        outcome: AcceptedClientWriteReceiverTestOutcome,
    ) {
        ACCEPTED_RECEIVER_TEST_OUTCOMES
            .lock()
            .expect("accepted receiver test outcomes lock")
            .push_back(outcome);
    }

    fn require_dynamic_consensus_platform() -> Result<(), ConsensusSessionStoreOpenError> {
        if cfg!(target_os = "linux") {
            Ok(())
        } else {
            Err(ConsensusSessionStoreOpenError::DynamicConsensusUnsupportedPlatform)
        }
    }

    /// Start one durable Openraft node without yet forming pristine membership.
    ///
    /// `topology` contains only immutable member descriptors. `backend` is this
    /// node's sole local state-machine database; every remote member must be
    /// represented by exactly one consensus-only peer instead of a backend
    /// adapter. Dynamic consensus is Linux-only; other platforms return
    /// [`ConsensusSessionStoreOpenError::DynamicConsensusUnsupportedPlatform`]
    /// before creating consensus snapshot or database state.
    pub async fn open(
        topology: ValidatedQuorumTopology,
        backend: SqliteSessionBackend,
        snapshot_dir: impl Into<PathBuf>,
        peers: BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
    ) -> Result<Self, ConsensusSessionStoreOpenError> {
        Self::require_dynamic_consensus_platform()?;
        Self::open_with_clock(
            topology,
            backend,
            snapshot_dir,
            peers,
            Arc::new(SystemClock),
            DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
        )
        .await
    }

    /// Start one immutable fixed three- or five-voter durable quorum node.
    ///
    /// This path requires a fixed-quorum topology, exact scope-bound
    /// authenticated remote peers. Dynamic membership construction remains
    /// separate and is intentionally unavailable for this immutable quorum
    /// profile.
    pub async fn open_fixed_durable_quorum(
        topology: ValidatedQuorumTopology,
        backend: SqliteSessionBackend,
        snapshot_dir: impl Into<PathBuf>,
        peers: BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
    ) -> Result<Self, ConsensusSessionStoreOpenError> {
        Self::open_fixed_durable_quorum_with_clock(
            topology,
            backend,
            snapshot_dir,
            peers,
            Arc::new(SystemClock),
            DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
        )
        .await
    }

    /// Start one immutable fixed three- or five-voter durable quorum node
    /// with an injected logical clock and bounded complete operation deadline.
    ///
    /// This preserves the same fixed-quorum topology, durable-storage, and
    /// exact scope-bound peer admission as [`Self::open_fixed_durable_quorum`].
    /// It exists for deterministic retention qualification, where advancing a
    /// test clock must not relax any production admission invariant.
    pub async fn open_fixed_durable_quorum_with_clock(
        topology: ValidatedQuorumTopology,
        backend: SqliteSessionBackend,
        snapshot_dir: impl Into<PathBuf>,
        peers: BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
        clock: Arc<dyn Clock>,
        operation_timeout: Duration,
    ) -> Result<Self, ConsensusSessionStoreOpenError> {
        if !cfg!(target_os = "linux") {
            return Err(ConsensusSessionStoreOpenError::FixedQuorumUnsupportedPlatform);
        }
        if operation_timeout.is_zero() || operation_timeout > Duration::from_secs(60) {
            return Err(ConsensusSessionStoreOpenError::InvalidRuntimeConfiguration);
        }
        if topology.summary().mode() != QuorumTopologyMode::FixedDurableQuorum {
            return Err(ConsensusSessionStoreOpenError::InvalidTopology);
        }
        if !backend.is_file_backed() {
            return Err(ConsensusSessionStoreOpenError::StorageUnavailable);
        }
        let identity = topology
            .consensus_identity()
            .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)?;
        let local_node_id = topology
            .local_consensus_node_id()
            .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)?;
        let members = topology
            .members()
            .iter()
            .map(|descriptor| {
                topology
                    .consensus_node_id(descriptor.replica_id())
                    .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if !matches!(members.len(), 3 | 5)
            || members.len() != topology.summary().configured_members()
            || !members.contains(&local_node_id)
        {
            return Err(ConsensusSessionStoreOpenError::InvalidTopology);
        }
        let expected_peers = members
            .iter()
            .copied()
            .filter(|node_id| *node_id != local_node_id)
            .collect::<BTreeSet<_>>();
        if peers.keys().copied().collect::<BTreeSet<_>>() != expected_peers
            || peers.iter().any(|(node_id, peer)| {
                peer.node_id() != *node_id || peer.scope_identity() != Some(identity)
            })
        {
            return Err(ConsensusSessionStoreOpenError::PeerSetMismatch);
        }
        let topology_coordinator = Arc::new(SessionTopologyCoordinatorState::try_from_topology(
            &topology,
        )?);
        let diagnostics = Arc::new(ConsensusStoreDiagnosticCounters::default());
        let backend = backend.with_consensus_diagnostics(Arc::clone(&diagnostics));
        let network =
            SessionRaftNetworkFactory::try_new(identity, local_node_id, members.clone(), peers)?;
        let peer_directory = network.peer_directory();
        let bindings = topology_node_bindings(&topology);
        let placement_policy = topology
            .summary()
            .fixed_durable_placement_policy()
            .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)?;
        let (log_store, state_machine, storage_identity) =
            storage::open_fixed_with_member_bindings(
                &backend,
                snapshot_dir,
                identity,
                members.clone(),
                bindings.clone(),
                peer_directory.clone(),
                placement_policy,
            )
            .await?;
        let (membership_scope, _) = backend
            .consensus_membership_scope_snapshot(storage_identity)
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?;
        topology_coordinator
            .load_retained_transitions(&membership_scope)
            .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?;
        let config = Arc::new(session_raft_config()?);
        let raft = SessionRaft::new(local_node_id, config, network, log_store, state_machine)
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::EngineUnavailable)?;
        let admitted = Arc::new(AtomicBool::new(false));
        let raft_handler = SessionRaftRpcHandler::new_fixed_durable_quorum(
            raft.clone(),
            peer_directory.clone(),
            local_node_id,
            FixedQuorumEngineAdmission::new(
                backend.clone(),
                storage_identity,
                members.clone(),
                bindings.clone(),
                placement_policy,
                Arc::clone(&admitted),
            ),
        );
        let linearizability = EnsureLinearizableSupervisor::new(raft.clone());
        let read_barrier = LinearizableReadBarrier::new(
            local_node_id,
            linearizability.clone(),
            raft.metrics(),
            // Readiness and generic reads require a fresh point-in-time
            // quorum proof. An ownership/read lease is not reachability
            // evidence after an immediate partition.
            LinearizableReadLease::Disabled,
        );
        let raw_v2_read_barrier = LinearizableReadBarrier::new(
            local_node_id,
            linearizability.clone(),
            raft.metrics(),
            // Raw V2 admission is the only leased read boundary. It keeps
            // the bounded same-term optimization without allowing a cached
            // proof to satisfy readiness or any generic read.
            LinearizableReadLease::Enabled,
        );
        let topology_summary = topology.summary().clone();
        let topology_attestation_time_high_water = topology_summary
            .attestation_admission()
            .production_verified_at()
            .map(TopologyAttestationTime::unix_seconds)
            .unwrap_or(0);
        let (logical_read_time, logical_read_time_receiver) = LogicalReadTimeSupervisor::new();
        let (
            fenced_transition_v2_status_logical_time_ingress,
            fenced_transition_v2_status_logical_time_ingress_receiver,
        ) = FencedTransitionV2StatusLogicalTimeIngressSupervisor::new();
        let (
            fenced_transition_v2_status_logical_time,
            fenced_transition_v2_status_logical_time_receiver,
        ) = FencedTransitionV2StatusLogicalTimeSupervisor::new();
        let (fenced_transition_v2_status_batch, fenced_transition_v2_status_batch_receiver) =
            FencedTransitionV2StatusBatchSupervisor::new();

        let inner = Arc::new(ConsensusSessionStoreInner {
            raft,
            raft_handler,
            backend,
            storage_identity,
            local_node_id,
            peer_directory,
            topology_coordinator,
            bootstrap_members: members,
            bootstrap_bindings: bindings,
            topology: topology_summary,
            clock,
            operation_timeout,
            admitted,
            topology_attestation_time_high_water: AtomicU64::new(
                topology_attestation_time_high_water,
            ),
            linearizability,
            read_barrier,
            raw_v2_read_barrier,
            logical_read_time,
            fenced_transition_v2_status_logical_time_ingress,
            fenced_transition_v2_status_logical_time,
            fenced_transition_v2_status_batch,
            proposal_admission: Arc::new(tokio::sync::Semaphore::new(
                DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
            )),
            diagnostics,
        });
        LogicalReadTimeSupervisor::start(logical_read_time_receiver, Arc::downgrade(&inner));
        FencedTransitionV2StatusLogicalTimeIngressSupervisor::start(
            fenced_transition_v2_status_logical_time_ingress_receiver,
            Arc::downgrade(&inner),
        );
        FencedTransitionV2StatusLogicalTimeSupervisor::start(
            fenced_transition_v2_status_logical_time_receiver,
            Arc::downgrade(&inner),
        );
        FencedTransitionV2StatusBatchSupervisor::start(
            fenced_transition_v2_status_batch_receiver,
            Arc::downgrade(&inner),
        );
        Ok(Self { inner })
    }

    /// Start one durable Openraft node with a bounded complete operation
    /// deadline.
    ///
    /// The deadline covers leader discovery/forwarding, quorum confirmation,
    /// commit, and local apply for writes and linearizable readiness/reads.
    pub async fn open_with_operation_timeout(
        topology: ValidatedQuorumTopology,
        backend: SqliteSessionBackend,
        snapshot_dir: impl Into<PathBuf>,
        peers: BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
        operation_timeout: Duration,
    ) -> Result<Self, ConsensusSessionStoreOpenError> {
        Self::require_dynamic_consensus_platform()?;
        Self::open_with_clock(
            topology,
            backend,
            snapshot_dir,
            peers,
            Arc::new(SystemClock),
            operation_timeout,
        )
        .await
    }

    /// Start a node with an injected logical-clock source and bounded complete
    /// operation deadline. Primarily useful for deterministic qualification.
    /// On non-Linux platforms this fails before topology validation or any
    /// consensus-owned filesystem or schema initialization.
    pub async fn open_with_clock(
        topology: ValidatedQuorumTopology,
        backend: SqliteSessionBackend,
        snapshot_dir: impl Into<PathBuf>,
        peers: BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
        clock: Arc<dyn Clock>,
        operation_timeout: Duration,
    ) -> Result<Self, ConsensusSessionStoreOpenError> {
        Self::require_dynamic_consensus_platform()?;
        if operation_timeout.is_zero() || operation_timeout > Duration::from_secs(60) {
            return Err(ConsensusSessionStoreOpenError::InvalidRuntimeConfiguration);
        }
        if !matches!(
            topology.summary().mode(),
            QuorumTopologyMode::ValidatedHa
                | QuorumTopologyMode::AttestedHa
                | QuorumTopologyMode::LabSingleton
        ) {
            return Err(ConsensusSessionStoreOpenError::InvalidTopology);
        }
        let identity = topology
            .consensus_identity()
            .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)?;
        let local_node_id = topology
            .local_consensus_node_id()
            .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)?;
        let members = topology
            .members()
            .iter()
            .map(|descriptor| {
                topology
                    .consensus_node_id(descriptor.replica_id())
                    .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if members.len() != topology.summary().configured_members()
            || !members.contains(&local_node_id)
        {
            return Err(ConsensusSessionStoreOpenError::InvalidTopology);
        }
        let expected_peers = members
            .iter()
            .copied()
            .filter(|node_id| *node_id != local_node_id)
            .collect::<BTreeSet<_>>();
        if peers.keys().copied().collect::<BTreeSet<_>>() != expected_peers {
            return Err(ConsensusSessionStoreOpenError::PeerSetMismatch);
        }
        let topology_coordinator = Arc::new(SessionTopologyCoordinatorState::try_from_topology(
            &topology,
        )?);
        let diagnostics = Arc::new(ConsensusStoreDiagnosticCounters::default());
        let backend = backend.with_consensus_diagnostics(Arc::clone(&diagnostics));

        let network = SessionRaftNetworkFactory::try_new(
            identity,
            local_node_id,
            members.clone(),
            peers.clone(),
        )?;
        let peer_directory = network.peer_directory();
        let bindings = topology_node_bindings(&topology);
        let (log_store, state_machine, storage_identity) = storage::open_with_member_bindings(
            &backend,
            snapshot_dir,
            identity,
            members.clone(),
            bindings.clone(),
            peer_directory.clone(),
        )
        .await?;
        let (membership_scope, _) = backend
            .consensus_membership_scope_snapshot(storage_identity)
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?;
        topology_coordinator
            .load_retained_transitions(&membership_scope)
            .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?;
        let config = Arc::new(session_raft_config()?);
        let raft = SessionRaft::new(local_node_id, config, network, log_store, state_machine)
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::EngineUnavailable)?;
        let raft_handler =
            SessionRaftRpcHandler::new(raft.clone(), peer_directory.clone(), local_node_id);
        let linearizability = EnsureLinearizableSupervisor::new(raft.clone());
        let read_barrier = LinearizableReadBarrier::new(
            local_node_id,
            linearizability.clone(),
            raft.metrics(),
            // Readiness and generic reads require a fresh point-in-time
            // quorum proof. An ownership/read lease is not reachability
            // evidence after an immediate partition.
            LinearizableReadLease::Disabled,
        );
        let raw_v2_read_barrier = LinearizableReadBarrier::new(
            local_node_id,
            linearizability.clone(),
            raft.metrics(),
            // Keep only raw V2 admission on the bounded, revalidated
            // same-term lease after reopening a durable store.
            LinearizableReadLease::Enabled,
        );
        let topology_summary = topology.summary().clone();
        let topology_attestation_time_high_water = topology_summary
            .attestation_admission()
            .production_verified_at()
            .map(TopologyAttestationTime::unix_seconds)
            .unwrap_or(0);
        let (logical_read_time, logical_read_time_receiver) = LogicalReadTimeSupervisor::new();
        let (
            fenced_transition_v2_status_logical_time_ingress,
            fenced_transition_v2_status_logical_time_ingress_receiver,
        ) = FencedTransitionV2StatusLogicalTimeIngressSupervisor::new();
        let (
            fenced_transition_v2_status_logical_time,
            fenced_transition_v2_status_logical_time_receiver,
        ) = FencedTransitionV2StatusLogicalTimeSupervisor::new();
        let (fenced_transition_v2_status_batch, fenced_transition_v2_status_batch_receiver) =
            FencedTransitionV2StatusBatchSupervisor::new();

        let inner = Arc::new(ConsensusSessionStoreInner {
            raft,
            raft_handler,
            backend,
            storage_identity,
            local_node_id,
            peer_directory,
            topology_coordinator,
            bootstrap_members: members,
            bootstrap_bindings: bindings,
            topology: topology_summary,
            clock,
            operation_timeout,
            admitted: Arc::new(AtomicBool::new(false)),
            topology_attestation_time_high_water: AtomicU64::new(
                topology_attestation_time_high_water,
            ),
            linearizability,
            read_barrier,
            raw_v2_read_barrier,
            logical_read_time,
            fenced_transition_v2_status_logical_time_ingress,
            fenced_transition_v2_status_logical_time,
            fenced_transition_v2_status_batch,
            proposal_admission: Arc::new(tokio::sync::Semaphore::new(
                DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
            )),
            diagnostics,
        });
        LogicalReadTimeSupervisor::start(logical_read_time_receiver, Arc::downgrade(&inner));
        FencedTransitionV2StatusLogicalTimeIngressSupervisor::start(
            fenced_transition_v2_status_logical_time_ingress_receiver,
            Arc::downgrade(&inner),
        );
        FencedTransitionV2StatusLogicalTimeSupervisor::start(
            fenced_transition_v2_status_logical_time_receiver,
            Arc::downgrade(&inner),
        );
        FencedTransitionV2StatusBatchSupervisor::start(
            fenced_transition_v2_status_batch_receiver,
            Arc::downgrade(&inner),
        );
        Ok(Self { inner })
    }

    /// Consensus-only handler to install on the authenticated session-net
    /// listener before cluster formation begins.
    pub fn rpc_handler(&self) -> Arc<dyn SessionConsensusRpcHandler> {
        Arc::new(SessionConsensusService {
            store: self.clone(),
        })
    }

    /// Build the typed least-authority service for authenticated stateless
    /// application consumers.
    ///
    /// The returned service is not a consensus RPC handler and cannot be used
    /// to add a local member, access SQLite/snapshot state, or dispatch raw
    /// replication/rebuild commands. Its caller must authenticate and
    /// authorize each [`SessionConsumerIdentity`] before calling it.
    pub fn consumer_service(&self) -> ConsensusSessionConsumerService {
        ConsensusSessionConsumerService {
            store: self.clone(),
        }
    }

    /// Return the exact currently admitted scope for stateless consumers.
    ///
    /// A state-process composition layer uses this value to configure both
    /// its consumer authorizer and externally constructed clients. A client
    /// must be recreated with a successor scope after a completed topology
    /// transition; this accessor never weakens the exact-scope check at the
    /// consumer service boundary.
    pub fn consumer_scope(&self) -> Result<SessionConsumerScope, StoreError> {
        self.require_exact_membership_admission()?;
        if self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum
            && !self
                .inner
                .topology
                .fixed_durable_placement_policy()
                .is_some_and(|placement_policy| {
                    self.inner.backend.fixed_quorum_authority_is_exact_now(
                        self.inner.storage_identity,
                        &self.inner.bootstrap_members,
                        &self.inner.bootstrap_bindings,
                        placement_policy,
                    )
                })
        {
            return Err(consensus_unavailable());
        }
        self.current_scope()
            .map(|(identity, _)| SessionConsumerScope::new(identity))
    }

    fn local_fenced_transition_capability(&self) -> AtomicFencedTransitionCapability {
        // This store owns the concrete SQLite consensus state machine that
        // implements V1. Independent legacy capability bits do not establish
        // this combined contract and are deliberately not consulted here.
        AtomicFencedTransitionCapability::V1
    }

    fn local_fenced_transition_v2_capability(&self) -> Option<FencedTransitionV2Capability> {
        // V2 is a separate concrete SQLite state-machine profile.  Do not
        // infer it from V1 or from any individual backend feature bit. The
        // profile-bound payload, command-schema, RPC, and durable-log limits
        // must all match the concrete local consensus backend, or a follower
        // could reject a V2 command after this node advertised support.
        local_fenced_transition_v2_capability_for_backend_capabilities(
            self.inner.backend.consensus_capabilities(),
            SESSION_CONSENSUS_SCHEMA_VERSION,
            SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
            self.inner.backend.consensus_log_entry_max_bytes(),
        )
    }

    /// Select the fixed-quorum consumer warm route from local implementation
    /// support alone. This is deliberately not an activation or authority
    /// check: the leader receives the captured consumer scope and consumes its
    /// uncached atomic snapshot at the sole effect-admission boundary.
    fn fixed_raw_v2_consumer_warm_route(
        &self,
        required_consumer_scope: Option<&SessionConsensusIdentity>,
    ) -> bool {
        required_consumer_scope.is_some()
            && self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum
            && self.local_fenced_transition_v2_capability()
                == Some(FencedTransitionV2Capability::V2)
    }

    fn fixed_raw_v2_consumer_warm_route_for_intent(
        &self,
        intent: &SessionMutationIntent,
        required_consumer_scope: Option<&SessionConsensusIdentity>,
    ) -> bool {
        is_raw_fenced_transition_v2_mutation(intent, false)
            && self.fixed_raw_v2_consumer_warm_route(required_consumer_scope)
    }

    /// Admit V1 for one exact linearizable voter scope.
    ///
    /// A durable certificate first permits ordinary quorum availability.  In
    /// its absence every exact voter must answer the authenticated V1 probe;
    /// the caller may then carry that proof only into the first transition's
    /// same-position activation command.  An unavailable, unsupported, or
    /// changed voter never becomes a quorum-derived compatibility proof.
    async fn require_fenced_transition_capability_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionCapabilityAdmission, StoreError> {
        self.require_exact_membership_admission()?;
        self.linearizable_barrier_before(deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        let expected_scope = self.current_scope()?;
        if self.local_fenced_transition_capability() != AtomicFencedTransitionCapability::V1 {
            return Err(unsupported_fenced_transition());
        }
        if !expected_scope.1.contains(&self.inner.local_node_id) {
            return Err(consensus_unavailable());
        }
        let activated = self
            .inner
            .backend
            .consensus_fenced_transition_activation_matches_scope(
                self.inner.storage_identity,
                expected_scope.0,
                expected_scope.1.clone(),
            )
            .await?;
        if activated {
            if self.current_scope()? != expected_scope || !self.exact_membership_is_admitted() {
                return Err(consensus_unavailable());
            }
            return Ok(FencedTransitionCapabilityAdmission::Activated);
        }
        let probes = expected_scope
            .1
            .iter()
            .copied()
            .filter(|member| *member != self.inner.local_node_id)
            .map(|member| async move {
                self.call_peer::<_, FencedTransitionCapabilityReply>(
                    member,
                    SessionConsensusRpcFamily::ReadBarrier,
                    &FencedTransitionCapabilityProbe {
                        schema_version: FENCED_TRANSITION_SCHEMA_V1,
                    },
                    deadline,
                )
                .await
            });
        if futures_util::future::join_all(probes)
            .await
            .into_iter()
            .any(|reply| !matches!(reply, Ok(FencedTransitionCapabilityReply::V1)))
        {
            return Err(unsupported_fenced_transition());
        }
        if self.current_scope()? != expected_scope || !self.exact_membership_is_admitted() {
            return Err(consensus_unavailable());
        }
        Ok(FencedTransitionCapabilityAdmission::FreshUnanimous)
    }

    /// Admit V2 for one exact linearizable voter scope and one immutable
    /// fixed-profile digest. V1 activation evidence is deliberately never
    /// consulted here: a V2 receipt/history change requires every exact voter
    /// to freshly acknowledge the exact V2 profile before the first command.
    async fn require_fenced_transition_v2_capability_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionV2CapabilityAdmission, StoreError> {
        self.require_exact_membership_admission()?;
        self.linearizable_barrier_before(deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        self.require_fenced_transition_v2_capability_after_barrier(deadline)
            .await
    }

    /// Validate V2's exact activation certificate or obtain its fresh
    /// unanimous proof after the caller has already fenced the local leader.
    ///
    /// This deliberately does not perform a second generic read barrier or
    /// application-authority snapshot. The raw V2 mutation path invokes it
    /// only after its operation-gate-held direct leased V2 barrier, with
    /// the uncached application authority revalidated at the final proposal
    /// acceptance boundary. Read APIs continue through
    /// `require_fenced_transition_v2_capability_before` above.
    async fn require_fenced_transition_v2_capability_after_barrier(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionV2CapabilityAdmission, StoreError> {
        let expected_scope = self.current_scope()?;
        if self.local_fenced_transition_v2_capability() != Some(FencedTransitionV2Capability::V2) {
            return Err(unsupported_fenced_transition_v2());
        }
        if !expected_scope.1.contains(&self.inner.local_node_id) {
            return Err(consensus_unavailable());
        }
        let profile_digest = crate::fenced_transition::fenced_transition_v2_profile_digest();
        let activated = self
            .inner
            .backend
            .consensus_fenced_transition_v2_activation_matches_scope(
                self.inner.storage_identity,
                expected_scope.0,
                expected_scope.1.clone(),
                profile_digest,
            )
            .await?;
        if activated {
            if self.current_scope()? != expected_scope || !self.exact_membership_is_admitted() {
                return Err(consensus_unavailable());
            }
            return Ok(FencedTransitionV2CapabilityAdmission::Activated);
        }
        let probes = expected_scope
            .1
            .iter()
            .copied()
            .filter(|member| *member != self.inner.local_node_id)
            .map(|member| async move {
                self.call_peer::<_, FencedTransitionV2CapabilityReply>(
                    member,
                    SessionConsensusRpcFamily::ReadBarrier,
                    &FencedTransitionV2CapabilityProbe {
                        schema_version: FENCED_TRANSITION_SCHEMA_V2,
                        profile_digest,
                    },
                    deadline,
                )
                .await
            });
        if futures_util::future::join_all(probes)
            .await
            .into_iter()
            .any(|reply| {
                !matches!(
                    reply,
                    Ok(FencedTransitionV2CapabilityReply::V2 {
                        profile_digest: received,
                    }) if received == profile_digest
                )
            })
        {
            return Err(unsupported_fenced_transition_v2());
        }
        if self.current_scope()? != expected_scope || !self.exact_membership_is_admitted() {
            return Err(consensus_unavailable());
        }
        Ok(FencedTransitionV2CapabilityAdmission::FreshUnanimous)
    }

    /// Fence one raw V2 mutation on this already-selected local leader.
    ///
    /// The operation gate is held by the caller, so an accepted topology
    /// writer cannot change the scope through the proposal. `admit` checks
    /// the same local leader term around a quorum read-index and waits for
    /// local application; exact membership is checked on both sides. The
    /// caller must immediately perform V2 activation/scope validation before
    /// any further await that could reach proposal admission.
    async fn admit_raw_v2_mutation_on_local_leader_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), ForwardMutationReply> {
        if self.require_exact_membership_admission().is_err() {
            return Err(ForwardMutationReply::Unavailable);
        }
        match self.inner.raw_v2_read_barrier.admit(deadline).await {
            Ok(_) => {}
            Err(LinearizableReadBarrierError::NotLeader { leader }) => {
                return Err(ForwardMutationReply::NotLeader { leader });
            }
            Err(LinearizableReadBarrierError::Unavailable) | Err(_) => {
                if tokio::time::Instant::now() >= deadline {
                    self.inner
                        .diagnostics
                        .raw_read_barrier_deadline
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    self.inner
                        .diagnostics
                        .raw_read_barrier_unavailable
                        .fetch_add(1, Ordering::Relaxed);
                }
                return Err(ForwardMutationReply::Unavailable);
            }
        }
        if self.require_exact_membership_admission().is_err() {
            return Err(ForwardMutationReply::Unavailable);
        }
        Ok(())
    }

    /// Advertise V1 after either the exact durable certificate or a fresh
    /// unanimous proof that can immediately seed the first transition.
    pub async fn fenced_transition_capability(
        &self,
    ) -> Result<Option<AtomicFencedTransitionCapability>, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.require_fenced_transition_capability_before(deadline)
            .await
            .map(|_| Some(AtomicFencedTransitionCapability::V1))
    }

    /// Advertise V2 only after the exact durable V2 certificate or a fresh,
    /// unanimous exact-profile proof that can seed the first V2 transition.
    pub async fn fenced_transition_v2_capability(
        &self,
    ) -> Result<Option<FencedTransitionV2Capability>, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.require_fenced_transition_v2_capability_before(deadline)
            .await
            .map(|_| Some(FencedTransitionV2Capability::V2))
    }

    /// Obtain a fresh record plus the durable fence floor for one exact key.
    ///
    /// This observation owns one consensus logical-time barrier. It does not
    /// allocate a fence; a later acquire succeeds only if the observed floor
    /// is still exact at the transition's committed position.
    pub async fn observe_fenced_transition(
        &self,
        key: &SessionKey,
    ) -> Result<FencedTransitionObservation, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        let probed_scope = self.current_scope()?;
        // A read-only observation is safe under a fresh exact unanimous
        // proof.  Requiring the durable marker here would make the first
        // Acquire impossible: callers need this fence floor to form the
        // transition that atomically installs that marker.
        self.require_fenced_transition_capability_before(deadline)
            .await?;
        if self.current_scope()? != probed_scope {
            return Err(consensus_unavailable());
        }
        let logical_time = self.logical_read_time_before(None, deadline).await?;
        let observation = self
            .inner
            .backend
            .consensus_observe_fenced_transition_at(key, logical_time)
            .await?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        if self.current_scope()? != probed_scope {
            return Err(consensus_unavailable());
        }
        Ok(observation)
    }

    /// Atomically acquire or renew one exact-key fence and apply one bounded
    /// same-record mutation at one consensus position.
    pub async fn fenced_transition(
        &self,
        request: FencedTransitionRequest,
    ) -> Result<FencedTransitionOutcome, StoreError> {
        request.validate()?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        // Probe before any ForwardMutation transmission so an older current
        // leader yields a definite compatibility error, never an ambiguous
        // transition outcome. The leader repeats this proof immediately before
        // proposal to cover a different forwarding route or intervening restart.
        self.require_fenced_transition_capability_before(deadline)
            .await?;
        // Do not run the legacy finite-record expiry preflight here. That
        // preflight may advance consensus logical time in its own entry and
        // would turn this primitive back into a two-proposal composition. The
        // transition has no pre-proposal provider side effect to protect.
        // Immutable structure and protected payloads are admitted here, while
        // time-dependent new-execution checks run only after apply has proved
        // that no exact durable receipt exists.
        let request_id = SessionConsensusRequestId::from_bytes(*request.request_id().as_bytes());
        let response = self
            .submit_request_before(
                request_id,
                SessionMutationIntent::FencedTransition(Box::new(request)),
                None,
                deadline,
            )
            .await?;
        match response.result? {
            SessionMutationOutcome::FencedTransition(outcome) => Ok(outcome),
            _ => Err(StoreError::FencedTransitionOutcomeUnknown),
        }
    }

    /// Resolve the exact retained result for a possibly ambiguous transition.
    ///
    /// Status first advances committed logical time, then reads the durable
    /// body binding without proposing another user mutation. `NotFound` is an
    /// observation at that barrier, not proof that an earlier delayed proposal
    /// cannot commit later; only the identical ID/body may be submitted again.
    pub async fn fenced_transition_status(
        &self,
        request: &FencedTransitionRequest,
    ) -> Result<FencedTransitionStatus, StoreError> {
        request.validate()?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        // Status is read-only and uses the same exact live-voter proof as
        // observation before the first activating transition.  It never
        // treats a quorum as an activation certificate.
        self.require_fenced_transition_capability_before(deadline)
            .await?;
        self.logical_read_time_before(None, deadline).await?;
        let (authority_identity, _) = self.current_scope()?;
        let status = self
            .inner
            .backend
            .consensus_fenced_transition_status(
                self.inner.storage_identity,
                authority_identity,
                request,
            )
            .await?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        if !self
            .current_scope()
            .is_ok_and(|(current_identity, _)| current_identity == authority_identity)
        {
            return Err(consensus_unavailable());
        }
        Ok(status)
    }

    /// Atomically apply one V2 transition under the fixed V2 receipt-history
    /// profile.  Its complete V2 request ID remains inside the command; only
    /// the outer generic envelope uses a domain-separated derived ID.
    pub async fn fenced_transition_v2(
        &self,
        request: FencedTransitionV2Request,
    ) -> Result<FencedTransitionOutcome, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.fenced_transition_v2_before(request, None, deadline)
            .await
    }

    /// Apply one V2 transition while preserving an optional consumer authority
    /// scope through the leader's final proposal gate.
    async fn fenced_transition_v2_before(
        &self,
        request: FencedTransitionV2Request,
        required_consumer_scope: Option<SessionConsensusIdentity>,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionOutcome, StoreError> {
        let response = self
            .fenced_transition_v2_response_before(request, required_consumer_scope, deadline, false)
            .await?;
        match response.result? {
            SessionMutationOutcome::FencedTransition(outcome) => Ok(outcome),
            _ => Err(StoreError::FencedTransitionOutcomeUnknown),
        }
    }

    /// Execute one V2 singleton while preserving whether a validated response
    /// came from a committed command rather than a pre-proposal rejection.
    async fn consumer_fenced_transition_v2_before(
        &self,
        scope: SessionConsumerScope,
        request: FencedTransitionV2Request,
        deadline: tokio::time::Instant,
    ) -> Result<(Result<FencedTransitionOutcome, StoreError>, bool), StoreError> {
        let response = self
            .fenced_transition_v2_response_before(
                request,
                Some(scope.consensus_identity()),
                deadline,
                true,
            )
            .await?;
        let committed = response.raft_log_index != 0;
        let result = match response.result {
            Ok(SessionMutationOutcome::FencedTransition(outcome)) => Ok(outcome),
            Ok(_) => Err(StoreError::FencedTransitionOutcomeUnknown),
            Err(error) => Err(error),
        };
        Ok((result, committed))
    }

    async fn fenced_transition_v2_response_before(
        &self,
        request: FencedTransitionV2Request,
        required_consumer_scope: Option<SessionConsensusIdentity>,
        deadline: tokio::time::Instant,
        preserve_rejected_response: bool,
    ) -> Result<SessionConsensusResponse, StoreError> {
        request.validate()?;
        if !self.fixed_raw_v2_consumer_warm_route(required_consumer_scope.as_ref()) {
            let admission = self
                .require_fenced_transition_v2_capability_before(deadline)
                .await?;
            if matches!(
                admission,
                FencedTransitionV2CapabilityAdmission::FreshUnanimous
            ) {
                // A fresh proof can mean either the first V2 command (where the
                // backend exposes the fixed initial epoch) or a re-certification
                // after topology cutover (where durable history exposes its
                // existing active epoch). Check that deterministic lifecycle
                // state before transmitting any activating proposal.
                let (authority_identity, _) = self.current_scope()?;
                let history = self
                    .inner
                    .backend
                    .consensus_fenced_transition_v2_history_state(
                        self.inner.storage_identity,
                        authority_identity,
                    )
                    .await?;
                classify_fresh_v2_history_epoch(&history, request.request_id().epoch())?;
                if !self
                    .current_scope()
                    .is_ok_and(|(current_identity, _)| current_identity == authority_identity)
                {
                    return Err(consensus_unavailable());
                }
            }
        }
        let request_id = fenced_transition_v2_outer_request_id(&request);
        self.submit_request_before_with_rejected_response(
            request_id,
            SessionMutationIntent::FencedTransitionV2(Box::new(request)),
            required_consumer_scope,
            deadline,
            preserve_rejected_response,
        )
        .await
    }

    /// Run the V2 singleton's actual submit path without collapsing a proven
    /// pre-proposal failure into the legacy `StoreError` surface.
    async fn fenced_transition_v2_submission_effect_before(
        &self,
        request: FencedTransitionV2Request,
        required_consumer_scope: Option<SessionConsensusIdentity>,
        deadline: tokio::time::Instant,
    ) -> ConsensusSubmissionEffect {
        if let Err(error) = request.validate() {
            return ConsensusSubmissionEffect::NotTransmitted(error);
        }
        if !self.fixed_raw_v2_consumer_warm_route(required_consumer_scope.as_ref()) {
            let admission = match self
                .require_fenced_transition_v2_capability_before(deadline)
                .await
            {
                Ok(admission) => admission,
                Err(error) => return ConsensusSubmissionEffect::NotTransmitted(error),
            };
            if matches!(
                admission,
                FencedTransitionV2CapabilityAdmission::FreshUnanimous
            ) {
                // Every operation in this block is a local/read-only
                // admission check before a forwarding write or proposal.
                let (authority_identity, _) = match self.current_scope() {
                    Ok(scope) => scope,
                    Err(error) => return ConsensusSubmissionEffect::NotTransmitted(error),
                };
                let history = match self
                    .inner
                    .backend
                    .consensus_fenced_transition_v2_history_state(
                        self.inner.storage_identity,
                        authority_identity,
                    )
                    .await
                {
                    Ok(history) => history,
                    Err(error) => return ConsensusSubmissionEffect::NotTransmitted(error),
                };
                if let Err(error) =
                    classify_fresh_v2_history_epoch(&history, request.request_id().epoch())
                {
                    return ConsensusSubmissionEffect::NotTransmitted(error);
                }
                if !self
                    .current_scope()
                    .is_ok_and(|(current_identity, _)| current_identity == authority_identity)
                {
                    return ConsensusSubmissionEffect::NotTransmitted(consensus_unavailable());
                }
            }
        }
        let request_id = fenced_transition_v2_outer_request_id(&request);
        self.submit_request_effect_before(
            request_id,
            SessionMutationIntent::FencedTransitionV2(Box::new(request)),
            required_consumer_scope,
            deadline,
        )
        .await
    }

    /// Coalesce an ordered, bounded V2 transition batch into one command.
    ///
    /// The caller retains every complete V2 request ID.  A successful reply
    /// is exactly ordered with `requests`, including deterministic per-item
    /// failures. Each item remains an independent logical transition and
    /// status identity: shared Raft/SQLite work does not create a caller-
    /// visible all-or-nothing multi-key conditional contract. Once either the
    /// activation singleton or the batch proposal
    /// may have crossed Raft's acceptance boundary, an unavailable reply is
    /// intentionally whole-batch ambiguity: callers resolve each retained ID
    /// through [`Self::fenced_transition_v2_status`].
    pub async fn fenced_transition_v2_batch(
        &self,
        requests: Vec<FencedTransitionV2Request>,
    ) -> Result<Vec<Result<FencedTransitionOutcome, StoreError>>, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.fenced_transition_v2_batch_before(requests, None, deadline)
            .await
    }

    /// Apply a V2 transition batch while preserving an optional consumer
    /// authority scope through every possible singleton or batch proposal.
    async fn fenced_transition_v2_batch_before(
        &self,
        requests: Vec<FencedTransitionV2Request>,
        required_consumer_scope: Option<SessionConsensusIdentity>,
        deadline: tokio::time::Instant,
    ) -> Result<Vec<Result<FencedTransitionOutcome, StoreError>>, StoreError> {
        self.fenced_transition_v2_batch_execution_before(
            requests,
            required_consumer_scope,
            deadline,
            false,
        )
        .await
        .map(|(outcomes, _)| outcomes)
    }

    /// Execute one consumer-scoped V2 batch and retain whether any command
    /// may have committed before a final scope re-admission.
    async fn consumer_fenced_transition_v2_batch_before(
        &self,
        scope: SessionConsumerScope,
        requests: Vec<FencedTransitionV2Request>,
        deadline: tokio::time::Instant,
    ) -> Result<(Vec<Result<FencedTransitionOutcome, StoreError>>, bool), StoreError> {
        self.fenced_transition_v2_batch_execution_before(
            requests,
            Some(scope.consensus_identity()),
            deadline,
            true,
        )
        .await
    }

    async fn fenced_transition_v2_batch_execution_before(
        &self,
        mut requests: Vec<FencedTransitionV2Request>,
        required_consumer_scope: Option<SessionConsensusIdentity>,
        deadline: tokio::time::Instant,
        preserve_rejected_response: bool,
    ) -> Result<(Vec<Result<FencedTransitionOutcome, StoreError>>, bool), StoreError> {
        validate_fenced_transition_v2_batch(&requests)?;

        // Local V2 support is only a route hint. The exact consumer scope is
        // carried in the forwarded request and the selected leader consumes
        // the sole durable authority/activation snapshot immediately before
        // it proposes. In particular, the ingress must not turn this warm
        // route into a second SQLite activation read.
        if self.fixed_raw_v2_consumer_warm_route(required_consumer_scope.as_ref()) {
            let request_id = fenced_transition_v2_batch_request_id(&requests)?;
            let response = self
                .submit_request_before_with_rejected_response(
                    request_id,
                    SessionMutationIntent::FencedTransitionV2Batch(requests),
                    required_consumer_scope,
                    deadline,
                    preserve_rejected_response,
                )
                .await?;
            let committed = response.raft_log_index != 0;
            return match response.result {
                Ok(SessionMutationOutcome::FencedTransitionV2Batch(outcomes)) => {
                    Ok((outcomes, committed))
                }
                // A nonzero log index means the leader returned a committed
                // reply envelope.  Its outer error is therefore not a safe
                // deterministic pre-proposal rejection for a caller-owned
                // V2 batch; retain ambiguity for status recovery.
                Err(_error) if committed => Err(StoreError::FencedTransitionOutcomeUnknown),
                Err(error) => Err(error),
                _ => Err(StoreError::FencedTransitionOutcomeUnknown),
            };
        }

        let admission = self
            .require_fenced_transition_v2_capability_before(deadline)
            .await?;

        // Batch coalescing never activates or replays an arbitrary lifecycle
        // epoch.  Every submitted batch uses the one currently active epoch;
        // the singleton activation below has the same exact precondition.
        let (authority_identity, _) = self.current_scope()?;
        let history = self
            .inner
            .backend
            .consensus_fenced_transition_v2_history_state(
                self.inner.storage_identity,
                authority_identity,
            )
            .await?;
        require_fenced_transition_v2_batch_active_epoch(
            &history,
            requests[0].request_id().epoch(),
        )?;
        if !self
            .current_scope()
            .is_ok_and(|(current_identity, _)| current_identity == authority_identity)
        {
            return Err(consensus_unavailable());
        }

        let mut activation_outcome = None;
        if matches!(
            admission,
            FencedTransitionV2CapabilityAdmission::FreshUnanimous
        ) {
            // There is deliberately no implicit batch activation: the first
            // V2 caller effect keeps the pre-existing singleton activation
            // receipt/certificate semantics.  Only after that one committed
            // effect may the remaining items share their single batch entry.
            let first = requests.remove(0);
            let response = self
                .submit_request_before_with_rejected_response(
                    fenced_transition_v2_outer_request_id(&first),
                    SessionMutationIntent::FencedTransitionV2(Box::new(first)),
                    required_consumer_scope,
                    deadline,
                    preserve_rejected_response,
                )
                .await?;
            let activation_committed = response.raft_log_index != 0;
            let outcome = match response.result {
                Ok(SessionMutationOutcome::FencedTransition(outcome)) => outcome,
                Err(error) if activation_committed && requests.is_empty() => {
                    return Ok((vec![Err(error)], true));
                }
                Err(_) if activation_committed => {
                    return Err(StoreError::FencedTransitionOutcomeUnknown);
                }
                Err(error) => return Err(error),
                Ok(_) => return Err(StoreError::FencedTransitionOutcomeUnknown),
            };
            activation_outcome = Some(Ok(outcome));
            if requests.is_empty() {
                return Ok((
                    activation_outcome.into_iter().collect(),
                    activation_committed,
                ));
            }
        }

        let request_id = match fenced_transition_v2_batch_request_id(&requests) {
            Ok(request_id) => request_id,
            Err(_) if activation_outcome.is_some() => {
                return Err(StoreError::FencedTransitionOutcomeUnknown);
            }
            Err(error) => return Err(error),
        };
        let response = match self
            .submit_request_before_with_rejected_response(
                request_id,
                SessionMutationIntent::FencedTransitionV2Batch(requests),
                required_consumer_scope,
                deadline,
                preserve_rejected_response,
            )
            .await
        {
            Ok(response) => response,
            Err(_) if activation_outcome.is_some() => {
                return Err(StoreError::FencedTransitionOutcomeUnknown);
            }
            Err(error) => return Err(error),
        };
        let committed = response.raft_log_index != 0;
        let activation_effect_may_have_committed = activation_outcome.is_some();
        let mut outcomes = match response.result {
            Ok(SessionMutationOutcome::FencedTransitionV2Batch(outcomes)) => outcomes,
            Ok(_) | Err(_) if activation_outcome.is_some() => {
                return Err(StoreError::FencedTransitionOutcomeUnknown);
            }
            Ok(_) => return Err(StoreError::FencedTransitionOutcomeUnknown),
            Err(error) => return Err(error),
        };
        if let Some(outcome) = activation_outcome {
            outcomes.insert(0, outcome);
        }
        Ok((outcomes, committed || activation_effect_may_have_committed))
    }

    /// Execute a V2 batch with the submit boundary preserved for protected
    /// callers.  The legacy batch method above intentionally projects this
    /// detail into `StoreError`; this path is only for the additive effect API.
    async fn fenced_transition_v2_batch_submission_effect_before(
        &self,
        mut requests: Vec<FencedTransitionV2Request>,
        required_consumer_scope: Option<SessionConsensusIdentity>,
        deadline: tokio::time::Instant,
    ) -> FencedTransitionV2Effect<
        Result<Vec<Result<FencedTransitionOutcome, StoreError>>, StoreError>,
    > {
        if let Err(error) = validate_fenced_transition_v2_batch(&requests) {
            return FencedTransitionV2Effect::Resolved(Err(error));
        }
        let request_ids = requests
            .iter()
            .map(FencedTransitionV2Request::request_id)
            .collect::<Vec<_>>();
        let unknown = || FencedTransitionV2Effect::OutcomeUnknown {
            request_ids: request_ids.clone(),
        };
        // A rejected submit response is authenticated before proposal.  Its
        // error therefore proves this invocation did not transmit.  A
        // malformed success-shaped rejected response has no such proof.
        let from_rejected_batch_response =
            |response: SessionConsensusResponse| match response.result {
                Err(error) => FencedTransitionV2Effect::NotTransmitted(error),
                Ok(_) => unknown(),
            };

        if self.fixed_raw_v2_consumer_warm_route(required_consumer_scope.as_ref()) {
            let request_id = match fenced_transition_v2_batch_request_id(&requests) {
                Ok(request_id) => request_id,
                Err(error) => return FencedTransitionV2Effect::Resolved(Err(error)),
            };
            let expected_requests = requests.clone();
            return match self
                .submit_request_effect_before(
                    request_id,
                    SessionMutationIntent::FencedTransitionV2Batch(requests),
                    required_consumer_scope,
                    deadline,
                )
                .await
            {
                ConsensusSubmissionEffect::NotTransmitted(error) => {
                    FencedTransitionV2Effect::NotTransmitted(error)
                }
                ConsensusSubmissionEffect::OutcomeUnknown => unknown(),
                ConsensusSubmissionEffect::Committed(response) => {
                    committed_fenced_transition_v2_batch_effect(
                        &request_ids,
                        &expected_requests,
                        None,
                        response,
                    )
                }
                ConsensusSubmissionEffect::Rejected(response) => {
                    from_rejected_batch_response(response)
                }
            };
        }

        let admission = match self
            .require_fenced_transition_v2_capability_before(deadline)
            .await
        {
            Ok(admission) => admission,
            Err(error) => return FencedTransitionV2Effect::NotTransmitted(error),
        };
        let (authority_identity, _) = match self.current_scope() {
            Ok(scope) => scope,
            Err(error) => return FencedTransitionV2Effect::NotTransmitted(error),
        };
        let history = match self
            .inner
            .backend
            .consensus_fenced_transition_v2_history_state(
                self.inner.storage_identity,
                authority_identity,
            )
            .await
        {
            Ok(history) => history,
            Err(error) => return FencedTransitionV2Effect::NotTransmitted(error),
        };
        if let Err(error) = require_fenced_transition_v2_batch_active_epoch(
            &history,
            requests[0].request_id().epoch(),
        ) {
            return FencedTransitionV2Effect::NotTransmitted(error);
        }
        if !self
            .current_scope()
            .is_ok_and(|(current_identity, _)| current_identity == authority_identity)
        {
            return FencedTransitionV2Effect::NotTransmitted(consensus_unavailable());
        }

        let mut activation_outcome = None;
        if matches!(
            admission,
            FencedTransitionV2CapabilityAdmission::FreshUnanimous
        ) {
            let first = requests.remove(0);
            let activation_request = first.clone();
            match self
                .submit_request_effect_before(
                    fenced_transition_v2_outer_request_id(&first),
                    SessionMutationIntent::FencedTransitionV2(Box::new(first)),
                    required_consumer_scope,
                    deadline,
                )
                .await
            {
                ConsensusSubmissionEffect::NotTransmitted(error) => {
                    return FencedTransitionV2Effect::NotTransmitted(error);
                }
                ConsensusSubmissionEffect::OutcomeUnknown => return unknown(),
                ConsensusSubmissionEffect::Committed(response) => {
                    match committed_fenced_transition_v2_activation_result(
                        &activation_request,
                        !requests.is_empty(),
                        response,
                    ) {
                        Some(Ok(outcome)) => {
                            activation_outcome = Some(Ok(outcome));
                        }
                        Some(Err(error)) => {
                            return FencedTransitionV2Effect::Resolved(Ok(vec![Err(error)]));
                        }
                        None => return unknown(),
                    }
                }
                ConsensusSubmissionEffect::Rejected(response) => match response.result {
                    Err(error) => return FencedTransitionV2Effect::NotTransmitted(error),
                    Ok(_) => return unknown(),
                },
            }
            if requests.is_empty() {
                return FencedTransitionV2Effect::Resolved(Ok(activation_outcome
                    .into_iter()
                    .collect()));
            }
        }

        let request_id = match fenced_transition_v2_batch_request_id(&requests) {
            Ok(request_id) => request_id,
            Err(_error) if activation_outcome.is_some() => return unknown(),
            Err(error) => return FencedTransitionV2Effect::Resolved(Err(error)),
        };
        let expected_requests = requests.clone();
        match self
            .submit_request_effect_before(
                request_id,
                SessionMutationIntent::FencedTransitionV2Batch(requests),
                required_consumer_scope,
                deadline,
            )
            .await
        {
            ConsensusSubmissionEffect::NotTransmitted(_error) if activation_outcome.is_some() => {
                unknown()
            }
            ConsensusSubmissionEffect::NotTransmitted(error) => {
                FencedTransitionV2Effect::NotTransmitted(error)
            }
            ConsensusSubmissionEffect::OutcomeUnknown => unknown(),
            ConsensusSubmissionEffect::Committed(response) => {
                committed_fenced_transition_v2_batch_effect(
                    &request_ids,
                    &expected_requests,
                    activation_outcome,
                    response,
                )
            }
            ConsensusSubmissionEffect::Rejected(response) => match response.result {
                Err(error) if activation_outcome.is_none() => {
                    FencedTransitionV2Effect::NotTransmitted(error)
                }
                Err(_) | Ok(_) => unknown(),
            },
        }
    }

    /// Resolve V2's exact receipt state after a caller-owned consensus
    /// barrier.  This never falls back to V1 receipt state.
    pub async fn fenced_transition_v2_status(
        &self,
        request: &FencedTransitionV2Request,
    ) -> Result<FencedTransitionV2Status, StoreError> {
        if let Err(error) = request.validate() {
            // A V2 request ID self-authenticates its complete canonical body.
            // Status is deliberately the conflict-resolution path for an
            // altered body under a retained full ID, even before a backend
            // lookup. Other malformed structure remains an outer rejection.
            return if matches!(error, StoreError::FencedTransitionRequestConflict) {
                Ok(FencedTransitionV2Status::RequestConflict)
            } else {
                Err(error)
            };
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.require_fenced_transition_v2_capability_before(deadline)
            .await?;
        self.logical_read_time_before(None, deadline).await?;
        let (authority_identity, _) = self.current_scope()?;
        let status = self
            .inner
            .backend
            .consensus_fenced_transition_v2_status(
                self.inner.storage_identity,
                authority_identity,
                request,
            )
            .await?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        if !self
            .current_scope()
            .is_ok_and(|(current_identity, _)| current_identity == authority_identity)
        {
            return Err(consensus_unavailable());
        }
        Ok(status)
    }

    /// Read V2 history state at a linearized exact voter scope.
    pub async fn fenced_transition_v2_history_state(
        &self,
    ) -> Result<FencedTransitionV2HistoryState, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.require_fenced_transition_v2_capability_before(deadline)
            .await?;
        self.logical_read_time_before(None, deadline).await?;
        let (authority_identity, _) = self.current_scope()?;
        let state = self
            .inner
            .backend
            .consensus_fenced_transition_v2_history_state(
                self.inner.storage_identity,
                authority_identity,
            )
            .await?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        if !self
            .current_scope()
            .is_ok_and(|(current_identity, _)| current_identity == authority_identity)
        {
            return Err(consensus_unavailable());
        }
        Ok(state)
    }

    /// Run one deterministic V2 history-maintenance step as the local
    /// operator authority.
    ///
    /// Possession of this state-process store is the operator authority. This
    /// method is deliberately absent from the stateless consumer and
    /// forwarding surfaces; raw maintenance intents remain rejected unless
    /// this local boundary supplies the internal authority marker.
    pub async fn maintain_fenced_transition_v2_history(
        &self,
        expected_state: FencedTransitionV2HistoryState,
    ) -> Result<FencedTransitionV2HistoryState, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.require_durable_fixed_quorum_admission_before(deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
        if self.inner.raft.metrics().borrow().current_leader != Some(self.inner.local_node_id) {
            return Err(consensus_unavailable());
        }
        let reply = self
            .apply_on_local_leader_inner(
                ForwardMutationRequest {
                    request_id: SessionConsensusRequestId::new(),
                    intent: SessionMutationIntent::MaintainFencedTransitionV2History {
                        expected_generation: expected_state.generation(),
                        expected_active_epoch: expected_state.active_epoch(),
                        expected_retired_through: expected_state
                            .retired_through()
                            .map_or(0, |epoch| epoch.get()),
                        expected_bound_entries: expected_state.bound_entries() as u64,
                    },
                    required_consumer_scope: ForwardConsumerScope::Internal,
                },
                self.inner.local_node_id,
                deadline,
                true,
                None,
            )
            .await;
        match reply {
            ForwardMutationReply::Applied(response)
                if matches!(response.result, Ok(SessionMutationOutcome::Unit)) =>
            {
                self.inner
                    .backend
                    .consensus_fenced_transition_v2_history_state(
                        self.inner.storage_identity,
                        self.current_scope().map_err(|_| consensus_unavailable())?.0,
                    )
                    .await
            }
            ForwardMutationReply::Applied(response) => match response.result {
                Err(error) => Err(error),
                Ok(_) => Err(consensus_unavailable()),
            },
            ForwardMutationReply::NotLeader { .. }
            | ForwardMutationReply::OutcomeUnknown
            | ForwardMutationReply::Unavailable
            | ForwardMutationReply::RecordExpiryPreflight(_) => Err(consensus_unavailable()),
        }
    }

    async fn consumer_scope_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsumerScope, StoreError> {
        self.require_application_traffic_authority_before(deadline)
            .await?;
        self.current_scope()
            .map(|(identity, _)| SessionConsumerScope::new(identity))
    }

    /// Produce the only member-exclusion manifest accepted by the stateless
    /// consumer listener. The set is derived from the store-owned, currently
    /// admitted topology bindings while its operation gate is held.
    pub async fn consumer_authorization_manifest(
        &self,
    ) -> Result<SessionConsumerAuthorizationManifest, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        let scope = self.consumer_scope_before(deadline).await?;
        let admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
        let descriptors = self
            .inner
            .topology_coordinator
            .current_member_descriptors(admission.required_scope)
            .ok_or_else(consensus_unavailable)?;
        let members = descriptors
            .into_values()
            .map(|descriptor| {
                SessionConsumerIdentity::new(descriptor.tls_identity().as_str().to_owned())
                    .map_err(|_| consensus_unavailable())
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if members.is_empty() {
            return Err(consensus_unavailable());
        }
        Ok(SessionConsumerAuthorizationManifest::new(scope, members))
    }

    async fn consumer_scope_is_current(
        &self,
        scope: SessionConsumerScope,
        deadline: tokio::time::Instant,
    ) -> Result<(), SessionConsumerRejection> {
        let (current_scope, _) = self
            .current_scope()
            .map_err(|_| SessionConsumerRejection::Unavailable)?;
        if current_scope != scope.consensus_identity() {
            return Err(SessionConsumerRejection::ScopeMismatch);
        }
        self.require_durable_fixed_quorum_admission_before(deadline)
            .await
            .map_err(|_| SessionConsumerRejection::Unavailable)
    }

    /// The raw fixed-durable V2 warm route deliberately avoids only the
    /// preliminary SQLite authority snapshot.  It still takes the topology
    /// operation gate and proves the currently admitted in-memory scope; the
    /// leader proposal path and the final consumer admission retain durable
    /// authority checks.
    fn consumer_scope_is_current_in_memory(
        &self,
        scope: SessionConsumerScope,
    ) -> Result<(), SessionConsumerRejection> {
        let (current_scope, _) = self
            .current_scope()
            .map_err(|_| SessionConsumerRejection::Unavailable)?;
        if current_scope != scope.consensus_identity() {
            return Err(SessionConsumerRejection::ScopeMismatch);
        }
        self.require_exact_membership_admission()
            .map_err(|_| SessionConsumerRejection::Unavailable)
    }

    async fn admit_consumer_scope_in_memory(
        &self,
        scope: SessionConsumerScope,
        deadline: tokio::time::Instant,
    ) -> Result<ConsumerScopeAdmission, SessionConsumerRejection> {
        let operation_gate = self.inner.topology_coordinator.operation_gate();
        let operation_guard = tokio::time::timeout_at(deadline, operation_gate.read_owned())
            .await
            .map_err(|_| SessionConsumerRejection::Unavailable)?;
        self.consumer_scope_is_current_in_memory(scope)?;
        Ok(ConsumerScopeAdmission {
            required_scope: scope.consensus_identity(),
            _operation_guard: operation_guard,
        })
    }

    async fn admit_consumer_scope(
        &self,
        scope: SessionConsumerScope,
        deadline: tokio::time::Instant,
    ) -> Result<ConsumerScopeAdmission, SessionConsumerRejection> {
        let operation_gate = self.inner.topology_coordinator.operation_gate();
        let operation_guard = tokio::time::timeout_at(deadline, operation_gate.read_owned())
            .await
            .map_err(|_| SessionConsumerRejection::Unavailable)?;
        self.consumer_scope_is_current(scope, deadline).await?;
        Ok(ConsumerScopeAdmission {
            required_scope: scope.consensus_identity(),
            _operation_guard: operation_guard,
        })
    }

    /// Initialize pristine members with the exact admitted voting set.
    ///
    /// Concurrent calls are expected, but only the canonical lowest pristine
    /// member invokes Openraft initialization. Other pristine members wait for
    /// replicated membership, avoiding fixed-timeout split-vote lockstep.
    /// Clean first formation fails closed if the canonical member is absent.
    pub async fn initialize_cluster(&self) -> Result<(), ConsensusSessionStoreOpenError> {
        self.inner.admitted.store(false, Ordering::Release);
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or(ConsensusSessionStoreOpenError::ClusterFormationRejected)?;
        let initialized = tokio::time::timeout_at(deadline, self.inner.raft.is_initialized())
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::ClusterFormationRejected)?
            .map_err(|_| ConsensusSessionStoreOpenError::EngineUnavailable)?;
        let canonical_bootstrap = self.inner.bootstrap_members.first().copied();
        if !initialized && canonical_bootstrap == Some(self.inner.local_node_id) {
            let initialize = tokio::time::timeout_at(
                deadline,
                self.inner
                    .raft
                    .initialize(self.inner.bootstrap_members.clone()),
            )
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::ClusterFormationRejected)?;
            match initialize {
                Ok(()) | Err(RaftError::APIError(InitializeError::NotAllowed(_))) => {}
                Err(RaftError::APIError(InitializeError::NotInMembers(_))) => {
                    return Err(ConsensusSessionStoreOpenError::ClusterFormationRejected);
                }
                Err(RaftError::Fatal(_)) => {
                    return Err(ConsensusSessionStoreOpenError::EngineUnavailable);
                }
            }
        }
        self.wait_for_exact_membership(deadline).await?;
        if self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum
            && !self.durable_fixed_quorum_scope_is_exact().await?
        {
            return Err(ConsensusSessionStoreOpenError::ClusterFormationRejected);
        }
        self.inner.admitted.store(true, Ordering::Release);
        if !self.exact_membership_is_admitted() {
            return Err(ConsensusSessionStoreOpenError::ClusterFormationRejected);
        }
        Ok(())
    }

    /// Redaction-safe immutable topology shape.
    pub fn topology(&self) -> &QuorumTopologySummary {
        &self.inner.topology
    }

    /// Snapshot redaction-safe status directly from the one Openraft engine.
    pub fn status(&self) -> SessionConsensusStatus {
        let current_members = self
            .current_scope()
            .map(|(_, members)| members)
            .unwrap_or_default();
        let metrics = self.inner.raft.metrics();
        let (term, leader_id, last_log_index, applied_index, engine_running) = {
            let current = metrics.borrow();
            (
                current.current_term,
                current.current_leader,
                current.last_log_index,
                current.last_applied.as_ref().map(|log_id| log_id.index),
                current.running_state.is_ok(),
            )
        };
        // `membership_config` is Openraft's effective proposal state, not the
        // applied membership authority. It may remain joint or otherwise lead
        // the state machine after a completed change, so it must neither grant
        // nor veto application authority. The latch is set only after the
        // exact durable applied scope is proven; engine failure and local
        // removal remain live vetoes.
        let admitted = self.inner.admitted.load(Ordering::Acquire)
            && engine_running
            && current_members.contains(&self.inner.local_node_id)
            && (self.inner.topology.mode() != QuorumTopologyMode::FixedDurableQuorum
                || self
                    .inner
                    .topology
                    .fixed_durable_placement_policy()
                    .is_some_and(|placement_policy| {
                        self.inner.backend.fixed_quorum_authority_is_exact_now(
                            self.inner.storage_identity,
                            &self.inner.bootstrap_members,
                            &self.inner.bootstrap_bindings,
                            placement_policy,
                        )
                    }));
        SessionConsensusStatus {
            node_id: self.inner.local_node_id,
            term,
            leader_id,
            last_log_index,
            applied_index,
            admitted,
        }
    }

    pub(crate) fn recovery_identity(&self) -> SessionConsensusIdentity {
        self.inner.storage_identity
    }

    pub(crate) fn recovery_members(&self) -> &BTreeSet<SessionConsensusNodeId> {
        &self.inner.bootstrap_members
    }

    /// Static, fail-closed engine profile admitted from descriptor shape.
    ///
    /// Time-bound HA evidence cannot safely produce a static quorum claim, so
    /// HA topologies return [`SessionStorePlatformProfile::Unknown`]. Production
    /// callers must use [`Self::production_platform_profile_at`] and
    /// [`Self::probe_production_durable_readiness`].
    pub fn platform_profile(&self) -> SessionStorePlatformProfile {
        self.inner.topology.mode().platform_profile()
    }

    /// Redaction-safe topology evidence provenance and freshness at `now`.
    ///
    /// The summary contains only provenance class, configuration epoch,
    /// freshness durations, and result. It never exposes member identities,
    /// endpoints, TLS identities, placement, backing identities, collectors,
    /// proof bytes, or canonical digests. This wall-clock summary is diagnostic
    /// only; it does not apply the store's monotonic expiry or clock high-water
    /// and cannot authorize traffic.
    pub fn topology_attestation_summary_at(
        &self,
        now: TopologyAttestationTime,
    ) -> TopologyAttestationSummary {
        self.inner.topology.attestation_at(now)
    }

    /// Platform profile after requiring fresh production-eligible topology
    /// evidence at `now`.
    ///
    /// Descriptor-only HA returns [`SessionStorePlatformProfile::Unknown`]
    /// rather than presenting configuration strings as observed proof. Calls
    /// share a nondecreasing per-store time authority; a backward `now` fails
    /// closed and cannot revive evidence after a forward/expired evaluation.
    pub fn production_platform_profile_at(
        &self,
        now: TopologyAttestationTime,
    ) -> SessionStorePlatformProfile {
        match self.inner.topology.mode() {
            QuorumTopologyMode::LabSingleton => SessionStorePlatformProfile::SingleReplica,
            QuorumTopologyMode::AttestedHa
                if self
                    .initial_production_attestation_valid_for_at(now)
                    .is_some() =>
            {
                SessionStorePlatformProfile::Quorum
            }
            QuorumTopologyMode::ValidatedHa
            | QuorumTopologyMode::AttestedHa
            | QuorumTopologyMode::FixedDurableQuorum => SessionStorePlatformProfile::Unknown,
        }
    }

    /// Platform profile gated by a separately refreshed attestation for this
    /// exact immutable topology. Identity and production provenance are checked
    /// before the supplied nondecreasing time can advance the store high-water.
    pub fn production_platform_profile_with_attestation_at(
        &self,
        attestation: &VerifiedQuorumTopologyAttestation,
        now: TopologyAttestationTime,
    ) -> SessionStorePlatformProfile {
        if self.inner.topology.mode() != QuorumTopologyMode::AttestedHa {
            return SessionStorePlatformProfile::Unknown;
        }
        if self
            .refreshed_production_attestation_valid_for_at(attestation, now)
            .is_some()
        {
            SessionStorePlatformProfile::Quorum
        } else {
            SessionStorePlatformProfile::Unknown
        }
    }

    async fn wait_for_exact_membership(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), ConsensusSessionStoreOpenError> {
        let mut metrics = self.inner.raft.metrics();
        loop {
            let effective_membership_is_exact = {
                let current = metrics.borrow();
                if current.running_state.is_err() {
                    return Err(ConsensusSessionStoreOpenError::EngineUnavailable);
                }
                exact_uniform_voter_membership(
                    current.membership_config.as_ref(),
                    &self.inner.bootstrap_members,
                )
            };
            if effective_membership_is_exact && self.durable_uniform_scope_is_admitted().await? {
                return Ok(());
            }
            tokio::select! {
                changed = metrics.changed() => {
                    if changed.is_err() {
                        return Err(ConsensusSessionStoreOpenError::EngineUnavailable);
                    }
                }
                () = tokio::time::sleep(Duration::from_millis(25)) => {}
                () = tokio::time::sleep_until(deadline) => {
                    return Err(ConsensusSessionStoreOpenError::ClusterFormationRejected);
                }
            }
        }
    }

    async fn durable_uniform_scope_is_admitted(
        &self,
    ) -> Result<bool, ConsensusSessionStoreOpenError> {
        let (scope, applied_membership) = self
            .inner
            .backend
            .consensus_membership_scope_snapshot(self.inner.storage_identity)
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?;
        let (current_identity, current_members) = self
            .inner
            .peer_directory
            .current_scope()
            .map_err(|_| ConsensusSessionStoreOpenError::ClusterFormationRejected)?;
        Ok(scope.current_identity == current_identity
            && scope.current_members == current_members
            && scope.application_authority_epoch == current_identity.configuration_epoch()
            && scope.application_authority_members == current_members
            && scope.pending.is_none()
            && current_members.contains(&self.inner.local_node_id)
            && exact_uniform_voter_membership(&applied_membership, &current_members))
    }

    fn engine_is_running_in_local_scope(&self) -> bool {
        let Ok((_, current_members)) = self.current_scope() else {
            return false;
        };
        if !current_members.contains(&self.inner.local_node_id) {
            return false;
        }
        let metrics = self.inner.raft.metrics();
        let current = metrics.borrow();
        current.running_state.is_ok()
    }

    fn exact_membership_is_admitted(&self) -> bool {
        self.inner.admitted.load(Ordering::Acquire)
            && self.engine_is_running_in_local_scope()
            && (self.inner.topology.mode() != QuorumTopologyMode::FixedDurableQuorum
                || self.fixed_durable_quorum_scope_is_exact())
    }

    fn current_application_scope_matches(
        &self,
        sender: SessionConsensusNodeId,
        identity: SessionConsensusIdentity,
    ) -> bool {
        self.current_scope()
            .is_ok_and(|(current_identity, current_members)| {
                current_identity == identity
                    && current_members.contains(&self.inner.local_node_id)
                    && current_members.contains(&sender)
            })
    }

    fn current_scope(
        &self,
    ) -> Result<(SessionConsensusIdentity, BTreeSet<SessionConsensusNodeId>), StoreError> {
        self.inner
            .peer_directory
            .current_scope()
            .map_err(|_| consensus_unavailable())
    }

    fn current_member_count(&self) -> Option<usize> {
        self.current_scope().ok().map(|(_, members)| members.len())
    }

    fn is_current_member(&self, node_id: SessionConsensusNodeId) -> bool {
        self.current_scope()
            .is_ok_and(|(_, members)| members.contains(&node_id))
    }

    fn require_exact_membership_admission(&self) -> Result<(), StoreError> {
        if self.exact_membership_is_admitted() {
            Ok(())
        } else {
            Err(consensus_unavailable())
        }
    }

    async fn require_durable_fixed_quorum_admission_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        self.require_exact_membership_admission()?;
        if self.inner.topology.mode() != QuorumTopologyMode::FixedDurableQuorum {
            return Ok(());
        }
        match tokio::time::timeout_at(deadline, self.durable_fixed_quorum_scope_is_exact()).await {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) | Ok(Err(_)) | Err(_) => Err(consensus_unavailable()),
        }
    }

    async fn operator_recovery_pending_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<bool, StoreError> {
        match tokio::time::timeout_at(
            deadline,
            self.inner
                .backend
                .consensus_operator_recovery_pending(self.inner.storage_identity),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(consensus_unavailable()),
        }
    }

    /// Revalidate every durable application-traffic authority immediately
    /// before an ordinary result or proposal crosses its acceptance boundary.
    /// Operator Recovery uses a separate explicitly authorized path.
    async fn require_application_traffic_authority_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        if self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum {
            self.require_exact_membership_admission()?;
            let expected_placement_policy = self
                .inner
                .topology
                .fixed_durable_placement_policy()
                .ok_or_else(consensus_unavailable)?;
            return match tokio::time::timeout_at(
                deadline,
                self.inner
                    .backend
                    .fixed_quorum_application_traffic_authority_is_exact(
                        self.inner.storage_identity,
                        self.inner.bootstrap_members.clone(),
                        self.inner.bootstrap_bindings.clone(),
                        expected_placement_policy,
                    ),
            )
            .await
            {
                Ok(Ok(true)) => Ok(()),
                Ok(Ok(false)) | Ok(Err(_)) | Err(_) => Err(consensus_unavailable()),
            };
        }
        self.require_durable_fixed_quorum_admission_before(deadline)
            .await?;
        match self.operator_recovery_pending_before(deadline).await {
            Ok(false) => Ok(()),
            Ok(true) | Err(_) => Err(consensus_unavailable()),
        }
    }

    /// Fixed watches must re-establish quorum-backed read authority after a
    /// notification is dequeued and before it is exposed. Dynamic watches
    /// retain their original passive stream semantics.
    async fn fixed_watch_authority_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        if self.inner.topology.mode() != QuorumTopologyMode::FixedDurableQuorum {
            return Ok(());
        }
        self.require_application_traffic_authority_before(deadline)
            .await?;
        self.linearizable_barrier_before(deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
        self.require_application_traffic_authority_before(deadline)
            .await
    }

    async fn durable_fixed_quorum_engine_admission_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> bool {
        if self.inner.topology.mode() != QuorumTopologyMode::FixedDurableQuorum
            || !self.inner.admitted.load(Ordering::Acquire)
        {
            return true;
        }
        matches!(
            tokio::time::timeout_at(deadline, self.durable_fixed_quorum_scope_is_exact()).await,
            Ok(Ok(true))
        )
    }

    /// Fresh readiness proof using the same Openraft quorum/read-index path as
    /// authoritative operations.
    ///
    /// This is an engine/lab/conformance probe and does not evaluate platform
    /// topology evidence. Its `Ready` result MUST NOT authorize production
    /// traffic; use [`Self::probe_production_durable_readiness`] for that gate.
    ///
    /// The recovery-latch check and linearizable barrier share one complete
    /// operation deadline. A delayed recovery check therefore cannot silently
    /// grant the barrier a second operation budget.
    pub async fn probe_durable_readiness(&self) -> DurableReadinessReport {
        let start = tokio::time::Instant::now();
        let deadline = self.operation_deadline_from(start);
        self.probe_durable_readiness_before(deadline).await
    }

    /// Probe the fixed durable-quorum authority and physical-placement result
    /// as separate typed observations.
    ///
    /// The traffic result requires exact persisted fixed 3/5 membership,
    /// recovery clearance, and a fresh Openraft linearizable-majority barrier.
    /// Physical-placement expiry can only
    /// downgrade [`PlacementResilienceReport`]; it never changes the traffic
    /// authority branch or Openraft mutation sequencing.
    pub async fn probe_fixed_durable_quorum_readiness(&self) -> FixedQuorumReadinessReport {
        let start = tokio::time::Instant::now();
        let deadline = self.operation_deadline_from(start);
        let placement_policy = self
            .inner
            .topology
            .fixed_durable_placement_policy()
            .unwrap_or_default();
        let durable_readiness = self.probe_fixed_durable_readiness_before(deadline).await;
        let placement_resilience = TopologyAttestationTime::now()
            .ok()
            .and_then(|now| self.fixed_quorum_placement_resilience_at(placement_policy, now));
        self.fixed_durable_quorum_readiness_report(
            placement_resilience.unwrap_or_else(|| placement_policy.evaluate_unverified()),
            durable_readiness,
        )
    }

    /// Deterministic-time form of [`Self::probe_fixed_durable_quorum_readiness`].
    ///
    /// `now` evaluates only the separate physical-placement claim. It is never
    /// used to extend, revoke, or otherwise influence fixed quorum authority.
    pub async fn probe_fixed_durable_quorum_readiness_at(
        &self,
        now: TopologyAttestationTime,
    ) -> FixedQuorumReadinessReport {
        let start = tokio::time::Instant::now();
        let deadline = self.operation_deadline_from(start);
        let placement_policy = self
            .inner
            .topology
            .fixed_durable_placement_policy()
            .unwrap_or_default();
        let durable_readiness = self.probe_fixed_durable_readiness_before(deadline).await;
        let placement_resilience = self
            .fixed_quorum_placement_resilience_at(placement_policy, now)
            .unwrap_or_else(|| placement_policy.evaluate_unverified());
        self.fixed_durable_quorum_readiness_report(placement_resilience, durable_readiness)
    }

    /// Probe fixed durable quorum authority using replacement authenticated
    /// physical-placement evidence and the current platform clock.
    ///
    /// The replacement evidence is bound to this exact immutable
    /// configuration. Its expiry can change only the placement disposition;
    /// the traffic authority remains a fresh durable Openraft observation.
    pub async fn probe_fixed_durable_quorum_readiness_with_placement_attestation(
        &self,
        attestation: &VerifiedQuorumTopologyAttestation,
    ) -> FixedQuorumReadinessReport {
        let start = tokio::time::Instant::now();
        let deadline = self.operation_deadline_from(start);
        let placement_policy = self
            .inner
            .topology
            .fixed_durable_placement_policy()
            .unwrap_or_default();
        let durable_readiness = self.probe_fixed_durable_readiness_before(deadline).await;
        let placement_resilience = TopologyAttestationTime::now()
            .ok()
            .and_then(|now| {
                self.refreshed_fixed_quorum_placement_attestation_valid_for_at(attestation, now)
            })
            .map(|_| PlacementResilienceReport::qualified(placement_policy))
            .unwrap_or_else(|| placement_policy.evaluate_unverified());
        self.fixed_durable_quorum_readiness_report(placement_resilience, durable_readiness)
    }

    /// Deterministic-time form of
    /// [`Self::probe_fixed_durable_quorum_readiness_with_placement_attestation`].
    ///
    /// `now` evaluates only the refreshed physical-placement claim. It never
    /// extends, revokes, or otherwise influences fixed quorum authority.
    pub async fn probe_fixed_durable_quorum_readiness_with_placement_attestation_at(
        &self,
        attestation: &VerifiedQuorumTopologyAttestation,
        now: TopologyAttestationTime,
    ) -> FixedQuorumReadinessReport {
        let start = tokio::time::Instant::now();
        let deadline = self.operation_deadline_from(start);
        let placement_policy = self
            .inner
            .topology
            .fixed_durable_placement_policy()
            .unwrap_or_default();
        let durable_readiness = self.probe_fixed_durable_readiness_before(deadline).await;
        let placement_resilience = self
            .refreshed_fixed_quorum_placement_attestation_valid_for_at(attestation, now)
            .map(|_| PlacementResilienceReport::qualified(placement_policy))
            .unwrap_or_else(|| placement_policy.evaluate_unverified());
        self.fixed_durable_quorum_readiness_report(placement_resilience, durable_readiness)
    }

    fn fixed_durable_quorum_readiness_report(
        &self,
        placement_resilience: PlacementResilienceReport,
        durable_readiness: DurableReadinessReport,
    ) -> FixedQuorumReadinessReport {
        let traffic_authority = match durable_readiness.state() {
            DurableReadinessState::Ready => FixedQuorumTrafficAuthority::Granted,
            DurableReadinessState::RecoveryRequired => {
                FixedQuorumTrafficAuthority::RecoveryRequired
            }
            DurableReadinessState::NoQuorum => FixedQuorumTrafficAuthority::NoQuorum,
            DurableReadinessState::TopologyInvalid => {
                FixedQuorumTrafficAuthority::StructuralRecoveryRequired
            }
        };
        FixedQuorumReadinessReport::new(traffic_authority, placement_resilience, durable_readiness)
    }

    async fn probe_fixed_durable_readiness_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> DurableReadinessReport {
        if let Some(report) = self.fatal_engine_readiness_report() {
            return report;
        }
        match tokio::time::timeout_at(deadline, self.durable_fixed_quorum_scope_record_is_exact())
            .await
        {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => return self.topology_invalid_readiness_report(),
            Ok(Err(_)) | Err(_) => return self.unavailable_durable_readiness_report(),
        }
        let report = self.probe_durable_readiness_before(deadline).await;
        if report.state() != DurableReadinessState::Ready {
            return report;
        }
        match tokio::time::timeout_at(deadline, self.durable_fixed_quorum_scope_is_exact()).await {
            Ok(Ok(true)) => report,
            Ok(Ok(false)) => self.topology_invalid_readiness_report(),
            Ok(Err(_)) | Err(_) => self.unavailable_durable_readiness_report(),
        }
    }

    async fn durable_fixed_quorum_scope_is_exact(
        &self,
    ) -> Result<bool, ConsensusSessionStoreOpenError> {
        if self.inner.topology.mode() != QuorumTopologyMode::FixedDurableQuorum {
            return Ok(false);
        }
        let (authority_profile, persisted_placement_policy, scope, applied_membership) = self
            .inner
            .backend
            .fixed_quorum_scope_snapshot(self.inner.storage_identity)
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?;
        Ok(
            authority_profile == storage::ConsensusAuthorityProfile::FixedImmutable
                && persisted_placement_policy
                    == self.inner.topology.fixed_durable_placement_policy()
                && scope.current_identity == self.inner.storage_identity
                && scope.current_members == self.inner.bootstrap_members
                && scope.current_bindings == self.inner.bootstrap_bindings
                && scope.application_authority_epoch
                    == self.inner.storage_identity.configuration_epoch()
                && scope.application_authority_members == self.inner.bootstrap_members
                && scope.pending.is_none()
                && scope.predecessor.is_none()
                && scope.history.is_empty()
                && scope.terminal_history.is_empty()
                && scope.terminal.is_none()
                && exact_uniform_voter_membership(
                    &applied_membership,
                    &self.inner.bootstrap_members,
                ),
        )
    }

    async fn durable_fixed_quorum_scope_record_is_exact(
        &self,
    ) -> Result<bool, ConsensusSessionStoreOpenError> {
        if self.inner.topology.mode() != QuorumTopologyMode::FixedDurableQuorum {
            return Ok(false);
        }
        let (authority_profile, persisted_placement_policy, scope, _) = self
            .inner
            .backend
            .fixed_quorum_scope_snapshot(self.inner.storage_identity)
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?;
        Ok(
            authority_profile == storage::ConsensusAuthorityProfile::FixedImmutable
                && persisted_placement_policy
                    == self.inner.topology.fixed_durable_placement_policy()
                && scope.current_identity == self.inner.storage_identity
                && scope.current_members == self.inner.bootstrap_members
                && scope.current_bindings == self.inner.bootstrap_bindings
                && scope.application_authority_epoch
                    == self.inner.storage_identity.configuration_epoch()
                && scope.application_authority_members == self.inner.bootstrap_members
                && scope.pending.is_none()
                && scope.predecessor.is_none()
                && scope.history.is_empty()
                && scope.terminal_history.is_empty()
                && scope.terminal.is_none(),
        )
    }

    fn fixed_durable_quorum_scope_is_exact(&self) -> bool {
        matches!(
            self.inner.topology.mode(),
            QuorumTopologyMode::FixedDurableQuorum
        ) && matches!(self.inner.bootstrap_members.len(), 3 | 5)
            && self
                .inner
                .topology
                .fixed_durable_placement_policy()
                .is_some()
            && self.current_scope().is_ok_and(|(identity, members)| {
                identity == self.inner.storage_identity && members == self.inner.bootstrap_members
            })
    }

    fn fixed_quorum_placement_resilience_at(
        &self,
        placement_policy: PlacementResiliencePolicy,
        now: TopologyAttestationTime,
    ) -> Option<PlacementResilienceReport> {
        if self.inner.topology.mode() != QuorumTopologyMode::FixedDurableQuorum {
            return None;
        }
        if self
            .fixed_quorum_placement_attestation_valid_for_at(now)
            .is_some()
        {
            Some(PlacementResilienceReport::qualified(placement_policy))
        } else {
            Some(placement_policy.evaluate_unverified())
        }
    }

    fn operation_deadline_from(&self, start: tokio::time::Instant) -> tokio::time::Instant {
        start
            .checked_add(self.inner.operation_timeout)
            .unwrap_or(start)
    }

    async fn probe_durable_readiness_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> DurableReadinessReport {
        if let Some(report) = self.fatal_engine_readiness_report() {
            return report;
        }
        let configured = self.current_member_count().unwrap_or(0);
        let quorum = (configured / 2) + 1;
        let report_without_barrier = |state, recovery_progress| {
            DurableReadinessReport::new(state, configured, 0, 0, quorum, None, Vec::new())
                .with_recovery_progress(recovery_progress)
        };
        let progress = || {
            let metrics = self.inner.raft.metrics();
            let metrics = metrics.borrow();
            let state = if metrics.running_state.is_err() {
                DurableRecoveryState::RecoveryRequired
            } else if metrics.last_log_index
                > metrics.last_applied.as_ref().map(|log_id| log_id.index)
            {
                DurableRecoveryState::CatchingUp
            } else {
                DurableRecoveryState::AwaitingQuorum
            };
            DurableRecoveryProgress::new(
                state,
                metrics.last_log_index,
                metrics.last_applied.as_ref().map(|log_id| log_id.index),
                metrics.snapshot.as_ref().map(|log_id| log_id.index),
                metrics.purged.as_ref().map(|log_id| log_id.index),
            )
        };
        let recovery_pending = match tokio::time::timeout_at(
            deadline,
            self.inner
                .backend
                .consensus_operator_recovery_pending(self.inner.storage_identity),
        )
        .await
        {
            Ok(Ok(recovery_pending)) => recovery_pending,
            Ok(Err(_)) | Err(_) => return self.unavailable_durable_readiness_report(),
        };
        if recovery_pending {
            let metrics = self.inner.raft.metrics();
            let metrics = metrics.borrow();
            let recovery_progress = DurableRecoveryProgress::new(
                DurableRecoveryState::RecoveryRequired,
                metrics.last_log_index,
                metrics.last_applied.as_ref().map(|log_id| log_id.index),
                metrics.snapshot.as_ref().map(|log_id| log_id.index),
                metrics.purged.as_ref().map(|log_id| log_id.index),
            );
            return report_without_barrier(
                DurableReadinessState::RecoveryRequired,
                recovery_progress,
            );
        }
        if !self.exact_membership_is_admitted() {
            let progress = progress();
            let state = if progress.state() == DurableRecoveryState::RecoveryRequired {
                DurableReadinessState::RecoveryRequired
            } else {
                DurableReadinessState::NoQuorum
            };
            return report_without_barrier(state, progress);
        }
        match self.linearizable_barrier_before(deadline).await {
            Ok(log_id) => {
                let metrics = self.inner.raft.metrics();
                let metrics = metrics.borrow();
                let recovery_progress = DurableRecoveryProgress::new(
                    DurableRecoveryState::Synchronized,
                    metrics.last_log_index,
                    metrics.last_applied.as_ref().map(|log_id| log_id.index),
                    metrics.snapshot.as_ref().map(|log_id| log_id.index),
                    metrics.purged.as_ref().map(|log_id| log_id.index),
                );
                let observations = self
                    .inner
                    .topology
                    .local_replica_id()
                    .cloned()
                    .map(|replica_id| {
                        ReplicaReadinessObservation::new(
                            replica_id,
                            log_id.map(|log_id| log_id.index),
                            ReplicaReadinessOutcome::Fresh,
                        )
                    })
                    .into_iter()
                    .collect();
                DurableReadinessReport::new(
                    DurableReadinessState::Ready,
                    configured,
                    quorum,
                    quorum,
                    quorum,
                    log_id.map(|log_id| log_id.index),
                    observations,
                )
                .with_recovery_progress(recovery_progress)
            }
            Err(LinearizableBarrierFailure::RecoveryRequired) => {
                let metrics = self.inner.raft.metrics();
                let metrics = metrics.borrow();
                let recovery_progress = DurableRecoveryProgress::new(
                    DurableRecoveryState::RecoveryRequired,
                    metrics.last_log_index,
                    metrics.last_applied.as_ref().map(|log_id| log_id.index),
                    metrics.snapshot.as_ref().map(|log_id| log_id.index),
                    metrics.purged.as_ref().map(|log_id| log_id.index),
                );
                report_without_barrier(DurableReadinessState::RecoveryRequired, recovery_progress)
            }
            Err(LinearizableBarrierFailure::Unavailable) => {
                let progress = progress();
                let state = if progress.state() == DurableRecoveryState::RecoveryRequired {
                    DurableReadinessState::RecoveryRequired
                } else {
                    DurableReadinessState::NoQuorum
                };
                report_without_barrier(state, progress)
            }
        }
    }

    /// Fresh Openraft readiness gated by currently valid, production-eligible
    /// platform topology evidence.
    ///
    /// Unlike [`Self::probe_durable_readiness`], this is the production traffic
    /// gate. Descriptor-only, deterministic-conformance, expired, or
    /// not-yet-valid evidence returns [`DurableReadinessState::TopologyInvalid`]
    /// without attempting to turn a successful quorum barrier into readiness.
    pub async fn probe_production_durable_readiness(&self) -> DurableReadinessReport {
        let Ok(now) = TopologyAttestationTime::now() else {
            return self.topology_invalid_readiness_report();
        };
        let report = self.probe_production_durable_readiness_at(now).await;
        let Ok(finished_at) = TopologyAttestationTime::now() else {
            return self.topology_invalid_readiness_report();
        };
        if self
            .initial_production_attestation_valid_for_at(finished_at)
            .is_none()
        {
            return self.topology_invalid_readiness_report();
        }
        report
    }

    /// Deterministic-time form of [`Self::probe_production_durable_readiness`]
    /// for conformance harnesses and platform clocks.
    ///
    /// `now` is the wall-clock evaluation origin. Monotonic elapsed time during
    /// the asynchronous probe still consumes the evidence's remaining validity.
    /// Every call on one store must come from one nondecreasing trusted clock;
    /// a backward value fails closed. The no-argument production method uses
    /// the platform system clock directly.
    pub async fn probe_production_durable_readiness_at(
        &self,
        now: TopologyAttestationTime,
    ) -> DurableReadinessReport {
        self.probe_durable_readiness_with_production_attestation(
            self.inner.topology.attestation_admission(),
            now,
        )
        .await
    }

    /// Fresh Openraft readiness gated by a separately refreshed attestation
    /// and the current platform wall clock.
    ///
    /// The proof is bound to the exact immutable store topology. The probe also
    /// uses a monotonic deadline and rechecks wall-clock freshness after the
    /// asynchronous barrier, so evidence expiring during the operation cannot
    /// produce a ready result.
    pub async fn probe_production_durable_readiness_with_attestation(
        &self,
        attestation: &VerifiedQuorumTopologyAttestation,
    ) -> DurableReadinessReport {
        let Ok(now) = TopologyAttestationTime::now() else {
            return self.topology_invalid_readiness_report();
        };
        let report = self
            .probe_production_durable_readiness_with_attestation_at(attestation, now)
            .await;
        let Ok(finished_at) = TopologyAttestationTime::now() else {
            return self.topology_invalid_readiness_report();
        };
        if self
            .refreshed_production_attestation_valid_for_at(attestation, finished_at)
            .is_none()
        {
            return self.topology_invalid_readiness_report();
        }
        report
    }

    /// Fresh Openraft readiness gated by a separately refreshed attestation
    /// for this exact immutable topology.
    ///
    /// This is the long-running form of the production gate: consumers may
    /// periodically authenticate replacement evidence through
    /// [`ValidatedQuorumTopology::verify_attestation_evidence`] and pass the
    /// resulting opaque value here. The token cannot change membership and a
    /// token for another cluster/configuration/epoch fails closed. Monotonic
    /// elapsed time during the probe consumes the token's remaining validity.
    /// Every explicit `now` on one store must come from the same nondecreasing
    /// trusted clock authority. A process restart must authenticate evidence
    /// again against current time; the in-process clock high-water and verified
    /// token are intentionally not persisted. The attestor's proof/replay policy
    /// decides whether a still-unexpired underlying proof may be re-presented.
    pub async fn probe_production_durable_readiness_with_attestation_at(
        &self,
        attestation: &VerifiedQuorumTopologyAttestation,
        now: TopologyAttestationTime,
    ) -> DurableReadinessReport {
        let current_identity = self.current_scope().ok().map(|(identity, _)| identity);
        if self.inner.topology.mode() != QuorumTopologyMode::AttestedHa
            || current_identity != Some(attestation.consensus_identity())
        {
            return self.topology_invalid_readiness_report();
        }
        self.probe_durable_readiness_with_production_attestation(attestation.admission(), now)
            .await
    }

    async fn probe_durable_readiness_with_production_attestation(
        &self,
        admission: &crate::topology_attestation::TopologyAttestationAdmission,
        now: TopologyAttestationTime,
    ) -> DurableReadinessReport {
        // Capture the operation origin before evaluating freshness. Any time
        // consumed by wall/monotonic verification must reduce, never extend,
        // the asynchronous barrier budget.
        let start = tokio::time::Instant::now();
        let Some(valid_for) = self.attestation_valid_for_at(admission, now) else {
            return self.topology_invalid_readiness_report();
        };
        let Some(attestation_deadline) =
            attestation_deadline_from_verification_start(start, valid_for)
        else {
            return self.topology_invalid_readiness_report();
        };
        let deadline = self
            .operation_deadline_from(start)
            .min(attestation_deadline);
        let report = self
            .probe_durable_readiness_before(deadline)
            .await
            .with_production_topology_attestation();
        if tokio::time::Instant::now() >= attestation_deadline
            || self.attestation_valid_for_at(admission, now).is_none()
        {
            self.topology_invalid_readiness_report()
        } else {
            report
        }
    }

    fn initial_production_attestation_valid_for_at(
        &self,
        now: TopologyAttestationTime,
    ) -> Option<Duration> {
        (self.inner.topology.mode() == QuorumTopologyMode::AttestedHa).then_some(())?;
        self.current_scope()
            .ok()
            .filter(|(identity, _)| *identity == self.inner.storage_identity)?;
        self.attestation_valid_for_at(self.inner.topology.attestation_admission(), now)
    }

    fn fixed_quorum_placement_attestation_valid_for_at(
        &self,
        now: TopologyAttestationTime,
    ) -> Option<Duration> {
        (self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum).then_some(())?;
        self.current_scope()
            .ok()
            .filter(|(identity, _)| *identity == self.inner.storage_identity)?;
        self.attestation_valid_for_at(self.inner.topology.attestation_admission(), now)
    }

    fn refreshed_fixed_quorum_placement_attestation_valid_for_at(
        &self,
        attestation: &VerifiedQuorumTopologyAttestation,
        now: TopologyAttestationTime,
    ) -> Option<Duration> {
        (self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum).then_some(())?;
        self.current_scope()
            .ok()
            .filter(|(identity, _)| *identity == attestation.consensus_identity())?;
        self.attestation_valid_for_at(attestation.admission(), now)
    }

    fn refreshed_production_attestation_valid_for_at(
        &self,
        attestation: &VerifiedQuorumTopologyAttestation,
        now: TopologyAttestationTime,
    ) -> Option<Duration> {
        (self.inner.topology.mode() == QuorumTopologyMode::AttestedHa).then_some(())?;
        self.current_scope()
            .ok()
            .filter(|(identity, _)| *identity == attestation.consensus_identity())?;
        self.attestation_valid_for_at(attestation.admission(), now)
    }

    fn attestation_valid_for_at(
        &self,
        admission: &crate::topology_attestation::TopologyAttestationAdmission,
        now: TopologyAttestationTime,
    ) -> Option<Duration> {
        let verified_at = admission.production_verified_at()?;
        if self.current_member_count()? < 3
            || now < verified_at
            || !self.advance_topology_attestation_time(now)
        {
            return None;
        }
        let valid_for = admission.production_valid_for_at(now, std::time::Instant::now())?;
        (self
            .inner
            .topology_attestation_time_high_water
            .load(Ordering::Acquire)
            == now.unix_seconds())
        .then_some(valid_for)
    }

    fn advance_topology_attestation_time(&self, now: TopologyAttestationTime) -> bool {
        let candidate = now.unix_seconds();
        let high_water = &self.inner.topology_attestation_time_high_water;
        let mut current = high_water.load(Ordering::Acquire);
        loop {
            if candidate < current {
                return false;
            }
            if candidate == current {
                return true;
            }
            match high_water.compare_exchange_weak(
                current,
                candidate,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    fn topology_invalid_readiness_report(&self) -> DurableReadinessReport {
        let configured = self.current_member_count().unwrap_or(0);
        let quorum = (configured / 2) + 1;
        DurableReadinessReport::new(
            DurableReadinessState::TopologyInvalid,
            configured,
            0,
            0,
            quorum,
            None,
            Vec::new(),
        )
        .with_production_topology_attestation()
    }

    /// A durable observation did not complete. This remains a transient
    /// quorum failure unless the local Openraft engine has already supplied
    /// authoritative fatal evidence.
    fn unavailable_durable_readiness_report(&self) -> DurableReadinessReport {
        if let Some(report) = self.fatal_engine_readiness_report() {
            return report;
        }
        let configured = self.current_member_count().unwrap_or(0);
        let quorum = (configured / 2) + 1;
        let metrics = self.inner.raft.metrics();
        let metrics = metrics.borrow();
        DurableReadinessReport::new(
            DurableReadinessState::NoQuorum,
            configured,
            0,
            0,
            quorum,
            None,
            Vec::new(),
        )
        .with_recovery_progress(DurableRecoveryProgress::new(
            DurableRecoveryState::AwaitingQuorum,
            metrics.last_log_index,
            metrics.last_applied.as_ref().map(|log_id| log_id.index),
            metrics.snapshot.as_ref().map(|log_id| log_id.index),
            metrics.purged.as_ref().map(|log_id| log_id.index),
        ))
    }

    /// A fatal Openraft engine state is local authoritative evidence. It has
    /// priority over failures while reading auxiliary durable authority, so a
    /// known recovery-required state cannot be downgraded to transient
    /// no-quorum.
    fn fatal_engine_readiness_report(&self) -> Option<DurableReadinessReport> {
        let metrics = self.inner.raft.metrics();
        let metrics = metrics.borrow();
        if metrics.running_state.is_ok() {
            return None;
        }
        let configured = self.current_member_count().unwrap_or(0);
        let quorum = (configured / 2) + 1;
        Some(
            DurableReadinessReport::new(
                DurableReadinessState::RecoveryRequired,
                configured,
                0,
                0,
                quorum,
                None,
                Vec::new(),
            )
            .with_recovery_progress(DurableRecoveryProgress::new(
                DurableRecoveryState::RecoveryRequired,
                metrics.last_log_index,
                metrics.last_applied.as_ref().map(|log_id| log_id.index),
                metrics.snapshot.as_ref().map(|log_id| log_id.index),
                metrics.purged.as_ref().map(|log_id| log_id.index),
            )),
        )
    }

    async fn submit_intent(
        &self,
        intent: SessionMutationIntent,
    ) -> Result<SessionConsensusResponse, StoreError> {
        self.submit_request(SessionConsensusRequestId::new(), intent)
            .await
    }

    async fn submit_request(
        &self,
        request_id: SessionConsensusRequestId,
        intent: SessionMutationIntent,
    ) -> Result<SessionConsensusResponse, StoreError> {
        self.submit_request_with_consumer_scope(request_id, intent, None)
            .await
    }

    async fn submit_request_with_consumer_scope(
        &self,
        request_id: SessionConsensusRequestId,
        intent: SessionMutationIntent,
        required_consumer_scope: Option<SessionConsensusIdentity>,
    ) -> Result<SessionConsensusResponse, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.submit_request_before(request_id, intent, required_consumer_scope, deadline)
            .await
    }

    async fn submit_request_before(
        &self,
        request_id: SessionConsensusRequestId,
        intent: SessionMutationIntent,
        required_consumer_scope: Option<SessionConsensusIdentity>,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsensusResponse, StoreError> {
        self.submit_request_before_with_rejected_response(
            request_id,
            intent,
            required_consumer_scope,
            deadline,
            false,
        )
        .await
    }

    /// Submit one request, optionally retaining a validated rejected response
    /// so a consumer-scoped V2 path can distinguish a pre-proposal rejection
    /// from a committed, receipt-bearing deterministic error by log index.
    /// Existing generic callers retain the historical typed-error projection.
    async fn submit_request_before_with_rejected_response(
        &self,
        request_id: SessionConsensusRequestId,
        intent: SessionMutationIntent,
        required_consumer_scope: Option<SessionConsensusIdentity>,
        deadline: tokio::time::Instant,
        preserve_rejected_response: bool,
    ) -> Result<SessionConsensusResponse, StoreError> {
        let outcome_unavailable = consensus_outcome_unavailable(&intent);
        match self
            .submit_request_effect_before(request_id, intent, required_consumer_scope, deadline)
            .await
        {
            ConsensusSubmissionEffect::NotTransmitted(error) => Err(error),
            ConsensusSubmissionEffect::OutcomeUnknown => Err(outcome_unavailable),
            ConsensusSubmissionEffect::Committed(response) => Ok(response),
            ConsensusSubmissionEffect::Rejected(response) if preserve_rejected_response => {
                Ok(response)
            }
            ConsensusSubmissionEffect::Rejected(response) => match response.result {
                Err(error) => Err(error),
                Ok(_) => Err(outcome_unavailable),
            },
        }
    }

    /// Submit one mutation while retaining only evidence that is meaningful at
    /// the request effect boundary.  In particular, `BeforeTransmission` and
    /// local pre-accept failures remain distinct from a forwarded write or a
    /// Raft proposal that may already exist.
    async fn submit_request_effect_before(
        &self,
        request_id: SessionConsensusRequestId,
        intent: SessionMutationIntent,
        required_consumer_scope: Option<SessionConsensusIdentity>,
        deadline: tokio::time::Instant,
    ) -> ConsensusSubmissionEffect {
        if let Err(error) = validate_consensus_intent(&intent) {
            return ConsensusSubmissionEffect::NotTransmitted(error);
        }
        let fixed_raw_v2_consumer_warm_route = self
            .fixed_raw_v2_consumer_warm_route_for_intent(&intent, required_consumer_scope.as_ref());
        if !fixed_raw_v2_consumer_warm_route {
            if let Err(error) = self
                .require_application_traffic_authority_before(deadline)
                .await
            {
                return ConsensusSubmissionEffect::NotTransmitted(error);
            }
        }
        let request = ForwardMutationRequest {
            request_id,
            intent,
            required_consumer_scope: ForwardConsumerScope::from_optional(required_consumer_scope),
        };
        let mut preferred = None;
        let mut outcome_may_be_unavailable = false;

        loop {
            let leader = match preferred.take() {
                Some(leader) => leader,
                None => match self.wait_for_known_leader(deadline).await {
                    Ok(leader) => leader,
                    Err(_) if outcome_may_be_unavailable => {
                        return ConsensusSubmissionEffect::OutcomeUnknown;
                    }
                    Err(error) => return ConsensusSubmissionEffect::NotTransmitted(error),
                },
            };
            let reply = if leader == self.inner.local_node_id {
                self.apply_on_local_leader(request.clone(), self.inner.local_node_id, deadline)
                    .await
            } else {
                match self
                    .call_peer::<_, ForwardMutationReply>(
                        leader,
                        SessionConsensusRpcFamily::ForwardMutation,
                        &ForwardRequest::Mutation(request.clone()),
                        deadline,
                    )
                    .await
                {
                    Ok(reply) => reply,
                    Err(ConsensusPeerCallFailure::AfterTransmission) => {
                        // The peer abstraction cannot prove that a failed call
                        // stopped before delivery. Retrying this same durable
                        // request ID is safe; returning a generic unavailable
                        // error after this point is not.
                        outcome_may_be_unavailable = true;
                        // A fenced transition exposes exact status precisely
                        // so callers never need an automatic replay after the
                        // forwarding write boundary. Return ambiguity after
                        // the first possibly delivered transmission; only a
                        // proven pre-transmission failure may reroute it.
                        if mutation_requires_exact_status_resolution(&request) {
                            return ConsensusSubmissionEffect::OutcomeUnknown;
                        }
                        if self.wait_for_route_refresh(leader, deadline).await.is_err() {
                            return ConsensusSubmissionEffect::OutcomeUnknown;
                        }
                        continue;
                    }
                    Err(ConsensusPeerCallFailure::BeforeTransmission) => {
                        if let Err(error) = self.wait_for_route_refresh(leader, deadline).await {
                            return if outcome_may_be_unavailable {
                                ConsensusSubmissionEffect::OutcomeUnknown
                            } else {
                                ConsensusSubmissionEffect::NotTransmitted(error)
                            };
                        }
                        continue;
                    }
                }
            };
            match reply {
                ForwardMutationReply::Applied(response) => {
                    if committed_response_matches_intent(&request.intent, &response) {
                        if !fixed_raw_v2_consumer_warm_route
                            && self
                                .require_application_traffic_authority_before(deadline)
                                .await
                                .is_err()
                        {
                            return ConsensusSubmissionEffect::OutcomeUnknown;
                        }
                        return ConsensusSubmissionEffect::Committed(*response);
                    }
                    if !outcome_may_be_unavailable
                        && rejected_response_matches_intent(&request.intent, &response)
                    {
                        return ConsensusSubmissionEffect::Rejected(*response);
                    }
                    return ConsensusSubmissionEffect::OutcomeUnknown;
                }
                ForwardMutationReply::NotLeader {
                    leader: next_leader,
                } => {
                    preferred = next_leader.filter(|candidate| {
                        *candidate != leader && self.is_current_member(*candidate)
                    });
                    if preferred.is_none() {
                        if let Err(error) = self.wait_for_route_refresh(leader, deadline).await {
                            return if outcome_may_be_unavailable {
                                ConsensusSubmissionEffect::OutcomeUnknown
                            } else {
                                ConsensusSubmissionEffect::NotTransmitted(error)
                            };
                        }
                    }
                }
                // The request may already have reached a forwarding peer or
                // Raft append. Only exact status may resolve this boundary.
                ForwardMutationReply::OutcomeUnknown => {
                    return accepted_client_write_receiver_failure_effect();
                }
                ForwardMutationReply::Unavailable => {
                    if let Err(error) = self.wait_for_route_refresh(leader, deadline).await {
                        return if outcome_may_be_unavailable {
                            ConsensusSubmissionEffect::OutcomeUnknown
                        } else {
                            ConsensusSubmissionEffect::NotTransmitted(error)
                        };
                    }
                }
                ForwardMutationReply::RecordExpiryPreflight(_) => {
                    return ConsensusSubmissionEffect::OutcomeUnknown;
                }
            }
        }
    }

    async fn preflight_record_expiry_before(
        &self,
        preflights: &[RecordExpiryPreflight],
        required_consumer_scope: Option<SessionConsensusIdentity>,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        validate_record_expiry_preflights_profile(preflights)?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        let request = ForwardRequest::RecordExpiryPreflight {
            preflights: BoundedRecordExpiryPreflights::try_from_slice(preflights)?,
            required_consumer_scope: ForwardConsumerScope::from_optional(required_consumer_scope),
        };
        let mut preferred = None;
        loop {
            let leader = match preferred.take() {
                Some(leader) => leader,
                None => self.wait_for_known_leader(deadline).await?,
            };
            let reply = if leader == self.inner.local_node_id {
                let ForwardRequest::RecordExpiryPreflight {
                    preflights,
                    required_consumer_scope,
                } = request.clone()
                else {
                    unreachable!("fixed expiry-preflight request")
                };
                self.preflight_record_expiry_on_local_leader(
                    preflights.into_inner(),
                    required_consumer_scope,
                    self.inner.local_node_id,
                    deadline,
                )
                .await
            } else {
                match self
                    .call_peer::<_, ForwardMutationReply>(
                        leader,
                        SessionConsensusRpcFamily::ForwardMutation,
                        &request,
                        deadline,
                    )
                    .await
                {
                    Ok(reply) => reply,
                    Err(ConsensusPeerCallFailure::AfterTransmission) => {
                        // A valid preflight may have committed only its logical
                        // time floor. Never run provider work without a
                        // definitive acknowledgement; an outer retry is safe.
                        return Err(consensus_unavailable());
                    }
                    Err(ConsensusPeerCallFailure::BeforeTransmission) => {
                        self.wait_for_route_refresh(leader, deadline).await?;
                        continue;
                    }
                }
            };
            match reply {
                ForwardMutationReply::RecordExpiryPreflight(result) => {
                    result?;
                    self.require_application_traffic_authority_before(deadline)
                        .await?;
                    return Ok(());
                }
                ForwardMutationReply::NotLeader {
                    leader: next_leader,
                } => {
                    preferred = next_leader.filter(|candidate| {
                        *candidate != leader && self.is_current_member(*candidate)
                    });
                    if preferred.is_none() {
                        self.wait_for_route_refresh(leader, deadline).await?;
                    }
                }
                ForwardMutationReply::Unavailable => {
                    self.wait_for_route_refresh(leader, deadline).await?;
                }
                ForwardMutationReply::OutcomeUnknown => {
                    return Err(consensus_unavailable());
                }
                ForwardMutationReply::Applied(_) => {
                    return Err(consensus_unavailable());
                }
            }
        }
    }

    async fn apply_on_local_leader(
        &self,
        request: ForwardMutationRequest,
        origin: SessionConsensusNodeId,
        deadline: tokio::time::Instant,
    ) -> ForwardMutationReply {
        self.apply_on_local_leader_inner(request, origin, deadline, false, None)
            .await
    }

    /// Execute one already-routed V2 status ticket on the local leader.
    ///
    /// The cohort freeze is not serialized and cannot be supplied by a peer:
    /// it is an in-process ownership marker installed only by the leader's
    /// bounded supervisor.
    async fn fenced_transition_v2_status_logical_time_on_local_leader(
        &self,
        required_consumer_scope: SessionConsensusIdentity,
        deadline: tokio::time::Instant,
        cohort_freeze: Arc<AtomicBool>,
    ) -> FencedTransitionV2StatusLogicalTimeTicketReply {
        let reply = self
            .apply_on_local_leader_inner(
                ForwardMutationRequest {
                    request_id: SessionConsensusRequestId::new(),
                    intent: SessionMutationIntent::AdvanceLogicalTime,
                    required_consumer_scope: ForwardConsumerScope::Consumer(Box::new(
                        required_consumer_scope,
                    )),
                },
                self.inner.local_node_id,
                deadline,
                false,
                Some(cohort_freeze),
            )
            .await;
        match reply {
            ForwardMutationReply::Applied(response) => {
                match FencedTransitionV2StatusLogicalTimeTicket::try_from_response(
                    required_consumer_scope,
                    *response,
                ) {
                    Ok(ticket) => {
                        FencedTransitionV2StatusLogicalTimeTicketReply::Ticket(Box::new(ticket))
                    }
                    Err(error) => FencedTransitionV2StatusLogicalTimeTicketReply::Rejected(error),
                }
            }
            ForwardMutationReply::NotLeader { leader } => {
                FencedTransitionV2StatusLogicalTimeTicketReply::NotLeader { leader }
            }
            ForwardMutationReply::OutcomeUnknown
            | ForwardMutationReply::Unavailable
            | ForwardMutationReply::RecordExpiryPreflight(_) => {
                FencedTransitionV2StatusLogicalTimeTicketReply::Unavailable
            }
        }
    }

    async fn apply_on_local_leader_inner(
        &self,
        mut request: ForwardMutationRequest,
        origin: SessionConsensusNodeId,
        deadline: tokio::time::Instant,
        allow_operator_recovery: bool,
        cohort_freeze: Option<Arc<AtomicBool>>,
    ) -> ForwardMutationReply {
        if let Err(error) =
            validate_consensus_intent_with_recovery(&request.intent, allow_operator_recovery)
        {
            return ForwardMutationReply::Applied(Box::new(SessionConsensusResponse::rejected(
                error,
            )));
        }
        // Membership changes take the exclusive side of this gate. Holding a
        // shared guard through the definitive proposal result lets the
        // transition driver drain every already-admitted application write
        // before it commits learner-ready/fencing evidence.
        let operation_gate = self.inner.topology_coordinator.operation_gate();
        let operation_guard =
            match tokio::time::timeout_at(deadline, operation_gate.read_owned()).await {
                Ok(guard) => guard,
                Err(_) => return ForwardMutationReply::Unavailable,
            };
        let raw_v2_mutation =
            is_raw_fenced_transition_v2_mutation(&request.intent, allow_operator_recovery);
        let fixed_raw_v2_mutation =
            raw_v2_mutation && self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum;
        let initial_authority = if fixed_raw_v2_mutation {
            // The operation gate remains held, and the exact durable
            // authority is consumed once in the atomic post-barrier snapshot
            // below. Reading it here as well would serialize an avoidable
            // SQLite job without strengthening the acceptance boundary.
            Ok(())
        } else if allow_operator_recovery {
            self.require_durable_fixed_quorum_admission_before(deadline)
                .await
        } else {
            self.require_application_traffic_authority_before(deadline)
                .await
        };
        if initial_authority.is_err() {
            return ForwardMutationReply::Unavailable;
        }
        if request
            .required_consumer_scope
            .consumer_scope()
            .is_some_and(|required_scope| {
                self.current_scope()
                    .map_or(true, |(current_scope, _)| current_scope != *required_scope)
            })
        {
            return ForwardMutationReply::Applied(Box::new(SessionConsensusResponse::rejected(
                StoreError::TopologyAuthorityRevoked,
            )));
        }
        let proposal_permit = match tokio::time::timeout_at(
            deadline,
            Arc::clone(&self.inner.proposal_admission).acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) | Err(_) => {
                self.inner
                    .diagnostics
                    .proposal_permit_deadline
                    .fetch_add(1, Ordering::Relaxed);
                return ForwardMutationReply::Unavailable;
            }
        };

        // Raw V2 mutations own one local leader/read-index fence. It retains
        // exact membership before and after the barrier, then immediately
        // enters V2 activation/scope validation below. In a fixed quorum, the
        // next atomic SQLite snapshot is the sole final durable authority
        // check. Other topology modes retain their initial and final
        // authority checks. Activation wrappers and every other intent keep
        // generic leader admission.
        if requires_generic_leader_admission(&request.intent, allow_operator_recovery) {
            match self
                .inner
                .linearizability
                .ensure_linearizable(deadline)
                .await
            {
                EnsureLinearizableOutcome::Ready { .. } => {
                    let authority = if allow_operator_recovery {
                        self.require_durable_fixed_quorum_admission_before(deadline)
                            .await
                    } else {
                        self.require_application_traffic_authority_before(deadline)
                            .await
                    };
                    if authority.is_err() {
                        return ForwardMutationReply::Unavailable;
                    }
                }
                EnsureLinearizableOutcome::Retry { leader_hint } => {
                    return ForwardMutationReply::NotLeader {
                        leader: leader_hint,
                    };
                }
                EnsureLinearizableOutcome::Unavailable => {
                    return ForwardMutationReply::Unavailable;
                }
                _ => return ForwardMutationReply::Unavailable,
            }
        }

        if raw_v2_mutation {
            if let Err(reply) = self
                .admit_raw_v2_mutation_on_local_leader_before(deadline)
                .await
            {
                return reply;
            }
        }

        // An already-activated fixed raw V2 mutation has one final, uncached
        // SQLite acceptance snapshot after the direct same-term/read-index
        // barrier. The transaction binds exact authority, recovery state,
        // consumer scope, V2 profile activation, and applied logical time.
        // `Some(None)` means activated with no prior logical time; outer None
        // means the scope is not yet activated and retains the existing fresh
        // unanimity path below.
        let fixed_v2_snapshot_logical_time = if fixed_raw_v2_mutation {
            let (scope_identity, voters) = match self.current_scope() {
                Ok(scope) => scope,
                Err(_) => return ForwardMutationReply::Unavailable,
            };
            let expected_placement_policy =
                match self.inner.topology.fixed_durable_placement_policy() {
                    Some(policy) => policy,
                    None => return ForwardMutationReply::Unavailable,
                };
            match tokio::time::timeout_at(
                deadline,
                self.inner
                    .backend
                    .fixed_quorum_activated_v2_mutation_snapshot(
                        crate::sqlite::FixedQuorumActivatedV2MutationSnapshotRequest {
                            storage_identity: self.inner.storage_identity,
                            scope_identity,
                            voters,
                            expected_members: self.inner.bootstrap_members.clone(),
                            expected_bindings: self.inner.bootstrap_bindings.clone(),
                            expected_placement_policy,
                            profile_digest:
                                crate::fenced_transition::fenced_transition_v2_profile_digest(),
                        },
                    ),
            )
            .await
            {
                Ok(Ok(crate::sqlite::FixedQuorumActivatedV2MutationSnapshot::Activated {
                    applied_logical_time,
                })) => Some(applied_logical_time),
                Ok(Ok(crate::sqlite::FixedQuorumActivatedV2MutationSnapshot::Unactivated)) => None,
                Ok(Err(_)) => {
                    self.inner
                        .diagnostics
                        .atomic_v2_authority_snapshot_backend_error
                        .fetch_add(1, Ordering::Relaxed);
                    return ForwardMutationReply::Unavailable;
                }
                Err(_) => {
                    self.inner
                        .diagnostics
                        .atomic_v2_authority_snapshot_deadline
                        .fetch_add(1, Ordering::Relaxed);
                    return ForwardMutationReply::Unavailable;
                }
            }
        } else {
            None
        };

        if matches!(&request.intent, SessionMutationIntent::FencedTransition(_)) {
            match self
                .require_fenced_transition_capability_before(deadline)
                .await
            {
                Ok(FencedTransitionCapabilityAdmission::Activated) => {}
                Ok(FencedTransitionCapabilityAdmission::FreshUnanimous) => {
                    let (scope_identity, voters) = match self.current_scope() {
                        Ok(scope) => scope,
                        Err(_) => return ForwardMutationReply::Unavailable,
                    };
                    let SessionMutationIntent::FencedTransition(transition) = request.intent else {
                        return ForwardMutationReply::Unavailable;
                    };
                    request.intent = SessionMutationIntent::ActivateFencedTransition {
                        request: transition,
                        scope_identity,
                        voter_set_digest: fenced_transition_voter_set_digest(
                            scope_identity,
                            &voters,
                        ),
                    };
                }
                Err(_) => {
                    return ForwardMutationReply::Applied(Box::new(
                        SessionConsensusResponse::rejected(unsupported_fenced_transition()),
                    ));
                }
            }
        }
        if matches!(
            &request.intent,
            SessionMutationIntent::FencedTransitionV2(_)
                | SessionMutationIntent::FencedTransitionV2Batch(_)
        ) {
            // The raw V2 local-admission path immediately above already
            // fenced this leader and checked exact membership on both sides.
            // Keep the full helper for any future non-raw V2 caller.
            let admission = if fixed_v2_snapshot_logical_time.is_some() {
                Ok(FencedTransitionV2CapabilityAdmission::Activated)
            } else if is_raw_fenced_transition_v2_mutation(&request.intent, allow_operator_recovery)
            {
                self.require_fenced_transition_v2_capability_after_barrier(deadline)
                    .await
            } else {
                self.require_fenced_transition_v2_capability_before(deadline)
                    .await
            };
            match admission {
                Ok(FencedTransitionV2CapabilityAdmission::Activated) => {}
                Ok(FencedTransitionV2CapabilityAdmission::FreshUnanimous) => {
                    // The public batch path consumes a fresh proof through
                    // one existing singleton activation before it forwards
                    // the remainder.  A raw batch must never manufacture a
                    // different activation shape at the leader.
                    if matches!(
                        &request.intent,
                        SessionMutationIntent::FencedTransitionV2Batch(_)
                    ) {
                        return ForwardMutationReply::Unavailable;
                    }
                    let (scope_identity, voters) = match self.current_scope() {
                        Ok(scope) => scope,
                        Err(_) => return ForwardMutationReply::Unavailable,
                    };
                    let SessionMutationIntent::FencedTransitionV2(transition) = request.intent
                    else {
                        return ForwardMutationReply::Unavailable;
                    };
                    request.intent = SessionMutationIntent::ActivateFencedTransitionV2 {
                        request: transition,
                        scope_identity,
                        voter_set_digest: fenced_transition_voter_set_digest(
                            scope_identity,
                            &voters,
                        ),
                        profile_digest:
                            crate::fenced_transition::fenced_transition_v2_profile_digest(),
                    };
                }
                Err(error) => {
                    return fenced_transition_v2_capability_failure_reply(error);
                }
            }
        }

        let logical_time = match fixed_v2_snapshot_logical_time {
            Some(persisted) => {
                let now = self.inner.clock.now_utc();
                persisted.map_or(now, |persisted| persisted.max(now))
            }
            None => match tokio::time::timeout_at(
                deadline,
                self.inner
                    .backend
                    .consensus_logical_time(self.inner.storage_identity),
            )
            .await
            {
                Ok(Ok(persisted)) => persisted.map_or_else(
                    || self.inner.clock.now_utc(),
                    |persisted| persisted.max(self.inner.clock.now_utc()),
                ),
                Ok(Err(_)) | Err(_) => return ForwardMutationReply::Unavailable,
            },
        };
        // Activated fixed raw V2 already consumed its sole final uncached
        // authority/logical-time snapshot above. Other raw V2 paths retain
        // their final authority check inside `propose_on_local_leader`. Keep
        // this historical post-logical-time authority snapshot for every
        // non-raw intent.
        if !is_raw_fenced_transition_v2_mutation(&request.intent, allow_operator_recovery)
            && !allow_operator_recovery
            && self
                .require_application_traffic_authority_before(deadline)
                .await
                .is_err()
        {
            return ForwardMutationReply::Unavailable;
        }
        // A fresh unanimity proof is intentionally never cached.  Recheck
        // the exact scope immediately before proposal as well, so a topology
        // hand-off between probing and logical-time admission cannot leave a
        // stale activation wrapper in the replicated log.
        if let Some((scope_identity, voter_set_digest, profile_digest)) =
            fenced_transition_activation_scope(&request.intent)
        {
            let Ok((current_identity, current_voters)) = self.current_scope() else {
                return ForwardMutationReply::Unavailable;
            };
            if *scope_identity != current_identity
                || *voter_set_digest
                    != fenced_transition_voter_set_digest(current_identity, &current_voters)
                || profile_digest.is_some_and(|profile_digest| {
                    *profile_digest
                        != crate::fenced_transition::fenced_transition_v2_profile_digest()
                })
            {
                return ForwardMutationReply::Unavailable;
            }
        }
        self.propose_on_local_leader(
            request,
            LocalProposalAuthority {
                origin,
                allows_operator_recovery: allow_operator_recovery,
                fixed_raw_v2_snapshot: fixed_v2_snapshot_logical_time.is_some(),
            },
            logical_time,
            LocalProposalExecution {
                proposal_permit,
                operation_guard,
                cohort_freeze,
            },
            deadline,
        )
        .await
    }

    async fn propose_on_local_leader(
        &self,
        request: ForwardMutationRequest,
        authority: LocalProposalAuthority,
        logical_time: Timestamp,
        execution: LocalProposalExecution,
        deadline: tokio::time::Instant,
    ) -> ForwardMutationReply {
        let LocalProposalExecution {
            proposal_permit,
            operation_guard,
            cohort_freeze,
        } = execution;
        let Ok((identity, voters)) = self.current_scope() else {
            return ForwardMutationReply::Unavailable;
        };
        if request
            .required_consumer_scope
            .consumer_scope()
            .is_some_and(|required_scope| *required_scope != identity)
        {
            return ForwardMutationReply::Applied(Box::new(SessionConsensusResponse::rejected(
                StoreError::TopologyAuthorityRevoked,
            )));
        }
        if let Some((scope_identity, voter_set_digest, profile_digest)) =
            fenced_transition_activation_scope(&request.intent)
        {
            if *scope_identity != identity
                || *voter_set_digest != fenced_transition_voter_set_digest(identity, &voters)
                || profile_digest.is_some_and(|profile_digest| {
                    *profile_digest
                        != crate::fenced_transition::fenced_transition_v2_profile_digest()
                })
            {
                return ForwardMutationReply::Unavailable;
            }
        }
        let reroute_receiver_forward_to_leader =
            !mutation_requires_exact_status_resolution(&request);
        let intent = match request.intent {
            intent @ SessionMutationIntent::FinalizeOperatorRecovery { .. }
            | intent @ SessionMutationIntent::MaintainFencedTransitionV2History { .. }
                if authority.allows_operator_recovery =>
            {
                intent
            }
            mutation => SessionMutationIntent::Authorized {
                origin: authority.origin,
                authority_identity: identity,
                mutation: Box::new(mutation),
            },
        };
        let command = super::SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: self.inner.storage_identity,
            request_id: request.request_id,
            logical_time,
            intent,
        };
        if let Err(error) = validate_consensus_command_preproposal(&command) {
            return ForwardMutationReply::Applied(Box::new(SessionConsensusResponse::rejected(
                error,
            )));
        }
        if encode_bounded(&command).is_err() {
            let max = self.inner.backend.consensus_capabilities().max_value_bytes;
            return ForwardMutationReply::Applied(Box::new(SessionConsensusResponse::rejected(
                StoreError::PayloadTooLarge {
                    actual: max.saturating_add(1),
                    max,
                },
            )));
        }

        if !authority.allows_operator_recovery
            && !authority.fixed_raw_v2_snapshot
            && self
                .require_application_traffic_authority_before(deadline)
                .await
                .is_err()
        {
            return ForwardMutationReply::Unavailable;
        }

        // This is the leader-owned cohort's linearization boundary.  Every
        // accepted exact-scope ticket which joined before this store becomes
        // part of this proposal; later arrivals stay queued for a new one.
        let status_ticket_proposal = cohort_freeze.is_some();
        if let Some(cohort_freeze) = cohort_freeze {
            cohort_freeze.store(true, Ordering::Release);
        }

        // Split Openraft's enqueue and result phases explicitly. Returning a
        // receiver proves only that the request entered Openraft's API queue;
        // the Raft core can still reject it as `ForwardToLeader` before append.
        // Losing that receiver or crossing the deadline remains an unknown
        // outcome, as do receiver errors for protected/status-resolved writes.
        let response =
            match tokio::time::timeout_at(deadline, self.inner.raft.client_write_ff(command)).await
            {
                Err(_) | Ok(Err(_)) => {
                    self.inner
                        .diagnostics
                        .client_write_ff_preaccept_failure
                        .fetch_add(1, Ordering::Relaxed);
                    return ForwardMutationReply::Unavailable;
                }
                Ok(Ok(response)) => {
                    if status_ticket_proposal {
                        self.inner
                            .diagnostics
                            .status_proposals
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    response
                }
            };
        #[cfg(test)]
        let accepted_receiver_test_error = ACCEPTED_RECEIVER_TEST_OUTCOMES
            .lock()
            .expect("accepted receiver test outcomes lock")
            .pop_front()
            .map(|outcome| match outcome {
                AcceptedClientWriteReceiverTestOutcome::ForwardToLeader => {
                    ClientWriteError::ForwardToLeader(
                        opc_consensus::engine::error::ForwardToLeader::new(
                            self.inner.local_node_id,
                            EmptyNode::new(),
                        ),
                    )
                }
            });
        // A detached supervisor owns the proposal permit until Openraft
        // resolves the receiver, so caller cancellation, peer EOF, or a
        // response deadline cannot admit an unbounded queue of detached
        // mutations behind the still-running command.
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            #[cfg(test)]
            if let Some(error) = accepted_receiver_test_error {
                // The test replaces only the receiver's observable result.
                // Keep the actual accepted receiver supervised exactly as in
                // production, including its proposal-admission lifetime.
                tokio::spawn(async move {
                    let _ = response.await;
                    drop(proposal_permit);
                    drop(operation_guard);
                });
                let _ = completion_tx.send(client_write_receiver_error_reply(
                    error,
                    reroute_receiver_forward_to_leader,
                ));
                return;
            }
            let reply = match response.await {
                Err(_) => ForwardMutationReply::OutcomeUnknown,
                Ok(Ok(response)) => ForwardMutationReply::Applied(Box::new(response.data)),
                Ok(Err(error)) => {
                    client_write_receiver_error_reply(error, reroute_receiver_forward_to_leader)
                }
            };
            let _ = completion_tx.send(reply);
            drop(proposal_permit);
            drop(operation_guard);
        });
        match tokio::time::timeout_at(deadline, completion_rx).await {
            Err(_) | Ok(Err(_)) => ForwardMutationReply::OutcomeUnknown,
            Ok(Ok(reply)) => reply,
        }
    }

    async fn preflight_record_expiry_on_local_leader(
        &self,
        preflights: Vec<RecordExpiryPreflight>,
        required_consumer_scope: ForwardConsumerScope,
        origin: SessionConsensusNodeId,
        deadline: tokio::time::Instant,
    ) -> ForwardMutationReply {
        if let Err(error) = validate_record_expiry_preflights_profile(&preflights) {
            return ForwardMutationReply::RecordExpiryPreflight(Err(error));
        }
        let operation_gate = self.inner.topology_coordinator.operation_gate();
        let operation_guard =
            match tokio::time::timeout_at(deadline, operation_gate.read_owned()).await {
                Ok(guard) => guard,
                Err(_) => return ForwardMutationReply::Unavailable,
            };
        if self
            .require_application_traffic_authority_before(deadline)
            .await
            .is_err()
        {
            return ForwardMutationReply::Unavailable;
        }
        if required_consumer_scope
            .consumer_scope()
            .is_some_and(|required_scope| {
                self.current_scope()
                    .map_or(true, |(current_scope, _)| current_scope != *required_scope)
            })
        {
            return ForwardMutationReply::RecordExpiryPreflight(Err(
                StoreError::TopologyAuthorityRevoked,
            ));
        }
        let proposal_permit = match tokio::time::timeout_at(
            deadline,
            Arc::clone(&self.inner.proposal_admission).acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(_)) | Err(_) => {
                self.inner
                    .diagnostics
                    .proposal_permit_deadline
                    .fetch_add(1, Ordering::Relaxed);
                return ForwardMutationReply::Unavailable;
            }
        };
        match self
            .inner
            .linearizability
            .ensure_linearizable(deadline)
            .await
        {
            EnsureLinearizableOutcome::Ready { .. } => {
                if self
                    .require_application_traffic_authority_before(deadline)
                    .await
                    .is_err()
                {
                    return ForwardMutationReply::Unavailable;
                }
            }
            EnsureLinearizableOutcome::Retry { leader_hint } => {
                return ForwardMutationReply::NotLeader {
                    leader: leader_hint,
                };
            }
            EnsureLinearizableOutcome::Unavailable => {
                return ForwardMutationReply::Unavailable;
            }
            _ => return ForwardMutationReply::Unavailable,
        }
        let persisted = match tokio::time::timeout_at(
            deadline,
            self.inner
                .backend
                .consensus_logical_time(self.inner.storage_identity),
        )
        .await
        {
            Ok(Ok(persisted)) => persisted,
            Ok(Err(_)) | Err(_) => return ForwardMutationReply::Unavailable,
        };
        if persisted.is_some_and(|persisted| {
            validate_record_expiry_preflights_at(&preflights, persisted).is_ok()
        }) {
            if self
                .require_application_traffic_authority_before(deadline)
                .await
                .is_err()
            {
                return ForwardMutationReply::Unavailable;
            }
            return ForwardMutationReply::RecordExpiryPreflight(Ok(()));
        }
        let authority_time = persisted.map_or_else(
            || self.inner.clock.now_utc(),
            |persisted| persisted.max(self.inner.clock.now_utc()),
        );
        if let Err(error) = validate_record_expiry_preflights_at(&preflights, authority_time) {
            return ForwardMutationReply::RecordExpiryPreflight(Err(error));
        }
        if !preflights
            .iter()
            .copied()
            .any(RecordExpiryPreflight::is_finite)
        {
            if self
                .require_application_traffic_authority_before(deadline)
                .await
                .is_err()
            {
                return ForwardMutationReply::Unavailable;
            }
            return ForwardMutationReply::RecordExpiryPreflight(Ok(()));
        }

        if self
            .require_application_traffic_authority_before(deadline)
            .await
            .is_err()
        {
            return ForwardMutationReply::Unavailable;
        }

        let intent = SessionMutationIntent::AdvanceLogicalTime;
        let reply = self
            .propose_on_local_leader(
                ForwardMutationRequest {
                    request_id: SessionConsensusRequestId::new(),
                    intent: intent.clone(),
                    required_consumer_scope,
                },
                LocalProposalAuthority {
                    origin,
                    allows_operator_recovery: false,
                    fixed_raw_v2_snapshot: false,
                },
                authority_time,
                LocalProposalExecution {
                    proposal_permit,
                    operation_guard,
                    cohort_freeze: None,
                },
                deadline,
            )
            .await;
        match reply {
            ForwardMutationReply::Applied(response) => ForwardMutationReply::RecordExpiryPreflight(
                validate_committed_record_expiry_preflight(&preflights, &intent, &response),
            ),
            other => other,
        }
    }

    pub(crate) async fn commit_operator_recovery(
        &self,
        request_id: SessionConsensusRequestId,
        recovery_epoch: u64,
        plan_digest: [u8; 32],
        fence_high_water: u64,
        credential_high_water: u64,
    ) -> Result<(), OperatorRecoveryCommitError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or(OperatorRecoveryCommitError::Unavailable)?;
        self.require_durable_fixed_quorum_admission_before(deadline)
            .await
            .map_err(|_| OperatorRecoveryCommitError::Unavailable)?;
        if recovery_epoch == 0 {
            return Err(OperatorRecoveryCommitError::Rejected);
        }
        let metrics = self.inner.raft.metrics();
        if metrics.borrow().current_leader != Some(self.inner.local_node_id) {
            return Err(OperatorRecoveryCommitError::NotLocalLeader);
        }
        let reply = self
            .apply_on_local_leader_inner(
                ForwardMutationRequest {
                    request_id,
                    intent: SessionMutationIntent::FinalizeOperatorRecovery {
                        recovery_epoch,
                        plan_digest,
                        fence_high_water,
                        credential_high_water,
                    },
                    required_consumer_scope: ForwardConsumerScope::Internal,
                },
                self.inner.local_node_id,
                deadline,
                true,
                None,
            )
            .await;
        match reply {
            ForwardMutationReply::Applied(response) => match response.result {
                Ok(SessionMutationOutcome::Unit) => Ok(()),
                Err(StoreError::InvalidKey(reason))
                    if reason == "operator_recovery_epoch_rejected" =>
                {
                    Err(OperatorRecoveryCommitError::Rejected)
                }
                _ => Err(OperatorRecoveryCommitError::Unavailable),
            },
            ForwardMutationReply::NotLeader { .. } => {
                Err(OperatorRecoveryCommitError::NotLocalLeader)
            }
            ForwardMutationReply::OutcomeUnknown
            | ForwardMutationReply::Unavailable
            | ForwardMutationReply::RecordExpiryPreflight(_) => {
                Err(OperatorRecoveryCommitError::Unavailable)
            }
        }
    }

    pub(crate) async fn probe_operator_recovery_rejoin(
        &self,
        recovery_epoch: u64,
        plan_digest: [u8; 32],
    ) -> bool {
        let deadline = match tokio::time::Instant::now().checked_add(self.inner.operation_timeout) {
            Some(deadline) => deadline,
            None => return false,
        };
        if self
            .require_durable_fixed_quorum_admission_before(deadline)
            .await
            .is_err()
        {
            return false;
        }
        if !matches!(
            self.inner
                .linearizability
                .ensure_linearizable(deadline)
                .await,
            EnsureLinearizableOutcome::Ready { .. }
        ) {
            return false;
        }
        let committed = tokio::time::timeout_at(
            deadline,
            self.inner.backend.consensus_operator_recovery_committed(
                self.inner.storage_identity,
                recovery_epoch,
                plan_digest,
            ),
        )
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or(false);
        committed
            && self
                .require_durable_fixed_quorum_admission_before(deadline)
                .await
                .is_ok()
    }

    async fn wait_for_known_leader(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsensusNodeId, StoreError> {
        let mut metrics = self.inner.raft.metrics();
        loop {
            if let Some(leader) = metrics.borrow().current_leader {
                return Ok(leader);
            }
            match tokio::time::timeout_at(deadline, metrics.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    self.inner
                        .diagnostics
                        .route_metrics_watch_closed
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(consensus_unavailable());
                }
                Err(_) => {
                    self.inner
                        .diagnostics
                        .route_deadline
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(consensus_unavailable());
                }
            }
        }
    }

    async fn wait_for_route_refresh(
        &self,
        attempted_leader: SessionConsensusNodeId,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            self.inner
                .diagnostics
                .route_deadline
                .fetch_add(1, Ordering::Relaxed);
            return Err(consensus_unavailable());
        }
        let retry_deadline = now
            .checked_add(SESSION_CONSENSUS_ROUTE_RETRY_BACKOFF)
            .map_or(deadline, |candidate| candidate.min(deadline));
        let mut metrics = self.inner.raft.metrics();
        loop {
            if metrics.borrow().current_leader != Some(attempted_leader) {
                return Ok(());
            }
            match tokio::time::timeout_at(retry_deadline, metrics.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    self.inner
                        .diagnostics
                        .route_metrics_watch_closed
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(consensus_unavailable());
                }
                Err(_) if retry_deadline < deadline => return Ok(()),
                Err(_) => {
                    self.inner
                        .diagnostics
                        .route_deadline
                        .fetch_add(1, Ordering::Relaxed);
                    return Err(consensus_unavailable());
                }
            }
        }
    }

    async fn call_peer<Req, Resp>(
        &self,
        target: SessionConsensusNodeId,
        family: SessionConsensusRpcFamily,
        request: &Req,
        deadline: tokio::time::Instant,
    ) -> Result<Resp, ConsensusPeerCallFailure>
    where
        Req: Serialize + ?Sized,
        Resp: serde::de::DeserializeOwned,
    {
        let (identity, peer) = self
            .inner
            .peer_directory
            .resolve_application(target)
            .map_err(|_| ConsensusPeerCallFailure::BeforeTransmission)?;
        let payload =
            encode_bounded(request).map_err(|_| ConsensusPeerCallFailure::BeforeTransmission)?;
        let wire = SessionConsensusWireRequest::try_new(
            identity,
            self.inner.local_node_id,
            family,
            payload,
        )
        .map_err(|_| ConsensusPeerCallFailure::BeforeTransmission)?;
        let response = tokio::time::timeout_at(deadline, peer.call(wire))
            .await
            .map_err(|_| ConsensusPeerCallFailure::AfterTransmission)?
            .map_err(|_| ConsensusPeerCallFailure::AfterTransmission)?;
        response
            .validate()
            .map_err(|_| ConsensusPeerCallFailure::AfterTransmission)?;
        let payload = response
            .result
            .map_err(|_| ConsensusPeerCallFailure::AfterTransmission)?;
        decode_bounded(&payload).map_err(|_| ConsensusPeerCallFailure::AfterTransmission)
    }

    async fn local_read_barrier(&self, deadline: tokio::time::Instant) -> ReadBarrierReply {
        if self
            .require_durable_fixed_quorum_admission_before(deadline)
            .await
            .is_err()
        {
            return ReadBarrierReply::Unavailable;
        }
        match self.operator_recovery_pending_before(deadline).await {
            Ok(true) => return ReadBarrierReply::RecoveryRequired,
            Ok(false) => {}
            Err(_) => return ReadBarrierReply::Unavailable,
        }
        match self.inner.read_barrier.admit(deadline).await {
            Ok(admit) => {
                if self
                    .require_durable_fixed_quorum_admission_before(deadline)
                    .await
                    .is_err()
                {
                    return ReadBarrierReply::Unavailable;
                }
                match self.operator_recovery_pending_before(deadline).await {
                    Ok(false) => ReadBarrierReply::Ready(admit.read_log_id()),
                    Ok(true) => ReadBarrierReply::RecoveryRequired,
                    Err(_) => ReadBarrierReply::Unavailable,
                }
            }
            Err(LinearizableReadBarrierError::Unavailable) => ReadBarrierReply::Unavailable,
            Err(LinearizableReadBarrierError::NotLeader { leader }) => {
                ReadBarrierReply::NotLeader { leader }
            }
            _ => ReadBarrierReply::Unavailable,
        }
    }

    async fn linearizable_barrier_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<Option<LogId<SessionConsensusNodeId>>, LinearizableBarrierFailure> {
        self.require_durable_fixed_quorum_admission_before(deadline)
            .await
            .map_err(|_| LinearizableBarrierFailure::Unavailable)?;
        match self.operator_recovery_pending_before(deadline).await {
            Ok(false) => {}
            Ok(true) => return Err(LinearizableBarrierFailure::RecoveryRequired),
            Err(_) => return Err(LinearizableBarrierFailure::Unavailable),
        }
        let mut preferred = None;
        loop {
            let leader = match preferred.take() {
                Some(leader) => leader,
                None => self
                    .wait_for_known_leader(deadline)
                    .await
                    .map_err(|_| LinearizableBarrierFailure::Unavailable)?,
            };
            let reply = if leader == self.inner.local_node_id {
                self.local_read_barrier(deadline).await
            } else {
                match self
                    .call_peer::<_, ReadBarrierReply>(
                        leader,
                        SessionConsensusRpcFamily::ReadBarrier,
                        &ReadBarrierRequest,
                        deadline,
                    )
                    .await
                {
                    Ok(reply) => reply,
                    Err(_) => {
                        self.wait_for_route_refresh(leader, deadline)
                            .await
                            .map_err(|_| LinearizableBarrierFailure::Unavailable)?;
                        continue;
                    }
                }
            };
            match reply {
                ReadBarrierReply::Ready(log_id) => {
                    if let Some(log_id) = &log_id {
                        self.inner
                            .read_barrier
                            .wait_for_applied_index(log_id.index, deadline)
                            .await
                            .map_err(|_| LinearizableBarrierFailure::Unavailable)?;
                    }
                    self.require_durable_fixed_quorum_admission_before(deadline)
                        .await
                        .map_err(|_| LinearizableBarrierFailure::Unavailable)?;
                    match self.operator_recovery_pending_before(deadline).await {
                        Ok(false) => {}
                        Ok(true) => return Err(LinearizableBarrierFailure::RecoveryRequired),
                        Err(_) => return Err(LinearizableBarrierFailure::Unavailable),
                    }
                    return Ok(log_id);
                }
                ReadBarrierReply::RecoveryRequired => {
                    return Err(LinearizableBarrierFailure::RecoveryRequired);
                }
                ReadBarrierReply::NotLeader {
                    leader: next_leader,
                } => {
                    preferred = next_leader.filter(|candidate| {
                        *candidate != leader && self.is_current_member(*candidate)
                    });
                    if preferred.is_none() {
                        self.wait_for_route_refresh(leader, deadline)
                            .await
                            .map_err(|_| LinearizableBarrierFailure::Unavailable)?;
                    }
                }
                ReadBarrierReply::Unavailable => {
                    self.wait_for_route_refresh(leader, deadline)
                        .await
                        .map_err(|_| LinearizableBarrierFailure::Unavailable)?;
                }
            }
        }
    }

    async fn logical_read_time_before(
        &self,
        required_consumer_scope: Option<SessionConsensusIdentity>,
        deadline: tokio::time::Instant,
    ) -> Result<Timestamp, StoreError> {
        let logical_time = self
            .logical_read_time_before_without_post_authority(required_consumer_scope, deadline)
            .await?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        Ok(logical_time)
    }

    /// Commit and locally apply a logical-time fence without a second local
    /// authority snapshot.
    ///
    /// The `AdvanceLogicalTime` proposal is itself leader-fenced and accepts
    /// `required_consumer_scope` at the consensus boundary.  Consumer V2
    /// status uses this private variant only when its immediately following
    /// fixed-quorum SQLite transaction atomically rechecks authority and
    /// decides the returned status.  Public and generic callers retain the
    /// post-apply authority check in [`Self::logical_read_time_before`].
    async fn logical_read_time_before_without_post_authority(
        &self,
        required_consumer_scope: Option<SessionConsensusIdentity>,
        deadline: tokio::time::Instant,
    ) -> Result<Timestamp, StoreError> {
        let response = self
            .inner
            .logical_read_time
            .logical_read_time_before(required_consumer_scope, deadline)
            .await?;
        response.result?;
        if response.raft_log_index == 0 {
            return Err(consensus_unavailable());
        }
        self.inner
            .read_barrier
            .wait_for_applied_index(response.raft_log_index, deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
        response.logical_time.ok_or_else(consensus_unavailable)
    }

    /// Obtain one node-local exact-scope V2 status ticket, then wait until
    /// this ingress node has applied that committed position.  No authority,
    /// activation, recovery, or receipt result is carried across this step.
    async fn fenced_transition_v2_status_logical_time_ticket_before(
        &self,
        required_consumer_scope: SessionConsensusIdentity,
        deadline: tokio::time::Instant,
    ) -> Result<Timestamp, StoreError> {
        // Admit the caller's scope before it sends a ticket arrival anywhere.
        // The guard is intentionally released before leader routing: a queued
        // topology writer must not self-block the leader's proposal gate.
        let scope = SessionConsumerScope::new(required_consumer_scope);
        let admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        drop(admission);

        self.inner
            .diagnostics
            .status_ingress_requests
            .fetch_add(1, Ordering::Relaxed);
        match self
            .inner
            .fenced_transition_v2_status_logical_time_ingress
            .ticket_before(required_consumer_scope, deadline)
            .await?
        {
            FencedTransitionV2StatusLogicalTimeTicketReply::Ticket(ticket)
                if ticket.required_consumer_scope == required_consumer_scope =>
            {
                self.inner
                    .read_barrier
                    .wait_for_applied_index(ticket.raft_log_index, deadline)
                    .await
                    .map_err(|_| consensus_unavailable())?;
                Ok(ticket.logical_time)
            }
            FencedTransitionV2StatusLogicalTimeTicketReply::Ticket(_)
            | FencedTransitionV2StatusLogicalTimeTicketReply::NotLeader { .. }
            | FencedTransitionV2StatusLogicalTimeTicketReply::Unavailable => {
                Err(consensus_unavailable())
            }
            FencedTransitionV2StatusLogicalTimeTicketReply::Rejected(error) => Err(error),
        }
    }

    /// Dispatch the one frozen local status cohort representative.
    ///
    /// A resolved route, requested scope, and current local scope are all
    /// checked before the representative is frozen.  From the freeze onward
    /// it is deliberately single-shot: leader, scope, transport, or topology
    /// churn returns a fresh unavailable result rather than sending a second
    /// representative for the same local callers.
    async fn fenced_transition_v2_status_logical_time_ticket_representative(
        &self,
        required_consumer_scope: SessionConsensusIdentity,
        deadline: tokio::time::Instant,
        cohort_freeze: Arc<AtomicBool>,
    ) -> FencedTransitionV2StatusLogicalTimeTicketReply {
        if self
            .current_scope()
            .map_or(true, |(scope, _)| scope != required_consumer_scope)
        {
            return FencedTransitionV2StatusLogicalTimeTicketReply::Rejected(
                StoreError::TopologyAuthorityRevoked,
            );
        }
        let leader = match self.wait_for_known_leader(deadline).await {
            Ok(leader) if self.is_current_member(leader) => leader,
            _ => return FencedTransitionV2StatusLogicalTimeTicketReply::Unavailable,
        };
        if self
            .current_scope()
            .map_or(true, |(scope, _)| scope != required_consumer_scope)
        {
            return FencedTransitionV2StatusLogicalTimeTicketReply::Rejected(
                StoreError::TopologyAuthorityRevoked,
            );
        }

        // This is the node-local causal boundary.  No caller admitted after
        // this store can attach to the representative, even if its transport
        // or leader proposal later fails.
        self.inner
            .diagnostics
            .status_representatives
            .fetch_add(1, Ordering::Relaxed);
        cohort_freeze.store(true, Ordering::Release);
        if leader == self.inner.local_node_id {
            // This enters the distinct leader-owned cohort rather than this
            // ingress supervisor, so local leadership never recurses.
            return self
                .fenced_transition_v2_status_logical_time_ticket_on_local_leader(
                    required_consumer_scope,
                    deadline,
                )
                .await;
        }

        match self
            .call_peer::<_, FencedTransitionV2StatusLogicalTimeTicketReply>(
                leader,
                SessionConsensusRpcFamily::ForwardMutation,
                &ForwardRequest::FencedTransitionV2StatusLogicalTimeTicket {
                    required_consumer_scope: Box::new(required_consumer_scope),
                },
                deadline,
            )
            .await
        {
            Ok(reply) => reply,
            // A peer may have accepted this one representative.  Never reroute
            // the frozen cohort or retain a ticket/authority cache to make a
            // subsequent attempt appear safe.
            Err(ConsensusPeerCallFailure::BeforeTransmission)
            | Err(ConsensusPeerCallFailure::AfterTransmission) => {
                FencedTransitionV2StatusLogicalTimeTicketReply::Unavailable
            }
        }
    }

    /// Admit one exact-scope arrival to this node's leader supervisor.  The
    /// service handler invokes this only after envelope sender/scope binding;
    /// this fresh local check binds the payload's requested scope as well.
    async fn fenced_transition_v2_status_logical_time_ticket_on_local_leader(
        &self,
        required_consumer_scope: SessionConsensusIdentity,
        deadline: tokio::time::Instant,
    ) -> FencedTransitionV2StatusLogicalTimeTicketReply {
        if self
            .current_scope()
            .map_or(true, |(scope, _)| scope != required_consumer_scope)
        {
            return FencedTransitionV2StatusLogicalTimeTicketReply::Rejected(
                StoreError::TopologyAuthorityRevoked,
            );
        }
        self.inner
            .diagnostics
            .status_leader_cohort_requests
            .fetch_add(1, Ordering::Relaxed);
        match self
            .inner
            .fenced_transition_v2_status_logical_time
            .ticket_before(required_consumer_scope, deadline)
            .await
        {
            Ok(reply) => reply,
            Err(_) => FencedTransitionV2StatusLogicalTimeTicketReply::Unavailable,
        }
    }

    async fn logical_read_time(&self) -> Result<Timestamp, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.logical_read_time_before(None, deadline).await
    }

    async fn consumer_preflight_record_expiry(
        &self,
        scope: SessionConsumerScope,
        preflights: &[RecordExpiryPreflight],
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        validate_record_expiry_preflights_profile(preflights)?;
        if !preflights
            .iter()
            .copied()
            .any(RecordExpiryPreflight::is_finite)
        {
            return Ok(());
        }
        self.preflight_record_expiry_before(preflights, Some(scope.consensus_identity()), deadline)
            .await
    }

    async fn consumer_get(
        &self,
        scope: SessionConsumerScope,
        key: &SessionKey,
        deadline: tokio::time::Instant,
    ) -> Result<Option<StoredSessionRecord>, StoreError> {
        let logical_time = self
            .logical_read_time_before(Some(scope.consensus_identity()), deadline)
            .await?;
        // `logical_read_time_before` submits a consensus command and owns its
        // own leader-side topology gate. Acquire the local read gate only
        // after that command has settled; retaining it across the submission
        // can self-block behind a queued topology writer on Tokio's fair lock.
        let _admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        let record = self
            .inner
            .backend
            .consensus_get_at(key, logical_time)
            .await?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        Ok(record)
    }

    async fn consumer_fenced_transition_capability(
        &self,
        scope: SessionConsumerScope,
        deadline: tokio::time::Instant,
    ) -> Result<AtomicFencedTransitionCapability, StoreError> {
        // Scope admission is intentionally repeated around the fresh
        // unanimous exact-voter probe. A capability answer must not be reused after an
        // authority rollover, even though its receipt IDs deliberately survive
        // one.
        let admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        drop(admission);
        let capability = self
            .require_fenced_transition_capability_before(deadline)
            .await
            .map(|_| AtomicFencedTransitionCapability::V1)?;
        let admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        drop(admission);
        Ok(capability)
    }

    async fn consumer_observe_fenced_transition(
        &self,
        scope: SessionConsumerScope,
        key: &SessionKey,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionObservation, StoreError> {
        let admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        drop(admission);
        self.require_fenced_transition_capability_before(deadline)
            .await?;
        let logical_time = self
            .logical_read_time_before(Some(scope.consensus_identity()), deadline)
            .await?;
        // Retain the exact-scope gate through the final authority check so a
        // topology writer cannot roll authority between the durable read and
        // the successful consumer response.
        let _admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        let observation = self
            .inner
            .backend
            .consensus_observe_fenced_transition_at(key, logical_time)
            .await?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        Ok(observation)
    }

    async fn consumer_fenced_transition(
        &self,
        scope: SessionConsumerScope,
        request: FencedTransitionRequest,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionOutcome, StoreError> {
        request.validate()?;
        if let Some(record) = request.mutation().record() {
            crate::sqlite::validate_consensus_record(record)?;
        }
        self.consumer_fenced_transition_capability(scope, deadline)
            .await?;
        // Unlike legacy consumer mutations this does not submit a separate
        // BindConsumerRequest marker. The transition's durable receipt binds
        // its complete body at the same single consensus position as lease and
        // record effects.
        let request_id = SessionConsensusRequestId::from_bytes(*request.request_id().as_bytes());
        let response = self
            .submit_request_before(
                request_id,
                SessionMutationIntent::FencedTransition(Box::new(request)),
                Some(scope.consensus_identity()),
                deadline,
            )
            .await?;
        match response.result? {
            SessionMutationOutcome::FencedTransition(outcome) => Ok(outcome),
            _ => Err(StoreError::FencedTransitionOutcomeUnknown),
        }
    }

    async fn consumer_fenced_transition_status(
        &self,
        scope: SessionConsumerScope,
        request: &FencedTransitionRequest,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionStatus, StoreError> {
        request.validate()?;
        let admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        drop(admission);
        self.require_fenced_transition_capability_before(deadline)
            .await?;
        self.logical_read_time_before(Some(scope.consensus_identity()), deadline)
            .await?;
        // Retain the exact-scope gate through the final authority check so a
        // topology writer cannot roll authority between the durable status
        // lookup and the successful consumer response.
        let _admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        let status = self
            .inner
            .backend
            .consensus_fenced_transition_status(
                self.inner.storage_identity,
                scope.consensus_identity(),
                request,
            )
            .await?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        Ok(status)
    }

    /// Re-admit an exact consumer scope before an exceptional read response
    /// that has no later atomic acceptance transaction of its own.
    async fn consumer_scope_before_response(
        &self,
        scope: SessionConsumerScope,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        let admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        drop(admission);
        Ok(())
    }

    /// Resolve one V2 status under the consumer's exact fixed-quorum scope.
    ///
    /// A committed `AdvanceLogicalTime` is the required consensus fence, so
    /// this path deliberately does not pay the generic capability helper's
    /// independent read barrier.  Once the time command is applied, one
    /// scope-held SQLite transaction accepts immutable authority, recovery,
    /// activation evidence, and the status together.  A missing activation
    /// certificate follows the existing one-shot unanimous proof path and
    /// repeats that same atomic acceptance read; the warm certified path does
    /// not probe peers or cache authority.
    async fn consumer_fenced_transition_v2_status(
        &self,
        scope: SessionConsumerScope,
        request: &FencedTransitionV2Request,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionV2Status, StoreError> {
        if let Err(error) = request.validate() {
            return if matches!(error, StoreError::FencedTransitionRequestConflict) {
                self.consumer_scope_before_response(scope, deadline).await?;
                Ok(FencedTransitionV2Status::RequestConflict)
            } else {
                Err(error)
            };
        }
        if self.local_fenced_transition_v2_capability() != Some(FencedTransitionV2Capability::V2) {
            self.consumer_scope_before_response(scope, deadline).await?;
            return Err(unsupported_fenced_transition_v2());
        }
        let profile_digest = crate::fenced_transition::fenced_transition_v2_profile_digest();
        let placement_policy = self
            .inner
            .topology
            .fixed_durable_placement_policy()
            .ok_or_else(consensus_unavailable)?;
        self.inner
            .diagnostics
            .status_local_requests
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .fenced_transition_v2_status_batch
            .status_before(
                scope.consensus_identity(),
                profile_digest,
                placement_policy,
                request.clone(),
                deadline,
            )
            .await
    }

    /// Resolve one frozen local V2 status cohort after its shared logical-time
    /// ticket has applied.  Every request is evaluated in ordered form by one
    /// backend read snapshot; no result is used after this call returns.
    async fn fenced_transition_v2_status_batch_at_scope(
        &self,
        key: FencedTransitionV2StatusBatchKey,
        requests: Vec<FencedTransitionV2Request>,
        deadline: tokio::time::Instant,
    ) -> Result<Vec<FencedTransitionV2Status>, StoreError> {
        self.fenced_transition_v2_status_logical_time_ticket_before(key.scope, deadline)
            .await?;

        // The post-proposal admission holds the local topology gate through
        // the atomic acceptance read. It is intentionally acquired only after
        // the leader-owned proposal has settled, so a waiting topology writer
        // cannot deadlock the proposal behind Tokio's fair RwLock.
        let admission = self
            .admit_consumer_scope(SessionConsumerScope::new(key.scope), deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        let (scope_identity, voters) = self.current_scope()?;
        if admission.required_scope != scope_identity {
            return Err(StoreError::TopologyAuthorityRevoked);
        }
        let first_read = self
            .inner
            .backend
            .fixed_quorum_fenced_transition_v2_status_batch_at_scope(
                crate::sqlite::FixedQuorumFencedTransitionV2StatusReadRequest {
                    storage_identity: self.inner.storage_identity,
                    scope_identity,
                    voters,
                    expected_members: self.inner.bootstrap_members.clone(),
                    expected_bindings: self.inner.bootstrap_bindings.clone(),
                    expected_placement_policy: key.placement_policy,
                    profile_digest: key.profile_digest,
                    require_activation: true,
                },
                requests.clone(),
            )
            .await?;
        match first_read {
            crate::sqlite::FixedQuorumFencedTransitionV2StatusBatchRead::Activated(statuses) => {
                // Keep `admission` through the response acceptance boundary.
                Ok(statuses)
            }
            crate::sqlite::FixedQuorumFencedTransitionV2StatusBatchRead::Unactivated => {
                // The normal warm path above never reaches here. Do not hold
                // the topology gate across fresh network probes; the helper
                // checks the exact scope both before and after them, then the
                // final atomic read below reacquires this same post guard.
                drop(admission);
                self.require_fenced_transition_v2_capability_after_barrier(deadline)
                    .await?;
                let admission = self
                    .admit_consumer_scope(SessionConsumerScope::new(key.scope), deadline)
                    .await
                    .map_err(|rejection| match rejection {
                        SessionConsumerRejection::ScopeMismatch => {
                            StoreError::TopologyAuthorityRevoked
                        }
                        _ => consensus_unavailable(),
                    })?;
                let (scope_identity, voters) = self.current_scope()?;
                if admission.required_scope != scope_identity {
                    return Err(StoreError::TopologyAuthorityRevoked);
                }
                match self
                    .inner
                    .backend
                    .fixed_quorum_fenced_transition_v2_status_batch_at_scope(
                        crate::sqlite::FixedQuorumFencedTransitionV2StatusReadRequest {
                            storage_identity: self.inner.storage_identity,
                            scope_identity,
                            voters,
                            expected_members: self.inner.bootstrap_members.clone(),
                            expected_bindings: self.inner.bootstrap_bindings.clone(),
                            expected_placement_policy: key.placement_policy,
                            profile_digest: key.profile_digest,
                            require_activation: false,
                        },
                        requests,
                    )
                    .await?
                {
                    crate::sqlite::FixedQuorumFencedTransitionV2StatusBatchRead::Activated(
                        statuses,
                    ) => {
                        // Keep `admission` through the response acceptance boundary.
                        Ok(statuses)
                    }
                    crate::sqlite::FixedQuorumFencedTransitionV2StatusBatchRead::Unactivated => {
                        Err(consensus_unavailable())
                    }
                }
            }
        }
    }

    async fn consumer_scan_restore_records(
        &self,
        scope: SessionConsumerScope,
        request: RestoreScanRequest,
        deadline: tokio::time::Instant,
    ) -> Result<RestoreScanPage, StoreError> {
        request.validate()?;
        let logical_time = tokio::time::timeout_at(
            deadline,
            self.logical_read_time_before(Some(scope.consensus_identity()), deadline),
        )
        .await
        .map_err(|_| StoreError::RestoreScanWorkBudgetExceeded)??;
        let _admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        let page = self
            .inner
            .backend
            .consensus_scan_restore_records_at(request, logical_time, deadline)
            .await?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        Ok(page)
    }

    async fn consumer_watch(
        &self,
        scope: SessionConsumerScope,
        start_sequence: u64,
        deadline: tokio::time::Instant,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        StoreError,
    > {
        self.logical_read_time_before(Some(scope.consensus_identity()), deadline)
            .await?;
        let admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        let stream = self
            .inner
            .backend
            .consensus_consumer_watch(start_sequence)
            .await?;
        let store = self.clone();
        let scope = SessionConsumerScope::new(admission.required_scope);
        drop(admission);
        Ok(futures_util::stream::unfold(
            (stream, store, scope),
            |(mut stream, store, scope)| async move {
                loop {
                    let entry = if store.inner.topology.mode()
                        == QuorumTopologyMode::FixedDurableQuorum
                    {
                        tokio::select! {
                            entry = stream.next() => entry?,
                            _ = tokio::time::sleep(CONSUMER_WATCH_SCOPE_RECHECK_INTERVAL) => {
                                let deadline = tokio::time::Instant::now()
                                    .checked_add(store.inner.operation_timeout)?;
                                if store.fixed_watch_authority_before(deadline).await.is_err()
                                    || store.admit_consumer_scope(scope, deadline).await.is_err()
                                {
                                    return None;
                                }
                                continue;
                            }
                        }
                    } else {
                        stream.next().await?
                    };
                    let deadline =
                        tokio::time::Instant::now().checked_add(store.inner.operation_timeout)?;
                    if store.fixed_watch_authority_before(deadline).await.is_err()
                        || store.admit_consumer_scope(scope, deadline).await.is_err()
                    {
                        return None;
                    }
                    return Some((
                        entry.map_err(SessionConsumerStoreError::from),
                        (stream, store, scope),
                    ));
                }
            },
        )
        .boxed())
    }
}

/// Classify a delayed V2 request before a fresh activation proposal carries it
/// into a successor scope. The retired floor is terminal; the bounded
/// contiguous interval below the active epoch is closed to new identities but
/// remains eligible for exact replay.
fn local_fenced_transition_v2_capability_for_backend_capabilities(
    capabilities: BackendCapabilities,
    consensus_schema_version: u16,
    rpc_payload_capacity: usize,
    durable_log_entry_capacity: usize,
) -> Option<FencedTransitionV2Capability> {
    // V2's record-envelope and command-transport limits are hashed into the
    // immutable V2 validation profile. This check deliberately precedes every
    // local V2 advertisement, probe acknowledgement, and activation path.
    if capabilities.atomic_compare_and_set
        && capabilities.monotonic_fencing_token
        && capabilities.per_key_ttl
        && capabilities.server_side_lease_expiry
        && capabilities.max_value_bytes == FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES
        && consensus_schema_version == FENCED_TRANSITION_V2_CONSENSUS_SCHEMA_VERSION
        && rpc_payload_capacity >= FENCED_TRANSITION_V2_MIN_CONSENSUS_RPC_PAYLOAD_BYTES
        && durable_log_entry_capacity >= FENCED_TRANSITION_V2_MIN_DURABLE_LOG_ENTRY_BYTES
    {
        Some(FencedTransitionV2Capability::V2)
    } else {
        // The separate V1 capability/probe remains available through
        // `fenced_transition_capability`, but this V2-only profile is not
        // advertised when any exact input does not match.
        None
    }
}

fn classify_fresh_v2_history_epoch(
    history: &FencedTransitionV2HistoryState,
    request_epoch: FencedTransitionV2HistoryEpoch,
) -> Result<(), StoreError> {
    if history
        .retired_through()
        .is_some_and(|floor| request_epoch <= floor)
    {
        return Err(StoreError::FencedTransitionHistoryEpochRetired);
    }
    match history.active_epoch() {
        Some(active) if request_epoch == active => Ok(()),
        Some(active) if request_epoch < active => Ok(()),
        _ => Err(StoreError::FencedTransitionHistoryEpochNotActive),
    }
}

/// Batch commands may only target the exact currently active V2 history
/// epoch.  Unlike singleton status/replay handling, coalescing does not turn
/// an older retained identity into a fresh batch slot.
fn require_fenced_transition_v2_batch_active_epoch(
    history: &FencedTransitionV2HistoryState,
    request_epoch: FencedTransitionV2HistoryEpoch,
) -> Result<(), StoreError> {
    if history
        .retired_through()
        .is_some_and(|floor| request_epoch <= floor)
    {
        return Err(StoreError::FencedTransitionHistoryEpochRetired);
    }
    if history.active_epoch() != Some(request_epoch) {
        return Err(StoreError::FencedTransitionHistoryEpochNotActive);
    }
    Ok(())
}

fn session_raft_config() -> Result<opc_consensus::engine::Config, ConsensusSessionStoreOpenError> {
    durable_openraft_config(DurableOpenraftDomain::SessionState)
        .map_err(|_| ConsensusSessionStoreOpenError::InvalidRuntimeConfiguration)
}

fn consensus_unavailable() -> StoreError {
    StoreError::BackendUnavailable("session consensus quorum is unavailable".into())
}

fn unsupported_fenced_transition() -> StoreError {
    StoreError::CapabilityNotSupported("atomic_fenced_transition_v1".into())
}

fn unsupported_fenced_transition_v2() -> StoreError {
    StoreError::CapabilityNotSupported("atomic_fenced_transition_epoch_history_v2".into())
}

/// Raw V2 mutations immediately run the stronger V2 capability admission in
/// `apply_on_local_leader_inner`, so they must not also queue a generic
/// linearizable read. Recovery and all proof-carrying/internal forms retain
/// the generic admission path.
fn is_raw_fenced_transition_v2_mutation(
    intent: &SessionMutationIntent,
    allow_operator_recovery: bool,
) -> bool {
    !allow_operator_recovery
        && matches!(
            intent,
            SessionMutationIntent::FencedTransitionV2(_)
                | SessionMutationIntent::FencedTransitionV2Batch(_)
        )
}

fn requires_generic_leader_admission(
    intent: &SessionMutationIntent,
    allow_operator_recovery: bool,
) -> bool {
    !is_raw_fenced_transition_v2_mutation(intent, allow_operator_recovery)
}

fn fenced_transition_v2_capability_failure_reply(error: StoreError) -> ForwardMutationReply {
    if matches!(
        error,
        StoreError::CapabilityNotSupported(ref reason)
            if reason == "atomic_fenced_transition_epoch_history_v2"
    ) {
        return ForwardMutationReply::Applied(Box::new(SessionConsensusResponse::rejected(
            unsupported_fenced_transition_v2(),
        )));
    }

    // An activated cluster can temporarily miss the shared operation deadline
    // while rechecking its linearizable certificate under load. That is
    // availability, not evidence that a voter implements a different V2
    // profile. Fail before proposal without converting the transient condition
    // into a definitive unsupported-capability result.
    ForwardMutationReply::Unavailable
}

type FencedTransitionActivationScope<'a> = (
    &'a SessionConsensusIdentity,
    &'a [u8; 32],
    Option<&'a [u8; 32]>,
);

/// Extract the replicated activation binding without ever conflating V1 and
/// V2. `None` for the profile is V1's frozen wire shape.
fn fenced_transition_activation_scope(
    intent: &SessionMutationIntent,
) -> Option<FencedTransitionActivationScope<'_>> {
    match intent {
        SessionMutationIntent::ActivateFencedTransition {
            scope_identity,
            voter_set_digest,
            ..
        } => Some((scope_identity, voter_set_digest, None)),
        SessionMutationIntent::ActivateFencedTransitionV2 {
            scope_identity,
            voter_set_digest,
            profile_digest,
            ..
        } => Some((scope_identity, voter_set_digest, Some(profile_digest))),
        _ => None,
    }
}

fn consensus_outcome_unavailable(intent: &SessionMutationIntent) -> StoreError {
    match intent {
        SessionMutationIntent::CompareAndSet(_) => StoreError::CasIdempotencyOutcomeUnavailable,
        SessionMutationIntent::FencedTransition(_)
        | SessionMutationIntent::ActivateFencedTransition { .. }
        | SessionMutationIntent::FencedTransitionV2(_)
        | SessionMutationIntent::FencedTransitionV2Batch(_)
        | SessionMutationIntent::ActivateFencedTransitionV2 { .. } => {
            StoreError::FencedTransitionOutcomeUnknown
        }
        _ => StoreError::BackendOperationOutcomeUnavailable,
    }
}

/// Protected and consumer-scoped mutations expose exact status resolution and
/// must never be automatically replayed after a possibly transmitted write.
fn mutation_requires_exact_status_resolution(request: &ForwardMutationRequest) -> bool {
    request.required_consumer_scope.is_consumer_scoped()
        || matches!(
            &request.intent,
            SessionMutationIntent::FencedTransition(_)
                | SessionMutationIntent::FencedTransitionV2(_)
                | SessionMutationIntent::FencedTransitionV2Batch(_)
                | SessionMutationIntent::ActivateFencedTransitionV2 { .. }
        )
}

/// Openraft can return `ForwardToLeader` from a `client_write_ff` receiver
/// before appending the command. Generic requests may safely reroute their
/// stable request ID; protected/status-resolved requests remain ambiguous.
fn client_write_receiver_error_reply(
    error: ClientWriteError<SessionConsensusNodeId, EmptyNode>,
    reroute_forward_to_leader: bool,
) -> ForwardMutationReply {
    match error {
        ClientWriteError::ForwardToLeader(forward) if reroute_forward_to_leader => {
            ForwardMutationReply::NotLeader {
                leader: forward.leader_id,
            }
        }
        ClientWriteError::ForwardToLeader(_) | ClientWriteError::ChangeMembershipError(_) => {
            ForwardMutationReply::OutcomeUnknown
        }
    }
}

fn accepted_client_write_receiver_failure_effect() -> ConsensusSubmissionEffect {
    ConsensusSubmissionEffect::OutcomeUnknown
}

fn validate_committed_record_expiry_preflight(
    preflights: &[RecordExpiryPreflight],
    intent: &SessionMutationIntent,
    response: &SessionConsensusResponse,
) -> Result<(), StoreError> {
    if !committed_response_matches_intent(intent, response)
        || !matches!(&response.result, Ok(SessionMutationOutcome::Unit))
    {
        return Err(consensus_unavailable());
    }
    let committed_logical_time = response.logical_time.ok_or_else(consensus_unavailable)?;
    validate_record_expiry_preflights_at(preflights, committed_logical_time)
}

fn committed_response_matches_intent(
    intent: &SessionMutationIntent,
    response: &SessionConsensusResponse,
) -> bool {
    // Retention exhaustion is an absorbing replay-style no-effect result. It
    // can be the first application command, so its committed response may
    // legitimately retain the genesis application sequence while still
    // carrying the committed logical-time, digest, and Raft position. A stale
    // authority at that same horizon is deliberately masked as authority
    // revocation without changing those no-effect sequence semantics.
    let genesis_safe_fenced_rejection = matches!(
        (&response.result, intent),
        (
            Err(StoreError::FencedTransitionRetentionExhausted
                | StoreError::TopologyAuthorityRevoked),
            SessionMutationIntent::FencedTransition(_)
                | SessionMutationIntent::ActivateFencedTransition { .. }
                | SessionMutationIntent::FencedTransitionV2(_)
                | SessionMutationIntent::FencedTransitionV2Batch(_)
                | SessionMutationIntent::ActivateFencedTransitionV2 { .. }
        ) | (
            Err(StoreError::FencedTransitionHistoryEpochNotActive),
            SessionMutationIntent::FencedTransitionV2(_)
                | SessionMutationIntent::ActivateFencedTransitionV2 { .. }
        )
    );
    if (!genesis_safe_fenced_rejection && response.sequence == 0)
        || response.digest.is_none()
        || response.logical_time.is_none()
        || response.raft_log_index == 0
    {
        return false;
    }
    let Some(logical_time) = response.logical_time else {
        return false;
    };
    if let Ok(outcome) = &response.result {
        if crate::sqlite::consensus::validate_consensus_outcome_records(outcome).is_err() {
            return false;
        }
    }
    match (&response.result, intent) {
        (Err(error), intent) => committed_error_matches_intent(intent, error),
        (Ok(SessionMutationOutcome::Unit), SessionMutationIntent::AdvanceLogicalTime)
        | (Ok(SessionMutationOutcome::Unit), SessionMutationIntent::BindConsumerRequest { .. })
        | (Ok(SessionMutationOutcome::Unit), SessionMutationIntent::DeleteFenced(_))
        | (Ok(SessionMutationOutcome::Unit), SessionMutationIntent::RefreshTtl { .. })
        | (Ok(SessionMutationOutcome::Unit), SessionMutationIntent::ReleaseLease(_))
        | (
            Ok(SessionMutationOutcome::Unit),
            SessionMutationIntent::FinalizeOperatorRecovery { .. },
        )
        | (
            Ok(SessionMutationOutcome::Unit),
            SessionMutationIntent::MaintainFencedTransitionV2History { .. },
        ) => true,
        (
            Ok(SessionMutationOutcome::ConsumerRecord(record)),
            SessionMutationIntent::ReadConsumerRecord { key },
        ) => record.as_ref().is_none_or(|record| record.key == *key),
        (
            Ok(SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Success)),
            SessionMutationIntent::CompareAndSet(_),
        )
        | (
            Ok(SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Conflict {
                current: None,
            })),
            SessionMutationIntent::CompareAndSet(_),
        ) => true,
        (
            Ok(SessionMutationOutcome::CompareAndSet(CompareAndSetResult::Conflict {
                current: Some(current),
            })),
            SessionMutationIntent::CompareAndSet(operation),
        ) => current.key == operation.key,
        (
            Ok(SessionMutationOutcome::Lease(guard)),
            SessionMutationIntent::AcquireLease {
                key, owner, ttl, ..
            },
        ) => {
            guard.key() == key
                && guard.owner() == owner
                && guard.fence().get() != 0
                && guard.credential_id() != 0
                && guard.acquired_at() == logical_time
                && checked_session_deadline(logical_time, *ttl)
                    .is_ok_and(|expires_at| guard.expires_at() == expires_at)
        }
        (
            Ok(SessionMutationOutcome::Lease(renewed)),
            SessionMutationIntent::RenewLease { lease, ttl },
        ) => {
            renewed.key() == lease.key()
                && renewed.owner() == lease.owner()
                && renewed.fence() == lease.fence()
                && renewed.credential_id() == lease.credential_id()
                && renewed.acquired_at() == lease.acquired_at()
                && checked_session_deadline(logical_time, *ttl)
                    .is_ok_and(|expires_at| renewed.expires_at() == expires_at)
        }
        (
            Ok(SessionMutationOutcome::FencedTransition(outcome)),
            SessionMutationIntent::FencedTransition(request),
        ) => fenced_transition_outcome_matches_request(request, outcome, logical_time),
        (
            Ok(SessionMutationOutcome::FencedTransition(outcome)),
            SessionMutationIntent::FencedTransitionV2(request)
            | SessionMutationIntent::ActivateFencedTransitionV2 { request, .. },
        ) => fenced_transition_v2_outcome_matches_request(request, outcome, logical_time),
        (
            Ok(SessionMutationOutcome::FencedTransitionV2Batch(outcomes)),
            SessionMutationIntent::FencedTransitionV2Batch(requests),
        ) => fenced_transition_v2_batch_outcomes_match_requests(requests, outcomes, logical_time),
        _ => false,
    }
}

fn fenced_transition_outcome_matches_request(
    request: &FencedTransitionRequest,
    outcome: &FencedTransitionOutcome,
    logical_time: Timestamp,
) -> bool {
    outcome.matches_request_at(request, logical_time)
}

fn fenced_transition_v2_outcome_matches_request(
    request: &FencedTransitionV2Request,
    outcome: &FencedTransitionOutcome,
    logical_time: Timestamp,
) -> bool {
    // Keep one complete matcher for V2. Besides its full self-authenticating
    // identity, it validates the credential and acquisition-time details
    // that a hand-written partial match can accidentally omit.
    outcome.recorded_at() == logical_time && outcome.matches_v2_request(request)
}

fn fenced_transition_v2_batch_outcomes_match_requests(
    requests: &[FencedTransitionV2Request],
    outcomes: &[Result<FencedTransitionOutcome, StoreError>],
    logical_time: Timestamp,
) -> bool {
    super::types::validate_fenced_transition_v2_batch_outcomes(outcomes).is_ok()
        && requests.len() == outcomes.len()
        && requests
            .iter()
            .zip(outcomes)
            .all(|(request, outcome)| match outcome {
                // A batch envelope can contain an exact retained replay
                // alongside fresh work. The replay keeps its original
                // profiled timestamp, which must not be later than this
                // committed batch envelope.
                Ok(outcome) => {
                    outcome.recorded_at() <= logical_time && outcome.matches_v2_request(request)
                }
                Err(error) => committed_error_matches_intent(
                    &SessionMutationIntent::FencedTransitionV2(Box::new(request.clone())),
                    error,
                ),
            })
}

/// Project a committed V2 batch envelope into its caller-visible effect only
/// after proving that it carries every submitted item's validated result.
///
/// An outer committed envelope or a deterministic error alone cannot resolve
/// a batch: callers retain one independent status ID per item.  In the fresh
/// activation path, `activation_outcome` supplies the first item and this
/// response must still prove the complete suffix before the combined batch is
/// resolved.
fn committed_fenced_transition_v2_batch_effect(
    original_request_ids: &[crate::FencedTransitionV2RequestId],
    requests: &[FencedTransitionV2Request],
    activation_outcome: Option<Result<FencedTransitionOutcome, StoreError>>,
    response: SessionConsensusResponse,
) -> FencedTransitionV2Effect<Result<Vec<Result<FencedTransitionOutcome, StoreError>>, StoreError>>
{
    let unknown = || FencedTransitionV2Effect::OutcomeUnknown {
        request_ids: original_request_ids.to_vec(),
    };
    let intent = SessionMutationIntent::FencedTransitionV2Batch(requests.to_vec());
    if !committed_response_matches_intent(&intent, &response) {
        return unknown();
    }
    let Ok(SessionMutationOutcome::FencedTransitionV2Batch(mut outcomes)) = response.result else {
        return unknown();
    };
    if let Some(outcome) = activation_outcome {
        outcomes.insert(0, outcome);
    }
    FencedTransitionV2Effect::Resolved(Ok(outcomes))
}

/// A fresh activation is the first item of a caller's V2 batch. Its committed
/// deterministic error is a complete result only for a singleton caller; a
/// nonempty suffix has independent retained IDs and is therefore ambiguous.
fn committed_fenced_transition_v2_activation_result(
    request: &FencedTransitionV2Request,
    has_suffix: bool,
    response: SessionConsensusResponse,
) -> Option<Result<FencedTransitionOutcome, StoreError>> {
    let intent = SessionMutationIntent::FencedTransitionV2(Box::new(request.clone()));
    if !committed_response_matches_intent(&intent, &response) {
        return None;
    }
    match response.result {
        Ok(SessionMutationOutcome::FencedTransition(outcome)) => Some(Ok(outcome)),
        Err(error) if !has_suffix => Some(Err(error)),
        Err(_) | Ok(_) => None,
    }
}

fn rejected_response_matches_intent(
    intent: &SessionMutationIntent,
    response: &SessionConsensusResponse,
) -> bool {
    // The original private forwarding wire shape does not echo the request ID.
    // Keep the existing private wire discriminants stable, but accept a rejection as
    // preproposal only when it carries the sentinel non-committed metadata and
    // the error is one this exact intent can encounter before submission.
    response.sequence == 0
        && response.digest.is_none()
        && response.logical_time.is_none()
        && response.raft_log_index == 0
        && matches!(
            &response.result,
            Err(error) if rejected_error_matches_intent(intent, error)
        )
}

fn rejected_error_matches_intent(intent: &SessionMutationIntent, error: &StoreError) -> bool {
    // Normal callers validate intent before routing. The only remaining
    // preproposal rejection is the fixed bounded-command encoding limit.
    matches!(error, StoreError::PayloadTooLarge { .. })
        || matches!(
            (intent, error),
            (
                SessionMutationIntent::CompareAndSet(_),
                StoreError::InvalidRecordExpiry
            )
        )
        || matches!(
            (intent, error),
            (
                SessionMutationIntent::FencedTransitionV2(_)
                    | SessionMutationIntent::FencedTransitionV2Batch(_)
                    | SessionMutationIntent::ActivateFencedTransitionV2 { .. },
                StoreError::CapabilityNotSupported(reason)
            ) if reason == "atomic_fenced_transition_epoch_history_v2"
        )
        || matches!(
            (intent, error),
            (
                SessionMutationIntent::FencedTransition(_),
                StoreError::CapabilityNotSupported(reason)
            ) if reason == "atomic_fenced_transition_v1"
        )
}

fn committed_error_matches_intent(intent: &SessionMutationIntent, error: &StoreError) -> bool {
    // Application-authority revocation is a deterministic committed outcome
    // for every user mutation. The response is matched against the original
    // unwrapped intent, not the state-machine-only `Authorized` envelope.
    if matches!(error, StoreError::TopologyAuthorityRevoked) {
        return matches!(
            intent,
            SessionMutationIntent::CompareAndSet(_)
                | SessionMutationIntent::DeleteFenced(_)
                | SessionMutationIntent::RefreshTtl { .. }
                | SessionMutationIntent::AcquireLease { .. }
                | SessionMutationIntent::RenewLease { .. }
                | SessionMutationIntent::ReleaseLease(_)
                | SessionMutationIntent::ReadConsumerRecord { .. }
                | SessionMutationIntent::FencedTransition(_)
                | SessionMutationIntent::ActivateFencedTransition { .. }
                | SessionMutationIntent::FencedTransitionV2(_)
                | SessionMutationIntent::FencedTransitionV2Batch(_)
                | SessionMutationIntent::ActivateFencedTransitionV2 { .. }
        );
    }
    match intent {
        SessionMutationIntent::AdvanceLogicalTime => false,
        SessionMutationIntent::BindConsumerRequest { .. } => {
            matches!(error, StoreError::CasIdempotencyConflict)
        }
        SessionMutationIntent::ReadConsumerRecord { .. } => false,
        SessionMutationIntent::CompareAndSet(_) => matches!(
            error,
            StoreError::NotFound
                | StoreError::StaleFence
                | StoreError::InvalidKey(_)
                | StoreError::LeaseExpired
                | StoreError::InvalidRecordExpiry
                | StoreError::PayloadTooLarge { .. }
        ),
        SessionMutationIntent::DeleteFenced(_) => matches!(
            error,
            StoreError::NotFound | StoreError::StaleFence | StoreError::LeaseExpired
        ),
        SessionMutationIntent::RefreshTtl { .. } => matches!(
            error,
            StoreError::NotFound
                | StoreError::StaleFence
                | StoreError::InvalidSessionTtl
                | StoreError::LeaseExpired
        ),
        SessionMutationIntent::AcquireLease { .. } => {
            matches!(error, StoreError::InvalidSessionTtl | StoreError::LeaseHeld)
        }
        SessionMutationIntent::RenewLease { .. } => matches!(
            error,
            StoreError::NotFound
                | StoreError::StaleFence
                | StoreError::InvalidSessionTtl
                | StoreError::LeaseHeld
                | StoreError::LeaseExpired
        ),
        SessionMutationIntent::ReleaseLease(_) => matches!(
            error,
            StoreError::NotFound | StoreError::StaleFence | StoreError::LeaseHeld
        ),
        SessionMutationIntent::FencedTransition(_) => matches!(
            error,
            StoreError::NotFound
                | StoreError::StaleFence
                | StoreError::CasConflict
                | StoreError::InvalidSessionTtl
                | StoreError::InvalidRecordExpiry
                | StoreError::LeaseHeld
                | StoreError::LeaseExpired
                | StoreError::FencedTransitionRequestConflict
                | StoreError::FencedTransitionRequestExpired
                | StoreError::FencedTransitionHistoryFull
                | StoreError::FencedTransitionRetentionExhausted
                | StoreError::FencedTransitionStorageExhausted
        ),
        SessionMutationIntent::FencedTransitionV2(_)
        | SessionMutationIntent::FencedTransitionV2Batch(_)
        | SessionMutationIntent::ActivateFencedTransitionV2 { .. } => matches!(
            error,
            StoreError::NotFound
                | StoreError::StaleFence
                | StoreError::CasConflict
                | StoreError::InvalidSessionTtl
                | StoreError::InvalidRecordExpiry
                | StoreError::LeaseHeld
                | StoreError::LeaseExpired
                | StoreError::FencedTransitionRequestConflict
                | StoreError::FencedTransitionRequestExpired
                | StoreError::FencedTransitionHistoryFull
                | StoreError::FencedTransitionHistoryEpochRetired
                | StoreError::FencedTransitionHistoryEpochNotActive
                | StoreError::FencedTransitionRetentionExhausted
                | StoreError::FencedTransitionStorageExhausted
        ),
        SessionMutationIntent::FinalizeOperatorRecovery { .. } => {
            matches!(error, StoreError::InvalidKey(reason) if reason == "operator_recovery_epoch_rejected")
        }
        SessionMutationIntent::PrepareTopologyTransition { .. }
        | SessionMutationIntent::MarkTopologyLearnersReady { .. }
        | SessionMutationIntent::FenceTopologyAuthority { .. }
        | SessionMutationIntent::AbortTopologyTransition { .. }
        | SessionMutationIntent::FinalizeTopologyTransition { .. }
        | SessionMutationIntent::ActivateFencedTransition { .. }
        | SessionMutationIntent::Authorized { .. } => false,
        SessionMutationIntent::MaintainFencedTransitionV2History { .. } => {
            matches!(
                error,
                StoreError::FencedTransitionHistoryEpochNotActive
                    | StoreError::FencedTransitionStorageExhausted
            )
        }
    }
}

fn exact_uniform_voter_membership(
    stored: &StoredMembership<SessionConsensusNodeId, EmptyNode>,
    configured: &BTreeSet<SessionConsensusNodeId>,
) -> bool {
    let membership = stored.membership();
    let configs = membership.get_joint_config();
    let nodes = membership
        .nodes()
        .map(|(node_id, _)| *node_id)
        .collect::<BTreeSet<_>>();
    stored.log_id().is_some()
        && configs.len() == 1
        && configs.first() == Some(configured)
        && membership.learner_ids().next().is_none()
        && nodes == *configured
}

fn validate_consensus_intent(intent: &SessionMutationIntent) -> Result<(), StoreError> {
    validate_consensus_intent_with_recovery(intent, false)
}

fn validate_consensus_command_preproposal(
    command: &super::SessionConsensusCommand,
) -> Result<(), StoreError> {
    let intent = match &command.intent {
        SessionMutationIntent::Authorized { mutation, .. } => {
            if matches!(mutation.as_ref(), SessionMutationIntent::Authorized { .. }) {
                return Err(StoreError::CapabilityNotSupported(
                    "nested_authorized_mutation_not_allowed".into(),
                ));
            }
            mutation.as_ref()
        }
        intent => intent,
    };
    if let SessionMutationIntent::CompareAndSet(op) = intent {
        validate_stored_record_expiry_at(&op.new_record, command.logical_time)?;
        validate_sealed_payload(op)?;
    }
    if let SessionMutationIntent::FencedTransition(request)
    | SessionMutationIntent::ActivateFencedTransition { request, .. } = intent
    {
        if command.request_id
            != SessionConsensusRequestId::from_bytes(*request.request_id().as_bytes())
        {
            return Err(StoreError::InvalidKey(
                "fenced_transition_request_id_mismatch".into(),
            ));
        }
        request.validate()?;
        if let Some(record) = request.mutation().record() {
            crate::sqlite::validate_consensus_record(record)?;
        }
    }
    if let SessionMutationIntent::FencedTransitionV2(request)
    | SessionMutationIntent::ActivateFencedTransitionV2 { request, .. } = intent
    {
        if command.request_id != fenced_transition_v2_outer_request_id(request) {
            return Err(StoreError::InvalidKey(
                "fenced_transition_v2_request_id_mismatch".into(),
            ));
        }
        request.validate()?;
        if let Some(record) = request.mutation().record() {
            crate::sqlite::validate_consensus_record(record)?;
        }
    }
    if let SessionMutationIntent::FencedTransitionV2Batch(requests) = intent {
        validate_fenced_transition_v2_batch(requests)?;
        if command.request_id != fenced_transition_v2_batch_request_id(requests)? {
            return Err(StoreError::InvalidKey(
                "fenced_transition_v2_batch_request_id_mismatch".into(),
            ));
        }
        for request in requests {
            // A retained complete ID with a substituted body is a
            // deterministic per-item conflict. Its nested record is not an
            // independently admissible command payload, so do not let a
            // malformed substitution override the conflict before apply.
            if matches!(
                request.validate(),
                Err(StoreError::FencedTransitionRequestConflict)
            ) {
                continue;
            }
            if let Some(record) = request.mutation().record() {
                crate::sqlite::validate_consensus_record(record)?;
            }
        }
    }
    Ok(())
}

fn validate_consensus_intent_with_recovery(
    intent: &SessionMutationIntent,
    allow_operator_recovery: bool,
) -> Result<(), StoreError> {
    if matches!(
        intent,
        SessionMutationIntent::FinalizeOperatorRecovery { .. }
            | SessionMutationIntent::MaintainFencedTransitionV2History { .. }
    ) && !allow_operator_recovery
    {
        return Err(StoreError::CapabilityNotSupported(
            "operator_recovery_requires_local_admin_authority".into(),
        ));
    }
    if matches!(
        intent,
        SessionMutationIntent::PrepareTopologyTransition { .. }
            | SessionMutationIntent::MarkTopologyLearnersReady { .. }
            | SessionMutationIntent::FenceTopologyAuthority { .. }
            | SessionMutationIntent::AbortTopologyTransition { .. }
            | SessionMutationIntent::FinalizeTopologyTransition { .. }
            | SessionMutationIntent::ActivateFencedTransition { .. }
            | SessionMutationIntent::ActivateFencedTransitionV2 { .. }
            | SessionMutationIntent::Authorized { .. }
    ) {
        return Err(StoreError::CapabilityNotSupported(
            "topology_transition_requires_local_coordinator_authority".into(),
        ));
    }
    if let SessionMutationIntent::MaintainFencedTransitionV2History {
        expected_bound_entries,
        ..
    } = intent
    {
        if usize::try_from(*expected_bound_entries)
            .ok()
            .is_none_or(|entries| entries > FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES)
        {
            return Err(StoreError::InvalidKey(
                "fenced_transition_v2_expected_bound_entries_invalid".into(),
            ));
        }
    }
    if let SessionMutationIntent::CompareAndSet(op) = intent {
        validate_sealed_payload(op)?;
    }
    if let SessionMutationIntent::FencedTransition(request) = intent {
        request.validate()?;
        if let Some(record) = request.mutation().record() {
            crate::sqlite::validate_consensus_record(record)?;
        }
    }
    if let SessionMutationIntent::FencedTransitionV2(request) = intent {
        request.validate()?;
        if let Some(record) = request.mutation().record() {
            crate::sqlite::validate_consensus_record(record)?;
        }
    }
    if let SessionMutationIntent::FencedTransitionV2Batch(requests) = intent {
        validate_fenced_transition_v2_batch(requests)?;
        for request in requests {
            // Keep the leader's generic validation aligned with SQLite apply:
            // an exact V2 body conflict remains a committed per-item result.
            if matches!(
                request.validate(),
                Err(StoreError::FencedTransitionRequestConflict)
            ) {
                continue;
            }
            if let Some(record) = request.mutation().record() {
                crate::sqlite::validate_consensus_record(record)?;
            }
        }
    }
    Ok(())
}

fn validate_consensus_batch(ops: &[SessionOp]) -> Result<(), StoreError> {
    for op in ops {
        if let SessionOp::CompareAndSet(op) = op {
            validate_sealed_payload(op)?;
        }
    }
    Ok(())
}

fn validate_sealed_payload(op: &CompareAndSet) -> Result<(), StoreError> {
    crate::sqlite::validate_consensus_record(&op.new_record)
}

fn validate_consumer_operation(operation: &SessionConsumerOperation) -> Result<(), StoreError> {
    operation
        .validate()
        .map_err(|_| StoreError::InvalidKey("consumer request rejected".into()))?;
    match operation {
        SessionConsumerOperation::CompareAndSet { op } => validate_sealed_payload(op),
        SessionConsumerOperation::Batch { ops } => validate_consensus_batch(ops),
        SessionConsumerOperation::FencedTransition { request }
        | SessionConsumerOperation::FencedTransitionStatus { request } => {
            if let Some(record) = request.mutation().record() {
                crate::sqlite::validate_consensus_record(record)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[derive(Clone)]
struct SessionConsensusService {
    store: ConsensusSessionStore,
}

impl fmt::Debug for SessionConsensusService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionConsensusService(<redacted>)")
    }
}

#[async_trait]
impl SessionConsensusRpcHandler for SessionConsensusService {
    async fn handle(
        &self,
        authenticated_sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        if request.validate().is_err()
            || request.schema_version != SESSION_CONSENSUS_SCHEMA_VERSION
            || request.sender != authenticated_sender
        {
            return SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::ScopeMismatch),
            };
        }

        match request.family {
            SessionConsensusRpcFamily::Vote
            | SessionConsensusRpcFamily::AppendEntries
            | SessionConsensusRpcFamily::InstallSnapshot => {
                let deadline = tokio::time::Instant::now()
                    .checked_add(self.store.inner.operation_timeout)
                    .unwrap_or_else(tokio::time::Instant::now);
                if !self
                    .store
                    .durable_fixed_quorum_engine_admission_before(deadline)
                    .await
                {
                    return SessionConsensusWireResponse {
                        result: Err(SessionConsensusPeerError::ScopeMismatch),
                    };
                }
                self.store
                    .inner
                    .raft_handler
                    .handle(authenticated_sender, request)
                    .await
            }
            SessionConsensusRpcFamily::ForwardMutation => {
                if !self
                    .store
                    .current_application_scope_matches(authenticated_sender, request.identity)
                {
                    return SessionConsensusWireResponse {
                        result: Err(SessionConsensusPeerError::ScopeMismatch),
                    };
                }
                let forwarded: ForwardRequest = match decode_bounded(&request.payload) {
                    Ok(forwarded) => forwarded,
                    Err(_) => return protocol_rejection(),
                };
                let deadline = tokio::time::Instant::now()
                    .checked_add(self.store.inner.operation_timeout)
                    .unwrap_or_else(tokio::time::Instant::now);
                let reply = match forwarded {
                    ForwardRequest::Mutation(request) => {
                        self.store
                            .apply_on_local_leader(request, authenticated_sender, deadline)
                            .await
                    }
                    ForwardRequest::FencedTransitionV2StatusLogicalTimeTicket {
                        required_consumer_scope,
                    } => {
                        return encode_service_reply(
                            &self
                                .store
                                .fenced_transition_v2_status_logical_time_ticket_on_local_leader(
                                    *required_consumer_scope,
                                    deadline,
                                )
                                .await,
                        );
                    }
                    ForwardRequest::RecordExpiryPreflight {
                        preflights,
                        required_consumer_scope,
                    } => {
                        self.store
                            .preflight_record_expiry_on_local_leader(
                                preflights.into_inner(),
                                required_consumer_scope,
                                authenticated_sender,
                                deadline,
                            )
                            .await
                    }
                };
                encode_service_reply(&reply)
            }
            SessionConsensusRpcFamily::ReadBarrier => {
                if !self
                    .store
                    .current_application_scope_matches(authenticated_sender, request.identity)
                {
                    return SessionConsensusWireResponse {
                        result: Err(SessionConsensusPeerError::ScopeMismatch),
                    };
                }
                if decode_bounded::<ReadBarrierRequest>(&request.payload).is_ok() {
                    let deadline = tokio::time::Instant::now()
                        .checked_add(self.store.inner.operation_timeout)
                        .unwrap_or_else(tokio::time::Instant::now);
                    return encode_service_reply(&self.store.local_read_barrier(deadline).await);
                }
                if let Ok(probe) =
                    decode_bounded::<FencedTransitionCapabilityProbe>(&request.payload)
                {
                    let reply = if probe.schema_version == FENCED_TRANSITION_SCHEMA_V1
                        && self.store.local_fenced_transition_capability()
                            == AtomicFencedTransitionCapability::V1
                    {
                        FencedTransitionCapabilityReply::V1
                    } else {
                        FencedTransitionCapabilityReply::Unsupported
                    };
                    return encode_service_reply(&reply);
                }
                let probe =
                    match decode_bounded::<FencedTransitionV2CapabilityProbe>(&request.payload) {
                        Ok(probe) => probe,
                        Err(_) => return protocol_rejection(),
                    };
                let reply = fenced_transition_v2_capability_probe_reply(
                    probe,
                    self.store.local_fenced_transition_v2_capability(),
                );
                encode_service_reply(&reply)
            }
            SessionConsensusRpcFamily::TopologyAdmissionBarrier => {
                let barrier = match decode_bounded(&request.payload) {
                    Ok(barrier) => barrier,
                    Err(_) => return protocol_rejection(),
                };
                let reply = self
                    .store
                    .handle_topology_admission_barrier(
                        authenticated_sender,
                        request.identity,
                        barrier,
                    )
                    .await;
                encode_service_reply(&reply)
            }
            _ => protocol_rejection(),
        }
    }
}

fn encode_service_reply<T: Serialize>(reply: &T) -> SessionConsensusWireResponse {
    match encode_bounded(reply) {
        Ok(payload) => SessionConsensusWireResponse {
            result: Ok(payload),
        },
        Err(_) => protocol_rejection(),
    }
}

fn protocol_rejection() -> SessionConsensusWireResponse {
    SessionConsensusWireResponse {
        result: Err(SessionConsensusPeerError::Protocol),
    }
}

impl ConsensusSessionConsumerService {
    async fn execute_fenced_transition(
        &self,
        identity: &SessionConsumerIdentity,
        request: &SessionConsumerRequest,
        transition: FencedTransitionRequest,
        deadline: tokio::time::Instant,
    ) -> SessionConsumerResponse {
        let internal =
            match derive_consumer_fenced_transition_request(identity, request.scope(), &transition)
            {
                Ok(internal) => internal,
                Err(rejection) => return SessionConsumerResponse::Rejected(rejection),
            };
        match self
            .store
            .consumer_fenced_transition(request.scope(), internal, deadline)
            .await
        {
            Ok(outcome) if outcome.matches_request(&transition) => {
                SessionConsumerResponse::FencedTransition(Ok(outcome))
            }
            Ok(_) | Err(StoreError::FencedTransitionOutcomeUnknown) => {
                SessionConsumerResponse::OutcomeUnknown(SessionConsumerOutcomeUnknown::Mutation {
                    request_id: request.request_id(),
                })
            }
            Err(error) => SessionConsumerResponse::FencedTransition(Err(error.into())),
        }
    }

    async fn fenced_transition_status(
        &self,
        identity: &SessionConsumerIdentity,
        request: &SessionConsumerRequest,
        transition: FencedTransitionRequest,
        deadline: tokio::time::Instant,
    ) -> SessionConsumerResponse {
        let internal =
            match derive_consumer_fenced_transition_request(identity, request.scope(), &transition)
            {
                Ok(internal) => internal,
                Err(rejection) => return SessionConsumerResponse::Rejected(rejection),
            };
        SessionConsumerResponse::FencedTransitionStatus(
            self.store
                .consumer_fenced_transition_status(request.scope(), &internal, deadline)
                .await
                .map(Into::into)
                .map_err(SessionConsumerStoreError::from),
        )
    }

    fn operation_deadline(&self) -> Result<tokio::time::Instant, SessionConsumerRejection> {
        tokio::time::Instant::now()
            .checked_add(self.store.inner.operation_timeout)
            .ok_or(SessionConsumerRejection::Unavailable)
    }

    /// Preserve deterministic pre-proposal responses, but never relabel a
    /// committed V2 receipt as a safe scope rejection. Once the final consumer
    /// admission cannot be confirmed, the retained V2 IDs are the only valid
    /// recovery route for a completed singleton or batch command.
    fn v2_response_after_scope_loss(
        request: &SessionConsumerV2Request,
        response: SessionConsumerV2Response,
        effect_may_have_committed: bool,
        rejection: SessionConsumerRejection,
    ) -> SessionConsumerV2Response {
        match (request.operation(), response, effect_may_have_committed) {
            (SessionConsumerV2Operation::FencedTransitionV2 { .. }, _, true) => {
                SessionConsumerV2Response::FencedTransitionV2(Err(
                    SessionConsumerV2FencedTransitionError::OutcomeUnknown,
                ))
            }
            (SessionConsumerV2Operation::FencedTransitionV2Batch { requests }, _, true) => {
                let request_ids = requests
                    .iter()
                    .map(FencedTransitionV2Request::request_id)
                    .collect();
                match SessionConsumerV2FencedTransitionBatchError::outcome_unknown(request_ids) {
                    Ok(error) => SessionConsumerV2Response::FencedTransitionV2Batch(Err(error)),
                    Err(rejection) => SessionConsumerV2Response::Rejected(rejection),
                }
            }
            (SessionConsumerV2Operation::FencedTransitionV2 { .. }, response, _)
            | (SessionConsumerV2Operation::FencedTransitionV2Batch { .. }, response, _) => response,
            (_, _, _) => SessionConsumerV2Response::Rejected(rejection),
        }
    }

    async fn bind_consumer_request(
        &self,
        identity: &SessionConsumerIdentity,
        request: &SessionConsumerRequest,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        let request_id = derive_consumer_request_binding_id(identity, request);
        let request_commitment = consumer_request_commitment(request)
            .map_err(|_| StoreError::InvalidKey("consumer request commitment rejected".into()))?;
        let response = self
            .store
            .submit_request_before(
                request_id,
                SessionMutationIntent::BindConsumerRequest { request_commitment },
                Some(request.scope().consensus_identity()),
                deadline,
            )
            .await
            .map_err(|error| match error {
                // This marker never performs application work. Its unconfirmed
                // durable outcome is safely retried only by the caller using
                // the same explicit consumer request ID.
                StoreError::BackendOperationOutcomeUnavailable => consensus_unavailable(),
                error => error,
            })?;
        match response.result? {
            SessionMutationOutcome::Unit => Ok(()),
            _ => Err(StoreError::CasIdempotencyOutcomeUnavailable),
        }
    }

    async fn submit_consumer_intent(
        &self,
        identity: &SessionConsumerIdentity,
        request: &SessionConsumerRequest,
        slot: u16,
        intent: SessionMutationIntent,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsensusResponse, StoreError> {
        let request_id = derive_consumer_consensus_request_id(identity, request, slot)
            .map_err(|_| StoreError::InvalidKey("consumer request commitment rejected".into()))?;
        self.store
            .submit_request_before(
                request_id,
                intent,
                Some(request.scope().consensus_identity()),
                deadline,
            )
            .await
    }

    fn binding_failure_response(
        operation: &SessionConsumerOperation,
        error: StoreError,
    ) -> SessionConsumerResponse {
        if !matches!(error, StoreError::CasIdempotencyConflict) {
            return SessionConsumerResponse::Rejected(SessionConsumerRejection::Unavailable);
        }
        let conflict = SessionConsumerStoreError::RequestConflict;
        match operation {
            SessionConsumerOperation::CompareAndSet { .. } => {
                SessionConsumerResponse::CompareAndSet(Err(conflict))
            }
            SessionConsumerOperation::DeleteFenced { .. } => {
                SessionConsumerResponse::DeleteFenced(Err(conflict))
            }
            SessionConsumerOperation::RefreshTtl { .. } => {
                SessionConsumerResponse::RefreshTtl(Err(conflict))
            }
            SessionConsumerOperation::Batch { .. } => SessionConsumerResponse::Batch(Err(conflict)),
            SessionConsumerOperation::AcquireLease { .. } => SessionConsumerResponse::AcquireLease(
                Err(crate::SessionConsumerLeaseError::RequestConflict),
            ),
            SessionConsumerOperation::RenewLease { .. } => SessionConsumerResponse::RenewLease(
                Err(crate::SessionConsumerLeaseError::RequestConflict),
            ),
            SessionConsumerOperation::ReleaseLease { .. } => SessionConsumerResponse::ReleaseLease(
                Err(crate::SessionConsumerLeaseError::RequestConflict),
            ),
            SessionConsumerOperation::Capabilities
            | SessionConsumerOperation::Get { .. }
            | SessionConsumerOperation::PreflightRecordExpiry { .. }
            | SessionConsumerOperation::ScanRestoreRecords { .. }
            | SessionConsumerOperation::Watch { .. }
            | SessionConsumerOperation::FencedTransitionCapability
            | SessionConsumerOperation::ObserveFencedTransition { .. }
            | SessionConsumerOperation::FencedTransitionStatus { .. } => {
                SessionConsumerResponse::Rejected(SessionConsumerRejection::MalformedRequest)
            }
            SessionConsumerOperation::FencedTransition { .. } => {
                SessionConsumerResponse::FencedTransition(Err(
                    SessionConsumerFencedTransitionError::RequestConflict,
                ))
            }
        }
    }

    fn semantic_validation_response(
        operation: &SessionConsumerOperation,
        error: StoreError,
    ) -> SessionConsumerResponse {
        // Payload size has a stable typed representation for CAS and batch
        // mutations. Other protected-data details remain deliberately opaque
        // at this boundary and are reported as malformed input.
        if matches!(error, StoreError::PayloadTooLarge { .. }) {
            return match operation {
                SessionConsumerOperation::CompareAndSet { .. } => {
                    SessionConsumerResponse::CompareAndSet(Err(
                        SessionConsumerStoreError::PayloadTooLarge,
                    ))
                }
                SessionConsumerOperation::Batch { .. } => {
                    SessionConsumerResponse::Batch(Err(SessionConsumerStoreError::PayloadTooLarge))
                }
                SessionConsumerOperation::FencedTransition { .. } => {
                    SessionConsumerResponse::FencedTransition(Err(
                        SessionConsumerFencedTransitionError::Store(
                            SessionConsumerStoreError::PayloadTooLarge,
                        ),
                    ))
                }
                _ => SessionConsumerResponse::Rejected(SessionConsumerRejection::MalformedRequest),
            };
        }
        SessionConsumerResponse::Rejected(SessionConsumerRejection::MalformedRequest)
    }

    fn operation_mutates(operation: &SessionConsumerOperation) -> bool {
        match operation {
            SessionConsumerOperation::Capabilities
            | SessionConsumerOperation::Get { .. }
            | SessionConsumerOperation::PreflightRecordExpiry { .. }
            | SessionConsumerOperation::ScanRestoreRecords { .. }
            | SessionConsumerOperation::Watch { .. }
            | SessionConsumerOperation::FencedTransitionCapability
            | SessionConsumerOperation::ObserveFencedTransition { .. }
            | SessionConsumerOperation::FencedTransitionStatus { .. } => false,
            SessionConsumerOperation::Batch { ops } => ops
                .iter()
                .any(|operation| !matches!(operation, SessionOp::Get { .. })),
            SessionConsumerOperation::CompareAndSet { .. }
            | SessionConsumerOperation::DeleteFenced { .. }
            | SessionConsumerOperation::RefreshTtl { .. }
            | SessionConsumerOperation::AcquireLease { .. }
            | SessionConsumerOperation::RenewLease { .. }
            | SessionConsumerOperation::ReleaseLease { .. }
            | SessionConsumerOperation::FencedTransition { .. } => true,
        }
    }

    /// Bound the response before binding or applying a batch request.
    ///
    /// A `Get` or failed `CompareAndSet` can return a complete stored record.
    /// Their upper bound is derived from the backend's admitted payload limit,
    /// using four JSON bytes per source byte plus a deliberately generous
    /// envelope allowance. This makes a clean `PayloadTooLarge` response
    /// impossible after a batch effect has reached consensus.
    fn batch_response_is_admitted(&self, ops: &[SessionOp]) -> bool {
        consumer_batch_response_is_admitted(
            self.store
                .inner
                .backend
                .consensus_capabilities()
                .max_value_bytes,
            ops,
        )
    }
}

fn consumer_batch_response_is_admitted(max_payload_bytes: usize, ops: &[SessionOp]) -> bool {
    const RESPONSE_ENVELOPE_BYTES: usize = 4 * 1024;
    const SLOT_ENVELOPE_BYTES: usize = 4 * 1024;
    const RECORD_ENVELOPE_BYTES: usize = 64 * 1024;

    let Some(max_record_bytes) = max_payload_bytes
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(RECORD_ENVELOPE_BYTES))
    else {
        return false;
    };
    let Some(mut total) =
        RESPONSE_ENVELOPE_BYTES.checked_add(ops.len().saturating_mul(SLOT_ENVELOPE_BYTES))
    else {
        return false;
    };
    for op in ops {
        let possible_record = matches!(op, SessionOp::Get { .. } | SessionOp::CompareAndSet(_));
        let slot_bytes = if possible_record {
            max_record_bytes
        } else {
            SLOT_ENVELOPE_BYTES
        };
        let Some(next) = total.checked_add(slot_bytes) else {
            return false;
        };
        if next > MAX_SESSION_CONSUMER_BATCH_RESPONSE_BYTES {
            return false;
        }
        total = next;
    }
    true
}

impl ConsensusSessionConsumerService {
    async fn execute_batch(
        &self,
        identity: &SessionConsumerIdentity,
        request: &SessionConsumerRequest,
        deadline: tokio::time::Instant,
        ops: Vec<SessionOp>,
    ) -> SessionConsumerResponse {
        let contains_mutation = ops
            .iter()
            .any(|operation| !matches!(operation, SessionOp::Get { .. }));
        if let Err(error) = validate_consensus_batch(&ops) {
            return if matches!(error, StoreError::PayloadTooLarge { .. }) {
                SessionConsumerResponse::Batch(Err(SessionConsumerStoreError::PayloadTooLarge))
            } else {
                SessionConsumerResponse::Rejected(SessionConsumerRejection::MalformedRequest)
            };
        }
        let preflights = match record_expiry_preflights(&ops) {
            Ok(preflights) => preflights,
            Err(_) => {
                return SessionConsumerResponse::Rejected(
                    SessionConsumerRejection::MalformedRequest,
                );
            }
        };
        if let Err(error) = self
            .store
            .consumer_preflight_record_expiry(request.scope(), &preflights, deadline)
            .await
        {
            return SessionConsumerResponse::Batch(Err(SessionConsumerStoreError::from(error)));
        }

        let mut results = Vec::with_capacity(ops.len());
        for (index, op) in ops.into_iter().enumerate() {
            let slot = match u16::try_from(index + 1) {
                Ok(slot) => slot,
                Err(_) => {
                    return SessionConsumerResponse::Rejected(
                        SessionConsumerRejection::MalformedRequest,
                    );
                }
            };
            let response = match op {
                SessionOp::Get { key } => {
                    let result = self
                        .submit_consumer_intent(
                            identity,
                            request,
                            slot,
                            SessionMutationIntent::ReadConsumerRecord { key },
                            deadline,
                        )
                        .await
                        .and_then(|response| match response.result? {
                            SessionMutationOutcome::ConsumerRecord(record) => Ok(record),
                            _ => Err(StoreError::BackendOperationOutcomeUnavailable),
                        });
                    if consumer_mutation_unknown(&result) {
                        return if contains_mutation {
                            SessionConsumerResponse::OutcomeUnknown(
                                SessionConsumerOutcomeUnknown::Mutation {
                                    request_id: request.request_id(),
                                },
                            )
                        } else {
                            SessionConsumerResponse::Batch(Err(
                                SessionConsumerStoreError::Unavailable,
                            ))
                        };
                    }
                    SessionConsumerBatchResult::Get(result.map_err(SessionConsumerStoreError::from))
                }
                SessionOp::CompareAndSet(op) => {
                    let result = self
                        .submit_consumer_intent(
                            identity,
                            request,
                            slot,
                            SessionMutationIntent::CompareAndSet(Box::new(op)),
                            deadline,
                        )
                        .await
                        .and_then(|response| match response.result? {
                            SessionMutationOutcome::CompareAndSet(result) => Ok(result),
                            _ => Err(StoreError::CasIdempotencyOutcomeUnavailable),
                        });
                    if consumer_mutation_unknown(&result) {
                        return SessionConsumerResponse::OutcomeUnknown(
                            SessionConsumerOutcomeUnknown::Mutation {
                                request_id: request.request_id(),
                            },
                        );
                    }
                    SessionConsumerBatchResult::CompareAndSet(
                        result.map_err(SessionConsumerStoreError::from),
                    )
                }
                SessionOp::DeleteFenced { lease } => {
                    let result = self
                        .submit_consumer_intent(
                            identity,
                            request,
                            slot,
                            SessionMutationIntent::DeleteFenced(lease),
                            deadline,
                        )
                        .await
                        .and_then(|response| match response.result? {
                            SessionMutationOutcome::Unit => Ok(()),
                            _ => Err(StoreError::BackendOperationOutcomeUnavailable),
                        });
                    if consumer_mutation_unknown(&result) {
                        return SessionConsumerResponse::OutcomeUnknown(
                            SessionConsumerOutcomeUnknown::Mutation {
                                request_id: request.request_id(),
                            },
                        );
                    }
                    SessionConsumerBatchResult::DeleteFenced(
                        result.map_err(SessionConsumerStoreError::from),
                    )
                }
                SessionOp::RefreshTtl { lease, ttl } => {
                    let result = self
                        .submit_consumer_intent(
                            identity,
                            request,
                            slot,
                            SessionMutationIntent::RefreshTtl { lease, ttl },
                            deadline,
                        )
                        .await
                        .and_then(|response| match response.result? {
                            SessionMutationOutcome::Unit => Ok(()),
                            _ => Err(StoreError::BackendOperationOutcomeUnavailable),
                        });
                    if consumer_mutation_unknown(&result) {
                        return SessionConsumerResponse::OutcomeUnknown(
                            SessionConsumerOutcomeUnknown::Mutation {
                                request_id: request.request_id(),
                            },
                        );
                    }
                    SessionConsumerBatchResult::RefreshTtl(
                        result.map_err(SessionConsumerStoreError::from),
                    )
                }
            };
            results.push(response);
        }
        SessionConsumerResponse::Batch(Ok(results))
    }
}

fn consumer_mutation_unknown<T>(result: &Result<T, StoreError>) -> bool {
    matches!(
        result,
        Err(StoreError::CasIdempotencyOutcomeUnavailable)
            | Err(StoreError::BackendOperationOutcomeUnavailable)
    )
}

fn fixed_durable_v2_status_for_batch_dispatch(
    topology_mode: QuorumTopologyMode,
    request: &SessionConsumerV2Request,
) -> Option<&FencedTransitionV2Request> {
    if topology_mode != QuorumTopologyMode::FixedDurableQuorum {
        return None;
    }
    let SessionConsumerV2Operation::FencedTransitionV2Status { request } = request.operation()
    else {
        return None;
    };
    Some(request)
}

fn fixed_durable_raw_v2_warm_dispatch(
    topology_mode: QuorumTopologyMode,
    local_capability: Option<FencedTransitionV2Capability>,
    request: &SessionConsumerV2Request,
) -> bool {
    matches!(
        request.operation(),
        SessionConsumerV2Operation::FencedTransitionV2 { .. }
            | SessionConsumerV2Operation::FencedTransitionV2Batch { .. }
    ) && topology_mode == QuorumTopologyMode::FixedDurableQuorum
        && local_capability == Some(FencedTransitionV2Capability::V2)
}

#[async_trait]
impl SessionQuorumConsumer for ConsensusSessionConsumerService {
    async fn execute(
        &self,
        identity: &SessionConsumerIdentity,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        let deadline = match self.operation_deadline() {
            Ok(deadline) => deadline,
            Err(rejection) => return SessionConsumerResponse::Rejected(rejection),
        };
        if let Err(rejection) = request.validate() {
            return SessionConsumerResponse::Rejected(rejection);
        }
        let operation = request.operation().clone();
        if let Err(error) = validate_consumer_operation(&operation) {
            return Self::semantic_validation_response(&operation, error);
        }
        let admission = match self
            .store
            .admit_consumer_scope(request.scope(), deadline)
            .await
        {
            Ok(admission) => admission,
            Err(rejection) => return SessionConsumerResponse::Rejected(rejection),
        };
        if Self::operation_mutates(&operation) {
            // Mutation authority is reacquired and scope-checked inside the
            // leader topology gate. Do not retain this first detector guard
            // while entering that path: Tokio's fair RwLock would otherwise
            // allow a queued writer to self-block this consumer request.
            drop(admission);
            if let SessionConsumerOperation::FencedTransition {
                request: transition,
            } = operation
            {
                return self
                    .execute_fenced_transition(identity, &request, *transition, deadline)
                    .await;
            }
            if let SessionConsumerOperation::Batch { ops } = &operation {
                if !self.batch_response_is_admitted(ops) {
                    return SessionConsumerResponse::Batch(Err(
                        SessionConsumerStoreError::PayloadTooLarge,
                    ));
                }
            }
            if let Err(error) = self
                .bind_consumer_request(identity, &request, deadline)
                .await
            {
                return Self::binding_failure_response(&operation, error);
            }
            return match operation {
                SessionConsumerOperation::CompareAndSet { op } => {
                    let result = self
                        .submit_consumer_intent(
                            identity,
                            &request,
                            0,
                            SessionMutationIntent::CompareAndSet(op),
                            deadline,
                        )
                        .await
                        .and_then(|response| match response.result? {
                            SessionMutationOutcome::CompareAndSet(result) => Ok(result),
                            _ => Err(StoreError::CasIdempotencyOutcomeUnavailable),
                        });
                    if consumer_mutation_unknown(&result) {
                        SessionConsumerResponse::OutcomeUnknown(
                            SessionConsumerOutcomeUnknown::Mutation {
                                request_id: request.request_id(),
                            },
                        )
                    } else {
                        SessionConsumerResponse::CompareAndSet(
                            result.map_err(SessionConsumerStoreError::from),
                        )
                    }
                }
                SessionConsumerOperation::DeleteFenced { lease } => {
                    let result = self
                        .submit_consumer_intent(
                            identity,
                            &request,
                            0,
                            SessionMutationIntent::DeleteFenced(lease),
                            deadline,
                        )
                        .await
                        .and_then(|response| match response.result? {
                            SessionMutationOutcome::Unit => Ok(()),
                            _ => Err(StoreError::BackendOperationOutcomeUnavailable),
                        });
                    if consumer_mutation_unknown(&result) {
                        SessionConsumerResponse::OutcomeUnknown(
                            SessionConsumerOutcomeUnknown::Mutation {
                                request_id: request.request_id(),
                            },
                        )
                    } else {
                        SessionConsumerResponse::DeleteFenced(
                            result.map_err(SessionConsumerStoreError::from),
                        )
                    }
                }
                SessionConsumerOperation::RefreshTtl { lease, ttl } => {
                    let result = self
                        .submit_consumer_intent(
                            identity,
                            &request,
                            0,
                            SessionMutationIntent::RefreshTtl { lease, ttl },
                            deadline,
                        )
                        .await
                        .and_then(|response| match response.result? {
                            SessionMutationOutcome::Unit => Ok(()),
                            _ => Err(StoreError::BackendOperationOutcomeUnavailable),
                        });
                    if consumer_mutation_unknown(&result) {
                        SessionConsumerResponse::OutcomeUnknown(
                            SessionConsumerOutcomeUnknown::Mutation {
                                request_id: request.request_id(),
                            },
                        )
                    } else {
                        SessionConsumerResponse::RefreshTtl(
                            result.map_err(SessionConsumerStoreError::from),
                        )
                    }
                }
                SessionConsumerOperation::Batch { ops } => {
                    self.execute_batch(identity, &request, deadline, ops).await
                }
                SessionConsumerOperation::AcquireLease { key, owner, ttl } => {
                    let result = self
                        .submit_consumer_intent(
                            identity,
                            &request,
                            0,
                            SessionMutationIntent::AcquireLease { key, owner, ttl },
                            deadline,
                        )
                        .await
                        .and_then(|response| match response.result? {
                            SessionMutationOutcome::Lease(lease) => Ok(lease),
                            _ => Err(StoreError::BackendOperationOutcomeUnavailable),
                        })
                        .map_err(LeaseError::from);
                    if matches!(result, Err(LeaseError::OperationOutcomeUnavailable)) {
                        SessionConsumerResponse::OutcomeUnknown(
                            SessionConsumerOutcomeUnknown::Lease,
                        )
                    } else {
                        SessionConsumerResponse::AcquireLease(
                            result.map_err(crate::SessionConsumerLeaseError::from),
                        )
                    }
                }
                SessionConsumerOperation::RenewLease { lease, ttl } => {
                    let result = self
                        .submit_consumer_intent(
                            identity,
                            &request,
                            0,
                            SessionMutationIntent::RenewLease { lease, ttl },
                            deadline,
                        )
                        .await
                        .and_then(|response| match response.result? {
                            SessionMutationOutcome::Lease(lease) => Ok(lease),
                            _ => Err(StoreError::BackendOperationOutcomeUnavailable),
                        })
                        .map_err(LeaseError::from);
                    if matches!(result, Err(LeaseError::OperationOutcomeUnavailable)) {
                        SessionConsumerResponse::OutcomeUnknown(
                            SessionConsumerOutcomeUnknown::Lease,
                        )
                    } else {
                        SessionConsumerResponse::RenewLease(
                            result.map_err(crate::SessionConsumerLeaseError::from),
                        )
                    }
                }
                SessionConsumerOperation::ReleaseLease { lease } => {
                    let result = self
                        .submit_consumer_intent(
                            identity,
                            &request,
                            0,
                            SessionMutationIntent::ReleaseLease(lease),
                            deadline,
                        )
                        .await
                        .and_then(|response| match response.result? {
                            SessionMutationOutcome::Unit => Ok(()),
                            _ => Err(StoreError::BackendOperationOutcomeUnavailable),
                        })
                        .map_err(LeaseError::from);
                    if matches!(result, Err(LeaseError::OperationOutcomeUnavailable)) {
                        SessionConsumerResponse::OutcomeUnknown(
                            SessionConsumerOutcomeUnknown::Lease,
                        )
                    } else {
                        SessionConsumerResponse::ReleaseLease(
                            result.map_err(crate::SessionConsumerLeaseError::from),
                        )
                    }
                }
                SessionConsumerOperation::FencedTransition { .. } => {
                    unreachable!("fenced transition bypasses the legacy binding marker")
                }
                _ => unreachable!("mutation classifier and operation variant disagree"),
            };
        }

        match operation {
            SessionConsumerOperation::Capabilities => {
                SessionConsumerResponse::Capabilities(self.store.capabilities().await)
            }
            SessionConsumerOperation::FencedTransitionCapability => {
                drop(admission);
                SessionConsumerResponse::FencedTransitionCapability(
                    self.store
                        .consumer_fenced_transition_capability(request.scope(), deadline)
                        .await
                        .map_err(SessionConsumerStoreError::from),
                )
            }
            SessionConsumerOperation::ObserveFencedTransition { key } => {
                drop(admission);
                SessionConsumerResponse::ObserveFencedTransition(
                    self.store
                        .consumer_observe_fenced_transition(request.scope(), &key, deadline)
                        .await
                        .map_err(SessionConsumerStoreError::from),
                )
            }
            SessionConsumerOperation::FencedTransitionStatus {
                request: transition,
            } => {
                drop(admission);
                self.fenced_transition_status(identity, &request, *transition, deadline)
                    .await
            }
            SessionConsumerOperation::Get { key } => {
                drop(admission);
                SessionConsumerResponse::Get(
                    self.store
                        .consumer_get(request.scope(), &key, deadline)
                        .await
                        .map_err(SessionConsumerStoreError::from),
                )
            }
            SessionConsumerOperation::PreflightRecordExpiry { preflights } => {
                drop(admission);
                SessionConsumerResponse::PreflightRecordExpiry(
                    self.store
                        .consumer_preflight_record_expiry(request.scope(), &preflights, deadline)
                        .await
                        .map_err(SessionConsumerStoreError::from),
                )
            }
            SessionConsumerOperation::Batch { ops } => {
                drop(admission);
                self.execute_batch(identity, &request, deadline, ops).await
            }
            SessionConsumerOperation::CompareAndSet { .. }
            | SessionConsumerOperation::DeleteFenced { .. }
            | SessionConsumerOperation::RefreshTtl { .. }
            | SessionConsumerOperation::AcquireLease { .. }
            | SessionConsumerOperation::RenewLease { .. }
            | SessionConsumerOperation::ReleaseLease { .. }
            | SessionConsumerOperation::FencedTransition { .. } => {
                unreachable!("mutation classifier and operation variant disagree")
            }
            SessionConsumerOperation::ScanRestoreRecords { request: scan } => {
                drop(admission);
                SessionConsumerResponse::ScanRestoreRecords(
                    self.store
                        .consumer_scan_restore_records(request.scope(), scan, deadline)
                        .await
                        .map_err(SessionConsumerStoreError::from),
                )
            }
            SessionConsumerOperation::Watch { .. } => SessionConsumerResponse::WatchOpened,
        }
    }

    async fn execute_v2(
        &self,
        _identity: &SessionConsumerIdentity,
        request: SessionConsumerV2Request,
    ) -> SessionConsumerV2Response {
        let deadline = match self.operation_deadline() {
            Ok(deadline) => deadline,
            Err(rejection) => return SessionConsumerV2Response::Rejected(rejection),
        };
        if request.validate().is_err() {
            return SessionConsumerV2Response::Rejected(SessionConsumerRejection::MalformedRequest);
        }
        if let Some(transition) =
            fixed_durable_v2_status_for_batch_dispatch(self.store.inner.topology.mode(), &request)
        {
            // The fixed-quorum status path owns the fresh exact-scope
            // admission immediately before the shared ticket and the
            // post-ticket admission held through its atomic authority/status
            // read. Enter it before the generic detector admission so local
            // arrivals can form one status batch.
            return SessionConsumerV2Response::FencedTransitionV2Status(
                self.store
                    .consumer_fenced_transition_v2_status(request.scope(), transition, deadline)
                    .await
                    .map_err(SessionConsumerStoreError::from)
                    .and_then(SessionConsumerV2FencedTransitionStatus::try_from),
            );
        }
        // This first exact-scope admission is only a detector. Do not hold the
        // read gate while entering a leader proposal/read barrier, where a
        // queued topology writer could otherwise self-block this request.
        let preliminary_admission = if fixed_durable_raw_v2_warm_dispatch(
            self.store.inner.topology.mode(),
            self.store.local_fenced_transition_v2_capability(),
            &request,
        ) {
            self.store
                .admit_consumer_scope_in_memory(request.scope(), deadline)
                .await
        } else {
            self.store
                .admit_consumer_scope(request.scope(), deadline)
                .await
        };
        let admission = match preliminary_admission {
            Ok(admission) => admission,
            Err(rejection) => return SessionConsumerV2Response::Rejected(rejection),
        };
        drop(admission);
        let operation = request.operation().clone();
        let mut effect_may_have_committed = false;
        let response = match operation {
            SessionConsumerV2Operation::FencedTransitionV2Capability => {
                SessionConsumerV2Response::FencedTransitionV2Capability(
                    self.store
                        .fenced_transition_v2_capability()
                        .await
                        .and_then(|capability| {
                            capability.ok_or_else(unsupported_fenced_transition_v2)
                        })
                        .map_err(SessionConsumerStoreError::from),
                )
            }
            SessionConsumerV2Operation::FencedTransitionV2HistoryState => {
                SessionConsumerV2Response::FencedTransitionV2HistoryState(
                    self.store
                        .fenced_transition_v2_history_state()
                        .await
                        .map_err(SessionConsumerStoreError::from),
                )
            }
            SessionConsumerV2Operation::FencedTransitionV2 {
                request: transition,
            } => {
                let result = match self
                    .store
                    .consumer_fenced_transition_v2_before(request.scope(), *transition, deadline)
                    .await
                {
                    Ok((result, committed)) => {
                        effect_may_have_committed = committed;
                        result.map_err(SessionConsumerV2FencedTransitionError::from)
                    }
                    Err(error) => Err(error.into()),
                };
                SessionConsumerV2Response::FencedTransitionV2(result)
            }
            SessionConsumerV2Operation::FencedTransitionV2Batch { requests } => {
                let request_ids = requests
                    .iter()
                    .map(|request| request.request_id())
                    .collect::<Vec<_>>();
                match self
                    .store
                    .consumer_fenced_transition_v2_batch_before(request.scope(), requests, deadline)
                    .await
                {
                    Ok((outcomes, committed)) if outcomes.len() == request_ids.len() => {
                        effect_may_have_committed = committed;
                        let results = request_ids
                            .into_iter()
                            .zip(outcomes)
                            .map(|(request_id, result)| {
                                SessionConsumerV2FencedTransitionBatchResult::new(
                                    request_id,
                                    result.map_err(SessionConsumerV2FencedTransitionError::from),
                                )
                            })
                            .collect();
                        SessionConsumerV2Response::FencedTransitionV2Batch(Ok(results))
                    }
                    Ok(_) | Err(StoreError::FencedTransitionOutcomeUnknown) => {
                        match SessionConsumerV2FencedTransitionBatchError::outcome_unknown(
                            request_ids,
                        ) {
                            Ok(error) => {
                                SessionConsumerV2Response::FencedTransitionV2Batch(Err(error))
                            }
                            Err(rejection) => SessionConsumerV2Response::Rejected(rejection),
                        }
                    }
                    Err(error) => {
                        SessionConsumerV2Response::FencedTransitionV2Batch(Err(error.into()))
                    }
                }
            }
            SessionConsumerV2Operation::FencedTransitionV2Status {
                request: transition,
            } => SessionConsumerV2Response::FencedTransitionV2Status(
                self.store
                    .fenced_transition_v2_status(&transition)
                    .await
                    .map_err(SessionConsumerStoreError::from)
                    .and_then(SessionConsumerV2FencedTransitionStatus::try_from),
            ),
        };
        // The called store method owns its own membership proof; admit the
        // consumer scope once more before returning so a cutover cannot turn a
        // predecessor-scoped request into a successor response.
        match self
            .store
            .admit_consumer_scope(request.scope(), deadline)
            .await
        {
            Ok(admission) => {
                drop(admission);
                response
            }
            Err(rejection) => Self::v2_response_after_scope_loss(
                &request,
                response,
                effect_may_have_committed,
                rejection,
            ),
        }
    }

    async fn watch(
        &self,
        _identity: &SessionConsumerIdentity,
        scope: SessionConsumerScope,
        start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        let deadline = self.operation_deadline()?;
        let admission = self.store.admit_consumer_scope(scope, deadline).await?;
        drop(admission);
        match self
            .store
            .consumer_watch(scope, start_sequence, deadline)
            .await
        {
            Ok(watch) => Ok(watch),
            Err(StoreError::TopologyAuthorityRevoked) => {
                Err(SessionConsumerRejection::ScopeMismatch)
            }
            Err(error @ StoreError::ReplicationWatchCatchUpRequired)
            | Err(error @ StoreError::ReplicationLogCursorCompacted { .. }) => {
                // These are coherent cursor decisions, not transient setup
                // failures. Open the watch and deliver one typed terminal so
                // callers can catch up without a blind reconnect loop.
                Ok(stream::once(async move {
                    Err(consumer_watch_setup_terminal(error)
                        .expect("matched permanent watch setup error"))
                })
                .boxed())
            }
            Err(_) => Err(SessionConsumerRejection::Unavailable),
        }
    }
}

fn consumer_watch_setup_terminal(error: StoreError) -> Option<SessionConsumerStoreError> {
    match error {
        error @ (StoreError::ReplicationWatchCatchUpRequired
        | StoreError::ReplicationLogCursorCompacted { .. }) => {
            Some(SessionConsumerStoreError::from(error))
        }
        _ => None,
    }
}

fn prepared_fenced_transition_storage_commitment(identity: SessionConsensusIdentity) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-store/prepared-consensus-storage/v1\0");
    digest.update(identity.cluster_id().as_bytes());
    digest.update(identity.configuration_id().as_bytes());
    digest.update(identity.configuration_epoch().get().to_be_bytes());
    digest.finalize().into()
}

#[async_trait]
impl SessionBackend for ConsensusSessionStore {
    fn fenced_transition_preserves_protected_payloads(&self) -> bool {
        true
    }

    fn fenced_transition_accepts_prepared_physical_token(
        &self,
        prepared: &PreparedFencedTransition,
    ) -> bool {
        prepared
            .without_outer_protection(PreparedFencedTransitionProtection::ConsensusPhysicalV1 {
                storage_commitment: prepared_fenced_transition_storage_commitment(
                    self.inner.storage_identity,
                ),
            })
            .and_then(|inner| inner.request_for_unprotected_backend())
            .is_ok()
    }

    fn restore_scan_cursor_profile(&self) -> Option<crate::RestoreScanCursorProfile> {
        Some(crate::RestoreScanCursorProfile::DurableOpaqueV1)
    }

    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        Some(BackendInstanceIdentity::for_shared(&self.inner))
    }

    async fn capabilities(&self) -> BackendCapabilities {
        let mut capabilities = self.inner.backend.consensus_capabilities();
        capabilities.ordered_replication_log = true;
        capabilities.watch = true;
        capabilities.restore_scan = true;
        capabilities
    }

    async fn preflight_record_expiry(
        &self,
        preflights: &[RecordExpiryPreflight],
    ) -> Result<(), StoreError> {
        validate_record_expiry_preflights_profile(preflights)?;
        if !preflights
            .iter()
            .copied()
            .any(RecordExpiryPreflight::is_finite)
        {
            return Ok(());
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.preflight_record_expiry_before(preflights, None, deadline)
            .await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        let logical_time = self.logical_read_time_before(None, deadline).await?;
        let record = self
            .inner
            .backend
            .consensus_get_at(key, logical_time)
            .await?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        Ok(record)
    }

    async fn observe_fenced_transition(
        &self,
        key: &SessionKey,
    ) -> Result<FencedTransitionObservation, StoreError> {
        ConsensusSessionStore::observe_fenced_transition(self, key).await
    }

    async fn fenced_transition_capability(
        &self,
    ) -> Result<Option<AtomicFencedTransitionCapability>, StoreError> {
        ConsensusSessionStore::fenced_transition_capability(self).await
    }

    async fn fenced_transition_v2_capability(
        &self,
    ) -> Result<Option<FencedTransitionV2Capability>, StoreError> {
        ConsensusSessionStore::fenced_transition_v2_capability(self).await
    }

    async fn fenced_transition_v2_history_state(
        &self,
    ) -> Result<FencedTransitionV2HistoryState, StoreError> {
        ConsensusSessionStore::fenced_transition_v2_history_state(self).await
    }

    async fn prepare_fenced_transition(
        &self,
        request: FencedTransitionRequest,
    ) -> Result<PreparedFencedTransition, StoreError> {
        validate_consensus_physical_fenced_transition_request(&request)?;
        PreparedFencedTransition::from_unprotected_request(request)?.with_protection(
            PreparedFencedTransitionProtection::ConsensusPhysicalV1 {
                storage_commitment: prepared_fenced_transition_storage_commitment(
                    self.inner.storage_identity,
                ),
            },
        )
    }

    async fn fenced_transition(
        &self,
        prepared: &PreparedFencedTransition,
    ) -> Result<FencedTransitionOutcome, FencedTransitionExecuteError> {
        let request_id = prepared.request_id();
        let prepared = prepared
            .without_outer_protection(PreparedFencedTransitionProtection::ConsensusPhysicalV1 {
                storage_commitment: prepared_fenced_transition_storage_commitment(
                    self.inner.storage_identity,
                ),
            })
            .map_err(|_| FencedTransitionExecuteError::NotTransmitted)?;
        let request = prepared
            .request_for_unprotected_backend()
            .map_err(|_| FencedTransitionExecuteError::NotTransmitted)?;
        match ConsensusSessionStore::fenced_transition(self, request).await {
            Ok(outcome) => Ok(outcome),
            Err(StoreError::FencedTransitionOutcomeUnknown) => {
                Err(FencedTransitionExecuteError::OutcomeUnknown { request_id })
            }
            Err(error) => Err(FencedTransitionExecuteError::Rejected(error)),
        }
    }

    async fn fenced_transition_v2(
        &self,
        request: FencedTransitionV2Request,
    ) -> Result<FencedTransitionOutcome, StoreError> {
        ConsensusSessionStore::fenced_transition_v2(self, request).await
    }

    async fn fenced_transition_v2_effect(
        &self,
        request: FencedTransitionV2Request,
    ) -> FencedTransitionV2Effect<Result<FencedTransitionOutcome, StoreError>> {
        let request_id = request.request_id();
        let deadline = match tokio::time::Instant::now().checked_add(self.inner.operation_timeout) {
            Some(deadline) => deadline,
            None => return FencedTransitionV2Effect::NotTransmitted(consensus_unavailable()),
        };
        match self
            .fenced_transition_v2_submission_effect_before(request, None, deadline)
            .await
        {
            ConsensusSubmissionEffect::NotTransmitted(error) => {
                FencedTransitionV2Effect::NotTransmitted(error)
            }
            ConsensusSubmissionEffect::OutcomeUnknown => FencedTransitionV2Effect::OutcomeUnknown {
                request_ids: vec![request_id],
            },
            ConsensusSubmissionEffect::Committed(response) => match response.result {
                Ok(SessionMutationOutcome::FencedTransition(outcome)) => {
                    FencedTransitionV2Effect::Resolved(Ok(outcome))
                }
                Err(error) => FencedTransitionV2Effect::Resolved(Err(error)),
                Ok(_) => FencedTransitionV2Effect::OutcomeUnknown {
                    request_ids: vec![request_id],
                },
            },
            ConsensusSubmissionEffect::Rejected(response) => match response.result {
                Err(error) => FencedTransitionV2Effect::NotTransmitted(error),
                Ok(_) => FencedTransitionV2Effect::OutcomeUnknown {
                    request_ids: vec![request_id],
                },
            },
        }
    }

    async fn fenced_transition_v2_batch(
        &self,
        requests: Vec<FencedTransitionV2Request>,
    ) -> Result<Vec<Result<FencedTransitionOutcome, StoreError>>, StoreError> {
        ConsensusSessionStore::fenced_transition_v2_batch(self, requests).await
    }

    async fn fenced_transition_v2_batch_effect(
        &self,
        requests: Vec<FencedTransitionV2Request>,
    ) -> FencedTransitionV2Effect<
        Result<Vec<Result<FencedTransitionOutcome, StoreError>>, StoreError>,
    > {
        if let Err(error) = validate_fenced_transition_v2_batch(&requests) {
            return FencedTransitionV2Effect::Resolved(Err(error));
        }
        let request_ids = requests
            .iter()
            .map(FencedTransitionV2Request::request_id)
            .collect::<Vec<_>>();
        let deadline = match tokio::time::Instant::now().checked_add(self.inner.operation_timeout) {
            Some(deadline) => deadline,
            None => return FencedTransitionV2Effect::NotTransmitted(consensus_unavailable()),
        };
        let effect = self
            .fenced_transition_v2_batch_submission_effect_before(requests, None, deadline)
            .await;
        // The internal path constructs every ambiguity with the original
        // validated request set. Retain all if an implementation ever loses
        // that proof rather than deleting a subset of mappings.
        match effect {
            FencedTransitionV2Effect::OutcomeUnknown {
                request_ids: effect_ids,
            } if effect_ids == request_ids => FencedTransitionV2Effect::OutcomeUnknown {
                request_ids: effect_ids,
            },
            FencedTransitionV2Effect::OutcomeUnknown { .. } => {
                FencedTransitionV2Effect::OutcomeUnknown { request_ids }
            }
            effect => effect,
        }
    }

    async fn fenced_transition_status(
        &self,
        prepared: &PreparedFencedTransition,
    ) -> Result<FencedTransitionStatus, StoreError> {
        let prepared = prepared.without_outer_protection(
            PreparedFencedTransitionProtection::ConsensusPhysicalV1 {
                storage_commitment: prepared_fenced_transition_storage_commitment(
                    self.inner.storage_identity,
                ),
            },
        )?;
        let request = prepared.request_for_unprotected_backend()?;
        ConsensusSessionStore::fenced_transition_status(self, &request).await
    }

    async fn fenced_transition_v2_status(
        &self,
        request: &FencedTransitionV2Request,
    ) -> Result<FencedTransitionV2Status, StoreError> {
        ConsensusSessionStore::fenced_transition_v2_status(self, request).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        let response = self
            .submit_intent(SessionMutationIntent::CompareAndSet(Box::new(op)))
            .await?;
        match response.result? {
            SessionMutationOutcome::CompareAndSet(result) => Ok(result),
            _ => Err(StoreError::CasIdempotencyOutcomeUnavailable),
        }
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        let response = self
            .submit_intent(SessionMutationIntent::DeleteFenced(lease.clone()))
            .await?;
        match response.result? {
            SessionMutationOutcome::Unit => Ok(()),
            _ => Err(StoreError::BackendOperationOutcomeUnavailable),
        }
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        validate_session_ttl(ttl)?;
        checked_session_deadline(self.inner.clock.now_utc(), ttl)?;
        let response = self
            .submit_intent(SessionMutationIntent::RefreshTtl {
                lease: lease.clone(),
                ttl,
            })
            .await?;
        match response.result? {
            SessionMutationOutcome::Unit => Ok(()),
            _ => Err(StoreError::BackendOperationOutcomeUnavailable),
        }
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        let preflights = record_expiry_preflights(&ops)?;
        validate_consensus_batch(&ops)?;
        self.preflight_record_expiry(&preflights).await?;
        let mut results = Vec::with_capacity(ops.len());
        for op in ops {
            results.push(match op {
                SessionOp::Get { key } => SessionOpResult::Get(self.get(&key).await),
                SessionOp::CompareAndSet(op) => {
                    SessionOpResult::CompareAndSet(self.compare_and_set(op).await)
                }
                SessionOp::DeleteFenced { lease } => {
                    SessionOpResult::DeleteFenced(self.delete_fenced(&lease).await)
                }
                SessionOp::RefreshTtl { lease, ttl } => {
                    SessionOpResult::RefreshTtl(self.refresh_ttl(&lease, ttl).await)
                }
            });
        }
        Ok(results)
    }

    async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        request.validate()?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
        let logical_time =
            tokio::time::timeout_at(deadline, self.logical_read_time_before(None, deadline))
                .await
                .map_err(|_| StoreError::RestoreScanWorkBudgetExceeded)??;
        let page = self
            .inner
            .backend
            .consensus_scan_restore_records_at(request, logical_time, deadline)
            .await?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        Ok(page)
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.logical_read_time_before(None, deadline).await?;
        let sequence = self
            .inner
            .backend
            .consensus_max_replication_sequence()
            .await?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        Ok(sequence)
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let range = ReplicationLogRange::try_new(start, limit)?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        if range.is_empty() {
            return Ok(Vec::new());
        }
        self.logical_read_time_before(None, deadline).await?;
        let entries = validate_replication_log_page_owned(
            start,
            limit,
            self.inner
                .backend
                .consensus_get_replication_log(start, limit)
                .await?,
        )?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        Ok(entries)
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let _ = entry.into_validated()?;
        Err(StoreError::CapabilityNotSupported(
            "direct_replication_authority".into(),
        ))
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        let _ = validate_replication_prefix_owned(entries)?;
        Err(StoreError::CapabilityNotSupported(
            "direct_rebuild_authority".into(),
        ))
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<BoxStream<'static, Result<ReplicationEntry, StoreError>>, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.require_durable_fixed_quorum_admission_before(deadline)
            .await?;
        self.logical_read_time().await?;
        let stream = self.inner.backend.consensus_watch(start_sequence).await?;
        let store = self.clone();
        Ok(futures_util::stream::unfold(
            (stream, store, false),
            |(mut stream, store, terminated)| async move {
                if terminated {
                    return None;
                }
                loop {
                    let entry = if store.inner.topology.mode()
                        == QuorumTopologyMode::FixedDurableQuorum
                    {
                        tokio::select! {
                            entry = stream.next() => entry?,
                            () = tokio::time::sleep(GENERIC_WATCH_AUTHORITY_RECHECK_INTERVAL) => {
                                let deadline = tokio::time::Instant::now()
                                    .checked_add(store.inner.operation_timeout)?;
                                if store.fixed_watch_authority_before(deadline).await.is_err() {
                                    return Some((Err(consensus_unavailable()), (stream, store, true)));
                                }
                                continue;
                            }
                        }
                    } else {
                        stream.next().await?
                    };
                    let deadline = tokio::time::Instant::now()
                        .checked_add(store.inner.operation_timeout)?;
                    let admission = store.fixed_watch_authority_before(deadline).await;
                    let terminated = admission.is_err();
                    return Some((admission.and(entry), (stream, store, terminated)));
                }
            },
        )
        .boxed())
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "external_lease_sequencing".into(),
        ))
    }
}

#[async_trait]
impl SessionLeaseManager for ConsensusSessionStore {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        checked_session_deadline(self.inner.clock.now_utc(), ttl).map_err(LeaseError::from)?;
        let response = self
            .submit_intent(SessionMutationIntent::AcquireLease {
                key: key.clone(),
                owner,
                ttl,
            })
            .await
            .map_err(LeaseError::from)?;
        match response.result.map_err(LeaseError::from)? {
            SessionMutationOutcome::Lease(guard) => Ok(guard),
            _ => Err(LeaseError::OperationOutcomeUnavailable),
        }
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        checked_session_deadline(self.inner.clock.now_utc(), ttl).map_err(LeaseError::from)?;
        let response = self
            .submit_intent(SessionMutationIntent::RenewLease {
                lease: lease.clone(),
                ttl,
            })
            .await
            .map_err(LeaseError::from)?;
        match response.result.map_err(LeaseError::from)? {
            SessionMutationOutcome::Lease(guard) => Ok(guard),
            _ => Err(LeaseError::OperationOutcomeUnavailable),
        }
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        let response = self
            .submit_intent(SessionMutationIntent::ReleaseLease(lease))
            .await
            .map_err(LeaseError::from)?;
        match response.result.map_err(LeaseError::from)? {
            SessionMutationOutcome::Unit => Ok(()),
            _ => Err(LeaseError::OperationOutcomeUnavailable),
        }
    }
}

#[cfg(test)]
mod membership_tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use bytes::Bytes;
    use futures_util::{FutureExt, StreamExt};
    use opc_consensus::engine::{CommittedLeaderId, Membership};
    use opc_consensus::{
        derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
    };
    use opc_crypto::CryptoEnvelopeV1;
    use opc_key::{
        serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyId, KeyPurpose, MemoryKeyProvider,
        SessionAad, Zeroizing, AEAD_TAG_LEN, AES_256_GCM_SIV_KEY_LEN, AES_256_GCM_SIV_NONCE_LEN,
    };

    use super::*;
    use crate::backend::ReplicationOp;
    use crate::model::{FenceToken, Generation, SessionKeyType, StateClass, StateType};
    use crate::record::EncryptedSessionPayload;
    use crate::topology::{
        QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
        ReplicaId, ReplicaTlsIdentity,
    };

    async fn wait_for_log_index_after(
        store: &ConsensusSessionStore,
        before: u64,
        context: &'static str,
    ) {
        let mut metrics = store.inner.raft.metrics();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if metrics.borrow().last_log_index > Some(before) {
                    return;
                }
                metrics
                    .changed()
                    .await
                    .expect("Openraft metrics remain available");
            }
        })
        .await
        .unwrap_or_else(|_| panic!("Openraft log did not advance: {context}"));
    }

    #[test]
    fn diagnostic_snapshot_maps_each_fixed_counter_without_sensitive_output() {
        let counters = ConsensusStoreDiagnosticCounters::default();
        counters.increment_sqlite_worker_permit_deadline();
        counters.increment_sqlite_connection_lock_deadline();
        counters.increment_sqlite_execution_deadline();
        counters
            .proposal_permit_deadline
            .fetch_add(4, Ordering::Relaxed);
        counters
            .raw_read_barrier_unavailable
            .fetch_add(5, Ordering::Relaxed);
        counters
            .raw_read_barrier_deadline
            .fetch_add(6, Ordering::Relaxed);
        counters
            .atomic_v2_authority_snapshot_backend_error
            .fetch_add(7, Ordering::Relaxed);
        counters
            .atomic_v2_authority_snapshot_deadline
            .fetch_add(8, Ordering::Relaxed);
        counters
            .client_write_ff_preaccept_failure
            .fetch_add(9, Ordering::Relaxed);
        counters.route_deadline.fetch_add(10, Ordering::Relaxed);
        counters
            .route_metrics_watch_closed
            .fetch_add(11, Ordering::Relaxed);

        let snapshot = counters.snapshot();
        assert_eq!(
            snapshot,
            ConsensusStoreDiagnosticSnapshot {
                sqlite_worker_permit_deadline: 1,
                sqlite_connection_lock_deadline: 1,
                sqlite_execution_deadline: 1,
                proposal_permit_deadline: 4,
                raw_read_barrier_unavailable: 5,
                raw_read_barrier_deadline: 6,
                atomic_v2_authority_snapshot_backend_error: 7,
                atomic_v2_authority_snapshot_deadline: 8,
                client_write_ff_preaccept_failure: 9,
                route_deadline: 10,
                route_metrics_watch_closed: 11,
                ..ConsensusStoreDiagnosticSnapshot::default()
            }
        );
        let debug = format!("{snapshot:?}");
        let encoded = serde_json::to_string(&snapshot).expect("encode diagnostic snapshot");
        for forbidden in ["secret", "scope", "sqlite_error", "SELECT", "127.0.0.1"] {
            assert!(!debug.contains(forbidden));
            assert!(!encoded.contains(forbidden));
        }
        assert!(encoded.contains("sqlite_worker_permit_deadline"));
        assert!(encoded.contains("route_metrics_watch_closed"));
    }
    use crate::{
        FencedTransitionLease, FencedTransitionMutation, FencedTransitionMutationResult,
        FencedTransitionOutcome, FencedTransitionRequestId, FencedTransitionV2CallerNonce,
        FencedTransitionV2HistoryEpoch, FencedTransitionV2Request, FencedTransitionV2Status,
        SessionConsumerRequestId,
    };
    use opc_types::{NetworkFunctionKind, TenantId};

    fn node(value: u64) -> SessionConsensusNodeId {
        SessionConsensusNodeId::new(value).expect("valid test consensus node ID")
    }

    fn status_ticket_scope(epoch: u64) -> SessionConsensusIdentity {
        SessionConsensusIdentity::new(
            crate::SessionConsensusClusterId::from_bytes([0x4A; 32]),
            crate::SessionConsensusConfigurationId::from_bytes([0xB4; 32]),
            SessionConsensusConfigurationEpoch::new(epoch).expect("status ticket scope epoch"),
        )
    }

    fn status_ticket_reply(
        required_consumer_scope: SessionConsensusIdentity,
        raft_log_index: u64,
    ) -> FencedTransitionV2StatusLogicalTimeTicketReply {
        FencedTransitionV2StatusLogicalTimeTicketReply::Ticket(Box::new(
            FencedTransitionV2StatusLogicalTimeTicket {
                required_consumer_scope,
                raft_log_index,
                logical_time: Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
            },
        ))
    }

    #[test]
    fn permanent_consumer_watch_setup_errors_remain_typed_terminals() {
        assert_eq!(
            consumer_watch_setup_terminal(StoreError::ReplicationWatchCatchUpRequired),
            Some(SessionConsumerStoreError::WatchCatchUpRequired)
        );
        assert_eq!(
            consumer_watch_setup_terminal(StoreError::ReplicationLogCursorCompacted {
                resume_from: 7,
            }),
            Some(SessionConsumerStoreError::InvalidInput)
        );
        assert_eq!(
            consumer_watch_setup_terminal(StoreError::BackendUnavailable(
                "fixed test unavailable".into(),
            )),
            None,
            "only coherent permanent cursor decisions bypass transient setup rejection"
        );
    }

    #[derive(Debug)]
    struct MutableClock(Mutex<Timestamp>);

    impl MutableClock {
        fn new(now: Timestamp) -> Self {
            Self(Mutex::new(now))
        }

        fn set(&self, now: Timestamp) {
            *self.0.lock().expect("clock lock") = now;
        }
    }

    impl Clock for MutableClock {
        fn now_utc(&self) -> Timestamp {
            *self.0.lock().expect("clock lock")
        }
    }

    fn stored_membership(
        configs: Vec<BTreeSet<SessionConsensusNodeId>>,
        nodes: BTreeSet<SessionConsensusNodeId>,
    ) -> StoredMembership<SessionConsensusNodeId, EmptyNode> {
        let membership: Membership<SessionConsensusNodeId, EmptyNode> =
            Membership::new(configs, nodes);
        StoredMembership::new(
            Some(LogId::new(CommittedLeaderId::new(1, node(1)), 0)),
            membership,
        )
    }

    fn singleton_topology() -> ValidatedQuorumTopology {
        let replica_id = ReplicaId::new("membership-admission-singleton").expect("replica ID");
        let descriptor = QuorumReplicaDescriptor::new(
            replica_id.clone(),
            ReplicaEndpoint::new("membership-admission.invalid", 7443).expect("endpoint"),
            ReplicaTlsIdentity::new("spiffe://test/session/membership-admission")
                .expect("TLS identity"),
            ReplicaFailureDomain::new("membership-admission-zone").expect("failure domain"),
            ReplicaBackingIdentity::new("membership-admission-disk").expect("backing identity"),
        );
        let cluster_id =
            ConsensusClusterId::new("session-membership-admission-tests").expect("cluster ID");
        let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
        let configuration_id =
            derive_configuration_id(cluster_id, epoch, &[descriptor.configuration_fingerprint()]);
        ValidatedQuorumTopology::try_new_consensus_lab_singleton(
            replica_id,
            vec![descriptor],
            ConsensusIdentity::new(cluster_id, configuration_id, epoch),
        )
        .expect("singleton topology")
    }

    #[tokio::test]
    async fn consensus_session_store_debug_is_fixed_and_redacts_topology_identity() {
        let directory = tempfile::tempdir().expect("debug canary directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("debug canary SQLite backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open debug canary store");
        let node_ordinal = store.inner.local_node_id.get().to_string();
        let configuration_epoch = store
            .inner
            .storage_identity
            .configuration_epoch()
            .get()
            .to_string();

        let rendered = format!("{store:?}");
        assert!(
            rendered == "ConsensusSessionStore(<redacted>)",
            "consensus store Debug must remain fixed and redacted"
        );
        for canary in [
            "storage_identity",
            "ConsensusIdentity",
            "local_node_id",
            "ConsensusNodeId",
            "configuration_epoch",
            "peer_directory",
            node_ordinal.as_str(),
            configuration_epoch.as_str(),
        ] {
            assert!(
                !rendered.contains(canary),
                "consensus store Debug exposed a topology identity canary"
            );
        }
    }

    fn forged_operator_recovery_intent(seed: u8) -> SessionMutationIntent {
        SessionMutationIntent::FinalizeOperatorRecovery {
            recovery_epoch: 1,
            plan_digest: [seed; 32],
            fence_high_water: 7,
            credential_high_water: 9,
        }
    }

    fn durable_recovery_epoch(
        database: &std::path::Path,
        identity: SessionConsensusIdentity,
    ) -> u64 {
        let connection = rusqlite::Connection::open(database).expect("open recovery state");
        crate::sqlite::consensus::read_operator_recovery_sync(&connection, identity)
            .expect("read recovery state")
            .recovery_epoch
    }

    #[test]
    fn exact_membership_requires_one_uniform_config_and_no_learners() {
        let configured = [node(1), node(2), node(3)]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let exact = stored_membership(vec![configured.clone()], configured.clone());
        assert!(exact_uniform_voter_membership(&exact, &configured));

        let subset = [node(1), node(2)].into_iter().collect::<BTreeSet<_>>();
        let subset_membership = stored_membership(vec![subset.clone()], subset);
        assert!(!exact_uniform_voter_membership(
            &subset_membership,
            &configured
        ));

        let joint_left = [node(1), node(2)].into_iter().collect::<BTreeSet<_>>();
        let joint_right = [node(2), node(3)].into_iter().collect::<BTreeSet<_>>();
        let joint = stored_membership(vec![joint_left, joint_right], configured.clone());
        assert!(!exact_uniform_voter_membership(&joint, &configured));

        let mut voter_and_learner_nodes = configured.clone();
        voter_and_learner_nodes.insert(node(4));
        let learner = stored_membership(vec![configured.clone()], voter_and_learner_nodes);
        assert!(!exact_uniform_voter_membership(&learner, &configured));

        let without_durable_log = StoredMembership::new(
            None,
            Membership::<SessionConsensusNodeId, EmptyNode>::new(
                vec![configured.clone()],
                configured.clone(),
            ),
        );
        assert!(!exact_uniform_voter_membership(
            &without_durable_log,
            &configured
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn attestation_deadline_is_anchored_before_verification_work() {
        let verification_started_at = tokio::time::Instant::now();
        tokio::time::advance(Duration::from_millis(400)).await;

        let deadline = attestation_deadline_from_verification_start(
            verification_started_at,
            Duration::from_secs(1),
        )
        .expect("representable attestation deadline");

        assert_eq!(
            deadline.saturating_duration_since(tokio::time::Instant::now()),
            Duration::from_millis(600),
            "verification work must consume the original validity budget"
        );
    }

    #[test]
    fn corrupt_durable_state_is_typed_as_recovery_required() {
        assert_eq!(
            ConsensusSessionStoreOpenError::RecoveryRequired,
            ConsensusSessionStoreOpenError::from(SessionConsensusStorageError::CorruptState)
        );
    }

    #[test]
    fn forwarded_expiry_preflight_is_bounded_during_deserialization() {
        let key = SessionKey {
            tenant: TenantId::new("preflight-bound").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"preflight-bound")
                .try_into()
                .expect("stable ID"),
        };
        let descriptor = RecordExpiryPreflight::from_record(&StoredSessionRecord {
            key,
            generation: Generation::new(1),
            owner: OwnerId::new("preflight-bound-owner").expect("owner"),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("preflight-bound"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"must-not-cross-preflight"),
        });
        let required_scope = SessionConsensusIdentity::new(
            crate::SessionConsensusClusterId::from_bytes([0x31; 32]),
            crate::SessionConsensusConfigurationId::from_bytes([0x32; 32]),
            SessionConsensusConfigurationEpoch::new(7).expect("consumer scope epoch"),
        );
        let exact = ForwardRequest::RecordExpiryPreflight {
            preflights: BoundedRecordExpiryPreflights::try_from_slice(&vec![
                descriptor;
                MAX_RECORD_EXPIRY_PREFLIGHTS
            ])
            .expect("exact bound"),
            required_consumer_scope: ForwardConsumerScope::Consumer(Box::new(required_scope)),
        };
        let mut encoded = serde_json::to_value(exact).expect("encode exact preflight");
        let decoded: ForwardRequest =
            serde_json::from_value(encoded.clone()).expect("decode exact preflight");
        assert!(matches!(
            decoded,
            ForwardRequest::RecordExpiryPreflight {
                preflights,
                required_consumer_scope: ForwardConsumerScope::Consumer(scope),
            } if preflights.0.len() == MAX_RECORD_EXPIRY_PREFLIGHTS
                && *scope == required_scope
        ));
        let mut missing_scope = encoded.clone();
        missing_scope["RecordExpiryPreflight"]
            .as_object_mut()
            .expect("forwarded preflight object")
            .remove("required_consumer_scope");
        assert!(serde_json::from_value::<ForwardRequest>(missing_scope).is_err());
        let rendered = encoded.to_string();
        for forbidden in ["stable_id", "payload", "owner", "generation", "fence"] {
            assert!(!rendered.contains(forbidden));
        }

        let values = encoded["RecordExpiryPreflight"]["preflights"]
            .as_array_mut()
            .expect("preflight array");
        values.push(values[0].clone());
        assert!(serde_json::from_value::<ForwardRequest>(encoded).is_err());
    }

    #[test]
    fn expiry_preflight_uses_committed_logical_time_and_fails_closed_when_absent() {
        let proposed_time = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let expires_at = checked_session_deadline(proposed_time, crate::MAX_SESSION_TTL)
            .expect("maximum expiry");
        let record = StoredSessionRecord {
            key: SessionKey {
                tenant: TenantId::new("concurrent-expiry-floor").expect("tenant"),
                nf_kind: NetworkFunctionKind::smf(),
                key_type: SessionKeyType::PduSession,
                stable_id: Bytes::from_static(b"concurrent-expiry-floor")
                    .try_into()
                    .expect("stable ID"),
            },
            generation: Generation::new(1),
            owner: OwnerId::new("concurrent-expiry-owner").expect("owner"),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("concurrent-expiry-floor"),
            expires_at: Some(expires_at),
            payload: EncryptedSessionPayload::new(b"payload-free-preflight"),
        };
        let preflights = [RecordExpiryPreflight::from_record(&record)];
        let intent = SessionMutationIntent::AdvanceLogicalTime;
        let response = |logical_time| SessionConsensusResponse {
            result: Ok(SessionMutationOutcome::Unit),
            sequence: 1,
            digest: Some(crate::consensus::SessionConsensusEntryDigest::from_bytes(
                [0x4d; 32],
            )),
            logical_time: Some(logical_time),
            raft_log_index: 1,
        };

        validate_committed_record_expiry_preflight(&preflights, &intent, &response(proposed_time))
            .expect("proposal-time verdict remains valid at the same committed time");

        let concurrently_advanced = Timestamp::from_offset_datetime(
            proposed_time
                .as_offset_datetime()
                .checked_add(time::Duration::nanoseconds(1))
                .expect("one nanosecond later"),
        );
        validate_committed_record_expiry_preflight(
            &preflights,
            &intent,
            &response(concurrently_advanced),
        )
        .expect("a newer committed floor preserves the maximum-TTL upper bound");

        let mut missing_authority = response(concurrently_advanced);
        missing_authority.logical_time = None;
        assert!(matches!(
            validate_committed_record_expiry_preflight(&preflights, &intent, &missing_authority,),
            Err(StoreError::BackendUnavailable(_))
        ));
    }

    #[test]
    fn forwarded_mutation_responses_are_bound_to_the_exact_intent() {
        let key = |stable_id: &'static [u8]| SessionKey {
            tenant: TenantId::new("forward-response-binding").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(stable_id).try_into().expect("stable ID"),
        };
        let key_a = key(b"key-a");
        let key_b = key(b"key-b");
        let owner_a = OwnerId::new("owner-a").expect("owner");
        let owner_b = OwnerId::new("owner-b").expect("owner");
        let logical_time = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let ttl = Duration::from_secs(60);
        let expires_at = checked_session_deadline(logical_time, ttl).expect("lease deadline");
        let lease_a = LeaseGuard::new(
            key_a.clone(),
            owner_a.clone(),
            FenceToken::new(7),
            logical_time,
            expires_at,
            9,
        );
        let record = |key: SessionKey| StoredSessionRecord {
            key,
            generation: Generation::new(1),
            owner: owner_a.clone(),
            fence: lease_a.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("forward-response-binding").expect("state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(Bytes::from_static(b"payload")),
        };
        let cas = CompareAndSet {
            key: key_a.clone(),
            lease: lease_a.clone(),
            expected_generation: None,
            new_record: record(key_a.clone()),
        };
        let committed = |result| SessionConsensusResponse {
            result,
            sequence: 1,
            digest: Some(crate::consensus::SessionConsensusEntryDigest::from_bytes(
                [0x5a; 32],
            )),
            logical_time: Some(logical_time),
            raft_log_index: 1,
        };

        let rejected =
            SessionConsensusResponse::rejected(StoreError::PayloadTooLarge { actual: 2, max: 1 });
        assert!(rejected_response_matches_intent(
            &SessionMutationIntent::AdvanceLogicalTime,
            &rejected
        ));
        assert!(!committed_response_matches_intent(
            &SessionMutationIntent::AdvanceLogicalTime,
            &rejected
        ));
        assert!(!rejected_response_matches_intent(
            &SessionMutationIntent::AdvanceLogicalTime,
            &SessionConsensusResponse::rejected(StoreError::BackendOperationOutcomeUnavailable)
        ));

        let cas_intent = SessionMutationIntent::CompareAndSet(Box::new(cas));
        assert!(rejected_response_matches_intent(
            &cas_intent,
            &SessionConsensusResponse::rejected(StoreError::InvalidRecordExpiry)
        ));
        assert!(!rejected_response_matches_intent(
            &SessionMutationIntent::DeleteFenced(lease_a.clone()),
            &SessionConsensusResponse::rejected(StoreError::InvalidRecordExpiry)
        ));
        assert!(!committed_response_matches_intent(
            &cas_intent,
            &committed(Ok(SessionMutationOutcome::Unit))
        ));

        let SessionMutationIntent::CompareAndSet(cas) = &cas_intent else {
            unreachable!("CAS intent changed variant")
        };
        let mut invalid_cas = cas.as_ref().clone();
        invalid_cas.new_record.expires_at = Some(Timestamp::from_offset_datetime(
            checked_session_deadline(logical_time, crate::MAX_SESSION_TTL)
                .expect("maximum record expiry")
                .as_offset_datetime()
                .checked_add(time::Duration::nanoseconds(1))
                .expect("maximum plus one"),
        ));
        let invalid_command = crate::consensus::SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: singleton_topology()
                .consensus_identity()
                .expect("consensus topology identity"),
            request_id: SessionConsensusRequestId::new(),
            logical_time,
            intent: SessionMutationIntent::CompareAndSet(Box::new(invalid_cas)),
        };
        assert_eq!(
            validate_consensus_command_preproposal(&invalid_command),
            Err(StoreError::InvalidRecordExpiry)
        );
        assert!(!committed_response_matches_intent(
            &cas_intent,
            &committed(Err(StoreError::CasConflict))
        ));
        assert!(!committed_response_matches_intent(
            &cas_intent,
            &committed(Ok(SessionMutationOutcome::CompareAndSet(
                CompareAndSetResult::Conflict {
                    current: Some(record(key_b)),
                },
            )))
        ));
        assert!(committed_response_matches_intent(
            &cas_intent,
            &committed(Ok(SessionMutationOutcome::CompareAndSet(
                CompareAndSetResult::Conflict {
                    current: Some(consumer_record_with_payload_len(
                        &key_a,
                        &lease_a,
                        64 * 1024,
                    )),
                },
            )))
        ));

        assert!(!committed_response_matches_intent(
            &SessionMutationIntent::ReleaseLease(lease_a.clone()),
            &committed(Err(StoreError::LeaseExpired))
        ));

        let acquire = SessionMutationIntent::AcquireLease {
            key: key_a.clone(),
            owner: owner_a.clone(),
            ttl,
        };
        assert!(committed_response_matches_intent(
            &acquire,
            &committed(Ok(SessionMutationOutcome::Lease(lease_a.clone())))
        ));
        let forged_acquire = LeaseGuard::new(
            key_a.clone(),
            owner_b,
            lease_a.fence(),
            logical_time,
            expires_at,
            lease_a.credential_id(),
        );
        assert!(!committed_response_matches_intent(
            &acquire,
            &committed(Ok(SessionMutationOutcome::Lease(forged_acquire)))
        ));

        let renew = SessionMutationIntent::RenewLease {
            lease: lease_a.clone(),
            ttl,
        };
        for revoked_intent in [
            cas_intent.clone(),
            SessionMutationIntent::DeleteFenced(lease_a.clone()),
            SessionMutationIntent::RefreshTtl {
                lease: lease_a.clone(),
                ttl,
            },
            acquire.clone(),
            renew.clone(),
            SessionMutationIntent::ReleaseLease(lease_a.clone()),
        ] {
            assert!(committed_response_matches_intent(
                &revoked_intent,
                &committed(Err(StoreError::TopologyAuthorityRevoked)),
            ));
        }
        assert!(!committed_response_matches_intent(
            &SessionMutationIntent::AdvanceLogicalTime,
            &committed(Err(StoreError::TopologyAuthorityRevoked)),
        ));
        assert!(committed_response_matches_intent(
            &renew,
            &committed(Ok(SessionMutationOutcome::Lease(lease_a.clone())))
        ));
        let forged_renew = LeaseGuard::new(
            key_a,
            owner_a,
            lease_a.fence(),
            lease_a.acquired_at(),
            expires_at,
            lease_a.credential_id() + 1,
        );
        assert!(!committed_response_matches_intent(
            &renew,
            &committed(Ok(SessionMutationOutcome::Lease(forged_renew)))
        ));
    }

    #[test]
    fn preproposal_rejects_a_consensus_record_above_the_retained_cap() {
        let logical_time = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let key = SessionKey {
            tenant: TenantId::new("preproposal-cap").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"preproposal-cap")
                .try_into()
                .expect("stable ID"),
        };
        let owner = OwnerId::new("preproposal-cap-owner").expect("owner");
        let lease = LeaseGuard::new(
            key.clone(),
            owner.clone(),
            FenceToken::new(1),
            logical_time,
            checked_session_deadline(logical_time, Duration::from_secs(60))
                .expect("lease deadline"),
            1,
        );
        let mut new_record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner: owner.clone(),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("preproposal-cap"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([]),
        };
        let key_id = KeyId::new("preproposal-cap-key").expect("key ID");
        let aad = EnvelopeAad::session(
            new_record.key.tenant.clone(),
            1,
            SessionAad::new(
                new_record.key.nf_kind.as_str(),
                "preproposal-cap-keyed-session-digest",
                new_record.state_type.as_str(),
                new_record.generation.get(),
                new_record.fence.get(),
                "preproposal-cap-backend",
            )
            .expect("session AAD"),
        );
        let envelope = |opaque_len| CryptoEnvelopeV1 {
            algorithm: AeadAlgorithm::Aes256GcmSiv,
            key_id: key_id.clone(),
            nonce: vec![0x42; AES_256_GCM_SIV_NONCE_LEN],
            aad: serialize_bound_aad(&aad, &key_id).expect("bound AAD"),
            ciphertext_and_tag: {
                let mut ciphertext_and_tag = vec![0x5a; opaque_len];
                ciphertext_and_tag.extend_from_slice(&[0xa5; AEAD_TAG_LEN]);
                ciphertext_and_tag
            },
        };
        let payload_len = crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES + 1;
        let envelope_overhead = envelope(0).encode().expect("empty envelope").len();
        let encoded = envelope(payload_len - envelope_overhead)
            .encode()
            .expect("oversized envelope");
        assert_eq!(encoded.len(), payload_len);
        new_record.payload = EncryptedSessionPayload::try_envelope(encoded)
            .expect("bounded oversized envelope fixture");
        let command = crate::consensus::SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: singleton_topology()
                .consensus_identity()
                .expect("consensus topology identity"),
            request_id: SessionConsensusRequestId::new(),
            logical_time,
            intent: SessionMutationIntent::CompareAndSet(Box::new(CompareAndSet {
                key: key.clone(),
                lease,
                expected_generation: None,
                new_record,
            })),
        };

        assert_eq!(
            validate_consensus_command_preproposal(&command),
            Err(StoreError::PayloadTooLarge {
                actual: crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES + 1,
                max: crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES,
            })
        );
    }

    #[test]
    fn preproposal_binds_the_outer_request_id_to_the_complete_fenced_transition() {
        let logical_time = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let key = SessionKey {
            tenant: TenantId::new("fenced-request-binding").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"fenced-request-binding")
                .try_into()
                .expect("stable ID"),
        };
        let owner = OwnerId::new("fenced-request-binding-owner").expect("owner");
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x41; 16]),
            FencedTransitionLease::acquire(
                key.clone(),
                owner.clone(),
                FenceToken::new(0),
                Duration::from_secs(60),
            )
            .expect("lease action"),
            FencedTransitionMutation::create(StoredSessionRecord {
                key,
                generation: Generation::new(1),
                owner,
                fence: FenceToken::new(1),
                state_class: StateClass::AuthoritativeSession,
                state_type: StateType::from_static("fenced-request-binding"),
                expires_at: None,
                payload: EncryptedSessionPayload::new([]),
            }),
        )
        .expect("transition request");
        let identity = singleton_topology()
            .consensus_identity()
            .expect("consensus identity");
        let command = crate::consensus::SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity,
            request_id: SessionConsensusRequestId::from_bytes([0x42; 16]),
            logical_time,
            intent: SessionMutationIntent::Authorized {
                origin: node(1),
                authority_identity: identity,
                mutation: Box::new(SessionMutationIntent::FencedTransition(Box::new(request))),
            },
        };

        assert_eq!(
            validate_consensus_command_preproposal(&command),
            Err(StoreError::InvalidKey(
                "fenced_transition_request_id_mismatch".into()
            ))
        );
    }

    fn v2_test_request(epoch: u64) -> FencedTransitionV2Request {
        let key = SessionKey {
            tenant: TenantId::new("fenced-v2-request-binding").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"fenced-v2-request-binding")
                .try_into()
                .expect("stable ID"),
        };
        let owner = OwnerId::new("fenced-v2-request-binding-owner").expect("owner");
        FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(epoch).expect("nonzero epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0x51; 16]),
            FencedTransitionLease::acquire(
                key.clone(),
                owner.clone(),
                FenceToken::new(0),
                Duration::from_secs(60),
            )
            .expect("lease action"),
            // Keep this request structurally valid without requiring a
            // sealed record fixture. The preproposal test is about the V2
            // full-ID and activation binding, not payload cryptography.
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("V2 transition request")
    }

    #[tokio::test]
    async fn generic_receiver_forward_to_leader_is_rerouted_with_same_request_id() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let directory = tempfile::tempdir().expect("generic receiver routing directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("generic receiver routing backend");
        let store = ConsensusSessionStore::open_with_clock(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Arc::new(SystemClock),
            Duration::from_secs(1),
        )
        .await
        .expect("open uninitialized generic receiver routing store");
        let identity = singleton_topology()
            .consensus_identity()
            .expect("generic receiver routing identity");
        let request = ForwardMutationRequest {
            request_id: SessionConsensusRequestId::new(),
            intent: SessionMutationIntent::AdvanceLogicalTime,
            required_consumer_scope: ForwardConsumerScope::Internal,
        };
        assert!(
            !mutation_requires_exact_status_resolution(&request),
            "an unscoped generic mutation may reroute its stable request ID"
        );
        let command = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity,
            request_id: request.request_id,
            logical_time: store.inner.clock.now_utc(),
            intent: SessionMutationIntent::Authorized {
                origin: store.inner.local_node_id,
                authority_identity: identity,
                mutation: Box::new(request.intent.clone()),
            },
        };
        let before = store.inner.raft.metrics().borrow().last_log_index;
        let receiver = store
            .inner
            .raft
            .client_write_ff(command.clone())
            .await
            .expect("Openraft enqueues generic request on an uninitialized node");
        let receiver_result = tokio::time::timeout(Duration::from_secs(1), receiver)
            .await
            .expect("uninitialized Openraft receiver deadline")
            .expect("uninitialized Openraft receiver remains available");
        let error = match receiver_result {
            Err(error @ ClientWriteError::ForwardToLeader(_)) => error,
            Err(_) => panic!("uninitialized Openraft returned the wrong receiver error"),
            Ok(_) => panic!("uninitialized Openraft unexpectedly appended a command"),
        };
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            before,
            "the receiver ForwardToLeader is a pre-append routing result"
        );
        assert!(matches!(
            client_write_receiver_error_reply(error, true),
            ForwardMutationReply::NotLeader { .. }
        ));
        assert_eq!(
            request.request_id, command.request_id,
            "rerouting retains the original request ID"
        );
    }

    #[tokio::test]
    async fn accepted_receiver_forward_to_leader_is_terminal_unknown_for_singleton_and_batch_effects(
    ) {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let open = |label: &'static str| async move {
            let directory = tempfile::tempdir().expect("accepted receiver effect directory");
            let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
                .expect("accepted receiver effect backend");
            let store = ConsensusSessionStore::open_with_clock(
                singleton_topology(),
                backend,
                directory.path().join("snapshots"),
                BTreeMap::new(),
                Arc::new(SystemClock),
                Duration::from_secs(1),
            )
            .await
            .unwrap_or_else(|_| panic!("open {label} accepted receiver effect store"));
            store
                .initialize_cluster()
                .await
                .unwrap_or_else(|_| panic!("initialize {label} accepted receiver effect store"));
            (directory, store)
        };

        let (_directory, store) = open("singleton").await;
        let singleton = v2_test_request(1);
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        store.inject_accepted_client_write_receiver_outcome(
            AcceptedClientWriteReceiverTestOutcome::ForwardToLeader,
        );
        assert!(matches!(
            SessionBackend::fenced_transition_v2_effect(&store, singleton.clone()).await,
            FencedTransitionV2Effect::OutcomeUnknown { request_ids }
                if request_ids == vec![singleton.request_id()]
        ));
        wait_for_log_index_after(&store, before, "accepted singleton receiver proposal").await;
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1),
            "the accepted singleton receiver error cannot reroute or repropose"
        );

        let (_directory, store) = open("batch").await;
        let first = v2_test_request(1);
        let second = FencedTransitionV2Request::new(
            first.request_id().epoch(),
            FencedTransitionV2CallerNonce::from_bytes([0x52; 16]),
            first.lease().clone(),
            FencedTransitionMutation::delete(Generation::new(2)),
        )
        .expect("distinct V2 batch request");
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        store.inject_accepted_client_write_receiver_outcome(
            AcceptedClientWriteReceiverTestOutcome::ForwardToLeader,
        );
        assert!(matches!(
            SessionBackend::fenced_transition_v2_batch_effect(
                &store,
                vec![first.clone(), second.clone()],
            )
            .await,
            FencedTransitionV2Effect::OutcomeUnknown { request_ids }
                if request_ids == vec![first.request_id(), second.request_id()]
        ));
        wait_for_log_index_after(&store, before, "accepted batch receiver proposal").await;
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1),
            "the accepted batch receiver error cannot reroute or repropose"
        );
    }

    #[tokio::test]
    async fn fresh_activation_error_resolves_only_a_singleton_effect() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let open = |label: &'static str| async move {
            let directory = tempfile::tempdir().expect("fresh activation effect directory");
            let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
                .expect("fresh activation effect backend");
            let store = ConsensusSessionStore::open_with_clock(
                singleton_topology(),
                backend,
                directory.path().join("snapshots"),
                BTreeMap::new(),
                Arc::new(SystemClock),
                Duration::from_secs(1),
            )
            .await
            .unwrap_or_else(|_| panic!("open {label} fresh activation effect store"));
            store
                .initialize_cluster()
                .await
                .unwrap_or_else(|_| panic!("initialize {label} fresh activation effect store"));
            (directory, store)
        };

        let (_directory, store) = open("batch").await;
        let first = v2_test_request(1);
        let second = FencedTransitionV2Request::new(
            first.request_id().epoch(),
            FencedTransitionV2CallerNonce::from_bytes([0x52; 16]),
            first.lease().clone(),
            FencedTransitionMutation::delete(Generation::new(2)),
        )
        .expect("distinct V2 activation suffix request");
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        assert!(matches!(
            SessionBackend::fenced_transition_v2_batch_effect(
                &store,
                vec![first.clone(), second.clone()],
            )
            .await,
            FencedTransitionV2Effect::OutcomeUnknown { request_ids }
                if request_ids == vec![first.request_id(), second.request_id()]
        ));
        wait_for_log_index_after(&store, before, "fresh activation batch rejection").await;
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1)
        );

        let (_directory, store) = open("singleton").await;
        let singleton = v2_test_request(1);
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        let singleton_effect =
            SessionBackend::fenced_transition_v2_batch_effect(&store, vec![singleton.clone()])
                .await;
        assert!(matches!(
            singleton_effect,
            FencedTransitionV2Effect::Resolved(Ok(outcomes))
                if matches!(outcomes.as_slice(), [Err(_)])
        ));
        wait_for_log_index_after(&store, before, "fresh activation singleton rejection").await;
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1)
        );
    }

    async fn v2_create_request_for_supervision() -> FencedTransitionV2Request {
        let key = SessionKey {
            tenant: TenantId::new("fenced-v2-reply-loss").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"fenced-v2-reply-loss")
                .try_into()
                .expect("stable ID"),
        };
        let owner = OwnerId::new("fenced-v2-reply-loss-owner").expect("owner");
        let mut record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner: owner.clone(),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("fenced-v2-reply-loss"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(Bytes::from_static(b"reply-loss")),
        };
        let provider = MemoryKeyProvider::new();
        provider
            .insert_active_key(
                KeyId::new("fenced-v2-reply-loss-key").expect("key ID"),
                KeyPurpose::Session,
                TenantId::new("fenced-v2-reply-loss").expect("tenant"),
                Zeroizing::new([0xD2; AES_256_GCM_SIV_KEY_LEN]),
            )
            .expect("active test session key");
        record.payload = EncryptedSessionPayload::encrypt(&provider, &record, "reply-loss")
            .await
            .expect("seal V2 reply-loss record");
        FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(1).expect("initial V2 epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0xD2; 16]),
            FencedTransitionLease::acquire(
                key.clone(),
                owner.clone(),
                FenceToken::new(0),
                Duration::from_secs(60),
            )
            .expect("lease action"),
            FencedTransitionMutation::create(record),
        )
        .expect("V2 create request")
    }

    fn v2_request_with_same_id_different_body(
        request: &FencedTransitionV2Request,
    ) -> FencedTransitionV2Request {
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
            serde_json::Value::String("fenced-v2-reply-loss-altered".to_owned()),
        );
        serde_json::from_value(encoded).expect("deserialize same-ID altered V2 request")
    }

    fn serialized_v2_consumer_body_conflict(
        scope: SessionConsumerScope,
        status: bool,
    ) -> SessionConsumerV2Request {
        let original = v2_test_request(1);
        let altered = FencedTransitionV2Request::new(
            original.request_id().epoch(),
            original.request_id().nonce(),
            original.lease().clone(),
            FencedTransitionMutation::delete(Generation::new(2)),
        )
        .expect("altered V2 transition");
        let operation = |request| {
            if status {
                SessionConsumerV2Operation::FencedTransitionV2Status {
                    request: Box::new(request),
                }
            } else {
                SessionConsumerV2Operation::FencedTransitionV2 {
                    request: Box::new(request),
                }
            }
        };
        let original = SessionConsumerV2Request::new(scope, operation(original));
        let altered = SessionConsumerV2Request::new(scope, operation(altered));
        let original_id = serde_json::to_value(original.request_id()).expect("full ID encodes");
        let mut encoded = serde_json::to_value(altered).expect("altered envelope encodes");
        let serde_json::Value::Object(fields) = &mut encoded else {
            panic!("V2 envelope is an object");
        };
        fields.insert("request_id".into(), original_id.clone());
        let body = fields
            .get_mut("operation")
            .and_then(serde_json::Value::as_object_mut)
            .and_then(|operation| operation.get_mut("request"))
            .and_then(serde_json::Value::as_object_mut)
            .expect("V2 body is an object");
        body.insert("request_id".into(), original_id);
        serde_json::from_value(encoded).expect("structural conflict decodes")
    }

    #[tokio::test]
    async fn consumer_v2_dispatches_a_serialized_same_id_body_conflict() {
        let (_directory, store, scope, identity, _key, _lease) = consumer_boundary_store().await;
        let execute = serialized_v2_consumer_body_conflict(scope, false);
        let status = serialized_v2_consumer_body_conflict(scope, true);
        assert!(execute.validate().is_ok());
        assert!(status.validate().is_ok());

        let service = store.consumer_service();
        assert_eq!(
            service.execute_v2(&identity, execute).await,
            SessionConsumerV2Response::FencedTransitionV2(Err(
                SessionConsumerV2FencedTransitionError::RequestConflict,
            ))
        );
        assert_eq!(
            service.execute_v2(&identity, status).await,
            SessionConsumerV2Response::FencedTransitionV2Status(Ok(
                SessionConsumerV2FencedTransitionStatus::RequestConflict,
            ))
        );
    }

    #[test]
    fn fixed_durable_v2_status_bypasses_the_generic_preliminary_admission() {
        let scope = SessionConsumerScope::new(
            singleton_topology()
                .consensus_identity()
                .expect("singleton consumer scope"),
        );
        let status = SessionConsumerV2Request::new(
            scope,
            SessionConsumerV2Operation::FencedTransitionV2Status {
                request: Box::new(v2_test_request(1)),
            },
        );
        let non_status = SessionConsumerV2Request::new(
            scope,
            SessionConsumerV2Operation::FencedTransitionV2 {
                request: Box::new(v2_test_request(1)),
            },
        );

        assert!(fixed_durable_v2_status_for_batch_dispatch(
            QuorumTopologyMode::FixedDurableQuorum,
            &status,
        )
        .is_some());
        assert!(fixed_durable_v2_status_for_batch_dispatch(
            QuorumTopologyMode::LabSingleton,
            &status,
        )
        .is_none());
        assert!(fixed_durable_v2_status_for_batch_dispatch(
            QuorumTopologyMode::FixedDurableQuorum,
            &non_status,
        )
        .is_none());
        let batch = SessionConsumerV2Request::new(
            scope,
            SessionConsumerV2Operation::FencedTransitionV2Batch {
                requests: vec![v2_test_request(1)],
            },
        );
        assert!(fixed_durable_raw_v2_warm_dispatch(
            QuorumTopologyMode::FixedDurableQuorum,
            Some(FencedTransitionV2Capability::V2),
            &non_status,
        ));
        assert!(fixed_durable_raw_v2_warm_dispatch(
            QuorumTopologyMode::FixedDurableQuorum,
            Some(FencedTransitionV2Capability::V2),
            &batch,
        ));
        assert!(!fixed_durable_raw_v2_warm_dispatch(
            QuorumTopologyMode::FixedDurableQuorum,
            None,
            &non_status,
        ));
        assert!(!fixed_durable_raw_v2_warm_dispatch(
            QuorumTopologyMode::LabSingleton,
            Some(FencedTransitionV2Capability::V2),
            &non_status,
        ));
        assert!(!fixed_durable_raw_v2_warm_dispatch(
            QuorumTopologyMode::FixedDurableQuorum,
            Some(FencedTransitionV2Capability::V2),
            &status,
        ));
    }

    #[test]
    fn consumer_v2_scope_loss_after_committed_receipts_is_outcome_unknown_with_exact_ids() {
        let scope = SessionConsumerScope::new(
            singleton_topology()
                .consensus_identity()
                .expect("singleton consumer scope"),
        );
        let singleton = SessionConsumerV2Request::new(
            scope,
            SessionConsumerV2Operation::FencedTransitionV2 {
                request: Box::new(v2_test_request(1)),
            },
        );
        assert_eq!(
            ConsensusSessionConsumerService::v2_response_after_scope_loss(
                &singleton,
                SessionConsumerV2Response::FencedTransitionV2(Err(
                    SessionConsumerV2FencedTransitionError::LeaseHeld,
                )),
                true,
                SessionConsumerRejection::ScopeMismatch,
            ),
            SessionConsumerV2Response::FencedTransitionV2(Err(
                SessionConsumerV2FencedTransitionError::OutcomeUnknown,
            )),
            "a committed deterministic singleton receipt cannot become a safe scope rejection"
        );

        let first = v2_test_request(1);
        let second = FencedTransitionV2Request::new(
            first.request_id().epoch(),
            FencedTransitionV2CallerNonce::from_bytes([0x63; 16]),
            first.lease().clone(),
            FencedTransitionMutation::delete(Generation::new(2)),
        )
        .expect("distinct V2 batch request");
        let request_ids = vec![first.request_id(), second.request_id()];
        let batch = SessionConsumerV2Request::new(
            scope,
            SessionConsumerV2Operation::FencedTransitionV2Batch {
                requests: vec![first, second],
            },
        );
        assert_eq!(
            ConsensusSessionConsumerService::v2_response_after_scope_loss(
                &batch,
                SessionConsumerV2Response::FencedTransitionV2Batch(Ok(Vec::new())),
                true,
                SessionConsumerRejection::ScopeMismatch,
            ),
            SessionConsumerV2Response::FencedTransitionV2Batch(Err(
                SessionConsumerV2FencedTransitionBatchError::outcome_unknown(request_ids)
                    .expect("valid exact batch IDs"),
            )),
            "a committed batch scope loss retains every caller-owned V2 ID in order"
        );

        assert_eq!(
            ConsensusSessionConsumerService::v2_response_after_scope_loss(
                &singleton,
                SessionConsumerV2Response::FencedTransitionV2(Err(
                    SessionConsumerV2FencedTransitionError::Store(
                        SessionConsumerStoreError::Unavailable,
                    ),
                )),
                false,
                SessionConsumerRejection::ScopeMismatch,
            ),
            SessionConsumerV2Response::FencedTransitionV2(Err(
                SessionConsumerV2FencedTransitionError::Store(
                    SessionConsumerStoreError::Unavailable,
                ),
            )),
            "a known pre-proposal availability error remains typed rather than ambiguous"
        );
    }

    #[tokio::test]
    async fn v2_fresh_history_exposes_initial_epoch_and_rejects_wrong_first_epoch() {
        let directory = tempfile::tempdir().expect("V2 history fixture directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("V2 history fixture backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("V2 history fixture store");
        store
            .initialize_cluster()
            .await
            .expect("initialize singleton cluster");
        let history = store
            .fenced_transition_v2_history_state()
            .await
            .expect("fresh V2 history state");
        assert_eq!(
            history.active_epoch(),
            Some(
                FencedTransitionV2HistoryEpoch::new(
                    crate::fenced_transition::FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH,
                )
                .expect("initial epoch"),
            )
        );
        assert_eq!(history.generation(), 0);
        assert_eq!(history.bound_entries(), 0);
        assert_eq!(
            store.fenced_transition_v2(v2_test_request(2)).await,
            Err(StoreError::FencedTransitionHistoryEpochNotActive),
        );
    }

    #[test]
    fn v2_fresh_recertification_classifies_delayed_predecessor_epochs_by_floor() {
        let epoch_two = FencedTransitionV2HistoryEpoch::new(2).expect("epoch two");
        let history = FencedTransitionV2HistoryState::new(
            Some(epoch_two),
            Some(FencedTransitionV2HistoryEpoch::new(1).expect("retired epoch")),
            None,
            0,
            9,
            0,
            4_096,
        )
        .expect("rotated history state");

        assert_eq!(
            classify_fresh_v2_history_epoch(
                &history,
                FencedTransitionV2HistoryEpoch::new(1).expect("delayed predecessor epoch"),
            ),
            Err(StoreError::FencedTransitionHistoryEpochRetired),
            "a delayed predecessor epoch is terminally retired during fresh recertification"
        );
        assert_eq!(
            classify_fresh_v2_history_epoch(
                &history,
                FencedTransitionV2HistoryEpoch::new(3).expect("future epoch"),
            ),
            Err(StoreError::FencedTransitionHistoryEpochNotActive),
            "only an epoch above the retired floor remains temporarily not active"
        );
        assert_eq!(classify_fresh_v2_history_epoch(&history, epoch_two), Ok(()));

        let successor = FencedTransitionV2HistoryState::new(
            Some(FencedTransitionV2HistoryEpoch::new(3).expect("active successor")),
            None,
            None,
            0,
            10,
            0,
            4_096,
        )
        .expect("bounded closed replay interval");
        assert_eq!(
            classify_fresh_v2_history_epoch(
                &successor,
                FencedTransitionV2HistoryEpoch::new(1).expect("closed replay epoch"),
            ),
            Ok(()),
            "a retained predecessor may replay while a fresh successor scope is certified"
        );
    }

    #[test]
    fn v2_preproposal_binds_full_id_and_first_activation_scope() {
        let identity = singleton_topology()
            .consensus_identity()
            .expect("consensus identity");
        let request = v2_test_request(1);
        let intent = SessionMutationIntent::ActivateFencedTransitionV2 {
            request: Box::new(request.clone()),
            scope_identity: identity,
            voter_set_digest: fenced_transition_voter_set_digest(
                identity,
                &[node(1)].into_iter().collect(),
            ),
            profile_digest: crate::fenced_transition::fenced_transition_v2_profile_digest(),
        };
        let command = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity,
            request_id: fenced_transition_v2_outer_request_id(&request),
            logical_time: Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
            intent: intent.clone(),
        };
        let validation = validate_consensus_command_preproposal(&command);
        assert!(
            validation.is_ok(),
            "unexpected V2 preproposal error: {validation:?}"
        );
        let Some((scope, voters, profile)) = fenced_transition_activation_scope(&intent) else {
            panic!("V2 activation must retain exact scope binding");
        };
        assert_eq!(*scope, identity);
        assert_eq!(
            *voters,
            fenced_transition_voter_set_digest(identity, &[node(1)].into_iter().collect())
        );
        assert_eq!(
            profile.copied(),
            Some(crate::fenced_transition::fenced_transition_v2_profile_digest())
        );
        assert_ne!(
            command.request_id,
            // V1 derives its generic envelope directly from its 16-byte
            // caller request ID.  The V2 nonce has that same width, but must
            // remain in a separate collision domain even when its bytes are
            // intentionally identical to a possible V1 ID.
            SessionConsensusRequestId::from_bytes(*request.request_id().nonce().as_bytes()),
            "V2 outer IDs must use a domain-separated derivation from V1"
        );
    }

    #[test]
    fn only_raw_v2_mutations_fuse_generic_and_capability_admission() {
        let identity = singleton_topology()
            .consensus_identity()
            .expect("consensus identity");
        let request = v2_test_request(1);
        let activated = SessionMutationIntent::ActivateFencedTransitionV2 {
            request: Box::new(request.clone()),
            scope_identity: identity,
            voter_set_digest: fenced_transition_voter_set_digest(
                identity,
                &[node(1)].into_iter().collect(),
            ),
            profile_digest: crate::fenced_transition::fenced_transition_v2_profile_digest(),
        };

        assert!(
            !requires_generic_leader_admission(
                &SessionMutationIntent::FencedTransitionV2(Box::new(request.clone())),
                false,
            ),
            "a raw V2 singleton immediately consumes the stronger capability admission"
        );
        assert!(
            is_raw_fenced_transition_v2_mutation(
                &SessionMutationIntent::FencedTransitionV2(Box::new(request.clone())),
                false,
            ),
            "the direct local leader/read-index barrier is limited to raw V2 singletons"
        );
        assert!(
            !requires_generic_leader_admission(
                &SessionMutationIntent::FencedTransitionV2Batch(vec![request]),
                false,
            ),
            "a raw V2 batch immediately consumes the stronger capability admission"
        );
        assert!(
            requires_generic_leader_admission(&activated, false),
            "proof-carrying activation wrappers retain generic admission"
        );
        assert!(
            !is_raw_fenced_transition_v2_mutation(&activated, false),
            "proof-carrying activation wrappers never omit generic admission"
        );
        assert!(
            requires_generic_leader_admission(&SessionMutationIntent::AdvanceLogicalTime, false),
            "non-V2 mutations retain generic admission"
        );
        assert!(
            !is_raw_fenced_transition_v2_mutation(
                &SessionMutationIntent::AdvanceLogicalTime,
                false,
            ),
            "ordinary writes and reads keep their established generic barriers"
        );
        assert!(
            requires_generic_leader_admission(
                &SessionMutationIntent::FencedTransitionV2(Box::new(v2_test_request(1))),
                true,
            ),
            "recovery authority never receives the V2 fast path"
        );
    }

    #[tokio::test]
    async fn raw_v2_expired_direct_barrier_fails_before_any_proposal() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let directory = tempfile::tempdir().expect("raw V2 barrier directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("raw V2 barrier backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open raw V2 barrier store");
        store
            .initialize_cluster()
            .await
            .expect("initialize raw V2 barrier store");

        let before = store.inner.raft.metrics().borrow().last_log_index;
        assert_eq!(
            store
                .admit_raw_v2_mutation_on_local_leader_before(tokio::time::Instant::now())
                .await,
            Err(ForwardMutationReply::Unavailable),
            "an expired direct leader/read-index admission must fail closed"
        );
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            before,
            "a failed direct barrier must never reach Openraft proposal admission"
        );
    }

    #[tokio::test]
    async fn raw_v2_final_authority_recheck_blocks_proposal_after_local_barrier() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let directory = tempfile::tempdir().expect("raw V2 final authority directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("raw V2 final authority backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open raw V2 final authority store");
        store
            .initialize_cluster()
            .await
            .expect("initialize raw V2 final authority store");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let operation_guard = store
            .inner
            .topology_coordinator
            .operation_gate()
            .read_owned()
            .await;
        store
            .admit_raw_v2_mutation_on_local_leader_before(deadline)
            .await
            .expect("direct V2 local barrier");
        let before = store.inner.raft.metrics().borrow().last_log_index;
        store.inner.admitted.store(false, Ordering::Release);
        let proposal_permit = Arc::clone(&store.inner.proposal_admission)
            .acquire_owned()
            .await
            .expect("proposal permit");
        let request = v2_test_request(1);
        let reply = store
            .propose_on_local_leader(
                ForwardMutationRequest {
                    request_id: fenced_transition_v2_outer_request_id(&request),
                    intent: SessionMutationIntent::FencedTransitionV2(Box::new(request)),
                    required_consumer_scope: ForwardConsumerScope::Internal,
                },
                LocalProposalAuthority {
                    origin: store.inner.local_node_id,
                    allows_operator_recovery: false,
                    fixed_raw_v2_snapshot: false,
                },
                store.inner.clock.now_utc(),
                LocalProposalExecution {
                    proposal_permit,
                    operation_guard,
                    cohort_freeze: None,
                },
                deadline,
            )
            .await;
        assert_eq!(reply, ForwardMutationReply::Unavailable);
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            before,
            "authority revoked after the direct barrier must fail at the final check before client_write_ff"
        );
    }

    #[test]
    fn v2_batch_outer_id_is_ordered_and_preproposal_rejects_bad_vectors() {
        let identity = singleton_topology()
            .consensus_identity()
            .expect("consensus identity");
        let first = v2_test_request(1);
        let second = FencedTransitionV2Request::new(
            first.request_id().epoch(),
            FencedTransitionV2CallerNonce::from_bytes([0x52; 16]),
            first.lease().clone(),
            FencedTransitionMutation::delete(Generation::new(2)),
        )
        .expect("distinct V2 batch request");
        let ordered = vec![first.clone(), second.clone()];
        let ordered_id = fenced_transition_v2_batch_request_id(&ordered).expect("ordered ID");
        assert_eq!(
            ordered_id,
            fenced_transition_v2_batch_request_id(&ordered).expect("stable ordered ID")
        );
        assert_ne!(
            ordered_id,
            fenced_transition_v2_batch_request_id(&[second.clone(), first.clone()])
                .expect("reordered ID"),
            "the outer command binds caller order as well as every full V2 ID"
        );

        let command = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity,
            request_id: ordered_id,
            logical_time: Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
            intent: SessionMutationIntent::FencedTransitionV2Batch(ordered.clone()),
        };
        assert!(validate_consensus_command_preproposal(&command).is_ok());

        let mismatched_outer = SessionConsensusCommand {
            request_id: SessionConsensusRequestId::from_bytes([0x73; 16]),
            ..command.clone()
        };
        assert_eq!(
            validate_consensus_command_preproposal(&mismatched_outer),
            Err(StoreError::InvalidKey(
                "fenced_transition_v2_batch_request_id_mismatch".into()
            ))
        );
        assert_eq!(
            validate_consensus_intent(&SessionMutationIntent::FencedTransitionV2Batch(vec![
                first.clone(),
                first,
            ])),
            Err(StoreError::InvalidKey(
                "fenced_transition_v2_batch_duplicate_request_id".into()
            ))
        );
        assert_eq!(
            validate_consensus_intent(&SessionMutationIntent::FencedTransitionV2Batch(vec![
                second,
                v2_test_request(2),
            ])),
            Err(StoreError::InvalidKey(
                "fenced_transition_v2_batch_epoch_mismatch".into()
            ))
        );
    }

    #[tokio::test]
    async fn v2_batch_conflict_precedes_nested_record_validation() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let original = v2_create_request_for_supervision().await;
        let altered = v2_request_with_same_id_different_body(&original);
        assert_eq!(
            altered.validate(),
            Err(StoreError::FencedTransitionRequestConflict),
            "the retained full ID must make this substituted body a conflict"
        );
        assert!(matches!(
            crate::sqlite::validate_consensus_record(
                altered
                    .mutation()
                    .record()
                    .expect("altered V2 create record"),
            ),
            Err(StoreError::Crypto(_)),
        ));

        let directory = tempfile::tempdir().expect("V2 conflict batch directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("V2 conflict batch backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open V2 conflict batch store");
        store
            .initialize_cluster()
            .await
            .expect("initialize V2 conflict batch store");
        let activated = store
            .fenced_transition_v2_batch(vec![original])
            .await
            .expect("activate original V2 request");
        let [Ok(activated)] = activated.as_slice() else {
            panic!("original V2 request did not activate with an outcome");
        };
        let valid = FencedTransitionV2Request::new(
            altered.request_id().epoch(),
            FencedTransitionV2CallerNonce::from_bytes([0xD3; 16]),
            FencedTransitionLease::renew(activated.lease().clone(), Duration::from_secs(60))
                .expect("renewal lease for valid V2 batch suffix"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("valid V2 batch suffix");
        let requests = vec![altered.clone(), valid.clone()];

        let identity = singleton_topology()
            .consensus_identity()
            .expect("consensus identity");
        let command = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity,
            request_id: fenced_transition_v2_batch_request_id(&requests).expect("batch request ID"),
            logical_time: Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
            intent: SessionMutationIntent::FencedTransitionV2Batch(requests.clone()),
        };
        assert!(
            validate_consensus_command_preproposal(&command).is_ok(),
            "leader preproposal must preserve the deterministic conflict"
        );
        assert!(
            validate_consensus_intent(&command.intent).is_ok(),
            "generic leader validation must preserve the deterministic conflict"
        );
        assert!(matches!(
            store
                .fenced_transition_v2_batch(requests)
                .await
                .expect("mixed V2 conflict batch"),
            outcomes if matches!(outcomes.as_slice(), [
                Err(StoreError::FencedTransitionRequestConflict),
                Ok(_),
            ])
        ));
    }

    #[test]
    fn v2_batch_exact_replay_resolves_with_original_recorded_at() {
        let recorded_at = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let envelope_time = Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH
                .checked_add(time::Duration::seconds(1))
                .expect("later batch envelope time"),
        );
        let first = v2_test_request(1);
        let second = FencedTransitionV2Request::new(
            first.request_id().epoch(),
            FencedTransitionV2CallerNonce::from_bytes([0x52; 16]),
            first.lease().clone(),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("second V2 batch request");
        let outcome = |request: &FencedTransitionV2Request, time| {
            FencedTransitionOutcome::new(
                LeaseGuard::new(
                    request.lease().key().clone(),
                    request.lease().owner().clone(),
                    request.lease().committed_fence().expect("committed fence"),
                    time,
                    checked_session_deadline(time, request.lease().ttl())
                        .expect("outcome lease deadline"),
                    1,
                ),
                Generation::new(1),
                FencedTransitionMutationResult::Deleted,
                time,
            )
            .expect("matching V2 outcome")
        };
        let replay_first = outcome(&first, recorded_at);
        let replay_second = outcome(&second, recorded_at);
        let fresh_second = outcome(&second, envelope_time);
        let response = |outcomes| SessionConsensusResponse {
            result: Ok(SessionMutationOutcome::FencedTransitionV2Batch(outcomes)),
            sequence: 1,
            digest: Some(crate::consensus::SessionConsensusEntryDigest::from_bytes(
                [0xD4; 32],
            )),
            logical_time: Some(envelope_time),
            raft_log_index: 1,
        };
        let requests = vec![first.clone(), second.clone()];
        let request_ids = requests
            .iter()
            .map(FencedTransitionV2Request::request_id)
            .collect::<Vec<_>>();

        let all_replay = response(vec![Ok(replay_first.clone()), Ok(replay_second.clone())]);
        assert!(
            committed_response_matches_intent(
                &SessionMutationIntent::FencedTransitionV2Batch(requests.clone()),
                &all_replay,
            ),
            "an exact retained batch replay keeps every item's original timestamp"
        );
        assert!(matches!(
            committed_fenced_transition_v2_batch_effect(
                &request_ids,
                &requests,
                None,
                all_replay,
            ),
            FencedTransitionV2Effect::Resolved(Ok(outcomes))
                if outcomes == vec![Ok(replay_first.clone()), Ok(replay_second)]
        ));

        let mixed = response(vec![Ok(replay_first.clone()), Ok(fresh_second.clone())]);
        assert!(
            committed_response_matches_intent(
                &SessionMutationIntent::FencedTransitionV2Batch(requests.clone()),
                &mixed,
            ),
            "a replay may be ordered with a newly recorded batch item"
        );
        assert!(matches!(
            committed_fenced_transition_v2_batch_effect(&request_ids, &requests, None, mixed),
            FencedTransitionV2Effect::Resolved(Ok(outcomes))
                if outcomes == vec![Ok(replay_first), Ok(fresh_second)]
        ));
    }

    #[test]
    fn v2_batch_requires_exact_active_epoch() {
        let active = FencedTransitionV2HistoryEpoch::new(2).expect("active epoch");
        let history = FencedTransitionV2HistoryState::new(
            Some(active),
            Some(FencedTransitionV2HistoryEpoch::new(1).expect("retired epoch")),
            None,
            0,
            9,
            0,
            4_096,
        )
        .expect("history");
        assert_eq!(
            require_fenced_transition_v2_batch_active_epoch(
                &history,
                FencedTransitionV2HistoryEpoch::new(1).expect("retired request epoch"),
            ),
            Err(StoreError::FencedTransitionHistoryEpochRetired)
        );
        assert_eq!(
            require_fenced_transition_v2_batch_active_epoch(
                &history,
                FencedTransitionV2HistoryEpoch::new(3).expect("future request epoch"),
            ),
            Err(StoreError::FencedTransitionHistoryEpochNotActive)
        );
        assert_eq!(
            require_fenced_transition_v2_batch_active_epoch(&history, active),
            Ok(())
        );
    }

    #[test]
    fn v2_reactivation_at_active_epoch_is_admitted_and_external_maintenance_rejects() {
        let identity = singleton_topology()
            .consensus_identity()
            .expect("consensus identity");
        let request = v2_test_request(2);
        let command = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity,
            request_id: fenced_transition_v2_outer_request_id(&request),
            logical_time: Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
            intent: SessionMutationIntent::ActivateFencedTransitionV2 {
                request: Box::new(request),
                scope_identity: identity,
                voter_set_digest: fenced_transition_voter_set_digest(
                    identity,
                    &[node(1)].into_iter().collect(),
                ),
                profile_digest: crate::fenced_transition::fenced_transition_v2_profile_digest(),
            },
        };
        // A topology cutover clears only the exact-scope V2 certificate; it
        // does not reset retained V2 history. SQLite apply therefore checks
        // the epoch against its durable history state, while preproposal must
        // permit the active epoch for this re-certification command.
        assert!(validate_consensus_command_preproposal(&command).is_ok());
        assert_eq!(
            validate_consensus_intent(&SessionMutationIntent::MaintainFencedTransitionV2History {
                expected_generation: 0,
                expected_active_epoch: None,
                expected_retired_through: 0,
                expected_bound_entries: 0,
            }),
            Err(StoreError::CapabilityNotSupported(
                "operator_recovery_requires_local_admin_authority".into()
            ))
        );
        assert_eq!(
            validate_consensus_intent_with_recovery(
                &SessionMutationIntent::MaintainFencedTransitionV2History {
                    expected_generation: 0,
                    expected_active_epoch: None,
                    expected_retired_through: 0,
                    expected_bound_entries: (FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u64) + 1,
                },
                true,
            ),
            Err(StoreError::InvalidKey(
                "fenced_transition_v2_expected_bound_entries_invalid".into()
            ))
        );
    }

    #[test]
    fn v2_probe_rejects_v1_only_and_profile_mismatched_voters() {
        let expected = crate::fenced_transition::fenced_transition_v2_profile_digest();
        let v1_payload = encode_bounded(&FencedTransitionCapabilityReply::V1)
            .expect("bounded V1 capability reply");
        assert!(
            decode_bounded::<FencedTransitionV2CapabilityReply>(&v1_payload).is_err(),
            "a V1-only voter must not decode as a V2 capability voter"
        );
        let mismatch = FencedTransitionV2CapabilityReply::V2 {
            profile_digest: [0xA5; 32],
        };
        assert!(!matches!(
            mismatch,
            FencedTransitionV2CapabilityReply::V2 { profile_digest } if profile_digest == expected
        ));
    }

    #[test]
    fn v2_local_profile_mismatch_disables_advertisement_probe_and_activation() {
        let backend = SqliteSessionBackend::in_memory().expect("SQLite backend");
        let exact = backend.consensus_capabilities();
        assert_eq!(
            SESSION_CONSENSUS_SCHEMA_VERSION, FENCED_TRANSITION_V2_CONSENSUS_SCHEMA_VERSION,
            "the active consensus command schema matches V2's pinned schema"
        );
        assert_eq!(
            SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
            FENCED_TRANSITION_V2_MIN_CONSENSUS_RPC_PAYLOAD_BYTES,
            "the active Postcard RPC capacity matches V2's profiled command minimum"
        );
        let durable_log_entry_capacity = backend.consensus_log_entry_max_bytes();
        assert_eq!(
            durable_log_entry_capacity, FENCED_TRANSITION_V2_MIN_DURABLE_LOG_ENTRY_BYTES,
            "the concrete SQLite durable JSON command-log capacity matches V2's profile"
        );
        let exact_transport = || {
            (
                FENCED_TRANSITION_V2_CONSENSUS_SCHEMA_VERSION,
                FENCED_TRANSITION_V2_MIN_CONSENSUS_RPC_PAYLOAD_BYTES,
                durable_log_entry_capacity,
            )
        };
        assert_eq!(
            local_fenced_transition_v2_capability_for_backend_capabilities(
                exact,
                exact_transport().0,
                exact_transport().1,
                exact_transport().2,
            ),
            Some(FencedTransitionV2Capability::V2),
            "the concrete SQLite consensus cap exactly matches V2's profile"
        );
        let probe = FencedTransitionV2CapabilityProbe {
            schema_version: FENCED_TRANSITION_SCHEMA_V2,
            profile_digest: crate::fenced_transition::fenced_transition_v2_profile_digest(),
        };
        assert!(matches!(
            fenced_transition_v2_capability_probe_reply(
                probe,
                local_fenced_transition_v2_capability_for_backend_capabilities(
                    exact,
                    exact_transport().0,
                    exact_transport().1,
                    exact_transport().2,
                ),
            ),
            FencedTransitionV2CapabilityReply::V2 { profile_digest }
                if profile_digest == crate::fenced_transition::fenced_transition_v2_profile_digest()
        ));

        let mut incompatible = exact;
        incompatible.max_value_bytes = FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES - 1;
        let capability = local_fenced_transition_v2_capability_for_backend_capabilities(
            incompatible,
            exact_transport().0,
            exact_transport().1,
            exact_transport().2,
        );
        assert_eq!(
            capability, None,
            "a local cap drift must not advertise V2 or permit V2 activation"
        );
        assert_eq!(
            fenced_transition_v2_capability_probe_reply(probe, capability),
            FencedTransitionV2CapabilityReply::Unsupported,
            "the authenticated V2 probe also fails closed on the same local mismatch"
        );

        assert_eq!(
            local_fenced_transition_v2_capability_for_backend_capabilities(
                exact,
                FENCED_TRANSITION_V2_CONSENSUS_SCHEMA_VERSION + 1,
                exact_transport().1,
                exact_transport().2,
            ),
            None,
            "V2 refuses a consensus command schema other than its pinned schema one"
        );
        assert_eq!(
            local_fenced_transition_v2_capability_for_backend_capabilities(
                exact,
                exact_transport().0,
                FENCED_TRANSITION_V2_MIN_CONSENSUS_RPC_PAYLOAD_BYTES - 1,
                exact_transport().2,
            ),
            None,
            "V2 refuses a Postcard RPC transport below its profiled command minimum"
        );
        assert_eq!(
            local_fenced_transition_v2_capability_for_backend_capabilities(
                exact,
                exact_transport().0,
                exact_transport().1,
                FENCED_TRANSITION_V2_MIN_DURABLE_LOG_ENTRY_BYTES - 1,
            ),
            None,
            "V2 refuses a durable JSON command log below its profiled entry minimum"
        );
    }

    #[test]
    fn v2_outcome_correlation_rejects_malformed_acquire_and_renew_credentials() {
        let logical_time = Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH
                .checked_add(time::Duration::seconds(120))
                .expect("fixture timestamp"),
        );
        let acquire = v2_test_request(1);
        let acquire_guard = LeaseGuard::new(
            acquire.lease().key().clone(),
            acquire.lease().owner().clone(),
            FenceToken::new(1),
            logical_time,
            checked_session_deadline(logical_time, Duration::from_secs(60))
                .expect("fixture deadline"),
            1,
        );
        let acquire_outcome = FencedTransitionOutcome::new(
            acquire_guard.clone(),
            Generation::new(1),
            FencedTransitionMutationResult::Deleted,
            logical_time,
        )
        .expect("valid acquire outcome");
        assert!(fenced_transition_v2_outcome_matches_request(
            &acquire,
            &acquire_outcome,
            logical_time,
        ));
        let malformed_acquire_guard = LeaseGuard::new(
            acquire.lease().key().clone(),
            acquire.lease().owner().clone(),
            FenceToken::new(1),
            Timestamp::from_offset_datetime(
                logical_time
                    .as_offset_datetime()
                    .checked_sub(time::Duration::seconds(1))
                    .expect("earlier fixture timestamp"),
            ),
            acquire_guard.expires_at(),
            1,
        );
        let malformed_acquire = FencedTransitionOutcome::new(
            malformed_acquire_guard,
            Generation::new(1),
            FencedTransitionMutationResult::Deleted,
            logical_time,
        )
        .expect("structurally valid malformed acquire outcome");
        assert!(!fenced_transition_v2_outcome_matches_request(
            &acquire,
            &malformed_acquire,
            logical_time,
        ));

        let prior = LeaseGuard::new(
            acquire.lease().key().clone(),
            acquire.lease().owner().clone(),
            FenceToken::new(1),
            Timestamp::from_offset_datetime(
                logical_time
                    .as_offset_datetime()
                    .checked_sub(time::Duration::seconds(30))
                    .expect("prior fixture timestamp"),
            ),
            checked_session_deadline(logical_time, Duration::from_secs(30))
                .expect("prior fixture expiry"),
            7,
        );
        let renew = FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(1).expect("epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0x52; 16]),
            FencedTransitionLease::renew(prior.clone(), Duration::from_secs(60))
                .expect("renew lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("renew request");
        let malformed_renew = FencedTransitionOutcome::new(
            LeaseGuard::new(
                prior.key().clone(),
                prior.owner().clone(),
                prior.fence(),
                prior.acquired_at(),
                checked_session_deadline(logical_time, Duration::from_secs(60))
                    .expect("renewed expiry"),
                prior.credential_id() + 1,
            ),
            Generation::new(1),
            FencedTransitionMutationResult::Deleted,
            logical_time,
        )
        .expect("structurally valid malformed renew outcome");
        assert!(!fenced_transition_v2_outcome_matches_request(
            &renew,
            &malformed_renew,
            logical_time,
        ));
    }

    #[tokio::test]
    async fn consensus_physical_token_hook_rejects_a_marker_for_another_storage_identity() {
        let directory = tempfile::tempdir().expect("physical token directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("physical token SQLite backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open physical token store");
        let key = SessionKey {
            tenant: TenantId::new("physical-token").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"physical-token")
                .try_into()
                .expect("stable ID"),
        };
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x45; 16]),
            FencedTransitionLease::acquire(
                key,
                OwnerId::new("physical-token-owner").expect("owner"),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .expect("lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("transition");
        let prepared = SessionBackend::prepare_fenced_transition(&store, request)
            .await
            .expect("prepare physical token");
        let expected = prepared_fenced_transition_storage_commitment(store.inner.storage_identity);
        let mut foreign = expected;
        foreign[0] ^= 1;
        let foreign_prepared = prepared
            .without_outer_protection(PreparedFencedTransitionProtection::ConsensusPhysicalV1 {
                storage_commitment: expected,
            })
            .expect("strip local marker")
            .with_protection(PreparedFencedTransitionProtection::ConsensusPhysicalV1 {
                storage_commitment: foreign,
            })
            .expect("attach foreign marker");

        assert!(!store.fenced_transition_accepts_prepared_physical_token(&foreign_prepared));
        assert!(matches!(
            SessionBackend::fenced_transition(&store, &foreign_prepared).await,
            Err(FencedTransitionExecuteError::NotTransmitted)
        ));
    }

    #[test]
    fn committed_fenced_rejections_match_the_apply_time_contract() {
        let logical_time = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let key = SessionKey {
            tenant: TenantId::new("fenced-committed-rejection").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"fenced-committed-rejection")
                .try_into()
                .expect("stable ID"),
        };
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x43; 16]),
            FencedTransitionLease::acquire(
                key,
                OwnerId::new("fenced-committed-owner").expect("owner"),
                FenceToken::new(0),
                Duration::from_secs(60),
            )
            .expect("lease action"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("fenced intent");
        let intent = SessionMutationIntent::FencedTransition(Box::new(request));
        let committed = |error| SessionConsensusResponse {
            result: Err(error),
            sequence: 1,
            digest: Some(crate::consensus::SessionConsensusEntryDigest::from_bytes(
                [0x44; 32],
            )),
            logical_time: Some(logical_time),
            raft_log_index: 1,
        };

        for error in [
            StoreError::InvalidSessionTtl,
            StoreError::InvalidRecordExpiry,
            StoreError::FencedTransitionHistoryFull,
            StoreError::FencedTransitionRetentionExhausted,
        ] {
            assert!(committed_response_matches_intent(
                &intent,
                &committed(error)
            ));
        }
        let mut genesis_exhausted = committed(StoreError::FencedTransitionRetentionExhausted);
        genesis_exhausted.sequence = 0;
        assert!(committed_response_matches_intent(
            &intent,
            &genesis_exhausted,
        ));
        let mut genesis_revoked = committed(StoreError::TopologyAuthorityRevoked);
        genesis_revoked.sequence = 0;
        assert!(committed_response_matches_intent(&intent, &genesis_revoked));
        let v2_intent = SessionMutationIntent::FencedTransitionV2(Box::new(v2_test_request(1)));
        assert!(committed_response_matches_intent(
            &v2_intent,
            &committed(StoreError::FencedTransitionRetentionExhausted),
        ));
        let mut v2_genesis_exhausted = committed(StoreError::FencedTransitionRetentionExhausted);
        v2_genesis_exhausted.sequence = 0;
        assert!(committed_response_matches_intent(
            &v2_intent,
            &v2_genesis_exhausted,
        ));
        let mut v2_genesis_epoch_not_active =
            committed(StoreError::FencedTransitionHistoryEpochNotActive);
        v2_genesis_epoch_not_active.sequence = 0;
        assert!(committed_response_matches_intent(
            &v2_intent,
            &v2_genesis_epoch_not_active,
        ));
        assert!(!committed_response_matches_intent(
            &intent,
            &v2_genesis_epoch_not_active,
        ));
        let activated_v2_intent = SessionMutationIntent::ActivateFencedTransitionV2 {
            request: Box::new(v2_test_request(1)),
            scope_identity: singleton_topology()
                .consensus_identity()
                .expect("consensus identity"),
            voter_set_digest: [0x61; 32],
            profile_digest: crate::fenced_transition::fenced_transition_v2_profile_digest(),
        };
        assert!(committed_response_matches_intent(
            &activated_v2_intent,
            &committed(StoreError::FencedTransitionRetentionExhausted),
        ));
        assert!(committed_response_matches_intent(
            &SessionMutationIntent::MaintainFencedTransitionV2History {
                expected_generation: 0,
                expected_active_epoch: None,
                expected_retired_through: 0,
                expected_bound_entries: 0,
            },
            &SessionConsensusResponse {
                result: Ok(SessionMutationOutcome::Unit),
                sequence: 1,
                digest: Some(crate::consensus::SessionConsensusEntryDigest::from_bytes(
                    [0x44; 32],
                )),
                logical_time: Some(logical_time),
                raft_log_index: 1,
            },
        ));
        assert!(committed_response_matches_intent(
            &SessionMutationIntent::MaintainFencedTransitionV2History {
                expected_generation: 0,
                expected_active_epoch: None,
                expected_retired_through: 0,
                expected_bound_entries: 0,
            },
            &committed(StoreError::FencedTransitionHistoryEpochNotActive),
        ));
        assert!(committed_response_matches_intent(
            &SessionMutationIntent::MaintainFencedTransitionV2History {
                expected_generation: u64::MAX,
                expected_active_epoch: None,
                expected_retired_through: u64::MAX,
                expected_bound_entries: 0,
            },
            &committed(StoreError::FencedTransitionStorageExhausted),
        ));
        assert!(!committed_response_matches_intent(
            &SessionMutationIntent::AdvanceLogicalTime,
            &genesis_revoked,
        ));
        let mut invalid_genesis = committed(StoreError::FencedTransitionHistoryFull);
        invalid_genesis.sequence = 0;
        assert!(!committed_response_matches_intent(
            &intent,
            &invalid_genesis,
        ));
        assert!(!committed_response_matches_intent(
            &intent,
            &committed(StoreError::PayloadTooLarge { actual: 2, max: 1 }),
        ));
        assert!(!rejected_response_matches_intent(
            &intent,
            &SessionConsensusResponse::rejected(StoreError::InvalidRecordExpiry),
        ));
    }

    #[test]
    fn preproposal_rejects_nested_authorized_consensus_record() {
        let logical_time = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let key = SessionKey {
            tenant: TenantId::new("nested-authorized").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"nested-authorized")
                .try_into()
                .expect("stable ID"),
        };
        let owner = OwnerId::new("nested-authorized-owner").expect("owner");
        let lease = LeaseGuard::new(
            key.clone(),
            owner.clone(),
            FenceToken::new(1),
            logical_time,
            checked_session_deadline(logical_time, Duration::from_secs(60))
                .expect("lease deadline"),
            1,
        );
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner,
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("nested-authorized"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"unsealed"),
        };
        let mutation = SessionMutationIntent::CompareAndSet(Box::new(CompareAndSet {
            key,
            lease,
            expected_generation: None,
            new_record: record,
        }));
        let identity = singleton_topology()
            .consensus_identity()
            .expect("consensus identity");
        let command = crate::consensus::SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity,
            request_id: SessionConsensusRequestId::new(),
            logical_time,
            intent: SessionMutationIntent::Authorized {
                origin: node(1),
                authority_identity: identity,
                mutation: Box::new(SessionMutationIntent::Authorized {
                    origin: node(1),
                    authority_identity: identity,
                    mutation: Box::new(mutation),
                }),
            },
        };
        assert!(matches!(
            validate_consensus_command_preproposal(&command),
            Err(StoreError::CapabilityNotSupported(_))
        ));
    }

    #[test]
    fn committed_consumer_record_requires_consensus_validation() {
        let logical_time = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let key = SessionKey {
            tenant: TenantId::new("forwarded-record").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"forwarded-record")
                .try_into()
                .expect("stable ID"),
        };
        let owner = OwnerId::new("forwarded-record-owner").expect("owner");
        let lease = LeaseGuard::new(
            key.clone(),
            owner.clone(),
            FenceToken::new(1),
            logical_time,
            checked_session_deadline(logical_time, Duration::from_secs(60))
                .expect("lease deadline"),
            1,
        );
        let invalid_record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner,
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("forwarded-record"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"unsealed"),
        };
        let oversized_record = consumer_record_with_payload_len(
            &key,
            &lease,
            crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES + 1,
        );
        let mut aad_mismatched_record = consumer_record_with_payload_len(
            &key,
            &lease,
            crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES,
        );
        aad_mismatched_record.state_type = StateType::from_static("different-state");
        for record in [invalid_record, oversized_record, aad_mismatched_record] {
            let response = SessionConsensusResponse {
                result: Ok(SessionMutationOutcome::ConsumerRecord(Some(record))),
                sequence: 1,
                digest: Some(crate::consensus::SessionConsensusEntryDigest::from_bytes(
                    [0x55; 32],
                )),
                logical_time: Some(logical_time),
                raft_log_index: 1,
            };
            assert!(!committed_response_matches_intent(
                &SessionMutationIntent::ReadConsumerRecord { key: key.clone() },
                &response
            ));
        }
        drop(lease);
    }

    #[test]
    fn committed_cas_conflict_record_requires_consensus_validation() {
        let logical_time = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let key = SessionKey {
            tenant: TenantId::new("forwarded-cas-record").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"forwarded-cas-record")
                .try_into()
                .expect("stable ID"),
        };
        let owner = OwnerId::new("forwarded-cas-owner").expect("owner");
        let lease = LeaseGuard::new(
            key.clone(),
            owner.clone(),
            FenceToken::new(1),
            logical_time,
            checked_session_deadline(logical_time, Duration::from_secs(60))
                .expect("lease deadline"),
            1,
        );
        let intent = SessionMutationIntent::CompareAndSet(Box::new(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: consumer_record_with_payload_len(&key, &lease, 64 * 1024),
        }));
        let invalid_record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner,
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("forwarded-cas-record"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"unsealed"),
        };
        let oversized_record = consumer_record_with_payload_len(
            &key,
            &lease,
            crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES + 1,
        );
        let mut aad_mismatched_record = consumer_record_with_payload_len(
            &key,
            &lease,
            crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES,
        );
        aad_mismatched_record.state_type = StateType::from_static("different-state");

        for current in [invalid_record, oversized_record, aad_mismatched_record] {
            let response = SessionConsensusResponse {
                result: Ok(SessionMutationOutcome::CompareAndSet(
                    CompareAndSetResult::Conflict {
                        current: Some(current),
                    },
                )),
                sequence: 1,
                digest: Some(crate::consensus::SessionConsensusEntryDigest::from_bytes(
                    [0x56; 32],
                )),
                logical_time: Some(logical_time),
                raft_log_index: 1,
            };
            assert!(!committed_response_matches_intent(&intent, &response));
        }
    }

    fn consumer_record_with_payload_len(
        key: &SessionKey,
        lease: &LeaseGuard,
        payload_len: usize,
    ) -> StoredSessionRecord {
        let mut record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner: lease.owner().clone(),
            fence: lease.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("consumer-boundary"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([]),
        };
        let key_id = KeyId::new("consumer-boundary-key").expect("key ID");
        let aad = EnvelopeAad::session(
            record.key.tenant.clone(),
            1,
            SessionAad::new(
                record.key.nf_kind.as_str(),
                "consumer-boundary-digest",
                record.state_type.as_str(),
                record.generation.get(),
                record.fence.get(),
                "consumer-boundary-backend",
            )
            .expect("session AAD"),
        );
        let envelope = |opaque_len| CryptoEnvelopeV1 {
            algorithm: AeadAlgorithm::Aes256GcmSiv,
            key_id: key_id.clone(),
            nonce: vec![0x42; AES_256_GCM_SIV_NONCE_LEN],
            aad: serialize_bound_aad(&aad, &key_id).expect("bound AAD"),
            ciphertext_and_tag: {
                let mut ciphertext_and_tag = vec![0x5a; opaque_len];
                ciphertext_and_tag.extend_from_slice(&[0xa5; AEAD_TAG_LEN]);
                ciphertext_and_tag
            },
        };
        let envelope_overhead = envelope(0).encode().expect("empty envelope").len();
        let encoded = envelope(payload_len - envelope_overhead)
            .encode()
            .expect("bounded envelope");
        assert_eq!(encoded.len(), payload_len);
        record.payload =
            EncryptedSessionPayload::try_envelope(encoded).expect("bounded envelope fixture");
        record
    }

    #[test]
    fn physical_fenced_transition_admission_enforces_exact_record_cap_only() {
        let logical_time = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
        let key = SessionKey {
            tenant: TenantId::new("physical-fenced-admission").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"physical-fenced-admission")
                .try_into()
                .expect("stable ID"),
        };
        let owner = OwnerId::new("physical-fenced-admission-owner").expect("owner");
        let lease = LeaseGuard::new(
            key.clone(),
            owner,
            FenceToken::new(1),
            logical_time,
            checked_session_deadline(logical_time, Duration::from_secs(60))
                .expect("lease deadline"),
            1,
        );
        let make_request = |request_id, mutation| {
            FencedTransitionRequest::new(
                FencedTransitionRequestId::from_bytes([request_id; 16]),
                FencedTransitionLease::renew(lease.clone(), Duration::from_secs(30))
                    .expect("renewal"),
                mutation,
            )
            .expect("fenced transition")
        };

        let exact = make_request(
            0x31,
            FencedTransitionMutation::update(
                Generation::new(0),
                consumer_record_with_payload_len(
                    &key,
                    &lease,
                    crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES,
                ),
            ),
        );
        assert!(validate_consensus_physical_fenced_transition_request(&exact).is_ok());

        let oversized = make_request(
            0x32,
            FencedTransitionMutation::update(
                Generation::new(0),
                consumer_record_with_payload_len(
                    &key,
                    &lease,
                    crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES + 1,
                ),
            ),
        );
        assert_eq!(
            validate_consensus_physical_fenced_transition_request(&oversized),
            Err(StoreError::PayloadTooLarge {
                actual: crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES + 1,
                max: crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES,
            })
        );

        let delete = make_request(0x33, FencedTransitionMutation::delete(Generation::new(1)));
        let refresh = make_request(
            0x34,
            FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::from_secs(30))
                .expect("refresh"),
        );
        assert!(validate_consensus_physical_fenced_transition_request(&delete).is_ok());
        assert!(validate_consensus_physical_fenced_transition_request(&refresh).is_ok());
    }

    async fn consumer_boundary_store() -> (
        tempfile::TempDir,
        ConsensusSessionStore,
        SessionConsumerScope,
        SessionConsumerIdentity,
        SessionKey,
        LeaseGuard,
    ) {
        let directory = tempfile::tempdir().expect("consumer boundary directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("consumer boundary SQLite backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open consumer boundary store");
        store
            .initialize_cluster()
            .await
            .expect("initialize consumer boundary store");
        let key = SessionKey {
            tenant: TenantId::new("consumer-boundary").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"consumer-boundary")
                .try_into()
                .expect("stable ID"),
        };
        let lease = store
            .acquire(
                &key,
                OwnerId::new("consumer-boundary-owner").expect("owner"),
                Duration::from_secs(60),
            )
            .await
            .expect("consumer boundary lease");
        let scope = store.consumer_scope().expect("consumer boundary scope");
        let identity = SessionConsumerIdentity::new("spiffe://test.example/consumer/boundary")
            .expect("consumer boundary identity");
        (directory, store, scope, identity, key, lease)
    }

    #[tokio::test]
    async fn oversized_consumer_cas_does_not_bind_request_id() {
        let (_directory, store, scope, identity, key, lease) = consumer_boundary_store().await;
        let service = store.consumer_service();
        let request_id = crate::SessionConsumerRequestId::from_bytes([0x91; 16]);
        let oversized = CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: consumer_record_with_payload_len(
                &key,
                &lease,
                crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES + 1,
            ),
        };
        let exact = CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: consumer_record_with_payload_len(
                &key,
                &lease,
                crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES,
            ),
        };
        let invalid = service
            .execute(
                &identity,
                SessionConsumerRequest::new(
                    scope,
                    request_id,
                    SessionConsumerOperation::CompareAndSet {
                        op: Box::new(oversized),
                    },
                ),
            )
            .await;
        assert_eq!(
            invalid,
            SessionConsumerResponse::CompareAndSet(Err(SessionConsumerStoreError::PayloadTooLarge))
        );
        let valid = service
            .execute(
                &identity,
                SessionConsumerRequest::new(
                    scope,
                    request_id,
                    SessionConsumerOperation::CompareAndSet {
                        op: Box::new(exact),
                    },
                ),
            )
            .await;
        assert_eq!(
            valid,
            SessionConsumerResponse::CompareAndSet(Ok(CompareAndSetResult::Success))
        );
    }

    #[tokio::test]
    async fn oversized_consumer_batch_does_not_bind_request_id() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let (_directory, store, scope, identity, key, lease) = consumer_boundary_store().await;
        let service = store.consumer_service();
        let request_id = crate::SessionConsumerRequestId::from_bytes([0x92; 16]);
        let oversized = SessionOp::CompareAndSet(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: consumer_record_with_payload_len(
                &key,
                &lease,
                crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES + 1,
            ),
        });
        let exact = SessionOp::CompareAndSet(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: consumer_record_with_payload_len(
                &key,
                &lease,
                crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES,
            ),
        });
        let invalid = service
            .execute(
                &identity,
                SessionConsumerRequest::new(
                    scope,
                    request_id,
                    SessionConsumerOperation::Batch {
                        ops: vec![oversized],
                    },
                ),
            )
            .await;
        assert_eq!(
            invalid,
            SessionConsumerResponse::Batch(Err(SessionConsumerStoreError::PayloadTooLarge))
        );
        let valid = service
            .execute(
                &identity,
                SessionConsumerRequest::new(
                    scope,
                    request_id,
                    SessionConsumerOperation::Batch { ops: vec![exact] },
                ),
            )
            .await;
        assert_eq!(
            valid,
            SessionConsumerResponse::Batch(Ok(vec![SessionConsumerBatchResult::CompareAndSet(
                Ok(CompareAndSetResult::Success)
            ),]))
        );
    }

    #[test]
    fn v2_capability_recheck_preserves_transient_availability_failures() {
        assert_eq!(
            fenced_transition_v2_capability_failure_reply(unsupported_fenced_transition_v2()),
            ForwardMutationReply::Applied(Box::new(SessionConsensusResponse::rejected(
                unsupported_fenced_transition_v2()
            )))
        );
        assert_eq!(
            fenced_transition_v2_capability_failure_reply(StoreError::BackendUnavailable(
                "linearizable certificate recheck deadline elapsed".into()
            )),
            ForwardMutationReply::Unavailable
        );
        assert_eq!(
            fenced_transition_v2_capability_failure_reply(StoreError::CapabilityNotSupported(
                "another_capability".into()
            )),
            ForwardMutationReply::Unavailable
        );
    }

    #[tokio::test]
    async fn store_and_forwarded_services_fail_closed_before_exact_admission() {
        let directory = tempfile::tempdir().expect("membership admission directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("membership admission SQLite backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open uninitialized consensus store");

        let uninitialized = store.probe_durable_readiness().await;
        assert_eq!(uninitialized.state(), DurableReadinessState::NoQuorum);
        let production = store
            .probe_production_durable_readiness_at(TopologyAttestationTime::from_unix_seconds(
                1_000,
            ))
            .await;
        assert_eq!(production.state(), DurableReadinessState::TopologyInvalid);
        assert_eq!(
            uninitialized.recovery_progress().state(),
            DurableRecoveryState::AwaitingQuorum
        );
        assert!(matches!(
            store
                .submit_intent(SessionMutationIntent::AdvanceLogicalTime)
                .await,
            Err(StoreError::BackendUnavailable(_))
        ));

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let forwarded = store
            .apply_on_local_leader(
                ForwardMutationRequest {
                    request_id: SessionConsensusRequestId::new(),
                    intent: SessionMutationIntent::AdvanceLogicalTime,
                    required_consumer_scope: ForwardConsumerScope::Internal,
                },
                store.inner.local_node_id,
                deadline,
            )
            .await;
        assert_eq!(forwarded, ForwardMutationReply::Unavailable);
        let invalid_internal_authority = store
            .apply_on_local_leader(
                ForwardMutationRequest {
                    request_id: SessionConsensusRequestId::new(),
                    intent: SessionMutationIntent::Authorized {
                        origin: store.inner.local_node_id,
                        authority_identity: singleton_topology()
                            .consensus_identity()
                            .expect("singleton authority identity"),
                        mutation: Box::new(SessionMutationIntent::AdvanceLogicalTime),
                    },
                    required_consumer_scope: ForwardConsumerScope::Internal,
                },
                store.inner.local_node_id,
                deadline,
            )
            .await;
        assert!(matches!(
            invalid_internal_authority,
            ForwardMutationReply::Applied(response)
                if matches!(response.result, Err(StoreError::CapabilityNotSupported(_)))
        ));
        assert_eq!(
            store.local_read_barrier(deadline).await,
            ReadBarrierReply::Unavailable
        );

        store
            .initialize_cluster()
            .await
            .expect("admit exact singleton membership");
        assert!(store.exact_membership_is_admitted());
        let initialized = store.probe_durable_readiness().await;
        assert!(initialized.is_ready());
        let production = store
            .probe_production_durable_readiness_at(TopologyAttestationTime::from_unix_seconds(
                1_000,
            ))
            .await;
        assert_eq!(production.state(), DurableReadinessState::TopologyInvalid);
        assert_eq!(
            initialized.recovery_progress().state(),
            DurableRecoveryState::Synchronized
        );
    }

    #[tokio::test]
    async fn durable_probe_backend_error_and_deadline_are_transient_not_recovery_latches() {
        let directory = tempfile::tempdir().expect("durable probe deadline directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("durable probe deadline SQLite backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open durable probe deadline store");
        store
            .inner
            .backend
            .inject_consensus_operator_recovery_failure(true);
        let backend_error = store.probe_durable_readiness().await;
        assert_eq!(backend_error.state(), DurableReadinessState::NoQuorum);
        assert_eq!(
            backend_error.recovery_progress().state(),
            DurableRecoveryState::AwaitingQuorum
        );
        store
            .inner
            .backend
            .inject_consensus_operator_recovery_failure(false);
        let deadline = tokio::time::Instant::now();

        let general = store.probe_durable_readiness_before(deadline).await;
        assert_eq!(general.state(), DurableReadinessState::NoQuorum);
        assert_eq!(
            general.recovery_progress().state(),
            DurableRecoveryState::AwaitingQuorum
        );

        store
            .inner
            .raft
            .shutdown()
            .await
            .expect("shut down Raft for fatal-state priority detector");
        store
            .inner
            .backend
            .inject_consensus_operator_recovery_failure(true);
        let fatal = store.probe_durable_readiness().await;
        assert_eq!(fatal.state(), DurableReadinessState::RecoveryRequired);
        assert_eq!(
            fatal.recovery_progress().state(),
            DurableRecoveryState::RecoveryRequired,
            "a failed auxiliary Recovery read must not downgrade known fatal engine state"
        );
    }

    #[tokio::test]
    async fn forwarded_consumer_scope_is_rechecked_inside_the_leader_topology_gate() {
        let directory = tempfile::tempdir().expect("consumer scope gate directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("consumer scope gate SQLite backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open singleton consumer scope gate store");
        store
            .initialize_cluster()
            .await
            .expect("initialize singleton consumer scope gate store");

        let current = store
            .consumer_scope()
            .expect("current admitted consumer scope")
            .consensus_identity();
        let stale_scope = SessionConsensusIdentity::new(
            current.cluster_id(),
            current.configuration_id(),
            SessionConsensusConfigurationEpoch::new(current.configuration_epoch().get() + 1)
                .expect("successor configuration epoch"),
        );
        let response = store
            .apply_on_local_leader(
                ForwardMutationRequest {
                    request_id: SessionConsensusRequestId::new(),
                    intent: SessionMutationIntent::AdvanceLogicalTime,
                    required_consumer_scope: ForwardConsumerScope::Consumer(Box::new(stale_scope)),
                },
                store.inner.local_node_id,
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await;
        assert!(matches!(
            response,
            ForwardMutationReply::Applied(response)
                if response.result == Err(StoreError::TopologyAuthorityRevoked)
        ));
    }

    #[tokio::test]
    async fn stale_consumer_scope_rejects_raw_v2_before_the_leader_proposal() {
        let directory = tempfile::tempdir().expect("raw V2 consumer scope gate directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("raw V2 consumer scope gate SQLite backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open raw V2 consumer scope gate store");
        store
            .initialize_cluster()
            .await
            .expect("initialize raw V2 consumer scope gate store");

        let current = store
            .consumer_scope()
            .expect("current admitted consumer scope")
            .consensus_identity();
        let stale_scope = SessionConsensusIdentity::new(
            current.cluster_id(),
            current.configuration_id(),
            SessionConsensusConfigurationEpoch::new(current.configuration_epoch().get() + 1)
                .expect("successor configuration epoch"),
        );
        let before = store.inner.raft.metrics().borrow().last_log_index;
        let proposal_permit = Arc::clone(&store.inner.proposal_admission)
            .acquire_owned()
            .await
            .expect("proposal permit");
        let operation_guard = store
            .inner
            .topology_coordinator
            .operation_gate()
            .read_owned()
            .await;
        let request = v2_test_request(1);
        let response = store
            .propose_on_local_leader(
                ForwardMutationRequest {
                    request_id: fenced_transition_v2_outer_request_id(&request),
                    intent: SessionMutationIntent::FencedTransitionV2(Box::new(request)),
                    required_consumer_scope: ForwardConsumerScope::Consumer(Box::new(stale_scope)),
                },
                LocalProposalAuthority {
                    origin: store.inner.local_node_id,
                    allows_operator_recovery: false,
                    fixed_raw_v2_snapshot: false,
                },
                store.inner.clock.now_utc(),
                LocalProposalExecution {
                    proposal_permit,
                    operation_guard,
                    cohort_freeze: None,
                },
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await;
        assert!(matches!(
            response,
            ForwardMutationReply::Applied(response)
                if response.result == Err(StoreError::TopologyAuthorityRevoked)
        ));
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            before,
            "a stale consumer V2 scope is rejected before client_write_ff"
        );
    }

    #[tokio::test]
    async fn typed_consumer_service_deduplicates_and_fences_competing_leases() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let directory = tempfile::tempdir().expect("consumer service directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("consumer service SQLite backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open singleton consumer service store");
        store
            .initialize_cluster()
            .await
            .expect("initialize singleton consumer service store");

        let scope = store.consumer_scope().expect("current admitted scope");
        let key = SessionKey {
            tenant: TenantId::new("consumer-service").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"lease-race")
                .try_into()
                .expect("stable ID"),
        };
        let first_identity = SessionConsumerIdentity::new("spiffe://test.example/consumer/first")
            .expect("first consumer identity");
        let second_identity = SessionConsumerIdentity::new("spiffe://test.example/consumer/second")
            .expect("second consumer identity");
        let first_request = SessionConsumerRequest::new(
            scope,
            crate::SessionConsumerRequestId::from_bytes([1; 16]),
            SessionConsumerOperation::AcquireLease {
                key: key.clone(),
                owner: OwnerId::new("consumer-first").expect("first owner"),
                ttl: Duration::from_secs(30),
            },
        );
        let second_request = SessionConsumerRequest::new(
            scope,
            crate::SessionConsumerRequestId::from_bytes([2; 16]),
            SessionConsumerOperation::AcquireLease {
                key,
                owner: OwnerId::new("consumer-second").expect("second owner"),
                ttl: Duration::from_secs(30),
            },
        );
        let service = store.consumer_service();
        let (first, second) = tokio::join!(
            service.execute(&first_identity, first_request.clone()),
            service.execute(&second_identity, second_request),
        );
        assert_eq!(
            [first.clone(), second.clone()]
                .into_iter()
                .filter(|response| {
                    matches!(response, SessionConsumerResponse::AcquireLease(Ok(_)))
                })
                .count(),
            1,
            "the consumer boundary must preserve a single fenced winner"
        );
        assert_eq!(
            [first.clone(), second.clone()]
                .into_iter()
                .filter(|response| {
                    matches!(
                        response,
                        SessionConsumerResponse::AcquireLease(Err(
                            crate::SessionConsumerLeaseError::AlreadyHeld
                        ))
                    )
                })
                .count(),
            1,
            "the loser must receive the normal quorum lease conflict"
        );

        let retry = service.execute(&first_identity, first_request).await;
        if matches!(first, SessionConsumerResponse::AcquireLease(Ok(_))) {
            assert_eq!(
                retry, first,
                "the durable request ID must deduplicate a retry"
            );
        } else {
            assert!(matches!(
                retry,
                SessionConsumerResponse::AcquireLease(Err(
                    crate::SessionConsumerLeaseError::AlreadyHeld
                ))
            ));
        }
    }

    #[tokio::test]
    async fn consumer_fenced_transition_bypasses_the_legacy_binding_proposal() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let directory = tempfile::tempdir().expect("consumer transition directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("consumer transition SQLite backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open consumer transition store");
        store
            .initialize_cluster()
            .await
            .expect("initialize consumer transition store");

        let scope = store.consumer_scope().expect("current consumer scope");
        let identity = SessionConsumerIdentity::new("spiffe://test.example/consumer/transition")
            .expect("consumer identity");
        let key = SessionKey {
            tenant: TenantId::new("consumer-transition").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"one-proposal")
                .try_into()
                .expect("stable ID"),
        };
        let owner = OwnerId::new("consumer-transition-owner").expect("owner");
        let transition_id = FencedTransitionRequestId::from_bytes([0x91; 16]);
        let transition = FencedTransitionRequest::new(
            transition_id,
            FencedTransitionLease::acquire(
                key.clone(),
                owner.clone(),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .expect("lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("transition");
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .expect("initialized log index");
        let response = store
            .consumer_service()
            .execute(
                &identity,
                SessionConsumerRequest::new(
                    scope,
                    SessionConsumerRequestId::from_bytes(*transition_id.as_bytes()),
                    SessionConsumerOperation::FencedTransition {
                        request: Box::new(transition),
                    },
                ),
            )
            .await;
        assert!(matches!(
            response,
            SessionConsumerResponse::FencedTransition(_)
        ));
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1),
            "the consumer transition must not append a BindConsumerRequest marker"
        );
    }

    #[tokio::test]
    async fn local_raw_operator_recovery_intent_cannot_bypass_admin_authority() {
        let directory = tempfile::tempdir().expect("operator recovery spoof directory");
        let database = directory.path().join("local.sqlite");
        let backend =
            SqliteSessionBackend::open(&database).expect("operator recovery spoof backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("local-snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open operator recovery spoof store");
        store
            .initialize_cluster()
            .await
            .expect("initialize operator recovery spoof store");

        let before_log = store.inner.raft.metrics().borrow().last_log_index;
        assert_eq!(
            durable_recovery_epoch(&database, store.inner.storage_identity),
            0
        );
        let result = store
            .submit_intent(forged_operator_recovery_intent(0xA1))
            .await;
        assert!(matches!(
            result,
            Err(StoreError::CapabilityNotSupported(reason))
                if reason == "operator_recovery_requires_local_admin_authority"
        ));
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            before_log,
            "rejected local recovery forgery reached the Raft log"
        );
        assert_eq!(
            durable_recovery_epoch(&database, store.inner.storage_identity),
            0,
            "rejected local recovery forgery advanced the durable epoch"
        );
    }

    #[tokio::test]
    async fn forwarded_raw_operator_recovery_intent_cannot_spoof_admin_authority() {
        let directory = tempfile::tempdir().expect("forwarded recovery spoof directory");
        let database = directory.path().join("forwarded.sqlite");
        let backend =
            SqliteSessionBackend::open(&database).expect("forwarded recovery spoof backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("forwarded-snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open forwarded recovery spoof store");
        store
            .initialize_cluster()
            .await
            .expect("initialize forwarded recovery spoof store");

        let before_log = store.inner.raft.metrics().borrow().last_log_index;
        assert_eq!(
            durable_recovery_epoch(&database, store.inner.storage_identity),
            0
        );
        let payload = encode_bounded(&ForwardRequest::Mutation(ForwardMutationRequest {
            request_id: SessionConsensusRequestId::new(),
            intent: forged_operator_recovery_intent(0xB2),
            required_consumer_scope: ForwardConsumerScope::Internal,
        }))
        .expect("encode forged forwarded recovery request");
        let request = SessionConsensusWireRequest::try_new(
            store.inner.storage_identity,
            store.inner.local_node_id,
            SessionConsensusRpcFamily::ForwardMutation,
            payload,
        )
        .expect("bind forged request to an authenticated current member");
        let response = store
            .rpc_handler()
            .handle(store.inner.local_node_id, request)
            .await;
        response.validate().expect("valid rejection response");
        let payload = response.result.expect("encoded forwarded rejection");
        let reply: ForwardMutationReply =
            decode_bounded(&payload).expect("decode forwarded rejection");
        assert!(matches!(
            reply,
            ForwardMutationReply::Applied(response)
                if matches!(
                    &response.result,
                    Err(StoreError::CapabilityNotSupported(reason))
                        if reason == "operator_recovery_requires_local_admin_authority"
                )
                    && response.sequence == 0
                    && response.digest.is_none()
                    && response.logical_time.is_none()
                    && response.raft_log_index == 0
        ));
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            before_log,
            "rejected forwarded recovery forgery reached the Raft log"
        );
        assert_eq!(
            durable_recovery_epoch(&database, store.inner.storage_identity),
            0,
            "rejected forwarded recovery forgery advanced the durable epoch"
        );
    }

    #[tokio::test]
    async fn committed_expiry_floor_is_idempotent_and_survives_leader_clock_rollback() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let directory = tempfile::tempdir().expect("expiry floor directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("expiry floor SQLite backend");
        let start = Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("test timestamp"),
        );
        let clock = Arc::new(MutableClock::new(start));
        let store = ConsensusSessionStore::open_with_clock(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            clock.clone(),
            Duration::from_secs(1),
        )
        .await
        .expect("open expiry floor store");
        store
            .initialize_cluster()
            .await
            .expect("initialize expiry floor store");
        let key = SessionKey {
            tenant: TenantId::new("expiry-floor").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"expiry-floor")
                .try_into()
                .expect("stable ID"),
        };
        let maximum =
            checked_session_deadline(start, crate::MAX_SESSION_TTL).expect("maximum expiry");
        let mut record = StoredSessionRecord {
            key,
            generation: Generation::new(1),
            owner: OwnerId::new("expiry-floor-owner").expect("owner"),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("expiry-floor"),
            expires_at: Some(maximum),
            payload: EncryptedSessionPayload::new(b"payload-free-preflight"),
        };
        let descriptor = RecordExpiryPreflight::from_record(&record);

        store
            .preflight_record_expiry(&[descriptor])
            .await
            .expect("commit first authority floor");
        let first_log = store.inner.raft.metrics().borrow().last_log_index;
        clock.set(Timestamp::from_offset_datetime(
            start
                .as_offset_datetime()
                .checked_sub(time::Duration::days(1))
                .expect("clock rollback"),
        ));
        store
            .preflight_record_expiry(&[descriptor])
            .await
            .expect("persisted floor covers repeated preflight");
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            first_log,
            "nested wrapper preflights must not append another floor"
        );

        record.expires_at = Some(Timestamp::from_offset_datetime(
            maximum
                .as_offset_datetime()
                .checked_add(time::Duration::nanoseconds(1))
                .expect("maximum plus one"),
        ));
        let invalid = RecordExpiryPreflight::from_record(&record);
        assert_eq!(
            store.preflight_record_expiry(&[invalid]).await,
            Err(StoreError::InvalidRecordExpiry)
        );
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            first_log
        );

        let response = store
            .submit_intent(SessionMutationIntent::AdvanceLogicalTime)
            .await
            .expect("command after clock rollback");
        assert_eq!(response.logical_time, Some(start));
    }

    #[tokio::test]
    async fn watch_exposes_only_state_machine_applied_application_entries() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let directory = tempfile::tempdir().expect("watch commit gate directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("watch commit gate SQLite backend");
        let apply_gate = Arc::clone(&backend.consensus_apply_gate);
        let store = ConsensusSessionStore::open_with_clock(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Arc::new(SystemClock),
            Duration::from_secs(1),
        )
        .await
        .expect("open watch commit gate store");
        store
            .initialize_cluster()
            .await
            .expect("initialize watch commit gate store");
        let mut watch = store.watch(1).await.expect("register applied watch");

        let held_apply = apply_gate
            .acquire_owned()
            .await
            .expect("hold state-machine apply");
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        let key = SessionKey {
            tenant: TenantId::new("watch-commit-gate").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"watch-commit-gate")
                .try_into()
                .expect("stable ID"),
        };
        let mutation_store = store.clone();
        let mutation = tokio::spawn(async move {
            mutation_store
                .acquire(
                    &key,
                    OwnerId::new("watch-commit-owner").expect("owner"),
                    Duration::from_secs(30),
                )
                .await
        });
        wait_for_log_index_after(&store, before, "watch commit gate").await;
        assert!(
            watch.next().now_or_never().is_none(),
            "log-only entries must not be visible before state-machine apply"
        );

        drop(held_apply);
        mutation
            .await
            .expect("acquire task")
            .expect("committed acquire");
        let applied = tokio::time::timeout(Duration::from_secs(1), watch.next())
            .await
            .expect("applied watch deadline")
            .expect("applied watch item")
            .expect("valid applied entry");
        assert_eq!(applied.sequence, 1);
        assert!(matches!(applied.op, ReplicationOp::AcquireLease { .. }));
    }

    #[tokio::test]
    async fn accepted_local_proposals_remain_supervised_after_timeout_and_cancellation() {
        let directory = tempfile::tempdir().expect("proposal supervision directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("proposal supervision SQLite backend");
        let apply_gate = Arc::clone(&backend.consensus_apply_gate);
        let store = ConsensusSessionStore::open_with_clock(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Arc::new(SystemClock),
            Duration::from_millis(150),
        )
        .await
        .expect("open proposal supervision store");
        store
            .initialize_cluster()
            .await
            .expect("initialize proposal supervision store");

        let wait_for_all_supervisors = |store: ConsensusSessionStore| async move {
            let permits = tokio::time::timeout(
                Duration::from_secs(1),
                Arc::clone(&store.inner.proposal_admission).acquire_many_owned(
                    u32::try_from(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS)
                        .expect("proposal slot count fits u32"),
                ),
            )
            .await
            .expect("proposal supervisors release admission after apply")
            .expect("proposal admission remains open");
            drop(permits);
        };

        // Dropping the original caller after Openraft accepted its proposal
        // must not release its slot. Saturating the other seven slots proves a
        // disconnect flood cannot enqueue behind that supervised proposal.
        let held_apply = Arc::clone(&apply_gate)
            .acquire_owned()
            .await
            .expect("hold state-machine apply");
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        let cancelled_store = store.clone();
        let cancelled = tokio::spawn(async move {
            cancelled_store
                .submit_intent(SessionMutationIntent::AdvanceLogicalTime)
                .await
        });
        wait_for_log_index_after(&store, before, "first supervised proposal").await;
        assert_eq!(
            store.inner.proposal_admission.available_permits(),
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1,
            "the accepted proposal owns one bounded admission slot"
        );
        cancelled.abort();
        let _ = cancelled.await;
        assert_eq!(
            store.inner.proposal_admission.available_permits(),
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1,
            "accepted proposal admission must outlive its cancelled caller"
        );

        let held_saturation = Arc::clone(&store.inner.proposal_admission)
            .acquire_many_owned(
                u32::try_from(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1)
                    .expect("remaining proposal slots fit u32"),
            )
            .await
            .expect("saturate remaining proposal admission");
        assert_eq!(store.inner.proposal_admission.available_permits(), 0);

        let rejected_overflow = (0..16)
            .map(|_| {
                let store = store.clone();
                tokio::spawn(async move {
                    store
                        .submit_intent(SessionMutationIntent::AdvanceLogicalTime)
                        .await
                })
            })
            .collect::<Vec<_>>();
        for attempt in rejected_overflow {
            assert!(matches!(
                attempt.await.expect("bounded overflow task"),
                Err(StoreError::BackendUnavailable(_))
            ));
        }
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1),
            "saturated admission cannot append another Openraft proposal"
        );
        drop(held_saturation);
        assert_eq!(
            store.inner.proposal_admission.available_permits(),
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1,
            "the cancelled accepted proposal still owns its slot"
        );
        drop(held_apply);
        wait_for_all_supervisors(store.clone()).await;

        // A live non-CAS caller that crosses the same post-submit boundary
        // receives typed ambiguity while the supervisor continues to own
        // admission until the delayed state-machine result arrives.
        let held_apply = Arc::clone(&apply_gate)
            .acquire_owned()
            .await
            .expect("hold state-machine apply for non-CAS");
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        let mutation_store = store.clone();
        let mutation = tokio::spawn(async move {
            mutation_store
                .submit_intent(SessionMutationIntent::AdvanceLogicalTime)
                .await
        });
        wait_for_log_index_after(&store, before, "supervised non-CAS proposal").await;
        assert_eq!(
            mutation.await.expect("non-CAS task"),
            Err(StoreError::BackendOperationOutcomeUnavailable)
        );
        assert_eq!(
            store.inner.proposal_admission.available_permits(),
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1
        );
        drop(held_apply);
        wait_for_all_supervisors(store.clone()).await;

        // Lease APIs must translate that same committed-unknown boundary to
        // their lease-specific non-retryable outcome.
        let held_apply = Arc::clone(&apply_gate)
            .acquire_owned()
            .await
            .expect("hold state-machine apply for lease");
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        let key = SessionKey {
            tenant: TenantId::new("proposal-supervision").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"lease-timeout")
                .try_into()
                .expect("stable ID"),
        };
        let lease_store = store.clone();
        let lease = tokio::spawn(async move {
            lease_store
                .acquire(
                    &key,
                    OwnerId::new("proposal-supervision-owner").expect("owner"),
                    Duration::from_secs(30),
                )
                .await
        });
        wait_for_log_index_after(&store, before, "supervised lease proposal").await;
        assert_eq!(
            lease.await.expect("lease task"),
            Err(LeaseError::OperationOutcomeUnavailable)
        );
        assert_eq!(
            store.inner.proposal_admission.available_permits(),
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1
        );
        drop(held_apply);
        wait_for_all_supervisors(store).await;
    }

    #[tokio::test]
    async fn v2_accepted_proposal_timeout_records_one_effect_and_exact_retry() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let directory = tempfile::tempdir().expect("V2 reply-loss directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("V2 reply-loss SQLite backend");
        let apply_gate = Arc::clone(&backend.consensus_apply_gate);
        let store = ConsensusSessionStore::open_with_clock(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Arc::new(SystemClock),
            Duration::from_millis(150),
        )
        .await
        .expect("open V2 reply-loss store");
        store
            .initialize_cluster()
            .await
            .expect("initialize V2 reply-loss store");
        let mut watch = store.watch(1).await.expect("register applied watch");
        let request = v2_create_request_for_supervision().await;
        let altered = v2_request_with_same_id_different_body(&request);

        // Holding SQLite apply after `last_log_index` advances deterministically
        // cuts the caller after Openraft has accepted the V2 command but before
        // its state-machine receipt or replication notification exists.
        let held_apply = apply_gate
            .acquire_owned()
            .await
            .expect("hold V2 state-machine apply");
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        // The public raw V2 route intentionally requires a fixed durable
        // quorum, and its pre-proposal read-index barrier waits for apply.
        // Construct the exact command that the leader emits after that barrier
        // so this singleton can isolate the already-accepted reply-loss cut.
        let (authority_identity, voters) = store.current_scope().expect("current V2 scope");
        let command = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: store.inner.storage_identity,
            request_id: fenced_transition_v2_outer_request_id(&request),
            logical_time: store.inner.clock.now_utc(),
            intent: SessionMutationIntent::Authorized {
                origin: store.inner.local_node_id,
                authority_identity,
                mutation: Box::new(SessionMutationIntent::ActivateFencedTransitionV2 {
                    request: Box::new(request.clone()),
                    scope_identity: authority_identity,
                    voter_set_digest: fenced_transition_voter_set_digest(
                        authority_identity,
                        &voters,
                    ),
                    profile_digest: crate::fenced_transition::fenced_transition_v2_profile_digest(),
                }),
            },
        };
        validate_consensus_command_preproposal(&command).expect("valid V2 activation command");
        let proposal_permit = Arc::clone(&store.inner.proposal_admission)
            .acquire_owned()
            .await
            .expect("reserve V2 proposal admission");
        let response = store
            .inner
            .raft
            .client_write_ff(command.clone())
            .await
            .expect("Openraft accepts V2 command");
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let completion = response.await;
            let _ = completion_tx.send(completion);
            drop(proposal_permit);
        });
        wait_for_log_index_after(&store, before, "accepted V2 proposal").await;
        let caller_result: Result<(), StoreError> =
            match tokio::time::timeout(Duration::from_millis(150), completion_rx).await {
                Err(_) => Err(StoreError::FencedTransitionOutcomeUnknown),
                Ok(Ok(Ok(Ok(_)))) => Ok(()),
                Ok(Ok(_)) | Ok(Err(_)) => Err(StoreError::FencedTransitionOutcomeUnknown),
            };
        assert_eq!(
            caller_result,
            Err(StoreError::FencedTransitionOutcomeUnknown),
            "a caller deadline after Openraft acceptance is typed ambiguity"
        );
        assert_eq!(
            store.inner.proposal_admission.available_permits(),
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1,
            "the detached accepted V2 proposal retains one bounded admission slot"
        );
        assert!(
            watch.next().now_or_never().is_none(),
            "an accepted but unapplied V2 command has no watch-visible effect"
        );

        drop(held_apply);
        let permits = tokio::time::timeout(
            Duration::from_secs(1),
            Arc::clone(&store.inner.proposal_admission).acquire_many_owned(
                u32::try_from(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS)
                    .expect("proposal slot count fits u32"),
            ),
        )
        .await
        .expect("V2 supervisor releases admission after apply")
        .expect("proposal admission remains open");
        drop(permits);

        let outcome = match store
            .inner
            .backend
            .consensus_fenced_transition_v2_status(
                store.inner.storage_identity,
                authority_identity,
                &request,
            )
            .await
            .expect("exact V2 status after delayed apply")
        {
            FencedTransitionV2Status::Recorded(result) => result
                .as_ref()
                .as_ref()
                .expect("delayed V2 create outcome")
                .clone(),
            status => panic!("delayed V2 request was not recorded: {status:?}"),
        };
        assert!(matches!(
            outcome.mutation(),
            FencedTransitionMutationResult::Created
        ));
        let applied = tokio::time::timeout(Duration::from_secs(1), watch.next())
            .await
            .expect("delayed V2 applied watch deadline")
            .expect("delayed V2 applied watch item")
            .expect("valid delayed V2 applied entry");
        assert_eq!(applied.sequence, 1, "the V2 create applies exactly once");

        assert_eq!(
            store
                .inner
                .raft
                .client_write_ff(command)
                .await
                .expect("Openraft accepts exact V2 retry")
                .await
                .expect("exact V2 retry reaches the state machine")
                .expect("exact V2 retry has a response")
                .data
                .result
                .and_then(|result| match result {
                    SessionMutationOutcome::FencedTransition(retry) => Ok(retry),
                    _ => Err(StoreError::FencedTransitionOutcomeUnknown),
                }),
            Ok(outcome),
            "the exact retained V2 ID/body returns its recorded outcome"
        );
        assert!(
            watch.next().now_or_never().is_none(),
            "the exact V2 retry has no second business or watch effect"
        );
        assert_eq!(
            store
                .inner
                .backend
                .consensus_fenced_transition_v2_status(
                    store.inner.storage_identity,
                    authority_identity,
                    &altered,
                )
                .await,
            Ok(FencedTransitionV2Status::RequestConflict),
            "the same full V2 ID with a different body is a conflict"
        );
    }

    #[tokio::test]
    async fn v2_effect_boundary_proves_uninitialized_singleton_and_batch_not_transmitted() {
        let directory = tempfile::tempdir().expect("V2 effect boundary directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("V2 effect boundary SQLite backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open uninitialized V2 effect boundary store");

        let singleton = v2_test_request(1);
        assert!(matches!(
            SessionBackend::fenced_transition_v2_effect(&store, singleton).await,
            FencedTransitionV2Effect::NotTransmitted(StoreError::BackendUnavailable(_))
        ));

        let first = v2_test_request(1);
        let second = FencedTransitionV2Request::new(
            first.request_id().epoch(),
            FencedTransitionV2CallerNonce::from_bytes([0x52; 16]),
            first.lease().clone(),
            FencedTransitionMutation::delete(Generation::new(2)),
        )
        .expect("distinct V2 batch request");
        assert!(matches!(
            SessionBackend::fenced_transition_v2_batch_effect(&store, vec![first, second]).await,
            FencedTransitionV2Effect::NotTransmitted(StoreError::BackendUnavailable(_))
        ));
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            None,
            "effect-boundary preflight failures append no consensus proposal"
        );
    }

    #[tokio::test]
    async fn v2_submit_effect_boundary_retains_an_openraft_accepted_request() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let directory = tempfile::tempdir().expect("V2 accepted effect boundary directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("V2 accepted effect boundary SQLite backend");
        let apply_gate = Arc::clone(&backend.consensus_apply_gate);
        let store = ConsensusSessionStore::open_with_clock(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Arc::new(SystemClock),
            Duration::from_millis(150),
        )
        .await
        .expect("open V2 accepted effect boundary store");
        store
            .initialize_cluster()
            .await
            .expect("initialize V2 accepted effect boundary store");

        let request = v2_create_request_for_supervision().await;
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        let held_apply = apply_gate
            .acquire_owned()
            .await
            .expect("hold V2 accepted effect state-machine apply");
        let submitting_store = store.clone();
        let submitted_request = request.clone();
        let submission = tokio::spawn(async move {
            submitting_store
                .submit_request_effect_before(
                    fenced_transition_v2_outer_request_id(&submitted_request),
                    SessionMutationIntent::FencedTransitionV2(Box::new(submitted_request)),
                    None,
                    tokio::time::Instant::now() + Duration::from_millis(150),
                )
                .await
        });
        wait_for_log_index_after(&store, before, "V2 effect-boundary accepted proposal").await;
        assert!(matches!(
            submission.await.expect("V2 effect submission task"),
            ConsensusSubmissionEffect::OutcomeUnknown
        ));

        drop(held_apply);
        let permits = tokio::time::timeout(
            Duration::from_secs(1),
            Arc::clone(&store.inner.proposal_admission).acquire_many_owned(
                u32::try_from(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS)
                    .expect("proposal slot count fits u32"),
            ),
        )
        .await
        .expect("accepted V2 supervisor releases admission")
        .expect("proposal admission remains open");
        drop(permits);

        let (authority_identity, _) = store.current_scope().expect("current V2 authority");
        assert!(matches!(
            store
                .inner
                .backend
                .consensus_fenced_transition_v2_status(
                    store.inner.storage_identity,
                    authority_identity,
                    &request,
                )
                .await,
            Ok(FencedTransitionV2Status::Recorded(_))
        ));
    }

    #[tokio::test]
    async fn logical_read_time_cohort_is_shared_bounded_and_cancellation_safe() {
        let directory = tempfile::tempdir().expect("logical-read cohort directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("logical-read cohort SQLite backend");
        let apply_gate = Arc::clone(&backend.consensus_apply_gate);
        let store = ConsensusSessionStore::open_with_clock(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Arc::new(SystemClock),
            Duration::from_secs(1),
        )
        .await
        .expect("open logical-read cohort store");
        store
            .initialize_cluster()
            .await
            .expect("initialize logical-read cohort store");

        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        let held_apply = apply_gate
            .acquire_owned()
            .await
            .expect("hold logical-read state-machine apply");
        let callers = 4;
        let start = Arc::new(tokio::sync::Barrier::new(callers + 1));
        let mut reads = (0..callers)
            .map(|_| {
                let store = store.clone();
                let start = Arc::clone(&start);
                tokio::spawn(async move {
                    start.wait().await;
                    store.logical_read_time().await
                })
            })
            .collect::<Vec<_>>();
        start.wait().await;
        wait_for_log_index_after(&store, before, "logical-read cohort").await;
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1),
            "overlapping same-scope reads share exactly one committed time advance"
        );

        // This arrives after the worker has snapshotted the active cohort. It
        // must wait for a later command, never join an already accepted one.
        let mut late = Box::pin(store.logical_read_time());
        assert!(matches!(
            futures_util::poll!(&mut late),
            std::task::Poll::Pending
        ));
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1),
            "a late caller cannot join an in-flight logical-time proposal"
        );

        // Once the cohort proposal has crossed Openraft's acceptance boundary,
        // removing one caller must neither cancel it nor release its shared
        // work. The surviving callers still receive the same committed time.
        reads.pop().expect("cancelled cohort caller").abort();
        drop(held_apply);
        let mut logical_times = Vec::new();
        for read in reads {
            logical_times.push(
                read.await
                    .expect("live logical-read caller")
                    .expect("cohort logical time"),
            );
        }
        assert!(
            logical_times.windows(2).all(|pair| pair[0] == pair[1]),
            "every live caller observes the cohort's one committed logical time"
        );
        late.await.expect("later cohort logical time");
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 2),
            "a late caller receives a separate later committed cohort"
        );

        let current_scope = store
            .consumer_scope()
            .expect("current consumer scope")
            .consensus_identity();
        let stale_scope = SessionConsensusIdentity::new(
            current_scope.cluster_id(),
            current_scope.configuration_id(),
            SessionConsensusConfigurationEpoch::new(current_scope.configuration_epoch().get() + 1)
                .expect("successor scope epoch"),
        );
        assert_eq!(
            store
                .logical_read_time_before(
                    Some(stale_scope),
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await,
            Err(consensus_unavailable()),
            "a cohort never reuses a committed time across an unadmitted authority scope"
        );
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 2),
            "the rejected authority scope cannot append a logical-time command"
        );

        let permits = Arc::clone(&store.inner.logical_read_time.admission)
            .acquire_many_owned(
                u32::try_from(DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY)
                    .expect("logical-read admission capacity fits u32"),
            )
            .await
            .expect("saturate fixed logical-read admission");
        let deadline = tokio::time::Instant::now() + Duration::from_millis(20);
        assert_eq!(
            store.logical_read_time_before(None, deadline).await,
            Err(consensus_unavailable()),
            "callers beyond the fixed cohort admission fail closed before proposing"
        );
        drop(permits);
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 2),
            "rejected overflow cannot append another logical-time command"
        );
    }

    #[tokio::test]
    async fn v2_status_logical_time_ticket_freezes_at_proposal_and_stays_bounded() {
        let directory = tempfile::tempdir().expect("V2 status ticket cohort directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("V2 status ticket cohort SQLite backend");
        let apply_gate = Arc::clone(&backend.consensus_apply_gate);
        let store = ConsensusSessionStore::open_with_clock(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Arc::new(SystemClock),
            Duration::from_secs(1),
        )
        .await
        .expect("open V2 status ticket cohort store");
        store
            .initialize_cluster()
            .await
            .expect("initialize V2 status ticket cohort store");

        let scope = store
            .consumer_scope()
            .expect("current consumer scope")
            .consensus_identity();
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        let held_apply = apply_gate
            .acquire_owned()
            .await
            .expect("hold V2 status ticket apply");
        let held_proposal = Arc::clone(&store.inner.proposal_admission)
            .acquire_many_owned(
                u32::try_from(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS)
                    .expect("proposal capacity fits u32"),
            )
            .await
            .expect("hold V2 status ticket preproposal");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut first =
            Box::pin(store.fenced_transition_v2_status_logical_time_ticket_before(scope, deadline));
        let mut second =
            Box::pin(store.fenced_transition_v2_status_logical_time_ticket_before(scope, deadline));
        assert!(matches!(
            futures_util::poll!(&mut first),
            std::task::Poll::Pending
        ));
        assert!(matches!(
            futures_util::poll!(&mut second),
            std::task::Poll::Pending
        ));
        drop(held_proposal);
        wait_for_log_index_after(&store, before, "V2 status ticket cohort").await;
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1),
            "arrivals admitted during authority/preproposal share one time fence"
        );

        // `last_log_index` proves `client_write_ff` has accepted the first
        // command.  This arrival sees the freeze and must become the next
        // exact-scope cohort, not a waiter on an already accepted receipt.
        let late_store = store.clone();
        let late = tokio::spawn(async move {
            late_store
                .fenced_transition_v2_status_logical_time_ticket_before(scope, deadline)
                .await
        });
        drop(first);
        drop(held_apply);
        let second_time = second.await.expect("shared V2 status ticket");
        let late_time = late
            .await
            .expect("late V2 status ticket caller")
            .expect("later V2 status ticket");
        assert!(late_time >= second_time);
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 2),
            "an arrival after freeze receives a separate committed proposal"
        );

        let stale_scope = SessionConsensusIdentity::new(
            scope.cluster_id(),
            scope.configuration_id(),
            SessionConsensusConfigurationEpoch::new(scope.configuration_epoch().get() + 1)
                .expect("successor status scope epoch"),
        );
        assert_eq!(
            store
                .fenced_transition_v2_status_logical_time_ticket_before(
                    stale_scope,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await,
            Err(StoreError::TopologyAuthorityRevoked),
            "a distinct authority scope never joins the current ticket cohort"
        );
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 2),
            "scope rejection does not append a logical-time command"
        );

        let permits = Arc::clone(
            &store
                .inner
                .fenced_transition_v2_status_logical_time
                .admission,
        )
        .acquire_many_owned(
            u32::try_from(DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY)
                .expect("V2 status ticket capacity fits u32"),
        )
        .await
        .expect("saturate V2 status ticket admission");
        assert_eq!(
            store
                .fenced_transition_v2_status_logical_time_ticket_before(
                    scope,
                    tokio::time::Instant::now() + Duration::from_millis(20),
                )
                .await,
            Err(consensus_unavailable()),
            "ticket admission capacity fails closed before a proposal"
        );
        drop(permits);
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 2),
            "capacity rejection cannot append a logical-time command"
        );
    }

    #[tokio::test]
    async fn v2_status_follower_ingress_coalesces_until_one_transmission_and_survives_cancel() {
        let (ingress, receiver) = FencedTransitionV2StatusLogicalTimeIngressSupervisor::new();
        let transmissions = Arc::new(AtomicUsize::new(0));
        let representative_entered = Arc::new(tokio::sync::Notify::new());
        let allow_transmission = Arc::new(tokio::sync::Notify::new());
        let allow_reply = Arc::new(tokio::sync::Semaphore::new(0));
        let (transmitted_tx, mut transmitted_rx) = tokio::sync::mpsc::unbounded_channel();
        let scope = status_ticket_scope(1);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut first = Box::pin(ingress.ticket_before(scope, deadline));
        let mut second = Box::pin(ingress.ticket_before(scope, deadline));
        assert!(matches!(
            futures_util::poll!(&mut first),
            std::task::Poll::Pending
        ));
        assert!(matches!(
            futures_util::poll!(&mut second),
            std::task::Poll::Pending
        ));
        let worker = tokio::spawn(
            run_fenced_transition_v2_status_logical_time_cohort_supervisor(receiver, {
                let transmissions = Arc::clone(&transmissions);
                let representative_entered = Arc::clone(&representative_entered);
                let allow_transmission = Arc::clone(&allow_transmission);
                let allow_reply = Arc::clone(&allow_reply);
                let transmitted_tx = transmitted_tx.clone();
                move |scope, _deadline, freeze| {
                    let transmissions = Arc::clone(&transmissions);
                    let representative_entered = Arc::clone(&representative_entered);
                    let allow_transmission = Arc::clone(&allow_transmission);
                    let allow_reply = Arc::clone(&allow_reply);
                    let transmitted_tx = transmitted_tx.clone();
                    async move {
                        representative_entered.notify_one();
                        allow_transmission.notified().await;
                        freeze.store(true, Ordering::Release);
                        let ticket_index = transmissions.fetch_add(1, Ordering::SeqCst) + 1;
                        let _ = transmitted_tx.send(ticket_index);
                        let Ok(_reply_permit) = allow_reply.acquire().await else {
                            return FencedTransitionV2StatusLogicalTimeTicketReply::Unavailable;
                        };
                        status_ticket_reply(scope, ticket_index as u64)
                    }
                }
            }),
        );
        representative_entered.notified().await;
        allow_transmission.notify_one();
        assert_eq!(transmitted_rx.recv().await, Some(1));

        let mut late = Box::pin(ingress.ticket_before(scope, deadline));
        assert!(matches!(
            futures_util::poll!(&mut late),
            std::task::Poll::Pending
        ));

        // The first requester may disappear after its representative has
        // frozen, but the supervisor keeps the reply ownership and bounded
        // admission through the shared ticket's completion.
        drop(first);
        allow_reply.add_permits(1);
        assert!(matches!(
            second.await.expect("live follower caller"),
            FencedTransitionV2StatusLogicalTimeTicketReply::Ticket(ticket)
                if ticket.required_consumer_scope == scope && ticket.raft_log_index == 1
        ));
        allow_transmission.notify_one();
        assert_eq!(transmitted_rx.recv().await, Some(2));
        allow_reply.add_permits(1);
        assert!(matches!(
            late.await.expect("post-freeze follower caller"),
            FencedTransitionV2StatusLogicalTimeTicketReply::Ticket(ticket)
                if ticket.required_consumer_scope == scope && ticket.raft_log_index == 2
        ));
        assert_eq!(
            transmissions.load(Ordering::SeqCst),
            2,
            "two overlapping callers produced one follower representative, while the post-freeze caller produced its successor"
        );
        drop(ingress);
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("follower ingress worker closes")
            .expect("follower ingress worker task");
    }

    #[tokio::test]
    async fn v2_status_follower_ingress_collects_an_already_queued_burst_before_freeze() {
        let (ingress, receiver) = FencedTransitionV2StatusLogicalTimeIngressSupervisor::new();
        let transmissions = Arc::new(AtomicUsize::new(0));
        let scope = status_ticket_scope(1);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let mut callers = (0..4)
            .map(|_| Box::pin(ingress.ticket_before(scope, deadline)))
            .collect::<Vec<_>>();
        for caller in &mut callers {
            assert!(matches!(
                futures_util::poll!(caller),
                std::task::Poll::Pending
            ));
        }

        let worker = tokio::spawn(
            run_fenced_transition_v2_status_logical_time_cohort_supervisor(receiver, {
                let transmissions = Arc::clone(&transmissions);
                move |scope, _deadline, freeze| {
                    let transmissions = Arc::clone(&transmissions);
                    async move {
                        // The bounded queue is drained before the callback is
                        // polled, so every already-admitted request shares the
                        // representative without scheduler synchronization.
                        freeze.store(true, Ordering::Release);
                        let ticket_index = transmissions.fetch_add(1, Ordering::SeqCst) + 1;
                        status_ticket_reply(scope, ticket_index as u64)
                    }
                }
            }),
        );
        for caller in callers {
            assert!(matches!(
                caller.await.expect("queued follower caller"),
                FencedTransitionV2StatusLogicalTimeTicketReply::Ticket(ticket)
                    if ticket.required_consumer_scope == scope && ticket.raft_log_index == 1
            ));
        }
        assert_eq!(
            transmissions.load(Ordering::SeqCst),
            1,
            "one overlapping local follower burst sends one representative without a pre-freeze gate"
        );
        drop(ingress);
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("queued burst worker closes")
            .expect("queued burst worker task");
    }

    #[tokio::test(start_paused = true)]
    async fn v2_status_leader_window_collects_staggered_voter_representatives_once() {
        let (leader, receiver) = FencedTransitionV2StatusLogicalTimeSupervisor::new();
        let proposals = Arc::new(AtomicUsize::new(0));
        let scope = status_ticket_scope(1);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);

        // Queue the first voter before dispatch, then let the leader enter its
        // one absolute collection window. Virtual time cannot advance while
        // this test remains runnable, so the other two voter representatives
        // are deterministically staggered after the initial queue drain.
        let mut first = Box::pin(leader.ticket_before(scope, deadline));
        assert!(matches!(
            futures_util::poll!(&mut first),
            std::task::Poll::Pending
        ));
        let collection_window = Duration::from_millis(10);
        let worker = tokio::spawn(
            run_fenced_transition_v2_status_logical_time_cohort_supervisor_with_collection_window(
                receiver,
                collection_window,
                {
                    let proposals = Arc::clone(&proposals);
                    move |scope, _deadline, freeze| {
                        let proposals = Arc::clone(&proposals);
                        async move {
                            freeze.store(true, Ordering::Release);
                            let proposal = proposals.fetch_add(1, Ordering::SeqCst) + 1;
                            status_ticket_reply(scope, proposal as u64)
                        }
                    }
                },
            ),
        );
        tokio::time::advance(Duration::ZERO).await;
        let mut second = Box::pin(leader.ticket_before(scope, deadline));
        let mut third = Box::pin(leader.ticket_before(scope, deadline));
        assert!(matches!(
            futures_util::poll!(&mut second),
            std::task::Poll::Pending
        ));
        assert!(matches!(
            futures_util::poll!(&mut third),
            std::task::Poll::Pending
        ));
        tokio::time::advance(collection_window).await;

        for caller in [first, second, third] {
            assert!(matches!(
                caller.await.expect("voter ticket caller"),
                FencedTransitionV2StatusLogicalTimeTicketReply::Ticket(ticket)
                    if ticket.required_consumer_scope == scope && ticket.raft_log_index == 1
            ));
        }
        assert_eq!(
            proposals.load(Ordering::SeqCst),
            1,
            "three staggered same-scope voter representatives share one proposal",
        );

        // A representative admitted after the first callback froze belongs to
        // a successor cohort; the original absolute window is never extended.
        assert!(matches!(
            leader
                .ticket_before(scope, deadline)
                .await
                .expect("post-freeze voter caller"),
            FencedTransitionV2StatusLogicalTimeTicketReply::Ticket(ticket)
                if ticket.required_consumer_scope == scope && ticket.raft_log_index == 2
        ));
        assert_eq!(proposals.load(Ordering::SeqCst), 2);
        drop(leader);
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("leader collection worker closes")
            .expect("leader collection worker task");
    }

    #[tokio::test]
    async fn v2_status_ingress_keeps_scopes_fifo_and_rejects_capacity_overflow() {
        let (ingress, receiver) = FencedTransitionV2StatusLogicalTimeIngressSupervisor::new();
        let dispatched_scopes = Arc::new(Mutex::new(Vec::new()));
        let first_dispatch = Arc::new(tokio::sync::Notify::new());
        let release_first = Arc::new(tokio::sync::Notify::new());
        let dispatches = Arc::new(AtomicUsize::new(0));
        let worker = tokio::spawn(
            run_fenced_transition_v2_status_logical_time_cohort_supervisor(receiver, {
                let dispatched_scopes = Arc::clone(&dispatched_scopes);
                let first_dispatch = Arc::clone(&first_dispatch);
                let release_first = Arc::clone(&release_first);
                let dispatches = Arc::clone(&dispatches);
                move |scope, _deadline, freeze| {
                    let dispatched_scopes = Arc::clone(&dispatched_scopes);
                    let first_dispatch = Arc::clone(&first_dispatch);
                    let release_first = Arc::clone(&release_first);
                    let dispatches = Arc::clone(&dispatches);
                    async move {
                        freeze.store(true, Ordering::Release);
                        let ticket_index = dispatches.fetch_add(1, Ordering::SeqCst) + 1;
                        dispatched_scopes
                            .lock()
                            .expect("dispatched scopes lock")
                            .push(scope);
                        if ticket_index == 1 {
                            first_dispatch.notify_one();
                            release_first.notified().await;
                        }
                        status_ticket_reply(scope, ticket_index as u64)
                    }
                }
            }),
        );
        let first_scope = status_ticket_scope(1);
        let second_scope = status_ticket_scope(2);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        let first_ingress = ingress.clone();
        let first = tokio::spawn(async move {
            first_ingress
                .ticket_before(first_scope, deadline)
                .await
                .expect("first-scope ticket reply")
        });
        first_dispatch.notified().await;
        let mut second = Box::pin(ingress.ticket_before(second_scope, deadline));
        assert!(matches!(
            futures_util::poll!(&mut second),
            std::task::Poll::Pending
        ));
        release_first.notify_one();
        assert!(matches!(
            first.await.expect("first scope caller"),
            FencedTransitionV2StatusLogicalTimeTicketReply::Ticket(ticket)
                if ticket.required_consumer_scope == first_scope
        ));
        assert!(matches!(
            second.await.expect("second scope caller"),
            FencedTransitionV2StatusLogicalTimeTicketReply::Ticket(ticket)
                if ticket.required_consumer_scope == second_scope
        ));
        assert_eq!(
            *dispatched_scopes.lock().expect("dispatched scopes lock"),
            vec![first_scope, second_scope],
            "incompatible scopes remain FIFO and never share a representative"
        );

        let permits = Arc::clone(&ingress.admission)
            .acquire_many_owned(
                u32::try_from(DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY)
                    .expect("status ticket capacity fits u32"),
            )
            .await
            .expect("saturate follower ingress admission");
        assert_eq!(
            ingress
                .ticket_before(
                    first_scope,
                    tokio::time::Instant::now() + Duration::from_millis(20),
                )
                .await,
            Err(consensus_unavailable()),
            "the fixed local ingress capacity fails closed before dispatch"
        );
        drop(permits);
        drop(ingress);
        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("scope FIFO worker closes")
            .expect("scope FIFO worker task");
    }

    #[tokio::test]
    async fn v2_status_leader_ingress_routes_into_leader_cohort_without_deadlock() {
        let (leader, leader_receiver) = FencedTransitionV2StatusLogicalTimeSupervisor::new();
        let leader_dispatches = Arc::new(AtomicUsize::new(0));
        let leader_worker = tokio::spawn(
            run_fenced_transition_v2_status_logical_time_cohort_supervisor(leader_receiver, {
                let leader_dispatches = Arc::clone(&leader_dispatches);
                move |scope, _deadline, freeze| {
                    let leader_dispatches = Arc::clone(&leader_dispatches);
                    async move {
                        freeze.store(true, Ordering::Release);
                        let ticket_index = leader_dispatches.fetch_add(1, Ordering::SeqCst) + 1;
                        status_ticket_reply(scope, ticket_index as u64)
                    }
                }
            }),
        );
        let (ingress, ingress_receiver) =
            FencedTransitionV2StatusLogicalTimeIngressSupervisor::new();
        let ingress_worker = tokio::spawn(
            run_fenced_transition_v2_status_logical_time_cohort_supervisor(ingress_receiver, {
                let leader = leader.clone();
                move |scope, deadline, freeze| {
                    let leader = leader.clone();
                    async move {
                        // This is the leader-local route: it freezes the
                        // ingress cohort, then enters the separate leader
                        // cohort rather than recursively entering ingress.
                        freeze.store(true, Ordering::Release);
                        match leader.ticket_before(scope, deadline).await {
                            Ok(reply) => reply,
                            Err(_) => FencedTransitionV2StatusLogicalTimeTicketReply::Unavailable,
                        }
                    }
                }
            }),
        );
        let scope = status_ticket_scope(1);
        let reply = tokio::time::timeout(
            Duration::from_secs(1),
            ingress.ticket_before(scope, tokio::time::Instant::now() + Duration::from_secs(1)),
        )
        .await
        .expect("leader-local ingress cannot wait on itself")
        .expect("leader-local ticket reply");
        assert!(matches!(
            reply,
            FencedTransitionV2StatusLogicalTimeTicketReply::Ticket(ticket)
                if ticket.required_consumer_scope == scope
        ));
        assert_eq!(leader_dispatches.load(Ordering::SeqCst), 1);
        ingress_worker.abort();
        leader_worker.abort();
    }

    #[tokio::test]
    async fn logical_read_deferred_scopes_remain_fifo_across_cohorts() {
        let current = SessionConsensusIdentity::new(
            crate::SessionConsensusClusterId::from_bytes([0x41; 32]),
            crate::SessionConsensusConfigurationId::from_bytes([0x42; 32]),
            SessionConsensusConfigurationEpoch::new(1).expect("current scope epoch"),
        );
        let successor = SessionConsensusIdentity::new(
            current.cluster_id(),
            current.configuration_id(),
            SessionConsensusConfigurationEpoch::new(2).expect("successor scope epoch"),
        );
        let admission = Arc::new(tokio::sync::Semaphore::new(5));
        let request = |scope| {
            let admission = Arc::clone(&admission);
            async move {
                let (reply, _response) = tokio::sync::oneshot::channel();
                LogicalReadTimeRequest {
                    required_consumer_scope: scope,
                    deadline: tokio::time::Instant::now() + Duration::from_secs(1),
                    reply,
                    _admission: admission
                        .acquire_owned()
                        .await
                        .expect("bounded test admission"),
                }
            }
        };

        // The active `None` cohort may collect the later `None` request, but
        // the two incompatible authority scopes retain arrival order and form
        // the next cohort together; neither is coalesced with `None`.
        let mut deferred = VecDeque::from([
            request(Some(current)).await,
            request(None).await,
            request(Some(current)).await,
        ]);
        let mut cohort = vec![request(None).await];
        append_same_scope_logical_read_requests(None, &mut deferred, &mut cohort);
        assert_eq!(cohort.len(), 2, "only exact None scope joins its cohort");
        assert_eq!(deferred.len(), 2);
        assert!(
            deferred
                .iter()
                .all(|request| request.required_consumer_scope == Some(current)),
            "the incompatible scope remains a stable FIFO cohort"
        );

        let first = deferred.pop_front().expect("oldest deferred scope");
        assert_eq!(first.required_consumer_scope, Some(current));
        let mut successor_cohort = vec![first];
        append_same_scope_logical_read_requests(
            Some(current),
            &mut deferred,
            &mut successor_cohort,
        );
        assert_eq!(successor_cohort.len(), 2);
        assert!(deferred.is_empty());

        let mut separate_scope = VecDeque::from([request(Some(successor)).await]);
        append_same_scope_logical_read_requests(None, &mut separate_scope, &mut cohort);
        assert_eq!(
            separate_scope
                .front()
                .map(|request| request.required_consumer_scope),
            Some(Some(successor)),
            "a distinct epoch never crosses into another logical-read cohort"
        );
    }
}

#[cfg(test)]
mod encryption_tests;
