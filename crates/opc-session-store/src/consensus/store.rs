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
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

#[cfg(all(test, target_os = "linux", feature = "test-vfs"))]
use std::sync::{Condvar, OnceLock};

use async_trait::async_trait;
use futures_util::stream::{BoxStream, StreamExt};
use opc_consensus::engine::error::{ClientWriteError, InitializeError, RaftError};
use opc_consensus::engine::{EmptyNode, LogId, StoredMembership};
use opc_consensus::{
    decode_bounded, decode_roster_bounded, durable_openraft_config, encode_bounded,
    encode_roster_bounded, DurableOpenraftDomain, EnsureLinearizableOutcome,
    EnsureLinearizableSupervisor, LinearizableReadAdmit, LinearizableReadBarrier,
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
    protected_roster_profile_voter_set_digest, validate_fenced_transition_v2_batch,
    ConsensusRosterAdmissionCommand, ConsensusRosterAdmissionOutcome, ConsensusRosterRejection,
    ConsensusRosterTerminalCommand, ConsensusRosterTerminalOutcome,
    FinalizeOperatorRecoveryV2Intent,
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
    derive_consumer_consensus_request_id_from_commitment,
    derive_consumer_fenced_transition_request, derive_consumer_request_binding_id,
    session_consumer_identity_commitment, session_consumer_roster_ingress_operation,
    session_consumer_roster_scope_commitment, SessionConsumerAuthorization,
    SessionConsumerAuthorizationGrant, SessionConsumerAuthorizationManifest,
    SessionConsumerBatchResult, SessionConsumerChange, SessionConsumerCompareAndSetRequest,
    SessionConsumerCompareAndSetStatus, SessionConsumerFencedTransitionError,
    SessionConsumerIdentity, SessionConsumerLeaseMutationRequest,
    SessionConsumerLeaseMutationStatus, SessionConsumerOperation, SessionConsumerOutcomeUnknown,
    SessionConsumerRejection, SessionConsumerRequest, SessionConsumerResponse,
    SessionConsumerRoster, SessionConsumerRosterAdmissionMutationResponse,
    SessionConsumerRosterAdmissionReadResponse, SessionConsumerRosterAuthorization,
    SessionConsumerRosterCurrentPublicationAuthorityReadResponse, SessionConsumerRosterRejection,
    SessionConsumerRosterTerminalMutationResponse, SessionConsumerRosterTerminalReadResponse,
    SessionConsumerScope, SessionConsumerStoreError, SessionConsumerV2FencedTransitionBatchError,
    SessionConsumerV2FencedTransitionBatchResult, SessionConsumerV2FencedTransitionError,
    SessionConsumerV2FencedTransitionStatus, SessionConsumerV2Operation, SessionConsumerV2Request,
    SessionConsumerV2Response, SessionQuorumConsumer, SessionQuorumRosterIngress,
    MAX_SESSION_CONSUMER_BATCH_RESPONSE_BYTES,
};
use crate::error::{LeaseError, StoreError};
use crate::fenced_mutation_roster::{
    verify_compact_admission_provenance_v2, CompactAdmissionProvenanceVerificationV2,
    RosterAttestationTrustRootV1, RosterCompactAdmissionProvenanceSigningInputV2,
    RosterCompactAdmissionProvenanceV2, RosterIngressAttestationV1,
    RosterIngressAttestationVerificationInputV1,
};
use crate::fenced_mutation_roster_transport::{
    decode_admission_request_for_scope, decode_terminal_request_for_scope,
    encode_admission_compacted_response, encode_admission_fresh_response,
    encode_admission_poll_admitted_response, encode_admission_replayed_response,
    encode_admission_terminal_response, encode_terminal_admitted_response,
    encode_terminal_compacted_response, encode_terminal_replayed_bytes_response,
    encode_terminal_terminalized_bytes_response,
    encode_terminal_terminalized_validated_bytes_response,
};
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

/// Feature-gated signing fixtures for live consensus integration coverage.
#[cfg(feature = "test-control")]
#[doc(hidden)]
pub mod test_support;

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

const FENCED_TRANSITION_ACTIVATION_REQUEST_ID_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/fenced-transition-activation-request/v1\0";
const PROTECTED_ROSTER_PROFILE_ACTIVATION_REQUEST_ID_DOMAIN: &[u8] =
    b"openpacketcore/session-consensus/protected-roster-profile-activation-request/v1\0";

#[cfg(test)]
static CONSUMER_CONSENSUS_PROPOSAL_COUNT: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static FENCED_TRANSITION_LINEARIZABLE_ADMISSION_COUNT: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static ROSTER_INGRESS_LINEARIZABLE_BARRIER_COUNT: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static ROSTER_INGRESS_LOGICAL_TIME_READ_COUNT: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static ROSTER_INGRESS_ADMISSION_SUBMISSION_COUNT: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static ROSTER_INGRESS_TERMINAL_SUBMISSION_COUNT: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static ROSTER_INGRESS_TERMINAL_STATUS_READ_COUNT: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
#[derive(Default)]
struct ConsumerCasTestCounters {
    command_encodings: AtomicU64,
    command_encoded_bytes: AtomicU64,
    proposals: AtomicU64,
}

#[cfg(test)]
impl ConsumerCasTestCounters {
    fn record_command_encoding(&self, encoded_bytes: usize) {
        self.command_encodings.fetch_add(1, Ordering::Relaxed);
        self.command_encoded_bytes
            .fetch_add(encoded_bytes as u64, Ordering::Relaxed);
    }

    fn record_proposal(&self) {
        self.proposals.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
tokio::task_local! {
    static CONSUMER_CAS_TEST_COUNTERS: Arc<ConsumerCasTestCounters>;
}

#[cfg(test)]
fn reset_consumer_consensus_proposal_count() {
    CONSUMER_CONSENSUS_PROPOSAL_COUNT.store(0, Ordering::Relaxed);
}

#[cfg(test)]
fn reset_fenced_transition_linearizable_admission_count() {
    FENCED_TRANSITION_LINEARIZABLE_ADMISSION_COUNT.store(0, Ordering::Relaxed);
}

#[cfg(test)]
fn reset_roster_ingress_test_counters() {
    ROSTER_INGRESS_LINEARIZABLE_BARRIER_COUNT.store(0, Ordering::Relaxed);
    ROSTER_INGRESS_LOGICAL_TIME_READ_COUNT.store(0, Ordering::Relaxed);
    ROSTER_INGRESS_ADMISSION_SUBMISSION_COUNT.store(0, Ordering::Relaxed);
    ROSTER_INGRESS_TERMINAL_SUBMISSION_COUNT.store(0, Ordering::Relaxed);
    ROSTER_INGRESS_TERMINAL_STATUS_READ_COUNT.store(0, Ordering::Relaxed);
}

const SESSION_CONSENSUS_ROUTE_RETRY_BACKOFF: Duration = Duration::from_millis(50);
const FENCED_TRANSITION_V2_STATUS_LEADER_COLLECTION_WINDOW: Duration = Duration::from_micros(500);
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

/// Derive a stable private activation request identity from one exact voter
/// scope. It accepts no caller material, so concurrent state-voter startups
/// coalesce to one certificate proposal for the same scope.
fn fenced_transition_activation_request_id(
    scope: SessionConsensusIdentity,
) -> SessionConsensusRequestId {
    let mut hasher = Sha256::new();
    hasher.update(FENCED_TRANSITION_ACTIVATION_REQUEST_ID_DOMAIN);
    hasher.update(scope.cluster_id().as_bytes());
    hasher.update(scope.configuration_id().as_bytes());
    hasher.update(scope.configuration_epoch().get().to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut request_id = [0_u8; 16];
    request_id.copy_from_slice(&digest[..16]);
    SessionConsensusRequestId::from_bytes(request_id)
}

/// Derive a separate idempotency namespace for immutable protected-roster
/// profile activation. A prior generic V1 activation must not suppress this
/// stronger exact-profile certificate proposal.
fn protected_roster_profile_activation_request_id(
    scope: SessionConsensusIdentity,
) -> SessionConsensusRequestId {
    let mut hasher = Sha256::new();
    hasher.update(PROTECTED_ROSTER_PROFILE_ACTIVATION_REQUEST_ID_DOMAIN);
    hasher.update(scope.cluster_id().as_bytes());
    hasher.update(scope.configuration_id().as_bytes());
    hasher.update(scope.configuration_epoch().get().to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut request_id = [0_u8; 16];
    request_id.copy_from_slice(&digest[..16]);
    SessionConsensusRequestId::from_bytes(request_id)
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
    /// Number of snapshots that completed offline finalization and durable
    /// OpenRaft publication on this voter.
    pub completed_snapshot_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperatorRecoveryCommitError {
    NotLocalLeader,
    Rejected,
    Unavailable,
}

/// One complete V2 recovery-finalization proposal. Keeping the request as an
/// authenticated payload makes the call boundary mirror the replicated
/// command and prevents the recovery API from growing an error-prone list of
/// independent high-water and predecessor arguments.
#[derive(Clone)]
pub(crate) struct OperatorRecoveryCommitRequest {
    pub(crate) request_id: SessionConsensusRequestId,
    pub(crate) intent: FinalizeOperatorRecoveryV2Intent,
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
    RecordExpiryPreflight {
        preflights: BoundedRecordExpiryPreflights,
        /// The consumer scope that must remain valid through the leader's
        /// logical-time proposal. Internal callers do not carry this scope.
        required_consumer_scope: ForwardConsumerScope,
    },
    /// Ask the current leader to join one exact-scope V2 status logical-time
    /// cohort.  This is deliberately a separate forwarding shape: forwarding
    /// a raw `AdvanceLogicalTime` from every voter would recreate one proposal
    /// per node before the leader had an opportunity to coalesce arrivals.
    FencedTransitionV2StatusLogicalTimeTicket {
        required_consumer_scope: Box<SessionConsensusIdentity>,
    },
}

/// Serialization-only view used while forwarding a mutation to a remote
/// leader.  Keeping this as a reference is wire-identical to
/// [`ForwardRequest::Mutation`] but avoids cloning the sealed mutation just
/// to encode a proven-before-transmission attempt.
#[derive(Serialize)]
enum BorrowedForwardRequest<'a> {
    Mutation(&'a ForwardMutationRequest),
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
    Unavailable,
    /// A forwarded write or local proposal crossed a boundary after which the
    /// command may exist and must be resolved by its retained ID.
    OutcomeUnknown,
    // This is deliberately appended. ForwardMutation is a postcard enum used
    // by already-deployed state voters, so changing the discriminants of
    // NotLeader or Unavailable would turn an ordinary mixed-version rejection
    // into a misinterpreted successful control response.
    FencedTransitionActivation(Result<FencedTransitionActivationReply, StoreError>),
}

/// Private forwarding acknowledgement for the state-voter-only V1 startup
/// preflight. The applied index makes a follower wait until its own SQLite
/// state machine has durably observed the certificate before reporting ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct FencedTransitionActivationReply {
    applied_log_index: u64,
}

// Postcard encodes enum discriminants by declaration order. These test-only
// mirrors are the frozen v711 forwarding contract: future additions must stay
// append-only so an older receiver fails closed instead of interpreting a new
// terminal response as a retryable one.
#[cfg(test)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
enum FrozenV711ForwardRequest {
    Mutation(ForwardMutationRequest),
    RecordExpiryPreflight {
        preflights: BoundedRecordExpiryPreflights,
        required_consumer_scope: ForwardConsumerScope,
    },
}

#[cfg(test)]
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
enum FrozenV711ForwardMutationReply {
    Applied(Box<SessionConsensusResponse>),
    RecordExpiryPreflight(Result<(), StoreError>),
    NotLeader {
        leader: Option<SessionConsensusNodeId>,
    },
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
    AuthenticatedRejection(SessionConsensusPeerError),
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

/// Probe for the V1 cluster-scope activation command. This is distinct from
/// the transition probe: a voter that can execute a transition might predate
/// the activation command, and therefore cannot establish its certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FencedTransitionActivationCapabilityProbe {
    activation_probe_schema_version: u16,
    activation_command_schema_version: u16,
}

const FENCED_TRANSITION_ACTIVATION_PROBE_SCHEMA_V1: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum FencedTransitionActivationCapabilityReply {
    V1,
    Unsupported,
}

/// An explicit authenticated unsupported response is a protocol fact. A
/// timeout, malformed response, or failed RPC is only a transient failure to
/// establish unanimity and must never be reported as incompatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FencedTransitionCapabilityProbeOutcome {
    V1,
    Unsupported,
    Unavailable,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FencedTransitionV2CapabilityProbeOutcome {
    Exact,
    Unsupported,
    Unavailable,
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

/// Exact immutable protected-roster profile probe. It is intentionally a
/// separate wire shape from every fenced-transition probe, so an older peer,
/// a mixed profile, or a future profile cannot be counted toward unanimity.
const PROTECTED_ROSTER_PROFILE_PROBE_DOMAIN_V1: [u8; 8] = *b"opc-rp-1";
const PROTECTED_ROSTER_PROFILE_PROBE_SCHEMA_V1: u16 = 1;
const PROTECTED_ROSTER_PROFILE_REPLY_DOMAIN_V1: [u8; 8] = *b"opc-rr-1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedRosterProfileCapabilityProbe {
    domain: [u8; 8],
    schema_version: u16,
    profile_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedRosterProfileCapabilityReply {
    domain: [u8; 8],
    schema_version: u16,
    outcome: ProtectedRosterProfileCapabilityOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum ProtectedRosterProfileCapabilityOutcome {
    Supported { profile_digest: [u8; 32] },
    Unsupported,
}

fn protected_roster_profile_capability_probe_reply(
    probe: ProtectedRosterProfileCapabilityProbe,
    local_capability: AtomicFencedTransitionCapability,
) -> ProtectedRosterProfileCapabilityReply {
    let profile_digest = crate::fenced_mutation_roster::profile_digest();
    if probe.domain == PROTECTED_ROSTER_PROFILE_PROBE_DOMAIN_V1
        && probe.schema_version == PROTECTED_ROSTER_PROFILE_PROBE_SCHEMA_V1
        && probe.profile_digest == profile_digest
        && local_capability == AtomicFencedTransitionCapability::V1
    {
        ProtectedRosterProfileCapabilityReply {
            domain: PROTECTED_ROSTER_PROFILE_REPLY_DOMAIN_V1,
            schema_version: PROTECTED_ROSTER_PROFILE_PROBE_SCHEMA_V1,
            outcome: ProtectedRosterProfileCapabilityOutcome::Supported { profile_digest },
        }
    } else {
        ProtectedRosterProfileCapabilityReply {
            domain: PROTECTED_ROSTER_PROFILE_REPLY_DOMAIN_V1,
            schema_version: PROTECTED_ROSTER_PROFILE_PROBE_SCHEMA_V1,
            outcome: ProtectedRosterProfileCapabilityOutcome::Unsupported,
        }
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

/// The one local quorum proof that a physical V1 transition or V1 activation
/// preflight carries into its eventual Raft proposal. It is leader-local, so
/// it cannot be reused for another scope, authority, or operation.
struct FencedTransitionProposalAdmission {
    read_admit: Option<LinearizableReadAdmit<SessionConsensusNodeId>>,
    scope_identity: SessionConsensusIdentity,
    voter_set_digest: [u8; 32],
    required_consumer_scope: ForwardConsumerScope,
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

/// Recovery-gate result at a local readiness boundary.
///
/// This deliberately keeps immutable terminal proof failures separate from
/// retryable backend unavailability.  Both deny traffic, but only the latter
/// is a transient observation; a durable Active latch and corrupt terminal
/// evidence require explicit recovery handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OperatorRecoveryGate {
    Clear,
    Active,
    Corrupt,
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
    /// Public raw V2 calls which retained the cold generic admission path.
    pub public_raw_v2_cold_admissions: u64,
    /// Public raw V2 cold paths which read receipt history before submit.
    pub public_raw_v2_history_reads: u64,
    /// Fixed raw V2 atomic authority/activation snapshots attempted locally.
    pub fixed_raw_v2_acceptance_snapshots: u64,
    /// Fixed raw V2 proposals accepted at the local OpenRaft boundary.
    pub fixed_raw_v2_proposals: u64,
    /// Proactive SQLite PASSIVE checkpoint attempts for this store.
    pub proactive_checkpoint_attempts: u64,
    /// Proactive SQLite PASSIVE checkpoints that fully drained their reported
    /// WAL frames without a busy reader.
    pub proactive_checkpoint_completed: u64,
    /// Proactive SQLite PASSIVE checkpoints that left reported WAL frames
    /// undrained, whether SQLite reported busy or a pinned reader allowed only
    /// partial progress.
    pub proactive_checkpoint_busy: u64,
    /// Proactive SQLite PASSIVE checkpoint connection or SQLite failures.
    pub proactive_checkpoint_failures: u64,
    /// Maximum queued proactive checkpoint signals; this lane is capacity one.
    pub proactive_checkpoint_queue_high_water: u64,
    /// Maximum simultaneous proactive checkpoint workers; this lane is one.
    pub proactive_checkpoint_worker_high_water: u64,
    /// Physical log-prune signals accepted by the fixed-capacity lane.
    pub consensus_log_prune_signals: u64,
    /// Physical log-prune turns started by this store's one worker.
    pub consensus_log_prune_attempts: u64,
    /// Physical log-prune turns which completed their selected delete.
    pub consensus_log_prune_completed_turns: u64,
    /// Physical log-prune turns which drained all rows through the floor.
    pub consensus_log_prune_drained_turns: u64,
    /// Physical log-prune turns retried after SQLite busy or locked contention.
    pub consensus_log_prune_busy_retries: u64,
    /// Permanent physical log-prune failures; the worker stops until reopen.
    pub consensus_log_prune_permanent_failures: u64,
    /// Whether this fixed lane is permanently degraded until the store is
    /// reopened. This has no identifying error detail.
    #[serde(default)]
    pub consensus_log_prune_degraded: bool,
    /// Physical consensus-log rows deleted by completed prune turns.
    pub consensus_log_prune_rows_deleted: u64,
    /// Encoded consensus-log bytes deleted by completed prune turns.
    pub consensus_log_prune_encoded_bytes_deleted: u64,
    /// Completed prune turns that left rows through the logical floor.
    pub consensus_log_prune_backlog_turns: u64,
    /// Physical-prune turns which required another bounded turn.
    pub consensus_log_prune_more_turns: u64,
    /// Maximum queued physical-prune signals; this lane is capacity one.
    pub consensus_log_prune_queue_high_water: u64,
    /// Maximum active physical-prune turns; this lane has one worker.
    pub consensus_log_prune_active_high_water: u64,
    /// Maximum physical-prune workers; this lane has one worker.
    pub consensus_log_prune_worker_high_water: u64,
}

/// Fixed number of logarithmic millisecond buckets in protected-roster store
/// diagnostics. Bucket zero is below one millisecond, bucket `n` covers
/// `[2^(n-1), 2^n)` milliseconds, and the final bucket includes all larger
/// durations.
pub const PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS: usize = 16;

/// Fixed-cardinality, redaction-safe diagnostics for the protected-roster
/// consensus and durable-storage path.
///
/// This is a separate additive snapshot so extending roster observability
/// does not change the established [`ConsensusStoreDiagnosticSnapshot`]
/// source or positional-serialization shape. It contains only numeric scalars
/// and fixed arrays; no peer, scope, tenant, request, path, SQL, payload, or
/// backend error can enter it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Default)]
pub struct ProtectedRosterConsensusDiagnosticSnapshot {
    /// Admission proposal-to-applied-response latency while the initiating
    /// store caller still awaited completion.
    pub admission_applied_attached_latency_millis:
        [u64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
    /// Admission proposal-to-applied-response latency after the initiating
    /// store caller detached or timed out.
    pub admission_applied_detached_latency_millis:
        [u64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
    /// Terminal proposal-to-applied-response latency while the initiating
    /// store caller still awaited completion.
    pub terminal_applied_attached_latency_millis:
        [u64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
    /// Terminal proposal-to-applied-response latency after the initiating
    /// store caller detached or timed out.
    pub terminal_applied_detached_latency_millis:
        [u64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
    /// Successful SQLite transaction-commit duration for Raft-log batches
    /// containing a protected-roster command. On production file-backed
    /// stores this includes the configured synchronous durability path; it is
    /// not represented as isolated VFS `xSync` duration.
    pub log_append_sqlite_commit_latency_millis: [u64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
    /// Successful SQLite state-machine transaction-commit duration when the
    /// transaction contains a roster command or deterministic roster work.
    pub state_machine_sqlite_commit_latency_millis:
        [u64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
    /// Number of deterministic roster maintenance turns performed inside an
    /// ordinary response-path state-machine transaction.
    pub response_path_maintenance_turns: u64,
    /// Response-path roster maintenance latency before the enclosing commit.
    pub response_path_maintenance_latency_millis:
        [u64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
    /// Store-wide proactive checkpoint-worker latency. This is explicitly
    /// background work and is not attributed to a tenant or roster.
    pub background_checkpoint_latency_millis: [u64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
    /// Whether the following occupancy gauges are one coherent authenticated
    /// witness projection (`0` or `1`).
    pub occupancy_valid: u64,
    /// Even publication generation for the coherent gauge group; it changes
    /// after every complete publication.
    pub occupancy_generation: u64,
    /// Live protected-roster reservations.
    pub live_reservations: u64,
    /// Retained terminal protected-roster reservations.
    pub retained_reservations: u64,
    /// Compact terminal tombstone reservations.
    pub tombstone_reservations: u64,
    /// Durable partition history floors.
    pub history_floors: u64,
    /// Durable retirement cursors.
    pub retirement_cursors: u64,
    /// Materialized protected-roster charge.
    pub materialized_charge_bytes: u64,
    /// Reserved future protected-roster charge.
    pub reserved_future_charge_bytes: u64,
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
    public_raw_v2_cold_admissions: AtomicU64,
    public_raw_v2_history_reads: AtomicU64,
    fixed_raw_v2_acceptance_snapshots: AtomicU64,
    fixed_raw_v2_proposals: AtomicU64,
    proactive_checkpoint_attempts: AtomicU64,
    proactive_checkpoint_completed: AtomicU64,
    proactive_checkpoint_busy: AtomicU64,
    proactive_checkpoint_failures: AtomicU64,
    proactive_checkpoint_queue_high_water: AtomicU64,
    proactive_checkpoint_workers_active: AtomicU64,
    proactive_checkpoint_worker_high_water: AtomicU64,
    consensus_log_prune_signals: AtomicU64,
    consensus_log_prune_attempts: AtomicU64,
    consensus_log_prune_completed_turns: AtomicU64,
    consensus_log_prune_drained_turns: AtomicU64,
    consensus_log_prune_busy_retries: AtomicU64,
    consensus_log_prune_permanent_failures: AtomicU64,
    consensus_log_prune_degraded: AtomicBool,
    consensus_log_prune_rows_deleted: AtomicU64,
    consensus_log_prune_encoded_bytes_deleted: AtomicU64,
    consensus_log_prune_backlog_turns: AtomicU64,
    consensus_log_prune_more_turns: AtomicU64,
    consensus_log_prune_queue_high_water: AtomicU64,
    consensus_log_prune_active: AtomicU64,
    consensus_log_prune_active_high_water: AtomicU64,
    consensus_log_prune_workers_active: AtomicU64,
    consensus_log_prune_worker_high_water: AtomicU64,
    protected_roster_admission_applied_attached_latency_millis:
        [AtomicU64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
    protected_roster_admission_applied_detached_latency_millis:
        [AtomicU64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
    protected_roster_terminal_applied_attached_latency_millis:
        [AtomicU64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
    protected_roster_terminal_applied_detached_latency_millis:
        [AtomicU64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
    protected_roster_log_append_sqlite_commit_latency_millis:
        [AtomicU64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
    protected_roster_state_machine_sqlite_commit_latency_millis:
        [AtomicU64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
    protected_roster_response_path_maintenance_turns: AtomicU64,
    protected_roster_response_path_maintenance_latency_millis:
        [AtomicU64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
    background_checkpoint_latency_millis: [AtomicU64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
    protected_roster_occupancy_writer: AtomicBool,
    protected_roster_occupancy_generation: AtomicU64,
    protected_roster_occupancy_valid: AtomicBool,
    protected_roster_live_reservations: AtomicU64,
    protected_roster_retained_reservations: AtomicU64,
    protected_roster_tombstone_reservations: AtomicU64,
    protected_roster_history_floors: AtomicU64,
    protected_roster_retirement_cursors: AtomicU64,
    protected_roster_materialized_charge_bytes: AtomicU64,
    protected_roster_reserved_future_charge_bytes: AtomicU64,
    // This is not a diagnostic value. Reusing the existing per-store Arc
    // keeps the hint store-scoped across every construction path.
    fixed_raw_v2_warm_route: AtomicBool,
}

impl ConsensusStoreDiagnosticCounters {
    fn saturating_add(counter: &AtomicU64, value: u64) {
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            Some(current.saturating_add(value))
        });
    }

    fn duration_bucket(duration: Duration) -> usize {
        let milliseconds = u64::try_from(duration.as_millis()).unwrap_or(u64::MAX);
        if milliseconds == 0 {
            return 0;
        }
        ((u64::BITS - milliseconds.leading_zeros()) as usize)
            .min(PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS - 1)
    }

    fn record_latency(
        buckets: &[AtomicU64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS],
        duration: Duration,
    ) {
        Self::saturating_add(&buckets[Self::duration_bucket(duration)], 1);
    }

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

    pub(crate) fn observe_proactive_checkpoint_signal(&self) {
        self.proactive_checkpoint_queue_high_water
            .fetch_max(1, Ordering::Relaxed);
    }

    pub(crate) fn begin_proactive_checkpoint(&self) {
        self.proactive_checkpoint_attempts
            .fetch_add(1, Ordering::Relaxed);
        let active = self
            .proactive_checkpoint_workers_active
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.proactive_checkpoint_worker_high_water
            .fetch_max(active, Ordering::Relaxed);
    }

    pub(crate) fn complete_proactive_checkpoint(&self, incomplete: bool, elapsed: Duration) {
        self.proactive_checkpoint_workers_active
            .fetch_sub(1, Ordering::Relaxed);
        Self::record_latency(&self.background_checkpoint_latency_millis, elapsed);
        if incomplete {
            self.proactive_checkpoint_busy
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.proactive_checkpoint_completed
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn fail_proactive_checkpoint(&self, elapsed: Duration) {
        self.proactive_checkpoint_workers_active
            .fetch_sub(1, Ordering::Relaxed);
        Self::record_latency(&self.background_checkpoint_latency_millis, elapsed);
        self.proactive_checkpoint_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn observe_protected_roster_proposal_to_applied_response(
        &self,
        terminal: bool,
        attached: bool,
        elapsed: Duration,
    ) {
        let buckets = match (terminal, attached) {
            (false, true) => &self.protected_roster_admission_applied_attached_latency_millis,
            (false, false) => &self.protected_roster_admission_applied_detached_latency_millis,
            (true, true) => &self.protected_roster_terminal_applied_attached_latency_millis,
            (true, false) => &self.protected_roster_terminal_applied_detached_latency_millis,
        };
        Self::record_latency(buckets, elapsed);
    }

    pub(crate) fn observe_protected_roster_log_append_sqlite_commit(&self, elapsed: Duration) {
        Self::record_latency(
            &self.protected_roster_log_append_sqlite_commit_latency_millis,
            elapsed,
        );
    }

    pub(crate) fn observe_protected_roster_state_machine_sqlite_commit(&self, elapsed: Duration) {
        Self::record_latency(
            &self.protected_roster_state_machine_sqlite_commit_latency_millis,
            elapsed,
        );
    }

    pub(crate) fn observe_protected_roster_piggyback_maintenance(
        &self,
        turns: u64,
        elapsed: Duration,
    ) {
        Self::saturating_add(
            &self.protected_roster_response_path_maintenance_turns,
            turns,
        );
        Self::record_latency(
            &self.protected_roster_response_path_maintenance_latency_millis,
            elapsed,
        );
    }

    pub(crate) fn set_protected_roster_occupancy(
        &self,
        occupancy: crate::fenced_mutation_roster_storage::ProtectedRosterLedgerOccupancy,
    ) {
        self.publish_protected_roster_occupancy(Some(occupancy));
    }

    pub(crate) fn invalidate_protected_roster_occupancy(&self) {
        self.publish_protected_roster_occupancy(None);
    }

    fn publish_protected_roster_occupancy(
        &self,
        occupancy: Option<crate::fenced_mutation_roster_storage::ProtectedRosterLedgerOccupancy>,
    ) {
        while self
            .protected_roster_occupancy_writer
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            std::hint::spin_loop();
        }
        self.protected_roster_occupancy_generation
            .fetch_add(1, Ordering::AcqRel);
        let valid = occupancy.is_some();
        let occupancy = occupancy.unwrap_or_default();
        self.protected_roster_live_reservations
            .store(occupancy.live_reservations, Ordering::Relaxed);
        self.protected_roster_retained_reservations
            .store(occupancy.retained_reservations, Ordering::Relaxed);
        self.protected_roster_tombstone_reservations
            .store(occupancy.tombstone_reservations, Ordering::Relaxed);
        self.protected_roster_history_floors
            .store(occupancy.history_floors, Ordering::Relaxed);
        self.protected_roster_retirement_cursors
            .store(occupancy.retirement_cursors, Ordering::Relaxed);
        self.protected_roster_materialized_charge_bytes
            .store(occupancy.materialized_charge_bytes, Ordering::Relaxed);
        self.protected_roster_reserved_future_charge_bytes
            .store(occupancy.reserved_future_charge_bytes, Ordering::Relaxed);
        self.protected_roster_occupancy_valid
            .store(valid, Ordering::Relaxed);
        self.protected_roster_occupancy_generation
            .fetch_add(1, Ordering::Release);
        self.protected_roster_occupancy_writer
            .store(false, Ordering::Release);
    }

    pub(crate) fn observe_consensus_log_prune_signal(&self) {
        self.consensus_log_prune_signals
            .fetch_add(1, Ordering::Relaxed);
        self.consensus_log_prune_queue_high_water
            .fetch_max(1, Ordering::Relaxed);
    }

    pub(crate) fn begin_consensus_log_prune_worker(&self) {
        let active = self
            .consensus_log_prune_workers_active
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.consensus_log_prune_worker_high_water
            .fetch_max(active, Ordering::Relaxed);
    }

    pub(crate) fn end_consensus_log_prune_worker(&self) {
        self.consensus_log_prune_workers_active
            .fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn begin_consensus_log_prune_turn(&self) {
        self.consensus_log_prune_attempts
            .fetch_add(1, Ordering::Relaxed);
        let active = self
            .consensus_log_prune_active
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        self.consensus_log_prune_active_high_water
            .fetch_max(active, Ordering::Relaxed);
    }

    pub(crate) fn complete_consensus_log_prune_turn(
        &self,
        rows_deleted: u64,
        encoded_bytes_deleted: u64,
        more: bool,
    ) {
        self.consensus_log_prune_active
            .fetch_sub(1, Ordering::Relaxed);
        self.consensus_log_prune_completed_turns
            .fetch_add(1, Ordering::Relaxed);
        self.consensus_log_prune_rows_deleted
            .fetch_add(rows_deleted, Ordering::Relaxed);
        self.consensus_log_prune_encoded_bytes_deleted
            .fetch_add(encoded_bytes_deleted, Ordering::Relaxed);
        if more {
            self.consensus_log_prune_backlog_turns
                .fetch_add(1, Ordering::Relaxed);
            self.consensus_log_prune_more_turns
                .fetch_add(1, Ordering::Relaxed);
        } else {
            self.consensus_log_prune_drained_turns
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn retry_consensus_log_prune_turn(&self) {
        self.consensus_log_prune_active
            .fetch_sub(1, Ordering::Relaxed);
        self.consensus_log_prune_busy_retries
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn fail_consensus_log_prune_turn(&self) {
        self.consensus_log_prune_active
            .fetch_sub(1, Ordering::Relaxed);
        self.consensus_log_prune_permanent_failures
            .fetch_add(1, Ordering::Relaxed);
        self.consensus_log_prune_degraded
            .store(true, Ordering::Release);
    }

    pub(crate) fn clear_consensus_log_prune_degraded(&self) {
        self.consensus_log_prune_degraded
            .store(false, Ordering::Release);
    }

    /// End an active physical-prune turn cancelled by store shutdown. This is
    /// intentionally not a failure: shutdown may interrupt any SQLite stage.
    pub(crate) fn cancel_consensus_log_prune_turn(&self) {
        self.consensus_log_prune_active
            .fetch_sub(1, Ordering::Relaxed);
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn consensus_log_prune_gauges_for_test(&self) -> (u64, u64) {
        (
            self.consensus_log_prune_active.load(Ordering::Relaxed),
            self.consensus_log_prune_workers_active
                .load(Ordering::Relaxed),
        )
    }

    pub(crate) fn snapshot(&self) -> ConsensusStoreDiagnosticSnapshot {
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
            public_raw_v2_cold_admissions: self
                .public_raw_v2_cold_admissions
                .load(Ordering::Relaxed),
            public_raw_v2_history_reads: self.public_raw_v2_history_reads.load(Ordering::Relaxed),
            fixed_raw_v2_acceptance_snapshots: self
                .fixed_raw_v2_acceptance_snapshots
                .load(Ordering::Relaxed),
            fixed_raw_v2_proposals: self.fixed_raw_v2_proposals.load(Ordering::Relaxed),
            proactive_checkpoint_attempts: self
                .proactive_checkpoint_attempts
                .load(Ordering::Relaxed),
            proactive_checkpoint_completed: self
                .proactive_checkpoint_completed
                .load(Ordering::Relaxed),
            proactive_checkpoint_busy: self.proactive_checkpoint_busy.load(Ordering::Relaxed),
            proactive_checkpoint_failures: self
                .proactive_checkpoint_failures
                .load(Ordering::Relaxed),
            proactive_checkpoint_queue_high_water: self
                .proactive_checkpoint_queue_high_water
                .load(Ordering::Relaxed),
            proactive_checkpoint_worker_high_water: self
                .proactive_checkpoint_worker_high_water
                .load(Ordering::Relaxed),
            consensus_log_prune_signals: self.consensus_log_prune_signals.load(Ordering::Relaxed),
            consensus_log_prune_attempts: self.consensus_log_prune_attempts.load(Ordering::Relaxed),
            consensus_log_prune_completed_turns: self
                .consensus_log_prune_completed_turns
                .load(Ordering::Relaxed),
            consensus_log_prune_drained_turns: self
                .consensus_log_prune_drained_turns
                .load(Ordering::Relaxed),
            consensus_log_prune_busy_retries: self
                .consensus_log_prune_busy_retries
                .load(Ordering::Relaxed),
            consensus_log_prune_permanent_failures: self
                .consensus_log_prune_permanent_failures
                .load(Ordering::Relaxed),
            consensus_log_prune_degraded: self.consensus_log_prune_degraded.load(Ordering::Acquire),
            consensus_log_prune_rows_deleted: self
                .consensus_log_prune_rows_deleted
                .load(Ordering::Relaxed),
            consensus_log_prune_encoded_bytes_deleted: self
                .consensus_log_prune_encoded_bytes_deleted
                .load(Ordering::Relaxed),
            consensus_log_prune_backlog_turns: self
                .consensus_log_prune_backlog_turns
                .load(Ordering::Relaxed),
            consensus_log_prune_more_turns: self
                .consensus_log_prune_more_turns
                .load(Ordering::Relaxed),
            consensus_log_prune_queue_high_water: self
                .consensus_log_prune_queue_high_water
                .load(Ordering::Relaxed),
            consensus_log_prune_active_high_water: self
                .consensus_log_prune_active_high_water
                .load(Ordering::Relaxed),
            consensus_log_prune_worker_high_water: self
                .consensus_log_prune_worker_high_water
                .load(Ordering::Relaxed),
        }
    }

    fn protected_roster_snapshot(&self) -> ProtectedRosterConsensusDiagnosticSnapshot {
        let occupancy = loop {
            let before = self
                .protected_roster_occupancy_generation
                .load(Ordering::Acquire);
            if !before.is_multiple_of(2) {
                std::hint::spin_loop();
                continue;
            }
            let occupancy = (
                self.protected_roster_occupancy_valid
                    .load(Ordering::Relaxed),
                self.protected_roster_live_reservations
                    .load(Ordering::Relaxed),
                self.protected_roster_retained_reservations
                    .load(Ordering::Relaxed),
                self.protected_roster_tombstone_reservations
                    .load(Ordering::Relaxed),
                self.protected_roster_history_floors.load(Ordering::Relaxed),
                self.protected_roster_retirement_cursors
                    .load(Ordering::Relaxed),
                self.protected_roster_materialized_charge_bytes
                    .load(Ordering::Relaxed),
                self.protected_roster_reserved_future_charge_bytes
                    .load(Ordering::Relaxed),
            );
            let after = self
                .protected_roster_occupancy_generation
                .load(Ordering::Acquire);
            if before == after {
                break (after, occupancy);
            }
        };
        let load_buckets = |buckets: &[AtomicU64; PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS]| {
            buckets
                .each_ref()
                .map(|counter| counter.load(Ordering::Relaxed))
        };
        ProtectedRosterConsensusDiagnosticSnapshot {
            admission_applied_attached_latency_millis: load_buckets(
                &self.protected_roster_admission_applied_attached_latency_millis,
            ),
            admission_applied_detached_latency_millis: load_buckets(
                &self.protected_roster_admission_applied_detached_latency_millis,
            ),
            terminal_applied_attached_latency_millis: load_buckets(
                &self.protected_roster_terminal_applied_attached_latency_millis,
            ),
            terminal_applied_detached_latency_millis: load_buckets(
                &self.protected_roster_terminal_applied_detached_latency_millis,
            ),
            log_append_sqlite_commit_latency_millis: load_buckets(
                &self.protected_roster_log_append_sqlite_commit_latency_millis,
            ),
            state_machine_sqlite_commit_latency_millis: load_buckets(
                &self.protected_roster_state_machine_sqlite_commit_latency_millis,
            ),
            response_path_maintenance_turns: self
                .protected_roster_response_path_maintenance_turns
                .load(Ordering::Relaxed),
            response_path_maintenance_latency_millis: load_buckets(
                &self.protected_roster_response_path_maintenance_latency_millis,
            ),
            background_checkpoint_latency_millis: load_buckets(
                &self.background_checkpoint_latency_millis,
            ),
            occupancy_valid: u64::from(occupancy.1 .0),
            occupancy_generation: occupancy.0,
            live_reservations: occupancy.1 .1,
            retained_reservations: occupancy.1 .2,
            tombstone_reservations: occupancy.1 .3,
            history_floors: occupancy.1 .4,
            retirement_cursors: occupancy.1 .5,
            materialized_charge_bytes: occupancy.1 .6,
            reserved_future_charge_bytes: occupancy.1 .7,
        }
    }
}

struct ConsensusSessionStoreInner {
    raft: SessionRaft,
    storage_shutdown: storage::ConsensusStorageShutdownObserver,
    terminal_recovery_handoff_consumer: storage::LiveTerminalRecoveryHandoffConsumer,
    #[cfg(test)]
    terminal_recovery_gate_checks: AtomicU64,
    raft_handler: SessionRaftRpcHandler,
    backend: SqliteSessionBackend,
    proactive_checkpoint_lane: Option<Arc<crate::sqlite::consensus::ProactiveCheckpointLane>>,
    consensus_log_prune_lane: Option<Arc<crate::sqlite::consensus::ConsensusLogPruneLane>>,
    storage_identity: SessionConsensusIdentity,
    local_node_id: SessionConsensusNodeId,
    peer_directory: SessionRaftPeerDirectory,
    topology_coordinator: Arc<SessionTopologyCoordinatorState>,
    bootstrap_members: BTreeSet<SessionConsensusNodeId>,
    bootstrap_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    topology: QuorumTopologySummary,
    roster_attestation_trust_root: Option<RosterAttestationTrustRootV1>,
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
    shutdown: ConsensusShutdownCoordinator,
    #[cfg(test)]
    accepted_receiver_test_outcomes: Mutex<VecDeque<AcceptedClientWriteReceiverTestOutcome>>,
}

/// The one clone-wide shutdown drain.  A caller timing out must not cancel the
/// actual engine drain: OpenRaft has already signalled its core before it
/// joins that core's tasks, so dropping that future can strand its tick
/// cleanup.  All clones therefore observe this single background operation.
struct ConsensusShutdownCoordinator {
    completion: Mutex<Option<tokio::sync::watch::Receiver<ConsensusShutdownCompletion>>>,
}

#[derive(Clone)]
enum ConsensusShutdownCompletion {
    Running,
    Finished(Result<(), StoreError>),
}

impl ConsensusShutdownCoordinator {
    const fn new() -> Self {
        Self {
            completion: Mutex::new(None),
        }
    }

    fn start_or_subscribe(
        &self,
        inner: Arc<ConsensusSessionStoreInner>,
    ) -> tokio::sync::watch::Receiver<ConsensusShutdownCompletion> {
        let mut completion = self
            .completion
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(receiver) = completion.as_ref() {
            return receiver.clone();
        }
        let (sender, receiver) = tokio::sync::watch::channel(ConsensusShutdownCompletion::Running);
        *completion = Some(receiver.clone());
        tokio::spawn(async move {
            let result = shutdown_consensus_session_store(inner).await;
            sender.send_replace(ConsensusShutdownCompletion::Finished(result));
        });
        receiver
    }
}

async fn shutdown_consensus_session_store(
    inner: Arc<ConsensusSessionStoreInner>,
) -> Result<(), StoreError> {
    match (
        inner.consensus_log_prune_lane.as_ref(),
        inner.proactive_checkpoint_lane.as_ref(),
    ) {
        (Some(prune), Some(checkpoint)) => {
            tokio::join!(prune.shutdown(), checkpoint.shutdown());
        }
        (Some(prune), None) => prune.shutdown().await,
        (None, Some(checkpoint)) => checkpoint.shutdown().await,
        (None, None) => {}
    }
    #[cfg(all(test, target_os = "linux", feature = "test-vfs"))]
    if let Some(gate) = raft_shutdown_gate_for_store(&inner) {
        gate.wait_before_raft_shutdown().await;
    }
    inner
        .raft
        .shutdown()
        .await
        .map_err(|_| consensus_unavailable())?;
    inner.storage_shutdown.wait().await;
    Ok(())
}

async fn await_consensus_session_store_shutdown(
    mut completion: tokio::sync::watch::Receiver<ConsensusShutdownCompletion>,
) -> Result<(), StoreError> {
    loop {
        let state = completion.borrow_and_update().clone();
        match state {
            ConsensusShutdownCompletion::Finished(result) => return result,
            ConsensusShutdownCompletion::Running => {
                if completion.changed().await.is_err() {
                    return Err(consensus_unavailable());
                }
            }
        }
    }
}

/// Store-scoped test gate immediately before the real Raft shutdown call.
///
/// The guard deliberately does not alter a lane or the Raft engine.  It only
/// makes the public shutdown phase boundary observable: maintenance lanes
/// must have stopped and joined before the core shutdown can be held here.
#[cfg(all(test, target_os = "linux", feature = "test-vfs"))]
struct RaftShutdownGate {
    state: Mutex<RaftShutdownGateState>,
    entered: Condvar,
    release: tokio::sync::watch::Sender<bool>,
}

#[cfg(all(test, target_os = "linux", feature = "test-vfs"))]
#[derive(Default)]
struct RaftShutdownGateState {
    armed: bool,
    entered: bool,
}

#[cfg(all(test, target_os = "linux", feature = "test-vfs"))]
impl RaftShutdownGate {
    fn new() -> Arc<Self> {
        let (release, _) = tokio::sync::watch::channel(false);
        Arc::new(Self {
            state: Mutex::new(RaftShutdownGateState::default()),
            entered: Condvar::new(),
            release,
        })
    }

    fn arm(self: &Arc<Self>, key: usize) -> RaftShutdownHoldForTest {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(
            !state.armed,
            "only one Raft shutdown test hold may be armed"
        );
        state.armed = true;
        state.entered = false;
        self.release.send_replace(false);
        RaftShutdownHoldForTest {
            gate: Arc::clone(self),
            key,
        }
    }

    async fn wait_before_raft_shutdown(&self) {
        let mut release = self.release.subscribe();
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.armed {
                return;
            }
            state.entered = true;
            self.entered.notify_all();
        }
        while !*release.borrow() {
            if release.changed().await.is_err() {
                return;
            }
        }
    }

    fn wait_until_entered(&self, timeout: Duration) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (state, _) = self
            .entered
            .wait_timeout_while(state, timeout, |state| !state.entered)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.entered
    }

    fn release(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.armed {
            return;
        }
        state.armed = false;
        self.release.send_replace(true);
    }
}

#[cfg(all(test, target_os = "linux", feature = "test-vfs"))]
fn raft_shutdown_gates() -> &'static Mutex<BTreeMap<usize, Weak<RaftShutdownGate>>> {
    static GATES: OnceLock<Mutex<BTreeMap<usize, Weak<RaftShutdownGate>>>> = OnceLock::new();
    GATES.get_or_init(|| Mutex::new(BTreeMap::new()))
}

#[cfg(all(test, target_os = "linux", feature = "test-vfs"))]
fn raft_shutdown_gate_key(inner: &Arc<ConsensusSessionStoreInner>) -> usize {
    Arc::as_ptr(inner) as usize
}

#[cfg(all(test, target_os = "linux", feature = "test-vfs"))]
fn install_raft_shutdown_gate_for_test(
    inner: &Arc<ConsensusSessionStoreInner>,
) -> RaftShutdownHoldForTest {
    let key = raft_shutdown_gate_key(inner);
    let gate = RaftShutdownGate::new();
    let mut gates = raft_shutdown_gates()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert!(
        gates.get(&key).and_then(Weak::upgrade).is_none(),
        "only one Raft shutdown test hold may be armed"
    );
    gates.insert(key, Arc::downgrade(&gate));
    drop(gates);
    gate.arm(key)
}

#[cfg(all(test, target_os = "linux", feature = "test-vfs"))]
fn raft_shutdown_gate_for_store(
    inner: &Arc<ConsensusSessionStoreInner>,
) -> Option<Arc<RaftShutdownGate>> {
    let key = raft_shutdown_gate_key(inner);
    let mut gates = raft_shutdown_gates()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let gate = gates.get(&key).and_then(Weak::upgrade);
    if gate.is_none() {
        gates.remove(&key);
    }
    gate
}

/// RAII release for one store-scoped Raft shutdown hold.
#[cfg(all(test, target_os = "linux", feature = "test-vfs"))]
struct RaftShutdownHoldForTest {
    gate: Arc<RaftShutdownGate>,
    key: usize,
}

#[cfg(all(test, target_os = "linux", feature = "test-vfs"))]
impl Drop for RaftShutdownHoldForTest {
    fn drop(&mut self) {
        self.gate.release();
        let mut gates = raft_shutdown_gates()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if gates
            .get(&self.key)
            .is_some_and(|current| current.ptr_eq(&Arc::downgrade(&self.gate)))
        {
            gates.remove(&self.key);
        }
    }
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
/// dropped caller only drops its reply receiver. The worker prunes it before
/// proposal dispatch; after dispatch begins, the worker still supervises the
/// accepted cohort to a bounded terminal result.
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

        // No consensus proposal has begun at this boundary. Discard callers
        // whose reply authority is already gone, plus requests whose complete
        // deadline has elapsed while queued. Once submit_request_before starts,
        // its existing detached supervision remains responsible for any
        // accepted client_write_ff outcome.
        let now = tokio::time::Instant::now();
        cohort.retain(|request| !request.reply.is_closed() && now < request.deadline);
        if cohort.is_empty() {
            continue;
        }

        let deadline = cohort
            .iter()
            .map(|request| request.deadline)
            .max()
            .unwrap_or_else(tokio::time::Instant::now);
        let result = {
            let submission = async {
                match store.upgrade() {
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
                                StoreError::BackendOperationOutcomeUnavailable => {
                                    consensus_unavailable()
                                }
                                error => error,
                            })
                    }
                    None => Err(consensus_unavailable()),
                }
            };
            tokio::pin!(submission);
            let all_reply_authority_lost = async {
                for request in &mut cohort {
                    if request.reply.is_closed() || tokio::time::Instant::now() >= request.deadline
                    {
                        continue;
                    }
                    tokio::select! {
                        biased;
                        _ = request.reply.closed() => {}
                        _ = tokio::time::sleep_until(request.deadline) => {}
                    }
                }
            };
            tokio::pin!(all_reply_authority_lost);
            tokio::select! {
                biased;
                result = &mut submission => Some(result),
                () = &mut all_reply_authority_lost => None,
            }
        };
        let Some(result) = result else {
            // Dropping an unaccepted submission cancels its routing/proposal
            // work. If client_write_ff already accepted it, the lower-level
            // detached supervisor retains the proposal permit and completes
            // the outcome independently of this caller cohort.
            continue;
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

    /// Return fixed-cardinality, redaction-safe diagnostics for protected
    /// roster consensus, durable storage, and bounded background work.
    pub fn protected_roster_diagnostic_snapshot(
        &self,
    ) -> ProtectedRosterConsensusDiagnosticSnapshot {
        self.inner.diagnostics.protected_roster_snapshot()
    }

    #[cfg(test)]
    fn inject_accepted_client_write_receiver_outcome(
        &self,
        outcome: AcceptedClientWriteReceiverTestOutcome,
    ) {
        self.inner
            .accepted_receiver_test_outcomes
            .lock()
            .expect("accepted receiver test outcomes lock")
            .push_back(outcome);
    }

    /// Enable or disable ticker-driven elections for deterministic integration
    /// qualification. Explicit engine-triggered campaigns remain enabled.
    #[cfg(feature = "test-control")]
    #[doc(hidden)]
    pub fn set_automatic_election_for_test(&self, enabled: bool) {
        self.inner.raft.runtime_config().elect(enabled);
    }

    /// Ask Openraft to start one normal campaign for deterministic integration
    /// qualification. Openraft owns vote creation, persistence, and transport.
    #[cfg(feature = "test-control")]
    #[doc(hidden)]
    pub async fn trigger_election_for_test(&self) -> Result<(), StoreError> {
        self.inner
            .raft
            .trigger()
            .elect()
            .await
            .map_err(|_| consensus_unavailable())
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
        let roster_attestation_trust_root = topology.roster_attestation_trust_root().cloned();
        let (log_store, state_machine, storage_identity) =
            storage::open_fixed_with_member_bindings_and_roster_attestation_root(
                &backend,
                snapshot_dir,
                identity,
                members.clone(),
                bindings.clone(),
                peer_directory.clone(),
                placement_policy,
                roster_attestation_trust_root.clone(),
            )
            .await?;
        let proactive_checkpoint_lane = log_store.proactive_checkpoint_lane();
        let consensus_log_prune_lane = log_store.consensus_log_prune_lane();
        let terminal_recovery_handoff_consumer =
            log_store.live_terminal_recovery_handoff_consumer();
        let storage_shutdown = state_machine
            .shutdown_observer()
            .ok_or(ConsensusSessionStoreOpenError::StorageUnavailable)?;
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
                operation_timeout,
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
            storage_shutdown,
            terminal_recovery_handoff_consumer,
            #[cfg(test)]
            terminal_recovery_gate_checks: AtomicU64::new(0),
            raft_handler,
            backend,
            proactive_checkpoint_lane,
            consensus_log_prune_lane,
            storage_identity,
            local_node_id,
            peer_directory,
            topology_coordinator,
            bootstrap_members: members,
            bootstrap_bindings: bindings,
            topology: topology_summary,
            roster_attestation_trust_root,
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
            shutdown: ConsensusShutdownCoordinator::new(),
            #[cfg(test)]
            accepted_receiver_test_outcomes: Mutex::new(VecDeque::new()),
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
        let roster_attestation_trust_root = topology.roster_attestation_trust_root().cloned();
        let (log_store, state_machine, storage_identity) =
            storage::open_with_member_bindings_and_roster_attestation_root(
                &backend,
                snapshot_dir,
                identity,
                members.clone(),
                bindings.clone(),
                peer_directory.clone(),
                roster_attestation_trust_root.clone(),
            )
            .await?;
        let proactive_checkpoint_lane = log_store.proactive_checkpoint_lane();
        let consensus_log_prune_lane = log_store.consensus_log_prune_lane();
        let terminal_recovery_handoff_consumer =
            log_store.live_terminal_recovery_handoff_consumer();
        let storage_shutdown = state_machine
            .shutdown_observer()
            .ok_or(ConsensusSessionStoreOpenError::StorageUnavailable)?;
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
            storage_shutdown,
            terminal_recovery_handoff_consumer,
            #[cfg(test)]
            terminal_recovery_gate_checks: AtomicU64::new(0),
            raft_handler,
            backend,
            proactive_checkpoint_lane,
            consensus_log_prune_lane,
            storage_identity,
            local_node_id,
            peer_directory,
            topology_coordinator,
            bootstrap_members: members,
            bootstrap_bindings: bindings,
            topology: topology_summary,
            roster_attestation_trust_root,
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
            shutdown: ConsensusShutdownCoordinator::new(),
            #[cfg(test)]
            accepted_receiver_test_outcomes: Mutex::new(VecDeque::new()),
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

    /// Start this store's clone-wide consensus shutdown and wait for every
    /// engine-owned task to exit.
    ///
    /// Shutdown is clone-wide: every handle to this store observes the same
    /// stopped engine. Callers must remove the store's authenticated RPC
    /// handler from their transport before invoking this method so no new
    /// request can enter while the engine drains. The bounded maintenance
    /// lanes are stopped and joined first, so a Raft shutdown that cannot
    /// complete cannot retain their workers or checkpoint connections. This
    /// call is bounded by the configured complete-operation deadline. On its
    /// fixed `consensus_unavailable` timeout error, shutdown continues in the
    /// shared background drain; callers must not reopen the durable store
    /// until a later clone-wide `shutdown` call observes successful drain.
    pub async fn shutdown(&self) -> Result<(), StoreError> {
        let completion = self
            .inner
            .shutdown
            .start_or_subscribe(Arc::clone(&self.inner));
        tokio::time::timeout(
            self.inner.operation_timeout,
            await_consensus_session_store_shutdown(completion),
        )
        .await
        .unwrap_or_else(|_| Err(consensus_unavailable()))
    }

    /// Hold the test-only phase immediately before the real Raft shutdown.
    ///
    /// Releasing the returned guard resumes the core shutdown. Production
    /// construction omits the gate entirely.
    #[cfg(all(test, target_os = "linux", feature = "test-vfs"))]
    fn hold_raft_shutdown_before_core_for_test(&self) -> RaftShutdownHoldForTest {
        install_raft_shutdown_gate_for_test(&self.inner)
    }

    /// Reset the fixed proactive-checkpoint write cadence for an isolated VFS
    /// qualification test.
    #[cfg(feature = "test-vfs")]
    #[doc(hidden)]
    pub fn reset_proactive_checkpoint_cadence_for_test(&self) {
        if let Some(lane) = &self.inner.proactive_checkpoint_lane {
            lane.reset_durable_write_budget_for_test();
        }
    }

    /// Return the remaining durable-write budget for an isolated VFS test.
    #[cfg(feature = "test-vfs")]
    #[doc(hidden)]
    pub fn proactive_checkpoint_cadence_remaining_for_test(&self) -> Option<u64> {
        self.inner
            .proactive_checkpoint_lane
            .as_ref()
            .map(|lane| lane.durable_write_budget_for_test())
    }

    /// Return the store-scoped proactive checkpoint cadence for an isolated
    /// VFS test.
    #[cfg(feature = "test-vfs")]
    #[doc(hidden)]
    pub const fn proactive_checkpoint_cadence_batch_for_test() -> u64 {
        crate::sqlite::consensus::ProactiveCheckpointLane::durable_write_batch_for_test()
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

    /// Select the fixed-quorum consumer warm route only after this store has
    /// observed one definitive V2 result. The bit is a route hint rather than
    /// activation or authority: the leader still consumes the captured scope
    /// and its uncached atomic snapshot at the sole effect-admission boundary.
    fn fixed_raw_v2_consumer_warm_route(
        &self,
        required_consumer_scope: Option<&SessionConsensusIdentity>,
    ) -> bool {
        required_consumer_scope.is_some()
            && self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum
            && self.local_fenced_transition_v2_capability()
                == Some(FencedTransitionV2Capability::V2)
            && self
                .inner
                .diagnostics
                .fixed_raw_v2_warm_route
                .load(Ordering::Acquire)
    }

    fn fixed_raw_v2_consumer_warm_route_for_intent(
        &self,
        intent: &SessionMutationIntent,
        required_consumer_scope: Option<&SessionConsensusIdentity>,
    ) -> bool {
        is_raw_fenced_transition_v2_mutation(intent, false)
            && self.fixed_raw_v2_consumer_warm_route(required_consumer_scope)
    }

    /// Capture the current fixed-quorum scope for a public raw V2 batch warm
    /// route.
    ///
    /// The bit is deliberately only a monotonic, store-local route hint. A
    /// reopened store always starts cold, and a stale set bit never permits a
    /// generic fallback: the leader receives this scope and must still pass
    /// its operation gate, same-term raw-V2 barrier, and one atomic durable
    /// authority/recovery/profile/activation snapshot before it can propose.
    fn public_fixed_raw_v2_warm_scope(
        &self,
    ) -> Result<Option<SessionConsensusIdentity>, StoreError> {
        if !self
            .inner
            .diagnostics
            .fixed_raw_v2_warm_route
            .load(Ordering::Acquire)
        {
            return Ok(None);
        }
        if self.inner.topology.mode() != QuorumTopologyMode::FixedDurableQuorum {
            return Err(consensus_unavailable());
        }
        if self.local_fenced_transition_v2_capability() != Some(FencedTransitionV2Capability::V2) {
            return Err(unsupported_fenced_transition_v2());
        }
        self.require_exact_membership_admission()?;
        self.current_scope().map(|(scope, _)| Some(scope))
    }

    /// Record only proof obtained by this process for its immutable storage
    /// identity/profile. This is intentionally not a certificate and never
    /// carries subscriber, consumer, or topology authority state.
    fn seed_fixed_raw_v2_warm_route(&self) {
        if self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum
            && self.local_fenced_transition_v2_capability()
                == Some(FencedTransitionV2Capability::V2)
        {
            self.inner
                .diagnostics
                .fixed_raw_v2_warm_route
                .store(true, Ordering::Release);
        }
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
        self.require_fenced_transition_capability_after_authority(false, deadline)
            .await
    }

    /// Continue a fenced-transition capability proof from the same local
    /// quorum admission that fenced the impending proposal.  Unlike the
    /// standalone capability and status paths, this must not begin a second
    /// read-index round.
    async fn require_fenced_transition_capability_after_read_admit(
        &self,
        read_admit: &LinearizableReadAdmit<SessionConsensusNodeId>,
        require_activation_command: bool,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionCapabilityAdmission, StoreError> {
        self.require_exact_membership_admission()?;
        self.inner
            .read_barrier
            .revalidate(read_admit, deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        self.require_fenced_transition_capability_after_authority(
            require_activation_command,
            deadline,
        )
        .await
    }

    /// Verify the local V1 capability and, before activation, every exact
    /// remote voter after a caller has established its own linearizable and
    /// application-traffic authority.
    async fn require_fenced_transition_capability_after_authority(
        &self,
        require_activation_command: bool,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionCapabilityAdmission, StoreError> {
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
                if require_activation_command {
                    match self
                        .call_peer::<_, FencedTransitionActivationCapabilityReply>(
                            member,
                            SessionConsensusRpcFamily::ReadBarrier,
                            &FencedTransitionActivationCapabilityProbe {
                                activation_probe_schema_version:
                                    FENCED_TRANSITION_ACTIVATION_PROBE_SCHEMA_V1,
                                activation_command_schema_version: FENCED_TRANSITION_SCHEMA_V1,
                            },
                            deadline,
                        )
                        .await
                    {
                        Ok(FencedTransitionActivationCapabilityReply::V1) => {
                            FencedTransitionCapabilityProbeOutcome::V1
                        }
                        Ok(FencedTransitionActivationCapabilityReply::Unsupported) => {
                            FencedTransitionCapabilityProbeOutcome::Unsupported
                        }
                        Err(_) => FencedTransitionCapabilityProbeOutcome::Unavailable,
                    }
                } else {
                    match self
                        .call_peer::<_, FencedTransitionCapabilityReply>(
                            member,
                            SessionConsensusRpcFamily::ReadBarrier,
                            &FencedTransitionCapabilityProbe {
                                schema_version: FENCED_TRANSITION_SCHEMA_V1,
                            },
                            deadline,
                        )
                        .await
                    {
                        Ok(FencedTransitionCapabilityReply::V1) => {
                            FencedTransitionCapabilityProbeOutcome::V1
                        }
                        Ok(FencedTransitionCapabilityReply::Unsupported) => {
                            FencedTransitionCapabilityProbeOutcome::Unsupported
                        }
                        Err(_) => FencedTransitionCapabilityProbeOutcome::Unavailable,
                    }
                }
            });
        let outcomes = futures_util::future::join_all(probes).await;
        if outcomes.contains(&FencedTransitionCapabilityProbeOutcome::Unavailable) {
            return Err(consensus_unavailable());
        }
        if outcomes.contains(&FencedTransitionCapabilityProbeOutcome::Unsupported) {
            return Err(unsupported_fenced_transition());
        }
        if self.current_scope()? != expected_scope || !self.exact_membership_is_admitted() {
            return Err(consensus_unavailable());
        }
        Ok(FencedTransitionCapabilityAdmission::FreshUnanimous)
    }

    /// Check only the durable exact V1 activation fact. The following Raft
    /// write is the linearizing quorum operation, so activation, status, and
    /// dynamic capability paths must continue to use their read barriers.
    async fn activated_fenced_transition_scope_is_current(&self) -> Result<bool, StoreError> {
        self.require_exact_membership_admission()?;
        let expected_scope = self.current_scope()?;
        if self.local_fenced_transition_capability() != AtomicFencedTransitionCapability::V1
            || !expected_scope.1.contains(&self.inner.local_node_id)
        {
            return Ok(false);
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
        Ok(activated
            && self.current_scope()? == expected_scope
            && self.exact_membership_is_admitted())
    }

    /// Require a prior exact-current-voter immutable protected-roster profile
    /// certificate. Admission paths never turn a missing certificate into a
    /// fresh proof: startup/deployment activation is the only place allowed
    /// to append that reusable, non-roster transaction.
    async fn require_protected_roster_profile_activation_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        self.require_exact_membership_admission()?;
        self.linearizable_barrier_before(deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        if self
            .activated_protected_roster_profile_scope_is_current()
            .await?
        {
            Ok(())
        } else {
            Err(StoreError::CapabilityNotSupported(
                "protected_roster_profile_not_activated".into(),
            ))
        }
    }

    /// Continue a profile activation proof from the same local quorum
    /// admission that fences its proposal. Every remote voter must answer the
    /// exact frozen profile payload; decode failure, absence, and any future
    /// profile are all fail-closed.
    async fn require_protected_roster_profile_activation_after_read_admit(
        &self,
        read_admit: &LinearizableReadAdmit<SessionConsensusNodeId>,
        deadline: tokio::time::Instant,
    ) -> Result<FencedTransitionCapabilityAdmission, StoreError> {
        self.require_exact_membership_admission()?;
        self.inner
            .read_barrier
            .revalidate(read_admit, deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        let expected_scope = self.current_scope()?;
        if self.local_fenced_transition_capability() != AtomicFencedTransitionCapability::V1
            || !expected_scope.1.contains(&self.inner.local_node_id)
        {
            return Err(unsupported_fenced_transition());
        }
        if self
            .inner
            .backend
            .consensus_protected_roster_profile_activation_matches_scope(
                self.inner.storage_identity,
                expected_scope.0,
                expected_scope.1.clone(),
            )
            .await?
        {
            if self.current_scope()? != expected_scope || !self.exact_membership_is_admitted() {
                return Err(consensus_unavailable());
            }
            return Ok(FencedTransitionCapabilityAdmission::Activated);
        }
        let profile_digest = crate::fenced_mutation_roster::profile_digest();
        let probes = expected_scope
            .1
            .iter()
            .copied()
            .filter(|member| *member != self.inner.local_node_id)
            .map(|member| async move {
                let supported = match self
                    .call_peer::<_, ProtectedRosterProfileCapabilityReply>(
                        member,
                        SessionConsensusRpcFamily::ReadBarrier,
                        &ProtectedRosterProfileCapabilityProbe {
                            domain: PROTECTED_ROSTER_PROFILE_PROBE_DOMAIN_V1,
                            schema_version: PROTECTED_ROSTER_PROFILE_PROBE_SCHEMA_V1,
                            profile_digest,
                        },
                        deadline,
                    )
                    .await
                {
                    Ok(ProtectedRosterProfileCapabilityReply {
                        domain,
                        schema_version,
                        outcome:
                            ProtectedRosterProfileCapabilityOutcome::Supported {
                                profile_digest: peer_profile,
                            },
                    }) if domain == PROTECTED_ROSTER_PROFILE_REPLY_DOMAIN_V1
                        && schema_version == PROTECTED_ROSTER_PROFILE_PROBE_SCHEMA_V1
                        && peer_profile == profile_digest =>
                    {
                        true
                    }
                    Ok(_) => false,
                    Err(_) => return Err(consensus_unavailable()),
                };
                Ok(supported)
            });
        for result in futures_util::future::join_all(probes).await {
            if !result? {
                return Err(unsupported_fenced_transition());
            }
        }
        if self.current_scope()? != expected_scope || !self.exact_membership_is_admitted() {
            return Err(consensus_unavailable());
        }
        Ok(FencedTransitionCapabilityAdmission::FreshUnanimous)
    }

    /// Check only the durable exact-profile fact; proposal apply repeats the
    /// same proof against the committed membership scope.
    async fn activated_protected_roster_profile_scope_is_current(
        &self,
    ) -> Result<bool, StoreError> {
        self.require_exact_membership_admission()?;
        let expected_scope = self.current_scope()?;
        if self.local_fenced_transition_capability() != AtomicFencedTransitionCapability::V1
            || !expected_scope.1.contains(&self.inner.local_node_id)
        {
            return Ok(false);
        }
        let activated = self
            .inner
            .backend
            .consensus_protected_roster_profile_activation_matches_scope(
                self.inner.storage_identity,
                expected_scope.0,
                expected_scope.1.clone(),
            )
            .await?;
        Ok(activated
            && self.current_scope()? == expected_scope
            && self.exact_membership_is_admitted())
    }

    /// Revalidate every local fact bound to one V1 quorum admission. The
    /// revalidation is intentionally the final action before `client_write_ff`.
    async fn revalidate_fenced_transition_proposal_admission_before(
        &self,
        admission: &FencedTransitionProposalAdmission,
        required_consumer_scope: &ForwardConsumerScope,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        self.require_exact_membership_admission()?;
        if admission.required_consumer_scope != *required_consumer_scope {
            return Err(consensus_unavailable());
        }
        let (current_scope, current_voters) = self.current_scope()?;
        if current_scope != admission.scope_identity
            || fenced_transition_voter_set_digest(current_scope, &current_voters)
                != admission.voter_set_digest
            || required_consumer_scope
                .consumer_scope()
                .is_some_and(|scope| *scope != current_scope)
        {
            return Err(consensus_unavailable());
        }
        self.require_application_traffic_authority_before(deadline)
            .await?;
        match &admission.read_admit {
            Some(read_admit) => self
                .inner
                .read_barrier
                .revalidate(read_admit, deadline)
                .await
                .map_err(|_| consensus_unavailable()),
            // The exact activation certificate and the checks above bind this
            // no-read-index path; the immediate write quorum linearizes it.
            None => Ok(()),
        }
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
                match self
                    .call_peer::<_, FencedTransitionV2CapabilityReply>(
                        member,
                        SessionConsensusRpcFamily::ReadBarrier,
                        &FencedTransitionV2CapabilityProbe {
                            schema_version: FENCED_TRANSITION_SCHEMA_V2,
                            profile_digest,
                        },
                        deadline,
                    )
                    .await
                {
                    Ok(FencedTransitionV2CapabilityReply::V2 {
                        profile_digest: received,
                    }) if received == profile_digest => {
                        FencedTransitionV2CapabilityProbeOutcome::Exact
                    }
                    Ok(FencedTransitionV2CapabilityReply::V2 { .. })
                    | Ok(FencedTransitionV2CapabilityReply::Unsupported) => {
                        FencedTransitionV2CapabilityProbeOutcome::Unsupported
                    }
                    Err(ConsensusPeerCallFailure::AuthenticatedRejection(
                        SessionConsensusPeerError::Protocol,
                    )) => FencedTransitionV2CapabilityProbeOutcome::Unsupported,
                    Err(_) => FencedTransitionV2CapabilityProbeOutcome::Unavailable,
                }
            });
        let outcomes = futures_util::future::join_all(probes).await;
        if outcomes.contains(&FencedTransitionV2CapabilityProbeOutcome::Unavailable) {
            return Err(consensus_unavailable());
        }
        if outcomes.contains(&FencedTransitionV2CapabilityProbeOutcome::Unsupported) {
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

    /// Durably activate V1 for this concrete state voter before it accepts
    /// external traffic. The operation follows the authenticated internal
    /// forwarding path and returns only after this replica has applied the
    /// current-scope certificate.
    pub async fn activate_fenced_transition_capability(&self) -> Result<(), StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.activate_fenced_transition_capability_before(deadline)
            .await
    }

    /// Durably establish the immutable protected-roster profile for this
    /// exact voter scope. This is reusable startup/deployment capability
    /// negotiation, never a per-roster member write.
    pub async fn activate_protected_roster_profile(&self) -> Result<(), StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.activate_protected_roster_profile_before(deadline)
            .await
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
        // A singleton deliberately remains cold even after it seeds the
        // store-local batch route hint. This preserves its existing exact
        // activation admission shape and prevents a stale hint from ever
        // converting an unactivated singleton into a fresh proposal.
        let outcome = self
            .fenced_transition_v2_before(request, None, deadline)
            .await?;
        // A cold successful singleton either observed the exact durable
        // activation admission or committed the one permitted activation
        // singleton. Only later public batches may consume this route hint.
        self.seed_fixed_raw_v2_warm_route();
        Ok(outcome)
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
        if committed {
            self.seed_fixed_raw_v2_warm_route();
        }
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
            if required_consumer_scope.is_none()
                && self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum
            {
                self.inner
                    .diagnostics
                    .public_raw_v2_cold_admissions
                    .fetch_add(1, Ordering::Relaxed);
            }
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
                if required_consumer_scope.is_none()
                    && self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum
                {
                    self.inner
                        .diagnostics
                        .public_raw_v2_history_reads
                        .fetch_add(1, Ordering::Relaxed);
                }
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
            if required_consumer_scope.is_none()
                && self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum
            {
                self.inner
                    .diagnostics
                    .public_raw_v2_cold_admissions
                    .fetch_add(1, Ordering::Relaxed);
            }
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
                if required_consumer_scope.is_none()
                    && self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum
                {
                    self.inner
                        .diagnostics
                        .public_raw_v2_history_reads
                        .fetch_add(1, Ordering::Relaxed);
                }
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
        let every_request_is_self_authenticated =
            requests.iter().all(|request| request.validate().is_ok());
        let route_scope = self.public_fixed_raw_v2_warm_scope()?;
        let outcomes = self
            .fenced_transition_v2_batch_before(requests, route_scope, deadline)
            .await?;
        // A fresh public batch keeps the existing singleton activation shape;
        // only its definitive successful return for an entirely
        // self-authenticated request set can warm later public calls. A
        // locally resolved body conflict is not activation evidence.
        if every_request_is_self_authenticated {
            self.seed_fixed_raw_v2_warm_route();
        }
        Ok(outcomes)
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
        let every_request_is_self_authenticated =
            requests.iter().all(|request| request.validate().is_ok());
        let result = self
            .fenced_transition_v2_batch_execution_before(
                requests,
                Some(scope.consensus_identity()),
                deadline,
                true,
            )
            .await;
        if result.is_ok() && every_request_is_self_authenticated {
            self.seed_fixed_raw_v2_warm_route();
        }
        result
    }

    async fn fenced_transition_v2_batch_execution_before(
        &self,
        mut requests: Vec<FencedTransitionV2Request>,
        required_consumer_scope: Option<SessionConsensusIdentity>,
        deadline: tokio::time::Instant,
        preserve_rejected_response: bool,
    ) -> Result<(Vec<Result<FencedTransitionOutcome, StoreError>>, bool), StoreError> {
        validate_fenced_transition_v2_batch(&requests)?;
        let contains_body_conflict = requests
            .iter()
            .any(fenced_transition_v2_request_is_body_conflict);
        if requests
            .iter()
            .all(fenced_transition_v2_request_is_body_conflict)
        {
            return Ok((
                fenced_transition_v2_batch_body_conflict_outcomes(&requests),
                false,
            ));
        }

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

        if required_consumer_scope.is_none()
            && self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum
        {
            self.inner
                .diagnostics
                .public_raw_v2_cold_admissions
                .fetch_add(1, Ordering::Relaxed);
        }
        let admission = self
            .require_fenced_transition_v2_capability_before(deadline)
            .await?;

        // Batch coalescing admits only the active epoch or the bounded
        // retained interval above the durable floor. SQLite remains the
        // authority that distinguishes an exact retained receipt from an
        // unbound identity in that closed epoch.
        let (authority_identity, _) = self.current_scope()?;
        if required_consumer_scope.is_none()
            && self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum
        {
            self.inner
                .diagnostics
                .public_raw_v2_history_reads
                .fetch_add(1, Ordering::Relaxed);
        }
        let history = self
            .inner
            .backend
            .consensus_fenced_transition_v2_history_state(
                self.inner.storage_identity,
                authority_identity,
            )
            .await?;
        if let Err(error) = require_fenced_transition_v2_batch_history_epoch(
            &history,
            requests[0].request_id().epoch(),
        ) {
            return if contains_body_conflict {
                Ok((
                    fenced_transition_v2_batch_epoch_outcomes(&requests, error),
                    false,
                ))
            } else {
                Err(error)
            };
        }
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
            let Some(activation_slot) = requests
                .iter()
                .position(|request| !fenced_transition_v2_request_is_body_conflict(request))
            else {
                return Ok((
                    fenced_transition_v2_batch_body_conflict_outcomes(&requests),
                    false,
                ));
            };
            let first = requests.remove(activation_slot);
            let has_unresolved_suffix = requests
                .iter()
                .any(|request| !fenced_transition_v2_request_is_body_conflict(request));
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
                Err(error) if activation_committed && !has_unresolved_suffix => {
                    let mut outcomes = fenced_transition_v2_batch_body_conflict_outcomes(&requests);
                    outcomes.insert(activation_slot, Err(error));
                    return Ok((outcomes, true));
                }
                Err(_) if activation_committed => {
                    return Err(StoreError::FencedTransitionOutcomeUnknown);
                }
                Err(error) => return Err(error),
                Ok(_) => return Err(StoreError::FencedTransitionOutcomeUnknown),
            };
            activation_outcome = Some((activation_slot, Ok(outcome)));
            if !has_unresolved_suffix {
                let mut outcomes = fenced_transition_v2_batch_body_conflict_outcomes(&requests);
                if let Some((slot, outcome)) = activation_outcome {
                    outcomes.insert(slot, outcome);
                }
                return Ok((outcomes, activation_committed));
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
        if let Some((slot, outcome)) = activation_outcome {
            outcomes.insert(slot, outcome);
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
        let every_request_is_self_authenticated =
            requests.iter().all(|request| request.validate().is_ok());
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

        if !every_request_is_self_authenticated
            && requests
                .iter()
                .all(fenced_transition_v2_request_is_body_conflict)
        {
            return FencedTransitionV2Effect::Resolved(Ok(
                fenced_transition_v2_batch_body_conflict_outcomes(&requests),
            ));
        }

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

        if required_consumer_scope.is_none()
            && self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum
        {
            self.inner
                .diagnostics
                .public_raw_v2_cold_admissions
                .fetch_add(1, Ordering::Relaxed);
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
        if required_consumer_scope.is_none()
            && self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum
        {
            self.inner
                .diagnostics
                .public_raw_v2_history_reads
                .fetch_add(1, Ordering::Relaxed);
        }
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
        if let Err(error) = require_fenced_transition_v2_batch_history_epoch(
            &history,
            requests[0].request_id().epoch(),
        ) {
            return if every_request_is_self_authenticated {
                FencedTransitionV2Effect::NotTransmitted(error)
            } else {
                FencedTransitionV2Effect::Resolved(Ok(fenced_transition_v2_batch_epoch_outcomes(
                    &requests, error,
                )))
            };
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
            let Some(activation_slot) = requests
                .iter()
                .position(|request| !fenced_transition_v2_request_is_body_conflict(request))
            else {
                return FencedTransitionV2Effect::Resolved(Ok(
                    fenced_transition_v2_batch_body_conflict_outcomes(&requests),
                ));
            };
            let first = requests.remove(activation_slot);
            let has_unresolved_suffix = requests
                .iter()
                .any(|request| !fenced_transition_v2_request_is_body_conflict(request));
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
                        has_unresolved_suffix,
                        response,
                    ) {
                        Some(Ok(outcome)) => {
                            activation_outcome = Some((activation_slot, Ok(outcome)));
                        }
                        Some(Err(error)) => {
                            let mut outcomes =
                                fenced_transition_v2_batch_body_conflict_outcomes(&requests);
                            outcomes.insert(activation_slot, Err(error));
                            return FencedTransitionV2Effect::Resolved(Ok(outcomes));
                        }
                        None => return unknown(),
                    }
                }
                ConsensusSubmissionEffect::Rejected(response) => match response.result {
                    Err(error) => return FencedTransitionV2Effect::NotTransmitted(error),
                    Ok(_) => return unknown(),
                },
            }
            if !has_unresolved_suffix {
                let mut outcomes = fenced_transition_v2_batch_body_conflict_outcomes(&requests);
                if let Some((slot, outcome)) = activation_outcome {
                    outcomes.insert(slot, outcome);
                }
                return FencedTransitionV2Effect::Resolved(Ok(outcomes));
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
            | ForwardMutationReply::RecordExpiryPreflight(_)
            | ForwardMutationReply::FencedTransitionActivation(_) => Err(consensus_unavailable()),
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
    /// consumer listener. The sorted node-to-identity roster is derived from
    /// the store-owned, currently admitted topology bindings while its
    /// operation gate is held.
    pub async fn consumer_authorization_manifest(
        &self,
        grants: impl IntoIterator<Item = SessionConsumerAuthorizationGrant>,
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
        let (current_scope, current_members) = self.current_scope()?;
        if current_scope != admission.required_scope {
            return Err(consensus_unavailable());
        }
        let roster = SessionConsumerRoster::try_new(
            scope,
            &current_members,
            descriptors
                .into_iter()
                .map(|(node_id, descriptor)| (node_id.get(), descriptor)),
        )
        .map_err(|_| consensus_unavailable())?;
        SessionConsumerAuthorizationManifest::try_new(self.inner.local_node_id, roster, grants)
            .map_err(|_| consensus_unavailable())
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
        let (_, _, _, completed_snapshot_count) =
            self.inner.backend.snapshot_observation().snapshot();
        SessionConsensusStatus {
            node_id: self.inner.local_node_id,
            term,
            leader_id,
            last_log_index,
            applied_index,
            admitted,
            completed_snapshot_count,
        }
    }

    pub(crate) fn recovery_identity(&self) -> SessionConsensusIdentity {
        self.inner.storage_identity
    }

    pub(crate) fn recovery_members(&self) -> &BTreeSet<SessionConsensusNodeId> {
        &self.inner.bootstrap_members
    }

    /// Acquire the live core's snapshot transaction for the complete
    /// operator-recovery finalization transaction.
    ///
    /// The recovery manager obtains this before it pins the selected S1
    /// artifact and retains it through Terminal(PendingHandoff) publication
    /// and descriptor-bound consumption.  This prevents a live build/install
    /// from publishing S2 between those irreversible boundaries.
    pub(crate) async fn acquire_live_operator_recovery_terminal_handoff_gate(
        &self,
    ) -> Result<storage::LiveTerminalRecoveryHandoffGate, SessionConsensusStorageError> {
        self.inner
            .terminal_recovery_handoff_consumer
            .acquire_gate()
            .await
    }

    /// Consume a terminal recovery handoff while the recovery manager still
    /// owns the gate returned by
    /// [`Self::acquire_live_operator_recovery_terminal_handoff_gate`].
    pub(crate) async fn consume_live_operator_recovery_terminal_handoff_with_gate(
        &self,
        gate: &storage::LiveTerminalRecoveryHandoffGate,
    ) -> Result<(), SessionConsensusStorageError> {
        self.inner
            .terminal_recovery_handoff_consumer
            .consume_with_gate(gate)
            .await
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

    async fn operator_recovery_gate_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> OperatorRecoveryGate {
        #[cfg(test)]
        self.inner
            .terminal_recovery_gate_checks
            .fetch_add(1, Ordering::Relaxed);
        // Do not preflight through the backend's pathname-only terminal
        // classifier.  If recovery published S1 and a parent operator then
        // replaces configured D1 with D2, that preflight could resolve D2
        // before this retained consumer admits S1 through D1.  The live core
        // classifier below carries the lease-opened descriptor instead.
        match tokio::time::timeout_at(
            deadline,
            self.inner.terminal_recovery_handoff_consumer.reconcile(),
        )
        .await
        {
            Ok(Ok(storage::LiveTerminalRecoveryHandoffState::Active)) => {
                OperatorRecoveryGate::Active
            }
            Ok(Ok(
                storage::LiveTerminalRecoveryHandoffState::Clear
                | storage::LiveTerminalRecoveryHandoffState::Consumed,
            )) => OperatorRecoveryGate::Clear,
            Ok(Err(SessionConsensusStorageError::BackendUnavailable)) | Err(_) => {
                OperatorRecoveryGate::Unavailable
            }
            Ok(Err(_)) => OperatorRecoveryGate::Corrupt,
        }
    }

    /// Revalidation after a response has already proved that the mutation
    /// committed. Dynamic ingress performed its descriptor-bound recovery gate
    /// before the first possible transmission, and the leader repeated that
    /// gate immediately before proposal. Repeating the origin gate here could
    /// exhaust the original deadline and misclassify a known commit as an
    /// unknown outcome. Fixed durable authority remains a result boundary and
    /// therefore retains its full revalidation.
    async fn require_application_traffic_committed_reply_authority_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        // A committed Dynamic response is still returned only by an exact
        // current member. This is deliberately the cheap scope check: the
        // recovery workflow must drain the fleet before publishing Active,
        // and a second terminal reconciliation cannot revoke a known commit.
        self.require_application_traffic_intermediate_authority_before(deadline)
            .await
    }

    /// Preserve Fixed's persistent authority checks at every historical
    /// checkpoint while avoiding repeated Dynamic terminal-sidecar probes
    /// inside one leader-owned proposal turn.
    ///
    /// Dynamic ingress performs a full recovery gate before transmission, and
    /// `propose_on_local_leader` performs the full leader gate immediately
    /// before enqueue. The topology operation guard spans the intermediate
    /// checkpoints, so exact live membership is sufficient there. Pending
    /// recovery may still exchange Raft/read-index traffic, while the final
    /// gate prevents it from admitting an ordinary mutation.
    async fn require_application_traffic_intermediate_authority_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        if self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum {
            return self
                .require_application_traffic_authority_before(deadline)
                .await;
        }
        self.require_durable_fixed_quorum_admission_before(deadline)
            .await
    }

    /// Revalidate every durable application-traffic authority before an
    /// ordinary operation can first transmit or a leader proposal crosses its
    /// acceptance boundary. A validated committed reply uses the narrower
    /// result policy above so known effect is never converted into ambiguity.
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
        match self.operator_recovery_gate_before(deadline).await {
            OperatorRecoveryGate::Clear => Ok(()),
            OperatorRecoveryGate::Active
            | OperatorRecoveryGate::Corrupt
            | OperatorRecoveryGate::Unavailable => Err(consensus_unavailable()),
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
        if let Some(report) = self.local_authoritative_recovery_report() {
            return report;
        }
        let scope_record =
            tokio::time::timeout_at(deadline, self.durable_fixed_quorum_scope_record_is_exact())
                .await;
        if let Some(report) = self.local_authoritative_recovery_report() {
            return report;
        }
        match scope_record {
            Ok(Ok(true)) => {}
            Ok(Ok(false)) => return self.topology_invalid_readiness_report(),
            Ok(Err(_)) | Err(_) => return self.unavailable_durable_readiness_report(),
        }
        let report = self.probe_durable_readiness_before(deadline).await;
        if let Some(report) = self.local_authoritative_recovery_report() {
            return report;
        }
        if report.state() != DurableReadinessState::Ready {
            return report;
        }
        let exact_scope =
            tokio::time::timeout_at(deadline, self.durable_fixed_quorum_scope_is_exact()).await;
        if let Some(report) = self.local_authoritative_recovery_report() {
            return report;
        }
        match exact_scope {
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
        if let Some(report) = self.local_authoritative_recovery_report() {
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
        match self.operator_recovery_gate_before(deadline).await {
            OperatorRecoveryGate::Clear => {}
            OperatorRecoveryGate::Active | OperatorRecoveryGate::Corrupt => {
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
            OperatorRecoveryGate::Unavailable => {
                return self.unavailable_durable_readiness_report();
            }
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
        if let Some(report) = self.local_authoritative_recovery_report() {
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
        if self.inner.raft.metrics().borrow().running_state.is_ok() {
            return None;
        }
        Some(self.recovery_required_durable_readiness_report())
    }

    /// Return locally authoritative recovery evidence before classifying any
    /// asynchronous durable observation. A permanent physical-prune failure
    /// is store-scoped and cannot be downgraded to transient no-quorum or a
    /// traffic grant merely because it became visible while that observation
    /// was in flight.
    fn local_authoritative_recovery_report(&self) -> Option<DurableReadinessReport> {
        self.fatal_engine_readiness_report().or_else(|| {
            self.inner
                .consensus_log_prune_lane
                .as_ref()
                .is_some_and(|lane| lane.is_degraded())
                .then(|| self.recovery_required_durable_readiness_report())
        })
    }

    fn recovery_required_durable_readiness_report(&self) -> DurableReadinessReport {
        let configured = self.current_member_count().unwrap_or(0);
        let quorum = (configured / 2) + 1;
        let metrics = self.inner.raft.metrics();
        let metrics = metrics.borrow();
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
        ))
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
        let roster_mutation = is_roster_mutation_intent(&request.intent);
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
                match if roster_mutation {
                    self.call_roster_mutation_peer(leader, &request, deadline)
                        .await
                } else {
                    self.call_peer::<_, ForwardMutationReply>(
                        leader,
                        SessionConsensusRpcFamily::ForwardMutation,
                        &BorrowedForwardRequest::Mutation(&request),
                        deadline,
                    )
                    .await
                } {
                    Ok(reply) => reply,
                    Err(ConsensusPeerCallFailure::AfterTransmission)
                    | Err(ConsensusPeerCallFailure::AuthenticatedRejection(_)) => {
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
                        if request.required_consumer_scope.is_consumer_scoped()
                            || matches!(
                                &request.intent,
                                SessionMutationIntent::FencedTransition(_)
                                    | SessionMutationIntent::RosterAdmission(_)
                                    | SessionMutationIntent::RosterTerminal(_)
                            )
                        {
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
                                .require_application_traffic_committed_reply_authority_before(
                                    deadline,
                                )
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
                ForwardMutationReply::FencedTransitionActivation(_) => {
                    return ConsensusSubmissionEffect::OutcomeUnknown;
                }
            }
        }
    }

    /// Submit the internal V1 activation marker through the same authenticated
    /// leader-forwarding path as a state mutation. The request identity is
    /// derived only from the exact cluster scope so concurrent voter startups
    /// coalesce to one durable certificate command.
    async fn activate_fenced_transition_capability_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        self.activate_capability_before(deadline, false).await
    }

    async fn activate_protected_roster_profile_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        self.activate_capability_before(deadline, true).await
    }

    async fn activate_capability_before(
        &self,
        deadline: tokio::time::Instant,
        protected_roster_profile: bool,
    ) -> Result<(), StoreError> {
        self.require_application_traffic_authority_before(deadline)
            .await?;
        let (scope_identity, _) = self.current_scope()?;
        let request = ForwardMutationRequest {
            request_id: if protected_roster_profile {
                protected_roster_profile_activation_request_id(scope_identity)
            } else {
                fenced_transition_activation_request_id(scope_identity)
            },
            intent: if protected_roster_profile {
                SessionMutationIntent::PreflightProtectedRosterProfile
            } else {
                SessionMutationIntent::PreflightFencedTransitionCapability
            },
            required_consumer_scope: ForwardConsumerScope::Internal,
        };
        let mut preferred = None;
        loop {
            let leader = match preferred.take() {
                Some(leader) => leader,
                None => self.wait_for_known_leader(deadline).await?,
            };
            let reply = if leader == self.inner.local_node_id {
                self.apply_on_local_leader(request.clone(), self.inner.local_node_id, deadline)
                    .await
            } else {
                match self
                    .call_peer::<_, ForwardMutationReply>(
                        leader,
                        SessionConsensusRpcFamily::ForwardMutation,
                        &BorrowedForwardRequest::Mutation(&request),
                        deadline,
                    )
                    .await
                {
                    Ok(reply) => reply,
                    // The deterministic cluster-scope request ID makes a
                    // later startup retry idempotent, but this invocation
                    // does not replay after an ambiguous transmit boundary.
                    Err(ConsensusPeerCallFailure::AfterTransmission)
                    | Err(ConsensusPeerCallFailure::AuthenticatedRejection(_)) => {
                        return Err(consensus_unavailable());
                    }
                    Err(ConsensusPeerCallFailure::BeforeTransmission) => {
                        self.wait_for_route_refresh(leader, deadline).await?;
                        continue;
                    }
                }
            };
            match reply {
                ForwardMutationReply::FencedTransitionActivation(Ok(reply)) => {
                    self.inner
                        .read_barrier
                        .wait_for_applied_index(reply.applied_log_index, deadline)
                        .await
                        .map_err(|_| consensus_unavailable())?;
                    self.require_application_traffic_authority_before(deadline)
                        .await?;
                    let (scope_identity, voters) = self.current_scope()?;
                    let activated = if protected_roster_profile {
                        self.inner
                            .backend
                            .consensus_protected_roster_profile_activation_matches_scope(
                                self.inner.storage_identity,
                                scope_identity,
                                voters,
                            )
                            .await?
                    } else {
                        self.inner
                            .backend
                            .consensus_fenced_transition_activation_matches_scope(
                                self.inner.storage_identity,
                                scope_identity,
                                voters,
                            )
                            .await?
                    };
                    if activated {
                        return Ok(());
                    }
                    return Err(consensus_unavailable());
                }
                ForwardMutationReply::FencedTransitionActivation(Err(error)) => {
                    return Err(error);
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
                ForwardMutationReply::Applied(_)
                | ForwardMutationReply::RecordExpiryPreflight(_)
                | ForwardMutationReply::OutcomeUnknown => {
                    return Err(consensus_unavailable());
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
                    Err(ConsensusPeerCallFailure::AfterTransmission)
                    | Err(ConsensusPeerCallFailure::AuthenticatedRejection(_)) => {
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
                ForwardMutationReply::FencedTransitionActivation(_) => {
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
            | ForwardMutationReply::RecordExpiryPreflight(_)
            | ForwardMutationReply::FencedTransitionActivation(_) => {
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
        let fenced_activation_preflight = matches!(
            &request.intent,
            SessionMutationIntent::PreflightFencedTransitionCapability
        );
        let protected_roster_profile_preflight = matches!(
            &request.intent,
            SessionMutationIntent::PreflightProtectedRosterProfile
        );
        let activation_preflight =
            fenced_activation_preflight || protected_roster_profile_preflight;
        let consumer_scoped = request.required_consumer_scope.is_consumer_scoped();
        let raw_v2_mutation =
            is_raw_fenced_transition_v2_mutation(&request.intent, allow_operator_recovery);
        let fixed_raw_v2_mutation =
            raw_v2_mutation && self.inner.topology.mode() == QuorumTopologyMode::FixedDurableQuorum;
        // A durable exact V1 activation can be linearized by the immediate
        // Raft write quorum. It must not relax the distinct V2 authority path.
        let activated_fenced_transition = !activation_preflight
            && matches!(&request.intent, SessionMutationIntent::FencedTransition(_))
            && match self.activated_fenced_transition_scope_is_current().await {
                Ok(activated) => activated,
                Err(_) => return ForwardMutationReply::Unavailable,
            };
        let roster_profile_activated = if is_roster_mutation_intent(&request.intent) {
            match self
                .activated_protected_roster_profile_scope_is_current()
                .await
            {
                Ok(activated) => activated,
                Err(_) => return ForwardMutationReply::Unavailable,
            }
        } else {
            true
        };
        if !roster_profile_activated {
            return ForwardMutationReply::Unavailable;
        }
        let initial_authority = if fixed_raw_v2_mutation || activated_fenced_transition {
            // The operation gate remains held, and the exact durable
            // authority is consumed at its respective final acceptance
            // boundary. Reading it here as well would only add an avoidable
            // SQLite job without strengthening the proposal.
            Ok(())
        } else if allow_operator_recovery {
            self.require_durable_fixed_quorum_admission_before(deadline)
                .await
        } else {
            self.require_application_traffic_intermediate_authority_before(deadline)
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
        // The outcome ledger is append-only, so an already-recorded binding
        // can be returned before acquiring the mutation proposal permit. A
        // match or conflict is absorbing; only a missing binding proceeds to
        // the normal linearized mutation path, where a concurrent first bind
        // is still resolved by consensus. This keeps changed v2 authority
        // context from appending a no-effect conflict proposal.
        if let SessionMutationIntent::BindConsumerRequest { request_commitment } = &request.intent {
            let (authority_identity, _) = match self.current_scope() {
                Ok(scope) => scope,
                Err(_) => return ForwardMutationReply::Unavailable,
            };
            match self
                .inner
                .backend
                .consensus_consumer_request_binding_lookup(
                    self.inner.storage_identity,
                    authority_identity,
                    request.request_id,
                    *request_commitment,
                )
                .await
            {
                Ok(crate::sqlite::consensus::ConsumerRequestBindingLookup::Matched(response)) => {
                    return ForwardMutationReply::Applied(response);
                }
                Ok(crate::sqlite::consensus::ConsumerRequestBindingLookup::Conflict) => {
                    return ForwardMutationReply::Applied(Box::new(
                        SessionConsensusResponse::rejected(StoreError::CasIdempotencyConflict),
                    ));
                }
                Ok(crate::sqlite::consensus::ConsumerRequestBindingLookup::Missing) => {}
                Err(_) => return ForwardMutationReply::Unavailable,
            }
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

        // A physical V1 transition and the state-voter-only V1 activation
        // preflight carry this one typed admission through the capability
        // probe and final proposal. Consumer writes are linearized by the
        // write itself; raw V2 owns the stronger barrier immediately below.
        let fenced_read_admit = if activated_fenced_transition {
            None
        } else if matches!(
            &request.intent,
            SessionMutationIntent::FencedTransition(_)
                | SessionMutationIntent::PreflightFencedTransitionCapability
                | SessionMutationIntent::PreflightProtectedRosterProfile
        ) {
            #[cfg(test)]
            FENCED_TRANSITION_LINEARIZABLE_ADMISSION_COUNT.fetch_add(1, Ordering::Relaxed);
            match self.inner.read_barrier.admit(deadline).await {
                Ok(admit) => Some(admit),
                Err(LinearizableReadBarrierError::NotLeader { leader }) => {
                    return ForwardMutationReply::NotLeader { leader };
                }
                Err(_) => return ForwardMutationReply::Unavailable,
            }
        } else if consumer_scoped
            || !requires_generic_leader_admission(&request.intent, allow_operator_recovery)
        {
            None
        } else {
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
                        self.require_application_traffic_intermediate_authority_before(deadline)
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
            None
        };

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
            self.inner
                .diagnostics
                .fixed_raw_v2_acceptance_snapshots
                .fetch_add(1, Ordering::Relaxed);
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

        let authority = if activated_fenced_transition {
            Ok(())
        } else if allow_operator_recovery {
            self.require_durable_fixed_quorum_admission_before(deadline)
                .await
        } else {
            self.require_application_traffic_intermediate_authority_before(deadline)
                .await
        };
        if authority.is_err() {
            return ForwardMutationReply::Unavailable;
        }

        let fenced_transition_admission = if activated_fenced_transition {
            let (scope_identity, voters) = match self.current_scope() {
                Ok(scope) => scope,
                Err(_) => return ForwardMutationReply::Unavailable,
            };
            Some(FencedTransitionProposalAdmission {
                read_admit: None,
                scope_identity,
                voter_set_digest: fenced_transition_voter_set_digest(scope_identity, &voters),
                required_consumer_scope: request.required_consumer_scope.clone(),
            })
        } else if let Some(read_admit) = fenced_read_admit {
            let capability = match if protected_roster_profile_preflight {
                self.require_protected_roster_profile_activation_after_read_admit(
                    &read_admit,
                    deadline,
                )
                .await
            } else {
                self.require_fenced_transition_capability_after_read_admit(
                    &read_admit,
                    fenced_activation_preflight,
                    deadline,
                )
                .await
            } {
                Ok(capability) => capability,
                Err(error) => {
                    return if activation_preflight {
                        ForwardMutationReply::FencedTransitionActivation(Err(error))
                    } else if matches!(error, StoreError::CapabilityNotSupported(_)) {
                        ForwardMutationReply::Applied(Box::new(SessionConsensusResponse::rejected(
                            unsupported_fenced_transition(),
                        )))
                    } else {
                        // A stale typed admission, changed scope, or revoked
                        // application authority is transient.  Classifying it
                        // as permanent incompatibility would hide the retry
                        // route and, more importantly, blur the no-proposal
                        // distinction at this exact pre-write boundary.
                        ForwardMutationReply::Unavailable
                    };
                }
            };
            let (scope_identity, voters) = match self.current_scope() {
                Ok(scope) => scope,
                Err(_) => return ForwardMutationReply::Unavailable,
            };
            let voter_set_digest = fenced_transition_voter_set_digest(scope_identity, &voters);
            let admission = FencedTransitionProposalAdmission {
                read_admit: Some(read_admit),
                scope_identity,
                voter_set_digest,
                required_consumer_scope: request.required_consumer_scope.clone(),
            };
            match (
                protected_roster_profile_preflight,
                fenced_activation_preflight,
                capability,
            ) {
                (true, false, FencedTransitionCapabilityAdmission::Activated) => {
                    if self
                        .revalidate_fenced_transition_proposal_admission_before(
                            &admission,
                            &request.required_consumer_scope,
                            deadline,
                        )
                        .await
                        .is_err()
                    {
                        return ForwardMutationReply::Unavailable;
                    }
                    let applied_log_index = self
                        .inner
                        .raft
                        .metrics()
                        .borrow()
                        .last_applied
                        .as_ref()
                        .map(|log_id| log_id.index)
                        .filter(|index| *index != 0);
                    return match applied_log_index {
                        Some(applied_log_index) => {
                            ForwardMutationReply::FencedTransitionActivation(Ok(
                                FencedTransitionActivationReply { applied_log_index },
                            ))
                        }
                        None => ForwardMutationReply::Unavailable,
                    };
                }
                (true, false, FencedTransitionCapabilityAdmission::FreshUnanimous) => {
                    request.intent = SessionMutationIntent::ActivateFencedTransitionCapability {
                        schema_version: FENCED_TRANSITION_SCHEMA_V1,
                        scope_identity,
                        voter_set_digest: protected_roster_profile_voter_set_digest(
                            scope_identity,
                            &voters,
                        ),
                    };
                }
                (false, true, FencedTransitionCapabilityAdmission::Activated) => {
                    if self
                        .revalidate_fenced_transition_proposal_admission_before(
                            &admission,
                            &request.required_consumer_scope,
                            deadline,
                        )
                        .await
                        .is_err()
                    {
                        return ForwardMutationReply::Unavailable;
                    }
                    let applied_log_index = self
                        .inner
                        .raft
                        .metrics()
                        .borrow()
                        .last_applied
                        .as_ref()
                        .map(|log_id| log_id.index)
                        .filter(|index| *index != 0);
                    return match applied_log_index {
                        Some(applied_log_index) => {
                            ForwardMutationReply::FencedTransitionActivation(Ok(
                                FencedTransitionActivationReply { applied_log_index },
                            ))
                        }
                        None => ForwardMutationReply::Unavailable,
                    };
                }
                (false, true, FencedTransitionCapabilityAdmission::FreshUnanimous) => {
                    request.intent = SessionMutationIntent::ActivateFencedTransitionCapability {
                        schema_version: FENCED_TRANSITION_SCHEMA_V1,
                        scope_identity,
                        voter_set_digest,
                    };
                }
                (false, false, FencedTransitionCapabilityAdmission::FreshUnanimous) => {
                    let SessionMutationIntent::FencedTransition(transition) = request.intent else {
                        return ForwardMutationReply::Unavailable;
                    };
                    request.intent = SessionMutationIntent::ActivateFencedTransition {
                        request: transition,
                        scope_identity,
                        voter_set_digest,
                    };
                }
                (false, false, FencedTransitionCapabilityAdmission::Activated) => {}
                _ => return ForwardMutationReply::Unavailable,
            }
            Some(admission)
        } else {
            None
        };
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
            && fenced_transition_admission.is_none()
            && self
                .require_application_traffic_intermediate_authority_before(deadline)
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
                || !fenced_transition_activation_voter_set_digest_matches_intent(
                    &request.intent,
                    voter_set_digest,
                    current_identity,
                    &current_voters,
                )
                || profile_digest.is_some_and(|profile_digest| {
                    *profile_digest
                        != crate::fenced_transition::fenced_transition_v2_profile_digest()
                })
            {
                return ForwardMutationReply::Unavailable;
            }
        }
        let reply = self
            .propose_on_local_leader(
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
                fenced_transition_admission,
                deadline,
            )
            .await;
        if activation_preflight {
            return match reply {
                ForwardMutationReply::Applied(response)
                    if matches!(response.result, Ok(SessionMutationOutcome::Unit))
                        && response.raft_log_index != 0 =>
                {
                    ForwardMutationReply::FencedTransitionActivation(Ok(
                        FencedTransitionActivationReply {
                            applied_log_index: response.raft_log_index,
                        },
                    ))
                }
                ForwardMutationReply::Applied(response) => {
                    ForwardMutationReply::FencedTransitionActivation(Err(response
                        .result
                        .err()
                        .unwrap_or_else(consensus_unavailable)))
                }
                ForwardMutationReply::NotLeader { leader } => {
                    ForwardMutationReply::NotLeader { leader }
                }
                ForwardMutationReply::Unavailable | ForwardMutationReply::OutcomeUnknown => {
                    ForwardMutationReply::Unavailable
                }
                ForwardMutationReply::RecordExpiryPreflight(_)
                | ForwardMutationReply::FencedTransitionActivation(_) => {
                    ForwardMutationReply::Unavailable
                }
            };
        }
        reply
    }

    async fn propose_on_local_leader(
        &self,
        request: ForwardMutationRequest,
        authority: LocalProposalAuthority,
        logical_time: Timestamp,
        execution: LocalProposalExecution,
        fenced_transition_admission: Option<FencedTransitionProposalAdmission>,
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
                || !fenced_transition_activation_voter_set_digest_matches_intent(
                    &request.intent,
                    voter_set_digest,
                    identity,
                    &voters,
                )
                || profile_digest.is_some_and(|profile_digest| {
                    *profile_digest
                        != crate::fenced_transition::fenced_transition_v2_profile_digest()
                })
            {
                return ForwardMutationReply::Unavailable;
            }
        }
        #[cfg(test)]
        let consumer_scoped = request.required_consumer_scope.is_consumer_scoped();
        #[cfg(test)]
        let consumer_compare_and_set =
            matches!(&request.intent, SessionMutationIntent::CompareAndSet(_));
        let required_consumer_scope = request.required_consumer_scope.clone();
        let reroute_receiver_forward_to_leader =
            !mutation_requires_exact_status_resolution(&request);
        let roster_mutation = is_roster_mutation_intent(&request.intent);
        let roster_terminal = matches!(&request.intent, SessionMutationIntent::RosterTerminal(_));
        let intent = match request.intent {
            intent @ SessionMutationIntent::FinalizeOperatorRecovery { .. }
            | intent @ SessionMutationIntent::FinalizeOperatorRecoveryV2(_)
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
        let encoded_command = match if roster_mutation {
            encode_roster_bounded(&command)
        } else {
            encode_bounded(&command)
        } {
            Ok(encoded) => encoded,
            Err(_) => {
                let max = self.inner.backend.consensus_capabilities().max_value_bytes;
                return ForwardMutationReply::Applied(Box::new(
                    SessionConsensusResponse::rejected(StoreError::PayloadTooLarge {
                        actual: max.saturating_add(1),
                        max,
                    }),
                ));
            }
        };
        #[cfg(test)]
        if consumer_scoped && consumer_compare_and_set {
            let _ = CONSUMER_CAS_TEST_COUNTERS.try_with(|counters| {
                counters.record_command_encoding(encoded_command.len());
            });
        }
        let _ = encoded_command;

        if let Some(admission) = fenced_transition_admission.as_ref() {
            if self
                .revalidate_fenced_transition_proposal_admission_before(
                    admission,
                    &required_consumer_scope,
                    deadline,
                )
                .await
                .is_err()
            {
                return ForwardMutationReply::Unavailable;
            }
        } else if !authority.allows_operator_recovery
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
        if authority.fixed_raw_v2_snapshot {
            self.inner
                .diagnostics
                .fixed_raw_v2_proposals
                .fetch_add(1, Ordering::Relaxed);
        }
        let roster_response_observation = roster_mutation.then(|| {
            (
                Arc::clone(&self.inner.diagnostics),
                roster_terminal,
                std::time::Instant::now(),
            )
        });
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
                    #[cfg(test)]
                    if consumer_scoped {
                        CONSUMER_CONSENSUS_PROPOSAL_COUNT.fetch_add(1, Ordering::Relaxed);
                        let _ = CONSUMER_CAS_TEST_COUNTERS.try_with(|counters| {
                            counters.record_proposal();
                        });
                    }
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
        let accepted_receiver_test_error = self
            .inner
            .accepted_receiver_test_outcomes
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
                let injected_observation = roster_response_observation.clone();
                tokio::spawn(async move {
                    if matches!(response.await, Ok(Ok(_))) {
                        if let Some((diagnostics, terminal, started)) = injected_observation {
                            diagnostics.observe_protected_roster_proposal_to_applied_response(
                                terminal,
                                false,
                                started.elapsed(),
                            );
                        }
                    }
                    drop(proposal_permit);
                    drop(operation_guard);
                });
                let _ = completion_tx.send(client_write_receiver_error_reply(
                    error,
                    reroute_receiver_forward_to_leader,
                ));
                return;
            }
            let (reply, applied_observation) = match response.await {
                Err(_) => (ForwardMutationReply::OutcomeUnknown, None),
                Ok(Ok(response)) => (
                    ForwardMutationReply::Applied(Box::new(response.data)),
                    roster_response_observation,
                ),
                Ok(Err(error)) => (
                    client_write_receiver_error_reply(error, reroute_receiver_forward_to_leader),
                    None,
                ),
            };
            let attached = completion_tx.send(reply).is_ok();
            if let Some((diagnostics, terminal, started)) = applied_observation {
                diagnostics.observe_protected_roster_proposal_to_applied_response(
                    terminal,
                    attached,
                    started.elapsed(),
                );
            }
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
                None,
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
        request: OperatorRecoveryCommitRequest,
    ) -> Result<(), OperatorRecoveryCommitError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or(OperatorRecoveryCommitError::Unavailable)?;
        self.require_durable_fixed_quorum_admission_before(deadline)
            .await
            .map_err(|_| OperatorRecoveryCommitError::Unavailable)?;
        if request.intent.recovery_epoch == 0 {
            return Err(OperatorRecoveryCommitError::Rejected);
        }
        let metrics = self.inner.raft.metrics();
        if metrics.borrow().current_leader != Some(self.inner.local_node_id) {
            return Err(OperatorRecoveryCommitError::NotLocalLeader);
        }
        let reply = self
            .apply_on_local_leader_inner(
                ForwardMutationRequest {
                    request_id: request.request_id,
                    intent: SessionMutationIntent::FinalizeOperatorRecoveryV2(Box::new(
                        request.intent,
                    )),
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
            | ForwardMutationReply::RecordExpiryPreflight(_)
            | ForwardMutationReply::FencedTransitionActivation(_) => {
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
        // Roster-sized envelopes require a structural proof supplied by the
        // dedicated forwarding path below. Generic callers must never widen
        // an arbitrary application request to the roster payload ceiling.
        if matches!(
            family,
            SessionConsensusRpcFamily::ForwardRosterMutation
                | SessionConsensusRpcFamily::AppendEntriesRoster
        ) {
            return Err(ConsensusPeerCallFailure::BeforeTransmission);
        }
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
            .map_err(ConsensusPeerCallFailure::AuthenticatedRejection)?;
        decode_bounded(&payload).map_err(|_| ConsensusPeerCallFailure::AfterTransmission)
    }

    /// Forward exactly one protected-roster mutation through the distinct,
    /// roster-bounded RPC family. The predicate is checked before selecting
    /// the family and checked again by the leader before it proposes.
    async fn call_roster_mutation_peer(
        &self,
        target: SessionConsensusNodeId,
        request: &ForwardMutationRequest,
        deadline: tokio::time::Instant,
    ) -> Result<ForwardMutationReply, ConsensusPeerCallFailure> {
        if !is_roster_mutation_intent(&request.intent) {
            return Err(ConsensusPeerCallFailure::BeforeTransmission);
        }
        let (identity, peer) = self
            .inner
            .peer_directory
            .resolve_application(target)
            .map_err(|_| ConsensusPeerCallFailure::BeforeTransmission)?;
        let payload = encode_roster_bounded(&BorrowedForwardRequest::Mutation(request))
            .map_err(|_| ConsensusPeerCallFailure::BeforeTransmission)?;
        let wire = SessionConsensusWireRequest::try_new(
            identity,
            self.inner.local_node_id,
            SessionConsensusRpcFamily::ForwardRosterMutation,
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
        decode_roster_bounded(&payload).map_err(|_| ConsensusPeerCallFailure::AfterTransmission)
    }

    async fn local_read_barrier(&self, deadline: tokio::time::Instant) -> ReadBarrierReply {
        if self
            .require_durable_fixed_quorum_admission_before(deadline)
            .await
            .is_err()
        {
            return ReadBarrierReply::Unavailable;
        }
        match self.operator_recovery_gate_before(deadline).await {
            OperatorRecoveryGate::Clear => {}
            OperatorRecoveryGate::Active | OperatorRecoveryGate::Corrupt => {
                return ReadBarrierReply::RecoveryRequired;
            }
            OperatorRecoveryGate::Unavailable => return ReadBarrierReply::Unavailable,
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
                match self.operator_recovery_gate_before(deadline).await {
                    OperatorRecoveryGate::Clear => ReadBarrierReply::Ready(admit.read_log_id()),
                    OperatorRecoveryGate::Active | OperatorRecoveryGate::Corrupt => {
                        ReadBarrierReply::RecoveryRequired
                    }
                    OperatorRecoveryGate::Unavailable => ReadBarrierReply::Unavailable,
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
        #[cfg(test)]
        ROSTER_INGRESS_LINEARIZABLE_BARRIER_COUNT.fetch_add(1, Ordering::Relaxed);
        self.require_durable_fixed_quorum_admission_before(deadline)
            .await
            .map_err(|_| LinearizableBarrierFailure::Unavailable)?;
        match self.operator_recovery_gate_before(deadline).await {
            OperatorRecoveryGate::Clear => {}
            OperatorRecoveryGate::Active | OperatorRecoveryGate::Corrupt => {
                return Err(LinearizableBarrierFailure::RecoveryRequired);
            }
            OperatorRecoveryGate::Unavailable => {
                return Err(LinearizableBarrierFailure::Unavailable);
            }
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
                    match self.operator_recovery_gate_before(deadline).await {
                        OperatorRecoveryGate::Clear => {}
                        OperatorRecoveryGate::Active | OperatorRecoveryGate::Corrupt => {
                            return Err(LinearizableBarrierFailure::RecoveryRequired);
                        }
                        OperatorRecoveryGate::Unavailable => {
                            return Err(LinearizableBarrierFailure::Unavailable);
                        }
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
            | Err(ConsensusPeerCallFailure::AfterTransmission)
            | Err(ConsensusPeerCallFailure::AuthenticatedRejection(_)) => {
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
        // The local consumer service must not spend this one operation budget
        // proving V1 and then ask the authoritative leader to prove the same
        // exact voter set again before it can create the activation receipt.
        // `apply_on_local_leader_inner` performs the only proof that may seed
        // `ActivateFencedTransition`, after it has admitted this exact scope
        // and established leader linearizability.  It also rechecks the scope
        // identity and voter digest immediately before proposal.  Keeping that
        // proof only at the proposal authority means its result is never
        // detached from the activation command, while the caller retains the
        // identical request body/ID if the response becomes ambiguous.
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
        // Exact receipt resolution is a read-only, leader-linearized
        // operation.  It must not create `AdvanceLogicalTime` traffic or
        // repeat an activation capability proof: either can consume the
        // retained recovery budget and turn a durable receipt into a
        // transport-looking ambiguity.  The post-barrier exact-scope
        // admission and final application-authority check below still fence
        // topology hand-off in flight.
        self.linearizable_barrier_before(deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
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

    /// Resolve one ordinary consumer lease receipt through a leader-linearized
    /// read-only path. The binding and operation IDs are already derived from
    /// the authenticated consumer identity by the service; this method never
    /// submits `BindConsumerRequest`, a lease operation, or logical-time work.
    async fn consumer_lease_mutation_status(
        &self,
        scope: SessionConsumerScope,
        binding_request_id: SessionConsensusRequestId,
        operation_request_id: SessionConsensusRequestId,
        request: &SessionConsumerRequest,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsumerLeaseMutationStatus, StoreError> {
        request
            .validate()
            .map_err(|_| StoreError::InvalidKey("consumer request rejected".into()))?;
        if request.scope() != scope {
            return Err(StoreError::TopologyAuthorityRevoked);
        }
        let admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        drop(admission);
        self.linearizable_barrier_before(deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
        // Retain exact-scope admission across the local SQLite receipt read
        // and final authority proof. A topology writer therefore cannot turn
        // an old-scope receipt into a successful current response.
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
            .consensus_consumer_lease_mutation_status(
                self.inner.storage_identity,
                scope.consensus_identity(),
                binding_request_id,
                operation_request_id,
                request,
            )
            .await?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        Ok(status)
    }

    /// Resolve one prepared consumer compare-and-set outcome through a
    /// leader-linearizable read-only path. This never proposes a binding,
    /// mutation, logical-time update, or ordinary row readback.
    async fn consumer_compare_and_set_status(
        &self,
        scope: SessionConsumerScope,
        lookup: crate::sqlite::consensus::ConsumerCompareAndSetReceiptLookup,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsumerCompareAndSetStatus, StoreError> {
        let admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        drop(admission);
        self.linearizable_barrier_before(deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
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
            .consensus_consumer_compare_and_set_status(self.inner.storage_identity, lookup)
            .await?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        Ok(status)
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

/// Admit a batch epoch only while it is active or retained above the durable
/// floor. The state machine still resolves each retained identity against its
/// exact receipt and rejects an absent old identity without allocating a new
/// slot.
fn require_fenced_transition_v2_batch_history_epoch(
    history: &FencedTransitionV2HistoryState,
    request_epoch: FencedTransitionV2HistoryEpoch,
) -> Result<(), StoreError> {
    classify_fresh_v2_history_epoch(history, request_epoch)
}

fn fenced_transition_v2_request_is_body_conflict(request: &FencedTransitionV2Request) -> bool {
    matches!(
        request.validate(),
        Err(StoreError::FencedTransitionRequestConflict)
    )
}

fn fenced_transition_v2_batch_body_conflict_outcomes(
    requests: &[FencedTransitionV2Request],
) -> Vec<Result<FencedTransitionOutcome, StoreError>> {
    requests
        .iter()
        .map(|_| Err(StoreError::FencedTransitionRequestConflict))
        .collect()
}

fn fenced_transition_v2_batch_epoch_outcomes(
    requests: &[FencedTransitionV2Request],
    epoch_error: StoreError,
) -> Vec<Result<FencedTransitionOutcome, StoreError>> {
    requests
        .iter()
        .map(|request| {
            if fenced_transition_v2_request_is_body_conflict(request) {
                Err(StoreError::FencedTransitionRequestConflict)
            } else {
                Err(epoch_error.clone())
            }
        })
        .collect()
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
        }
        | SessionMutationIntent::ActivateFencedTransitionCapability {
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

fn fenced_transition_activation_voter_set_digest_matches_intent(
    intent: &SessionMutationIntent,
    digest: &[u8; 32],
    scope: SessionConsensusIdentity,
    voters: &BTreeSet<SessionConsensusNodeId>,
) -> bool {
    if *digest == fenced_transition_voter_set_digest(scope, voters) {
        return true;
    }
    matches!(
        intent,
        SessionMutationIntent::ActivateFencedTransitionCapability { .. }
    ) && *digest == protected_roster_profile_voter_set_digest(scope, voters)
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
        SessionMutationIntent::RosterAdmission(_) | SessionMutationIntent::RosterTerminal(_) => {
            StoreError::BackendOperationOutcomeUnavailable
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
                | SessionMutationIntent::PreflightFencedTransitionCapability
                | SessionMutationIntent::PreflightProtectedRosterProfile
                | SessionMutationIntent::ActivateFencedTransitionCapability { .. }
                | SessionMutationIntent::FencedTransitionV2(_)
                | SessionMutationIntent::FencedTransitionV2Batch(_)
                | SessionMutationIntent::ActivateFencedTransitionV2 { .. }
                | SessionMutationIntent::RosterAdmission(_)
                | SessionMutationIntent::RosterTerminal(_)
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
        let uses_dedicated_roster_validation = matches!(
            outcome,
            SessionMutationOutcome::RosterAdmission(_) | SessionMutationOutcome::RosterTerminal(_)
        );
        if !uses_dedicated_roster_validation
            && crate::sqlite::consensus::validate_consensus_outcome_records(outcome).is_err()
        {
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
            SessionMutationIntent::FinalizeOperatorRecoveryV2(_),
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
        (
            Ok(SessionMutationOutcome::RosterAdmission(outcome)),
            SessionMutationIntent::RosterAdmission(command),
        ) => roster_admission_outcome_matches_command(command, outcome),
        (
            Ok(SessionMutationOutcome::RosterTerminal(outcome)),
            SessionMutationIntent::RosterTerminal(command),
        ) => roster_terminal_outcome_matches_command(command, outcome),
        _ => false,
    }
}

fn roster_admission_outcome_matches_command(
    command: &ConsensusRosterAdmissionCommand,
    outcome: &ConsensusRosterAdmissionOutcome,
) -> bool {
    if validate_roster_admission_command(command, None).is_err() {
        return false;
    }
    match outcome {
        ConsensusRosterAdmissionOutcome::Admitted {
            outcome_binding,
            slot,
            binding,
            registration_handle,
            registration_request_id,
            registration_terminal_slot,
        } => {
            let Ok(true) = outcome_binding.matches_admission(command) else {
                return false;
            };
            let Ok(expected_slot) = command.admission_slot() else {
                return false;
            };
            if *slot != expected_slot {
                return false;
            }

            let Ok(expected_binding) = command
                .admission()
                .binding_key(registration_request_id.history_epoch())
            else {
                return false;
            };
            if binding.as_ref() != &expected_binding {
                return false;
            }

            let Ok(registration) =
                crate::fenced_mutation_roster_executor::BackendRegistration::from_consensus_parts(
                    *registration_handle,
                    *registration_request_id,
                    command.admission(),
                )
            else {
                return false;
            };
            let (checked_handle, checked_request_id, checked_terminal_slot) =
                registration.consensus_parts();
            checked_handle == *registration_handle
                && checked_request_id == *registration_request_id
                && *checked_terminal_slot.as_bytes() == *registration_terminal_slot
        }
        ConsensusRosterAdmissionOutcome::Rejected {
            outcome_binding,
            rejection,
        } => {
            outcome_binding.matches_admission(command) == Ok(true)
                && roster_rejection_is_typed(*rejection)
        }
        ConsensusRosterAdmissionOutcome::Replayed { outcome_binding } => {
            outcome_binding.matches_admission(command) == Ok(true)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RosterAdmissionIngressDisposition {
    Fresh,
    Replayed,
}

/// The registration history epoch is minted exactly at the first admitted
/// Raft entry. A later committed admission result can therefore never issue a
/// second execution capability for that registration.
fn roster_admission_ingress_disposition(
    registration_history_epoch: u64,
    response_raft_log_index: u64,
) -> Result<RosterAdmissionIngressDisposition, ()> {
    if registration_history_epoch == 0 || response_raft_log_index == 0 {
        return Err(());
    }
    match registration_history_epoch.cmp(&response_raft_log_index) {
        std::cmp::Ordering::Equal => Ok(RosterAdmissionIngressDisposition::Fresh),
        std::cmp::Ordering::Less => Ok(RosterAdmissionIngressDisposition::Replayed),
        std::cmp::Ordering::Greater => Err(()),
    }
}

fn roster_terminal_outcome_matches_command(
    command: &ConsensusRosterTerminalCommand,
    outcome: &ConsensusRosterTerminalOutcome,
) -> bool {
    if validate_roster_terminal_command(command, None).is_err() {
        return false;
    }
    let Ok(expected_slot) = command.terminal_slot() else {
        return false;
    };

    match outcome {
        ConsensusRosterTerminalOutcome::Committed {
            outcome_binding,
            slot,
            ..
        } => {
            let Ok(expected_body_commitment) =
                crate::fenced_mutation_roster::TerminalRecord::canonical_body_commitment(
                    command.record_bytes(),
                )
            else {
                return false;
            };
            outcome_binding.matches_terminal(command) == Ok(true)
                && *slot == expected_slot
                && outcome.committed_bytes().is_some_and(|committed| {
                    crate::fenced_mutation_roster_executor::CommittedTerminal::canonical_terminal_body_commitment(
                        committed,
                    ) == Ok(expected_body_commitment)
                })
        }
        ConsensusRosterTerminalOutcome::Compacted {
            outcome_binding,
            slot,
            ..
        } => {
            let (_, registration_request_id, registration_terminal_slot) =
                command.registration_parts();
            let Ok(terminal_body_commitment) =
                crate::fenced_mutation_roster::TerminalRecord::canonical_body_commitment(
                    command.record_bytes(),
                )
            else {
                return false;
            };
            let Ok(Some((history_epoch, tombstone))) = outcome.compacted_parts() else {
                return false;
            };
            outcome_binding.matches_terminal(command) == Ok(true)
                && *slot == expected_slot
                && history_epoch == command.binding().history_epoch()
                && history_epoch == registration_request_id.history_epoch()
                && tombstone
                    .validate_compacted_terminal(
                        command.binding(),
                        registration_request_id,
                        registration_terminal_slot,
                        command.authority().fence(),
                        command.authority().generation(),
                        terminal_body_commitment,
                    )
                    .is_ok()
        }
        ConsensusRosterTerminalOutcome::Rejected {
            outcome_binding,
            rejection,
        } => {
            outcome_binding.matches_terminal(command) == Ok(true)
                && roster_rejection_is_typed(*rejection)
        }
    }
}

fn roster_rejection_is_typed(rejection: ConsensusRosterRejection) -> bool {
    match rejection {
        ConsensusRosterRejection::Authority
        | ConsensusRosterRejection::RecoveryRequired
        | ConsensusRosterRejection::TerminalLocked
        | ConsensusRosterRejection::TerminalConflict
        | ConsensusRosterRejection::RecordMissing
        | ConsensusRosterRejection::GenerationConflict
        | ConsensusRosterRejection::GenerationExhausted
        | ConsensusRosterRejection::BusinessKeyReserved
        | ConsensusRosterRejection::InvalidProtectedCheckpoint
        | ConsensusRosterRejection::AggregateBytesFull
        | ConsensusRosterRejection::LiveFull
        | ConsensusRosterRejection::HistoryFull => true,
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
                    outcome.recorded_at() <= logical_time
                        && !outcome.is_expired_at(logical_time)
                        && outcome.matches_v2_request(request)
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
/// activation path, `activation_outcome` supplies the selected activating
/// item and this
/// response must still prove the complete suffix before the combined batch is
/// resolved.
fn committed_fenced_transition_v2_batch_effect(
    original_request_ids: &[crate::FencedTransitionV2RequestId],
    requests: &[FencedTransitionV2Request],
    activation_outcome: Option<(usize, Result<FencedTransitionOutcome, StoreError>)>,
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
    if let Some((slot, outcome)) = activation_outcome {
        if slot > outcomes.len() {
            return unknown();
        }
        outcomes.insert(slot, outcome);
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
                SessionMutationIntent::BindConsumerRequest { .. },
                StoreError::CasIdempotencyConflict
            )
        )
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
        SessionMutationIntent::FinalizeOperatorRecovery { .. }
        | SessionMutationIntent::FinalizeOperatorRecoveryV2(_) => {
            matches!(error, StoreError::InvalidKey(reason) if reason == "operator_recovery_epoch_rejected")
        }
        SessionMutationIntent::PrepareTopologyTransition { .. }
        | SessionMutationIntent::MarkTopologyLearnersReady { .. }
        | SessionMutationIntent::FenceTopologyAuthority { .. }
        | SessionMutationIntent::AbortTopologyTransition { .. }
        | SessionMutationIntent::FinalizeTopologyTransition { .. }
        | SessionMutationIntent::ActivateFencedTransition { .. }
        | SessionMutationIntent::PreflightFencedTransitionCapability
        | SessionMutationIntent::PreflightProtectedRosterProfile
        | SessionMutationIntent::ActivateFencedTransitionCapability { .. }
        | SessionMutationIntent::RosterAdmission(_)
        | SessionMutationIntent::RosterTerminal(_)
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
    if let SessionMutationIntent::ActivateFencedTransitionCapability { schema_version, .. } = intent
    {
        if *schema_version != FENCED_TRANSITION_SCHEMA_V1 {
            return Err(unsupported_fenced_transition());
        }
    }
    match intent {
        SessionMutationIntent::RosterAdmission(roster) => {
            validate_roster_admission_command(roster, Some(command.request_id))?
        }
        SessionMutationIntent::RosterTerminal(roster) => {
            validate_roster_terminal_command(roster, Some(command.request_id))?
        }
        _ => {}
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
            | SessionMutationIntent::FinalizeOperatorRecoveryV2(_)
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
            | SessionMutationIntent::ActivateFencedTransitionCapability { .. }
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
    match intent {
        SessionMutationIntent::RosterAdmission(command) => {
            validate_roster_admission_command(command, None)?
        }
        SessionMutationIntent::RosterTerminal(command) => {
            validate_roster_terminal_command(command, None)?
        }
        _ => {}
    }
    Ok(())
}

fn validate_roster_admission_command(
    command: &ConsensusRosterAdmissionCommand,
    expected_request_id: Option<SessionConsensusRequestId>,
) -> Result<(), StoreError> {
    let request_id = command.request_id()?;
    if expected_request_id.is_some_and(|expected| expected != request_id) {
        return Err(StoreError::InvalidKey(
            "roster_admission_request_id_mismatch".into(),
        ));
    }
    let _slot = command.admission_slot()?;
    let _payload_digest = command.immutable_payload_digest()?;
    let ingress = command.ingress_attestation()?;
    let _provenance = command.admission_provenance()?;
    if command.ingress_request_id() == [0; 16]
        || ingress.request_id() != command.ingress_request_id()
    {
        return Err(StoreError::InvalidKey(
            "roster_admission_ingress_request_id_mismatch".into(),
        ));
    }
    Ok(())
}

fn validate_roster_terminal_command(
    command: &ConsensusRosterTerminalCommand,
    expected_request_id: Option<SessionConsensusRequestId>,
) -> Result<(), StoreError> {
    let request_id = command.request_id()?;
    if expected_request_id.is_some_and(|expected| expected != request_id) {
        return Err(StoreError::InvalidKey(
            "roster_terminal_request_id_mismatch".into(),
        ));
    }
    let (registration_handle, registration_request_id, registration_terminal_slot) =
        command.registration_parts();
    if registration_handle == [0; 32]
        || registration_terminal_slot == [0; 32]
        || registration_request_id.history_epoch() != command.binding().history_epoch()
        || command.terminal_slot()? != registration_terminal_slot
    {
        return Err(StoreError::InvalidKey(
            "roster_terminal_registration_mismatch".into(),
        ));
    }
    crate::fenced_mutation_roster::TerminalRecord::canonical_body_commitment(
        command.record_bytes(),
    )
    .map_err(|_| StoreError::InvalidKey("roster_terminal_record_invalid".into()))?;
    command.proof_bundle()?;
    command.terminal_evidence()?;
    let ingress = command.ingress_attestation()?;
    if command.ingress_request_id() == [0; 16]
        || ingress.request_id() != command.ingress_request_id()
    {
        return Err(StoreError::InvalidKey(
            "roster_terminal_ingress_request_id_mismatch".into(),
        ));
    }
    let _outcome_binding = command.outcome_binding()?;
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
            | SessionConsensusRpcFamily::AppendEntriesRoster
            | SessionConsensusRpcFamily::InstallSnapshot => {
                let deadline = tokio::time::Instant::now()
                    .checked_add(self.store.inner.operation_timeout)
                    .unwrap_or_else(tokio::time::Instant::now);
                self.store
                    .inner
                    .raft_handler
                    .handle_before(authenticated_sender, request, deadline)
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
            SessionConsensusRpcFamily::ForwardRosterMutation => {
                if !self
                    .store
                    .current_application_scope_matches(authenticated_sender, request.identity)
                {
                    return SessionConsensusWireResponse {
                        result: Err(SessionConsensusPeerError::ScopeMismatch),
                    };
                }
                let forwarded: ForwardRequest = match decode_roster_bounded(&request.payload) {
                    Ok(forwarded) => forwarded,
                    Err(_) => return protocol_rejection(),
                };
                let ForwardRequest::Mutation(forwarded) = forwarded else {
                    return protocol_rejection();
                };
                if !is_roster_mutation_intent(&forwarded.intent) {
                    return protocol_rejection();
                }
                let deadline = tokio::time::Instant::now()
                    .checked_add(self.store.inner.operation_timeout)
                    .unwrap_or_else(tokio::time::Instant::now);
                encode_service_reply(
                    &self
                        .store
                        .apply_on_local_leader(forwarded, authenticated_sender, deadline)
                        .await,
                )
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
                if let Ok(probe) =
                    decode_bounded::<FencedTransitionActivationCapabilityProbe>(&request.payload)
                {
                    // Activation establishes a distinct replicated command
                    // shape.  A voter that can execute ordinary V1 fenced
                    // transitions but does not recognize that shape is not
                    // sufficient for an exact-scope activation certificate.
                    let reply = if probe.activation_probe_schema_version
                        == FENCED_TRANSITION_ACTIVATION_PROBE_SCHEMA_V1
                        && probe.activation_command_schema_version == FENCED_TRANSITION_SCHEMA_V1
                        && self.store.local_fenced_transition_capability()
                            == AtomicFencedTransitionCapability::V1
                    {
                        FencedTransitionActivationCapabilityReply::V1
                    } else {
                        FencedTransitionActivationCapabilityReply::Unsupported
                    };
                    return encode_service_reply(&reply);
                }
                if let Ok(probe) =
                    decode_bounded::<ProtectedRosterProfileCapabilityProbe>(&request.payload)
                {
                    return encode_service_reply(&protected_roster_profile_capability_probe_reply(
                        probe,
                        self.store.local_fenced_transition_capability(),
                    ));
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

fn is_roster_mutation_intent(intent: &SessionMutationIntent) -> bool {
    matches!(
        intent,
        SessionMutationIntent::RosterAdmission(_) | SessionMutationIntent::RosterTerminal(_)
    )
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

    async fn lease_mutation_status(
        &self,
        identity: &SessionConsumerIdentity,
        request: &SessionConsumerRequest,
        retained: SessionConsumerLeaseMutationRequest,
        deadline: tokio::time::Instant,
    ) -> SessionConsumerResponse {
        let original = retained.into_original_consumer_request(request.scope());
        let operation_request_id =
            match derive_consumer_consensus_request_id(identity, &original, 0) {
                Ok(request_id) => request_id,
                Err(rejection) => return SessionConsumerResponse::Rejected(rejection),
            };
        let binding_request_id = derive_consumer_request_binding_id(identity, &original);
        SessionConsumerResponse::LeaseMutationStatus(
            self.store
                .consumer_lease_mutation_status(
                    request.scope(),
                    binding_request_id,
                    operation_request_id,
                    &original,
                    deadline,
                )
                .await
                // A receipt lookup has no operation-specific outer error
                // family. Its only authoritative outcomes are the exact
                // retained receipt, RequestConflict, and NotFound. In
                // particular, topology or read-barrier failures must remain
                // ambiguous availability rather than being converted into a
                // lease-shaped value (such as StaleFence) that the transport
                // correctly rejects as impossible for this read-only call.
                .map_err(|_| SessionConsumerStoreError::Unavailable),
        )
    }

    async fn compare_and_set_status(
        &self,
        identity: &SessionConsumerIdentity,
        request: &SessionConsumerRequest,
        retained: SessionConsumerCompareAndSetRequest,
        deadline: tokio::time::Instant,
    ) -> SessionConsumerResponse {
        let original = retained.into_original_consumer_request(request.scope());
        if original.validate().is_err() {
            return SessionConsumerResponse::Rejected(SessionConsumerRejection::MalformedRequest);
        }
        let request_commitment = match consumer_request_commitment(&original) {
            Ok(commitment) => commitment,
            Err(rejection) => return SessionConsumerResponse::Rejected(rejection),
        };
        let operation_request_id =
            derive_consumer_consensus_request_id_from_commitment(identity, request_commitment, 0);
        let binding_request_id = derive_consumer_request_binding_id(identity, &original);
        let operation = match original.operation() {
            SessionConsumerOperation::CompareAndSet { op } => op.as_ref(),
            _ => {
                return SessionConsumerResponse::Rejected(
                    SessionConsumerRejection::MalformedRequest,
                );
            }
        };
        let lookup = match crate::sqlite::consensus::consumer_compare_and_set_receipt_lookup(
            self.store.inner.storage_identity,
            request.scope().consensus_identity(),
            binding_request_id,
            operation_request_id,
            request_commitment,
            operation,
        ) {
            Ok(lookup) => lookup,
            Err(_) => {
                return SessionConsumerResponse::Rejected(SessionConsumerRejection::Unavailable);
            }
        };
        match self
            .store
            .consumer_compare_and_set_status(request.scope(), lookup, deadline)
            .await
        {
            // Preserve exact topology revocation as a typed no-authority
            // result. All other read failures remain unavailable and cannot
            // be mistaken for a recorded outcome.
            Err(StoreError::TopologyAuthorityRevoked) => {
                SessionConsumerResponse::Rejected(SessionConsumerRejection::ScopeMismatch)
            }
            result => SessionConsumerResponse::CompareAndSetStatus(
                result.map_err(|_| SessionConsumerStoreError::Unavailable),
            ),
        }
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
        request_commitment: [u8; 32],
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        let request_id = derive_consumer_request_binding_id(identity, request);
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

    /// Persist only the ordinary consumer request binding for conformance
    /// qualification.
    ///
    /// This is available solely with `test-control`. It validates the same
    /// request, authorization, and scope admission as the normal consumer
    /// mutation path, then commits the exact durable idempotency binding. It
    /// deliberately does not submit, replay, or otherwise execute the
    /// request's effect.
    #[cfg(feature = "test-control")]
    #[doc(hidden)]
    pub async fn prepare_consumer_request_binding_for_test(
        &self,
        authorization: &SessionConsumerAuthorization,
        request: &SessionConsumerRequest,
    ) -> Result<(), StoreError> {
        let deadline = self
            .operation_deadline()
            .map_err(|_| consensus_unavailable())?;
        request.validate().map_err(|_| consensus_unavailable())?;
        validate_consumer_operation(request.operation()).map_err(|_| consensus_unavailable())?;
        authorization
            .authorize_operation(request.operation())
            .map_err(|_| consensus_unavailable())?;
        let admission = self
            .store
            .admit_consumer_scope(request.scope(), deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
        drop(admission);
        let request_commitment =
            consumer_request_commitment(request).map_err(|_| consensus_unavailable())?;
        self.bind_consumer_request(
            authorization.identity(),
            request,
            request_commitment,
            deadline,
        )
        .await
    }

    async fn submit_consumer_intent(
        &self,
        identity: &SessionConsumerIdentity,
        request: &SessionConsumerRequest,
        request_commitment: [u8; 32],
        slot: u16,
        intent: SessionMutationIntent,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsensusResponse, StoreError> {
        let request_id = derive_consumer_consensus_request_id_from_commitment(
            identity,
            request_commitment,
            slot,
        );
        self.submit_consumer_intent_with_id(request.scope(), request_id, intent, deadline)
            .await
    }

    async fn submit_consumer_intent_with_id(
        &self,
        scope: SessionConsumerScope,
        request_id: SessionConsensusRequestId,
        intent: SessionMutationIntent,
        deadline: tokio::time::Instant,
    ) -> Result<SessionConsensusResponse, StoreError> {
        self.store
            .submit_request_before(
                request_id,
                intent,
                Some(scope.consensus_identity()),
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
            | SessionConsumerOperation::LeaseMutationStatus { .. }
            | SessionConsumerOperation::CompareAndSetStatus { .. }
            | SessionConsumerOperation::FencedTransitionStatus { .. }
            | SessionConsumerOperation::FencedMutationRosterPollAdmit { .. }
            | SessionConsumerOperation::FencedMutationRosterAdmissionStatus { .. }
            | SessionConsumerOperation::FencedMutationRosterRecover { .. }
            | SessionConsumerOperation::FencedMutationRosterTerminalize { .. }
            | SessionConsumerOperation::FencedMutationRosterTerminalStatus { .. }
            | SessionConsumerOperation::FencedMutationRosterCurrentPublicationAuthority {
                ..
            } => SessionConsumerResponse::Rejected(SessionConsumerRejection::MalformedRequest),
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
            | SessionConsumerOperation::LeaseMutationStatus { .. }
            | SessionConsumerOperation::CompareAndSetStatus { .. }
            | SessionConsumerOperation::FencedTransitionStatus { .. }
            // Protected-roster operations are deliberately outside this
            // ordinary consumer mutation classifier. The dedicated `/3`
            // ingress authenticates and dispatches them through its closed
            // roster service instead of this general authorization path.
            | SessionConsumerOperation::FencedMutationRosterPollAdmit { .. }
            | SessionConsumerOperation::FencedMutationRosterAdmissionStatus { .. }
            | SessionConsumerOperation::FencedMutationRosterRecover { .. }
            | SessionConsumerOperation::FencedMutationRosterTerminalize { .. }
            | SessionConsumerOperation::FencedMutationRosterTerminalStatus { .. }
            | SessionConsumerOperation::FencedMutationRosterCurrentPublicationAuthority { .. } => {
                false
            }
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
        request_commitment: [u8; 32],
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
                            request_commitment,
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
                            request_commitment,
                            slot,
                            SessionMutationIntent::CompareAndSet(Arc::new(op)),
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
                            request_commitment,
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
                            request_commitment,
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

fn session_consumer_roster_rejection(
    rejection: ConsensusRosterRejection,
) -> SessionConsumerRosterRejection {
    match rejection {
        ConsensusRosterRejection::Authority => SessionConsumerRosterRejection::Authority,
        ConsensusRosterRejection::RecoveryRequired | ConsensusRosterRejection::TerminalLocked => {
            SessionConsumerRosterRejection::RecoveryRequired
        }
        ConsensusRosterRejection::TerminalConflict => SessionConsumerRosterRejection::Conflict,
        ConsensusRosterRejection::RecordMissing => SessionConsumerRosterRejection::RecordMissing,
        ConsensusRosterRejection::GenerationConflict => {
            SessionConsumerRosterRejection::GenerationConflict
        }
        ConsensusRosterRejection::GenerationExhausted => {
            SessionConsumerRosterRejection::GenerationExhausted
        }
        ConsensusRosterRejection::BusinessKeyReserved => {
            SessionConsumerRosterRejection::BusinessKeyReserved
        }
        ConsensusRosterRejection::InvalidProtectedCheckpoint => {
            SessionConsumerRosterRejection::InvalidProtectedCheckpoint
        }
        ConsensusRosterRejection::AggregateBytesFull => {
            SessionConsumerRosterRejection::AggregateBytesFull
        }
        ConsensusRosterRejection::LiveFull => SessionConsumerRosterRejection::LiveFull,
        ConsensusRosterRejection::HistoryFull => SessionConsumerRosterRejection::HistoryFull,
    }
}

fn roster_store_rejection(error: &StoreError) -> SessionConsumerRosterRejection {
    match error {
        // The SQLite protected-roster adapter deliberately uses this
        // redacted validation error for a stale, expired, or cross-scoped
        // authority.  All caller-controlled decode errors have already been
        // rejected at the opaque transport boundary.
        StoreError::InvalidKey(_) | StoreError::TopologyAuthorityRevoked => {
            SessionConsumerRosterRejection::Authority
        }
        StoreError::CapabilityNotSupported(_) => SessionConsumerRosterRejection::Capability,
        _ => SessionConsumerRosterRejection::Unavailable,
    }
}

fn roster_admission_mutation_rejected(
    rejection: SessionConsumerRosterRejection,
) -> SessionConsumerResponse {
    SessionConsumerResponse::FencedMutationRosterPollAdmit(
        SessionConsumerRosterAdmissionMutationResponse::Rejected(rejection),
    )
}

fn roster_admission_read_rejected(
    recovery: bool,
    rejection: SessionConsumerRosterRejection,
) -> SessionConsumerResponse {
    let response = SessionConsumerRosterAdmissionReadResponse::Rejected(rejection);
    if recovery {
        SessionConsumerResponse::FencedMutationRosterRecover(response)
    } else {
        SessionConsumerResponse::FencedMutationRosterAdmissionStatus(response)
    }
}

fn roster_terminal_mutation_rejected(
    rejection: SessionConsumerRosterRejection,
) -> SessionConsumerResponse {
    SessionConsumerResponse::FencedMutationRosterTerminalize(
        SessionConsumerRosterTerminalMutationResponse::Rejected(rejection),
    )
}

fn roster_terminal_read_rejected(
    rejection: SessionConsumerRosterRejection,
) -> SessionConsumerResponse {
    SessionConsumerResponse::FencedMutationRosterTerminalStatus(
        SessionConsumerRosterTerminalReadResponse::Rejected(rejection),
    )
}

/// Do not distinguish malformed, stale, expired, foreign, or unavailable
/// current-publication-authority reads. This private capability is only a
/// Boolean eligibility check to the consumed publication adapter.
fn roster_current_publication_authority_rejected() -> SessionConsumerResponse {
    SessionConsumerResponse::FencedMutationRosterCurrentPublicationAuthority(
        SessionConsumerRosterCurrentPublicationAuthorityReadResponse::Rejected,
    )
}

enum RosterAdmissionRead {
    Status(
        Box<(
            crate::fenced_mutation_roster::Admission,
            crate::fenced_mutation_roster_executor::AuthorityBinding,
        )>,
    ),
    Recovery(Box<crate::fenced_mutation_roster_executor::RecoveryRequest>),
}

impl ConsensusSessionConsumerService {
    fn roster_expected_root(&self) -> Option<RosterAttestationTrustRootV1> {
        self.store.inner.roster_attestation_trust_root.clone()
    }

    async fn roster_read_time(&self) -> Result<Timestamp, SessionConsumerRosterRejection> {
        #[cfg(test)]
        ROSTER_INGRESS_LOGICAL_TIME_READ_COUNT.fetch_add(1, Ordering::Relaxed);
        let persisted = self
            .store
            .inner
            .backend
            .consensus_logical_time(self.store.inner.storage_identity)
            .await
            .map_err(|_| SessionConsumerRosterRejection::Unavailable)?;
        Ok(persisted.map_or_else(
            || self.store.inner.clock.now_utc(),
            |time| time.max(self.store.inner.clock.now_utc()),
        ))
    }

    fn roster_read_response(
        &self,
        scope: SessionConsumerScope,
        read: crate::sqlite::consensus::ProtectedRosterReadResult,
        recovery: bool,
    ) -> SessionConsumerResponse {
        use crate::sqlite::consensus::ProtectedRosterReadResult;

        let result = match read {
            // Absence after an unconfirmed write is deliberately not a proof
            // that it did not apply. A caller must keep its retained body and
            // move through recovery, never manufacture a new admission.
            ProtectedRosterReadResult::Missing => {
                return roster_admission_read_rejected(
                    recovery,
                    SessionConsumerRosterRejection::RecoveryRequired,
                );
            }
            ProtectedRosterReadResult::Admitted(live) => encode_admission_poll_admitted_response(
                scope,
                live.registration,
                &live.admission,
                &live.admission_provenance,
            ),
            ProtectedRosterReadResult::Terminalized(terminal) => {
                encode_admission_terminal_response(
                    scope,
                    terminal.registration,
                    &terminal.admission,
                    &terminal.committed,
                    &terminal.admission_provenance,
                )
            }
            ProtectedRosterReadResult::Compacted {
                history_epoch,
                tombstone,
            } => encode_admission_compacted_response(scope, history_epoch, *tombstone),
        };
        match result {
            Ok(capsule) => {
                let response = SessionConsumerRosterAdmissionReadResponse::Recorded(capsule);
                if recovery {
                    SessionConsumerResponse::FencedMutationRosterRecover(response)
                } else {
                    SessionConsumerResponse::FencedMutationRosterAdmissionStatus(response)
                }
            }
            Err(_) => roster_admission_read_rejected(
                recovery,
                SessionConsumerRosterRejection::Unavailable,
            ),
        }
    }

    fn roster_terminal_read(
        &self,
        scope: SessionConsumerScope,
        decoded: crate::fenced_mutation_roster_transport::DecodedTerminalRequest,
        read: crate::sqlite::consensus::ProtectedRosterReadResult,
        _post_barrier_guard: ConsumerScopeAdmission,
    ) -> SessionConsumerResponse {
        use crate::sqlite::consensus::ProtectedRosterReadResult;

        match read {
            ProtectedRosterReadResult::Missing => {
                roster_terminal_read_rejected(SessionConsumerRosterRejection::RecoveryRequired)
            }
            ProtectedRosterReadResult::Compacted {
                history_epoch,
                tombstone,
            } => {
                let result = encode_terminal_compacted_response(scope, history_epoch, *tombstone);
                match result {
                    Ok(capsule) => SessionConsumerResponse::FencedMutationRosterTerminalStatus(
                        SessionConsumerRosterTerminalReadResponse::Recorded(capsule),
                    ),
                    Err(_) => {
                        roster_terminal_read_rejected(SessionConsumerRosterRejection::Unavailable)
                    }
                }
            }
            ProtectedRosterReadResult::Terminalized(terminal) => {
                // Rehydrate only after the exact retained admission was
                // selected by the backend. This validates the supplied raw
                // registration and terminal body without reconstructing the
                // committed terminal bytes we return below.
                if decoded.into_terminal_request(&terminal.admission).is_err() {
                    return roster_terminal_read_rejected(
                        SessionConsumerRosterRejection::Malformed,
                    );
                }
                match encode_terminal_terminalized_validated_bytes_response(
                    scope,
                    &terminal.admission,
                    terminal.committed_canonical,
                ) {
                    Ok(capsule) => SessionConsumerResponse::FencedMutationRosterTerminalStatus(
                        SessionConsumerRosterTerminalReadResponse::Recorded(capsule),
                    ),
                    Err(_) => {
                        roster_terminal_read_rejected(SessionConsumerRosterRejection::Unavailable)
                    }
                }
            }
            ProtectedRosterReadResult::Admitted(live) => {
                match decoded.into_terminal_request(&live.admission) {
                    Ok(_) => match encode_terminal_admitted_response(scope) {
                        Ok(capsule) => SessionConsumerResponse::FencedMutationRosterTerminalStatus(
                            SessionConsumerRosterTerminalReadResponse::Recorded(capsule),
                        ),
                        Err(_) => roster_terminal_read_rejected(
                            SessionConsumerRosterRejection::Unavailable,
                        ),
                    },
                    Err(_) => {
                        roster_terminal_read_rejected(SessionConsumerRosterRejection::Malformed)
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn roster_terminal_mutate(
        &self,
        scope: SessionConsumerScope,
        ingress_request_id: crate::consumer::SessionConsumerRequestId,
        attestation: RosterIngressAttestationV1,
        decoded: crate::fenced_mutation_roster_transport::DecodedTerminalRequest,
        deadline: tokio::time::Instant,
        scope_guard: ConsumerScopeAdmission,
    ) -> SessionConsumerResponse {
        let binding = decoded.binding();
        let (registration_handle, registration_request_id, registration_terminal_slot) =
            decoded.registration_parts();
        let authority = decoded.authority().clone();
        let record = decoded.canonical_record().to_vec();
        if decoded.terminal_body_commitment().is_err() {
            return roster_terminal_mutation_rejected(SessionConsumerRosterRejection::Malformed);
        }
        let proof_bundle = match decoded.proof_bundle() {
            Ok(proof_bundle) => proof_bundle,
            Err(_) => {
                return roster_terminal_mutation_rejected(
                    SessionConsumerRosterRejection::Malformed,
                );
            }
        };
        let terminal_evidence = match decoded.terminal_evidence() {
            Ok(terminal_evidence) => terminal_evidence,
            Err(_) => {
                return roster_terminal_mutation_rejected(
                    SessionConsumerRosterRejection::Malformed,
                );
            }
        };
        let command = match ConsensusRosterTerminalCommand::new_with_proof_bundle_evidence_and_ingress_request_id(
                super::types::ConsensusRosterTerminalCommandInput {
                    binding,
                    registration_handle,
                    registration_request_id,
                    registration_terminal_slot,
                    authority,
                    record,
                },
                proof_bundle,
                terminal_evidence,
                *ingress_request_id.as_bytes(),
                attestation,
            ) {
                Ok(command) => command,
                Err(_) => {
                    return roster_terminal_mutation_rejected(
                        SessionConsumerRosterRejection::Malformed,
                    )
                }
            };
        let request_id = match command.request_id() {
            Ok(request_id) => request_id,
            Err(_) => {
                return roster_terminal_mutation_rejected(
                    SessionConsumerRosterRejection::Malformed,
                );
            }
        };
        // The leader path re-admits the exact scope. Release the local guard
        // before entering it so this one terminal proposal cannot self-block.
        drop(scope_guard);
        #[cfg(test)]
        ROSTER_INGRESS_TERMINAL_SUBMISSION_COUNT.fetch_add(1, Ordering::Relaxed);
        match self
            .store
            .submit_request_before(
                request_id,
                SessionMutationIntent::RosterTerminal(Box::new(command)),
                Some(scope.consensus_identity()),
                deadline,
            )
            .await
        {
            Ok(response) => match response.result {
                Ok(SessionMutationOutcome::RosterTerminal(outcome)) => match outcome {
                    ConsensusRosterTerminalOutcome::Committed { .. } => {
                        let encoded = if outcome.is_replayed() {
                            encode_terminal_replayed_bytes_response(
                                scope,
                                outcome.committed_bytes().unwrap_or_default().to_vec(),
                            )
                        } else {
                            encode_terminal_terminalized_bytes_response(
                                scope,
                                outcome.committed_bytes().unwrap_or_default().to_vec(),
                            )
                        };
                        match encoded {
                            Ok(capsule) => {
                                SessionConsumerResponse::FencedMutationRosterTerminalize(
                                    SessionConsumerRosterTerminalMutationResponse::Recorded(
                                        capsule,
                                    ),
                                )
                            }
                            Err(_) => SessionConsumerResponse::FencedMutationRosterTerminalize(
                                SessionConsumerRosterTerminalMutationResponse::OutcomeUnknown,
                            ),
                        }
                    }
                    ConsensusRosterTerminalOutcome::Compacted { .. } => {
                        match outcome.compacted_parts() {
                            Ok(Some((history_epoch, tombstone))) => {
                                match encode_terminal_compacted_response(
                                    scope,
                                    history_epoch,
                                    tombstone,
                                ) {
                                    Ok(capsule) => {
                                        SessionConsumerResponse::FencedMutationRosterTerminalize(
                                            SessionConsumerRosterTerminalMutationResponse::Recorded(
                                                capsule,
                                            ),
                                        )
                                    }
                                    Err(_) => {
                                        SessionConsumerResponse::FencedMutationRosterTerminalize(
                                            SessionConsumerRosterTerminalMutationResponse::OutcomeUnknown,
                                        )
                                    }
                                }
                            }
                            _ => SessionConsumerResponse::FencedMutationRosterTerminalize(
                                SessionConsumerRosterTerminalMutationResponse::OutcomeUnknown,
                            ),
                        }
                    }
                    ConsensusRosterTerminalOutcome::Rejected { rejection, .. } => {
                        roster_terminal_mutation_rejected(session_consumer_roster_rejection(
                            rejection,
                        ))
                    }
                },
                Ok(_) | Err(_) => SessionConsumerResponse::FencedMutationRosterTerminalize(
                    SessionConsumerRosterTerminalMutationResponse::OutcomeUnknown,
                ),
            },
            Err(StoreError::BackendOperationOutcomeUnavailable) => {
                SessionConsumerResponse::FencedMutationRosterTerminalize(
                    SessionConsumerRosterTerminalMutationResponse::OutcomeUnknown,
                )
            }
            Err(_) => SessionConsumerResponse::FencedMutationRosterTerminalize(
                SessionConsumerRosterTerminalMutationResponse::NotTransmitted,
            ),
        }
    }
}

#[async_trait]
impl SessionQuorumConsumer for ConsensusSessionConsumerService {
    async fn execute(
        &self,
        authorization: &SessionConsumerAuthorization,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse {
        let deadline = match self.operation_deadline() {
            Ok(deadline) => deadline,
            Err(rejection) => return SessionConsumerResponse::Rejected(rejection),
        };
        if let Err(rejection) = request.validate() {
            return SessionConsumerResponse::Rejected(rejection);
        }
        if let Err(error) = validate_consumer_operation(request.operation()) {
            return Self::semantic_validation_response(request.operation(), error);
        }
        if let Err(rejection) = authorization.authorize_operation(request.operation()) {
            return SessionConsumerResponse::Rejected(rejection);
        }
        let identity = authorization.identity();
        let admission = match self
            .store
            .admit_consumer_scope(request.scope(), deadline)
            .await
        {
            Ok(admission) => admission,
            Err(rejection) => return SessionConsumerResponse::Rejected(rejection),
        };
        // A healthy prepared CAS is the maximum-sized mutation path. Validate
        // by borrow, build its request commitment once, bind that exact value,
        // then move the sealed body directly into the consensus intent. This
        // avoids both a full `SessionConsumerOperation` clone and a second
        // request serialization/hash between binding and operation IDs.
        if matches!(
            request.operation(),
            SessionConsumerOperation::CompareAndSet { .. }
        ) {
            drop(admission);
            let request_commitment = match consumer_request_commitment(&request) {
                Ok(commitment) => commitment,
                Err(_) => {
                    return SessionConsumerResponse::Rejected(
                        SessionConsumerRejection::MalformedRequest,
                    );
                }
            };
            if let Err(error) = self
                .bind_consumer_request(identity, &request, request_commitment, deadline)
                .await
            {
                return Self::binding_failure_response(request.operation(), error);
            }
            let scope = request.scope();
            let public_request_id = request.request_id();
            let operation_request_id = derive_consumer_consensus_request_id_from_commitment(
                identity,
                request_commitment,
                0,
            );
            let SessionConsumerOperation::CompareAndSet { op } = request.into_operation() else {
                unreachable!("checked prepared CAS operation")
            };
            let result = self
                .submit_consumer_intent_with_id(
                    scope,
                    operation_request_id,
                    SessionMutationIntent::CompareAndSet(Arc::from(op)),
                    deadline,
                )
                .await
                .and_then(|response| match response.result? {
                    SessionMutationOutcome::CompareAndSet(result) => Ok(result),
                    _ => Err(StoreError::CasIdempotencyOutcomeUnavailable),
                });
            return if consumer_mutation_unknown(&result) {
                SessionConsumerResponse::OutcomeUnknown(SessionConsumerOutcomeUnknown::Mutation {
                    request_id: public_request_id,
                })
            } else {
                SessionConsumerResponse::CompareAndSet(
                    result.map_err(SessionConsumerStoreError::from),
                )
            };
        }
        let operation = request.operation().clone();
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
            let request_commitment = match consumer_request_commitment(&request) {
                Ok(commitment) => commitment,
                Err(_) => {
                    return SessionConsumerResponse::Rejected(
                        SessionConsumerRejection::MalformedRequest,
                    );
                }
            };
            if let Err(error) = self
                .bind_consumer_request(identity, &request, request_commitment, deadline)
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
                            request_commitment,
                            0,
                            SessionMutationIntent::CompareAndSet(Arc::from(op)),
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
                            request_commitment,
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
                            request_commitment,
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
                    self.execute_batch(identity, &request, request_commitment, deadline, ops)
                        .await
                }
                SessionConsumerOperation::AcquireLease { key, owner, ttl } => {
                    let result = self
                        .submit_consumer_intent(
                            identity,
                            &request,
                            request_commitment,
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
                            request_commitment,
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
                            request_commitment,
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
            SessionConsumerOperation::LeaseMutationStatus { request: retained } => {
                drop(admission);
                self.lease_mutation_status(identity, &request, *retained, deadline)
                    .await
            }
            SessionConsumerOperation::CompareAndSetStatus { request: retained } => {
                drop(admission);
                self.compare_and_set_status(identity, &request, *retained, deadline)
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
                let request_commitment = match consumer_request_commitment(&request) {
                    Ok(commitment) => commitment,
                    Err(_) => {
                        return SessionConsumerResponse::Rejected(
                            SessionConsumerRejection::MalformedRequest,
                        );
                    }
                };
                self.execute_batch(identity, &request, request_commitment, deadline, ops)
                    .await
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
            SessionConsumerOperation::FencedMutationRosterPollAdmit { .. }
            | SessionConsumerOperation::FencedMutationRosterAdmissionStatus { .. }
            | SessionConsumerOperation::FencedMutationRosterRecover { .. }
            | SessionConsumerOperation::FencedMutationRosterTerminalize { .. }
            | SessionConsumerOperation::FencedMutationRosterTerminalStatus { .. }
            | SessionConsumerOperation::FencedMutationRosterCurrentPublicationAuthority {
                ..
            } => SessionConsumerResponse::Rejected(SessionConsumerRejection::Unauthorized),
        }
    }

    async fn execute_v2(
        &self,
        authorization: &SessionConsumerAuthorization,
        request: SessionConsumerV2Request,
    ) -> SessionConsumerV2Response {
        let deadline = match self.operation_deadline() {
            Ok(deadline) => deadline,
            Err(rejection) => return SessionConsumerV2Response::Rejected(rejection),
        };
        if request.validate().is_err() {
            return SessionConsumerV2Response::Rejected(SessionConsumerRejection::MalformedRequest);
        }
        if let Err(rejection) = authorization.authorize_v2_operation(request.operation()) {
            return SessionConsumerV2Response::Rejected(rejection);
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
        _authorization: &SessionConsumerAuthorization,
        _scope: SessionConsumerScope,
        _start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    > {
        // The replication sequence is global. Opening this stream for a
        // scoped consumer would expose foreign-tenant activity through cursor
        // progression and event timing, even if every item were removed.
        Err(SessionConsumerRejection::Unauthorized)
    }
}

#[async_trait]
impl SessionQuorumRosterIngress for ConsensusSessionConsumerService {
    fn expected_roster_attestation_trust_root_identity(
        &self,
    ) -> Option<crate::fenced_mutation_roster::RosterAttestationTrustRootIdentityV1> {
        self.roster_expected_root().map(|root| root.identity())
    }

    fn prepare_compact_admission_provenance_input(
        &self,
        authorization: &SessionConsumerRosterAuthorization,
        request: &SessionConsumerRequest,
        attestation: &RosterIngressAttestationV1,
        certificate_subject_identity_commitment: [u8; 32],
    ) -> Result<RosterCompactAdmissionProvenanceSigningInputV2, SessionConsumerRosterRejection>
    {
        let operation = request.operation();
        let SessionConsumerOperation::FencedMutationRosterPollAdmit { request: capsule } =
            operation
        else {
            return Err(SessionConsumerRosterRejection::Capability);
        };
        if request.validate().is_err() || validate_consumer_operation(operation).is_err() {
            return Err(SessionConsumerRosterRejection::Malformed);
        }
        let (operation_tag, capsule_digest) = session_consumer_roster_ingress_operation(operation)?;
        let root = self
            .roster_expected_root()
            .ok_or(SessionConsumerRosterRejection::Capability)?;
        let (configuration_identity, _) = self
            .store
            .current_scope()
            .map_err(|_| SessionConsumerRosterRejection::Unavailable)?;
        let expected = RosterIngressAttestationVerificationInputV1 {
            configuration_identity: &configuration_identity,
            expected_peer_identity_commitment: session_consumer_identity_commitment(
                authorization.identity(),
            ),
            expected_scope: session_consumer_roster_scope_commitment(request.scope()),
            expected_request_id: *request.request_id().as_bytes(),
            expected_operation_tag: operation_tag,
            expected_capsule_digest: capsule_digest,
        };
        attestation
            .verify_connection_binding(&root, &expected)
            .map_err(|_| SessionConsumerRosterRejection::Authority)?;
        let (admission, authority) = decode_admission_request_for_scope(capsule, request.scope())
            .and_then(|decoded| decoded.into_register_parts())
            .map_err(|_| SessionConsumerRosterRejection::Malformed)?;
        authorization
            .authorize_session_key(admission.key())
            .map_err(|_| SessionConsumerRosterRejection::Authority)?;
        RosterCompactAdmissionProvenanceSigningInputV2::for_admission(
            configuration_identity,
            &admission,
            &authority,
            attestation.signing_input(),
            certificate_subject_identity_commitment,
        )
        .map_err(|_| SessionConsumerRosterRejection::Malformed)
    }

    async fn execute_roster_ingress(
        &self,
        authorization: &SessionConsumerRosterAuthorization,
        request: SessionConsumerRequest,
        attestation: RosterIngressAttestationV1,
        admission_provenance: Option<RosterCompactAdmissionProvenanceV2>,
    ) -> SessionConsumerResponse {
        let operation = request.operation().clone();
        let ingress_kind = match &operation {
            SessionConsumerOperation::FencedMutationRosterPollAdmit { .. } => 1_u8,
            SessionConsumerOperation::FencedMutationRosterAdmissionStatus { .. } => 2,
            SessionConsumerOperation::FencedMutationRosterRecover { .. } => 3,
            SessionConsumerOperation::FencedMutationRosterTerminalize { .. } => 4,
            SessionConsumerOperation::FencedMutationRosterTerminalStatus { .. } => 5,
            SessionConsumerOperation::FencedMutationRosterCurrentPublicationAuthority {
                ..
            } => 6,
            _ => 0,
        };
        let admission_response = |rejection| roster_admission_mutation_rejected(rejection);
        let admission_read_response =
            |recovery, rejection| roster_admission_read_rejected(recovery, rejection);
        let terminal_response = |rejection| roster_terminal_mutation_rejected(rejection);
        let terminal_read_response = |rejection| roster_terminal_read_rejected(rejection);
        let current_authority_response = || roster_current_publication_authority_rejected();

        let rejection_response = |rejection| match ingress_kind {
            1 => admission_response(rejection),
            2 => admission_read_response(false, rejection),
            3 => admission_read_response(true, rejection),
            4 => terminal_response(rejection),
            5 => terminal_read_response(rejection),
            6 => current_authority_response(),
            _ => SessionConsumerResponse::Rejected(SessionConsumerRejection::Unauthorized),
        };

        if (ingress_kind == 1) != admission_provenance.is_some() {
            return rejection_response(SessionConsumerRosterRejection::Malformed);
        }

        let deadline = match self.operation_deadline() {
            Ok(deadline) => deadline,
            Err(_) => return rejection_response(SessionConsumerRosterRejection::Unavailable),
        };
        if request.validate().is_err() || validate_consumer_operation(&operation).is_err() {
            return rejection_response(SessionConsumerRosterRejection::Malformed);
        }
        let (operation_tag, capsule_digest) =
            match session_consumer_roster_ingress_operation(&operation) {
                Ok(value) => value,
                Err(rejection) => return rejection_response(rejection),
            };
        let Some(root) = self.roster_expected_root() else {
            return rejection_response(SessionConsumerRosterRejection::Capability);
        };
        let (configuration_identity, _) = match self.store.current_scope() {
            Ok(scope) => scope,
            Err(_) => return rejection_response(SessionConsumerRosterRejection::Unavailable),
        };
        let expected = RosterIngressAttestationVerificationInputV1 {
            configuration_identity: &configuration_identity,
            expected_peer_identity_commitment: session_consumer_identity_commitment(
                authorization.identity(),
            ),
            expected_scope: session_consumer_roster_scope_commitment(request.scope()),
            expected_request_id: *request.request_id().as_bytes(),
            expected_operation_tag: operation_tag,
            expected_capsule_digest: capsule_digest,
        };
        // This must precede all opaque capsule decoding and all backend
        // lookups: the attestation is the only authority for this ingress.
        if attestation
            .verify_connection_binding(&root, &expected)
            .is_err()
        {
            return rejection_response(SessionConsumerRosterRejection::Authority);
        }

        match operation {
            SessionConsumerOperation::FencedMutationRosterPollAdmit { request: capsule } => {
                let (admission, authority) =
                    match decode_admission_request_for_scope(&capsule, request.scope())
                        .and_then(|decoded| decoded.into_register_parts())
                    {
                        Ok(parts) => parts,
                        Err(_) => {
                            return admission_response(SessionConsumerRosterRejection::Malformed);
                        }
                    };
                let admission_provenance = admission_provenance
                    .as_ref()
                    .expect("admission provenance presence checked before dispatch");
                if authorization
                    .authorize_session_key(admission.key())
                    .is_err()
                {
                    return admission_response(SessionConsumerRosterRejection::Authority);
                }
                let binding = match admission.binding_key(1) {
                    Ok(binding) => binding,
                    Err(_) => return admission_response(SessionConsumerRosterRejection::Malformed),
                };
                if verify_compact_admission_provenance_v2(
                    CompactAdmissionProvenanceVerificationV2 {
                        root: &root,
                        configuration_identity,
                        binding,
                        admission: &admission,
                        original_authority: &authority,
                        ingress: attestation.signing_input(),
                        provenance: admission_provenance,
                    },
                )
                .is_err()
                {
                    return admission_response(SessionConsumerRosterRejection::Authority);
                }
                // A roster admission is permitted only after the reusable
                // immutable exact-voter profile certificate exists. This is
                // read-only at ingress: deployment/startup activation owns
                // the separate quorum transaction, so a fresh roster still
                // has exactly Admission then Terminal mutations.
                if self
                    .store
                    .require_protected_roster_profile_activation_before(deadline)
                    .await
                    .is_err()
                {
                    return admission_response(SessionConsumerRosterRejection::Capability);
                }
                let admission_guard = match self
                    .store
                    .admit_consumer_scope(request.scope(), deadline)
                    .await
                {
                    Ok(guard) => guard,
                    Err(_) => return admission_response(SessionConsumerRosterRejection::Authority),
                };
                // Never carry the local topology read lock into leader
                // forwarding; a queued topology writer would otherwise be
                // able to self-block this request.
                drop(admission_guard);
                let command = match ConsensusRosterAdmissionCommand::new_with_provenance_and_ingress_request_id(
                    admission.clone(),
                    authority,
                    *request.request_id().as_bytes(),
                    attestation,
                    admission_provenance.clone(),
                ) {
                    Ok(command) => command,
                    Err(_) => return admission_response(SessionConsumerRosterRejection::Malformed),
                };
                let consensus_request_id = match command.request_id() {
                    Ok(request_id) => request_id,
                    Err(_) => return admission_response(SessionConsumerRosterRejection::Malformed),
                };
                #[cfg(test)]
                ROSTER_INGRESS_ADMISSION_SUBMISSION_COUNT.fetch_add(1, Ordering::Relaxed);
                match self
                    .store
                    .submit_request_before(
                        consensus_request_id,
                        SessionMutationIntent::RosterAdmission(Box::new(command.clone())),
                        Some(request.scope().consensus_identity()),
                        deadline,
                    )
                    .await
                {
                    Ok(response) => {
                        let response_raft_log_index = response.raft_log_index;
                        match response.result {
                            Ok(SessionMutationOutcome::RosterAdmission(
                                ConsensusRosterAdmissionOutcome::Admitted {
                                    registration_handle,
                                    registration_request_id,
                                    ..
                                },
                            )) => {
                                let result = match roster_admission_ingress_disposition(
                                    registration_request_id.history_epoch(),
                                    response_raft_log_index,
                                ) {
                                    Ok(RosterAdmissionIngressDisposition::Fresh) => {
                                        crate::fenced_mutation_roster_executor::BackendRegistration::from_consensus_parts(
                                            registration_handle,
                                            registration_request_id,
                                            &admission,
                                        )
                                        .map_err(|_| ())
                                        .and_then(|registration| {
                                            encode_admission_fresh_response(
                                                request.scope(),
                                                registration,
                                                admission_provenance,
                                            )
                                            .map_err(|_| ())
                                        })
                                    }
                                    Ok(RosterAdmissionIngressDisposition::Replayed) => {
                                        encode_admission_replayed_response(request.scope())
                                            .map_err(|_| ())
                                    }
                                    Err(()) => Err(()),
                                };
                                match result {
                                    Ok(capsule) => SessionConsumerResponse::FencedMutationRosterPollAdmit(
                                        SessionConsumerRosterAdmissionMutationResponse::Recorded(capsule),
                                    ),
                                    Err(_) => SessionConsumerResponse::FencedMutationRosterPollAdmit(
                                        SessionConsumerRosterAdmissionMutationResponse::OutcomeUnknown,
                                    ),
                                }
                            }
                            Ok(SessionMutationOutcome::RosterAdmission(
                                ConsensusRosterAdmissionOutcome::Replayed { .. },
                            )) => match encode_admission_replayed_response(request.scope()) {
                                Ok(capsule) => {
                                    SessionConsumerResponse::FencedMutationRosterPollAdmit(
                                        SessionConsumerRosterAdmissionMutationResponse::Recorded(
                                            capsule,
                                        ),
                                    )
                                }
                                Err(_) => SessionConsumerResponse::FencedMutationRosterPollAdmit(
                                    SessionConsumerRosterAdmissionMutationResponse::OutcomeUnknown,
                                ),
                            },
                            Ok(SessionMutationOutcome::RosterAdmission(
                                ConsensusRosterAdmissionOutcome::Rejected { rejection, .. },
                            )) => admission_response(session_consumer_roster_rejection(rejection)),
                            Ok(_) | Err(_) => {
                                SessionConsumerResponse::FencedMutationRosterPollAdmit(
                                    SessionConsumerRosterAdmissionMutationResponse::OutcomeUnknown,
                                )
                            }
                        }
                    }
                    Err(StoreError::BackendOperationOutcomeUnavailable) => {
                        SessionConsumerResponse::FencedMutationRosterPollAdmit(
                            SessionConsumerRosterAdmissionMutationResponse::OutcomeUnknown,
                        )
                    }
                    Err(_) => SessionConsumerResponse::FencedMutationRosterPollAdmit(
                        SessionConsumerRosterAdmissionMutationResponse::NotTransmitted,
                    ),
                }
            }
            SessionConsumerOperation::FencedMutationRosterAdmissionStatus { request: capsule }
            | SessionConsumerOperation::FencedMutationRosterRecover { request: capsule } => {
                let recovery = ingress_kind == 3;
                let decoded = match decode_admission_request_for_scope(&capsule, request.scope()) {
                    Ok(decoded) => decoded,
                    Err(_) => {
                        return admission_read_response(
                            recovery,
                            SessionConsumerRosterRejection::Malformed,
                        );
                    }
                };
                let read = if recovery {
                    match decoded.into_recovery() {
                        Ok(recovery_request) => {
                            if authorization
                                .authorize_session_key(recovery_request.authority().key())
                                .is_err()
                            {
                                return admission_read_response(
                                    true,
                                    SessionConsumerRosterRejection::Authority,
                                );
                            }
                            RosterAdmissionRead::Recovery(Box::new(recovery_request))
                        }
                        Err(_) => {
                            return admission_read_response(
                                true,
                                SessionConsumerRosterRejection::Malformed,
                            );
                        }
                    }
                } else {
                    match decoded.into_register_parts() {
                        Ok((admission, authority)) => {
                            if authorization
                                .authorize_session_key(admission.key())
                                .is_err()
                            {
                                return admission_read_response(
                                    false,
                                    SessionConsumerRosterRejection::Authority,
                                );
                            }
                            RosterAdmissionRead::Status(Box::new((admission, authority)))
                        }
                        Err(_) => {
                            return admission_read_response(
                                false,
                                SessionConsumerRosterRejection::Malformed,
                            );
                        }
                    }
                };
                let initial_guard = match self
                    .store
                    .admit_consumer_scope(request.scope(), deadline)
                    .await
                {
                    Ok(guard) => guard,
                    Err(_) => {
                        return admission_read_response(
                            recovery,
                            SessionConsumerRosterRejection::Authority,
                        );
                    }
                };
                drop(initial_guard);
                if let Err(error) = self.store.linearizable_barrier_before(deadline).await {
                    return admission_read_response(
                        recovery,
                        match error {
                            LinearizableBarrierFailure::RecoveryRequired => {
                                SessionConsumerRosterRejection::RecoveryRequired
                            }
                            _ => SessionConsumerRosterRejection::Unavailable,
                        },
                    );
                }
                let _post_barrier_guard = match self
                    .store
                    .admit_consumer_scope(request.scope(), deadline)
                    .await
                {
                    Ok(guard) => guard,
                    Err(_) => {
                        return admission_read_response(
                            recovery,
                            SessionConsumerRosterRejection::Authority,
                        );
                    }
                };
                let wall_time_floor = self.store.inner.clock.now_utc();
                let result = match read {
                    RosterAdmissionRead::Status(admission) => {
                        let (admission, authority) = *admission;
                        self.store
                            .inner
                            .backend
                            .consensus_protected_roster_admission_status(
                                self.store.inner.storage_identity,
                                admission,
                                authority,
                                wall_time_floor,
                            )
                            .await
                    }
                    RosterAdmissionRead::Recovery(recovery_request) => {
                        self.store
                            .inner
                            .backend
                            .consensus_protected_roster_recovery(
                                self.store.inner.storage_identity,
                                *recovery_request,
                                wall_time_floor,
                            )
                            .await
                    }
                };
                let (read, authority_time) = match result {
                    Ok(read) => read,
                    Err(error) => {
                        return admission_read_response(recovery, roster_store_rejection(&error));
                    }
                };
                // The backend selected both this state image and its current
                // consensus time under one lock. Re-check the ingress proof at
                // that exact effective time before exposing any protected
                // admission, plan, checkpoint, or result bytes.
                if attestation
                    .verify(&root, &expected, authority_time)
                    .is_err()
                {
                    return admission_read_response(
                        recovery,
                        SessionConsumerRosterRejection::Authority,
                    );
                }
                if self
                    .store
                    .require_application_traffic_authority_before(deadline)
                    .await
                    .is_err()
                {
                    return admission_read_response(
                        recovery,
                        SessionConsumerRosterRejection::Authority,
                    );
                }
                self.roster_read_response(request.scope(), read, recovery)
            }
            SessionConsumerOperation::FencedMutationRosterTerminalize { request: capsule }
            | SessionConsumerOperation::FencedMutationRosterTerminalStatus { request: capsule } => {
                let terminalize = ingress_kind == 4;
                let decoded = match decode_terminal_request_for_scope(&capsule, request.scope()) {
                    Ok(decoded) => decoded,
                    Err(_) => return rejection_response(SessionConsumerRosterRejection::Malformed),
                };
                if authorization
                    .authorize_session_key(decoded.authority().key())
                    .is_err()
                {
                    return rejection_response(SessionConsumerRosterRejection::Authority);
                }
                let initial_guard = match self
                    .store
                    .admit_consumer_scope(request.scope(), deadline)
                    .await
                {
                    Ok(guard) => guard,
                    Err(_) => return rejection_response(SessionConsumerRosterRejection::Authority),
                };
                if terminalize {
                    let authority_time = match self.roster_read_time().await {
                        Ok(time) => time,
                        Err(rejection) => return rejection_response(rejection),
                    };
                    if attestation
                        .verify(&root, &expected, authority_time)
                        .is_err()
                    {
                        return rejection_response(SessionConsumerRosterRejection::Authority);
                    }
                    return self
                        .roster_terminal_mutate(
                            request.scope(),
                            request.request_id(),
                            attestation,
                            decoded,
                            deadline,
                            initial_guard,
                        )
                        .await;
                }
                // Status is the read-only ambiguity path. It alone performs
                // a quorum barrier before consulting the exact local
                // admission/terminal projection. Fresh terminalization above
                // goes directly to its one consensus linearization point.
                drop(initial_guard);
                if let Err(error) = self.store.linearizable_barrier_before(deadline).await {
                    return rejection_response(match error {
                        LinearizableBarrierFailure::RecoveryRequired => {
                            SessionConsumerRosterRejection::RecoveryRequired
                        }
                        _ => SessionConsumerRosterRejection::Unavailable,
                    });
                }
                let post_barrier_guard = match self
                    .store
                    .admit_consumer_scope(request.scope(), deadline)
                    .await
                {
                    Ok(guard) => guard,
                    Err(_) => return rejection_response(SessionConsumerRosterRejection::Authority),
                };
                // The read barrier may wait past either the lease or ingress
                // certificate deadline. The backend combines this wall-clock
                // floor with its current persisted logical time under the
                // same lock that selects the terminal projection.
                let wall_time_floor = self.store.inner.clock.now_utc();
                let binding = decoded.binding();
                let registration = decoded.registration_parts();
                let authority = decoded.authority().clone();
                let terminal_body_commitment = match decoded.terminal_body_commitment() {
                    Ok(commitment) => commitment,
                    Err(_) => return rejection_response(SessionConsumerRosterRejection::Malformed),
                };
                let terminal_evidence = match decoded.terminal_evidence() {
                    Ok(terminal_evidence) => terminal_evidence,
                    Err(_) => return rejection_response(SessionConsumerRosterRejection::Malformed),
                };
                #[cfg(test)]
                ROSTER_INGRESS_TERMINAL_STATUS_READ_COUNT.fetch_add(1, Ordering::Relaxed);
                let read = match self
                    .store
                    .inner
                    .backend
                    .consensus_protected_roster_terminal_status(
                        self.store.inner.storage_identity,
                        binding,
                        registration,
                        authority,
                        terminal_body_commitment,
                        terminal_evidence,
                        wall_time_floor,
                    )
                    .await
                {
                    Ok(read) => read,
                    Err(error) => return rejection_response(roster_store_rejection(&error)),
                };
                let (read, authority_time) = read;
                if attestation
                    .verify(&root, &expected, authority_time)
                    .is_err()
                {
                    return rejection_response(SessionConsumerRosterRejection::Authority);
                }
                if self
                    .store
                    .require_application_traffic_authority_before(deadline)
                    .await
                    .is_err()
                {
                    return rejection_response(SessionConsumerRosterRejection::Authority);
                }
                self.roster_terminal_read(request.scope(), decoded, read, post_barrier_guard)
            }
            SessionConsumerOperation::FencedMutationRosterCurrentPublicationAuthority {
                request: capsule,
            } => {
                // A publication adapter submits only this narrow query.  The
                // client-owned fields are authenticated by the ingress first,
                // then all are compared under a fresh ReadIndex/SQLite read;
                // no existing admission/recovery/status operation is reused.
                if capsule.scope() != session_consumer_roster_scope_commitment(request.scope())
                    || authorization.authorize_session_key(capsule.key()).is_err()
                {
                    return current_authority_response();
                }
                let initial_guard = match self
                    .store
                    .admit_consumer_scope(request.scope(), deadline)
                    .await
                {
                    Ok(guard) => guard,
                    Err(_) => return current_authority_response(),
                };
                drop(initial_guard);
                if self
                    .store
                    .linearizable_barrier_before(deadline)
                    .await
                    .is_err()
                {
                    return current_authority_response();
                }
                let _post_barrier_guard = match self
                    .store
                    .admit_consumer_scope(request.scope(), deadline)
                    .await
                {
                    Ok(guard) => guard,
                    Err(_) => return current_authority_response(),
                };
                let wall_time_floor = self.store.inner.clock.now_utc();
                let authority_time = match self
                    .store
                    .inner
                    .backend
                    .consensus_protected_roster_current_publication_authority(
                        self.store.inner.storage_identity,
                        *capsule,
                        wall_time_floor,
                    )
                    .await
                {
                    Ok(time) => time,
                    Err(_) => return current_authority_response(),
                };
                // The barrier can wait through an ingress certificate or
                // traffic-authority change. Re-check both at the exact time
                // selected with the durable authority row before returning
                // an eligibility ACK to provider-local publication work.
                if attestation
                    .verify(&root, &expected, authority_time)
                    .is_err()
                    || self
                        .store
                        .require_application_traffic_authority_before(deadline)
                        .await
                        .is_err()
                {
                    return current_authority_response();
                }
                SessionConsumerResponse::FencedMutationRosterCurrentPublicationAuthority(
                    SessionConsumerRosterCurrentPublicationAuthorityReadResponse::Current,
                )
            }
            _ => SessionConsumerResponse::Rejected(SessionConsumerRejection::Unauthorized),
        }
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
        let every_request_is_self_authenticated =
            requests.iter().all(|request| request.validate().is_ok());
        let request_ids = requests
            .iter()
            .map(FencedTransitionV2Request::request_id)
            .collect::<Vec<_>>();
        let deadline = match tokio::time::Instant::now().checked_add(self.inner.operation_timeout) {
            Some(deadline) => deadline,
            None => return FencedTransitionV2Effect::NotTransmitted(consensus_unavailable()),
        };
        let route_scope = match self.public_fixed_raw_v2_warm_scope() {
            Ok(route_scope) => route_scope,
            Err(error) => return FencedTransitionV2Effect::NotTransmitted(error),
        };
        let effect = self
            .fenced_transition_v2_batch_submission_effect_before(requests, route_scope, deadline)
            .await;
        // The internal path constructs every ambiguity with the original
        // validated request set. Retain all if an implementation ever loses
        // that proof rather than deleting a subset of mappings.
        let effect = match effect {
            FencedTransitionV2Effect::OutcomeUnknown {
                request_ids: effect_ids,
            } if effect_ids == request_ids => FencedTransitionV2Effect::OutcomeUnknown {
                request_ids: effect_ids,
            },
            FencedTransitionV2Effect::OutcomeUnknown { .. } => {
                FencedTransitionV2Effect::OutcomeUnknown { request_ids }
            }
            effect => effect,
        };
        // The scope capture above is only a route hint.  Preserve it only
        // after this public invocation obtained the full definitive result;
        // a pre-transmission rejection or an ambiguous effect cannot prove
        // activation and must leave the next call on the cold path.
        if every_request_is_self_authenticated
            && matches!(&effect, FencedTransitionV2Effect::Resolved(Ok(_)))
        {
            self.seed_fixed_raw_v2_warm_route();
        }
        effect
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
            .submit_intent(SessionMutationIntent::CompareAndSet(Arc::new(op)))
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
    use std::str::FromStr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use bytes::Bytes;
    use futures_util::{FutureExt, StreamExt};
    use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload, Membership, Vote};
    use opc_consensus::{
        derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
    };
    use opc_crypto::CryptoEnvelopeV1;
    use opc_key::{
        serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyId, KeyPurpose, MemoryKeyProvider,
        SessionAad, Zeroizing, AEAD_TAG_LEN, AES_256_GCM_SIV_KEY_LEN, AES_256_GCM_SIV_NONCE_LEN,
    };
    use p256::ecdsa::{signature::hazmat::PrehashSigner, SigningKey};
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::backend::ReplicationOp;
    use crate::consumer::SessionConsumerTenantNfScope;
    use crate::fenced_mutation_roster::{
        roster_executor_evidence_commitment, stable_terminal_proof_commitment,
        verify_compact_terminal_evidence_v2, verify_executor_terminal_proof_bundle, Admission,
        AdmissionProposal, CompactTerminalEvidenceVerificationV2, EstablishedMutation,
        ExecutorTerminalProofVerification, Member, MemberOperationId, Phase, Profile,
        RequestId as RosterRequestId, RosterAttestationCertificateRoleV1,
        RosterAttestationLeafCertificatePartsV1, RosterAttestationLeafCertificateV1,
        RosterAttestationTrustRootV1, RosterCompactAdmissionProvenanceV2,
        RosterCompactTerminalEvidenceBindingV2, RosterCompactTerminalEvidenceV2,
        RosterCompactTerminalMemberProjectionV2, RosterCompactTerminalMemberProofPartsV2,
        RosterCompactTerminalMemberSigningInputV2, RosterExecutorMemberProofPartsV1,
        RosterExecutorProofBundleV1, RosterId, RosterIngressAttestationSigningInputV1,
        RosterProviderOperationV1, RosterProviderOutcomeV1, RosterProviderReceiptSigningInputV1,
        RosterTerminalAttestationSigningInputV1, Scope, TerminalRecord, FRESH_ROSTER_MEMBERS,
    };
    use crate::fenced_mutation_roster_executor::{
        AuthorityBinding, AuthorityLeaseMetadata, BackendRegistration,
    };
    use crate::model::{FenceToken, Generation, SessionKeyType, StateClass, StateType};
    use crate::record::EncryptedSessionPayload;
    use crate::sqlite::consensus::{ensure_operator_recovery_latch_sync, OperatorRecoveryLatch};
    use crate::topology::{
        QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
        ReplicaId, ReplicaTlsIdentity,
    };

    fn fixed_counter_total<const N: usize>(counters: &[u64; N]) -> u64 {
        counters.iter().copied().sum()
    }

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
        counters
            .public_raw_v2_cold_admissions
            .fetch_add(12, Ordering::Relaxed);
        counters
            .public_raw_v2_history_reads
            .fetch_add(13, Ordering::Relaxed);
        counters
            .fixed_raw_v2_acceptance_snapshots
            .fetch_add(14, Ordering::Relaxed);
        counters
            .fixed_raw_v2_proposals
            .fetch_add(15, Ordering::Relaxed);
        counters.begin_proactive_checkpoint();
        counters.complete_proactive_checkpoint(false, Duration::from_nanos(43));
        counters.observe_consensus_log_prune_signal();
        counters.begin_consensus_log_prune_worker();
        counters.begin_consensus_log_prune_turn();
        counters.complete_consensus_log_prune_turn(16, 32, true);
        counters.begin_consensus_log_prune_turn();
        counters.complete_consensus_log_prune_turn(4, 8, false);
        counters.begin_consensus_log_prune_turn();
        counters.retry_consensus_log_prune_turn();
        counters.begin_consensus_log_prune_turn();
        counters.fail_consensus_log_prune_turn();
        counters.end_consensus_log_prune_worker();

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
                public_raw_v2_cold_admissions: 12,
                public_raw_v2_history_reads: 13,
                fixed_raw_v2_acceptance_snapshots: 14,
                fixed_raw_v2_proposals: 15,
                proactive_checkpoint_attempts: 1,
                proactive_checkpoint_completed: 1,
                proactive_checkpoint_worker_high_water: 1,
                consensus_log_prune_signals: 1,
                consensus_log_prune_attempts: 4,
                consensus_log_prune_completed_turns: 2,
                consensus_log_prune_drained_turns: 1,
                consensus_log_prune_busy_retries: 1,
                consensus_log_prune_permanent_failures: 1,
                consensus_log_prune_degraded: true,
                consensus_log_prune_rows_deleted: 20,
                consensus_log_prune_encoded_bytes_deleted: 40,
                consensus_log_prune_backlog_turns: 1,
                consensus_log_prune_more_turns: 1,
                consensus_log_prune_queue_high_water: 1,
                consensus_log_prune_active_high_water: 1,
                consensus_log_prune_worker_high_water: 1,
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
        assert!(encoded.contains("fixed_raw_v2_acceptance_snapshots"));
        assert!(encoded.contains("consensus_log_prune_permanent_failures"));
        assert!(encoded.contains("consensus_log_prune_degraded"));

        let mut legacy = serde_json::to_value(snapshot).expect("encode legacy diagnostic value");
        legacy
            .as_object_mut()
            .expect("diagnostic snapshot is a JSON object")
            .remove("consensus_log_prune_degraded");
        let decoded: ConsensusStoreDiagnosticSnapshot =
            serde_json::from_value(legacy).expect("decode diagnostic snapshot without new field");
        assert!(!decoded.consensus_log_prune_degraded);
    }

    #[test]
    fn protected_roster_diagnostics_are_fixed_numeric_coherent_and_saturating() {
        let counters = ConsensusStoreDiagnosticCounters::default();
        counters.observe_protected_roster_proposal_to_applied_response(false, true, Duration::ZERO);
        counters.observe_protected_roster_proposal_to_applied_response(
            false,
            false,
            Duration::from_millis(1),
        );
        counters.observe_protected_roster_proposal_to_applied_response(
            true,
            true,
            Duration::from_millis(8),
        );
        counters.observe_protected_roster_proposal_to_applied_response(true, false, Duration::MAX);
        counters.observe_protected_roster_log_append_sqlite_commit(Duration::from_millis(2));
        counters.observe_protected_roster_state_machine_sqlite_commit(Duration::from_millis(4));
        counters.observe_protected_roster_piggyback_maintenance(2, Duration::from_millis(16));
        counters.begin_proactive_checkpoint();
        counters.complete_proactive_checkpoint(false, Duration::from_millis(32));
        counters.set_protected_roster_occupancy(
            crate::fenced_mutation_roster_storage::ProtectedRosterLedgerOccupancy {
                live_reservations: 2,
                retained_reservations: 3,
                tombstone_reservations: 5,
                history_floors: 7,
                retirement_cursors: 11,
                materialized_charge_bytes: 37,
                reserved_future_charge_bytes: 41,
            },
        );

        let snapshot = counters.protected_roster_snapshot();
        assert_eq!(snapshot.admission_applied_attached_latency_millis[0], 1);
        assert_eq!(snapshot.admission_applied_detached_latency_millis[1], 1);
        assert_eq!(snapshot.terminal_applied_attached_latency_millis[4], 1);
        assert_eq!(
            snapshot.terminal_applied_detached_latency_millis
                [PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS - 1],
            1
        );
        assert_eq!(snapshot.log_append_sqlite_commit_latency_millis[2], 1);
        assert_eq!(snapshot.state_machine_sqlite_commit_latency_millis[3], 1);
        assert_eq!(snapshot.response_path_maintenance_turns, 2);
        assert_eq!(snapshot.response_path_maintenance_latency_millis[5], 1);
        assert_eq!(snapshot.background_checkpoint_latency_millis[6], 1);
        assert_eq!(snapshot.occupancy_valid, 1);
        assert_eq!(snapshot.occupancy_generation, 2);
        assert_eq!(snapshot.live_reservations, 2);
        assert_eq!(snapshot.retained_reservations, 3);
        assert_eq!(snapshot.tombstone_reservations, 5);
        assert_eq!(snapshot.history_floors, 7);
        assert_eq!(snapshot.retirement_cursors, 11);
        assert_eq!(snapshot.materialized_charge_bytes, 37);
        assert_eq!(snapshot.reserved_future_charge_bytes, 41);

        let value = serde_json::to_value(snapshot).expect("serialize roster diagnostics");
        let object = value.as_object().expect("diagnostics object");
        let expected_keys = [
            "admission_applied_attached_latency_millis",
            "admission_applied_detached_latency_millis",
            "terminal_applied_attached_latency_millis",
            "terminal_applied_detached_latency_millis",
            "log_append_sqlite_commit_latency_millis",
            "state_machine_sqlite_commit_latency_millis",
            "response_path_maintenance_turns",
            "response_path_maintenance_latency_millis",
            "background_checkpoint_latency_millis",
            "occupancy_valid",
            "occupancy_generation",
            "live_reservations",
            "retained_reservations",
            "tombstone_reservations",
            "history_floors",
            "retirement_cursors",
            "materialized_charge_bytes",
            "reserved_future_charge_bytes",
        ];
        assert_eq!(object.len(), expected_keys.len());
        for key in expected_keys {
            let value = object.get(key).unwrap_or_else(|| panic!("missing {key}"));
            if key.ends_with("_millis") {
                let buckets = value.as_array().expect("fixed latency buckets");
                assert_eq!(buckets.len(), PROTECTED_ROSTER_DIAGNOSTIC_LATENCY_BUCKETS);
                assert!(buckets.iter().all(serde_json::Value::is_u64));
            } else {
                assert!(value.is_u64(), "{key} must be numeric");
            }
        }

        counters.protected_roster_log_append_sqlite_commit_latency_millis[0]
            .store(u64::MAX, Ordering::Relaxed);
        counters.observe_protected_roster_log_append_sqlite_commit(Duration::ZERO);
        assert_eq!(
            counters
                .protected_roster_snapshot()
                .log_append_sqlite_commit_latency_millis[0],
            u64::MAX
        );

        counters.invalidate_protected_roster_occupancy();
        let invalid = counters.protected_roster_snapshot();
        assert_eq!(invalid.occupancy_valid, 0);
        assert_eq!(invalid.occupancy_generation, 4);
        assert_eq!(invalid.live_reservations, 0);
        assert_eq!(invalid.retained_reservations, 0);
        assert_eq!(invalid.tombstone_reservations, 0);
        assert_eq!(invalid.history_floors, 0);
        assert_eq!(invalid.retirement_cursors, 0);
        assert_eq!(invalid.materialized_charge_bytes, 0);
        assert_eq!(invalid.reserved_future_charge_bytes, 0);
    }

    #[test]
    fn consensus_log_prune_cancellation_balances_active_and_worker_gauges_without_failure() {
        let counters = ConsensusStoreDiagnosticCounters::default();
        counters.begin_consensus_log_prune_worker();
        counters.begin_consensus_log_prune_turn();
        counters.cancel_consensus_log_prune_turn();
        counters.end_consensus_log_prune_worker();

        assert_eq!(
            counters.consensus_log_prune_active.load(Ordering::Relaxed),
            0,
            "shutdown cancellation releases the active turn admission"
        );
        assert_eq!(
            counters
                .consensus_log_prune_workers_active
                .load(Ordering::Relaxed),
            0,
            "shutdown join releases the one worker admission"
        );
        let snapshot = counters.snapshot();
        assert_eq!(snapshot.consensus_log_prune_permanent_failures, 0);
        assert_eq!(snapshot.consensus_log_prune_active_high_water, 1);
        assert_eq!(snapshot.consensus_log_prune_worker_high_water, 1);
    }
    use crate::{
        FencedTransitionLease, FencedTransitionMutation, FencedTransitionMutationResult,
        FencedTransitionOutcome, FencedTransitionRequestId, FencedTransitionV2CallerNonce,
        FencedTransitionV2HistoryEpoch, FencedTransitionV2Request, FencedTransitionV2Status,
        OwnerId, SessionConsensusClusterId, SessionConsensusConfigurationId,
        SessionConsumerAuthorizationGrant, SessionConsumerRequestId,
    };
    use opc_types::{NetworkFunctionKind, SpiffeId, TenantId};

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

    const TEST_ADMISSION_REQUEST_MAGIC: [u8; 8] = *b"OPCRPA1\0";
    const TEST_TERMINAL_REQUEST_MAGIC: [u8; 8] = *b"OPCRPT1\0";
    const TEST_ADMISSION_RESPONSE_MAGIC: [u8; 8] = *b"OPCRPS1\0";
    const TEST_ADMISSION_REQUEST_DOMAIN: &[u8] =
        b"openpacketcore/protected-roster/admission-port/request/v1\0";
    const TEST_TERMINAL_REQUEST_DOMAIN: &[u8] =
        b"openpacketcore/protected-roster/terminal-port/request/v1\0";
    const TEST_ADMISSION_RESPONSE_DOMAIN: &[u8] =
        b"openpacketcore/protected-roster/admission-port/response/v1\0";

    #[derive(Serialize)]
    struct RosterIngressAuthorityWire {
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        credential_id: u64,
        generation: Generation,
        acquired_at: Timestamp,
        expires_at: Timestamp,
    }

    impl From<&AuthorityBinding> for RosterIngressAuthorityWire {
        fn from(authority: &AuthorityBinding) -> Self {
            Self {
                key: authority.key().clone(),
                owner: authority.owner().clone(),
                fence: authority.fence(),
                credential_id: authority.credential_id(),
                generation: authority.generation(),
                acquired_at: authority.acquired_at(),
                expires_at: authority.expires_at(),
            }
        }
    }

    #[derive(Clone, Deserialize, Serialize)]
    struct RosterIngressRegistrationWire {
        handle: [u8; 32],
        request_id: RosterRequestId,
        terminal_slot: [u8; 32],
    }

    impl From<BackendRegistration> for RosterIngressRegistrationWire {
        fn from(registration: BackendRegistration) -> Self {
            let (handle, request_id, terminal_slot) = registration.consensus_parts();
            Self {
                handle,
                request_id,
                terminal_slot: *terminal_slot.as_bytes(),
            }
        }
    }

    impl RosterIngressRegistrationWire {
        fn registration(&self, admission: &Admission) -> BackendRegistration {
            BackendRegistration::from_consensus_parts(self.handle, self.request_id, admission)
                .expect("registration from admission response")
        }
    }

    #[derive(Serialize)]
    enum RosterIngressAdmissionRequestWire {
        Register {
            scope: [u8; 32],
            admission: Vec<u8>,
            authority: RosterIngressAuthorityWire,
        },
    }

    #[allow(
        dead_code,
        reason = "the test decoder must preserve every production response discriminant"
    )]
    #[derive(Deserialize)]
    enum RosterIngressAdmissionResponseWire {
        Fresh {
            scope: [u8; 32],
            registration: RosterIngressRegistrationWire,
            admission_provenance: Vec<u8>,
        },
        Replayed {
            scope: [u8; 32],
        },
        PollAdmitted {
            scope: [u8; 32],
            registration: RosterIngressRegistrationWire,
            admission: Vec<u8>,
            admission_provenance: Vec<u8>,
        },
        Terminal {
            scope: [u8; 32],
            registration: RosterIngressRegistrationWire,
            admission: Vec<u8>,
            committed: Vec<u8>,
            admission_provenance: Vec<u8>,
        },
        Compacted {
            scope: [u8; 32],
            history_epoch: u64,
            tombstone: Vec<u8>,
        },
        Reject {
            scope: [u8; 32],
            rejection: crate::consumer::SessionConsumerRosterRejection,
        },
    }

    #[derive(Serialize)]
    struct RosterIngressTerminalRequestWire {
        scope: [u8; 32],
        binding: crate::fenced_mutation_roster::RequestBindingKey,
        registration: RosterIngressRegistrationWire,
        authority: RosterIngressAuthorityWire,
        record: Vec<u8>,
        proof_bundle: Vec<u8>,
        terminal_evidence: Vec<u8>,
    }

    fn admission_capsule(
        scope: Scope,
        admission: &Admission,
        authority: &AuthorityBinding,
    ) -> crate::consumer::SessionConsumerRosterAdmissionCapsule {
        let wire = RosterIngressAdmissionRequestWire::Register {
            scope: scope.digest(),
            admission: admission.to_canonical_bytes().expect("admission bytes"),
            authority: authority.into(),
        };
        crate::consumer::SessionConsumerRosterAdmissionCapsule::new(
            crate::fenced_mutation_roster::encode_frame(
                TEST_ADMISSION_REQUEST_MAGIC,
                TEST_ADMISSION_REQUEST_DOMAIN,
                &wire,
                crate::fenced_mutation_roster_transport::MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
            )
            .expect("admission frame"),
        )
        .expect("admission capsule")
    }

    struct TerminalCapsuleInput<'a> {
        scope: Scope,
        binding: crate::fenced_mutation_roster::RequestBindingKey,
        registration: BackendRegistration,
        authority: &'a AuthorityBinding,
        terminal: &'a TerminalRecord,
        admission: &'a Admission,
        proof_bundle: &'a RosterExecutorProofBundleV1,
        terminal_evidence: &'a RosterCompactTerminalEvidenceV2,
    }

    fn terminal_capsule(
        input: TerminalCapsuleInput<'_>,
    ) -> crate::consumer::SessionConsumerRosterTerminalCapsule {
        let TerminalCapsuleInput {
            scope,
            binding,
            registration,
            authority,
            terminal,
            admission,
            proof_bundle,
            terminal_evidence,
        } = input;
        let wire = RosterIngressTerminalRequestWire {
            scope: scope.digest(),
            binding,
            registration: registration.into(),
            authority: authority.into(),
            record: terminal
                .to_canonical_bytes(admission)
                .expect("terminal bytes"),
            proof_bundle: proof_bundle.canonical_bytes().expect("proof bundle bytes"),
            terminal_evidence: terminal_evidence
                .canonical_bytes()
                .expect("compact terminal evidence bytes"),
        };
        crate::consumer::SessionConsumerRosterTerminalCapsule::new(
            crate::fenced_mutation_roster::encode_frame(
                TEST_TERMINAL_REQUEST_MAGIC,
                TEST_TERMINAL_REQUEST_DOMAIN,
                &wire,
                crate::fenced_mutation_roster_transport::MAX_PROTECTED_ROSTER_TERMINAL_CAPSULE_BYTES,
            )
            .expect("terminal frame"),
        )
        .expect("terminal capsule")
    }

    struct RosterIngressTestIssuer {
        root: RosterAttestationTrustRootV1,
        root_key: SigningKey,
        ingress_key: SigningKey,
        executor_key: SigningKey,
        identity: SessionConsensusIdentity,
        valid_from: Timestamp,
        valid_until: Timestamp,
    }

    struct RosterIngressTestInput {
        peer_identity_commitment: [u8; 32],
        scope: [u8; 32],
        request_id: SessionConsumerRequestId,
        operation_tag: u8,
        capsule: [u8; 32],
        authenticated_at: Timestamp,
        material_generation: u64,
        handshake_epoch: u64,
    }

    fn roster_ingress_test_root() -> RosterAttestationTrustRootV1 {
        let root_key = SigningKey::from_bytes((&[0x41; 32]).into()).expect("root key");
        RosterAttestationTrustRootV1::new(
            [0x42; 32],
            compressed_roster_test_key(root_key.verifying_key()),
        )
        .expect("trust root")
    }

    impl RosterIngressTestIssuer {
        fn new(
            identity: SessionConsensusIdentity,
            valid_from: Timestamp,
            valid_until: Timestamp,
        ) -> Self {
            let root_key = SigningKey::from_bytes((&[0x41; 32]).into()).expect("root key");
            Self {
                root: roster_ingress_test_root(),
                root_key,
                ingress_key: SigningKey::from_bytes((&[0x43; 32]).into()).expect("ingress key"),
                executor_key: SigningKey::from_bytes((&[0x44; 32]).into()).expect("executor key"),
                identity,
                valid_from,
                valid_until,
            }
        }

        fn certificate(
            &self,
            role: RosterAttestationCertificateRoleV1,
            scope: [u8; 32],
            subject_identity_commitment: [u8; 32],
            key_id: [u8; 32],
            public_key: &p256::ecdsa::VerifyingKey,
        ) -> RosterAttestationLeafCertificatePartsV1 {
            let mut certificate = RosterAttestationLeafCertificatePartsV1 {
                root_id: self.root.root_id(),
                role,
                configuration_identity: self.identity,
                scope,
                subject_identity_commitment,
                leaf_epoch: 1,
                key_id,
                not_before: self.valid_from,
                not_after: self.valid_until,
                public_key: compressed_roster_test_key(public_key),
                root_signature: [0; 64],
            };
            certificate.root_signature = sign_roster_test_digest(
                &self.root_key,
                RosterAttestationLeafCertificateV1::signing_digest(&certificate)
                    .expect("certificate digest"),
            );
            certificate
        }

        fn ingress(
            &self,
            peer_identity_commitment: [u8; 32],
            scope: [u8; 32],
            request_id: SessionConsumerRequestId,
            operation_tag: u8,
            capsule: [u8; 32],
        ) -> RosterIngressAttestationV1 {
            self.ingress_with_metadata(RosterIngressTestInput {
                peer_identity_commitment,
                scope,
                request_id,
                operation_tag,
                capsule,
                authenticated_at: self.valid_from,
                material_generation: 1,
                handshake_epoch: 1,
            })
        }

        fn ingress_with_metadata(
            &self,
            input: RosterIngressTestInput,
        ) -> RosterIngressAttestationV1 {
            let RosterIngressTestInput {
                peer_identity_commitment,
                scope,
                request_id,
                operation_tag,
                capsule,
                authenticated_at,
                material_generation,
                handshake_epoch,
            } = input;
            let input = RosterIngressAttestationSigningInputV1 {
                peer_identity_commitment,
                consumer_scope: scope,
                request_id: *request_id.as_bytes(),
                operation_tag,
                canonical_capsule_digest: capsule,
                authenticated_at,
                peer_certificate_expires_at: self.valid_until,
                material_generation,
                handshake_epoch,
            };
            RosterIngressAttestationV1::issue_from_signed_parts(
                &self.root,
                self.certificate(
                    RosterAttestationCertificateRoleV1::TransportIngress,
                    scope,
                    peer_identity_commitment,
                    [0x45; 32],
                    self.ingress_key.verifying_key(),
                ),
                &input,
                sign_roster_test_digest(&self.ingress_key, input.digest().expect("ingress digest")),
            )
            .expect("ingress attestation")
        }

        fn compact_admission(
            &self,
            scope: [u8; 32],
            subject_identity_commitment: [u8; 32],
            input: &RosterCompactAdmissionProvenanceSigningInputV2,
        ) -> RosterCompactAdmissionProvenanceV2 {
            RosterCompactAdmissionProvenanceV2::issue_from_signed_parts(
                &self.root,
                self.certificate(
                    RosterAttestationCertificateRoleV1::TransportIngress,
                    scope,
                    subject_identity_commitment,
                    [0x49; 32],
                    self.ingress_key.verifying_key(),
                ),
                input,
                sign_roster_test_digest(
                    &self.ingress_key,
                    input.digest().expect("compact admission digest"),
                ),
            )
            .expect("compact admission provenance")
        }

        fn terminal(
            &self,
            admission: &Admission,
            binding: crate::fenced_mutation_roster::RequestBindingKey,
            registration: BackendRegistration,
            authority: &AuthorityBinding,
            admission_provenance: &RosterCompactAdmissionProvenanceV2,
        ) -> (
            TerminalRecord,
            RosterExecutorProofBundleV1,
            RosterCompactTerminalEvidenceV2,
        ) {
            let (registration_handle, registration_request_id, registration_terminal_slot) =
                registration.consensus_parts();
            let evidence = admission
                .members()
                .iter()
                .map(|member| vec![0x46, member.ordinal()])
                .collect::<Vec<_>>();
            let commitments = admission
                .members()
                .iter()
                .zip(&evidence)
                .map(|(member, evidence)| {
                    stable_terminal_proof_commitment(
                        binding,
                        registration,
                        admission,
                        Phase::Established,
                        member,
                        RosterProviderOutcomeV1::AppliedExecuted,
                        roster_executor_evidence_commitment(evidence),
                    )
                    .expect("terminal proof commitment")
                })
                .collect();
            let terminal = TerminalRecord::new(
                admission,
                registration_request_id,
                Phase::Established,
                commitments,
            )
            .expect("terminal record");
            let proofs = admission
                .members()
                .iter()
                .zip(&evidence)
                .map(|(member, evidence)| {
                    let input = RosterTerminalAttestationSigningInputV1 {
                        profile: admission.profile(),
                        configuration_identity: self.identity,
                        certificate_subject_identity_commitment: [0x47; 32],
                        certificate_role: RosterAttestationCertificateRoleV1::Executor,
                        binding: binding.to_bytes(),
                        registration_handle,
                        registration_request_id: registration_request_id.to_bytes(),
                        registration_terminal_slot: *registration_terminal_slot.as_bytes(),
                        roster_id: *admission.roster_id().as_bytes(),
                        admission_commitment: admission.body_commitment(),
                        terminal_phase: Phase::Established,
                        terminal_body_commitment: terminal.body_commitment(),
                        ordinal: member.ordinal(),
                        member_operation_id: *member.operation_id().as_bytes(),
                        descriptor: member.descriptor().to_vec(),
                        descriptor_commitment: member.descriptor_commitment(),
                        expected_member_version: member.expected_version(),
                        admission_generation: admission.expected_generation().get(),
                        authority_scope: authority.scope().digest(),
                        authority_ingress_scope: authority.ingress_scope().digest(),
                        authority_key_canonical: authority.key().canonical_digest_input(),
                        authority_owner: authority.owner().as_str().as_bytes().to_vec(),
                        authority_fence: authority.fence().get(),
                        authority_credential_id: authority.credential_id(),
                        authority_generation: authority.generation().get(),
                        authority_acquired_at: authority.acquired_at(),
                        authority_expires_at: authority.expires_at(),
                        proof_epoch: 1,
                        provider_operation: RosterProviderOperationV1::Execute,
                        outcome: RosterProviderOutcomeV1::AppliedExecuted,
                        evidence: evidence.clone(),
                    };
                    let provider_input = RosterProviderReceiptSigningInputV1::from_terminal_input(
                        &input, [0x4a; 32],
                    )
                    .expect("provider receipt input");
                    RosterExecutorMemberProofPartsV1 {
                        ordinal: member.ordinal(),
                        provider_operation: RosterProviderOperationV1::Execute,
                        outcome: RosterProviderOutcomeV1::AppliedExecuted,
                        proof_epoch: 1,
                        evidence: input.evidence.clone(),
                        provider_certificate: self.certificate(
                            RosterAttestationCertificateRoleV1::Provider,
                            authority.ingress_scope().digest(),
                            [0x4a; 32],
                            [0x4b; 32],
                            self.executor_key.verifying_key(),
                        ),
                        provider_signature: sign_roster_test_digest(
                            &self.executor_key,
                            provider_input.digest().expect("provider receipt digest"),
                        ),
                        signature: sign_roster_test_digest(
                            &self.executor_key,
                            input.digest().expect("executor proof digest"),
                        ),
                    }
                })
                .collect();
            let proof_bundle = RosterExecutorProofBundleV1::issue_from_signed_parts(
                &self.root,
                self.certificate(
                    RosterAttestationCertificateRoleV1::Executor,
                    authority.ingress_scope().digest(),
                    [0x47; 32],
                    [0x48; 32],
                    self.executor_key.verifying_key(),
                ),
                proofs,
            )
            .expect("executor proof bundle");
            let compact_binding = RosterCompactTerminalEvidenceBindingV2::for_terminal(
                self.identity,
                binding,
                registration,
                admission_provenance,
                admission,
                authority,
                &terminal,
                [0x47; 32],
            )
            .expect("compact terminal binding");
            let compact_proofs = admission
                .members()
                .iter()
                .zip(terminal.proof_commitments())
                .zip(&evidence)
                .map(|((member, stable_proof_commitment), evidence)| {
                    let member = RosterCompactTerminalMemberProjectionV2 {
                        ordinal: member.ordinal(),
                        member_operation_id: *member.operation_id().as_bytes(),
                        descriptor_length: member.descriptor().len() as u16,
                        descriptor_commitment: member.descriptor_commitment(),
                        expected_member_version: member.expected_version(),
                        admission_generation: admission.expected_generation().get(),
                        proof_epoch: 1,
                        provider_operation: RosterProviderOperationV1::Execute,
                        outcome: RosterProviderOutcomeV1::AppliedExecuted,
                        evidence_length: evidence.len() as u16,
                        evidence_commitment: roster_executor_evidence_commitment(evidence),
                        stable_proof_commitment: *stable_proof_commitment,
                    };
                    let provider_certificate = self.certificate(
                        RosterAttestationCertificateRoleV1::Provider,
                        authority.ingress_scope().digest(),
                        [0x4a; 32],
                        [0x4b; 32],
                        self.executor_key.verifying_key(),
                    );
                    let provider = RosterAttestationLeafCertificateV1::issue_from_signed_parts(
                        &self.root,
                        provider_certificate.clone(),
                    )
                    .expect("provider certificate");
                    RosterCompactTerminalMemberProofPartsV2 {
                        provider_certificate,
                        provider_signature: sign_roster_test_digest(
                            &self.executor_key,
                            crate::fenced_mutation_roster::provider_receipt_compact_digest(
                                &compact_binding,
                                &member,
                                &provider,
                            )
                            .expect("provider receipt digest"),
                        ),
                        signature: sign_roster_test_digest(
                            &self.executor_key,
                            RosterCompactTerminalMemberSigningInputV2 {
                                binding: compact_binding.clone(),
                                member: member.clone(),
                            }
                            .digest()
                            .expect("compact terminal member digest"),
                        ),
                        member,
                    }
                })
                .collect();
            let terminal_evidence = RosterCompactTerminalEvidenceV2::issue_from_signed_parts(
                &self.root,
                self.certificate(
                    RosterAttestationCertificateRoleV1::Executor,
                    authority.ingress_scope().digest(),
                    [0x47; 32],
                    [0x48; 32],
                    self.executor_key.verifying_key(),
                ),
                &compact_binding,
                compact_proofs,
            )
            .expect("compact terminal evidence");
            (terminal, proof_bundle, terminal_evidence)
        }
    }

    fn roster_ingress_singleton_topology(
        root: RosterAttestationTrustRootV1,
    ) -> ValidatedQuorumTopology {
        let replica_id = ReplicaId::new("roster-ingress-singleton").expect("replica ID");
        let descriptor = QuorumReplicaDescriptor::new(
            replica_id.clone(),
            ReplicaEndpoint::new("roster-ingress.invalid", 7443).expect("endpoint"),
            ReplicaTlsIdentity::new("spiffe://test/session/roster-ingress").expect("TLS identity"),
            ReplicaFailureDomain::new("roster-ingress-zone").expect("failure domain"),
            ReplicaBackingIdentity::new("roster-ingress-disk").expect("backing identity"),
        );
        let cluster_id = ConsensusClusterId::new("session-roster-ingress-tests").expect("cluster");
        let epoch = ConsensusConfigurationEpoch::new(1).expect("epoch");
        let identity =
            crate::topology::derive_durable_quorum_consensus_identity_with_roster_attestation_root(
                cluster_id,
                epoch,
                &[descriptor.configuration_fingerprint()],
                Some(&root),
            );
        ValidatedQuorumTopology::try_new_consensus_lab_singleton_with_roster_attestation_trust_root(
            replica_id,
            vec![descriptor],
            identity,
            Some(root),
        )
        .expect("root-aware singleton topology")
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

    #[cfg(all(target_os = "linux", feature = "test-vfs"))]
    #[derive(Debug)]
    struct ShutdownUnavailablePeer {
        node_id: SessionConsensusNodeId,
        identity: ConsensusIdentity,
    }

    #[cfg(all(target_os = "linux", feature = "test-vfs"))]
    #[async_trait]
    impl SessionConsensusPeer for ShutdownUnavailablePeer {
        fn node_id(&self) -> SessionConsensusNodeId {
            self.node_id
        }

        fn scope_identity(&self) -> Option<ConsensusIdentity> {
            Some(self.identity)
        }

        async fn call(
            &self,
            _request: SessionConsensusWireRequest,
        ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
            Err(SessionConsensusPeerError::Unavailable)
        }
    }

    #[cfg(all(target_os = "linux", feature = "test-vfs"))]
    fn fixed_shutdown_topology() -> ValidatedQuorumTopology {
        let members = (0..3)
            .map(|index| {
                let replica_id =
                    ReplicaId::new(format!("shutdown-order-voter-{index}")).expect("replica ID");
                QuorumReplicaDescriptor::new(
                    replica_id,
                    ReplicaEndpoint::new(format!("shutdown-order-{index}.invalid"), 7443)
                        .expect("endpoint"),
                    ReplicaTlsIdentity::new(format!(
                        "spiffe://test/session/shutdown-order/{index}"
                    ))
                    .expect("TLS identity"),
                    ReplicaFailureDomain::new(format!("shutdown-order-zone-{index}"))
                        .expect("failure domain"),
                    ReplicaBackingIdentity::new(format!("shutdown-order-backing-{index}"))
                        .expect("backing identity"),
                )
            })
            .collect::<Vec<_>>();
        let cluster_id =
            ConsensusClusterId::new("session-shutdown-order-tests").expect("cluster ID");
        let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
        let placement_policy = PlacementResiliencePolicy::default();
        let fingerprints = members
            .iter()
            .map(QuorumReplicaDescriptor::configuration_fingerprint)
            .collect::<Vec<_>>();
        let identity = crate::derive_fixed_durable_quorum_consensus_identity(
            cluster_id,
            epoch,
            &fingerprints,
            placement_policy,
        );
        ValidatedQuorumTopology::try_from_fixed_durable_quorum_with_placement_policy(
            crate::topology::QuorumTopologyConfig::new_consensus(
                ReplicaId::new("shutdown-order-voter-0").expect("local replica ID"),
                members,
                identity,
            ),
            placement_policy,
        )
        .expect("fixed shutdown topology")
    }

    #[cfg(all(target_os = "linux", feature = "test-vfs"))]
    fn unavailable_fixed_shutdown_peers(
        topology: &ValidatedQuorumTopology,
    ) -> BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>> {
        let local_node_id = topology
            .local_consensus_node_id()
            .expect("fixed local node ID");
        let identity = topology.consensus_identity().expect("fixed identity");
        topology
            .members()
            .iter()
            .filter_map(|descriptor| {
                let node_id = topology.consensus_node_id(descriptor.replica_id())?;
                (node_id != local_node_id).then(|| {
                    let peer: Arc<dyn SessionConsensusPeer> =
                        Arc::new(ShutdownUnavailablePeer { node_id, identity });
                    (node_id, peer)
                })
            })
            .collect()
    }

    #[cfg(all(target_os = "linux", feature = "test-vfs"))]
    #[tokio::test]
    async fn shutdown_stops_maintenance_lanes_before_a_held_raft_shutdown_and_reopens() {
        let directory = tempfile::tempdir().expect("shutdown-order directory");
        let database_path = directory.path().join("store.sqlite");
        let snapshot_path = directory.path().join("snapshots");
        let topology = fixed_shutdown_topology();
        let backend = SqliteSessionBackend::open(&database_path).expect("file-backed backend");
        let mut checkpoint_workers = backend.proactive_checkpoint_worker_observation_for_test();
        let store = ConsensusSessionStore::open_fixed_durable_quorum(
            topology.clone(),
            backend,
            &snapshot_path,
            unavailable_fixed_shutdown_peers(&topology),
        )
        .await
        .expect("open fixed store with both maintenance lanes");

        assert!(
            store.inner.proactive_checkpoint_lane.is_some(),
            "fixed durable storage constructs the owned checkpoint lane"
        );
        assert!(
            store.inner.consensus_log_prune_lane.is_some(),
            "fixed durable storage constructs the owned physical-prune lane"
        );
        assert!(tokio::time::timeout(
            Duration::from_secs(1),
            checkpoint_workers.wait_for_worker_count(1),
        )
        .await
        .expect("checkpoint worker starts"));

        let hold = store.hold_raft_shutdown_before_core_for_test();
        let gate = Arc::clone(&hold.gate);
        let shutdown_store = store.clone();
        let shutdown = tokio::spawn(async move { shutdown_store.shutdown().await });
        assert!(
            tokio::task::spawn_blocking(move || gate.wait_until_entered(Duration::from_secs(1)))
                .await
                .expect("join Raft shutdown gate observer"),
            "the public shutdown reaches the held core phase only after both maintenance joins"
        );
        assert!(tokio::time::timeout(
            Duration::from_secs(1),
            checkpoint_workers.wait_for_worker_count(0),
        )
        .await
        .expect("checkpoint worker exits before core shutdown"));
        assert_eq!(
            store
                .inner
                .diagnostics
                .consensus_log_prune_gauges_for_test(),
            (0, 0),
            "the physical-prune turn and its sole worker join before the held core shutdown"
        );
        assert!(
            !shutdown.is_finished(),
            "the core shutdown remains held after maintenance lanes have exited"
        );

        drop(hold);
        tokio::time::timeout(Duration::from_secs(1), shutdown)
            .await
            .expect("released Raft shutdown completes")
            .expect("shutdown task completes")
            .expect("shutdown succeeds after releasing the core gate");

        // The snapshot namespace lease is exclusive for the lifetime of every
        // store clone, including handles that have completed their core
        // shutdown. Reopen only after this fixture releases its last old
        // store handle, exactly as a process restart does.
        drop(store);
        let reopened = ConsensusSessionStore::open_fixed_durable_quorum(
            topology.clone(),
            SqliteSessionBackend::open(&database_path).expect("reopen file-backed backend"),
            &snapshot_path,
            unavailable_fixed_shutdown_peers(&topology),
        )
        .await
        .expect("reopen after maintenance joins and core shutdown");
        reopened
            .shutdown()
            .await
            .expect("shut down reopened fixed store");
    }

    #[cfg(all(target_os = "linux", feature = "test-vfs"))]
    #[tokio::test]
    async fn shutdown_deadline_is_clone_wide_while_a_held_core_continues_draining() {
        let directory = tempfile::tempdir().expect("clone-wide shutdown directory");
        let database_path = directory.path().join("store.sqlite");
        let snapshot_path = directory.path().join("snapshots");
        let topology = fixed_shutdown_topology();
        let backend = SqliteSessionBackend::open(&database_path).expect("file-backed backend");
        let mut checkpoint_workers = backend.proactive_checkpoint_worker_observation_for_test();
        let store = ConsensusSessionStore::open_fixed_durable_quorum_with_clock(
            topology.clone(),
            backend,
            &snapshot_path,
            unavailable_fixed_shutdown_peers(&topology),
            Arc::new(SystemClock),
            Duration::from_millis(25),
        )
        .await
        .expect("open fixed store with bounded shutdown deadline");
        assert!(tokio::time::timeout(
            Duration::from_secs(1),
            checkpoint_workers.wait_for_worker_count(1),
        )
        .await
        .expect("checkpoint worker starts"));

        let hold = store.hold_raft_shutdown_before_core_for_test();
        let gate = Arc::clone(&hold.gate);
        let first_store = store.clone();
        let second_store = store.clone();
        let first = tokio::spawn(async move { first_store.shutdown().await });
        let second = tokio::spawn(async move { second_store.shutdown().await });
        assert!(
            tokio::task::spawn_blocking(move || gate.wait_until_entered(Duration::from_secs(1)))
                .await
                .expect("join Raft shutdown gate observer"),
            "the shared shutdown reaches the deliberately stalled core"
        );
        assert!(tokio::time::timeout(
            Duration::from_secs(1),
            checkpoint_workers.wait_for_worker_count(0),
        )
        .await
        .expect("checkpoint worker exits before either caller times out"));

        let first = tokio::time::timeout(Duration::from_secs(1), first)
            .await
            .expect("first shutdown obeys its configured deadline")
            .expect("first shutdown task completes");
        let second = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("second shutdown obeys its configured deadline")
            .expect("second shutdown task completes");
        assert_eq!(first, Err(consensus_unavailable()));
        assert_eq!(second, Err(consensus_unavailable()));
        assert_eq!(
            store
                .inner
                .diagnostics
                .consensus_log_prune_gauges_for_test(),
            (0, 0),
            "the shared background drain stops every SDK maintenance lane despite a stuck core"
        );

        drop(hold);
        tokio::time::timeout(Duration::from_secs(1), store.shutdown())
            .await
            .expect("a later clone can observe the same completed shutdown")
            .expect("released shared shutdown succeeds");
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
    fn forwarding_postcard_v711_variants_are_byte_stable_and_cross_decode() {
        let preflight = ForwardRequest::RecordExpiryPreflight {
            preflights: BoundedRecordExpiryPreflights::try_from_slice(&[])
                .expect("empty preflight is bounded"),
            required_consumer_scope: ForwardConsumerScope::Internal,
        };
        let legacy_preflight = FrozenV711ForwardRequest::RecordExpiryPreflight {
            preflights: BoundedRecordExpiryPreflights::try_from_slice(&[])
                .expect("empty legacy preflight is bounded"),
            required_consumer_scope: ForwardConsumerScope::Internal,
        };
        let current_preflight = encode_bounded(&preflight).expect("encode current preflight");
        let frozen_preflight =
            encode_bounded(&legacy_preflight).expect("encode frozen v711 preflight");
        assert_eq!(current_preflight.as_ref(), [0x01, 0x00, 0x00]);
        assert_eq!(frozen_preflight.as_ref(), [0x01, 0x00, 0x00]);
        assert!(matches!(
            decode_bounded::<FrozenV711ForwardRequest>(&current_preflight),
            Ok(FrozenV711ForwardRequest::RecordExpiryPreflight {
                preflights,
                required_consumer_scope: ForwardConsumerScope::Internal,
            }) if preflights.0.is_empty()
        ));
        assert!(matches!(
            decode_bounded::<ForwardRequest>(&frozen_preflight),
            Ok(ForwardRequest::RecordExpiryPreflight {
                preflights,
                required_consumer_scope: ForwardConsumerScope::Internal,
            }) if preflights.0.is_empty()
        ));

        let reply = ForwardMutationReply::RecordExpiryPreflight(Ok(()));
        let legacy_reply = FrozenV711ForwardMutationReply::RecordExpiryPreflight(Ok(()));
        let current_reply = encode_bounded(&reply).expect("encode current preflight reply");
        let frozen_reply = encode_bounded(&legacy_reply).expect("encode frozen preflight reply");
        assert_eq!(current_reply.as_ref(), [0x01, 0x00]);
        assert_eq!(frozen_reply.as_ref(), [0x01, 0x00]);
        assert!(matches!(
            decode_bounded::<FrozenV711ForwardMutationReply>(&current_reply),
            Ok(FrozenV711ForwardMutationReply::RecordExpiryPreflight(
                Ok(())
            ))
        ));
        assert!(matches!(
            decode_bounded::<ForwardMutationReply>(&frozen_reply),
            Ok(ForwardMutationReply::RecordExpiryPreflight(Ok(())))
        ));

        let not_leader = ForwardMutationReply::NotLeader {
            leader: Some(node(1)),
        };
        let legacy_not_leader = FrozenV711ForwardMutationReply::NotLeader {
            leader: Some(node(1)),
        };
        let current_not_leader = encode_bounded(&not_leader).expect("encode current not leader");
        let frozen_not_leader =
            encode_bounded(&legacy_not_leader).expect("encode frozen not leader");
        assert_eq!(current_not_leader.as_ref(), [0x02, 0x01, 0x01]);
        assert_eq!(frozen_not_leader.as_ref(), [0x02, 0x01, 0x01]);
        assert!(matches!(
            decode_bounded::<FrozenV711ForwardMutationReply>(&current_not_leader),
            Ok(FrozenV711ForwardMutationReply::NotLeader {
                leader: Some(leader),
            }) if leader == node(1)
        ));
        assert!(matches!(
            decode_bounded::<ForwardMutationReply>(&frozen_not_leader),
            Ok(ForwardMutationReply::NotLeader {
                leader: Some(leader),
            }) if leader == node(1)
        ));

        let mutation = ForwardMutationRequest {
            request_id: SessionConsensusRequestId::from_bytes([0xA5; 16]),
            intent: SessionMutationIntent::AdvanceLogicalTime,
            required_consumer_scope: ForwardConsumerScope::Internal,
        };
        let current_mutation =
            encode_bounded(&ForwardRequest::Mutation(mutation.clone())).expect("encode mutation");
        let frozen_mutation = encode_bounded(&FrozenV711ForwardRequest::Mutation(mutation))
            .expect("encode frozen mutation");
        assert_eq!(current_mutation.first(), Some(&0x00));
        assert_eq!(current_mutation, frozen_mutation);
        assert!(matches!(
            decode_bounded::<FrozenV711ForwardRequest>(&current_mutation),
            Ok(FrozenV711ForwardRequest::Mutation(_))
        ));
        assert!(matches!(
            decode_bounded::<ForwardRequest>(&frozen_mutation),
            Ok(ForwardRequest::Mutation(_))
        ));

        let applied = SessionConsensusResponse::rejected(consensus_unavailable());
        let current_applied =
            encode_bounded(&ForwardMutationReply::Applied(Box::new(applied.clone())))
                .expect("encode applied reply");
        let frozen_applied =
            encode_bounded(&FrozenV711ForwardMutationReply::Applied(Box::new(applied)))
                .expect("encode frozen applied reply");
        assert_eq!(current_applied.first(), Some(&0x00));
        assert_eq!(current_applied, frozen_applied);
        assert!(matches!(
            decode_bounded::<FrozenV711ForwardMutationReply>(&current_applied),
            Ok(FrozenV711ForwardMutationReply::Applied(_))
        ));
        assert!(matches!(
            decode_bounded::<ForwardMutationReply>(&frozen_applied),
            Ok(ForwardMutationReply::Applied(_))
        ));
    }

    #[test]
    fn forwarding_postcard_v711_rejects_appended_variants_without_aliasing_unavailable() {
        let ticket = ForwardRequest::FencedTransitionV2StatusLogicalTimeTicket {
            required_consumer_scope: Box::new(status_ticket_scope(1)),
        };
        let encoded_ticket = encode_bounded(&ticket).expect("encode status ticket");
        assert_eq!(encoded_ticket.first(), Some(&0x02));
        assert!(decode_bounded::<FrozenV711ForwardRequest>(&encoded_ticket).is_err());

        let encoded_unknown = encode_bounded(&ForwardMutationReply::OutcomeUnknown)
            .expect("encode terminal unknown reply");
        assert_eq!(encoded_unknown.as_ref(), [0x04]);
        assert!(decode_bounded::<FrozenV711ForwardMutationReply>(&encoded_unknown).is_err());

        let encoded_unavailable =
            encode_bounded(&ForwardMutationReply::Unavailable).expect("encode unavailable reply");
        assert_eq!(encoded_unavailable.as_ref(), [0x03]);
        assert!(matches!(
            decode_bounded::<FrozenV711ForwardMutationReply>(&encoded_unavailable),
            Ok(FrozenV711ForwardMutationReply::Unavailable)
        ));
        assert!(matches!(
            decode_bounded::<ForwardMutationReply>(
                &encode_bounded(&FrozenV711ForwardMutationReply::Unavailable)
                    .expect("encode frozen unavailable")
            ),
            Ok(ForwardMutationReply::Unavailable)
        ));
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

        let cas_intent = SessionMutationIntent::CompareAndSet(Arc::new(cas));
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
            intent: SessionMutationIntent::CompareAndSet(Arc::new(invalid_cas)),
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

    fn roster_response_admission() -> Admission {
        let proposal = AdmissionProposal::new(
            Profile::v1(),
            RosterId::from_bytes([0x71; 16]).expect("roster ID"),
            (0..FRESH_ROSTER_MEMBERS)
                .map(|ordinal| {
                    Member::new(
                        ordinal as u8,
                        MemberOperationId::from_bytes([ordinal as u8 + 1; 16])
                            .expect("member operation ID"),
                        vec![ordinal as u8 + 1],
                        1,
                    )
                    .expect("member")
                })
                .collect(),
            EstablishedMutation::no_op(),
            vec![0x72],
            vec![0x73],
            vec![0x74],
        )
        .expect("admission proposal");
        Admission::authenticate(
            proposal,
            SessionKey {
                tenant: TenantId::from_static("roster-response-tenant"),
                nf_kind: NetworkFunctionKind::smf(),
                key_type: SessionKeyType::PduSession,
                stable_id: Bytes::from_static(b"roster-response-key")
                    .try_into()
                    .expect("stable ID"),
            },
            Scope::from_digest([0x75; 32]),
            OwnerId::new("roster-response-owner").expect("owner"),
            FenceToken::new(7),
            Generation::new(3),
        )
        .expect("admission")
    }

    fn roster_response_authority(admission: &Admission) -> AuthorityBinding {
        AuthorityBinding::from_consensus_parts(
            admission.scope().digest(),
            admission.key().clone(),
            admission.logical_owner().clone(),
            admission.admission_fence(),
            AuthorityLeaseMetadata::new(
                11,
                admission.expected_generation(),
                Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
                Timestamp::from_offset_datetime(
                    time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(60),
                ),
            ),
        )
        .expect("authority")
    }

    fn roster_response_production_admission_command(
        admission: Admission,
        authority: AuthorityBinding,
    ) -> ConsensusRosterAdmissionCommand {
        let identity = singleton_topology()
            .consensus_identity()
            .expect("roster response identity");
        let issuer = RosterIngressTestIssuer::new(
            identity,
            Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
            Timestamp::from_offset_datetime(
                time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(60),
            ),
        );
        let ingress = issuer.ingress(
            [0x94; 32],
            admission.scope().digest(),
            SessionConsumerRequestId::from_bytes([0x95; 16]),
            1,
            [0x96; 32],
        );
        let provenance_input = RosterCompactAdmissionProvenanceSigningInputV2::for_admission(
            identity,
            &admission,
            &authority,
            ingress.signing_input(),
            [0x97; 32],
        )
        .expect("roster response provenance input");
        let provenance =
            issuer.compact_admission(admission.scope().digest(), [0x97; 32], &provenance_input);
        ConsensusRosterAdmissionCommand::new_with_provenance_and_ingress_request_id(
            admission,
            authority,
            ingress.request_id(),
            ingress,
            provenance,
        )
        .expect("production roster response command")
    }

    fn roster_response_authority_at_fence(admission: &Admission, fence: u64) -> AuthorityBinding {
        AuthorityBinding::from_consensus_parts(
            admission.scope().digest(),
            admission.key().clone(),
            admission.logical_owner().clone(),
            FenceToken::new(fence),
            AuthorityLeaseMetadata::new(
                11,
                admission.expected_generation(),
                Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
                Timestamp::from_offset_datetime(
                    time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(60),
                ),
            ),
        )
        .expect("authority")
    }

    fn compressed_roster_test_key(key: &p256::ecdsa::VerifyingKey) -> [u8; 33] {
        key.to_sec1_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed P-256 key")
    }

    fn sign_roster_test_digest(key: &SigningKey, digest: [u8; 32]) -> [u8; 64] {
        let signature: p256::ecdsa::Signature = key.sign_prehash(&digest).expect("sign digest");
        signature.normalize_s().to_bytes().into()
    }

    fn roster_response_proof_bundle(admission: &Admission) -> RosterExecutorProofBundleV1 {
        let root_key = SigningKey::from_bytes((&[0x31; 32]).into()).expect("root key");
        let leaf_key = SigningKey::from_bytes((&[0x32; 32]).into()).expect("leaf key");
        let identity = SessionConsensusIdentity::new(
            SessionConsensusClusterId::new("roster-matcher").expect("cluster"),
            SessionConsensusConfigurationId::from_bytes([0x41; 32]),
            SessionConsensusConfigurationEpoch::new(2).expect("epoch"),
        );
        let root = RosterAttestationTrustRootV1::new(
            [0x81; 32],
            compressed_roster_test_key(root_key.verifying_key()),
        )
        .expect("test root");
        let mut certificate = RosterAttestationLeafCertificatePartsV1 {
            root_id: root.root_id(),
            role: RosterAttestationCertificateRoleV1::Executor,
            configuration_identity: identity,
            scope: admission.scope().digest(),
            subject_identity_commitment: [0x82; 32],
            leaf_epoch: 1,
            key_id: [0x83; 32],
            not_before: Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
            not_after: Timestamp::from_offset_datetime(
                time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(60),
            ),
            public_key: compressed_roster_test_key(leaf_key.verifying_key()),
            root_signature: [0; 64],
        };
        certificate.root_signature = sign_roster_test_digest(
            &root_key,
            RosterExecutorProofBundleV1::certificate_signing_digest(&certificate)
                .expect("certificate digest"),
        );
        let mut provider_certificate = RosterAttestationLeafCertificatePartsV1 {
            root_id: root.root_id(),
            role: RosterAttestationCertificateRoleV1::Provider,
            configuration_identity: identity,
            scope: admission.scope().digest(),
            subject_identity_commitment: [0x84; 32],
            leaf_epoch: 1,
            key_id: [0x85; 32],
            not_before: Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
            not_after: Timestamp::from_offset_datetime(
                time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(60),
            ),
            public_key: compressed_roster_test_key(leaf_key.verifying_key()),
            root_signature: [0; 64],
        };
        provider_certificate.root_signature = sign_roster_test_digest(
            &root_key,
            RosterExecutorProofBundleV1::certificate_signing_digest(&provider_certificate)
                .expect("provider certificate digest"),
        );
        let proofs = admission
            .members()
            .iter()
            .map(|member| RosterExecutorMemberProofPartsV1 {
                ordinal: member.ordinal(),
                provider_operation: RosterProviderOperationV1::Execute,
                outcome: RosterProviderOutcomeV1::AppliedExecuted,
                proof_epoch: 1,
                evidence: vec![0x84, member.ordinal()],
                provider_certificate: provider_certificate.clone(),
                provider_signature: sign_roster_test_digest(
                    &leaf_key,
                    [member.ordinal().saturating_add(2); 32],
                ),
                signature: sign_roster_test_digest(
                    &leaf_key,
                    [member.ordinal().saturating_add(1); 32],
                ),
            })
            .collect();
        RosterExecutorProofBundleV1::issue_from_signed_parts(&root, certificate, proofs)
            .expect("proof bundle")
    }

    fn roster_response_terminal_command(
        admission: &Admission,
        authority: AuthorityBinding,
    ) -> ConsensusRosterTerminalCommand {
        let request_id = RosterRequestId::bind(9, admission).expect("request ID");
        let registration =
            BackendRegistration::from_consensus_parts([0x91; 32], request_id, admission)
                .expect("registration");
        let (registration_handle, registration_request_id, terminal_slot) =
            registration.consensus_parts();
        let record = TerminalRecord::new(
            admission,
            registration_request_id,
            Phase::Established,
            vec![[0x92; 32]; FRESH_ROSTER_MEMBERS],
        )
        .expect("record")
        .to_canonical_bytes(admission)
        .expect("record bytes");
        ConsensusRosterTerminalCommand::new_with_proof_bundle(
            crate::consensus::types::ConsensusRosterTerminalCommandInput {
                binding: admission
                    .binding_key(registration_request_id.history_epoch())
                    .expect("binding"),
                registration_handle,
                registration_request_id,
                registration_terminal_slot: *terminal_slot.as_bytes(),
                authority,
                record,
            },
            roster_response_proof_bundle(admission),
        )
        .expect("terminal command")
    }

    #[test]
    fn roster_append_predicate_requires_exactly_one_normal_roster_command() {
        let identity = singleton_topology()
            .consensus_identity()
            .expect("singleton consensus identity");
        let leader = node(1);
        let entry = |index, intent| Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, leader), index),
            payload: EntryPayload::Normal(SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity,
                request_id: SessionConsensusRequestId::from_bytes([index as u8; 16]),
                logical_time: Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
                intent,
            }),
        };
        let append = |entries| opc_consensus::engine::raft::AppendEntriesRequest {
            vote: Vote::new_committed(1, leader),
            prev_log_id: None,
            leader_commit: None,
            entries,
        };

        let admission = roster_response_admission();
        let admission_intent = SessionMutationIntent::RosterAdmission(Box::new(
            ConsensusRosterAdmissionCommand::new(
                admission.clone(),
                roster_response_authority(&admission),
            )
            .expect("admission command"),
        ));
        assert!(crate::consensus::raft_adapter::is_singleton_roster_append(
            &append(vec![entry(1, admission_intent),])
        ));

        let terminal_intent = SessionMutationIntent::RosterTerminal(Box::new(
            roster_response_terminal_command(&admission, roster_response_authority(&admission)),
        ));
        assert!(crate::consensus::raft_adapter::is_singleton_roster_append(
            &append(vec![entry(2, terminal_intent),])
        ));

        assert!(!crate::consensus::raft_adapter::is_singleton_roster_append(
            &append(vec![])
        ));
        assert!(!crate::consensus::raft_adapter::is_singleton_roster_append(
            &append(vec![entry(3, SessionMutationIntent::AdvanceLogicalTime),])
        ));
        let second_admission = SessionMutationIntent::RosterAdmission(Box::new(
            ConsensusRosterAdmissionCommand::new(
                admission.clone(),
                roster_response_authority(&admission),
            )
            .expect("second admission command"),
        ));
        let third_admission = SessionMutationIntent::RosterAdmission(Box::new(
            ConsensusRosterAdmissionCommand::new(
                admission.clone(),
                roster_response_authority(&admission),
            )
            .expect("third admission command"),
        ));
        assert!(!crate::consensus::raft_adapter::is_singleton_roster_append(
            &append(vec![entry(4, second_admission), entry(5, third_admission)])
        ));
        let mixed_admission = SessionMutationIntent::RosterAdmission(Box::new(
            ConsensusRosterAdmissionCommand::new(
                admission.clone(),
                roster_response_authority(&admission),
            )
            .expect("mixed admission command"),
        ));
        assert!(!crate::consensus::raft_adapter::is_singleton_roster_append(
            &append(vec![
                entry(6, mixed_admission),
                entry(7, SessionMutationIntent::AdvanceLogicalTime),
            ])
        ));
    }

    #[test]
    fn roster_admission_committed_responses_require_exact_typed_binding() {
        let admission = roster_response_admission();
        let command = roster_response_production_admission_command(
            admission.clone(),
            roster_response_authority(&admission),
        );
        let request_id = RosterRequestId::bind(9, &admission).expect("request ID");
        let registration =
            BackendRegistration::from_consensus_parts([0x81; 32], request_id, &admission)
                .expect("registration");
        let (registration_handle, registration_request_id, registration_terminal_slot) =
            registration.consensus_parts();
        let binding = admission
            .binding_key(registration_request_id.history_epoch())
            .expect("binding");
        let slot = command.admission_slot().expect("admission slot");
        let outcome_binding = command.outcome_binding().expect("outcome binding");
        let intent = SessionMutationIntent::RosterAdmission(Box::new(command));
        let committed = |result| SessionConsensusResponse {
            result,
            sequence: 1,
            digest: Some(crate::consensus::SessionConsensusEntryDigest::from_bytes(
                [0x82; 32],
            )),
            logical_time: Some(Timestamp::from_offset_datetime(
                time::OffsetDateTime::UNIX_EPOCH,
            )),
            raft_log_index: 1,
        };
        let admitted = || {
            SessionMutationOutcome::RosterAdmission(ConsensusRosterAdmissionOutcome::Admitted {
                outcome_binding,
                slot,
                binding: Box::new(binding),
                registration_handle,
                registration_request_id,
                registration_terminal_slot: *registration_terminal_slot.as_bytes(),
            })
        };

        assert!(committed_response_matches_intent(
            &intent,
            &committed(Ok(admitted()))
        ));
        assert!(committed_response_matches_intent(
            &intent,
            &committed(Ok(SessionMutationOutcome::RosterAdmission(
                ConsensusRosterAdmissionOutcome::Replayed { outcome_binding },
            ))),
        ));

        let mut wrong_slot = slot;
        wrong_slot[0] ^= 1;
        assert!(!committed_response_matches_intent(
            &intent,
            &committed(Ok(SessionMutationOutcome::RosterAdmission(
                ConsensusRosterAdmissionOutcome::Admitted {
                    outcome_binding,
                    slot: wrong_slot,
                    binding: Box::new(
                        admission
                            .binding_key(registration_request_id.history_epoch())
                            .expect("binding"),
                    ),
                    registration_handle,
                    registration_request_id,
                    registration_terminal_slot: *registration_terminal_slot.as_bytes(),
                },
            ))),
        ));
        assert!(committed_response_matches_intent(
            &intent,
            &committed(Ok(SessionMutationOutcome::RosterAdmission(
                ConsensusRosterAdmissionOutcome::Rejected {
                    outcome_binding,
                    rejection: ConsensusRosterRejection::Authority,
                },
            ))),
        ));
        let other_authority = AuthorityBinding::from_consensus_parts(
            admission.scope().digest(),
            admission.key().clone(),
            admission.logical_owner().clone(),
            admission.admission_fence(),
            AuthorityLeaseMetadata::new(
                12,
                admission.expected_generation(),
                Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
                Timestamp::from_offset_datetime(
                    time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(60),
                ),
            ),
        )
        .expect("other authority");
        let other_outcome_binding =
            roster_response_production_admission_command(admission.clone(), other_authority)
                .outcome_binding()
                .expect("other outcome binding");
        assert!(!committed_response_matches_intent(
            &intent,
            &committed(Ok(SessionMutationOutcome::RosterAdmission(
                ConsensusRosterAdmissionOutcome::Rejected {
                    outcome_binding: other_outcome_binding,
                    rejection: ConsensusRosterRejection::Authority,
                },
            ))),
        ));
        assert!(!committed_response_matches_intent(
            &intent,
            &committed(Err(StoreError::BackendUnavailable(
                "generic roster error".into(),
            ))),
        ));
        assert_eq!(
            consensus_outcome_unavailable(&intent),
            StoreError::BackendOperationOutcomeUnavailable
        );
    }

    #[test]
    fn admission_response_epoch_classification_rejects_future_registration() {
        assert_eq!(
            roster_admission_ingress_disposition(9, 9),
            Ok(RosterAdmissionIngressDisposition::Fresh),
        );
        assert_eq!(
            roster_admission_ingress_disposition(9, 10),
            Ok(RosterAdmissionIngressDisposition::Replayed),
        );
        assert_eq!(roster_admission_ingress_disposition(10, 9), Err(()));
        assert_eq!(roster_admission_ingress_disposition(0, 9), Err(()));
        assert_eq!(roster_admission_ingress_disposition(9, 0), Err(()));
    }

    #[test]
    fn roster_terminal_rejection_cannot_cross_current_authority_attempts() {
        let admission = roster_response_admission();
        let old = roster_response_terminal_command(
            &admission,
            roster_response_authority_at_fence(&admission, 7),
        );
        let newer = roster_response_terminal_command(
            &admission,
            roster_response_authority_at_fence(&admission, 8),
        );
        assert_eq!(
            old.request_id().expect("request ID"),
            newer.request_id().expect("request ID")
        );
        assert_eq!(
            old.terminal_slot().expect("slot"),
            newer.terminal_slot().expect("slot")
        );
        assert_eq!(
            old.immutable_payload_digest(),
            newer.immutable_payload_digest()
        );
        assert_ne!(
            old.exact_attempt_digest().expect("old attempt"),
            newer.exact_attempt_digest().expect("new attempt"),
        );

        let outcome =
            ConsensusRosterTerminalOutcome::rejected(&old, ConsensusRosterRejection::Authority)
                .expect("old rejection");
        let encoded = postcard::to_allocvec(&outcome).expect("outcome encoding");
        let decoded = postcard::from_bytes::<ConsensusRosterTerminalOutcome>(&encoded)
            .expect("outcome decoding");
        let response = SessionConsensusResponse {
            result: Ok(SessionMutationOutcome::RosterTerminal(decoded)),
            sequence: 1,
            digest: Some(crate::consensus::SessionConsensusEntryDigest::from_bytes(
                [0x93; 32],
            )),
            logical_time: Some(Timestamp::from_offset_datetime(
                time::OffsetDateTime::UNIX_EPOCH,
            )),
            raft_log_index: 1,
        };
        assert!(!committed_response_matches_intent(
            &SessionMutationIntent::RosterTerminal(Box::new(newer)),
            &response,
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
            intent: SessionMutationIntent::CompareAndSet(Arc::new(CompareAndSet {
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

    fn v2_test_request_with_same_id_different_body(
        request: &FencedTransitionV2Request,
    ) -> FencedTransitionV2Request {
        let altered = FencedTransitionV2Request::new(
            request.request_id().epoch(),
            request.request_id().nonce(),
            request.lease().clone(),
            FencedTransitionMutation::delete(Generation::new(2)),
        )
        .expect("altered V2 transition request");
        let original_id = serde_json::to_value(request.request_id()).expect("full V2 ID encodes");
        let mut encoded = serde_json::to_value(altered).expect("altered V2 request encodes");
        let serde_json::Value::Object(fields) = &mut encoded else {
            panic!("V2 request is an object");
        };
        fields.insert("request_id".into(), original_id);
        serde_json::from_value(encoded).expect("structural V2 body conflict decodes")
    }

    #[test]
    fn roster_mutations_require_exact_status_resolution_without_consumer_scope() {
        let admission = roster_response_admission();
        let authority = roster_response_authority(&admission);
        let mutations = [
            SessionMutationIntent::RosterAdmission(Box::new(
                roster_response_production_admission_command(admission.clone(), authority.clone()),
            )),
            SessionMutationIntent::RosterTerminal(Box::new(roster_response_terminal_command(
                &admission, authority,
            ))),
        ];

        for intent in mutations {
            let request = ForwardMutationRequest {
                request_id: SessionConsensusRequestId::new(),
                intent,
                required_consumer_scope: ForwardConsumerScope::Internal,
            };
            assert!(
                mutation_requires_exact_status_resolution(&request),
                "protected roster mutations must not reroute after transport ambiguity"
            );
        }
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

    #[tokio::test]
    async fn cold_v2_batch_activates_with_a_valid_item_and_preserves_conflict_order() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let open = |label: &'static str| async move {
            let directory = tempfile::tempdir().expect("cold conflict batch directory");
            let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
                .expect("cold conflict batch backend");
            let store = ConsensusSessionStore::open_with_clock(
                singleton_topology(),
                backend,
                directory.path().join("snapshots"),
                BTreeMap::new(),
                Arc::new(SystemClock),
                Duration::from_secs(1),
            )
            .await
            .unwrap_or_else(|_| panic!("open {label} cold conflict batch store"));
            store
                .initialize_cluster()
                .await
                .unwrap_or_else(|_| panic!("initialize {label} cold conflict batch store"));
            (directory, store)
        };
        let requests = || {
            let original = v2_test_request(1);
            let conflict = v2_test_request_with_same_id_different_body(&original);
            let valid = FencedTransitionV2Request::new(
                original.request_id().epoch(),
                FencedTransitionV2CallerNonce::from_bytes([0x52; 16]),
                original.lease().clone(),
                FencedTransitionMutation::delete(Generation::new(1)),
            )
            .expect("self-authenticated activation item");
            assert_eq!(
                conflict.validate(),
                Err(StoreError::FencedTransitionRequestConflict)
            );
            assert!(valid.validate().is_ok());
            vec![conflict, valid]
        };

        let (_directory, store) = open("public effect").await;
        let public_requests = requests();
        let public_ids = public_requests
            .iter()
            .map(FencedTransitionV2Request::request_id)
            .collect::<Vec<_>>();
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        let effect =
            SessionBackend::fenced_transition_v2_batch_effect(&store, public_requests).await;
        let FencedTransitionV2Effect::Resolved(Ok(outcomes)) = effect else {
            panic!("cold public conflict batch must resolve exactly");
        };
        assert!(matches!(
            outcomes.as_slice(),
            [
                Err(StoreError::FencedTransitionRequestConflict),
                Err(StoreError::CasConflict)
            ]
        ));
        wait_for_log_index_after(&store, before, "valid cold batch activation item").await;
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1),
            "the conflict-only suffix needs no second proposal"
        );
        assert_eq!(
            public_ids.len(),
            outcomes.len(),
            "every original caller ID retains one ordered result"
        );

        let (_directory, store, scope, identity, _key, _lease) = consumer_boundary_store().await;
        let consumer_requests = requests();
        let consumer_ids = consumer_requests
            .iter()
            .map(FencedTransitionV2Request::request_id)
            .collect::<Vec<_>>();
        let response = store
            .consumer_service()
            .execute_v2(
                &identity,
                SessionConsumerV2Request::new(
                    scope,
                    SessionConsumerV2Operation::FencedTransitionV2Batch {
                        requests: consumer_requests,
                    },
                ),
            )
            .await;
        let SessionConsumerV2Response::FencedTransitionV2Batch(Ok(results)) = response else {
            panic!("cold consumer conflict batch must resolve exactly");
        };
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].request_id(), consumer_ids[0]);
        assert_eq!(results[1].request_id(), consumer_ids[1]);
        assert_eq!(
            results[0].result(),
            &Err(SessionConsumerV2FencedTransitionError::RequestConflict)
        );
        assert_eq!(
            results[1].result(),
            &Err(SessionConsumerV2FencedTransitionError::Store(
                SessionConsumerStoreError::CasConflict,
            ))
        );
    }

    #[tokio::test]
    async fn cold_v2_batch_keeps_body_conflict_ahead_of_a_future_epoch() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let mixed_requests = |epoch: u64, valid_nonce: u8| {
            let original = v2_test_request(epoch);
            let conflict = v2_test_request_with_same_id_different_body(&original);
            let valid = FencedTransitionV2Request::new(
                original.request_id().epoch(),
                FencedTransitionV2CallerNonce::from_bytes([valid_nonce; 16]),
                original.lease().clone(),
                FencedTransitionMutation::delete(Generation::new(1)),
            )
            .expect("valid cold epoch-classification request");
            vec![conflict, valid]
        };

        let directory = tempfile::tempdir().expect("cold epoch batch directory");
        let database = directory.path().join("store.sqlite");
        let backend = SqliteSessionBackend::open(&database).expect("cold epoch batch backend");
        let store = ConsensusSessionStore::open_with_clock(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Arc::new(SystemClock),
            Duration::from_secs(1),
        )
        .await
        .expect("open cold epoch batch store");
        store
            .initialize_cluster()
            .await
            .expect("initialize cold epoch batch store");
        assert_eq!(
            store.fenced_transition_v2(v2_test_request(1)).await,
            Err(StoreError::CasConflict),
            "the deterministic initial error still binds the activation receipt",
        );
        rusqlite::Connection::open(&database)
            .expect("open public future epoch fixture")
            .execute(
                "DELETE FROM consensus_fenced_transition_v2_activation WHERE singleton = 1",
                [],
            )
            .expect("clear the public activation certificate");
        let before_future = store.inner.raft.metrics().borrow().last_log_index;
        assert!(matches!(
            SessionBackend::fenced_transition_v2_batch_effect(
                &store,
                mixed_requests(2, 0x56),
            )
            .await,
            FencedTransitionV2Effect::Resolved(Ok(outcomes))
                if matches!(outcomes.as_slice(), [
                    Err(StoreError::FencedTransitionRequestConflict),
                    Err(StoreError::FencedTransitionHistoryEpochNotActive),
                ])
        ));
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            before_future,
            "a conflict plus future epoch is fully resolved before proposal",
        );

        let (directory, consumer_store, scope, identity, _key, _lease) =
            consumer_boundary_store().await;
        assert_eq!(
            consumer_store
                .fenced_transition_v2(v2_test_request(1))
                .await,
            Err(StoreError::CasConflict),
        );
        rusqlite::Connection::open(directory.path().join("store.sqlite"))
            .expect("open consumer future epoch fixture")
            .execute(
                "DELETE FROM consensus_fenced_transition_v2_activation WHERE singleton = 1",
                [],
            )
            .expect("clear the consumer activation certificate");
        let consumer_requests = mixed_requests(2, 0x57);
        let consumer_ids = consumer_requests
            .iter()
            .map(FencedTransitionV2Request::request_id)
            .collect::<Vec<_>>();
        let response = consumer_store
            .consumer_service()
            .execute_v2(
                &identity,
                SessionConsumerV2Request::new(
                    scope,
                    SessionConsumerV2Operation::FencedTransitionV2Batch {
                        requests: consumer_requests,
                    },
                ),
            )
            .await;
        let SessionConsumerV2Response::FencedTransitionV2Batch(Ok(results)) = response else {
            panic!("cold consumer future batch must preserve per-item outcomes");
        };
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].request_id(), consumer_ids[0]);
        assert_eq!(results[1].request_id(), consumer_ids[1]);
        assert_eq!(
            results[0].result(),
            &Err(SessionConsumerV2FencedTransitionError::RequestConflict)
        );
        assert_eq!(
            results[1].result(),
            &Err(SessionConsumerV2FencedTransitionError::EpochNotActive)
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
                None,
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
        let response = |logical_time, outcomes| SessionConsensusResponse {
            result: Ok(SessionMutationOutcome::FencedTransitionV2Batch(outcomes)),
            sequence: 1,
            digest: Some(crate::consensus::SessionConsensusEntryDigest::from_bytes(
                [0xD4; 32],
            )),
            logical_time: Some(logical_time),
            raft_log_index: 1,
        };
        let requests = vec![first.clone(), second.clone()];
        let request_ids = requests
            .iter()
            .map(FencedTransitionV2Request::request_id)
            .collect::<Vec<_>>();

        let all_replay = response(
            envelope_time,
            vec![Ok(replay_first.clone()), Ok(replay_second.clone())],
        );
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
                if outcomes == vec![Ok(replay_first.clone()), Ok(replay_second.clone())]
        ));

        let mixed = response(
            envelope_time,
            vec![Ok(replay_first.clone()), Ok(fresh_second.clone())],
        );
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
                if outcomes == vec![Ok(replay_first.clone()), Ok(fresh_second)]
        ));

        let expired_replay = response(
            replay_second.retained_until(),
            vec![Ok(replay_first), Ok(replay_second)],
        );
        assert!(
            !committed_response_matches_intent(
                &SessionMutationIntent::FencedTransitionV2Batch(requests),
                &expired_replay,
            ),
            "a terminal replay cannot be accepted at its retention boundary"
        );
    }

    #[test]
    fn v2_batch_admits_retained_or_active_epoch_and_rejects_floor_or_future() {
        let retained = FencedTransitionV2HistoryEpoch::new(2).expect("retained epoch");
        let active = FencedTransitionV2HistoryEpoch::new(3).expect("active epoch");
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
            require_fenced_transition_v2_batch_history_epoch(
                &history,
                FencedTransitionV2HistoryEpoch::new(1).expect("retired request epoch"),
            ),
            Err(StoreError::FencedTransitionHistoryEpochRetired)
        );
        assert_eq!(
            require_fenced_transition_v2_batch_history_epoch(
                &history,
                FencedTransitionV2HistoryEpoch::new(4).expect("future request epoch"),
            ),
            Err(StoreError::FencedTransitionHistoryEpochNotActive)
        );
        assert_eq!(
            require_fenced_transition_v2_batch_history_epoch(&history, retained),
            Ok(())
        );
        assert_eq!(
            require_fenced_transition_v2_batch_history_epoch(&history, active),
            Ok(())
        );

        let original = v2_test_request(1);
        let conflict = v2_test_request_with_same_id_different_body(&original);
        let valid = FencedTransitionV2Request::new(
            original.request_id().epoch(),
            FencedTransitionV2CallerNonce::from_bytes([0x53; 16]),
            original.lease().clone(),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("valid epoch-classification request");
        let requests = vec![conflict, valid];
        assert!(matches!(
            fenced_transition_v2_batch_epoch_outcomes(
                &requests,
                StoreError::FencedTransitionHistoryEpochRetired,
            )
            .as_slice(),
            [
                Err(StoreError::FencedTransitionRequestConflict),
                Err(StoreError::FencedTransitionHistoryEpochRetired),
            ]
        ));
        assert!(matches!(
            fenced_transition_v2_batch_epoch_outcomes(
                &requests,
                StoreError::FencedTransitionHistoryEpochNotActive,
            )
            .as_slice(),
            [
                Err(StoreError::FencedTransitionRequestConflict),
                Err(StoreError::FencedTransitionHistoryEpochNotActive),
            ]
        ));
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
    fn protected_roster_profile_probe_and_certificate_binding_fail_closed() {
        let profile_digest = crate::fenced_mutation_roster::profile_digest();
        let single_scope_profile_digest = [
            0x1f, 0xc9, 0xe4, 0xbd, 0xaf, 0xfd, 0x17, 0x46, 0xf1, 0xaf, 0x8d, 0x21, 0xc7, 0xb7,
            0x34, 0x37, 0xc5, 0xba, 0x14, 0x22, 0x8e, 0xc4, 0x3b, 0xe4, 0xe2, 0xcf, 0x18, 0x2c,
            0x6a, 0x3d, 0xda, 0x35,
        ];
        assert_ne!(
            profile_digest, single_scope_profile_digest,
            "the successor-ingress proof format must have a distinct capability digest",
        );
        let probe = ProtectedRosterProfileCapabilityProbe {
            domain: PROTECTED_ROSTER_PROFILE_PROBE_DOMAIN_V1,
            schema_version: PROTECTED_ROSTER_PROFILE_PROBE_SCHEMA_V1,
            profile_digest,
        };
        let v1_reply = encode_bounded(&FencedTransitionCapabilityReply::V1)
            .expect("bounded V1 capability reply");
        assert!(
            decode_bounded::<ProtectedRosterProfileCapabilityReply>(&v1_reply).is_err(),
            "a V1-only voter reply cannot decode as protected-roster profile support",
        );
        assert!(matches!(
            protected_roster_profile_capability_probe_reply(
                probe,
                AtomicFencedTransitionCapability::V1,
            ),
            ProtectedRosterProfileCapabilityReply {
                domain,
                schema_version,
                outcome: ProtectedRosterProfileCapabilityOutcome::Supported {
                    profile_digest: reply,
                },
            } if domain == PROTECTED_ROSTER_PROFILE_REPLY_DOMAIN_V1
                && schema_version == PROTECTED_ROSTER_PROFILE_PROBE_SCHEMA_V1
                && reply == profile_digest
        ));
        assert_eq!(
            protected_roster_profile_capability_probe_reply(
                ProtectedRosterProfileCapabilityProbe {
                    domain: PROTECTED_ROSTER_PROFILE_PROBE_DOMAIN_V1,
                    schema_version: PROTECTED_ROSTER_PROFILE_PROBE_SCHEMA_V1,
                    profile_digest: single_scope_profile_digest,
                },
                AtomicFencedTransitionCapability::V1,
            ),
            ProtectedRosterProfileCapabilityReply {
                domain: PROTECTED_ROSTER_PROFILE_REPLY_DOMAIN_V1,
                schema_version: PROTECTED_ROSTER_PROFILE_PROBE_SCHEMA_V1,
                outcome: ProtectedRosterProfileCapabilityOutcome::Unsupported,
            },
            "a future or mixed immutable roster profile cannot be admitted",
        );
        let identity = singleton_topology()
            .consensus_identity()
            .expect("singleton identity");
        let voters = BTreeSet::from([node(1)]);
        assert_ne!(
            fenced_transition_voter_set_digest(identity, &voters),
            protected_roster_profile_voter_set_digest(identity, &voters),
            "a generic V1 activation certificate is never roster-profile evidence",
        );
    }

    #[test]
    fn protected_roster_profile_wire_authority_is_decoder_disjoint() {
        let profile_digest = crate::fenced_mutation_roster::profile_digest();
        let profile_probe = encode_bounded(&ProtectedRosterProfileCapabilityProbe {
            domain: PROTECTED_ROSTER_PROFILE_PROBE_DOMAIN_V1,
            schema_version: PROTECTED_ROSTER_PROFILE_PROBE_SCHEMA_V1,
            profile_digest,
        })
        .expect("bounded protected-roster profile probe");
        assert!(decode_bounded::<ProtectedRosterProfileCapabilityProbe>(&profile_probe).is_ok());
        assert!(decode_bounded::<ReadBarrierRequest>(&profile_probe).is_err());
        assert!(decode_bounded::<FencedTransitionCapabilityProbe>(&profile_probe).is_err());
        assert!(
            decode_bounded::<FencedTransitionActivationCapabilityProbe>(&profile_probe).is_err()
        );
        assert!(decode_bounded::<FencedTransitionV2CapabilityProbe>(&profile_probe).is_err());

        for existing_probe in [
            encode_bounded(&ReadBarrierRequest).expect("read-barrier probe"),
            encode_bounded(&FencedTransitionCapabilityProbe {
                schema_version: FENCED_TRANSITION_SCHEMA_V1,
            })
            .expect("V1 transition probe"),
            encode_bounded(&FencedTransitionActivationCapabilityProbe {
                activation_probe_schema_version: FENCED_TRANSITION_ACTIVATION_PROBE_SCHEMA_V1,
                activation_command_schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            })
            .expect("V1 activation probe"),
            encode_bounded(&FencedTransitionV2CapabilityProbe {
                schema_version: FENCED_TRANSITION_SCHEMA_V2,
                profile_digest: crate::fenced_transition::fenced_transition_v2_profile_digest(),
            })
            .expect("V2 transition probe"),
        ] {
            assert!(
                decode_bounded::<ProtectedRosterProfileCapabilityProbe>(&existing_probe).is_err(),
                "an existing read-family request cannot decode as roster-profile authority",
            );
        }

        for profile_reply in [
            encode_bounded(&ProtectedRosterProfileCapabilityReply {
                domain: PROTECTED_ROSTER_PROFILE_REPLY_DOMAIN_V1,
                schema_version: PROTECTED_ROSTER_PROFILE_PROBE_SCHEMA_V1,
                outcome: ProtectedRosterProfileCapabilityOutcome::Supported { profile_digest },
            })
            .expect("bounded supported protected-roster profile reply"),
            encode_bounded(&ProtectedRosterProfileCapabilityReply {
                domain: PROTECTED_ROSTER_PROFILE_REPLY_DOMAIN_V1,
                schema_version: PROTECTED_ROSTER_PROFILE_PROBE_SCHEMA_V1,
                outcome: ProtectedRosterProfileCapabilityOutcome::Unsupported,
            })
            .expect("bounded unsupported protected-roster profile reply"),
        ] {
            assert!(
                decode_bounded::<ProtectedRosterProfileCapabilityReply>(&profile_reply).is_ok()
            );
            assert!(decode_bounded::<ReadBarrierReply>(&profile_reply).is_err());
            assert!(decode_bounded::<FencedTransitionCapabilityReply>(&profile_reply).is_err());
            assert!(
                decode_bounded::<FencedTransitionActivationCapabilityReply>(&profile_reply)
                    .is_err()
            );
            assert!(decode_bounded::<FencedTransitionV2CapabilityReply>(&profile_reply).is_err());
        }

        for existing_reply in [
            encode_bounded(&ReadBarrierReply::Ready(None)).expect("read-barrier reply"),
            encode_bounded(&FencedTransitionCapabilityReply::V1).expect("V1 transition reply"),
            encode_bounded(&FencedTransitionCapabilityReply::Unsupported)
                .expect("unsupported V1 transition reply"),
            encode_bounded(&FencedTransitionActivationCapabilityReply::V1)
                .expect("V1 activation reply"),
            encode_bounded(&FencedTransitionActivationCapabilityReply::Unsupported)
                .expect("unsupported V1 activation reply"),
            encode_bounded(&FencedTransitionV2CapabilityReply::V2 {
                profile_digest: crate::fenced_transition::fenced_transition_v2_profile_digest(),
            })
            .expect("V2 transition reply"),
            encode_bounded(&FencedTransitionV2CapabilityReply::Unsupported)
                .expect("unsupported V2 transition reply"),
        ] {
            assert!(
                decode_bounded::<ProtectedRosterProfileCapabilityReply>(&existing_reply).is_err(),
                "an existing read-family reply cannot decode as roster-profile support",
            );
        }
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
        let mutation = SessionMutationIntent::CompareAndSet(Arc::new(CompareAndSet {
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
        let intent = SessionMutationIntent::CompareAndSet(Arc::new(CompareAndSet {
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
        SessionConsumerAuthorization,
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
        let identity = SessionConsumerIdentity::new(
            "spiffe://test.example/tenant/consumer-boundary/ns/default/sa/store/nf/smf/instance/one",
        )
            .expect("consumer boundary identity");
        // The V2 consumer cases intentionally exercise a request whose
        // retained ID/body fixture is in a second tenant. Grant that exact
        // tenant/NF pair so those cases reach the conflict and history
        // semantics; production authorization remains tenant/NF scoped.
        let v2_fixture_key = v2_test_request(1).lease().key().clone();
        let grant = SessionConsumerAuthorizationGrant::try_new(
            SpiffeId::new(identity.as_str()).expect("canonical consumer SPIFFE ID"),
            [
                SessionConsumerTenantNfScope::new(key.tenant.clone(), key.nf_kind.clone()),
                SessionConsumerTenantNfScope::new(v2_fixture_key.tenant, v2_fixture_key.nf_kind),
            ],
        )
        .expect("consumer grant");
        let manifest = store
            .consumer_authorization_manifest([grant])
            .await
            .expect("consumer authorization manifest");
        let authorization = manifest
            .authorize(&identity)
            .expect("consumer authorization");
        (directory, store, scope, authorization, key, lease)
    }

    #[tokio::test]
    #[allow(
        clippy::await_holding_lock,
        reason = "the roster-ingress call counters are process-global test evidence"
    )]
    async fn protected_roster_ingress_has_two_mutations_and_read_only_status_paths() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let directory = tempfile::tempdir().expect("roster ingress directory");
        let start = Timestamp::from_str("2025-01-01T00:00:00Z").expect("test start");
        let clock = Arc::new(MutableClock::new(start));
        let root = roster_ingress_test_root();
        let topology = roster_ingress_singleton_topology(root.clone());
        let identity = topology.consensus_identity().expect("consensus identity");
        let store = ConsensusSessionStore::open_with_clock(
            topology,
            SqliteSessionBackend::open(directory.path().join("store.sqlite"))
                .expect("roster ingress SQLite backend"),
            directory.path().join("snapshots"),
            BTreeMap::new(),
            clock.clone(),
            Duration::from_secs(1),
        )
        .await
        .expect("open roster ingress store");
        store
            .initialize_cluster()
            .await
            .expect("initialize roster ingress store");

        let key = SessionKey {
            tenant: TenantId::new("roster-ingress").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"two-mutations")
                .try_into()
                .expect("stable ID"),
        };
        let owner = OwnerId::new("roster-ingress-owner").expect("owner");
        let lease = store
            .acquire(&key, owner.clone(), Duration::from_secs(60))
            .await
            .expect("roster ingress lease");
        let initial = consumer_record_with_payload_len(&key, &lease, 1024);
        assert!(matches!(
            store
                .compare_and_set(CompareAndSet {
                    key: key.clone(),
                    lease: lease.clone(),
                    expected_generation: None,
                    new_record: initial,
                })
                .await
                .expect("write initial roster business record"),
            CompareAndSetResult::Success
        ));

        let scope = store.consumer_scope().expect("consumer scope");
        let consumer_identity = SessionConsumerIdentity::new(
            "spiffe://test.example/tenant/roster-ingress/ns/default/sa/store/nf/smf/instance/one",
        )
        .expect("consumer identity");
        let manifest = store
            .consumer_authorization_manifest([SessionConsumerAuthorizationGrant::try_new(
                SpiffeId::new(consumer_identity.as_str()).expect("consumer SPIFFE ID"),
                [SessionConsumerTenantNfScope::new(
                    key.tenant.clone(),
                    key.nf_kind.clone(),
                )],
            )
            .expect("consumer grant")])
            .await
            .expect("consumer authorization manifest");
        let authorization = manifest
            .authorize(&consumer_identity)
            .expect("consumer authorization");
        let activation_deadline = tokio::time::Instant::now()
            .checked_add(store.inner.operation_timeout)
            .expect("activation deadline");
        assert!(matches!(
            store
                .require_protected_roster_profile_activation_before(activation_deadline)
                .await,
            Err(StoreError::CapabilityNotSupported(reason))
                if reason == "protected_roster_profile_not_activated"
        ));
        store
            .activate_protected_roster_profile()
            .await
            .expect("activate immutable protected roster profile");
        let first_profile_activation_log = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .expect("profile activation log index");
        store
            .activate_protected_roster_profile()
            .await
            .expect("reuse immutable protected roster profile activation");
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(first_profile_activation_log),
            "the immutable profile certificate is reusable and does not add a roster mutation",
        );
        let roster_authorization = authorization.roster_authorization();
        let roster_scope = Scope::from_digest(session_consumer_roster_scope_commitment(scope));
        let admission = Admission::authenticate(
            AdmissionProposal::new(
                Profile::v1(),
                RosterId::from_bytes([0x51; 16]).expect("roster ID"),
                (0..FRESH_ROSTER_MEMBERS)
                    .map(|ordinal| {
                        Member::new(
                            ordinal as u8,
                            MemberOperationId::from_bytes([ordinal as u8 + 1; 16])
                                .expect("member operation ID"),
                            vec![ordinal as u8 + 1],
                            1,
                        )
                        .expect("member")
                    })
                    .collect(),
                EstablishedMutation::no_op(),
                vec![0x52],
                vec![0x53],
                vec![0x54],
            )
            .expect("admission proposal"),
            key.clone(),
            roster_scope,
            owner,
            lease.fence(),
            Generation::new(1),
        )
        .expect("admission");
        let authority = AuthorityBinding::for_admission(
            &admission,
            lease.owner().clone(),
            lease.fence(),
            AuthorityLeaseMetadata::new(
                lease.credential_id(),
                Generation::new(1),
                lease.acquired_at(),
                lease.expires_at(),
            ),
        )
        .expect("authority binding");
        let issuer = RosterIngressTestIssuer::new(
            identity,
            Timestamp::from_str("2024-12-31T23:59:59Z").expect("certificate start"),
            Timestamp::from_str("2025-01-01T00:00:30Z").expect("certificate expiry"),
        );
        let peer_identity_commitment =
            session_consumer_identity_commitment(authorization.identity());
        let service = store.consumer_service();
        let original_admission_capsule = admission_capsule(roster_scope, &admission, &authority);
        let admission_request_id = SessionConsumerRequestId::from_bytes([0x55; 16]);
        let admission_request = SessionConsumerRequest::new(
            scope,
            admission_request_id,
            SessionConsumerOperation::FencedMutationRosterPollAdmit {
                request: Box::new(original_admission_capsule.clone()),
            },
        );
        let (admission_tag, admission_digest) =
            session_consumer_roster_ingress_operation(admission_request.operation())
                .expect("admission ingress operation");

        reset_roster_ingress_test_counters();
        reset_consumer_consensus_proposal_count();
        let diagnostics_before_admission = store.protected_roster_diagnostic_snapshot();
        let first_log = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .expect("first log index");
        let admission_attestation = issuer.ingress(
            peer_identity_commitment,
            roster_scope.digest(),
            admission_request_id,
            admission_tag,
            admission_digest,
        );
        let admission_subject_identity_commitment = [0x4a; 32];
        let admission_provenance_input = service
            .prepare_compact_admission_provenance_input(
                &roster_authorization,
                &admission_request,
                &admission_attestation,
                admission_subject_identity_commitment,
            )
            .expect("compact admission provenance input");
        let admission_provenance = issuer.compact_admission(
            roster_scope.digest(),
            admission_subject_identity_commitment,
            &admission_provenance_input,
        );
        let admission_response = service
            .execute_roster_ingress(
                &roster_authorization,
                admission_request,
                admission_attestation.clone(),
                Some(admission_provenance.clone()),
            )
            .await;
        let admission_response_capsule = match admission_response {
            SessionConsumerResponse::FencedMutationRosterPollAdmit(
                SessionConsumerRosterAdmissionMutationResponse::Recorded(capsule),
            ) => capsule,
            SessionConsumerResponse::FencedMutationRosterPollAdmit(
                SessionConsumerRosterAdmissionMutationResponse::OutcomeUnknown,
            ) => panic!("expected recorded fresh roster admission, got OutcomeUnknown"),
            SessionConsumerResponse::FencedMutationRosterPollAdmit(
                SessionConsumerRosterAdmissionMutationResponse::NotTransmitted,
            ) => panic!("expected recorded fresh roster admission, got NotTransmitted"),
            SessionConsumerResponse::FencedMutationRosterPollAdmit(
                SessionConsumerRosterAdmissionMutationResponse::Rejected(rejection),
            ) => panic!("expected recorded fresh roster admission, got {rejection:?}"),
            response => panic!("expected fresh roster admission, got {response:?}"),
        };
        let diagnostics_after_admission = store.protected_roster_diagnostic_snapshot();
        assert_eq!(
            fixed_counter_total(
                &diagnostics_after_admission.admission_applied_attached_latency_millis,
            ),
            fixed_counter_total(
                &diagnostics_before_admission.admission_applied_attached_latency_millis,
            ) + 1,
            "one attached admission proposal reaches an applied response",
        );
        assert_eq!(
            fixed_counter_total(
                &diagnostics_after_admission.admission_applied_detached_latency_millis,
            ),
            fixed_counter_total(
                &diagnostics_before_admission.admission_applied_detached_latency_millis,
            ),
            "the successful caller remains attached",
        );
        assert_eq!(
            fixed_counter_total(
                &diagnostics_after_admission.log_append_sqlite_commit_latency_millis
            ),
            fixed_counter_total(
                &diagnostics_before_admission.log_append_sqlite_commit_latency_millis
            ) + 1,
            "one durable log append is measured for the admission",
        );
        assert_eq!(
            fixed_counter_total(
                &diagnostics_after_admission.state_machine_sqlite_commit_latency_millis,
            ),
            fixed_counter_total(
                &diagnostics_before_admission.state_machine_sqlite_commit_latency_millis,
            ) + 1,
            "one durable state-machine commit is measured for the admission",
        );
        assert_eq!(diagnostics_after_admission.occupancy_valid, 1);
        assert_eq!(diagnostics_after_admission.live_reservations, 1);
        assert_eq!(diagnostics_after_admission.retained_reservations, 0);
        let admission_wire: RosterIngressAdmissionResponseWire =
            crate::fenced_mutation_roster::decode_frame(
                admission_response_capsule.canonical_bytes(),
                TEST_ADMISSION_RESPONSE_MAGIC,
                TEST_ADMISSION_RESPONSE_DOMAIN,
                crate::fenced_mutation_roster_transport::MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
            )
            .expect("decode fresh admission response");
        let (registration, registration_request_id) = match admission_wire {
            RosterIngressAdmissionResponseWire::Fresh {
                scope: response_scope,
                registration,
                ..
            } => {
                assert_eq!(response_scope, roster_scope.digest());
                let request_id = registration.request_id;
                (registration.registration(&admission), request_id)
            }
            _ => panic!("expected fresh admission response wire"),
        };
        assert_eq!(
            registration_request_id.history_epoch(),
            first_log + 1,
            "the first admission Raft entry mints the registration epoch"
        );

        // An independent authenticated ingress for the same canonical body
        // must be recorded as a stable-slot replay. It has a fresh consumer
        // request ID, authenticated-at instant, material generation, and
        // handshake epoch, so equality cannot depend on its compact proof.
        clock.set(start.add_seconds(1).expect("replay logical time"));
        let replay_request_id = SessionConsumerRequestId::from_bytes([0x5b; 16]);
        let replay_request = SessionConsumerRequest::new(
            scope,
            replay_request_id,
            SessionConsumerOperation::FencedMutationRosterPollAdmit {
                request: Box::new(original_admission_capsule.clone()),
            },
        );
        let (replay_tag, replay_digest) =
            session_consumer_roster_ingress_operation(replay_request.operation())
                .expect("replay ingress operation");
        let replay_attestation = issuer.ingress_with_metadata(RosterIngressTestInput {
            peer_identity_commitment,
            scope: roster_scope.digest(),
            request_id: replay_request_id,
            operation_tag: replay_tag,
            capsule: replay_digest,
            authenticated_at: start.add_seconds(1).expect("replay authentication time"),
            material_generation: 2,
            handshake_epoch: 2,
        });
        let replay_provenance_input = service
            .prepare_compact_admission_provenance_input(
                &roster_authorization,
                &replay_request,
                &replay_attestation,
                admission_subject_identity_commitment,
            )
            .expect("replay compact admission provenance input");
        let replay_provenance = issuer.compact_admission(
            roster_scope.digest(),
            admission_subject_identity_commitment,
            &replay_provenance_input,
        );
        assert_ne!(
            admission_provenance
                .canonical_bytes()
                .expect("fresh provenance bytes"),
            replay_provenance
                .canonical_bytes()
                .expect("replay provenance bytes"),
            "independently signed ingress provenance differs from the stored proof"
        );
        let replay_response = service
            .execute_roster_ingress(
                &roster_authorization,
                replay_request,
                replay_attestation,
                Some(replay_provenance),
            )
            .await;
        let replay_capsule = match replay_response {
            SessionConsumerResponse::FencedMutationRosterPollAdmit(
                SessionConsumerRosterAdmissionMutationResponse::Recorded(capsule),
            ) => capsule,
            response => panic!("expected replayed roster admission, got {response:?}"),
        };
        let replay_wire: RosterIngressAdmissionResponseWire =
            crate::fenced_mutation_roster::decode_frame(
                replay_capsule.canonical_bytes(),
                TEST_ADMISSION_RESPONSE_MAGIC,
                TEST_ADMISSION_RESPONSE_DOMAIN,
                crate::fenced_mutation_roster_transport::MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
            )
            .expect("decode capability-free replay response");
        assert!(matches!(
            replay_wire,
            RosterIngressAdmissionResponseWire::Replayed { scope: response_scope }
                if response_scope == roster_scope.digest()
        ));
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(first_log + 2),
            "same-body replay applies at a new Raft position without another registration"
        );
        assert_eq!(
            CONSUMER_CONSENSUS_PROPOSAL_COUNT.load(Ordering::Relaxed),
            2,
            "fresh admission and the no-effect replay are the only submitted admission commands"
        );
        assert_eq!(
            ROSTER_INGRESS_ADMISSION_SUBMISSION_COUNT.load(Ordering::Relaxed),
            2
        );

        // The protected-roster namespace deliberately bypasses the generic
        // request ledger. Replaying the original byte-for-byte command still
        // reaches the stable-slot classifier at a later Raft index and must
        // therefore be capability-free as well.
        let exact_duplicate_request = SessionConsumerRequest::new(
            scope,
            admission_request_id,
            SessionConsumerOperation::FencedMutationRosterPollAdmit {
                request: Box::new(original_admission_capsule.clone()),
            },
        );
        let exact_duplicate_response = service
            .execute_roster_ingress(
                &roster_authorization,
                exact_duplicate_request,
                admission_attestation,
                Some(admission_provenance.clone()),
            )
            .await;
        let exact_duplicate_capsule = match exact_duplicate_response {
            SessionConsumerResponse::FencedMutationRosterPollAdmit(
                SessionConsumerRosterAdmissionMutationResponse::Recorded(capsule),
            ) => capsule,
            response => panic!("expected exact replayed roster admission, got {response:?}"),
        };
        let exact_duplicate_wire: RosterIngressAdmissionResponseWire =
            crate::fenced_mutation_roster::decode_frame(
                exact_duplicate_capsule.canonical_bytes(),
                TEST_ADMISSION_RESPONSE_MAGIC,
                TEST_ADMISSION_RESPONSE_DOMAIN,
                crate::fenced_mutation_roster_transport::MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
            )
            .expect("decode exact capability-free replay response");
        assert!(matches!(
            exact_duplicate_wire,
            RosterIngressAdmissionResponseWire::Replayed { scope: response_scope }
                if response_scope == roster_scope.digest()
        ));
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(first_log + 3),
            "an exact replay reaches the roster classifier instead of the generic ledger"
        );
        assert_eq!(
            CONSUMER_CONSENSUS_PROPOSAL_COUNT.load(Ordering::Relaxed),
            3,
            "the exact replay is a no-effect roster command, not a cached capability response"
        );
        assert_eq!(
            ROSTER_INGRESS_ADMISSION_SUBMISSION_COUNT.load(Ordering::Relaxed),
            3
        );

        // A status projection reads the original durable registration and
        // compact proof after the independent retry. This is causal evidence
        // that the replay did not replace stored provenance or mint a new
        // epoch/capability.
        let replay_status_request_id = SessionConsumerRequestId::from_bytes([0x5c; 16]);
        let replay_status_request = SessionConsumerRequest::new(
            scope,
            replay_status_request_id,
            SessionConsumerOperation::FencedMutationRosterAdmissionStatus {
                request: Box::new(original_admission_capsule.clone()),
            },
        );
        let (replay_status_tag, replay_status_digest) =
            session_consumer_roster_ingress_operation(replay_status_request.operation())
                .expect("replay status operation");
        let replay_status_response = service
            .execute_roster_ingress(
                &roster_authorization,
                replay_status_request,
                issuer.ingress(
                    peer_identity_commitment,
                    roster_scope.digest(),
                    replay_status_request_id,
                    replay_status_tag,
                    replay_status_digest,
                ),
                None,
            )
            .await;
        let replay_status_capsule = match replay_status_response {
            SessionConsumerResponse::FencedMutationRosterAdmissionStatus(
                SessionConsumerRosterAdmissionReadResponse::Recorded(capsule),
            ) => capsule,
            response => panic!("expected post-replay admission status, got {response:?}"),
        };
        let replay_status_wire: RosterIngressAdmissionResponseWire =
            crate::fenced_mutation_roster::decode_frame(
                replay_status_capsule.canonical_bytes(),
                TEST_ADMISSION_RESPONSE_MAGIC,
                TEST_ADMISSION_RESPONSE_DOMAIN,
                crate::fenced_mutation_roster_transport::MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
            )
            .expect("decode post-replay admission status");
        match replay_status_wire {
            RosterIngressAdmissionResponseWire::PollAdmitted {
                registration: stored_registration,
                admission_provenance: stored_provenance,
                ..
            } => {
                assert_eq!(stored_registration.request_id, registration_request_id);
                assert_eq!(
                    stored_provenance,
                    admission_provenance
                        .canonical_bytes()
                        .expect("stored provenance bytes"),
                    "the retry must not replace durable provenance"
                );
            }
            _ => panic!("expected nonterminal stored admission after replay"),
        }

        let conflicting_admission = Admission::authenticate(
            AdmissionProposal::new(
                Profile::v1(),
                RosterId::from_bytes([0x51; 16]).expect("same roster ID"),
                (0..FRESH_ROSTER_MEMBERS)
                    .map(|ordinal| {
                        Member::new(
                            ordinal as u8,
                            MemberOperationId::from_bytes([ordinal as u8 + 1; 16])
                                .expect("member operation ID"),
                            vec![ordinal as u8 + 0x61],
                            1,
                        )
                        .expect("conflicting member")
                    })
                    .collect(),
                EstablishedMutation::no_op(),
                vec![0x52],
                vec![0x53],
                vec![0x54],
            )
            .expect("conflicting admission proposal"),
            key.clone(),
            roster_scope,
            authority.owner().clone(),
            authority.fence(),
            admission.expected_generation(),
        )
        .expect("same-slot conflicting admission");
        let conflicting_capsule =
            admission_capsule(roster_scope, &conflicting_admission, &authority);
        let conflicting_request_id = SessionConsumerRequestId::from_bytes([0x5d; 16]);
        let conflicting_request = SessionConsumerRequest::new(
            scope,
            conflicting_request_id,
            SessionConsumerOperation::FencedMutationRosterPollAdmit {
                request: Box::new(conflicting_capsule),
            },
        );
        let (conflicting_tag, conflicting_digest) =
            session_consumer_roster_ingress_operation(conflicting_request.operation())
                .expect("conflicting admission operation");
        let conflicting_attestation = issuer.ingress_with_metadata(RosterIngressTestInput {
            peer_identity_commitment,
            scope: roster_scope.digest(),
            request_id: conflicting_request_id,
            operation_tag: conflicting_tag,
            capsule: conflicting_digest,
            authenticated_at: start.add_seconds(1).expect("conflict authentication time"),
            material_generation: 3,
            handshake_epoch: 3,
        });
        let conflicting_provenance_input = service
            .prepare_compact_admission_provenance_input(
                &roster_authorization,
                &conflicting_request,
                &conflicting_attestation,
                admission_subject_identity_commitment,
            )
            .expect("conflicting compact admission provenance input");
        let conflicting_provenance = issuer.compact_admission(
            roster_scope.digest(),
            admission_subject_identity_commitment,
            &conflicting_provenance_input,
        );
        assert!(matches!(
            service
                .execute_roster_ingress(
                    &roster_authorization,
                    conflicting_request,
                    conflicting_attestation,
                    Some(conflicting_provenance),
                )
                .await,
            SessionConsumerResponse::FencedMutationRosterPollAdmit(
                SessionConsumerRosterAdmissionMutationResponse::Rejected(
                    SessionConsumerRosterRejection::Conflict
                )
            )
        ));

        // Keep the existing fresh-terminal accounting isolated from the
        // replay/read assertions above.
        reset_roster_ingress_test_counters();
        reset_consumer_consensus_proposal_count();
        let binding = admission
            .binding_key(registration_request_id.history_epoch())
            .expect("admission binding");
        let (terminal, proof_bundle, terminal_evidence) = issuer.terminal(
            &admission,
            binding,
            registration,
            &authority,
            &admission_provenance,
        );
        verify_compact_terminal_evidence_v2(CompactTerminalEvidenceVerificationV2 {
            root: &root,
            configuration_identity: identity,
            logical_time: start,
            binding,
            registration,
            admission_provenance: &admission_provenance,
            committing_authority: &authority,
            evidence: &terminal_evidence,
        })
        .expect("terminal evidence verifies before ingress");
        verify_executor_terminal_proof_bundle(ExecutorTerminalProofVerification {
            root: Some(&root),
            configuration_identity: identity,
            logical_time: start,
            binding,
            registration,
            admission: &admission,
            authority: &authority,
            terminal: &terminal,
            bundle: &proof_bundle,
        })
        .expect("terminal proof bundle verifies before ingress");
        let terminal_capsule = terminal_capsule(TerminalCapsuleInput {
            scope: roster_scope,
            binding,
            registration,
            authority: &authority,
            terminal: &terminal,
            admission: &admission,
            proof_bundle: &proof_bundle,
            terminal_evidence: &terminal_evidence,
        });
        let terminal_request_id = SessionConsumerRequestId::from_bytes([0x56; 16]);
        let terminal_request = SessionConsumerRequest::new(
            scope,
            terminal_request_id,
            SessionConsumerOperation::FencedMutationRosterTerminalize {
                request: Box::new(terminal_capsule.clone()),
            },
        );
        let (terminal_tag, terminal_digest) =
            session_consumer_roster_ingress_operation(terminal_request.operation())
                .expect("terminal ingress operation");
        assert_eq!(
            crate::fenced_mutation_roster_transport::roster_terminal_ingress_capsule_commitment(
                binding,
                registration,
                &authority,
                &terminal,
                &admission,
                &proof_bundle,
                &terminal_evidence,
            )
            .expect("reconstruct terminal ingress capsule"),
            terminal_digest,
            "test terminal request must match the durable command reconstruction"
        );
        let diagnostics_before_terminal = store.protected_roster_diagnostic_snapshot();
        let terminal_response = service
            .execute_roster_ingress(
                &roster_authorization,
                terminal_request,
                issuer.ingress(
                    peer_identity_commitment,
                    roster_scope.digest(),
                    terminal_request_id,
                    terminal_tag,
                    terminal_digest,
                ),
                None,
            )
            .await;
        let diagnostics_after_terminal = store.protected_roster_diagnostic_snapshot();
        assert!(matches!(
            terminal_response,
            SessionConsumerResponse::FencedMutationRosterTerminalize(
                SessionConsumerRosterTerminalMutationResponse::Recorded(_)
            )
        ));
        assert_eq!(
            fixed_counter_total(
                &diagnostics_after_terminal.terminal_applied_attached_latency_millis,
            ),
            fixed_counter_total(
                &diagnostics_before_terminal.terminal_applied_attached_latency_millis,
            ) + 1,
            "one attached terminal proposal reaches an applied response",
        );
        assert_eq!(
            fixed_counter_total(
                &diagnostics_after_terminal.terminal_applied_detached_latency_millis,
            ),
            fixed_counter_total(
                &diagnostics_before_terminal.terminal_applied_detached_latency_millis,
            ),
            "the successful terminal caller remains attached",
        );
        assert_eq!(
            fixed_counter_total(
                &diagnostics_after_terminal.log_append_sqlite_commit_latency_millis
            ),
            fixed_counter_total(
                &diagnostics_before_terminal.log_append_sqlite_commit_latency_millis
            ) + 1,
            "one durable log append is measured for terminalization",
        );
        assert_eq!(
            fixed_counter_total(
                &diagnostics_after_terminal.state_machine_sqlite_commit_latency_millis,
            ),
            fixed_counter_total(
                &diagnostics_before_terminal.state_machine_sqlite_commit_latency_millis,
            ) + 1,
            "one durable state-machine commit is measured for terminalization",
        );
        assert_eq!(diagnostics_after_terminal.occupancy_valid, 1);
        assert_eq!(diagnostics_after_terminal.live_reservations, 0);
        assert_eq!(diagnostics_after_terminal.retained_reservations, 1);
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(first_log + 5),
            "fresh admission, independent and exact replays, body conflict, and terminalization each append once"
        );
        assert_eq!(
            CONSUMER_CONSENSUS_PROPOSAL_COUNT.load(Ordering::Relaxed),
            1,
            "after replay accounting resets, terminalization is the only fresh-effect command"
        );
        assert_eq!(
            ROSTER_INGRESS_ADMISSION_SUBMISSION_COUNT.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            ROSTER_INGRESS_TERMINAL_SUBMISSION_COUNT.load(Ordering::Relaxed),
            1
        );
        assert_eq!(
            ROSTER_INGRESS_LINEARIZABLE_BARRIER_COUNT.load(Ordering::Relaxed),
            0,
            "terminalize must not issue a pre-write ReadIndex barrier"
        );
        assert_eq!(
            ROSTER_INGRESS_TERMINAL_STATUS_READ_COUNT.load(Ordering::Relaxed),
            0,
            "terminalize must not consult the terminal-status projection"
        );
        assert_eq!(
            ROSTER_INGRESS_LOGICAL_TIME_READ_COUNT.load(Ordering::Relaxed),
            1,
            "terminalize performs its one local temporal admission read"
        );

        reset_roster_ingress_test_counters();
        reset_consumer_consensus_proposal_count();
        let diagnostics_before_status = store.protected_roster_diagnostic_snapshot();
        let status_log = store.inner.raft.metrics().borrow().last_log_index;
        for (request_id, operation) in [
            (
                SessionConsumerRequestId::from_bytes([0x57; 16]),
                SessionConsumerOperation::FencedMutationRosterAdmissionStatus {
                    request: Box::new(original_admission_capsule.clone()),
                },
            ),
            (
                SessionConsumerRequestId::from_bytes([0x58; 16]),
                SessionConsumerOperation::FencedMutationRosterTerminalStatus {
                    request: Box::new(terminal_capsule.clone()),
                },
            ),
        ] {
            let request = SessionConsumerRequest::new(scope, request_id, operation);
            let (tag, digest) = session_consumer_roster_ingress_operation(request.operation())
                .expect("status ingress operation");
            let response = service
                .execute_roster_ingress(
                    &roster_authorization,
                    request,
                    issuer.ingress(
                        peer_identity_commitment,
                        roster_scope.digest(),
                        request_id,
                        tag,
                        digest,
                    ),
                    None,
                )
                .await;
            assert!(!matches!(
                response,
                SessionConsumerResponse::Rejected(_) | SessionConsumerResponse::OutcomeUnknown(_)
            ));
        }
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            status_log
        );
        assert_eq!(CONSUMER_CONSENSUS_PROPOSAL_COUNT.load(Ordering::Relaxed), 0);
        assert_eq!(
            ROSTER_INGRESS_ADMISSION_SUBMISSION_COUNT.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            ROSTER_INGRESS_TERMINAL_SUBMISSION_COUNT.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            ROSTER_INGRESS_LINEARIZABLE_BARRIER_COUNT.load(Ordering::Relaxed),
            2,
            "each protected-roster read path has one quorum barrier"
        );
        assert_eq!(
            ROSTER_INGRESS_TERMINAL_STATUS_READ_COUNT.load(Ordering::Relaxed),
            1,
            "only terminal status reaches its terminal projection"
        );
        assert_eq!(
            ROSTER_INGRESS_LOGICAL_TIME_READ_COUNT.load(Ordering::Relaxed),
            0,
            "status uses its post-barrier projection read rather than terminalize's pre-write read"
        );
        let diagnostics_after_status = store.protected_roster_diagnostic_snapshot();
        assert_eq!(
            diagnostics_after_status.admission_applied_attached_latency_millis,
            diagnostics_before_status.admission_applied_attached_latency_millis,
        );
        assert_eq!(
            diagnostics_after_status.admission_applied_detached_latency_millis,
            diagnostics_before_status.admission_applied_detached_latency_millis,
        );
        assert_eq!(
            diagnostics_after_status.terminal_applied_attached_latency_millis,
            diagnostics_before_status.terminal_applied_attached_latency_millis,
        );
        assert_eq!(
            diagnostics_after_status.terminal_applied_detached_latency_millis,
            diagnostics_before_status.terminal_applied_detached_latency_millis,
            "read-only admission and terminal status cannot add a mutation sample",
        );

        clock.set(issuer.valid_until);
        reset_roster_ingress_test_counters();
        reset_consumer_consensus_proposal_count();
        let expired_status_log = store.inner.raft.metrics().borrow().last_log_index;
        let expired_request_id = SessionConsumerRequestId::from_bytes([0x5a; 16]);
        let expired_request = SessionConsumerRequest::new(
            scope,
            expired_request_id,
            SessionConsumerOperation::FencedMutationRosterTerminalStatus {
                request: Box::new(terminal_capsule),
            },
        );
        let (expired_tag, expired_digest) =
            session_consumer_roster_ingress_operation(expired_request.operation())
                .expect("expired status ingress operation");
        let expired_response = service
            .execute_roster_ingress(
                &roster_authorization,
                expired_request,
                issuer.ingress(
                    peer_identity_commitment,
                    roster_scope.digest(),
                    expired_request_id,
                    expired_tag,
                    expired_digest,
                ),
                None,
            )
            .await;
        assert_eq!(
            expired_response,
            SessionConsumerResponse::FencedMutationRosterTerminalStatus(
                SessionConsumerRosterTerminalReadResponse::Rejected(
                    SessionConsumerRosterRejection::Authority,
                ),
            ),
            "a certificate that expires while the status path is waiting must be rejected after its barrier"
        );
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            expired_status_log
        );
        assert_eq!(CONSUMER_CONSENSUS_PROPOSAL_COUNT.load(Ordering::Relaxed), 0);
        assert_eq!(
            ROSTER_INGRESS_ADMISSION_SUBMISSION_COUNT.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            ROSTER_INGRESS_TERMINAL_SUBMISSION_COUNT.load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            ROSTER_INGRESS_LINEARIZABLE_BARRIER_COUNT.load(Ordering::Relaxed),
            1,
            "expired terminal status reaches the post-barrier expiry check"
        );
        assert_eq!(
            ROSTER_INGRESS_TERMINAL_STATUS_READ_COUNT.load(Ordering::Relaxed),
            1,
            "expiry is rechecked from the post-barrier terminal projection time"
        );
    }

    #[tokio::test]
    async fn protected_roster_sqlite_successor_authority_preserves_the_immutable_admission() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let directory = tempfile::tempdir().expect("successor roster directory");
        let start = Timestamp::from_str("2025-02-01T00:00:00Z").expect("test start");
        let clock = Arc::new(MutableClock::new(start));
        let root = roster_ingress_test_root();
        let topology = roster_ingress_singleton_topology(root.clone());
        let identity = topology.consensus_identity().expect("consensus identity");
        let store = ConsensusSessionStore::open_with_clock(
            topology,
            SqliteSessionBackend::open(directory.path().join("successor.sqlite"))
                .expect("successor SQLite backend"),
            directory.path().join("snapshots"),
            BTreeMap::new(),
            clock.clone(),
            Duration::from_secs(1),
        )
        .await
        .expect("open successor store");
        store
            .initialize_cluster()
            .await
            .expect("initialize successor store");
        store
            .activate_protected_roster_profile()
            .await
            .expect("activate immutable roster profile before admission");

        let key = SessionKey {
            tenant: TenantId::new("roster-successor").expect("tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"same-session")
                .try_into()
                .expect("stable ID"),
        };
        // Start the original owner at fence two so both equal- and lower-
        // fence successor attempts can be represented by valid wire values.
        let seed = store
            .acquire(
                &key,
                OwnerId::new("successor-seed").expect("seed owner"),
                Duration::from_secs(60),
            )
            .await
            .expect("seed lease");
        store.release(seed).await.expect("release seed lease");
        let original_owner = OwnerId::new("successor-owner-a").expect("original owner");
        let original_lease = store
            .acquire(&key, original_owner.clone(), Duration::from_secs(60))
            .await
            .expect("original lease");
        assert_eq!(original_lease.fence().get(), 2);
        let initial = consumer_record_with_payload_len(&key, &original_lease, 1024);
        assert!(matches!(
            store
                .compare_and_set(CompareAndSet {
                    key: key.clone(),
                    lease: original_lease.clone(),
                    expected_generation: None,
                    new_record: initial,
                })
                .await
                .expect("write protected business record"),
            CompareAndSetResult::Success
        ));

        let scope = store.consumer_scope().expect("consumer scope");
        let consumer_identity = SessionConsumerIdentity::new(
            "spiffe://test.example/tenant/roster-successor/ns/default/sa/store/nf/smf/instance/one",
        )
        .expect("consumer identity");
        let manifest = store
            .consumer_authorization_manifest([SessionConsumerAuthorizationGrant::try_new(
                SpiffeId::new(consumer_identity.as_str()).expect("consumer SPIFFE ID"),
                [SessionConsumerTenantNfScope::new(
                    key.tenant.clone(),
                    key.nf_kind.clone(),
                )],
            )
            .expect("consumer grant")])
            .await
            .expect("consumer authorization manifest");
        let authorization = manifest
            .authorize(&consumer_identity)
            .expect("consumer authorization");
        let roster_authorization = authorization.roster_authorization();
        let roster_scope = Scope::from_digest(session_consumer_roster_scope_commitment(scope));
        let admission = Admission::authenticate(
            AdmissionProposal::new(
                Profile::v1(),
                RosterId::from_bytes([0x61; 16]).expect("roster ID"),
                (0..FRESH_ROSTER_MEMBERS)
                    .map(|ordinal| {
                        Member::new(
                            ordinal as u8,
                            MemberOperationId::from_bytes([ordinal as u8 + 1; 16])
                                .expect("member operation ID"),
                            vec![ordinal as u8 + 1],
                            1,
                        )
                        .expect("member")
                    })
                    .collect(),
                EstablishedMutation::no_op(),
                vec![0x62],
                vec![0x63],
                vec![0x64],
            )
            .expect("admission proposal"),
            key.clone(),
            roster_scope,
            original_owner.clone(),
            original_lease.fence(),
            Generation::new(1),
        )
        .expect("admission");
        let original_authority = AuthorityBinding::for_admission(
            &admission,
            original_owner.clone(),
            original_lease.fence(),
            AuthorityLeaseMetadata::new(
                original_lease.credential_id(),
                Generation::new(1),
                original_lease.acquired_at(),
                original_lease.expires_at(),
            ),
        )
        .expect("original authority");
        let issuer = RosterIngressTestIssuer::new(
            identity,
            Timestamp::from_str("2025-01-31T23:59:59Z").expect("certificate start"),
            start.add_seconds(50).expect("certificate expiry"),
        );
        let peer_identity_commitment =
            session_consumer_identity_commitment(authorization.identity());
        let service = store.consumer_service();
        let admission_request_id = SessionConsumerRequestId::from_bytes([0x65; 16]);
        let admission_request = SessionConsumerRequest::new(
            scope,
            admission_request_id,
            SessionConsumerOperation::FencedMutationRosterPollAdmit {
                request: Box::new(admission_capsule(
                    roster_scope,
                    &admission,
                    &original_authority,
                )),
            },
        );
        let (admission_tag, admission_digest) =
            session_consumer_roster_ingress_operation(admission_request.operation())
                .expect("admission operation");
        let admission_attestation = issuer.ingress(
            peer_identity_commitment,
            roster_scope.digest(),
            admission_request_id,
            admission_tag,
            admission_digest,
        );
        let admission_provenance_input = service
            .prepare_compact_admission_provenance_input(
                &roster_authorization,
                &admission_request,
                &admission_attestation,
                [0x66; 32],
            )
            .expect("admission provenance input");
        let admission_provenance = issuer.compact_admission(
            roster_scope.digest(),
            [0x66; 32],
            &admission_provenance_input,
        );
        let registration = match service
            .execute_roster_ingress(
                &roster_authorization,
                admission_request,
                admission_attestation,
                Some(admission_provenance.clone()),
            )
            .await
        {
            SessionConsumerResponse::FencedMutationRosterPollAdmit(
                SessionConsumerRosterAdmissionMutationResponse::Recorded(capsule),
            ) => match crate::fenced_mutation_roster::decode_frame(
                capsule.canonical_bytes(),
                TEST_ADMISSION_RESPONSE_MAGIC,
                TEST_ADMISSION_RESPONSE_DOMAIN,
                crate::fenced_mutation_roster_transport::MAX_PROTECTED_ROSTER_ADMISSION_CAPSULE_BYTES,
            )
            .expect("decode fresh admission") {
                RosterIngressAdmissionResponseWire::Fresh { registration, .. } => {
                    registration.registration(&admission)
                }
                _ => panic!("expected fresh admission registration"),
            },
            response => panic!("expected admitted roster, got {response:?}"),
        };

        // This is an actual lease handoff in the same SQLite backend, not a
        // caller-authored authority. The reservation prevents any third
        // business mutation while the successor recovers and terminalizes.
        store
            .release(original_lease.clone())
            .await
            .expect("release original lease");
        let successor_owner = OwnerId::new("successor-owner-b").expect("successor owner");
        let successor_lease = store
            .acquire(&key, successor_owner.clone(), Duration::from_secs(60))
            .await
            .expect("successor lease");
        assert_eq!(
            successor_lease.fence().get(),
            original_lease.fence().get() + 1
        );
        let successor_authority = AuthorityBinding::from_consensus_parts(
            roster_scope.digest(),
            key.clone(),
            successor_owner.clone(),
            successor_lease.fence(),
            AuthorityLeaseMetadata::new(
                successor_lease.credential_id(),
                Generation::new(1),
                successor_lease.acquired_at(),
                successor_lease.expires_at(),
            ),
        )
        .expect("successor authority");

        let admission_status = store
            .inner
            .backend
            .consensus_protected_roster_admission_status(
                identity,
                admission.clone(),
                successor_authority.clone(),
                start,
            )
            .await
            .expect("successor exact admission status")
            .0;
        assert!(matches!(
            admission_status,
            crate::sqlite::consensus::ProtectedRosterReadResult::Admitted(_)
        ));
        let recovery = crate::fenced_mutation_roster_executor::RecoveryRequest::new(
            crate::fenced_mutation_roster_executor::RecoveryRequestInput::new(
                crate::fenced_mutation_roster_executor::RecoveryLookup::new(
                    roster_scope,
                    admission.roster_id(),
                ),
                admission.logical_owner().clone(),
                admission.admission_fence(),
                successor_authority.clone(),
            ),
        )
        .expect("successor recovery request");
        assert!(matches!(
            store
                .inner
                .backend
                .consensus_protected_roster_recovery(identity, recovery, start)
                .await
                .expect("successor recovery")
                .0,
            crate::sqlite::consensus::ProtectedRosterReadResult::Admitted(_)
        ));

        let binding = admission
            .binding_key(registration.consensus_parts().1.history_epoch())
            .expect("admission binding");
        let (terminal, proof_bundle, terminal_evidence) = issuer.terminal(
            &admission,
            binding,
            registration,
            &successor_authority,
            &admission_provenance,
        );
        let terminal_capsule = terminal_capsule(TerminalCapsuleInput {
            scope: roster_scope,
            binding,
            registration,
            authority: &successor_authority,
            terminal: &terminal,
            admission: &admission,
            proof_bundle: &proof_bundle,
            terminal_evidence: &terminal_evidence,
        });
        let terminal_request_id = SessionConsumerRequestId::from_bytes([0x67; 16]);
        let terminal_request = SessionConsumerRequest::new(
            scope,
            terminal_request_id,
            SessionConsumerOperation::FencedMutationRosterTerminalize {
                request: Box::new(terminal_capsule.clone()),
            },
        );
        let (terminal_tag, terminal_digest) =
            session_consumer_roster_ingress_operation(terminal_request.operation())
                .expect("terminal operation");
        let terminalized_bytes = match service
            .execute_roster_ingress(
                &roster_authorization,
                terminal_request,
                issuer.ingress(
                    peer_identity_commitment,
                    roster_scope.digest(),
                    terminal_request_id,
                    terminal_tag,
                    terminal_digest,
                ),
                None,
            )
            .await
        {
            SessionConsumerResponse::FencedMutationRosterTerminalize(
                SessionConsumerRosterTerminalMutationResponse::Recorded(capsule),
            ) => capsule.canonical_bytes().to_vec(),
            response => panic!("expected successor terminalization, got {response:?}"),
        };
        let (registration_handle, registration_request_id, registration_terminal_slot) =
            registration.consensus_parts();
        let terminal_status = store
            .inner
            .backend
            .consensus_protected_roster_terminal_status(
                identity,
                binding,
                (
                    registration_handle,
                    registration_request_id,
                    *registration_terminal_slot.as_bytes(),
                ),
                successor_authority.clone(),
                terminal.body_commitment(),
                terminal_evidence.clone(),
                start,
            )
            .await
            .expect("successor exact terminal status")
            .0;
        let receipt_commitment = match &terminal_status {
            crate::sqlite::consensus::ProtectedRosterReadResult::Terminalized(read) => {
                read.committed.receipt_commitment()
            }
            _ => panic!("successor terminal status must retain Established"),
        };
        let terminal_status_request_id = SessionConsumerRequestId::from_bytes([0x68; 16]);
        let terminal_status_request = SessionConsumerRequest::new(
            scope,
            terminal_status_request_id,
            SessionConsumerOperation::FencedMutationRosterTerminalStatus {
                request: Box::new(terminal_capsule.clone()),
            },
        );
        let (terminal_status_tag, terminal_status_digest) =
            session_consumer_roster_ingress_operation(terminal_status_request.operation())
                .expect("terminal status operation");
        let status_bytes = match service
            .execute_roster_ingress(
                &roster_authorization,
                terminal_status_request,
                issuer.ingress(
                    peer_identity_commitment,
                    roster_scope.digest(),
                    terminal_status_request_id,
                    terminal_status_tag,
                    terminal_status_digest,
                ),
                None,
            )
            .await
        {
            SessionConsumerResponse::FencedMutationRosterTerminalStatus(
                SessionConsumerRosterTerminalReadResponse::Recorded(capsule),
            ) => capsule.canonical_bytes().to_vec(),
            response => panic!("expected successor terminal status, got {response:?}"),
        };
        assert_eq!(
            status_bytes, terminalized_bytes,
            "status returns exact retained bytes"
        );

        let publication =
            crate::consumer::SessionConsumerRosterCurrentPublicationAuthorityCapsule::new(
                roster_scope.digest(),
                key.clone(),
                *admission.roster_id().as_bytes(),
                admission.body_commitment(),
                terminal.body_commitment(),
                receipt_commitment,
                original_owner.clone(),
                original_lease.fence(),
                registration_handle,
                registration_request_id.to_bytes(),
                *registration_terminal_slot.as_bytes(),
                successor_owner.clone(),
                successor_lease.fence(),
                successor_lease.credential_id(),
                Generation::new(1),
                successor_lease.acquired_at(),
                successor_lease.expires_at(),
            )
            .expect("Established publication query");
        let publication_request_id = SessionConsumerRequestId::from_bytes([0x69; 16]);
        let publication_request = SessionConsumerRequest::new(
            scope,
            publication_request_id,
            SessionConsumerOperation::FencedMutationRosterCurrentPublicationAuthority {
                request: Box::new(publication),
            },
        );
        let (publication_tag, publication_digest) =
            session_consumer_roster_ingress_operation(publication_request.operation())
                .expect("publication operation");
        assert!(matches!(
            service
                .execute_roster_ingress(
                    &roster_authorization,
                    publication_request,
                    issuer.ingress(
                        peer_identity_commitment,
                        roster_scope.digest(),
                        publication_request_id,
                        publication_tag,
                        publication_digest,
                    ),
                    None,
                )
                .await,
            SessionConsumerResponse::FencedMutationRosterCurrentPublicationAuthority(
                SessionConsumerRosterCurrentPublicationAuthorityReadResponse::Current
            )
        ));

        let wrong_ingress_publication =
            crate::consumer::SessionConsumerRosterCurrentPublicationAuthorityCapsule::new(
                [0x70; 32],
                key.clone(),
                *admission.roster_id().as_bytes(),
                admission.body_commitment(),
                terminal.body_commitment(),
                receipt_commitment,
                original_owner,
                original_lease.fence(),
                registration_handle,
                registration_request_id.to_bytes(),
                *registration_terminal_slot.as_bytes(),
                successor_owner,
                successor_lease.fence(),
                successor_lease.credential_id(),
                Generation::new(1),
                successor_lease.acquired_at(),
                successor_lease.expires_at(),
            )
            .expect("foreign-ingress publication query");
        let wrong_ingress_request_id = SessionConsumerRequestId::from_bytes([0x6a; 16]);
        let wrong_ingress_request = SessionConsumerRequest::new(
            scope,
            wrong_ingress_request_id,
            SessionConsumerOperation::FencedMutationRosterCurrentPublicationAuthority {
                request: Box::new(wrong_ingress_publication),
            },
        );
        let (wrong_ingress_tag, wrong_ingress_digest) =
            session_consumer_roster_ingress_operation(wrong_ingress_request.operation())
                .expect("foreign-ingress publication operation");
        assert!(matches!(
            service
                .execute_roster_ingress(
                    &roster_authorization,
                    wrong_ingress_request,
                    issuer.ingress(
                        peer_identity_commitment,
                        roster_scope.digest(),
                        wrong_ingress_request_id,
                        wrong_ingress_tag,
                        wrong_ingress_digest,
                    ),
                    None,
                )
                .await,
            SessionConsumerResponse::FencedMutationRosterCurrentPublicationAuthority(
                SessionConsumerRosterCurrentPublicationAuthorityReadResponse::Rejected
            )
        ));

        let equal_fence = AuthorityBinding::from_consensus_parts(
            roster_scope.digest(),
            key.clone(),
            OwnerId::new("successor-owner-b-equal").expect("equal owner"),
            original_lease.fence(),
            AuthorityLeaseMetadata::new(
                successor_lease.credential_id(),
                Generation::new(1),
                successor_lease.acquired_at(),
                successor_lease.expires_at(),
            ),
        )
        .expect("equal-fence authority");
        let lower_fence = AuthorityBinding::from_consensus_parts(
            roster_scope.digest(),
            key.clone(),
            OwnerId::new("successor-owner-b-lower").expect("lower owner"),
            FenceToken::new(original_lease.fence().get() - 1),
            AuthorityLeaseMetadata::new(
                successor_lease.credential_id(),
                Generation::new(1),
                successor_lease.acquired_at(),
                successor_lease.expires_at(),
            ),
        )
        .expect("lower-fence authority");
        let old_owner = AuthorityBinding::from_consensus_parts(
            roster_scope.digest(),
            key.clone(),
            original_authority.owner().clone(),
            original_lease.fence(),
            AuthorityLeaseMetadata::new(
                original_lease.credential_id(),
                Generation::new(1),
                original_lease.acquired_at(),
                original_lease.expires_at(),
            ),
        )
        .expect("old owner authority");
        let wrong_tenant = AuthorityBinding::from_consensus_parts(
            roster_scope.digest(),
            SessionKey {
                tenant: TenantId::new("other-tenant").expect("other tenant"),
                nf_kind: NetworkFunctionKind::smf(),
                key_type: SessionKeyType::PduSession,
                stable_id: key.stable_id.clone(),
            },
            successor_authority.owner().clone(),
            successor_lease.fence(),
            AuthorityLeaseMetadata::new(
                successor_lease.credential_id(),
                Generation::new(1),
                successor_lease.acquired_at(),
                successor_lease.expires_at(),
            ),
        )
        .expect("wrong tenant authority");
        let wrong_key = AuthorityBinding::from_consensus_parts(
            roster_scope.digest(),
            SessionKey {
                tenant: key.tenant.clone(),
                nf_kind: NetworkFunctionKind::smf(),
                key_type: SessionKeyType::PduSession,
                stable_id: Bytes::from_static(b"other-session")
                    .try_into()
                    .expect("other stable ID"),
            },
            successor_authority.owner().clone(),
            successor_lease.fence(),
            AuthorityLeaseMetadata::new(
                successor_lease.credential_id(),
                Generation::new(1),
                successor_lease.acquired_at(),
                successor_lease.expires_at(),
            ),
        )
        .expect("wrong key authority");
        let wrong_generation = AuthorityBinding::from_consensus_parts(
            roster_scope.digest(),
            key.clone(),
            successor_authority.owner().clone(),
            successor_lease.fence(),
            AuthorityLeaseMetadata::new(
                successor_lease.credential_id(),
                Generation::new(2),
                successor_lease.acquired_at(),
                successor_lease.expires_at(),
            ),
        )
        .expect("wrong generation authority");
        let wrong_credential = AuthorityBinding::from_consensus_parts(
            roster_scope.digest(),
            key.clone(),
            successor_authority.owner().clone(),
            successor_lease.fence(),
            AuthorityLeaseMetadata::new(
                successor_lease.credential_id() + 1,
                Generation::new(1),
                successor_lease.acquired_at(),
                successor_lease.expires_at(),
            ),
        )
        .expect("wrong credential authority");
        let wrong_window = AuthorityBinding::from_consensus_parts(
            roster_scope.digest(),
            key.clone(),
            successor_authority.owner().clone(),
            successor_lease.fence(),
            AuthorityLeaseMetadata::new(
                successor_lease.credential_id(),
                Generation::new(1),
                successor_lease
                    .acquired_at()
                    .add_seconds(1)
                    .expect("shifted acquisition"),
                successor_lease.expires_at(),
            ),
        )
        .expect("wrong lease window authority");
        let last_log = store.inner.raft.metrics().borrow().last_log_index;
        for authority in [
            equal_fence,
            lower_fence,
            old_owner,
            wrong_tenant,
            wrong_key,
            wrong_generation,
            wrong_credential,
            wrong_window,
        ] {
            assert!(
                store
                    .inner
                    .backend
                    .consensus_protected_roster_terminal_status(
                        identity,
                        binding,
                        (
                            registration_handle,
                            registration_request_id,
                            *registration_terminal_slot.as_bytes(),
                        ),
                        authority,
                        terminal.body_commitment(),
                        terminal_evidence.clone(),
                        start,
                    )
                    .await
                    .is_err(),
                "stale, foreign, or malformed successor authority must fail closed"
            );
        }
        assert!(
            store
                .inner
                .backend
                .consensus_protected_roster_terminal_status(
                    identity,
                    binding,
                    (
                        registration_handle,
                        registration_request_id,
                        *registration_terminal_slot.as_bytes(),
                    ),
                    successor_authority,
                    terminal.body_commitment(),
                    terminal_evidence,
                    successor_lease.expires_at(),
                )
                .await
                .is_err(),
            "an expired successor lease cannot read the retained terminal"
        );
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            last_log,
            "all successor validation failures are read-only and cannot create a third mutation"
        );
    }

    #[tokio::test]
    async fn oversized_consumer_cas_does_not_bind_request_id() {
        let (_directory, store, scope, authorization, key, lease) = consumer_boundary_store().await;
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
                &authorization,
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
                &authorization,
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
    async fn consumer_cas_body_is_bound_v2_and_conflicts_fail_without_effect() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let (_directory, store, scope, authorization, key, lease) = consumer_boundary_store().await;
        let service = store.consumer_service();
        let request_id = crate::SessionConsumerRequestId::from_bytes([0x93; 16]);
        let operation = CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: consumer_record_with_payload_len(
                &key,
                &lease,
                crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES,
            ),
        };
        let request = SessionConsumerRequest::new(
            scope,
            request_id,
            SessionConsumerOperation::CompareAndSet {
                op: Box::new(operation.clone()),
            },
        );
        let commitment_counters =
            Arc::new(crate::consumer::ConsumerRequestCommitmentV2TestCounters::default());
        let cas_counters = Arc::new(ConsumerCasTestCounters::default());
        let applied = CONSUMER_CAS_TEST_COUNTERS
            .scope(
                Arc::clone(&cas_counters),
                crate::consumer::CONSUMER_REQUEST_COMMITMENT_V2_TEST_COUNTERS.scope(
                    Arc::clone(&commitment_counters),
                    service.execute(&authorization, request),
                ),
            )
            .await;
        assert_eq!(
            applied,
            SessionConsumerResponse::CompareAndSet(Ok(CompareAndSetResult::Success))
        );
        assert_eq!(
            commitment_counters.serializations(),
            1,
            "the healthy maximum-payload CAS serializes/hashes its full request once"
        );
        assert!(
            commitment_counters.serialized_bytes()
                > crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES,
            "the one counted allocation covers the complete request, not only an ID"
        );
        assert_eq!(
            cas_counters.command_encodings.load(Ordering::Relaxed),
            1,
            "the server encodes the maximum-sized CAS command once"
        );
        assert!(
            cas_counters.command_encoded_bytes.load(Ordering::Relaxed)
                > crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES as u64,
            "the single server command allocation carries the full CAS payload"
        );
        let after_applied_effect = store
            .max_replication_sequence()
            .await
            .expect("applied effect sequence");
        let proposals_after_applied = cas_counters.proposals.load(Ordering::Relaxed);

        let changed = CompareAndSet {
            expected_generation: Some(Generation::new(99)),
            ..operation
        };
        let response = CONSUMER_CAS_TEST_COUNTERS
            .scope(
                Arc::clone(&cas_counters),
                service.execute(
                    &authorization,
                    SessionConsumerRequest::new(
                        scope,
                        request_id,
                        SessionConsumerOperation::CompareAndSet {
                            op: Box::new(changed),
                        },
                    ),
                ),
            )
            .await;
        assert_eq!(
            response,
            SessionConsumerResponse::CompareAndSet(Err(SessionConsumerStoreError::RequestConflict)),
            "a changed ordinary v2 request cannot reuse a durable request identity"
        );
        assert_eq!(
            cas_counters.proposals.load(Ordering::Relaxed),
            proposals_after_applied,
            "a changed request reaches no consensus proposal"
        );
        assert_eq!(
            store
                .max_replication_sequence()
                .await
                .expect("conflict effect sequence"),
            after_applied_effect,
            "a conflict applies no second session mutation"
        );
    }

    #[tokio::test]
    async fn prepared_cas_remote_forwarding_borrows_the_canonical_body_without_payload_clone() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let (_directory, store, _scope, _authorization, key, lease) =
            consumer_boundary_store().await;
        let request = ForwardMutationRequest {
            request_id: SessionConsensusRequestId::new(),
            intent: SessionMutationIntent::CompareAndSet(Arc::new(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: consumer_record_with_payload_len(
                    &key,
                    &lease,
                    crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES,
                ),
            })),
            required_consumer_scope: ForwardConsumerScope::Internal,
        };
        let owned = encode_bounded(&ForwardRequest::Mutation(request.clone()))
            .expect("owned prepared CAS forwarding encodes");
        let owned_counters =
            Arc::new(crate::record::EncryptedSessionPayloadOwnershipTestCounters::default());
        let encoded = crate::record::ENCRYPTED_SESSION_PAYLOAD_OWNERSHIP_TEST_COUNTERS
            .scope(Arc::clone(&owned_counters), async {
                encode_bounded(&BorrowedForwardRequest::Mutation(&request))
            })
            .await
            .expect("borrowed prepared CAS forwarding encodes");
        assert_eq!(
            encoded, owned,
            "borrowed forwarding remains byte-for-byte golden-compatible with ForwardRequest"
        );
        let decoded_owned: ForwardRequest =
            crate::record::ENCRYPTED_SESSION_PAYLOAD_OWNERSHIP_TEST_COUNTERS
                .scope(Arc::clone(&owned_counters), async {
                    decode_bounded(&owned)
                })
                .await
                .expect("consumer peer decodes the owned request");
        assert_eq!(decoded_owned, ForwardRequest::Mutation(request.clone()));
        assert_eq!(
            owned_counters.snapshot(),
            crate::record::EncryptedSessionPayloadOwnershipCounters {
                initial_owners: 1,
                initial_owned_bytes: crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES as u64,
                handle_clones: 0,
                deserialized_owners: 1,
                visit_bytes_owners: 0,
                visit_bytes_copied_bytes: 0,
                visit_byte_buf_owners: 0,
                sequence_chunk_allocations: (crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES
                    / crate::record::PAYLOAD_DESERIALIZE_CHUNK_BYTES)
                    as u64,
                sequence_chunk_capacity_bytes: crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES
                    as u64,
                sequence_staged_bytes: crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES as u64,
                sequence_final_allocations: 1,
                sequence_final_allocation_bytes: crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES
                    as u64,
                sequence_final_copied_bytes: crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES as u64,
            },
            "owned bytes decode through the same durable generic-sequence ownership path"
        );

        let borrowed_counters =
            Arc::new(crate::record::EncryptedSessionPayloadOwnershipTestCounters::default());
        let decoded: ForwardRequest =
            crate::record::ENCRYPTED_SESSION_PAYLOAD_OWNERSHIP_TEST_COUNTERS
                .scope(Arc::clone(&borrowed_counters), async {
                    decode_bounded(&encoded)
                })
                .await
                .expect("consumer peer decodes the borrowed wire bytes");

        assert_eq!(decoded, ForwardRequest::Mutation(request));
        assert_eq!(
            borrowed_counters.snapshot(),
            crate::record::EncryptedSessionPayloadOwnershipCounters {
                initial_owners: 1,
                initial_owned_bytes: crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES as u64,
                handle_clones: 0,
                deserialized_owners: 1,
                visit_bytes_owners: 0,
                visit_bytes_copied_bytes: 0,
                visit_byte_buf_owners: 0,
                sequence_chunk_allocations: (crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES
                    / crate::record::PAYLOAD_DESERIALIZE_CHUNK_BYTES)
                    as u64,
                sequence_chunk_capacity_bytes: crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES
                    as u64,
                sequence_staged_bytes: crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES as u64,
                sequence_final_allocations: 1,
                sequence_final_allocation_bytes: crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES
                    as u64,
                sequence_final_copied_bytes: crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES as u64,
            },
            "a proven-before-transmission remote reroute shares the canonical body; decoding the durable JSON sequence has one measured staged-to-final copy"
        );
        drop(store);
    }

    #[tokio::test]
    async fn oversized_consumer_batch_does_not_bind_request_id() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let (_directory, store, scope, authorization, key, lease) = consumer_boundary_store().await;
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
                &authorization,
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
                &authorization,
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
    #[allow(
        clippy::await_holding_lock,
        reason = "the test-only proposal counter is process-global evidence"
    )]
    async fn consumer_authorization_rejects_mixed_cas_and_batch_before_any_effect() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let (_directory, store, scope, authorization, key, lease) = consumer_boundary_store().await;
        let service = store.consumer_service();
        let foreign_key = SessionKey {
            tenant: TenantId::from_static("consumer-ungranted-third-tenant"),
            ..key.clone()
        };
        let before = store
            .max_replication_sequence()
            .await
            .expect("sequence before rejected consumer requests");
        reset_consumer_consensus_proposal_count();

        let mixed_cas = service
            .execute(
                &authorization,
                SessionConsumerRequest::new(
                    scope,
                    SessionConsumerRequestId::from_bytes([0x94; 16]),
                    SessionConsumerOperation::CompareAndSet {
                        op: Box::new(CompareAndSet {
                            key: key.clone(),
                            lease: lease.clone(),
                            expected_generation: None,
                            new_record: consumer_record_with_payload_len(
                                &foreign_key,
                                &lease,
                                crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES,
                            ),
                        }),
                    },
                ),
            )
            .await;
        assert_eq!(
            mixed_cas,
            SessionConsumerResponse::Rejected(SessionConsumerRejection::Unauthorized),
            "CAS checks its direct key, lease key, and replacement-record key"
        );

        let mixed_batch = service
            .execute(
                &authorization,
                SessionConsumerRequest::new(
                    scope,
                    SessionConsumerRequestId::from_bytes([0x95; 16]),
                    SessionConsumerOperation::Batch {
                        ops: vec![
                            SessionOp::RefreshTtl {
                                lease: lease.clone(),
                                ttl: Duration::from_secs(30),
                            },
                            SessionOp::Get { key: foreign_key },
                        ],
                    },
                ),
            )
            .await;
        assert_eq!(
            mixed_batch,
            SessionConsumerResponse::Rejected(SessionConsumerRejection::Unauthorized),
            "an unauthorized later slot prevents the potentially mutating slot zero effect"
        );
        assert_eq!(
            CONSUMER_CONSENSUS_PROPOSAL_COUNT.load(Ordering::Relaxed),
            0,
            "authorization rejects mixed fields before a consensus proposal"
        );
        assert_eq!(
            store
                .max_replication_sequence()
                .await
                .expect("sequence after rejected consumer requests"),
            before,
            "mixed authorization rejects before slot zero can mutate"
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
    async fn dynamic_committed_reply_does_not_repeat_origin_terminal_gate() {
        let directory = tempfile::tempdir().expect("dynamic forwarding boundary directory");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            SqliteSessionBackend::open(directory.path().join("store.sqlite"))
                .expect("dynamic forwarding boundary backend"),
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open dynamic forwarding boundary store");
        store
            .initialize_cluster()
            .await
            .expect("initialize dynamic forwarding boundary store");
        store
            .inner
            .terminal_recovery_gate_checks
            .store(0, Ordering::Relaxed);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        store
            .require_application_traffic_authority_before(deadline)
            .await
            .expect("dynamic origin is recovery-clear before transmission");
        assert_eq!(
            store
                .inner
                .terminal_recovery_gate_checks
                .load(Ordering::Relaxed),
            1,
            "origin ingress performs exactly one live terminal-recovery reconciliation"
        );

        store
            .require_application_traffic_committed_reply_authority_before(deadline)
            .await
            .expect("known committed Dynamic reply needs no duplicate origin reconciliation");
        assert_eq!(
            store
                .inner
                .terminal_recovery_gate_checks
                .load(Ordering::Relaxed),
            1,
            "a committed reply cannot spend the residual deadline on a duplicate origin gate"
        );
    }

    #[tokio::test]
    async fn dynamic_active_recovery_latch_rejects_before_any_proposal() {
        let directory = tempfile::tempdir().expect("dynamic active-latch directory");
        let database = directory.path().join("store.sqlite");
        let topology = singleton_topology();
        let identity = topology
            .consensus_identity()
            .expect("dynamic active-latch identity");
        let store = ConsensusSessionStore::open(
            topology,
            SqliteSessionBackend::open(&database).expect("dynamic active-latch backend"),
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open dynamic active-latch store");
        store
            .initialize_cluster()
            .await
            .expect("initialize dynamic active-latch store");

        let before_log = store.inner.raft.metrics().borrow().last_log_index;
        let before_sequence = store
            .inner
            .backend
            .consensus_max_replication_sequence()
            .await
            .expect("read application sequence before active latch");
        ensure_operator_recovery_latch_sync(
            &database,
            OperatorRecoveryLatch {
                identity,
                recovery_epoch: 1,
                plan_digest: [0xA7; 32],
                audit_pending: false,
            },
        )
        .expect("publish active recovery latch");
        store
            .inner
            .terminal_recovery_gate_checks
            .store(0, Ordering::Relaxed);

        let effect = store
            .submit_request_effect_before(
                SessionConsensusRequestId::new(),
                SessionMutationIntent::AdvanceLogicalTime,
                Some(identity),
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await;
        assert!(matches!(
            effect,
            ConsensusSubmissionEffect::NotTransmitted(StoreError::BackendUnavailable(_))
        ));
        assert_eq!(
            store
                .inner
                .terminal_recovery_gate_checks
                .load(Ordering::Relaxed),
            1,
            "origin ingress performs one recovery reconciliation before transmission"
        );
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            before_log,
            "an Active origin recovery latch cannot append a log entry"
        );
        assert_eq!(
            store
                .inner
                .backend
                .consensus_max_replication_sequence()
                .await
                .expect("read application sequence after active latch"),
            before_sequence,
            "an Active origin recovery latch cannot mutate application state"
        );
    }

    #[tokio::test]
    async fn dynamic_clear_submission_gates_origin_and_leader_once() {
        let directory = tempfile::tempdir().expect("dynamic clear submission directory");
        let topology = singleton_topology();
        let identity = topology
            .consensus_identity()
            .expect("dynamic clear submission identity");
        let store = ConsensusSessionStore::open(
            topology,
            SqliteSessionBackend::open(directory.path().join("store.sqlite"))
                .expect("dynamic clear submission backend"),
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open dynamic clear submission store");
        store
            .initialize_cluster()
            .await
            .expect("initialize dynamic clear submission store");
        let before_log = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .expect("initialized Dynamic log index");
        store
            .inner
            .terminal_recovery_gate_checks
            .store(0, Ordering::Relaxed);

        let effect = store
            .submit_request_effect_before(
                SessionConsensusRequestId::new(),
                SessionMutationIntent::AdvanceLogicalTime,
                Some(identity),
                tokio::time::Instant::now() + Duration::from_secs(1),
            )
            .await;
        assert!(matches!(effect, ConsensusSubmissionEffect::Committed(_)));
        assert_eq!(
            store
                .inner
                .terminal_recovery_gate_checks
                .load(Ordering::Relaxed),
            2,
            "one clear Dynamic submission reconciles only origin ingress and leader acceptance"
        );
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before_log + 1),
            "one clear Dynamic submission appends exactly one Raft entry"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_retry_after_cancellation_waits_for_detached_snapshot_capture() {
        let directory = tempfile::tempdir().expect("shutdown retry directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("shutdown retry SQLite backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open shutdown retry store");
        store
            .initialize_cluster()
            .await
            .expect("initialize shutdown retry store");

        let capture_gate = store.inner.backend.snapshot_capture_gate();
        capture_gate.arm();
        store
            .inner
            .raft
            .trigger()
            .snapshot()
            .await
            .expect("start engine-owned snapshot capture");
        tokio::time::timeout(Duration::from_secs(5), async {
            while !capture_gate.started() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("detached snapshot capture reaches its fixed gate");

        let cancelled_shutdown = tokio::spawn({
            let store = store.clone();
            async move { store.shutdown().await }
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while store.inner.raft.metrics().borrow().running_state.is_ok() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("shutdown reaches the engine termination edge");
        tokio::task::yield_now().await;
        assert!(
            !cancelled_shutdown.is_finished(),
            "shutdown must remain pending while the detached snapshot worker owns SQLite"
        );
        cancelled_shutdown.abort();
        assert!(
            cancelled_shutdown
                .await
                .expect_err("public shutdown future is cancelled")
                .is_cancelled(),
            "the fixture must cancel only the public shutdown caller"
        );

        let retry = tokio::spawn({
            let store = store.clone();
            async move { store.shutdown().await }
        });
        tokio::task::yield_now().await;
        assert!(
            !retry.is_finished(),
            "a retry cannot authorize reopening while the detached snapshot worker owns SQLite"
        );

        capture_gate.release();
        tokio::time::timeout(Duration::from_secs(5), retry)
            .await
            .expect("released detached snapshot worker completes the retry barrier")
            .expect("retry task remains available")
            .expect("retry authorizes reopening only after all tracked owners exit");
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

    #[cfg(all(target_os = "linux", feature = "test-vfs"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fixed_readiness_prune_degradation_wins_during_scope_read_and_over_deadline() {
        let directory = tempfile::tempdir().expect("fixed prune-readiness directory");
        let database_path = directory.path().join("store.sqlite");
        let snapshot_path = directory.path().join("snapshots");
        let topology = fixed_shutdown_topology();
        let backend = SqliteSessionBackend::open(&database_path)
            .expect("file-backed prune-readiness backend");
        let inspection_backend = backend.clone();
        let store = ConsensusSessionStore::open_fixed_durable_quorum(
            topology.clone(),
            backend,
            &snapshot_path,
            unavailable_fixed_shutdown_peers(&topology),
        )
        .await
        .expect("open fixed prune-readiness store");
        let lane = Arc::clone(
            store
                .inner
                .consensus_log_prune_lane
                .as_ref()
                .expect("fixed store owns a physical-prune lane"),
        );

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let diagnostics = store.inner.diagnostics.snapshot();
                if diagnostics.consensus_log_prune_attempts >= 1
                    && store
                        .inner
                        .diagnostics
                        .consensus_log_prune_gauges_for_test()
                        .0
                        == 0
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("startup prune recovery becomes quiescent");

        // Hold the primary backend lock after the fixed-readiness call has
        // announced its first durable scope read. This creates an exact
        // observation window in which the independent prune connection can
        // establish permanent local recovery evidence.
        let primary = inspection_backend.lock_connection_for_test().await;
        let purge_floor = LogId::new(CommittedLeaderId::new(1, store.inner.local_node_id), 1);
        let encoded_purge_floor =
            serde_json::to_vec(&purge_floor).expect("encode causal prune floor");
        let configuration_epoch =
            i64::try_from(store.inner.storage_identity.configuration_epoch().get())
                .expect("fixed configuration epoch fits SQLite");
        primary
            .execute(
                "INSERT INTO consensus_purged (singleton, configuration_epoch, term, log_index, log_id_json) VALUES (1, ?1, 1, 1, ?2)",
                rusqlite::params![configuration_epoch, encoded_purge_floor],
            )
            .expect("seed a causal physical-prune floor");
        primary
            .execute(
                "INSERT INTO consensus_log (log_index, configuration_epoch, term, entry_json) VALUES (1, ?1, 1, X'7B7D')",
                [configuration_epoch],
            )
            .expect("seed one row beneath the causal prune floor");
        let checks_before = inspection_backend
            .fixed_quorum_durable_check_count
            .load(Ordering::SeqCst);
        let probe_store = store.clone();
        let probe = tokio::spawn(async move {
            probe_store
                .probe_fixed_durable_readiness_before(
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while inspection_backend
                .fixed_quorum_durable_check_count
                .load(Ordering::SeqCst)
                == checks_before
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("fixed readiness blocks inside its durable scope read");

        primary
            .execute(
                "UPDATE consensus_identity SET fixed_placement_policy = 2 WHERE singleton = 1",
                [],
            )
            .expect("tamper fixed prune authority inside the observation window");
        lane.signal();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !lane.is_degraded() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("prune authority failure permanently degrades the lane");
        primary
            .execute(
                "UPDATE consensus_identity SET fixed_placement_policy = 1 WHERE singleton = 1",
                [],
            )
            .expect("restore exact fixed authority before releasing the scope read");
        drop(primary);

        let raced = probe.await.expect("fixed readiness probe task");
        assert_eq!(raced.state(), DurableReadinessState::RecoveryRequired);
        assert_eq!(
            raced.recovery_progress().state(),
            DurableRecoveryState::RecoveryRequired,
            "permanent prune failure observed during a durable read cannot be downgraded"
        );

        inspection_backend.inject_consensus_operator_recovery_failure(true);
        let expired = store
            .probe_fixed_durable_readiness_before(tokio::time::Instant::now())
            .await;
        assert_eq!(expired.state(), DurableReadinessState::RecoveryRequired);
        assert_eq!(
            expired.recovery_progress().state(),
            DurableRecoveryState::RecoveryRequired,
            "backend failure and an expired deadline cannot mask known prune degradation"
        );
        inspection_backend.inject_consensus_operator_recovery_failure(false);

        store
            .shutdown()
            .await
            .expect("shut down degraded fixed prune-readiness store");
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
                None,
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
        let first_identity = SessionConsumerIdentity::new(
            "spiffe://test.example/tenant/consumer-service/ns/default/sa/store/nf/smf/instance/one",
        )
        .expect("first consumer identity");
        let second_identity = SessionConsumerIdentity::new(
            "spiffe://test.example/tenant/consumer-service/ns/default/sa/store/nf/smf/instance/two",
        )
        .expect("second consumer identity");
        let first_grant = SessionConsumerAuthorizationGrant::try_new(
            SpiffeId::new(first_identity.as_str()).expect("canonical first SPIFFE ID"),
            [SessionConsumerTenantNfScope::new(
                key.tenant.clone(),
                key.nf_kind.clone(),
            )],
        )
        .expect("first consumer grant");
        let second_grant = SessionConsumerAuthorizationGrant::try_new(
            SpiffeId::new(second_identity.as_str()).expect("canonical second SPIFFE ID"),
            [SessionConsumerTenantNfScope::new(
                key.tenant.clone(),
                key.nf_kind.clone(),
            )],
        )
        .expect("second consumer grant");
        let manifest = store
            .consumer_authorization_manifest([first_grant, second_grant])
            .await
            .expect("consumer authorization manifest");
        let first_authorization = manifest
            .authorize(&first_identity)
            .expect("first consumer authorization");
        let second_authorization = manifest
            .authorize(&second_identity)
            .expect("second consumer authorization");
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
            service.execute(&first_authorization, first_request.clone()),
            service.execute(&second_authorization, second_request),
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

        let retry = service.execute(&first_authorization, first_request).await;
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
        let identity = SessionConsumerIdentity::new(
            "spiffe://test.example/tenant/consumer-transition/ns/default/sa/store/nf/smf/instance/one",
        )
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
        let grant = SessionConsumerAuthorizationGrant::try_new(
            SpiffeId::new(identity.as_str()).expect("canonical consumer SPIFFE ID"),
            [SessionConsumerTenantNfScope::new(
                key.tenant.clone(),
                key.nf_kind.clone(),
            )],
        )
        .expect("consumer grant");
        let manifest = store
            .consumer_authorization_manifest([grant])
            .await
            .expect("consumer authorization manifest");
        let authorization = manifest
            .authorize(&identity)
            .expect("consumer authorization");
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
        reset_fenced_transition_linearizable_admission_count();
        reset_consumer_consensus_proposal_count();
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
                &authorization,
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
        assert_eq!(
            FENCED_TRANSITION_LINEARIZABLE_ADMISSION_COUNT.load(Ordering::Relaxed),
            1,
            "a warmed local fenced transition admits exactly one linearizable quorum proof"
        );
        assert_eq!(
            CONSUMER_CONSENSUS_PROPOSAL_COUNT.load(Ordering::Relaxed),
            1,
            "the carried proof reaches exactly one fenced-transition proposal"
        );
    }

    #[tokio::test]
    async fn state_voter_activation_is_one_proof_one_proposal_and_idempotent() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let (_directory, store, scope, authorization, key, _lease) =
            consumer_boundary_store().await;
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .expect("initialized log index");
        reset_fenced_transition_linearizable_admission_count();

        store
            .activate_fenced_transition_capability()
            .await
            .expect("cold state-voter V1 activation");
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1),
            "cold activation appends exactly its cluster-scope certificate"
        );
        assert_eq!(
            FENCED_TRANSITION_LINEARIZABLE_ADMISSION_COUNT.load(Ordering::Relaxed),
            1,
            "cold activation carries exactly one typed quorum admission"
        );

        store
            .activate_fenced_transition_capability()
            .await
            .expect("idempotent state-voter V1 activation");
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1),
            "an already applied exact certificate never appends a second proposal"
        );
        assert_eq!(
            FENCED_TRANSITION_LINEARIZABLE_ADMISSION_COUNT.load(Ordering::Relaxed),
            2,
            "repeat activation still proves the current leader but reuses the durable certificate"
        );

        let physical_key = SessionKey {
            tenant: key.tenant.clone(),
            nf_kind: key.nf_kind.clone(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"activated-v1-transition")
                .try_into()
                .expect("stable ID"),
        };
        let transition_id = FencedTransitionRequestId::from_bytes([0xA3; 16]);
        let transition = FencedTransitionRequest::new(
            transition_id,
            FencedTransitionLease::acquire(
                physical_key,
                OwnerId::new("activated-v1-owner").expect("owner"),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .expect("lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("transition");
        reset_fenced_transition_linearizable_admission_count();
        let transition_before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .expect("activation log index");
        let response = store
            .consumer_service()
            .execute(
                &authorization,
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
            Some(transition_before + 1),
            "an activated V1 transition retains one proposal and no binding marker"
        );
        assert_eq!(
            FENCED_TRANSITION_LINEARIZABLE_ADMISSION_COUNT.load(Ordering::Relaxed),
            0,
            "the durable activation lets the following V1 write quorum linearize without a redundant read admission"
        );
    }

    #[tokio::test]
    async fn state_voter_activation_refuses_caller_selected_scope_or_voters() {
        let directory = tempfile::tempdir().expect("activation authority directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("activation authority backend");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open activation authority store");
        store
            .initialize_cluster()
            .await
            .expect("initialize activation authority store");
        let (current_scope, voters) = store.current_scope().expect("current scope");
        let stale_scope = SessionConsensusIdentity::new(
            current_scope.cluster_id(),
            current_scope.configuration_id(),
            SessionConsensusConfigurationEpoch::new(current_scope.configuration_epoch().get() + 1)
                .expect("successor epoch"),
        );
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .expect("initialized log index");
        for (scope_identity, voter_set_digest) in [
            (
                stale_scope,
                fenced_transition_voter_set_digest(stale_scope, &voters),
            ),
            (current_scope, [0xA5; 32]),
        ] {
            let reply = store
                .apply_on_local_leader(
                    ForwardMutationRequest {
                        request_id: SessionConsensusRequestId::new(),
                        intent: SessionMutationIntent::ActivateFencedTransitionCapability {
                            schema_version: FENCED_TRANSITION_SCHEMA_V1,
                            scope_identity,
                            voter_set_digest,
                        },
                        required_consumer_scope: ForwardConsumerScope::Internal,
                    },
                    store.inner.local_node_id,
                    tokio::time::Instant::now() + Duration::from_secs(1),
                )
                .await;
            assert!(
                matches!(
                    reply,
                    ForwardMutationReply::Applied(response)
                        if matches!(response.result, Err(StoreError::CapabilityNotSupported(_)))
                ),
                "a raw scope or voter digest cannot reach the leader activation path"
            );
        }
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before),
            "caller-selected scope, voter, or epoch material has no proposal effect"
        );
    }

    #[test]
    fn forward_mutation_reply_appends_activation_without_retagging_baseline_control_replies() {
        // This is the postcard layout at signed baseline 36720e58. The new
        // acknowledgement must remain appended after Unavailable so a
        // mixed-version follower never misreads an ordinary control reply.
        #[derive(Serialize, Deserialize)]
        enum BaselineForwardMutationReply {
            Applied(Box<SessionConsensusResponse>),
            RecordExpiryPreflight(Result<(), StoreError>),
            NotLeader {
                leader: Option<SessionConsensusNodeId>,
            },
            Unavailable,
        }

        let baseline_not_leader = encode_bounded(&BaselineForwardMutationReply::NotLeader {
            leader: Some(node(1)),
        })
        .expect("encode baseline NotLeader");
        assert!(matches!(
            decode_bounded::<ForwardMutationReply>(&baseline_not_leader)
                .expect("current decoder preserves baseline NotLeader"),
            ForwardMutationReply::NotLeader {
                leader: Some(leader)
            } if leader == node(1)
        ));

        let current_unavailable =
            encode_bounded(&ForwardMutationReply::Unavailable).expect("encode current Unavailable");
        assert!(matches!(
            decode_bounded::<BaselineForwardMutationReply>(&current_unavailable)
                .expect("baseline decoder preserves current Unavailable"),
            BaselineForwardMutationReply::Unavailable
        ));
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
    async fn roster_forwarding_rejects_a_generic_mutation_smuggled_into_its_family() {
        let directory = tempfile::tempdir().expect("roster forwarding directory");
        let store = ConsensusSessionStore::open(
            singleton_topology(),
            SqliteSessionBackend::open(directory.path().join("store.sqlite"))
                .expect("roster forwarding backend"),
            directory.path().join("snapshots"),
            BTreeMap::new(),
        )
        .await
        .expect("open roster forwarding store");
        store
            .initialize_cluster()
            .await
            .expect("initialize roster forwarding store");

        let before_log = store.inner.raft.metrics().borrow().last_log_index;
        let payload = encode_roster_bounded(&ForwardRequest::Mutation(ForwardMutationRequest {
            request_id: SessionConsensusRequestId::new(),
            intent: SessionMutationIntent::AdvanceLogicalTime,
            required_consumer_scope: ForwardConsumerScope::Internal,
        }))
        .expect("encode smuggled generic forwarding request");
        let request = SessionConsensusWireRequest::try_new(
            store.inner.storage_identity,
            store.inner.local_node_id,
            SessionConsensusRpcFamily::ForwardRosterMutation,
            payload,
        )
        .expect("bind smuggled forwarding request to the local member");
        let response = store
            .rpc_handler()
            .handle(store.inner.local_node_id, request)
            .await;
        assert_eq!(response.result, Err(SessionConsensusPeerError::Protocol));
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            before_log,
            "a generic request smuggled through roster forwarding reached the Raft log"
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

    #[cfg(feature = "test-control")]
    #[tokio::test]
    async fn padding_receipt_resolves_accepted_timeout_without_reproposal() {
        let _timing_permit = crate::acquire_consensus_timing_test_permit().await;
        let directory = tempfile::tempdir().expect("padding receipt directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("padding receipt SQLite backend");
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
        .expect("open padding receipt store");
        store
            .initialize_cluster()
            .await
            .expect("initialize padding receipt store");

        let held_apply = apply_gate
            .acquire_owned()
            .await
            .expect("hold padding receipt state-machine apply");
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        let request_id = *b"OPCPADRECEIPT001";
        let submit_store = store.clone();
        let submission = tokio::spawn(async move {
            submit_store
                .submit_request(
                    SessionConsensusRequestId::from_bytes(request_id),
                    SessionMutationIntent::AdvanceLogicalTime,
                )
                .await
        });
        wait_for_log_index_after(&store, before, "accepted padding receipt proposal").await;
        assert_eq!(
            submission.await.expect("padding receipt submit task"),
            Err(StoreError::BackendOperationOutcomeUnavailable),
            "an accepted command whose apply result missed its deadline is ambiguous"
        );
        assert_eq!(
            crate::test_support::consensus_padding_receipt_status_for_test(&store, request_id)
                .await
                .expect("read held padding receipt"),
            crate::test_support::ConsensusPaddingReceiptStatusForTest::NotFound,
            "an accepted but unapplied command has no durable outcome receipt"
        );
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1),
            "the ambiguous caller submitted exactly one command"
        );

        drop(held_apply);
        let recorded_index = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match crate::test_support::consensus_padding_receipt_status_for_test(
                    &store, request_id,
                )
                .await
                .expect("read applied padding receipt")
                {
                    crate::test_support::ConsensusPaddingReceiptStatusForTest::NotFound => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    crate::test_support::ConsensusPaddingReceiptStatusForTest::Recorded {
                        raft_log_index,
                    } => break raft_log_index,
                    crate::test_support::ConsensusPaddingReceiptStatusForTest::Conflict => {
                        panic!("the exact padding receipt cannot conflict")
                    }
                }
            }
        })
        .await
        .expect("padding receipt becomes visible after apply");
        assert_eq!(recorded_index, before + 1);
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1),
            "receipt recovery never reproposes the ambiguous command"
        );
        let permits = tokio::time::timeout(
            Duration::from_secs(1),
            Arc::clone(&store.inner.proposal_admission).acquire_many_owned(
                u32::try_from(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS)
                    .expect("proposal slot count fits u32"),
            ),
        )
        .await
        .expect("padding receipt supervisor releases admission after apply")
        .expect("padding receipt proposal admission remains open");
        drop(permits);
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
    async fn logical_read_time_supervisor_drops_all_dead_preproposal_cohort_without_dispatch() {
        let directory = tempfile::tempdir().expect("logical-read pruning directory");
        let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
            .expect("logical-read pruning SQLite backend");
        let store = ConsensusSessionStore::open_with_clock(
            singleton_topology(),
            backend,
            directory.path().join("snapshots"),
            BTreeMap::new(),
            Arc::new(SystemClock),
            Duration::from_secs(1),
        )
        .await
        .expect("open logical-read pruning store");
        store
            .initialize_cluster()
            .await
            .expect("initialize logical-read pruning store");
        let before = store
            .inner
            .raft
            .metrics()
            .borrow()
            .last_log_index
            .unwrap_or(0);
        let held_proposals = Arc::clone(&store.inner.proposal_admission)
            .acquire_many_owned(
                u32::try_from(DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS)
                    .expect("proposal capacity fits u32"),
            )
            .await
            .expect("hold every proposal before client_write_ff");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        let mut dead_callers = (0..2)
            .map(|_| {
                let store = store.clone();
                tokio::spawn(async move { store.logical_read_time_before(None, deadline).await })
            })
            .collect::<Vec<_>>();
        tokio::time::timeout(Duration::from_secs(1), async {
            while store.inner.logical_read_time.admission.available_permits()
                > DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY - dead_callers.len()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dead cohort reaches bounded supervisor admission");
        for caller in &dead_callers {
            caller.abort();
        }
        for caller in dead_callers.drain(..) {
            let _ = caller.await;
        }
        let dead_permits = tokio::time::timeout(
            Duration::from_secs(1),
            Arc::clone(&store.inner.logical_read_time.admission).acquire_many_owned(
                u32::try_from(DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY)
                    .expect("logical-read admission capacity fits u32"),
            ),
        )
        .await
        .expect("all-dead preproposal cohort releases its admissions")
        .expect("logical-read admission remains open");
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before),
            "a cohort with no live reply authority appends no consensus command"
        );
        drop(dead_permits);

        let dead_store = store.clone();
        let dead =
            tokio::spawn(async move { dead_store.logical_read_time_before(None, deadline).await });
        let live_store = store.clone();
        let live =
            tokio::spawn(async move { live_store.logical_read_time_before(None, deadline).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while store.inner.logical_read_time.admission.available_permits()
                > DURABLE_OPENRAFT_LINEARIZABILITY_ADMISSION_CAPACITY - 2
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("mixed cohort reaches bounded supervisor admission");
        dead.abort();
        let _ = dead.await;
        drop(held_proposals);
        let _live_result = tokio::time::timeout(Duration::from_secs(1), live)
            .await
            .expect("mixed cohort live caller completes")
            .expect("join mixed cohort live caller")
            .expect("mixed cohort logical-time proposal succeeds");
        assert_eq!(
            store.inner.raft.metrics().borrow().last_log_index,
            Some(before + 1),
            "one live member causes exactly one logical-time proposal"
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
