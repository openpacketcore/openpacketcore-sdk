//! Production session store coordinated exclusively by Openraft.
//!
//! Session payload sealing remains an outer adapter concern. Commands admitted
//! here contain only already-enveloped records; the consensus engine, network,
//! log store, snapshots, and state machine never receive an HKMS provider,
//! plaintext key, or plaintext session payload.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::{self, BoxStream, StreamExt};
use opc_consensus::engine::error::{ClientWriteError, InitializeError, RaftError};
use opc_consensus::engine::{EmptyNode, LogId, StoredMembership};
use opc_consensus::{
    decode_bounded, durable_openraft_config, encode_bounded, DurableOpenraftDomain,
    EnsureLinearizableOutcome, EnsureLinearizableSupervisor, LinearizableReadBarrier,
    LinearizableReadBarrierError, LinearizableReadLease, DURABLE_CONSENSUS_OPERATION_TIMEOUT,
    DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
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
    fenced_mutation_roster_outer_request_id, fenced_mutation_roster_terminal_outer_request_id,
    fenced_mutation_roster_voter_set_digest, fenced_transition_voter_set_digest,
    ManagedProviderJobMutationOutcome,
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
    derive_fenced_mutation_roster_scope_for_consumer, SessionConsumerAuthorizationManifest,
    SessionConsumerBatchResult, SessionConsumerChange, SessionConsumerFencedMutationRosterProfile,
    SessionConsumerFencedTransitionError, SessionConsumerIdentity, SessionConsumerOperation,
    SessionConsumerOutcomeUnknown, SessionConsumerRejection, SessionConsumerRequest,
    SessionConsumerResponse, SessionConsumerScope, SessionConsumerStoreError,
    SessionConsumerV2FencedTransitionError, SessionConsumerV2FencedTransitionStatus,
    SessionConsumerV2Operation, SessionConsumerV2Request, SessionConsumerV2Response,
    SessionConsumerV3Operation, SessionConsumerV3Request, SessionConsumerV3Response,
    SessionConsumerV4Request, SessionConsumerV4Response, SessionQuorumConsumer,
    MAX_SESSION_CONSUMER_BATCH_RESPONSE_BYTES,
};
use crate::error::{LeaseError, StoreError};
use crate::fenced_mutation_roster::{
    fenced_mutation_roster_managed_provider_v5_profile_digest,
    fenced_mutation_roster_profile_digest, FencedMutationRosterAdmission,
    FencedMutationRosterCapability, FencedMutationRosterError, FencedMutationRosterHistoryState,
    FencedMutationRosterManagedProviderV5Capability, FencedMutationRosterMemberAttestation,
    FencedMutationRosterMemberAttestationError, FencedMutationRosterMemberAttestationVerifier,
    FencedMutationRosterMemberExecutionContext, FencedMutationRosterMemberExecutionError,
    FencedMutationRosterMemberProof, FencedMutationRosterMemberProvider,
    FencedMutationRosterOrdinal, FencedMutationRosterOutcome, FencedMutationRosterPhase,
    FencedMutationRosterProtectedPlan, FencedMutationRosterRequestId, FencedMutationRosterStatus,
    FencedMutationRosterTerminal, FENCED_MUTATION_ROSTER_ADMISSION_CODEC_MAX_BYTES,
    FENCED_MUTATION_ROSTER_SCHEMA_V2, FENCED_MUTATION_ROSTER_TERMINAL_CODEC_MAX_BYTES,
};
use crate::fenced_transition::{
    AtomicFencedTransitionCapability, FencedTransitionExecuteError, FencedTransitionObservation,
    FencedTransitionOutcome, FencedTransitionRequest, FencedTransitionStatus,
    FencedTransitionV2Capability, FencedTransitionV2HistoryEpoch, FencedTransitionV2HistoryState,
    FencedTransitionV2Request, FencedTransitionV2Status, PreparedFencedTransition,
    PreparedFencedTransitionProtection, FENCED_TRANSITION_SCHEMA_V1, FENCED_TRANSITION_SCHEMA_V2,
    FENCED_TRANSITION_V2_CONSENSUS_SCHEMA_VERSION, FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
    FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES,
    FENCED_TRANSITION_V2_MIN_CONSENSUS_RPC_PAYLOAD_BYTES,
    FENCED_TRANSITION_V2_MIN_DURABLE_LOG_ENTRY_BYTES,
};
use crate::lease::{LeaseGuard, SessionLeaseManager};
use crate::managed_provider_job::{
    ManagedProviderJobAuthority, ManagedProviderJobEffectStart, ManagedProviderJobFacade,
    ManagedProviderJobId, ManagedProviderJobMemberPhase, ManagedProviderJobMode,
    ManagedProviderJobRemoteProvider, ManagedProviderJobStatus, ManagedProviderJobStore,
    ManagedProviderJobVerifiedReceipt,
};
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

const FENCED_MUTATION_ROSTER_V4_REQUEST_RESERVATION_DOMAIN: &[u8] =
    b"opc-session-store/fenced-mutation-roster/v4-verifier-request/v1";
const FENCED_MUTATION_ROSTER_V4_WORKER_RESERVATION_DOMAIN: &[u8] =
    b"opc-session-store/fenced-mutation-roster/v4-verifier-worker/v1";

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
const CONSUMER_WATCH_SCOPE_RECHECK_INTERVAL: Duration = Duration::from_millis(50);
const GENERIC_WATCH_AUTHORITY_RECHECK_INTERVAL: Duration = Duration::from_millis(50);
const TOPOLOGY_ENDPOINT_BINDING_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-endpoint-binding/v1\0";
const TOPOLOGY_TLS_BINDING_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-tls-binding/v1\0";
const TOPOLOGY_BACKING_BINDING_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-backing-binding/v1\0";
const FENCED_MUTATION_ROSTER_CAPABILITY_PROBE_MAGIC: [u8; 8] = *b"OPCFMRCP";
const FENCED_MUTATION_ROSTER_CAPABILITY_REPLY_MAGIC: [u8; 8] = *b"OPCFMRCR";
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

#[derive(Clone, Copy)]
struct LocalProposalAuthority {
    origin: SessionConsensusNodeId,
    allows_operator_recovery: bool,
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

/// Roster's exact-profile probe is intentionally a distinct ReadBarrier
/// payload.  A V1/V2-only voter cannot decode it and therefore cannot be
/// counted as compatible during roster admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FencedMutationRosterCapabilityProbe {
    /// Unique frame marker: structurally similar V2 probes must not decode as
    /// roster support merely because they have a schema and digest field.
    magic: [u8; 8],
    schema_version: u16,
    profile_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum FencedMutationRosterCapabilityReply {
    V2 {
        magic: [u8; 8],
        profile_digest: [u8; 32],
    },
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedProviderV5CapabilityProbe {
    magic: [u8; 8],
    schema_version: u16,
    profile_digest: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum ManagedProviderV5CapabilityReply {
    V5 {
        magic: [u8; 8],
        profile_digest: [u8; 32],
    },
    Unsupported,
}

const MANAGED_PROVIDER_V5_CAPABILITY_SCHEMA_VERSION: u16 = 5;
const MANAGED_PROVIDER_V5_CAPABILITY_PROBE_MAGIC: [u8; 8] = *b"OPCMV5CP";
const MANAGED_PROVIDER_V5_CAPABILITY_REPLY_MAGIC: [u8; 8] = *b"OPCMV5CR";

fn managed_provider_v5_capability_probe_reply(
    probe: ManagedProviderV5CapabilityProbe,
    local_capability: Option<FencedMutationRosterManagedProviderV5Capability>,
) -> ManagedProviderV5CapabilityReply {
    let profile_digest = fenced_mutation_roster_managed_provider_v5_profile_digest();
    if probe.magic == MANAGED_PROVIDER_V5_CAPABILITY_PROBE_MAGIC
        && probe.schema_version == MANAGED_PROVIDER_V5_CAPABILITY_SCHEMA_VERSION
        && probe.profile_digest == profile_digest
        && local_capability == Some(FencedMutationRosterManagedProviderV5Capability::V5)
    {
        ManagedProviderV5CapabilityReply::V5 {
            magic: MANAGED_PROVIDER_V5_CAPABILITY_REPLY_MAGIC,
            profile_digest,
        }
    } else {
        ManagedProviderV5CapabilityReply::Unsupported
    }
}

fn fenced_mutation_roster_capability_probe_reply(
    probe: FencedMutationRosterCapabilityProbe,
    local_capability: Option<FencedMutationRosterCapability>,
) -> FencedMutationRosterCapabilityReply {
    let profile_digest = fenced_mutation_roster_profile_digest();
    if probe.magic == FENCED_MUTATION_ROSTER_CAPABILITY_PROBE_MAGIC
        && probe.schema_version == FENCED_MUTATION_ROSTER_SCHEMA_V2
        && probe.profile_digest == profile_digest
        && local_capability == Some(FencedMutationRosterCapability::V2)
    {
        FencedMutationRosterCapabilityReply::V2 {
            magic: FENCED_MUTATION_ROSTER_CAPABILITY_REPLY_MAGIC,
            profile_digest,
        }
    } else {
        FencedMutationRosterCapabilityReply::Unsupported
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

/// Roster compatibility is either its independently persisted exact-scope
/// certificate or a fresh unanimous proof over the current voters. It
/// deliberately has no V2 lifecycle coupling and is never inferred from a
/// quorum response or an older transition certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FencedMutationRosterCapabilityAdmission {
    /// The independently persisted certificate is still bound to this exact
    /// current voter scope and roster profile.
    Activated,
    /// Every current voter just returned the uniquely framed roster reply.
    FreshUnanimous,
}

/// Managed V5 has no reusable durable activation certificate. Every managed
/// command must observe a fresh exact all-voter acknowledgement of the V5
/// wire and applied-digest profile before it can reach proposal admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManagedProviderV5CapabilityAdmission {
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
    proposal_admission: Arc<tokio::sync::Semaphore>,
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

/// One-use, store-owned authority to obtain an opaque member proof.
///
/// This capability is created only by [`ConsensusSessionStore`] after it
/// verifies the authenticated consumer scope, exact durable `PollAdmitted`
/// receipt, canonical member ordinal, and admitted fence. It is deliberately
/// neither constructible nor clonable by consumers. Each execution consumes
/// the authority and revalidates the same durable receipt after provider I/O
/// before issuing an opaque proof.
pub struct FencedMutationRosterMemberExecutionAuthority {
    store: ConsensusSessionStore,
    scope: SessionConsumerScope,
    admission: FencedMutationRosterAdmission,
    ordinal: FencedMutationRosterOrdinal,
}

impl fmt::Debug for FencedMutationRosterMemberExecutionAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedMutationRosterMemberExecutionAuthority(<redacted>)")
    }
}

impl FencedMutationRosterMemberExecutionAuthority {
    fn context(
        &self,
    ) -> Result<FencedMutationRosterMemberExecutionContext<'_>, FencedMutationRosterError> {
        self.admission.validate()?;
        let member = self
            .admission
            .members()
            .as_slice()
            .iter()
            .find(|member| member.ordinal() == self.ordinal)
            .ok_or(FencedMutationRosterError::LifecycleConflict)?;
        Ok(FencedMutationRosterMemberExecutionContext::new(
            &self.admission,
            member,
        ))
    }

    async fn revalidate_current_receipt(&self) -> Result<(), StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.store.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        let status = self
            .store
            .consumer_fenced_mutation_roster_status(self.scope, &self.admission, deadline)
            .await?;
        if status.phase() != FencedMutationRosterPhase::PollAdmitted
            || status.request_id() != self.admission.request_id()
        {
            return Err(StoreError::InvalidKey(
                "fenced_mutation_roster_member_not_poll_admitted".into(),
            ));
        }
        Ok(())
    }

    /// Execute one member and issue a proof only after both durable receipt
    /// validations succeed.
    pub async fn execute_member<P>(
        self,
        provider: &P,
    ) -> Result<FencedMutationRosterMemberProof, FencedMutationRosterMemberExecutionError<P::Error>>
    where
        P: FencedMutationRosterMemberProvider + ?Sized,
    {
        let context = self
            .context()
            .map_err(FencedMutationRosterMemberExecutionError::Context)?;
        self.revalidate_current_receipt()
            .await
            .map_err(FencedMutationRosterMemberExecutionError::Authority)?;
        let outcome = provider
            .execute_member(&context)
            .await
            .map_err(FencedMutationRosterMemberExecutionError::Provider)?;
        self.revalidate_current_receipt()
            .await
            .map_err(FencedMutationRosterMemberExecutionError::Authority)?;
        Ok(FencedMutationRosterMemberProof::issue(&context, outcome))
    }

    /// Read one member's durable evidence and issue a proof only after both
    /// durable receipt validations succeed.
    pub async fn member_status<P>(
        self,
        provider: &P,
    ) -> Result<FencedMutationRosterMemberProof, FencedMutationRosterMemberExecutionError<P::Error>>
    where
        P: FencedMutationRosterMemberProvider + ?Sized,
    {
        let context = self
            .context()
            .map_err(FencedMutationRosterMemberExecutionError::Context)?;
        self.revalidate_current_receipt()
            .await
            .map_err(FencedMutationRosterMemberExecutionError::Authority)?;
        let outcome = provider
            .member_status(&context)
            .await
            .map_err(FencedMutationRosterMemberExecutionError::Provider)?;
        self.revalidate_current_receipt()
            .await
            .map_err(FencedMutationRosterMemberExecutionError::Authority)?;
        Ok(FencedMutationRosterMemberProof::issue(&context, outcome))
    }

    /// Reconcile one member and issue a proof only after both durable receipt
    /// validations succeed.
    pub async fn adopt_member<P>(
        self,
        provider: &P,
    ) -> Result<FencedMutationRosterMemberProof, FencedMutationRosterMemberExecutionError<P::Error>>
    where
        P: FencedMutationRosterMemberProvider + ?Sized,
    {
        let context = self
            .context()
            .map_err(FencedMutationRosterMemberExecutionError::Context)?;
        self.revalidate_current_receipt()
            .await
            .map_err(FencedMutationRosterMemberExecutionError::Authority)?;
        let outcome = provider
            .adopt_member(&context)
            .await
            .map_err(FencedMutationRosterMemberExecutionError::Provider)?;
        self.revalidate_current_receipt()
            .await
            .map_err(FencedMutationRosterMemberExecutionError::Authority)?;
        Ok(FencedMutationRosterMemberProof::issue(&context, outcome))
    }

    /// Verify remote worker evidence and issue a private proof only after the
    /// verifier and both durable receipt checks succeed.
    ///
    /// The verifier is server-configured. It receives the authenticated mTLS
    /// identity and must cryptographically bind it to this exact context; the
    /// serializable attestation is otherwise only untrusted input.
    async fn verify_member_attestation(
        self,
        identity: &SessionConsumerIdentity,
        verifier: &dyn FencedMutationRosterMemberAttestationVerifier,
        attestation: &FencedMutationRosterMemberAttestation,
    ) -> Result<
        FencedMutationRosterMemberProof,
        FencedMutationRosterMemberExecutionError<FencedMutationRosterMemberAttestationError>,
    > {
        let context = self
            .context()
            .map_err(FencedMutationRosterMemberExecutionError::Context)?;
        attestation
            .validate_for(&context)
            .map_err(FencedMutationRosterMemberExecutionError::Context)?;
        self.revalidate_current_receipt()
            .await
            .map_err(FencedMutationRosterMemberExecutionError::Authority)?;
        let outcome = verifier
            .verify_member_attestation(identity, &context, attestation)
            .await
            .map_err(FencedMutationRosterMemberExecutionError::Provider)?;
        if outcome != attestation.outcome() {
            return Err(FencedMutationRosterMemberExecutionError::Provider(
                FencedMutationRosterMemberAttestationError::Rejected,
            ));
        }
        self.revalidate_current_receipt()
            .await
            .map_err(FencedMutationRosterMemberExecutionError::Authority)?;
        Ok(FencedMutationRosterMemberProof::issue(&context, outcome))
    }
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
    attestation_verifier: Option<Arc<dyn FencedMutationRosterMemberAttestationVerifier>>,
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

fn managed_provider_status(mode: u8, phase: u8) -> Result<ManagedProviderJobStatus, StoreError> {
    let mode = match mode {
        0 => ManagedProviderJobMode::Unselected,
        1 => ManagedProviderJobMode::FrozenV4Terminal,
        // Mode 3 is the managed terminal claim. A terminal command returns
        // its terminal phase, while an exact replay returns phase zero and
        // the subsequent durable member lookup supplies the terminal phase.
        // Neither is a predecessor V4 terminal.
        3 => ManagedProviderJobMode::ManagedV5,
        2 => ManagedProviderJobMode::ManagedV5,
        _ => return Err(consensus_unavailable()),
    };
    let phase = match phase {
        0 => ManagedProviderJobMemberPhase::Ready,
        1 => ManagedProviderJobMemberPhase::EffectStarted,
        2 => ManagedProviderJobMemberPhase::Verified,
        3 => ManagedProviderJobMemberPhase::ReconciliationRequired,
        4 => ManagedProviderJobMemberPhase::Established,
        5 => ManagedProviderJobMemberPhase::Aborted,
        _ => return Err(consensus_unavailable()),
    };
    Ok(ManagedProviderJobStatus::new(mode, phase))
}

#[async_trait]
impl ManagedProviderJobStore for ConsensusSessionStore {
    type Error = StoreError;

    async fn ensure_job(
        &self,
        admission: &FencedMutationRosterAdmission,
        checkpoint: &[u8],
        authority: ManagedProviderJobAuthority,
    ) -> Result<ManagedProviderJobStatus, Self::Error> {
        admission
            .validate()
            .map_err(|_| StoreError::InvalidKey("managed_provider_admission_invalid".into()))?;
        let checkpoint =
            FencedMutationRosterProtectedPlan::new(checkpoint.to_vec().into_boxed_slice())
                .map_err(|_| {
                    StoreError::InvalidKey("managed_provider_checkpoint_invalid".into())
                })?;
        let scope = authority.scope();
        if scope.consensus_identity() != self.current_scope()?.0 {
            return Err(StoreError::TopologyAuthorityRevoked);
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        // A managed facade is deliberately not a roster-admission API. Its
        // exact immutable body must already have passed the authenticated V3
        // consumer admission path; otherwise ensure must not create an
        // operation, claim, job row, or authority commitment.
        let admitted = self
            .managed_provider_admission(admission.request_id(), scope, deadline)
            .await?;
        if admitted != *admission {
            return Err(StoreError::InvalidKey(
                "managed_provider_admission_conflict".into(),
            ));
        }
        let response = self
            .submit_request_before(
                SessionConsensusRequestId::new(),
                SessionMutationIntent::EnsureManagedProviderJob {
                    admission: Box::new(admission.clone()),
                    protected_checkpoint: checkpoint,
                    worker_digest: authority.worker_identity_commitment(),
                    verifier_digest: authority.verifier_identity_commitment(),
                },
                Some(scope.consensus_identity()),
                deadline,
            )
            .await?;
        match response.result? {
            SessionMutationOutcome::ManagedProviderJob(outcome) => {
                managed_provider_status(outcome.mode, outcome.phase)
            }
            _ => Err(consensus_unavailable()),
        }
    }

    async fn job_status(
        &self,
        id: ManagedProviderJobId,
        authority: ManagedProviderJobAuthority,
    ) -> Result<ManagedProviderJobStatus, Self::Error> {
        let scope = authority.scope();
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.logical_read_time_before(Some(scope.consensus_identity()), deadline)
            .await?;
        let (mode, phase) = self
            .inner
            .backend
            .consensus_managed_provider_job_status(
                self.inner.storage_identity,
                id.roster().to_bytes(),
                id.ordinal().get(),
                authority.worker_identity_commitment(),
            )
            .await?;
        managed_provider_status(mode, phase)
    }

    async fn mark_member_effect_started(
        &self,
        id: ManagedProviderJobId,
        authority: ManagedProviderJobAuthority,
    ) -> Result<ManagedProviderJobEffectStart, Self::Error> {
        let scope = authority.scope();
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        let admission = self
            .managed_provider_admission(id.roster(), scope, deadline)
            .await?;
        let response = self
            .submit_request_before(
                SessionConsensusRequestId::new(),
                SessionMutationIntent::StartManagedProviderMember {
                    admission: Box::new(admission),
                    ordinal: id.ordinal().get(),
                    worker_digest: authority.worker_identity_commitment(),
                },
                Some(scope.consensus_identity()),
                deadline,
            )
            .await?;
        match response.result? {
            SessionMutationOutcome::ManagedProviderJob(outcome) if outcome.execute => {
                Ok(ManagedProviderJobEffectStart::Execute)
            }
            SessionMutationOutcome::ManagedProviderJob(outcome) => {
                Ok(ManagedProviderJobEffectStart::Existing(
                    managed_provider_status(outcome.mode, outcome.phase)?,
                ))
            }
            _ => Err(consensus_unavailable()),
        }
    }

    async fn record_verified_attestation(
        &self,
        id: ManagedProviderJobId,
        receipt: ManagedProviderJobVerifiedReceipt,
        authority: ManagedProviderJobAuthority,
    ) -> Result<ManagedProviderJobStatus, Self::Error> {
        let scope = authority.scope();
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        let admission = self
            .managed_provider_admission(id.roster(), scope, deadline)
            .await?;
        let response = self
            .submit_request_before(
                SessionConsensusRequestId::new(),
                SessionMutationIntent::RecordManagedProviderReceipt {
                    admission: Box::new(admission),
                    ordinal: id.ordinal().get(),
                    worker_digest: authority.worker_identity_commitment(),
                    verifier_digest: authority.verifier_identity_commitment(),
                    receipt_digest: receipt.digest(),
                    outcome: receipt.outcome() as u8,
                },
                Some(scope.consensus_identity()),
                deadline,
            )
            .await?;
        match response.result? {
            SessionMutationOutcome::ManagedProviderJob(outcome) => {
                managed_provider_status(outcome.mode, outcome.phase)
            }
            _ => Err(consensus_unavailable()),
        }
    }

    async fn finalize_job(
        &self,
        admission: &FencedMutationRosterAdmission,
        authority: ManagedProviderJobAuthority,
    ) -> Result<ManagedProviderJobStatus, Self::Error> {
        let scope = authority.scope();
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        let response = self
            .submit_request_before(
                SessionConsensusRequestId::new(),
                SessionMutationIntent::FinalizeManagedProviderJob {
                    admission: Box::new(admission.clone()),
                    worker_digest: authority.worker_identity_commitment(),
                },
                Some(scope.consensus_identity()),
                deadline,
            )
            .await?;
        match response.result? {
            SessionMutationOutcome::ManagedProviderJob(outcome) => {
                managed_provider_status(outcome.mode, outcome.phase)
            }
            _ => Err(consensus_unavailable()),
        }
    }

    async fn recover_owned_jobs(
        &self,
        authority: ManagedProviderJobAuthority,
    ) -> Result<Box<[ManagedProviderJobId]>, Self::Error> {
        let scope = authority.scope();
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.logical_read_time_before(Some(scope.consensus_identity()), deadline)
            .await?;
        self.inner
            .backend
            .consensus_managed_provider_recovery_jobs(
                self.inner.storage_identity,
                authority.worker_identity_commitment(),
            )
            .await?
            .into_iter()
            .map(|(request_id, ordinal)| {
                let roster = crate::decode_fenced_mutation_roster_identity(&request_id)
                    .map_err(|_| consensus_unavailable())?;
                let ordinal = FencedMutationRosterOrdinal::new(ordinal)
                    .map_err(|_| consensus_unavailable())?;
                Ok(ManagedProviderJobId::for_member(roster, ordinal))
            })
            .collect::<Result<Vec<_>, StoreError>>()
            .map(Vec::into_boxed_slice)
    }

    async fn abort_not_applied(
        &self,
        id: ManagedProviderJobId,
        authority: ManagedProviderJobAuthority,
    ) -> Result<ManagedProviderJobStatus, Self::Error> {
        let scope = authority.scope();
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        let admission = self
            .managed_provider_admission(id.roster(), scope, deadline)
            .await?;
        let response = self
            .submit_request_before(
                SessionConsensusRequestId::new(),
                SessionMutationIntent::AbortManagedProviderNotApplied {
                    admission: Box::new(admission),
                    ordinal: id.ordinal().get(),
                    worker_digest: authority.worker_identity_commitment(),
                },
                Some(scope.consensus_identity()),
                deadline,
            )
            .await?;
        match response.result? {
            SessionMutationOutcome::ManagedProviderJob(outcome) => {
                managed_provider_status(outcome.mode, outcome.phase)
            }
            _ => Err(consensus_unavailable()),
        }
    }

    async fn require_reconciliation(
        &self,
        id: ManagedProviderJobId,
        authority: ManagedProviderJobAuthority,
    ) -> Result<ManagedProviderJobStatus, Self::Error> {
        let scope = authority.scope();
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        let admission = self
            .managed_provider_admission(id.roster(), scope, deadline)
            .await?;
        let response = self
            .submit_request_before(
                SessionConsensusRequestId::new(),
                SessionMutationIntent::RequireManagedProviderReconciliation {
                    admission: Box::new(admission),
                    ordinal: id.ordinal().get(),
                    worker_digest: authority.worker_identity_commitment(),
                },
                Some(scope.consensus_identity()),
                deadline,
            )
            .await?;
        match response.result? {
            SessionMutationOutcome::ManagedProviderJob(outcome) => {
                managed_provider_status(outcome.mode, outcome.phase)
            }
            _ => Err(consensus_unavailable()),
        }
    }
}

impl ConsensusSessionStore {
    /// Create the only public managed-provider execution surface.
    ///
    /// This factory belongs at authenticated server composition: `scope`,
    /// `worker`, and both commitments must come from that layer, never from a
    /// request. The returned facade owns these fixed dependencies and exposes
    /// no authority token or component-selection API.
    pub fn managed_provider_job_facade<P, V>(
        &self,
        scope: SessionConsumerScope,
        worker: SessionConsumerIdentity,
        worker_identity_commitment: [u8; 32],
        verifier_identity_commitment: [u8; 32],
        provider: P,
        verifier: V,
    ) -> Result<ManagedProviderJobFacade, StoreError>
    where
        P: ManagedProviderJobRemoteProvider + 'static,
        V: FencedMutationRosterMemberAttestationVerifier + 'static,
    {
        let authority = Self::managed_provider_job_authority(
            scope,
            worker_identity_commitment,
            verifier_identity_commitment,
        )?;
        Ok(ManagedProviderJobFacade::new(
            self.clone(),
            provider,
            verifier,
            worker,
            authority,
        ))
    }

    /// Mint the opaque managed-job authority only at authenticated server
    /// composition.  The worker and verifier commitments are never sourced
    /// from a managed request body.
    #[doc(hidden)]
    #[allow(dead_code)] // consumed by the crate-private authenticated server composition.
    pub(crate) fn managed_provider_job_authority(
        scope: SessionConsumerScope,
        worker_identity_commitment: [u8; 32],
        verifier_identity_commitment: [u8; 32],
    ) -> Result<ManagedProviderJobAuthority, StoreError> {
        if worker_identity_commitment == [0; 32] || verifier_identity_commitment == [0; 32] {
            return Err(StoreError::InvalidKey(
                "managed_provider_authority_invalid".into(),
            ));
        }
        Ok(ManagedProviderJobAuthority::from_authenticated_scope(
            scope,
            worker_identity_commitment,
            verifier_identity_commitment,
        ))
    }

    async fn managed_provider_admission(
        &self,
        request_id: FencedMutationRosterRequestId,
        scope: SessionConsumerScope,
        deadline: tokio::time::Instant,
    ) -> Result<FencedMutationRosterAdmission, StoreError> {
        self.logical_read_time_before(Some(scope.consensus_identity()), deadline)
            .await?;
        let admission = self
            .inner
            .backend
            .consensus_managed_provider_admission(
                self.inner.storage_identity,
                request_id.to_bytes(),
            )
            .await?;
        if scope.consensus_identity() != self.current_scope()?.0 {
            return Err(StoreError::TopologyAuthorityRevoked);
        }
        Ok(admission)
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
            LinearizableReadLease::Disabled,
        );
        let topology_summary = topology.summary().clone();
        let topology_attestation_time_high_water = topology_summary
            .attestation_admission()
            .production_verified_at()
            .map(TopologyAttestationTime::unix_seconds)
            .unwrap_or(0);

        Ok(Self {
            inner: Arc::new(ConsensusSessionStoreInner {
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
                proposal_admission: Arc::new(tokio::sync::Semaphore::new(
                    DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
                )),
            }),
        })
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
            LinearizableReadLease::Disabled,
        );
        let topology_summary = topology.summary().clone();
        let topology_attestation_time_high_water = topology_summary
            .attestation_admission()
            .production_verified_at()
            .map(TopologyAttestationTime::unix_seconds)
            .unwrap_or(0);

        Ok(Self {
            inner: Arc::new(ConsensusSessionStoreInner {
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
                proposal_admission: Arc::new(tokio::sync::Semaphore::new(
                    DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
                )),
            }),
        })
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
            attestation_verifier: None,
        }
    }

    /// Build the revision-6 capability with its verifier fixed at composition
    /// time. Network listeners receive only this configured capability and
    /// therefore cannot select or replace the verifier per call.
    pub fn consumer_service_with_attestation_verifier(
        &self,
        verifier: Arc<dyn FencedMutationRosterMemberAttestationVerifier>,
    ) -> ConsensusSessionConsumerService {
        ConsensusSessionConsumerService {
            store: self.clone(),
            attestation_verifier: Some(verifier),
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

    fn local_fenced_mutation_roster_capability(&self) -> Option<FencedMutationRosterCapability> {
        // Roster commands are persisted by this concrete SQLite consensus
        // state machine.  Do not derive support from V1/V2 transition bits:
        // its profile carries independent arity, protected-body, retention,
        // and lifecycle rules.  The entire canonical admission still has to
        // fit both authenticated forwarding and the durable log.
        if SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES
            >= FENCED_MUTATION_ROSTER_ADMISSION_CODEC_MAX_BYTES
            && self.inner.backend.consensus_log_entry_max_bytes()
                >= FENCED_MUTATION_ROSTER_ADMISSION_CODEC_MAX_BYTES
            && SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES
                >= FENCED_MUTATION_ROSTER_TERMINAL_CODEC_MAX_BYTES
            && self.inner.backend.consensus_log_entry_max_bytes()
                >= FENCED_MUTATION_ROSTER_TERMINAL_CODEC_MAX_BYTES
        {
            Some(FencedMutationRosterCapability::V2)
        } else {
            None
        }
    }

    fn local_managed_provider_v5_capability(
        &self,
    ) -> Option<FencedMutationRosterManagedProviderV5Capability> {
        // V5's proof is not inferred from the roster's activation certificate:
        // this local check only establishes that this exact binary can carry
        // the bounded command shape. Peer compatibility is proved separately
        // by the V5-only probe immediately before every proposal.
        self.local_fenced_mutation_roster_capability()
            .map(|_| FencedMutationRosterManagedProviderV5Capability::V5)
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

    /// Require the independently certified roster profile at the exact
    /// current voter scope, or obtain a fresh all-voter acknowledgement. A
    /// profile-mismatched voter must make a new admission fail before its
    /// command reaches a leader proposal.
    async fn require_fenced_mutation_roster_capability_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<FencedMutationRosterCapabilityAdmission, StoreError> {
        self.require_exact_membership_admission()?;
        self.linearizable_barrier_before(deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        let expected_scope = self.current_scope()?;
        if self.local_fenced_mutation_roster_capability()
            != Some(FencedMutationRosterCapability::V2)
        {
            return Err(unsupported_fenced_mutation_roster());
        }
        if !expected_scope.1.contains(&self.inner.local_node_id) {
            return Err(consensus_unavailable());
        }
        let profile_digest = fenced_mutation_roster_profile_digest();
        // A prior Admit is the only durable roster profile certificate. It is
        // valid only while it names this precise scope; topology cutover
        // clears it without touching PollAdmitted history. Do not borrow V2's
        // certificate or infer this result from a quorum reply.
        if self
            .inner
            .backend
            .consensus_fenced_mutation_roster_activation_matches_scope(
                self.inner.storage_identity,
                expected_scope.0,
                &expected_scope.1,
                profile_digest,
            )
            .await?
        {
            if self.current_scope()? == expected_scope && self.exact_membership_is_admitted() {
                return Ok(FencedMutationRosterCapabilityAdmission::Activated);
            }
            return Err(consensus_unavailable());
        }
        let probes = expected_scope
            .1
            .iter()
            .copied()
            .filter(|member| *member != self.inner.local_node_id)
            .map(|member| async move {
                self.call_peer::<_, FencedMutationRosterCapabilityReply>(
                    member,
                    SessionConsensusRpcFamily::ReadBarrier,
                    &FencedMutationRosterCapabilityProbe {
                        magic: FENCED_MUTATION_ROSTER_CAPABILITY_PROBE_MAGIC,
                        schema_version: FENCED_MUTATION_ROSTER_SCHEMA_V2,
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
                    Ok(FencedMutationRosterCapabilityReply::V2 {
                        magic,
                        profile_digest: received,
                    }) if magic == FENCED_MUTATION_ROSTER_CAPABILITY_REPLY_MAGIC
                        && received == profile_digest
                )
            })
        {
            return Err(unsupported_fenced_mutation_roster());
        }
        if self.current_scope()? != expected_scope || !self.exact_membership_is_admitted() {
            return Err(consensus_unavailable());
        }
        Ok(FencedMutationRosterCapabilityAdmission::FreshUnanimous)
    }

    async fn require_managed_provider_v5_capability_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<ManagedProviderV5CapabilityAdmission, StoreError> {
        self.require_exact_membership_admission()?;
        self.linearizable_barrier_before(deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        let expected_scope = self.current_scope()?;
        if self.local_managed_provider_v5_capability()
            != Some(FencedMutationRosterManagedProviderV5Capability::V5)
            || !expected_scope.1.contains(&self.inner.local_node_id)
        {
            return Err(unsupported_fenced_mutation_roster());
        }
        let profile_digest = fenced_mutation_roster_managed_provider_v5_profile_digest();
        let probes = expected_scope
            .1
            .iter()
            .copied()
            .filter(|member| *member != self.inner.local_node_id)
            .map(|member| async move {
                self.call_peer::<_, ManagedProviderV5CapabilityReply>(
                    member,
                    SessionConsensusRpcFamily::ReadBarrier,
                    &ManagedProviderV5CapabilityProbe {
                        magic: MANAGED_PROVIDER_V5_CAPABILITY_PROBE_MAGIC,
                        schema_version: MANAGED_PROVIDER_V5_CAPABILITY_SCHEMA_VERSION,
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
                    Ok(ManagedProviderV5CapabilityReply::V5 {
                        magic,
                        profile_digest: received,
                    }) if magic == MANAGED_PROVIDER_V5_CAPABILITY_REPLY_MAGIC
                        && received == profile_digest
                )
            })
        {
            return Err(unsupported_fenced_mutation_roster());
        }
        if self.current_scope()? != expected_scope || !self.exact_membership_is_admitted() {
            return Err(consensus_unavailable());
        }
        Ok(ManagedProviderV5CapabilityAdmission::FreshUnanimous)
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
        request.validate()?;
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
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
        let request_id = fenced_transition_v2_outer_request_id(&request);
        let response = self
            .submit_request_before(
                request_id,
                SessionMutationIntent::FencedTransitionV2(Box::new(request)),
                None,
                deadline,
            )
            .await?;
        match response.result? {
            SessionMutationOutcome::FencedTransition(outcome) => Ok(outcome),
            _ => Err(StoreError::FencedTransitionOutcomeUnknown),
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
            | ForwardMutationReply::Unavailable
            | ForwardMutationReply::RecordExpiryPreflight(_) => Err(consensus_unavailable()),
        }
    }

    /// Read roster terminal-history state at a linearized exact voter scope.
    ///
    /// The result is the complete compare-and-set snapshot accepted by
    /// [`Self::maintain_fenced_mutation_roster_history`]. This state-process
    /// API is deliberately not a consumer RPC or forwarding operation.
    pub async fn fenced_mutation_roster_history_state(
        &self,
    ) -> Result<FencedMutationRosterHistoryState, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        self.require_fenced_mutation_roster_capability_before(deadline)
            .await?;
        self.logical_read_time_before(None, deadline).await?;
        let (authority_identity, _) = self.current_scope()?;
        let state = self
            .inner
            .backend
            .consensus_fenced_mutation_roster_history_state(
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

    /// Run one deterministic, bounded roster-history maintenance step as the
    /// local operator authority.
    ///
    /// This is intentionally absent from consumer and remote-forwarding
    /// surfaces. It can only originate on the current local leader after a
    /// durable fixed-quorum admission; raw maintenance intents are rejected
    /// unless this boundary supplies the internal operator marker.
    pub async fn maintain_fenced_mutation_roster_history(
        &self,
        expected_state: FencedMutationRosterHistoryState,
    ) -> Result<FencedMutationRosterHistoryState, StoreError> {
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
                    intent: SessionMutationIntent::MaintainFencedMutationRosterHistory {
                        expected_generation: expected_state.generation,
                        expected_active_epoch: expected_state.active_epoch,
                        expected_retired_through: expected_state.retired_through,
                        expected_bound_entries: expected_state.bound,
                        expected_live_entries: expected_state.live,
                    },
                    required_consumer_scope: ForwardConsumerScope::Internal,
                },
                self.inner.local_node_id,
                deadline,
                true,
            )
            .await;
        match reply {
            ForwardMutationReply::Applied(response)
                if matches!(response.result, Ok(SessionMutationOutcome::Unit)) =>
            {
                self.inner
                    .backend
                    .consensus_fenced_mutation_roster_history_state(
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

    /// Obtain the one-use SDK authority required to issue one roster member
    /// proof from a provider's durable evidence.
    ///
    /// The authenticated `identity` must be supplied by the consumer mTLS
    /// boundary, not a request body. This method verifies that its derived
    /// roster scope, the current consensus scope, the exact canonical member,
    /// and the durable receipt all match before it returns the opaque
    /// authority. The authority repeats the durable receipt verification after
    /// provider I/O, so a terminalized, absent, or superseded receipt cannot
    /// yield a proof.
    pub async fn fenced_mutation_roster_member_execution_authority(
        &self,
        identity: &SessionConsumerIdentity,
        scope: SessionConsumerScope,
        admission: FencedMutationRosterAdmission,
        ordinal: FencedMutationRosterOrdinal,
    ) -> Result<FencedMutationRosterMemberExecutionAuthority, StoreError> {
        admission
            .validate()
            .map_err(|_| StoreError::InvalidKey("fenced_mutation_roster_invalid".into()))?;
        if !admission
            .members()
            .as_slice()
            .iter()
            .any(|member| member.ordinal() == ordinal)
        {
            return Err(StoreError::InvalidKey(
                "fenced_mutation_roster_member_ordinal_invalid".into(),
            ));
        }
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        let scope_admission = self.admit_consumer_scope(scope, deadline).await.map_err(
            |rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            },
        )?;
        let authority_scope = derive_fenced_mutation_roster_scope_for_consumer(
            identity,
            SessionConsumerScope::new(scope_admission.required_scope),
        );
        drop(scope_admission);
        if admission.scope() != authority_scope {
            return Err(StoreError::TopologyAuthorityRevoked);
        }
        let authority = FencedMutationRosterMemberExecutionAuthority {
            store: self.clone(),
            scope,
            admission,
            ordinal,
        };
        authority.revalidate_current_receipt().await?;
        Ok(authority)
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
        self.require_application_traffic_authority_before(deadline)
            .await?;
        validate_consensus_intent(&intent)?;
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
                        return Err(consensus_outcome_unavailable(&request.intent));
                    }
                    Err(error) => return Err(error),
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
                        if request.required_consumer_scope.is_consumer_scoped()
                            || matches!(
                                &request.intent,
                                SessionMutationIntent::FencedTransition(_)
                                    | SessionMutationIntent::FencedTransitionV2(_)
                                    | SessionMutationIntent::ActivateFencedTransitionV2 { .. }
                                    | SessionMutationIntent::AdmitFencedMutationRoster { .. }
                                    | SessionMutationIntent::TerminalizeFencedMutationRoster { .. }
                                    | SessionMutationIntent::ReserveFencedMutationRosterV4VerifierDispatch { .. }
                            )
                        {
                            return Err(consensus_outcome_unavailable(&request.intent));
                        }
                        if self.wait_for_route_refresh(leader, deadline).await.is_err() {
                            return Err(consensus_outcome_unavailable(&request.intent));
                        }
                        continue;
                    }
                    Err(ConsensusPeerCallFailure::BeforeTransmission) => {
                        if let Err(error) = self.wait_for_route_refresh(leader, deadline).await {
                            return if outcome_may_be_unavailable {
                                Err(consensus_outcome_unavailable(&request.intent))
                            } else {
                                Err(error)
                            };
                        }
                        continue;
                    }
                }
            };
            match reply {
                ForwardMutationReply::Applied(response) => {
                    if committed_response_matches_intent(&request.intent, &response) {
                        if self
                            .require_application_traffic_authority_before(deadline)
                            .await
                            .is_err()
                        {
                            return Err(consensus_outcome_unavailable(&request.intent));
                        }
                        return Ok(*response);
                    }
                    if !outcome_may_be_unavailable
                        && rejected_response_matches_intent(&request.intent, &response)
                    {
                        return match response.result {
                            Err(error) => Err(error),
                            Ok(_) => Err(consensus_outcome_unavailable(&request.intent)),
                        };
                    }
                    return Err(consensus_outcome_unavailable(&request.intent));
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
                                Err(consensus_outcome_unavailable(&request.intent))
                            } else {
                                Err(error)
                            };
                        }
                    }
                }
                ForwardMutationReply::Unavailable => {
                    if let Err(error) = self.wait_for_route_refresh(leader, deadline).await {
                        return if outcome_may_be_unavailable {
                            Err(consensus_outcome_unavailable(&request.intent))
                        } else {
                            Err(error)
                        };
                    }
                }
                ForwardMutationReply::RecordExpiryPreflight(_) => {
                    return Err(consensus_outcome_unavailable(&request.intent));
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
        self.apply_on_local_leader_inner(request, origin, deadline, false)
            .await
    }

    async fn apply_on_local_leader_inner(
        &self,
        mut request: ForwardMutationRequest,
        origin: SessionConsensusNodeId,
        deadline: tokio::time::Instant,
        allow_operator_recovery: bool,
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
        let initial_authority = if allow_operator_recovery {
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
            Ok(Err(_)) | Err(_) => return ForwardMutationReply::Unavailable,
        };

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
        ) {
            match self
                .require_fenced_transition_v2_capability_before(deadline)
                .await
            {
                Ok(FencedTransitionV2CapabilityAdmission::Activated) => {}
                Ok(FencedTransitionV2CapabilityAdmission::FreshUnanimous) => {
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
        if matches!(
            &request.intent,
            SessionMutationIntent::AdmitFencedMutationRoster { .. }
                | SessionMutationIntent::ReserveFencedMutationRosterV4VerifierDispatch { .. }
                | SessionMutationIntent::EnsureManagedProviderJob { .. }
                | SessionMutationIntent::StartManagedProviderMember { .. }
                | SessionMutationIntent::RecordManagedProviderReceipt { .. }
                | SessionMutationIntent::RequireManagedProviderReconciliation { .. }
                | SessionMutationIntent::AbortManagedProviderNotApplied { .. }
                | SessionMutationIntent::FinalizeManagedProviderJob { .. }
        ) {
            match self
                .require_fenced_mutation_roster_capability_before(deadline)
                .await
            {
                Ok(FencedMutationRosterCapabilityAdmission::Activated)
                | Ok(FencedMutationRosterCapabilityAdmission::FreshUnanimous) => {}
                Err(_) => {
                    return ForwardMutationReply::Applied(Box::new(
                        SessionConsensusResponse::rejected(unsupported_fenced_mutation_roster()),
                    ));
                }
            }
        }
        if matches!(
            &request.intent,
            SessionMutationIntent::EnsureManagedProviderJob { .. }
                | SessionMutationIntent::StartManagedProviderMember { .. }
                | SessionMutationIntent::RecordManagedProviderReceipt { .. }
                | SessionMutationIntent::RequireManagedProviderReconciliation { .. }
                | SessionMutationIntent::AbortManagedProviderNotApplied { .. }
                | SessionMutationIntent::FinalizeManagedProviderJob { .. }
        ) && self
            .require_managed_provider_v5_capability_before(deadline)
            .await
            .is_err()
        {
            return ForwardMutationReply::Applied(Box::new(SessionConsensusResponse::rejected(
                unsupported_fenced_mutation_roster(),
            )));
        }
        let logical_time = match tokio::time::timeout_at(
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
        };
        if !allow_operator_recovery
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
        if let Some((scope_identity, voter_set_digest, profile_digest)) =
            fenced_mutation_roster_admission_scope(&request.intent)
        {
            let Ok((current_identity, current_voters)) = self.current_scope() else {
                return ForwardMutationReply::Unavailable;
            };
            if *scope_identity != current_identity
                || *voter_set_digest
                    != fenced_mutation_roster_voter_set_digest(current_identity, &current_voters)
                || *profile_digest != fenced_mutation_roster_profile_digest()
            {
                return ForwardMutationReply::Unavailable;
            }
        }
        self.propose_on_local_leader(
            request,
            LocalProposalAuthority {
                origin,
                allows_operator_recovery: allow_operator_recovery,
            },
            logical_time,
            proposal_permit,
            operation_guard,
            deadline,
        )
        .await
    }

    async fn propose_on_local_leader(
        &self,
        request: ForwardMutationRequest,
        authority: LocalProposalAuthority,
        logical_time: Timestamp,
        proposal_permit: tokio::sync::OwnedSemaphorePermit,
        operation_guard: tokio::sync::OwnedRwLockReadGuard<()>,
        deadline: tokio::time::Instant,
    ) -> ForwardMutationReply {
        let outcome_unavailable = consensus_outcome_unavailable(&request.intent);
        let Ok((identity, voters)) = self.current_scope() else {
            return ForwardMutationReply::Unavailable;
        };
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
        if let Some((scope_identity, voter_set_digest, profile_digest)) =
            fenced_mutation_roster_admission_scope(&request.intent)
        {
            if *scope_identity != identity
                || *voter_set_digest != fenced_mutation_roster_voter_set_digest(identity, &voters)
                || *profile_digest != fenced_mutation_roster_profile_digest()
            {
                return ForwardMutationReply::Unavailable;
            }
        }
        let intent = match request.intent {
            intent @ SessionMutationIntent::FinalizeOperatorRecovery { .. }
            | intent @ SessionMutationIntent::MaintainFencedTransitionV2History { .. }
            | intent @ SessionMutationIntent::MaintainFencedMutationRosterHistory { .. }
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
            && self
                .require_application_traffic_authority_before(deadline)
                .await
                .is_err()
        {
            return ForwardMutationReply::Unavailable;
        }

        // Split Openraft's enqueue and result phases explicitly. Once
        // `client_write_ff` returns a receiver, the proposal was accepted by
        // the local Raft core. Losing the receiver or crossing the deadline
        // after that point is an unknown committed outcome, never a safe
        // retryable availability failure.
        let response =
            match tokio::time::timeout_at(deadline, self.inner.raft.client_write_ff(command)).await
            {
                Err(_) => return ForwardMutationReply::Unavailable,
                Ok(Err(_)) => return ForwardMutationReply::Unavailable,
                Ok(Ok(response)) => response,
            };
        // Once Openraft returns the receiver, the proposal is accepted by its
        // core. A detached supervisor owns the proposal permit until Openraft
        // resolves the receiver, so caller cancellation, peer EOF, or a
        // response deadline cannot admit an unbounded queue of detached
        // mutations behind the still-running command.
        let (completion_tx, completion_rx) = tokio::sync::oneshot::channel();
        let timeout_outcome_unavailable = outcome_unavailable.clone();
        tokio::spawn(async move {
            let reply = match response.await {
                Err(_) => ForwardMutationReply::Applied(Box::new(
                    SessionConsensusResponse::rejected(outcome_unavailable.clone()),
                )),
                Ok(Ok(response)) => ForwardMutationReply::Applied(Box::new(response.data)),
                Ok(Err(ClientWriteError::ForwardToLeader(forward))) => {
                    ForwardMutationReply::NotLeader {
                        leader: forward.leader_id,
                    }
                }
                Ok(Err(ClientWriteError::ChangeMembershipError(_))) => {
                    ForwardMutationReply::Applied(Box::new(SessionConsensusResponse::rejected(
                        outcome_unavailable,
                    )))
                }
            };
            let _ = completion_tx.send(reply);
            drop(proposal_permit);
            drop(operation_guard);
        });
        match tokio::time::timeout_at(deadline, completion_rx).await {
            Err(_) | Ok(Err(_)) => ForwardMutationReply::Applied(Box::new(
                SessionConsensusResponse::rejected(timeout_outcome_unavailable),
            )),
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
            Ok(Err(_)) | Err(_) => return ForwardMutationReply::Unavailable,
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
                },
                authority_time,
                proposal_permit,
                operation_guard,
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
            ForwardMutationReply::Unavailable | ForwardMutationReply::RecordExpiryPreflight(_) => {
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
                Ok(Err(_)) | Err(_) => return Err(consensus_unavailable()),
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
                Ok(Err(_)) => return Err(consensus_unavailable()),
                Err(_) if retry_deadline < deadline => return Ok(()),
                Err(_) => return Err(consensus_unavailable()),
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
        let response = self
            .submit_request_before(
                SessionConsensusRequestId::new(),
                SessionMutationIntent::AdvanceLogicalTime,
                required_consumer_scope,
                deadline,
            )
            .await
            .map_err(|error| match error {
                // Advancing logical time is an idempotent implementation
                // detail of a read barrier. A lost result may have advanced
                // time, but repeating it cannot duplicate a user mutation.
                StoreError::BackendOperationOutcomeUnavailable => consensus_unavailable(),
                error => error,
            })?;
        response.result?;
        if response.raft_log_index == 0 {
            return Err(consensus_unavailable());
        }
        self.inner
            .read_barrier
            .wait_for_applied_index(response.raft_log_index, deadline)
            .await
            .map_err(|_| consensus_unavailable())?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        response.logical_time.ok_or_else(consensus_unavailable)
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

    async fn consumer_fenced_mutation_roster_capability(
        &self,
        scope: SessionConsumerScope,
        deadline: tokio::time::Instant,
    ) -> Result<FencedMutationRosterCapability, StoreError> {
        // Capability is an exact live-voter proof. Do not retain the local
        // read gate across the barrier/probe path, where a topology writer
        // could otherwise self-block this consumer request.
        let admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        drop(admission);
        self.require_fenced_mutation_roster_capability_before(deadline)
            .await?;
        let admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        drop(admission);
        Ok(FencedMutationRosterCapability::V2)
    }

    async fn consumer_fenced_mutation_roster_history_state(
        &self,
        scope: SessionConsumerScope,
        deadline: tokio::time::Instant,
    ) -> Result<FencedMutationRosterHistoryState, StoreError> {
        let admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        drop(admission);
        self.require_fenced_mutation_roster_capability_before(deadline)
            .await?;
        self.logical_read_time_before(Some(scope.consensus_identity()), deadline)
            .await?;
        // Retain the exact-scope gate until after the durable read and final
        // authority proof. A reclaim state with no public active epoch is
        // rejected by the SQLite projection rather than misrepresented.
        let _admission = self
            .admit_consumer_scope(scope, deadline)
            .await
            .map_err(|rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            })?;
        let history = self
            .inner
            .backend
            .consensus_fenced_mutation_roster_history_state(
                self.inner.storage_identity,
                scope.consensus_identity(),
            )
            .await?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        Ok(history)
    }

    async fn consumer_fenced_mutation_roster_status(
        &self,
        scope: SessionConsumerScope,
        admission: &FencedMutationRosterAdmission,
        deadline: tokio::time::Instant,
    ) -> Result<FencedMutationRosterStatus, StoreError> {
        admission
            .validate()
            .map_err(|_| StoreError::InvalidKey("fenced_mutation_roster_invalid".into()))?;
        let scope_admission = self.admit_consumer_scope(scope, deadline).await.map_err(
            |rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            },
        )?;
        drop(scope_admission);
        self.require_fenced_mutation_roster_capability_before(deadline)
            .await?;
        self.logical_read_time_before(Some(scope.consensus_identity()), deadline)
            .await?;
        // Both status and adoption are this exact durable lookup. It never
        // invokes an adapter, checkpoint publisher, or raw backend path.
        let _scope_admission = self.admit_consumer_scope(scope, deadline).await.map_err(
            |rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            },
        )?;
        let status = self
            .inner
            .backend
            .consensus_fenced_mutation_roster_status(
                self.inner.storage_identity,
                scope.consensus_identity(),
                admission,
            )
            .await?;
        self.require_application_traffic_authority_before(deadline)
            .await?;
        Ok(status)
    }

    async fn consumer_fenced_mutation_roster_admit(
        &self,
        scope: SessionConsumerScope,
        admission: FencedMutationRosterAdmission,
        deadline: tokio::time::Instant,
    ) -> Result<FencedMutationRosterOutcome, StoreError> {
        admission
            .validate()
            .map_err(|_| StoreError::InvalidKey("fenced_mutation_roster_invalid".into()))?;
        let scope_admission = self.admit_consumer_scope(scope, deadline).await.map_err(
            |rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            },
        )?;
        drop(scope_admission);
        self.require_fenced_mutation_roster_capability_before(deadline)
            .await?;
        let (scope_identity, voters) = self.current_scope()?;
        if scope_identity != scope.consensus_identity() {
            return Err(StoreError::TopologyAuthorityRevoked);
        }
        let request_id = fenced_mutation_roster_outer_request_id(admission.request_id());
        let response = self
            .submit_request_before(
                request_id,
                SessionMutationIntent::AdmitFencedMutationRoster {
                    admission: Box::new(admission),
                    scope_identity,
                    voter_set_digest: fenced_mutation_roster_voter_set_digest(
                        scope_identity,
                        &voters,
                    ),
                    profile_digest: fenced_mutation_roster_profile_digest(),
                },
                Some(scope.consensus_identity()),
                deadline,
            )
            .await?;
        match response.result? {
            SessionMutationOutcome::FencedMutationRoster(outcome) => Ok(outcome),
            _ => Err(StoreError::BackendOperationOutcomeUnavailable),
        }
    }

    // This internal submission path is reachable only after revision-6 derives
    // a terminal from private member proofs. Revision 5 has no caller into it:
    // its serde terminal is not evidence of a member effect.
    async fn consumer_fenced_mutation_roster_terminalize(
        &self,
        scope: SessionConsumerScope,
        admission: FencedMutationRosterAdmission,
        terminal: FencedMutationRosterTerminal,
        deadline: tokio::time::Instant,
    ) -> Result<FencedMutationRosterOutcome, StoreError> {
        admission
            .validate()
            .and_then(|()| terminal.validate_for_admission(&admission))
            .map_err(|_| {
                StoreError::InvalidKey("fenced_mutation_roster_terminal_invalid".into())
            })?;
        let scope_admission = self.admit_consumer_scope(scope, deadline).await.map_err(
            |rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            },
        )?;
        drop(scope_admission);
        self.require_fenced_mutation_roster_capability_before(deadline)
            .await?;
        if self.current_scope()?.0 != scope.consensus_identity() {
            return Err(StoreError::TopologyAuthorityRevoked);
        }
        let request_id = fenced_mutation_roster_terminal_outer_request_id(&admission, &terminal)?;
        let protected_checkpoint =
            crate::fenced_mutation_roster::FencedMutationRosterProtectedPlan::new(
                terminal.protected_checkpoint().to_vec().into_boxed_slice(),
            )
            .map_err(|_| {
                StoreError::InvalidKey("fenced_mutation_roster_terminal_invalid".into())
            })?;
        let response = self
            .submit_request_before(
                request_id,
                SessionMutationIntent::TerminalizeFencedMutationRoster {
                    admission: Box::new(admission),
                    terminal: Box::new(terminal),
                    protected_checkpoint,
                },
                Some(scope.consensus_identity()),
                deadline,
            )
            .await?;
        match response.result? {
            SessionMutationOutcome::FencedMutationRoster(outcome) => Ok(outcome),
            _ => Err(StoreError::BackendOperationOutcomeUnavailable),
        }
    }

    async fn reserve_fenced_mutation_roster_v4_verifier_dispatch(
        &self,
        scope: SessionConsumerScope,
        admission: FencedMutationRosterAdmission,
        request_digest: [u8; 32],
        worker_digest: [u8; 32],
        deadline: tokio::time::Instant,
    ) -> Result<bool, StoreError> {
        let scope_admission = self.admit_consumer_scope(scope, deadline).await.map_err(
            |rejection| match rejection {
                SessionConsumerRejection::ScopeMismatch => StoreError::TopologyAuthorityRevoked,
                _ => consensus_unavailable(),
            },
        )?;
        drop(scope_admission);
        self.require_fenced_mutation_roster_capability_before(deadline)
            .await?;
        if self.current_scope()?.0 != scope.consensus_identity() {
            return Err(StoreError::TopologyAuthorityRevoked);
        }
        let response = self
            .submit_request_before(
                SessionConsensusRequestId::new(),
                SessionMutationIntent::ReserveFencedMutationRosterV4VerifierDispatch {
                    admission: Box::new(admission),
                    request_digest,
                    worker_digest,
                },
                Some(scope.consensus_identity()),
                deadline,
            )
            .await?;
        match response.result? {
            SessionMutationOutcome::FencedMutationRosterV4VerifierDispatchReserved(reserved) => {
                Ok(reserved)
            }
            _ => Err(StoreError::BackendOperationOutcomeUnavailable),
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

/// Reject a delayed V2 request before a fresh activation proposal can carry it
/// into a successor scope.  The retired floor is terminal, whereas a request
/// above that floor may become active after an in-progress rotation finishes.
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

fn unsupported_fenced_mutation_roster() -> StoreError {
    StoreError::CapabilityNotSupported("fenced_mutation_roster_v1".into())
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

type FencedMutationRosterAdmissionScope<'a> =
    (&'a SessionConsensusIdentity, &'a [u8; 32], &'a [u8; 32]);

fn fenced_mutation_roster_admission_scope(
    intent: &SessionMutationIntent,
) -> Option<FencedMutationRosterAdmissionScope<'_>> {
    match intent {
        SessionMutationIntent::AdmitFencedMutationRoster {
            scope_identity,
            voter_set_digest,
            profile_digest,
            ..
        } => Some((scope_identity, voter_set_digest, profile_digest)),
        _ => None,
    }
}

fn consensus_outcome_unavailable(intent: &SessionMutationIntent) -> StoreError {
    match intent {
        SessionMutationIntent::CompareAndSet(_) => StoreError::CasIdempotencyOutcomeUnavailable,
        SessionMutationIntent::FencedTransition(_)
        | SessionMutationIntent::ActivateFencedTransition { .. }
        | SessionMutationIntent::FencedTransitionV2(_)
        | SessionMutationIntent::ActivateFencedTransitionV2 { .. } => {
            StoreError::FencedTransitionOutcomeUnknown
        }
        SessionMutationIntent::AdmitFencedMutationRoster { .. }
        | SessionMutationIntent::TerminalizeFencedMutationRoster { .. }
        | SessionMutationIntent::ReserveFencedMutationRosterV4VerifierDispatch { .. } => {
            StoreError::BackendOperationOutcomeUnavailable
        }
        _ => StoreError::BackendOperationOutcomeUnavailable,
    }
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
        )
        | (
            Ok(SessionMutationOutcome::Unit),
            SessionMutationIntent::MaintainFencedMutationRosterHistory { .. },
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
            Ok(SessionMutationOutcome::FencedMutationRoster(outcome)),
            intent @ (SessionMutationIntent::AdmitFencedMutationRoster { .. }
            | SessionMutationIntent::TerminalizeFencedMutationRoster { .. }),
        ) => fenced_mutation_roster_outcome_matches_intent(intent, outcome),
        (
            Ok(SessionMutationOutcome::FencedMutationRosterV4VerifierDispatchReserved(_)),
            SessionMutationIntent::ReserveFencedMutationRosterV4VerifierDispatch { .. },
        ) => true,
        (
            Ok(SessionMutationOutcome::ManagedProviderJob(outcome)),
            intent @ (SessionMutationIntent::EnsureManagedProviderJob { .. }
            | SessionMutationIntent::StartManagedProviderMember { .. }
            | SessionMutationIntent::RecordManagedProviderReceipt { .. }
            | SessionMutationIntent::RequireManagedProviderReconciliation { .. }
            | SessionMutationIntent::AbortManagedProviderNotApplied { .. }
            | SessionMutationIntent::FinalizeManagedProviderJob { .. }),
        ) => managed_provider_outcome_matches_intent(intent, outcome),
        _ => false,
    }
}

/// Match the complete fixed-width outcome family for every managed command.
/// This gate runs after a Raft commit before a public store method releases
/// the outcome to its caller, so accepting only the enum variant would turn a
/// valid commit into a spurious unavailable result (or, worse, authorize I/O
/// from a mismatched result).
fn managed_provider_outcome_matches_intent(
    intent: &SessionMutationIntent,
    outcome: &ManagedProviderJobMutationOutcome,
) -> bool {
    let valid_mode_phase = |mode, phase| {
        matches!(
            (mode, phase),
            (0, 0) | (1, 0..=5) | (2, 0..=5) | (3, 0 | 4 | 5)
        )
    };
    if !valid_mode_phase(outcome.mode, outcome.phase) {
        return false;
    }
    match intent {
        SessionMutationIntent::EnsureManagedProviderJob { .. } => {
            !outcome.execute
                && matches!(
                    (outcome.mode, outcome.phase),
                    (1, 0) | (2, 0) | (3, 0 | 4 | 5)
                )
        }
        SessionMutationIntent::StartManagedProviderMember { .. } => {
            (outcome.execute && (outcome.mode, outcome.phase) == (2, 1))
                || (!outcome.execute
                    && matches!(
                        (outcome.mode, outcome.phase),
                        (1, 0..=5) | (2, 1..=5) | (3, 0)
                    ))
        }
        SessionMutationIntent::RecordManagedProviderReceipt { .. } => {
            !outcome.execute
                && matches!(
                    (outcome.mode, outcome.phase),
                    (2, 2 | 5) | (1, 0..=5) | (3, 0)
                )
        }
        SessionMutationIntent::RequireManagedProviderReconciliation { .. } => {
            !outcome.execute
                && matches!(
                    (outcome.mode, outcome.phase),
                    (2, 3 | 5) | (1, 0..=5) | (3, 0)
                )
        }
        SessionMutationIntent::AbortManagedProviderNotApplied { .. } => {
            !outcome.execute
                && matches!((outcome.mode, outcome.phase), (2, 5) | (1, 0..=5) | (3, 0))
        }
        SessionMutationIntent::FinalizeManagedProviderJob { .. } => {
            !outcome.execute
                && matches!(
                    (outcome.mode, outcome.phase),
                    (2, 5) | (3, 0 | 4 | 5) | (1, 0..=5)
                )
        }
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

fn fenced_mutation_roster_outcome_matches_intent(
    intent: &SessionMutationIntent,
    outcome: &FencedMutationRosterOutcome,
) -> bool {
    let Some((admission, terminal, terminalizes)) = fenced_mutation_roster_intent_parts(intent)
    else {
        return false;
    };
    let status = &outcome.status;
    if status.request_id() != admission.request_id() {
        return false;
    }
    match (terminalizes, status.phase(), terminal) {
        (false, FencedMutationRosterPhase::PollAdmitted, None)
        | (false, FencedMutationRosterPhase::Established, None)
        | (false, FencedMutationRosterPhase::Aborted, None) => true,
        // A terminal response must carry the exact durable terminal frame for
        // establishment.  An abort is intentionally result-free, but only
        // the already validated requested terminal can lead to that phase.
        (true, FencedMutationRosterPhase::Established, Some(expected)) => {
            expected.phase() == FencedMutationRosterPhase::Established
                && status.terminal() == Some(expected)
        }
        (true, FencedMutationRosterPhase::Aborted, Some(expected)) => {
            expected.phase() == FencedMutationRosterPhase::Aborted && status.terminal().is_none()
        }
        _ => false,
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
        || matches!(
            (intent, error),
            (
                SessionMutationIntent::AdmitFencedMutationRoster { .. }
                    | SessionMutationIntent::TerminalizeFencedMutationRoster { .. }
                    | SessionMutationIntent::ReserveFencedMutationRosterV4VerifierDispatch { .. }
                    | SessionMutationIntent::EnsureManagedProviderJob { .. }
                    | SessionMutationIntent::StartManagedProviderMember { .. }
                    | SessionMutationIntent::RecordManagedProviderReceipt { .. }
                    | SessionMutationIntent::RequireManagedProviderReconciliation { .. }
                    | SessionMutationIntent::AbortManagedProviderNotApplied { .. }
                    | SessionMutationIntent::FinalizeManagedProviderJob { .. },
                StoreError::CapabilityNotSupported(reason)
            ) if reason == "fenced_mutation_roster_v1"
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
                | SessionMutationIntent::ActivateFencedTransitionV2 { .. }
                | SessionMutationIntent::AdmitFencedMutationRoster { .. }
                | SessionMutationIntent::TerminalizeFencedMutationRoster { .. }
                | SessionMutationIntent::ReserveFencedMutationRosterV4VerifierDispatch { .. }
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
        SessionMutationIntent::AdmitFencedMutationRoster { .. }
        | SessionMutationIntent::TerminalizeFencedMutationRoster { .. }
        | SessionMutationIntent::ReserveFencedMutationRosterV4VerifierDispatch { .. }
        | SessionMutationIntent::EnsureManagedProviderJob { .. }
        | SessionMutationIntent::StartManagedProviderMember { .. }
        | SessionMutationIntent::RecordManagedProviderReceipt { .. }
        | SessionMutationIntent::RequireManagedProviderReconciliation { .. }
        | SessionMutationIntent::AbortManagedProviderNotApplied { .. }
        | SessionMutationIntent::FinalizeManagedProviderJob { .. } => matches!(
            error,
            StoreError::InvalidKey(_) | StoreError::StaleFence | StoreError::NotFound
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
        SessionMutationIntent::MaintainFencedMutationRosterHistory { .. } => {
            matches!(error, StoreError::InvalidKey(_))
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
    if let Some((admission, terminal, terminalizes)) = fenced_mutation_roster_intent_parts(intent) {
        let expected_request_id = if terminalizes {
            fenced_mutation_roster_terminal_outer_request_id(
                admission,
                terminal.expect("terminalization carries terminal"),
            )?
        } else {
            fenced_mutation_roster_outer_request_id(admission.request_id())
        };
        if command.request_id != expected_request_id {
            return Err(StoreError::InvalidKey(
                "fenced_mutation_roster_request_id_mismatch".into(),
            ));
        }
        admission
            .validate()
            .map_err(|_| StoreError::InvalidKey("fenced_mutation_roster_invalid".into()))?;
    }
    if let SessionMutationIntent::TerminalizeFencedMutationRoster {
        admission,
        terminal,
        protected_checkpoint,
    } = intent
    {
        validate_fenced_mutation_roster_terminal(admission, terminal, protected_checkpoint)?;
    }
    if let SessionMutationIntent::AdmitFencedMutationRoster { profile_digest, .. } = intent {
        if *profile_digest != fenced_mutation_roster_profile_digest() {
            return Err(StoreError::CapabilityNotSupported(
                "fenced_mutation_roster_profile_mismatch".into(),
            ));
        }
    }
    if let SessionMutationIntent::ReserveFencedMutationRosterV4VerifierDispatch {
        admission,
        request_digest,
        worker_digest,
    } = intent
    {
        admission
            .validate()
            .map_err(|_| StoreError::InvalidKey("fenced_mutation_roster_invalid".into()))?;
        if request_digest.iter().all(|byte| *byte == 0)
            || worker_digest.iter().all(|byte| *byte == 0)
        {
            return Err(StoreError::InvalidKey(
                "fenced_mutation_roster_v4_reservation_invalid".into(),
            ));
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
            | SessionMutationIntent::MaintainFencedMutationRosterHistory { .. }
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
    if let SessionMutationIntent::MaintainFencedMutationRosterHistory {
        expected_bound_entries,
        expected_live_entries,
        ..
    } = intent
    {
        let bound_valid = usize::try_from(*expected_bound_entries)
            .ok()
            .is_some_and(|entries| {
                entries <= crate::fenced_mutation_roster::FENCED_MUTATION_ROSTER_RETAINED_RESULT_CAPACITY
            });
        let live_valid = usize::try_from(*expected_live_entries)
            .ok()
            .is_some_and(|entries| {
                entries <= crate::fenced_mutation_roster::FENCED_MUTATION_ROSTER_MAX_LIVE
            });
        if !bound_valid || !live_valid || expected_live_entries > expected_bound_entries {
            return Err(StoreError::InvalidKey(
                "fenced_mutation_roster_maintenance_counts_invalid".into(),
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
    if let Some((admission, _, _)) = fenced_mutation_roster_intent_parts(intent) {
        admission
            .validate()
            .map_err(|_| StoreError::InvalidKey("fenced_mutation_roster_invalid".into()))?;
    }
    if let SessionMutationIntent::TerminalizeFencedMutationRoster {
        admission,
        terminal,
        protected_checkpoint,
    } = intent
    {
        validate_fenced_mutation_roster_terminal(admission, terminal, protected_checkpoint)?;
    }
    Ok(())
}

fn fenced_mutation_roster_intent_parts(
    intent: &SessionMutationIntent,
) -> Option<(
    &FencedMutationRosterAdmission,
    Option<&FencedMutationRosterTerminal>,
    bool,
)> {
    match intent {
        SessionMutationIntent::AdmitFencedMutationRoster { admission, .. } => {
            Some((admission, None, false))
        }
        SessionMutationIntent::TerminalizeFencedMutationRoster {
            admission,
            terminal,
            ..
        } => Some((admission, Some(terminal), true)),
        _ => None,
    }
}

fn validate_fenced_mutation_roster_terminal(
    admission: &FencedMutationRosterAdmission,
    terminal: &FencedMutationRosterTerminal,
    protected_checkpoint: &crate::fenced_mutation_roster::FencedMutationRosterProtectedPlan,
) -> Result<(), StoreError> {
    terminal
        .validate_for_admission(admission)
        .map_err(|_| StoreError::InvalidKey("fenced_mutation_roster_terminal_invalid".into()))?;
    if terminal.protected_checkpoint() != protected_checkpoint.as_bytes() {
        return Err(StoreError::InvalidKey(
            "fenced_mutation_roster_checkpoint_mismatch".into(),
        ));
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
                if let Ok(
                    probe @ ManagedProviderV5CapabilityProbe {
                        magic: MANAGED_PROVIDER_V5_CAPABILITY_PROBE_MAGIC,
                        ..
                    },
                ) = decode_bounded::<ManagedProviderV5CapabilityProbe>(&request.payload)
                {
                    return encode_service_reply(&managed_provider_v5_capability_probe_reply(
                        probe,
                        self.store.local_managed_provider_v5_capability(),
                    ));
                }
                if let Ok(
                    probe @ FencedMutationRosterCapabilityProbe {
                        magic: FENCED_MUTATION_ROSTER_CAPABILITY_PROBE_MAGIC,
                        ..
                    },
                ) = decode_bounded::<FencedMutationRosterCapabilityProbe>(&request.payload)
                {
                    return encode_service_reply(&fenced_mutation_roster_capability_probe_reply(
                        probe,
                        self.store.local_fenced_mutation_roster_capability(),
                    ));
                }
                if let Ok(
                    probe @ FencedTransitionV2CapabilityProbe {
                        schema_version: FENCED_TRANSITION_SCHEMA_V2,
                        ..
                    },
                ) = decode_bounded::<FencedTransitionV2CapabilityProbe>(&request.payload)
                {
                    let reply = fenced_transition_v2_capability_probe_reply(
                        probe,
                        self.store.local_fenced_transition_v2_capability(),
                    );
                    return encode_service_reply(&reply);
                }
                if let Ok(FencedTransitionCapabilityProbe {
                    schema_version: FENCED_TRANSITION_SCHEMA_V1,
                }) = decode_bounded::<FencedTransitionCapabilityProbe>(&request.payload)
                {
                    let reply = if self.store.local_fenced_transition_capability()
                        == AtomicFencedTransitionCapability::V1
                    {
                        FencedTransitionCapabilityReply::V1
                    } else {
                        FencedTransitionCapabilityReply::Unsupported
                    };
                    return encode_service_reply(&reply);
                }
                protocol_rejection()
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

fn fenced_mutation_roster_v4_request_reservation_digest(
    request: &SessionConsumerV4Request,
) -> Result<[u8; 32], StoreError> {
    let encoded = serde_json::to_vec(request).map_err(|_| {
        StoreError::Serialization("fenced mutation roster V4 request rejected".into())
    })?;
    let mut hasher = Sha256::new();
    hasher.update(FENCED_MUTATION_ROSTER_V4_REQUEST_RESERVATION_DOMAIN);
    hasher.update((encoded.len() as u64).to_be_bytes());
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

fn fenced_mutation_roster_v4_worker_reservation_digest(
    identity: &SessionConsumerIdentity,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FENCED_MUTATION_ROSTER_V4_WORKER_RESERVATION_DOMAIN);
    hasher.update(identity.as_str().as_bytes());
    hasher.finalize().into()
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
        // This first exact-scope admission is only a detector. Do not hold the
        // read gate while entering a leader proposal/read barrier, where a
        // queued topology writer could otherwise self-block this request.
        let admission = match self
            .store
            .admit_consumer_scope(request.scope(), deadline)
            .await
        {
            Ok(admission) => admission,
            Err(rejection) => return SessionConsumerV2Response::Rejected(rejection),
        };
        drop(admission);
        let operation = request.operation().clone();
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
                let result = self
                    .store
                    .fenced_transition_v2(*transition)
                    .await
                    .map_err(SessionConsumerV2FencedTransitionError::from);
                SessionConsumerV2Response::FencedTransitionV2(result)
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
            Err(rejection) => SessionConsumerV2Response::Rejected(rejection),
        }
    }

    fn fenced_mutation_roster_profile(&self) -> Option<SessionConsumerFencedMutationRosterProfile> {
        // This synchronous advertisement proves only the concrete local
        // static profile. Every V3 request still proves current scope plus
        // leader/quorum authority through the durable store path below.
        self.store
            .local_fenced_mutation_roster_capability()
            .map(|_| SessionConsumerFencedMutationRosterProfile::v2())
    }

    fn fenced_mutation_roster_attested_profile(
        &self,
    ) -> Option<SessionConsumerFencedMutationRosterProfile> {
        self.attestation_verifier.as_ref().and_then(|_| {
            self.store
                .local_fenced_mutation_roster_capability()
                .map(|_| SessionConsumerFencedMutationRosterProfile::v3())
        })
    }

    async fn execute_v3(
        &self,
        identity: &SessionConsumerIdentity,
        request: SessionConsumerV3Request,
    ) -> SessionConsumerV3Response {
        let deadline = match self.operation_deadline() {
            Ok(deadline) => deadline,
            Err(rejection) => return SessionConsumerV3Response::Rejected(rejection),
        };
        if request.validate().is_err() {
            return SessionConsumerV3Response::Rejected(SessionConsumerRejection::MalformedRequest);
        }
        // Reject scope mismatches before any capability probe, consensus
        // barrier, durable receipt lookup, or prospective mutation work.
        let admission = match self
            .store
            .admit_consumer_scope(request.scope(), deadline)
            .await
        {
            Ok(admission) => admission,
            Err(rejection) => return SessionConsumerV3Response::Rejected(rejection),
        };
        let authority_scope = derive_fenced_mutation_roster_scope_for_consumer(
            identity,
            SessionConsumerScope::new(admission.required_scope),
        );

        let operation = request.operation().clone();
        // The opaque scope in every admission-bearing V3 body is the durable
        // receipt namespace. Derive it from authenticated mTLS identity plus
        // the exact scope admitted by this store before any roster capability
        // probe, read barrier, receipt lookup, or proposal. The body itself is
        // never rewritten server-side: mismatch is a pre-dispatch rejection.
        if !fenced_mutation_roster_operation_has_authority_scope(&operation, authority_scope) {
            return SessionConsumerV3Response::Rejected(SessionConsumerRejection::Unauthorized);
        }
        drop(admission);
        let response = match operation {
            SessionConsumerV3Operation::FencedMutationRosterCapability => {
                SessionConsumerV3Response::FencedMutationRosterCapability(
                    self.store
                        .consumer_fenced_mutation_roster_capability(request.scope(), deadline)
                        .await
                        .map(|capability| {
                            (capability, SessionConsumerFencedMutationRosterProfile::v2())
                        })
                        .map_err(SessionConsumerStoreError::from),
                )
            }
            SessionConsumerV3Operation::FencedMutationRosterHistoryState => {
                SessionConsumerV3Response::FencedMutationRosterHistoryState(
                    self.store
                        .consumer_fenced_mutation_roster_history_state(request.scope(), deadline)
                        .await
                        .map_err(SessionConsumerStoreError::from),
                )
            }
            SessionConsumerV3Operation::FencedMutationRosterStatus { admission } => {
                SessionConsumerV3Response::FencedMutationRosterStatus(
                    self.store
                        .consumer_fenced_mutation_roster_status(
                            request.scope(),
                            &admission,
                            deadline,
                        )
                        .await
                        .map_err(SessionConsumerStoreError::from),
                )
            }
            SessionConsumerV3Operation::FencedMutationRosterAdoption { admission } => {
                SessionConsumerV3Response::FencedMutationRosterAdoption(
                    self.store
                        .consumer_fenced_mutation_roster_status(
                            request.scope(),
                            &admission,
                            deadline,
                        )
                        .await
                        .map_err(SessionConsumerStoreError::from),
                )
            }
            SessionConsumerV3Operation::FencedMutationRosterAdmit { admission } => {
                SessionConsumerV3Response::FencedMutationRosterAdmit(
                    self.store
                        .consumer_fenced_mutation_roster_admit(
                            request.scope(),
                            *admission,
                            deadline,
                        )
                        .await
                        .map_err(|_| FencedMutationRosterError::Indeterminate),
                )
            }
            SessionConsumerV3Operation::FencedMutationRosterTerminalize { .. } => {
                // Revision 5 carried a serde terminal receipt.  Its public
                // fields can be made internally consistent by an authenticated
                // caller, but they do not prove that the member effect ran.
                // Do not turn the store-owned, non-serde member proof into a
                // wire claim by validating those fields again here.
                //
                // Keep the frozen V3 DTO decodable for wire isolation, but
                // close this terminal endpoint until a successor transport
                // carries a provider-attestation verifier contract.  In
                // particular, never submit a terminal mutation from V3.
                return SessionConsumerV3Response::Rejected(SessionConsumerRejection::Unavailable);
            }
        };

        // Match V2's successor-scope guard: a response derived under the
        // predecessor must never cross a completed authority cutover.
        match self
            .store
            .admit_consumer_scope(request.scope(), deadline)
            .await
        {
            Ok(admission) => {
                drop(admission);
                response
            }
            Err(rejection) => SessionConsumerV3Response::Rejected(rejection),
        }
    }

    async fn execute_v4(
        &self,
        identity: &SessionConsumerIdentity,
        request: SessionConsumerV4Request,
    ) -> SessionConsumerV4Response {
        let Some(verifier) = self.attestation_verifier.as_deref() else {
            return SessionConsumerV4Response::Rejected(SessionConsumerRejection::Unavailable);
        };
        let deadline = match self.operation_deadline() {
            Ok(deadline) => deadline,
            Err(rejection) => return SessionConsumerV4Response::Rejected(rejection),
        };
        if request.validate().is_err() {
            return SessionConsumerV4Response::Rejected(SessionConsumerRejection::MalformedRequest);
        }
        // mTLS admission and the derived scope gate run before consulting any
        // attestation, provider outcome, receipt, or mutation path.
        let scope_admission = match self
            .store
            .admit_consumer_scope(request.scope(), deadline)
            .await
        {
            Ok(admission) => admission,
            Err(rejection) => return SessionConsumerV4Response::Rejected(rejection),
        };
        let authority_scope = derive_fenced_mutation_roster_scope_for_consumer(
            identity,
            SessionConsumerScope::new(scope_admission.required_scope),
        );
        drop(scope_admission);

        let operation = request.operation().clone();
        let admission = operation.admission().clone();
        if admission.scope() != authority_scope {
            return SessionConsumerV4Response::Rejected(SessionConsumerRejection::Unauthorized);
        }

        // Structural attestation binding is pure local validation. Reject it
        // before consuming the one-shot verifier reservation: only a request
        // that could reach the configured external verifier owns that durable
        // fail-closed slot.
        for (member, attestation) in admission
            .members()
            .as_slice()
            .iter()
            .zip(operation.attestations())
        {
            let context = match FencedMutationRosterMemberExecutionContext::for_admission_member(
                &admission,
                member.ordinal(),
            ) {
                Ok(context) => context,
                Err(_) => {
                    return SessionConsumerV4Response::Rejected(
                        SessionConsumerRejection::MalformedRequest,
                    )
                }
            };
            if attestation.validate_for(&context).is_err() {
                return SessionConsumerV4Response::Rejected(
                    SessionConsumerRejection::MalformedRequest,
                );
            }
        }

        // Commit the exact request/worker reservation before any verifier
        // dispatch. A recovered reservation is deliberately fail-closed: a
        // retry cannot re-open verifier I/O after a process crash.
        let request_digest = match fenced_mutation_roster_v4_request_reservation_digest(&request) {
            Ok(digest) => digest,
            Err(_) => {
                return SessionConsumerV4Response::Rejected(
                    SessionConsumerRejection::MalformedRequest,
                )
            }
        };
        let reserved = self
            .store
            .reserve_fenced_mutation_roster_v4_verifier_dispatch(
                request.scope(),
                admission.clone(),
                request_digest,
                fenced_mutation_roster_v4_worker_reservation_digest(identity),
                deadline,
            )
            .await;
        match reserved {
            Ok(true) => {}
            Ok(false) => {
                return SessionConsumerV4Response::Rejected(SessionConsumerRejection::Unavailable)
            }
            Err(_) => {
                return SessionConsumerV4Response::Rejected(SessionConsumerRejection::Unavailable)
            }
        }

        // Each store-owned authority supplies an independent pre- and
        // post-verification durable `PollAdmitted` check. A competing or
        // replayed terminalization moves the durable phase, causing the next
        // check (or the terminal CAS) to fail closed before another terminal
        // commit can occur.
        let mut proofs = Vec::with_capacity(admission.members().len());
        for (member, attestation) in admission
            .members()
            .as_slice()
            .iter()
            .zip(operation.attestations())
        {
            let authority = match self
                .store
                .fenced_mutation_roster_member_execution_authority(
                    identity,
                    request.scope(),
                    admission.clone(),
                    member.ordinal(),
                )
                .await
            {
                Ok(authority) => authority,
                Err(_) => {
                    return SessionConsumerV4Response::Rejected(
                        SessionConsumerRejection::Unavailable,
                    )
                }
            };
            match authority
                .verify_member_attestation(identity, verifier, attestation)
                .await
            {
                Ok(proof) => proofs.push(proof),
                Err(FencedMutationRosterMemberExecutionError::Context(_)) => {
                    return SessionConsumerV4Response::Rejected(
                        SessionConsumerRejection::MalformedRequest,
                    )
                }
                Err(FencedMutationRosterMemberExecutionError::Provider(
                    FencedMutationRosterMemberAttestationError::Rejected,
                )) => {
                    return SessionConsumerV4Response::Rejected(
                        SessionConsumerRejection::Unauthorized,
                    )
                }
                Err(_) => {
                    return SessionConsumerV4Response::Rejected(
                        SessionConsumerRejection::Unavailable,
                    )
                }
            }
        }

        let terminal = match FencedMutationRosterTerminal::from_member_proofs(
            &admission,
            proofs,
            operation.protected_checkpoint().to_vec(),
            admission.terminal_result().as_bytes().to_vec(),
        ) {
            Ok(terminal) => terminal,
            Err(_) => {
                return SessionConsumerV4Response::Rejected(
                    SessionConsumerRejection::MalformedRequest,
                )
            }
        };
        let response = SessionConsumerV4Response::FencedMutationRosterTerminalize(
            self.store
                .consumer_fenced_mutation_roster_terminalize(
                    request.scope(),
                    admission,
                    terminal,
                    deadline,
                )
                .await
                .map_err(|_| FencedMutationRosterError::Indeterminate),
        );
        match self
            .store
            .admit_consumer_scope(request.scope(), deadline)
            .await
        {
            Ok(scope_admission) => {
                drop(scope_admission);
                response
            }
            Err(rejection) => SessionConsumerV4Response::Rejected(rejection),
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

fn fenced_mutation_roster_operation_has_authority_scope(
    operation: &SessionConsumerV3Operation,
    authority_scope: crate::fenced_mutation_roster::FencedMutationRosterScope,
) -> bool {
    match operation {
        // These operations expose no roster body or receipt namespace. Their
        // exact store-scope admission remains sufficient and does not turn a
        // capability/history observation into an identity oracle.
        SessionConsumerV3Operation::FencedMutationRosterCapability
        | SessionConsumerV3Operation::FencedMutationRosterHistoryState => true,
        SessionConsumerV3Operation::FencedMutationRosterAdmit { admission }
        | SessionConsumerV3Operation::FencedMutationRosterStatus { admission }
        | SessionConsumerV3Operation::FencedMutationRosterAdoption { admission }
        | SessionConsumerV3Operation::FencedMutationRosterTerminalize { admission, .. } => {
            admission.scope() == authority_scope
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
    use std::sync::atomic::AtomicUsize;
    use std::sync::{Arc, Mutex, RwLock};

    use bytes::Bytes;
    use futures_util::StreamExt;
    use opc_consensus::engine::{CommittedLeaderId, Membership};
    use opc_consensus::{
        derive_configuration_id, ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusIdentity,
    };
    use opc_crypto::CryptoEnvelopeV1;
    use opc_key::{
        serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyId, SessionAad, AEAD_TAG_LEN,
        AES_256_GCM_SIV_NONCE_LEN,
    };
    use tokio::sync::Notify;

    use super::*;
    use crate::backend::ReplicationOp;
    use crate::model::{FenceToken, Generation, SessionKeyType, StateClass, StateType};
    use crate::record::EncryptedSessionPayload;
    use crate::topology::{
        QuorumReplicaDescriptor, QuorumTopologyConfig, ReplicaBackingIdentity, ReplicaEndpoint,
        ReplicaFailureDomain, ReplicaId, ReplicaTlsIdentity,
    };
    use crate::{
        FencedTransitionLease, FencedTransitionMutation, FencedTransitionMutationResult,
        FencedTransitionOutcome, FencedTransitionRequestId, FencedTransitionV2CallerNonce,
        FencedTransitionV2HistoryEpoch, FencedTransitionV2Request, SessionConsumerRequestId,
    };
    use opc_types::{NetworkFunctionKind, TenantId};

    fn node(value: u64) -> SessionConsensusNodeId {
        SessionConsensusNodeId::new(value).expect("valid test consensus node ID")
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

    const MANAGED_V5_CAPABILITY_TEST_VOTERS: usize = 3;

    #[derive(Clone)]
    struct ManagedV5CapabilityTestPeer {
        target: SessionConsensusNodeId,
        handler: Arc<RwLock<Option<Arc<dyn SessionConsensusRpcHandler>>>>,
    }

    impl ManagedV5CapabilityTestPeer {
        fn new(target: SessionConsensusNodeId) -> Self {
            Self {
                target,
                handler: Arc::new(RwLock::new(None)),
            }
        }

        fn install(&self, handler: Arc<dyn SessionConsensusRpcHandler>) {
            *self.handler.write().expect("capability test handler lock") = Some(handler);
        }

        fn clear_handler(&self) {
            self.handler
                .write()
                .expect("capability test handler lock")
                .take();
        }
    }

    impl fmt::Debug for ManagedV5CapabilityTestPeer {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("ManagedV5CapabilityTestPeer")
                .field("target", &self.target)
                .finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl SessionConsensusPeer for ManagedV5CapabilityTestPeer {
        fn node_id(&self) -> SessionConsensusNodeId {
            self.target
        }

        async fn call(
            &self,
            request: SessionConsensusWireRequest,
        ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
            let handler = self
                .handler
                .read()
                .expect("capability test handler lock")
                .clone()
                .ok_or(SessionConsensusPeerError::Unavailable)?;
            Ok(handler.handle(request.sender, request).await)
        }
    }

    /// Test-only copies of the private capability frame preserve the real
    /// postcard boundary while allowing one peer to advertise the predecessor
    /// profile. The command itself still crosses `ConsensusSessionStore`.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ManagedV5CapabilityTestProbe {
        magic: [u8; 8],
        schema_version: u16,
        profile_digest: [u8; 32],
    }

    #[derive(Serialize)]
    enum ManagedV5CapabilityTestReply {
        V5 {
            magic: [u8; 8],
            profile_digest: [u8; 32],
        },
    }

    struct PredecessorManagedV5ProfileHandler {
        inner: Arc<dyn SessionConsensusRpcHandler>,
        v5_probes: Arc<AtomicUsize>,
    }

    impl fmt::Debug for PredecessorManagedV5ProfileHandler {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("PredecessorManagedV5ProfileHandler(<redacted>)")
        }
    }

    #[async_trait::async_trait]
    impl SessionConsensusRpcHandler for PredecessorManagedV5ProfileHandler {
        async fn handle(
            &self,
            authenticated_sender: SessionConsensusNodeId,
            request: SessionConsensusWireRequest,
        ) -> SessionConsensusWireResponse {
            if request.family == SessionConsensusRpcFamily::ReadBarrier
                && matches!(
                    decode_bounded::<ManagedV5CapabilityTestProbe>(&request.payload),
                    Ok(ManagedV5CapabilityTestProbe {
                        magic: MANAGED_PROVIDER_V5_CAPABILITY_PROBE_MAGIC,
                        schema_version: MANAGED_PROVIDER_V5_CAPABILITY_SCHEMA_VERSION,
                        profile_digest,
                    }) if profile_digest == fenced_mutation_roster_managed_provider_v5_profile_digest()
                )
            {
                self.v5_probes.fetch_add(1, Ordering::SeqCst);
                let reply = ManagedV5CapabilityTestReply::V5 {
                    magic: MANAGED_PROVIDER_V5_CAPABILITY_REPLY_MAGIC,
                    profile_digest: fenced_mutation_roster_profile_digest(),
                };
                return SessionConsensusWireResponse {
                    result: encode_bounded(&reply).map_err(|_| SessionConsensusPeerError::Protocol),
                };
            }
            self.inner.handle(authenticated_sender, request).await
        }
    }

    struct ManagedV5CapabilityThreeVoterFixture {
        paths: BTreeMap<(usize, usize), Arc<ManagedV5CapabilityTestPeer>>,
        stores: Vec<ConsensusSessionStore>,
        _backends: Vec<SqliteSessionBackend>,
        _directory: tempfile::TempDir,
    }

    impl Drop for ManagedV5CapabilityThreeVoterFixture {
        fn drop(&mut self) {
            for path in self.paths.values() {
                path.clear_handler();
            }
        }
    }

    fn managed_v5_capability_test_member(index: usize) -> QuorumReplicaDescriptor {
        let replica_id =
            ReplicaId::new(format!("managed-v5-capability-test-{index}")).expect("replica ID");
        QuorumReplicaDescriptor::new(
            replica_id,
            ReplicaEndpoint::new(format!("managed-v5-capability-test-{index}.invalid"), 7443)
                .expect("endpoint"),
            ReplicaTlsIdentity::new(format!("spiffe://test/session/managed-v5/{index}"))
                .expect("TLS identity"),
            ReplicaFailureDomain::new(format!("managed-v5-capability-zone-{index}"))
                .expect("failure domain"),
            ReplicaBackingIdentity::new(format!("managed-v5-capability-disk-{index}"))
                .expect("backing identity"),
        )
    }

    async fn managed_v5_capability_three_voter_fixture() -> ManagedV5CapabilityThreeVoterFixture {
        let members = (0..MANAGED_V5_CAPABILITY_TEST_VOTERS)
            .map(managed_v5_capability_test_member)
            .collect::<Vec<_>>();
        let cluster_id =
            ConsensusClusterId::new("managed-v5-capability-three-voter").expect("cluster ID");
        let epoch = ConsensusConfigurationEpoch::new(1).expect("configuration epoch");
        let configuration_id = derive_configuration_id(
            cluster_id,
            epoch,
            &members
                .iter()
                .map(QuorumReplicaDescriptor::configuration_fingerprint)
                .collect::<Vec<_>>(),
        );
        let identity = ConsensusIdentity::new(cluster_id, configuration_id, epoch);
        let topologies = members
            .iter()
            .map(|member| {
                ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                    member.replica_id().clone(),
                    members.clone(),
                    identity,
                ))
                .expect("three-voter topology")
            })
            .collect::<Vec<_>>();
        let node_ids = topologies
            .iter()
            .map(|topology| topology.local_consensus_node_id().expect("node ID"))
            .collect::<Vec<_>>();
        let directory = tempfile::tempdir().expect("three-voter directory");
        let backends = (0..MANAGED_V5_CAPABILITY_TEST_VOTERS)
            .map(|index| {
                SqliteSessionBackend::open(directory.path().join(format!("node-{index}.sqlite")))
                    .expect("file-backed SQLite backend")
            })
            .collect::<Vec<_>>();
        let mut paths = BTreeMap::new();
        for source in 0..MANAGED_V5_CAPABILITY_TEST_VOTERS {
            for (target, node_id) in node_ids.iter().copied().enumerate() {
                if source != target {
                    paths.insert(
                        (source, target),
                        Arc::new(ManagedV5CapabilityTestPeer::new(node_id)),
                    );
                }
            }
        }
        let mut stores = Vec::with_capacity(MANAGED_V5_CAPABILITY_TEST_VOTERS);
        for index in 0..MANAGED_V5_CAPABILITY_TEST_VOTERS {
            let peers = (0..MANAGED_V5_CAPABILITY_TEST_VOTERS)
                .filter(|target| *target != index)
                .map(|target| {
                    let peer: Arc<dyn SessionConsensusPeer> =
                        paths.get(&(index, target)).expect("test path").clone();
                    (node_ids[target], peer)
                })
                .collect();
            stores.push(
                ConsensusSessionStore::open(
                    topologies[index].clone(),
                    backends[index].clone(),
                    directory.path().join(format!("snapshots-{index}")),
                    peers,
                )
                .await
                .expect("open three-voter consensus store"),
            );
        }
        let fixture = ManagedV5CapabilityThreeVoterFixture {
            paths,
            stores,
            _backends: backends,
            _directory: directory,
        };
        for ((_, target), path) in &fixture.paths {
            path.install(fixture.stores[*target].rpc_handler());
        }
        for result in futures_util::future::join_all(
            fixture
                .stores
                .iter()
                .map(ConsensusSessionStore::initialize_cluster),
        )
        .await
        {
            result.expect("initialize three-voter cluster");
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if futures_util::future::join_all(
                    fixture
                        .stores
                        .iter()
                        .map(ConsensusSessionStore::probe_durable_readiness),
                )
                .await
                .iter()
                .all(DurableReadinessReport::is_ready)
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("three-voter cluster reaches readiness");
        fixture
    }

    #[tokio::test]
    async fn managed_v5_command_rejects_mismatched_three_voter_profile_before_proposal_or_apply() {
        let fixture = managed_v5_capability_three_voter_fixture().await;
        let statuses = fixture
            .stores
            .iter()
            .map(ConsensusSessionStore::status)
            .collect::<Vec<_>>();
        let leader_id = statuses
            .first()
            .and_then(|status| status.leader_id)
            .expect("ready cluster has a leader");
        let leader = statuses
            .iter()
            .position(|status| status.node_id == leader_id)
            .expect("leader is configured");
        let predecessor = (leader + 1) % MANAGED_V5_CAPABILITY_TEST_VOTERS;
        let predecessor_v5_probes = Arc::new(AtomicUsize::new(0));
        for source in 0..MANAGED_V5_CAPABILITY_TEST_VOTERS {
            if source != predecessor {
                fixture
                    .paths
                    .get(&(source, predecessor))
                    .expect("path to predecessor-profile voter")
                    .install(Arc::new(PredecessorManagedV5ProfileHandler {
                        inner: fixture.stores[predecessor].rpc_handler(),
                        v5_probes: Arc::clone(&predecessor_v5_probes),
                    }));
            }
        }

        let before = fixture
            .stores
            .iter()
            .map(ConsensusSessionStore::status)
            .map(|status| (status.last_log_index, status.applied_index))
            .collect::<Vec<_>>();
        let scope = fixture.stores[leader]
            .consumer_scope()
            .expect("leader exposes its admitted consumer scope");
        let consumer = SessionConsumerIdentity::new("spiffe://test/managed-v5/capability")
            .expect("consumer identity");
        let admission = consumer_v3_roster_admission(scope, &consumer);
        let result = fixture.stores[leader]
            .submit_intent(SessionMutationIntent::EnsureManagedProviderJob {
                admission: Box::new(admission.clone()),
                protected_checkpoint: FencedMutationRosterProtectedPlan::new(
                    vec![0xA7].into_boxed_slice(),
                )
                .expect("managed checkpoint"),
                worker_digest: [0xA8; 32],
                verifier_digest: [0xA9; 32],
            })
            .await;
        assert!(
            matches!(
                result,
                Err(StoreError::CapabilityNotSupported(ref reason)) if reason == "fenced_mutation_roster_v1"
            ),
            "a predecessor managed-V5 profile must reject the public consensus command"
        );
        assert_eq!(
            predecessor_v5_probes.load(Ordering::SeqCst),
            1,
            "the mismatched voter must advertise its predecessor profile to the fresh V5 probe"
        );
        let after = fixture
            .stores
            .iter()
            .map(ConsensusSessionStore::status)
            .map(|status| (status.last_log_index, status.applied_index))
            .collect::<Vec<_>>();
        assert_eq!(
            after, before,
            "a mismatched voter must stop the managed command before proposal or apply on every voter"
        );
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

    fn consumer_v3_roster_admission(
        scope: SessionConsumerScope,
        identity: &SessionConsumerIdentity,
    ) -> FencedMutationRosterAdmission {
        consumer_v3_roster_admission_with_fence(scope, identity, FenceToken::new(1))
    }

    fn consumer_v3_roster_admission_with_fence(
        scope: SessionConsumerScope,
        identity: &SessionConsumerIdentity,
        fence: FenceToken,
    ) -> FencedMutationRosterAdmission {
        let member = crate::fenced_mutation_roster::FencedMutationRosterMember::new(
            crate::fenced_mutation_roster::FencedMutationRosterOrdinal::new(0)
                .expect("roster ordinal"),
            [0x71; 16],
            crate::fenced_mutation_roster::FencedMutationRosterDescriptor::new(Vec::new())
                .expect("roster descriptor"),
            1,
            1,
            crate::fenced_mutation_roster::FencedMutationRosterDisposition::Pending,
            crate::fenced_mutation_roster::FencedMutationRosterAdoption::Unreconciled,
        )
        .expect("roster member");
        FencedMutationRosterAdmission::new(
            1,
            crate::FencedMutationRosterOperationId::new([0x72; 16]).expect("roster operation ID"),
            derive_fenced_mutation_roster_scope_for_consumer(identity, scope),
            crate::FencedMutationRosterFenceIntent::new(
                OwnerId::new("consumer-v3-roster-owner").expect("roster owner"),
                fence,
            ),
            Generation::new(1),
            crate::FencedMutationRosterMembers::new([member]).expect("roster members"),
            crate::FencedMutationRosterProtectedPlan::new(Box::new([]))
                .expect("roster protected plan"),
        )
        .expect("roster admission")
        .with_terminal_result(
            crate::FencedMutationRosterProtectedResult::new(vec![0x74].into_boxed_slice())
                .expect("roster protected result"),
        )
        .expect("roster admission terminal result")
    }

    #[tokio::test]
    async fn managed_provider_postcommit_gate_accepts_only_its_exact_command_outcomes() {
        let (_directory, _store, scope, identity, _key, _lease) = consumer_boundary_store().await;
        let admission = consumer_v3_roster_admission(scope, &identity);
        let checkpoint = FencedMutationRosterProtectedPlan::new(vec![0x75].into_boxed_slice())
            .expect("managed checkpoint");
        let worker = [0x76; 32];
        let verifier = [0x77; 32];
        let ordinal = admission.members().as_slice()[0].ordinal().get();
        let intents = [
            (
                SessionMutationIntent::EnsureManagedProviderJob {
                    admission: Box::new(admission.clone()),
                    protected_checkpoint: checkpoint,
                    worker_digest: worker,
                    verifier_digest: verifier,
                },
                ManagedProviderJobMutationOutcome {
                    mode: 2,
                    phase: 0,
                    execute: false,
                },
            ),
            (
                SessionMutationIntent::StartManagedProviderMember {
                    admission: Box::new(admission.clone()),
                    ordinal,
                    worker_digest: worker,
                },
                ManagedProviderJobMutationOutcome {
                    mode: 2,
                    phase: 1,
                    execute: true,
                },
            ),
            (
                SessionMutationIntent::RecordManagedProviderReceipt {
                    admission: Box::new(admission.clone()),
                    ordinal,
                    worker_digest: worker,
                    verifier_digest: verifier,
                    receipt_digest: [0x78; 32],
                    outcome: 0,
                },
                ManagedProviderJobMutationOutcome {
                    mode: 2,
                    phase: 2,
                    execute: false,
                },
            ),
            (
                SessionMutationIntent::RequireManagedProviderReconciliation {
                    admission: Box::new(admission.clone()),
                    ordinal,
                    worker_digest: worker,
                },
                ManagedProviderJobMutationOutcome {
                    mode: 2,
                    phase: 3,
                    execute: false,
                },
            ),
            (
                SessionMutationIntent::AbortManagedProviderNotApplied {
                    admission: Box::new(admission.clone()),
                    ordinal,
                    worker_digest: worker,
                },
                ManagedProviderJobMutationOutcome {
                    mode: 2,
                    phase: 5,
                    execute: false,
                },
            ),
            (
                SessionMutationIntent::FinalizeManagedProviderJob {
                    admission: Box::new(admission),
                    worker_digest: worker,
                },
                ManagedProviderJobMutationOutcome {
                    mode: 3,
                    phase: 4,
                    execute: false,
                },
            ),
        ];
        for (intent, outcome) in intents {
            assert!(managed_provider_outcome_matches_intent(&intent, &outcome));
            let mismatched = if outcome.execute {
                ManagedProviderJobMutationOutcome {
                    mode: 2,
                    phase: 0,
                    execute: true,
                }
            } else {
                ManagedProviderJobMutationOutcome {
                    execute: true,
                    ..outcome
                }
            };
            assert!(
                !managed_provider_outcome_matches_intent(&intent, &mismatched),
                "execute is an I/O permit only for Ready -> EffectStarted"
            );
        }
    }

    struct ConsumerV3AppliedRosterProvider;

    #[async_trait::async_trait]
    impl crate::FencedMutationRosterMemberProvider for ConsumerV3AppliedRosterProvider {
        type Error = std::convert::Infallible;

        async fn execute_member(
            &self,
            _context: &crate::FencedMutationRosterMemberExecutionContext<'_>,
        ) -> Result<crate::FencedMutationRosterProviderOutcome, Self::Error> {
            Ok(crate::FencedMutationRosterProviderOutcome::AppliedExecuted)
        }

        async fn member_status(
            &self,
            _context: &crate::FencedMutationRosterMemberExecutionContext<'_>,
        ) -> Result<crate::FencedMutationRosterProviderOutcome, Self::Error> {
            Ok(crate::FencedMutationRosterProviderOutcome::AppliedExecuted)
        }

        async fn adopt_member(
            &self,
            _context: &crate::FencedMutationRosterMemberExecutionContext<'_>,
        ) -> Result<crate::FencedMutationRosterProviderOutcome, Self::Error> {
            Ok(crate::FencedMutationRosterProviderOutcome::AppliedExecuted)
        }
    }

    struct ConsumerV3FailingRosterProvider;

    #[async_trait::async_trait]
    impl crate::FencedMutationRosterMemberProvider for ConsumerV3FailingRosterProvider {
        type Error = FencedMutationRosterError;

        async fn execute_member(
            &self,
            _context: &crate::FencedMutationRosterMemberExecutionContext<'_>,
        ) -> Result<crate::FencedMutationRosterProviderOutcome, Self::Error> {
            Err(FencedMutationRosterError::Indeterminate)
        }

        async fn member_status(
            &self,
            _context: &crate::FencedMutationRosterMemberExecutionContext<'_>,
        ) -> Result<crate::FencedMutationRosterProviderOutcome, Self::Error> {
            Err(FencedMutationRosterError::Indeterminate)
        }

        async fn adopt_member(
            &self,
            _context: &crate::FencedMutationRosterMemberExecutionContext<'_>,
        ) -> Result<crate::FencedMutationRosterProviderOutcome, Self::Error> {
            Err(FencedMutationRosterError::Indeterminate)
        }
    }

    struct ConsumerV4TestAttestationVerifier;

    struct BlockingConsumerV4TestAttestationVerifier {
        calls: AtomicUsize,
        started: Notify,
        release: Notify,
    }

    #[async_trait::async_trait]
    impl crate::FencedMutationRosterMemberAttestationVerifier
        for BlockingConsumerV4TestAttestationVerifier
    {
        async fn verify_member_attestation(
            &self,
            _identity: &SessionConsumerIdentity,
            _context: &crate::FencedMutationRosterMemberExecutionContext<'_>,
            attestation: &crate::FencedMutationRosterMemberAttestation,
        ) -> Result<
            crate::FencedMutationRosterProviderOutcome,
            crate::FencedMutationRosterMemberAttestationError,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.started.notify_waiters();
            self.release.notified().await;
            Ok(attestation.outcome())
        }
    }

    #[async_trait::async_trait]
    impl crate::FencedMutationRosterMemberAttestationVerifier for ConsumerV4TestAttestationVerifier {
        async fn verify_member_attestation(
            &self,
            identity: &SessionConsumerIdentity,
            context: &crate::FencedMutationRosterMemberExecutionContext<'_>,
            attestation: &crate::FencedMutationRosterMemberAttestation,
        ) -> Result<
            crate::FencedMutationRosterProviderOutcome,
            crate::FencedMutationRosterMemberAttestationError,
        > {
            if identity.as_str() == "spiffe://test.example/consumer/boundary"
                && attestation.validate_for(context).is_ok()
                && attestation.evidence() == [0xa5]
            {
                Ok(crate::FencedMutationRosterProviderOutcome::AppliedExecuted)
            } else {
                Err(crate::FencedMutationRosterMemberAttestationError::Rejected)
            }
        }
    }

    struct ConsumerV3TerminalizingRosterProvider {
        store: ConsensusSessionStore,
        scope: SessionConsumerScope,
        identity: SessionConsumerIdentity,
    }

    #[async_trait::async_trait]
    impl crate::FencedMutationRosterMemberProvider for ConsumerV3TerminalizingRosterProvider {
        type Error = std::convert::Infallible;

        async fn execute_member(
            &self,
            context: &crate::FencedMutationRosterMemberExecutionContext<'_>,
        ) -> Result<crate::FencedMutationRosterProviderOutcome, Self::Error> {
            let proof = crate::FencedMutationRosterMemberProof::issue(
                context,
                crate::FencedMutationRosterProviderOutcome::AppliedExecuted,
            );
            let terminal = FencedMutationRosterTerminal::from_member_proofs(
                context.admission(),
                vec![proof],
                vec![0x75],
                context.admission().terminal_result().as_bytes().to_vec(),
            )
            .expect("test-only terminal construction");
            assert!(matches!(
                self.store
                    .consumer_service()
                    .execute_v3(
                        &self.identity,
                        SessionConsumerV3Request::new(
                            self.scope,
                            SessionConsumerV3Operation::FencedMutationRosterTerminalize {
                                admission: Box::new(context.admission().clone()),
                                terminal: Box::new(terminal),
                            },
                        ),
                    )
                    .await,
                SessionConsumerV3Response::Rejected(SessionConsumerRejection::Unavailable)
            ));
            Ok(crate::FencedMutationRosterProviderOutcome::AppliedExecuted)
        }

        async fn member_status(
            &self,
            context: &crate::FencedMutationRosterMemberExecutionContext<'_>,
        ) -> Result<crate::FencedMutationRosterProviderOutcome, Self::Error> {
            self.execute_member(context).await
        }

        async fn adopt_member(
            &self,
            context: &crate::FencedMutationRosterMemberExecutionContext<'_>,
        ) -> Result<crate::FencedMutationRosterProviderOutcome, Self::Error> {
            self.execute_member(context).await
        }
    }

    async fn consumer_v3_roster_proof(
        store: &ConsensusSessionStore,
        scope: SessionConsumerScope,
        identity: &SessionConsumerIdentity,
        admission: &FencedMutationRosterAdmission,
    ) -> crate::FencedMutationRosterMemberProof {
        let member = &admission.members().as_slice()[0];
        store
            .fenced_mutation_roster_member_execution_authority(
                identity,
                scope,
                admission.clone(),
                member.ordinal(),
            )
            .await
            .expect("store owns admitted roster proof authority")
            .execute_member(
                &ConsumerV3AppliedRosterProvider
                    as &dyn crate::FencedMutationRosterMemberProvider<
                        Error = std::convert::Infallible,
                    >,
            )
            .await
            .expect("SDK issues roster proof")
    }

    async fn consumer_v3_roster_terminal(
        store: &ConsensusSessionStore,
        scope: SessionConsumerScope,
        identity: &SessionConsumerIdentity,
        admission: &FencedMutationRosterAdmission,
    ) -> FencedMutationRosterTerminal {
        let proof = consumer_v3_roster_proof(store, scope, identity, admission).await;
        FencedMutationRosterTerminal::from_member_proofs(
            admission,
            vec![proof],
            vec![0x75],
            admission.terminal_result().as_bytes().to_vec(),
        )
        .expect("terminal roster")
    }

    // Model a malformed-but-wire-deserializable terminal that would have
    // selected its own replacement result before the admission-bound check.
    fn consumer_v3_self_attested_roster_terminal(
        admission: &FencedMutationRosterAdmission,
        protected_result: Vec<u8>,
    ) -> FencedMutationRosterTerminal {
        let plan = crate::fenced_mutation_roster::FencedMutationRosterPlan::new(
            fenced_mutation_roster_profile_digest(),
            admission.scope().digest(),
            admission
                .fence_intent()
                .owner()
                .as_str()
                .as_bytes()
                .to_vec(),
            admission
                .fence_intent()
                .fence()
                .get()
                .to_be_bytes()
                .to_vec(),
            admission.expected_generation().get(),
            admission.members().as_slice().to_vec(),
            admission.protected_plan().as_bytes().to_vec(),
            protected_result.clone(),
        )
        .expect("self-attested terminal plan");
        let member = &admission.members().as_slice()[0];
        FencedMutationRosterTerminal::new(
            plan.admission_commitment(),
            vec![
                crate::fenced_mutation_roster::FencedMutationRosterMemberOutcome::new(
                    member.ordinal(),
                    *member.caller_id(),
                    crate::fenced_mutation_roster::FencedMutationRosterDisposition::Applied,
                    crate::fenced_mutation_roster::FencedMutationRosterAdoption::Executed,
                    crate::fenced_mutation_roster::FencedMutationRosterStatusBytes::new(Vec::new())
                        .expect("terminal status"),
                )
                .expect("terminal member"),
            ],
            vec![0x75],
            protected_result,
        )
        .expect("self-attested terminal")
    }

    async fn activate_roster_predecessor(
        store: &ConsensusSessionStore,
        scope: SessionConsumerScope,
        identity: &SessionConsumerIdentity,
    ) {
        let key = SessionKey {
            tenant: TenantId::new("consumer-v3-roster-activation").expect("activation tenant"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"consumer-v3-roster-activation")
                .try_into()
                .expect("activation stable ID"),
        };
        let transition = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x76; 16]),
            FencedTransitionLease::acquire(
                key,
                OwnerId::new("consumer-v3-roster-activation-owner").expect("activation owner"),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .expect("activation lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("activation transition");
        let response = store
            .consumer_service()
            .execute(
                identity,
                SessionConsumerRequest::new(
                    scope,
                    SessionConsumerRequestId::from_bytes([0x76; 16]),
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
    }

    #[tokio::test]
    async fn consumer_v3_profile_advertises_the_exact_roster_contract() {
        let (_directory, store, _scope, _identity, _key, _lease) = consumer_boundary_store().await;

        assert_eq!(
            store.consumer_service().fenced_mutation_roster_profile(),
            Some(crate::SessionConsumerFencedMutationRosterProfile::v2())
        );
    }

    #[tokio::test]
    async fn consumer_v3_dispatches_capability_and_history_through_the_durable_store() {
        let (_directory, store, scope, identity, _key, _lease) = consumer_boundary_store().await;
        let service = store.consumer_service();

        assert_eq!(
            service
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterCapability,
                    ),
                )
                .await,
            SessionConsumerV3Response::FencedMutationRosterCapability(Ok((
                FencedMutationRosterCapability::V2,
                SessionConsumerFencedMutationRosterProfile::v2(),
            )))
        );
        assert_eq!(
            service
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterHistoryState,
                    ),
                )
                .await,
            SessionConsumerV3Response::FencedMutationRosterHistoryState(Ok(
                FencedMutationRosterHistoryState {
                    active_epoch: Some(1),
                    retired_through: 0,
                    generation: 0,
                    bound: 0,
                    live: 0,
                },
            ))
        );
    }

    #[tokio::test]
    async fn consumer_v3_dispatches_status_and_adoption_through_the_durable_store() {
        let (_directory, store, scope, identity, _key, _lease) = consumer_boundary_store().await;
        let service = store.consumer_service();
        let admission = consumer_v3_roster_admission(scope, &identity);
        let expected = FencedMutationRosterStatus::new(
            FencedMutationRosterPhase::Absent,
            admission.request_id(),
            None,
        )
        .expect("absent roster status");

        assert_eq!(
            service
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterStatus {
                            admission: Box::new(admission.clone()),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::FencedMutationRosterStatus(Ok(expected.clone()))
        );
        assert_eq!(
            service
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterAdoption {
                            admission: Box::new(admission),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::FencedMutationRosterAdoption(Ok(expected))
        );
    }

    #[tokio::test]
    async fn consumer_v3_rejects_scope_mismatch_before_roster_dispatch() {
        let (_directory, store, scope, identity, _key, _lease) = consumer_boundary_store().await;
        let current = scope.consensus_identity();
        let stale_scope = SessionConsumerScope::new(SessionConsensusIdentity::new(
            current.cluster_id(),
            current.configuration_id(),
            SessionConsensusConfigurationEpoch::new(current.configuration_epoch().get() + 1)
                .expect("successor configuration epoch"),
        ));

        assert_eq!(
            store
                .consumer_service()
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        stale_scope,
                        SessionConsumerV3Operation::FencedMutationRosterCapability,
                    ),
                )
                .await,
            SessionConsumerV3Response::Rejected(SessionConsumerRejection::ScopeMismatch)
        );
    }

    #[tokio::test]
    async fn consumer_v3_rejects_cross_identity_roster_replay_before_dispatch() {
        let (_directory, store, scope, identity, _key, _lease) = consumer_boundary_store().await;
        let other_identity = SessionConsumerIdentity::new("spiffe://test.example/consumer/other")
            .expect("other consumer identity");
        let admission = consumer_v3_roster_admission(scope, &identity);
        let terminal = consumer_v3_self_attested_roster_terminal(
            &admission,
            admission.terminal_result().as_bytes().to_vec(),
        );

        assert_eq!(
            store
                .consumer_service()
                .execute_v3(
                    &other_identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterAdmit {
                            admission: Box::new(admission.clone()),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::Rejected(SessionConsumerRejection::Unauthorized)
        );
        assert_eq!(
            store
                .consumer_service()
                .execute_v3(
                    &other_identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterStatus {
                            admission: Box::new(admission.clone()),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::Rejected(SessionConsumerRejection::Unauthorized)
        );
        assert_eq!(
            store
                .consumer_service()
                .execute_v3(
                    &other_identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterAdoption {
                            admission: Box::new(admission.clone()),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::Rejected(SessionConsumerRejection::Unauthorized)
        );
        assert_eq!(
            store
                .consumer_service()
                .execute_v3(
                    &other_identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterTerminalize {
                            admission: Box::new(admission),
                            terminal: Box::new(terminal),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::Rejected(SessionConsumerRejection::Unauthorized)
        );
    }

    #[tokio::test]
    async fn consumer_v3_rejects_terminal_result_substitution_before_proposal() {
        let (_directory, store, scope, identity, _key, _lease) = consumer_boundary_store().await;
        activate_roster_predecessor(&store, scope, &identity).await;
        let admission = consumer_v3_roster_admission(scope, &identity);
        assert!(matches!(
            store
                .consumer_service()
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterAdmit {
                            admission: Box::new(admission.clone()),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::FencedMutationRosterAdmit(Ok(_))
        ));

        let proof = consumer_v3_roster_proof(&store, scope, &identity, &admission).await;
        assert_eq!(
            FencedMutationRosterTerminal::from_member_proofs(
                &admission,
                vec![proof],
                vec![0x75],
                vec![0x7a],
            ),
            Err(FencedMutationRosterError::RequestConflict),
            "SDK proof issuance cannot replace the result frozen by admission"
        );
        let replacement = serde_json::from_slice::<FencedMutationRosterTerminal>(
            &serde_json::to_vec(&consumer_v3_self_attested_roster_terminal(
                &admission,
                vec![0x7a],
            ))
            .expect("replacement terminal encodes"),
        )
        .expect("replacement terminal decodes from the typed wire body");
        assert!(
            replacement.validate_for_admission(&admission).is_err(),
            "a wire terminal cannot self-attest a replacement admitted result"
        );
        let history_before = store
            .consumer_service()
            .execute_v3(
                &identity,
                SessionConsumerV3Request::new(
                    scope,
                    SessionConsumerV3Operation::FencedMutationRosterHistoryState,
                ),
            )
            .await;

        assert_eq!(
            store
                .consumer_service()
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterTerminalize {
                            admission: Box::new(admission.clone()),
                            terminal: Box::new(replacement),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::Rejected(SessionConsumerRejection::MalformedRequest)
        );
        assert_eq!(
            store
                .consumer_service()
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterHistoryState,
                    ),
                )
                .await,
            history_before,
            "rejected terminal result substitution changes no receipt or history"
        );
        assert_eq!(
            store
                .consumer_service()
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterStatus {
                            admission: Box::new(admission.clone()),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::FencedMutationRosterStatus(Ok(
                FencedMutationRosterStatus::new(
                    FencedMutationRosterPhase::PollAdmitted,
                    admission.request_id(),
                    None,
                )
                .expect("admitted roster status"),
            ))
        );
        assert!(
            consumer_v3_roster_terminal(&store, scope, &identity, &admission)
                .await
                .validate_for_admission(&admission)
                .is_ok(),
            "the frozen admission result remains terminalizable"
        );
    }

    #[tokio::test]
    async fn consumer_v3_rejects_a_proof_derived_terminal_before_consensus_submission() {
        let (_directory, store, scope, identity, _key, _lease) = consumer_boundary_store().await;
        activate_roster_predecessor(&store, scope, &identity).await;
        let admission = consumer_v3_roster_admission(scope, &identity);
        assert!(matches!(
            store
                .consumer_service()
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterAdmit {
                            admission: Box::new(admission.clone()),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::FencedMutationRosterAdmit(Ok(_))
        ));
        let terminal = consumer_v3_roster_terminal(&store, scope, &identity, &admission).await;
        let terminal: FencedMutationRosterTerminal = serde_json::from_slice(
            &serde_json::to_vec(&terminal).expect("proof-shaped terminal JSON encodes"),
        )
        .expect("caller-authored proof-shaped terminal JSON decodes");
        assert_eq!(
            store
                .consumer_service()
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterTerminalize {
                            admission: Box::new(admission.clone()),
                            terminal: Box::new(terminal),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::Rejected(SessionConsumerRejection::Unavailable),
            "revision-5 terminal JSON is never a proof authority"
        );
        assert_eq!(
            store
                .consumer_service()
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterStatus {
                            admission: Box::new(admission.clone()),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::FencedMutationRosterStatus(Ok(
                FencedMutationRosterStatus::new(
                    FencedMutationRosterPhase::PollAdmitted,
                    admission.request_id(),
                    None,
                )
                .expect("admitted roster status"),
            )),
            "a rejected V3 terminal never reaches the durable terminal mutation"
        );
    }

    #[tokio::test]
    async fn consumer_v4_derives_terminal_only_after_verifier_bound_attestation() {
        let (_directory, store, scope, identity, _key, _lease) = consumer_boundary_store().await;
        activate_roster_predecessor(&store, scope, &identity).await;
        let admission = consumer_v3_roster_admission(scope, &identity);
        let service = store.consumer_service_with_attestation_verifier(Arc::new(
            ConsumerV4TestAttestationVerifier,
        ));
        assert!(matches!(
            service
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterAdmit {
                            admission: Box::new(admission.clone()),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::FencedMutationRosterAdmit(Ok(_))
        ));
        let context = crate::FencedMutationRosterMemberExecutionContext::for_admission_member(
            &admission,
            admission.members().as_slice()[0].ordinal(),
        )
        .expect("member context");
        let attestation = crate::FencedMutationRosterMemberAttestation::new(
            &context,
            crate::FencedMutationRosterProviderOutcome::AppliedExecuted,
            vec![0xa5].into_boxed_slice(),
        )
        .expect("bounded attestation");
        let request = SessionConsumerV4Request::new(
            scope,
            crate::SessionConsumerV4Operation::FencedMutationRosterTerminalizeAttested {
                admission: Box::new(admission.clone()),
                attestations: vec![attestation].into_boxed_slice(),
                protected_checkpoint: vec![0x75].into_boxed_slice(),
            },
        );
        let response = service.execute_v4(&identity, request.clone()).await;
        match response {
            crate::SessionConsumerV4Response::FencedMutationRosterTerminalize(Ok(outcome)) => {
                assert_eq!(
                    outcome.status.phase(),
                    FencedMutationRosterPhase::Established
                )
            }
            crate::SessionConsumerV4Response::FencedMutationRosterTerminalize(Err(error)) => {
                panic!("unexpected V4 terminal error: {error:?}")
            }
            crate::SessionConsumerV4Response::Rejected(rejection) => {
                panic!("unexpected V4 rejection: {rejection:?}")
            }
        }
        assert_eq!(
            service.execute_v4(&identity, request).await,
            crate::SessionConsumerV4Response::Rejected(SessionConsumerRejection::Unavailable),
            "a durable terminal consumes the attestation authority before replay"
        );
    }

    #[tokio::test]
    async fn consumer_v4_concurrent_exact_replay_dispatches_verifier_once() {
        let (_directory, store, scope, identity, _key, _lease) = consumer_boundary_store().await;
        activate_roster_predecessor(&store, scope, &identity).await;
        let admission = consumer_v3_roster_admission(scope, &identity);
        let verifier = Arc::new(BlockingConsumerV4TestAttestationVerifier {
            calls: AtomicUsize::new(0),
            started: Notify::new(),
            release: Notify::new(),
        });
        let service = Arc::new(store.consumer_service_with_attestation_verifier(verifier.clone()));
        assert!(matches!(
            service
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterAdmit {
                            admission: Box::new(admission.clone()),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::FencedMutationRosterAdmit(Ok(_))
        ));
        let context = crate::FencedMutationRosterMemberExecutionContext::for_admission_member(
            &admission,
            admission.members().as_slice()[0].ordinal(),
        )
        .expect("member context");
        let request = SessionConsumerV4Request::new(
            scope,
            crate::SessionConsumerV4Operation::FencedMutationRosterTerminalizeAttested {
                admission: Box::new(admission.clone()),
                attestations: vec![crate::FencedMutationRosterMemberAttestation::new(
                    &context,
                    crate::FencedMutationRosterProviderOutcome::AppliedExecuted,
                    vec![0xa5].into_boxed_slice(),
                )
                .expect("bounded attestation")]
                .into_boxed_slice(),
                protected_checkpoint: vec![0x75].into_boxed_slice(),
            },
        );
        let first_service = Arc::clone(&service);
        let first_identity = identity.clone();
        let first_request = request.clone();
        let first = tokio::spawn(async move {
            first_service
                .execute_v4(&first_identity, first_request)
                .await
        });
        verifier.started.notified().await;
        let second_service = Arc::clone(&service);
        let second_identity = identity.clone();
        let second =
            tokio::spawn(async move { second_service.execute_v4(&second_identity, request).await });
        let second = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .expect("an exact replay is rejected without waiting for verifier completion")
            .expect("second task");
        assert_eq!(
            second,
            crate::SessionConsumerV4Response::Rejected(SessionConsumerRejection::Unavailable)
        );
        assert_eq!(
            verifier.calls.load(Ordering::SeqCst),
            1,
            "an exact replay must not dispatch the verifier twice"
        );
        verifier.release.notify_waiters();
        let _ = first.await.expect("first task");
    }

    #[tokio::test]
    async fn consumer_v4_rejects_forged_identity_and_fence_mismatched_attestations_without_terminalizing(
    ) {
        let (_directory, store, scope, identity, _key, _lease) = consumer_boundary_store().await;
        activate_roster_predecessor(&store, scope, &identity).await;
        let admission = consumer_v3_roster_admission(scope, &identity);
        let service = store.consumer_service_with_attestation_verifier(Arc::new(
            ConsumerV4TestAttestationVerifier,
        ));
        assert!(matches!(
            service
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterAdmit {
                            admission: Box::new(admission.clone()),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::FencedMutationRosterAdmit(Ok(_))
        ));
        let current = scope.consensus_identity();
        let stale_scope = SessionConsumerScope::new(SessionConsensusIdentity::new(
            current.cluster_id(),
            current.configuration_id(),
            SessionConsensusConfigurationEpoch::new(current.configuration_epoch().get() + 1)
                .expect("successor configuration epoch"),
        ));
        let context = crate::FencedMutationRosterMemberExecutionContext::for_admission_member(
            &admission,
            admission.members().as_slice()[0].ordinal(),
        )
        .expect("member context");
        let forged = crate::FencedMutationRosterMemberAttestation::new(
            &context,
            crate::FencedMutationRosterProviderOutcome::AppliedExecuted,
            vec![0x00].into_boxed_slice(),
        )
        .expect("forged bounded evidence");
        let stale_scope_request = SessionConsumerV4Request::new(
            stale_scope,
            crate::SessionConsumerV4Operation::FencedMutationRosterTerminalizeAttested {
                admission: Box::new(admission.clone()),
                attestations: vec![forged.clone()].into_boxed_slice(),
                protected_checkpoint: vec![0x75].into_boxed_slice(),
            },
        );
        assert_eq!(
            service.execute_v4(&identity, stale_scope_request).await,
            crate::SessionConsumerV4Response::Rejected(SessionConsumerRejection::ScopeMismatch),
            "a mismatched consensus scope is rejected before verifier dispatch"
        );
        let forged_request = SessionConsumerV4Request::new(
            scope,
            crate::SessionConsumerV4Operation::FencedMutationRosterTerminalizeAttested {
                admission: Box::new(admission.clone()),
                attestations: vec![forged].into_boxed_slice(),
                protected_checkpoint: vec![0x75].into_boxed_slice(),
            },
        );
        assert_eq!(
            service.execute_v4(&identity, forged_request).await,
            crate::SessionConsumerV4Response::Rejected(SessionConsumerRejection::Unauthorized)
        );
        let other = SessionConsumerIdentity::new("spiffe://test.example/consumer/other")
            .expect("other identity");
        let correct = crate::FencedMutationRosterMemberAttestation::new(
            &context,
            crate::FencedMutationRosterProviderOutcome::AppliedExecuted,
            vec![0xa5].into_boxed_slice(),
        )
        .expect("correct evidence");
        let identity_request = SessionConsumerV4Request::new(
            scope,
            crate::SessionConsumerV4Operation::FencedMutationRosterTerminalizeAttested {
                admission: Box::new(admission.clone()),
                attestations: vec![correct].into_boxed_slice(),
                protected_checkpoint: vec![0x75].into_boxed_slice(),
            },
        );
        assert_eq!(
            service.execute_v4(&other, identity_request).await,
            crate::SessionConsumerV4Response::Rejected(SessionConsumerRejection::Unauthorized)
        );
        let wrong_fence =
            consumer_v3_roster_admission_with_fence(scope, &identity, FenceToken::new(2));
        let wrong_context =
            crate::FencedMutationRosterMemberExecutionContext::for_admission_member(
                &wrong_fence,
                wrong_fence.members().as_slice()[0].ordinal(),
            )
            .expect("wrong fence context");
        let mismatch = crate::FencedMutationRosterMemberAttestation::new(
            &wrong_context,
            crate::FencedMutationRosterProviderOutcome::AppliedExecuted,
            vec![0xa5].into_boxed_slice(),
        )
        .expect("mismatched attestation");
        let mismatch_request = SessionConsumerV4Request::new(
            scope,
            crate::SessionConsumerV4Operation::FencedMutationRosterTerminalizeAttested {
                admission: Box::new(admission.clone()),
                attestations: vec![mismatch].into_boxed_slice(),
                protected_checkpoint: vec![0x75].into_boxed_slice(),
            },
        );
        assert_eq!(
            service.execute_v4(&identity, mismatch_request).await,
            crate::SessionConsumerV4Response::Rejected(SessionConsumerRejection::MalformedRequest)
        );
        let outcome_mismatch = crate::FencedMutationRosterMemberAttestation::new(
            &context,
            crate::FencedMutationRosterProviderOutcome::AppliedAdopted,
            vec![0xa5].into_boxed_slice(),
        )
        .expect("outcome-mismatched attestation");
        let outcome_mismatch_request = SessionConsumerV4Request::new(
            scope,
            crate::SessionConsumerV4Operation::FencedMutationRosterTerminalizeAttested {
                admission: Box::new(admission.clone()),
                attestations: vec![outcome_mismatch].into_boxed_slice(),
                protected_checkpoint: vec![0x75].into_boxed_slice(),
            },
        );
        assert_eq!(
            service
                .execute_v4(&identity, outcome_mismatch_request)
                .await,
            crate::SessionConsumerV4Response::Rejected(SessionConsumerRejection::Unavailable),
            "a failed verifier attempt retains its shared one-shot V4 claim"
        );
        assert!(matches!(
            service
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterStatus {
                            admission: Box::new(admission),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::FencedMutationRosterStatus(Ok(status))
                if status.phase() == FencedMutationRosterPhase::PollAdmitted
        ));
    }

    #[tokio::test]
    async fn roster_member_proof_authority_requires_a_current_durable_admission() {
        let (_directory, store, scope, identity, _key, _lease) = consumer_boundary_store().await;
        activate_roster_predecessor(&store, scope, &identity).await;
        let admission = consumer_v3_roster_admission(scope, &identity);
        let ordinal = admission.members().as_slice()[0].ordinal();

        assert!(
            store
                .fenced_mutation_roster_member_execution_authority(
                    &identity,
                    scope,
                    admission.clone(),
                    ordinal,
                )
                .await
                .is_err(),
            "an absent receipt cannot authorize provider I/O or proof issuance"
        );

        assert!(matches!(
            store
                .consumer_service()
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterAdmit {
                            admission: Box::new(admission.clone()),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::FencedMutationRosterAdmit(Ok(_))
        ));

        let other_identity = SessionConsumerIdentity::new("spiffe://test.example/consumer/other")
            .expect("other consumer identity");
        assert!(
            matches!(
                store
                    .fenced_mutation_roster_member_execution_authority(
                        &other_identity,
                        scope,
                        admission.clone(),
                        ordinal,
                    )
                    .await,
                Err(StoreError::TopologyAuthorityRevoked)
            ),
            "the authority scope is derived from authenticated mTLS identity"
        );
        assert!(
            matches!(
                store
                    .fenced_mutation_roster_member_execution_authority(
                        &identity,
                        scope,
                        admission.clone(),
                        FencedMutationRosterOrdinal::new(1).expect("invalid ordinal fixture"),
                    )
                    .await,
                Err(StoreError::InvalidKey(reason)) if reason == "fenced_mutation_roster_member_ordinal_invalid"
            ),
            "a member mismatch is rejected before provider I/O"
        );
        let mut nested_wire_body =
            serde_json::to_value(&admission).expect("admission wire body encodes");
        nested_wire_body["members"][0]["ordinal"] = serde_json::json!(1);
        let malformed_from_wire: FencedMutationRosterAdmission =
            serde_json::from_value(nested_wire_body).expect("malformed body deserializes");
        assert!(
            store
                .fenced_mutation_roster_member_execution_authority(
                    &identity,
                    scope,
                    malformed_from_wire,
                    ordinal,
                )
                .await
                .is_err(),
            "nested serde cannot bypass canonical admission validation"
        );
        let fabricated_high_fence =
            consumer_v3_roster_admission_with_fence(scope, &identity, FenceToken::new(9));
        assert!(
            store
                .fenced_mutation_roster_member_execution_authority(
                    &identity,
                    scope,
                    fabricated_high_fence,
                    ordinal,
                )
                .await
                .is_err(),
            "a caller cannot replace the durable admission fence with a higher token"
        );

        let dynamic_provider: &dyn crate::FencedMutationRosterMemberProvider<
            Error = std::convert::Infallible,
        > = &ConsumerV3AppliedRosterProvider;
        let proof = store
            .fenced_mutation_roster_member_execution_authority(
                &identity,
                scope,
                admission.clone(),
                ordinal,
            )
            .await
            .expect("durably admitted authority")
            .execute_member(dynamic_provider)
            .await
            .expect("dynamic provider receives an SDK-issued proof");
        let terminal = FencedMutationRosterTerminal::from_member_proofs(
            &admission,
            vec![proof],
            vec![0x75],
            admission.terminal_result().as_bytes().to_vec(),
        )
        .expect("SDK proof derives a terminal bound to the admitted result");
        terminal
            .validate_for_admission(&admission)
            .expect("terminal retains the exact admission commitment");

        assert_eq!(
            store
                .fenced_mutation_roster_member_execution_authority(
                    &identity,
                    scope,
                    admission.clone(),
                    ordinal,
                )
                .await
                .expect("fresh authority for provider-error coverage")
                .execute_member(&ConsumerV3FailingRosterProvider)
                .await,
            Err(crate::FencedMutationRosterMemberExecutionError::Provider(
                FencedMutationRosterError::Indeterminate,
            )),
            "provider failure cannot issue a proof"
        );
    }

    #[tokio::test]
    async fn roster_member_proof_authority_does_not_let_a_provider_reopen_v3_terminalization() {
        let (_directory, store, scope, identity, _key, _lease) = consumer_boundary_store().await;
        activate_roster_predecessor(&store, scope, &identity).await;
        let admission = consumer_v3_roster_admission(scope, &identity);
        let ordinal = admission.members().as_slice()[0].ordinal();
        assert!(matches!(
            store
                .consumer_service()
                .execute_v3(
                    &identity,
                    SessionConsumerV3Request::new(
                        scope,
                        SessionConsumerV3Operation::FencedMutationRosterAdmit {
                            admission: Box::new(admission.clone()),
                        },
                    ),
                )
                .await,
            SessionConsumerV3Response::FencedMutationRosterAdmit(Ok(_))
        ));

        let provider = ConsumerV3TerminalizingRosterProvider {
            store: store.clone(),
            scope,
            identity: identity.clone(),
        };
        assert!(
            store
                .fenced_mutation_roster_member_execution_authority(
                    &identity, scope, admission, ordinal
                )
                .await
                .expect("durably admitted authority")
                .execute_member(&provider)
                .await
                .is_ok(),
            "a rejected V3 terminal attempt cannot consume or forge the authority"
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
        let roster_maintenance = SessionMutationIntent::MaintainFencedMutationRosterHistory {
            expected_generation: 0,
            expected_active_epoch: None,
            expected_retired_through: 0,
            expected_bound_entries: 0,
            expected_live_entries: 0,
        };
        assert_eq!(
            validate_consensus_intent(&roster_maintenance),
            Err(StoreError::CapabilityNotSupported(
                "operator_recovery_requires_local_admin_authority".into()
            ))
        );
        assert!(validate_consensus_intent_with_recovery(&roster_maintenance, true).is_ok());
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
    fn managed_v5_probe_rejects_predecessor_or_substituted_profile() {
        let exact = ManagedProviderV5CapabilityProbe {
            magic: MANAGED_PROVIDER_V5_CAPABILITY_PROBE_MAGIC,
            schema_version: MANAGED_PROVIDER_V5_CAPABILITY_SCHEMA_VERSION,
            profile_digest: fenced_mutation_roster_managed_provider_v5_profile_digest(),
        };
        assert!(matches!(
            managed_provider_v5_capability_probe_reply(
                exact,
                Some(FencedMutationRosterManagedProviderV5Capability::V5),
            ),
            ManagedProviderV5CapabilityReply::V5 { magic, profile_digest }
                if magic == MANAGED_PROVIDER_V5_CAPABILITY_REPLY_MAGIC
                    && profile_digest == fenced_mutation_roster_managed_provider_v5_profile_digest()
        ));
        assert_eq!(
            managed_provider_v5_capability_probe_reply(
                ManagedProviderV5CapabilityProbe {
                    profile_digest: fenced_mutation_roster_profile_digest(),
                    ..exact
                },
                Some(FencedMutationRosterManagedProviderV5Capability::V5),
            ),
            ManagedProviderV5CapabilityReply::Unsupported,
            "the predecessor roster profile cannot acknowledge managed V5"
        );
        assert_eq!(
            managed_provider_v5_capability_probe_reply(exact, None),
            ManagedProviderV5CapabilityReply::Unsupported,
            "missing V5 capability fails closed"
        );
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
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if store.inner.raft.metrics().borrow().last_log_index > Some(before) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("proposal reaches Openraft log");
        assert!(
            tokio::time::timeout(Duration::from_millis(40), watch.next())
                .await
                .is_err(),
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

        let wait_for_submission = |store: ConsensusSessionStore, before: u64| async move {
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if store.inner.raft.metrics().borrow().last_log_index > Some(before) {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("proposal reaches the real Openraft log");
        };
        let wait_for_available = |store: ConsensusSessionStore,
                                  expected: usize,
                                  context: &'static str| async move {
            tokio::time::timeout(Duration::from_secs(1), async {
                loop {
                    if store.inner.proposal_admission.available_permits() == expected {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap_or_else(|_| panic!("proposal admission did not reach {expected}: {context}"));
        };
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
        wait_for_submission(store.clone(), before).await;
        wait_for_available(
            store.clone(),
            DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS - 1,
            "first accepted proposal",
        )
        .await;
        cancelled.abort();
        let _ = cancelled.await;
        tokio::task::yield_now().await;
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
        wait_for_submission(store.clone(), before).await;
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
        wait_for_submission(store.clone(), before).await;
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
}

#[cfg(test)]
mod encryption_tests;
