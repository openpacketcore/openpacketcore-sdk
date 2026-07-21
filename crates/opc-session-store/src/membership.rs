//! Typed, redaction-safe plans and evidence for topology-epoch transitions.
//!
//! This module validates the caller-owned shape of a membership request. It
//! does not execute Openraft membership changes, admit network peers, or
//! persist transition state. Runtime coordinators can use the deterministic
//! request digest for idempotency and the status/evidence types for bounded
//! operator-facing state.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::consensus::{
    SessionConsensusClusterId, SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId,
    SessionConsensusIdentity, SessionConsensusNodeId, SessionTopologyMemberBinding,
};
use crate::topology::{
    QuorumReplicaDescriptor, QuorumTopologyConfig, QuorumTopologyError, ReplicaId,
    ValidatedQuorumTopology, QUORUM_TOPOLOGY_MAX_MEMBERS,
};

const TRANSITION_REQUEST_DIGEST_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-transition-request/v1\0";
const TRANSITION_ENDPOINT_BINDING_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-endpoint-binding/v1\0";
const TRANSITION_TLS_BINDING_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-tls-binding/v1\0";
const TRANSITION_BACKING_BINDING_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-backing-binding/v1\0";

/// Maximum complete operation timeout admitted for one topology transition.
///
/// This matches the existing consensus-store runtime configuration ceiling.
/// A runtime coordinator may impose a shorter deadline.
pub const SESSION_TOPOLOGY_TRANSITION_MAX_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);

/// Stable caller-owned identity for one topology transition and its retries.
///
/// The identifier is deliberately opaque. Its raw bytes are available for
/// persistence and protocol adapters, but are never rendered by `Debug` and no
/// `Display` implementation is provided.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionTopologyTransitionId([u8; 16]);

impl SessionTopologyTransitionId {
    /// Generate a cryptographically random transition identity.
    #[must_use]
    pub fn new() -> Self {
        Self(*uuid::Uuid::new_v4().as_bytes())
    }

    /// Reconstruct an identity from its exact fixed-width representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Return the exact fixed-width representation.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl Default for SessionTopologyTransitionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SessionTopologyTransitionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionTopologyTransitionId(<redacted>)")
    }
}

/// Fixed-width digest of one exact validated transition request.
///
/// The digest is safe to compare and persist as an idempotency discriminator.
/// Its bytes are kept out of diagnostic rendering to avoid turning logs into
/// an unbounded correlation surface.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionTopologyTransitionDigest([u8; 32]);

impl SessionTopologyTransitionDigest {
    /// Reconstruct a digest from its exact fixed-width representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the exact fixed-width representation.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for SessionTopologyTransitionDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionTopologyTransitionDigest(<redacted>)")
    }
}

/// Stable validation or idempotency failure at the transition-model boundary.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SessionTopologyTransitionError {
    /// The expected epoch cannot be incremented without overflowing `u64`.
    #[error("session topology transition epoch cannot advance")]
    EpochOverflow,
    /// The desired epoch was not exactly one greater than the expected epoch.
    #[error("session topology transition epoch is not sequential")]
    NonSequentialEpoch,
    /// The desired descriptors failed an existing topology invariant.
    #[error("session topology transition desired membership is invalid: {source}")]
    InvalidDesiredTopology {
        /// Redaction-safe topology validation failure.
        #[source]
        source: QuorumTopologyError,
    },
    /// The timeout was zero or exceeded the consensus runtime ceiling.
    #[error("session topology transition operation timeout is invalid")]
    InvalidOperationTimeout,
    /// A retained transition identity was reused for different request input.
    #[error("session topology transition identity was reused")]
    IdempotencyConflict,
    /// The expected epoch no longer matches the committed topology epoch.
    #[error("session topology transition expected epoch is stale")]
    StaleEpoch,
    /// The requested transition cannot preserve the required quorum.
    #[error("session topology transition would lose quorum")]
    QuorumLosingChange,
    /// The desired membership is identical to the current voter set.
    #[error("session topology transition does not change membership")]
    NoMembershipChange,
    /// Retained or replacement members violate cross-epoch identity bindings.
    #[error("session topology transition member bindings are invalid")]
    InvalidTransitionBindings,
    /// Another nonterminal transition already owns the cluster scope.
    #[error("session topology transition is already in progress")]
    TransitionInProgress,
    /// The deadline elapsed after durable work that must be resumed.
    #[error("session topology transition deadline elapsed; recovery is required")]
    DeadlineExceededResumable,
    /// Cancellation arrived after the transition became non-rollbackable.
    #[error("session topology transition can no longer be cancelled")]
    CancellationTooLate,
    /// The receiving node is not the current Openraft leader.
    #[error("session topology transition requires the current leader")]
    NotLeader,
    /// Required consensus or peer authority is currently unavailable.
    #[error("session topology transition is unavailable")]
    Unavailable,
    /// A status/evidence tuple contradicted its phase or committed epoch.
    #[error("session topology transition evidence state is invalid")]
    InvalidEvidenceState,
}

impl SessionTopologyTransitionError {
    /// Stable low-cardinality reason code for metrics and status adapters.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::EpochOverflow => "session_topology_transition_epoch_overflow",
            Self::NonSequentialEpoch => "session_topology_transition_nonsequential_epoch",
            Self::InvalidDesiredTopology { .. } => {
                "session_topology_transition_invalid_desired_topology"
            }
            Self::InvalidOperationTimeout => {
                "session_topology_transition_invalid_operation_timeout"
            }
            Self::IdempotencyConflict => "session_topology_transition_idempotency_conflict",
            Self::StaleEpoch => "session_topology_transition_stale_epoch",
            Self::QuorumLosingChange => "session_topology_transition_quorum_losing_change",
            Self::NoMembershipChange => "session_topology_transition_no_membership_change",
            Self::InvalidTransitionBindings => "session_topology_transition_invalid_bindings",
            Self::TransitionInProgress => "session_topology_transition_in_progress",
            Self::DeadlineExceededResumable => {
                "session_topology_transition_deadline_exceeded_resumable"
            }
            Self::CancellationTooLate => "session_topology_transition_cancellation_too_late",
            Self::NotLeader => "session_topology_transition_not_leader",
            Self::Unavailable => "session_topology_transition_unavailable",
            Self::InvalidEvidenceState => "session_topology_transition_invalid_evidence_state",
        }
    }
}

/// Validated caller intent for one exact topology-epoch transition.
///
/// Construction validates a strict one-epoch advance, the bounded deadline,
/// and the complete existing HA topology contract. Desired descriptors are
/// retained in canonical logical-replica order, so semantically identical
/// caller orderings compare equally and produce the same request digest.
#[must_use = "a validated topology transition request must be submitted or retained"]
#[derive(Clone, PartialEq, Eq)]
pub struct SessionTopologyTransitionRequest {
    transition_id: SessionTopologyTransitionId,
    cluster_id: SessionConsensusClusterId,
    expected_epoch: SessionConsensusConfigurationEpoch,
    desired_epoch: SessionConsensusConfigurationEpoch,
    desired_members: Vec<QuorumReplicaDescriptor>,
    desired_configuration_id: SessionConsensusConfigurationId,
    operation_timeout: Duration,
    request_digest: SessionTopologyTransitionDigest,
}

impl SessionTopologyTransitionRequest {
    /// Validate and construct one topology transition request.
    ///
    /// The desired epoch must equal `expected_epoch + 1`. Desired membership
    /// must contain an odd number of members from three through
    /// [`QUORUM_TOPOLOGY_MAX_MEMBERS`] and satisfy every descriptor, identity,
    /// backing, endpoint, failure-domain, and derived consensus-node invariant
    /// enforced by [`ValidatedQuorumTopology`].
    pub fn try_new(
        transition_id: SessionTopologyTransitionId,
        cluster_id: SessionConsensusClusterId,
        expected_epoch: SessionConsensusConfigurationEpoch,
        desired_epoch: SessionConsensusConfigurationEpoch,
        mut desired_members: Vec<QuorumReplicaDescriptor>,
        operation_timeout: Duration,
    ) -> Result<Self, SessionTopologyTransitionError> {
        let next_epoch = expected_epoch
            .get()
            .checked_add(1)
            .ok_or(SessionTopologyTransitionError::EpochOverflow)?;
        if desired_epoch.get() != next_epoch {
            return Err(SessionTopologyTransitionError::NonSequentialEpoch);
        }
        if operation_timeout.is_zero()
            || operation_timeout > SESSION_TOPOLOGY_TRANSITION_MAX_OPERATION_TIMEOUT
        {
            return Err(SessionTopologyTransitionError::InvalidOperationTimeout);
        }

        // Reject oversized caller input before sorting or fingerprinting it.
        validate_member_count(desired_members.len())?;
        desired_members.sort_by(|left, right| left.replica_id().cmp(right.replica_id()));
        let desired_configuration_id =
            validate_desired_membership(cluster_id, desired_epoch, desired_members.as_slice())?;
        let member_count = u32::try_from(desired_members.len()).map_err(|_| {
            invalid_topology(QuorumTopologyError::MemberCountTooLarge {
                configured: desired_members.len(),
                max: QUORUM_TOPOLOGY_MAX_MEMBERS,
            })
        })?;
        let request_digest = calculate_request_digest(
            transition_id,
            cluster_id,
            expected_epoch,
            desired_epoch,
            desired_configuration_id,
            member_count,
            operation_timeout,
        );

        Ok(Self {
            transition_id,
            cluster_id,
            expected_epoch,
            desired_epoch,
            desired_members,
            desired_configuration_id,
            operation_timeout,
            request_digest,
        })
    }

    /// Caller-owned transition identity.
    #[must_use]
    pub const fn transition_id(&self) -> SessionTopologyTransitionId {
        self.transition_id
    }

    /// Stable cluster scope against which derived node identities were checked.
    #[must_use]
    pub const fn cluster_id(&self) -> SessionConsensusClusterId {
        self.cluster_id
    }

    /// Epoch the caller expects to be current before any transition work.
    #[must_use]
    pub const fn expected_epoch(&self) -> SessionConsensusConfigurationEpoch {
        self.expected_epoch
    }

    /// Exact next epoch requested by the caller.
    #[must_use]
    pub const fn desired_epoch(&self) -> SessionConsensusConfigurationEpoch {
        self.desired_epoch
    }

    /// Canonically ordered desired member descriptors.
    #[must_use]
    pub fn desired_members(&self) -> &[QuorumReplicaDescriptor] {
        &self.desired_members
    }

    /// Exact order-independent configuration identity for the desired epoch.
    #[must_use]
    pub const fn desired_configuration_id(&self) -> SessionConsensusConfigurationId {
        self.desired_configuration_id
    }

    /// Exact consensus scope derived for the desired descriptor set.
    #[must_use]
    pub const fn desired_identity(&self) -> SessionConsensusIdentity {
        SessionConsensusIdentity::new(
            self.cluster_id,
            self.desired_configuration_id,
            self.desired_epoch,
        )
    }

    /// Stable consensus node ID of one desired logical replica.
    ///
    /// The result is absent when the replica is not part of the exact desired
    /// descriptor set. Node IDs are derived from cluster identity and logical
    /// replica identity, so retained members keep their ID across epochs.
    #[must_use]
    pub fn desired_consensus_node_id(
        &self,
        replica_id: &ReplicaId,
    ) -> Option<SessionConsensusNodeId> {
        self.desired_members
            .binary_search_by(|descriptor| descriptor.replica_id().cmp(replica_id))
            .ok()?;
        opc_consensus::derive_node_id(self.cluster_id, replica_id.as_str().as_bytes()).ok()
    }

    /// Exact desired voter IDs in canonical order.
    #[must_use]
    pub fn desired_consensus_node_ids(&self) -> BTreeSet<SessionConsensusNodeId> {
        self.desired_members
            .iter()
            .filter_map(|descriptor| self.desired_consensus_node_id(descriptor.replica_id()))
            .collect()
    }

    pub(crate) fn desired_node_bindings(
        &self,
    ) -> BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding> {
        self.desired_members
            .iter()
            .filter_map(|descriptor| {
                self.desired_consensus_node_id(descriptor.replica_id())
                    .map(|node_id| (node_id, member_binding(descriptor)))
            })
            .collect()
    }

    /// Complete caller-approved operation timeout.
    #[must_use]
    pub const fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }

    /// Deterministic digest of every request input.
    #[must_use]
    pub const fn request_digest(&self) -> SessionTopologyTransitionDigest {
        self.request_digest
    }

    /// Whether `other` is an exact retry of this transition identity and input.
    #[must_use]
    pub fn is_idempotent_retry(&self, other: &Self) -> bool {
        self.transition_id == other.transition_id && self.request_digest == other.request_digest
    }

    /// Fail closed unless `other` is an exact retry of this request.
    pub fn validate_idempotent_retry(
        &self,
        other: &Self,
    ) -> Result<(), SessionTopologyTransitionError> {
        if self.is_idempotent_retry(other) {
            Ok(())
        } else {
            Err(SessionTopologyTransitionError::IdempotencyConflict)
        }
    }
}

fn member_binding(descriptor: &QuorumReplicaDescriptor) -> SessionTopologyMemberBinding {
    let mut endpoint = Sha256::new();
    endpoint.update(TRANSITION_ENDPOINT_BINDING_DOMAIN);
    endpoint.update(Sha256::digest(descriptor.endpoint().host().as_bytes()));
    endpoint.update(descriptor.endpoint().port().to_be_bytes());

    let mut tls_identity = Sha256::new();
    tls_identity.update(TRANSITION_TLS_BINDING_DOMAIN);
    tls_identity.update(Sha256::digest(
        descriptor.tls_identity().as_str().as_bytes(),
    ));

    let mut backing_identity = Sha256::new();
    backing_identity.update(TRANSITION_BACKING_BINDING_DOMAIN);
    backing_identity.update(descriptor.backing_identity().fingerprint());

    SessionTopologyMemberBinding::new(
        descriptor.configuration_fingerprint(),
        endpoint.finalize().into(),
        tls_identity.finalize().into(),
        backing_identity.finalize().into(),
    )
}

impl fmt::Debug for SessionTopologyTransitionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTopologyTransitionRequest")
            .field("transition_id", &self.transition_id)
            .field("cluster_id", &self.cluster_id)
            .field("expected_epoch", &self.expected_epoch)
            .field("desired_epoch", &self.desired_epoch)
            .field("desired_member_count", &self.desired_members.len())
            .field("desired_configuration_id", &self.desired_configuration_id)
            .field("operation_timeout", &self.operation_timeout)
            .field("request_digest", &self.request_digest)
            .finish()
    }
}

/// Durable phase of a topology transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum SessionTopologyTransitionPhase {
    /// The exact request was admitted and durably planned.
    Prepared,
    /// Added members are admitted only as learners and are catching up.
    LearnersCatchingUp,
    /// Every added learner is caught up and successor voting transport is admitted.
    LearnersReady,
    /// Removed origins are fenced from authoritative application mutations.
    AuthorityFenced,
    /// Openraft durably committed a joint old/new voter configuration.
    JointCommitted,
    /// Openraft durably committed the desired uniform voter configuration.
    UniformCommitted,
    /// The desired epoch is committed while admission/audit finalization runs.
    Finalizing,
    /// The desired epoch and terminal success evidence are committed.
    Completed,
    /// A pre-joint abort decision is durable while learner cleanup is pending.
    Aborting,
    /// Pre-joint work was safely aborted while the expected epoch remained current.
    Aborted,
}

impl SessionTopologyTransitionPhase {
    /// Stable low-cardinality phase code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::LearnersCatchingUp => "learners_catching_up",
            Self::LearnersReady => "learners_ready",
            Self::AuthorityFenced => "authority_fenced",
            Self::JointCommitted => "joint_committed",
            Self::UniformCommitted => "uniform_committed",
            Self::Finalizing => "finalizing",
            Self::Completed => "completed",
            Self::Aborting => "aborting",
            Self::Aborted => "aborted",
        }
    }

    /// Whether no further transition progress is required.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Aborted)
    }

    const fn desired_epoch_is_committed(self) -> bool {
        matches!(
            self,
            Self::UniformCommitted | Self::Finalizing | Self::Completed
        )
    }
}

/// Typed result associated with transition status or durable evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SessionTopologyTransitionOutcome {
    /// Durable transition work is continuing normally.
    InProgress,
    /// The desired uniform epoch completed successfully.
    Succeeded,
    /// Pre-joint work was safely aborted without committing the desired epoch.
    Aborted,
    /// Durable state requires an idempotent retry or a successor leader.
    RecoveryRequired,
}

impl SessionTopologyTransitionOutcome {
    /// Stable low-cardinality outcome code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InProgress => "in_progress",
            Self::Succeeded => "succeeded",
            Self::Aborted => "aborted",
            Self::RecoveryRequired => "recovery_required",
        }
    }

    /// Whether the transition has a terminal outcome.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Aborted)
    }
}

/// Low-cardinality reason attached to transition evidence.
///
/// Values are deliberately closed over operational categories and never carry
/// free-form text, member identities, endpoints, or backend errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SessionTopologyTransitionReason {
    /// The current durable phase is progressing normally.
    Progressing,
    /// The desired uniform epoch completed successfully.
    Succeeded,
    /// The caller cancelled while rollback remained safe.
    AbortedByCaller,
    /// A deadline elapsed after durable work that must be resumed.
    DeadlineExceeded,
    /// Cancellation arrived after a joint membership commit.
    CancellationTooLate,
    /// Leadership changed while durable work remained resumable.
    LeaderChanged,
    /// A required old/new majority or admitted peer is unavailable.
    QuorumUnavailable,
}

impl SessionTopologyTransitionReason {
    /// Stable metrics, readiness, and audit code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Progressing => "progressing",
            Self::Succeeded => "succeeded",
            Self::AbortedByCaller => "aborted_by_caller",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::CancellationTooLate => "cancellation_too_late",
            Self::LeaderChanged => "leader_changed",
            Self::QuorumUnavailable => "quorum_unavailable",
        }
    }
}

/// Optional committed log indexes associated with membership transition phases.
///
/// Indexes are operational counters and contain no member or session identity.
/// [`SessionTopologyTransitionEvidence::try_from_request`] validates their
/// presence and strict ordering against the supplied phase.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionTopologyTransitionLogIndexes {
    joint: Option<u64>,
    uniform: Option<u64>,
    finalization: Option<u64>,
    abort_decision: Option<u64>,
    abort_cleanup: Option<u64>,
}

impl SessionTopologyTransitionLogIndexes {
    /// Construct an exact set of observed committed transition indexes.
    #[must_use]
    pub const fn new(joint: Option<u64>, uniform: Option<u64>, finalization: Option<u64>) -> Self {
        Self {
            joint,
            uniform,
            finalization,
            abort_decision: None,
            abort_cleanup: None,
        }
    }

    /// Construct abort decision and cleanup evidence.
    #[must_use]
    pub const fn aborted(abort_decision: u64, abort_cleanup: Option<u64>) -> Self {
        Self {
            joint: None,
            uniform: None,
            finalization: None,
            abort_decision: Some(abort_decision),
            abort_cleanup,
        }
    }

    /// Log index that committed joint old/new voter membership.
    #[must_use]
    pub const fn joint(self) -> Option<u64> {
        self.joint
    }

    /// Log index that committed desired uniform voter membership.
    #[must_use]
    pub const fn uniform(self) -> Option<u64> {
        self.uniform
    }

    /// Log index that committed transition finalization.
    #[must_use]
    pub const fn finalization(self) -> Option<u64> {
        self.finalization
    }

    /// Log index that committed the pre-joint abort decision.
    #[must_use]
    pub const fn abort_decision(self) -> Option<u64> {
        self.abort_decision
    }

    /// Membership log index that proved exact current-uniform cleanup.
    #[must_use]
    pub const fn abort_cleanup(self) -> Option<u64> {
        self.abort_cleanup
    }
}

/// Redaction-safe durable evidence for one transition phase and outcome.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionTopologyTransitionEvidence {
    expected_epoch: SessionConsensusConfigurationEpoch,
    desired_epoch: SessionConsensusConfigurationEpoch,
    committed_epoch: SessionConsensusConfigurationEpoch,
    desired_configuration_id: SessionConsensusConfigurationId,
    request_digest: SessionTopologyTransitionDigest,
    current_member_count: usize,
    current_quorum: usize,
    desired_member_count: usize,
    desired_quorum: usize,
    phase: SessionTopologyTransitionPhase,
    outcome: SessionTopologyTransitionOutcome,
    reason: SessionTopologyTransitionReason,
    log_indexes: SessionTopologyTransitionLogIndexes,
}

impl SessionTopologyTransitionEvidence {
    /// Build evidence from a validated request and a self-consistent state.
    ///
    /// Phases before uniform commit retain the expected epoch. Uniform commit
    /// and later phases report the desired epoch. `Aborting` remains
    /// in-progress until exact current-uniform cleanup is durable; only
    /// `Completed/Succeeded` and `Aborted/Aborted` are terminal combinations.
    pub fn try_from_request(
        request: &SessionTopologyTransitionRequest,
        current_member_count: usize,
        committed_epoch: SessionConsensusConfigurationEpoch,
        phase: SessionTopologyTransitionPhase,
        outcome: SessionTopologyTransitionOutcome,
        reason: SessionTopologyTransitionReason,
        log_indexes: SessionTopologyTransitionLogIndexes,
    ) -> Result<Self, SessionTopologyTransitionError> {
        let expected_committed_epoch = if phase.desired_epoch_is_committed() {
            request.desired_epoch
        } else {
            request.expected_epoch
        };
        let phase_outcome_is_valid = match phase {
            SessionTopologyTransitionPhase::Completed => {
                outcome == SessionTopologyTransitionOutcome::Succeeded
            }
            SessionTopologyTransitionPhase::Aborted => {
                outcome == SessionTopologyTransitionOutcome::Aborted
            }
            _ => matches!(
                outcome,
                SessionTopologyTransitionOutcome::InProgress
                    | SessionTopologyTransitionOutcome::RecoveryRequired
            ),
        };
        if committed_epoch != expected_committed_epoch
            || !phase_outcome_is_valid
            || !reason_is_valid_for_state(reason, outcome, phase)
            || !member_count_is_valid(current_member_count)
            || !log_indexes_are_valid_for_phase(log_indexes, phase)
        {
            return Err(SessionTopologyTransitionError::InvalidEvidenceState);
        }

        let desired_member_count = request.desired_members.len();
        Ok(Self {
            expected_epoch: request.expected_epoch,
            desired_epoch: request.desired_epoch,
            committed_epoch,
            desired_configuration_id: request.desired_configuration_id,
            request_digest: request.request_digest,
            current_member_count,
            current_quorum: (current_member_count / 2) + 1,
            desired_member_count,
            desired_quorum: (desired_member_count / 2) + 1,
            phase,
            outcome,
            reason,
            log_indexes,
        })
    }

    /// Epoch expected when the request was admitted.
    #[must_use]
    pub const fn expected_epoch(&self) -> SessionConsensusConfigurationEpoch {
        self.expected_epoch
    }

    /// Desired next topology epoch.
    #[must_use]
    pub const fn desired_epoch(&self) -> SessionConsensusConfigurationEpoch {
        self.desired_epoch
    }

    /// Topology epoch committed at this evidence point.
    #[must_use]
    pub const fn committed_epoch(&self) -> SessionConsensusConfigurationEpoch {
        self.committed_epoch
    }

    /// Exact desired configuration digest without raw descriptors.
    #[must_use]
    pub const fn desired_configuration_id(&self) -> SessionConsensusConfigurationId {
        self.desired_configuration_id
    }

    /// Exact validated request digest without raw descriptors.
    #[must_use]
    pub const fn request_digest(&self) -> SessionTopologyTransitionDigest {
        self.request_digest
    }

    /// Number of voters in the expected topology epoch.
    #[must_use]
    pub const fn current_member_count(&self) -> usize {
        self.current_member_count
    }

    /// Majority required by the expected topology epoch.
    #[must_use]
    pub const fn current_quorum(&self) -> usize {
        self.current_quorum
    }

    /// Number of desired uniform voters.
    #[must_use]
    pub const fn desired_member_count(&self) -> usize {
        self.desired_member_count
    }

    /// Majority required by the desired uniform voter set.
    #[must_use]
    pub const fn desired_quorum(&self) -> usize {
        self.desired_quorum
    }

    /// Durable transition phase.
    #[must_use]
    pub const fn phase(&self) -> SessionTopologyTransitionPhase {
        self.phase
    }

    /// Result observed at this evidence point.
    #[must_use]
    pub const fn outcome(&self) -> SessionTopologyTransitionOutcome {
        self.outcome
    }

    /// Low-cardinality reason for this evidence result.
    #[must_use]
    pub const fn reason(&self) -> SessionTopologyTransitionReason {
        self.reason
    }

    /// Stable low-cardinality reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        self.reason.as_str()
    }

    /// Committed joint, uniform, and finalization log indexes observed so far.
    #[must_use]
    pub const fn log_indexes(&self) -> SessionTopologyTransitionLogIndexes {
        self.log_indexes
    }
}

impl fmt::Debug for SessionTopologyTransitionEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTopologyTransitionEvidence")
            .field("expected_epoch", &self.expected_epoch)
            .field("desired_epoch", &self.desired_epoch)
            .field("committed_epoch", &self.committed_epoch)
            .field("desired_configuration_id", &self.desired_configuration_id)
            .field("request_digest", &self.request_digest)
            .field("current_member_count", &self.current_member_count)
            .field("current_quorum", &self.current_quorum)
            .field("desired_member_count", &self.desired_member_count)
            .field("desired_quorum", &self.desired_quorum)
            .field("phase", &self.phase)
            .field("outcome", &self.outcome)
            .field("reason", &self.reason)
            .field("log_indexes", &self.log_indexes)
            .finish()
    }
}

/// Redaction-safe current status for one caller-owned transition identity.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionTopologyTransitionStatus {
    transition_id: SessionTopologyTransitionId,
    evidence: SessionTopologyTransitionEvidence,
}

impl SessionTopologyTransitionStatus {
    /// Build current status from a validated request and evidence state.
    pub fn try_from_request(
        request: &SessionTopologyTransitionRequest,
        current_member_count: usize,
        committed_epoch: SessionConsensusConfigurationEpoch,
        phase: SessionTopologyTransitionPhase,
        outcome: SessionTopologyTransitionOutcome,
        reason: SessionTopologyTransitionReason,
        log_indexes: SessionTopologyTransitionLogIndexes,
    ) -> Result<Self, SessionTopologyTransitionError> {
        Ok(Self {
            transition_id: request.transition_id,
            evidence: SessionTopologyTransitionEvidence::try_from_request(
                request,
                current_member_count,
                committed_epoch,
                phase,
                outcome,
                reason,
                log_indexes,
            )?,
        })
    }

    /// Caller-owned transition identity.
    #[must_use]
    pub const fn transition_id(&self) -> SessionTopologyTransitionId {
        self.transition_id
    }

    /// Redaction-safe durable transition evidence.
    #[must_use]
    pub const fn evidence(&self) -> &SessionTopologyTransitionEvidence {
        &self.evidence
    }

    /// Durable transition phase.
    #[must_use]
    pub const fn phase(&self) -> SessionTopologyTransitionPhase {
        self.evidence.phase
    }

    /// Result observed at this status point.
    #[must_use]
    pub const fn outcome(&self) -> SessionTopologyTransitionOutcome {
        self.evidence.outcome
    }

    /// Stable low-cardinality reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        self.evidence.reason_code()
    }

    /// Number of voters in the expected topology epoch.
    #[must_use]
    pub const fn current_member_count(&self) -> usize {
        self.evidence.current_member_count
    }

    /// Majority required by the expected topology epoch.
    #[must_use]
    pub const fn current_quorum(&self) -> usize {
        self.evidence.current_quorum
    }

    /// Number of voters in the desired uniform topology epoch.
    #[must_use]
    pub const fn desired_member_count(&self) -> usize {
        self.evidence.desired_member_count
    }

    /// Majority required by the desired uniform topology epoch.
    #[must_use]
    pub const fn desired_quorum(&self) -> usize {
        self.evidence.desired_quorum
    }

    /// Committed joint, uniform, and finalization log indexes observed so far.
    #[must_use]
    pub const fn log_indexes(&self) -> SessionTopologyTransitionLogIndexes {
        self.evidence.log_indexes
    }
}

impl fmt::Debug for SessionTopologyTransitionStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTopologyTransitionStatus")
            .field("transition_id", &self.transition_id)
            .field("evidence", &self.evidence)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
struct SessionTopologyAdmissionProofScope {
    transition_id: SessionTopologyTransitionId,
    cluster_id: SessionConsensusClusterId,
    expected_epoch: SessionConsensusConfigurationEpoch,
    desired_epoch: SessionConsensusConfigurationEpoch,
    desired_configuration_id: SessionConsensusConfigurationId,
    request_digest: SessionTopologyTransitionDigest,
    desired_member_count: usize,
}

impl SessionTopologyAdmissionProofScope {
    fn from_request(request: &SessionTopologyTransitionRequest) -> Self {
        Self {
            transition_id: request.transition_id,
            cluster_id: request.cluster_id,
            expected_epoch: request.expected_epoch,
            desired_epoch: request.desired_epoch,
            desired_configuration_id: request.desired_configuration_id,
            request_digest: request.request_digest,
            desired_member_count: request.desired_members.len(),
        }
    }

    fn matches_request(&self, request: &SessionTopologyTransitionRequest) -> bool {
        self.transition_id == request.transition_id
            && self.cluster_id == request.cluster_id
            && self.expected_epoch == request.expected_epoch
            && self.desired_epoch == request.desired_epoch
            && self.desired_configuration_id == request.desired_configuration_id
            && self.request_digest == request.request_digest
            && self.desired_member_count == request.desired_members.len()
    }

    fn validate_status(
        request: &SessionTopologyTransitionRequest,
        status: &SessionTopologyTransitionStatus,
    ) -> Result<(), SessionTopologyTransitionError> {
        if status.transition_id != request.transition_id
            || status.evidence.request_digest != request.request_digest
        {
            return Err(SessionTopologyTransitionError::IdempotencyConflict);
        }
        if status.evidence.expected_epoch != request.expected_epoch
            || status.evidence.desired_epoch != request.desired_epoch
            || status.evidence.desired_configuration_id != request.desired_configuration_id
            || status.evidence.desired_member_count != request.desired_members.len()
        {
            return Err(SessionTopologyTransitionError::InvalidEvidenceState);
        }
        Ok(())
    }
}

impl fmt::Debug for SessionTopologyAdmissionProofScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTopologyAdmissionProofScope")
            .field("transition_id", &self.transition_id)
            .field("cluster_id", &self.cluster_id)
            .field("expected_epoch", &self.expected_epoch)
            .field("desired_epoch", &self.desired_epoch)
            .field("desired_configuration_id", &self.desired_configuration_id)
            .field("request_digest", &self.request_digest)
            .field("desired_member_count", &self.desired_member_count)
            .finish()
    }
}

macro_rules! impl_admission_proof_scope {
    ($proof:ident) => {
        impl $proof {
            /// Caller-owned transition identity bound into this proof.
            #[must_use]
            pub const fn transition_id(&self) -> SessionTopologyTransitionId {
                self.scope.transition_id
            }

            /// Exact validated request digest bound into this proof.
            #[must_use]
            pub const fn request_digest(&self) -> SessionTopologyTransitionDigest {
                self.scope.request_digest
            }

            /// Expected topology epoch bound into this proof.
            #[must_use]
            pub const fn expected_epoch(&self) -> SessionConsensusConfigurationEpoch {
                self.scope.expected_epoch
            }

            /// Desired topology epoch bound into this proof.
            #[must_use]
            pub const fn desired_epoch(&self) -> SessionConsensusConfigurationEpoch {
                self.scope.desired_epoch
            }

            /// Exact desired configuration identity bound into this proof.
            #[must_use]
            pub const fn desired_configuration_id(&self) -> SessionConsensusConfigurationId {
                self.scope.desired_configuration_id
            }

            /// Number of desired voters bound into this proof.
            #[must_use]
            pub const fn desired_member_count(&self) -> usize {
                self.scope.desired_member_count
            }

            /// Verify that this store-issued proof names the exact request.
            #[must_use]
            pub fn validates_request(&self, request: &SessionTopologyTransitionRequest) -> bool {
                self.scope.matches_request(request)
            }
        }
    };
}

/// Store-issued proof that every added learner is identity-admitted and caught up.
///
/// Only the session-store coordinator can construct this token. Transport code
/// may inspect its redaction-safe fixed-width scope, but callers cannot assert
/// learner readiness themselves.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionTopologyLearnersReadyAdmissionProof {
    scope: SessionTopologyAdmissionProofScope,
}

impl SessionTopologyLearnersReadyAdmissionProof {
    /// Mint proof after the coordinator has verified every exact added learner.
    #[allow(
        dead_code,
        reason = "used by the dynamic-membership coordinator in the complete cross-crate integration"
    )]
    pub(crate) fn from_caught_up_request(request: &SessionTopologyTransitionRequest) -> Self {
        Self {
            scope: SessionTopologyAdmissionProofScope::from_request(request),
        }
    }
}

impl_admission_proof_scope!(SessionTopologyLearnersReadyAdmissionProof);

impl fmt::Debug for SessionTopologyLearnersReadyAdmissionProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTopologyLearnersReadyAdmissionProof")
            .field("scope", &self.scope)
            .finish()
    }
}

/// Store-issued proof that no durable transition exists for one staged request.
///
/// Only the session-store coordinator can construct this token, while holding
/// its transition-operation fence and after reading exact durable state. It
/// permits transport code to discard process-local successor staging without
/// falsely recording a durable abort.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionTopologyPrePrepareUnstageProof {
    scope: SessionTopologyAdmissionProofScope,
}

impl SessionTopologyPrePrepareUnstageProof {
    /// Mint proof after exact durable absence was verified under the operation fence.
    pub(crate) fn from_unprepared_request(request: &SessionTopologyTransitionRequest) -> Self {
        Self {
            scope: SessionTopologyAdmissionProofScope::from_request(request),
        }
    }
}

impl_admission_proof_scope!(SessionTopologyPrePrepareUnstageProof);

impl fmt::Debug for SessionTopologyPrePrepareUnstageProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTopologyPrePrepareUnstageProof")
            .field("scope", &self.scope)
            .finish()
    }
}

/// Store-issued proof that an aborted candidate may retire process-local admission.
///
/// The coordinator mints this only after the terminal current-uniform cleanup
/// index is newer than the durable abort decision. Candidate handlers also
/// verify either their replicated abort decision or exact cancellation
/// tombstone before accepting the retirement action.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionTopologyCandidateRetirementProof {
    scope: SessionTopologyAdmissionProofScope,
    abort_decision_log_index: u64,
    abort_cleanup_log_index: u64,
}

impl SessionTopologyCandidateRetirementProof {
    pub(crate) fn try_from_remote_cleanup(
        request: &SessionTopologyTransitionRequest,
        abort_decision_log_index: u64,
        abort_cleanup_log_index: u64,
    ) -> Result<Self, SessionTopologyTransitionError> {
        if abort_decision_log_index == 0 || abort_cleanup_log_index <= abort_decision_log_index {
            return Err(SessionTopologyTransitionError::InvalidEvidenceState);
        }
        Ok(Self {
            scope: SessionTopologyAdmissionProofScope::from_request(request),
            abort_decision_log_index,
            abort_cleanup_log_index,
        })
    }

    /// Log index of the durable pre-joint abort decision.
    #[must_use]
    pub const fn abort_decision_log_index(&self) -> u64 {
        self.abort_decision_log_index
    }

    /// Newer membership index proving exact current-uniform cleanup.
    #[must_use]
    pub const fn abort_cleanup_log_index(&self) -> u64 {
        self.abort_cleanup_log_index
    }
}

impl_admission_proof_scope!(SessionTopologyCandidateRetirementProof);

impl fmt::Debug for SessionTopologyCandidateRetirementProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTopologyCandidateRetirementProof")
            .field("scope", &self.scope)
            .field("abort_decision_log_index", &self.abort_decision_log_index)
            .field("abort_cleanup_log_index", &self.abort_cleanup_log_index)
            .finish()
    }
}

/// Store-issued proof that a pre-joint transition durably aborted.
///
/// This token can only be minted from exact durable `Aborted/Aborted` status.
/// It authorizes transport to remove the staged successor without describing a
/// joint or uniform membership commit as roll-backable.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionTopologyAbortAdmissionProof {
    scope: SessionTopologyAdmissionProofScope,
}

impl SessionTopologyAbortAdmissionProof {
    /// Mint proof from exact durable terminal-abort status.
    #[allow(
        dead_code,
        reason = "used by the dynamic-membership coordinator in the complete cross-crate integration"
    )]
    pub(crate) fn try_from_status(
        request: &SessionTopologyTransitionRequest,
        status: &SessionTopologyTransitionStatus,
    ) -> Result<Self, SessionTopologyTransitionError> {
        SessionTopologyAdmissionProofScope::validate_status(request, status)?;
        if status.phase() != SessionTopologyTransitionPhase::Aborted
            || status.outcome() != SessionTopologyTransitionOutcome::Aborted
            || status.evidence.committed_epoch != request.expected_epoch
            || status.log_indexes().joint().is_some()
            || status.log_indexes().uniform().is_some()
            || status.log_indexes().finalization().is_some()
            || status.log_indexes().abort_decision().is_none()
            || status.log_indexes().abort_cleanup().is_none()
        {
            return Err(SessionTopologyTransitionError::InvalidEvidenceState);
        }
        Ok(Self {
            scope: SessionTopologyAdmissionProofScope::from_request(request),
        })
    }
}

impl_admission_proof_scope!(SessionTopologyAbortAdmissionProof);

impl fmt::Debug for SessionTopologyAbortAdmissionProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTopologyAbortAdmissionProof")
            .field("scope", &self.scope)
            .finish()
    }
}

/// Store-issued proof that exact joint membership is durably applied.
///
/// Successor Vote traffic is forbidden before this token exists. Learner
/// catch-up alone is insufficient because a higher-term Vote from a node that
/// is not yet a committed voter can still perturb the Raft term.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionTopologyJointCommitAdmissionProof {
    scope: SessionTopologyAdmissionProofScope,
}

impl SessionTopologyJointCommitAdmissionProof {
    /// Mint proof from exact durable joint-or-later status.
    pub(crate) fn try_from_status(
        request: &SessionTopologyTransitionRequest,
        status: &SessionTopologyTransitionStatus,
    ) -> Result<Self, SessionTopologyTransitionError> {
        SessionTopologyAdmissionProofScope::validate_status(request, status)?;
        let phase = status.phase();
        let committed_epoch = if phase == SessionTopologyTransitionPhase::JointCommitted {
            request.expected_epoch
        } else {
            request.desired_epoch
        };
        if !matches!(
            phase,
            SessionTopologyTransitionPhase::JointCommitted
                | SessionTopologyTransitionPhase::UniformCommitted
                | SessionTopologyTransitionPhase::Finalizing
                | SessionTopologyTransitionPhase::Completed
        ) || status.evidence.committed_epoch != committed_epoch
            || status.log_indexes().joint().is_none()
        {
            return Err(SessionTopologyTransitionError::InvalidEvidenceState);
        }
        Ok(Self {
            scope: SessionTopologyAdmissionProofScope::from_request(request),
        })
    }
}

impl_admission_proof_scope!(SessionTopologyJointCommitAdmissionProof);

impl fmt::Debug for SessionTopologyJointCommitAdmissionProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTopologyJointCommitAdmissionProof")
            .field("scope", &self.scope)
            .finish()
    }
}

/// Store-issued proof that the desired uniform membership is durably committed.
///
/// The token is available for `UniformCommitted`, `Finalizing`, and terminal
/// `Completed` status only. Transport finalization therefore cannot precede the
/// Openraft uniform-configuration commit.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionTopologyUniformCommitAdmissionProof {
    scope: SessionTopologyAdmissionProofScope,
}

impl SessionTopologyUniformCommitAdmissionProof {
    /// Mint proof from exact durable uniform-or-later status.
    #[allow(
        dead_code,
        reason = "used by the dynamic-membership coordinator in the complete cross-crate integration"
    )]
    pub(crate) fn try_from_status(
        request: &SessionTopologyTransitionRequest,
        status: &SessionTopologyTransitionStatus,
    ) -> Result<Self, SessionTopologyTransitionError> {
        SessionTopologyAdmissionProofScope::validate_status(request, status)?;
        if !matches!(
            status.phase(),
            SessionTopologyTransitionPhase::UniformCommitted
                | SessionTopologyTransitionPhase::Finalizing
                | SessionTopologyTransitionPhase::Completed
        ) || status.evidence.committed_epoch != request.desired_epoch
            || status.log_indexes().joint().is_none()
            || status.log_indexes().uniform().is_none()
        {
            return Err(SessionTopologyTransitionError::InvalidEvidenceState);
        }
        Ok(Self {
            scope: SessionTopologyAdmissionProofScope::from_request(request),
        })
    }
}

impl_admission_proof_scope!(SessionTopologyUniformCommitAdmissionProof);

impl fmt::Debug for SessionTopologyUniformCommitAdmissionProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTopologyUniformCommitAdmissionProof")
            .field("scope", &self.scope)
            .finish()
    }
}

fn reason_is_valid_for_state(
    reason: SessionTopologyTransitionReason,
    outcome: SessionTopologyTransitionOutcome,
    phase: SessionTopologyTransitionPhase,
) -> bool {
    match outcome {
        SessionTopologyTransitionOutcome::InProgress => {
            reason == SessionTopologyTransitionReason::Progressing
        }
        SessionTopologyTransitionOutcome::Succeeded => {
            reason == SessionTopologyTransitionReason::Succeeded
        }
        SessionTopologyTransitionOutcome::Aborted => {
            reason == SessionTopologyTransitionReason::AbortedByCaller
        }
        SessionTopologyTransitionOutcome::RecoveryRequired => {
            matches!(
                reason,
                SessionTopologyTransitionReason::DeadlineExceeded
                    | SessionTopologyTransitionReason::LeaderChanged
                    | SessionTopologyTransitionReason::QuorumUnavailable
            ) || (reason == SessionTopologyTransitionReason::CancellationTooLate
                && matches!(
                    phase,
                    SessionTopologyTransitionPhase::JointCommitted
                        | SessionTopologyTransitionPhase::UniformCommitted
                        | SessionTopologyTransitionPhase::Finalizing
                ))
        }
    }
}

fn member_count_is_valid(count: usize) -> bool {
    (3..=QUORUM_TOPOLOGY_MAX_MEMBERS).contains(&count) && !count.is_multiple_of(2)
}

fn log_indexes_are_valid_for_phase(
    indexes: SessionTopologyTransitionLogIndexes,
    phase: SessionTopologyTransitionPhase,
) -> bool {
    let values_are_nonzero = [
        indexes.joint,
        indexes.uniform,
        indexes.finalization,
        indexes.abort_decision,
        indexes.abort_cleanup,
    ]
    .into_iter()
    .flatten()
    .all(|index| index != 0);
    let values_are_ordered = indexes
        .joint
        .zip(indexes.uniform)
        .is_none_or(|(joint, uniform)| joint < uniform)
        && indexes
            .uniform
            .zip(indexes.finalization)
            .is_none_or(|(uniform, finalization)| uniform < finalization)
        && indexes
            .abort_decision
            .zip(indexes.abort_cleanup)
            .is_none_or(|(decision, cleanup)| decision < cleanup);
    if !values_are_nonzero || !values_are_ordered {
        return false;
    }

    match phase {
        SessionTopologyTransitionPhase::Prepared
        | SessionTopologyTransitionPhase::LearnersCatchingUp
        | SessionTopologyTransitionPhase::LearnersReady
        | SessionTopologyTransitionPhase::AuthorityFenced => {
            indexes == SessionTopologyTransitionLogIndexes::default()
        }
        SessionTopologyTransitionPhase::Aborting => {
            indexes.joint.is_none()
                && indexes.uniform.is_none()
                && indexes.finalization.is_none()
                && indexes.abort_decision.is_some()
                && indexes.abort_cleanup.is_none()
        }
        SessionTopologyTransitionPhase::Aborted => {
            indexes.joint.is_none()
                && indexes.uniform.is_none()
                && indexes.finalization.is_none()
                && indexes.abort_decision.is_some()
                && indexes.abort_cleanup.is_some()
        }
        SessionTopologyTransitionPhase::JointCommitted => {
            indexes.joint.is_some() && indexes.uniform.is_none() && indexes.finalization.is_none()
        }
        SessionTopologyTransitionPhase::UniformCommitted => {
            indexes.joint.is_some() && indexes.uniform.is_some() && indexes.finalization.is_none()
        }
        SessionTopologyTransitionPhase::Finalizing => {
            indexes.joint.is_some() && indexes.uniform.is_some() && indexes.finalization.is_none()
        }
        SessionTopologyTransitionPhase::Completed => {
            indexes.joint.is_some() && indexes.uniform.is_some() && indexes.finalization.is_some()
        }
    }
}

fn validate_desired_membership(
    cluster_id: SessionConsensusClusterId,
    desired_epoch: SessionConsensusConfigurationEpoch,
    desired_members: &[QuorumReplicaDescriptor],
) -> Result<SessionConsensusConfigurationId, SessionTopologyTransitionError> {
    validate_member_count(desired_members.len())?;
    if desired_members
        .windows(2)
        .any(|members| members[0].replica_id() == members[1].replica_id())
    {
        return Err(invalid_topology(QuorumTopologyError::DuplicateReplicaId));
    }

    let fingerprints = desired_members
        .iter()
        .map(QuorumReplicaDescriptor::configuration_fingerprint)
        .collect::<Vec<_>>();
    let desired_configuration_id =
        opc_consensus::derive_configuration_id(cluster_id, desired_epoch, &fingerprints);
    let identity =
        SessionConsensusIdentity::new(cluster_id, desired_configuration_id, desired_epoch);
    let local_replica_id = desired_members
        .first()
        .map(|member| member.replica_id().clone())
        .ok_or_else(|| {
            invalid_topology(QuorumTopologyError::HaMemberCountTooSmall { configured: 0 })
        })?;
    ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
        local_replica_id,
        desired_members.to_vec(),
        identity,
    ))
    .map_err(invalid_topology)?;
    Ok(desired_configuration_id)
}

fn validate_member_count(count: usize) -> Result<(), SessionTopologyTransitionError> {
    if count > QUORUM_TOPOLOGY_MAX_MEMBERS {
        return Err(invalid_topology(QuorumTopologyError::MemberCountTooLarge {
            configured: count,
            max: QUORUM_TOPOLOGY_MAX_MEMBERS,
        }));
    }
    if count < 3 {
        return Err(invalid_topology(
            QuorumTopologyError::HaMemberCountTooSmall { configured: count },
        ));
    }
    if count.is_multiple_of(2) {
        return Err(invalid_topology(
            QuorumTopologyError::HaMemberCountMustBeOdd { configured: count },
        ));
    }
    Ok(())
}

fn invalid_topology(source: QuorumTopologyError) -> SessionTopologyTransitionError {
    SessionTopologyTransitionError::InvalidDesiredTopology { source }
}

fn calculate_request_digest(
    transition_id: SessionTopologyTransitionId,
    cluster_id: SessionConsensusClusterId,
    expected_epoch: SessionConsensusConfigurationEpoch,
    desired_epoch: SessionConsensusConfigurationEpoch,
    desired_configuration_id: SessionConsensusConfigurationId,
    desired_member_count: u32,
    operation_timeout: Duration,
) -> SessionTopologyTransitionDigest {
    let mut hasher = Sha256::new();
    hasher.update(TRANSITION_REQUEST_DIGEST_DOMAIN);
    hasher.update(transition_id.as_bytes());
    hasher.update(cluster_id.as_bytes());
    hasher.update(expected_epoch.get().to_be_bytes());
    hasher.update(desired_epoch.get().to_be_bytes());
    hasher.update(desired_member_count.to_be_bytes());
    hasher.update(desired_configuration_id.as_bytes());
    hasher.update(operation_timeout.as_secs().to_be_bytes());
    hasher.update(operation_timeout.subsec_nanos().to_be_bytes());
    SessionTopologyTransitionDigest::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
mod admission_proof_tests {
    use super::*;
    use crate::topology::{
        ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId,
        ReplicaTlsIdentity,
    };

    fn descriptor(index: u16) -> QuorumReplicaDescriptor {
        QuorumReplicaDescriptor::new(
            ReplicaId::new(format!("proof-replica-{index}")).expect("replica ID"),
            ReplicaEndpoint::new(format!("proof-{index}.test.invalid"), 7443).expect("endpoint"),
            ReplicaTlsIdentity::new(format!(
                "spiffe://proof.test/tenant/test/ns/default/sa/session/nf/smf/instance/{index}"
            ))
            .expect("TLS identity"),
            ReplicaFailureDomain::new(format!("proof-zone-{index}")).expect("failure domain"),
            ReplicaBackingIdentity::new(format!("proof-disk-{index}")).expect("backing identity"),
        )
    }

    fn transition_request(id: u8, timeout: Duration) -> SessionTopologyTransitionRequest {
        SessionTopologyTransitionRequest::try_new(
            SessionTopologyTransitionId::from_bytes([id; 16]),
            SessionConsensusClusterId::new("membership-proof-test").expect("cluster"),
            SessionConsensusConfigurationEpoch::new(7).expect("expected epoch"),
            SessionConsensusConfigurationEpoch::new(8).expect("desired epoch"),
            (1..=5).map(descriptor).collect(),
            timeout,
        )
        .expect("transition request")
    }

    #[test]
    fn admission_proofs_bind_exact_request_and_only_durable_legal_phases() {
        let request = transition_request(51, Duration::from_secs(10));
        let conflicting = transition_request(51, Duration::from_secs(11));
        let learners = SessionTopologyLearnersReadyAdmissionProof::from_caught_up_request(&request);
        assert!(learners.validates_request(&request));
        assert!(!learners.validates_request(&conflicting));

        let aborted = SessionTopologyTransitionStatus::try_from_request(
            &request,
            3,
            request.expected_epoch(),
            SessionTopologyTransitionPhase::Aborted,
            SessionTopologyTransitionOutcome::Aborted,
            SessionTopologyTransitionReason::AbortedByCaller,
            SessionTopologyTransitionLogIndexes::aborted(10, Some(11)),
        )
        .expect("durable abort status");
        let abort_proof = SessionTopologyAbortAdmissionProof::try_from_status(&request, &aborted)
            .expect("abort proof");
        assert!(abort_proof.validates_request(&request));

        let joint = SessionTopologyTransitionStatus::try_from_request(
            &request,
            3,
            request.expected_epoch(),
            SessionTopologyTransitionPhase::JointCommitted,
            SessionTopologyTransitionOutcome::InProgress,
            SessionTopologyTransitionReason::Progressing,
            SessionTopologyTransitionLogIndexes::new(Some(10), None, None),
        )
        .expect("joint status");
        assert_eq!(
            SessionTopologyAbortAdmissionProof::try_from_status(&request, &joint),
            Err(SessionTopologyTransitionError::InvalidEvidenceState),
            "a joint commit is not roll-backable transport-abort proof"
        );
        assert_eq!(
            SessionTopologyUniformCommitAdmissionProof::try_from_status(&request, &joint),
            Err(SessionTopologyTransitionError::InvalidEvidenceState),
            "a joint commit cannot prematurely finalize transport admission"
        );

        let uniform = SessionTopologyTransitionStatus::try_from_request(
            &request,
            3,
            request.desired_epoch(),
            SessionTopologyTransitionPhase::UniformCommitted,
            SessionTopologyTransitionOutcome::InProgress,
            SessionTopologyTransitionReason::Progressing,
            SessionTopologyTransitionLogIndexes::new(Some(10), Some(11), None),
        )
        .expect("uniform status");
        let uniform_proof =
            SessionTopologyUniformCommitAdmissionProof::try_from_status(&request, &uniform)
                .expect("uniform proof");
        assert!(uniform_proof.validates_request(&request));
        assert!(!uniform_proof.validates_request(&conflicting));

        let debug = format!("{learners:?} {abort_proof:?} {uniform_proof:?}");
        assert!(!debug.contains("spiffe://"));
        assert!(!debug.contains("proof-replica"));
        assert!(!debug.contains("33333333333333333333333333333333"));
    }
}
