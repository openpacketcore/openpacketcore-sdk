//! Runtime coordination for one exact session topology-epoch transition.
//!
//! Openraft remains the sole authority for learner, joint, and uniform
//! membership entries. This module serializes the surrounding SDK boundaries:
//! exact peer routing, application-authority fencing, transport admission,
//! durable evidence, and process-local proposal admission.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock, RwLock};

use async_trait::async_trait;
use futures_util::stream::{FuturesUnordered, StreamExt};
use opc_consensus::engine::error::{ClientWriteError, RaftError};
use opc_consensus::engine::{ChangeMembers, EmptyNode, StoredMembership};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::*;
use crate::membership::{
    SessionTopologyAbortAdmissionProof, SessionTopologyCandidateRetirementProof,
    SessionTopologyJointCommitAdmissionProof, SessionTopologyLearnersReadyAdmissionProof,
    SessionTopologyPrePrepareUnstageProof, SessionTopologyTransitionError,
    SessionTopologyTransitionLogIndexes, SessionTopologyTransitionOutcome,
    SessionTopologyTransitionPhase, SessionTopologyTransitionReason,
    SessionTopologyTransitionRequest, SessionTopologyTransitionStatus,
    SessionTopologyUniformCommitAdmissionProof,
};
use crate::sqlite::consensus::{
    MembershipScopeMutationError, MembershipTransitionEvidence, MembershipValidationScope,
    TerminalMembershipOutcome,
};
use crate::topology::{QuorumReplicaDescriptor, QuorumTopologyConfig};

const TRANSITION_REQUEST_ID_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-transition-command/v1\0";
const TRANSITION_ENGINE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

/// Exact authenticated remote-peer set for a desired topology epoch.
///
/// The map must contain every desired voter except the local node. Each peer
/// must report the map key as its authenticated node ID and the request's exact
/// desired consensus identity as its scope.
pub type SessionTopologyTransitionPeers =
    BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>;

/// Immutable database-incarnation identity for joining-node bootstrap.
///
/// This value is redaction-safe identity metadata, not an authorization token
/// or secret. A consumer may serialize it for delivery over its authenticated
/// control plane. Candidate storage, topology, mTLS peer admission, and Raft
/// catch-up independently reject a mismatched or stale anchor.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SessionConsensusStorageAnchor(SessionConsensusIdentity);

impl fmt::Debug for SessionConsensusStorageAnchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionConsensusStorageAnchor")
            .field("identity", &self.0)
            .finish()
    }
}

/// Validated predecessor/successor manifest used to open one joining learner.
///
/// Unlike [`ValidatedQuorumTopology`], this value does not pretend that the
/// candidate is a member of the predecessor topology and does not require the
/// caller to nominate an irrelevant predecessor-local replica. Construction
/// validates both exact descriptor sets, the one-epoch transition, retained
/// descriptor bindings, candidate absence/presence, and immutable anchor
/// cluster scope.
#[derive(Clone)]
pub struct SessionTopologyCandidateBootstrap {
    storage_anchor: SessionConsensusStorageAnchor,
    current_topology: ValidatedQuorumTopology,
    request: SessionTopologyTransitionRequest,
    local_candidate: QuorumReplicaDescriptor,
}

impl SessionTopologyCandidateBootstrap {
    /// Validate one joining candidate bootstrap manifest.
    pub fn try_new(
        storage_anchor: SessionConsensusStorageAnchor,
        current_identity: SessionConsensusIdentity,
        current_members: Vec<QuorumReplicaDescriptor>,
        request: SessionTopologyTransitionRequest,
        local_candidate: QuorumReplicaDescriptor,
    ) -> Result<Self, SessionTopologyTransitionError> {
        let validation_local = current_members
            .first()
            .map(|member| member.replica_id().clone())
            .ok_or(SessionTopologyTransitionError::InvalidTransitionBindings)?;
        let current_topology =
            ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                validation_local,
                current_members,
                current_identity,
            ))
            .map_err(|_| SessionTopologyTransitionError::InvalidTransitionBindings)?;
        if current_identity.cluster_id() != request.cluster_id()
            || current_identity.configuration_epoch() != request.expected_epoch()
            || storage_anchor.0.cluster_id() != request.cluster_id()
            || current_topology
                .members()
                .iter()
                .any(|member| member.replica_id() == local_candidate.replica_id())
        {
            return Err(SessionTopologyTransitionError::InvalidTransitionBindings);
        }
        let desired_descriptor = request
            .desired_members()
            .iter()
            .find(|member| member.replica_id() == local_candidate.replica_id())
            .ok_or(SessionTopologyTransitionError::InvalidTransitionBindings)?;
        if desired_descriptor != &local_candidate {
            return Err(SessionTopologyTransitionError::InvalidTransitionBindings);
        }
        let current_descriptors =
            descriptors_by_node_id(current_identity, current_topology.members())
                .ok_or(SessionTopologyTransitionError::InvalidTransitionBindings)?;
        let desired_descriptors =
            descriptors_by_node_id(request.desired_identity(), request.desired_members())
                .ok_or(SessionTopologyTransitionError::InvalidTransitionBindings)?;
        validate_transition_descriptor_bindings(&current_descriptors, &desired_descriptors)?;
        let current_ids = current_descriptors.keys().copied().collect::<BTreeSet<_>>();
        let desired_ids = desired_descriptors.keys().copied().collect::<BTreeSet<_>>();
        let retained = current_ids.intersection(&desired_ids).count();
        if retained < (current_ids.len() / 2) + 1 || retained < (desired_ids.len() / 2) + 1 {
            return Err(SessionTopologyTransitionError::QuorumLosingChange);
        }
        Ok(Self {
            storage_anchor,
            current_topology,
            request,
            local_candidate,
        })
    }

    /// Exact validated transition request staged by this candidate.
    pub const fn request(&self) -> &SessionTopologyTransitionRequest {
        &self.request
    }

    /// Candidate logical descriptor in the desired manifest.
    #[must_use]
    pub const fn local_candidate(&self) -> &QuorumReplicaDescriptor {
        &self.local_candidate
    }
}

impl fmt::Debug for SessionTopologyCandidateBootstrap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionTopologyCandidateBootstrap")
            .field("storage_anchor", &self.storage_anchor)
            .field(
                "current_identity",
                &self.current_topology.consensus_identity(),
            )
            .field(
                "current_member_count",
                &self.current_topology.members().len(),
            )
            .field("request", &self.request)
            .field("candidate_descriptor", &"<redacted>")
            .finish()
    }
}

/// Redaction-safe failure at the store-owned transport-admission boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SessionTopologyTransportAdmissionError {
    /// The transport rejected a proof or exact transition binding.
    #[error("session topology transport admission rejected the transition")]
    Rejected,
    /// The transport admission boundary is temporarily unavailable.
    #[error("session topology transport admission is unavailable")]
    Unavailable,
}

impl SessionTopologyTransportAdmissionError {
    /// Stable low-cardinality diagnostic code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Rejected => "session_topology_transport_admission_rejected",
            Self::Unavailable => "session_topology_transport_admission_unavailable",
        }
    }
}

/// Product-neutral transport admission required by a membership transition.
///
/// The store owns sequencing and supplies unforgeable proofs. A transport
/// implementation cannot admit successor voting before committed joint membership,
/// retire the predecessor before uniform commit, or remove a staged successor
/// before a durable pre-joint abort.
#[async_trait]
pub trait SessionTopologyTransportAdmission: Send + Sync + 'static {
    /// Discard exact process-local staging before any durable Prepare exists.
    async fn unstage_successor_before_prepare(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyPrePrepareUnstageProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError>;

    /// Retire an aborted candidate after terminal current-uniform cleanup.
    async fn retire_aborted_candidate(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyCandidateRetirementProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError>;

    /// Admit successor-scoped Vote RPCs after exact joint membership applies.
    async fn admit_successor_voting(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyJointCommitAdmissionProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError>;

    /// Retire predecessor transport admission after desired uniform commit.
    async fn finalize_successor(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyUniformCommitAdmissionProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError>;

    /// Remove staged successor admission after a durable pre-joint abort.
    async fn abort_successor(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyAbortAdmissionProof,
    ) -> Result<(), SessionTopologyTransportAdmissionError>;
}

#[derive(Clone)]
struct StagedTopologyBindings {
    request: SessionTopologyTransitionRequest,
    transition_id: crate::membership::SessionTopologyTransitionId,
    request_digest: crate::membership::SessionTopologyTransitionDigest,
    expected_epoch: SessionConsensusConfigurationEpoch,
    desired_identity: SessionConsensusIdentity,
    desired_members: BTreeSet<SessionConsensusNodeId>,
    desired_descriptors: BTreeMap<SessionConsensusNodeId, QuorumReplicaDescriptor>,
    desired_peers: SessionTopologyTransitionPeers,
}

struct TopologyBindingState {
    current_identity: SessionConsensusIdentity,
    current_descriptors: BTreeMap<SessionConsensusNodeId, QuorumReplicaDescriptor>,
    staged: Option<StagedTopologyBindings>,
    // Maximum replicated log index represented by the last accepted scope.
    // This orders async SQLite observations without clocks or task ordering.
    last_scope_progress_index: Option<u64>,
    blocking_terminal: Option<(
        crate::membership::SessionTopologyTransitionId,
        crate::membership::SessionTopologyTransitionDigest,
    )>,
    retained_transitions: BTreeMap<
        crate::membership::SessionTopologyTransitionId,
        crate::membership::SessionTopologyTransitionDigest,
    >,
}

fn membership_scope_progress_index(scope: &MembershipValidationScope) -> u64 {
    let mut progress = 0_u64;
    let mut observe = |index: u64| progress = progress.max(index);

    for predecessor in scope.history.iter().chain(scope.predecessor.iter()) {
        observe(predecessor.transition_start_log_index);
        observe(predecessor.cutover_log_index);
    }
    for terminal in &scope.terminal_history {
        observe(terminal.transition_start_log_index);
        for index in [
            terminal.learners_ready_log_index,
            terminal.joint_membership_log_index,
            terminal.uniform_membership_log_index,
            terminal.cutover_log_index,
            terminal.finalization_log_index,
            terminal.abort_decision_log_index,
            terminal.abort_cleanup_log_index,
        ]
        .into_iter()
        .flatten()
        {
            observe(index);
        }
    }
    if let Some(pending) = &scope.pending {
        observe(pending.transition_start_log_index);
        for index in [
            pending.learners_ready_log_index,
            pending.joint_membership_log_index,
            pending.uniform_membership_log_index,
        ]
        .into_iter()
        .flatten()
        {
            observe(index);
        }
    }
    if let Some(terminal) = &scope.terminal {
        observe(terminal.transition_start_log_index);
        for index in [
            terminal.learners_ready_log_index,
            terminal.joint_membership_log_index,
            terminal.uniform_membership_log_index,
            terminal.cutover_log_index,
            terminal.finalization_log_index,
        ]
        .into_iter()
        .flatten()
        {
            observe(index);
        }
        if let Some(cleanup) = &terminal.abort_cleanup {
            observe(cleanup.decision_log_index);
            if let Some(index) = cleanup.cleanup_log_index {
                observe(index);
            }
        }
    }
    progress
}

fn terminal_membership_is_complete(
    terminal: &crate::sqlite::consensus::TerminalMembershipTransition,
) -> bool {
    match terminal.outcome {
        TerminalMembershipOutcome::Aborted => terminal
            .abort_cleanup
            .as_ref()
            .is_some_and(|cleanup| cleanup.cleanup_log_index.is_some()),
        TerminalMembershipOutcome::Promoted => terminal.finalization_log_index.is_some(),
    }
}

/// Process-local coordination state retained by every store clone.
///
/// Durable membership phase remains in SQLite. This state contains only the
/// proposal drain, redaction-safe descriptor bindings needed before a change,
/// and a set-once local transport adapter.
pub(super) struct SessionTopologyCoordinatorState {
    operation_gate: Arc<tokio::sync::RwLock<()>>,
    bindings: RwLock<TopologyBindingState>,
    transport: OnceLock<Arc<dyn SessionTopologyTransportAdmission>>,
    supervisor_started: AtomicBool,
    supervisor_notify: Arc<tokio::sync::Notify>,
}

impl fmt::Debug for SessionTopologyCoordinatorState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("SessionTopologyCoordinatorState");
        match self.bindings.read() {
            Ok(bindings) => {
                debug
                    .field("current_identity", &bindings.current_identity)
                    .field("current_member_count", &bindings.current_descriptors.len())
                    .field("transition_staged", &bindings.staged.is_some())
                    .field(
                        "terminal_transition_blocking",
                        &bindings.blocking_terminal.is_some(),
                    );
            }
            Err(_) => {
                debug.field("state", &"<unavailable>");
            }
        }
        debug
            .field("transport_bound", &self.transport.get().is_some())
            .finish()
    }
}

impl SessionTopologyCoordinatorState {
    pub(super) fn try_from_topology(
        topology: &ValidatedQuorumTopology,
    ) -> Result<Self, ConsensusSessionStoreOpenError> {
        let identity = topology
            .consensus_identity()
            .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)?;
        let descriptors = descriptors_by_node_id(identity, topology.members())
            .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)?;
        Ok(Self {
            operation_gate: Arc::new(tokio::sync::RwLock::new(())),
            bindings: RwLock::new(TopologyBindingState {
                current_identity: identity,
                current_descriptors: descriptors,
                staged: None,
                last_scope_progress_index: None,
                blocking_terminal: None,
                retained_transitions: BTreeMap::new(),
            }),
            transport: OnceLock::new(),
            supervisor_started: AtomicBool::new(false),
            supervisor_notify: Arc::new(tokio::sync::Notify::new()),
        })
    }

    pub(super) fn operation_gate(&self) -> Arc<tokio::sync::RwLock<()>> {
        Arc::clone(&self.operation_gate)
    }

    pub(super) fn load_retained_transitions(
        &self,
        scope: &MembershipValidationScope,
    ) -> Result<(), SessionTopologyTransitionError> {
        let mut retained = BTreeMap::new();
        for (transition_id, request_digest) in
            scope
                .terminal
                .iter()
                .filter(|terminal| terminal_membership_is_complete(terminal))
                .map(|terminal| (terminal.transition_id, terminal.transition_digest))
                .chain(
                    scope
                        .terminal_history
                        .iter()
                        .map(|terminal| (terminal.transition_id, terminal.transition_digest)),
                )
                .chain(
                    scope.predecessor.iter().map(|predecessor| {
                        (predecessor.transition_id, predecessor.transition_digest)
                    }),
                )
                .chain(
                    scope.history.iter().map(|predecessor| {
                        (predecessor.transition_id, predecessor.transition_digest)
                    }),
                )
        {
            let transition_id =
                crate::membership::SessionTopologyTransitionId::from_bytes(transition_id);
            let request_digest =
                crate::membership::SessionTopologyTransitionDigest::from_bytes(request_digest);
            if retained
                .insert(transition_id, request_digest)
                .is_some_and(|existing| existing != request_digest)
            {
                return Err(SessionTopologyTransitionError::InvalidEvidenceState);
            }
        }
        // A promoted transition is also the current predecessor lineage.
        // Until its terminal finalize applies, its exact ID remains resumable
        // rather than becoming an immutable history tombstone. Its terminal
        // blocker still rejects every other ID and every conflicting digest.
        if let Some(terminal) = scope
            .terminal
            .as_ref()
            .filter(|terminal| !terminal_membership_is_complete(terminal))
        {
            retained.remove(&crate::membership::SessionTopologyTransitionId::from_bytes(
                terminal.transition_id,
            ));
        }
        let blocking_terminal = scope.terminal.as_ref().and_then(|terminal| {
            (!terminal_membership_is_complete(terminal)).then_some((
                crate::membership::SessionTopologyTransitionId::from_bytes(terminal.transition_id),
                crate::membership::SessionTopologyTransitionDigest::from_bytes(
                    terminal.transition_digest,
                ),
            ))
        });
        let progress_index = membership_scope_progress_index(scope);
        let mut state = self
            .bindings
            .write()
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        // Terminal creation/completion and terminal-history rotation each
        // carry their committing log index. A delayed older read must not
        // clear a newer blocker or retained transition-ID binding. Equal
        // progress with different derived authority is inconsistent and
        // therefore fails closed.
        if let Some(observed) = state.last_scope_progress_index {
            match progress_index.cmp(&observed) {
                std::cmp::Ordering::Less => return Ok(()),
                std::cmp::Ordering::Equal
                    if state.retained_transitions != retained
                        || state.blocking_terminal != blocking_terminal =>
                {
                    return Err(SessionTopologyTransitionError::InvalidEvidenceState);
                }
                std::cmp::Ordering::Equal => return Ok(()),
                std::cmp::Ordering::Greater => {}
            }
        }
        state.retained_transitions = retained;
        state.blocking_terminal = blocking_terminal;
        state.last_scope_progress_index = Some(progress_index);
        Ok(())
    }

    fn bind_transport(
        &self,
        transport: Arc<dyn SessionTopologyTransportAdmission>,
    ) -> Result<(), SessionTopologyTransitionError> {
        self.transport
            .set(transport)
            .map_err(|_| SessionTopologyTransitionError::InvalidTransitionBindings)
    }

    fn notify_supervisor(&self) {
        self.supervisor_notify.notify_one();
    }

    fn staged_request_if_any(
        &self,
    ) -> Result<Option<SessionTopologyTransitionRequest>, SessionTopologyTransitionError> {
        self.bindings
            .read()
            .map(|state| state.staged.as_ref().map(|staged| staged.request.clone()))
            .map_err(|_| SessionTopologyTransitionError::Unavailable)
    }

    fn transport(
        &self,
    ) -> Result<Arc<dyn SessionTopologyTransportAdmission>, SessionTopologyTransitionError> {
        self.transport
            .get()
            .cloned()
            .ok_or(SessionTopologyTransitionError::Unavailable)
    }

    fn stage_bindings(
        &self,
        request: &SessionTopologyTransitionRequest,
        desired_peers: &SessionTopologyTransitionPeers,
    ) -> Result<bool, SessionTopologyTransitionError> {
        let desired_members = request.desired_consensus_node_ids();
        let desired_descriptors =
            descriptors_by_node_id(request.desired_identity(), request.desired_members())
                .ok_or(SessionTopologyTransitionError::InvalidTransitionBindings)?;
        if desired_members.len() != request.desired_members().len()
            || desired_descriptors.len() != desired_members.len()
        {
            return Err(SessionTopologyTransitionError::InvalidTransitionBindings);
        }

        let mut state = self
            .bindings
            .write()
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        if let Some((blocking_id, blocking_digest)) = state.blocking_terminal {
            if blocking_id != request.transition_id() {
                return Err(SessionTopologyTransitionError::TransitionInProgress);
            }
            if blocking_digest != request.request_digest() {
                return Err(SessionTopologyTransitionError::IdempotencyConflict);
            }
        }
        if let Some(retained_digest) = state.retained_transitions.get(&request.transition_id()) {
            if *retained_digest != request.request_digest() {
                return Err(SessionTopologyTransitionError::IdempotencyConflict);
            }
            if state.current_identity == request.desired_identity()
                && state.current_descriptors == desired_descriptors
            {
                return Ok(false);
            }
            return Err(SessionTopologyTransitionError::IdempotencyConflict);
        }
        if state.current_identity == request.desired_identity() {
            if state.current_descriptors != desired_descriptors {
                return Err(SessionTopologyTransitionError::InvalidTransitionBindings);
            }
            return match state.staged.as_ref() {
                Some(staged)
                    if staged.transition_id == request.transition_id()
                        && staged.request_digest == request.request_digest()
                        && staged.desired_identity == request.desired_identity()
                        && staged.desired_descriptors == desired_descriptors
                        && same_peer_bindings(&staged.desired_peers, desired_peers) =>
                {
                    Ok(false)
                }
                Some(staged) if staged.transition_id == request.transition_id() => {
                    Err(SessionTopologyTransitionError::IdempotencyConflict)
                }
                Some(_) => Err(SessionTopologyTransitionError::TransitionInProgress),
                None => {
                    state.staged = Some(StagedTopologyBindings {
                        request: request.clone(),
                        transition_id: request.transition_id(),
                        request_digest: request.request_digest(),
                        expected_epoch: request.expected_epoch(),
                        desired_identity: request.desired_identity(),
                        desired_members,
                        desired_descriptors,
                        desired_peers: desired_peers.clone(),
                    });
                    Ok(true)
                }
            };
        }
        if state.current_identity.cluster_id() != request.cluster_id()
            || state.current_identity.configuration_epoch() != request.expected_epoch()
        {
            return Err(SessionTopologyTransitionError::StaleEpoch);
        }
        if desired_members
            == state
                .current_descriptors
                .keys()
                .copied()
                .collect::<BTreeSet<_>>()
        {
            return Err(SessionTopologyTransitionError::NoMembershipChange);
        }
        let current_members = state
            .current_descriptors
            .keys()
            .copied()
            .collect::<BTreeSet<_>>();
        let retained_members = current_members.intersection(&desired_members).count();
        let current_quorum = (current_members.len() / 2) + 1;
        let desired_quorum = (desired_members.len() / 2) + 1;
        if retained_members < current_quorum || retained_members < desired_quorum {
            return Err(SessionTopologyTransitionError::QuorumLosingChange);
        }
        validate_transition_descriptor_bindings(&state.current_descriptors, &desired_descriptors)?;

        match state.staged.as_ref() {
            Some(staged)
                if staged.transition_id == request.transition_id()
                    && staged.request_digest == request.request_digest()
                    && staged.expected_epoch == request.expected_epoch()
                    && staged.desired_identity == request.desired_identity()
                    && staged.desired_members == desired_members
                    && staged.desired_descriptors == desired_descriptors
                    && same_peer_bindings(&staged.desired_peers, desired_peers) =>
            {
                Ok(false)
            }
            Some(staged) if staged.transition_id == request.transition_id() => {
                Err(SessionTopologyTransitionError::IdempotencyConflict)
            }
            Some(_) => Err(SessionTopologyTransitionError::TransitionInProgress),
            None => {
                state.staged = Some(StagedTopologyBindings {
                    request: request.clone(),
                    transition_id: request.transition_id(),
                    request_digest: request.request_digest(),
                    expected_epoch: request.expected_epoch(),
                    desired_identity: request.desired_identity(),
                    desired_members,
                    desired_descriptors,
                    desired_peers: desired_peers.clone(),
                });
                Ok(true)
            }
        }
    }

    fn finalize_bindings(
        &self,
        request: &SessionTopologyTransitionRequest,
    ) -> Result<(), SessionTopologyTransitionError> {
        let desired_descriptors =
            descriptors_by_node_id(request.desired_identity(), request.desired_members())
                .ok_or(SessionTopologyTransitionError::InvalidTransitionBindings)?;
        let mut state = self
            .bindings
            .write()
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        if state.current_identity == request.desired_identity() {
            if state.current_descriptors != desired_descriptors {
                return Err(SessionTopologyTransitionError::InvalidTransitionBindings);
            }
            if let Some(staged) = state.staged.as_ref() {
                if staged.transition_id != request.transition_id()
                    || staged.request_digest != request.request_digest()
                    || staged.desired_identity != request.desired_identity()
                    || staged.desired_descriptors != desired_descriptors
                {
                    return Err(SessionTopologyTransitionError::IdempotencyConflict);
                }
                state.staged = None;
            }
            return Ok(());
        }
        if state.current_identity.configuration_epoch() != request.expected_epoch()
            || state.current_identity.cluster_id() != request.cluster_id()
        {
            return Err(SessionTopologyTransitionError::StaleEpoch);
        }
        let staged = state
            .staged
            .take()
            .ok_or(SessionTopologyTransitionError::InvalidTransitionBindings)?;
        if staged.transition_id != request.transition_id()
            || staged.request_digest != request.request_digest()
            || staged.desired_identity != request.desired_identity()
            || staged.desired_descriptors != desired_descriptors
        {
            state.staged = Some(staged);
            return Err(SessionTopologyTransitionError::IdempotencyConflict);
        }
        state.current_identity = staged.desired_identity;
        state.current_descriptors = staged.desired_descriptors;
        Ok(())
    }

    fn drop_staged_bindings(
        &self,
        transition_id: crate::membership::SessionTopologyTransitionId,
        request_digest: crate::membership::SessionTopologyTransitionDigest,
    ) -> Result<(), SessionTopologyTransitionError> {
        let mut state = self
            .bindings
            .write()
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        let Some(staged) = state.staged.take() else {
            return Ok(());
        };
        if staged.transition_id != transition_id || staged.request_digest != request_digest {
            state.staged = Some(staged);
            return Err(SessionTopologyTransitionError::IdempotencyConflict);
        }
        Ok(())
    }

    async fn admit_staged_successor_voting(
        &self,
        request: &SessionTopologyTransitionRequest,
        status: &SessionTopologyTransitionStatus,
    ) -> Result<(), SessionTopologyTransitionError> {
        {
            let state = self
                .bindings
                .read()
                .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
            let staged = state
                .staged
                .as_ref()
                .ok_or(SessionTopologyTransitionError::InvalidTransitionBindings)?;
            if staged.transition_id != request.transition_id()
                || staged.request_digest != request.request_digest()
            {
                return Err(SessionTopologyTransitionError::IdempotencyConflict);
            }
            if staged.request != *request {
                return Err(SessionTopologyTransitionError::InvalidTransitionBindings);
            }
        }
        let proof = SessionTopologyJointCommitAdmissionProof::try_from_status(request, status)?;
        self.transport()?
            .admit_successor_voting(request, &proof)
            .await
            .map_err(map_transport_error)
    }

    async fn finalize_staged_successor_transport(
        &self,
        request: &SessionTopologyTransitionRequest,
        status: &SessionTopologyTransitionStatus,
        deadline: tokio::time::Instant,
    ) -> Result<(), SessionTopologyTransitionError> {
        let proof = SessionTopologyUniformCommitAdmissionProof::try_from_status(request, status)?;
        tokio::time::timeout_at(
            deadline,
            self.transport()?.finalize_successor(request, &proof),
        )
        .await
        .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?
        .map_err(map_transport_error)
    }

    async fn abort_staged_successor_transport(
        &self,
        request: &SessionTopologyTransitionRequest,
        status: &SessionTopologyTransitionStatus,
        deadline: tokio::time::Instant,
    ) -> Result<(), SessionTopologyTransitionError> {
        let proof = SessionTopologyAbortAdmissionProof::try_from_status(request, status)?;
        tokio::time::timeout_at(deadline, self.transport()?.abort_successor(request, &proof))
            .await
            .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?
            .map_err(map_transport_error)
    }

    fn staged_request(
        &self,
        transition_id: crate::membership::SessionTopologyTransitionId,
        request_digest: crate::membership::SessionTopologyTransitionDigest,
    ) -> Result<SessionTopologyTransitionRequest, SessionTopologyTransitionError> {
        let state = self
            .bindings
            .read()
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        let staged = state
            .staged
            .as_ref()
            .ok_or(SessionTopologyTransitionError::InvalidTransitionBindings)?;
        if staged.transition_id != transition_id || staged.request_digest != request_digest {
            return Err(SessionTopologyTransitionError::IdempotencyConflict);
        }
        Ok(staged.request.clone())
    }

    fn is_current_request(
        &self,
        request: &SessionTopologyTransitionRequest,
    ) -> Result<bool, SessionTopologyTransitionError> {
        let desired_descriptors =
            descriptors_by_node_id(request.desired_identity(), request.desired_members())
                .ok_or(SessionTopologyTransitionError::InvalidTransitionBindings)?;
        let state = self
            .bindings
            .read()
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        Ok(state.current_identity == request.desired_identity()
            && state.current_descriptors == desired_descriptors)
    }

    fn authorizes_staged_sender(
        &self,
        request: &SessionTopologyTransitionRequest,
        sender: SessionConsensusNodeId,
    ) -> Result<bool, SessionTopologyTransitionError> {
        let state = self
            .bindings
            .read()
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        let current_member = state.current_descriptors.contains_key(&sender);
        let desired_member = request.desired_consensus_node_ids().contains(&sender);
        Ok(current_member || desired_member)
    }

    fn current_members(
        &self,
    ) -> Result<BTreeSet<SessionConsensusNodeId>, SessionTopologyTransitionError> {
        self.bindings
            .read()
            .map(|state| state.current_descriptors.keys().copied().collect())
            .map_err(|_| SessionTopologyTransitionError::Unavailable)
    }

    fn has_exact_staged_request(
        &self,
        request: &SessionTopologyTransitionRequest,
    ) -> Result<bool, SessionTopologyTransitionError> {
        let state = self
            .bindings
            .read()
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        match state.staged.as_ref() {
            None => Ok(false),
            Some(staged)
                if staged.transition_id == request.transition_id()
                    && staged.request_digest == request.request_digest() =>
            {
                Ok(true)
            }
            Some(_) => Err(SessionTopologyTransitionError::TransitionInProgress),
        }
    }

    fn is_current_expected_epoch(
        &self,
        request: &SessionTopologyTransitionRequest,
    ) -> Result<bool, SessionTopologyTransitionError> {
        let state = self
            .bindings
            .read()
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        Ok(state.current_identity.cluster_id() == request.cluster_id()
            && state.current_identity.configuration_epoch() == request.expected_epoch())
    }

    fn staged_peers(
        &self,
        request: &SessionTopologyTransitionRequest,
    ) -> Result<SessionTopologyTransitionPeers, SessionTopologyTransitionError> {
        let state = self
            .bindings
            .read()
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        let staged = state
            .staged
            .as_ref()
            .ok_or(SessionTopologyTransitionError::InvalidTransitionBindings)?;
        if staged.transition_id != request.transition_id()
            || staged.request_digest != request.request_digest()
        {
            return Err(SessionTopologyTransitionError::IdempotencyConflict);
        }
        Ok(staged.desired_peers.clone())
    }
}

fn map_transport_error(
    error: SessionTopologyTransportAdmissionError,
) -> SessionTopologyTransitionError {
    match error {
        SessionTopologyTransportAdmissionError::Rejected => {
            SessionTopologyTransitionError::InvalidTransitionBindings
        }
        SessionTopologyTransportAdmissionError::Unavailable => {
            SessionTopologyTransitionError::Unavailable
        }
    }
}

fn same_peer_bindings(
    left: &SessionTopologyTransitionPeers,
    right: &SessionTopologyTransitionPeers,
) -> bool {
    left.len() == right.len()
        && left.iter().all(|(node_id, peer)| {
            right.get(node_id).is_some_and(|candidate| {
                peer.node_id() == candidate.node_id()
                    && peer.scope_identity() == candidate.scope_identity()
            })
        })
}

fn descriptors_by_node_id(
    identity: SessionConsensusIdentity,
    descriptors: &[QuorumReplicaDescriptor],
) -> Option<BTreeMap<SessionConsensusNodeId, QuorumReplicaDescriptor>> {
    descriptors
        .iter()
        .map(|descriptor| {
            opc_consensus::derive_node_id(
                identity.cluster_id(),
                descriptor.replica_id().as_str().as_bytes(),
            )
            .ok()
            .map(|node_id| (node_id, descriptor.clone()))
        })
        .collect()
}

fn validate_transition_descriptor_bindings(
    current: &BTreeMap<SessionConsensusNodeId, QuorumReplicaDescriptor>,
    desired: &BTreeMap<SessionConsensusNodeId, QuorumReplicaDescriptor>,
) -> Result<(), SessionTopologyTransitionError> {
    for (node_id, descriptor) in current {
        if desired.get(node_id).is_some_and(|candidate| {
            descriptor.configuration_fingerprint() != candidate.configuration_fingerprint()
        }) {
            return Err(SessionTopologyTransitionError::InvalidTransitionBindings);
        }
    }
    for (current_id, current_descriptor) in current {
        for (desired_id, desired_descriptor) in desired {
            if current_id == desired_id {
                continue;
            }
            if current_descriptor.endpoint() == desired_descriptor.endpoint()
                || current_descriptor.tls_identity() == desired_descriptor.tls_identity()
                || current_descriptor.backing_identity() == desired_descriptor.backing_identity()
            {
                return Err(SessionTopologyTransitionError::InvalidTransitionBindings);
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransitionControlKind {
    Prepare = 1,
    LearnersReady = 2,
    Fence = 3,
    Abort = 4,
    Finalize = 5,
    AbortCleanup = 6,
}

fn transition_request_id(
    request: &SessionTopologyTransitionRequest,
    kind: TransitionControlKind,
) -> SessionConsensusRequestId {
    let mut hasher = Sha256::new();
    hasher.update(TRANSITION_REQUEST_ID_DOMAIN);
    hasher.update(request.transition_id().as_bytes());
    hasher.update(request.request_digest().as_bytes());
    hasher.update([kind as u8]);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut request_id = [0_u8; 16];
    request_id.copy_from_slice(&digest[..16]);
    SessionConsensusRequestId::from_bytes(request_id)
}

fn transition_engine_attempt_deadline(
    operation_deadline: tokio::time::Instant,
) -> tokio::time::Instant {
    tokio::time::Instant::now()
        .checked_add(TRANSITION_ENGINE_ATTEMPT_TIMEOUT)
        .map_or(operation_deadline, |attempt| {
            attempt.min(operation_deadline)
        })
}

fn validate_desired_peer_map(
    local_node_id: SessionConsensusNodeId,
    request: &SessionTopologyTransitionRequest,
    peers: &SessionTopologyTransitionPeers,
) -> Result<BTreeSet<SessionConsensusNodeId>, SessionTopologyTransitionError> {
    let desired_members = request.desired_consensus_node_ids();
    if desired_members.len() != request.desired_members().len()
        || (!desired_members.contains(&local_node_id)
            && peers.keys().copied().collect::<BTreeSet<_>>() != desired_members)
    {
        return Err(SessionTopologyTransitionError::InvalidTransitionBindings);
    }
    let expected_peers = desired_members
        .iter()
        .copied()
        .filter(|node_id| *node_id != local_node_id)
        .collect::<BTreeSet<_>>();
    if peers.keys().copied().collect::<BTreeSet<_>>() != expected_peers
        || peers.iter().any(|(node_id, peer)| {
            peer.node_id() != *node_id || peer.scope_identity() != Some(request.desired_identity())
        })
    {
        return Err(SessionTopologyTransitionError::InvalidTransitionBindings);
    }
    Ok(desired_members)
}

fn transition_deadline(
    request: &SessionTopologyTransitionRequest,
) -> Result<tokio::time::Instant, SessionTopologyTransitionError> {
    tokio::time::Instant::now()
        .checked_add(request.operation_timeout())
        .ok_or(SessionTopologyTransitionError::InvalidOperationTimeout)
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct TopologyAdmissionBarrierRequest {
    transition_id: [u8; 16],
    request_digest: [u8; 32],
    action: TopologyAdmissionBarrierAction,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum TopologyAdmissionBarrierAction {
    ConfirmStaged,
    AppliedLearnerMarker {
        log_index: u64,
    },
    AdmitJointVoting,
    AppliedAbortDecision {
        log_index: u64,
    },
    CancelProvisionalCandidate,
    FinalizeAbortedCandidate {
        abort_decision_log_index: u64,
        abort_cleanup_log_index: u64,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum TopologyAdmissionBarrierReply {
    Ready,
    NotReady,
}

struct DurableTransitionState {
    scope: MembershipValidationScope,
    evidence: Option<MembershipTransitionEvidence>,
    applied_membership: StoredMembership<SessionConsensusNodeId, EmptyNode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppliedMembershipShape {
    CurrentUniform,
    Learners,
    Joint,
    DesiredUniform,
    Invalid,
}

fn classify_applied_membership(
    membership: &StoredMembership<SessionConsensusNodeId, EmptyNode>,
    current_members: &BTreeSet<SessionConsensusNodeId>,
    desired_members: &BTreeSet<SessionConsensusNodeId>,
) -> AppliedMembershipShape {
    if membership.log_id().is_none() {
        return AppliedMembershipShape::Invalid;
    }
    let configs = membership.membership().get_joint_config();
    let learners = membership
        .membership()
        .learner_ids()
        .collect::<BTreeSet<_>>();
    let nodes = membership
        .membership()
        .nodes()
        .map(|(node_id, _)| *node_id)
        .collect::<BTreeSet<_>>();
    if configs.len() == 2
        && configs.first() == Some(current_members)
        && configs.get(1) == Some(desired_members)
        && learners.is_empty()
        && nodes == current_members.union(desired_members).copied().collect()
    {
        return AppliedMembershipShape::Joint;
    }
    if configs.len() != 1 {
        return AppliedMembershipShape::Invalid;
    }
    if configs.first() == Some(desired_members) && learners.is_empty() && nodes == *desired_members
    {
        return AppliedMembershipShape::DesiredUniform;
    }
    if configs.first() != Some(current_members) {
        return AppliedMembershipShape::Invalid;
    }
    if learners.is_empty() && nodes == *current_members {
        return AppliedMembershipShape::CurrentUniform;
    }
    let expected_additions = desired_members
        .difference(current_members)
        .copied()
        .collect::<BTreeSet<_>>();
    if learners.is_subset(&expected_additions)
        && nodes == current_members.union(&learners).copied().collect()
    {
        AppliedMembershipShape::Learners
    } else {
        AppliedMembershipShape::Invalid
    }
}

fn map_membership_storage_error(
    error: MembershipScopeMutationError,
) -> SessionTopologyTransitionError {
    match error {
        MembershipScopeMutationError::ConflictingTransition => {
            SessionTopologyTransitionError::IdempotencyConflict
        }
        MembershipScopeMutationError::InvalidScope | MembershipScopeMutationError::CorruptState => {
            SessionTopologyTransitionError::InvalidEvidenceState
        }
        MembershipScopeMutationError::CompactionRequired
        | MembershipScopeMutationError::TransitionNotQuiescent
        | MembershipScopeMutationError::BackendUnavailable => {
            SessionTopologyTransitionError::Unavailable
        }
    }
}

impl ConsensusSessionStore {
    /// Open a joining learner that is absent from the current voter topology.
    ///
    /// `bootstrap` contains the immutable database anchor, exact predecessor
    /// descriptor set, transition request, and local successor descriptor. The
    /// desired peer map contains every desired member except the candidate. A
    /// candidate installs no predecessor-scope outbound routes; it only accepts
    /// inbound learner replication until the successor scope is committed.
    ///
    /// The returned node is application- and Vote-fenced. Callers install its
    /// RPC handler, bind the topology transport admission adapter, and leave
    /// cluster initialization to the existing voters. Only replicated learner
    /// catch-up followed by committed joint membership can admit voting.
    pub async fn open_membership_candidate(
        bootstrap: SessionTopologyCandidateBootstrap,
        backend: SqliteSessionBackend,
        snapshot_dir: impl Into<PathBuf>,
        desired_peers: SessionTopologyTransitionPeers,
    ) -> Result<Self, ConsensusSessionStoreOpenError> {
        let SessionTopologyCandidateBootstrap {
            storage_anchor,
            current_topology,
            request,
            local_candidate,
        } = bootstrap;
        let current_identity = current_topology
            .consensus_identity()
            .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)?;
        if !matches!(
            current_topology.summary().mode(),
            QuorumTopologyMode::ValidatedHa | QuorumTopologyMode::AttestedHa
        ) || current_identity.cluster_id() != request.cluster_id()
            || current_identity.configuration_epoch() != request.expected_epoch()
            || storage_anchor.0.cluster_id() != request.cluster_id()
            || current_topology
                .members()
                .iter()
                .any(|member| member.replica_id() == local_candidate.replica_id())
        {
            return Err(ConsensusSessionStoreOpenError::InvalidTopology);
        }
        let desired_descriptor = request
            .desired_members()
            .iter()
            .find(|member| member.replica_id() == local_candidate.replica_id())
            .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)?;
        if desired_descriptor != &local_candidate {
            return Err(ConsensusSessionStoreOpenError::InvalidTopology);
        }
        let desired_topology =
            ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
                local_candidate.replica_id().clone(),
                request.desired_members().to_vec(),
                request.desired_identity(),
            ))
            .map_err(|_| ConsensusSessionStoreOpenError::InvalidTopology)?;
        let local_node_id = desired_topology
            .local_consensus_node_id()
            .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)?;
        let current_members = current_topology
            .members()
            .iter()
            .map(|descriptor| {
                current_topology
                    .consensus_node_id(descriptor.replica_id())
                    .ok_or(ConsensusSessionStoreOpenError::InvalidTopology)
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if current_members.contains(&local_node_id) {
            return Err(ConsensusSessionStoreOpenError::InvalidTopology);
        }
        validate_desired_peer_map(local_node_id, &request, &desired_peers)
            .map_err(|_| ConsensusSessionStoreOpenError::PeerSetMismatch)?;
        let cancelled = backend
            .provisional_consensus_candidate_is_cancelled(
                storage_anchor.0,
                local_node_id,
                request.transition_id().as_bytes(),
                request.request_digest().as_bytes(),
            )
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::StorageUnavailable)?;
        if cancelled {
            // No process-local routes or transport admission have been
            // published by this fresh handle yet. Refusing construction is
            // the idempotent restart cleanup boundary and prevents the exact
            // tombstoned candidate scope from being revived.
            return Err(ConsensusSessionStoreOpenError::CandidateTransitionCancelled);
        }

        let topology_coordinator = Arc::new(SessionTopologyCoordinatorState::try_from_topology(
            &current_topology,
        )?);
        let network = SessionRaftNetworkFactory::try_new_candidate(
            current_identity,
            local_node_id,
            current_members.clone(),
        )?;
        let peer_directory = network.peer_directory();
        let current_bindings = topology_node_bindings(&current_topology);
        let desired_members = request.desired_consensus_node_ids();
        let desired_bindings = request.desired_node_bindings();
        let (log_store, state_machine, storage_identity) = storage::open_with_pending_membership(
            &backend,
            snapshot_dir,
            storage_anchor.0,
            current_identity,
            current_members.clone(),
            current_bindings,
            local_node_id,
            request.transition_id().as_bytes(),
            request.request_digest().as_bytes(),
            request.desired_identity(),
            &desired_members,
            &desired_bindings,
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
        let topology_summary = desired_topology.summary().clone();
        let topology_attestation_time_high_water = topology_summary
            .attestation_admission()
            .production_verified_at()
            .map(TopologyAttestationTime::unix_seconds)
            .unwrap_or(0);
        let store = Self {
            inner: Arc::new(ConsensusSessionStoreInner {
                raft,
                raft_handler,
                backend,
                storage_identity,
                local_node_id,
                peer_directory,
                topology_coordinator,
                bootstrap_members: current_members,
                topology: topology_summary,
                clock: Arc::new(SystemClock),
                operation_timeout: DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
                admitted: AtomicBool::new(false),
                topology_attestation_time_high_water: AtomicU64::new(
                    topology_attestation_time_high_water,
                ),
                linearizability,
                read_barrier,
                proposal_admission: Arc::new(tokio::sync::Semaphore::new(
                    DURABLE_OPENRAFT_PROPOSAL_ADMISSION_SLOTS,
                )),
            }),
        };
        store
            .stage_topology_transition_peers(&request, desired_peers)
            .map_err(|_| ConsensusSessionStoreOpenError::PeerSetMismatch)?;
        Ok(store)
    }

    /// Return this database's immutable candidate-bootstrap anchor.
    ///
    /// The value is safe to expose through a consumer-authenticated control
    /// plane. It grants no authority by itself.
    #[must_use]
    pub fn storage_anchor(&self) -> SessionConsensusStorageAnchor {
        SessionConsensusStorageAnchor(self.inner.storage_identity)
    }

    /// Bind the one local transport-admission adapter used by topology changes.
    ///
    /// Binding is set-once for the process lifetime. Dynamic membership APIs
    /// fail closed until it is installed; immutable-topology users do not need
    /// to bind an adapter.
    pub fn bind_topology_transport_admission(
        &self,
        transport: Arc<dyn SessionTopologyTransportAdmission>,
    ) -> Result<(), SessionTopologyTransitionError> {
        self.inner.topology_coordinator.bind_transport(transport)?;
        self.ensure_topology_reconciliation_supervisor()?;
        self.inner.topology_coordinator.notify_supervisor();
        Ok(())
    }

    /// Stage exact desired-epoch engine routes on this local node.
    ///
    /// Every current member and joining candidate must stage routes before the
    /// leader starts learner replication. This operation changes no Openraft
    /// membership and grants no successor voting or application authority.
    pub fn stage_topology_transition_peers(
        &self,
        request: &SessionTopologyTransitionRequest,
        desired_peers: SessionTopologyTransitionPeers,
    ) -> Result<(), SessionTopologyTransitionError> {
        let desired_members =
            validate_desired_peer_map(self.inner.local_node_id, request, &desired_peers)?;
        let inserted_bindings = self
            .inner
            .topology_coordinator
            .stage_bindings(request, &desired_peers)?;
        let mut peer_routes_staged = false;
        let result = (|| {
            let (current_identity, current_members) = self
                .inner
                .peer_directory
                .current_scope()
                .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
            if current_identity == request.desired_identity() && current_members == desired_members
            {
                self.ensure_topology_reconciliation_supervisor()?;
                self.inner.topology_coordinator.notify_supervisor();
                return Ok(());
            }
            if current_identity.cluster_id() != request.cluster_id()
                || current_identity.configuration_epoch() != request.expected_epoch()
            {
                return Err(SessionTopologyTransitionError::StaleEpoch);
            }
            if current_members
                .intersection(&desired_members)
                .next()
                .is_none()
            {
                return Err(SessionTopologyTransitionError::InvalidTransitionBindings);
            }
            self.inner
                .peer_directory
                .stage(
                    request.transition_id(),
                    request.request_digest(),
                    request.expected_epoch(),
                    request.desired_identity(),
                    desired_members,
                    desired_peers,
                )
                .map_err(|_| SessionTopologyTransitionError::InvalidTransitionBindings)?;
            peer_routes_staged = true;
            self.ensure_topology_reconciliation_supervisor()?;
            self.inner.topology_coordinator.notify_supervisor();
            Ok(())
        })();
        if result.is_err() && inserted_bindings {
            if peer_routes_staged {
                let _ = self.inner.peer_directory.unstage_before_prepare(
                    request.transition_id(),
                    request.request_digest(),
                    request.expected_epoch(),
                );
            }
            let _ = self
                .inner
                .topology_coordinator
                .drop_staged_bindings(request.transition_id(), request.request_digest());
        }
        result
    }

    /// Discard one exact process-local staging operation before durable Prepare.
    ///
    /// This operation is cancellation-safe and idempotent. It holds the same
    /// transition fence as Prepare, proves that no durable pending command for
    /// this request exists, then removes transport admission, engine routes,
    /// and descriptor bindings in that order. Once Prepare exists, callers
    /// must use [`Self::abort_topology_transition`] instead.
    pub async fn unstage_topology_transition_peers(
        &self,
        request: &SessionTopologyTransitionRequest,
    ) -> Result<(), SessionTopologyTransitionError> {
        let deadline = transition_deadline(request)?;
        let operation_gate = self.inner.topology_coordinator.operation_gate();
        let operation_guard = tokio::time::timeout_at(deadline, operation_gate.write_owned())
            .await
            .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?;
        let durable = self.read_transition_state_before(request, deadline).await?;
        if let Some(pending) = durable.scope.pending.as_ref() {
            if pending.transition_id == request.transition_id().as_bytes() {
                return Err(SessionTopologyTransitionError::CancellationTooLate);
            }
            return Err(SessionTopologyTransitionError::TransitionInProgress);
        }
        if durable.evidence.is_some() {
            return Err(SessionTopologyTransitionError::CancellationTooLate);
        }
        if durable.scope.current_identity.cluster_id() != request.cluster_id()
            || durable.scope.current_identity.configuration_epoch() != request.expected_epoch()
        {
            return Err(SessionTopologyTransitionError::StaleEpoch);
        }

        let proof = SessionTopologyPrePrepareUnstageProof::from_unprepared_request(request);
        let transport = self.inner.topology_coordinator.transport()?;
        let peer_directory = self.inner.peer_directory.clone();
        let topology_coordinator = Arc::clone(&self.inner.topology_coordinator);
        let request = request.clone();
        let supervisor = tokio::spawn(async move {
            let _operation_guard = operation_guard;
            transport
                .unstage_successor_before_prepare(&request, &proof)
                .await
                .map_err(map_transport_error)?;
            peer_directory
                .unstage_before_prepare(
                    request.transition_id(),
                    request.request_digest(),
                    request.expected_epoch(),
                )
                .map_err(|_| SessionTopologyTransitionError::InvalidTransitionBindings)?;
            topology_coordinator
                .drop_staged_bindings(request.transition_id(), request.request_digest())?;
            topology_coordinator.notify_supervisor();
            Ok::<_, SessionTopologyTransitionError>(())
        });
        tokio::time::timeout_at(deadline, supervisor)
            .await
            .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?
    }

    fn ensure_topology_reconciliation_supervisor(
        &self,
    ) -> Result<(), SessionTopologyTransitionError> {
        if self
            .inner
            .topology_coordinator
            .supervisor_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(());
        }
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            self.inner
                .topology_coordinator
                .supervisor_started
                .store(false, Ordering::Release);
            SessionTopologyTransitionError::Unavailable
        })?;
        let weak_inner = Arc::downgrade(&self.inner);
        runtime.spawn(async move {
            loop {
                let Some(inner) = weak_inner.upgrade() else {
                    break;
                };
                let store = ConsensusSessionStore { inner };
                let request = store
                    .inner
                    .topology_coordinator
                    .staged_request_if_any()
                    .ok()
                    .flatten();
                let notify = Arc::clone(&store.inner.topology_coordinator.supervisor_notify);
                if let Some(request) = request {
                    let _ = store.reconcile_local_staged_transition(&request).await;
                    drop(store);
                    tokio::select! {
                        () = notify.notified() => {}
                        () = tokio::time::sleep(Duration::from_millis(25)) => {}
                    }
                } else {
                    drop(store);
                    tokio::select! {
                        () = notify.notified() => {}
                        () = tokio::time::sleep(Duration::from_secs(1)) => {}
                    }
                }
            }
        });
        Ok(())
    }

    async fn reconcile_local_staged_transition(
        &self,
        request: &SessionTopologyTransitionRequest,
    ) -> Result<(), SessionTopologyTransitionError> {
        let deadline = transition_deadline(request)?;
        let operation_gate = self.inner.topology_coordinator.operation_gate();
        let _operation_guard = tokio::time::timeout_at(deadline, operation_gate.write_owned())
            .await
            .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?;
        // Read only after acquiring the fence. A pre-lock snapshot may become
        // terminal while waiting behind commit and must never re-fence a node
        // that the terminal path just admitted.
        let durable = self.read_transition_state_before(request, deadline).await?;
        let Some(status) = status_from_durable(request, &durable)? else {
            return Ok(());
        };

        // Once Prepare applies, application authority remains closed until an
        // exact uniform successor or durable pre-joint abort is reconciled.
        self.inner.admitted.store(false, Ordering::Release);

        match status.phase() {
            SessionTopologyTransitionPhase::Prepared
            | SessionTopologyTransitionPhase::LearnersCatchingUp
            | SessionTopologyTransitionPhase::LearnersReady
            | SessionTopologyTransitionPhase::AuthorityFenced => {
                if let Some(log_index) = durable
                    .evidence
                    .as_ref()
                    .and_then(|evidence| evidence.learners_ready_log_index)
                {
                    self.apply_local_transition_barrier(
                        request,
                        TopologyAdmissionBarrierAction::AppliedLearnerMarker { log_index },
                        deadline,
                    )
                    .await?;
                }
                Ok(())
            }
            SessionTopologyTransitionPhase::JointCommitted => {
                self.apply_local_transition_barrier(
                    request,
                    TopologyAdmissionBarrierAction::AdmitJointVoting,
                    deadline,
                )
                .await
            }
            SessionTopologyTransitionPhase::UniformCommitted
            | SessionTopologyTransitionPhase::Finalizing
            | SessionTopologyTransitionPhase::Completed => {
                self.apply_local_transition_barrier(
                    request,
                    TopologyAdmissionBarrierAction::AdmitJointVoting,
                    deadline,
                )
                .await?;
                self.finish_local_successor_admission(request, &status, deadline)
                    .await
            }
            SessionTopologyTransitionPhase::Aborted => {
                self.finish_local_abort_admission(request, &status, deadline)
                    .await?;
                Ok(())
            }
            SessionTopologyTransitionPhase::Aborting => Ok(()),
        }
    }

    /// Durably prepare one transition and catch every added learner up through
    /// a replicated exact-application marker.
    ///
    /// Openraft learner admission is deliberately nonblocking. The coordinator
    /// commits a learner marker and then obtains an exact applied-index
    /// acknowledgement from every added member before returning the
    /// unforgeable proof.
    pub async fn prepare_topology_transition(
        &self,
        request: &SessionTopologyTransitionRequest,
        desired_peers: SessionTopologyTransitionPeers,
    ) -> Result<SessionTopologyLearnersReadyAdmissionProof, SessionTopologyTransitionError> {
        let deadline = transition_deadline(request)?;
        let operation_gate = self.inner.topology_coordinator.operation_gate();
        let mut operation_guard = tokio::time::timeout_at(deadline, operation_gate.write_owned())
            .await
            .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?;

        let mut durable = self.read_transition_state_before(request, deadline).await?;
        let initial_status = status_from_durable(request, &durable)?;
        if nonquiescent_prior_terminal(request, &durable) {
            return Err(SessionTopologyTransitionError::TransitionInProgress);
        }
        if retained_terminal_evidence(request, &durable) {
            return match initial_status {
                Some(status) if status.phase() == SessionTopologyTransitionPhase::Completed => {
                    Ok(SessionTopologyLearnersReadyAdmissionProof::from_caught_up_request(request))
                }
                Some(status) if status.phase() == SessionTopologyTransitionPhase::Aborted => {
                    Err(SessionTopologyTransitionError::IdempotencyConflict)
                }
                _ => Err(SessionTopologyTransitionError::InvalidEvidenceState),
            };
        }
        if initial_status.as_ref().is_some_and(|status| {
            matches!(
                status.phase(),
                SessionTopologyTransitionPhase::Aborting | SessionTopologyTransitionPhase::Aborted
            )
        }) {
            return Err(SessionTopologyTransitionError::IdempotencyConflict);
        }
        // Staging is process-local and occurs under the transition fence only
        // after terminal-abort retries have been rejected. This prevents an
        // exact aborted retry from poisoning later transition admission.
        self.stage_topology_transition_peers(request, desired_peers)?;
        if let Some(status) = initial_status {
            match status.phase() {
                SessionTopologyTransitionPhase::Aborting
                | SessionTopologyTransitionPhase::Aborted => {
                    return Err(SessionTopologyTransitionError::IdempotencyConflict);
                }
                SessionTopologyTransitionPhase::Completed
                | SessionTopologyTransitionPhase::Finalizing
                | SessionTopologyTransitionPhase::UniformCommitted
                | SessionTopologyTransitionPhase::JointCommitted
                | SessionTopologyTransitionPhase::AuthorityFenced => {
                    return Ok(
                        SessionTopologyLearnersReadyAdmissionProof::from_caught_up_request(request),
                    );
                }
                SessionTopologyTransitionPhase::Prepared
                | SessionTopologyTransitionPhase::LearnersCatchingUp
                | SessionTopologyTransitionPhase::LearnersReady => {}
            }
        } else {
            // A still-current leader may safely prepare learners even when it
            // will not belong to the successor. Retained leadership is only
            // required before successor authority/joint progression.
            self.require_local_current_leader(&durable).await?;
            let (returned_guard, _) = self
                .propose_transition_control(
                    request,
                    TransitionControlKind::Prepare,
                    SessionMutationIntent::PrepareTopologyTransition {
                        transition_id: request.transition_id().as_bytes(),
                        request_digest: request.request_digest().as_bytes(),
                        desired_identity: request.desired_identity(),
                        desired_members: request.desired_consensus_node_ids(),
                        desired_bindings: request.desired_node_bindings(),
                    },
                    operation_guard,
                    deadline,
                )
                .await?;
            operation_guard = returned_guard;
            durable = self.read_transition_state_before(request, deadline).await?;
        }

        self.await_current_staging_barrier(request, deadline)
            .await?;
        self.inner.admitted.store(false, Ordering::Release);
        // A removed incumbent may commit Prepare to the old voter set, but it
        // cannot authenticate candidate traffic under the desired manifest.
        // Require a retained desired member before learner replication and
        // every desired-scoped marker barrier.
        self.require_local_transition_leader(request, &durable, deadline)
            .await?;
        let current_members = durable.scope.current_members.clone();
        let desired_members = request.desired_consensus_node_ids();
        for learner in desired_members.difference(&current_members).copied() {
            operation_guard = self
                .add_learner_before(learner, operation_guard, deadline)
                .await?;
        }

        // The marker is an exact application target, not proof by itself.
        // Every retry re-runs the distributed barrier below.
        durable = self.read_transition_state_before(request, deadline).await?;
        if durable
            .evidence
            .as_ref()
            .is_none_or(|evidence| evidence.learners_ready_log_index.is_none())
        {
            let (returned_guard, _) = self
                .propose_transition_control(
                    request,
                    TransitionControlKind::LearnersReady,
                    SessionMutationIntent::MarkTopologyLearnersReady {
                        transition_id: request.transition_id().as_bytes(),
                        request_digest: request.request_digest().as_bytes(),
                    },
                    operation_guard,
                    deadline,
                )
                .await?;
            operation_guard = returned_guard;
            durable = self.read_transition_state_before(request, deadline).await?;
        }
        let marker = durable
            .evidence
            .as_ref()
            .and_then(|evidence| evidence.learners_ready_log_index)
            .ok_or(SessionTopologyTransitionError::InvalidEvidenceState)?;
        let proof = SessionTopologyLearnersReadyAdmissionProof::from_caught_up_request(request);
        let _operation_guard_is_held = &operation_guard;
        self.await_desired_transition_barrier(
            request,
            TopologyAdmissionBarrierAction::AppliedLearnerMarker { log_index: marker },
            deadline,
        )
        .await?;
        Ok(proof)
    }

    /// Commit a prepared transition through authority fence, joint consensus,
    /// desired uniform membership, transport retirement, and durable finalize.
    ///
    /// Dropping this future does not request abort. A retry uses durable phase
    /// evidence and may continue on a successor leader. Completion is returned
    /// only after `FinalizeTopologyTransition` itself commits and applies.
    pub async fn commit_topology_transition(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyLearnersReadyAdmissionProof,
    ) -> Result<SessionTopologyTransitionStatus, SessionTopologyTransitionError> {
        if !proof.validates_request(request) {
            return Err(SessionTopologyTransitionError::IdempotencyConflict);
        }
        let deadline = transition_deadline(request)?;
        let operation_gate = self.inner.topology_coordinator.operation_gate();
        let mut operation_guard = tokio::time::timeout_at(deadline, operation_gate.write_owned())
            .await
            .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?;

        let mut durable = self.read_transition_state_before(request, deadline).await?;
        let mut status = status_from_durable(request, &durable)?
            .ok_or(SessionTopologyTransitionError::InvalidEvidenceState)?;
        if retained_terminal_evidence(request, &durable) {
            return match status.phase() {
                SessionTopologyTransitionPhase::Completed => Ok(status),
                SessionTopologyTransitionPhase::Aborted => {
                    Err(SessionTopologyTransitionError::IdempotencyConflict)
                }
                _ => Err(SessionTopologyTransitionError::InvalidEvidenceState),
            };
        }
        self.inner.admitted.store(false, Ordering::Release);
        if matches!(
            status.phase(),
            SessionTopologyTransitionPhase::Aborting | SessionTopologyTransitionPhase::Aborted
        ) {
            return Err(SessionTopologyTransitionError::IdempotencyConflict);
        }
        if status.phase() == SessionTopologyTransitionPhase::Completed {
            self.finish_local_successor_admission(request, &status, deadline)
                .await?;
            return Ok(status);
        }

        if matches!(
            status.phase(),
            SessionTopologyTransitionPhase::Prepared
                | SessionTopologyTransitionPhase::LearnersCatchingUp
                | SessionTopologyTransitionPhase::LearnersReady
                | SessionTopologyTransitionPhase::AuthorityFenced
        ) {
            let marker = durable
                .evidence
                .as_ref()
                .and_then(|evidence| evidence.learners_ready_log_index)
                .ok_or(SessionTopologyTransitionError::InvalidEvidenceState)?;
            self.await_desired_transition_barrier(
                request,
                TopologyAdmissionBarrierAction::AppliedLearnerMarker { log_index: marker },
                deadline,
            )
            .await?;
        }
        if matches!(
            status.phase(),
            SessionTopologyTransitionPhase::JointCommitted
                | SessionTopologyTransitionPhase::UniformCommitted
                | SessionTopologyTransitionPhase::Finalizing
        ) {
            self.await_desired_transition_barrier(
                request,
                TopologyAdmissionBarrierAction::AdmitJointVoting,
                deadline,
            )
            .await?;
        }

        if matches!(
            status.phase(),
            SessionTopologyTransitionPhase::UniformCommitted
                | SessionTopologyTransitionPhase::Finalizing
        ) {
            self.finish_local_successor_admission(request, &status, deadline)
                .await?;
        }
        self.require_local_transition_leader(request, &durable, deadline)
            .await?;

        if durable.scope.application_authority_epoch != request.desired_epoch()
            || durable.scope.application_authority_members != request.desired_consensus_node_ids()
        {
            let (returned_guard, _) = self
                .propose_transition_control(
                    request,
                    TransitionControlKind::Fence,
                    SessionMutationIntent::FenceTopologyAuthority {
                        transition_id: request.transition_id().as_bytes(),
                        request_digest: request.request_digest().as_bytes(),
                    },
                    operation_guard,
                    deadline,
                )
                .await?;
            operation_guard = returned_guard;
            durable = self.read_transition_state_before(request, deadline).await?;
        }

        let desired_members = request.desired_consensus_node_ids();
        let shape = classify_applied_membership(
            &durable.applied_membership,
            &durable.scope.current_members,
            &desired_members,
        );
        if !matches!(shape, AppliedMembershipShape::DesiredUniform) {
            operation_guard = self
                .change_membership_before(desired_members.clone(), operation_guard, deadline)
                .await?;
            durable = self.read_transition_state_before(request, deadline).await?;
        }
        if classify_applied_membership(
            &durable.applied_membership,
            &durable.scope.current_members,
            &desired_members,
        ) != AppliedMembershipShape::DesiredUniform
            && durable.scope.current_identity != request.desired_identity()
        {
            return Err(SessionTopologyTransitionError::DeadlineExceededResumable);
        }
        status = status_from_durable(request, &durable)?
            .ok_or(SessionTopologyTransitionError::InvalidEvidenceState)?;
        self.await_desired_transition_barrier(
            request,
            TopologyAdmissionBarrierAction::AdmitJointVoting,
            deadline,
        )
        .await?;
        self.inner
            .topology_coordinator
            .finalize_staged_successor_transport(request, &status, deadline)
            .await?;

        self.inner
            .peer_directory
            .finalize(
                request.transition_id(),
                request.request_digest(),
                request.expected_epoch(),
                &desired_members,
            )
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        self.inner.topology_coordinator.finalize_bindings(request)?;

        // A leader removed by the new uniform set cannot manufacture terminal
        // success. A retained successor leader retries this exact request.
        self.require_local_current_leader(&durable).await?;
        let (returned_guard, _) = self
            .propose_transition_control(
                request,
                TransitionControlKind::Finalize,
                SessionMutationIntent::FinalizeTopologyTransition {
                    transition_id: request.transition_id().as_bytes(),
                    request_digest: request.request_digest().as_bytes(),
                },
                operation_guard,
                deadline,
            )
            .await?;
        let _operation_guard = returned_guard;
        durable = self.read_transition_state_before(request, deadline).await?;
        status = status_from_durable(request, &durable)?
            .ok_or(SessionTopologyTransitionError::InvalidEvidenceState)?;
        if status.phase() != SessionTopologyTransitionPhase::Completed {
            return Err(SessionTopologyTransitionError::DeadlineExceededResumable);
        }
        self.finish_local_successor_admission(request, &status, deadline)
            .await?;
        Ok(status)
    }

    /// Read exact durable status for one caller-owned transition request.
    pub async fn topology_transition_status(
        &self,
        request: &SessionTopologyTransitionRequest,
    ) -> Result<Option<SessionTopologyTransitionStatus>, SessionTopologyTransitionError> {
        let deadline = transition_deadline(request)?;
        let durable = self.read_transition_state_before(request, deadline).await?;
        status_from_durable(request, &durable)
    }

    /// Explicitly abort a transition only while durable pre-joint rollback is safe.
    ///
    /// Abort is committed while every admitted learner remains reachable. The
    /// retained successor leader then proves that exact decision on all actual
    /// learners, tombstones every provisional candidate that was never added,
    /// and finally commits an exact cleanup proof. When learners exist, that
    /// proof is their Openraft node-removal entry; otherwise the current-term
    /// cleanup control itself is sufficient. Public `Aborted` status and
    /// transport teardown are impossible before that last proof.
    pub async fn abort_topology_transition(
        &self,
        request: &SessionTopologyTransitionRequest,
    ) -> Result<SessionTopologyTransitionStatus, SessionTopologyTransitionError> {
        let deadline = transition_deadline(request)?;
        let operation_gate = self.inner.topology_coordinator.operation_gate();
        let mut operation_guard = tokio::time::timeout_at(deadline, operation_gate.write_owned())
            .await
            .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?;
        let mut durable = self.read_transition_state_before(request, deadline).await?;
        let mut status = status_from_durable(request, &durable)?
            .ok_or(SessionTopologyTransitionError::InvalidEvidenceState)?;
        if retained_terminal_evidence(request, &durable) {
            return match status.phase() {
                SessionTopologyTransitionPhase::Aborted => Ok(status),
                SessionTopologyTransitionPhase::Completed => {
                    Err(SessionTopologyTransitionError::CancellationTooLate)
                }
                _ => Err(SessionTopologyTransitionError::InvalidEvidenceState),
            };
        }
        if status.phase() == SessionTopologyTransitionPhase::Aborted {
            self.redispatch_terminal_abort_candidate_cleanup(request, &durable, &status, deadline)
                .await;
            self.finish_local_abort_admission(request, &status, deadline)
                .await?;
            return Ok(status);
        }
        if matches!(
            status.phase(),
            SessionTopologyTransitionPhase::JointCommitted
                | SessionTopologyTransitionPhase::UniformCommitted
                | SessionTopologyTransitionPhase::Finalizing
                | SessionTopologyTransitionPhase::Completed
        ) {
            return Err(SessionTopologyTransitionError::CancellationTooLate);
        }

        if status.phase() != SessionTopologyTransitionPhase::Aborting {
            let effective_shape = {
                let metrics = self.inner.raft.metrics();
                let current = metrics.borrow();
                classify_applied_membership(
                    current.membership_config.as_ref(),
                    &durable.scope.current_members,
                    &request.desired_consensus_node_ids(),
                )
            };
            if matches!(
                effective_shape,
                AppliedMembershipShape::Joint | AppliedMembershipShape::DesiredUniform
            ) {
                return Err(SessionTopologyTransitionError::CancellationTooLate);
            }
            self.require_local_current_leader(&durable).await?;
            let (returned_guard, _) = self
                .propose_transition_control(
                    request,
                    TransitionControlKind::Abort,
                    SessionMutationIntent::AbortTopologyTransition {
                        transition_id: request.transition_id().as_bytes(),
                        request_digest: request.request_digest().as_bytes(),
                    },
                    operation_guard,
                    deadline,
                )
                .await?;
            operation_guard = returned_guard;
            durable = self.read_transition_state_before(request, deadline).await?;
            status = status_from_durable(request, &durable)?
                .ok_or(SessionTopologyTransitionError::InvalidEvidenceState)?;
        }
        if status.phase() == SessionTopologyTransitionPhase::Aborted {
            self.redispatch_terminal_abort_candidate_cleanup(request, &durable, &status, deadline)
                .await;
            self.finish_local_abort_admission(request, &status, deadline)
                .await?;
            return Ok(status);
        }
        if status.phase() != SessionTopologyTransitionPhase::Aborting {
            return Err(SessionTopologyTransitionError::InvalidEvidenceState);
        }

        let cleanup = durable
            .scope
            .terminal
            .as_ref()
            .filter(|terminal| {
                terminal.transition_id == request.transition_id().as_bytes()
                    && terminal.transition_digest == request.request_digest().as_bytes()
                    && terminal.outcome == TerminalMembershipOutcome::Aborted
            })
            .and_then(|terminal| terminal.abort_cleanup.as_ref())
            .ok_or(SessionTopologyTransitionError::InvalidEvidenceState)?;
        let decision_log_index = cleanup.decision_log_index;
        let actual_learners = cleanup.learners.clone();
        let current_members = durable.scope.current_members.clone();
        let added_members = request
            .desired_consensus_node_ids()
            .difference(&current_members)
            .copied()
            .collect::<BTreeSet<_>>();
        if !actual_learners.is_subset(&added_members) {
            return Err(SessionTopologyTransitionError::InvalidEvidenceState);
        }
        let provisional_candidates = added_members
            .difference(&actual_learners)
            .copied()
            .collect::<BTreeSet<_>>();

        // From this point every candidate-facing action must originate from a
        // retained member admitted by both exact manifests.
        self.require_local_transition_leader(request, &durable, deadline)
            .await?;
        self.await_exact_member_barrier(
            request,
            TopologyAdmissionBarrierAction::AppliedAbortDecision {
                log_index: decision_log_index,
            },
            &actual_learners,
            deadline,
        )
        .await?;
        self.await_exact_member_barrier(
            request,
            TopologyAdmissionBarrierAction::CancelProvisionalCandidate,
            &provisional_candidates,
            deadline,
        )
        .await?;

        // Commit a deterministic current-term cleanup proof. With no admitted
        // learners this is terminal by itself; otherwise it first advances
        // any prior-term abort decision before the exact node-removal entry.
        // Repeated request IDs are idempotent in the durable state machine.
        let (returned_guard, _) = self
            .propose_transition_control(
                request,
                TransitionControlKind::AbortCleanup,
                SessionMutationIntent::AbortTopologyTransition {
                    transition_id: request.transition_id().as_bytes(),
                    request_digest: request.request_digest().as_bytes(),
                },
                operation_guard,
                deadline,
            )
            .await?;
        operation_guard = returned_guard;
        durable = self.read_transition_state_before(request, deadline).await?;
        status = status_from_durable(request, &durable)?
            .ok_or(SessionTopologyTransitionError::InvalidEvidenceState)?;
        if status.phase() == SessionTopologyTransitionPhase::Aborted {
            self.redispatch_terminal_abort_candidate_cleanup(request, &durable, &status, deadline)
                .await;
            self.finish_local_abort_admission(request, &status, deadline)
                .await?;
            return Ok(status);
        }

        // Remove only the learners proven by the durable abort decision.
        // Replacing the already-current voter set does not remove Openraft
        // learner nodes and can append a redundant membership entry instead.
        operation_guard = self
            .remove_learners_before(actual_learners, operation_guard, deadline)
            .await?;
        let _operation_guard = &operation_guard;
        durable = self.read_transition_state_before(request, deadline).await?;
        status = status_from_durable(request, &durable)?
            .ok_or(SessionTopologyTransitionError::InvalidEvidenceState)?;
        if status.phase() != SessionTopologyTransitionPhase::Aborted
            || classify_applied_membership(
                &durable.applied_membership,
                &current_members,
                &request.desired_consensus_node_ids(),
            ) != AppliedMembershipShape::CurrentUniform
        {
            return Err(SessionTopologyTransitionError::DeadlineExceededResumable);
        }
        self.redispatch_terminal_abort_candidate_cleanup(request, &durable, &status, deadline)
            .await;
        self.finish_local_abort_admission(request, &status, deadline)
            .await?;
        Ok(status)
    }

    async fn read_transition_state_before(
        &self,
        request: &SessionTopologyTransitionRequest,
        deadline: tokio::time::Instant,
    ) -> Result<DurableTransitionState, SessionTopologyTransitionError> {
        let (scope, evidence, applied_membership) = tokio::time::timeout_at(
            deadline,
            self.inner.backend.consensus_membership_transition_snapshot(
                self.inner.storage_identity,
                request.transition_id().as_bytes(),
                request.request_digest().as_bytes(),
            ),
        )
        .await
        .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?
        .map_err(map_membership_storage_error)?;
        self.inner
            .topology_coordinator
            .load_retained_transitions(&scope)?;
        Ok(DurableTransitionState {
            scope,
            evidence,
            applied_membership,
        })
    }

    async fn require_local_transition_leader(
        &self,
        request: &SessionTopologyTransitionRequest,
        durable: &DurableTransitionState,
        deadline: tokio::time::Instant,
    ) -> Result<(), SessionTopologyTransitionError> {
        let leader = self.inner.raft.current_leader().await;
        if leader == Some(self.inner.local_node_id) {
            if request
                .desired_consensus_node_ids()
                .contains(&self.inner.local_node_id)
            {
                return Ok(());
            }
            return Err(SessionTopologyTransitionError::NotLeader);
        }
        // When the current leader is being removed, a retained caller may
        // trigger an election and retry. There is no unsafe targeted transfer
        // in the pinned engine; disjoint replacement was rejected at staging.
        if leader.is_some_and(|leader| {
            !request.desired_consensus_node_ids().contains(&leader)
                && durable
                    .scope
                    .current_members
                    .contains(&self.inner.local_node_id)
                && request
                    .desired_consensus_node_ids()
                    .contains(&self.inner.local_node_id)
        }) {
            self.inner
                .raft
                .trigger()
                .elect()
                .await
                .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
            loop {
                let observed = self.inner.raft.current_leader().await;
                if observed == Some(self.inner.local_node_id) {
                    return Ok(());
                }
                if observed
                    .is_some_and(|node_id| request.desired_consensus_node_ids().contains(&node_id))
                {
                    return Err(SessionTopologyTransitionError::NotLeader);
                }
                tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(25)))
                    .await
                    .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?;
            }
        }
        Err(SessionTopologyTransitionError::NotLeader)
    }

    async fn require_local_current_leader(
        &self,
        durable: &DurableTransitionState,
    ) -> Result<(), SessionTopologyTransitionError> {
        if self.inner.raft.current_leader().await == Some(self.inner.local_node_id)
            && durable
                .scope
                .current_members
                .contains(&self.inner.local_node_id)
        {
            Ok(())
        } else {
            Err(SessionTopologyTransitionError::NotLeader)
        }
    }

    async fn propose_transition_control(
        &self,
        request: &SessionTopologyTransitionRequest,
        kind: TransitionControlKind,
        intent: SessionMutationIntent,
        operation_guard: tokio::sync::OwnedRwLockWriteGuard<()>,
        deadline: tokio::time::Instant,
    ) -> Result<(tokio::sync::OwnedRwLockWriteGuard<()>, u64), SessionTopologyTransitionError> {
        if self.inner.raft.current_leader().await != Some(self.inner.local_node_id) {
            return Err(SessionTopologyTransitionError::NotLeader);
        }
        let command = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: self.inner.storage_identity,
            request_id: transition_request_id(request, kind),
            logical_time: Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
            intent,
        };
        encode_bounded(&command).map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        let raft = self.inner.raft.clone();
        let attempt_deadline = transition_engine_attempt_deadline(deadline);
        let mut supervisor = tokio::spawn(async move {
            let result = match tokio::time::timeout_at(attempt_deadline, async move {
                let receiver = raft
                    .client_write_ff(command)
                    .await
                    .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
                let response = receiver
                    .await
                    .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?;
                match response {
                    Ok(response)
                        if matches!(response.data.result, Ok(SessionMutationOutcome::Unit)) =>
                    {
                        Ok(response.log_id.index)
                    }
                    Ok(_) => Err(SessionTopologyTransitionError::Unavailable),
                    Err(ClientWriteError::ForwardToLeader(_)) => {
                        Err(SessionTopologyTransitionError::NotLeader)
                    }
                    Err(ClientWriteError::ChangeMembershipError(_)) => {
                        Err(SessionTopologyTransitionError::Unavailable)
                    }
                }
            })
            .await
            {
                Ok(result) => result,
                Err(_) => Err(SessionTopologyTransitionError::DeadlineExceededResumable),
            };
            (operation_guard, result)
        });
        let (operation_guard, result) =
            match tokio::time::timeout_at(attempt_deadline, &mut supervisor).await {
                Ok(result) => result.map_err(|_| SessionTopologyTransitionError::Unavailable)?,
                Err(_) => {
                    supervisor.abort();
                    let _ = supervisor.await;
                    return Err(SessionTopologyTransitionError::DeadlineExceededResumable);
                }
            };
        result.map(|index| (operation_guard, index))
    }

    async fn add_learner_before(
        &self,
        learner: SessionConsensusNodeId,
        operation_guard: tokio::sync::OwnedRwLockWriteGuard<()>,
        deadline: tokio::time::Instant,
    ) -> Result<tokio::sync::OwnedRwLockWriteGuard<()>, SessionTopologyTransitionError> {
        let raft = self.inner.raft.clone();
        let attempt_deadline = transition_engine_attempt_deadline(deadline);
        let mut supervisor = tokio::spawn(async move {
            // Nonblocking admission commits the learner entry without letting
            // an unreachable candidate hold the global proposal fence forever.
            // Exact catch-up is proven separately by the replicated marker and
            // per-added-node applied barrier before any voting promotion.
            let result = match tokio::time::timeout_at(
                attempt_deadline,
                raft.add_learner(learner, EmptyNode::default(), false),
            )
            .await
            {
                Ok(result) => map_membership_change_result(result),
                Err(_) => Err(SessionTopologyTransitionError::DeadlineExceededResumable),
            };
            (operation_guard, result)
        });
        let (operation_guard, result) =
            match tokio::time::timeout_at(attempt_deadline, &mut supervisor).await {
                Ok(result) => result.map_err(|_| SessionTopologyTransitionError::Unavailable)?,
                Err(_) => {
                    supervisor.abort();
                    let _ = supervisor.await;
                    return Err(SessionTopologyTransitionError::DeadlineExceededResumable);
                }
            };
        result?;
        Ok(operation_guard)
    }

    async fn change_membership_before(
        &self,
        members: BTreeSet<SessionConsensusNodeId>,
        operation_guard: tokio::sync::OwnedRwLockWriteGuard<()>,
        deadline: tokio::time::Instant,
    ) -> Result<tokio::sync::OwnedRwLockWriteGuard<()>, SessionTopologyTransitionError> {
        let raft = self.inner.raft.clone();
        let attempt_deadline = transition_engine_attempt_deadline(deadline);
        let mut supervisor = tokio::spawn(async move {
            let result = match tokio::time::timeout_at(
                attempt_deadline,
                raft.change_membership(members, false),
            )
            .await
            {
                Ok(result) => map_membership_change_result(result),
                Err(_) => Err(SessionTopologyTransitionError::DeadlineExceededResumable),
            };
            (operation_guard, result)
        });
        let (operation_guard, result) =
            match tokio::time::timeout_at(attempt_deadline, &mut supervisor).await {
                Ok(result) => result.map_err(|_| SessionTopologyTransitionError::Unavailable)?,
                Err(_) => {
                    supervisor.abort();
                    let _ = supervisor.await;
                    return Err(SessionTopologyTransitionError::DeadlineExceededResumable);
                }
            };
        result?;
        Ok(operation_guard)
    }

    async fn remove_learners_before(
        &self,
        learners: BTreeSet<SessionConsensusNodeId>,
        operation_guard: tokio::sync::OwnedRwLockWriteGuard<()>,
        deadline: tokio::time::Instant,
    ) -> Result<tokio::sync::OwnedRwLockWriteGuard<()>, SessionTopologyTransitionError> {
        let raft = self.inner.raft.clone();
        let attempt_deadline = transition_engine_attempt_deadline(deadline);
        let mut supervisor = tokio::spawn(async move {
            let result = match tokio::time::timeout_at(
                attempt_deadline,
                raft.change_membership(ChangeMembers::RemoveNodes(learners), false),
            )
            .await
            {
                Ok(result) => map_membership_change_result(result),
                Err(_) => Err(SessionTopologyTransitionError::DeadlineExceededResumable),
            };
            (operation_guard, result)
        });
        let (operation_guard, result) =
            match tokio::time::timeout_at(attempt_deadline, &mut supervisor).await {
                Ok(result) => result.map_err(|_| SessionTopologyTransitionError::Unavailable)?,
                Err(_) => {
                    supervisor.abort();
                    let _ = supervisor.await;
                    return Err(SessionTopologyTransitionError::DeadlineExceededResumable);
                }
            };
        result?;
        Ok(operation_guard)
    }

    async fn await_current_staging_barrier(
        &self,
        request: &SessionTopologyTransitionRequest,
        deadline: tokio::time::Instant,
    ) -> Result<(), SessionTopologyTransitionError> {
        let (identity, peers) = self
            .inner
            .peer_directory
            .current_peers()
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        let current_members = self.inner.topology_coordinator.current_members()?;
        if identity == request.desired_identity()
            && current_members == request.desired_consensus_node_ids()
        {
            return self
                .apply_local_transition_barrier(
                    request,
                    TopologyAdmissionBarrierAction::ConfirmStaged,
                    deadline,
                )
                .await;
        }
        if identity.cluster_id() != request.cluster_id()
            || identity.configuration_epoch() != request.expected_epoch()
        {
            return Err(SessionTopologyTransitionError::StaleEpoch);
        }
        let action = TopologyAdmissionBarrierAction::ConfirmStaged;
        let payload = encode_bounded(&TopologyAdmissionBarrierRequest {
            transition_id: request.transition_id().as_bytes(),
            request_digest: request.request_digest().as_bytes(),
            action,
        })
        .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        let current_quorum = (current_members.len() / 2) + 1;

        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(SessionTopologyTransitionError::DeadlineExceededResumable);
            }
            let attempt_deadline = now
                .checked_add(Duration::from_secs(2))
                .map_or(deadline, |candidate| candidate.min(deadline));
            let mut ready_members = BTreeSet::new();
            match self
                .apply_local_transition_barrier(request, action, attempt_deadline)
                .await
            {
                Ok(()) => {
                    ready_members.insert(self.inner.local_node_id);
                }
                Err(
                    SessionTopologyTransitionError::Unavailable
                    | SessionTopologyTransitionError::DeadlineExceededResumable,
                ) => {}
                Err(error) => return Err(error),
            }
            let mut calls = FuturesUnordered::new();
            for (node_id, peer) in &peers {
                let wire = SessionConsensusWireRequest::try_new(
                    identity,
                    self.inner.local_node_id,
                    SessionConsensusRpcFamily::TopologyAdmissionBarrier,
                    payload.clone(),
                )
                .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
                let node_id = *node_id;
                let peer = Arc::clone(peer);
                calls.push(async move {
                    let remaining =
                        attempt_deadline.saturating_duration_since(tokio::time::Instant::now());
                    (
                        node_id,
                        tokio::time::timeout_at(
                            attempt_deadline,
                            peer.call_with_timeout(wire, remaining),
                        )
                        .await,
                    )
                });
            }
            while let Some((node_id, result)) = calls.next().await {
                let response = match result {
                    Err(_)
                    | Ok(Err(
                        SessionConsensusPeerError::Unavailable | SessionConsensusPeerError::Timeout,
                    )) => continue,
                    Ok(Err(_)) => {
                        return Err(SessionTopologyTransitionError::InvalidTransitionBindings)
                    }
                    Ok(Ok(response)) => response,
                };
                response
                    .validate()
                    .map_err(|_| SessionTopologyTransitionError::InvalidTransitionBindings)?;
                let response_payload = match response.result {
                    Err(
                        SessionConsensusPeerError::Unavailable | SessionConsensusPeerError::Timeout,
                    ) => continue,
                    Err(_) => {
                        return Err(SessionTopologyTransitionError::InvalidTransitionBindings)
                    }
                    Ok(payload) => payload,
                };
                let reply: TopologyAdmissionBarrierReply = decode_bounded(&response_payload)
                    .map_err(|_| SessionTopologyTransitionError::InvalidTransitionBindings)?;
                if reply == TopologyAdmissionBarrierReply::Ready {
                    ready_members.insert(node_id);
                }
            }
            if ready_members.intersection(&current_members).count() >= current_quorum {
                return Ok(());
            }
            tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(25)))
                .await
                .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?;
        }
    }

    async fn await_desired_transition_barrier(
        &self,
        request: &SessionTopologyTransitionRequest,
        action: TopologyAdmissionBarrierAction,
        deadline: tokio::time::Instant,
    ) -> Result<(), SessionTopologyTransitionError> {
        if self
            .inner
            .topology_coordinator
            .is_current_request(request)?
        {
            return self
                .apply_local_transition_barrier(request, action, deadline)
                .await;
        }
        let peers = self.inner.topology_coordinator.staged_peers(request)?;
        let current_members = self.inner.topology_coordinator.current_members()?;
        let desired_members = request.desired_consensus_node_ids();
        let added_members = desired_members
            .difference(&current_members)
            .copied()
            .collect::<BTreeSet<_>>();
        let desired_quorum = (desired_members.len() / 2) + 1;
        let payload = encode_bounded(&TopologyAdmissionBarrierRequest {
            transition_id: request.transition_id().as_bytes(),
            request_digest: request.request_digest().as_bytes(),
            action,
        })
        .map_err(|_| SessionTopologyTransitionError::Unavailable)?;

        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(SessionTopologyTransitionError::DeadlineExceededResumable);
            }
            let attempt_deadline = now
                .checked_add(Duration::from_secs(2))
                .map_or(deadline, |candidate| candidate.min(deadline));
            let mut ready_members = BTreeSet::new();
            match self
                .apply_local_transition_barrier(request, action, attempt_deadline)
                .await
            {
                Ok(()) => {
                    ready_members.insert(self.inner.local_node_id);
                }
                Err(
                    SessionTopologyTransitionError::Unavailable
                    | SessionTopologyTransitionError::DeadlineExceededResumable,
                ) => {}
                Err(error) => return Err(error),
            }
            let mut calls = FuturesUnordered::new();
            for (node_id, peer) in &peers {
                let wire = SessionConsensusWireRequest::try_new(
                    request.desired_identity(),
                    self.inner.local_node_id,
                    SessionConsensusRpcFamily::TopologyAdmissionBarrier,
                    payload.clone(),
                )
                .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
                let node_id = *node_id;
                let peer = Arc::clone(peer);
                calls.push(async move {
                    let remaining =
                        attempt_deadline.saturating_duration_since(tokio::time::Instant::now());
                    (
                        node_id,
                        tokio::time::timeout_at(
                            attempt_deadline,
                            peer.call_with_timeout(wire, remaining),
                        )
                        .await,
                    )
                });
            }
            while let Some((node_id, result)) = calls.next().await {
                let response = match result {
                    Err(_)
                    | Ok(Err(
                        SessionConsensusPeerError::Unavailable | SessionConsensusPeerError::Timeout,
                    )) => continue,
                    Ok(Err(_)) => {
                        return Err(SessionTopologyTransitionError::InvalidTransitionBindings)
                    }
                    Ok(Ok(response)) => response,
                };
                response
                    .validate()
                    .map_err(|_| SessionTopologyTransitionError::InvalidTransitionBindings)?;
                let response_payload = match response.result {
                    Err(
                        SessionConsensusPeerError::Unavailable | SessionConsensusPeerError::Timeout,
                    ) => continue,
                    Err(_) => {
                        return Err(SessionTopologyTransitionError::InvalidTransitionBindings)
                    }
                    Ok(payload) => payload,
                };
                let reply: TopologyAdmissionBarrierReply = decode_bounded(&response_payload)
                    .map_err(|_| SessionTopologyTransitionError::InvalidTransitionBindings)?;
                if reply == TopologyAdmissionBarrierReply::Ready {
                    ready_members.insert(node_id);
                }
            }
            let desired_ready = ready_members.intersection(&desired_members).count();
            let additions_ready = !matches!(
                action,
                TopologyAdmissionBarrierAction::AppliedLearnerMarker { .. }
            ) || added_members.is_subset(&ready_members);
            if additions_ready && desired_ready >= desired_quorum {
                return Ok(());
            }
            tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(25)))
                .await
                .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?;
        }
    }

    async fn await_exact_member_barrier(
        &self,
        request: &SessionTopologyTransitionRequest,
        action: TopologyAdmissionBarrierAction,
        required_members: &BTreeSet<SessionConsensusNodeId>,
        deadline: tokio::time::Instant,
    ) -> Result<(), SessionTopologyTransitionError> {
        if required_members.is_empty() {
            return Ok(());
        }
        let desired_members = request.desired_consensus_node_ids();
        if !required_members.is_subset(&desired_members) {
            return Err(SessionTopologyTransitionError::InvalidEvidenceState);
        }
        let peers = self.inner.topology_coordinator.staged_peers(request)?;
        let payload = encode_bounded(&TopologyAdmissionBarrierRequest {
            transition_id: request.transition_id().as_bytes(),
            request_digest: request.request_digest().as_bytes(),
            action,
        })
        .map_err(|_| SessionTopologyTransitionError::Unavailable)?;

        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Err(SessionTopologyTransitionError::DeadlineExceededResumable);
            }
            let attempt_deadline = now
                .checked_add(Duration::from_secs(2))
                .map_or(deadline, |candidate| candidate.min(deadline));
            let mut ready_members = BTreeSet::new();
            if required_members.contains(&self.inner.local_node_id) {
                match self
                    .apply_local_transition_barrier(request, action, attempt_deadline)
                    .await
                {
                    Ok(()) => {
                        ready_members.insert(self.inner.local_node_id);
                    }
                    Err(
                        SessionTopologyTransitionError::Unavailable
                        | SessionTopologyTransitionError::DeadlineExceededResumable,
                    ) => {}
                    Err(error) => return Err(error),
                }
            }
            let mut calls = FuturesUnordered::new();
            for node_id in required_members
                .iter()
                .filter(|node_id| **node_id != self.inner.local_node_id)
            {
                let peer = peers
                    .get(node_id)
                    .ok_or(SessionTopologyTransitionError::InvalidTransitionBindings)?;
                let wire = SessionConsensusWireRequest::try_new(
                    request.desired_identity(),
                    self.inner.local_node_id,
                    SessionConsensusRpcFamily::TopologyAdmissionBarrier,
                    payload.clone(),
                )
                .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
                let node_id = *node_id;
                let peer = Arc::clone(peer);
                calls.push(async move {
                    let remaining =
                        attempt_deadline.saturating_duration_since(tokio::time::Instant::now());
                    (
                        node_id,
                        tokio::time::timeout_at(
                            attempt_deadline,
                            peer.call_with_timeout(wire, remaining),
                        )
                        .await,
                    )
                });
            }
            while let Some((node_id, result)) = calls.next().await {
                let response = match result {
                    Err(_)
                    | Ok(Err(
                        SessionConsensusPeerError::Unavailable | SessionConsensusPeerError::Timeout,
                    )) => continue,
                    Ok(Err(_)) => {
                        return Err(SessionTopologyTransitionError::InvalidTransitionBindings)
                    }
                    Ok(Ok(response)) => response,
                };
                response
                    .validate()
                    .map_err(|_| SessionTopologyTransitionError::InvalidTransitionBindings)?;
                let response_payload = match response.result {
                    Err(
                        SessionConsensusPeerError::Unavailable | SessionConsensusPeerError::Timeout,
                    ) => continue,
                    Err(_) => {
                        return Err(SessionTopologyTransitionError::InvalidTransitionBindings)
                    }
                    Ok(payload) => payload,
                };
                let reply: TopologyAdmissionBarrierReply = decode_bounded(&response_payload)
                    .map_err(|_| SessionTopologyTransitionError::InvalidTransitionBindings)?;
                if reply == TopologyAdmissionBarrierReply::Ready {
                    ready_members.insert(node_id);
                }
            }
            if required_members.is_subset(&ready_members) {
                return Ok(());
            }
            tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(25)))
                .await
                .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?;
        }
    }

    async fn redispatch_terminal_abort_candidate_cleanup(
        &self,
        request: &SessionTopologyTransitionRequest,
        durable: &DurableTransitionState,
        status: &SessionTopologyTransitionStatus,
        deadline: tokio::time::Instant,
    ) {
        let Some(cleanup) = durable
            .scope
            .terminal
            .as_ref()
            .filter(|terminal| terminal.outcome == TerminalMembershipOutcome::Aborted)
            .and_then(|terminal| terminal.abort_cleanup.as_ref())
        else {
            return;
        };
        let Some(cleanup_log_index) = status.log_indexes().abort_cleanup() else {
            return;
        };
        let added_members = request
            .desired_consensus_node_ids()
            .difference(&durable.scope.current_members)
            .copied()
            .collect::<BTreeSet<_>>();
        self.dispatch_aborted_candidate_cleanup(
            request,
            &added_members,
            cleanup.decision_log_index,
            cleanup_log_index,
            deadline,
        )
        .await;
    }

    async fn dispatch_aborted_candidate_cleanup(
        &self,
        request: &SessionTopologyTransitionRequest,
        added_members: &BTreeSet<SessionConsensusNodeId>,
        abort_decision_log_index: u64,
        abort_cleanup_log_index: u64,
        deadline: tokio::time::Instant,
    ) {
        if added_members.is_empty() {
            return;
        }
        let Ok(peers) = self.inner.topology_coordinator.staged_peers(request) else {
            return;
        };
        let Ok(payload) = encode_bounded(&TopologyAdmissionBarrierRequest {
            transition_id: request.transition_id().as_bytes(),
            request_digest: request.request_digest().as_bytes(),
            action: TopologyAdmissionBarrierAction::FinalizeAbortedCandidate {
                abort_decision_log_index,
                abort_cleanup_log_index,
            },
        }) else {
            return;
        };
        let mut calls = FuturesUnordered::new();
        for node_id in added_members {
            let Some(peer) = peers.get(node_id) else {
                continue;
            };
            let Ok(wire) = SessionConsensusWireRequest::try_new(
                request.desired_identity(),
                self.inner.local_node_id,
                SessionConsensusRpcFamily::TopologyAdmissionBarrier,
                payload.clone(),
            ) else {
                continue;
            };
            let peer = Arc::clone(peer);
            calls.push(async move {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                let _ = tokio::time::timeout_at(deadline, peer.call_with_timeout(wire, remaining))
                    .await;
            });
        }
        while calls.next().await.is_some() {}
    }

    async fn apply_local_transition_barrier(
        &self,
        request: &SessionTopologyTransitionRequest,
        action: TopologyAdmissionBarrierAction,
        deadline: tokio::time::Instant,
    ) -> Result<(), SessionTopologyTransitionError> {
        if action == TopologyAdmissionBarrierAction::ConfirmStaged {
            self.inner.topology_coordinator.transport()?;
            let _staged_request = self
                .inner
                .topology_coordinator
                .staged_request(request.transition_id(), request.request_digest())?;
            return Ok(());
        }
        let durable = self.read_transition_state_before(request, deadline).await?;
        match action {
            TopologyAdmissionBarrierAction::ConfirmStaged => Ok(()),
            TopologyAdmissionBarrierAction::AppliedLearnerMarker { log_index } => {
                let observed_marker = durable
                    .evidence
                    .as_ref()
                    .and_then(|evidence| evidence.learners_ready_log_index);
                // The marker is written transactionally by applying that exact
                // normal command. Its local durable presence proves apply;
                // StoredMembership names only the last membership entry.
                if observed_marker != Some(log_index) {
                    return Err(SessionTopologyTransitionError::Unavailable);
                }
                let proof =
                    SessionTopologyLearnersReadyAdmissionProof::from_caught_up_request(request);
                if !proof.validates_request(request) {
                    return Err(SessionTopologyTransitionError::IdempotencyConflict);
                }
                self.inner.admitted.store(false, Ordering::Release);
                Ok(())
            }
            TopologyAdmissionBarrierAction::AdmitJointVoting => {
                let status = status_from_durable(request, &durable)?
                    .ok_or(SessionTopologyTransitionError::InvalidEvidenceState)?;
                let shape = classify_applied_membership(
                    &durable.applied_membership,
                    &durable.scope.current_members,
                    &request.desired_consensus_node_ids(),
                );
                if !matches!(
                    shape,
                    AppliedMembershipShape::Joint | AppliedMembershipShape::DesiredUniform
                ) {
                    return Err(SessionTopologyTransitionError::Unavailable);
                }
                if self
                    .inner
                    .topology_coordinator
                    .is_current_request(request)?
                {
                    self.inner.admitted.store(
                        request
                            .desired_consensus_node_ids()
                            .contains(&self.inner.local_node_id),
                        Ordering::Release,
                    );
                    return Ok(());
                }
                tokio::time::timeout_at(
                    deadline,
                    self.inner
                        .topology_coordinator
                        .admit_staged_successor_voting(request, &status),
                )
                .await
                .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)??;
                self.inner
                    .peer_directory
                    .admit_staged_voting(
                        request.transition_id(),
                        request.request_digest(),
                        request.expected_epoch(),
                    )
                    .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
                self.inner.admitted.store(false, Ordering::Release);
                Ok(())
            }
            TopologyAdmissionBarrierAction::AppliedAbortDecision { log_index } => {
                let observed_decision = durable
                    .evidence
                    .as_ref()
                    .filter(|evidence| evidence.outcome == Some(TerminalMembershipOutcome::Aborted))
                    .and_then(|evidence| evidence.abort_decision_log_index);
                if observed_decision != Some(log_index) {
                    return Err(SessionTopologyTransitionError::Unavailable);
                }
                self.inner.admitted.store(false, Ordering::Release);
                Ok(())
            }
            TopologyAdmissionBarrierAction::CancelProvisionalCandidate => {
                let current_members = self.inner.topology_coordinator.current_members()?;
                if current_members.contains(&self.inner.local_node_id)
                    || !request
                        .desired_consensus_node_ids()
                        .contains(&self.inner.local_node_id)
                {
                    return Err(SessionTopologyTransitionError::InvalidTransitionBindings);
                }
                tokio::time::timeout_at(
                    deadline,
                    self.inner.backend.cancel_provisional_consensus_candidate(
                        self.inner.storage_identity,
                        self.inner.local_node_id,
                        request.transition_id().as_bytes(),
                        request.request_digest().as_bytes(),
                    ),
                )
                .await
                .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?
                .map_err(map_membership_storage_error)?;
                // Retain the exact control-plane route until the leader has
                // observed every durable cancellation acknowledgement. If a
                // Ready response is lost, this action remains retryable.
                self.inner.admitted.store(false, Ordering::Release);
                Ok(())
            }
            TopologyAdmissionBarrierAction::FinalizeAbortedCandidate {
                abort_decision_log_index,
                abort_cleanup_log_index,
            } => {
                let current_members = self.inner.topology_coordinator.current_members()?;
                if current_members.contains(&self.inner.local_node_id)
                    || !request
                        .desired_consensus_node_ids()
                        .contains(&self.inner.local_node_id)
                {
                    return Err(SessionTopologyTransitionError::InvalidTransitionBindings);
                }
                let replicated_abort_applied = durable.evidence.as_ref().is_some_and(|evidence| {
                    evidence.outcome == Some(TerminalMembershipOutcome::Aborted)
                        && evidence.abort_decision_log_index == Some(abort_decision_log_index)
                });
                let cancelled_provisional = if replicated_abort_applied {
                    false
                } else {
                    tokio::time::timeout_at(
                        deadline,
                        self.inner
                            .backend
                            .provisional_consensus_candidate_is_cancelled(
                                self.inner.storage_identity,
                                self.inner.local_node_id,
                                request.transition_id().as_bytes(),
                                request.request_digest().as_bytes(),
                            ),
                    )
                    .await
                    .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?
                    .map_err(map_membership_storage_error)?
                };
                if !replicated_abort_applied && !cancelled_provisional {
                    return Err(SessionTopologyTransitionError::InvalidEvidenceState);
                }
                let proof = SessionTopologyCandidateRetirementProof::try_from_remote_cleanup(
                    request,
                    abort_decision_log_index,
                    abort_cleanup_log_index,
                )?;
                tokio::time::timeout_at(
                    deadline,
                    self.inner
                        .topology_coordinator
                        .transport()?
                        .retire_aborted_candidate(request, &proof),
                )
                .await
                .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?
                .map_err(map_transport_error)?;
                self.inner
                    .peer_directory
                    .abort_staged(
                        request.transition_id(),
                        request.request_digest(),
                        request.expected_epoch(),
                    )
                    .map_err(|_| SessionTopologyTransitionError::InvalidTransitionBindings)?;
                self.inner
                    .topology_coordinator
                    .drop_staged_bindings(request.transition_id(), request.request_digest())?;
                self.inner.admitted.store(false, Ordering::Release);
                Ok(())
            }
        }
    }

    pub(super) async fn handle_topology_admission_barrier(
        &self,
        authenticated_sender: SessionConsensusNodeId,
        identity: SessionConsensusIdentity,
        barrier: TopologyAdmissionBarrierRequest,
    ) -> TopologyAdmissionBarrierReply {
        let transition_id =
            crate::membership::SessionTopologyTransitionId::from_bytes(barrier.transition_id);
        let request_digest =
            crate::membership::SessionTopologyTransitionDigest::from_bytes(barrier.request_digest);
        let request = match self
            .inner
            .topology_coordinator
            .staged_request(transition_id, request_digest)
        {
            Ok(request) => request,
            Err(_) => return TopologyAdmissionBarrierReply::NotReady,
        };
        let (expected_identity, sender_admitted) = match barrier.action {
            TopologyAdmissionBarrierAction::ConfirmStaged => {
                match self.inner.peer_directory.current_scope() {
                    Ok((current_identity, current_members)) => (
                        current_identity,
                        current_members.contains(&authenticated_sender),
                    ),
                    Err(_) => return TopologyAdmissionBarrierReply::NotReady,
                }
            }
            TopologyAdmissionBarrierAction::AppliedLearnerMarker { .. }
            | TopologyAdmissionBarrierAction::AdmitJointVoting => (
                request.desired_identity(),
                self.inner
                    .topology_coordinator
                    .authorizes_staged_sender(&request, authenticated_sender)
                    .unwrap_or(false),
            ),
            TopologyAdmissionBarrierAction::AppliedAbortDecision { .. }
            | TopologyAdmissionBarrierAction::CancelProvisionalCandidate
            | TopologyAdmissionBarrierAction::FinalizeAbortedCandidate { .. } => {
                let current_members = match self.inner.topology_coordinator.current_members() {
                    Ok(members) => members,
                    Err(_) => return TopologyAdmissionBarrierReply::NotReady,
                };
                (
                    request.desired_identity(),
                    current_members.contains(&authenticated_sender)
                        && request
                            .desired_consensus_node_ids()
                            .contains(&authenticated_sender),
                )
            }
        };
        if identity != expected_identity || !sender_admitted {
            return TopologyAdmissionBarrierReply::NotReady;
        }
        let Ok(deadline) = transition_deadline(&request) else {
            return TopologyAdmissionBarrierReply::NotReady;
        };
        if self
            .apply_local_transition_barrier(&request, barrier.action, deadline)
            .await
            .is_ok()
        {
            TopologyAdmissionBarrierReply::Ready
        } else {
            TopologyAdmissionBarrierReply::NotReady
        }
    }

    async fn finish_local_successor_admission(
        &self,
        request: &SessionTopologyTransitionRequest,
        status: &SessionTopologyTransitionStatus,
        deadline: tokio::time::Instant,
    ) -> Result<(), SessionTopologyTransitionError> {
        if !self
            .inner
            .topology_coordinator
            .is_current_request(request)?
        {
            self.inner
                .topology_coordinator
                .finalize_staged_successor_transport(request, status, deadline)
                .await?;
            self.inner
                .peer_directory
                .finalize(
                    request.transition_id(),
                    request.request_digest(),
                    request.expected_epoch(),
                    &request.desired_consensus_node_ids(),
                )
                .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        }
        self.inner.topology_coordinator.finalize_bindings(request)?;
        let desired_members = request.desired_consensus_node_ids();
        self.inner.admitted.store(
            desired_members.contains(&self.inner.local_node_id),
            Ordering::Release,
        );
        Ok(())
    }

    async fn finish_local_abort_admission(
        &self,
        request: &SessionTopologyTransitionRequest,
        status: &SessionTopologyTransitionStatus,
        deadline: tokio::time::Instant,
    ) -> Result<(), SessionTopologyTransitionError> {
        if !self
            .inner
            .topology_coordinator
            .has_exact_staged_request(request)?
        {
            if !self
                .inner
                .topology_coordinator
                .is_current_expected_epoch(request)?
            {
                return Err(SessionTopologyTransitionError::InvalidTransitionBindings);
            }
            self.inner.admitted.store(
                self.inner
                    .topology_coordinator
                    .current_members()?
                    .contains(&self.inner.local_node_id),
                Ordering::Release,
            );
            return Ok(());
        }
        self.inner
            .topology_coordinator
            .abort_staged_successor_transport(request, status, deadline)
            .await?;
        self.inner
            .peer_directory
            .abort_staged(
                request.transition_id(),
                request.request_digest(),
                request.expected_epoch(),
            )
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        self.inner
            .topology_coordinator
            .drop_staged_bindings(request.transition_id(), request.request_digest())?;
        self.inner.admitted.store(
            self.inner
                .topology_coordinator
                .current_members()?
                .contains(&self.inner.local_node_id),
            Ordering::Release,
        );
        Ok(())
    }
}

fn map_membership_change_result(
    result: Result<
        opc_consensus::engine::raft::ClientWriteResponse<SessionRaftTypeConfig>,
        RaftError<SessionConsensusNodeId, ClientWriteError<SessionConsensusNodeId, EmptyNode>>,
    >,
) -> Result<(), SessionTopologyTransitionError> {
    match result {
        Ok(_) => Ok(()),
        Err(RaftError::APIError(ClientWriteError::ForwardToLeader(_))) => {
            Err(SessionTopologyTransitionError::NotLeader)
        }
        Err(RaftError::APIError(ClientWriteError::ChangeMembershipError(_))) => {
            Err(SessionTopologyTransitionError::Unavailable)
        }
        Err(RaftError::Fatal(_)) => Err(SessionTopologyTransitionError::Unavailable),
    }
}

fn status_from_durable(
    request: &SessionTopologyTransitionRequest,
    durable: &DurableTransitionState,
) -> Result<Option<SessionTopologyTransitionStatus>, SessionTopologyTransitionError> {
    let Some(evidence) = durable.evidence.as_ref() else {
        return Ok(None);
    };
    let expected_member_count = match evidence.outcome {
        Some(_) => durable
            .scope
            .terminal_history
            .iter()
            .find(|terminal| {
                terminal.transition_id == request.transition_id().as_bytes()
                    && terminal.transition_digest == request.request_digest().as_bytes()
            })
            .map(|terminal| terminal.expected_member_count)
            .or_else(|| {
                durable
                    .scope
                    .predecessor
                    .iter()
                    .chain(durable.scope.history.iter())
                    .find(|predecessor| {
                        predecessor.transition_id == request.transition_id().as_bytes()
                            && predecessor.transition_digest == request.request_digest().as_bytes()
                    })
                    .map(|predecessor| predecessor.members.len())
            })
            .unwrap_or(durable.scope.current_members.len()),
        None => durable.scope.current_members.len(),
    };
    let phase = match evidence.outcome {
        Some(TerminalMembershipOutcome::Aborted) if evidence.abort_cleanup_log_index.is_some() => {
            SessionTopologyTransitionPhase::Aborted
        }
        Some(TerminalMembershipOutcome::Aborted) => SessionTopologyTransitionPhase::Aborting,
        Some(TerminalMembershipOutcome::Promoted) if evidence.finalization_log_index.is_some() => {
            SessionTopologyTransitionPhase::Completed
        }
        Some(TerminalMembershipOutcome::Promoted) => SessionTopologyTransitionPhase::Finalizing,
        None if evidence.uniform_membership_log_index.is_some() => {
            SessionTopologyTransitionPhase::UniformCommitted
        }
        None if evidence.joint_membership_log_index.is_some() => {
            SessionTopologyTransitionPhase::JointCommitted
        }
        None if durable.scope.application_authority_epoch == request.desired_epoch()
            && durable.scope.application_authority_members
                == request.desired_consensus_node_ids() =>
        {
            SessionTopologyTransitionPhase::AuthorityFenced
        }
        None if evidence.learners_ready_log_index.is_some()
            || classify_applied_membership(
                &durable.applied_membership,
                &durable.scope.current_members,
                &request.desired_consensus_node_ids(),
            ) == AppliedMembershipShape::Learners =>
        {
            SessionTopologyTransitionPhase::LearnersCatchingUp
        }
        None => SessionTopologyTransitionPhase::Prepared,
    };
    let (outcome, reason) = match phase {
        SessionTopologyTransitionPhase::Completed => (
            SessionTopologyTransitionOutcome::Succeeded,
            SessionTopologyTransitionReason::Succeeded,
        ),
        SessionTopologyTransitionPhase::Aborted => (
            SessionTopologyTransitionOutcome::Aborted,
            SessionTopologyTransitionReason::AbortedByCaller,
        ),
        _ => (
            SessionTopologyTransitionOutcome::InProgress,
            SessionTopologyTransitionReason::Progressing,
        ),
    };
    let committed_epoch = if matches!(
        phase,
        SessionTopologyTransitionPhase::UniformCommitted
            | SessionTopologyTransitionPhase::Finalizing
            | SessionTopologyTransitionPhase::Completed
    ) {
        request.desired_epoch()
    } else {
        request.expected_epoch()
    };
    let log_indexes = if matches!(
        phase,
        SessionTopologyTransitionPhase::Aborting | SessionTopologyTransitionPhase::Aborted
    ) {
        SessionTopologyTransitionLogIndexes::aborted(
            evidence
                .abort_decision_log_index
                .ok_or(SessionTopologyTransitionError::InvalidEvidenceState)?,
            evidence.abort_cleanup_log_index,
        )
    } else {
        SessionTopologyTransitionLogIndexes::new(
            evidence.joint_membership_log_index,
            evidence.uniform_membership_log_index,
            evidence.finalization_log_index,
        )
    };
    SessionTopologyTransitionStatus::try_from_request(
        request,
        expected_member_count,
        committed_epoch,
        phase,
        outcome,
        reason,
        log_indexes,
    )
    .map(Some)
}

fn retained_terminal_evidence(
    request: &SessionTopologyTransitionRequest,
    durable: &DurableTransitionState,
) -> bool {
    durable.scope.terminal_history.iter().any(|terminal| {
        terminal.transition_id == request.transition_id().as_bytes()
            && terminal.transition_digest == request.request_digest().as_bytes()
    })
}

fn nonquiescent_prior_terminal(
    request: &SessionTopologyTransitionRequest,
    durable: &DurableTransitionState,
) -> bool {
    durable.scope.terminal.as_ref().is_some_and(|terminal| {
        terminal.transition_id != request.transition_id().as_bytes()
            && match terminal.outcome {
                TerminalMembershipOutcome::Aborted => terminal
                    .abort_cleanup
                    .as_ref()
                    .is_none_or(|cleanup| cleanup.cleanup_log_index.is_none()),
                TerminalMembershipOutcome::Promoted => terminal.finalization_log_index.is_none(),
            }
    })
}

#[cfg(test)]
mod scope_refresh_tests {
    use super::*;
    use crate::consensus::{SessionConsensusClusterId, SessionConsensusConfigurationId};
    use crate::membership::{SessionTopologyTransitionDigest, SessionTopologyTransitionId};
    use crate::sqlite::consensus::{
        AbortedMembershipCleanup, MembershipPredecessorScope, PendingMembershipScope,
        TerminalMembershipTransition,
    };
    use crate::topology::{
        ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain, ReplicaId,
        ReplicaTlsIdentity,
    };

    fn identity(epoch: u64, configuration: u8) -> SessionConsensusIdentity {
        SessionConsensusIdentity::new(
            SessionConsensusClusterId::new("scope-refresh-tests").expect("cluster ID"),
            SessionConsensusConfigurationId::from_bytes([configuration; 32]),
            SessionConsensusConfigurationEpoch::new(epoch).expect("configuration epoch"),
        )
    }

    fn coordinator(current_identity: SessionConsensusIdentity) -> SessionTopologyCoordinatorState {
        SessionTopologyCoordinatorState {
            operation_gate: Arc::new(tokio::sync::RwLock::new(())),
            bindings: RwLock::new(TopologyBindingState {
                current_identity,
                current_descriptors: BTreeMap::new(),
                staged: None,
                last_scope_progress_index: None,
                blocking_terminal: None,
                retained_transitions: BTreeMap::new(),
            }),
            transport: OnceLock::new(),
            supervisor_started: AtomicBool::new(false),
            supervisor_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn descriptor(index: usize) -> QuorumReplicaDescriptor {
        QuorumReplicaDescriptor::new(
            ReplicaId::new(format!("scope-refresh-{index}")).expect("replica ID"),
            ReplicaEndpoint::new(format!("scope-refresh-{index}.invalid"), 7443)
                .expect("replica endpoint"),
            ReplicaTlsIdentity::new(format!("spiffe://test/scope-refresh/{index}"))
                .expect("TLS identity"),
            ReplicaFailureDomain::new(format!("scope-refresh-zone-{index}"))
                .expect("failure domain"),
            ReplicaBackingIdentity::new(format!("scope-refresh-disk-{index}"))
                .expect("backing identity"),
        )
    }

    fn transition_fixture() -> (
        ValidatedQuorumTopology,
        ValidatedQuorumTopology,
        SessionTopologyTransitionRequest,
    ) {
        let members = (0..5).map(descriptor).collect::<Vec<_>>();
        let cluster =
            SessionConsensusClusterId::new("scope-refresh-transitions").expect("cluster ID");
        let current_epoch = SessionConsensusConfigurationEpoch::new(1).expect("current epoch");
        let current_configuration = opc_consensus::derive_configuration_id(
            cluster,
            current_epoch,
            &members[..3]
                .iter()
                .map(QuorumReplicaDescriptor::configuration_fingerprint)
                .collect::<Vec<_>>(),
        );
        let current_identity =
            SessionConsensusIdentity::new(cluster, current_configuration, current_epoch);
        let request = SessionTopologyTransitionRequest::try_new(
            SessionTopologyTransitionId::from_bytes([0x71; 16]),
            cluster,
            current_epoch,
            SessionConsensusConfigurationEpoch::new(2).expect("desired epoch"),
            members.clone(),
            Duration::from_secs(30),
        )
        .expect("transition request");
        let current = ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
            members[0].replica_id().clone(),
            members[..3].to_vec(),
            current_identity,
        ))
        .expect("current topology");
        let desired = ValidatedQuorumTopology::try_from(QuorumTopologyConfig::new_consensus(
            members[0].replica_id().clone(),
            members,
            request.desired_identity(),
        ))
        .expect("desired topology");
        (current, desired, request)
    }

    fn base_scope(current_identity: SessionConsensusIdentity) -> MembershipValidationScope {
        MembershipValidationScope {
            current_identity,
            current_members: BTreeSet::new(),
            current_bindings: BTreeMap::new(),
            application_authority_epoch: current_identity.configuration_epoch(),
            application_authority_members: BTreeSet::new(),
            predecessor: None,
            history: Vec::new(),
            terminal_history: Vec::new(),
            pending: None,
            terminal: None,
        }
    }

    fn pending_scope(
        current_identity: SessionConsensusIdentity,
        desired_identity: SessionConsensusIdentity,
        transition_id: [u8; 16],
        transition_digest: [u8; 32],
    ) -> MembershipValidationScope {
        let mut scope = base_scope(current_identity);
        scope.pending = Some(PendingMembershipScope {
            transition_id,
            transition_digest,
            desired_identity,
            desired_members: BTreeSet::new(),
            desired_bindings: BTreeMap::new(),
            transition_start_log_index: 10,
            learners_ready_log_index: Some(11),
            joint_membership_log_index: Some(12),
            uniform_membership_log_index: None,
        });
        scope
    }

    fn terminal_scope(
        current_identity: SessionConsensusIdentity,
        transition_id: [u8; 16],
        transition_digest: [u8; 32],
        finalization_log_index: Option<u64>,
    ) -> MembershipValidationScope {
        let mut scope = base_scope(current_identity);
        let predecessor_epoch = current_identity
            .configuration_epoch()
            .get()
            .checked_sub(1)
            .and_then(|epoch| SessionConsensusConfigurationEpoch::new(epoch).ok())
            .expect("terminal predecessor epoch");
        scope.predecessor = Some(MembershipPredecessorScope {
            transition_id,
            transition_digest,
            identity: SessionConsensusIdentity::new(
                current_identity.cluster_id(),
                SessionConsensusConfigurationId::from_bytes([0x30; 32]),
                predecessor_epoch,
            ),
            members: BTreeSet::new(),
            transition_start_log_index: 10,
            cutover_log_index: 13,
        });
        scope.terminal = Some(TerminalMembershipTransition {
            transition_id,
            transition_digest,
            outcome: TerminalMembershipOutcome::Promoted,
            transition_start_log_index: 10,
            learners_ready_log_index: Some(11),
            joint_membership_log_index: Some(12),
            uniform_membership_log_index: Some(13),
            cutover_log_index: Some(13),
            finalization_log_index,
            abort_cleanup: None,
        });
        scope
    }

    #[test]
    fn stale_scope_refresh_cannot_reopen_terminal_staging() {
        let predecessor = identity(1, 0x31);
        let successor = identity(2, 0x32);
        let transition_id = [0x41; 16];
        let transition_digest = [0x42; 32];
        let transition = SessionTopologyTransitionId::from_bytes(transition_id);
        let digest = SessionTopologyTransitionDigest::from_bytes(transition_digest);
        let coordinator = coordinator(predecessor);
        let stale_pending = pending_scope(predecessor, successor, transition_id, transition_digest);
        let finalizing = terminal_scope(successor, transition_id, transition_digest, None);
        let completed = terminal_scope(successor, transition_id, transition_digest, Some(14));

        coordinator
            .load_retained_transitions(&finalizing)
            .expect("observe terminal cutover");
        coordinator
            .load_retained_transitions(&stale_pending)
            .expect("ignore delayed pre-terminal observation");
        {
            let state = coordinator.bindings.read().expect("coordinator bindings");
            assert_eq!(Some((transition, digest)), state.blocking_terminal);
            assert_eq!(None, state.retained_transitions.get(&transition));
            assert_eq!(Some(13), state.last_scope_progress_index);
        }

        coordinator
            .load_retained_transitions(&completed)
            .expect("observe exact terminal completion");
        coordinator
            .load_retained_transitions(&finalizing)
            .expect("ignore delayed incomplete terminal observation");
        coordinator
            .load_retained_transitions(&stale_pending)
            .expect("ignore delayed pre-terminal observation after completion");
        let state = coordinator.bindings.read().expect("coordinator bindings");
        assert_eq!(None, state.blocking_terminal);
        assert_eq!(Some(&digest), state.retained_transitions.get(&transition));
        assert_eq!(Some(14), state.last_scope_progress_index);
    }

    #[test]
    fn equal_progress_scope_disagreement_fails_closed() {
        let successor = identity(2, 0x32);
        let coordinator = coordinator(successor);
        let first = terminal_scope(successor, [0x51; 16], [0x52; 32], None);
        let conflicting = terminal_scope(successor, [0x61; 16], [0x62; 32], None);

        coordinator
            .load_retained_transitions(&first)
            .expect("observe first terminal");
        assert_eq!(
            Err(SessionTopologyTransitionError::InvalidEvidenceState),
            coordinator.load_retained_transitions(&conflicting)
        );
    }

    #[test]
    fn incomplete_terminal_reopen_reconstructs_exact_staging() {
        let (current, desired, request) = transition_fixture();
        let transition_id = request.transition_id().as_bytes();
        let transition_digest = request.request_digest().as_bytes();

        let aborting = {
            let mut scope = base_scope(
                current
                    .consensus_identity()
                    .expect("current consensus identity"),
            );
            scope.current_members = request
                .desired_consensus_node_ids()
                .iter()
                .copied()
                .take(3)
                .collect();
            scope.terminal = Some(TerminalMembershipTransition {
                transition_id,
                transition_digest,
                outcome: TerminalMembershipOutcome::Aborted,
                transition_start_log_index: 10,
                learners_ready_log_index: Some(11),
                joint_membership_log_index: None,
                uniform_membership_log_index: None,
                cutover_log_index: None,
                finalization_log_index: None,
                abort_cleanup: Some(AbortedMembershipCleanup {
                    desired_identity: request.desired_identity(),
                    desired_members: request.desired_consensus_node_ids(),
                    desired_bindings: request.desired_node_bindings(),
                    learners: BTreeSet::new(),
                    decision_log_index: 12,
                    cleanup_log_index: None,
                }),
            });
            scope
        };
        let reopened_abort = SessionTopologyCoordinatorState::try_from_topology(&current)
            .expect("reopen current topology");
        reopened_abort
            .load_retained_transitions(&aborting)
            .expect("load incomplete abort");
        assert_eq!(
            Ok(true),
            reopened_abort.stage_bindings(&request, &BTreeMap::new()),
            "exact abort retry must reconstruct process-local staging"
        );

        let finalizing = terminal_scope(
            request.desired_identity(),
            transition_id,
            transition_digest,
            None,
        );
        let reopened_finalize = SessionTopologyCoordinatorState::try_from_topology(&desired)
            .expect("reopen desired topology");
        reopened_finalize
            .load_retained_transitions(&finalizing)
            .expect("load incomplete finalization");
        assert_eq!(
            Ok(true),
            reopened_finalize.stage_bindings(&request, &BTreeMap::new()),
            "exact finalization retry must reconstruct process-local staging"
        );
    }

    #[test]
    fn local_unstage_does_not_create_durable_retention_or_grow_state() {
        let (current, _, request) = transition_fixture();
        let coordinator = SessionTopologyCoordinatorState::try_from_topology(&current)
            .expect("current coordinator");
        let scope = base_scope(
            current
                .consensus_identity()
                .expect("current consensus identity"),
        );
        coordinator
            .load_retained_transitions(&scope)
            .expect("load initial scope");
        assert_eq!(
            Ok(true),
            coordinator.stage_bindings(&request, &BTreeMap::new())
        );
        coordinator
            .drop_staged_bindings(request.transition_id(), request.request_digest())
            .expect("drop failed local stage");
        coordinator
            .load_retained_transitions(&scope)
            .expect("same durable scope remains authoritative");
        assert_eq!(
            Ok(true),
            coordinator.stage_bindings(&request, &BTreeMap::new()),
            "exact retry after local unstage must remain admissible"
        );
        coordinator
            .drop_staged_bindings(request.transition_id(), request.request_digest())
            .expect("drop exact retry");

        for seed in 0_u16..5_000 {
            let mut transition_id = [0_u8; 16];
            transition_id[..2].copy_from_slice(&seed.to_be_bytes());
            coordinator
                .drop_staged_bindings(
                    SessionTopologyTransitionId::from_bytes(transition_id),
                    SessionTopologyTransitionDigest::from_bytes([0x91; 32]),
                )
                .expect("idempotent local drop");
        }
        let state = coordinator.bindings.read().expect("coordinator bindings");
        assert!(state.staged.is_none());
        assert!(state.retained_transitions.is_empty());
        assert_eq!(Some(0), state.last_scope_progress_index);
    }
}
