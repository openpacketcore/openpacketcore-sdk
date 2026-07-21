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
use opc_consensus::engine::{EmptyNode, StoredMembership};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::*;
use crate::membership::{
    SessionTopologyAbortAdmissionProof, SessionTopologyJointCommitAdmissionProof,
    SessionTopologyLearnersReadyAdmissionProof, SessionTopologyTransitionError,
    SessionTopologyTransitionLogIndexes, SessionTopologyTransitionOutcome,
    SessionTopologyTransitionPhase, SessionTopologyTransitionReason,
    SessionTopologyTransitionRequest, SessionTopologyTransitionStatus,
    SessionTopologyUniformCommitAdmissionProof,
};
use crate::sqlite::consensus::{
    MembershipScopeMutationError, MembershipTransitionEvidence, MembershipValidationScope,
    TerminalMembershipOutcome,
};
use crate::topology::QuorumReplicaDescriptor;

const TRANSITION_REQUEST_ID_DOMAIN: &[u8] =
    b"openpacketcore/session-store/topology-transition-command/v1\0";

/// Exact authenticated remote-peer set for a desired topology epoch.
///
/// The map must contain every desired voter except the local node. Each peer
/// must report the map key as its authenticated node ID and the request's exact
/// desired consensus identity as its scope.
pub type SessionTopologyTransitionPeers =
    BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>;

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
                    .field("transition_staged", &bindings.staged.is_some());
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
            }),
            transport: OnceLock::new(),
            supervisor_started: AtomicBool::new(false),
            supervisor_notify: Arc::new(tokio::sync::Notify::new()),
        })
    }

    pub(super) fn operation_gate(&self) -> Arc<tokio::sync::RwLock<()>> {
        Arc::clone(&self.operation_gate)
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
    ) -> Result<(), SessionTopologyTransitionError> {
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
                    Ok(())
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
                    Ok(())
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
                Ok(())
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
                Ok(())
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

    fn abort_bindings(
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
    AppliedLearnerMarker { log_index: u64 },
    AdmitJointVoting,
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
        self.inner
            .topology_coordinator
            .stage_bindings(request, &desired_peers)?;

        let (current_identity, current_members) = self
            .inner
            .peer_directory
            .current_scope()
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        if current_identity == request.desired_identity() && current_members == desired_members {
            self.ensure_topology_reconciliation_supervisor()?;
            self.inner.topology_coordinator.notify_supervisor();
            return Ok(());
        }
        if current_identity.cluster_id() != request.cluster_id()
            || current_identity.configuration_epoch() != request.expected_epoch()
        {
            return Err(SessionTopologyTransitionError::StaleEpoch);
        }
        if !current_members
            .intersection(&desired_members)
            .next()
            .is_some()
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
        self.ensure_topology_reconciliation_supervisor()?;
        self.inner.topology_coordinator.notify_supervisor();
        Ok(())
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
        let durable = self.read_transition_state_before(request, deadline).await?;
        let Some(status) = status_from_durable(request, &durable)? else {
            return Ok(());
        };

        // Once Prepare applies, application authority remains closed until an
        // exact uniform successor or durable pre-joint abort is reconciled.
        self.inner.admitted.store(false, Ordering::Release);
        let operation_gate = self.inner.topology_coordinator.operation_gate();
        let _operation_guard =
            tokio::time::timeout_at(deadline, operation_gate.write_owned())
                .await
                .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?;

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
                self.inner.admitted.store(true, Ordering::Release);
                Ok(())
            }
        }
    }

    /// Durably prepare one transition and catch every added learner up through
    /// a replicated exact-application marker.
    ///
    /// Openraft's blocking learner API permits bounded lag, so its return is
    /// never used as readiness proof. The coordinator commits a learner marker
    /// and then obtains an exact applied-index admission acknowledgement from
    /// every desired member before returning the unforgeable proof.
    pub async fn prepare_topology_transition(
        &self,
        request: &SessionTopologyTransitionRequest,
        desired_peers: SessionTopologyTransitionPeers,
    ) -> Result<SessionTopologyLearnersReadyAdmissionProof, SessionTopologyTransitionError> {
        let deadline = transition_deadline(request)?;
        self.stage_topology_transition_peers(request, desired_peers)?;
        self.await_current_staging_barrier(request, deadline).await?;
        let operation_gate = self.inner.topology_coordinator.operation_gate();
        let mut operation_guard = tokio::time::timeout_at(deadline, operation_gate.write_owned())
            .await
            .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?;

        let mut durable = self.read_transition_state_before(request, deadline).await?;
        if let Some(status) = status_from_durable(request, &durable)? {
            match status.phase() {
                SessionTopologyTransitionPhase::Aborted => {
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
                | SessionTopologyTransitionPhase::LearnersCatchingUp => {}
            }
        } else {
            self.require_local_transition_leader(request, &durable)
                .await?;
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

        self.inner.admitted.store(false, Ordering::Release);
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
        self.inner.admitted.store(false, Ordering::Release);

        let mut durable = self.read_transition_state_before(request, deadline).await?;
        let mut status = status_from_durable(request, &durable)?
            .ok_or(SessionTopologyTransitionError::InvalidEvidenceState)?;
        if status.phase() == SessionTopologyTransitionPhase::Aborted {
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
            self.inner
                .topology_coordinator
                .finalize_staged_successor_transport(request, &status, deadline)
                .await?;
            self.inner.topology_coordinator.finalize_bindings(request)?;
        }
        self.require_local_transition_leader(request, &durable)
            .await?;

        if durable.scope.application_authority_identity != request.desired_identity() {
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
        self.require_local_transition_leader(request, &durable)
            .await?;
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
        operation_guard = returned_guard;
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
    /// Learners are first removed by a committed Openraft membership operation
    /// while pending scope remains durable. The old exact uniform membership is
    /// then re-read from the applied state machine before Abort is proposed.
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
        let status = status_from_durable(request, &durable)?
            .ok_or(SessionTopologyTransitionError::InvalidEvidenceState)?;
        if status.phase() == SessionTopologyTransitionPhase::Aborted {
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
        self.require_local_transition_leader(request, &durable)
            .await?;
        let current_members = durable.scope.current_members.clone();
        if classify_applied_membership(
            &durable.applied_membership,
            &current_members,
            &request.desired_consensus_node_ids(),
        ) != AppliedMembershipShape::CurrentUniform
        {
            operation_guard = self
                .change_membership_before(current_members.clone(), operation_guard, deadline)
                .await?;
            durable = self.read_transition_state_before(request, deadline).await?;
        }
        if classify_applied_membership(
            &durable.applied_membership,
            &current_members,
            &request.desired_consensus_node_ids(),
        ) != AppliedMembershipShape::CurrentUniform
        {
            return Err(SessionTopologyTransitionError::DeadlineExceededResumable);
        }
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
        let status = status_from_durable(request, &durable)?
            .ok_or(SessionTopologyTransitionError::InvalidEvidenceState)?;
        if status.phase() != SessionTopologyTransitionPhase::Aborted {
            return Err(SessionTopologyTransitionError::DeadlineExceededResumable);
        }
        self.finish_local_abort_admission(request, &status, deadline)
            .await?;
        self.inner.admitted.store(true, Ordering::Release);
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
        }
        Err(SessionTopologyTransitionError::NotLeader)
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
        let supervisor = tokio::spawn(async move {
            let result = async move {
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
            }
            .await;
            (operation_guard, result)
        });
        let (operation_guard, result) = tokio::time::timeout_at(deadline, supervisor)
            .await
            .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        result.map(|index| (operation_guard, index))
    }

    async fn add_learner_before(
        &self,
        learner: SessionConsensusNodeId,
        operation_guard: tokio::sync::OwnedRwLockWriteGuard<()>,
        deadline: tokio::time::Instant,
    ) -> Result<tokio::sync::OwnedRwLockWriteGuard<()>, SessionTopologyTransitionError> {
        let raft = self.inner.raft.clone();
        let supervisor = tokio::spawn(async move {
            let result = raft.add_learner(learner, EmptyNode::default(), true).await;
            (operation_guard, result)
        });
        let (operation_guard, result) = tokio::time::timeout_at(deadline, supervisor)
            .await
            .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        map_membership_change_result(result)?;
        Ok(operation_guard)
    }

    async fn change_membership_before(
        &self,
        members: BTreeSet<SessionConsensusNodeId>,
        operation_guard: tokio::sync::OwnedRwLockWriteGuard<()>,
        deadline: tokio::time::Instant,
    ) -> Result<tokio::sync::OwnedRwLockWriteGuard<()>, SessionTopologyTransitionError> {
        let raft = self.inner.raft.clone();
        let supervisor = tokio::spawn(async move {
            let result = raft.change_membership(members, false).await;
            (operation_guard, result)
        });
        let (operation_guard, result) = tokio::time::timeout_at(deadline, supervisor)
            .await
            .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?
            .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
        map_membership_change_result(result)?;
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

        loop {
            let mut ready = self
                .apply_local_transition_barrier(request, action, deadline)
                .await
                .is_ok();
            let mut calls = FuturesUnordered::new();
            for peer in peers.values().cloned() {
                let wire = SessionConsensusWireRequest::try_new(
                    identity,
                    self.inner.local_node_id,
                    SessionConsensusRpcFamily::TopologyAdmissionBarrier,
                    payload.clone(),
                )
                .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
                calls.push(async move {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    tokio::time::timeout_at(deadline, peer.call_with_timeout(wire, remaining)).await
                });
            }
            while let Some(result) = calls.next().await {
                let response = result
                    .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?
                    .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
                response
                    .validate()
                    .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
                let response_payload = response
                    .result
                    .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
                let reply: TopologyAdmissionBarrierReply = decode_bounded(&response_payload)
                    .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
                ready &= reply == TopologyAdmissionBarrierReply::Ready;
            }
            if ready {
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
        let payload = encode_bounded(&TopologyAdmissionBarrierRequest {
            transition_id: request.transition_id().as_bytes(),
            request_digest: request.request_digest().as_bytes(),
            action,
        })
        .map_err(|_| SessionTopologyTransitionError::Unavailable)?;

        loop {
            let mut ready = self
                .apply_local_transition_barrier(request, action, deadline)
                .await
                .is_ok();
            let mut calls = FuturesUnordered::new();
            for peer in peers.values().cloned() {
                let wire = SessionConsensusWireRequest::try_new(
                    request.desired_identity(),
                    self.inner.local_node_id,
                    SessionConsensusRpcFamily::TopologyAdmissionBarrier,
                    payload.clone(),
                )
                .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
                calls.push(async move {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    tokio::time::timeout_at(deadline, peer.call_with_timeout(wire, remaining)).await
                });
            }
            while let Some(result) = calls.next().await {
                let response = result
                    .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?
                    .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
                response
                    .validate()
                    .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
                let response_payload = response
                    .result
                    .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
                let reply: TopologyAdmissionBarrierReply = decode_bounded(&response_payload)
                    .map_err(|_| SessionTopologyTransitionError::Unavailable)?;
                ready &= reply == TopologyAdmissionBarrierReply::Ready;
            }
            if ready {
                return Ok(());
            }
            tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(25)))
                .await
                .map_err(|_| SessionTopologyTransitionError::DeadlineExceededResumable)?;
        }
    }

    async fn apply_local_transition_barrier(
        &self,
        request: &SessionTopologyTransitionRequest,
        action: TopologyAdmissionBarrierAction,
        deadline: tokio::time::Instant,
    ) -> Result<(), SessionTopologyTransitionError> {
        if action == TopologyAdmissionBarrierAction::ConfirmStaged {
            self.inner.topology_coordinator.transport()?;
            self.inner
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
            .abort_bindings(request.transition_id(), request.request_digest())
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
        Some(TerminalMembershipOutcome::Promoted) => durable
            .scope
            .predecessor
            .as_ref()
            .filter(|predecessor| {
                predecessor.transition_id == request.transition_id().as_bytes()
                    && predecessor.transition_digest == request.request_digest().as_bytes()
            })
            .map_or(durable.scope.current_members.len(), |predecessor| {
                predecessor.members.len()
            }),
        Some(TerminalMembershipOutcome::Aborted) | None => durable.scope.current_members.len(),
    };
    let phase = match evidence.outcome {
        Some(TerminalMembershipOutcome::Aborted) => SessionTopologyTransitionPhase::Aborted,
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
        None if durable.scope.application_authority_identity == request.desired_identity() => {
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
    let log_indexes = SessionTopologyTransitionLogIndexes::new(
        evidence.joint_membership_log_index,
        evidence.uniform_membership_log_index,
        evidence.finalization_log_index,
    );
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
