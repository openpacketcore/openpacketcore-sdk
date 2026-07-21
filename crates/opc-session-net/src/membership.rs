//! Bounded transport admission during one consensus membership transition.
//!
//! The current and successor manifests remain immutable. This module only
//! controls which exact manifest identities may establish and use the
//! consensus transport while an Openraft membership change is in progress.

use std::fmt;
use std::sync::Arc;

use opc_consensus::{ConsensusIdentity, ConsensusNodeId, ConsensusRpcFamily};
use opc_session_store::{
    ReplicaId, SessionConsensusPeerError, SessionTopologyTransitionDigest,
    SessionTopologyTransitionError, SessionTopologyTransitionRequest,
};
pub use opc_session_store::{
    SessionTopologyAbortAdmissionProof, SessionTopologyLearnersReadyAdmissionProof,
    SessionTopologyTransitionId, SessionTopologyUniformCommitAdmissionProof,
};
use opc_types::SpiffeId;
use thiserror::Error;
use tokio::sync::{OwnedRwLockReadGuard, RwLock};

use crate::identity::{LocalReplicaBinding, SessionConfigurationEpoch, SessionReplicationManifest};

/// Result of an idempotent transport-admission transition operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionMembershipTransitionResult {
    /// A successor was staged for the first time.
    Staged,
    /// The exact successor was already staged by this transition.
    AlreadyStaged,
    /// Successor voting was admitted after caller-verified learner catch-up.
    VotingAdmitted,
    /// Successor voting had already been admitted for this transition.
    AlreadyVotingAdmitted,
    /// The staged successor became the sole current manifest.
    Finalized,
    /// The exact transition had already been finalized.
    AlreadyFinalized,
    /// The staged successor was removed before commit.
    Aborted,
    /// The exact transition had already been aborted.
    AlreadyAborted,
}

/// Redaction-safe membership-admission failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SessionMembershipAdmissionError {
    /// The shared topology-transition contract rejected this operation.
    #[error(transparent)]
    Topology(#[from] SessionTopologyTransitionError),
    /// The immutable successor does not exactly encode the validated request.
    #[error("session membership successor does not match the validated transition")]
    SuccessorManifestMismatch,
    /// The request cluster does not match the listener's current authority.
    #[error("session membership current manifest does not match the validated transition")]
    CurrentManifestMismatch,
    /// Distinct old/new members alias one authenticated or physical identity.
    #[error("session membership joint manifests contain an identity alias")]
    JointManifestIdentityConflict,
    /// The local replica is absent from both sides of the transition.
    #[error("local replica is absent from the membership transition")]
    MissingLocalReplica,
    /// No successor is staged for this operation.
    #[error("session membership transition is not staged")]
    TransitionNotStaged,
    /// The staged successor has not completed learner catch-up admission.
    #[error("session membership successor is not ready for finalization")]
    SuccessorNotReady,
}

impl SessionMembershipAdmissionError {
    /// Stable machine-readable diagnostic code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Topology(error) => error.reason_code(),
            Self::SuccessorManifestMismatch => "session_membership_successor_manifest_mismatch",
            Self::CurrentManifestMismatch => "session_membership_current_manifest_mismatch",
            Self::JointManifestIdentityConflict => {
                "session_membership_joint_manifest_identity_conflict"
            }
            Self::MissingLocalReplica => "session_membership_missing_local_replica",
            Self::TransitionNotStaged => "session_membership_transition_not_staged",
            Self::SuccessorNotReady => "session_membership_successor_not_ready",
        }
    }
}

/// Redaction-safe bounded view of transport membership admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionMembershipAdmissionSnapshot {
    current_identity: ConsensusIdentity,
    current_epoch: SessionConfigurationEpoch,
    current_members: usize,
    pending_identity: Option<ConsensusIdentity>,
    pending_epoch: Option<SessionConfigurationEpoch>,
    pending_members: usize,
    pending_voting_admitted: bool,
}

impl SessionMembershipAdmissionSnapshot {
    /// Exact current cluster/configuration/epoch identity.
    pub const fn current_identity(&self) -> ConsensusIdentity {
        self.current_identity
    }

    /// Sole authoritative configuration epoch.
    pub const fn current_epoch(&self) -> SessionConfigurationEpoch {
        self.current_epoch
    }

    /// Number of members in the current manifest.
    pub const fn current_members(&self) -> usize {
        self.current_members
    }

    /// Exact staged successor identity, when a transition is active.
    pub const fn pending_identity(&self) -> Option<ConsensusIdentity> {
        self.pending_identity
    }

    /// Staged successor epoch, when a transition is active.
    pub const fn pending_epoch(&self) -> Option<SessionConfigurationEpoch> {
        self.pending_epoch
    }

    /// Number of staged successor members, or zero when none is staged.
    pub const fn pending_members(&self) -> usize {
        self.pending_members
    }

    /// Whether the staged successor may send `Vote` RPCs after catch-up.
    pub const fn pending_voting_admitted(&self) -> bool {
        self.pending_voting_admitted
    }
}

#[derive(Clone)]
struct PendingMembership {
    transition_id: SessionTopologyTransitionId,
    request_digest: SessionTopologyTransitionDigest,
    expected_epoch: SessionConfigurationEpoch,
    manifest: Arc<SessionReplicationManifest>,
    voting_admitted: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CompletedMembership {
    Finalized {
        transition_id: SessionTopologyTransitionId,
        request_digest: SessionTopologyTransitionDigest,
        from_epoch: SessionConfigurationEpoch,
        to_epoch: SessionConfigurationEpoch,
    },
    Aborted {
        transition_id: SessionTopologyTransitionId,
        request_digest: SessionTopologyTransitionDigest,
        from_epoch: SessionConfigurationEpoch,
        to_epoch: SessionConfigurationEpoch,
    },
}

impl CompletedMembership {
    const fn transition_id(self) -> SessionTopologyTransitionId {
        match self {
            Self::Finalized { transition_id, .. } | Self::Aborted { transition_id, .. } => {
                transition_id
            }
        }
    }

    const fn request_digest(self) -> SessionTopologyTransitionDigest {
        match self {
            Self::Finalized { request_digest, .. } | Self::Aborted { request_digest, .. } => {
                request_digest
            }
        }
    }
}

struct MembershipAdmissionState {
    current: Arc<SessionReplicationManifest>,
    pending: Option<PendingMembership>,
    last_completed: Option<CompletedMembership>,
}

/// Shared, bounded admission state for one local consensus listener.
///
/// Existing [`LocalReplicaBinding`] values remain immutable. During staging,
/// AppendEntries and snapshot catch-up traffic may use either exact manifest.
/// Successor voting requires an explicit post-catch-up promotion, while
/// consumer mutation/read authority remains on the current manifest.
/// Finalization atomically makes the successor the only admitted identity;
/// abort atomically removes it.
#[derive(Clone)]
pub struct SessionMembershipAdmission {
    local_replica_id: ReplicaId,
    state: Arc<RwLock<MembershipAdmissionState>>,
}

impl SessionMembershipAdmission {
    /// Start with one immutable current manifest.
    ///
    /// A joining replica may be absent from `current`; it admits no connection
    /// until a staged successor contains its exact identity.
    pub fn new(current: Arc<SessionReplicationManifest>, local_replica_id: ReplicaId) -> Self {
        Self {
            local_replica_id,
            state: Arc::new(RwLock::new(MembershipAdmissionState {
                current,
                pending: None,
                last_completed: None,
            })),
        }
    }

    /// Preserve the legacy single-manifest server behavior.
    pub fn from_current_binding(binding: LocalReplicaBinding) -> Self {
        Self::new(
            Arc::clone(binding.manifest()),
            binding.local_replica_id().clone(),
        )
    }

    /// Stage the exact successor encoded by a validated topology request.
    ///
    /// Repeating the exact transition is idempotent. A different concurrent
    /// transition, stale epoch, cluster change, or transition-ID reuse fails
    /// closed without changing admission.
    pub async fn stage_successor(
        &self,
        request: &SessionTopologyTransitionRequest,
        successor: Arc<SessionReplicationManifest>,
    ) -> Result<SessionMembershipTransitionResult, SessionMembershipAdmissionError> {
        let mut state = self.state.write().await;
        let transition_id = request.transition_id();
        let request_digest = request.request_digest();
        let expected_epoch = request.expected_epoch();
        let successor_identity = successor.consensus_identity();
        if successor_identity.cluster_id() != request.cluster_id()
            || successor_identity.configuration_epoch() != request.desired_epoch()
            || successor_identity.configuration_id() != request.desired_configuration_id()
            || successor.configured_members() != request.desired_members().len()
        {
            return Err(SessionMembershipAdmissionError::SuccessorManifestMismatch);
        }
        if state.current.consensus_identity().cluster_id() != request.cluster_id() {
            return Err(SessionMembershipAdmissionError::CurrentManifestMismatch);
        }

        if let Some(pending) = &state.pending {
            if pending.transition_id == transition_id
                && pending.request_digest == request_digest
                && pending.expected_epoch == expected_epoch
                && pending.manifest.consensus_identity() == successor.consensus_identity()
            {
                return Ok(SessionMembershipTransitionResult::AlreadyStaged);
            }
            let error = if pending.transition_id == transition_id {
                SessionTopologyTransitionError::IdempotencyConflict
            } else {
                SessionTopologyTransitionError::TransitionInProgress
            };
            return Err(error.into());
        }

        if let Some(completed) = state.last_completed {
            if completed.transition_id() == transition_id {
                if completed.request_digest() != request_digest {
                    return Err(SessionTopologyTransitionError::IdempotencyConflict.into());
                }
                return match completed {
                    CompletedMembership::Finalized {
                        from_epoch,
                        to_epoch,
                        ..
                    } if from_epoch == expected_epoch
                        && to_epoch == successor.configuration_epoch() =>
                    {
                        Ok(SessionMembershipTransitionResult::AlreadyFinalized)
                    }
                    CompletedMembership::Aborted {
                        from_epoch,
                        to_epoch,
                        ..
                    } if from_epoch == expected_epoch
                        && to_epoch == successor.configuration_epoch() =>
                    {
                        Ok(SessionMembershipTransitionResult::AlreadyAborted)
                    }
                    _ => Err(SessionTopologyTransitionError::IdempotencyConflict.into()),
                };
            }
        }

        if state.current.configuration_epoch() != expected_epoch {
            return Err(SessionTopologyTransitionError::StaleEpoch.into());
        }
        if !state.current.retained_member_bindings_match(&successor) {
            return Err(SessionMembershipAdmissionError::SuccessorManifestMismatch);
        }
        if !state
            .current
            .transition_member_aliases_are_unique(&successor)
        {
            return Err(SessionMembershipAdmissionError::JointManifestIdentityConflict);
        }
        if state
            .current
            .consensus_node_id(&self.local_replica_id)
            .is_none()
            && successor
                .consensus_node_id(&self.local_replica_id)
                .is_none()
        {
            return Err(SessionMembershipAdmissionError::MissingLocalReplica);
        }

        state.pending = Some(PendingMembership {
            transition_id,
            request_digest,
            expected_epoch,
            manifest: successor,
            voting_admitted: false,
        });
        Ok(SessionMembershipTransitionResult::Staged)
    }

    /// Admit `Vote` RPCs under the staged successor after learner catch-up.
    ///
    /// The topology coordinator must call this only after it has verified that
    /// every added learner is caught up and identity-admitted. The transport
    /// cannot inspect Openraft replication progress; before this explicit
    /// promotion it admits only AppendEntries and snapshot catch-up traffic
    /// under the successor identity. `proof` is minted only by the session-store
    /// coordinator after exact learner progress is verified. Its transition ID,
    /// epochs, desired configuration, and request digest must match the staged
    /// request.
    pub async fn admit_successor_voting_after_catch_up(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyLearnersReadyAdmissionProof,
    ) -> Result<SessionMembershipTransitionResult, SessionMembershipAdmissionError> {
        if !proof.validates_request(request) {
            return Err(SessionTopologyTransitionError::IdempotencyConflict.into());
        }
        self.admit_successor_voting_validated(request).await
    }

    async fn admit_successor_voting_validated(
        &self,
        request: &SessionTopologyTransitionRequest,
    ) -> Result<SessionMembershipTransitionResult, SessionMembershipAdmissionError> {
        let mut state = self.state.write().await;
        let transition_id = request.transition_id();
        let request_digest = request.request_digest();
        let Some(pending) = state.pending.as_mut() else {
            return match state.last_completed {
                Some(CompletedMembership::Finalized {
                    transition_id: completed,
                    request_digest: completed_digest,
                    ..
                }) if completed == transition_id && completed_digest == request_digest => {
                    Ok(SessionMembershipTransitionResult::AlreadyFinalized)
                }
                Some(CompletedMembership::Aborted {
                    transition_id: completed,
                    request_digest: completed_digest,
                    ..
                }) if completed == transition_id && completed_digest == request_digest => {
                    Ok(SessionMembershipTransitionResult::AlreadyAborted)
                }
                Some(completed) if completed.transition_id() == transition_id => {
                    Err(SessionTopologyTransitionError::IdempotencyConflict.into())
                }
                _ => Err(SessionMembershipAdmissionError::TransitionNotStaged),
            };
        };
        if pending.transition_id != transition_id || pending.request_digest != request_digest {
            return Err(SessionTopologyTransitionError::IdempotencyConflict.into());
        }
        if pending.voting_admitted {
            return Ok(SessionMembershipTransitionResult::AlreadyVotingAdmitted);
        }
        pending.voting_admitted = true;
        Ok(SessionMembershipTransitionResult::VotingAdmitted)
    }

    /// Atomically make the staged successor the sole admitted manifest.
    ///
    /// Finalization fails closed until
    /// [`Self::admit_successor_voting_after_catch_up`] has admitted voting for
    /// the exact staged transition.
    ///
    /// The exclusive update waits for already-admitted handler calls to finish.
    /// After it returns, no old connection can start another handler call.
    /// `proof` is minted only after the desired uniform Openraft membership is
    /// durably committed. Its exact transition scope must match the request.
    pub async fn finalize_successor(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyUniformCommitAdmissionProof,
    ) -> Result<SessionMembershipTransitionResult, SessionMembershipAdmissionError> {
        if !proof.validates_request(request) {
            return Err(SessionTopologyTransitionError::IdempotencyConflict.into());
        }
        self.finalize_successor_validated(request).await
    }

    async fn finalize_successor_validated(
        &self,
        request: &SessionTopologyTransitionRequest,
    ) -> Result<SessionMembershipTransitionResult, SessionMembershipAdmissionError> {
        let mut state = self.state.write().await;
        let transition_id = request.transition_id();
        let request_digest = request.request_digest();
        let Some(pending) = state.pending.as_ref() else {
            return match state.last_completed {
                Some(CompletedMembership::Finalized {
                    transition_id: completed,
                    request_digest: completed_digest,
                    ..
                }) if completed == transition_id && completed_digest == request_digest => {
                    Ok(SessionMembershipTransitionResult::AlreadyFinalized)
                }
                Some(CompletedMembership::Aborted {
                    transition_id: completed,
                    request_digest: completed_digest,
                    ..
                }) if completed == transition_id && completed_digest == request_digest => {
                    Ok(SessionMembershipTransitionResult::AlreadyAborted)
                }
                Some(completed) if completed.transition_id() == transition_id => {
                    Err(SessionTopologyTransitionError::IdempotencyConflict.into())
                }
                _ => Err(SessionMembershipAdmissionError::TransitionNotStaged),
            };
        };
        if pending.transition_id != transition_id || pending.request_digest != request_digest {
            return Err(SessionTopologyTransitionError::IdempotencyConflict.into());
        }
        if !pending.voting_admitted {
            return Err(SessionMembershipAdmissionError::SuccessorNotReady);
        }
        let pending = state
            .pending
            .take()
            .ok_or(SessionMembershipAdmissionError::TransitionNotStaged)?;
        let from_epoch = state.current.configuration_epoch();
        let to_epoch = pending.manifest.configuration_epoch();
        state.current = pending.manifest;
        state.last_completed = Some(CompletedMembership::Finalized {
            transition_id,
            request_digest: pending.request_digest,
            from_epoch,
            to_epoch,
        });
        Ok(SessionMembershipTransitionResult::Finalized)
    }

    /// Atomically remove a staged successor after a pre-joint abort is durable.
    /// `proof` cannot be constructed for a joint-or-later transition and its
    /// exact transition scope must match the request.
    pub async fn abort_successor(
        &self,
        request: &SessionTopologyTransitionRequest,
        proof: &SessionTopologyAbortAdmissionProof,
    ) -> Result<SessionMembershipTransitionResult, SessionMembershipAdmissionError> {
        if !proof.validates_request(request) {
            return Err(SessionTopologyTransitionError::IdempotencyConflict.into());
        }
        self.abort_successor_validated(request).await
    }

    async fn abort_successor_validated(
        &self,
        request: &SessionTopologyTransitionRequest,
    ) -> Result<SessionMembershipTransitionResult, SessionMembershipAdmissionError> {
        let mut state = self.state.write().await;
        let transition_id = request.transition_id();
        let request_digest = request.request_digest();
        let Some(pending) = state.pending.take() else {
            return match state.last_completed {
                Some(CompletedMembership::Aborted {
                    transition_id: completed,
                    request_digest: completed_digest,
                    ..
                }) if completed == transition_id && completed_digest == request_digest => {
                    Ok(SessionMembershipTransitionResult::AlreadyAborted)
                }
                Some(CompletedMembership::Finalized {
                    transition_id: completed,
                    request_digest: completed_digest,
                    ..
                }) if completed == transition_id && completed_digest == request_digest => {
                    Ok(SessionMembershipTransitionResult::AlreadyFinalized)
                }
                Some(completed) if completed.transition_id() == transition_id => {
                    Err(SessionTopologyTransitionError::IdempotencyConflict.into())
                }
                _ => Err(SessionMembershipAdmissionError::TransitionNotStaged),
            };
        };
        if pending.transition_id != transition_id || pending.request_digest != request_digest {
            state.pending = Some(pending);
            return Err(SessionTopologyTransitionError::IdempotencyConflict.into());
        }
        let from_epoch = state.current.configuration_epoch();
        let to_epoch = pending.manifest.configuration_epoch();
        state.last_completed = Some(CompletedMembership::Aborted {
            transition_id,
            request_digest: pending.request_digest,
            from_epoch,
            to_epoch,
        });
        Ok(SessionMembershipTransitionResult::Aborted)
    }

    #[cfg(test)]
    pub(crate) async fn admit_successor_voting_after_catch_up_for_test(
        &self,
        request: &SessionTopologyTransitionRequest,
    ) -> Result<SessionMembershipTransitionResult, SessionMembershipAdmissionError> {
        self.admit_successor_voting_validated(request).await
    }

    #[cfg(test)]
    pub(crate) async fn finalize_successor_for_test(
        &self,
        request: &SessionTopologyTransitionRequest,
    ) -> Result<SessionMembershipTransitionResult, SessionMembershipAdmissionError> {
        self.finalize_successor_validated(request).await
    }

    #[cfg(test)]
    pub(crate) async fn abort_successor_for_test(
        &self,
        request: &SessionTopologyTransitionRequest,
    ) -> Result<SessionMembershipTransitionResult, SessionMembershipAdmissionError> {
        self.abort_successor_validated(request).await
    }

    /// Capture bounded, redaction-safe admission evidence.
    pub async fn snapshot(&self) -> SessionMembershipAdmissionSnapshot {
        let state = self.state.read().await;
        SessionMembershipAdmissionSnapshot {
            current_identity: state.current.consensus_identity(),
            current_epoch: state.current.configuration_epoch(),
            current_members: state.current.configured_members(),
            pending_identity: state
                .pending
                .as_ref()
                .map(|pending| pending.manifest.consensus_identity()),
            pending_epoch: state
                .pending
                .as_ref()
                .map(|pending| pending.manifest.configuration_epoch()),
            pending_members: state
                .pending
                .as_ref()
                .map_or(0, |pending| pending.manifest.configured_members()),
            pending_voting_admitted: state
                .pending
                .as_ref()
                .is_some_and(|pending| pending.voting_admitted),
        }
    }

    pub(crate) async fn admit_engine_bootstrap(
        &self,
        sender_replica_id: &ReplicaId,
        expected_server_replica_id: &ReplicaId,
        identity: ConsensusIdentity,
        sender_node_id: ConsensusNodeId,
        expected_server_node_id: ConsensusNodeId,
        authenticated_spiffe: Option<&SpiffeId>,
    ) -> Result<SessionMembershipEngineScope, SessionConsensusPeerError> {
        let state = self.state.read().await;
        for manifest in std::iter::once(&state.current)
            .chain(state.pending.as_ref().map(|pending| &pending.manifest))
        {
            if manifest.consensus_identity() != identity {
                continue;
            }
            let local_node_id = manifest.consensus_node_id(&self.local_replica_id);
            let configured_sender_node_id = manifest.consensus_node_id(sender_replica_id);
            if expected_server_replica_id != &self.local_replica_id
                || local_node_id != Some(expected_server_node_id)
                || configured_sender_node_id != Some(sender_node_id)
            {
                continue;
            }
            let Some(expected_spiffe) = manifest.member_spiffe_id(sender_replica_id) else {
                continue;
            };
            if authenticated_spiffe
                .is_some_and(|actual| actual.as_str() != expected_spiffe.as_str())
            {
                return Err(SessionConsensusPeerError::Authentication);
            }
            let binding = manifest
                .bind_local(self.local_replica_id.clone())
                .map_err(|_| SessionConsensusPeerError::ScopeMismatch)?;
            return Ok(SessionMembershipEngineScope {
                binding,
                sender_replica_id: sender_replica_id.clone(),
                sender_node_id,
                authenticated_spiffe: authenticated_spiffe.cloned(),
            });
        }
        Err(SessionConsensusPeerError::ScopeMismatch)
    }

    pub(crate) async fn revalidate_engine_scope(
        &self,
        scope: &SessionMembershipEngineScope,
        identity: ConsensusIdentity,
        sender_node_id: ConsensusNodeId,
        family: ConsensusRpcFamily,
    ) -> Result<SessionMembershipEngineLease, SessionConsensusPeerError> {
        let state = Arc::clone(&self.state).read_owned().await;
        if identity != scope.binding.consensus_identity() || sender_node_id != scope.sender_node_id
        {
            return Err(SessionConsensusPeerError::ScopeMismatch);
        }

        let current_matches = manifest_matches_scope(&state.current, scope, &self.local_replica_id);
        let (pending_matches, pending_voting_admitted) =
            state.pending.as_ref().map_or((false, false), |pending| {
                (
                    manifest_matches_scope(&pending.manifest, scope, &self.local_replica_id),
                    pending.voting_admitted,
                )
            });
        let pending_engine_catchup = match family {
            ConsensusRpcFamily::Vote => pending_voting_admitted,
            ConsensusRpcFamily::AppendEntries | ConsensusRpcFamily::InstallSnapshot => true,
            ConsensusRpcFamily::ForwardMutation | ConsensusRpcFamily::ReadBarrier => false,
            _ => false,
        };
        if !(current_matches || pending_matches && pending_engine_catchup) {
            return Err(SessionConsensusPeerError::ScopeMismatch);
        }
        Ok(SessionMembershipEngineLease { _state: state })
    }

    pub(crate) async fn revalidate_bootstrap_scope(
        &self,
        scope: &SessionMembershipEngineScope,
    ) -> Result<SessionMembershipEngineLease, SessionConsensusPeerError> {
        let state = Arc::clone(&self.state).read_owned().await;
        let admitted = manifest_matches_scope(&state.current, scope, &self.local_replica_id)
            || state.pending.as_ref().is_some_and(|pending| {
                manifest_matches_scope(&pending.manifest, scope, &self.local_replica_id)
            });
        if !admitted {
            return Err(SessionConsensusPeerError::ScopeMismatch);
        }
        Ok(SessionMembershipEngineLease { _state: state })
    }
}

impl fmt::Debug for SessionMembershipAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionMembershipAdmission")
            .field("local_replica_id", &self.local_replica_id)
            .finish_non_exhaustive()
    }
}

pub(crate) struct SessionMembershipEngineScope {
    binding: LocalReplicaBinding,
    sender_replica_id: ReplicaId,
    sender_node_id: ConsensusNodeId,
    authenticated_spiffe: Option<SpiffeId>,
}

impl SessionMembershipEngineScope {
    pub(crate) const fn binding(&self) -> &LocalReplicaBinding {
        &self.binding
    }
}

pub(crate) struct SessionMembershipEngineLease {
    _state: OwnedRwLockReadGuard<MembershipAdmissionState>,
}

fn manifest_matches_scope(
    manifest: &SessionReplicationManifest,
    scope: &SessionMembershipEngineScope,
    local_replica_id: &ReplicaId,
) -> bool {
    manifest.consensus_identity() == scope.binding.consensus_identity()
        && manifest.consensus_node_id(local_replica_id)
            == Some(scope.binding.local_consensus_node_id())
        && manifest.consensus_node_id(&scope.sender_replica_id) == Some(scope.sender_node_id)
        && scope.authenticated_spiffe.as_ref().is_none_or(|actual| {
            manifest
                .member_spiffe_id(&scope.sender_replica_id)
                .is_some_and(|expected| expected.as_str() == actual.as_str())
        })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use opc_session_store::{
        QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
        ReplicaTlsIdentity, SessionConsensusClusterId,
    };

    use super::*;
    use crate::identity::{SessionClusterId, SessionConfigurationGeneration, SessionManifestError};

    fn replica_id(index: u16) -> ReplicaId {
        ReplicaId::new(format!("replica-{index}")).expect("test replica ID")
    }

    fn spiffe(index: u16) -> SpiffeId {
        SpiffeId::new(format!(
            "spiffe://test.example/tenant/test/ns/default/sa/session/nf/smf/instance/{index}"
        ))
        .expect("test SPIFFE ID")
    }

    fn descriptor(index: u16) -> QuorumReplicaDescriptor {
        descriptor_with_host(index, format!("replica-{index}.quorum.test.invalid"))
    }

    fn descriptor_with_host(index: u16, host: String) -> QuorumReplicaDescriptor {
        QuorumReplicaDescriptor::new(
            replica_id(index),
            ReplicaEndpoint::new(host, 7443).expect("test endpoint"),
            ReplicaTlsIdentity::new(spiffe(index).as_str()).expect("test TLS identity"),
            ReplicaFailureDomain::new(format!("zone-{index}")).expect("test failure domain"),
            ReplicaBackingIdentity::new(format!("disk-{index}")).expect("test backing identity"),
        )
    }

    fn manifest(epoch: u64, members: &[u16]) -> Arc<SessionReplicationManifest> {
        manifest_with_descriptors(
            epoch,
            members.iter().copied().map(descriptor).collect::<Vec<_>>(),
        )
    }

    fn manifest_with_descriptors(
        epoch: u64,
        descriptors: Vec<QuorumReplicaDescriptor>,
    ) -> Arc<SessionReplicationManifest> {
        manifest_in_cluster("membership-test", epoch, descriptors)
    }

    fn manifest_in_cluster(
        cluster: &str,
        epoch: u64,
        descriptors: Vec<QuorumReplicaDescriptor>,
    ) -> Arc<SessionReplicationManifest> {
        Arc::new(
            SessionReplicationManifest::try_new_with_epoch(
                SessionClusterId::new(cluster).expect("test cluster"),
                SessionConfigurationGeneration::new("legacy-test").expect("test generation"),
                SessionConfigurationEpoch::new(epoch).expect("test epoch"),
                descriptors,
            )
            .expect("test manifest"),
        )
    }

    fn transition_request(
        transition_id: SessionTopologyTransitionId,
        expected_epoch: u64,
        desired_epoch: u64,
        members: &[u16],
    ) -> SessionTopologyTransitionRequest {
        SessionTopologyTransitionRequest::try_new(
            transition_id,
            SessionConsensusClusterId::new("membership-test").expect("test cluster"),
            SessionConfigurationEpoch::new(expected_epoch).expect("expected epoch"),
            SessionConfigurationEpoch::new(desired_epoch).expect("desired epoch"),
            members.iter().copied().map(descriptor).collect(),
            Duration::from_secs(10),
        )
        .expect("test transition request")
    }

    async fn bootstrap(
        admission: &SessionMembershipAdmission,
        manifest: &Arc<SessionReplicationManifest>,
        sender: u16,
        local: u16,
        authenticated_spiffe: Option<&SpiffeId>,
    ) -> Result<SessionMembershipEngineScope, SessionConsensusPeerError> {
        admission
            .admit_engine_bootstrap(
                &replica_id(sender),
                &replica_id(local),
                manifest.consensus_identity(),
                manifest
                    .consensus_node_id(&replica_id(sender))
                    .expect("test sender node ID"),
                manifest
                    .consensus_node_id(&replica_id(local))
                    .expect("test local node ID"),
                authenticated_spiffe,
            )
            .await
    }

    #[tokio::test]
    async fn staged_three_to_five_to_three_admits_only_exact_engine_scope() {
        let three = manifest(1, &[1, 2, 3]);
        let five = manifest(2, &[1, 2, 3, 4, 5]);
        let reduced = manifest(3, &[2, 3, 4]);
        let admission = SessionMembershipAdmission::new(Arc::clone(&three), replica_id(3));
        let expand = SessionTopologyTransitionId::from_bytes([1; 16]);
        let expand_request = transition_request(expand, 1, 2, &[1, 2, 3, 4, 5]);

        assert_eq!(
            admission
                .stage_successor(&expand_request, Arc::clone(&five),)
                .await,
            Ok(SessionMembershipTransitionResult::Staged)
        );
        assert_eq!(
            admission
                .stage_successor(&expand_request, Arc::clone(&five),)
                .await,
            Ok(SessionMembershipTransitionResult::AlreadyStaged)
        );

        let current_scope = bootstrap(&admission, &three, 1, 3, Some(&spiffe(1)))
            .await
            .expect("current bootstrap");
        let pending_scope = bootstrap(&admission, &five, 4, 3, Some(&spiffe(4)))
            .await
            .expect("pending bootstrap");
        assert!(admission
            .revalidate_engine_scope(
                &current_scope,
                three.consensus_identity(),
                current_scope.sender_node_id,
                ConsensusRpcFamily::ForwardMutation,
            )
            .await
            .is_ok());
        assert!(admission
            .revalidate_engine_scope(
                &pending_scope,
                five.consensus_identity(),
                pending_scope.sender_node_id,
                ConsensusRpcFamily::AppendEntries,
            )
            .await
            .is_ok());
        assert_eq!(
            admission
                .revalidate_engine_scope(
                    &pending_scope,
                    five.consensus_identity(),
                    pending_scope.sender_node_id,
                    ConsensusRpcFamily::Vote,
                )
                .await
                .map(|_| ()),
            Err(SessionConsensusPeerError::ScopeMismatch),
            "a staged learner must not vote before catch-up promotion"
        );
        assert_eq!(
            admission
                .admit_successor_voting_after_catch_up_for_test(&expand_request)
                .await,
            Ok(SessionMembershipTransitionResult::VotingAdmitted)
        );
        assert_eq!(
            admission
                .admit_successor_voting_after_catch_up_for_test(&expand_request)
                .await,
            Ok(SessionMembershipTransitionResult::AlreadyVotingAdmitted)
        );
        assert!(admission.snapshot().await.pending_voting_admitted());
        assert!(admission
            .revalidate_engine_scope(
                &pending_scope,
                five.consensus_identity(),
                pending_scope.sender_node_id,
                ConsensusRpcFamily::Vote,
            )
            .await
            .is_ok());
        assert_eq!(
            admission
                .revalidate_engine_scope(
                    &pending_scope,
                    five.consensus_identity(),
                    pending_scope.sender_node_id,
                    ConsensusRpcFamily::ForwardMutation,
                )
                .await
                .map(|_| ()),
            Err(SessionConsensusPeerError::ScopeMismatch),
            "a learner may catch up but cannot acquire application authority"
        );

        assert_eq!(
            admission.finalize_successor_for_test(&expand_request).await,
            Ok(SessionMembershipTransitionResult::Finalized)
        );
        assert_eq!(
            admission
                .revalidate_engine_scope(
                    &current_scope,
                    three.consensus_identity(),
                    current_scope.sender_node_id,
                    ConsensusRpcFamily::AppendEntries,
                )
                .await
                .map(|_| ()),
            Err(SessionConsensusPeerError::ScopeMismatch),
            "an already-open old connection loses admission after finalize"
        );
        assert!(admission
            .revalidate_engine_scope(
                &pending_scope,
                five.consensus_identity(),
                pending_scope.sender_node_id,
                ConsensusRpcFamily::ForwardMutation,
            )
            .await
            .is_ok());

        let shrink = SessionTopologyTransitionId::from_bytes([2; 16]);
        let shrink_request = transition_request(shrink, 2, 3, &[2, 3, 4]);
        assert_eq!(
            admission
                .stage_successor(&shrink_request, Arc::clone(&reduced),)
                .await,
            Ok(SessionMembershipTransitionResult::Staged)
        );
        let reduced_scope = bootstrap(&admission, &reduced, 2, 3, Some(&spiffe(2)))
            .await
            .expect("reduced bootstrap");
        assert!(admission
            .revalidate_engine_scope(
                &reduced_scope,
                reduced.consensus_identity(),
                reduced_scope.sender_node_id,
                ConsensusRpcFamily::InstallSnapshot,
            )
            .await
            .is_ok());
        assert_eq!(
            admission.finalize_successor_for_test(&shrink_request).await,
            Err(SessionMembershipAdmissionError::SuccessorNotReady),
            "a staged learner cannot become current before catch-up admission"
        );
        let not_ready = admission.snapshot().await;
        assert_eq!(
            not_ready.pending_identity(),
            Some(reduced.consensus_identity())
        );
        assert!(!not_ready.pending_voting_admitted());
        assert_eq!(
            admission
                .admit_successor_voting_after_catch_up_for_test(&shrink_request)
                .await,
            Ok(SessionMembershipTransitionResult::VotingAdmitted)
        );
        assert_eq!(
            admission.finalize_successor_for_test(&shrink_request).await,
            Ok(SessionMembershipTransitionResult::Finalized)
        );
        assert_eq!(admission.snapshot().await.current_members(), 3);
        assert_eq!(admission.snapshot().await.current_epoch().get(), 3);
    }

    #[tokio::test]
    async fn abort_removes_pending_bootstrap_and_preserves_current() {
        let current = manifest(7, &[1, 2, 3]);
        let pending = manifest(8, &[1, 2, 3, 4, 5]);
        let admission = SessionMembershipAdmission::new(Arc::clone(&current), replica_id(2));
        let transition = SessionTopologyTransitionId::from_bytes([7; 16]);
        let request = transition_request(transition, 7, 8, &[1, 2, 3, 4, 5]);
        admission
            .stage_successor(&request, Arc::clone(&pending))
            .await
            .expect("stage successor");
        bootstrap(&admission, &pending, 4, 2, Some(&spiffe(4)))
            .await
            .expect("pending bootstrap before abort");

        assert_eq!(
            admission.abort_successor_for_test(&request).await,
            Ok(SessionMembershipTransitionResult::Aborted)
        );
        assert_eq!(
            admission.abort_successor_for_test(&request).await,
            Ok(SessionMembershipTransitionResult::AlreadyAborted)
        );
        assert_eq!(
            bootstrap(&admission, &pending, 4, 2, Some(&spiffe(4)))
                .await
                .map(|_| ()),
            Err(SessionConsensusPeerError::ScopeMismatch)
        );
        bootstrap(&admission, &current, 1, 2, Some(&spiffe(1)))
            .await
            .expect("current bootstrap survives abort");
    }

    #[tokio::test]
    async fn dynamic_admission_rejects_wrong_fqdn_scope_and_spiffe_identity() {
        let current = manifest(1, &[1, 2, 3]);
        let pending = manifest(2, &[1, 2, 3, 4, 5]);
        let mut changed_retained_descriptors = (1..=5).map(descriptor).collect::<Vec<_>>();
        changed_retained_descriptors[1] =
            descriptor_with_host(2, "renamed.quorum.test.invalid".to_owned());
        let changed_retained = manifest_with_descriptors(2, changed_retained_descriptors.clone());
        let changed_retained_request = SessionTopologyTransitionRequest::try_new(
            SessionTopologyTransitionId::from_bytes([30; 16]),
            SessionConsensusClusterId::new("membership-test").expect("test cluster"),
            SessionConfigurationEpoch::new(1).expect("expected epoch"),
            SessionConfigurationEpoch::new(2).expect("desired epoch"),
            changed_retained_descriptors,
            Duration::from_secs(10),
        )
        .expect("changed retained-member request");
        let mut wrong_descriptors = (1..=5).map(descriptor).collect::<Vec<_>>();
        wrong_descriptors[3] = descriptor_with_host(4, "alias.quorum.test.invalid".to_owned());
        let wrong_fqdn_scope = manifest_with_descriptors(2, wrong_descriptors);
        let admission = SessionMembershipAdmission::new(current, replica_id(3));
        assert_eq!(
            admission
                .stage_successor(&changed_retained_request, changed_retained)
                .await,
            Err(SessionMembershipAdmissionError::SuccessorManifestMismatch),
            "a retained member cannot silently change its endpoint or identity binding"
        );
        admission
            .stage_successor(
                &transition_request(
                    SessionTopologyTransitionId::from_bytes([3; 16]),
                    1,
                    2,
                    &[1, 2, 3, 4, 5],
                ),
                Arc::clone(&pending),
            )
            .await
            .expect("stage successor");

        assert_eq!(
            bootstrap(&admission, &wrong_fqdn_scope, 4, 3, Some(&spiffe(4)),)
                .await
                .map(|_| ()),
            Err(SessionConsensusPeerError::ScopeMismatch),
            "a descriptor FQDN change produces a different exact scope"
        );
        assert_eq!(
            bootstrap(&admission, &pending, 4, 3, Some(&spiffe(5)))
                .await
                .map(|_| ()),
            Err(SessionConsensusPeerError::Authentication),
            "a valid but wrong member SPIFFE identity must not be accepted"
        );
    }

    #[tokio::test]
    async fn stage_rejects_rebinding_the_current_listener_to_another_cluster() {
        let current = manifest_in_cluster(
            "current-membership-cluster",
            1,
            (1..=3).map(descriptor).collect(),
        );
        let successor = manifest_in_cluster(
            "different-membership-cluster",
            2,
            (1..=5).map(descriptor).collect(),
        );
        let request = SessionTopologyTransitionRequest::try_new(
            SessionTopologyTransitionId::from_bytes([41; 16]),
            SessionConsensusClusterId::new("different-membership-cluster")
                .expect("different cluster"),
            SessionConfigurationEpoch::new(1).expect("expected epoch"),
            SessionConfigurationEpoch::new(2).expect("desired epoch"),
            (1..=5).map(descriptor).collect(),
            Duration::from_secs(10),
        )
        .expect("cross-cluster-shaped request");
        let admission = SessionMembershipAdmission::new(current, replica_id(2));

        assert_eq!(
            admission.stage_successor(&request, successor).await,
            Err(SessionMembershipAdmissionError::CurrentManifestMismatch)
        );
        assert_eq!(
            admission.snapshot().await.pending_identity(),
            None,
            "a cluster-rebinding request must leave no staged admission"
        );
    }

    #[derive(Clone, Copy)]
    enum CrossManifestAlias {
        Endpoint,
        TlsIdentity,
        BackingIdentity,
    }

    fn aliased_replacement_descriptor(alias: CrossManifestAlias) -> QuorumReplicaDescriptor {
        let removed = descriptor(1);
        let replacement = descriptor(4);
        QuorumReplicaDescriptor::new(
            replacement.replica_id().clone(),
            match alias {
                CrossManifestAlias::Endpoint => removed.endpoint().clone(),
                CrossManifestAlias::TlsIdentity | CrossManifestAlias::BackingIdentity => {
                    replacement.endpoint().clone()
                }
            },
            match alias {
                CrossManifestAlias::TlsIdentity => removed.tls_identity().clone(),
                CrossManifestAlias::Endpoint | CrossManifestAlias::BackingIdentity => {
                    replacement.tls_identity().clone()
                }
            },
            replacement.failure_domain().clone(),
            match alias {
                CrossManifestAlias::BackingIdentity => removed.backing_identity().clone(),
                CrossManifestAlias::Endpoint | CrossManifestAlias::TlsIdentity => {
                    replacement.backing_identity().clone()
                }
            },
        )
    }

    async fn assert_cross_manifest_alias_rejected(alias: CrossManifestAlias) {
        let current = manifest(1, &[1, 2, 3]);
        let desired = vec![
            descriptor(2),
            descriptor(3),
            aliased_replacement_descriptor(alias),
        ];
        let successor = manifest_with_descriptors(2, desired.clone());
        let request = SessionTopologyTransitionRequest::try_new(
            SessionTopologyTransitionId::from_bytes([42; 16]),
            SessionConsensusClusterId::new("membership-test").expect("test cluster"),
            SessionConfigurationEpoch::new(1).expect("expected epoch"),
            SessionConfigurationEpoch::new(2).expect("desired epoch"),
            desired,
            Duration::from_secs(10),
        )
        .expect("individually valid successor request");
        let admission = SessionMembershipAdmission::new(current, replica_id(2));

        assert_eq!(
            admission.stage_successor(&request, successor).await,
            Err(SessionMembershipAdmissionError::JointManifestIdentityConflict)
        );
        assert!(admission.snapshot().await.pending_identity().is_none());
    }

    #[tokio::test]
    async fn stage_rejects_endpoint_tls_and_backing_aliases_across_joint_manifests() {
        assert_cross_manifest_alias_rejected(CrossManifestAlias::Endpoint).await;
        assert_cross_manifest_alias_rejected(CrossManifestAlias::TlsIdentity).await;
        assert_cross_manifest_alias_rejected(CrossManifestAlias::BackingIdentity).await;
    }

    #[tokio::test]
    async fn joining_local_replica_is_closed_until_its_successor_is_staged() {
        let current = manifest(1, &[1, 2, 3]);
        let pending = manifest(2, &[1, 2, 3, 4, 5]);
        let admission = SessionMembershipAdmission::new(current, replica_id(4));
        assert_eq!(
            bootstrap(&admission, &pending, 1, 4, Some(&spiffe(1)))
                .await
                .map(|_| ()),
            Err(SessionConsensusPeerError::ScopeMismatch)
        );
        admission
            .stage_successor(
                &transition_request(
                    SessionTopologyTransitionId::from_bytes([4; 16]),
                    1,
                    2,
                    &[1, 2, 3, 4, 5],
                ),
                Arc::clone(&pending),
            )
            .await
            .expect("stage joining successor");
        bootstrap(&admission, &pending, 1, 4, Some(&spiffe(1)))
            .await
            .expect("joining node bootstrap after staging");
    }

    #[tokio::test]
    async fn finalize_waits_for_an_admitted_call_and_then_fences_old_scope() {
        let current = manifest(1, &[1, 2, 3]);
        let pending = manifest(2, &[1, 2, 3, 4, 5]);
        let admission = SessionMembershipAdmission::new(Arc::clone(&current), replica_id(3));
        let transition = SessionTopologyTransitionId::from_bytes([5; 16]);
        let request = transition_request(transition, 1, 2, &[1, 2, 3, 4, 5]);
        admission
            .stage_successor(&request, pending)
            .await
            .expect("stage successor");
        admission
            .admit_successor_voting_after_catch_up_for_test(&request)
            .await
            .expect("admit successor voting after catch-up");
        let old_scope = bootstrap(&admission, &current, 1, 3, Some(&spiffe(1)))
            .await
            .expect("old bootstrap");
        let lease = admission
            .revalidate_engine_scope(
                &old_scope,
                current.consensus_identity(),
                old_scope.sender_node_id,
                ConsensusRpcFamily::AppendEntries,
            )
            .await
            .expect("admit in-flight call");

        let finalizer_admission = admission.clone();
        let finalizer_request = request.clone();
        let finalizer = tokio::spawn(async move {
            finalizer_admission
                .finalize_successor_for_test(&finalizer_request)
                .await
        });
        tokio::task::yield_now().await;
        assert!(
            !finalizer.is_finished(),
            "finalize must wait for an admitted handler lease"
        );
        drop(lease);
        assert_eq!(
            finalizer.await.expect("finalizer task"),
            Ok(SessionMembershipTransitionResult::Finalized)
        );
        assert_eq!(
            admission
                .revalidate_engine_scope(
                    &old_scope,
                    current.consensus_identity(),
                    old_scope.sender_node_id,
                    ConsensusRpcFamily::AppendEntries,
                )
                .await
                .map(|_| ()),
            Err(SessionConsensusPeerError::ScopeMismatch)
        );
    }

    #[tokio::test]
    async fn stale_conflicting_and_reused_transition_operations_fail_closed() {
        let current = manifest(1, &[1, 2, 3]);
        let pending = manifest(2, &[1, 2, 3, 4, 5]);
        let admission = SessionMembershipAdmission::new(current, replica_id(2));
        let first = SessionTopologyTransitionId::from_bytes([6; 16]);
        let other = SessionTopologyTransitionId::from_bytes([9; 16]);
        let request = transition_request(first, 1, 2, &[1, 2, 3, 4, 5]);
        let other_request = transition_request(other, 1, 2, &[1, 2, 3, 4, 5]);

        assert_eq!(
            admission
                .stage_successor(
                    &transition_request(first, 2, 3, &[1, 2, 3, 4, 5]),
                    manifest(3, &[1, 2, 3, 4, 5]),
                )
                .await,
            Err(SessionMembershipAdmissionError::Topology(
                SessionTopologyTransitionError::StaleEpoch
            ))
        );
        admission
            .stage_successor(&request, Arc::clone(&pending))
            .await
            .expect("stage successor");
        let same_id_different_digest = SessionTopologyTransitionRequest::try_new(
            first,
            SessionConsensusClusterId::new("membership-test").expect("test cluster"),
            SessionConfigurationEpoch::new(1).expect("expected epoch"),
            SessionConfigurationEpoch::new(2).expect("desired epoch"),
            (1..=5).map(descriptor).collect(),
            Duration::from_secs(11),
        )
        .expect("conflicting retry request");
        assert_eq!(
            admission
                .finalize_successor_for_test(&same_id_different_digest)
                .await,
            Err(SessionMembershipAdmissionError::Topology(
                SessionTopologyTransitionError::IdempotencyConflict
            )),
            "finalization requires both the transition ID and request digest"
        );
        assert_eq!(
            admission
                .stage_successor(&other_request, Arc::clone(&pending),)
                .await,
            Err(SessionMembershipAdmissionError::Topology(
                SessionTopologyTransitionError::TransitionInProgress
            ))
        );
        assert_eq!(
            admission.finalize_successor_for_test(&other_request).await,
            Err(SessionMembershipAdmissionError::Topology(
                SessionTopologyTransitionError::IdempotencyConflict
            ))
        );
        admission
            .admit_successor_voting_after_catch_up_for_test(&request)
            .await
            .expect("admit successor voting after catch-up");
        admission
            .finalize_successor_for_test(&request)
            .await
            .expect("finalize successor");
        assert_eq!(
            admission
                .stage_successor(&request, manifest(2, &[1, 2, 3, 4, 6]))
                .await,
            Err(SessionMembershipAdmissionError::SuccessorManifestMismatch),
            "an idempotent transition ID cannot mask a different manifest argument"
        );
        let epoch_three = manifest(3, &[2, 3, 4]);
        let reused_request = transition_request(first, 2, 3, &[2, 3, 4]);
        assert_eq!(
            admission
                .stage_successor(&reused_request, epoch_three)
                .await,
            Err(SessionMembershipAdmissionError::Topology(
                SessionTopologyTransitionError::IdempotencyConflict
            ))
        );

        let debug = format!("{admission:?} {first:?} {:?}", admission.snapshot().await);
        assert!(!debug.contains("spiffe://"));
        assert!(!debug.contains("quorum.test.invalid"));
        assert!(!debug.contains("06060606060606060606060606060606"));
    }

    #[test]
    fn malformed_successor_manifest_is_rejected_before_admission() {
        let duplicate = descriptor(1);
        let result = SessionReplicationManifest::try_new_with_epoch(
            SessionClusterId::new("membership-test").expect("test cluster"),
            SessionConfigurationGeneration::new("legacy-test").expect("test generation"),
            SessionConfigurationEpoch::new(2).expect("test epoch"),
            vec![duplicate.clone(), duplicate],
        );
        assert!(matches!(
            result,
            Err(SessionManifestError::DuplicateReplicaId)
        ));
    }
}
