//! Private Openraft transport adapter for the session consensus service.
//!
//! The authenticated transport carries only bounded, identity-scoped engine
//! RPCs. It deliberately does not implement any session-backend operation or
//! alternate replication/repair authority.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, RwLock};

use opc_consensus::engine::error::{
    InstallSnapshotError, PayloadTooLarge, RPCError, RaftError, RemoteError, Timeout, Unreachable,
};
use opc_consensus::engine::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use opc_consensus::engine::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use opc_consensus::engine::{EmptyNode, Membership, StoredMembership, Vote};
use opc_consensus::{decode_bounded, encode_bounded, ConsensusCodecError};
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use super::{
    SessionConsensusIdentity, SessionConsensusNodeId, SessionConsensusPeer,
    SessionConsensusPeerError, SessionConsensusRpcFamily, SessionConsensusRpcHandler,
    SessionConsensusWireRequest, SessionConsensusWireResponse, SessionRaft, SessionRaftTypeConfig,
    SESSION_CONSENSUS_SCHEMA_VERSION,
};
use crate::membership::{SessionTopologyTransitionDigest, SessionTopologyTransitionId};
use crate::topology::QUORUM_TOPOLOGY_MAX_MEMBERS;

type EngineRpcError<E = opc_consensus::engine::error::Infallible> =
    RPCError<SessionConsensusNodeId, EmptyNode, RaftError<SessionConsensusNodeId, E>>;
type SessionCurrentPeerSnapshot = (
    SessionConsensusIdentity,
    BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
);

/// Fail-closed construction error for the private Openraft network factory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum SessionRaftAdapterError {
    /// A peer was registered under a node ID different from its authenticated
    /// transport identity.
    #[error("session consensus peer node identity does not match its routing key")]
    PeerNodeIdMismatch,
    /// A dynamically staged peer did not prove the exact desired manifest.
    #[error("session consensus peer scope does not match the desired identity")]
    PeerScopeMismatch,
    /// A caller attempted to install the local node as its own remote peer.
    #[error("session consensus local node cannot be registered as a peer")]
    LocalNodeRegisteredAsPeer,
    /// Active and staged peers exceeded the topology admission bound.
    #[error("session consensus peer directory exceeds the membership bound")]
    PeerCapacityExceeded,
    /// A transition tried to mutate peer routing under a stale topology epoch.
    #[error("session consensus peer transition epoch is stale")]
    StalePeerTransition,
    /// A transition identity conflicted with already staged peer routing.
    #[error("session consensus peer transition conflicts with staged state")]
    PeerTransitionConflict,
    /// Current and desired peer scopes were not one valid epoch transition.
    #[error("session consensus peer transition scope is invalid")]
    InvalidPeerTransitionScope,
    /// The supplied desired peer set was incomplete or included another node.
    #[error("session consensus desired peer is not staged")]
    DesiredPeerMissing,
    /// A poisoned synchronization primitive made peer authority unknowable.
    #[error("session consensus peer directory is unavailable")]
    PeerDirectoryUnavailable,
}

#[derive(Clone)]
struct SessionRaftPeerRoute {
    identity: SessionConsensusIdentity,
    peer: Arc<dyn SessionConsensusPeer>,
}

struct SessionRaftStagedPeers {
    transition_id: SessionTopologyTransitionId,
    request_digest: SessionTopologyTransitionDigest,
    expected_epoch: opc_consensus::ConsensusConfigurationEpoch,
    desired_identity: SessionConsensusIdentity,
    desired_members: BTreeSet<SessionConsensusNodeId>,
    routes: BTreeMap<SessionConsensusNodeId, SessionRaftPeerRoute>,
    /// Vote traffic is forbidden until the exact joint membership is durably
    /// applied and the store issues its bound joint-commit proof.
    voting_admitted: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SessionRaftPeerTransitionTerminalKind {
    Aborted,
    Finalized,
}

struct SessionRaftPeerTransitionTerminal {
    transition_id: SessionTopologyTransitionId,
    request_digest: SessionTopologyTransitionDigest,
    expected_epoch: opc_consensus::ConsensusConfigurationEpoch,
    desired_identity: SessionConsensusIdentity,
    desired_members: BTreeSet<SessionConsensusNodeId>,
    kind: SessionRaftPeerTransitionTerminalKind,
}

struct SessionRaftPeerDirectoryState {
    current_identity: SessionConsensusIdentity,
    current_members: BTreeSet<SessionConsensusNodeId>,
    active: BTreeMap<SessionConsensusNodeId, SessionRaftPeerRoute>,
    staged: Option<SessionRaftStagedPeers>,
    terminal: Option<SessionRaftPeerTransitionTerminal>,
    last_applied_membership: Option<StoredMembership<SessionConsensusNodeId, EmptyNode>>,
    engine_admission_suspended: bool,
}

/// Bounded peer routing shared by all Openraft clients created for one node.
///
/// Openraft may retain a target client across a membership transition. The
/// client therefore resolves its authenticated peer handle for every call
/// instead of capturing the handle that happened to exist at construction.
/// Staged peers are engine-routable so learners can catch up, but callers must
/// explicitly finalize or abort the staged set.
#[derive(Clone)]
pub(crate) struct SessionRaftPeerDirectory {
    local_node_id: SessionConsensusNodeId,
    state: Arc<RwLock<SessionRaftPeerDirectoryState>>,
    membership_apply_fence: Arc<tokio::sync::RwLock<()>>,
}

impl SessionRaftPeerDirectory {
    fn try_new(
        identity: SessionConsensusIdentity,
        local_node_id: SessionConsensusNodeId,
        current_members: BTreeSet<SessionConsensusNodeId>,
        peers: BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
    ) -> Result<Self, SessionRaftAdapterError> {
        validate_peer_map(local_node_id, &peers)?;
        validate_desired_peer_map(local_node_id, &current_members, &peers)?;
        validate_peer_count(current_members.len())?;
        let active = peers
            .into_iter()
            .map(|(node_id, peer)| (node_id, SessionRaftPeerRoute { identity, peer }))
            .collect();
        Ok(Self {
            local_node_id,
            state: Arc::new(RwLock::new(SessionRaftPeerDirectoryState {
                current_identity: identity,
                current_members,
                active,
                staged: None,
                terminal: None,
                last_applied_membership: None,
                engine_admission_suspended: false,
            })),
            membership_apply_fence: Arc::new(tokio::sync::RwLock::new(())),
        })
    }

    fn try_new_candidate(
        identity: SessionConsensusIdentity,
        local_node_id: SessionConsensusNodeId,
        current_members: BTreeSet<SessionConsensusNodeId>,
    ) -> Result<Self, SessionRaftAdapterError> {
        if current_members.contains(&local_node_id) {
            return Err(SessionRaftAdapterError::InvalidPeerTransitionScope);
        }
        validate_peer_count(current_members.len())?;
        Ok(Self {
            local_node_id,
            state: Arc::new(RwLock::new(SessionRaftPeerDirectoryState {
                current_identity: identity,
                current_members,
                active: BTreeMap::new(),
                staged: None,
                terminal: None,
                last_applied_membership: None,
                engine_admission_suspended: false,
            })),
            membership_apply_fence: Arc::new(tokio::sync::RwLock::new(())),
        })
    }

    /// Stage authenticated peers before Openraft admits them as learners.
    ///
    /// Repeating the same transition and authenticated topology binding is
    /// idempotent even when a transport adapter reconstructed its `Arc` handle.
    /// A different transition cannot overwrite staged routing.
    pub(crate) fn stage(
        &self,
        transition_id: SessionTopologyTransitionId,
        request_digest: SessionTopologyTransitionDigest,
        expected_epoch: opc_consensus::ConsensusConfigurationEpoch,
        desired_identity: SessionConsensusIdentity,
        desired_members: BTreeSet<SessionConsensusNodeId>,
        peers: BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
    ) -> Result<(), SessionRaftAdapterError> {
        validate_peer_map(self.local_node_id, &peers)?;
        validate_desired_peer_map(self.local_node_id, &desired_members, &peers)?;
        if peers
            .values()
            .any(|peer| peer.scope_identity() != Some(desired_identity))
        {
            return Err(SessionRaftAdapterError::PeerScopeMismatch);
        }
        validate_peer_count(desired_members.len())?;
        let mut state = self
            .state
            .write()
            .map_err(|_| SessionRaftAdapterError::PeerDirectoryUnavailable)?;
        validate_peer_transition_scope(state.current_identity, expected_epoch, desired_identity)?;
        if state.current_members == desired_members {
            return Err(SessionRaftAdapterError::InvalidPeerTransitionScope);
        }

        if let Some(terminal) = state.terminal.as_ref() {
            if transition_matches(
                terminal,
                transition_id,
                request_digest,
                expected_epoch,
                desired_identity,
                &desired_members,
            ) {
                return Err(SessionRaftAdapterError::PeerTransitionConflict);
            }
        }

        match state.staged.as_mut() {
            Some(staged)
                if staged.transition_id == transition_id
                    && staged.request_digest == request_digest
                    && staged.expected_epoch == expected_epoch
                    && staged.desired_identity == desired_identity
                    && staged.desired_members == desired_members =>
            {
                if !same_peer_bindings(&staged.routes, &peers) {
                    return Err(SessionRaftAdapterError::PeerTransitionConflict);
                }
            }
            Some(_) => return Err(SessionRaftAdapterError::PeerTransitionConflict),
            None => {
                let routes = peers
                    .into_iter()
                    .map(|(node_id, peer)| {
                        (
                            node_id,
                            SessionRaftPeerRoute {
                                identity: desired_identity,
                                peer,
                            },
                        )
                    })
                    .collect();
                state.staged = Some(SessionRaftStagedPeers {
                    transition_id,
                    request_digest,
                    expected_epoch,
                    desired_identity,
                    desired_members,
                    routes,
                    voting_admitted: false,
                });
            }
        }
        promote_applied_uniform_membership(&mut state);
        Ok(())
    }

    /// Remove exact process-local routes before a durable Prepare exists.
    ///
    /// This is deliberately distinct from `abort_staged`: it records no
    /// terminal outcome and refuses to remove routes after successor voting
    /// admission. The store coordinator supplies the durable-absence proof.
    pub(crate) fn unstage_before_prepare(
        &self,
        transition_id: SessionTopologyTransitionId,
        request_digest: SessionTopologyTransitionDigest,
        expected_epoch: opc_consensus::ConsensusConfigurationEpoch,
    ) -> Result<(), SessionRaftAdapterError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| SessionRaftAdapterError::PeerDirectoryUnavailable)?;
        if state.terminal.as_ref().is_some_and(|terminal| {
            terminal.transition_id == transition_id
                && terminal.request_digest == request_digest
                && terminal.expected_epoch == expected_epoch
        }) {
            return Err(SessionRaftAdapterError::PeerTransitionConflict);
        }
        let Some(staged) = state.staged.take() else {
            return Ok(());
        };
        if staged.transition_id != transition_id
            || staged.request_digest != request_digest
            || staged.expected_epoch != expected_epoch
            || staged.voting_admitted
        {
            state.staged = Some(staged);
            return Err(SessionRaftAdapterError::PeerTransitionConflict);
        }
        Ok(())
    }

    /// Admit staged successor Vote RPCs after exact durable joint membership.
    ///
    /// Staging alone deliberately permits only log replication and snapshot
    /// installation. The membership coordinator calls this method only after
    /// consuming a store-issued proof bound to the exact applied joint
    /// membership.
    pub(crate) fn admit_staged_voting(
        &self,
        transition_id: SessionTopologyTransitionId,
        request_digest: SessionTopologyTransitionDigest,
        expected_epoch: opc_consensus::ConsensusConfigurationEpoch,
    ) -> Result<(), SessionRaftAdapterError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| SessionRaftAdapterError::PeerDirectoryUnavailable)?;
        if state.terminal.as_ref().is_some_and(|terminal| {
            terminal.transition_id == transition_id
                && terminal.request_digest == request_digest
                && terminal.expected_epoch == expected_epoch
                && terminal.kind == SessionRaftPeerTransitionTerminalKind::Finalized
        }) {
            return Ok(());
        }
        let staged = state
            .staged
            .as_mut()
            .ok_or(SessionRaftAdapterError::PeerTransitionConflict)?;
        if staged.transition_id != transition_id
            || staged.request_digest != request_digest
            || staged.expected_epoch != expected_epoch
        {
            return Err(SessionRaftAdapterError::PeerTransitionConflict);
        }
        staged.voting_admitted = true;
        Ok(())
    }

    /// Discard every candidate that has not become part of active membership.
    pub(crate) fn abort_staged(
        &self,
        transition_id: SessionTopologyTransitionId,
        request_digest: SessionTopologyTransitionDigest,
        expected_epoch: opc_consensus::ConsensusConfigurationEpoch,
    ) -> Result<(), SessionRaftAdapterError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| SessionRaftAdapterError::PeerDirectoryUnavailable)?;
        if let Some(terminal) = state.terminal.as_ref() {
            if terminal.transition_id == transition_id
                && terminal.request_digest == request_digest
                && terminal.expected_epoch == expected_epoch
                && terminal.kind == SessionRaftPeerTransitionTerminalKind::Aborted
            {
                return Ok(());
            }
        }
        if state.current_identity.configuration_epoch() != expected_epoch {
            return Err(SessionRaftAdapterError::StalePeerTransition);
        }
        let staged = match state.staged.take() {
            Some(staged)
                if staged.transition_id == transition_id
                    && staged.request_digest == request_digest
                    && staged.expected_epoch == expected_epoch =>
            {
                staged
            }
            Some(staged) => {
                state.staged = Some(staged);
                return Err(SessionRaftAdapterError::PeerTransitionConflict);
            }
            None => return Err(SessionRaftAdapterError::PeerTransitionConflict),
        };
        state.terminal = Some(SessionRaftPeerTransitionTerminal {
            transition_id,
            request_digest,
            expected_epoch,
            desired_identity: staged.desired_identity,
            desired_members: staged.desired_members,
            kind: SessionRaftPeerTransitionTerminalKind::Aborted,
        });
        Ok(())
    }

    /// Atomically publish the desired remote peer set and retire all others.
    ///
    /// Removed voters remain engine-routable in `active` until this method is
    /// called after uniform membership commits. Every desired peer must already
    /// be active or staged.
    pub(crate) fn finalize(
        &self,
        transition_id: SessionTopologyTransitionId,
        request_digest: SessionTopologyTransitionDigest,
        expected_epoch: opc_consensus::ConsensusConfigurationEpoch,
        desired_members: &BTreeSet<SessionConsensusNodeId>,
    ) -> Result<(), SessionRaftAdapterError> {
        validate_peer_count(desired_members.len())?;

        let mut state = self
            .state
            .write()
            .map_err(|_| SessionRaftAdapterError::PeerDirectoryUnavailable)?;
        if let Some(terminal) = state.terminal.as_ref() {
            if terminal.transition_id == transition_id
                && terminal.request_digest == request_digest
                && terminal.expected_epoch == expected_epoch
                && &terminal.desired_members == desired_members
                && terminal.kind == SessionRaftPeerTransitionTerminalKind::Finalized
                && state.current_identity == terminal.desired_identity
            {
                return Ok(());
            }
        }
        if state.current_identity.configuration_epoch() != expected_epoch {
            return Err(SessionRaftAdapterError::StalePeerTransition);
        }
        let staged = state
            .staged
            .take()
            .ok_or(SessionRaftAdapterError::PeerTransitionConflict)?;
        if staged.transition_id != transition_id
            || staged.request_digest != request_digest
            || staged.expected_epoch != expected_epoch
            || &staged.desired_members != desired_members
        {
            state.staged = Some(staged);
            return Err(SessionRaftAdapterError::PeerTransitionConflict);
        }
        publish_staged_successor(&mut state, staged);
        Ok(())
    }

    fn resolve_engine(
        &self,
        target: SessionConsensusNodeId,
    ) -> Result<Option<SessionRaftPeerRoute>, SessionRaftAdapterError> {
        self.resolve_engine_for(target, SessionConsensusRpcFamily::AppendEntries)
    }

    fn resolve_engine_for(
        &self,
        target: SessionConsensusNodeId,
        family: SessionConsensusRpcFamily,
    ) -> Result<Option<SessionRaftPeerRoute>, SessionRaftAdapterError> {
        let state = self
            .state
            .read()
            .map_err(|_| SessionRaftAdapterError::PeerDirectoryUnavailable)?;
        if state.engine_admission_suspended {
            return Ok(None);
        }
        let active = state.active.get(&target);
        let staged = state
            .staged
            .as_ref()
            .filter(|staged| family != SessionConsensusRpcFamily::Vote || staged.voting_admitted)
            .and_then(|staged| staged.routes.get(&target));
        let route = if state.current_members.contains(&self.local_node_id) {
            active.or(staged)
        } else {
            // A joining candidate may use staged successor routes before it
            // becomes a voter. Once uniform promotion removes the local node,
            // `staged` is consumed and no active route remains authoritative.
            staged
        };
        Ok(route
            .filter(|route| route.peer.node_id() == target)
            .cloned())
    }

    fn authorizes_engine(
        &self,
        sender: SessionConsensusNodeId,
        identity: SessionConsensusIdentity,
        family: SessionConsensusRpcFamily,
    ) -> bool {
        self.state.read().is_ok_and(|state| {
            !state.engine_admission_suspended
                && ((state.current_members.contains(&self.local_node_id)
                    && state.active.get(&sender).is_some_and(|route| {
                        route.identity == identity && route.peer.node_id() == sender
                    }))
                    || state.staged.as_ref().is_some_and(|staged| {
                        (family != SessionConsensusRpcFamily::Vote || staged.voting_admitted)
                            && staged.routes.get(&sender).is_some_and(|route| {
                                route.identity == identity && route.peer.node_id() == sender
                            })
                    }))
        })
    }

    pub(crate) fn current_scope(
        &self,
    ) -> Result<(SessionConsensusIdentity, BTreeSet<SessionConsensusNodeId>), SessionRaftAdapterError>
    {
        let state = self
            .state
            .read()
            .map_err(|_| SessionRaftAdapterError::PeerDirectoryUnavailable)?;
        Ok((state.current_identity, state.current_members.clone()))
    }

    /// Snapshot every exact current-scope remote route for a bounded control
    /// barrier. This is used before Prepare to prove that removed-only current
    /// voters staged the same transition and can later fence their transport.
    pub(crate) fn current_peers(
        &self,
    ) -> Result<SessionCurrentPeerSnapshot, SessionRaftAdapterError> {
        let state = self
            .state
            .read()
            .map_err(|_| SessionRaftAdapterError::PeerDirectoryUnavailable)?;
        let peers = state
            .current_members
            .iter()
            .copied()
            .filter(|node_id| *node_id != self.local_node_id)
            .map(|node_id| {
                let route = state
                    .active
                    .get(&node_id)
                    .filter(|route| {
                        route.identity == state.current_identity && route.peer.node_id() == node_id
                    })
                    .ok_or(SessionRaftAdapterError::DesiredPeerMissing)?;
                Ok((node_id, Arc::clone(&route.peer)))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        Ok((state.current_identity, peers))
    }

    pub(crate) fn resolve_application(
        &self,
        target: SessionConsensusNodeId,
    ) -> Result<(SessionConsensusIdentity, Arc<dyn SessionConsensusPeer>), SessionRaftAdapterError>
    {
        let state = self
            .state
            .read()
            .map_err(|_| SessionRaftAdapterError::PeerDirectoryUnavailable)?;
        if !state.current_members.contains(&self.local_node_id)
            || !state.current_members.contains(&target)
        {
            return Err(SessionRaftAdapterError::DesiredPeerMissing);
        }
        let route = state
            .active
            .get(&target)
            .filter(|route| {
                route.identity == state.current_identity && route.peer.node_id() == target
            })
            .ok_or(SessionRaftAdapterError::DesiredPeerMissing)?;
        Ok((route.identity, Arc::clone(&route.peer)))
    }

    /// Reconcile engine routing with the membership applied by the local
    /// Openraft state machine.
    ///
    /// Exact desired-uniform application atomically publishes staged routes
    /// and retires predecessor routes. The state-machine adapter invokes this
    /// before reporting application complete, so a delayed process-level
    /// transport-finalization callback cannot leave cached predecessor engine
    /// RPCs admitted. Remembering the last applied membership also closes the
    /// startup ordering where Openraft restores state before durable staged
    /// routes are reconstructed.
    pub(crate) fn observe_applied_membership(
        &self,
        membership: &StoredMembership<SessionConsensusNodeId, EmptyNode>,
    ) -> Result<(), SessionRaftAdapterError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| SessionRaftAdapterError::PeerDirectoryUnavailable)?;
        state.last_applied_membership = Some(membership.clone());
        state.engine_admission_suspended = membership.log_id().is_some()
            && is_uniform_membership_different_from(
                membership.membership(),
                &state.current_members,
            );
        promote_applied_uniform_membership(&mut state);
        Ok(())
    }

    /// Serialize one durable membership apply against per-RPC engine
    /// authorization and cached outbound route resolution.
    ///
    /// The state-machine adapter acquires this guard before locking SQLite and
    /// beginning the synchronous apply transaction. That lock order lets the
    /// writer drain engine RPCs that may still be waiting on SQLite without
    /// deadlocking the apply path. It promotes exact desired-uniform routes
    /// before releasing the guard, so every engine RPC is ordered either before
    /// the durable cutover or after predecessor revocation.
    pub(crate) async fn begin_membership_apply(&self) -> tokio::sync::OwnedRwLockWriteGuard<()> {
        Arc::clone(&self.membership_apply_fence).write_owned().await
    }

    async fn begin_engine_rpc(&self) -> tokio::sync::OwnedRwLockReadGuard<()> {
        Arc::clone(&self.membership_apply_fence).read_owned().await
    }

    pub(crate) fn requires_uniform_membership_fence(
        &self,
        membership: &Membership<SessionConsensusNodeId, EmptyNode>,
    ) -> bool {
        self.state.read().is_ok_and(|state| {
            is_uniform_membership_different_from(membership, &state.current_members)
                || state.staged.as_ref().is_some_and(|staged| {
                    is_exact_uniform_membership(membership, &staged.desired_members)
                })
        })
    }

    fn summary(&self) -> Option<(SessionConsensusIdentity, usize, usize)> {
        self.state.read().ok().map(|state| {
            (
                state.current_identity,
                state.active.len(),
                state
                    .staged
                    .as_ref()
                    .map_or(0, |staged| staged.routes.len()),
            )
        })
    }
}

fn promote_applied_uniform_membership(state: &mut SessionRaftPeerDirectoryState) {
    let Some(staged) = state.staged.as_ref() else {
        return;
    };
    let Some(membership) = state.last_applied_membership.as_ref() else {
        return;
    };
    let is_exact_uniform = membership.log_id().is_some()
        && is_exact_uniform_membership(membership.membership(), &staged.desired_members);
    if !is_exact_uniform {
        return;
    }

    if let Some(staged) = state.staged.take() {
        publish_staged_successor(state, staged);
    }
}

fn is_exact_uniform_membership(
    membership: &Membership<SessionConsensusNodeId, EmptyNode>,
    desired_members: &BTreeSet<SessionConsensusNodeId>,
) -> bool {
    let configured = membership.get_joint_config();
    let nodes = membership
        .nodes()
        .map(|(node_id, _)| *node_id)
        .collect::<BTreeSet<_>>();
    configured.len() == 1
        && configured.first() == Some(desired_members)
        && membership.learner_ids().next().is_none()
        && nodes == *desired_members
}

fn is_uniform_membership_different_from(
    membership: &Membership<SessionConsensusNodeId, EmptyNode>,
    current_members: &BTreeSet<SessionConsensusNodeId>,
) -> bool {
    let configured = membership.get_joint_config();
    configured.len() == 1
        && membership.learner_ids().next().is_none()
        && configured
            .first()
            .is_some_and(|voters| voters != current_members)
}

fn publish_staged_successor(
    state: &mut SessionRaftPeerDirectoryState,
    staged: SessionRaftStagedPeers,
) {
    let terminal = SessionRaftPeerTransitionTerminal {
        transition_id: staged.transition_id,
        request_digest: staged.request_digest,
        expected_epoch: staged.expected_epoch,
        desired_identity: staged.desired_identity,
        desired_members: staged.desired_members.clone(),
        kind: SessionRaftPeerTransitionTerminalKind::Finalized,
    };
    state.current_identity = staged.desired_identity;
    state.current_members = staged.desired_members;
    state.active = staged.routes;
    state.terminal = Some(terminal);
    state.engine_admission_suspended = false;
}

impl fmt::Debug for SessionRaftPeerDirectory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("SessionRaftPeerDirectory");
        debug.field("local_node_id", &self.local_node_id);
        match self.summary() {
            Some((current_identity, active, staged)) => {
                debug.field("current_identity", &current_identity);
                debug.field("active_peer_count", &active);
                debug.field("staged_peer_count", &staged);
            }
            None => {
                debug.field("state", &"<unavailable>");
            }
        }
        debug.finish()
    }
}

fn validate_peer_map(
    local_node_id: SessionConsensusNodeId,
    peers: &BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
) -> Result<(), SessionRaftAdapterError> {
    if peers.contains_key(&local_node_id) {
        return Err(SessionRaftAdapterError::LocalNodeRegisteredAsPeer);
    }
    if peers
        .iter()
        .any(|(node_id, peer)| peer.node_id() != *node_id)
    {
        return Err(SessionRaftAdapterError::PeerNodeIdMismatch);
    }
    Ok(())
}

fn validate_desired_peer_map(
    local_node_id: SessionConsensusNodeId,
    desired_members: &BTreeSet<SessionConsensusNodeId>,
    peers: &BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
) -> Result<(), SessionRaftAdapterError> {
    let expected_remotes = desired_members
        .iter()
        .copied()
        .filter(|node_id| *node_id != local_node_id)
        .collect::<BTreeSet<_>>();
    if peers.keys().copied().collect::<BTreeSet<_>>() != expected_remotes {
        return Err(SessionRaftAdapterError::DesiredPeerMissing);
    }
    Ok(())
}

fn same_peer_bindings(
    staged: &BTreeMap<SessionConsensusNodeId, SessionRaftPeerRoute>,
    peers: &BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
) -> bool {
    staged.len() == peers.len()
        && staged.iter().all(|(node_id, route)| {
            peers.get(node_id).is_some_and(|peer| {
                peer.node_id() == *node_id && peer.scope_identity() == Some(route.identity)
            })
        })
}

fn transition_matches(
    terminal: &SessionRaftPeerTransitionTerminal,
    transition_id: SessionTopologyTransitionId,
    request_digest: SessionTopologyTransitionDigest,
    expected_epoch: opc_consensus::ConsensusConfigurationEpoch,
    desired_identity: SessionConsensusIdentity,
    desired_members: &BTreeSet<SessionConsensusNodeId>,
) -> bool {
    terminal.transition_id == transition_id
        && terminal.request_digest == request_digest
        && terminal.expected_epoch == expected_epoch
        && terminal.desired_identity == desired_identity
        && terminal.desired_members == *desired_members
}

fn validate_peer_count(remote_peer_count: usize) -> Result<(), SessionRaftAdapterError> {
    if remote_peer_count > QUORUM_TOPOLOGY_MAX_MEMBERS {
        Err(SessionRaftAdapterError::PeerCapacityExceeded)
    } else {
        Ok(())
    }
}

fn validate_peer_transition_scope(
    current_identity: SessionConsensusIdentity,
    expected_epoch: opc_consensus::ConsensusConfigurationEpoch,
    desired_identity: SessionConsensusIdentity,
) -> Result<(), SessionRaftAdapterError> {
    if current_identity.configuration_epoch() != expected_epoch {
        return Err(SessionRaftAdapterError::StalePeerTransition);
    }
    let desired_epoch = expected_epoch
        .get()
        .checked_add(1)
        .ok_or(SessionRaftAdapterError::InvalidPeerTransitionScope)?;
    if desired_identity.cluster_id() != current_identity.cluster_id()
        || desired_identity.configuration_epoch().get() != desired_epoch
    {
        return Err(SessionRaftAdapterError::InvalidPeerTransitionScope);
    }
    Ok(())
}

/// Openraft network factory backed exclusively by consensus-only peers.
#[derive(Clone)]
pub(crate) struct SessionRaftNetworkFactory {
    local_node_id: SessionConsensusNodeId,
    peer_directory: SessionRaftPeerDirectory,
}

impl SessionRaftNetworkFactory {
    /// Bind the engine network to one immutable cluster scope and canonical
    /// node-ID routing table.
    pub(crate) fn try_new(
        identity: SessionConsensusIdentity,
        local_node_id: SessionConsensusNodeId,
        current_members: BTreeSet<SessionConsensusNodeId>,
        peers: BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
    ) -> Result<Self, SessionRaftAdapterError> {
        Ok(Self {
            local_node_id,
            peer_directory: SessionRaftPeerDirectory::try_new(
                identity,
                local_node_id,
                current_members,
                peers,
            )?,
        })
    }

    /// Bind a joining learner to predecessor metadata without granting it any
    /// predecessor-scope outbound route.
    pub(crate) fn try_new_candidate(
        current_identity: SessionConsensusIdentity,
        local_node_id: SessionConsensusNodeId,
        current_members: BTreeSet<SessionConsensusNodeId>,
    ) -> Result<Self, SessionRaftAdapterError> {
        Ok(Self {
            local_node_id,
            peer_directory: SessionRaftPeerDirectory::try_new_candidate(
                current_identity,
                local_node_id,
                current_members,
            )?,
        })
    }

    /// Shared dynamic directory used by the membership transition driver.
    pub(crate) fn peer_directory(&self) -> SessionRaftPeerDirectory {
        self.peer_directory.clone()
    }
}

impl fmt::Debug for SessionRaftNetworkFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRaftNetworkFactory")
            .field("local_node_id", &self.local_node_id)
            .field("peer_directory", &self.peer_directory)
            .finish()
    }
}

impl RaftNetworkFactory<SessionRaftTypeConfig> for SessionRaftNetworkFactory {
    type Network = SessionRaftNetwork;

    async fn new_client(
        &mut self,
        target: SessionConsensusNodeId,
        _node: &EmptyNode,
    ) -> Self::Network {
        SessionRaftNetwork {
            local_node_id: self.local_node_id,
            target,
            peer_directory: self.peer_directory.clone(),
        }
    }
}

/// One target-bound private Openraft connection.
pub(crate) struct SessionRaftNetwork {
    local_node_id: SessionConsensusNodeId,
    target: SessionConsensusNodeId,
    peer_directory: SessionRaftPeerDirectory,
}

impl fmt::Debug for SessionRaftNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRaftNetwork")
            .field("local_node_id", &self.local_node_id)
            .field("target", &self.target)
            .field(
                "peer_configured",
                &self
                    .peer_directory
                    .resolve_engine(self.target)
                    .ok()
                    .flatten()
                    .is_some(),
            )
            .finish()
    }
}

impl SessionRaftNetwork {
    async fn call<Resp, E>(
        &self,
        family: SessionConsensusRpcFamily,
        action: opc_consensus::engine::RPCTypes,
        payload: Vec<u8>,
        option: RPCOption,
    ) -> Result<Resp, EngineRpcError<E>>
    where
        Resp: DeserializeOwned,
        E: std::error::Error + DeserializeOwned,
    {
        // Keep the route-generation permit for the complete peer call. A
        // uniform apply waits for all predecessor-scoped calls already in
        // flight before publishing successor routes.
        let _engine_rpc = self.peer_directory.begin_engine_rpc().await;
        let route = self
            .peer_directory
            .resolve_engine_for(self.target, family)
            .map_err(|_| EngineRpcError::Unreachable(Unreachable::new(&PeerDirectoryUnavailable)))?
            .ok_or_else(|| EngineRpcError::Unreachable(Unreachable::new(&MissingConsensusPeer)))?;
        let peer = route.peer;
        if peer.node_id() != self.target {
            return Err(EngineRpcError::Unreachable(Unreachable::new(
                &PeerIdentityChanged,
            )));
        }

        let wire = SessionConsensusWireRequest::try_new(
            route.identity,
            self.local_node_id,
            family,
            payload,
        )
        .map_err(|error| EngineRpcError::Unreachable(Unreachable::new(&error)))?;

        let hard_ttl = option.hard_ttl();
        let response = match peer.call_with_timeout(wire, option.soft_ttl()).await {
            Err(error) => return Err(map_peer_error(error, action, self, hard_ttl)),
            Ok(response) => response,
        };

        response
            .validate()
            .map_err(|error| EngineRpcError::Unreachable(Unreachable::new(&error)))?;
        let payload = response
            .result
            .map_err(|error| map_peer_error(error, action, self, hard_ttl))?;
        let result: Result<Resp, RaftError<SessionConsensusNodeId, E>> = decode_bounded(&payload)
            .map_err(|error| {
            EngineRpcError::Unreachable(Unreachable::new(&CodecTransportError(error)))
        })?;
        result.map_err(|error| EngineRpcError::RemoteError(RemoteError::new(self.target, error)))
    }

    async fn append(
        &self,
        request: &AppendEntriesRequest<SessionRaftTypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<SessionConsensusNodeId>, EngineRpcError> {
        let entry_count = request.entries.len();
        let payload = match encode_bounded(request) {
            Ok(payload) => payload,
            Err(ConsensusCodecError::TooLarge) => {
                if let Some(entries_hint) = append_entries_split_hint(entry_count) {
                    return Err(EngineRpcError::PayloadTooLarge(
                        PayloadTooLarge::new_entries_hint(entries_hint),
                    ));
                }
                return Err(EngineRpcError::Unreachable(Unreachable::new(
                    &CodecTransportError(ConsensusCodecError::TooLarge),
                )));
            }
            Err(error) => {
                return Err(EngineRpcError::Unreachable(Unreachable::new(
                    &CodecTransportError(error),
                )));
            }
        };
        self.call(
            SessionConsensusRpcFamily::AppendEntries,
            opc_consensus::engine::RPCTypes::AppendEntries,
            payload,
            option,
        )
        .await
    }
}

fn append_entries_split_hint(entry_count: usize) -> Option<u64> {
    (entry_count > 1).then(|| u64::try_from((entry_count / 2).max(1)).unwrap_or(u64::MAX))
}

impl RaftNetwork<SessionRaftTypeConfig> for SessionRaftNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<SessionRaftTypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<SessionConsensusNodeId>, EngineRpcError> {
        self.append(&rpc, option).await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<SessionRaftTypeConfig>,
        option: RPCOption,
    ) -> Result<InstallSnapshotResponse<SessionConsensusNodeId>, EngineRpcError<InstallSnapshotError>>
    {
        let payload = encode_bounded(&rpc).map_err(|error| {
            EngineRpcError::Unreachable(Unreachable::new(&CodecTransportError(error)))
        })?;
        self.call(
            SessionConsensusRpcFamily::InstallSnapshot,
            opc_consensus::engine::RPCTypes::InstallSnapshot,
            payload,
            option,
        )
        .await
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<SessionConsensusNodeId>,
        option: RPCOption,
    ) -> Result<VoteResponse<SessionConsensusNodeId>, EngineRpcError> {
        let payload = encode_bounded(&rpc).map_err(|error| {
            EngineRpcError::Unreachable(Unreachable::new(&CodecTransportError(error)))
        })?;
        self.call(
            SessionConsensusRpcFamily::Vote,
            opc_consensus::engine::RPCTypes::Vote,
            payload,
            option,
        )
        .await
    }
}

fn map_peer_error<E>(
    error: SessionConsensusPeerError,
    action: opc_consensus::engine::RPCTypes,
    network: &SessionRaftNetwork,
    ttl: std::time::Duration,
) -> EngineRpcError<E>
where
    E: std::error::Error,
{
    match error {
        SessionConsensusPeerError::Timeout => EngineRpcError::Timeout(Timeout {
            action,
            id: network.local_node_id,
            target: network.target,
            timeout: ttl,
        }),
        _ => EngineRpcError::Unreachable(Unreachable::new(&error)),
    }
}

/// Engine-only inbound RPC handler. SDK-owned command forwarding and read
/// barriers are composed by the coordinator outside this type.
#[derive(Clone)]
pub(crate) struct SessionRaftRpcHandler {
    raft: SessionRaft,
    peer_directory: SessionRaftPeerDirectory,
    local_node_id: SessionConsensusNodeId,
}

impl SessionRaftRpcHandler {
    pub(crate) fn new(
        raft: SessionRaft,
        peer_directory: SessionRaftPeerDirectory,
        local_node_id: SessionConsensusNodeId,
    ) -> Self {
        Self {
            raft,
            peer_directory,
            local_node_id,
        }
    }
}

impl fmt::Debug for SessionRaftRpcHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRaftRpcHandler")
            .field("peer_directory", &self.peer_directory)
            .field("local_node_id", &self.local_node_id)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl SessionConsensusRpcHandler for SessionRaftRpcHandler {
    async fn handle(
        &self,
        authenticated_sender: SessionConsensusNodeId,
        request: SessionConsensusWireRequest,
    ) -> SessionConsensusWireResponse {
        if let Err(error) = validate_envelope(authenticated_sender, &request) {
            return rejected_response(error);
        }
        // Vote and AppendEntries keep this permit through the Openraft
        // response. The pinned engine emits an AppendEntries response before
        // applying commit-index state-machine work, so uniform apply cannot
        // self-deadlock. The final snapshot cutover carrier is released in its
        // arm below because snapshot response follows state-machine install.
        let mut engine_rpc = Some(self.peer_directory.begin_engine_rpc().await);
        if !self.peer_directory.authorizes_engine(
            authenticated_sender,
            request.identity,
            request.family,
        ) {
            return rejected_response(SessionConsensusPeerError::ScopeMismatch);
        }
        if !is_engine_rpc_family(request.family) {
            return rejected_response(SessionConsensusPeerError::Rejected);
        }

        let result = match request.family {
            SessionConsensusRpcFamily::AppendEntries => {
                let rpc = match decode_and_bind_sender::<AppendEntriesRequest<SessionRaftTypeConfig>>(
                    &request.payload,
                    request.sender,
                ) {
                    Ok(rpc) => rpc,
                    Err(error) => return rejected_response(error),
                };
                encode_engine_result(&self.raft.append_entries(rpc).await)
            }
            SessionConsensusRpcFamily::Vote => {
                let rpc = match decode_and_bind_sender::<VoteRequest<SessionConsensusNodeId>>(
                    &request.payload,
                    request.sender,
                ) {
                    Ok(rpc) => rpc,
                    Err(error) => return rejected_response(error),
                };
                encode_engine_result(&self.raft.vote(rpc).await)
            }
            SessionConsensusRpcFamily::InstallSnapshot => {
                let rpc = match decode_and_bind_sender::<
                    InstallSnapshotRequest<SessionRaftTypeConfig>,
                >(&request.payload, request.sender)
                {
                    Ok(rpc) => rpc,
                    Err(error) => return rejected_response(error),
                };
                if rpc.done
                    && self
                        .peer_directory
                        .requires_uniform_membership_fence(rpc.meta.last_membership.membership())
                {
                    // This final chunk carries metadata for a prospective
                    // exact-uniform cutover. Release its own permit so a valid
                    // state-machine install can drain every other predecessor
                    // RPC and atomically publish successor admission. A chunk
                    // rejected by Openraft or storage never reaches that
                    // publication point.
                    drop(engine_rpc.take());
                }
                encode_engine_result(&self.raft.install_snapshot(rpc).await)
            }
            SessionConsensusRpcFamily::ForwardMutation | SessionConsensusRpcFamily::ReadBarrier => {
                return rejected_response(SessionConsensusPeerError::Rejected);
            }
            SessionConsensusRpcFamily::TopologyAdmissionBarrier => {
                return rejected_response(SessionConsensusPeerError::Rejected);
            }
            _ => return rejected_response(SessionConsensusPeerError::Rejected),
        };
        drop(engine_rpc);

        match result {
            Ok(payload) => SessionConsensusWireResponse {
                result: Ok(payload),
            },
            Err(error) => rejected_response(error),
        }
    }
}

fn validate_envelope(
    authenticated_sender: SessionConsensusNodeId,
    request: &SessionConsensusWireRequest,
) -> Result<(), SessionConsensusPeerError> {
    request.validate()?;
    if request.schema_version != SESSION_CONSENSUS_SCHEMA_VERSION
        || authenticated_sender != request.sender
    {
        return Err(SessionConsensusPeerError::ScopeMismatch);
    }
    Ok(())
}

fn is_engine_rpc_family(family: SessionConsensusRpcFamily) -> bool {
    matches!(
        family,
        SessionConsensusRpcFamily::Vote
            | SessionConsensusRpcFamily::AppendEntries
            | SessionConsensusRpcFamily::InstallSnapshot
    )
}

trait EngineRequestSender {
    fn vote(&self) -> &Vote<SessionConsensusNodeId>;
}

impl EngineRequestSender for AppendEntriesRequest<SessionRaftTypeConfig> {
    fn vote(&self) -> &Vote<SessionConsensusNodeId> {
        &self.vote
    }
}

impl EngineRequestSender for VoteRequest<SessionConsensusNodeId> {
    fn vote(&self) -> &Vote<SessionConsensusNodeId> {
        &self.vote
    }
}

impl EngineRequestSender for InstallSnapshotRequest<SessionRaftTypeConfig> {
    fn vote(&self) -> &Vote<SessionConsensusNodeId> {
        &self.vote
    }
}

fn decode_and_bind_sender<T>(
    payload: &[u8],
    sender: SessionConsensusNodeId,
) -> Result<T, SessionConsensusPeerError>
where
    T: DeserializeOwned + EngineRequestSender,
{
    let request: T = decode_bounded(payload).map_err(|_| SessionConsensusPeerError::Protocol)?;
    if request.vote().leader_id.voted_for() != Some(sender) {
        return Err(SessionConsensusPeerError::ScopeMismatch);
    }
    Ok(request)
}

fn encode_engine_result<T, E>(result: &Result<T, E>) -> Result<Vec<u8>, SessionConsensusPeerError>
where
    T: Serialize,
    E: Serialize,
{
    encode_bounded(result).map_err(|_| SessionConsensusPeerError::Protocol)
}

fn rejected_response(error: SessionConsensusPeerError) -> SessionConsensusWireResponse {
    SessionConsensusWireResponse { result: Err(error) }
}

#[derive(Debug, Error)]
#[error("consensus peer is not configured")]
struct MissingConsensusPeer;

#[derive(Debug, Error)]
#[error("consensus peer directory is unavailable")]
struct PeerDirectoryUnavailable;

#[derive(Debug, Error)]
#[error("consensus peer identity changed")]
struct PeerIdentityChanged;

#[derive(Debug, Error)]
#[error("consensus codec rejected the engine payload")]
struct CodecTransportError(#[source] ConsensusCodecError);

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::sync::Mutex;
    use std::time::Duration;

    use bytes::Bytes;
    use opc_consensus::engine::storage::{RaftSnapshotBuilder, RaftStateMachine};
    use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload, LogId, Membership};
    use opc_consensus::{durable_openraft_config, DurableOpenraftDomain};
    use opc_types::Timestamp;
    use tokio::sync::Notify;

    use super::*;
    use crate::consensus::{
        storage, SessionConsensusClusterId, SessionConsensusCommand,
        SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId,
        SessionConsensusRequestId, SessionMutationIntent, SessionTopologyMemberBinding,
        SESSION_CONSENSUS_SCHEMA_VERSION,
    };
    use crate::sqlite::SqliteSessionBackend;

    #[derive(Debug)]
    struct MockPeer {
        node_id: SessionConsensusNodeId,
        response: SessionConsensusWireResponse,
    }

    #[async_trait::async_trait]
    impl SessionConsensusPeer for MockPeer {
        fn node_id(&self) -> SessionConsensusNodeId {
            self.node_id
        }

        async fn call(
            &self,
            _request: SessionConsensusWireRequest,
        ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
            Ok(self.response.clone())
        }
    }

    struct DeadlineRecordingPeer {
        node_id: SessionConsensusNodeId,
        observed_timeout: Mutex<Option<Duration>>,
        observed_identity: Mutex<Option<SessionConsensusIdentity>>,
        entered: Notify,
        release: Notify,
        response: SessionConsensusWireResponse,
    }

    impl fmt::Debug for DeadlineRecordingPeer {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("DeadlineRecordingPeer")
                .field("node_id", &self.node_id)
                .finish_non_exhaustive()
        }
    }

    #[async_trait::async_trait]
    impl SessionConsensusPeer for DeadlineRecordingPeer {
        fn node_id(&self) -> SessionConsensusNodeId {
            self.node_id
        }

        async fn call(
            &self,
            _request: SessionConsensusWireRequest,
        ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
            Err(SessionConsensusPeerError::Protocol)
        }

        async fn call_with_timeout(
            &self,
            request: SessionConsensusWireRequest,
            timeout: Duration,
        ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
            *self
                .observed_timeout
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(timeout);
            *self
                .observed_identity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(request.identity);
            self.entered.notify_one();
            self.release.notified().await;
            Ok(self.response.clone())
        }
    }

    #[derive(Debug)]
    struct ScopeCheckingPeer {
        node_id: SessionConsensusNodeId,
        expected_identity: SessionConsensusIdentity,
        response: SessionConsensusWireResponse,
    }

    #[async_trait::async_trait]
    impl SessionConsensusPeer for ScopeCheckingPeer {
        fn node_id(&self) -> SessionConsensusNodeId {
            self.node_id
        }

        fn scope_identity(&self) -> Option<SessionConsensusIdentity> {
            Some(self.expected_identity)
        }

        async fn call(
            &self,
            request: SessionConsensusWireRequest,
        ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
            if request.identity != self.expected_identity {
                return Err(SessionConsensusPeerError::ScopeMismatch);
            }
            Ok(self.response.clone())
        }
    }

    fn node_id(value: u64) -> SessionConsensusNodeId {
        SessionConsensusNodeId::new(value).expect("non-zero test node ID")
    }

    fn identity(seed: u8) -> SessionConsensusIdentity {
        SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([seed; 32]),
            SessionConsensusConfigurationId::from_bytes([seed.wrapping_add(1); 32]),
            SessionConsensusConfigurationEpoch::new(1).expect("non-zero test epoch"),
        )
    }

    fn successor_identity(
        current: SessionConsensusIdentity,
        configuration_seed: u8,
    ) -> SessionConsensusIdentity {
        SessionConsensusIdentity::new(
            current.cluster_id(),
            SessionConsensusConfigurationId::from_bytes([configuration_seed; 32]),
            SessionConsensusConfigurationEpoch::new(current.configuration_epoch().get() + 1)
                .expect("successor test epoch"),
        )
    }

    fn transition_id(seed: u8) -> SessionTopologyTransitionId {
        SessionTopologyTransitionId::from_bytes([seed; 16])
    }

    fn transition_digest(seed: u8) -> SessionTopologyTransitionDigest {
        SessionTopologyTransitionDigest::from_bytes([seed; 32])
    }

    fn stored_membership(
        configs: Vec<BTreeSet<SessionConsensusNodeId>>,
        nodes: BTreeSet<SessionConsensusNodeId>,
    ) -> StoredMembership<SessionConsensusNodeId, EmptyNode> {
        StoredMembership::new(
            Some(LogId::new(CommittedLeaderId::new(3, node_id(1)), 17)),
            Membership::new(configs, nodes),
        )
    }

    struct RealFollowerFixture {
        _temp: tempfile::TempDir,
        backend: SqliteSessionBackend,
        raft: SessionRaft,
        state_machine: storage::SqliteConsensusStateMachine,
        handler: SessionRaftRpcHandler,
        directory: SessionRaftPeerDirectory,
        current: SessionConsensusIdentity,
        desired: SessionConsensusIdentity,
        current_members: BTreeSet<SessionConsensusNodeId>,
        desired_members: BTreeSet<SessionConsensusNodeId>,
        leader: SessionConsensusNodeId,
        local: SessionConsensusNodeId,
        transition: SessionTopologyTransitionId,
        digest: SessionTopologyTransitionDigest,
    }

    fn member_binding(node: SessionConsensusNodeId) -> SessionTopologyMemberBinding {
        let seed = u8::try_from(node.get()).expect("small test node ID");
        SessionTopologyMemberBinding::new(
            [seed; 32],
            [seed.wrapping_add(0x20); 32],
            [seed.wrapping_add(0x40); 32],
            [seed.wrapping_add(0x60); 32],
        )
    }

    fn member_bindings(
        members: &BTreeSet<SessionConsensusNodeId>,
    ) -> BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding> {
        members
            .iter()
            .copied()
            .map(|node| (node, member_binding(node)))
            .collect()
    }

    fn scope_peers(
        local: SessionConsensusNodeId,
        members: &BTreeSet<SessionConsensusNodeId>,
        scope: SessionConsensusIdentity,
    ) -> BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>> {
        members
            .iter()
            .copied()
            .filter(|node| *node != local)
            .map(|node| {
                let peer: Arc<dyn SessionConsensusPeer> = Arc::new(ScopeCheckingPeer {
                    node_id: node,
                    expected_identity: scope,
                    response: rejected_response(SessionConsensusPeerError::Rejected),
                });
                (node, peer)
            })
            .collect()
    }

    fn transition_command_entry(
        leader: SessionConsensusNodeId,
        index: u64,
        identity: SessionConsensusIdentity,
        request_seed: u8,
        intent: SessionMutationIntent,
    ) -> Entry<SessionRaftTypeConfig> {
        Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, leader), index),
            payload: EntryPayload::Normal(SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity,
                request_id: SessionConsensusRequestId::from_bytes([request_seed; 16]),
                logical_time: Timestamp::from_str("2026-07-21T00:00:00Z").expect("test timestamp"),
                intent,
            }),
        }
    }

    fn membership_entry(
        leader: SessionConsensusNodeId,
        index: u64,
        configs: Vec<BTreeSet<SessionConsensusNodeId>>,
        nodes: BTreeSet<SessionConsensusNodeId>,
    ) -> Entry<SessionRaftTypeConfig> {
        Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, leader), index),
            payload: EntryPayload::Membership(Membership::new(configs, nodes)),
        }
    }

    fn append_request(
        fixture: &RealFollowerFixture,
        prev_log_id: Option<LogId<SessionConsensusNodeId>>,
        entries: Vec<Entry<SessionRaftTypeConfig>>,
        leader_commit: Option<LogId<SessionConsensusNodeId>>,
    ) -> AppendEntriesRequest<SessionRaftTypeConfig> {
        AppendEntriesRequest {
            vote: Vote::new_committed(1, fixture.leader),
            prev_log_id,
            leader_commit,
            entries,
        }
    }

    async fn call_append_handler(
        fixture: &RealFollowerFixture,
        identity: SessionConsensusIdentity,
        rpc: AppendEntriesRequest<SessionRaftTypeConfig>,
    ) -> SessionConsensusWireResponse {
        tokio::time::timeout(
            Duration::from_secs(5),
            fixture
                .handler
                .handle(fixture.leader, append_wire(fixture, identity, &rpc)),
        )
        .await
        .expect("AppendEntries handler completes within test deadline")
    }

    fn append_wire(
        fixture: &RealFollowerFixture,
        identity: SessionConsensusIdentity,
        rpc: &AppendEntriesRequest<SessionRaftTypeConfig>,
    ) -> SessionConsensusWireRequest {
        let payload = encode_bounded(rpc).expect("bounded append request");
        SessionConsensusWireRequest::try_new(
            identity,
            fixture.leader,
            SessionConsensusRpcFamily::AppendEntries,
            payload,
        )
        .expect("valid append envelope")
    }

    fn assert_append_success(response: SessionConsensusWireResponse) {
        let payload = response.result.expect("append transport accepted");
        let result: Result<
            AppendEntriesResponse<SessionConsensusNodeId>,
            RaftError<SessionConsensusNodeId>,
        > = decode_bounded(&payload).expect("append response decodes");
        assert_eq!(result, Ok(AppendEntriesResponse::Success));
    }

    fn snapshot_wire(
        fixture: &RealFollowerFixture,
        identity: SessionConsensusIdentity,
        rpc: &InstallSnapshotRequest<SessionRaftTypeConfig>,
    ) -> SessionConsensusWireRequest {
        let payload = encode_bounded(rpc).expect("bounded snapshot request");
        SessionConsensusWireRequest::try_new(
            identity,
            fixture.leader,
            SessionConsensusRpcFamily::InstallSnapshot,
            payload,
        )
        .expect("valid snapshot envelope")
    }

    fn decode_snapshot_response(
        response: SessionConsensusWireResponse,
    ) -> InstallSnapshotResponse<SessionConsensusNodeId> {
        let payload = response.result.expect("snapshot transport accepted");
        let result: Result<
            InstallSnapshotResponse<SessionConsensusNodeId>,
            RaftError<SessionConsensusNodeId, InstallSnapshotError>,
        > = decode_bounded(&payload).expect("snapshot response decodes");
        result.expect("snapshot engine accepted")
    }

    async fn real_follower_fixture() -> RealFollowerFixture {
        let temp = tempfile::tempdir().expect("follower tempdir");
        let backend = SqliteSessionBackend::open(temp.path().join("sessions.sqlite"))
            .expect("follower backend");
        let current = identity(0x71);
        let desired = successor_identity(current, 0x73);
        let leader = node_id(1);
        let local = node_id(2);
        let current_members = BTreeSet::from([leader, local, node_id(3)]);
        let desired_members = BTreeSet::from([leader, local, node_id(4)]);
        let network = SessionRaftNetworkFactory::try_new(
            current,
            local,
            current_members.clone(),
            scope_peers(local, &current_members, current),
        )
        .expect("follower network");
        let directory = network.peer_directory();
        let (log_store, state_machine, _) = storage::open_with_member_bindings(
            &backend,
            temp.path().join("snapshots"),
            current,
            current_members.clone(),
            member_bindings(&current_members),
            directory.clone(),
        )
        .await
        .expect("follower storage");
        let config = Arc::new(
            durable_openraft_config(DurableOpenraftDomain::SessionState)
                .expect("durable test Raft config"),
        );
        let snapshot_state_machine = state_machine.clone();
        let raft = SessionRaft::new(local, config, network, log_store, state_machine)
            .await
            .expect("follower Raft");
        let handler = SessionRaftRpcHandler::new(raft.clone(), directory.clone(), local);
        RealFollowerFixture {
            _temp: temp,
            backend,
            raft,
            state_machine: snapshot_state_machine,
            handler,
            directory,
            current,
            desired,
            current_members,
            desired_members,
            leader,
            local,
            transition: transition_id(0x74),
            digest: transition_digest(0x75),
        }
    }

    async fn apply_through_joint(fixture: &RealFollowerFixture) {
        let all_nodes = fixture
            .current_members
            .union(&fixture.desired_members)
            .copied()
            .collect::<BTreeSet<_>>();
        let transition_id = fixture.transition.as_bytes();
        let request_digest = fixture.digest.as_bytes();
        let entries = vec![
            membership_entry(
                fixture.leader,
                0,
                vec![fixture.current_members.clone()],
                fixture.current_members.clone(),
            ),
            transition_command_entry(
                fixture.leader,
                1,
                fixture.current,
                0x11,
                SessionMutationIntent::PrepareTopologyTransition {
                    transition_id,
                    request_digest,
                    desired_identity: fixture.desired,
                    desired_members: fixture.desired_members.clone(),
                    desired_bindings: member_bindings(&fixture.desired_members),
                },
            ),
            membership_entry(
                fixture.leader,
                2,
                vec![fixture.current_members.clone()],
                all_nodes.clone(),
            ),
            transition_command_entry(
                fixture.leader,
                3,
                fixture.current,
                0x12,
                SessionMutationIntent::MarkTopologyLearnersReady {
                    transition_id,
                    request_digest,
                },
            ),
            transition_command_entry(
                fixture.leader,
                4,
                fixture.current,
                0x13,
                SessionMutationIntent::FenceTopologyAuthority {
                    transition_id,
                    request_digest,
                },
            ),
            membership_entry(
                fixture.leader,
                5,
                vec![
                    fixture.current_members.clone(),
                    fixture.desired_members.clone(),
                ],
                all_nodes,
            ),
        ];
        let committed = entries.last().map(|entry| entry.log_id);
        assert_append_success(
            call_append_handler(
                fixture,
                fixture.current,
                append_request(fixture, None, entries, committed),
            )
            .await,
        );
        fixture
            .raft
            .wait(Some(Duration::from_secs(5)))
            .applied_index(
                committed.map(|log_id| log_id.index),
                "pre-uniform transition entries apply",
            )
            .await
            .expect("pre-uniform entries applied");
        fixture
            .directory
            .stage(
                fixture.transition,
                fixture.digest,
                fixture.current.configuration_epoch(),
                fixture.desired,
                fixture.desired_members.clone(),
                scope_peers(fixture.local, &fixture.desired_members, fixture.desired),
            )
            .expect("stage desired routes before uniform apply");
        fixture
            .directory
            .admit_staged_voting(
                fixture.transition,
                fixture.digest,
                fixture.current.configuration_epoch(),
            )
            .expect("admit desired voting after joint proof");
    }

    async fn wait_for_membership_writer(directory: &SessionRaftPeerDirectory) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            match tokio::time::timeout(Duration::from_millis(5), directory.begin_engine_rpc()).await
            {
                Ok(probe) => drop(probe),
                Err(_) => return,
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "membership apply writer did not queue behind predecessor RPC"
            );
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn inbound_append_uniform_responds_before_apply_then_fences_predecessor() {
        let fixture = real_follower_fixture().await;
        apply_through_joint(&fixture).await;
        let final_log_id = LogId::new(CommittedLeaderId::new(1, fixture.leader), 6);
        let uniform = membership_entry(
            fixture.leader,
            6,
            vec![fixture.desired_members.clone()],
            fixture.desired_members.clone(),
        );
        let final_rpc = append_request(
            &fixture,
            Some(LogId::new(CommittedLeaderId::new(1, fixture.leader), 5)),
            vec![uniform],
            Some(final_log_id),
        );
        let held_apply = Arc::clone(&fixture.backend.consensus_apply_gate)
            .acquire_owned()
            .await
            .expect("hold state-machine apply");
        let handler = fixture.handler.clone();
        let leader = fixture.leader;
        let wire = append_wire(&fixture, fixture.current, &final_rpc);
        let response = tokio::time::timeout(Duration::from_secs(2), async move {
            handler.handle(leader, wire).await
        })
        .await
        .expect("AppendEntries responds before committed state-machine apply");
        assert_append_success(response);
        assert_eq!(
            fixture.directory.current_scope().expect("pre-apply scope"),
            (fixture.current, fixture.current_members.clone()),
            "uniform routing changed before state-machine apply"
        );

        let predecessor_rpc = fixture.directory.begin_engine_rpc().await;
        drop(held_apply);
        wait_for_membership_writer(&fixture.directory).await;
        assert_eq!(
            fixture
                .directory
                .current_scope()
                .expect("scope while predecessor RPC remains active")
                .0,
            fixture.current,
            "uniform apply crossed an already-admitted predecessor RPC"
        );
        drop(predecessor_rpc);
        fixture
            .raft
            .wait(Some(Duration::from_secs(5)))
            .applied_index(Some(final_log_id.index), "uniform membership apply")
            .await
            .expect("uniform membership applied after predecessor RPC drained");
        assert_eq!(
            fixture.directory.current_scope().expect("post-apply scope"),
            (fixture.desired, fixture.desired_members.clone())
        );

        let stale_heartbeat =
            append_request(&fixture, Some(final_log_id), Vec::new(), Some(final_log_id));
        assert_eq!(
            call_append_handler(&fixture, fixture.current, stale_heartbeat)
                .await
                .result,
            Err(SessionConsensusPeerError::ScopeMismatch),
            "predecessor-scoped AppendEntries remained admitted after uniform apply"
        );
        fixture.raft.shutdown().await.expect("shutdown test Raft");
    }

    #[tokio::test]
    async fn inbound_final_snapshot_releases_own_permit_and_fences_predecessor() {
        let source = real_follower_fixture().await;
        apply_through_joint(&source).await;
        let uniform_log_id = LogId::new(CommittedLeaderId::new(1, source.leader), 6);
        assert_append_success(
            call_append_handler(
                &source,
                source.current,
                append_request(
                    &source,
                    Some(LogId::new(CommittedLeaderId::new(1, source.leader), 5)),
                    vec![membership_entry(
                        source.leader,
                        6,
                        vec![source.desired_members.clone()],
                        source.desired_members.clone(),
                    )],
                    Some(uniform_log_id),
                ),
            )
            .await,
        );
        source
            .raft
            .wait(Some(Duration::from_secs(5)))
            .applied_index(Some(uniform_log_id.index), "snapshot source uniform apply")
            .await
            .expect("snapshot source reaches desired uniform");
        let mut snapshot_state_machine = source.state_machine.clone();
        let mut builder = snapshot_state_machine.get_snapshot_builder().await;
        let snapshot = builder
            .build_snapshot()
            .await
            .expect("build source snapshot");
        let snapshot_meta = snapshot.meta.clone();
        let snapshot_bytes = tokio::fs::read(snapshot.snapshot.path())
            .await
            .expect("read source snapshot envelope");

        let target = real_follower_fixture().await;
        apply_through_joint(&target).await;
        let held_predecessor_rpc = target.directory.begin_engine_rpc().await;
        let final_chunk = InstallSnapshotRequest {
            vote: Vote::new_committed(1, target.leader),
            meta: snapshot_meta.clone(),
            offset: 0,
            data: snapshot_bytes.clone(),
            done: true,
        };
        let handler = target.handler.clone();
        let leader = target.leader;
        let wire = snapshot_wire(&target, target.current, &final_chunk);
        let mut install = tokio::spawn(async move { handler.handle(leader, wire).await });
        wait_for_membership_writer(&target.directory).await;
        assert!(
            !install.is_finished(),
            "final snapshot crossed another admitted predecessor RPC"
        );
        assert_eq!(
            target
                .directory
                .current_scope()
                .expect("pre-install scope")
                .0,
            target.current
        );
        drop(held_predecessor_rpc);
        let response = tokio::time::timeout(Duration::from_secs(5), &mut install)
            .await
            .expect("final snapshot does not self-deadlock")
            .expect("snapshot handler task remains live");
        let _ = decode_snapshot_response(response);
        target
            .raft
            .wait(Some(Duration::from_secs(5)))
            .applied_index(
                Some(uniform_log_id.index),
                "snapshot target uniform install",
            )
            .await
            .expect("snapshot target reaches desired uniform");
        assert_eq!(
            target
                .directory
                .current_scope()
                .expect("post-snapshot scope"),
            (target.desired, target.desired_members.clone())
        );
        let stale_heartbeat = append_request(
            &target,
            Some(uniform_log_id),
            Vec::new(),
            Some(uniform_log_id),
        );
        assert_eq!(
            call_append_handler(&target, target.current, stale_heartbeat)
                .await
                .result,
            Err(SessionConsensusPeerError::ScopeMismatch)
        );

        let cancelled = real_follower_fixture().await;
        apply_through_joint(&cancelled).await;
        let held_cancelled_predecessor = cancelled.directory.begin_engine_rpc().await;
        let cancelled_chunk = InstallSnapshotRequest {
            vote: Vote::new_committed(1, cancelled.leader),
            meta: snapshot_meta.clone(),
            offset: 0,
            data: snapshot_bytes.clone(),
            done: true,
        };
        let handler = cancelled.handler.clone();
        let leader = cancelled.leader;
        let wire = snapshot_wire(&cancelled, cancelled.current, &cancelled_chunk);
        let cancelled_install = tokio::spawn(async move { handler.handle(leader, wire).await });
        wait_for_membership_writer(&cancelled.directory).await;
        cancelled_install.abort();
        let cancelled_error = tokio::time::timeout(Duration::from_secs(1), cancelled_install)
            .await
            .expect("cancelled snapshot handler task terminates")
            .expect_err("snapshot handler task was cancelled");
        assert!(cancelled_error.is_cancelled());
        drop(held_cancelled_predecessor);
        cancelled
            .raft
            .wait(Some(Duration::from_secs(5)))
            .applied_index(
                Some(uniform_log_id.index),
                "cancelled caller snapshot finishes safely",
            )
            .await
            .expect("snapshot install survives caller cancellation");
        assert_eq!(
            cancelled
                .directory
                .current_scope()
                .expect("post-cancellation snapshot scope"),
            (cancelled.desired, cancelled.desired_members.clone())
        );

        let malformed = real_follower_fixture().await;
        apply_through_joint(&malformed).await;
        let mut malformed_state_machine = malformed.state_machine.clone();
        let (_, durable_before_malformed) = malformed_state_machine
            .applied_state()
            .await
            .expect("read durable membership before malformed snapshot");
        let malformed_wire = SessionConsensusWireRequest::try_new(
            malformed.current,
            malformed.leader,
            SessionConsensusRpcFamily::InstallSnapshot,
            vec![0xA5; 32],
        )
        .expect("bounded malformed snapshot envelope");
        let malformed_response = tokio::time::timeout(
            Duration::from_secs(5),
            malformed.handler.handle(malformed.leader, malformed_wire),
        )
        .await
        .expect("malformed snapshot wire is rejected within test deadline");
        assert_eq!(
            malformed_response.result,
            Err(SessionConsensusPeerError::Protocol)
        );

        let stale_vote = Vote::new_committed(0, malformed.leader);
        let rejected_chunk = InstallSnapshotRequest {
            vote: stale_vote,
            meta: snapshot_meta,
            offset: 0,
            data: snapshot_bytes,
            done: true,
        };
        let rejected_response = tokio::time::timeout(
            Duration::from_secs(5),
            malformed.handler.handle(
                malformed.leader,
                snapshot_wire(&malformed, malformed.current, &rejected_chunk),
            ),
        )
        .await
        .expect("stale-vote final snapshot is rejected within test deadline");
        let engine_response = decode_snapshot_response(rejected_response);
        assert_ne!(
            engine_response.vote, stale_vote,
            "stale-vote final snapshot was unexpectedly accepted"
        );
        assert_eq!(
            malformed
                .directory
                .current_scope()
                .expect("malformed snapshot scope"),
            (malformed.current, malformed.current_members.clone())
        );
        let (_, durable_after_malformed) = malformed_state_machine
            .applied_state()
            .await
            .expect("read durable membership after malformed snapshot");
        assert_eq!(
            durable_after_malformed, durable_before_malformed,
            "malformed final snapshot changed durable SQLite membership"
        );
        assert!(malformed.directory.authorizes_engine(
            malformed.leader,
            malformed.current,
            SessionConsensusRpcFamily::AppendEntries,
        ));

        tokio::time::timeout(Duration::from_secs(5), source.raft.shutdown())
            .await
            .expect("snapshot source shutdown completes")
            .expect("shutdown snapshot source");
        tokio::time::timeout(Duration::from_secs(5), target.raft.shutdown())
            .await
            .expect("snapshot target shutdown completes")
            .expect("shutdown snapshot target");
        tokio::time::timeout(Duration::from_secs(5), cancelled.raft.shutdown())
            .await
            .expect("cancelled snapshot target shutdown completes")
            .expect("shutdown cancelled snapshot target");
        let _ = tokio::time::timeout(Duration::from_secs(5), malformed.raft.shutdown()).await;
    }

    #[test]
    fn joining_candidate_has_no_predecessor_scope_routes() {
        let current_identity = identity(0x31);
        let current_members = BTreeSet::from([node_id(1), node_id(2), node_id(3)]);
        let local_candidate = node_id(4);
        let factory = SessionRaftNetworkFactory::try_new_candidate(
            current_identity,
            local_candidate,
            current_members.clone(),
        )
        .expect("candidate peer directory");
        let directory = factory.peer_directory();

        assert_eq!(
            directory.current_scope().expect("candidate scope"),
            (current_identity, current_members.clone())
        );
        for current_member in current_members {
            assert!(
                directory
                    .resolve_engine(current_member)
                    .expect("candidate directory remains available")
                    .is_none(),
                "a joining candidate must not receive predecessor-scope outbound authority"
            );
            assert!(!directory.authorizes_engine(
                current_member,
                current_identity,
                SessionConsensusRpcFamily::AppendEntries,
            ));
        }
    }

    fn vote_request(sender: SessionConsensusNodeId) -> VoteRequest<SessionConsensusNodeId> {
        VoteRequest::new(Vote::new(7, sender), None)
    }

    fn rejecting_peer_map(
        first_node_id: u64,
        count: usize,
        scope: Option<SessionConsensusIdentity>,
    ) -> BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>> {
        (0..count)
            .map(|offset| {
                let id = node_id(
                    first_node_id + u64::try_from(offset).expect("bounded peer-map offset"),
                );
                let response = rejected_response(SessionConsensusPeerError::Rejected);
                let peer: Arc<dyn SessionConsensusPeer> = match scope {
                    Some(expected_identity) => Arc::new(ScopeCheckingPeer {
                        node_id: id,
                        expected_identity,
                        response,
                    }),
                    None => Arc::new(MockPeer {
                        node_id: id,
                        response,
                    }),
                };
                (id, peer)
            })
            .collect()
    }

    async fn call_test_network(network: &SessionRaftNetwork) -> Result<u64, EngineRpcError> {
        network
            .call::<u64, opc_consensus::engine::error::Infallible>(
                SessionConsensusRpcFamily::Vote,
                opc_consensus::engine::RPCTypes::Vote,
                Vec::new(),
                RPCOption::new(Duration::from_secs(1)),
            )
            .await
    }

    #[tokio::test(start_paused = true)]
    async fn adapter_passes_soft_ttl_and_leaves_hard_timeout_to_openraft() {
        let target = node_id(2);
        let encoded_result: Result<
            u64,
            RaftError<SessionConsensusNodeId, opc_consensus::engine::error::Infallible>,
        > = Ok(7);
        let peer = Arc::new(DeadlineRecordingPeer {
            node_id: target,
            observed_timeout: Mutex::new(None),
            observed_identity: Mutex::new(None),
            entered: Notify::new(),
            release: Notify::new(),
            response: SessionConsensusWireResponse {
                result: Ok(encode_bounded(&encoded_result).expect("bounded test response")),
            },
        });
        let peer_for_directory: Arc<dyn SessionConsensusPeer> = peer.clone();
        let current_identity = identity(1);
        let directory = SessionRaftPeerDirectory::try_new(
            current_identity,
            node_id(1),
            BTreeSet::from([node_id(1), target]),
            BTreeMap::from([(target, peer_for_directory)]),
        )
        .expect("valid peer directory");
        let network = SessionRaftNetwork {
            local_node_id: node_id(1),
            target,
            peer_directory: directory.clone(),
        };
        let hard_ttl = Duration::from_secs(4);
        let option = RPCOption::new(hard_ttl);
        let expected_soft_ttl = option.soft_ttl();
        let call = tokio::spawn(async move {
            network
                .call::<u64, opc_consensus::engine::error::Infallible>(
                    SessionConsensusRpcFamily::Vote,
                    opc_consensus::engine::RPCTypes::Vote,
                    Vec::new(),
                    option,
                )
                .await
        });

        peer.entered.notified().await;
        assert_eq!(
            *peer
                .observed_timeout
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Some(expected_soft_ttl)
        );
        assert_eq!(
            *peer
                .observed_identity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Some(current_identity),
            "fixed-topology clients must retain their exact admitted scope"
        );

        // Exact uniform apply drains the complete already-admitted RPC before
        // publishing successor routes. This exercises the actual cached
        // network-call lifetime rather than only a route lookup.
        let transition = transition_id(0xa1);
        let digest = transition_digest(0xa1);
        let desired = successor_identity(current_identity, 9);
        let desired_members = BTreeSet::from([node_id(3), node_id(4), node_id(5)]);
        let desired_peers = rejecting_peer_map(3, 3, Some(desired));
        directory
            .stage(
                transition,
                digest,
                current_identity.configuration_epoch(),
                desired,
                desired_members.clone(),
                desired_peers,
            )
            .expect("stage removal while call is blocked");
        let cutover_directory = directory.clone();
        let applied_uniform =
            stored_membership(vec![desired_members.clone()], desired_members.clone());
        let mut cutover = tokio::spawn(async move {
            let _apply_guard = cutover_directory.begin_membership_apply().await;
            cutover_directory
                .observe_applied_membership(&applied_uniform)
                .expect("apply exact uniform membership");
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut cutover)
                .await
                .is_err(),
            "uniform apply crossed an active cached engine RPC"
        );

        tokio::time::advance(hard_ttl + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(
            !call.is_finished(),
            "the adapter must not duplicate Openraft's outer hard timeout"
        );

        peer.release.notify_one();
        assert_eq!(call.await.expect("adapter task"), Ok(7));
        cutover.await.expect("uniform cutover after RPC drain");

        directory
            .finalize(
                transition,
                digest,
                current_identity.configuration_epoch(),
                &desired_members,
            )
            .expect("delayed process finalization remains idempotent");

        let retired = SessionRaftNetwork {
            local_node_id: node_id(1),
            target,
            peer_directory: directory,
        };
        assert!(matches!(
            call_test_network(&retired).await,
            Err(EngineRpcError::Unreachable(_))
        ));
    }

    #[test]
    fn append_entries_split_hint_never_retries_a_singleton_as_payload_too_large() {
        assert_eq!(append_entries_split_hint(0), None);
        assert_eq!(append_entries_split_hint(1), None);
        assert_eq!(append_entries_split_hint(2), Some(1));
        assert_eq!(append_entries_split_hint(64), Some(32));
    }

    #[test]
    fn factory_rejects_a_peer_registered_under_another_node_id() {
        let mut peers: BTreeMap<_, Arc<dyn SessionConsensusPeer>> = BTreeMap::new();
        peers.insert(
            node_id(1),
            Arc::new(MockPeer {
                node_id: node_id(2),
                response: rejected_response(SessionConsensusPeerError::Rejected),
            }),
        );

        assert!(matches!(
            SessionRaftNetworkFactory::try_new(
                identity(1),
                node_id(3),
                BTreeSet::from([node_id(1), node_id(3)]),
                peers,
            ),
            Err(SessionRaftAdapterError::PeerNodeIdMismatch)
        ));
    }

    #[test]
    fn peer_directory_bounds_identity_and_transition_scope() {
        let local = node_id(1);
        let target = node_id(2);
        let current = identity(1);
        let desired = successor_identity(current, 9);
        let expected_epoch = current.configuration_epoch();
        let transition_a = transition_id(0xa1);
        let transition_b = transition_id(0xb2);
        let digest_a = transition_digest(0xa1);
        let digest_b = transition_digest(0xb2);
        let desired_members = BTreeSet::from([target]);
        let peer: Arc<dyn SessionConsensusPeer> = Arc::new(ScopeCheckingPeer {
            node_id: target,
            expected_identity: desired,
            response: rejected_response(SessionConsensusPeerError::Rejected),
        });
        let directory = SessionRaftPeerDirectory::try_new(
            current,
            local,
            BTreeSet::from([local]),
            BTreeMap::new(),
        )
        .expect("empty bounded directory");

        directory
            .stage(
                transition_a,
                digest_a,
                expected_epoch,
                desired,
                desired_members.clone(),
                BTreeMap::from([(target, peer)]),
            )
            .expect("stage matching peer");

        // Pointer identity is not admission identity: a reconstructed adapter
        // for the same node and desired manifest remains an exact retry.
        let reconstructed: Arc<dyn SessionConsensusPeer> = Arc::new(ScopeCheckingPeer {
            node_id: target,
            expected_identity: desired,
            response: rejected_response(SessionConsensusPeerError::Rejected),
        });
        directory
            .stage(
                transition_a,
                digest_a,
                expected_epoch,
                desired,
                desired_members.clone(),
                BTreeMap::from([(target, reconstructed)]),
            )
            .expect("same authenticated binding is idempotent");

        let wrong_scope: Arc<dyn SessionConsensusPeer> = Arc::new(ScopeCheckingPeer {
            node_id: target,
            expected_identity: current,
            response: rejected_response(SessionConsensusPeerError::Rejected),
        });
        assert_eq!(
            directory.stage(
                transition_a,
                digest_a,
                expected_epoch,
                desired,
                desired_members.clone(),
                BTreeMap::from([(target, wrong_scope)]),
            ),
            Err(SessionRaftAdapterError::PeerScopeMismatch)
        );

        assert_eq!(
            directory.stage(
                transition_b,
                digest_b,
                expected_epoch,
                desired,
                desired_members.clone(),
                rejecting_peer_map(2, 1, Some(desired)),
            ),
            Err(SessionRaftAdapterError::PeerTransitionConflict)
        );
        assert_eq!(
            directory.stage(
                transition_a,
                digest_a,
                expected_epoch,
                successor_identity(current, 10),
                desired_members.clone(),
                rejecting_peer_map(2, 1, Some(successor_identity(current, 10))),
            ),
            Err(SessionRaftAdapterError::PeerTransitionConflict)
        );

        let mismatched: Arc<dyn SessionConsensusPeer> = Arc::new(MockPeer {
            node_id: node_id(3),
            response: rejected_response(SessionConsensusPeerError::Rejected),
        });
        assert_eq!(
            directory.stage(
                transition_a,
                digest_a,
                expected_epoch,
                desired,
                desired_members.clone(),
                BTreeMap::from([(target, mismatched)]),
            ),
            Err(SessionRaftAdapterError::PeerNodeIdMismatch)
        );
        assert_eq!(
            directory.stage(
                transition_a,
                digest_a,
                expected_epoch,
                desired,
                BTreeSet::from([local]),
                BTreeMap::from([(
                    local,
                    Arc::new(MockPeer {
                        node_id: local,
                        response: rejected_response(SessionConsensusPeerError::Rejected),
                    }) as Arc<dyn SessionConsensusPeer>,
                )]),
            ),
            Err(SessionRaftAdapterError::LocalNodeRegisteredAsPeer)
        );

        directory
            .abort_staged(transition_a, digest_a, expected_epoch)
            .expect("abort first transition");
        directory
            .abort_staged(transition_a, digest_a, expected_epoch)
            .expect("exact abort retry is idempotent");
        directory
            .stage(
                transition_b,
                digest_b,
                expected_epoch,
                desired,
                desired_members,
                rejecting_peer_map(2, 1, Some(desired)),
            )
            .expect("stage successor transition");
        assert_eq!(
            directory.abort_staged(transition_a, digest_a, expected_epoch),
            Ok(()),
            "a late abort from transition A must not clear transition B"
        );
        assert_eq!(
            directory.abort_staged(transition_id(0xc3), transition_digest(0xc3), expected_epoch,),
            Err(SessionRaftAdapterError::PeerTransitionConflict)
        );
        assert!(directory
            .resolve_engine(target)
            .expect("directory remains available")
            .is_some());
        directory
            .abort_staged(transition_b, digest_b, expected_epoch)
            .expect("matching successor abort still succeeds");

        let oversized = rejecting_peer_map(2, QUORUM_TOPOLOGY_MAX_MEMBERS + 1, None);
        let oversized_members = oversized
            .keys()
            .copied()
            .chain(std::iter::once(local))
            .collect();
        assert!(matches!(
            SessionRaftPeerDirectory::try_new(current, local, oversized_members, oversized),
            Err(SessionRaftAdapterError::PeerCapacityExceeded)
        ));
    }

    #[test]
    fn staged_peer_vote_is_proof_gated_in_both_directions() {
        let local = node_id(1);
        let added = node_id(2);
        let current = identity(1);
        let desired = successor_identity(current, 9);
        let transition = transition_id(0xa1);
        let digest = transition_digest(0xb2);
        let peer: Arc<dyn SessionConsensusPeer> = Arc::new(ScopeCheckingPeer {
            node_id: added,
            expected_identity: desired,
            response: rejected_response(SessionConsensusPeerError::Rejected),
        });
        let directory = SessionRaftPeerDirectory::try_new(
            current,
            local,
            BTreeSet::from([local]),
            BTreeMap::new(),
        )
        .expect("current directory");
        directory
            .stage(
                transition,
                digest,
                current.configuration_epoch(),
                desired,
                BTreeSet::from([local, added]),
                BTreeMap::from([(added, peer)]),
            )
            .expect("stage added learner");

        assert!(directory
            .resolve_engine_for(added, SessionConsensusRpcFamily::AppendEntries)
            .expect("append route lookup")
            .is_some());
        assert!(directory
            .resolve_engine_for(added, SessionConsensusRpcFamily::InstallSnapshot)
            .expect("snapshot route lookup")
            .is_some());
        assert!(directory
            .resolve_engine_for(added, SessionConsensusRpcFamily::Vote)
            .expect("vote route lookup")
            .is_none());
        assert!(directory.authorizes_engine(
            added,
            desired,
            SessionConsensusRpcFamily::AppendEntries
        ));
        assert!(directory.authorizes_engine(
            added,
            desired,
            SessionConsensusRpcFamily::InstallSnapshot
        ));
        assert!(!directory.authorizes_engine(added, desired, SessionConsensusRpcFamily::Vote));
        assert_eq!(
            directory.admit_staged_voting(
                transition_id(0xff),
                digest,
                current.configuration_epoch(),
            ),
            Err(SessionRaftAdapterError::PeerTransitionConflict)
        );

        directory
            .admit_staged_voting(transition, digest, current.configuration_epoch())
            .expect("exact durable proof admits voting");
        directory
            .admit_staged_voting(transition, digest, current.configuration_epoch())
            .expect("exact voting admission retry is idempotent");
        assert!(directory
            .resolve_engine_for(added, SessionConsensusRpcFamily::Vote)
            .expect("vote route lookup after admission")
            .is_some());
        assert!(directory.authorizes_engine(added, desired, SessionConsensusRpcFamily::Vote));
    }

    #[test]
    fn peer_directory_bounds_each_legal_topology_without_bounding_the_union_to_one_set() {
        let local = node_id(1);
        let current = identity(1);
        let desired = successor_identity(current, 9);
        let transition = transition_id(0xa1);
        let digest = transition_digest(0xa1);
        let active = rejecting_peer_map(2, QUORUM_TOPOLOGY_MAX_MEMBERS - 1, None);
        let current_members = active
            .keys()
            .copied()
            .chain(std::iter::once(local))
            .collect();
        let directory = SessionRaftPeerDirectory::try_new(current, local, current_members, active)
            .expect("maximum current topology including local member");
        let staged = rejecting_peer_map(100, QUORUM_TOPOLOGY_MAX_MEMBERS, Some(desired));
        let desired_members = staged.keys().copied().collect::<BTreeSet<_>>();
        directory
            .stage(
                transition,
                digest,
                current.configuration_epoch(),
                desired,
                desired_members,
                staged,
            )
            .expect("maximum desired topology excluding retiring local member");

        let extra_id = node_id(500);
        let oversized_peers =
            rejecting_peer_map(100, QUORUM_TOPOLOGY_MAX_MEMBERS + 1, Some(desired));
        let oversized_members = oversized_peers.keys().copied().collect();
        let empty_directory = SessionRaftPeerDirectory::try_new(
            current,
            local,
            BTreeSet::from([local]),
            BTreeMap::new(),
        )
        .expect("empty current topology for capacity rejection");
        assert_eq!(
            empty_directory.stage(
                transition,
                digest,
                current.configuration_epoch(),
                desired,
                oversized_members,
                oversized_peers,
            ),
            Err(SessionRaftAdapterError::PeerCapacityExceeded)
        );
        assert!(empty_directory
            .resolve_engine(extra_id)
            .expect("directory remains available")
            .is_none());
    }

    #[tokio::test]
    async fn applied_uniform_fences_cached_predecessor_engine_rpcs_before_process_finalize() {
        let local = node_id(1);
        let removed = node_id(2);
        let retained = node_id(3);
        let added = node_id(4);
        let current = identity(1);
        let desired = successor_identity(current, 9);
        let transition = transition_id(0xa1);
        let digest = transition_digest(0xa1);
        let current_members = BTreeSet::from([local, removed, retained]);
        let desired_members = BTreeSet::from([local, retained, added]);
        let current_peers = rejecting_peer_map(2, 2, None);
        let desired_peers = BTreeMap::from([
            (
                retained,
                Arc::new(ScopeCheckingPeer {
                    node_id: retained,
                    expected_identity: desired,
                    response: rejected_response(SessionConsensusPeerError::Rejected),
                }) as Arc<dyn SessionConsensusPeer>,
            ),
            (
                added,
                Arc::new(ScopeCheckingPeer {
                    node_id: added,
                    expected_identity: desired,
                    response: rejected_response(SessionConsensusPeerError::Rejected),
                }) as Arc<dyn SessionConsensusPeer>,
            ),
        ]);
        let directory = SessionRaftPeerDirectory::try_new(
            current,
            local,
            current_members.clone(),
            current_peers,
        )
        .expect("current routes");
        directory
            .stage(
                transition,
                digest,
                current.configuration_epoch(),
                desired,
                desired_members.clone(),
                desired_peers,
            )
            .expect("successor routes");

        let cached_predecessor_families = [
            SessionConsensusRpcFamily::Vote,
            SessionConsensusRpcFamily::AppendEntries,
            SessionConsensusRpcFamily::InstallSnapshot,
        ];
        for family in cached_predecessor_families {
            assert!(directory.authorizes_engine(removed, current, family));
            assert!(directory
                .resolve_engine_for(removed, family)
                .expect("predecessor route remains available before joint")
                .is_some());
        }

        let joint_nodes = current_members
            .union(&desired_members)
            .copied()
            .collect::<BTreeSet<_>>();
        directory
            .observe_applied_membership(&stored_membership(
                vec![current_members, desired_members.clone()],
                joint_nodes,
            ))
            .expect("joint membership remains routable");
        assert_eq!(
            directory.current_scope().expect("current scope").0,
            current,
            "joint consensus must not retire the predecessor scope"
        );
        assert!(directory
            .resolve_engine(removed)
            .expect("old route remains")
            .is_some());
        for family in cached_predecessor_families {
            assert!(
                directory.authorizes_engine(removed, current, family),
                "joint application prematurely fenced predecessor {family:?}"
            );
        }

        let release_calls = Arc::new(tokio::sync::Semaphore::new(0));
        let (entered_tx, mut entered_rx) = tokio::sync::mpsc::channel(3);
        let mut cached_calls = Vec::new();
        for family in cached_predecessor_families {
            let cached_directory = directory.clone();
            let release = Arc::clone(&release_calls);
            let entered = entered_tx.clone();
            cached_calls.push(tokio::spawn(async move {
                let _full_rpc_lifetime = cached_directory.begin_engine_rpc().await;
                assert!(cached_directory.authorizes_engine(removed, current, family));
                assert!(cached_directory
                    .resolve_engine_for(removed, family)
                    .expect("cached directory remains available")
                    .is_some());
                entered.send(family).await.expect("report entered RPC");
                release
                    .acquire()
                    .await
                    .expect("release cached RPC")
                    .forget();
            }));
        }
        drop(entered_tx);
        for _ in cached_predecessor_families {
            entered_rx.recv().await.expect("all cached RPCs entered");
        }

        let apply_directory = directory.clone();
        let applied_uniform =
            stored_membership(vec![desired_members.clone()], desired_members.clone());
        let mut apply = tokio::spawn(async move {
            let _apply_guard = apply_directory.begin_membership_apply().await;
            apply_directory
                .observe_applied_membership(&applied_uniform)
                .expect("uniform successor commit");
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(25), &mut apply)
                .await
                .is_err(),
            "uniform cutover did not drain full predecessor RPC lifetimes"
        );
        release_calls.add_permits(cached_predecessor_families.len());
        for call in cached_calls {
            call.await.expect("cached RPC completes before cutover");
        }
        apply
            .await
            .expect("uniform apply completes after RPC drain");
        assert_eq!(
            directory.current_scope().expect("desired scope"),
            (desired, desired_members.clone())
        );
        assert!(directory
            .resolve_engine(removed)
            .expect("directory remains available")
            .is_none());
        for family in cached_predecessor_families {
            assert!(
                !directory.authorizes_engine(removed, current, family),
                "cached predecessor {family:?} remained authorized after local uniform apply"
            );
            assert!(
                directory
                    .resolve_engine_for(removed, family)
                    .expect("uniform-applied directory remains available")
                    .is_none(),
                "cached predecessor {family:?} retained an outbound route"
            );
        }
        assert!(directory.authorizes_engine(
            retained,
            desired,
            SessionConsensusRpcFamily::AppendEntries,
        ));

        // Model an arbitrarily delayed process-level transport callback. The
        // apply-driven fence above is already authoritative, and the callback
        // remains an exact idempotent cleanup operation.
        directory
            .finalize(
                transition,
                digest,
                current.configuration_epoch(),
                &desired_members,
            )
            .expect("delayed finalization remains idempotent");
    }

    #[test]
    fn same_voter_set_epoch_cannot_promote_from_stale_applied_membership() {
        let local = node_id(1);
        let remote = node_id(2);
        let current = identity(1);
        let desired = successor_identity(current, 9);
        let members = BTreeSet::from([local, remote]);
        let directory = SessionRaftPeerDirectory::try_new(
            current,
            local,
            members.clone(),
            rejecting_peer_map(2, 1, None),
        )
        .expect("current routes");
        directory
            .observe_applied_membership(&stored_membership(vec![members.clone()], members.clone()))
            .expect("restore current applied membership");

        assert_eq!(
            directory.stage(
                transition_id(0xa2),
                transition_digest(0xa2),
                current.configuration_epoch(),
                desired,
                members.clone(),
                rejecting_peer_map(2, 1, Some(desired)),
            ),
            Err(SessionRaftAdapterError::InvalidPeerTransitionScope),
            "a node-set-only epoch change could reuse stale uniform evidence"
        );
        assert_eq!(
            directory.current_scope().expect("current scope remains"),
            (current, members)
        );
    }

    #[test]
    fn restored_uniform_before_route_stage_fails_closed_then_promotes_exact_successor() {
        let local = node_id(1);
        let removed = node_id(2);
        let retained = node_id(3);
        let added = node_id(4);
        let current = identity(1);
        let desired = successor_identity(current, 9);
        let current_members = BTreeSet::from([local, removed, retained]);
        let desired_members = BTreeSet::from([local, retained, added]);
        let directory = SessionRaftPeerDirectory::try_new(
            current,
            local,
            current_members.clone(),
            rejecting_peer_map(2, 2, None),
        )
        .expect("current routes");

        directory
            .observe_applied_membership(&stored_membership(
                vec![desired_members.clone()],
                desired_members.clone(),
            ))
            .expect("restore desired uniform membership");
        for family in [
            SessionConsensusRpcFamily::Vote,
            SessionConsensusRpcFamily::AppendEntries,
            SessionConsensusRpcFamily::InstallSnapshot,
        ] {
            assert!(!directory.authorizes_engine(removed, current, family));
            assert!(directory
                .resolve_engine_for(removed, family)
                .expect("suspended directory remains available")
                .is_none());
        }
        assert_eq!(
            directory.current_scope().expect("staging scope retained"),
            (current, current_members)
        );

        let desired_peers = BTreeMap::from([
            (
                retained,
                Arc::new(ScopeCheckingPeer {
                    node_id: retained,
                    expected_identity: desired,
                    response: rejected_response(SessionConsensusPeerError::Rejected),
                }) as Arc<dyn SessionConsensusPeer>,
            ),
            (
                added,
                Arc::new(ScopeCheckingPeer {
                    node_id: added,
                    expected_identity: desired,
                    response: rejected_response(SessionConsensusPeerError::Rejected),
                }) as Arc<dyn SessionConsensusPeer>,
            ),
        ]);
        directory
            .stage(
                transition_id(0xa3),
                transition_digest(0xa3),
                current.configuration_epoch(),
                desired,
                desired_members.clone(),
                desired_peers,
            )
            .expect("stage exact restored successor routes");
        assert_eq!(
            directory.current_scope().expect("restored successor scope"),
            (desired, desired_members)
        );
        assert!(directory.authorizes_engine(
            retained,
            desired,
            SessionConsensusRpcFamily::AppendEntries,
        ));
    }

    #[test]
    fn uniform_promotion_gives_removed_local_node_zero_engine_authority() {
        let local = node_id(1);
        let retained_a = node_id(2);
        let retained_b = node_id(3);
        let added = node_id(4);
        let current = identity(1);
        let desired = successor_identity(current, 9);
        let transition = transition_id(0xa4);
        let digest = transition_digest(0xa4);
        let current_members = BTreeSet::from([local, retained_a, retained_b]);
        let desired_members = BTreeSet::from([retained_a, retained_b, added]);
        let directory = SessionRaftPeerDirectory::try_new(
            current,
            local,
            current_members,
            rejecting_peer_map(2, 2, None),
        )
        .expect("current routes");
        directory
            .stage(
                transition,
                digest,
                current.configuration_epoch(),
                desired,
                desired_members.clone(),
                rejecting_peer_map(2, 3, Some(desired)),
            )
            .expect("stage successor excluding local node");
        directory
            .admit_staged_voting(transition, digest, current.configuration_epoch())
            .expect("admit successor voting before uniform");
        assert!(directory.authorizes_engine(retained_a, desired, SessionConsensusRpcFamily::Vote,));

        directory
            .observe_applied_membership(&stored_membership(
                vec![desired_members.clone()],
                desired_members,
            ))
            .expect("apply uniform membership excluding local node");
        for family in [
            SessionConsensusRpcFamily::Vote,
            SessionConsensusRpcFamily::AppendEntries,
            SessionConsensusRpcFamily::InstallSnapshot,
        ] {
            for sender in [retained_a, retained_b, added] {
                assert!(
                    !directory.authorizes_engine(sender, desired, family),
                    "removed local node accepted inbound {family:?} from successor"
                );
                assert!(
                    directory
                        .resolve_engine_for(sender, family)
                        .expect("removed directory remains available")
                        .is_none(),
                    "removed local node retained outbound {family:?} routing"
                );
            }
        }
    }

    #[tokio::test]
    async fn retained_openraft_client_observes_stage_abort_finalize_and_retirement() {
        let local = node_id(1);
        let target = node_id(2);
        let current = identity(1);
        let desired = successor_identity(current, 9);
        let transition_a = transition_id(0xa1);
        let digest_a = transition_digest(0xa1);
        let mut factory = SessionRaftNetworkFactory::try_new(
            current,
            local,
            BTreeSet::from([local]),
            BTreeMap::new(),
        )
        .expect("valid empty routing table");
        let directory = factory.peer_directory();
        let network = factory.new_client(target, &EmptyNode::default()).await;

        assert!(matches!(
            call_test_network(&network).await,
            Err(EngineRpcError::Unreachable(_))
        ));

        let result: Result<
            u64,
            RaftError<SessionConsensusNodeId, opc_consensus::engine::error::Infallible>,
        > = Ok(7);
        let peer: Arc<dyn SessionConsensusPeer> = Arc::new(ScopeCheckingPeer {
            node_id: target,
            expected_identity: desired,
            response: SessionConsensusWireResponse {
                result: Ok(encode_bounded(&result).expect("bounded response")),
            },
        });
        directory
            .stage(
                transition_a,
                digest_a,
                current.configuration_epoch(),
                desired,
                BTreeSet::from([local, target]),
                BTreeMap::from([(target, peer.clone())]),
            )
            .expect("stage learner peer");
        assert!(matches!(
            call_test_network(&network).await,
            Err(EngineRpcError::Unreachable(_))
        ));
        directory
            .admit_staged_voting(transition_a, digest_a, current.configuration_epoch())
            .expect("joint proof admits staged Vote routing");
        assert_eq!(call_test_network(&network).await, Ok(7));

        directory
            .abort_staged(transition_a, digest_a, current.configuration_epoch())
            .expect("abort learner admission");
        assert!(matches!(
            call_test_network(&network).await,
            Err(EngineRpcError::Unreachable(_))
        ));

        let transition_b = transition_id(0xb2);
        let digest_b = transition_digest(0xb2);
        directory
            .stage(
                transition_b,
                digest_b,
                current.configuration_epoch(),
                desired,
                BTreeSet::from([local, target]),
                BTreeMap::from([(target, peer)]),
            )
            .expect("restage learner peer");
        directory
            .finalize(
                transition_b,
                digest_b,
                current.configuration_epoch(),
                &BTreeSet::from([local, target]),
            )
            .expect("promote staged peer");
        directory
            .finalize(
                transition_b,
                digest_b,
                current.configuration_epoch(),
                &BTreeSet::from([local, target]),
            )
            .expect("exact finalization retry is idempotent");
        assert_eq!(call_test_network(&network).await, Ok(7));

        let transition_c = transition_id(0xc3);
        let digest_c = transition_digest(0xc3);
        let successor = successor_identity(desired, 10);
        directory
            .stage(
                transition_c,
                digest_c,
                desired.configuration_epoch(),
                successor,
                BTreeSet::from([local]),
                BTreeMap::new(),
            )
            .expect("stage removal transition");
        assert_eq!(
            directory.finalize(
                transition_b,
                digest_b,
                current.configuration_epoch(),
                &BTreeSet::from([local, target]),
            ),
            Ok(()),
            "a completed transition retry must not disturb its staged successor"
        );
        directory
            .finalize(
                transition_c,
                digest_c,
                desired.configuration_epoch(),
                &BTreeSet::from([local]),
            )
            .expect("retire removed peer");
        assert!(matches!(
            call_test_network(&network).await,
            Err(EngineRpcError::Unreachable(_))
        ));
        assert_eq!(
            directory.finalize(
                transition_c,
                digest_c,
                desired.configuration_epoch(),
                &BTreeSet::from([local]),
            ),
            Ok(())
        );
    }

    #[tokio::test]
    async fn joining_node_prefers_successor_scope_for_retained_targets() {
        let local = node_id(4);
        let target = node_id(1);
        let current = identity(1);
        let desired = successor_identity(current, 9);
        let current_members = BTreeSet::from([node_id(1), node_id(2), node_id(3)]);
        let desired_members =
            BTreeSet::from([node_id(1), node_id(2), node_id(3), local, node_id(5)]);
        let mut factory =
            SessionRaftNetworkFactory::try_new_candidate(current, local, current_members)
                .expect("joining candidate has no predecessor routes");
        let directory = factory.peer_directory();
        let encoded_desired: Result<
            u64,
            RaftError<SessionConsensusNodeId, opc_consensus::engine::error::Infallible>,
        > = Ok(2);
        let desired_peer: Arc<dyn SessionConsensusPeer> = Arc::new(ScopeCheckingPeer {
            node_id: target,
            expected_identity: desired,
            response: SessionConsensusWireResponse {
                result: Ok(encode_bounded(&encoded_desired).expect("bounded desired response")),
            },
        });
        let mut desired_peers = rejecting_peer_map(1, 5, Some(desired));
        desired_peers.remove(&local);
        desired_peers.insert(target, desired_peer);
        directory
            .stage(
                transition_id(0xa1),
                transition_digest(0xa1),
                current.configuration_epoch(),
                desired,
                desired_members,
                desired_peers,
            )
            .expect("stage joining-node successor routes");

        let network = factory.new_client(target, &EmptyNode::default()).await;
        assert!(matches!(
            call_test_network(&network).await,
            Err(EngineRpcError::Unreachable(_))
        ));
        directory
            .admit_staged_voting(
                transition_id(0xa1),
                transition_digest(0xa1),
                current.configuration_epoch(),
            )
            .expect("joint proof admits successor Vote routing");
        assert_eq!(
            call_test_network(&network).await,
            Ok(2),
            "a candidate absent from current membership must not claim current scope"
        );
    }

    #[tokio::test]
    async fn missing_target_and_malformed_response_fail_as_unreachable() {
        let mut factory = SessionRaftNetworkFactory::try_new(
            identity(1),
            node_id(1),
            BTreeSet::from([node_id(1)]),
            BTreeMap::new(),
        )
        .expect("valid empty routing table");
        let mut missing = factory.new_client(node_id(2), &EmptyNode::default()).await;
        assert!(matches!(
            missing
                .vote(
                    vote_request(node_id(1)),
                    RPCOption::new(Duration::from_secs(1))
                )
                .await,
            Err(EngineRpcError::Unreachable(_))
        ));

        let mut peers: BTreeMap<_, Arc<dyn SessionConsensusPeer>> = BTreeMap::new();
        peers.insert(
            node_id(2),
            Arc::new(MockPeer {
                node_id: node_id(2),
                response: SessionConsensusWireResponse {
                    result: Ok(vec![0xff, 0xff]),
                },
            }),
        );
        let mut factory = SessionRaftNetworkFactory::try_new(
            identity(1),
            node_id(1),
            BTreeSet::from([node_id(1), node_id(2)]),
            peers,
        )
        .expect("matching routing table");
        let mut malformed = factory.new_client(node_id(2), &EmptyNode::default()).await;
        assert!(matches!(
            malformed
                .vote(
                    vote_request(node_id(1)),
                    RPCOption::new(Duration::from_secs(1))
                )
                .await,
            Err(EngineRpcError::Unreachable(_))
        ));
    }

    #[test]
    fn envelope_scope_schema_and_bounds_are_fail_closed() {
        let expected_identity = identity(1);
        let sender = node_id(1);
        let payload = encode_bounded(&vote_request(sender)).expect("bounded vote");
        let mut request = SessionConsensusWireRequest::try_new(
            expected_identity,
            sender,
            SessionConsensusRpcFamily::Vote,
            payload,
        )
        .expect("valid envelope");

        assert_eq!(validate_envelope(sender, &request), Ok(()));
        assert_eq!(
            validate_envelope(node_id(2), &request),
            Err(SessionConsensusPeerError::ScopeMismatch)
        );

        request.identity = identity(2);
        assert_eq!(validate_envelope(sender, &request), Ok(()));
        request.identity = expected_identity;
        request.schema_version = SESSION_CONSENSUS_SCHEMA_VERSION + 1;
        assert_eq!(
            validate_envelope(sender, &request),
            Err(SessionConsensusPeerError::Protocol)
        );
        request.schema_version = SESSION_CONSENSUS_SCHEMA_VERSION;
        request.payload = vec![0; opc_consensus::CONSENSUS_MAX_RPC_PAYLOAD_BYTES + 1];
        assert_eq!(
            validate_envelope(sender, &request),
            Err(SessionConsensusPeerError::Protocol)
        );
    }

    #[test]
    fn inner_vote_is_bound_to_authenticated_envelope_sender() {
        let sender = node_id(1);
        let mut payload = encode_bounded(&vote_request(sender)).expect("bounded vote");
        let decoded =
            decode_and_bind_sender::<VoteRequest<SessionConsensusNodeId>>(&payload, sender)
                .expect("matching sender");
        assert_eq!(decoded.vote.leader_id.voted_for(), Some(sender));
        assert_eq!(
            decode_and_bind_sender::<VoteRequest<SessionConsensusNodeId>>(&payload, node_id(2)),
            Err(SessionConsensusPeerError::ScopeMismatch)
        );

        payload.push(0);
        assert_eq!(
            decode_and_bind_sender::<VoteRequest<SessionConsensusNodeId>>(&payload, sender),
            Err(SessionConsensusPeerError::Protocol)
        );
    }

    #[test]
    fn consumer_rpc_families_are_not_engine_authority() {
        assert!(is_engine_rpc_family(SessionConsensusRpcFamily::Vote));
        assert!(is_engine_rpc_family(
            SessionConsensusRpcFamily::AppendEntries
        ));
        assert!(is_engine_rpc_family(
            SessionConsensusRpcFamily::InstallSnapshot
        ));
        assert!(!is_engine_rpc_family(
            SessionConsensusRpcFamily::ForwardMutation
        ));
        assert!(!is_engine_rpc_family(
            SessionConsensusRpcFamily::ReadBarrier
        ));
        assert!(!is_engine_rpc_family(
            SessionConsensusRpcFamily::TopologyAdmissionBarrier
        ));
    }

    #[test]
    fn stable_id_domain_prevents_oversized_append_payloads() {
        assert_eq!(
            crate::StableId::new(Bytes::from(vec![0xa5; crate::STABLE_ID_MAX_BYTES + 1])),
            Err(crate::StableIdError::InvalidWidth)
        );
    }
}
