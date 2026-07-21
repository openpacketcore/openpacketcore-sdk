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
use opc_consensus::engine::{EmptyNode, StoredMembership, Vote};
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
            })),
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
                });
            }
        }
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
        let desired_identity = staged.desired_identity;
        let desired = staged.routes;
        state.current_identity = staged.desired_identity;
        state.current_members = staged.desired_members.clone();
        state.active = desired;
        state.terminal = Some(SessionRaftPeerTransitionTerminal {
            transition_id,
            request_digest,
            expected_epoch,
            desired_identity,
            desired_members: desired_members.clone(),
            kind: SessionRaftPeerTransitionTerminalKind::Finalized,
        });
        Ok(())
    }

    fn resolve_engine(
        &self,
        target: SessionConsensusNodeId,
    ) -> Result<Option<SessionRaftPeerRoute>, SessionRaftAdapterError> {
        let state = self
            .state
            .read()
            .map_err(|_| SessionRaftAdapterError::PeerDirectoryUnavailable)?;
        let active = state.active.get(&target);
        let staged = state
            .staged
            .as_ref()
            .and_then(|staged| staged.routes.get(&target));
        let route = if state.current_members.contains(&self.local_node_id) {
            active.or(staged)
        } else {
            staged.or(active)
        };
        Ok(route
            .filter(|route| route.peer.node_id() == target)
            .cloned())
    }

    fn authorizes_engine(
        &self,
        sender: SessionConsensusNodeId,
        identity: SessionConsensusIdentity,
    ) -> bool {
        self.state.read().is_ok_and(|state| {
            state
                .active
                .get(&sender)
                .is_some_and(|route| route.identity == identity && route.peer.node_id() == sender)
                || state.staged.as_ref().is_some_and(|staged| {
                    staged.routes.get(&sender).is_some_and(|route| {
                        route.identity == identity && route.peer.node_id() == sender
                    })
                })
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

    /// Publish a staged successor only after Openraft reports its exact
    /// uniform voter set. This is safe to call before and after every engine
    /// RPC and makes follower-side route retirement follow the durable
    /// membership commit rather than a process-local coordinator callback.
    pub(crate) fn reconcile_committed_membership(
        &self,
        membership: &StoredMembership<SessionConsensusNodeId, EmptyNode>,
    ) -> Result<(), SessionRaftAdapterError> {
        let staged = {
            let state = self
                .state
                .read()
                .map_err(|_| SessionRaftAdapterError::PeerDirectoryUnavailable)?;
            state.staged.as_ref().map(|staged| {
                (
                    staged.transition_id,
                    staged.request_digest,
                    staged.expected_epoch,
                    staged.desired_members.clone(),
                )
            })
        };
        let Some((transition_id, request_digest, expected_epoch, desired_members)) = staged else {
            return Ok(());
        };
        let configured = membership.membership().get_joint_config();
        let nodes = membership
            .membership()
            .nodes()
            .map(|(node_id, _)| *node_id)
            .collect::<BTreeSet<_>>();
        if membership.log_id().is_some()
            && configured.len() == 1
            && configured.first() == Some(&desired_members)
            && membership.membership().learner_ids().next().is_none()
            && nodes == desired_members
        {
            self.finalize(
                transition_id,
                request_digest,
                expected_epoch,
                &desired_members,
            )?;
        }
        Ok(())
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
        let route = self
            .peer_directory
            .resolve_engine(self.target)
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

    fn reconcile_committed_membership(&self) -> Result<(), SessionRaftAdapterError> {
        let metrics = self.raft.metrics();
        let metrics = metrics.borrow();
        self.peer_directory
            .reconcile_committed_membership(metrics.membership_config.as_ref())
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
        if self.reconcile_committed_membership().is_err() {
            return rejected_response(SessionConsensusPeerError::Unavailable);
        }
        if let Err(error) = validate_envelope(authenticated_sender, &request) {
            return rejected_response(error);
        }
        if !self
            .peer_directory
            .authorizes_engine(authenticated_sender, request.identity)
        {
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
                encode_engine_result(&self.raft.install_snapshot(rpc).await)
            }
            SessionConsensusRpcFamily::ForwardMutation | SessionConsensusRpcFamily::ReadBarrier => {
                return rejected_response(SessionConsensusPeerError::Rejected);
            }
            _ => return rejected_response(SessionConsensusPeerError::Rejected),
        };

        if self.reconcile_committed_membership().is_err() {
            return rejected_response(SessionConsensusPeerError::Unavailable);
        }
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
    use std::sync::Mutex;
    use std::time::Duration;

    use bytes::Bytes;
    use opc_consensus::engine::{CommittedLeaderId, LogId, Membership};
    use tokio::sync::Notify;

    use super::*;
    use crate::consensus::{
        SessionConsensusClusterId, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId,
    };

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

        // Directory retirement stops future routing, but deliberately cannot
        // revoke an already authenticated in-flight call. The membership
        // driver must commit its inbound authority fence before finalization.
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
        directory
            .finalize(
                transition,
                digest,
                current_identity.configuration_epoch(),
                &desired_members,
            )
            .expect("finalize removal while call is blocked");

        tokio::time::advance(hard_ttl + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(
            !call.is_finished(),
            "the adapter must not duplicate Openraft's outer hard timeout"
        );

        peer.release.notify_one();
        assert_eq!(call.await.expect("adapter task"), Ok(7));

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

    #[test]
    fn peer_directory_retires_old_scope_only_after_exact_uniform_commit() {
        let local = node_id(1);
        let removed = node_id(2);
        let retained = node_id(3);
        let added = node_id(4);
        let current = identity(1);
        let desired = successor_identity(current, 9);
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
                transition_id(0xa1),
                transition_digest(0xa1),
                current.configuration_epoch(),
                desired,
                desired_members.clone(),
                desired_peers,
            )
            .expect("successor routes");

        let joint_nodes = current_members
            .union(&desired_members)
            .copied()
            .collect::<BTreeSet<_>>();
        directory
            .reconcile_committed_membership(&stored_membership(
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

        directory
            .reconcile_committed_membership(&stored_membership(
                vec![desired_members.clone()],
                desired_members.clone(),
            ))
            .expect("uniform successor commit");
        assert_eq!(
            directory.current_scope().expect("desired scope"),
            (desired, desired_members)
        );
        assert!(directory
            .resolve_engine(removed)
            .expect("directory remains available")
            .is_none());
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
                BTreeSet::from([target]),
                BTreeMap::from([(target, peer.clone())]),
            )
            .expect("stage learner peer");
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
                BTreeSet::from([target]),
                BTreeMap::from([(target, peer)]),
            )
            .expect("restage learner peer");
        directory
            .finalize(
                transition_b,
                digest_b,
                current.configuration_epoch(),
                &BTreeSet::from([target]),
            )
            .expect("promote staged peer");
        directory
            .finalize(
                transition_b,
                digest_b,
                current.configuration_epoch(),
                &BTreeSet::from([target]),
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
                &BTreeSet::from([target]),
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
        let encoded_current: Result<
            u64,
            RaftError<SessionConsensusNodeId, opc_consensus::engine::error::Infallible>,
        > = Ok(1);
        let current_peer: Arc<dyn SessionConsensusPeer> = Arc::new(ScopeCheckingPeer {
            node_id: target,
            expected_identity: current,
            response: SessionConsensusWireResponse {
                result: Ok(encode_bounded(&encoded_current).expect("bounded current response")),
            },
        });
        let mut current_peers = rejecting_peer_map(1, 3, Some(current));
        current_peers.insert(target, current_peer);
        let mut factory =
            SessionRaftNetworkFactory::try_new(current, local, current_members, current_peers)
                .expect("joining node current routing");
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
    }

    #[test]
    fn stable_id_domain_prevents_oversized_append_payloads() {
        assert_eq!(
            crate::StableId::new(Bytes::from(vec![0xa5; crate::STABLE_ID_MAX_BYTES + 1])),
            Err(crate::StableIdError::InvalidWidth)
        );
    }
}
