//! Private Openraft adapter over the shared authenticated consensus transport.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use opc_consensus::engine::error::{
    InstallSnapshotError, PayloadTooLarge, RPCError, RaftError, RemoteError, Timeout, Unreachable,
};
use opc_consensus::engine::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use opc_consensus::engine::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use opc_consensus::engine::{EmptyNode, Vote};
use opc_consensus::{
    ConsensusCodecError, ConsensusIdentity, ConsensusNodeId, ConsensusPeer, ConsensusPeerError,
    ConsensusRpcFamily, ConsensusRpcHandler, ConsensusWireRequest, ConsensusWireResponse,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;

use super::types::{decode_config_wire, encode_config_wire};
use super::{ConfigRaft, ConfigRaftTypeConfig};

type EngineRpcError<E = opc_consensus::engine::error::Infallible> =
    RPCError<ConsensusNodeId, EmptyNode, RaftError<ConsensusNodeId, E>>;

/// Fail-closed network-factory construction error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ConfigRaftAdapterError {
    /// A route key did not match the peer's authenticated canonical node ID.
    #[error("config consensus peer node identity does not match routing key")]
    PeerNodeIdMismatch,
}

/// Openraft network factory backed only by shared consensus peers.
#[derive(Clone)]
pub(crate) struct ConfigRaftNetworkFactory {
    identity: ConsensusIdentity,
    local_node_id: ConsensusNodeId,
    peers: Arc<BTreeMap<ConsensusNodeId, Arc<dyn ConsensusPeer>>>,
}

impl ConfigRaftNetworkFactory {
    pub(crate) fn try_new(
        identity: ConsensusIdentity,
        local_node_id: ConsensusNodeId,
        peers: BTreeMap<ConsensusNodeId, Arc<dyn ConsensusPeer>>,
    ) -> Result<Self, ConfigRaftAdapterError> {
        if peers
            .iter()
            .any(|(node_id, peer)| peer.node_id() != *node_id)
        {
            return Err(ConfigRaftAdapterError::PeerNodeIdMismatch);
        }
        Ok(Self {
            identity,
            local_node_id,
            peers: Arc::new(peers),
        })
    }
}

impl fmt::Debug for ConfigRaftNetworkFactory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigRaftNetworkFactory")
            .field("identity", &self.identity)
            .field("local_node_id", &self.local_node_id)
            .field("peer_count", &self.peers.len())
            .finish()
    }
}

impl RaftNetworkFactory<ConfigRaftTypeConfig> for ConfigRaftNetworkFactory {
    type Network = ConfigRaftNetwork;

    async fn new_client(&mut self, target: ConsensusNodeId, _node: &EmptyNode) -> Self::Network {
        ConfigRaftNetwork {
            identity: self.identity,
            local_node_id: self.local_node_id,
            target,
            peer: self
                .peers
                .get(&target)
                .filter(|peer| peer.node_id() == target)
                .cloned(),
        }
    }
}

pub(crate) struct ConfigRaftNetwork {
    identity: ConsensusIdentity,
    local_node_id: ConsensusNodeId,
    target: ConsensusNodeId,
    peer: Option<Arc<dyn ConsensusPeer>>,
}

impl fmt::Debug for ConfigRaftNetwork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigRaftNetwork")
            .field("identity", &self.identity)
            .field("local_node_id", &self.local_node_id)
            .field("target", &self.target)
            .field("peer_configured", &self.peer.is_some())
            .finish()
    }
}

impl ConfigRaftNetwork {
    async fn call<Resp, E>(
        &self,
        family: ConsensusRpcFamily,
        action: opc_consensus::engine::RPCTypes,
        payload: Vec<u8>,
        option: RPCOption,
    ) -> Result<Resp, EngineRpcError<E>>
    where
        Resp: DeserializeOwned,
        E: std::error::Error + DeserializeOwned,
    {
        let peer = self
            .peer
            .as_ref()
            .ok_or_else(|| EngineRpcError::Unreachable(Unreachable::new(&MissingConsensusPeer)))?;
        if peer.node_id() != self.target {
            return Err(EngineRpcError::Unreachable(Unreachable::new(
                &PeerIdentityChanged,
            )));
        }
        let wire =
            ConsensusWireRequest::try_new(self.identity, self.local_node_id, family, payload)
                .map_err(|error| EngineRpcError::Unreachable(Unreachable::new(&error)))?;
        let ttl = option.hard_ttl();
        let response = match tokio::time::timeout(ttl, peer.call(wire)).await {
            Err(_) => {
                return Err(EngineRpcError::Timeout(Timeout {
                    action,
                    id: self.local_node_id,
                    target: self.target,
                    timeout: ttl,
                }))
            }
            Ok(Err(error)) => return Err(map_peer_error(error, action, self, ttl)),
            Ok(Ok(response)) => response,
        };
        response
            .validate()
            .map_err(|error| EngineRpcError::Unreachable(Unreachable::new(&error)))?;
        let payload = response
            .result
            .map_err(|error| map_peer_error(error, action, self, ttl))?;
        let result: Result<Resp, RaftError<ConsensusNodeId, E>> = decode_config_wire(&payload)
            .map_err(|error| {
                EngineRpcError::Unreachable(Unreachable::new(&CodecTransportError(error)))
            })?;
        result.map_err(|error| EngineRpcError::RemoteError(RemoteError::new(self.target, error)))
    }

    async fn append(
        &self,
        request: &AppendEntriesRequest<ConfigRaftTypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<ConsensusNodeId>, EngineRpcError> {
        let entry_count = request.entries.len();
        let payload = match encode_config_wire(request) {
            Ok(payload) => payload,
            Err(ConsensusCodecError::TooLarge) if entry_count > 0 => {
                let entries_hint = u64::try_from((entry_count / 2).max(1)).unwrap_or(u64::MAX);
                return Err(EngineRpcError::PayloadTooLarge(
                    PayloadTooLarge::new_entries_hint(entries_hint),
                ));
            }
            Err(error) => {
                return Err(EngineRpcError::Unreachable(Unreachable::new(
                    &CodecTransportError(error),
                )))
            }
        };
        self.call(
            ConsensusRpcFamily::AppendEntries,
            opc_consensus::engine::RPCTypes::AppendEntries,
            payload,
            option,
        )
        .await
    }
}

impl RaftNetwork<ConfigRaftTypeConfig> for ConfigRaftNetwork {
    async fn append_entries(
        &mut self,
        request: AppendEntriesRequest<ConfigRaftTypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<ConsensusNodeId>, EngineRpcError> {
        self.append(&request, option).await
    }

    async fn install_snapshot(
        &mut self,
        request: InstallSnapshotRequest<ConfigRaftTypeConfig>,
        option: RPCOption,
    ) -> Result<InstallSnapshotResponse<ConsensusNodeId>, EngineRpcError<InstallSnapshotError>>
    {
        let payload = encode_config_wire(&request).map_err(|error| {
            EngineRpcError::Unreachable(Unreachable::new(&CodecTransportError(error)))
        })?;
        self.call(
            ConsensusRpcFamily::InstallSnapshot,
            opc_consensus::engine::RPCTypes::InstallSnapshot,
            payload,
            option,
        )
        .await
    }

    async fn vote(
        &mut self,
        request: VoteRequest<ConsensusNodeId>,
        option: RPCOption,
    ) -> Result<VoteResponse<ConsensusNodeId>, EngineRpcError> {
        let payload = encode_config_wire(&request).map_err(|error| {
            EngineRpcError::Unreachable(Unreachable::new(&CodecTransportError(error)))
        })?;
        self.call(
            ConsensusRpcFamily::Vote,
            opc_consensus::engine::RPCTypes::Vote,
            payload,
            option,
        )
        .await
    }
}

fn map_peer_error<E>(
    error: ConsensusPeerError,
    action: opc_consensus::engine::RPCTypes,
    network: &ConfigRaftNetwork,
    ttl: std::time::Duration,
) -> EngineRpcError<E>
where
    E: std::error::Error,
{
    match error {
        ConsensusPeerError::Timeout => EngineRpcError::Timeout(Timeout {
            action,
            id: network.local_node_id,
            target: network.target,
            timeout: ttl,
        }),
        ConsensusPeerError::Authentication => {
            opc_redaction::metrics::METRICS
                .persist_rpc_auth_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            EngineRpcError::Unreachable(Unreachable::new(&error))
        }
        _ => EngineRpcError::Unreachable(Unreachable::new(&error)),
    }
}

/// Engine-only inbound handler. Consumer forwarding is composed outside it.
#[derive(Clone)]
pub(crate) struct ConfigRaftRpcHandler {
    raft: ConfigRaft,
    identity: ConsensusIdentity,
    local_node_id: ConsensusNodeId,
}

impl ConfigRaftRpcHandler {
    pub(crate) const fn new(
        raft: ConfigRaft,
        identity: ConsensusIdentity,
        local_node_id: ConsensusNodeId,
    ) -> Self {
        Self {
            raft,
            identity,
            local_node_id,
        }
    }
}

impl fmt::Debug for ConfigRaftRpcHandler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConfigRaftRpcHandler")
            .field("identity", &self.identity)
            .field("local_node_id", &self.local_node_id)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl ConsensusRpcHandler for ConfigRaftRpcHandler {
    async fn handle(
        &self,
        authenticated_sender: ConsensusNodeId,
        request: ConsensusWireRequest,
    ) -> ConsensusWireResponse {
        if let Err(error) = validate_envelope(self.identity, authenticated_sender, &request) {
            return rejected_response(error);
        }
        let result = match request.family {
            ConsensusRpcFamily::AppendEntries => {
                let rpc = match decode_and_bind_sender::<AppendEntriesRequest<ConfigRaftTypeConfig>>(
                    &request.payload,
                    request.sender,
                ) {
                    Ok(rpc) => rpc,
                    Err(error) => return rejected_response(error),
                };
                encode_engine_result(&self.raft.append_entries(rpc).await)
            }
            ConsensusRpcFamily::Vote => {
                let rpc = match decode_and_bind_sender::<VoteRequest<ConsensusNodeId>>(
                    &request.payload,
                    request.sender,
                ) {
                    Ok(rpc) => rpc,
                    Err(error) => return rejected_response(error),
                };
                encode_engine_result(&self.raft.vote(rpc).await)
            }
            ConsensusRpcFamily::InstallSnapshot => {
                let rpc = match decode_and_bind_sender::<InstallSnapshotRequest<ConfigRaftTypeConfig>>(
                    &request.payload,
                    request.sender,
                ) {
                    Ok(rpc) => rpc,
                    Err(error) => return rejected_response(error),
                };
                encode_engine_result(&self.raft.install_snapshot(rpc).await)
            }
            _ => return rejected_response(ConsensusPeerError::Rejected),
        };
        match result {
            Ok(payload) => ConsensusWireResponse {
                result: Ok(payload),
            },
            Err(error) => rejected_response(error),
        }
    }
}

fn validate_envelope(
    identity: ConsensusIdentity,
    authenticated_sender: ConsensusNodeId,
    request: &ConsensusWireRequest,
) -> Result<(), ConsensusPeerError> {
    request.validate()?;
    if request.schema_version != opc_consensus::CONSENSUS_SCHEMA_VERSION
        || request.identity != identity
        || request.sender != authenticated_sender
    {
        return Err(ConsensusPeerError::ScopeMismatch);
    }
    Ok(())
}

trait EngineRequestSender {
    fn vote(&self) -> &Vote<ConsensusNodeId>;
}

impl EngineRequestSender for AppendEntriesRequest<ConfigRaftTypeConfig> {
    fn vote(&self) -> &Vote<ConsensusNodeId> {
        &self.vote
    }
}

impl EngineRequestSender for VoteRequest<ConsensusNodeId> {
    fn vote(&self) -> &Vote<ConsensusNodeId> {
        &self.vote
    }
}

impl EngineRequestSender for InstallSnapshotRequest<ConfigRaftTypeConfig> {
    fn vote(&self) -> &Vote<ConsensusNodeId> {
        &self.vote
    }
}

fn decode_and_bind_sender<T>(
    payload: &[u8],
    sender: ConsensusNodeId,
) -> Result<T, ConsensusPeerError>
where
    T: DeserializeOwned + EngineRequestSender,
{
    let request: T = decode_config_wire(payload).map_err(|_| ConsensusPeerError::Protocol)?;
    if request.vote().leader_id.voted_for() != Some(sender) {
        return Err(ConsensusPeerError::ScopeMismatch);
    }
    Ok(request)
}

fn encode_engine_result<T, E>(result: &Result<T, E>) -> Result<Vec<u8>, ConsensusPeerError>
where
    T: Serialize,
    E: Serialize,
{
    encode_config_wire(result).map_err(|_| ConsensusPeerError::Protocol)
}

fn rejected_response(error: ConsensusPeerError) -> ConsensusWireResponse {
    ConsensusWireResponse { result: Err(error) }
}

#[derive(Debug, Error)]
#[error("consensus peer is not configured")]
struct MissingConsensusPeer;

#[derive(Debug, Error)]
#[error("consensus peer identity changed")]
struct PeerIdentityChanged;

#[derive(Debug, Error)]
#[error("consensus codec rejected engine payload")]
struct CodecTransportError(#[source] ConsensusCodecError);
