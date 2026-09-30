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

use super::types::{decode_config_wire_for_profile, encode_config_wire_for_profile};
use super::{ConfigRaft, ConfigRaftTypeConfig};

#[cfg(test)]
mod config_capacity_snapshot_extent_tests;

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
    mode: super::RetainedConfigMode,
    append_encoding: Option<Arc<tokio::sync::Mutex<()>>>,
}

impl ConfigRaftNetworkFactory {
    pub(crate) fn try_new(
        identity: ConsensusIdentity,
        local_node_id: ConsensusNodeId,
        peers: BTreeMap<ConsensusNodeId, Arc<dyn ConsensusPeer>>,
        mode: super::RetainedConfigMode,
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
            mode,
            append_encoding: (mode.capacity_profile()
                == opc_crypto::ConfigCapacityProfile::BoundedV1)
                .then(|| Arc::new(tokio::sync::Mutex::new(()))),
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
            mode: self.mode,
            identity: self.identity,
            local_node_id: self.local_node_id,
            target,
            append_encoding: self.append_encoding.clone(),
            peer: self
                .peers
                .get(&target)
                .filter(|peer| peer.node_id() == target)
                .cloned(),
        }
    }
}

pub(crate) struct ConfigRaftNetwork {
    mode: super::RetainedConfigMode,
    identity: ConsensusIdentity,
    local_node_id: ConsensusNodeId,
    target: ConsensusNodeId,
    peer: Option<Arc<dyn ConsensusPeer>>,
    append_encoding: Option<Arc<tokio::sync::Mutex<()>>>,
}

// Fields drop in declaration order, including on cancellation and unwinding.
// Retire the actual typed request before another client may create its output.
struct AppendEncoding<'a> {
    #[cfg(feature = "dangerous-test-hooks")]
    request: super::capacity_observation::raft_buffers::OriginalAppend,
    #[cfg(not(feature = "dangerous-test-hooks"))]
    request: AppendEntriesRequest<ConfigRaftTypeConfig>,
    _guard: Option<tokio::sync::MutexGuard<'a, ()>>,
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
    // OpenRaft requires this transport error type; boxing it would change the
    // adapter's prescribed RPC error contract.
    #[allow(clippy::result_large_err)]
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
        #[cfg(feature = "dangerous-test-hooks")]
        let timeout_before = tokio::time::Instant::now();
        let response = tokio::time::timeout(ttl, peer.call(wire));
        #[cfg(feature = "dangerous-test-hooks")]
        let response = super::capacity_observation::raft_buffers::scope_rpc_deadline(
            ttl,
            timeout_before,
            tokio::time::Instant::now(),
            response,
        );
        let response = match response.await {
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
        let result: Result<Resp, RaftError<ConsensusNodeId, E>> =
            decode_config_wire_for_profile(self.mode, &payload).map_err(|error| {
                EngineRpcError::Unreachable(Unreachable::new(&CodecTransportError(error)))
            })?;
        result.map_err(|error| EngineRpcError::RemoteError(RemoteError::new(self.target, error)))
    }

    // OpenRaft's append RPC must retain its prescribed transport error type.
    #[allow(clippy::result_large_err)]
    async fn append(
        &self,
        request: AppendEntriesRequest<ConfigRaftTypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<ConsensusNodeId>, EngineRpcError> {
        #[cfg(feature = "dangerous-test-hooks")]
        let request = super::capacity_observation::raft_buffers::OriginalAppend::start(
            self.identity,
            self.local_node_id,
            self.target,
            request,
        );
        // All clients and later clients from the same factory share this
        // guard. Waiting still owns (and observes) the original decoded DTO;
        // only the typed-plus-encoded pair is serialized. Openraft's existing
        // outer RPC timeout includes this wait. Peer IO never holds the guard.
        let guard = match &self.append_encoding {
            Some(encoding) => {
                let wait = encoding.lock();
                #[cfg(all(test, target_os = "linux", feature = "dangerous-test-hooks"))]
                let wait = super::types::config_capacity_parallel_encoding_tests::observe_wait(
                    encoding, wait,
                );
                Some(wait.await)
            }
            None => None,
        };
        let request = AppendEncoding {
            request,
            _guard: guard,
        };
        #[cfg(feature = "dangerous-test-hooks")]
        let typed = request.request.borrow();
        #[cfg(not(feature = "dangerous-test-hooks"))]
        let typed = &request.request;
        let entry_count = typed.entries.len();
        let payload = match encode_config_wire_for_profile(self.mode, typed) {
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
                )))
            }
        };
        #[cfg(all(test, target_os = "linux", feature = "dangerous-test-hooks"))]
        super::types::config_capacity_parallel_encoding_tests::encoded(
            &payload,
            request._guard.as_ref(),
        );
        #[cfg(feature = "dangerous-test-hooks")]
        let observation = super::capacity_observation::append_context(
            self.identity,
            self.local_node_id,
            self.target,
            typed,
            &payload,
        );
        #[cfg(feature = "dangerous-test-hooks")]
        let original_wire = request.request.wire(&payload);
        #[cfg(all(feature = "dangerous-test-hooks", test))]
        request.request.before_drop().await;
        #[cfg(all(test, target_os = "linux", feature = "dangerous-test-hooks"))]
        super::types::config_capacity_parallel_encoding_tests::original_ready(
            &payload,
            request._guard.as_ref(),
        );
        // Each follower has independently decoded the typed log batch. This
        // physically drops that DTO before unlocking; IO needs only the wire.
        drop(request);
        let call = self.call(
            ConsensusRpcFamily::AppendEntries,
            opc_consensus::engine::RPCTypes::AppendEntries,
            payload,
            option,
        );
        #[cfg(feature = "dangerous-test-hooks")]
        let call = super::capacity_observation::scope_transport(observation, call);
        #[cfg(feature = "dangerous-test-hooks")]
        let call = super::capacity_observation::raft_buffers::scope_wire(original_wire, call);
        call.await
    }
}

fn append_entries_split_hint(entry_count: usize) -> Option<u64> {
    (entry_count > 1).then(|| u64::try_from((entry_count / 2).max(1)).unwrap_or(u64::MAX))
}

impl RaftNetwork<ConfigRaftTypeConfig> for ConfigRaftNetwork {
    async fn append_entries(
        &mut self,
        request: AppendEntriesRequest<ConfigRaftTypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<ConsensusNodeId>, EngineRpcError> {
        self.append(request, option).await
    }

    async fn install_snapshot(
        &mut self,
        request: InstallSnapshotRequest<ConfigRaftTypeConfig>,
        option: RPCOption,
    ) -> Result<InstallSnapshotResponse<ConsensusNodeId>, EngineRpcError<InstallSnapshotError>>
    {
        let payload = encode_config_wire_for_profile(self.mode, &request).map_err(|error| {
            EngineRpcError::Unreachable(Unreachable::new(&CodecTransportError(error)))
        })?;
        #[cfg(feature = "dangerous-test-hooks")]
        let observation = super::capacity_observation::snapshot_context(
            self.identity,
            self.local_node_id,
            self.target,
            &request.data,
            &payload,
        );
        let call = self.call(
            ConsensusRpcFamily::InstallSnapshot,
            opc_consensus::engine::RPCTypes::InstallSnapshot,
            payload,
            option,
        );
        #[cfg(feature = "dangerous-test-hooks")]
        let call = super::capacity_observation::scope_transport(observation, call);
        call.await
    }

    async fn vote(
        &mut self,
        request: VoteRequest<ConsensusNodeId>,
        option: RPCOption,
    ) -> Result<VoteResponse<ConsensusNodeId>, EngineRpcError> {
        let payload = encode_config_wire_for_profile(self.mode, &request).map_err(|error| {
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
    mode: super::RetainedConfigMode,
    audit_key: crate::AuditKey,
}

impl ConfigRaftRpcHandler {
    pub(crate) fn new(
        raft: ConfigRaft,
        identity: ConsensusIdentity,
        local_node_id: ConsensusNodeId,
        mode: super::RetainedConfigMode,
        audit_key: crate::AuditKey,
    ) -> Self {
        Self {
            raft,
            identity,
            local_node_id,
            mode,
            audit_key,
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
                    self.mode,
                ) {
                    Ok(rpc) => rpc,
                    Err(error) => return rejected_response(error),
                };
                if super::sqlite::validate_entry_capacities(
                    &rpc.entries,
                    self.identity,
                    &self.audit_key,
                    self.mode,
                )
                .is_err()
                {
                    return rejected_response(ConsensusPeerError::Rejected);
                }
                encode_engine_result(self.mode, &self.raft.append_entries(rpc).await)
            }
            ConsensusRpcFamily::Vote => {
                let rpc = match decode_and_bind_sender::<VoteRequest<ConsensusNodeId>>(
                    &request.payload,
                    request.sender,
                    self.mode,
                ) {
                    Ok(rpc) => rpc,
                    Err(error) => return rejected_response(error),
                };
                encode_engine_result(self.mode, &self.raft.vote(rpc).await)
            }
            ConsensusRpcFamily::InstallSnapshot => {
                let rpc = match decode_and_bind_sender::<InstallSnapshotRequest<ConfigRaftTypeConfig>>(
                    &request.payload,
                    request.sender,
                    self.mode,
                ) {
                    Ok(rpc) => rpc,
                    Err(error) => return rejected_response(error),
                };
                encode_engine_result(self.mode, &self.raft.install_snapshot(rpc).await)
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

trait EngineRequestSender: Sized {
    fn vote(&self) -> &Vote<ConsensusNodeId>;

    fn decode(
        profile: super::RetainedConfigMode,
        payload: &[u8],
    ) -> Result<Self, ConsensusCodecError>;
}

impl EngineRequestSender for AppendEntriesRequest<ConfigRaftTypeConfig> {
    fn decode(
        profile: super::RetainedConfigMode,
        payload: &[u8],
    ) -> Result<Self, ConsensusCodecError> {
        if profile.capacity_profile() == opc_crypto::ConfigCapacityProfile::BoundedV1 {
            super::config_capacity_decode::engine::append(profile, payload)
        } else {
            decode_config_wire_for_profile(profile, payload)
        }
    }

    fn vote(&self) -> &Vote<ConsensusNodeId> {
        &self.vote
    }
}

impl EngineRequestSender for VoteRequest<ConsensusNodeId> {
    fn decode(
        profile: super::RetainedConfigMode,
        payload: &[u8],
    ) -> Result<Self, ConsensusCodecError> {
        decode_config_wire_for_profile(profile, payload)
    }

    fn vote(&self) -> &Vote<ConsensusNodeId> {
        &self.vote
    }
}

impl EngineRequestSender for InstallSnapshotRequest<ConfigRaftTypeConfig> {
    fn decode(
        profile: super::RetainedConfigMode,
        payload: &[u8],
    ) -> Result<Self, ConsensusCodecError> {
        super::config_capacity_decode::engine::snapshot(profile, payload)
    }

    fn vote(&self) -> &Vote<ConsensusNodeId> {
        &self.vote
    }
}

fn decode_and_bind_sender<T>(
    payload: &[u8],
    sender: ConsensusNodeId,
    mode: super::RetainedConfigMode,
) -> Result<T, ConsensusPeerError>
where
    T: DeserializeOwned + EngineRequestSender,
{
    let request = T::decode(mode, payload).map_err(|_| ConsensusPeerError::Protocol)?;
    if request.vote().leader_id.voted_for() != Some(sender) {
        return Err(ConsensusPeerError::ScopeMismatch);
    }
    Ok(request)
}

fn encode_engine_result<T, E>(
    mode: super::RetainedConfigMode,
    result: &Result<T, E>,
) -> Result<Vec<u8>, ConsensusPeerError>
where
    T: Serialize,
    E: Serialize,
{
    encode_config_wire_for_profile(mode, result).map_err(|_| ConsensusPeerError::Protocol)
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

#[cfg(test)]
mod tests {
    use super::append_entries_split_hint;

    #[test]
    fn append_entries_split_hint_never_retries_a_singleton_as_payload_too_large() {
        assert_eq!(append_entries_split_hint(0), None);
        assert_eq!(append_entries_split_hint(1), None);
        assert_eq!(append_entries_split_hint(2), Some(1));
        assert_eq!(append_entries_split_hint(64), Some(32));
    }
}
