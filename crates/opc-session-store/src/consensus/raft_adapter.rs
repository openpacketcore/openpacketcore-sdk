//! Private Openraft transport adapter for the session consensus service.
//!
//! The authenticated transport carries only bounded, identity-scoped engine
//! RPCs. It deliberately does not implement any session-backend operation or
//! alternate replication/repair authority.

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

type EngineRpcError<E = opc_consensus::engine::error::Infallible> =
    RPCError<SessionConsensusNodeId, EmptyNode, RaftError<SessionConsensusNodeId, E>>;

/// Fail-closed construction error for the private Openraft network factory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum SessionRaftAdapterError {
    /// A peer was registered under a node ID different from its authenticated
    /// transport identity.
    #[error("session consensus peer node identity does not match its routing key")]
    PeerNodeIdMismatch,
}

/// Openraft network factory backed exclusively by consensus-only peers.
#[derive(Clone)]
pub(crate) struct SessionRaftNetworkFactory {
    identity: SessionConsensusIdentity,
    local_node_id: SessionConsensusNodeId,
    peers: Arc<BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>>,
}

impl SessionRaftNetworkFactory {
    /// Bind the engine network to one immutable cluster scope and canonical
    /// node-ID routing table.
    pub(crate) fn try_new(
        identity: SessionConsensusIdentity,
        local_node_id: SessionConsensusNodeId,
        peers: BTreeMap<SessionConsensusNodeId, Arc<dyn SessionConsensusPeer>>,
    ) -> Result<Self, SessionRaftAdapterError> {
        if peers
            .iter()
            .any(|(node_id, peer)| peer.node_id() != *node_id)
        {
            return Err(SessionRaftAdapterError::PeerNodeIdMismatch);
        }

        Ok(Self {
            identity,
            local_node_id,
            peers: Arc::new(peers),
        })
    }
}

impl fmt::Debug for SessionRaftNetworkFactory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRaftNetworkFactory")
            .field("identity", &self.identity)
            .field("local_node_id", &self.local_node_id)
            .field("peer_count", &self.peers.len())
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
        let peer = self
            .peers
            .get(&target)
            .filter(|peer| peer.node_id() == target)
            .cloned();

        SessionRaftNetwork {
            identity: self.identity,
            local_node_id: self.local_node_id,
            target,
            peer,
        }
    }
}

/// One target-bound private Openraft connection.
pub(crate) struct SessionRaftNetwork {
    identity: SessionConsensusIdentity,
    local_node_id: SessionConsensusNodeId,
    target: SessionConsensusNodeId,
    peer: Option<Arc<dyn SessionConsensusPeer>>,
}

impl fmt::Debug for SessionRaftNetwork {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRaftNetwork")
            .field("identity", &self.identity)
            .field("local_node_id", &self.local_node_id)
            .field("target", &self.target)
            .field("peer_configured", &self.peer.is_some())
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
        let peer = self
            .peer
            .as_ref()
            .ok_or_else(|| EngineRpcError::Unreachable(Unreachable::new(&MissingConsensusPeer)))?;
        if peer.node_id() != self.target {
            return Err(EngineRpcError::Unreachable(Unreachable::new(
                &PeerIdentityChanged,
            )));
        }

        let wire = SessionConsensusWireRequest::try_new(
            self.identity,
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
    identity: SessionConsensusIdentity,
    local_node_id: SessionConsensusNodeId,
}

impl SessionRaftRpcHandler {
    pub(crate) fn new(
        raft: SessionRaft,
        identity: SessionConsensusIdentity,
        local_node_id: SessionConsensusNodeId,
    ) -> Self {
        Self {
            raft,
            identity,
            local_node_id,
        }
    }
}

impl fmt::Debug for SessionRaftRpcHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionRaftRpcHandler")
            .field("identity", &self.identity)
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
        if let Err(error) = validate_envelope(self.identity, authenticated_sender, &request) {
            return rejected_response(error);
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

        match result {
            Ok(payload) => SessionConsensusWireResponse {
                result: Ok(payload),
            },
            Err(error) => rejected_response(error),
        }
    }
}

fn validate_envelope(
    expected_identity: SessionConsensusIdentity,
    authenticated_sender: SessionConsensusNodeId,
    request: &SessionConsensusWireRequest,
) -> Result<(), SessionConsensusPeerError> {
    request.validate()?;
    if request.schema_version != SESSION_CONSENSUS_SCHEMA_VERSION
        || request.identity != expected_identity
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
            _request: SessionConsensusWireRequest,
            timeout: Duration,
        ) -> Result<SessionConsensusWireResponse, SessionConsensusPeerError> {
            *self
                .observed_timeout
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(timeout);
            self.entered.notify_one();
            self.release.notified().await;
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

    fn vote_request(sender: SessionConsensusNodeId) -> VoteRequest<SessionConsensusNodeId> {
        VoteRequest::new(Vote::new(7, sender), None)
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
            entered: Notify::new(),
            release: Notify::new(),
            response: SessionConsensusWireResponse {
                result: Ok(encode_bounded(&encoded_result).expect("bounded test response")),
            },
        });
        let network = SessionRaftNetwork {
            identity: identity(1),
            local_node_id: node_id(1),
            target,
            peer: Some(peer.clone()),
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

        tokio::time::advance(hard_ttl + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        assert!(
            !call.is_finished(),
            "the adapter must not duplicate Openraft's outer hard timeout"
        );

        peer.release.notify_one();
        assert_eq!(call.await.expect("adapter task"), Ok(7));
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
            SessionRaftNetworkFactory::try_new(identity(1), node_id(3), peers),
            Err(SessionRaftAdapterError::PeerNodeIdMismatch)
        ));
    }

    #[tokio::test]
    async fn missing_target_and_malformed_response_fail_as_unreachable() {
        let mut factory =
            SessionRaftNetworkFactory::try_new(identity(1), node_id(1), BTreeMap::new())
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
        let mut factory = SessionRaftNetworkFactory::try_new(identity(1), node_id(1), peers)
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

        assert_eq!(
            validate_envelope(expected_identity, sender, &request),
            Ok(())
        );
        assert_eq!(
            validate_envelope(expected_identity, node_id(2), &request),
            Err(SessionConsensusPeerError::ScopeMismatch)
        );

        request.identity = identity(2);
        assert_eq!(
            validate_envelope(expected_identity, sender, &request),
            Err(SessionConsensusPeerError::ScopeMismatch)
        );
        request.identity = expected_identity;
        request.schema_version = SESSION_CONSENSUS_SCHEMA_VERSION + 1;
        assert_eq!(
            validate_envelope(expected_identity, sender, &request),
            Err(SessionConsensusPeerError::Protocol)
        );
        request.schema_version = SESSION_CONSENSUS_SCHEMA_VERSION;
        request.payload = vec![0; opc_consensus::CONSENSUS_MAX_RPC_PAYLOAD_BYTES + 1];
        assert_eq!(
            validate_envelope(expected_identity, sender, &request),
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
