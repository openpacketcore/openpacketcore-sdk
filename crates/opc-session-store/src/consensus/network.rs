//! Session-facing names for the shared consensus-only transport port.

pub use opc_consensus::{
    forward_pre_vote as forward_session_consensus_pre_vote, ConsensusPeer as SessionConsensusPeer,
    ConsensusPeerError as SessionConsensusPeerError,
    ConsensusRpcFamily as SessionConsensusRpcFamily,
    ConsensusRpcHandler as SessionConsensusRpcHandler,
    ConsensusWireRequest as SessionConsensusWireRequest,
    ConsensusWireResponse as SessionConsensusWireResponse,
    PreVoteCall as SessionConsensusPreVoteCall,
    CONSENSUS_MAX_RPC_PAYLOAD_BYTES as SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
};
