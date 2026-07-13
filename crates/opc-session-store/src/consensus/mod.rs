//! Durable leader/term consensus for replicated session state.
//!
//! Openraft is exact-pinned and kept behind SDK-owned domain, storage, network,
//! and state-machine boundaries. No Openraft type is part of the documented
//! stable public session-store API or the authenticated session-net contract.

pub mod network;
pub(crate) mod raft_adapter;
pub(crate) mod snapshot;
pub(crate) mod storage;
mod store;
pub mod types;

pub use network::{
    SessionConsensusPeer, SessionConsensusPeerError, SessionConsensusRpcFamily,
    SessionConsensusRpcHandler, SessionConsensusWireRequest, SessionConsensusWireResponse,
    SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
};
pub(crate) use store::OperatorRecoveryCommitError;
pub use store::{
    ConsensusSessionStore, ConsensusSessionStoreOpenError, SessionConsensusStatus,
    DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
};

pub use types::{
    SessionConsensusClusterId, SessionConsensusCommand, SessionConsensusConfigurationEpoch,
    SessionConsensusConfigurationId, SessionConsensusEntryDigest, SessionConsensusIdentity,
    SessionConsensusIdentityError, SessionConsensusNodeId, SessionConsensusRequestId,
    SessionConsensusResponse, SessionConsensusRpc, SessionMutationIntent, SessionMutationOutcome,
    SESSION_CONSENSUS_CLUSTER_ID_MAX_BYTES, SESSION_CONSENSUS_SCHEMA_VERSION,
};

opc_consensus::engine::declare_raft_types!(
    /// Internal Openraft type configuration for the session state machine.
    pub(crate) SessionRaftTypeConfig:
        D = SessionConsensusCommand,
        R = SessionConsensusResponse,
        NodeId = SessionConsensusNodeId,
        Node = opc_consensus::engine::EmptyNode,
        SnapshotData = snapshot::SessionSnapshotFile,
        AsyncRuntime = opc_consensus::DurableOpenraftRuntime,
);

pub(crate) type SessionRaft = opc_consensus::engine::Raft<SessionRaftTypeConfig>;
