//! Durable leader/term consensus for replicated session state.
//!
//! Openraft is exact-pinned and kept behind SDK-owned domain, storage, network,
//! and state-machine boundaries. No Openraft type is part of the documented
//! stable public session-store API or the authenticated session-net contract.

pub mod network;
pub(crate) mod raft_adapter;
pub(crate) mod snapshot;
pub(crate) mod storage;
pub(crate) mod store;
pub mod types;

pub use network::{
    SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES, SessionConsensusPeer, SessionConsensusPeerError,
    SessionConsensusRpcFamily, SessionConsensusRpcHandler, SessionConsensusWireRequest,
    SessionConsensusWireResponse,
};
pub(crate) use store::OperatorRecoveryCommitError;
pub use store::{
    ConsensusSessionConsumerService, ConsensusSessionStore, ConsensusSessionStoreOpenError,
    ConsensusStoreDiagnosticSnapshot, DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
    SessionConsensusStatus, SessionConsensusStorageAnchor, SessionTopologyCandidateBootstrap,
    SessionTopologyTransitionPeers, SessionTopologyTransportAdmission,
    SessionTopologyTransportAdmissionError, validate_consensus_physical_fenced_transition_request,
};

pub use types::{
    SESSION_CONSENSUS_CLUSTER_ID_MAX_BYTES, SESSION_CONSENSUS_SCHEMA_VERSION,
    SessionConsensusClusterId, SessionConsensusCommand, SessionConsensusConfigurationEpoch,
    SessionConsensusConfigurationId, SessionConsensusEntryDigest, SessionConsensusIdentity,
    SessionConsensusIdentityError, SessionConsensusNodeId, SessionConsensusRequestId,
    SessionConsensusResponse, SessionConsensusRpc, SessionMutationIntent, SessionMutationOutcome,
    SessionTopologyMemberBinding,
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
