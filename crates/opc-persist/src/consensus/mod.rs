//! Durable configuration consensus coordinated exclusively by Openraft.
//!
//! Config payload encryption is an outer-adapter responsibility. This module
//! admits only structurally valid AEAD envelopes and finalized redacted audit
//! metadata; it never owns an HKMS/KMS provider, key handle, or plaintext
//! configuration value.

mod raft_adapter;
mod snapshot_file;
mod sqlite;
mod storage;
mod store;
mod types;

pub use store::{
    ConfigConsensusOpenError, ConfigConsensusStatus, ConfigLocalAuthorityOutcome,
    ConsensusConfigStore, DEFAULT_CONFIG_CONSENSUS_OPERATION_TIMEOUT,
};
pub use types::{
    ApprovedLegacyConfigRecovery, ConfigConsensusClock, ConfigConsensusClusterId,
    ConfigConsensusConfigurationEpoch, ConfigConsensusConfigurationId, ConfigConsensusEntryDigest,
    ConfigConsensusIdentity, ConfigConsensusIdentityError, ConfigConsensusNodeId,
    ConfigConsensusPeer, ConfigConsensusRequestId, ConfigConsensusRpcHandler,
    ConfigConsensusTopology, ConfigConsensusTopologyError, LegacyConfigTailDisposition,
    SharedConfigConsensusClock, SystemConfigConsensusClock, CONFIG_CONSENSUS_COMMAND_VERSION,
    CONFIG_CONSENSUS_MAX_MEMBERS, CONFIG_CONSENSUS_SNAPSHOT_VERSION,
    CONFIG_CONSENSUS_STORAGE_VERSION, CONFIG_CONSENSUS_WIRE_VERSION,
};
pub(crate) use types::{
    ConfigConsensusCommand, ConfigConsensusResponse, ConfigMutationFailure, ConfigMutationIntent,
    PreparedConfigCommit,
};

opc_consensus::engine::declare_raft_types!(
    /// Internal Openraft type configuration for encrypted config state.
    pub(crate) ConfigRaftTypeConfig:
        D = ConfigConsensusCommand,
        R = ConfigConsensusResponse,
        NodeId = ConfigConsensusNodeId,
        Node = opc_consensus::engine::EmptyNode,
        SnapshotData = snapshot_file::ConfigSnapshotFile,
        AsyncRuntime = opc_consensus::DurableOpenraftRuntime,
);

pub(crate) type ConfigRaft = opc_consensus::engine::Raft<ConfigRaftTypeConfig>;
