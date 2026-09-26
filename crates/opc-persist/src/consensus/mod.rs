//! Durable configuration consensus coordinated exclusively by Openraft.
//!
//! Config payload encryption is an outer-adapter responsibility. This module
//! admits only structurally valid AEAD envelopes and finalized redacted audit
//! metadata; it never owns an HKMS/KMS provider, key handle, or plaintext
//! configuration value.

mod audit;
mod audit_mutation;
pub use audit_mutation::PreparedAuditedMutation;
mod capacity_record;
mod config_capacity_decode;
mod config_capacity_json;
pub(crate) mod history;
mod preparation;
mod raft_adapter;
mod snapshot_file;
mod sqlite;
pub(crate) use sqlite::run_backend_sqlite_with_timeout;
mod storage;
pub(crate) use storage::ConfigConsensusStorageError;
mod store;
mod types;

#[cfg(test)]
pub(crate) mod config_capacity_simultaneous_working_tests;

pub(crate) use sqlite::{provision_retained_schema, validate_retained_schema};

pub use history::{ConfigHistoryLimits, ConfigHistoryRetention};

pub use store::{
    ConfigCommitRecoveryHandle, ConfigCommitRecoveryOutcome, ConfigConsensusOpenError,
    ConfigConsensusStatus, ConfigLocalAuthorityOutcome, ConsensusConfigStore,
    PreparedConfigCommitOperation, DEFAULT_CONFIG_CONSENSUS_OPERATION_TIMEOUT,
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
