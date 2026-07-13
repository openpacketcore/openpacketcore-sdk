#![deny(missing_docs)]
//! Shared consensus substrate for SDK-owned durable state machines.
//!
//! This crate exact-pins and re-exports Openraft, and owns the identity and
//! authenticated transport envelopes shared by every SDK consensus consumer.
//! Consumers still own their deterministic state machine and durable storage,
//! but must not implement alternate election, term, vote, replication, commit,
//! membership, read-index, or snapshot-authority algorithms.

#![forbid(unsafe_code)]

pub mod codec;
pub mod identity;
pub mod profile;
pub mod transport;

/// The single consensus engine used by production-path SDK adapters.
///
/// The machine-readable HA profile remains experimental until issue #143 is
/// fully qualified.
pub use openraft as engine;

pub use codec::{decode_bounded, encode_bounded, ConsensusCodecError};

pub use identity::{
    derive_configuration_id, derive_node_id, ConsensusClusterId, ConsensusConfigurationEpoch,
    ConsensusConfigurationId, ConsensusEntryDigest, ConsensusIdentity, ConsensusIdentityError,
    ConsensusNodeId, ConsensusRequestId, CONSENSUS_CLUSTER_ID_MAX_BYTES,
    CONSENSUS_MEMBER_ID_MAX_BYTES, CONSENSUS_NODE_ID_MAX,
};
pub use profile::{
    durable_openraft_config, validate_durable_consensus_timing_profile,
    DurableConsensusTimingProfile, DurableConsensusTimingProfileError, DurableOpenraftDomain,
    DurableOpenraftProfile, DurableOpenraftProfileError, DurableOpenraftRuntime,
    DURABLE_CONSENSUS_OPERATION_TIMEOUT, DURABLE_CONSENSUS_TIMING_PROFILE,
    DURABLE_OPENRAFT_PROFILE,
};
pub use transport::{
    ConsensusPeer, ConsensusPeerError, ConsensusRpcFamily, ConsensusRpcHandler,
    ConsensusWireRequest, ConsensusWireResponse, CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
    CONSENSUS_SCHEMA_VERSION,
};
