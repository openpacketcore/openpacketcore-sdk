//! Networked session replication transport for OpenPacketCore (experimental).
//!
//! Provides bounded length-prefixed transports for session state. The
//! production consensus boundary is [`SessionConsensusServer`] and
//! [`RemoteSessionConsensusPeer`] over a dedicated ALPN; those types expose
//! only the shared consensus handler/peer ports and cannot perform raw backend
//! mutation or rebuild operations. The legacy remote-backend client, server,
//! and public protocol surface are quarantined behind the non-default
//! `legacy-session-net-compat` feature for controlled migration work.
//! Endpoints derive their local/remote authority from one immutable
//! [`SessionReplicationManifest`]. Consensus peers bind the claimed stable
//! replica IDs and manifest scope to the canonical SPIFFE identities extracted
//! from the live mutual-TLS connection, and prove the exact same
//! [`SessionConsensusContractProfile`] before an operation is dispatched.

#![forbid(unsafe_code)]

#[cfg(feature = "legacy-session-net-compat")]
pub mod client;
pub mod consensus;
pub mod error;
pub mod identity;
#[cfg(not(feature = "legacy-session-net-compat"))]
mod protocol;
#[cfg(feature = "legacy-session-net-compat")]
pub mod protocol;
#[cfg(feature = "legacy-session-net-compat")]
pub mod server;

#[cfg(feature = "legacy-session-net-compat")]
pub use client::RemoteSessionBackend;
pub use consensus::{
    RemoteAddrResolver, RemoteSessionConsensusPeer, SessionConsensusServer,
    SessionConsensusServerHandle,
};
pub use error::ProtocolError;
pub use identity::{
    LocalReplicaBinding, RemoteReplicaBinding, SessionClusterId, SessionConfigurationEpoch,
    SessionConfigurationGeneration, SessionConfigurationId, SessionManifestError,
    SessionReplicationManifest,
};
pub use opc_consensus::{
    ConsensusClusterId, ConsensusConfigurationEpoch, ConsensusConfigurationId, ConsensusIdentity,
    ConsensusNodeId,
};
#[cfg(feature = "legacy-session-net-compat")]
pub use protocol::{
    conservative_payload_budget, ContractProfile, HelloRejectReason, Request, Response,
    CURRENT_CONTRACT_PROFILE, MAX_SESSION_NET_BATCH_OPERATIONS, MAX_SESSION_NET_REBUILD_ENTRIES,
    MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES, MAX_SESSION_NET_REPLICATION_TX_ID_BYTES,
    MAX_SESSION_NET_STABLE_ID_BYTES, MIN_NEGOTIATED_FRAME_SIZE, SESSION_NET_CAS_REQUEST_ID_BYTES,
};
pub use protocol::{
    SessionConsensusContractProfile, CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE,
    MAX_NEGOTIATED_FRAME_SIZE, MIN_SESSION_CONSENSUS_FRAME_SIZE, SESSION_CONSENSUS_ALPN,
    SESSION_CONSENSUS_TRANSPORT_REVISION,
};
#[cfg(feature = "legacy-session-net-compat")]
pub use server::SessionReplicationServer;
