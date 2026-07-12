//! Networked session replication transport for OpenPacketCore (experimental).
//!
//! Provides a length-prefixed JSON wire protocol between a
//! [`SessionReplicationServer`] and [`RemoteSessionBackend`]. Production
//! endpoints derive their local/remote authority from one immutable
//! [`SessionReplicationManifest`]; protocol v4 then binds the claimed stable
//! replica IDs and manifest scope to the canonical SPIFFE identities extracted
//! from the live mutual-TLS connection before any backend operation. Peers must
//! also prove the exact same [`ContractProfile`] before operation DTOs are
//! decoded or backend work is dispatched.

#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod identity;
pub mod protocol;
pub mod server;

pub use client::{RemoteAddrResolver, RemoteSessionBackend};
pub use error::ProtocolError;
pub use identity::{
    LocalReplicaBinding, RemoteReplicaBinding, SessionClusterId, SessionConfigurationGeneration,
    SessionConfigurationId, SessionManifestError, SessionReplicationManifest,
};
pub use protocol::{
    conservative_payload_budget, ContractProfile, HelloRejectReason, Request, Response,
    CURRENT_CONTRACT_PROFILE, MAX_NEGOTIATED_FRAME_SIZE, MAX_SESSION_NET_BATCH_OPERATIONS,
    MAX_SESSION_NET_REBUILD_ENTRIES, MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES,
    MAX_SESSION_NET_REPLICATION_TX_ID_BYTES, MAX_SESSION_NET_STABLE_ID_BYTES,
    MIN_NEGOTIATED_FRAME_SIZE, SESSION_NET_CAS_REQUEST_ID_BYTES,
};
pub use server::SessionReplicationServer;
