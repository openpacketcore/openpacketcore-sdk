//! Networked session replication transport for OpenPacketCore (experimental).
//!
//! Provides a length-prefixed JSON wire protocol between a
//! [`SessionReplicationServer`] and [`RemoteSessionBackend`]. Production
//! endpoints derive their local/remote authority from one immutable
//! [`SessionReplicationManifest`]; protocol v3 then binds the claimed stable
//! replica IDs and manifest scope to the canonical SPIFFE identities extracted
//! from the live mutual-TLS connection before any backend operation.

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
pub use protocol::{HelloRejectReason, Request, Response};
pub use server::SessionReplicationServer;
