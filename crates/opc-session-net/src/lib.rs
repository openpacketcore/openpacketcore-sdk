//! Networked session replication transport for OpenPacketCore (experimental).
//!
//! Provides a length-prefixed JSON wire protocol between a
//! [`SessionReplicationServer`] and [`RemoteSessionBackend`].

#![forbid(unsafe_code)]

pub mod client;
pub mod error;
pub mod protocol;
pub mod server;

pub use client::RemoteSessionBackend;
pub use error::ProtocolError;
pub use protocol::{Request, Response};
pub use server::SessionReplicationServer;
