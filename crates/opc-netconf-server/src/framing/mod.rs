//! NETCONF message framing.

pub mod base10;
pub mod base11;

use opc_mgmt_limits::LimitsError;
use thiserror::Error;

/// NETCONF framing error. Display text is payload-free.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FramingError {
    /// A shared management-plane limit was exceeded or invalid.
    #[error(transparent)]
    Limit(#[from] LimitsError),
    /// The base 1.0 end marker was absent.
    #[error("NETCONF base 1.0 frame missing end marker")]
    MissingEndMarker,
    /// Extra non-whitespace bytes followed the framed message.
    #[error("NETCONF frame has trailing bytes")]
    TrailingBytes,
    /// A base 1.1 chunk header was malformed.
    #[error("NETCONF base 1.1 invalid chunk header")]
    InvalidChunkHeader,
    /// A base 1.1 chunk length was malformed or unsupported.
    #[error("NETCONF base 1.1 invalid chunk length")]
    InvalidChunkLength,
    /// A base 1.1 chunk did not contain the declared number of bytes.
    #[error("NETCONF base 1.1 missing chunk data")]
    MissingChunkData,
    /// The base 1.1 end marker was malformed.
    #[error("NETCONF base 1.1 invalid end marker")]
    InvalidEndMarker,
}
