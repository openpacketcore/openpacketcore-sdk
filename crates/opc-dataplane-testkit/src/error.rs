//! Error types for deterministic dataplane tests.

use thiserror::Error;

/// Error returned by packet builders, decoders, traffic observers, and the
/// in-memory GTP-U reflector.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DataplaneTestkitError {
    /// A packet ended before the named structure was complete.
    #[error("packet truncated while decoding {context}")]
    Truncated {
        /// Structure being decoded.
        context: &'static str,
    },
    /// A packet used an unsupported IP version.
    #[error("unsupported IP version {version}")]
    UnsupportedIpVersion {
        /// IP version nibble.
        version: u8,
    },
    /// A packet was structurally invalid.
    #[error("invalid packet: {reason}")]
    InvalidPacket {
        /// Stable redaction-safe reason.
        reason: &'static str,
    },
    /// Numeric conversion or length arithmetic overflowed.
    #[error("numeric value overflow: {field}")]
    Overflow {
        /// Field or calculation that overflowed.
        field: &'static str,
    },
    /// A return timestamp was earlier than the recorded send timestamp.
    #[error("return timestamp moved backwards")]
    TimestampReversed,
    /// A GTP-U decoder rejected a packet.
    #[error("GTP-U decode failed: {0}")]
    GtpuDecode(String),
    /// A GTP-U encoder rejected a message.
    #[error("GTP-U encode failed: {0}")]
    GtpuEncode(String),
    /// A G-PDU arrived for a TEID not configured on the reflector.
    #[error("G-PDU arrived for an unknown local TEID")]
    UnknownTeid,
    /// Multi-session reflector capacity was zero or above its hard bound.
    #[error("invalid GTP-U reflector session capacity")]
    InvalidReflectorCapacity,
    /// A reflector session used an invalid zero TEID or UDP port.
    #[error("invalid GTP-U reflector session")]
    InvalidReflectorSession,
    /// A local TEID was already mapped to a different peer target.
    #[error("conflicting GTP-U reflector session")]
    ReflectorSessionConflict,
    /// A new reflector session would exceed configured capacity.
    #[error("GTP-U reflector session capacity exceeded")]
    ReflectorSessionCapacityExceeded,
    /// A serialized evidence value failed redaction validation.
    #[error("redaction violation: {0}")]
    RedactionViolation(String),
}

impl DataplaneTestkitError {
    /// Build an invalid-packet error with a stable reason.
    pub const fn invalid_packet(reason: &'static str) -> Self {
        Self::InvalidPacket { reason }
    }

    /// Build a truncation error for the named structure.
    pub const fn truncated(context: &'static str) -> Self {
        Self::Truncated { context }
    }
}
