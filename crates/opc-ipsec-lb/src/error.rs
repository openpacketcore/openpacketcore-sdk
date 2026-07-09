//! Redaction-safe error types for IPsec load-balancing primitives.

use thiserror::Error;

/// Error type for IPsec load-balancing primitives and ports.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IpsecLbError {
    /// A requested tagged SPI layout cannot satisfy the configured safety floor.
    #[error(
        "invalid SPI layout: total_bits={total_bits} tag_bits={tag_bits} min_unpredictable_bits={min_unpredictable_bits}"
    )]
    InvalidSpiLayout {
        /// Total SPI bits in the wire field.
        total_bits: u8,
        /// Bits reserved for the routing tag.
        tag_bits: u8,
        /// Required unpredictable non-tag bits.
        min_unpredictable_bits: u8,
    },
    /// A requested shard is not in the configured shard set.
    #[error("unknown shard")]
    UnknownShard,
    /// The shard set is empty.
    #[error("empty shard set")]
    EmptyShardSet,
    /// The shard set contains duplicate entries.
    #[error("duplicate shard")]
    DuplicateShard,
    /// The tag space cannot represent or route the requested shard set.
    #[error("tag space exhausted")]
    TagSpaceExhausted,
    /// Randomness could not be obtained.
    #[error("entropy source failed")]
    EntropyUnavailable,
    /// Allocator failed to find a usable SPI within its bounded attempts.
    #[error("SPI allocation attempts exhausted")]
    AllocationAttemptsExhausted,
    /// A SPI does not fit the expected wire width.
    #[error("SPI value out of range")]
    SpiOutOfRange,
    /// Packet is not accepted for steering.
    #[error("packet rejected: {code}")]
    PacketRejected {
        /// Stable rejection code.
        code: &'static str,
    },
    /// Unsupported backend or platform.
    #[error("IPsec load-balancing operation is unsupported")]
    Unsupported,
    /// Requested state already exists.
    #[error("IPsec load-balancing state already exists")]
    AlreadyExists,
    /// Requested state was not found.
    #[error("IPsec load-balancing state not found")]
    NotFound,
    /// Failover resume would violate nonce or replay safety.
    #[error("unsafe failover resume: {reason}")]
    UnsafeResume {
        /// Static, redaction-safe reason.
        reason: &'static str,
    },
    /// Cookie verification failed.
    #[error("IKE cookie verification failed")]
    CookieRejected,
}

impl IpsecLbError {
    /// Build a redaction-safe packet rejection.
    #[must_use]
    pub const fn packet_rejected(code: &'static str) -> Self {
        Self::PacketRejected { code }
    }

    /// Build an unsafe-resume error.
    #[must_use]
    pub const fn unsafe_resume(reason: &'static str) -> Self {
        Self::UnsafeResume { reason }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_do_not_format_packet_or_secret_material() {
        let err = IpsecLbError::packet_rejected("malformed_ike");
        assert_eq!(err.to_string(), "packet rejected: malformed_ike");
        let debug = format!("{err:?}");
        assert!(!debug.contains("subscriber"));
        assert!(!debug.contains("key"));
    }
}
