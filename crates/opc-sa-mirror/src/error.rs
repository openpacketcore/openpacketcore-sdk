//! Redaction-safe error types for live SA keymat mirroring.

use std::io;

use opc_ipsec_lb::IpsecLbError;
use thiserror::Error;

/// Error type for live SA keymat mirroring ports and transport.
///
/// Every variant is redaction-safe by construction: reasons and field labels
/// are static strings, I/O failures are reduced to their kind and OS error
/// code, and no peer-controlled text is ever carried.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SaMirrorError {
    /// A mirror request field failed validation.
    #[error("invalid SA mirror field '{field}': {reason}")]
    Invalid {
        /// Stable field label.
        field: &'static str,
        /// Static payload-free reason.
        reason: &'static str,
    },
    /// The install or withdraw epoch is older than the held generation.
    #[error("stale SA mirror epoch")]
    StaleEpoch,
    /// The request conflicts with held mirror state.
    #[error("SA mirror conflict: {reason}")]
    Conflict {
        /// Static, redaction-safe reason.
        reason: &'static str,
    },
    /// The standby holder is at capacity and fails closed for new SAs.
    #[error("standby keymat capacity exhausted")]
    CapacityExhausted,
    /// No mirrored keymat is held for the requested SA.
    #[error("mirrored SA not found")]
    NotFound,
    /// The takeover evidence would violate re-pin resume safety.
    #[error("unsafe live-mirror takeover")]
    Resume(#[source] IpsecLbError),
    /// Transport or socket I/O failed.
    #[error("SA mirror {operation} I/O failed{}", .raw_os_error.map(|code| format!(" (os error {code})")).unwrap_or_default())]
    Io {
        /// Stable operation label.
        operation: &'static str,
        /// Captured I/O error kind.
        kind: io::ErrorKind,
        /// Raw OS error code, when present.
        raw_os_error: Option<i32>,
    },
    /// A frame exceeded the configured size bound.
    #[error("SA mirror frame too large: {0} bytes")]
    FrameTooLarge(usize),
    /// The peer speaks a different mirror contract version.
    #[error("SA mirror contract version mismatch: local={local} remote={remote}")]
    VersionMismatch {
        /// Local contract version.
        local: u32,
        /// Remote contract version.
        remote: u32,
    },
    /// The peer violated the wire protocol.
    #[error("SA mirror protocol violation: {reason}")]
    Protocol {
        /// Static, redaction-safe reason.
        reason: &'static str,
    },
    /// The per-call deadline elapsed before the exchange completed.
    #[error("SA mirror deadline exceeded")]
    DeadlineExceeded,
}

impl SaMirrorError {
    /// Build a redaction-safe invalid-field error.
    #[must_use]
    pub const fn invalid(field: &'static str, reason: &'static str) -> Self {
        Self::Invalid { field, reason }
    }

    /// Build a redaction-safe conflict error.
    #[must_use]
    pub const fn conflict(reason: &'static str) -> Self {
        Self::Conflict { reason }
    }

    /// Build a redaction-safe protocol violation.
    #[must_use]
    pub const fn protocol(reason: &'static str) -> Self {
        Self::Protocol { reason }
    }

    /// Build a redaction-safe I/O error, discarding the source message.
    #[must_use]
    pub fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io {
            operation,
            kind: source.kind(),
            raw_os_error: source.raw_os_error(),
        }
    }

    /// Stable redaction-safe code carried in wire rejections.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Invalid { .. } => "invalid",
            Self::StaleEpoch => "stale_epoch",
            Self::Conflict { .. } => "mirror_conflict",
            Self::CapacityExhausted => "capacity_exhausted",
            Self::NotFound => "not_found",
            Self::Resume(_) => "unsafe_resume",
            Self::Io { .. } => "io",
            Self::FrameTooLarge(_) => "frame_too_large",
            Self::VersionMismatch { .. } => "version_mismatch",
            Self::Protocol { .. } => "protocol",
            Self::DeadlineExceeded => "deadline_exceeded",
        }
    }

    /// Map a wire rejection code back into a typed error.
    ///
    /// Unknown codes collapse to a static protocol violation so no
    /// peer-controlled text enters errors or logs.
    #[must_use]
    pub fn from_remote_code(code: &str) -> Self {
        match code {
            "invalid" => Self::invalid("remote", "peer rejected the request as invalid"),
            "stale_epoch" => Self::StaleEpoch,
            "mirror_conflict" => Self::conflict("peer holds conflicting mirror state"),
            "capacity_exhausted" => Self::CapacityExhausted,
            "not_found" => Self::NotFound,
            _ => Self::protocol("unrecognized remote rejection code"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_debug_discards_sensitive_source_message() {
        let err = SaMirrorError::io(
            "mirror_install",
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "subscriber=001010123456789 key=deadbeef",
            ),
        );
        let debug = format!("{err:?}");
        assert!(debug.contains("PermissionDenied"));
        assert!(!debug.contains("subscriber"));
        assert!(!debug.contains("deadbeef"));
    }

    #[test]
    fn remote_code_round_trips_known_codes_and_collapses_unknown_text() {
        for err in [
            SaMirrorError::StaleEpoch,
            SaMirrorError::CapacityExhausted,
            SaMirrorError::NotFound,
        ] {
            assert_eq!(SaMirrorError::from_remote_code(err.code()), err);
        }
        assert!(matches!(
            SaMirrorError::from_remote_code("key=deadbeef injected"),
            SaMirrorError::Protocol { .. }
        ));
    }
}
