//! Redaction-safe error types for XFRM backend operations.
//!
//! Error variants deliberately carry only stable operation/field labels and
//! static payload-free reasons. They never hold raw key material, SPIs, or
//! addresses, so `Debug` and `Display` are safe for logs and support bundles.

use std::io;

use thiserror::Error;

/// Error type for safe XFRM backend operations.
///
/// The type is `Clone` so mock/test backends can reuse injected failures. I/O
/// errors are captured only as their [`io::ErrorKind`], the raw OS error code
/// (when present), and a stable operation label; the original OS error string
/// is intentionally discarded so that `Debug` and `Display` never leak
/// addresses, SPIs, subscriber context, or key material. The errno integer
/// itself carries no payload data and is redaction-safe.
#[non_exhaustive]
#[derive(Debug, Clone, Error)]
pub enum XfrmError {
    /// The platform does not support XFRM operations.
    #[error("XFRM operations are not supported on this platform")]
    UnsupportedPlatform,
    /// A requested XFRM feature is outside this capability profile.
    #[error("XFRM feature is unsupported: {feature}")]
    UnsupportedFeature {
        /// Stable feature label.
        feature: &'static str,
    },
    /// Configuration failed validation.
    #[error("invalid XFRM config field '{field}': {reason}")]
    InvalidConfig {
        /// Stable field label.
        field: &'static str,
        /// Static payload-free reason. Keeping this `&'static str` prevents
        /// accidental inclusion of request-derived sensitive values in a
        /// redaction-safe error.
        reason: &'static str,
    },
    /// Kernel or socket I/O failed.
    #[error("XFRM {operation} failed{}", .raw_os_error.map(|code| format!(" (os error {code})")).unwrap_or_default())]
    Io {
        /// Stable operation label.
        operation: &'static str,
        /// Captured I/O error kind.
        kind: io::ErrorKind,
        /// Raw OS error code (errno), when the source carried one. The
        /// integer is redaction-safe: it never encodes addresses, SPIs, or
        /// key material.
        raw_os_error: Option<i32>,
    },
    /// A mutation may have been accepted, but its final kernel state could
    /// not be proven or safely reconciled.
    #[error("XFRM {operation} final state is indeterminate")]
    StateIndeterminate {
        /// Stable operation label.
        operation: &'static str,
    },
    /// A bounded read response exceeded the configured receive buffer.
    ///
    /// The response datagram was consumed. Unlike [`Self::StateIndeterminate`],
    /// this variant is emitted only for non-mutating operations and does not
    /// imply that kernel state may have changed.
    #[error(
        "XFRM {operation} response exceeded the bounded receive buffer ({datagram_bytes} > {buffer_bytes} bytes)"
    )]
    ResponseTooLarge {
        /// Stable read operation label.
        operation: &'static str,
        /// Configured receive-buffer bound.
        buffer_bytes: usize,
        /// Full datagram size reported by Linux.
        datagram_bytes: usize,
    },
    /// Query-proven state did not match the caller's current-state snapshot.
    #[error("XFRM {operation} current state does not match the request")]
    StateMismatch {
        /// Stable operation label.
        operation: &'static str,
    },
    /// The requested SA or policy was not found.
    #[error("XFRM state not found")]
    NotFound,
    /// The requested SA or policy already exists.
    #[error("XFRM state already exists")]
    AlreadyExists,
    /// The backend is in a state that prevents the operation.
    #[error("XFRM backend unavailable")]
    Unavailable,
}

impl XfrmError {
    /// Build an `InvalidConfig` error with a static reason.
    pub fn invalid_config(field: &'static str, reason: &'static str) -> Self {
        Self::InvalidConfig { field, reason }
    }

    /// Build an `Io` error with a stable operation label.
    ///
    /// The original OS error message is discarded; only [`io::ErrorKind`] and
    /// the raw OS error code (a redaction-safe integer) are retained to keep
    /// `Debug` output safe for logs and support bundles.
    pub fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io {
            operation,
            kind: source.kind(),
            raw_os_error: source.raw_os_error(),
        }
    }

    /// Return the I/O error kind when this is an `Io` variant.
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Io { kind, .. } => Some(*kind),
            _ => None,
        }
    }

    /// Return the raw OS error code (errno) when this is an `Io` variant that
    /// captured one.
    pub fn raw_os_error(&self) -> Option<i32> {
        match self {
            Self::Io { raw_os_error, .. } => *raw_os_error,
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_platform_display_is_safe() {
        let err = XfrmError::UnsupportedPlatform;
        let display = err.to_string();
        assert!(display.contains("not supported"));
    }

    #[test]
    fn invalid_config_display_uses_labels_only() {
        let err = XfrmError::invalid_config("selector.source_prefix_len", "must be <= 128");
        let display = err.to_string();
        assert!(display.contains("selector.source_prefix_len"));
        assert!(display.contains("must be <= 128"));
    }

    #[test]
    fn io_error_display_uses_operation_label() {
        let source = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let err = XfrmError::io("netlink_send", source);
        let display = err.to_string();
        assert!(display.contains("netlink_send"));
        assert!(!display.contains("denied"));
    }

    #[test]
    fn io_error_kind_is_preserved() {
        let source = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let err = XfrmError::io("netlink_send", source);
        assert_eq!(err.io_kind(), Some(io::ErrorKind::PermissionDenied));
    }

    #[test]
    fn io_error_captures_raw_os_error() {
        let source = io::Error::from_raw_os_error(97);
        let err = XfrmError::io("netlink_ack", source);
        assert_eq!(err.raw_os_error(), Some(97));
        let display = err.to_string();
        assert!(display.contains("netlink_ack"));
        assert!(display.contains("os error 97"));
    }

    #[test]
    fn io_error_without_raw_os_error_omits_code() {
        let source = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let err = XfrmError::io("netlink_send", source);
        assert_eq!(err.raw_os_error(), None);
        assert_eq!(err.to_string(), "XFRM netlink_send failed");
    }

    #[test]
    fn non_io_variants_have_no_raw_os_error() {
        assert_eq!(XfrmError::NotFound.raw_os_error(), None);
        assert_eq!(XfrmError::UnsupportedPlatform.raw_os_error(), None);
    }

    #[test]
    fn state_indeterminate_display_is_safe() {
        let err = XfrmError::StateIndeterminate {
            operation: "install_sa",
        };

        assert_eq!(
            err.to_string(),
            "XFRM install_sa final state is indeterminate"
        );
    }

    #[test]
    fn response_too_large_display_contains_only_stable_sizes_and_operation() {
        let err = XfrmError::ResponseTooLarge {
            operation: "query_sa",
            buffer_bytes: 8_192,
            datagram_bytes: 12_288,
        };

        assert_eq!(
            err.to_string(),
            "XFRM query_sa response exceeded the bounded receive buffer (12288 > 8192 bytes)"
        );
        assert_eq!(err.raw_os_error(), None);
    }

    #[test]
    fn state_mismatch_display_is_safe() {
        let err = XfrmError::StateMismatch {
            operation: "relocate_sa_preflight",
        };

        assert_eq!(
            err.to_string(),
            "XFRM relocate_sa_preflight current state does not match the request"
        );
    }

    #[test]
    fn error_clone_preserves_io_kind() {
        let source = io::Error::new(io::ErrorKind::NotFound, "missing");
        let err = XfrmError::io("allocspi", source);
        let cloned = err.clone();
        assert_eq!(cloned.io_kind(), Some(io::ErrorKind::NotFound));
    }

    #[test]
    fn io_error_debug_does_not_leak_source_message() {
        let sensitive = "subscriber=123456789012345 spi=0x12345678";
        let source = io::Error::new(io::ErrorKind::PermissionDenied, sensitive);
        let err = XfrmError::io("netlink_send", source);
        let debug = format!("{err:?}");
        assert!(debug.contains("PermissionDenied"));
        assert!(!debug.contains("subscriber"));
        assert!(!debug.contains("123456789012345"));
        assert!(!debug.contains("0x12345678"));
    }

    #[test]
    fn already_exists_display_is_safe() {
        let err = XfrmError::AlreadyExists;
        assert_eq!(err.to_string(), "XFRM state already exists");
    }
}
