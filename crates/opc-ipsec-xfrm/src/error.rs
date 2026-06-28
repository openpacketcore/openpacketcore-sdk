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
/// errors are captured only as their [`io::ErrorKind`] plus a stable operation
/// label; the original OS error string is intentionally discarded so that
/// `Debug` and `Display` never leak addresses, SPIs, subscriber context, or key
/// material.
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
    #[error("XFRM {operation} failed")]
    Io {
        /// Stable operation label.
        operation: &'static str,
        /// Captured I/O error kind.
        kind: io::ErrorKind,
    },
    /// The requested SA or policy was not found.
    #[error("XFRM state not found")]
    NotFound,
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
    /// The original OS error message is discarded; only [`io::ErrorKind`] is
    /// retained to keep `Debug` output safe for logs and support bundles.
    pub fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io {
            operation,
            kind: source.kind(),
        }
    }

    /// Return the I/O error kind when this is an `Io` variant.
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Io { kind, .. } => Some(*kind),
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
}
