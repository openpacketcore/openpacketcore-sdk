//! Redaction-safe error types for GTP-U dataplane backend operations.
//!
//! Error variants deliberately carry only stable operation/field labels and
//! static payload-free reasons. They never hold TEIDs, subscriber addresses, or
//! peer addresses, so `Debug` and `Display` are safe for logs and support
//! bundles.

use std::io;

use thiserror::Error;

/// Error type for safe GTP-U dataplane backend operations.
///
/// The type is `Clone` so mock/test backends can reuse injected failures. I/O
/// errors are captured only as their [`io::ErrorKind`], raw OS error code, and
/// a stable operation label; the original OS error string is intentionally
/// discarded so `Debug` and `Display` never leak addresses, TEIDs, or
/// subscriber context.
#[non_exhaustive]
#[derive(Debug, Clone, Error)]
pub enum GtpuError {
    /// The platform does not support Linux GTP-U operations.
    #[error("GTP-U dataplane operations are not supported on this platform")]
    UnsupportedPlatform,
    /// A requested feature is outside this backend's capability profile.
    #[error("GTP-U dataplane feature is unsupported: {feature}")]
    UnsupportedFeature {
        /// Stable feature label.
        feature: &'static str,
    },
    /// Kernel or socket I/O failed.
    #[error("GTP-U {operation} failed{}", .raw_os_error.map(|code| format!(" (os error {code})")).unwrap_or_default())]
    Io {
        /// Stable operation label.
        operation: &'static str,
        /// Captured I/O error kind.
        kind: io::ErrorKind,
        /// Raw OS error code (errno), when the source carried one.
        raw_os_error: Option<i32>,
    },
    /// The requested device or PDP context already exists.
    #[error("GTP-U state already exists")]
    AlreadyExists,
    /// The requested device or PDP context was not found.
    #[error("GTP-U state not found")]
    NotFound,
    /// A safe recovery step completed, but the requested mutation was not
    /// applied and must be retried as a new operation.
    #[error("GTP-U {operation} must be retried")]
    RetryRequired {
        /// Stable operation label identifying the retriable boundary.
        operation: &'static str,
    },
    /// Configuration failed validation.
    #[error("invalid GTP-U config field '{field}': {reason}")]
    InvalidConfig {
        /// Stable field label.
        field: &'static str,
        /// Static payload-free reason.
        reason: &'static str,
    },
    /// A mutation or cleanup may be partial, ACK-uncertain, or otherwise have
    /// an unproven final state.
    #[error("GTP-U {operation} outcome is indeterminate")]
    StateIndeterminate {
        /// Stable operation label.
        operation: &'static str,
    },
}

impl GtpuError {
    /// Build an `InvalidConfig` error with a static reason.
    pub fn invalid_config(field: &'static str, reason: &'static str) -> Self {
        Self::InvalidConfig { field, reason }
    }

    /// Build an `Io` error with a stable operation label.
    ///
    /// The original OS error message is discarded; only [`io::ErrorKind`] and
    /// raw OS error code are retained to keep diagnostics redaction-safe.
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
    fn invalid_config_display_uses_labels_only() {
        let err = GtpuError::invalid_config("device.name", "must be nonempty");
        let display = err.to_string();
        assert!(display.contains("device.name"));
        assert!(display.contains("must be nonempty"));
    }

    #[test]
    fn io_error_display_uses_operation_label_and_errno_only() {
        let source = io::Error::from_raw_os_error(95);
        let err = GtpuError::io("netlink_ack", source);
        let display = err.to_string();
        assert!(display.contains("netlink_ack"));
        assert!(display.contains("os error 95"));
    }

    #[test]
    fn io_error_debug_does_not_leak_source_message() {
        let sensitive = "subscriber=123456789012345 teid=0x12345678 addr=10.23.0.2";
        let source = io::Error::new(io::ErrorKind::PermissionDenied, sensitive);
        let err = GtpuError::io("netlink_send", source);
        let debug = format!("{err:?}");
        assert!(debug.contains("PermissionDenied"));
        assert!(!debug.contains("subscriber"));
        assert!(!debug.contains("123456789012345"));
        assert!(!debug.contains("0x12345678"));
        assert!(!debug.contains("10.23.0.2"));
    }

    #[test]
    fn non_io_variants_have_no_raw_os_error() {
        assert_eq!(GtpuError::NotFound.raw_os_error(), None);
        assert_eq!(GtpuError::AlreadyExists.raw_os_error(), None);
        assert_eq!(
            GtpuError::RetryRequired {
                operation: "install_pdp_context"
            }
            .raw_os_error(),
            None
        );
        assert_eq!(GtpuError::UnsupportedPlatform.raw_os_error(), None);
    }

    #[test]
    fn retry_required_uses_only_the_stable_operation_label() {
        let error = GtpuError::RetryRequired {
            operation: "install_pdp_context",
        };
        assert_eq!(
            error.to_string(),
            "GTP-U install_pdp_context must be retried"
        );
    }
}
