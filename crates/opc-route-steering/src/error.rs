//! Redaction-safe route-steering errors.

use std::io;

use thiserror::Error;

/// Error type for safe route-steering backend operations.
#[non_exhaustive]
#[derive(Debug, Clone, Error)]
pub enum RouteSteeringError {
    /// The platform does not support Linux route/rule operations.
    #[error("route steering operations are not supported on this platform")]
    UnsupportedPlatform,
    /// Kernel or socket I/O failed.
    #[error("route steering {operation} failed{}", .raw_os_error.map(|code| format!(" (os error {code})")).unwrap_or_default())]
    Io {
        /// Stable operation label.
        operation: &'static str,
        /// Captured I/O error kind.
        kind: io::ErrorKind,
        /// Raw OS error code, when present.
        raw_os_error: Option<i32>,
    },
    /// Requested route/rule already exists.
    #[error("route steering state already exists")]
    AlreadyExists,
    /// Requested route/rule was not found.
    #[error("route steering state not found")]
    NotFound,
    /// Configuration failed validation.
    #[error("invalid route steering config field '{field}': {reason}")]
    InvalidConfig {
        /// Stable field label.
        field: &'static str,
        /// Static payload-free reason.
        reason: &'static str,
    },
}

impl RouteSteeringError {
    /// Build an invalid-config error.
    pub fn invalid_config(field: &'static str, reason: &'static str) -> Self {
        Self::InvalidConfig { field, reason }
    }

    /// Build an I/O error with a stable operation label.
    pub fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io {
            operation,
            kind: source.kind(),
            raw_os_error: source.raw_os_error(),
        }
    }

    /// Return the I/O error kind when this is an I/O variant.
    pub fn io_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Io { kind, .. } => Some(*kind),
            _ => None,
        }
    }

    /// Return the captured raw OS error code.
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
    fn io_error_debug_does_not_leak_source_message() {
        let sensitive = "subscriber=123456789012345 prefix=10.23.0.0/24";
        let source = io::Error::new(io::ErrorKind::PermissionDenied, sensitive);
        let err = RouteSteeringError::io("netlink_send", source);
        let debug = format!("{err:?}");
        assert!(debug.contains("PermissionDenied"));
        assert!(!debug.contains("subscriber"));
        assert!(!debug.contains("10.23.0.0"));
    }

    #[test]
    fn invalid_config_display_uses_labels_only() {
        let err = RouteSteeringError::invalid_config("route.table", "table must be nonzero");
        assert_eq!(
            err.to_string(),
            "invalid route steering config field 'route.table': table must be nonzero"
        );
    }
}
