//! Redaction-safe route-steering errors.

use std::io;

use thiserror::Error;

use crate::model::ReadbackIndeterminateReason;

/// Stable, payload-free class for an operation failure.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteSteeringFailureClass {
    /// The backend is unsupported on this platform.
    UnsupportedPlatform,
    /// Kernel or transport I/O failed.
    Io,
    /// A colliding kernel object exists.
    AlreadyExists,
    /// The requested object was absent.
    NotFound,
    /// A caller-provided request or backend bound was invalid.
    InvalidConfig,
    /// A bounded resident-state readback was not conclusive.
    ReadbackIndeterminate,
    /// A paired operation failed and its owned rollback also failed.
    RollbackFailed,
}

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
    /// A bounded readback could not complete safely.
    #[error("route steering readback is indeterminate: {reason:?}")]
    ReadbackIndeterminate {
        /// Stable payload-free reason.
        reason: ReadbackIndeterminateReason,
    },
    /// A paired operation failed and removal of state owned by that attempt failed.
    #[error("route steering paired operation and owned rollback both failed")]
    RollbackFailed {
        /// Failure class for the primary route/rule operation.
        primary: RouteSteeringFailureClass,
        /// Failure class for the owned rollback operation.
        rollback: RouteSteeringFailureClass,
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

    pub(crate) const fn indeterminate(reason: ReadbackIndeterminateReason) -> Self {
        Self::ReadbackIndeterminate { reason }
    }

    /// Return a stable payload-free failure class.
    #[must_use]
    pub const fn class(&self) -> RouteSteeringFailureClass {
        match self {
            Self::UnsupportedPlatform => RouteSteeringFailureClass::UnsupportedPlatform,
            Self::Io { .. } => RouteSteeringFailureClass::Io,
            Self::AlreadyExists => RouteSteeringFailureClass::AlreadyExists,
            Self::NotFound => RouteSteeringFailureClass::NotFound,
            Self::InvalidConfig { .. } => RouteSteeringFailureClass::InvalidConfig,
            Self::ReadbackIndeterminate { .. } => RouteSteeringFailureClass::ReadbackIndeterminate,
            Self::RollbackFailed { .. } => RouteSteeringFailureClass::RollbackFailed,
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
