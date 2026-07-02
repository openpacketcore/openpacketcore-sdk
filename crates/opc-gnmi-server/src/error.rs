//! gNMI foundation errors.

use opc_mgmt_errors::MgmtStatus;
use opc_mgmt_limits::LimitsError;
use thiserror::Error;

use crate::encoding::{Encoding, EncodingError};

/// Client-facing gNMI error classification plus server-local detail.
///
/// `Display` is intentionally generic and payload-free. Details can contain
/// schema paths or local diagnostics and must stay in server logs/audit context,
/// not in future gRPC status messages.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GnmiError {
    /// Invalid request syntax or semantics.
    #[error("invalid gNMI request")]
    InvalidArgument {
        /// Server-local, payload-free detail.
        detail: String,
    },
    /// Requested path or schema object does not exist.
    #[error("gNMI path not found")]
    NotFound {
        /// Server-local, payload-free detail.
        detail: String,
    },
    /// Authenticated principal is not authorized.
    #[error("gNMI access denied")]
    PermissionDenied,
    /// No valid authentication was available.
    #[error("gNMI authentication required")]
    Unauthenticated,
    /// Capability, encoding, extension, or operation is outside the advertised profile.
    #[error("gNMI operation is not supported")]
    Unimplemented {
        /// Server-local, payload-free detail.
        detail: String,
    },
    /// Retryable backend unavailability or backpressure.
    #[error("gNMI service unavailable")]
    Unavailable {
        /// Server-local, payload-free detail.
        detail: String,
    },
    /// Deadline expired.
    #[error("gNMI deadline exceeded")]
    DeadlineExceeded,
    /// System state forbids the operation.
    #[error("gNMI failed precondition")]
    FailedPrecondition {
        /// Server-local, payload-free detail.
        detail: String,
    },
    /// Internal invariant failure.
    #[error("gNMI internal error")]
    Internal {
        /// Server-local, payload-free detail.
        detail: String,
    },
}

impl GnmiError {
    /// Builds an invalid-argument error.
    pub fn invalid(detail: impl Into<String>) -> Self {
        Self::InvalidArgument {
            detail: detail.into(),
        }
    }

    /// Builds a not-found error.
    pub fn not_found(detail: impl Into<String>) -> Self {
        Self::NotFound {
            detail: detail.into(),
        }
    }

    /// Builds an unimplemented error.
    pub fn unimplemented(detail: impl Into<String>) -> Self {
        Self::Unimplemented {
            detail: detail.into(),
        }
    }

    /// Builds an unavailable error.
    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self::Unavailable {
            detail: detail.into(),
        }
    }

    /// Builds a failed-precondition error.
    pub fn failed_precondition(detail: impl Into<String>) -> Self {
        Self::FailedPrecondition {
            detail: detail.into(),
        }
    }

    /// Builds an internal error from schema/server-local detail.
    pub fn schema(detail: impl Into<String>) -> Self {
        Self::Internal {
            detail: detail.into(),
        }
    }

    /// Maps this error to the gRPC-aligned management status taxonomy.
    pub const fn status(&self) -> MgmtStatus {
        match self {
            Self::InvalidArgument { .. } => MgmtStatus::InvalidArgument,
            Self::NotFound { .. } => MgmtStatus::NotFound,
            Self::PermissionDenied => MgmtStatus::PermissionDenied,
            Self::Unauthenticated => MgmtStatus::Unauthenticated,
            Self::Unimplemented { .. } => MgmtStatus::Unimplemented,
            Self::Unavailable { .. } => MgmtStatus::Unavailable,
            Self::DeadlineExceeded => MgmtStatus::DeadlineExceeded,
            Self::FailedPrecondition { .. } => MgmtStatus::FailedPrecondition,
            Self::Internal { .. } => MgmtStatus::Internal,
        }
    }

    /// Server-local diagnostic detail, if present.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::InvalidArgument { detail }
            | Self::NotFound { detail }
            | Self::Unimplemented { detail }
            | Self::Unavailable { detail }
            | Self::FailedPrecondition { detail }
            | Self::Internal { detail } => Some(detail.as_str()),
            Self::PermissionDenied | Self::Unauthenticated | Self::DeadlineExceeded => None,
        }
    }

    /// Converts a management-plane limit error into a gNMI invalid-argument
    /// error. Limits display only stable limit names and counts, never payloads.
    pub fn from_limits(err: LimitsError) -> Self {
        Self::invalid(err.to_string())
    }
}

impl From<EncodingError> for GnmiError {
    fn from(err: EncodingError) -> Self {
        Self::unimplemented(err.to_string())
    }
}

impl From<Encoding> for GnmiError {
    fn from(encoding: Encoding) -> Self {
        Self::unimplemented(format!("unsupported encoding {}", encoding.as_str()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn display_does_not_include_detail() {
        let err = GnmiError::invalid("secret value abc");
        assert_eq!(err.to_string(), "invalid gNMI request");
        assert_eq!(err.detail(), Some("secret value abc"));
    }

    #[test]
    fn statuses_match_error_classes() {
        assert_eq!(
            GnmiError::PermissionDenied.status(),
            MgmtStatus::PermissionDenied
        );
        assert_eq!(
            GnmiError::unimplemented("x").status(),
            MgmtStatus::Unimplemented
        );
        assert_eq!(GnmiError::schema("x").status(), MgmtStatus::Internal);
    }
}
