//! Transport-neutral status taxonomy and SDK-error→gNMI/NETCONF mappings for the
//! OpenPacketCore management plane.
//!
//! The gNMI and NETCONF servers translate the same `opc-config-bus` write-path
//! failures (and read/authorization denials) into client-facing errors. They
//! must do so identically and without leaking internal detail. This crate is the
//! single home for that translation:
//!
//! - [`MgmtStatus`] — a gRPC-aligned status taxonomy that the gNMI server maps
//!   1:1 onto `tonic::Code`.
//! - [`NetconfErrorType`] / [`NetconfErrorTag`] / [`NetconfError`] — the
//!   `<rpc-error>` `error-type`/`error-tag` values the NETCONF server emits
//!   (RFC 6241).
//! - [`commit_error_to_status`] / [`commit_error_to_netconf`] /
//!   [`commit_error_to_netconf_app_tag`] — the mappings from
//!   [`opc_config_model::CommitErrorCode`], written as exhaustive `match`es so a
//!   new SDK error code forces both transport mappings to be updated.
//!
//! The mappings deliberately translate only the *stable code*; they never carry
//! `CommitError::message`, paths, or values. The server attaches a generic,
//! redacted human string and the machine-readable status to the response.

#![forbid(unsafe_code)]

use opc_config_model::CommitErrorCode;

/// Stable NETCONF `error-app-tag` for a write whose durable outcome is unknown.
///
/// Clients must reconcile the request or idempotency identity before retrying.
/// The tag carries no request, configuration, backend, or peer detail.
pub const NETCONF_OUTCOME_UNKNOWN_APP_TAG: &str = "outcome-unknown";

/// gRPC-aligned status taxonomy for management-plane responses.
///
/// Variants and their canonical strings match gRPC status codes so the gNMI
/// server can map each onto `tonic::Code` directly. `#[non_exhaustive]` so future
/// codes can be added without breaking downstream `match`es.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MgmtStatus {
    /// Success.
    Ok,
    /// Client sent something malformed or semantically invalid.
    InvalidArgument,
    /// Addressed schema node / rollback target does not exist.
    NotFound,
    /// Authenticated but not authorized (NACM denial).
    PermissionDenied,
    /// No valid transport authentication.
    Unauthenticated,
    /// Capability/encoding/operation outside the advertised profile.
    Unimplemented,
    /// Transient backend unavailability (queue full, rollback target pending).
    Unavailable,
    /// Request deadline expired before completion.
    DeadlineExceeded,
    /// System is in a state that forbids the operation (recovery fence raised).
    FailedPrecondition,
    /// Internal invariant violation; not the client's fault.
    Internal,
}

impl MgmtStatus {
    /// Stable uppercase code string (matches the canonical gRPC status names).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::NotFound => "NOT_FOUND",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::Unauthenticated => "UNAUTHENTICATED",
            Self::Unimplemented => "UNIMPLEMENTED",
            Self::Unavailable => "UNAVAILABLE",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Internal => "INTERNAL",
        }
    }
}

/// NETCONF `<rpc-error>` `error-type` (RFC 6241 §4.3). Closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetconfErrorType {
    /// Secure transport layer.
    Transport,
    /// RPC layer.
    Rpc,
    /// Protocol operation layer.
    Protocol,
    /// Data-model/content (application) layer.
    Application,
}

impl NetconfErrorType {
    /// Canonical `error-type` string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Transport => "transport",
            Self::Rpc => "rpc",
            Self::Protocol => "protocol",
            Self::Application => "application",
        }
    }
}

/// NETCONF `<rpc-error>` `error-tag` (RFC 6241 Appendix A).
///
/// `#[non_exhaustive]`: the server may emit tags this crate does not yet map from
/// an SDK code (e.g. parser-level `malformed-message`), and new tags may be added.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetconfErrorTag {
    /// `in-use`
    InUse,
    /// `invalid-value`
    InvalidValue,
    /// `too-big`
    TooBig,
    /// `missing-attribute`
    MissingAttribute,
    /// `bad-attribute`
    BadAttribute,
    /// `unknown-attribute`
    UnknownAttribute,
    /// `missing-element`
    MissingElement,
    /// `bad-element`
    BadElement,
    /// `unknown-element`
    UnknownElement,
    /// `unknown-namespace`
    UnknownNamespace,
    /// `access-denied`
    AccessDenied,
    /// `lock-denied`
    LockDenied,
    /// `resource-denied`
    ResourceDenied,
    /// `data-exists`
    DataExists,
    /// `data-missing`
    DataMissing,
    /// `operation-not-supported`
    OperationNotSupported,
    /// `operation-failed`
    OperationFailed,
    /// `malformed-message`
    MalformedMessage,
}

impl NetconfErrorTag {
    /// Canonical `error-tag` string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InUse => "in-use",
            Self::InvalidValue => "invalid-value",
            Self::TooBig => "too-big",
            Self::MissingAttribute => "missing-attribute",
            Self::BadAttribute => "bad-attribute",
            Self::UnknownAttribute => "unknown-attribute",
            Self::MissingElement => "missing-element",
            Self::BadElement => "bad-element",
            Self::UnknownElement => "unknown-element",
            Self::UnknownNamespace => "unknown-namespace",
            Self::AccessDenied => "access-denied",
            Self::LockDenied => "lock-denied",
            Self::ResourceDenied => "resource-denied",
            Self::DataExists => "data-exists",
            Self::DataMissing => "data-missing",
            Self::OperationNotSupported => "operation-not-supported",
            Self::OperationFailed => "operation-failed",
            Self::MalformedMessage => "malformed-message",
        }
    }
}

/// A NETCONF `<rpc-error>` classification (`error-type` + `error-tag`).
///
/// `error-severity` is always `error` for these, and `error-message`/`error-path`
/// are supplied by the server (subject to NACM disclosure rules), not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetconfError {
    /// The `<error-type>` layer.
    pub error_type: NetconfErrorType,
    /// The `<error-tag>`.
    pub tag: NetconfErrorTag,
}

impl NetconfError {
    /// Convenience constructor.
    pub const fn new(error_type: NetconfErrorType, tag: NetconfErrorTag) -> Self {
        Self { error_type, tag }
    }
}

/// Maps an `opc-config-bus` [`CommitErrorCode`] to a gNMI gRPC status
/// (gNMI server spec §11). Exhaustive: adding a new code is a compile error here.
pub const fn commit_error_to_status(code: CommitErrorCode) -> MgmtStatus {
    match code {
        // Admission queue full → retryable backpressure.
        CommitErrorCode::AdmissionRejected => MgmtStatus::Unavailable,
        // Candidate is valid, but apply-plan policy/workflow blocks it.
        CommitErrorCode::ApplyPlanRejected => MgmtStatus::FailedPrecondition,
        CommitErrorCode::DeadlineExceeded => MgmtStatus::DeadlineExceeded,
        CommitErrorCode::MissingCandidate => MgmtStatus::InvalidArgument,
        CommitErrorCode::SyntaxValidationFailed => MgmtStatus::InvalidArgument,
        CommitErrorCode::SemanticValidationFailed => MgmtStatus::InvalidArgument,
        CommitErrorCode::DiffFailed => MgmtStatus::InvalidArgument,
        // Durable append failed — backend problem, not the client's fault.
        CommitErrorCode::PersistFailed => MgmtStatus::Internal,
        // A generic UNAVAILABLE response invites blind retries. Force the
        // client to reconcile by request/idempotency identity first.
        CommitErrorCode::OutcomeUnknown => MgmtStatus::FailedPrecondition,
        CommitErrorCode::VersionExhausted => MgmtStatus::Internal,
        CommitErrorCode::RollbackNotFound => MgmtStatus::NotFound,
        CommitErrorCode::RollbackUnavailable => MgmtStatus::Unavailable,
        // Recovery fence raised: writes are refused until reconciled.
        CommitErrorCode::RecoveryRequired => MgmtStatus::FailedPrecondition,
        CommitErrorCode::StateMachineFault => MgmtStatus::Internal,
        CommitErrorCode::AuthorizationDenied => MgmtStatus::PermissionDenied,
    }
}

/// Maps an `opc-config-bus` [`CommitErrorCode`] to a NETCONF `<rpc-error>`
/// classification (NETCONF server spec §13). Exhaustive: adding a new code is a
/// compile error here.
pub const fn commit_error_to_netconf(code: CommitErrorCode) -> NetconfError {
    use NetconfErrorTag as Tag;
    use NetconfErrorType as Ty;
    match code {
        CommitErrorCode::AdmissionRejected => {
            NetconfError::new(Ty::Application, Tag::ResourceDenied)
        }
        CommitErrorCode::ApplyPlanRejected => {
            NetconfError::new(Ty::Application, Tag::OperationFailed)
        }
        CommitErrorCode::DeadlineExceeded => {
            NetconfError::new(Ty::Application, Tag::OperationFailed)
        }
        CommitErrorCode::MissingCandidate => NetconfError::new(Ty::Protocol, Tag::MissingElement),
        // Commit validation failed → operation-failed (spec §13).
        CommitErrorCode::SyntaxValidationFailed => {
            NetconfError::new(Ty::Application, Tag::OperationFailed)
        }
        CommitErrorCode::SemanticValidationFailed => {
            NetconfError::new(Ty::Application, Tag::OperationFailed)
        }
        CommitErrorCode::DiffFailed => NetconfError::new(Ty::Application, Tag::OperationFailed),
        CommitErrorCode::PersistFailed => NetconfError::new(Ty::Application, Tag::OperationFailed),
        CommitErrorCode::OutcomeUnknown => NetconfError::new(Ty::Application, Tag::OperationFailed),
        CommitErrorCode::VersionExhausted => {
            NetconfError::new(Ty::Application, Tag::OperationFailed)
        }
        CommitErrorCode::RollbackNotFound => {
            NetconfError::new(Ty::Application, Tag::OperationFailed)
        }
        CommitErrorCode::RollbackUnavailable => {
            NetconfError::new(Ty::Application, Tag::ResourceDenied)
        }
        // config-bus recovery required → operation-failed (spec §13).
        CommitErrorCode::RecoveryRequired => {
            NetconfError::new(Ty::Application, Tag::OperationFailed)
        }
        CommitErrorCode::StateMachineFault => {
            NetconfError::new(Ty::Application, Tag::OperationFailed)
        }
        CommitErrorCode::AuthorizationDenied => NetconfError::new(Ty::Protocol, Tag::AccessDenied),
    }
}

/// Maps an `opc-config-bus` [`CommitErrorCode`] to an optional stable NETCONF
/// `<error-app-tag>`.
///
/// This supplements [`commit_error_to_netconf`] without changing its
/// classification-only return type. The mapping deliberately carries only
/// bounded static strings and never copies an error message or rejected value.
pub const fn commit_error_to_netconf_app_tag(code: CommitErrorCode) -> Option<&'static str> {
    match code {
        CommitErrorCode::OutcomeUnknown => Some(NETCONF_OUTCOME_UNKNOWN_APP_TAG),
        CommitErrorCode::AdmissionRejected
        | CommitErrorCode::ApplyPlanRejected
        | CommitErrorCode::DeadlineExceeded
        | CommitErrorCode::MissingCandidate
        | CommitErrorCode::SyntaxValidationFailed
        | CommitErrorCode::SemanticValidationFailed
        | CommitErrorCode::DiffFailed
        | CommitErrorCode::PersistFailed
        | CommitErrorCode::VersionExhausted
        | CommitErrorCode::RollbackNotFound
        | CommitErrorCode::RollbackUnavailable
        | CommitErrorCode::RecoveryRequired
        | CommitErrorCode::StateMachineFault
        | CommitErrorCode::AuthorizationDenied => None,
    }
}

/// The gNMI status for a NACM read/write/subscribe denial: `PERMISSION_DENIED`
/// (the server discards policy detail and returns only the code — spec §8.3).
pub const fn nacm_denied_status() -> MgmtStatus {
    MgmtStatus::PermissionDenied
}

/// The NETCONF `<rpc-error>` for a NACM denial: `(protocol, access-denied)`
/// (spec §10.3).
pub const fn nacm_denied_netconf() -> NetconfError {
    NetconfError::new(NetconfErrorType::Protocol, NetconfErrorTag::AccessDenied)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `CommitErrorCode` the SDK defines today; if a variant is added the
    /// match in the mapping functions stops compiling, and this list (used to
    /// assert totality of the mapping at runtime) is the place to extend.
    const ALL_CODES: [CommitErrorCode; 15] = [
        CommitErrorCode::AdmissionRejected,
        CommitErrorCode::ApplyPlanRejected,
        CommitErrorCode::DeadlineExceeded,
        CommitErrorCode::MissingCandidate,
        CommitErrorCode::SyntaxValidationFailed,
        CommitErrorCode::SemanticValidationFailed,
        CommitErrorCode::DiffFailed,
        CommitErrorCode::PersistFailed,
        CommitErrorCode::OutcomeUnknown,
        CommitErrorCode::VersionExhausted,
        CommitErrorCode::RollbackNotFound,
        CommitErrorCode::RollbackUnavailable,
        CommitErrorCode::RecoveryRequired,
        CommitErrorCode::StateMachineFault,
        CommitErrorCode::AuthorizationDenied,
    ];

    #[test]
    fn every_commit_code_maps_to_both_transports() {
        for code in ALL_CODES {
            // Total functions: any code yields a status and a netconf classification.
            let _status = commit_error_to_status(code);
            let nc = commit_error_to_netconf(code);
            // error-tag/type strings are non-empty and stable.
            assert!(!nc.tag.as_str().is_empty());
            assert!(!nc.error_type.as_str().is_empty());
            let _app_tag = commit_error_to_netconf_app_tag(code);
        }
    }

    #[test]
    fn key_mappings_match_spec_tables() {
        // gNMI spec §11
        assert_eq!(
            commit_error_to_status(CommitErrorCode::AuthorizationDenied),
            MgmtStatus::PermissionDenied
        );
        assert_eq!(
            commit_error_to_status(CommitErrorCode::AdmissionRejected),
            MgmtStatus::Unavailable
        );
        assert_eq!(
            commit_error_to_status(CommitErrorCode::DeadlineExceeded),
            MgmtStatus::DeadlineExceeded
        );
        assert_eq!(
            commit_error_to_status(CommitErrorCode::RecoveryRequired),
            MgmtStatus::FailedPrecondition
        );
        assert_eq!(
            commit_error_to_status(CommitErrorCode::OutcomeUnknown),
            MgmtStatus::FailedPrecondition
        );
        assert_eq!(
            commit_error_to_status(CommitErrorCode::ApplyPlanRejected),
            MgmtStatus::FailedPrecondition
        );
        assert_eq!(
            commit_error_to_status(CommitErrorCode::SemanticValidationFailed),
            MgmtStatus::InvalidArgument
        );
        assert_eq!(
            commit_error_to_status(CommitErrorCode::RollbackNotFound),
            MgmtStatus::NotFound
        );
        assert_eq!(
            commit_error_to_status(CommitErrorCode::StateMachineFault),
            MgmtStatus::Internal
        );

        // NETCONF spec §13
        assert_eq!(
            commit_error_to_netconf(CommitErrorCode::AuthorizationDenied),
            NetconfError::new(NetconfErrorType::Protocol, NetconfErrorTag::AccessDenied)
        );
        assert_eq!(
            commit_error_to_netconf(CommitErrorCode::SemanticValidationFailed),
            NetconfError::new(
                NetconfErrorType::Application,
                NetconfErrorTag::OperationFailed
            )
        );
        assert_eq!(
            commit_error_to_netconf(CommitErrorCode::MissingCandidate),
            NetconfError::new(NetconfErrorType::Protocol, NetconfErrorTag::MissingElement)
        );
        assert_eq!(
            commit_error_to_netconf(CommitErrorCode::RecoveryRequired),
            NetconfError::new(
                NetconfErrorType::Application,
                NetconfErrorTag::OperationFailed
            )
        );
        assert_eq!(
            commit_error_to_netconf(CommitErrorCode::OutcomeUnknown),
            NetconfError::new(
                NetconfErrorType::Application,
                NetconfErrorTag::OperationFailed
            )
        );
        assert_eq!(
            commit_error_to_netconf(CommitErrorCode::ApplyPlanRejected),
            NetconfError::new(
                NetconfErrorType::Application,
                NetconfErrorTag::OperationFailed
            )
        );
    }

    #[test]
    fn nacm_denials_map_consistently() {
        assert_eq!(nacm_denied_status(), MgmtStatus::PermissionDenied);
        assert_eq!(
            nacm_denied_netconf(),
            NetconfError::new(NetconfErrorType::Protocol, NetconfErrorTag::AccessDenied)
        );
    }

    #[test]
    fn status_and_tag_strings_are_stable() {
        assert_eq!(MgmtStatus::PermissionDenied.as_str(), "PERMISSION_DENIED");
        assert_eq!(
            MgmtStatus::FailedPrecondition.as_str(),
            "FAILED_PRECONDITION"
        );
        assert_eq!(NetconfErrorTag::AccessDenied.as_str(), "access-denied");
        assert_eq!(
            NetconfErrorTag::OperationFailed.as_str(),
            "operation-failed"
        );
        assert_eq!(NetconfErrorType::Protocol.as_str(), "protocol");
    }

    #[test]
    fn outcome_unknown_has_distinct_redaction_safe_netconf_app_tag() {
        assert_eq!(
            commit_error_to_netconf_app_tag(CommitErrorCode::OutcomeUnknown),
            Some(NETCONF_OUTCOME_UNKNOWN_APP_TAG)
        );
        assert_eq!(NETCONF_OUTCOME_UNKNOWN_APP_TAG, "outcome-unknown");
        assert_eq!(
            commit_error_to_netconf_app_tag(CommitErrorCode::PersistFailed),
            None
        );
    }
}
