//! Management-plane audit event model and sink for the OpenPacketCore gNMI and
//! NETCONF servers.
//!
//! `opc-config-bus` durably records *committed* config changes, but the spec
//! requires auditing every management operation, including the failed and
//! **denied** ones that never produce a commit (NACM denials, validation
//! failures, rejected reads). [`AuditEvent`] + [`AuditSink`] are that
//! complementary trail.
//!
//! An event records the touched **schema-node paths** (predicate-free, so list
//! key *values* never enter the audit), and outcomes carry validated stable
//! machine codes, never free-form messages. [`TracingAuditSink`] is a
//! best-effort diagnostic bridge that reports a disabled tracing target as loss;
//! production fail-closed paths should use a durable, tamper-evident sink over
//! `opc-persist`.
//!
//! Audit is a privileged record (it legitimately names the principal) and is
//! distinct from a redaction-scrubbed diagnostic bundle. Use
//! [`label_safe_outcome`] / [`label_safe_reason`] / [`label_safe_transport`] for
//! metric labels; never use principal or request id as labels.

#![forbid(unsafe_code)]

use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

use opc_config_model::{RequestId, TransportType, TrustedPrincipal, WorkloadIdentity};
use opc_redaction::metrics_label_safe;
use thiserror::Error;

const MAX_AUDIT_REASON_CODE_LEN: usize = 64;
static TRACING_AUDIT_EVENTS_DROPPED: AtomicU64 = AtomicU64::new(0);

/// Number of events the tracing audit sink could not emit because its tracing
/// target was disabled.
pub fn tracing_audit_events_dropped() -> u64 {
    TRACING_AUDIT_EVENTS_DROPPED.load(Ordering::Relaxed)
}

/// The management operation being audited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOperation {
    /// Capability/schema discovery.
    Capabilities,
    /// Data read (gNMI `Get`, NETCONF `<get>`/`<get-config>`).
    Read,
    /// Subscription create.
    Subscribe,
    /// Node creation.
    Create,
    /// Merge/update.
    Update,
    /// Subtree replace.
    Replace,
    /// Deletion.
    Delete,
    /// Candidate-to-running commit.
    Commit,
    /// Rollback.
    Rollback,
    /// Validation.
    Validate,
    /// RPC/exec (e.g. `<kill-session>`).
    Exec,
}

impl AuditOperation {
    /// Stable lowercase operation code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Capabilities => "capabilities",
            Self::Read => "read",
            Self::Subscribe => "subscribe",
            Self::Create => "create",
            Self::Update => "update",
            Self::Replace => "replace",
            Self::Delete => "delete",
            Self::Commit => "commit",
            Self::Rollback => "rollback",
            Self::Validate => "validate",
            Self::Exec => "exec",
        }
    }
}

/// Stable, value-free reason code for denied/failed audit outcomes.
///
/// Reason codes are intentionally constrained to a small machine-code alphabet
/// so callers cannot accidentally use free-form backend errors, identifiers, or
/// request values as audit outcome reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditReasonCode(&'static str);

impl AuditReasonCode {
    /// RFC-shaped access denial.
    pub const ACCESS_DENIED: Self = Self("access-denied");
    /// RFC-shaped unsupported operation.
    pub const OPERATION_NOT_SUPPORTED: Self = Self("operation-not-supported");
    /// Resource unavailable/denied.
    pub const RESOURCE_DENIED: Self = Self("resource-denied");
    /// Invalid input value.
    pub const INVALID_VALUE: Self = Self("invalid-value");
    /// Ambiguous schema source.
    pub const DATA_NOT_UNIQUE: Self = Self("data-not-unique");
    /// Generic operation failure.
    pub const OPERATION_FAILED: Self = Self("operation-failed");
    /// Malformed NETCONF message.
    pub const MALFORMED_MESSAGE: Self = Self("malformed-message");
    /// Unknown XML namespace.
    pub const UNKNOWN_NAMESPACE: Self = Self("unknown-namespace");
    /// Missing required attribute.
    pub const MISSING_ATTRIBUTE: Self = Self("missing-attribute");
    /// Missing required element.
    pub const MISSING_ELEMENT: Self = Self("missing-element");
    /// Request exceeded a configured bound.
    pub const TOO_BIG: Self = Self("too-big");

    /// Validates a stable reason code.
    pub fn new(code: &'static str) -> Result<Self, AuditReasonCodeError> {
        if code.is_empty() {
            return Err(AuditReasonCodeError::Empty);
        }
        if code.len() > MAX_AUDIT_REASON_CODE_LEN {
            return Err(AuditReasonCodeError::TooLong);
        }
        if !code
            .chars()
            .all(|ch| matches!(ch, 'a'..='z' | '0'..='9' | '-' | '_' | '.'))
        {
            return Err(AuditReasonCodeError::UnsafeCharacter);
        }
        Ok(Self(code))
    }

    /// Returns the reason-code string.
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for AuditReasonCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Invalid audit reason code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuditReasonCodeError {
    /// Code was empty.
    #[error("audit reason code must not be empty")]
    Empty,
    /// Code exceeded the audit reason-code bound.
    #[error("audit reason code is too long")]
    TooLong,
    /// Code contained characters outside the stable machine-code alphabet.
    #[error("audit reason code contains unsafe characters")]
    UnsafeCharacter,
}

/// A predicate-free schema-node path safe for audit path sets.
///
/// This is intentionally narrower than `opc_config_model::YangPath`: the commit
/// journal may record instance paths, but management-plane failed/denied audits
/// record schema nodes only so list-key values never enter the audit path set.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SchemaNodePath(String);

impl SchemaNodePath {
    /// Validates a predicate-free schema-node path.
    pub fn new(path: impl Into<String>) -> Result<Self, SchemaNodePathError> {
        let path = path.into();
        if path.is_empty() {
            return Err(SchemaNodePathError::Empty);
        }
        if !path.starts_with('/') {
            return Err(SchemaNodePathError::Relative);
        }
        if path.chars().any(char::is_control) {
            return Err(SchemaNodePathError::ControlCharacter);
        }
        if path.contains('[')
            || path.contains(']')
            || path.contains('=')
            || path.contains('"')
            || path.contains('\'')
        {
            return Err(SchemaNodePathError::PredicateOrValue);
        }
        if path == "/" {
            return Err(SchemaNodePathError::MalformedSegment);
        }

        for segment in path.trim_start_matches('/').split('/') {
            let Some((prefix, name)) = segment.split_once(':') else {
                return Err(SchemaNodePathError::MalformedSegment);
            };
            if segment.split_once(':') != segment.rsplit_once(':') {
                return Err(SchemaNodePathError::MalformedSegment);
            }
            validate_yang_identifier(prefix).map_err(|_| SchemaNodePathError::MalformedSegment)?;
            validate_yang_identifier(name).map_err(|_| SchemaNodePathError::MalformedSegment)?;
        }
        Ok(Self(path))
    }

    /// Returns the path string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SchemaNodePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn validate_yang_identifier(value: &str) -> Result<(), ()> {
    if value.is_empty() || value.trim() != value {
        return Err(());
    }

    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(());
    };
    if !matches!(first, 'a'..='z' | 'A'..='Z' | '_') {
        return Err(());
    }

    for ch in chars {
        if !matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.') {
            return Err(());
        }
    }
    Ok(())
}

/// Invalid audit schema-node path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SchemaNodePathError {
    /// Path was empty.
    #[error("audit schema path must not be empty")]
    Empty,
    /// Path did not start with `/`.
    #[error("audit schema path must be absolute")]
    Relative,
    /// Path contained a control character.
    #[error("audit schema path must not contain control characters")]
    ControlCharacter,
    /// Path looked instance-qualified or value-bearing.
    #[error("audit schema path must be predicate-free")]
    PredicateOrValue,
    /// Path was not made of prefix-qualified YANG identifier segments.
    #[error("audit schema path must contain prefix-qualified YANG identifiers")]
    MalformedSegment,
}

/// Audit sink failure. Display text is payload-free; backend details remain
/// server-side diagnostics via [`Self::detail`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuditError {
    /// The audit destination is unavailable or cannot accept records.
    #[error("management audit sink unavailable")]
    Unavailable {
        /// Server-side diagnostic detail. Do not surface directly to clients.
        detail: String,
    },
    /// The audit destination rejected or failed to persist the record.
    #[error("management audit sink failed")]
    Failed {
        /// Server-side diagnostic detail. Do not surface directly to clients.
        detail: String,
    },
}

impl AuditError {
    /// Constructs an unavailable audit-sink error.
    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self::Unavailable {
            detail: detail.into(),
        }
    }

    /// Constructs a failed audit-write error.
    pub fn failed(detail: impl Into<String>) -> Self {
        Self::Failed {
            detail: detail.into(),
        }
    }

    /// Server-side diagnostic detail.
    pub fn detail(&self) -> &str {
        match self {
            Self::Unavailable { detail } | Self::Failed { detail } => detail,
        }
    }
}

/// The outcome of an audited operation. Denied/Failed carry a stable machine
/// code (never a free-form message, so nothing sensitive leaks into the trail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditOutcome {
    /// The operation intent was durably recorded before the side effect.
    Intent,
    /// The operation succeeded.
    Success,
    /// The operation was authorized-denied (e.g. NACM `access-denied`).
    Denied(AuditReasonCode),
    /// The operation failed (e.g. `operation-failed`, `invalid-value`).
    Failed(AuditReasonCode),
}

impl AuditOutcome {
    /// Builds a denied outcome after validating the reason code.
    pub fn denied(code: &'static str) -> Result<Self, AuditReasonCodeError> {
        Ok(Self::Denied(AuditReasonCode::new(code)?))
    }

    /// Builds a failed outcome after validating the reason code.
    pub fn failed(code: &'static str) -> Result<Self, AuditReasonCodeError> {
        Ok(Self::Failed(AuditReasonCode::new(code)?))
    }

    /// Builds a denied outcome from a pre-validated code.
    pub const fn denied_code(code: AuditReasonCode) -> Self {
        Self::Denied(code)
    }

    /// Builds a failed outcome from a pre-validated code.
    pub const fn failed_code(code: AuditReasonCode) -> Self {
        Self::Failed(code)
    }

    /// Stable outcome class string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Success => "success",
            Self::Denied(_) => "denied",
            Self::Failed(_) => "failed",
        }
    }

    /// The stable reason code for a denied/failed outcome, if any.
    pub const fn code(self) -> Option<&'static str> {
        match self {
            Self::Intent | Self::Success => None,
            Self::Denied(code) | Self::Failed(code) => Some(code.as_str()),
        }
    }
}

/// Stable transport code for audit records.
pub const fn transport_code(transport: TransportType) -> &'static str {
    match transport {
        TransportType::Gnmi => "gnmi",
        TransportType::NetconfSsh => "netconf-ssh",
        TransportType::NetconfTls => "netconf-tls",
        TransportType::RestconfHttps => "restconf-https",
        TransportType::Internal => "internal",
    }
}

/// Stable principal descriptor for audit records.
pub fn principal_descriptor(principal: &TrustedPrincipal) -> String {
    match &principal.identity {
        WorkloadIdentity::Spiffe(id) => id.to_string(),
        WorkloadIdentity::User(user) => format!("user:{user}"),
        WorkloadIdentity::Internal(name) => format!("internal:{name}"),
    }
}

/// Sanitizes the audit outcome class for metric labels.
pub fn label_safe_outcome(outcome: AuditOutcome) -> String {
    metrics_label_safe(outcome.as_str())
}

/// Sanitizes the audit reason code for metric labels.
pub fn label_safe_reason(outcome: AuditOutcome) -> String {
    metrics_label_safe(outcome.code().unwrap_or("none"))
}

/// Sanitizes the transport code for metric labels.
pub fn label_safe_transport(transport: TransportType) -> String {
    metrics_label_safe(transport_code(transport))
}

/// One management-plane audit event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// Northbound request correlation id.
    pub request_id: RequestId,
    /// Tenant the principal belongs to.
    pub tenant: String,
    /// Principal descriptor (e.g. SPIFFE id). Audit legitimately names the
    /// principal; do not put this in a metric label or diagnostic bundle.
    pub principal: String,
    /// Northbound transport.
    pub transport: TransportType,
    /// The operation.
    pub operation: AuditOperation,
    /// Schema-node paths touched (predicate-free — no list-key values).
    pub schema_paths: Vec<SchemaNodePath>,
    /// The outcome.
    pub outcome: AuditOutcome,
    /// Transaction id, when the operation produced/targeted one.
    pub tx_id: Option<String>,
}

impl AuditEvent {
    /// Builds an event with no paths or transaction id set.
    pub fn new(
        request_id: RequestId,
        principal: &TrustedPrincipal,
        transport: TransportType,
        operation: AuditOperation,
        outcome: AuditOutcome,
    ) -> Self {
        Self {
            request_id,
            tenant: principal.tenant.to_string(),
            principal: principal_descriptor(principal),
            transport,
            operation,
            schema_paths: Vec::new(),
            outcome,
            tx_id: None,
        }
    }

    /// Attaches the touched schema-node paths (predicate-free).
    pub fn with_paths(mut self, paths: impl IntoIterator<Item = SchemaNodePath>) -> Self {
        self.schema_paths = paths.into_iter().collect();
        self
    }

    /// Attaches the transaction id.
    pub fn with_tx_id(mut self, tx_id: impl Into<String>) -> Self {
        self.tx_id = Some(tx_id.into());
        self
    }
}

/// A destination for management-plane audit events. Implemented by a durable,
/// tamper-evident store in production; [`TracingAuditSink`] is the default.
pub trait AuditSink: Send + Sync {
    /// Records one audit event. Implementations must not drop events silently on
    /// the success path of a security-relevant operation; callers that are about
    /// to grant access or mutate state must fail closed when this returns `Err`.
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError>;
}

/// An [`AuditSink`] that emits a structured event on the `opc_mgmt_audit`
/// tracing target.
///
/// This sink is best-effort and not durable. It returns
/// [`AuditError::Unavailable`] when the `opc_mgmt_audit` INFO target is
/// disabled, and increments [`tracing_audit_events_dropped`]. It cannot prove
/// that a downstream log collector accepted the event after tracing dispatch, so
/// security-critical production paths should provide a durable sink instead.
#[derive(Debug, Clone, Copy, Default)]
pub struct TracingAuditSink;

impl AuditSink for TracingAuditSink {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        if !tracing::enabled!(target: "opc_mgmt_audit", tracing::Level::INFO) {
            TRACING_AUDIT_EVENTS_DROPPED.fetch_add(1, Ordering::Relaxed);
            return Err(AuditError::unavailable(
                "opc_mgmt_audit tracing target is disabled",
            ));
        }

        // schema_paths are predicate-free node names, safe to record verbatim.
        let paths = event
            .schema_paths
            .iter()
            .map(SchemaNodePath::as_str)
            .collect::<Vec<_>>()
            .join(",");
        tracing::info!(
            target: "opc_mgmt_audit",
            request_id = %event.request_id,
            tenant = %event.tenant,
            principal = %event.principal,
            transport = transport_code(event.transport),
            operation = event.operation.as_str(),
            outcome = event.outcome.as_str(),
            reason = event.outcome.code().unwrap_or("-"),
            tx_id = event.tx_id.as_deref().unwrap_or("-"),
            paths = %paths,
            "management-plane audit",
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_config_model::{AuthStrength, TrustedPrincipal, WorkloadIdentity};
    use opc_types::TenantId;
    use std::sync::Mutex;

    #[derive(Default)]
    struct CapturingSink {
        events: Mutex<Vec<AuditEvent>>,
    }
    impl AuditSink for CapturingSink {
        fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
            self.events.lock().expect("audit mutex").push(event.clone());
            Ok(())
        }
    }

    struct FailingSink;
    impl AuditSink for FailingSink {
        fn record(&self, _event: &AuditEvent) -> Result<(), AuditError> {
            Err(AuditError::unavailable(
                "sqlite unavailable for tenant acme",
            ))
        }
    }

    fn principal() -> TrustedPrincipal {
        TrustedPrincipal::new(
            WorkloadIdentity::User("operator".to_string()),
            TenantId::new("acme").expect("tenant"),
        )
        .with_auth_strength(AuthStrength::MutualTls)
    }

    fn schema_path(value: &str) -> SchemaNodePath {
        SchemaNodePath::new(value).expect("schema path")
    }

    #[test]
    fn records_a_denied_read_with_stable_code() {
        let sink = CapturingSink::default();
        let principal = principal();
        let request_id = RequestId::new();
        let event = AuditEvent::new(
            request_id,
            &principal,
            TransportType::Gnmi,
            AuditOperation::Read,
            AuditOutcome::denied_code(AuditReasonCode::ACCESS_DENIED),
        )
        .with_paths([schema_path("/sys:system/sys:secret")]);

        sink.record(&event).expect("audit record");

        let captured = sink.events.lock().expect("audit mutex");
        assert_eq!(captured.len(), 1);
        assert_eq!(captured[0].request_id, request_id);
        assert_eq!(captured[0].tenant, "acme");
        assert_eq!(captured[0].principal, "user:operator");
        assert_eq!(captured[0].operation, AuditOperation::Read);
        assert_eq!(captured[0].outcome.as_str(), "denied");
        assert_eq!(captured[0].outcome.code(), Some("access-denied"));
        assert_eq!(
            captured[0].schema_paths,
            vec![schema_path("/sys:system/sys:secret")]
        );
    }

    #[test]
    fn records_a_successful_commit_with_tx_id() {
        let sink = CapturingSink::default();
        let principal = principal();
        let event = AuditEvent::new(
            RequestId::new(),
            &principal,
            TransportType::NetconfTls,
            AuditOperation::Commit,
            AuditOutcome::Success,
        )
        .with_tx_id("tx-abc");

        sink.record(&event).expect("audit record");
        let captured = sink.events.lock().expect("audit mutex");
        assert_eq!(captured[0].outcome, AuditOutcome::Success);
        assert_eq!(captured[0].outcome.code(), None);
        assert_eq!(captured[0].tx_id.as_deref(), Some("tx-abc"));
        assert_eq!(captured[0].transport, TransportType::NetconfTls);
        assert_eq!(transport_code(captured[0].transport), "netconf-tls");
    }

    #[test]
    fn outcome_codes_are_stable() {
        assert_eq!(AuditOutcome::Intent.as_str(), "intent");
        assert_eq!(AuditOutcome::Intent.code(), None);
        assert_eq!(AuditOutcome::Success.as_str(), "success");
        assert_eq!(
            AuditOutcome::denied_code(AuditReasonCode::ACCESS_DENIED).as_str(),
            "denied"
        );
        assert_eq!(
            AuditOutcome::failed_code(AuditReasonCode::OPERATION_FAILED).as_str(),
            "failed"
        );
        assert_eq!(
            AuditOutcome::failed_code(AuditReasonCode::OPERATION_FAILED).code(),
            Some("operation-failed")
        );
    }

    #[test]
    fn operation_codes_are_stable() {
        assert_eq!(AuditOperation::Capabilities.as_str(), "capabilities");
        assert_eq!(AuditOperation::Read.as_str(), "read");
        assert_eq!(AuditOperation::Subscribe.as_str(), "subscribe");
        assert_eq!(AuditOperation::Exec.as_str(), "exec");
    }

    #[test]
    fn schema_paths_reject_instance_predicates_and_values() {
        assert!(SchemaNodePath::new("/sys:system/sys:user/sys:secret").is_ok());
        assert!(SchemaNodePath::new("/if-:interfaces-/if-:admin.status").is_ok());
        assert_eq!(
            SchemaNodePath::new("sys:system").unwrap_err(),
            SchemaNodePathError::Relative
        );
        assert_eq!(
            SchemaNodePath::new("/sys:system/sys:user[sys:name='admin']/sys:secret").unwrap_err(),
            SchemaNodePathError::PredicateOrValue
        );
        assert_eq!(
            SchemaNodePath::new("/sys:system/sys:user=sys:admin").unwrap_err(),
            SchemaNodePathError::PredicateOrValue
        );
    }

    #[test]
    fn schema_paths_reject_malformed_schema_segments() {
        for malformed in [
            "/",
            "/sys:system/",
            "/sys:system//sys:hostname",
            "/sys:system/hostname",
            "/9sys:system/sys:hostname",
            "/sys:system/sys:bad name",
            "/sys:system/sys:bad:name",
        ] {
            assert_eq!(
                SchemaNodePath::new(malformed).unwrap_err(),
                SchemaNodePathError::MalformedSegment,
                "{malformed}"
            );
        }
    }

    #[test]
    fn metric_label_helpers_sanitize_only_safe_dimensions() {
        assert_eq!(label_safe_outcome(AuditOutcome::Intent), "intent");
        assert_eq!(label_safe_outcome(AuditOutcome::Success), "success");
        assert_eq!(
            label_safe_reason(AuditOutcome::denied_code(AuditReasonCode::ACCESS_DENIED)),
            "access-denied"
        );
        assert_eq!(
            label_safe_transport(TransportType::NetconfTls),
            "netconf-tls"
        );
        assert_eq!(
            metrics_label_safe("spiffe://example.org/tenant/acme"),
            "redacted"
        );
    }

    #[test]
    fn audit_errors_are_payload_free_but_keep_diagnostics() {
        let err =
            AuditError::unavailable("failed writing /sys:system/sys:user[sys:name='secret-admin']");
        assert_eq!(err.to_string(), "management audit sink unavailable");
        assert!(err.detail().contains("secret-admin"));
        assert!(!err.to_string().contains("secret-admin"));

        let principal = principal();
        let event = AuditEvent::new(
            RequestId::new(),
            &principal,
            TransportType::Gnmi,
            AuditOperation::Read,
            AuditOutcome::failed_code(AuditReasonCode::OPERATION_FAILED),
        );
        assert!(matches!(
            FailingSink.record(&event),
            Err(AuditError::Unavailable { .. })
        ));
    }

    #[test]
    fn tracing_sink_reports_disabled_target_without_silent_loss() {
        let principal = principal();
        let before = tracing_audit_events_dropped();

        let err = TracingAuditSink
            .record(&AuditEvent::new(
                RequestId::new(),
                &principal,
                TransportType::Gnmi,
                AuditOperation::Update,
                AuditOutcome::failed_code(AuditReasonCode::OPERATION_FAILED),
            ))
            .expect_err("disabled tracing audit target must fail closed");

        assert!(matches!(err, AuditError::Unavailable { .. }));
        assert_eq!(tracing_audit_events_dropped(), before + 1);
    }

    #[test]
    fn audit_reason_codes_reject_free_form_or_sensitive_values() {
        assert_eq!(
            AuditReasonCode::new("operation-failed")
                .expect("reason")
                .as_str(),
            "operation-failed"
        );
        assert_eq!(
            AuditReasonCode::new("").unwrap_err(),
            AuditReasonCodeError::Empty
        );
        assert_eq!(
            AuditReasonCode::new("access denied").unwrap_err(),
            AuditReasonCodeError::UnsafeCharacter
        );
        assert_eq!(
            AuditReasonCode::new("spiffe://example.org/tenant/acme").unwrap_err(),
            AuditReasonCodeError::UnsafeCharacter
        );
        assert_eq!(
            AuditReasonCode::new(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
            .unwrap_err(),
            AuditReasonCodeError::TooLong
        );
    }
}
