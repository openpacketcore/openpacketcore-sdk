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
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use opc_config_model::{RequestId, TransportType, TrustedPrincipal, WorkloadIdentity};
use opc_redaction::metrics_label_safe;
use thiserror::Error;

const MAX_AUDIT_REASON_CODE_LEN: usize = 64;
const MAX_AUDIT_TX_ID_LEN: usize = 128;
const NANOS_PER_SECOND: i128 = 1_000_000_000;
/// Largest monotonic sequence representable by the durable SQLite profile.
pub const MAX_AUDIT_MONOTONIC_SEQUENCE: u64 = i64::MAX as u64;
static TRACING_AUDIT_EVENTS_DROPPED: AtomicU64 = AtomicU64::new(0);
static AUDIT_MONOTONIC_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Number of events the tracing audit sink could not emit because its tracing
/// target was disabled.
pub fn tracing_audit_events_dropped() -> u64 {
    TRACING_AUDIT_EVENTS_DROPPED.load(Ordering::Relaxed)
}

/// Authority that supplied an audit event's UTC wall-clock timestamp.
///
/// The default is deliberately [`Self::NodeClock`]. A caller may claim
/// [`Self::SynchronisedNodeClock`] only when it has independent evidence that
/// the node clock is actively disciplined; the SDK does not manufacture that
/// assurance from a successful clock read.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum AuditTimeSource {
    /// Node wall clock with no synchronisation assurance.
    #[default]
    NodeClock,
    /// Node wall clock while a synchronisation source was disciplined.
    SynchronisedNodeClock,
}

impl AuditTimeSource {
    /// Stable lowercase source code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NodeClock => "node-clock",
            Self::SynchronisedNodeClock => "synchronised-node-clock",
        }
    }
}

/// UTC wall-clock time plus a process-local monotonic ordering sequence.
///
/// RFC 003 §11.3 requires UTC audit timestamps and recommends pairing wall
/// clock with a monotonic sequence. `utc_seconds` is signed seconds from the
/// Unix epoch, so pre-epoch instants are unambiguous; `nanosecond` is the
/// canonical non-negative fractional second. The sequence is nondecreasing and
/// saturates at [`MAX_AUDIT_MONOTONIC_SEQUENCE`] instead of wrapping. Once
/// saturated it no longer supplies a unique tiebreak; consumers must not infer
/// strict order from equal terminal sequence values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuditInstant {
    utc_seconds: i64,
    nanosecond: u32,
    monotonic_sequence: u64,
    source: AuditTimeSource,
}

impl AuditInstant {
    /// Read the node clock without claiming synchronisation.
    ///
    /// Clock reads are infallible at this boundary. Host times outside the
    /// signed durable range saturate to the nearest representable UTC instant.
    pub fn now() -> Self {
        Self::from_system_time(SystemTime::now(), AuditTimeSource::NodeClock)
    }

    /// Read the node clock with an explicit source attribution.
    ///
    /// Passing [`AuditTimeSource::SynchronisedNodeClock`] is an assurance by
    /// the caller and must be backed by its clock-discipline authority.
    pub fn now_with_source(source: AuditTimeSource) -> Self {
        Self::from_system_time(SystemTime::now(), source)
    }

    /// Convert a wall-clock reading with an explicit source attribution.
    ///
    /// This is useful for adapters with an injectable clock. It allocates a
    /// fresh process-local monotonic sequence and never fails.
    pub fn from_system_time(time: SystemTime, source: AuditTimeSource) -> Self {
        let (utc_seconds, nanosecond) = utc_parts(time);
        Self {
            utc_seconds,
            nanosecond,
            monotonic_sequence: next_audit_monotonic_sequence(),
            source,
        }
    }

    /// Reconstruct an instant from authenticated durable parts.
    pub fn try_from_parts(
        utc_seconds: i64,
        nanosecond: u32,
        monotonic_sequence: u64,
        source: AuditTimeSource,
    ) -> Result<Self, AuditInstantError> {
        if nanosecond >= NANOS_PER_SECOND as u32 {
            return Err(AuditInstantError::Nanosecond);
        }
        if monotonic_sequence > MAX_AUDIT_MONOTONIC_SEQUENCE {
            return Err(AuditInstantError::MonotonicSequence);
        }
        Ok(Self {
            utc_seconds,
            nanosecond,
            monotonic_sequence,
            source,
        })
    }

    /// Signed whole UTC seconds from the Unix epoch.
    pub const fn utc_seconds(self) -> i64 {
        self.utc_seconds
    }

    /// Canonical fractional nanosecond in `0..1_000_000_000`.
    pub const fn nanosecond(self) -> u32 {
        self.nanosecond
    }

    /// Process-local nondecreasing ordering sequence.
    ///
    /// Equal values at [`MAX_AUDIT_MONOTONIC_SEQUENCE`] indicate exhaustion,
    /// not simultaneous events or a strict ordering.
    pub const fn monotonic_sequence(self) -> u64 {
        self.monotonic_sequence
    }

    /// Wall-clock source attribution.
    pub const fn source(self) -> AuditTimeSource {
        self.source
    }
}

/// Invalid authenticated audit-time parts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuditInstantError {
    /// Fractional nanosecond was outside its canonical range.
    #[error("audit timestamp nanosecond is outside its canonical range")]
    Nanosecond,
    /// Monotonic sequence exceeded the durable signed-integer range.
    #[error("audit monotonic sequence exceeds its durable range")]
    MonotonicSequence,
}

fn utc_parts(time: SystemTime) -> (i64, u32) {
    let unix_nanoseconds = match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => {
            i128::from(duration.as_secs()) * NANOS_PER_SECOND + i128::from(duration.subsec_nanos())
        }
        Err(error) => {
            let duration = error.duration();
            -(i128::from(duration.as_secs()) * NANOS_PER_SECOND
                + i128::from(duration.subsec_nanos()))
        }
    };
    let minimum = i128::from(i64::MIN) * NANOS_PER_SECOND;
    let maximum = i128::from(i64::MAX) * NANOS_PER_SECOND + (NANOS_PER_SECOND - 1);
    let bounded = unix_nanoseconds.clamp(minimum, maximum);
    (
        bounded.div_euclid(NANOS_PER_SECOND) as i64,
        bounded.rem_euclid(NANOS_PER_SECOND) as u32,
    )
}

const fn advance_audit_monotonic_sequence(current: u64) -> u64 {
    if current >= MAX_AUDIT_MONOTONIC_SEQUENCE {
        MAX_AUDIT_MONOTONIC_SEQUENCE
    } else {
        current + 1
    }
}

fn next_audit_monotonic_sequence() -> u64 {
    match AUDIT_MONOTONIC_SEQUENCE.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        Some(advance_audit_monotonic_sequence(current))
    }) {
        Ok(previous) => advance_audit_monotonic_sequence(previous),
        Err(current) => current,
    }
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

/// A bounded transaction id safe for audit records and trace fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuditTxId(String);

impl AuditTxId {
    /// Validates an audit transaction id.
    pub fn new(value: impl Into<String>) -> Result<Self, AuditTxIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(AuditTxIdError::Empty);
        }
        if value.len() > MAX_AUDIT_TX_ID_LEN {
            return Err(AuditTxIdError::TooLong);
        }
        if !value
            .chars()
            .all(|ch| matches!(ch, 'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.'))
        {
            return Err(AuditTxIdError::UnsafeCharacter);
        }
        Ok(Self(value))
    }

    /// Returns the transaction id string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AuditTxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Invalid audit transaction id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuditTxIdError {
    /// Transaction id was empty.
    #[error("audit transaction id must not be empty")]
    Empty,
    /// Transaction id exceeded the audit transaction-id bound.
    #[error("audit transaction id is too long")]
    TooLong,
    /// Transaction id contained characters outside the stable machine-code alphabet.
    #[error("audit transaction id contains unsafe characters")]
    UnsafeCharacter,
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
    /// UTC decision time, monotonic tiebreak, and clock-source attribution.
    ///
    /// Durable sinks authenticate every component of this value.
    pub occurred_at: AuditInstant,
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
    pub tx_id: Option<AuditTxId>,
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
            occurred_at: AuditInstant::now(),
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

    /// Replaces the default node-clock observation with an explicitly sourced
    /// audit instant.
    pub fn with_occurred_at(mut self, occurred_at: AuditInstant) -> Self {
        self.occurred_at = occurred_at;
        self
    }

    /// Attaches a validated transaction id.
    pub fn with_tx_id(mut self, tx_id: impl Into<String>) -> Result<Self, AuditTxIdError> {
        self.tx_id = Some(AuditTxId::new(tx_id)?);
        Ok(self)
    }
}

/// A destination for management-plane audit events. Implemented by a durable,
/// tamper-evident store in production; [`TracingAuditSink`] is the default.
pub trait AuditSink: Send + Sync {
    /// Records one audit event. Implementations must not drop events silently on
    /// the success path of a security-relevant operation; callers that are about
    /// to grant access or mutate state must fail closed when this returns `Err`.
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError>;

    /// Records one audit event from an asynchronous caller.
    ///
    /// The compatibility default invokes [`Self::record`] when the returned
    /// future is polled and may therefore block that poll. Existing
    /// implementations remain source-compatible, but a sink whose synchronous
    /// method waits on I/O or another thread must override this method before
    /// it is used on an async executor.
    ///
    /// An unpolled future need not persist anything. Once polled, an override
    /// must either complete or, before first returning
    /// [`std::task::Poll::Pending`], hand an immutable representation of the
    /// event to cancellation-independent processing. Dropping the future after
    /// that admission cannot retract the event. A timeout, error, or dropped
    /// future after admission can leave the durable outcome unknown, and
    /// callers must never infer that the event was not persisted.
    fn record_async<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuditError>> + Send + 'a>> {
        Box::pin(async move { self.record(event) })
    }
}

impl<T: AuditSink + ?Sized> AuditSink for Arc<T> {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        (**self).record(event)
    }

    fn record_async<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuditError>> + Send + 'a>> {
        (**self).record_async(event)
    }
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
            occurred_at_utc_seconds = event.occurred_at.utc_seconds(),
            occurred_at_nanosecond = event.occurred_at.nanosecond(),
            occurred_at_monotonic_sequence = event.occurred_at.monotonic_sequence(),
            occurred_at_time_source = event.occurred_at.source().as_str(),
            tenant = %event.tenant,
            principal = %event.principal,
            transport = transport_code(event.transport),
            operation = event.operation.as_str(),
            outcome = event.outcome.as_str(),
            reason = event.outcome.code().unwrap_or("-"),
            tx_id = event.tx_id.as_ref().map(AuditTxId::as_str).unwrap_or("-"),
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
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

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

    #[derive(Default)]
    struct AsyncOnlySink {
        calls: AtomicUsize,
    }

    impl AuditSink for AsyncOnlySink {
        fn record(&self, _event: &AuditEvent) -> Result<(), AuditError> {
            panic!("Arc forwarding used the blocking compatibility method")
        }

        fn record_async<'a>(
            &'a self,
            _event: &'a AuditEvent,
        ) -> Pin<Box<dyn Future<Output = Result<(), AuditError>> + Send + 'a>> {
            Box::pin(async move {
                self.calls.fetch_add(1, Ordering::Relaxed);
                Err(AuditError::failed("asynchronous sentinel"))
            })
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
    fn audit_instants_are_canonical_for_pre_epoch_time_and_default_to_node_clock() {
        let instant = AuditInstant::from_system_time(
            UNIX_EPOCH - std::time::Duration::from_nanos(1),
            AuditTimeSource::NodeClock,
        );
        assert_eq!(instant.utc_seconds(), -1);
        assert_eq!(instant.nanosecond(), 999_999_999);
        assert_eq!(instant.source(), AuditTimeSource::NodeClock);

        let event = AuditEvent::new(
            RequestId::new(),
            &principal(),
            TransportType::Internal,
            AuditOperation::Read,
            AuditOutcome::Success,
        );
        assert_eq!(event.occurred_at.source(), AuditTimeSource::NodeClock);
    }

    #[test]
    fn audit_instant_parts_reject_noncanonical_or_unpersistable_values() {
        assert_eq!(
            AuditInstant::try_from_parts(0, 1_000_000_000, 1, AuditTimeSource::NodeClock),
            Err(AuditInstantError::Nanosecond)
        );
        assert_eq!(
            AuditInstant::try_from_parts(
                0,
                0,
                MAX_AUDIT_MONOTONIC_SEQUENCE + 1,
                AuditTimeSource::NodeClock,
            ),
            Err(AuditInstantError::MonotonicSequence)
        );
        assert_eq!(
            advance_audit_monotonic_sequence(MAX_AUDIT_MONOTONIC_SEQUENCE),
            MAX_AUDIT_MONOTONIC_SEQUENCE
        );
    }

    #[test]
    fn concurrent_audit_instants_receive_unique_monotonic_sequences() {
        let mut workers = Vec::new();
        for _ in 0..32 {
            workers.push(std::thread::spawn(|| {
                AuditInstant::now().monotonic_sequence()
            }));
        }
        let mut sequences = workers
            .into_iter()
            .map(|worker| worker.join().expect("audit clock worker"))
            .collect::<Vec<_>>();
        sequences.sort_unstable();
        assert!(
            sequences.windows(2).all(|pair| pair[0] < pair[1]),
            "non-saturated concurrent allocations must be unique"
        );
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
        .with_tx_id("tx-abc")
        .expect("tx id");

        sink.record(&event).expect("audit record");
        let captured = sink.events.lock().expect("audit mutex");
        assert_eq!(captured[0].outcome, AuditOutcome::Success);
        assert_eq!(captured[0].outcome.code(), None);
        assert_eq!(
            captured[0].tx_id.as_ref().map(AuditTxId::as_str),
            Some("tx-abc")
        );
        assert_eq!(captured[0].transport, TransportType::NetconfTls);
        assert_eq!(transport_code(captured[0].transport), "netconf-tls");
    }

    #[test]
    fn audit_tx_ids_reject_injection_and_oversized_values() {
        let principal = principal();
        let event = AuditEvent::new(
            RequestId::new(),
            &principal,
            TransportType::NetconfTls,
            AuditOperation::Commit,
            AuditOutcome::Success,
        );

        assert_eq!(
            event.clone().with_tx_id("tx\ninjected").unwrap_err(),
            AuditTxIdError::UnsafeCharacter
        );
        assert_eq!(
            event.with_tx_id("x".repeat(1024 * 1024)).unwrap_err(),
            AuditTxIdError::TooLong
        );
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
    fn arc_trait_object_forwards_errors_unchanged() {
        let sink: Arc<dyn AuditSink> = Arc::new(FailingSink);
        let event = AuditEvent::new(
            RequestId::new(),
            &principal(),
            TransportType::Gnmi,
            AuditOperation::Read,
            AuditOutcome::failed_code(AuditReasonCode::OPERATION_FAILED),
        );

        let error = <Arc<dyn AuditSink> as AuditSink>::record(&sink, &event)
            .expect_err("failing sink error must be forwarded");

        assert_eq!(
            error,
            AuditError::unavailable("sqlite unavailable for tenant acme")
        );
    }

    #[test]
    fn async_default_keeps_existing_implementors_dyn_compatible() {
        let sink = CapturingSink::default();
        let object: &dyn AuditSink = &sink;
        let event = AuditEvent::new(
            RequestId::new(),
            &principal(),
            TransportType::Gnmi,
            AuditOperation::Read,
            AuditOutcome::Success,
        );

        futures_executor::block_on(object.record_async(&event))
            .expect("compatibility default records successfully");

        assert_eq!(sink.events.lock().expect("audit mutex").len(), 1);
    }

    #[test]
    fn arc_trait_object_forwards_async_override_without_blocking_fallback() {
        let concrete = Arc::new(AsyncOnlySink::default());
        let sink: Arc<dyn AuditSink> = concrete.clone();
        let event = AuditEvent::new(
            RequestId::new(),
            &principal(),
            TransportType::Gnmi,
            AuditOperation::Read,
            AuditOutcome::Success,
        );

        let error = futures_executor::block_on(<Arc<dyn AuditSink> as AuditSink>::record_async(
            &sink, &event,
        ))
        .expect_err("async sentinel must be forwarded");

        assert_eq!(error, AuditError::failed("asynchronous sentinel"));
        assert_eq!(concrete.calls.load(Ordering::Relaxed), 1);
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
