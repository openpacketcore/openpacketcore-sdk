//! Shared commit-model types for the OpenPacketCore configuration subsystem.
//!
//! The RFC 001 config bus splits durable commit execution from immutable
//! data-plane snapshot access. This crate holds the cross-crate request, result,
//! identity, and validation types used by that boundary.
//!
//! Apply-plan types classify the operational impact of a validated candidate
//! before durable append/publication. Products supply [`ConfigImpactClassifier`]
//! implementations for domain-specific rules; the default
//! [`HotConfigImpactClassifier`] preserves existing behavior by marking
//! SDK-derived changed paths as [`ChangeImpactClass::Hot`].
//!
//! ```
//! use opc_config_model::{
//!     CommitMode, CommitRequest, ConfigOperation, OpcConfig, RequestId, RequestSource,
//!     TransportType, TrustedPrincipal, ValidationContext, ValidationError, WorkloadIdentity,
//!     YangPath,
//! };
//! use opc_types::{ConfigVersion, SchemaDigest, TenantId};
//! use std::{str::FromStr, time::Instant};
//!
//! #[derive(Clone)]
//! struct ExampleConfig;
//!
//! impl OpcConfig for ExampleConfig {
//!     type Delta = &'static str;
//!
//!     fn schema_digest(&self) -> SchemaDigest {
//!         SchemaDigest::from_str(
//!             "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
//!         )
//!         .expect("valid digest")
//!     }
//!
//!     fn diff(&self, _previous: &Self) -> Result<Vec<Self::Delta>, opc_config_model::ConfigError> {
//!         Ok(vec!["replace:/example"])
//!     }
//!
//!     fn changed_paths(
//!         &self,
//!         _previous: &Self,
//!         _deltas: &[Self::Delta],
//!     ) -> Result<Vec<YangPath>, opc_config_model::ConfigError> {
//!         Ok(vec![YangPath::new("/example").expect("static path")])
//!     }
//!
//!     fn apply_delta(&mut self, _delta: Self::Delta) -> Result<(), opc_config_model::ConfigError> {
//!         Ok(())
//!     }
//!
//!     fn validate_syntax(&self) -> Result<(), ValidationError> {
//!         Ok(())
//!     }
//!
//!     fn validate_semantics(&self, _ctx: &ValidationContext<ExampleConfig>) -> Result<(), ValidationError> {
//!         Ok(())
//!     }
//! }
//!
//! let tenant = TenantId::new("tenant-a").expect("tenant");
//! let principal = TrustedPrincipal::new(
//!     WorkloadIdentity::Internal("system".into()),
//!     tenant,
//! );
//! let request = CommitRequest::commit(
//!     RequestId::new(),
//!     principal,
//!     TransportType::Internal,
//!     RequestSource::Northbound,
//!     ConfigOperation::Replace,
//!     ExampleConfig,
//!     vec![YangPath::new("/example").expect("path")],
//!     Instant::now(),
//! );
//!
//! assert!(matches!(request.mode, CommitMode::Commit));
//! assert_eq!(request.base_version, ConfigVersion::INITIAL);
//! ```

#![forbid(unsafe_code)]

use opc_types::{ConfigVersion, SchemaDigest, SpiffeId, TenantId, TxId};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use uuid::Uuid;

mod apply_plan;

pub use apply_plan::{
    ApplyPlan, ApplyPlanChange, ApplyPlanError, ApplyPlanWarning, ChangeImpact, ChangeImpactClass,
    ConfigImpactClassifier, ConfigWorkflowRequirement, HotConfigImpactClassifier,
    FORBIDDEN_LIVE_REQUIRES_MAINTENANCE_WORKFLOW,
};

/// Shared parse/validation error for config-model value objects.
///
/// The `kind` discriminator remains stringly typed on purpose so generated or
/// downstream value objects can introduce additional categories without forcing
/// an upstream enum expansion or exhaustive-match breakage.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{kind}: {message}")]
pub struct ValueError {
    kind: &'static str,
    message: String,
}

impl ValueError {
    fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> &'static str {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Workload identity associated with a trusted control-plane principal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WorkloadIdentity {
    Spiffe(SpiffeId),
    User(String),
    Internal(String),
}

/// Authentication strength presented by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthStrength {
    /// Mutual TLS with a verified peer certificate/SPIFFE identity.
    MutualTls,
    /// Bearer-token/JWT authentication.
    Jwt,
    /// SSH public-key or SSH-certificate authentication.
    SshPublicKey,
    /// Trusted local process boundary.
    LocalProcess,
}

/// Trusted principal used by commit admission and audit layers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedPrincipal {
    pub identity: WorkloadIdentity,
    pub tenant: TenantId,
    pub roles: Vec<String>,
    pub groups: Vec<String>,
    pub auth_strength: AuthStrength,
}

impl TrustedPrincipal {
    pub fn new(identity: WorkloadIdentity, tenant: TenantId) -> Self {
        Self {
            identity,
            tenant,
            roles: Vec::new(),
            groups: Vec::new(),
            auth_strength: AuthStrength::LocalProcess,
        }
    }

    pub fn with_auth_strength(mut self, auth_strength: AuthStrength) -> Self {
        self.auth_strength = auth_strength;
        self
    }

    pub fn with_roles(mut self, roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.roles = roles.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_groups(mut self, groups: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.groups = groups.into_iter().map(Into::into).collect();
        self
    }
}

/// Northbound transport used for the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportType {
    Gnmi,
    NetconfSsh,
    /// NETCONF over TLS (RFC 7589), distinct from [`TransportType::NetconfSsh`].
    ///
    /// A NETCONF-over-TLS session must record this transport so audit,
    /// authorization, and idempotency-fingerprint matching attribute the request
    /// to the transport it actually arrived on. Mapping TLS sessions onto
    /// `NetconfSsh` is forbidden because it makes those records inaccurate.
    NetconfTls,
    RestconfHttps,
    Internal,
}

/// Source that originated the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestSource {
    Northbound,
    StartupRecovery,
    Replication,
    Internal,
}

/// High-level config mutation shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfigOperation {
    Replace,
    Patch,
    Delete,
    Rollback,
}

/// Stable request identifier used to correlate retries and audit trails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestId(Uuid);

impl RequestId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for RequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for RequestId {
    type Err = ValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let uuid =
            Uuid::parse_str(value).map_err(|err| ValueError::new("request id", err.to_string()))?;
        Ok(Self(uuid))
    }
}

/// Optional caller-provided key used to deduplicate retried writes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(ValueError::new(
                "idempotency key",
                "value must not be empty or whitespace",
            ));
        }

        if value.chars().any(char::is_control) {
            return Err(ValueError::new(
                "idempotency key",
                "value must not contain control characters",
            ));
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdempotencyKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for IdempotencyKey {
    type Err = ValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Canonical YANG path used for authz, audit, and change reporting.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct YangPath(String);

impl YangPath {
    pub fn new(value: impl Into<String>) -> Result<Self, ValueError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ValueError::new("yang path", "path must not be empty"));
        }

        if !value.starts_with('/') {
            return Err(ValueError::new("yang path", "path must start with '/'"));
        }

        if value.chars().any(char::is_control) {
            return Err(ValueError::new(
                "yang path",
                "path must not contain control characters",
            ));
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for YangPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for YangPath {
    type Err = ValueError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

/// Rollback selectors admitted by the config store abstraction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RollbackTarget {
    Previous,
    Version(ConfigVersion),
    TxId(TxId),
    Label(String),
}

/// Commit operating mode from RFC 001 §5.3.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitMode {
    Commit,
    ValidateOnly,
    CommitConfirmed { timeout: Duration },
    CancelConfirmed,
    Rollback { target: RollbackTarget },
}

/// Stable result status returned to northbound callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitStatus {
    Committed,
    Validated,
    CommitConfirmedPending,
    RollbackApplied,
}

/// Machine-readable commit failure code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitErrorCode {
    AdmissionRejected,
    ApplyPlanRejected,
    DeadlineExceeded,
    MissingCandidate,
    SyntaxValidationFailed,
    SemanticValidationFailed,
    DiffFailed,
    PersistFailed,
    VersionExhausted,
    RollbackNotFound,
    RollbackUnavailable,
    RecoveryRequired,
    StateMachineFault,
    AuthorizationDenied,
}

impl CommitErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdmissionRejected => "admission_rejected",
            Self::ApplyPlanRejected => "apply_plan_rejected",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::MissingCandidate => "missing_candidate",
            Self::SyntaxValidationFailed => "syntax_validation_failed",
            Self::SemanticValidationFailed => "semantic_validation_failed",
            Self::DiffFailed => "diff_failed",
            Self::PersistFailed => "persist_failed",
            Self::VersionExhausted => "version_exhausted",
            Self::RollbackNotFound => "rollback_not_found",
            Self::RollbackUnavailable => "rollback_unavailable",
            Self::RecoveryRequired => "recovery_required",
            Self::StateMachineFault => "state_machine_fault",
            Self::AuthorizationDenied => "authorization_denied",
        }
    }
}

impl fmt::Display for CommitErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Stable commit failure envelope with a machine-readable code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[error("{code}: {message}")]
pub struct CommitError {
    pub code: CommitErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_plan: Option<Box<ApplyPlan>>,
}

impl CommitError {
    pub fn new(code: CommitErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            apply_plan: None,
        }
    }

    pub fn deadline_exceeded(message: impl Into<String>) -> Self {
        Self::new(CommitErrorCode::DeadlineExceeded, message)
    }

    pub fn missing_candidate() -> Self {
        Self::new(
            CommitErrorCode::MissingCandidate,
            "commit request did not include a candidate config",
        )
    }

    /// Redacts client-visible syntax failure detail while preserving the stage code.
    ///
    /// Implementations should log or audit the supplied validation error internally
    /// using redaction-aware sinks before returning this envelope to callers.
    pub fn syntax_validation(_error: ValidationError) -> Self {
        Self::new(
            CommitErrorCode::SyntaxValidationFailed,
            "candidate config failed syntax validation",
        )
    }

    /// Redacts client-visible semantic failure detail while preserving the stage code.
    ///
    /// Implementations should log or audit the supplied validation error internally
    /// using redaction-aware sinks before returning this envelope to callers.
    pub fn semantic_validation(_error: ValidationError) -> Self {
        Self::new(
            CommitErrorCode::SemanticValidationFailed,
            "candidate config failed semantic validation",
        )
    }

    /// Redacts client-visible diff failure detail while preserving the failure code.
    ///
    /// Implementations should log or audit the supplied config error internally
    /// using redaction-aware sinks before returning this envelope to callers.
    pub fn diff_failed(_error: ConfigError) -> Self {
        Self::new(
            CommitErrorCode::DiffFailed,
            "candidate config diff generation failed",
        )
    }

    pub fn persist_failed(message: impl Into<String>) -> Self {
        Self::new(CommitErrorCode::PersistFailed, message)
    }

    pub fn rollback_unavailable(message: impl Into<String>) -> Self {
        Self::new(CommitErrorCode::RollbackUnavailable, message)
    }

    pub fn rollback_not_found(message: impl Into<String>) -> Self {
        Self::new(CommitErrorCode::RollbackNotFound, message)
    }

    pub fn recovery_required(message: impl Into<String>) -> Self {
        Self::new(CommitErrorCode::RecoveryRequired, message)
    }

    pub fn state_machine_fault(message: impl Into<String>) -> Self {
        Self::new(CommitErrorCode::StateMachineFault, message)
    }

    pub fn authorization_denied(message: impl Into<String>) -> Self {
        Self::new(CommitErrorCode::AuthorizationDenied, message)
    }

    pub fn apply_plan_rejected(apply_plan: ApplyPlan) -> Self {
        Self {
            code: CommitErrorCode::ApplyPlanRejected,
            message: "candidate config apply plan was rejected".to_string(),
            apply_plan: Some(Box::new(apply_plan)),
        }
    }
}

/// Generic config-model error surfaced by generated config implementations.
///
/// The `kind` field is intentionally free-form so generated or hand-written
/// config models can expose implementation-specific categories without waiting
/// for an upstream enum expansion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[error("{kind}: {message}")]
pub struct ConfigError {
    kind: String,
    message: String,
}

impl ConfigError {
    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
        }
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Validation stage for RFC 001 syntax vs. semantic checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidationStage {
    Syntax,
    Semantics,
}

impl fmt::Display for ValidationStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax => f.write_str("syntax"),
            Self::Semantics => f.write_str("semantics"),
        }
    }
}

/// Validation error reported by generated or domain-specific config logic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[error("{stage} validation failed: {message}")]
pub struct ValidationError {
    pub stage: ValidationStage,
    pub message: String,
}

impl ValidationError {
    pub fn syntax(message: impl Into<String>) -> Self {
        Self {
            stage: ValidationStage::Syntax,
            message: message.into(),
        }
    }

    pub fn semantics(message: impl Into<String>) -> Self {
        Self {
            stage: ValidationStage::Semantics,
            message: message.into(),
        }
    }
}

/// Context presented to semantic validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationContext<C: OpcConfig = ()> {
    pub request_id: RequestId,
    pub principal: TrustedPrincipal,
    pub transport: TransportType,
    pub source: RequestSource,
    pub operation: ConfigOperation,
    pub mode: CommitMode,
    pub base_version: ConfigVersion,
    /// The running config at commit time.  Used by `validate_semantics` to
    /// detect secret-field removals in full-replace operations where the
    /// candidate carries no delta metadata (`applied_deltas = None`).
    ///
    /// `None` for startup recovery (where no previous config exists) and for
    /// `validate_startup_config`.
    pub previous: Option<Arc<C>>,
}

/// RFC 001 §4.2 generated root-config contract.
pub trait OpcConfig: Clone + Send + Sync + 'static {
    type Delta: Send + Sync + core::fmt::Debug + 'static;

    fn schema_digest(&self) -> SchemaDigest;
    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError>;
    /// Return canonical YANG paths for the diff produced by [`Self::diff`].
    ///
    /// ConfigBus authorization, audit, publication, and idempotency checks use
    /// these implementation-derived paths instead of caller-supplied request
    /// paths. Implementations must return every path whose mutation is
    /// represented by `deltas`, in a deterministic order.
    fn changed_paths(
        &self,
        previous: &Self,
        deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError>;
    /// Return the serialized candidate payload size used by config-bus
    /// admission limits.
    ///
    /// The default reports that no serialized size is available. A config bus
    /// with a max serialized payload configured fails closed for such configs;
    /// generated configs should override this with their canonical JSON size.
    fn admission_payload_size_bytes(&self) -> Result<Option<usize>, ConfigError> {
        Ok(None)
    }
    fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError>;
    fn validate_syntax(&self) -> Result<(), ValidationError>;
    fn validate_semantics(&self, ctx: &ValidationContext<Self>) -> Result<(), ValidationError>;
}

/// Bootstrap `OpcConfig` for `()` so that the default type parameter on
/// `ValidationContext` (`= ()`) satisfies the trait bound without forcing
/// every call-site that uses an explicit type to also specify `previous`.
impl OpcConfig for () {
    type Delta = ();
    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_bytes([0u8; 32])
    }
    fn diff(&self, _previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        Ok(vec![])
    }
    fn changed_paths(
        &self,
        _previous: &Self,
        _deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        Ok(vec![])
    }
    fn apply_delta(&mut self, _delta: Self::Delta) -> Result<(), ConfigError> {
        Ok(())
    }
    fn validate_syntax(&self) -> Result<(), ValidationError> {
        Ok(())
    }
    fn validate_semantics(&self, _ctx: &ValidationContext<Self>) -> Result<(), ValidationError> {
        Ok(())
    }
}

/// Commit request submitted to the config bus worker.
#[derive(Clone)]
pub struct CommitRequest<C: OpcConfig> {
    pub request_id: RequestId,
    pub principal: TrustedPrincipal,
    pub transport: TransportType,
    pub source: RequestSource,
    pub operation: ConfigOperation,
    pub mode: CommitMode,
    pub deadline: Instant,
    pub idempotency_key: Option<IdempotencyKey>,
    /// Caller-asserted running-config base version.
    ///
    /// Candidate-bearing requests are admitted only when this value matches the
    /// worker's current running version. This compare-and-swap check prevents a
    /// full candidate built from an older snapshot from overwriting intervening
    /// commits.
    pub base_version: ConfigVersion,
    pub candidate: Option<C>,
    /// Caller-supplied changed-path hint.
    ///
    /// ConfigBus implementations must derive authoritative changed paths from
    /// [`OpcConfig::changed_paths`] before authorization, publication, and
    /// idempotency persistence. This field remains useful for request logging and
    /// unsupported modes that cannot derive a candidate diff.
    pub changed_paths: Vec<YangPath>,
}

impl<C: OpcConfig> CommitRequest<C> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: RequestId,
        principal: TrustedPrincipal,
        transport: TransportType,
        source: RequestSource,
        operation: ConfigOperation,
        mode: CommitMode,
        deadline: Instant,
        candidate: Option<C>,
        changed_paths: Vec<YangPath>,
    ) -> Self {
        Self {
            request_id,
            principal,
            transport,
            source,
            operation,
            mode,
            deadline,
            idempotency_key: None,
            base_version: ConfigVersion::INITIAL,
            candidate,
            changed_paths,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit(
        request_id: RequestId,
        principal: TrustedPrincipal,
        transport: TransportType,
        source: RequestSource,
        operation: ConfigOperation,
        candidate: C,
        changed_paths: Vec<YangPath>,
        deadline: Instant,
    ) -> Self {
        Self::new(
            request_id,
            principal,
            transport,
            source,
            operation,
            CommitMode::Commit,
            deadline,
            Some(candidate),
            changed_paths,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn validate_only(
        request_id: RequestId,
        principal: TrustedPrincipal,
        transport: TransportType,
        source: RequestSource,
        operation: ConfigOperation,
        candidate: C,
        changed_paths: Vec<YangPath>,
        deadline: Instant,
    ) -> Self {
        Self::new(
            request_id,
            principal,
            transport,
            source,
            operation,
            CommitMode::ValidateOnly,
            deadline,
            Some(candidate),
            changed_paths,
        )
    }

    pub fn rollback(
        request_id: RequestId,
        principal: TrustedPrincipal,
        transport: TransportType,
        source: RequestSource,
        target: RollbackTarget,
        changed_paths: Vec<YangPath>,
        deadline: Instant,
    ) -> Self {
        Self::new(
            request_id,
            principal,
            transport,
            source,
            ConfigOperation::Rollback,
            CommitMode::Rollback { target },
            deadline,
            None,
            changed_paths,
        )
    }

    pub fn cancel_confirmed(
        request_id: RequestId,
        principal: TrustedPrincipal,
        transport: TransportType,
        source: RequestSource,
        changed_paths: Vec<YangPath>,
        deadline: Instant,
    ) -> Self {
        Self::new(
            request_id,
            principal,
            transport,
            source,
            ConfigOperation::Rollback,
            CommitMode::CancelConfirmed,
            deadline,
            None,
            changed_paths,
        )
    }

    pub fn with_idempotency_key(mut self, idempotency_key: IdempotencyKey) -> Self {
        self.idempotency_key = Some(idempotency_key);
        self
    }

    pub fn with_base_version(mut self, base_version: ConfigVersion) -> Self {
        self.base_version = base_version;
        self
    }
}

/// Commit result returned after validation, persistence, and publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitResult {
    pub tx_id: TxId,
    pub base_version: ConfigVersion,
    pub new_version: Option<ConfigVersion>,
    pub status: CommitStatus,
    pub changed_paths: Vec<YangPath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apply_plan: Option<ApplyPlan>,
}
