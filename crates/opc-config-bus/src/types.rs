use opc_alarm::SharedAlarmManager;
use opc_config_model::{
    ConfigError, ConfigOperation, IdempotencyKey, OpcConfig, RequestId, RequestSource,
    RollbackTarget, TransportType, TrustedPrincipal, ValidationContext, ValidationError, YangPath,
};
use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::watch;

/// Datastore authority mode for the running config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityMode {
    Authoritative,
    Shadow,
}

/// Coarse drift state exposed by the config bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftState {
    InSync,
    RecoveryRequired,
}

/// Persistent store error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreErrorCode {
    NotFound,
    Unavailable,
    Internal,
    Crypto,
    RestoreSchemaMismatch,
    RestoreRecoveryRequired,
    RestoreConfirmedDeadline,
    StartupSyntaxValidationFailed,
    StartupSemanticValidationFailed,
    StartupValidationTaskFailed,
}

impl StoreErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Unavailable => "unavailable",
            Self::Internal => "internal",
            Self::Crypto => "crypto",
            Self::RestoreSchemaMismatch => "restore_schema_mismatch",
            Self::RestoreRecoveryRequired => "restore_recovery_required",
            Self::RestoreConfirmedDeadline => "restore_confirmed_deadline",
            Self::StartupSyntaxValidationFailed => "startup_syntax_validation_failed",
            Self::StartupSemanticValidationFailed => "startup_semantic_validation_failed",
            Self::StartupValidationTaskFailed => "startup_validation_task_failed",
        }
    }
}

impl std::fmt::Display for StoreErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned by the managed datastore abstraction.
#[derive(Debug, Clone, Error)]
#[error("{code}: {message}")]
pub struct StoreError {
    pub code: StoreErrorCode,
    pub message: String,
    pub(crate) alarm_manager: Option<SharedAlarmManager>,
}

impl PartialEq for StoreError {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code && self.message == other.message
    }
}

impl Eq for StoreError {}

impl StoreError {
    pub(crate) fn with_alarm_manager(mut self, alarm_manager: &SharedAlarmManager) -> Self {
        self.alarm_manager = Some(alarm_manager.clone());
        self
    }

    pub fn alarm_manager(&self) -> Option<SharedAlarmManager> {
        self.alarm_manager.clone()
    }

    pub fn new(code: StoreErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            alarm_manager: None,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::NotFound, message)
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::Unavailable, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::Internal, message)
    }

    pub fn crypto(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::Crypto, message)
    }

    pub fn restore_schema_mismatch(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::RestoreSchemaMismatch, message)
    }

    pub fn restore_recovery_required(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::RestoreRecoveryRequired, message)
    }

    pub fn restore_confirmed_deadline(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::RestoreConfirmedDeadline, message)
    }

    pub fn startup_syntax_validation_failed(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::StartupSyntaxValidationFailed, message)
    }

    pub fn startup_semantic_validation_failed(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::StartupSemanticValidationFailed, message)
    }

    pub fn startup_validation_task_failed(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::StartupValidationTaskFailed, message)
    }
}

/// Persisted config record recovered or appended by the managed store.
#[derive(Clone)]
pub struct StoredConfig<C: OpcConfig> {
    pub tx_id: TxId,
    pub parent_tx_id: Option<TxId>,
    pub version: ConfigVersion,
    pub committed_at: Timestamp,
    pub principal: TrustedPrincipal,
    pub source: RequestSource,
    pub schema_digest: SchemaDigest,
    /// SHA-256 digest of the serialized plaintext payload.
    pub plaintext_digest: Option<[u8; 32]>,
    /// Running-config payload for plaintext stores.
    pub config: C,
    pub encrypted_blob: Vec<u8>,
    pub idempotency_key: Option<IdempotencyKey>,
    pub request_fingerprint: Option<StoredRequestFingerprint>,
    /// Original request identifier preserved for audit correlation on restart.
    pub request_id: Option<RequestId>,
    pub recovery_required: bool,
    pub confirmed_deadline: Option<Timestamp>,
    pub rollback_label: Option<String>,
}

/// Persisted request metadata used to safely replay idempotent writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRequestFingerprint {
    pub operation: ConfigOperation,
    pub mode: StoredRequestMode,
    pub transport: TransportType,
    pub changed_paths: Vec<YangPath>,
    #[serde(default)]
    pub base_version: Option<ConfigVersion>,
}

/// Persisted mode for idempotent commit/rollback replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredRequestMode {
    Commit,
    Rollback { target: RollbackTarget },
}

impl<C: OpcConfig> StoredConfig<C> {
    pub fn new(
        tx_id: TxId,
        version: ConfigVersion,
        principal: TrustedPrincipal,
        source: RequestSource,
        config: C,
    ) -> Self {
        let schema_digest = config.schema_digest();
        Self {
            tx_id,
            parent_tx_id: None,
            version,
            committed_at: Timestamp::now_utc(),
            principal,
            source,
            schema_digest,
            plaintext_digest: None,
            config,
            encrypted_blob: Vec::new(),
            idempotency_key: None,
            request_fingerprint: None,
            request_id: None,
            recovery_required: false,
            confirmed_deadline: None,
            rollback_label: None,
        }
    }

    /// Rewraps this record around a different config payload while preserving
    /// all commit metadata, including `schema_digest` and `encrypted_blob`.
    pub fn with_config<D: OpcConfig>(self, config: D) -> StoredConfig<D> {
        StoredConfig {
            tx_id: self.tx_id,
            parent_tx_id: self.parent_tx_id,
            version: self.version,
            committed_at: self.committed_at,
            principal: self.principal,
            source: self.source,
            schema_digest: self.schema_digest,
            plaintext_digest: self.plaintext_digest,
            config,
            encrypted_blob: self.encrypted_blob,
            idempotency_key: self.idempotency_key,
            request_fingerprint: self.request_fingerprint,
            request_id: self.request_id,
            recovery_required: self.recovery_required,
            confirmed_deadline: self.confirmed_deadline,
            rollback_label: self.rollback_label,
        }
    }
}

/// Metadata-only config marker stored behind encrypted config-bus envelopes.
#[derive(Clone)]
pub struct SealedConfig<C: OpcConfig> {
    schema_digest: SchemaDigest,
    legacy_plaintext: Option<C>,
    marker: PhantomData<fn() -> C>,
}

impl<C: OpcConfig> SealedConfig<C> {
    pub fn new(schema_digest: SchemaDigest) -> Self {
        Self {
            schema_digest,
            legacy_plaintext: None,
            marker: PhantomData,
        }
    }

    pub fn legacy_plaintext(config: C) -> Self {
        Self {
            schema_digest: config.schema_digest(),
            legacy_plaintext: Some(config),
            marker: PhantomData,
        }
    }

    pub fn schema_digest(&self) -> SchemaDigest {
        self.schema_digest
    }

    pub fn legacy_plaintext_config(&self) -> Option<&C> {
        self.legacy_plaintext.as_ref()
    }
}

impl<C: OpcConfig> OpcConfig for SealedConfig<C> {
    type Delta = ();

    fn schema_digest(&self) -> SchemaDigest {
        self.schema_digest
    }

    fn diff(&self, _previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        Ok(Vec::new())
    }

    fn changed_paths(
        &self,
        _previous: &Self,
        _deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        Ok(Vec::new())
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

#[derive(Clone)]
pub struct PublishedSnapshot<C: OpcConfig> {
    pub tx_id: Option<TxId>,
    pub version: ConfigVersion,
    pub config: Arc<C>,
}

/// Immutable running-config accessor used by the data plane.
pub trait ConfigSnapshot<C>: Send + Sync {
    fn load(&self) -> Arc<C>;
    fn version(&self) -> ConfigVersion;
}

/// Watch-backed immutable config snapshot.
pub struct AtomicConfigSnapshot<C: OpcConfig> {
    inner: watch::Sender<PublishedSnapshot<C>>,
}

impl<C: OpcConfig> AtomicConfigSnapshot<C> {
    pub fn new(initial: C) -> Self {
        Self::with_state(initial, ConfigVersion::INITIAL, None)
    }

    pub fn with_version(initial: C, version: ConfigVersion) -> Self {
        Self::with_state(initial, version, None)
    }

    pub fn with_state(initial: C, version: ConfigVersion, tx_id: Option<TxId>) -> Self {
        let (inner, _) = watch::channel(PublishedSnapshot {
            tx_id,
            version,
            config: Arc::new(initial),
        });
        Self { inner }
    }

    pub fn current_snapshot(&self) -> PublishedSnapshot<C> {
        self.inner.borrow().clone()
    }

    pub(crate) fn publish(&self, tx_id: Option<TxId>, version: ConfigVersion, config: Arc<C>) {
        self.inner.send_replace(PublishedSnapshot {
            tx_id,
            version,
            config,
        });
    }
}

impl<C: OpcConfig> ConfigSnapshot<C> for AtomicConfigSnapshot<C> {
    fn load(&self) -> Arc<C> {
        Arc::clone(&self.inner.borrow().config)
    }

    fn version(&self) -> ConfigVersion {
        self.inner.borrow().version
    }
}

/// Published change record delivered to subscribers after snapshot swap.
pub struct ConfigChange<C: OpcConfig> {
    pub tx_id: TxId,
    pub version: ConfigVersion,
    pub previous: Arc<C>,
    pub current: Arc<C>,
    pub deltas: Arc<[C::Delta]>,
    pub changed_paths: Arc<[YangPath]>,
}

impl<C: OpcConfig> Clone for ConfigChange<C> {
    fn clone(&self) -> Self {
        Self {
            tx_id: self.tx_id,
            version: self.version,
            previous: Arc::clone(&self.previous),
            current: Arc::clone(&self.current),
            deltas: Arc::clone(&self.deltas),
            changed_paths: Arc::clone(&self.changed_paths),
        }
    }
}

/// Subscriber notifications emitted by the config bus.
#[derive(Clone)]
pub enum ConfigEvent<C: OpcConfig> {
    Change(ConfigChange<C>),
    ResyncRequired { latest_version: ConfigVersion },
}

impl<C: OpcConfig> ConfigEvent<C> {
    pub(crate) fn version(&self) -> ConfigVersion {
        match self {
            Self::Change(change) => change.version,
            Self::ResyncRequired { latest_version } => *latest_version,
        }
    }
}
