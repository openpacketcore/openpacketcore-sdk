//! Shared config-bus types: store errors, persisted commit records, sealed
//! (encrypted) payload markers, atomically published snapshots, and the
//! change/resync events delivered to subscribers.

use opc_alarm::SharedAlarmManager;
use opc_config_model::{
    ApplyPlan, ConfigError, ConfigOperation, IdempotencyKey, OpcConfig, RequestId, RequestSource,
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
    /// This bus is the writer of record: commits are admitted, sequenced,
    /// persisted, and published locally. All built-in constructors create
    /// authoritative buses.
    Authoritative,
    /// Reserved for buses that mirror a running config owned by an external
    /// authority (for example a replication follower); local reads are served
    /// from the snapshot but the local worker is not the source of truth.
    Shadow,
}

impl AuthorityMode {
    /// Returns whether management reads and writes require an external
    /// writer-of-record authority proof.
    ///
    /// Shadow projections must fail closed when no authority port is installed;
    /// an authoritative single-writer bus preserves its local behavior.
    pub const fn requires_external_authority(self) -> bool {
        matches!(self, Self::Shadow)
    }
}

/// Coarse drift state exposed by the config bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriftState {
    /// The published snapshot and the durable store agree; new commits are
    /// admitted normally.
    InSync,
    /// The recovery fence is raised (partial durable side effect, worker
    /// panic, or expired commit-confirmed rollback failure); every new write
    /// is rejected with `RecoveryRequired` until the bus is rebuilt from the
    /// store. Reads keep serving the last published snapshot.
    RecoveryRequired,
}

/// Persistent store error code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreErrorCode {
    /// The requested record (rollback target, transaction, or idempotency
    /// key) does not exist; rollback commits map this to `RollbackNotFound`.
    NotFound,
    /// The backend is temporarily unable to serve the request (for example a
    /// rollback target that is still pending confirmation); retryable.
    Unavailable,
    /// The backend may have durably applied a write but lost the authoritative
    /// acknowledgement. The caller must resolve the result by reading with
    /// the request id or idempotency key before retrying.
    OutcomeUnknown,
    /// Store invariant violation or serialization failure (duplicate tx id or
    /// version, envelope encode failure); not retryable without intervention.
    Internal,
    /// AEAD encryption/decryption or plaintext-digest verification failed;
    /// the record is treated as tampered and the operation fails closed.
    Crypto,
    /// The stored schema digest does not match the digest recomputed from the
    /// decoded payload; the record is refused for publication.
    RestoreSchemaMismatch,
    /// The latest record still carries its `recovery_required` marker,
    /// meaning a previous process crashed between durable append and snapshot
    /// publication; startup fails closed until reconciled.
    RestoreRecoveryRequired,
    /// The latest record has an unresolved commit-confirmed deadline that
    /// could not be rolled back automatically; startup fails closed.
    RestoreConfirmedDeadline,
    /// The restored (or initial) config failed YANG syntax validation during
    /// startup; the bus refuses to publish it.
    StartupSyntaxValidationFailed,
    /// The restored (or initial) config failed NF semantic validation during
    /// startup; the bus refuses to publish it.
    StartupSemanticValidationFailed,
    /// The blocking startup validation task panicked; treated as a process
    /// bug and the bus fails closed rather than publishing unvalidated config.
    StartupValidationTaskFailed,
}

impl StoreErrorCode {
    /// Returns the stable snake_case code used in logs, metrics, and alarm
    /// details. These strings are part of the observability contract and
    /// never contain config payload or secret material.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::Unavailable => "unavailable",
            Self::OutcomeUnknown => "outcome_unknown",
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
    /// Machine-readable failure class; stable across releases so callers and
    /// alert rules can match on it instead of parsing `message`.
    pub code: StoreErrorCode,
    /// Human-oriented detail. It is passed through redaction before logging
    /// and must never carry raw config payload or key material.
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

    /// Returns the alarm manager that recorded this failure when the error
    /// was raised through the startup path, so callers can inspect or clear
    /// the startup-failure alarm after the constructor has already returned.
    /// `None` for errors that never raised an alarm.
    pub fn alarm_manager(&self) -> Option<SharedAlarmManager> {
        self.alarm_manager.clone()
    }

    /// Builds an error with an explicit code and no attached alarm manager;
    /// prefer the named constructors so code and message stay consistent.
    pub fn new(code: StoreErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            alarm_manager: None,
        }
    }

    /// Builds a `NotFound` error: the requested record is absent. Rollback
    /// resolution converts this into `RollbackNotFound` for the caller.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::NotFound, message)
    }

    /// Builds an `Unavailable` error: the backend cannot serve the request
    /// right now (retryable), for example rolling back to a still-pending
    /// commit-confirmed record.
    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::Unavailable, message)
    }

    /// Builds an `OutcomeUnknown` error for an append whose durable result
    /// cannot be proven from the acknowledgement path.
    pub fn outcome_unknown(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::OutcomeUnknown, message)
    }

    /// Builds an `Internal` error: a store invariant was violated (duplicate
    /// tx id/version, serialization failure); not retryable as-is.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::Internal, message)
    }

    /// Builds a `Crypto` error: AEAD encrypt/decrypt, AAD construction, or
    /// plaintext-digest verification failed; the operation fails closed.
    pub fn crypto(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::Crypto, message)
    }

    /// Builds a `RestoreSchemaMismatch` error: the stored schema digest does
    /// not match the decoded payload, so the record is refused for publication.
    pub fn restore_schema_mismatch(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::RestoreSchemaMismatch, message)
    }

    /// Builds a `RestoreRecoveryRequired` error: the record still carries its
    /// recovery marker from a crash between durable append and publication.
    pub fn restore_recovery_required(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::RestoreRecoveryRequired, message)
    }

    /// Builds a `RestoreConfirmedDeadline` error: the record has an
    /// unresolved commit-confirmed deadline that automatic rollback could not
    /// clear, so startup fails closed.
    pub fn restore_confirmed_deadline(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::RestoreConfirmedDeadline, message)
    }

    /// Builds a `StartupSyntaxValidationFailed` error: the restored or
    /// initial config failed YANG syntax validation and will not be published.
    pub fn startup_syntax_validation_failed(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::StartupSyntaxValidationFailed, message)
    }

    /// Builds a `StartupSemanticValidationFailed` error: the restored or
    /// initial config failed NF semantic validation and will not be published.
    pub fn startup_semantic_validation_failed(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::StartupSemanticValidationFailed, message)
    }

    /// Builds a `StartupValidationTaskFailed` error: the blocking startup
    /// validation task panicked, so the bus fails closed rather than publish
    /// an unvalidated config.
    pub fn startup_validation_task_failed(message: impl Into<String>) -> Self {
        Self::new(StoreErrorCode::StartupValidationTaskFailed, message)
    }
}

/// Persisted config record recovered or appended by the managed store.
#[derive(Clone)]
pub struct StoredConfig<C: OpcConfig> {
    /// Transaction id assigned by the commit worker; the store rejects
    /// appends that reuse an existing id.
    pub tx_id: TxId,
    /// Transaction this commit supersedes; `None` only for the first record.
    /// It is the automatic rollback target when a commit-confirmed deadline
    /// expires, and encrypting stores bind it into the envelope AAD.
    pub parent_tx_id: Option<TxId>,
    /// Monotonic running-config version; the store rejects duplicate versions
    /// so history stays a strict sequence.
    pub version: ConfigVersion,
    /// UTC creation time of the record; bound into the AEAD AAD so the
    /// ciphertext cannot be replayed under a different commit time.
    pub committed_at: Timestamp,
    /// Authenticated principal that authored the commit. Its tenant scopes
    /// the encryption key and AAD, so a record cannot be decrypted or
    /// re-attributed under another tenant or identity.
    pub principal: TrustedPrincipal,
    /// Origin of the request (northbound, startup recovery, internal),
    /// preserved for audit and used to rebuild validation context on restore.
    pub source: RequestSource,
    /// Digest of the config schema at commit time; restore fails closed with
    /// `RestoreSchemaMismatch` if the decoded payload no longer matches.
    pub schema_digest: SchemaDigest,
    /// SHA-256 digest of the serialized plaintext payload.
    pub plaintext_digest: Option<[u8; 32]>,
    /// Running-config payload for plaintext stores.
    pub config: C,
    /// AEAD envelope ciphertext written by encrypting stores; empty for
    /// plaintext stores and for legacy records written before encryption.
    pub encrypted_blob: Vec<u8>,
    /// Caller-supplied retry-deduplication key. A later request with the same
    /// key and matching fingerprint replays this record's result instead of
    /// committing again; a mismatched request is rejected as a collision.
    pub idempotency_key: Option<IdempotencyKey>,
    /// Apply plan admitted for this commit. Stored with request metadata so
    /// idempotent replay can return the same northbound contract.
    pub apply_plan: Option<ApplyPlan>,
    /// Shape of the original request, persisted so idempotent retries can be
    /// matched and replayed safely even across process restarts.
    pub request_fingerprint: Option<StoredRequestFingerprint>,
    /// Original request identifier preserved for audit correlation on restart.
    pub request_id: Option<RequestId>,
    /// Commit-fencing marker: set before durable append and cleared only
    /// after snapshot publication. If it survives a restart, the bus refuses
    /// to republish this record until recovery reconciles it.
    pub recovery_required: bool,
    /// Expiry of a pending commit-confirmed commit. Persisted so the rollback
    /// timer survives restarts; if the deadline passes unconfirmed the bus
    /// rolls back to `parent_tx_id` automatically.
    pub confirmed_deadline: Option<Timestamp>,
    /// Operator-assigned name marking this record as a rollback point that
    /// can later be addressed with `RollbackTarget::Label`.
    pub rollback_label: Option<String>,
}

/// Durable resolution applied atomically with a successor config record.
///
/// Both variants carry the exact pending transaction that the write expects
/// to remain current. A datastore must compare that id with its applied latest
/// record before changing state, so confirm and rollback cannot both win after
/// a leader change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmedCommitResolution {
    /// Permanently confirms the pending commit and clears its deadline.
    Confirm {
        /// Exact pending transaction that must still be current.
        pending_tx_id: TxId,
    },
    /// Supersedes the pending commit with the rollback record in the same
    /// atomic datastore operation.
    Rollback {
        /// Exact pending transaction that must still be current.
        pending_tx_id: TxId,
    },
}

impl ConfirmedCommitResolution {
    /// Returns the pending transaction guarded by this resolution.
    pub const fn pending_tx_id(self) -> TxId {
        match self {
            Self::Confirm { pending_tx_id } | Self::Rollback { pending_tx_id } => pending_tx_id,
        }
    }
}

/// One atomic durable config write with an applied-state compare condition.
///
/// The record's `parent_tx_id` is the expected current durable transaction.
/// Datastores must compare it at apply time, then append the record and apply
/// any [`ConfirmedCommitResolution`] as one indivisible state-machine update.
/// This prevents two leaders from committing sibling versions or deciding a
/// pending commit in opposite ways.
#[derive(Clone)]
pub struct CommitWrite<C: OpcConfig> {
    record: StoredConfig<C>,
    confirmed_resolution: Option<ConfirmedCommitResolution>,
}

/// Metadata attested by a datastore after one commit write succeeds.
///
/// The receipt contains no config payload, principal, or key material. The
/// plaintext digest is optional for source compatibility with custom stores
/// that predate receipt support; encrypted built-in stores always return it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CommitWriteReceipt {
    plaintext_digest: Option<[u8; 32]>,
}

impl CommitWriteReceipt {
    /// Builds a receipt from the digest stored with the committed record.
    pub const fn new(plaintext_digest: Option<[u8; 32]>) -> Self {
        Self { plaintext_digest }
    }

    /// Returns the exact SHA-256 plaintext-envelope digest stored for the
    /// commit. This is not necessarily a config-only content hash.
    pub const fn plaintext_digest(self) -> Option<[u8; 32]> {
        self.plaintext_digest
    }
}

impl<C: OpcConfig> CommitWrite<C> {
    /// Builds an ordinary compare-and-append write. The record's
    /// `parent_tx_id` is used as the expected current transaction.
    pub fn new(record: StoredConfig<C>) -> Self {
        Self {
            record,
            confirmed_resolution: None,
        }
    }

    /// Builds a write that atomically confirms or rolls back the exact current
    /// pending transaction.
    pub fn resolving(
        record: StoredConfig<C>,
        resolution: ConfirmedCommitResolution,
    ) -> Result<Self, StoreError> {
        if record.parent_tx_id != Some(resolution.pending_tx_id()) {
            return Err(StoreError::internal(
                "confirmed resolution does not match the commit parent",
            ));
        }
        if record.confirmed_deadline.is_some() {
            return Err(StoreError::internal(
                "confirmed resolution successor cannot itself be pending",
            ));
        }
        Ok(Self {
            record,
            confirmed_resolution: Some(resolution),
        })
    }

    /// Returns the config record to append.
    pub fn record(&self) -> &StoredConfig<C> {
        &self.record
    }

    /// Returns the applied latest transaction required before this write can
    /// commit. `None` requires an empty datastore.
    pub fn expected_current_tx_id(&self) -> Option<TxId> {
        self.record.parent_tx_id
    }

    /// Returns the optional pending commit decision carried by this write.
    pub fn confirmed_resolution(&self) -> Option<ConfirmedCommitResolution> {
        self.confirmed_resolution
    }

    /// Splits the write into the persisted record and its atomic resolution
    /// metadata for datastore adapters.
    pub fn into_parts(self) -> (StoredConfig<C>, Option<ConfirmedCommitResolution>) {
        (self.record, self.confirmed_resolution)
    }
}

impl<C: OpcConfig> std::fmt::Debug for CommitWrite<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitWrite")
            .field("tx_id", &self.record.tx_id)
            .field("version", &self.record.version)
            .field("expected_current_tx_id", &self.record.parent_tx_id)
            .field("confirmed_resolution", &self.confirmed_resolution)
            .finish_non_exhaustive()
    }
}

/// Persisted request metadata used to safely replay idempotent writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRequestFingerprint {
    /// Operation the original caller requested; a retry with a different
    /// operation is treated as an idempotency-key collision, not a replay.
    pub operation: ConfigOperation,
    /// Persisted mode of the durable request. Validate-only requests do not
    /// create records and therefore are never fingerprinted.
    pub mode: StoredRequestMode,
    /// Northbound transport of the original request; replays must arrive over
    /// the same transport to match.
    pub transport: TransportType,
    /// Paths reported by the original commit; returned verbatim on replay and
    /// re-authorized against the retrying principal before replaying.
    pub changed_paths: Vec<YangPath>,
    /// Running version the original commit was applied on. `None` for records
    /// persisted before this field existed; replay then derives it as
    /// `version - 1`.
    #[serde(default)]
    pub base_version: Option<ConfigVersion>,
}

/// Persisted mode for authoritative request reconciliation and idempotent
/// replay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StoredRequestMode {
    /// The record was produced by an ordinary (unconfirmed) commit; replay
    /// additionally requires the retried candidate to diff clean against the
    /// stored config in both directions.
    Commit,
    /// The record was produced by a rollback commit; replay requires the
    /// retried request to name the identical target.
    Rollback {
        /// Rollback selector (previous/version/tx-id/label) from the original
        /// request, compared exactly on idempotent replay.
        target: RollbackTarget,
    },
    /// The record started a commit-confirmed window. The original timeout is
    /// retained so a retry with the same key but different semantics is
    /// rejected as a collision. Kept after the original variants so binary
    /// serde discriminants remain compatible with pre-extension records.
    CommitConfirmed {
        /// Requested confirmation window.
        timeout: std::time::Duration,
    },
    /// The record cancelled the then-current pending commit and restored its
    /// parent configuration. Kept after the original variants for binary
    /// serde compatibility.
    CancelConfirmed,
    /// An ordinary `Commit` request with no candidate that explicitly
    /// confirmed the then-current pending commit. Kept distinct from a
    /// candidate-bearing commit so an idempotency key cannot be replayed with
    /// different semantics.
    ConfirmPending,
}

impl<C: OpcConfig> StoredConfig<C> {
    /// Builds a baseline record stamped with the current UTC time and the
    /// schema digest computed from `config`. Lineage and lifecycle fields
    /// start empty: no parent, no idempotency/fingerprint metadata,
    /// `recovery_required = false`, and no confirmed deadline; callers set
    /// those before appending.
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
            apply_plan: None,
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
            apply_plan: self.apply_plan,
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
    fresh_envelope: Option<opc_crypto::AuthenticatedEnvelope>,
    aad_principal: Option<Arc<str>>,
    marker: PhantomData<fn() -> C>,
}

impl<C: OpcConfig> SealedConfig<C> {
    /// Builds a sealed marker for a record whose payload exists only as AEAD
    /// ciphertext in `encrypted_blob`; the plaintext config is never held by
    /// the inner store.
    pub fn new(schema_digest: SchemaDigest) -> Self {
        Self {
            schema_digest,
            legacy_plaintext: None,
            fresh_envelope: None,
            aad_principal: None,
            marker: PhantomData,
        }
    }

    /// Builds a persisted sealed marker while retaining the exact principal
    /// JSON bytes that were bound into the envelope AAD.
    ///
    /// Persistence adapters must use this constructor instead of reserializing
    /// the decoded principal: JSON member ordering is semantically irrelevant
    /// but the authenticated AAD bytes are exact.
    pub fn from_persisted_aad_principal(
        schema_digest: SchemaDigest,
        aad_principal: String,
    ) -> Result<Self, StoreError> {
        serde_json::from_str::<TrustedPrincipal>(&aad_principal)
            .map_err(|_| StoreError::crypto("stored config AAD principal is invalid"))?;
        Ok(Self {
            schema_digest,
            legacy_plaintext: None,
            fresh_envelope: None,
            aad_principal: Some(Arc::<str>::from(aad_principal)),
            marker: PhantomData,
        })
    }

    pub(crate) fn newly_encrypted(
        schema_digest: SchemaDigest,
        envelope: opc_crypto::AuthenticatedEnvelope,
    ) -> Self {
        Self {
            schema_digest,
            legacy_plaintext: None,
            fresh_envelope: Some(envelope),
            aad_principal: None,
            marker: PhantomData,
        }
    }

    pub(crate) fn aad_principal(&self) -> Option<&str> {
        self.aad_principal.as_deref()
    }

    /// Consume evidence that this exact record was produced by the live
    /// encrypting adapter. Persisted markers created by [`Self::new`] and
    /// legacy plaintext markers cannot mint this capability.
    pub fn claim_fresh_envelope(
        &self,
    ) -> Result<opc_crypto::AuthenticatedEnvelopeClaim, StoreError> {
        self.fresh_envelope
            .as_ref()
            .ok_or_else(|| StoreError::crypto("config envelope lacks fresh encryption evidence"))?
            .claim()
            .map_err(|_| StoreError::crypto("config envelope evidence was already consumed"))
    }

    /// Wraps an unencrypted payload from a record written before envelope
    /// encryption was enabled, so old history stays readable. Decryption
    /// falls back to this payload only when the ciphertext blob is empty.
    pub fn legacy_plaintext(config: C) -> Self {
        Self {
            schema_digest: config.schema_digest(),
            legacy_plaintext: Some(config),
            fresh_envelope: None,
            aad_principal: None,
            marker: PhantomData,
        }
    }

    /// Returns the schema digest captured from the sealed payload; restore
    /// compares it against the digest recomputed after decryption and fails
    /// closed on mismatch.
    pub fn schema_digest(&self) -> SchemaDigest {
        self.schema_digest
    }

    /// Returns the unencrypted payload for legacy records; `None` for records
    /// sealed behind an AEAD envelope.
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

/// Consistent `(tx_id, version, config)` triple read from the publication
/// slot in one borrow, so the three fields can never mix two commits.
#[derive(Clone)]
pub struct PublishedSnapshot<C: OpcConfig> {
    /// Transaction that produced this snapshot; `None` while the bus is still
    /// serving the bootstrap config (no commit or restore has published yet).
    pub tx_id: Option<TxId>,
    /// Running-config version of the snapshot; starts at
    /// `ConfigVersion::INITIAL` for a bootstrap config.
    pub version: ConfigVersion,
    /// Shared immutable payload; cloning the `Arc` is the only cost of
    /// handing it to data-plane readers.
    pub config: Arc<C>,
}

/// Immutable running-config accessor used by the data plane.
pub trait ConfigSnapshot<C>: Send + Sync {
    /// Returns the currently published config. Implementations must not take
    /// the commit lock, await I/O, or run validation, so the call stays safe
    /// on data-plane threads regardless of commit-queue or store health.
    fn load(&self) -> Arc<C>;
    /// Returns the version of the currently published snapshot; comparing it
    /// against a subscriber's last applied version detects missed changes.
    fn version(&self) -> ConfigVersion;
}

/// Watch-backed immutable config snapshot.
pub struct AtomicConfigSnapshot<C: OpcConfig> {
    inner: watch::Sender<PublishedSnapshot<C>>,
}

impl<C: OpcConfig> AtomicConfigSnapshot<C> {
    /// Publishes `initial` at `ConfigVersion::INITIAL` with no transaction
    /// id, i.e. a bootstrap config that no commit has produced yet.
    pub fn new(initial: C) -> Self {
        Self::with_state(initial, ConfigVersion::INITIAL, None)
    }

    /// Publishes `initial` at a caller-chosen version (still without a
    /// transaction id), for seeding from out-of-band recovered state.
    pub fn with_version(initial: C, version: ConfigVersion) -> Self {
        Self::with_state(initial, version, None)
    }

    /// Publishes `initial` with full control over version and originating
    /// transaction id; the restore path uses this so the first snapshot
    /// already carries the recovered commit's identity.
    pub fn with_state(initial: C, version: ConfigVersion, tx_id: Option<TxId>) -> Self {
        let (inner, _) = watch::channel(PublishedSnapshot {
            tx_id,
            version,
            config: Arc::new(initial),
        });
        Self { inner }
    }

    /// Clones the published `(tx_id, version, config)` triple under a single
    /// borrow; the result is internally consistent even if a commit publishes
    /// concurrently.
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
    /// Transaction that produced this change; matches the tx id stamped on
    /// the published snapshot and the durable commit record.
    pub tx_id: TxId,
    /// Version the running config moved to. Events arrive in version order
    /// per subscriber unless the lag policy dropped intermediates.
    pub version: ConfigVersion,
    /// Snapshot that was running before this commit; shared, not a copy, so
    /// holding it does not block future publications.
    pub previous: Arc<C>,
    /// Snapshot published by this commit; identical `Arc` to what readers of
    /// the bus snapshot observe.
    pub current: Arc<C>,
    /// Structured deltas computed by diffing the candidate against
    /// `previous`, shared across all subscribers without re-diffing.
    pub deltas: Arc<[C::Delta]>,
    /// Canonical YANG paths touched by this commit; the same set that was
    /// presented to the authorizer before persistence.
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
    /// One published commit, delivered after the snapshot swap. May be
    /// skipped for lagging subscribers depending on their lag policy.
    Change(ConfigChange<C>),
    /// The subscriber's bounded queue overflowed under the `ForceResync`
    /// policy: queued changes were discarded, so the subscriber must reload
    /// state from the current snapshot instead of applying deltas.
    ResyncRequired {
        /// Version of the change that triggered the overflow; state at or
        /// before this version may have been dropped from the queue.
        latest_version: ConfigVersion,
    },
}

impl<C: OpcConfig> ConfigEvent<C> {
    pub(crate) fn version(&self) -> ConfigVersion {
        match self {
            Self::Change(change) => change.version,
            Self::ResyncRequired { latest_version } => *latest_version,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::AuthorityMode;

    #[test]
    fn shadow_mode_requires_external_authority_while_authoritative_does_not() {
        assert!(!AuthorityMode::Authoritative.requires_external_authority());
        assert!(AuthorityMode::Shadow.requires_external_authority());
    }
}
