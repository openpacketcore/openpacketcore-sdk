//! Core types for the persistence layer: records, stored configs, and the ConfigStore trait.

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use opc_data_governance::DataClass;
use opc_redaction::{redact, RedactionLevel};
use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::Sha256;
use std::net::Ipv6Addr;
use std::{fmt, fmt::Debug};
use zeroize::Zeroizing;

use crate::preflight::PersistCapabilities;
use opc_types::{ConfigVersion, SchemaDigest, Timestamp, TxId};

/// Maximum UTF-8 byte length of a durable named rollback point.
pub const CONFIG_ROLLBACK_LABEL_MAX_BYTES: usize = 128;

/// Source of a configuration commit request.
///
/// Mirrors the management substrate's `RequestSource` to avoid a cycle back to
/// opc-config-model in this phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitSource {
    Gnmi,
    Netconf,
    LocalOperator,
    StartupRestore,
    Rollback,
    CommitConfirmedRestore,
}

/// Rollback target selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value")]
pub enum RollbackTarget {
    /// Roll back to the previous confirmed configuration.
    Previous,
    /// Roll back to an explicit transaction ID.
    ByTxId(TxId),
    /// Roll back to an explicit version number.
    ByVersion(ConfigVersion),
    /// Roll back to a labeled rollback point.
    ByLabel(String),
}

/// A durable configuration commit record.
///
/// Stored in the `config_history` table. The `encrypted_blob` contains the
/// AES-256-GCM-SIV (or XChaCha20-Poly1305) encrypted configuration envelope
/// per RFC 001 §9.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommitRecord {
    /// Unique transaction identifier.
    pub tx_id: TxId,
    /// Parent transaction (None for the genesis commit).
    pub parent_tx_id: Option<TxId>,
    /// Monotonic config version.
    pub version: ConfigVersion,
    /// Wall-clock time at commit.
    pub committed_at: Timestamp,
    /// Encoded principal identity (SPIFFE ID + tenant + roles).
    pub principal: String,
    /// How the commit was initiated.
    pub source: CommitSource,
    /// YANG schema digest at commit time.
    pub schema_digest: SchemaDigest,
    /// SHA-256 digest of the plaintext payload (verified after AEAD decryption).
    pub plaintext_digest: Vec<u8>,
    /// AEAD encrypted configuration envelope.
    pub encrypted_blob: Vec<u8>,
    /// Whether this record is an explicit rollback point.
    pub rollback_point: bool,
    /// Deadline for commit-confirmed commits (None otherwise).
    pub confirmed_deadline: Option<Timestamp>,
}

/// Atomic decision applied with a successor configuration commit.
///
/// The referenced transaction must be the current durable head, must still be
/// pending commit-confirmed, and must equal the successor's `parent_tx_id`.
/// Persistence backends compare and apply this decision in the same
/// transaction as the successor append.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfirmedCommitResolution {
    /// Permanently confirm the exact pending parent.
    Confirm {
        /// Pending transaction that must still be the applied head.
        pending_tx_id: TxId,
    },
    /// Supersede the exact pending parent with a rollback successor.
    Rollback {
        /// Pending transaction that must still be the applied head.
        pending_tx_id: TxId,
    },
}

impl ConfirmedCommitResolution {
    /// Return the pending transaction guarded by this decision.
    pub const fn pending_tx_id(self) -> TxId {
        match self {
            Self::Confirm { pending_tx_id } | Self::Rollback { pending_tx_id } => pending_tx_id,
        }
    }
}

/// An individual YANG-path-level audit entry.
///
/// Each entry records the operation performed on a single YANG data node during
/// a commit, and carries an HMAC that chains to the previous entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AuditRecord {
    /// Owning transaction ID.
    pub tx_id: TxId,
    /// Monotonic sequence within the transaction (0-based).
    pub sequence: u32,
    /// Canonical YANG path, e.g. `/ietf-interfaces:interfaces/interface[name='eth0']/config/enabled`.
    pub yang_path: String,
    /// Operation type on this node.
    pub op_type: AuditOpType,
    /// JSON-encoded previous value, if any (redacted per policy).
    pub previous_value: Option<String>,
    /// JSON-encoded new value, if any (redacted per policy).
    pub new_value: Option<String>,
    /// Whether field-level redaction was applied to this entry.
    pub redaction_applied: bool,
    /// Hash of the previous audit entry in the chain (all-zero for first entry).
    pub previous_hash: [u8; 32],
    /// HMAC of this entry using the tenant-scoped audit key.
    pub entry_hmac: [u8; 32],
}

/// Operation type on a YANG data node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditOpType {
    Create,
    Update,
    Replace,
    Delete,
}

/// A stored encrypted configuration blob with its metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredConfig {
    /// Commit record for this configuration.
    pub record: CommitRecord,
    /// Audit trail for this configuration.
    pub audit: Vec<AuditRecord>,
}

/// A config commit bound to one successful outer-adapter AEAD encryption.
///
/// The one-shot encryption claim is consumed by [`Self::try_new`] and is not
/// retained or serialized. Consensus therefore receives only ciphertext and
/// deterministic metadata, while unauthenticated raw bytes cannot enter its
/// proposal API.
pub struct AttestedConfigCommit {
    record: CommitRecord,
    audit: Vec<AuditRecord>,
    confirmed_resolution: Option<ConfirmedCommitResolution>,
}

impl AttestedConfigCommit {
    pub fn try_new(
        record: CommitRecord,
        audit: Vec<AuditRecord>,
        claim: opc_crypto::AuthenticatedEnvelopeClaim,
    ) -> Result<Self, PersistError> {
        if !claim.matches(&record.encrypted_blob)
            || !claim.matches_plaintext_digest(&record.plaintext_digest)
        {
            return Err(PersistError::corrupt_blob());
        }
        Ok(Self {
            record,
            audit,
            confirmed_resolution: None,
        })
    }

    /// Bind a fresh authenticated envelope to an atomic commit-confirmed
    /// decision. The successor must name the guarded pending transaction as
    /// its parent and cannot itself be pending.
    pub fn try_new_resolving(
        record: CommitRecord,
        audit: Vec<AuditRecord>,
        claim: opc_crypto::AuthenticatedEnvelopeClaim,
        resolution: ConfirmedCommitResolution,
    ) -> Result<Self, PersistError> {
        if record.parent_tx_id != Some(resolution.pending_tx_id())
            || record.confirmed_deadline.is_some()
        {
            return Err(PersistError::constraint_violation(
                "confirmed resolution does not match a non-pending successor",
            ));
        }
        if !claim.matches(&record.encrypted_blob)
            || !claim.matches_plaintext_digest(&record.plaintext_digest)
        {
            return Err(PersistError::corrupt_blob());
        }
        Ok(Self {
            record,
            audit,
            confirmed_resolution: Some(resolution),
        })
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        CommitRecord,
        Vec<AuditRecord>,
        Option<ConfirmedCommitResolution>,
    ) {
        (self.record, self.audit, self.confirmed_resolution)
    }

    pub fn record(&self) -> &CommitRecord {
        &self.record
    }

    /// Return the optional atomic decision carried by this commit.
    pub const fn confirmed_resolution(&self) -> Option<ConfirmedCommitResolution> {
        self.confirmed_resolution
    }
}

impl fmt::Debug for AttestedConfigCommit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AttestedConfigCommit")
            .field("tx_id", &self.record.tx_id)
            .field("version", &self.record.version)
            .field("confirmed_resolution", &self.confirmed_resolution)
            .field("encrypted_blob", &"<redacted>")
            .field("audit_records", &self.audit.len())
            .finish()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ConfigStore trait
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum number of config-history records returned by one persistence page.
pub const CONFIG_HISTORY_PAGE_MAX_ENTRIES: usize = 64;

/// Core persistence trait for the management substrate.
///
/// Implementors must guarantee that [`append_commit`](ConfigStore::append_commit)
/// is fully atomic: either the commit record and all its audit records are
/// durable together, or neither is visible after recovery.
///
/// The trait is object-safe (`dyn ConfigStore`) and is mockable for tests via
/// [`MockConfigStore`](super::MockConfigStore).
#[async_trait]
pub trait ConfigStore: Send + Sync {
    /// Load the most recent configuration, including a pending commit-confirmed
    /// row when it is the newest durable record.
    async fn load_latest(&self) -> Result<Option<StoredConfig>, PersistError>;

    /// Load the most recent publication-safe record visible in this node's
    /// local committed state-machine view.
    ///
    /// Standalone stores use the same durable head as `load_latest`.
    /// Consensus stores override this method to avoid a leader/read-index
    /// round while still returning only locally applied state through the
    /// first uncleared `recovery_required` publication fence.
    async fn load_committed_latest(&self) -> Result<Option<StoredConfig>, PersistError> {
        self.load_latest()
            .await?
            .map(|record| {
                config_recovery_required(&record.record.principal)
                    .map(|fenced| (!fenced).then_some(record))
            })
            .transpose()
            .map(Option::flatten)
    }

    /// Load at most `limit` durable publication-safe config records strictly
    /// after `version`, ordered by ascending `ConfigVersion`.
    ///
    /// Implementations supporting follower-served config watches must return
    /// only the contiguous locally committed/applied, recovery-cleared prefix
    /// and must never start after the exact successor or skip a fenced row.
    /// The default fails closed for legacy adapters.
    async fn load_since(
        &self,
        _version: ConfigVersion,
        _limit: usize,
    ) -> Result<Vec<StoredConfig>, PersistError> {
        Err(PersistError::constraint_violation(
            "ordered committed config history is unsupported",
        ))
    }

    /// Wait until this local store may have applied a revision newer than
    /// `version`.
    ///
    /// The notification is a wake hint only; consumers must repage and enforce
    /// the durable cursor. Consensus stores override this with a
    /// register-before-head apply notification. Legacy stores use a bounded
    /// fallback interval.
    async fn wait_for_committed_change(&self, _version: ConfigVersion) -> Result<(), PersistError> {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        Ok(())
    }

    /// Load a specific rollback target.
    async fn load_rollback(&self, target: RollbackTarget) -> Result<StoredConfig, PersistError>;

    /// Load the unique config record carrying one domain-separated replay
    /// lookup digest.
    ///
    /// Production stores override this with one authoritative indexed read.
    /// The default fails closed so external stores continue to compile but do
    /// not turn a long history walk into an availability cliff.
    async fn load_by_replay_lookup_digest(
        &self,
        _digest: &str,
    ) -> Result<Option<StoredConfig>, PersistError> {
        Err(PersistError::constraint_violation(
            "indexed config replay lookup is unsupported",
        ))
    }

    /// Append a new commit record and its audit trail atomically.
    ///
    /// This method MUST be atomic: on recovery, either both `record` and all
    /// `audit` entries are visible, or neither is.
    async fn append_commit(
        &self,
        record: CommitRecord,
        audit: Vec<AuditRecord>,
    ) -> Result<(), PersistError>;

    /// Atomically compare the current head, append the successor, and resolve
    /// its exact pending commit-confirmed parent. The default rejects the
    /// operation so legacy adapters fail closed instead of splitting it into
    /// two writes; production backends in this SDK override it.
    async fn append_commit_resolving(
        &self,
        _record: CommitRecord,
        _audit: Vec<AuditRecord>,
        _resolution: ConfirmedCommitResolution,
    ) -> Result<(), PersistError> {
        Err(PersistError::constraint_violation(
            "atomic confirmed-commit resolution is unsupported",
        ))
    }

    /// Append a commit carrying one-shot evidence from the real encryption
    /// adapter. Ordinary SQLite/mock stores delegate to their existing typed
    /// append; consensus stores override this and reject the raw method.
    async fn append_attested_commit(
        &self,
        commit: AttestedConfigCommit,
    ) -> Result<(), PersistError> {
        let (record, audit, resolution) = commit.into_parts();
        match resolution {
            Some(resolution) => {
                self.append_commit_resolving(record, audit, resolution)
                    .await
            }
            None => self.append_commit(record, audit).await,
        }
    }

    /// Durably clear the config-bus recovery marker for one committed
    /// transaction. Production backends apply this as an idempotent lifecycle
    /// mutation; the default fails closed for legacy adapters.
    async fn clear_recovery_required(&self, _tx_id: TxId) -> Result<(), PersistError> {
        Err(PersistError::constraint_violation(
            "durable recovery-marker lifecycle is unsupported",
        ))
    }

    /// Mark a commit-confirmed transaction as confirmed before its deadline.
    async fn mark_confirmed(&self, tx_id: TxId) -> Result<(), PersistError>;

    /// Create a named rollback point at the given transaction.
    async fn create_rollback_point(
        &self,
        tx_id: TxId,
        label: Option<String>,
    ) -> Result<(), PersistError>;

    /// Run preflight checks and return the capabilities of this backend.
    ///
    /// This method MUST NOT fail after the first successful call on a newly
    /// opened database; subsequent calls should return the same result cheaply.
    async fn preflight(&self) -> Result<PersistCapabilities, PersistError>;
}

/// A persisted record of an administrative alarm action audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlarmAuditEventRecord {
    pub action: String,
    pub outcome: String,
    pub alarm_id: String,
    pub alarm_type: String,
    pub probable_cause: String,
    pub principal: String,
    pub tenant: Option<String>,
    pub reason: String,
    pub scope: String,
    pub correlation_id: Option<String>,
    pub occurred_at: String,
}

// Re-export PersistError so callers don't need to know about the error module.
pub use crate::error::PersistError;

/// A purpose-separated key for audit HMAC chaining.
///
/// The key is deliberately opaque and refuses all-zero material so production
/// callers cannot accidentally get forgeable audit chains.
///
/// ```compile_fail
/// use opc_persist::AuditKey;
/// let key = AuditKey::new([7; 32]).expect("audit key");
/// let _raw_material = key.as_bytes();
/// ```
#[derive(Clone)]
pub struct AuditKey {
    epoch: u64,
    material: Zeroizing<[u8; 32]>,
}

const AUDIT_KEY_FINGERPRINT_DOMAIN: &[u8] = b"openpacketcore/config-audit-key/fingerprint/v1\0";

impl AuditKey {
    pub fn new(bytes: [u8; 32]) -> Result<Self, PersistError> {
        Self::new_with_epoch(bytes, 1)
    }

    /// Construct deployment-owned audit material at an explicit rotation
    /// epoch. The epoch is non-secret and participates in config-consensus
    /// durable identity and peer admission.
    pub fn new_with_epoch(bytes: [u8; 32], epoch: u64) -> Result<Self, PersistError> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(PersistError::preflight_failed(
                "audit HMAC key must not be all zero",
            ));
        }
        if epoch == 0 || epoch > i64::MAX as u64 {
            return Err(PersistError::preflight_failed(
                "audit HMAC key epoch is outside the durable range",
            ));
        }
        Ok(Self {
            epoch,
            material: Zeroizing::new(bytes),
        })
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.material
    }

    /// Non-secret deployment rotation epoch used by durable/peer admission.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Purpose-separated, non-secret fingerprint for fleet compatibility
    /// checks. This is an HMAC output and does not reveal the key material.
    pub fn fingerprint(&self) -> [u8; 32] {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(self.as_bytes())
            .expect("HMAC-SHA-256 accepts a 32-byte key");
        mac.update(AUDIT_KEY_FINGERPRINT_DOMAIN);
        mac.update(&self.epoch.to_be_bytes());
        mac.finalize().into_bytes().into()
    }
}

impl fmt::Debug for AuditKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuditKey")
            .field("epoch", &self.epoch)
            .field(
                "fingerprint",
                &"<non-secret-available-via-consensus-status>",
            )
            .field("material", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize)]
struct ConfigPrincipalMetadata {
    principal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    replay_lookup_digest: Option<String>,
    recovery_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    rollback_label: Option<String>,
}

#[derive(Debug, Default)]
struct ConfigPrincipalMetadataProbe {
    is_object: bool,
    saw_reserved_field: bool,
    saw_principal: bool,
    principal: Option<String>,
    saw_replay_lookup_digest: bool,
    replay_lookup_digest: Option<String>,
    saw_recovery_required: bool,
    recovery_required: Option<bool>,
    saw_rollback_label: bool,
    rollback_label: Option<String>,
    duplicate_reserved_field: bool,
    unknown_field: bool,
    invalid_field_type: bool,
}

impl<'de> Deserialize<'de> for ConfigPrincipalMetadataProbe {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProbeVisitor;

        impl<'de> Visitor<'de> for ProbeVisitor {
            type Value = ConfigPrincipalMetadataProbe;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON object")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut probe = ConfigPrincipalMetadataProbe {
                    is_object: true,
                    ..ConfigPrincipalMetadataProbe::default()
                };
                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "principal" => {
                            probe.saw_reserved_field = true;
                            if probe.saw_principal {
                                probe.duplicate_reserved_field = true;
                            }
                            probe.saw_principal = true;
                            let value = map.next_value::<serde_json::Value>()?;
                            match value {
                                serde_json::Value::String(principal) => {
                                    probe.principal = Some(principal);
                                }
                                _ => probe.invalid_field_type = true,
                            }
                        }
                        "replay_lookup_digest" => {
                            probe.saw_reserved_field = true;
                            if probe.saw_replay_lookup_digest {
                                probe.duplicate_reserved_field = true;
                            }
                            probe.saw_replay_lookup_digest = true;
                            let value = map.next_value::<serde_json::Value>()?;
                            match value {
                                serde_json::Value::Null => probe.replay_lookup_digest = None,
                                serde_json::Value::String(digest) => {
                                    probe.replay_lookup_digest = Some(digest);
                                }
                                _ => probe.invalid_field_type = true,
                            }
                        }
                        "recovery_required" => {
                            probe.saw_reserved_field = true;
                            if probe.saw_recovery_required {
                                probe.duplicate_reserved_field = true;
                            }
                            probe.saw_recovery_required = true;
                            let value = map.next_value::<serde_json::Value>()?;
                            match value {
                                serde_json::Value::Bool(required) => {
                                    probe.recovery_required = Some(required);
                                }
                                _ => probe.invalid_field_type = true,
                            }
                        }
                        "rollback_label" => {
                            probe.saw_reserved_field = true;
                            if probe.saw_rollback_label {
                                probe.duplicate_reserved_field = true;
                            }
                            probe.saw_rollback_label = true;
                            let value = map.next_value::<serde_json::Value>()?;
                            match value {
                                serde_json::Value::Null => probe.rollback_label = None,
                                serde_json::Value::String(label) => {
                                    probe.rollback_label = Some(label);
                                }
                                _ => probe.invalid_field_type = true,
                            }
                        }
                        _ => {
                            probe.unknown_field = true;
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(probe)
            }
        }

        deserializer.deserialize_any(ProbeVisitor)
    }
}

enum ParsedConfigPrincipal {
    Legacy,
    Wrapped(ConfigPrincipalMetadata),
    Invalid,
}

fn parse_config_principal(stored: &str) -> ParsedConfigPrincipal {
    let Ok(probe) = serde_json::from_str::<ConfigPrincipalMetadataProbe>(stored) else {
        return ParsedConfigPrincipal::Legacy;
    };
    if !probe.is_object || !probe.saw_reserved_field {
        return ParsedConfigPrincipal::Legacy;
    }
    if probe.duplicate_reserved_field
        || probe.unknown_field
        || probe.invalid_field_type
        || !probe.saw_principal
        || !probe.saw_recovery_required
    {
        return ParsedConfigPrincipal::Invalid;
    }
    let Some(principal) = probe.principal else {
        return ParsedConfigPrincipal::Invalid;
    };
    let Some(recovery_required) = probe.recovery_required else {
        return ParsedConfigPrincipal::Invalid;
    };
    if principal.is_empty()
        || probe
            .replay_lookup_digest
            .as_deref()
            .is_some_and(|digest| validate_replay_lookup_digest(digest).is_err())
        || probe
            .rollback_label
            .as_deref()
            .is_some_and(|label| validate_rollback_label(label).is_err())
    {
        return ParsedConfigPrincipal::Invalid;
    }
    ParsedConfigPrincipal::Wrapped(ConfigPrincipalMetadata {
        principal,
        replay_lookup_digest: probe.replay_lookup_digest,
        recovery_required,
        rollback_label: probe.rollback_label,
    })
}

fn wrapped_config_principal(principal: &str) -> Option<String> {
    match parse_config_principal(principal) {
        ParsedConfigPrincipal::Wrapped(metadata) => Some(metadata.principal),
        ParsedConfigPrincipal::Legacy | ParsedConfigPrincipal::Invalid => None,
    }
}

/// Compare a durable principal field with the principal bound into config
/// envelope AAD. Newer adapters may wrap the authenticated principal with
/// cleartext lookup/lifecycle metadata; legacy rows store the principal
/// directly. The wrapper retains the exact serialized principal string, so
/// the comparison does not depend on JSON object ordering or on a product
/// model type in the persistence crate.
pub(crate) fn config_principal_matches_aad(stored: &str, aad_principal: &str) -> bool {
    match parse_config_principal(stored) {
        ParsedConfigPrincipal::Legacy => stored == aad_principal,
        ParsedConfigPrincipal::Wrapped(metadata) => metadata.principal == aad_principal,
        ParsedConfigPrincipal::Invalid => false,
    }
}

/// Validate the bounded cleartext metadata wrapper used by encrypted config
/// adapters. A principal without the wrapper remains a supported legacy
/// representation.
pub(crate) fn config_principal_metadata_is_valid(stored: &str) -> bool {
    !matches!(
        parse_config_principal(stored),
        ParsedConfigPrincipal::Invalid
    )
}

/// Extract and validate the clear, domain-separated replay lookup digest from
/// the encrypted config metadata wrapper. Legacy principal-only rows have no
/// wrapper and therefore no lookup value.
pub(crate) fn config_replay_lookup_digest(stored: &str) -> Result<Option<String>, PersistError> {
    match parse_config_principal(stored) {
        ParsedConfigPrincipal::Legacy => Ok(None),
        ParsedConfigPrincipal::Wrapped(metadata) => Ok(metadata.replay_lookup_digest),
        ParsedConfigPrincipal::Invalid => Err(PersistError::corrupt_blob()),
    }
}

/// Extract and validate the optional named rollback point carried by an
/// encrypted config record's clear lifecycle metadata.
pub(crate) fn config_rollback_label(stored: &str) -> Result<Option<String>, PersistError> {
    match parse_config_principal(stored) {
        ParsedConfigPrincipal::Legacy => Ok(None),
        ParsedConfigPrincipal::Wrapped(metadata) => Ok(metadata.rollback_label),
        ParsedConfigPrincipal::Invalid => Err(PersistError::corrupt_blob()),
    }
}

pub(crate) fn config_recovery_required(stored: &str) -> Result<bool, PersistError> {
    match parse_config_principal(stored) {
        ParsedConfigPrincipal::Legacy => Ok(false),
        ParsedConfigPrincipal::Wrapped(metadata) => Ok(metadata.recovery_required),
        ParsedConfigPrincipal::Invalid => Err(PersistError::corrupt_blob()),
    }
}

pub(crate) fn clear_config_recovery_required(stored: &str) -> Result<Option<String>, PersistError> {
    let ParsedConfigPrincipal::Wrapped(mut metadata) = parse_config_principal(stored) else {
        return Err(PersistError::corrupt_blob());
    };
    if !metadata.recovery_required {
        return Ok(None);
    }
    metadata.recovery_required = false;
    serde_json::to_string(&metadata)
        .map(Some)
        .map_err(|_| PersistError::corrupt_blob())
}

pub(crate) fn validate_replay_lookup_digest(digest: &str) -> Result<(), PersistError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(PersistError::constraint_violation(
            "config replay lookup digest is invalid",
        ));
    }
    Ok(())
}

pub(crate) fn validate_rollback_label(label: &str) -> Result<(), PersistError> {
    if label.is_empty()
        || label.len() > CONFIG_ROLLBACK_LABEL_MAX_BYTES
        || label.trim() != label
        || label.chars().any(char::is_control)
    {
        return Err(PersistError::constraint_violation(
            "rollback label is not canonically representable",
        ));
    }
    Ok(())
}

pub fn extract_tenant(principal: &str) -> String {
    let wrapped = wrapped_config_principal(principal);
    let principal = wrapped.as_deref().unwrap_or(principal);
    if let Some(tenant) = serde_json::from_str::<serde_json::Value>(principal)
        .ok()
        .and_then(|principal| {
            principal
                .get("tenant")
                .and_then(|value| value.as_str())
                .map(str::to_owned)
        })
    {
        return tenant;
    }
    if let Some(rest) = principal.strip_prefix("spiffe://") {
        let mut segs = rest.split('/');
        while let Some(seg) = segs.next() {
            if seg == "tenant" {
                if let Some(tenant) = segs.next() {
                    return tenant.to_string();
                }
            }
        }
    }
    "default".to_string()
}

pub fn is_sensitive(path: &str, raw_val: &str) -> bool {
    let path_lower = path.to_lowercase();

    // 1. Path-based check
    if path_lower.contains("supi")
        || path_lower.contains("gpsi")
        || path_lower.contains("imsi")
        || path_lower.contains("msisdn")
        || path_lower.contains("pei")
        || path_lower.contains("guti")
        || path_lower.contains("secret")
        || path_lower.contains("token")
        || path_lower.contains("password")
        || path_lower.contains("key")
        || path_lower.contains("credential")
        || path_lower.contains("private-key")
        || path_lower.contains("private_key")
        || path_lower.contains("ip-address")
        || path_lower.contains("ip_address")
        || path_lower.contains("ipv4")
        || path_lower.contains("ipv6")
    {
        return true;
    }

    // 2. Value-based check: Subscriber identifiers and credential material.
    let val_lower = raw_val.to_lowercase();
    if val_lower.contains("supi-")
        || val_lower.contains("imsi-")
        || val_lower.contains("gpsi-")
        || val_lower.contains("msisdn")
        || val_lower.contains("pei-")
        || val_lower.contains("guti-")
        || val_lower.contains("bearer ")
        || val_lower.contains("basic ")
        || val_lower.contains("authorization")
        || val_lower.contains("password")
        || val_lower.contains("secret")
        || val_lower.contains("private-key")
        || val_lower.contains("private_key")
        || val_lower.contains("access-token")
        || val_lower.contains("access_token")
        || val_lower.contains("refresh-token")
        || val_lower.contains("refresh_token")
        || val_lower.contains("api-key")
        || val_lower.contains("api_key")
        || val_lower.contains("apikey")
        || val_lower.contains("credential")
    {
        return true;
    }

    // 3. Value-based check: embedded subscriber identifiers or IP addresses.
    if contains_long_digit_run(raw_val, 8)
        || contains_ipv4(raw_val)
        || contains_ipv6(raw_val)
        || contains_sensitive_base64(raw_val)
    {
        return true;
    }

    false
}

pub fn redact_entry(path: &str, value_opt: &mut Option<String>, redaction_applied: &mut bool) {
    if let Some(val) = value_opt {
        if val == "\"<redacted>\"" || val == "<redacted>" {
            return;
        }

        let raw_val = match serde_json::from_str::<serde_json::Value>(val) {
            Ok(serde_json::Value::String(s)) => s,
            Ok(json_value) => json_value.to_string(),
            Err(_) => val.clone(),
        };

        if is_sensitive(path, &raw_val) {
            let masked = redact(
                &raw_val,
                DataClass::AuditRegulated,
                RedactionLevel::Mask,
                None,
                None,
            )
            .to_string();
            *value_opt = Some(
                serde_json::to_string(&masked)
                    .expect("redaction placeholder serializes as a JSON string"),
            );
            *redaction_applied = true;
        }
    }
}

fn contains_long_digit_run(input: &str, min_len: usize) -> bool {
    let mut run = 0;
    for ch in input.chars() {
        if ch.is_ascii_digit() {
            run += 1;
            if run >= min_len {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

fn contains_ipv4(input: &str) -> bool {
    input
        .split(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .any(is_ipv4_candidate)
}

fn is_ipv4_candidate(candidate: &str) -> bool {
    let mut parts_seen = 0;
    for part in candidate.split('.') {
        parts_seen += 1;
        if part.is_empty()
            || part.len() > 3
            || !part.chars().all(|ch| ch.is_ascii_digit())
            || part.parse::<u8>().is_err()
        {
            return false;
        }
    }

    if parts_seen != 4 {
        return false;
    }

    true
}

fn contains_ipv6(input: &str) -> bool {
    input
        .split(|ch: char| !(ch.is_ascii_hexdigit() || ch == ':'))
        .any(is_ipv6_candidate)
}

fn is_ipv6_candidate(candidate: &str) -> bool {
    candidate.contains(':') && candidate.parse::<Ipv6Addr>().is_ok()
}

fn contains_sensitive_base64(input: &str) -> bool {
    input
        .split(|ch: char| {
            !(ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '-' | '_'))
        })
        .any(is_sensitive_base64_candidate)
}

fn is_sensitive_base64_candidate(candidate: &str) -> bool {
    if candidate.len() < 32 || candidate.len() % 4 == 1 {
        return false;
    }

    if !candidate
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '-' | '_'))
    {
        return false;
    }

    let mut seen_padding = false;
    let mut has_upper = false;
    let mut has_lower = false;
    let mut has_digit = false;
    for ch in candidate.chars() {
        if ch == '=' {
            seen_padding = true;
            continue;
        }
        if seen_padding {
            return false;
        }
        has_upper |= ch.is_ascii_uppercase();
        has_lower |= ch.is_ascii_lowercase();
        has_digit |= ch.is_ascii_digit();
    }

    if !(has_upper && has_lower && has_digit) {
        return false;
    }

    shannon_entropy(candidate.trim_end_matches('=')) >= 4.0
}

fn shannon_entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for byte in input.bytes() {
        counts[usize::from(byte)] += 1;
    }

    let len = input.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

impl AuditRecord {
    pub fn calculate_hmac(&self, audit_key: &AuditKey, tenant: &str) -> [u8; 32] {
        self.calculate_hmac_inner(audit_key, tenant, None)
    }

    pub fn calculate_hmac_with_audit_count(
        &self,
        audit_key: &AuditKey,
        tenant: &str,
        audit_count: u32,
    ) -> [u8; 32] {
        self.calculate_hmac_inner(audit_key, tenant, Some(audit_count))
    }

    fn calculate_hmac_inner(
        &self,
        audit_key: &AuditKey,
        tenant: &str,
        audit_count: Option<u32>,
    ) -> [u8; 32] {
        let op_type_str = match self.op_type {
            AuditOpType::Create => "CREATE",
            AuditOpType::Update => "UPDATE",
            AuditOpType::Replace => "REPLACE",
            AuditOpType::Delete => "DELETE",
        };

        let mut mac_input = Vec::new();
        // write tenant
        mac_input.extend_from_slice(&(tenant.len() as u32).to_be_bytes());
        mac_input.extend_from_slice(tenant.as_bytes());

        if let Some(audit_count) = audit_count {
            mac_input.extend_from_slice(&audit_count.to_be_bytes());
        }

        // write sequence
        mac_input.extend_from_slice(&self.sequence.to_be_bytes());

        // write yang_path
        mac_input.extend_from_slice(&(self.yang_path.len() as u32).to_be_bytes());
        mac_input.extend_from_slice(self.yang_path.as_bytes());

        // write op_type
        mac_input.extend_from_slice(&(op_type_str.len() as u32).to_be_bytes());
        mac_input.extend_from_slice(op_type_str.as_bytes());

        // write previous_value
        match &self.previous_value {
            Some(val) => {
                mac_input.push(1);
                mac_input.extend_from_slice(&(val.len() as u32).to_be_bytes());
                mac_input.extend_from_slice(val.as_bytes());
            }
            None => {
                mac_input.push(0);
            }
        }

        // write new_value
        match &self.new_value {
            Some(val) => {
                mac_input.push(1);
                mac_input.extend_from_slice(&(val.len() as u32).to_be_bytes());
                mac_input.extend_from_slice(val.as_bytes());
            }
            None => {
                mac_input.push(0);
            }
        }

        // write redaction_applied
        mac_input.push(if self.redaction_applied { 1 } else { 0 });

        // write previous_hash
        mac_input.extend_from_slice(&self.previous_hash);

        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(audit_key.as_bytes())
            .expect("HMAC-SHA-256 works with 32-byte key");
        mac.update(&mac_input);
        mac.finalize().into_bytes().into()
    }
}

impl StoredConfig {
    pub fn verify_audit_chain(&self, audit_key: &AuditKey) -> Result<(), PersistError> {
        let tenant = extract_tenant(&self.record.principal);
        let mut prev_hash = [0u8; 32];
        let audit_count =
            u32::try_from(self.audit.len()).map_err(|_| PersistError::audit_chain_broken())?;
        for entry in &self.audit {
            if entry.previous_hash != prev_hash {
                return Err(PersistError::audit_chain_broken());
            }
            let expected_hmac =
                entry.calculate_hmac_with_audit_count(audit_key, &tenant, audit_count);
            if entry.entry_hmac != expected_hmac {
                return Err(PersistError::audit_chain_broken());
            }
            prev_hash = entry.entry_hmac;
        }
        Ok(())
    }
}

#[cfg(test)]
mod config_principal_metadata_tests {
    use super::*;

    const PRINCIPAL: &str =
        "{\"tenant\":\"tenant-a\",\"identity\":{\"internal\":\"config-writer\"}}";

    #[test]
    fn strict_wrapper_parser_preserves_the_exact_nested_principal() {
        let encoded = serde_json::json!({
            "principal": PRINCIPAL,
            "replay_lookup_digest": "a".repeat(64),
            "recovery_required": true,
            "rollback_label": "release-candidate",
        })
        .to_string();
        assert!(config_principal_metadata_is_valid(&encoded));
        assert_eq!(
            Some(PRINCIPAL),
            wrapped_config_principal(&encoded).as_deref()
        );
        assert!(config_principal_matches_aad(&encoded, PRINCIPAL));
        assert!(
            !config_principal_matches_aad(&encoded, &encoded),
            "the metadata wrapper itself is never an authenticated principal"
        );
        assert_eq!(
            Some("a".repeat(64)),
            config_replay_lookup_digest(&encoded).expect("valid replay digest")
        );
        assert_eq!(
            Some("release-candidate".to_owned()),
            config_rollback_label(&encoded).expect("valid rollback label")
        );

        let cleared = clear_config_recovery_required(&encoded)
            .expect("valid recovery metadata")
            .expect("marker changes");
        assert_eq!(
            Some(PRINCIPAL),
            wrapped_config_principal(&cleared).as_deref()
        );
        assert!(clear_config_recovery_required(&cleared)
            .expect("valid cleared metadata")
            .is_none());
    }

    #[test]
    fn wrapper_only_and_duplicate_reserved_fields_fail_closed() {
        let malformed = [
            format!(
                "{{\"replay_lookup_digest\":\"{}\",\"recovery_required\":true}}",
                "a".repeat(64)
            ),
            format!(
                "{{\"principal\":{PRINCIPAL:?},\"principal\":{PRINCIPAL:?},\"recovery_required\":true}}"
            ),
            format!(
                "{{\"principal\":{PRINCIPAL:?},\"replay_lookup_digest\":\"{}\",\"replay_lookup_digest\":\"{}\",\"recovery_required\":true}}",
                "a".repeat(64),
                "b".repeat(64)
            ),
            format!(
                "{{\"principal\":{PRINCIPAL:?},\"recovery_required\":true,\"recovery_required\":false}}"
            ),
            format!(
                "{{\"principal\":{PRINCIPAL:?},\"recovery_required\":false,\"rollback_label\":\"one\",\"rollback_label\":\"two\"}}"
            ),
            format!(
                "{{\"principal\":{PRINCIPAL:?},\"recovery_required\":false,\"rollback_label\":{:?}}}",
                "x".repeat(CONFIG_ROLLBACK_LABEL_MAX_BYTES + 1)
            ),
        ];
        for encoded in malformed {
            assert!(!config_principal_metadata_is_valid(&encoded));
            assert!(config_replay_lookup_digest(&encoded).is_err());
            assert!(config_rollback_label(&encoded).is_err());
            assert!(clear_config_recovery_required(&encoded).is_err());
        }
    }

    #[test]
    fn legacy_principal_objects_without_wrapper_fields_remain_supported() {
        assert!(config_principal_metadata_is_valid(PRINCIPAL));
        assert_eq!(
            None,
            config_replay_lookup_digest(PRINCIPAL).expect("legacy principal")
        );
        assert_eq!(
            None,
            config_rollback_label(PRINCIPAL).expect("legacy principal")
        );
        assert!(config_principal_matches_aad(PRINCIPAL, PRINCIPAL));
    }
}
