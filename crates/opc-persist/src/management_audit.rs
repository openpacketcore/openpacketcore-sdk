//! Durable management-plane audit storage over the reference SQLite profile.

use std::fmt;

use rusqlite::types::ValueRef;
use rusqlite::Connection;

use crate::backend::SqliteBackend;
use crate::error::PersistError;
use crate::types::{calculate_audit_chain_hmac, AuditChainDomain, AuditChainField, AuditKey};

/// Durable management-audit record/anchor schema version.
pub const MANAGEMENT_AUDIT_FORMAT_VERSION: u64 = 1;
/// Maximum supported retained-record cap.
pub const MANAGEMENT_AUDIT_MAX_RETAINED_RECORDS: u64 = 1_000_000;
/// Maximum tenant field size in UTF-8 bytes.
pub const MANAGEMENT_AUDIT_MAX_TENANT_BYTES: usize = 256;
/// Maximum principal field size in UTF-8 bytes.
pub const MANAGEMENT_AUDIT_MAX_PRINCIPAL_BYTES: usize = 1024;
/// Maximum predicate-free schema paths in one event.
pub const MANAGEMENT_AUDIT_MAX_SCHEMA_PATHS: usize = 256;
/// Maximum UTF-8 bytes in one predicate-free schema path.
pub const MANAGEMENT_AUDIT_MAX_SCHEMA_PATH_BYTES: usize = 4096;
/// Maximum transaction-id field size in UTF-8 bytes.
pub const MANAGEMENT_AUDIT_MAX_TX_ID_BYTES: usize = 128;
/// Maximum stable reason-code size in UTF-8 bytes.
pub const MANAGEMENT_AUDIT_MAX_REASON_BYTES: usize = 64;
/// Maximum total UTF-8 bytes across one event's persisted variable fields.
pub const MANAGEMENT_AUDIT_MAX_EVENT_BYTES: usize = 256 * 1024;
/// Maximum records returned by one authenticated management-audit page.
pub const MANAGEMENT_AUDIT_MAX_PAGE_RECORDS: u32 = 256;

const ZERO_HASH: [u8; 32] = [0; 32];
const MANAGEMENT_AUDIT_MAX_STABLE_CODE_BYTES: usize = 32;

/// Validated count-based retention policy for the durable management trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagementAuditRetention {
    max_records: u64,
}

impl ManagementAuditRetention {
    /// Validate a non-zero retained-record cap.
    pub fn try_new(max_records: u64) -> Result<Self, ManagementAuditRetentionError> {
        if max_records == 0 {
            return Err(ManagementAuditRetentionError::Zero);
        }
        if max_records > MANAGEMENT_AUDIT_MAX_RETAINED_RECORDS {
            return Err(ManagementAuditRetentionError::TooLarge);
        }
        Ok(Self { max_records })
    }

    /// Maximum records retained after each atomic append.
    pub const fn max_records(self) -> u64 {
        self.max_records
    }
}

/// Invalid durable management-audit retention configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ManagementAuditRetentionError {
    /// A zero-record trail cannot preserve a retained terminal record.
    #[error("management audit retention must keep at least one record")]
    Zero,
    /// The cap exceeded the implementation's fixed storage/verification bound.
    #[error("management audit retention exceeds the supported bound")]
    TooLarge,
}

/// Stable persisted transport code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementAuditTransportCode {
    /// gNMI.
    Gnmi,
    /// NETCONF over SSH.
    NetconfSsh,
    /// NETCONF over TLS.
    NetconfTls,
    /// RESTCONF over HTTPS.
    RestconfHttps,
    /// Trusted internal boundary.
    Internal,
}

impl ManagementAuditTransportCode {
    /// Stable lowercase durable code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gnmi => "gnmi",
            Self::NetconfSsh => "netconf-ssh",
            Self::NetconfTls => "netconf-tls",
            Self::RestconfHttps => "restconf-https",
            Self::Internal => "internal",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "gnmi" => Some(Self::Gnmi),
            "netconf-ssh" => Some(Self::NetconfSsh),
            "netconf-tls" => Some(Self::NetconfTls),
            "restconf-https" => Some(Self::RestconfHttps),
            "internal" => Some(Self::Internal),
            _ => None,
        }
    }
}

/// Stable persisted management-operation code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementAuditOperationCode {
    /// Capability/schema discovery.
    Capabilities,
    /// Data read.
    Read,
    /// Subscription creation.
    Subscribe,
    /// Node creation.
    Create,
    /// Merge/update.
    Update,
    /// Subtree replacement.
    Replace,
    /// Deletion.
    Delete,
    /// Candidate-to-running commit.
    Commit,
    /// Rollback.
    Rollback,
    /// Validation.
    Validate,
    /// RPC/exec.
    Exec,
}

impl ManagementAuditOperationCode {
    /// Stable lowercase durable code.
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

    fn parse(value: &str) -> Option<Self> {
        match value {
            "capabilities" => Some(Self::Capabilities),
            "read" => Some(Self::Read),
            "subscribe" => Some(Self::Subscribe),
            "create" => Some(Self::Create),
            "update" => Some(Self::Update),
            "replace" => Some(Self::Replace),
            "delete" => Some(Self::Delete),
            "commit" => Some(Self::Commit),
            "rollback" => Some(Self::Rollback),
            "validate" => Some(Self::Validate),
            "exec" => Some(Self::Exec),
            _ => None,
        }
    }
}

/// Stable persisted management-audit outcome class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementAuditOutcomeCode {
    /// Pre-side-effect intent.
    Intent,
    /// Successful operation.
    Success,
    /// Authorization denial.
    Denied,
    /// Operation failure.
    Failed,
}

impl ManagementAuditOutcomeCode {
    /// Stable lowercase durable code.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Intent => "intent",
            Self::Success => "success",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "intent" => Some(Self::Intent),
            "success" => Some(Self::Success),
            "denied" => Some(Self::Denied),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    const fn requires_reason(self) -> bool {
        matches!(self, Self::Denied | Self::Failed)
    }
}

/// Payload-free typed input accepted by the durable management-audit backend.
#[derive(Clone, PartialEq, Eq)]
pub struct ManagementAuditEventRecord {
    request_id: [u8; 16],
    tenant: String,
    principal: String,
    transport: ManagementAuditTransportCode,
    operation: ManagementAuditOperationCode,
    outcome: ManagementAuditOutcomeCode,
    reason: Option<String>,
    schema_paths: Vec<String>,
    tx_id: Option<String>,
}

impl ManagementAuditEventRecord {
    /// Construct and bound one payload-free management event.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        request_id: [u8; 16],
        tenant: impl AsRef<str>,
        principal: impl AsRef<str>,
        transport: ManagementAuditTransportCode,
        operation: ManagementAuditOperationCode,
        outcome: ManagementAuditOutcomeCode,
        reason: Option<impl AsRef<str>>,
        schema_paths: impl IntoIterator<Item = impl AsRef<str>>,
        tx_id: Option<impl AsRef<str>>,
    ) -> Result<Self, ManagementAuditRecordError> {
        let tenant = tenant.as_ref();
        let principal = principal.as_ref();
        let reason = reason.as_ref().map(AsRef::as_ref);
        let tx_id = tx_id.as_ref().map(AsRef::as_ref);

        validate_required_text(tenant, MANAGEMENT_AUDIT_MAX_TENANT_BYTES)?;
        validate_required_text(principal, MANAGEMENT_AUDIT_MAX_PRINCIPAL_BYTES)?;
        if outcome.requires_reason() != reason.is_some() {
            return Err(ManagementAuditRecordError::OutcomeReason);
        }
        if let Some(reason) = reason {
            validate_machine_code(reason, MANAGEMENT_AUDIT_MAX_REASON_BYTES)?;
        }
        if let Some(tx_id) = tx_id {
            validate_machine_code(tx_id, MANAGEMENT_AUDIT_MAX_TX_ID_BYTES)?;
        }

        let variable_bytes = tenant
            .len()
            .checked_add(principal.len())
            .and_then(|total| total.checked_add(reason.map_or(0, str::len)))
            .and_then(|total| total.checked_add(tx_id.map_or(0, str::len)))
            .ok_or(ManagementAuditRecordError::TooLarge)?;
        if variable_bytes > MANAGEMENT_AUDIT_MAX_EVENT_BYTES {
            return Err(ManagementAuditRecordError::TooLarge);
        }

        let mut variable_bytes = variable_bytes;
        let mut bounded_paths = Vec::new();
        for path in schema_paths {
            if bounded_paths.len() == MANAGEMENT_AUDIT_MAX_SCHEMA_PATHS {
                return Err(ManagementAuditRecordError::TooManyPaths);
            }
            let path = path.as_ref();
            validate_schema_path(path)?;
            variable_bytes = variable_bytes
                .checked_add(path.len())
                .ok_or(ManagementAuditRecordError::TooLarge)?;
            if variable_bytes > MANAGEMENT_AUDIT_MAX_EVENT_BYTES {
                return Err(ManagementAuditRecordError::TooLarge);
            }
            bounded_paths.push(path.to_owned());
        }

        Ok(Self {
            request_id,
            tenant: tenant.to_owned(),
            principal: principal.to_owned(),
            transport,
            operation,
            outcome,
            reason: reason.map(str::to_owned),
            schema_paths: bounded_paths,
            tx_id: tx_id.map(str::to_owned),
        })
    }

    /// Exact request UUID bytes.
    pub const fn request_id(&self) -> &[u8; 16] {
        &self.request_id
    }

    /// Tenant text from the trusted management principal.
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// Principal descriptor from the trusted management boundary.
    pub fn principal(&self) -> &str {
        &self.principal
    }

    /// Stable transport code.
    pub const fn transport(&self) -> ManagementAuditTransportCode {
        self.transport
    }

    /// Stable operation code.
    pub const fn operation(&self) -> ManagementAuditOperationCode {
        self.operation
    }

    /// Stable outcome class.
    pub const fn outcome(&self) -> ManagementAuditOutcomeCode {
        self.outcome
    }

    /// Stable reason code for denied/failed outcomes.
    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    /// Predicate-free schema-node paths in caller order.
    pub fn schema_paths(&self) -> &[String] {
        &self.schema_paths
    }

    /// Optional bounded transaction id.
    pub fn tx_id(&self) -> Option<&str> {
        self.tx_id.as_deref()
    }
}

impl fmt::Debug for ManagementAuditEventRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagementAuditEventRecord")
            .field("request_id", &"<redacted>")
            .field("tenant", &"<redacted>")
            .field("principal", &"<redacted>")
            .field("transport", &self.transport)
            .field("operation", &self.operation)
            .field("outcome", &self.outcome)
            .field("reason", &self.reason)
            .field("schema_path_count", &self.schema_paths.len())
            .field("tx_id", &self.tx_id.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Invalid payload-free management-audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ManagementAuditRecordError {
    /// A required field was empty or exceeded its byte bound.
    #[error("management audit required field is invalid")]
    RequiredField,
    /// Outcome and reason presence were inconsistent.
    #[error("management audit outcome and reason are inconsistent")]
    OutcomeReason,
    /// A stable machine code was empty, too long, or contained unsafe bytes.
    #[error("management audit machine code is invalid")]
    MachineCode,
    /// Too many schema paths were supplied.
    #[error("management audit schema-path count exceeds its bound")]
    TooManyPaths,
    /// A schema path was not an absolute, predicate-free path.
    #[error("management audit schema path is invalid")]
    SchemaPath,
    /// The complete record exceeded its fixed byte bound.
    #[error("management audit record exceeds its byte bound")]
    TooLarge,
}

fn validate_required_text(value: &str, max_bytes: usize) -> Result<(), ManagementAuditRecordError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        Err(ManagementAuditRecordError::RequiredField)
    } else {
        Ok(())
    }
}

fn validate_machine_code(value: &str, max_bytes: usize) -> Result<(), ManagementAuditRecordError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(ManagementAuditRecordError::MachineCode)
    } else {
        Ok(())
    }
}

fn validate_schema_path(path: &str) -> Result<(), ManagementAuditRecordError> {
    if path.len() > MANAGEMENT_AUDIT_MAX_SCHEMA_PATH_BYTES
        || path == "/"
        || !path.starts_with('/')
        || path.chars().any(char::is_control)
        || path
            .bytes()
            .any(|byte| matches!(byte, b'[' | b']' | b'=' | b'\'' | b'"'))
    {
        return Err(ManagementAuditRecordError::SchemaPath);
    }
    let segments_valid = path.trim_start_matches('/').split('/').all(|segment| {
        let Some((prefix, name)) = segment.split_once(':') else {
            return false;
        };
        !prefix.is_empty()
            && !name.is_empty()
            && segment.split_once(':') == segment.rsplit_once(':')
            && [prefix, name].into_iter().all(valid_yang_identifier)
    });
    if segments_valid {
        Ok(())
    } else {
        Err(ManagementAuditRecordError::SchemaPath)
    }
}

fn valid_yang_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// One retained durable record and its authenticated chain links.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredManagementAuditRecord {
    sequence: u64,
    event: ManagementAuditEventRecord,
    previous_hash: [u8; 32],
    entry_hmac: [u8; 32],
}

impl StoredManagementAuditRecord {
    /// Absolute, never-reused append sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Payload-free management event.
    pub const fn event(&self) -> &ManagementAuditEventRecord {
        &self.event
    }

    /// Hash link immediately before this record.
    pub const fn previous_hash(&self) -> &[u8; 32] {
        &self.previous_hash
    }

    /// HMAC authenticating this record and its predecessor link.
    pub const fn entry_hmac(&self) -> &[u8; 32] {
        &self.entry_hmac
    }
}

impl fmt::Debug for StoredManagementAuditRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StoredManagementAuditRecord")
            .field("sequence", &self.sequence)
            .field("event", &self.event)
            .field("previous_hash", &"<redacted>")
            .field("entry_hmac", &"<redacted>")
            .finish()
    }
}

/// Verified durable management-audit boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagementAuditVerification {
    /// Total records appended since genesis, including retention-pruned rows.
    pub total_count: u64,
    /// Records currently retained.
    pub retained_count: u64,
    /// Absolute sequence of the first retained row or next append when empty.
    pub low_water_sequence: u64,
    /// Absolute sequence of the terminal row, when non-empty.
    pub terminal_sequence: Option<u64>,
    /// Configured retained-record cap authenticated by the anchor.
    pub retention_max_records: u64,
}

/// Validated bounded retrieval request for retained management-audit records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagementAuditPageRequest {
    start_sequence: Option<u64>,
    limit: u32,
}

impl ManagementAuditPageRequest {
    /// Construct a page request from an optional absolute sequence cursor.
    ///
    /// `None` starts at the authenticated low-water mark. The limit must be in
    /// `1..=`[`MANAGEMENT_AUDIT_MAX_PAGE_RECORDS`].
    pub fn try_new(
        start_sequence: Option<u64>,
        limit: u32,
    ) -> Result<Self, ManagementAuditPageRequestError> {
        if limit == 0 || limit > MANAGEMENT_AUDIT_MAX_PAGE_RECORDS {
            return Err(ManagementAuditPageRequestError::InvalidLimit);
        }
        Ok(Self {
            start_sequence,
            limit,
        })
    }

    /// Absolute sequence at which retrieval starts, or the low-water mark.
    pub const fn start_sequence(self) -> Option<u64> {
        self.start_sequence
    }

    /// Maximum records returned by this request.
    pub const fn limit(self) -> u32 {
        self.limit
    }
}

/// Invalid bounded management-audit page request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ManagementAuditPageRequestError {
    /// The requested page was empty or exceeded the fixed public bound.
    #[error("management audit page limit is outside its supported bound")]
    InvalidLimit,
}

/// A requested absolute cursor is outside the currently retained trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ManagementAuditCursorError {
    /// The cursor points to a record removed by authenticated retention.
    #[error("management audit cursor precedes the retained low-water mark")]
    Pruned {
        /// Requested absolute sequence.
        requested: u64,
        /// First retained absolute sequence.
        low_water_sequence: u64,
    },
    /// The cursor is beyond the next valid append sequence.
    #[error("management audit cursor exceeds the current trail")]
    Ahead {
        /// Requested absolute sequence.
        requested: u64,
        /// Sequence that the next append will receive.
        next_append_sequence: u64,
    },
}

/// One bounded page returned only after complete chain authentication.
#[derive(Clone, PartialEq, Eq)]
pub struct ManagementAuditPage {
    records: Vec<StoredManagementAuditRecord>,
    next_sequence: Option<u64>,
    verification: ManagementAuditVerification,
}

impl ManagementAuditPage {
    /// Authenticated records in ascending absolute sequence order.
    pub fn records(&self) -> &[StoredManagementAuditRecord] {
        &self.records
    }

    /// Cursor for the next page, or `None` when the authenticated tail was read.
    pub const fn next_sequence(&self) -> Option<u64> {
        self.next_sequence
    }

    /// Authenticated boundaries observed by this transactional query.
    pub const fn verification(&self) -> ManagementAuditVerification {
        self.verification
    }
}

impl fmt::Debug for ManagementAuditPage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagementAuditPage")
            .field("record_count", &self.records.len())
            .field("next_sequence", &self.next_sequence)
            .field("verification", &self.verification)
            .finish()
    }
}

/// Stable class for a management-audit verification failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManagementAuditVerificationFailure {
    /// Rows exist without the mandatory authenticated anchor.
    MissingAnchor,
    /// Anchor fields or fixed-width hashes are malformed.
    MalformedAnchor,
    /// Anchor HMAC or key epoch does not match.
    AnchorAuthentication,
    /// Counts, watermarks, retention, or terminal metadata disagree.
    AnchorInvariant,
    /// A retained sequence is absent or duplicated.
    Sequence,
    /// A persisted event/path field is malformed.
    MalformedRecord,
    /// The predecessor hash is not the expected chain link.
    PreviousHash,
    /// The record HMAC does not authenticate its persisted fields.
    RecordAuthentication,
    /// Final count or terminal hash does not match the authenticated anchor.
    Terminal,
}

/// Typed first-break result from management-audit verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagementAuditVerificationError {
    failure: ManagementAuditVerificationFailure,
    sequence: Option<u64>,
}

impl ManagementAuditVerificationError {
    fn new(failure: ManagementAuditVerificationFailure, sequence: Option<u64>) -> Self {
        Self { failure, sequence }
    }

    /// Stable failure class.
    pub const fn failure(&self) -> ManagementAuditVerificationFailure {
        self.failure
    }

    /// First absolute sequence at which verification failed, when applicable.
    pub const fn sequence(&self) -> Option<u64> {
        self.sequence
    }
}

impl fmt::Display for ManagementAuditVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.sequence {
            Some(sequence) => write!(
                formatter,
                "management audit chain verification failed at sequence {sequence}"
            ),
            None => formatter.write_str("management audit chain verification failed"),
        }
    }
}

impl std::error::Error for ManagementAuditVerificationError {}

/// Durable backend or integrity failure from the management-audit store.
#[derive(thiserror::Error)]
pub enum ManagementAuditStoreError {
    /// SQLite/preflight/storage failure.
    #[error(transparent)]
    Persistence(#[from] PersistError),
    /// Authenticated-chain verification failure.
    #[error(transparent)]
    Verification(#[from] ManagementAuditVerificationError),
    /// The requested absolute page cursor is no longer available or not valid yet.
    #[error(transparent)]
    Cursor(#[from] ManagementAuditCursorError),
}

impl fmt::Debug for ManagementAuditStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self {
            Self::Persistence(_) => "Persistence",
            Self::Verification(_) => "Verification",
            Self::Cursor(_) => "Cursor",
        };
        formatter
            .debug_struct("ManagementAuditStoreError")
            .field("class", &class)
            .finish()
    }
}

#[derive(Debug, Clone)]
struct AnchorState {
    retention_max_records: u64,
    key_epoch: u64,
    total_count: u64,
    retained_count: u64,
    low_water_sequence: u64,
    low_water_hash: [u8; 32],
    terminal_sequence: Option<u64>,
    terminal_hash: [u8; 32],
    anchor_hmac: [u8; 32],
}

impl AnchorState {
    fn fresh(
        retention: ManagementAuditRetention,
        audit_key: &AuditKey,
    ) -> Result<Self, PersistError> {
        let mut state = Self {
            retention_max_records: retention.max_records(),
            key_epoch: audit_key.epoch(),
            total_count: 0,
            retained_count: 0,
            low_water_sequence: 0,
            low_water_hash: ZERO_HASH,
            terminal_sequence: None,
            terminal_hash: ZERO_HASH,
            anchor_hmac: ZERO_HASH,
        };
        state.anchor_hmac = state.calculate_hmac(audit_key)?;
        Ok(state)
    }

    fn calculate_hmac(&self, audit_key: &AuditKey) -> Result<[u8; 32], PersistError> {
        calculate_audit_chain_hmac(
            audit_key,
            AuditChainDomain::ManagementAnchorV1,
            &[
                AuditChainField::U64(MANAGEMENT_AUDIT_FORMAT_VERSION),
                AuditChainField::U64(self.key_epoch),
                AuditChainField::U64(self.retention_max_records),
                AuditChainField::U64(self.total_count),
                AuditChainField::U64(self.retained_count),
                AuditChainField::U64(self.low_water_sequence),
                AuditChainField::Hash(&self.low_water_hash),
                AuditChainField::U64(self.terminal_sequence.unwrap_or(u64::MAX)),
                AuditChainField::Hash(&self.terminal_hash),
            ],
        )
    }

    fn validate(&self, audit_key: &AuditKey) -> Result<(), ManagementAuditVerificationError> {
        if self.key_epoch != audit_key.epoch()
            || self.calculate_hmac(audit_key).ok() != Some(self.anchor_hmac)
        {
            return Err(ManagementAuditVerificationError::new(
                ManagementAuditVerificationFailure::AnchorAuthentication,
                None,
            ));
        }
        let expected_low_water = self.total_count.checked_sub(self.retained_count);
        let expected_terminal = self.total_count.checked_sub(1);
        let valid_empty = self.total_count != 0
            || (self.retained_count == 0
                && self.low_water_sequence == 0
                && self.low_water_hash == ZERO_HASH
                && self.terminal_sequence.is_none()
                && self.terminal_hash == ZERO_HASH);
        if self.retention_max_records == 0
            || self.retention_max_records > MANAGEMENT_AUDIT_MAX_RETAINED_RECORDS
            || self.retained_count > self.retention_max_records
            || expected_low_water != Some(self.low_water_sequence)
            || self.terminal_sequence != expected_terminal
            || (self.total_count > 0 && self.retained_count == 0)
            || !valid_empty
        {
            return Err(ManagementAuditVerificationError::new(
                ManagementAuditVerificationFailure::AnchorInvariant,
                None,
            ));
        }
        Ok(())
    }

    fn verification(&self) -> ManagementAuditVerification {
        ManagementAuditVerification {
            total_count: self.total_count,
            retained_count: self.retained_count,
            low_water_sequence: self.low_water_sequence,
            terminal_sequence: self.terminal_sequence,
            retention_max_records: self.retention_max_records,
        }
    }
}

impl SqliteBackend {
    /// Verify the existing management trail, configure retention, and create an
    /// authenticated empty anchor for a fresh store.
    ///
    /// Existing rows are verified before any retention-policy update or prune.
    pub async fn configure_management_audit(
        &self,
        retention: ManagementAuditRetention,
    ) -> Result<ManagementAuditVerification, ManagementAuditStoreError> {
        let conn = self.conn().lock_owned().await;
        let tx = conn.unchecked_transaction().map_err(PersistError::from)?;
        let (mut anchor, _) = match verify_chain(&tx, self.audit_key())? {
            Some(verified) => verified,
            None => {
                let anchor = AnchorState::fresh(retention, self.audit_key())?;
                insert_anchor(&tx, &anchor)?;
                let verification = anchor.verification();
                let data_version = sqlite_data_version(&tx)?;
                tx.commit().map_err(|_| PersistError::outcome_unknown())?;
                self.set_management_audit_data_version(data_version);
                return Ok(verification);
            }
        };

        if anchor.retention_max_records != retention.max_records() {
            anchor.retention_max_records = retention.max_records();
            prune_to_retention(&tx, &mut anchor)?;
            anchor.anchor_hmac = anchor.calculate_hmac(self.audit_key())?;
            update_anchor(&tx, &anchor)?;
        }
        let verification = anchor.verification();
        let data_version = sqlite_data_version(&tx)?;
        tx.commit().map_err(|_| PersistError::outcome_unknown())?;
        self.set_management_audit_data_version(data_version);
        Ok(verification)
    }

    /// Append one event, prune over-cap rows, and advance the authenticated
    /// anchor in one SQLite transaction.
    pub async fn append_management_audit(
        &self,
        event: &ManagementAuditEventRecord,
        retention: ManagementAuditRetention,
    ) -> Result<u64, ManagementAuditStoreError> {
        let conn = self.conn().lock_owned().await;
        let tx = conn.unchecked_transaction().map_err(PersistError::from)?;
        let data_version = sqlite_data_version(&tx)?;
        let observed_data_version = self.management_audit_data_version();
        let check_external_orphans =
            observed_data_version == 0 || observed_data_version != data_version;
        let Some(mut anchor) = load_append_anchor(&tx, self.audit_key(), check_external_orphans)?
        else {
            return Err(ManagementAuditVerificationError::new(
                ManagementAuditVerificationFailure::MissingAnchor,
                None,
            )
            .into());
        };
        if anchor.retention_max_records != retention.max_records() {
            return Err(PersistError::constraint_violation(
                "management audit retention changed without reconfiguration",
            )
            .into());
        }
        let sequence = anchor.total_count;
        if sequence > i64::MAX as u64 {
            return Err(PersistError::constraint_violation(
                "management audit sequence exhausted its durable range",
            )
            .into());
        }
        let previous_hash = anchor.terminal_hash;
        let entry_hmac = calculate_event_hmac(self.audit_key(), sequence, event, &previous_hash)?;
        insert_event(&tx, sequence, event, &previous_hash, &entry_hmac)?;

        anchor.total_count = anchor.total_count.checked_add(1).ok_or_else(|| {
            PersistError::constraint_violation("management audit count exhausted")
        })?;
        anchor.retained_count = anchor.retained_count.checked_add(1).ok_or_else(|| {
            PersistError::constraint_violation("management audit retained count exhausted")
        })?;
        anchor.terminal_sequence = Some(sequence);
        anchor.terminal_hash = entry_hmac;
        // A configured append adds exactly one row, so fixed retention can
        // prune only the current authenticated low-water row. The successor
        // becomes low-water and must authenticate on the next append before it
        // can ever be pruned. Multi-row pruning is confined to configuration,
        // which performs complete-chain verification first.
        prune_to_retention(&tx, &mut anchor)?;
        anchor.anchor_hmac = anchor.calculate_hmac(self.audit_key())?;
        update_anchor(&tx, &anchor)?;
        tx.commit().map_err(|_| PersistError::outcome_unknown())?;
        self.set_management_audit_data_version(data_version);
        Ok(sequence)
    }

    /// Verify all retained management events against the authenticated
    /// low-water and terminal anchor.
    pub async fn verify_management_audit(
        &self,
    ) -> Result<ManagementAuditVerification, ManagementAuditStoreError> {
        let conn = self.conn().lock_owned().await;
        let tx = conn.unchecked_transaction().map_err(PersistError::from)?;
        let Some((_, verification)) = verify_chain(&tx, self.audit_key())? else {
            return Err(ManagementAuditVerificationError::new(
                ManagementAuditVerificationFailure::MissingAnchor,
                None,
            )
            .into());
        };
        let data_version = sqlite_data_version(&tx)?;
        tx.commit().map_err(PersistError::from)?;
        self.set_management_audit_data_version(data_version);
        Ok(verification)
    }

    /// Return one bounded retained page after authenticating the complete chain.
    ///
    /// The cursor is an absolute sequence. A cursor below the authenticated
    /// low-water mark returns [`ManagementAuditCursorError::Pruned`] instead of
    /// silently skipping retention-pruned records.
    pub async fn query_management_audits_page(
        &self,
        request: ManagementAuditPageRequest,
    ) -> Result<ManagementAuditPage, ManagementAuditStoreError> {
        let conn = self.conn().lock_owned().await;
        let tx = conn.unchecked_transaction().map_err(PersistError::from)?;
        let Some((anchor, verification)) = verify_chain(&tx, self.audit_key())? else {
            return Err(ManagementAuditVerificationError::new(
                ManagementAuditVerificationFailure::MissingAnchor,
                None,
            )
            .into());
        };
        let start_sequence = request
            .start_sequence()
            .unwrap_or(anchor.low_water_sequence);
        if start_sequence < anchor.low_water_sequence {
            return Err(ManagementAuditCursorError::Pruned {
                requested: start_sequence,
                low_water_sequence: anchor.low_water_sequence,
            }
            .into());
        }
        if start_sequence > anchor.total_count {
            return Err(ManagementAuditCursorError::Ahead {
                requested: start_sequence,
                next_append_sequence: anchor.total_count,
            }
            .into());
        }
        let records = load_record_page(&tx, self.audit_key(), start_sequence, request.limit())?;
        let returned = u64::try_from(records.len()).map_err(|_| {
            PersistError::constraint_violation("management audit page count overflow")
        })?;
        let after_page = start_sequence.checked_add(returned).ok_or_else(|| {
            PersistError::constraint_violation("management audit page cursor overflow")
        })?;
        let next_sequence = (after_page < anchor.total_count).then_some(after_page);
        let data_version = sqlite_data_version(&tx)?;
        tx.commit().map_err(PersistError::from)?;
        self.set_management_audit_data_version(data_version);
        Ok(ManagementAuditPage {
            records,
            next_sequence,
            verification,
        })
    }
}

fn calculate_event_hmac(
    audit_key: &AuditKey,
    sequence: u64,
    event: &ManagementAuditEventRecord,
    previous_hash: &[u8; 32],
) -> Result<[u8; 32], PersistError> {
    let mut fields = Vec::with_capacity(12 + event.schema_paths.len());
    fields.extend([
        AuditChainField::U64(MANAGEMENT_AUDIT_FORMAT_VERSION),
        AuditChainField::U64(sequence),
        AuditChainField::Bytes(&event.request_id),
        AuditChainField::Text(&event.tenant),
        AuditChainField::Text(&event.principal),
        AuditChainField::Text(event.transport.as_str()),
        AuditChainField::Text(event.operation.as_str()),
        AuditChainField::Text(event.outcome.as_str()),
        AuditChainField::OptionalText(event.reason.as_deref()),
        AuditChainField::U64(event.schema_paths.len() as u64),
    ]);
    fields.extend(
        event
            .schema_paths
            .iter()
            .map(|path| AuditChainField::Text(path)),
    );
    fields.extend([
        AuditChainField::OptionalText(event.tx_id.as_deref()),
        AuditChainField::Hash(previous_hash),
    ]);
    calculate_audit_chain_hmac(audit_key, AuditChainDomain::ManagementEventV1, &fields)
}

struct RawManagementAuditRow {
    sequence: u64,
    request_id: [u8; 16],
    tenant: String,
    principal: String,
    transport: String,
    operation: String,
    outcome: String,
    reason: Option<String>,
    path_count: usize,
    tx_id: Option<String>,
    previous_hash: [u8; 32],
    entry_hmac: [u8; 32],
}

fn malformed_record(sequence: Option<u64>) -> ManagementAuditStoreError {
    ManagementAuditVerificationError::new(
        ManagementAuditVerificationFailure::MalformedRecord,
        sequence,
    )
    .into()
}

fn malformed_anchor() -> ManagementAuditStoreError {
    ManagementAuditVerificationError::new(ManagementAuditVerificationFailure::MalformedAnchor, None)
        .into()
}

fn read_record_text(
    row: &rusqlite::Row<'_>,
    index: usize,
    maximum_bytes: usize,
    sequence: u64,
) -> Result<String, ManagementAuditStoreError> {
    let bytes = match row.get_ref(index).map_err(PersistError::from)? {
        ValueRef::Text(bytes) if bytes.len() <= maximum_bytes => bytes,
        _ => return Err(malformed_record(Some(sequence))),
    };
    let value = std::str::from_utf8(bytes).map_err(|_| malformed_record(Some(sequence)))?;
    Ok(value.to_owned())
}

fn read_optional_record_text(
    row: &rusqlite::Row<'_>,
    index: usize,
    maximum_bytes: usize,
    sequence: u64,
) -> Result<Option<String>, ManagementAuditStoreError> {
    match row.get_ref(index).map_err(PersistError::from)? {
        ValueRef::Null => Ok(None),
        ValueRef::Text(bytes) if bytes.len() <= maximum_bytes => {
            let value = std::str::from_utf8(bytes).map_err(|_| malformed_record(Some(sequence)))?;
            Ok(Some(value.to_owned()))
        }
        _ => Err(malformed_record(Some(sequence))),
    }
}

fn read_record_blob<const N: usize>(
    row: &rusqlite::Row<'_>,
    index: usize,
    sequence: u64,
) -> Result<[u8; N], ManagementAuditStoreError> {
    match row.get_ref(index).map_err(PersistError::from)? {
        ValueRef::Blob(bytes) if bytes.len() == N => bytes
            .try_into()
            .map_err(|_| malformed_record(Some(sequence))),
        _ => Err(malformed_record(Some(sequence))),
    }
}

fn read_raw_record(
    row: &rusqlite::Row<'_>,
    expected_sequence: u64,
) -> Result<RawManagementAuditRow, ManagementAuditStoreError> {
    let raw_sequence = match row.get_ref(0).map_err(PersistError::from)? {
        ValueRef::Integer(value) => value,
        _ => return Err(malformed_record(Some(expected_sequence))),
    };
    let sequence = u64::try_from(raw_sequence).map_err(|_| {
        ManagementAuditVerificationError::new(
            ManagementAuditVerificationFailure::Sequence,
            Some(expected_sequence),
        )
    })?;
    let raw_path_count = match row.get_ref(8).map_err(PersistError::from)? {
        ValueRef::Integer(value) => value,
        _ => return Err(malformed_record(Some(sequence))),
    };
    let path_count =
        usize::try_from(raw_path_count).map_err(|_| malformed_record(Some(sequence)))?;
    if path_count > MANAGEMENT_AUDIT_MAX_SCHEMA_PATHS {
        return Err(malformed_record(Some(sequence)));
    }

    Ok(RawManagementAuditRow {
        sequence,
        request_id: read_record_blob(row, 1, sequence)?,
        tenant: read_record_text(row, 2, MANAGEMENT_AUDIT_MAX_TENANT_BYTES, sequence)?,
        principal: read_record_text(row, 3, MANAGEMENT_AUDIT_MAX_PRINCIPAL_BYTES, sequence)?,
        transport: read_record_text(row, 4, MANAGEMENT_AUDIT_MAX_STABLE_CODE_BYTES, sequence)?,
        operation: read_record_text(row, 5, MANAGEMENT_AUDIT_MAX_STABLE_CODE_BYTES, sequence)?,
        outcome: read_record_text(row, 6, MANAGEMENT_AUDIT_MAX_STABLE_CODE_BYTES, sequence)?,
        reason: read_optional_record_text(row, 7, MANAGEMENT_AUDIT_MAX_REASON_BYTES, sequence)?,
        path_count,
        tx_id: read_optional_record_text(row, 9, MANAGEMENT_AUDIT_MAX_TX_ID_BYTES, sequence)?,
        previous_hash: read_record_blob(row, 10, sequence)?,
        entry_hmac: read_record_blob(row, 11, sequence)?,
    })
}

fn decode_record(
    conn: &Connection,
    audit_key: &AuditKey,
    raw: RawManagementAuditRow,
) -> Result<StoredManagementAuditRecord, ManagementAuditStoreError> {
    let RawManagementAuditRow {
        sequence,
        request_id,
        tenant,
        principal,
        transport,
        operation,
        outcome,
        reason,
        path_count,
        tx_id,
        previous_hash,
        entry_hmac,
    } = raw;
    let malformed = || {
        ManagementAuditVerificationError::new(
            ManagementAuditVerificationFailure::MalformedRecord,
            Some(sequence),
        )
    };
    let base_variable_bytes = tenant
        .len()
        .checked_add(principal.len())
        .and_then(|total| total.checked_add(reason.as_ref().map_or(0, String::len)))
        .and_then(|total| total.checked_add(tx_id.as_ref().map_or(0, String::len)))
        .ok_or_else(malformed)?;
    let remaining_path_bytes = MANAGEMENT_AUDIT_MAX_EVENT_BYTES
        .checked_sub(base_variable_bytes)
        .ok_or_else(malformed)?;
    let schema_paths = load_paths(conn, sequence, remaining_path_bytes)?;
    if schema_paths.len() != path_count {
        return Err(malformed().into());
    }
    let transport = ManagementAuditTransportCode::parse(&transport).ok_or_else(malformed)?;
    let operation = ManagementAuditOperationCode::parse(&operation).ok_or_else(malformed)?;
    let outcome = ManagementAuditOutcomeCode::parse(&outcome).ok_or_else(malformed)?;
    let event = ManagementAuditEventRecord::try_new(
        request_id,
        tenant,
        principal,
        transport,
        operation,
        outcome,
        reason,
        schema_paths,
        tx_id,
    )
    .map_err(|_| malformed())?;
    let expected_hmac = calculate_event_hmac(audit_key, sequence, &event, &previous_hash)?;
    if entry_hmac != expected_hmac {
        return Err(ManagementAuditVerificationError::new(
            ManagementAuditVerificationFailure::RecordAuthentication,
            Some(sequence),
        )
        .into());
    }
    Ok(StoredManagementAuditRecord {
        sequence,
        event,
        previous_hash,
        entry_hmac,
    })
}

fn sqlite_data_version(conn: &Connection) -> Result<u64, PersistError> {
    let raw = conn
        .query_row("PRAGMA data_version", [], |row| row.get::<_, i64>(0))
        .map_err(PersistError::from)?;
    u64::try_from(raw).map_err(|_| {
        PersistError::constraint_violation("SQLite returned an invalid data-version value")
    })
}

fn first_orphan_path_sequence(conn: &Connection) -> Result<Option<u64>, ManagementAuditStoreError> {
    let mut statement = conn
        .prepare(
            "SELECT paths.event_sequence \
             FROM management_audit_schema_path AS paths \
             LEFT JOIN management_audit_event AS events \
               ON events.sequence = paths.event_sequence \
             WHERE events.sequence IS NULL \
             ORDER BY paths.event_sequence ASC, paths.path_index ASC LIMIT 1",
        )
        .map_err(PersistError::from)?;
    let mut rows = statement.query([]).map_err(PersistError::from)?;
    let Some(row) = rows.next().map_err(PersistError::from)? else {
        return Ok(None);
    };
    match row.get_ref(0).map_err(PersistError::from)? {
        ValueRef::Integer(raw_sequence) => u64::try_from(raw_sequence)
            .map(Some)
            .map_err(|_| malformed_record(None)),
        _ => Err(malformed_record(None)),
    }
}

fn reject_orphan_paths(conn: &Connection) -> Result<(), ManagementAuditStoreError> {
    if let Some(sequence) = first_orphan_path_sequence(conn)? {
        return Err(malformed_record(Some(sequence)));
    }
    Ok(())
}

fn verify_chain(
    conn: &Connection,
    audit_key: &AuditKey,
) -> Result<Option<(AnchorState, ManagementAuditVerification)>, ManagementAuditStoreError> {
    let Some(anchor) = load_anchor(conn)? else {
        let event_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM management_audit_event LIMIT 1)",
                [],
                |row| row.get(0),
            )
            .map_err(PersistError::from)?;
        let path_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM management_audit_schema_path LIMIT 1)",
                [],
                |row| row.get(0),
            )
            .map_err(PersistError::from)?;
        if event_exists || path_exists {
            return Err(ManagementAuditVerificationError::new(
                ManagementAuditVerificationFailure::MissingAnchor,
                None,
            )
            .into());
        }
        return Ok(None);
    };
    anchor.validate(audit_key)?;
    reject_orphan_paths(conn)?;

    let mut statement = conn
        .prepare(
            "SELECT sequence, request_id, tenant, principal, transport, operation, outcome, reason, schema_path_count, tx_id, previous_hash, entry_hmac \
             FROM management_audit_event ORDER BY sequence ASC",
        )
        .map_err(PersistError::from)?;
    let mut rows = statement.query([]).map_err(PersistError::from)?;

    let mut expected_sequence = anchor.low_water_sequence;
    let mut previous_hash = anchor.low_water_hash;
    let mut actual_count = 0_u64;
    while let Some(row) = rows.next().map_err(PersistError::from)? {
        if actual_count >= anchor.retained_count {
            return Err(ManagementAuditVerificationError::new(
                ManagementAuditVerificationFailure::Sequence,
                Some(expected_sequence),
            )
            .into());
        }
        #[cfg(test)]
        note_full_verification_row();
        let record = decode_record(conn, audit_key, read_raw_record(row, expected_sequence)?)?;
        if record.sequence != expected_sequence {
            return Err(ManagementAuditVerificationError::new(
                ManagementAuditVerificationFailure::Sequence,
                Some(expected_sequence),
            )
            .into());
        }
        if record.previous_hash != previous_hash {
            return Err(ManagementAuditVerificationError::new(
                ManagementAuditVerificationFailure::PreviousHash,
                Some(record.sequence),
            )
            .into());
        }
        previous_hash = record.entry_hmac;
        expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
            PersistError::constraint_violation("management audit verification sequence overflow")
        })?;
        actual_count = actual_count.checked_add(1).ok_or_else(|| {
            PersistError::constraint_violation("management audit verification count overflow")
        })?;
    }

    if actual_count != anchor.retained_count {
        return Err(ManagementAuditVerificationError::new(
            ManagementAuditVerificationFailure::Sequence,
            Some(expected_sequence),
        )
        .into());
    }
    if previous_hash != anchor.terminal_hash {
        return Err(ManagementAuditVerificationError::new(
            ManagementAuditVerificationFailure::Terminal,
            anchor.terminal_sequence,
        )
        .into());
    }
    let verification = anchor.verification();
    Ok(Some((anchor, verification)))
}

fn load_append_anchor(
    conn: &Connection,
    audit_key: &AuditKey,
    check_external_orphans: bool,
) -> Result<Option<AnchorState>, ManagementAuditStoreError> {
    let Some(anchor) = load_anchor(conn)? else {
        return Ok(None);
    };
    anchor.validate(audit_key)?;
    // Normal appends remain boundary-only. SQLite's per-connection data
    // version makes externally committed writes observable in O(1), and only
    // that exceptional path pays for a complete orphan-child scan.
    if check_external_orphans {
        reject_orphan_paths(conn)?;
    }

    let first_sequence = boundary_sequence(conn, "ASC", Some(anchor.low_water_sequence))?;
    let last_sequence = boundary_sequence(conn, "DESC", anchor.terminal_sequence)?;
    if anchor.retained_count == 0 {
        let path_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM management_audit_schema_path LIMIT 1)",
                [],
                |row| row.get(0),
            )
            .map_err(PersistError::from)?;
        if first_sequence.is_some() || last_sequence.is_some() || path_exists {
            return Err(ManagementAuditVerificationError::new(
                ManagementAuditVerificationFailure::AnchorInvariant,
                None,
            )
            .into());
        }
        return Ok(Some(anchor));
    }

    let terminal_sequence = anchor.terminal_sequence.ok_or_else(|| {
        ManagementAuditVerificationError::new(
            ManagementAuditVerificationFailure::AnchorInvariant,
            None,
        )
    })?;
    if first_sequence != Some(anchor.low_water_sequence) {
        return Err(ManagementAuditVerificationError::new(
            ManagementAuditVerificationFailure::Sequence,
            Some(anchor.low_water_sequence),
        )
        .into());
    }
    if last_sequence != Some(terminal_sequence) {
        return Err(ManagementAuditVerificationError::new(
            ManagementAuditVerificationFailure::Terminal,
            Some(terminal_sequence),
        )
        .into());
    }

    let low_water =
        load_record_at(conn, audit_key, anchor.low_water_sequence)?.ok_or_else(|| {
            ManagementAuditVerificationError::new(
                ManagementAuditVerificationFailure::Sequence,
                Some(anchor.low_water_sequence),
            )
        })?;
    if low_water.previous_hash != anchor.low_water_hash {
        return Err(ManagementAuditVerificationError::new(
            ManagementAuditVerificationFailure::PreviousHash,
            Some(anchor.low_water_sequence),
        )
        .into());
    }

    let terminal = if terminal_sequence == anchor.low_water_sequence {
        low_water
    } else {
        load_record_at(conn, audit_key, terminal_sequence)?.ok_or_else(|| {
            ManagementAuditVerificationError::new(
                ManagementAuditVerificationFailure::Terminal,
                Some(terminal_sequence),
            )
        })?
    };
    if terminal.entry_hmac != anchor.terminal_hash {
        return Err(ManagementAuditVerificationError::new(
            ManagementAuditVerificationFailure::Terminal,
            Some(terminal_sequence),
        )
        .into());
    }
    Ok(Some(anchor))
}

fn boundary_sequence(
    conn: &Connection,
    direction: &'static str,
    expected_sequence: Option<u64>,
) -> Result<Option<u64>, ManagementAuditStoreError> {
    let sql = match direction {
        "ASC" => "SELECT sequence FROM management_audit_event ORDER BY sequence ASC LIMIT 1",
        "DESC" => "SELECT sequence FROM management_audit_event ORDER BY sequence DESC LIMIT 1",
        _ => {
            return Err(PersistError::constraint_violation(
                "management audit boundary direction is invalid",
            )
            .into());
        }
    };
    let mut statement = conn.prepare(sql).map_err(PersistError::from)?;
    let mut rows = statement.query([]).map_err(PersistError::from)?;
    let Some(row) = rows.next().map_err(PersistError::from)? else {
        return Ok(None);
    };
    let raw = match row.get_ref(0).map_err(PersistError::from)? {
        ValueRef::Integer(value) => value,
        _ => {
            return Err(ManagementAuditVerificationError::new(
                ManagementAuditVerificationFailure::Sequence,
                expected_sequence,
            )
            .into());
        }
    };
    u64::try_from(raw).map(Some).map_err(|_| {
        ManagementAuditVerificationError::new(
            ManagementAuditVerificationFailure::Sequence,
            expected_sequence,
        )
        .into()
    })
}

fn load_record_at(
    conn: &Connection,
    audit_key: &AuditKey,
    sequence: u64,
) -> Result<Option<StoredManagementAuditRecord>, ManagementAuditStoreError> {
    let sqlite_sequence = to_sqlite_integer(sequence)?;
    let mut statement = conn
        .prepare(
            "SELECT sequence, request_id, tenant, principal, transport, operation, outcome, reason, schema_path_count, tx_id, previous_hash, entry_hmac \
             FROM management_audit_event WHERE sequence = ?1",
        )
        .map_err(PersistError::from)?;
    let mut rows = statement
        .query([sqlite_sequence])
        .map_err(PersistError::from)?;
    let Some(row) = rows.next().map_err(PersistError::from)? else {
        return Ok(None);
    };
    decode_record(conn, audit_key, read_raw_record(row, sequence)?).map(Some)
}

fn load_record_page(
    conn: &Connection,
    audit_key: &AuditKey,
    start_sequence: u64,
    limit: u32,
) -> Result<Vec<StoredManagementAuditRecord>, ManagementAuditStoreError> {
    let mut statement = conn
        .prepare(
            "SELECT sequence, request_id, tenant, principal, transport, operation, outcome, reason, schema_path_count, tx_id, previous_hash, entry_hmac \
             FROM management_audit_event WHERE sequence >= ?1 ORDER BY sequence ASC LIMIT ?2",
        )
        .map_err(PersistError::from)?;
    let mut rows = statement
        .query(rusqlite::params![
            to_sqlite_integer(start_sequence)?,
            i64::from(limit)
        ])
        .map_err(PersistError::from)?;
    let capacity = usize::try_from(limit).map_err(|_| {
        PersistError::constraint_violation("management audit page limit conversion failed")
    })?;
    let mut records = Vec::with_capacity(capacity);
    let mut expected_sequence = start_sequence;
    while let Some(row) = rows.next().map_err(PersistError::from)? {
        let record = decode_record(conn, audit_key, read_raw_record(row, expected_sequence)?)?;
        if record.sequence != expected_sequence {
            return Err(ManagementAuditVerificationError::new(
                ManagementAuditVerificationFailure::Sequence,
                Some(expected_sequence),
            )
            .into());
        }
        expected_sequence = expected_sequence.checked_add(1).ok_or_else(|| {
            PersistError::constraint_violation("management audit page sequence overflow")
        })?;
        records.push(record);
    }
    Ok(records)
}

#[cfg(test)]
std::thread_local! {
    static FULL_VERIFICATION_ROWS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_full_verification_row() {
    FULL_VERIFICATION_ROWS.with(|count| count.set(count.get().saturating_add(1)));
}

#[cfg(test)]
fn reset_full_verification_rows() {
    FULL_VERIFICATION_ROWS.with(|count| count.set(0));
}

#[cfg(test)]
fn full_verification_rows() -> u64 {
    FULL_VERIFICATION_ROWS.with(std::cell::Cell::get)
}

fn load_paths(
    conn: &Connection,
    sequence: u64,
    maximum_total_bytes: usize,
) -> Result<Vec<String>, ManagementAuditStoreError> {
    let sqlite_sequence = i64::try_from(sequence).map_err(|_| {
        PersistError::constraint_violation("management audit sequence is outside SQLite range")
    })?;
    let mut statement = conn
        .prepare(
            "SELECT path_index, schema_path FROM management_audit_schema_path \
             WHERE event_sequence = ?1 ORDER BY path_index ASC",
        )
        .map_err(PersistError::from)?;
    let mut rows = statement
        .query([sqlite_sequence])
        .map_err(PersistError::from)?;
    let mut paths = Vec::new();
    let mut total_bytes = 0_usize;
    while let Some(row) = rows.next().map_err(PersistError::from)? {
        if paths.len() >= MANAGEMENT_AUDIT_MAX_SCHEMA_PATHS {
            return Err(malformed_record(Some(sequence)));
        }
        let raw_index = match row.get_ref(0).map_err(PersistError::from)? {
            ValueRef::Integer(value) => value,
            _ => return Err(malformed_record(Some(sequence))),
        };
        let expected_index = i64::try_from(paths.len()).map_err(|_| {
            PersistError::constraint_violation("management audit path count overflow")
        })?;
        if raw_index != expected_index {
            return Err(malformed_record(Some(sequence)));
        }
        let bytes = match row.get_ref(1).map_err(PersistError::from)? {
            ValueRef::Text(bytes) if bytes.len() <= MANAGEMENT_AUDIT_MAX_SCHEMA_PATH_BYTES => bytes,
            _ => return Err(malformed_record(Some(sequence))),
        };
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= maximum_total_bytes)
            .ok_or_else(|| malformed_record(Some(sequence)))?;
        let path = std::str::from_utf8(bytes)
            .map_err(|_| malformed_record(Some(sequence)))?
            .to_owned();
        paths.push(path);
    }
    Ok(paths)
}

fn read_anchor_integer(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> Result<u64, ManagementAuditStoreError> {
    match row.get_ref(index).map_err(PersistError::from)? {
        ValueRef::Integer(value) => u64::try_from(value).map_err(|_| malformed_anchor()),
        _ => Err(malformed_anchor()),
    }
}

fn read_optional_anchor_integer(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> Result<Option<u64>, ManagementAuditStoreError> {
    match row.get_ref(index).map_err(PersistError::from)? {
        ValueRef::Null => Ok(None),
        ValueRef::Integer(value) => u64::try_from(value)
            .map(Some)
            .map_err(|_| malformed_anchor()),
        _ => Err(malformed_anchor()),
    }
}

fn read_anchor_blob<const N: usize>(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> Result<[u8; N], ManagementAuditStoreError> {
    match row.get_ref(index).map_err(PersistError::from)? {
        ValueRef::Blob(bytes) if bytes.len() == N => {
            bytes.try_into().map_err(|_| malformed_anchor())
        }
        _ => Err(malformed_anchor()),
    }
}

fn load_anchor(conn: &Connection) -> Result<Option<AnchorState>, ManagementAuditStoreError> {
    let mut statement = conn
        .prepare(
            "SELECT format_version, retention_max_records, key_epoch, total_count, retained_count, low_water_sequence, low_water_hash, terminal_sequence, terminal_hash, anchor_hmac \
             FROM management_audit_anchor WHERE id = 1",
        )
        .map_err(PersistError::from)?;
    let mut rows = statement.query([]).map_err(PersistError::from)?;
    let Some(row) = rows.next().map_err(PersistError::from)? else {
        return Ok(None);
    };
    if read_anchor_integer(row, 0)? != MANAGEMENT_AUDIT_FORMAT_VERSION {
        return Err(malformed_anchor());
    }
    Ok(Some(AnchorState {
        retention_max_records: read_anchor_integer(row, 1)?,
        key_epoch: read_anchor_integer(row, 2)?,
        total_count: read_anchor_integer(row, 3)?,
        retained_count: read_anchor_integer(row, 4)?,
        low_water_sequence: read_anchor_integer(row, 5)?,
        low_water_hash: read_anchor_blob(row, 6)?,
        terminal_sequence: read_optional_anchor_integer(row, 7)?,
        terminal_hash: read_anchor_blob(row, 8)?,
        anchor_hmac: read_anchor_blob(row, 9)?,
    }))
}

fn insert_event(
    conn: &Connection,
    sequence: u64,
    event: &ManagementAuditEventRecord,
    previous_hash: &[u8; 32],
    entry_hmac: &[u8; 32],
) -> Result<(), PersistError> {
    let sequence = i64::try_from(sequence).map_err(|_| {
        PersistError::constraint_violation("management audit sequence is outside SQLite range")
    })?;
    let path_count = i64::try_from(event.schema_paths.len()).map_err(|_| {
        PersistError::constraint_violation("management audit path count is outside SQLite range")
    })?;
    conn.execute(
        "INSERT INTO management_audit_event \
         (sequence, request_id, tenant, principal, transport, operation, outcome, reason, schema_path_count, tx_id, previous_hash, entry_hmac) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        rusqlite::params![
            sequence,
            &event.request_id[..],
            &event.tenant,
            &event.principal,
            event.transport.as_str(),
            event.operation.as_str(),
            event.outcome.as_str(),
            event.reason.as_deref(),
            path_count,
            event.tx_id.as_deref(),
            &previous_hash[..],
            &entry_hmac[..],
        ],
    )
    .map_err(PersistError::from)?;
    for (index, path) in event.schema_paths.iter().enumerate() {
        let index = i64::try_from(index).map_err(|_| {
            PersistError::constraint_violation(
                "management audit path index is outside SQLite range",
            )
        })?;
        conn.execute(
            "INSERT INTO management_audit_schema_path (event_sequence, path_index, schema_path) \
             VALUES (?1, ?2, ?3)",
            rusqlite::params![sequence, index, path],
        )
        .map_err(PersistError::from)?;
    }
    Ok(())
}

fn prune_to_retention(conn: &Connection, anchor: &mut AnchorState) -> Result<(), PersistError> {
    if anchor.retained_count <= anchor.retention_max_records {
        return Ok(());
    }
    let prune_count = anchor.retained_count - anchor.retention_max_records;
    let offset = i64::try_from(prune_count - 1).map_err(|_| {
        PersistError::constraint_violation("management audit prune offset is outside SQLite range")
    })?;
    let (raw_sequence, raw_entry_hmac): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT sequence, entry_hmac FROM management_audit_event \
             ORDER BY sequence ASC LIMIT 1 OFFSET ?1",
            [offset],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(PersistError::from)?;
    let last_pruned_sequence = u64::try_from(raw_sequence).map_err(|_| {
        PersistError::constraint_violation("management audit prune sequence is malformed")
    })?;
    let expected_last_pruned = anchor
        .low_water_sequence
        .checked_add(prune_count - 1)
        .ok_or_else(|| PersistError::constraint_violation("management audit prune overflow"))?;
    if last_pruned_sequence != expected_last_pruned {
        return Err(PersistError::audit_chain_broken());
    }
    let last_pruned_hash =
        fixed_bytes::<32>(&raw_entry_hmac).ok_or_else(PersistError::audit_chain_broken)?;
    let new_low_water = last_pruned_sequence
        .checked_add(1)
        .ok_or_else(|| PersistError::constraint_violation("management audit prune overflow"))?;
    let changed = conn
        .execute(
            "DELETE FROM management_audit_event WHERE sequence < ?1",
            [i64::try_from(new_low_water).map_err(|_| {
                PersistError::constraint_violation(
                    "management audit low-water sequence is outside SQLite range",
                )
            })?],
        )
        .map_err(PersistError::from)?;
    if u64::try_from(changed).ok() != Some(prune_count) {
        return Err(PersistError::audit_chain_broken());
    }
    anchor.low_water_sequence = new_low_water;
    anchor.low_water_hash = last_pruned_hash;
    anchor.retained_count -= prune_count;
    Ok(())
}

fn insert_anchor(conn: &Connection, anchor: &AnchorState) -> Result<(), PersistError> {
    let changed = conn
        .execute(
            "INSERT INTO management_audit_anchor \
             (id, format_version, retention_max_records, key_epoch, total_count, retained_count, low_water_sequence, low_water_hash, terminal_sequence, terminal_hash, anchor_hmac) \
             VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            anchor_params(anchor)?,
        )
        .map_err(PersistError::from)?;
    if changed != 1 {
        return Err(PersistError::constraint_violation(
            "management audit anchor insert cardinality violated",
        ));
    }
    Ok(())
}

fn update_anchor(conn: &Connection, anchor: &AnchorState) -> Result<(), PersistError> {
    let params = anchor_params(anchor)?;
    let changed = conn
        .execute(
            "UPDATE management_audit_anchor SET \
             format_version = ?1, retention_max_records = ?2, key_epoch = ?3, total_count = ?4, retained_count = ?5, low_water_sequence = ?6, low_water_hash = ?7, terminal_sequence = ?8, terminal_hash = ?9, anchor_hmac = ?10 \
             WHERE id = 1",
            params,
        )
        .map_err(PersistError::from)?;
    if changed != 1 {
        return Err(PersistError::audit_chain_broken());
    }
    Ok(())
}

fn anchor_params(
    anchor: &AnchorState,
) -> Result<rusqlite::ParamsFromIter<Vec<rusqlite::types::Value>>, PersistError> {
    let values = vec![
        rusqlite::types::Value::Integer(MANAGEMENT_AUDIT_FORMAT_VERSION as i64),
        rusqlite::types::Value::Integer(to_sqlite_integer(anchor.retention_max_records)?),
        rusqlite::types::Value::Integer(to_sqlite_integer(anchor.key_epoch)?),
        rusqlite::types::Value::Integer(to_sqlite_integer(anchor.total_count)?),
        rusqlite::types::Value::Integer(to_sqlite_integer(anchor.retained_count)?),
        rusqlite::types::Value::Integer(to_sqlite_integer(anchor.low_water_sequence)?),
        rusqlite::types::Value::Blob(anchor.low_water_hash.to_vec()),
        match anchor.terminal_sequence {
            Some(sequence) => rusqlite::types::Value::Integer(to_sqlite_integer(sequence)?),
            None => rusqlite::types::Value::Null,
        },
        rusqlite::types::Value::Blob(anchor.terminal_hash.to_vec()),
        rusqlite::types::Value::Blob(anchor.anchor_hmac.to_vec()),
    ];
    Ok(rusqlite::params_from_iter(values))
}

fn to_sqlite_integer(value: u64) -> Result<i64, PersistError> {
    i64::try_from(value).map_err(|_| {
        PersistError::constraint_violation("management audit value is outside SQLite range")
    })
}

fn fixed_bytes<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    bytes.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(request_id: u8) -> ManagementAuditEventRecord {
        ManagementAuditEventRecord::try_new(
            [request_id; 16],
            "tenant-a",
            "operator-a",
            ManagementAuditTransportCode::Gnmi,
            ManagementAuditOperationCode::Read,
            ManagementAuditOutcomeCode::Success,
            None::<String>,
            ["/ietf-system:system"],
            Some(format!("tx-{request_id}")),
        )
        .expect("valid management audit event")
    }

    #[test]
    fn record_constructor_rejects_payload_shaped_fields() {
        let result = ManagementAuditEventRecord::try_new(
            [1; 16],
            "tenant-a",
            "operator",
            ManagementAuditTransportCode::Gnmi,
            ManagementAuditOperationCode::Read,
            ManagementAuditOutcomeCode::Failed,
            Some("backend said SELECT secret FROM table"),
            ["/ietf-system:system"],
            None::<String>,
        );
        assert_eq!(result, Err(ManagementAuditRecordError::MachineCode));

        let path_result = ManagementAuditEventRecord::try_new(
            [1; 16],
            "tenant-a",
            "operator",
            ManagementAuditTransportCode::Gnmi,
            ManagementAuditOperationCode::Read,
            ManagementAuditOutcomeCode::Success,
            None::<String>,
            ["/ietf-interfaces:interfaces/interface[name='subscriber-secret']"],
            None::<String>,
        );
        assert_eq!(path_result, Err(ManagementAuditRecordError::SchemaPath));
    }

    #[test]
    fn record_constructor_stops_an_unbounded_path_iterator_at_the_fixed_cap() {
        let result = ManagementAuditEventRecord::try_new(
            [1; 16],
            "tenant-a",
            "operator",
            ManagementAuditTransportCode::Gnmi,
            ManagementAuditOperationCode::Read,
            ManagementAuditOutcomeCode::Success,
            None::<String>,
            std::iter::repeat("/ietf-system:system"),
            None::<String>,
        );
        assert_eq!(result, Err(ManagementAuditRecordError::TooManyPaths));
    }

    #[test]
    fn anchor_authentication_binds_retention_and_watermarks() {
        let key = AuditKey::new([0x44; 32]).expect("audit key");
        let retention = ManagementAuditRetention::try_new(8).expect("retention");
        let anchor = AnchorState::fresh(retention, &key).expect("anchor");
        assert!(anchor.validate(&key).is_ok());

        let mut tampered = anchor.clone();
        tampered.retention_max_records = 7;
        assert_eq!(
            tampered.validate(&key),
            Err(ManagementAuditVerificationError::new(
                ManagementAuditVerificationFailure::AnchorAuthentication,
                None,
            ))
        );
    }

    #[test]
    fn page_request_enforces_the_fixed_bound() {
        assert_eq!(
            ManagementAuditPageRequest::try_new(None, 0),
            Err(ManagementAuditPageRequestError::InvalidLimit)
        );
        assert_eq!(
            ManagementAuditPageRequest::try_new(None, MANAGEMENT_AUDIT_MAX_PAGE_RECORDS + 1),
            Err(ManagementAuditPageRequestError::InvalidLimit)
        );
        assert!(
            ManagementAuditPageRequest::try_new(Some(9), MANAGEMENT_AUDIT_MAX_PAGE_RECORDS).is_ok()
        );
    }

    #[test]
    fn store_error_debug_redacts_persistence_detail() {
        let canary = "customer-secret-path-canary";
        let error = ManagementAuditStoreError::Persistence(PersistError::sqlite(format!(
            "/var/lib/{canary}/management.db"
        )));
        let rendered = format!("{error:?}");
        assert!(!rendered.contains(canary));
        assert!(!rendered.contains("/var/lib"));
        assert!(rendered.contains("Persistence"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn append_checks_only_authenticated_boundaries_and_pages_are_bounded() {
        let backend = SqliteBackend::in_memory_for_test()
            .await
            .expect("in-memory backend");
        let retention = ManagementAuditRetention::try_new(2).expect("retention");
        backend
            .configure_management_audit(retention)
            .await
            .expect("configure");

        reset_full_verification_rows();
        for request_id in 1..=3 {
            backend
                .append_management_audit(&event(request_id), retention)
                .await
                .expect("append");
        }
        assert_eq!(
            full_verification_rows(),
            0,
            "append must not rescan retained history"
        );

        let verification = backend
            .verify_management_audit()
            .await
            .expect("verify retained trail");
        assert_eq!(verification.total_count, 3);
        assert_eq!(verification.retained_count, 2);
        assert_eq!(verification.low_water_sequence, 1);
        assert_eq!(verification.terminal_sequence, Some(2));
        assert_eq!(full_verification_rows(), 2);

        let first_page = backend
            .query_management_audits_page(
                ManagementAuditPageRequest::try_new(None, 1).expect("page request"),
            )
            .await
            .expect("first page");
        assert_eq!(first_page.records().len(), 1);
        assert_eq!(first_page.records()[0].sequence(), 1);
        assert_eq!(first_page.next_sequence(), Some(2));

        let second_page = backend
            .query_management_audits_page(
                ManagementAuditPageRequest::try_new(first_page.next_sequence(), 1)
                    .expect("page request"),
            )
            .await
            .expect("second page");
        assert_eq!(second_page.records().len(), 1);
        assert_eq!(second_page.records()[0].sequence(), 2);
        assert_eq!(second_page.next_sequence(), None);

        let pruned = backend
            .query_management_audits_page(
                ManagementAuditPageRequest::try_new(Some(0), 1).expect("page request"),
            )
            .await;
        assert!(matches!(
            pruned,
            Err(ManagementAuditStoreError::Cursor(
                ManagementAuditCursorError::Pruned {
                    requested: 0,
                    low_water_sequence: 1
                }
            ))
        ));
    }
}
