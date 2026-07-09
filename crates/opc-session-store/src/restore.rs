//! Restore evidence vocabulary for stateful packet-core CNFs.
//!
//! The helpers in this module summarize durable session-store record headers
//! and restore gates without decoding product payloads or making any packet
//! forwarding claim.

use std::collections::BTreeMap;

use opc_redaction::{redact_text, RedactionSummary};
use opc_types::{NetworkFunctionKind, TenantId};
use serde::{Deserialize, Serialize};

use crate::{
    hex::encode_lower, OwnerId, SessionKeyType, StateClass, StateType, StoreError,
    StoredSessionRecord,
};

/// Default maximum restore scan page size.
pub const RESTORE_SCAN_DEFAULT_PAGE_SIZE: usize = 256;

/// Hard maximum restore scan page size.
pub const RESTORE_SCAN_MAX_PAGE_SIZE: usize = 1024;

/// Opaque cursor for paged restore scans.
///
/// The current SDK cursor is an offset into the backend's deterministic live
/// record ordering. It intentionally carries no session key bytes or product
/// payload identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RestoreScanCursor {
    offset: usize,
}

impl RestoreScanCursor {
    /// Build a cursor from a backend-supplied offset.
    pub const fn from_offset(offset: usize) -> Self {
        Self { offset }
    }

    /// Return the offset represented by this cursor.
    pub const fn offset(self) -> usize {
        self.offset
    }
}

/// Typed scope for backend-neutral restore scans.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RestoreScanScope {
    /// Optional tenant filter.
    pub tenant: Option<TenantId>,
    /// Optional network-function kind filter.
    pub nf_kind: Option<NetworkFunctionKind>,
    /// Optional session-key type filter.
    pub key_type: Option<SessionKeyType>,
    /// Optional state-class filter.
    pub state_class: Option<StateClass>,
    /// Optional state-type filter.
    pub state_type: Option<StateType>,
    /// Optional record-owner filter.
    pub owner: Option<OwnerId>,
}

impl RestoreScanScope {
    /// Scope that matches every live record.
    pub fn all() -> Self {
        Self::default()
    }

    /// Whether this scope includes `record`.
    pub fn matches_record(&self, record: &StoredSessionRecord) -> bool {
        self.tenant
            .as_ref()
            .is_none_or(|tenant| tenant == &record.key.tenant)
            && self
                .nf_kind
                .as_ref()
                .is_none_or(|nf_kind| nf_kind == &record.key.nf_kind)
            && self
                .key_type
                .as_ref()
                .is_none_or(|key_type| key_type == &record.key.key_type)
            && self
                .state_class
                .is_none_or(|state_class| state_class == record.state_class)
            && self
                .state_type
                .as_ref()
                .is_none_or(|state_type| state_type == &record.state_type)
            && self
                .owner
                .as_ref()
                .is_none_or(|owner| owner == &record.owner)
    }
}

/// Restore scan request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreScanRequest {
    /// Scope to scan.
    pub scope: RestoreScanScope,
    /// Cursor returned by a previous page, or `None` for the first page.
    pub cursor: Option<RestoreScanCursor>,
    /// Maximum records to return in this page.
    pub limit: usize,
}

impl RestoreScanRequest {
    /// Build a first-page request for all live records.
    pub const fn all(limit: usize) -> Self {
        Self {
            scope: RestoreScanScope {
                tenant: None,
                nf_kind: None,
                key_type: None,
                state_class: None,
                state_type: None,
                owner: None,
            },
            cursor: None,
            limit,
        }
    }

    /// Validate page-size bounds.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.limit == 0 {
            return Err(StoreError::InvalidRestoreScanRequest(
                "restore scan limit must be greater than zero".to_string(),
            ));
        }
        if self.limit > RESTORE_SCAN_MAX_PAGE_SIZE {
            return Err(StoreError::RestoreScanPageTooLarge {
                requested: self.limit,
                max: RESTORE_SCAN_MAX_PAGE_SIZE,
            });
        }
        Ok(())
    }
}

impl Default for RestoreScanRequest {
    fn default() -> Self {
        Self::all(RESTORE_SCAN_DEFAULT_PAGE_SIZE)
    }
}

/// One page of a backend restore scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreScanPage {
    /// Live records returned in this page.
    pub records: Vec<StoredSessionRecord>,
    /// Number of records returned in this page.
    pub loaded_count: usize,
    /// Live records excluded by the supplied scope while building this page.
    pub excluded_count: usize,
    /// Cursor for the next page, or `None` when the scan is complete.
    pub next_cursor: Option<RestoreScanCursor>,
    /// Whether this page completed the scan.
    pub complete: bool,
}

impl RestoreScanPage {
    /// Build a page from records and pagination metadata.
    pub fn new(
        records: Vec<StoredSessionRecord>,
        excluded_count: usize,
        next_cursor: Option<RestoreScanCursor>,
    ) -> Self {
        let loaded_count = records.len();
        Self {
            records,
            loaded_count,
            excluded_count,
            next_cursor,
            complete: next_cursor.is_none(),
        }
    }

    /// Header-only restore summary for this page.
    pub fn record_summary(&self) -> RestoreRecordSummary {
        RestoreRecordSummary::from_records(&self.records, self.excluded_count)
    }
}

/// Deterministic ordering shared by restore-scan backends.
pub(crate) fn compare_restore_records(
    left: &StoredSessionRecord,
    right: &StoredSessionRecord,
) -> std::cmp::Ordering {
    left.key
        .tenant
        .as_str()
        .cmp(right.key.tenant.as_str())
        .then_with(|| left.key.nf_kind.as_str().cmp(right.key.nf_kind.as_str()))
        .then_with(|| left.key.key_type.cmp(&right.key.key_type))
        .then_with(|| {
            left.key
                .stable_id
                .as_ref()
                .cmp(right.key.stable_id.as_ref())
        })
        .then_with(|| left.state_class.cmp(&right.state_class))
        .then_with(|| left.state_type.cmp(&right.state_type))
        .then_with(|| left.owner.cmp(&right.owner))
        .then_with(|| left.generation.cmp(&right.generation))
}

/// Generic restore progress stage for startup and failover evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreStage {
    /// Connection to the session-store substrate.
    SessionStoreConnect,
    /// Ownership or lease validation before restore can proceed.
    Ownership,
    /// Durable record enumeration and load.
    RecordLoad,
    /// Generation and fence validation for loaded records.
    GenerationFenceValidation,
    /// Dataplane reinstall or replay of restored state.
    DataplaneReinstall,
    /// Peer health or degraded-mode classification.
    PeerDegradedClassification,
}

/// Machine-readable restore block reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreBlockReasonCode {
    /// The session store could not be reached or authenticated.
    SessionStoreUnavailable,
    /// Current ownership could not be proven.
    OwnershipConflict,
    /// A stale owner/fence was rejected during restore.
    StaleOwnerRejected,
    /// Record enumeration or header load failed.
    RecordLoadFailed,
    /// A loaded record failed generation or fence validation.
    GenerationFenceInvalid,
    /// Dataplane reinstall has not completed yet.
    DataplaneReinstallPending,
    /// Dataplane reinstall failed and traffic must stay blocked.
    DataplaneReinstallFailed,
    /// A peer is degraded and restore must not claim full readiness.
    PeerDegraded,
}

/// Redaction-safe reason a restore workflow is blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreBlockReason {
    /// Restore stage that produced the block.
    pub stage: RestoreStage,
    /// Machine-readable reason code.
    pub code: RestoreBlockReasonCode,
    /// Redaction-safe operator/evidence message.
    pub message: String,
    /// Whether this block prevents traffic readiness claims.
    pub traffic_blocking: bool,
}

impl RestoreBlockReason {
    /// Build a restore block reason and redact message text for evidence.
    pub fn new(
        stage: RestoreStage,
        code: RestoreBlockReasonCode,
        message: impl AsRef<str>,
        traffic_blocking: bool,
    ) -> Self {
        Self {
            stage,
            code,
            message: redact_restore_message(message.as_ref()),
            traffic_blocking,
        }
    }

    /// Session-store connection block.
    pub fn session_store_connect(message: impl AsRef<str>) -> Self {
        Self::new(
            RestoreStage::SessionStoreConnect,
            RestoreBlockReasonCode::SessionStoreUnavailable,
            message,
            true,
        )
    }

    /// Ownership conflict block.
    pub fn ownership_conflict(message: impl AsRef<str>) -> Self {
        Self::new(
            RestoreStage::Ownership,
            RestoreBlockReasonCode::OwnershipConflict,
            message,
            true,
        )
    }

    /// Stale owner/fence rejection block.
    pub fn stale_owner_rejected(message: impl AsRef<str>) -> Self {
        Self::new(
            RestoreStage::Ownership,
            RestoreBlockReasonCode::StaleOwnerRejected,
            message,
            true,
        )
    }

    /// Record-load block.
    pub fn record_load(message: impl AsRef<str>) -> Self {
        Self::new(
            RestoreStage::RecordLoad,
            RestoreBlockReasonCode::RecordLoadFailed,
            message,
            true,
        )
    }

    /// Generation/fence validation block.
    pub fn generation_fence_validation(message: impl AsRef<str>) -> Self {
        Self::new(
            RestoreStage::GenerationFenceValidation,
            RestoreBlockReasonCode::GenerationFenceInvalid,
            message,
            true,
        )
    }

    /// Dataplane reinstall pending block.
    pub fn dataplane_reinstall_pending(message: impl AsRef<str>) -> Self {
        Self::new(
            RestoreStage::DataplaneReinstall,
            RestoreBlockReasonCode::DataplaneReinstallPending,
            message,
            true,
        )
    }

    /// Dataplane reinstall failure block.
    pub fn dataplane_reinstall_failed(message: impl AsRef<str>) -> Self {
        Self::new(
            RestoreStage::DataplaneReinstall,
            RestoreBlockReasonCode::DataplaneReinstallFailed,
            message,
            true,
        )
    }

    /// Peer degraded classification block.
    pub fn peer_degraded(message: impl AsRef<str>, traffic_blocking: bool) -> Self {
        Self::new(
            RestoreStage::PeerDegradedClassification,
            RestoreBlockReasonCode::PeerDegraded,
            message,
            traffic_blocking,
        )
    }

    /// Whether this reason prevents traffic readiness claims.
    pub const fn blocks_traffic(&self) -> bool {
        self.traffic_blocking
    }
}

/// Header-only summary of a stored session record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRecordHeaderSummary {
    /// SHA-256 digest of the composite session key.
    pub key_digest: String,
    /// Tenant identifier from the key.
    pub tenant: String,
    /// Network-function kind from the key.
    pub nf_kind: String,
    /// Session key type from the key.
    pub key_type: String,
    /// Record state class.
    pub state_class: StateClass,
    /// Record state type.
    pub state_type: String,
    /// Record generation.
    pub generation: u64,
    /// Record fence.
    pub fence: u64,
    /// Owner recorded on the stored header.
    pub owner: String,
    /// Whether the record has an expiry deadline.
    pub expires: bool,
    /// Whether this record is an authoritative session record.
    pub authoritative: bool,
}

impl StoredRecordHeaderSummary {
    /// Build a redaction-safe header summary from a stored record.
    pub fn from_record(record: &StoredSessionRecord) -> Self {
        Self {
            key_digest: encode_lower(&record.key.digest()),
            tenant: record.key.tenant.to_string(),
            nf_kind: record.key.nf_kind.to_string(),
            key_type: record.key.key_type.to_string(),
            state_class: record.state_class,
            state_type: record.state_type.to_string(),
            generation: record.generation.get(),
            fence: record.fence.get(),
            owner: record.owner.to_string(),
            expires: record.expires_at.is_some(),
            authoritative: record.state_class == StateClass::AuthoritativeSession,
        }
    }
}

/// Owner/fence aggregation for restore evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerFenceMetadata {
    /// Owner represented by this aggregate.
    pub owner: String,
    /// Number of loaded records for this owner.
    pub record_count: usize,
    /// Number of authoritative records for this owner.
    pub authoritative_count: usize,
    /// Highest generation observed for this owner.
    pub highest_generation: u64,
    /// Highest fence observed for this owner.
    pub highest_fence: u64,
}

/// Summary of record headers loaded during restore.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreRecordSummary {
    /// Number of records loaded from the session store.
    pub loaded_count: usize,
    /// Number of loaded authoritative records.
    pub authoritative_count: usize,
    /// Number of records excluded by caller restore policy.
    pub excluded_count: usize,
    /// Highest generation observed across loaded records.
    pub highest_generation: Option<u64>,
    /// Highest fence observed across loaded records.
    pub highest_fence: Option<u64>,
    /// Per-owner generation/fence metadata.
    pub owner_fence_metadata: Vec<OwnerFenceMetadata>,
    /// Redaction-safe stored-record header summaries.
    pub headers: Vec<StoredRecordHeaderSummary>,
}

impl RestoreRecordSummary {
    /// Build a restore summary from already loaded stored records.
    pub fn from_records(records: &[StoredSessionRecord], excluded_count: usize) -> Self {
        summarize_restore_records(records, excluded_count)
    }
}

/// Summarize loaded stored-record headers for restore evidence.
pub fn summarize_restore_records(
    records: &[StoredSessionRecord],
    excluded_count: usize,
) -> RestoreRecordSummary {
    let mut headers = records
        .iter()
        .map(StoredRecordHeaderSummary::from_record)
        .collect::<Vec<_>>();
    headers.sort_by(|left, right| {
        left.owner
            .cmp(&right.owner)
            .then_with(|| left.key_digest.cmp(&right.key_digest))
            .then_with(|| left.state_type.cmp(&right.state_type))
    });

    let loaded_count = headers.len();
    let authoritative_count = headers.iter().filter(|header| header.authoritative).count();
    let highest_generation = headers.iter().map(|header| header.generation).max();
    let highest_fence = headers.iter().map(|header| header.fence).max();

    let mut owner_map = BTreeMap::<String, OwnerFenceMetadata>::new();
    for header in &headers {
        let metadata =
            owner_map
                .entry(header.owner.clone())
                .or_insert_with(|| OwnerFenceMetadata {
                    owner: header.owner.clone(),
                    record_count: 0,
                    authoritative_count: 0,
                    highest_generation: 0,
                    highest_fence: 0,
                });
        metadata.record_count += 1;
        if header.authoritative {
            metadata.authoritative_count += 1;
        }
        metadata.highest_generation = metadata.highest_generation.max(header.generation);
        metadata.highest_fence = metadata.highest_fence.max(header.fence);
    }

    RestoreRecordSummary {
        loaded_count,
        authoritative_count,
        excluded_count,
        highest_generation,
        highest_fence,
        owner_fence_metadata: owner_map.into_values().collect(),
        headers,
    }
}

fn redact_restore_message(message: &str) -> String {
    let mut summary = RedactionSummary::default();
    redact_text(message, &mut summary)
}
