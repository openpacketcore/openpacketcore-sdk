use std::{fmt, marker::PhantomData, time::Duration};

use opc_session_store::backend::{
    CompareAndSet, CompareAndSetResult, ReplicationEntry, ReplicationOp, SessionOp,
    SessionOpResult, MAX_REPLICATION_OPERATIONS_PER_ENTRY, MAX_REPLICATION_OPERATION_DEPTH,
};
use opc_session_store::capability::BackendCapabilities;
use opc_session_store::error::{LeaseError, StoreError};
use opc_session_store::lease::LeaseGuard;
use opc_session_store::model::{
    FenceToken, Generation, OwnerId, SessionKey, OWNER_ID_MAX_BYTES, SESSION_KEY_TYPE_MAX_BYTES,
    STATE_TYPE_MAX_BYTES,
};
use opc_session_store::record::StoredSessionRecord;
use opc_session_store::{
    RestoreScanCursor, RestoreScanPage, RestoreScanRequest, RestoreScanScope, MAX_SESSION_TTL,
    RESTORE_SCAN_MAX_PAGE_SIZE,
};
use opc_types::Timestamp;
use serde::de::{IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::ProtocolError;

pub const CONTRACT_VERSION: u32 = 4;
pub const DEFAULT_MAX_FRAME_SIZE: usize = 1024 * 1024;
pub const MAX_HANDSHAKE_FRAME_SIZE: usize = 8 * 1024;
pub const MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE: usize = 512;
pub const MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES: usize = 65_536;
pub const MAX_SESSION_NET_BATCH_OPERATIONS: usize = 256;
pub const MAX_SESSION_NET_REBUILD_ENTRIES: usize = 65_536;
pub const SESSION_NET_ALPN: &[u8] = b"opc-session-net/4";

const WIRE_SCHEMA_REVISION: u16 = 1;
const ERROR_SET_REVISION: u16 = 1;

/// Exact semantic and resource-bound contract required by protocol v4.
///
/// Peers compare this structure for equality during the frozen bootstrap
/// exchange. There is no subset negotiation: a mismatch fails before any
/// operation frame is accepted.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContractProfile {
    pub wire_schema_revision: u16,
    pub error_set_revision: u16,
    pub max_restore_scan_page_records: u32,
    pub max_replication_log_page_entries: u32,
    pub max_batch_operations: u32,
    pub max_rebuild_entries: u32,
    pub max_replication_operation_depth: u16,
    pub max_replication_operations_per_entry: u32,
    pub max_session_ttl_seconds: u64,
    pub owner_id_max_bytes: u16,
    pub session_key_type_max_bytes: u16,
    pub state_type_max_bytes: u16,
}

impl ContractProfile {
    /// Return the one exact profile implemented by this SDK build.
    pub const fn current() -> Self {
        CURRENT_CONTRACT_PROFILE
    }

    /// Whether this value is the exact profile implemented by this SDK build.
    pub const fn is_current(self) -> bool {
        self.wire_schema_revision == CURRENT_CONTRACT_PROFILE.wire_schema_revision
            && self.error_set_revision == CURRENT_CONTRACT_PROFILE.error_set_revision
            && self.max_restore_scan_page_records
                == CURRENT_CONTRACT_PROFILE.max_restore_scan_page_records
            && self.max_replication_log_page_entries
                == CURRENT_CONTRACT_PROFILE.max_replication_log_page_entries
            && self.max_batch_operations == CURRENT_CONTRACT_PROFILE.max_batch_operations
            && self.max_rebuild_entries == CURRENT_CONTRACT_PROFILE.max_rebuild_entries
            && self.max_replication_operation_depth
                == CURRENT_CONTRACT_PROFILE.max_replication_operation_depth
            && self.max_replication_operations_per_entry
                == CURRENT_CONTRACT_PROFILE.max_replication_operations_per_entry
            && self.max_session_ttl_seconds == CURRENT_CONTRACT_PROFILE.max_session_ttl_seconds
            && self.owner_id_max_bytes == CURRENT_CONTRACT_PROFILE.owner_id_max_bytes
            && self.session_key_type_max_bytes
                == CURRENT_CONTRACT_PROFILE.session_key_type_max_bytes
            && self.state_type_max_bytes == CURRENT_CONTRACT_PROFILE.state_type_max_bytes
    }
}

pub const CURRENT_CONTRACT_PROFILE: ContractProfile = ContractProfile {
    wire_schema_revision: WIRE_SCHEMA_REVISION,
    error_set_revision: ERROR_SET_REVISION,
    max_restore_scan_page_records: RESTORE_SCAN_MAX_PAGE_SIZE as u32,
    max_replication_log_page_entries: MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES as u32,
    max_batch_operations: MAX_SESSION_NET_BATCH_OPERATIONS as u32,
    max_rebuild_entries: MAX_SESSION_NET_REBUILD_ENTRIES as u32,
    max_replication_operation_depth: MAX_REPLICATION_OPERATION_DEPTH as u16,
    max_replication_operations_per_entry: MAX_REPLICATION_OPERATIONS_PER_ENTRY as u32,
    max_session_ttl_seconds: MAX_SESSION_TTL.as_secs(),
    owner_id_max_bytes: OWNER_ID_MAX_BYTES as u16,
    session_key_type_max_bytes: SESSION_KEY_TYPE_MAX_BYTES as u16,
    state_type_max_bytes: STATE_TYPE_MAX_BYTES as u16,
};

const _: () = {
    assert!(RESTORE_SCAN_MAX_PAGE_SIZE <= u32::MAX as usize);
    assert!(MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES <= u32::MAX as usize);
    assert!(MAX_SESSION_NET_BATCH_OPERATIONS <= u32::MAX as usize);
    assert!(MAX_SESSION_NET_REBUILD_ENTRIES <= u32::MAX as usize);
    assert!(MAX_REPLICATION_OPERATION_DEPTH <= u16::MAX as usize);
    assert!(MAX_REPLICATION_OPERATIONS_PER_ENTRY <= u32::MAX as usize);
    assert!(OWNER_ID_MAX_BYTES <= u16::MAX as usize);
    assert!(SESSION_KEY_TYPE_MAX_BYTES <= u16::MAX as usize);
    assert!(STATE_TYPE_MAX_BYTES <= u16::MAX as usize);
};

/// Redaction-safe reason a Hello was rejected before backend dispatch.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HelloRejectReason {
    /// A required field was absent, malformed, or outside its fixed bound.
    Malformed,
    /// The authenticated peer did not match the configured membership scope.
    Authentication,
}

/// Frozen bootstrap payload for the first client frame.
///
/// Optional fields remain optional so peers with different contract versions
/// can exchange a clean version mismatch. A v4 server accepts operations only
/// after separately requiring `contract_profile == Some(CURRENT_CONTRACT_PROFILE)`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapHello {
    pub contract_version: u32,
    pub node_id: String,
    #[serde(default)]
    pub expected_server_replica_id: Option<String>,
    #[serde(default)]
    pub cluster_id: Option<String>,
    #[serde(default)]
    pub configuration_id: Option<String>,
    #[serde(default)]
    pub handshake_nonce: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_profile: Option<ContractProfile>,
}

/// Frozen bootstrap payload for a server acknowledgement.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapHelloAck {
    pub contract_version: u32,
    #[serde(default)]
    pub server_replica_id: Option<String>,
    #[serde(default)]
    pub accepted_client_replica_id: Option<String>,
    #[serde(default)]
    pub cluster_id: Option<String>,
    #[serde(default)]
    pub configuration_id: Option<String>,
    #[serde(default)]
    pub handshake_nonce: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_profile: Option<ContractProfile>,
}

/// The only frame shape decoded before a server authenticates a connection.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) enum BootstrapRequest {
    Hello(BootstrapHello),
}

/// The only frame shapes decoded by a client during bootstrap.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) enum BootstrapResponse {
    HelloAck(BootstrapHelloAck),
    HelloRejected { reason: HelloRejectReason },
}

/// Architecture-independent semantic restore-scan request carried by protocol v4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreScanWireRequest {
    scope: RestoreScanScope,
    cursor: Option<u64>,
    limit: u32,
}

impl TryFrom<&RestoreScanRequest> for RestoreScanWireRequest {
    type Error = StoreError;

    fn try_from(request: &RestoreScanRequest) -> Result<Self, Self::Error> {
        request.validate()?;
        let cursor = request
            .cursor
            .map(RestoreScanCursor::offset)
            .map(u64::try_from)
            .transpose()
            .map_err(|_| {
                StoreError::InvalidRestoreScanRequest(
                    "restore scan cursor exceeds the protocol range".to_string(),
                )
            })?;
        let limit = u32::try_from(request.limit).map_err(|_| {
            StoreError::InvalidRestoreScanRequest(
                "restore scan limit exceeds the protocol range".to_string(),
            )
        })?;
        Ok(Self {
            scope: request.scope.clone(),
            cursor,
            limit,
        })
    }
}

impl TryFrom<RestoreScanWireRequest> for RestoreScanRequest {
    type Error = StoreError;

    fn try_from(request: RestoreScanWireRequest) -> Result<Self, Self::Error> {
        let cursor = request
            .cursor
            .map(usize::try_from)
            .transpose()
            .map_err(|_| {
                StoreError::InvalidRestoreScanRequest(
                    "restore scan cursor is not representable on this server".to_string(),
                )
            })?
            .map(RestoreScanCursor::from_offset);
        let limit = usize::try_from(request.limit).map_err(|_| {
            StoreError::InvalidRestoreScanRequest(
                "restore scan limit is not representable on this server".to_string(),
            )
        })?;
        let request = Self {
            scope: request.scope,
            cursor,
            limit,
        };
        request.validate()?;
        Ok(request)
    }
}

#[derive(Debug, Clone)]
pub enum Request {
    Hello {
        contract_version: u32,
        /// Stable client replica ID. The v2 field name is retained solely so
        /// mixed versions can exchange a clean version mismatch.
        node_id: String,
        expected_server_replica_id: Option<String>,
        cluster_id: Option<String>,
        configuration_id: Option<String>,
        handshake_nonce: Option<uuid::Uuid>,
        contract_profile: Option<ContractProfile>,
    },
    Capabilities,
    Get {
        key: SessionKey,
    },
    CompareAndSet {
        op: CompareAndSet,
        request_id: Option<String>,
    },
    DeleteFenced {
        lease: LeaseGuard,
    },
    RefreshTtl {
        lease: LeaseGuard,
        ttl: Duration,
    },
    Batch {
        ops: Vec<SessionOp>,
    },
    ScanRestoreRecords {
        request: RestoreScanWireRequest,
        max_response_frame_size: u32,
    },
    MaxReplicationSequence,
    GetReplicationLog {
        start: u64,
        limit: usize,
    },
    ReplicateEntry {
        entry: ReplicationEntry,
    },
    RebuildReplicationState {
        entries: Vec<ReplicationEntry>,
    },
    Watch {
        start_sequence: u64,
    },
    NextLeaseInfo,
    AcquireLease {
        key: SessionKey,
        owner: OwnerId,
        ttl: Duration,
    },
    RenewLease {
        lease: LeaseGuard,
        ttl: Duration,
    },
    ReleaseLease {
        lease: LeaseGuard,
    },
}

#[derive(Debug, Clone)]
pub enum Response {
    HelloAck {
        contract_version: u32,
        server_replica_id: Option<String>,
        accepted_client_replica_id: Option<String>,
        cluster_id: Option<String>,
        configuration_id: Option<String>,
        handshake_nonce: Option<uuid::Uuid>,
        contract_profile: Option<ContractProfile>,
    },
    HelloRejected {
        reason: HelloRejectReason,
    },
    Capabilities(BackendCapabilities),
    Get(Result<Option<StoredSessionRecord>, opc_session_store::error::StoreError>),
    CompareAndSet(
        Result<
            opc_session_store::backend::CompareAndSetResult,
            opc_session_store::error::StoreError,
        >,
    ),
    DeleteFenced(Result<(), opc_session_store::error::StoreError>),
    RefreshTtl(Result<(), opc_session_store::error::StoreError>),
    Batch(Result<Vec<SessionOpResult>, opc_session_store::error::StoreError>),
    ScanRestoreRecords(Result<RestoreScanPage, opc_session_store::error::StoreError>),
    MaxReplicationSequence(Result<u64, opc_session_store::error::StoreError>),
    GetReplicationLog(Result<Vec<ReplicationEntry>, opc_session_store::error::StoreError>),
    ReplicateEntry(Result<(), opc_session_store::error::StoreError>),
    RebuildReplicationState(Result<(), opc_session_store::error::StoreError>),
    WatchStream,
    WatchEntry(Result<ReplicationEntry, opc_session_store::error::StoreError>),
    NextLeaseInfo(Result<(u64, u64), opc_session_store::error::StoreError>),
    AcquireLease(Result<LeaseGuard, opc_session_store::error::LeaseError>),
    RenewLease(Result<LeaseGuard, opc_session_store::error::LeaseError>),
    ReleaseLease(Result<(), opc_session_store::error::LeaseError>),
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WireConversionError(&'static str);

impl fmt::Display for WireConversionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

fn wire_u64_from_usize(value: usize, message: &'static str) -> Result<u64, WireConversionError> {
    u64::try_from(value).map_err(|_| WireConversionError(message))
}

fn wire_u32_from_usize(
    value: usize,
    max: usize,
    message: &'static str,
) -> Result<u32, WireConversionError> {
    if value > max {
        return Err(WireConversionError(message));
    }
    u32::try_from(value).map_err(|_| WireConversionError(message))
}

fn usize_from_wire_u64(value: u64, message: &'static str) -> Result<usize, WireConversionError> {
    usize::try_from(value).map_err(|_| WireConversionError(message))
}

fn usize_from_wire_u32(
    value: u32,
    max: usize,
    message: &'static str,
) -> Result<usize, WireConversionError> {
    let value = usize::try_from(value).map_err(|_| WireConversionError(message))?;
    if value > max {
        return Err(WireConversionError(message));
    }
    Ok(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundedVec<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> BoundedVec<T, MAX> {
    fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T: Serialize, const MAX: usize> Serialize for BoundedVec<T, MAX> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

struct BoundedVecVisitor<T, const MAX: usize>(PhantomData<T>);

impl<'de, T, const MAX: usize> Visitor<'de> for BoundedVecVisitor<T, MAX>
where
    T: Deserialize<'de>,
{
    type Value = BoundedVec<T, MAX>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "an array with at most {MAX} elements")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence.size_hint().is_some_and(|hint| hint > MAX) {
            return Err(serde::de::Error::custom("wire collection limit exceeded"));
        }

        let capacity = sequence.size_hint().unwrap_or(0).min(MAX);
        let mut values = Vec::with_capacity(capacity);
        while values.len() < MAX {
            let Some(value) = sequence.next_element()? else {
                return Ok(BoundedVec(values));
            };
            values.push(value);
        }

        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom("wire collection limit exceeded"));
        }
        Ok(BoundedVec(values))
    }
}

impl<'de, T, const MAX: usize> Deserialize<'de> for BoundedVec<T, MAX>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(BoundedVecVisitor::<T, MAX>(PhantomData))
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WireRestoreScanRequestRef<'a> {
    scope: &'a RestoreScanScope,
    cursor: Option<u64>,
    limit: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRestoreScanRequest {
    scope: RestoreScanScope,
    cursor: Option<u64>,
    limit: u32,
}

impl<'a> TryFrom<&'a RestoreScanWireRequest> for WireRestoreScanRequestRef<'a> {
    type Error = WireConversionError;

    fn try_from(request: &'a RestoreScanWireRequest) -> Result<Self, Self::Error> {
        let domain = RestoreScanRequest::try_from(request.clone())
            .map_err(|_| WireConversionError("restore scan request violates the v4 contract"))?;
        domain
            .validate()
            .map_err(|_| WireConversionError("restore scan request violates the v4 contract"))?;
        Ok(Self {
            scope: &request.scope,
            cursor: request.cursor,
            limit: request.limit,
        })
    }
}

impl TryFrom<WireRestoreScanRequest> for RestoreScanWireRequest {
    type Error = WireConversionError;

    fn try_from(request: WireRestoreScanRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            scope: request.scope,
            cursor: request.cursor,
            limit: request.limit,
        })
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WireRestoreScanPageRef<'a> {
    records: &'a [StoredSessionRecord],
    excluded_count: u64,
    next_cursor: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRestoreScanPage {
    records: BoundedVec<StoredSessionRecord, RESTORE_SCAN_MAX_PAGE_SIZE>,
    excluded_count: u64,
    next_cursor: Option<u64>,
}

impl<'a> TryFrom<&'a RestoreScanPage> for WireRestoreScanPageRef<'a> {
    type Error = WireConversionError;

    fn try_from(page: &'a RestoreScanPage) -> Result<Self, Self::Error> {
        if page.records.len() > RESTORE_SCAN_MAX_PAGE_SIZE
            || page.loaded_count != page.records.len()
            || page.complete != page.next_cursor.is_none()
        {
            return Err(WireConversionError(
                "restore scan page violates the v4 contract",
            ));
        }
        Ok(Self {
            records: &page.records,
            excluded_count: wire_u64_from_usize(
                page.excluded_count,
                "restore excluded count exceeds the v4 wire range",
            )?,
            next_cursor: page
                .next_cursor
                .map(RestoreScanCursor::offset)
                .map(|value| wire_u64_from_usize(value, "restore cursor exceeds the v4 wire range"))
                .transpose()?,
        })
    }
}

impl TryFrom<WireRestoreScanPage> for RestoreScanPage {
    type Error = WireConversionError;

    fn try_from(page: WireRestoreScanPage) -> Result<Self, Self::Error> {
        let excluded_count = usize_from_wire_u64(
            page.excluded_count,
            "restore excluded count is not representable on this peer",
        )?;
        let next_cursor = page
            .next_cursor
            .map(|value| {
                usize_from_wire_u64(value, "restore cursor is not representable on this peer")
            })
            .transpose()?
            .map(RestoreScanCursor::from_offset);
        Ok(Self::new(
            page.records.into_inner(),
            excluded_count,
            next_cursor,
        ))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WireBackendCapabilities {
    atomic_compare_and_set: bool,
    monotonic_fencing_token: bool,
    per_key_ttl: bool,
    server_side_lease_expiry: bool,
    ordered_replication_log: bool,
    batch_write: bool,
    watch: bool,
    restore_scan: bool,
    max_value_bytes: u64,
}

impl TryFrom<&BackendCapabilities> for WireBackendCapabilities {
    type Error = WireConversionError;

    fn try_from(capabilities: &BackendCapabilities) -> Result<Self, Self::Error> {
        Ok(Self {
            atomic_compare_and_set: capabilities.atomic_compare_and_set,
            monotonic_fencing_token: capabilities.monotonic_fencing_token,
            per_key_ttl: capabilities.per_key_ttl,
            server_side_lease_expiry: capabilities.server_side_lease_expiry,
            ordered_replication_log: capabilities.ordered_replication_log,
            batch_write: capabilities.batch_write,
            watch: capabilities.watch,
            restore_scan: capabilities.restore_scan,
            max_value_bytes: wire_u64_from_usize(
                capabilities.max_value_bytes,
                "capability size exceeds the v4 wire range",
            )?,
        })
    }
}

impl TryFrom<WireBackendCapabilities> for BackendCapabilities {
    type Error = WireConversionError;

    fn try_from(capabilities: WireBackendCapabilities) -> Result<Self, Self::Error> {
        Ok(Self {
            atomic_compare_and_set: capabilities.atomic_compare_and_set,
            monotonic_fencing_token: capabilities.monotonic_fencing_token,
            per_key_ttl: capabilities.per_key_ttl,
            server_side_lease_expiry: capabilities.server_side_lease_expiry,
            ordered_replication_log: capabilities.ordered_replication_log,
            batch_write: capabilities.batch_write,
            watch: capabilities.watch,
            restore_scan: capabilities.restore_scan,
            max_value_bytes: usize_from_wire_u64(
                capabilities.max_value_bytes,
                "capability size is not representable on this peer",
            )?,
        })
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
enum WireStoreError {
    NotFound,
    StaleFence,
    CasConflict,
    CapabilityNotSupported(String),
    BackendUnavailable(String),
    InvalidKey(String),
    InvalidReplicationSequence,
    ReplicationOperationLimitExceeded,
    InvalidSessionTtl,
    LeaseHeld,
    LeaseExpired,
    Crypto(String),
    Serialization(String),
    PayloadTooLarge { actual: u64, max: u64 },
    InvalidRestoreScanRequest(String),
    InvalidRestoreScanResponse(String),
    RestoreScanPageTooLarge { requested: u64, max: u64 },
    RestoreScanResponseTooLarge { max_bytes: u64 },
}

impl TryFrom<&StoreError> for WireStoreError {
    type Error = WireConversionError;

    fn try_from(error: &StoreError) -> Result<Self, Self::Error> {
        Ok(match error {
            StoreError::NotFound => Self::NotFound,
            StoreError::StaleFence => Self::StaleFence,
            StoreError::CasConflict => Self::CasConflict,
            StoreError::CapabilityNotSupported(message) => {
                Self::CapabilityNotSupported(message.clone())
            }
            StoreError::BackendUnavailable(message) => Self::BackendUnavailable(message.clone()),
            StoreError::InvalidKey(message) => Self::InvalidKey(message.clone()),
            StoreError::InvalidReplicationSequence => Self::InvalidReplicationSequence,
            StoreError::ReplicationOperationLimitExceeded => {
                Self::ReplicationOperationLimitExceeded
            }
            StoreError::InvalidSessionTtl => Self::InvalidSessionTtl,
            StoreError::LeaseHeld => Self::LeaseHeld,
            StoreError::LeaseExpired => Self::LeaseExpired,
            StoreError::Crypto(message) => Self::Crypto(message.clone()),
            StoreError::Serialization(message) => Self::Serialization(message.clone()),
            StoreError::PayloadTooLarge { actual, max } => Self::PayloadTooLarge {
                actual: wire_u64_from_usize(*actual, "payload size exceeds the v4 wire range")?,
                max: wire_u64_from_usize(*max, "payload limit exceeds the v4 wire range")?,
            },
            StoreError::InvalidRestoreScanRequest(message) => {
                Self::InvalidRestoreScanRequest(message.clone())
            }
            StoreError::InvalidRestoreScanResponse(message) => {
                Self::InvalidRestoreScanResponse(message.clone())
            }
            StoreError::RestoreScanPageTooLarge { requested, max } => {
                Self::RestoreScanPageTooLarge {
                    requested: wire_u64_from_usize(
                        *requested,
                        "restore page size exceeds the v4 wire range",
                    )?,
                    max: wire_u64_from_usize(*max, "restore page limit exceeds the v4 wire range")?,
                }
            }
            StoreError::RestoreScanResponseTooLarge { max_bytes } => {
                Self::RestoreScanResponseTooLarge {
                    max_bytes: wire_u64_from_usize(
                        *max_bytes,
                        "restore response limit exceeds the v4 wire range",
                    )?,
                }
            }
        })
    }
}

impl TryFrom<WireStoreError> for StoreError {
    type Error = WireConversionError;

    fn try_from(error: WireStoreError) -> Result<Self, Self::Error> {
        Ok(match error {
            WireStoreError::NotFound => Self::NotFound,
            WireStoreError::StaleFence => Self::StaleFence,
            WireStoreError::CasConflict => Self::CasConflict,
            WireStoreError::CapabilityNotSupported(message) => {
                Self::CapabilityNotSupported(message)
            }
            WireStoreError::BackendUnavailable(message) => Self::BackendUnavailable(message),
            WireStoreError::InvalidKey(message) => Self::InvalidKey(message),
            WireStoreError::InvalidReplicationSequence => Self::InvalidReplicationSequence,
            WireStoreError::ReplicationOperationLimitExceeded => {
                Self::ReplicationOperationLimitExceeded
            }
            WireStoreError::InvalidSessionTtl => Self::InvalidSessionTtl,
            WireStoreError::LeaseHeld => Self::LeaseHeld,
            WireStoreError::LeaseExpired => Self::LeaseExpired,
            WireStoreError::Crypto(message) => Self::Crypto(message),
            WireStoreError::Serialization(message) => Self::Serialization(message),
            WireStoreError::PayloadTooLarge { actual, max } => Self::PayloadTooLarge {
                actual: usize_from_wire_u64(
                    actual,
                    "payload size is not representable on this peer",
                )?,
                max: usize_from_wire_u64(max, "payload limit is not representable on this peer")?,
            },
            WireStoreError::InvalidRestoreScanRequest(message) => {
                Self::InvalidRestoreScanRequest(message)
            }
            WireStoreError::InvalidRestoreScanResponse(message) => {
                Self::InvalidRestoreScanResponse(message)
            }
            WireStoreError::RestoreScanPageTooLarge { requested, max } => {
                Self::RestoreScanPageTooLarge {
                    requested: usize_from_wire_u64(
                        requested,
                        "restore page size is not representable on this peer",
                    )?,
                    max: usize_from_wire_u64(
                        max,
                        "restore page limit is not representable on this peer",
                    )?,
                }
            }
            WireStoreError::RestoreScanResponseTooLarge { max_bytes } => {
                Self::RestoreScanResponseTooLarge {
                    max_bytes: usize_from_wire_u64(
                        max_bytes,
                        "restore response limit is not representable on this peer",
                    )?,
                }
            }
        })
    }
}

#[derive(Serialize)]
enum WireReplicationNodeRef<'a> {
    CompareAndSet {
        key: &'a SessionKey,
        expected_generation: &'a Option<Generation>,
        credential_id: u64,
        guard_expires_at: &'a Timestamp,
        new_record: &'a StoredSessionRecord,
    },
    DeleteFenced {
        key: &'a SessionKey,
        owner: &'a OwnerId,
        fence: &'a FenceToken,
    },
    RefreshTtl {
        key: &'a SessionKey,
        owner: &'a OwnerId,
        fence: &'a FenceToken,
        ttl: &'a Duration,
        expires_at: &'a Timestamp,
    },
    AcquireLease {
        key: &'a SessionKey,
        owner: &'a OwnerId,
        fence: &'a FenceToken,
        credential_id: u64,
        ttl: &'a Duration,
        expires_at: &'a Timestamp,
    },
    RenewLease {
        key: &'a SessionKey,
        owner: &'a OwnerId,
        fence: &'a FenceToken,
        credential_id: u64,
        ttl: &'a Duration,
        expires_at: &'a Timestamp,
    },
    ReleaseLease {
        key: &'a SessionKey,
        owner: &'a OwnerId,
        fence: &'a FenceToken,
        credential_id: u64,
    },
    Batch {
        child_count: u16,
    },
}

#[derive(Deserialize)]
enum WireReplicationNode {
    CompareAndSet {
        key: SessionKey,
        expected_generation: Option<Generation>,
        credential_id: u64,
        guard_expires_at: Timestamp,
        new_record: StoredSessionRecord,
    },
    DeleteFenced {
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
    },
    RefreshTtl {
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        ttl: Duration,
        expires_at: Timestamp,
    },
    AcquireLease {
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        credential_id: u64,
        ttl: Duration,
        expires_at: Timestamp,
    },
    RenewLease {
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        credential_id: u64,
        ttl: Duration,
        expires_at: Timestamp,
    },
    ReleaseLease {
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        credential_id: u64,
    },
    Batch {
        child_count: u16,
    },
}

impl WireReplicationNode {
    fn child_count(&self) -> usize {
        match self {
            Self::Batch { child_count } => usize::from(*child_count),
            _ => 0,
        }
    }

    fn into_leaf(self) -> Result<ReplicationOp, WireConversionError> {
        Ok(match self {
            Self::CompareAndSet {
                key,
                expected_generation,
                credential_id,
                guard_expires_at,
                new_record,
            } => ReplicationOp::CompareAndSet {
                key,
                expected_generation,
                credential_id,
                guard_expires_at,
                new_record,
            },
            Self::DeleteFenced { key, owner, fence } => {
                ReplicationOp::DeleteFenced { key, owner, fence }
            }
            Self::RefreshTtl {
                key,
                owner,
                fence,
                ttl,
                expires_at,
            } => ReplicationOp::RefreshTtl {
                key,
                owner,
                fence,
                ttl,
                expires_at,
            },
            Self::AcquireLease {
                key,
                owner,
                fence,
                credential_id,
                ttl,
                expires_at,
            } => ReplicationOp::AcquireLease {
                key,
                owner,
                fence,
                credential_id,
                ttl,
                expires_at,
            },
            Self::RenewLease {
                key,
                owner,
                fence,
                credential_id,
                ttl,
                expires_at,
            } => ReplicationOp::RenewLease {
                key,
                owner,
                fence,
                credential_id,
                ttl,
                expires_at,
            },
            Self::ReleaseLease {
                key,
                owner,
                fence,
                credential_id,
            } => ReplicationOp::ReleaseLease {
                key,
                owner,
                fence,
                credential_id,
            },
            Self::Batch { .. } => {
                return Err(WireConversionError(
                    "replication operation tree is malformed",
                ));
            }
        })
    }
}

enum WireReplicationNodes {
    Nodes(Vec<WireReplicationNode>),
    LimitExceeded,
}

struct WireReplicationNodesVisitor;

impl<'de> Visitor<'de> for WireReplicationNodesVisitor {
    type Value = WireReplicationNodes;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a flat replication tree with at most {MAX_REPLICATION_OPERATIONS_PER_ENTRY} nodes"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence
            .size_hint()
            .is_some_and(|hint| hint > MAX_REPLICATION_OPERATIONS_PER_ENTRY)
        {
            while sequence.next_element::<IgnoredAny>()?.is_some() {}
            return Ok(WireReplicationNodes::LimitExceeded);
        }

        let capacity = sequence
            .size_hint()
            .unwrap_or(0)
            .min(MAX_REPLICATION_OPERATIONS_PER_ENTRY);
        let mut nodes = Vec::with_capacity(capacity);
        while nodes.len() < MAX_REPLICATION_OPERATIONS_PER_ENTRY {
            let Some(node) = sequence.next_element()? else {
                return Ok(WireReplicationNodes::Nodes(nodes));
            };
            nodes.push(node);
        }

        let mut exceeded = false;
        while sequence.next_element::<IgnoredAny>()?.is_some() {
            exceeded = true;
        }
        if exceeded {
            Ok(WireReplicationNodes::LimitExceeded)
        } else {
            Ok(WireReplicationNodes::Nodes(nodes))
        }
    }
}

impl<'de> Deserialize<'de> for WireReplicationNodes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(WireReplicationNodesVisitor)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WireReplicationEntryRef<'a> {
    sequence: u64,
    tx_id: &'a str,
    operation_nodes: Vec<WireReplicationNodeRef<'a>>,
    timestamp: &'a Timestamp,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReplicationEntry {
    sequence: u64,
    tx_id: String,
    operation_nodes: WireReplicationNodes,
    timestamp: Timestamp,
}

impl<'a> TryFrom<&'a ReplicationEntry> for WireReplicationEntryRef<'a> {
    type Error = WireConversionError;

    fn try_from(entry: &'a ReplicationEntry) -> Result<Self, Self::Error> {
        entry
            .validate()
            .map_err(|_| WireConversionError("replication entry violates the v4 contract"))?;

        let mut pending = Vec::with_capacity(MAX_REPLICATION_OPERATION_DEPTH);
        let mut operation_nodes = Vec::with_capacity(MAX_REPLICATION_OPERATION_DEPTH);
        pending.push(&entry.op);
        while let Some(operation) = pending.pop() {
            let node = match operation {
                ReplicationOp::CompareAndSet {
                    key,
                    expected_generation,
                    credential_id,
                    guard_expires_at,
                    new_record,
                } => WireReplicationNodeRef::CompareAndSet {
                    key,
                    expected_generation,
                    credential_id: *credential_id,
                    guard_expires_at,
                    new_record,
                },
                ReplicationOp::DeleteFenced { key, owner, fence } => {
                    WireReplicationNodeRef::DeleteFenced { key, owner, fence }
                }
                ReplicationOp::RefreshTtl {
                    key,
                    owner,
                    fence,
                    ttl,
                    expires_at,
                } => WireReplicationNodeRef::RefreshTtl {
                    key,
                    owner,
                    fence,
                    ttl,
                    expires_at,
                },
                ReplicationOp::AcquireLease {
                    key,
                    owner,
                    fence,
                    credential_id,
                    ttl,
                    expires_at,
                } => WireReplicationNodeRef::AcquireLease {
                    key,
                    owner,
                    fence,
                    credential_id: *credential_id,
                    ttl,
                    expires_at,
                },
                ReplicationOp::RenewLease {
                    key,
                    owner,
                    fence,
                    credential_id,
                    ttl,
                    expires_at,
                } => WireReplicationNodeRef::RenewLease {
                    key,
                    owner,
                    fence,
                    credential_id: *credential_id,
                    ttl,
                    expires_at,
                },
                ReplicationOp::ReleaseLease {
                    key,
                    owner,
                    fence,
                    credential_id,
                } => WireReplicationNodeRef::ReleaseLease {
                    key,
                    owner,
                    fence,
                    credential_id: *credential_id,
                },
                ReplicationOp::Batch { ops } => {
                    let child_count = u16::try_from(ops.len()).map_err(|_| {
                        WireConversionError("replication batch exceeds the v4 wire range")
                    })?;
                    pending.extend(ops.iter().rev());
                    WireReplicationNodeRef::Batch { child_count }
                }
            };
            operation_nodes.push(node);
        }

        if operation_nodes.is_empty()
            || operation_nodes.len() > MAX_REPLICATION_OPERATIONS_PER_ENTRY
        {
            return Err(WireConversionError(
                "replication entry violates the v4 contract",
            ));
        }
        Ok(Self {
            sequence: entry.sequence,
            tx_id: &entry.tx_id,
            operation_nodes,
            timestamp: &entry.timestamp,
        })
    }
}

impl TryFrom<WireReplicationEntry> for ReplicationEntry {
    type Error = WireConversionError;

    fn try_from(entry: WireReplicationEntry) -> Result<Self, Self::Error> {
        let nodes = match entry.operation_nodes {
            WireReplicationNodes::Nodes(nodes) => nodes,
            WireReplicationNodes::LimitExceeded => {
                return Err(WireConversionError(
                    "replication operation tree exceeds the v4 node limit",
                ));
            }
        };
        validate_wire_replication_tree(&nodes)?;

        let mut operations = Vec::with_capacity(MAX_REPLICATION_OPERATION_DEPTH);
        for node in nodes.into_iter().rev() {
            match node {
                WireReplicationNode::Batch { child_count } => {
                    let child_count = usize::from(child_count);
                    if operations.len() < child_count {
                        return Err(WireConversionError(
                            "replication operation tree is malformed",
                        ));
                    }
                    let mut children = Vec::with_capacity(child_count);
                    for _ in 0..child_count {
                        children.push(operations.pop().ok_or(WireConversionError(
                            "replication operation tree is malformed",
                        ))?);
                    }
                    operations.push(ReplicationOp::Batch { ops: children });
                }
                leaf => operations.push(leaf.into_leaf()?),
            }
        }

        if operations.len() != 1 {
            return Err(WireConversionError(
                "replication operation tree is malformed",
            ));
        }
        let operation = operations.pop().ok_or(WireConversionError(
            "replication operation tree is malformed",
        ))?;
        Ok(ReplicationEntry {
            sequence: entry.sequence,
            tx_id: entry.tx_id,
            op: operation,
            timestamp: entry.timestamp,
        })
    }
}

fn validated_replication_entry_from_wire(
    entry: WireReplicationEntry,
) -> Result<ReplicationEntry, WireConversionError> {
    ReplicationEntry::try_from(entry)?
        .into_validated()
        .map_err(|_| WireConversionError("replication entry violates the v4 contract"))
}

fn validate_wire_replication_tree(
    nodes: &[WireReplicationNode],
) -> Result<(), WireConversionError> {
    if nodes.is_empty() || nodes.len() > MAX_REPLICATION_OPERATIONS_PER_ENTRY {
        return Err(WireConversionError(
            "replication operation tree is malformed",
        ));
    }

    let mut remaining_children = Vec::<usize>::with_capacity(MAX_REPLICATION_OPERATION_DEPTH);
    for (index, node) in nodes.iter().enumerate() {
        if index > 0 {
            while remaining_children.last() == Some(&0) {
                remaining_children.pop();
            }
            let Some(remaining) = remaining_children.last_mut() else {
                return Err(WireConversionError(
                    "replication operation tree is malformed",
                ));
            };
            *remaining = remaining.checked_sub(1).ok_or(WireConversionError(
                "replication operation tree is malformed",
            ))?;
        }

        let depth = remaining_children
            .len()
            .checked_add(1)
            .ok_or(WireConversionError(
                "replication operation tree is malformed",
            ))?;
        if depth > MAX_REPLICATION_OPERATION_DEPTH {
            return Err(WireConversionError(
                "replication operation tree exceeds the v4 depth limit",
            ));
        }

        let child_count = node.child_count();
        if child_count > 0 {
            if depth >= MAX_REPLICATION_OPERATION_DEPTH
                || child_count > nodes.len().saturating_sub(index + 1)
            {
                return Err(WireConversionError(
                    "replication operation tree is malformed",
                ));
            }
            remaining_children.push(child_count);
        }
    }

    while remaining_children.last() == Some(&0) {
        remaining_children.pop();
    }
    if !remaining_children.is_empty() {
        return Err(WireConversionError(
            "replication operation tree is malformed",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
enum WireRequestRef<'a> {
    Hello(BootstrapHello),
    Capabilities,
    Get {
        key: &'a SessionKey,
    },
    CompareAndSet {
        op: &'a CompareAndSet,
        request_id: &'a Option<String>,
    },
    DeleteFenced {
        lease: &'a LeaseGuard,
    },
    RefreshTtl {
        lease: &'a LeaseGuard,
        ttl: &'a Duration,
    },
    Batch {
        ops: &'a [SessionOp],
    },
    ScanRestoreRecords {
        request: WireRestoreScanRequestRef<'a>,
        max_response_frame_size: u32,
    },
    MaxReplicationSequence,
    GetReplicationLog {
        start: u64,
        limit: u32,
    },
    ReplicateEntry {
        entry: WireReplicationEntryRef<'a>,
    },
    RebuildReplicationState {
        entries: Vec<WireReplicationEntryRef<'a>>,
    },
    Watch {
        start_sequence: u64,
    },
    NextLeaseInfo,
    AcquireLease {
        key: &'a SessionKey,
        owner: &'a OwnerId,
        ttl: &'a Duration,
    },
    RenewLease {
        lease: &'a LeaseGuard,
        ttl: &'a Duration,
    },
    ReleaseLease {
        lease: &'a LeaseGuard,
    },
}

#[derive(Deserialize)]
#[allow(clippy::large_enum_variant)] // one frame is independently bounded before decode
enum WireRequest {
    Hello(BootstrapHello),
    Capabilities,
    Get {
        key: SessionKey,
    },
    CompareAndSet {
        op: CompareAndSet,
        #[serde(default)]
        request_id: Option<String>,
    },
    DeleteFenced {
        lease: LeaseGuard,
    },
    RefreshTtl {
        lease: LeaseGuard,
        ttl: Duration,
    },
    Batch {
        ops: BoundedVec<SessionOp, MAX_SESSION_NET_BATCH_OPERATIONS>,
    },
    ScanRestoreRecords {
        request: WireRestoreScanRequest,
        max_response_frame_size: u32,
    },
    MaxReplicationSequence,
    GetReplicationLog {
        start: u64,
        limit: u32,
    },
    ReplicateEntry {
        entry: WireReplicationEntry,
    },
    RebuildReplicationState {
        entries: BoundedVec<WireReplicationEntry, MAX_SESSION_NET_REBUILD_ENTRIES>,
    },
    Watch {
        start_sequence: u64,
    },
    NextLeaseInfo,
    AcquireLease {
        key: SessionKey,
        owner: OwnerId,
        ttl: Duration,
    },
    RenewLease {
        lease: LeaseGuard,
        ttl: Duration,
    },
    ReleaseLease {
        lease: LeaseGuard,
    },
}

impl<'a> TryFrom<&'a Request> for WireRequestRef<'a> {
    type Error = WireConversionError;

    fn try_from(request: &'a Request) -> Result<Self, Self::Error> {
        Ok(match request {
            Request::Hello {
                contract_version,
                node_id,
                expected_server_replica_id,
                cluster_id,
                configuration_id,
                handshake_nonce,
                contract_profile,
            } => Self::Hello(BootstrapHello {
                contract_version: *contract_version,
                node_id: node_id.clone(),
                expected_server_replica_id: expected_server_replica_id.clone(),
                cluster_id: cluster_id.clone(),
                configuration_id: configuration_id.clone(),
                handshake_nonce: *handshake_nonce,
                contract_profile: *contract_profile,
            }),
            Request::Capabilities => Self::Capabilities,
            Request::Get { key } => Self::Get { key },
            Request::CompareAndSet { op, request_id } => Self::CompareAndSet { op, request_id },
            Request::DeleteFenced { lease } => Self::DeleteFenced { lease },
            Request::RefreshTtl { lease, ttl } => Self::RefreshTtl { lease, ttl },
            Request::Batch { ops } => {
                if ops.len() > MAX_SESSION_NET_BATCH_OPERATIONS {
                    return Err(WireConversionError("batch exceeds the v4 operation limit"));
                }
                Self::Batch { ops }
            }
            Request::ScanRestoreRecords {
                request,
                max_response_frame_size,
            } => Self::ScanRestoreRecords {
                request: WireRestoreScanRequestRef::try_from(request)?,
                max_response_frame_size: *max_response_frame_size,
            },
            Request::MaxReplicationSequence => Self::MaxReplicationSequence,
            Request::GetReplicationLog { start, limit } => Self::GetReplicationLog {
                start: *start,
                limit: wire_u32_from_usize(
                    *limit,
                    MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES,
                    "replication log page exceeds the v4 operation limit",
                )?,
            },
            Request::ReplicateEntry { entry } => Self::ReplicateEntry {
                entry: WireReplicationEntryRef::try_from(entry)?,
            },
            Request::RebuildReplicationState { entries } => {
                if entries.len() > MAX_SESSION_NET_REBUILD_ENTRIES {
                    return Err(WireConversionError(
                        "replication rebuild exceeds the v4 entry limit",
                    ));
                }
                let entries = entries
                    .iter()
                    .map(WireReplicationEntryRef::try_from)
                    .collect::<Result<Vec<_>, _>>()?;
                Self::RebuildReplicationState { entries }
            }
            Request::Watch { start_sequence } => Self::Watch {
                start_sequence: *start_sequence,
            },
            Request::NextLeaseInfo => Self::NextLeaseInfo,
            Request::AcquireLease { key, owner, ttl } => Self::AcquireLease { key, owner, ttl },
            Request::RenewLease { lease, ttl } => Self::RenewLease { lease, ttl },
            Request::ReleaseLease { lease } => Self::ReleaseLease { lease },
        })
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)] // one decoded frame is independently bounded
pub(crate) enum InboundRequest {
    Operation(Request),
    ReplicateEntryOperationLimitExceeded,
    RebuildReplicationStateOperationLimitExceeded,
}

impl TryFrom<WireRequest> for InboundRequest {
    type Error = WireConversionError;

    fn try_from(request: WireRequest) -> Result<Self, Self::Error> {
        let request = match request {
            WireRequest::Hello(hello) => Request::Hello {
                contract_version: hello.contract_version,
                node_id: hello.node_id,
                expected_server_replica_id: hello.expected_server_replica_id,
                cluster_id: hello.cluster_id,
                configuration_id: hello.configuration_id,
                handshake_nonce: hello.handshake_nonce,
                contract_profile: hello.contract_profile,
            },
            WireRequest::Capabilities => Request::Capabilities,
            WireRequest::Get { key } => Request::Get { key },
            WireRequest::CompareAndSet { op, request_id } => {
                Request::CompareAndSet { op, request_id }
            }
            WireRequest::DeleteFenced { lease } => Request::DeleteFenced { lease },
            WireRequest::RefreshTtl { lease, ttl } => Request::RefreshTtl { lease, ttl },
            WireRequest::Batch { ops } => Request::Batch {
                ops: ops.into_inner(),
            },
            WireRequest::ScanRestoreRecords {
                request,
                max_response_frame_size,
            } => Request::ScanRestoreRecords {
                request: RestoreScanWireRequest::try_from(request)?,
                max_response_frame_size,
            },
            WireRequest::MaxReplicationSequence => Request::MaxReplicationSequence,
            WireRequest::GetReplicationLog { start, limit } => Request::GetReplicationLog {
                start,
                limit: usize_from_wire_u32(
                    limit,
                    MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES,
                    "replication log page exceeds the v4 operation limit",
                )?,
            },
            WireRequest::ReplicateEntry { entry } => match ReplicationEntry::try_from(entry) {
                Ok(entry) => Request::ReplicateEntry { entry },
                Err(_) => return Ok(Self::ReplicateEntryOperationLimitExceeded),
            },
            WireRequest::RebuildReplicationState { entries } => {
                let entries = entries.into_inner();
                let mut decoded = Vec::with_capacity(entries.len());
                for entry in entries {
                    let Ok(entry) = ReplicationEntry::try_from(entry) else {
                        return Ok(Self::RebuildReplicationStateOperationLimitExceeded);
                    };
                    decoded.push(entry);
                }
                Request::RebuildReplicationState { entries: decoded }
            }
            WireRequest::Watch { start_sequence } => Request::Watch { start_sequence },
            WireRequest::NextLeaseInfo => Request::NextLeaseInfo,
            WireRequest::AcquireLease { key, owner, ttl } => {
                Request::AcquireLease { key, owner, ttl }
            }
            WireRequest::RenewLease { lease, ttl } => Request::RenewLease { lease, ttl },
            WireRequest::ReleaseLease { lease } => Request::ReleaseLease { lease },
        };
        Ok(Self::Operation(request))
    }
}

impl TryFrom<WireRequest> for Request {
    type Error = WireConversionError;

    fn try_from(request: WireRequest) -> Result<Self, Self::Error> {
        match InboundRequest::try_from(request)? {
            InboundRequest::Operation(request) => Ok(request),
            InboundRequest::ReplicateEntryOperationLimitExceeded
            | InboundRequest::RebuildReplicationStateOperationLimitExceeded => Err(
                WireConversionError("replication operation tree violates the v4 contract"),
            ),
        }
    }
}

impl Serialize for Request {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        WireRequestRef::try_from(self)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Request {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Request::try_from(WireRequest::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<&Request> for BootstrapRequest {
    type Error = WireConversionError;

    fn try_from(request: &Request) -> Result<Self, Self::Error> {
        match request {
            Request::Hello {
                contract_version,
                node_id,
                expected_server_replica_id,
                cluster_id,
                configuration_id,
                handshake_nonce,
                contract_profile,
            } => Ok(Self::Hello(BootstrapHello {
                contract_version: *contract_version,
                node_id: node_id.clone(),
                expected_server_replica_id: expected_server_replica_id.clone(),
                cluster_id: cluster_id.clone(),
                configuration_id: configuration_id.clone(),
                handshake_nonce: *handshake_nonce,
                contract_profile: *contract_profile,
            })),
            _ => Err(WireConversionError("expected a bootstrap Hello frame")),
        }
    }
}

impl From<BootstrapRequest> for Request {
    fn from(request: BootstrapRequest) -> Self {
        match request {
            BootstrapRequest::Hello(hello) => Self::Hello {
                contract_version: hello.contract_version,
                node_id: hello.node_id,
                expected_server_replica_id: hello.expected_server_replica_id,
                cluster_id: hello.cluster_id,
                configuration_id: hello.configuration_id,
                handshake_nonce: hello.handshake_nonce,
                contract_profile: hello.contract_profile,
            },
        }
    }
}

fn wire_store_result_ref<T>(
    result: &Result<T, StoreError>,
) -> Result<Result<&T, WireStoreError>, WireConversionError> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(error) => Ok(Err(WireStoreError::try_from(error)?)),
    }
}

fn domain_store_result<T>(
    result: Result<T, WireStoreError>,
) -> Result<Result<T, StoreError>, WireConversionError> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(error) => Ok(Err(StoreError::try_from(error)?)),
    }
}

#[derive(Serialize)]
enum WireSessionOpResultRef<'a> {
    Get(Result<&'a Option<StoredSessionRecord>, WireStoreError>),
    CompareAndSet(Result<&'a CompareAndSetResult, WireStoreError>),
    DeleteFenced(Result<&'a (), WireStoreError>),
    RefreshTtl(Result<&'a (), WireStoreError>),
}

#[derive(Deserialize)]
enum WireSessionOpResult {
    Get(Result<Option<StoredSessionRecord>, WireStoreError>),
    CompareAndSet(Result<CompareAndSetResult, WireStoreError>),
    DeleteFenced(Result<(), WireStoreError>),
    RefreshTtl(Result<(), WireStoreError>),
}

impl<'a> TryFrom<&'a SessionOpResult> for WireSessionOpResultRef<'a> {
    type Error = WireConversionError;

    fn try_from(result: &'a SessionOpResult) -> Result<Self, Self::Error> {
        Ok(match result {
            SessionOpResult::Get(result) => Self::Get(wire_store_result_ref(result)?),
            SessionOpResult::CompareAndSet(result) => {
                Self::CompareAndSet(wire_store_result_ref(result)?)
            }
            SessionOpResult::DeleteFenced(result) => {
                Self::DeleteFenced(wire_store_result_ref(result)?)
            }
            SessionOpResult::RefreshTtl(result) => Self::RefreshTtl(wire_store_result_ref(result)?),
        })
    }
}

impl TryFrom<WireSessionOpResult> for SessionOpResult {
    type Error = WireConversionError;

    fn try_from(result: WireSessionOpResult) -> Result<Self, Self::Error> {
        Ok(match result {
            WireSessionOpResult::Get(result) => Self::Get(domain_store_result(result)?),
            WireSessionOpResult::CompareAndSet(result) => {
                Self::CompareAndSet(domain_store_result(result)?)
            }
            WireSessionOpResult::DeleteFenced(result) => {
                Self::DeleteFenced(domain_store_result(result)?)
            }
            WireSessionOpResult::RefreshTtl(result) => {
                Self::RefreshTtl(domain_store_result(result)?)
            }
        })
    }
}

#[derive(Serialize)]
enum WireResponseRef<'a> {
    HelloAck(BootstrapHelloAck),
    HelloRejected { reason: HelloRejectReason },
    Capabilities(WireBackendCapabilities),
    Get(Result<&'a Option<StoredSessionRecord>, WireStoreError>),
    CompareAndSet(Result<&'a CompareAndSetResult, WireStoreError>),
    DeleteFenced(Result<&'a (), WireStoreError>),
    RefreshTtl(Result<&'a (), WireStoreError>),
    Batch(Result<Vec<WireSessionOpResultRef<'a>>, WireStoreError>),
    ScanRestoreRecords(Result<WireRestoreScanPageRef<'a>, WireStoreError>),
    MaxReplicationSequence(Result<&'a u64, WireStoreError>),
    GetReplicationLog(Result<Vec<WireReplicationEntryRef<'a>>, WireStoreError>),
    ReplicateEntry(Result<&'a (), WireStoreError>),
    RebuildReplicationState(Result<&'a (), WireStoreError>),
    WatchStream,
    WatchEntry(Result<WireReplicationEntryRef<'a>, WireStoreError>),
    NextLeaseInfo(Result<&'a (u64, u64), WireStoreError>),
    AcquireLease(&'a Result<LeaseGuard, LeaseError>),
    RenewLease(&'a Result<LeaseGuard, LeaseError>),
    ReleaseLease(&'a Result<(), LeaseError>),
    Error { message: &'a str },
}

#[derive(Deserialize)]
enum WireResponse {
    HelloAck(BootstrapHelloAck),
    HelloRejected {
        reason: HelloRejectReason,
    },
    Capabilities(WireBackendCapabilities),
    Get(Result<Option<StoredSessionRecord>, WireStoreError>),
    CompareAndSet(Result<CompareAndSetResult, WireStoreError>),
    DeleteFenced(Result<(), WireStoreError>),
    RefreshTtl(Result<(), WireStoreError>),
    Batch(
        Result<BoundedVec<WireSessionOpResult, MAX_SESSION_NET_BATCH_OPERATIONS>, WireStoreError>,
    ),
    ScanRestoreRecords(Result<WireRestoreScanPage, WireStoreError>),
    MaxReplicationSequence(Result<u64, WireStoreError>),
    GetReplicationLog(
        Result<
            BoundedVec<WireReplicationEntry, MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES>,
            WireStoreError,
        >,
    ),
    ReplicateEntry(Result<(), WireStoreError>),
    RebuildReplicationState(Result<(), WireStoreError>),
    WatchStream,
    WatchEntry(Result<WireReplicationEntry, WireStoreError>),
    NextLeaseInfo(Result<(u64, u64), WireStoreError>),
    AcquireLease(Result<LeaseGuard, LeaseError>),
    RenewLease(Result<LeaseGuard, LeaseError>),
    ReleaseLease(Result<(), LeaseError>),
    Error {
        message: String,
    },
}

fn wire_replication_entries_ref<'a>(
    entries: &'a [ReplicationEntry],
    max: usize,
    message: &'static str,
) -> Result<Vec<WireReplicationEntryRef<'a>>, WireConversionError> {
    if entries.len() > max {
        return Err(WireConversionError(message));
    }
    entries
        .iter()
        .map(WireReplicationEntryRef::try_from)
        .collect()
}

impl<'a> TryFrom<&'a Response> for WireResponseRef<'a> {
    type Error = WireConversionError;

    fn try_from(response: &'a Response) -> Result<Self, WireConversionError> {
        Ok(match response {
            Response::HelloAck {
                contract_version,
                server_replica_id,
                accepted_client_replica_id,
                cluster_id,
                configuration_id,
                handshake_nonce,
                contract_profile,
            } => Self::HelloAck(BootstrapHelloAck {
                contract_version: *contract_version,
                server_replica_id: server_replica_id.clone(),
                accepted_client_replica_id: accepted_client_replica_id.clone(),
                cluster_id: cluster_id.clone(),
                configuration_id: configuration_id.clone(),
                handshake_nonce: *handshake_nonce,
                contract_profile: *contract_profile,
            }),
            Response::HelloRejected { reason } => Self::HelloRejected { reason: *reason },
            Response::Capabilities(capabilities) => {
                Self::Capabilities(WireBackendCapabilities::try_from(capabilities)?)
            }
            Response::Get(result) => Self::Get(wire_store_result_ref(result)?),
            Response::CompareAndSet(result) => Self::CompareAndSet(wire_store_result_ref(result)?),
            Response::DeleteFenced(result) => Self::DeleteFenced(wire_store_result_ref(result)?),
            Response::RefreshTtl(result) => Self::RefreshTtl(wire_store_result_ref(result)?),
            Response::Batch(result) => Self::Batch(match result {
                Ok(results) => {
                    if results.len() > MAX_SESSION_NET_BATCH_OPERATIONS {
                        return Err(WireConversionError(
                            "batch response exceeds the v4 operation limit",
                        ));
                    }
                    Ok(results
                        .iter()
                        .map(WireSessionOpResultRef::try_from)
                        .collect::<Result<Vec<_>, _>>()?)
                }
                Err(error) => Err(WireStoreError::try_from(error)?),
            }),
            Response::ScanRestoreRecords(result) => Self::ScanRestoreRecords(match result {
                Ok(page) => Ok(WireRestoreScanPageRef::try_from(page)?),
                Err(error) => Err(WireStoreError::try_from(error)?),
            }),
            Response::MaxReplicationSequence(result) => {
                Self::MaxReplicationSequence(wire_store_result_ref(result)?)
            }
            Response::GetReplicationLog(result) => Self::GetReplicationLog(match result {
                Ok(entries) => Ok(wire_replication_entries_ref(
                    entries,
                    MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES,
                    "replication log response exceeds the v4 entry limit",
                )?),
                Err(error) => Err(WireStoreError::try_from(error)?),
            }),
            Response::ReplicateEntry(result) => {
                Self::ReplicateEntry(wire_store_result_ref(result)?)
            }
            Response::RebuildReplicationState(result) => {
                Self::RebuildReplicationState(wire_store_result_ref(result)?)
            }
            Response::WatchStream => Self::WatchStream,
            Response::WatchEntry(result) => Self::WatchEntry(match result {
                Ok(entry) => Ok(WireReplicationEntryRef::try_from(entry)?),
                Err(error) => Err(WireStoreError::try_from(error)?),
            }),
            Response::NextLeaseInfo(result) => Self::NextLeaseInfo(wire_store_result_ref(result)?),
            Response::AcquireLease(result) => Self::AcquireLease(result),
            Response::RenewLease(result) => Self::RenewLease(result),
            Response::ReleaseLease(result) => Self::ReleaseLease(result),
            Response::Error { message } => Self::Error { message },
        })
    }
}

impl TryFrom<WireResponse> for Response {
    type Error = WireConversionError;

    fn try_from(response: WireResponse) -> Result<Self, WireConversionError> {
        Ok(match response {
            WireResponse::HelloAck(hello) => Self::HelloAck {
                contract_version: hello.contract_version,
                server_replica_id: hello.server_replica_id,
                accepted_client_replica_id: hello.accepted_client_replica_id,
                cluster_id: hello.cluster_id,
                configuration_id: hello.configuration_id,
                handshake_nonce: hello.handshake_nonce,
                contract_profile: hello.contract_profile,
            },
            WireResponse::HelloRejected { reason } => Self::HelloRejected { reason },
            WireResponse::Capabilities(capabilities) => {
                Self::Capabilities(BackendCapabilities::try_from(capabilities)?)
            }
            WireResponse::Get(result) => Self::Get(domain_store_result(result)?),
            WireResponse::CompareAndSet(result) => {
                Self::CompareAndSet(domain_store_result(result)?)
            }
            WireResponse::DeleteFenced(result) => Self::DeleteFenced(domain_store_result(result)?),
            WireResponse::RefreshTtl(result) => Self::RefreshTtl(domain_store_result(result)?),
            WireResponse::Batch(result) => Self::Batch(match result {
                Ok(results) => Ok(results
                    .into_inner()
                    .into_iter()
                    .map(SessionOpResult::try_from)
                    .collect::<Result<Vec<_>, _>>()?),
                Err(error) => Err(StoreError::try_from(error)?),
            }),
            WireResponse::ScanRestoreRecords(result) => Self::ScanRestoreRecords(match result {
                Ok(page) => Ok(RestoreScanPage::try_from(page)?),
                Err(error) => Err(StoreError::try_from(error)?),
            }),
            WireResponse::MaxReplicationSequence(result) => {
                Self::MaxReplicationSequence(domain_store_result(result)?)
            }
            WireResponse::GetReplicationLog(result) => Self::GetReplicationLog(match result {
                Ok(entries) => Ok(entries
                    .into_inner()
                    .into_iter()
                    .map(validated_replication_entry_from_wire)
                    .collect::<Result<Vec<_>, _>>()?),
                Err(error) => Err(StoreError::try_from(error)?),
            }),
            WireResponse::ReplicateEntry(result) => {
                Self::ReplicateEntry(domain_store_result(result)?)
            }
            WireResponse::RebuildReplicationState(result) => {
                Self::RebuildReplicationState(domain_store_result(result)?)
            }
            WireResponse::WatchStream => Self::WatchStream,
            WireResponse::WatchEntry(result) => Self::WatchEntry(match result {
                Ok(entry) => Ok(validated_replication_entry_from_wire(entry)?),
                Err(error) => Err(StoreError::try_from(error)?),
            }),
            WireResponse::NextLeaseInfo(result) => {
                Self::NextLeaseInfo(domain_store_result(result)?)
            }
            WireResponse::AcquireLease(result) => Self::AcquireLease(result),
            WireResponse::RenewLease(result) => Self::RenewLease(result),
            WireResponse::ReleaseLease(result) => Self::ReleaseLease(result),
            WireResponse::Error { message } => Self::Error { message },
        })
    }
}

impl Serialize for Response {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        WireResponseRef::try_from(self)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Response {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Response::try_from(WireResponse::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

impl TryFrom<&Response> for BootstrapResponse {
    type Error = WireConversionError;

    fn try_from(response: &Response) -> Result<Self, Self::Error> {
        match response {
            Response::HelloAck {
                contract_version,
                server_replica_id,
                accepted_client_replica_id,
                cluster_id,
                configuration_id,
                handshake_nonce,
                contract_profile,
            } => Ok(Self::HelloAck(BootstrapHelloAck {
                contract_version: *contract_version,
                server_replica_id: server_replica_id.clone(),
                accepted_client_replica_id: accepted_client_replica_id.clone(),
                cluster_id: cluster_id.clone(),
                configuration_id: configuration_id.clone(),
                handshake_nonce: *handshake_nonce,
                contract_profile: *contract_profile,
            })),
            Response::HelloRejected { reason } => Ok(Self::HelloRejected { reason: *reason }),
            _ => Err(WireConversionError(
                "expected a bootstrap acknowledgement frame",
            )),
        }
    }
}

impl From<BootstrapResponse> for Response {
    fn from(response: BootstrapResponse) -> Self {
        match response {
            BootstrapResponse::HelloAck(hello) => Self::HelloAck {
                contract_version: hello.contract_version,
                server_replica_id: hello.server_replica_id,
                accepted_client_replica_id: hello.accepted_client_replica_id,
                cluster_id: hello.cluster_id,
                configuration_id: hello.configuration_id,
                handshake_nonce: hello.handshake_nonce,
                contract_profile: hello.contract_profile,
            },
            BootstrapResponse::HelloRejected { reason } => Self::HelloRejected { reason },
        }
    }
}

pub async fn write_frame<W, T>(writer: &mut W, frame: &T) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: Serialize,
{
    let json = serde_json::to_vec(frame).map_err(ProtocolError::Serialization)?;
    let len = u32::try_from(json.len()).map_err(|_| ProtocolError::FrameTooLarge(json.len()))?;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(ProtocolError::Io)?;
    writer.write_all(&json).await.map_err(ProtocolError::Io)?;
    writer.flush().await.map_err(ProtocolError::Io)?;
    Ok(())
}

/// Write a complete frame within `timeout`.
///
/// Servers use this for bounded responses so a peer that stops reading cannot
/// retain a connection slot indefinitely.
pub async fn write_frame_within<W, T>(
    writer: &mut W,
    frame: &T,
    timeout: std::time::Duration,
) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: Serialize,
{
    match tokio::time::timeout(timeout, write_frame(writer, frame)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out writing frame to peer",
        ))),
    }
}

struct BoundedFrameCounter {
    encoded_len: usize,
    max_frame_size: usize,
    exceeded_at: Option<usize>,
}

impl std::io::Write for BoundedFrameCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(attempted) = self.encoded_len.checked_add(buf.len()) else {
            self.exceeded_at = Some(usize::MAX);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encoded frame length overflowed",
            ));
        };
        if attempted > self.max_frame_size {
            self.exceeded_at = Some(attempted);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "encoded frame exceeds configured limit",
            ));
        }
        self.encoded_len = attempted;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Validate an encoded frame size without allocating the encoded payload.
pub(crate) fn ensure_frame_fits<T>(frame: &T, max_frame_size: usize) -> Result<(), ProtocolError>
where
    T: Serialize,
{
    let mut counter = BoundedFrameCounter {
        encoded_len: 0,
        max_frame_size,
        exceeded_at: None,
    };
    match serde_json::to_writer(&mut counter, frame) {
        Ok(()) => Ok(()),
        Err(_) if counter.exceeded_at.is_some() => Err(ProtocolError::FrameTooLarge(
            counter
                .exceeded_at
                .unwrap_or(max_frame_size.saturating_add(1)),
        )),
        Err(error) => Err(ProtocolError::Serialization(error)),
    }
}

/// Size one successful restore response using the exact borrowed v4 wire DTO.
///
/// This avoids cloning record payloads while the server progressively trims a
/// page to the caller's response budget.
pub(crate) fn ensure_restore_scan_success_frame_fits(
    page: &RestoreScanPage,
    max_frame_size: usize,
) -> Result<(), ProtocolError> {
    let page =
        WireRestoreScanPageRef::try_from(page).map_err(|_| ProtocolError::InvalidWireValue)?;
    ensure_frame_fits(
        &WireResponseRef::ScanRestoreRecords(Ok(page)),
        max_frame_size,
    )
}

async fn read_frame_payload<R>(
    reader: &mut R,
    max_frame_size: usize,
) -> Result<Vec<u8>, ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut len_bytes = [0u8; 4];
    reader
        .read_exact(&mut len_bytes)
        .await
        .map_err(ProtocolError::Io)?;
    let len = usize::try_from(u32::from_be_bytes(len_bytes))
        .map_err(|_| ProtocolError::InvalidWireValue)?;
    if len > max_frame_size {
        return Err(ProtocolError::FrameTooLarge(len));
    }
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(ProtocolError::Io)?;
    Ok(buf)
}

pub async fn read_frame<R, T>(reader: &mut R, max_frame_size: usize) -> Result<T, ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let payload = read_frame_payload(reader, max_frame_size).await?;
    serde_json::from_slice(&payload).map_err(ProtocolError::Serialization)
}

/// Decode one post-bootstrap operation request through the private v4 DTO.
pub(crate) async fn read_request_frame<R>(
    reader: &mut R,
    max_frame_size: usize,
) -> Result<InboundRequest, ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let payload = read_frame_payload(reader, max_frame_size).await?;
    let wire =
        serde_json::from_slice::<WireRequest>(&payload).map_err(ProtocolError::Serialization)?;
    InboundRequest::try_from(wire).map_err(|_| ProtocolError::InvalidWireValue)
}

/// Decode one post-bootstrap operation response through the private v4 DTO.
pub(crate) async fn read_response_frame<R>(
    reader: &mut R,
    max_frame_size: usize,
) -> Result<Response, ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let payload = read_frame_payload(reader, max_frame_size).await?;
    let wire =
        serde_json::from_slice::<WireResponse>(&payload).map_err(ProtocolError::Serialization)?;
    Response::try_from(wire).map_err(|_| ProtocolError::InvalidWireValue)
}

/// Read a frame, failing with a timed-out I/O error if the whole frame does not
/// arrive within `timeout`.
///
/// Servers must use this rather than [`read_frame`] on accepted connections so
/// that a peer which connects and then stalls (sending nothing, or a partial
/// length prefix) is reaped instead of holding its connection slot forever
/// (slowloris-style exhaustion).
pub async fn read_frame_within<R, T>(
    reader: &mut R,
    max_frame_size: usize,
    timeout: std::time::Duration,
) -> Result<T, ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    match tokio::time::timeout(timeout, read_frame(reader, max_frame_size)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out reading frame from peer",
        ))),
    }
}

/// Deadline-bounded counterpart to [`read_request_frame`].
pub(crate) async fn read_request_frame_within<R>(
    reader: &mut R,
    max_frame_size: usize,
    timeout: std::time::Duration,
) -> Result<InboundRequest, ProtocolError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    match tokio::time::timeout(timeout, read_request_frame(reader, max_frame_size)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(ProtocolError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out reading frame from peer",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use opc_session_store::{
        CompareAndSetResult, EncryptedSessionPayload, FakeSessionBackend, FenceToken, Generation,
        ReplicationOp, SessionKeyType, SessionLeaseManager, StateClass, StateType,
    };
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
    use serde::de::DeserializeOwned;

    const OWNER_SENTINEL: &str = "peer-owner-sensitive-sentinel";
    const KEY_TYPE_SENTINEL: &str = "peer-key-type-sensitive-sentinel";

    fn replace_json_string(
        value: &mut serde_json::Value,
        needle: &str,
        replacement: &str,
    ) -> usize {
        match value {
            serde_json::Value::String(current) if current == needle => {
                *current = replacement.to_owned();
                1
            }
            serde_json::Value::Array(values) => values
                .iter_mut()
                .map(|value| replace_json_string(value, needle, replacement))
                .sum(),
            serde_json::Value::Object(fields) => fields
                .values_mut()
                .map(|value| replace_json_string(value, needle, replacement))
                .sum(),
            _ => 0,
        }
    }

    fn json<T: Serialize>(frame: T) -> serde_json::Value {
        serde_json::to_value(frame).expect("serialize valid protocol frame")
    }

    fn assert_hostile_mutations_rejected<T>(
        family: &str,
        frame: &serde_json::Value,
        field: &str,
        sentinel: &str,
        oversized: &str,
    ) where
        T: DeserializeOwned + std::fmt::Debug,
    {
        let valid_json = serde_json::to_vec(frame).expect("serialize valid protocol frame");
        serde_json::from_slice::<T>(&valid_json)
            .unwrap_or_else(|error| panic!("valid {family} frame did not decode: {error}"));

        for (boundary, replacement) in [("empty", ""), ("129-byte", oversized)] {
            let mut hostile = frame.clone();
            let replaced = replace_json_string(&mut hostile, sentinel, replacement);
            assert!(
                replaced > 0,
                "{family} frame did not contain the {field} sentinel"
            );

            let hostile_json =
                serde_json::to_vec(&hostile).expect("serialize hostile protocol frame");
            let error = serde_json::from_slice::<T>(&hostile_json).unwrap_err();
            let display = error.to_string();
            let debug = format!("{error:?}");

            for secret in [OWNER_SENTINEL, KEY_TYPE_SENTINEL, replacement] {
                if secret.is_empty() {
                    continue;
                }
                assert!(
                    !display.contains(secret),
                    "{family} {field} {boundary} error leaked peer input: {display}"
                );
                assert!(
                    !debug.contains(secret),
                    "{family} {field} {boundary} debug error leaked peer input: {debug}"
                );
            }
        }
    }

    fn test_session_key() -> SessionKey {
        SessionKey {
            tenant: TenantId::new("tenant-a").expect("test tenant"),
            nf_kind: NetworkFunctionKind::new("smf").expect("test NF kind"),
            key_type: SessionKeyType::other(KEY_TYPE_SENTINEL).expect("test key type"),
            stable_id: Bytes::from_static(b"protocol-invariant-boundary"),
        }
    }

    fn test_record(key: SessionKey, owner: OwnerId, fence: FenceToken) -> StoredSessionRecord {
        StoredSessionRecord {
            key,
            generation: Generation::new(1),
            owner,
            fence,
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("protocol-boundary").expect("test state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"payload"),
        }
    }

    #[test]
    fn restore_scan_protocol_v4_frames_round_trip_without_redundant_fields() {
        assert_eq!(CONTRACT_VERSION, 4);

        let domain_request = RestoreScanRequest {
            scope: RestoreScanScope::all(),
            cursor: Some(RestoreScanCursor::from_offset(7)),
            limit: 3,
        };
        let request = Request::ScanRestoreRecords {
            request: RestoreScanWireRequest::try_from(&domain_request).expect("wire request"),
            max_response_frame_size: 32_768,
        };
        let encoded = serde_json::to_vec(&request).expect("encode request");
        let decoded: Request = serde_json::from_slice(&encoded).expect("decode request");
        match decoded {
            Request::ScanRestoreRecords {
                request,
                max_response_frame_size,
            } => {
                assert_eq!(
                    RestoreScanRequest::try_from(request).expect("domain request"),
                    domain_request
                );
                assert_eq!(max_response_frame_size, 32_768);
            }
            other => panic!("unexpected request: {other:?}"),
        }

        let mut invalid_request: serde_json::Value =
            serde_json::from_slice(&encoded).expect("request JSON");
        invalid_request["ScanRestoreRecords"]["request"]["limit"] = serde_json::json!(0);
        let invalid_request: Request =
            serde_json::from_value(invalid_request).expect("representable request frame");
        let Request::ScanRestoreRecords { request, .. } = invalid_request else {
            panic!("unexpected restore request variant");
        };
        assert!(matches!(
            RestoreScanRequest::try_from(request),
            Err(StoreError::InvalidRestoreScanRequest(_))
        ));

        let page = RestoreScanPage::new(Vec::new(), 0, None);
        let response = Response::ScanRestoreRecords(Ok(page.clone()));
        let encoded = serde_json::to_vec(&response).expect("encode response");
        ensure_restore_scan_success_frame_fits(&page, encoded.len())
            .expect("borrowed sizing must match the exact response wire shape");
        assert!(matches!(
            ensure_restore_scan_success_frame_fits(&page, encoded.len() - 1),
            Err(ProtocolError::FrameTooLarge(_))
        ));
        let encoded_value: serde_json::Value =
            serde_json::from_slice(&encoded).expect("inspect response");
        let page = &encoded_value["ScanRestoreRecords"]["Ok"];
        assert!(page.get("loaded_count").is_none());
        assert!(page.get("complete").is_none());
        assert_eq!(page["excluded_count"], 0);
        assert!(page.get("next_cursor").is_some());

        let decoded: Response = serde_json::from_slice(&encoded).expect("decode response");
        assert!(matches!(
            decoded,
            Response::ScanRestoreRecords(Ok(RestoreScanPage {
                loaded_count: 0,
                complete: true,
                ..
            }))
        ));

        let mut legacy = encoded_value;
        legacy["ScanRestoreRecords"]["Ok"]["loaded_count"] = serde_json::json!(0);
        assert!(serde_json::from_value::<Response>(legacy).is_err());
    }

    #[test]
    fn contract_profile_and_bootstrap_frames_are_exact_and_version_tolerant() {
        assert_eq!(SESSION_NET_ALPN, b"opc-session-net/4");
        assert!(CURRENT_CONTRACT_PROFILE.is_current());
        assert_eq!(CURRENT_CONTRACT_PROFILE.error_set_revision, 1);
        assert_eq!(CURRENT_CONTRACT_PROFILE.max_session_ttl_seconds, 31_536_000);

        let profile = serde_json::to_value(CURRENT_CONTRACT_PROFILE).expect("profile JSON");
        assert_eq!(
            profile,
            serde_json::json!({
                "wire_schema_revision": 1,
                "error_set_revision": 1,
                "max_restore_scan_page_records": 1024,
                "max_replication_log_page_entries": 65536,
                "max_batch_operations": 256,
                "max_rebuild_entries": 65536,
                "max_replication_operation_depth": 16,
                "max_replication_operations_per_entry": 256,
                "max_session_ttl_seconds": 31536000,
                "owner_id_max_bytes": 128,
                "session_key_type_max_bytes": 128,
                "state_type_max_bytes": 128
            })
        );

        let legacy = serde_json::json!({
            "Hello": {
                "contract_version": 3,
                "node_id": "replica-a",
                "expected_server_replica_id": null,
                "cluster_id": null,
                "configuration_id": null,
                "handshake_nonce": null
            }
        });
        let decoded: BootstrapRequest =
            serde_json::from_value(legacy.clone()).expect("legacy bootstrap remains readable");
        let BootstrapRequest::Hello(decoded) = decoded;
        assert_eq!(decoded.contract_version, 3);
        assert_eq!(decoded.contract_profile, None);
        assert_eq!(
            serde_json::to_value(BootstrapRequest::Hello(decoded)).expect("bootstrap JSON"),
            legacy
        );

        assert!(
            serde_json::from_value::<BootstrapRequest>(serde_json::json!({
                "Capabilities": null
            }))
            .is_err()
        );
        let mut unknown_bootstrap = legacy.clone();
        unknown_bootstrap["Hello"]["future_field"] = serde_json::json!(true);
        assert!(serde_json::from_value::<BootstrapRequest>(unknown_bootstrap).is_err());

        let acknowledgement = BootstrapResponse::HelloAck(BootstrapHelloAck {
            contract_version: CONTRACT_VERSION,
            server_replica_id: Some("replica-b".to_string()),
            accepted_client_replica_id: Some("replica-a".to_string()),
            cluster_id: Some("cluster-a".to_string()),
            configuration_id: Some("00".repeat(32)),
            handshake_nonce: Some(uuid::Uuid::nil()),
            contract_profile: Some(CURRENT_CONTRACT_PROFILE),
        });
        let acknowledgement = serde_json::to_value(acknowledgement).expect("acknowledgement JSON");
        assert_eq!(
            acknowledgement["HelloAck"]["contract_version"],
            CONTRACT_VERSION
        );
        assert_eq!(acknowledgement["HelloAck"]["contract_profile"], profile);
    }

    #[test]
    fn fixed_width_limits_and_size_errors_have_golden_v4_shapes() {
        let request = Request::GetReplicationLog {
            start: u64::MAX,
            limit: MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES,
        };
        assert_eq!(
            serde_json::to_string(&request).expect("request JSON"),
            r#"{"GetReplicationLog":{"start":18446744073709551615,"limit":65536}}"#
        );
        assert!(serde_json::to_vec(&Request::GetReplicationLog {
            start: 1,
            limit: MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES + 1,
        })
        .is_err());

        let error = Response::Get(Err(StoreError::PayloadTooLarge {
            actual: usize::MAX,
            max: usize::MAX,
        }));
        let value = serde_json::to_value(error).expect("error JSON");
        let expected_max = u64::try_from(usize::MAX).expect("supported usize width");
        assert_eq!(
            value,
            serde_json::json!({
                "Get": {
                    "Err": {
                        "PayloadTooLarge": {
                            "actual": expected_max,
                            "max": expected_max
                        }
                    }
                }
            })
        );

        let nested = Response::Batch(Ok(vec![SessionOpResult::Get(Err(
            StoreError::RestoreScanPageTooLarge {
                requested: usize::MAX,
                max: RESTORE_SCAN_MAX_PAGE_SIZE,
            },
        ))]));
        let nested_json = serde_json::to_value(nested).expect("nested error JSON");
        assert_eq!(
            nested_json["Batch"]["Ok"][0]["Get"]["Err"]["RestoreScanPageTooLarge"]["requested"],
            expected_max
        );
        assert_eq!(
            nested_json["Batch"]["Ok"][0]["Get"]["Err"]["RestoreScanPageTooLarge"]["max"],
            1024
        );
    }

    #[test]
    fn every_store_error_has_a_frozen_v4_round_trip() {
        let errors = [
            StoreError::NotFound,
            StoreError::StaleFence,
            StoreError::CasConflict,
            StoreError::CapabilityNotSupported("capability".to_string()),
            StoreError::BackendUnavailable("backend".to_string()),
            StoreError::InvalidKey("invalid".to_string()),
            StoreError::InvalidReplicationSequence,
            StoreError::ReplicationOperationLimitExceeded,
            StoreError::InvalidSessionTtl,
            StoreError::LeaseHeld,
            StoreError::LeaseExpired,
            StoreError::Crypto("crypto".to_string()),
            StoreError::Serialization("serialization".to_string()),
            StoreError::PayloadTooLarge { actual: 2, max: 1 },
            StoreError::InvalidRestoreScanRequest("request".to_string()),
            StoreError::InvalidRestoreScanResponse("response".to_string()),
            StoreError::RestoreScanPageTooLarge {
                requested: 2,
                max: 1,
            },
            StoreError::RestoreScanResponseTooLarge { max_bytes: 512 },
        ];

        for expected in errors {
            let encoded = serde_json::to_vec(&Response::Get(Err(expected.clone())))
                .expect("encode StoreError");
            let decoded: Response = serde_json::from_slice(&encoded).expect("decode StoreError");
            assert!(matches!(decoded, Response::Get(Err(actual)) if actual == expected));
        }

        assert_eq!(
            serde_json::to_string(&Response::Get(Err(StoreError::InvalidReplicationSequence)))
                .expect("sequence error"),
            r#"{"Get":{"Err":"InvalidReplicationSequence"}}"#
        );
        let nested = Response::Batch(Ok(vec![SessionOpResult::Get(Err(
            StoreError::ReplicationOperationLimitExceeded,
        ))]));
        assert_eq!(
            serde_json::to_string(&nested).expect("operation limit error"),
            r#"{"Batch":{"Ok":[{"Get":{"Err":"ReplicationOperationLimitExceeded"}}]}}"#
        );
        let decoded: Response = serde_json::from_str(
            r#"{"Batch":{"Ok":[{"Get":{"Err":"ReplicationOperationLimitExceeded"}}]}}"#,
        )
        .expect("nested operation error");
        assert!(matches!(
            decoded,
            Response::Batch(Ok(results))
                if matches!(
                    results.as_slice(),
                    [SessionOpResult::Get(Err(StoreError::ReplicationOperationLimitExceeded))]
                )
        ));
    }

    #[test]
    fn u64_wire_sizes_are_checked_at_the_local_pointer_width() {
        let raw = br#"{"Get":{"Err":{"PayloadTooLarge":{"actual":18446744073709551615,"max":18446744073709551615}}}}"#;
        let decoded = serde_json::from_slice::<Response>(raw);
        #[cfg(target_pointer_width = "64")]
        assert!(matches!(
            decoded,
            Ok(Response::Get(Err(StoreError::PayloadTooLarge {
                actual: usize::MAX,
                max: usize::MAX
            })))
        ));
        #[cfg(target_pointer_width = "32")]
        assert!(decoded.is_err());
    }

    #[test]
    fn capabilities_use_a_checked_u64_wire_size() {
        let mut capabilities = BackendCapabilities::all_enabled();
        capabilities.max_value_bytes = usize::MAX;
        let encoded = serde_json::to_value(Response::Capabilities(capabilities))
            .expect("capability response JSON");
        assert_eq!(
            encoded["Capabilities"]["max_value_bytes"],
            u64::try_from(usize::MAX).expect("supported usize width")
        );
        let decoded: Response = serde_json::from_value(encoded).expect("capability response");
        assert!(matches!(
            decoded,
            Response::Capabilities(BackendCapabilities {
                max_value_bytes: usize::MAX,
                ..
            })
        ));

        let hostile = serde_json::json!({
            "Capabilities": {
                "atomic_compare_and_set": false,
                "monotonic_fencing_token": false,
                "per_key_ttl": false,
                "server_side_lease_expiry": false,
                "ordered_replication_log": false,
                "batch_write": false,
                "watch": false,
                "restore_scan": false,
                "max_value_bytes": u64::MAX
            }
        });
        let hostile = serde_json::from_value::<Response>(hostile);
        #[cfg(target_pointer_width = "64")]
        assert!(matches!(
            hostile,
            Ok(Response::Capabilities(BackendCapabilities {
                max_value_bytes: usize::MAX,
                ..
            }))
        ));
        #[cfg(target_pointer_width = "32")]
        assert!(hostile.is_err());
    }

    fn replication_leaf(key: &SessionKey, owner: &OwnerId) -> ReplicationOp {
        ReplicationOp::DeleteFenced {
            key: key.clone(),
            owner: owner.clone(),
            fence: FenceToken::new(1),
        }
    }

    fn replication_entry(op: ReplicationOp) -> ReplicationEntry {
        ReplicationEntry {
            sequence: 1,
            tx_id: "wire-tree".to_string(),
            op,
            timestamp: Timestamp::now_utc(),
        }
    }

    fn operation_at_depth(mut operation: ReplicationOp, depth: usize) -> ReplicationOp {
        for _ in 1..depth {
            operation = ReplicationOp::Batch {
                ops: vec![operation],
            };
        }
        operation
    }

    #[test]
    fn replication_tree_is_flat_bounded_and_reconstructed_iteratively() {
        let key = test_session_key();
        let owner = OwnerId::new("replica-a").expect("owner");

        let exact_depth = replication_entry(operation_at_depth(
            replication_leaf(&key, &owner),
            MAX_REPLICATION_OPERATION_DEPTH,
        ));
        let frame = Request::ReplicateEntry {
            entry: exact_depth.clone(),
        };
        let json = serde_json::to_value(&frame).expect("exact-depth frame");
        let nodes = json["ReplicateEntry"]["entry"]["operation_nodes"]
            .as_array()
            .expect("flat nodes");
        assert_eq!(nodes.len(), MAX_REPLICATION_OPERATION_DEPTH);
        assert!(json["ReplicateEntry"]["entry"].get("op").is_none());
        let decoded: Request = serde_json::from_value(json.clone()).expect("flat tree decode");
        assert!(matches!(
            decoded,
            Request::ReplicateEntry { entry } if entry == exact_depth
        ));

        let too_deep = Request::ReplicateEntry {
            entry: replication_entry(operation_at_depth(
                replication_leaf(&key, &owner),
                MAX_REPLICATION_OPERATION_DEPTH + 1,
            )),
        };
        assert!(serde_json::to_vec(&too_deep).is_err());

        let mut hostile_depth = json.clone();
        let nodes = hostile_depth["ReplicateEntry"]["entry"]["operation_nodes"]
            .as_array_mut()
            .expect("flat nodes");
        nodes.insert(
            nodes.len() - 1,
            serde_json::json!({"Batch": {"child_count": 1}}),
        );
        let wire: WireRequest =
            serde_json::from_value(hostile_depth.clone()).expect("bounded flat wire tree");
        assert!(matches!(
            InboundRequest::try_from(wire),
            Ok(InboundRequest::ReplicateEntryOperationLimitExceeded)
        ));
        let rebuild = serde_json::json!({
            "RebuildReplicationState": {
                "entries": [hostile_depth["ReplicateEntry"]["entry"].clone()]
            }
        });
        let wire: WireRequest = serde_json::from_value(rebuild).expect("bounded flat rebuild tree");
        assert!(matches!(
            InboundRequest::try_from(wire),
            Ok(InboundRequest::RebuildReplicationStateOperationLimitExceeded)
        ));
        assert!(serde_json::from_value::<Request>(hostile_depth).is_err());

        let exact_width = replication_entry(ReplicationOp::Batch {
            ops: (0..MAX_REPLICATION_OPERATIONS_PER_ENTRY - 1)
                .map(|_| replication_leaf(&key, &owner))
                .collect(),
        });
        let exact_width_json = serde_json::to_value(Request::ReplicateEntry {
            entry: exact_width.clone(),
        })
        .expect("exact-width frame");
        assert_eq!(
            exact_width_json["ReplicateEntry"]["entry"]["operation_nodes"]
                .as_array()
                .expect("nodes")
                .len(),
            MAX_REPLICATION_OPERATIONS_PER_ENTRY
        );
        let decoded: Request =
            serde_json::from_value(exact_width_json.clone()).expect("exact-width decode");
        assert!(matches!(
            decoded,
            Request::ReplicateEntry { entry } if entry == exact_width
        ));

        let too_wide = Request::ReplicateEntry {
            entry: replication_entry(ReplicationOp::Batch {
                ops: (0..MAX_REPLICATION_OPERATIONS_PER_ENTRY)
                    .map(|_| replication_leaf(&key, &owner))
                    .collect(),
            }),
        };
        assert!(serde_json::to_vec(&too_wide).is_err());

        let mut hostile_width = exact_width_json;
        let nodes = hostile_width["ReplicateEntry"]["entry"]["operation_nodes"]
            .as_array_mut()
            .expect("nodes");
        let leaf = nodes.last().expect("leaf").clone();
        nodes[0]["Batch"]["child_count"] = serde_json::json!(256);
        nodes.push(leaf);
        assert_eq!(nodes.len(), MAX_REPLICATION_OPERATIONS_PER_ENTRY + 1);
        let wire: WireRequest =
            serde_json::from_value(hostile_width.clone()).expect("bounded over-limit sentinel");
        assert!(matches!(
            InboundRequest::try_from(wire),
            Ok(InboundRequest::ReplicateEntryOperationLimitExceeded)
        ));
        assert!(serde_json::from_value::<Request>(hostile_width).is_err());

        let mut legacy_nested = json;
        let entry = legacy_nested["ReplicateEntry"]["entry"]
            .as_object_mut()
            .expect("entry");
        entry.remove("operation_nodes");
        entry.insert("op".to_string(), serde_json::json!({"Batch": {"ops": []}}));
        assert!(serde_json::from_value::<Request>(legacy_nested).is_err());
    }

    #[test]
    fn batch_collection_bound_is_independent_of_the_frame_limit() {
        let key = test_session_key();
        let operation = SessionOp::Get { key };
        let exact = Request::Batch {
            ops: vec![operation.clone(); MAX_SESSION_NET_BATCH_OPERATIONS],
        };
        let json = serde_json::to_value(exact).expect("exact batch");
        let decoded: Request = serde_json::from_value(json.clone()).expect("decode exact batch");
        assert!(matches!(
            decoded,
            Request::Batch { ops } if ops.len() == MAX_SESSION_NET_BATCH_OPERATIONS
        ));

        let too_many = Request::Batch {
            ops: vec![operation; MAX_SESSION_NET_BATCH_OPERATIONS + 1],
        };
        assert!(serde_json::to_value(too_many).is_err());

        let mut hostile = json;
        let operations = hostile["Batch"]["ops"].as_array_mut().expect("ops");
        operations.push(operations[0].clone());
        assert!(serde_json::from_value::<Request>(hostile).is_err());
    }

    #[test]
    fn rebuild_and_log_response_collection_boundaries_are_exact() {
        let key = test_session_key();
        let owner = OwnerId::new("replica-a").expect("owner");
        let entry = replication_entry(replication_leaf(&key, &owner));

        let rebuild_entries = vec![entry.clone(); MAX_SESSION_NET_REBUILD_ENTRIES];
        let rebuild = Request::RebuildReplicationState {
            entries: rebuild_entries,
        };
        assert!(WireRequestRef::try_from(&rebuild).is_ok());
        let rebuild_over = Request::RebuildReplicationState {
            entries: vec![entry.clone(); MAX_SESSION_NET_REBUILD_ENTRIES + 1],
        };
        assert!(WireRequestRef::try_from(&rebuild_over).is_err());

        let log = Response::GetReplicationLog(Ok(vec![
            entry.clone();
            MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES
        ]));
        assert!(WireResponseRef::try_from(&log).is_ok());
        let log_over = Response::GetReplicationLog(Ok(vec![
            entry;
            MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES
                + 1
        ]));
        assert!(WireResponseRef::try_from(&log_over).is_err());

        let exact = serde_json::to_vec(&vec![0_u8; MAX_SESSION_NET_REBUILD_ENTRIES])
            .expect("exact bounded array");
        let decoded: BoundedVec<u8, MAX_SESSION_NET_REBUILD_ENTRIES> =
            serde_json::from_slice(&exact).expect("decode exact bounded array");
        assert_eq!(decoded.into_inner().len(), MAX_SESSION_NET_REBUILD_ENTRIES);
        let one_over = serde_json::to_vec(&vec![0_u8; MAX_SESSION_NET_REBUILD_ENTRIES + 1])
            .expect("one-over bounded array");
        assert!(
            serde_json::from_slice::<BoundedVec<u8, MAX_SESSION_NET_REBUILD_ENTRIES>>(&one_over)
                .is_err()
        );
    }

    #[tokio::test]
    async fn typed_reader_classifies_fixed_width_conversion_failures() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let write = tokio::spawn(async move {
            write_frame(
                &mut writer,
                &serde_json::json!({
                    "GetReplicationLog": {
                        "start": 1,
                        "limit": 65537
                    }
                }),
            )
            .await
            .expect("write hostile request");
        });
        let error = read_request_frame(&mut reader, 1024)
            .await
            .expect_err("operation limit must fail");
        assert!(matches!(error, ProtocolError::InvalidWireValue));
        write.await.expect("writer task");
    }

    #[test]
    fn bounded_encoder_rejects_oversized_restore_frame() {
        let response =
            Response::ScanRestoreRecords(Err(StoreError::BackendUnavailable("x".repeat(1024))));
        assert!(matches!(
            ensure_frame_fits(&response, 128),
            Err(ProtocolError::FrameTooLarge(_))
        ));

        let terminal = Response::ScanRestoreRecords(Err(StoreError::RestoreScanResponseTooLarge {
            max_bytes: MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE,
        }));
        ensure_frame_fits(&terminal, MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE)
            .expect("minimum response budget must fit the terminal error");
    }

    #[tokio::test]
    async fn hostile_model_values_fail_during_decode_across_protocol_families() {
        let oversized = format!("{}x", "é".repeat(64));
        assert_eq!(oversized.len(), 129, "test value must be 129 UTF-8 bytes");

        let key = test_session_key();
        let owner = OwnerId::new(OWNER_SENTINEL).expect("test owner");
        let backend = FakeSessionBackend::new();
        let lease = backend
            .acquire(&key, owner.clone(), Duration::from_secs(60))
            .await
            .expect("test lease");
        let record = test_record(key.clone(), owner.clone(), lease.fence());
        let cas = CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        };
        let restore_request = RestoreScanRequest {
            scope: RestoreScanScope {
                tenant: None,
                nf_kind: None,
                key_type: Some(key.key_type.clone()),
                state_class: None,
                state_type: None,
                owner: Some(owner.clone()),
            },
            cursor: None,
            limit: 1,
        };
        let timestamp = Timestamp::now_utc();
        let entry = ReplicationEntry {
            sequence: 1,
            tx_id: "protocol-invariant-entry".to_owned(),
            op: ReplicationOp::RefreshTtl {
                key: key.clone(),
                owner: owner.clone(),
                fence: lease.fence(),
                ttl: Duration::from_secs(60),
                expires_at: timestamp,
            },
            timestamp,
        };

        let request_frames = [
            (
                "acquire request",
                json(Request::AcquireLease {
                    key: key.clone(),
                    owner: owner.clone(),
                    ttl: Duration::from_secs(60),
                }),
                true,
            ),
            (
                "lease request",
                json(Request::RenewLease {
                    lease: lease.clone(),
                    ttl: Duration::from_secs(60),
                }),
                true,
            ),
            (
                "get request",
                json(Request::Get { key: key.clone() }),
                false,
            ),
            (
                "CAS request",
                json(Request::CompareAndSet {
                    op: cas.clone(),
                    request_id: Some("protocol-invariant-request".to_owned()),
                }),
                true,
            ),
            (
                "batch request",
                json(Request::Batch {
                    ops: vec![
                        SessionOp::Get { key: key.clone() },
                        SessionOp::CompareAndSet(cas.clone()),
                    ],
                }),
                true,
            ),
            (
                "restore scope request",
                json(Request::ScanRestoreRecords {
                    request: RestoreScanWireRequest::try_from(&restore_request)
                        .expect("wire restore request"),
                    max_response_frame_size: 32_768,
                }),
                true,
            ),
            (
                "replicate request",
                json(Request::ReplicateEntry {
                    entry: entry.clone(),
                }),
                true,
            ),
            (
                "rebuild request",
                json(Request::RebuildReplicationState {
                    entries: vec![entry.clone()],
                }),
                true,
            ),
        ];

        let response_frames = [
            ("lease response", json(Response::AcquireLease(Ok(lease)))),
            (
                "get response",
                json(Response::Get(Ok(Some(record.clone())))),
            ),
            (
                "CAS response",
                json(Response::CompareAndSet(Ok(CompareAndSetResult::Conflict {
                    current: Some(record.clone()),
                }))),
            ),
            (
                "batch response",
                json(Response::Batch(Ok(vec![SessionOpResult::Get(Ok(Some(
                    record.clone(),
                )))]))),
            ),
            (
                "restore page response",
                json(Response::ScanRestoreRecords(Ok(RestoreScanPage::new(
                    vec![record],
                    0,
                    None,
                )))),
            ),
            (
                "replication log response",
                json(Response::GetReplicationLog(Ok(vec![entry.clone()]))),
            ),
            ("watch response", json(Response::WatchEntry(Ok(entry)))),
        ];

        for (family, frame, has_owner) in request_frames {
            if has_owner {
                assert_hostile_mutations_rejected::<Request>(
                    family,
                    &frame,
                    "owner",
                    OWNER_SENTINEL,
                    &oversized,
                );
            }
            assert_hostile_mutations_rejected::<Request>(
                family,
                &frame,
                "key type",
                KEY_TYPE_SENTINEL,
                &oversized,
            );
        }

        for (family, frame) in response_frames {
            assert_hostile_mutations_rejected::<Response>(
                family,
                &frame,
                "owner",
                OWNER_SENTINEL,
                &oversized,
            );
            assert_hostile_mutations_rejected::<Response>(
                family,
                &frame,
                "key type",
                KEY_TYPE_SENTINEL,
                &oversized,
            );
        }
    }

    #[tokio::test]
    async fn oversized_declared_frame_is_rejected_before_payload_read() {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        tokio::spawn(async move {
            writer
                .write_all(&1024_u32.to_be_bytes())
                .await
                .expect("write length");
        });

        let result = read_frame::<_, Response>(&mut reader, 128).await;
        assert!(matches!(result, Err(ProtocolError::FrameTooLarge(1024))));
    }
}
