#![cfg_attr(not(feature = "legacy-session-net-compat"), allow(dead_code))]
// The consensus transport reuses the bounded framing core below. The legacy
// protocol-v5 DTO/conversion graph remains compiled but private in production
// so the shared framing code does not fork; its unused compatibility-only
// branches are intentionally dead unless `legacy-session-net-compat` is set.

use std::sync::atomic::{AtomicBool, Ordering};
use std::{fmt, marker::PhantomData, time::Duration};

use opc_session_store::backend::{
    CompareAndSet, CompareAndSetResult, ReplicationEntry, ReplicationLogRange, ReplicationOp,
    ReplicationTxId, SessionOp, SessionOpResult, MAX_RECORD_EXPIRY_PREFLIGHTS,
    MAX_REPLICATION_LOG_PAGE_ENTRIES, MAX_REPLICATION_OPERATIONS_PER_ENTRY,
    MAX_REPLICATION_OPERATION_DEPTH,
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
    RecordExpiryPreflight, RestoreScanCursor, RestoreScanCursorProfile, RestoreScanPage,
    RestoreScanRequest, RestoreScanScope, SessionConsensusIdentity, SessionConsensusNodeId,
    SessionConsensusPeerError, SessionConsensusWireRequest, SessionConsensusWireResponse,
    MAX_SESSION_TTL, RESTORE_SCAN_MAX_PAGE_SIZE, SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES,
};
use opc_types::Timestamp;
use serde::de::{IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::ProtocolError;

pub const CONTRACT_VERSION: u32 = 5;
pub const DEFAULT_MAX_FRAME_SIZE: usize = 1024 * 1024;
pub const MAX_HANDSHAKE_FRAME_SIZE: usize = 8 * 1024;
/// Smallest post-bootstrap frame budget accepted by protocol v5.
///
/// This leaves room for every fixed, redaction-safe terminal response while
/// also carrying a zero-payload CAS/Get envelope with every bounded profile
/// identifier at its worst JSON expansion. The power-of-two headroom avoids
/// making compatibility depend on one exact serde byte count.
pub const MIN_NEGOTIATED_FRAME_SIZE: usize = 8 * 1024;
/// Smallest encoded frame budget accepted by the consensus-only profile.
///
/// A worst-case JSON byte-array representation of the shared 2 MiB opaque RPC
/// ceiling consumes about 8 MiB. This bound leaves deterministic envelope
/// headroom while remaining below the global per-frame ceiling.
pub const MIN_SESSION_CONSENSUS_FRAME_SIZE: usize = 9 * 1024 * 1024;
/// Largest post-bootstrap frame budget accepted by protocol v5.
///
/// This ceiling bounds one encoded JSON frame independently of the wire's
/// wider `u32` length prefix. At the conservative one-eighth payload ratio it
/// advertises 2,096,128 payload bytes, enough for the SQLite backend's 1 MiB
/// value limit while keeping per-connection response storage finite.
pub const MAX_NEGOTIATED_FRAME_SIZE: usize = 16 * 1024 * 1024;
pub const MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE: usize = MIN_NEGOTIATED_FRAME_SIZE;
pub const MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES: usize = MAX_REPLICATION_LOG_PAGE_ENTRIES;
pub const MAX_SESSION_NET_BATCH_OPERATIONS: usize = 256;
pub const MAX_SESSION_NET_REBUILD_ENTRIES: usize = 65_536;
/// Maximum transport width for a digest-oriented session stable identifier.
pub const MAX_SESSION_NET_STABLE_ID_BYTES: usize = opc_session_store::STABLE_ID_MAX_BYTES;
/// Maximum UTF-8 width retained for a durable replication transaction ID.
pub const MAX_SESSION_NET_REPLICATION_TX_ID_BYTES: usize =
    opc_session_store::REPLICATION_TX_ID_MAX_BYTES;
/// Canonical hyphenated UUID width used by CAS idempotency request IDs.
pub const SESSION_NET_CAS_REQUEST_ID_BYTES: usize = 36;
pub const SESSION_NET_ALPN: &[u8] = b"opc-session-net/5";
/// Dedicated ALPN for the least-authority consensus-only transport.
pub const SESSION_CONSENSUS_ALPN: &[u8] = b"opc-session-consensus/2";
/// Fixed revision of the consensus-only bootstrap and operation DTOs.
pub const SESSION_CONSENSUS_TRANSPORT_REVISION: u16 = 2;

/// Exact resource and semantic profile for consensus-only connections.
///
/// There is no subset negotiation. A mismatch is rejected before any
/// consensus request is decoded or dispatched.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SessionConsensusContractProfile {
    /// Revision of the dedicated consensus wire DTOs.
    pub wire_schema_revision: u16,
    /// Revision of the fixed transport and nested forwarded-operation errors.
    pub error_set_revision: u16,
    /// Largest decoded private consensus payload accepted in either direction.
    pub max_rpc_payload_bytes: u32,
    /// Smallest negotiated encoded frame budget.
    pub min_frame_size: u32,
    /// Largest negotiated encoded frame budget.
    pub max_frame_size: u32,
}

impl SessionConsensusContractProfile {
    /// Whether this is the exact profile implemented by this SDK build.
    pub const fn is_current(self) -> bool {
        self.wire_schema_revision == CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE.wire_schema_revision
            && self.error_set_revision
                == CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE.error_set_revision
            && self.max_rpc_payload_bytes
                == CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE.max_rpc_payload_bytes
            && self.min_frame_size == CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE.min_frame_size
            && self.max_frame_size == CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE.max_frame_size
    }
}

/// One exact consensus-only transport profile.
pub const CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE: SessionConsensusContractProfile =
    SessionConsensusContractProfile {
        wire_schema_revision: SESSION_CONSENSUS_TRANSPORT_REVISION,
        error_set_revision: 4,
        max_rpc_payload_bytes: SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES as u32,
        min_frame_size: MIN_SESSION_CONSENSUS_FRAME_SIZE as u32,
        max_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
    };

const WIRE_SCHEMA_REVISION: u16 = 6;
const ERROR_SET_REVISION: u16 = 8;

/// Exact semantic and resource-bound contract required by protocol v5.
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
    pub max_restore_scan_page_payload_bytes: u32,
    pub max_restore_scan_page_retained_bytes: u32,
    pub max_restore_scan_examined_rows: u32,
    pub max_restore_scan_examined_metadata_bytes: u32,
    pub max_replication_log_page_entries: u32,
    pub max_batch_operations: u32,
    pub max_rebuild_entries: u32,
    pub max_replication_operation_depth: u16,
    pub max_replication_operations_per_entry: u32,
    pub min_frame_size: u32,
    pub max_frame_size: u32,
    pub max_session_ttl_seconds: u64,
    pub owner_id_max_bytes: u16,
    pub session_key_type_max_bytes: u16,
    pub state_type_max_bytes: u16,
    pub stable_id_max_bytes: u16,
    pub replication_tx_id_max_bytes: u16,
    pub cas_request_id_bytes: u16,
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
            && self.max_restore_scan_page_payload_bytes
                == CURRENT_CONTRACT_PROFILE.max_restore_scan_page_payload_bytes
            && self.max_restore_scan_page_retained_bytes
                == CURRENT_CONTRACT_PROFILE.max_restore_scan_page_retained_bytes
            && self.max_restore_scan_examined_rows
                == CURRENT_CONTRACT_PROFILE.max_restore_scan_examined_rows
            && self.max_restore_scan_examined_metadata_bytes
                == CURRENT_CONTRACT_PROFILE.max_restore_scan_examined_metadata_bytes
            && self.max_replication_log_page_entries
                == CURRENT_CONTRACT_PROFILE.max_replication_log_page_entries
            && self.max_batch_operations == CURRENT_CONTRACT_PROFILE.max_batch_operations
            && self.max_rebuild_entries == CURRENT_CONTRACT_PROFILE.max_rebuild_entries
            && self.max_replication_operation_depth
                == CURRENT_CONTRACT_PROFILE.max_replication_operation_depth
            && self.max_replication_operations_per_entry
                == CURRENT_CONTRACT_PROFILE.max_replication_operations_per_entry
            && self.min_frame_size == CURRENT_CONTRACT_PROFILE.min_frame_size
            && self.max_frame_size == CURRENT_CONTRACT_PROFILE.max_frame_size
            && self.max_session_ttl_seconds == CURRENT_CONTRACT_PROFILE.max_session_ttl_seconds
            && self.owner_id_max_bytes == CURRENT_CONTRACT_PROFILE.owner_id_max_bytes
            && self.session_key_type_max_bytes
                == CURRENT_CONTRACT_PROFILE.session_key_type_max_bytes
            && self.state_type_max_bytes == CURRENT_CONTRACT_PROFILE.state_type_max_bytes
            && self.stable_id_max_bytes == CURRENT_CONTRACT_PROFILE.stable_id_max_bytes
            && self.replication_tx_id_max_bytes
                == CURRENT_CONTRACT_PROFILE.replication_tx_id_max_bytes
            && self.cas_request_id_bytes == CURRENT_CONTRACT_PROFILE.cas_request_id_bytes
    }
}

pub const CURRENT_CONTRACT_PROFILE: ContractProfile = ContractProfile {
    wire_schema_revision: WIRE_SCHEMA_REVISION,
    error_set_revision: ERROR_SET_REVISION,
    max_restore_scan_page_records: RESTORE_SCAN_MAX_PAGE_SIZE as u32,
    max_restore_scan_page_payload_bytes: opc_session_store::RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES
        as u32,
    max_restore_scan_page_retained_bytes: opc_session_store::RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES
        as u32,
    max_restore_scan_examined_rows: opc_session_store::RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE
        as u32,
    max_restore_scan_examined_metadata_bytes:
        opc_session_store::RESTORE_SCAN_MAX_EXAMINED_METADATA_BYTES as u32,
    max_replication_log_page_entries: MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES as u32,
    max_batch_operations: MAX_SESSION_NET_BATCH_OPERATIONS as u32,
    max_rebuild_entries: MAX_SESSION_NET_REBUILD_ENTRIES as u32,
    max_replication_operation_depth: MAX_REPLICATION_OPERATION_DEPTH as u16,
    max_replication_operations_per_entry: MAX_REPLICATION_OPERATIONS_PER_ENTRY as u32,
    min_frame_size: MIN_NEGOTIATED_FRAME_SIZE as u32,
    max_frame_size: MAX_NEGOTIATED_FRAME_SIZE as u32,
    max_session_ttl_seconds: MAX_SESSION_TTL.as_secs(),
    owner_id_max_bytes: OWNER_ID_MAX_BYTES as u16,
    session_key_type_max_bytes: SESSION_KEY_TYPE_MAX_BYTES as u16,
    state_type_max_bytes: STATE_TYPE_MAX_BYTES as u16,
    stable_id_max_bytes: MAX_SESSION_NET_STABLE_ID_BYTES as u16,
    replication_tx_id_max_bytes: MAX_SESSION_NET_REPLICATION_TX_ID_BYTES as u16,
    cas_request_id_bytes: SESSION_NET_CAS_REQUEST_ID_BYTES as u16,
};

const _: () = {
    assert!(SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES <= u32::MAX as usize);
    assert!(RESTORE_SCAN_MAX_PAGE_SIZE <= u32::MAX as usize);
    assert!(opc_session_store::RESTORE_SCAN_MAX_PAGE_PAYLOAD_BYTES <= u32::MAX as usize);
    assert!(opc_session_store::RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES <= u32::MAX as usize);
    assert!(opc_session_store::RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE <= u32::MAX as usize);
    assert!(opc_session_store::RESTORE_SCAN_MAX_EXAMINED_METADATA_BYTES <= u32::MAX as usize);
    assert!(MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES <= u32::MAX as usize);
    assert!(MAX_SESSION_NET_BATCH_OPERATIONS <= u32::MAX as usize);
    assert!(MAX_SESSION_NET_REBUILD_ENTRIES <= u32::MAX as usize);
    assert!(MAX_REPLICATION_OPERATION_DEPTH <= u16::MAX as usize);
    assert!(MAX_REPLICATION_OPERATIONS_PER_ENTRY <= u32::MAX as usize);
    assert!(MIN_NEGOTIATED_FRAME_SIZE <= u32::MAX as usize);
    assert!(MAX_NEGOTIATED_FRAME_SIZE <= u32::MAX as usize);
    assert!(MIN_NEGOTIATED_FRAME_SIZE <= DEFAULT_MAX_FRAME_SIZE);
    assert!(DEFAULT_MAX_FRAME_SIZE <= MAX_NEGOTIATED_FRAME_SIZE);
    assert!(MIN_SESSION_CONSENSUS_FRAME_SIZE <= MAX_NEGOTIATED_FRAME_SIZE);
    assert!(OWNER_ID_MAX_BYTES <= u16::MAX as usize);
    assert!(SESSION_KEY_TYPE_MAX_BYTES <= u16::MAX as usize);
    assert!(STATE_TYPE_MAX_BYTES <= u16::MAX as usize);
    assert!(MAX_SESSION_NET_STABLE_ID_BYTES <= u16::MAX as usize);
    assert!(MAX_SESSION_NET_REPLICATION_TX_ID_BYTES <= u16::MAX as usize);
    assert!(SESSION_NET_CAS_REQUEST_ID_BYTES <= u16::MAX as usize);
};

/// Convert a local frame budget into the fixed-width v5 wire representation.
///
/// Only budgets in
/// [`MIN_NEGOTIATED_FRAME_SIZE`]..=[`MAX_NEGOTIATED_FRAME_SIZE`] implement the
/// post-bootstrap resource contract.
pub(crate) fn checked_wire_frame_size(size: usize) -> Result<u32, ProtocolError> {
    if !(MIN_NEGOTIATED_FRAME_SIZE..=MAX_NEGOTIATED_FRAME_SIZE).contains(&size) {
        return Err(ProtocolError::InvalidWireValue);
    }
    u32::try_from(size).map_err(|_| ProtocolError::InvalidWireValue)
}

/// Validate and convert a frame budget received from a v5 peer.
pub(crate) fn checked_frame_size(size: u32) -> Result<usize, ProtocolError> {
    let size = usize::try_from(size).map_err(|_| ProtocolError::InvalidWireValue)?;
    if !(MIN_NEGOTIATED_FRAME_SIZE..=MAX_NEGOTIATED_FRAME_SIZE).contains(&size) {
        return Err(ProtocolError::InvalidWireValue);
    }
    Ok(size)
}

/// Select the response budget enforced by a server for one v5 connection.
pub(crate) fn negotiate_response_frame_size(
    requested: u32,
    server_max_frame_size: usize,
) -> Result<u32, ProtocolError> {
    let requested = checked_frame_size(requested)?;
    let server_max = checked_frame_size(checked_wire_frame_size(server_max_frame_size)?)?;
    checked_wire_frame_size(requested.min(server_max))
}

/// Conservative application-payload budget executable over a response frame.
///
/// Session payload bytes serialize as a JSON byte array, where a worst-case
/// byte plus delimiter consumes four bytes. Reserving one bootstrap-minimum
/// block and dividing the remainder by eight leaves at least the same amount
/// again for bounded record/key metadata and the `Get`/CAS JSON envelopes.
/// Servers clamp backend `max_value_bytes` to this value; protocol tests
/// exercise the returned budget through exact `Get` and CAS wire
/// representations with every profile identifier at its maximum and
/// worst-case (`255`) payload bytes.
pub const fn conservative_payload_budget(frame_size: usize) -> usize {
    frame_size.saturating_sub(MIN_NEGOTIATED_FRAME_SIZE) / 8
}

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
/// can exchange a clean version mismatch. A v5 server accepts operations only
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_epoch: Option<u64>,
    #[serde(default)]
    pub handshake_nonce: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_profile: Option<ContractProfile>,
    /// Largest encoded post-bootstrap response frame the client will accept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_response_frame_size: Option<u32>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_epoch: Option<u64>,
    #[serde(default)]
    pub handshake_nonce: Option<uuid::Uuid>,
    /// Process-scoped server epoch that fences bounded direct-CAS retries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cas_idempotency_epoch: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_profile: Option<ContractProfile>,
    /// Response-frame budget selected by the server for this connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_response_frame_size: Option<u32>,
    /// Largest encoded post-bootstrap request frame the server will accept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_request_frame_size: Option<u32>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BootstrapHelloAckRef<'a> {
    contract_version: u32,
    server_replica_id: Option<&'a str>,
    accepted_client_replica_id: Option<&'a str>,
    cluster_id: Option<&'a str>,
    configuration_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    configuration_epoch: Option<u64>,
    handshake_nonce: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cas_idempotency_epoch: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    contract_profile: Option<ContractProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    accepted_response_frame_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    server_request_frame_size: Option<u32>,
}

/// The only frame shape decoded before a server authenticates a connection.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) enum BootstrapRequest {
    Hello(BootstrapHello),
}

/// The only frame shapes decoded by a client during bootstrap.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) enum BootstrapResponse {
    HelloAck(Box<BootstrapHelloAck>),
    HelloRejected { reason: HelloRejectReason },
}

/// First frame on a dedicated consensus-only connection.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionConsensusBootstrapHello {
    pub transport_revision: u16,
    pub contract_profile: SessionConsensusContractProfile,
    pub sender_replica_id: String,
    pub expected_server_replica_id: String,
    pub identity: SessionConsensusIdentity,
    pub sender_node_id: SessionConsensusNodeId,
    pub expected_server_node_id: SessionConsensusNodeId,
    pub handshake_nonce: uuid::Uuid,
    pub requested_response_frame_size: u32,
}

/// Authenticated acknowledgement for a consensus-only connection.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionConsensusBootstrapAck {
    pub transport_revision: u16,
    pub contract_profile: SessionConsensusContractProfile,
    pub identity: SessionConsensusIdentity,
    pub server_node_id: SessionConsensusNodeId,
    pub accepted_sender_node_id: SessionConsensusNodeId,
    pub handshake_nonce: uuid::Uuid,
    pub accepted_response_frame_size: u32,
    pub server_request_frame_size: u32,
}

/// Only bootstrap request admitted by the consensus ALPN.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) enum SessionConsensusBootstrapRequest {
    Hello(SessionConsensusBootstrapHello),
}

/// Fixed, redaction-safe consensus bootstrap result.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) enum SessionConsensusBootstrapResponse {
    Accepted(SessionConsensusBootstrapAck),
    Rejected(SessionConsensusPeerError),
}

/// The only post-bootstrap request shape admitted on the consensus ALPN.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) enum SessionConsensusTransportRequest {
    Call {
        call_id: uuid::Uuid,
        request: SessionConsensusWireRequest,
    },
}

/// The only post-bootstrap response shape emitted on the consensus ALPN.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) enum SessionConsensusTransportResponse {
    Call {
        call_id: uuid::Uuid,
        response: SessionConsensusWireResponse,
    },
}

/// Architecture-independent semantic restore-scan request carried by protocol v5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreScanWireRequest {
    scope: RestoreScanScope,
    cursor: Option<RestoreScanCursor>,
    limit: u32,
}

impl TryFrom<&RestoreScanRequest> for RestoreScanWireRequest {
    type Error = StoreError;

    fn try_from(request: &RestoreScanRequest) -> Result<Self, Self::Error> {
        request.validate()?;
        let limit = u32::try_from(request.limit).map_err(|_| {
            StoreError::InvalidRestoreScanRequest(
                "restore scan limit exceeds the protocol range".to_string(),
            )
        })?;
        Ok(Self {
            scope: request.scope.clone(),
            cursor: request.cursor.clone(),
            limit,
        })
    }
}

impl TryFrom<RestoreScanWireRequest> for RestoreScanRequest {
    type Error = StoreError;

    fn try_from(request: RestoreScanWireRequest) -> Result<Self, Self::Error> {
        let limit = usize::try_from(request.limit).map_err(|_| {
            StoreError::InvalidRestoreScanRequest(
                "restore scan limit is not representable on this server".to_string(),
            )
        })?;
        let request = Self {
            scope: request.scope,
            cursor: request.cursor.clone(),
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
        configuration_epoch: Option<u64>,
        handshake_nonce: Option<uuid::Uuid>,
        contract_profile: Option<ContractProfile>,
        requested_response_frame_size: Option<u32>,
    },
    Capabilities,
    Get {
        key: SessionKey,
    },
    CompareAndSet {
        op: CompareAndSet,
        request_id: Option<String>,
        /// Server-issued process epoch from the authenticated bootstrap.
        idempotency_epoch: Option<String>,
    },
    DeleteFenced {
        lease: LeaseGuard,
    },
    RefreshTtl {
        lease: LeaseGuard,
        ttl: Duration,
    },
    RecordExpiryPreflight {
        preflights: Vec<RecordExpiryPreflight>,
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
        configuration_epoch: Option<u64>,
        handshake_nonce: Option<uuid::Uuid>,
        cas_idempotency_epoch: Option<uuid::Uuid>,
        contract_profile: Option<ContractProfile>,
        accepted_response_frame_size: Option<u32>,
        server_request_frame_size: Option<u32>,
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
    RecordExpiryPreflight(Result<(), opc_session_store::error::StoreError>),
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
    /// Authenticated proof that the server retired this connection before
    /// dispatching the one outstanding request.
    ///
    /// A client may retry only after decoding this complete frame. EOF,
    /// partial frames, and generic errors remain ambiguous for mutations.
    ConnectionRetiring,
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionOpExpectation {
    Get(SessionKey),
    CompareAndSet(SessionKey),
    DeleteFenced,
    RefreshTtl,
}

pub(crate) fn bounded_session_op_expectations(
    ops: &[SessionOp],
) -> Result<Vec<SessionOpExpectation>, StoreError> {
    if ops.len() > MAX_SESSION_NET_BATCH_OPERATIONS {
        return Err(StoreError::ReplicationOperationLimitExceeded);
    }
    Ok(ops
        .iter()
        .map(|op| match op {
            SessionOp::Get { key } => SessionOpExpectation::Get(key.clone()),
            SessionOp::CompareAndSet(op) => SessionOpExpectation::CompareAndSet(op.key.clone()),
            SessionOp::DeleteFenced { .. } => SessionOpExpectation::DeleteFenced,
            SessionOp::RefreshTtl { .. } => SessionOpExpectation::RefreshTtl,
        })
        .collect())
}

pub(crate) fn get_result_matches_key(
    expected_key: &SessionKey,
    result: &Result<Option<StoredSessionRecord>, StoreError>,
) -> bool {
    !matches!(result, Ok(Some(record)) if record.key != *expected_key)
}

pub(crate) fn compare_and_set_result_matches_key(
    expected_key: &SessionKey,
    result: &Result<CompareAndSetResult, StoreError>,
) -> bool {
    !matches!(
        result,
        Ok(CompareAndSetResult::Conflict {
            current: Some(record)
        }) if record.key != *expected_key
    )
}

pub(crate) fn session_op_results_match_expectations(
    expected: &[SessionOpExpectation],
    results: &[SessionOpResult],
) -> bool {
    expected.len() == results.len()
        && expected
            .iter()
            .zip(results)
            .all(|(expected, result)| match (expected, result) {
                (SessionOpExpectation::Get(key), SessionOpResult::Get(result)) => {
                    get_result_matches_key(key, result)
                        && !matches!(
                            result,
                            Err(StoreError::CasIdempotencyOutcomeUnavailable
                                | StoreError::BackendOperationOutcomeUnavailable)
                        )
                }
                (
                    SessionOpExpectation::CompareAndSet(key),
                    SessionOpResult::CompareAndSet(result),
                ) => {
                    compare_and_set_result_matches_key(key, result)
                        && !matches!(result, Err(StoreError::BackendOperationOutcomeUnavailable))
                }
                (SessionOpExpectation::DeleteFenced, SessionOpResult::DeleteFenced(result))
                | (SessionOpExpectation::RefreshTtl, SessionOpResult::RefreshTtl(result)) => {
                    !matches!(result, Err(StoreError::CasIdempotencyOutcomeUnavailable))
                }
                _ => false,
            })
}

fn validate_session_key_profile(key: &SessionKey) -> Result<(), WireConversionError> {
    if key.stable_id.is_empty() || key.stable_id.len() > MAX_SESSION_NET_STABLE_ID_BYTES {
        return Err(WireConversionError(
            "session stable ID violates the v5 transport profile",
        ));
    }
    Ok(())
}

fn validate_record_profile(record: &StoredSessionRecord) -> Result<(), WireConversionError> {
    validate_session_key_profile(&record.key)
}

fn validate_record_payload_limit(
    record: &StoredSessionRecord,
    max: usize,
) -> Result<(), StoreError> {
    let actual = record.payload.len();
    if actual > max {
        return Err(StoreError::PayloadTooLarge { actual, max });
    }
    Ok(())
}

fn validate_replication_payload_limit(
    entry: &ReplicationEntry,
    max: usize,
) -> Result<(), StoreError> {
    let mut pending = vec![std::slice::from_ref(&entry.op).iter()];
    while let Some(current) = pending.last_mut() {
        match current.next() {
            Some(ReplicationOp::CompareAndSet { new_record, .. }) => {
                validate_record_payload_limit(new_record, max)?;
            }
            Some(ReplicationOp::Batch { ops }) => pending.push(ops.iter()),
            Some(
                ReplicationOp::DeleteFenced { .. }
                | ReplicationOp::RefreshTtl { .. }
                | ReplicationOp::AcquireLease { .. }
                | ReplicationOp::RenewLease { .. }
                | ReplicationOp::ReleaseLease { .. },
            ) => {}
            None => {
                pending.pop();
            }
        }
    }
    Ok(())
}

/// Validate every record payload carried by a request against one transport value limit.
///
/// Nested replication batches use an iterator stack, so traversal allocates with depth rather
/// than attacker-controlled batch width. The whole request is checked before any dispatch.
pub(crate) fn validate_request_payload_limit(
    request: &Request,
    max: usize,
) -> Result<(), StoreError> {
    match request {
        Request::CompareAndSet { op, .. } => validate_record_payload_limit(&op.new_record, max),
        Request::Batch { ops } => ops.iter().try_for_each(|op| match op {
            SessionOp::CompareAndSet(op) => validate_record_payload_limit(&op.new_record, max),
            SessionOp::Get { .. }
            | SessionOp::DeleteFenced { .. }
            | SessionOp::RefreshTtl { .. } => Ok(()),
        }),
        Request::ReplicateEntry { entry } => validate_replication_payload_limit(entry, max),
        Request::RebuildReplicationState { entries } => entries
            .iter()
            .try_for_each(|entry| validate_replication_payload_limit(entry, max)),
        Request::Hello { .. }
        | Request::Capabilities
        | Request::Get { .. }
        | Request::DeleteFenced { .. }
        | Request::RefreshTtl { .. }
        | Request::RecordExpiryPreflight { .. }
        | Request::ScanRestoreRecords { .. }
        | Request::MaxReplicationSequence
        | Request::GetReplicationLog { .. }
        | Request::Watch { .. }
        | Request::NextLeaseInfo
        | Request::AcquireLease { .. }
        | Request::RenewLease { .. }
        | Request::ReleaseLease { .. } => Ok(()),
    }
}

fn validate_lease_profile(lease: &LeaseGuard) -> Result<(), WireConversionError> {
    validate_session_key_profile(lease.key())?;
    if lease.fence().get() == 0 {
        return Err(WireConversionError(
            "lease fence violates the v5 transport profile",
        ));
    }
    if lease.credential_id() == 0 {
        return Err(WireConversionError(
            "lease credential violates the v5 transport profile",
        ));
    }
    if lease.expires_at() < lease.acquired_at() {
        return Err(WireConversionError(
            "lease lifetime violates the v5 transport profile",
        ));
    }
    Ok(())
}

fn validate_compare_and_set_profile(op: &CompareAndSet) -> Result<(), WireConversionError> {
    validate_session_key_profile(&op.key)?;
    validate_lease_profile(&op.lease)?;
    validate_record_profile(&op.new_record)
}

fn validate_compare_and_set_result_profile(
    result: &CompareAndSetResult,
) -> Result<(), WireConversionError> {
    if let CompareAndSetResult::Conflict {
        current: Some(record),
    } = result
    {
        validate_record_profile(record)?;
    }
    Ok(())
}

fn validate_session_op_profile(op: &SessionOp) -> Result<(), WireConversionError> {
    op.validate_ttls()
        .map_err(|_| WireConversionError("session TTL violates the v5 transport profile"))?;
    validate_session_op_retained_profile(op)
}

fn validate_session_op_retained_profile(op: &SessionOp) -> Result<(), WireConversionError> {
    match op {
        SessionOp::Get { key } => validate_session_key_profile(key),
        SessionOp::CompareAndSet(op) => validate_compare_and_set_profile(op),
        SessionOp::DeleteFenced { lease } | SessionOp::RefreshTtl { lease, .. } => {
            validate_lease_profile(lease)
        }
    }
}

/// Validate only request fields that may be retained or dispatched without a
/// family-specific typed rejection.
///
/// Known semantic failures such as an invalid TTL or replication sequence are
/// deliberately left for the authenticated server dispatcher. That preserves
/// the protocol's typed error and keeps the connection usable, while local
/// callers still receive the stricter pre-I/O validation in
/// [`validate_request_profile`].
fn validate_inbound_request_profile(request: &Request) -> Result<(), WireConversionError> {
    match request {
        Request::Get { key } | Request::AcquireLease { key, .. } => {
            validate_session_key_profile(key)
        }
        Request::CompareAndSet { op, .. } => validate_compare_and_set_profile(op),
        Request::DeleteFenced { lease }
        | Request::RefreshTtl { lease, .. }
        | Request::RenewLease { lease, .. }
        | Request::ReleaseLease { lease } => validate_lease_profile(lease),
        Request::Batch { ops } => ops
            .iter()
            .try_for_each(validate_session_op_retained_profile),
        Request::RecordExpiryPreflight { preflights } => {
            opc_session_store::validate_record_expiry_preflights_profile(preflights)
                .map_err(|_| WireConversionError("record expiry violates the v5 transport profile"))
        }
        Request::ReplicateEntry { entry } => validate_replication_retained_profile(entry),
        Request::RebuildReplicationState { entries } => entries
            .iter()
            .try_for_each(validate_replication_retained_profile),
        Request::Hello { .. }
        | Request::Capabilities
        | Request::ScanRestoreRecords { .. }
        | Request::MaxReplicationSequence
        | Request::GetReplicationLog { .. }
        | Request::Watch { .. }
        | Request::NextLeaseInfo => Ok(()),
    }
}

fn validate_session_op_result_profile(result: &SessionOpResult) -> Result<(), WireConversionError> {
    match result {
        SessionOpResult::Get(Ok(Some(record))) => validate_record_profile(record),
        SessionOpResult::CompareAndSet(Ok(result)) => {
            validate_compare_and_set_result_profile(result)
        }
        SessionOpResult::Get(Ok(None) | Err(_))
        | SessionOpResult::CompareAndSet(Err(_))
        | SessionOpResult::DeleteFenced(_)
        | SessionOpResult::RefreshTtl(_) => Ok(()),
    }
}

fn validate_replication_entry_profile(entry: &ReplicationEntry) -> Result<(), WireConversionError> {
    entry
        .validate()
        .map_err(|_| WireConversionError("replication entry violates the v5 contract"))?;
    validate_replication_retained_profile(entry)
}

fn validate_replication_retained_profile(
    entry: &ReplicationEntry,
) -> Result<(), WireConversionError> {
    let mut pending = Vec::with_capacity(MAX_REPLICATION_OPERATION_DEPTH);
    pending.push(&entry.op);
    while let Some(op) = pending.pop() {
        match op {
            ReplicationOp::CompareAndSet {
                key, new_record, ..
            } => {
                validate_session_key_profile(key)?;
                validate_record_profile(new_record)?;
            }
            ReplicationOp::DeleteFenced { key, .. }
            | ReplicationOp::RefreshTtl { key, .. }
            | ReplicationOp::AcquireLease { key, .. }
            | ReplicationOp::RenewLease { key, .. }
            | ReplicationOp::ReleaseLease { key, .. } => validate_session_key_profile(key)?,
            ReplicationOp::Batch { ops } => pending.extend(ops.iter().rev()),
        }
    }
    Ok(())
}

fn discard_replication_entry_iteratively(entry: ReplicationEntry) {
    let ReplicationEntry { op, .. } = entry;
    let mut pending = vec![vec![op].into_iter()];
    while let Some(current) = pending.last_mut() {
        match current.next() {
            Some(ReplicationOp::Batch { ops }) => pending.push(ops.into_iter()),
            Some(_) => {}
            None => {
                pending.pop();
            }
        }
    }
}

fn discard_replication_entries_iteratively(entries: Vec<ReplicationEntry>) {
    entries
        .into_iter()
        .for_each(discard_replication_entry_iteratively);
}

fn into_profile_validated_replication_entry(
    entry: ReplicationEntry,
) -> Result<ReplicationEntry, WireConversionError> {
    let entry = entry
        .into_validated()
        .map_err(|_| WireConversionError("replication entry violates the v5 contract"))?;
    match validate_replication_retained_profile(&entry) {
        Ok(()) => Ok(entry),
        Err(error) => {
            discard_replication_entry_iteratively(entry);
            Err(error)
        }
    }
}

fn parse_canonical_cas_request_id(value: &str) -> Result<uuid::Uuid, WireConversionError> {
    if value.len() != SESSION_NET_CAS_REQUEST_ID_BYTES {
        return Err(WireConversionError(
            "CAS request ID must be a canonical UUID",
        ));
    }
    let request_id = uuid::Uuid::parse_str(value)
        .map_err(|_| WireConversionError("CAS request ID must be a canonical UUID"))?;
    if request_id.hyphenated().to_string() != value {
        return Err(WireConversionError(
            "CAS request ID must be a canonical UUID",
        ));
    }
    Ok(request_id)
}

/// Validate bounded retained identifiers and scalar/collection profile fields without encoding.
///
/// The serializer performs the same checks again. Clients use this allocation-light pass before
/// DNS or connection work so malformed local requests fail without observable network activity.
pub(crate) fn validate_request_profile(request: &Request) -> Result<(), WireConversionError> {
    match request {
        Request::Get { key } => validate_session_key_profile(key),
        Request::AcquireLease { key, ttl, .. } => {
            validate_session_key_profile(key)?;
            opc_session_store::validate_session_ttl(*ttl)
                .map_err(|_| WireConversionError("session TTL violates the v5 transport profile"))
        }
        Request::CompareAndSet {
            op,
            request_id,
            idempotency_epoch,
        } => {
            validate_compare_and_set_profile(op)?;
            if let Some(request_id) = request_id {
                parse_canonical_cas_request_id(request_id)?;
            }
            if let Some(idempotency_epoch) = idempotency_epoch {
                parse_canonical_cas_request_id(idempotency_epoch)?;
            }
            Ok(())
        }
        Request::DeleteFenced { lease } | Request::ReleaseLease { lease } => {
            validate_lease_profile(lease)
        }
        Request::RefreshTtl { lease, ttl } | Request::RenewLease { lease, ttl } => {
            validate_lease_profile(lease)?;
            opc_session_store::validate_session_ttl(*ttl)
                .map_err(|_| WireConversionError("session TTL violates the v5 transport profile"))
        }
        Request::Batch { ops } => {
            if ops.len() > MAX_SESSION_NET_BATCH_OPERATIONS {
                return Err(WireConversionError("batch exceeds the v5 operation limit"));
            }
            ops.iter().try_for_each(validate_session_op_profile)
        }
        Request::RecordExpiryPreflight { preflights } => {
            opc_session_store::validate_record_expiry_preflights_profile(preflights)
                .map_err(|_| WireConversionError("record expiry violates the v5 transport profile"))
        }
        Request::ScanRestoreRecords {
            request,
            max_response_frame_size,
        } => {
            RestoreScanRequest::try_from(request.clone()).map_err(|_| {
                WireConversionError("restore scan request violates the v5 contract")
            })?;
            checked_frame_size(*max_response_frame_size).map_err(|_| {
                WireConversionError("restore scan frame size violates the v5 contract")
            })?;
            Ok(())
        }
        Request::GetReplicationLog { start, limit } => {
            ReplicationLogRange::try_new(*start, *limit).map_err(|_| {
                WireConversionError("replication log range violates the v5 contract")
            })?;
            wire_u32_from_usize(
                *limit,
                MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES,
                "replication log page exceeds the v5 operation limit",
            )?;
            Ok(())
        }
        Request::ReplicateEntry { entry } => validate_replication_entry_profile(entry),
        Request::RebuildReplicationState { entries } => {
            if entries.len() > MAX_SESSION_NET_REBUILD_ENTRIES {
                return Err(WireConversionError(
                    "replication rebuild exceeds the v5 entry limit",
                ));
            }
            entries
                .iter()
                .try_for_each(validate_replication_entry_profile)
        }
        Request::Hello { .. }
        | Request::Capabilities
        | Request::MaxReplicationSequence
        | Request::Watch { .. }
        | Request::NextLeaseInfo => Ok(()),
    }
}

fn validate_response_profile(response: &Response) -> Result<(), WireConversionError> {
    match response {
        Response::Get(Ok(Some(record))) => validate_record_profile(record),
        Response::CompareAndSet(Ok(result)) => validate_compare_and_set_result_profile(result),
        Response::Batch(Ok(results)) => results
            .iter()
            .try_for_each(validate_session_op_result_profile),
        Response::ScanRestoreRecords(Ok(page)) => {
            page.records.iter().try_for_each(validate_record_profile)
        }
        Response::GetReplicationLog(Ok(entries)) => entries
            .iter()
            .try_for_each(validate_replication_entry_profile),
        Response::WatchEntry(Ok(entry)) => validate_replication_entry_profile(entry),
        Response::AcquireLease(Ok(lease)) | Response::RenewLease(Ok(lease)) => {
            validate_lease_profile(lease)
        }
        Response::HelloAck { .. }
        | Response::HelloRejected { .. }
        | Response::Capabilities(_)
        | Response::Get(Ok(None) | Err(_))
        | Response::CompareAndSet(Err(_))
        | Response::DeleteFenced(_)
        | Response::RefreshTtl(_)
        | Response::RecordExpiryPreflight(_)
        | Response::Batch(Err(_))
        | Response::ScanRestoreRecords(Err(_))
        | Response::MaxReplicationSequence(_)
        | Response::GetReplicationLog(Err(_))
        | Response::ReplicateEntry(_)
        | Response::RebuildReplicationState(_)
        | Response::WatchStream
        | Response::WatchEntry(Err(_))
        | Response::NextLeaseInfo(_)
        | Response::AcquireLease(Err(_))
        | Response::RenewLease(Err(_))
        | Response::ReleaseLease(_)
        | Response::ConnectionRetiring
        | Response::Error { .. } => Ok(()),
    }
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
    cursor: Option<RestoreScanCursor>,
    limit: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRestoreScanRequest {
    scope: RestoreScanScope,
    cursor: Option<RestoreScanCursor>,
    limit: u32,
}

impl<'a> TryFrom<&'a RestoreScanWireRequest> for WireRestoreScanRequestRef<'a> {
    type Error = WireConversionError;

    fn try_from(request: &'a RestoreScanWireRequest) -> Result<Self, Self::Error> {
        let domain = RestoreScanRequest::try_from(request.clone())
            .map_err(|_| WireConversionError("restore scan request violates the v5 contract"))?;
        domain
            .validate()
            .map_err(|_| WireConversionError("restore scan request violates the v5 contract"))?;
        Ok(Self {
            scope: &request.scope,
            cursor: request.cursor.clone(),
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
    next_cursor: Option<RestoreScanCursor>,
    cursor_profile: RestoreScanCursorProfile,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRestoreScanPage {
    records: BoundedVec<StoredSessionRecord, RESTORE_SCAN_MAX_PAGE_SIZE>,
    excluded_count: u64,
    next_cursor: Option<RestoreScanCursor>,
    cursor_profile: RestoreScanCursorProfile,
}

impl<'a> TryFrom<&'a RestoreScanPage> for WireRestoreScanPageRef<'a> {
    type Error = WireConversionError;

    fn try_from(page: &'a RestoreScanPage) -> Result<Self, Self::Error> {
        if page.records.len() > RESTORE_SCAN_MAX_PAGE_SIZE
            || page.loaded_count != page.records.len()
            || page.complete != page.next_cursor.is_none()
            || !matches!(
                page.retained_bytes(),
                Ok(bytes) if bytes <= opc_session_store::RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES
            )
        {
            return Err(WireConversionError(
                "restore scan page violates the v5 contract",
            ));
        }
        page.records.iter().try_for_each(validate_record_profile)?;
        Ok(Self {
            records: &page.records,
            excluded_count: wire_u64_from_usize(
                page.excluded_count,
                "restore excluded count exceeds the v5 wire range",
            )?,
            next_cursor: page.next_cursor.clone(),
            cursor_profile: page.cursor_profile,
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
        let mut result = Self::new(page.records.into_inner(), excluded_count, page.next_cursor);
        result.cursor_profile = page.cursor_profile;
        Ok(result)
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
                "capability size exceeds the v5 wire range",
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
#[serde(deny_unknown_fields)]
enum WireStoreError {
    NotFound,
    StaleFence,
    CasConflict,
    CasIdempotencyConflict,
    CasIdempotencyOutcomeUnavailable,
    BackendOperationOutcomeUnavailable,
    CapabilityNotSupported(String),
    BackendUnavailable(String),
    InvalidKey(String),
    InvalidReplicationSequence,
    InvalidReplicationLogRange,
    ReplicationLogPageTooLarge { requested: u64, max: u64 },
    ReplicationLogCursorCompacted { resume_from: u64 },
    ReplicationWatchCatchUpRequired,
    ReplicationOperationLimitExceeded,
    InvalidSessionTtl,
    InvalidRecordExpiry,
    RecordExpiryPreflightLimitExceeded,
    LeaseHeld,
    LeaseExpired,
    Crypto(String),
    Serialization(String),
    PayloadTooLarge { actual: u64, max: u64 },
    InvalidRestoreScanRequest(String),
    InvalidRestoreScanResponse(String),
    RestoreScanPageTooLarge { requested: u64, max: u64 },
    RestoreScanCursorStale,
    RestoreScanWorkBudgetExceeded,
    RestoreScanResponseTooLarge { max_bytes: u64 },
}

/// Borrowed outbound form so serializing backend errors never clones
/// peer-controlled or backend-provided strings.
#[derive(Serialize)]
enum WireStoreErrorRef<'a> {
    NotFound,
    StaleFence,
    CasConflict,
    CasIdempotencyConflict,
    CasIdempotencyOutcomeUnavailable,
    BackendOperationOutcomeUnavailable,
    CapabilityNotSupported(&'a str),
    BackendUnavailable(&'a str),
    InvalidKey(&'a str),
    InvalidReplicationSequence,
    InvalidReplicationLogRange,
    ReplicationLogPageTooLarge { requested: u64, max: u64 },
    ReplicationLogCursorCompacted { resume_from: u64 },
    ReplicationWatchCatchUpRequired,
    ReplicationOperationLimitExceeded,
    InvalidSessionTtl,
    InvalidRecordExpiry,
    RecordExpiryPreflightLimitExceeded,
    LeaseHeld,
    LeaseExpired,
    Crypto(&'a str),
    Serialization(&'a str),
    PayloadTooLarge { actual: u64, max: u64 },
    InvalidRestoreScanRequest(&'a str),
    InvalidRestoreScanResponse(&'a str),
    RestoreScanPageTooLarge { requested: u64, max: u64 },
    RestoreScanCursorStale,
    RestoreScanWorkBudgetExceeded,
    RestoreScanResponseTooLarge { max_bytes: u64 },
}

fn safe_capability_name(value: &str) -> &'static str {
    match value {
        "atomic_compare_and_set" => "atomic_compare_and_set",
        "monotonic_fencing_token" => "monotonic_fencing_token",
        "per_key_ttl" => "per_key_ttl",
        "batch_write" => "batch_write",
        "ordered_replication_log" => "ordered_replication_log",
        "restore_scan" => "restore_scan",
        "watch" => "watch",
        "lease_coordination" => "lease_coordination",
        "record_expiry_preflight" => "record_expiry_preflight",
        _ => "unknown_capability",
    }
}

impl<'a> TryFrom<&'a StoreError> for WireStoreErrorRef<'a> {
    type Error = WireConversionError;

    fn try_from(error: &'a StoreError) -> Result<Self, Self::Error> {
        Ok(match error {
            StoreError::NotFound => Self::NotFound,
            StoreError::StaleFence => Self::StaleFence,
            StoreError::CasConflict => Self::CasConflict,
            StoreError::CasIdempotencyConflict => Self::CasIdempotencyConflict,
            StoreError::CasIdempotencyOutcomeUnavailable => Self::CasIdempotencyOutcomeUnavailable,
            StoreError::BackendOperationOutcomeUnavailable => {
                Self::BackendOperationOutcomeUnavailable
            }
            StoreError::CapabilityNotSupported(message) => {
                Self::CapabilityNotSupported(safe_capability_name(message))
            }
            StoreError::BackendUnavailable(_) => Self::BackendUnavailable("backend unavailable"),
            StoreError::InvalidKey(_) => Self::InvalidKey("invalid key"),
            StoreError::InvalidReplicationSequence => Self::InvalidReplicationSequence,
            StoreError::InvalidReplicationLogRange => Self::InvalidReplicationLogRange,
            StoreError::ReplicationLogPageTooLarge { requested, max } => {
                Self::ReplicationLogPageTooLarge {
                    requested: wire_u64_from_usize(
                        *requested,
                        "replication page size exceeds the v5 wire range",
                    )?,
                    max: wire_u64_from_usize(
                        *max,
                        "replication page limit exceeds the v5 wire range",
                    )?,
                }
            }
            StoreError::ReplicationLogCursorCompacted { resume_from } => {
                Self::ReplicationLogCursorCompacted {
                    resume_from: *resume_from,
                }
            }
            StoreError::ReplicationWatchCatchUpRequired => Self::ReplicationWatchCatchUpRequired,
            StoreError::ReplicationOperationLimitExceeded => {
                Self::ReplicationOperationLimitExceeded
            }
            StoreError::InvalidSessionTtl => Self::InvalidSessionTtl,
            StoreError::InvalidRecordExpiry => Self::InvalidRecordExpiry,
            StoreError::RecordExpiryPreflightLimitExceeded => {
                Self::RecordExpiryPreflightLimitExceeded
            }
            StoreError::LeaseHeld => Self::LeaseHeld,
            StoreError::LeaseExpired => Self::LeaseExpired,
            StoreError::Crypto(_) => Self::Crypto("cryptographic operation failed"),
            StoreError::Serialization(_) => Self::Serialization("serialization failed"),
            StoreError::PayloadTooLarge { actual, max } => Self::PayloadTooLarge {
                actual: wire_u64_from_usize(*actual, "payload size exceeds the v5 wire range")?,
                max: wire_u64_from_usize(*max, "payload limit exceeds the v5 wire range")?,
            },
            StoreError::InvalidRestoreScanRequest(_) => {
                Self::InvalidRestoreScanRequest("restore scan request rejected")
            }
            StoreError::InvalidRestoreScanResponse(_) => {
                Self::InvalidRestoreScanResponse("restore scan response rejected")
            }
            StoreError::RestoreScanPageTooLarge { requested, max } => {
                Self::RestoreScanPageTooLarge {
                    requested: wire_u64_from_usize(
                        *requested,
                        "restore page size exceeds the v5 wire range",
                    )?,
                    max: wire_u64_from_usize(*max, "restore page limit exceeds the v5 wire range")?,
                }
            }
            StoreError::RestoreScanCursorStale => Self::RestoreScanCursorStale,
            StoreError::RestoreScanWorkBudgetExceeded => Self::RestoreScanWorkBudgetExceeded,
            StoreError::RestoreScanResponseTooLarge { max_bytes } => {
                Self::RestoreScanResponseTooLarge {
                    max_bytes: wire_u64_from_usize(
                        *max_bytes,
                        "restore response limit exceeds the v5 wire range",
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
            WireStoreError::CasIdempotencyConflict => Self::CasIdempotencyConflict,
            WireStoreError::CasIdempotencyOutcomeUnavailable => {
                Self::CasIdempotencyOutcomeUnavailable
            }
            WireStoreError::BackendOperationOutcomeUnavailable => {
                Self::BackendOperationOutcomeUnavailable
            }
            WireStoreError::CapabilityNotSupported(message) => {
                Self::CapabilityNotSupported(safe_capability_name(&message).to_string())
            }
            WireStoreError::BackendUnavailable(_) => {
                Self::BackendUnavailable("backend unavailable".to_string())
            }
            WireStoreError::InvalidKey(_) => Self::InvalidKey("invalid key".to_string()),
            WireStoreError::InvalidReplicationSequence => Self::InvalidReplicationSequence,
            WireStoreError::InvalidReplicationLogRange => Self::InvalidReplicationLogRange,
            WireStoreError::ReplicationLogPageTooLarge { requested, max } => {
                Self::ReplicationLogPageTooLarge {
                    requested: usize_from_wire_u64(
                        requested,
                        "replication page size is not representable on this peer",
                    )?,
                    max: usize_from_wire_u64(
                        max,
                        "replication page limit is not representable on this peer",
                    )?,
                }
            }
            WireStoreError::ReplicationLogCursorCompacted { resume_from } => {
                Self::ReplicationLogCursorCompacted { resume_from }
            }
            WireStoreError::ReplicationWatchCatchUpRequired => {
                Self::ReplicationWatchCatchUpRequired
            }
            WireStoreError::ReplicationOperationLimitExceeded => {
                Self::ReplicationOperationLimitExceeded
            }
            WireStoreError::InvalidSessionTtl => Self::InvalidSessionTtl,
            WireStoreError::InvalidRecordExpiry => Self::InvalidRecordExpiry,
            WireStoreError::RecordExpiryPreflightLimitExceeded => {
                Self::RecordExpiryPreflightLimitExceeded
            }
            WireStoreError::LeaseHeld => Self::LeaseHeld,
            WireStoreError::LeaseExpired => Self::LeaseExpired,
            WireStoreError::Crypto(_) => Self::Crypto("cryptographic operation failed".to_string()),
            WireStoreError::Serialization(_) => {
                Self::Serialization("serialization failed".to_string())
            }
            WireStoreError::PayloadTooLarge { actual, max } => Self::PayloadTooLarge {
                actual: usize_from_wire_u64(
                    actual,
                    "payload size is not representable on this peer",
                )?,
                max: usize_from_wire_u64(max, "payload limit is not representable on this peer")?,
            },
            WireStoreError::InvalidRestoreScanRequest(_) => {
                Self::InvalidRestoreScanRequest("restore scan request rejected".to_string())
            }
            WireStoreError::InvalidRestoreScanResponse(_) => {
                Self::InvalidRestoreScanResponse("restore scan response rejected".to_string())
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
            WireStoreError::RestoreScanCursorStale => Self::RestoreScanCursorStale,
            WireStoreError::RestoreScanWorkBudgetExceeded => Self::RestoreScanWorkBudgetExceeded,
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
enum WireLeaseErrorRef<'a> {
    AlreadyHeld,
    Expired,
    StaleFence,
    NotFound,
    InvalidSessionTtl,
    OperationOutcomeUnavailable,
    Backend(&'a str),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum WireLeaseError {
    AlreadyHeld,
    Expired,
    StaleFence,
    NotFound,
    InvalidSessionTtl,
    OperationOutcomeUnavailable,
    Backend(String),
}

impl<'a> From<&'a LeaseError> for WireLeaseErrorRef<'a> {
    fn from(error: &'a LeaseError) -> Self {
        match error {
            LeaseError::AlreadyHeld => Self::AlreadyHeld,
            LeaseError::Expired => Self::Expired,
            LeaseError::StaleFence => Self::StaleFence,
            LeaseError::NotFound => Self::NotFound,
            LeaseError::InvalidSessionTtl => Self::InvalidSessionTtl,
            LeaseError::OperationOutcomeUnavailable => Self::OperationOutcomeUnavailable,
            LeaseError::Backend(_) => Self::Backend("lease backend unavailable"),
        }
    }
}

impl From<WireLeaseError> for LeaseError {
    fn from(error: WireLeaseError) -> Self {
        match error {
            WireLeaseError::AlreadyHeld => Self::AlreadyHeld,
            WireLeaseError::Expired => Self::Expired,
            WireLeaseError::StaleFence => Self::StaleFence,
            WireLeaseError::NotFound => Self::NotFound,
            WireLeaseError::InvalidSessionTtl => Self::InvalidSessionTtl,
            WireLeaseError::OperationOutcomeUnavailable => Self::OperationOutcomeUnavailable,
            WireLeaseError::Backend(message) => {
                drop(message);
                Self::Backend("lease backend unavailable".to_string())
            }
        }
    }
}

fn wire_lease_result_ref<T>(result: &Result<T, LeaseError>) -> Result<&T, WireLeaseErrorRef<'_>> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => Err(WireLeaseErrorRef::from(error)),
    }
}

fn domain_lease_result<T>(result: Result<T, WireLeaseError>) -> Result<T, LeaseError> {
    result.map_err(LeaseError::from)
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
#[serde(deny_unknown_fields)]
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
    tx_id: ReplicationTxId,
    operation_nodes: WireReplicationNodes,
    timestamp: Timestamp,
}

impl<'a> TryFrom<&'a ReplicationEntry> for WireReplicationEntryRef<'a> {
    type Error = WireConversionError;

    fn try_from(entry: &'a ReplicationEntry) -> Result<Self, Self::Error> {
        validate_replication_entry_profile(entry)?;

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
                        WireConversionError("replication batch exceeds the v5 wire range")
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
                "replication entry violates the v5 contract",
            ));
        }
        Ok(Self {
            sequence: entry.sequence,
            tx_id: entry.tx_id.as_str(),
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
                    "replication operation tree exceeds the v5 node limit",
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
    into_profile_validated_replication_entry(ReplicationEntry::try_from(entry)?)
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
                "replication operation tree exceeds the v5 depth limit",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WireCasRequestId(uuid::Uuid);

impl Serialize for WireCasRequestId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.hyphenated().to_string())
    }
}

struct WireCasRequestIdVisitor;

impl Visitor<'_> for WireCasRequestIdVisitor {
    type Value = WireCasRequestId;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a canonical lowercase hyphenated UUID")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if value.len() != SESSION_NET_CAS_REQUEST_ID_BYTES {
            return Err(E::custom("CAS request ID must be a canonical UUID"));
        }
        let request_id = parse_canonical_cas_request_id(value)
            .map_err(|_| E::custom("CAS request ID must be a canonical UUID"))?;
        Ok(WireCasRequestId(request_id))
    }
}

impl<'de> Deserialize<'de> for WireCasRequestId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_str(WireCasRequestIdVisitor)
    }
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
        request_id: Option<WireCasRequestId>,
        #[serde(skip_serializing_if = "Option::is_none")]
        idempotency_epoch: Option<WireCasRequestId>,
    },
    DeleteFenced {
        lease: &'a LeaseGuard,
    },
    RefreshTtl {
        lease: &'a LeaseGuard,
        ttl: &'a Duration,
    },
    RecordExpiryPreflight {
        preflights: &'a [RecordExpiryPreflight],
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
        entries: WireReplicationEntriesRef<'a>,
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
#[serde(deny_unknown_fields)]
enum WireRequest {
    Hello(BootstrapHello),
    Capabilities,
    Get {
        key: SessionKey,
    },
    CompareAndSet {
        op: CompareAndSet,
        #[serde(default)]
        request_id: Option<WireCasRequestId>,
        #[serde(default)]
        idempotency_epoch: Option<WireCasRequestId>,
    },
    DeleteFenced {
        lease: LeaseGuard,
    },
    RefreshTtl {
        lease: LeaseGuard,
        ttl: Duration,
    },
    RecordExpiryPreflight {
        preflights: BoundedVec<RecordExpiryPreflight, MAX_RECORD_EXPIRY_PREFLIGHTS>,
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
        validate_request_profile(request)?;
        Ok(match request {
            Request::Hello {
                contract_version,
                node_id,
                expected_server_replica_id,
                cluster_id,
                configuration_id,
                configuration_epoch,
                handshake_nonce,
                contract_profile,
                requested_response_frame_size,
            } => Self::Hello(BootstrapHello {
                contract_version: *contract_version,
                node_id: node_id.clone(),
                expected_server_replica_id: expected_server_replica_id.clone(),
                cluster_id: cluster_id.clone(),
                configuration_id: configuration_id.clone(),
                configuration_epoch: *configuration_epoch,
                handshake_nonce: *handshake_nonce,
                contract_profile: *contract_profile,
                requested_response_frame_size: *requested_response_frame_size,
            }),
            Request::Capabilities => Self::Capabilities,
            Request::Get { key } => Self::Get { key },
            Request::CompareAndSet {
                op,
                request_id,
                idempotency_epoch,
            } => Self::CompareAndSet {
                op,
                request_id: request_id
                    .as_deref()
                    .map(parse_canonical_cas_request_id)
                    .transpose()
                    .map_err(|_| WireConversionError("CAS request ID must be a valid UUID"))?
                    .map(WireCasRequestId),
                idempotency_epoch: idempotency_epoch
                    .as_deref()
                    .map(parse_canonical_cas_request_id)
                    .transpose()
                    .map_err(|_| WireConversionError("CAS epoch must be a valid UUID"))?
                    .map(WireCasRequestId),
            },
            Request::DeleteFenced { lease } => Self::DeleteFenced { lease },
            Request::RefreshTtl { lease, ttl } => Self::RefreshTtl { lease, ttl },
            Request::RecordExpiryPreflight { preflights } => {
                Self::RecordExpiryPreflight { preflights }
            }
            Request::Batch { ops } => {
                if ops.len() > MAX_SESSION_NET_BATCH_OPERATIONS {
                    return Err(WireConversionError("batch exceeds the v5 operation limit"));
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
                    "replication log page exceeds the v5 operation limit",
                )?,
            },
            Request::ReplicateEntry { entry } => Self::ReplicateEntry {
                entry: WireReplicationEntryRef::try_from(entry)?,
            },
            Request::RebuildReplicationState { entries } => {
                if entries.len() > MAX_SESSION_NET_REBUILD_ENTRIES {
                    return Err(WireConversionError(
                        "replication rebuild exceeds the v5 entry limit",
                    ));
                }
                Self::RebuildReplicationState {
                    entries: WireReplicationEntriesRef(entries),
                }
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
                configuration_epoch: hello.configuration_epoch,
                handshake_nonce: hello.handshake_nonce,
                contract_profile: hello.contract_profile,
                requested_response_frame_size: hello.requested_response_frame_size,
            },
            WireRequest::Capabilities => Request::Capabilities,
            WireRequest::Get { key } => Request::Get { key },
            WireRequest::CompareAndSet {
                op,
                request_id,
                idempotency_epoch,
            } => Request::CompareAndSet {
                op,
                request_id: request_id.map(|request_id| request_id.0.hyphenated().to_string()),
                idempotency_epoch: idempotency_epoch.map(|epoch| epoch.0.hyphenated().to_string()),
            },
            WireRequest::DeleteFenced { lease } => Request::DeleteFenced { lease },
            WireRequest::RefreshTtl { lease, ttl } => Request::RefreshTtl { lease, ttl },
            WireRequest::RecordExpiryPreflight { preflights } => Request::RecordExpiryPreflight {
                preflights: preflights.into_inner(),
            },
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
            WireRequest::GetReplicationLog { start, limit } => {
                let limit = usize_from_wire_u32(
                    limit,
                    MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES,
                    "replication log page exceeds the v5 operation limit",
                )?;
                ReplicationLogRange::try_new(start, limit).map_err(|_| {
                    WireConversionError("replication log range violates the v5 contract")
                })?;
                Request::GetReplicationLog { start, limit }
            }
            WireRequest::ReplicateEntry { entry } => match ReplicationEntry::try_from(entry) {
                Ok(entry) => {
                    if let Err(error) = validate_replication_retained_profile(&entry) {
                        discard_replication_entry_iteratively(entry);
                        return Err(error);
                    }
                    Request::ReplicateEntry { entry }
                }
                Err(_) => return Ok(Self::ReplicateEntryOperationLimitExceeded),
            },
            WireRequest::RebuildReplicationState { entries } => {
                let entries = entries.into_inner();
                let mut decoded = Vec::with_capacity(entries.len());
                for entry in entries {
                    let Ok(entry) = ReplicationEntry::try_from(entry) else {
                        discard_replication_entries_iteratively(decoded);
                        return Ok(Self::RebuildReplicationStateOperationLimitExceeded);
                    };
                    if let Err(error) = validate_replication_retained_profile(&entry) {
                        discard_replication_entries_iteratively(decoded);
                        discard_replication_entry_iteratively(entry);
                        return Err(error);
                    }
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
        validate_inbound_request_profile(&request)?;
        Ok(Self::Operation(request))
    }
}

impl TryFrom<WireRequest> for Request {
    type Error = WireConversionError;

    fn try_from(request: WireRequest) -> Result<Self, Self::Error> {
        match InboundRequest::try_from(request)? {
            InboundRequest::Operation(request) => {
                validate_request_profile(&request)?;
                Ok(request)
            }
            InboundRequest::ReplicateEntryOperationLimitExceeded
            | InboundRequest::RebuildReplicationStateOperationLimitExceeded => Err(
                WireConversionError("replication operation tree violates the v5 contract"),
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
                configuration_epoch,
                handshake_nonce,
                contract_profile,
                requested_response_frame_size,
            } => Ok(Self::Hello(BootstrapHello {
                contract_version: *contract_version,
                node_id: node_id.clone(),
                expected_server_replica_id: expected_server_replica_id.clone(),
                cluster_id: cluster_id.clone(),
                configuration_id: configuration_id.clone(),
                configuration_epoch: *configuration_epoch,
                handshake_nonce: *handshake_nonce,
                contract_profile: *contract_profile,
                requested_response_frame_size: *requested_response_frame_size,
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
                configuration_epoch: hello.configuration_epoch,
                handshake_nonce: hello.handshake_nonce,
                contract_profile: hello.contract_profile,
                requested_response_frame_size: hello.requested_response_frame_size,
            },
        }
    }
}

fn wire_store_result_ref<T>(
    result: &Result<T, StoreError>,
) -> Result<Result<&T, WireStoreErrorRef<'_>>, WireConversionError> {
    match result {
        Ok(value) => Ok(Ok(value)),
        Err(error) => Ok(Err(WireStoreErrorRef::try_from(error)?)),
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
    Get(Result<&'a Option<StoredSessionRecord>, WireStoreErrorRef<'a>>),
    CompareAndSet(Result<&'a CompareAndSetResult, WireStoreErrorRef<'a>>),
    DeleteFenced(Result<&'a (), WireStoreErrorRef<'a>>),
    RefreshTtl(Result<&'a (), WireStoreErrorRef<'a>>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
enum WireSessionOpResult {
    Get(Result<Option<StoredSessionRecord>, WireStoreError>),
    CompareAndSet(Result<CompareAndSetResult, WireStoreError>),
    DeleteFenced(Result<(), WireStoreError>),
    RefreshTtl(Result<(), WireStoreError>),
}

impl<'a> TryFrom<&'a SessionOpResult> for WireSessionOpResultRef<'a> {
    type Error = WireConversionError;

    fn try_from(result: &'a SessionOpResult) -> Result<Self, Self::Error> {
        validate_session_op_result_profile(result)?;
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

struct WireSessionOpResultsRef<'a>(&'a [SessionOpResult]);

impl Serialize for WireSessionOpResultsRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;

        if self.0.len() > MAX_SESSION_NET_BATCH_OPERATIONS {
            return Err(serde::ser::Error::custom(
                "batch response exceeds the v5 operation limit",
            ));
        }
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for result in self.0 {
            let wire =
                WireSessionOpResultRef::try_from(result).map_err(serde::ser::Error::custom)?;
            sequence.serialize_element(&wire)?;
        }
        sequence.end()
    }
}

struct WireReplicationEntriesRef<'a>(&'a [ReplicationEntry]);

impl Serialize for WireReplicationEntriesRef<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;

        if self.0.len() > MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES {
            return Err(serde::ser::Error::custom(
                "replication log response exceeds the v5 entry limit",
            ));
        }
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for entry in self.0 {
            let wire =
                WireReplicationEntryRef::try_from(entry).map_err(serde::ser::Error::custom)?;
            sequence.serialize_element(&wire)?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
enum WireResponseRef<'a> {
    HelloAck(BootstrapHelloAckRef<'a>),
    HelloRejected { reason: HelloRejectReason },
    Capabilities(WireBackendCapabilities),
    Get(Result<&'a Option<StoredSessionRecord>, WireStoreErrorRef<'a>>),
    CompareAndSet(Result<&'a CompareAndSetResult, WireStoreErrorRef<'a>>),
    DeleteFenced(Result<&'a (), WireStoreErrorRef<'a>>),
    RefreshTtl(Result<&'a (), WireStoreErrorRef<'a>>),
    RecordExpiryPreflight(Result<&'a (), WireStoreErrorRef<'a>>),
    Batch(Result<WireSessionOpResultsRef<'a>, WireStoreErrorRef<'a>>),
    ScanRestoreRecords(Result<WireRestoreScanPageRef<'a>, WireStoreErrorRef<'a>>),
    MaxReplicationSequence(Result<&'a u64, WireStoreErrorRef<'a>>),
    GetReplicationLog(Result<WireReplicationEntriesRef<'a>, WireStoreErrorRef<'a>>),
    ReplicateEntry(Result<&'a (), WireStoreErrorRef<'a>>),
    RebuildReplicationState(Result<&'a (), WireStoreErrorRef<'a>>),
    WatchStream,
    WatchEntry(Result<WireReplicationEntryRef<'a>, WireStoreErrorRef<'a>>),
    NextLeaseInfo(Result<&'a (u64, u64), WireStoreErrorRef<'a>>),
    AcquireLease(Result<&'a LeaseGuard, WireLeaseErrorRef<'a>>),
    RenewLease(Result<&'a LeaseGuard, WireLeaseErrorRef<'a>>),
    ReleaseLease(Result<&'a (), WireLeaseErrorRef<'a>>),
    ConnectionRetiring,
    Error { message: &'a str },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
    RecordExpiryPreflight(Result<(), WireStoreError>),
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
    AcquireLease(Result<LeaseGuard, WireLeaseError>),
    RenewLease(Result<LeaseGuard, WireLeaseError>),
    ReleaseLease(Result<(), WireLeaseError>),
    ConnectionRetiring,
    Error {
        message: String,
    },
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
                configuration_epoch,
                handshake_nonce,
                cas_idempotency_epoch,
                contract_profile,
                accepted_response_frame_size,
                server_request_frame_size,
            } => Self::HelloAck(BootstrapHelloAckRef {
                contract_version: *contract_version,
                server_replica_id: server_replica_id.as_deref(),
                accepted_client_replica_id: accepted_client_replica_id.as_deref(),
                cluster_id: cluster_id.as_deref(),
                configuration_id: configuration_id.as_deref(),
                configuration_epoch: *configuration_epoch,
                handshake_nonce: *handshake_nonce,
                cas_idempotency_epoch: *cas_idempotency_epoch,
                contract_profile: *contract_profile,
                accepted_response_frame_size: *accepted_response_frame_size,
                server_request_frame_size: *server_request_frame_size,
            }),
            Response::HelloRejected { reason } => Self::HelloRejected { reason: *reason },
            Response::Capabilities(capabilities) => {
                Self::Capabilities(WireBackendCapabilities::try_from(capabilities)?)
            }
            Response::Get(result) => {
                if let Ok(Some(record)) = result {
                    validate_record_profile(record)?;
                }
                Self::Get(wire_store_result_ref(result)?)
            }
            Response::CompareAndSet(result) => {
                if let Ok(result) = result {
                    validate_compare_and_set_result_profile(result)?;
                }
                Self::CompareAndSet(wire_store_result_ref(result)?)
            }
            Response::DeleteFenced(result) => Self::DeleteFenced(wire_store_result_ref(result)?),
            Response::RefreshTtl(result) => Self::RefreshTtl(wire_store_result_ref(result)?),
            Response::RecordExpiryPreflight(result) => {
                Self::RecordExpiryPreflight(wire_store_result_ref(result)?)
            }
            Response::Batch(result) => Self::Batch(match result {
                Ok(results) if results.len() <= MAX_SESSION_NET_BATCH_OPERATIONS => {
                    Ok(WireSessionOpResultsRef(results))
                }
                Ok(_) => {
                    return Err(WireConversionError(
                        "batch response exceeds the v5 operation limit",
                    ));
                }
                Err(error) => Err(WireStoreErrorRef::try_from(error)?),
            }),
            Response::ScanRestoreRecords(result) => Self::ScanRestoreRecords(match result {
                Ok(page) => Ok(WireRestoreScanPageRef::try_from(page)?),
                Err(error) => Err(WireStoreErrorRef::try_from(error)?),
            }),
            Response::MaxReplicationSequence(result) => {
                Self::MaxReplicationSequence(wire_store_result_ref(result)?)
            }
            Response::GetReplicationLog(result) => Self::GetReplicationLog(match result {
                Ok(entries) if entries.len() <= MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES => {
                    Ok(WireReplicationEntriesRef(entries))
                }
                Ok(_) => {
                    return Err(WireConversionError(
                        "replication log response exceeds the v5 entry limit",
                    ));
                }
                Err(error) => Err(WireStoreErrorRef::try_from(error)?),
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
                Err(error) => Err(WireStoreErrorRef::try_from(error)?),
            }),
            Response::NextLeaseInfo(result) => Self::NextLeaseInfo(wire_store_result_ref(result)?),
            Response::AcquireLease(result) => {
                if let Ok(lease) = result {
                    validate_lease_profile(lease)?;
                }
                Self::AcquireLease(wire_lease_result_ref(result))
            }
            Response::RenewLease(result) => {
                if let Ok(lease) = result {
                    validate_lease_profile(lease)?;
                }
                Self::RenewLease(wire_lease_result_ref(result))
            }
            Response::ReleaseLease(result) => Self::ReleaseLease(wire_lease_result_ref(result)),
            Response::ConnectionRetiring => Self::ConnectionRetiring,
            Response::Error { .. } => Self::Error {
                message: "remote protocol error",
            },
        })
    }
}

impl TryFrom<WireResponse> for Response {
    type Error = WireConversionError;

    fn try_from(response: WireResponse) -> Result<Self, WireConversionError> {
        let response = match response {
            WireResponse::HelloAck(hello) => Self::HelloAck {
                contract_version: hello.contract_version,
                server_replica_id: hello.server_replica_id,
                accepted_client_replica_id: hello.accepted_client_replica_id,
                cluster_id: hello.cluster_id,
                configuration_id: hello.configuration_id,
                configuration_epoch: hello.configuration_epoch,
                handshake_nonce: hello.handshake_nonce,
                cas_idempotency_epoch: hello.cas_idempotency_epoch,
                contract_profile: hello.contract_profile,
                accepted_response_frame_size: hello.accepted_response_frame_size,
                server_request_frame_size: hello.server_request_frame_size,
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
            WireResponse::RecordExpiryPreflight(result) => {
                Self::RecordExpiryPreflight(domain_store_result(result)?)
            }
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
            WireResponse::AcquireLease(result) => Self::AcquireLease(domain_lease_result(result)),
            WireResponse::RenewLease(result) => Self::RenewLease(domain_lease_result(result)),
            WireResponse::ReleaseLease(result) => Self::ReleaseLease(domain_lease_result(result)),
            WireResponse::ConnectionRetiring => Self::ConnectionRetiring,
            WireResponse::Error { message } => {
                drop(message);
                Self::Error {
                    message: "remote protocol error".to_string(),
                }
            }
        };
        validate_response_profile(&response)?;
        Ok(response)
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
                configuration_epoch,
                handshake_nonce,
                cas_idempotency_epoch,
                contract_profile,
                accepted_response_frame_size,
                server_request_frame_size,
            } => Ok(Self::HelloAck(Box::new(BootstrapHelloAck {
                contract_version: *contract_version,
                server_replica_id: server_replica_id.clone(),
                accepted_client_replica_id: accepted_client_replica_id.clone(),
                cluster_id: cluster_id.clone(),
                configuration_id: configuration_id.clone(),
                configuration_epoch: *configuration_epoch,
                handshake_nonce: *handshake_nonce,
                cas_idempotency_epoch: *cas_idempotency_epoch,
                contract_profile: *contract_profile,
                accepted_response_frame_size: *accepted_response_frame_size,
                server_request_frame_size: *server_request_frame_size,
            }))),
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
            BootstrapResponse::HelloAck(hello) => {
                let hello = *hello;
                Self::HelloAck {
                    contract_version: hello.contract_version,
                    server_replica_id: hello.server_replica_id,
                    accepted_client_replica_id: hello.accepted_client_replica_id,
                    cluster_id: hello.cluster_id,
                    configuration_id: hello.configuration_id,
                    configuration_epoch: hello.configuration_epoch,
                    handshake_nonce: hello.handshake_nonce,
                    cas_idempotency_epoch: hello.cas_idempotency_epoch,
                    contract_profile: hello.contract_profile,
                    accepted_response_frame_size: hello.accepted_response_frame_size,
                    server_request_frame_size: hello.server_request_frame_size,
                }
            }
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
    let deadline = tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or(ProtocolError::InvalidWireValue)?;
    write_frame_bounded_until(writer, frame, MAX_NEGOTIATED_FRAME_SIZE, deadline).await
}

const INITIAL_ENCODED_FRAME_CHUNK_SIZE: usize = 8 * 1024;
const ENCODED_FRAME_CHUNK_SIZE: usize = 64 * 1024;
static NEVER_CANCELLED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncodingHalt {
    TimedOut,
    Cancelled,
}

#[derive(Clone, Copy)]
struct EncodingControl<'a> {
    deadline: Option<tokio::time::Instant>,
    cancellation: &'a AtomicBool,
}

impl EncodingControl<'_> {
    fn check(self) -> Result<(), EncodingHalt> {
        if self.cancellation.load(Ordering::Acquire) {
            return Err(EncodingHalt::Cancelled);
        }
        if self
            .deadline
            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            return Err(EncodingHalt::TimedOut);
        }
        Ok(())
    }
}

struct EncodedFrameChunk {
    bytes: Box<[u8]>,
    initialized: usize,
}

impl EncodedFrameChunk {
    fn initialized_bytes(&self) -> &[u8] {
        &self.bytes[..self.initialized]
    }
}

struct EncodedFrame {
    chunks: Vec<EncodedFrameChunk>,
    encoded_len: usize,
    retained_byte_capacity: usize,
}

struct BoundedFrameBuffer<'a> {
    frame: EncodedFrame,
    max_frame_size: usize,
    exceeded_at: Option<usize>,
    halted: Option<EncodingHalt>,
    control: EncodingControl<'a>,
}

impl<'a> BoundedFrameBuffer<'a> {
    fn new(max_frame_size: usize, control: EncodingControl<'a>) -> Self {
        Self {
            frame: EncodedFrame {
                chunks: Vec::new(),
                encoded_len: 0,
                retained_byte_capacity: 0,
            },
            max_frame_size,
            exceeded_at: None,
            halted: None,
            control,
        }
    }

    fn check_control(&mut self) -> std::io::Result<()> {
        self.control.check().map_err(|halted| {
            self.halted = Some(halted);
            encoding_halt_sink_error(halted)
        })
    }

    fn allocate_chunk(&mut self) {
        let remaining_capacity = self
            .max_frame_size
            .saturating_sub(self.frame.retained_byte_capacity);
        let preferred_size = if self.frame.chunks.is_empty() {
            INITIAL_ENCODED_FRAME_CHUNK_SIZE
        } else {
            ENCODED_FRAME_CHUNK_SIZE
        };
        let chunk_size = preferred_size.min(remaining_capacity);
        debug_assert!(chunk_size > 0);
        self.frame.chunks.push(EncodedFrameChunk {
            // Converting to a boxed slice discards Vec's spare capacity. Each
            // retained byte allocation therefore has exactly this logical
            // length; allocator slab/RSS overhead is intentionally outside the
            // negotiated encoded-JSON storage contract.
            bytes: vec![0_u8; chunk_size].into_boxed_slice(),
            initialized: 0,
        });
        self.frame.retained_byte_capacity += chunk_size;
    }
}

impl std::io::Write for BoundedFrameBuffer<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.check_control()?;
        let Some(attempted) = self.frame.encoded_len.checked_add(buf.len()) else {
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
        let mut remaining = buf;
        while !remaining.is_empty() {
            self.check_control()?;
            let needs_chunk = self
                .frame
                .chunks
                .last()
                .is_none_or(|chunk| chunk.initialized == chunk.bytes.len());
            if needs_chunk {
                self.allocate_chunk();
            }
            let Some(chunk) = self.frame.chunks.last_mut() else {
                return Err(std::io::Error::other(
                    "encoded frame chunk allocation did not retain storage",
                ));
            };
            let available = chunk.bytes.len() - chunk.initialized;
            let copied = available.min(remaining.len());
            chunk.bytes[chunk.initialized..chunk.initialized + copied]
                .copy_from_slice(&remaining[..copied]);
            chunk.initialized += copied;
            remaining = &remaining[copied..];
        }
        self.frame.encoded_len = attempted;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encoding_halt_sink_error(halted: EncodingHalt) -> std::io::Error {
    let (kind, message) = match halted {
        EncodingHalt::TimedOut => (
            std::io::ErrorKind::TimedOut,
            "timed out preparing frame for peer",
        ),
        EncodingHalt::Cancelled => (
            // `std::io::Write::write_all` retries `Interrupted` forever. Use a
            // non-retryable private sentinel here and map the retained halt
            // state to public `Interrupted` only after serde returns.
            std::io::ErrorKind::Other,
            "frame preparation cancelled",
        ),
    };
    std::io::Error::new(kind, message)
}

fn encoding_halt_protocol_error(halted: EncodingHalt) -> ProtocolError {
    let (kind, message) = match halted {
        EncodingHalt::TimedOut => (
            std::io::ErrorKind::TimedOut,
            "timed out preparing frame for peer",
        ),
        EncodingHalt::Cancelled => (
            std::io::ErrorKind::Interrupted,
            "frame preparation cancelled",
        ),
    };
    ProtocolError::Io(std::io::Error::new(kind, message))
}

fn encode_frame_bounded<T>(
    frame: &T,
    max_frame_size: usize,
    control: EncodingControl<'_>,
) -> Result<EncodedFrame, ProtocolError>
where
    T: Serialize,
{
    if max_frame_size > MAX_NEGOTIATED_FRAME_SIZE {
        return Err(ProtocolError::InvalidWireValue);
    }
    let mut buffer = BoundedFrameBuffer::new(max_frame_size, control);
    if let Err(halted) = control.check() {
        return Err(encoding_halt_protocol_error(halted));
    }
    match serde_json::to_writer(&mut buffer, frame) {
        Ok(()) => {
            control.check().map_err(encoding_halt_protocol_error)?;
            Ok(buffer.frame)
        }
        Err(error) => {
            if let Some(halted) = buffer.halted {
                Err(encoding_halt_protocol_error(halted))
            } else if let Some(exceeded_at) = buffer.exceeded_at {
                Err(ProtocolError::FrameTooLarge(exceeded_at))
            } else {
                Err(ProtocolError::Serialization(error))
            }
        }
    }
}

fn write_timeout_error() -> ProtocolError {
    ProtocolError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "timed out preparing or writing frame to peer",
    ))
}

/// Encode and write one complete frame under a negotiated size budget and one
/// absolute deadline.
///
/// Encoding is single-pass into lazy exact-length boxed chunks whose total
/// retained JSON-byte capacity never exceeds `max_frame_size`; the chunks are
/// not coalesced. Chunk-vector metadata and allocator slab/RSS overhead are
/// outside the encoded-byte contract. The length prefix is not emitted until
/// encoding succeeds, so oversize, timeout, cancellation, and serialization
/// failures leave the stream untouched. The same absolute deadline covers
/// encoding, prefix, payload, and flush.
pub(crate) async fn write_frame_bounded_until<W, T>(
    writer: &mut W,
    frame: &T,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: Serialize,
{
    write_frame_bounded_until_cancellable(writer, frame, max_frame_size, deadline, &NEVER_CANCELLED)
        .await
}

/// Cancellable counterpart to [`write_frame_bounded_until`].
///
/// Cancellation is cooperative while synchronous JSON serialization is in
/// progress: the sink checks it before every serializer write and between
/// retained chunks. The bounded wire DTO fields keep the interval between
/// checks finite; Tokio task abortion alone cannot preempt synchronous Rust.
pub(crate) async fn write_frame_bounded_until_cancellable<W, T>(
    writer: &mut W,
    frame: &T,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
    cancellation: &AtomicBool,
) -> Result<(), ProtocolError>
where
    W: tokio::io::AsyncWrite + Unpin,
    T: Serialize,
{
    let control = EncodingControl {
        deadline: Some(deadline),
        cancellation,
    };
    let json = encode_frame_bounded(frame, max_frame_size, control)?;
    control.check().map_err(encoding_halt_protocol_error)?;
    let len = u32::try_from(json.encoded_len)
        .map_err(|_| ProtocolError::FrameTooLarge(json.encoded_len))?;
    let write = async {
        writer
            .write_all(&len.to_be_bytes())
            .await
            .map_err(ProtocolError::Io)?;
        for chunk in &json.chunks {
            writer
                .write_all(chunk.initialized_bytes())
                .await
                .map_err(ProtocolError::Io)?;
        }
        writer.flush().await.map_err(ProtocolError::Io)
    };
    match tokio::time::timeout_at(deadline, write).await {
        Ok(result) => result,
        Err(_elapsed) => Err(write_timeout_error()),
    }
}

struct BoundedFrameCounter<'a> {
    encoded_len: usize,
    max_frame_size: usize,
    exceeded_at: Option<usize>,
    halted: Option<EncodingHalt>,
    control: EncodingControl<'a>,
}

impl BoundedFrameCounter<'_> {
    fn check_control(&mut self) -> std::io::Result<()> {
        self.control.check().map_err(|halted| {
            self.halted = Some(halted);
            encoding_halt_sink_error(halted)
        })
    }
}

impl std::io::Write for BoundedFrameCounter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.check_control()?;
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
#[cfg(test)]
pub(crate) fn ensure_frame_fits<T>(frame: &T, max_frame_size: usize) -> Result<(), ProtocolError>
where
    T: Serialize,
{
    ensure_frame_fits_controlled(
        frame,
        max_frame_size,
        EncodingControl {
            deadline: None,
            cancellation: &NEVER_CANCELLED,
        },
    )
}

fn ensure_frame_fits_controlled<T>(
    frame: &T,
    max_frame_size: usize,
    control: EncodingControl<'_>,
) -> Result<(), ProtocolError>
where
    T: Serialize,
{
    if max_frame_size > MAX_NEGOTIATED_FRAME_SIZE {
        return Err(ProtocolError::InvalidWireValue);
    }
    control.check().map_err(encoding_halt_protocol_error)?;
    let mut counter = BoundedFrameCounter {
        encoded_len: 0,
        max_frame_size,
        exceeded_at: None,
        halted: None,
        control,
    };
    match serde_json::to_writer(&mut counter, frame) {
        Ok(()) => control.check().map_err(encoding_halt_protocol_error),
        Err(error) => {
            if let Some(halted) = counter.halted {
                Err(encoding_halt_protocol_error(halted))
            } else if let Some(exceeded_at) = counter.exceeded_at {
                Err(ProtocolError::FrameTooLarge(exceeded_at))
            } else {
                Err(ProtocolError::Serialization(error))
            }
        }
    }
}

/// Validate an encoded frame size under one absolute deadline and cooperative
/// server cancellation signal, without allocating the encoded payload.
pub(crate) fn ensure_frame_fits_until<T>(
    frame: &T,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
    cancellation: &AtomicBool,
) -> Result<(), ProtocolError>
where
    T: Serialize,
{
    ensure_frame_fits_controlled(
        frame,
        max_frame_size,
        EncodingControl {
            deadline: Some(deadline),
            cancellation,
        },
    )
}

/// Size one successful point-read response using the exact borrowed v5 DTO.
#[cfg(test)]
pub(crate) fn ensure_get_success_frame_fits(
    record: &Option<StoredSessionRecord>,
    max_frame_size: usize,
) -> Result<(), ProtocolError> {
    ensure_frame_fits(&WireResponseRef::Get(Ok(record)), max_frame_size)
}

/// Deadline- and cancellation-aware replication-log response sizing.
pub(crate) fn ensure_replication_log_success_frame_fits_until(
    entries: &[ReplicationEntry],
    max_frame_size: usize,
    deadline: tokio::time::Instant,
    cancellation: &AtomicBool,
) -> Result<(), ProtocolError> {
    if entries.len() > MAX_SESSION_NET_REPLICATION_LOG_PAGE_ENTRIES {
        return Err(ProtocolError::InvalidWireValue);
    }
    ensure_frame_fits_until(
        &WireResponseRef::GetReplicationLog(Ok(WireReplicationEntriesRef(entries))),
        max_frame_size,
        deadline,
        cancellation,
    )
}

/// Size one successful restore response using the exact borrowed v5 wire DTO.
///
/// This avoids cloning record payloads while the server progressively trims a
/// page to the caller's response budget.
#[cfg(test)]
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

/// Deadline- and cancellation-aware restore-scan response sizing.
pub(crate) fn ensure_restore_scan_success_frame_fits_until(
    page: &RestoreScanPage,
    max_frame_size: usize,
    deadline: tokio::time::Instant,
    cancellation: &AtomicBool,
) -> Result<(), ProtocolError> {
    let control = EncodingControl {
        deadline: Some(deadline),
        cancellation,
    };
    control.check().map_err(encoding_halt_protocol_error)?;
    let page =
        WireRestoreScanPageRef::try_from(page).map_err(|_| ProtocolError::InvalidWireValue)?;
    ensure_frame_fits_controlled(
        &WireResponseRef::ScanRestoreRecords(Ok(page)),
        max_frame_size,
        control,
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

/// Decode one post-bootstrap operation request through the private v5 DTO.
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

/// Decode one post-bootstrap operation response through the private v5 DTO.
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

    fn replace_json_field(
        value: &mut serde_json::Value,
        field: &str,
        replacement: &serde_json::Value,
    ) -> usize {
        match value {
            serde_json::Value::Array(values) => values
                .iter_mut()
                .map(|value| replace_json_field(value, field, replacement))
                .sum(),
            serde_json::Value::Object(fields) => {
                let mut replaced = 0;
                if let Some(value) = fields.get_mut(field) {
                    *value = replacement.clone();
                    replaced += 1;
                }
                replaced
                    + fields
                        .values_mut()
                        .map(|value| replace_json_field(value, field, replacement))
                        .sum::<usize>()
            }
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
            stable_id: Bytes::from_static(b"protocol-invariant-boundary")
                .try_into()
                .expect("valid stable ID"),
        }
    }

    fn test_session_key_with_stable_id_len(
        len: usize,
    ) -> Result<SessionKey, opc_session_store::StableIdError> {
        let mut key = test_session_key();
        key.stable_id = Bytes::from(vec![u8::MAX; len]).try_into()?;
        Ok(key)
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
    fn restore_scan_protocol_v5_frames_round_trip_without_redundant_fields() {
        assert_eq!(CONTRACT_VERSION, 5);

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
        assert!(
            serde_json::from_value::<Request>(invalid_request).is_err(),
            "invalid restore scalars must fail during protocol decode"
        );

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
        assert_eq!(page["cursor_profile"], "legacy-compatibility");

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
    fn consensus_profile_fits_the_exact_worst_case_bounded_outer_frames() {
        let cluster = opc_consensus::ConsensusClusterId::new("frame-proof").expect("cluster");
        let epoch = opc_consensus::ConsensusConfigurationEpoch::new(1).expect("epoch");
        let identity = opc_consensus::ConsensusIdentity::new(
            cluster,
            opc_consensus::derive_configuration_id(cluster, epoch, &[[7; 32]]),
            epoch,
        );
        let sender = opc_consensus::derive_node_id(cluster, b"replica-a").expect("node ID");
        let request = SessionConsensusWireRequest::try_new(
            identity,
            sender,
            opc_consensus::ConsensusRpcFamily::AppendEntries,
            vec![u8::MAX; SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES],
        )
        .expect("maximum bounded request");
        let request = SessionConsensusTransportRequest::Call {
            call_id: uuid::Uuid::nil(),
            request,
        };
        ensure_frame_fits(&request, MIN_SESSION_CONSENSUS_FRAME_SIZE)
            .expect("consensus minimum must fit the worst byte request");

        let response = SessionConsensusTransportResponse::Call {
            call_id: uuid::Uuid::nil(),
            response: SessionConsensusWireResponse {
                result: Ok(vec![u8::MAX; SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES]),
            },
        };
        ensure_frame_fits(&response, MIN_SESSION_CONSENSUS_FRAME_SIZE)
            .expect("consensus minimum must fit the worst byte response");
        assert!(CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE.is_current());
        assert_eq!(
            CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE.error_set_revision,
            4
        );
        assert_eq!(SESSION_CONSENSUS_ALPN, b"opc-session-consensus/2");
        assert_eq!(SESSION_CONSENSUS_TRANSPORT_REVISION, 2);
        let mut previous_error_set = CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE;
        previous_error_set.error_set_revision = 1;
        assert!(!previous_error_set.is_current());
        assert_eq!(
            CURRENT_SESSION_CONSENSUS_CONTRACT_PROFILE.min_frame_size,
            MIN_SESSION_CONSENSUS_FRAME_SIZE as u32
        );
    }

    #[test]
    fn consensus_wire_rejects_hostile_zero_sender_and_epoch_during_decode() {
        let cluster = opc_consensus::ConsensusClusterId::new("zero-proof").expect("cluster");
        let epoch = opc_consensus::ConsensusConfigurationEpoch::new(1).expect("epoch");
        let identity = opc_consensus::ConsensusIdentity::new(
            cluster,
            opc_consensus::derive_configuration_id(cluster, epoch, &[[8; 32]]),
            epoch,
        );
        let sender = opc_consensus::derive_node_id(cluster, b"replica-a").expect("node ID");
        let frame = SessionConsensusTransportRequest::Call {
            call_id: uuid::Uuid::nil(),
            request: SessionConsensusWireRequest::try_new(
                identity,
                sender,
                opc_consensus::ConsensusRpcFamily::Vote,
                Vec::new(),
            )
            .expect("request"),
        };
        let mut zero_sender = serde_json::to_value(&frame).expect("frame JSON");
        zero_sender["Call"]["request"]["sender"] = serde_json::json!(0);
        assert!(serde_json::from_value::<SessionConsensusTransportRequest>(zero_sender).is_err());

        let mut zero_epoch = serde_json::to_value(frame).expect("frame JSON");
        zero_epoch["Call"]["request"]["identity"]["configuration_epoch"] = serde_json::json!(0);
        assert!(serde_json::from_value::<SessionConsensusTransportRequest>(zero_epoch).is_err());
    }

    #[test]
    fn contract_profile_and_bootstrap_frames_are_exact_and_version_tolerant() {
        assert_eq!(SESSION_NET_ALPN, b"opc-session-net/5");
        assert!(CURRENT_CONTRACT_PROFILE.is_current());
        assert_eq!(CURRENT_CONTRACT_PROFILE.wire_schema_revision, 6);
        assert_eq!(CURRENT_CONTRACT_PROFILE.error_set_revision, 8);
        assert_eq!(CURRENT_CONTRACT_PROFILE.max_frame_size, 16_777_216);
        assert_eq!(CURRENT_CONTRACT_PROFILE.max_session_ttl_seconds, 31_536_000);

        let profile = serde_json::to_value(CURRENT_CONTRACT_PROFILE).expect("profile JSON");
        assert_eq!(
            profile,
            serde_json::json!({
                "wire_schema_revision": 6,
                "error_set_revision": 8,
                "max_restore_scan_page_records": 1024,
                "max_restore_scan_page_payload_bytes": 4194304,
                "max_restore_scan_page_retained_bytes": 8388608,
                "max_restore_scan_examined_rows": 4096,
                "max_restore_scan_examined_metadata_bytes": 8388608,
                "max_replication_log_page_entries": 65536,
                "max_batch_operations": 256,
                "max_rebuild_entries": 65536,
                "max_replication_operation_depth": 16,
                "max_replication_operations_per_entry": 256,
                "min_frame_size": 8192,
                "max_frame_size": 16777216,
                "max_session_ttl_seconds": 31536000,
                "owner_id_max_bytes": 128,
                "session_key_type_max_bytes": 128,
                "state_type_max_bytes": 128,
                "stable_id_max_bytes": 64,
                "replication_tx_id_max_bytes": 128,
                "cas_request_id_bytes": 36
            })
        );

        let retiring = serde_json::to_value(Response::ConnectionRetiring)
            .expect("connection-retiring response");
        assert_eq!(retiring, serde_json::json!("ConnectionRetiring"));
        assert!(matches!(
            serde_json::from_value::<Response>(retiring),
            Ok(Response::ConnectionRetiring)
        ));

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

        let acknowledgement = BootstrapResponse::HelloAck(Box::new(BootstrapHelloAck {
            contract_version: CONTRACT_VERSION,
            server_replica_id: Some("replica-b".to_string()),
            accepted_client_replica_id: Some("replica-a".to_string()),
            cluster_id: Some("cluster-a".to_string()),
            configuration_id: Some("00".repeat(32)),
            configuration_epoch: Some(1),
            handshake_nonce: Some(uuid::Uuid::nil()),
            cas_idempotency_epoch: Some(uuid::Uuid::from_u128(1)),
            contract_profile: Some(CURRENT_CONTRACT_PROFILE),
            accepted_response_frame_size: Some(DEFAULT_MAX_FRAME_SIZE as u32),
            server_request_frame_size: Some(DEFAULT_MAX_FRAME_SIZE as u32),
        }));
        let acknowledgement = serde_json::to_value(acknowledgement).expect("acknowledgement JSON");
        assert_eq!(
            acknowledgement["HelloAck"]["contract_version"],
            CONTRACT_VERSION
        );
        assert_eq!(acknowledgement["HelloAck"]["contract_profile"], profile);
        assert_eq!(
            acknowledgement["HelloAck"]["accepted_response_frame_size"],
            DEFAULT_MAX_FRAME_SIZE as u32
        );
        assert_eq!(
            acknowledgement["HelloAck"]["server_request_frame_size"],
            DEFAULT_MAX_FRAME_SIZE as u32
        );
    }

    #[test]
    fn fixed_width_limits_and_size_errors_have_golden_v5_shapes() {
        let request = Request::GetReplicationLog {
            start: u64::MAX,
            limit: 1,
        };
        assert_eq!(
            serde_json::to_string(&request).expect("request JSON"),
            r#"{"GetReplicationLog":{"start":18446744073709551615,"limit":1}}"#
        );
        assert!(serde_json::to_vec(&Request::GetReplicationLog {
            start: u64::MAX,
            limit: 2,
        })
        .is_err());
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
    fn every_store_error_has_a_frozen_v5_round_trip() {
        let errors = [
            StoreError::NotFound,
            StoreError::StaleFence,
            StoreError::CasConflict,
            StoreError::CasIdempotencyConflict,
            StoreError::CasIdempotencyOutcomeUnavailable,
            StoreError::BackendOperationOutcomeUnavailable,
            StoreError::CapabilityNotSupported("capability".to_string()),
            StoreError::BackendUnavailable("backend".to_string()),
            StoreError::InvalidKey("invalid".to_string()),
            StoreError::InvalidReplicationSequence,
            StoreError::InvalidReplicationLogRange,
            StoreError::ReplicationLogPageTooLarge {
                requested: 2,
                max: 1,
            },
            StoreError::ReplicationLogCursorCompacted { resume_from: 7 },
            StoreError::ReplicationWatchCatchUpRequired,
            StoreError::ReplicationOperationLimitExceeded,
            StoreError::InvalidSessionTtl,
            StoreError::InvalidRecordExpiry,
            StoreError::RecordExpiryPreflightLimitExceeded,
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
            StoreError::RestoreScanCursorStale,
            StoreError::RestoreScanWorkBudgetExceeded,
            StoreError::RestoreScanResponseTooLarge { max_bytes: 512 },
        ];

        for expected in errors {
            let encoded = serde_json::to_vec(&Response::Get(Err(expected.clone())))
                .expect("encode StoreError");
            let decoded: Response = serde_json::from_slice(&encoded).expect("decode StoreError");
            let sanitized = match expected {
                StoreError::CapabilityNotSupported(ref capability) => {
                    StoreError::CapabilityNotSupported(safe_capability_name(capability).to_string())
                }
                StoreError::BackendUnavailable(_) => {
                    StoreError::BackendUnavailable("backend unavailable".to_string())
                }
                StoreError::InvalidKey(_) => StoreError::InvalidKey("invalid key".to_string()),
                StoreError::Crypto(_) => {
                    StoreError::Crypto("cryptographic operation failed".to_string())
                }
                StoreError::Serialization(_) => {
                    StoreError::Serialization("serialization failed".to_string())
                }
                StoreError::InvalidRestoreScanRequest(_) => StoreError::InvalidRestoreScanRequest(
                    "restore scan request rejected".to_string(),
                ),
                StoreError::InvalidRestoreScanResponse(_) => {
                    StoreError::InvalidRestoreScanResponse(
                        "restore scan response rejected".to_string(),
                    )
                }
                other => other,
            };
            assert!(matches!(decoded, Response::Get(Err(actual)) if actual == sanitized));
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
    fn hostile_peer_error_strings_are_normalized_and_not_retained() {
        const SECRET: &str = "secret-provider-path/token";
        let cases = [
            serde_json::json!({"Get": {"Err": {"BackendUnavailable": SECRET}}}),
            serde_json::json!({"Get": {"Err": {"InvalidKey": SECRET}}}),
            serde_json::json!({"Get": {"Err": {"Crypto": SECRET}}}),
            serde_json::json!({"Get": {"Err": {"Serialization": SECRET}}}),
            serde_json::json!({"Get": {"Err": {"CapabilityNotSupported": SECRET}}}),
            serde_json::json!({
                "Batch": {"Ok": [{"Get": {"Err": {"BackendUnavailable": SECRET}}}]}
            }),
            serde_json::json!({"AcquireLease": {"Err": {"Backend": SECRET}}}),
            serde_json::json!({"Error": {"message": SECRET}}),
        ];

        for wire in cases {
            let decoded: Response =
                serde_json::from_value(wire).expect("valid hostile error shape");
            let debug = format!("{decoded:?}");
            assert!(
                !debug.contains(SECRET),
                "peer error text was retained: {debug}"
            );
        }

        let allowed: Response = serde_json::from_value(serde_json::json!({
            "Get": {"Err": {"CapabilityNotSupported": "watch"}}
        }))
        .expect("allowlisted capability");
        assert!(matches!(
            allowed,
            Response::Get(Err(StoreError::CapabilityNotSupported(capability)))
                if capability == "watch"
        ));

        let expiry_preflight: Response = serde_json::from_value(serde_json::json!({
            "Get": {"Err": {"CapabilityNotSupported": "record_expiry_preflight"}}
        }))
        .expect("allowlisted expiry-preflight capability");
        assert!(matches!(
            expiry_preflight,
            Response::Get(Err(StoreError::CapabilityNotSupported(capability)))
                if capability == "record_expiry_preflight"
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

    #[test]
    fn every_lease_error_has_a_frozen_v5_round_trip() {
        let errors = [
            LeaseError::AlreadyHeld,
            LeaseError::Expired,
            LeaseError::StaleFence,
            LeaseError::NotFound,
            LeaseError::InvalidSessionTtl,
            LeaseError::OperationOutcomeUnavailable,
            LeaseError::Backend("backend".to_string()),
        ];

        for expected in errors {
            let encoded = serde_json::to_vec(&Response::AcquireLease(Err(expected.clone())))
                .expect("encode LeaseError");
            let decoded: Response = serde_json::from_slice(&encoded).expect("decode LeaseError");
            let expected = match expected {
                LeaseError::Backend(_) => {
                    LeaseError::Backend("lease backend unavailable".to_string())
                }
                expected => expected,
            };
            let Response::AcquireLease(Err(decoded)) = decoded else {
                panic!("lease error changed response family");
            };
            assert_eq!(decoded, expected);
        }
    }

    fn replication_entry(op: ReplicationOp) -> ReplicationEntry {
        ReplicationEntry {
            sequence: 1,
            tx_id: "wire-tree".try_into().expect("valid transaction ID"),
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
    fn exact_wire_containers_reject_unknown_top_level_and_nested_fields() {
        let mut get = serde_json::to_value(Request::Get {
            key: test_session_key(),
        })
        .expect("encode Get request");
        get["Get"]["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Request>(get).is_err());

        let mut generic = serde_json::to_value(Response::Error {
            message: "ignored".to_string(),
        })
        .expect("encode generic response");
        generic["Error"]["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Response>(generic).is_err());

        let key = test_session_key();
        let owner = OwnerId::new("unknown-field-owner").expect("owner");
        let entry = replication_entry(replication_leaf(&key, &owner));
        let mut replication = serde_json::to_value(Request::ReplicateEntry { entry })
            .expect("encode replication request");
        replication["ReplicateEntry"]["entry"]["operation_nodes"][0]["DeleteFenced"]["unknown"] =
            serde_json::json!(true);
        assert!(serde_json::from_value::<Request>(replication).is_err());

        let mut store_error =
            serde_json::to_value(Response::Get(Err(StoreError::PayloadTooLarge {
                actual: 2,
                max: 1,
            })))
            .expect("encode store error");
        store_error["Get"]["Err"]["PayloadTooLarge"]["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Response>(store_error).is_err());

        let mut batch =
            serde_json::to_value(Response::Batch(Ok(vec![SessionOpResult::Get(Ok(None))])))
                .expect("encode batch response");
        batch["Batch"]["Ok"][0]["unknown"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Response>(batch).is_err());
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
    fn record_expiry_preflight_is_payload_free_and_bounded_during_decode() {
        let descriptor = RecordExpiryPreflight::from_record(&test_record(
            test_session_key(),
            OwnerId::new("expiry-preflight-owner").expect("owner"),
            FenceToken::new(1),
        ));
        let exact = Request::RecordExpiryPreflight {
            preflights: vec![descriptor; MAX_RECORD_EXPIRY_PREFLIGHTS],
        };
        let json = serde_json::to_value(exact).expect("exact expiry preflight");
        let decoded: Request =
            serde_json::from_value(json.clone()).expect("decode exact expiry preflight");
        assert!(matches!(
            decoded,
            Request::RecordExpiryPreflight { preflights }
                if preflights.len() == MAX_RECORD_EXPIRY_PREFLIGHTS
        ));
        let rendered = json.to_string();
        for forbidden in ["stable_id", "payload", "owner", "generation", "fence"] {
            assert!(!rendered.contains(forbidden));
        }

        let too_many = Request::RecordExpiryPreflight {
            preflights: vec![descriptor; MAX_RECORD_EXPIRY_PREFLIGHTS + 1],
        };
        assert!(serde_json::to_value(too_many).is_err());
        let mut hostile = json;
        let preflights = hostile["RecordExpiryPreflight"]["preflights"]
            .as_array_mut()
            .expect("preflights");
        preflights.push(preflights[0].clone());
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
        let mut record = test_record(
            test_session_key(),
            OwnerId::new("bounded-owner").expect("owner"),
            FenceToken::new(1),
        );
        record.payload = EncryptedSessionPayload::new(vec![7; 1024]);
        let response =
            Response::ScanRestoreRecords(Ok(RestoreScanPage::new(vec![record], 0, None)));
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

    #[test]
    fn negotiated_frame_sizes_are_checked_without_truncation() {
        assert_eq!(
            MIN_RESTORE_SCAN_RESPONSE_FRAME_SIZE,
            MIN_NEGOTIATED_FRAME_SIZE
        );
        assert_eq!(
            checked_wire_frame_size(MIN_NEGOTIATED_FRAME_SIZE).expect("minimum wire budget"),
            MIN_NEGOTIATED_FRAME_SIZE as u32
        );
        assert_eq!(
            checked_wire_frame_size(MAX_NEGOTIATED_FRAME_SIZE).expect("maximum wire budget"),
            MAX_NEGOTIATED_FRAME_SIZE as u32
        );
        assert_eq!(
            checked_frame_size(MAX_NEGOTIATED_FRAME_SIZE as u32).expect("maximum local budget"),
            MAX_NEGOTIATED_FRAME_SIZE
        );
        assert_eq!(
            negotiate_response_frame_size(16_384, MIN_NEGOTIATED_FRAME_SIZE)
                .expect("negotiated minimum"),
            MIN_NEGOTIATED_FRAME_SIZE as u32
        );
        assert_eq!(
            negotiate_response_frame_size(
                MAX_NEGOTIATED_FRAME_SIZE as u32,
                MAX_NEGOTIATED_FRAME_SIZE,
            )
            .expect("negotiated maximum"),
            MAX_NEGOTIATED_FRAME_SIZE as u32
        );
        assert!(matches!(
            checked_wire_frame_size(MIN_NEGOTIATED_FRAME_SIZE - 1),
            Err(ProtocolError::InvalidWireValue)
        ));
        assert!(matches!(
            checked_frame_size((MIN_NEGOTIATED_FRAME_SIZE - 1) as u32),
            Err(ProtocolError::InvalidWireValue)
        ));
        assert!(matches!(
            checked_wire_frame_size(MAX_NEGOTIATED_FRAME_SIZE + 1),
            Err(ProtocolError::InvalidWireValue)
        ));
        assert!(matches!(
            checked_frame_size((MAX_NEGOTIATED_FRAME_SIZE + 1) as u32),
            Err(ProtocolError::InvalidWireValue)
        ));
        assert!(matches!(
            negotiate_response_frame_size(
                (MAX_NEGOTIATED_FRAME_SIZE + 1) as u32,
                MAX_NEGOTIATED_FRAME_SIZE,
            ),
            Err(ProtocolError::InvalidWireValue)
        ));
        assert!(matches!(
            negotiate_response_frame_size(
                MAX_NEGOTIATED_FRAME_SIZE as u32,
                MAX_NEGOTIATED_FRAME_SIZE + 1,
            ),
            Err(ProtocolError::InvalidWireValue)
        ));
        assert_eq!(conservative_payload_budget(DEFAULT_MAX_FRAME_SIZE), 130_048);
        assert_eq!(
            conservative_payload_budget(MAX_NEGOTIATED_FRAME_SIZE),
            2_096_128
        );
        assert!(
            conservative_payload_budget(MAX_NEGOTIATED_FRAME_SIZE) >= 1024 * 1024,
            "the negotiated ceiling must carry SQLite's 1 MiB value limit"
        );
        #[cfg(target_pointer_width = "64")]
        assert!(matches!(
            checked_wire_frame_size((u32::MAX as usize) + 1),
            Err(ProtocolError::InvalidWireValue)
        ));
    }

    #[test]
    fn stable_id_transport_boundaries_are_exact_for_encode_and_decode() {
        for (len, accepted) in [
            (0, false),
            (1, true),
            (MAX_SESSION_NET_STABLE_ID_BYTES, true),
            (MAX_SESSION_NET_STABLE_ID_BYTES + 1, false),
        ] {
            let key = test_session_key_with_stable_id_len(len);
            assert_eq!(key.is_ok(), accepted, "direct stable_id length {len}");
            if let Ok(key) = key {
                assert!(serde_json::to_vec(&Request::Get { key }).is_ok());
            }
        }

        let valid = serde_json::to_value(Request::Get {
            key: test_session_key_with_stable_id_len(MAX_SESSION_NET_STABLE_ID_BYTES)
                .expect("maximum stable ID"),
        })
        .expect("maximum stable ID request");
        for (len, accepted) in [
            (0, false),
            (1, true),
            (MAX_SESSION_NET_STABLE_ID_BYTES, true),
            (MAX_SESSION_NET_STABLE_ID_BYTES + 1, false),
        ] {
            let mut wire = valid.clone();
            let replacements = replace_json_field(
                &mut wire,
                "stable_id",
                &serde_json::json!(vec![u8::MAX; len]),
            );
            assert_eq!(replacements, 1);
            assert_eq!(
                serde_json::from_value::<Request>(wire).is_ok(),
                accepted,
                "inbound stable_id length {len}"
            );
        }

        assert!(test_session_key_with_stable_id_len(MAX_SESSION_NET_STABLE_ID_BYTES + 1).is_err());
    }

    #[test]
    fn replication_transaction_id_boundaries_are_exact_and_nested() {
        let key = test_session_key_with_stable_id_len(MAX_SESSION_NET_STABLE_ID_BYTES)
            .expect("maximum stable ID");
        let owner = OwnerId::new("replica-a").expect("owner");
        let base = replication_entry(replication_leaf(&key, &owner));

        for len in [1, MAX_SESSION_NET_REPLICATION_TX_ID_BYTES] {
            let mut entry = base.clone();
            entry.tx_id = ReplicationTxId::new(&"t".repeat(len)).expect("valid transaction ID");
            assert!(serde_json::to_vec(&Response::WatchEntry(Ok(entry.clone()))).is_ok());
            assert!(serde_json::to_vec(&Request::ReplicateEntry { entry }).is_ok());
        }
        assert!(ReplicationTxId::new("").is_err());
        assert!(
            ReplicationTxId::new(&"t".repeat(MAX_SESSION_NET_REPLICATION_TX_ID_BYTES + 1)).is_err()
        );

        let mut valid = base;
        valid.tx_id = ReplicationTxId::new(&"t".repeat(MAX_SESSION_NET_REPLICATION_TX_ID_BYTES))
            .expect("maximum transaction ID");
        let valid = serde_json::to_value(Response::WatchEntry(Ok(valid)))
            .expect("maximum transaction ID response");
        for (len, accepted) in [
            (0, false),
            (1, true),
            (MAX_SESSION_NET_REPLICATION_TX_ID_BYTES, true),
            (MAX_SESSION_NET_REPLICATION_TX_ID_BYTES + 1, false),
        ] {
            let mut wire = valid.clone();
            let replacements =
                replace_json_field(&mut wire, "tx_id", &serde_json::json!("t".repeat(len)));
            assert_eq!(replacements, 1);
            assert_eq!(
                serde_json::from_value::<Response>(wire).is_ok(),
                accepted,
                "inbound tx_id length {len}"
            );
        }

        let mut request_entry = replication_entry(replication_leaf(&key, &owner));
        request_entry.tx_id =
            ReplicationTxId::new(&"t".repeat(MAX_SESSION_NET_REPLICATION_TX_ID_BYTES))
                .expect("maximum transaction ID");
        let request = serde_json::to_value(Request::RebuildReplicationState {
            entries: vec![request_entry],
        })
        .expect("maximum transaction ID rebuild");
        for (len, accepted) in [
            (0, false),
            (1, true),
            (MAX_SESSION_NET_REPLICATION_TX_ID_BYTES, true),
            (MAX_SESSION_NET_REPLICATION_TX_ID_BYTES + 1, false),
        ] {
            let mut wire = request.clone();
            assert_eq!(
                replace_json_field(&mut wire, "tx_id", &serde_json::json!("t".repeat(len)),),
                1
            );
            assert_eq!(
                serde_json::from_value::<Request>(wire).is_ok(),
                accepted,
                "inbound retained request tx_id length {len}"
            );
        }
    }

    #[tokio::test]
    async fn retained_identifier_profiles_cover_nested_requests_and_response_carriers() {
        let valid_key = test_session_key_with_stable_id_len(MAX_SESSION_NET_STABLE_ID_BYTES)
            .expect("maximum stable ID");
        assert!(test_session_key_with_stable_id_len(MAX_SESSION_NET_STABLE_ID_BYTES + 1).is_err());
        let owner = OwnerId::new("replica-a").expect("owner");
        let backend = FakeSessionBackend::new();
        let valid_lease = backend
            .acquire(&valid_key, owner.clone(), Duration::from_secs(60))
            .await
            .expect("valid lease");
        let valid_record = test_record(valid_key.clone(), owner.clone(), valid_lease.fence());

        let valid_nested_entry = replication_entry(operation_at_depth(
            replication_leaf(&valid_key, &owner),
            MAX_REPLICATION_OPERATION_DEPTH,
        ));

        let valid_responses = vec![
            Response::Get(Ok(Some(valid_record.clone()))),
            Response::Batch(Ok(vec![
                SessionOpResult::Get(Ok(Some(valid_record.clone()))),
                SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Conflict {
                    current: Some(valid_record.clone()),
                })),
            ])),
            Response::ScanRestoreRecords(Ok(RestoreScanPage::new(
                vec![valid_record.clone()],
                0,
                None,
            ))),
            Response::AcquireLease(Ok(valid_lease.clone())),
            Response::RenewLease(Ok(valid_lease.clone())),
            Response::GetReplicationLog(Ok(vec![valid_nested_entry.clone()])),
            Response::WatchEntry(Ok(valid_nested_entry.clone())),
        ];
        for response in valid_responses {
            let mut wire = serde_json::to_value(response).expect("valid response carrier");
            let replacements = replace_json_field(
                &mut wire,
                "stable_id",
                &serde_json::json!(vec![u8::MAX; MAX_SESSION_NET_STABLE_ID_BYTES + 1]),
            );
            assert!(replacements > 0);
            assert!(
                serde_json::from_value::<Response>(wire).is_err(),
                "transport-oversized stable ID must not reach the client"
            );
        }

        let mut valid_rebuild = serde_json::to_value(Request::RebuildReplicationState {
            entries: vec![valid_nested_entry],
        })
        .expect("valid nested rebuild");
        assert!(
            replace_json_field(
                &mut valid_rebuild,
                "stable_id",
                &serde_json::json!(vec![u8::MAX; MAX_SESSION_NET_STABLE_ID_BYTES + 1]),
            ) > 0
        );
        assert!(serde_json::from_value::<Request>(valid_rebuild).is_err());
    }

    #[tokio::test]
    async fn lease_wire_profile_rejects_structurally_invalid_guards() {
        let key = test_session_key();
        let owner = OwnerId::new("replica-a").expect("owner");
        let backend = FakeSessionBackend::new();
        let lease = backend
            .acquire(&key, owner, Duration::from_secs(60))
            .await
            .expect("valid lease");
        let request = serde_json::to_value(Request::RenewLease {
            lease: lease.clone(),
            ttl: Duration::from_secs(60),
        })
        .expect("valid renew request");
        let response = serde_json::to_value(Response::AcquireLease(Ok(lease.clone())))
            .expect("valid acquire response");
        let expired_before_acquisition = serde_json::to_value(Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH,
        ))
        .expect("timestamp wire value");

        for (field, invalid) in [
            ("fence", serde_json::json!(0)),
            ("credential_id", serde_json::json!(0)),
            ("expires_at", expired_before_acquisition),
        ] {
            let mut invalid_request = request.clone();
            assert_eq!(replace_json_field(&mut invalid_request, field, &invalid), 1);
            assert!(
                serde_json::from_value::<Request>(invalid_request).is_err(),
                "invalid lease {field} reached request dispatch"
            );

            let mut invalid_response = response.clone();
            assert_eq!(
                replace_json_field(&mut invalid_response, field, &invalid),
                1
            );
            assert!(
                serde_json::from_value::<Response>(invalid_response).is_err(),
                "invalid lease {field} reached a client"
            );
        }

        let acquired_at = serde_json::to_value(lease.acquired_at()).expect("acquisition time");
        let mut zero_ttl_request = request;
        assert_eq!(
            replace_json_field(&mut zero_ttl_request, "expires_at", &acquired_at),
            1
        );
        assert!(
            serde_json::from_value::<Request>(zero_ttl_request).is_ok(),
            "an exact zero lease lifetime remains valid"
        );
        let mut zero_ttl_response = response;
        assert_eq!(
            replace_json_field(&mut zero_ttl_response, "expires_at", &acquired_at),
            1
        );
        assert!(serde_json::from_value::<Response>(zero_ttl_response).is_ok());
    }

    #[tokio::test]
    async fn cas_request_ids_are_canonical_uuid_values_before_dispatch() {
        let key = test_session_key_with_stable_id_len(1).expect("minimum stable ID");
        let owner = OwnerId::new("replica-a").expect("owner");
        let backend = FakeSessionBackend::new();
        let lease = backend
            .acquire(&key, owner.clone(), Duration::from_secs(60))
            .await
            .expect("lease");
        let op = CompareAndSet {
            key: key.clone(),
            lease,
            expected_generation: None,
            new_record: test_record(key, owner, FenceToken::new(1)),
        };
        let canonical = uuid::Uuid::parse_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
            .expect("test UUID")
            .hyphenated()
            .to_string();
        assert_eq!(canonical.len(), SESSION_NET_CAS_REQUEST_ID_BYTES);

        let canonical_request = Request::CompareAndSet {
            op: op.clone(),
            request_id: Some(canonical.clone()),
            idempotency_epoch: Some(uuid::Uuid::from_u128(1).to_string()),
        };
        let encoded = serde_json::to_value(&canonical_request).expect("canonical request ID");
        let decoded: Request =
            serde_json::from_value(encoded.clone()).expect("decode canonical request ID");
        assert!(matches!(
            decoded,
            Request::CompareAndSet { request_id: Some(ref value), .. } if value == &canonical
        ));

        let simple = canonical.replace('-', "");
        assert_eq!(simple.len(), 32);
        assert!(
            serde_json::to_value(Request::CompareAndSet {
                op: op.clone(),
                request_id: Some(simple),
                idempotency_epoch: None,
            })
            .is_err(),
            "non-canonical outbound UUID forms must fail closed"
        );

        for (value, accepted) in [
            (String::new(), false),
            ("x".to_string(), false),
            (canonical.clone(), true),
            (format!("{canonical}x"), false),
            (canonical.to_uppercase(), false),
        ] {
            let mut wire = encoded.clone();
            wire["CompareAndSet"]["request_id"] = serde_json::json!(value);
            assert_eq!(
                serde_json::from_value::<Request>(wire).is_ok(),
                accepted,
                "wire CAS request ID boundary"
            );
        }

        for invalid in [String::new(), "x".repeat(37), "not-a-uuid".to_string()] {
            assert!(serde_json::to_vec(&Request::CompareAndSet {
                op: op.clone(),
                request_id: Some(invalid),
                idempotency_epoch: None,
            })
            .is_err());
        }
    }

    #[tokio::test]
    async fn bounded_writer_accepts_exact_limit_and_emits_nothing_one_over() {
        const NON_POWER_BUDGET: usize = 10_000;
        let response = "x".repeat(NON_POWER_BUDGET - 2);
        let encoded = serde_json::to_vec(&response).expect("reference frame encoding");
        assert_eq!(encoded.len(), NON_POWER_BUDGET);
        assert!(encoded.len() > INITIAL_ENCODED_FRAME_CHUNK_SIZE);
        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_secs(1))
            .expect("test deadline");

        let mut exact = Vec::new();
        write_frame_bounded_until(&mut exact, &response, encoded.len(), deadline)
            .await
            .expect("exact-limit frame must be written");
        assert_eq!(
            &exact[..4],
            &(u32::try_from(encoded.len()).expect("test frame size")).to_be_bytes()
        );
        assert_eq!(&exact[4..], encoded);

        let mut rejected = Vec::new();
        let error =
            write_frame_bounded_until(&mut rejected, &response, encoded.len() - 1, deadline)
                .await
                .expect_err("one-byte-over frame must be rejected");
        assert!(matches!(error, ProtocolError::FrameTooLarge(_)));
        assert!(rejected.is_empty(), "no length prefix may be emitted");

        let mut exact_buffer = BoundedFrameBuffer::new(
            NON_POWER_BUDGET,
            EncodingControl {
                deadline: None,
                cancellation: &NEVER_CANCELLED,
            },
        );
        serde_json::to_writer(&mut exact_buffer, &response)
            .expect("exact non-power-of-two allocation must encode");
        assert_eq!(exact_buffer.frame.encoded_len, NON_POWER_BUDGET);
        assert!(exact_buffer.frame.chunks.len() >= 2);
        assert_eq!(
            exact_buffer
                .frame
                .chunks
                .iter()
                .map(|chunk| chunk.bytes.len())
                .sum::<usize>(),
            exact_buffer.frame.retained_byte_capacity
        );
        assert_eq!(exact_buffer.frame.retained_byte_capacity, NON_POWER_BUDGET);

        let mut rejected_buffer = BoundedFrameBuffer::new(
            NON_POWER_BUDGET - 1,
            EncodingControl {
                deadline: None,
                cancellation: &NEVER_CANCELLED,
            },
        );
        assert!(serde_json::to_writer(&mut rejected_buffer, &response).is_err());
        assert!(rejected_buffer.frame.encoded_len < encoded.len());
        assert!(rejected_buffer.frame.retained_byte_capacity < NON_POWER_BUDGET);
    }

    struct CancelMidSerialization<'a> {
        cancellation: &'a AtomicBool,
    }

    impl Serialize for CancelMidSerialization<'_> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut sequence = serializer.serialize_seq(Some(2))?;
            serde::ser::SerializeSeq::serialize_element(&mut sequence, &0_u8)?;
            self.cancellation.store(true, Ordering::Release);
            serde::ser::SerializeSeq::serialize_element(&mut sequence, &1_u8)?;
            serde::ser::SerializeSeq::end(sequence)
        }
    }

    struct PauseMidSerialization;

    impl Serialize for PauseMidSerialization {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let mut sequence = serializer.serialize_seq(Some(2))?;
            serde::ser::SerializeSeq::serialize_element(&mut sequence, &0_u8)?;
            std::thread::sleep(Duration::from_millis(5));
            serde::ser::SerializeSeq::serialize_element(&mut sequence, &1_u8)?;
            serde::ser::SerializeSeq::end(sequence)
        }
    }

    #[tokio::test]
    async fn bounded_storage_and_counter_stop_cooperatively_with_distinct_errors() {
        let storage_cancellation = AtomicBool::new(false);
        let mut output = Vec::new();
        let deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_secs(1))
            .expect("test deadline");
        let error = write_frame_bounded_until_cancellable(
            &mut output,
            &CancelMidSerialization {
                cancellation: &storage_cancellation,
            },
            MIN_NEGOTIATED_FRAME_SIZE,
            deadline,
            &storage_cancellation,
        )
        .await
        .expect_err("cancellation during encoding must stop before the prefix");
        assert!(matches!(
            error,
            ProtocolError::Io(ref error) if error.kind() == std::io::ErrorKind::Interrupted
        ));
        assert!(output.is_empty());

        let counter_cancellation = AtomicBool::new(false);
        let error = ensure_frame_fits_until(
            &CancelMidSerialization {
                cancellation: &counter_cancellation,
            },
            MIN_NEGOTIATED_FRAME_SIZE,
            deadline,
            &counter_cancellation,
        )
        .expect_err("counter cancellation must not be reported as serialization failure");
        assert!(matches!(
            error,
            ProtocolError::Io(ref error) if error.kind() == std::io::ErrorKind::Interrupted
        ));

        let deadline_cancellation = AtomicBool::new(false);
        let short_deadline = tokio::time::Instant::now()
            .checked_add(Duration::from_millis(1))
            .expect("short test deadline");
        let error = ensure_frame_fits_until(
            &PauseMidSerialization,
            MIN_NEGOTIATED_FRAME_SIZE,
            short_deadline,
            &deadline_cancellation,
        )
        .expect_err("counter must notice a deadline that expires during serialization");
        assert!(matches!(
            error,
            ProtocolError::Io(ref error) if error.kind() == std::io::ErrorKind::TimedOut
        ));
    }

    #[tokio::test]
    async fn expired_bounded_write_deadline_emits_nothing() {
        let mut writer = Vec::new();
        let error = write_frame_bounded_until(
            &mut writer,
            &Response::WatchStream,
            MIN_NEGOTIATED_FRAME_SIZE,
            tokio::time::Instant::now(),
        )
        .await
        .expect_err("expired deadline must fail");
        assert!(matches!(
            error,
            ProtocolError::Io(ref error) if error.kind() == std::io::ErrorKind::TimedOut
        ));
        assert!(writer.is_empty());

        let error = write_frame_within(&mut writer, &Response::WatchStream, Duration::MAX)
            .await
            .expect_err("unrepresentable relative deadline must fail without panicking");
        assert!(matches!(error, ProtocolError::InvalidWireValue));
        assert!(writer.is_empty());
    }

    #[tokio::test]
    async fn conservative_payload_budget_traverses_exact_get_and_cas_envelopes() {
        assert_eq!(conservative_payload_budget(MIN_NEGOTIATED_FRAME_SIZE), 0);
        let minimum_record = StoredSessionRecord {
            key: SessionKey {
                tenant: TenantId::new("t").expect("minimum tenant"),
                nf_kind: NetworkFunctionKind::new("x").expect("minimum NF kind"),
                key_type: SessionKeyType::PduSession,
                stable_id: Bytes::from_static(&[0])
                    .try_into()
                    .expect("valid stable ID"),
            },
            generation: Generation::new(1),
            owner: OwnerId::new("r").expect("minimum owner"),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("s").expect("minimum state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([]),
        };
        ensure_get_success_frame_fits(&Some(minimum_record), MIN_NEGOTIATED_FRAME_SIZE)
            .expect("minimum negotiated frame must carry an empty-payload Get response");

        let max_key = SessionKey {
            tenant: TenantId::new("t".repeat(128)).expect("maximum tenant"),
            nf_kind: NetworkFunctionKind::new("n".repeat(64)).expect("maximum NF kind"),
            key_type: SessionKeyType::other("\u{1}".repeat(SESSION_KEY_TYPE_MAX_BYTES))
                .expect("maximum escaped key type"),
            // Use the complete digest-oriented transport allowance and
            // worst-case JSON byte values.
            stable_id: Bytes::from(vec![u8::MAX; MAX_SESSION_NET_STABLE_ID_BYTES])
                .try_into()
                .expect("maximum stable ID"),
        };
        let max_owner =
            OwnerId::new("\u{1}".repeat(OWNER_ID_MAX_BYTES)).expect("maximum escaped owner");
        let backend = FakeSessionBackend::new();
        let lease = backend
            .acquire(&max_key, max_owner.clone(), Duration::from_secs(60))
            .await
            .expect("maximum-metadata lease");

        let frame_size = DEFAULT_MAX_FRAME_SIZE;
        let payload_budget = conservative_payload_budget(frame_size);
        assert!(payload_budget > 0);
        let max_record = StoredSessionRecord {
            key: max_key.clone(),
            generation: Generation::new(1),
            owner: max_owner.clone(),
            fence: lease.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("\u{1}".repeat(STATE_TYPE_MAX_BYTES))
                .expect("maximum escaped state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(vec![u8::MAX; payload_budget]),
        };
        ensure_get_success_frame_fits(&Some(max_record.clone()), frame_size).expect(
            "published worst-byte payload budget must cross the maximum-metadata Get envelope",
        );
        ensure_frame_fits(
            &Request::CompareAndSet {
                op: CompareAndSet {
                    key: max_key.clone(),
                    lease: lease.clone(),
                    expected_generation: None,
                    new_record: max_record,
                },
                request_id: Some(uuid::Uuid::nil().to_string()),
                idempotency_epoch: Some(uuid::Uuid::from_u128(1).to_string()),
            },
            frame_size,
        )
        .expect("published worst-byte payload budget must cross the maximum-metadata CAS envelope");

        let unequal_payload_budget = conservative_payload_budget(MIN_NEGOTIATED_FRAME_SIZE)
            .min(conservative_payload_budget(DEFAULT_MAX_FRAME_SIZE));
        assert_eq!(unequal_payload_budget, 0);
        let unequal_record = StoredSessionRecord {
            key: max_key.clone(),
            generation: Generation::new(2),
            owner: max_owner,
            fence: lease.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("\u{1}".repeat(STATE_TYPE_MAX_BYTES))
                .expect("maximum escaped state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(vec![u8::MAX; unequal_payload_budget]),
        };
        ensure_get_success_frame_fits(&Some(unequal_record.clone()), MIN_NEGOTIATED_FRAME_SIZE)
            .expect("minimum frame must carry maximum-metadata empty-payload Get response");
        let minimum_cas = Request::CompareAndSet {
            op: CompareAndSet {
                key: max_key,
                lease,
                expected_generation: Some(Generation::new(1)),
                new_record: unequal_record,
            },
            request_id: Some(uuid::Uuid::nil().to_string()),
            idempotency_epoch: Some(uuid::Uuid::from_u128(1).to_string()),
        };
        let minimum_cas_len = serde_json::to_vec(&minimum_cas)
            .expect("size minimum CAS")
            .len();
        ensure_frame_fits(&minimum_cas, MIN_NEGOTIATED_FRAME_SIZE).unwrap_or_else(|error| {
            panic!(
                "minimum frame must carry maximum-metadata zero-payload CAS ({minimum_cas_len} bytes): {error}"
            )
        });
        ensure_frame_fits(
            &Response::CompareAndSet(Ok(CompareAndSetResult::Success)),
            MIN_NEGOTIATED_FRAME_SIZE,
        )
        .expect("unequal-limit CAS acknowledgement must fit the minimum response direction");
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
            tx_id: "protocol-invariant-entry"
                .try_into()
                .expect("valid transaction ID"),
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
                    request_id: Some(uuid::Uuid::nil().to_string()),
                    idempotency_epoch: Some(uuid::Uuid::from_u128(1).to_string()),
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
