//! Least-authority application consumer contract for a session quorum.
//!
//! This module intentionally models only application state and lease
//! operations. It has no Openraft member, vote, topology, snapshot, or raw
//! replication-rebuild operation. A transport authenticates a
//! [`SessionConsumerIdentity`] separately from quorum members, then forwards
//! the typed request to a quorum-side implementation of
//! [`SessionQuorumConsumer`].

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::BoxStream;
use serde::{Deserialize, Serialize};

use crate::{
    BackendCapabilities, CompareAndSet, CompareAndSetResult, LeaseError, LeaseGuard, OwnerId,
    RecordExpiryPreflight, RestoreScanPage, RestoreScanRequest, SessionConsensusIdentity,
    SessionConsensusRequestId, SessionKey, SessionOp, SessionOpResult, StoreError,
    StoredSessionRecord, MAX_REPLICATION_OPERATIONS_PER_ENTRY,
};

/// Maximum batch slots admitted by one consumer request.
pub const MAX_SESSION_CONSUMER_BATCH_OPERATIONS: usize = 256;

/// Maximum serialized batch response bytes retained for one consumer request.
///
/// This is deliberately lower than the transport frame ceiling. It bounds the
/// aggregate of otherwise individually valid point-read results before the
/// quorum service retains them in a batch response.
pub const MAX_SESSION_CONSUMER_BATCH_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Maximum projected watch bytes queued for one authenticated consumer.
///
/// The consumer registry applies this bound before it clones a change to a
/// subscriber, so a large raw replication entry cannot multiply by consumer
/// connections in the backend's watch queues.
pub const MAX_SESSION_CONSUMER_WATCH_BUFFER_BYTES: usize = 256 * 1024;

/// Fixed byte width of one durable consumer request identity.
pub const SESSION_CONSUMER_REQUEST_ID_BYTES: usize = 16;

/// Maximum UTF-8 width of an authenticated consumer identity.
pub const SESSION_CONSUMER_IDENTITY_MAX_BYTES: usize = 253;

/// Redaction-safe construction failure for [`SessionConsumerIdentity`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid session consumer identity")]
pub struct SessionConsumerIdentityError;

/// Authenticated application identity, deliberately distinct from a quorum
/// member/node identity.
///
/// This value is supplied by the mTLS authorization layer, never by a
/// consumer request frame. Its textual form is retained only for identity
/// binding of durable request IDs and is redacted from `Debug` and errors.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionConsumerIdentity(String);

impl SessionConsumerIdentity {
    /// Validate one canonical authenticated application identity.
    pub fn new(value: impl Into<String>) -> Result<Self, SessionConsumerIdentityError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > SESSION_CONSUMER_IDENTITY_MAX_BYTES
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(SessionConsumerIdentityError);
        }
        Ok(Self(value))
    }

    /// Borrow the identity for authenticated authorization and request binding.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SessionConsumerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerIdentity(<redacted>)")
    }
}

/// Fixed-width client-generated request identity for one consumer operation.
///
/// The quorum-side adapter combines it with the authenticated consumer
/// identity before submitting the existing durable consensus request ID. A
/// client may explicitly retry an unconfirmed request with this same ID, but
/// this SDK never performs that replay automatically.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionConsumerRequestId([u8; SESSION_CONSUMER_REQUEST_ID_BYTES]);

impl SessionConsumerRequestId {
    /// Generate a new opaque request identity.
    pub fn new() -> Self {
        Self(*uuid::Uuid::new_v4().as_bytes())
    }

    /// Reconstruct an identity retained by an application across a retry.
    pub const fn from_bytes(bytes: [u8; SESSION_CONSUMER_REQUEST_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the fixed-width representation.
    pub const fn as_bytes(&self) -> &[u8; SESSION_CONSUMER_REQUEST_ID_BYTES] {
        &self.0
    }
}

impl Default for SessionConsumerRequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SessionConsumerRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerRequestId(<redacted>)")
    }
}

/// Exact cluster/configuration/epoch scope a consumer must present on every
/// request.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConsumerScope(SessionConsensusIdentity);

impl SessionConsumerScope {
    /// Bind the consumer contract to one exact consensus scope.
    pub const fn new(identity: SessionConsensusIdentity) -> Self {
        Self(identity)
    }

    /// Return the exact consensus identity being scoped.
    pub const fn consensus_identity(self) -> SessionConsensusIdentity {
        self.0
    }
}

impl fmt::Debug for SessionConsumerScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerScope(<redacted>)")
    }
}

/// Store-issued, scope-bound manifest of currently admitted consensus-member
/// identities. Its constructor is crate-private so a consumer listener cannot
/// be configured with an invented or incomplete exclusion set.
#[derive(Clone)]
pub struct SessionConsumerAuthorizationManifest {
    scope: SessionConsumerScope,
    consensus_members: BTreeSet<SessionConsumerIdentity>,
}

impl SessionConsumerAuthorizationManifest {
    pub(crate) fn new(
        scope: SessionConsumerScope,
        consensus_members: BTreeSet<SessionConsumerIdentity>,
    ) -> Self {
        Self {
            scope,
            consensus_members,
        }
    }

    /// Exact scope attested by the quorum store when this manifest was made.
    pub const fn scope(&self) -> SessionConsumerScope {
        self.scope
    }

    /// Iterate the authoritative member exclusion set without exposing a
    /// constructor that could replace it.
    pub fn consensus_member_identities(&self) -> impl Iterator<Item = &str> {
        self.consensus_members
            .iter()
            .map(SessionConsumerIdentity::as_str)
    }
}

impl fmt::Debug for SessionConsumerAuthorizationManifest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionConsumerAuthorizationManifest")
            .field("scope", &self.scope)
            .field("consensus_member_count", &self.consensus_members.len())
            .finish()
    }
}

/// Typed operation admitted by the stateless consumer boundary.
///
/// Deliberately absent are consensus-engine RPCs, membership/topology changes,
/// snapshots, raw replication append, and replication rebuild.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum SessionConsumerOperation {
    /// Read the quorum's current backend capability declaration.
    Capabilities,
    /// Authoritative, linearizable record read.
    Get {
        /// Session key to retrieve.
        key: SessionKey,
    },
    /// Validate payload-free absolute-expiry preflights at leader authority.
    PreflightRecordExpiry {
        /// Bounded payload-free expiry descriptors.
        preflights: Vec<RecordExpiryPreflight>,
    },
    /// Fenced compare-and-set mutation.
    CompareAndSet {
        /// Exact fenced mutation.
        op: Box<CompareAndSet>,
    },
    /// Fenced deletion.
    DeleteFenced {
        /// Existing lease credential.
        lease: LeaseGuard,
    },
    /// Fenced TTL refresh.
    RefreshTtl {
        /// Existing lease credential.
        lease: LeaseGuard,
        /// Requested bounded TTL.
        ttl: Duration,
    },
    /// Bounded sequential application batch.
    Batch {
        /// Operations in caller order.
        ops: Vec<SessionOp>,
    },
    /// Bounded restore scan.
    ScanRestoreRecords {
        /// Requested restore page.
        request: RestoreScanRequest,
    },
    /// Open a bounded committed-change watch from the inclusive sequence.
    Watch {
        /// Inclusive committed sequence to watch.
        start_sequence: u64,
    },
    /// Acquire a fenced lease.
    AcquireLease {
        /// Session key to lease.
        key: SessionKey,
        /// Requested owner.
        owner: OwnerId,
        /// Requested bounded TTL.
        ttl: Duration,
    },
    /// Renew an existing lease.
    RenewLease {
        /// Existing lease credential.
        lease: LeaseGuard,
        /// Requested bounded TTL.
        ttl: Duration,
    },
    /// Release an existing lease.
    ReleaseLease {
        /// Existing lease credential.
        lease: LeaseGuard,
    },
}

impl fmt::Debug for SessionConsumerOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Capabilities => "Capabilities",
            Self::Get { .. } => "Get",
            Self::PreflightRecordExpiry { .. } => "PreflightRecordExpiry",
            Self::CompareAndSet { .. } => "CompareAndSet",
            Self::DeleteFenced { .. } => "DeleteFenced",
            Self::RefreshTtl { .. } => "RefreshTtl",
            Self::Batch { .. } => "Batch",
            Self::ScanRestoreRecords { .. } => "ScanRestoreRecords",
            Self::Watch { .. } => "Watch",
            Self::AcquireLease { .. } => "AcquireLease",
            Self::RenewLease { .. } => "RenewLease",
            Self::ReleaseLease { .. } => "ReleaseLease",
        };
        formatter.write_str(name)
    }
}

impl SessionConsumerOperation {
    /// Check fixed consumer-side operation bounds before quorum dispatch.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        let validate_lease = |lease: &LeaseGuard| {
            lease
                .validate_profile()
                .map_err(|_| SessionConsumerRejection::MalformedRequest)
        };
        match self {
            Self::PreflightRecordExpiry { preflights } => {
                crate::validate_record_expiry_preflights_profile(preflights)
                    .map_err(|_| SessionConsumerRejection::MalformedRequest)
            }
            Self::Batch { ops } => {
                if ops.len() > MAX_SESSION_CONSUMER_BATCH_OPERATIONS {
                    return Err(SessionConsumerRejection::MalformedRequest);
                }
                crate::validate_session_ops_profile(ops)
                    .map_err(|_| SessionConsumerRejection::MalformedRequest)
            }
            Self::ScanRestoreRecords { request } => request
                .validate()
                .map_err(|_| SessionConsumerRejection::MalformedRequest),
            Self::CompareAndSet { op } => validate_lease(&op.lease),
            Self::DeleteFenced { lease } | Self::ReleaseLease { lease } => validate_lease(lease),
            Self::RefreshTtl { lease, ttl } | Self::RenewLease { lease, ttl } => {
                validate_lease(lease)?;
                crate::validate_session_ttl(*ttl)
                    .map_err(|_| SessionConsumerRejection::MalformedRequest)
            }
            Self::AcquireLease { ttl, .. } => crate::validate_session_ttl(*ttl)
                .map_err(|_| SessionConsumerRejection::MalformedRequest),
            Self::Capabilities | Self::Get { .. } | Self::Watch { .. } => Ok(()),
        }
    }
}

/// One scope-bound consumer request.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerRequest {
    scope: SessionConsumerScope,
    request_id: SessionConsumerRequestId,
    operation: SessionConsumerOperation,
}

impl SessionConsumerRequest {
    /// Construct one exact operation request.
    pub const fn new(
        scope: SessionConsumerScope,
        request_id: SessionConsumerRequestId,
        operation: SessionConsumerOperation,
    ) -> Self {
        Self {
            scope,
            request_id,
            operation,
        }
    }

    /// Exact cluster/configuration/epoch scope supplied by the caller.
    pub const fn scope(&self) -> SessionConsumerScope {
        self.scope
    }

    /// Caller-retained durable request identity.
    pub const fn request_id(&self) -> SessionConsumerRequestId {
        self.request_id
    }

    /// Typed application operation.
    pub const fn operation(&self) -> &SessionConsumerOperation {
        &self.operation
    }

    /// Validate the operation before dispatch.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        self.operation.validate()
    }
}

impl fmt::Debug for SessionConsumerRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionConsumerRequest")
            .field("scope", &self.scope)
            .field("request_id", &self.request_id)
            .field("operation", &self.operation)
            .finish()
    }
}

/// Closed, wire-safe store error returned by a consumer operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerStoreError {
    /// No live record exists.
    NotFound,
    /// A newer lease owner fenced this request.
    StaleFence,
    /// Compare-and-set did not match the current generation.
    CasConflict,
    /// A request ID was reused for another operation.
    RequestConflict,
    /// A mutation outcome is no longer known.
    OutcomeUnavailable,
    /// Topology authority is unavailable or no quorum is reachable.
    Unavailable,
    /// Input is structurally invalid.
    InvalidInput,
    /// The requested capability is deliberately absent.
    CapabilityNotSupported,
    /// A bounded watch requires coherent catch-up.
    WatchCatchUpRequired,
    /// The restore request or page is invalid.
    RestoreRejected,
    /// The restore cursor is stale.
    RestoreCursorStale,
    /// A restore scan exceeded its work or frame budget.
    RestoreBudgetExceeded,
    /// The requested TTL is invalid.
    InvalidTtl,
    /// The provided lease is held or expired.
    LeaseUnavailable,
    /// A payload exceeded the admitted size.
    PayloadTooLarge,
    /// The backend rejected protected data.
    ProtectedDataRejected,
}

impl From<StoreError> for SessionConsumerStoreError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::NotFound => Self::NotFound,
            StoreError::StaleFence | StoreError::TopologyAuthorityRevoked => Self::StaleFence,
            StoreError::CasConflict => Self::CasConflict,
            StoreError::CasIdempotencyConflict => Self::RequestConflict,
            StoreError::CasIdempotencyOutcomeUnavailable
            | StoreError::BackendOperationOutcomeUnavailable => Self::OutcomeUnavailable,
            StoreError::BackendUnavailable(_) => Self::Unavailable,
            StoreError::CapabilityNotSupported(_) => Self::CapabilityNotSupported,
            StoreError::InvalidKey(_)
            | StoreError::InvalidReplicationSequence
            | StoreError::InvalidReplicationLogRange
            | StoreError::ReplicationLogPageTooLarge { .. }
            | StoreError::ReplicationLogCursorCompacted { .. }
            | StoreError::ReplicationOperationLimitExceeded
            | StoreError::RecordExpiryPreflightLimitExceeded
            | StoreError::InvalidRecordExpiry => Self::InvalidInput,
            StoreError::ReplicationWatchCatchUpRequired => Self::WatchCatchUpRequired,
            StoreError::InvalidSessionTtl => Self::InvalidTtl,
            StoreError::LeaseHeld | StoreError::LeaseExpired => Self::LeaseUnavailable,
            StoreError::Crypto(_) | StoreError::Serialization(_) => Self::ProtectedDataRejected,
            StoreError::PayloadTooLarge { .. } => Self::PayloadTooLarge,
            StoreError::InvalidRestoreScanRequest(_)
            | StoreError::InvalidRestoreScanResponse(_)
            | StoreError::RestoreScanPageTooLarge { .. } => Self::RestoreRejected,
            StoreError::RestoreScanCursorStale => Self::RestoreCursorStale,
            StoreError::RestoreScanWorkBudgetExceeded
            | StoreError::RestoreScanResponseTooLarge { .. } => Self::RestoreBudgetExceeded,
        }
    }
}

impl SessionConsumerStoreError {
    /// Convert a safe protocol error into the domain error expected by
    /// application-facing storage traits.
    pub fn into_store_error(self) -> StoreError {
        match self {
            Self::NotFound => StoreError::NotFound,
            Self::StaleFence => StoreError::StaleFence,
            Self::CasConflict => StoreError::CasConflict,
            Self::RequestConflict => StoreError::CasIdempotencyConflict,
            Self::OutcomeUnavailable => StoreError::BackendOperationOutcomeUnavailable,
            Self::Unavailable => {
                StoreError::BackendUnavailable("consumer quorum unavailable".into())
            }
            Self::InvalidInput => StoreError::InvalidKey("consumer request rejected".into()),
            Self::CapabilityNotSupported => {
                StoreError::CapabilityNotSupported("consumer capability unavailable".into())
            }
            Self::WatchCatchUpRequired => StoreError::ReplicationWatchCatchUpRequired,
            Self::RestoreRejected => {
                StoreError::InvalidRestoreScanRequest("consumer restore request rejected".into())
            }
            Self::RestoreCursorStale => StoreError::RestoreScanCursorStale,
            Self::RestoreBudgetExceeded => StoreError::RestoreScanWorkBudgetExceeded,
            Self::InvalidTtl => StoreError::InvalidSessionTtl,
            Self::LeaseUnavailable => StoreError::LeaseHeld,
            Self::PayloadTooLarge => StoreError::PayloadTooLarge { actual: 0, max: 0 },
            Self::ProtectedDataRejected => {
                StoreError::Crypto("consumer protected data rejected".into())
            }
        }
    }
}

/// Closed, wire-safe lease error returned by a consumer operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerLeaseError {
    /// A caller-owned consumer request ID was reused for another operation.
    RequestConflict,
    /// Another consumer currently owns the lease.
    AlreadyHeld,
    /// The presented lease is expired.
    Expired,
    /// The presented fence is stale.
    StaleFence,
    /// The lease no longer exists.
    NotFound,
    /// The requested TTL is invalid.
    InvalidTtl,
    /// The mutation outcome is unknown and the lease must be treated as lost.
    OutcomeUnavailable,
    /// The quorum is unavailable and the lease must be treated as lost.
    Unavailable,
}

impl From<LeaseError> for SessionConsumerLeaseError {
    fn from(error: LeaseError) -> Self {
        match error {
            LeaseError::AlreadyHeld => Self::AlreadyHeld,
            LeaseError::Expired => Self::Expired,
            LeaseError::StaleFence => Self::StaleFence,
            LeaseError::NotFound => Self::NotFound,
            LeaseError::InvalidSessionTtl => Self::InvalidTtl,
            LeaseError::OperationOutcomeUnavailable => Self::OutcomeUnavailable,
            LeaseError::Backend(_) => Self::Unavailable,
        }
    }
}

impl SessionConsumerLeaseError {
    /// Convert a safe protocol lease error into the application trait error.
    pub fn into_lease_error(self) -> LeaseError {
        match self {
            Self::RequestConflict => LeaseError::Backend("consumer request conflict".into()),
            Self::AlreadyHeld => LeaseError::AlreadyHeld,
            Self::Expired => LeaseError::Expired,
            Self::StaleFence => LeaseError::StaleFence,
            Self::NotFound => LeaseError::NotFound,
            Self::InvalidTtl => LeaseError::InvalidSessionTtl,
            Self::OutcomeUnavailable => LeaseError::OperationOutcomeUnavailable,
            Self::Unavailable => LeaseError::Backend("consumer quorum unavailable".into()),
        }
    }
}

/// Explicit classification for a request that might have crossed its effect
/// point but cannot be confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionConsumerOutcomeUnknown {
    /// An application state mutation may have committed.
    Mutation,
    /// A lease mutation may have committed; the current guard is lost.
    Lease,
}

/// Least-authority committed-change projection for application consumers.
///
/// This is intentionally not a replication entry: it omits replay payloads,
/// lease credentials, absolute deadlines, transaction IDs, and raw
/// replication operation trees.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerChange {
    sequence: u64,
    changes: Vec<SessionConsumerChangeItem>,
}

/// One affected session key within a [`SessionConsumerChange`].
///
/// This is a deliberately coarse projection. It is not a lease credential,
/// fence, expiry, owner, record payload, replication transaction, or replay
/// instruction.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerChangeItem {
    key: SessionKey,
    kind: SessionConsumerChangeKind,
}

impl SessionConsumerChange {
    /// Committed change sequence used only as a consumer watch cursor.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Coarse affected keys in their committed batch order.
    ///
    /// One replication sequence can contain a bounded nested batch, so the
    /// consumer projection preserves every leaf change in one envelope rather
    /// than dropping all but the first key.
    pub fn changes(&self) -> &[SessionConsumerChangeItem] {
        self.changes.as_slice()
    }
}

impl fmt::Debug for SessionConsumerChange {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerChange(<redacted>)")
    }
}

impl SessionConsumerChangeItem {
    /// Session key affected by this committed leaf change.
    pub const fn key(&self) -> &SessionKey {
        &self.key
    }

    /// Coarse application-visible change kind.
    pub const fn kind(&self) -> SessionConsumerChangeKind {
        self.kind
    }
}

impl fmt::Debug for SessionConsumerChangeItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerChangeItem(<redacted>)")
    }
}

/// Coarse committed change class exposed by [`SessionConsumerChange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionConsumerChangeKind {
    /// A session record was created or replaced.
    RecordWritten,
    /// A session record was deleted.
    RecordDeleted,
    /// A session record TTL changed.
    RecordTtlRefreshed,
    /// A session lease was acquired.
    LeaseAcquired,
    /// A session lease was renewed.
    LeaseRenewed,
    /// A session lease was released.
    LeaseReleased,
}

pub(crate) fn session_consumer_change(
    entry: &crate::ReplicationEntry,
) -> Result<SessionConsumerChange, StoreError> {
    // A replication batch is a recursive replay instruction. Flatten it
    // iteratively so a historical bounded nested batch remains faithfully
    // observable without exposing that instruction tree at the consumer
    // boundary. Count both batch containers and leaves under the existing
    // SDK-wide admission cap; a malformed stored entry therefore fails the
    // watch closed instead of allocating an unbounded projection.
    let mut pending = vec![&entry.op];
    let mut visited = 0_usize;
    let mut changes = Vec::with_capacity(MAX_REPLICATION_OPERATIONS_PER_ENTRY);
    while let Some(operation) = pending.pop() {
        visited = visited
            .checked_add(1)
            .ok_or(StoreError::ReplicationOperationLimitExceeded)?;
        if visited > MAX_REPLICATION_OPERATIONS_PER_ENTRY {
            return Err(StoreError::ReplicationOperationLimitExceeded);
        }
        let item = match operation {
            crate::ReplicationOp::CompareAndSet { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::RecordWritten,
            }),
            crate::ReplicationOp::DeleteFenced { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::RecordDeleted,
            }),
            crate::ReplicationOp::RefreshTtl { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::RecordTtlRefreshed,
            }),
            crate::ReplicationOp::AcquireLease { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::LeaseAcquired,
            }),
            crate::ReplicationOp::RenewLease { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::LeaseRenewed,
            }),
            crate::ReplicationOp::ReleaseLease { key, .. } => Some(SessionConsumerChangeItem {
                key: key.clone(),
                kind: SessionConsumerChangeKind::LeaseReleased,
            }),
            crate::ReplicationOp::Batch { ops } => {
                pending.extend(ops.iter().rev());
                None
            }
        };
        if let Some(item) = item {
            changes.push(item);
        }
    }
    Ok(SessionConsumerChange {
        sequence: entry.sequence,
        changes,
    })
}

pub(crate) fn session_consumer_change_encoded_bytes(
    change: &SessionConsumerChange,
) -> Result<usize, StoreError> {
    serde_json::to_vec(change)
        .map(|encoded| encoded.len().saturating_add(256))
        .map_err(|_| StoreError::Serialization("consumer watch projection encoding failed".into()))
}

/// Closed rejection before an operation reaches the consensus state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionConsumerRejection {
    /// Cluster/configuration/epoch differs from the live quorum scope.
    ScopeMismatch,
    /// The typed request violated a fixed contract bound.
    MalformedRequest,
    /// The mTLS identity is not authorized as a consumer.
    Unauthorized,
    /// The server cannot dispatch the request within its bound.
    Unavailable,
}

/// Safe result of one batch slot.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum SessionConsumerBatchResult {
    /// Point-read slot result.
    Get(Result<Option<StoredSessionRecord>, SessionConsumerStoreError>),
    /// Compare-and-set slot result.
    CompareAndSet(Result<CompareAndSetResult, SessionConsumerStoreError>),
    /// Delete slot result.
    DeleteFenced(Result<(), SessionConsumerStoreError>),
    /// TTL-refresh slot result.
    RefreshTtl(Result<(), SessionConsumerStoreError>),
}

impl fmt::Debug for SessionConsumerBatchResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionConsumerBatchResult(<redacted>)")
    }
}

/// Typed response from one stateless consumer operation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "response",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum SessionConsumerResponse {
    /// Capability declaration.
    Capabilities(BackendCapabilities),
    /// Point-read result.
    Get(Result<Option<StoredSessionRecord>, SessionConsumerStoreError>),
    /// Record-expiry preflight result.
    PreflightRecordExpiry(Result<(), SessionConsumerStoreError>),
    /// Compare-and-set result.
    CompareAndSet(Result<CompareAndSetResult, SessionConsumerStoreError>),
    /// Delete result.
    DeleteFenced(Result<(), SessionConsumerStoreError>),
    /// TTL-refresh result.
    RefreshTtl(Result<(), SessionConsumerStoreError>),
    /// Batch result.
    Batch(Result<Vec<SessionConsumerBatchResult>, SessionConsumerStoreError>),
    /// Restore scan result.
    ScanRestoreRecords(Result<RestoreScanPage, SessionConsumerStoreError>),
    /// Watch admission result; entries follow as separately framed messages.
    WatchOpened,
    /// Lease acquisition result.
    AcquireLease(Result<LeaseGuard, SessionConsumerLeaseError>),
    /// Lease renewal result.
    RenewLease(Result<LeaseGuard, SessionConsumerLeaseError>),
    /// Lease release result.
    ReleaseLease(Result<(), SessionConsumerLeaseError>),
    /// A mutation outcome is ambiguous and must never be automatically replayed.
    OutcomeUnknown(SessionConsumerOutcomeUnknown),
    /// A request was rejected before dispatch.
    Rejected(SessionConsumerRejection),
}

impl fmt::Debug for SessionConsumerResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Capabilities(_) => "Capabilities",
            Self::Get(_) => "Get",
            Self::PreflightRecordExpiry(_) => "PreflightRecordExpiry",
            Self::CompareAndSet(_) => "CompareAndSet",
            Self::DeleteFenced(_) => "DeleteFenced",
            Self::RefreshTtl(_) => "RefreshTtl",
            Self::Batch(_) => "Batch",
            Self::ScanRestoreRecords(_) => "ScanRestoreRecords",
            Self::WatchOpened => "WatchOpened",
            Self::AcquireLease(_) => "AcquireLease",
            Self::RenewLease(_) => "RenewLease",
            Self::ReleaseLease(_) => "ReleaseLease",
            Self::OutcomeUnknown(_) => "OutcomeUnknown",
            Self::Rejected(_) => "Rejected",
        };
        formatter.write_str(name)
    }
}

/// Quorum-side typed application service used by the dedicated consumer
/// transport.
///
/// Implementations must authenticate the supplied identity at their inbound
/// boundary, reject a scope mismatch before backend work, and route mutations
/// through the durable quorum leader path. This trait intentionally cannot
/// express any consensus RPC, member/topology mutation, snapshot, or raw
/// replication append/rebuild request.
#[async_trait]
pub trait SessionQuorumConsumer: Send + Sync {
    /// Execute one authenticated, scope-bound consumer request.
    async fn execute(
        &self,
        identity: &SessionConsumerIdentity,
        request: SessionConsumerRequest,
    ) -> SessionConsumerResponse;

    /// Open a bounded committed-change watch after authenticated scope checks.
    async fn watch(
        &self,
        identity: &SessionConsumerIdentity,
        scope: SessionConsumerScope,
        start_sequence: u64,
    ) -> Result<
        BoxStream<'static, Result<SessionConsumerChange, SessionConsumerStoreError>>,
        SessionConsumerRejection,
    >;
}

/// Convert an application batch result into its wire-safe counterpart.
pub fn session_consumer_batch_result(result: SessionOpResult) -> SessionConsumerBatchResult {
    match result {
        SessionOpResult::Get(result) => {
            SessionConsumerBatchResult::Get(result.map_err(SessionConsumerStoreError::from))
        }
        SessionOpResult::CompareAndSet(result) => SessionConsumerBatchResult::CompareAndSet(
            result.map_err(SessionConsumerStoreError::from),
        ),
        SessionOpResult::DeleteFenced(result) => SessionConsumerBatchResult::DeleteFenced(
            result.map_err(SessionConsumerStoreError::from),
        ),
        SessionOpResult::RefreshTtl(result) => {
            SessionConsumerBatchResult::RefreshTtl(result.map_err(SessionConsumerStoreError::from))
        }
    }
}

/// Convert a consumer batch result into the application-facing result.
pub fn session_consumer_batch_result_into_store(
    result: SessionConsumerBatchResult,
) -> SessionOpResult {
    match result {
        SessionConsumerBatchResult::Get(result) => {
            SessionOpResult::Get(result.map_err(SessionConsumerStoreError::into_store_error))
        }
        SessionConsumerBatchResult::CompareAndSet(result) => SessionOpResult::CompareAndSet(
            result.map_err(SessionConsumerStoreError::into_store_error),
        ),
        SessionConsumerBatchResult::DeleteFenced(result) => SessionOpResult::DeleteFenced(
            result.map_err(SessionConsumerStoreError::into_store_error),
        ),
        SessionConsumerBatchResult::RefreshTtl(result) => {
            SessionOpResult::RefreshTtl(result.map_err(SessionConsumerStoreError::into_store_error))
        }
    }
}

/// Derive the durable consumer-request binding ID from an authenticated
/// identity and caller-owned request ID.
///
/// This deliberately excludes the operation commitment: the resulting ID is
/// used for a small quorum-durable binding command, whose payload commitment
/// makes reuse of this caller ID for a different request a closed conflict.
pub(crate) fn derive_consumer_request_binding_id(
    identity: &SessionConsumerIdentity,
    request: &SessionConsumerRequest,
) -> SessionConsensusRequestId {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-consumer/request-binding/v1\\0");
    digest.update(
        u16::try_from(identity.as_str().len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    digest.update(identity.as_str().as_bytes());
    // Keep this stable across a configuration-epoch transition. The marker
    // payload commits the exact scope, so an old caller ID can only recover
    // its original binding or receive a closed conflict; it cannot become a
    // fresh mutation in a successor scope.
    digest.update(request.scope().consensus_identity().cluster_id().as_bytes());
    digest.update(request.request_id().as_bytes());
    let hash: [u8; 32] = digest.finalize().into();
    let mut request_bytes = [0_u8; SESSION_CONSUMER_REQUEST_ID_BYTES];
    request_bytes.copy_from_slice(&hash[..SESSION_CONSUMER_REQUEST_ID_BYTES]);
    SessionConsensusRequestId::from_bytes(request_bytes)
}

/// Hash the full serialized request shape without exposing protected contents.
pub(crate) fn consumer_request_commitment(
    request: &SessionConsumerRequest,
) -> Result<[u8; 32], SessionConsumerRejection> {
    use sha2::{Digest, Sha256};

    let encoded =
        serde_json::to_vec(request).map_err(|_| SessionConsumerRejection::MalformedRequest)?;
    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-consumer/request-commitment/v1\\0");
    digest.update(encoded);
    Ok(digest.finalize().into())
}

/// Derive the operation-specific durable consensus request ID from an
/// authenticated identity, the complete request commitment, and bounded batch
/// slot. The full parent request shape prevents a changed batch from moving a
/// mutation onto an unrelated slot's durable outcome.
pub fn derive_consumer_consensus_request_id(
    identity: &SessionConsumerIdentity,
    request: &SessionConsumerRequest,
    slot: u16,
) -> Result<SessionConsensusRequestId, SessionConsumerRejection> {
    use sha2::{Digest, Sha256};

    let commitment = consumer_request_commitment(request)?;
    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-consumer/operation-request-id/v2\\0");
    digest.update(
        u16::try_from(identity.as_str().len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    digest.update(identity.as_str().as_bytes());
    digest.update(commitment);
    digest.update(slot.to_be_bytes());
    let hash: [u8; 32] = digest.finalize().into();
    let mut request_bytes = [0_u8; SESSION_CONSUMER_REQUEST_ID_BYTES];
    request_bytes.copy_from_slice(&hash[..SESSION_CONSUMER_REQUEST_ID_BYTES]);
    Ok(SessionConsensusRequestId::from_bytes(request_bytes))
}

/// Marker imported by stateless clients to make accidental use of
/// [`crate::SessionBackend`] explicit at composition time.
///
/// A consumer client deliberately composes the application subset instead of
/// implementing `SessionBackend` or [`crate::SessionLeaseManager`]: the former carries
/// legacy replication reconstruction authority and the latter would hide
/// freshly generated retry IDs. Lease calls on this boundary therefore always
/// require a caller-owned [`SessionConsumerRequestId`].
pub trait StatelessSessionConsumer: Send + Sync {}

#[cfg(test)]
mod tests {
    use super::{
        derive_consumer_consensus_request_id, SessionConsumerIdentity, SessionConsumerOperation,
        SessionConsumerRequest, SessionConsumerRequestId, SessionConsumerScope,
    };
    use crate::{
        SessionConsensusClusterId, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId, SessionConsensusIdentity,
    };

    #[test]
    fn durable_request_identity_is_stable_and_consumer_bound() {
        let request_id = SessionConsumerRequestId::from_bytes([7; 16]);
        let scope = SessionConsumerScope::new(SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([1; 32]),
            SessionConsensusConfigurationId::from_bytes([2; 32]),
            SessionConsensusConfigurationEpoch::new(3).expect("non-zero configuration epoch"),
        ));
        let request =
            SessionConsumerRequest::new(scope, request_id, SessionConsumerOperation::Capabilities);
        let changed_request = SessionConsumerRequest::new(
            scope,
            request_id,
            SessionConsumerOperation::Watch { start_sequence: 7 },
        );
        let first = SessionConsumerIdentity::new("spiffe://test.example/consumer/first")
            .expect("valid first consumer identity");
        let second = SessionConsumerIdentity::new("spiffe://test.example/consumer/second")
            .expect("valid second consumer identity");

        assert_eq!(
            derive_consumer_consensus_request_id(&first, &request, 0),
            derive_consumer_consensus_request_id(&first, &request, 0),
            "an explicit retry must preserve the durable request identity"
        );
        assert_ne!(
            derive_consumer_consensus_request_id(&first, &request, 0),
            derive_consumer_consensus_request_id(&second, &request, 0),
            "one consumer cannot collide with another consumer's retry domain"
        );
        assert_ne!(
            derive_consumer_consensus_request_id(&first, &request, 0),
            derive_consumer_consensus_request_id(&first, &request, 1),
            "batch slots must retain independently durable outcomes"
        );
        assert_ne!(
            derive_consumer_consensus_request_id(&first, &request, 0),
            derive_consumer_consensus_request_id(&first, &changed_request, 0),
            "a changed full request shape cannot reuse a slot outcome"
        );
    }

    #[test]
    fn consumer_identity_and_request_debug_are_redacted() {
        let identity = SessionConsumerIdentity::new("spiffe://test.example/consumer/secret")
            .expect("valid consumer identity");
        let request_id = SessionConsumerRequestId::from_bytes([9; 16]);
        let scope = SessionConsumerScope::new(SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([7; 32]),
            SessionConsensusConfigurationId::from_bytes([8; 32]),
            SessionConsensusConfigurationEpoch::new(9).expect("non-zero configuration epoch"),
        ));

        assert!(!format!("{identity:?}").contains(identity.as_str()));
        assert!(!format!("{request_id:?}").contains("090909"));
        assert_eq!(format!("{scope:?}"), "SessionConsumerScope(<redacted>)");
    }

    #[test]
    fn consumer_request_rejects_unknown_wire_fields() {
        let request = SessionConsumerRequest::new(
            SessionConsumerScope::new(SessionConsensusIdentity::new(
                SessionConsensusClusterId::from_bytes([1; 32]),
                SessionConsensusConfigurationId::from_bytes([2; 32]),
                SessionConsensusConfigurationEpoch::new(3).expect("non-zero configuration epoch"),
            )),
            SessionConsumerRequestId::from_bytes([4; 16]),
            SessionConsumerOperation::Watch { start_sequence: 5 },
        );
        let encoded = serde_json::to_value(request).expect("request encodes");
        let mut root_unknown = encoded.clone();
        let serde_json::Value::Object(fields) = &mut root_unknown else {
            panic!("request is an object");
        };
        fields.insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<SessionConsumerRequest>(root_unknown).is_err());

        let mut operation_unknown = encoded;
        let serde_json::Value::Object(fields) = &mut operation_unknown else {
            panic!("request is an object");
        };
        let operation = fields
            .get_mut("operation")
            .and_then(serde_json::Value::as_object_mut)
            .expect("operation is an object");
        operation.insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<SessionConsumerRequest>(operation_unknown).is_err());
    }
}
