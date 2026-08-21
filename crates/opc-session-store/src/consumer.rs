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

use crate::fenced_mutation_roster::{
    compute_fenced_mutation_roster_profile_digest, FencedMutationRosterAdmission,
    FencedMutationRosterCapability, FencedMutationRosterErrorStatus,
    FencedMutationRosterHistoryState, FencedMutationRosterOutcome, FencedMutationRosterProfile,
    FencedMutationRosterRequestId, FencedMutationRosterScope, FencedMutationRosterStatus,
    FencedMutationRosterTerminal,
};
use crate::{
    AtomicFencedTransitionCapability, BackendCapabilities, CompareAndSet, CompareAndSetResult,
    FencedTransitionObservation, FencedTransitionOutcome, FencedTransitionRequest,
    FencedTransitionRequestId, FencedTransitionStatus, FencedTransitionV2Capability,
    FencedTransitionV2HistoryState, FencedTransitionV2Request, FencedTransitionV2RequestId,
    FencedTransitionV2Status, LeaseError, LeaseGuard, OwnerId, RecordExpiryPreflight,
    RestoreScanPage, RestoreScanRequest, SessionConsensusIdentity, SessionConsensusRequestId,
    SessionKey, SessionOp, SessionOpResult, StoreError, StoredSessionRecord,
    FENCED_TRANSITION_REQUEST_ID_BYTES, FENCED_TRANSITION_V2_MAX_PAYLOAD_TOO_LARGE_ACTUAL_BYTES,
    FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES, MAX_REPLICATION_OPERATIONS_PER_ENTRY,
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

const SESSION_CONSUMER_SPIFFE_IDENTITY_COMMITMENT_DOMAIN: &[u8] =
    b"openpacketcore/tls/local-spiffe-identity-commitment/v1\0";
const FENCED_MUTATION_ROSTER_AUTHORITY_SCOPE_DOMAIN: &[u8] =
    b"openpacketcore/session-consumer/fenced-mutation-roster/authority-scope/v1\0";

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

    /// Return the redaction-safe commitment shared with local TLS material.
    ///
    /// A consumer identity is admitted only after mTLS SPIFFE authorization.
    /// The commitment deliberately preserves neither the SPIFFE text nor any
    /// certificate/key material in request, receipt, or diagnostic surfaces.
    pub(crate) fn spiffe_identity_commitment(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};

        let mut digest = Sha256::new();
        digest.update(SESSION_CONSUMER_SPIFFE_IDENTITY_COMMITMENT_DOMAIN);
        digest.update(
            u16::try_from(self.0.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        digest.update(self.0.as_bytes());
        digest.finalize().into()
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

/// Derive the sole V3 roster scope permitted for one authenticated consumer
/// identity at one exact consensus scope.
///
/// `local_identity_commitment` must be obtained from the authenticated local
/// TLS material. The server independently derives the same value from its
/// authenticated [`SessionConsumerIdentity`]. Fixed-width framing makes each
/// domain input unambiguous and keeps all identity material opaque.
pub fn derive_fenced_mutation_roster_scope(
    local_identity_commitment: [u8; 32],
    scope: SessionConsumerScope,
) -> FencedMutationRosterScope {
    use sha2::{Digest, Sha256};

    let identity = scope.consensus_identity();
    let mut digest = Sha256::new();
    digest.update(
        u16::try_from(FENCED_MUTATION_ROSTER_AUTHORITY_SCOPE_DOMAIN.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    digest.update(FENCED_MUTATION_ROSTER_AUTHORITY_SCOPE_DOMAIN);
    digest.update(32_u16.to_be_bytes());
    digest.update(local_identity_commitment);
    digest.update(32_u16.to_be_bytes());
    digest.update(identity.cluster_id().as_bytes());
    digest.update(32_u16.to_be_bytes());
    digest.update(identity.configuration_id().as_bytes());
    digest.update(8_u16.to_be_bytes());
    digest.update(identity.configuration_epoch().get().to_be_bytes());
    FencedMutationRosterScope::from_digest(digest.finalize().into())
}

/// Derive the V3 roster scope expected by the server for its authenticated
/// mTLS consumer identity and authoritative consensus scope.
pub(crate) fn derive_fenced_mutation_roster_scope_for_consumer(
    identity: &SessionConsumerIdentity,
    scope: SessionConsumerScope,
) -> FencedMutationRosterScope {
    derive_fenced_mutation_roster_scope(identity.spiffe_identity_commitment(), scope)
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
    /// Prove the exact atomic fenced-transition capability across the current
    /// admitted voter set.
    FencedTransitionCapability,
    /// Observe one exact record key and its durable fence floor.
    ObserveFencedTransition {
        /// Exact key to observe.
        key: SessionKey,
    },
    /// Atomically acquire or renew one lease and mutate its exact record.
    FencedTransition {
        /// Complete canonical transition body.
        request: Box<FencedTransitionRequest>,
    },
    /// Recover the exact status of one previously submitted transition.
    FencedTransitionStatus {
        /// Complete canonical transition body.
        request: Box<FencedTransitionRequest>,
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
            Self::FencedTransitionCapability => "FencedTransitionCapability",
            Self::ObserveFencedTransition { .. } => "ObserveFencedTransition",
            Self::FencedTransition { .. } => "FencedTransition",
            Self::FencedTransitionStatus { .. } => "FencedTransitionStatus",
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
            Self::FencedTransition { request } | Self::FencedTransitionStatus { request } => {
                request
                    .validate()
                    .map_err(|_| SessionConsumerRejection::MalformedRequest)
            }
            Self::Capabilities
            | Self::Get { .. }
            | Self::Watch { .. }
            | Self::FencedTransitionCapability
            | Self::ObserveFencedTransition { .. } => Ok(()),
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
        self.operation.validate()?;
        match &self.operation {
            SessionConsumerOperation::FencedTransition { request }
            | SessionConsumerOperation::FencedTransitionStatus { request }
                if request.request_id().as_bytes() != self.request_id.as_bytes() =>
            {
                Err(SessionConsumerRejection::MalformedRequest)
            }
            _ => Ok(()),
        }
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

/// Explicit revision-4-only operations for the V2 fenced-transition
/// contract.
///
/// This is deliberately a distinct request family rather than variants on
/// [`SessionConsumerOperation`]. Revision 3's JSON operation vocabulary and
/// its V1 transition semantics therefore remain frozen byte-for-byte.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum SessionConsumerV2Operation {
    /// Prove support for precisely the V2 fenced-transition contract.
    FencedTransitionV2Capability,
    /// Read the bounded public state of the active V2 history epoch.
    FencedTransitionV2HistoryState,
    /// Execute exactly one V2 transition under its full committed identity.
    FencedTransitionV2 {
        /// Complete canonical V2 transition body.
        request: Box<FencedTransitionV2Request>,
    },
    /// Read status for exactly one complete V2 transition body.
    FencedTransitionV2Status {
        /// Complete canonical V2 transition body.
        request: Box<FencedTransitionV2Request>,
    },
}

impl fmt::Debug for SessionConsumerV2Operation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::FencedTransitionV2Capability => "FencedTransitionV2Capability",
            Self::FencedTransitionV2HistoryState => "FencedTransitionV2HistoryState",
            Self::FencedTransitionV2 { .. } => "FencedTransitionV2",
            Self::FencedTransitionV2Status { .. } => "FencedTransitionV2Status",
        };
        formatter.write_str(name)
    }
}

impl SessionConsumerV2Operation {
    fn request_id(&self) -> Option<FencedTransitionV2RequestId> {
        match self {
            Self::FencedTransitionV2 { request } | Self::FencedTransitionV2Status { request } => {
                Some(request.request_id())
            }
            Self::FencedTransitionV2Capability | Self::FencedTransitionV2HistoryState => None,
        }
    }

    /// Validate the bounded V2 request body before quorum dispatch.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        match self {
            Self::FencedTransitionV2 { request } | Self::FencedTransitionV2Status { request } => {
                // A complete V2 ID commits to its body. A structurally valid
                // body substituted under a retained full ID is therefore a
                // typed request conflict, not a malformed wire frame. Admit
                // it so execute/status can report their respective conflict
                // semantics; every other validation failure remains a
                // transport rejection.
                match request.validate() {
                    Ok(()) | Err(StoreError::FencedTransitionRequestConflict) => Ok(()),
                    Err(_) => Err(SessionConsumerRejection::MalformedRequest),
                }
            }
            Self::FencedTransitionV2Capability | Self::FencedTransitionV2HistoryState => Ok(()),
        }
    }
}

/// One scope-bound revision-4 V2 consumer request.
///
/// V2 execute/status retain the full 56-byte V2 request identity outside the
/// operation body as well as inside it. The duplicated value is intentional:
/// it closes truncated-ID and cross-body substitutions before the request can
/// reach the consensus service. Capability and history-state reads have no
/// mutation identity and therefore use `None`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerV2Request {
    scope: SessionConsumerScope,
    request_id: Option<FencedTransitionV2RequestId>,
    operation: SessionConsumerV2Operation,
}

impl SessionConsumerV2Request {
    /// Construct an exact revision-4 V2 request.
    pub fn new(scope: SessionConsumerScope, operation: SessionConsumerV2Operation) -> Self {
        let request_id = operation.request_id();
        Self {
            scope,
            request_id,
            operation,
        }
    }

    /// Exact consensus scope supplied by the caller.
    pub const fn scope(&self) -> SessionConsumerScope {
        self.scope
    }

    /// Full V2 stable identity for execute/status, if this is an effectful
    /// V2 operation.
    pub const fn request_id(&self) -> Option<FencedTransitionV2RequestId> {
        self.request_id
    }

    /// Typed revision-4-only operation.
    pub const fn operation(&self) -> &SessionConsumerV2Operation {
        &self.operation
    }

    /// Enforce V2's full outer-ID commitment before dispatch.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        self.operation.validate()?;
        if self.request_id != self.operation.request_id() {
            return Err(SessionConsumerRejection::MalformedRequest);
        }
        Ok(())
    }
}

impl fmt::Debug for SessionConsumerV2Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionConsumerV2Request")
            .field("scope", &self.scope)
            .field("request_id", &self.request_id)
            .field("operation", &self.operation)
            .finish()
    }
}

/// The only profile that may be used by the revision-5 protected roster
/// lane.  It deliberately includes the transport, operation, and error
/// revisions in addition to the immutable domain profile digest: matching a
/// digest alone must never permit a peer to reinterpret a roster response
/// under a different wire error vocabulary.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerFencedMutationRosterProfile {
    /// Dedicated consumer transport revision.
    pub transport_revision: u16,
    /// Closed roster operation vocabulary revision.
    pub operation_revision: u16,
    /// Closed roster error vocabulary revision.
    pub error_revision: u16,
    /// Immutable bounded storage and codec profile.
    pub roster: FencedMutationRosterProfile,
    /// Maximum exact roster member count.
    pub max_members: u8,
    /// Maximum protected plan or checkpoint bytes.
    pub max_plan_or_checkpoint_bytes: u32,
    /// Maximum protected exact result bytes.
    pub max_exact_result_bytes: u32,
    /// Maximum live admitted rosters.
    pub max_live: u16,
    /// Maximum retained result bindings.
    pub retained_result_capacity: u32,
    /// Maximum reclamation batch.
    pub reclaim_batch: u16,
    /// Exact result retention duration in seconds.
    pub retention_seconds: u32,
}

impl SessionConsumerFencedMutationRosterProfile {
    /// Construct the one accepted revision-5 roster profile.
    pub fn v2() -> Self {
        Self {
            transport_revision: 5,
            operation_revision: 2,
            error_revision: 1,
            roster: FencedMutationRosterProfile::v2(),
            max_members: crate::fenced_mutation_roster::FENCED_MUTATION_ROSTER_MAX_MEMBERS as u8,
            max_plan_or_checkpoint_bytes:
                crate::fenced_mutation_roster::FENCED_MUTATION_ROSTER_MAX_PLAN_OR_CHECKPOINT_BYTES
                    as u32,
            max_exact_result_bytes:
                crate::fenced_mutation_roster::FENCED_MUTATION_ROSTER_MAX_EXACT_RESULT_BYTES as u32,
            max_live: crate::fenced_mutation_roster::FENCED_MUTATION_ROSTER_MAX_LIVE as u16,
            retained_result_capacity:
                crate::fenced_mutation_roster::FENCED_MUTATION_ROSTER_RETAINED_RESULT_CAPACITY
                    as u32,
            reclaim_batch: crate::fenced_mutation_roster::FENCED_MUTATION_ROSTER_RECLAIM_BATCH
                as u16,
            retention_seconds:
                crate::fenced_mutation_roster::FENCED_MUTATION_ROSTER_RETENTION_SECONDS as u32,
        }
    }

    /// Whether this is byte-for-byte the sole profile accepted on revision 5.
    pub fn is_exact(self) -> bool {
        self == Self::v2() && self.roster.digest == compute_fenced_mutation_roster_profile_digest()
    }
}

impl fmt::Debug for SessionConsumerFencedMutationRosterProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionConsumerFencedMutationRosterProfile")
            .field("transport_revision", &self.transport_revision)
            .field("operation_revision", &self.operation_revision)
            .field("error_revision", &self.error_revision)
            .field("roster_schema", &self.roster.schema)
            .field("profile_exact", &self.is_exact())
            .field("max_members", &self.max_members)
            .finish()
    }
}

/// Explicit revision-5-only protected roster operations.
///
/// This separate family cannot decode on either frozen consumer lane.  It
/// intentionally has no backend, membership, maintenance, snapshot, or raw
/// consensus operation; an authenticated roster service receives only these
/// six forms.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum SessionConsumerV3Operation {
    /// Prove the entire immutable revision-5 roster profile.
    FencedMutationRosterCapability,
    /// Read bounded durable roster history state.
    FencedMutationRosterHistoryState,
    /// Durably admit exactly one complete roster body before any adapter work.
    FencedMutationRosterAdmit {
        /// Exact self-authenticating roster admission.
        admission: Box<FencedMutationRosterAdmission>,
    },
    /// Read the status of exactly one complete roster admission body.
    FencedMutationRosterStatus {
        /// Exact self-authenticating roster admission.
        admission: Box<FencedMutationRosterAdmission>,
    },
    /// Read exact stable roster IDs/descriptors without running an adapter.
    FencedMutationRosterAdoption {
        /// Exact self-authenticating roster admission.
        admission: Box<FencedMutationRosterAdmission>,
    },
    /// Commit the conclusive terminal state of one admitted roster.
    FencedMutationRosterTerminalize {
        /// Exact roster admission previously committed by the authority.
        admission: Box<FencedMutationRosterAdmission>,
        /// Exact terminal disposition for that admission.
        terminal: Box<FencedMutationRosterTerminal>,
    },
}

impl fmt::Debug for SessionConsumerV3Operation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::FencedMutationRosterCapability => "FencedMutationRosterCapability",
            Self::FencedMutationRosterHistoryState => "FencedMutationRosterHistoryState",
            Self::FencedMutationRosterAdmit { .. } => "FencedMutationRosterAdmit",
            Self::FencedMutationRosterStatus { .. } => "FencedMutationRosterStatus",
            Self::FencedMutationRosterAdoption { .. } => "FencedMutationRosterAdoption",
            Self::FencedMutationRosterTerminalize { .. } => "FencedMutationRosterTerminalize",
        };
        formatter.write_str(name)
    }
}

impl SessionConsumerV3Operation {
    fn request_id(&self) -> Option<FencedMutationRosterRequestId> {
        match self {
            Self::FencedMutationRosterAdmit { admission }
            | Self::FencedMutationRosterStatus { admission }
            | Self::FencedMutationRosterAdoption { admission }
            | Self::FencedMutationRosterTerminalize { admission, .. } => {
                Some(admission.request_id())
            }
            Self::FencedMutationRosterCapability | Self::FencedMutationRosterHistoryState => None,
        }
    }

    /// Validate the complete roster identity/body/terminal binding before
    /// dispatch. A valid body conflict remains dispatchable so durable status
    /// can report its exact conflict; malformed structure is fail-closed.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        match self {
            Self::FencedMutationRosterCapability | Self::FencedMutationRosterHistoryState => Ok(()),
            Self::FencedMutationRosterAdmit { admission }
            | Self::FencedMutationRosterStatus { admission }
            | Self::FencedMutationRosterAdoption { admission } => admission
                .validate()
                .map_err(|_| SessionConsumerRejection::MalformedRequest),
            Self::FencedMutationRosterTerminalize {
                admission,
                terminal,
            } => admission
                .validate()
                .and_then(|()| terminal.validate_for_admission(admission))
                .map_err(|_| SessionConsumerRejection::MalformedRequest),
        }
    }
}

/// One scope-bound revision-5 roster request.
///
/// The full 56-byte roster request identity sits outside and inside every
/// effectful/read recovery body. This makes it impossible for a peer to
/// substitute a truncated ID, a different full body, or a terminal body from
/// another roster under a valid envelope.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionConsumerV3Request {
    scope: SessionConsumerScope,
    request_id: Option<FencedMutationRosterRequestId>,
    operation: SessionConsumerV3Operation,
}

impl SessionConsumerV3Request {
    /// Construct an exact revision-5 roster request.
    pub fn new(scope: SessionConsumerScope, operation: SessionConsumerV3Operation) -> Self {
        Self {
            scope,
            request_id: operation.request_id(),
            operation,
        }
    }

    /// Exact consensus scope carried on this request.
    pub const fn scope(&self) -> SessionConsumerScope {
        self.scope
    }

    /// Full roster identity for every body-bound operation.
    pub const fn request_id(&self) -> Option<FencedMutationRosterRequestId> {
        self.request_id
    }

    /// Closed revision-5 roster operation.
    pub const fn operation(&self) -> &SessionConsumerV3Operation {
        &self.operation
    }

    /// Validate the outer full roster identity and entire protected body.
    pub fn validate(&self) -> Result<(), SessionConsumerRejection> {
        self.operation.validate()?;
        if self.request_id != self.operation.request_id() {
            return Err(SessionConsumerRejection::MalformedRequest);
        }
        Ok(())
    }
}

impl fmt::Debug for SessionConsumerV3Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionConsumerV3Request")
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
            StoreError::CasIdempotencyConflict | StoreError::FencedTransitionRequestConflict => {
                Self::RequestConflict
            }
            // The closed generic store-error family has no specialized
            // fenced-transition exhaustion category. Preserve a fail-closed
            // capability response rather than widening that shared enum.
            StoreError::FencedTransitionHistoryFull
            | StoreError::FencedTransitionRetentionExhausted
            | StoreError::FencedTransitionStorageExhausted
            // These V2-only errors are unreachable through revision 3's V1
            // dispatch. Keep the frozen V1 family closed if a faulty backend
            // nevertheless leaks one across that boundary; revision 4 maps
            // them with `SessionConsumerV2FencedTransitionError` instead.
            | StoreError::FencedTransitionHistoryEpochRetired
            | StoreError::FencedTransitionHistoryEpochNotActive => Self::CapabilityNotSupported,
            StoreError::CasIdempotencyOutcomeUnavailable
            | StoreError::FencedTransitionOutcomeUnknown
            | StoreError::FencedTransitionRequestExpired
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
    Mutation {
        /// Stable caller-retained identity used for exact status recovery.
        request_id: SessionConsumerRequestId,
    },
    /// A lease mutation may have committed; the current guard is lost.
    Lease,
}

/// Safe deterministic error retained by a fenced-transition receipt.
///
/// This is intentionally a closed projection rather than `StoreError`: a
/// receipt must never serialize backend-provided diagnostic text to a
/// consumer transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerFencedTransitionError {
    /// A deterministic store result represented by the safe consumer error set.
    Store(SessionConsumerStoreError),
    /// The public identity is permanently bound to another body.
    RequestConflict,
    /// The exact retained outcome elapsed.
    Expired,
    /// The permanent receipt ledger cannot bind a new identity.
    HistoryFull,
    /// Logical time cannot retain a complete result window.
    RetentionExhausted,
    /// The deterministic transition receipt could not be retained.
    StorageExhausted,
}

/// Revision-4-only safe error family for V2 execution.
///
/// It is separate from the frozen V1 receipt error enum: V2 can retire a
/// bounded epoch and can be temporarily inactive while a new epoch is being
/// established. Neither condition exists in V1's absorbing-history wire
/// contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerV2FencedTransitionError {
    /// A deterministic error represented by the common safe store set.
    Store(SessionConsumerStoreError),
    /// The committed topology authority no longer admits this operation.
    TopologyAuthorityRevoked,
    /// The V2 transition lifetime is invalid.
    InvalidSessionTtl,
    /// The V2 record expiry is invalid.
    InvalidRecordExpiry,
    /// Another owner still holds the requested lease.
    LeaseHeld,
    /// The presented lease has elapsed.
    LeaseExpired,
    /// A V2 record payload exceeded its fixed profile bound.
    ///
    /// Both widths remain `u64` on every platform. A retained receipt only
    /// admits the fixed maximum and a checked actual length.
    PayloadTooLarge {
        /// Rejected payload size in bytes.
        actual: u64,
        /// Fixed V2 payload maximum in bytes.
        max: u64,
    },
    /// The referenced V2 history epoch was retired and can never execute.
    Retired,
    /// No V2 history epoch is active at this authority yet.
    EpochNotActive,
    /// The complete V2 identity is permanently bound to another body.
    RequestConflict,
    /// The transition may have crossed its effect boundary, but its exact
    /// outcome cannot be confirmed through this response.
    OutcomeUnknown,
    /// The exact retained outcome elapsed for this V2 identity.
    Expired,
    /// The active V2 history epoch cannot bind another identity.
    HistoryFull,
    /// Logical time cannot retain a complete V2 result window.
    RetentionExhausted,
    /// The deterministic V2 transition receipt could not be retained.
    StorageExhausted,
}

impl From<StoreError> for SessionConsumerV2FencedTransitionError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::TopologyAuthorityRevoked => Self::TopologyAuthorityRevoked,
            StoreError::InvalidSessionTtl => Self::InvalidSessionTtl,
            StoreError::InvalidRecordExpiry => Self::InvalidRecordExpiry,
            StoreError::LeaseHeld => Self::LeaseHeld,
            StoreError::LeaseExpired => Self::LeaseExpired,
            StoreError::PayloadTooLarge { actual, max } => Self::PayloadTooLarge {
                actual: actual as u64,
                max: max as u64,
            },
            StoreError::FencedTransitionHistoryEpochRetired => Self::Retired,
            StoreError::FencedTransitionHistoryEpochNotActive => Self::EpochNotActive,
            StoreError::FencedTransitionRequestConflict => Self::RequestConflict,
            StoreError::FencedTransitionOutcomeUnknown => Self::OutcomeUnknown,
            StoreError::FencedTransitionRequestExpired => Self::Expired,
            StoreError::FencedTransitionHistoryFull => Self::HistoryFull,
            StoreError::FencedTransitionRetentionExhausted => Self::RetentionExhausted,
            StoreError::FencedTransitionStorageExhausted => Self::StorageExhausted,
            error => Self::Store(SessionConsumerStoreError::from(error)),
        }
    }
}

impl SessionConsumerV2FencedTransitionError {
    /// Whether this error has the fixed revision-4 wire representation.
    ///
    /// All closed discriminants are wire-valid. The payload-too-large form is
    /// the sole structured variant, so it must retain the frozen maximum and
    /// the architecture-independent bounded actual width before transport
    /// accepts it.
    pub fn is_wire_valid(self) -> bool {
        !matches!(
            self,
            Self::PayloadTooLarge { actual, max }
                if max != FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES as u64
                    || actual <= max
                    || actual > FENCED_TRANSITION_V2_MAX_PAYLOAD_TOO_LARGE_ACTUAL_BYTES
        )
    }

    /// Project a deterministic V2 receipt error into its closed wire form.
    ///
    /// Only errors that the V2 consensus command can durably retain are
    /// admitted here. In particular, backend diagnostics and generic
    /// validation failures must remain outside a retained status response.
    pub fn from_recorded_store_error(error: StoreError) -> Option<Self> {
        matches!(
            error,
            StoreError::TopologyAuthorityRevoked
                | StoreError::NotFound
                | StoreError::StaleFence
                | StoreError::CasConflict
                | StoreError::InvalidSessionTtl
                | StoreError::InvalidRecordExpiry
                | StoreError::LeaseHeld
                | StoreError::LeaseExpired
                | StoreError::PayloadTooLarge { .. }
                | StoreError::FencedTransitionStorageExhausted
        )
        .then(|| Self::from(error))
        .filter(|error| error.is_recorded_deterministic())
    }

    /// Whether this closed V2 error can occur in a durably retained receipt.
    ///
    /// This rejects transport-only categories such as `Unavailable` even
    /// though they are representable by the shared safe store-error family.
    pub fn is_recorded_deterministic(self) -> bool {
        self.is_wire_valid()
            && (matches!(
                self,
                Self::Store(
                    SessionConsumerStoreError::NotFound
                        | SessionConsumerStoreError::StaleFence
                        | SessionConsumerStoreError::CasConflict
                ) | Self::TopologyAuthorityRevoked
                    | Self::InvalidSessionTtl
                    | Self::InvalidRecordExpiry
                    | Self::LeaseHeld
                    | Self::LeaseExpired
                    | Self::StorageExhausted
            ) || matches!(self, Self::PayloadTooLarge { .. }))
    }

    /// Convert this exact V2 wire error back into its storage-domain form.
    ///
    /// Unlike the shared consumer store-error family, each V2 fenced
    /// execution semantic has a lossless mapping so callers can retain the
    /// terminal/recovery distinction after crossing the consumer boundary.
    pub fn into_store_error(self) -> StoreError {
        match self {
            Self::Store(error) => error.into_store_error(),
            Self::TopologyAuthorityRevoked => StoreError::TopologyAuthorityRevoked,
            Self::InvalidSessionTtl => StoreError::InvalidSessionTtl,
            Self::InvalidRecordExpiry => StoreError::InvalidRecordExpiry,
            Self::LeaseHeld => StoreError::LeaseHeld,
            Self::LeaseExpired => StoreError::LeaseExpired,
            Self::PayloadTooLarge { actual, max } => {
                let (Ok(actual), Ok(max)) = (usize::try_from(actual), usize::try_from(max)) else {
                    return StoreError::InvalidKey("invalid V2 payload-too-large receipt".into());
                };
                StoreError::PayloadTooLarge { actual, max }
            }
            Self::Retired => StoreError::FencedTransitionHistoryEpochRetired,
            Self::EpochNotActive => StoreError::FencedTransitionHistoryEpochNotActive,
            Self::RequestConflict => StoreError::FencedTransitionRequestConflict,
            Self::OutcomeUnknown => StoreError::FencedTransitionOutcomeUnknown,
            Self::Expired => StoreError::FencedTransitionRequestExpired,
            Self::HistoryFull => StoreError::FencedTransitionHistoryFull,
            Self::RetentionExhausted => StoreError::FencedTransitionRetentionExhausted,
            Self::StorageExhausted => StoreError::FencedTransitionStorageExhausted,
        }
    }
}

impl From<StoreError> for SessionConsumerFencedTransitionError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::FencedTransitionRequestConflict => Self::RequestConflict,
            StoreError::FencedTransitionRequestExpired => Self::Expired,
            StoreError::FencedTransitionHistoryFull => Self::HistoryFull,
            StoreError::FencedTransitionRetentionExhausted => Self::RetentionExhausted,
            StoreError::FencedTransitionStorageExhausted => Self::StorageExhausted,
            error => Self::Store(SessionConsumerStoreError::from(error)),
        }
    }
}

/// Exact consumer-safe status of a fenced transition request/body pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionConsumerFencedTransitionStatus {
    /// A success or deterministic error remains recoverable.
    Recorded(Box<Result<FencedTransitionOutcome, SessionConsumerFencedTransitionError>>),
    /// The identity is bound to another body.
    RequestConflict,
    /// The exact recovery window elapsed.
    Expired,
    /// The receipt ledger is full for a fresh identity.
    HistoryFull,
    /// The retention horizon is exhausted for a fresh identity.
    RetentionExhausted,
    /// No request/body receipt existed at the read barrier.
    NotFound,
}

impl From<FencedTransitionStatus> for SessionConsumerFencedTransitionStatus {
    fn from(status: FencedTransitionStatus) -> Self {
        match status {
            FencedTransitionStatus::Recorded(result) => Self::Recorded(Box::new(
                result.map_err(SessionConsumerFencedTransitionError::from),
            )),
            FencedTransitionStatus::RequestConflict => Self::RequestConflict,
            FencedTransitionStatus::Expired => Self::Expired,
            FencedTransitionStatus::HistoryFull => Self::HistoryFull,
            FencedTransitionStatus::RetentionExhausted => Self::RetentionExhausted,
            FencedTransitionStatus::NotFound => Self::NotFound,
        }
    }
}

/// Closed, wire-safe V2 status of a fenced transition request/body pair.
///
/// Unlike the storage-domain [`FencedTransitionV2Status`], a recorded error
/// here cannot carry backend diagnostics, platform-sized fields, or future
/// unconstrained store variants across the revision-4 consumer transport.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub enum SessionConsumerV2FencedTransitionStatus {
    /// A success or deterministic V2 error remains recoverable.
    Recorded(Box<Result<FencedTransitionOutcome, SessionConsumerV2FencedTransitionError>>),
    /// The complete ID is bound to another body.
    RequestConflict,
    /// The exact recovery window elapsed.
    Expired,
    /// The request epoch is retired permanently.
    Retired,
    /// The active epoch cannot bind another identity.
    HistoryFull,
    /// No receipt exists for this complete V2 identity.
    NotFound,
    /// The named epoch is not active yet.
    EpochNotActive,
    /// Logical time cannot retain a complete result window.
    RetentionExhausted,
}

impl TryFrom<FencedTransitionV2Status> for SessionConsumerV2FencedTransitionStatus {
    type Error = SessionConsumerStoreError;

    fn try_from(status: FencedTransitionV2Status) -> Result<Self, Self::Error> {
        match status {
            FencedTransitionV2Status::Recorded(result) => match *result {
                Ok(outcome) => Ok(Self::Recorded(Box::new(Ok(outcome)))),
                Err(error) => {
                    SessionConsumerV2FencedTransitionError::from_recorded_store_error(error)
                        .map(|error| Self::Recorded(Box::new(Err(error))))
                        // Do not project untrusted backend diagnostics or an
                        // unexpected generic store error into a durable receipt.
                        .ok_or(SessionConsumerStoreError::Unavailable)
                }
            },
            FencedTransitionV2Status::RequestConflict => Ok(Self::RequestConflict),
            FencedTransitionV2Status::Expired => Ok(Self::Expired),
            FencedTransitionV2Status::Retired => Ok(Self::Retired),
            FencedTransitionV2Status::HistoryFull => Ok(Self::HistoryFull),
            FencedTransitionV2Status::NotFound => Ok(Self::NotFound),
            FencedTransitionV2Status::EpochNotActive => Ok(Self::EpochNotActive),
            FencedTransitionV2Status::RetentionExhausted => Ok(Self::RetentionExhausted),
        }
    }
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
    /// Exact unanimous atomic-transition capability result.
    FencedTransitionCapability(Result<AtomicFencedTransitionCapability, SessionConsumerStoreError>),
    /// Exact-key record and fence-floor observation.
    ObserveFencedTransition(Result<FencedTransitionObservation, SessionConsumerStoreError>),
    /// Atomic lease-and-record transition result.
    FencedTransition(Result<FencedTransitionOutcome, SessionConsumerFencedTransitionError>),
    /// Exact retained transition status.
    FencedTransitionStatus(
        Result<SessionConsumerFencedTransitionStatus, SessionConsumerStoreError>,
    ),
    /// A mutation outcome is ambiguous and must never be automatically replayed.
    OutcomeUnknown(SessionConsumerOutcomeUnknown),
    /// A request was rejected before dispatch.
    Rejected(SessionConsumerRejection),
}

/// Typed response carried only by the revision-4 V2 consumer lane.
///
/// This intentionally does not extend [`SessionConsumerResponse`]: adding a
/// V2 response discriminator there would allow a revision-3 decoder to
/// accept a new semantic contract.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "response",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum SessionConsumerV2Response {
    /// Exact V2 capability proof result.
    FencedTransitionV2Capability(Result<FencedTransitionV2Capability, SessionConsumerStoreError>),
    /// Bounded current V2 history state.
    FencedTransitionV2HistoryState(
        Result<FencedTransitionV2HistoryState, SessionConsumerStoreError>,
    ),
    /// Exact V2 execution result.
    FencedTransitionV2(Result<FencedTransitionOutcome, SessionConsumerV2FencedTransitionError>),
    /// Exact V2 retained-status result.
    FencedTransitionV2Status(
        Result<SessionConsumerV2FencedTransitionStatus, SessionConsumerStoreError>,
    ),
    /// The V2 operation was rejected before dispatch.
    Rejected(SessionConsumerRejection),
}

impl fmt::Debug for SessionConsumerV2Response {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::FencedTransitionV2Capability(_) => "FencedTransitionV2Capability",
            Self::FencedTransitionV2HistoryState(_) => "FencedTransitionV2HistoryState",
            Self::FencedTransitionV2(_) => "FencedTransitionV2",
            Self::FencedTransitionV2Status(_) => "FencedTransitionV2Status",
            Self::Rejected(_) => "Rejected",
        };
        formatter.write_str(name)
    }
}

/// Typed response carried only by the revision-5 protected roster lane.
///
/// No discriminator is shared with the frozen revision-3 or revision-4
/// families.  In particular, adoption is a read-only durable lookup: it
/// never conveys an adapter command or an arbitrary backend result.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "response",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum SessionConsumerV3Response {
    /// Exact roster capability and immutable profile proof.
    FencedMutationRosterCapability(
        Result<
            (
                FencedMutationRosterCapability,
                SessionConsumerFencedMutationRosterProfile,
            ),
            SessionConsumerStoreError,
        >,
    ),
    /// Bounded public durable roster-history state.
    FencedMutationRosterHistoryState(
        Result<FencedMutationRosterHistoryState, SessionConsumerStoreError>,
    ),
    /// Exact admission result.
    FencedMutationRosterAdmit(Result<FencedMutationRosterOutcome, FencedMutationRosterErrorStatus>),
    /// Exact retained-status result.
    FencedMutationRosterStatus(Result<FencedMutationRosterStatus, SessionConsumerStoreError>),
    /// Exact read-only adoption/status result.
    FencedMutationRosterAdoption(Result<FencedMutationRosterStatus, SessionConsumerStoreError>),
    /// Exact terminalization result.
    FencedMutationRosterTerminalize(
        Result<FencedMutationRosterOutcome, FencedMutationRosterErrorStatus>,
    ),
    /// The operation was rejected before application dispatch.
    Rejected(SessionConsumerRejection),
}

impl fmt::Debug for SessionConsumerV3Response {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::FencedMutationRosterCapability(_) => "FencedMutationRosterCapability",
            Self::FencedMutationRosterHistoryState(_) => "FencedMutationRosterHistoryState",
            Self::FencedMutationRosterAdmit(_) => "FencedMutationRosterAdmit",
            Self::FencedMutationRosterStatus(_) => "FencedMutationRosterStatus",
            Self::FencedMutationRosterAdoption(_) => "FencedMutationRosterAdoption",
            Self::FencedMutationRosterTerminalize(_) => "FencedMutationRosterTerminalize",
            Self::Rejected(_) => "Rejected",
        };
        formatter.write_str(name)
    }
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
            Self::FencedTransitionCapability(_) => "FencedTransitionCapability",
            Self::ObserveFencedTransition(_) => "ObserveFencedTransition",
            Self::FencedTransition(_) => "FencedTransition",
            Self::FencedTransitionStatus(_) => "FencedTransitionStatus",
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

    /// Execute one authenticated revision-4 V2 request.
    ///
    /// The default does no backend work and keeps an existing V1-only quorum
    /// implementation fail-closed on the new lane. Implementations that
    /// advertise V2 override this method and must perform the same scope and
    /// durable leader checks as [`Self::execute`].
    async fn execute_v2(
        &self,
        _identity: &SessionConsumerIdentity,
        _request: SessionConsumerV2Request,
    ) -> SessionConsumerV2Response {
        SessionConsumerV2Response::Rejected(SessionConsumerRejection::Unavailable)
    }

    /// Return the one exact protected-roster profile this service can prove.
    ///
    /// The default is deliberately absent: an existing consumer service does
    /// not accidentally advertise the revision-5 ALPN simply because it can
    /// compile the new DTOs.
    fn fenced_mutation_roster_profile(&self) -> Option<SessionConsumerFencedMutationRosterProfile> {
        None
    }

    /// Execute one authenticated revision-5 protected roster request.
    ///
    /// Implementations must bind the request scope plus authenticated
    /// consumer identity to their durable receipt domain and must never route
    /// this port to a raw backend or adapter. The default is fail-closed so a
    /// listener only enables the dedicated ALPN after explicit validated port
    /// construction.
    async fn execute_v3(
        &self,
        _identity: &SessionConsumerIdentity,
        _request: SessionConsumerV3Request,
    ) -> SessionConsumerV3Response {
        SessionConsumerV3Response::Rejected(SessionConsumerRejection::Unavailable)
    }

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

/// Rebuild a transition for the internal receipt ledger without exposing that
/// ledger's global identity domain to consumers.
///
/// The outer scope is still enforced at every proposal/read boundary. Its
/// stable cluster component isolates unrelated deployments while deliberately
/// excluding changing configuration and epoch values: a retry or status read
/// remains recoverable after an authorized authority rollover. The body is
/// excluded so the existing transition receipt binding can reject a reused ID
/// with a different body as `RequestConflict`.
pub(crate) fn derive_consumer_fenced_transition_request(
    identity: &SessionConsumerIdentity,
    scope: SessionConsumerScope,
    request: &FencedTransitionRequest,
) -> Result<FencedTransitionRequest, SessionConsumerRejection> {
    use sha2::{Digest, Sha256};

    request
        .validate()
        .map_err(|_| SessionConsumerRejection::MalformedRequest)?;
    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-consumer/fenced-transition-id/v1\0");
    digest.update(
        u16::try_from(identity.as_str().len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    digest.update(identity.as_str().as_bytes());
    digest.update(scope.consensus_identity().cluster_id().as_bytes());
    digest.update(request.request_id().as_bytes());
    let hash: [u8; 32] = digest.finalize().into();
    let mut internal_id = [0_u8; FENCED_TRANSITION_REQUEST_ID_BYTES];
    internal_id.copy_from_slice(&hash[..FENCED_TRANSITION_REQUEST_ID_BYTES]);
    // The public transition contract reserves the all-zero ID. A truncated
    // digest can equal that value in principle, so keep the derivation total
    // instead of probabilistically rejecting an otherwise valid request.
    if internal_id.iter().all(|byte| *byte == 0) {
        internal_id[FENCED_TRANSITION_REQUEST_ID_BYTES - 1] = 1;
    }
    FencedTransitionRequest::new(
        FencedTransitionRequestId::from_bytes(internal_id),
        request.lease().clone(),
        request.mutation().clone(),
    )
    .map_err(|_| SessionConsumerRejection::MalformedRequest)
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
        derive_consumer_consensus_request_id, derive_consumer_fenced_transition_request,
        derive_fenced_mutation_roster_scope, derive_fenced_mutation_roster_scope_for_consumer,
        SessionConsumerFencedTransitionError, SessionConsumerFencedTransitionStatus,
        SessionConsumerIdentity, SessionConsumerOperation, SessionConsumerRejection,
        SessionConsumerRequest, SessionConsumerRequestId, SessionConsumerScope,
        SessionConsumerStoreError, SessionConsumerV2FencedTransitionError,
        SessionConsumerV2FencedTransitionStatus, SessionConsumerV2Operation,
        SessionConsumerV2Request, SessionConsumerV2Response,
    };
    use crate::{
        AtomicFencedTransitionCapability, FenceToken, FencedTransitionLease,
        FencedTransitionMutation, FencedTransitionRequest, FencedTransitionRequestId,
        FencedTransitionStatus, FencedTransitionV2CallerNonce, FencedTransitionV2Capability,
        FencedTransitionV2HistoryEpoch, FencedTransitionV2Request, FencedTransitionV2Status,
        Generation, OwnerId, SessionConsensusClusterId, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId, SessionConsensusIdentity, SessionKey, SessionKeyType,
        StableId, StoreError,
    };
    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId};
    use std::time::Duration;

    fn scope(configuration: u8, epoch: u64) -> SessionConsumerScope {
        SessionConsumerScope::new(SessionConsensusIdentity::new(
            SessionConsensusClusterId::from_bytes([1; 32]),
            SessionConsensusConfigurationId::from_bytes([configuration; 32]),
            SessionConsensusConfigurationEpoch::new(epoch).expect("non-zero configuration epoch"),
        ))
    }

    #[test]
    fn revision_four_epoch_capability_keeps_the_v2_wire_shape_but_not_the_journal_type() {
        let response = SessionConsumerV2Response::FencedTransitionV2Capability(Ok(
            FencedTransitionV2Capability::V2,
        ));
        let encoded = serde_json::to_string(&response).expect("revision-four capability encodes");
        assert_eq!(
            encoded, r#"{"response":"fenced_transition_v2_capability","body":{"Ok":"V2"}}"#,
            "the established revision-four V2 capability JSON remains frozen"
        );
        assert_eq!(
            serde_json::from_str::<SessionConsumerV2Response>(&encoded)
                .expect("revision-four capability decodes"),
            response
        );

        let epoch_capability: FencedTransitionV2Capability =
            serde_json::from_str("\"V2\"").expect("epoch capability decodes");
        let journal_capability: AtomicFencedTransitionCapability =
            serde_json::from_str("\"V2\"").expect("journal capability decodes");
        assert_eq!(epoch_capability, FencedTransitionV2Capability::V2);
        assert_eq!(journal_capability, AtomicFencedTransitionCapability::V2);
    }

    fn transition(id: u8) -> FencedTransitionRequest {
        let key = SessionKey {
            tenant: TenantId::from_static("consumer-transition-test"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from_static(b"transition-id")).expect("stable ID"),
        };
        FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([id; 16]),
            FencedTransitionLease::acquire(
                key,
                OwnerId::new("consumer-transition-owner").expect("owner"),
                FenceToken::new(0),
                Duration::from_secs(30),
            )
            .expect("lease"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("transition")
    }

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
    fn roster_authority_scope_matches_tls_and_server_derivations_without_identity_exposure() {
        let identity = SessionConsumerIdentity::new("spiffe://test.example/consumer/opaque")
            .expect("valid consumer identity");
        let other_identity = SessionConsumerIdentity::new("spiffe://test.example/consumer/other")
            .expect("valid other consumer identity");
        let current_scope = scope(7, 3);
        let successor_scope = scope(7, 4);

        let client_scope = derive_fenced_mutation_roster_scope(
            identity.spiffe_identity_commitment(),
            current_scope,
        );
        assert_eq!(
            client_scope,
            derive_fenced_mutation_roster_scope_for_consumer(&identity, current_scope),
            "the authenticated local TLS and server mTLS derivations must agree"
        );
        assert_ne!(
            client_scope,
            derive_fenced_mutation_roster_scope_for_consumer(&other_identity, current_scope),
            "distinct authenticated consumers must not share a roster receipt namespace"
        );
        assert_ne!(
            client_scope,
            derive_fenced_mutation_roster_scope_for_consumer(&identity, successor_scope),
            "a different authoritative consensus scope must not share a roster receipt namespace"
        );
        assert_eq!(
            format!("{client_scope:?}"),
            "FencedMutationRosterScope(<redacted>)"
        );
        assert!(!format!("{identity:?}").contains(identity.as_str()));
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

    #[test]
    fn fenced_transition_identity_is_consumer_bound_and_rollover_stable() {
        let first = SessionConsumerIdentity::new("spiffe://test.example/consumer/first")
            .expect("first identity");
        let second = SessionConsumerIdentity::new("spiffe://test.example/consumer/second")
            .expect("second identity");
        let request = transition(0x55);
        let successor_scope = scope(3, 2);
        let first_scope = scope(2, 1);

        let first_internal =
            derive_consumer_fenced_transition_request(&first, first_scope, &request)
                .expect("first internal request");
        assert_eq!(
            first_internal.request_id(),
            derive_consumer_fenced_transition_request(&first, successor_scope, &request)
                .expect("successor internal request")
                .request_id(),
            "an authorized successor scope must recover the same receipt"
        );
        assert_ne!(
            first_internal.request_id(),
            derive_consumer_fenced_transition_request(&second, first_scope, &request)
                .expect("second internal request")
                .request_id(),
            "different authenticated consumers must not share a receipt domain"
        );
        let changed_body = FencedTransitionRequest::new(
            request.request_id(),
            request.lease().clone(),
            FencedTransitionMutation::delete(Generation::new(2)),
        )
        .expect("changed transition body");
        assert_eq!(
            first_internal.request_id(),
            derive_consumer_fenced_transition_request(&first, first_scope, &changed_body)
                .expect("changed-body internal request")
                .request_id(),
            "the receipt ledger, not the derivation, must bind conflicting bodies"
        );
    }

    #[test]
    fn fenced_transition_requires_matching_outer_and_nested_identity() {
        let request = transition(0x44);
        let consumer = SessionConsumerRequest::new(
            scope(2, 1),
            SessionConsumerRequestId::from_bytes([0x45; 16]),
            SessionConsumerOperation::FencedTransition {
                request: Box::new(request),
            },
        );
        assert_eq!(
            consumer.validate(),
            Err(SessionConsumerRejection::MalformedRequest)
        );
    }

    #[test]
    fn v2_transition_requires_the_full_outer_request_commitment() {
        let v1 = transition(0x46);
        let v2 = FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(1).expect("nonzero epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0x47; 16]),
            v1.lease().clone(),
            v1.mutation().clone(),
        )
        .expect("v2 transition");
        let request = SessionConsumerV2Request::new(
            scope(2, 1),
            SessionConsumerV2Operation::FencedTransitionV2 {
                request: Box::new(v2),
            },
        );
        assert!(request.validate().is_ok());

        let mut encoded = serde_json::to_value(request).expect("v2 request encodes");
        let serde_json::Value::Object(fields) = &mut encoded else {
            panic!("v2 request is an object");
        };
        fields.insert("request_id".into(), serde_json::Value::Null);
        let mismatched: SessionConsumerV2Request =
            serde_json::from_value(encoded).expect("well-formed mismatched envelope");
        assert_eq!(
            mismatched.validate(),
            Err(SessionConsumerRejection::MalformedRequest),
            "the outer ID must retain all V2 epoch, nonce, and body-commitment bytes"
        );
    }

    #[test]
    fn v2_transition_retains_a_structurally_valid_body_conflict_for_dispatch() {
        let original = FencedTransitionV2Request::new(
            FencedTransitionV2HistoryEpoch::new(1).expect("nonzero epoch"),
            FencedTransitionV2CallerNonce::from_bytes([0x48; 16]),
            transition(0x49).lease().clone(),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("original V2 transition");
        let altered = FencedTransitionV2Request::new(
            original.request_id().epoch(),
            original.request_id().nonce(),
            original.lease().clone(),
            FencedTransitionMutation::delete(Generation::new(2)),
        )
        .expect("altered V2 transition");
        let original_request = SessionConsumerV2Request::new(
            scope(2, 1),
            SessionConsumerV2Operation::FencedTransitionV2 {
                request: Box::new(original),
            },
        );
        let altered_request = SessionConsumerV2Request::new(
            scope(2, 1),
            SessionConsumerV2Operation::FencedTransitionV2 {
                request: Box::new(altered),
            },
        );

        let mut encoded = serde_json::to_value(altered_request).expect("altered request encodes");
        let original_id =
            serde_json::to_value(original_request.request_id()).expect("original full ID encodes");
        let serde_json::Value::Object(fields) = &mut encoded else {
            panic!("V2 envelope is an object");
        };
        fields.insert("request_id".into(), original_id.clone());
        let operation = fields
            .get_mut("operation")
            .and_then(serde_json::Value::as_object_mut)
            .expect("V2 operation is an object");
        let body = operation
            .get_mut("request")
            .and_then(serde_json::Value::as_object_mut)
            .expect("V2 body is an object");
        body.insert("request_id".into(), original_id);
        let conflicted: SessionConsumerV2Request =
            serde_json::from_value(encoded).expect("structural conflict decodes");

        assert_eq!(conflicted.request_id(), original_request.request_id());
        assert_eq!(
            conflicted.validate(),
            Ok(()),
            "a same-full-ID body conflict must reach V2 execute/status dispatch"
        );
        let SessionConsumerV2Operation::FencedTransitionV2 { request } = conflicted.operation()
        else {
            panic!("V2 execute operation");
        };
        assert_eq!(
            request.validate(),
            Err(StoreError::FencedTransitionRequestConflict)
        );
    }

    #[test]
    fn fenced_transition_status_is_safe_and_preserves_terminal_states() {
        assert_eq!(
            SessionConsumerFencedTransitionStatus::from(FencedTransitionStatus::Expired),
            SessionConsumerFencedTransitionStatus::Expired
        );
        assert_eq!(
            SessionConsumerFencedTransitionStatus::from(FencedTransitionStatus::HistoryFull),
            SessionConsumerFencedTransitionStatus::HistoryFull
        );
        assert_eq!(
            SessionConsumerFencedTransitionError::from(
                StoreError::FencedTransitionStorageExhausted
            ),
            SessionConsumerFencedTransitionError::StorageExhausted,
        );
    }

    #[test]
    fn v2_fenced_transition_errors_preserve_each_execution_semantic_on_the_wire() {
        let cases = [
            (
                StoreError::FencedTransitionRequestConflict,
                SessionConsumerV2FencedTransitionError::RequestConflict,
            ),
            (
                StoreError::FencedTransitionOutcomeUnknown,
                SessionConsumerV2FencedTransitionError::OutcomeUnknown,
            ),
            (
                StoreError::FencedTransitionRequestExpired,
                SessionConsumerV2FencedTransitionError::Expired,
            ),
            (
                StoreError::FencedTransitionHistoryFull,
                SessionConsumerV2FencedTransitionError::HistoryFull,
            ),
            (
                StoreError::FencedTransitionRetentionExhausted,
                SessionConsumerV2FencedTransitionError::RetentionExhausted,
            ),
            (
                StoreError::FencedTransitionStorageExhausted,
                SessionConsumerV2FencedTransitionError::StorageExhausted,
            ),
            (
                StoreError::FencedTransitionHistoryEpochRetired,
                SessionConsumerV2FencedTransitionError::Retired,
            ),
            (
                StoreError::FencedTransitionHistoryEpochNotActive,
                SessionConsumerV2FencedTransitionError::EpochNotActive,
            ),
            (
                StoreError::NotFound,
                SessionConsumerV2FencedTransitionError::Store(
                    super::SessionConsumerStoreError::NotFound,
                ),
            ),
        ];
        let mut encodings = std::collections::BTreeSet::new();

        for (store_error, wire_error) in cases {
            assert_eq!(
                SessionConsumerV2FencedTransitionError::from(store_error.clone()),
                wire_error
            );
            assert_eq!(wire_error.into_store_error(), store_error);
            let encoded = serde_json::to_string(&wire_error).expect("V2 error encodes");
            assert_eq!(
                serde_json::from_str::<SessionConsumerV2FencedTransitionError>(&encoded)
                    .expect("V2 error decodes"),
                wire_error
            );
            assert!(
                encodings.insert(encoded),
                "every V2 execution semantic needs a distinct wire value"
            );
        }
    }

    #[test]
    fn v2_recorded_status_projects_every_admitted_error_without_diagnostics() {
        let payload_actual = crate::FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES + 1;
        let cases = [
            (
                StoreError::TopologyAuthorityRevoked,
                SessionConsumerV2FencedTransitionError::TopologyAuthorityRevoked,
            ),
            (
                StoreError::NotFound,
                SessionConsumerV2FencedTransitionError::Store(SessionConsumerStoreError::NotFound),
            ),
            (
                StoreError::StaleFence,
                SessionConsumerV2FencedTransitionError::Store(
                    SessionConsumerStoreError::StaleFence,
                ),
            ),
            (
                StoreError::CasConflict,
                SessionConsumerV2FencedTransitionError::Store(
                    SessionConsumerStoreError::CasConflict,
                ),
            ),
            (
                StoreError::InvalidSessionTtl,
                SessionConsumerV2FencedTransitionError::InvalidSessionTtl,
            ),
            (
                StoreError::InvalidRecordExpiry,
                SessionConsumerV2FencedTransitionError::InvalidRecordExpiry,
            ),
            (
                StoreError::LeaseHeld,
                SessionConsumerV2FencedTransitionError::LeaseHeld,
            ),
            (
                StoreError::LeaseExpired,
                SessionConsumerV2FencedTransitionError::LeaseExpired,
            ),
            (
                StoreError::PayloadTooLarge {
                    actual: payload_actual,
                    max: crate::FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES,
                },
                SessionConsumerV2FencedTransitionError::PayloadTooLarge {
                    actual: payload_actual as u64,
                    max: crate::FENCED_TRANSITION_V2_MAX_RECORD_PAYLOAD_BYTES as u64,
                },
            ),
            (
                StoreError::FencedTransitionStorageExhausted,
                SessionConsumerV2FencedTransitionError::StorageExhausted,
            ),
        ];

        for (store_error, wire_error) in cases {
            let status = SessionConsumerV2FencedTransitionStatus::try_from(
                FencedTransitionV2Status::Recorded(Box::new(Err(store_error.clone()))),
            )
            .expect("admitted V2 receipt error projects");
            assert_eq!(
                status,
                SessionConsumerV2FencedTransitionStatus::Recorded(Box::new(Err(wire_error)))
            );
            assert_eq!(wire_error.into_store_error(), store_error);
            assert!(wire_error.is_wire_valid());
            assert!(wire_error.is_recorded_deterministic());
            let encoded = serde_json::to_string(&status).expect("closed V2 status encodes");
            assert_eq!(
                serde_json::from_str::<SessionConsumerV2FencedTransitionStatus>(&encoded)
                    .expect("closed V2 status decodes"),
                status
            );
        }

        let diagnostic = "backend diagnostic must never cross the consumer wire";
        assert_eq!(
            SessionConsumerV2FencedTransitionStatus::try_from(FencedTransitionV2Status::Recorded(
                Box::new(Err(StoreError::BackendUnavailable(diagnostic.into(),)))
            ),),
            Err(SessionConsumerStoreError::Unavailable),
            "backend diagnostics are deliberately non-projectable"
        );
        assert_eq!(
            SessionConsumerV2FencedTransitionStatus::try_from(FencedTransitionV2Status::Recorded(
                Box::new(Err(StoreError::InvalidKey(diagnostic.into(),)))
            ),),
            Err(SessionConsumerStoreError::Unavailable),
            "generic non-receipt errors are deliberately non-projectable"
        );
        assert!(
            !SessionConsumerV2FencedTransitionError::PayloadTooLarge { actual: 1, max: 2 }
                .is_wire_valid(),
            "a noncanonical payload bound cannot be represented on the V2 wire"
        );
        assert!(
            !SessionConsumerV2FencedTransitionError::PayloadTooLarge {
                actual: u64::MAX,
                max: 1,
            }
            .is_recorded_deterministic(),
            "a platform-independent overflow cannot be represented as a receipt"
        );
    }

    #[test]
    fn v2_error_additions_do_not_change_frozen_v1_error_shape_or_ordinal() {
        assert_eq!(
            serde_json::to_string(&SessionConsumerFencedTransitionError::RequestConflict)
                .expect("V1 request conflict encodes"),
            "\"RequestConflict\""
        );
        assert_eq!(
            serde_json::to_string(&SessionConsumerFencedTransitionError::Store(
                super::SessionConsumerStoreError::NotFound,
            ))
            .expect("V1 store error encodes"),
            "{\"Store\":\"NotFound\"}"
        );
        assert_eq!(
            opc_consensus::encode_bounded(&SessionConsumerFencedTransitionError::RequestConflict)
                .expect("V1 request conflict postcard encodes"),
            vec![1],
            "the frozen V1 RequestConflict discriminant remains ordinal one"
        );
        assert_eq!(
            opc_consensus::encode_bounded(&SessionConsumerFencedTransitionError::StorageExhausted)
                .expect("V1 storage exhausted postcard encodes"),
            vec![5],
            "the frozen V1 StorageExhausted discriminant remains ordinal five"
        );
    }
}
