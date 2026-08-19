//! Atomic, single-record lease-and-mutation transitions.
//!
//! A fenced transition combines exactly one lease acquire or renewal with
//! exactly one mutation of the lease's record. Consensus-backed stores commit
//! the pair at one log position; weaker backends keep the capability disabled.

use std::{fmt, time::Duration};

use opc_types::Timestamp;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    checked_session_deadline,
    error::StoreError,
    lease::LeaseGuard,
    model::{FenceToken, Generation, OwnerId, SessionKey},
    record::StoredSessionRecord,
    ttl::{
        validate_session_ttl, validate_stored_record_expiry_at,
        validate_stored_record_expiry_profile,
    },
};

/// Fixed width of a caller-retained fenced-transition request identity.
pub const FENCED_TRANSITION_REQUEST_ID_BYTES: usize = 16;

/// Maximum permanent ID/body receipt bindings retained for one storage
/// consensus identity.
///
/// This protocol bound includes both full exact-result receipts and their
/// permanent digest tombstones. Once it is reached, no new fenced-transition
/// request ID can be durably bound for that identity.
pub const FENCED_TRANSITION_MAX_HISTORY_ENTRIES: usize = 4_096;

/// Canonical store-side contract implemented by this primitive.
pub const FENCED_TRANSITION_SCHEMA_V1: u16 = 1;

/// Canonical binary schema of a prepared fenced transition.
pub const FENCED_TRANSITION_PREPARED_SCHEMA_V1: u16 = 1;

/// Reserved protection-boundary slots in the prepared-token V1 wire layout.
///
/// V1 validation admits only the frozen production shapes: zero or one known
/// boundary, or one consensus/consumer physical boundary followed by exactly
/// one local/remote payload-protection boundary. The remaining slots keep the
/// durable layout fixed and never authorize recursive wrapper composition.
pub const FENCED_TRANSITION_MAX_PREPARED_LAYERS: usize = 8;

/// Maximum canonical byte width of one opaque prepared-transition token.
///
/// The physical request must fit the consensus RPC admission ceiling. The
/// same ceiling bounds token import before any nested request allocation.
pub const FENCED_TRANSITION_MAX_PREPARED_BYTES: usize =
    opc_consensus::CONSENSUS_MAX_RPC_PAYLOAD_BYTES;

/// Exact atomic-transition capability advertised by a compatible store.
///
/// This is deliberately versioned rather than inferred from independent CAS,
/// fencing, TTL, or batch flags: composing those operations does not provide
/// the single linearization point required by this contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AtomicFencedTransitionCapability {
    /// One exact-key lease acquire/renew and one same-record mutation.
    V1,
    /// V1 plus caller-side durable recovery of an exact protected request by
    /// its stable transition identity before any ambiguous dispatch.
    V2,
}

/// Exact-result recovery window for a committed fenced transition.
///
/// The durable request/body binding remains for the consensus identity's
/// lifetime, including snapshots. The exact result is available for this
/// fixed window after its committed logical time. Once the window expires,
/// replay remains closed and status returns `Expired` instead of applying the
/// request again.
pub const FENCED_TRANSITION_OUTCOME_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

/// Maximum canonical JSON size accepted for one serialized transition result.
///
/// Results contain only one bounded key-bearing lease credential and scalar
/// mutation metadata; they never echo a record payload.
pub const FENCED_TRANSITION_MAX_OUTCOME_BYTES: usize = 16 * 1024;

const INVALID_TRANSITION_KEY: &str = "fenced_transition_key_mismatch";
const INVALID_TRANSITION_FENCE: &str = "fenced_transition_fence_mismatch";
const INVALID_TRANSITION_OWNER: &str = "fenced_transition_owner_mismatch";
const INVALID_TRANSITION_GENERATION: &str = "fenced_transition_generation_invalid";
const INVALID_TRANSITION_REFRESH_ACQUIRE: &str = "fenced_transition_refresh_acquire_invalid";
const INVALID_TRANSITION_OUTCOME: &str = "fenced_transition_outcome_invalid";
const INVALID_TRANSITION_REQUEST_ID: &str = "fenced_transition_request_id_invalid";
const INVALID_PREPARED_TRANSITION: &str = "prepared_fenced_transition_invalid";
const PREPARED_TRANSITION_MAGIC: [u8; 8] = *b"OPCFPT01";
const PREPARED_TRANSITION_VERSION_BYTES: usize = 2;
const PREPARED_TRANSITION_BODY_LENGTH_BYTES: usize = 4;
const PREPARED_TRANSITION_HEADER_BYTES: usize = PREPARED_TRANSITION_MAGIC.len()
    + PREPARED_TRANSITION_VERSION_BYTES
    + PREPARED_TRANSITION_BODY_LENGTH_BYTES;
const PREPARED_TRANSITION_DIGEST_BYTES: usize = 32;

/// Caller-generated identity retained unchanged across submission and status.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FencedTransitionRequestId([u8; FENCED_TRANSITION_REQUEST_ID_BYTES]);

impl FencedTransitionRequestId {
    /// Generate a new opaque request identity.
    pub fn new() -> Self {
        Self(*uuid::Uuid::new_v4().as_bytes())
    }

    /// Reconstruct an identity retained with its exact canonical request.
    pub const fn from_bytes(bytes: [u8; FENCED_TRANSITION_REQUEST_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Borrow the fixed-width persisted representation.
    pub const fn as_bytes(&self) -> &[u8; FENCED_TRANSITION_REQUEST_ID_BYTES] {
        &self.0
    }

    /// Borrow the fixed-width opaque request identity.
    pub const fn opaque_bytes(&self) -> &[u8; FENCED_TRANSITION_REQUEST_ID_BYTES] {
        self.as_bytes()
    }
}

impl Default for FencedTransitionRequestId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FencedTransitionRequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionRequestId(<redacted>)")
    }
}

/// Lease action committed together with one record mutation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FencedTransitionLease {
    /// Acquire a new credential under the exact previously observed fence.
    ///
    /// The committed fence is `expected_fence + 1`. This deterministic target
    /// lets a protected record bind that fence in its AEAD AAD before the
    /// request crosses the consensus boundary. A different persisted fence is
    /// a no-effect stale-fence rejection.
    Acquire {
        /// Exact record/lease key.
        key: SessionKey,
        /// Owner receiving the new credential.
        owner: OwnerId,
        /// Exact current fence, or zero for a key with no fence history.
        expected_fence: FenceToken,
        /// Bounded lease lifetime from committed admission time.
        ttl: Duration,
    },
    /// Renew one exact, unexpired lease credential without changing its fence.
    Renew {
        /// Existing lease credential.
        lease: LeaseGuard,
        /// Bounded renewed lifetime from committed admission time.
        ttl: Duration,
    },
}

impl FencedTransitionLease {
    /// Build a deterministic acquire action.
    pub fn acquire(
        key: SessionKey,
        owner: OwnerId,
        expected_fence: FenceToken,
        ttl: Duration,
    ) -> Result<Self, StoreError> {
        let action = Self::Acquire {
            key,
            owner,
            expected_fence,
            ttl,
        };
        action.validate()?;
        Ok(action)
    }

    /// Build a renewal action for an exact credential.
    pub fn renew(lease: LeaseGuard, ttl: Duration) -> Result<Self, StoreError> {
        let action = Self::Renew { lease, ttl };
        action.validate()?;
        Ok(action)
    }

    /// Exact key shared by the lease and record mutation.
    pub fn key(&self) -> &SessionKey {
        match self {
            Self::Acquire { key, .. } => key,
            Self::Renew { lease, .. } => lease.key(),
        }
    }

    /// Exact owner authorized by the transition.
    pub fn owner(&self) -> &OwnerId {
        match self {
            Self::Acquire { owner, .. } => owner,
            Self::Renew { lease, .. } => lease.owner(),
        }
    }

    /// Fence that a successful transition commits and returns.
    pub fn committed_fence(&self) -> Result<FenceToken, StoreError> {
        match self {
            Self::Acquire { expected_fence, .. } => expected_fence
                .get()
                .checked_add(1)
                .filter(|fence| *fence != 0)
                .map(FenceToken::new)
                .ok_or_else(|| StoreError::InvalidKey(INVALID_TRANSITION_FENCE.into())),
            Self::Renew { lease, .. } => Ok(lease.fence()),
        }
    }

    /// Requested lease lifetime.
    pub const fn ttl(&self) -> Duration {
        match self {
            Self::Acquire { ttl, .. } | Self::Renew { ttl, .. } => *ttl,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), StoreError> {
        validate_positive_ttl(self.ttl())?;
        if let Self::Renew { lease, .. } = self {
            lease.validate_profile()?;
        }
        let _ = self.committed_fence()?;
        Ok(())
    }

    pub(crate) fn validate_at(&self, logical_time: Timestamp) -> Result<(), StoreError> {
        self.validate()?;
        if let Self::Renew { lease, .. } = self {
            if lease.expires_at() <= logical_time {
                return Err(StoreError::LeaseExpired);
            }
        }
        let _ = checked_session_deadline(logical_time, self.ttl())?;
        Ok(())
    }
}

impl fmt::Debug for FencedTransitionLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = match self {
            Self::Acquire { .. } => "Acquire",
            Self::Renew { .. } => "Renew",
        };
        formatter
            .debug_struct("FencedTransitionLease")
            .field("action", &action)
            .finish_non_exhaustive()
    }
}

/// One same-record mutation committed with the lease action.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum FencedTransitionMutation {
    /// Create an absent record at generation one.
    Create {
        /// Complete record to install.
        record: Box<StoredSessionRecord>,
    },
    /// Replace an existing record at the exact successor generation.
    Update {
        /// Exact current generation required for admission.
        expected_generation: Generation,
        /// Complete successor record to install.
        record: Box<StoredSessionRecord>,
    },
    /// Delete an existing record only at the exact generation.
    Delete {
        /// Exact current generation required for admission.
        expected_generation: Generation,
    },
    /// Replace an existing record's TTL only at the exact generation.
    RefreshTtl {
        /// Exact current generation required for admission.
        expected_generation: Generation,
        /// New lifetime measured from committed admission time.
        ttl: Duration,
    },
}

impl FencedTransitionMutation {
    /// Build an absent-record creation.
    pub fn create(record: StoredSessionRecord) -> Self {
        Self::Create {
            record: Box::new(record),
        }
    }

    /// Build an exact-generation replacement.
    pub fn update(expected_generation: Generation, record: StoredSessionRecord) -> Self {
        Self::Update {
            expected_generation,
            record: Box::new(record),
        }
    }

    /// Build an exact-generation deletion.
    pub const fn delete(expected_generation: Generation) -> Self {
        Self::Delete {
            expected_generation,
        }
    }

    /// Build an exact-generation TTL refresh.
    pub fn refresh_ttl(expected_generation: Generation, ttl: Duration) -> Result<Self, StoreError> {
        validate_positive_ttl(ttl)?;
        Ok(Self::RefreshTtl {
            expected_generation,
            ttl,
        })
    }

    /// Expected live record generation, or `None` for create-if-absent.
    pub const fn expected_generation(&self) -> Option<Generation> {
        match self {
            Self::Create { .. } => None,
            Self::Update {
                expected_generation,
                ..
            }
            | Self::Delete {
                expected_generation,
            }
            | Self::RefreshTtl {
                expected_generation,
                ..
            } => Some(*expected_generation),
        }
    }

    /// Replacement record for create/update operations.
    pub fn record(&self) -> Option<&StoredSessionRecord> {
        match self {
            Self::Create { record } | Self::Update { record, .. } => Some(record),
            Self::Delete { .. } | Self::RefreshTtl { .. } => None,
        }
    }

    pub(crate) fn validate_for_lease(
        &self,
        lease: &FencedTransitionLease,
    ) -> Result<(), StoreError> {
        if let Self::RefreshTtl { ttl, .. } = self {
            validate_positive_ttl(*ttl)?;
            if matches!(lease, FencedTransitionLease::Acquire { .. }) {
                return Err(StoreError::InvalidKey(
                    INVALID_TRANSITION_REFRESH_ACQUIRE.into(),
                ));
            }
        }
        let Some(record) = self.record() else {
            return Ok(());
        };
        if &record.key != lease.key() {
            return Err(StoreError::InvalidKey(INVALID_TRANSITION_KEY.into()));
        }
        if &record.owner != lease.owner() {
            return Err(StoreError::InvalidKey(INVALID_TRANSITION_OWNER.into()));
        }
        if record.fence != lease.committed_fence()? {
            return Err(StoreError::InvalidKey(INVALID_TRANSITION_FENCE.into()));
        }
        let expected_new_generation = match self {
            Self::Create { .. } => Generation::new(1),
            Self::Update {
                expected_generation,
                ..
            } => expected_generation
                .next()
                .ok_or_else(|| StoreError::InvalidKey(INVALID_TRANSITION_GENERATION.into()))?,
            Self::Delete { .. } | Self::RefreshTtl { .. } => unreachable!(),
        };
        if record.generation != expected_new_generation {
            return Err(StoreError::InvalidKey(INVALID_TRANSITION_GENERATION.into()));
        }
        validate_stored_record_expiry_profile(record)
    }

    pub(crate) fn validate_at(&self, logical_time: Timestamp) -> Result<(), StoreError> {
        match self {
            Self::Create { record } | Self::Update { record, .. } => {
                validate_stored_record_expiry_at(record, logical_time)?;
                if record
                    .expires_at
                    .is_some_and(|expires_at| expires_at <= logical_time)
                {
                    return Err(StoreError::InvalidRecordExpiry);
                }
                Ok(())
            }
            Self::Delete { .. } => Ok(()),
            Self::RefreshTtl { ttl, .. } => {
                validate_positive_ttl(*ttl)?;
                let _ = checked_session_deadline(logical_time, *ttl)?;
                Ok(())
            }
        }
    }
}

impl fmt::Debug for FencedTransitionMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mutation = match self {
            Self::Create { .. } => "Create",
            Self::Update { .. } => "Update",
            Self::Delete { .. } => "Delete",
            Self::RefreshTtl { .. } => "RefreshTtl",
        };
        formatter
            .debug_struct("FencedTransitionMutation")
            .field("mutation", &mutation)
            .finish_non_exhaustive()
    }
}

/// Complete canonical body bound to one stable request identity.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FencedTransitionRequest {
    request_id: FencedTransitionRequestId,
    lease: FencedTransitionLease,
    mutation: FencedTransitionMutation,
}

impl FencedTransitionRequest {
    /// Construct and structurally validate one bounded single-record request.
    pub fn new(
        request_id: FencedTransitionRequestId,
        lease: FencedTransitionLease,
        mutation: FencedTransitionMutation,
    ) -> Result<Self, StoreError> {
        let request = Self {
            request_id,
            lease,
            mutation,
        };
        request.validate()?;
        Ok(request)
    }

    /// Stable caller-generated request identity.
    pub const fn request_id(&self) -> FencedTransitionRequestId {
        self.request_id
    }

    /// Lease action committed by this request.
    pub const fn lease(&self) -> &FencedTransitionLease {
        &self.lease
    }

    /// Same-record mutation committed by this request.
    pub const fn mutation(&self) -> &FencedTransitionMutation {
        &self.mutation
    }

    /// Validate time-independent structure before any proposal or provider work.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.request_id.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(StoreError::InvalidKey(INVALID_TRANSITION_REQUEST_ID.into()));
        }
        self.lease.validate()?;
        self.mutation.validate_for_lease(&self.lease)
    }

    /// Validate time-dependent request constraints at committed logical time.
    pub fn validate_at(&self, logical_time: Timestamp) -> Result<(), StoreError> {
        self.validate()?;
        self.lease.validate_at(logical_time)?;
        self.mutation.validate_at(logical_time)
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        FencedTransitionRequestId,
        FencedTransitionLease,
        FencedTransitionMutation,
    ) {
        (self.request_id, self.lease, self.mutation)
    }
}

impl fmt::Debug for FencedTransitionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionRequest(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PreparedFencedTransitionProtection {
    LocalAeadV1 { scope_commitment: [u8; 32] },
    RemoteSealV1 { scope_commitment: [u8; 32] },
    ConsensusPhysicalV1 { storage_commitment: [u8; 32] },
    // Append-only: the discriminants above are part of the prepared-token V1
    // compatibility corpus. This binds an opaque token to one authenticated
    // application-consumer physical boundary without retaining any identity
    // text or endpoint/topology details.
    AuthenticatedConsumerPhysicalV1 { binding_commitment: [u8; 32] },
}

/// Frozen payload of the prepared-transition V1 wire frame.
///
/// The fixed outer header dispatches on the schema before this type is
/// decoded. This layout must remain readable after later schemas are added;
/// its complete lease, mutation, record/expiry, and supported protection-stack
/// shapes are pinned by a golden compatibility corpus.
#[derive(Serialize, Deserialize)]
struct PreparedFencedTransitionWireV1 {
    request: FencedTransitionRequest,
    protection_layer_count: u8,
    protection_layers:
        [Option<PreparedFencedTransitionProtection>; FENCED_TRANSITION_MAX_PREPARED_LAYERS],
}

/// Redaction-safe import failure for an opaque prepared-transition token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PreparedFencedTransitionError {
    /// The token exceeds the fixed model-wide byte ceiling.
    #[error("prepared fenced transition exceeds its bounded encoding")]
    TooLarge,
    /// The token is malformed, noncanonical, corrupt, or structurally invalid.
    #[error("prepared fenced transition encoding is invalid")]
    InvalidEncoding,
    /// The token uses a prepared-transition schema this SDK does not support.
    #[error("prepared fenced transition version is unsupported")]
    UnsupportedVersion,
}

/// Durable lookup result for one caller-stable transition identity.
///
/// `Absent` describes only the SDK prepared-request journal. It is distinct
/// from [`FencedTransitionStatus::NotFound`], which is a non-exclusionary
/// observation of the consensus receipt ledger.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PreparedFencedTransitionLookup {
    /// The exact protected request is durably available for retry or status.
    Found(PreparedFencedTransition),
    /// No exact request is bound to this identity in the prepared journal.
    Absent,
}

impl fmt::Debug for PreparedFencedTransitionLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::Found(_) => "found",
            Self::Absent => "absent",
        };
        formatter
            .debug_struct("PreparedFencedTransitionLookup")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

/// Effect-boundary-preserving failure from a prepared fenced transition.
///
/// This type prevents a local pre-dispatch journal failure from being
/// confused with a request that may already have crossed the transport or
/// consensus proposal boundary.
#[derive(Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FencedTransitionExecuteError {
    /// This invocation did not dispatch any request because its exact durable
    /// prepared binding was unavailable.
    #[error("fenced transition was not transmitted")]
    NotTransmitted,
    /// The exact request may have reached its effect boundary.
    #[error("fenced transition outcome is unknown; recover only the retained request")]
    OutcomeUnknown {
        /// Stable identity whose exact prepared request remains recoverable.
        request_id: FencedTransitionRequestId,
    },
    /// A confirmed validation, authority, conflict, or store rejection.
    #[error(transparent)]
    Rejected(StoreError),
}

impl fmt::Debug for FencedTransitionExecuteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::NotTransmitted => "not_transmitted",
            Self::OutcomeUnknown { .. } => "outcome_unknown",
            Self::Rejected(_) => "rejected",
        };
        formatter
            .debug_struct("FencedTransitionExecuteError")
            .field("kind", &kind)
            .finish_non_exhaustive()
    }
}

impl FencedTransitionExecuteError {
    /// Return the only transition identity allowed for exact recovery after
    /// this invocation.
    pub const fn exact_retry_id(&self) -> Option<FencedTransitionRequestId> {
        match self {
            Self::OutcomeUnknown { request_id } => Some(*request_id),
            Self::NotTransmitted | Self::Rejected(_) => None,
        }
    }
}

/// Persistable exact body produced before an atomic transition is dispatched.
///
/// Create and update preparation through an SDK protection wrapper seals the
/// payload exactly once, then retains the complete physical request in this
/// token. A raw V1 physical backend exposes the serializable token but does
/// not promise restart recovery. Protected production composition requires a
/// V2 outer wrapper backed by [`crate::PreparedFencedTransitionJournal`]; that
/// SDK journal commits the exact token before dispatch and recovers it by the
/// caller-stable request ID after ambiguity or process restart without
/// resealing under a rotated key/provider.
///
/// The fields and `Debug` representation are intentionally opaque. A token
/// prepared through a protection wrapper contains no payload plaintext, but
/// every serialized token still contains the complete physical request and
/// belongs only in trusted, integrity-protected storage. Tokens must never be
/// logged, placed in metrics, or included in diagnostics. The frame digest
/// detects accidental modification but is not a substitute for the V2
/// journal's authenticated durable binding.
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedFencedTransition {
    canonical: Zeroizing<Vec<u8>>,
    request_id: FencedTransitionRequestId,
}

impl PreparedFencedTransition {
    /// Prepare an exact request at a capable unprotected backend boundary.
    ///
    /// This low-level adapter hook exists for [`crate::SessionBackend`]
    /// implementations. Application code should prepare through the complete
    /// journaled protected backend so every layer is retained durably before
    /// dispatch.
    #[doc(hidden)]
    pub fn from_unprotected_request(request: FencedTransitionRequest) -> Result<Self, StoreError> {
        request.validate()?;
        Self::from_body(PreparedFencedTransitionWireV1 {
            request,
            protection_layer_count: 0,
            protection_layers: [None; FENCED_TRANSITION_MAX_PREPARED_LAYERS],
        })
        .map_err(|_| invalid_prepared_transition())
    }

    pub(crate) fn with_protection(
        self,
        protection: PreparedFencedTransitionProtection,
    ) -> Result<Self, StoreError> {
        let mut body = self
            .decode_body()
            .map_err(|_| invalid_prepared_transition())?;
        let count = usize::from(body.protection_layer_count);
        if count >= FENCED_TRANSITION_MAX_PREPARED_LAYERS {
            return Err(invalid_prepared_transition());
        }
        body.protection_layers[count] = Some(protection);
        body.protection_layer_count = body
            .protection_layer_count
            .checked_add(1)
            .ok_or_else(invalid_prepared_transition)?;
        Self::from_body(body).map_err(|_| invalid_prepared_transition())
    }

    pub(crate) fn without_outer_protection(
        &self,
        expected: PreparedFencedTransitionProtection,
    ) -> Result<Self, StoreError> {
        let mut body = self
            .decode_body()
            .map_err(|_| invalid_prepared_transition())?;
        let count = usize::from(body.protection_layer_count);
        let Some(index) = count.checked_sub(1) else {
            return Err(invalid_prepared_transition());
        };
        if body.protection_layers[index] != Some(expected) {
            return Err(invalid_prepared_transition());
        }
        body.protection_layers[index] = None;
        body.protection_layer_count = body
            .protection_layer_count
            .checked_sub(1)
            .ok_or_else(invalid_prepared_transition)?;
        Self::from_body(body).map_err(|_| invalid_prepared_transition())
    }

    /// Attach the opaque authenticated-consumer physical-boundary marker.
    ///
    /// This SDK adapter hook intentionally accepts only a fixed-width
    /// commitment. It never exposes the protected request body or any local
    /// SPIFFE identity material to callers.
    #[doc(hidden)]
    pub fn with_authenticated_consumer_binding(
        self,
        binding_commitment: [u8; 32],
    ) -> Result<Self, StoreError> {
        self.with_protection(
            PreparedFencedTransitionProtection::AuthenticatedConsumerPhysicalV1 {
                binding_commitment,
            },
        )
    }

    /// Recover the exact request for a matching authenticated-consumer
    /// physical boundary.
    ///
    /// This SDK adapter hook fails closed before returning a request whenever
    /// the token was made by a different consumer boundary. A V2 outer wrapper
    /// must reload and pass the journaled token unchanged.
    #[doc(hidden)]
    pub fn request_for_authenticated_consumer(
        &self,
        binding_commitment: [u8; 32],
    ) -> Result<FencedTransitionRequest, StoreError> {
        self.without_outer_protection(
            PreparedFencedTransitionProtection::AuthenticatedConsumerPhysicalV1 {
                binding_commitment,
            },
        )?
        .request_for_unprotected_backend()
    }

    /// Restore one canonical opaque token from trusted durable bytes.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, PreparedFencedTransitionError> {
        if bytes.len() > FENCED_TRANSITION_MAX_PREPARED_BYTES {
            return Err(PreparedFencedTransitionError::TooLarge);
        }
        let body = decode_prepared_body(bytes)?;
        let request_id = body.request.request_id();
        Ok(Self {
            canonical: Zeroizing::new(bytes.to_vec()),
            request_id,
        })
    }

    /// Borrow the bounded canonical bytes for durable persistence.
    pub fn as_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Stable caller-generated identity of the retained physical request.
    pub const fn request_id(&self) -> FencedTransitionRequestId {
        self.request_id
    }

    /// Recover the exact request at an unprotected backend boundary.
    ///
    /// This low-level adapter method rejects tokens that still carry an
    /// SDK-owned protection layer. Application code should pass the opaque
    /// token back to the same composed [`crate::SessionBackend`] instead of
    /// inspecting or reconstructing its physical request.
    #[doc(hidden)]
    pub fn request_for_unprotected_backend(&self) -> Result<FencedTransitionRequest, StoreError> {
        let body = self
            .decode_body()
            .map_err(|_| invalid_prepared_transition())?;
        if body.protection_layer_count != 0 {
            return Err(invalid_prepared_transition());
        }
        Ok(body.request)
    }

    /// Revalidate canonical bytes restored from durable storage.
    pub fn validate(&self) -> Result<(), PreparedFencedTransitionError> {
        let body = self.decode_body()?;
        if body.request.request_id() != self.request_id {
            return Err(PreparedFencedTransitionError::InvalidEncoding);
        }
        Ok(())
    }

    fn from_body(
        body: PreparedFencedTransitionWireV1,
    ) -> Result<Self, PreparedFencedTransitionError> {
        validate_prepared_body(&body)?;
        let canonical = encode_prepared_body(&body)?;
        let request_id = body.request.request_id();
        Ok(Self {
            canonical,
            request_id,
        })
    }

    fn decode_body(&self) -> Result<PreparedFencedTransitionWireV1, PreparedFencedTransitionError> {
        decode_prepared_body(&self.canonical)
    }
}

impl Serialize for PreparedFencedTransition {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.canonical)
    }
}

impl<'de> Deserialize<'de> for PreparedFencedTransition {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct PreparedVisitor;

        impl<'de> serde::de::Visitor<'de> for PreparedVisitor {
            type Value = PreparedFencedTransition;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded opaque prepared fenced transition")
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                PreparedFencedTransition::try_from_bytes(value)
                    .map_err(|_| E::custom(INVALID_PREPARED_TRANSITION))
            }

            fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let value = Zeroizing::new(value);
                self.visit_bytes(&value)
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes =
                    Zeroizing::new(Vec::with_capacity(FENCED_TRANSITION_MAX_PREPARED_BYTES));
                while let Some(byte) = sequence.next_element::<u8>()? {
                    if bytes.len() == FENCED_TRANSITION_MAX_PREPARED_BYTES {
                        return Err(serde::de::Error::custom(INVALID_PREPARED_TRANSITION));
                    }
                    bytes.push(byte);
                }
                self.visit_bytes(&bytes)
            }
        }

        deserializer
            .deserialize_bytes(PreparedVisitor)
            .map_err(|_| serde::de::Error::custom(INVALID_PREPARED_TRANSITION))
    }
}

impl fmt::Debug for PreparedFencedTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedFencedTransition(<redacted>)")
    }
}

fn validate_prepared_body(
    body: &PreparedFencedTransitionWireV1,
) -> Result<(), PreparedFencedTransitionError> {
    let count = usize::from(body.protection_layer_count);
    if count > FENCED_TRANSITION_MAX_PREPARED_LAYERS
        || body.protection_layers[..count].iter().any(Option::is_none)
        || body.protection_layers[count..].iter().any(Option::is_some)
        || !valid_v1_protection_stack(&body.protection_layers[..count])
    {
        return Err(PreparedFencedTransitionError::InvalidEncoding);
    }
    body.request
        .validate()
        .map_err(|_| PreparedFencedTransitionError::InvalidEncoding)
}

fn valid_v1_protection_stack(layers: &[Option<PreparedFencedTransitionProtection>]) -> bool {
    use PreparedFencedTransitionProtection::{
        AuthenticatedConsumerPhysicalV1, ConsensusPhysicalV1, LocalAeadV1, RemoteSealV1,
    };

    matches!(
        layers,
        [] | [Some(_)]
            | [
                Some(ConsensusPhysicalV1 { .. } | AuthenticatedConsumerPhysicalV1 { .. }),
                Some(LocalAeadV1 { .. } | RemoteSealV1 { .. })
            ]
    )
}

fn decode_prepared_body(
    canonical: &[u8],
) -> Result<PreparedFencedTransitionWireV1, PreparedFencedTransitionError> {
    if canonical.len() > FENCED_TRANSITION_MAX_PREPARED_BYTES {
        return Err(PreparedFencedTransitionError::TooLarge);
    }
    let minimum_size = PREPARED_TRANSITION_HEADER_BYTES
        .checked_add(PREPARED_TRANSITION_DIGEST_BYTES)
        .ok_or(PreparedFencedTransitionError::TooLarge)?;
    if canonical.len() < minimum_size
        || canonical[..PREPARED_TRANSITION_MAGIC.len()] != PREPARED_TRANSITION_MAGIC
    {
        return Err(PreparedFencedTransitionError::InvalidEncoding);
    }

    let version_offset = PREPARED_TRANSITION_MAGIC.len();
    let version = u16::from_be_bytes([canonical[version_offset], canonical[version_offset + 1]]);
    if version != FENCED_TRANSITION_PREPARED_SCHEMA_V1 {
        return Err(PreparedFencedTransitionError::UnsupportedVersion);
    }

    let length_offset = version_offset + PREPARED_TRANSITION_VERSION_BYTES;
    let body_len = u32::from_be_bytes([
        canonical[length_offset],
        canonical[length_offset + 1],
        canonical[length_offset + 2],
        canonical[length_offset + 3],
    ]) as usize;
    let body_end = PREPARED_TRANSITION_HEADER_BYTES
        .checked_add(body_len)
        .ok_or(PreparedFencedTransitionError::TooLarge)?;
    let total_size = body_end
        .checked_add(PREPARED_TRANSITION_DIGEST_BYTES)
        .ok_or(PreparedFencedTransitionError::TooLarge)?;
    if total_size != canonical.len() {
        return Err(PreparedFencedTransitionError::InvalidEncoding);
    }

    let digest_bytes = &canonical[body_end..];
    if prepared_transition_digest(&canonical[..body_end]).as_slice() != digest_bytes {
        return Err(PreparedFencedTransitionError::InvalidEncoding);
    }
    let body_bytes = &canonical[PREPARED_TRANSITION_HEADER_BYTES..body_end];
    let (body, remainder) = postcard::take_from_bytes::<PreparedFencedTransitionWireV1>(body_bytes)
        .map_err(|_| PreparedFencedTransitionError::InvalidEncoding)?;
    if !remainder.is_empty() {
        return Err(PreparedFencedTransitionError::InvalidEncoding);
    }
    validate_prepared_body(&body)?;
    let reencoded = encode_prepared_body(&body)?;
    if reencoded.as_slice() != canonical {
        return Err(PreparedFencedTransitionError::InvalidEncoding);
    }
    Ok(body)
}

fn encode_prepared_body(
    body: &PreparedFencedTransitionWireV1,
) -> Result<Zeroizing<Vec<u8>>, PreparedFencedTransitionError> {
    let body_size = postcard::experimental::serialized_size(body)
        .map_err(|_| PreparedFencedTransitionError::InvalidEncoding)?;
    let body_size_u32 =
        u32::try_from(body_size).map_err(|_| PreparedFencedTransitionError::TooLarge)?;
    let body_end = PREPARED_TRANSITION_HEADER_BYTES
        .checked_add(body_size)
        .ok_or(PreparedFencedTransitionError::TooLarge)?;
    let total_size = body_end
        .checked_add(PREPARED_TRANSITION_DIGEST_BYTES)
        .ok_or(PreparedFencedTransitionError::TooLarge)?;
    if total_size > FENCED_TRANSITION_MAX_PREPARED_BYTES {
        return Err(PreparedFencedTransitionError::TooLarge);
    }

    let mut canonical = Zeroizing::new(vec![0_u8; total_size]);
    canonical[..PREPARED_TRANSITION_MAGIC.len()].copy_from_slice(&PREPARED_TRANSITION_MAGIC);
    let version_offset = PREPARED_TRANSITION_MAGIC.len();
    canonical[version_offset..version_offset + PREPARED_TRANSITION_VERSION_BYTES]
        .copy_from_slice(&FENCED_TRANSITION_PREPARED_SCHEMA_V1.to_be_bytes());
    let length_offset = version_offset + PREPARED_TRANSITION_VERSION_BYTES;
    canonical[length_offset..length_offset + PREPARED_TRANSITION_BODY_LENGTH_BYTES]
        .copy_from_slice(&body_size_u32.to_be_bytes());
    let encoded = postcard::to_slice(
        body,
        &mut canonical[PREPARED_TRANSITION_HEADER_BYTES..body_end],
    )
    .map_err(|_| PreparedFencedTransitionError::InvalidEncoding)?;
    if encoded.len() != body_size {
        return Err(PreparedFencedTransitionError::InvalidEncoding);
    }
    let digest = prepared_transition_digest(&canonical[..body_end]);
    canonical[body_end..].copy_from_slice(&digest);
    Ok(canonical)
}

fn prepared_transition_digest(body: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut digest = Sha256::new();
    digest.update(b"openpacketcore/session-store/prepared-fenced-transition/v1\0");
    digest.update(body);
    digest.finalize().into()
}

fn invalid_prepared_transition() -> StoreError {
    StoreError::Serialization(INVALID_PREPARED_TRANSITION.into())
}

/// Typed record effect of one committed transition.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FencedTransitionMutationResult {
    /// An absent record was created.
    Created,
    /// An existing record was replaced.
    Updated,
    /// The exact existing record was deleted.
    Deleted,
    /// The exact existing record's TTL was replaced.
    TtlRefreshed {
        /// Committed absolute deadline.
        expires_at: Timestamp,
    },
}

impl fmt::Debug for FencedTransitionMutationResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionMutationResult(<redacted>)")
    }
}

/// Exact result recorded at the transition's single consensus position.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FencedTransitionOutcome {
    lease: LeaseGuard,
    committed_generation: Generation,
    mutation: FencedTransitionMutationResult,
    recorded_at: Timestamp,
    retained_until: Timestamp,
}

impl FencedTransitionOutcome {
    pub(crate) fn new(
        lease: LeaseGuard,
        committed_generation: Generation,
        mutation: FencedTransitionMutationResult,
        recorded_at: Timestamp,
    ) -> Result<Self, StoreError> {
        let retained_until =
            checked_session_deadline(recorded_at, FENCED_TRANSITION_OUTCOME_RETENTION)?;
        let outcome = Self {
            lease,
            committed_generation,
            mutation,
            recorded_at,
            retained_until,
        };
        outcome.validate()?;
        Ok(outcome)
    }

    /// Lease credential acquired or renewed by the same committed entry.
    pub const fn lease(&self) -> &LeaseGuard {
        &self.lease
    }

    /// Generation created, updated, deleted, or TTL-refreshed by the entry.
    pub const fn committed_generation(&self) -> Generation {
        self.committed_generation
    }

    /// Typed same-record effect.
    pub const fn mutation(&self) -> FencedTransitionMutationResult {
        self.mutation
    }

    /// Committed logical timestamp used for lease and record expiry admission.
    pub const fn recorded_at(&self) -> Timestamp {
        self.recorded_at
    }

    /// End of the exact-result recovery window.
    pub const fn retained_until(&self) -> Timestamp {
        self.retained_until
    }

    /// Whether exact replay/status has expired at a committed logical time.
    pub fn is_expired_at(&self, logical_time: Timestamp) -> bool {
        self.retained_until <= logical_time
    }

    /// Validate a deserialized outcome against its complete transition body.
    ///
    /// The outcome's own committed timestamp is authoritative; callers do not
    /// supply a wall-clock value that could accidentally validate a receipt at
    /// a different logical time.
    pub fn matches_request(&self, request: &FencedTransitionRequest) -> bool {
        self.matches_request_at(request, self.recorded_at)
    }

    /// Validate that one serialized success is the exact result shape implied
    /// by its bound request at the committed admission time.
    pub(crate) fn matches_request_at(
        &self,
        request: &FencedTransitionRequest,
        logical_time: Timestamp,
    ) -> bool {
        if request.validate_at(logical_time).is_err()
            || self.validate().is_err()
            || self.recorded_at != logical_time
            || self.lease.key() != request.lease().key()
            || self.lease.owner() != request.lease().owner()
            || !request
                .lease()
                .committed_fence()
                .is_ok_and(|fence| self.lease.fence() == fence)
            || !checked_session_deadline(logical_time, request.lease().ttl())
                .is_ok_and(|expires_at| self.lease.expires_at() == expires_at)
        {
            return false;
        }
        match request.lease() {
            FencedTransitionLease::Acquire { .. } => {
                if self.lease.acquired_at() != logical_time || self.lease.credential_id() == 0 {
                    return false;
                }
            }
            FencedTransitionLease::Renew { lease, .. } => {
                if self.lease.acquired_at() != lease.acquired_at()
                    || self.lease.credential_id() != lease.credential_id()
                {
                    return false;
                }
            }
        }
        match (request.mutation(), self.mutation) {
            (
                FencedTransitionMutation::Create { record },
                FencedTransitionMutationResult::Created,
            ) => self.committed_generation == record.generation,
            (
                FencedTransitionMutation::Update { record, .. },
                FencedTransitionMutationResult::Updated,
            ) => self.committed_generation == record.generation,
            (
                FencedTransitionMutation::Delete {
                    expected_generation,
                },
                FencedTransitionMutationResult::Deleted,
            ) => self.committed_generation == *expected_generation,
            (
                FencedTransitionMutation::RefreshTtl {
                    expected_generation,
                    ttl,
                },
                FencedTransitionMutationResult::TtlRefreshed { expires_at },
            ) => {
                self.committed_generation == *expected_generation
                    && checked_session_deadline(logical_time, *ttl)
                        .is_ok_and(|expected| expires_at == expected)
            }
            _ => false,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), StoreError> {
        let maximum_lease_expiry =
            checked_session_deadline(self.recorded_at, crate::MAX_SESSION_TTL).ok();
        if self.lease.fence().get() == 0
            || self.lease.credential_id() == 0
            || self.lease.acquired_at() > self.recorded_at
            || self.lease.expires_at() <= self.recorded_at
            || maximum_lease_expiry.is_some_and(|maximum| self.lease.expires_at() > maximum)
            || self.retained_until <= self.recorded_at
        {
            return Err(StoreError::Serialization(INVALID_TRANSITION_OUTCOME.into()));
        }
        if let FencedTransitionMutationResult::TtlRefreshed { expires_at } = self.mutation {
            if expires_at <= self.recorded_at
                || maximum_lease_expiry.is_some_and(|maximum| expires_at > maximum)
            {
                return Err(StoreError::Serialization(INVALID_TRANSITION_OUTCOME.into()));
            }
        }
        let maximum_retained_until =
            checked_session_deadline(self.recorded_at, FENCED_TRANSITION_OUTCOME_RETENTION)
                .map_err(|_| StoreError::Serialization(INVALID_TRANSITION_OUTCOME.into()))?;
        if self.retained_until != maximum_retained_until {
            return Err(StoreError::Serialization(INVALID_TRANSITION_OUTCOME.into()));
        }
        let encoded = serde_json::to_vec(self)
            .map_err(|_| StoreError::Serialization(INVALID_TRANSITION_OUTCOME.into()))?;
        if encoded.len() > FENCED_TRANSITION_MAX_OUTCOME_BYTES {
            return Err(StoreError::Serialization(INVALID_TRANSITION_OUTCOME.into()));
        }
        Ok(())
    }
}

impl fmt::Debug for FencedTransitionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionOutcome(<redacted>)")
    }
}

/// One fresh, exact-key observation used to prepare a deterministic acquire.
///
/// The record and durable per-key fence floor are read in the same backend
/// transaction after a consensus read barrier. A deleted key therefore still
/// exposes its fence floor without granting fence-allocation authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FencedTransitionObservation {
    record: Option<StoredSessionRecord>,
    current_fence: FenceToken,
}

impl FencedTransitionObservation {
    pub(crate) fn new(
        record: Option<StoredSessionRecord>,
        current_fence: FenceToken,
    ) -> Result<Self, StoreError> {
        if record
            .as_ref()
            .is_some_and(|record| record.fence > current_fence)
        {
            return Err(StoreError::Serialization(
                "fenced_transition_observation_invalid".into(),
            ));
        }
        Ok(Self {
            record,
            current_fence,
        })
    }

    /// Live record at the committed observation time, if present.
    pub const fn record(&self) -> Option<&StoredSessionRecord> {
        self.record.as_ref()
    }

    /// Durable fence floor for the exact key, including deleted history.
    pub const fn current_fence(&self) -> FenceToken {
        self.current_fence
    }
}

impl fmt::Debug for FencedTransitionObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionObservation(<redacted>)")
    }
}

/// Exact, linearized status of one retained transition request/body pair.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FencedTransitionStatus {
    /// The exact success or deterministic no-effect error remains in its
    /// recovery window.
    ///
    /// The result is heap allocated so this public status enum remains small
    /// even though a successful outcome carries a complete lease credential.
    /// `Box` is serialization-transparent, preserving the persisted wire
    /// representation of this variant.
    Recorded(Box<Result<FencedTransitionOutcome, StoreError>>),
    /// The identity is durably bound to a different canonical request body.
    RequestConflict,
    /// The identity/body binding exists but its exact-result window elapsed.
    Expired,
    /// The identity is unbound, but the permanent receipt ledger cannot bind
    /// another ID for this consensus identity.
    ///
    /// An ID rejected this way remains unbound, so both its same-body and
    /// different-body retries return `HistoryFull` rather than
    /// `RequestConflict`.
    HistoryFull,
    /// The identity is unbound, but committed logical time can no longer
    /// represent the protocol's complete exact-result retention window.
    ///
    /// This horizon is absorbing because committed logical time never moves
    /// backward. Same-body and different-body attempts therefore remain
    /// deterministic no-effect rejections under this still-unbound ID.
    RetentionExhausted,
    /// No committed request/body binding existed at the status log position.
    NotFound,
}

impl fmt::Debug for FencedTransitionStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionStatus(<redacted>)")
    }
}

fn validate_positive_ttl(ttl: Duration) -> Result<(), StoreError> {
    if ttl.is_zero() {
        return Err(StoreError::InvalidSessionTtl);
    }
    validate_session_ttl(ttl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EncryptedSessionPayload, SessionKeyType, StableId, StateClass, StateType};
    use bytes::Bytes;
    use opc_crypto::CryptoEnvelopeV1;
    use opc_key::{
        serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyId, SessionAad, AEAD_TAG_LEN,
        AES_256_GCM_SIV_NONCE_LEN,
    };
    use opc_types::{NetworkFunctionKind, TenantId};

    fn key() -> SessionKey {
        SessionKey {
            tenant: TenantId::from_static("fenced-transition-model"),
            nf_kind: NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: StableId::new(Bytes::from_static(b"opaque-id")).expect("stable ID"),
        }
    }

    fn timestamp(seconds: i64) -> Timestamp {
        Timestamp::from_offset_datetime(
            time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(seconds),
        )
    }

    fn lease_guard(key: SessionKey, owner: OwnerId, fence: FenceToken) -> LeaseGuard {
        LeaseGuard::new(key, owner, fence, timestamp(10), timestamp(70), 1)
    }

    fn record(
        key: SessionKey,
        owner: OwnerId,
        fence: FenceToken,
        generation: u64,
    ) -> StoredSessionRecord {
        StoredSessionRecord {
            key,
            generation: Generation::new(generation),
            owner,
            fence,
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("opaque-state").expect("state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"opaque"),
        }
    }

    fn prepared_request(request_id: u8) -> FencedTransitionRequest {
        let owner = OwnerId::new("prepared-owner").expect("owner");
        FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([request_id; 16]),
            FencedTransitionLease::acquire(
                key(),
                owner.clone(),
                FenceToken::new(7),
                Duration::from_secs(30),
            )
            .expect("lease"),
            FencedTransitionMutation::create(record(key(), owner, FenceToken::new(8), 1)),
        )
        .expect("request")
    }

    fn prepared_delete_request(request_id: u8) -> FencedTransitionRequest {
        let owner = OwnerId::new("prepared-wire-owner").expect("owner");
        let key = key();
        FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([request_id; 16]),
            FencedTransitionLease::renew(
                lease_guard(key, owner, FenceToken::new(9)),
                Duration::from_secs(30),
            )
            .expect("renewal"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("record-free request")
    }

    fn prepared_wire_payload(
        encoding: crate::SessionPayloadEncoding,
        key: &SessionKey,
        state_type: &StateType,
        generation: Generation,
        fence: FenceToken,
    ) -> EncryptedSessionPayload {
        match encoding {
            crate::SessionPayloadEncoding::Plaintext => EncryptedSessionPayload::new([0x51]),
            crate::SessionPayloadEncoding::LegacyPlaintext => {
                EncryptedSessionPayload::legacy_plaintext([0x52])
            }
            crate::SessionPayloadEncoding::EnvelopeV1 => {
                let key_id = KeyId::new("prepared-wire-test-key").expect("key ID");
                let aad = EnvelopeAad::session(
                    key.tenant.clone(),
                    1,
                    SessionAad::new(
                        key.nf_kind.as_str(),
                        "prepared-wire-test-keyed-session-digest",
                        state_type.as_str(),
                        generation.get(),
                        fence.get(),
                        "prepared-wire-test-backend",
                    )
                    .expect("session AAD"),
                );
                let envelope = CryptoEnvelopeV1 {
                    algorithm: AeadAlgorithm::Aes256GcmSiv,
                    key_id: key_id.clone(),
                    nonce: vec![0x53; AES_256_GCM_SIV_NONCE_LEN],
                    aad: serialize_bound_aad(&aad, &key_id).expect("bound AAD"),
                    ciphertext_and_tag: vec![0x54; AEAD_TAG_LEN],
                }
                .encode()
                .expect("envelope encoding");
                EncryptedSessionPayload::try_envelope(envelope).expect("valid envelope")
            }
            crate::SessionPayloadEncoding::Unclassified => {
                EncryptedSessionPayload::unclassified([0x55])
            }
        }
    }

    fn prepared_wire_expiry(state_class: StateClass) -> Option<Timestamp> {
        match state_class {
            StateClass::AuthoritativeSession
            | StateClass::DataplaneLookup
            | StateClass::ReplicatedDr
            | StateClass::TelemetryDerived => None,
            StateClass::EphemeralProcedure => Some(timestamp(90)),
        }
    }

    fn prepared_wire_create_request(
        request_id: u8,
        state_class: StateClass,
        encoding: crate::SessionPayloadEncoding,
    ) -> FencedTransitionRequest {
        let owner = OwnerId::new("prepared-wire-owner").expect("owner");
        let key = key();
        let generation = Generation::new(1);
        let fence = FenceToken::new(8);
        let state_type = StateType::new("prepared-wire-state").expect("state type");
        let record = StoredSessionRecord {
            key: key.clone(),
            generation,
            owner: owner.clone(),
            fence,
            state_class,
            state_type: state_type.clone(),
            expires_at: prepared_wire_expiry(state_class),
            payload: prepared_wire_payload(encoding, &key, &state_type, generation, fence),
        };
        FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([request_id; 16]),
            FencedTransitionLease::acquire(key, owner, FenceToken::new(7), Duration::new(30, 123))
                .expect("acquire"),
            FencedTransitionMutation::create(record),
        )
        .expect("create request")
    }

    fn prepared_wire_update_request(
        request_id: u8,
        state_class: StateClass,
        encoding: crate::SessionPayloadEncoding,
    ) -> FencedTransitionRequest {
        let owner = OwnerId::new("prepared-wire-owner").expect("owner");
        let key = key();
        let generation = Generation::new(2);
        let fence = FenceToken::new(9);
        let state_type = StateType::new("prepared-wire-state").expect("state type");
        let record = StoredSessionRecord {
            key: key.clone(),
            generation,
            owner: owner.clone(),
            fence,
            state_class,
            state_type: state_type.clone(),
            expires_at: prepared_wire_expiry(state_class),
            payload: prepared_wire_payload(encoding, &key, &state_type, generation, fence),
        };
        FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([request_id; 16]),
            FencedTransitionLease::renew(
                lease_guard(key, owner, FenceToken::new(9)),
                Duration::new(45, 456),
            )
            .expect("renewal"),
            FencedTransitionMutation::update(Generation::new(1), record),
        )
        .expect("update request")
    }

    fn prepared_wire_refresh_request(request_id: u8) -> FencedTransitionRequest {
        let owner = OwnerId::new("prepared-wire-owner").expect("owner");
        let key = key();
        FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([request_id; 16]),
            FencedTransitionLease::renew(
                lease_guard(key, owner, FenceToken::new(9)),
                Duration::from_secs(30),
            )
            .expect("renewal"),
            FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::new(60, 789))
                .expect("refresh"),
        )
        .expect("record-free refresh request")
    }

    fn prepared_wire_acquire_update_request(request_id: u8) -> FencedTransitionRequest {
        let owner = OwnerId::new("prepared-wire-owner").expect("owner");
        let key = key();
        FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([request_id; 16]),
            FencedTransitionLease::acquire(
                key.clone(),
                owner.clone(),
                FenceToken::new(7),
                Duration::from_secs(30),
            )
            .expect("acquire"),
            FencedTransitionMutation::update(
                Generation::new(1),
                record(key, owner, FenceToken::new(8), 2),
            ),
        )
        .expect("acquire-update request")
    }

    fn prepared_wire_acquire_delete_request(request_id: u8) -> FencedTransitionRequest {
        let owner = OwnerId::new("prepared-wire-owner").expect("owner");
        FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([request_id; 16]),
            FencedTransitionLease::acquire(
                key(),
                owner,
                FenceToken::new(7),
                Duration::from_secs(30),
            )
            .expect("acquire"),
            FencedTransitionMutation::delete(Generation::new(1)),
        )
        .expect("acquire-delete request")
    }

    fn prepared_wire_renew_create_request(request_id: u8) -> FencedTransitionRequest {
        let owner = OwnerId::new("prepared-wire-owner").expect("owner");
        let key = key();
        FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([request_id; 16]),
            FencedTransitionLease::renew(
                lease_guard(key.clone(), owner.clone(), FenceToken::new(9)),
                Duration::from_secs(30),
            )
            .expect("renewal"),
            FencedTransitionMutation::create(record(key, owner, FenceToken::new(9), 1)),
        )
        .expect("renew-create request")
    }

    fn prepared_wire_with_layers(
        request_id: u8,
        layers: &[PreparedFencedTransitionProtection],
    ) -> PreparedFencedTransition {
        let mut prepared =
            PreparedFencedTransition::from_unprotected_request(prepared_delete_request(request_id))
                .expect("prepare record-free V1 token");
        for layer in layers {
            prepared = prepared
                .with_protection(*layer)
                .expect("append compatibility layer");
        }
        prepared
    }

    fn encode_unvalidated_prepared_body(
        body: &PreparedFencedTransitionWireV1,
    ) -> Zeroizing<Vec<u8>> {
        encode_prepared_body(body).expect("encode test body")
    }

    #[test]
    fn protected_fenced_transition_token_round_trip_is_exact_and_redacted() {
        let request = prepared_request(0x31);
        let request_id = request.request_id();
        let prepared = PreparedFencedTransition::from_unprotected_request(request)
            .expect("prepare exact request");
        let durable = Zeroizing::new(prepared.as_bytes().to_vec());

        let restored = PreparedFencedTransition::try_from_bytes(&durable).expect("restore bytes");
        let serialized_capacity = prepared
            .as_bytes()
            .len()
            .checked_mul(4)
            .and_then(|size| size.checked_add(2))
            .expect("bounded JSON capacity");
        let mut serde_bytes = Zeroizing::new(Vec::with_capacity(serialized_capacity));
        serde_json::to_writer(&mut *serde_bytes, &prepared).expect("serialize token");
        let serde_restored: PreparedFencedTransition =
            serde_json::from_slice(&serde_bytes).expect("deserialize token");

        assert_eq!(restored, prepared);
        assert_eq!(serde_restored, prepared);
        assert!(
            restored.as_bytes() == durable.as_slice(),
            "the durable token bytes must round trip exactly"
        );
        assert_eq!(restored.request_id(), request_id);
        assert_eq!(
            format!("{prepared:?}"),
            "PreparedFencedTransition(<redacted>)"
        );
        assert!(!format!("{prepared:?}").contains("prepared-owner"));
        assert!(prepared.validate().is_ok());
    }

    #[test]
    fn protected_fenced_transition_v1_wire_compatibility_corpus_is_frozen() {
        const EXPECTED_V1_FINGERPRINT: [u8; 32] = [
            122, 121, 223, 157, 17, 215, 129, 104, 8, 61, 165, 127, 127, 130, 209, 13, 109, 0, 116,
            25, 52, 126, 221, 158, 1, 104, 238, 233, 26, 223, 214, 247,
        ];

        use sha2::{Digest, Sha256};

        let consensus = PreparedFencedTransitionProtection::ConsensusPhysicalV1 {
            storage_commitment: [0x31; 32],
        };
        let local = PreparedFencedTransitionProtection::LocalAeadV1 {
            scope_commitment: [0x32; 32],
        };
        let remote = PreparedFencedTransitionProtection::RemoteSealV1 {
            scope_commitment: [0x33; 32],
        };
        let consumer = PreparedFencedTransitionProtection::AuthenticatedConsumerPhysicalV1 {
            binding_commitment: [0x34; 32],
        };
        let corpus = [
            (
                "acquire-create-record-no-expiry",
                PreparedFencedTransition::from_unprotected_request(prepared_wire_create_request(
                    0x38,
                    StateClass::AuthoritativeSession,
                    crate::SessionPayloadEncoding::EnvelopeV1,
                ))
                .expect("prepare create V1 token"),
            ),
            (
                "renew-update-record-with-expiry",
                PreparedFencedTransition::from_unprotected_request(prepared_wire_update_request(
                    0x39,
                    StateClass::EphemeralProcedure,
                    crate::SessionPayloadEncoding::Unclassified,
                ))
                .expect("prepare update V1 token"),
            ),
            (
                "acquire-create-legacy-plaintext-dataplane",
                PreparedFencedTransition::from_unprotected_request(prepared_wire_create_request(
                    0x44,
                    StateClass::DataplaneLookup,
                    crate::SessionPayloadEncoding::LegacyPlaintext,
                ))
                .expect("prepare legacy plaintext V1 token"),
            ),
            (
                "renew-update-plaintext-replicated-dr",
                PreparedFencedTransition::from_unprotected_request(prepared_wire_update_request(
                    0x45,
                    StateClass::ReplicatedDr,
                    crate::SessionPayloadEncoding::Plaintext,
                ))
                .expect("prepare plaintext V1 token"),
            ),
            (
                "renew-update-envelope-telemetry-derived",
                PreparedFencedTransition::from_unprotected_request(prepared_wire_update_request(
                    0x46,
                    StateClass::TelemetryDerived,
                    crate::SessionPayloadEncoding::EnvelopeV1,
                ))
                .expect("prepare envelope V1 token"),
            ),
            ("renew-delete", prepared_wire_with_layers(0x3a, &[])),
            (
                "renew-refresh-ttl",
                PreparedFencedTransition::from_unprotected_request(prepared_wire_refresh_request(
                    0x3b,
                ))
                .expect("prepare refresh V1 token"),
            ),
            (
                "acquire-update",
                PreparedFencedTransition::from_unprotected_request(
                    prepared_wire_acquire_update_request(0x47),
                )
                .expect("prepare acquire-update V1 token"),
            ),
            (
                "acquire-delete",
                PreparedFencedTransition::from_unprotected_request(
                    prepared_wire_acquire_delete_request(0x48),
                )
                .expect("prepare acquire-delete V1 token"),
            ),
            (
                "renew-create",
                PreparedFencedTransition::from_unprotected_request(
                    prepared_wire_renew_create_request(0x49),
                )
                .expect("prepare renew-create V1 token"),
            ),
            ("local-only", prepared_wire_with_layers(0x3c, &[local])),
            ("remote-only", prepared_wire_with_layers(0x3d, &[remote])),
            (
                "consensus-only",
                prepared_wire_with_layers(0x3e, &[consensus]),
            ),
            (
                "consensus-then-local",
                prepared_wire_with_layers(0x3f, &[consensus, local]),
            ),
            (
                "consensus-then-remote",
                prepared_wire_with_layers(0x40, &[consensus, remote]),
            ),
            (
                "consumer-only",
                prepared_wire_with_layers(0x41, &[consumer]),
            ),
            (
                "consumer-then-local",
                prepared_wire_with_layers(0x42, &[consumer, local]),
            ),
            (
                "consumer-then-remote",
                prepared_wire_with_layers(0x43, &[consumer, remote]),
            ),
        ];
        let mut digest = Sha256::new();
        digest
            .update(b"openpacketcore/session-store/prepared-fenced-transition/golden-corpus/v1\0");
        for (label, prepared) in corpus {
            let label = label.as_bytes();
            digest.update(
                u32::try_from(label.len())
                    .expect("bounded label")
                    .to_be_bytes(),
            );
            digest.update(label);
            digest.update(
                u32::try_from(prepared.as_bytes().len())
                    .expect("bounded token")
                    .to_be_bytes(),
            );
            digest.update(prepared.as_bytes());
            assert!(
                PreparedFencedTransition::try_from_bytes(prepared.as_bytes()).is_ok(),
                "each frozen V1 corpus member must be canonical and readable"
            );
        }
        let fingerprint: [u8; 32] = digest.finalize().into();
        assert!(
            fingerprint == EXPECTED_V1_FINGERPRINT,
            "the complete prepared-transition V1 wire compatibility corpus changed"
        );
    }

    #[test]
    fn protected_fenced_transition_token_rejects_corruption_and_trailing_bytes() {
        let prepared = PreparedFencedTransition::from_unprotected_request(prepared_request(0x32))
            .expect("prepare exact request");

        let mut corrupt = Zeroizing::new(prepared.as_bytes().to_vec());
        corrupt[0] ^= 0x80;
        assert_eq!(
            PreparedFencedTransition::try_from_bytes(&corrupt),
            Err(PreparedFencedTransitionError::InvalidEncoding)
        );

        let body_len = prepared.as_bytes().len() - PREPARED_TRANSITION_DIGEST_BYTES;
        let mut trailing = Zeroizing::new(Vec::with_capacity(prepared.as_bytes().len() + 1));
        trailing.extend_from_slice(&prepared.as_bytes()[..body_len]);
        trailing.push(0);
        let digest = prepared_transition_digest(&trailing);
        trailing.extend_from_slice(&digest);
        assert_eq!(
            PreparedFencedTransition::try_from_bytes(&trailing),
            Err(PreparedFencedTransitionError::InvalidEncoding)
        );
    }

    #[test]
    fn authenticated_consumer_marker_requires_the_exact_binding() {
        let request = prepared_delete_request(0x41);
        let request_id = request.request_id();
        let prepared = PreparedFencedTransition::from_unprotected_request(request)
            .expect("prepare exact request")
            .with_authenticated_consumer_binding([0x61; 32])
            .expect("append consumer binding");

        assert_eq!(
            prepared
                .request_for_authenticated_consumer([0x61; 32])
                .expect("matching consumer binding")
                .request_id(),
            request_id,
        );
        assert!(prepared
            .request_for_authenticated_consumer([0x62; 32])
            .is_err());
        assert_eq!(
            format!("{prepared:?}"),
            "PreparedFencedTransition(<redacted>)"
        );
    }

    #[test]
    fn protected_fenced_transition_token_rejects_wrong_header_version_and_shape() {
        let base = PreparedFencedTransitionWireV1 {
            request: prepared_request(0x33),
            protection_layer_count: 0,
            protection_layers: [None; FENCED_TRANSITION_MAX_PREPARED_LAYERS],
        };

        let mut wrong_magic = encode_unvalidated_prepared_body(&base);
        wrong_magic[0] ^= 0x80;
        assert_eq!(
            PreparedFencedTransition::try_from_bytes(&wrong_magic),
            Err(PreparedFencedTransitionError::InvalidEncoding)
        );

        let mut unsupported = encode_unvalidated_prepared_body(&base);
        let version_offset = PREPARED_TRANSITION_MAGIC.len();
        unsupported[version_offset..version_offset + PREPARED_TRANSITION_VERSION_BYTES]
            .copy_from_slice(&(FENCED_TRANSITION_PREPARED_SCHEMA_V1 + 1).to_be_bytes());
        assert_eq!(
            PreparedFencedTransition::try_from_bytes(&unsupported),
            Err(PreparedFencedTransitionError::UnsupportedVersion)
        );

        let mut layers = [None; FENCED_TRANSITION_MAX_PREPARED_LAYERS];
        layers[1] = Some(PreparedFencedTransitionProtection::LocalAeadV1 {
            scope_commitment: [0x44; 32],
        });
        let hole = PreparedFencedTransitionWireV1 {
            request: prepared_request(0x35),
            protection_layer_count: 2,
            protection_layers: layers,
        };
        assert_eq!(
            PreparedFencedTransition::try_from_bytes(&encode_unvalidated_prepared_body(&hole)),
            Err(PreparedFencedTransitionError::InvalidEncoding)
        );
    }

    #[test]
    fn protected_fenced_transition_token_enforces_exact_byte_and_layer_bounds() {
        let exact_bound = vec![0_u8; FENCED_TRANSITION_MAX_PREPARED_BYTES];
        assert_eq!(
            PreparedFencedTransition::try_from_bytes(&exact_bound),
            Err(PreparedFencedTransitionError::InvalidEncoding),
            "the exact byte ceiling reaches validation rather than being rejected as oversized"
        );
        let one_over = vec![0_u8; FENCED_TRANSITION_MAX_PREPARED_BYTES + 1];
        assert_eq!(
            PreparedFencedTransition::try_from_bytes(&one_over),
            Err(PreparedFencedTransitionError::TooLarge)
        );

        let physical = PreparedFencedTransitionProtection::ConsensusPhysicalV1 {
            storage_commitment: [0x44; 32],
        };
        let outer = PreparedFencedTransitionProtection::LocalAeadV1 {
            scope_commitment: [0x45; 32],
        };
        let mut prepared =
            PreparedFencedTransition::from_unprotected_request(prepared_request(0x36))
                .expect("prepare exact request");
        prepared = prepared
            .with_protection(physical)
            .expect("one physical layer");
        prepared = prepared
            .with_protection(outer)
            .expect("one outer protection layer");
        assert!(matches!(
            prepared.clone().with_protection(outer),
            Err(StoreError::Serialization(message)) if message == INVALID_PREPARED_TRANSITION
        ));
        prepared = prepared
            .without_outer_protection(outer)
            .expect("peel outer layer")
            .without_outer_protection(physical)
            .expect("peel physical layer");
        assert_eq!(
            prepared
                .request_for_unprotected_backend()
                .expect("all layers peeled")
                .request_id(),
            FencedTransitionRequestId::from_bytes([0x36; 16])
        );
    }

    #[test]
    fn protected_fenced_transition_token_errors_never_describe_contents() {
        let secret = "prepared-owner";
        let prepared = PreparedFencedTransition::from_unprotected_request(prepared_request(0x37))
            .expect("prepare exact request");
        let mut corrupt = Zeroizing::new(prepared.as_bytes().to_vec());
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        let public_error =
            PreparedFencedTransition::try_from_bytes(&corrupt).expect_err("corruption must fail");
        let adapter_error = prepared
            .with_protection(PreparedFencedTransitionProtection::RemoteSealV1 {
                scope_commitment: [0x99; 32],
            })
            .expect("one layer")
            .request_for_unprotected_backend()
            .expect_err("protected token must not expose a raw request");

        for rendered in [public_error.to_string(), adapter_error.to_string()] {
            assert!(!rendered.contains(secret));
            assert!(!rendered.contains("99"));
            assert!(!rendered.contains("37"));
            assert!(rendered.len() < 96);
        }
    }

    #[test]
    fn protected_fenced_transition_serde_errors_never_echo_malformed_input() {
        const CANARY: &str = "opaque-import-redaction-canary";
        let malformed = [
            format!("\"{CANARY}\""),
            format!("[1,\"{CANARY}\"]"),
            format!("{{\"unexpected\":\"{CANARY}\"}}"),
        ];

        for input in malformed {
            let error = serde_json::from_str::<PreparedFencedTransition>(&input)
                .expect_err("malformed token must fail");
            for rendered in [error.to_string(), format!("{error:?}")] {
                assert!(
                    !rendered.contains(CANARY),
                    "prepared-token import errors must not echo input"
                );
                assert!(rendered.len() < 128, "prepared-token errors stay bounded");
            }
        }
    }

    #[test]
    fn acquire_create_requires_exact_successor_fence_and_generation() {
        let owner = OwnerId::new("owner-a").expect("owner");
        let lease = FencedTransitionLease::acquire(
            key(),
            owner.clone(),
            FenceToken::new(7),
            Duration::from_secs(30),
        )
        .expect("lease action");
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([1; 16]),
            lease.clone(),
            FencedTransitionMutation::create(record(key(), owner.clone(), FenceToken::new(8), 1)),
        );
        assert!(request.is_ok());

        let wrong_fence = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([2; 16]),
            lease.clone(),
            FencedTransitionMutation::create(record(key(), owner.clone(), FenceToken::new(9), 1)),
        );
        assert!(matches!(wrong_fence, Err(StoreError::InvalidKey(_))));

        let mut another_key = key();
        another_key.tenant = TenantId::from_static("different-fenced-transition-model");
        let wrong_key = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([3; 16]),
            lease.clone(),
            FencedTransitionMutation::create(record(
                another_key,
                owner.clone(),
                FenceToken::new(8),
                1,
            )),
        );
        assert!(matches!(wrong_key, Err(StoreError::InvalidKey(_))));

        let wrong_owner = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([4; 16]),
            lease.clone(),
            FencedTransitionMutation::create(record(
                key(),
                OwnerId::new("owner-b").expect("owner"),
                FenceToken::new(8),
                1,
            )),
        );
        assert!(matches!(wrong_owner, Err(StoreError::InvalidKey(_))));

        let wrong_generation = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([5; 16]),
            lease,
            FencedTransitionMutation::create(record(key(), owner, FenceToken::new(8), 2)),
        );
        assert!(matches!(wrong_generation, Err(StoreError::InvalidKey(_))));
    }

    #[test]
    fn transition_ttls_must_be_positive() {
        let owner = OwnerId::new("owner-a").expect("owner");
        assert!(matches!(
            FencedTransitionLease::acquire(
                key(),
                owner.clone(),
                FenceToken::new(7),
                Duration::ZERO,
            ),
            Err(StoreError::InvalidSessionTtl)
        ));
        assert!(matches!(
            FencedTransitionLease::renew(
                lease_guard(key(), owner, FenceToken::new(8)),
                Duration::ZERO,
            ),
            Err(StoreError::InvalidSessionTtl)
        ));
        assert!(matches!(
            FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::ZERO),
            Err(StoreError::InvalidSessionTtl)
        ));
    }

    #[test]
    fn transition_ttls_accept_the_exact_maximum_and_reject_one_nanosecond_more() {
        let owner = OwnerId::new("owner-a").expect("owner");
        let maximum = crate::MAX_SESSION_TTL;
        let one_over = maximum + Duration::from_nanos(1);

        assert!(
            FencedTransitionLease::acquire(key(), owner.clone(), FenceToken::new(7), maximum,)
                .is_ok()
        );
        assert!(matches!(
            FencedTransitionLease::acquire(key(), owner.clone(), FenceToken::new(7), one_over),
            Err(StoreError::InvalidSessionTtl)
        ));

        assert!(FencedTransitionLease::renew(
            lease_guard(key(), owner.clone(), FenceToken::new(8)),
            maximum,
        )
        .is_ok());
        assert!(matches!(
            FencedTransitionLease::renew(
                lease_guard(key(), owner.clone(), FenceToken::new(8)),
                one_over,
            ),
            Err(StoreError::InvalidSessionTtl)
        ));

        assert!(FencedTransitionMutation::refresh_ttl(Generation::new(1), maximum).is_ok());
        assert!(matches!(
            FencedTransitionMutation::refresh_ttl(Generation::new(1), one_over),
            Err(StoreError::InvalidSessionTtl)
        ));
    }

    #[test]
    fn renew_rejects_malformed_guard_profile_structurally() {
        let owner = OwnerId::new("owner-a").expect("owner");
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x11; 16]),
            FencedTransitionLease::Renew {
                lease: LeaseGuard::new(
                    key(),
                    owner,
                    FenceToken::new(8),
                    timestamp(20),
                    timestamp(19),
                    1,
                ),
                ttl: Duration::from_secs(30),
            },
            FencedTransitionMutation::delete(Generation::new(1)),
        );

        assert!(matches!(
            request,
            Err(StoreError::InvalidKey(message)) if message == "invalid lease guard"
        ));
    }

    #[test]
    fn renew_requires_a_guard_live_at_admission() {
        let owner = OwnerId::new("owner-a").expect("owner");
        let admission = timestamp(20);
        let request_with_expiry = |request_id, expires_at| {
            FencedTransitionRequest::new(
                FencedTransitionRequestId::from_bytes([request_id; 16]),
                FencedTransitionLease::renew(
                    LeaseGuard::new(
                        key(),
                        owner.clone(),
                        FenceToken::new(8),
                        timestamp(10),
                        expires_at,
                        1,
                    ),
                    Duration::from_secs(30),
                )
                .expect("structurally valid lease"),
                FencedTransitionMutation::delete(Generation::new(1)),
            )
            .expect("structurally valid request")
        };

        for (request_id, expires_at) in [(0x12, admission), (0x13, timestamp(19))] {
            assert_eq!(
                request_with_expiry(request_id, expires_at).validate_at(admission),
                Err(StoreError::LeaseExpired)
            );
        }
        assert!(request_with_expiry(0x14, timestamp(21))
            .validate_at(admission)
            .is_ok());
    }

    #[test]
    fn renew_outcome_matches_only_a_guard_live_at_recorded_time() {
        let owner = OwnerId::new("owner-a").expect("owner");
        let recorded_at = timestamp(20);
        let request_with_expiry = |request_id, expires_at| {
            FencedTransitionRequest::new(
                FencedTransitionRequestId::from_bytes([request_id; 16]),
                FencedTransitionLease::renew(
                    LeaseGuard::new(
                        key(),
                        owner.clone(),
                        FenceToken::new(8),
                        timestamp(10),
                        expires_at,
                        1,
                    ),
                    Duration::from_secs(30),
                )
                .expect("structurally valid lease"),
                FencedTransitionMutation::delete(Generation::new(1)),
            )
            .expect("structurally valid request")
        };
        let outcome = FencedTransitionOutcome::new(
            LeaseGuard::new(
                key(),
                owner.clone(),
                FenceToken::new(8),
                timestamp(10),
                checked_session_deadline(recorded_at, Duration::from_secs(30))
                    .expect("renewed lease expiry"),
                1,
            ),
            Generation::new(1),
            FencedTransitionMutationResult::Deleted,
            recorded_at,
        )
        .expect("valid outcome shape");

        assert!(outcome.matches_request(&request_with_expiry(0x15, timestamp(21))));
        assert!(!outcome.matches_request(&request_with_expiry(0x16, recorded_at)));
    }

    #[test]
    fn request_identity_must_not_be_all_zeroes() {
        let owner = OwnerId::new("owner-a").expect("owner");
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0; 16]),
            FencedTransitionLease::acquire(
                key(),
                owner.clone(),
                FenceToken::new(7),
                Duration::from_secs(30),
            )
            .expect("lease action"),
            FencedTransitionMutation::create(record(key(), owner, FenceToken::new(8), 1)),
        );
        assert!(matches!(
            request,
            Err(StoreError::InvalidKey(message)) if message == INVALID_TRANSITION_REQUEST_ID
        ));
    }

    #[test]
    fn acquire_cannot_refresh_an_old_fenced_record() {
        let owner = OwnerId::new("owner-a").expect("owner");
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([6; 16]),
            FencedTransitionLease::acquire(
                key(),
                owner.clone(),
                FenceToken::new(7),
                Duration::from_secs(30),
            )
            .expect("lease action"),
            FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::from_secs(30))
                .expect("mutation"),
        );
        assert!(matches!(
            request,
            Err(StoreError::InvalidKey(message))
                if message == INVALID_TRANSITION_REFRESH_ACQUIRE
        ));

        let renewed = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([7; 16]),
            FencedTransitionLease::renew(
                lease_guard(key(), owner, FenceToken::new(8)),
                Duration::from_secs(30),
            )
            .expect("lease action"),
            FencedTransitionMutation::refresh_ttl(Generation::new(1), Duration::from_secs(30))
                .expect("mutation"),
        );
        assert!(renewed.is_ok());
    }

    #[test]
    fn outcome_retention_is_exactly_one_day() {
        let recorded_at = timestamp(10);
        let outcome = FencedTransitionOutcome::new(
            lease_guard(
                key(),
                OwnerId::new("owner-a").expect("owner"),
                FenceToken::new(8),
            ),
            Generation::new(1),
            FencedTransitionMutationResult::Created,
            recorded_at,
        )
        .expect("outcome");
        let expected = checked_session_deadline(recorded_at, FENCED_TRANSITION_OUTCOME_RETENTION)
            .expect("retention deadline");
        assert_eq!(outcome.retained_until(), expected);
        assert!(!outcome.is_expired_at(timestamp(10)));
        assert!(outcome.is_expired_at(expected));
        assert_eq!(
            format!("{outcome:?}"),
            "FencedTransitionOutcome(<redacted>)"
        );

        let too_late = Timestamp::from_offset_datetime(
            *expected.as_offset_datetime() + time::Duration::nanoseconds(1),
        );
        let invalid = FencedTransitionOutcome {
            lease: outcome.lease.clone(),
            committed_generation: outcome.committed_generation,
            mutation: outcome.mutation,
            recorded_at,
            retained_until: too_late,
        };
        assert!(matches!(
            invalid.validate(),
            Err(StoreError::Serialization(_))
        ));
    }

    #[test]
    fn public_outcome_validation_uses_the_outcome_recorded_time() {
        let recorded_at = timestamp(10);
        let owner = OwnerId::new("outcome-validation-owner").expect("owner");
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0x44; 16]),
            FencedTransitionLease::acquire(
                key(),
                owner.clone(),
                FenceToken::new(7),
                Duration::from_secs(30),
            )
            .expect("lease"),
            FencedTransitionMutation::create(record(key(), owner.clone(), FenceToken::new(8), 1)),
        )
        .expect("request");
        let outcome = FencedTransitionOutcome::new(
            LeaseGuard::new(
                key(),
                owner,
                FenceToken::new(8),
                recorded_at,
                checked_session_deadline(recorded_at, Duration::from_secs(30)).expect("expiry"),
                1,
            ),
            Generation::new(1),
            FencedTransitionMutationResult::Created,
            recorded_at,
        )
        .expect("outcome");
        assert!(outcome.matches_request(&request));
    }

    #[test]
    fn outcome_time_envelopes_accept_exact_maximum_and_reject_one_over() {
        let recorded_at = timestamp(10);
        let exact_maximum = checked_session_deadline(recorded_at, crate::MAX_SESSION_TTL)
            .expect("maximum outcome deadline");
        let one_over = Timestamp::from_offset_datetime(
            exact_maximum
                .as_offset_datetime()
                .checked_add(time::Duration::nanoseconds(1))
                .expect("one-over outcome deadline"),
        );
        let retained_until =
            checked_session_deadline(recorded_at, FENCED_TRANSITION_OUTCOME_RETENTION)
                .expect("retention deadline");
        let make_outcome = |acquired_at, lease_expires_at, mutation| FencedTransitionOutcome {
            lease: LeaseGuard::new(
                key(),
                OwnerId::new("owner-a").expect("owner"),
                FenceToken::new(8),
                acquired_at,
                lease_expires_at,
                1,
            ),
            committed_generation: Generation::new(1),
            mutation,
            recorded_at,
            retained_until,
        };

        assert!(make_outcome(
            recorded_at,
            exact_maximum,
            FencedTransitionMutationResult::TtlRefreshed {
                expires_at: exact_maximum,
            },
        )
        .validate()
        .is_ok());
        for invalid in [
            make_outcome(
                recorded_at,
                one_over,
                FencedTransitionMutationResult::Created,
            ),
            make_outcome(
                recorded_at,
                exact_maximum,
                FencedTransitionMutationResult::TtlRefreshed {
                    expires_at: one_over,
                },
            ),
            make_outcome(
                Timestamp::from_offset_datetime(
                    recorded_at
                        .as_offset_datetime()
                        .checked_add(time::Duration::nanoseconds(1))
                        .expect("future acquisition"),
                ),
                exact_maximum,
                FencedTransitionMutationResult::Created,
            ),
            make_outcome(
                recorded_at,
                exact_maximum,
                FencedTransitionMutationResult::TtlRefreshed {
                    expires_at: recorded_at,
                },
            ),
        ] {
            assert!(matches!(
                invalid.validate(),
                Err(StoreError::Serialization(_))
            ));
        }
    }

    #[test]
    fn maximum_typed_outcome_serialization_is_below_the_outcome_cap() {
        // Every variable-width member of an outcome is in its lease key or
        // owner. This fixture uses each public maximum, plus scalar values
        // whose JSON renderings are maximal, to show that a typed outcome
        // cannot approach the 16 KiB cap without adding a payload field.
        // 9999-12-30T00:00:00Z leaves the fixed 24-hour receipt window
        // representable while maximizing the timestamp's JSON width.
        let recorded_at = timestamp(253_402_128_000);
        let lease = LeaseGuard::new(
            SessionKey {
                tenant: TenantId::new("t".repeat(128)).expect("maximum tenant"),
                nf_kind: NetworkFunctionKind::new("n".repeat(64)).expect("maximum NF kind"),
                key_type: SessionKeyType::other("k".repeat(crate::SESSION_KEY_TYPE_MAX_BYTES))
                    .expect("maximum key type"),
                stable_id: StableId::new(Bytes::from(vec![u8::MAX; crate::STABLE_ID_MAX_BYTES]))
                    .expect("maximum stable ID"),
            },
            OwnerId::new("o".repeat(crate::OWNER_ID_MAX_BYTES)).expect("maximum owner"),
            FenceToken::new(u64::MAX),
            recorded_at,
            Timestamp::from_offset_datetime(
                *recorded_at.as_offset_datetime() + time::Duration::nanoseconds(1),
            ),
            u64::MAX,
        );
        let outcome = FencedTransitionOutcome::new(
            lease,
            Generation::new(u64::MAX),
            FencedTransitionMutationResult::TtlRefreshed {
                expires_at: Timestamp::from_offset_datetime(
                    *recorded_at.as_offset_datetime() + time::Duration::nanoseconds(1),
                ),
            },
            recorded_at,
        )
        .expect("maximum typed outcome remains valid");
        let encoded = serde_json::to_vec(&outcome).expect("serialize maximum typed outcome");

        assert!(
            encoded.len() < FENCED_TRANSITION_MAX_OUTCOME_BYTES,
            "maximum typed outcome is {} bytes, below the {} byte cap",
            encoded.len(),
            FENCED_TRANSITION_MAX_OUTCOME_BYTES,
        );
        assert!(outcome.validate().is_ok());
    }

    #[test]
    fn debug_output_is_non_identifying() {
        let request_id = FencedTransitionRequestId::from_bytes([0x5a; 16]);
        assert_eq!(
            format!("{request_id:?}"),
            "FencedTransitionRequestId(<redacted>)"
        );
        assert!(!format!("{request_id:?}").contains("5a"));
        assert_eq!(
            format!(
                "{:?}",
                FencedTransitionMutationResult::TtlRefreshed {
                    expires_at: timestamp(123),
                }
            ),
            "FencedTransitionMutationResult(<redacted>)"
        );
        assert_eq!(
            format!(
                "{:?}",
                FencedTransitionStatus::Recorded(Box::new(Err(StoreError::InvalidKey(
                    "secret".into(),
                ))))
            ),
            "FencedTransitionStatus(<redacted>)"
        );

        let mut debug_key = key();
        debug_key.tenant = TenantId::from_static("debug-secret-tenant");
        let debug_owner = OwnerId::new("debug-secret-owner").expect("owner");
        let debug_lease = FencedTransitionLease::acquire(
            debug_key.clone(),
            debug_owner.clone(),
            FenceToken::new(90),
            Duration::from_secs(30),
        )
        .expect("lease action");
        let debug_mutation = FencedTransitionMutation::create(record(
            debug_key.clone(),
            debug_owner,
            FenceToken::new(91),
            1,
        ));
        let debug_request = FencedTransitionRequest::new(
            FencedTransitionRequestId::from_bytes([0xA5; 16]),
            debug_lease.clone(),
            debug_mutation.clone(),
        )
        .expect("request");
        let debug_observation =
            FencedTransitionObservation::new(debug_mutation.record().cloned(), FenceToken::new(91))
                .expect("observation");
        let rendered =
            format!("{debug_lease:?}{debug_mutation:?}{debug_request:?}{debug_observation:?}");
        let rendered_lower = rendered.to_ascii_lowercase();
        for secret in ["debug-secret", "90", "91", "a5", "opaque"] {
            assert!(!rendered_lower.contains(secret));
        }
        assert_eq!(
            [
                StoreError::FencedTransitionRequestConflict,
                StoreError::FencedTransitionOutcomeUnknown,
                StoreError::FencedTransitionRequestExpired,
                StoreError::FencedTransitionHistoryFull,
                StoreError::FencedTransitionRetentionExhausted,
                StoreError::FencedTransitionStorageExhausted,
            ]
            .map(|error| error.to_string()),
            [
                "fenced transition request identity was reused",
                "fenced transition outcome is unknown",
                "fenced transition result retention expired",
                "fenced transition request history is full",
                "fenced transition result retention horizon is exhausted",
                "fenced transition storage counter is exhausted",
            ]
            .map(str::to_owned)
        );
    }

    #[test]
    fn status_recorded_result_is_compact_and_serialization_transparent() {
        let status = FencedTransitionStatus::Recorded(Box::new(Err(StoreError::NotFound)));

        assert!(
            std::mem::size_of::<FencedTransitionStatus>()
                < std::mem::size_of::<FencedTransitionOutcome>(),
            "the status must not inline a complete outcome"
        );
        assert_eq!(
            serde_json::to_string(&status).expect("serialize status"),
            r#"{"Recorded":{"Err":"NotFound"}}"#,
            "boxing must not change the externally tagged persisted status shape"
        );
        assert_eq!(
            serde_json::from_str::<FencedTransitionStatus>(r#"{"Recorded":{"Err":"NotFound"}}"#,)
                .expect("deserialize legacy recorded status"),
            status,
        );
    }
}
