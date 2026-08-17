//! Atomic, single-record lease-and-mutation transitions.
//!
//! A fenced transition combines exactly one lease acquire or renewal with
//! exactly one mutation of the lease's record. Consensus-backed stores commit
//! the pair at one log position; weaker backends keep the capability disabled.

use std::{fmt, time::Duration};

use opc_types::Timestamp;
use serde::{Deserialize, Serialize};

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
        let _ = self.committed_fence()?;
        Ok(())
    }

    pub(crate) fn validate_at(&self, logical_time: Timestamp) -> Result<(), StoreError> {
        self.validate()?;
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
}

impl fmt::Debug for FencedTransitionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FencedTransitionRequest(<redacted>)")
    }
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
        if self.lease.fence().get() == 0
            || self.lease.credential_id() == 0
            || self.lease.expires_at() <= self.recorded_at
            || self.retained_until <= self.recorded_at
        {
            return Err(StoreError::Serialization(INVALID_TRANSITION_OUTCOME.into()));
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
            ]
            .map(|error| error.to_string()),
            [
                "fenced transition request identity was reused",
                "fenced transition outcome is unknown",
                "fenced transition result retention expired",
                "fenced transition request history is full",
                "fenced transition result retention horizon is exhausted",
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
