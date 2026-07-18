//! Generic fenced ownership leases backed by the session-store authority.
//!
//! The primitive is deliberately key-agnostic. Callers supply a bounded opaque
//! key and metadata; the SDK maps them into one tenant/NF-scoped session record
//! without interpreting either value. The existing backend lease serializes
//! each mutation, and the committed record is the logical ownership lease.
//! Consequently Openraft remains the only production commit/sequencing
//! authority and a transfer is one generation-checked record replacement.
//!
//! The facade also adds no cryptographic boundary. Production callers retain
//! at-rest payload protection by placing it above an
//! [`crate::EncryptingSessionBackend`] (normally wrapping the consensus store);
//! a plain backend receives a plaintext ownership payload. Cache bootstrap is
//! similarly explicit: replay from committed sequence one through a proven
//! [`FencedOwnershipCacheReplayHead`], or provide a namespace-bound
//! [`FencedOwnershipCacheSeed`] whose snapshot/head coherence and proof time
//! were established by an external authority. Restore scans do not currently
//! provide that watermark. A quiet watch provides no heartbeat: the view ages
//! stale unless the consumer supplies new committed evidence.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use opc_key::Zeroizing;
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::backend::{CompareAndSet, CompareAndSetResult, ReplicationEntry, ReplicationOp};
use crate::capability::BackendCapabilities;
use crate::clock::Clock;
use crate::error::{LeaseError, StoreError};
use crate::lease::{LeaseGuard, SessionLeaseManager};
use crate::model::{
    Generation, OwnerId, SessionKey, SessionKeyType, StableId, StateClass, StateType,
};
use crate::record::{EncryptedSessionPayload, SessionPayloadEncoding, StoredSessionRecord};
use crate::{checked_session_deadline, validate_session_ttl, SessionBackend};

const OWNERSHIP_KEY_TYPE: &str = "fenced-ownership-v1";
const OWNERSHIP_RECORD_MAGIC: [u8; 4] = *b"OPFO";
const OWNERSHIP_RECORD_VERSION: u8 = 1;
const OWNERSHIP_RECORD_FIXED_BYTES: usize = 78;
const OWNERSHIP_RECORD_MAX_BYTES: usize =
    OWNERSHIP_RECORD_FIXED_BYTES + OWNERSHIP_METADATA_MAX_BYTES;
const CLAIM_KIND: u8 = 1;
const RENEW_KIND: u8 = 2;
const TRANSFER_KIND: u8 = 3;
const MUTATION_LEASE_TTL: Duration = Duration::from_secs(10);
const MUTATION_RELEASE_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum bytes in one caller-defined ownership key.
pub const OWNERSHIP_KEY_MAX_BYTES: usize = crate::STABLE_ID_MAX_BYTES;

/// Maximum opaque metadata bytes retained in one ownership record.
pub const OWNERSHIP_METADATA_MAX_BYTES: usize = 65_536;

/// Maximum entries admitted to one local owner cache.
pub const OWNERSHIP_CACHE_MAX_ENTRIES: usize = 65_536;

/// Maximum variable/fixed record bytes retained by one local owner cache.
///
/// Entry count independently bounds map/`Arc` overhead. This byte ceiling
/// prevents maximum-sized opaque metadata across every entry from retaining
/// multiple gigabytes.
pub const OWNERSHIP_CACHE_MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;

/// Stable, redaction-safe failure from the fenced-ownership boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum FencedOwnershipError {
    /// The opaque key was empty or exceeded its production bound.
    #[error("invalid fenced-ownership key")]
    InvalidKey,
    /// Opaque metadata exceeded its production bound.
    #[error("fenced-ownership metadata exceeds the production bound")]
    MetadataTooLarge,
    /// A logical ownership lease used a zero, oversized, or unrepresentable TTL.
    #[error("invalid fenced-ownership lease TTL")]
    InvalidLeaseTtl,
    /// The selected backend cannot provide the authority contract.
    #[error("backend lacks fenced-ownership capabilities")]
    CapabilityNotSupported,
    /// Another mutation currently holds the bounded serialization lease.
    #[error("fenced-ownership mutation is contended")]
    Contended,
    /// The expected absence or generation did not match authoritative state.
    #[error("fenced-ownership compare-and-set conflict")]
    Conflict,
    /// A newer ownership generation exists.
    #[error("fenced-ownership token is stale")]
    StaleFence,
    /// The logical ownership lease has expired.
    #[error("fenced-ownership lease expired")]
    Expired,
    /// No authoritative ownership record exists.
    #[error("fenced-ownership record not found")]
    NotFound,
    /// A mutation identity was reused for different inputs.
    #[error("fenced-ownership mutation identity was reused")]
    IdempotencyConflict,
    /// A mutation crossed a boundary without a confirmable outcome.
    #[error("fenced-ownership mutation outcome is unavailable")]
    OutcomeUnavailable,
    /// Persisted or watched ownership state violated the bounded schema.
    #[error("invalid fenced-ownership record")]
    InvalidRecord,
    /// Cache configuration was zero or exceeded its fixed limit.
    #[error("invalid fenced-ownership cache configuration")]
    InvalidCacheConfig,
    /// A committed watch skipped or reordered an application sequence.
    #[error("fenced-ownership watch sequence is not contiguous")]
    WatchGap,
    /// A cache feed stopped without explicit cancellation.
    #[error("fenced-ownership watch ended")]
    WatchEnded,
    /// The configured cache cannot retain another entry or record byte.
    #[error("fenced-ownership cache capacity exceeded")]
    CacheCapacityExceeded,
    /// The authoritative backend was unavailable.
    #[error("fenced-ownership backend unavailable")]
    BackendUnavailable,
}

impl FencedOwnershipError {
    /// Stable machine-readable diagnostic code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidKey => "fenced_ownership_invalid_key",
            Self::MetadataTooLarge => "fenced_ownership_metadata_too_large",
            Self::InvalidLeaseTtl => "fenced_ownership_invalid_lease_ttl",
            Self::CapabilityNotSupported => "fenced_ownership_capability_not_supported",
            Self::Contended => "fenced_ownership_contended",
            Self::Conflict => "fenced_ownership_conflict",
            Self::StaleFence => "fenced_ownership_stale_fence",
            Self::Expired => "fenced_ownership_expired",
            Self::NotFound => "fenced_ownership_not_found",
            Self::IdempotencyConflict => "fenced_ownership_idempotency_conflict",
            Self::OutcomeUnavailable => "fenced_ownership_outcome_unavailable",
            Self::InvalidRecord => "fenced_ownership_invalid_record",
            Self::InvalidCacheConfig => "fenced_ownership_invalid_cache_config",
            Self::WatchGap => "fenced_ownership_watch_gap",
            Self::WatchEnded => "fenced_ownership_watch_ended",
            Self::CacheCapacityExceeded => "fenced_ownership_cache_capacity_exceeded",
            Self::BackendUnavailable => "fenced_ownership_backend_unavailable",
        }
    }
}

/// Bounded opaque ownership key supplied by a consumer.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FencedOwnershipKey(StableId);

impl FencedOwnershipKey {
    /// Validate one opaque key without interpreting its bytes.
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self, FencedOwnershipError> {
        let value = value.as_ref();
        if value.is_empty() || value.len() > OWNERSHIP_KEY_MAX_BYTES {
            return Err(FencedOwnershipError::InvalidKey);
        }
        StableId::new(Bytes::copy_from_slice(value))
            .map(Self)
            .map_err(|_| FencedOwnershipError::InvalidKey)
    }

    /// Borrow the exact opaque bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for FencedOwnershipKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FencedOwnershipKey")
            .field("len", &self.as_bytes().len())
            .finish()
    }
}

/// Bounded opaque caller metadata associated with an owner.
#[derive(Clone, PartialEq, Eq)]
pub struct FencedOwnershipMetadata(Bytes);

impl FencedOwnershipMetadata {
    /// Validate and retain opaque metadata.
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self, FencedOwnershipError> {
        let value = value.as_ref();
        if value.len() > OWNERSHIP_METADATA_MAX_BYTES {
            return Err(FencedOwnershipError::MetadataTooLarge);
        }
        Ok(Self(Bytes::copy_from_slice(value)))
    }

    /// Construct empty metadata.
    #[must_use]
    pub const fn empty() -> Self {
        Self(Bytes::new())
    }

    /// Borrow the exact opaque bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for FencedOwnershipMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FencedOwnershipMetadata")
            .field("len", &self.0.len())
            .finish()
    }
}

/// Stable caller identity for retrying one ownership mutation on one key.
///
/// Callers must mint a distinct ID for concurrent mutations. Exact replay and
/// conflicting reuse are detectable while that key's result remains in its
/// current ownership record; this is not a separate global request registry.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FencedOwnershipMutationId(uuid::Uuid);

impl FencedOwnershipMutationId {
    /// Generate a cryptographically random mutation identity.
    #[must_use]
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }

    /// Construct from exact UUID bytes, useful when restoring a retained request.
    #[must_use]
    pub const fn from_bytes(value: [u8; 16]) -> Self {
        Self(uuid::Uuid::from_bytes(value))
    }

    /// Return the exact fixed-width representation.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        *self.0.as_bytes()
    }
}

impl Default for FencedOwnershipMutationId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for FencedOwnershipMutationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FencedOwnershipMutationId([redacted])")
    }
}

/// Strictly positive monotonic ownership generation and effect-point fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FencedOwnershipGeneration(u64);

impl FencedOwnershipGeneration {
    fn new(value: u64) -> Result<Self, FencedOwnershipError> {
        if value == 0 {
            Err(FencedOwnershipError::InvalidRecord)
        } else {
            Ok(Self(value))
        }
    }

    /// Return the monotonic scalar value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Current authoritative owner, generation, expiry, and opaque metadata.
#[derive(Clone, PartialEq, Eq)]
pub struct FencedOwnershipRecord {
    namespace: FencedOwnershipNamespace,
    key: FencedOwnershipKey,
    owner: OwnerId,
    generation: FencedOwnershipGeneration,
    expires_at: Timestamp,
    metadata: FencedOwnershipMetadata,
}

impl FencedOwnershipRecord {
    /// Borrow the tenant/NF scope that issued this record.
    #[must_use]
    pub const fn namespace(&self) -> &FencedOwnershipNamespace {
        &self.namespace
    }

    /// Borrow the opaque caller key.
    #[must_use]
    pub const fn key(&self) -> &FencedOwnershipKey {
        &self.key
    }

    /// Borrow the current owner identity.
    #[must_use]
    pub const fn owner(&self) -> &OwnerId {
        &self.owner
    }

    /// Return the current ownership generation/fence.
    #[must_use]
    pub const fn generation(&self) -> FencedOwnershipGeneration {
        self.generation
    }

    /// Return the logical lease deadline.
    #[must_use]
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    /// Borrow the exact opaque metadata.
    #[must_use]
    pub const fn metadata(&self) -> &FencedOwnershipMetadata {
        &self.metadata
    }

    /// Create the effect-point token for this exact owner generation.
    #[must_use]
    pub fn fence_token(&self) -> FencedOwnershipToken {
        FencedOwnershipToken {
            namespace: self.namespace.clone(),
            key: self.key.clone(),
            owner: self.owner.clone(),
            generation: self.generation,
            expires_at: self.expires_at,
        }
    }
}

impl fmt::Debug for FencedOwnershipRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FencedOwnershipRecord")
            .field("key", &self.key)
            .field("owner", &"[redacted]")
            .field("generation", &self.generation)
            .field("expires_at", &"[redacted]")
            .field("metadata", &self.metadata)
            .finish()
    }
}

/// Effect-point proof naming one exact owner generation and lease deadline.
#[derive(Clone, PartialEq, Eq)]
pub struct FencedOwnershipToken {
    namespace: FencedOwnershipNamespace,
    key: FencedOwnershipKey,
    owner: OwnerId,
    generation: FencedOwnershipGeneration,
    expires_at: Timestamp,
}

impl FencedOwnershipToken {
    /// Borrow the tenant/NF scope bound to this token.
    #[must_use]
    pub const fn namespace(&self) -> &FencedOwnershipNamespace {
        &self.namespace
    }

    /// Borrow the opaque key.
    #[must_use]
    pub const fn key(&self) -> &FencedOwnershipKey {
        &self.key
    }

    /// Borrow the owner identity.
    #[must_use]
    pub const fn owner(&self) -> &OwnerId {
        &self.owner
    }

    /// Return the monotonic generation/fence.
    #[must_use]
    pub const fn generation(&self) -> FencedOwnershipGeneration {
        self.generation
    }

    /// Return the logical lease deadline.
    #[must_use]
    pub const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}

impl fmt::Debug for FencedOwnershipToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FencedOwnershipToken")
            .field("key", &self.key)
            .field("owner", &"[redacted]")
            .field("generation", &self.generation)
            .field("expires_at", &"[redacted]")
            .finish()
    }
}

/// Whether a mutation was newly applied or recovered from its retained ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FencedOwnershipMutation<T> {
    /// This invocation committed the mutation.
    Applied(T),
    /// The same mutation had already committed and its exact result was replayed.
    Replayed(T),
}

impl<T> FencedOwnershipMutation<T> {
    /// Consume the outcome and return its value.
    #[must_use]
    pub fn into_inner(self) -> T {
        match self {
            Self::Applied(value) | Self::Replayed(value) => value,
        }
    }
}

/// Tenant/NF scope used to map opaque keys into session-store keys.
#[derive(Clone, PartialEq, Eq)]
pub struct FencedOwnershipNamespace {
    tenant: TenantId,
    nf_kind: NetworkFunctionKind,
}

impl FencedOwnershipNamespace {
    /// Construct an explicit tenant and network-function scope.
    #[must_use]
    pub const fn new(tenant: TenantId, nf_kind: NetworkFunctionKind) -> Self {
        Self { tenant, nf_kind }
    }

    fn session_key(&self, key: &FencedOwnershipKey) -> Result<SessionKey, FencedOwnershipError> {
        Ok(SessionKey {
            tenant: self.tenant.clone(),
            nf_kind: self.nf_kind.clone(),
            key_type: SessionKeyType::other(OWNERSHIP_KEY_TYPE)
                .map_err(|_| FencedOwnershipError::InvalidRecord)?,
            stable_id: key.0.clone(),
        })
    }

    fn owns_session_key(&self, key: &SessionKey) -> bool {
        key.tenant == self.tenant
            && key.nf_kind == self.nf_kind
            && key.key_type.as_str() == OWNERSHIP_KEY_TYPE
    }

    fn opaque_key(&self, key: &SessionKey) -> Result<FencedOwnershipKey, FencedOwnershipError> {
        if !self.owns_session_key(key) {
            return Err(FencedOwnershipError::InvalidRecord);
        }
        Ok(FencedOwnershipKey(key.stable_id.clone()))
    }
}

impl fmt::Debug for FencedOwnershipNamespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FencedOwnershipNamespace")
            .field("tenant", &"[redacted]")
            .field("nf_kind", &self.nf_kind)
            .finish()
    }
}

/// Capability verdict for the ownership authority and its committed-watch cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FencedOwnershipCapabilities {
    /// Backend can commit authoritative ownership mutations.
    pub authoritative_mutations: bool,
    /// Backend can feed a cache from committed ordered changes.
    pub committed_watch_cache: bool,
}

impl FencedOwnershipCapabilities {
    /// Derive the executable ownership surface from backend capabilities.
    #[must_use]
    pub const fn from_backend(capabilities: BackendCapabilities) -> Self {
        let authoritative_mutations = capabilities.atomic_compare_and_set
            && capabilities.monotonic_fencing_token
            && capabilities.per_key_ttl
            && capabilities.server_side_lease_expiry
            && capabilities.max_value_bytes >= OWNERSHIP_RECORD_MAX_BYTES;
        Self {
            authoritative_mutations,
            committed_watch_cache: authoritative_mutations
                && capabilities.ordered_replication_log
                && capabilities.watch,
        }
    }
}

#[derive(Clone)]
struct DecodedOwnershipRecord {
    public: FencedOwnershipRecord,
    storage_generation: Generation,
    mutation_id: FencedOwnershipMutationId,
    mutation_fingerprint: [u8; 32],
    mutation_kind: u8,
}

enum CurrentExpectation<'a> {
    Absent,
    Token(&'a FencedOwnershipToken),
}

struct MutationLeaseCleanup<B>
where
    B: SessionLeaseManager + 'static,
{
    backend: Arc<B>,
    lease: Option<LeaseGuard>,
}

impl<B> MutationLeaseCleanup<B>
where
    B: SessionLeaseManager + 'static,
{
    fn guard(&self) -> Result<&LeaseGuard, FencedOwnershipError> {
        self.lease
            .as_ref()
            .ok_or(FencedOwnershipError::OutcomeUnavailable)
    }
}

impl<B> Drop for MutationLeaseCleanup<B>
where
    B: SessionLeaseManager + 'static,
{
    fn drop(&mut self) {
        let Some(lease) = self.lease.take() else {
            return;
        };
        let backend = Arc::clone(&self.backend);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            drop(runtime.spawn(async move {
                let _ =
                    tokio::time::timeout(MUTATION_RELEASE_TIMEOUT, backend.release(lease)).await;
            }));
        }
    }
}

/// Generic fenced-ownership authority over an existing session backend.
#[derive(Clone)]
pub struct FencedOwnershipStore<B, C> {
    backend: Arc<B>,
    namespace: FencedOwnershipNamespace,
    clock: C,
}

impl<B, C> fmt::Debug for FencedOwnershipStore<B, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FencedOwnershipStore")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl<B, C> FencedOwnershipStore<B, C>
where
    B: SessionBackend + SessionLeaseManager + 'static,
    C: Clock + Clone,
{
    /// Compose ownership with an existing backend and injected clock.
    #[must_use]
    pub fn new(backend: B, namespace: FencedOwnershipNamespace, clock: C) -> Self {
        Self {
            backend: Arc::new(backend),
            namespace,
            clock,
        }
    }

    /// Report whether the backend can execute authority and cache contracts.
    pub async fn capabilities(&self) -> FencedOwnershipCapabilities {
        FencedOwnershipCapabilities::from_backend(self.backend.capabilities().await)
    }

    /// Fail closed at configuration time if authoritative mutations are unavailable.
    pub async fn validate_authority(&self) -> Result<(), FencedOwnershipError> {
        if self.capabilities().await.authoritative_mutations {
            Ok(())
        } else {
            Err(FencedOwnershipError::CapabilityNotSupported)
        }
    }

    /// Read the current live owner from authoritative state.
    pub async fn current(
        &self,
        key: &FencedOwnershipKey,
    ) -> Result<Option<FencedOwnershipRecord>, FencedOwnershipError> {
        self.validate_authority().await?;
        Ok(self.read_current(key).await?.map(|decoded| decoded.public))
    }

    /// Claim an absent or expired key with a fresh, strictly positive generation.
    pub async fn claim(
        &self,
        mutation_id: FencedOwnershipMutationId,
        key: FencedOwnershipKey,
        owner: OwnerId,
        ttl: Duration,
        metadata: FencedOwnershipMetadata,
    ) -> Result<FencedOwnershipMutation<FencedOwnershipRecord>, FencedOwnershipError> {
        validate_logical_ttl(ttl)?;
        let fingerprint = mutation_fingerprint(CLAIM_KIND, &key, None, &owner, ttl, &metadata);
        self.commit_record(
            mutation_id,
            CLAIM_KIND,
            fingerprint,
            key,
            CurrentExpectation::Absent,
            owner,
            ttl,
            metadata,
        )
        .await
    }

    /// Renew ownership only for the exact current owner generation.
    ///
    /// Renewal commits a higher generation, so the previous token is fenced
    /// immediately when this method succeeds.
    pub async fn renew(
        &self,
        mutation_id: FencedOwnershipMutationId,
        token: &FencedOwnershipToken,
        ttl: Duration,
    ) -> Result<FencedOwnershipMutation<FencedOwnershipRecord>, FencedOwnershipError> {
        validate_logical_ttl(ttl)?;
        self.ensure_token_scope(token)?;
        let current = self
            .read_current(token.key())
            .await?
            .ok_or(FencedOwnershipError::NotFound)?;
        let fingerprint = mutation_fingerprint(
            RENEW_KIND,
            token.key(),
            Some(token),
            token.owner(),
            ttl,
            current.public.metadata(),
        );
        self.commit_record(
            mutation_id,
            RENEW_KIND,
            fingerprint,
            token.key.clone(),
            CurrentExpectation::Token(token),
            token.owner.clone(),
            ttl,
            current.public.metadata,
        )
        .await
    }

    /// Atomically transfer the exact current generation to a new owner.
    pub async fn transfer(
        &self,
        mutation_id: FencedOwnershipMutationId,
        token: &FencedOwnershipToken,
        new_owner: OwnerId,
        ttl: Duration,
        metadata: FencedOwnershipMetadata,
    ) -> Result<FencedOwnershipMutation<FencedOwnershipRecord>, FencedOwnershipError> {
        validate_logical_ttl(ttl)?;
        self.ensure_token_scope(token)?;
        if token.owner == new_owner {
            return Err(FencedOwnershipError::Conflict);
        }
        let fingerprint = mutation_fingerprint(
            TRANSFER_KIND,
            token.key(),
            Some(token),
            &new_owner,
            ttl,
            &metadata,
        );
        self.commit_record(
            mutation_id,
            TRANSFER_KIND,
            fingerprint,
            token.key.clone(),
            CurrentExpectation::Token(token),
            new_owner,
            ttl,
            metadata,
        )
        .await
    }

    /// Release the exact current generation, retaining the backend fence floor.
    pub async fn release(
        &self,
        token: &FencedOwnershipToken,
    ) -> Result<FencedOwnershipMutation<()>, FencedOwnershipError> {
        self.validate_authority().await?;
        self.ensure_token_scope(token)?;
        if self.read_current(token.key()).await?.is_none() {
            return Ok(FencedOwnershipMutation::Replayed(()));
        }
        self.read_expected(token).await?;
        let key = self.namespace.session_key(token.key())?;
        let cleanup =
            acquire_mutation_lease(Arc::clone(&self.backend), key, token.owner.clone()).await?;
        self.read_expected(token).await?;
        self.backend
            .delete_fenced(cleanup.guard()?)
            .await
            .map_err(map_store_error)?;
        Ok(FencedOwnershipMutation::Applied(()))
    }

    /// Validate a fence token against a fresh authoritative read.
    pub async fn validate_fence(
        &self,
        token: &FencedOwnershipToken,
    ) -> Result<(), FencedOwnershipError> {
        self.validate_authority().await?;
        self.ensure_token_scope(token)?;
        self.read_expected(token).await.map(|_| ())
    }

    async fn read_current(
        &self,
        key: &FencedOwnershipKey,
    ) -> Result<Option<DecodedOwnershipRecord>, FencedOwnershipError> {
        let session_key = self.namespace.session_key(key)?;
        self.backend
            .get(&session_key)
            .await
            .map_err(map_store_error)?
            .map(|record| decode_record(&self.namespace, &record))
            .transpose()
    }

    async fn read_expected(
        &self,
        token: &FencedOwnershipToken,
    ) -> Result<DecodedOwnershipRecord, FencedOwnershipError> {
        self.ensure_token_scope(token)?;
        if token.expires_at <= self.clock.now_utc() {
            return Err(FencedOwnershipError::Expired);
        }
        let Some(current) = self.read_current(token.key()).await? else {
            return Err(FencedOwnershipError::NotFound);
        };
        if current.public.owner != token.owner
            || current.public.generation != token.generation
            || current.public.expires_at != token.expires_at
        {
            return Err(FencedOwnershipError::StaleFence);
        }
        if current.public.expires_at <= self.clock.now_utc() {
            return Err(FencedOwnershipError::Expired);
        }
        Ok(current)
    }

    #[allow(clippy::too_many_arguments)]
    async fn commit_record(
        &self,
        mutation_id: FencedOwnershipMutationId,
        mutation_kind: u8,
        mutation_fingerprint: [u8; 32],
        key: FencedOwnershipKey,
        expectation: CurrentExpectation<'_>,
        owner: OwnerId,
        ttl: Duration,
        metadata: FencedOwnershipMetadata,
    ) -> Result<FencedOwnershipMutation<FencedOwnershipRecord>, FencedOwnershipError> {
        self.validate_authority().await?;
        if let Some(replayed) = self.validate_current_or_replay(
            self.read_current(&key).await?,
            &expectation,
            mutation_id,
            mutation_kind,
            mutation_fingerprint,
        )? {
            return Ok(FencedOwnershipMutation::Replayed(replayed.public));
        }

        let session_key = self.namespace.session_key(&key)?;
        let cleanup = acquire_mutation_lease(
            Arc::clone(&self.backend),
            session_key.clone(),
            owner.clone(),
        )
        .await?;
        let current = self.read_current(&key).await?;
        if let Some(replayed) = self.validate_current_or_replay(
            current.clone(),
            &expectation,
            mutation_id,
            mutation_kind,
            mutation_fingerprint,
        )? {
            return Ok(FencedOwnershipMutation::Replayed(replayed.public));
        }

        let guard = cleanup.guard()?;
        let generation = FencedOwnershipGeneration::new(guard.fence().get())?;
        if current
            .as_ref()
            .is_some_and(|value| generation <= value.public.generation)
        {
            return Err(FencedOwnershipError::StaleFence);
        }
        let expires_at = checked_session_deadline(guard.acquired_at(), ttl)
            .map_err(|_| FencedOwnershipError::InvalidLeaseTtl)?;
        let storage_generation = match current.as_ref() {
            Some(value) => value
                .storage_generation
                .next()
                .ok_or(FencedOwnershipError::OutcomeUnavailable)?,
            None => Generation::new(1),
        };
        let public = FencedOwnershipRecord {
            namespace: self.namespace.clone(),
            key: key.clone(),
            owner: owner.clone(),
            generation,
            expires_at,
            metadata,
        };
        let payload = encode_record(&public, mutation_id, mutation_fingerprint, mutation_kind)?;
        let stored = StoredSessionRecord {
            key: session_key.clone(),
            generation: storage_generation,
            owner,
            fence: guard.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new(OWNERSHIP_KEY_TYPE)
                .map_err(|_| FencedOwnershipError::InvalidRecord)?,
            expires_at: Some(expires_at),
            payload,
        };
        let result = self
            .backend
            .compare_and_set(CompareAndSet {
                key: session_key,
                lease: guard.clone(),
                expected_generation: current.as_ref().map(|value| value.storage_generation),
                new_record: stored,
            })
            .await
            .map_err(map_store_error)?;
        match result {
            CompareAndSetResult::Success => Ok(FencedOwnershipMutation::Applied(public)),
            CompareAndSetResult::Conflict { current } => {
                let replay = current
                    .map(|record| decode_record(&self.namespace, &record))
                    .transpose()?;
                if let Some(replayed) = replay.filter(|value| {
                    value.mutation_id == mutation_id
                        && value.mutation_kind == mutation_kind
                        && value.mutation_fingerprint == mutation_fingerprint
                }) {
                    Ok(FencedOwnershipMutation::Replayed(replayed.public))
                } else {
                    Err(FencedOwnershipError::Conflict)
                }
            }
        }
    }

    fn validate_current_or_replay(
        &self,
        current: Option<DecodedOwnershipRecord>,
        expectation: &CurrentExpectation<'_>,
        mutation_id: FencedOwnershipMutationId,
        mutation_kind: u8,
        mutation_fingerprint: [u8; 32],
    ) -> Result<Option<DecodedOwnershipRecord>, FencedOwnershipError> {
        if let CurrentExpectation::Token(token) = expectation {
            self.ensure_token_scope(token)?;
        }
        if let Some(value) = current
            .as_ref()
            .filter(|value| value.mutation_id == mutation_id)
        {
            return if value.mutation_kind == mutation_kind
                && value.mutation_fingerprint == mutation_fingerprint
            {
                Ok(current)
            } else {
                Err(FencedOwnershipError::IdempotencyConflict)
            };
        }
        match (expectation, current.as_ref()) {
            (CurrentExpectation::Absent, None) => Ok(None),
            (CurrentExpectation::Absent, Some(_)) => Err(FencedOwnershipError::Conflict),
            (CurrentExpectation::Token(token), Some(value))
                if value.public.owner == token.owner
                    && value.public.generation == token.generation
                    && value.public.expires_at == token.expires_at
                    && token.expires_at > self.clock.now_utc() =>
            {
                Ok(None)
            }
            (CurrentExpectation::Token(token), _) if token.expires_at <= self.clock.now_utc() => {
                Err(FencedOwnershipError::Expired)
            }
            (CurrentExpectation::Token(_), None) => Err(FencedOwnershipError::NotFound),
            (CurrentExpectation::Token(_), Some(_)) => Err(FencedOwnershipError::StaleFence),
        }
    }

    fn ensure_token_scope(&self, token: &FencedOwnershipToken) -> Result<(), FencedOwnershipError> {
        if token.namespace == self.namespace {
            Ok(())
        } else {
            Err(FencedOwnershipError::StaleFence)
        }
    }
}

async fn acquire_mutation_lease<B>(
    backend: Arc<B>,
    key: SessionKey,
    owner: OwnerId,
) -> Result<MutationLeaseCleanup<B>, FencedOwnershipError>
where
    B: SessionLeaseManager + 'static,
{
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|_| FencedOwnershipError::BackendUnavailable)?;
    let acquisition_backend = Arc::clone(&backend);
    runtime
        .spawn(async move {
            let lease = tokio::time::timeout(
                MUTATION_LEASE_TTL,
                acquisition_backend.acquire(&key, owner, MUTATION_LEASE_TTL),
            )
            .await
            .map_err(|_| FencedOwnershipError::OutcomeUnavailable)?
            .map_err(map_lease_error)?;
            Ok(MutationLeaseCleanup {
                backend: acquisition_backend,
                lease: Some(lease),
            })
        })
        .await
        .map_err(|_| FencedOwnershipError::OutcomeUnavailable)?
}

fn validate_logical_ttl(ttl: Duration) -> Result<(), FencedOwnershipError> {
    if ttl.is_zero() || validate_session_ttl(ttl).is_err() {
        Err(FencedOwnershipError::InvalidLeaseTtl)
    } else {
        Ok(())
    }
}

fn map_lease_error(error: LeaseError) -> FencedOwnershipError {
    match error {
        LeaseError::AlreadyHeld => FencedOwnershipError::Contended,
        LeaseError::Expired => FencedOwnershipError::Expired,
        LeaseError::StaleFence => FencedOwnershipError::StaleFence,
        LeaseError::NotFound => FencedOwnershipError::NotFound,
        LeaseError::InvalidSessionTtl => FencedOwnershipError::InvalidLeaseTtl,
        LeaseError::OperationOutcomeUnavailable => FencedOwnershipError::OutcomeUnavailable,
        LeaseError::Backend(_) => FencedOwnershipError::BackendUnavailable,
    }
}

fn map_store_error(error: StoreError) -> FencedOwnershipError {
    match error {
        StoreError::StaleFence => FencedOwnershipError::StaleFence,
        StoreError::CasConflict => FencedOwnershipError::Conflict,
        StoreError::CasIdempotencyConflict => FencedOwnershipError::IdempotencyConflict,
        StoreError::CasIdempotencyOutcomeUnavailable
        | StoreError::BackendOperationOutcomeUnavailable => {
            FencedOwnershipError::OutcomeUnavailable
        }
        StoreError::CapabilityNotSupported(_) => FencedOwnershipError::CapabilityNotSupported,
        StoreError::BackendUnavailable(_) => FencedOwnershipError::BackendUnavailable,
        StoreError::LeaseHeld => FencedOwnershipError::Contended,
        StoreError::LeaseExpired => FencedOwnershipError::Expired,
        StoreError::NotFound => FencedOwnershipError::NotFound,
        StoreError::InvalidSessionTtl | StoreError::InvalidRecordExpiry => {
            FencedOwnershipError::InvalidLeaseTtl
        }
        _ => FencedOwnershipError::InvalidRecord,
    }
}

fn map_watch_error(error: StoreError) -> FencedOwnershipError {
    match error {
        StoreError::ReplicationLogCursorCompacted { .. }
        | StoreError::ReplicationWatchCatchUpRequired => FencedOwnershipError::WatchGap,
        other => map_store_error(other),
    }
}

fn mutation_fingerprint(
    kind: u8,
    key: &FencedOwnershipKey,
    previous: Option<&FencedOwnershipToken>,
    owner: &OwnerId,
    ttl: Duration,
    metadata: &FencedOwnershipMetadata,
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"opc-session-store/fenced-ownership-mutation/v1");
    digest.update([kind]);
    hash_bytes(&mut digest, key.as_bytes());
    match previous {
        Some(token) => {
            digest.update([1]);
            hash_bytes(&mut digest, token.owner.as_str().as_bytes());
            digest.update(token.generation.get().to_be_bytes());
            digest.update(
                token
                    .expires_at
                    .as_offset_datetime()
                    .unix_timestamp()
                    .to_be_bytes(),
            );
            digest.update(
                token
                    .expires_at
                    .as_offset_datetime()
                    .nanosecond()
                    .to_be_bytes(),
            );
        }
        None => digest.update([0]),
    }
    hash_bytes(&mut digest, owner.as_str().as_bytes());
    digest.update(ttl.as_secs().to_be_bytes());
    digest.update(ttl.subsec_nanos().to_be_bytes());
    hash_bytes(&mut digest, metadata.as_bytes());
    digest.finalize().into()
}

fn hash_bytes(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn encode_record(
    record: &FencedOwnershipRecord,
    mutation_id: FencedOwnershipMutationId,
    mutation_fingerprint: [u8; 32],
    mutation_kind: u8,
) -> Result<EncryptedSessionPayload, FencedOwnershipError> {
    let metadata_len = u32::try_from(record.metadata.0.len())
        .map_err(|_| FencedOwnershipError::MetadataTooLarge)?;
    let mut encoded = Vec::with_capacity(OWNERSHIP_RECORD_FIXED_BYTES + record.metadata.0.len());
    encoded.extend_from_slice(&OWNERSHIP_RECORD_MAGIC);
    encoded.push(OWNERSHIP_RECORD_VERSION);
    encoded.push(mutation_kind);
    encoded.extend_from_slice(&mutation_id.as_bytes());
    encoded.extend_from_slice(&mutation_fingerprint);
    encoded.extend_from_slice(&record.generation.get().to_be_bytes());
    encoded.extend_from_slice(
        &record
            .expires_at
            .as_offset_datetime()
            .unix_timestamp()
            .to_be_bytes(),
    );
    encoded.extend_from_slice(
        &record
            .expires_at
            .as_offset_datetime()
            .nanosecond()
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&metadata_len.to_be_bytes());
    encoded.extend_from_slice(record.metadata.as_bytes());
    Ok(EncryptedSessionPayload::new_zeroizing(Zeroizing::new(
        encoded,
    )))
}

fn decode_record(
    namespace: &FencedOwnershipNamespace,
    record: &StoredSessionRecord,
) -> Result<DecodedOwnershipRecord, FencedOwnershipError> {
    if !namespace.owns_session_key(&record.key)
        || record.state_class != StateClass::AuthoritativeSession
        || record.state_type.as_str() != OWNERSHIP_KEY_TYPE
        || record.payload.encoding() != SessionPayloadEncoding::Plaintext
        || record.expires_at.is_none()
        || record.payload.len() < OWNERSHIP_RECORD_FIXED_BYTES
        || record.payload.len() > OWNERSHIP_RECORD_FIXED_BYTES + OWNERSHIP_METADATA_MAX_BYTES
    {
        return Err(FencedOwnershipError::InvalidRecord);
    }
    let bytes = record.payload.as_bytes();
    let mut cursor = RecordCursor::new(bytes);
    if cursor.take::<4>()? != OWNERSHIP_RECORD_MAGIC || cursor.u8()? != OWNERSHIP_RECORD_VERSION {
        return Err(FencedOwnershipError::InvalidRecord);
    }
    let mutation_kind = cursor.u8()?;
    if !matches!(mutation_kind, CLAIM_KIND | RENEW_KIND | TRANSFER_KIND) {
        return Err(FencedOwnershipError::InvalidRecord);
    }
    let mutation_id = FencedOwnershipMutationId::from_bytes(cursor.take::<16>()?);
    let mutation_fingerprint = cursor.take::<32>()?;
    let generation = FencedOwnershipGeneration::new(cursor.u64()?)?;
    let seconds = cursor.i64()?;
    let nanoseconds = cursor.u32()?;
    let metadata_len =
        usize::try_from(cursor.u32()?).map_err(|_| FencedOwnershipError::InvalidRecord)?;
    if metadata_len > OWNERSHIP_METADATA_MAX_BYTES || cursor.remaining() != metadata_len {
        return Err(FencedOwnershipError::InvalidRecord);
    }
    let expires_at = time::OffsetDateTime::from_unix_timestamp(seconds)
        .ok()
        .and_then(|value| value.replace_nanosecond(nanoseconds).ok())
        .map(Timestamp::from_offset_datetime)
        .ok_or(FencedOwnershipError::InvalidRecord)?;
    if record.expires_at != Some(expires_at) || record.fence.get() != generation.get() {
        return Err(FencedOwnershipError::InvalidRecord);
    }
    let key = namespace.opaque_key(&record.key)?;
    let metadata = FencedOwnershipMetadata::new(cursor.rest())?;
    Ok(DecodedOwnershipRecord {
        public: FencedOwnershipRecord {
            namespace: namespace.clone(),
            key,
            owner: record.owner.clone(),
            generation,
            expires_at,
            metadata,
        },
        storage_generation: record.generation,
        mutation_id,
        mutation_fingerprint,
        mutation_kind,
    })
}

struct RecordCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> RecordCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N], FencedOwnershipError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(FencedOwnershipError::InvalidRecord)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(FencedOwnershipError::InvalidRecord)?;
        self.position = end;
        value
            .try_into()
            .map_err(|_| FencedOwnershipError::InvalidRecord)
    }

    fn u8(&mut self) -> Result<u8, FencedOwnershipError> {
        Ok(self.take::<1>()?[0])
    }

    fn u32(&mut self) -> Result<u32, FencedOwnershipError> {
        Ok(u32::from_be_bytes(self.take()?))
    }

    fn u64(&mut self) -> Result<u64, FencedOwnershipError> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn i64(&mut self) -> Result<i64, FencedOwnershipError> {
        Ok(i64::from_be_bytes(self.take()?))
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn rest(&self) -> &'a [u8] {
        self.bytes.get(self.position..).unwrap_or_default()
    }
}

/// Cache construction limits and explicit maximum staleness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FencedOwnershipCacheConfig {
    /// Maximum duration since the last contiguous committed watch item.
    pub max_staleness: Duration,
    /// Maximum distinct keys retained by the cache.
    pub max_entries: usize,
    /// Maximum total encoded record/key/owner/metadata bytes retained.
    pub max_retained_bytes: usize,
}

impl FencedOwnershipCacheConfig {
    /// Validate a non-zero bounded cache profile.
    pub fn validate(self) -> Result<Self, FencedOwnershipError> {
        if self.max_staleness.is_zero()
            || self.max_staleness > crate::MAX_SESSION_TTL
            || self.max_entries == 0
            || self.max_entries > OWNERSHIP_CACHE_MAX_ENTRIES
            || self.max_retained_bytes == 0
            || self.max_retained_bytes > OWNERSHIP_CACHE_MAX_RETAINED_BYTES
        {
            Err(FencedOwnershipError::InvalidCacheConfig)
        } else {
            Ok(self)
        }
    }
}

/// Deliberate namespace-bound assertion that records and a committed log head
/// form one coherent snapshot.
///
/// The SDK does not currently derive this proof from restore scans: their
/// public cursor does not expose an atomic replication watermark. Consumers
/// must obtain the records and `committed_through` from an external authority
/// that guarantees they describe the same committed state. Without that
/// proof, construct an empty cache and replay the committed log from sequence
/// one instead.
pub struct FencedOwnershipCacheSeed {
    namespace: FencedOwnershipNamespace,
    records: Vec<FencedOwnershipRecord>,
    committed_through: u64,
    proven_at: Timestamp,
    retained_bytes: usize,
}

impl FencedOwnershipCacheSeed {
    /// Assert that `records` in `namespace` are complete at exactly
    /// `committed_through`.
    ///
    /// This constructor validates only structural bounds. Calling it is an
    /// explicit consumer assertion of external snapshot/log coherence; it
    /// does not manufacture or verify that authority. `proven_at` must be the
    /// time at which that external proof completed. Cache staleness is measured
    /// from that timestamp, so installing an old snapshot cannot make it fresh.
    pub fn from_caller_proven_snapshot(
        namespace: FencedOwnershipNamespace,
        records: impl IntoIterator<Item = FencedOwnershipRecord>,
        committed_through: u64,
        proven_at: Timestamp,
    ) -> Result<Self, FencedOwnershipError> {
        committed_through
            .checked_add(1)
            .ok_or(FencedOwnershipError::WatchGap)?;
        let mut bounded = Vec::new();
        let mut retained_bytes = 0usize;
        for record in records {
            if record.namespace != namespace {
                return Err(FencedOwnershipError::InvalidRecord);
            }
            if bounded.len() >= OWNERSHIP_CACHE_MAX_ENTRIES {
                return Err(FencedOwnershipError::CacheCapacityExceeded);
            }
            retained_bytes = retained_bytes
                .checked_add(cache_record_retained_bytes(&record))
                .ok_or(FencedOwnershipError::CacheCapacityExceeded)?;
            if retained_bytes > OWNERSHIP_CACHE_MAX_RETAINED_BYTES {
                return Err(FencedOwnershipError::CacheCapacityExceeded);
            }
            bounded.push(record);
        }
        Ok(Self {
            namespace,
            records: bounded,
            committed_through,
            proven_at,
            retained_bytes,
        })
    }

    /// Borrow the tenant/NF scope covered by the asserted snapshot.
    #[must_use]
    pub const fn namespace(&self) -> &FencedOwnershipNamespace {
        &self.namespace
    }

    /// Return the exact committed head asserted by the caller.
    #[must_use]
    pub const fn committed_through(&self) -> u64 {
        self.committed_through
    }

    /// Return when the caller completed its external coherence proof.
    #[must_use]
    pub const fn proven_at(&self) -> Timestamp {
        self.proven_at
    }

    /// Return the bounded number of records in the asserted snapshot.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.records.len()
    }

    /// Return whether the asserted snapshot contains no ownership records.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Return the bounded total record bytes carried by this seed.
    #[must_use]
    pub const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
}

impl fmt::Debug for FencedOwnershipCacheSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FencedOwnershipCacheSeed")
            .field("namespace", &self.namespace)
            .field("records", &self.records.len())
            .field("committed_through", &self.committed_through)
            .field("proven_at", &"[redacted]")
            .field("retained_bytes", &self.retained_bytes)
            .finish()
    }
}

/// Explicit caller assertion of the committed head for a full replay.
///
/// This is a global application-log proof, not a namespace-scoped cursor, and
/// cannot skip history: it is accepted only by a fresh or invalidated cache
/// whose next required sequence is one. The cache remains stale until every
/// entry through this head has been applied.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FencedOwnershipCacheReplayHead {
    committed_through: u64,
    proven_at: Timestamp,
}

impl FencedOwnershipCacheReplayHead {
    /// Assert an externally proven committed application-journal head.
    ///
    /// `proven_at` is the time at which the external proof completed and is
    /// retained as the cache freshness origin when the asserted head is empty.
    #[must_use]
    pub const fn from_caller_proven_head(committed_through: u64, proven_at: Timestamp) -> Self {
        Self {
            committed_through,
            proven_at,
        }
    }

    /// Return the exact committed head asserted by the caller.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.committed_through
    }

    /// Return when the caller completed its external head proof.
    #[must_use]
    pub const fn proven_at(self) -> Timestamp {
        self.proven_at
    }
}

impl fmt::Debug for FencedOwnershipCacheReplayHead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FencedOwnershipCacheReplayHead")
            .field("committed_through", &self.committed_through)
            .field("proven_at", &"[redacted]")
            .finish()
    }
}

/// Hot-path lookup outcome; `Stale` never carries an owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FencedOwnershipCacheLookup {
    /// A fresh live owner was found.
    ///
    /// The `Arc` shares allocation only; retaining it does not extend cache
    /// freshness. Callers must perform a new lookup at each effect boundary.
    Hit(Arc<FencedOwnershipRecord>),
    /// The fresh view contains no live owner for this key.
    Miss,
    /// Feed freshness or integrity is outside the configured bound.
    Stale,
}

/// Redaction-safe snapshot of cache health and counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FencedOwnershipCacheMetricsSnapshot {
    /// Fresh cache hits.
    pub hits: u64,
    /// Fresh cache misses, including locally expired records.
    pub misses: u64,
    /// Fail-closed stale lookups.
    pub stale: u64,
    /// Feed integrity, capacity, backend, or premature-end failures.
    pub feed_failures: u64,
    /// Number of retained records.
    pub entries: usize,
    /// Total bounded record bytes retained by the cache.
    pub retained_bytes: usize,
    /// Last contiguous committed application sequence, if seeded or replayed.
    pub last_sequence: Option<u64>,
    /// Current feed lag, or `None` before a healthy seed/item.
    pub cache_lag: Option<Duration>,
}

#[derive(Clone)]
struct CacheExpiryEntry(Arc<FencedOwnershipRecord>);

impl PartialEq for CacheExpiryEntry {
    fn eq(&self, other: &Self) -> bool {
        self.0.expires_at == other.0.expires_at
            && self.0.generation == other.0.generation
            && self.0.key == other.0.key
    }
}

impl Eq for CacheExpiryEntry {}

impl PartialOrd for CacheExpiryEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CacheExpiryEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .expires_at
            .cmp(&other.0.expires_at)
            .then_with(|| self.0.generation.cmp(&other.0.generation))
            .then_with(|| self.0.key.cmp(&other.0.key))
    }
}

struct FencedOwnershipCacheState {
    records: HashMap<FencedOwnershipKey, Arc<FencedOwnershipRecord>>,
    expirations: BTreeSet<CacheExpiryEntry>,
    retained_bytes: usize,
    next_sequence: u64,
    last_sequence: Option<u64>,
    last_observed: Option<Timestamp>,
    healthy: bool,
    terminal: bool,
    catch_up_through: Option<u64>,
}

struct FencedOwnershipCacheClockState {
    last_sample: Timestamp,
    invalid: bool,
}

struct FencedOwnershipCacheCounters {
    hits: AtomicU64,
    misses: AtomicU64,
    stale: AtomicU64,
    feed_failures: AtomicU64,
}

/// Bounded local owner cache fed from committed application-journal watches.
pub struct FencedOwnershipCache<C> {
    namespace: FencedOwnershipNamespace,
    clock: C,
    clock_state: Mutex<FencedOwnershipCacheClockState>,
    config: FencedOwnershipCacheConfig,
    state: RwLock<FencedOwnershipCacheState>,
    counters: FencedOwnershipCacheCounters,
}

impl<C> fmt::Debug for FencedOwnershipCache<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FencedOwnershipCache")
            .field("namespace", &self.namespace)
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl<C> FencedOwnershipCache<C>
where
    C: Clock,
{
    /// Create an empty fail-closed cache that must replay from sequence one.
    ///
    /// A caller resuming after sequence one must first install a caller-proven
    /// coherent snapshot through [`Self::seed`]. This prevents an empty cache
    /// from skipping older ownership records and later reporting a false
    /// fresh miss.
    pub fn new(
        namespace: FencedOwnershipNamespace,
        clock: C,
        config: FencedOwnershipCacheConfig,
    ) -> Result<Self, FencedOwnershipError> {
        let config = config.validate()?;
        let initial_clock_sample = clock.now_utc();
        Ok(Self {
            namespace,
            clock,
            clock_state: Mutex::new(FencedOwnershipCacheClockState {
                last_sample: initial_clock_sample,
                invalid: false,
            }),
            config,
            state: RwLock::new(FencedOwnershipCacheState {
                records: HashMap::new(),
                expirations: BTreeSet::new(),
                retained_bytes: 0,
                next_sequence: 1,
                last_sequence: None,
                last_observed: None,
                healthy: false,
                terminal: false,
                catch_up_through: None,
            }),
            counters: FencedOwnershipCacheCounters {
                hits: AtomicU64::new(0),
                misses: AtomicU64::new(0),
                stale: AtomicU64::new(0),
                feed_failures: AtomicU64::new(0),
            },
        })
    }

    /// Replace cache state from an explicitly caller-proven coherent seed.
    pub fn seed(&self, seed: FencedOwnershipCacheSeed) -> Result<(), FencedOwnershipError> {
        let FencedOwnershipCacheSeed {
            namespace,
            records,
            committed_through,
            proven_at,
            retained_bytes: _,
        } = seed;
        if namespace != self.namespace {
            return Err(FencedOwnershipError::InvalidRecord);
        }
        let mut staged = HashMap::new();
        let mut staged_expirations = BTreeSet::new();
        let mut seen = HashSet::new();
        let mut retained_bytes = 0usize;
        for record in records {
            if record.namespace != self.namespace {
                return Err(FencedOwnershipError::InvalidRecord);
            }
            if !seen.insert(record.key.clone()) {
                return Err(FencedOwnershipError::InvalidRecord);
            }
            retained_bytes = retained_bytes
                .checked_add(cache_record_retained_bytes(&record))
                .ok_or(FencedOwnershipError::CacheCapacityExceeded)?;
            let record = Arc::new(record);
            if !staged_expirations.insert(CacheExpiryEntry(Arc::clone(&record))) {
                return Err(FencedOwnershipError::InvalidRecord);
            }
            staged.insert(record.key.clone(), record);
        }
        let next_sequence = committed_through
            .checked_add(1)
            .ok_or(FencedOwnershipError::WatchGap)?;
        let mut state = self
            .state
            .write()
            .map_err(|_| FencedOwnershipError::BackendUnavailable)?;
        let now = match self.sample_cache_clock() {
            Ok(now) => now,
            Err(error) => {
                invalidate_state(&mut state);
                return Err(error);
            }
        };
        if elapsed(now, proven_at).is_none() {
            invalidate_state(&mut state);
            saturating_increment(&self.counters.feed_failures);
            return Err(FencedOwnershipError::InvalidRecord);
        }
        if let Err(error) = purge_expired_cache_parts(
            &mut staged,
            &mut staged_expirations,
            &mut retained_bytes,
            now,
        ) {
            invalidate_state(&mut state);
            saturating_increment(&self.counters.feed_failures);
            return Err(error);
        }
        if staged.len() > self.config.max_entries || retained_bytes > self.config.max_retained_bytes
        {
            return Err(FencedOwnershipError::CacheCapacityExceeded);
        }
        state.records = staged;
        state.expirations = staged_expirations;
        state.retained_bytes = retained_bytes;
        state.next_sequence = next_sequence;
        state.last_sequence = Some(committed_through);
        state.last_observed = Some(proven_at);
        state.healthy = true;
        state.terminal = false;
        state.catch_up_through = None;
        Ok(())
    }

    /// Begin a complete manual replay from sequence one through a proven head.
    ///
    /// [`Self::run_watch_until`] obtains this head from the backend itself.
    /// Callers driving [`Self::apply_entry`] directly must establish it first;
    /// applying a prefix without reaching the head never makes the view fresh.
    pub fn begin_full_replay(
        &self,
        head: FencedOwnershipCacheReplayHead,
    ) -> Result<(), FencedOwnershipError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| FencedOwnershipError::BackendUnavailable)?;
        let now = match self.sample_cache_clock() {
            Ok(now) => now,
            Err(error) => {
                invalidate_state(&mut state);
                return Err(error);
            }
        };
        if elapsed(now, head.proven_at()).is_none() {
            invalidate_state(&mut state);
            saturating_increment(&self.counters.feed_failures);
            return Err(FencedOwnershipError::InvalidRecord);
        }
        if state.healthy
            || state.next_sequence != 1
            || state.last_sequence.is_some()
            || !state.records.is_empty()
            || !state.expirations.is_empty()
            || state.retained_bytes != 0
        {
            return Err(FencedOwnershipError::InvalidRecord);
        }
        prepare_catch_up(&mut state, head.get(), head.proven_at())
    }

    /// Look up one key without I/O; stale state always fails closed.
    #[must_use]
    pub fn lookup(&self, key: &FencedOwnershipKey) -> FencedOwnershipCacheLookup {
        let Ok(state) = self.state.read() else {
            saturating_increment(&self.counters.stale);
            return FencedOwnershipCacheLookup::Stale;
        };
        let now = match self.sample_cache_clock() {
            Ok(now) => now,
            Err(_) => {
                drop(state);
                let _ = self.invalidate();
                saturating_increment(&self.counters.stale);
                return FencedOwnershipCacheLookup::Stale;
            }
        };
        let lag = state
            .last_observed
            .and_then(|observed| elapsed(now, observed));
        let fresh = state.healthy && lag.is_some_and(|lag| lag <= self.config.max_staleness);
        if !fresh {
            let impossible_future = state.last_observed.is_some() && lag.is_none();
            drop(state);
            if impossible_future {
                let _ = self.record_feed_failure();
            }
            saturating_increment(&self.counters.stale);
            return FencedOwnershipCacheLookup::Stale;
        }
        match state.records.get(key) {
            Some(record) if record.expires_at > now => {
                saturating_increment(&self.counters.hits);
                FencedOwnershipCacheLookup::Hit(Arc::clone(record))
            }
            Some(record) => {
                let expired = Arc::clone(record);
                drop(state);
                let _ = self.remove_expired_lookup(key, &expired);
                saturating_increment(&self.counters.misses);
                FencedOwnershipCacheLookup::Miss
            }
            None => {
                saturating_increment(&self.counters.misses);
                FencedOwnershipCacheLookup::Miss
            }
        }
    }

    /// Apply one exact committed application-journal item.
    ///
    /// A newly constructed cache remains stale unless
    /// [`Self::begin_full_replay`] established the committed head first.
    /// Seeded or already caught-up views apply later items incrementally.
    pub fn apply_entry(&self, entry: &ReplicationEntry) -> Result<(), FencedOwnershipError> {
        if entry.validate().is_err() {
            self.record_feed_failure()?;
            return Err(FencedOwnershipError::InvalidRecord);
        }
        let changes = match collect_cache_changes(&self.namespace, &entry.op) {
            Ok(changes) => changes,
            Err(error) => {
                self.record_feed_failure()?;
                return Err(error);
            }
        };
        let mut state = self
            .state
            .write()
            .map_err(|_| FencedOwnershipError::BackendUnavailable)?;
        let now = match self.sample_cache_clock() {
            Ok(now) => now,
            Err(error) => {
                invalidate_state(&mut state);
                return Err(error);
            }
        };
        if elapsed(now, entry.timestamp).is_none() {
            invalidate_state(&mut state);
            saturating_increment(&self.counters.feed_failures);
            return Err(FencedOwnershipError::InvalidRecord);
        }
        if state.terminal || entry.sequence != state.next_sequence {
            invalidate_state(&mut state);
            saturating_increment(&self.counters.feed_failures);
            return Err(FencedOwnershipError::WatchGap);
        }
        if !state.healthy && state.catch_up_through.is_none() {
            invalidate_state(&mut state);
            saturating_increment(&self.counters.feed_failures);
            return Err(FencedOwnershipError::InvalidRecord);
        }
        if let Err(error) = purge_expired_records(&mut state, now) {
            invalidate_state(&mut state);
            saturating_increment(&self.counters.feed_failures);
            return Err(error);
        }
        let staged = (|| {
            let mut overlay =
                HashMap::<FencedOwnershipKey, Option<Arc<FencedOwnershipRecord>>>::new();
            let mut projected_entries = state.records.len();
            let mut projected_bytes = state.retained_bytes;
            for change in changes {
                let (key, replacement) = match change {
                    CacheChange::Remove(key) => (key, None),
                    CacheChange::Upsert(record) if record.expires_at <= now => {
                        (record.key.clone(), None)
                    }
                    CacheChange::Upsert(record) => (record.key.clone(), Some(Arc::new(record))),
                };
                let (previous_exists, previous_bytes) = match overlay.get(&key) {
                    Some(Some(previous)) => (true, cache_record_retained_bytes(previous)),
                    Some(None) => (false, 0),
                    None => match state.records.get(&key) {
                        Some(previous) => (true, cache_record_retained_bytes(previous)),
                        None => (false, 0),
                    },
                };
                projected_bytes = projected_bytes
                    .checked_sub(previous_bytes)
                    .ok_or(FencedOwnershipError::InvalidRecord)?;
                match replacement.as_ref() {
                    Some(record) => {
                        if !previous_exists {
                            projected_entries = projected_entries
                                .checked_add(1)
                                .ok_or(FencedOwnershipError::CacheCapacityExceeded)?;
                        }
                        projected_bytes = projected_bytes
                            .checked_add(cache_record_retained_bytes(record))
                            .ok_or(FencedOwnershipError::CacheCapacityExceeded)?;
                    }
                    None if previous_exists => {
                        projected_entries = projected_entries
                            .checked_sub(1)
                            .ok_or(FencedOwnershipError::InvalidRecord)?;
                    }
                    None => {}
                }
                if projected_entries > self.config.max_entries
                    || projected_bytes > self.config.max_retained_bytes
                {
                    return Err(FencedOwnershipError::CacheCapacityExceeded);
                }
                overlay.insert(key, replacement);
            }
            Ok((overlay, projected_bytes))
        })();
        let (staged, retained_bytes) = match staged {
            Ok(staged) => staged,
            Err(error) => {
                invalidate_state(&mut state);
                saturating_increment(&self.counters.feed_failures);
                return Err(error);
            }
        };
        if staged.keys().any(|key| {
            state.records.get(key).is_some_and(|record| {
                !state
                    .expirations
                    .contains(&CacheExpiryEntry(Arc::clone(record)))
            })
        }) {
            invalidate_state(&mut state);
            saturating_increment(&self.counters.feed_failures);
            return Err(FencedOwnershipError::InvalidRecord);
        }
        for (key, replacement) in staged {
            if let Some(previous) = state.records.remove(&key) {
                if !state
                    .expirations
                    .remove(&CacheExpiryEntry(Arc::clone(&previous)))
                {
                    invalidate_state(&mut state);
                    saturating_increment(&self.counters.feed_failures);
                    return Err(FencedOwnershipError::InvalidRecord);
                }
            }
            if let Some(record) = replacement {
                if !state
                    .expirations
                    .insert(CacheExpiryEntry(Arc::clone(&record)))
                {
                    invalidate_state(&mut state);
                    saturating_increment(&self.counters.feed_failures);
                    return Err(FencedOwnershipError::InvalidRecord);
                }
                state.records.insert(key, record);
            }
        }
        state.retained_bytes = retained_bytes;
        state.last_sequence = Some(entry.sequence);
        match state.catch_up_through {
            Some(target) if entry.sequence >= target => {
                state.catch_up_through = None;
                state.last_observed = Some(entry.timestamp);
                state.healthy = true;
            }
            Some(_) => {}
            None if state.healthy => state.last_observed = Some(entry.timestamp),
            None => {}
        }
        match entry.sequence.checked_add(1) {
            Some(next) => state.next_sequence = next,
            None => state.terminal = true,
        }
        Ok(())
    }

    /// Consume the committed backend watch until explicit shutdown.
    ///
    /// The method owns no detached task. Dropping its future drops the backend
    /// watch; explicit shutdown marks the cache stale before returning.
    pub async fn run_watch_until<B, F>(
        &self,
        backend: &B,
        shutdown: F,
    ) -> Result<FencedOwnershipWatchExit, FencedOwnershipError>
    where
        B: SessionBackend,
        F: Future<Output = ()> + Send,
    {
        if !FencedOwnershipCapabilities::from_backend(backend.capabilities().await)
            .committed_watch_cache
        {
            self.feed_failed()?;
            return Err(FencedOwnershipError::CapabilityNotSupported);
        }
        let start = self.next_sequence()?;
        let caught_up_through = match backend.max_replication_sequence().await {
            Ok(head) => head,
            Err(error) => {
                self.feed_failed()?;
                return Err(map_watch_error(error));
            }
        };
        let caught_up_at = self.cache_now()?;
        let mut watch = match backend.watch(start).await {
            Ok(watch) => watch,
            Err(error) => {
                self.feed_failed()?;
                return Err(map_watch_error(error));
            }
        };
        self.prepare_watch_catch_up(caught_up_through, caught_up_at)?;
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                () = &mut shutdown => {
                    self.invalidate()?;
                    return Ok(FencedOwnershipWatchExit::Cancelled);
                }
                item = watch.next() => match item {
                    Some(Ok(entry)) => self.apply_entry(&entry)?,
                    Some(Err(error)) => {
                        self.feed_failed()?;
                        return Err(map_watch_error(error));
                    }
                    None => {
                        self.feed_failed()?;
                        return Err(FencedOwnershipError::WatchEnded);
                    }
                }
            }
        }
    }

    /// Return a redaction-safe metrics snapshot.
    #[must_use]
    pub fn metrics(&self) -> FencedOwnershipCacheMetricsSnapshot {
        let Ok(state) = self.state.read() else {
            return FencedOwnershipCacheMetricsSnapshot {
                hits: self.counters.hits.load(Ordering::Relaxed),
                misses: self.counters.misses.load(Ordering::Relaxed),
                stale: self.counters.stale.load(Ordering::Relaxed),
                feed_failures: self.counters.feed_failures.load(Ordering::Relaxed),
                entries: 0,
                retained_bytes: 0,
                last_sequence: None,
                cache_lag: None,
            };
        };
        let now = match self.sample_cache_clock() {
            Ok(now) => now,
            Err(_) => {
                drop(state);
                let _ = self.invalidate();
                return FencedOwnershipCacheMetricsSnapshot {
                    hits: self.counters.hits.load(Ordering::Relaxed),
                    misses: self.counters.misses.load(Ordering::Relaxed),
                    stale: self.counters.stale.load(Ordering::Relaxed),
                    feed_failures: self.counters.feed_failures.load(Ordering::Relaxed),
                    entries: 0,
                    retained_bytes: 0,
                    last_sequence: None,
                    cache_lag: None,
                };
            }
        };
        FencedOwnershipCacheMetricsSnapshot {
            hits: self.counters.hits.load(Ordering::Relaxed),
            misses: self.counters.misses.load(Ordering::Relaxed),
            stale: self.counters.stale.load(Ordering::Relaxed),
            feed_failures: self.counters.feed_failures.load(Ordering::Relaxed),
            entries: state.records.len(),
            retained_bytes: state.retained_bytes,
            last_sequence: state.last_sequence,
            cache_lag: state
                .last_observed
                .and_then(|observed| elapsed(now, observed)),
        }
    }

    fn sample_cache_clock(&self) -> Result<Timestamp, FencedOwnershipError> {
        let mut state = self
            .clock_state
            .lock()
            .map_err(|_| FencedOwnershipError::BackendUnavailable)?;
        if state.invalid {
            return Err(FencedOwnershipError::InvalidRecord);
        }
        let now = self.clock.now_utc();
        if now < state.last_sample {
            state.invalid = true;
            saturating_increment(&self.counters.feed_failures);
            Err(FencedOwnershipError::InvalidRecord)
        } else {
            state.last_sample = now;
            Ok(now)
        }
    }

    fn cache_now(&self) -> Result<Timestamp, FencedOwnershipError> {
        match self.sample_cache_clock() {
            Ok(now) => Ok(now),
            Err(error) => {
                self.invalidate()?;
                Err(error)
            }
        }
    }

    fn remove_expired_lookup(
        &self,
        key: &FencedOwnershipKey,
        expected: &Arc<FencedOwnershipRecord>,
    ) -> Result<(), FencedOwnershipError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| FencedOwnershipError::BackendUnavailable)?;
        let now = match self.sample_cache_clock() {
            Ok(now) => now,
            Err(error) => {
                invalidate_state(&mut state);
                return Err(error);
            }
        };
        let current = state.records.get(key).and_then(|record| {
            (Arc::ptr_eq(record, expected) && record.expires_at <= now).then(|| Arc::clone(record))
        });
        let Some(current) = current else {
            return Ok(());
        };
        if !state
            .expirations
            .remove(&CacheExpiryEntry(Arc::clone(&current)))
        {
            invalidate_state(&mut state);
            saturating_increment(&self.counters.feed_failures);
            return Err(FencedOwnershipError::InvalidRecord);
        }
        state.records.remove(key);
        let Some(retained_bytes) = state
            .retained_bytes
            .checked_sub(cache_record_retained_bytes(&current))
        else {
            invalidate_state(&mut state);
            saturating_increment(&self.counters.feed_failures);
            return Err(FencedOwnershipError::InvalidRecord);
        };
        state.retained_bytes = retained_bytes;
        Ok(())
    }

    fn next_sequence(&self) -> Result<u64, FencedOwnershipError> {
        self.state
            .read()
            .map(|state| state.next_sequence)
            .map_err(|_| FencedOwnershipError::BackendUnavailable)
    }

    fn prepare_watch_catch_up(
        &self,
        committed_through: u64,
        proven_at: Timestamp,
    ) -> Result<(), FencedOwnershipError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| FencedOwnershipError::BackendUnavailable)?;
        let now = match self.sample_cache_clock() {
            Ok(now) => now,
            Err(error) => {
                invalidate_state(&mut state);
                return Err(error);
            }
        };
        if elapsed(now, proven_at).is_none() {
            invalidate_state(&mut state);
            saturating_increment(&self.counters.feed_failures);
            return Err(FencedOwnershipError::InvalidRecord);
        }
        let initial = state.next_sequence == 1
            && state.last_sequence.is_none()
            && state.records.is_empty()
            && state.expirations.is_empty()
            && state.retained_bytes == 0;
        if !state.healthy && state.catch_up_through.is_none() && !initial {
            invalidate_state(&mut state);
            saturating_increment(&self.counters.feed_failures);
            return Err(FencedOwnershipError::InvalidRecord);
        }
        if let Err(error) = prepare_catch_up(&mut state, committed_through, proven_at) {
            invalidate_state(&mut state);
            saturating_increment(&self.counters.feed_failures);
            return Err(error);
        }
        Ok(())
    }

    fn invalidate(&self) -> Result<(), FencedOwnershipError> {
        let mut state = self
            .state
            .write()
            .map_err(|_| FencedOwnershipError::BackendUnavailable)?;
        invalidate_state(&mut state);
        Ok(())
    }

    fn feed_failed(&self) -> Result<(), FencedOwnershipError> {
        self.record_feed_failure()
    }

    fn record_feed_failure(&self) -> Result<(), FencedOwnershipError> {
        self.invalidate()?;
        saturating_increment(&self.counters.feed_failures);
        Ok(())
    }
}

/// Normal completion reason for a bounded watch consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FencedOwnershipWatchExit {
    /// The caller's explicit shutdown future completed.
    Cancelled,
}

enum CacheChange {
    Remove(FencedOwnershipKey),
    Upsert(FencedOwnershipRecord),
}

fn collect_cache_changes(
    namespace: &FencedOwnershipNamespace,
    root: &ReplicationOp,
) -> Result<Vec<CacheChange>, FencedOwnershipError> {
    root.validate_structure()
        .map_err(|_| FencedOwnershipError::InvalidRecord)?;
    let mut pending = vec![root];
    let mut changes = Vec::new();
    while let Some(op) = pending.pop() {
        match op {
            ReplicationOp::CompareAndSet {
                key, new_record, ..
            } if namespace.owns_session_key(key) => {
                if &new_record.key != key {
                    return Err(FencedOwnershipError::InvalidRecord);
                }
                changes.push(CacheChange::Upsert(
                    decode_record(namespace, new_record)?.public,
                ));
            }
            ReplicationOp::DeleteFenced { key, .. } if namespace.owns_session_key(key) => {
                changes.push(CacheChange::Remove(namespace.opaque_key(key)?));
            }
            ReplicationOp::Batch { ops } => pending.extend(ops.iter().rev()),
            ReplicationOp::CompareAndSet { .. }
            | ReplicationOp::DeleteFenced { .. }
            | ReplicationOp::RefreshTtl { .. }
            | ReplicationOp::AcquireLease { .. }
            | ReplicationOp::RenewLease { .. }
            | ReplicationOp::ReleaseLease { .. } => {}
        }
    }
    Ok(changes)
}

fn purge_expired_records(
    state: &mut FencedOwnershipCacheState,
    now: Timestamp,
) -> Result<(), FencedOwnershipError> {
    purge_expired_cache_parts(
        &mut state.records,
        &mut state.expirations,
        &mut state.retained_bytes,
        now,
    )
}

fn purge_expired_cache_parts(
    records: &mut HashMap<FencedOwnershipKey, Arc<FencedOwnershipRecord>>,
    expirations: &mut BTreeSet<CacheExpiryEntry>,
    retained_bytes: &mut usize,
    now: Timestamp,
) -> Result<(), FencedOwnershipError> {
    loop {
        let Some(expired) = expirations.first().cloned() else {
            return Ok(());
        };
        if expired.0.expires_at > now {
            return Ok(());
        }
        let key = expired.0.key.clone();
        let Some(current) = records.get(&key).cloned() else {
            return Err(FencedOwnershipError::InvalidRecord);
        };
        if !Arc::ptr_eq(&current, &expired.0) || !expirations.remove(&expired) {
            return Err(FencedOwnershipError::InvalidRecord);
        }
        records.remove(&key);
        *retained_bytes = retained_bytes
            .checked_sub(cache_record_retained_bytes(&current))
            .ok_or(FencedOwnershipError::InvalidRecord)?;
    }
}

fn invalidate_state(state: &mut FencedOwnershipCacheState) {
    state.records.clear();
    state.expirations.clear();
    state.retained_bytes = 0;
    state.next_sequence = 1;
    state.last_sequence = None;
    state.last_observed = None;
    state.healthy = false;
    state.terminal = false;
    state.catch_up_through = None;
}

fn prepare_catch_up(
    state: &mut FencedOwnershipCacheState,
    committed_through: u64,
    observed_at: Timestamp,
) -> Result<(), FencedOwnershipError> {
    let last_sequence = state.last_sequence.unwrap_or(0);
    if committed_through < last_sequence
        || state
            .catch_up_through
            .is_some_and(|previous| committed_through < previous)
    {
        return Err(FencedOwnershipError::WatchGap);
    }
    if committed_through == last_sequence {
        state.last_sequence = Some(committed_through);
        state.last_observed = Some(observed_at);
        state.healthy = true;
        state.catch_up_through = None;
    } else {
        state.catch_up_through = Some(committed_through);
    }
    Ok(())
}

fn cache_record_retained_bytes(record: &FencedOwnershipRecord) -> usize {
    OWNERSHIP_RECORD_FIXED_BYTES
        + record.namespace.tenant.as_str().len()
        + record.namespace.nf_kind.as_str().len()
        + record.key.as_bytes().len()
        + record.owner.as_str().len()
        + record.metadata.as_bytes().len()
}

fn elapsed(now: Timestamp, observed: Timestamp) -> Option<Duration> {
    let nanoseconds =
        (*now.as_offset_datetime() - *observed.as_offset_datetime()).whole_nanoseconds();
    let nanoseconds = u128::try_from(nanoseconds).ok()?;
    let seconds = u64::try_from(nanoseconds / 1_000_000_000).ok()?;
    let subsecond = u32::try_from(nanoseconds % 1_000_000_000).ok()?;
    Some(Duration::new(seconds, subsecond))
}

fn saturating_increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_add(1))
    });
}
