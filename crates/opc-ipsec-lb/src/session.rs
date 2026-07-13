//! Session-store backed ownership reads and fenced owner promotion.

use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, LeaseError, LeaseGuard, OwnerId,
    SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager, SessionPayloadEncoding,
    StateClass, StoreError, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId};

use crate::error::IpsecLbError;
use crate::model::{ClusterNode, SaId, ShardId};
use crate::ports::{OwnershipFencer, OwnershipSource};
use crate::repin::{
    validate_sa_identifier, OwnershipFence, OwnershipFenceGrant, OwnershipFenceRequest,
    OwnershipRetryProof, OwnershipSnapshot, OwnershipTransitionFingerprint, OwnershipTransitionId,
};

const OWNERSHIP_KEY_TYPE: &str = "ipsec-lb-ownership";
const SHARD_KEY_PREFIX: &[u8] = b"opc-ipsec-lb/shard/";
const IKE_SA_KEY_PREFIX: &[u8] = b"opc-ipsec-lb/sa/ike/";
const ESP_SA_KEY_PREFIX: &[u8] = b"opc-ipsec-lb/sa/esp/";
const OWNERSHIP_TRANSITION_PAYLOAD_PREFIX: &[u8] = b"opc-ipsec-lb/transition/v1:";
/// The lease only needs to cover one fenced owner-promotion CAS. A failed
/// writer must not prevent another promotion indefinitely.
const OWNERSHIP_FENCE_LEASE_TTL: Duration = Duration::from_secs(10);
/// Bound detached best-effort cleanup so a broken backend cannot leak one
/// task and backend reference per successful promotion indefinitely.
const OWNERSHIP_RELEASE_TIMEOUT: Duration = Duration::from_secs(1);

fn release_lease_bounded<B>(backend: Arc<B>, lease: LeaseGuard)
where
    B: SessionLeaseManager + 'static,
{
    // Lease release is a liveness optimization; expiry remains the fallback.
    // Detach it so no post-CAS await can hide a grant, and bound the task so a
    // broken backend cannot leak one task/reference per attempt indefinitely.
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        drop(runtime.spawn(async move {
            let _release_result =
                tokio::time::timeout(OWNERSHIP_RELEASE_TIMEOUT, backend.release(lease)).await;
        }));
    }
}

struct LeaseCleanup<B>
where
    B: SessionLeaseManager + 'static,
{
    backend: Arc<B>,
    lease: Option<LeaseGuard>,
}

impl<B> LeaseCleanup<B>
where
    B: SessionLeaseManager + 'static,
{
    fn new(backend: Arc<B>, lease: LeaseGuard) -> Self {
        Self {
            backend,
            lease: Some(lease),
        }
    }

    fn guard(&self) -> Option<&LeaseGuard> {
        self.lease.as_ref()
    }
}

impl<B> Drop for LeaseCleanup<B>
where
    B: SessionLeaseManager + 'static,
{
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            release_lease_bounded(Arc::clone(&self.backend), lease);
        }
    }
}

async fn acquire_lease_cleanup<B>(
    backend: Arc<B>,
    key: SessionKey,
    owner: OwnerId,
    ttl: Duration,
) -> Result<LeaseCleanup<B>, IpsecLbError>
where
    B: SessionLeaseManager + 'static,
{
    let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
        IpsecLbError::invalid_config(
            "session_store.runtime",
            "ownership fencing requires a Tokio runtime",
        )
    })?;
    let acquisition_backend = Arc::clone(&backend);

    // Run acquisition to completion independently of the caller future. If
    // the caller is cancelled after the backend applies the lease but before
    // it returns the guard, the detached task still receives that guard and
    // `LeaseCleanup` releases it. Dropping the JoinHandle detaches rather than
    // aborts the task, so lease TTL is only the final fallback for a backend
    // whose acquire future itself never completes.
    runtime
        .spawn(async move {
            let lease = tokio::time::timeout(ttl, acquisition_backend.acquire(&key, owner, ttl))
                .await
                .map_err(|_| {
                    IpsecLbError::io(
                        "session_store_ownership_lease",
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            "session store lease acquisition timed out",
                        ),
                    )
                })?
                .map_err(map_lease_error)?;
            Ok(LeaseCleanup::new(acquisition_backend, lease))
        })
        .await
        .map_err(|_| {
            IpsecLbError::io(
                "session_store_ownership_lease",
                io::Error::other("session store lease acquisition task failed"),
            )
        })?
}

/// Resolves LB ownership lookups to session-store keys.
pub trait SessionOwnershipKeyResolver: Send + Sync + fmt::Debug {
    /// Return the session-store key for a shard owner.
    fn shard_key(&self, shard: ShardId) -> Result<SessionKey, IpsecLbError>;

    /// Return the session-store key for an SA owner.
    fn sa_key(&self, sa: SaId) -> Result<SessionKey, IpsecLbError>;
}

/// Deterministic default keyspace for IPsec LB ownership records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOwnershipKeyspace {
    tenant: TenantId,
    nf_kind: NetworkFunctionKind,
}

impl SessionOwnershipKeyspace {
    /// Build a keyspace scoped to one tenant and NF kind.
    #[must_use]
    pub const fn new(tenant: TenantId, nf_kind: NetworkFunctionKind) -> Self {
        Self { tenant, nf_kind }
    }

    fn key(&self, stable_id: Vec<u8>) -> Result<SessionKey, IpsecLbError> {
        let stable_id = opc_session_store::StableId::new(Bytes::from(stable_id)).map_err(|_| {
            IpsecLbError::InvalidConfig {
                field: "session_store_stable_id",
                reason: "ownership key exceeds the session-store production profile",
            }
        })?;
        Ok(SessionKey {
            tenant: self.tenant.clone(),
            nf_kind: self.nf_kind.clone(),
            key_type: SessionKeyType::other(OWNERSHIP_KEY_TYPE).expect("static ownership key type"),
            stable_id,
        })
    }
}

impl SessionOwnershipKeyResolver for SessionOwnershipKeyspace {
    fn shard_key(&self, shard: ShardId) -> Result<SessionKey, IpsecLbError> {
        let mut stable_id = Vec::with_capacity(SHARD_KEY_PREFIX.len() + 2);
        stable_id.extend_from_slice(SHARD_KEY_PREFIX);
        stable_id.extend_from_slice(&shard.get().to_be_bytes());
        self.key(stable_id)
    }

    fn sa_key(&self, sa: SaId) -> Result<SessionKey, IpsecLbError> {
        validate_sa_identifier(sa)?;
        let mut stable_id = Vec::new();
        match sa {
            SaId::Ike { responder_spi } => {
                stable_id.reserve(IKE_SA_KEY_PREFIX.len() + 8);
                stable_id.extend_from_slice(IKE_SA_KEY_PREFIX);
                stable_id.extend_from_slice(&responder_spi.to_be_bytes());
            }
            SaId::Esp { spi } => {
                stable_id.reserve(ESP_SA_KEY_PREFIX.len() + 4);
                stable_id.extend_from_slice(ESP_SA_KEY_PREFIX);
                stable_id.extend_from_slice(&spi.to_be_bytes());
            }
        }
        self.key(stable_id)
    }
}

/// Ownership source backed by `opc-session-store` record metadata.
///
/// SA reads project the authoritative store owner and its exact non-zero fence
/// into [`OwnershipSnapshot`], so callers can bind a new transition to the
/// predecessor state they actually observed.
#[derive(Clone)]
pub struct SessionStoreOwnershipSource<B, R = SessionOwnershipKeyspace> {
    backend: B,
    resolver: R,
}

impl<B, R> fmt::Debug for SessionStoreOwnershipSource<B, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionStoreOwnershipSource")
            .finish_non_exhaustive()
    }
}

impl<B, R> SessionStoreOwnershipSource<B, R>
where
    B: SessionBackend,
    R: SessionOwnershipKeyResolver,
{
    /// Build a session-store ownership source from explicit backend and key resolver.
    #[must_use]
    pub const fn new(backend: B, resolver: R) -> Self {
        Self { backend, resolver }
    }

    async fn ownership_for_key(
        &self,
        key: SessionKey,
    ) -> Result<Option<OwnershipSnapshot>, IpsecLbError> {
        let Some(record) = self.backend.get(&key).await.map_err(map_store_error)? else {
            return Ok(None);
        };
        validate_ownership_record(&record, &key)?;
        Ok(Some(OwnershipSnapshot::new(
            ClusterNode::new(record.owner.as_str()),
            OwnershipFence::new(record.fence.get())?,
        )))
    }
}

#[async_trait]
impl<B, R> OwnershipSource for SessionStoreOwnershipSource<B, R>
where
    B: SessionBackend,
    R: SessionOwnershipKeyResolver,
{
    async fn shard_owner(&self, shard: ShardId) -> Result<Option<ClusterNode>, IpsecLbError> {
        let key = self.resolver.shard_key(shard)?;
        Ok(self
            .ownership_for_key(key)
            .await?
            .map(|snapshot| snapshot.owner().clone()))
    }

    async fn sa_ownership(&self, sa: SaId) -> Result<Option<OwnershipSnapshot>, IpsecLbError> {
        let key = self.resolver.sa_key(sa)?;
        self.ownership_for_key(key).await
    }
}

/// Write-side ownership fencer backed by `opc-session-store` lease and CAS
/// authority.
///
/// The fence returned by this adapter is a projection of the store-minted
/// [`opc_session_store::FenceToken`] committed in the ownership record. It
/// never uses a process-local counter. Consequently a grant can only escape
/// after the authoritative store has committed the new owner and fence.
///
/// # Production HA requirement
///
/// Production failover wiring must use
/// [`opc_session_store::QuorumSessionStore`] or an equivalent backend whose
/// successful lease and compare-and-set operations mean majority commitment.
/// A single-process fake or single-node SQLite backend is suitable for tests
/// and non-HA deployments, but cannot establish split-brain safety by itself.
/// This adapter also requires an active Tokio runtime for its bounded detached
/// lease-acquisition and cleanup tasks; it fails closed during promotion when
/// no Tokio runtime is available.
///
/// # Record prerequisite
///
/// [`OwnershipFencer::fence_sa_owner`] promotes an existing, metadata-only SA
/// ownership record. The SA birth path must first create that authoritative
/// record under the same [`SessionOwnershipKeyResolver`]. Promotion is not an
/// upsert: a missing record fails closed with [`IpsecLbError::NotFound`].
/// [`OwnershipFencer::recover_fence_grant`] is the cancellation-safe read path:
/// it projects the exact committed store fence only when the requested new
/// owner, transition ID, and full request fingerprint match the record, and it
/// never performs a second promotion. Lease acquisition continues in a
/// bounded detached task if its caller is cancelled; an acknowledged guard is
/// released, while an acquire future that never completes is dropped at the
/// lease TTL.
#[derive(Clone)]
pub struct SessionStoreOwnershipFencer<B, R = SessionOwnershipKeyspace> {
    backend: Arc<B>,
    resolver: R,
    lease_ttl: Duration,
}

impl<B, R> fmt::Debug for SessionStoreOwnershipFencer<B, R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionStoreOwnershipFencer")
            .field("lease_ttl", &self.lease_ttl)
            .finish_non_exhaustive()
    }
}

impl<B, R> SessionStoreOwnershipFencer<B, R>
where
    B: SessionBackend + SessionLeaseManager + 'static,
    R: SessionOwnershipKeyResolver,
{
    /// Build an ownership fencer from a store backend and the key resolver
    /// shared with [`SessionStoreOwnershipSource`].
    #[must_use]
    pub fn new(backend: B, resolver: R) -> Self {
        Self {
            backend: Arc::new(backend),
            resolver,
            lease_ttl: OWNERSHIP_FENCE_LEASE_TTL,
        }
    }

    async fn recover(
        &self,
        request: &OwnershipFenceRequest,
    ) -> Result<Option<OwnershipFenceGrant>, IpsecLbError> {
        validate_sa_identifier(request.sa)?;
        if request.previous_owner == request.new_owner {
            return Err(IpsecLbError::ownership_conflict(
                "ownership recovery requires distinct owners",
            ));
        }

        let key = self.resolver.sa_key(request.sa)?;
        let Some(current) = self.backend.get(&key).await.map_err(map_store_error)? else {
            return Err(IpsecLbError::NotFound);
        };
        let committed_transition = validate_ownership_record(&current, &key)?;

        if current.owner.as_str() == request.previous_owner.as_str() {
            return if current.fence.get() == request.previous_fence.get() {
                Ok(None)
            } else {
                Err(IpsecLbError::ownership_conflict(
                    "expected previous owner holds a different authoritative fence",
                ))
            };
        }
        if current.owner.as_str() != request.new_owner.as_str() {
            return Err(IpsecLbError::ownership_conflict(
                "neither requested owner holds the authoritative SA record",
            ));
        }
        if committed_transition != Some((request.transition_id, request.fingerprint)) {
            return Err(IpsecLbError::ownership_conflict(
                "current owner was committed by a different ownership transition",
            ));
        }

        Ok(Some(OwnershipFenceGrant {
            sa: request.sa,
            transition_id: request.transition_id,
            fingerprint: request.fingerprint,
            owner: request.new_owner.clone(),
            fence: OwnershipFence::new(current.fence.get())?,
        }))
    }

    async fn promote(
        &self,
        request: OwnershipFenceRequest,
    ) -> Result<OwnershipFenceGrant, IpsecLbError> {
        validate_sa_identifier(request.sa)?;
        if request.previous_owner == request.new_owner {
            return Err(IpsecLbError::ownership_conflict(
                "ownership promotion requires distinct owners",
            ));
        }
        let key = self.resolver.sa_key(request.sa)?;
        let Some(current) = self.backend.get(&key).await.map_err(map_store_error)? else {
            return Err(IpsecLbError::NotFound);
        };
        validate_ownership_record(&current, &key)?;

        if current.owner.as_str() != request.previous_owner.as_str() {
            return Err(IpsecLbError::ownership_conflict(
                "expected previous owner does not hold the SA",
            ));
        }
        if current.fence.get() != request.previous_fence.get() {
            return Err(IpsecLbError::ownership_conflict(
                "expected previous owner holds a different authoritative fence",
            ));
        }

        let next_generation = current.generation.next().ok_or_else(|| {
            IpsecLbError::invalid_config(
                "session_store.generation",
                "ownership record generation exhausted",
            )
        })?;
        let new_owner = OwnerId::new(request.new_owner.as_str()).map_err(|_| {
            IpsecLbError::invalid_config("session_store.owner", "ownership record owner is invalid")
        })?;
        let lease = acquire_lease_cleanup(
            Arc::clone(&self.backend),
            key.clone(),
            new_owner.clone(),
            self.lease_ttl,
        )
        .await?;
        let committed_fence = lease.guard().map(LeaseGuard::fence).ok_or_else(|| {
            IpsecLbError::invalid_config(
                "session_store.lease",
                "ownership lease cleanup guard is unavailable",
            )
        })?;

        // A conforming lease manager mints a strictly higher token on every
        // acquisition. Check the boundary explicitly so an incorrectly wired
        // backend fails closed instead of publishing a non-advancing fence.
        if committed_fence <= current.fence {
            return Err(IpsecLbError::invalid_config(
                "session_store.fence",
                "ownership lease fence did not advance",
            ));
        }

        let record = StoredSessionRecord {
            key: key.clone(),
            generation: next_generation,
            owner: new_owner,
            fence: committed_fence,
            state_class: StateClass::AuthoritativeSession,
            state_type: current.state_type,
            expires_at: None,
            payload: encode_ownership_transition(request.transition_id, request.fingerprint),
        };
        // Build every fallible projection before the commit. After a successful
        // CAS there must be no await or fallible operation before this grant is
        // returned to the coordinator.
        let fence = match OwnershipFence::new(committed_fence.get()) {
            Ok(fence) => fence,
            Err(error) => return Err(error),
        };
        let grant = OwnershipFenceGrant {
            sa: request.sa,
            transition_id: request.transition_id,
            fingerprint: request.fingerprint,
            owner: request.new_owner,
            fence,
        };
        let cas_lease = lease.guard().cloned().ok_or_else(|| {
            IpsecLbError::invalid_config(
                "session_store.lease",
                "ownership lease cleanup guard is unavailable",
            )
        })?;
        let commit_result = tokio::time::timeout(
            self.lease_ttl,
            self.backend.compare_and_set(CompareAndSet {
                key,
                lease: cas_lease,
                expected_generation: Some(current.generation),
                new_record: record,
            }),
        )
        .await;

        match commit_result {
            Ok(Ok(CompareAndSetResult::Success)) => Ok(grant),
            Ok(Ok(CompareAndSetResult::Conflict { .. })) => Err(IpsecLbError::ownership_conflict(
                "ownership record changed during promotion",
            )),
            Ok(Err(error)) => {
                let mapped = map_store_error(error);
                // A backend error can be commit-ambiguous. Do not place a
                // cleanup await between that result and caller-side recovery.
                Err(mapped)
            }
            Err(_) => Err(IpsecLbError::io(
                "session_store_ownership_cas",
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "session store ownership commit acknowledgement timed out",
                ),
            )),
        }
    }
}

#[async_trait]
impl<B, R> OwnershipFencer for SessionStoreOwnershipFencer<B, R>
where
    B: SessionBackend + SessionLeaseManager + 'static,
    R: SessionOwnershipKeyResolver,
{
    async fn recover_fence_grant(
        &self,
        request: &OwnershipFenceRequest,
    ) -> Result<Option<OwnershipFenceGrant>, IpsecLbError> {
        self.recover(request).await
    }

    async fn fence_sa_owner(
        &self,
        request: OwnershipFenceRequest,
    ) -> Result<OwnershipFenceGrant, IpsecLbError> {
        self.promote(request).await
    }

    async fn validate_retry_proof(&self, proof: &OwnershipRetryProof) -> Result<(), IpsecLbError> {
        validate_sa_identifier(proof.sa())?;
        let key = self.resolver.sa_key(proof.sa())?;
        let Some(current) = self.backend.get(&key).await.map_err(map_store_error)? else {
            return Err(IpsecLbError::NotFound);
        };
        let committed_transition = validate_ownership_record(&current, &key)?;

        if current.owner.as_str() != proof.owner().as_str()
            || current.fence.get() != proof.fence().get()
            || committed_transition != Some((proof.transition_id(), proof.fingerprint()))
        {
            return Err(IpsecLbError::ownership_conflict(
                "retry proof does not match the authoritative owner and fence",
            ));
        }
        Ok(())
    }
}

fn validate_ownership_record(
    record: &StoredSessionRecord,
    expected_key: &SessionKey,
) -> Result<Option<(OwnershipTransitionId, OwnershipTransitionFingerprint)>, IpsecLbError> {
    if &record.key != expected_key {
        return Err(IpsecLbError::invalid_config(
            "session_store.key",
            "ownership record key mismatch",
        ));
    }
    if record.state_class != StateClass::AuthoritativeSession {
        return Err(IpsecLbError::invalid_config(
            "session_store.state_class",
            "ownership records must be authoritative-session state",
        ));
    }
    if record.key.key_type.as_str() != OWNERSHIP_KEY_TYPE {
        return Err(IpsecLbError::invalid_config(
            "session_store.key_type",
            "ownership record key type mismatch",
        ));
    }
    if record.state_type.as_str() != OWNERSHIP_KEY_TYPE {
        return Err(IpsecLbError::invalid_config(
            "session_store.state_type",
            "ownership record state type mismatch",
        ));
    }
    if record.fence.get() == 0 {
        return Err(IpsecLbError::invalid_config(
            "session_store.fence",
            "ownership record fence must be non-zero",
        ));
    }
    if record.expires_at.is_some() {
        return Err(IpsecLbError::invalid_config(
            "session_store.expires_at",
            "ownership records must not expire",
        ));
    }
    if record.payload.encoding() != SessionPayloadEncoding::Plaintext {
        return Err(IpsecLbError::invalid_config(
            "session_store.payload",
            "ownership records must have a caller-facing plaintext metadata payload",
        ));
    }
    OwnerId::new(record.owner.as_str()).map_err(|_| {
        IpsecLbError::invalid_config("session_store.owner", "ownership record owner is invalid")
    })?;
    decode_ownership_transition(&record.payload)
}

fn encode_ownership_transition(
    transition_id: OwnershipTransitionId,
    fingerprint: OwnershipTransitionFingerprint,
) -> EncryptedSessionPayload {
    let mut payload = Vec::with_capacity(OWNERSHIP_TRANSITION_PAYLOAD_PREFIX.len() + 16 + 32);
    payload.extend_from_slice(OWNERSHIP_TRANSITION_PAYLOAD_PREFIX);
    payload.extend_from_slice(&transition_id.get().to_be_bytes());
    payload.extend_from_slice(&fingerprint.as_bytes());
    EncryptedSessionPayload::new(payload)
}

fn decode_ownership_transition(
    payload: &EncryptedSessionPayload,
) -> Result<Option<(OwnershipTransitionId, OwnershipTransitionFingerprint)>, IpsecLbError> {
    let bytes = payload.as_bytes();
    if bytes.is_empty() {
        return Ok(None);
    }
    let Some(raw_id) = bytes.strip_prefix(OWNERSHIP_TRANSITION_PAYLOAD_PREFIX) else {
        return Err(IpsecLbError::invalid_config(
            "session_store.payload",
            "ownership transition metadata prefix is invalid",
        ));
    };
    let raw_transition: [u8; 48] = raw_id.try_into().map_err(|_| {
        IpsecLbError::invalid_config(
            "session_store.payload",
            "ownership transition metadata length is invalid",
        )
    })?;
    let raw_id: [u8; 16] = raw_transition[..16].try_into().map_err(|_| {
        IpsecLbError::invalid_config(
            "session_store.payload",
            "ownership transition ID length is invalid",
        )
    })?;
    let raw_fingerprint: [u8; 32] = raw_transition[16..].try_into().map_err(|_| {
        IpsecLbError::invalid_config(
            "session_store.payload",
            "ownership transition fingerprint length is invalid",
        )
    })?;
    OwnershipTransitionId::new(u128::from_be_bytes(raw_id)).map(|transition_id| {
        Some((
            transition_id,
            OwnershipTransitionFingerprint::from_bytes(raw_fingerprint),
        ))
    })
}

fn map_lease_error(error: LeaseError) -> IpsecLbError {
    match error {
        LeaseError::AlreadyHeld | LeaseError::Expired | LeaseError::StaleFence => {
            IpsecLbError::ownership_conflict("session-store ownership lease is contended")
        }
        LeaseError::InvalidSessionTtl => IpsecLbError::invalid_config(
            "session_store.ttl",
            "session-store TTL is outside the supported range",
        ),
        LeaseError::NotFound | LeaseError::Backend(_) => IpsecLbError::io(
            "session_store_ownership_lease",
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "session store unavailable",
            ),
        ),
    }
}

fn map_store_error(error: StoreError) -> IpsecLbError {
    match error {
        StoreError::NotFound => IpsecLbError::NotFound,
        StoreError::StaleFence | StoreError::LeaseHeld | StoreError::LeaseExpired => {
            IpsecLbError::ownership_conflict("session-store ownership fence is not held")
        }
        StoreError::CasConflict => {
            IpsecLbError::ownership_conflict("session-store ownership generation changed")
        }
        StoreError::InvalidKey(_) => {
            IpsecLbError::invalid_config("session_store.key", "session-store key rejected")
        }
        StoreError::CasIdempotencyConflict => IpsecLbError::invalid_config(
            "session_store.idempotency",
            "session-store mutation identity was reused",
        ),
        StoreError::CasIdempotencyOutcomeUnavailable => IpsecLbError::io(
            "session_store_compare_and_set",
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "session-store mutation outcome is unavailable",
            ),
        ),
        StoreError::InvalidReplicationSequence
        | StoreError::InvalidReplicationLogRange
        | StoreError::ReplicationLogPageTooLarge { .. }
        | StoreError::ReplicationLogCursorCompacted { .. } => IpsecLbError::invalid_config(
            "session_store.replication",
            "session-store replication metadata rejected",
        ),
        StoreError::ReplicationOperationLimitExceeded => IpsecLbError::invalid_config(
            "session_store.replication",
            "session-store replication operation limit exceeded",
        ),
        StoreError::InvalidSessionTtl => IpsecLbError::invalid_config(
            "session_store.ttl",
            "session-store TTL is outside the supported range",
        ),
        StoreError::CapabilityNotSupported(_) => IpsecLbError::Unsupported,
        StoreError::BackendUnavailable(_) => IpsecLbError::io(
            "session_store_get",
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "session store unavailable",
            ),
        ),
        StoreError::Crypto(_) | StoreError::Serialization(_) => IpsecLbError::invalid_config(
            "session_store.record",
            "session-store ownership record is unreadable",
        ),
        StoreError::PayloadTooLarge { .. }
        | StoreError::InvalidRestoreScanRequest(_)
        | StoreError::InvalidRestoreScanResponse(_)
        | StoreError::RestoreScanPageTooLarge { .. }
        | StoreError::RestoreScanResponseTooLarge { .. }
        | StoreError::RestoreScanCursorStale
        | StoreError::RestoreScanWorkBudgetExceeded => {
            IpsecLbError::invalid_config("session_store", "session-store read failed")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
    use opc_session_store::{
        BackendCapabilities, BackendInstanceIdentity, BackendPeerBinding, CompareAndSet,
        CompareAndSetResult, EncryptedSessionPayload, EncryptingSessionBackend, FakeSessionBackend,
        FenceToken, Generation, LeaseGuard, OwnerId, SessionBackend, SessionLeaseManager,
        SessionOp, SessionOpResult, SessionStore, StateType, StoredSessionRecord,
    };
    use opc_session_testkit::ConsensusTestCluster;
    use tokio::sync::{Barrier, Notify};

    use super::*;

    fn keyspace() -> SessionOwnershipKeyspace {
        SessionOwnershipKeyspace::new(
            TenantId::new("tenant-a").unwrap(),
            NetworkFunctionKind::new("epdg").unwrap(),
        )
    }

    fn encryption_provider() -> Arc<MemoryKeyProvider> {
        let provider = Arc::new(MemoryKeyProvider::new());
        provider
            .insert_active_key(
                KeyId::new("ipsec-ownership-session-key").expect("test key ID"),
                KeyPurpose::Session,
                TenantId::new("tenant-a").expect("test tenant"),
                Zeroizing::new([0x5a; 32]),
            )
            .expect("install test session key");
        provider
    }

    fn transition_id(value: u128) -> OwnershipTransitionId {
        OwnershipTransitionId::new(value).unwrap()
    }

    fn fingerprint(value: u8) -> OwnershipTransitionFingerprint {
        OwnershipTransitionFingerprint::from_bytes([value; 32])
    }

    async fn write_owner<B>(
        store: &B,
        key: SessionKey,
        owner: &str,
        state_class: StateClass,
    ) -> StoredSessionRecord
    where
        B: SessionBackend + SessionLeaseManager,
    {
        let owner = OwnerId::new(owner).unwrap();
        let lease = store
            .acquire(&key, owner.clone(), Duration::from_secs(60))
            .await
            .unwrap();
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner,
            fence: lease.fence(),
            state_class,
            state_type: StateType::from_static(OWNERSHIP_KEY_TYPE),
            expires_at: None,
            payload: EncryptedSessionPayload::new([]),
        };
        let result = store
            .compare_and_set(CompareAndSet {
                key,
                lease: lease.clone(),
                expected_generation: None,
                new_record: record.clone(),
            })
            .await
            .unwrap();
        assert_eq!(result, CompareAndSetResult::Success);
        store.release(lease).await.unwrap();
        record
    }

    #[derive(Debug, Clone, Copy)]
    enum CasBehavior {
        Delegate,
        Conflict,
        StoreConflict,
        CommitThenStoreError,
        CommitThenPending,
        Pending,
    }

    #[derive(Debug, Clone)]
    struct InstrumentedBackend<B> {
        inner: B,
        read_barrier: Option<Arc<Barrier>>,
        cas_behavior: CasBehavior,
        release_fails: bool,
        release_hangs: bool,
        acquire_waits_after_apply: bool,
        releases: Arc<AtomicUsize>,
        acquire_applied: Arc<AtomicUsize>,
        acquire_continue: Arc<Notify>,
        cas_attempts: Arc<AtomicUsize>,
    }

    impl<B> InstrumentedBackend<B> {
        fn concurrent(inner: B) -> Self {
            Self {
                inner,
                read_barrier: Some(Arc::new(Barrier::new(2))),
                cas_behavior: CasBehavior::Delegate,
                release_fails: false,
                release_hangs: false,
                acquire_waits_after_apply: false,
                releases: Arc::new(AtomicUsize::new(0)),
                acquire_applied: Arc::new(AtomicUsize::new(0)),
                acquire_continue: Arc::new(Notify::new()),
                cas_attempts: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl InstrumentedBackend<SessionStore<FakeSessionBackend>> {
        fn with_cas_behavior(
            inner: SessionStore<FakeSessionBackend>,
            cas_behavior: CasBehavior,
        ) -> Self {
            Self {
                inner,
                read_barrier: None,
                cas_behavior,
                release_fails: false,
                release_hangs: false,
                acquire_waits_after_apply: false,
                releases: Arc::new(AtomicUsize::new(0)),
                acquire_applied: Arc::new(AtomicUsize::new(0)),
                acquire_continue: Arc::new(Notify::new()),
                cas_attempts: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn with_release_failure(inner: SessionStore<FakeSessionBackend>) -> Self {
            Self {
                inner,
                read_barrier: None,
                cas_behavior: CasBehavior::Delegate,
                release_fails: true,
                release_hangs: false,
                acquire_waits_after_apply: false,
                releases: Arc::new(AtomicUsize::new(0)),
                acquire_applied: Arc::new(AtomicUsize::new(0)),
                acquire_continue: Arc::new(Notify::new()),
                cas_attempts: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn with_hanging_release(inner: SessionStore<FakeSessionBackend>) -> Self {
            Self {
                inner,
                read_barrier: None,
                cas_behavior: CasBehavior::Delegate,
                release_fails: false,
                release_hangs: true,
                acquire_waits_after_apply: false,
                releases: Arc::new(AtomicUsize::new(0)),
                acquire_applied: Arc::new(AtomicUsize::new(0)),
                acquire_continue: Arc::new(Notify::new()),
                cas_attempts: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn with_apply_then_wait_acquire(inner: SessionStore<FakeSessionBackend>) -> Self {
            Self {
                inner,
                read_barrier: None,
                cas_behavior: CasBehavior::Delegate,
                release_fails: false,
                release_hangs: false,
                acquire_waits_after_apply: true,
                releases: Arc::new(AtomicUsize::new(0)),
                acquire_applied: Arc::new(AtomicUsize::new(0)),
                acquire_continue: Arc::new(Notify::new()),
                cas_attempts: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    #[async_trait]
    impl<B> SessionBackend for InstrumentedBackend<B>
    where
        B: SessionBackend,
    {
        fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
            self.inner.backend_instance_identity()
        }

        fn peer_binding(&self) -> Option<BackendPeerBinding> {
            self.inner.peer_binding()
        }

        async fn capabilities(&self) -> BackendCapabilities {
            self.inner.capabilities().await
        }

        async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
            let result = self.inner.get(key).await;
            if let Some(barrier) = &self.read_barrier {
                barrier.wait().await;
            }
            result
        }

        async fn compare_and_set(
            &self,
            op: CompareAndSet,
        ) -> Result<CompareAndSetResult, StoreError> {
            self.cas_attempts.fetch_add(1, Ordering::SeqCst);
            match self.cas_behavior {
                CasBehavior::Delegate => self.inner.compare_and_set(op).await,
                CasBehavior::Conflict => Ok(CompareAndSetResult::Conflict { current: None }),
                CasBehavior::StoreConflict => Err(StoreError::CasConflict),
                CasBehavior::CommitThenStoreError => {
                    let result = self.inner.compare_and_set(op).await?;
                    assert_eq!(result, CompareAndSetResult::Success);
                    Err(StoreError::BackendUnavailable(
                        "injected lost CAS acknowledgement".to_owned(),
                    ))
                }
                CasBehavior::CommitThenPending => {
                    let result = self.inner.compare_and_set(op).await?;
                    assert_eq!(result, CompareAndSetResult::Success);
                    std::future::pending().await
                }
                CasBehavior::Pending => std::future::pending().await,
            }
        }

        async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
            self.inner.delete_fenced(lease).await
        }

        async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
            self.inner.refresh_ttl(lease, ttl).await
        }

        async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
            self.inner.batch(ops).await
        }
    }

    #[async_trait]
    impl<B> SessionLeaseManager for InstrumentedBackend<B>
    where
        B: SessionLeaseManager,
    {
        async fn acquire(
            &self,
            key: &SessionKey,
            owner: OwnerId,
            ttl: Duration,
        ) -> Result<LeaseGuard, LeaseError> {
            let lease = self.inner.acquire(key, owner, ttl).await?;
            if self.acquire_waits_after_apply {
                self.acquire_applied.fetch_add(1, Ordering::SeqCst);
                self.acquire_continue.notified().await;
            }
            Ok(lease)
        }

        async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
            self.inner.renew(lease, ttl).await
        }

        async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
            self.releases.fetch_add(1, Ordering::SeqCst);
            if self.release_hangs {
                return std::future::pending().await;
            }
            if self.release_fails {
                Err(LeaseError::Backend("injected release failure".into()))
            } else {
                self.inner.release(lease).await
            }
        }
    }

    #[tokio::test]
    async fn reads_sa_and_shard_owners_from_session_store_metadata() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let keyspace = keyspace();
        let sa = SaId::Esp { spi: 0x1122_3344 };
        let sa_record = write_owner(
            &store,
            keyspace.sa_key(sa).unwrap(),
            "worker-a",
            StateClass::AuthoritativeSession,
        )
        .await;
        write_owner(
            &store,
            keyspace.shard_key(ShardId::new(7)).unwrap(),
            "worker-b",
            StateClass::AuthoritativeSession,
        )
        .await;

        let source = SessionStoreOwnershipSource::new(store, keyspace);
        let sa_ownership = source.sa_ownership(sa).await.unwrap().unwrap();
        assert_eq!(sa_ownership.owner().as_str(), "worker-a");
        assert_eq!(
            sa_ownership.fence(),
            OwnershipFence::new(sa_record.fence.get()).unwrap()
        );
        assert_eq!(
            source
                .shard_owner(ShardId::new(7))
                .await
                .unwrap()
                .unwrap()
                .as_str(),
            "worker-b"
        );
    }

    #[tokio::test]
    async fn missing_owner_reads_as_none() {
        let source = SessionStoreOwnershipSource::new(
            SessionStore::new(FakeSessionBackend::new()),
            keyspace(),
        );
        assert!(source
            .sa_owner(SaId::Esp { spi: 1 })
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn non_authoritative_records_are_rejected() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let keyspace = keyspace();
        let sa = SaId::Ike { responder_spi: 9 };
        write_owner(
            &store,
            keyspace.sa_key(sa).unwrap(),
            "worker-a",
            StateClass::DataplaneLookup,
        )
        .await;

        let source = SessionStoreOwnershipSource::new(store, keyspace);
        assert!(matches!(
            source.sa_owner(sa).await.unwrap_err(),
            IpsecLbError::InvalidConfig { .. }
        ));
    }

    #[tokio::test]
    async fn fencer_projects_the_strictly_higher_committed_store_fence() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let keyspace = keyspace();
        let sa = SaId::Esp { spi: 0x1122_3344 };
        let key = keyspace.sa_key(sa).unwrap();
        let initial = write_owner(
            &store,
            key.clone(),
            "worker-a",
            StateClass::AuthoritativeSession,
        )
        .await;
        let fencer = SessionStoreOwnershipFencer::new(store.clone(), keyspace);

        let grant = fencer
            .fence_sa_owner(OwnershipFenceRequest {
                sa,
                transition_id: transition_id(1),
                fingerprint: fingerprint(1),
                previous_fence: OwnershipFence::new(1).unwrap(),
                previous_owner: ClusterNode::new("worker-a"),
                new_owner: ClusterNode::new("worker-b"),
            })
            .await
            .unwrap();

        let committed = store.get(&key).await.unwrap().unwrap();
        assert_eq!(grant.sa, sa);
        assert_eq!(grant.owner.as_str(), "worker-b");
        assert_eq!(committed.owner.as_str(), "worker-b");
        assert_eq!(grant.fence.get(), committed.fence.get());
        assert!(committed.fence > initial.fence);
        assert_eq!(committed.generation, Generation::new(2));
    }

    #[tokio::test]
    async fn retry_proof_requires_the_exact_authoritative_owner_and_fence() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let keyspace = keyspace();
        let sa = SaId::Esp { spi: 0x2233_4455 };
        write_owner(
            &store,
            keyspace.sa_key(sa).unwrap(),
            "worker-a",
            StateClass::AuthoritativeSession,
        )
        .await;
        let fencer = SessionStoreOwnershipFencer::new(store.clone(), keyspace.clone());
        let grant = fencer
            .fence_sa_owner(OwnershipFenceRequest {
                sa,
                transition_id: transition_id(1),
                fingerprint: fingerprint(1),
                previous_fence: OwnershipFence::new(1).unwrap(),
                previous_owner: ClusterNode::new("worker-a"),
                new_owner: ClusterNode::new("worker-b"),
            })
            .await
            .unwrap();
        let proof = OwnershipRetryProof::from_grant(&grant);
        fencer.validate_retry_proof(&proof).await.unwrap();

        let forged_fence = OwnershipFence::new(grant.fence.get() + 1).unwrap();
        let forged = OwnershipRetryProof::from_grant(&OwnershipFenceGrant {
            fence: forged_fence,
            ..grant.clone()
        });
        assert!(matches!(
            fencer.validate_retry_proof(&forged).await.unwrap_err(),
            IpsecLbError::OwnershipConflict { .. }
        ));

        // Successful promotion releases the one-shot CAS lease on a detached
        // task so no post-commit await can hide the grant.
        tokio::task::yield_now().await;
        fencer
            .fence_sa_owner(OwnershipFenceRequest {
                sa,
                transition_id: transition_id(2),
                fingerprint: fingerprint(2),
                previous_fence: OwnershipFence::new(2).unwrap(),
                previous_owner: ClusterNode::new("worker-b"),
                new_owner: ClusterNode::new("worker-c"),
            })
            .await
            .unwrap();
        assert!(matches!(
            fencer.validate_retry_proof(&proof).await.unwrap_err(),
            IpsecLbError::OwnershipConflict { .. }
        ));
    }

    #[tokio::test]
    async fn grant_recovery_distinguishes_previous_new_and_third_owners() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let keyspace = keyspace();
        let sa = SaId::Esp { spi: 0x2345_6789 };
        write_owner(
            &store,
            keyspace.sa_key(sa).unwrap(),
            "worker-a",
            StateClass::AuthoritativeSession,
        )
        .await;
        let fencer = SessionStoreOwnershipFencer::new(store.clone(), keyspace.clone());
        let request = OwnershipFenceRequest {
            sa,
            transition_id: transition_id(1),
            fingerprint: fingerprint(1),
            previous_fence: OwnershipFence::new(1).unwrap(),
            previous_owner: ClusterNode::new("worker-a"),
            new_owner: ClusterNode::new("worker-b"),
        };

        assert_eq!(fencer.recover_fence_grant(&request).await.unwrap(), None);
        let committed = fencer.fence_sa_owner(request.clone()).await.unwrap();
        assert_eq!(
            fencer.recover_fence_grant(&request).await.unwrap(),
            Some(committed.clone())
        );

        let wrong_transition = OwnershipFenceRequest {
            transition_id: transition_id(2),
            fingerprint: fingerprint(2),
            ..request.clone()
        };
        assert!(matches!(
            fencer
                .recover_fence_grant(&wrong_transition)
                .await
                .unwrap_err(),
            IpsecLbError::OwnershipConflict { .. }
        ));

        let wrong_target = OwnershipFenceRequest {
            new_owner: ClusterNode::new("worker-c"),
            ..request.clone()
        };
        assert!(matches!(
            fencer.recover_fence_grant(&wrong_target).await.unwrap_err(),
            IpsecLbError::OwnershipConflict { .. }
        ));

        tokio::task::yield_now().await;
        let returned_to_a = fencer
            .fence_sa_owner(OwnershipFenceRequest {
                sa,
                transition_id: transition_id(3),
                fingerprint: fingerprint(3),
                previous_fence: committed.fence,
                previous_owner: ClusterNode::new("worker-b"),
                new_owner: ClusterNode::new("worker-a"),
            })
            .await
            .unwrap();
        assert!(returned_to_a.fence > request.previous_fence);
        let key = keyspace.sa_key(sa).unwrap();
        let before_stale_replay = store.get(&key).await.unwrap().unwrap();

        assert!(matches!(
            fencer.recover_fence_grant(&request).await.unwrap_err(),
            IpsecLbError::OwnershipConflict { .. }
        ));
        assert!(matches!(
            fencer.fence_sa_owner(request).await.unwrap_err(),
            IpsecLbError::OwnershipConflict { .. }
        ));
        assert_eq!(store.get(&key).await.unwrap(), Some(before_stale_replay));
    }

    #[tokio::test]
    async fn fencer_rejects_zero_sa_identifiers_at_both_entry_points() {
        let fencer = SessionStoreOwnershipFencer::new(
            SessionStore::new(FakeSessionBackend::new()),
            keyspace(),
        );

        for sa in [SaId::Esp { spi: 0 }, SaId::Ike { responder_spi: 0 }] {
            assert!(matches!(
                fencer
                    .fence_sa_owner(OwnershipFenceRequest {
                        sa,
                        transition_id: transition_id(1),
                        fingerprint: fingerprint(1),
                        previous_fence: OwnershipFence::new(1).unwrap(),
                        previous_owner: ClusterNode::new("worker-a"),
                        new_owner: ClusterNode::new("worker-b"),
                    })
                    .await
                    .unwrap_err(),
                IpsecLbError::InvalidConfig { .. }
            ));

            let proof = OwnershipRetryProof::from_grant(&OwnershipFenceGrant {
                sa,
                transition_id: transition_id(1),
                fingerprint: fingerprint(1),
                owner: ClusterNode::new("worker-b"),
                fence: OwnershipFence::new(1).unwrap(),
            });
            assert!(matches!(
                fencer.validate_retry_proof(&proof).await.unwrap_err(),
                IpsecLbError::InvalidConfig { .. }
            ));
        }
    }

    #[tokio::test]
    async fn quorum_fencer_returns_only_the_majority_committed_owner_and_fence() {
        let cluster = ConsensusTestCluster::start(3).await;
        // Exercise production quorum semantics while one configured replica
        // is unavailable: both lease acquisition and CAS still require the
        // two-replica majority before a grant can be returned.
        cluster.set_node_online(2, false);
        cluster.wait_node_durable_ready(0).await;
        let quorum = EncryptingSessionBackend::new(
            Arc::new(cluster.store(0)),
            encryption_provider(),
            "ipsec-ownership-test",
        );
        let keyspace = keyspace();
        let sa = SaId::Ike {
            responder_spi: 0x1122_3344_5566_7788,
        };
        let key = keyspace.sa_key(sa).unwrap();
        let initial = write_owner(
            &quorum,
            key.clone(),
            "worker-a",
            StateClass::AuthoritativeSession,
        )
        .await;
        let fencer = SessionStoreOwnershipFencer::new(quorum.clone(), keyspace);

        let grant = fencer
            .fence_sa_owner(OwnershipFenceRequest {
                sa,
                transition_id: transition_id(1),
                fingerprint: fingerprint(1),
                previous_fence: OwnershipFence::new(1).unwrap(),
                previous_owner: ClusterNode::new("worker-a"),
                new_owner: ClusterNode::new("worker-b"),
            })
            .await
            .unwrap();

        let committed = quorum.get(&key).await.unwrap().unwrap();
        assert_eq!(committed.owner.as_str(), grant.owner.as_str());
        assert_eq!(committed.fence.get(), grant.fence.get());
        assert!(committed.fence > initial.fence);
        assert_eq!(committed.generation, Generation::new(2));
    }

    #[tokio::test]
    async fn fencer_rejects_missing_and_stale_previous_owners_without_mutating() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let keyspace = keyspace();
        let fencer = SessionStoreOwnershipFencer::new(store.clone(), keyspace.clone());
        let missing_sa = SaId::Ike { responder_spi: 1 };
        let stale_sa = SaId::Ike { responder_spi: 2 };

        assert_eq!(
            fencer
                .fence_sa_owner(OwnershipFenceRequest {
                    sa: missing_sa,
                    transition_id: transition_id(1),
                    fingerprint: fingerprint(1),
                    previous_fence: OwnershipFence::new(1).unwrap(),
                    previous_owner: ClusterNode::new("worker-a"),
                    new_owner: ClusterNode::new("worker-b"),
                })
                .await
                .unwrap_err(),
            IpsecLbError::NotFound
        );

        let key = keyspace.sa_key(stale_sa).unwrap();
        let initial = write_owner(
            &store,
            key.clone(),
            "worker-a",
            StateClass::AuthoritativeSession,
        )
        .await;
        assert!(matches!(
            fencer
                .fence_sa_owner(OwnershipFenceRequest {
                    sa: stale_sa,
                    transition_id: transition_id(1),
                    fingerprint: fingerprint(1),
                    previous_fence: OwnershipFence::new(1).unwrap(),
                    previous_owner: ClusterNode::new("worker-stale"),
                    new_owner: ClusterNode::new("worker-b"),
                })
                .await
                .unwrap_err(),
            IpsecLbError::OwnershipConflict { .. }
        ));
        assert_eq!(store.get(&key).await.unwrap(), Some(initial));

        assert!(matches!(
            fencer
                .fence_sa_owner(OwnershipFenceRequest {
                    sa: stale_sa,
                    transition_id: transition_id(1),
                    fingerprint: fingerprint(1),
                    previous_fence: OwnershipFence::new(1).unwrap(),
                    previous_owner: ClusterNode::new("worker-a"),
                    new_owner: ClusterNode::new("worker-a"),
                })
                .await
                .unwrap_err(),
            IpsecLbError::OwnershipConflict { .. }
        ));
        assert_eq!(
            store.get(&key).await.unwrap().unwrap().owner.as_str(),
            "worker-a"
        );
    }

    #[tokio::test]
    async fn concurrent_promotions_have_exactly_one_committed_winner() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let keyspace = keyspace();
        let sa = SaId::Esp { spi: 0x5566_7788 };
        let key = keyspace.sa_key(sa).unwrap();
        let initial = write_owner(
            &store,
            key.clone(),
            "worker-a",
            StateClass::AuthoritativeSession,
        )
        .await;
        // Both contenders are held after reading the same generation. This
        // exercises the lease/CAS race rather than relying on task timing.
        let backend = InstrumentedBackend::concurrent(store.clone());
        let fencer = SessionStoreOwnershipFencer::new(backend, keyspace);
        let promote = |owner: &'static str| {
            let fencer = fencer.clone();
            async move {
                fencer
                    .fence_sa_owner(OwnershipFenceRequest {
                        sa,
                        transition_id: transition_id(if owner == "worker-b" { 1 } else { 2 }),
                        fingerprint: fingerprint(if owner == "worker-b" { 1 } else { 2 }),
                        previous_fence: OwnershipFence::new(1).unwrap(),
                        previous_owner: ClusterNode::new("worker-a"),
                        new_owner: ClusterNode::new(owner),
                    })
                    .await
            }
        };

        let (left, right) = tokio::join!(promote("worker-b"), promote("worker-c"));
        let success_count = [&left, &right]
            .into_iter()
            .filter(|result| result.is_ok())
            .count();
        assert_eq!(success_count, 1, "left={left:?}, right={right:?}");
        let (winner, loser) = if let Ok(grant) = left {
            (grant, right.unwrap_err())
        } else {
            (right.unwrap(), left.unwrap_err())
        };
        assert!(matches!(loser, IpsecLbError::OwnershipConflict { .. }));

        let committed = store.get(&key).await.unwrap().unwrap();
        assert_eq!(committed.owner.as_str(), winner.owner.as_str());
        assert_eq!(committed.fence.get(), winner.fence.get());
        assert!(committed.fence > initial.fence);
        assert_eq!(committed.generation, Generation::new(2));
    }

    #[tokio::test]
    async fn quorum_concurrent_promotions_have_exactly_one_committed_winner() {
        let cluster = ConsensusTestCluster::start(3).await;
        let quorum = EncryptingSessionBackend::new(
            Arc::new(cluster.store(0)),
            encryption_provider(),
            "ipsec-ownership-test",
        );
        let keyspace = keyspace();
        let sa = SaId::Esp { spi: 0x6677_8899 };
        let key = keyspace.sa_key(sa).unwrap();
        let initial = write_owner(
            &quorum,
            key.clone(),
            "worker-a",
            StateClass::AuthoritativeSession,
        )
        .await;

        // The barrier ensures both fencers observe the same committed owner
        // and generation before they contend through the real three-replica
        // quorum lease and CAS paths.
        let backend = InstrumentedBackend::concurrent(quorum.clone());
        let fencer = SessionStoreOwnershipFencer::new(backend, keyspace);
        let promote = |owner: &'static str| {
            let fencer = fencer.clone();
            async move {
                fencer
                    .fence_sa_owner(OwnershipFenceRequest {
                        sa,
                        transition_id: transition_id(if owner == "worker-b" { 1 } else { 2 }),
                        fingerprint: fingerprint(if owner == "worker-b" { 1 } else { 2 }),
                        previous_fence: OwnershipFence::new(1).unwrap(),
                        previous_owner: ClusterNode::new("worker-a"),
                        new_owner: ClusterNode::new(owner),
                    })
                    .await
            }
        };

        let (left, right) = tokio::join!(promote("worker-b"), promote("worker-c"));
        let success_count = [&left, &right]
            .into_iter()
            .filter(|result| result.is_ok())
            .count();
        assert_eq!(success_count, 1, "left={left:?}, right={right:?}");
        let (winner, loser) = if let Ok(grant) = left {
            (grant, right.unwrap_err())
        } else {
            (right.unwrap(), left.unwrap_err())
        };
        assert!(
            matches!(loser, IpsecLbError::OwnershipConflict { .. }),
            "loser must report ownership contention, got {loser:?}"
        );

        let committed = quorum.get(&key).await.unwrap().unwrap();
        assert_eq!(committed.owner.as_str(), winner.owner.as_str());
        assert_eq!(committed.fence.get(), winner.fence.get());
        assert!(committed.fence > initial.fence);
        assert_eq!(committed.generation, Generation::new(2));
    }

    #[tokio::test]
    async fn fencer_releases_lease_after_cas_conflict_and_store_error() {
        for behavior in [CasBehavior::Conflict, CasBehavior::StoreConflict] {
            let store = SessionStore::new(FakeSessionBackend::new());
            let keyspace = keyspace();
            let sa = SaId::Esp { spi: 9 };
            write_owner(
                &store,
                keyspace.sa_key(sa).unwrap(),
                "worker-a",
                StateClass::AuthoritativeSession,
            )
            .await;
            let backend = InstrumentedBackend::with_cas_behavior(store, behavior);
            let release_counter = backend.releases.clone();
            let fencer = SessionStoreOwnershipFencer::new(backend, keyspace);

            assert!(matches!(
                fencer
                    .fence_sa_owner(OwnershipFenceRequest {
                        sa,
                        transition_id: transition_id(1),
                        fingerprint: fingerprint(1),
                        previous_fence: OwnershipFence::new(1).unwrap(),
                        previous_owner: ClusterNode::new("worker-a"),
                        new_owner: ClusterNode::new("worker-b"),
                    })
                    .await
                    .unwrap_err(),
                IpsecLbError::OwnershipConflict { .. }
            ));
            tokio::task::yield_now().await;
            assert_eq!(release_counter.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn commit_ambiguous_store_error_is_recoverable_without_refencing() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let keyspace = keyspace();
        let sa = SaId::Esp { spi: 12 };
        let key = keyspace.sa_key(sa).unwrap();
        write_owner(
            &store,
            key.clone(),
            "worker-a",
            StateClass::AuthoritativeSession,
        )
        .await;
        let backend = InstrumentedBackend::with_cas_behavior(
            store.clone(),
            CasBehavior::CommitThenStoreError,
        );
        let fencer = SessionStoreOwnershipFencer::new(backend, keyspace);
        let request = OwnershipFenceRequest {
            sa,
            transition_id: transition_id(1),
            fingerprint: fingerprint(1),
            previous_fence: OwnershipFence::new(1).unwrap(),
            previous_owner: ClusterNode::new("worker-a"),
            new_owner: ClusterNode::new("worker-b"),
        };

        assert!(matches!(
            fencer.fence_sa_owner(request.clone()).await.unwrap_err(),
            IpsecLbError::Io { .. }
        ));
        let recovered = fencer
            .recover_fence_grant(&request)
            .await
            .unwrap()
            .expect("the acknowledged store error hid a committed promotion");

        let committed = store.get(&key).await.unwrap().unwrap();
        assert_eq!(recovered.owner.as_str(), "worker-b");
        assert_eq!(recovered.fence.get(), committed.fence.get());
        assert_eq!(committed.generation, Generation::new(2));
    }

    #[tokio::test]
    async fn commit_then_hung_ack_is_bounded_and_recoverable_without_refencing() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let keyspace = keyspace();
        let sa = SaId::Esp { spi: 16 };
        let key = keyspace.sa_key(sa).unwrap();
        write_owner(
            &store,
            key.clone(),
            "worker-a",
            StateClass::AuthoritativeSession,
        )
        .await;
        let backend =
            InstrumentedBackend::with_cas_behavior(store.clone(), CasBehavior::CommitThenPending);
        let release_attempts = backend.releases.clone();
        let mut fencer = SessionStoreOwnershipFencer::new(backend, keyspace);
        fencer.lease_ttl = Duration::from_millis(50);
        let request = OwnershipFenceRequest {
            sa,
            transition_id: transition_id(1),
            fingerprint: fingerprint(1),
            previous_fence: OwnershipFence::new(1).unwrap(),
            previous_owner: ClusterNode::new("worker-a"),
            new_owner: ClusterNode::new("worker-b"),
        };

        let error = tokio::time::timeout(
            Duration::from_secs(1),
            fencer.fence_sa_owner(request.clone()),
        )
        .await
        .expect("CAS acknowledgement wait must be bounded")
        .unwrap_err();
        assert!(matches!(error, IpsecLbError::Io { .. }));
        let recovered = fencer
            .recover_fence_grant(&request)
            .await
            .unwrap()
            .expect("exact recovery must find the commit hidden by the timeout");

        let committed = store.get(&key).await.unwrap().unwrap();
        assert_eq!(committed.owner.as_str(), "worker-b");
        assert_eq!(recovered.fence.get(), committed.fence.get());
        tokio::time::timeout(Duration::from_secs(1), async {
            while release_attempts.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("timed-out CAS must trigger detached lease cleanup");
    }

    #[tokio::test]
    async fn cancelling_apply_then_wait_acquire_releases_the_lease() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let keyspace = keyspace();
        let sa = SaId::Esp { spi: 14 };
        write_owner(
            &store,
            keyspace.sa_key(sa).unwrap(),
            "worker-a",
            StateClass::AuthoritativeSession,
        )
        .await;
        let backend = InstrumentedBackend::with_apply_then_wait_acquire(store.clone());
        let acquire_applied = backend.acquire_applied.clone();
        let acquire_continue = backend.acquire_continue.clone();
        let release_attempts = backend.releases.clone();
        let fencer = SessionStoreOwnershipFencer::new(backend, keyspace.clone());
        let request = OwnershipFenceRequest {
            sa,
            transition_id: transition_id(1),
            fingerprint: fingerprint(1),
            previous_fence: OwnershipFence::new(1).unwrap(),
            previous_owner: ClusterNode::new("worker-a"),
            new_owner: ClusterNode::new("worker-b"),
        };

        let pending = {
            let fencer = fencer.clone();
            let request = request.clone();
            tokio::spawn(async move { fencer.fence_sa_owner(request).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while acquire_applied.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("test backend must apply the lease before acknowledging it");
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());

        // The acquisition task is detached from the cancelled caller. Let it
        // return the already-applied guard; its abandoned cleanup value must
        // release immediately rather than wait for the lease TTL.
        acquire_continue.notify_one();
        tokio::time::timeout(Duration::from_secs(1), async {
            while release_attempts.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled acquisition must release its returned lease guard");

        let replay = SessionStoreOwnershipFencer::new(store, keyspace);
        let grant = replay.fence_sa_owner(request).await.unwrap();
        assert_eq!(grant.owner.as_str(), "worker-b");
    }

    #[tokio::test]
    async fn cancelled_hung_acquire_task_is_bounded_by_the_lease_ttl() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let keyspace = keyspace();
        let sa = SaId::Esp { spi: 15 };
        write_owner(
            &store,
            keyspace.sa_key(sa).unwrap(),
            "worker-a",
            StateClass::AuthoritativeSession,
        )
        .await;
        let backend = InstrumentedBackend::with_apply_then_wait_acquire(store.clone());
        let acquire_applied = backend.acquire_applied.clone();
        let mut fencer = SessionStoreOwnershipFencer::new(backend, keyspace.clone());
        fencer.lease_ttl = Duration::from_millis(50);
        let request = OwnershipFenceRequest {
            sa,
            transition_id: transition_id(1),
            fingerprint: fingerprint(1),
            previous_fence: OwnershipFence::new(1).unwrap(),
            previous_owner: ClusterNode::new("worker-a"),
            new_owner: ClusterNode::new("worker-b"),
        };

        let pending = {
            let fencer = fencer.clone();
            let request = request.clone();
            tokio::spawn(async move { fencer.fence_sa_owner(request).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while acquire_applied.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("test backend must enter its hung acquire acknowledgement");
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        assert_eq!(Arc::strong_count(&fencer.backend), 2);

        tokio::time::timeout(Duration::from_secs(1), async {
            while Arc::strong_count(&fencer.backend) != 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("detached acquire must not leak a task past the lease TTL");

        // The backend never returned a guard to release, so expiry is the
        // bounded fallback. A fresh writer can proceed after that same TTL.
        let replay = SessionStoreOwnershipFencer::new(store, keyspace);
        let grant = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match replay.fence_sa_owner(request.clone()).await {
                    Ok(grant) => break grant,
                    Err(IpsecLbError::OwnershipConflict { .. }) => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("unexpected replay failure: {error:?}"),
                }
            }
        })
        .await
        .expect("lease expiry must permit retry after a hung acquisition");
        assert_eq!(grant.owner.as_str(), "worker-b");
    }

    #[tokio::test]
    async fn cancelling_a_pending_cas_releases_the_lease_for_immediate_replay() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let keyspace = keyspace();
        let sa = SaId::Esp { spi: 13 };
        write_owner(
            &store,
            keyspace.sa_key(sa).unwrap(),
            "worker-a",
            StateClass::AuthoritativeSession,
        )
        .await;
        let backend = InstrumentedBackend::with_cas_behavior(store.clone(), CasBehavior::Pending);
        let cas_attempts = backend.cas_attempts.clone();
        let release_attempts = backend.releases.clone();
        let fencer = SessionStoreOwnershipFencer::new(backend, keyspace.clone());
        let request = OwnershipFenceRequest {
            sa,
            transition_id: transition_id(1),
            fingerprint: fingerprint(1),
            previous_fence: OwnershipFence::new(1).unwrap(),
            previous_owner: ClusterNode::new("worker-a"),
            new_owner: ClusterNode::new("worker-b"),
        };

        let pending = {
            let fencer = fencer.clone();
            let request = request.clone();
            tokio::spawn(async move { fencer.fence_sa_owner(request).await })
        };
        tokio::time::timeout(Duration::from_secs(1), async {
            while cas_attempts.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("test fencer must reach the pending CAS");
        pending.abort();
        assert!(pending.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), async {
            while release_attempts.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelling CAS must trigger bounded lease cleanup");

        let replay = SessionStoreOwnershipFencer::new(store, keyspace);
        let grant = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                match replay.fence_sa_owner(request.clone()).await {
                    Ok(grant) => break grant,
                    Err(IpsecLbError::OwnershipConflict { .. }) => {
                        tokio::task::yield_now().await;
                    }
                    Err(error) => panic!("unexpected replay failure: {error:?}"),
                }
            }
        })
        .await
        .expect("lease cleanup must allow replay without waiting for the 10s TTL");
        assert_eq!(grant.owner.as_str(), "worker-b");
    }

    #[tokio::test]
    async fn committed_grant_does_not_wait_for_release_completion() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let keyspace = keyspace();
        let sa = SaId::Esp { spi: 10 };
        let key = keyspace.sa_key(sa).unwrap();
        write_owner(
            &store,
            key.clone(),
            "worker-a",
            StateClass::AuthoritativeSession,
        )
        .await;
        let backend = InstrumentedBackend::with_release_failure(store.clone());
        let release_counter = backend.releases.clone();
        let fencer = SessionStoreOwnershipFencer::new(backend, keyspace);

        let grant = fencer
            .fence_sa_owner(OwnershipFenceRequest {
                sa,
                transition_id: transition_id(1),
                fingerprint: fingerprint(1),
                previous_fence: OwnershipFence::new(1).unwrap(),
                previous_owner: ClusterNode::new("worker-a"),
                new_owner: ClusterNode::new("worker-b"),
            })
            .await
            .unwrap();

        // The grant is returned before the detached release task is polled.
        // Even a release failure therefore cannot strand committed ownership.
        tokio::task::yield_now().await;
        assert_eq!(release_counter.load(Ordering::SeqCst), 1);
        let committed = store.get(&key).await.unwrap().unwrap();
        assert_eq!(committed.owner.as_str(), grant.owner.as_str());
        assert_eq!(committed.fence.get(), grant.fence.get());
    }

    #[tokio::test]
    async fn hung_release_cannot_hide_an_already_committed_grant() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let keyspace = keyspace();
        let sa = SaId::Esp { spi: 11 };
        let key = keyspace.sa_key(sa).unwrap();
        write_owner(
            &store,
            key.clone(),
            "worker-a",
            StateClass::AuthoritativeSession,
        )
        .await;
        let backend = InstrumentedBackend::with_hanging_release(store.clone());
        let release_counter = backend.releases.clone();
        let fencer = SessionStoreOwnershipFencer::new(backend, keyspace);

        let grant = tokio::time::timeout(
            Duration::from_millis(100),
            fencer.fence_sa_owner(OwnershipFenceRequest {
                sa,
                transition_id: transition_id(1),
                fingerprint: fingerprint(1),
                previous_fence: OwnershipFence::new(1).unwrap(),
                previous_owner: ClusterNode::new("worker-a"),
                new_owner: ClusterNode::new("worker-b"),
            }),
        )
        .await
        .expect("post-commit lease release must not delay the grant")
        .unwrap();

        tokio::task::yield_now().await;
        assert_eq!(release_counter.load(Ordering::SeqCst), 1);
        assert_eq!(Arc::strong_count(&fencer.backend), 2);
        tokio::time::timeout(Duration::from_secs(2), async {
            while Arc::strong_count(&fencer.backend) != 1 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("detached release must be cancelled at its cleanup deadline");
        let committed = store.get(&key).await.unwrap().unwrap();
        assert_eq!(committed.owner.as_str(), grant.owner.as_str());
        assert_eq!(committed.fence.get(), grant.fence.get());
    }

    #[test]
    fn malformed_ownership_record_shapes_fail_closed() {
        let expected_key = keyspace().sa_key(SaId::Esp { spi: 7 }).unwrap();
        let valid = StoredSessionRecord {
            key: expected_key.clone(),
            generation: Generation::new(1),
            owner: OwnerId::new("worker-a").unwrap(),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static(OWNERSHIP_KEY_TYPE),
            expires_at: None,
            payload: EncryptedSessionPayload::new([]),
        };
        assert_eq!(validate_ownership_record(&valid, &expected_key), Ok(None));
        let mut transitioned = valid.clone();
        transitioned.payload = encode_ownership_transition(transition_id(7), fingerprint(9));
        assert_eq!(
            validate_ownership_record(&transitioned, &expected_key),
            Ok(Some((transition_id(7), fingerprint(9))))
        );

        let mut wrong_record_key = valid.clone();
        wrong_record_key.key = keyspace().sa_key(SaId::Esp { spi: 8 }).unwrap();
        assert!(matches!(
            validate_ownership_record(&wrong_record_key, &expected_key),
            Err(IpsecLbError::InvalidConfig { .. })
        ));

        let mut wrong_key_type = valid.clone();
        wrong_key_type.key.key_type =
            SessionKeyType::other("not-ownership").expect("test key type");
        let wrong_expected_key = wrong_key_type.key.clone();
        assert!(matches!(
            validate_ownership_record(&wrong_key_type, &wrong_expected_key),
            Err(IpsecLbError::InvalidConfig { .. })
        ));

        let mut wrong_state_type = valid.clone();
        wrong_state_type.state_type = StateType::from_static("not-ownership");
        assert!(matches!(
            validate_ownership_record(&wrong_state_type, &expected_key),
            Err(IpsecLbError::InvalidConfig { .. })
        ));

        let mut expiring = valid.clone();
        expiring.expires_at = Some(opc_types::Timestamp::now_utc());
        assert!(matches!(
            validate_ownership_record(&expiring, &expected_key),
            Err(IpsecLbError::InvalidConfig { .. })
        ));

        assert!(EncryptedSessionPayload::try_envelope(b"").is_err());
        for payload in [
            EncryptedSessionPayload::legacy_plaintext(b""),
            EncryptedSessionPayload::unclassified(b""),
        ] {
            let mut wrong_encoding = valid.clone();
            wrong_encoding.payload = payload;
            assert!(matches!(
                validate_ownership_record(&wrong_encoding, &expected_key),
                Err(IpsecLbError::InvalidConfig { .. })
            ));
        }

        let mut payload_bearing = valid.clone();
        payload_bearing.payload = EncryptedSessionPayload::new(b"not-metadata-only");
        assert!(matches!(
            validate_ownership_record(&payload_bearing, &expected_key),
            Err(IpsecLbError::InvalidConfig { .. })
        ));

        for invalid_owner in [String::new(), "x".repeat(129)] {
            let mut hostile = serde_json::to_value(&valid).unwrap();
            hostile["owner"] = serde_json::Value::String(invalid_owner.clone());
            let error = serde_json::from_value::<StoredSessionRecord>(hostile).unwrap_err();
            if !invalid_owner.is_empty() {
                assert!(!error.to_string().contains(&invalid_owner));
            }
        }
    }

    #[test]
    fn store_fencing_conflicts_map_to_ownership_conflicts() {
        for error in [
            StoreError::StaleFence,
            StoreError::LeaseHeld,
            StoreError::CasConflict,
        ] {
            assert!(matches!(
                map_store_error(error),
                IpsecLbError::OwnershipConflict { .. }
            ));
        }
    }

    #[test]
    fn invalid_session_boundaries_map_to_configuration_errors() {
        assert!(matches!(
            map_store_error(StoreError::InvalidSessionTtl),
            IpsecLbError::InvalidConfig { .. }
        ));
        assert!(matches!(
            map_store_error(StoreError::ReplicationOperationLimitExceeded),
            IpsecLbError::InvalidConfig { .. }
        ));
        for error in [
            StoreError::InvalidReplicationLogRange,
            StoreError::ReplicationLogPageTooLarge {
                requested: 2,
                max: 1,
            },
            StoreError::ReplicationLogCursorCompacted { resume_from: 2 },
        ] {
            assert!(matches!(
                map_store_error(error),
                IpsecLbError::InvalidConfig { .. }
            ));
        }
        assert!(matches!(
            map_lease_error(LeaseError::InvalidSessionTtl),
            IpsecLbError::InvalidConfig { .. }
        ));
    }
}
