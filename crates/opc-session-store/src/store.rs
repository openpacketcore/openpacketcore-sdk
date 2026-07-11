//! Unified session-store handle.
//!
//! [`SessionStore`] bundles a [`SessionBackend`] and a [`SessionLeaseManager`]
//! behind a single handle so consumers do not have to pass two trait objects
//! around for the same physical backend.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::BoxStream;

use crate::backend::{
    BackendInstanceIdentity, CompareAndSet, CompareAndSetResult, ReplicationEntry, SessionBackend,
    SessionOp, SessionOpResult,
};
use crate::capability::BackendCapabilities;
use crate::error::{LeaseError, StoreError};
use crate::lease::{LeaseGuard, SessionLeaseManager};
use crate::model::{OwnerId, SessionKey};
use crate::record::StoredSessionRecord;
use crate::restore::{RestoreScanPage, RestoreScanRequest};

/// A single handle that owns one backend and exposes both storage and lease
/// operations.
///
/// Construct a store from anything that implements both [`SessionBackend`] and
/// [`SessionLeaseManager`]. The handle is cheap to clone: clones share the same
/// backend.
///
/// # Example
///
/// ```rust,no_run
/// use std::time::Duration;
/// use opc_session_store::{
///     FakeSessionBackend, OwnerId, SessionKey, SessionKeyType, SessionLeaseManager, SessionStore,
/// };
/// use opc_types::{NetworkFunctionKind, TenantId};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let store = SessionStore::new(FakeSessionBackend::new());
/// let owner = OwnerId::new("smf-01")?;
/// let key = SessionKey {
///     tenant: TenantId::new("ref-smf")?,
///     nf_kind: NetworkFunctionKind::new("smf")?,
///     key_type: SessionKeyType::PduSession,
///     stable_id: bytes::Bytes::from_static(b"seid-1"),
/// };
/// let lease = store.acquire(&key, owner, Duration::from_secs(60)).await?;
/// # let _ = lease;
/// # Ok(())
/// # }
/// ```
pub struct SessionStore<B: SessionBackend + SessionLeaseManager> {
    backend: Arc<B>,
}

impl<B: SessionBackend + SessionLeaseManager> std::fmt::Debug for SessionStore<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionStore").finish_non_exhaustive()
    }
}

impl<B: SessionBackend + SessionLeaseManager> Clone for SessionStore<B> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
        }
    }
}

impl<B: SessionBackend + SessionLeaseManager> SessionStore<B> {
    /// Wrap `backend` in a shared handle.
    pub fn new(backend: B) -> Self {
        Self {
            backend: Arc::new(backend),
        }
    }

    /// Wrap an existing `Arc<B>` in a shared handle.
    pub fn from_arc(backend: Arc<B>) -> Self {
        Self { backend }
    }

    /// Access the underlying backend arc.
    pub fn backend(&self) -> &Arc<B> {
        &self.backend
    }
}

#[async_trait]
impl<B: SessionBackend + SessionLeaseManager> SessionBackend for SessionStore<B> {
    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        self.backend.backend_instance_identity()
    }

    async fn capabilities(&self) -> BackendCapabilities {
        self.backend.capabilities().await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.backend.get(key).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        self.backend.compare_and_set(op).await
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        self.backend.delete_fenced(lease).await
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        self.backend.refresh_ttl(lease, ttl).await
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        self.backend.batch(ops).await
    }

    async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        self.backend.scan_restore_records(request).await
    }

    async fn assert_suitable_for(
        &self,
        profile: crate::capability::SessionStateProfile,
    ) -> Result<(), crate::capability::CapabilityError> {
        self.backend.assert_suitable_for(profile).await
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.backend.max_replication_sequence().await
    }

    async fn probe_replication_head(
        &self,
    ) -> Result<u64, crate::readiness::ReplicaReadinessFailure> {
        self.backend.probe_replication_head().await
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        self.backend.get_replication_log(start, limit).await
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        self.backend.replicate_entry(entry).await
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        self.backend.rebuild_replication_state(entries).await
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<BoxStream<'static, Result<ReplicationEntry, StoreError>>, StoreError> {
        self.backend.watch(start_sequence).await
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        self.backend.next_lease_info().await
    }
}

#[async_trait]
impl<B: SessionBackend + SessionLeaseManager> SessionLeaseManager for SessionStore<B> {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        self.backend.acquire(key, owner, ttl).await
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        self.backend.renew(lease, ttl).await
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        self.backend.release(lease).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Generation, SessionKeyType, StateClass, StateType};
    use crate::record::EncryptedSessionPayload;
    use crate::FakeSessionBackend;
    use bytes::Bytes;
    use opc_types::{NetworkFunctionKind, TenantId};

    #[tokio::test]
    async fn fake_backend_slots_into_session_store() {
        let store = SessionStore::new(FakeSessionBackend::new());
        let owner = OwnerId::new("smf-01").expect("valid owner");
        let key = SessionKey {
            tenant: TenantId::from_static("ref-smf"),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"seid-1"),
        };
        let lease = store
            .acquire(&key, owner.clone(), Duration::from_secs(60))
            .await
            .expect("acquire");
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner: owner.clone(),
            fence: lease.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("pdu-session"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(Bytes::from_static(b"payload")),
        };
        let result = store
            .compare_and_set(CompareAndSet {
                key,
                lease,
                expected_generation: None,
                new_record: record,
            })
            .await
            .expect("cas");
        assert!(matches!(result, CompareAndSetResult::Success));
    }
}
