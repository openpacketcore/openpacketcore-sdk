use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream;
mod support;

use opc_session_store::{
    BackendCapabilities, BackendInstanceIdentity, CompareAndSet, CompareAndSetResult, LeaseError,
    LeaseGuard, OwnerId, ReplicationEntry, SessionBackend, SessionKey, SessionKeyType,
    SessionLeaseManager, SessionOp, SessionOpResult, StoreError, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId};
use std::{sync::Arc, time::Duration};

#[derive(Debug)]
struct MissingLeaseCoordinationBackend {
    identity: Arc<()>,
}

#[async_trait]
impl SessionBackend for MissingLeaseCoordinationBackend {
    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        Some(BackendInstanceIdentity::for_shared(&self.identity))
    }

    async fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::all_enabled()
    }

    async fn get(&self, _key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        Ok(None)
    }

    async fn compare_and_set(&self, _op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        Ok(CompareAndSetResult::Success)
    }

    async fn delete_fenced(&self, _lease: &LeaseGuard) -> Result<(), StoreError> {
        Ok(())
    }

    async fn refresh_ttl(&self, _lease: &LeaseGuard, _ttl: Duration) -> Result<(), StoreError> {
        Ok(())
    }

    async fn batch(&self, _ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        Ok(Vec::new())
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        Ok(0)
    }

    async fn get_replication_log(
        &self,
        _start: u64,
        _limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        Ok(Vec::new())
    }

    async fn replicate_entry(&self, _entry: ReplicationEntry) -> Result<(), StoreError> {
        Ok(())
    }

    async fn rebuild_replication_state(
        &self,
        _entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        Ok(())
    }

    async fn watch(
        &self,
        _start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        use futures_util::StreamExt;
        Ok(stream::empty().boxed())
    }
}

#[async_trait]
impl SessionLeaseManager for MissingLeaseCoordinationBackend {
    async fn acquire(
        &self,
        _key: &SessionKey,
        _owner: OwnerId,
        _ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        Err(LeaseError::Backend("not used by quorum".into()))
    }

    async fn renew(&self, _lease: &LeaseGuard, _ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        Err(LeaseError::Backend("not used by quorum".into()))
    }

    async fn release(&self, _lease: LeaseGuard) -> Result<(), LeaseError> {
        Ok(())
    }
}

fn test_key() -> SessionKey {
    SessionKey {
        tenant: TenantId::new("tenant-a").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(b"missing-lease-coordination"),
    }
}

#[tokio::test]
async fn quorum_acquire_fails_when_replica_omits_next_lease_info() {
    let backend = Arc::new(MissingLeaseCoordinationBackend {
        identity: Arc::new(()),
    });
    let quorum = support::lab_singleton(support::member(0, backend));

    let err = quorum
        .acquire(
            &test_key(),
            OwnerId::new("owner-a").expect("owner"),
            Duration::from_secs(60),
        )
        .await
        .expect_err("missing lease coordination must fail closed");

    assert!(
        matches!(err, LeaseError::Backend(ref message) if message.contains("lease_coordination")),
        "unexpected error: {err:?}"
    );
}
