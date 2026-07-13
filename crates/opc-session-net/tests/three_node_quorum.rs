#![cfg(feature = "legacy-session-net-compat")]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt;
use opc_identity::{build_identity_state, parse_certs_pem, parse_key_pem, TrustBundle};
use opc_session_net::{
    LocalReplicaBinding, RemoteAddrResolver, RemoteReplicaBinding, RemoteSessionBackend,
    SessionClusterId, SessionConfigurationEpoch, SessionConfigurationGeneration,
    SessionReplicationManifest, SessionReplicationServer,
};
use opc_session_store::backend::{
    CompareAndSet, CompareAndSetResult, ReplicationEntry, ReplicationOp, SessionBackend,
};
use opc_session_store::capability::BackendCapabilities;
use opc_session_store::fake::{FakeBackendLimits, FakeSessionBackend};
use opc_session_store::lease::SessionLeaseManager;
use opc_session_store::model::{
    FenceToken, Generation, OwnerId, SessionKey, SessionKeyType, StateClass, StateType,
};
use opc_session_store::quorum::SessionStoreBackend;
use opc_session_store::record::{EncryptedSessionPayload, StoredSessionRecord};
use opc_session_store::{
    QuorumReplicaDescriptor, ReplicaBackingIdentity, ReplicaEndpoint, ReplicaFailureDomain,
    ReplicaId, ReplicaReadinessFailure, ReplicaTlsIdentity, RestoreScanRequest, RestoreScanScope,
    SqliteSessionBackend, StoreError, MAX_REPLICATION_LOG_PAGE_ENTRIES,
    MAX_REPLICATION_OPERATIONS_PER_ENTRY, MAX_REPLICATION_OPERATION_DEPTH,
};
use opc_tls::{AuthenticatedClientConfig, AuthenticatedServerConfig, TlsConfigBuilder};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

#[derive(Clone)]
struct TestMtls {
    manifest: Arc<SessionReplicationManifest>,
    replicas: Arc<BTreeMap<ReplicaId, TestReplicaMtls>>,
}

#[derive(Clone)]
struct TestReplicaMtls {
    server_config: AuthenticatedServerConfig,
    client_config: AuthenticatedClientConfig,
}

fn topology_replica_id(index: usize) -> ReplicaId {
    ReplicaId::new(format!("test-replica-{index}")).expect("test replica ID")
}

fn topology_spiffe_id(index: usize) -> String {
    format!(
        "spiffe://test-domain/tenant/test/ns/default/sa/session/nf/smf/instance/test-replica-{index}"
    )
}

fn topology_descriptor(index: usize) -> QuorumReplicaDescriptor {
    QuorumReplicaDescriptor::new(
        topology_replica_id(index),
        ReplicaEndpoint::new(format!("test-replica-{index}.invalid"), 7443).expect("test endpoint"),
        ReplicaTlsIdentity::new(topology_spiffe_id(index)).expect("test TLS identity"),
        ReplicaFailureDomain::new(format!("test-failure-domain-{index}"))
            .expect("test failure domain"),
        ReplicaBackingIdentity::new(format!("test-backing-{index}"))
            .expect("test backing identity"),
    )
}

fn test_key() -> SessionKey {
    test_key_with_stable_id(b"test-session")
}

fn test_key_with_stable_id(stable_id: &'static [u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("tenant-a").unwrap(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from_static(stable_id)
            .try_into()
            .expect("valid stable ID"),
    }
}

async fn write_test_record<B>(backend: &B, key: SessionKey, owner: OwnerId) -> StoredSessionRecord
where
    B: SessionBackend + SessionLeaseManager,
{
    let lease = backend
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .expect("acquire test lease");
    let record = test_record(&key, &owner, lease.fence(), Generation::new(1));
    let result = backend
        .compare_and_set(CompareAndSet {
            key,
            lease,
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .expect("write test record");
    assert_eq!(result, CompareAndSetResult::Success);
    record
}

fn test_record(
    key: &SessionKey,
    owner: &OwnerId,
    fence: FenceToken,
    generation: Generation,
) -> StoredSessionRecord {
    StoredSessionRecord {
        key: key.clone(),
        generation,
        owner: owner.clone(),
        fence,
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("test").unwrap(),
        expires_at: None,
        payload: EncryptedSessionPayload::new(b"payload"),
    }
}

fn nested_refresh_replication_entry(
    sequence: u64,
    key: SessionKey,
    owner: OwnerId,
    fence: FenceToken,
    ttl: Duration,
) -> ReplicationEntry {
    ReplicationEntry {
        sequence,
        tx_id: format!("ttl-boundary-{sequence}")
            .try_into()
            .expect("valid transaction ID"),
        op: ReplicationOp::Batch {
            ops: vec![ReplicationOp::RefreshTtl {
                key,
                owner,
                fence,
                ttl,
                expires_at: Timestamp::now_utc(),
            }],
        },
        timestamp: Timestamp::now_utc(),
    }
}

fn forged_refresh_deadline_entry(
    sequence: u64,
    key: SessionKey,
    owner: OwnerId,
    fence: FenceToken,
) -> ReplicationEntry {
    let timestamp = Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH);
    let expires_at = Timestamp::from_offset_datetime(
        time::OffsetDateTime::UNIX_EPOCH
            .checked_add(time::Duration::seconds(61))
            .expect("representable test deadline"),
    );
    ReplicationEntry {
        sequence,
        tx_id: format!("forged-deadline-{sequence}")
            .try_into()
            .expect("valid transaction ID"),
        op: ReplicationOp::RefreshTtl {
            key,
            owner,
            fence,
            ttl: Duration::from_secs(60),
            expires_at,
        },
        timestamp,
    }
}

fn operation_tree_at_depth(depth: usize) -> ReplicationOp {
    let mut op = ReplicationOp::Batch { ops: Vec::new() };
    for _ in 1..depth {
        op = ReplicationOp::Batch { ops: vec![op] };
    }
    op
}

fn over_depth_replication_entry(sequence: u64) -> ReplicationEntry {
    ReplicationEntry {
        sequence,
        tx_id: format!("over-depth-{sequence}")
            .try_into()
            .expect("valid transaction ID"),
        op: operation_tree_at_depth(MAX_REPLICATION_OPERATION_DEPTH + 1),
        timestamp: Timestamp::now_utc(),
    }
}

fn over_count_replication_entry(sequence: u64) -> ReplicationEntry {
    let ops = (0..MAX_REPLICATION_OPERATIONS_PER_ENTRY)
        .map(|_| ReplicationOp::Batch { ops: Vec::new() })
        .collect();
    ReplicationEntry {
        sequence,
        tx_id: format!("over-count-{sequence}")
            .try_into()
            .expect("valid transaction ID"),
        op: ReplicationOp::Batch { ops },
        timestamp: Timestamp::now_utc(),
    }
}

fn payload_replication_entry(sequence: u64, payload_len: usize) -> ReplicationEntry {
    let key = test_key();
    let owner = OwnerId::new("log-owner").expect("log owner");
    let mut record = test_record(&key, &owner, FenceToken::new(sequence), Generation::new(1));
    record.payload = EncryptedSessionPayload::new(vec![255; payload_len]);
    let timestamp = Timestamp::now_utc();
    ReplicationEntry {
        sequence,
        tx_id: format!("log-{sequence}")
            .try_into()
            .expect("valid transaction ID"),
        op: ReplicationOp::CompareAndSet {
            key,
            expected_generation: None,
            credential_id: sequence,
            guard_expires_at: timestamp,
            new_record: record,
        },
        timestamp,
    }
}

fn low_json_payload_replication_entry(sequence: u64, payload_len: usize) -> ReplicationEntry {
    let mut entry = payload_replication_entry(sequence, 0);
    let ReplicationOp::CompareAndSet { new_record, .. } = &mut entry.op else {
        unreachable!("payload fixture is a CAS entry");
    };
    new_record.payload = EncryptedSessionPayload::new(vec![0; payload_len]);
    entry
}

fn wire_operation_nodes_mut<'a>(
    request: &'a mut serde_json::Value,
    entry_pointer: &str,
) -> &'a mut Vec<serde_json::Value> {
    request
        .pointer_mut(entry_pointer)
        .expect("wire replication entry")["operation_nodes"]
        .as_array_mut()
        .expect("flat wire replication operation nodes")
}

fn wire_refresh_ttl_node_mut<'a>(
    request: &'a mut serde_json::Value,
    entry_pointer: &str,
) -> &'a mut serde_json::Value {
    wire_operation_nodes_mut(request, entry_pointer)
        .iter_mut()
        .find(|node| node.get("RefreshTtl").is_some())
        .expect("wire refresh-TTL operation node")
}

#[derive(Clone)]
struct ReplicationDispatchSpy {
    inner: FakeSessionBackend,
    compare_and_set_calls: Arc<AtomicUsize>,
    refresh_calls: Arc<AtomicUsize>,
    batch_calls: Arc<AtomicUsize>,
    replicate_calls: Arc<AtomicUsize>,
    rebuild_calls: Arc<AtomicUsize>,
    acquire_calls: Arc<AtomicUsize>,
    renew_calls: Arc<AtomicUsize>,
}

impl ReplicationDispatchSpy {
    fn new() -> Self {
        Self {
            inner: FakeSessionBackend::new(),
            compare_and_set_calls: Arc::new(AtomicUsize::new(0)),
            refresh_calls: Arc::new(AtomicUsize::new(0)),
            batch_calls: Arc::new(AtomicUsize::new(0)),
            replicate_calls: Arc::new(AtomicUsize::new(0)),
            rebuild_calls: Arc::new(AtomicUsize::new(0)),
            acquire_calls: Arc::new(AtomicUsize::new(0)),
            renew_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait::async_trait]
impl SessionBackend for ReplicationDispatchSpy {
    async fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities().await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.inner.get(key).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        self.compare_and_set_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.compare_and_set(op).await
    }

    async fn delete_fenced(&self, lease: &opc_session_store::LeaseGuard) -> Result<(), StoreError> {
        self.inner.delete_fenced(lease).await
    }

    async fn refresh_ttl(
        &self,
        lease: &opc_session_store::LeaseGuard,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        self.refresh_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.refresh_ttl(lease, ttl).await
    }

    async fn batch(
        &self,
        ops: Vec<opc_session_store::SessionOp>,
    ) -> Result<Vec<opc_session_store::SessionOpResult>, StoreError> {
        self.batch_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.batch(ops).await
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.inner.max_replication_sequence().await
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        self.inner.get_replication_log(start, limit).await
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        self.replicate_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.replicate_entry(entry).await
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        self.rebuild_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.rebuild_replication_state(entries).await
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        self.inner.next_lease_info().await
    }
}

#[async_trait::async_trait]
impl SessionLeaseManager for ReplicationDispatchSpy {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<opc_session_store::LeaseGuard, opc_session_store::LeaseError> {
        self.acquire_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.acquire(key, owner, ttl).await
    }

    async fn renew(
        &self,
        lease: &opc_session_store::LeaseGuard,
        ttl: Duration,
    ) -> Result<opc_session_store::LeaseGuard, opc_session_store::LeaseError> {
        self.renew_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.renew(lease, ttl).await
    }

    async fn release(
        &self,
        lease: opc_session_store::LeaseGuard,
    ) -> Result<(), opc_session_store::LeaseError> {
        self.inner.release(lease).await
    }
}

#[derive(Clone)]
struct CancellableStallBackend {
    inner: FakeSessionBackend,
    active: Arc<AtomicUsize>,
    get_calls: Arc<AtomicUsize>,
    delete_calls: Arc<AtomicUsize>,
    delete_effects: Arc<AtomicUsize>,
}

impl CancellableStallBackend {
    fn new() -> Self {
        Self {
            inner: FakeSessionBackend::new(),
            active: Arc::new(AtomicUsize::new(0)),
            get_calls: Arc::new(AtomicUsize::new(0)),
            delete_calls: Arc::new(AtomicUsize::new(0)),
            delete_effects: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn stall(&self) {
        self.active.fetch_add(1, Ordering::SeqCst);
        let _active = ActiveOperation(Arc::clone(&self.active));
        std::future::pending::<()>().await;
    }
}

struct ActiveOperation(Arc<AtomicUsize>);

impl Drop for ActiveOperation {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl SessionBackend for CancellableStallBackend {
    async fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities().await
    }

    async fn get(&self, _key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        self.stall().await;
        unreachable!("stall completes only when its future is cancelled")
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        self.inner.compare_and_set(op).await
    }

    async fn delete_fenced(
        &self,
        _lease: &opc_session_store::LeaseGuard,
    ) -> Result<(), StoreError> {
        self.delete_calls.fetch_add(1, Ordering::SeqCst);
        // Model an adapter that crossed its effect boundary but has not yet
        // made the exact outcome observable to the RPC handler.
        self.delete_effects.fetch_add(1, Ordering::SeqCst);
        self.stall().await;
        unreachable!("stall completes only when its future is cancelled")
    }

    async fn refresh_ttl(
        &self,
        lease: &opc_session_store::LeaseGuard,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        self.inner.refresh_ttl(lease, ttl).await
    }

    async fn batch(
        &self,
        ops: Vec<opc_session_store::SessionOp>,
    ) -> Result<Vec<opc_session_store::SessionOpResult>, StoreError> {
        self.inner.batch(ops).await
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.inner.max_replication_sequence().await
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        self.inner.get_replication_log(start, limit).await
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        self.inner.replicate_entry(entry).await
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        self.inner.rebuild_replication_state(entries).await
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        self.inner.next_lease_info().await
    }
}

#[async_trait::async_trait]
impl SessionLeaseManager for CancellableStallBackend {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<opc_session_store::LeaseGuard, opc_session_store::LeaseError> {
        self.inner.acquire(key, owner, ttl).await
    }

    async fn renew(
        &self,
        lease: &opc_session_store::LeaseGuard,
        ttl: Duration,
    ) -> Result<opc_session_store::LeaseGuard, opc_session_store::LeaseError> {
        self.inner.renew(lease, ttl).await
    }

    async fn release(
        &self,
        lease: opc_session_store::LeaseGuard,
    ) -> Result<(), opc_session_store::LeaseError> {
        self.inner.release(lease).await
    }
}

#[derive(Clone)]
struct MalformedReplicationOutputBackend {
    inner: ReplicationDispatchSpy,
    log_calls: Arc<AtomicUsize>,
    watch_calls: Arc<AtomicUsize>,
}

impl MalformedReplicationOutputBackend {
    fn new() -> Self {
        Self {
            inner: ReplicationDispatchSpy::new(),
            log_calls: Arc::new(AtomicUsize::new(0)),
            watch_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait::async_trait]
impl SessionBackend for MalformedReplicationOutputBackend {
    async fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities().await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.inner.get(key).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        self.inner.compare_and_set(op).await
    }

    async fn delete_fenced(&self, lease: &opc_session_store::LeaseGuard) -> Result<(), StoreError> {
        self.inner.delete_fenced(lease).await
    }

    async fn refresh_ttl(
        &self,
        lease: &opc_session_store::LeaseGuard,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        self.inner.refresh_ttl(lease, ttl).await
    }

    async fn batch(
        &self,
        ops: Vec<opc_session_store::SessionOp>,
    ) -> Result<Vec<opc_session_store::SessionOpResult>, StoreError> {
        self.inner.batch(ops).await
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.inner.max_replication_sequence().await
    }

    async fn get_replication_log(
        &self,
        _start: u64,
        _limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        self.log_calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![over_depth_replication_entry(1)])
    }

    async fn watch(
        &self,
        _start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        self.watch_calls.fetch_add(1, Ordering::SeqCst);
        Ok(futures_util::stream::iter(vec![Ok(over_count_replication_entry(1))]).boxed())
    }
}

#[async_trait::async_trait]
impl SessionLeaseManager for MalformedReplicationOutputBackend {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<opc_session_store::LeaseGuard, opc_session_store::LeaseError> {
        self.inner.acquire(key, owner, ttl).await
    }

    async fn renew(
        &self,
        lease: &opc_session_store::LeaseGuard,
        ttl: Duration,
    ) -> Result<opc_session_store::LeaseGuard, opc_session_store::LeaseError> {
        self.inner.renew(lease, ttl).await
    }

    async fn release(
        &self,
        lease: opc_session_store::LeaseGuard,
    ) -> Result<(), opc_session_store::LeaseError> {
        self.inner.release(lease).await
    }
}

#[derive(Clone)]
struct RejectingWatchBackend {
    inner: FakeSessionBackend,
    rejection: StoreError,
}

#[async_trait::async_trait]
impl SessionBackend for RejectingWatchBackend {
    async fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities().await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.inner.get(key).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        self.inner.compare_and_set(op).await
    }

    async fn delete_fenced(&self, lease: &opc_session_store::LeaseGuard) -> Result<(), StoreError> {
        self.inner.delete_fenced(lease).await
    }

    async fn refresh_ttl(
        &self,
        lease: &opc_session_store::LeaseGuard,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        self.inner.refresh_ttl(lease, ttl).await
    }

    async fn batch(
        &self,
        ops: Vec<opc_session_store::SessionOp>,
    ) -> Result<Vec<opc_session_store::SessionOpResult>, StoreError> {
        self.inner.batch(ops).await
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.inner.max_replication_sequence().await
    }

    async fn watch(
        &self,
        _start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        Err(self.rejection.clone())
    }
}

#[async_trait::async_trait]
impl SessionLeaseManager for RejectingWatchBackend {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<opc_session_store::LeaseGuard, opc_session_store::LeaseError> {
        self.inner.acquire(key, owner, ttl).await
    }

    async fn renew(
        &self,
        lease: &opc_session_store::LeaseGuard,
        ttl: Duration,
    ) -> Result<opc_session_store::LeaseGuard, opc_session_store::LeaseError> {
        self.inner.renew(lease, ttl).await
    }

    async fn release(
        &self,
        lease: opc_session_store::LeaseGuard,
    ) -> Result<(), opc_session_store::LeaseError> {
        self.inner.release(lease).await
    }
}

#[derive(Clone)]
struct WrongReplicationRangeBackend {
    inner: FakeSessionBackend,
    page: Arc<Vec<ReplicationEntry>>,
}

#[async_trait::async_trait]
impl SessionBackend for WrongReplicationRangeBackend {
    async fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities().await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.inner.get(key).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        self.inner.compare_and_set(op).await
    }

    async fn delete_fenced(&self, lease: &opc_session_store::LeaseGuard) -> Result<(), StoreError> {
        self.inner.delete_fenced(lease).await
    }

    async fn refresh_ttl(
        &self,
        lease: &opc_session_store::LeaseGuard,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        self.inner.refresh_ttl(lease, ttl).await
    }

    async fn batch(
        &self,
        ops: Vec<opc_session_store::SessionOp>,
    ) -> Result<Vec<opc_session_store::SessionOpResult>, StoreError> {
        self.inner.batch(ops).await
    }

    async fn get_replication_log(
        &self,
        _start: u64,
        _limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        Ok(self.page.as_ref().clone())
    }
}

#[async_trait::async_trait]
impl SessionLeaseManager for WrongReplicationRangeBackend {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<opc_session_store::LeaseGuard, opc_session_store::LeaseError> {
        self.inner.acquire(key, owner, ttl).await
    }

    async fn renew(
        &self,
        lease: &opc_session_store::LeaseGuard,
        ttl: Duration,
    ) -> Result<opc_session_store::LeaseGuard, opc_session_store::LeaseError> {
        self.inner.renew(lease, ttl).await
    }

    async fn release(
        &self,
        lease: opc_session_store::LeaseGuard,
    ) -> Result<(), opc_session_store::LeaseError> {
        self.inner.release(lease).await
    }
}

#[derive(Clone)]
struct OversizedOutputBackend {
    inner: ReplicationDispatchSpy,
    record: StoredSessionRecord,
    log: Arc<Vec<ReplicationEntry>>,
    watch_entry: ReplicationEntry,
    get_calls: Arc<AtomicUsize>,
}

impl OversizedOutputBackend {
    fn new(
        record: StoredSessionRecord,
        log: Vec<ReplicationEntry>,
        watch_entry: ReplicationEntry,
    ) -> Self {
        Self {
            inner: ReplicationDispatchSpy::new(),
            record,
            log: Arc::new(log),
            watch_entry,
            get_calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[async_trait::async_trait]
impl SessionBackend for OversizedOutputBackend {
    async fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::all_enabled()
    }

    async fn get(&self, _key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        self.get_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(self.record.clone()))
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        self.inner
            .compare_and_set_calls
            .fetch_add(1, Ordering::SeqCst);
        assert_eq!(op.key, self.record.key);
        Ok(CompareAndSetResult::Conflict {
            current: Some(self.record.clone()),
        })
    }

    async fn delete_fenced(&self, lease: &opc_session_store::LeaseGuard) -> Result<(), StoreError> {
        self.inner.delete_fenced(lease).await
    }

    async fn refresh_ttl(
        &self,
        lease: &opc_session_store::LeaseGuard,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        self.inner.refresh_ttl(lease, ttl).await
    }

    async fn batch(
        &self,
        ops: Vec<opc_session_store::SessionOp>,
    ) -> Result<Vec<opc_session_store::SessionOpResult>, StoreError> {
        Ok(ops
            .into_iter()
            .map(|_| opc_session_store::SessionOpResult::Get(Ok(Some(self.record.clone()))))
            .collect())
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        Ok(self.log.last().map(|entry| entry.sequence).unwrap_or(0))
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        Ok(self
            .log
            .iter()
            .filter(|entry| entry.sequence >= start)
            .take(limit)
            .cloned()
            .collect())
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        self.inner.replicate_entry(entry).await
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        self.inner.rebuild_replication_state(entries).await
    }

    async fn watch(
        &self,
        _start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        Ok(futures_util::stream::iter(vec![Ok(self.watch_entry.clone())]).boxed())
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        self.inner.next_lease_info().await
    }
}

#[async_trait::async_trait]
impl SessionLeaseManager for OversizedOutputBackend {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<opc_session_store::LeaseGuard, opc_session_store::LeaseError> {
        self.inner.acquire(key, owner, ttl).await
    }

    async fn renew(
        &self,
        lease: &opc_session_store::LeaseGuard,
        ttl: Duration,
    ) -> Result<opc_session_store::LeaseGuard, opc_session_store::LeaseError> {
        self.inner.renew(lease, ttl).await
    }

    async fn release(
        &self,
        lease: opc_session_store::LeaseGuard,
    ) -> Result<(), opc_session_store::LeaseError> {
        self.inner.release(lease).await
    }
}

#[derive(Clone)]
struct SemanticViolationBackend {
    inner: ReplicationDispatchSpy,
    wrong_record: StoredSessionRecord,
    wrong_acquire_lease: opc_session_store::LeaseGuard,
    wrong_renew_lease: opc_session_store::LeaseGuard,
}

#[async_trait::async_trait]
impl SessionBackend for SemanticViolationBackend {
    async fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities::all_enabled()
    }

    async fn get(&self, _key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        Ok(Some(self.wrong_record.clone()))
    }

    async fn compare_and_set(&self, _op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        Ok(CompareAndSetResult::Conflict {
            current: Some(self.wrong_record.clone()),
        })
    }

    async fn delete_fenced(&self, lease: &opc_session_store::LeaseGuard) -> Result<(), StoreError> {
        self.inner.delete_fenced(lease).await
    }

    async fn refresh_ttl(
        &self,
        lease: &opc_session_store::LeaseGuard,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        self.inner.refresh_ttl(lease, ttl).await
    }

    async fn batch(
        &self,
        ops: Vec<opc_session_store::SessionOp>,
    ) -> Result<Vec<opc_session_store::SessionOpResult>, StoreError> {
        Ok(ops
            .into_iter()
            .map(|_| opc_session_store::SessionOpResult::Get(Ok(Some(self.wrong_record.clone()))))
            .collect())
    }
}

#[async_trait::async_trait]
impl SessionLeaseManager for SemanticViolationBackend {
    async fn acquire(
        &self,
        _key: &SessionKey,
        _owner: OwnerId,
        _ttl: Duration,
    ) -> Result<opc_session_store::LeaseGuard, opc_session_store::LeaseError> {
        Ok(self.wrong_acquire_lease.clone())
    }

    async fn renew(
        &self,
        _lease: &opc_session_store::LeaseGuard,
        _ttl: Duration,
    ) -> Result<opc_session_store::LeaseGuard, opc_session_store::LeaseError> {
        Ok(self.wrong_renew_lease.clone())
    }

    async fn release(
        &self,
        lease: opc_session_store::LeaseGuard,
    ) -> Result<(), opc_session_store::LeaseError> {
        self.inner.release(lease).await
    }
}

impl TestMtls {
    fn standard() -> Self {
        Self::from_descriptors((1..=3).map(topology_descriptor).collect())
    }

    fn from_descriptors(descriptors: Vec<QuorumReplicaDescriptor>) -> Self {
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let mut ca_params = rcgen::CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Session Net Test CA");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
        let mut replicas = BTreeMap::new();

        for descriptor in &descriptors {
            let (cert, key) = signed_leaf(
                &ca_cert,
                &ca_key,
                descriptor.replica_id().as_str(),
                descriptor.tls_identity().as_str(),
            );
            let state = identity_state_from_pem(
                &(cert.pem() + &ca_cert.pem()),
                &key.serialize_pem(),
                &ca_cert.pem(),
            );
            let (_state_tx, state_rx) = tokio::sync::watch::channel(Some(state));
            let server_config = TlsConfigBuilder::new(state_rx.clone())
                .allow_any_trusted_peer()
                .build_authenticated_server_config()
                .expect("authenticated server TLS config");
            let client_config = TlsConfigBuilder::new(state_rx)
                .allow_any_trusted_peer()
                .build_authenticated_client_config()
                .expect("authenticated client TLS config");
            replicas.insert(
                descriptor.replica_id().clone(),
                TestReplicaMtls {
                    server_config,
                    client_config,
                },
            );
        }

        let manifest = Arc::new(
            SessionReplicationManifest::try_new_with_epoch(
                SessionClusterId::new("session-net-integration").expect("test cluster ID"),
                SessionConfigurationGeneration::new("v3").expect("test configuration generation"),
                SessionConfigurationEpoch::new(1).expect("configuration epoch"),
                descriptors,
            )
            .expect("test session replication manifest"),
        );
        Self {
            manifest,
            replicas: Arc::new(replicas),
        }
    }

    fn local_binding(&self, index: usize) -> LocalReplicaBinding {
        self.local_binding_for(&topology_replica_id(index))
    }

    fn local_binding_for(&self, replica_id: &ReplicaId) -> LocalReplicaBinding {
        self.manifest
            .bind_local(replica_id.clone())
            .expect("test local replica binding")
    }

    fn remote_binding(&self, local_index: usize, remote_index: usize) -> RemoteReplicaBinding {
        self.local_binding(local_index)
            .bind_remote(topology_replica_id(remote_index))
            .expect("test remote replica binding")
    }

    fn server_config(&self, index: usize) -> AuthenticatedServerConfig {
        self.server_config_for(&topology_replica_id(index))
    }

    fn server_config_for(&self, replica_id: &ReplicaId) -> AuthenticatedServerConfig {
        self.replicas
            .get(replica_id)
            .expect("test server TLS config")
            .server_config
            .clone()
    }

    fn client_config(&self, index: usize) -> AuthenticatedClientConfig {
        self.client_config_for(&topology_replica_id(index))
    }

    fn client_config_for(&self, replica_id: &ReplicaId) -> AuthenticatedClientConfig {
        self.replicas
            .get(replica_id)
            .expect("test client TLS config")
            .client_config
            .clone()
    }
}

fn mtls_configs() -> TestMtls {
    TestMtls::standard()
}

fn pinned_resolver(addr: SocketAddr) -> RemoteAddrResolver {
    Arc::new(move || Box::pin(async move { Ok(addr) }))
}

fn remote_backend(
    mtls: &TestMtls,
    local_index: usize,
    remote_index: usize,
    addr: SocketAddr,
    deadline: Option<Duration>,
) -> RemoteSessionBackend {
    RemoteSessionBackend::new_with_resolver(
        mtls.remote_binding(local_index, remote_index),
        pinned_resolver(addr),
        mtls.client_config(local_index),
        deadline,
    )
}

async fn authenticated_raw_stream(
    mtls: &TestMtls,
    local_index: usize,
    remote_index: usize,
    addr: SocketAddr,
    response_frame_size: usize,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    authenticated_raw_stream_with_epoch(mtls, local_index, remote_index, addr, response_frame_size)
        .await
        .0
}

async fn authenticated_raw_stream_with_epoch(
    mtls: &TestMtls,
    local_index: usize,
    remote_index: usize,
    addr: SocketAddr,
    response_frame_size: usize,
) -> (
    tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
    uuid::Uuid,
) {
    use opc_session_net::protocol::{
        read_frame, write_frame, CONTRACT_VERSION, CURRENT_CONTRACT_PROFILE, SESSION_NET_ALPN,
    };
    use opc_session_net::{Request, Response};

    let mut client_config = mtls
        .client_config(local_index)
        .rustls_config()
        .as_ref()
        .clone();
    client_config.alpn_protocols = vec![SESSION_NET_ALPN.to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect authenticated raw client");
    let server_name = rustls_pki_types::ServerName::IpAddress(addr.ip().into());
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .expect("establish authenticated raw client");

    let binding = mtls.remote_binding(local_index, remote_index);
    let nonce = uuid::Uuid::new_v4();
    let requested_response_frame_size =
        u32::try_from(response_frame_size).expect("test response frame size fits the v4 wire");
    write_frame(
        &mut stream,
        &Request::Hello {
            contract_version: CONTRACT_VERSION,
            contract_profile: Some(CURRENT_CONTRACT_PROFILE),
            node_id: binding.local_replica_id().as_str().to_string(),
            expected_server_replica_id: Some(binding.remote_replica_id().as_str().to_string()),
            cluster_id: Some(binding.cluster_id().as_str().to_string()),
            configuration_id: Some(binding.configuration_id().to_hex()),
            configuration_epoch: Some(binding.configuration_epoch().get()),
            handshake_nonce: Some(nonce),
            requested_response_frame_size: Some(requested_response_frame_size),
        },
    )
    .await
    .expect("write authenticated raw hello");
    let hello: Response = read_frame(&mut stream, response_frame_size)
        .await
        .expect("read authenticated raw hello acknowledgement");
    let epoch = match hello {
        Response::HelloAck {
            contract_version: CONTRACT_VERSION,
            handshake_nonce: Some(echoed),
            accepted_response_frame_size: Some(accepted),
            cas_idempotency_epoch: Some(epoch),
            ..
        } if echoed == nonce && accepted == requested_response_frame_size => epoch,
        other => panic!("unexpected authenticated hello acknowledgement: {other:?}"),
    };
    (stream, epoch)
}

#[cfg(feature = "insecure-test")]
fn hello_ack_for(
    request: &opc_session_net::Request,
    contract_version: u32,
) -> opc_session_net::Response {
    let opc_session_net::Request::Hello {
        node_id,
        expected_server_replica_id,
        cluster_id,
        configuration_id,
        configuration_epoch,
        handshake_nonce,
        requested_response_frame_size,
        ..
    } = request
    else {
        panic!("test handshake helper requires a hello request");
    };
    opc_session_net::Response::HelloAck {
        contract_version,
        contract_profile: (contract_version == opc_session_net::protocol::CONTRACT_VERSION)
            .then_some(opc_session_net::protocol::CURRENT_CONTRACT_PROFILE),
        server_replica_id: expected_server_replica_id.clone(),
        accepted_client_replica_id: Some(node_id.clone()),
        cluster_id: cluster_id.clone(),
        configuration_id: configuration_id.clone(),
        configuration_epoch: *configuration_epoch,
        handshake_nonce: *handshake_nonce,
        cas_idempotency_epoch: Some(uuid::Uuid::from_u128(1)),
        accepted_response_frame_size: (contract_version
            == opc_session_net::protocol::CONTRACT_VERSION)
            .then_some(
                requested_response_frame_size
                    .unwrap_or(opc_session_net::protocol::DEFAULT_MAX_FRAME_SIZE as u32),
            ),
        server_request_frame_size: (contract_version
            == opc_session_net::protocol::CONTRACT_VERSION)
            .then_some(opc_session_net::protocol::DEFAULT_MAX_FRAME_SIZE as u32),
    }
}

fn signed_leaf(
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
    common_name: &str,
    spiffe_id: &str,
) -> (rcgen::Certificate, rcgen::KeyPair) {
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::Ia5String::try_from(spiffe_id).expect("spiffe id"),
    ));
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(1);

    let key = rcgen::KeyPair::generate().expect("leaf key");
    let cert = params.signed_by(&key, ca_cert, ca_key).expect("leaf cert");
    (cert, key)
}

fn identity_state_from_pem(
    cert_chain_pem: &str,
    key_pem: &str,
    ca_pem: &str,
) -> opc_identity::IdentityState {
    let ca_certs = parse_certs_pem(ca_pem).expect("ca pem");
    let cert_chain = parse_certs_pem(cert_chain_pem).expect("cert chain pem");
    let trust_domain = opc_identity::TrustDomain::new("test-domain").expect("trust domain");
    let mut trust_bundles = opc_identity::TrustBundleSet::new();
    trust_bundles.insert(TrustBundle {
        trust_domain,
        certificates: ca_certs,
    });
    let private_key = parse_key_pem(key_pem).expect("key pem");
    build_identity_state(cert_chain, private_key, trust_bundles).expect("identity state")
}

async fn start_server(
    mtls: &TestMtls,
    server_index: usize,
) -> (
    SocketAddr,
    FakeSessionBackend,
    opc_session_net::server::ServerHandle,
) {
    let backend = FakeSessionBackend::new();
    start_server_with_backend(mtls, server_index, backend).await
}

async fn start_server_with_backend<B>(
    mtls: &TestMtls,
    server_index: usize,
    backend: B,
) -> (SocketAddr, B, opc_session_net::server::ServerHandle)
where
    B: SessionStoreBackend + Clone + 'static,
{
    start_server_with_backend_for(mtls, topology_replica_id(server_index), backend).await
}

async fn start_server_with_backend_for<B>(
    mtls: &TestMtls,
    server_replica_id: ReplicaId,
    backend: B,
) -> (SocketAddr, B, opc_session_net::server::ServerHandle)
where
    B: SessionStoreBackend + Clone + 'static,
{
    let server = SessionReplicationServer::new(
        Arc::new(backend.clone()),
        mtls.server_config_for(&server_replica_id),
        mtls.local_binding_for(&server_replica_id),
    );
    let (handle, addr) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    (addr, backend, handle)
}

#[tokio::test]
async fn mtls_backend_deadlines_disconnects_and_shutdown_release_stalled_work() {
    use opc_session_net::protocol::write_frame;
    use opc_session_net::Request;

    let mtls = mtls_configs();
    let backend = CancellableStallBackend::new();
    let key = test_key_with_stable_id(b"backend-lifetime");
    let owner = OwnerId::new("backend-lifetime-owner").expect("owner");
    let lease = backend
        .acquire(&key, owner, Duration::from_secs(60))
        .await
        .expect("seed lease before server starts");
    let server = SessionReplicationServer::new(
        Arc::new(backend.clone()),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
    .with_backend_operation_timeout(Duration::from_millis(75))
    .with_backend_operation_concurrency(1)
    .with_idle_timeout(Duration::from_millis(250));
    let (handle, addr) = server
        .listen("127.0.0.1:0".parse().expect("loopback"))
        .await
        .expect("start bounded server");
    let remote = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_secs(1)));

    let read_error = remote
        .get(&key)
        .await
        .expect_err("stalled read must reach its backend deadline");
    assert!(matches!(read_error, StoreError::BackendUnavailable(_)));
    assert_eq!(backend.get_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.active.load(Ordering::SeqCst), 0);

    let mutation_error = remote
        .delete_fenced(&lease)
        .await
        .expect_err("post-effect stall must have an ambiguous outcome");
    assert_eq!(
        mutation_error,
        StoreError::BackendOperationOutcomeUnavailable
    );
    assert_eq!(backend.delete_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.delete_effects.load(Ordering::SeqCst), 1);
    assert_eq!(backend.active.load(Ordering::SeqCst), 0);
    handle.abort_and_wait().await;

    let disconnect_server = SessionReplicationServer::new(
        Arc::new(backend.clone()),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
    .with_backend_operation_timeout(Duration::from_secs(5))
    .with_backend_operation_concurrency(1)
    .with_idle_timeout(Duration::from_millis(250));
    let (disconnect_handle, disconnect_addr) = disconnect_server
        .listen("127.0.0.1:0".parse().expect("loopback"))
        .await
        .expect("start disconnect server");

    let mut disconnected = authenticated_raw_stream(
        &mtls,
        1,
        2,
        disconnect_addr,
        opc_session_net::protocol::DEFAULT_MAX_FRAME_SIZE,
    )
    .await;
    write_frame(&mut disconnected, &Request::Get { key: key.clone() })
        .await
        .expect("write stalled read");
    tokio::time::timeout(Duration::from_secs(1), async {
        while backend.active.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("backend read starts");
    let readiness = remote_backend(
        &mtls,
        1,
        2,
        disconnect_addr,
        Some(Duration::from_millis(500)),
    )
    .probe_replication_head()
    .await;
    assert_eq!(
        readiness,
        Err(ReplicaReadinessFailure::Backend),
        "fresh readiness must fail closed while the read family is exhausted"
    );
    drop(disconnected);
    tokio::time::timeout(Duration::from_secs(1), async {
        while backend.active.load(Ordering::SeqCst) != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("peer disconnect cancels and releases backend work");

    let mut shutdown = authenticated_raw_stream(
        &mtls,
        1,
        2,
        disconnect_addr,
        opc_session_net::protocol::DEFAULT_MAX_FRAME_SIZE,
    )
    .await;
    write_frame(&mut shutdown, &Request::Get { key })
        .await
        .expect("write shutdown-stalled read");
    tokio::time::timeout(Duration::from_secs(1), async {
        while backend.active.load(Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("shutdown backend read starts");
    tokio::time::timeout(Duration::from_secs(1), disconnect_handle.abort_and_wait())
        .await
        .expect("shutdown barrier cancels stalled backend work");
    assert_eq!(backend.active.load(Ordering::SeqCst), 0);
    drop(shutdown);
}

#[tokio::test]
async fn remote_client_rejects_zero_sequence_before_resolve_or_retry() {
    let mtls = mtls_configs();
    let backend = ReplicationDispatchSpy::new();
    let (addr, backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let resolve_calls = Arc::new(AtomicUsize::new(0));
    let resolve_calls_for_request = Arc::clone(&resolve_calls);
    let resolver: RemoteAddrResolver = Arc::new(move || {
        let resolve_calls = Arc::clone(&resolve_calls_for_request);
        Box::pin(async move {
            resolve_calls.fetch_add(1, Ordering::SeqCst);
            Ok(addr)
        })
    });
    let remote = RemoteSessionBackend::new_with_resolver(
        mtls.remote_binding(1, 2),
        resolver,
        mtls.client_config(1),
        Some(Duration::from_millis(500)),
    );

    let error = tokio::time::timeout(
        Duration::from_millis(100),
        remote.replicate_entry(ReplicationEntry {
            sequence: 0,
            tx_id: "untrusted-transaction-canary"
                .try_into()
                .expect("valid transaction ID"),
            op: ReplicationOp::Batch { ops: Vec::new() },
            timestamp: Timestamp::now_utc(),
        }),
    )
    .await
    .expect("local validation must not enter a retry loop")
    .expect_err("sequence zero must be rejected");

    assert_eq!(error, StoreError::InvalidReplicationSequence);
    assert!(!format!("{error:?}").contains("untrusted-transaction-canary"));
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.replicate_calls.load(Ordering::SeqCst), 0);
    let rebuild_error = remote
        .rebuild_replication_state(vec![
            ReplicationEntry {
                sequence: 1,
                tx_id: "prefix-one".try_into().expect("valid transaction ID"),
                op: ReplicationOp::Batch { ops: Vec::new() },
                timestamp: Timestamp::now_utc(),
            },
            ReplicationEntry {
                sequence: 3,
                tx_id: "prefix-gap".try_into().expect("valid transaction ID"),
                op: ReplicationOp::Batch { ops: Vec::new() },
                timestamp: Timestamp::now_utc(),
            },
        ])
        .await
        .expect_err("a malformed rebuild must fail before resolution");
    assert_eq!(rebuild_error, StoreError::InvalidReplicationSequence);
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.rebuild_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.max_replication_sequence().await.unwrap(), 0);

    assert_eq!(remote.max_replication_sequence().await.unwrap(), 0);
    assert!(remote.get_replication_log(1, 1).await.unwrap().is_empty());
    assert_eq!(
        resolve_calls.load(Ordering::SeqCst),
        1,
        "a successful follow-up must reuse one authenticated connection"
    );
    handle.abort();
}

#[tokio::test]
async fn remote_client_rejects_operation_limits_before_resolve_or_dispatch() {
    let mtls = mtls_configs();
    let backend = ReplicationDispatchSpy::new();
    let (addr, backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let resolve_calls = Arc::new(AtomicUsize::new(0));
    let resolve_calls_for_request = Arc::clone(&resolve_calls);
    let resolver: RemoteAddrResolver = Arc::new(move || {
        let resolve_calls = Arc::clone(&resolve_calls_for_request);
        Box::pin(async move {
            resolve_calls.fetch_add(1, Ordering::SeqCst);
            Ok(addr)
        })
    });
    let remote = RemoteSessionBackend::new_with_resolver(
        mtls.remote_binding(1, 2),
        resolver,
        mtls.client_config(1),
        Some(Duration::from_millis(500)),
    );

    for entry in [
        over_depth_replication_entry(1),
        over_count_replication_entry(1),
    ] {
        let error = remote
            .replicate_entry(entry)
            .await
            .expect_err("an over-limit entry must be rejected locally");
        assert_eq!(error, StoreError::ReplicationOperationLimitExceeded);
    }

    for entry in [
        over_depth_replication_entry(1),
        over_count_replication_entry(1),
    ] {
        let error = remote
            .rebuild_replication_state(vec![entry])
            .await
            .expect_err("an over-limit rebuild must be rejected locally");
        assert_eq!(error, StoreError::ReplicationOperationLimitExceeded);
    }

    assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.replicate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.rebuild_calls.load(Ordering::SeqCst), 0);
    handle.abort();
}

#[tokio::test]
async fn remote_client_rejects_invalid_ttls_before_resolve_or_retry() {
    let mtls = mtls_configs();
    let backend = ReplicationDispatchSpy::new();
    let (addr, backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let key = test_key_with_stable_id(b"client-invalid-ttl-canary");
    let owner = OwnerId::new("client-invalid-ttl-owner").expect("test owner");
    let lease = backend
        .inner
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .expect("seed lease directly in backend");
    let initial_sequence = backend.max_replication_sequence().await.unwrap();
    let resolve_calls = Arc::new(AtomicUsize::new(0));
    let resolve_calls_for_request = Arc::clone(&resolve_calls);
    let resolver: RemoteAddrResolver = Arc::new(move || {
        let resolve_calls = Arc::clone(&resolve_calls_for_request);
        Box::pin(async move {
            resolve_calls.fetch_add(1, Ordering::SeqCst);
            Ok(addr)
        })
    });
    let remote = RemoteSessionBackend::new_with_resolver(
        mtls.remote_binding(1, 2),
        resolver,
        mtls.client_config(1),
        Some(Duration::from_millis(500)),
    );

    let acquire_error = remote
        .acquire(&key, owner.clone(), Duration::MAX)
        .await
        .expect_err("invalid acquire TTL must be rejected locally");
    assert_eq!(
        acquire_error,
        opc_session_store::LeaseError::InvalidSessionTtl
    );
    let renew_error = remote
        .renew(&lease, Duration::MAX)
        .await
        .expect_err("invalid renew TTL must be rejected locally");
    assert_eq!(
        renew_error,
        opc_session_store::LeaseError::InvalidSessionTtl
    );
    let refresh_error = remote
        .refresh_ttl(&lease, Duration::MAX)
        .await
        .expect_err("invalid refresh TTL must be rejected locally");
    assert_eq!(refresh_error, StoreError::InvalidSessionTtl);
    let batch_error = remote
        .batch(vec![opc_session_store::SessionOp::RefreshTtl {
            lease: lease.clone(),
            ttl: Duration::MAX,
        }])
        .await
        .expect_err("invalid batched TTL must be rejected locally");
    assert_eq!(batch_error, StoreError::InvalidSessionTtl);

    let nested = nested_refresh_replication_entry(
        1,
        key.clone(),
        owner.clone(),
        lease.fence(),
        Duration::MAX,
    );
    let replicate_error = remote
        .replicate_entry(nested.clone())
        .await
        .expect_err("invalid nested replicated TTL must be rejected locally");
    assert_eq!(replicate_error, StoreError::InvalidSessionTtl);
    let rebuild_error = remote
        .rebuild_replication_state(vec![nested])
        .await
        .expect_err("invalid nested rebuild TTL must be rejected locally");
    assert_eq!(rebuild_error, StoreError::InvalidSessionTtl);
    let forged = forged_refresh_deadline_entry(1, key, owner, lease.fence());
    let forged_error = remote
        .replicate_entry(forged)
        .await
        .expect_err("a forged replicated deadline must be rejected locally");
    assert_eq!(forged_error, StoreError::InvalidSessionTtl);

    assert_eq!(resolve_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.acquire_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.renew_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.refresh_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.batch_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.replicate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.rebuild_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        backend.max_replication_sequence().await.unwrap(),
        initial_sequence
    );

    assert_eq!(
        remote.max_replication_sequence().await.unwrap(),
        initial_sequence
    );
    assert_eq!(resolve_calls.load(Ordering::SeqCst), 1);
    handle.abort();
}

#[tokio::test]
async fn authenticated_server_rejects_wire_zero_and_keeps_connection_usable() {
    use opc_session_net::protocol::{
        read_frame, write_frame, CONTRACT_VERSION, DEFAULT_MAX_FRAME_SIZE, SESSION_NET_ALPN,
    };
    use opc_session_net::{Request, Response};

    let mtls = mtls_configs();
    let backend = ReplicationDispatchSpy::new();
    let (addr, backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let mut client_config = mtls.client_config(1).rustls_config().as_ref().clone();
    client_config.alpn_protocols = vec![SESSION_NET_ALPN.to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to replication server");
    let server_name = rustls_pki_types::ServerName::IpAddress(addr.ip().into());
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .expect("mutual TLS connection");

    let binding = mtls.remote_binding(1, 2);
    let nonce = uuid::Uuid::new_v4();
    write_frame(
        &mut stream,
        &Request::Hello {
            contract_version: CONTRACT_VERSION,
            contract_profile: Some(opc_session_net::protocol::CURRENT_CONTRACT_PROFILE),
            node_id: binding.local_replica_id().as_str().to_string(),
            expected_server_replica_id: Some(binding.remote_replica_id().as_str().to_string()),
            cluster_id: Some(binding.cluster_id().as_str().to_string()),
            configuration_id: Some(binding.configuration_id().to_hex()),
            configuration_epoch: Some(binding.configuration_epoch().get()),
            handshake_nonce: Some(nonce),
            requested_response_frame_size: Some(DEFAULT_MAX_FRAME_SIZE as u32),
        },
    )
    .await
    .expect("write authenticated hello");
    let hello: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read authenticated hello response");
    assert!(matches!(
        hello,
        Response::HelloAck {
            contract_version: CONTRACT_VERSION,
            handshake_nonce: Some(echoed),
            ..
        } if echoed == nonce
    ));

    let mut malformed = serde_json::to_value(Request::ReplicateEntry {
        entry: ReplicationEntry {
            sequence: 1,
            tx_id: "wire-transaction-canary"
                .try_into()
                .expect("valid transaction ID"),
            op: ReplicationOp::Batch { ops: Vec::new() },
            timestamp: Timestamp::now_utc(),
        },
    })
    .expect("serialize valid replication entry");
    malformed["ReplicateEntry"]["entry"]["sequence"] = serde_json::json!(0);
    write_frame(&mut stream, &malformed)
        .await
        .expect("write zero-sequence replication wire entry");
    let rejected: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read typed sequence rejection");
    assert!(matches!(
        rejected,
        Response::ReplicateEntry(Err(StoreError::InvalidReplicationSequence))
    ));
    assert_eq!(backend.replicate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.max_replication_sequence().await.unwrap(), 0);

    write_frame(
        &mut stream,
        &Request::RebuildReplicationState {
            entries: vec![
                ReplicationEntry {
                    sequence: 1,
                    tx_id: "wire-prefix-one".try_into().expect("valid transaction ID"),
                    op: ReplicationOp::Batch { ops: Vec::new() },
                    timestamp: Timestamp::now_utc(),
                },
                ReplicationEntry {
                    sequence: 3,
                    tx_id: "wire-prefix-gap".try_into().expect("valid transaction ID"),
                    op: ReplicationOp::Batch { ops: Vec::new() },
                    timestamp: Timestamp::now_utc(),
                },
            ],
        },
    )
    .await
    .expect("write malformed replication prefix");
    let rebuild_rejected: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read typed rebuild rejection");
    assert!(matches!(
        rebuild_rejected,
        Response::RebuildReplicationState(Err(StoreError::InvalidReplicationSequence))
    ));
    assert_eq!(backend.rebuild_calls.load(Ordering::SeqCst), 0);

    write_frame(&mut stream, &Request::MaxReplicationSequence)
        .await
        .expect("write follow-up on retained connection");
    let follow_up: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read follow-up on retained connection");
    assert!(matches!(follow_up, Response::MaxReplicationSequence(Ok(0))));

    handle.abort();
}

#[tokio::test]
async fn authenticated_server_rejects_operation_limits_and_keeps_connection_usable() {
    use opc_session_net::protocol::{
        read_frame, write_frame, CONTRACT_VERSION, DEFAULT_MAX_FRAME_SIZE, SESSION_NET_ALPN,
    };
    use opc_session_net::{Request, Response};

    let mtls = mtls_configs();
    let backend = ReplicationDispatchSpy::new();
    let (addr, backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let mut client_config = mtls.client_config(1).rustls_config().as_ref().clone();
    client_config.alpn_protocols = vec![SESSION_NET_ALPN.to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to replication server");
    let server_name = rustls_pki_types::ServerName::IpAddress(addr.ip().into());
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .expect("mutual TLS connection");

    let binding = mtls.remote_binding(1, 2);
    let nonce = uuid::Uuid::new_v4();
    write_frame(
        &mut stream,
        &Request::Hello {
            contract_version: CONTRACT_VERSION,
            contract_profile: Some(opc_session_net::protocol::CURRENT_CONTRACT_PROFILE),
            node_id: binding.local_replica_id().as_str().to_string(),
            expected_server_replica_id: Some(binding.remote_replica_id().as_str().to_string()),
            cluster_id: Some(binding.cluster_id().as_str().to_string()),
            configuration_id: Some(binding.configuration_id().to_hex()),
            configuration_epoch: Some(binding.configuration_epoch().get()),
            handshake_nonce: Some(nonce),
            requested_response_frame_size: Some(DEFAULT_MAX_FRAME_SIZE as u32),
        },
    )
    .await
    .expect("write authenticated hello");
    let hello: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read authenticated hello response");
    assert!(matches!(
        hello,
        Response::HelloAck {
            contract_version: CONTRACT_VERSION,
            handshake_nonce: Some(echoed),
            ..
        } if echoed == nonce
    ));

    let mut request = serde_json::to_value(Request::ReplicateEntry {
        entry: ReplicationEntry {
            sequence: 1,
            tx_id: "wire-over-depth".try_into().expect("valid transaction ID"),
            op: operation_tree_at_depth(MAX_REPLICATION_OPERATION_DEPTH),
            timestamp: Timestamp::now_utc(),
        },
    })
    .expect("serialize exact-depth replication entry");
    let nodes = wire_operation_nodes_mut(&mut request, "/ReplicateEntry/entry");
    nodes.insert(
        nodes.len() - 1,
        serde_json::json!({"Batch": {"child_count": 1}}),
    );
    write_frame(&mut stream, &request)
        .await
        .expect("write over-depth replication wire entry");

    let rejected: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read typed depth-limit rejection");
    assert!(matches!(
        rejected,
        Response::ReplicateEntry(Err(StoreError::ReplicationOperationLimitExceeded))
    ));
    assert_eq!(backend.replicate_calls.load(Ordering::SeqCst), 0);

    let mut exact_count = over_count_replication_entry(1);
    let ReplicationOp::Batch { ops } = &mut exact_count.op else {
        unreachable!("fixture operation is fixed");
    };
    ops.pop().expect("remove one operation for exact limit");
    let mut request = serde_json::to_value(Request::RebuildReplicationState {
        entries: vec![exact_count],
    })
    .expect("serialize exact-width replication rebuild");
    let nodes = wire_operation_nodes_mut(&mut request, "/RebuildReplicationState/entries/0");
    let leaf = nodes.last().expect("last operation node").clone();
    nodes[0]["Batch"]["child_count"] = serde_json::json!(MAX_REPLICATION_OPERATIONS_PER_ENTRY);
    nodes.push(leaf);
    write_frame(&mut stream, &request)
        .await
        .expect("write over-count replication rebuild wire request");

    let rejected: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read typed count-limit rejection");
    assert!(matches!(
        rejected,
        Response::RebuildReplicationState(Err(StoreError::ReplicationOperationLimitExceeded))
    ));
    assert_eq!(backend.rebuild_calls.load(Ordering::SeqCst), 0);

    write_frame(&mut stream, &Request::MaxReplicationSequence)
        .await
        .expect("write valid follow-up on retained connection");
    let follow_up: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read valid follow-up on retained connection");
    assert!(matches!(follow_up, Response::MaxReplicationSequence(Ok(0))));

    handle.abort();
}

#[tokio::test]
async fn authenticated_server_rejects_malformed_backend_log_and_watch_output() {
    use opc_session_net::protocol::{
        read_frame, write_frame, CONTRACT_VERSION, DEFAULT_MAX_FRAME_SIZE, SESSION_NET_ALPN,
    };
    use opc_session_net::{Request, Response};

    let mtls = mtls_configs();
    let backend = MalformedReplicationOutputBackend::new();
    let (addr, backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let mut client_config = mtls.client_config(1).rustls_config().as_ref().clone();
    client_config.alpn_protocols = vec![SESSION_NET_ALPN.to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to replication server");
    let server_name = rustls_pki_types::ServerName::IpAddress(addr.ip().into());
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .expect("mutual TLS connection");

    let binding = mtls.remote_binding(1, 2);
    let nonce = uuid::Uuid::new_v4();
    write_frame(
        &mut stream,
        &Request::Hello {
            contract_version: CONTRACT_VERSION,
            contract_profile: Some(opc_session_net::protocol::CURRENT_CONTRACT_PROFILE),
            node_id: binding.local_replica_id().as_str().to_string(),
            expected_server_replica_id: Some(binding.remote_replica_id().as_str().to_string()),
            cluster_id: Some(binding.cluster_id().as_str().to_string()),
            configuration_id: Some(binding.configuration_id().to_hex()),
            configuration_epoch: Some(binding.configuration_epoch().get()),
            handshake_nonce: Some(nonce),
            requested_response_frame_size: Some(DEFAULT_MAX_FRAME_SIZE as u32),
        },
    )
    .await
    .expect("write authenticated hello");
    let hello: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read authenticated hello");
    assert!(matches!(
        hello,
        Response::HelloAck {
            contract_version: CONTRACT_VERSION,
            handshake_nonce: Some(echoed),
            ..
        } if echoed == nonce
    ));

    write_frame(
        &mut stream,
        &Request::GetReplicationLog { start: 1, limit: 1 },
    )
    .await
    .expect("request malformed backend log output");
    let response: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read rejected backend log output");
    assert!(matches!(
        response,
        Response::GetReplicationLog(Err(StoreError::ReplicationOperationLimitExceeded))
    ));
    assert_eq!(backend.log_calls.load(Ordering::SeqCst), 1);

    write_frame(&mut stream, &Request::Watch { start_sequence: 1 })
        .await
        .expect("request malformed backend watch output");
    let response: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read watch acknowledgement");
    assert!(matches!(response, Response::WatchStream));
    let response: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read rejected backend watch output");
    assert!(matches!(
        response,
        Response::WatchEntry(Err(StoreError::ReplicationOperationLimitExceeded))
    ));
    assert_eq!(backend.watch_calls.load(Ordering::SeqCst), 1);

    assert!(
        read_frame::<_, Response>(&mut stream, DEFAULT_MAX_FRAME_SIZE)
            .await
            .is_err(),
        "corrupt watch metadata terminates the authenticated connection"
    );

    handle.abort();
}

#[tokio::test]
async fn mtls_remote_watch_preserves_typed_initial_rejection_and_remains_usable() {
    let mtls = mtls_configs();
    let rejection = StoreError::ReplicationWatchCatchUpRequired;
    let backend = RejectingWatchBackend {
        inner: FakeSessionBackend::new(),
        rejection: rejection.clone(),
    };
    let (addr, _backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let remote = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_secs(2)));

    let actual = match remote.watch(1).await {
        Ok(_) => panic!("initial watch rejection must fail the watch call"),
        Err(error) => error,
    };
    assert_eq!(actual, rejection);
    assert_eq!(
        remote
            .max_replication_sequence()
            .await
            .expect("independent request after rejected watch"),
        0
    );

    handle.abort_and_wait().await;
}

#[tokio::test]
async fn authenticated_server_rejects_wire_invalid_ttls_and_keeps_connection_usable() {
    use opc_session_net::protocol::{
        read_frame, write_frame, CONTRACT_VERSION, DEFAULT_MAX_FRAME_SIZE, SESSION_NET_ALPN,
    };
    use opc_session_net::{Request, Response};

    let mtls = mtls_configs();
    let backend = ReplicationDispatchSpy::new();
    let (addr, backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let mut client_config = mtls.client_config(1).rustls_config().as_ref().clone();
    client_config.alpn_protocols = vec![SESSION_NET_ALPN.to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let tcp = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect to replication server");
    let server_name = rustls_pki_types::ServerName::IpAddress(addr.ip().into());
    let mut stream = connector
        .connect(server_name, tcp)
        .await
        .expect("mutual TLS connection");

    let binding = mtls.remote_binding(1, 2);
    let nonce = uuid::Uuid::new_v4();
    write_frame(
        &mut stream,
        &Request::Hello {
            contract_version: CONTRACT_VERSION,
            contract_profile: Some(opc_session_net::protocol::CURRENT_CONTRACT_PROFILE),
            node_id: binding.local_replica_id().as_str().to_string(),
            expected_server_replica_id: Some(binding.remote_replica_id().as_str().to_string()),
            cluster_id: Some(binding.cluster_id().as_str().to_string()),
            configuration_id: Some(binding.configuration_id().to_hex()),
            configuration_epoch: Some(binding.configuration_epoch().get()),
            handshake_nonce: Some(nonce),
            requested_response_frame_size: Some(DEFAULT_MAX_FRAME_SIZE as u32),
        },
    )
    .await
    .expect("write authenticated hello");
    let hello: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read authenticated hello response");
    assert!(matches!(
        hello,
        Response::HelloAck {
            contract_version: CONTRACT_VERSION,
            handshake_nonce: Some(echoed),
            ..
        } if echoed == nonce
    ));

    let key = test_key_with_stable_id(b"wire-invalid-ttl-canary");
    let owner = OwnerId::new("wire-invalid-ttl-owner").expect("test owner");
    let mut invalid_acquire = serde_json::to_value(Request::AcquireLease {
        key: key.clone(),
        owner: owner.clone(),
        ttl: Duration::from_secs(60),
    })
    .expect("serialize valid acquire request");
    invalid_acquire["AcquireLease"]["ttl"] =
        serde_json::to_value(Duration::MAX).expect("serialize hostile TTL");
    write_frame(&mut stream, &invalid_acquire)
        .await
        .expect("write invalid acquire TTL");
    let acquire_rejected: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read typed acquire TTL rejection");
    assert!(matches!(
        acquire_rejected,
        Response::AcquireLease(Err(opc_session_store::LeaseError::InvalidSessionTtl))
    ));
    assert_eq!(backend.acquire_calls.load(Ordering::SeqCst), 0);

    write_frame(
        &mut stream,
        &Request::AcquireLease {
            key: key.clone(),
            owner: owner.clone(),
            ttl: Duration::from_secs(60),
        },
    )
    .await
    .expect("write valid acquire on retained connection");
    let lease = match read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read valid acquire response")
    {
        Response::AcquireLease(Ok(lease)) => lease,
        response => panic!("unexpected valid acquire response: {response:?}"),
    };
    assert_eq!(backend.acquire_calls.load(Ordering::SeqCst), 1);

    let mut invalid_renew = serde_json::to_value(Request::RenewLease {
        lease: lease.clone(),
        ttl: Duration::from_secs(60),
    })
    .expect("serialize valid renew request");
    invalid_renew["RenewLease"]["ttl"] =
        serde_json::to_value(Duration::MAX).expect("serialize hostile TTL");
    write_frame(&mut stream, &invalid_renew)
        .await
        .expect("write invalid renew TTL");
    let renew_rejected: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read typed renew TTL rejection");
    assert!(matches!(
        renew_rejected,
        Response::RenewLease(Err(opc_session_store::LeaseError::InvalidSessionTtl))
    ));
    assert_eq!(backend.renew_calls.load(Ordering::SeqCst), 0);

    let mut invalid_refresh = serde_json::to_value(Request::RefreshTtl {
        lease: lease.clone(),
        ttl: Duration::from_secs(60),
    })
    .expect("serialize valid refresh request");
    invalid_refresh["RefreshTtl"]["ttl"] =
        serde_json::to_value(Duration::MAX).expect("serialize hostile TTL");
    write_frame(&mut stream, &invalid_refresh)
        .await
        .expect("write invalid refresh TTL");
    let refresh_rejected: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read typed refresh TTL rejection");
    assert!(matches!(
        refresh_rejected,
        Response::RefreshTtl(Err(StoreError::InvalidSessionTtl))
    ));
    assert_eq!(backend.refresh_calls.load(Ordering::SeqCst), 0);

    let mut invalid_batch = serde_json::to_value(Request::Batch {
        ops: vec![opc_session_store::SessionOp::RefreshTtl {
            lease: lease.clone(),
            ttl: Duration::from_secs(60),
        }],
    })
    .expect("serialize valid batch request");
    invalid_batch["Batch"]["ops"][0]["RefreshTtl"]["ttl"] =
        serde_json::to_value(Duration::MAX).expect("serialize hostile TTL");
    write_frame(&mut stream, &invalid_batch)
        .await
        .expect("write invalid batched TTL");
    let batch_rejected: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read typed batch TTL rejection");
    assert!(matches!(
        batch_rejected,
        Response::Batch(Err(StoreError::InvalidSessionTtl))
    ));
    assert_eq!(backend.batch_calls.load(Ordering::SeqCst), 0);

    let nested = nested_refresh_replication_entry(
        1,
        key.clone(),
        owner.clone(),
        lease.fence(),
        Duration::from_secs(60),
    );
    let mut replicate_request = serde_json::to_value(Request::ReplicateEntry {
        entry: nested.clone(),
    })
    .expect("serialize valid nested replicated TTL");
    wire_refresh_ttl_node_mut(&mut replicate_request, "/ReplicateEntry/entry")["RefreshTtl"]
        ["ttl"] = serde_json::to_value(Duration::MAX).expect("serialize hostile TTL");
    write_frame(&mut stream, &replicate_request)
        .await
        .expect("write invalid nested replicated TTL wire request");
    let replicate_rejected: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read typed replicated TTL rejection");
    assert!(matches!(
        replicate_rejected,
        Response::ReplicateEntry(Err(StoreError::InvalidSessionTtl))
    ));
    assert_eq!(backend.replicate_calls.load(Ordering::SeqCst), 0);

    let mut rebuild_request = serde_json::to_value(Request::RebuildReplicationState {
        entries: vec![nested],
    })
    .expect("serialize valid nested rebuild TTL");
    wire_refresh_ttl_node_mut(&mut rebuild_request, "/RebuildReplicationState/entries/0")
        ["RefreshTtl"]["ttl"] = serde_json::to_value(Duration::MAX).expect("serialize hostile TTL");
    write_frame(&mut stream, &rebuild_request)
        .await
        .expect("write invalid nested rebuild TTL wire request");
    let rebuild_rejected: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read typed rebuild TTL rejection");
    assert!(matches!(
        rebuild_rejected,
        Response::RebuildReplicationState(Err(StoreError::InvalidSessionTtl))
    ));
    assert_eq!(backend.rebuild_calls.load(Ordering::SeqCst), 0);

    let mut deadline_entry = forged_refresh_deadline_entry(1, key, owner, lease.fence());
    let valid_expires_at = deadline_entry.timestamp;
    let forged_expires_at = match &mut deadline_entry.op {
        ReplicationOp::RefreshTtl { expires_at, .. } => {
            let forged = *expires_at;
            *expires_at = valid_expires_at;
            forged
        }
        _ => unreachable!("fixture operation is fixed"),
    };
    let mut forged_request = serde_json::to_value(Request::ReplicateEntry {
        entry: deadline_entry,
    })
    .expect("serialize valid replicated deadline");
    wire_refresh_ttl_node_mut(&mut forged_request, "/ReplicateEntry/entry")["RefreshTtl"]
        ["expires_at"] =
        serde_json::to_value(forged_expires_at).expect("serialize forged deadline");
    write_frame(&mut stream, &forged_request)
        .await
        .expect("write forged replicated deadline wire request");
    let forged_rejected: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read typed forged-deadline rejection");
    assert!(matches!(
        forged_rejected,
        Response::ReplicateEntry(Err(StoreError::InvalidSessionTtl))
    ));
    assert_eq!(backend.replicate_calls.load(Ordering::SeqCst), 0);

    write_frame(&mut stream, &Request::MaxReplicationSequence)
        .await
        .expect("write follow-up on retained connection");
    let follow_up: Response = read_frame(&mut stream, DEFAULT_MAX_FRAME_SIZE)
        .await
        .expect("read follow-up on retained connection");
    assert!(matches!(follow_up, Response::MaxReplicationSequence(Ok(_))));

    handle.abort();
}

#[tokio::test]
async fn remote_restore_scan_round_trips_scope_and_pagination_over_mtls() {
    let mtls = mtls_configs();
    let backend = SqliteSessionBackend::in_memory().expect("in-memory SQLite");
    let (addr, backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let remote = remote_backend(&mtls, 1, 2, addr, None);

    assert!(remote.capabilities().await.restore_scan);
    let empty = remote
        .scan_restore_records(RestoreScanRequest::all(1))
        .await
        .expect("empty remote restore scan");
    assert!(empty.records.is_empty());
    assert!(empty.complete);

    let owner_a = OwnerId::new("owner-a").unwrap();
    let owner_b = OwnerId::new("owner-b").unwrap();
    write_test_record(&backend, test_key_with_stable_id(b"a"), owner_a.clone()).await;
    write_test_record(&backend, test_key_with_stable_id(b"b"), owner_b.clone()).await;
    write_test_record(&backend, test_key_with_stable_id(b"c"), owner_a.clone()).await;

    let request = RestoreScanRequest {
        scope: RestoreScanScope {
            owner: Some(owner_a),
            ..RestoreScanScope::all()
        },
        cursor: None,
        limit: 1,
    };
    let first = remote
        .scan_restore_records(request.clone())
        .await
        .expect("first remote restore page");
    assert_eq!(first.records.len(), 1);
    assert_eq!(first.records[0].key.stable_id.as_ref(), b"a");
    assert_eq!(first.excluded_count, 0);
    assert!(!first.complete);
    assert!(first.next_cursor.is_some());

    let second = remote
        .scan_restore_records(RestoreScanRequest {
            cursor: first.next_cursor,
            ..request
        })
        .await
        .expect("second remote restore page");
    assert_eq!(second.records.len(), 1);
    assert_eq!(second.records[0].key.stable_id.as_ref(), b"c");
    assert_eq!(second.excluded_count, 1);
    assert!(second.complete);
    assert!(second.next_cursor.is_none());

    let large_key = test_key_with_stable_id(b"d");
    let large_lease = backend
        .acquire(&large_key, owner_b.clone(), Duration::from_secs(60))
        .await
        .expect("acquire large-record lease");
    let mut large_record = test_record(
        &large_key,
        &owner_b,
        large_lease.fence(),
        Generation::new(1),
    );
    let minimum_frame_size = opc_session_net::protocol::MIN_NEGOTIATED_FRAME_SIZE;
    large_record.payload = EncryptedSessionPayload::new(vec![255; minimum_frame_size]);
    assert_eq!(
        backend
            .compare_and_set(CompareAndSet {
                key: large_key,
                lease: large_lease,
                expected_generation: None,
                new_record: large_record,
            })
            .await
            .expect("write large record"),
        CompareAndSetResult::Success
    );

    let prefix = remote
        .scan_restore_records(RestoreScanRequest::all(3))
        .await
        .expect("obtain durable cursor before the large record");
    assert_eq!(prefix.records.len(), 3);
    let large_record_cursor = prefix
        .next_cursor
        .expect("large record follows the bounded prefix");

    let small_frame_remote = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_secs(1)))
        .with_max_frame_size(minimum_frame_size);
    let oversized = small_frame_remote
        .scan_restore_records(RestoreScanRequest {
            scope: RestoreScanScope::all(),
            cursor: Some(large_record_cursor),
            limit: 1,
        })
        .await
        .expect_err("a single record larger than the peer frame must fail closed");
    assert_eq!(
        oversized,
        StoreError::RestoreScanResponseTooLarge {
            max_bytes: minimum_frame_size
        }
    );

    handle.abort();
}

#[tokio::test]
async fn remote_restore_capability_matches_executable_backend_support() {
    let mtls = mtls_configs();
    let mut capabilities = BackendCapabilities::all_enabled();
    capabilities.restore_scan = false;
    let backend = FakeSessionBackend::with_capabilities(capabilities);
    let (addr, _backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let remote = remote_backend(&mtls, 1, 2, addr, None);

    assert!(!remote.capabilities().await.restore_scan);
    assert_eq!(
        remote
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
            .expect_err("remote backend without scan capability must fail closed"),
        StoreError::CapabilityNotSupported("restore_scan".to_string())
    );

    handle.abort();
}

#[tokio::test]
async fn unusable_client_or_server_frame_bound_masks_restore_capability() {
    let mtls = mtls_configs();
    let (addr, _backend, handle) = start_server(&mtls, 2).await;
    let below_minimum = opc_session_net::protocol::MIN_NEGOTIATED_FRAME_SIZE.saturating_sub(1);
    let constrained_client = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_secs(1)))
        .with_max_frame_size(below_minimum);

    assert!(!constrained_client.capabilities().await.restore_scan);
    assert_eq!(
        constrained_client
            .scan_restore_records(RestoreScanRequest::all(1))
            .await
            .expect_err("client frame below the protocol minimum must reject scans"),
        StoreError::RestoreScanResponseTooLarge {
            max_bytes: below_minimum
        }
    );
    handle.abort();

    let backend = FakeSessionBackend::new();
    let server = SessionReplicationServer::new(
        Arc::new(backend),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
    .with_max_frame_size(below_minimum);
    let error = server
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .expect_err("server frame bounds below the protocol minimum must fail admission");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn server_rejects_invalid_frame_and_timeout_configuration_before_binding() {
    let mtls = mtls_configs();
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve test address");
    let occupied_addr = occupied.local_addr().expect("reserved test address");

    let below_minimum = opc_session_net::protocol::MIN_NEGOTIATED_FRAME_SIZE.saturating_sub(1);
    let server = SessionReplicationServer::new(
        Arc::new(FakeSessionBackend::new()),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
    .with_max_connections(0);
    let error = server
        .listen(occupied_addr)
        .await
        .expect_err("zero connection slots must fail admission");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let server = SessionReplicationServer::new(
        Arc::new(FakeSessionBackend::new()),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
    .with_max_connections(tokio::sync::Semaphore::MAX_PERMITS.saturating_add(1));
    let error = server
        .listen(occupied_addr)
        .await
        .expect_err("unrepresentable connection slots must fail admission");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let server = SessionReplicationServer::new(
        Arc::new(FakeSessionBackend::new()),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
    .with_max_frame_size(below_minimum);
    let error = server
        .listen(occupied_addr)
        .await
        .expect_err("invalid frame size must win over bind failure");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    let server = SessionReplicationServer::new(
        Arc::new(FakeSessionBackend::new()),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
    .with_max_frame_size(opc_session_net::MAX_NEGOTIATED_FRAME_SIZE + 1);
    let error = server
        .listen(occupied_addr)
        .await
        .expect_err("a u32-representable frame above the profile ceiling must fail before bind");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);

    #[cfg(target_pointer_width = "64")]
    {
        let server = SessionReplicationServer::new(
            Arc::new(FakeSessionBackend::new()),
            mtls.server_config(2),
            mtls.local_binding(2),
        )
        .with_max_frame_size((u32::MAX as usize) + 1);
        let error = server
            .listen(occupied_addr)
            .await
            .expect_err("frame sizes outside the v4 wire range must fail admission");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    let server = SessionReplicationServer::new(
        Arc::new(FakeSessionBackend::new()),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
    .with_idle_timeout(Duration::MAX);
    let error = server
        .listen(occupied_addr)
        .await
        .expect_err("unrepresentable write deadlines must fail admission");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn negotiated_response_limit_contains_malicious_backend_outputs_by_family() {
    let mtls = mtls_configs();
    let key = test_key();
    let owner = OwnerId::new("oversized-owner").expect("oversized owner");
    let mut record = test_record(&key, &owner, FenceToken::new(1), Generation::new(1));
    record.payload = EncryptedSessionPayload::new(vec![255; 4096]);
    let backend =
        OversizedOutputBackend::new(record, Vec::new(), payload_replication_entry(1, 4096));
    let (addr, _backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let budget = opc_session_net::protocol::MIN_NEGOTIATED_FRAME_SIZE;
    let remote =
        remote_backend(&mtls, 1, 2, addr, Some(Duration::from_secs(2))).with_max_frame_size(budget);

    let get_error = remote
        .get(&key)
        .await
        .expect_err("oversized Get output must fail in the Get family");
    assert_eq!(
        get_error,
        StoreError::BackendUnavailable("backend unavailable".to_string())
    );
    assert_eq!(remote.max_replication_sequence().await.unwrap(), 0);

    let batch_error = remote
        .batch(vec![opc_session_store::SessionOp::Get { key: key.clone() }])
        .await
        .expect_err("an oversized batch must fail atomically rather than truncate results");
    assert_eq!(
        batch_error,
        StoreError::BackendUnavailable("backend unavailable".to_string())
    );
    assert_eq!(remote.max_replication_sequence().await.unwrap(), 0);

    let mut watch = remote.watch(1).await.expect("open oversized-output watch");
    let watch_error = tokio::time::timeout(Duration::from_secs(2), watch.next())
        .await
        .expect("bounded watch response")
        .expect("watch must emit its terminal typed error")
        .expect_err("oversized watch item must not cross the response boundary");
    assert_eq!(
        watch_error,
        StoreError::BackendUnavailable("backend unavailable".to_string())
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), watch.next())
            .await
            .expect("watch closes after the typed limit error")
            .is_none(),
        "the server must terminate an oversized watch stream"
    );

    handle.abort_and_wait().await;
}

#[tokio::test]
async fn oversized_cas_outcome_is_typed_and_exact_retry_is_not_redispatched() {
    use opc_session_net::protocol::{read_frame, write_frame, MIN_NEGOTIATED_FRAME_SIZE};
    use opc_session_net::{Request, Response};

    let mtls = mtls_configs();
    let frame_budget = 2 * MIN_NEGOTIATED_FRAME_SIZE;
    let key = test_key_with_stable_id(b"oversized-cas-outcome");
    let owner = OwnerId::new("oversized-cas-owner").expect("oversized CAS owner");
    let mut current = test_record(&key, &owner, FenceToken::new(1), Generation::new(1));
    current.payload = EncryptedSessionPayload::new(vec![255; 4096]);
    let backend = OversizedOutputBackend::new(current, Vec::new(), payload_replication_entry(1, 1));
    let lease = backend
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .expect("seed oversized CAS lease");
    backend
        .inner
        .compare_and_set_calls
        .store(0, Ordering::SeqCst);
    let operation = CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation: None,
        new_record: test_record(&key, &owner, lease.fence(), Generation::new(2)),
    };
    let (addr, backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let (mut stream, idempotency_epoch) =
        authenticated_raw_stream_with_epoch(&mtls, 1, 2, addr, frame_budget).await;
    let request = Request::CompareAndSet {
        op: operation,
        request_id: Some(uuid::Uuid::new_v4().hyphenated().to_string()),
        idempotency_epoch: Some(idempotency_epoch.hyphenated().to_string()),
    };

    for _ in 0..2 {
        write_frame(&mut stream, &request)
            .await
            .expect("write exact CAS attempt");
        let response: Response = read_frame(&mut stream, frame_budget)
            .await
            .expect("read bounded CAS response");
        assert!(
            matches!(
                &response,
                Response::CompareAndSet(Err(StoreError::CasIdempotencyOutcomeUnavailable))
            ),
            "unexpected bounded CAS response: {response:?}"
        );
    }
    assert_eq!(
        backend.inner.compare_and_set_calls.load(Ordering::SeqCst),
        1,
        "the exact retry must replay the cached oversized outcome without backend redispatch"
    );

    handle.abort_and_wait().await;
}

#[tokio::test]
async fn hostile_cas_request_id_is_rejected_before_backend_or_idempotency_cache() {
    use opc_session_net::protocol::{read_frame, write_frame, DEFAULT_MAX_FRAME_SIZE};
    use opc_session_net::{Request, Response};

    let mtls = mtls_configs();
    let backend = ReplicationDispatchSpy::new();
    let key = test_key_with_stable_id(b"cas-request-id");
    let owner = OwnerId::new("cas-request-owner").expect("CAS request owner");
    let lease = backend
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .expect("seed CAS request lease");
    let operation = CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation: None,
        new_record: test_record(&key, &owner, FenceToken::new(1), Generation::new(1)),
    };
    backend.compare_and_set_calls.store(0, Ordering::SeqCst);
    let (addr, backend, handle) = start_server_with_backend(&mtls, 2, backend).await;

    let request_id = uuid::Uuid::new_v4().hyphenated().to_string();
    let mut valid_request = Request::CompareAndSet {
        op: operation,
        request_id: Some(request_id),
        idempotency_epoch: None,
    };
    let mut hostile_wire =
        serde_json::to_value(&valid_request).expect("encode valid canonical CAS request");
    hostile_wire["CompareAndSet"]["request_id"] = serde_json::Value::String("x".repeat(1024));

    let mut hostile = authenticated_raw_stream(&mtls, 1, 2, addr, DEFAULT_MAX_FRAME_SIZE).await;
    write_frame(&mut hostile, &hostile_wire)
        .await
        .expect("write hostile CAS request ID");
    let rejected = tokio::time::timeout(
        Duration::from_secs(2),
        read_frame::<_, Response>(&mut hostile, DEFAULT_MAX_FRAME_SIZE),
    )
    .await
    .expect("server must close a connection carrying a hostile CAS request ID");
    assert!(rejected.is_err());
    assert_eq!(backend.compare_and_set_calls.load(Ordering::SeqCst), 0);

    let (mut valid, epoch) =
        authenticated_raw_stream_with_epoch(&mtls, 1, 2, addr, DEFAULT_MAX_FRAME_SIZE).await;
    let Request::CompareAndSet {
        idempotency_epoch, ..
    } = &mut valid_request
    else {
        unreachable!("constructed CAS request changed family")
    };
    *idempotency_epoch = Some(epoch.to_string());
    for expected_backend_calls in [1, 1] {
        write_frame(&mut valid, &valid_request)
            .await
            .expect("write canonical CAS request");
        let response: Response = read_frame(&mut valid, DEFAULT_MAX_FRAME_SIZE)
            .await
            .expect("read canonical CAS response");
        assert!(matches!(
            response,
            Response::CompareAndSet(Ok(CompareAndSetResult::Success))
        ));
        assert_eq!(
            backend.compare_and_set_calls.load(Ordering::SeqCst),
            expected_backend_calls,
            "only the canonical request may populate and hit the idempotency cache"
        );
    }

    handle.abort_and_wait().await;
}

#[tokio::test]
async fn replication_log_returns_the_largest_contiguous_prefix_for_the_peer_budget() {
    let mtls = mtls_configs();
    let entries = vec![
        payload_replication_entry(1, 4096),
        payload_replication_entry(2, 4096),
        payload_replication_entry(3, 4096),
    ];
    // RFC 3339 fractional seconds are canonically trimmed, so otherwise
    // equivalent entries created at different instants can differ by a few
    // encoded bytes. Every page continuation must fit the chosen one-entry
    // budget; sizing only the first entry makes this test nondeterministic.
    let one_entry_budget = entries
        .iter()
        .map(|entry| {
            serde_json::to_vec(&opc_session_net::Response::GetReplicationLog(Ok(vec![
                entry.clone(),
            ])))
            .expect("size one valid replication entry")
            .len()
        })
        .max()
        .expect("non-empty replication fixture");
    assert!(one_entry_budget >= opc_session_net::protocol::MIN_NEGOTIATED_FRAME_SIZE);
    assert!(
        serde_json::to_vec(&opc_session_net::Response::GetReplicationLog(Ok(entries
            [..2]
            .to_vec(),)))
        .expect("size two valid replication entries")
        .len()
            > one_entry_budget
    );

    let key = test_key();
    let owner = OwnerId::new("log-backend-owner").expect("log backend owner");
    let record = test_record(&key, &owner, FenceToken::new(1), Generation::new(1));
    let backend =
        OversizedOutputBackend::new(record, entries.clone(), payload_replication_entry(4, 0));
    let (addr, _backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let remote = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_secs(2)))
        .with_max_frame_size(one_entry_budget);

    let first = remote
        .get_replication_log(0, 3)
        .await
        .expect("read first bounded log prefix");
    assert_eq!(
        first.iter().map(|entry| entry.sequence).collect::<Vec<_>>(),
        vec![1]
    );
    let second = remote
        .get_replication_log(2, 2)
        .await
        .expect("resume after the first bounded prefix");
    assert_eq!(
        second
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>(),
        vec![2]
    );

    handle.abort_and_wait().await;
}

#[tokio::test]
async fn server_rejects_contiguous_backend_pages_before_or_after_the_requested_range() {
    let mtls = mtls_configs();
    for page in [
        vec![
            payload_replication_entry(1, 0),
            payload_replication_entry(2, 0),
        ],
        vec![
            payload_replication_entry(100, 0),
            payload_replication_entry(101, 0),
        ],
    ] {
        let backend = WrongReplicationRangeBackend {
            inner: FakeSessionBackend::new(),
            page: Arc::new(page),
        };
        let (addr, _backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
        let remote = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_secs(2)));
        assert_eq!(
            remote
                .get_replication_log(3, 2)
                .await
                .expect_err("server must reject a page outside the requested interval"),
            StoreError::InvalidReplicationSequence
        );
        handle.abort_and_wait().await;
    }
}

#[tokio::test]
async fn compacted_replication_cursor_round_trips_with_the_exact_resume_point() {
    let mtls = mtls_configs();
    let backend = FakeSessionBackend::with_limits(FakeBackendLimits {
        max_tracked_keys: 8,
        max_replication_entries: 2,
    });
    for sequence in 1..=3 {
        let mut entry = payload_replication_entry(sequence, 0);
        entry.op = ReplicationOp::Batch { ops: Vec::new() };
        backend
            .replicate_entry(entry)
            .await
            .expect("seed compacting backend");
    }
    let (addr, _backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let remote = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_secs(2)));

    assert_eq!(
        remote
            .get_replication_log(0, 2)
            .await
            .expect_err("sequence one was compacted"),
        StoreError::ReplicationLogCursorCompacted { resume_from: 2 }
    );
    let retained = remote
        .get_replication_log(2, 2)
        .await
        .expect("resume at the first retained sequence");
    assert_eq!(
        retained
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>(),
        vec![2, 3]
    );
    handle.abort_and_wait().await;
}

#[tokio::test]
async fn advertised_payload_limit_is_executable_with_unequal_peer_budgets() {
    let mtls = mtls_configs();
    let client_budget = opc_session_net::protocol::MIN_NEGOTIATED_FRAME_SIZE
        .saturating_mul(2)
        .max(4096);
    let server_budget = client_budget.saturating_mul(2);
    let backend = FakeSessionBackend::new();
    let server = SessionReplicationServer::new(
        Arc::new(backend),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
    .with_max_frame_size(server_budget);
    let (handle, addr) = server
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .expect("listen with unequal frame budgets");
    let remote = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_secs(2)))
        .with_max_frame_size(client_budget);

    let capabilities = remote.capabilities().await;
    let advertised = opc_session_net::protocol::conservative_payload_budget(client_budget);
    assert_eq!(capabilities.max_value_bytes, advertised);
    assert!(advertised > 0);

    let key = test_key_with_stable_id(b"advertised-limit");
    let owner = OwnerId::new("advertised-owner").expect("advertised owner");
    let lease = remote
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .expect("acquire through the smaller peer budget");
    let mut record = test_record(&key, &owner, lease.fence(), Generation::new(1));
    record.payload = EncryptedSessionPayload::new(vec![255; advertised]);
    assert_eq!(
        remote
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease,
                expected_generation: None,
                new_record: record.clone(),
            })
            .await
            .expect("write the exact advertised payload through the smaller request budget"),
        CompareAndSetResult::Success
    );
    assert_eq!(
        remote
            .get(&key)
            .await
            .expect("read the exact advertised payload through the smaller response budget"),
        Some(record)
    );

    let over_key = test_key_with_stable_id(b"advertised-limit-over");
    let over_owner = OwnerId::new("advertised-over-owner").expect("over owner");
    let over_lease = remote
        .acquire(&over_key, over_owner.clone(), Duration::from_secs(60))
        .await
        .expect("acquire one-over lease");
    let mut over_record = test_record(
        &over_key,
        &over_owner,
        over_lease.fence(),
        Generation::new(1),
    );
    over_record.payload = EncryptedSessionPayload::new(vec![0; advertised + 1]);
    assert_eq!(
        remote
            .compare_and_set(CompareAndSet {
                key: over_key.clone(),
                lease: over_lease,
                expected_generation: None,
                new_record: over_record,
            })
            .await,
        Err(StoreError::PayloadTooLarge {
            actual: advertised + 1,
            max: advertised,
        })
    );
    assert_eq!(remote.get(&over_key).await.expect("one-over read"), None);

    handle.abort_and_wait().await;
}

#[tokio::test]
async fn transport_payload_limit_preflights_all_mutation_families_atomically() {
    use opc_session_net::protocol::{read_frame, write_frame};
    use opc_session_net::{Request, Response};

    let mtls = mtls_configs();
    let frame_budget = 2 * opc_session_net::protocol::MIN_NEGOTIATED_FRAME_SIZE;
    let max_payload = opc_session_net::protocol::conservative_payload_budget(frame_budget);
    let backend = ReplicationDispatchSpy::new();
    let key = test_key_with_stable_id(b"transport-payload-limit");
    let owner = OwnerId::new("transport-payload-owner").expect("payload owner");
    let lease = backend
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .expect("seed payload lease");
    backend.acquire_calls.store(0, Ordering::SeqCst);
    let mut record = test_record(&key, &owner, lease.fence(), Generation::new(1));
    record.payload = EncryptedSessionPayload::new(vec![0; max_payload + 1]);
    let operation = CompareAndSet {
        key: key.clone(),
        lease,
        expected_generation: None,
        new_record: record,
    };
    let server = SessionReplicationServer::new(
        Arc::new(backend.clone()),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
    .with_max_frame_size(frame_budget);
    let (handle, addr) = server
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .expect("listen for payload preflight");
    let (mut stream, idempotency_epoch) =
        authenticated_raw_stream_with_epoch(&mtls, 1, 2, addr, frame_budget).await;
    let request_id = uuid::Uuid::new_v4().hyphenated().to_string();

    write_frame(
        &mut stream,
        &Request::CompareAndSet {
            op: operation.clone(),
            request_id: Some(request_id.clone()),
            idempotency_epoch: Some(idempotency_epoch.to_string()),
        },
    )
    .await
    .expect("write one-over CAS");
    let cas: Response = read_frame(&mut stream, frame_budget)
        .await
        .expect("read CAS rejection");
    assert!(matches!(
        cas,
        Response::CompareAndSet(Err(StoreError::PayloadTooLarge { actual, max }))
            if actual == max_payload + 1 && max == max_payload
    ));

    write_frame(
        &mut stream,
        &Request::Batch {
            ops: vec![opc_session_store::SessionOp::CompareAndSet(
                operation.clone(),
            )],
        },
    )
    .await
    .expect("write one-over batch");
    let batch: Response = read_frame(&mut stream, frame_budget)
        .await
        .expect("read batch rejection");
    assert!(matches!(
        batch,
        Response::Batch(Err(StoreError::PayloadTooLarge { actual, max }))
            if actual == max_payload + 1 && max == max_payload
    ));

    let entry = low_json_payload_replication_entry(1, max_payload + 1);
    write_frame(
        &mut stream,
        &Request::ReplicateEntry {
            entry: entry.clone(),
        },
    )
    .await
    .expect("write one-over replication entry");
    let replicate: Response = read_frame(&mut stream, frame_budget)
        .await
        .expect("read replication rejection");
    assert!(matches!(
        replicate,
        Response::ReplicateEntry(Err(StoreError::PayloadTooLarge { actual, max }))
            if actual == max_payload + 1 && max == max_payload
    ));

    write_frame(
        &mut stream,
        &Request::RebuildReplicationState {
            entries: vec![entry],
        },
    )
    .await
    .expect("write one-over rebuild");
    let rebuild: Response = read_frame(&mut stream, frame_budget)
        .await
        .expect("read rebuild rejection");
    assert!(matches!(
        rebuild,
        Response::RebuildReplicationState(Err(StoreError::PayloadTooLarge { actual, max }))
            if actual == max_payload + 1 && max == max_payload
    ));

    assert_eq!(backend.compare_and_set_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.batch_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.replicate_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.rebuild_calls.load(Ordering::SeqCst), 0);

    let mut exact = operation;
    exact.new_record.payload = EncryptedSessionPayload::new(vec![0; max_payload]);
    write_frame(
        &mut stream,
        &Request::CompareAndSet {
            op: exact,
            request_id: Some(request_id),
            idempotency_epoch: Some(idempotency_epoch.to_string()),
        },
    )
    .await
    .expect("write exact CAS after rejected idempotency key");
    let exact: Response = read_frame(&mut stream, frame_budget)
        .await
        .expect("read exact CAS");
    assert!(matches!(
        exact,
        Response::CompareAndSet(Ok(CompareAndSetResult::Success))
    ));
    assert_eq!(backend.compare_and_set_calls.load(Ordering::SeqCst), 1);

    let batch_key = test_key_with_stable_id(b"transport-payload-batch-exact");
    let batch_owner = OwnerId::new("transport-batch-owner").expect("batch owner");
    let batch_lease = backend
        .acquire(&batch_key, batch_owner.clone(), Duration::from_secs(60))
        .await
        .expect("seed exact batch lease");
    let mut batch_record = test_record(
        &batch_key,
        &batch_owner,
        batch_lease.fence(),
        Generation::new(1),
    );
    batch_record.payload = EncryptedSessionPayload::new(vec![0; max_payload]);
    write_frame(
        &mut stream,
        &Request::Batch {
            ops: vec![opc_session_store::SessionOp::CompareAndSet(CompareAndSet {
                key: batch_key,
                lease: batch_lease,
                expected_generation: None,
                new_record: batch_record,
            })],
        },
    )
    .await
    .expect("write exact batch");
    let exact_batch: Response = read_frame(&mut stream, frame_budget)
        .await
        .expect("read exact batch");
    assert!(matches!(
        exact_batch,
        Response::Batch(Ok(results))
            if matches!(results.as_slice(), [opc_session_store::SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Success))])
    ));
    assert_eq!(backend.batch_calls.load(Ordering::SeqCst), 1);

    let replication_key = test_key_with_stable_id(b"transport-payload-replication-exact");
    let replication_owner = OwnerId::new("transport-replication-owner").expect("rep owner");
    let replication_lease = backend
        .acquire(
            &replication_key,
            replication_owner.clone(),
            Duration::from_secs(60),
        )
        .await
        .expect("seed exact replication lease");
    let mut replication_record = test_record(
        &replication_key,
        &replication_owner,
        replication_lease.fence(),
        Generation::new(1),
    );
    replication_record.payload = EncryptedSessionPayload::new(vec![0; max_payload]);
    let timestamp = Timestamp::now_utc();
    let exact_entry = ReplicationEntry {
        sequence: backend
            .max_replication_sequence()
            .await
            .expect("read sequence before exact replication")
            + 1,
        tx_id: "transport-exact-replication"
            .try_into()
            .expect("valid transaction ID"),
        op: ReplicationOp::CompareAndSet {
            key: replication_key,
            expected_generation: None,
            credential_id: replication_lease.credential_id(),
            guard_expires_at: replication_lease.expires_at(),
            new_record: replication_record,
        },
        timestamp,
    };
    write_frame(
        &mut stream,
        &Request::ReplicateEntry {
            entry: exact_entry.clone(),
        },
    )
    .await
    .expect("write exact replication entry");
    let exact_replicate: Response = read_frame(&mut stream, frame_budget)
        .await
        .expect("read exact replication response");
    assert!(matches!(exact_replicate, Response::ReplicateEntry(Ok(()))));
    assert_eq!(backend.replicate_calls.load(Ordering::SeqCst), 1);

    let rebuild_entries = backend
        .get_replication_log(1, MAX_REPLICATION_LOG_PAGE_ENTRIES)
        .await
        .expect("read coherent exact-payload log for rebuild");

    write_frame(
        &mut stream,
        &Request::RebuildReplicationState {
            entries: rebuild_entries,
        },
    )
    .await
    .expect("write exact rebuild");
    let exact_rebuild: Response = read_frame(&mut stream, frame_budget)
        .await
        .expect("read exact rebuild response");
    assert!(matches!(
        exact_rebuild,
        Response::RebuildReplicationState(Ok(()))
    ));
    assert_eq!(backend.rebuild_calls.load(Ordering::SeqCst), 1);

    handle.abort_and_wait().await;
}

#[tokio::test]
async fn server_rejects_backend_outputs_bound_to_a_different_request() {
    let mtls = mtls_configs();
    let inner = ReplicationDispatchSpy::new();
    let requested_key = test_key_with_stable_id(b"semantic-request-key");
    let requested_owner = OwnerId::new("semantic-request-owner").expect("requested owner");
    let valid_lease = inner
        .acquire(
            &requested_key,
            requested_owner.clone(),
            Duration::from_secs(60),
        )
        .await
        .expect("seed valid request lease");
    let wrong_key = test_key_with_stable_id(b"semantic-wrong-key");
    let wrong_owner = OwnerId::new("semantic-wrong-owner").expect("wrong owner");
    let wrong_lease = inner
        .acquire(&wrong_key, wrong_owner.clone(), Duration::from_secs(60))
        .await
        .expect("seed wrong lease");
    let wrong_record = test_record(
        &wrong_key,
        &wrong_owner,
        wrong_lease.fence(),
        Generation::new(1),
    );
    let mut forged_renewal = serde_json::to_value(&valid_lease).expect("serialize valid lease");
    forged_renewal["credential_id"] = serde_json::json!(valid_lease.credential_id() + 1);
    let wrong_renew_lease =
        serde_json::from_value(forged_renewal).expect("forge renewal credential");
    let backend = SemanticViolationBackend {
        inner,
        wrong_record,
        wrong_acquire_lease: wrong_lease,
        wrong_renew_lease,
    };
    let (addr, _backend, handle) = start_server_with_backend(&mtls, 2, backend).await;
    let remote = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_secs(2)));
    let expected_store = StoreError::BackendUnavailable("backend unavailable".to_string());

    assert_eq!(
        remote.get(&requested_key).await,
        Err(expected_store.clone())
    );
    let record = test_record(
        &requested_key,
        &requested_owner,
        valid_lease.fence(),
        Generation::new(1),
    );
    assert_eq!(
        remote
            .compare_and_set(CompareAndSet {
                key: requested_key.clone(),
                lease: valid_lease.clone(),
                expected_generation: None,
                new_record: record,
            })
            .await,
        Err(StoreError::CasIdempotencyOutcomeUnavailable)
    );
    let batch_record = test_record(
        &requested_key,
        &requested_owner,
        valid_lease.fence(),
        Generation::new(2),
    );
    assert_eq!(
        remote
            .batch(vec![opc_session_store::SessionOp::CompareAndSet(
                CompareAndSet {
                    key: requested_key.clone(),
                    lease: valid_lease.clone(),
                    expected_generation: None,
                    new_record: batch_record,
                },
            )])
            .await,
        Err(StoreError::BackendOperationOutcomeUnavailable)
    );
    assert_eq!(
        remote
            .batch(vec![opc_session_store::SessionOp::Get {
                key: requested_key.clone(),
            }])
            .await,
        Err(expected_store)
    );
    assert_eq!(
        remote
            .acquire(
                &requested_key,
                requested_owner.clone(),
                Duration::from_secs(60),
            )
            .await,
        Err(opc_session_store::LeaseError::OperationOutcomeUnavailable)
    );
    assert_eq!(
        remote.renew(&valid_lease, Duration::from_secs(60)).await,
        Err(opc_session_store::LeaseError::OperationOutcomeUnavailable)
    );

    handle.abort_and_wait().await;
}

#[tokio::test]
async fn authenticated_continuous_slow_readers_release_slots_and_do_not_block_shutdown() {
    use opc_session_net::protocol::write_frame;
    use opc_session_net::{Request, Response};

    let mtls = mtls_configs();
    let server_budget = opc_session_net::protocol::MIN_NEGOTIATED_FRAME_SIZE.max(1024 * 1024);
    let key = test_key_with_stable_id(b"slow-reader");
    let owner = OwnerId::new("slow-reader-owner").expect("slow-reader owner");
    let mut record = test_record(&key, &owner, FenceToken::new(1), Generation::new(1));
    record.payload = EncryptedSessionPayload::new(vec![255; server_budget / 5]);
    let encoded_response = serde_json::to_vec(&Response::Get(Ok(Some(record.clone()))))
        .expect("encode near-limit response")
        .len();
    assert!(encoded_response < server_budget);
    assert!(encoded_response > server_budget * 3 / 4);

    let backend = OversizedOutputBackend::new(record, Vec::new(), payload_replication_entry(1, 0));
    let server = SessionReplicationServer::new(
        Arc::new(backend.clone()),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
    .with_max_frame_size(server_budget)
    .with_max_connections(1)
    .with_idle_timeout(Duration::from_millis(125));
    let (handle, addr) = server
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .expect("listen for slow-reader test");

    for cycle in 0..3 {
        let baseline_gets = backend.get_calls.load(Ordering::SeqCst);
        let stalled = authenticated_raw_stream(&mtls, 1, 2, addr, server_budget).await;
        let (stalled_reader, mut stalled_writer) = tokio::io::split(stalled);
        let sent = Arc::new(AtomicUsize::new(0));
        let sent_by_writer = Arc::clone(&sent);
        let request_key = key.clone();
        let flood = tokio::spawn(async move {
            loop {
                if write_frame(
                    &mut stalled_writer,
                    &Request::Get {
                        key: request_key.clone(),
                    },
                )
                .await
                .is_err()
                {
                    break;
                }
                sent_by_writer.fetch_add(1, Ordering::SeqCst);
            }
        });

        let probe = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_secs(4)))
            .with_max_frame_size(server_budget);
        let head = tokio::time::timeout(Duration::from_secs(5), probe.max_replication_sequence())
            .await
            .unwrap_or_else(|_| panic!("cycle {cycle}: stalled writer retained the only slot"))
            .unwrap_or_else(|error| panic!("cycle {cycle}: recovery probe failed: {error}"));
        assert_eq!(head, 0);
        assert!(sent.load(Ordering::SeqCst) > 1);
        assert!(backend.get_calls.load(Ordering::SeqCst) > baseline_gets);

        flood.abort();
        let _ = flood.await;
        drop(stalled_reader);
    }

    handle.abort_and_wait().await;

    let shutdown_server = SessionReplicationServer::new(
        Arc::new(backend.clone()),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
    .with_max_frame_size(server_budget)
    .with_max_connections(1)
    .with_idle_timeout(Duration::from_secs(30));
    let (shutdown_handle, shutdown_addr) = shutdown_server
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .expect("listen for blocked-shutdown proof");
    let baseline_gets = backend.get_calls.load(Ordering::SeqCst);
    let stalled = authenticated_raw_stream(&mtls, 1, 2, shutdown_addr, server_budget).await;
    let (stalled_reader, mut stalled_writer) = tokio::io::split(stalled);
    let request_key = key;
    let flood = tokio::spawn(async move {
        loop {
            if write_frame(
                &mut stalled_writer,
                &Request::Get {
                    key: request_key.clone(),
                },
            )
            .await
            .is_err()
            {
                break;
            }
        }
    });
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut previous = baseline_gets;
        let mut plateau_samples = 0_u8;
        loop {
            tokio::time::sleep(Duration::from_millis(25)).await;
            let current = backend.get_calls.load(Ordering::SeqCst);
            if current > baseline_gets && current == previous {
                plateau_samples = plateau_samples.saturating_add(1);
                if plateau_samples >= 4 {
                    break;
                }
            } else {
                plateau_samples = 0;
            }
            previous = current;
        }
    })
    .await
    .expect("near-limit writes must plateau while the authenticated reader remains idle");
    assert!(
        !flood.is_finished(),
        "the request flood must remain live while the server writer is blocked"
    );

    tokio::time::timeout(Duration::from_secs(1), shutdown_handle.abort_and_wait())
        .await
        .expect("abort_and_wait must cancel a handler blocked on a slow reader");
    flood.abort();
    let _ = flood.await;
    drop(stalled_reader);
}

#[tokio::test]
async fn stalled_connection_is_reaped_after_idle_timeout() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let backend = FakeSessionBackend::new();
    let mtls = mtls_configs();
    let server = SessionReplicationServer::new(
        Arc::new(backend),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
    .with_max_connections(1)
    .with_idle_timeout(Duration::from_millis(150));
    let (handle, addr) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();

    // Connect and send only a partial length prefix (2 of 4 bytes), then stall
    // — the classic slowloris move.
    let mut stalled = tokio::net::TcpStream::connect(addr).await.unwrap();
    stalled.write_all(&[0x00, 0x00]).await.unwrap();
    stalled.flush().await.unwrap();

    // The server must reap the idle connection rather than hold its slot
    // forever: a TLS alert byte or EOF are both acceptable, but the read must
    // complete once the server closes the stalled handshake.
    let mut buf = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(5), stalled.read(&mut buf))
        .await
        .expect("server should close the stalled connection within the timeout")
        .expect("read from reaped connection");

    drop(handle);
}

#[tokio::test]
#[cfg(feature = "insecure-test")]
async fn incompatible_client_receives_server_contract_before_disconnect() {
    use opc_session_net::protocol::{read_frame, write_frame, CONTRACT_VERSION};
    use opc_session_net::{Request, Response};

    let server = SessionReplicationServer::new_insecure(Arc::new(FakeSessionBackend::new()));
    let (handle, addr) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    write_frame(
        &mut stream,
        &Request::Hello {
            contract_version: CONTRACT_VERSION - 1,
            contract_profile: None,
            node_id: "old-client".to_string(),
            expected_server_replica_id: None,
            cluster_id: None,
            configuration_id: None,
            configuration_epoch: None,
            handshake_nonce: None,
            requested_response_frame_size: None,
        },
    )
    .await
    .unwrap();

    let response: Response = read_frame(&mut stream, 1024).await.unwrap();
    assert!(matches!(
        response,
        Response::HelloAck {
            contract_version,
            ..
        } if contract_version == CONTRACT_VERSION
    ));

    handle.abort();
}

#[tokio::test]
async fn plaintext_rebuild_is_rejected_before_backend_dispatch() {
    let mtls = mtls_configs();
    let backend = FakeSessionBackend::new();
    let server = SessionReplicationServer::new(
        Arc::new(backend.clone()),
        mtls.server_config(2),
        mtls.local_binding(2),
    )
    .with_idle_timeout(Duration::from_millis(150));
    let (handle, addr) = server.listen("127.0.0.1:0".parse().unwrap()).await.unwrap();

    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _ = opc_session_net::protocol::write_frame(
        &mut stream,
        &opc_session_net::Request::Hello {
            contract_version: opc_session_net::protocol::CONTRACT_VERSION,
            contract_profile: Some(opc_session_net::protocol::CURRENT_CONTRACT_PROFILE),
            node_id: "plaintext-peer".to_string(),
            expected_server_replica_id: None,
            cluster_id: None,
            configuration_id: None,
            configuration_epoch: None,
            handshake_nonce: None,
            requested_response_frame_size: Some(
                opc_session_net::protocol::DEFAULT_MAX_FRAME_SIZE as u32,
            ),
        },
    )
    .await;
    let _ = opc_session_net::protocol::write_frame(
        &mut stream,
        &opc_session_net::Request::RebuildReplicationState {
            entries: vec![ReplicationEntry {
                sequence: 1,
                tx_id: "plaintext-rebuild"
                    .try_into()
                    .expect("valid transaction ID"),
                op: ReplicationOp::AcquireLease {
                    key: test_key(),
                    owner: OwnerId::new("plaintext-owner").unwrap(),
                    fence: FenceToken::new(1),
                    credential_id: 1,
                    ttl: Duration::from_secs(60),
                    expires_at: opc_types::Timestamp::now_utc(),
                },
                timestamp: opc_types::Timestamp::now_utc(),
            }],
        },
    )
    .await;

    tokio::time::sleep(Duration::from_millis(250)).await;

    assert_eq!(backend.max_replication_sequence().await.unwrap(), 0);
    handle.abort();
}

#[tokio::test]
async fn abort_and_wait_releases_listener_and_registered_handlers() {
    let mtls = mtls_configs();
    let (addr, _backend, handle) = start_server(&mtls, 2).await;
    let remote = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_millis(750)));
    let key = test_key_with_stable_id(b"shutdown-barrier");

    assert_eq!(
        remote.get(&key).await.expect("warm persistent connection"),
        None
    );
    handle.abort();
    handle.abort_and_wait().await;

    let rebound = tokio::net::TcpListener::bind(addr)
        .await
        .expect("listener address must be reusable when the barrier returns");
    let result = tokio::time::timeout(Duration::from_secs(1), remote.get(&key))
        .await
        .expect("the retired handler must not keep serving past the barrier");
    assert!(
        result.is_err(),
        "the established handler remained usable after abort_and_wait"
    );
    drop(rebound);
}

#[tokio::test]
async fn cancelling_abort_and_wait_cannot_leave_handler_live() {
    let mtls = mtls_configs();
    let (addr, _backend, handle) = start_server(&mtls, 2).await;
    let remote = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_millis(750)));
    let key = test_key_with_stable_id(b"cancelled-shutdown-barrier");

    assert_eq!(
        remote.get(&key).await.expect("warm persistent connection"),
        None
    );

    let mut barrier = Box::pin(handle.abort_and_wait());
    let was_pending = std::future::poll_fn(|cx| {
        let poll = std::future::Future::poll(barrier.as_mut(), cx);
        std::task::Poll::Ready(poll.is_pending())
    })
    .await;
    assert!(was_pending, "the test must cancel a pending barrier");
    drop(barrier);

    let result = tokio::time::timeout(Duration::from_secs(1), remote.get(&key))
        .await
        .expect("cancelled barrier cleanup must remain bounded");
    assert!(
        result.is_err(),
        "a handler served a request after its teardown barrier was cancelled"
    );
}

#[tokio::test]
async fn test_persistent_connection_reconnect_after_restart() {
    let mtls = mtls_configs();
    let (addr, backend, handle) = start_server(&mtls, 2).await;
    let remote = Arc::new(remote_backend(&mtls, 1, 2, addr, None));

    // Warm up the persistent connection.
    let key = test_key();
    assert_eq!(remote.get(&key).await.unwrap(), None);

    // Kill the server. The old TCP connection may linger until the next write.
    handle.abort_and_wait().await;

    // Restart a server on the same address with the same backend state.
    let server = SessionReplicationServer::new(
        Arc::new(backend.clone()),
        mtls.server_config(2),
        mtls.local_binding(2),
    );
    let (handle_new, _addr_new) = server.listen(addr).await.unwrap();

    // The next request must transparently reconnect rather than fail.
    assert_eq!(remote.get(&key).await.unwrap(), None);

    handle_new.abort_and_wait().await;
}

#[tokio::test]
async fn capabilities_uses_cached_success_after_disconnect() {
    let mtls = mtls_configs();
    let (addr, _backend, handle) = start_server(&mtls, 2).await;
    let remote = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_secs(2)));

    let warmed = remote.capabilities().await;
    assert!(
        warmed.atomic_compare_and_set && warmed.monotonic_fencing_token && warmed.batch_write,
        "expected warmed remote capabilities to reflect the full backend"
    );

    handle.abort_and_wait().await;

    let after_disconnect = remote.capabilities().await;
    let mut expected = warmed;
    expected.restore_scan = false;
    assert_eq!(
        after_disconnect, expected,
        "cached backend features may survive transport loss, but restore support must be masked without a fresh negotiation"
    );
}

#[tokio::test]
async fn test_request_after_shutdown_surfaces_error_within_deadline() {
    let mtls = mtls_configs();
    let (addr, _backend, handle) = start_server(&mtls, 2).await;

    // Short deadline so reconnect attempts expire before any restart.
    let remote = Arc::new(remote_backend(
        &mtls,
        1,
        2,
        addr,
        Some(Duration::from_millis(300)),
    ));

    // Warm up the persistent connection.
    let key = test_key();
    assert_eq!(remote.get(&key).await.unwrap(), None);

    // Stop the server and all established handlers before issuing the request.
    handle.abort_and_wait().await;

    let start = tokio::time::Instant::now();
    let result = remote.get(&key).await;
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "expected backend-unavailable error after disconnect, got {result:?}"
    );
    assert!(
        elapsed < Duration::from_secs(1),
        "request hung instead of failing within deadline: {elapsed:?}"
    );
}

#[tokio::test]
#[cfg(feature = "insecure-test")]
async fn direct_cas_dropped_response_stops_unsafe_retry() {
    use opc_session_net::protocol::{read_frame, write_frame, CONTRACT_VERSION};
    use opc_session_net::{Request, Response};
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

    let backend = Arc::new(FakeSessionBackend::new());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let first_cas = Arc::new(AtomicBool::new(true));
    let cas_request_ids = Arc::new(Mutex::new(Vec::new()));

    let server = {
        let backend = backend.clone();
        let first_cas = first_cas.clone();
        let cas_request_ids = cas_request_ids.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let backend = backend.clone();
                let first_cas = first_cas.clone();
                let cas_request_ids = cas_request_ids.clone();
                tokio::spawn(async move {
                    let (mut r, mut w) = stream.into_split();
                    let hello: Request = read_frame(&mut r, 1 << 20).await.unwrap();
                    assert!(matches!(hello, Request::Hello { .. }));
                    write_frame(&mut w, &hello_ack_for(&hello, CONTRACT_VERSION))
                        .await
                        .unwrap();

                    loop {
                        let req: Request = match read_frame(&mut r, 1 << 20).await {
                            Ok(req) => req,
                            Err(_) => return,
                        };
                        match req {
                            Request::AcquireLease { key, owner, ttl } => {
                                let res = backend.acquire(&key, owner, ttl).await;
                                write_frame(&mut w, &Response::AcquireLease(res))
                                    .await
                                    .unwrap();
                            }
                            Request::CompareAndSet { op, request_id, .. } => {
                                let request_id =
                                    request_id.expect("direct CAS must carry an idempotency key");
                                let mut ids = cas_request_ids.lock().await;
                                let first_seen_id = ids.first().cloned();
                                ids.push(request_id.clone());
                                drop(ids);

                                if first_cas.swap(false, Ordering::SeqCst) {
                                    let res = backend.compare_and_set(op).await;
                                    assert_eq!(res.as_ref(), Ok(&CompareAndSetResult::Success));
                                    return;
                                }

                                if first_seen_id.as_ref() == Some(&request_id) {
                                    write_frame(
                                        &mut w,
                                        &Response::CompareAndSet(Ok(CompareAndSetResult::Success)),
                                    )
                                    .await
                                    .unwrap();
                                } else {
                                    let res = backend.compare_and_set(op).await;
                                    write_frame(&mut w, &Response::CompareAndSet(res))
                                        .await
                                        .unwrap();
                                }
                            }
                            other => panic!("unexpected request in CAS retry test: {other:?}"),
                        }
                    }
                });
            }
        })
    };

    let remote = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(2)));
    let key = test_key();
    let owner = OwnerId::new("owner-retry").unwrap();
    let lease = remote
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let result = remote
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: test_record(&key, &owner, lease.fence(), Generation::new(1)),
        })
        .await;

    assert_eq!(result, Err(StoreError::CasIdempotencyOutcomeUnavailable));
    let ids = cas_request_ids.lock().await;
    assert_eq!(ids.len(), 1, "ambiguous direct CAS must not be retried");
    drop(ids);
    assert!(backend
        .get(&key)
        .await
        .expect("inspect backend effect")
        .is_some());

    server.abort();
}

#[tokio::test]
async fn historical_cas_is_rejected_after_server_restart_without_redispatch() {
    use opc_session_net::protocol::{read_frame, write_frame, DEFAULT_MAX_FRAME_SIZE};
    use opc_session_net::{Request, Response};

    let mtls = TestMtls::standard();
    let backend = ReplicationDispatchSpy::new();
    let key = test_key_with_stable_id(b"restart-ambiguous-cas");
    let owner = OwnerId::new("restart-ambiguous-owner").expect("owner");
    let lease = backend
        .acquire(&key, owner.clone(), Duration::from_secs(60))
        .await
        .expect("lease");
    let operation = CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation: None,
        new_record: test_record(&key, &owner, lease.fence(), Generation::new(1)),
    };
    backend.compare_and_set_calls.store(0, Ordering::SeqCst);

    let (first_addr, backend, first_handle) = start_server_with_backend(&mtls, 2, backend).await;
    let (mut first, first_epoch) =
        authenticated_raw_stream_with_epoch(&mtls, 1, 2, first_addr, DEFAULT_MAX_FRAME_SIZE).await;
    let historical = Request::CompareAndSet {
        op: operation,
        request_id: Some(uuid::Uuid::new_v4().hyphenated().to_string()),
        idempotency_epoch: Some(first_epoch.hyphenated().to_string()),
    };
    write_frame(&mut first, &historical)
        .await
        .expect("send historical CAS");
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if backend.get(&key).await.expect("inspect backend").is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("CAS effect before response is intentionally abandoned");
    drop(first);
    first_handle.abort_and_wait().await;

    let (second_addr, backend, second_handle) = start_server_with_backend(&mtls, 2, backend).await;
    let (mut second, second_epoch) =
        authenticated_raw_stream_with_epoch(&mtls, 1, 2, second_addr, DEFAULT_MAX_FRAME_SIZE).await;
    assert_ne!(first_epoch, second_epoch);
    write_frame(&mut second, &historical)
        .await
        .expect("send historical CAS after restart");
    assert!(matches!(
        read_frame(&mut second, DEFAULT_MAX_FRAME_SIZE)
            .await
            .expect("typed stale-epoch rejection"),
        Response::CompareAndSet(Err(StoreError::CasIdempotencyOutcomeUnavailable))
    ));
    assert_eq!(
        backend.compare_and_set_calls.load(Ordering::SeqCst),
        1,
        "historical CAS must not be dispatched after restart"
    );
    second_handle.abort_and_wait().await;
}

/// A deadline that fires mid-exchange must poison the connection: the next
/// request has to reconnect rather than reuse a connection whose pending
/// (stale) response would otherwise be read as the new request's reply.
#[tokio::test]
#[cfg(feature = "insecure-test")]
async fn test_timeout_mid_exchange_forces_reconnect() {
    use opc_session_net::protocol::{read_frame, write_frame, CONTRACT_VERSION};
    use opc_session_net::{Request, Response};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let conn_count = connections.clone();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            let n = conn_count.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut r, mut w) = stream.into_split();
                // Speak the handshake on every connection.
                let hello: Request = match read_frame(&mut r, 1 << 20).await {
                    Ok(req) => req,
                    Err(_) => return,
                };
                assert!(matches!(hello, Request::Hello { .. }));
                write_frame(&mut w, &hello_ack_for(&hello, CONTRACT_VERSION))
                    .await
                    .unwrap();

                loop {
                    let req: Request = match read_frame(&mut r, 1 << 20).await {
                        Ok(req) => req,
                        Err(_) => return,
                    };
                    if n == 0 {
                        // First connection: swallow the request forever so the
                        // client's deadline fires mid-exchange.
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                        return;
                    }
                    // Later connections answer promptly.
                    if let Request::Get { .. } = req {
                        write_frame(&mut w, &Response::Get(Ok(None))).await.unwrap();
                    }
                }
            });
        }
    });

    let remote = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_millis(300)));
    let key = test_key();

    // First request hits the stalling connection and must fail at the
    // deadline rather than hang.
    let start = tokio::time::Instant::now();
    let first = remote.get(&key).await;
    assert!(first.is_err(), "stalled request must surface an error");
    assert!(start.elapsed() < Duration::from_secs(2));

    // Second request must succeed via a NEW connection - reusing the stalled
    // one would read no (or the wrong) response.
    let second = remote.get(&key).await;
    assert_eq!(second.unwrap(), None);
    assert!(
        connections.load(Ordering::SeqCst) >= 2,
        "client must reconnect after a timed-out exchange"
    );
}

#[tokio::test]
async fn durable_readiness_probe_classifies_tls_accept_then_close_as_transport() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test endpoint");
    let addr = listener.local_addr().expect("test endpoint address");
    let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept TLS probe client");
        accepted_tx.send(()).expect("signal accepted connection");
        drop(stream);
    });

    let mtls = mtls_configs();
    let remote = remote_backend(&mtls, 1, 2, addr, Some(Duration::from_millis(250)));

    assert_eq!(
        remote.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Transport)
    );
    accepted_rx.await.expect("raw peer accepted TLS connection");
    server.await.expect("raw peer task");
}

#[tokio::test]
#[cfg(feature = "insecure-test")]
async fn durable_readiness_probe_classifies_stalled_peer_as_timeout() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test endpoint");
    let addr = listener.local_addr().expect("test endpoint address");
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.expect("accept probe client");
        std::future::pending::<()>().await;
    });
    let remote = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_millis(100)));

    assert_eq!(
        remote.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Timeout)
    );
    server.abort();
}

#[tokio::test]
#[cfg(feature = "insecure-test")]
async fn durable_readiness_probe_classifies_version_mismatch_as_protocol() {
    use opc_session_net::protocol::{read_frame, write_frame, CONTRACT_VERSION};
    use opc_session_net::Request;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test endpoint");
    let addr = listener.local_addr().expect("test endpoint address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept probe client");
        let hello: Request = read_frame(&mut stream, 1 << 20)
            .await
            .expect("read client hello");
        assert!(matches!(hello, Request::Hello { .. }));
        write_frame(&mut stream, &hello_ack_for(&hello, CONTRACT_VERSION - 1))
            .await
            .expect("write incompatible hello response");
    });
    let remote = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

    assert_eq!(
        remote.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Protocol)
    );
    server.await.expect("protocol test server");
}

#[tokio::test]
#[cfg(feature = "insecure-test")]
async fn durable_readiness_probe_classifies_redacted_remote_rejection_as_backend() {
    use opc_session_net::protocol::{read_frame, write_frame, CONTRACT_VERSION};
    use opc_session_net::{Request, Response};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test endpoint");
    let addr = listener.local_addr().expect("test endpoint address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept probe client");
        let hello: Request = read_frame(&mut stream, 1 << 20)
            .await
            .expect("read client hello");
        assert!(matches!(hello, Request::Hello { .. }));
        write_frame(&mut stream, &hello_ack_for(&hello, CONTRACT_VERSION))
            .await
            .expect("write hello response");
        let probe: Request = read_frame(&mut stream, 1 << 20)
            .await
            .expect("read replication-head probe");
        assert!(matches!(probe, Request::MaxReplicationSequence));
        write_frame(
            &mut stream,
            &Response::MaxReplicationSequence(Err(StoreError::BackendUnavailable(
                "private-database-path-canary".to_string(),
            ))),
        )
        .await
        .expect("write backend rejection");
    });
    let remote = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

    let failure = remote
        .probe_replication_head()
        .await
        .expect_err("remote rejection must fail readiness");
    assert_eq!(failure, ReplicaReadinessFailure::Backend);
    assert!(!format!("{failure:?}").contains("private-database-path-canary"));
    server.await.expect("backend rejection test server");
}

#[tokio::test]
#[cfg(feature = "insecure-test")]
async fn durable_readiness_probe_classifies_redacted_generic_error_as_protocol() {
    use opc_session_net::protocol::{read_frame, write_frame, CONTRACT_VERSION};
    use opc_session_net::{Request, Response};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test endpoint");
    let addr = listener.local_addr().expect("test endpoint address");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept probe client");
        let hello: Request = read_frame(&mut stream, 1 << 20)
            .await
            .expect("read client hello");
        assert!(matches!(hello, Request::Hello { .. }));
        write_frame(&mut stream, &hello_ack_for(&hello, CONTRACT_VERSION))
            .await
            .expect("write hello response");
        let probe: Request = read_frame(&mut stream, 1 << 20)
            .await
            .expect("read replication-head probe");
        assert!(matches!(probe, Request::MaxReplicationSequence));
        write_frame(
            &mut stream,
            &Response::Error {
                message: "secret-peer-diagnostic-canary".to_string(),
            },
        )
        .await
        .expect("write generic protocol error");
    });
    let remote = RemoteSessionBackend::new_insecure(addr, Some(Duration::from_secs(1)));

    let failure = remote
        .probe_replication_head()
        .await
        .expect_err("a generic error response is not a valid replication head");
    assert_eq!(failure, ReplicaReadinessFailure::Protocol);
    assert!(!format!("{failure:?}").contains("secret-peer-diagnostic-canary"));
    server.await.expect("protocol-error test server");
}

#[tokio::test]
#[cfg(feature = "insecure-test")]
async fn cancelled_readiness_probe_drops_connection_before_the_next_probe() {
    use opc_session_net::protocol::{read_frame, write_frame, CONTRACT_VERSION};
    use opc_session_net::{Request, Response};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test endpoint");
    let addr = listener.local_addr().expect("test endpoint address");
    let (first_probe_tx, first_probe_rx) = tokio::sync::oneshot::channel();
    let (release_stale_tx, release_stale_rx) = tokio::sync::oneshot::channel();
    let (first_connection_done_tx, first_connection_done_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.expect("accept first probe client");
        let hello: Request = read_frame(&mut first, 1 << 20)
            .await
            .expect("read first client hello");
        assert!(matches!(hello, Request::Hello { .. }));
        write_frame(&mut first, &hello_ack_for(&hello, CONTRACT_VERSION))
            .await
            .expect("write first hello response");
        let probe: Request = read_frame(&mut first, 1 << 20)
            .await
            .expect("read first replication-head probe");
        assert!(matches!(probe, Request::MaxReplicationSequence));
        first_probe_tx.send(()).expect("signal stalled exchange");

        release_stale_rx
            .await
            .expect("test releases stale response after cancellation");
        let _ = write_frame(&mut first, &Response::MaxReplicationSequence(Ok(7))).await;
        drop(first);
        first_connection_done_tx
            .send(())
            .expect("signal first connection completion");

        let (mut second, _) = listener.accept().await.expect("accept second probe client");
        let hello: Request = read_frame(&mut second, 1 << 20)
            .await
            .expect("read second client hello");
        assert!(matches!(hello, Request::Hello { .. }));
        write_frame(&mut second, &hello_ack_for(&hello, CONTRACT_VERSION))
            .await
            .expect("write second hello response");
        let probe: Request = read_frame(&mut second, 1 << 20)
            .await
            .expect("read second replication-head probe");
        assert!(matches!(probe, Request::MaxReplicationSequence));
        write_frame(&mut second, &Response::MaxReplicationSequence(Ok(42)))
            .await
            .expect("write fresh replication head");
    });

    let remote = Arc::new(RemoteSessionBackend::new_insecure(
        addr,
        Some(Duration::from_secs(5)),
    ));
    let cancelled = tokio::spawn({
        let remote = remote.clone();
        async move { remote.probe_replication_head().await }
    });
    first_probe_rx
        .await
        .expect("first readiness request reached the peer");
    cancelled.abort();
    assert!(cancelled
        .await
        .expect_err("aborted readiness probe must be cancelled")
        .is_cancelled());
    release_stale_tx
        .send(())
        .expect("release stale first response");
    first_connection_done_rx
        .await
        .expect("first connection was retired");

    let recovered = tokio::time::timeout(Duration::from_secs(2), remote.probe_replication_head())
        .await
        .expect("fresh probe must not stall behind the cancelled exchange")
        .expect("fresh probe must reconnect");
    assert_eq!(
        recovered, 42,
        "the next probe must not consume the stale head from the cancelled exchange"
    );
    server.await.expect("cancellation test server");
}

#[tokio::test]
async fn durable_readiness_probe_classifies_untrusted_peer_as_authentication() {
    let server_mtls = mtls_configs();
    let unrelated_client_mtls = mtls_configs();
    let (addr, _backend, handle) = start_server(&server_mtls, 2).await;
    let remote = RemoteSessionBackend::new_with_resolver(
        server_mtls.remote_binding(1, 2),
        pinned_resolver(addr),
        unrelated_client_mtls.client_config(1),
        Some(Duration::from_millis(400)),
    );

    assert_eq!(
        remote.probe_replication_head().await,
        Err(ReplicaReadinessFailure::Authentication)
    );
    handle.abort();
}
