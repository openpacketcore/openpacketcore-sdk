use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{stream, StreamExt};
use opc_crypto::CryptoEnvelopeV1;
use opc_key::{
    serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyId, SessionAad, AEAD_TAG_LEN,
    AES_256_GCM_SIV_NONCE_LEN,
};
use opc_session_cache::SessionCache;
use opc_session_store::{
    BackendCapabilities, BackendInstanceIdentity, CompareAndSet, CompareAndSetResult,
    FakeSessionBackend, Generation, OwnerId, ReplicationEntry, SessionBackend, SessionKey,
    SessionLeaseManager, SessionOp, SessionOpResult, StateClass, StateType, StoreError,
    StoredSessionRecord,
};
use opc_session_testkit::ConsensusTestCluster;

fn test_session_key() -> SessionKey {
    SessionKey {
        tenant: opc_types::TenantId::new("test-tenant").unwrap(),
        nf_kind: opc_types::NetworkFunctionKind::new("amf").unwrap(),
        key_type: opc_session_store::SessionKeyType::SubscriberContext,
        stable_id: bytes::Bytes::copy_from_slice(&[0xAA; 16])
            .try_into()
            .expect("valid stable ID"),
    }
}

#[test]
fn cache_keys_share_the_model_wide_stable_id_boundary() {
    for (width, accepted) in [
        (0, false),
        (1, true),
        (opc_session_store::STABLE_ID_MAX_BYTES, true),
        (opc_session_store::STABLE_ID_MAX_BYTES + 1, false),
    ] {
        let stable_id = opc_session_store::StableId::new(bytes::Bytes::from(vec![0xa5; width]));
        assert_eq!(stable_id.is_ok(), accepted, "stable ID width {width}");
    }
}

#[tokio::test]
async fn cache_delegates_backend_adapter_instance_identity() {
    let backend: Arc<dyn SessionBackend> = Arc::new(FakeSessionBackend::new());
    let expected = backend.backend_instance_identity();
    let first = SessionCache::new(backend.clone());
    let second = SessionCache::new(backend);

    assert!(expected.is_some());
    assert_eq!(first.backend_instance_identity(), expected);
    assert_eq!(second.backend_instance_identity(), expected);
}

fn make_record(
    key: &SessionKey,
    generation: u64,
    lease: &opc_session_store::LeaseGuard,
) -> StoredSessionRecord {
    let mut record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(generation),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_str("amf-state").unwrap(),
        expires_at: None,
        payload: opc_session_store::EncryptedSessionPayload::new([]),
    };
    let key_id = KeyId::new("cache-test-key").expect("key ID");
    let aad = EnvelopeAad::session(
        record.key.tenant.clone(),
        1,
        SessionAad::new(
            record.key.nf_kind.as_str(),
            "cache-test-keyed-session-digest",
            record.state_type.as_str(),
            record.generation.get(),
            record.fence.get(),
            "cache-test-backend",
        )
        .expect("session AAD"),
    );
    let mut ciphertext_and_tag = b"opaque-cache-fixture".to_vec();
    ciphertext_and_tag.extend_from_slice(&[0xA5; AEAD_TAG_LEN]);
    let envelope = CryptoEnvelopeV1 {
        algorithm: AeadAlgorithm::Aes256GcmSiv,
        key_id: key_id.clone(),
        nonce: vec![0x42; AES_256_GCM_SIV_NONCE_LEN],
        aad: serialize_bound_aad(&aad, &key_id).expect("bound AAD"),
        ciphertext_and_tag,
    }
    .encode()
    .expect("test envelope");
    record.payload =
        opc_session_store::EncryptedSessionPayload::try_envelope(envelope).expect("valid envelope");
    record
}

async fn wait_for_watch_ready(cache: &SessionCache) {
    for _ in 0..50 {
        if cache.is_watch_ready() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("cache watch did not become ready");
}

async fn wait_for_sequence(cache: &SessionCache, sequence: u64) {
    for _ in 0..50 {
        if cache.is_watch_ready() && cache.last_sequence() >= sequence {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "cache did not process sequence {}; last sequence is {}",
        sequence,
        cache.last_sequence()
    );
}

async fn wait_for_cache_len(cache: &SessionCache, expected: usize) {
    for _ in 0..50 {
        if cache.len().await == expected {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!(
        "cache length did not become {}; current length is {}",
        expected,
        cache.len().await
    );
}

enum WatchMode {
    DisabledCapability,
    PendingForever,
}

struct WatchModeBackend {
    inner: Arc<dyn SessionBackend>,
    mode: WatchMode,
}

#[async_trait::async_trait]
impl SessionBackend for WatchModeBackend {
    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        self.inner.backend_instance_identity()
    }

    async fn capabilities(&self) -> BackendCapabilities {
        let mut caps = self.inner.capabilities().await;
        match self.mode {
            WatchMode::DisabledCapability => {
                caps.watch = false;
            }
            WatchMode::PendingForever => {
                caps.watch = true;
                caps.ordered_replication_log = true;
            }
        }
        caps
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

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
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

    async fn watch(
        &self,
        _start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        match self.mode {
            WatchMode::DisabledCapability => {
                Err(StoreError::CapabilityNotSupported("watch".to_string()))
            }
            WatchMode::PendingForever => Ok(stream::pending().boxed()),
        }
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        self.inner.next_lease_info().await
    }
}

#[tokio::test]
async fn test_cache_miss_and_populate() {
    let cluster = ConsensusTestCluster::start(1).await;
    let coord = Arc::new(cluster.store(0));
    let cache = SessionCache::new(coord.clone());
    wait_for_watch_ready(&cache).await;

    let key = test_session_key();
    let owner = OwnerId::from_str("owner").unwrap();
    let lease = coord
        .acquire(&key, owner, Duration::from_secs(10))
        .await
        .unwrap();

    let record = make_record(&key, 1, &lease);
    let op = CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation: None,
        new_record: record.clone(),
    };
    let res = coord.compare_and_set(op).await.unwrap();
    assert_eq!(res, CompareAndSetResult::Success);
    wait_for_sequence(&cache, coord.max_replication_sequence().await.unwrap()).await;

    // Initial cache is empty
    assert_eq!(cache.len().await, 0);

    // Read through: miss, then populate cache
    let retrieved = cache.get(&key).await.unwrap().unwrap();
    assert_eq!(retrieved.generation.get(), 1);
    assert_eq!(cache.len().await, 1);

    // Subsequent read is a cache hit
    let retrieved2 = cache.get(&key).await.unwrap().unwrap();
    assert_eq!(retrieved2.generation.get(), 1);
}

#[tokio::test]
async fn test_update_invalidates_cache() {
    let cluster = ConsensusTestCluster::start(1).await;
    let coord = Arc::new(cluster.store(0));
    let cache = SessionCache::new(coord.clone());
    wait_for_watch_ready(&cache).await;

    let key = test_session_key();
    let owner = OwnerId::from_str("owner").unwrap();
    let lease = coord
        .acquire(&key, owner, Duration::from_secs(10))
        .await
        .unwrap();

    // Write initial record
    let record1 = make_record(&key, 1, &lease);
    coord
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record1,
        })
        .await
        .unwrap();
    wait_for_sequence(&cache, coord.max_replication_sequence().await.unwrap()).await;

    // Read through to cache it
    cache.get(&key).await.unwrap().unwrap();
    assert_eq!(cache.len().await, 1);

    // Update the record authoritatively
    let record2 = make_record(&key, 2, &lease);
    coord
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record: record2,
        })
        .await
        .unwrap();

    wait_for_cache_len(&cache, 0).await;

    // Read through again to get the updated version
    let retrieved = cache.get(&key).await.unwrap().unwrap();
    assert_eq!(retrieved.generation.get(), 2);
    assert_eq!(cache.len().await, 1);
}

#[tokio::test]
async fn invalid_consensus_expiry_does_not_invalidate_a_populated_cache() {
    let cluster = ConsensusTestCluster::start(1).await;
    let coord = Arc::new(cluster.store(0));
    let cache = SessionCache::new(coord.clone());
    wait_for_watch_ready(&cache).await;

    let key = test_session_key();
    let lease = coord
        .acquire(
            &key,
            OwnerId::from_str("expiry-cache-owner").expect("owner"),
            Duration::from_secs(30),
        )
        .await
        .expect("lease");
    coord
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: make_record(&key, 1, &lease),
        })
        .await
        .expect("initial record");
    wait_for_sequence(&cache, coord.max_replication_sequence().await.unwrap()).await;
    cache.get(&key).await.expect("cache read").expect("record");
    assert_eq!(cache.len().await, 1);
    let sequence_before = coord.max_replication_sequence().await.expect("sequence");

    let mut invalid = make_record(&key, 2, &lease);
    invalid.expires_at = Some(
        opc_types::Timestamp::from_str("9999-12-31T23:59:59.999999999Z")
            .expect("far-future expiry"),
    );
    assert_eq!(
        cache
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease,
                expected_generation: Some(Generation::new(1)),
                new_record: invalid,
            })
            .await,
        Err(StoreError::InvalidRecordExpiry)
    );

    assert_eq!(cache.len().await, 1, "preflight must precede invalidation");
    assert_eq!(
        coord.max_replication_sequence().await.expect("sequence"),
        sequence_before,
        "invalid preflight must not publish a watch mutation"
    );
    assert_eq!(
        coord
            .get(&key)
            .await
            .expect("authoritative read")
            .expect("record")
            .generation
            .get(),
        1
    );
}

#[tokio::test]
async fn test_delete_invalidates_cache() {
    let cluster = ConsensusTestCluster::start(1).await;
    let coord = Arc::new(cluster.store(0));
    let cache = SessionCache::new(coord.clone());
    wait_for_watch_ready(&cache).await;

    let key = test_session_key();
    let owner = OwnerId::from_str("owner").unwrap();
    let lease = coord
        .acquire(&key, owner, Duration::from_secs(10))
        .await
        .unwrap();

    // Write initial record
    let record = make_record(&key, 1, &lease);
    coord
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record,
        })
        .await
        .unwrap();
    wait_for_sequence(&cache, coord.max_replication_sequence().await.unwrap()).await;

    // Cache it
    cache.get(&key).await.unwrap().unwrap();
    assert_eq!(cache.len().await, 1);

    // Delete record authoritatively
    coord.delete_fenced(&lease).await.unwrap();

    wait_for_cache_len(&cache, 0).await;

    // Verify it is gone authoritatively too
    let retrieved = cache.get(&key).await.unwrap();
    assert!(retrieved.is_none());
}

#[tokio::test]
async fn test_ttl_refresh_invalidates_cache() {
    let cluster = ConsensusTestCluster::start(1).await;
    let coord = Arc::new(cluster.store(0));
    let cache = SessionCache::new(coord.clone());
    wait_for_watch_ready(&cache).await;

    let key = test_session_key();
    let owner = OwnerId::from_str("owner").unwrap();
    let lease = coord
        .acquire(&key, owner, Duration::from_secs(10))
        .await
        .unwrap();

    // Write record
    let record = make_record(&key, 1, &lease);
    coord
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record,
        })
        .await
        .unwrap();
    wait_for_sequence(&cache, coord.max_replication_sequence().await.unwrap()).await;

    // Cache it
    cache.get(&key).await.unwrap().unwrap();
    assert_eq!(cache.len().await, 1);

    // Refresh TTL
    coord
        .refresh_ttl(&lease, Duration::from_secs(30))
        .await
        .unwrap();

    wait_for_cache_len(&cache, 0).await;
}

#[tokio::test]
async fn test_manual_resync() {
    let cluster = ConsensusTestCluster::start(1).await;
    let coord = Arc::new(cluster.store(0));
    let cache = SessionCache::new(coord.clone());
    wait_for_watch_ready(&cache).await;

    let key = test_session_key();
    let owner = OwnerId::from_str("owner").unwrap();
    let lease = coord
        .acquire(&key, owner, Duration::from_secs(10))
        .await
        .unwrap();

    let record = make_record(&key, 1, &lease);
    coord
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record,
        })
        .await
        .unwrap();
    wait_for_sequence(&cache, coord.max_replication_sequence().await.unwrap()).await;

    // Cache it
    cache.get(&key).await.unwrap().unwrap();
    assert_eq!(cache.len().await, 1);

    // Trigger manual resync
    cache.resync().unwrap();

    wait_for_cache_len(&cache, 0).await;
}

#[tokio::test]
async fn test_no_watch_backend_bypasses_local_cache() {
    let cluster = ConsensusTestCluster::start(1).await;
    let coord = Arc::new(cluster.store(0));

    let key = test_session_key();
    let owner = OwnerId::from_str("owner").unwrap();
    let lease = coord
        .acquire(&key, owner, Duration::from_secs(10))
        .await
        .unwrap();
    let record = make_record(&key, 1, &lease);
    coord
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record,
        })
        .await
        .unwrap();

    let wrapped = Arc::new(WatchModeBackend {
        inner: coord.clone(),
        mode: WatchMode::DisabledCapability,
    });
    let cache = SessionCache::new(wrapped);

    let retrieved = cache.get(&key).await.unwrap().unwrap();
    assert_eq!(retrieved.generation.get(), 1);
    assert_eq!(cache.len().await, 0);
    assert!(!cache.is_watch_ready());
}

#[tokio::test]
async fn test_lagging_watch_bypasses_stale_cached_record() {
    let cluster = ConsensusTestCluster::start(1).await;
    let coord = Arc::new(cluster.store(0));

    let key = test_session_key();
    let owner = OwnerId::from_str("owner").unwrap();
    let lease = coord
        .acquire(&key, owner, Duration::from_secs(10))
        .await
        .unwrap();

    coord
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: make_record(&key, 1, &lease),
        })
        .await
        .unwrap();

    let wrapped = Arc::new(WatchModeBackend {
        inner: coord.clone(),
        mode: WatchMode::PendingForever,
    });
    let cache = SessionCache::new(wrapped);
    wait_for_watch_ready(&cache).await;

    let retrieved = cache.get(&key).await.unwrap().unwrap();
    assert_eq!(retrieved.generation.get(), 1);
    assert_eq!(cache.len().await, 1);

    coord
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record: make_record(&key, 2, &lease),
        })
        .await
        .unwrap();

    let retrieved = cache.get(&key).await.unwrap().unwrap();
    assert_eq!(retrieved.generation.get(), 2);
    assert_eq!(cache.len().await, 0);
    assert!(!cache.is_watch_ready());
}

#[tokio::test]
async fn test_wrapper_compare_and_set_invalidates_immediately() {
    let cluster = ConsensusTestCluster::start(1).await;
    let coord = Arc::new(cluster.store(0));
    let cache = SessionCache::new(coord.clone());
    wait_for_watch_ready(&cache).await;

    let key = test_session_key();
    let owner = OwnerId::from_str("owner").unwrap();
    let lease = coord
        .acquire(&key, owner, Duration::from_secs(10))
        .await
        .unwrap();

    coord
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: make_record(&key, 1, &lease),
        })
        .await
        .unwrap();
    wait_for_sequence(&cache, coord.max_replication_sequence().await.unwrap()).await;

    cache.get(&key).await.unwrap().unwrap();
    assert_eq!(cache.len().await, 1);

    let result = SessionBackend::compare_and_set(
        cache.as_ref(),
        CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record: make_record(&key, 2, &lease),
        },
    )
    .await
    .unwrap();

    assert_eq!(result, CompareAndSetResult::Success);
    assert_eq!(cache.len().await, 0);

    let retrieved = cache.get(&key).await.unwrap().unwrap();
    assert_eq!(retrieved.generation.get(), 2);
}
