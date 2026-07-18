use std::sync::{Arc, Mutex};
use std::time::Duration;

use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_session_store::{
    checked_session_deadline, fake::FakeBackendLimits, BackendCapabilities, Clock,
    EncryptedSessionPayload, EncryptingSessionBackend, FakeSessionBackend, FencedOwnershipCache,
    FencedOwnershipCacheConfig, FencedOwnershipCacheLookup, FencedOwnershipCacheReplayHead,
    FencedOwnershipCacheSeed, FencedOwnershipError, FencedOwnershipKey, FencedOwnershipMetadata,
    FencedOwnershipMutation, FencedOwnershipMutationId, FencedOwnershipNamespace,
    FencedOwnershipRecord, FencedOwnershipStore, FencedOwnershipWatchExit, OwnerId, ReplicationOp,
    ReplicationTxId, SessionBackend, SessionPayloadEncoding, Timestamp, TokioVirtualClock,
    OWNERSHIP_CACHE_MAX_ENTRIES, OWNERSHIP_CACHE_MAX_RETAINED_BYTES, OWNERSHIP_KEY_MAX_BYTES,
    OWNERSHIP_METADATA_MAX_BYTES,
};
use opc_types::{NetworkFunctionKind, TenantId};

#[derive(Debug, Clone)]
struct AdjustableClock(Arc<Mutex<Timestamp>>);

impl AdjustableClock {
    fn new(now: Timestamp) -> Self {
        Self(Arc::new(Mutex::new(now)))
    }

    fn set(&self, now: Timestamp) {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = now;
    }
}

impl Clock for AdjustableClock {
    fn now_utc(&self) -> Timestamp {
        *self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn seconds_after(timestamp: Timestamp, seconds: i64) -> Timestamp {
    Timestamp::from_offset_datetime(
        *timestamp.as_offset_datetime() + time::Duration::seconds(seconds),
    )
}

fn namespace() -> FencedOwnershipNamespace {
    FencedOwnershipNamespace::new(
        TenantId::new("ownership-tests").expect("tenant"),
        NetworkFunctionKind::new("epdg").expect("NF kind"),
    )
}

fn other_namespace() -> FencedOwnershipNamespace {
    FencedOwnershipNamespace::new(
        TenantId::new("other-ownership-tests").expect("other tenant"),
        NetworkFunctionKind::new("epdg").expect("NF kind"),
    )
}

fn key(value: &[u8]) -> FencedOwnershipKey {
    FencedOwnershipKey::new(value).expect("ownership key")
}

fn owner(value: &str) -> OwnerId {
    OwnerId::new(value).expect("owner")
}

fn metadata(value: &[u8]) -> FencedOwnershipMetadata {
    FencedOwnershipMetadata::new(value).expect("metadata")
}

fn proven_seed(
    records: impl IntoIterator<Item = FencedOwnershipRecord>,
    committed_through: u64,
    proven_at: opc_session_store::Timestamp,
) -> FencedOwnershipCacheSeed {
    proven_seed_for(namespace(), records, committed_through, proven_at)
}

fn proven_seed_for(
    namespace: FencedOwnershipNamespace,
    records: impl IntoIterator<Item = FencedOwnershipRecord>,
    committed_through: u64,
    proven_at: opc_session_store::Timestamp,
) -> FencedOwnershipCacheSeed {
    FencedOwnershipCacheSeed::from_caller_proven_snapshot(
        namespace,
        records,
        committed_through,
        proven_at,
    )
    .expect("caller-proven coherent seed")
}

fn proven_replay_head(
    committed_through: u64,
    proven_at: opc_session_store::Timestamp,
) -> FencedOwnershipCacheReplayHead {
    FencedOwnershipCacheReplayHead::from_caller_proven_head(committed_through, proven_at)
}

fn setup() -> (
    FakeSessionBackend,
    TokioVirtualClock,
    FencedOwnershipStore<FakeSessionBackend, TokioVirtualClock>,
) {
    let clock = TokioVirtualClock::new();
    let backend = FakeSessionBackend::new().with_clock(Arc::new(clock.clone()));
    let store = FencedOwnershipStore::new(backend.clone(), namespace(), clock.clone());
    (backend, clock, store)
}

async fn settle_release() {
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn concurrent_claim_race_has_exactly_one_winner() {
    let (_backend, _clock, store) = setup();
    let store = Arc::new(store);
    let barrier = Arc::new(tokio::sync::Barrier::new(16));
    let mut tasks = Vec::new();

    for claimant in 0..16 {
        let store = Arc::clone(&store);
        let barrier = Arc::clone(&barrier);
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .claim(
                    FencedOwnershipMutationId::new(),
                    key(b"race-key"),
                    owner(format!("owner-{claimant}").as_str()),
                    Duration::from_secs(30),
                    FencedOwnershipMetadata::empty(),
                )
                .await
        }));
    }

    let mut successes = 0;
    let mut rejections = 0;
    for task in tasks {
        match task.await.expect("claim task") {
            Ok(FencedOwnershipMutation::Applied(_)) => successes += 1,
            Err(FencedOwnershipError::Contended | FencedOwnershipError::Conflict) => {
                rejections += 1;
            }
            other => panic!("unexpected claim outcome: {other:?}"),
        }
    }
    assert_eq!(successes, 1);
    assert_eq!(rejections, 15);
}

#[tokio::test(start_paused = true)]
async fn renew_transfer_and_aba_require_strictly_newer_generations() {
    let (_backend, _clock, store) = setup();
    let first = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"aba-key"),
            owner("owner-a"),
            Duration::from_secs(30),
            metadata(b"standby=a,b;revision=7"),
        )
        .await
        .expect("initial claim")
        .into_inner();
    settle_release().await;

    let second = store
        .transfer(
            FencedOwnershipMutationId::new(),
            &first.fence_token(),
            owner("owner-b"),
            Duration::from_secs(30),
            metadata(b"standby=a;revision=8"),
        )
        .await
        .expect("transfer to B")
        .into_inner();
    assert!(second.generation() > first.generation());
    assert_eq!(
        store.validate_fence(&first.fence_token()).await,
        Err(FencedOwnershipError::StaleFence)
    );
    assert_eq!(
        store
            .renew(
                FencedOwnershipMutationId::new(),
                &first.fence_token(),
                Duration::from_secs(30),
            )
            .await,
        Err(FencedOwnershipError::StaleFence)
    );
    settle_release().await;

    let third = store
        .transfer(
            FencedOwnershipMutationId::new(),
            &second.fence_token(),
            owner("owner-a"),
            Duration::from_secs(30),
            metadata(b"standby=b;revision=9"),
        )
        .await
        .expect("ABA transfer")
        .into_inner();
    assert!(third.generation() > second.generation());
    assert_eq!(third.owner().as_str(), "owner-a");
    settle_release().await;

    let renewed = store
        .renew(
            FencedOwnershipMutationId::new(),
            &third.fence_token(),
            Duration::from_secs(60),
        )
        .await
        .expect("renew current owner")
        .into_inner();
    assert!(renewed.generation() > third.generation());
    assert_eq!(renewed.metadata().as_bytes(), third.metadata().as_bytes());
    assert_eq!(
        store.validate_fence(&third.fence_token()).await,
        Err(FencedOwnershipError::StaleFence)
    );
    store
        .validate_fence(&renewed.fence_token())
        .await
        .expect("renewed fence");
}

#[tokio::test(start_paused = true)]
async fn expiry_is_deterministic_and_never_regresses_the_generation() {
    let (_backend, _clock, store) = setup();
    let first = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"expiry-key"),
            owner("owner-a"),
            Duration::from_secs(5),
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("claim")
        .into_inner();
    settle_release().await;
    tokio::time::advance(Duration::from_secs(6)).await;

    assert_eq!(
        store.validate_fence(&first.fence_token()).await,
        Err(FencedOwnershipError::Expired)
    );
    assert_eq!(store.current(first.key()).await.expect("current"), None);

    let successor = store
        .claim(
            FencedOwnershipMutationId::new(),
            first.key().clone(),
            owner("owner-b"),
            Duration::from_secs(5),
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("successor claim")
        .into_inner();
    assert!(successor.generation() > first.generation());
}

#[tokio::test(start_paused = true)]
async fn logical_expiry_is_anchored_to_the_backend_lease_authority_clock() {
    let authority_now = Timestamp::now_utc();
    let authority_clock = AdjustableClock::new(authority_now);
    let facade_clock = AdjustableClock::new(seconds_after(authority_now, 3_600));
    let backend = FakeSessionBackend::new().with_clock(Arc::new(authority_clock));
    let store = FencedOwnershipStore::new(backend, namespace(), facade_clock);
    let ttl = Duration::from_secs(30);

    let record = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"authority-deadline"),
            owner("owner-a"),
            ttl,
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("claim with divergent facade clock")
        .into_inner();

    assert_eq!(
        record.expires_at(),
        checked_session_deadline(authority_now, ttl).expect("authority deadline")
    );
}

#[tokio::test(start_paused = true)]
async fn retained_mutation_id_replays_exact_result_and_rejects_reuse() {
    let (_backend, _clock, store) = setup();
    let mutation_id = FencedOwnershipMutationId::new();
    let first = store
        .claim(
            mutation_id,
            key(b"idempotent-key"),
            owner("owner-a"),
            Duration::from_secs(30),
            metadata(b"opaque"),
        )
        .await
        .expect("first claim")
        .into_inner();

    let replay = store
        .claim(
            mutation_id,
            key(b"idempotent-key"),
            owner("owner-a"),
            Duration::from_secs(30),
            metadata(b"opaque"),
        )
        .await
        .expect("replay");
    assert_eq!(replay, FencedOwnershipMutation::Replayed(first.clone()));
    assert_eq!(
        store
            .claim(
                mutation_id,
                key(b"idempotent-key"),
                owner("owner-a"),
                Duration::from_secs(30),
                metadata(b"different"),
            )
            .await,
        Err(FencedOwnershipError::IdempotencyConflict)
    );
}

#[tokio::test(start_paused = true)]
async fn release_is_fenced_and_idempotently_converges_to_absence() {
    let (_backend, _clock, store) = setup();
    let record = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"release-key"),
            owner("owner-a"),
            Duration::from_secs(30),
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("claim")
        .into_inner();
    settle_release().await;
    assert_eq!(
        store.release(&record.fence_token()).await,
        Ok(FencedOwnershipMutation::Applied(()))
    );
    settle_release().await;
    assert_eq!(
        store.release(&record.fence_token()).await,
        Ok(FencedOwnershipMutation::Replayed(()))
    );
    assert_eq!(store.current(record.key()).await.expect("current"), None);
}

#[tokio::test(start_paused = true)]
async fn ownership_payload_protection_is_inherited_from_the_encrypted_backend() {
    let marker = b"opaque-routing-metadata";
    let (plain_backend, _plain_clock, plain_store) = setup();
    plain_store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"plain-boundary"),
            owner("owner-a"),
            Duration::from_secs(60),
            metadata(marker),
        )
        .await
        .expect("plain claim");
    settle_release().await;
    let plain_head = plain_backend
        .max_replication_sequence()
        .await
        .expect("plain replication head");
    let plain_log = plain_backend
        .get_replication_log(
            1,
            usize::try_from(plain_head).expect("small plain replication head"),
        )
        .await
        .expect("plain replication log");
    let plain_payload = plain_log
        .iter()
        .find_map(|entry| match &entry.op {
            ReplicationOp::CompareAndSet { new_record, .. } => Some(&new_record.payload),
            _ => None,
        })
        .expect("plain ownership CAS");
    assert_eq!(plain_payload.encoding(), SessionPayloadEncoding::Plaintext);
    assert!(plain_payload
        .as_bytes()
        .windows(marker.len())
        .any(|window| window == marker));

    let clock = TokioVirtualClock::new();
    let inner = Arc::new(FakeSessionBackend::new().with_clock(Arc::new(clock.clone())));
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("ownership-session-key-2026-07").expect("key ID"),
            KeyPurpose::Session,
            TenantId::new("ownership-tests").expect("tenant"),
            Zeroizing::new([0x42; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("active session key");
    let encrypted_backend =
        EncryptingSessionBackend::new(Arc::clone(&inner), provider, "ownership-test-backend");
    let encrypted_store = FencedOwnershipStore::new(encrypted_backend, namespace(), clock);
    let encrypted_record = encrypted_store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"encrypted-boundary"),
            owner("owner-a"),
            Duration::from_secs(60),
            metadata(marker),
        )
        .await
        .expect("encrypted claim")
        .into_inner();
    settle_release().await;
    assert_eq!(
        encrypted_store
            .current(encrypted_record.key())
            .await
            .expect("decrypted current record"),
        Some(encrypted_record)
    );
    let encrypted_head = inner
        .max_replication_sequence()
        .await
        .expect("encrypted replication head");
    let encrypted_log = inner
        .get_replication_log(
            1,
            usize::try_from(encrypted_head).expect("small encrypted replication head"),
        )
        .await
        .expect("encrypted replication log");
    let encrypted_payload = encrypted_log
        .iter()
        .find_map(|entry| match &entry.op {
            ReplicationOp::CompareAndSet { new_record, .. } => Some(&new_record.payload),
            _ => None,
        })
        .expect("encrypted ownership CAS");
    assert_eq!(
        encrypted_payload.encoding(),
        SessionPayloadEncoding::EnvelopeV1
    );
    encrypted_payload
        .validate_envelope()
        .expect("canonical encrypted session envelope");
    assert!(!encrypted_payload
        .as_bytes()
        .windows(marker.len())
        .any(|window| window == marker));
}

#[tokio::test(start_paused = true)]
async fn records_tokens_and_cache_seeds_are_bound_to_one_namespace() {
    let (backend, clock, store) = setup();
    let record = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"namespace-bound"),
            owner("owner-a"),
            Duration::from_secs(60),
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("claim")
        .into_inner();
    let other_store = FencedOwnershipStore::new(backend, other_namespace(), clock.clone());
    assert_eq!(
        other_store.validate_fence(&record.fence_token()).await,
        Err(FencedOwnershipError::StaleFence)
    );
    let other_cache = FencedOwnershipCache::new(
        other_namespace(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(10),
            max_entries: 16,
            max_retained_bytes: 1024 * 1024,
        },
    )
    .expect("other cache");
    let empty_seed = proven_seed_for(namespace(), std::iter::empty(), 0, clock.now_utc());
    assert_eq!(empty_seed.namespace(), &namespace());
    assert_eq!(
        other_cache.seed(empty_seed),
        Err(FencedOwnershipError::InvalidRecord)
    );
    assert_eq!(
        other_cache.seed(proven_seed([record], 1, clock.now_utc())),
        Err(FencedOwnershipError::InvalidRecord)
    );
}

#[tokio::test(start_paused = true)]
async fn committed_watch_cache_converges_then_fails_closed_when_stalled() {
    let (backend, clock, store) = setup();
    let record = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"cache-key"),
            owner("owner-a"),
            Duration::from_secs(60),
            metadata(b"cache-metadata"),
        )
        .await
        .expect("claim")
        .into_inner();
    settle_release().await;

    let head = backend
        .max_replication_sequence()
        .await
        .expect("replication head");
    let entries = backend
        .get_replication_log(1, usize::try_from(head).expect("small test head"))
        .await
        .expect("replication log");
    let cache = FencedOwnershipCache::new(
        namespace(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(5),
            max_entries: 16,
            max_retained_bytes: 1024 * 1024,
        },
    )
    .expect("cache");
    assert_eq!(
        cache.lookup(record.key()),
        FencedOwnershipCacheLookup::Stale
    );
    cache
        .begin_full_replay(proven_replay_head(head, clock.now_utc()))
        .expect("proven full replay");
    let (first_entry, remaining_entries) = entries.split_first().expect("replay entries");
    cache.apply_entry(first_entry).expect("first cache entry");
    assert!(first_entry.sequence < head);
    assert_eq!(
        cache.lookup(record.key()),
        FencedOwnershipCacheLookup::Stale
    );
    for entry in remaining_entries {
        cache.apply_entry(entry).expect("cache entry");
    }
    let first_hit = match cache.lookup(record.key()) {
        FencedOwnershipCacheLookup::Hit(record) => record,
        other => panic!("expected cache hit, got {other:?}"),
    };
    let second_hit = match cache.lookup(record.key()) {
        FencedOwnershipCacheLookup::Hit(record) => record,
        other => panic!("expected cache hit, got {other:?}"),
    };
    assert_eq!(*first_hit, record);
    assert!(Arc::ptr_eq(&first_hit, &second_hit));
    let healthy_metrics = cache.metrics();
    assert_eq!(healthy_metrics.hits, 2);
    assert_eq!(healthy_metrics.stale, 2);
    assert_eq!(healthy_metrics.last_sequence, Some(head));

    tokio::time::advance(Duration::from_secs(6)).await;
    assert_eq!(
        cache.lookup(record.key()),
        FencedOwnershipCacheLookup::Stale
    );
    assert_eq!(cache.metrics().stale, 3);
}

#[tokio::test(start_paused = true)]
async fn installing_an_old_seed_or_replay_proof_does_not_reset_freshness() {
    let (backend, clock, store) = setup();
    let record = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"old-proof"),
            owner("owner-a"),
            Duration::from_secs(60),
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("claim")
        .into_inner();
    settle_release().await;
    let committed_through = backend
        .max_replication_sequence()
        .await
        .expect("replication head");
    let old_proof = clock.now_utc();
    tokio::time::advance(Duration::from_secs(6)).await;

    let seeded = FencedOwnershipCache::new(
        namespace(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(5),
            max_entries: 16,
            max_retained_bytes: 1024 * 1024,
        },
    )
    .expect("seeded cache");
    seeded
        .seed(proven_seed([record.clone()], committed_through, old_proof))
        .expect("old coherent seed");
    assert_eq!(
        seeded.lookup(record.key()),
        FencedOwnershipCacheLookup::Stale
    );

    let replayed = FencedOwnershipCache::new(
        namespace(),
        clock,
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(5),
            max_entries: 16,
            max_retained_bytes: 1024 * 1024,
        },
    )
    .expect("replay cache");
    replayed
        .begin_full_replay(proven_replay_head(0, old_proof))
        .expect("empty replay proof");
    assert_eq!(
        replayed.lookup(record.key()),
        FencedOwnershipCacheLookup::Stale
    );
}

#[tokio::test(start_paused = true)]
async fn future_proofs_and_future_committed_timestamps_fail_closed_permanently() {
    let (backend, clock, store) = setup();
    let record = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"future-proof"),
            owner("owner-a"),
            Duration::from_secs(60),
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("claim")
        .into_inner();
    settle_release().await;
    let head = backend
        .max_replication_sequence()
        .await
        .expect("replication head");
    let entries = backend
        .get_replication_log(1, usize::try_from(head).expect("small test head"))
        .await
        .expect("replication log");
    let now = clock.now_utc();
    let future = seconds_after(now, 10);
    let config = FencedOwnershipCacheConfig {
        max_staleness: Duration::from_secs(30),
        max_entries: 16,
        max_retained_bytes: 1024 * 1024,
    };

    let seeded = FencedOwnershipCache::new(namespace(), clock.clone(), config).expect("seed cache");
    assert_eq!(
        seeded.seed(proven_seed([record.clone()], head, future)),
        Err(FencedOwnershipError::InvalidRecord)
    );
    assert_eq!(
        seeded.lookup(record.key()),
        FencedOwnershipCacheLookup::Stale
    );

    let replayed =
        FencedOwnershipCache::new(namespace(), clock.clone(), config).expect("replay cache");
    assert_eq!(
        replayed.begin_full_replay(proven_replay_head(head, future)),
        Err(FencedOwnershipError::InvalidRecord)
    );

    let watched = FencedOwnershipCache::new(namespace(), clock, config).expect("watch cache");
    watched
        .begin_full_replay(proven_replay_head(head, now))
        .expect("current replay proof");
    let mut future_entry = entries.first().expect("first entry").clone();
    future_entry.timestamp = future;
    assert_eq!(
        watched.apply_entry(&future_entry),
        Err(FencedOwnershipError::InvalidRecord)
    );
    tokio::time::advance(Duration::from_secs(11)).await;
    assert_eq!(
        watched.lookup(record.key()),
        FencedOwnershipCacheLookup::Stale
    );
}

#[tokio::test(start_paused = true)]
async fn cache_clock_regression_latches_after_expiry_reclamation() {
    let (backend, authority_clock, store) = setup();
    let record = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"clock-regression"),
            owner("owner-a"),
            Duration::from_secs(5),
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("claim")
        .into_inner();
    settle_release().await;
    let head = backend
        .max_replication_sequence()
        .await
        .expect("replication head");
    let initial = authority_clock.now_utc();
    let cache_clock = AdjustableClock::new(initial);
    let cache = FencedOwnershipCache::new(
        namespace(),
        cache_clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(30),
            max_entries: 16,
            max_retained_bytes: 1024 * 1024,
        },
    )
    .expect("cache");
    cache
        .seed(proven_seed([record.clone()], head, initial))
        .expect("seed");

    cache_clock.set(seconds_after(initial, 10));
    assert_eq!(cache.lookup(record.key()), FencedOwnershipCacheLookup::Miss);
    assert_eq!(cache.metrics().entries, 0);

    cache_clock.set(seconds_after(initial, 3));
    assert_eq!(
        cache.lookup(record.key()),
        FencedOwnershipCacheLookup::Stale
    );
    cache_clock.set(seconds_after(initial, 11));
    assert_eq!(
        cache.lookup(record.key()),
        FencedOwnershipCacheLookup::Stale
    );
    assert_eq!(cache.metrics().feed_failures, 1);
}

#[tokio::test(start_paused = true)]
async fn watch_runner_captures_the_committed_head_before_serving() {
    let (backend, clock, store) = setup();
    let record = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"watch-runner-bootstrap"),
            owner("owner-a"),
            Duration::from_secs(60),
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("claim")
        .into_inner();
    settle_release().await;
    let cache = Arc::new(
        FencedOwnershipCache::new(
            namespace(),
            clock,
            FencedOwnershipCacheConfig {
                max_staleness: Duration::from_secs(10),
                max_entries: 16,
                max_retained_bytes: 1024 * 1024,
            },
        )
        .expect("cache"),
    );
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let watch_cache = Arc::clone(&cache);
    let watch_backend = backend.clone();
    let watch_task = tokio::spawn(async move {
        watch_cache
            .run_watch_until(&watch_backend, async {
                let _ = shutdown_rx.await;
            })
            .await
    });

    let mut hit = None;
    for _ in 0..16 {
        if let FencedOwnershipCacheLookup::Hit(value) = cache.lookup(record.key()) {
            hit = Some(value);
            break;
        }
        tokio::task::yield_now().await;
    }
    assert_eq!(hit.as_deref(), Some(&record));
    shutdown_tx.send(()).expect("watch shutdown");
    assert_eq!(
        watch_task.await.expect("watch task"),
        Ok(FencedOwnershipWatchExit::Cancelled)
    );
    assert_eq!(
        cache.lookup(record.key()),
        FencedOwnershipCacheLookup::Stale
    );
}

#[tokio::test(start_paused = true)]
async fn unseeded_cache_cannot_skip_history_on_an_unrelated_later_entry() {
    let (backend, clock, store) = setup();
    let record = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"skipped-owner"),
            owner("owner-a"),
            Duration::from_secs(60),
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("claim")
        .into_inner();
    settle_release().await;
    let head = backend
        .max_replication_sequence()
        .await
        .expect("replication head");
    let entries = backend
        .get_replication_log(1, usize::try_from(head).expect("small test head"))
        .await
        .expect("replication log");
    let unrelated_later_entry = entries
        .iter()
        .find(|entry| entry.sequence > 1 && matches!(entry.op, ReplicationOp::ReleaseLease { .. }))
        .expect("later internal release entry");
    let unprepared = FencedOwnershipCache::new(
        namespace(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(10),
            max_entries: 16,
            max_retained_bytes: 1024 * 1024,
        },
    )
    .expect("unprepared cache");
    assert_eq!(
        unprepared.apply_entry(entries.first().expect("first entry")),
        Err(FencedOwnershipError::InvalidRecord)
    );
    assert_eq!(unprepared.metrics().entries, 0);
    let cache = FencedOwnershipCache::new(
        namespace(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(10),
            max_entries: 16,
            max_retained_bytes: 1024 * 1024,
        },
    )
    .expect("cache");
    cache
        .begin_full_replay(proven_replay_head(head, clock.now_utc()))
        .expect("proven full replay");

    assert_eq!(
        cache.apply_entry(unrelated_later_entry),
        Err(FencedOwnershipError::WatchGap)
    );
    assert_eq!(
        cache.lookup(record.key()),
        FencedOwnershipCacheLookup::Stale
    );
    assert_eq!(cache.metrics().misses, 0);
}

#[tokio::test(start_paused = true)]
async fn cache_reports_local_expiry_as_miss_while_feed_is_fresh() {
    let (_backend, clock, store) = setup();
    let record = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"cache-expiry"),
            owner("owner-a"),
            Duration::from_secs(5),
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("claim")
        .into_inner();
    let cache = FencedOwnershipCache::new(
        namespace(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(10),
            max_entries: 16,
            max_retained_bytes: 1024 * 1024,
        },
    )
    .expect("cache");
    cache
        .seed(proven_seed([record.clone()], 1, clock.now_utc()))
        .expect("seed");
    tokio::time::advance(Duration::from_secs(6)).await;
    assert_eq!(cache.lookup(record.key()), FencedOwnershipCacheLookup::Miss);
    assert_eq!(cache.metrics().misses, 1);
}

#[tokio::test(start_paused = true)]
async fn passive_expiry_is_reclaimed_before_distinct_key_capacity_admission() {
    let (backend, clock, store) = setup();
    let expired = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"expired-capacity"),
            owner("owner-a"),
            Duration::from_secs(5),
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("first claim")
        .into_inner();
    settle_release().await;
    let first_head = backend
        .max_replication_sequence()
        .await
        .expect("first replication head");
    let cache = FencedOwnershipCache::new(
        namespace(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(30),
            max_entries: 1,
            max_retained_bytes: 1024 * 1024,
        },
    )
    .expect("one-entry cache");
    cache
        .seed(proven_seed([expired.clone()], first_head, clock.now_utc()))
        .expect("first seed");

    tokio::time::advance(Duration::from_secs(6)).await;
    let replacement = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"live-capacity"),
            owner("owner-b"),
            Duration::from_secs(60),
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("second claim after passive expiry")
        .into_inner();
    settle_release().await;
    let final_head = backend
        .max_replication_sequence()
        .await
        .expect("final replication head");
    let entries = backend
        .get_replication_log(
            first_head.checked_add(1).expect("next sequence"),
            usize::try_from(final_head - first_head).expect("small delta"),
        )
        .await
        .expect("incremental replication log");
    for entry in entries {
        cache.apply_entry(&entry).expect("incremental entry");
    }

    assert_eq!(
        cache.lookup(expired.key()),
        FencedOwnershipCacheLookup::Miss
    );
    assert_eq!(
        cache.lookup(replacement.key()),
        FencedOwnershipCacheLookup::Hit(Arc::new(replacement))
    );
    assert_eq!(cache.metrics().entries, 1);
}

#[tokio::test(start_paused = true)]
async fn cache_seed_retained_byte_budget_is_exact_and_fail_closed() {
    let (_backend, clock, store) = setup();
    let record = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"seed-byte-budget"),
            owner("owner-a"),
            Duration::from_secs(60),
            metadata(&[0x5a; 64]),
        )
        .await
        .expect("claim")
        .into_inner();
    let probe = FencedOwnershipCache::new(
        namespace(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(10),
            max_entries: 16,
            max_retained_bytes: 1024 * 1024,
        },
    )
    .expect("probe cache");
    probe
        .seed(proven_seed([record.clone()], 1, clock.now_utc()))
        .expect("probe seed");
    let exact_bytes = probe.metrics().retained_bytes;
    assert!(exact_bytes > record.metadata().as_bytes().len());

    let exact = FencedOwnershipCache::new(
        namespace(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(10),
            max_entries: 1,
            max_retained_bytes: exact_bytes,
        },
    )
    .expect("exact cache");
    exact
        .seed(proven_seed([record.clone()], 1, clock.now_utc()))
        .expect("exact-bound seed");
    assert_eq!(exact.metrics().retained_bytes, exact_bytes);

    let over = FencedOwnershipCache::new(
        namespace(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(10),
            max_entries: 1,
            max_retained_bytes: exact_bytes.checked_sub(1).expect("nonzero bound"),
        },
    )
    .expect("over-bound cache");
    assert_eq!(
        over.seed(proven_seed([record.clone()], 1, clock.now_utc())),
        Err(FencedOwnershipError::CacheCapacityExceeded)
    );
    assert_eq!(over.metrics().entries, 0);
    assert_eq!(over.metrics().retained_bytes, 0);
    assert_eq!(over.lookup(record.key()), FencedOwnershipCacheLookup::Stale);
}

#[tokio::test(start_paused = true)]
async fn cache_replacement_and_removal_account_retained_bytes_atomically() {
    let (backend, clock, store) = setup();
    let first = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"replacement-byte-budget"),
            owner("owner-a"),
            Duration::from_secs(60),
            metadata(&[0x11; 8]),
        )
        .await
        .expect("claim")
        .into_inner();
    settle_release().await;
    let replacement = store
        .transfer(
            FencedOwnershipMutationId::new(),
            &first.fence_token(),
            owner("owner-b"),
            Duration::from_secs(60),
            metadata(&[0x22; 256]),
        )
        .await
        .expect("replacement")
        .into_inner();
    settle_release().await;
    store
        .release(&replacement.fence_token())
        .await
        .expect("release replacement");
    settle_release().await;
    let head = backend
        .max_replication_sequence()
        .await
        .expect("replication head");
    let entries = backend
        .get_replication_log(1, usize::try_from(head).expect("small test head"))
        .await
        .expect("replication log");
    let cache = FencedOwnershipCache::new(
        namespace(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(10),
            max_entries: 16,
            max_retained_bytes: 1024 * 1024,
        },
    )
    .expect("cache");
    cache
        .begin_full_replay(proven_replay_head(head, clock.now_utc()))
        .expect("proven full replay");
    let mut cas_bytes = Vec::new();
    for entry in &entries {
        cache.apply_entry(entry).expect("cache replay");
        match &entry.op {
            ReplicationOp::CompareAndSet { .. } => {
                cas_bytes.push(cache.metrics().retained_bytes);
            }
            ReplicationOp::DeleteFenced { .. } => {
                assert_eq!(cache.metrics().entries, 0);
                assert_eq!(cache.metrics().retained_bytes, 0);
            }
            _ => {}
        }
    }
    assert_eq!(cas_bytes.len(), 2);
    assert!(cas_bytes[1] > cas_bytes[0]);

    let constrained = FencedOwnershipCache::new(
        namespace(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(10),
            max_entries: 16,
            max_retained_bytes: cas_bytes[0],
        },
    )
    .expect("constrained cache");
    constrained
        .begin_full_replay(proven_replay_head(head, clock.now_utc()))
        .expect("constrained full replay");
    let mut seen_cas = 0;
    for entry in &entries {
        if matches!(&entry.op, ReplicationOp::CompareAndSet { .. }) {
            seen_cas += 1;
        }
        let result = constrained.apply_entry(entry);
        if seen_cas == 2 {
            assert_eq!(result, Err(FencedOwnershipError::CacheCapacityExceeded));
            break;
        }
        result.expect("pre-replacement replay");
    }
    assert_eq!(constrained.metrics().entries, 0);
    assert_eq!(constrained.metrics().retained_bytes, 0);
    assert_eq!(
        constrained.lookup(first.key()),
        FencedOwnershipCacheLookup::Stale
    );
}

#[tokio::test(start_paused = true)]
async fn explicit_watch_cancellation_owns_no_task_and_invalidates_the_view() {
    let (backend, clock, store) = setup();
    let record = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"cancelled-watch"),
            owner("owner-a"),
            Duration::from_secs(60),
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("claim")
        .into_inner();
    settle_release().await;
    let head = backend
        .max_replication_sequence()
        .await
        .expect("replication head");
    let cache = FencedOwnershipCache::new(
        namespace(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(10),
            max_entries: 16,
            max_retained_bytes: 1024 * 1024,
        },
    )
    .expect("cache");
    cache
        .seed(proven_seed([record.clone()], head, clock.now_utc()))
        .expect("seed");
    assert_eq!(
        cache.run_watch_until(&backend, async {}).await,
        Ok(FencedOwnershipWatchExit::Cancelled)
    );
    assert_eq!(
        cache.lookup(record.key()),
        FencedOwnershipCacheLookup::Stale
    );
}

#[tokio::test(start_paused = true)]
async fn watch_start_failure_invalidates_a_previously_seeded_view() {
    let (source_backend, clock, store) = setup();
    let record = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"failed-watch-start"),
            owner("owner-a"),
            Duration::from_secs(60),
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("claim")
        .into_inner();
    settle_release().await;
    let head = source_backend
        .max_replication_sequence()
        .await
        .expect("replication head");
    let source_entries = source_backend
        .get_replication_log(1, usize::try_from(head).expect("small test head"))
        .await
        .expect("source replication log");
    let unavailable_watch = FakeSessionBackend::with_limits(FakeBackendLimits {
        max_tracked_keys: 16,
        max_replication_entries: 1,
    });
    for entry in source_entries {
        unavailable_watch
            .replicate_entry(entry)
            .await
            .expect("replicate compacted fixture");
    }
    let cache = FencedOwnershipCache::new(
        namespace(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(10),
            max_entries: 16,
            max_retained_bytes: 1024 * 1024,
        },
    )
    .expect("cache");
    cache
        .seed(proven_seed([record.clone()], 1, clock.now_utc()))
        .expect("seed");

    assert_eq!(
        cache
            .run_watch_until(&unavailable_watch, std::future::pending())
            .await,
        Err(FencedOwnershipError::WatchGap)
    );
    assert_eq!(
        cache.lookup(record.key()),
        FencedOwnershipCacheLookup::Stale
    );
    assert_eq!(cache.metrics().feed_failures, 1);
}

#[tokio::test(start_paused = true)]
async fn malformed_or_gapped_watch_input_invalidates_the_complete_cache() {
    let (backend, clock, store) = setup();
    let record = store
        .claim(
            FencedOwnershipMutationId::new(),
            key(b"malformed-cache"),
            owner("owner-a"),
            Duration::from_secs(60),
            FencedOwnershipMetadata::empty(),
        )
        .await
        .expect("claim")
        .into_inner();
    settle_release().await;
    let head = backend
        .max_replication_sequence()
        .await
        .expect("replication head");
    let entries = backend
        .get_replication_log(1, usize::try_from(head).expect("small head"))
        .await
        .expect("replication log");
    let original_cas = entries
        .iter()
        .find(|entry| matches!(entry.op, ReplicationOp::CompareAndSet { .. }))
        .expect("CAS entry")
        .clone();
    let mut malformed = original_cas.clone();
    malformed.sequence = head.checked_add(1).expect("next sequence");
    malformed.tx_id = ReplicationTxId::new("malformed-owner-record").expect("tx ID");
    if let ReplicationOp::CompareAndSet { new_record, .. } = &mut malformed.op {
        new_record.payload = EncryptedSessionPayload::new(b"invalid");
    }

    let cache = FencedOwnershipCache::new(
        namespace(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(10),
            max_entries: 16,
            max_retained_bytes: 1024 * 1024,
        },
    )
    .expect("cache");
    cache
        .seed(proven_seed([record.clone()], head, clock.now_utc()))
        .expect("seed");
    assert_eq!(
        cache.apply_entry(&malformed),
        Err(FencedOwnershipError::InvalidRecord)
    );
    assert_eq!(
        cache.lookup(record.key()),
        FencedOwnershipCacheLookup::Stale
    );
    assert_eq!(cache.metrics().feed_failures, 1);

    let gap_cache = FencedOwnershipCache::new(
        namespace(),
        clock.clone(),
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(10),
            max_entries: 16,
            max_retained_bytes: 1024 * 1024,
        },
    )
    .expect("gap cache");
    gap_cache
        .seed(proven_seed([record.clone()], head, clock.now_utc()))
        .expect("seed");
    let mut gapped = original_cas;
    gapped.sequence = head.checked_add(2).expect("gapped sequence");
    gapped.tx_id = ReplicationTxId::new("gapped-owner-record").expect("tx ID");
    assert_eq!(
        gap_cache.apply_entry(&gapped),
        Err(FencedOwnershipError::WatchGap)
    );
    assert_eq!(
        gap_cache.lookup(record.key()),
        FencedOwnershipCacheLookup::Stale
    );
}

#[tokio::test(start_paused = true)]
async fn unsupported_backend_fails_at_capability_validation() {
    let clock = TokioVirtualClock::new();
    let backend = FakeSessionBackend::with_capabilities(BackendCapabilities::minimal())
        .with_clock(Arc::new(clock.clone()));
    let store = FencedOwnershipStore::new(backend.clone(), namespace(), clock.clone());
    assert_eq!(
        store.validate_authority().await,
        Err(FencedOwnershipError::CapabilityNotSupported)
    );
    let cache = FencedOwnershipCache::new(
        namespace(),
        clock,
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(10),
            max_entries: 16,
            max_retained_bytes: 1024 * 1024,
        },
    )
    .expect("cache");
    assert_eq!(
        cache.run_watch_until(&backend, async {}).await,
        Err(FencedOwnershipError::CapabilityNotSupported)
    );
    assert_eq!(cache.metrics().feed_failures, 1);

    let mut too_small = BackendCapabilities::all_enabled();
    too_small.max_value_bytes = OWNERSHIP_METADATA_MAX_BYTES;
    let too_small_backend = FakeSessionBackend::with_capabilities(too_small)
        .with_clock(Arc::new(TokioVirtualClock::new()));
    let too_small_store =
        FencedOwnershipStore::new(too_small_backend, namespace(), TokioVirtualClock::new());
    assert_eq!(
        too_small_store.validate_authority().await,
        Err(FencedOwnershipError::CapabilityNotSupported)
    );
}

#[test]
fn key_metadata_and_cache_bounds_are_exact_and_redacted() {
    assert!(FencedOwnershipKey::new(vec![0xa5; OWNERSHIP_KEY_MAX_BYTES]).is_ok());
    assert_eq!(
        FencedOwnershipKey::new(vec![0xa5; OWNERSHIP_KEY_MAX_BYTES + 1]),
        Err(FencedOwnershipError::InvalidKey)
    );
    assert!(FencedOwnershipMetadata::new(vec![0x5a; OWNERSHIP_METADATA_MAX_BYTES]).is_ok());
    assert_eq!(
        FencedOwnershipMetadata::new(vec![0x5a; OWNERSHIP_METADATA_MAX_BYTES + 1]),
        Err(FencedOwnershipError::MetadataTooLarge)
    );
    assert_eq!(
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(1),
            max_entries: OWNERSHIP_CACHE_MAX_ENTRIES + 1,
            max_retained_bytes: 1024 * 1024,
        }
        .validate(),
        Err(FencedOwnershipError::InvalidCacheConfig)
    );
    assert_eq!(
        FencedOwnershipCacheConfig {
            max_staleness: Duration::from_secs(1),
            max_entries: 1,
            max_retained_bytes: OWNERSHIP_CACHE_MAX_RETAINED_BYTES + 1,
        }
        .validate(),
        Err(FencedOwnershipError::InvalidCacheConfig)
    );
    assert!(!format!("{:?}", key(b"secret-session-key")).contains("secret-session-key"));
    assert!(!format!("{:?}", metadata(b"secret-metadata")).contains("secret-metadata"));
    assert!(!format!("{:?}", FencedOwnershipMutationId::new()).contains('-'));
}

#[test]
fn every_error_has_a_stable_code_and_redacted_text() {
    let errors = [
        FencedOwnershipError::InvalidKey,
        FencedOwnershipError::MetadataTooLarge,
        FencedOwnershipError::InvalidLeaseTtl,
        FencedOwnershipError::CapabilityNotSupported,
        FencedOwnershipError::Contended,
        FencedOwnershipError::Conflict,
        FencedOwnershipError::StaleFence,
        FencedOwnershipError::Expired,
        FencedOwnershipError::NotFound,
        FencedOwnershipError::IdempotencyConflict,
        FencedOwnershipError::OutcomeUnavailable,
        FencedOwnershipError::InvalidRecord,
        FencedOwnershipError::InvalidCacheConfig,
        FencedOwnershipError::WatchGap,
        FencedOwnershipError::WatchEnded,
        FencedOwnershipError::CacheCapacityExceeded,
        FencedOwnershipError::BackendUnavailable,
    ];
    for error in errors {
        assert!(error.as_str().starts_with("fenced_ownership_"));
        assert!(!error.to_string().contains("owner-a"));
        assert!(!format!("{error:?}").contains("owner-a"));
    }
}
