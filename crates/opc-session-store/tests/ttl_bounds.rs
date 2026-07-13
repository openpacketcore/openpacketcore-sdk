use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::Bytes;
use futures_util::{FutureExt, StreamExt};
use opc_session_store::{
    checked_session_deadline, Clock, CompareAndSet, CompareAndSetResult, EncryptedSessionPayload,
    FakeSessionBackend, FenceToken, Generation, LeaseError, LeaseGuard, OwnerId,
    RecordExpiryPreflight, ReplicationEntry, ReplicationOp, SessionKey, SessionKeyType, SessionOp,
    SessionStoreBackend, SqliteSessionBackend, StateClass, StateType, StoreError,
    StoredSessionRecord, MAX_RECORD_EXPIRY_PREFLIGHTS, MAX_REPLICATION_LOG_PAGE_ENTRIES,
    MAX_SESSION_TTL,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

#[derive(Debug, Clone, Copy)]
enum BackendKind {
    Fake,
    Sqlite,
}

#[derive(Debug)]
struct FixedClock {
    now: Mutex<Timestamp>,
}

impl FixedClock {
    fn new(now: Timestamp) -> Self {
        Self {
            now: Mutex::new(now),
        }
    }

    fn set(&self, now: Timestamp) {
        *self.now.lock().expect("test clock lock") = now;
    }
}

impl Clock for FixedClock {
    fn now_utc(&self) -> Timestamp {
        *self.now.lock().expect("test clock lock")
    }
}

fn base_timestamp() -> Timestamp {
    Timestamp::from_offset_datetime(
        time::OffsetDateTime::from_unix_timestamp(1_900_000_000)
            .expect("test timestamp seconds")
            .checked_add(time::Duration::nanoseconds(987_654_321))
            .expect("test timestamp nanoseconds"),
    )
}

fn shift(timestamp: Timestamp, delta: time::Duration) -> Timestamp {
    Timestamp::from_offset_datetime(
        timestamp
            .as_offset_datetime()
            .checked_add(delta)
            .expect("representable test timestamp"),
    )
}

fn max_plus_one_nanosecond() -> Duration {
    MAX_SESSION_TTL
        .checked_add(Duration::from_nanos(1))
        .expect("SDK TTL maximum has headroom")
}

fn test_key(stable_id: &[u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("ttl-bounds").expect("tenant"),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(stable_id)
            .try_into()
            .expect("valid stable ID"),
    }
}

fn owner(name: &str) -> OwnerId {
    OwnerId::new(name).expect("owner")
}

fn record(key: SessionKey, generation: u64, lease: &LeaseGuard) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("smf-pdu-context"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"ttl-bounds-payload")),
    }
}

fn replicated_record(
    key: SessionKey,
    generation: u64,
    owner: OwnerId,
    fence: FenceToken,
) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner,
        fence,
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("smf-pdu-context"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"replicated-payload")),
    }
}

fn backend(kind: BackendKind, clock: Arc<FixedClock>) -> Arc<dyn SessionStoreBackend> {
    match kind {
        BackendKind::Fake => Arc::new(FakeSessionBackend::new().with_clock(clock)),
        BackendKind::Sqlite => Arc::new(
            SqliteSessionBackend::in_memory()
                .expect("in-memory SQLite backend")
                .with_clock(clock),
        ),
    }
}

async fn replication_log(backend: &dyn SessionStoreBackend) -> Vec<ReplicationEntry> {
    backend
        .get_replication_log(1, MAX_REPLICATION_LOG_PAGE_ENTRIES)
        .await
        .expect("replication log")
}

async fn seed_record(
    backend: &dyn SessionStoreBackend,
    key: &SessionKey,
) -> (LeaseGuard, StoredSessionRecord) {
    let lease = backend
        .acquire(key, owner("owner-a"), Duration::from_secs(60))
        .await
        .expect("seed lease");
    let stored = record(key.clone(), 1, &lease);
    assert_eq!(
        backend
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: stored.clone(),
            })
            .await
            .expect("seed record"),
        CompareAndSetResult::Success
    );
    (lease, stored)
}

fn assert_lease_ttl_error(error: LeaseError) {
    assert_eq!(error, LeaseError::InvalidSessionTtl);
    assert_eq!(error.to_string(), "invalid session TTL");
    assert_eq!(format!("{error:?}"), "InvalidSessionTtl");
}

fn assert_store_ttl_error(error: StoreError) {
    assert_eq!(error, StoreError::InvalidSessionTtl);
    assert_eq!(error.to_string(), "invalid session TTL");
    assert_eq!(format!("{error:?}"), "InvalidSessionTtl");
}

fn assert_store_expiry_error(error: StoreError) {
    assert_eq!(error, StoreError::InvalidRecordExpiry);
    assert_eq!(error.to_string(), "invalid session record expiry");
    assert_eq!(format!("{error:?}"), "InvalidRecordExpiry");
}

fn valid_ttls() -> [Duration; 3] {
    [
        Duration::ZERO,
        Duration::new(7, 456_789_123),
        MAX_SESSION_TTL,
    ]
}

fn invalid_ttls() -> [Duration; 2] {
    [max_plus_one_nanosecond(), Duration::MAX]
}

async fn assert_acquire_boundaries(kind: BackendKind) {
    for (index, ttl) in valid_ttls().into_iter().enumerate() {
        let now = base_timestamp();
        let clock = Arc::new(FixedClock::new(now));
        let backend = backend(kind, clock);
        let key = test_key(format!("acquire-valid-{index}").as_bytes());

        let lease = backend
            .acquire(&key, owner("owner-a"), ttl)
            .await
            .expect("bounded acquire must succeed");
        let expected = checked_session_deadline(now, ttl).expect("bounded deadline");

        assert_eq!(lease.acquired_at(), now, "{kind:?} acquire timestamp");
        assert_eq!(lease.expires_at(), expected, "{kind:?} acquire deadline");
        assert_eq!(lease.fence(), FenceToken::new(1));
        assert_eq!(backend.next_lease_info().await.expect("lease info"), (2, 2));

        if let Some(entry) = replication_log(backend.as_ref()).await.last() {
            assert_eq!(entry.timestamp, now);
            assert!(matches!(
                &entry.op,
                ReplicationOp::AcquireLease {
                    ttl: recorded_ttl,
                    expires_at,
                    ..
                } if *recorded_ttl == ttl && *expires_at == expected
            ));
        }
    }

    for (index, ttl) in invalid_ttls().into_iter().enumerate() {
        let clock = Arc::new(FixedClock::new(base_timestamp()));
        let backend = backend(kind, clock);
        let key = test_key(format!("acquire-invalid-{index}").as_bytes());
        let mut watch = backend.watch(1).await.expect("watch before rejection");

        let error = backend
            .acquire(&key, owner("owner-a"), ttl)
            .await
            .expect_err("oversized acquire must fail");

        assert_lease_ttl_error(error);
        assert_eq!(backend.next_lease_info().await.expect("lease info"), (1, 1));
        assert_eq!(backend.max_replication_sequence().await.expect("head"), 0);
        assert!(replication_log(backend.as_ref()).await.is_empty());
        assert_eq!(backend.get(&key).await.expect("record state"), None);
        assert!(
            watch.next().now_or_never().is_none(),
            "{kind:?} invalid acquire notified a watcher"
        );
    }
}

async fn assert_renew_boundaries(kind: BackendKind) {
    for (index, ttl) in valid_ttls().into_iter().enumerate() {
        let now = base_timestamp();
        let clock = Arc::new(FixedClock::new(now));
        let backend = backend(kind, clock);
        let key = test_key(format!("renew-valid-{index}").as_bytes());
        let lease = backend
            .acquire(&key, owner("owner-a"), Duration::from_secs(60))
            .await
            .expect("seed lease");

        let renewed = backend
            .renew(&lease, ttl)
            .await
            .expect("bounded renewal must succeed");
        let expected = checked_session_deadline(now, ttl).expect("bounded deadline");

        assert_eq!(renewed.expires_at(), expected, "{kind:?} renew deadline");
        assert_eq!(renewed.fence(), lease.fence());
        assert_eq!(renewed.owner(), lease.owner());
        assert_eq!(backend.next_lease_info().await.expect("lease info"), (2, 2));

        if let Some(entry) = replication_log(backend.as_ref()).await.last() {
            assert!(matches!(
                &entry.op,
                ReplicationOp::RenewLease {
                    ttl: recorded_ttl,
                    expires_at,
                    ..
                } if *recorded_ttl == ttl && *expires_at == expected
            ));
        }
    }

    for (index, ttl) in invalid_ttls().into_iter().enumerate() {
        let clock = Arc::new(FixedClock::new(base_timestamp()));
        let backend = backend(kind, clock);
        let key = test_key(format!("renew-invalid-{index}").as_bytes());
        let lease = backend
            .acquire(&key, owner("owner-a"), Duration::from_secs(60))
            .await
            .expect("seed lease");
        let before_info = backend.next_lease_info().await.expect("lease info");
        let before_head = backend.max_replication_sequence().await.expect("head");
        let before_log = replication_log(backend.as_ref()).await;
        let mut watch = backend
            .watch(before_head + 1)
            .await
            .expect("watch before rejection");

        let error = backend
            .renew(&lease, ttl)
            .await
            .expect_err("oversized renewal must fail");

        assert_lease_ttl_error(error);
        assert_eq!(
            backend.next_lease_info().await.expect("lease info"),
            before_info
        );
        assert_eq!(
            backend.max_replication_sequence().await.expect("head"),
            before_head
        );
        assert_eq!(replication_log(backend.as_ref()).await, before_log);
        assert_eq!(
            backend
                .acquire(&key, owner("contender"), Duration::from_secs(60))
                .await
                .expect_err("original lease must remain held"),
            LeaseError::AlreadyHeld
        );
        assert!(
            watch.next().now_or_never().is_none(),
            "{kind:?} invalid renewal notified a watcher"
        );
    }
}

async fn assert_refresh_boundaries(kind: BackendKind) {
    for (index, ttl) in valid_ttls().into_iter().enumerate() {
        let now = base_timestamp();
        let clock = Arc::new(FixedClock::new(now));
        let backend = backend(kind, Arc::clone(&clock));
        let key = test_key(format!("refresh-valid-{index}").as_bytes());
        let (lease, _) = seed_record(backend.as_ref(), &key).await;

        backend
            .refresh_ttl(&lease, ttl)
            .await
            .expect("bounded refresh must succeed");
        let expected = checked_session_deadline(now, ttl).expect("bounded deadline");

        // A zero TTL is immediately expired at `now`; step the injected clock
        // back one nanosecond so the exact stored deadline remains observable.
        clock.set(shift(now, time::Duration::nanoseconds(-1)));
        let refreshed = backend
            .get(&key)
            .await
            .expect("read refreshed record")
            .expect("record is live one nanosecond before its deadline");
        assert_eq!(
            refreshed.expires_at,
            Some(expected),
            "{kind:?} refresh deadline"
        );

        if let Some(entry) = replication_log(backend.as_ref()).await.last() {
            assert!(matches!(
                &entry.op,
                ReplicationOp::RefreshTtl {
                    ttl: recorded_ttl,
                    expires_at,
                    ..
                } if *recorded_ttl == ttl && *expires_at == expected
            ));
        }
    }

    for (index, ttl) in invalid_ttls().into_iter().enumerate() {
        let clock = Arc::new(FixedClock::new(base_timestamp()));
        let backend = backend(kind, clock);
        let key = test_key(format!("refresh-invalid-{index}").as_bytes());
        let (lease, stored) = seed_record(backend.as_ref(), &key).await;
        let before_info = backend.next_lease_info().await.expect("lease info");
        let before_head = backend.max_replication_sequence().await.expect("head");
        let before_log = replication_log(backend.as_ref()).await;
        let mut watch = backend
            .watch(before_head + 1)
            .await
            .expect("watch before rejection");

        let error = backend
            .refresh_ttl(&lease, ttl)
            .await
            .expect_err("oversized refresh must fail");

        assert_store_ttl_error(error);
        assert_eq!(backend.get(&key).await.expect("record state"), Some(stored));
        assert_eq!(
            backend.next_lease_info().await.expect("lease info"),
            before_info
        );
        assert_eq!(
            backend.max_replication_sequence().await.expect("head"),
            before_head
        );
        assert_eq!(replication_log(backend.as_ref()).await, before_log);
        assert_eq!(
            backend
                .acquire(&key, owner("contender"), Duration::from_secs(60))
                .await
                .expect_err("original lease must remain held"),
            LeaseError::AlreadyHeld
        );
        assert!(
            watch.next().now_or_never().is_none(),
            "{kind:?} invalid refresh notified a watcher"
        );
    }
}

async fn assert_batch_preflight_is_atomic(kind: BackendKind) {
    let clock = Arc::new(FixedClock::new(base_timestamp()));
    let backend = backend(kind, clock);
    let key = test_key(b"batch-preflight");
    let (lease, stored) = seed_record(backend.as_ref(), &key).await;
    let before_info = backend.next_lease_info().await.expect("lease info");
    let before_head = backend.max_replication_sequence().await.expect("head");
    let before_log = replication_log(backend.as_ref()).await;
    let mut watch = backend
        .watch(before_head + 1)
        .await
        .expect("watch before rejection");

    let error = backend
        .batch(vec![
            SessionOp::DeleteFenced {
                lease: lease.clone(),
            },
            SessionOp::RefreshTtl {
                lease: lease.clone(),
                ttl: max_plus_one_nanosecond(),
            },
        ])
        .await
        .expect_err("later malformed TTL must reject the entire batch");

    assert_store_ttl_error(error);
    assert_eq!(backend.get(&key).await.expect("record state"), Some(stored));
    assert_eq!(
        backend.next_lease_info().await.expect("lease info"),
        before_info
    );
    assert_eq!(
        backend.max_replication_sequence().await.expect("head"),
        before_head
    );
    assert_eq!(replication_log(backend.as_ref()).await, before_log);
    assert_eq!(
        backend
            .acquire(&key, owner("contender"), Duration::from_secs(60))
            .await
            .expect_err("preflight must preserve the original lease and fence"),
        LeaseError::AlreadyHeld
    );
    assert!(
        watch.next().now_or_never().is_none(),
        "{kind:?} invalid batch notified a watcher"
    );
}

#[derive(Debug, Clone, Copy)]
enum ReplicatedTtlKind {
    Acquire,
    Renew,
    Refresh,
}

fn ttl_op(
    kind: ReplicatedTtlKind,
    key: SessionKey,
    ttl: Duration,
    expires_at: Timestamp,
) -> ReplicationOp {
    match kind {
        ReplicatedTtlKind::Acquire => ReplicationOp::AcquireLease {
            key,
            owner: owner("owner-a"),
            fence: FenceToken::new(1),
            credential_id: 1,
            ttl,
            expires_at,
        },
        ReplicatedTtlKind::Renew => ReplicationOp::RenewLease {
            key,
            owner: owner("owner-a"),
            fence: FenceToken::new(1),
            credential_id: 1,
            ttl,
            expires_at,
        },
        ReplicatedTtlKind::Refresh => ReplicationOp::RefreshTtl {
            key,
            owner: owner("owner-a"),
            fence: FenceToken::new(1),
            ttl,
            expires_at,
        },
    }
}

fn replication_entry(
    sequence: u64,
    tx_id: &str,
    timestamp: Timestamp,
    op: ReplicationOp,
) -> ReplicationEntry {
    ReplicationEntry {
        sequence,
        tx_id: tx_id.try_into().expect("valid transaction ID"),
        op,
        timestamp,
    }
}

#[test]
fn replicated_ttl_validation_is_recursive_exact_and_legacy_compatible() {
    let timestamp = base_timestamp();
    let ttl = Duration::new(17, 123_456_789);
    let exact = checked_session_deadline(timestamp, ttl).expect("exact deadline");
    let legacy_limit = shift(exact, time::Duration::microseconds(1));
    let forged = shift(legacy_limit, time::Duration::nanoseconds(1));

    for kind in [
        ReplicatedTtlKind::Acquire,
        ReplicatedTtlKind::Renew,
        ReplicatedTtlKind::Refresh,
    ] {
        for expires_at in [
            shift(exact, time::Duration::nanoseconds(-1)),
            exact,
            legacy_limit,
        ] {
            let direct = ttl_op(kind, test_key(b"legacy-compatible"), ttl, expires_at);
            direct
                .validate_ttls_at(timestamp)
                .expect("deadlines no more than one microsecond late are accepted");
            ReplicationOp::Batch {
                ops: vec![ReplicationOp::Batch { ops: vec![direct] }],
            }
            .validate_ttls_at(timestamp)
            .expect("nested legacy-compatible deadline");
        }

        for invalid in [
            ttl_op(kind, test_key(b"forged-deadline"), ttl, forged),
            ttl_op(
                kind,
                test_key(b"oversized-duration"),
                max_plus_one_nanosecond(),
                timestamp,
            ),
            ttl_op(kind, test_key(b"duration-max"), Duration::MAX, timestamp),
        ] {
            assert_store_ttl_error(
                invalid
                    .validate_ttls_at(timestamp)
                    .expect_err("direct malformed replicated TTL must fail"),
            );
            assert_store_ttl_error(
                ReplicationOp::Batch {
                    ops: vec![ReplicationOp::Batch { ops: vec![invalid] }],
                }
                .validate_ttls_at(timestamp)
                .expect_err("nested malformed replicated TTL must fail"),
            );
        }
    }
}

async fn assert_replicated_ttl_rejection_is_atomic(kind: BackendKind) {
    let now = base_timestamp();
    let clock = Arc::new(FixedClock::new(now));
    let backend = backend(kind, clock);
    let key = test_key(b"replicated-ttl");
    let valid_ttl = Duration::from_secs(60);
    let exact = checked_session_deadline(now, valid_ttl).expect("deadline");
    let forged = shift(
        exact,
        time::Duration::microseconds(1) + time::Duration::nanoseconds(1),
    );
    let mut watch = backend.watch(1).await.expect("watch before rejection");

    let malformed_entries = [
        replication_entry(
            1,
            "oversized-direct",
            now,
            ttl_op(
                ReplicatedTtlKind::Acquire,
                key.clone(),
                max_plus_one_nanosecond(),
                now,
            ),
        ),
        replication_entry(
            1,
            "forged-deadline",
            now,
            ttl_op(ReplicatedTtlKind::Acquire, key.clone(), valid_ttl, forged),
        ),
        replication_entry(
            1,
            "oversized-nested",
            now,
            ReplicationOp::Batch {
                ops: vec![
                    ttl_op(ReplicatedTtlKind::Acquire, key.clone(), valid_ttl, exact),
                    ReplicationOp::Batch {
                        ops: vec![ttl_op(
                            ReplicatedTtlKind::Renew,
                            key.clone(),
                            Duration::MAX,
                            now,
                        )],
                    },
                ],
            },
        ),
    ];

    for malformed in malformed_entries {
        assert_store_ttl_error(
            backend
                .replicate_entry(malformed)
                .await
                .expect_err("malformed replication entry must fail"),
        );
        assert_eq!(backend.max_replication_sequence().await.expect("head"), 0);
        assert_eq!(backend.next_lease_info().await.expect("lease info"), (1, 1));
        assert_eq!(backend.get(&key).await.expect("record state"), None);
        assert!(replication_log(backend.as_ref()).await.is_empty());
        assert!(
            watch.next().now_or_never().is_none(),
            "{kind:?} invalid replicated TTL notified a watcher"
        );
    }

    let accepted = replication_entry(
        1,
        "legacy-tolerance",
        now,
        ttl_op(
            ReplicatedTtlKind::Acquire,
            key.clone(),
            valid_ttl,
            shift(exact, time::Duration::microseconds(1)),
        ),
    );
    backend
        .replicate_entry(accepted.clone())
        .await
        .expect("one-microsecond legacy extension must remain compatible");
    assert_eq!(backend.max_replication_sequence().await.expect("head"), 1);
    assert_eq!(backend.next_lease_info().await.expect("lease info"), (2, 2));
    assert_eq!(replication_log(backend.as_ref()).await, vec![accepted]);
}

async fn assert_invalid_rebuild_preserves_state(kind: BackendKind) {
    let now = base_timestamp();
    let clock = Arc::new(FixedClock::new(now));
    let backend = backend(kind, clock);
    let key = test_key(b"preserved-prefix");
    let lease_ttl = Duration::from_secs(60);
    let expires_at = checked_session_deadline(now, lease_ttl).expect("lease deadline");
    let original = vec![
        replication_entry(
            1,
            "original-lease",
            now,
            ttl_op(
                ReplicatedTtlKind::Acquire,
                key.clone(),
                lease_ttl,
                expires_at,
            ),
        ),
        replication_entry(
            2,
            "original-record",
            now,
            ReplicationOp::CompareAndSet {
                key: key.clone(),
                expected_generation: None,
                credential_id: 1,
                guard_expires_at: expires_at,
                new_record: replicated_record(key.clone(), 1, owner("owner-a"), FenceToken::new(1)),
            },
        ),
    ];
    backend
        .rebuild_replication_state(original.clone())
        .await
        .expect("seed original prefix");
    let before_record = backend.get(&key).await.expect("original record");
    let before_info = backend.next_lease_info().await.expect("lease info");
    let before_log = replication_log(backend.as_ref()).await;
    let mut watch = backend.watch(3).await.expect("watch before rejection");

    let replacement_key = test_key(b"invalid-replacement");
    let malformed = vec![
        replication_entry(
            1,
            "replacement-first",
            now,
            ttl_op(
                ReplicatedTtlKind::Acquire,
                replacement_key.clone(),
                lease_ttl,
                expires_at,
            ),
        ),
        replication_entry(
            2,
            "replacement-malformed",
            now,
            ReplicationOp::Batch {
                ops: vec![
                    ReplicationOp::DeleteFenced {
                        key: replacement_key.clone(),
                        owner: owner("owner-a"),
                        fence: FenceToken::new(1),
                    },
                    ttl_op(
                        ReplicatedTtlKind::Renew,
                        replacement_key,
                        max_plus_one_nanosecond(),
                        now,
                    ),
                ],
            },
        ),
    ];

    assert_store_ttl_error(
        backend
            .rebuild_replication_state(malformed)
            .await
            .expect_err("entire replacement prefix must be validated before clearing state"),
    );
    assert_eq!(
        backend.get(&key).await.expect("record state"),
        before_record
    );
    assert_eq!(
        backend.next_lease_info().await.expect("lease info"),
        before_info
    );
    assert_eq!(backend.max_replication_sequence().await.expect("head"), 2);
    assert_eq!(replication_log(backend.as_ref()).await, before_log);
    assert_eq!(
        backend
            .acquire(&key, owner("contender"), Duration::from_secs(60))
            .await
            .expect_err("original rebuilt lease must survive invalid replacement"),
        LeaseError::AlreadyHeld
    );
    assert!(
        watch.next().now_or_never().is_none(),
        "{kind:?} invalid rebuild notified a watcher"
    );
}

async fn assert_absolute_record_expiry_boundaries(kind: BackendKind) {
    let now = base_timestamp();
    let maximum = checked_session_deadline(now, MAX_SESSION_TTL).expect("maximum expiry");
    let maximum_plus_one = shift(maximum, time::Duration::nanoseconds(1));
    let past = shift(now, time::Duration::nanoseconds(-1));

    for (index, expires_at) in [past, now, maximum].into_iter().enumerate() {
        let clock = Arc::new(FixedClock::new(now));
        let backend = backend(kind, clock);
        let key = test_key(format!("absolute-valid-{index}").as_bytes());
        let lease = backend
            .acquire(&key, owner("owner-a"), Duration::from_secs(60))
            .await
            .expect("lease");
        let mut new_record = record(key.clone(), 1, &lease);
        new_record.expires_at = Some(expires_at);
        assert_eq!(
            backend
                .compare_and_set(CompareAndSet {
                    key,
                    lease,
                    expected_generation: None,
                    new_record,
                })
                .await
                .expect("bounded absolute expiry"),
            CompareAndSetResult::Success,
            "{kind:?} expiry boundary {index}"
        );
    }

    let clock = Arc::new(FixedClock::new(now));
    let backend = backend(kind, clock);
    let key = test_key(b"absolute-invalid");
    let lease = backend
        .acquire(&key, owner("owner-a"), Duration::from_secs(60))
        .await
        .expect("lease");
    let before_head = backend.max_replication_sequence().await.expect("head");
    let before_log = replication_log(backend.as_ref()).await;
    let mut watch = backend
        .watch(before_head.checked_add(1).expect("watch cursor"))
        .await
        .expect("watch");

    let mut far_future = record(key.clone(), 1, &lease);
    far_future.expires_at = Some(maximum_plus_one);
    assert_store_expiry_error(
        backend
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: far_future,
            })
            .await
            .expect_err("maximum plus one must fail"),
    );

    let mut immortal_ephemeral = record(key.clone(), 1, &lease);
    immortal_ephemeral.state_class = StateClass::EphemeralProcedure;
    assert_store_expiry_error(
        backend
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease,
                expected_generation: None,
                new_record: immortal_ephemeral,
            })
            .await
            .expect_err("ephemeral state must carry finite expiry"),
    );
    assert_eq!(backend.get(&key).await.expect("record"), None);
    assert_eq!(
        backend.max_replication_sequence().await.expect("head"),
        before_head
    );
    assert_eq!(replication_log(backend.as_ref()).await, before_log);
    assert!(watch.next().now_or_never().is_none());
}

async fn assert_absolute_expiry_batch_rebuild_and_replication_are_atomic(kind: BackendKind) {
    let now = base_timestamp();
    let maximum = checked_session_deadline(now, MAX_SESSION_TTL).expect("maximum expiry");
    let invalid = shift(maximum, time::Duration::nanoseconds(1));
    let clock = Arc::new(FixedClock::new(now));
    let backend = backend(kind, clock);
    let preserved_key = test_key(b"absolute-preserved");
    let (preserved_lease, preserved_record) = seed_record(backend.as_ref(), &preserved_key).await;
    let invalid_key = test_key(b"absolute-batch-invalid");
    let invalid_lease = backend
        .acquire(&invalid_key, owner("owner-a"), Duration::from_secs(60))
        .await
        .expect("invalid-slot lease");
    let mut invalid_record = record(invalid_key.clone(), 1, &invalid_lease);
    invalid_record.expires_at = Some(invalid);
    let before_head = backend.max_replication_sequence().await.expect("head");
    let before_log = replication_log(backend.as_ref()).await;

    assert_store_expiry_error(
        backend
            .batch(vec![
                SessionOp::DeleteFenced {
                    lease: preserved_lease,
                },
                SessionOp::CompareAndSet(CompareAndSet {
                    key: invalid_key.clone(),
                    lease: invalid_lease,
                    expected_generation: None,
                    new_record: invalid_record,
                }),
            ])
            .await
            .expect_err("whole batch must reject before its first mutation"),
    );
    assert_eq!(
        backend.get(&preserved_key).await.expect("preserved record"),
        Some(preserved_record.clone())
    );
    assert_eq!(
        backend.max_replication_sequence().await.expect("head"),
        before_head
    );
    assert_eq!(replication_log(backend.as_ref()).await, before_log);

    let replacement_key = test_key(b"absolute-rebuild-invalid");
    let lease_expiry =
        checked_session_deadline(now, Duration::from_secs(60)).expect("lease expiry");
    let mut replicated = replicated_record(
        replacement_key.clone(),
        1,
        owner("owner-a"),
        FenceToken::new(1),
    );
    replicated.expires_at = Some(invalid);
    let invalid_cas = ReplicationOp::CompareAndSet {
        key: replacement_key.clone(),
        expected_generation: None,
        credential_id: 1,
        guard_expires_at: lease_expiry,
        new_record: replicated,
    };
    let entry = replication_entry(1, "absolute-wire-invalid", now, invalid_cas.clone());
    assert_store_expiry_error(entry.validate().expect_err("entry timestamp is authority"));
    assert_store_expiry_error(
        backend
            .replicate_entry(entry)
            .await
            .expect_err("invalid replication CAS must fail before mutation"),
    );

    let rebuild = vec![
        replication_entry(
            1,
            "absolute-rebuild-lease",
            now,
            ttl_op(
                ReplicatedTtlKind::Acquire,
                replacement_key,
                Duration::from_secs(60),
                lease_expiry,
            ),
        ),
        replication_entry(2, "absolute-rebuild-cas", now, invalid_cas),
    ];
    assert_store_expiry_error(
        backend
            .rebuild_replication_state(rebuild)
            .await
            .expect_err("invalid rebuild must preserve prior state"),
    );
    assert_eq!(
        backend.get(&preserved_key).await.expect("preserved record"),
        Some(preserved_record)
    );
    assert_eq!(
        backend.max_replication_sequence().await.expect("head"),
        before_head
    );
    assert_eq!(replication_log(backend.as_ref()).await, before_log);
}

async fn assert_backend_contract(kind: BackendKind) {
    assert_acquire_boundaries(kind).await;
    assert_renew_boundaries(kind).await;
    assert_refresh_boundaries(kind).await;
    assert_batch_preflight_is_atomic(kind).await;
    assert_replicated_ttl_rejection_is_atomic(kind).await;
    assert_invalid_rebuild_preserves_state(kind).await;
    assert_absolute_record_expiry_boundaries(kind).await;
    assert_absolute_expiry_batch_rebuild_and_replication_are_atomic(kind).await;
}

#[tokio::test]
async fn fake_ttl_boundaries_are_exact_typed_and_atomic() {
    assert_backend_contract(BackendKind::Fake).await;
}

#[tokio::test]
async fn sqlite_ttl_boundaries_are_exact_typed_and_atomic() {
    assert_backend_contract(BackendKind::Sqlite).await;
}

#[test]
fn expiry_preflight_descriptor_limit_is_typed_and_redaction_safe() {
    let now = base_timestamp();
    let key = test_key(b"expiry-preflight-limit");
    let descriptor = RecordExpiryPreflight::from_record(&StoredSessionRecord {
        key,
        generation: Generation::new(1),
        owner: owner("expiry-preflight-owner"),
        fence: FenceToken::new(1),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::from_static("expiry-preflight-limit"),
        expires_at: Some(now),
        payload: EncryptedSessionPayload::new(b"expiry-preflight-limit-payload"),
    });
    assert!(
        opc_session_store::validate_record_expiry_preflights_profile(&vec![
        descriptor;
        MAX_RECORD_EXPIRY_PREFLIGHTS
    ])
        .is_ok()
    );
    let error = opc_session_store::validate_record_expiry_preflights_profile(&vec![
        descriptor;
        MAX_RECORD_EXPIRY_PREFLIGHTS
            + 1
    ])
    .expect_err("one-over descriptor set");
    assert_eq!(error, StoreError::RecordExpiryPreflightLimitExceeded);
    assert_eq!(
        error.to_string(),
        "session record-expiry preflight limit exceeded"
    );
    let rendered = format!("{error:?} {descriptor:?}");
    for forbidden in ["expiry-preflight-limit", "expiry-preflight-owner"] {
        assert!(!rendered.contains(forbidden));
    }
}
