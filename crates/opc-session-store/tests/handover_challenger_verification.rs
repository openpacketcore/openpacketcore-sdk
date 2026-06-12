use bytes::Bytes;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use opc_session_store::{
    clock::Clock, CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, Generation,
    HandoverEnvelope, HandoverError, HandoverManager, HandoverPhase, HandoverTxId, LeaseGuard,
    OwnerId, SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager, SqliteSessionBackend,
    StateClass, StateType, StoreError, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};

#[derive(Debug)]
struct StepClock {
    times: Mutex<Vec<Timestamp>>,
}

impl StepClock {
    fn new(sequence: Vec<Timestamp>) -> Self {
        Self {
            times: Mutex::new(sequence),
        }
    }
}

impl Clock for StepClock {
    fn now_utc(&self) -> Timestamp {
        let mut guard = self.times.lock().unwrap();
        if guard.len() > 1 {
            guard.remove(0)
        } else {
            guard[0]
        }
    }
}

fn tenant() -> TenantId {
    TenantId::new("tenant-challenger").expect("tenant")
}

fn test_key(stable_id: &[u8]) -> SessionKey {
    SessionKey {
        tenant: tenant(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(stable_id),
    }
}

async fn setup_initial_record(
    backend: &Arc<SqliteSessionBackend>,
    key: &SessionKey,
    owner: OwnerId,
    payload: &[u8],
) -> (LeaseGuard, StoredSessionRecord) {
    let lease = backend
        .acquire(key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let initial_envelope = HandoverEnvelope {
        phase: HandoverPhase::Stable,
        payload: payload.to_vec(),
    };
    let payload_bytes = initial_envelope.pack_raw().unwrap();
    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner: owner.clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("smf-pdu-context").expect("state type"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(payload_bytes),
    };
    let cas_res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();
    assert_eq!(cas_res, CompareAndSetResult::Success);
    (lease, record)
}

#[tokio::test]
async fn test_target_stale_lease_rejection() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = HandoverManager::new(backend.clone(), Arc::new(opc_session_store::SystemClock));
    let key = test_key(b"target-stale-lease-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();
    let tx = HandoverTxId::new();

    let (lease_s, _record) =
        setup_initial_record(&backend, &key, owner_s.clone(), b"session-payload").await;

    // 1. Prepare
    manager
        .prepare_handover(&lease_s, Generation::new(1), tx, owner_t.clone())
        .await
        .unwrap();

    // Release source lease
    backend.release(lease_s.clone()).await.unwrap();

    // 2. Target T acquires first lease T1 (e.g. fence = 3)
    let lease_t1 = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    // Release T1 so T can acquire T2
    backend.release(lease_t1.clone()).await.unwrap();

    // 3. Target T acquires second lease T2 (e.g. fence = 4)
    let lease_t2 = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    // Now lease_t1 is stale because lease_t2 is active in the database.
    // Try to mark prepared using stale lease_t1 -> should fail with StaleFence (wrapped in HandoverError::Store)
    let res = manager
        .mark_prepared(&lease_t1, Generation::new(2), tx)
        .await;
    assert!(
        matches!(res, Err(HandoverError::Store(StoreError::StaleFence))),
        "Expected StoreError::StaleFence, got {res:?}"
    );

    // Try to mark prepared using active lease_t2 -> should succeed
    manager
        .mark_prepared(&lease_t2, Generation::new(2), tx)
        .await
        .unwrap();

    // Try to activate using stale lease_t1 -> should fail
    let res = manager
        .activate_handover(&lease_t1, Generation::new(3), tx)
        .await;
    assert!(
        matches!(
            res,
            Err(HandoverError::FencingMismatch { .. })
                | Err(HandoverError::Store(StoreError::StaleFence))
        ),
        "Expected FencingMismatch or StaleFence, got {res:?}"
    );

    // Try to activate using active lease_t2 -> should succeed
    manager
        .activate_handover(&lease_t2, Generation::new(3), tx)
        .await
        .unwrap();

    // Try to complete using stale lease_t1 -> should fail
    let res = manager
        .complete_handover(&lease_t1, Generation::new(4), tx)
        .await;
    assert!(
        matches!(
            res,
            Err(HandoverError::FencingMismatch { .. })
                | Err(HandoverError::Store(StoreError::StaleFence))
        ),
        "Expected FencingMismatch or StaleFence, got {res:?}"
    );

    // Try to complete using active lease_t2 -> should succeed
    manager
        .complete_handover(&lease_t2, Generation::new(4), tx)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_source_stale_lease_rejection() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = HandoverManager::new(backend.clone(), Arc::new(opc_session_store::SystemClock));
    let key = test_key(b"source-stale-lease-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();
    let tx = HandoverTxId::new();

    // S acquires S1
    let lease_s1 = backend
        .acquire(&key, owner_s.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    // Setup initial record with lease_s1
    let initial_envelope = HandoverEnvelope {
        phase: HandoverPhase::Stable,
        payload: b"session-payload".to_vec(),
    };
    let payload_bytes = initial_envelope.pack_raw().unwrap();
    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner: owner_s.clone(),
        fence: lease_s1.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("smf-pdu-context").expect("state type"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(payload_bytes),
    };
    let cas_res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease_s1.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();
    assert_eq!(cas_res, CompareAndSetResult::Success);

    // S releases S1
    backend.release(lease_s1.clone()).await.unwrap();

    // S acquires S2 (fence is incremented)
    let lease_s2 = backend
        .acquire(&key, owner_s.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    // S1 is now stale. Call prepare_handover using S1 -> should fail with StaleFence (wrapped in HandoverError::Store)
    let res = manager
        .prepare_handover(&lease_s1, Generation::new(1), tx, owner_t.clone())
        .await;
    assert!(
        matches!(res, Err(HandoverError::Store(StoreError::StaleFence))),
        "Expected StoreError::StaleFence, got {res:?}"
    );

    // Call prepare_handover using S2 -> should succeed
    manager
        .prepare_handover(&lease_s2, Generation::new(1), tx, owner_t.clone())
        .await
        .unwrap();
}

#[tokio::test]
async fn test_lease_expiration_during_handover_operations() {
    let start_time = Timestamp::from_offset_datetime(
        time::Date::from_calendar_date(2026, time::Month::June, 6)
            .unwrap()
            .with_hms_nano(10, 0, 0, 0)
            .unwrap()
            .assume_utc(),
    );

    // We will construct a sequence of times for StepClock where the first check in HandoverManager (e.g. lease.expires_at() <= clock.now_utc()) passes
    // because now_utc() is start_time, but when backend.compare_and_set/backend.get runs, now_utc() returns an expired time (e.g. start_time + 10s).
    // Note: lease expires at start_time + 5s.
    let expired_now = Timestamp::from_offset_datetime(
        *start_time.as_offset_datetime() + time::Duration::seconds(10),
    );

    // Let's test prepare_handover
    {
        let clock = Arc::new(StepClock::new(vec![
            start_time,  // Used by backend.acquire
            start_time,  // Used by backend.compare_and_set (init)
            start_time,  // HandoverManager check
            expired_now, // backend.get
            expired_now, // backend.compare_and_set (lease expiration check)
        ]));

        let backend = Arc::new(
            SqliteSessionBackend::in_memory()
                .unwrap()
                .with_clock(clock.clone()),
        );
        let manager = HandoverManager::new(backend.clone(), clock.clone());
        let key = test_key(b"exp-during-prepare");
        let owner_s = OwnerId::new("owner-source").unwrap();
        let owner_t = OwnerId::new("owner-target").unwrap();
        let tx = HandoverTxId::new();

        // Acquire lease S with TTL of 5 seconds (expires at start_time + 5s)
        let lease_s = backend
            .acquire(&key, owner_s.clone(), Duration::from_secs(5))
            .await
            .unwrap();

        // Write initial record
        let initial_envelope = HandoverEnvelope {
            phase: HandoverPhase::Stable,
            payload: b"payload".to_vec(),
        };
        let payload_bytes = initial_envelope.pack_raw().unwrap();
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner: owner_s.clone(),
            fence: lease_s.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("smf-pdu-context").expect("state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(payload_bytes),
        };
        backend
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease_s.clone(),
                expected_generation: None,
                new_record: record.clone(),
            })
            .await
            .unwrap();

        // Calling prepare_handover.
        // StepClock sequence will return:
        // 1st: start_time (lease.expires_at() <= now_utc() check -> 5 <= 0? false, valid)
        // 2nd: expired_now (backend.get)
        // 3rd: expired_now (backend.compare_and_set -> lease validation will fail with LeaseExpired)
        let res = manager
            .prepare_handover(&lease_s, Generation::new(1), tx, owner_t.clone())
            .await;
        assert!(
            matches!(res, Err(HandoverError::Store(StoreError::LeaseExpired))),
            "Expected StoreError::LeaseExpired, got {res:?}"
        );
    }
}

#[tokio::test]
async fn test_abort_and_finalize_stale_lease_rejection() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = HandoverManager::new(backend.clone(), Arc::new(opc_session_store::SystemClock));
    let key = test_key(b"abort-stale-lease-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();
    let tx = HandoverTxId::new();

    // 1. S acquires S1
    let lease_s1 = backend
        .acquire(&key, owner_s.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    // Setup initial record
    let initial_envelope = HandoverEnvelope {
        phase: HandoverPhase::Stable,
        payload: b"payload".to_vec(),
    };
    let payload_bytes = initial_envelope.pack_raw().unwrap();
    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner: owner_s.clone(),
        fence: lease_s1.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("smf-pdu-context").expect("state type"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(payload_bytes),
    };
    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease_s1.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();

    // S prepares handover using S1
    manager
        .prepare_handover(&lease_s1, Generation::new(1), tx, owner_t.clone())
        .await
        .unwrap();

    // Release S1
    backend.release(lease_s1.clone()).await.unwrap();

    // S acquires S2 (fence is incremented, S1 is now stale)
    let lease_s2 = backend
        .acquire(&key, owner_s.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    // S tries to abort using stale S1 -> should fail with StaleFence (wrapped in HandoverError::Store)
    let res = manager
        .abort_handover(&lease_s1, Generation::new(2), tx)
        .await;
    assert!(
        matches!(res, Err(HandoverError::Store(StoreError::StaleFence))),
        "Expected StoreError::StaleFence, got {res:?}"
    );

    // S aborts using S2 -> should succeed (phase becomes Aborting)
    manager
        .abort_handover(&lease_s2, Generation::new(2), tx)
        .await
        .unwrap();

    // Release S2
    backend.release(lease_s2.clone()).await.unwrap();

    // S acquires S3 (fence is incremented, S2 is now stale)
    let lease_s3 = backend
        .acquire(&key, owner_s.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    // S tries to finalize abort using stale S2 -> should fail with StaleFence (wrapped in HandoverError::Store)
    let res = manager
        .finalize_abort(&lease_s2, Generation::new(3), tx, owner_s.clone())
        .await;
    assert!(
        matches!(res, Err(HandoverError::Store(StoreError::StaleFence))),
        "Expected StoreError::StaleFence, got {res:?}"
    );

    // S finalizes abort using S3 -> should succeed (phase becomes Stable)
    manager
        .finalize_abort(&lease_s3, Generation::new(3), tx, owner_s.clone())
        .await
        .unwrap();

    // Verify final phase is Stable
    let rec = manager.get_record::<Vec<u8>>(&key).await.unwrap().unwrap();
    assert_eq!(rec.phase, HandoverPhase::Stable);
}
