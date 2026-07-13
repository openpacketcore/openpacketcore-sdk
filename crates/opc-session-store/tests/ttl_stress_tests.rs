use bytes::Bytes;
use opc_session_store::{
    clock::Clock, CompareAndSet, EncryptedSessionPayload, FakeSessionBackend, Generation, OwnerId,
    SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager, SqliteSessionBackend,
    StateClass, StateType, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug)]
struct ManualClock {
    current: Mutex<Timestamp>,
}

impl ManualClock {
    fn new(start: Timestamp) -> Self {
        Self {
            current: Mutex::new(start),
        }
    }

    fn advance(&self, duration: Duration) {
        let mut guard = self.current.lock().unwrap();
        let next =
            *guard.as_offset_datetime() + time::Duration::seconds_f64(duration.as_secs_f64());
        *guard = Timestamp::from_offset_datetime(next);
    }

    fn set(&self, ts: Timestamp) {
        let mut guard = self.current.lock().unwrap();
        *guard = ts;
    }
}

impl Clock for ManualClock {
    fn now_utc(&self) -> Timestamp {
        *self.current.lock().unwrap()
    }
}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").expect("tenant")
}

fn test_key(stable_id: &[u8]) -> SessionKey {
    SessionKey {
        tenant: tenant(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(stable_id)
            .try_into()
            .expect("valid stable ID"),
    }
}

fn test_record(
    key: SessionKey,
    lease_fence: opc_session_store::model::FenceToken,
    owner: OwnerId,
) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(1),
        owner,
        fence: lease_fence,
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("smf-pdu-context").unwrap(),
        expires_at: None,
        payload: EncryptedSessionPayload::new(b"payload-data"),
    }
}

async fn run_boundary_test<B>(backend: B, clock: Arc<ManualClock>, start_time: Timestamp)
where
    B: SessionBackend + SessionLeaseManager + Clone + 'static,
{
    let key = test_key(b"boundary-key");

    // 1. Acquire lease with 1 second TTL
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();

    // Write a record that expires at the same time as the lease
    let mut record = test_record(key.clone(), lease.fence(), lease.owner().clone());
    record.expires_at = Some(lease.expires_at());

    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record,
        })
        .await
        .unwrap();

    // 2. Advance clock exactly 1 second (expires_at == now)
    clock.advance(Duration::from_secs(1));

    // 3. Verify get returns None (record expired at boundary)
    let got = backend.get(&key).await.unwrap();
    assert!(
        got.is_none(),
        "Record should be expired when now == expires_at"
    );

    // 4. Verify lease cannot be renewed (lease expired at boundary)
    let renew_res = backend.renew(&lease, Duration::from_secs(5)).await;
    assert!(
        renew_res.is_err(),
        "Lease should not be renewable when now == expires_at"
    );

    // Reset clock for next test
    clock.set(start_time);
}

// Test 1: Boundary conditions for expiration on exact bounds (expires_at == now)
#[tokio::test]
async fn test_expiration_boundary_conditions() {
    let start_time = Timestamp::now_utc();
    let clock = Arc::new(ManualClock::new(start_time));

    let fake_backend = FakeSessionBackend::new().with_clock(clock.clone());
    run_boundary_test(fake_backend, clock.clone(), start_time).await;

    let sqlite_backend = SqliteSessionBackend::in_memory()
        .unwrap()
        .with_clock(clock.clone());
    run_boundary_test(sqlite_backend, clock.clone(), start_time).await;
}

async fn run_clock_skew_test<B>(backend: B, clock: Arc<ManualClock>, start_time: Timestamp)
where
    B: SessionBackend + SessionLeaseManager + Clone + 'static,
{
    let key = test_key(b"skew-key");

    // 1. Acquire lease
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

    // 2. Write record
    let mut record = test_record(key.clone(), lease.fence(), lease.owner().clone());
    record.expires_at = Some(lease.expires_at());
    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record,
        })
        .await
        .unwrap();

    // 3. Perform a clock skew backward (clock jumps back by 10 seconds)
    let skew_time = *start_time.as_offset_datetime() - time::Duration::seconds(10);
    clock.set(Timestamp::from_offset_datetime(skew_time));

    // 4. Record and lease should still be active/valid because now is before expires_at
    let got = backend.get(&key).await.unwrap();
    assert!(
        got.is_some(),
        "Record should be valid after backward clock jump"
    );

    let renew_res = backend.renew(&lease, Duration::from_secs(5)).await;
    assert!(
        renew_res.is_ok(),
        "Lease renewal should succeed after backward clock jump"
    );

    let updated_lease = renew_res.unwrap();

    // 5. Jump clock forward to expiration (original start_time + 15 seconds)
    let expiry_time = *start_time.as_offset_datetime() + time::Duration::seconds(15);
    clock.set(Timestamp::from_offset_datetime(expiry_time));

    // 6. Record and lease should now be expired
    let got = backend.get(&key).await.unwrap();
    assert!(
        got.is_none(),
        "Record should be expired after moving past expiry"
    );

    // 7. Try renewal of the updated lease, should fail
    let renew_res = backend.renew(&updated_lease, Duration::from_secs(5)).await;
    assert!(renew_res.is_err(), "Lease renewal should fail after expiry");

    // 8. Verify that jumping the clock back to start_time does NOT restore the record,
    // because physical pruning has already deleted the row.
    clock.set(start_time);
    let got_after_restore = backend.get(&key).await.unwrap();
    assert!(
        got_after_restore.is_none(),
        "Pruned records must not reappear when clock jumps back"
    );

    // Reset clock
    clock.set(start_time);
}

// Test 2: Clock skews / backward jumps
#[tokio::test]
async fn test_clock_skew_backward_jump() {
    let start_time = Timestamp::now_utc();
    let clock = Arc::new(ManualClock::new(start_time));

    let fake_backend = FakeSessionBackend::new().with_clock(clock.clone());
    run_clock_skew_test(fake_backend, clock.clone(), start_time).await;

    let sqlite_backend = SqliteSessionBackend::in_memory()
        .unwrap()
        .with_clock(clock.clone());
    run_clock_skew_test(sqlite_backend, clock.clone(), start_time).await;
}

// Test 3: Concurrency and race conditions around lease takeover and renewal
#[tokio::test]
async fn test_lease_takeover_concurrency_race() {
    let start_time = Timestamp::now_utc();
    let clock = Arc::new(ManualClock::new(start_time));

    // SQLite backed store
    let backend = Arc::new(
        SqliteSessionBackend::in_memory()
            .unwrap()
            .with_clock(clock.clone()),
    );
    let key = test_key(b"concurrency-key");

    // Acquire initial lease for owner-a
    let lease_a = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();

    // Advance clock to the point where lease is expired
    clock.advance(Duration::from_secs(2));

    // Now, we have multiple tasks trying to take over the lease (owner-b, owner-c, owner-d)
    // and owner-a trying to renew (which should fail because the lease is already expired).
    let mut tasks = vec![];

    let b_clone = backend.clone();
    // Task 0: owner-a trying to renew (should fail)
    tasks.push(tokio::spawn(async move {
        b_clone.renew(&lease_a, Duration::from_secs(5)).await
    }));

    // Spawn 10 tasks trying to acquire the lease for owner-b, owner-c, etc.
    for i in 0..10 {
        let b_clone = backend.clone();
        let k_clone = key.clone();
        let owner_id = OwnerId::new(format!("owner-{i}")).unwrap();
        tasks.push(tokio::spawn(async move {
            b_clone
                .acquire(&k_clone, owner_id, Duration::from_secs(5))
                .await
        }));
    }

    let results = futures_util::future::join_all(tasks).await;

    // Analyze results:
    // 1. The renew attempt from owner-a MUST fail with LeaseError::Expired or similar because the lease was already expired.
    // 2. Exactly one of the acquire attempts from the other owners must succeed (first to get the lock/write transaction).
    // 3. The other acquire attempts must fail because once the first one acquires it, the lease is active again, blocking others.

    let renew_result = results[0].as_ref().unwrap();
    assert!(renew_result.is_err(), "Renewing expired lease must fail");

    let mut success_count = 0;
    for res in results.iter().skip(1) {
        if res.as_ref().unwrap().is_ok() {
            success_count += 1;
        }
    }

    assert_eq!(
        success_count, 1,
        "Exactly one concurrent acquire must succeed, but got {success_count}"
    );
}
