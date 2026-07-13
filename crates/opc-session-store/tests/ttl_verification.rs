use bytes::Bytes;
use opc_session_store::{
    clock::TokioVirtualClock, CompareAndSet, EncryptedSessionPayload, Generation, OwnerId,
    SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager, SqliteSessionBackend,
    StateClass, StateType, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;

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

// Verification 1: Clock injection virtual time takeover success.
#[tokio::test(start_paused = true)]
async fn test_virtual_time_lease_takeover_success() {
    let clock = Arc::new(TokioVirtualClock::new());
    let backend = SqliteSessionBackend::in_memory().unwrap().with_clock(clock);
    let key = test_key(b"virtual-time-test");

    // 1. Acquire lease with a TTL of 1 second.
    let _lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();

    // 2. Advance tokio virtual time by 2 seconds.
    tokio::time::advance(Duration::from_secs(2)).await;

    // 3. Attempt takeover by owner-b.
    // Since we are using TokioVirtualClock and have advanced tokio virtual time,
    // the takeover should now succeed!
    let takeover_result = backend
        .acquire(
            &key,
            OwnerId::new("owner-b").unwrap(),
            Duration::from_secs(5),
        )
        .await;

    assert!(
        takeover_result.is_ok(),
        "Expected takeover to succeed, but got: {takeover_result:?}"
    );
}

// Verification 2: Non-leakage of expired records and leases in SQLite database (pruning).
#[tokio::test]
async fn test_database_row_pruning() {
    // Create a temporary database file
    let tmp_file = NamedTempFile::new().unwrap();
    let db_path = tmp_file.path();

    {
        let backend = SqliteSessionBackend::open(db_path).unwrap();
        let key = test_key(b"leak-test-key");

        // Acquire lease with a TTL of 500 ms
        let lease = backend
            .acquire(
                &key,
                OwnerId::new("owner-a").unwrap(),
                Duration::from_millis(500),
            )
            .await
            .unwrap();

        // Write a session record with expires_at in the past
        let now = Timestamp::now_utc();
        let past = *now.as_offset_datetime() - time::Duration::seconds_f64(10.0);
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner: lease.owner().clone(),
            fence: lease.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("smf-pdu-context").unwrap(),
            expires_at: Some(Timestamp::from_offset_datetime(past)),
            payload: EncryptedSessionPayload::new(b"secret-payload"),
        };

        backend
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease,
                expected_generation: None,
                new_record: record,
            })
            .await
            .unwrap();

        // Wait for the lease to definitely expire in real time (sleep 600 ms)
        tokio::time::sleep(Duration::from_millis(600)).await;

        // Verify that the record is indeed expired and get returns None
        let got = backend.get(&key).await.unwrap();
        assert!(got.is_none(), "Record should be expired");
    }

    // Now open the database file directly via rusqlite Connection to inspect row counts.
    let conn = rusqlite::Connection::open(db_path).unwrap();

    // 1. Verify session_records table contains 0 records (expired record pruned).
    let record_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM session_records", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        record_count, 0,
        "Expired records should be physically pruned from database"
    );

    // 2. Verify leases table contains 0 records (expired lease pruned).
    let lease_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM leases", [], |row| row.get(0))
        .unwrap();
    assert_eq!(
        lease_count, 0,
        "Expired leases should be physically pruned from database"
    );
}

use opc_session_store::{Clock, FakeSessionBackend};
use std::sync::Mutex;

#[derive(Debug)]
struct MockClock {
    now: Mutex<Timestamp>,
}

impl MockClock {
    fn new(t: Timestamp) -> Self {
        Self { now: Mutex::new(t) }
    }

    fn set_time(&self, t: Timestamp) {
        *self.now.lock().unwrap() = t;
    }

    fn advance(&self, duration: Duration) {
        let mut guard = self.now.lock().unwrap();
        let odt = *guard.as_offset_datetime() + time::Duration::seconds_f64(duration.as_secs_f64());
        *guard = Timestamp::from_offset_datetime(odt);
    }
}

impl Clock for MockClock {
    fn now_utc(&self) -> Timestamp {
        *self.now.lock().unwrap()
    }
}

// Verification 3: Verify clock skew and jump determinism using a mock clock.
#[tokio::test]
async fn test_clock_skew_and_jumps_determinism() {
    let base_time = Timestamp::now_utc();
    let clock = Arc::new(MockClock::new(base_time));

    // Test both SQLite and Fake backends
    let sqlite_backend = SqliteSessionBackend::in_memory()
        .unwrap()
        .with_clock(clock.clone());
    let fake_backend = FakeSessionBackend::new().with_clock(clock.clone());

    let key = test_key(b"skew-test-key");

    for backend in [
        Arc::new(sqlite_backend) as Arc<dyn SessionLeaseManager>,
        Arc::new(fake_backend) as Arc<dyn SessionLeaseManager>,
    ] {
        // Reset clock
        clock.set_time(base_time);

        // 1. Acquire lease with a TTL of 10 seconds.
        let lease = backend
            .acquire(
                &key,
                OwnerId::new("owner-a").unwrap(),
                Duration::from_secs(10),
            )
            .await
            .unwrap();

        assert_eq!(lease.owner().as_str(), "owner-a");

        // 2. Simulate clock skew / regression: time moves BACKWARD by 5 seconds.
        let backward_time = *base_time.as_offset_datetime() - time::Duration::seconds_f64(5.0);
        clock.set_time(Timestamp::from_offset_datetime(backward_time));

        // Try to takeover. Since lease is not expired (and in fact we set the clock back),
        // the takeover must fail with AlreadyHeld.
        let takeover_result = backend
            .acquire(
                &key,
                OwnerId::new("owner-b").unwrap(),
                Duration::from_secs(10),
            )
            .await;

        assert!(
            matches!(
                takeover_result,
                Err(opc_session_store::LeaseError::AlreadyHeld)
            ),
            "Expected AlreadyHeld, got: {takeover_result:?}"
        );

        // 3. Simulate clock jump: time moves FORWARD by 20 seconds from base_time.
        let forward_time = *base_time.as_offset_datetime() + time::Duration::seconds_f64(20.0);
        clock.set_time(Timestamp::from_offset_datetime(forward_time));

        // Since lease has now expired due to the forward jump, takeover must succeed.
        let takeover_result = backend
            .acquire(
                &key,
                OwnerId::new("owner-b").unwrap(),
                Duration::from_secs(10),
            )
            .await;

        assert!(
            takeover_result.is_ok(),
            "Expected takeover to succeed, but got: {takeover_result:?}"
        );
        let fresh_lease = takeover_result.unwrap();
        assert_eq!(fresh_lease.owner().as_str(), "owner-b");
    }
}

// Verification 4: CAS rejection when lease has expired under injected clock.
#[tokio::test]
async fn test_expired_lease_cas_rejection_with_injected_clock() {
    let base_time = Timestamp::now_utc();
    let clock = Arc::new(MockClock::new(base_time));

    let sqlite_backend = SqliteSessionBackend::in_memory()
        .unwrap()
        .with_clock(clock.clone());
    let fake_backend = FakeSessionBackend::new().with_clock(clock.clone());

    let key = test_key(b"cas-lease-exp");

    // Helper function to run the test
    async fn run_test<B>(
        backend: Arc<B>,
        key: SessionKey,
        clock: Arc<MockClock>,
        base_time: Timestamp,
    ) where
        B: SessionBackend + SessionLeaseManager + 'static,
    {
        clock.set_time(base_time);

        // Acquire lease for 10 seconds
        let lease = backend
            .acquire(
                &key,
                OwnerId::new("owner-a").unwrap(),
                Duration::from_secs(10),
            )
            .await
            .unwrap();

        // Write initial record
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner: lease.owner().clone(),
            fence: lease.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("smf-pdu-context").unwrap(),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"initial"),
        };

        backend
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: record.clone(),
            })
            .await
            .unwrap();

        // Now advance clock by 15 seconds so lease expires
        clock.advance(Duration::from_secs(15));

        // Attempt to write a new record using the expired lease.
        // This MUST fail because the lease is expired.
        let record_v2 = StoredSessionRecord {
            generation: Generation::new(2),
            payload: EncryptedSessionPayload::new(b"v2"),
            ..record
        };

        let cas_res = backend
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: Some(Generation::new(1)),
                new_record: record_v2,
            })
            .await;

        assert!(
            matches!(cas_res, Err(opc_session_store::StoreError::LeaseExpired)),
            "Expected StoreError::LeaseExpired, got: {cas_res:?}"
        );
    }

    run_test(
        Arc::new(sqlite_backend),
        key.clone(),
        clock.clone(),
        base_time,
    )
    .await;
    run_test(
        Arc::new(fake_backend),
        key.clone(),
        clock.clone(),
        base_time,
    )
    .await;
}

// Verification 5: Concurrent lease takeover race verification.
#[tokio::test]
async fn test_concurrency_lease_takeover_race() {
    let base_time = Timestamp::now_utc();
    let clock = Arc::new(MockClock::new(base_time));

    let sqlite_backend = Arc::new(
        SqliteSessionBackend::in_memory()
            .unwrap()
            .with_clock(clock.clone()),
    );
    let fake_backend = Arc::new(FakeSessionBackend::new().with_clock(clock.clone()));

    let key = test_key(b"concurrent-takeover");

    for backend in [
        sqlite_backend as Arc<dyn SessionLeaseManager>,
        fake_backend as Arc<dyn SessionLeaseManager>,
    ] {
        clock.set_time(base_time);

        // 1. Acquire lease as owner-a for 1 second.
        let _lease = backend
            .acquire(
                &key,
                OwnerId::new("owner-a").unwrap(),
                Duration::from_secs(1),
            )
            .await
            .unwrap();

        // 2. Advance clock so lease expires.
        clock.advance(Duration::from_secs(2));

        // 3. Spawn 20 tasks concurrently trying to acquire lease as different owners (owner-0 to owner-19).
        let mut tasks = Vec::new();
        for i in 0..20 {
            let backend_clone = backend.clone();
            let key_clone = key.clone();
            tasks.push(tokio::spawn(async move {
                backend_clone
                    .acquire(
                        &key_clone,
                        OwnerId::new(format!("owner-{i}")).unwrap(),
                        Duration::from_secs(10),
                    )
                    .await
            }));
        }

        let mut success_count = 0;
        let mut held_count = 0;

        for task in tasks {
            let res = task.await.unwrap();
            match res {
                Ok(_) => success_count += 1,
                Err(opc_session_store::LeaseError::AlreadyHeld) => held_count += 1,
                Err(other) => panic!("Unexpected error during concurrent acquire: {other:?}"),
            }
        }

        // Exactly one task must have succeeded in taking over the expired lease and securing the lock.
        // The rest must have been rejected because the first one immediately extended/secured it.
        assert_eq!(
            success_count, 1,
            "Exactly one owner must succeed in taking over the lease"
        );
        assert_eq!(
            held_count, 19,
            "All other concurrent attempts must fail with AlreadyHeld"
        );
    }
}
