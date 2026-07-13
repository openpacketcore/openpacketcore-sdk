use bytes::Bytes;
use opc_session_store::{
    clock::Clock, CompareAndSet, EncryptedSessionPayload, FakeSessionBackend, Generation,
    LeaseError, OwnerId, SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager,
    SqliteSessionBackend, StateClass, StateType, StoreError, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug)]
struct MockClock {
    current: Mutex<Timestamp>,
}

impl MockClock {
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

impl Clock for MockClock {
    fn now_utc(&self) -> Timestamp {
        *self.current.lock().unwrap()
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
        payload: EncryptedSessionPayload::new(b"challenger-data"),
    }
}

#[tokio::test]
async fn test_sqlite_nanosecond_precision_expiration() {
    // Start at a precise timestamp with fractional seconds: 2026-06-06T10:00:00.000100000Z
    let start_time = Timestamp::from_offset_datetime(
        time::Date::from_calendar_date(2026, time::Month::June, 6)
            .unwrap()
            .with_hms_nano(10, 0, 0, 100_000)
            .unwrap()
            .assume_utc(),
    );
    let clock = Arc::new(MockClock::new(start_time));
    let backend = SqliteSessionBackend::in_memory()
        .unwrap()
        .with_clock(clock.clone());

    let key = test_key(b"nanosecond-precision-key");

    // Acquire lease for 800 microseconds (800_000 nanoseconds)
    // Expiry should be exactly at 10:00:00.000900000Z
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-challenger").unwrap(),
            Duration::from_nanos(800_000),
        )
        .await
        .unwrap();

    // Verify lease expiration timestamp
    let expected_expiry = Timestamp::from_offset_datetime(
        time::Date::from_calendar_date(2026, time::Month::June, 6)
            .unwrap()
            .with_hms_nano(10, 0, 0, 900_000)
            .unwrap()
            .assume_utc(),
    );
    assert_eq!(lease.expires_at(), expected_expiry);

    // 1. Write record before expiry (at 10:00:00.000100000Z)
    let record = test_record(key.clone(), lease.fence(), lease.owner().clone());
    let cas_res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record,
        })
        .await;
    assert!(cas_res.is_ok(), "CAS should succeed before expiry");

    // 2. Advance clock to 799 microseconds from start (10:00:00.000899000Z)
    // The lease is still valid (899us < 900us)
    clock.set(Timestamp::from_offset_datetime(
        time::Date::from_calendar_date(2026, time::Month::June, 6)
            .unwrap()
            .with_hms_nano(10, 0, 0, 899_000)
            .unwrap()
            .assume_utc(),
    ));

    // CAS should still succeed or get should be valid
    let get_res = backend.get(&key).await.unwrap();
    assert!(
        get_res.is_some(),
        "Record should still be retrievable before expiry"
    );

    // 3. Advance clock to exactly 800 microseconds from start (10:00:00.000900000Z)
    // Now it is expired (900us == 900us)
    clock.set(Timestamp::from_offset_datetime(
        time::Date::from_calendar_date(2026, time::Month::June, 6)
            .unwrap()
            .with_hms_nano(10, 0, 0, 900_000)
            .unwrap()
            .assume_utc(),
    ));

    // Try a renew attempt at boundary, should return Expired
    let renew_res = backend.renew(&lease, Duration::from_secs(5)).await;
    assert_eq!(
        renew_res,
        Err(LeaseError::Expired),
        "Renew at boundary should fail with Expired"
    );
}

#[tokio::test]
async fn test_consistent_lease_expiry_rejection() {
    let start_time = Timestamp::now_utc();
    let clock = Arc::new(MockClock::new(start_time));

    let sqlite_backend = SqliteSessionBackend::in_memory()
        .unwrap()
        .with_clock(clock.clone());
    let fake_backend = FakeSessionBackend::new().with_clock(clock.clone());

    let key_sqlite = test_key(b"sqlite-expiry");
    let key_fake = test_key(b"fake-expiry");

    // Test SqliteSessionBackend
    run_expiry_rejection_suite(
        Arc::new(sqlite_backend),
        key_sqlite,
        clock.clone(),
        start_time,
    )
    .await;

    // Test FakeSessionBackend
    run_expiry_rejection_resolutions(Arc::new(fake_backend), key_fake, clock.clone(), start_time)
        .await;
}

async fn run_expiry_rejection_suite<B>(
    backend: Arc<B>,
    key: SessionKey,
    clock: Arc<MockClock>,
    start_time: Timestamp,
) where
    B: SessionBackend + SessionLeaseManager + 'static,
{
    clock.set(start_time);

    // Acquire lease for 1 second
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-challenger").unwrap(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();

    // Write a record
    let record = test_record(key.clone(), lease.fence(), lease.owner().clone());
    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();

    // Advance clock so lease expires
    clock.advance(Duration::from_secs(2));

    // 1. compare_and_set with expired lease must return Err(StoreError::LeaseExpired)
    let new_record = StoredSessionRecord {
        generation: Generation::new(2),
        payload: EncryptedSessionPayload::new(b"v2"),
        ..record.clone()
    };
    let cas_res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record,
        })
        .await;
    assert_eq!(
        cas_res,
        Err(StoreError::LeaseExpired),
        "compare_and_set with expired lease must return StoreError::LeaseExpired"
    );

    // 2. renew with expired lease must return Err(LeaseError::Expired)
    let renew_res = backend.renew(&lease, Duration::from_secs(5)).await;
    assert_eq!(
        renew_res,
        Err(LeaseError::Expired),
        "renew with expired lease must return LeaseError::Expired"
    );

    // 3. delete_fenced with expired lease must return Err(StoreError::LeaseExpired)
    let delete_res = backend.delete_fenced(&lease).await;
    assert_eq!(
        delete_res,
        Err(StoreError::LeaseExpired),
        "delete_fenced with expired lease must return StoreError::LeaseExpired"
    );

    // 4. refresh_ttl with expired lease must return Err(StoreError::LeaseExpired)
    let refresh_res = backend.refresh_ttl(&lease, Duration::from_secs(10)).await;
    assert_eq!(
        refresh_res,
        Err(StoreError::LeaseExpired),
        "refresh_ttl with expired lease must return StoreError::LeaseExpired"
    );
}

// Separate helper for FakeSessionBackend to avoid any trait bounds mismatch since both implement the same traits
async fn run_expiry_rejection_resolutions(
    backend: Arc<FakeSessionBackend>,
    key: SessionKey,
    clock: Arc<MockClock>,
    start_time: Timestamp,
) {
    clock.set(start_time);

    // Acquire lease for 1 second
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-challenger").unwrap(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();

    // Write a record
    let record = test_record(key.clone(), lease.fence(), lease.owner().clone());
    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();

    // Advance clock so lease expires
    clock.advance(Duration::from_secs(2));

    // 1. compare_and_set with expired lease must return Err(StoreError::LeaseExpired)
    let new_record = StoredSessionRecord {
        generation: Generation::new(2),
        payload: EncryptedSessionPayload::new(b"v2"),
        ..record.clone()
    };
    let cas_res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record,
        })
        .await;
    assert_eq!(
        cas_res,
        Err(StoreError::LeaseExpired),
        "compare_and_set with expired lease must return StoreError::LeaseExpired"
    );

    // 2. renew with expired lease must return Err(LeaseError::Expired)
    let renew_res = backend.renew(&lease, Duration::from_secs(5)).await;
    assert_eq!(
        renew_res,
        Err(LeaseError::Expired),
        "renew with expired lease must return LeaseError::Expired"
    );

    // 3. delete_fenced with expired lease must return Err(StoreError::LeaseExpired)
    let delete_res = backend.delete_fenced(&lease).await;
    assert_eq!(
        delete_res,
        Err(StoreError::LeaseExpired),
        "delete_fenced with expired lease must return StoreError::LeaseExpired"
    );

    // 4. refresh_ttl with expired lease must return Err(StoreError::LeaseExpired)
    let refresh_res = backend.refresh_ttl(&lease, Duration::from_secs(10)).await;
    assert_eq!(
        refresh_res,
        Err(StoreError::LeaseExpired),
        "refresh_ttl with expired lease must return StoreError::LeaseExpired"
    );
}
