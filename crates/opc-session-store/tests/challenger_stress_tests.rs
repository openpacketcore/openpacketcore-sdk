use bytes::Bytes;
use opc_session_store::{
    clock::Clock, CompareAndSet, EncryptedSessionPayload, FakeSessionBackend, Generation,
    LeaseError, OwnerId, SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager,
    SqliteSessionBackend, StateClass, StateType, StoreError, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone)]
struct ManualClock {
    time: Arc<Mutex<Timestamp>>,
}

impl ManualClock {
    fn new(t: Timestamp) -> Self {
        Self {
            time: Arc::new(Mutex::new(t)),
        }
    }

    fn advance(&self, duration: Duration) {
        let mut guard = self.time.lock().unwrap();
        let odt = *guard.as_offset_datetime() + time::Duration::seconds_f64(duration.as_secs_f64());
        *guard = Timestamp::from_offset_datetime(odt);
    }
}

impl Clock for ManualClock {
    fn now_utc(&self) -> Timestamp {
        *self.time.lock().unwrap()
    }
}

fn test_key(stable_id: &[u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::new("tenant-challenger").unwrap(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(stable_id)
            .try_into()
            .expect("valid stable ID"),
    }
}

#[tokio::test]
async fn test_expired_lease_write_rejections_fake() {
    let base_time = Timestamp::now_utc();
    let clock = Arc::new(ManualClock::new(base_time));
    let backend = FakeSessionBackend::new().with_clock(clock.clone());
    let key = test_key(b"fake-exp-rejections");

    // 1. Acquire lease
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(5),
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

    // 2. Advance clock so lease expires
    clock.advance(Duration::from_secs(6));

    // 3. Test CAS write rejects with LeaseExpired
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
    assert_eq!(cas_res, Err(StoreError::LeaseExpired));

    // 4. Test delete_fenced rejects with LeaseExpired
    let del_res = backend.delete_fenced(&lease).await;
    assert_eq!(del_res, Err(StoreError::LeaseExpired));

    // 5. Test refresh_ttl rejects with LeaseExpired
    let refresh_res = backend.refresh_ttl(&lease, Duration::from_secs(10)).await;
    assert_eq!(refresh_res, Err(StoreError::LeaseExpired));

    // 6. Test renew rejects with Expired
    let renew_res = backend.renew(&lease, Duration::from_secs(5)).await;
    assert_eq!(renew_res, Err(LeaseError::Expired));
}

#[tokio::test]
async fn test_expired_lease_write_rejections_sqlite() {
    let base_time = Timestamp::now_utc();
    let clock = Arc::new(ManualClock::new(base_time));
    let backend = SqliteSessionBackend::in_memory()
        .unwrap()
        .with_clock(clock.clone());
    let key = test_key(b"sqlite-exp-rejections");

    // 1. Acquire lease
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(5),
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

    // 2. Advance clock so lease expires
    clock.advance(Duration::from_secs(6));

    // 3. Test CAS write rejects with LeaseExpired
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
    assert_eq!(cas_res, Err(StoreError::LeaseExpired));

    // 4. Test delete_fenced rejects with LeaseExpired
    let del_res = backend.delete_fenced(&lease).await;
    assert_eq!(del_res, Err(StoreError::LeaseExpired));

    // 5. Test refresh_ttl rejects with LeaseExpired
    let refresh_res = backend.refresh_ttl(&lease, Duration::from_secs(10)).await;
    assert_eq!(refresh_res, Err(StoreError::LeaseExpired));

    // 6. Test renew rejects with Expired
    let renew_res = backend.renew(&lease, Duration::from_secs(5)).await;
    assert_eq!(renew_res, Err(LeaseError::Expired));
}

#[tokio::test]
async fn test_subsecond_boundary_conditions_precision() {
    let base_time = Timestamp::now_utc();
    let clock = Arc::new(ManualClock::new(base_time));
    let fake_backend = FakeSessionBackend::new().with_clock(clock.clone());
    let sqlite_backend = SqliteSessionBackend::in_memory()
        .unwrap()
        .with_clock(clock.clone());

    let key_fake = test_key(b"subsecond-boundary-fake");
    let key_sqlite = test_key(b"subsecond-boundary-sqlite");

    for (backend, key) in [
        (
            Arc::new(fake_backend) as Arc<dyn SessionLeaseManager>,
            key_fake,
        ),
        (
            Arc::new(sqlite_backend) as Arc<dyn SessionLeaseManager>,
            key_sqlite,
        ),
    ] {
        // Acquire lease for exactly 10 milliseconds
        let lease = backend
            .acquire(
                &key,
                OwnerId::new("owner-a").unwrap(),
                Duration::from_millis(10),
            )
            .await
            .unwrap();

        // 9 milliseconds later: should NOT be expired yet
        clock.advance(Duration::from_millis(9));
        let renew_res = backend.renew(&lease, Duration::from_secs(5)).await;
        assert!(renew_res.is_ok(), "Lease should not expire at 9ms");

        // Use the renewed lease (expires in 5s)
        let renewed_lease = renew_res.unwrap();

        // 4999 milliseconds later: should NOT be expired yet
        clock.advance(Duration::from_millis(4999));
        let renew_res_2 = backend.renew(&renewed_lease, Duration::from_secs(2)).await;
        assert!(renew_res_2.is_ok(), "Lease should not expire at 4999ms");

        // 2001 milliseconds later: should definitely be expired now
        clock.advance(Duration::from_millis(2001));
        let renew_res_3 = backend
            .renew(&renew_res_2.unwrap(), Duration::from_secs(5))
            .await;
        assert_eq!(
            renew_res_3,
            Err(LeaseError::Expired),
            "Lease must be expired after its TTL"
        );
    }
}
