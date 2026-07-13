use bytes::Bytes;
use opc_session_store::{
    clock::Clock, CompareAndSet, EncryptedSessionPayload, Generation, OwnerId, SessionBackend,
    SessionKey, SessionKeyType, SessionLeaseManager, SqliteSessionBackend, StateClass, StateType,
    StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Clone)]
struct FixedClock {
    time: Arc<std::sync::Mutex<Timestamp>>,
}

impl Clock for FixedClock {
    fn now_utc(&self) -> Timestamp {
        *self.time.lock().unwrap()
    }
}

#[tokio::test]
async fn test_sqlite_string_comparison_subsecond_bug() {
    // Parse base time with zero subseconds: 2026-06-06T10:00:00Z
    let base_time = Timestamp::from_str("2026-06-06T10:00:00Z").unwrap();
    let clock = Arc::new(FixedClock {
        time: Arc::new(std::sync::Mutex::new(base_time)),
    });

    let backend = SqliteSessionBackend::in_memory()
        .unwrap()
        .with_clock(clock.clone());

    let key = SessionKey {
        tenant: TenantId::new("tenant-a").unwrap(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(vec![1, 2, 3])
            .try_into()
            .expect("valid stable ID"),
    };

    // Acquire lease
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(10),
        )
        .await
        .unwrap();

    // Set expires_at to 100 milliseconds in the future: 2026-06-06T10:00:00.100Z
    let expires_at = Timestamp::from_str("2026-06-06T10:00:00.100Z").unwrap();

    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("test").unwrap(),
        expires_at: Some(expires_at),
        payload: EncryptedSessionPayload::new(b"data"),
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

    let got = backend.get(&key).await.unwrap();
    assert!(
        got.is_some(),
        "Record should not be pruned because it expires in the future!"
    );
}

#[tokio::test]
async fn test_sqlite_string_comparison_subsecond_bug_not_pruning_expired() {
    // Parse base time with zero subseconds: 2026-06-06T10:00:00Z
    let base_time = Timestamp::from_str("2026-06-06T10:00:00Z").unwrap();
    let clock_state = Arc::new(std::sync::Mutex::new(base_time));
    let clock = Arc::new(FixedClock {
        time: clock_state.clone(),
    });

    // Use NamedTempFile to inspect raw database rows
    let tmp_file = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp_file.path();

    let backend = SqliteSessionBackend::open(db_path)
        .unwrap()
        .with_clock(clock.clone());

    let key = SessionKey {
        tenant: TenantId::new("tenant-a").unwrap(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(vec![4, 5, 6])
            .try_into()
            .expect("valid stable ID"),
    };

    // Acquire lease
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(10),
        )
        .await
        .unwrap();

    // Set expires_at with zero subseconds: 2026-06-06T10:00:00Z
    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("test").unwrap(),
        expires_at: Some(base_time),
        payload: EncryptedSessionPayload::new(b"data"),
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

    // Advance clock to 1 millisecond in the future of the base_time: 2026-06-06T10:00:00.001Z
    let now_time = Timestamp::from_str("2026-06-06T10:00:00.001Z").unwrap();
    *clock_state.lock().unwrap() = now_time;

    // This triggers prune_sync internally
    let _got = backend.get(&key).await.unwrap();

    // Open connection directly to verify if row was deleted
    let conn = rusqlite::Connection::open(db_path).unwrap();
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM session_records", [], |r| r.get(0))
        .unwrap();
    assert_eq!(
        count, 0,
        "Record should be pruned from SQLite table because now is after expires_at!"
    );
}

#[tokio::test]
async fn test_sqlite_lease_premature_millisecond_prune() {
    // Base time: 2026-06-06T10:00:00.000100000Z (100 microseconds)
    let base_time = Timestamp::from_str("2026-06-06T10:00:00.000100000Z").unwrap();
    let clock_state = Arc::new(std::sync::Mutex::new(base_time));
    let clock = Arc::new(FixedClock {
        time: clock_state.clone(),
    });

    let tmp_file = tempfile::NamedTempFile::new().unwrap();
    let db_path = tmp_file.path();
    let backend = SqliteSessionBackend::open(db_path)
        .unwrap()
        .with_clock(clock.clone());

    let key = SessionKey {
        tenant: TenantId::new("tenant-a").unwrap(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::from(vec![7, 8, 9])
            .try_into()
            .expect("valid stable ID"),
    };

    // Acquire lease at base_time (100 microseconds) with a TTL of 800 microseconds.
    // The expires_at should be 2026-06-06T10:00:00.000900000Z (900 microseconds).
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_nanos(800_000),
        )
        .await
        .unwrap();

    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("test").unwrap(),
        expires_at: None,
        payload: EncryptedSessionPayload::new(b"data"),
    };

    let res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease,
            expected_generation: None,
            new_record: record,
        })
        .await;

    assert!(
        res.is_ok(),
        "CAS should succeed because lease is still valid (100us < 900us), but got: {res:?}"
    );
}
