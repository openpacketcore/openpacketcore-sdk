use bytes::Bytes;
use opc_crypto::CryptoEnvelopeV1;
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, EncryptingSessionBackend,
    Generation, LeaseError, OwnerId, SessionBackend, SessionKey, SessionKeyType,
    SessionLeaseManager, SessionOp, SessionOpResult, SqliteSessionBackend, StateClass, StateType,
    StoreError, StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, TenantId};
use std::{sync::Arc, time::Duration};
use tempfile::NamedTempFile;

fn tenant() -> TenantId {
    TenantId::new("tenant-a").expect("tenant")
}

fn test_provider() -> Arc<MemoryKeyProvider> {
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("session-active-2026-01").expect("key id"),
            KeyPurpose::Session,
            tenant(),
            Zeroizing::new([0x22; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("insert key");
    provider
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
    generation: u64,
    lease: &opc_session_store::LeaseGuard,
) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: lease.owner().clone(),
        fence: lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("smf-pdu-context").expect("state type"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"plain-session")),
    }
}

#[tokio::test]
async fn test_sqlite_capabilities_are_truthful_for_single_node_backend() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let caps = backend.capabilities().await;

    assert!(caps.atomic_compare_and_set);
    assert!(caps.monotonic_fencing_token);
    assert!(caps.per_key_ttl);
    assert!(caps.server_side_lease_expiry);
    assert!(caps.batch_write);
    assert!(caps.restore_scan);
    assert!(!caps.ordered_replication_log);
    assert!(!caps.watch);
    assert_eq!(caps.max_value_bytes, 1_048_576);
}

#[tokio::test]
async fn test_sqlite_restore_order_matches_canonical_key_type_order() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let key_types = vec![
        SessionKeyType::SubscriberContext,
        SessionKeyType::PduSession,
        SessionKeyType::TeidMapping,
        SessionKeyType::PfcpSeid,
        SessionKeyType::HandoverTransaction,
        SessionKeyType::other("aaa-custom").unwrap(),
        SessionKeyType::other("zzz-custom").unwrap(),
    ];

    for (index, key_type) in key_types.into_iter().enumerate() {
        let key = SessionKey {
            key_type,
            ..test_key(format!("ordered-{index}").as_bytes())
        };
        let lease = backend
            .acquire(
                &key,
                OwnerId::new("owner-a").unwrap(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        backend
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: test_record(key, 1, &lease),
            })
            .await
            .unwrap();
    }

    let request = opc_session_store::RestoreScanRequest::all(16);
    let page = backend.scan_restore_records(request.clone()).await.unwrap();
    page.validate_for_request(&request).unwrap();

    let observed = page
        .records
        .iter()
        .map(|record| record.key.key_type.as_str())
        .collect::<Vec<_>>();
    let mut expected = observed.clone();
    expected.sort_unstable();
    assert_eq!(observed, expected);
}

#[tokio::test]
async fn test_sqlite_file_backend_applies_wal_profile() {
    let file = NamedTempFile::new().unwrap();
    let path = file.path().to_path_buf();

    {
        let backend = SqliteSessionBackend::open(&path).unwrap();
        drop(backend);
    }

    let conn = rusqlite::Connection::open(&path).unwrap();
    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(journal_mode.to_lowercase(), "wal");
}

#[tokio::test]
async fn test_sqlite_basic_crud() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let key = test_key(b"crud-key");

    // Check get miss
    assert!(backend.get(&key).await.unwrap().is_none());

    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    // Create record
    let record = test_record(key.clone(), 1, &lease);
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

    // Get record
    let got = backend.get(&key).await.unwrap().unwrap();
    assert_eq!(got.generation, Generation::new(1));
    assert_eq!(got.payload.as_bytes(), b"plain-session");

    // Update record
    let updated = StoredSessionRecord {
        generation: Generation::new(2),
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"plain-session-updated")),
        ..record.clone()
    };
    let cas_res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record: updated.clone(),
        })
        .await
        .unwrap();
    assert_eq!(cas_res, CompareAndSetResult::Success);

    // Verify update
    let got = backend.get(&key).await.unwrap().unwrap();
    assert_eq!(got.generation, Generation::new(2));
    assert_eq!(got.payload.as_bytes(), b"plain-session-updated");

    // Delete record
    backend.delete_fenced(&lease).await.unwrap();
    assert!(backend.get(&key).await.unwrap().is_none());
}

#[tokio::test]
async fn test_sqlite_max_payload_bytes_is_enforced() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let caps = backend.capabilities().await;
    let key = test_key(b"max-payload");
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    let record = StoredSessionRecord {
        payload: EncryptedSessionPayload::new(Bytes::from(vec![0xAB; caps.max_value_bytes + 1])),
        ..test_record(key.clone(), 1, &lease)
    };

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease,
            expected_generation: None,
            new_record: record,
        })
        .await
        .unwrap_err();

    assert_eq!(
        err,
        StoreError::PayloadTooLarge {
            actual: caps.max_value_bytes + 1,
            max: caps.max_value_bytes
        }
    );
}

#[tokio::test]
async fn test_sqlite_duplicate_create_rejection() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let key = test_key(b"dup-create");
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    let record = test_record(key.clone(), 1, &lease);
    let res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();
    assert_eq!(res, CompareAndSetResult::Success);

    // Try creating again
    let res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();

    match res {
        CompareAndSetResult::Conflict { current } => {
            let current = current.unwrap();
            assert_eq!(current.generation, Generation::new(1));
        }
        CompareAndSetResult::Success => panic!("expected conflict on duplicate create"),
    }
}

#[tokio::test]
async fn test_sqlite_cas_success() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let key = test_key(b"cas-success");
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    let record = test_record(key.clone(), 1, &lease);
    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();

    let record_v2 = StoredSessionRecord {
        generation: Generation::new(2),
        ..record.clone()
    };

    let res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record: record_v2,
        })
        .await
        .unwrap();
    assert_eq!(res, CompareAndSetResult::Success);
}

#[tokio::test]
async fn test_sqlite_cas_stale_failure() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let key = test_key(b"cas-stale");
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    let record = test_record(key.clone(), 1, &lease);
    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();

    let record_v2 = StoredSessionRecord {
        generation: Generation::new(2),
        ..record.clone()
    };

    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record: record_v2.clone(),
        })
        .await
        .unwrap();

    // Attempting to CAS with stale expected generation 1 when current is 2
    let record_v3 = StoredSessionRecord {
        generation: Generation::new(3),
        ..record.clone()
    };
    let res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record: record_v3,
        })
        .await
        .unwrap();

    match res {
        CompareAndSetResult::Conflict { current } => {
            let current = current.unwrap();
            assert_eq!(current.generation, Generation::new(2));
        }
        CompareAndSetResult::Success => panic!("expected conflict on stale CAS"),
    }
}

#[tokio::test]
async fn test_sqlite_concurrent_cas_race() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let key = test_key(b"cas-race");
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    let record = test_record(key.clone(), 1, &lease);
    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();

    let mut tasks = Vec::new();
    for i in 0..10 {
        let backend_clone = backend.clone();
        let key_clone = key.clone();
        let lease_clone = lease.clone();
        let record_clone = record.clone();
        tasks.push(tokio::spawn(async move {
            let record_new = StoredSessionRecord {
                generation: Generation::new(2),
                payload: EncryptedSessionPayload::new(Bytes::from(format!("payload-{i}"))),
                ..record_clone
            };
            backend_clone
                .compare_and_set(CompareAndSet {
                    key: key_clone,
                    lease: lease_clone,
                    expected_generation: Some(Generation::new(1)),
                    new_record: record_new,
                })
                .await
        }));
    }

    let mut success_count = 0;
    let mut conflict_count = 0;

    for task in tasks {
        let res = task.await.unwrap().unwrap();
        match res {
            CompareAndSetResult::Success => success_count += 1,
            CompareAndSetResult::Conflict { .. } => conflict_count += 1,
        }
    }

    assert_eq!(success_count, 1);
    assert_eq!(conflict_count, 9);
}

#[tokio::test]
async fn test_sqlite_fencing_token_monotonicity() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let key = test_key(b"monotonic-fence");

    let lease_a = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    // Release lease A so owner B can acquire a lease
    backend.release(lease_a.clone()).await.unwrap();

    let lease_b = backend
        .acquire(
            &key,
            OwnerId::new("owner-b").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    assert!(lease_b.fence().get() > lease_a.fence().get());
}

#[tokio::test]
async fn test_sqlite_stale_fence_write_rejection() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let key = test_key(b"stale-fence");

    let lease_a = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    let record_a = test_record(key.clone(), 1, &lease_a);
    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease_a.clone(),
            expected_generation: None,
            new_record: record_a.clone(),
        })
        .await
        .unwrap();

    // Release lease A so owner B can acquire a lease
    let stale_lease_a = lease_a.clone();
    backend.release(lease_a).await.unwrap();

    // Fence increases when lease B is acquired
    let lease_b = backend
        .acquire(
            &key,
            OwnerId::new("owner-b").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    // Writing using lease A (stale fence) must be rejected
    let record_a_v2 = StoredSessionRecord {
        generation: Generation::new(2),
        ..record_a
    };

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: stale_lease_a.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record: record_a_v2,
        })
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);

    // Delete fenced using lease A must be rejected
    let err = backend.delete_fenced(&stale_lease_a).await.unwrap_err();
    assert_eq!(err, StoreError::StaleFence);

    // Delete fenced using lease B must succeed
    backend.delete_fenced(&lease_b).await.unwrap();
}

#[tokio::test]
async fn test_sqlite_lease_acquire_renew_release() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let key = test_key(b"lease-lifecycle");

    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    let renewed = backend
        .renew(&lease, Duration::from_secs(120))
        .await
        .unwrap();
    assert_eq!(renewed.fence(), lease.fence());
    assert!(renewed.expires_at() > lease.expires_at());

    backend.release(renewed.clone()).await.unwrap();

    // Operations with released lease must be rejected
    let err = backend
        .renew(&renewed, Duration::from_secs(60))
        .await
        .unwrap_err();
    assert!(matches!(err, LeaseError::StaleFence));
}

#[tokio::test]
async fn test_sqlite_stale_guard_after_same_owner_reacquire_is_rejected() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let key = test_key(b"same-owner-reacquire");

    let first = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let second = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    assert!(second.fence() > first.fence());

    let err = backend.release(first.clone()).await.unwrap_err();
    assert_eq!(err, LeaseError::StaleFence);

    let err = backend
        .renew(&first, Duration::from_secs(60))
        .await
        .unwrap_err();
    assert_eq!(err, LeaseError::StaleFence);

    backend.release(second).await.unwrap();
}

#[tokio::test]
async fn test_sqlite_stale_guard_after_renew_is_rejected() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let key = test_key(b"stale-after-renew");

    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let renewed = backend
        .renew(&lease, Duration::from_secs(120))
        .await
        .unwrap();

    let err = backend.release(lease.clone()).await.unwrap_err();
    assert_eq!(err, LeaseError::StaleFence);

    let err = backend
        .renew(&lease, Duration::from_secs(180))
        .await
        .unwrap_err();
    assert_eq!(err, LeaseError::StaleFence);

    backend.release(renewed).await.unwrap();
}

#[tokio::test]
async fn test_sqlite_expired_lease_takeover() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let key = test_key(b"takeover");

    let _lease_a = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_millis(1),
        )
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(5)).await;

    let lease_b = backend
        .acquire(
            &key,
            OwnerId::new("owner-b").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    assert_eq!(lease_b.owner().as_str(), "owner-b");
}

#[tokio::test]
async fn test_sqlite_backend_restart_preserves_state() {
    let file = NamedTempFile::new().unwrap();
    let path = file.path().to_path_buf();

    let key = test_key(b"restart-key");
    let lease = {
        let backend = SqliteSessionBackend::open(&path).unwrap();
        let lease = backend
            .acquire(
                &key,
                OwnerId::new("owner-a").unwrap(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();

        let record = test_record(key.clone(), 1, &lease);
        backend
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: record,
            })
            .await
            .unwrap();
        lease
    };

    // Reopen backend and check
    {
        let backend = SqliteSessionBackend::open(&path).unwrap();
        let record = backend.get(&key).await.unwrap().unwrap();
        assert_eq!(record.generation, Generation::new(1));
        assert_eq!(record.payload.as_bytes(), b"plain-session");

        // Renew lease must work
        let renewed = backend
            .renew(&lease, Duration::from_secs(120))
            .await
            .unwrap();
        assert_eq!(renewed.fence(), lease.fence());
    }
}

#[tokio::test]
async fn test_sqlite_encrypting_session_backend_round_trip() {
    let inner = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let provider = test_provider();
    let backend = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "regional-cache-a",
    );
    let key = test_key(b"round-trip");
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    let first = test_record(key.clone(), 1, &lease);
    let result = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: first,
        })
        .await
        .unwrap();
    assert_eq!(result, CompareAndSetResult::Success);

    // Retrieve via wrapped backend (decrypts automatically)
    let round_trip = backend.get(&key).await.unwrap().unwrap();
    assert_eq!(round_trip.payload.as_bytes(), b"plain-session");

    // Inspect raw stored bytes (must be encrypted)
    let inner_record = inner.get(&key).await.unwrap().unwrap();
    assert_ne!(inner_record.payload.as_bytes(), b"plain-session");

    // Verify it is a valid CryptoEnvelopeV1
    CryptoEnvelopeV1::decode(inner_record.payload.as_bytes()).expect("valid envelope");
}

#[tokio::test]
async fn test_sqlite_encrypting_session_backend_missing_key_fails_closed() {
    let inner = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let writer_provider = test_provider();
    let writer = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::clone(&writer_provider),
        "regional-cache-a",
    );
    let reader = EncryptingSessionBackend::new(
        Arc::clone(&inner),
        Arc::new(MemoryKeyProvider::new()),
        "regional-cache-a",
    );
    let key = test_key(b"fail-closed");
    let lease = writer
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    writer
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: test_record(key.clone(), 1, &lease),
        })
        .await
        .unwrap();

    let err = reader.get(&key).await.unwrap_err();
    assert_eq!(
        err,
        StoreError::Crypto("session envelope decryption failed".into())
    );
}

#[tokio::test]
async fn test_sqlite_batch_behavior() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let key = test_key(b"batch-test");
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    let record = test_record(key.clone(), 1, &lease);

    let results = backend
        .batch(vec![
            SessionOp::CompareAndSet(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: record.clone(),
            }),
            SessionOp::Get { key: key.clone() },
        ])
        .await
        .unwrap();

    assert_eq!(results.len(), 2);
    assert!(matches!(
        results[0],
        SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Success))
    ));
    match &results[1] {
        SessionOpResult::Get(Ok(Some(rec))) => {
            assert_eq!(rec.generation, Generation::new(1));
        }
        _ => panic!("unexpected batch get result"),
    }
}

#[tokio::test]
async fn test_sqlite_ttl_expiration() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let key = test_key(b"ttl-exp-key");
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    let mut record = test_record(key.clone(), 1, &lease);

    // Set expires_at in the past
    let now = opc_types::Timestamp::now_utc();
    let past = *now.as_offset_datetime() - time::Duration::seconds_f64(10.0);
    record.expires_at = Some(opc_types::Timestamp::from_offset_datetime(past));

    // Perform CAS to write the expired record.
    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();

    // 1. Reading it (get) must return None.
    let got = backend.get(&key).await.unwrap();
    assert!(got.is_none(), "expired record should return None on get");

    // 2. CAS checks: if it's expired, it acts as absent/None.
    // A CAS expecting None (create) should succeed and overwrite/update the expired record.
    let new_record = test_record(key.clone(), 2, &lease);
    let res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: new_record.clone(),
        })
        .await
        .unwrap();
    assert_eq!(
        res,
        CompareAndSetResult::Success,
        "CAS expecting None should succeed on expired record"
    );

    // Now the record is generation 2 and NOT expired (expires_at is None).
    let got = backend.get(&key).await.unwrap().unwrap();
    assert_eq!(got.generation, Generation::new(2));

    // Make it expired again by setting expires_at to past and update via CAS.
    let mut expired_v3 = test_record(key.clone(), 3, &lease);
    expired_v3.expires_at = Some(opc_types::Timestamp::from_offset_datetime(past));
    let res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(2)),
            new_record: expired_v3,
        })
        .await
        .unwrap();
    assert_eq!(res, CompareAndSetResult::Success);

    // Now record is expired again. Attempting to CAS it expecting generation 3 should fail as absent.
    let v4 = test_record(key.clone(), 4, &lease);
    let res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: Some(Generation::new(3)),
            new_record: v4,
        })
        .await
        .unwrap();
    assert_eq!(
        res,
        CompareAndSetResult::Conflict { current: None },
        "CAS expecting generation should conflict with None if expired"
    );

    // 3. TTL refreshes: if record is expired, refreshing TTL must return StoreError::NotFound.
    let err = backend
        .refresh_ttl(&lease, Duration::from_secs(10))
        .await
        .unwrap_err();
    assert_eq!(
        err,
        StoreError::NotFound,
        "refreshing TTL of expired record must return NotFound"
    );
}
