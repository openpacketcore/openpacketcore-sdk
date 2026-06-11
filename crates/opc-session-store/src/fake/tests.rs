use super::*;
use crate::model::{Generation, StateClass};
use bytes::Bytes;
use opc_types::{NetworkFunctionKind, TenantId};

fn test_key(tenant: &str, stable_id: &[u8]) -> SessionKey {
    SessionKey {
        tenant: TenantId::new(tenant).unwrap(),
        nf_kind: NetworkFunctionKind::new("smf").unwrap(),
        key_type: crate::model::SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(stable_id),
    }
}

fn test_record(key: SessionKey, generation: u64, fence: u64, owner: &str) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: OwnerId::new(owner).unwrap(),
        fence: FenceToken::new(fence),
        state_class: StateClass::AuthoritativeSession,
        state_type: crate::model::StateType::new("test").unwrap(),
        expires_at: None,
        payload: crate::record::EncryptedSessionPayload::new(Bytes::from_static(b"payload")),
    }
}

fn test_record_with_state_class(
    key: SessionKey,
    generation: u64,
    fence: u64,
    owner: &str,
    state_class: StateClass,
) -> StoredSessionRecord {
    StoredSessionRecord {
        state_class,
        ..test_record(key, generation, fence, owner)
    }
}

async fn acquire_test_lease(
    backend: &FakeSessionBackend,
    key: &SessionKey,
    owner: &str,
) -> LeaseGuard {
    backend
        .acquire(key, OwnerId::new(owner).unwrap(), Duration::from_secs(60))
        .await
        .unwrap()
}

fn test_record_for_lease(
    key: SessionKey,
    generation: u64,
    lease: &LeaseGuard,
) -> StoredSessionRecord {
    test_record(key, generation, lease.fence().get(), lease.owner().as_str())
}

fn test_record_for_lease_with_state_class(
    key: SessionKey,
    generation: u64,
    lease: &LeaseGuard,
    state_class: StateClass,
) -> StoredSessionRecord {
    test_record_with_state_class(
        key,
        generation,
        lease.fence().get(),
        lease.owner().as_str(),
        state_class,
    )
}

fn cas_for_lease(
    key: SessionKey,
    lease: &LeaseGuard,
    expected_generation: Option<Generation>,
    generation: u64,
) -> CompareAndSet {
    CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation,
        new_record: test_record_for_lease(key, generation, lease),
    }
}

fn cas_for_lease_with_state_class(
    key: SessionKey,
    lease: &LeaseGuard,
    expected_generation: Option<Generation>,
    generation: u64,
    state_class: StateClass,
) -> CompareAndSet {
    CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation,
        new_record: test_record_for_lease_with_state_class(key, generation, lease, state_class),
    }
}

#[tokio::test]
async fn fake_backend_get_miss() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let result = backend.get(&key).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn cas_success_create() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;
    let record = test_record_for_lease(key.clone(), 1, &lease);

    let op = CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation: None,
        new_record: record.clone(),
    };

    let result = backend.compare_and_set(op).await.unwrap();
    assert_eq!(result, CompareAndSetResult::Success);

    let got = backend.get(&key).await.unwrap().unwrap();
    assert_eq!(got.generation, Generation::new(1));
}

#[tokio::test]
async fn cas_conflict_wrong_generation() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;
    let record = test_record_for_lease(key.clone(), 1, &lease);

    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();

    let op = CompareAndSet {
        key: key.clone(),
        lease: lease.clone(),
        expected_generation: Some(Generation::new(99)),
        new_record: test_record_for_lease(key.clone(), 2, &lease),
    };

    let result = backend.compare_and_set(op).await.unwrap();
    assert_eq!(
        result,
        CompareAndSetResult::Conflict {
            current: Some(test_record_for_lease(key.clone(), 1, &lease)),
        }
    );
}

#[tokio::test]
async fn cas_conflict_same_generation_for_authoritative_state() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;
    let current = test_record_for_lease(key.clone(), 7, &lease);

    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: current.clone(),
        })
        .await
        .unwrap();

    let result = backend
        .compare_and_set(cas_for_lease(
            key.clone(),
            &lease,
            Some(Generation::new(7)),
            7,
        ))
        .await
        .unwrap();

    assert_eq!(
        result,
        CompareAndSetResult::Conflict {
            current: Some(current),
        }
    );
}

#[tokio::test]
async fn cas_conflict_decrementing_generation_for_authoritative_state() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;
    let current = test_record_for_lease(key.clone(), 7, &lease);

    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease.clone(),
            expected_generation: None,
            new_record: current.clone(),
        })
        .await
        .unwrap();

    let result = backend
        .compare_and_set(cas_for_lease(
            key.clone(),
            &lease,
            Some(Generation::new(7)),
            3,
        ))
        .await
        .unwrap();

    assert_eq!(
        result,
        CompareAndSetResult::Conflict {
            current: Some(current),
        }
    );
}

#[tokio::test]
async fn cas_allows_non_monotonic_generation_for_telemetry_state() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    backend
        .compare_and_set(cas_for_lease_with_state_class(
            key.clone(),
            &lease,
            None,
            7,
            StateClass::TelemetryDerived,
        ))
        .await
        .unwrap();

    let result = backend
        .compare_and_set(cas_for_lease_with_state_class(
            key.clone(),
            &lease,
            Some(Generation::new(7)),
            3,
            StateClass::TelemetryDerived,
        ))
        .await
        .unwrap();

    assert_eq!(result, CompareAndSetResult::Success);
}

#[tokio::test]
async fn cas_rejects_mismatched_record_key_on_create() {
    let backend = FakeSessionBackend::new();
    let key_a = test_key("t1", b"id1");
    let key_b = test_key("t2", b"id2");
    let lease_a = acquire_test_lease(&backend, &key_a, "owner-a").await;

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key_a.clone(),
            lease: lease_a,
            expected_generation: None,
            new_record: test_record(key_b, 1, 1, "owner-a"),
        })
        .await
        .unwrap_err();

    assert_eq!(
        err,
        StoreError::InvalidKey("compare-and-set key does not match record key".into())
    );
    assert!(backend.get(&key_a).await.unwrap().is_none());
}

#[tokio::test]
async fn cas_rejects_mismatched_record_key_on_update() {
    let backend = FakeSessionBackend::new();
    let key_a = test_key("t1", b"id1");
    let key_b = test_key("t2", b"id2");
    let lease_a = acquire_test_lease(&backend, &key_a, "owner-a").await;

    backend
        .compare_and_set(CompareAndSet {
            key: key_a.clone(),
            lease: lease_a.clone(),
            expected_generation: None,
            new_record: test_record_for_lease(key_a.clone(), 1, &lease_a),
        })
        .await
        .unwrap();

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key_a.clone(),
            lease: lease_a,
            expected_generation: Some(Generation::new(1)),
            new_record: test_record(key_b, 2, 2, "owner-a"),
        })
        .await
        .unwrap_err();

    assert_eq!(
        err,
        StoreError::InvalidKey("compare-and-set key does not match record key".into())
    );
    assert_eq!(backend.get(&key_a).await.unwrap().unwrap().key, key_a);
}

#[tokio::test]
async fn stale_fence_rejected() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    // Owner A acquires lease with fence 1.
    let lease_a = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(lease_a.fence(), FenceToken::new(1));

    // Owner A writes with fence 1.
    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease_a, None, 1))
        .await
        .unwrap();

    // Owner A releases lease.
    let stale_lease_a = lease_a.clone();
    backend.release(lease_a).await.unwrap();

    // Owner B acquires lease with fence 2.
    let lease_b = backend
        .acquire(
            &key,
            OwnerId::new("owner-b").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(lease_b.fence(), FenceToken::new(2));

    // Owner A tries to write again with old fence 1.
    let err = backend
        .compare_and_set(cas_for_lease(
            key.clone(),
            &stale_lease_a,
            Some(Generation::new(1)),
            2,
        ))
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test(start_paused = true)]
async fn stale_fence_after_lease_expiry() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    // Owner A acquires a very short lease.
    let lease_a = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_millis(50),
        )
        .await
        .unwrap();

    // Owner A writes.
    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease_a, None, 1))
        .await
        .unwrap();

    // Advance time past lease expiry.
    tokio::time::advance(Duration::from_millis(100)).await;

    // Owner B acquires new lease with higher fence.
    let lease_b = backend
        .acquire(
            &key,
            OwnerId::new("owner-b").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert!(lease_b.fence() > lease_a.fence());

    // Owner A tries to write with old fence.
    let err = backend
        .compare_and_set(cas_for_lease(
            key.clone(),
            &lease_a,
            Some(Generation::new(1)),
            2,
        ))
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test(start_paused = true)]
async fn expired_lease_cas_is_rejected_without_reacquire() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_millis(50),
        )
        .await
        .unwrap();

    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();

    tokio::time::advance(Duration::from_millis(100)).await;

    let err = backend
        .compare_and_set(cas_for_lease(
            key.clone(),
            &lease,
            Some(Generation::new(1)),
            2,
        ))
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::LeaseExpired);
}

#[tokio::test]
async fn forged_higher_fence_cas_is_rejected_while_other_owner_holds_lease() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease_a = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease_a, None, 1))
        .await
        .unwrap();

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease_a,
            expected_generation: Some(Generation::new(1)),
            new_record: test_record(key.clone(), 2, 999, "owner-b"),
        })
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test]
async fn released_lease_same_fence_cas_is_rejected_until_reacquire() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();

    let stale_lease = lease.clone();
    backend.release(lease).await.unwrap();

    let err = backend
        .compare_and_set(cas_for_lease(
            key.clone(),
            &stale_lease,
            Some(Generation::new(1)),
            2,
        ))
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test]
async fn released_lease_forged_higher_fence_cas_is_rejected_until_reacquire() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();

    let stale_lease = lease.clone();
    backend.release(lease).await.unwrap();

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: stale_lease,
            expected_generation: Some(Generation::new(1)),
            new_record: test_record(key.clone(), 2, 999, "owner-b"),
        })
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test]
async fn stale_reader_cannot_replay_get_output_into_compare_and_set() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease_a = acquire_test_lease(&backend, &key, "owner-a").await;
    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease_a, None, 1))
        .await
        .unwrap();

    let snapshot = backend.get(&key).await.unwrap().unwrap();
    let stale_lease = lease_a.clone();
    backend.release(lease_a).await.unwrap();
    let _lease_b = acquire_test_lease(&backend, &key, "owner-b").await;

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: stale_lease,
            expected_generation: Some(snapshot.generation),
            new_record: StoredSessionRecord {
                key,
                generation: Generation::new(2),
                ..snapshot
            },
        })
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test]
async fn stale_reader_cannot_replay_get_output_into_delete_fenced() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease = acquire_test_lease(&backend, &key, "owner-a").await;
    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();

    let _snapshot = backend.get(&key).await.unwrap().unwrap();
    let stale_lease = lease.clone();
    backend.release(lease).await.unwrap();

    let err = backend.delete_fenced(&stale_lease).await.unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test]
async fn stale_reader_cannot_replay_get_output_into_refresh_ttl() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease = acquire_test_lease(&backend, &key, "owner-a").await;
    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();

    let _snapshot = backend.get(&key).await.unwrap().unwrap();
    let stale_lease = lease.clone();
    backend.release(lease).await.unwrap();

    let err = backend
        .refresh_ttl(&stale_lease, Duration::from_secs(10))
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test]
async fn matching_fence_but_wrong_owner_cas_is_rejected() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    let lease_a = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease_a, None, 1))
        .await
        .unwrap();

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease_a,
            expected_generation: Some(Generation::new(1)),
            new_record: test_record(key.clone(), 2, FenceToken::new(1).get(), "owner-b"),
        })
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test]
async fn acquire_fence_advances_past_recorded_key_fence() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let mk = FakeSessionBackend::map_key(&key);
    {
        let mut state = backend.inner.lock().await;
        state.key_fences.insert(mk, FenceToken::new(10));
        state.next_fence = 1;
    }

    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-b").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(lease.fence(), FenceToken::new(11));

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease,
            expected_generation: Some(Generation::new(1)),
            new_record: test_record(key.clone(), 2, 10, "owner-a"),
        })
        .await
        .unwrap_err();
    assert_eq!(err, StoreError::StaleFence);
}

#[tokio::test]
async fn lease_acquire_renew_release() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    // Acquire.
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(lease.owner().as_str(), "owner-a");
    assert_eq!(lease.fence(), FenceToken::new(1));

    // Renew.
    let renewed = backend
        .renew(&lease, Duration::from_secs(120))
        .await
        .unwrap();
    assert_eq!(renewed.fence(), lease.fence());
    assert_eq!(renewed.owner(), lease.owner());

    // Release.
    backend.release(renewed).await.unwrap();

    // After release, another owner can acquire.
    let lease2 = backend
        .acquire(
            &key,
            OwnerId::new("owner-b").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(lease2.owner().as_str(), "owner-b");
    // Fence must be higher than previous.
    assert!(lease2.fence() > lease.fence());
}

#[tokio::test]
async fn stale_guard_release_after_renew_is_rejected() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

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

    let err = backend.release(lease).await.unwrap_err();
    assert_eq!(err, LeaseError::StaleFence);

    backend.release(renewed).await.unwrap();
}

#[tokio::test]
async fn stale_guard_renew_after_renew_is_rejected() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

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

    let err = backend
        .renew(&lease, Duration::from_secs(180))
        .await
        .unwrap_err();
    assert_eq!(err, LeaseError::StaleFence);

    backend.release(renewed).await.unwrap();
}

#[tokio::test]
async fn stale_guard_release_after_same_owner_reacquire_is_rejected() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

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

    let err = backend.release(first).await.unwrap_err();
    assert_eq!(err, LeaseError::StaleFence);

    backend.release(second).await.unwrap();
}

#[tokio::test]
async fn stale_guard_renew_after_same_owner_reacquire_is_rejected() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

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

    let err = backend
        .renew(&first, Duration::from_secs(60))
        .await
        .unwrap_err();
    assert_eq!(err, LeaseError::StaleFence);

    backend.release(second).await.unwrap();
}

#[tokio::test]
async fn lease_held_by_other_blocks_acquire() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");

    backend
        .acquire(
            &key,
            OwnerId::new("owner-a").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

    let err = backend
        .acquire(
            &key,
            OwnerId::new("owner-b").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap_err();

    assert_eq!(err, LeaseError::AlreadyHeld);
}

#[tokio::test]
async fn tenant_scoped_key_digesting() {
    let key_a = test_key("tenant-a", b"same-id");
    let key_b = test_key("tenant-b", b"same-id");

    let digest_a = key_a.digest();
    let digest_b = key_b.digest();

    assert_ne!(digest_a, digest_b);

    // Also verify HMAC-style digests differ.
    let hmac_a = key_a.digest_with_key(b"privacy-key");
    let hmac_b = key_b.digest_with_key(b"privacy-key");
    assert_ne!(hmac_a, hmac_b);
    assert_ne!(hmac_a, digest_a);
}

#[tokio::test]
async fn capability_enforcement_cas_disabled() {
    let mut caps = BackendCapabilities::all_enabled();
    caps.atomic_compare_and_set = false;
    let backend = FakeSessionBackend::with_capabilities(caps);
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease,
            expected_generation: None,
            new_record: test_record(key.clone(), 1, 1, "owner-a"),
        })
        .await
        .unwrap_err();

    assert_eq!(
        err,
        StoreError::CapabilityNotSupported("atomic_compare_and_set".into())
    );
}

#[tokio::test]
async fn capability_enforcement_fence_disabled() {
    let mut caps = BackendCapabilities::all_enabled();
    caps.monotonic_fencing_token = false;
    let backend = FakeSessionBackend::with_capabilities(caps);
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    let err = backend.delete_fenced(&lease).await.unwrap_err();

    assert_eq!(
        err,
        StoreError::CapabilityNotSupported("monotonic_fencing_token".into())
    );
}

#[tokio::test]
async fn capability_enforcement_ttl_disabled() {
    let mut caps = BackendCapabilities::all_enabled();
    caps.per_key_ttl = false;
    let backend = FakeSessionBackend::with_capabilities(caps);
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    let err = backend
        .refresh_ttl(&lease, Duration::from_secs(10))
        .await
        .unwrap_err();

    assert_eq!(
        err,
        StoreError::CapabilityNotSupported("per_key_ttl".into())
    );
}

#[tokio::test]
async fn capability_enforcement_max_value_bytes() {
    let mut caps = BackendCapabilities::all_enabled();
    caps.max_value_bytes = 4;
    let backend = FakeSessionBackend::with_capabilities(caps);
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease,
            expected_generation: None,
            new_record: test_record(key, 1, 1, "owner-a"),
        })
        .await
        .unwrap_err();

    assert_eq!(err, StoreError::PayloadTooLarge { actual: 7, max: 4 });
}

#[tokio::test]
async fn batch_mixed_ops() {
    let backend = FakeSessionBackend::new();
    let key1 = test_key("t1", b"id1");
    let key2 = test_key("t1", b"id2");
    let lease1 = acquire_test_lease(&backend, &key1, "owner-a").await;

    let ops = vec![
        SessionOp::CompareAndSet(cas_for_lease(key1.clone(), &lease1, None, 1)),
        SessionOp::Get { key: key1.clone() },
        SessionOp::Get { key: key2.clone() },
    ];

    let results = backend.batch(ops).await.unwrap();
    assert_eq!(results.len(), 3);

    assert_eq!(
        results[0],
        SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Success))
    );
    assert!(
        matches!(&results[1], SessionOpResult::Get(Ok(Some(r))) if r.generation == Generation::new(1))
    );
    assert_eq!(results[2], SessionOpResult::Get(Ok(None)));
}

#[tokio::test]
async fn capability_enforcement_batch_disabled() {
    let mut caps = BackendCapabilities::all_enabled();
    caps.batch_write = false;
    let backend = FakeSessionBackend::with_capabilities(caps);

    let err = backend.batch(vec![]).await.unwrap_err();

    assert_eq!(
        err,
        StoreError::CapabilityNotSupported("batch_write".into())
    );
}

#[tokio::test]
async fn delete_fenced_success_and_stale() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();

    // Stale released guard.
    let stale_lease = lease.clone();
    backend.release(lease).await.unwrap();
    let err = backend.delete_fenced(&stale_lease).await.unwrap_err();
    assert_eq!(err, StoreError::StaleFence);

    // Valid active lease.
    let active_lease = acquire_test_lease(&backend, &key, "owner-b").await;
    backend.delete_fenced(&active_lease).await.unwrap();
    assert!(backend.get(&key).await.unwrap().is_none());
}

#[tokio::test]
async fn refresh_ttl_success_and_stale() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;

    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();

    // Stale released guard.
    let stale_lease = lease.clone();
    backend.release(lease).await.unwrap();
    let err = backend
        .refresh_ttl(&stale_lease, Duration::from_secs(10))
        .await
        .unwrap_err();
    assert_eq!(err, StoreError::StaleFence);

    // Valid active lease.
    let active_lease = acquire_test_lease(&backend, &key, "owner-b").await;
    backend
        .refresh_ttl(&active_lease, Duration::from_secs(10))
        .await
        .unwrap();

    let got = backend.get(&key).await.unwrap().unwrap();
    assert!(got.expires_at.is_some());
}

#[tokio::test]
async fn test_ttl_expiration_fake_backend() {
    let backend = FakeSessionBackend::new();
    let key = test_key("t1", b"id1");
    let lease = acquire_test_lease(&backend, &key, "owner-a").await;
    let mut record = test_record_for_lease(key.clone(), 1, &lease);

    // Set expires_at in the past
    let now = Timestamp::now_utc();
    let past = *now.as_offset_datetime() - time::Duration::seconds_f64(10.0);
    record.expires_at = Some(Timestamp::from_offset_datetime(past));

    // Verify is_expired() directly on the record
    assert!(record.is_expired());

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
    let new_record = test_record_for_lease(key.clone(), 2, &lease);
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
    let mut expired_v3 = test_record_for_lease(key.clone(), 3, &lease);
    expired_v3.expires_at = Some(Timestamp::from_offset_datetime(past));
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
    let v4 = test_record_for_lease(key.clone(), 4, &lease);
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
