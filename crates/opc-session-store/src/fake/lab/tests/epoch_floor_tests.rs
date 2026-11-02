use super::*;

fn capacity_backend() -> FakeSessionBackend {
    let mut backend = FakeSessionBackend::in_memory_lab();
    backend.limits.max_tracked_keys = 1;
    backend
}

fn capacity_key(number: u64) -> SessionKey {
    let mut value = key();
    value.stable_id = StableId::new(Bytes::copy_from_slice(&number.to_be_bytes())).unwrap();
    value
}

#[tokio::test(start_paused = true)]
async fn fake_epoch_capacity_rotates_below_threshold_without_a_lifetime_ceiling() {
    let backend = capacity_backend();
    let mut floor = 0;
    for number in 1..=8 {
        let key = capacity_key(number);
        let lease = backend
            .acquire(&key, record(1, 1).owner, Duration::from_secs(30))
            .await
            .expect("dead history cannot exhaust key capacity");
        let observed = backend.observe_fenced_transition(&key).await.unwrap();
        assert_eq!(observed.current_fence(), lease.fence());
        {
            let state = backend.inner.lock().await;
            assert_eq!(state.key_fences.len(), 1);
            assert_eq!(state.key_retention.epoch, 2 * (number - 1));
            assert_eq!(state.key_retention.retired_count, 0);
            if number > 1 {
                assert!(state.key_retention.floor_cur >= floor + 2);
                assert_eq!(
                    state.key_retention.last_rotation,
                    Some(crate::key_retention::RotationReason::Capacity)
                );
            }
            floor = state.key_retention.floor_cur;
        }
        backend.release(lease).await.unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn fake_epoch_capacity_strictly_advances_floors_and_rejects_two_rotation_preparation() {
    let backend = capacity_backend();
    let first = backend
        .acquire(
            &capacity_key(1),
            record(1, 1).owner,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    backend.release(first).await.unwrap();
    let second = backend
        .acquire(
            &capacity_key(2),
            record(1, 1).owner,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let observed = backend.observe_fenced_transition(&key()).await.unwrap();
    let floor = observed.current_fence();
    // The second acquire committed before its own capacity rotations, so its
    // exact fence is below the now-published absent floor. Retiring it exercises
    // strict advancement even when retired_max + 1 cannot raise that floor.
    assert!(second.fence() < floor);
    let request = FencedTransitionRequest::new(
        FencedTransitionRequestId::new(),
        FencedTransitionLease::acquire(key(), record(1, 1).owner, floor, Duration::from_secs(30))
            .unwrap(),
        FencedTransitionMutation::create(record(1, floor.get() + 1)),
    )
    .unwrap();
    let prepared = backend.prepare_fenced_transition(request).await.unwrap();
    backend.release(second).await.unwrap();
    let third = backend
        .acquire(
            &capacity_key(3),
            record(1, 1).owner,
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let full_retention = backend.inner.lock().await.key_retention;
    let full_sequence = backend.max_replication_sequence().await.unwrap();
    assert_eq!(
        backend.fenced_transition(&prepared).await,
        Err(FencedTransitionExecuteError::Rejected(
            StoreError::StaleFence
        )),
        "stale preparation is rejected even while live keys fill capacity"
    );
    assert_eq!(backend.inner.lock().await.key_retention, full_retention);
    assert_eq!(
        backend.max_replication_sequence().await.unwrap(),
        full_sequence
    );
    backend.release(third).await.unwrap();
    let before = backend.inner.lock().await.key_retention;
    assert_eq!(before.epoch, 4);
    assert_eq!(before.floor_prev, floor.get() + 1);
    assert_eq!(before.floor_cur, floor.get() + 2);
    assert_eq!(
        before.last_rotation,
        Some(crate::key_retention::RotationReason::Capacity)
    );
    let sequence = backend.max_replication_sequence().await.unwrap();
    assert_eq!(
        backend.fenced_transition(&prepared).await,
        Err(FencedTransitionExecuteError::Rejected(
            StoreError::StaleFence
        ))
    );
    assert_eq!(backend.inner.lock().await.key_retention, before);
    assert_eq!(backend.max_replication_sequence().await.unwrap(), sequence);
    assert!(backend.get(&key()).await.unwrap().is_none());
    let fresh = backend
        .observe_fenced_transition(&key())
        .await
        .unwrap()
        .current_fence();
    let request = FencedTransitionRequest::new(
        FencedTransitionRequestId::new(),
        FencedTransitionLease::acquire(key(), record(1, 1).owner, fresh, Duration::from_secs(30))
            .unwrap(),
        FencedTransitionMutation::create(record(1, fresh.get() + 1)),
    )
    .unwrap();
    let prepared = backend.prepare_fenced_transition(request).await.unwrap();
    assert_eq!(
        backend
            .fenced_transition(&prepared)
            .await
            .unwrap()
            .lease()
            .fence()
            .get(),
        fresh.get() + 1
    );
}

#[tokio::test(start_paused = true)]
async fn fake_epoch_floor_keeps_recently_dead_key_exact() {
    let backend = FakeSessionBackend::in_memory_lab();
    let old = backend
        .acquire(&key(), record(1, 1).owner, Duration::from_secs(30))
        .await
        .unwrap();
    backend.release(old.clone()).await.unwrap();
    let observed = backend.observe_fenced_transition(&key()).await.unwrap();
    assert!(observed.record().is_none());
    assert_eq!(observed.current_fence(), old.fence());
    assert!(backend
        .inner
        .lock()
        .await
        .key_fences
        .contains_key(&FakeSessionBackend::map_key(&key())));
}

#[tokio::test(start_paused = true)]
async fn fake_epoch_floor_prepared_create_survives_unrelated_retirement() {
    let backend = FakeSessionBackend::in_memory_lab();
    let prepared = backend
        .prepare_fenced_transition(create_request())
        .await
        .unwrap();
    let mut other = key();
    other.stable_id = StableId::new(Bytes::from_static(b"epoch-floor-other")).unwrap();
    let old = backend
        .acquire(&other, record(1, 1).owner, Duration::from_secs(30))
        .await
        .unwrap();
    backend.release(old).await.unwrap();
    let outcome = backend.fenced_transition(&prepared).await.unwrap();
    assert_eq!(outcome.lease().fence().get(), 1);
    assert_eq!(backend.fenced_transition(&prepared).await.unwrap(), outcome);
}

#[tokio::test(start_paused = true)]
async fn fake_epoch_floor_recreation_clears_exact_retirement_tag() {
    let backend = FakeSessionBackend::in_memory_lab();
    let old = backend
        .acquire(&key(), record(1, 1).owner, Duration::from_secs(30))
        .await
        .unwrap();
    backend.release(old.clone()).await.unwrap();
    let mut other = key();
    other.stable_id = StableId::new(Bytes::from_static(b"tag-maintenance")).unwrap();
    backend
        .acquire(&other, record(1, 1).owner, Duration::from_secs(30))
        .await
        .unwrap();
    let mk = FakeSessionBackend::map_key(&key());
    {
        let state = backend.inner.lock().await;
        assert_eq!(state.retired_keys.get(&mk), Some(&0));
        assert!(state.retired_index.contains(&(0, mk.clone())));
        assert_eq!(state.key_retention.retired_count, 1);
        assert_eq!(state.key_retention.retired_max, old.fence().get());
        assert_eq!(state.key_retention.floor_cur, 0);
    }
    let request = FencedTransitionRequest::new(
        FencedTransitionRequestId::new(),
        FencedTransitionLease::acquire(
            key(),
            record(1, 1).owner,
            old.fence(),
            Duration::from_secs(30),
        )
        .unwrap(),
        FencedTransitionMutation::create(record(1, old.fence().get() + 1)),
    )
    .unwrap();
    let prepared = backend.prepare_fenced_transition(request).await.unwrap();
    let outcome = backend.fenced_transition(&prepared).await.unwrap();
    assert_eq!(outcome.lease().fence().get(), old.fence().get() + 1);
    let state = backend.inner.lock().await;
    assert!(!state.retired_keys.contains_key(&mk));
    assert!(!state.retired_index.contains(&(0, mk.clone())));
    assert_eq!(state.key_retention.retired_count, 1);
    assert_eq!(state.key_retention.retired_max, old.fence().get());
    assert_eq!(state.key_fences.get(&mk), Some(&outcome.lease().fence()));
    assert!(state.retirement_candidates.is_empty());
}

#[tokio::test]
async fn round6_lab_absent_admission_uses_replayed_recovery_floor() {
    let backend = FakeSessionBackend::in_memory_lab();
    let now = Timestamp::now_utc();
    let make = |sequence, policy| crate::ReplicationEntry {
        sequence,
        timestamp: now,
        replay_policy: policy,
        tx_id: crate::ReplicationTxId::from_request_bytes(u128::from(sequence).to_be_bytes()),
        op: crate::ReplicationOp::Batch { ops: Vec::new() },
    };
    backend
        .replicate_entry(make(1, crate::ReplicationReplayPolicy::preserve()))
        .await
        .unwrap();
    let mut policy = crate::ReplicationReplayPolicy::preserve();
    policy.async_fence_floor = 100;
    policy.recovery = crate::ReplicationRecoveryBoundary::Recover {
        previous_sequence: 1,
    };
    backend.replicate_entry(make(101, policy)).await.unwrap();
    let observed = backend.observe_fenced_transition(&key()).await.unwrap();
    assert_eq!(observed.current_fence(), FenceToken::new(100));
    let request = FencedTransitionRequest::new(
        FencedTransitionRequestId::new(),
        FencedTransitionLease::acquire(
            key(),
            record(1, 1).owner,
            observed.current_fence(),
            Duration::from_secs(30),
        )
        .unwrap(),
        FencedTransitionMutation::create(record(1, 101)),
    )
    .unwrap();
    let prepared = backend.prepare_fenced_transition(request).await.unwrap();
    let result = backend
        .fenced_transition(&prepared)
        .await
        .expect("the observed current floor admits its successor");
    assert_eq!(result.lease().fence(), FenceToken::new(101));
}
