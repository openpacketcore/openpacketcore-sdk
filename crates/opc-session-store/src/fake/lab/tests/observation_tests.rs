use super::*;

async fn acquire_after_expiry(with_record: bool, with_other_key: bool) {
    let backend = FakeSessionBackend::in_memory_lab();
    let old = backend
        .acquire(&key(), record(1, 1).owner, Duration::from_secs(30))
        .await
        .unwrap();
    if with_record {
        let mut expiring = record(1, old.fence().get());
        expiring.expires_at = Some(old.expires_at());
        assert_eq!(
            backend
                .compare_and_set(CompareAndSet {
                    key: key(),
                    lease: old.clone(),
                    expected_generation: None,
                    new_record: expiring
                })
                .await
                .unwrap(),
            CompareAndSetResult::Success
        );
    }
    if with_other_key {
        let mut other = key();
        other.stable_id = StableId::new(Bytes::from_static(b"later-expiring-key")).unwrap();
        let higher = backend
            .acquire(&other, record(1, 1).owner, Duration::from_secs(30))
            .await
            .unwrap();
        assert!(higher.fence() > old.fence());
    }
    tokio::time::advance(Duration::from_secs(31)).await;
    let observed = backend.observe_fenced_transition(&key()).await.unwrap();
    assert!(observed.record().is_none());
    let request = FencedTransitionRequest::new(
        FencedTransitionRequestId::new(),
        FencedTransitionLease::acquire(
            key(),
            record(1, 1).owner,
            observed.current_fence(),
            Duration::from_secs(30),
        )
        .unwrap(),
        FencedTransitionMutation::create(record(1, observed.current_fence().get() + 1)),
    )
    .unwrap();
    let prepared = backend.prepare_fenced_transition(request).await.unwrap();
    // No maintenance write, retry, or clock advance between observation and apply.
    let outcome = backend.fenced_transition(&prepared).await.unwrap();
    assert!(outcome.lease().fence() > old.fence());
    assert_eq!(backend.fenced_transition(&prepared).await.unwrap(), outcome);
    assert_eq!(
        backend.get(&key()).await.unwrap(),
        Some(record(1, outcome.lease().fence().get()))
    );
    assert_eq!(
        backend
            .compare_and_set(CompareAndSet {
                key: key(),
                new_record: record(2, old.fence().get()),
                lease: old,
                expected_generation: Some(Generation::new(1))
            })
            .await,
        Err(StoreError::StaleFence)
    );
}

#[tokio::test(start_paused = true)]
async fn uncontended_acquire_uses_observed_fence_after_lease_expiry() {
    acquire_after_expiry(false, false).await;
}

#[tokio::test(start_paused = true)]
async fn uncontended_acquire_uses_observed_fence_after_record_and_lease_expiry() {
    acquire_after_expiry(true, false).await;
}

#[tokio::test(start_paused = true)]
async fn uncontended_acquire_uses_observed_fence_after_other_key_expiry() {
    acquire_after_expiry(false, true).await;
}

#[tokio::test(start_paused = true)]
async fn observation_keeps_live_key_fences_when_other_keys_expire() {
    for with_record in [false, true] {
        let backend = FakeSessionBackend::in_memory_lab();
        let lease = backend
            .acquire(
                &key(),
                record(1, 1).owner,
                Duration::from_secs(if with_record { 30 } else { 60 }),
            )
            .await
            .unwrap();
        if with_record {
            assert_eq!(
                backend
                    .compare_and_set(CompareAndSet {
                        key: key(),
                        lease: lease.clone(),
                        expected_generation: None,
                        new_record: record(1, lease.fence().get()),
                    })
                    .await
                    .unwrap(),
                CompareAndSetResult::Success
            );
        }
        let mut other = key();
        other.stable_id = StableId::new(Bytes::from_static(b"expired-other-key")).unwrap();
        let higher = backend
            .acquire(&other, record(1, 1).owner, Duration::from_secs(30))
            .await
            .unwrap();
        assert!(higher.fence() > lease.fence());
        tokio::time::advance(Duration::from_secs(31)).await;
        let observed = backend.observe_fenced_transition(&key()).await.unwrap();
        assert_eq!(observed.current_fence(), lease.fence());
        assert_eq!(observed.record().is_some(), with_record);
        let state = backend.inner.lock().await;
        assert_eq!(state.key_retention.floor_cur, 0);
        assert_eq!(state.key_fences.len(), 2);
        assert_eq!(state.leases.len(), 2);
    }
}

#[tokio::test]
async fn observation_keeps_unretirable_fences_at_allocation_boundaries() {
    for (fence, next_fence, expected) in [
        (7, 8, 7),
        (8, 8, 8),
        (9, 8, 9),
        (u64::MAX - 2, u64::MAX, u64::MAX - 2),
        (u64::MAX - 1, u64::MAX, u64::MAX - 1),
        (u64::MAX, u64::MAX, u64::MAX),
    ] {
        let backend = FakeSessionBackend::in_memory_lab();
        let map_key = FakeSessionBackend::map_key(&key());
        {
            let mut state = backend.inner.lock().await;
            state
                .key_fences
                .insert(map_key.clone(), FenceToken::new(fence));
            state.next_fence = next_fence;
        }
        let observed = backend.observe_fenced_transition(&key()).await.unwrap();
        assert!(observed.record().is_none());
        assert_eq!(observed.current_fence(), FenceToken::new(expected));
        let state = backend.inner.lock().await;
        assert_eq!(
            state.key_fences.get(&map_key),
            Some(&FenceToken::new(fence))
        );
        assert_eq!(state.next_fence, next_fence);
        assert_eq!(state.key_retention.floor_cur, 0);
        let mut applied = state.stage_data();
        FakeSessionBackend::prune_state(&mut applied, backend.clock.now_utc());
        assert_eq!(
            FakeSessionBackend::current_fence(&applied, &map_key),
            observed.current_fence()
        );
    }
}
