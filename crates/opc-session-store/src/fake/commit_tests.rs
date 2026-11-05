use super::*;

async fn expired_and_live(backend: &FakeSessionBackend) -> (LeaseGuard, LeaseGuard) {
    let owner = OwnerId::new("commit-owner").unwrap();
    let expired = backend
        .acquire(
            &test_key("commit", b"expired"),
            owner.clone(),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let mut expiring = test_record(
        expired.key().clone(),
        1,
        expired.fence().get(),
        owner.as_str(),
    );
    expiring.expires_at = Some(expired.expires_at());
    assert_eq!(
        backend
            .compare_and_set(CompareAndSet {
                key: expired.key().clone(),
                lease: expired.clone(),
                expected_generation: None,
                new_record: expiring,
            })
            .await
            .unwrap(),
        CompareAndSetResult::Success
    );
    let live = backend
        .acquire(
            &test_key("commit", b"live"),
            owner.clone(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(
        backend
            .compare_and_set(CompareAndSet {
                key: live.key().clone(),
                lease: live.clone(),
                expected_generation: None,
                new_record: test_record(live.key().clone(), 1, live.fence().get(), owner.as_str()),
            })
            .await
            .unwrap(),
        CompareAndSetResult::Success
    );
    tokio::time::advance(Duration::from_secs(31)).await;
    (expired, live)
}

fn wrong_credential(lease: &LeaseGuard) -> LeaseGuard {
    LeaseGuard::new(
        lease.key().clone(),
        lease.owner().clone(),
        lease.fence(),
        lease.acquired_at(),
        lease.expires_at(),
        lease.credential_id() + 1,
    )
}

fn conflicting_cas(lease: &LeaseGuard) -> CompareAndSet {
    CompareAndSet {
        key: lease.key().clone(),
        lease: lease.clone(),
        expected_generation: Some(Generation::new(2)),
        new_record: test_record(
            lease.key().clone(),
            3,
            lease.fence().get(),
            lease.owner().as_str(),
        ),
    }
}

#[tokio::test(start_paused = true)]
async fn successful_batch_commits_one_replayable_boundary() {
    let clock: Arc<dyn Clock> = Arc::new(TokioVirtualClock::new());
    let backend = FakeSessionBackend::new().with_clock(Arc::clone(&clock));
    let (expired, live) = expired_and_live(&backend).await;
    let before_sequence = backend.max_replication_sequence().await.unwrap();
    let mut watcher = backend.watch(before_sequence + 1).await.unwrap();
    let results = backend
        .batch(vec![
            SessionOp::CompareAndSet(conflicting_cas(&live)),
            SessionOp::RefreshTtl {
                lease: live.clone(),
                ttl: Duration::from_secs(30),
            },
            SessionOp::DeleteFenced {
                lease: wrong_credential(&live),
            },
            SessionOp::DeleteFenced {
                lease: live.clone(),
            },
            SessionOp::Get {
                key: live.key().clone(),
            },
            SessionOp::Get {
                key: expired.key().clone(),
            },
        ])
        .await
        .unwrap();
    assert!(matches!(
        &results[..],
        [
            SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Conflict { current: Some(_) })),
            SessionOpResult::RefreshTtl(Ok(())),
            SessionOpResult::DeleteFenced(Err(StoreError::StaleFence)),
            SessionOpResult::DeleteFenced(Ok(())),
            SessionOpResult::Get(Ok(None)),
            SessionOpResult::Get(Ok(None))
        ]
    ));
    assert_eq!(
        backend.max_replication_sequence().await.unwrap(),
        before_sequence + 1
    );
    let entry = next_replication_entry(&mut watcher).await;
    assert!(
        matches!(&entry.op, ReplicationOp::Batch { ops } if matches!(&ops[..],
        [ReplicationOp::RefreshTtl { .. }, ReplicationOp::DeleteFenced { .. }]))
    );
    let log = backend.get_replication_log(1, 64).await.unwrap();
    assert_eq!(log.last(), Some(&entry));
    // Drop the watcher so the complete data snapshots also compare that count.
    drop(watcher);
    backend
        .inner
        .lock()
        .await
        .watchers
        .retain(|watcher| !watcher.is_closed());
    let replica = FakeSessionBackend::new().with_clock(Arc::clone(&clock));
    for entry in log.clone() {
        replica.replicate_entry(entry).await.unwrap();
    }
    let rebuilt = FakeSessionBackend::new().with_clock(clock);
    rebuilt.rebuild_replication_state(log).await.unwrap();
    assert_eq!(
        backend_data_snapshot(&backend).await,
        backend_data_snapshot(&replica).await
    );
    assert_eq!(
        backend_data_snapshot(&backend).await,
        backend_data_snapshot(&rebuilt).await
    );
}

#[tokio::test(start_paused = true)]
async fn rejected_acquire_keeps_uncommitted_expiry() {
    let backend = FakeSessionBackend::new();
    let (_, live) = expired_and_live(&backend).await;
    let before = backend_data_snapshot(&backend).await;
    assert_eq!(
        backend
            .acquire(
                live.key(),
                OwnerId::new("other").unwrap(),
                Duration::from_secs(30)
            )
            .await,
        Err(LeaseError::AlreadyHeld)
    );
    assert_eq!(backend_data_snapshot(&backend).await, before);
}

#[tokio::test(start_paused = true)]
async fn rejected_renew_keeps_uncommitted_expiry() {
    let backend = FakeSessionBackend::new();
    let (expired, _) = expired_and_live(&backend).await;
    let before = backend_data_snapshot(&backend).await;
    assert_eq!(
        backend.renew(&expired, Duration::from_secs(30)).await,
        Err(LeaseError::Expired)
    );
    assert_eq!(backend_data_snapshot(&backend).await, before);
}

#[tokio::test(start_paused = true)]
async fn rejected_release_keeps_uncommitted_expiry() {
    let backend = FakeSessionBackend::new();
    let (_, live) = expired_and_live(&backend).await;
    let before = backend_data_snapshot(&backend).await;
    assert_eq!(
        backend.release(wrong_credential(&live)).await,
        Err(LeaseError::StaleFence)
    );
    assert_eq!(backend_data_snapshot(&backend).await, before);
}

#[tokio::test(start_paused = true)]
async fn conflicting_cas_keeps_uncommitted_expiry() {
    let backend = FakeSessionBackend::new();
    let (_, live) = expired_and_live(&backend).await;
    let before = backend_data_snapshot(&backend).await;
    assert!(matches!(
        backend
            .compare_and_set(conflicting_cas(&live))
            .await
            .unwrap(),
        CompareAndSetResult::Conflict { current: Some(_) }
    ));
    assert_eq!(backend_data_snapshot(&backend).await, before);
}

#[tokio::test(start_paused = true)]
async fn rejected_delete_keeps_uncommitted_expiry() {
    let backend = FakeSessionBackend::new();
    let (_, live) = expired_and_live(&backend).await;
    let before = backend_data_snapshot(&backend).await;
    assert_eq!(
        backend.delete_fenced(&wrong_credential(&live)).await,
        Err(StoreError::StaleFence)
    );
    assert_eq!(backend_data_snapshot(&backend).await, before);
}

#[tokio::test(start_paused = true)]
async fn rejected_refresh_keeps_uncommitted_expiry() {
    let backend = FakeSessionBackend::new();
    let (_, live) = expired_and_live(&backend).await;
    let before = backend_data_snapshot(&backend).await;
    assert_eq!(
        backend
            .refresh_ttl(&wrong_credential(&live), Duration::from_secs(30))
            .await,
        Err(StoreError::StaleFence)
    );
    assert_eq!(backend_data_snapshot(&backend).await, before);
}

#[tokio::test(start_paused = true)]
async fn no_effect_batch_keeps_uncommitted_expiry() {
    let backend = FakeSessionBackend::new();
    let (expired, live) = expired_and_live(&backend).await;
    let before = backend_data_snapshot(&backend).await;
    let results = backend
        .batch(vec![
            SessionOp::CompareAndSet(conflicting_cas(&live)),
            SessionOp::DeleteFenced {
                lease: wrong_credential(&live),
            },
            SessionOp::Get {
                key: expired.key().clone(),
            },
        ])
        .await
        .unwrap();
    assert!(matches!(
        &results[..],
        [
            SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Conflict { current: Some(_) })),
            SessionOpResult::DeleteFenced(Err(StoreError::StaleFence)),
            SessionOpResult::Get(Ok(None))
        ]
    ));
    assert_eq!(backend_data_snapshot(&backend).await, before);
}

#[cfg(feature = "lab-memory")]
#[tokio::test(start_paused = true)]
async fn rejected_lab_transition_keeps_uncommitted_expiry() {
    let backend = FakeSessionBackend::in_memory_lab();
    let (_, live) = expired_and_live(&backend).await;
    let request = crate::FencedTransitionRequest::new(
        crate::FencedTransitionRequestId::new(),
        crate::FencedTransitionLease::renew(live.clone(), Duration::from_secs(30)).unwrap(),
        crate::FencedTransitionMutation::update(
            Generation::new(2),
            test_record(
                live.key().clone(),
                3,
                live.fence().get(),
                live.owner().as_str(),
            ),
        ),
    )
    .unwrap();
    let prepared = backend.prepare_fenced_transition(request).await.unwrap();
    let before = backend_data_snapshot(&backend).await;
    let revision = backend.inner.lock().await.lab_restore_revision;
    assert_eq!(
        backend.fenced_transition(&prepared).await,
        Err(crate::FencedTransitionExecuteError::Rejected(
            StoreError::CasConflict
        ))
    );
    assert_eq!(backend_data_snapshot(&backend).await, before);
    assert_eq!(backend.inner.lock().await.lab_restore_revision, revision);
    assert_eq!(
        backend.fenced_transition_status(&prepared).await.unwrap(),
        crate::FencedTransitionStatus::Recorded(Box::new(Err(StoreError::CasConflict)))
    );
}

#[tokio::test(start_paused = true)]
async fn retired_key_rejects_every_old_replicated_authority_without_publication() {
    let backend = FakeSessionBackend::new();
    let old = backend
        .acquire(
            &test_key("retention", b"old"),
            OwnerId::new("old-owner").unwrap(),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    backend.release(old.clone()).await.unwrap();
    backend
        .acquire(
            &test_key("retention", b"maintenance"),
            OwnerId::new("maintenance-owner").unwrap(),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let map_key = FakeSessionBackend::map_key(old.key());
    {
        let state = backend.inner.lock().await;
        assert_eq!(state.retired_keys.get(&map_key), Some(&0));
        assert_eq!(state.key_retention.retired_count, 1);
        assert_eq!(state.key_retention.retired_max, old.fence().get());
        assert_eq!(state.key_fences.get(&map_key), Some(&old.fence()));
    }
    let sequence = backend.max_replication_sequence().await.unwrap() + 1;
    let mut watcher = backend.watch(sequence).await.unwrap();
    let before = backend_data_snapshot(&backend).await;
    let ops = [
        ReplicationOp::AcquireLease {
            key: old.key().clone(),
            owner: old.owner().clone(),
            fence: old.fence(),
            credential_id: old.credential_id(),
            ttl: Duration::from_secs(30),
            expires_at: old.expires_at(),
        },
        ReplicationOp::RenewLease {
            key: old.key().clone(),
            owner: old.owner().clone(),
            fence: old.fence(),
            credential_id: old.credential_id(),
            ttl: Duration::from_secs(30),
            expires_at: old.expires_at(),
        },
        ReplicationOp::ReleaseLease {
            key: old.key().clone(),
            owner: old.owner().clone(),
            fence: old.fence(),
            credential_id: old.credential_id(),
        },
        ReplicationOp::DeleteFenced {
            key: old.key().clone(),
            owner: old.owner().clone(),
            fence: old.fence(),
        },
        ReplicationOp::RefreshTtl {
            key: old.key().clone(),
            owner: old.owner().clone(),
            fence: old.fence(),
            ttl: Duration::from_secs(30),
            expires_at: old.expires_at(),
        },
        ReplicationOp::CompareAndSet {
            key: old.key().clone(),
            expected_generation: None,
            credential_id: old.credential_id(),
            guard_expires_at: old.expires_at(),
            new_record: test_record(
                old.key().clone(),
                1,
                old.fence().get(),
                old.owner().as_str(),
            ),
        },
    ];
    for op in ops {
        let entry = replication_entry(sequence, "retired-authority", backend.clock.now_utc(), op);
        assert_eq!(
            backend.replicate_entry(entry).await,
            Err(StoreError::StaleFence)
        );
        assert_eq!(backend_data_snapshot(&backend).await, before);
    }
    assert_no_replication_entry(&mut watcher).await;
}
