use super::*;

#[tokio::test(start_paused = true)]
async fn capacity_decisions_replay_identically_under_a_larger_local_limit() {
    let source = FakeSessionBackend::with_limits(FakeBackendLimits {
        max_tracked_keys: 2,
        max_replication_entries: 64,
    });
    let replica = FakeSessionBackend::with_limits(FakeBackendLimits {
        max_tracked_keys: 64,
        max_replication_entries: 64,
    });
    let mut next = 1;
    for index in 0..8_u64 {
        let key = test_key("capacity-replay", &index.to_be_bytes());
        let lease = source
            .acquire(
                &key,
                OwnerId::new("owner").unwrap(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        source.release(lease).await.unwrap();
        let entries = source.get_replication_log(next, 16).await.unwrap();
        assert_eq!(entries.len(), 2);
        for entry in entries {
            replica.replicate_entry(entry).await.unwrap();
            next += 1;
        }
        assert_eq!(
            backend_data_snapshot(&source).await,
            backend_data_snapshot(&replica).await,
            "capacity decisions belong to the committed entry at lifecycle {index}"
        );
    }
    assert!(source.inner.lock().await.key_retention.epoch > 0);
    let rebuilt = FakeSessionBackend::new();
    rebuilt
        .rebuild_replication_state(source.get_replication_log(1, 64).await.unwrap())
        .await
        .unwrap();
    assert_eq!(
        backend_data_snapshot(&source).await,
        backend_data_snapshot(&rebuilt).await
    );
}

#[tokio::test(start_paused = true)]
async fn smaller_replica_refuses_capacity_without_uncommitted_rotation() {
    let source = FakeSessionBackend::with_limits(FakeBackendLimits {
        max_tracked_keys: 64,
        max_replication_entries: 64,
    });
    let replica = FakeSessionBackend::with_limits(FakeBackendLimits {
        max_tracked_keys: 4,
        max_replication_entries: 64,
    });
    for index in 0..4_u64 {
        let key = test_key("capacity-replay", &index.to_be_bytes());
        let lease = source
            .acquire(
                &key,
                OwnerId::new("owner").unwrap(),
                Duration::from_secs(60),
            )
            .await
            .unwrap();
        source.release(lease).await.unwrap();
    }
    for entry in source.get_replication_log(1, 64).await.unwrap() {
        replica.replicate_entry(entry).await.unwrap();
    }
    let before = backend_data_snapshot(&replica).await;
    let mut watch = replica.watch(9).await.unwrap();
    source
        .acquire(
            &test_key("capacity-replay", b"fifth"),
            OwnerId::new("owner").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let entry = source.get_replication_log(9, 1).await.unwrap().remove(0);
    assert!(
        matches!(
            replica.replicate_entry(entry).await,
            Err(StoreError::BackendUnavailable(_))
        ),
        "a local limit cannot invent committed epoch rotations"
    );
    assert_eq!(
        backend_data_snapshot(&replica).await.watcher_count,
        before.watcher_count + 1
    );
    let mut after = backend_data_snapshot(&replica).await;
    after.watcher_count = before.watcher_count;
    assert_eq!(after, before);
    assert_no_replication_entry(&mut watch).await;
    let before_rebuild = backend_data_snapshot(&replica).await;
    assert!(matches!(
        replica
            .rebuild_replication_state(source.get_replication_log(1, 64).await.unwrap())
            .await,
        Err(StoreError::BackendUnavailable(_))
    ));
    assert_eq!(backend_data_snapshot(&replica).await, before_rebuild);
}

#[tokio::test(start_paused = true)]
async fn fake_batch_refuses_an_unrepresentable_entry_before_publication() {
    let backend = FakeSessionBackend::new();
    let lease = backend
        .acquire(
            &test_key("batch-bound", b"key"),
            OwnerId::new("owner").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let mut watch = backend.watch(2).await.unwrap();
    let before = backend_data_snapshot(&backend).await;
    let count = crate::backend::MAX_REPLICATION_OPERATIONS_PER_ENTRY;
    let operations = || {
        (0..count)
            .map(|_| SessionOp::DeleteFenced {
                lease: lease.clone(),
            })
            .collect()
    };
    assert_eq!(
        backend.batch(operations()).await,
        Err(StoreError::ReplicationOperationLimitExceeded)
    );
    assert_eq!(backend_data_snapshot(&backend).await, before);
    assert_no_replication_entry(&mut watch).await;
    let accepted = (0..count - 1)
        .map(|_| SessionOp::DeleteFenced {
            lease: lease.clone(),
        })
        .collect();
    let results = backend.batch(accepted).await.unwrap();
    assert_eq!(results.len(), count - 1);
    assert!(results
        .iter()
        .all(|result| matches!(result, SessionOpResult::DeleteFenced(Ok(())))));
    let entries = backend.get_replication_log(2, 1).await.unwrap();
    assert_eq!(entries.len(), 1);
    entries[0].validate().unwrap();
    let replica = FakeSessionBackend::new();
    replica
        .rebuild_replication_state(backend.get_replication_log(1, 16).await.unwrap())
        .await
        .unwrap();
    assert_eq!(
        backend_data_snapshot(&replica).await.records,
        backend_data_snapshot(&backend).await.records
    );
}
