use super::*;

#[derive(Clone, Copy, Debug)]
enum Read {
    Get,
    Batch,
    Restore,
    #[cfg(feature = "lab-memory")]
    Observe,
    #[cfg(feature = "lab-memory")]
    LabRestore,
}

fn replica(read: Read, clock: Arc<dyn Clock>) -> FakeSessionBackend {
    #[cfg(feature = "lab-memory")]
    if matches!(read, Read::Observe | Read::LabRestore) {
        return FakeSessionBackend::in_memory_lab().with_clock(clock);
    }
    let _ = read;
    FakeSessionBackend::new().with_clock(clock)
}

async fn read_expired(backend: &FakeSessionBackend, key: &SessionKey, read: Read) {
    match read {
        Read::Get => assert!(backend.get(key).await.unwrap().is_none()),
        Read::Batch => {
            let result = backend
                .batch(vec![SessionOp::Get { key: key.clone() }])
                .await
                .unwrap();
            assert!(matches!(
                result.as_slice(),
                [SessionOpResult::Get(Ok(None))]
            ));
        }
        Read::Restore => assert!(backend
            .scan_restore_records(RestoreScanRequest::all(16))
            .await
            .unwrap()
            .records
            .is_empty()),
        #[cfg(feature = "lab-memory")]
        Read::Observe => assert!(backend
            .observe_fenced_transition(key)
            .await
            .unwrap()
            .record()
            .is_none()),
        #[cfg(feature = "lab-memory")]
        Read::LabRestore => assert!(backend
            .scan_restore_records(RestoreScanRequest::all(16))
            .await
            .unwrap()
            .records
            .is_empty()),
    }
}

async fn expired_read_preserves_committed_state(read: Read) {
    let clock: Arc<dyn Clock> = Arc::new(TokioVirtualClock::new());
    let backend = replica(read, clock);
    let key = test_key("replay-time", b"expired-read");
    let lease = backend
        .acquire(&key, OwnerId::new("owner").unwrap(), Duration::from_secs(1))
        .await
        .unwrap();
    let mut cas = cas_for_lease(key.clone(), &lease, None, 1);
    cas.new_record.expires_at = Some(lease.expires_at());
    backend.compare_and_set(cas).await.unwrap();
    let before = backend_data_snapshot(&backend).await;
    #[cfg(feature = "lab-memory")]
    let revision = backend.inner.lock().await.lab_restore_revision;
    tokio::time::advance(Duration::from_secs(2)).await;
    read_expired(&backend, &key, read).await;
    assert_eq!(backend_data_snapshot(&backend).await, before, "{read:?}");
    #[cfg(feature = "lab-memory")]
    assert_eq!(backend.inner.lock().await.lab_restore_revision, revision);
}

#[tokio::test(start_paused = true)]
async fn get_filters_expiry_without_retiring_committed_state() {
    expired_read_preserves_committed_state(Read::Get).await;
}

#[tokio::test(start_paused = true)]
async fn read_only_batch_filters_expiry_without_retiring_committed_state() {
    expired_read_preserves_committed_state(Read::Batch).await;
}

#[tokio::test(start_paused = true)]
async fn restore_filters_expiry_without_retiring_committed_state() {
    expired_read_preserves_committed_state(Read::Restore).await;
}

#[cfg(feature = "lab-memory")]
#[tokio::test(start_paused = true)]
async fn observation_filters_expiry_without_retiring_committed_state() {
    expired_read_preserves_committed_state(Read::Observe).await;
}

#[cfg(feature = "lab-memory")]
#[tokio::test(start_paused = true)]
async fn lab_restore_filters_expiry_without_retiring_committed_state() {
    expired_read_preserves_committed_state(Read::LabRestore).await;
}

async fn delayed_release(read: Option<Read>) {
    let clock: Arc<dyn Clock> = Arc::new(TokioVirtualClock::new());
    let source = FakeSessionBackend::new().with_clock(Arc::clone(&clock));
    let follower = replica(read.unwrap_or(Read::Get), Arc::clone(&clock));
    let prompt = FakeSessionBackend::new().with_clock(Arc::clone(&clock));
    let rebuilt = FakeSessionBackend::new().with_clock(clock);
    let key = test_key("replay-time", b"delayed-release");
    let lease = source
        .acquire(
            &key,
            OwnerId::new("owner").unwrap(),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let acquire = source.get_replication_log(1, 1).await.unwrap().remove(0);
    follower.replicate_entry(acquire.clone()).await.unwrap();
    prompt.replicate_entry(acquire).await.unwrap();
    tokio::time::advance(Duration::from_secs(1)).await;
    source.release(lease).await.unwrap();
    let entries = source.get_replication_log(1, 8).await.unwrap();
    assert_eq!(entries.len(), 2);
    prompt.replicate_entry(entries[1].clone()).await.unwrap();
    tokio::time::advance(Duration::from_secs(30)).await;
    if let Some(read) = read {
        read_expired(&follower, &key, read).await;
    }
    follower.replicate_entry(entries[1].clone()).await.unwrap();
    rebuilt.rebuild_replication_state(entries).await.unwrap();
    assert_eq!(
        backend_data_snapshot(&follower).await,
        backend_data_snapshot(&prompt).await
    );
    assert_eq!(
        backend_data_snapshot(&follower).await,
        backend_data_snapshot(&rebuilt).await
    );
    let successor = source
        .acquire(
            &key,
            OwnerId::new("successor").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    let next = source.get_replication_log(3, 1).await.unwrap().remove(0);
    for backend in [&follower, &prompt, &rebuilt] {
        backend.replicate_entry(next.clone()).await.unwrap();
        assert_eq!(backend.inner.lock().await.last_replication_sequence, 3);
        assert_eq!(
            FakeSessionBackend::current_fence(
                &*backend.inner.lock().await,
                &FakeSessionBackend::map_key(&key)
            ),
            successor.fence()
        );
    }
}

#[tokio::test(start_paused = true)]
async fn delayed_release_uses_committed_entry_time() {
    delayed_release(None).await;
}

#[tokio::test(start_paused = true)]
async fn delayed_release_survives_follower_reads() {
    for read in [Read::Get, Read::Batch, Read::Restore] {
        delayed_release(Some(read)).await;
    }
}

#[cfg(feature = "lab-memory")]
#[tokio::test(start_paused = true)]
async fn delayed_release_survives_follower_lab_reads() {
    for read in [Read::Observe, Read::LabRestore] {
        delayed_release(Some(read)).await;
    }
}

#[derive(Clone, Copy)]
enum DelayedMutation {
    Delete,
    Renew,
    Refresh,
}

async fn delayed_mutation_after_expired_read(mutation: DelayedMutation) {
    let clock: Arc<dyn Clock> = Arc::new(TokioVirtualClock::new());
    let source = FakeSessionBackend::new().with_clock(Arc::clone(&clock));
    let follower = FakeSessionBackend::new().with_clock(Arc::clone(&clock));
    let rebuilt = FakeSessionBackend::new().with_clock(clock);
    let key = test_key("replay-time", b"delayed-mutation");
    let lease = source
        .acquire(
            &key,
            OwnerId::new("owner").unwrap(),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let mut cas = cas_for_lease(key.clone(), &lease, None, 1);
    cas.new_record.expires_at = Some(lease.expires_at());
    source.compare_and_set(cas).await.unwrap();
    for entry in source.get_replication_log(1, 8).await.unwrap() {
        follower.replicate_entry(entry).await.unwrap();
    }
    tokio::time::advance(Duration::from_secs(1)).await;
    match mutation {
        DelayedMutation::Delete => source.delete_fenced(&lease).await.unwrap(),
        DelayedMutation::Renew => {
            source.renew(&lease, Duration::from_secs(60)).await.unwrap();
        }
        DelayedMutation::Refresh => source
            .refresh_ttl(&lease, Duration::from_secs(60))
            .await
            .unwrap(),
    }
    let entries = source.get_replication_log(1, 8).await.unwrap();
    assert_eq!(entries.len(), 3);
    tokio::time::advance(Duration::from_secs(30)).await;
    read_expired(&follower, &key, Read::Get).await;
    follower.replicate_entry(entries[2].clone()).await.unwrap();
    rebuilt.rebuild_replication_state(entries).await.unwrap();
    assert_eq!(
        backend_data_snapshot(&follower).await,
        backend_data_snapshot(&rebuilt).await
    );
    assert_eq!(
        follower.get(&key).await.unwrap(),
        rebuilt.get(&key).await.unwrap()
    );
}

#[tokio::test(start_paused = true)]
async fn delayed_delete_survives_follower_expiry_read() {
    delayed_mutation_after_expired_read(DelayedMutation::Delete).await;
}

#[tokio::test(start_paused = true)]
async fn delayed_renewal_survives_follower_expiry_read() {
    delayed_mutation_after_expired_read(DelayedMutation::Renew).await;
}

#[tokio::test(start_paused = true)]
async fn delayed_refresh_survives_follower_expiry_read() {
    delayed_mutation_after_expired_read(DelayedMutation::Refresh).await;
}

#[tokio::test(start_paused = true)]
async fn duplicate_delivery_never_prunes_committed_state() {
    for max_replication_entries in [0, 8] {
        let source = FakeSessionBackend::new();
        let follower = FakeSessionBackend::with_limits(FakeBackendLimits {
            max_tracked_keys: 4,
            max_replication_entries,
        });
        let key = test_key("replay-time", b"duplicate");
        source
            .acquire(&key, OwnerId::new("owner").unwrap(), Duration::from_secs(1))
            .await
            .unwrap();
        let entry = source.get_replication_log(1, 1).await.unwrap().remove(0);
        follower.replicate_entry(entry.clone()).await.unwrap();
        let mut watch = follower.watch(2).await.unwrap();
        let before = backend_data_snapshot(&follower).await;
        #[cfg(feature = "lab-memory")]
        let revision = follower.inner.lock().await.lab_restore_revision;
        tokio::time::advance(Duration::from_secs(2)).await;
        follower.replicate_entry(entry).await.unwrap();
        assert_eq!(backend_data_snapshot(&follower).await, before);
        #[cfg(feature = "lab-memory")]
        assert_eq!(follower.inner.lock().await.lab_restore_revision, revision);
        assert_no_replication_entry(&mut watch).await;
    }
}

#[derive(Debug)]
struct RewindClock(std::sync::Mutex<Timestamp>);

impl Clock for RewindClock {
    fn now_utc(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

async fn rewind_preserves_expiry_and_committed_state(read: Read) {
    let start = Timestamp::now_utc();
    let clock = Arc::new(RewindClock(std::sync::Mutex::new(start)));
    let backend = replica(read, clock.clone());
    let key = test_key("replay-time", b"clock-rewind");
    let lease = backend
        .acquire(&key, OwnerId::new("owner").unwrap(), Duration::from_secs(1))
        .await
        .unwrap();
    let mut cas = cas_for_lease(key.clone(), &lease, None, 1);
    cas.new_record.expires_at = Some(lease.expires_at());
    backend.compare_and_set(cas).await.unwrap();
    let committed = backend_data_snapshot(&backend).await;
    *clock.0.lock().unwrap() = start.add_seconds(2).unwrap();
    read_expired(&backend, &key, read).await;
    assert_eq!(backend_data_snapshot(&backend).await, committed);
    *clock.0.lock().unwrap() = start;
    // Clones share record-expiry visibility as well as committed data.
    let clone = backend.clone();
    read_expired(&clone, &key, read).await;
    assert!(clone.get(&key).await.unwrap().is_none());
    assert_eq!(backend_data_snapshot(&backend).await, committed);
    let renewed = clone.renew(&lease, Duration::from_secs(1)).await.unwrap();
    assert_eq!(renewed.acquired_at(), start);
    assert_eq!(renewed.expires_at(), lease.expires_at());
    // A reader's clock cannot reject a write, and an unrelated lease update
    // cannot make an already observed expired record visible again.
    assert!(backend.get(&key).await.unwrap().is_none());
}

#[tokio::test]
async fn get_keeps_expired_authority_hidden_after_clock_rewind() {
    rewind_preserves_expiry_and_committed_state(Read::Get).await;
}

#[tokio::test]
async fn batch_keeps_expired_authority_hidden_after_clock_rewind() {
    rewind_preserves_expiry_and_committed_state(Read::Batch).await;
}

#[tokio::test]
async fn restore_keeps_expired_authority_hidden_after_clock_rewind() {
    rewind_preserves_expiry_and_committed_state(Read::Restore).await;
}

#[cfg(feature = "lab-memory")]
#[tokio::test]
async fn observation_keeps_expired_authority_hidden_after_clock_rewind() {
    rewind_preserves_expiry_and_committed_state(Read::Observe).await;
}

#[cfg(feature = "lab-memory")]
#[tokio::test]
async fn lab_restore_keeps_expired_authority_hidden_after_clock_rewind() {
    rewind_preserves_expiry_and_committed_state(Read::LabRestore).await;
}

#[tokio::test]
async fn committed_cleanup_preserves_new_zero_ttl_boundary_and_replay() {
    let start = Timestamp::now_utc();
    let clock = Arc::new(RewindClock(std::sync::Mutex::new(start)));
    let backend = FakeSessionBackend::new().with_clock(clock.clone());
    let old_key = test_key("replay-time", b"expired-before-new-record");
    let old_lease = backend
        .acquire(
            &old_key,
            OwnerId::new("old-owner").unwrap(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    let mut cas = cas_for_lease(old_key.clone(), &old_lease, None, 1);
    cas.new_record.expires_at = Some(old_lease.expires_at());
    backend.compare_and_set(cas).await.unwrap();
    let before_read = backend_data_snapshot(&backend).await;
    let observed = start.add_seconds(2).unwrap();
    *clock.0.lock().unwrap() = observed;
    assert!(backend.get(&old_key).await.unwrap().is_none());
    assert_eq!(backend_data_snapshot(&backend).await, before_read);

    *clock.0.lock().unwrap() = start;
    let new_key = test_key("replay-time", b"new-zero-ttl");
    let new_lease = backend
        .acquire(
            &new_key,
            OwnerId::new("new-owner").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    // The write uses its own clock. Reader expiry stays local and cannot
    // choose the next command's pruning or replication timestamp.
    assert_eq!(new_lease.acquired_at(), start);
    assert!(backend
        .inner
        .lock()
        .await
        .records
        .contains_key(&FakeSessionBackend::map_key(&old_key)));
    assert!(backend.get(&old_key).await.unwrap().is_none());
    backend
        .compare_and_set(cas_for_lease(new_key.clone(), &new_lease, None, 1))
        .await
        .unwrap();
    backend
        .refresh_ttl(&new_lease, Duration::ZERO)
        .await
        .unwrap();
    let deadline = backend.inner.lock().await.records[&FakeSessionBackend::map_key(&new_key)]
        .expires_at
        .unwrap();
    let just_before = Timestamp::from_offset_datetime(
        *deadline.as_offset_datetime() - time::Duration::nanoseconds(1),
    );
    *clock.0.lock().unwrap() = just_before;
    assert_eq!(
        backend.get(&new_key).await.unwrap().unwrap().expires_at,
        Some(deadline)
    );
    *clock.0.lock().unwrap() = deadline;
    assert!(backend.get(&new_key).await.unwrap().is_none());
    *clock.0.lock().unwrap() = just_before;
    assert!(backend.clone().get(&new_key).await.unwrap().is_none());

    let replayed = FakeSessionBackend::new().with_clock(clock);
    for entry in backend.get_replication_log(1, 16).await.unwrap() {
        replayed.replicate_entry(entry).await.unwrap();
    }
    assert_eq!(
        backend_data_snapshot(&backend).await,
        backend_data_snapshot(&replayed).await
    );
}

#[tokio::test]
async fn queued_batch_observation_survives_a_commit_and_clock_rewind() {
    let start = Timestamp::now_utc();
    let clock = Arc::new(RewindClock(std::sync::Mutex::new(start)));
    let backend = FakeSessionBackend::new().with_clock(clock.clone());
    let key = test_key("replay-time", b"queued-expiry-observation");
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    backend
        .compare_and_set(cas_for_lease(key.clone(), &lease, None, 1))
        .await
        .unwrap();

    // Queue both real public calls behind the state lock in FIFO order. The
    // batch must retain its expiry observation of the newly committed record
    // independently of any timestamp used by the preceding commit.
    let held = backend.inner.lock().await;
    let mut refresh = Box::pin(backend.refresh_ttl(&lease, Duration::ZERO));
    assert!(futures_util::poll!(refresh.as_mut()).is_pending());
    let mut read = Box::pin(backend.batch(vec![SessionOp::Get { key: key.clone() }]));
    assert!(futures_util::poll!(read.as_mut()).is_pending());
    drop(held);
    refresh.await.unwrap();
    assert!(matches!(
        read.await.unwrap().as_slice(),
        [SessionOpResult::Get(Ok(None))]
    ));
    let committed = backend_data_snapshot(&backend).await;
    *clock.0.lock().unwrap() = Timestamp::from_offset_datetime(
        *start.as_offset_datetime() - time::Duration::nanoseconds(1),
    );
    assert!(backend.clone().get(&key).await.unwrap().is_none());
    assert_eq!(backend_data_snapshot(&backend).await, committed);
}

#[derive(Clone, Copy, Debug)]
enum QueuedMutation {
    CompareAndSet,
    Refresh,
    Acquire,
    Renew,
}

async fn queued_mutation_observes_expiry(mutation: QueuedMutation) {
    let start = Timestamp::now_utc();
    let clock = Arc::new(RewindClock(std::sync::Mutex::new(start)));
    let backend = FakeSessionBackend::new().with_clock(clock.clone());
    let key = test_key("replay-time", b"queued-read-before-write");
    let lease_ttl = match mutation {
        QueuedMutation::CompareAndSet | QueuedMutation::Refresh => 60,
        QueuedMutation::Acquire | QueuedMutation::Renew => 1,
    };
    let lease = backend
        .acquire(
            &key,
            OwnerId::new("owner").unwrap(),
            Duration::from_secs(lease_ttl),
        )
        .await
        .unwrap();
    let mut cas = cas_for_lease(key.clone(), &lease, None, 1);
    cas.new_record.expires_at = Some(start.add_seconds(1).unwrap());
    assert_eq!(
        backend.compare_and_set(cas).await.unwrap(),
        CompareAndSetResult::Success
    );
    let before = backend_data_snapshot(&backend).await;
    let observed = start.add_seconds(2).unwrap();

    // Tokio's FIFO mutex makes the public read run first. Only the writer's
    // lock-time sample can see the expiry that this preceding reader observes.
    let held = backend.inner.lock().await;
    let mut read = Box::pin(backend.get(&key));
    assert!(futures_util::poll!(read.as_mut()).is_pending());
    let mut write = Box::pin(async {
        match mutation {
            QueuedMutation::CompareAndSet => assert_eq!(
                backend
                    .compare_and_set(cas_for_lease(
                        key.clone(),
                        &lease,
                        Some(Generation::new(1)),
                        2
                    ))
                    .await,
                Ok(CompareAndSetResult::Conflict { current: None }),
            ),
            QueuedMutation::Refresh => assert_eq!(
                backend.refresh_ttl(&lease, Duration::from_secs(60)).await,
                Err(StoreError::NotFound),
            ),
            QueuedMutation::Acquire => {
                let acquired = backend
                    .acquire(
                        &key,
                        OwnerId::new("next-owner").unwrap(),
                        Duration::from_secs(60),
                    )
                    .await
                    .unwrap();
                assert_eq!(acquired.acquired_at(), observed);
                assert_eq!(acquired.expires_at(), observed.add_seconds(60).unwrap());
                assert!(acquired.fence() > lease.fence());
            }
            QueuedMutation::Renew => assert!(matches!(
                backend.renew(&lease, Duration::from_secs(60)).await,
                Err(LeaseError::Expired),
            )),
        }
    });
    assert!(futures_util::poll!(write.as_mut()).is_pending());
    *clock.0.lock().unwrap() = observed;
    drop(held);
    assert!(read.await.unwrap().is_none());
    write.await;
    assert!(backend.get(&key).await.unwrap().is_none());
    if !matches!(mutation, QueuedMutation::Acquire) {
        assert_eq!(backend_data_snapshot(&backend).await, before);
    }
    let entries = backend.get_replication_log(1, 16).await.unwrap();
    assert_eq!(
        entries.len(),
        if matches!(mutation, QueuedMutation::Acquire) {
            3
        } else {
            2
        }
    );
    let replayed = FakeSessionBackend::new().with_clock(clock.clone());
    for entry in &entries {
        replayed.replicate_entry(entry.clone()).await.unwrap();
    }
    let rebuilt = FakeSessionBackend::new().with_clock(clock);
    rebuilt.rebuild_replication_state(entries).await.unwrap();
    assert_eq!(
        backend_data_snapshot(&backend).await,
        backend_data_snapshot(&replayed).await
    );
    assert_eq!(
        backend_data_snapshot(&backend).await,
        backend_data_snapshot(&rebuilt).await
    );
}

#[tokio::test]
async fn queued_cas_cannot_revive_a_record_after_a_read_observes_expiry() {
    queued_mutation_observes_expiry(QueuedMutation::CompareAndSet).await;
}

#[tokio::test]
async fn queued_refresh_cannot_revive_a_record_after_a_read_observes_expiry() {
    queued_mutation_observes_expiry(QueuedMutation::Refresh).await;
}

#[tokio::test]
async fn queued_acquire_uses_the_expiry_observed_by_a_preceding_read() {
    queued_mutation_observes_expiry(QueuedMutation::Acquire).await;
}

#[tokio::test]
async fn queued_renew_cannot_revive_a_lease_after_a_read_observes_expiry() {
    queued_mutation_observes_expiry(QueuedMutation::Renew).await;
}
