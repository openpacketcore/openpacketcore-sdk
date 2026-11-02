use super::*;

#[derive(Debug)]
struct RewindClock(std::sync::Mutex<Timestamp>);
impl Clock for RewindClock {
    fn now_utc(&self) -> Timestamp {
        *self.0.lock().unwrap()
    }
}

#[tokio::test]
async fn expired_receipt_stays_expired_after_rewind_and_an_unrelated_commit() {
    let start = Timestamp::now_utc();
    let clock = Arc::new(RewindClock(std::sync::Mutex::new(start)));
    let backend = FakeSessionBackend::in_memory_lab().with_clock(clock.clone());
    let prepared = backend
        .prepare_fenced_transition(create_request())
        .await
        .unwrap();
    backend.fenced_transition(&prepared).await.unwrap();
    *clock.0.lock().unwrap() = start
        .add_seconds(FENCED_TRANSITION_OUTCOME_RETENTION.as_secs() as i64)
        .unwrap();
    assert_eq!(
        backend.fenced_transition_status(&prepared).await.unwrap(),
        FencedTransitionStatus::Expired
    );
    *clock.0.lock().unwrap() = start;
    let mut unrelated = key();
    unrelated.stable_id = StableId::new(Bytes::from_static(b"unrelated-receipt-commit")).unwrap();
    backend
        .acquire(
            &unrelated,
            OwnerId::new("other").unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
    assert_eq!(
        backend.fenced_transition_status(&prepared).await.unwrap(),
        FencedTransitionStatus::Expired
    );
    assert_eq!(
        backend.fenced_transition(&prepared).await,
        Err(FencedTransitionExecuteError::Rejected(
            StoreError::FencedTransitionRequestExpired
        ))
    );
    assert_eq!(backend.inner.lock().await.lab_transitions.len(), 1);
}

#[derive(Clone, Copy, Debug)]
enum LeaseOnly {
    Acquire,
    Renew,
    Release,
    DeleteAbsent,
}

async fn lease_only_preserves_cursor(operation: LeaseOnly, replay: bool) {
    let backend = FakeSessionBackend::in_memory_lab();
    insert_restore_record(&backend, b"a-first").await;
    let last = insert_restore_record(&backend, b"b-last").await;
    let mut empty_key = key();
    empty_key.stable_id = StableId::new(Bytes::from_static(b"empty-lease-key")).unwrap();
    let owner = OwnerId::new("empty-owner").unwrap();
    let lease = backend
        .acquire(&empty_key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    let observer = if replay {
        let follower = FakeSessionBackend::in_memory_lab();
        follower
            .rebuild_replication_state(backend.get_replication_log(1, 64).await.unwrap())
            .await
            .unwrap();
        follower
    } else {
        backend.clone()
    };
    let next_sequence = backend.max_replication_sequence().await.unwrap() + 1;
    let mut request = RestoreScanRequest::all(1);
    let first = observer
        .scan_restore_records(request.clone())
        .await
        .unwrap();
    first.validate_for_request(&request).unwrap();
    request.cursor = first.next_cursor;
    assert!(request.cursor.is_some());
    let before = observer.inner.lock().await.records.clone();
    let revision = observer.inner.lock().await.lab_restore_revision;
    match operation {
        LeaseOnly::Acquire => {
            empty_key.stable_id = StableId::new(Bytes::from_static(b"another-empty-key")).unwrap();
            backend
                .acquire(&empty_key, owner, Duration::from_secs(60))
                .await
                .unwrap();
        }
        LeaseOnly::Renew => {
            backend
                .renew(&lease, Duration::from_secs(60))
                .await
                .unwrap();
        }
        LeaseOnly::Release => {
            backend.release(lease).await.unwrap();
        }
        LeaseOnly::DeleteAbsent => {
            backend.delete_fenced(&lease).await.unwrap();
        }
    }
    if replay {
        let entries = backend
            .get_replication_log(next_sequence, 64)
            .await
            .unwrap();
        assert_eq!(entries.len(), 1);
        for entry in entries {
            observer.replicate_entry(entry).await.unwrap();
        }
    }
    assert_eq!(observer.inner.lock().await.records, before);
    assert_eq!(
        observer.inner.lock().await.lab_restore_revision,
        revision,
        "{operation:?}: unchanged records preserve the cursor"
    );
    let page = observer
        .scan_restore_records(request.clone())
        .await
        .unwrap();
    page.validate_for_request(&request).unwrap();
    assert_eq!(page.records, vec![last]);
    assert!(page.complete);
}

#[tokio::test(start_paused = true)]
async fn restore_cursor_survives_lease_acquisition() {
    lease_only_preserves_cursor(LeaseOnly::Acquire, false).await;
}
#[tokio::test(start_paused = true)]
async fn restore_cursor_survives_lease_renewal() {
    lease_only_preserves_cursor(LeaseOnly::Renew, false).await;
}
#[tokio::test(start_paused = true)]
async fn restore_cursor_survives_lease_release() {
    lease_only_preserves_cursor(LeaseOnly::Release, false).await;
}
#[tokio::test(start_paused = true)]
async fn restore_cursor_survives_absent_record_deletion() {
    lease_only_preserves_cursor(LeaseOnly::DeleteAbsent, false).await;
}

#[tokio::test(start_paused = true)]
async fn restore_cursor_survives_replayed_lease_acquisition() {
    lease_only_preserves_cursor(LeaseOnly::Acquire, true).await;
}
#[tokio::test(start_paused = true)]
async fn restore_cursor_survives_replayed_lease_renewal() {
    lease_only_preserves_cursor(LeaseOnly::Renew, true).await;
}
#[tokio::test(start_paused = true)]
async fn restore_cursor_survives_replayed_lease_release() {
    lease_only_preserves_cursor(LeaseOnly::Release, true).await;
}
#[tokio::test(start_paused = true)]
async fn restore_cursor_survives_replayed_absent_record_deletion() {
    lease_only_preserves_cursor(LeaseOnly::DeleteAbsent, true).await;
}

#[tokio::test]
async fn stale_restore_cursor_keeps_observed_expiry_after_clock_rewind() {
    let start = Timestamp::now_utc();
    let clock = Arc::new(RewindClock(std::sync::Mutex::new(start)));
    let backend = FakeSessionBackend::in_memory_lab().with_clock(clock.clone());
    insert_restore_record(&backend, b"a-first").await;
    let mut last = record(1, 1);
    last.key.stable_id = StableId::new(Bytes::from_static(b"b-expiring")).unwrap();
    let lease = backend
        .acquire(&last.key, last.owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    last.fence = lease.fence();
    last.expires_at = Some(start.add_seconds(1).unwrap());
    assert_eq!(
        backend
            .compare_and_set(CompareAndSet {
                key: last.key.clone(),
                expected_generation: None,
                lease,
                new_record: last.clone(),
            })
            .await
            .unwrap(),
        CompareAndSetResult::Success
    );
    let before = backend.inner.lock().await.records.clone();
    let revision = backend.inner.lock().await.lab_restore_revision;
    let mut request = RestoreScanRequest::all(1);
    let first = backend.scan_restore_records(request.clone()).await.unwrap();
    first.validate_for_request(&request).unwrap();
    request.cursor = first.next_cursor;
    assert!(request.cursor.is_some());
    *clock.0.lock().unwrap() = start.add_seconds(2).unwrap();
    assert_eq!(
        backend.scan_restore_records(request.clone()).await,
        Err(StoreError::RestoreScanCursorStale)
    );
    *clock.0.lock().unwrap() = start;
    assert!(backend.get(&last.key).await.unwrap().is_none());
    assert_eq!(
        backend.scan_restore_records(request).await,
        Err(StoreError::RestoreScanCursorStale)
    );
    assert_eq!(backend.inner.lock().await.records, before);
    assert_eq!(backend.inner.lock().await.lab_restore_revision, revision);
}
