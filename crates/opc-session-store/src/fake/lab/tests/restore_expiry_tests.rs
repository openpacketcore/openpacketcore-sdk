use super::*;

async fn expired_tail_counts_only_live_scope_exclusions(limit: usize) {
    let backend = FakeSessionBackend::in_memory_lab();
    let live = insert_restore_record(&backend, b"a-live").await;
    let mut expired = record(1, 1);
    expired.key.stable_id = StableId::new(Bytes::from_static(b"z-expired")).unwrap();
    let lease = backend
        .acquire(&expired.key, expired.owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    expired.fence = lease.fence();
    expired.expires_at = Some(backend.clock.now_utc().add_seconds(1).unwrap());
    assert_eq!(
        backend
            .compare_and_set(CompareAndSet {
                key: expired.key.clone(),
                expected_generation: None,
                lease,
                new_record: expired,
            })
            .await
            .unwrap(),
        CompareAndSetResult::Success
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    let before = backend.inner.lock().await.records.clone();
    let request = RestoreScanRequest::all(limit);
    let page = backend.scan_restore_records(request.clone()).await.unwrap();
    page.validate_for_request(&request).unwrap();
    assert_eq!(page.records, vec![live]);
    assert_eq!(
        page.excluded_count, 0,
        "expired rows are absent from the live scan view"
    );
    assert!(
        page.complete,
        "a short expired tail must not force an empty continuation page"
    );
    assert!(page.next_cursor.is_none());
    assert_eq!(backend.inner.lock().await.records, before);
}

#[tokio::test(start_paused = true)]
async fn lab_restore_does_not_count_expired_rows_as_scope_exclusions() {
    expired_tail_counts_only_live_scope_exclusions(16).await;
}

#[tokio::test(start_paused = true)]
async fn lab_restore_finishes_a_full_page_with_a_short_expired_tail() {
    expired_tail_counts_only_live_scope_exclusions(1).await;
}

#[tokio::test(start_paused = true)]
async fn lab_restore_expired_rows_still_consume_the_scan_work_budget() {
    let maximum = crate::restore::RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE;
    for count in [maximum, maximum + 1] {
        let backend = FakeSessionBackend::in_memory_lab();
        let deadline = backend.clock.now_utc().add_seconds(1).unwrap();
        {
            let mut state = backend.inner.lock().await;
            for index in 0..count {
                let mut value = record(1, 1);
                value.key.stable_id =
                    StableId::new(Bytes::copy_from_slice(&(index as u64).to_be_bytes())).unwrap();
                value.expires_at = Some(deadline);
                state
                    .records
                    .insert(FakeSessionBackend::map_key(&value.key), value);
            }
        }
        tokio::time::advance(Duration::from_secs(2)).await;
        let before = backend.inner.lock().await.records.clone();
        let mut request = RestoreScanRequest::all(1);
        request.scope.owner = Some(OwnerId::new("absent-owner").unwrap());
        // Both expired-only sources fit the physical visit allowance. They
        // consume no live-row allowance and require no empty continuation.
        assert!(count < crate::restore::RESTORE_SCAN_MAX_SQLITE_VM_STEPS);
        let page = backend.scan_restore_records(request.clone()).await.unwrap();
        page.validate_for_request(&request).unwrap();
        assert!(page.records.is_empty());
        assert_eq!(page.excluded_count, 0);
        assert!(page.complete);
        assert!(page.next_cursor.is_none());
        assert_eq!(backend.inner.lock().await.records, before);
    }
}

#[tokio::test(start_paused = true)]
async fn lab_restore_cursor_counts_live_rows_while_bounding_expired_scan_work() {
    let backend = FakeSessionBackend::in_memory_lab();
    let maximum = crate::restore::RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE;
    let deadline = backend.clock.now_utc().add_seconds(1).unwrap();
    let mut live = Vec::new();
    {
        let mut state = backend.inner.lock().await;
        for index in 0..=maximum + 1 {
            let mut value = record(1, 1);
            value.key.stable_id =
                StableId::new(Bytes::copy_from_slice(&(index as u64).to_be_bytes())).unwrap();
            if index == 0 || index == maximum + 1 {
                live.push(value.clone());
            } else {
                value.expires_at = Some(deadline);
            }
            state
                .records
                .insert(FakeSessionBackend::map_key(&value.key), value);
        }
    }
    tokio::time::advance(Duration::from_secs(2)).await;
    let before = backend.inner.lock().await.records.clone();
    let mut request = RestoreScanRequest::all(1);
    let first = backend.scan_restore_records(request.clone()).await.unwrap();
    first.validate_for_request(&request).unwrap();
    assert_eq!(first.records, vec![live[0].clone()]);
    assert_eq!(first.excluded_count, 0);
    assert!(!first.complete);
    request.cursor = first.next_cursor;
    assert!(request.cursor.is_some());
    let last = backend.scan_restore_records(request.clone()).await.unwrap();
    last.validate_for_request(&request).unwrap();
    assert_eq!(last.records, vec![live[1].clone()]);
    assert_eq!(last.excluded_count, 0);
    assert!(last.complete);
    assert_eq!(backend.inner.lock().await.records, before);
}

#[tokio::test(start_paused = true)]
async fn lab_restore_skips_a_long_expired_prefix_before_live_row_accounting() {
    let backend = FakeSessionBackend::in_memory_lab();
    let count = crate::restore::RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE + 256;
    let deadline = backend.clock.now_utc().add_seconds(1).unwrap();
    let mut live = record(1, 1);
    {
        let mut state = backend.inner.lock().await;
        for index in 0..=count {
            let mut value = record(1, 1);
            value.key.stable_id =
                StableId::new(Bytes::copy_from_slice(&(index as u64).to_be_bytes())).unwrap();
            if index == count {
                live = value.clone();
            } else {
                value.expires_at = Some(deadline);
            }
            state
                .records
                .insert(FakeSessionBackend::map_key(&value.key), value);
        }
    }
    tokio::time::advance(Duration::from_secs(2)).await;
    let before = backend.inner.lock().await.records.clone();
    let request = RestoreScanRequest::all(1);
    for _ in 0..2 {
        let page = backend.scan_restore_records(request.clone()).await.unwrap();
        page.validate_for_request(&request).unwrap();
        assert_eq!(page.records, vec![live.clone()]);
        assert_eq!(page.excluded_count, 0);
        assert!(page.complete);
        assert!(page.next_cursor.is_none());
        assert_eq!(backend.inner.lock().await.records, before);
    }
}

#[tokio::test(start_paused = true)]
async fn lab_full_live_work_page_finishes_after_an_expired_only_tail() {
    let backend = FakeSessionBackend::in_memory_lab();
    let count = crate::restore::RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE;
    let deadline = backend.clock.now_utc().add_seconds(1).unwrap();
    {
        let mut state = backend.inner.lock().await;
        for index in 0..count + 8 {
            let mut value = record(1, 1);
            value.key.stable_id =
                StableId::new(Bytes::copy_from_slice(&(index as u64).to_be_bytes())).unwrap();
            if index >= count {
                value.expires_at = Some(deadline);
            }
            state
                .records
                .insert(FakeSessionBackend::map_key(&value.key), value);
        }
    }
    tokio::time::advance(Duration::from_secs(2)).await;
    let before = backend.inner.lock().await.records.clone();
    let mut request = RestoreScanRequest::all(1);
    request.scope.owner = Some(OwnerId::new("unmatched-owner").unwrap());
    let page = backend.scan_restore_records(request.clone()).await.unwrap();
    page.validate_for_request(&request).unwrap();
    assert!(page.records.is_empty());
    assert_eq!(page.excluded_count, count);
    assert!(
        page.complete,
        "expired physical rows do not create a live continuation"
    );
    assert!(page.next_cursor.is_none());
    assert_eq!(backend.inner.lock().await.records, before);
}
