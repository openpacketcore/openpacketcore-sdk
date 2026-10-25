use super::*;
use crate::{
    AtomicFencedTransitionCapability, EncryptedSessionPayload, EncryptingSessionBackend,
    FencedTransitionExecuteError, FencedTransitionRequestId, Generation,
    PreparedFencedTransitionJournal, PreparedFencedTransitionLookup, StateClass, StateType,
};
use bytes::Bytes;
use opc_types::{NetworkFunctionKind, TenantId};

fn key() -> SessionKey {
    SessionKey {
        tenant: TenantId::new("lab").unwrap(),
        nf_kind: NetworkFunctionKind::from_static("epdg"),
        key_type: SessionKeyType::PduSession,
        stable_id: StableId::new(Bytes::from_static(b"synthetic-session")).unwrap(),
    }
}

fn record(generation: u64, fence: u64) -> StoredSessionRecord {
    StoredSessionRecord {
        key: key(),
        generation: Generation::new(generation),
        owner: OwnerId::new("lab-owner").unwrap(),
        fence: FenceToken::new(fence),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("lab-record").unwrap(),
        expires_at: None,
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"synthetic-payload")),
    }
}

fn create_request() -> FencedTransitionRequest {
    FencedTransitionRequest::new(
        FencedTransitionRequestId::new(),
        FencedTransitionLease::acquire(
            key(),
            OwnerId::new("lab-owner").unwrap(),
            FenceToken::new(0),
            Duration::from_secs(30),
        )
        .unwrap(),
        FencedTransitionMutation::create(record(1, 1)),
    )
    .unwrap()
}

#[tokio::test]
async fn ordinary_fake_still_withholds_atomic_transition_capability() {
    let backend = FakeSessionBackend::new();
    assert_eq!(backend.fenced_transition_capability().await.unwrap(), None);
    assert!(backend
        .prepare_fenced_transition(create_request())
        .await
        .is_err());
}

#[tokio::test]
async fn lab_create_replay_and_renew_update_share_one_live_record() {
    let backend = FakeSessionBackend::in_memory_lab();
    let prepared = backend
        .prepare_fenced_transition(create_request())
        .await
        .unwrap();
    let first = backend.fenced_transition(&prepared).await.unwrap();
    assert_eq!(backend.fenced_transition(&prepared).await.unwrap(), first);
    assert_eq!(backend.get(&key()).await.unwrap(), Some(record(1, 1)));
    let update = FencedTransitionRequest::new(
        FencedTransitionRequestId::new(),
        FencedTransitionLease::renew(first.lease().clone(), Duration::from_secs(60)).unwrap(),
        FencedTransitionMutation::update(Generation::new(1), record(2, 1)),
    )
    .unwrap();
    let update = backend.prepare_fenced_transition(update).await.unwrap();
    let result = backend.fenced_transition(&update).await.unwrap();
    assert_eq!(result.committed_generation(), Generation::new(2));
    assert_eq!(backend.get(&key()).await.unwrap(), Some(record(2, 1)));
    assert_eq!(
        backend.fenced_transition_status(&prepared).await.unwrap(),
        FencedTransitionStatus::Recorded(Box::new(Ok(first)))
    );
}

#[tokio::test]
async fn failed_record_condition_does_not_allocate_lease_or_fence() {
    let backend = FakeSessionBackend::in_memory_lab();
    let invalid = FencedTransitionRequest::new(
        FencedTransitionRequestId::new(),
        FencedTransitionLease::acquire(
            key(),
            OwnerId::new("lab-owner").unwrap(),
            FenceToken::new(0),
            Duration::from_secs(30),
        )
        .unwrap(),
        FencedTransitionMutation::update(Generation::new(1), record(2, 1)),
    )
    .unwrap();
    let prepared = backend.prepare_fenced_transition(invalid).await.unwrap();
    assert_eq!(
        backend.fenced_transition(&prepared).await,
        Err(FencedTransitionExecuteError::Rejected(
            StoreError::CasConflict
        ))
    );
    let observation = backend.observe_fenced_transition(&key()).await.unwrap();
    assert!(observation.record().is_none());
    assert_eq!(observation.current_fence(), FenceToken::new(0));
    let prepared = backend
        .prepare_fenced_transition(create_request())
        .await
        .unwrap();
    assert!(backend.fenced_transition(&prepared).await.is_ok());
}

#[tokio::test]
async fn committing_another_key_preserves_the_first_record_lease_and_receipt() {
    let backend = FakeSessionBackend::in_memory_lab();
    let first = backend
        .prepare_fenced_transition(create_request())
        .await
        .unwrap();
    let first_outcome = backend.fenced_transition(&first).await.unwrap();
    let mut other_record = record(1, 1);
    other_record.key.stable_id = StableId::new(Bytes::from_static(b"other-session")).unwrap();
    let other = FencedTransitionRequest::new(
        FencedTransitionRequestId::new(),
        FencedTransitionLease::acquire(
            other_record.key.clone(),
            other_record.owner.clone(),
            FenceToken::new(0),
            Duration::from_secs(30),
        )
        .unwrap(),
        FencedTransitionMutation::create(other_record.clone()),
    )
    .unwrap();
    let other = backend.prepare_fenced_transition(other).await.unwrap();
    backend.fenced_transition(&other).await.unwrap();
    assert_eq!(backend.get(&key()).await.unwrap(), Some(record(1, 1)));
    assert_eq!(
        backend.get(&other_record.key).await.unwrap(),
        Some(other_record)
    );
    assert_eq!(
        backend.fenced_transition(&first).await.unwrap(),
        first_outcome
    );
    let renewed = backend
        .renew(first_outcome.lease(), Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(renewed.fence(), first_outcome.lease().fence());
}

#[tokio::test]
async fn request_identity_cannot_be_rebound_and_another_allocation_rejects_token() {
    let backend = FakeSessionBackend::in_memory_lab();
    let request = create_request();
    let prepared = backend
        .prepare_fenced_transition(request.clone())
        .await
        .unwrap();
    backend.fenced_transition(&prepared).await.unwrap();
    let mut different = record(1, 1);
    different.payload = EncryptedSessionPayload::new(Bytes::from_static(b"different"));
    let conflict = FencedTransitionRequest::new(
        request.request_id(),
        request.lease().clone(),
        FencedTransitionMutation::create(different),
    )
    .unwrap();
    let conflict = backend.prepare_fenced_transition(conflict).await.unwrap();
    assert_eq!(
        backend.fenced_transition_status(&conflict).await.unwrap(),
        FencedTransitionStatus::RequestConflict
    );
    assert_eq!(
        backend.fenced_transition(&conflict).await,
        Err(FencedTransitionExecuteError::Rejected(
            StoreError::FencedTransitionRequestConflict
        ))
    );
    let other = FakeSessionBackend::in_memory_lab();
    assert!(!other.fenced_transition_accepts_prepared_physical_token(&prepared));
    assert!(other.fenced_transition(&prepared).await.is_err());
    assert!(other.get(&key()).await.unwrap().is_none());
}

#[tokio::test]
async fn stale_fence_leaves_record_unchanged() {
    let backend = FakeSessionBackend::in_memory_lab();
    let prepared = backend
        .prepare_fenced_transition(create_request())
        .await
        .unwrap();
    let first = backend.fenced_transition(&prepared).await.unwrap();
    let newer = backend
        .acquire(
            &key(),
            OwnerId::new("lab-owner").unwrap(),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    let stale = FencedTransitionRequest::new(
        FencedTransitionRequestId::new(),
        FencedTransitionLease::renew(first.lease().clone(), Duration::from_secs(30)).unwrap(),
        FencedTransitionMutation::update(Generation::new(1), record(2, 1)),
    )
    .unwrap();
    let stale = backend.prepare_fenced_transition(stale).await.unwrap();
    assert_eq!(
        backend.fenced_transition(&stale).await,
        Err(FencedTransitionExecuteError::Rejected(
            StoreError::StaleFence
        ))
    );
    assert!(newer.fence() > first.lease().fence());
    assert_eq!(backend.get(&key()).await.unwrap(), Some(record(1, 1)));
}

#[tokio::test(start_paused = true)]
async fn expired_renewal_leaves_record_and_fence_unchanged() {
    let backend = FakeSessionBackend::in_memory_lab();
    let prepared = backend
        .prepare_fenced_transition(create_request())
        .await
        .unwrap();
    let first = backend.fenced_transition(&prepared).await.unwrap();
    let renewal = FencedTransitionRequest::new(
        FencedTransitionRequestId::new(),
        FencedTransitionLease::renew(first.lease().clone(), Duration::from_secs(30)).unwrap(),
        FencedTransitionMutation::update(Generation::new(1), record(2, 1)),
    )
    .unwrap();
    let renewal = backend.prepare_fenced_transition(renewal).await.unwrap();
    tokio::time::advance(Duration::from_secs(31)).await;
    assert_eq!(
        backend.fenced_transition(&renewal).await,
        Err(FencedTransitionExecuteError::Rejected(
            StoreError::LeaseExpired
        ))
    );
    let observed = backend.observe_fenced_transition(&key()).await.unwrap();
    assert_eq!(observed.record(), Some(&record(1, 1)));
    assert_eq!(observed.current_fence(), FenceToken::new(1));
}

#[tokio::test]
async fn memory_journal_and_sealing_support_exact_recovery_without_files() {
    let physical = Arc::new(FakeSessionBackend::in_memory_lab());
    let provider = Arc::new(opc_key::MemoryKeyProvider::new());
    provider
        .insert_active_key(
            opc_key::KeyId::new("lab-key").unwrap(),
            opc_key::KeyPurpose::Session,
            key().tenant.clone(),
            opc_key::Zeroizing::new([7; 32]),
        )
        .unwrap();
    let journal = Arc::new(PreparedFencedTransitionJournal::in_memory_lab());
    let backend =
        EncryptingSessionBackend::new(Arc::clone(&physical), Arc::clone(&provider), "lab-memory")
            .with_fenced_transition_journal(Arc::clone(&journal));
    assert_eq!(
        backend.fenced_transition_capability().await.unwrap(),
        Some(AtomicFencedTransitionCapability::V2)
    );
    let request = create_request();
    let prepared = backend
        .prepare_fenced_transition(request.clone())
        .await
        .unwrap();
    let first = backend.fenced_transition(&prepared).await.unwrap();
    assert_eq!(backend.get(&key()).await.unwrap(), Some(record(1, 1)));
    assert_ne!(
        physical.get(&key()).await.unwrap().unwrap().payload,
        record(1, 1).payload
    );
    let recovered = EncryptingSessionBackend::new(physical, provider, "lab-memory")
        .with_fenced_transition_journal(journal);
    let PreparedFencedTransitionLookup::Found(token) = recovered
        .recover_prepared_fenced_transition(request.request_id())
        .await
        .unwrap()
    else {
        panic!("retained preparation missing");
    };
    assert_eq!(token, prepared);
    assert_eq!(
        recovered.fenced_transition_status(&token).await.unwrap(),
        FencedTransitionStatus::Recorded(Box::new(Ok(first)))
    );
    let fresh = PreparedFencedTransitionJournal::in_memory_lab();
    assert!(matches!(
        fresh.lookup(request.request_id()).await.unwrap(),
        PreparedFencedTransitionLookup::Absent
    ));
}

#[tokio::test]
async fn receipt_capacity_fails_without_record_mutation() {
    let mut backend = FakeSessionBackend::in_memory_lab();
    backend.limits.max_replication_entries = 0;
    let prepared = backend
        .prepare_fenced_transition(create_request())
        .await
        .unwrap();
    assert_eq!(
        backend.fenced_transition(&prepared).await,
        Err(FencedTransitionExecuteError::Rejected(
            StoreError::FencedTransitionHistoryFull
        ))
    );
    assert!(backend.get(&key()).await.unwrap().is_none());
    assert_eq!(
        backend
            .observe_fenced_transition(&key())
            .await
            .unwrap()
            .current_fence(),
        FenceToken::new(0)
    );
}

async fn insert_restore_record(backend: &FakeSessionBackend, id: &[u8]) -> StoredSessionRecord {
    let mut value = record(1, 1);
    value.key.stable_id = StableId::new(Bytes::copy_from_slice(id)).unwrap();
    let lease = backend
        .acquire(&value.key, value.owner.clone(), Duration::from_secs(30))
        .await
        .unwrap();
    value.fence = lease.fence();
    assert_eq!(
        backend
            .compare_and_set(CompareAndSet {
                key: value.key.clone(),
                expected_generation: None,
                lease,
                new_record: value.clone(),
            })
            .await
            .unwrap(),
        CompareAndSetResult::Success
    );
    value
}

#[tokio::test]
async fn lab_restore_uses_authenticated_seek_pages_and_preserves_ordinary_fake_profile() {
    let backend = FakeSessionBackend::in_memory_lab();
    let first_record = insert_restore_record(&backend, b"a").await;
    let last_record = insert_restore_record(&backend, b"z").await;
    let request = RestoreScanRequest::all(1);
    let first = backend.scan_restore_records(request.clone()).await.unwrap();
    assert_eq!(
        backend.restore_scan_cursor_profile(),
        Some(crate::RestoreScanCursorProfile::DurableOpaqueV1)
    );
    assert_eq!(
        first.cursor_profile,
        crate::RestoreScanCursorProfile::DurableOpaqueV1
    );
    first.validate_for_request(&request).unwrap();
    assert_eq!(first.records, vec![first_record]);
    let cursor = first.next_cursor.unwrap();
    assert!(!cursor.is_legacy());
    let next_request = RestoreScanRequest {
        cursor: Some(cursor),
        ..request
    };
    let last = backend
        .scan_restore_records(next_request.clone())
        .await
        .unwrap();
    last.validate_for_request(&next_request).unwrap();
    assert_eq!(last.records, vec![last_record]);
    assert!(last.complete);
    assert_eq!(
        FakeSessionBackend::new().restore_scan_cursor_profile(),
        Some(crate::RestoreScanCursorProfile::LegacyCompatibility)
    );
}

#[tokio::test]
async fn lab_restore_rejects_legacy_foreign_scoped_and_changed_snapshot_cursors() {
    let backend = FakeSessionBackend::in_memory_lab();
    insert_restore_record(&backend, b"a").await;
    insert_restore_record(&backend, b"z").await;
    let request = RestoreScanRequest::all(1);
    let cursor = backend
        .scan_restore_records(request.clone())
        .await
        .unwrap()
        .next_cursor
        .unwrap();
    let next = RestoreScanRequest {
        cursor: Some(cursor),
        ..request.clone()
    };
    let legacy = RestoreScanRequest {
        cursor: Some(RestoreScanCursor::from_offset(1)),
        ..request
    };
    assert_eq!(
        backend.scan_restore_records(legacy).await,
        Err(StoreError::RestoreScanCursorStale)
    );
    assert_eq!(
        FakeSessionBackend::in_memory_lab()
            .scan_restore_records(next.clone())
            .await,
        Err(StoreError::RestoreScanCursorStale)
    );
    let mut scoped = next.clone();
    scoped.scope.owner = Some(OwnerId::new("other-owner").unwrap());
    assert!(backend.scan_restore_records(scoped).await.is_err());
    insert_restore_record(&backend, b"b").await;
    assert_eq!(
        backend.scan_restore_records(next).await,
        Err(StoreError::RestoreScanCursorStale)
    );
}

#[tokio::test(start_paused = true)]
async fn lab_restore_rejects_a_cursor_after_expiry_prunes_the_snapshot() {
    let backend = FakeSessionBackend::in_memory_lab();
    insert_restore_record(&backend, b"a").await;
    let expiring = insert_restore_record(&backend, b"z").await;
    let lease = backend
        .acquire(
            &expiring.key,
            expiring.owner.clone(),
            Duration::from_secs(30),
        )
        .await
        .unwrap();
    backend
        .refresh_ttl(&lease, Duration::from_secs(1))
        .await
        .unwrap();
    let request = RestoreScanRequest::all(1);
    let cursor = backend
        .scan_restore_records(request.clone())
        .await
        .unwrap()
        .next_cursor
        .unwrap();
    tokio::time::advance(Duration::from_secs(2)).await;
    assert_eq!(
        backend
            .scan_restore_records(RestoreScanRequest {
                cursor: Some(cursor),
                ..request
            })
            .await,
        Err(StoreError::RestoreScanCursorStale)
    );
}

#[tokio::test]
async fn lab_restore_rejects_cursor_after_batch_or_rebuild_and_at_revision_exhaustion() {
    let backend = FakeSessionBackend::in_memory_lab();
    let mut value = insert_restore_record(&backend, b"a").await;
    insert_restore_record(&backend, b"z").await;
    let lease = backend
        .acquire(&value.key, value.owner.clone(), Duration::from_secs(30))
        .await
        .unwrap();
    value.fence = lease.fence();
    value.generation = Generation::new(2);
    let request = RestoreScanRequest::all(1);
    let cursor = backend
        .scan_restore_records(request.clone())
        .await
        .unwrap()
        .next_cursor
        .unwrap();
    let results = backend
        .batch(vec![SessionOp::CompareAndSet(CompareAndSet {
            key: value.key.clone(),
            expected_generation: Some(Generation::new(1)),
            lease,
            new_record: value,
        })])
        .await
        .unwrap();
    assert!(matches!(
        results.as_slice(),
        [SessionOpResult::CompareAndSet(Ok(
            CompareAndSetResult::Success
        ))]
    ));
    assert_eq!(
        backend
            .scan_restore_records(RestoreScanRequest {
                cursor: Some(cursor),
                ..request.clone()
            })
            .await,
        Err(StoreError::RestoreScanCursorStale)
    );
    let cursor = backend
        .scan_restore_records(request.clone())
        .await
        .unwrap()
        .next_cursor
        .unwrap();
    backend.rebuild_replication_state(Vec::new()).await.unwrap();
    assert_eq!(
        backend
            .scan_restore_records(RestoreScanRequest {
                cursor: Some(cursor),
                ..request.clone()
            })
            .await,
        Err(StoreError::RestoreScanCursorStale)
    );
    backend.inner.lock().await.lab_restore_revision = u64::MAX;
    assert_eq!(
        backend.scan_restore_records(request).await,
        Err(StoreError::RestoreScanWorkBudgetExceeded)
    );
}

#[tokio::test]
async fn lab_restore_sparse_scope_pages_bound_work_and_advance_without_matches() {
    let backend = FakeSessionBackend::in_memory_lab();
    let maximum = crate::restore::RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE;
    {
        let mut state = backend.inner.lock().await;
        for index in 0..=maximum {
            let mut value = record(1, 1);
            value.key.stable_id =
                StableId::new(Bytes::copy_from_slice(&(index as u64).to_be_bytes())).unwrap();
            state
                .records
                .insert(FakeSessionBackend::map_key(&value.key), value);
        }
    }
    let mut request = RestoreScanRequest::all(1);
    request.scope.owner = Some(OwnerId::new("absent-owner").unwrap());
    let first = backend.scan_restore_records(request.clone()).await.unwrap();
    first.validate_for_request(&request).unwrap();
    assert!(first.records.is_empty());
    assert_eq!(first.excluded_count, maximum);
    request.cursor = first.next_cursor;
    assert!(request.cursor.is_some());
    let last = backend.scan_restore_records(request.clone()).await.unwrap();
    last.validate_for_request(&request).unwrap();
    assert!(last.records.is_empty());
    assert_eq!(last.excluded_count, 1);
    assert!(last.complete);
}

fn session_key_at(index: u32) -> SessionKey {
    let mut value = key();
    value.stable_id = StableId::new(Bytes::copy_from_slice(&index.to_be_bytes())).unwrap();
    value
}

fn record_for_key(key: SessionKey) -> StoredSessionRecord {
    let mut value = record(1, 1);
    value.key = key;
    value
}

/// Build a create request the way an SDK client does: observe the key's fence
/// first, then bind the record to `observed + 1`.
///
/// A key whose dead floor was retired under capacity pressure observes the
/// backend-wide retired-fence high-water instead of zero, so a fixed zero
/// expectation would be rejected and would silently reintroduce the fence
/// regression the high-water prevents.
async fn create_request_at(backend: &FakeSessionBackend, index: u32) -> FencedTransitionRequest {
    let key = session_key_at(index);
    let observed = backend
        .observe_fenced_transition(&key)
        .await
        .unwrap()
        .current_fence();
    let mut record = record_for_key(key.clone());
    record.owner = OwnerId::new("lab-owner").unwrap();
    record.fence = FenceToken::new(observed.get() + 1);
    FencedTransitionRequest::new(
        FencedTransitionRequestId::new(),
        FencedTransitionLease::acquire(
            key,
            OwnerId::new("lab-owner").unwrap(),
            observed,
            Duration::from_secs(30),
        )
        .unwrap(),
        FencedTransitionMutation::create(record),
    )
    .unwrap()
}

fn delete_request_after(outcome: &FencedTransitionOutcome) -> FencedTransitionRequest {
    FencedTransitionRequest::new(
        FencedTransitionRequestId::new(),
        FencedTransitionLease::renew(outcome.lease().clone(), Duration::from_secs(30)).unwrap(),
        FencedTransitionMutation::delete(Generation::new(1)),
    )
    .unwrap()
}

async fn execute_transition(
    backend: &FakeSessionBackend,
    request: FencedTransitionRequest,
) -> FencedTransitionOutcome {
    let prepared = backend.prepare_fenced_transition(request).await.unwrap();
    backend.fenced_transition(&prepared).await.unwrap()
}

/// Execute a fresh create transition, rebuilding it from a fresh observation if
/// a retired-floor maintenance step raced the request (retryable `StaleFence`).
async fn execute_create(backend: &FakeSessionBackend, index: u32) -> FencedTransitionOutcome {
    for _ in 0..4 {
        let request = create_request_at(backend, index).await;
        let prepared = backend.prepare_fenced_transition(request).await.unwrap();
        match backend.fenced_transition(&prepared).await {
            Ok(outcome) => return outcome,
            Err(FencedTransitionExecuteError::Rejected(StoreError::StaleFence)) => continue,
            Err(other) => panic!("unexpected create transition failure: {other:?}"),
        }
    }
    panic!("create transition was not admitted after rebuilding from observation");
}

#[tokio::test(start_paused = true)]
async fn lab_retires_only_elapsed_receipts_at_capacity_and_keeps_typed_expiry() {
    let mut backend = FakeSessionBackend::in_memory_lab();
    backend.caps.ordered_replication_log = false;
    backend.limits.max_replication_entries = 4;
    let mut prepared = Vec::new();
    for index in 0..4u32 {
        prepared.push(
            backend
                .prepare_fenced_transition(create_request_at(&backend, index).await)
                .await
                .unwrap(),
        );
        backend
            .fenced_transition(prepared.last().unwrap())
            .await
            .unwrap();
    }
    assert_eq!(backend.inner.lock().await.lab_transitions.len(), 4);

    // Every retained receipt is still inside its answer window, so the bound is
    // authoritative and the next transition fails closed without mutation.
    let fifth = backend
        .prepare_fenced_transition(create_request_at(&backend, 99).await)
        .await
        .unwrap();
    assert_eq!(
        backend.fenced_transition(&fifth).await,
        Err(FencedTransitionExecuteError::Rejected(
            StoreError::FencedTransitionHistoryFull
        ))
    );
    assert!(backend.get(&session_key_at(99)).await.unwrap().is_none());
    assert_eq!(backend.inner.lock().await.lab_transitions.len(), 4);

    // Inside the window the exact outcome still replays.
    let first = backend.fenced_transition(&prepared[0]).await.unwrap();
    assert_eq!(
        backend
            .fenced_transition_status(&prepared[0])
            .await
            .unwrap(),
        FencedTransitionStatus::Recorded(Box::new(Ok(first)))
    );

    // Past the window the retained receipt reports the typed expiry.
    tokio::time::advance(FENCED_TRANSITION_OUTCOME_RETENTION + Duration::from_secs(1)).await;
    assert_eq!(
        backend
            .fenced_transition_status(&prepared[0])
            .await
            .unwrap(),
        FencedTransitionStatus::Expired
    );
    assert_eq!(
        backend.fenced_transition(&prepared[0]).await,
        Err(FencedTransitionExecuteError::Rejected(
            StoreError::FencedTransitionRequestExpired
        ))
    );

    // Capacity pressure now retires only those elapsed receipts and the new
    // transition proceeds with the retained set still bounded.
    backend.fenced_transition(&fifth).await.unwrap();
    let state = backend.inner.lock().await;
    assert!(state.lab_transitions.len() <= 4);
}

#[tokio::test(start_paused = true)]
async fn lab_bounds_receipts_past_sixty_five_thousand_fenced_transitions() {
    let mut backend = FakeSessionBackend::in_memory_lab();
    backend.caps.ordered_replication_log = false;
    backend.limits.max_tracked_keys = 1_024;
    let mut completed = 0usize;
    let mut index = 0u32;
    while completed <= 65_536 {
        for _ in 0..256 {
            let create = execute_create(&backend, index).await;
            index += 1;
            let _delete = execute_transition(&backend, delete_request_after(&create)).await;
            completed += 2;
        }
        tokio::time::advance(FENCED_TRANSITION_OUTCOME_RETENTION + Duration::from_secs(1)).await;
    }
    // Trigger the ordinary expiry prune for the final batch before the bounds.
    let _ = backend.get(&session_key_at(0)).await.unwrap();
    let state = backend.inner.lock().await;
    assert!(
        completed > 65_536,
        "the run passes the old lifetime ceiling"
    );
    assert!(
        state.lab_transitions.len() <= 65_536,
        "retained receipts stay bounded"
    );
    assert!(
        state.key_fences.len() <= 1_024,
        "tracked key floors stay bounded"
    );
    assert!(state.records.is_empty(), "every created record was deleted");
    assert!(state.leases.len() <= 1_024);
}

#[tokio::test]
async fn lab_bounds_created_and_deleted_keys_past_one_hundred_thousand() {
    let mut backend = FakeSessionBackend::in_memory_lab();
    backend.caps.ordered_replication_log = false;
    backend.limits.max_tracked_keys = 1_024;
    let owner = OwnerId::new("lab-owner").unwrap();
    for index in 0..100_010u32 {
        let key = session_key_at(index);
        let lease = backend
            .acquire(&key, owner.clone(), Duration::from_secs(30))
            .await
            .unwrap();
        let mut record = record_for_key(key.clone());
        record.owner = lease.owner().clone();
        record.fence = lease.fence();
        backend
            .compare_and_set(CompareAndSet {
                key: key.clone(),
                lease: lease.clone(),
                expected_generation: None,
                new_record: record,
            })
            .await
            .unwrap();
        backend.delete_fenced(&lease).await.unwrap();
        backend.release(lease).await.unwrap();
    }
    assert!(
        backend.inner.lock().await.key_fences.len() <= 1_024,
        "only live key floors are retained"
    );
}

#[tokio::test(start_paused = true)]
async fn retired_floor_high_water_keeps_recreated_key_fences_monotone_and_log_rebuildable() {
    let mut backend = FakeSessionBackend::in_memory_lab();
    backend.limits.max_tracked_keys = 1;
    backend.limits.max_replication_entries = 128;
    let key = session_key_at(7);
    let owner = OwnerId::new("lab-owner").unwrap();

    // Commit fences 1 and 2 for the key through the direct lease API, then
    // delete the record and release so only a dead floor remains.
    let mut committed = Vec::new();
    let first = backend
        .acquire(&key, owner.clone(), Duration::from_secs(30))
        .await
        .unwrap();
    committed.push(first.fence());
    backend.release(first).await.unwrap();
    let second = backend
        .acquire(&key, owner.clone(), Duration::from_secs(30))
        .await
        .unwrap();
    committed.push(second.fence());
    assert_eq!(committed, vec![FenceToken::new(1), FenceToken::new(2)]);
    let mut record = record_for_key(key.clone());
    record.owner = owner.clone();
    record.fence = second.fence();
    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: second.clone(),
            expected_generation: None,
            new_record: record,
        })
        .await
        .unwrap();
    backend.delete_fenced(&second).await.unwrap();
    backend.release(second).await.unwrap();
    tokio::time::advance(Duration::from_secs(31)).await;

    // Capacity pressure retires the dead floor: its fence becomes the
    // backend-wide high-water instead of being forgotten.
    let trigger = session_key_at(8);
    let trigger_lease = backend
        .acquire(&trigger, owner.clone(), Duration::from_secs(30))
        .await
        .unwrap();
    {
        let state = backend.inner.lock().await;
        assert!(!state
            .key_fences
            .contains_key(&FakeSessionBackend::map_key(&key)));
        assert_eq!(state.retired_fence_high_water, FenceToken::new(2));
    }
    backend.release(trigger_lease).await.unwrap();

    // Observation -> prepare -> execute can race the retired-floor maintenance:
    // a maintenance step may raise the high-water after the key was observed, so
    // the exact request is rebuilt from a fresh observation (retryable
    // `StaleFence`).
    let mut recreated = None;
    for _ in 0..4 {
        let observed = backend
            .observe_fenced_transition(&key)
            .await
            .unwrap()
            .current_fence();
        let mut record = record_for_key(key.clone());
        record.owner = owner.clone();
        record.fence = FenceToken::new(observed.get() + 1);
        let request = FencedTransitionRequest::new(
            FencedTransitionRequestId::new(),
            FencedTransitionLease::acquire(
                key.clone(),
                owner.clone(),
                observed,
                Duration::from_secs(30),
            )
            .unwrap(),
            FencedTransitionMutation::create(record.clone()),
        )
        .unwrap();
        let prepared = backend.prepare_fenced_transition(request).await.unwrap();
        match backend.fenced_transition(&prepared).await {
            Ok(outcome) => {
                recreated = Some((outcome, record));
                break;
            }
            Err(FencedTransitionExecuteError::Rejected(StoreError::StaleFence)) => continue,
            Err(other) => panic!("unexpected transition failure: {other:?}"),
        }
    }
    let (outcome, record) = recreated.expect("the re-acquire must eventually commit");
    assert!(
        committed
            .iter()
            .all(|prior| outcome.lease().fence() > *prior),
        "a re-created key must commit a fence strictly above every earlier fence: {} vs {:?}",
        outcome.lease().fence(),
        committed
    );
    assert_eq!(backend.get(&key).await.unwrap(), Some(record.clone()));

    // The self-generated replication log replays deterministically through the
    // same capacity-retirement rules instead of depending on the live bound.
    let log = backend.get_replication_log(1, 128).await.unwrap();
    backend
        .rebuild_replication_state(log)
        .await
        .expect("the self-generated log must rebuild after floor retirement");
    assert_eq!(backend.get(&key).await.unwrap(), Some(record));
}

#[tokio::test(start_paused = true)]
async fn lab_key_capacity_refusal_mutates_nothing_and_is_retryable() {
    let mut backend = FakeSessionBackend::in_memory_lab();
    backend.caps.ordered_replication_log = false;
    backend.limits.max_tracked_keys = 1;
    let owner = OwnerId::new("lab-owner").unwrap();

    let occupied = session_key_at(1);
    let occupied_lease = backend
        .acquire(&occupied, owner.clone(), Duration::from_secs(30))
        .await
        .unwrap();
    // Add a record that expires while the occupying lease stays live. A
    // prune-on-refusal implementation would drop this record even though the
    // capacity check ultimately refuses, so it must survive the refusal.
    let now = backend.clock.now_utc();
    let mut occupied_record = record_for_key(occupied.clone());
    occupied_record.owner = owner.clone();
    occupied_record.fence = occupied_lease.fence();
    occupied_record.expires_at =
        Some(checked_session_deadline(now, Duration::from_secs(5)).expect("record expiry"));
    backend
        .compare_and_set(CompareAndSet {
            key: occupied.clone(),
            lease: occupied_lease.clone(),
            expected_generation: None,
            new_record: occupied_record,
        })
        .await
        .unwrap();
    tokio::time::advance(Duration::from_secs(6)).await;
    assert_eq!(
        backend.inner.lock().await.records.len(),
        1,
        "the occupying record is expired but not yet pruned"
    );

    let snapshot = {
        let state = backend.inner.lock().await;
        (
            state.key_fences.clone(),
            state.leases.clone(),
            state.records.clone(),
            state.lab_transitions.len(),
            state.next_fence,
            state.retired_fence_high_water,
        )
    };
    let blocked = create_request_at(&backend, 2).await;
    let prepared = backend.prepare_fenced_transition(blocked).await.unwrap();
    assert_eq!(
        backend.fenced_transition(&prepared).await,
        Err(FencedTransitionExecuteError::Rejected(
            StoreError::BackendUnavailable("fake backend tracked-key limit reached".into())
        ))
    );
    let after = {
        let state = backend.inner.lock().await;
        (
            state.key_fences.clone(),
            state.leases.clone(),
            state.records.clone(),
            state.lab_transitions.len(),
            state.next_fence,
            state.retired_fence_high_water,
        )
    };
    assert!(
        snapshot == after,
        "a capacity refusal must leave every record (including the expired one), lease, fence, receipt and watermark untouched"
    );

    // Retryable: once the occupying elapsed state can be retired, a freshly
    // observed request is admitted (the first retry may see a retryable
    // StaleFence if retiring that state raises the high-water first).
    tokio::time::advance(Duration::from_secs(61)).await;
    drop(occupied_lease);
    let target = session_key_at(2);
    let mut admitted = false;
    for _ in 0..4 {
        let request = create_request_at(&backend, 2).await;
        let prepared = backend.prepare_fenced_transition(request).await.unwrap();
        match backend.fenced_transition(&prepared).await {
            Ok(_) => {
                admitted = true;
                break;
            }
            Err(FencedTransitionExecuteError::Rejected(StoreError::StaleFence)) => continue,
            Err(other) => panic!("unexpected transition failure: {other:?}"),
        }
    }
    assert!(
        admitted,
        "capacity must be reclaimable and the transition retryable"
    );
    assert!(backend.get(&target).await.unwrap().is_some());
}

fn stale_replication_entry(
    sequence: u64,
    tx_id: &str,
    timestamp: Timestamp,
    op: ReplicationOp,
) -> ReplicationEntry {
    ReplicationEntry {
        sequence,
        tx_id: tx_id.try_into().expect("valid transaction ID"),
        op,
        timestamp,
    }
}

#[tokio::test(start_paused = true)]
async fn replicated_stale_delete_cannot_remove_a_newer_record_after_floor_retirement() {
    let mut backend = FakeSessionBackend::in_memory_lab();
    backend.limits.max_tracked_keys = 1;
    backend.limits.max_replication_entries = 128;
    let key = session_key_at(17);
    let owner = OwnerId::new("lab-owner").unwrap();

    // Commit fences 1 and 2 for the key through the direct lease API, then
    // delete the record and release so only a dead floor remains.
    let first = backend
        .acquire(&key, owner.clone(), Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(first.fence(), FenceToken::new(1));
    backend.release(first).await.unwrap();
    let second = backend
        .acquire(&key, owner.clone(), Duration::from_secs(30))
        .await
        .unwrap();
    assert_eq!(second.fence(), FenceToken::new(2));
    let mut record = record_for_key(key.clone());
    record.owner = owner.clone();
    record.fence = second.fence();
    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: second.clone(),
            expected_generation: None,
            new_record: record,
        })
        .await
        .unwrap();
    backend.delete_fenced(&second).await.unwrap();
    backend.release(second).await.unwrap();
    tokio::time::advance(Duration::from_secs(31)).await;

    // Capacity pressure retires the dead floor into the backend high-water.
    let trigger = session_key_at(18);
    let trigger_lease = backend
        .acquire(&trigger, owner.clone(), Duration::from_secs(30))
        .await
        .unwrap();
    {
        let state = backend.inner.lock().await;
        assert!(!state
            .key_fences
            .contains_key(&FakeSessionBackend::map_key(&key)));
        assert_eq!(state.retired_fence_high_water, FenceToken::new(2));
    }
    backend.release(trigger_lease).await.unwrap();

    // Re-create the SAME key through the lab `Acquire` path (observe, then bind
    // the record to the observed fence). On the pre-fix backend observation
    // reports zero here, so this would commit fence 1 and the stale replicated
    // `DeleteFenced` below would delete the newer record instead of failing.
    let _outcome = execute_create(&backend, 17).await;
    let recreated = backend
        .get(&key)
        .await
        .unwrap()
        .expect("the lab Acquire path re-created the record");
    assert!(
        recreated.fence > FenceToken::new(2),
        "re-created record fence {} must exceed the retired fences",
        recreated.fence
    );

    // A stale replicated DeleteFenced carrying an old fence must not remove the
    // newer record: with the high-water in place the floor check still rejects it.
    let sequence = backend.max_replication_sequence().await.unwrap() + 1;
    let stale = stale_replication_entry(
        sequence,
        "stale-delete-after-recreate",
        backend.clock.now_utc(),
        ReplicationOp::DeleteFenced {
            key: key.clone(),
            owner: owner.clone(),
            fence: FenceToken::new(2),
        },
    );
    assert_eq!(
        backend.replicate_entry(stale).await.unwrap_err(),
        StoreError::StaleFence
    );
    assert_eq!(
        backend.get(&key).await.unwrap(),
        Some(recreated),
        "the stale replicated delete must not remove the newer record"
    );
}
