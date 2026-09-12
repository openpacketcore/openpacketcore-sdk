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
