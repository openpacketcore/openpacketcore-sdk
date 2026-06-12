use bytes::Bytes;
use std::sync::Arc;
use std::time::Duration;

use opc_session_store::{
    CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, Generation, HandoverEnvelope,
    HandoverError, HandoverManager, HandoverPhase, HandoverTxId, LeaseGuard, OwnerId,
    SessionBackend, SessionKey, SessionKeyType, SessionLeaseManager, SqliteSessionBackend,
    StateClass, StateType, StoreError, StoredSessionRecord, SystemClock, TokioVirtualClock,
};
use opc_types::{NetworkFunctionKind, TenantId};

fn tenant() -> TenantId {
    TenantId::new("tenant-a").expect("tenant")
}

fn test_key(stable_id: &[u8]) -> SessionKey {
    SessionKey {
        tenant: tenant(),
        nf_kind: NetworkFunctionKind::from_static("smf"),
        key_type: SessionKeyType::PduSession,
        stable_id: Bytes::copy_from_slice(stable_id),
    }
}

async fn setup_record_with_fence(
    backend: &Arc<SqliteSessionBackend>,
    key: &SessionKey,
    owner: OwnerId,
    fence_val: u64,
    payload: &[u8],
) -> (LeaseGuard, StoredSessionRecord) {
    let lease = backend
        .acquire(key, owner.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    let mut current_lease = lease;
    while current_lease.fence().get() < fence_val {
        current_lease = backend
            .acquire(key, owner.clone(), Duration::from_secs(60))
            .await
            .unwrap();
    }

    let initial_envelope = HandoverEnvelope {
        phase: HandoverPhase::Stable,
        payload: payload.to_vec(),
    };
    let payload_bytes = initial_envelope.pack_raw().unwrap();
    let record = StoredSessionRecord {
        key: key.clone(),
        generation: Generation::new(1),
        owner: owner.clone(),
        fence: current_lease.fence(),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("smf-pdu-context").expect("state type"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(payload_bytes),
    };
    let cas_res = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: current_lease.clone(),
            expected_generation: None,
            new_record: record.clone(),
        })
        .await
        .unwrap();
    assert_eq!(cas_res, CompareAndSetResult::Success);
    (current_lease, record)
}

#[tokio::test]
async fn test_fence_tokens_validation() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = HandoverManager::new(backend.clone(), Arc::new(SystemClock));
    let key = test_key(b"fence-test-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();
    let tx = HandoverTxId::new();

    let (lease_s, _record) =
        setup_record_with_fence(&backend, &key, owner_s.clone(), 5, b"payload").await;
    let s_fence = lease_s.fence();
    assert!(s_fence.get() >= 5);

    manager
        .prepare_handover(&lease_s, Generation::new(1), tx, owner_t.clone())
        .await
        .unwrap();

    backend.release(lease_s.clone()).await.unwrap();

    let res = manager
        .mark_prepared(&lease_s, Generation::new(2), tx)
        .await;
    assert!(matches!(res, Err(HandoverError::OwnerConflict { .. })));

    let lease_t = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    assert!(lease_t.fence().get() > s_fence.get());

    manager
        .mark_prepared(&lease_t, Generation::new(2), tx)
        .await
        .unwrap();

    let t_fence = lease_t.fence();
    backend.release(lease_t.clone()).await.unwrap();

    let lease_t_new = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();
    assert!(lease_t_new.fence().get() > t_fence.get());

    manager
        .activate_handover(&lease_t_new, Generation::new(3), tx)
        .await
        .unwrap();

    let res_complete = manager
        .complete_handover(&lease_t, Generation::new(4), tx)
        .await;
    assert!(matches!(
        res_complete,
        Err(HandoverError::FencingMismatch { .. })
    ));
}

#[tokio::test(start_paused = true)]
async fn test_lease_expiration_checks() {
    let clock = Arc::new(TokioVirtualClock::new());
    let backend = Arc::new(
        SqliteSessionBackend::in_memory()
            .unwrap()
            .with_clock(clock.clone()),
    );
    let manager = HandoverManager::new(backend.clone(), clock);
    let key = test_key(b"expiry-test-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();
    let tx = HandoverTxId::new();

    let lease_s = backend
        .acquire(&key, owner_s.clone(), Duration::from_millis(10))
        .await
        .unwrap();

    tokio::time::advance(Duration::from_millis(20)).await;

    let res = manager
        .prepare_handover(&lease_s, Generation::new(1), tx, owner_t.clone())
        .await;
    assert!(matches!(res, Err(HandoverError::InvalidLease { .. })));
}

#[tokio::test]
async fn test_stale_source_rejections() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = HandoverManager::new(backend.clone(), Arc::new(SystemClock));
    let key = test_key(b"stale-source-test-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();
    let tx = HandoverTxId::new();

    let (lease_s, _record) =
        setup_record_with_fence(&backend, &key, owner_s.clone(), 1, b"payload").await;

    manager
        .prepare_handover(&lease_s, Generation::new(1), tx, owner_t.clone())
        .await
        .unwrap();

    backend.release(lease_s.clone()).await.unwrap();
    let lease_t = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    manager
        .mark_prepared(&lease_t, Generation::new(2), tx)
        .await
        .unwrap();

    let res_prep = manager
        .prepare_handover(&lease_s, Generation::new(3), tx, owner_t.clone())
        .await;
    assert!(matches!(
        res_prep,
        Err(HandoverError::FencingMismatch { .. })
            | Err(HandoverError::Store(StoreError::StaleFence))
            | Err(HandoverError::OwnerConflict { .. })
            | Err(HandoverError::PhaseRegression { .. })
    ));

    let res_abort = manager
        .abort_handover(&lease_s, Generation::new(3), tx)
        .await;
    assert!(matches!(
        res_abort,
        Err(HandoverError::FencingMismatch { .. })
            | Err(HandoverError::Store(StoreError::StaleFence))
    ));
}

#[tokio::test]
async fn test_transaction_id_mismatch() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = HandoverManager::new(backend.clone(), Arc::new(SystemClock));
    let key = test_key(b"tx-mismatch-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t = OwnerId::new("owner-target").unwrap();

    let tx_correct = HandoverTxId::new();
    let tx_wrong = HandoverTxId::new();

    let (lease_s, _record) =
        setup_record_with_fence(&backend, &key, owner_s.clone(), 1, b"payload").await;

    manager
        .prepare_handover(&lease_s, Generation::new(1), tx_correct, owner_t.clone())
        .await
        .unwrap();

    let res = manager
        .prepare_handover(&lease_s, Generation::new(2), tx_wrong, owner_t.clone())
        .await;
    assert!(matches!(
        res,
        Err(HandoverError::TransactionConflict { active, received })
        if active == tx_correct && received == tx_wrong
    ));

    backend.release(lease_s.clone()).await.unwrap();
    let lease_t = backend
        .acquire(&key, owner_t.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    let res = manager
        .mark_prepared(&lease_t, Generation::new(2), tx_wrong)
        .await;
    assert!(matches!(
        res,
        Err(HandoverError::TransactionConflict { active, received })
        if active == tx_correct && received == tx_wrong
    ));

    manager
        .mark_prepared(&lease_t, Generation::new(2), tx_correct)
        .await
        .unwrap();

    let res = manager
        .activate_handover(&lease_t, Generation::new(3), tx_wrong)
        .await;
    assert!(matches!(
        res,
        Err(HandoverError::TransactionConflict { active, received })
        if active == tx_correct && received == tx_wrong
    ));

    manager
        .activate_handover(&lease_t, Generation::new(3), tx_correct)
        .await
        .unwrap();

    let res = manager
        .complete_handover(&lease_t, Generation::new(4), tx_wrong)
        .await;
    assert!(matches!(
        res,
        Err(HandoverError::TransactionConflict { active, received })
        if active == tx_correct && received == tx_wrong
    ));
}

#[tokio::test]
async fn test_concurrent_handover_race() {
    let backend = Arc::new(SqliteSessionBackend::in_memory().unwrap());
    let manager = Arc::new(HandoverManager::new(backend.clone(), Arc::new(SystemClock)));
    let key = test_key(b"race-key");
    let owner_s = OwnerId::new("owner-source").unwrap();
    let owner_t1 = OwnerId::new("owner-target-1").unwrap();
    let owner_t2 = OwnerId::new("owner-target-2").unwrap();

    let tx1 = HandoverTxId::new();
    let tx2 = HandoverTxId::new();

    let (lease_s, _record) =
        setup_record_with_fence(&backend, &key, owner_s.clone(), 1, b"initial-payload").await;

    manager
        .prepare_handover(&lease_s, Generation::new(1), tx1, owner_t1.clone())
        .await
        .unwrap();

    backend.release(lease_s.clone()).await.unwrap();

    let lease_t1 = backend
        .acquire(&key, owner_t1.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    backend.release(lease_t1.clone()).await.unwrap();

    let lease_t2 = backend
        .acquire(&key, owner_t2.clone(), Duration::from_secs(60))
        .await
        .unwrap();

    assert!(lease_t2.fence().get() > lease_t1.fence().get());

    let res_t1 = manager
        .mark_prepared(&lease_t1, Generation::new(2), tx1)
        .await;
    assert!(matches!(
        res_t1,
        Err(HandoverError::Store(StoreError::StaleFence))
    ));

    let res_t2 = manager
        .mark_prepared(&lease_t2, Generation::new(2), tx2)
        .await;
    assert!(matches!(
        res_t2,
        Err(HandoverError::TransactionConflict { .. }) | Err(HandoverError::OwnerConflict { .. })
    ));
}
