use super::*;
use crate::consensus::native::changes::tests::{apply, request, time};
use crate::consensus::{
    SessionConsensusClusterId, SessionConsensusConfigurationEpoch, SessionConsensusConfigurationId,
};
use opc_consensus::engine::{CommittedLeaderId, Membership};
use std::time::Duration;

fn fixture() -> NativeStorage {
    let identity = SessionConsensusIdentity::new(
        SessionConsensusClusterId::new("async-boundary-fixture").unwrap(),
        SessionConsensusConfigurationId::from_bytes([0x91; 32]),
        SessionConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let members = [7, 8, 9]
        .map(|id| SessionConsensusNodeId::new(id).unwrap())
        .into();
    let mut storage = NativeStorage::empty(identity, members).unwrap();
    let membership = Entry {
        log_id: log_id(1, 0),
        payload: EntryPayload::Membership(Membership::new(
            vec![storage.business.members.clone()],
            storage.business.members.clone(),
        )),
    };
    apply(&mut storage, &[membership]);
    storage
}

fn log_id(term: u64, index: u64) -> LogId<SessionConsensusNodeId> {
    LogId::new(
        CommittedLeaderId::new(term, SessionConsensusNodeId::new(7).unwrap()),
        index,
    )
}

fn command(
    storage: &NativeStorage,
    term: u64,
    index: u64,
    intent: SessionMutationIntent,
) -> Entry<SessionRaftTypeConfig> {
    Entry {
        log_id: log_id(term, index),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: crate::consensus::SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: storage.business.identity,
            request_id: SessionConsensusRequestId::from_bytes(match &intent {
                SessionMutationIntent::FencedTransitionV2(request) => {
                    fenced_transition_v2_outer_request_id(request.request_id())
                }
                _ => u128::from(index + 100).to_be_bytes(),
            }),
            logical_time: time(2),
            intent,
        }),
    }
}

fn acquire(storage: &mut NativeStorage, term: u64, index: u64) -> LeaseGuard {
    let key = request(1, None).lease().key().clone();
    let entry = command(
        storage,
        term,
        index,
        SessionMutationIntent::AcquireLease {
            key,
            owner: crate::OwnerId::new("async-boundary-owner").unwrap(),
            ttl: Duration::from_secs(60),
        },
    );
    let result = apply(storage, &[entry]);
    let Ok(SessionMutationOutcome::Lease(guard)) = &result.responses[0].result else {
        panic!("lease must succeed")
    };
    guard.clone()
}

fn recover(storage: &mut NativeStorage, index: u64) -> u64 {
    let term = Reservation::initial().ceiling() + 2;
    let entry = command(
        storage,
        term,
        index,
        SessionMutationIntent::AsyncRecoveryBoundary {
            protected: None,
            era: 2,
            plan: [0xB1; 32],
        },
    );
    let result = apply(storage, &[entry]);
    assert!(result.responses[0].result.is_ok());
    term
}

#[test]
fn native_async_boundary_retires_unexpired_credentials_and_absent_key_fences() {
    let mut storage = fixture();
    let old = acquire(&mut storage, 1, 1);
    let old_tail = storage.business.watch_sequence();
    let term = recover(&mut storage, 2);
    assert!(old.expires_at() > time(2));
    let floor = Reservation::initial().ceiling();
    let mut absent = old.key().clone();
    absent.stable_id = bytes::Bytes::from_static(b"absent-async-boundary-key")
        .try_into()
        .unwrap();
    assert_eq!(
        storage
            .business
            .observe_at(&absent, time(2))
            .unwrap()
            .current_fence()
            .get(),
        floor
    );
    for (index, intent) in [
        (3, SessionMutationIntent::DeleteFenced(old.clone())),
        (
            4,
            SessionMutationIntent::RenewLease {
                lease: old.clone(),
                ttl: Duration::from_secs(60),
            },
        ),
        (5, SessionMutationIntent::ReleaseLease(old.clone())),
    ] {
        let entry = command(&storage, term, index, intent);
        assert!(matches!(
            apply(&mut storage, &[entry]).responses[0].result,
            Err(StoreError::StaleFence)
        ));
    }
    let successor = acquire(&mut storage, term, 6);
    assert!(successor.fence().get() > floor && successor.credential_id() > floor);
    let stale = command(&storage, term, 7, SessionMutationIntent::ReleaseLease(old));
    assert!(matches!(
        apply(&mut storage, &[stale]).responses[0].result,
        Err(StoreError::StaleFence)
    ));
    let valid = command(
        &storage,
        term,
        8,
        SessionMutationIntent::ReleaseLease(successor),
    );
    assert!(apply(&mut storage, &[valid]).responses[0].result.is_ok());
    assert!(matches!(
        storage.business.replication_log(old_tail, 1, &|| Ok(())),
        Err(StoreError::ReplicationLogCursorCompacted { .. })
    ));
    assert!(storage
        .business
        .replication_log(floor + 1, 32, &|| Ok(()))
        .unwrap()
        .iter()
        .all(|entry| entry.sequence > floor));
    storage.validate_image().unwrap();
}

#[test]
fn native_async_boundary_invalidates_a_prepared_old_application() {
    let mut storage = fixture();
    let old = acquire(&mut storage, 1, 1);
    let entry = command(&storage, 1, 2, SessionMutationIntent::ReleaseLease(old));
    let prepared = storage
        .business
        .capture_application()
        .unwrap()
        .prepare(&[entry], &|| Ok(()), || Ok(()))
        .unwrap();
    recover(&mut storage, 2);
    assert!(!prepared.is_current(&storage.business).unwrap());
    let before = serde_json::to_vec(&storage.business.frontiers).unwrap();
    assert!(prepared.publish(&mut storage.business).is_err());
    assert_eq!(
        serde_json::to_vec(&storage.business.frontiers).unwrap(),
        before
    );
    storage.validate_image().unwrap();
}

#[test]
fn native_async_boundary_rejects_retained_ordinary_receipt_as_new_authority() {
    let mut storage = fixture();
    let old = acquire(&mut storage, 1, 1);
    let old_id = SessionConsensusRequestId::from_bytes(101u128.to_be_bytes());
    let term = recover(&mut storage, 2);
    {
        use crate::sqlite::consensus::consumer_receipts::ConsumerReceiptStore;
        let receipts = storage.business.consumer_receipts().unwrap();
        assert!(receipts
            .outcome(storage.business.identity, old_id)
            .unwrap()
            .is_none());
        assert!(receipts
            .occupied(storage.business.identity, old_id)
            .unwrap());
    }
    // Re-submit the exact old acquisition after retirement. It must not
    // replay its still-unexpired credential as a successful current result.
    let mut replay = command(
        &storage,
        term,
        3,
        SessionMutationIntent::AcquireLease {
            key: old.key().clone(),
            owner: old.owner().clone(),
            ttl: Duration::from_secs(60),
        },
    );
    let EntryPayload::Normal(ref mut command) = replay.payload else {
        unreachable!()
    };
    command.request_id = old_id;
    assert!(
        matches!(
            apply(&mut storage, &[replay]).responses[0].result,
            Err(StoreError::TopologyAuthorityRevoked)
        ),
        "retired receipt must never reissue old authority"
    );
    storage.validate_image().unwrap();
}

#[test]
fn native_async_boundary_retires_v1_receipt_without_clearing_its_binding() {
    let (mut storage, request, old) = v1::tests::fixture();
    let id = SessionConsensusRequestId::from_bytes(*request.request_id().as_bytes());
    let retained = serde_json::to_vec(&storage.business.generic_receipts[&id]).unwrap();
    let term = recover(&mut storage, 2);
    assert!(old.lease().expires_at() > time(2));
    assert!(matches!(
        storage.business.status_v1(&request).unwrap(),
        crate::FencedTransitionStatus::Expired
    ));
    let mut replay = v1::tests::command(3, &request, time(2), false);
    replay.log_id = log_id(term, 3);
    assert!(matches!(
        apply(&mut storage, &[replay]).responses[0].result,
        Err(StoreError::FencedTransitionRequestExpired)
    ));
    assert_eq!(
        serde_json::to_vec(&storage.business.generic_receipts[&id]).unwrap(),
        retained
    );
    storage.validate_image().unwrap();
}

#[test]
fn native_async_boundary_requires_successor_term_and_preserves_named_header() {
    let mut storage = fixture();
    let old = acquire(&mut storage, 1, 1);
    let invalid_entry = command(
        &storage,
        1,
        2,
        SessionMutationIntent::AsyncRecoveryBoundary {
            protected: None,
            era: 2,
            plan: [0xB1; 32],
        },
    );
    assert!(storage
        .business
        .capture_application()
        .unwrap()
        .prepare(&[invalid_entry], &|| Ok(()), || Ok(()))
        .is_err());
    let term = recover(&mut storage, 2);
    let encoded = serde_json::to_vec(&storage.business.frontiers).unwrap();
    let decoded: NativeFrontiers = serde_json::from_slice(&encoded).unwrap();
    assert!(decoded == storage.business.frontiers);
    assert!(postcard::to_stdvec(&decoded).is_err());
    assert!(storage
        .check_async_reservation(Reservation::initial(), &|| Ok(()))
        .is_err());
    storage
        .check_async_reservation(Reservation::recovery(2, [0xB1; 32]).unwrap(), &|| Ok(()))
        .unwrap();
    let duplicate = command(
        &storage,
        term,
        3,
        SessionMutationIntent::AsyncRecoveryBoundary {
            protected: None,
            era: 2,
            plan: [0xB1; 32],
        },
    );
    assert!(storage
        .business
        .capture_application()
        .unwrap()
        .prepare(&[duplicate], &|| Ok(()), || Ok(()))
        .is_err());
    assert!(
        storage
            .business
            .observe_at(old.key(), time(2))
            .unwrap()
            .current_fence()
            .get()
            > old.fence().get()
    );
}

#[test]
fn native_async_boundary_retires_v2_history_and_accepts_next_valid_operation() {
    use crate::fenced_transition::{
        FencedTransitionLease, FencedTransitionMutation, FencedTransitionV2CallerNonce,
        FencedTransitionV2HistoryEpoch,
    };
    let (mut storage, old_request, old_outcome) = changes::tests::fixture();
    storage.begin_changes().unwrap();
    let term = recover(&mut storage, 2);
    let history = storage.business.history_state().unwrap();
    let floor = Reservation::initial().ceiling();
    assert_eq!(history.active_epoch().unwrap().get(), floor + 1);
    assert_eq!(history.retired_through().unwrap().get(), floor);
    assert_eq!(history.reclaimed_entries(), 1);
    assert_eq!(history.bound_entries(), 0);
    assert!(matches!(
        storage.business.status(&old_request).unwrap(),
        FencedTransitionV2Status::Retired
    ));
    let old = command(
        &storage,
        term,
        3,
        SessionMutationIntent::FencedTransitionV2(Box::new(old_request)),
    );
    assert!(matches!(
        apply(&mut storage, &[old]).responses[0].result,
        Err(StoreError::FencedTransitionHistoryEpochRetired)
    ));
    let next = FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(floor + 1).unwrap(),
        FencedTransitionV2CallerNonce::from_bytes([0xB5; 16]),
        FencedTransitionLease::acquire(
            old_outcome.lease().key().clone(),
            old_outcome.lease().owner().clone(),
            crate::FenceToken::new(floor),
            Duration::from_secs(60),
        )
        .unwrap(),
        FencedTransitionMutation::delete(old_outcome.committed_generation()),
    )
    .unwrap();
    let entry = command(
        &storage,
        term,
        4,
        SessionMutationIntent::FencedTransitionV2(Box::new(next.clone())),
    );
    let applied = apply(&mut storage, &[entry]);
    let Ok(SessionMutationOutcome::FencedTransition(outcome)) = &applied.responses[0].result else {
        panic!("successor V2 operation must succeed");
    };
    assert!(outcome.lease().fence().get() > floor);
    let old = command(
        &storage,
        term,
        5,
        SessionMutationIntent::ReleaseLease(old_outcome.lease().clone()),
    );
    assert!(matches!(
        apply(&mut storage, &[old]).responses[0].result,
        Err(StoreError::StaleFence)
    ));
    storage
        .take_changes()
        .unwrap()
        .validate(&|| Ok(()))
        .unwrap();
    storage.validate_image().unwrap();
}

#[test]
fn native_async_boundary_coalesced_history_cannot_omit_transient_receipts() {
    let (mut storage, _, old) = changes::tests::fixture();
    storage.begin_changes().unwrap();
    let request = changes::tests::request(2, Some(&old));
    apply(
        &mut storage,
        &[changes::tests::command(2, &request, time(2), false)],
    );
    recover(&mut storage, 3);
    let captured = storage.take_changes().unwrap();
    captured.validate(&|| Ok(())).unwrap();
    assert_eq!(
        storage
            .business
            .history_state()
            .unwrap()
            .reclaimed_entries(),
        2
    );
    assert!(storage.business.receipts.is_empty());
    // Corrupt the cumulative retirement accounting independently of the
    // apply code. Neither a retained image nor a coalesced interval may hide
    // a missing receipt behind the skipped epoch range.
    let mut corrupt = storage.clone();
    corrupt
        .business
        .frontiers
        .async_recovery
        .as_mut()
        .unwrap()
        .history
        .skipped_bindings = [0; 16];
    assert!(corrupt.validate_image().is_err());
}

#[test]
fn native_async_boundary_watch_does_not_relabel_predecessor_effects() {
    let mut storage = fixture();
    acquire(&mut storage, 1, 1);
    assert_eq!(storage.business.watch_sequence(), 1);
    let term = recover(&mut storage, 2);
    let floor = Reservation::initial().ceiling();
    assert!(storage
        .business
        .replication_log(floor + 1, 32, &|| Ok(()))
        .unwrap()
        .is_empty());
    assert_eq!(storage.business.watch_sequence(), floor);
    acquire(&mut storage, term, 3);
    let page = storage
        .business
        .replication_log(floor + 1, 32, &|| Ok(()))
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].sequence, floor + 1);
    assert_eq!(storage.business.watch_sequence(), floor + 1);
}

#[test]
fn native_async_boundary_history_generation_exceeds_lost_range() {
    let (mut storage, _, _) = changes::tests::fixture();
    recover(&mut storage, 2);
    let floor = Reservation::initial().ceiling();
    assert!(storage.business.history_state().unwrap().generation() > floor);
    let mut inactive = fixture();
    recover(&mut inactive, 1);
    assert!(inactive.business.history_state().unwrap().generation() > floor);
}
