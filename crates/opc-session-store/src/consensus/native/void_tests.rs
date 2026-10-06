use super::*;
use crate::fenced_transition::{
    fenced_transition_v2_void_outer_request_id, FencedTransitionV2Profile,
};
use changes::tests::{apply, command, fixture, request, time};

fn extended_fixture() -> (NativeStorage, FencedTransitionV2Request) {
    let (original, _, outcome) = fixture();
    // Create an independent fixture under the extended profile. A production
    // store must select this profile before its first consensus initialization.
    let mut storage = original.clone();
    storage.business.frontiers.fenced_transition_profile = FencedTransitionV2Profile::V2WithVoid;
    storage
        .business
        .frontiers
        .activation
        .as_mut()
        .unwrap()
        .profile = FencedTransitionV2Profile::V2WithVoid.digest();
    storage.business.admit_business().unwrap();
    storage.log.admit(&storage.business).unwrap();
    (storage, request(2, Some(&outcome)))
}

fn void(index: u64, request: &FencedTransitionV2Request) -> Entry<SessionRaftTypeConfig> {
    let mut entry = command(index, request, time(2), false);
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!();
    };
    command.request_id = SessionConsensusRequestId::from_bytes(
        fenced_transition_v2_void_outer_request_id(request.request_id()),
    );
    command.intent = SessionMutationIntent::VoidFencedTransitionV2(Box::new(request.clone()));
    entry
}

#[test]
fn native_void_before_original_binds_one_receipt_without_a_session_or_watch_effect() {
    for same_batch in [false, true] {
        let (mut storage, request) = extended_fixture();
        let watch = storage.business.frontiers.watch_sequence;
        let restore = storage.business.frontiers.restore_revision;
        let original = command(3, &request, time(3), false);
        let results = if same_batch {
            apply(&mut storage, &[void(2, &request), original]).responses
        } else {
            let mut first = apply(&mut storage, &[void(2, &request)]).responses;
            first.extend(apply(&mut storage, &[original]).responses);
            first
        };
        for response in results {
            assert_eq!(response.result, Err(StoreError::FencedTransitionVoided));
            assert_eq!(
                response.raft_log_index, 2,
                "replay preserves the deciding receipt"
            );
        }
        assert_eq!(storage.business.frontiers.watch_sequence, watch);
        assert_eq!(storage.business.frontiers.restore_revision, restore);
        assert_eq!(storage.business.history().unwrap().bound_entries(), 2);
        assert_eq!(
            apply(&mut storage, &[void(4, &request)]).responses[0].result,
            Err(StoreError::FencedTransitionVoided)
        );
        assert_eq!(storage.business.history().unwrap().bound_entries(), 2);
    }
}

#[test]
fn native_original_before_void_replays_success_including_within_one_apply_batch() {
    for same_batch in [false, true] {
        let (mut storage, request) = extended_fixture();
        let original = command(2, &request, time(2), false);
        let results = if same_batch {
            apply(&mut storage, &[original, void(3, &request)]).responses
        } else {
            let mut first = apply(&mut storage, &[original]).responses;
            first.extend(apply(&mut storage, &[void(3, &request)]).responses);
            first
        };
        assert!(matches!(
            results[0].result,
            Ok(SessionMutationOutcome::FencedTransition(_))
        ));
        assert_eq!(results[0], results[1]);
        assert_eq!(storage.business.frontiers.watch_sequence, 2);
        assert_eq!(storage.business.history().unwrap().bound_entries(), 2);
    }
}

#[test]
fn native_base_profile_never_accepts_void_even_after_original_is_bound() {
    let (mut storage, request, _) = fixture();
    let before = serde_json::to_vec(&storage.business.frontiers).unwrap();
    assert!(storage.business.apply(&[void(2, &request)]).is_err());
    assert_eq!(
        serde_json::to_vec(&storage.business.frontiers).unwrap(),
        before
    );
}

#[test]
fn native_void_command_tags_are_appended_and_digest_domain_is_separate() {
    let (storage, request) = extended_fixture();
    let EntryPayload::Normal(void) = void(2, &request).payload else {
        unreachable!()
    };
    let EntryPayload::Normal(original) = command(2, &request, time(2), false).payload else {
        unreachable!()
    };
    assert_eq!(postcard::to_allocvec(&void.intent).unwrap()[0], 33);
    let activate = SessionMutationIntent::ActivateVoidFencedTransitionV2 {
        request: Box::new(request),
        scope_identity: storage.business.identity,
        voter_set_digest: fenced_transition_voter_set_digest(
            storage.business.identity,
            &storage.business.members,
        ),
        profile_digest: FencedTransitionV2Profile::V2WithVoid.digest(),
    };
    assert_eq!(postcard::to_allocvec(&activate).unwrap()[0], 34);
    assert_ne!(
        void.calculate_applied_digest(2, storage.business.frontiers.digest, time(2))
            .unwrap(),
        original
            .calculate_applied_digest(2, storage.business.frontiers.digest, time(2))
            .unwrap()
    );
}

#[test]
fn native_void_and_original_preserve_first_binding_across_epoch_rotation() {
    for void_first in [false, true] {
        let (mut storage, request) = extended_fixture();
        let epoch = crate::FencedTransitionV2HistoryEpoch::new(1).unwrap();
        let mut filler = storage
            .business
            .receipts
            .iter()
            .next()
            .unwrap()
            .1
            .response
            .as_deref()
            .unwrap()
            .clone();
        filler.result = Err(StoreError::StaleFence);
        lifecycle_tests::seed(
            &mut storage,
            FencedTransitionV2HistoryState::new(
                Some(epoch),
                None,
                None,
                0,
                0,
                FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - 1,
                0,
            )
            .unwrap(),
            time(1),
            Some(filler),
            true,
        );
        let deciding = if void_first {
            void(2, &request)
        } else {
            command(2, &request, time(2), false)
        };
        let receipt = apply(&mut storage, &[deciding]).responses.remove(0);
        let watch = storage.business.frontiers.watch_sequence;
        let rotation = lifecycle_tests::maintenance(&storage, 3, time(3));
        apply(&mut storage, &[rotation]);
        assert_eq!(
            storage
                .business
                .history()
                .unwrap()
                .active_epoch()
                .unwrap()
                .get(),
            2
        );
        let late = if void_first {
            command(4, &request, time(4), false)
        } else {
            void(4, &request)
        };
        assert_eq!(apply(&mut storage, &[late]).responses[0], receipt);
        assert_eq!(storage.business.frontiers.watch_sequence, watch);
        assert_eq!(storage.business.history().unwrap().bound_entries(), 0);
    }
}

#[test]
fn native_void_and_original_cannot_bind_an_unbound_request_after_its_epoch_closes() {
    for void_first in [false, true] {
        let (mut storage, request) = extended_fixture();
        let epoch = crate::FencedTransitionV2HistoryEpoch::new(1).unwrap();
        let mut filler = storage
            .business
            .receipts
            .iter()
            .next()
            .unwrap()
            .1
            .response
            .as_deref()
            .unwrap()
            .clone();
        filler.result = Err(StoreError::StaleFence);
        lifecycle_tests::seed(
            &mut storage,
            FencedTransitionV2HistoryState::new(
                Some(epoch),
                None,
                None,
                0,
                0,
                FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
                0,
            )
            .unwrap(),
            time(1),
            Some(filler),
            true,
        );
        let rotation = lifecycle_tests::maintenance(&storage, 2, time(2));
        apply(&mut storage, &[rotation]);
        let entries = if void_first {
            [void(3, &request), command(4, &request, time(4), false)]
        } else {
            [command(3, &request, time(3), false), void(4, &request)]
        };
        for result in apply(&mut storage, &entries).responses {
            assert_eq!(
                result.result,
                Err(StoreError::FencedTransitionHistoryEpochNotActive)
            );
        }
        assert_eq!(storage.business.frontiers.watch_sequence, 1);
        assert_eq!(storage.business.history().unwrap().bound_entries(), 0);
    }
}

#[test]
fn native_void_obeys_original_authority_before_binding_and_fence_checks() {
    let (mut storage, request) = extended_fixture();
    let mut unauthorized = void(2, &request);
    let EntryPayload::Normal(command) = &mut unauthorized.payload else {
        unreachable!()
    };
    command.intent = SessionMutationIntent::Authorized {
        origin: SessionConsensusNodeId::new(999).unwrap(),
        authority_identity: storage.business.identity,
        mutation: Box::new(command.intent.clone()),
    };
    let response = apply(&mut storage, &[unauthorized]).responses.remove(0);
    assert_eq!(response.result, Err(StoreError::TopologyAuthorityRevoked));
    assert!(!storage
        .business
        .receipts
        .contains_key(&request.request_id()));
    let mut stale = void(3, &request);
    let EntryPayload::Normal(command) = &mut stale.payload else {
        unreachable!()
    };
    command.logical_time = "2026-07-12T00:01:02Z".parse().unwrap();
    assert!(matches!(
        apply(&mut storage, &[stale]).responses[0].result,
        Err(StoreError::LeaseExpired)
    ));
    assert_eq!(storage.business.frontiers.watch_sequence, 1);
    assert!(storage
        .business
        .receipts
        .contains_key(&request.request_id()));
}

#[test]
fn native_void_prevents_late_batched_original_under_the_authorized_envelope() {
    let (mut storage, request) = extended_fixture();
    let mut entry = void(2, &request);
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.intent = SessionMutationIntent::Authorized {
        origin: *storage.business.members.iter().next().unwrap(),
        authority_identity: storage.business.identity,
        mutation: Box::new(command.intent.clone()),
    };
    assert_eq!(
        apply(&mut storage, &[entry]).responses[0].result,
        Err(StoreError::FencedTransitionVoided)
    );
    let mut late = changes::tests::command(3, &request, time(3), false);
    let EntryPayload::Normal(command) = &mut late.payload else {
        unreachable!()
    };
    command.request_id = SessionConsensusRequestId::from_bytes(
        crate::consensus::types::fenced_transition_v2_batch_outer_request_id(std::slice::from_ref(
            &request,
        ))
        .unwrap(),
    );
    command.intent = SessionMutationIntent::FencedTransitionV2Batch(vec![request]);
    assert_eq!(
        apply(&mut storage, &[late]).responses[0].result,
        Ok(SessionMutationOutcome::FencedTransitionV2Batch(vec![Err(
            StoreError::FencedTransitionVoided
        )]))
    );
    assert_eq!(storage.business.frontiers.watch_sequence, 1);
    assert_eq!(storage.business.history().unwrap().bound_entries(), 2);
}
