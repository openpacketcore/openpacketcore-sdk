use super::*;
use crate::{
    FencedTransitionLease, FencedTransitionMutation, FencedTransitionV2CallerNonce,
    FencedTransitionV2HistoryEpoch, OwnerId,
};
use changes::tests::{apply, command, fixture_with_profile, time, void_command};
use std::time::Duration;

fn at(seconds: u64) -> Timestamp {
    Timestamp::from_offset_datetime(*time(0).as_offset_datetime() + Duration::from_secs(seconds))
}

fn successor(prior: &FencedTransitionOutcome) -> FencedTransitionV2Request {
    FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(1).unwrap(),
        FencedTransitionV2CallerNonce::from_bytes([0xD3; 16]),
        FencedTransitionLease::acquire(
            prior.lease().key().clone(),
            OwnerId::new("synthetic-deferred-owner").unwrap(),
            prior.lease().fence(),
            Duration::from_secs(60),
        )
        .unwrap(),
        FencedTransitionMutation::delete(prior.committed_generation()),
    )
    .unwrap()
}

pub(in crate::consensus::native) fn pending_fixture() -> (NativeStorage, FencedTransitionV2Request)
{
    let (mut storage, _, prior) =
        fixture_with_profile(FencedTransitionV2Profile::V2WithLeaseDeferral);
    let pending = successor(&prior);
    let response = apply(&mut storage, &[command(2, &pending, time(2), false)])
        .responses
        .remove(0);
    assert_eq!(
        response.result,
        Err(StoreError::FencedTransitionLeaseDeferred)
    );
    (storage, pending)
}

#[test]
fn native_lease_deferral_status_boundary_is_profile_specific_before_and_after_activation() {
    let marker = crate::fenced_transition::fenced_transition_v2_deferral_retention().unwrap();
    let boundary = Timestamp::from_offset_datetime(
        *marker.as_offset_datetime() - FENCED_TRANSITION_OUTCOME_RETENTION,
    );
    let before =
        Timestamp::from_offset_datetime(*boundary.as_offset_datetime() - Duration::from_secs(1));
    for profile in [
        FencedTransitionV2Profile::V2,
        FencedTransitionV2Profile::V2WithVoid,
        FencedTransitionV2Profile::V2WithLeaseDeferral,
    ] {
        let (mut active, original, _) = fixture_with_profile(profile);
        let mut inactive = NativeStorage::empty_with_roster_root_and_profile(
            active.business.identity,
            active.business.members.clone(),
            None,
            profile,
        )
        .unwrap();
        assert!(inactive.business.frontiers.history.is_none());
        assert_eq!(active.business.history().unwrap().bound_entries(), 1);
        let fresh = FencedTransitionV2Request::new(
            original.request_id().epoch(),
            FencedTransitionV2CallerNonce::from_bytes([0xD8; 16]),
            original.lease().clone(),
            original.mutation().clone(),
        )
        .unwrap();
        for storage in [&mut inactive, &mut active] {
            storage.business.frontiers.logical_time = Some(before);
            assert_eq!(
                storage.business.status(&fresh).unwrap(),
                FencedTransitionV2Status::NotFound
            );
            storage.business.frontiers.logical_time = Some(boundary);
            assert_eq!(
                storage.business.status(&fresh).unwrap(),
                if profile.defers_live_leases() {
                    FencedTransitionV2Status::RetentionExhausted
                } else {
                    FencedTransitionV2Status::NotFound
                }
            );
        }
    }
}

#[test]
fn native_lease_deferral_reserved_retention_boundary_preserves_pending_and_reports_exhaustion() {
    let (mut storage, pending) = pending_fixture();
    let fresh = FencedTransitionV2Request::new(
        pending.request_id().epoch(),
        FencedTransitionV2CallerNonce::from_bytes([0xD4; 16]),
        pending.lease().clone(),
        pending.mutation().clone(),
    )
    .unwrap();
    let marker = crate::fenced_transition::fenced_transition_v2_deferral_retention().unwrap();
    let now = Timestamp::from_offset_datetime(
        *marker.as_offset_datetime() - FENCED_TRANSITION_OUTCOME_RETENTION,
    );
    assert_eq!(retention_deadline(now), Some(marker));
    let sequence = storage.business.frontiers.sequence;
    let watch = storage.business.frontiers.watch_sequence;
    let response = apply(&mut storage, &[command(3, &pending, now, false)])
        .responses
        .remove(0);
    assert_eq!(
        response.result,
        Err(StoreError::FencedTransitionOutcomeUnknown)
    );
    let rejected = apply(&mut storage, &[command(4, &fresh, now, false)])
        .responses
        .remove(0);
    assert_eq!(
        rejected.result,
        Err(StoreError::FencedTransitionRetentionExhausted)
    );
    assert_eq!(storage.business.frontiers.sequence, sequence);
    assert_eq!(storage.business.frontiers.watch_sequence, watch);
    assert_eq!(storage.business.history().unwrap().bound_entries(), 2);
    assert_eq!(
        storage
            .business
            .get(pending.lease().key())
            .unwrap()
            .generation,
        crate::Generation::new(1)
    );
    assert_eq!(
        storage.business.status(&pending).unwrap(),
        FencedTransitionV2Status::LeaseDeferred {
            request_id: pending.request_id()
        }
    );
    assert_eq!(
        storage.business.status(&fresh).unwrap(),
        FencedTransitionV2Status::RetentionExhausted
    );
}

#[test]
fn native_lease_deferral_sequence_exhaustion_resolves_once_without_a_business_effect() {
    let (mut storage, pending) = pending_fixture();
    storage.business.frontiers.sequence = COUNTER_MAX;
    storage.business.admit_business().unwrap();
    storage.log.admit(&storage.business).unwrap();
    let watch = storage.business.frontiers.watch_sequence;
    assert_eq!(
        apply(&mut storage, &[command(3, &pending, time(3), false)]).responses[0].result,
        Err(StoreError::FencedTransitionLeaseDeferred)
    );
    let terminal = apply(&mut storage, &[command(4, &pending, at(80), false)])
        .responses
        .remove(0);
    assert_eq!(
        terminal.result,
        Err(StoreError::FencedTransitionStorageExhausted)
    );
    assert_eq!(storage.business.frontiers.sequence, COUNTER_MAX);
    assert_eq!(storage.business.frontiers.watch_sequence, watch);
    assert_eq!(storage.business.history().unwrap().bound_entries(), 2);
    assert_eq!(
        storage
            .business
            .get(pending.lease().key())
            .unwrap()
            .generation,
        crate::Generation::new(1)
    );
    let row = &storage.business.receipts[&pending.request_id()];
    assert_eq!(row.ordinal, 2);
    assert_eq!(row.retained_until, retention_deadline(at(80)).unwrap());
    assert!(!row.lease_deferred());
    assert_eq!(
        apply(&mut storage, &[command(5, &pending, at(81), false)]).responses[0],
        terminal
    );
}

#[test]
fn native_lease_deferral_retries_and_image_restart_keep_one_ordinal_then_resolve_once() {
    let (mut storage, pending) = pending_fixture();
    let sequence = storage.business.frontiers.sequence;
    let ordinal = storage
        .business
        .receipts
        .get(&pending.request_id())
        .unwrap()
        .ordinal;
    let watch = storage.business.frontiers.watch_sequence;
    for index in 3..19 {
        let response = apply(&mut storage, &[command(index, &pending, time(3), false)])
            .responses
            .remove(0);
        assert_eq!(
            response.result,
            Err(StoreError::FencedTransitionLeaseDeferred)
        );
        assert_eq!(storage.business.frontiers.sequence, sequence);
        assert_eq!(storage.business.frontiers.watch_sequence, watch);
        assert_eq!(storage.business.history().unwrap().bound_entries(), 2);
        assert_eq!(
            storage
                .business
                .receipts
                .get(&pending.request_id())
                .unwrap()
                .ordinal,
            ordinal
        );
    }
    let mut bytes = Vec::new();
    storage.write_image(&mut bytes, [0xB4; 32], 18).unwrap();
    let mut restarted = NativeStorage::read_image(
        &mut bytes.as_slice(),
        [0xB4; 32],
        18,
        storage.business.identity,
    )
    .unwrap();
    assert_eq!(
        restarted.business.status(&pending).unwrap(),
        FencedTransitionV2Status::LeaseDeferred {
            request_id: pending.request_id()
        }
    );
    let completed = apply(&mut restarted, &[command(19, &pending, at(80), false)])
        .responses
        .remove(0);
    assert!(matches!(
        completed.result,
        Ok(SessionMutationOutcome::FencedTransition(_))
    ));
    assert_eq!(restarted.business.history().unwrap().bound_entries(), 2);
    assert_eq!(restarted.business.frontiers.watch_sequence, watch + 1);
    assert!(restarted.business.get(pending.lease().key()).is_none());
    let replay = apply(&mut restarted, &[command(20, &pending, at(81), false)])
        .responses
        .remove(0);
    assert_eq!(replay, completed);
    assert_eq!(restarted.business.frontiers.watch_sequence, watch + 1);
    let receipt = restarted
        .business
        .receipts
        .get(&pending.request_id())
        .unwrap();
    assert_eq!(receipt.ordinal, ordinal);
    assert!(!receipt.lease_deferred());
    assert_eq!(receipt.retained_until, retention_deadline(at(80)).unwrap());
}

#[test]
fn native_lease_deferral_void_resolves_pending_without_a_business_effect() {
    for now in [time(3), at(80)] {
        let (mut storage, pending) = pending_fixture();
        let watch = storage.business.frontiers.watch_sequence;
        let response = apply(&mut storage, &[void_command(3, &pending, now, false)])
            .responses
            .remove(0);
        assert_eq!(
            response.result,
            Err(if now == time(3) {
                StoreError::LeaseHeld
            } else {
                StoreError::FencedTransitionVoided
            })
        );
        assert_eq!(storage.business.frontiers.watch_sequence, watch);
        assert!(storage.business.get(pending.lease().key()).is_some());
        assert_eq!(storage.business.history().unwrap().bound_entries(), 2);
        assert!(matches!(
            storage.business.status(&pending).unwrap(),
            FencedTransitionV2Status::Recorded(_)
        ));
        assert!(!storage
            .business
            .receipts
            .get(&pending.request_id())
            .unwrap()
            .lease_deferred());
        assert_eq!(
            apply(&mut storage, &[command(4, &pending, now, false)]).responses[0],
            response
        );
    }
}

#[test]
fn native_lease_deferral_preserves_the_original_profiles_terminal_contention() {
    for profile in [
        FencedTransitionV2Profile::V2,
        FencedTransitionV2Profile::V2WithVoid,
    ] {
        let (mut storage, _, prior) = fixture_with_profile(profile);
        let request = successor(&prior);
        let first = apply(&mut storage, &[command(2, &request, time(2), false)])
            .responses
            .remove(0);
        assert_eq!(first.result, Err(StoreError::LeaseHeld));
        assert_eq!(
            apply(&mut storage, &[command(3, &request, at(80), false)]).responses[0],
            first
        );
        assert!(matches!(storage.business.status(&request).unwrap(),
            FencedTransitionV2Status::Recorded(result) if matches!(*result, Err(StoreError::LeaseHeld))));
    }
}

#[test]
fn native_lease_deferral_pins_a_full_closed_epoch_and_completion_restores_retirement() {
    let (mut storage, pending) = pending_fixture();
    let mut row = (**storage
        .business
        .receipts
        .get(&pending.request_id())
        .unwrap())
    .clone();
    row.ordinal = 1;
    storage.business.receipts.clear();
    storage
        .business
        .receipts
        .insert(pending.request_id(), SharedRow::new(row).unwrap());
    let history = FencedTransitionV2HistoryState::new(
        Some(FencedTransitionV2HistoryEpoch::new(8).unwrap()),
        None,
        None,
        0,
        7,
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
        0,
    )
    .unwrap();
    lifecycle_tests::seed(&mut storage, history, at(100_000), None, true);
    let mut horizon = storage.clone();
    let maximum = crate::fenced_transition::fenced_transition_v2_deferral_retention().unwrap();
    let entry = lifecycle_tests::maintenance(&horizon, 3, maximum);
    apply(&mut horizon, &[entry]);
    assert_eq!(horizon.business.history().unwrap().retired_through(), None);
    assert_eq!(
        horizon.business.status(&pending).unwrap(),
        FencedTransitionV2Status::LeaseDeferred {
            request_id: pending.request_id()
        }
    );
    assert_eq!(
        apply(&mut horizon, &[command(4, &pending, maximum, false)]).responses[0].result,
        Err(StoreError::FencedTransitionOutcomeUnknown)
    );
    assert!(horizon
        .business
        .receipts
        .get(&pending.request_id())
        .unwrap()
        .retained());
    drop(horizon);
    let completed = apply(&mut storage, &[command(3, &pending, at(100_001), false)])
        .responses
        .remove(0);
    assert!(matches!(
        completed.result,
        Ok(SessionMutationOutcome::FencedTransition(_))
    ));
    assert_eq!(
        storage.business.history().unwrap().bound_entries(),
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES
    );
    let before_retention = lifecycle_tests::maintenance(&storage, 4, at(100_002));
    apply(&mut storage, &[before_retention]);
    assert_eq!(storage.business.history().unwrap().retired_through(), None);
    let retire =
        lifecycle_tests::maintenance(&storage, 5, retention_deadline(at(100_001)).unwrap());
    apply(&mut storage, &[retire]);
    assert_eq!(
        storage.business.history().unwrap().retired_through(),
        Some(FencedTransitionV2HistoryEpoch::new(1).unwrap())
    );
    assert_eq!(
        storage.business.history().unwrap().reclaimed_entries(),
        crate::fenced_transition::FENCED_TRANSITION_V2_RECLAIM_BATCH as u64
    );
    assert_eq!(
        storage.business.status(&pending).unwrap(),
        FencedTransitionV2Status::Retired
    );
}
