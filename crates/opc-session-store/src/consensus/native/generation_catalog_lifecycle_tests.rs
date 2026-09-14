use super::*;
use crate::consensus::native::lifecycle_tests::{maintenance, seed, synthetic_id};
use crate::fenced_transition::{
    FencedTransitionV2HistoryEpoch, FENCED_TRANSITION_V2_RECLAIM_BATCH,
};

#[test]
fn native_history_reclaim_checkpoint_reopens_exact_cursor_and_mixed_atomic_successor_binding() {
    let (mut storage, original, _) = fixture();
    let epoch = |number| FencedTransitionV2HistoryEpoch::new(number).unwrap();
    let remaining = 2 * FENCED_TRANSITION_V2_RECLAIM_BATCH + 1;
    let max = FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES;
    let history = FencedTransitionV2HistoryState::new(
        Some(epoch(2)),
        Some(epoch(1)),
        Some(epoch(1)),
        remaining,
        1,
        0,
        (max - remaining) as u64,
    )
    .unwrap();
    let response = storage
        .business
        .receipts
        .values()
        .next()
        .unwrap()
        .response
        .as_deref()
        .unwrap()
        .clone();
    let expiry = retention_deadline(response.logical_time.unwrap()).unwrap();
    seed(&mut storage, history, expiry, Some(response), false);
    let (mut files, catalog) = Files::new(&storage);
    let mut cold = catalog.into_storage(&|| Ok(())).unwrap();
    assert!(cold
        .business
        .receipts
        .values()
        .all(|row| row.cold_range().is_some()));
    storage.begin_changes().unwrap();
    cold.begin_changes().unwrap();
    let one = maintenance(&storage, 2, time(11));
    let actual = apply(&mut storage, std::slice::from_ref(&one));
    let cold_actual = apply(&mut cold, &[one]);
    assert_eq!(actual.responses, cold_actual.responses);
    assert!(actual.notifications.is_empty());
    assert_eq!(
        storage.business.receipts.len(),
        remaining - FENCED_TRANSITION_V2_RECLAIM_BATCH
    );
    let catalog = files.append(&mut storage, 21);
    assert_eq!(
        catalog.rows.receipts.len(),
        remaining - FENCED_TRANSITION_V2_RECLAIM_BATCH
    );
    drop(cold);
    cold = catalog.into_storage(&|| Ok(())).unwrap();
    assert_eq!(
        cold.business.history_state().unwrap().reclaim_remaining(),
        1_025
    );

    // A new request in the active epoch and deletion in the oldest epoch
    // share one atomic publication and one captured checkpoint.
    let successor = FencedTransitionV2Request::new(
        epoch(2),
        crate::FencedTransitionV2CallerNonce::from_bytes([0xF1; 16]),
        original.lease().clone(),
        original.mutation().clone(),
    )
    .unwrap();
    let bind = command(3, &successor, time(12), false);
    let mut two = maintenance(&storage, 4, time(13));
    let EntryPayload::Normal(value) = &mut two.payload else {
        unreachable!()
    };
    let SessionMutationIntent::MaintainFencedTransitionV2History {
        expected_bound_entries,
        ..
    } = &mut value.intent
    else {
        unreachable!()
    };
    *expected_bound_entries = 1;
    let actual = apply(&mut storage, &[bind.clone(), two.clone()]);
    let cold_actual = apply(&mut cold, &[bind, two]);
    assert_eq!(actual.responses, cold_actual.responses);
    let catalog = files.append(&mut storage, 24);
    assert_eq!(catalog.rows.receipts.len(), 2);
    assert_eq!(
        catalog.rows.receipts[&synthetic_id(1, max as u64)]
            .row
            .facts
            .ordinal,
        max as u64
    );
    assert_eq!(
        catalog.rows.receipts[&successor.request_id()]
            .row
            .facts
            .ordinal,
        1
    );
    drop(cold);
    cold = catalog.into_storage(&|| Ok(())).unwrap();
    let three = maintenance(&storage, 5, time(14));
    apply(&mut storage, std::slice::from_ref(&three));
    apply(&mut cold, &[three]);
    let catalog = files.append(&mut storage, 27);
    assert_eq!(catalog.rows.receipts.len(), 1);
    let current = cold.business.history_state().unwrap();
    assert_eq!(current.reclaim_epoch(), None);
    assert_eq!(current.reclaim_remaining(), 0);
    assert_eq!(current.reclaimed_entries(), max as u64);
    assert_eq!(current.bound_entries(), 1);
    assert_eq!(current.active_epoch(), Some(epoch(2)));
    assert!(
        cold.business.generic_receipts.is_empty(),
        "maintenance never enters the generic receipt ledger"
    );
    catalog
        .into_storage(&|| Ok(()))
        .unwrap()
        .validate_image()
        .unwrap();
}
