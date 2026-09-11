use super::*;
use crate::fenced_transition::{
    FencedTransitionV2HistoryEpoch, FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES,
    FENCED_TRANSITION_V2_RECLAIM_BATCH,
};

pub(crate) fn synthetic_id(epoch: u64, ordinal: u64) -> FencedTransitionV2RequestId {
    let mut bytes = [0; 56];
    bytes[..8].copy_from_slice(&epoch.to_be_bytes());
    bytes[48..].copy_from_slice(&ordinal.to_be_bytes());
    cold::receipt_id(bytes).unwrap()
}

// The same exact synthetic ordinal ranges used by the existing SQL lifecycle
// tests. This only constructs a fully audited starting fixture; production
// constants, command paths and admission checks are unchanged.
pub(crate) fn seed(
    storage: &mut NativeStorage,
    history: FencedTransitionV2HistoryState,
    now: Timestamp,
    response: Option<SessionConsensusResponse>,
    keep_first: bool,
) {
    let until = response.as_ref().map_or(now, |response| {
        retention_deadline(response.logical_time.unwrap()).unwrap()
    });
    let first = keep_first.then(|| {
        storage
            .business
            .receipts
            .iter()
            .next()
            .map(|(id, row)| (*id, row.clone()))
            .unwrap()
    });
    storage.business.receipts.clear();
    for range in lifecycle::ranges(Some(history)).unwrap() {
        for ordinal in range.first..range.first + range.count as u64 {
            let (id, row) = if ordinal == 1
                && first
                    .as_ref()
                    .is_some_and(|(id, _)| id.epoch().get() == range.epoch)
            {
                first.as_ref().unwrap().clone()
            } else {
                let id = synthetic_id(range.epoch, ordinal);
                let digest =
                    crate::sqlite::consensus::fenced_transition_v2_payload_digest_for_request_id(
                        storage.business.identity,
                        id.to_bytes(),
                    )
                    .unwrap();
                (
                    id,
                    SharedRow::new(NativeReceipt {
                        ordinal,
                        payload_digest: digest,
                        retained_until: until,
                        response: response.clone().map(Arc::new),
                        cold: None,
                    })
                    .unwrap(),
                )
            };
            storage.business.receipts.insert(id, row);
        }
    }
    storage.business.frontiers.history = Some(history);
    storage.business.frontiers.logical_time = Some(now);
    storage.business.admit_business().unwrap();
    storage.log.admit(&storage.business).unwrap();
    storage.validate_image().unwrap();
}

pub(crate) fn maintenance(
    storage: &NativeStorage,
    index: u64,
    now: Timestamp,
) -> Entry<SessionRaftTypeConfig> {
    let mut entry = changes::tests::clock(index, now);
    entry.log_id.leader_id = storage.business.applied().unwrap().leader_id;
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    let history = storage.business.history().unwrap();
    command.identity = storage.business.identity;
    command.intent = SessionMutationIntent::MaintainFencedTransitionV2History {
        expected_generation: history.generation(),
        expected_active_epoch: history.active_epoch(),
        expected_retired_through: lifecycle::floor(Some(history)),
        expected_bound_entries: history.bound_entries() as u64,
    };
    entry
}

#[test]
fn native_history_order_keeps_original_eight_epoch_bound_and_exact_reclaim_prefix() {
    let max = FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES;
    assert_eq!(max, 131_072);
    assert_eq!(FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES, 8 * max);
    assert_eq!(FENCED_TRANSITION_V2_RECLAIM_BATCH, 1_024);
    let epoch = |value| FencedTransitionV2HistoryEpoch::new(value).unwrap();
    let history =
        FencedTransitionV2HistoryState::new(Some(epoch(8)), None, None, 0, 7, max, 0).unwrap();
    let until = changes::tests::time(20);
    let mut order = history_order::ReceiptOrder::preparing(Some(history)).unwrap();
    for number in (1..=8).rev() {
        for ordinal in (1..=max as u64).rev() {
            order
                .insert_cold(synthetic_id(number, ordinal), ordinal, until)
                .unwrap();
        }
    }
    order.validate(Some(history)).unwrap();
    assert!(order.insert_cold(synthetic_id(8, 1), 1, until).is_err());
    assert!(
        order.append(synthetic_id(9, 1), 1, until).is_err(),
        "a ninth retained epoch is rejected"
    );
    assert!(
        order.remove_prefix(synthetic_id(1, 2), 2).is_err(),
        "cannot skip the reclaim cursor"
    );
    let retained = order.clone();
    for ordinal in 1..=FENCED_TRANSITION_V2_RECLAIM_BATCH as u64 {
        order
            .remove_prefix(synthetic_id(1, ordinal), ordinal)
            .unwrap();
    }
    let after = FencedTransitionV2HistoryState::new(
        Some(epoch(8)),
        Some(epoch(1)),
        Some(epoch(1)),
        max - FENCED_TRANSITION_V2_RECLAIM_BATCH,
        8,
        max,
        1_024,
    )
    .unwrap();
    order.validate(Some(after)).unwrap();
    retained.validate(Some(history)).unwrap();
    assert!(retained
        .validate_retirement(Some(history), Some(after), Some(changes::tests::time(19)))
        .is_err());
    retained
        .validate_retirement(Some(history), Some(after), Some(until))
        .unwrap();
    lifecycle::transition(Some(history), Some(after)).unwrap();
    lifecycle::conservation(Some(history), Some(after), 0, 1_024, 0).unwrap();
    assert!(lifecycle::conservation(Some(history), Some(after), 0, 1_023, 0).is_err());
    assert!(
        lifecycle::removed_is_retired(synthetic_id(1, 1_025), Some(1_025), Some(after)).is_err()
    );
    assert!(lifecycle::removed_is_retired(synthetic_id(2, 1), Some(1), Some(after)).is_err());
    let mut hole = history_order::ReceiptOrder::preparing(Some(after)).unwrap();
    assert!(hole
        .insert_cold(synthetic_id(1, 1_024), 1_024, until)
        .is_err());
    assert!(hole.validate(Some(after)).is_err());
}

#[test]
fn native_history_full_validator_rejects_ordinal_holes_and_retention_regressions() {
    let (mut storage, _, _) = changes::tests::fixture();
    let epoch = FencedTransitionV2HistoryEpoch::new(1).unwrap();
    let history = FencedTransitionV2HistoryState::new(Some(epoch), None, None, 0, 0, 3, 0).unwrap();
    seed(&mut storage, history, changes::tests::time(20), None, false);
    let valid = storage.business.clone();
    for case in 0..4 {
        storage.business = valid.clone();
        let id = synthetic_id(1, 2);
        let mut row = (**storage.business.receipts.get(&id).unwrap()).clone();
        match case {
            0 => row.ordinal = 1,
            1 => row.ordinal = 4,
            2 => row.retained_until = changes::tests::time(19),
            3 => row.payload_digest[0] ^= 1,
            _ => unreachable!(),
        }
        storage
            .business
            .receipts
            .insert(id, SharedRow::new(row).unwrap());
        assert!(
            storage.business.validate_full_business().is_err(),
            "complete validator rejects case {case}"
        );
    }
}

#[test]
fn native_history_signed_horizons_preserve_stale_cas_precedence_and_all_effects() {
    let epoch = |value| FencedTransitionV2HistoryEpoch::new(value).unwrap();
    for horizon in 0..4 {
        let (mut storage, _, _) = changes::tests::fixture();
        let history = match horizon {
            0 | 1 => FencedTransitionV2HistoryState::new(
                Some(epoch(1)),
                None,
                None,
                0,
                if horizon == 1 { COUNTER_MAX } else { 0 },
                0,
                0,
            )
            .unwrap(),
            2 => FencedTransitionV2HistoryState::new(
                Some(epoch(COUNTER_MAX)),
                Some(epoch(COUNTER_MAX - 1)),
                None,
                0,
                0,
                0,
                0,
            )
            .unwrap(),
            3 => FencedTransitionV2HistoryState::new(
                Some(epoch(2)),
                Some(epoch(1)),
                Some(epoch(1)),
                1,
                1,
                0,
                COUNTER_MAX,
            )
            .unwrap(),
            _ => unreachable!(),
        };
        seed(&mut storage, history, changes::tests::time(10), None, false);
        if horizon == 0 {
            storage.business.frontiers.sequence = COUNTER_MAX;
            storage.business.admit_business().unwrap();
            storage.log.admit(&storage.business).unwrap();
        }
        let sequence = storage.business.frontiers.sequence;
        let digest = storage.business.frontiers.digest;
        let receipts = storage.business.receipts.len();
        let mut stale = maintenance(&storage, 2, changes::tests::time(11));
        let EntryPayload::Normal(command) = &mut stale.payload else {
            unreachable!()
        };
        let SessionMutationIntent::MaintainFencedTransitionV2History {
            expected_bound_entries,
            ..
        } = &mut command.intent
        else {
            unreachable!()
        };
        *expected_bound_entries = 1;
        let response = changes::tests::apply(&mut storage, &[stale]);
        assert_eq!(
            response.responses[0].result,
            Err(StoreError::FencedTransitionHistoryEpochNotActive)
        );
        let entry = maintenance(&storage, 3, changes::tests::time(12));
        let response = changes::tests::apply(&mut storage, &[entry]);
        assert_eq!(
            response.responses[0].result,
            Err(StoreError::FencedTransitionStorageExhausted),
            "signed horizon {horizon}"
        );
        assert_eq!(response.responses[0].sequence, sequence);
        assert_eq!(response.responses[0].digest, Some(digest));
        assert_eq!(
            response.responses[0].logical_time,
            Some(changes::tests::time(12))
        );
        assert!(response.notifications.is_empty());
        assert_eq!(storage.business.receipts.len(), receipts);
        assert_eq!(storage.business.history(), Some(history));
        assert!(storage.business.generic_receipts.is_empty());
        assert_eq!(storage.business.notifications.len(), 1);
    }
}

#[test]
fn native_history_reclaim_omitted_changed_receipt_fails_before_atomic_publication() {
    let (mut storage, _, _) = changes::tests::fixture();
    let epoch = |value| FencedTransitionV2HistoryEpoch::new(value).unwrap();
    let remaining = FENCED_TRANSITION_V2_RECLAIM_BATCH + 1;
    let history = FencedTransitionV2HistoryState::new(
        Some(epoch(2)),
        Some(epoch(1)),
        Some(epoch(1)),
        remaining,
        1,
        0,
        (FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - remaining) as u64,
    )
    .unwrap();
    seed(&mut storage, history, changes::tests::time(10), None, false);
    let entry = maintenance(&storage, 2, changes::tests::time(11));
    let proof = storage.business.require_business_proof().unwrap().clone();
    let mut delta = storage
        .business
        .prepare(std::slice::from_ref(&entry))
        .unwrap();
    assert_eq!(
        delta.receipt_removals.len(),
        FENCED_TRANSITION_V2_RECLAIM_BATCH
    );
    let removed = *delta.receipt_removals.iter().next().unwrap();
    delta.receipt_removals.remove(&removed);
    assert!(changes::Publication::prepare(delta).is_err());
    assert!(std::sync::Arc::ptr_eq(
        &proof,
        storage.business.require_business_proof().unwrap()
    ));
    assert_eq!(storage.business.receipts.len(), remaining);
    assert_eq!(storage.business.history(), Some(history));
    changes::tests::apply(&mut storage, &[entry]);
    assert_eq!(storage.business.receipts.len(), 1);
}
