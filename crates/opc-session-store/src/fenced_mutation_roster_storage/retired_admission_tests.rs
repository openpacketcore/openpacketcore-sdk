// Inspect the durable serialization through the existing codec so these REDs
// compile before the witness field exists. No production accessor or fallback
// value is introduced: an absent field remains None and fails the contract.
pub(crate) fn retired_admission_witness_fence_for_test(
    witness: GlobalChargeWitness,
) -> Option<u64> {
    let bytes = witness.to_canonical_bytes().unwrap();
    let reopened = GlobalChargeWitness::from_canonical_bytes(&bytes).unwrap();
    assert_eq!(reopened.to_canonical_bytes().unwrap(), bytes);
    serde_json::to_value(reopened).unwrap()["highest_retired_admission_fence"].as_u64()
}

#[test]
fn retired_admission_witness_codec_rejects_old_missing_and_inconsistent_state() {
    let initial = GlobalChargeWitness::empty();
    assert_eq!(retired_admission_witness_fence_for_test(initial), Some(0));
    for version in [
        GLOBAL_CHARGE_WITNESS_V1,
        GLOBAL_CHARGE_WITNESS_V2,
        GLOBAL_CHARGE_WITNESS_VERSION + 1,
    ] {
        let unsupported = GlobalChargeWitness { version, ..initial };
        assert!(matches!(
            GlobalChargeWitness::from_canonical_bytes(&unsupported.to_canonical_bytes().unwrap()),
            Err(ReservationError::UnknownWitnessVersion)
        ));
    }
    let mut missing = initial.to_canonical_bytes().unwrap();
    missing.pop();
    assert!(GlobalChargeWitness::from_canonical_bytes(&missing).is_err());
    let inconsistent = GlobalChargeWitness {
        retired_terminal_sequence: 1,
        ..initial
    };
    assert!(
        GlobalChargeWitness::from_canonical_bytes(&inconsistent.to_canonical_bytes().unwrap())
            .is_err()
    );
}

fn retired_admission_v1(identity: u16, fence: u64) -> Admission {
    admission_for_authority(
        "tenant",
        identity,
        OwnerId::new("owner").unwrap(),
        FenceToken::new(fence),
        Generation::new(1),
    )
}

fn retired_admission_ordering(streamed: bool, fences: &[u64], batch: usize) {
    let profile = profile();
    let records = fences
        .iter()
        .enumerate()
        .map(|(index, fence)| {
            compact_v1_terminal(
                &retired_admission_v1(200 + u16::try_from(index).unwrap(), *fence),
                1,
                profile,
            )
        })
        .collect::<Vec<_>>();
    let floor = IrreversibleHistoryFloor::initial(records[0].binding()).unwrap();
    let counters = records.iter().fold(zero_counters(), |counters, record| {
        counters_with_production_record(counters, record, profile).unwrap()
    });
    let mut witness = GlobalChargeWitness::v1(
        0,
        0,
        counters_with_production_floor(counters, floor).unwrap(),
    );
    let mut observed = Vec::new();
    let mut expected = Vec::new();
    let mut maximum = 0;
    let mut removed = 0;
    for page in records.chunks(batch) {
        removed += page.len();
        let final_page = removed == records.len();
        let partition = ProductionMixedTerminalRetirementPartition::new_with_partition_empty_after(
            floor, None, 1, final_page, final_page,
        )
        .unwrap();
        if streamed {
            let mut stream = ProductionMixedTerminalRetirementStream::new(
                witness,
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            )
            .unwrap();
            for record in page {
                let edit = stream
                    .push(ProductionMixedTerminalRetirementSelection::V1(record))
                    .unwrap();
                assert!(edit.v1_delete().is_some());
            }
            let closure = stream.finish(&[partition]).unwrap();
            witness = closure.next;
            assert_eq!(
                closure.floor_actions[0].floor().replacement().is_none(),
                final_page
            );
        } else {
            let selected = page
                .iter()
                .map(ProductionMixedTerminalRetirementSelection::V1)
                .collect::<Vec<_>>();
            let transaction = prepare_production_mixed_terminal_retirement(
                &selected,
                &[partition],
                witness,
                GlobalChargeBudget::v1(u64::MAX),
                profile,
            )
            .unwrap();
            assert_eq!(transaction.rows().len(), page.len());
            assert!(transaction
                .rows()
                .iter()
                .all(|row| row.v1_delete().is_some()));
            assert_eq!(
                transaction.floor_actions()[0]
                    .floor()
                    .replacement()
                    .is_none(),
                final_page
            );
            witness = transaction.next_witness();
        }
        assert_eq!(
            witness.roster.durable_epoch_bindings(),
            records.len() - removed
        );
        assert_eq!(
            witness.retired_terminal_sequence(),
            page.last().unwrap().terminal_sequence().unwrap()
        );
        maximum = maximum.max(*fences[removed - page.len()..removed].iter().max().unwrap());
        expected.push(Some(maximum));
        observed.push(retired_admission_witness_fence_for_test(witness));
    }
    assert_eq!(witness.roster.floor_count(), 0);
    assert_eq!(observed, expected, "each deletion page must persist the maximum ORIGINAL fence, even when later terminal sequences retire lower fences");
}

#[test]
fn retired_admission_witness_stream_preserves_maximum_across_out_of_order_fences() {
    retired_admission_ordering(true, &[27, 3, 27], 1);
}

#[test]
fn retired_admission_witness_vector_preserves_maximum_across_out_of_order_fences() {
    retired_admission_ordering(false, &[27, 3, 27], 1);
}

#[test]
fn retired_admission_witness_survives_full_batch_then_last_floor_deletion() {
    let mut fences = vec![3; RECLAIM_BATCH + 1];
    fences[0] = 91;
    retired_admission_ordering(true, &fences, RECLAIM_BATCH);
}

#[test]
fn retired_admission_witness_mixed_v1_v2_counts_both_deletion_profiles() {
    let profile = profile();
    let v1 = compact_v1_terminal(
        &admission_for_authority_in_scope(
            "tenant",
            146,
            OwnerId::new("owner").unwrap(),
            FenceToken::new(29),
            Generation::new(1),
            [10; 32],
        ),
        1,
        profile,
    );
    let v2 = compact_v2_terminal(&absent_predecessor_admission(147), profile);
    let floor = IrreversibleHistoryFloor::initial(v1.binding()).unwrap();
    assert_eq!(
        ProductionFloorKey::from_binding(v2.binding()).unwrap(),
        ProductionFloorKey::from_floor(floor).unwrap()
    );
    let counters = counters_with_production_floor(
        counters_with_production_record_v2(
            counters_with_production_record(zero_counters(), &v1, profile).unwrap(),
            &v2,
            profile,
        )
        .unwrap(),
        floor,
    )
    .unwrap();
    let witness = GlobalChargeWitness::v1(0, 0, counters);
    let partial = ProductionMixedTerminalRetirementPartition::new_with_partition_empty_after(
        floor, None, 1, false, false,
    )
    .unwrap();
    let first = prepare_production_mixed_terminal_retirement(
        &[ProductionMixedTerminalRetirementSelection::V2(&v2)],
        &[partial],
        witness,
        GlobalChargeBudget::v1(u64::MAX),
        profile,
    )
    .unwrap();
    assert!(first.rows()[0].v2_delete().is_some());
    assert_eq!(first.next_witness().roster.durable_epoch_bindings(), 1);
    let last = ProductionMixedTerminalRetirementPartition::new_with_partition_empty_after(
        floor, None, 1, true, true,
    )
    .unwrap();
    let second = prepare_production_mixed_terminal_retirement(
        &[ProductionMixedTerminalRetirementSelection::V1(&v1)],
        &[last],
        first.next_witness(),
        GlobalChargeBudget::v1(u64::MAX),
        profile,
    )
    .unwrap();
    assert!(second.rows()[0].v1_delete().is_some());
    assert_eq!(second.next_witness().roster.durable_epoch_bindings(), 0);
    assert_eq!(second.next_witness().roster.floor_count(), 0);
    assert_eq!(
        [
            retired_admission_witness_fence_for_test(first.next_witness()),
            retired_admission_witness_fence_for_test(second.next_witness())
        ],
        [Some(1), Some(29)],
        "V2 and V1 removals must contribute their original fences to the same witness",
    );
}

#[test]
fn retired_admission_witness_partition_planner_and_adapter_preserve_original_fence() {
    let profile = profile();
    let record = compact_v1_terminal(&retired_admission_v1(143, 17), 7, profile);
    let previous = IrreversibleHistoryFloor::initial(record.binding()).unwrap();
    let next = previous.advance_to(7).unwrap();
    let witness = GlobalChargeWitness::v1(
        0,
        0,
        counters_with_production_floor(
            validate_production_snapshot(std::slice::from_ref(&record), profile).unwrap(),
            previous,
        )
        .unwrap(),
    );
    let selected = vec![(record.binding(), record.clone())];
    let prepared = prepare_production_retirement(
        ProductionRetirementPrefix::new(previous, next, &selected, true, true).unwrap(),
        previous,
        next,
        None,
        witness,
        GlobalChargeBudget::v1(u64::MAX),
        profile,
    )
    .unwrap();
    let planned = retired_admission_witness_fence_for_test(prepared.next_witness());
    let mut store = InMemoryProductionStore {
        rows: BTreeMap::from([(record.binding(), record)]),
        witness,
        floors: BTreeMap::from([(ProductionFloorKey::from_floor(previous).unwrap(), previous)]),
        retirement_cursors: BTreeMap::new(),
        business: None,
        business_reservation: None,
        fail_at: None,
    };
    store.compare_and_apply_production(prepared).unwrap();
    assert!(store.rows.is_empty() && store.floors.is_empty());
    assert_eq!(store.witness.roster.durable_epoch_bindings(), 0);
    assert_eq!(
        [planned, retired_admission_witness_fence_for_test(store.witness)],
        [Some(17), Some(17)],
        "the alternate partition retirement planner and its adapter may not drop the original-fence witness",
    );
}

#[test]
fn retired_admission_witness_uses_original_fence_instead_of_terminal_writer() {
    let profile = profile();
    let admission = retired_admission_v1(144, 7);
    let now = "2026-01-01T00:00:00Z".parse::<Timestamp>().unwrap();
    let authority = AuthorityBinding::from_consensus_parts(
        admission.scope().digest(),
        admission.key().clone(),
        OwnerId::new("successor").unwrap(),
        FenceToken::new(99),
        AuthorityLeaseMetadata::new(2, Generation::new(1), now, now.add_seconds(60).unwrap()),
    )
    .unwrap();
    let request = RequestId::bind(1, &admission).unwrap();
    let committed = CommittedTerminal::issue_from_record(
        BackendRegistration::issue([1; 32], request, &admission).unwrap(),
        &admission,
        &authority,
        TerminalRecord::new(&admission, request, Phase::Aborted, vec![[1; 32]]).unwrap(),
        ConsensusCommitMetadata::issue(201, 202, now).unwrap(),
    )
    .unwrap();
    assert_eq!(admission.admission_fence().get(), 7);
    assert_eq!(authority.fence().get(), 99);
    let mut record = live(&admission, 1, profile);
    record.terminalize(&committed, profile).unwrap();
    record
        .reclaim_at(
            record
                .terminalized_at()
                .unwrap()
                .checked_add_retention()
                .unwrap(),
            profile,
        )
        .unwrap();
    let floor = IrreversibleHistoryFloor::initial(record.binding()).unwrap();
    let counters = counters_with_production_floor(
        counters_with_production_record(zero_counters(), &record, profile).unwrap(),
        floor,
    )
    .unwrap();
    let partition = ProductionMixedTerminalRetirementPartition::new_with_partition_empty_after(
        floor, None, 1, true, true,
    )
    .unwrap();
    let retired = prepare_production_mixed_terminal_retirement(
        &[ProductionMixedTerminalRetirementSelection::V1(&record)],
        &[partition],
        GlobalChargeWitness::v1(0, 0, counters),
        GlobalChargeBudget::v1(u64::MAX),
        profile,
    )
    .unwrap();
    assert_eq!(retired.next_witness().retired_terminal_sequence(), 201);
    assert_eq!(
        retired_admission_witness_fence_for_test(retired.next_witness()),
        Some(7),
        "terminal fence 99 and terminal sequence 201 are not the retired original fence 7"
    );
}
