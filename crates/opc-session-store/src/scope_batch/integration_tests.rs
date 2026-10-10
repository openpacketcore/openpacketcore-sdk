use super::*;

fn independent(
    state: &State,
    id: u8,
    lane: u8,
    operations: Vec<ScopeChildMutation>,
) -> ScopeBatchCommand {
    ScopeBatchCommand {
        request: ScopeBatchRequest::in_lane(
            state.authority.view.stamp().unwrap(),
            [id; 16],
            lane,
            state.checkpoint.lanes[usize::from(lane)].sequence + 1,
            operations,
            vec![],
        )
        .unwrap(),
    }
}

#[test]
fn retained_receipt_counters_cannot_exceed_a_cold_ledger() {
    let mut state = State::new();
    let mut first = independent(&state, 1, 0, vec![create(1, &[])]);
    first.request.counters = vec![ScopeCounterMutation::new(0, 0, 7).unwrap()];
    state.apply(&first).unwrap();
    let second = independent(&state, 2, 1, vec![create(2, &[])]);
    state.apply(&second).unwrap();
    // A cold restore has no earlier local row to compare. Keep its latest
    // receipt consistent with the header, but regress below the older receipt.
    let mut cold = state.checkpoint.clone();
    cold.counters[0] = 6;
    let ScopeBatchTerminal::Applied(latest) = &mut cold.lanes[1].receipt.as_mut().unwrap().terminal
    else {
        unreachable!();
    };
    latest.counters[0] = 6;
    assert_eq!(cold.validate_stored(), Err(ScopeBatchError::FormatMismatch));
    assert_eq!(
        ScopeBatchReadCut::new(
            &cold.scope,
            Some(state.authority.clone()),
            Some(cold.clone())
        ),
        Err(ScopeBatchError::FormatMismatch)
    );
}

#[test]
fn same_lane_next_sequence_collision_is_positive_no_apply_evidence() {
    let mut state = State::new();
    let first = independent(&state, 7, 7, vec![create(1, &[])]);
    state.apply(&first).unwrap();
    let colliding = independent(&state, 7, 7, vec![create(2, &[])])
        .request
        .attempt()
        .unwrap();
    let cut = ScopeBatchReadCut::new(
        &state.checkpoint.scope,
        Some(state.authority.clone()),
        Some(state.checkpoint.clone()),
    )
    .unwrap()
    .reopen();
    let proof = ScopeBatchNoApplyProof::new(&colliding, &cut)
        .expect("replacing the colliding receipt necessarily consumes this sequence");
    assert!(proof.matches(&colliding));
    assert_eq!(proof.lane_sequence(), 1);
    let mut future = colliding.clone();
    future.sequence += 1;
    assert!(
        ScopeBatchNoApplyProof::new(&future, &cut).is_err(),
        "a gapped sequence may become eligible after the collision is discarded"
    );
    let mut cross_lane = colliding;
    cross_lane.lane = 0;
    cross_lane.sequence = 1;
    assert!(
        ScopeBatchNoApplyProof::new(&cross_lane, &cut).is_err(),
        "another lane can discard its receipt without consuming this sequence"
    );
    let intermediate = independent(&state, 8, 7, vec![create(3, &[])]);
    state.apply(&intermediate).unwrap();
    let reused_after_pruning = independent(&state, 7, 7, vec![create(4, &[])]);
    state.apply(&reused_after_pruning).unwrap();
    let cut = ScopeBatchReadCut::new(
        &state.checkpoint.scope,
        Some(state.authority.clone()),
        Some(state.checkpoint.clone()),
    )
    .unwrap()
    .reopen();
    assert!(
        ScopeBatchNoApplyProof::new(&first.request.attempt().unwrap(), &cut).is_err(),
        "an old pruned attempt actually applied before this ID was reused"
    );
}

#[test]
fn data_lane_service_refuses_safety_control_on_every_lane() {
    use crate::scope_scheduler::ScopeWorkClass;
    for lane in 0..SCOPE_BATCH_LANES as u8 {
        assert_eq!(
            super::super::service::require_data_lane_class(lane, ScopeWorkClass::SafetyControl),
            Err(ScopeAuthorityError::Unauthorized.into())
        );
        assert_eq!(
            super::super::service::require_data_lane_class(lane, ScopeWorkClass::Emergency),
            Ok(())
        );
    }
}

#[test]
fn all_eight_disjoint_lanes_from_one_cut_commit_independently() {
    let mut state = State::new();
    let commands: Vec<_> = (0..8)
        .map(|lane| independent(&state, lane + 1, lane, vec![create(lane + 1, &[])]))
        .collect();
    for (index, command) in commands.iter().enumerate() {
        let outcome = state
            .apply(command)
            .expect("disjoint lane has no scope guard");
        assert_eq!(outcome.lane(), index as u8);
        assert_eq!(outcome.sequence(), 1);
        assert_eq!(outcome.revision(), index as u64 + 1);
    }
    for command in commands {
        let before = state.bytes();
        let outcome = state
            .apply(&command)
            .expect("historical lane receipt replays");
        assert_eq!(outcome.revision(), u64::from(command.request.lane()) + 1);
        assert_eq!(state.bytes(), before);
    }
}

#[test]
fn overlapping_child_claim_and_counter_have_one_winner() {
    for conflict_kind in 0..3 {
        let mut state = State::new();
        let mut first = independent(&state, 1, 0, vec![create(1, &[1])]);
        let mut second = independent(&state, 2, 7, vec![create(2, &[2])]);
        match conflict_kind {
            0 => second.request.operations = vec![create(1, &[])],
            1 => second.request.operations = vec![create(2, &[1])],
            _ => {
                first.request.counters = vec![ScopeCounterMutation::new(0, 0, 1).unwrap()];
                second.request.counters = vec![ScopeCounterMutation::new(0, 0, 2).unwrap()];
            }
        }
        state.apply(&first).unwrap();
        let before = state.bytes();
        assert!(
            matches!(state.apply(&second), Err(ScopeBatchError::Conflict(_))),
            "overlap {conflict_kind} must compare at apply"
        );
        assert_eq!(state.bytes(), before);
        assert_eq!(state.checkpoint.lanes[7].sequence, 0);
    }
}

#[test]
fn every_read_only_child_dependency_is_compared_without_rewriting_it() {
    for changed in 1..=4 {
        let mut state = State::new();
        state
            .apply(&state.command(1, (1..=4).map(|n| create(n, &[])).collect()))
            .unwrap();
        let conditions: Vec<_> = (1..=4)
            .map(|n| ScopeChildCondition::new(key(n), state.child(n).unwrap().revision()).unwrap())
            .collect();
        let old = state.child(changed).unwrap().revision();
        state
            .apply(&state.command(
                2,
                vec![ScopeChildMutation::CompareAndSet {
                    key: key(changed),
                    expected: old,
                    value: value(9),
                    claims: vec![],
                }],
            ))
            .unwrap();
        // The whole-scope guard intentionally matches; only the read predicate
        // can detect a stale predecessor/barrier/locator dependency here.
        let mut handoff = state.command(3, vec![create(5, &[])]);
        handoff.request = handoff
            .request
            .with_read_conditions(conditions, vec![])
            .unwrap();
        let before = state.bytes();
        let Err(ScopeBatchError::Conflict(conflicts)) = state.apply(&handoff) else {
            panic!("changed dependency {changed} must refuse the entire handoff");
        };
        assert_eq!(conflicts.children, vec![key(changed)]);
        assert_eq!(state.bytes(), before);
    }
}

#[test]
fn claim_revision_and_owner_birth_prevent_identical_recreation() {
    let mut state = State::new();
    let first = state
        .apply(&state.command(1, vec![create(1, &[1])]))
        .unwrap();
    let predicate = ScopeClaimCondition::new(
        claim(1),
        first.revision(),
        Some(ScopeClaimOwner::new(key(1), first.rows()[0].birth()).unwrap()),
    )
    .unwrap();
    state
        .apply(&state.command(
            2,
            vec![ScopeChildMutation::Delete {
                key: key(1),
                expected: first.rows()[0],
            }],
        ))
        .unwrap();
    state
        .apply(&state.command(3, vec![create(1, &[1])]))
        .unwrap();
    let mut handoff = state.command(4, vec![create(2, &[])]);
    handoff.request = handoff
        .request
        .with_read_conditions(vec![], vec![predicate])
        .unwrap();
    let before = state.bytes();
    let Err(ScopeBatchError::Conflict(conflicts)) = state.apply(&handoff) else {
        panic!("recreated claim owner must not match its predecessor");
    };
    assert_eq!(conflicts.claims, vec![claim(1)]);
    assert_eq!(state.bytes(), before);
}

#[test]
fn missing_claim_is_not_a_retained_released_claim() {
    let mut state = State::new();
    let mut handoff = state.command(1, vec![create(1, &[])]);
    handoff.request = handoff
        .request
        .with_read_conditions(
            vec![],
            vec![ScopeClaimCondition::new(claim(1), 1, None).unwrap()],
        )
        .unwrap();
    let before = state.bytes();
    assert!(matches!(
        state.apply(&handoff),
        Err(ScopeBatchError::Conflict(_))
    ));
    assert_eq!(state.bytes(), before);
}

#[test]
fn historical_receipts_keep_their_original_counters() {
    let mut state = State::new();
    let mut first = independent(&state, 1, 0, vec![create(1, &[])]);
    first.request.counters = vec![ScopeCounterMutation::new(0, 0, 1).unwrap()];
    let retained = state.apply(&first).unwrap();
    let mut emergency = independent(&state, 2, 7, vec![create(2, &[])]);
    emergency.request.counters = vec![ScopeCounterMutation::new(0, 1, 2).unwrap()];
    state.apply(&emergency).unwrap();
    state.checkpoint.validate_stored().unwrap();
    assert_eq!(state.apply(&first).unwrap(), retained);
    assert_eq!(retained.counters()[0], 1);
    assert_eq!(state.checkpoint.counters[0], 2);
}

#[test]
fn lane_seven_revalidates_forged_decrease_and_stale_equality() {
    let mut state = State::new();
    let mut first = independent(&state, 1, 7, vec![create(1, &[])]);
    first.request.counters = vec![ScopeCounterMutation::new(0, 0, 2).unwrap()];
    state.apply(&first).unwrap();
    let mut next = independent(&state, 2, 7, vec![create(2, &[])]);
    let mut wire = serde_json::to_value(ScopeCounterMutation::new(0, 2, 2).unwrap()).unwrap();
    wire["next"] = 1.into();
    next.request.counters = vec![serde_json::from_value(wire).unwrap()];
    let before = state.bytes();
    assert_eq!(state.apply(&next), Err(ScopeBatchError::InvalidRequest));
    assert_eq!(state.bytes(), before);
    next.request.counters = vec![ScopeCounterMutation::new(0, 1, 1).unwrap()];
    assert!(matches!(
        state.apply(&next),
        Err(ScopeBatchError::Conflict(_))
    ));
    assert_eq!(state.bytes(), before);
    next.request.counters = vec![ScopeCounterMutation::new(0, 2, 2).unwrap()];
    assert_eq!(state.apply(&next).unwrap().counters()[0], 2);
}

#[test]
fn higher_scope_revision_cannot_replace_a_consumed_lane_with_zero() {
    for lost_lane in 0..8 {
        let mut before = State::new();
        for n in 1..=2 {
            before
                .apply(&independent(&before, n, lost_lane, vec![create(n, &[])]))
                .unwrap();
        }
        let mut competing = State::new();
        for n in 1..=3 {
            competing
                .apply(&independent(
                    &competing,
                    n + 10,
                    (lost_lane + 1) % 8,
                    vec![create(n, &[])],
                ))
                .unwrap();
        }
        let facts = |checkpoint: ScopeBatchCheckpoint| {
            crate::scope_storage::ScopeRow::Batch(Box::new(checkpoint))
                .facts()
                .unwrap()
        };
        assert!(!facts(competing.checkpoint).can_replace(facts(before.checkpoint)),
            "snapshot must retain consumed sequence and discarded-through floor of lane {lost_lane}");
    }
}

#[test]
fn equal_lane_sequence_requires_identical_receipt_when_other_lanes_advance() {
    let mut before = State::new();
    before
        .apply(&independent(&before, 1, 0, vec![create(1, &[])]))
        .unwrap();
    let mut competing = State::new();
    competing
        .apply(&independent(&competing, 2, 0, vec![create(1, &[])]))
        .unwrap();
    competing
        .apply(&independent(&competing, 3, 7, vec![create(2, &[])]))
        .unwrap();
    let facts = |checkpoint: ScopeBatchCheckpoint| {
        crate::scope_storage::ScopeRow::Batch(Box::new(checkpoint))
            .facts()
            .unwrap()
    };
    assert!(
        !facts(competing.checkpoint).can_replace(facts(before.checkpoint)),
        "a larger scope revision cannot rewrite another lane's retained receipt"
    );
}

#[test]
fn physical_reclamation_cannot_recycle_child_or_claim_observations() {
    let mut state = State::new();
    let first = state
        .apply(&state.command(1, vec![create(1, &[1])]))
        .unwrap();
    let old_child = ScopeChildCondition::new(key(1), first.rows()[0]).unwrap();
    let old_claim = ScopeClaimCondition::new(
        claim(1),
        first.revision(),
        Some(ScopeClaimOwner::new(key(1), first.rows()[0].birth()).unwrap()),
    )
    .unwrap();
    state
        .apply(&state.command(
            2,
            vec![ScopeChildMutation::Delete {
                key: key(1),
                expected: first.rows()[0],
            }],
        ))
        .unwrap();
    let namespace = state.authority.view.stamp().unwrap().namespace();
    state
        .rows
        .remove(&crate::scope_storage::child_key(namespace, key(1)).unwrap());
    state
        .rows
        .remove(&crate::scope_storage::claim_key(namespace, claim(1)).unwrap());
    state
        .apply(&state.command(3, vec![create(1, &[1])]))
        .unwrap();
    let mut next = state.command(4, vec![create(2, &[])]);
    next.request = next
        .request
        .with_read_conditions(vec![old_child], vec![old_claim])
        .unwrap();
    let before = state.bytes();
    let Err(ScopeBatchError::Conflict(conflicts)) = state.apply(&next) else {
        panic!("physically removed identities must not recur");
    };
    assert_eq!(conflicts.children, vec![key(1)]);
    assert_eq!(conflicts.claims, vec![claim(1)]);
    assert_eq!(state.bytes(), before);
}
