use super::*;

fn cut(state: &State) -> ScopeBatchReadCut {
    ScopeBatchReadCut::new(
        &scope(),
        Some(state.authority.clone()),
        Some(state.checkpoint.clone()),
    )
    .unwrap()
}

#[test]
fn same_cut_requires_authority_and_ledger_together() {
    let state = State::new();
    assert!(matches!(
        ScopeBatchReadCut::new(&scope(), None, None).unwrap(),
        ScopeBatchReadCut::Uninitialized
    ));
    for (authority, ledger) in [
        (Some(state.authority.clone()), None),
        (None, Some(state.checkpoint.clone())),
    ] {
        assert_eq!(
            ScopeBatchReadCut::new(&scope(), authority, ledger),
            Err(ScopeBatchError::FormatMismatch)
        );
    }
    assert!(matches!(cut(&state), ScopeBatchReadCut::Initialized { .. }));
}

#[test]
fn same_cut_fences_old_attempts_but_not_absence_or_future_authority() {
    let mut state = State::new();
    let old = state
        .command(1, vec![create(1, &[])])
        .request
        .attempt()
        .unwrap();
    assert_eq!(
        cut(&state).lookup(&old).unwrap(),
        ScopeBatchLookup::NotRecorded
    );
    state.authority = state
        .authority
        .transition(&close(&state.authority, 2))
        .unwrap();
    assert_eq!(
        cut(&state).lookup(&old).unwrap(),
        ScopeBatchLookup::NotApplied
    );
    let future = state
        .authority
        .transition(&successor(&state.authority, 3))
        .unwrap();
    let pending = ScopeBatchRequest::in_lane(
        future.view.stamp().unwrap(),
        [3; 16],
        7,
        1,
        vec![create(2, &[])],
        vec![],
    )
    .unwrap()
    .attempt()
    .unwrap();
    assert_eq!(
        cut(&state).lookup(&pending).unwrap(),
        ScopeBatchLookup::NotRecorded
    );
    assert_eq!(
        ScopeBatchReadCut::Uninitialized.lookup(&old).unwrap(),
        ScopeBatchLookup::NotRecorded
    );
}

#[test]
fn same_cut_rejects_a_receipt_from_future_or_different_current_authority() {
    let mut state = State::new();
    state
        .apply(&state.command(1, vec![create(1, &[])]))
        .unwrap();
    for field in 0..4 {
        let mut ledger = state.checkpoint.clone();
        let receipt = ledger.lanes[0].receipt.as_mut().unwrap();
        let mut stamp = serde_json::to_value(&receipt.attempt.stamp).unwrap();
        match field {
            0 => stamp["revision"] = 2.into(),
            1 => stamp["namespace"]["incarnation"] = 2.into(),
            2 => stamp["execution"]["admission_generation"] = 2.into(),
            _ => stamp["execution"]["boot_key"] = serde_json::to_value([2; 32]).unwrap(),
        }
        receipt.attempt.stamp = serde_json::from_value(stamp).unwrap();
        ledger.validate_stored().unwrap();
        assert_eq!(
            ScopeBatchReadCut::new(&scope(), Some(state.authority.clone()), Some(ledger)),
            Err(ScopeBatchError::FormatMismatch),
            "individually valid rows are not a coherent authority/ledger cut: {field}"
        );
    }
}

#[test]
fn same_cut_preserves_historical_receipts_and_pruned_uncertainty_after_succession() {
    let mut state = State::new();
    let first = state.command(1, vec![create(1, &[])]).request;
    let result = state
        .apply(&ScopeBatchCommand {
            request: first.clone(),
        })
        .unwrap();
    let retained = cut(&state);
    state.authority = state
        .authority
        .transition(&successor(&state.authority, 2))
        .unwrap();
    assert_eq!(
        cut(&state).lookup(&first.attempt().unwrap()).unwrap(),
        ScopeBatchLookup::Applied(Box::new(result.clone()))
    );
    state
        .apply(&state.command(3, vec![create(2, &[])]))
        .unwrap();
    assert_eq!(
        cut(&state).lookup(&first.attempt().unwrap()).unwrap(),
        ScopeBatchLookup::Pruned
    );
    assert_eq!(
        retained.lookup(&first.attempt().unwrap()).unwrap(),
        ScopeBatchLookup::Applied(Box::new(result))
    );
}
