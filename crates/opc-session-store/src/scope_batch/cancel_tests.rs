use super::*;

fn attempt(state: &State, id: u8, lane: u8) -> ScopeBatchCommand {
    ScopeBatchCommand {
        request: ScopeBatchRequest::in_lane(
            state.authority.view.stamp().unwrap(),
            [id; 16],
            lane,
            state.checkpoint.lanes[usize::from(lane)].sequence + 1,
            vec![create(id, &[])],
            vec![],
        )
        .unwrap(),
    }
}

fn cancel(
    state: &mut State,
    request: &ScopeBatchRequest,
) -> Result<ScopeBatchReceipt, ScopeBatchError> {
    let command = ScopeBatchCancelCommand {
        attempt: request.attempt()?,
    };
    let plan = command.plan(&state.authority, &state.checkpoint)?;
    state.rows.extend(plan.rows);
    state.checkpoint = plan.checkpoint;
    state
        .checkpoint
        .receipt(request.lane())
        .cloned()
        .ok_or(ScopeBatchError::FormatMismatch)
}

#[test]
fn apply_and_cancel_race_for_one_immutable_terminal_receipt() {
    for apply_first in [true, false] {
        let mut state = State::new();
        let request = attempt(&state, 1, 7).request;
        if apply_first {
            let outcome = state
                .apply(&ScopeBatchCommand {
                    request: request.clone(),
                })
                .unwrap();
            let bytes = state.bytes();
            let receipt = cancel(&mut state, &request).unwrap();
            assert_eq!(
                receipt.terminal(),
                &ScopeBatchTerminal::Applied(Box::new(outcome))
            );
            assert_eq!(receipt.revision(), 1);
            assert_eq!(state.bytes(), bytes);
        } else {
            let receipt = cancel(&mut state, &request).unwrap();
            assert_eq!(receipt.terminal(), &ScopeBatchTerminal::Cancelled);
            assert_eq!(receipt.revision(), 1);
            assert!(state.child(1).is_none());
            let bytes = state.bytes();
            assert_eq!(
                state.apply(&ScopeBatchCommand {
                    request: request.clone()
                }),
                Err(ScopeBatchError::Cancelled)
            );
            assert_eq!(cancel(&mut state, &request).unwrap(), receipt);
            assert_eq!(state.bytes(), bytes);
        }
        assert_eq!(state.checkpoint.revision, 1);
        assert_eq!(state.checkpoint.lanes[7].sequence, 1);
        assert_eq!(state.checkpoint.birth_floor, u64::from(apply_first));
    }
}

#[test]
fn cancelled_receipt_rejects_changed_digest_or_authority_and_cannot_erase_effects() {
    let mut state = State::new();
    let original = attempt(&state, 1, 3).request;
    cancel(&mut state, &original).unwrap();
    let bytes = state.bytes();
    let mut changed = original.clone();
    changed.operations = vec![create(2, &[])];
    assert_eq!(
        cancel(&mut state, &changed),
        Err(ScopeBatchError::IdempotencyConflict)
    );
    assert_eq!(
        state.apply(&ScopeBatchCommand { request: changed }),
        Err(ScopeBatchError::IdempotencyConflict)
    );
    state.authority = state
        .authority
        .transition(&successor(&state.authority, 2))
        .unwrap();
    let mut restamped = original.clone();
    restamped.stamp = state.authority.view.stamp().unwrap().clone();
    assert_eq!(
        cancel(&mut state, &restamped),
        Err(ScopeBatchError::IdempotencyConflict)
    );
    assert_eq!(
        cancel(&mut state, &original).unwrap().terminal(),
        &ScopeBatchTerminal::Cancelled
    );
    assert_eq!(state.bytes(), bytes);
}

#[test]
fn exact_lookup_distinguishes_eligible_absence_fencing_and_pruned_history() {
    let mut state = State::new();
    let first = attempt(&state, 1, 4).request;
    let identity = first.attempt().unwrap();
    assert_eq!(
        state.checkpoint.lookup(&identity, false).unwrap(),
        ScopeBatchLookup::NotRecorded
    );
    assert_eq!(
        state.checkpoint.lookup(&identity, true).unwrap(),
        ScopeBatchLookup::NotApplied
    );
    cancel(&mut state, &first).unwrap();
    assert_eq!(
        state.checkpoint.lookup(&identity, false).unwrap(),
        ScopeBatchLookup::Cancelled
    );
    let second = attempt(&state, 2, 4).request;
    state
        .apply(&ScopeBatchCommand {
            request: second.clone(),
        })
        .unwrap();
    assert_eq!(
        state.checkpoint.lookup(&identity, false).unwrap(),
        ScopeBatchLookup::Pruned
    );
    assert_eq!(
        state.checkpoint.lookup(&identity, true).unwrap(),
        ScopeBatchLookup::Pruned
    );
    assert!(matches!(
        state
            .checkpoint
            .lookup(&second.attempt().unwrap(), true)
            .unwrap(),
        ScopeBatchLookup::Applied(_)
    ));
    let mut alternate = second;
    alternate.request_id = [3; 16];
    assert_eq!(
        state
            .checkpoint
            .lookup(&alternate.attempt().unwrap(), false)
            .unwrap(),
        ScopeBatchLookup::NotApplied
    );
}

#[test]
fn pending_cancel_after_closure_refuses_without_advancing_any_floor() {
    let mut state = State::new();
    let pending = attempt(&state, 1, 7).request;
    state.authority = state
        .authority
        .transition(&close(&state.authority, 2))
        .unwrap();
    let bytes = state.bytes();
    assert!(matches!(
        cancel(&mut state, &pending),
        Err(ScopeBatchError::Scope(_))
    ));
    assert_eq!(state.bytes(), bytes);
}

#[test]
fn retained_id_cannot_move_between_lanes_or_skip_sequences() {
    let mut state = State::new();
    let request = attempt(&state, 1, 0).request;
    cancel(&mut state, &request).unwrap();
    let bytes = state.bytes();
    let mut altered = request.clone();
    altered.lane = 1;
    assert_eq!(
        cancel(&mut state, &altered),
        Err(ScopeBatchError::IdempotencyConflict)
    );
    assert_eq!(
        state.checkpoint.lookup(&altered.attempt().unwrap(), false),
        Err(ScopeBatchError::IdempotencyConflict)
    );
    let mut gap = attempt(&state, 2, 0).request;
    gap.sequence += 1;
    assert_eq!(
        cancel(&mut state, &gap),
        Err(ScopeBatchError::SequenceConflict)
    );
    assert_eq!(state.bytes(), bytes);
}
