use super::*;
use crate::scope_lease::tests::{at, bounds, execution, request, scope};

fn selected() -> ScopeLeaseCheckpoint {
    ScopeLeaseCommand {
        request: request(
            0,
            1,
            ScopeLeaseOperation::Select {
                execution: execution(1),
            },
        ),
        bounds: bounds(0),
    }
    .apply(None)
    .unwrap()
}

fn stored(checkpoint: ScopeLeaseCheckpoint) -> ([u8; 32], SessionConsensusResponse) {
    (
        checkpoint.digest().unwrap(),
        SessionConsensusResponse {
            result: Ok(SessionMutationOutcome::ScopeLease(Ok(checkpoint))),
            sequence: 1,
            digest: None,
            logical_time: Some(at(0)),
            raft_log_index: 1,
        },
    )
}

#[test]
fn scope_checkpoint_framing_rejects_legacy_trailing_truncated_and_oversized_data() {
    let checkpoint = selected();
    let json = serde_json::to_vec(&checkpoint).unwrap();
    assert_eq!(json.len(), 2 * MAX_SCOPE_LEASE_RECORD_BYTES + 2);
    assert_eq!(
        serde_json::from_slice::<ScopeLeaseCheckpoint>(&json).unwrap(),
        checkpoint
    );
    let wire = postcard::to_allocvec(&checkpoint).unwrap();
    assert_eq!(
        postcard::from_bytes::<ScopeLeaseCheckpoint>(&wire).unwrap(),
        checkpoint
    );
    let mut invalid = Vec::new();
    let mut legacy = checkpoint.0.clone();
    legacy[2 + RECORD_MAGIC.len() - 1] = 1;
    invalid.push(legacy);
    let mut trailing = checkpoint.0.clone();
    *trailing.last_mut().unwrap() = 1;
    invalid.push(trailing);
    let mut framing = checkpoint.0.clone();
    framing[..2].copy_from_slice(&u16::MAX.to_le_bytes());
    invalid.push(framing);
    invalid.push(checkpoint.0[..checkpoint.0.len() - 1].to_vec());
    invalid.push(vec![0; MAX_SCOPE_LEASE_RECORD_BYTES + 1]);
    for bytes in invalid {
        let encoded = serde_json::to_vec(&hex::encode(bytes)).unwrap();
        assert!(serde_json::from_slice::<ScopeLeaseCheckpoint>(&encoded).is_err());
    }
}

#[test]
fn scope_checkpoint_slots_refuse_other_scopes_digests_and_outcome_families() {
    let checkpoint = selected();
    let mut foreign_scope = scope();
    foreign_scope.slot = [9; 32];
    assert_eq!(
        checkpoint_state(&foreign_scope, Some(stored(checkpoint.clone()))),
        Err(ScopeLeaseError::FormatMismatch)
    );
    assert_eq!(
        checkpoint.validate_slot(scope().checkpoint_id().unwrap(), [9; 32]),
        Err(ScopeLeaseError::FormatMismatch)
    );
    let (digest, mut response) = stored(checkpoint);
    response.result = Ok(SessionMutationOutcome::Unit);
    assert_eq!(
        checkpoint_state(&scope(), Some((digest, response))),
        Err(ScopeLeaseError::FormatMismatch)
    );
}

#[test]
fn scope_checkpoint_replacement_preserves_identity_and_every_monotonic_floor() {
    let selected = selected();
    let acquired = ScopeLeaseCommand {
        request: request(
            1,
            2,
            ScopeLeaseOperation::Acquire {
                execution: execution(1),
                selection: 1,
            },
        ),
        bounds: bounds(1),
    }
    .apply(Some(stored(selected.clone())))
    .unwrap();
    assert!(acquired.can_replace(&selected));
    assert!(acquired.can_replace(&acquired));
    assert!(!selected.can_replace(&acquired));
    let before = acquired.state().unwrap();
    let mut after = before.clone();
    after.view.revision += 1;
    after.last_request_id = [3; 16];
    after.last_digest = [3; 32];
    // All these records are independently well formed, but none is a valid
    // replacement of the predecessor. Reject corruption during publication.
    for field in 0..4 {
        let mut regressed = after.clone();
        match field {
            0 => regressed.view.scope.slot = [9; 32],
            1 => regressed.view.revision = before.view.revision,
            2 => {
                regressed.view.grant_floor = 0;
                regressed.view.granted_selection = 0;
                regressed.view.permit = None;
            }
            _ => {
                regressed.last_time = at(0);
                regressed.view.permit = None;
            }
        }
        if field == 0 {
            regressed.view.permit = None;
        }
        let checkpoint = ScopeLeaseCheckpoint::new(&regressed).unwrap();
        assert!(
            !checkpoint.can_replace(&acquired),
            "regressed field {field}"
        );
    }
    let later_selection = ScopeLeaseCommand {
        request: request(
            2,
            3,
            ScopeLeaseOperation::Select {
                execution: execution(2),
            },
        ),
        bounds: bounds(100),
    }
    .apply(Some(stored(acquired)))
    .unwrap();
    let mut regressed = later_selection.state().unwrap();
    regressed.view.revision += 1;
    regressed.view.selection = 1;
    regressed.view.selected = Some(execution(1));
    assert!(!ScopeLeaseCheckpoint::new(&regressed)
        .unwrap()
        .can_replace(&later_selection));
}

#[test]
fn scope_command_and_wire_clock_refuse_invalid_bounds() {
    let command = ScopeLeaseCommand {
        request: request(
            0,
            1,
            ScopeLeaseOperation::Select {
                execution: execution(1),
            },
        ),
        bounds: ScopeClockBounds {
            earliest: at(0),
            latest: at(2),
        },
    };
    assert!(
        serde_json::from_slice::<ScopeLeaseCommand>(&serde_json::to_vec(&command).unwrap())
            .is_err(),
        "deserialization must preserve the clock interval invariant used by gate helpers"
    );
    assert_eq!(command.apply(None), Err(ScopeLeaseError::ClockUncertain));
}
