use super::*;
use crate::scope_authority::tests::{
    admitted, at, close, execution, request, retired_fixture, scope, successor,
};

fn selected() -> ScopeAuthorityCheckpoint {
    ScopeAuthorityCommand {
        request: request(
            0,
            1,
            ScopeAuthorityOperation::AdmitInitial {
                execution: execution(1),
            },
        ),
    }
    .apply(None)
    .unwrap()
}

fn stored(checkpoint: ScopeAuthorityCheckpoint) -> ([u8; 32], SessionConsensusResponse) {
    (
        checkpoint.digest().unwrap(),
        SessionConsensusResponse {
            result: Ok(SessionMutationOutcome::ScopeAuthority(Ok(checkpoint))),
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
    assert_eq!(json.len(), 2 * MAX_SCOPE_AUTHORITY_RECORD_BYTES + 2);
    assert_eq!(
        serde_json::from_slice::<ScopeAuthorityCheckpoint>(&json).unwrap(),
        checkpoint
    );
    let wire = postcard::to_allocvec(&checkpoint).unwrap();
    assert_eq!(
        postcard::from_bytes::<ScopeAuthorityCheckpoint>(&wire).unwrap(),
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
    invalid.push(vec![0; MAX_SCOPE_AUTHORITY_RECORD_BYTES + 1]);
    for bytes in invalid {
        let encoded = serde_json::to_vec(&hex::encode(bytes)).unwrap();
        assert!(serde_json::from_slice::<ScopeAuthorityCheckpoint>(&encoded).is_err());
    }
}

#[test]
fn scope_checkpoint_slots_refuse_other_scopes_digests_and_outcome_families() {
    let checkpoint = selected();
    let mut foreign_scope = scope();
    foreign_scope.slot = [9; 32];
    assert_eq!(
        checkpoint_state(&foreign_scope, Some(stored(checkpoint.clone()))),
        Err(ScopeAuthorityError::FormatMismatch)
    );
    assert_eq!(
        checkpoint.validate_slot(scope().checkpoint_id().unwrap(), [9; 32]),
        Err(ScopeAuthorityError::FormatMismatch)
    );
    let (digest, mut response) = stored(checkpoint);
    response.result = Ok(SessionMutationOutcome::Unit);
    assert_eq!(
        checkpoint_state(&scope(), Some((digest, response))),
        Err(ScopeAuthorityError::FormatMismatch)
    );
}

#[test]
fn scope_checkpoint_replacement_preserves_identity_and_every_monotonic_floor() {
    let before = admitted();
    let retired = retired_fixture(&before, 2);
    let old = ScopeAuthorityCheckpoint::new(&before).unwrap();
    let later = ScopeAuthorityCheckpoint::new(&retired).unwrap();
    assert!(later.can_replace(&old));
    assert!(!old.can_replace(&later));
    let closed = before.transition(&close(&before, 2)).unwrap();
    let closed_checkpoint = ScopeAuthorityCheckpoint::new(&closed).unwrap();
    assert!(closed_checkpoint.can_replace(&old));
    let successor = closed.transition(&successor(&closed, 3)).unwrap();
    assert!(ScopeAuthorityCheckpoint::new(&successor)
        .unwrap()
        .can_replace(&closed_checkpoint));
    for field in 0..4 {
        let mut invalid = retired.clone();
        invalid.view.revision += 1;
        invalid.view.stamp.as_mut().unwrap().revision += 1;
        match field {
            0 => invalid.view.retired_through = 0,
            1 => {
                invalid.view.admission_generation_floor = 1;
                invalid.view.stamp.as_mut().unwrap().execution = execution(1);
            }
            2 => {
                invalid.view.stamp.as_mut().unwrap().execution.process = [8; 16];
            }
            _ => {
                invalid.view.stamp.as_mut().unwrap().namespace.incarnation =
                    ScopeIncarnation::new(1).unwrap();
                invalid.view.retired_through = 0;
            }
        }
        assert!(
            !ScopeAuthorityCheckpoint::new(&invalid)
                .unwrap()
                .can_replace(&later),
            "field {field}"
        );
    }
    let mut reopened = closed;
    reopened.view.revision += 1;
    reopened.view.stamp.as_mut().unwrap().revision += 1;
    reopened.view.active = true;
    reopened.view.closed_digest = None;
    assert!(!ScopeAuthorityCheckpoint::new(&reopened)
        .unwrap()
        .can_replace(&closed_checkpoint));
}

#[test]
fn closure_tokens_are_exact_and_cannot_be_omitted_from_succession() {
    let request = successor(&admitted(), 2);
    assert_eq!(
        ScopeAuthorityCommand::verified(request.clone(), None),
        Err(ScopeAuthorityError::ClosureRequired)
    );
    let (predecessor, evidence) = request.operation.closure().unwrap();
    let token = VerifiedScopeClosure {
        predecessor: predecessor.clone(),
        evidence: evidence.clone(),
    };
    assert!(ScopeAuthorityCommand::verified(request.clone(), Some(token.clone())).is_ok());
    let mut mismatched = token;
    mismatched.evidence.digest = [9; 32];
    assert_eq!(
        ScopeAuthorityCommand::verified(request, Some(mismatched)),
        Err(ScopeAuthorityError::ClosureRequired)
    );
}

#[test]
fn exact_response_matching_checks_revision_execution_and_operation_shape() {
    let request = request(
        0,
        1,
        ScopeAuthorityOperation::AdmitInitial {
            execution: execution(1),
        },
    );
    let command = ScopeAuthorityCommand { request };
    let current = command.apply(None).unwrap();
    assert!(command.matches(&current));
    for field in 0..3 {
        let mut changed = current.state().unwrap();
        match field {
            0 => {
                changed.view.revision += 1;
                changed.view.stamp.as_mut().unwrap().revision += 1;
            }
            1 => {
                changed.view.stamp.as_mut().unwrap().execution.process = [8; 16];
            }
            _ => {
                changed.view.active = false;
                changed.view.closed_digest = Some(changed.last_digest);
            }
        }
        assert!(
            !command.matches(&ScopeAuthorityCheckpoint::new(&changed).unwrap()),
            "field {field}"
        );
    }
}
