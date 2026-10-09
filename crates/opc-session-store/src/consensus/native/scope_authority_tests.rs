use super::*;
use crate::scope_authority::tests::{at, execution, request};
use crate::scope_authority::ScopeAuthorityOperation;

#[test]
fn scope_checkpoint_replacement_does_not_weaken_ordinary_receipt_immutability() {
    let checkpoint = ScopeAuthorityCommand {
        request: request(
            0,
            1,
            ScopeAuthorityOperation::AdmitInitial {
                execution: execution(1),
            },
        ),
    }
    .apply(None)
    .unwrap();
    let scoped = NativeGenericReceipt::Ordinary(NativeOrdinaryReceipt {
        payload_digest: checkpoint.digest().unwrap(),
        response: Box::new(SessionConsensusResponse {
            result: Ok(SessionMutationOutcome::ScopeAuthority(Ok(checkpoint))),
            sequence: 1,
            digest: None,
            logical_time: Some(at(0)),
            raft_log_index: 1,
        }),
    });
    assert!(
        changes::generic_payload(Some(&scoped)).is_err(),
        "cold admission must refuse checkpoints in the previous receipt placement"
    );
    let mut ordinary = scoped.clone();
    let NativeGenericReceipt::Ordinary(row) = &mut ordinary else {
        unreachable!()
    };
    row.response.result = Ok(SessionMutationOutcome::Unit);
    assert!(ordinary
        .validate_replacement(&ordinary, Some(at(0)))
        .is_ok());
    assert!(scoped.validate_replacement(&ordinary, Some(at(0))).is_err());
    assert!(ordinary.validate_replacement(&scoped, Some(at(0))).is_err());
    let mut changed = ordinary.clone();
    let NativeGenericReceipt::Ordinary(row) = &mut changed else {
        unreachable!()
    };
    row.response.sequence += 1;
    assert!(changed
        .validate_replacement(&ordinary, Some(at(1)))
        .is_err());
}

#[test]
fn native_initial_admission_refuses_orphan_rows_in_every_incarnation() {
    use crate::consensus::native::changes::tests::{clock, fixture};
    use crate::scope_authority::{ScopeAuthorityRequest, ScopeId, ScopeProfileActivation};
    use crate::scope_storage::ScopeRow;
    let (storage, _, _) = fixture();
    let identity = storage.business.identity;
    let scope = ScopeId::new(
        identity,
        opc_types::TenantId::from_static("orphan"),
        opc_types::NetworkFunctionKind::smf(),
        [1; 32],
    )
    .unwrap();
    let operation = ScopeAuthorityCommand {
        request: ScopeAuthorityRequest::new(
            scope.clone(),
            [7; 16],
            0,
            ScopeAuthorityOperation::AdmitInitial {
                execution: execution(1),
            },
        )
        .unwrap(),
    };
    let EntryPayload::Normal(mut command) = clock(2, at(0)).payload else {
        unreachable!()
    };
    command.request_id = SessionConsensusRequestId::from_bytes([7; 16]);
    command.intent = SessionMutationIntent::Authorized {
        origin: *storage.business.members.first().unwrap(),
        authority_identity: identity,
        mutation: Box::new(SessionMutationIntent::ScopeAuthority(Box::new(
            operation.clone(),
        ))),
    };
    let activation = ScopeRow::Activation(ScopeProfileActivation::new(
        identity,
        fenced_transition_voter_set_digest(identity, &storage.business.members),
    ))
    .to_record()
    .unwrap();
    for orphan in crate::scope_batch::tests::orphan_rows(scope.clone()) {
        let mut delta = storage.business.prepare(&[]).unwrap();
        delta.keys.insert(
            activation.key.clone(),
            NativeKeyState {
                record: Some(activation.clone()),
                ..NativeKeyState::default()
            },
        );
        let record = orphan.to_record().unwrap();
        delta.keys.insert(
            record.key.clone(),
            NativeKeyState {
                record: Some(record),
                ..NativeKeyState::default()
            },
        );
        let encoded = |keys: &HashMap<SessionKey, NativeKeyState>| {
            let mut rows: Vec<_> = keys
                .iter()
                .map(|row| postcard::to_allocvec(&row).unwrap())
                .collect();
            rows.sort();
            rows
        };
        let before = encoded(&delta.keys);
        let response = delta
            .scope_authority(&command, &operation, true, at(0), 2)
            .unwrap();
        assert!(matches!(
            response.result,
            Ok(SessionMutationOutcome::ScopeAuthority(Err(
                ScopeAuthorityError::FormatMismatch
            )))
        ));
        assert_eq!(
            encoded(&delta.keys),
            before,
            "no orphan row, counter, floor or receipt may change"
        );
        assert!(!delta.keys.contains_key(&scope.key().unwrap()));
    }
}
