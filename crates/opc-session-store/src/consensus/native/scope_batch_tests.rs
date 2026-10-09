use super::*;
use crate::consensus::native::changes::tests::{apply, clock, fixture};
use crate::scope_authority::tests::{at, execution};
use crate::scope_authority::{
    ScopeAuthorityCommand, ScopeAuthorityOperation, ScopeAuthorityRequest, ScopeId,
    ScopeProfileActivation,
};
use crate::scope_batch::tests::{claim, create, key, value};
use crate::scope_batch::{ScopeBatchRequest, ScopeChildMutation, ScopeChildRevision};

fn entry(
    storage: &NativeStorage,
    index: u64,
    intent: SessionMutationIntent,
) -> Entry<SessionRaftTypeConfig> {
    let mut entry = clock(index, at(0));
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.request_id = SessionConsensusRequestId::from_bytes(match &intent {
        SessionMutationIntent::ScopeAuthority(operation) => *operation.request.request_id(),
        SessionMutationIntent::ScopeBatch(operation) => *operation.request.request_id(),
        _ => (0x1000 + u128::from(index)).to_be_bytes(),
    });
    command.intent = SessionMutationIntent::Authorized {
        origin: *storage.business.members.first().unwrap(),
        authority_identity: storage.business.identity,
        mutation: Box::new(intent),
    };
    entry
}

#[test]
fn required_native_ledger_is_atomic_and_cannot_be_omitted_on_reopen() {
    let (mut storage, _, _) = fixture();
    let identity = storage.business.identity;
    let scope = ScopeId::new(
        identity,
        opc_types::TenantId::from_static("required-ledger"),
        opc_types::NetworkFunctionKind::smf(),
        [1; 32],
    )
    .unwrap();
    let activate = entry(
        &storage,
        2,
        SessionMutationIntent::ActivateScopeProfile(Box::new(ScopeProfileActivation::new(
            identity,
            fenced_transition_voter_set_digest(identity, &storage.business.members),
        ))),
    );
    apply(&mut storage, &[activate]);
    let initial = entry(
        &storage,
        3,
        SessionMutationIntent::ScopeAuthority(Box::new(ScopeAuthorityCommand {
            request: ScopeAuthorityRequest::new(
                scope.clone(),
                [3; 16],
                0,
                ScopeAuthorityOperation::AdmitInitial {
                    execution: execution(1),
                },
            )
            .unwrap(),
        })),
    );
    let key = scope_storage::batch_key(&scope).unwrap();
    let complete = storage
        .business
        .prepare(std::slice::from_ref(&initial))
        .unwrap();
    assert!(
        complete.keys.contains_key(&key),
        "admission includes the zero ledger"
    );
    changes::Publication::prepare(complete).unwrap();
    let mut incomplete = storage
        .business
        .prepare(std::slice::from_ref(&initial))
        .unwrap();
    incomplete.keys.remove(&key);
    assert!(changes::Publication::prepare(incomplete).is_err());
    apply(&mut storage, &[initial]);
    storage.business.validate_full_business_rows().unwrap();
    let mut damaged = storage.business.clone();
    damaged.keys.remove(&key).unwrap();
    assert!(
        damaged.validate_full_business_rows().is_err(),
        "cold admission cannot synthesize missing stable floors"
    );
}

#[test]
fn native_previous_scope_format_log_admission_requires_fresh_installation() {
    let (storage, _, _) = fixture();
    let record =
        crate::scope_storage::previous_profile_record_for_test(ScopeProfileActivation::new(
            storage.business.identity,
            fenced_transition_voter_set_digest(
                storage.business.identity,
                &storage.business.members,
            ),
        ));
    let crate::scope_storage::ScopeRow::Activation(certificate) =
        postcard::from_bytes(&record.payload.as_bytes()[5..]).unwrap()
    else {
        unreachable!()
    };
    let old = entry(
        &storage,
        2,
        SessionMutationIntent::ActivateScopeProfile(Box::new(certificate)),
    );
    let admission = log::NativeLog::validate_entry(&old, &storage.business).unwrap_err();
    let owned = owned::entry(&old).err().unwrap();
    for error in [admission, owned] {
        assert!(
            error.to_string().contains("fresh installation required"),
            "retained native log admission must retain the format reason: {error}"
        );
        assert_eq!(
            crate::consensus::storage::SessionConsensusStorageError::from_validation_error(error),
            crate::consensus::storage::SessionConsensusStorageError::FreshInstallationRequired
        );
    }
}

#[test]
fn native_scope_batch_publication_rejects_omitted_links_and_unchanged_child_generation() {
    let (mut storage, _, _) = fixture();
    let identity = storage.business.identity;
    let scope = ScopeId::new(
        identity,
        opc_types::TenantId::from_static("scope-links"),
        opc_types::NetworkFunctionKind::smf(),
        [1; 32],
    )
    .unwrap();
    let activate = entry(
        &storage,
        2,
        SessionMutationIntent::ActivateScopeProfile(Box::new(ScopeProfileActivation::new(
            identity,
            fenced_transition_voter_set_digest(identity, &storage.business.members),
        ))),
    );
    apply(&mut storage, &[activate]);
    let operation = entry(
        &storage,
        3,
        SessionMutationIntent::ScopeAuthority(Box::new(ScopeAuthorityCommand {
            request: ScopeAuthorityRequest::new(
                scope.clone(),
                [3; 16],
                0,
                ScopeAuthorityOperation::AdmitInitial {
                    execution: execution(1),
                },
            )
            .unwrap(),
        })),
    );
    let applied = apply(&mut storage, &[operation]);
    let Ok(SessionMutationOutcome::ScopeAuthority(Ok(checkpoint))) = &applied.responses[0].result
    else {
        panic!("scope admission")
    };
    let permit = checkpoint.state().unwrap().view.stamp().cloned().unwrap();
    let create = entry(
        &storage,
        4,
        SessionMutationIntent::ScopeBatch(Box::new(ScopeBatchCommand {
            request: ScopeBatchRequest::new(&permit, [1; 16], 0, vec![create(1, &[1])], vec![])
                .unwrap(),
        })),
    );
    let applied = apply(&mut storage, &[create]);
    let Ok(SessionMutationOutcome::ScopeBatch(Ok(outcome))) = &applied.responses[0].result else {
        panic!("scope child")
    };
    let version = outcome.rows()[0];
    let update = entry(
        &storage,
        5,
        SessionMutationIntent::ScopeBatch(Box::new(ScopeBatchCommand {
            request: ScopeBatchRequest::new(
                &permit,
                [2; 16],
                1,
                vec![ScopeChildMutation::CompareAndSet {
                    key: key(1),
                    expected: version,
                    value: value(2),
                    claims: vec![claim(2)],
                }],
                vec![],
            )
            .unwrap(),
        })),
    );
    let valid = storage
        .business
        .prepare(std::slice::from_ref(&update))
        .unwrap();
    changes::Publication::prepare(valid)
        .expect("positive control: complete staged transaction is publishable");
    let before = storage.business.business_digest_for_test().unwrap();
    for fault in 0..4 {
        let mut delta = storage
            .business
            .prepare(std::slice::from_ref(&update))
            .unwrap();
        match fault {
            0 => {
                delta
                    .keys
                    .remove(&scope_storage::claim_key(permit.namespace(), claim(1)).unwrap());
            }
            1 => {
                delta
                    .keys
                    .remove(&scope_storage::batch_key(&scope).unwrap());
            }
            2 => {
                let row = delta
                    .keys
                    .get_mut(&scope_storage::claim_key(permit.namespace(), claim(2)).unwrap())
                    .unwrap();
                let Some(ScopeRow::Claim(mut claim)) = decode(row).unwrap() else {
                    unreachable!()
                };
                claim.owner.as_mut().unwrap().child = key(2);
                row.record = Some(ScopeRow::Claim(claim).to_record().unwrap());
            }
            _ => {
                let row = delta
                    .keys
                    .get_mut(&scope_storage::child_key(permit.namespace(), key(1)).unwrap())
                    .unwrap();
                let Some(ScopeRow::Child(mut child)) = decode(row).unwrap() else {
                    unreachable!()
                };
                child.revision =
                    ScopeChildRevision::new(version.birth(), version.generation()).unwrap();
                row.record = Some(ScopeRow::Child(child).to_record().unwrap());
            }
        }
        assert!(
            changes::Publication::prepare(delta).is_err(),
            "fault {fault} cannot mint a business proof"
        );
        assert_eq!(storage.business.business_digest_for_test().unwrap(), before);
    }
}

#[test]
fn native_profile_three_rows_and_log_activation_require_fresh_installation() {
    let (storage, _, _) = fixture();
    let record =
        crate::scope_storage::previous_timed_profile_record_for_test(ScopeProfileActivation::new(
            storage.business.identity,
            fenced_transition_voter_set_digest(
                storage.business.identity,
                &storage.business.members,
            ),
        ));
    let error = crate::scope_storage::require_current_record_format(&record).unwrap_err();
    assert!(error.to_string().contains("fresh installation required"));
    let ScopeRow::Activation(certificate) =
        postcard::from_bytes(&record.payload.as_bytes()[5..]).unwrap()
    else {
        unreachable!()
    };
    let old = entry(
        &storage,
        2,
        SessionMutationIntent::ActivateScopeProfile(Box::new(certificate)),
    );
    for error in [
        log::NativeLog::validate_entry(&old, &storage.business).unwrap_err(),
        owned::entry(&old).err().unwrap(),
    ] {
        assert_eq!(
            crate::consensus::storage::SessionConsensusStorageError::from_validation_error(error),
            crate::consensus::storage::SessionConsensusStorageError::FreshInstallationRequired
        );
    }
}
