use super::chain::ContinuityState;
use super::checkpoint::CheckpointBody;
use super::*;
use crate::audit_authority::ledger::{HandleBody, LedgerState};
use crate::audit_authority::*;
use crate::*;

fn identity() -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("audit-continuity-fixture").unwrap(),
        ConfigConsensusConfigurationId::from_bytes([7; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    )
}
fn root() -> AuditKey {
    AuditKey::new([8; 32]).unwrap()
}
fn keys() -> AuditKeyRing {
    AuditKeyRing::new(vec![
        AuditSigningKey::new(1, [9; 32]).unwrap(),
        AuditSigningKey::new(2, [10; 32]).unwrap(),
    ])
    .unwrap()
}
fn event() -> ProjectedAuditEvent {
    ProjectedAuditEvent::project(
        &AuditPrivacyKey::new([11; 32]).unwrap(),
        &ManagementAuditEventRecord::try_new(
            [1; 16],
            ManagementAuditInstant::try_new(100, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
                .unwrap(),
            "synthetic-tenant",
            "synthetic-principal",
            ManagementAuditTransportCode::Gnmi,
            ManagementAuditOperationCode::Update,
            ManagementAuditOutcomeCode::Intent,
            None::<&str>,
            ["/fixture:value"],
            None::<&str>,
        )
        .unwrap(),
    )
    .unwrap()
}
fn ledger() -> LedgerState {
    let mut ledger = LedgerState::new(
        identity(),
        event().projection,
        AuditLedgerLimits::new(12, 4).unwrap(),
    );
    ledger.continuity = Some(ContinuityState::new(1));
    ledger
}
fn append(ledger: &mut LedgerState) {
    ledger.append_event(&root(), event()).unwrap();
    ledger.seal_continuity(Some(&keys())).unwrap();
}
fn checkpoint(ledger: &LedgerState) -> AuditCheckpoint {
    let chain = ledger.continuity.as_ref().unwrap();
    AuditCheckpoint::issue(
        &keys(),
        CheckpointBody {
            version: 1,
            identity: identity(),
            sequence: ledger.sequence,
            root_anchor: ledger.terminal,
            anchor: chain.terminal,
            epoch_at_sequence: chain.active_epoch,
            signing_epoch: chain.active_epoch,
            acknowledged_export: [12; 32],
        },
    )
    .unwrap()
}
fn freeze(ledger: &LedgerState) -> AuditExportSession {
    AuditExportSession::freeze(
        ledger,
        Arc::new(keys()),
        event().caller,
        110,
        100,
        Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap(),
    )
    .unwrap()
}
fn verifier(session: &AuditExportSession) -> AuditExportVerifier {
    AuditExportVerifier::new(
        Arc::new(keys()),
        session.manifest().clone(),
        identity(),
        event().caller,
        111,
    )
    .unwrap()
}

#[test]
fn keys_reject_material_reuse_and_do_not_activate_by_mounting() {
    assert!(AuditSigningKey::new(0, [9; 32]).is_err());
    assert!(AuditSigningKey::new(1, [0; 32]).is_err());
    assert!(AuditKeyRing::new(vec![
        AuditSigningKey::new(1, [9; 32]).unwrap(),
        AuditSigningKey::new(2, [9; 32]).unwrap()
    ])
    .is_err());
    let root_reuse = AuditKeyRing::new(vec![AuditSigningKey::new(99, [8; 32]).unwrap()]).unwrap();
    assert!(root_reuse.separate_from(&root()).is_err());
    let mut state = ledger();
    append(&mut state);
    state.validate_continuity(Some(&keys())).unwrap();
    assert_eq!(state.continuity.as_ref().unwrap().active_epoch, 1);
    let old_only = AuditKeyRing::new(vec![AuditSigningKey::new(1, [9; 32]).unwrap()]).unwrap();
    state.validate_continuity(Some(&old_only)).unwrap();
    assert_eq!(
        state.validate_continuity(None),
        Err(AuditAuthorityError::KeyUnavailable)
    );
}

#[test]
fn cross_signed_rotation_requires_both_keys_and_exact_prefix() {
    let mut state = ledger();
    append(&mut state);
    let before = state.clone();
    let transition = AuditKeyTransition::prepare(
        &keys(),
        identity(),
        state.sequence,
        state.continuity.as_ref().unwrap().terminal,
        1,
        2,
    )
    .unwrap();
    assert_eq!(
        state.continuity.as_ref().unwrap().active_epoch,
        1,
        "preparation grants no authority"
    );
    let mut tampered = serde_json::to_value(&transition).unwrap();
    tampered["new_proof"][0] = serde_json::json!(77);
    let tampered = serde_json::from_value(tampered).unwrap();
    assert!(state.transition_key(&root(), &keys(), &tampered).is_err());
    assert!(state == before);
    state.transition_key(&root(), &keys(), &transition).unwrap();
    state.transition_key(&root(), &keys(), &transition).unwrap();
    assert_eq!(state.sequence, 2);
    append(&mut state);
    assert_eq!(state.continuity.as_ref().unwrap().active_epoch, 2);
    state.validate(&root(), identity()).unwrap();
    state.validate_continuity(Some(&keys())).unwrap();
    let new_only = AuditKeyRing::new(vec![AuditSigningKey::new(2, [10; 32]).unwrap()]).unwrap();
    assert_eq!(
        state.validate_continuity(Some(&new_only)),
        Err(AuditAuthorityError::KeyUnavailable)
    );
    let wrong = AuditKeyRing::new(vec![
        AuditSigningKey::new(1, [9; 32]).unwrap(),
        AuditSigningKey::new(2, [77; 32]).unwrap(),
    ])
    .unwrap();
    assert!(state.validate_continuity(Some(&wrong)).is_err());
    let mut diverged = before;
    append(&mut diverged);
    assert!(diverged
        .transition_key(&root(), &keys(), &transition)
        .is_err());
}

#[test]
fn frozen_export_rejects_malicious_pages_and_incomplete_ranges() {
    let mut state = ledger();
    append(&mut state);
    append(&mut state);
    let transition = AuditKeyTransition::prepare(
        &keys(),
        identity(),
        state.sequence,
        state.continuity.as_ref().unwrap().terminal,
        1,
        2,
    )
    .unwrap();
    state.transition_key(&root(), &keys(), &transition).unwrap();
    append(&mut state);
    let session = freeze(&state);
    let first = session.page_at(None, 2, event().caller, 111).unwrap();
    let last = session
        .page_at(first.next_cursor(), 2, event().caller, 111)
        .unwrap();
    let mut valid = verifier(&session);
    valid.accept(&first).unwrap();
    valid.accept(&last).unwrap();
    valid.finish().unwrap();
    let mut incomplete = verifier(&session);
    incomplete.accept(&first).unwrap();
    assert!(incomplete.finish().is_err());
    let mut repeated = verifier(&session);
    repeated.accept(&first).unwrap();
    assert!(repeated.accept(&first).is_err());
    assert!(repeated.accept(&last).is_err(), "failure is sticky");
    assert!(verifier(&session).accept(&last).is_err());
    for mutation in 0..7 {
        let mut page = serde_json::to_value(&first).unwrap();
        match mutation {
            0 => {
                page["rows"].as_array_mut().unwrap().remove(0);
            }
            1 => {
                page["rows"].as_array_mut().unwrap().swap(0, 1);
            }
            2 => {
                page["rows"][1] = page["rows"][0].clone();
            }
            3 => {
                page["rows"][0]["entry"]["sequence"] = serde_json::json!(55);
            }
            4 => {
                page["rows"][0]["proof"]["signature"][0] = serde_json::json!(88);
            }
            5 => {
                page["next"] = serde_json::Value::Null;
            }
            _ => {
                // Changing a signed row field must fail even when all sequence,
                // predecessor, cursor and signature bytes are left untouched.
                page["rows"][0]["entry"]["key_epoch"] = serde_json::json!(55);
            }
        }
        let altered = AuditExportPage::decode(&serde_json::to_vec(&page).unwrap()).unwrap();
        assert!(
            verifier(&session).accept(&altered).is_err(),
            "mutation {mutation}"
        );
    }
    let another = freeze(&state);
    assert!(verifier(&another).accept(&first).is_err());
    assert!(another
        .page_at(first.next_cursor(), 2, event().caller, 111)
        .is_err());
    assert!(matches!(
        session.page_at(None, 2, event().caller, 210),
        Err(AuditAuthorityError::Expired)
    ));
    assert!(matches!(
        session.page_at(None, 2, event().caller, 109),
        Err(AuditAuthorityError::Expired)
    ));
    append(&mut state);
    assert_eq!(
        session
            .page_at(first.next_cursor(), 2, event().caller, 111)
            .unwrap(),
        last,
        "live appends cannot change the frozen range"
    );
}

#[test]
fn pruning_requires_export_checkpoint_and_expired_whole_operations_before_key_retirement() {
    let mut state = ledger();
    let event = event();
    let handle = AuditOperationHandle::issue(
        HandleBody {
            version: 1,
            identity: identity(),
            binding: AuditOperationBinding::project(
                &AuditPrivacyKey::new([11; 32]).unwrap(),
                &event,
                0,
                b"fixture",
            )
            .unwrap(),
            event,
            issued_at: 100,
            expires_at: 200,
            nonce: [13; 16],
            key_epoch: 1,
            mutation: None,
        },
        &root(),
    )
    .unwrap();
    state.admit(&root(), &handle, 110).unwrap();
    state.seal_continuity(Some(&keys())).unwrap();
    let unresolved = checkpoint(&state);
    state.continuity.as_mut().unwrap().checkpoint = Some(unresolved.clone());
    assert_eq!(
        state.prune(&keys(), 1, &unresolved, 201),
        Err(AuditAuthorityError::BindingMismatch),
        "a continuity checkpoint alone is not export acknowledgement"
    );
    state.continuity.as_mut().unwrap().export_checkpoint = Some(unresolved.clone());
    assert_eq!(
        state.prune(&keys(), 1, &unresolved, 201),
        Err(AuditAuthorityError::Full)
    );
    state
        .resolve(&root(), &handle, AuditOperationState::Rejected)
        .unwrap();
    state.acknowledge_terminal(&root(), &handle).unwrap();
    state.seal_continuity(Some(&keys())).unwrap();
    let complete = checkpoint(&state);
    state.continuity.as_mut().unwrap().checkpoint = Some(complete.clone());
    state.continuity.as_mut().unwrap().export_checkpoint = Some(complete.clone());
    assert_eq!(
        state.prune(&keys(), 3, &complete, 199),
        Err(AuditAuthorityError::Full)
    );
    assert_eq!(
        state.prune(&keys(), 2, &complete, 201),
        Err(AuditAuthorityError::Full),
        "no split operation"
    );
    let transition = AuditKeyTransition::prepare(
        &keys(),
        identity(),
        state.sequence,
        state.continuity.as_ref().unwrap().terminal,
        1,
        2,
    )
    .unwrap();
    state.transition_key(&root(), &keys(), &transition).unwrap();
    let rotated = checkpoint(&state);
    assert!(
        state.prune(&keys(), 4, &rotated, 201).is_err(),
        "unacknowledged export cannot prune"
    );
    state.continuity.as_mut().unwrap().checkpoint = Some(rotated.clone());
    assert_eq!(
        state.prune(&keys(), 4, &rotated, 201),
        Err(AuditAuthorityError::BindingMismatch),
        "a later continuity checkpoint cannot extend export retention authority"
    );
    state.continuity.as_mut().unwrap().export_checkpoint = Some(rotated.clone());
    state.prune(&keys(), 4, &rotated, 201).unwrap();
    state.validate(&root(), identity()).unwrap();
    let new_only = AuditKeyRing::new(vec![AuditSigningKey::new(2, [10; 32]).unwrap()]).unwrap();
    state.validate_continuity(Some(&new_only)).unwrap();
    assert_eq!(state.floor, 4);
    assert!(state.operations.is_empty());
    assert!(state
        .lookup(&root(), &handle, handle.body.binding.caller)
        .unwrap()
        .is_none());
    assert_eq!(
        state.admit(&root(), &handle, 201),
        Err(AuditAuthorityError::Expired)
    );
}

#[test]
fn checkpoint_detects_coherent_local_rollback_and_tampering() {
    let mut state = ledger();
    append(&mut state);
    let old = state.clone();
    append(&mut state);
    let checkpoint = checkpoint(&state);
    assert_eq!(
        old.matches_checkpoint(&checkpoint),
        Err(AuditAuthorityError::RollbackDetected)
    );
    checkpoint.verify(&keys(), identity()).unwrap();
    let mut bytes = serde_json::to_value(&checkpoint).unwrap();
    bytes["body"]["sequence"] = serde_json::json!(1);
    let altered = AuditCheckpoint::decode(&serde_json::to_vec(&bytes).unwrap()).unwrap();
    assert!(altered.verify(&keys(), identity()).is_err());
}
