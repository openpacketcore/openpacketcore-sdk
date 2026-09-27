use super::*;
use crate::audit_authority::continuity::chain::ContinuityState;
use crate::audit_authority::continuity::checkpoint::CheckpointBody;
use crate::audit_authority::ledger::LedgerState;
use crate::audit_authority::*;
use crate::*;

fn keys() -> AuditKeyRing {
    AuditKeyRing::new(vec![
        super::super::AuditSigningKey::new(1, [31; 32]).unwrap(),
        super::super::AuditSigningKey::new(2, [32; 32]).unwrap(),
    ])
    .unwrap()
}

fn state(request: u8) -> (LedgerState, AuditCaller) {
    let identity = ConfigConsensusIdentity::new(
        ConfigConsensusClusterId::new("recipient-fixture").unwrap(),
        ConfigConsensusConfigurationId::from_bytes([11; 32]),
        ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    );
    let event = ProjectedAuditEvent::project(
        &AuditPrivacyKey::new([33; 32]).unwrap(),
        &ManagementAuditEventRecord::try_new(
            [request; 16],
            ManagementAuditInstant::try_new(1, 0, 1, ManagementAuditTimeSourceCode::NodeClock)
                .unwrap(),
            "synthetic-tenant",
            "synthetic-recipient",
            ManagementAuditTransportCode::Gnmi,
            ManagementAuditOperationCode::Update,
            ManagementAuditOutcomeCode::Denied,
            Some("denied"),
            ["/fixture:value"],
            None::<&str>,
        )
        .unwrap(),
    )
    .unwrap();
    let caller = event.caller;
    let mut state = LedgerState::new(
        identity,
        event.projection,
        AuditLedgerLimits::new(12, 4).unwrap(),
    );
    state.continuity = Some(ContinuityState::new(1));
    state
        .append_event(&AuditKey::new([34; 32]).unwrap(), event)
        .unwrap();
    state.seal_continuity(Some(&keys())).unwrap();
    (state, caller)
}

fn checkpoint(state: &LedgerState, acknowledgement: u8) -> AuditCheckpoint {
    let chain = state.continuity.as_ref().unwrap();
    AuditCheckpoint::issue(
        &keys(),
        CheckpointBody {
            version: 1,
            identity: state.identity,
            sequence: state.sequence,
            root_anchor: state.terminal,
            anchor: chain.terminal,
            epoch_at_sequence: chain.active_epoch,
            signing_epoch: chain.active_epoch,
            acknowledged_export: [acknowledgement; 32],
        },
    )
    .unwrap()
}

fn freeze(state: &LedgerState, caller: AuditCaller) -> AuditExportSession {
    AuditExportSession::freeze(
        state,
        Arc::new(keys()),
        caller,
        100,
        60,
        Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn recipient_progress_rejects_authentic_equal_sequence_replacement() {
    let (state, _) = state(1);
    let before = checkpoint(&state, 0);
    let conflict = checkpoint(&state, 1);
    before.verify(&keys(), state.identity).unwrap();
    conflict.verify(&keys(), state.identity).unwrap();
    state.matches_checkpoint(&before).unwrap();
    state.matches_checkpoint(&conflict).unwrap();
    assert_eq!(before.sequence(), conflict.sequence());
    assert_eq!(check_checkpoint_progress(&before, &before), Ok(()));
    assert_eq!(
        check_checkpoint_progress(&before, &conflict),
        Err(AuditAuthorityError::RollbackDetected),
        "COMPLETE_EQUAL_CHECKPOINT_BINDING"
    );
    let mut genesis = LedgerState::new(
        state.identity,
        state.projection,
        AuditLedgerLimits::new(12, 4).unwrap(),
    );
    genesis.continuity = Some(ContinuityState::new(1));
    let older = checkpoint(&genesis, 0);
    older.verify(&keys(), state.identity).unwrap();
    genesis.matches_checkpoint(&older).unwrap();
    assert_eq!(
        check_checkpoint_progress(&before, &older),
        Err(AuditAuthorityError::RollbackDetected),
        "CAPTURED_CHECKPOINT_CANNOT_REGRESS"
    );
}

#[test]
fn recipient_overlap_compares_authentic_root_anchor_and_epoch() {
    let (state, caller) = state(1);
    let session = freeze(&state, caller);
    let current = checkpoint(&state, 0);
    session.matches_checkpoint(&current).unwrap();
    state.matches_export_manifest(session.manifest()).unwrap();
    for field in ["root", "signing-anchor", "epoch"] {
        let mut changed = current.body.clone();
        match field {
            "root" => changed.root_anchor[0] ^= 1,
            "signing-anchor" => changed.anchor[0] ^= 1,
            "epoch" => changed.epoch_at_sequence = 2,
            _ => unreachable!(),
        }
        let signed = AuditCheckpoint::issue(&keys(), changed).unwrap();
        signed.verify(&keys(), state.identity).unwrap();
        assert_eq!(
            session.matches_checkpoint(&signed),
            Err(AuditAuthorityError::BindingMismatch),
            "FROZEN_CHECKPOINT_ANCHOR: {field}"
        );
        assert_eq!(
            state.matches_checkpoint(&signed),
            Err(AuditAuthorityError::BindingMismatch)
        );
    }
    let (different, _) = self::state(2);
    assert_eq!(
        different.matches_export_manifest(session.manifest()),
        Err(AuditAuthorityError::BindingMismatch),
        "CURRENT_LEDGER_OVERLAP"
    );
}

#[test]
fn recipient_fixed_time_and_wire_bounds() {
    let (state, caller) = state(1);
    let export = freeze(&state, caller);
    let client = AuditRecipientClient::new(state.identity, caller);
    let binding = AuditRecipientSessionBinding {
        request: client.request().clone(),
        manifest: export.manifest().clone(),
        checkpoint_at_freeze: checkpoint(&state, 0),
    };
    assert_eq!(binding.live(99), Err(AuditAuthorityError::Expired));
    assert_eq!(binding.live(100), Ok(()));
    assert_eq!(binding.live(159), Ok(()));
    assert_eq!(binding.live(160), Err(AuditAuthorityError::Expired));
    assert!(AuditRecipientSessionBinding::decode(&vec![b' '; MAX_MESSAGE_BYTES + 1]).is_err());
    assert!(AuditRecipientVerificationReport::decode(&vec![b' '; MAX_MESSAGE_BYTES + 1]).is_err());
    assert!(AuditRecipientVerificationRequest::decode(&vec![b' '; MAX_MESSAGE_BYTES + 1]).is_err());
}
