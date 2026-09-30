//! Target budget arithmetic and canonical bytes, using real signed originals.
//! The separate native test exercises the authoritative retained reducer.

use super::*;
use crate::audit_authority::continuity::chain::ContinuityState;
use crate::audit_authority::continuity::{AuditKeyRing, AuditSigningKey};
use crate::audit_authority::ledger::target_budget_probe::Observation;
use crate::audit_authority::ledger::{
    EntryPayload, LedgerState, RetainedTargetIntent, MAX_STATE_BYTES,
};
use crate::audit_authority::{AuditAuthorityError, AuditLedgerLimits, AuditOperationState};
use crate::consensus::audit::{canonical_state_len, encode_state, StoredLedger};

fn target_ledger() -> LedgerState {
    let original = signed_discard();
    let mut ledger = LedgerState::new(
        original.handle().body.identity,
        original.handle().body.event.projection,
        AuditLedgerLimits::new(4096, 1024).unwrap(),
    );
    ledger.continuity = Some(ContinuityState::new(1));
    ledger
        .admit_target(&AuditKey::new([0x24; 32]).unwrap(), original.command(), 100)
        .unwrap();
    ledger
}

fn exact_encoding(ledger: &LedgerState) {
    let key = AuditKey::new([0x24; 32]).unwrap();
    let stored = StoredLedger {
        identity: ledger.identity,
        ledger: Some(ledger.clone()),
    };
    let old = serde_json::to_vec(&stored).unwrap();
    assert_eq!(canonical_state_len(&stored).unwrap(), old.len());
    let old_mac = crate::audit_authority::ledger::authenticate(
        &key,
        crate::audit_authority::ledger::STATE_DOMAIN,
        &stored,
    )
    .unwrap();
    let (encoded, mac) = encode_state(&stored, &key).unwrap();
    assert_eq!(encoded, old, "TARGET_LEDGER_BUDGET_CANONICAL_BYTES");
    assert_eq!(mac, old_mac, "TARGET_LEDGER_BUDGET_CANONICAL_MAC");
}

#[test]
fn target_ledger_budget_preserves_legacy_target_bytes_and_original_result() {
    let original = signed_discard();
    let key = AuditKey::new([0x24; 32]).unwrap();
    let mut legacy = LedgerState::new(
        original.handle().body.identity,
        original.handle().body.event.projection,
        AuditLedgerLimits::new(12, 4).unwrap(),
    );
    exact_encoding(&legacy);
    legacy.admit(&key, original.handle(), 100).unwrap();
    exact_encoding(&legacy);
    let observation = Observation::start();
    legacy.check_target_capacity().unwrap();
    assert_eq!(
        observation.sample().checks,
        0,
        "legacy bypass stays unchanged"
    );
    drop(observation);

    let mut ledger = target_ledger();
    let observation = Observation::start();
    ledger.check_target_capacity().unwrap();
    let sample = observation.sample();
    assert_eq!(sample.checks, 1, "TARGET_LEDGER_BUDGET_PROBE_SETUP");
    assert_eq!(
        sample.operations_started, 1,
        "TARGET_LEDGER_BUDGET_PROBE_SETUP"
    );
    assert_eq!(sample.stopped_before_operations, 0);
    drop(observation);
    exact_encoding(&ledger);
    let unchanged = serde_json::to_vec(&ledger).unwrap();
    // Exact acknowledged originals remain replayable even after their original
    // expiry. No new identity or extended expiry is issued by this retry.
    ledger.admit_target(&key, original.command(), 160).unwrap();
    assert_eq!(serde_json::to_vec(&ledger).unwrap(), unchanged);
    ledger
        .resolve(&key, original.handle(), AuditOperationState::Rejected)
        .unwrap();
    ledger
        .acknowledge_terminal(&key, original.handle())
        .unwrap();
    let keys = AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x61; 32]).unwrap()]).unwrap();
    ledger.seal_continuity(Some(&keys)).unwrap();
    ledger.validate(&key, ledger.identity).unwrap();
    ledger.validate_continuity(Some(&keys)).unwrap();
    exact_encoding(&ledger);
    let retained = serde_json::to_vec(&ledger).unwrap();
    let restored: LedgerState = serde_json::from_slice(&retained).unwrap();
    assert_eq!(
        restored
            .recover_target(&key, original.handle(), original.command().effect.caller)
            .unwrap(),
        original
    );
    let receipt = restored
        .lookup(&key, original.handle(), original.command().effect.caller)
        .unwrap()
        .unwrap();
    assert_eq!(receipt.state(), AuditOperationState::Rejected);
    assert!(receipt.terminal_recorded());
}

#[test]
fn target_ledger_budget_keeps_exact_reservation_and_slack_boundary() {
    let mut ledger = target_ledger();
    let reserved = ledger
        .operations
        .iter()
        .map(|op| op.reserved)
        .sum::<usize>();
    let unsealed = ledger.entries.len() - ledger.continuity.as_ref().unwrap().rows.len();
    assert_eq!((reserved, unsealed), (2, 1));
    let charges = reserved * 32 * 1024 + unsealed * 1024 + 16 * 1024;
    let original_len = serde_json::to_vec(&ledger).unwrap().len();
    let padding = MAX_STATE_BYTES.checked_sub(charges + original_len).unwrap();
    // These copies isolate byte arithmetic, not authentication: only the real
    // native test persists recovery payloads. ASCII padding has exact JSON cost.
    let EntryPayload::TargetIntent(retained) = &mut ledger.entries[0].payload else {
        panic!("real target admission must retain TargetIntent");
    };
    std::sync::Arc::make_mut(&mut retained.recovery).extend(std::iter::repeat_n('x', padding));
    let encoded = serde_json::to_vec(&ledger).unwrap();
    assert_eq!(encoded.len() + charges, MAX_STATE_BYTES);
    assert_eq!(
        ledger.check_target_capacity(),
        Ok(()),
        "TARGET_LEDGER_BUDGET_EXACT_LIMIT"
    );
    let EntryPayload::TargetIntent(retained) = &mut ledger.entries[0].payload else {
        unreachable!()
    };
    std::sync::Arc::make_mut(&mut retained.recovery).push('x');
    let before = serde_json::to_vec(&ledger).unwrap();
    assert_eq!(before.len() + charges, MAX_STATE_BYTES + 1);
    assert_eq!(
        ledger.check_target_capacity(),
        Err(AuditAuthorityError::Full),
        "TARGET_LEDGER_BUDGET_RESERVED_FULL"
    );
    assert_eq!(serde_json::to_vec(&ledger).unwrap(), before);
}

#[test]
fn retained_recovery_preserves_string_json_codec_and_mac() {
    // This reference has the previous owned String field. It does not use the
    // new field adapter, so encoding both sides through that adapter cannot
    // hide a changed scalar representation or authenticator transcript.
    #[derive(serde::Serialize, serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyRecovery {
        #[serde(deserialize_with = "crate::audit_authority::ledger::deserialize_target_handle")]
        handle: AuditOperationHandle,
        recovery: String,
    }

    let original = signed_discard();
    let key = AuditKey::new([0x24; 32]).unwrap();
    let command = String::from_utf8(original.encode().unwrap()).unwrap();
    for recovery in [command.as_str(), "", "quoted \"text\" \\ \0\n\r\t café 🦀"] {
        let previous = LegacyRecovery {
            handle: original.handle().clone(),
            recovery: recovery.to_owned(),
        };
        let current = RetainedTargetIntent {
            handle: previous.handle.clone(),
            recovery: previous.recovery.clone().into(),
        };
        let json = serde_json::to_vec(&previous).unwrap();
        assert_eq!(serde_json::to_vec(&current).unwrap(), json);
        let wire = opc_consensus::encode_bounded(&previous).unwrap();
        assert_eq!(opc_consensus::encode_bounded(&current).unwrap(), wire);
        assert_eq!(
            crate::audit_authority::ledger::authenticate(
                &key,
                crate::audit_authority::ledger::STATE_DOMAIN,
                &current,
            )
            .unwrap(),
            crate::audit_authority::ledger::authenticate(
                &key,
                crate::audit_authority::ledger::STATE_DOMAIN,
                &previous,
            )
            .unwrap(),
        );
        let from_json: RetainedTargetIntent = serde_json::from_slice(&json).unwrap();
        let from_wire: RetainedTargetIntent = opc_consensus::decode_bounded(&wire).unwrap();
        for decoded in [from_json, from_wire] {
            assert_eq!(decoded.handle, previous.handle);
            assert_eq!(decoded.recovery.as_str(), previous.recovery);
        }
        let sequence = serde_json::json!([previous.handle, previous.recovery]);
        let from_sequence: RetainedTargetIntent = serde_json::from_value(sequence).unwrap();
        assert_eq!(from_sequence.recovery.as_str(), recovery);
    }

    let handle = serde_json::to_string(original.handle()).unwrap();
    for recovery in ["null", "7", "false", "[]", "{}"] {
        let json = format!("{{\"handle\":{handle},\"recovery\":{recovery}}}");
        assert!(serde_json::from_str::<LegacyRecovery>(&json).is_err());
        assert!(serde_json::from_str::<RetainedTargetIntent>(&json).is_err());
    }
    for suffix in [",\"unknown\":0", ",\"recovery\":\"duplicate\""] {
        let json = format!("{{\"handle\":{handle},\"recovery\":\"original\"{suffix}}}");
        assert!(serde_json::from_str::<LegacyRecovery>(&json).is_err());
        assert!(serde_json::from_str::<RetainedTargetIntent>(&json).is_err());
    }
}

#[test]
fn retained_recovery_snapshot_keeps_original_authentication_and_failed_admission() {
    let original = signed_discard();
    let key = AuditKey::new([0x24; 32]).unwrap();
    let keys = AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x61; 32]).unwrap()]).unwrap();
    let mut ledger = target_ledger();
    ledger
        .resolve(&key, original.handle(), AuditOperationState::Rejected)
        .unwrap();
    ledger
        .acknowledge_terminal(&key, original.handle())
        .unwrap();
    ledger.seal_continuity(Some(&keys)).unwrap();
    let before = serde_json::to_vec(&ledger).unwrap();
    let mut candidate = ledger.clone();
    let EntryPayload::TargetIntent(retained) = &ledger.entries[0].payload else {
        panic!("original target recovery")
    };
    let EntryPayload::TargetIntent(copied) = &candidate.entries[0].payload else {
        panic!("copied target recovery")
    };
    assert!(std::sync::Arc::ptr_eq(&retained.recovery, &copied.recovery));
    assert_eq!(serde_json::to_vec(&candidate).unwrap(), before);

    let mut collision = original.clone();
    collision.command_mut().handle.body.nonce = [0x76; 16];
    resign_target(&mut collision);
    assert!(matches!(
        candidate.admit_target(&key, collision.command(), 100),
        Err(
            crate::audit_authority::ledger::LedgerMutationError::Authority(
                AuditAuthorityError::BindingMismatch
            )
        ),
    ));
    assert_eq!(serde_json::to_vec(&candidate).unwrap(), before);

    let EntryPayload::TargetIntent(copied) = &mut candidate.entries[0].payload else {
        unreachable!()
    };
    // A test-only modification detaches this snapshot. Its malformed original
    // still fails both authenticators, while the pinned original stays valid.
    std::sync::Arc::make_mut(&mut copied.recovery).push(' ');
    assert!(candidate.validate(&key, ledger.identity).is_err());
    assert!(candidate.validate_continuity(Some(&keys)).is_err());
    assert_eq!(serde_json::to_vec(&ledger).unwrap(), before);
    ledger.validate(&key, ledger.identity).unwrap();
    ledger.validate_continuity(Some(&keys)).unwrap();
    assert_eq!(
        ledger
            .recover_target(&key, original.handle(), original.command().effect.caller)
            .unwrap(),
        original,
    );
    exact_encoding(&ledger);
}
