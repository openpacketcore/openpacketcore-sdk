//! Target budget arithmetic and canonical bytes, using real signed originals.
//! The separate native test exercises the authoritative retained reducer.

use super::*;
use crate::audit_authority::continuity::chain::ContinuityState;
use crate::audit_authority::continuity::{AuditKeyRing, AuditSigningKey};
use crate::audit_authority::ledger::target_budget_probe::Observation;
use crate::audit_authority::ledger::{EntryPayload, LedgerState, MAX_STATE_BYTES};
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
        .admit_target(&AuditKey::new([0x24; 32]).unwrap(), &original, 100)
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
    ledger.admit_target(&key, &original, 160).unwrap();
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
            .recover_target(&key, original.handle(), original.effect.caller)
            .unwrap(),
        original
    );
    let receipt = restored
        .lookup(&key, original.handle(), original.effect.caller)
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
    retained.recovery.extend(std::iter::repeat_n('x', padding));
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
    retained.recovery.push('x');
    let before = serde_json::to_vec(&ledger).unwrap();
    assert_eq!(before.len() + charges, MAX_STATE_BYTES + 1);
    assert_eq!(
        ledger.check_target_capacity(),
        Err(AuditAuthorityError::Full),
        "TARGET_LEDGER_BUDGET_RESERVED_FULL"
    );
    assert_eq!(serde_json::to_vec(&ledger).unwrap(), before);
}
