//! The landed index must preserve operation ordinals across retained payloads.

use super::*;
use crate::audit_authority::{
    EmptyCommitGuard, PreparedNetconfEmptyCommit, PreparedTargetMutation,
};

fn target(number: u64) -> PreparedTargetMutation {
    let mut body = handle(number, ManagementAuditOutcomeCode::Intent).body;
    body.event.transport = ManagementAuditTransportCode::NetconfTls;
    body.event.operation = ManagementAuditOperationCode::Exec;
    body.mutation = Some([0xC1; 32]);
    let operation = AuditOperationHandle::issue(body, &key()).unwrap();
    let mut prepared: PreparedTargetMutation = serde_json::from_value(serde_json::json!({
        "handle": operation,
        "effect": {
            "format": 1,
            "authority": identity(),
            "profile_incarnation": vec![0xC2_u8; 16],
            "device_incarnation": vec![0xC3_u8; 16],
            "caller": operation.body.binding.caller,
            "request": operation.body.binding.request,
            "action": 5,
            "destination": {"candidate": {"generation": {"authority": identity(), "value": 0}}},
            "source": null,
            "lock": {"datastore": 1, "incarnation": 1, "session": vec![0xC4_u8; 16], "requester": vec![0xC4_u8; 16]},
            "expires_at": 160,
            "encrypted_payload": null,
            "resolution": null
        }
    }))
    .unwrap();
    let mut body = prepared.handle().body.clone();
    body.mutation = Some(
        authenticate(
            &key(),
            b"openpacketcore/management-audit/netconf-target/v1\0",
            &prepared.command().effect,
        )
        .unwrap(),
    );
    prepared.command_mut().handle = AuditOperationHandle::issue(body, &key()).unwrap();
    prepared.command().verify_effect(&key()).unwrap();
    prepared
}

fn empty_commit(number: u64) -> PreparedNetconfEmptyCommit {
    let mut body = handle(number, ManagementAuditOutcomeCode::Success).body;
    body.event.transport = ManagementAuditTransportCode::NetconfTls;
    body.event.operation = ManagementAuditOperationCode::Commit;
    body.event.transaction = None;
    let handle = AuditOperationHandle::issue(body, &key()).unwrap();
    let guard = EmptyCommitGuard {
        format: 1,
        authority: identity(),
        profile_incarnation: [0xC2; 16],
        device_incarnation: [0xC3; 16],
        caller: handle.body.binding.caller,
        session: [0xC4; 16],
        candidate_generation: 0,
        state_digest: [0xC5; 32],
        running_base: 0,
    };
    let guard_mac = authenticate(
        &key(),
        b"openpacketcore/management-audit/netconf-empty-commit/v1\0",
        &(&handle, &guard),
    )
    .unwrap();
    let prepared = PreparedNetconfEmptyCommit {
        handle,
        guard,
        guard_mac,
    };
    prepared
        .verify(&key(), identity(), prepared.guard.caller)
        .unwrap();
    prepared
}

fn mixed() -> LedgerState {
    let mut ledger = empty();
    ledger.continuity = Some(ContinuityState::new(1));
    ledger
        .admit(&key(), &handle(1, ManagementAuditOutcomeCode::Intent), 110)
        .unwrap();
    ledger
        .admit_empty_commit(&key(), &empty_commit(2), 110)
        .unwrap();
    ledger
        .admit_target(&key(), target(3).command(), 110)
        .unwrap();
    ledger
        .admit(&key(), &handle(4, ManagementAuditOutcomeCode::Intent), 110)
        .unwrap();
    // Reverse resolution makes outcome lookup cross both retained variants.
    for number in [4, 3, 1] {
        let handle = ledger.operations[number - 1].handle.clone();
        ledger
            .resolve(&key(), &handle, AuditOperationState::Rejected)
            .unwrap();
        ledger.acknowledge_terminal(&key(), &handle).unwrap();
    }
    ledger
}

#[test]
fn indexed_validation_retained_payloads_share_authenticated_prefix_ordinals() {
    let ledger = mixed();
    let before = serde_json::to_vec(&ledger).unwrap();
    let owners = crate::consensus::config_capacity_simultaneous_working_tests::ledger::ObservationGuard::start(Default::default());
    let probe = validation_probe::Probe::start(None);
    ledger
        .validate(&key(), identity())
        .expect("LEDGER_VALIDATION_RETAINED_ORDINALS");
    let counts = probe.counts();
    assert_eq!(counts.intents, 4);
    assert_eq!(counts.capacity, 4);
    assert_eq!(counts.reserves, 1);
    assert_eq!(counts.live_indexes, 0);
    drop(probe);
    let owners = owners.finish();
    assert_eq!(
        owners.validation_peak.validation_index, counts.heap_bytes,
        "LEDGER_VALIDATION_INDEX_OWNER"
    );
    assert_eq!(
        owners.validation_peak.total,
        owners.validation_peak.derived
            + owners.validation_peak.authentication
            + owners.validation_peak.validation_index,
        "live validation scratch must participate in the same simultaneous sample"
    );
    let index = validation_index::ValidationIndex::new(&ledger.entries).unwrap();
    for (ordinal, operation) in ledger.operations.iter().enumerate() {
        assert!(!index.duplicate_request(ordinal).unwrap());
        assert_eq!(index.prior_operation(&operation.handle.mac, ordinal), None);
        assert_eq!(
            index.prior_operation(&operation.handle.mac, ordinal + 1),
            Some(ordinal)
        );
    }
    let restored: LedgerState = serde_json::from_slice(&before).unwrap();
    restored.validate(&key(), identity()).unwrap();
    let original = target(3);
    assert_eq!(
        restored
            .recover_target(
                &key(),
                original.handle(),
                original.handle().body.binding.caller
            )
            .unwrap(),
        original
    );
    assert_eq!(serde_json::to_vec(&ledger).unwrap(), before);
}

#[test]
fn indexed_validation_retained_payloads_detect_cross_variant_duplicate_requests() {
    let target = target(1);
    let payloads = [
        EntryPayload::Intent(Box::new(handle(1, ManagementAuditOutcomeCode::Intent))),
        EntryPayload::TargetIntent(Box::new(RetainedTargetIntent {
            handle: target.handle().clone(),
            recovery: Arc::new(
                String::from_utf8(
                    target
                        .command()
                        .encode_retained(&key(), identity())
                        .unwrap(),
                )
                .unwrap(),
            ),
        })),
        EntryPayload::EmptyCommit(Box::new(empty_commit(1))),
    ];
    for first in &payloads {
        for second in &payloads {
            let mut ledger = empty();
            ledger.continuity = Some(ContinuityState::new(1));
            ledger.append(&key(), first.clone()).unwrap();
            ledger.append(&key(), second.clone()).unwrap();
            let index = validation_index::ValidationIndex::new(&ledger.entries).unwrap();
            assert!(!index.duplicate_request(0).unwrap());
            assert!(index.duplicate_request(1).unwrap());
            assert_eq!(
                ledger.validate(&key(), identity()),
                Err(AuditAuthorityError::BindingMismatch)
            );
        }
    }
}

#[test]
fn indexed_validation_retained_payloads_keep_authentication_and_order_checks() {
    let original = mixed();
    let mutations: &[MutationCase] = &[
        ("target recovery is independently authenticated", |ledger| {
            let EntryPayload::TargetIntent(retained) = &mut ledger.entries[2].payload else {
                panic!("target fixture");
            };
            retained.recovery = Arc::new("invalid retained original".into());
        }),
        ("empty guard is independently authenticated", |ledger| {
            let EntryPayload::EmptyCommit(prepared) = &mut ledger.entries[1].payload else {
                panic!("empty commit fixture");
            };
            prepared.guard_mac[0] ^= 1;
        }),
        ("retained payloads require continuity", |ledger| {
            ledger.continuity = None
        }),
        ("Outcome cannot reference future target", |ledger| {
            ledger.entries[0].payload = EntryPayload::Outcome {
                operation: ledger.operations[2].handle.mac,
                state: AuditOperationState::Rejected,
            };
        }),
        ("Terminal cannot reference future empty commit", |ledger| {
            ledger.entries[0].payload = EntryPayload::Terminal {
                operation: ledger.operations[1].handle.mac,
            };
        }),
        ("retained operations preserve stored order", |ledger| {
            ledger.operations.swap(1, 2)
        }),
        ("retained operations preserve reservations", |ledger| {
            ledger.operations[2].reserved = 1
        }),
    ];
    for (label, mutate) in mutations {
        let mut changed = original.clone();
        mutate(&mut changed);
        resign(&mut changed);
        assert!(changed.validate(&key(), identity()).is_err(), "{label}");
    }
    original.validate(&key(), identity()).unwrap();
}

#[test]
fn indexed_validation_retained_payloads_keep_fallible_index_allocation() {
    let ledger = mixed();
    let before = serde_json::to_vec(&ledger).unwrap();
    let probe = validation_probe::Probe::start(Some(0));
    assert_eq!(
        ledger.validate(&key(), identity()),
        Err(AuditAuthorityError::Unavailable)
    );
    assert!(probe.injected());
    assert_eq!(probe.counts().reserves, 1);
    assert_eq!(probe.counts().live_indexes, 0);
    drop(probe);
    assert_eq!(serde_json::to_vec(&ledger).unwrap(), before);
    ledger.validate(&key(), identity()).unwrap();
}
