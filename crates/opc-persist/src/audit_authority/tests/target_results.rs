//! Target receipts use the existing ledger and checkpoint obligations.
//! This exercises ledger primitives, not NETCONF target effect application.

use super::*;
use crate::audit_authority::continuity::chain::ContinuityState;
use crate::audit_authority::continuity::checkpoint::CheckpointBody;
use crate::audit_authority::continuity::{AuditCheckpoint, AuditKeyRing, AuditSigningKey};
use crate::audit_authority::receipt::AuthenticatedAuditReceipt;

fn target_handle(nonce: u8) -> AuditOperationHandle {
    let mut body = handle(nonce).body;
    body.mutation = Some([0x53; 32]);
    body.event.transport = ManagementAuditTransportCode::Netconf;
    body.event.request = AuditToken::from_keyed_projection([nonce; 32]).unwrap();
    body.binding.request = body.event.request;
    AuditOperationHandle::issue(body, &key()).unwrap()
}

fn outcomes() -> [NetconfAppliedOutcome; 8] {
    let generation = CandidateGeneration {
        authority: identity(),
        value: 1,
    };
    let revision = StartupRevision {
        authority: identity(),
        value: 2,
    };
    let pending = NetconfPendingConfirmation {
        authority: identity(),
        value: [0x54; 16],
    };
    [
        NetconfAppliedOutcome::Candidate { generation },
        NetconfAppliedOutcome::Startup { revision },
        NetconfAppliedOutcome::CopiedRunning { running_version: 8 },
        NetconfAppliedOutcome::Promoted {
            running_version: 8,
            retired_generation: generation,
        },
        NetconfAppliedOutcome::Tentative {
            running_version: 8,
            retired_generation: generation,
            pending,
        },
        NetconfAppliedOutcome::Confirmed { pending },
        NetconfAppliedOutcome::RolledBack {
            running_version: 8,
            pending,
        },
        NetconfAppliedOutcome::Lifecycle {
            incarnation: NetconfIncarnation {
                authority: identity(),
                value: [0x55; 16],
            },
        },
    ]
}

fn state(outcome: NetconfAppliedOutcome) -> AuditOperationState {
    AuditOperationState::TargetV1(
        NetconfTargetResult::new(identity(), [0x56; 16], [0x57; 32], outcome).unwrap(),
    )
}

fn new_ledger() -> LedgerState {
    LedgerState::new(
        identity(),
        event().projection,
        AuditLedgerLimits::new(6, 2).unwrap(),
    )
}

#[test]
fn target_results_retain_exact_outcome_and_reserved_terminal_through_encoding() {
    for outcome in outcomes() {
        let mut ledger = new_ledger();
        let handle = target_handle(71);
        ledger.admit(&key(), &handle, 110).unwrap();
        ledger.resolve(&key(), &handle, state(outcome)).unwrap();
        assert_eq!(ledger.sequence, 2);
        assert_eq!(ledger.operations[0].reserved, 1);
        let recovered: LedgerState =
            serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
        recovered.validate(&key(), identity()).unwrap();
        let receipt = recovered
            .lookup(&key(), &handle, handle.body.binding.caller)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.state(), state(outcome));
        assert!(!receipt.terminal_recorded());
        let proof = AuthenticatedAuditReceipt::seal(&key(), &receipt).unwrap();
        assert_eq!(
            proof
                .read_back(&key(), identity(), &handle, handle.body.binding.caller)
                .unwrap(),
            receipt
        );
        assert_eq!(
            ledger.resolve(&key(), &handle, AuditOperationState::Rejected),
            Err(AuditAuthorityError::BindingMismatch)
        );
        ledger.resolve(&key(), &handle, state(outcome)).unwrap();
        ledger.acknowledge_terminal(&key(), &handle).unwrap();
        ledger.acknowledge_terminal(&key(), &handle).unwrap();
        assert_eq!(ledger.sequence, 3);
        assert_eq!(ledger.operations[0].reserved, 0);
        ledger.validate(&key(), identity()).unwrap();
        assert_eq!(
            ledger
                .lookup(&key(), &handle, handle.body.binding.caller)
                .unwrap()
                .unwrap()
                .state(),
            state(outcome)
        );
    }
}

#[test]
fn target_results_require_netconf_mutation_and_matching_authority() {
    for kind in 0..3 {
        let mut ledger = new_ledger();
        let mut handle = target_handle(72);
        let mut result = state(outcomes()[0]);
        match kind {
            0 => handle.body.mutation = None,
            1 => handle.body.event.transport = ManagementAuditTransportCode::Gnmi,
            2 => {
                let foreign = ConfigConsensusIdentity::new(
                    identity().cluster_id(),
                    identity().configuration_id(),
                    ConfigConsensusConfigurationEpoch::new(2).unwrap(),
                );
                result = AuditOperationState::TargetV1(
                    NetconfTargetResult::new(
                        foreign,
                        [0x56; 16],
                        [0x57; 32],
                        NetconfAppliedOutcome::Candidate {
                            generation: CandidateGeneration {
                                authority: foreign,
                                value: 1,
                            },
                        },
                    )
                    .unwrap(),
                );
            }
            _ => unreachable!(),
        }
        handle = AuditOperationHandle::issue(handle.body, &key()).unwrap();
        ledger.admit(&key(), &handle, 110).unwrap();
        assert_eq!(
            ledger.resolve(&key(), &handle, result),
            Err(AuditAuthorityError::BindingMismatch)
        );
        assert_eq!(ledger.sequence, 1);
        assert_eq!(ledger.operations[0].state, AuditOperationState::Intent);
        let fabricated = AuditOperationReceipt {
            handle,
            state: result,
            terminal_recorded: false,
            sequence: 2,
        };
        assert!(AuthenticatedAuditReceipt::seal(&key(), &fabricated).is_err());
    }
}

#[test]
fn target_receipt_authenticates_profile_state_digest_and_disjoint_result() {
    for outcome in outcomes() {
        let handle = target_handle(73);
        let receipt = AuditOperationReceipt {
            handle: handle.clone(),
            state: state(outcome),
            terminal_recorded: false,
            sequence: 2,
        };
        let proof = AuthenticatedAuditReceipt::seal(&key(), &receipt).unwrap();
        for field in ["profile_incarnation", "state_digest", "outcome"] {
            let mut value = serde_json::to_value(&proof).unwrap();
            let result = &mut value["body"]["state"]["target-v1"];
            if field == "outcome" {
                result[field] = serde_json::json!({"copied-running": {"running_version": 9}});
            } else {
                result[field][0] = serde_json::json!(0x58);
            }
            let tampered: AuthenticatedAuditReceipt = serde_json::from_value(value).unwrap();
            assert!(tampered
                .read_back(&key(), identity(), &handle, handle.body.binding.caller)
                .is_err());
        }
        let mut value = serde_json::to_value(&proof).unwrap();
        value["body"]["state"] = serde_json::json!({"committed": {"version": 8}});
        let tampered: AuthenticatedAuditReceipt = serde_json::from_value(value).unwrap();
        assert!(tampered
            .read_back(&key(), identity(), &handle, handle.body.binding.caller)
            .is_err());
    }
}

#[test]
fn target_counters_retain_tombstones_and_refuse_wraparound() {
    let candidate = CandidateGeneration {
        authority: identity(),
        value: 0,
    };
    let startup = StartupRevision {
        authority: identity(),
        value: 0,
    };
    assert_eq!(candidate.checked_next().unwrap().get(), 1);
    assert_eq!(startup.checked_next().unwrap().get(), 1);
    assert_eq!(candidate.checked_next().unwrap().authority(), identity());
    let candidate = CandidateGeneration {
        value: u64::MAX,
        ..candidate
    };
    let startup = StartupRevision {
        value: u64::MAX,
        ..startup
    };
    assert_eq!(candidate.checked_next(), Err(AuditAuthorityError::Full));
    assert_eq!(startup.checked_next(), Err(AuditAuthorityError::Full));
    for outcome in &outcomes()[..2] {
        assert_eq!(outcome.running_version(), None);
    }
}

#[test]
fn target_terminal_debt_survives_restore_until_independent_checkpoint() {
    let keys = AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x59; 32]).unwrap()]).unwrap();
    for outcome in outcomes() {
        let mut ledger = new_ledger();
        ledger.continuity = Some(ContinuityState::new(1));
        let first = target_handle(74);
        let second = target_handle(75);
        ledger.admit(&key(), &first, 110).unwrap();
        ledger.resolve(&key(), &first, state(outcome)).unwrap();
        ledger.seal_continuity(Some(&keys)).unwrap();
        assert_eq!(
            ledger.admit(&key(), &second, 110),
            Err(AuditAuthorityError::RecoveryRequired)
        );
        ledger.acknowledge_terminal(&key(), &first).unwrap();
        ledger.seal_continuity(Some(&keys)).unwrap();
        let mut recovered: LedgerState =
            serde_json::from_slice(&serde_json::to_vec(&ledger).unwrap()).unwrap();
        recovered.validate(&key(), identity()).unwrap();
        recovered.validate_continuity(Some(&keys)).unwrap();
        assert_eq!(
            recovered.admit(&key(), &second, 110),
            Err(AuditAuthorityError::RecoveryRequired)
        );
        assert_eq!(
            recovered
                .lookup(&key(), &first, first.body.binding.caller)
                .unwrap()
                .unwrap()
                .state(),
            state(outcome)
        );
        let chain = recovered.continuity.as_ref().unwrap();
        let checkpoint = AuditCheckpoint::issue(
            &keys,
            CheckpointBody {
                version: 1,
                identity: identity(),
                sequence: recovered.sequence,
                root_anchor: recovered.terminal,
                anchor: chain.terminal,
                epoch_at_sequence: chain.active_epoch,
                signing_epoch: chain.active_epoch,
                acknowledged_export: [0; 32],
            },
        )
        .unwrap();
        recovered.continuity.as_mut().unwrap().checkpoint = Some(checkpoint);
        recovered.validate_continuity(Some(&keys)).unwrap();
        recovered.admit(&key(), &second, 110).unwrap();
        assert_eq!(recovered.sequence, 4);
    }
}
