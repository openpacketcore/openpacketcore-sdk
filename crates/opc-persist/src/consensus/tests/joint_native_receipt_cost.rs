//! Real SQLite Apply/receipt work, with cleanup before cost assertions.
//! The focused fixture produces a durable rejection; native success remains
//! covered by the existing disk-backed maximum fixture and its original budget.

use super::*;
use crate::consensus::{ConfigConsensusCommand, ConfigMutationIntent, ConfigRaftTypeConfig};
use opc_consensus::engine::{CommittedLeaderId, Entry, EntryPayload as RaftPayload, LogId};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ReceiptCounts {
    rows: usize,
    watched: usize,
    recoveries: usize,
    completed: usize,
}

struct Current {
    watched: AuditOperationHandle,
    counts: ReceiptCounts,
    started: Instant,
}

type RowFault = Box<dyn FnOnce(&Connection)>;

#[derive(Default)]
struct Controls {
    fault: Option<RowFault>,
    cancel_after_row: Option<Arc<SqliteWorkCancellation>>,
    last: ReceiptCounts,
}

thread_local! {
    static CURRENT: RefCell<Option<Current>> = const { RefCell::new(None) };
    static CONTROLS: RefCell<Option<Controls>> = const { RefCell::new(None) };
}

pub(in crate::consensus) fn before_receipt(conn: &Connection) {
    let fault = CONTROLS.with(|slot| slot.borrow_mut().as_mut().and_then(|c| c.fault.take()));
    if let Some(fault) = fault {
        fault(conn);
    }
}

pub(in crate::consensus) struct ReceiptScope {
    previous: Option<Current>,
    active: bool,
}

impl ReceiptScope {
    pub(in crate::consensus) fn enter(intent: &ConfigMutationIntent) -> Self {
        let watched = match intent {
            ConfigMutationIntent::ManagementAudit(audit) => match audit.as_ref() {
                AuditCommand::NetconfTarget(target) => match target.as_ref() {
                    TargetAuditCommandV1::Apply(prepared)
                        if prepared.bounded_running().is_some() =>
                    {
                        Some(prepared.handle().clone())
                    }
                    _ => None,
                },
                _ => None,
            },
            _ => None,
        };
        let Some(watched) = watched else {
            return Self {
                previous: None,
                active: false,
            };
        };
        let previous = CURRENT.with(|slot| {
            slot.replace(Some(Current {
                watched,
                counts: ReceiptCounts::default(),
                started: Instant::now(),
            }))
        });
        Self {
            previous,
            active: true,
        }
    }

    pub(in crate::consensus) fn complete(self, receipt_present: bool) {
        if self.active && receipt_present {
            CURRENT.with(|slot| {
                slot.borrow_mut().as_mut().unwrap().counts.completed += 1;
            });
        }
    }
}

impl Drop for ReceiptScope {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let current = CURRENT
            .with(|slot| slot.replace(self.previous.take()))
            .unwrap();
        CONTROLS.with(|slot| {
            if let Some(controls) = slot.borrow_mut().as_mut() {
                controls.last = current.counts;
            }
        });
        if current.counts.completed == 1 {
            eprintln!(
                "RECEIPT_COST_READBACK_COMPLETED rows={} watched={} recoveries={} elapsed_ms={}",
                current.counts.rows,
                current.counts.watched,
                current.counts.recoveries,
                current.started.elapsed().as_millis(),
            );
        }
    }
}

pub(in crate::consensus) fn row_authenticated() {
    let active = CURRENT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if let Some(current) = slot.as_mut() {
            current.counts.rows += 1;
            true
        } else {
            false
        }
    });
    if active {
        let cancellation = CONTROLS.with(|slot| {
            slot.borrow_mut()
                .as_mut()
                .and_then(|c| c.cancel_after_row.take())
        });
        if let Some(cancellation) = cancellation {
            cancellation.cancel_for_history_gate_test();
        }
    }
}

pub(in crate::consensus) fn recovered(handle: &AuditOperationHandle) {
    CURRENT.with(|slot| {
        if let Some(current) = slot.borrow_mut().as_mut() {
            current.counts.recoveries += 1;
            if &current.watched == handle {
                current.counts.watched += 1;
            }
        }
    });
}

fn observing<T>(controls: Controls, work: impl FnOnce() -> T) -> (T, ReceiptCounts) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            CONTROLS.with(|slot| *slot.borrow_mut() = None);
        }
    }
    CONTROLS.with(|slot| {
        assert!(slot.borrow().is_none(), "receipt observation cannot nest");
        *slot.borrow_mut() = Some(controls);
    });
    let reset = Reset;
    let result = work();
    let counts = CONTROLS.with(|slot| slot.borrow_mut().take().unwrap().last);
    drop(reset);
    (result, counts)
}

fn intent(f: &Fixture) -> ConfigMutationIntent {
    ConfigMutationIntent::ManagementAudit(Box::new(AuditCommand::NetconfTarget(Box::new(
        TargetAuditCommandV1::Apply(f.original.command().clone()),
    ))))
}

fn run_apply(
    f: &Fixture,
    cancellation: &SqliteWorkCancellation,
    mode: RetainedConfigMode,
) -> io::Result<Vec<crate::consensus::ConfigConsensusResponse>> {
    let node = crate::ConfigConsensusNodeId::new(1).unwrap();
    let entry: Entry<ConfigRaftTypeConfig> = Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, node), 0),
        payload: RaftPayload::Normal(ConfigConsensusCommand {
            schema_version: 10,
            identity: identity(),
            request_id: opc_consensus::ConsensusRequestId::from_bytes([0xa1; 16]),
            logical_time: opc_types::Timestamp::from_offset_datetime(
                time::OffsetDateTime::from_unix_timestamp(100).unwrap(),
            ),
            intent: intent(f),
        }),
    };
    crate::consensus::sqlite::apply_entries_cancellable_sync(
        &f.conn,
        identity(),
        &BTreeSet::from([node]),
        vec![entry],
        cancellation,
        &key(),
        Some(&f.keys),
        mode,
    )
}

fn response_state(
    f: &Fixture,
    responses: &[crate::consensus::ConfigConsensusResponse],
) -> AuditOperationState {
    assert_eq!(responses.len(), 1, "one actual applied entry");
    let receipt = responses[0]
        .audit_receipt
        .as_ref()
        .expect("authenticated actual receipt")
        .read_back(
            &key(),
            identity(),
            f.original.handle(),
            f.original.command().effect.caller,
        )
        .unwrap();
    receipt.state()
}

fn row(conn: &Connection) -> (Vec<u8>, Vec<u8>) {
    conn.query_row(
        "SELECT state_json,state_hmac FROM config_raft_management_audit WHERE singleton=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )
    .unwrap()
}

fn restore_row(conn: &Connection, stored: &(Vec<u8>, Vec<u8>)) {
    conn.execute(
        "UPDATE config_raft_management_audit SET state_json=?1,state_hmac=?2 WHERE singleton=1",
        rusqlite::params![stored.0, stored.1],
    )
    .unwrap();
}

fn no_committed_apply(f: &Fixture, before: &Snapshot) {
    assert!(
        f.conn.is_autocommit(),
        "failed apply transaction has unwound"
    );
    assert_eq!(
        snapshot(&f.conn).rows,
        before.rows,
        "exact signed rows rolled back"
    );
    let outcomes: usize = f
        .conn
        .query_row(
            "SELECT COUNT(*) FROM config_raft_request_outcomes",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(outcomes, 0, "no fabricated outcome after rollback");
    let sequence: u64 = f
        .conn
        .query_row(
            "SELECT application_sequence FROM config_raft_machine WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(sequence, 0, "no committed machine frontier");
}

#[test]
fn joint_receipt_cost_rejects_once_then_cleans_up_before_counting() {
    let f = Fixture::new(opc_crypto::CONFIG_CAPACITY_V1_LOGICAL_BYTES);
    f.checkpoint();
    let (result, counts) = observing(Controls::default(), || {
        run_apply(
            &f,
            &SqliteWorkCancellation::audit_test(),
            RetainedConfigMode::NetconfRunningV1,
        )
    });
    let responses = result.expect("real outer transaction completed");
    assert_eq!(
        responses[0].result,
        Err(crate::consensus::ConfigMutationFailure::Conflict)
    );
    assert_eq!(
        response_state(&f, &responses),
        AuditOperationState::Rejected
    );
    assert!(f.conn.is_autocommit());
    let ledger = f.ledger();
    let recovered = ledger
        .recover_target(
            &key(),
            f.original.handle(),
            f.original.command().effect.caller,
        )
        .unwrap();
    assert_eq!(
        recovered.command(),
        f.original.command(),
        "exact original still recoverable"
    );
    let outcomes: usize = f
        .conn
        .query_row(
            "SELECT COUNT(*) FROM config_raft_request_outcomes",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(outcomes, 1, "durable rejection has a real retained result");
    drop(recovered);
    drop(ledger);
    f.apply(AuditCommand::Terminal(f.original.handle().clone()));
    f.checkpoint();
    assert!(f.ledger().operations.iter().all(|op| op.terminal_recorded));
    drop(responses);
    drop(f);
    eprintln!("RECEIPT_COST_TRANSACTION_RECEIPT_CLEANUP_COMPLETED");
    assert_eq!(
        (
            counts.rows,
            counts.watched,
            counts.recoveries,
            counts.completed
        ),
        (1, 1, 3, 1),
        "RECEIPT_COST_ONE_BOUNDED_THREE_TOTAL",
    );
}

#[test]
fn joint_receipt_cost_fresh_read_rejects_tampered_mac_and_foreign_identity() {
    for foreign in [false, true] {
        let f = Fixture::new(4096);
        f.checkpoint();
        let before = snapshot(&f.conn);
        let controls = Controls {
            fault: Some(Box::new(move |conn| {
                if foreign {
                    let other = ConfigConsensusIdentity::new(
                        crate::ConfigConsensusClusterId::from_bytes([0xa2; 32]),
                        identity().configuration_id(),
                        identity().configuration_epoch(),
                    );
                    audit::write_sync(conn, &key(), other, None, false).unwrap();
                    assert_row_mac(conn, &key());
                } else {
                    conn.execute("UPDATE config_raft_management_audit SET state_hmac=zeroblob(32) WHERE singleton=1", []).unwrap();
                }
            })),
            ..Controls::default()
        };
        let (result, counts) = observing(controls, || {
            run_apply(
                &f,
                &SqliteWorkCancellation::audit_test(),
                RetainedConfigMode::NetconfRunningV1,
            )
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        no_committed_apply(&f, &before);
        drop(f);
        assert_eq!(
            counts.completed, 0,
            "no receipt can survive replaced authority"
        );
    }
}

fn resign_entries(ledger: &mut LedgerState, keys: &AuditKeyRing) {
    let mut previous = ledger.predecessor;
    for entry in &mut ledger.entries {
        entry.previous = previous;
        entry.mac = original_mac(
            &key(),
            b"openpacketcore/management-audit/replicated-entry/v1\0",
            &(
                identity(),
                entry.sequence,
                previous,
                entry.key_epoch,
                &entry.payload,
            ),
        );
        previous = entry.mac;
    }
    ledger.terminal = previous;
    ledger.continuity = Some(ContinuityState::new(1));
    ledger.seal_continuity(Some(keys)).unwrap();
    ledger.validate_continuity(Some(keys)).unwrap();
}

#[test]
fn joint_receipt_cost_rejects_resigned_malformed_matching_and_other_originals() {
    for matching in [true, false] {
        let f = Fixture::new(4096);
        f.checkpoint();
        let before = snapshot(&f.conn);
        let watched = f.original.handle().clone();
        let controls = Controls {
            fault: Some(Box::new(move |conn| {
                let mut ledger = audit::read_sync(conn, &key(), identity()).unwrap().unwrap();
                let retained = ledger
                    .entries
                    .iter_mut()
                    .find_map(|entry| match &mut entry.payload {
                        EntryPayload::TargetIntent(retained)
                            if (retained.handle == watched) == matching =>
                        {
                            Some(retained)
                        }
                        _ => None,
                    })
                    .unwrap();
                std::sync::Arc::make_mut(&mut retained.recovery).insert(0, ' ');
                let keys =
                    AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x7c; 32]).unwrap()]).unwrap();
                resign_entries(&mut ledger, &keys);
                audit::write_sync(conn, &key(), identity(), Some(ledger), false).unwrap();
                assert_row_mac(conn, &key());
            })),
            ..Controls::default()
        };
        let (result, counts) = observing(controls, || {
            run_apply(
                &f,
                &SqliteWorkCancellation::audit_test(),
                RetainedConfigMode::NetconfRunningV1,
            )
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        no_committed_apply(&f, &before);
        drop(f);
        assert_eq!(
            counts.rows, 1,
            "malformed original rejected after actual row authentication"
        );
        assert_eq!(counts.completed, 0);
    }
}

#[test]
fn joint_receipt_cost_rejects_authenticated_entry_mac_corruption() {
    let f = Fixture::new(4096);
    f.checkpoint();
    let before = snapshot(&f.conn);
    let controls = Controls {
        fault: Some(Box::new(|conn| {
            let mut ledger = audit::read_sync(conn, &key(), identity()).unwrap().unwrap();
            ledger.entries[0].mac[0] ^= 1;
            audit::write_sync(conn, &key(), identity(), Some(ledger), false).unwrap();
            assert_row_mac(conn, &key());
        })),
        ..Controls::default()
    };
    let (result, counts) = observing(controls, || {
        run_apply(
            &f,
            &SqliteWorkCancellation::audit_test(),
            RetainedConfigMode::NetconfRunningV1,
        )
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    no_committed_apply(&f, &before);
    drop(f);
    assert_eq!((counts.rows, counts.completed), (1, 0));
}

#[test]
fn joint_receipt_cost_returns_actual_replaced_row_state() {
    let f = Fixture::new(4096);
    f.checkpoint();
    let original_intent_row = row(&f.conn);
    let controls = Controls {
        fault: Some(Box::new(move |conn| {
            restore_row(conn, &original_intent_row)
        })),
        ..Controls::default()
    };
    let (result, _) = observing(controls, || {
        run_apply(
            &f,
            &SqliteWorkCancellation::audit_test(),
            RetainedConfigMode::NetconfRunningV1,
        )
    });
    let responses = result.unwrap();
    assert_eq!(
        response_state(&f, &responses),
        AuditOperationState::Intent,
        "fresh replaced row cannot produce a cached Rejected or Applied receipt"
    );
    assert_eq!(
        f.ledger()
            .lookup(
                &key(),
                f.original.handle(),
                f.original.command().effect.caller
            )
            .unwrap()
            .unwrap()
            .state(),
        AuditOperationState::Intent
    );
    drop(responses);
    drop(f);
}

#[test]
fn joint_receipt_cost_cancellation_after_authentication_rolls_back() {
    let f = Fixture::new(4096);
    f.checkpoint();
    let before = snapshot(&f.conn);
    let cancellation = Arc::new(SqliteWorkCancellation::audit_test());
    let controls = Controls {
        cancel_after_row: Some(cancellation.clone()),
        ..Controls::default()
    };
    let (result, counts) = observing(controls, || {
        run_apply(&f, &cancellation, RetainedConfigMode::NetconfRunningV1)
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    no_committed_apply(&f, &before);
    let fresh = run_apply(
        &f,
        &SqliteWorkCancellation::audit_test(),
        RetainedConfigMode::NetconfRunningV1,
    )
    .unwrap();
    assert_eq!(
        response_state(&f, &fresh),
        AuditOperationState::Rejected,
        "retry after rollback rereads the actual original and creates its real outcome"
    );
    drop(fresh);
    drop(f);
    drop(cancellation);
    assert_eq!(
        counts.rows, 1,
        "cancellation injected after real row authentication"
    );
}

#[test]
fn joint_receipt_cost_wrong_mode_and_preexisting_cancellation_never_apply() {
    for cancelled in [false, true] {
        let f = Fixture::new(4096);
        f.checkpoint();
        let before = snapshot(&f.conn);
        let cancellation = SqliteWorkCancellation::audit_test();
        let mode = if cancelled {
            cancellation.cancel_for_history_gate_test();
            RetainedConfigMode::NetconfRunningV1
        } else {
            RetainedConfigMode::NetconfTargetsV1
        };
        let (result, counts) =
            observing(Controls::default(), || run_apply(&f, &cancellation, mode));
        assert!(result.is_err());
        no_committed_apply(&f, &before);
        drop(f);
        assert_eq!(
            counts,
            ReceiptCounts::default(),
            "wrong mode/cancellation cannot enter receipt"
        );
    }
}

#[test]
fn joint_receipt_cost_autocommit_readback_keeps_full_recovery() {
    let f = Fixture::new(4096);
    f.checkpoint();
    let responses = run_apply(
        &f,
        &SqliteWorkCancellation::audit_test(),
        RetainedConfigMode::NetconfRunningV1,
    )
    .unwrap();
    assert_eq!(
        response_state(&f, &responses),
        AuditOperationState::Rejected
    );
    let intent = intent(&f);
    let (proof, counts) = observing(Controls::default(), || {
        let scope = ReceiptScope::enter(&intent);
        let proof = audit::applied_receipt_sync(&f.conn, &key(), identity(), &intent).unwrap();
        scope.complete(proof.is_some());
        proof
    });
    assert_eq!(
        proof
            .unwrap()
            .read_back(
                &key(),
                identity(),
                f.original.handle(),
                f.original.command().effect.caller
            )
            .unwrap()
            .state(),
        AuditOperationState::Rejected
    );
    drop(responses);
    drop(f);
    assert_eq!(
        (
            counts.rows,
            counts.watched,
            counts.recoveries,
            counts.completed
        ),
        (1, 3, 5, 1)
    );
}

#[test]
fn joint_receipt_cost_exact_candidate_still_requires_full_verification() {
    let mut f = Fixture::new(4096);
    f.checkpoint();
    let before = snapshot(&f.conn);
    // Keep the handle valid while making the command's effect inconsistent.
    // Apply rejects it before mutation. At readback inject those exact bytes
    // behind independently valid entry/row MACs: equality is not validation.
    f.original.command_mut().effect.expires_at -= 1;
    let forged = serde_json::to_string(f.original.command()).unwrap();
    let watched = f.original.handle().clone();
    let controls = Controls {
        fault: Some(Box::new(move |conn| {
            let mut ledger = audit::read_sync(conn, &key(), identity()).unwrap().unwrap();
            let retained = ledger
                .entries
                .iter_mut()
                .find_map(|entry| match &mut entry.payload {
                    EntryPayload::TargetIntent(retained) if retained.handle == watched => {
                        Some(retained)
                    }
                    _ => None,
                })
                .unwrap();
            retained.recovery = forged.into();
            let keys =
                AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x7c; 32]).unwrap()]).unwrap();
            resign_entries(&mut ledger, &keys);
            audit::write_sync(conn, &key(), identity(), Some(ledger), false).unwrap();
            assert_row_mac(conn, &key());
        })),
        ..Controls::default()
    };
    let (result, counts) = observing(controls, || {
        run_apply(
            &f,
            &SqliteWorkCancellation::audit_test(),
            RetainedConfigMode::NetconfRunningV1,
        )
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    no_committed_apply(&f, &before);
    drop(f);
    assert_eq!((counts.rows, counts.completed), (1, 0));
}

#[test]
fn joint_receipt_cost_mismatched_candidate_preserves_no_receipt_result() {
    let mut f = Fixture::new(4096);
    f.checkpoint();
    let before = row(&f.conn);
    // This valid handle still identifies the genuine stored command. A bad
    // submitted description must not make that stored original malformed.
    f.original.command_mut().effect.expires_at -= 1;
    let responses = run_apply(
        &f,
        &SqliteWorkCancellation::audit_test(),
        RetainedConfigMode::NetconfRunningV1,
    )
    .unwrap();
    assert_eq!(
        responses[0].result,
        Err(crate::consensus::ConfigMutationFailure::Conflict)
    );
    assert!(
        responses[0].audit_receipt.is_none(),
        "existing substituted-command classification"
    );
    assert_eq!(
        row(&f.conn),
        before,
        "genuine retained original remains unchanged"
    );
    drop(responses);
    drop(f);
}

#[test]
fn joint_receipt_cost_rejects_resigned_wrong_result_profile() {
    let f = Fixture::new(4096);
    f.checkpoint();
    let before = snapshot(&f.conn);
    let watched = f.original.handle().clone();
    let record = &f
        .original
        .command()
        .bounded_running()
        .unwrap()
        .commit()
        .record;
    let outcome = NetconfAppliedOutcome::RunningReplaced {
        tx_id: record.tx_id,
        running_version: record.version.get(),
        plaintext_digest: record.plaintext_digest.as_slice().try_into().unwrap(),
    };
    let controls = Controls {
        fault: Some(Box::new(move |conn| {
            let mut ledger = audit::read_sync(conn, &key(), identity()).unwrap().unwrap();
            let wrong =
                NetconfTargetResult::new(identity(), [0xa4; 16], [0xa5; 32], outcome).unwrap();
            let mut sequence = 0;
            for entry in &mut ledger.entries {
                if let EntryPayload::Outcome { operation, state } = &mut entry.payload {
                    if *operation == watched.mac {
                        *state = AuditOperationState::TargetV1(wrong);
                        sequence = entry.sequence;
                    }
                }
            }
            assert!(sequence > 0, "real rejection exists before fault");
            ledger
                .operations
                .iter_mut()
                .find(|op| op.handle == watched)
                .unwrap()
                .state = AuditOperationState::TargetV1(wrong);
            ledger.target_anchor = Some(crate::audit_authority::ledger::TargetStateAnchor {
                sequence,
                result: wrong,
            });
            let keys =
                AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x7c; 32]).unwrap()]).unwrap();
            resign_entries(&mut ledger, &keys);
            audit::write_sync(conn, &key(), identity(), Some(ledger), false).unwrap();
            assert_row_mac(conn, &key());
        })),
        ..Controls::default()
    };
    let (result, counts) = observing(controls, || {
        run_apply(
            &f,
            &SqliteWorkCancellation::audit_test(),
            RetainedConfigMode::NetconfRunningV1,
        )
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    no_committed_apply(&f, &before);
    drop(f);
    assert_eq!((counts.rows, counts.completed), (1, 0));
}

// These candidate-stage cases call the selector itself. The earlier public
// Apply rejection and legacy readback tests remain useful independent guards.
fn settle_rejected_receipt_fixture(f: &Fixture) {
    let ledger = f.ledger();
    let recovered = ledger
        .recover_target(
            &key(),
            f.original.handle(),
            f.original.command().effect.caller,
        )
        .unwrap();
    assert_eq!(recovered.command(), f.original.command());
    drop(recovered);
    drop(ledger);
    f.apply(AuditCommand::Terminal(f.original.handle().clone()));
    f.checkpoint();
    assert!(f.ledger().operations.iter().all(|op| op.terminal_recorded));
}

fn selected_receipt_counts_after_cleanup(
    mode: RetainedConfigMode,
    in_transaction: bool,
    cleanup_marker: &str,
) -> ReceiptCounts {
    let f = Fixture::new(4096);
    f.checkpoint();
    let responses = run_apply(
        &f,
        &SqliteWorkCancellation::audit_test(),
        RetainedConfigMode::NetconfRunningV1,
    )
    .unwrap();
    assert_eq!(
        response_state(&f, &responses),
        AuditOperationState::Rejected
    );
    let before = snapshot(&f.conn);
    let intent = intent(&f);
    let read = |conn: &Connection| {
        observing(Controls::default(), || {
            let scope = ReceiptScope::enter(&intent);
            let result =
                audit::applied_receipt_for_mode_sync(conn, &key(), identity(), &intent, mode);
            scope.complete(matches!(&result, Ok(Some(_))));
            result
        })
    };
    let (result, counts) = if in_transaction {
        let tx = f.conn.unchecked_transaction().unwrap();
        assert!(
            !tx.is_autocommit(),
            "real SQLite transaction surrounds selection"
        );
        let observed = read(&tx);
        tx.rollback().unwrap();
        observed
    } else {
        assert!(f.conn.is_autocommit(), "autocommit is read from SQLite");
        read(&f.conn)
    };
    let state = result.map(|proof| {
        proof.map(|proof| {
            proof
                .read_back(
                    &key(),
                    identity(),
                    f.original.handle(),
                    f.original.command().effect.caller,
                )
                .map(|receipt| receipt.state())
        })
    });
    let after = snapshot(&f.conn);
    let autocommit = f.conn.is_autocommit();
    settle_rejected_receipt_fixture(&f);
    drop(responses);
    drop(intent);
    drop(f);
    eprintln!(
        "{cleanup_marker} mode={mode:?} in_transaction={in_transaction} counts=({},{},{},{})",
        counts.rows, counts.watched, counts.recoveries, counts.completed,
    );
    assert_eq!(
        state.unwrap().unwrap().unwrap(),
        AuditOperationState::Rejected
    );
    assert!(autocommit, "read transaction finished before cleanup");
    assert_eq!(after, before, "receipt selection writes no stored state");
    counts
}

#[test]
fn joint_receipt_cost_selector_running_transaction_borrows_exact_original() {
    let mode = RetainedConfigMode::resolve(
        crate::RetainedConfigProfile::NetconfRunningV1,
        opc_crypto::ConfigCapacityProfile::BoundedV1,
    )
    .unwrap();
    let counts = selected_receipt_counts_after_cleanup(
        mode,
        true,
        "RECEIPT_COST_SELECTOR_RUNNING_TRANSACTION_CLEANUP_COMPLETED",
    );
    assert_eq!(
        (
            counts.rows,
            counts.watched,
            counts.recoveries,
            counts.completed
        ),
        (1, 1, 3, 1),
        "RECEIPT_COST_SELECTOR_RUNNING_TRANSACTION_ONE_BOUNDED_THREE_TOTAL",
    );
}

#[test]
fn joint_receipt_cost_selector_autocommit_keeps_full_recovery() {
    let mode = RetainedConfigMode::resolve(
        crate::RetainedConfigProfile::NetconfRunningV1,
        opc_crypto::ConfigCapacityProfile::BoundedV1,
    )
    .unwrap();
    let counts = selected_receipt_counts_after_cleanup(
        mode,
        false,
        "RECEIPT_COST_SELECTOR_AUTOCOMMIT_CLEANUP_COMPLETED",
    );
    assert_eq!(
        (
            counts.rows,
            counts.watched,
            counts.recoveries,
            counts.completed
        ),
        (1, 3, 5, 1),
        "RECEIPT_COST_SELECTOR_AUTOCOMMIT_THREE_BOUNDED_FIVE_TOTAL",
    );
}

#[test]
fn joint_receipt_cost_selector_non_running_mode_keeps_full_recovery() {
    // Resolve the independently selected profile through the same resolver as
    // retained admission. A bounded payload must not opt this read into Running.
    // The row is a valid prior Running rejection; this call reads its receipt,
    // rather than trying to submit that command under a different Apply mode.
    let mode = RetainedConfigMode::resolve(
        crate::RetainedConfigProfile::NetconfTargetsV1,
        opc_crypto::ConfigCapacityProfile::Legacy,
    )
    .unwrap();
    let counts = selected_receipt_counts_after_cleanup(
        mode,
        true,
        "RECEIPT_COST_SELECTOR_NON_RUNNING_CLEANUP_COMPLETED",
    );
    assert_eq!(
        (
            counts.rows,
            counts.watched,
            counts.recoveries,
            counts.completed
        ),
        (1, 3, 5, 1),
        "RECEIPT_COST_SELECTOR_NON_RUNNING_THREE_BOUNDED_FIVE_TOTAL",
    );
}

struct ReceiptFaultObservation {
    error: Option<io::ErrorKind>,
    before: Snapshot,
    after: Snapshot,
    autocommit: bool,
    outcomes: usize,
    sequence: u64,
    counts: ReceiptCounts,
}

impl ReceiptFaultObservation {
    fn assert_rejected(self, marker: &str) {
        assert_eq!(self.error, Some(io::ErrorKind::InvalidData), "{marker}");
        assert!(
            self.autocommit,
            "failed outer Apply transaction has unwound"
        );
        assert_eq!(
            self.after.rows, self.before.rows,
            "exact signed rows rolled back"
        );
        assert_eq!(
            (self.outcomes, self.sequence),
            (0, 0),
            "no committed outcome/frontier"
        );
        assert_eq!(
            (
                self.counts.rows,
                self.counts.watched,
                self.counts.recoveries,
                self.counts.completed
            ),
            (1, 0, 2, 0),
            "fresh authenticated row rejects before matching original recovery completes",
        );
    }
}

fn receipt_fault_after_cleanup(
    fault: impl FnOnce(&Connection, &AuditOperationHandle) + 'static,
    cleanup_marker: &str,
) -> ReceiptFaultObservation {
    let f = Fixture::new(4096);
    f.checkpoint();
    let before = snapshot(&f.conn);
    let original_intent_row = row(&f.conn);
    let watched = f.original.handle().clone();
    let controls = Controls {
        fault: Some(Box::new(move |conn| {
            assert!(
                !conn.is_autocommit(),
                "fault is inside the real outer Apply transaction"
            );
            fault(conn, &watched);
        })),
        ..Controls::default()
    };
    let (result, counts) = observing(controls, || {
        run_apply(
            &f,
            &SqliteWorkCancellation::audit_test(),
            RetainedConfigMode::NetconfRunningV1,
        )
    });
    // Capture all assertions' evidence before repairing an injected row for
    // cleanup. A mutant that commits cannot be hidden by that later repair.
    let observed = ReceiptFaultObservation {
        error: result.as_ref().err().map(io::Error::kind),
        before,
        after: snapshot(&f.conn),
        autocommit: f.conn.is_autocommit(),
        outcomes: f
            .conn
            .query_row(
                "SELECT COUNT(*) FROM config_raft_request_outcomes",
                [],
                |r| r.get(0),
            )
            .unwrap(),
        sequence: f
            .conn
            .query_row(
                "SELECT application_sequence FROM config_raft_machine WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .unwrap(),
        counts,
    };
    drop(result);
    // Both a rolled-back original and a deliberately faulty committed row are
    // restored to the saved valid Intent, then resolved and checkpointed using
    // real audit transactions. The in-memory connection is dropped afterward.
    restore_row(&f.conn, &original_intent_row);
    f.apply(AuditCommand::Reject(f.original.handle().clone()));
    settle_rejected_receipt_fixture(&f);
    drop(f);
    eprintln!(
        "{cleanup_marker} error={:?} autocommit={} rollback={} outcomes={} sequence={} counts=({},{},{},{})",
        observed.error,
        observed.autocommit,
        observed.after.rows == observed.before.rows,
        observed.outcomes,
        observed.sequence,
        counts.rows, counts.watched, counts.recoveries, counts.completed,
    );
    observed
}

fn assert_receipt_entry_chain(ledger: &LedgerState, expected_bad_macs: usize) {
    let mut previous = ledger.predecessor;
    let mut sequence = ledger.floor;
    let mut bad_macs = 0;
    for entry in &ledger.entries {
        sequence += 1;
        assert_eq!(entry.sequence, sequence);
        assert_eq!(entry.previous, previous);
        assert_eq!(entry.key_epoch, key().epoch());
        let expected = original_mac(
            &key(),
            b"openpacketcore/management-audit/replicated-entry/v1\0",
            &(
                identity(),
                sequence,
                previous,
                entry.key_epoch,
                &entry.payload,
            ),
        );
        bad_macs += usize::from(entry.mac != expected);
        previous = entry.mac;
    }
    assert_eq!(sequence, ledger.sequence);
    assert_eq!(previous, ledger.terminal);
    assert_eq!(bad_macs, expected_bad_macs);
}

#[test]
fn joint_receipt_cost_rejects_linked_final_entry_mac_corruption() {
    let observed = receipt_fault_after_cleanup(
        |conn, watched| {
            let keys =
                AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x7c; 32]).unwrap()]).unwrap();
            let mut ledger = audit::read_with_keys_sync(conn, &key(), Some(&keys), identity())
                .unwrap()
                .unwrap();
            let last = ledger.entries.last_mut().unwrap();
            assert!(
                matches!(&last.payload, EntryPayload::Outcome { operation, state }
                if *operation == watched.mac && *state == AuditOperationState::Rejected)
            );
            // A final-entry fault cannot invalidate a successor's `previous`.
            // Update the terminal and re-sign only its continuity row. Keep all
            // payloads, derived operations, anchors and prior checkpoints intact.
            last.mac[0] ^= 1;
            ledger.terminal = last.mac;
            let chain = ledger.continuity.as_mut().unwrap();
            let old_signature = chain.rows.pop().unwrap();
            chain.terminal = old_signature.previous;
            assert_eq!(chain.active_epoch, old_signature.epoch);
            ledger.seal_continuity(Some(&keys)).unwrap();
            ledger.validate_continuity(Some(&keys)).unwrap();
            assert_receipt_entry_chain(&ledger, 1);
            audit::write_sync(conn, &key(), identity(), Some(ledger), false).unwrap();
            assert_row_mac(conn, &key());
            eprintln!("RECEIPT_COST_LINKED_ENTRY_MAC_VALID_SURROUNDING_AUTH");
        },
        "RECEIPT_COST_LINKED_ENTRY_MAC_CLEANUP_COMPLETED",
    );
    observed.assert_rejected("RECEIPT_COST_LINKED_ENTRY_MAC_INVALID_DATA");
}

#[derive(Clone, Copy)]
enum ReceiptRetainedEncodingFault {
    TrailingWhitespace,
    TrailingData,
    UnknownField,
    DuplicateField,
    AlternateEscape,
}

fn malformed_receipt_original_after_cleanup(
    fault: ReceiptRetainedEncodingFault,
    cleanup_marker: &str,
) -> ReceiptFaultObservation {
    receipt_fault_after_cleanup(
        move |conn, watched| {
            let keys =
                AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x7c; 32]).unwrap()]).unwrap();
            let mut ledger = audit::read_with_keys_sync(conn, &key(), Some(&keys), identity())
                .unwrap()
                .unwrap();
            let retained = ledger
                .entries
                .iter_mut()
                .find_map(|entry| match &mut entry.payload {
                    EntryPayload::TargetIntent(retained) if &retained.handle == watched => {
                        Some(retained)
                    }
                    _ => None,
                })
                .unwrap();
            let saved = retained.recovery.clone();
            retained.recovery = match fault {
                ReceiptRetainedEncodingFault::TrailingWhitespace => format!("{saved} \t\r\n"),
                ReceiptRetainedEncodingFault::TrailingData => format!("{saved}{{}}"),
                ReceiptRetainedEncodingFault::UnknownField => {
                    saved.replacen("\"effect\":{", "\"effect\":{\"unknown\":0,", 1)
                }
                ReceiptRetainedEncodingFault::DuplicateField => {
                    saved.replacen("\"format\":1", "\"format\":1,\"format\":1", 1)
                }
                ReceiptRetainedEncodingFault::AlternateEscape => {
                    saved.replacen("\"effect\":", "\"\\u0065ffect\":", 1)
                }
            }
            .into();
            assert_ne!(
                retained.recovery, saved,
                "fixture changes actual retained bytes"
            );
            if matches!(
                fault,
                ReceiptRetainedEncodingFault::TrailingWhitespace
                    | ReceiptRetainedEncodingFault::TrailingData
            ) {
                assert!(
                    retained.recovery.starts_with(saved.as_str()),
                    "complete canonical prefix remains intact"
                );
            }
            if matches!(fault, ReceiptRetainedEncodingFault::AlternateEscape) {
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&retained.recovery).unwrap(),
                    serde_json::from_str::<serde_json::Value>(&saved).unwrap(),
                    "alternate spelling changes no decoded value",
                );
            }
            // Keep the outer row, every entry, linkage and continuity valid;
            // only the actual matching retained-original representation is bad.
            resign_entries(&mut ledger, &keys);
            assert_receipt_entry_chain(&ledger, 0);
            audit::write_sync(conn, &key(), identity(), Some(ledger), false).unwrap();
            assert_row_mac(conn, &key());
            eprintln!("RECEIPT_COST_MALFORMED_ORIGINAL_VALID_SURROUNDING_AUTH");
        },
        cleanup_marker,
    )
}

#[test]
fn joint_receipt_cost_rejects_resigned_trailing_whitespace_original() {
    let observed = malformed_receipt_original_after_cleanup(
        ReceiptRetainedEncodingFault::TrailingWhitespace,
        "RECEIPT_COST_TRAILING_WHITESPACE_CLEANUP_COMPLETED",
    );
    observed.assert_rejected("RECEIPT_COST_TRAILING_WHITESPACE_INVALID_DATA");
}

#[test]
fn joint_receipt_cost_rejects_resigned_trailing_data_original() {
    let observed = malformed_receipt_original_after_cleanup(
        ReceiptRetainedEncodingFault::TrailingData,
        "RECEIPT_COST_TRAILING_DATA_CLEANUP_COMPLETED",
    );
    observed.assert_rejected("RECEIPT_COST_TRAILING_DATA_INVALID_DATA");
}

#[test]
fn joint_receipt_cost_rejects_resigned_unknown_field_original() {
    let observed = malformed_receipt_original_after_cleanup(
        ReceiptRetainedEncodingFault::UnknownField,
        "RECEIPT_COST_UNKNOWN_FIELD_CLEANUP_COMPLETED",
    );
    observed.assert_rejected("RECEIPT_COST_UNKNOWN_FIELD_INVALID_DATA");
}

#[test]
fn joint_receipt_cost_rejects_resigned_duplicate_field_original() {
    let observed = malformed_receipt_original_after_cleanup(
        ReceiptRetainedEncodingFault::DuplicateField,
        "RECEIPT_COST_DUPLICATE_FIELD_CLEANUP_COMPLETED",
    );
    observed.assert_rejected("RECEIPT_COST_DUPLICATE_FIELD_INVALID_DATA");
}

#[test]
fn joint_receipt_cost_rejects_resigned_alternate_escape_original() {
    let observed = malformed_receipt_original_after_cleanup(
        ReceiptRetainedEncodingFault::AlternateEscape,
        "RECEIPT_COST_ALTERNATE_ESCAPE_CLEANUP_COMPLETED",
    );
    observed.assert_rejected("RECEIPT_COST_ALTERNATE_ESCAPE_INVALID_DATA");
}
