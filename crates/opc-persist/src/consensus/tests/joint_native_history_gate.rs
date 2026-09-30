//! Synchronous history-gate behavior and actual authentication/recovery counts.
//! In-memory SQL isolates this call boundary; native durability, latency and
//! whole-operation memory qualification remain separate.

use super::*;
use crate::audit_authority::continuity::chain::ContinuityState;
use crate::audit_authority::continuity::checkpoint::CheckpointBody;
use crate::audit_authority::continuity::AuditSigningKey;
use crate::audit_authority::ledger::native_cost_tests::original_mac;
use crate::audit_authority::ledger::{EntryPayload, HandleBody};
use crate::audit_authority::{
    AuditLedgerLimits, AuditOperationBinding, AuditOperationHandle, AuditPrivacyKey,
    CandidateGeneration, ProjectedAuditEvent,
};
use crate::consensus::audit::{self, ApplyContext, AuditCommand};
use crate::consensus::audit_mutation::{TargetAuditCommandV1, TargetEffectV1};
use crate::consensus::{ConfigConsensusTopology, RetainedConfigMode};
use hmac::{Hmac, KeyInit, Mac};
use opc_crypto::ConfigPreparationPool;
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Counts {
    rows: usize,
    watched: usize,
    recoveries: usize,
    anchors: usize,
}

struct Active {
    watched: Option<AuditOperationHandle>,
    counts: Counts,
    cancel_after_anchor: Option<Arc<SqliteWorkCancellation>>,
}

thread_local! {
    static ACTIVE: RefCell<Option<Active>> = const { RefCell::new(None) };
}

pub(in crate::consensus) fn row_authenticated() {
    receipt_cost_tests::row_authenticated();
    ACTIVE.with(|slot| {
        if let Some(active) = slot.borrow_mut().as_mut() {
            active.counts.rows += 1;
        }
    });
}

pub(in crate::consensus) fn recovered(handle: &AuditOperationHandle) {
    receipt_cost_tests::recovered(handle);
    ACTIVE.with(|slot| {
        if let Some(active) = slot.borrow_mut().as_mut() {
            active.counts.recoveries += 1;
            if active.watched.as_ref() == Some(handle) {
                active.counts.watched += 1;
            }
        }
    });
}

pub(in crate::consensus) fn anchor_validated() {
    let cancellation = ACTIVE.with(|slot| {
        slot.borrow_mut().as_mut().and_then(|active| {
            active.counts.anchors += 1;
            active.cancel_after_anchor.take()
        })
    });
    if let Some(cancellation) = cancellation {
        cancellation.cancel_for_history_gate_test();
    }
}

fn observe<T>(
    watched: Option<&AuditOperationHandle>,
    cancellation: Option<Arc<SqliteWorkCancellation>>,
    work: impl FnOnce() -> T,
) -> (T, Counts) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            ACTIVE.with(|slot| *slot.borrow_mut() = None);
        }
    }
    ACTIVE.with(|slot| {
        assert!(
            slot.borrow().is_none(),
            "synchronous observation cannot nest"
        );
        *slot.borrow_mut() = Some(Active {
            watched: watched.cloned(),
            counts: Counts::default(),
            cancel_after_anchor: cancellation,
        });
    });
    let reset = Reset;
    let result = work();
    let counts = ACTIVE.with(|slot| slot.borrow_mut().take().unwrap().counts);
    drop(reset);
    (result, counts)
}

fn identity() -> ConfigConsensusIdentity {
    ConfigConsensusIdentity::new(
        crate::ConfigConsensusClusterId::from_bytes([0x72; 32]),
        crate::ConfigConsensusConfigurationId::from_bytes([0x73; 32]),
        crate::ConfigConsensusConfigurationEpoch::new(1).unwrap(),
    )
}

fn key() -> AuditKey {
    AuditKey::new([0x74; 32]).unwrap()
}

fn privacy() -> AuditPrivacyKey {
    AuditPrivacyKey::new([0x75; 32]).unwrap()
}

fn provision(mode: RetainedConfigMode) -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    let tx = conn.unchecked_transaction().unwrap();
    crate::schema::initialize_schema(&tx).unwrap();
    tx.commit().unwrap();
    let node = crate::ConfigConsensusNodeId::new(1).unwrap();
    let topology =
        ConfigConsensusTopology::try_new(identity(), node, BTreeSet::from([node])).unwrap();
    crate::consensus::sqlite::provision_retained_schema(
        &conn,
        &topology,
        &key(),
        mode,
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap();
    conn
}

struct Fixture {
    conn: Connection,
    keys: AuditKeyRing,
    original: PreparedTargetMutation,
}

impl Fixture {
    fn new(size: usize) -> Self {
        let pool = ConfigPreparationPool::bounded_v1();
        let mut plaintext = vec![b'x'; size];
        plaintext[0] = b'"';
        *plaintext.last_mut().unwrap() = b'"';
        let original = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(
                crate::consensus::audit_mutation::joint_running::tests::prepared_for_history_gate(
                    &pool,
                    identity(),
                    &key(),
                    &plaintext,
                ),
            );
        let fixture = Self {
            conn: provision(RetainedConfigMode::NetconfRunningV1),
            keys: AuditKeyRing::new(vec![AuditSigningKey::new(1, [0x7c; 32]).unwrap()]).unwrap(),
            original,
        };
        fixture.apply(AuditCommand::InitializeWithContinuity {
            projection: fixture.original.handle().body.event.projection,
            limits: AuditLedgerLimits::new(96, 32).unwrap(),
            initial_epoch: 1,
        });
        let checkpoint = fixture.checkpoint();
        let event = fixture.event(1);
        let activation = fixture.sign(
            TargetEffectV1 {
                format: 1,
                authority: identity(),
                profile_incarnation: [0x78; 16],
                device_incarnation: [0x79; 16],
                caller: event.caller,
                request: event.request,
                action: 0.try_into().unwrap(),
                destination: TargetExpectationV1::Lifecycle {
                    state_digest: fixture.state().profile.state_digest,
                },
                source: None,
                lock: None,
                expires_at: 160,
                encrypted_payload: None,
                resolution: Some(TargetResolutionV1::Activate { checkpoint }),
            },
            event,
        );
        fixture.apply(AuditCommand::NetconfTarget(Box::new(
            TargetAuditCommandV1::Admit(activation.command().clone()),
        )));
        fixture.checkpoint();
        fixture.apply(AuditCommand::NetconfTarget(Box::new(
            TargetAuditCommandV1::Apply(activation.command().clone()),
        )));
        fixture.apply(AuditCommand::Terminal(activation.handle().clone()));
        fixture.checkpoint();
        fixture.apply(AuditCommand::NetconfTarget(Box::new(
            TargetAuditCommandV1::Admit(fixture.original.command().clone()),
        )));
        fixture
            .ledger()
            .validate_continuity(Some(&fixture.keys))
            .unwrap();
        fixture
    }

    fn event(&self, request: u8) -> ProjectedAuditEvent {
        ProjectedAuditEvent::project(
            &privacy(),
            &crate::ManagementAuditEventRecord::try_new(
                [request; 16],
                crate::ManagementAuditInstant::try_new(
                    100,
                    0,
                    1,
                    crate::ManagementAuditTimeSourceCode::NodeClock,
                )
                .unwrap(),
                "synthetic",
                "synthetic-principal",
                crate::ManagementAuditTransportCode::NetconfSsh,
                crate::ManagementAuditOperationCode::Exec,
                crate::ManagementAuditOutcomeCode::Intent,
                None::<&str>,
                ["/fixture:config"],
                Some("history-gate"),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn sign(&self, effect: TargetEffectV1, event: ProjectedAuditEvent) -> PreparedTargetMutation {
        // Independent original serde/HMAC recipe, not the optimized authenticator.
        let digest = original_mac(
            &key(),
            b"openpacketcore/management-audit/netconf-target/v1\0",
            &effect,
        );
        let handle = AuditOperationHandle::issue(
            HandleBody {
                version: 1,
                identity: identity(),
                binding: AuditOperationBinding::project(&privacy(), &event, 0, &digest).unwrap(),
                event,
                issued_at: 100,
                expires_at: 160,
                nonce: [0x7d; 16],
                key_epoch: key().epoch(),
                mutation: Some(digest),
            },
            &key(),
        )
        .unwrap();
        PreparedTargetMutation::new(handle, effect, None)
    }

    fn apply(&self, command: AuditCommand) {
        let tx = self.conn.unchecked_transaction().unwrap();
        audit::apply_cancellable_for_mode_sync(
            &tx,
            &key(),
            identity(),
            &command,
            Some(&self.keys),
            &ApplyContext {
                logical_time: opc_types::Timestamp::from_offset_datetime(
                    time::OffsetDateTime::from_unix_timestamp(100).unwrap(),
                ),
                request_id: opc_consensus::ConsensusRequestId::from_bytes([0x7e; 16]),
                cancellation: &SqliteWorkCancellation::audit_test(),
            },
            RetainedConfigMode::NetconfRunningV1,
        )
        .unwrap()
        .unwrap();
        tx.commit().unwrap();
    }

    fn ledger(&self) -> LedgerState {
        audit::read_with_keys_sync(&self.conn, &key(), Some(&self.keys), identity())
            .unwrap()
            .unwrap()
    }

    fn issue_checkpoint(&self, ledger: &LedgerState) -> AuditCheckpoint {
        let chain = ledger.continuity.as_ref().unwrap();
        AuditCheckpoint::issue(
            &self.keys,
            CheckpointBody {
                version: 1,
                identity: identity(),
                sequence: ledger.sequence,
                root_anchor: ledger.terminal,
                anchor: chain.terminal,
                epoch_at_sequence: chain.active_epoch,
                signing_epoch: chain.active_epoch,
                acknowledged_export: [0; 32],
            },
        )
        .unwrap()
    }

    fn checkpoint(&self) -> AuditCheckpoint {
        let checkpoint = self.issue_checkpoint(&self.ledger());
        self.apply(AuditCommand::Checkpoint(checkpoint.clone()));
        checkpoint
    }

    fn state(&self) -> TargetState {
        read_state_sync(
            &self.conn,
            &key(),
            identity(),
            &SqliteWorkCancellation::audit_test(),
        )
        .unwrap()
    }

    fn write_ledger(&self, ledger: LedgerState) {
        audit::write_sync(&self.conn, &key(), identity(), Some(ledger), false).unwrap();
    }

    fn write_state(&self, mut state: TargetState, reanchor: bool) {
        state.profile.state_digest =
            state_digest(&state.profile, &state.targets, &state.lifecycle).unwrap();
        state.validate(identity()).unwrap();
        if reanchor {
            let old = self.ledger();
            let EntryPayload::TargetIntent(retained) = &old.entries[0].payload else {
                panic!("activation original");
            };
            let activation = old
                .recover_target(
                    &key(),
                    &retained.handle,
                    retained.handle.body.binding.caller,
                )
                .unwrap();
            let mut ledger = LedgerState::new(identity(), old.projection, old.limits);
            ledger.continuity = Some(ContinuityState::new(1));
            ledger
                .admit_target(&key(), activation.command(), 100)
                .unwrap();
            ledger
                .resolve(
                    &key(),
                    activation.handle(),
                    AuditOperationState::TargetV1(
                        NetconfTargetResult::new(
                            identity(),
                            [0x78; 16],
                            state.profile.state_digest,
                            NetconfAppliedOutcome::Lifecycle {
                                incarnation: NetconfIncarnation {
                                    authority: identity(),
                                    value: [0x79; 16],
                                },
                            },
                        )
                        .unwrap(),
                    ),
                )
                .unwrap();
            ledger
                .acknowledge_terminal(&key(), activation.handle())
                .unwrap();
            // Satisfy the same signed checkpoint debt as ordinary admission;
            // only the adversarial target-state digest differs in this fixture.
            ledger.seal_continuity(Some(&self.keys)).unwrap();
            let checkpoint = self.issue_checkpoint(&ledger);
            ledger.matches_checkpoint(&checkpoint).unwrap();
            ledger.continuity.as_mut().unwrap().checkpoint = Some(checkpoint);
            ledger
                .admit_target(&key(), self.original.command(), 100)
                .unwrap();
            ledger.seal_continuity(Some(&self.keys)).unwrap();
            ledger.validate(&key(), identity()).unwrap();
            ledger.validate_continuity(Some(&self.keys)).unwrap();
            state.validate_anchor(Some(&ledger)).unwrap();
            self.write_ledger(ledger);
        }
        state
            .write(&self.conn, &key(), &SqliteWorkCancellation::audit_test())
            .unwrap();
    }
}

fn validate(conn: &Connection, cancellation: &SqliteWorkCancellation) -> io::Result<()> {
    crate::consensus::history::validate_access_for_profile_sync(
        conn,
        &key(),
        true,
        Some(identity()),
        RetainedConfigMode::NetconfRunningV1,
        cancellation,
    )
}

#[derive(Debug, PartialEq)]
struct Snapshot {
    rows: Vec<(Vec<u8>, Vec<u8>)>,
    changes: u64,
}

fn snapshot(conn: &Connection) -> Snapshot {
    let mut rows = Vec::new();
    for table in [
        "config_raft_management_audit",
        "config_raft_history_retention",
        "config_netconf_profile",
        "config_netconf_targets",
        "config_netconf_lifecycle",
    ] {
        let mut query = conn
            .prepare(&format!(
                "SELECT state_json, state_hmac FROM {table} ORDER BY rowid"
            ))
            .unwrap();
        rows.extend(
            query
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap(),
        );
    }
    Snapshot {
        rows,
        changes: conn
            .query_row("SELECT total_changes()", [], |row| row.get(0))
            .unwrap(),
    }
}

fn reject(fixture: &Fixture) -> Counts {
    let before = snapshot(&fixture.conn);
    let tx = fixture.conn.unchecked_transaction().unwrap();
    let (result, counts) = observe(Some(fixture.original.handle()), None, || {
        validate(&tx, &SqliteWorkCancellation::audit_test())
    });
    assert_eq!(
        result.unwrap_err().kind(),
        io::ErrorKind::InvalidData,
        "HISTORY_GATE_AUTHENTICATED_REJECTION"
    );
    assert_eq!(snapshot(&tx), before, "history rejection writes no state");
    tx.rollback().unwrap();
    counts
}

fn assert_row_mac(conn: &Connection, signing_key: &AuditKey) {
    let (bytes, tag): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT state_json, state_hmac FROM config_raft_management_audit WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(signing_key.as_bytes()).unwrap();
    mac.update(b"openpacketcore/management-audit/replicated-state/v1\0");
    mac.update(&(bytes.len() as u64).to_be_bytes());
    mac.update(&bytes);
    mac.verify_slice(&tag).expect("independent outer row MAC");
}

#[test]
fn joint_history_gate_reuses_only_adjacent_authenticated_read() {
    let fixture = Fixture::new(opc_crypto::CONFIG_CAPACITY_V1_LOGICAL_BYTES);
    let before = snapshot(&fixture.conn);
    let tx = fixture.conn.unchecked_transaction().unwrap();
    let (result, counts) = observe(Some(fixture.original.handle()), None, || {
        validate(&tx, &SqliteWorkCancellation::audit_test())
    });
    result.expect("HISTORY_GATE_FULL_VALIDATION_COMPLETED");
    eprintln!("HISTORY_GATE_FULL_VALIDATION_COMPLETED");
    assert_eq!(
        snapshot(&tx),
        before,
        "validation preserves exact signed bytes"
    );
    assert_eq!(
        (counts.rows, counts.watched, counts.recoveries),
        (1, 1, 3),
        "HISTORY_GATE_ONE_READ_ONE_BOUNDED_THREE_TOTAL"
    );
    assert_eq!(counts.anchors, 1);
    tx.commit().unwrap();
}

#[test]
fn joint_history_gate_autocommit_keeps_independent_reads() {
    let fixture = Fixture::new(4096);
    assert!(fixture.conn.is_autocommit());
    let before = snapshot(&fixture.conn);
    let (result, counts) = observe(Some(fixture.original.handle()), None, || {
        validate(&fixture.conn, &SqliteWorkCancellation::audit_test())
    });
    result.unwrap();
    assert_eq!(
        (counts.rows, counts.watched, counts.recoveries),
        (2, 3, 8),
        "HISTORY_GATE_AUTOCOMMIT_UNCHANGED"
    );
    assert_eq!(snapshot(&fixture.conn), before);
}

#[test]
fn joint_history_gate_reauthenticates_each_transaction_after_tampering() {
    let fixture = Fixture::new(4096);
    for _ in 0..2 {
        let tx = fixture.conn.unchecked_transaction().unwrap();
        let (result, counts) = observe(Some(fixture.original.handle()), None, || {
            validate(&tx, &SqliteWorkCancellation::audit_test())
        });
        result.unwrap();
        assert_eq!(
            (counts.rows, counts.watched, counts.recoveries),
            (1, 1, 3),
            "every invocation performs fresh authentication and retained recovery"
        );
        tx.commit().unwrap();
    }
    fixture
        .conn
        .execute(
            "UPDATE config_raft_management_audit SET state_hmac=zeroblob(32) WHERE singleton=1",
            [],
        )
        .unwrap();
    reject(&fixture);
}

#[test]
fn joint_history_gate_reauthenticates_again_inside_same_transaction() {
    let fixture = Fixture::new(4096);
    let before = snapshot(&fixture.conn);
    let tx = fixture.conn.unchecked_transaction().unwrap();
    let (result, counts) = observe(Some(fixture.original.handle()), None, || {
        validate(&tx, &SqliteWorkCancellation::audit_test())
    });
    result.unwrap();
    assert_eq!((counts.rows, counts.watched, counts.recoveries), (1, 1, 3));
    tx.execute(
        "UPDATE config_raft_management_audit SET state_hmac=zeroblob(32) WHERE singleton=1",
        [],
    )
    .unwrap();
    let tampered = snapshot(&tx);
    let (result, counts) = observe(Some(fixture.original.handle()), None, || {
        validate(&tx, &SqliteWorkCancellation::audit_test())
    });
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(counts, Counts::default());
    assert_eq!(snapshot(&tx), tampered, "rejection writes no state");
    tx.rollback().unwrap();
    assert_eq!(snapshot(&fixture.conn).rows, before.rows);
}

#[test]
fn joint_history_gate_rejects_anchor_mismatch_with_valid_running_policy() {
    let fixture = Fixture::new(4096);
    let mut state = fixture.state();
    // Keep every closed-state and retained-original policy valid. Only the
    // authenticated profile's link to the retained audit anchor is stale.
    state.profile.last_target_transition_sequence += 1;
    fixture.write_state(state, false);
    validate_running_only_sync(
        &fixture.conn,
        &key(),
        identity(),
        &SqliteWorkCancellation::audit_test(),
    )
    .expect("independently valid Running state and retained-original policy");
    let state = fixture.state();
    let ledger = fixture.ledger();
    assert!(state.validate_anchor(Some(&ledger)).is_err());
    let before = snapshot(&fixture.conn);
    let tx = fixture.conn.unchecked_transaction().unwrap();
    let (result, counts) = observe(Some(fixture.original.handle()), None, || {
        validate(&tx, &SqliteWorkCancellation::audit_test())
    });
    assert_eq!(
        result
            .expect_err("HISTORY_GATE_ANCHOR_ONLY_REQUIRED")
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!((counts.rows, counts.watched, counts.recoveries), (1, 1, 3));
    assert_eq!(counts.anchors, 0);
    assert_eq!(snapshot(&tx), before, "anchor rejection writes no state");
    tx.rollback().unwrap();
}

#[test]
fn joint_history_gate_rejects_authenticated_anchor_mismatch_before_policy() {
    let fixture = Fixture::new(4096);
    let mut state = fixture.state();
    // Independently well-formed and signed closed-state violation as well:
    // the old anchor must reject before either closed-state or entry policy.
    state.targets[0].generation = 1;
    state.targets[0].last_applying_operation = Some([0x81; 32]);
    fixture.write_state(state, false);
    let state = fixture.state();
    let ledger = fixture.ledger();
    assert!(state.validate_anchor(Some(&ledger)).is_err());
    let counts = reject(&fixture);
    assert_eq!(counts.anchors, 0, "HISTORY_GATE_ANCHOR_PRECEDES_POLICY");
    assert_eq!((counts.watched, counts.recoveries), (1, 3));
}

#[test]
fn joint_history_gate_rejects_closed_state_after_independent_authentication() {
    for slot in 0..4 {
        let fixture = Fixture::new(4096);
        let mut state = fixture.state();
        if slot < 2 {
            state.targets[slot].generation = 1;
            state.targets[slot].last_applying_operation = Some([0x82; 32]);
        } else {
            let lock = state.lifecycle.locks[slot - 1].as_mut().unwrap();
            lock.incarnation = 1;
            lock.session = Some([0x83; 16]);
            lock.caller = Some(fixture.original.handle().body.binding.caller);
        }
        fixture.write_state(state, true);
        validate_inactive_sync(
            &fixture.conn,
            &key(),
            identity(),
            &SqliteWorkCancellation::audit_test(),
        )
        .expect("valid row, ledger and target anchor");
        let counts = reject(&fixture);
        assert_eq!(counts.anchors, 1, "HISTORY_GATE_CLOSED_STATE_AUTHENTICATED");
        assert_eq!((counts.watched, counts.recoveries), (1, 3));
    }
}

#[test]
fn joint_history_gate_rejects_unsupported_original_and_generic_mutation() {
    for target_intent in [true, false] {
        let fixture = Fixture::new(4096);
        let event = fixture.event(3);
        let unsupported = fixture.sign(
            TargetEffectV1 {
                format: 1,
                authority: identity(),
                profile_incarnation: [0x78; 16],
                device_incarnation: [0x79; 16],
                caller: event.caller,
                request: event.request,
                action: 5.try_into().unwrap(),
                destination: TargetExpectationV1::Candidate {
                    generation: CandidateGeneration {
                        authority: identity(),
                        value: 0,
                    },
                },
                source: None,
                lock: None,
                expires_at: 160,
                encrypted_payload: None,
                resolution: None,
            },
            event,
        );
        let mut ledger = fixture.ledger();
        if target_intent {
            ledger
                .admit_target(&key(), unsupported.command(), 100)
                .unwrap();
        } else {
            ledger.admit(&key(), unsupported.handle(), 100).unwrap();
        }
        ledger.seal_continuity(Some(&fixture.keys)).unwrap();
        ledger.validate(&key(), identity()).unwrap();
        ledger.validate_continuity(Some(&fixture.keys)).unwrap();
        fixture.write_ledger(ledger);
        validate_inactive_sync(
            &fixture.conn,
            &key(),
            identity(),
            &SqliteWorkCancellation::audit_test(),
        )
        .expect("unsupported policy is still authentic");
        let counts = reject(&fixture);
        assert_eq!(
            counts.anchors, 1,
            "HISTORY_GATE_UNSUPPORTED_POLICY_AUTHENTICATED"
        );
    }
}

#[test]
fn joint_history_gate_rejects_row_entry_key_and_identity_substitution() {
    for attack in 0..4 {
        let fixture = Fixture::new(4096);
        let mut ledger = fixture.ledger();
        match attack {
            0 => {
                fixture
                    .conn
                    .execute(
                        "UPDATE config_raft_management_audit SET state_hmac=zeroblob(32) WHERE singleton=1",
                        [],
                    )
                    .unwrap();
            }
            1 => {
                ledger.entries[0].mac[0] ^= 1;
                fixture.write_ledger(ledger);
                assert_row_mac(&fixture.conn, &key());
            }
            2 => {
                let other_key = AuditKey::new([0x91; 32]).unwrap();
                audit::write_sync(&fixture.conn, &other_key, identity(), Some(ledger), false)
                    .unwrap();
                assert_row_mac(&fixture.conn, &other_key);
            }
            _ => {
                let foreign = ConfigConsensusIdentity::new(
                    crate::ConfigConsensusClusterId::from_bytes([0x92; 32]),
                    identity().configuration_id(),
                    identity().configuration_epoch(),
                );
                audit::write_sync(&fixture.conn, &key(), foreign, None, false).unwrap();
                assert_row_mac(&fixture.conn, &key());
            }
        }
        reject(&fixture);
    }
}

#[test]
fn joint_history_gate_rejects_resigned_noncanonical_retained_original() {
    let fixture = Fixture::new(4096);
    let mut ledger = fixture.ledger();
    let retained = ledger
        .entries
        .iter_mut()
        .find_map(|entry| match &mut entry.payload {
            EntryPayload::TargetIntent(retained)
                if retained.handle == *fixture.original.handle() =>
            {
                Some(retained)
            }
            _ => None,
        })
        .expect("exact bounded original");
    std::sync::Arc::make_mut(&mut retained.recovery).insert(0, ' ');
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
    ledger.seal_continuity(Some(&fixture.keys)).unwrap();
    ledger.validate_continuity(Some(&fixture.keys)).unwrap();
    fixture.write_ledger(ledger);
    assert_row_mac(&fixture.conn, &key());
    let counts = reject(&fixture);
    assert_eq!(
        counts.rows, 1,
        "HISTORY_GATE_CANONICAL_REJECT_AFTER_ROW_MAC"
    );
    assert_eq!(
        counts.watched, 0,
        "noncanonical original never finishes recovery"
    );
}

#[test]
fn joint_history_gate_observes_cancellation_before_closed_state_policy() {
    let fixture = Fixture::new(4096);
    let mut state = fixture.state();
    state.targets[0].generation = 1;
    state.targets[0].last_applying_operation = Some([0x93; 32]);
    fixture.write_state(state, true);
    validate_inactive_sync(
        &fixture.conn,
        &key(),
        identity(),
        &SqliteWorkCancellation::audit_test(),
    )
    .unwrap();
    let cancellation = Arc::new(SqliteWorkCancellation::audit_test());
    let before = snapshot(&fixture.conn);
    let tx = fixture.conn.unchecked_transaction().unwrap();
    let (result, counts) = observe(
        Some(fixture.original.handle()),
        Some(cancellation.clone()),
        || validate(&tx, &cancellation),
    );
    assert_eq!(
        counts.anchors, 1,
        "real anchor validation triggers cancellation"
    );
    assert_eq!(
        result.unwrap_err().kind(),
        io::ErrorKind::TimedOut,
        "HISTORY_GATE_CANCEL_AT_FORMER_BOUNDARY"
    );
    assert_eq!(snapshot(&tx), before);
    tx.rollback().unwrap();
}

#[test]
fn joint_history_gate_other_profiles_keep_original_paths() {
    for (mode, expected_rows) in [
        (RetainedConfigMode::Legacy, 0),
        (RetainedConfigMode::BoundedV1, 0),
        (RetainedConfigMode::NetconfTargetsV1, 1),
    ] {
        let conn = provision(mode);
        let tx = conn.unchecked_transaction().unwrap();
        let (result, counts) = observe(None, None, || {
            crate::consensus::history::validate_access_for_profile_sync(
                &tx,
                &key(),
                true,
                Some(identity()),
                mode,
                &SqliteWorkCancellation::audit_test(),
            )
        });
        result.unwrap();
        assert_eq!(
            counts.rows, expected_rows,
            "HISTORY_GATE_OTHER_PROFILES_UNCHANGED"
        );
        assert_eq!(counts.recoveries, 0);
        tx.rollback().unwrap();
    }
}

#[path = "joint_native_receipt_cost.rs"]
pub(in crate::consensus) mod receipt_cost_tests;

#[path = "joint_native_apply_original.rs"]
pub(in crate::consensus) mod apply_original_tests;
