use super::*;
use crate::scope_authority::tests::execution;
use crate::scope_authority::{
    ScopeAuthorityCommand, ScopeAuthorityOperation, ScopeAuthorityRequest, ScopeAuthorityStamp,
    ScopeAuthorityView, ScopeId, ScopeProfileActivation, ScopeProfileContinuation,
};
use crate::scope_batch::tests::{claim, create, key, value};
use crate::scope_batch::*;
use crate::scope_storage::{self as rows, ScopeRow};

struct Both {
    sql: SqliteSessionBackend,
    #[cfg(target_os = "linux")]
    native: crate::consensus::native::NativeState,
    scope: ScopeId,
    index: u64,
}

impl Both {
    fn new(activate: bool) -> Self {
        let sql = SqliteSessionBackend::in_memory().unwrap();
        let voters = members(&[7, 8, 9]);
        initialize_schema(&sql.conn.blocking_lock(), identity(), &voters).unwrap();
        let membership = membership_entry_at(0, vec![voters.clone()], voters.clone());
        apply_entries_sync(
            &sql.conn.blocking_lock(),
            identity(),
            &sql.caps,
            vec![membership.clone()],
        )
        .unwrap();
        #[cfg(target_os = "linux")]
        let native = {
            let mut native =
                crate::consensus::native::NativeState::empty(identity(), voters.clone()).unwrap();
            native.apply(&[membership]).unwrap();
            native
        };
        let mut both = Self {
            sql,
            #[cfg(target_os = "linux")]
            native,
            scope: ScopeId::new(
                identity(),
                TenantId::from_static("batch-parity"),
                NetworkFunctionKind::smf(),
                [1; 32],
            )
            .unwrap(),
            index: 0,
        };
        if activate {
            let result = both.apply(
                SessionMutationIntent::ActivateScopeProfile(Box::new(ScopeProfileActivation::new(
                    identity(),
                    fenced_transition_voter_set_digest(identity(), &voters),
                ))),
                timestamp(4),
            );
            assert_eq!(result, SessionMutationOutcome::Unit);
        }
        both
    }

    fn apply(&mut self, mutation: SessionMutationIntent, now: Timestamp) -> SessionMutationOutcome {
        self.index += 1;
        let request_id = match &mutation {
            SessionMutationIntent::ScopeAuthority(command) => *command.request.request_id(),
            SessionMutationIntent::ScopeBatch(command) => *command.request.request_id(),
            _ => (0x1000 + u128::from(self.index)).to_be_bytes(),
        };
        let entry = Entry {
            log_id: log_id(self.index),
            payload: EntryPayload::Normal(SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity: identity(),
                request_id: SessionConsensusRequestId::from_bytes(request_id),
                logical_time: now,
                intent: SessionMutationIntent::Authorized {
                    origin: member(7),
                    authority_identity: identity(),
                    mutation: Box::new(mutation),
                },
            }),
        };
        let sql = apply_entries_sync(
            &self.sql.conn.blocking_lock(),
            identity(),
            &self.sql.caps,
            vec![entry.clone()],
        )
        .unwrap();
        #[cfg(target_os = "linux")]
        {
            let native = self.native.apply(&[entry]).unwrap();
            assert_eq!(
                native.responses, sql.responses,
                "the two engines commit the same complete response"
            );
        }
        sql.responses.into_iter().next().unwrap().result.unwrap()
    }

    fn authority(
        &mut self,
        revision: u64,
        operation: ScopeAuthorityOperation,
        second: i64,
    ) -> ScopeAuthorityView {
        let now = timestamp(0).add_seconds(second).unwrap();
        let result = self.apply(
            SessionMutationIntent::ScopeAuthority(Box::new(ScopeAuthorityCommand {
                request: ScopeAuthorityRequest::new(
                    self.scope.clone(),
                    (0x2000 + u128::from(self.index)).to_be_bytes(),
                    revision,
                    operation,
                )
                .unwrap(),
            })),
            now,
        );
        match result {
            SessionMutationOutcome::ScopeAuthority(Ok(checkpoint)) => {
                checkpoint.state().unwrap().view
            }
            other => panic!("scope lease must succeed: {other:?}"),
        }
    }

    fn namespace(&self) -> crate::scope_authority::ScopeNamespace {
        crate::scope_authority::ScopeNamespace::new(
            self.scope.clone(),
            crate::scope_authority::ScopeIncarnation::new(1).unwrap(),
        )
        .unwrap()
    }
    fn admit(&mut self) -> ScopeAuthorityStamp {
        self.authority(
            0,
            ScopeAuthorityOperation::AdmitInitial {
                execution: execution(1),
            },
            4,
        )
        .stamp()
        .unwrap()
        .clone()
    }

    fn command(
        &self,
        permit: &ScopeAuthorityStamp,
        id: u8,
        revision: u64,
        operations: Vec<ScopeChildMutation>,
        counters: Vec<ScopeCounterMutation>,
    ) -> ScopeBatchCommand {
        ScopeBatchCommand {
            request: ScopeBatchRequest::new(permit, [id; 16], revision, operations, counters)
                .unwrap(),
        }
    }

    fn batch(
        &mut self,
        command: &ScopeBatchCommand,
        second: i64,
    ) -> Result<ScopeBatchOutcome, ScopeBatchError> {
        let result = self.apply(
            SessionMutationIntent::ScopeBatch(Box::new(command.clone())),
            timestamp(0).add_seconds(second).unwrap(),
        );
        self.assert_rows();
        match result {
            SessionMutationOutcome::ScopeBatch(result) => result,
            other => panic!("batch result: {other:?}"),
        }
    }

    fn row(&self, key: &SessionKey) -> Option<ScopeRow> {
        let row = super::super::scope_batch::read(&self.sql.conn.blocking_lock(), key).unwrap();
        #[cfg(target_os = "linux")]
        assert_eq!(self.native.scope_record(identity(), key).unwrap(), row);
        row
    }

    fn assert_rows(&self) {
        validate_sealed_state_sync(&self.sql.conn.blocking_lock()).unwrap();
        self.row(&rows::batch_key(&self.scope).unwrap());
        for n in 1..=70 {
            self.row(&rows::child_key(&self.namespace(), key(n)).unwrap());
            self.row(&rows::claim_key(&self.namespace(), claim(n)).unwrap());
        }
        let receipts: u64 = self
            .sql
            .conn
            .blocking_lock()
            .query_row(
                "SELECT COUNT(*) FROM consensus_request_outcomes",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            receipts, 1,
            "only the one cluster activation has an ordinary receipt"
        );
    }

    fn bytes(&self) -> Vec<(String, Vec<u8>, i64, Vec<u8>)> {
        let conn = self.sql.conn.blocking_lock();
        let mut statement = conn.prepare("SELECT key_type,stable_id,generation,payload FROM session_records ORDER BY key_type,stable_id").unwrap();
        statement
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }
}

#[test]
fn scope_batch_sqlite_local_decode_fault_aborts_apply_without_advancing_state() {
    for kind in 0..4 {
        let mut both = Both::new(true);
        let permit = both.admit();
        let first = both
            .batch(
                &both.command(
                    &permit,
                    1,
                    0,
                    vec![create(1, &[1])],
                    vec![ScopeCounterMutation::new(0, 0, 1).unwrap()],
                ),
                4,
            )
            .unwrap();
        let command = both.command(
            &permit,
            2,
            1,
            vec![ScopeChildMutation::CompareAndSet {
                key: key(1),
                expected: first.rows()[0],
                value: value(2),
                claims: vec![claim(1)],
            }],
            vec![ScopeCounterMutation::new(0, 1, 2).unwrap()],
        );
        let damaged = match kind {
            0 => rows::child_key(&both.namespace(), key(1)).unwrap(),
            1 => rows::claim_key(&both.namespace(), claim(1)).unwrap(),
            2 => rows::batch_key(&both.scope).unwrap(),
            _ => both.scope.key().unwrap(),
        };
        let entry = Entry {
            log_id: log_id(both.index + 1),
            payload: EntryPayload::Normal(SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity: identity(),
                request_id: SessionConsensusRequestId::from_bytes(*command.request.request_id()),
                logical_time: timestamp(4),
                intent: SessionMutationIntent::Authorized {
                    origin: member(7),
                    authority_identity: identity(),
                    mutation: Box::new(SessionMutationIntent::ScopeBatch(Box::new(command))),
                },
            }),
        };
        let conn = both.sql.conn.blocking_lock();
        let original = ops::get_raw_sync(&conn, &damaged).unwrap().unwrap();
        conn.execute(
            "UPDATE session_records SET payload=X'00' WHERE key_type=?1 AND stable_id=?2",
            params![damaged.key_type.as_str(), damaged.stable_id.as_bytes()],
        )
        .unwrap();
        let applied = read_applied_sync(&conn, identity()).unwrap();
        let machine = read_machine_sync(&conn, identity()).unwrap();
        let faulted = apply_entries_sync(&conn, identity(), &both.sql.caps, vec![entry.clone()]);
        assert!(
            faulted.is_err(),
            "a local SQLite decode fault in row kind {kind} must abort, not commit a batch result: {faulted:?}"
        );
        assert_eq!(read_applied_sync(&conn, identity()).unwrap(), applied);
        assert_eq!(read_machine_sync(&conn, identity()).unwrap(), machine);
        // Restoring the injected fault makes the exact same log entry apply.
        // This proves the failure belongs to local state, not its request.
        ops::insert_or_replace_scope_record_sync(&conn, &original).unwrap();
        let healthy = apply_entries_sync(&conn, identity(), &both.sql.caps, vec![entry]).unwrap();
        assert!(matches!(
            &healthy.responses[0].result,
            Ok(SessionMutationOutcome::ScopeBatch(Ok(outcome)))
                if outcome.revision() == 2 && outcome.counters()[0] == 2
        ));
        assert_eq!(
            read_machine_sync(&conn, identity()).unwrap().0,
            machine.0 + 1
        );
    }
}

#[test]
fn scope_batch_native_sqlite_atomic_children_claims_counters_and_exact_births() {
    let mut both = Both::new(true);
    let permit = both.admit();
    let first_command = both.command(
        &permit,
        1,
        0,
        vec![create(1, &[1]), create(2, &[2])],
        vec![ScopeCounterMutation::new(0, 0, 2).unwrap()],
    );
    let first = both.batch(&first_command, 4).unwrap();
    let before = both.bytes();
    for command in [
        both.command(&permit, 2, 1, vec![create(3, &[3]), create(1, &[])], vec![]),
        both.command(
            &permit,
            3,
            1,
            vec![create(3, &[3]), create(4, &[1])],
            vec![ScopeCounterMutation::new(0, 2, 4).unwrap()],
        ),
        both.command(
            &permit,
            4,
            1,
            vec![create(3, &[3])],
            vec![ScopeCounterMutation::new(0, 0, 1).unwrap()],
        ),
    ] {
        assert!(matches!(
            both.batch(&command, 4),
            Err(ScopeBatchError::Conflict(_))
        ));
        assert_eq!(
            both.bytes(),
            before,
            "no failed batch may publish a child, claim, counter, birth or result"
        );
    }
    assert_eq!(both.batch(&first_command, 4).unwrap(), first);
    let swap = both.command(
        &permit,
        5,
        1,
        vec![
            ScopeChildMutation::CompareAndSet {
                key: key(1),
                expected: first.rows()[0],
                value: value(3),
                claims: vec![claim(2)],
            },
            ScopeChildMutation::CompareAndSet {
                key: key(2),
                expected: first.rows()[1],
                value: value(4),
                claims: vec![claim(1)],
            },
        ],
        vec![],
    );
    let swapped = both.batch(&swap, 4).unwrap();
    let delete = both.command(
        &permit,
        6,
        2,
        vec![ScopeChildMutation::Delete {
            key: key(1),
            expected: swapped.rows()[0],
        }],
        vec![],
    );
    both.batch(&delete, 4).unwrap();
    assert_eq!(
        both.batch(&first_command, 4),
        Err(ScopeBatchError::RevisionConflict),
        "delayed create cannot resurrect a deletion"
    );
    let replace = both.command(&permit, 7, 3, vec![create(1, &[2])], vec![]);
    let replacement = both.batch(&replace, 4).unwrap();
    assert_eq!(
        replacement.rows()[0].birth(),
        3,
        "failed batches and CAS never consume a birth"
    );
    assert_eq!(replacement.rows()[0].generation(), 1);
    let before = both.bytes();
    for mutation in [
        ScopeChildMutation::Delete {
            key: key(1),
            expected: first.rows()[0],
        },
        ScopeChildMutation::CompareAndSet {
            key: key(1),
            expected: first.rows()[0],
            value: value(9),
            claims: vec![],
        },
    ] {
        let stale = both.command(&permit, 8, 4, vec![mutation], vec![]);
        assert!(matches!(
            both.batch(&stale, 4),
            Err(ScopeBatchError::Conflict(_))
        ));
        assert_eq!(both.bytes(), before);
    }
}

#[test]
fn scope_batch_native_sqlite_current_authority_survives_elapsed_application_time() {
    let mut both = Both::new(true);
    let stamp = both.admit();
    let first = both.command(&stamp, 1, 0, vec![create(1, &[1])], vec![]);
    both.batch(&first, 86400).unwrap();
    let pending = both.command(&stamp, 2, 1, vec![create(2, &[2])], vec![]);
    both.authority(
        1,
        ScopeAuthorityOperation::SucceedClosed {
            predecessor: stamp,
            execution: execution(2),
            evidence: crate::scope_authority::ScopeClosureEvidence::new(
                crate::scope_authority::ScopeClosureKind::FinalTermination,
                [2; 32],
            )
            .unwrap(),
        },
        86401,
    );
    let before = both.bytes();
    assert!(matches!(
        both.batch(&pending, 86402),
        Err(ScopeBatchError::Scope(
            crate::scope_authority::ScopeAuthorityError::StaleAuthority
        ))
    ));
    assert_eq!(both.bytes(), before);
    assert!(
        both.batch(&first, 86403).is_ok(),
        "exact receipt replay has no effects"
    );
    assert_eq!(both.bytes(), before);
}

#[test]
fn scope_batch_native_sqlite_refuses_before_profile_activation() {
    let mut both = Both::new(false);
    let state = crate::scope_authority::ScopeState::empty(both.scope.clone());
    let state = state
        .transition(
            &ScopeAuthorityRequest::new(
                both.scope.clone(),
                [1; 16],
                0,
                ScopeAuthorityOperation::AdmitInitial {
                    execution: execution(1),
                },
            )
            .unwrap(),
        )
        .unwrap();
    let command = both.command(
        state.view.stamp().unwrap(),
        3,
        0,
        vec![create(1, &[1])],
        vec![],
    );
    assert_eq!(
        both.apply(
            SessionMutationIntent::ScopeBatch(Box::new(command)),
            timestamp(4)
        ),
        SessionMutationOutcome::ScopeBatch(Err(ScopeBatchError::Scope(
            crate::scope_authority::ScopeAuthorityError::ProfileNotActivated
        )))
    );
    assert!(both.bytes().is_empty());
}

#[test]
fn scope_batch_native_sqlite_refuses_before_initial_admission_with_same_error() {
    let mut both = Both::new(true);
    let uncommitted = crate::scope_authority::ScopeState::empty(both.scope.clone())
        .transition(
            &ScopeAuthorityRequest::new(
                both.scope.clone(),
                [1; 16],
                0,
                ScopeAuthorityOperation::AdmitInitial {
                    execution: execution(1),
                },
            )
            .unwrap(),
        )
        .unwrap();
    let command = both.command(
        uncommitted.view.stamp().unwrap(),
        3,
        0,
        vec![create(1, &[1])],
        vec![ScopeCounterMutation::new(0, 0, 1).unwrap()],
    );
    let before = both.bytes();
    assert_eq!(
        both.batch(&command, 4),
        Err(ScopeBatchError::Scope(
            crate::scope_authority::ScopeAuthorityError::StaleAuthority
        ))
    );
    assert_eq!(both.bytes(), before, "an unadmitted scope writes no rows");
    assert!(both.row(&rows::batch_key(&both.scope).unwrap()).is_none());
}

#[test]
fn required_zero_ledger_is_created_with_initial_authority() {
    let mut both = Both::new(true);
    both.admit();
    let row = both.row(&rows::batch_key(&both.scope).unwrap());
    let Some(ScopeRow::Batch(checkpoint)) = row else {
        panic!("initial authority must atomically create its required stable ledger")
    };
    assert_eq!(*checkpoint, ScopeBatchCheckpoint::empty(both.scope.clone()));
    let row = ScopeRow::Batch(checkpoint);
    assert_eq!(
        ScopeRow::from_record(&row.to_record().unwrap()).unwrap(),
        row
    );
    both.assert_rows();
}

#[test]
fn required_counter_ledger_loss_is_corruption_without_child_rows() {
    let mut both = Both::new(true);
    let stamp = both.admit();
    let command = both.command(
        &stamp,
        1,
        0,
        vec![],
        vec![ScopeCounterMutation::new(0, 0, 9).unwrap()],
    );
    both.batch(&command, 4).unwrap();
    let conn = both.sql.conn.blocking_lock();
    assert_eq!(
        conn.execute(
            "DELETE FROM session_records WHERE key_type='opc-scope-batch'",
            []
        )
        .unwrap(),
        1
    );
    assert!(
        validate_sealed_state_sync(&conn).is_err(),
        "missing stable counters cannot be admitted as a never-used scope"
    );
}

#[test]
fn scope_batch_snapshot_higher_revision_cannot_lower_any_counter_or_birth_floor() {
    let mut both = Both::new(true);
    let stamp = both.admit();
    let initial = both.command(
        &stamp,
        1,
        0,
        vec![create(1, &[]), create(2, &[])],
        (0..SCOPE_COUNTERS)
            .map(|index| ScopeCounterMutation::new(index as u8, 0, 10 + index as u64).unwrap())
            .collect(),
    );
    both.batch(&initial, 4).unwrap();
    // Retain the births even when the latest receipt contains no child rows.
    let compare = both.command(
        &stamp,
        2,
        1,
        vec![],
        vec![ScopeCounterMutation::new(0, 10, 10).unwrap()],
    );
    both.batch(&compare, 4).unwrap();
    let retained = both.row(&rows::batch_key(&both.scope).unwrap()).unwrap();
    let mut future = serde_json::to_value(&retained).unwrap();
    future["Batch"]["revision"] = 3.into();
    future["Batch"]["lanes"][0]["sequence"] = 3.into();
    future["Batch"]["lanes"][0]["floor"] = 2.into();
    future["Batch"]["lanes"][0]["outcome"]["sequence"] = 3.into();
    future["Batch"]["lanes"][0]["outcome"]["revision"] = 3.into();
    let conn = both.sql.conn.blocking_lock();
    conn.execute("ATTACH DATABASE ':memory:' AS consensus_incoming", [])
        .unwrap();
    conn.execute(
        "CREATE TABLE consensus_incoming.session_records AS SELECT * FROM main.session_records",
        [],
    )
    .unwrap();
    let replace_incoming = |value| {
        let row: ScopeRow = serde_json::from_value(value).unwrap();
        // Every candidate has a valid current encoding and a higher revision.
        // The rejection must come from the retained floor comparison.
        let record = row.to_record().unwrap();
        conn.execute(
            "UPDATE consensus_incoming.session_records SET generation=?1,payload=?2 WHERE key_type='opc-scope-batch'",
            params![record.generation.get(), record.payload.as_bytes()],
        )
        .unwrap();
    };
    let validate = || super::super::scope_batch::validate_snapshot_preserves_scopes(&conn);
    replace_incoming(future.clone());
    validate().expect("higher revision preserving all floors is allowed");
    for index in 0..SCOPE_COUNTERS {
        let mut rollback = future.clone();
        rollback["Batch"]["counters"][index] = (9 + index as u64).into();
        rollback["Batch"]["lanes"][0]["outcome"]["counters"][index] = (9 + index as u64).into();
        replace_incoming(rollback);
        assert!(validate().is_err(), "counter {index} is a protected floor");
    }
    let mut rollback = future.clone();
    rollback["Batch"]["birth_floor"] = 1.into();
    replace_incoming(rollback);
    assert!(validate().is_err(), "birth floor never resets");
    replace_incoming(future);
    validate().unwrap();
}

#[test]
fn scope_batch_snapshot_install_preserves_authority_claim_and_deleted_birth_floors() {
    let mut both = Both::new(true);
    let permit = both.admit();
    let create = both.command(&permit, 1, 0, vec![create(1, &[1])], vec![]);
    let created = both.batch(&create, 4).unwrap();
    let live_record = both
        .row(&rows::child_key(&both.namespace(), key(1)).unwrap())
        .unwrap()
        .to_record()
        .unwrap();
    let delete = both.command(
        &permit,
        2,
        1,
        vec![ScopeChildMutation::Delete {
            key: key(1),
            expected: created.rows()[0],
        }],
        vec![],
    );
    both.batch(&delete, 4).unwrap();
    let conn = both.sql.conn.blocking_lock();
    // An aborted transition retains its continuation floor alongside the
    // predecessor activation and the existing scope rows.
    let desired = identity_at(2, 0xA3);
    let desired_members = members(&[7, 8, 10]);
    let continuation = ScopeProfileContinuation {
        transition_id: [0xA3; 16],
        transition_digest: [0xA3; 32],
        predecessor: ScopeProfileActivation::new(
            identity(),
            fenced_transition_voter_set_digest(identity(), &members(&[7, 8, 9])),
        ),
        successor: ScopeProfileActivation::new(
            desired,
            fenced_transition_voter_set_digest(desired, &desired_members),
        ),
    };
    let intents = [
        SessionMutationIntent::PrepareTopologyTransition {
            transition_id: continuation.transition_id,
            request_digest: continuation.transition_digest,
            desired_identity: desired,
            desired_bindings: test_member_bindings(&desired_members),
            desired_members,
        },
        SessionMutationIntent::CertifyScopeProfileContinuation(Box::new(continuation.clone())),
        SessionMutationIntent::AbortTopologyTransition {
            transition_id: continuation.transition_id,
            request_digest: continuation.transition_digest,
        },
    ];
    for (offset, intent) in intents.into_iter().enumerate() {
        let index = both.index + offset as u64 + 1;
        let applied = apply_entries_sync(
            &conn,
            identity(),
            &both.sql.caps,
            vec![topology_entry_at(index, index as u8, intent)],
        )
        .unwrap();
        assert!(applied.responses.iter().all(|reply| reply.result.is_ok()));
    }
    conn.execute("ATTACH DATABASE ':memory:' AS consensus_incoming", [])
        .unwrap();
    conn.execute(
        "CREATE TABLE consensus_incoming.session_records AS SELECT * FROM main.session_records",
        [],
    )
    .unwrap();
    let validate = || super::super::scope_batch::validate_snapshot_preserves_scopes(&conn);
    validate().expect("same complete snapshot preserves every floor");
    // The legacy key is reserved only for refusal; current state never creates it.
    for kind in rows::RESERVED_KEY_TYPES
        .into_iter()
        .filter(|kind| *kind != "opc-scope-lease")
    {
        let removed = conn
            .execute(
                "DELETE FROM consensus_incoming.session_records WHERE key_type=?1",
                [kind],
            )
            .unwrap();
        assert!(removed > 0, "fixture must retain a {kind} row");
        assert!(validate().is_err(), "snapshot cannot omit {kind}");
        conn.execute("INSERT INTO consensus_incoming.session_records SELECT * FROM main.session_records WHERE key_type=?1", [kind]).unwrap();
        validate().unwrap();
    }
    conn.execute("UPDATE consensus_incoming.session_records SET generation=?1,payload=?2 WHERE key_type='opc-scope-child'",
        params![live_record.generation.get(), live_record.payload.as_bytes()]).unwrap();
    assert!(
        validate().is_err(),
        "a live predecessor cannot resurrect a deleted birth"
    );
    conn.execute("INSERT INTO key_fences (tenant,nf_kind,key_type,stable_id,fence) SELECT tenant,nf_kind,key_type,stable_id,1 FROM main.session_records WHERE key_type='opc-scope-child'", []).unwrap();
    assert!(
        validate_sealed_state_sync(&conn).is_err(),
        "ordinary fencing cannot be attached to scope children"
    );
}
