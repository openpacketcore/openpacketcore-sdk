use super::*;
use crate::scope_batch::tests::{claim, create, key, value};
use crate::scope_batch::*;
use crate::scope_lease::tests::execution;
use crate::scope_lease::{
    ScopeClockBounds, ScopeLeaseCommand, ScopeLeaseId, ScopeLeaseOperation, ScopeLeaseRequest,
    ScopeLeaseView, ScopePermit, ScopeProfileActivation,
};
use crate::scope_storage::{self as rows, ScopeRow};

struct Both {
    sql: SqliteSessionBackend,
    #[cfg(target_os = "linux")]
    native: crate::consensus::native::NativeState,
    scope: ScopeLeaseId,
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
            scope: ScopeLeaseId::new(
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
            SessionMutationIntent::ScopeLease(command) => *command.request.request_id(),
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

    fn lease(
        &mut self,
        revision: u64,
        operation: ScopeLeaseOperation,
        second: i64,
    ) -> ScopeLeaseView {
        let now = timestamp(0).add_seconds(second).unwrap();
        let result = self.apply(
            SessionMutationIntent::ScopeLease(Box::new(ScopeLeaseCommand {
                request: ScopeLeaseRequest::new(
                    self.scope.clone(),
                    (0x2000 + u128::from(self.index)).to_be_bytes(),
                    revision,
                    operation,
                )
                .unwrap(),
                bounds: ScopeClockBounds::new(now, now).unwrap(),
            })),
            now,
        );
        match result {
            SessionMutationOutcome::ScopeLease(Ok(checkpoint)) => checkpoint.state().unwrap().view,
            other => panic!("scope lease must succeed: {other:?}"),
        }
    }

    fn acquire(&mut self) -> ScopePermit {
        self.lease(
            0,
            ScopeLeaseOperation::Select {
                execution: execution(1),
            },
            4,
        );
        self.lease(
            1,
            ScopeLeaseOperation::Acquire {
                execution: execution(1),
                selection: 1,
            },
            4,
        )
        .permit()
        .unwrap()
        .clone()
    }

    fn command(
        &self,
        permit: &ScopePermit,
        id: u8,
        revision: u64,
        operations: Vec<ScopeChildMutation>,
        counters: Vec<ScopeCounterMutation>,
    ) -> ScopeBatchCommand {
        ScopeBatchCommand {
            request: ScopeBatchRequest::new(permit, [id; 16], revision, operations, counters)
                .unwrap(),
            bounds: ScopeClockBounds::new(timestamp(4), timestamp(4)).unwrap(),
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
            self.row(&rows::child_key(&self.scope, key(n)).unwrap());
            self.row(&rows::claim_key(&self.scope, claim(n)).unwrap());
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
        let permit = both.acquire();
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
            0 => rows::child_key(&both.scope, key(1)).unwrap(),
            1 => rows::claim_key(&both.scope, claim(1)).unwrap(),
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
    let permit = both.acquire();
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
fn scope_batch_native_sqlite_checks_current_grant_and_replicated_apply_time() {
    let mut both = Both::new(true);
    let permit = both.acquire();
    let pending = both.command(&permit, 1, 0, vec![create(1, &[1])], vec![]);
    let renewed = both.lease(
        2,
        ScopeLeaseOperation::Renew {
            permit: permit.clone(),
        },
        5,
    );
    both.batch(&pending, 5)
        .expect("stable grant remains valid across renewal");
    let pending = both.command(&permit, 2, 1, vec![create(2, &[2])], vec![]);
    let before = both.bytes();
    assert!(matches!(
        both.batch(&pending, 83),
        Err(ScopeBatchError::Scope(
            crate::scope_lease::ScopeLeaseError::Expired
        ))
    ));
    assert_eq!(
        both.bytes(),
        before,
        "preparation time cannot authorize apply after the retained permit expires"
    );
    both.lease(
        3,
        ScopeLeaseOperation::Select {
            execution: execution(2),
        },
        100,
    );
    both.lease(
        4,
        ScopeLeaseOperation::Acquire {
            execution: execution(2),
            selection: 2,
        },
        100,
    );
    let before = both.bytes();
    assert!(matches!(
        both.batch(&pending, 100),
        Err(ScopeBatchError::Scope(
            crate::scope_lease::ScopeLeaseError::StalePermit
        ))
    ));
    assert_eq!(both.bytes(), before);
    assert!(renewed.permit().unwrap().stop_at() > permit.stop_at());
}

#[test]
fn scope_batch_native_sqlite_refuses_before_profile_activation() {
    let mut both = Both::new(false);
    let state = crate::scope_lease::ScopeState::empty(both.scope.clone());
    let state = state
        .transition(
            &ScopeLeaseRequest::new(
                both.scope.clone(),
                [1; 16],
                0,
                ScopeLeaseOperation::Select {
                    execution: execution(1),
                },
            )
            .unwrap(),
            ScopeClockBounds::new(timestamp(4), timestamp(4)).unwrap(),
        )
        .unwrap();
    let state = state
        .transition(
            &ScopeLeaseRequest::new(
                both.scope.clone(),
                [2; 16],
                1,
                ScopeLeaseOperation::Acquire {
                    execution: execution(1),
                    selection: 1,
                },
            )
            .unwrap(),
            ScopeClockBounds::new(timestamp(4), timestamp(4)).unwrap(),
        )
        .unwrap();
    let command = both.command(
        state.view.permit().unwrap(),
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
            crate::scope_lease::ScopeLeaseError::ProfileNotActivated
        )))
    );
    assert!(both.bytes().is_empty());
}

#[test]
fn scope_batch_snapshot_install_preserves_authority_claim_and_deleted_birth_floors() {
    let mut both = Both::new(true);
    let permit = both.acquire();
    let create = both.command(&permit, 1, 0, vec![create(1, &[1])], vec![]);
    let created = both.batch(&create, 4).unwrap();
    let live_record = both
        .row(&rows::child_key(&both.scope, key(1)).unwrap())
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
    conn.execute("ATTACH DATABASE ':memory:' AS consensus_incoming", [])
        .unwrap();
    conn.execute(
        "CREATE TABLE consensus_incoming.session_records AS SELECT * FROM main.session_records",
        [],
    )
    .unwrap();
    let validate = || super::super::scope_batch::validate_snapshot_preserves_scopes(&conn);
    validate().expect("same complete snapshot preserves every floor");
    for kind in rows::RESERVED_KEY_TYPES {
        conn.execute(
            "DELETE FROM consensus_incoming.session_records WHERE key_type=?1",
            [kind],
        )
        .unwrap();
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
