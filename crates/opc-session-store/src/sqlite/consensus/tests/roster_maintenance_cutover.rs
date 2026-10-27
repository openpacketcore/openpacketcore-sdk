use super::*;
use crate::consensus::v1_fixture;
use crate::{CompareAndSet, StateType};

fn command(
    storage: SessionConsensusIdentity,
    authority: SessionConsensusIdentity,
    index: u64,
    now: Timestamp,
    intent: SessionMutationIntent,
) -> Entry<SessionRaftTypeConfig> {
    let intent = match intent {
        SessionMutationIntent::PrepareTopologyTransition { .. }
        | SessionMutationIntent::MarkTopologyLearnersReady { .. }
        | SessionMutationIntent::FinalizeTopologyTransition { .. } => intent,
        mutation => SessionMutationIntent::Authorized {
            origin: node_id(),
            authority_identity: authority,
            mutation: Box::new(mutation),
        },
    };
    Entry {
        log_id: log_id(index),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: storage,
            request_id: SessionConsensusRequestId::from_bytes(
                (0xD000_u128 + u128::from(index)).to_be_bytes(),
            ),
            logical_time: now,
            intent,
        }),
    }
}

fn apply_cutover_entries(
    conn: &Connection,
    backend: &SqliteSessionBackend,
    identity: SessionConsensusIdentity,
    entries: Vec<Entry<SessionRaftTypeConfig>>,
) -> AppliedBatch {
    append_logs_sync(conn, identity, &entries).expect("append exact committed commands");
    save_committed_sync(conn, identity, entries.last().map(|entry| entry.log_id))
        .expect("commit exact command prefix");
    apply_entries_sync(conn, identity, &backend.caps, entries)
        .expect("inactive roster history must not stop committed apply")
}

fn activation(
    v1: bool,
    identity: SessionConsensusIdentity,
    voters: &BTreeSet<SessionConsensusNodeId>,
) -> SessionMutationIntent {
    if v1 {
        SessionMutationIntent::ActivateFencedTransitionCapability {
            schema_version: FENCED_TRANSITION_SCHEMA_V1,
            scope_identity: identity,
            voter_set_digest: protected_roster_profile_voter_set_digest(identity, voters),
        }
    } else {
        let profile = crate::fenced_mutation_roster::Profile::v2();
        SessionMutationIntent::ActivateProtectedRosterProfileV2 {
            schema_version: profile.schema(),
            consumer_revision: profile.consumer_revision(),
            scope_identity: identity,
            voter_set_digest: protected_roster_profile_v2_voter_set_digest(identity, voters),
            profile_digest: profile.digest(),
        }
    }
}

fn reactivate_v2(
    conn: &Connection,
    backend: &SqliteSessionBackend,
    storage: SessionConsensusIdentity,
    scope: SessionConsensusIdentity,
    voters: &BTreeSet<SessionConsensusNodeId>,
    now: Timestamp,
) {
    // Exercise the production activation step, including its current-scope,
    // voter and profile checks. Log admission separately requires V2's scope
    // to equal the storage anchor, so it cannot drive successor activation.
    // This maintenance test does not bypass or change that validator.
    let tx = conn.unchecked_transaction().unwrap();
    let (outcome, replication) =
        execute_application_intent_sync(&tx, &activation(false, scope, voters), &backend.caps, now)
            .expect("activate V2 for the exact successor scope");
    assert_eq!(outcome, SessionMutationOutcome::Unit);
    assert!(replication.is_none());
    tx.commit().unwrap();
    assert!(protected_roster_profile_v2_activation_matches_scope_sync(
        conn, storage, scope, voters
    )
    .unwrap());
}

fn table_image(
    conn: &Connection,
    tables: impl IntoIterator<Item = &'static str>,
) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    tables
        .into_iter()
        .map(|table| {
            let mut query = conn
                .prepare(&format!("SELECT * FROM {table} ORDER BY 1"))
                .unwrap();
            let columns = query.column_count();
            query
                .query_map([], |row| {
                    (0..columns).map(|column| row.get(column)).collect()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        })
        .collect()
}

fn roster_image(conn: &Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    table_image(
        conn,
        PROTECTED_ROSTER_TABLES
            .iter()
            .chain(PROTECTED_ROSTER_V2_TABLES)
            .copied(),
    )
}

fn v1_binding_image(conn: &Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    table_image(
        conn,
        [
            "consensus_protected_roster_rows",
            "consensus_protected_roster_business",
            "consensus_protected_roster_admissions",
        ],
    )
}

fn row_states(conn: &Connection) -> Vec<i64> {
    conn.prepare(
        "SELECT state FROM consensus_protected_roster_rows UNION ALL \
         SELECT state FROM consensus_protected_roster_v2_admissions ORDER BY state",
    )
    .unwrap()
    .query_map([], |row| row.get(0))
    .unwrap()
    .collect::<rusqlite::Result<Vec<_>>>()
    .unwrap()
}

struct CutoverState {
    storage: SessionConsensusIdentity,
    successor_identity: SessionConsensusIdentity,
    successor: BTreeSet<SessionConsensusNodeId>,
    now: Timestamp,
    due: Timestamp,
    next: u64,
}

impl CutoverState {
    fn apply(
        &mut self,
        conn: &Connection,
        backend: &SqliteSessionBackend,
        now: Timestamp,
        intent: SessionMutationIntent,
    ) -> AppliedBatch {
        let applied = apply_cutover_entries(
            conn,
            backend,
            self.storage,
            vec![command(
                self.storage,
                self.successor_identity,
                self.next,
                now,
                intent,
            )],
        );
        assert_eq!(
            read_applied_sync(conn, self.storage).unwrap(),
            Some(log_id(self.next))
        );
        assert_eq!(
            proposal_state_sync(conn, self.storage).unwrap().2,
            Some(now)
        );
        self.next += 1;
        applied
    }
}

fn with_inactive_history_after_cutover(
    v1: bool,
    check: impl FnOnce(&Connection, &SqliteSessionBackend, CutoverState),
) {
    with_inactive_history_layout_after_cutover(v1, true, false, check);
}

fn with_inactive_history_layout_after_cutover(
    v1: bool,
    v2_history: bool,
    reclaim_before_cutover: bool,
    check: impl FnOnce(&Connection, &SqliteSessionBackend, CutoverState),
) {
    assert!(v1 || v2_history, "the fixture must retain history");
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("retained-cutover.sqlite");
    let predecessor = members(&[7, 8, 9]);
    if v2_history {
        initialize_protected_roster_v2_recovery_fixture_with_members(
            &path,
            if v1 {
                ProtectedRosterV2RecoveryFixtureState::Established
            } else {
                ProtectedRosterV2RecoveryFixtureState::Aborted
            },
            predecessor.clone(),
        )
        .unwrap();
    }
    let signed = if v1 {
        crate::consensus::types::roster_v2_persistence_fixture()
    } else {
        crate::consensus::types::roster_v2_aborted_persistence_fixture()
    };
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let conn = backend.conn.blocking_lock();
    let storage = signed.identity;
    let successor = members(&[7, 8, 9, 10, 11]);
    let successor_identity = SessionConsensusIdentity::new(
        storage.cluster_id(),
        SessionConsensusConfigurationId::from_bytes([0xD7; 32]),
        SessionConsensusConfigurationEpoch::new(storage.configuration_epoch().get() + 1).unwrap(),
    );
    let mut now = v2_persistence_logical_time();
    let due = now.add_seconds(24 * 60 * 60 + 1).unwrap();
    if !v2_history {
        // Activate the exact V2 namespace without admitting a V2 roster. A
        // committed ordinary CAS supplies V1's existing-record predecessor.
        initialize_v2_persistence_fixture_with_members(&conn, &signed, &predecessor);
        let authority = &signed.authority;
        ops::insert_or_replace_fence_sync(&conn, authority.key(), authority.fence().get()).unwrap();
        conn.execute(
            "UPDATE lease_globals SET val=MAX(val, ?1) WHERE key='next_fence'",
            [checked_positive_i64(authority.fence().get() + 1).unwrap()],
        )
        .unwrap();
        conn.execute(
            "UPDATE lease_globals SET val=MAX(val, ?1) WHERE key='next_credential_id'",
            [checked_positive_i64(authority.credential_id() + 1).unwrap()],
        )
        .unwrap();
        conn.execute(
            "UPDATE leases SET expires_at_unix_ms=?1",
            [ops::timestamp_unix_millis(authority.expires_at()).unwrap()],
        )
        .unwrap();
        let lease = LeaseGuard::new(
            authority.key().clone(),
            authority.owner().clone(),
            authority.fence(),
            authority.acquired_at(),
            authority.expires_at(),
            authority.credential_id(),
        );
        let mut new_record = StoredSessionRecord {
            key: authority.key().clone(),
            generation: authority.generation(),
            owner: authority.owner().clone(),
            fence: authority.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("roster-predecessor"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([]),
        };
        new_record.payload = sealed_payload_for_record(&new_record, 1_024);
        let applied = apply_cutover_entries(
            &conn,
            &backend,
            storage,
            vec![
                membership_entry_at(0, vec![predecessor.clone()], predecessor.clone()),
                command(
                    storage,
                    storage,
                    1,
                    now,
                    SessionMutationIntent::CompareAndSet(Arc::new(CompareAndSet {
                        key: authority.key().clone(),
                        lease,
                        expected_generation: None,
                        new_record,
                    })),
                ),
                Entry {
                    log_id: log_id(2),
                    payload: EntryPayload::Blank,
                },
            ],
        );
        assert!(applied.responses.iter().any(|response| matches!(
            response.result,
            Ok(SessionMutationOutcome::CompareAndSet(
                CompareAndSetResult::Success
            ))
        )));
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM consensus_protected_roster_v2_admissions",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
    let mut next = 3;
    if v1 {
        let admitted = v1_fixture::signed_v1_command(&signed);
        let terminal = v1_fixture::terminal(
            &signed,
            &admitted,
            4,
            crate::fenced_mutation_roster::Phase::Aborted,
        );
        let mut admission = command(
            storage,
            storage,
            4,
            now,
            SessionMutationIntent::RosterAdmission(Box::new(admitted.clone())),
        );
        let mut completion = command(
            storage,
            storage,
            5,
            now,
            SessionMutationIntent::RosterTerminal(Box::new(terminal.clone())),
        );
        if let EntryPayload::Normal(command) = &mut admission.payload {
            command.request_id = admitted.request_id().unwrap();
        }
        if let EntryPayload::Normal(command) = &mut completion.payload {
            command.request_id = terminal.request_id().unwrap();
        }
        let applied = apply_cutover_entries(
            &conn,
            &backend,
            storage,
            vec![
                command(
                    storage,
                    storage,
                    3,
                    now,
                    activation(true, storage, &predecessor),
                ),
                admission,
                completion,
            ],
        );
        assert!(applied
            .responses
            .iter()
            .all(|response| response.result.is_ok()));
        assert!(matches!(
            applied.responses[2].result,
            Ok(SessionMutationOutcome::RosterTerminal(
                ConsensusRosterTerminalOutcome::Committed { .. }
            ))
        ));
        next = 6;
    }
    let retained_count = usize::from(v1) + usize::from(v2_history);
    assert_eq!(row_states(&conn), vec![2; retained_count]);
    validate_protected_roster_state_sync(&conn, storage).expect("valid signed retained history");

    if reclaim_before_cutover {
        let reclaimed = apply_cutover_entries(
            &conn,
            &backend,
            storage,
            vec![command(
                storage,
                storage,
                next,
                due,
                SessionMutationIntent::AdvanceLogicalTime,
            )],
        );
        assert_eq!(
            reclaimed.responses[0].result,
            Ok(SessionMutationOutcome::Unit)
        );
        assert_eq!(row_states(&conn), vec![3; retained_count]);
        next += 1;
        now = due;
    }

    let transition_id = [0xD8; MEMBERSHIP_TRANSITION_ID_BYTES];
    let transition_digest = [0xD9; 32];
    stage_membership_scope_sync(
        &conn,
        storage,
        transition_id,
        transition_digest,
        successor_identity,
        &successor,
    )
    .expect("stage valid successor scope");
    apply_cutover_entries(
        &conn,
        &backend,
        storage,
        vec![
            membership_entry_at(next, vec![predecessor.clone()], successor.clone()),
            command(
                storage,
                storage,
                next + 1,
                now,
                SessionMutationIntent::MarkTopologyLearnersReady {
                    transition_id,
                    request_digest: transition_digest,
                },
            ),
        ],
    );
    fence_application_authority_sync(&conn, storage, transition_id, transition_digest)
        .expect("fence predecessor before the membership cutover");
    apply_cutover_entries(
        &conn,
        &backend,
        storage,
        vec![
            membership_entry_at(
                next + 2,
                vec![predecessor, successor.clone()],
                successor.clone(),
            ),
            membership_entry_at(next + 3, vec![successor.clone()], successor.clone()),
            command(
                storage,
                successor_identity,
                next + 4,
                now,
                SessionMutationIntent::FinalizeTopologyTransition {
                    transition_id,
                    request_digest: transition_digest,
                },
            ),
        ],
    );
    next += 5;
    let scope = read_membership_scope_sync(&conn, storage).unwrap();
    assert_eq!(scope.current_identity, successor_identity);
    assert!(scope.pending.is_none());
    assert!(scope.predecessor.is_some());
    assert_eq!(
        scope.application_authority_epoch,
        successor_identity.configuration_epoch()
    );
    assert_eq!(scope.application_authority_members, successor);
    assert!(
        read_fenced_transition_activation_certificate_sync(&conn, storage, false)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        protected_roster_v2_layout_in_sync(&conn, false).unwrap(),
        ProtectedRosterV2Layout::Inactive
    );
    assert!(
        read_protected_roster_v2_activation_certificate_in_sync(&conn, storage, false)
            .unwrap()
            .is_none()
    );
    check(
        &conn,
        &backend,
        CutoverState {
            storage,
            successor_identity,
            successor,
            now,
            due,
            next,
        },
    );
}

fn assert_inactive_history_defers_until_reactivation(v1: bool, write_first: bool) {
    with_inactive_history_after_cutover(v1, |conn, backend, state| {
        let CutoverState {
            storage,
            successor_identity,
            successor,
            now,
            due,
            mut next,
        } = state;
        if v1 {
            // Restore V2 while all history is young, leaving only V1 inactive.
            // Otherwise a V2 failure could mask the independent V1 regression.
            reactivate_v2(conn, backend, storage, successor_identity, &successor, now);
            // An inactive V1 profile must not hide a present foreign V2 policy.
            conn.execute(
                "UPDATE consensus_protected_roster_v2_activation SET voter_set_digest=?1",
                [[0xCE_u8; 32].as_slice()],
            )
            .unwrap();
            let foreign = roster_image(conn);
            let changes = conn.total_changes();
            assert!(maintain_due_protected_roster_reclaim_sync(conn, storage, due).is_err());
            assert_eq!(conn.total_changes(), changes);
            assert_eq!(roster_image(conn), foreign);
            reactivate_v2(conn, backend, storage, successor_identity, &successor, now);
        }
        validate_existing_schema(conn, storage).expect("post-cutover inactive layout is valid");
        validate_protected_roster_state_sync(conn, storage)
            .expect("inactive history remains valid");
        let before = roster_image(conn);
        let before_v1 = v1_binding_image(conn);
        let witness = protected_roster_read_witness_sync(conn, storage).unwrap();
        let write = SessionMutationIntent::AcquireLease {
            key: key(),
            owner: OwnerId::new("unrelated-successor-owner").unwrap(),
            ttl: Duration::from_secs(300),
        };
        let intents = if write_first {
            [write, SessionMutationIntent::AdvanceLogicalTime]
        } else {
            [SessionMutationIntent::AdvanceLogicalTime, write]
        };
        for (turn, intent) in intents.into_iter().enumerate() {
            let is_write = matches!(intent, SessionMutationIntent::AcquireLease { .. });
            let applied = apply_cutover_entries(
                conn,
                backend,
                storage,
                vec![command(storage, successor_identity, next, due, intent)],
            );
            assert!(matches!(
                (&applied.responses[0].result, is_write),
                (Ok(SessionMutationOutcome::Lease(_)), true)
                    | (Ok(SessionMutationOutcome::Unit), false)
            ));
            assert_eq!(
                read_applied_sync(conn, storage).unwrap(),
                Some(log_id(next))
            );
            assert_eq!(proposal_state_sync(conn, storage).unwrap().2, Some(due));
            if v1 {
                assert_eq!(
                    v1_binding_image(conn),
                    before_v1,
                    "inactive V1 rows stay byte-identical"
                );
                assert_eq!(
                    row_states(conn),
                    if turn == 0 { vec![2, 3] } else { vec![2] },
                    "ready V2 reclaims and retires independently of inactive V1"
                );
                let current = protected_roster_read_witness_sync(conn, storage)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    retirement_fixture_durable_bindings(current),
                    if turn == 0 { 2 } else { 1 }
                );
                validate_protected_roster_state_sync(conn, storage)
                    .expect("shared floor and exact witness retain inactive V1 history");
            } else {
                assert_eq!(
                    roster_image(conn),
                    before,
                    "inactive maintenance changes no roster state"
                );
                assert_eq!(
                    protected_roster_read_witness_sync(conn, storage).unwrap(),
                    witness
                );
            }
            next += 1;
        }
        let changes = conn.total_changes();
        assert!(!maintain_due_protected_roster_reclaim_sync(conn, storage, due).unwrap());
        assert_eq!(
            conn.total_changes(),
            changes,
            "deferred turn performs no writes"
        );
        if v1 {
            assert!(
                read_fenced_transition_activation_certificate_sync(conn, storage, false)
                    .unwrap()
                    .is_none()
            );
        } else {
            assert!(
                read_protected_roster_v2_activation_certificate_in_sync(conn, storage, false)
                    .unwrap()
                    .is_none()
            );
        }

        let resume = if v1 {
            activation(true, successor_identity, &successor)
        } else {
            reactivate_v2(conn, backend, storage, successor_identity, &successor, due);
            SessionMutationIntent::AdvanceLogicalTime
        };
        let activated = apply_cutover_entries(
            conn,
            backend,
            storage,
            vec![command(storage, successor_identity, next, due, resume)],
        );
        assert_eq!(
            activated.responses[0].result,
            Ok(SessionMutationOutcome::Unit)
        );
        assert_eq!(
            row_states(conn),
            vec![3],
            "activation resumes bounded reclaim of the remaining profile"
        );
        next += 1;
        let retired = apply_cutover_entries(
            conn,
            backend,
            storage,
            vec![command(
                storage,
                successor_identity,
                next,
                due,
                SessionMutationIntent::AdvanceLogicalTime,
            )],
        );
        assert_eq!(
            retired.responses[0].result,
            Ok(SessionMutationOutcome::Unit)
        );
        assert!(
            row_states(conn).is_empty(),
            "next turn resumes terminal retirement"
        );
        for table in [
            "consensus_protected_roster_floors",
            "consensus_protected_roster_retirement_cursors",
        ] {
            assert_eq!(
                conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        assert_eq!(
            retirement_fixture_durable_bindings(
                protected_roster_read_witness_sync(conn, storage)
                    .unwrap()
                    .unwrap()
            ),
            0
        );
        validate_protected_roster_state_sync(conn, storage)
            .expect("resumed maintenance remains valid");
    });
}

#[test]
fn roster_v1_inactive_history_allows_clock_advance_and_resumes_after_cutover() {
    assert_inactive_history_defers_until_reactivation(true, false);
}

#[test]
fn roster_v1_inactive_history_allows_unrelated_write_and_resumes_after_cutover() {
    assert_inactive_history_defers_until_reactivation(true, true);
}

#[test]
fn roster_v2_inactive_history_allows_clock_advance_and_resumes_after_cutover() {
    assert_inactive_history_defers_until_reactivation(false, false);
}

#[test]
fn roster_v2_inactive_history_allows_unrelated_write_and_resumes_after_cutover() {
    assert_inactive_history_defers_until_reactivation(false, true);
}

#[test]
fn inactive_signed_history_requires_its_witness_after_authority_cutover() {
    with_inactive_history_after_cutover(false, |conn, _backend, state| {
        assert!(read_protected_roster_v2_activation_certificate_in_sync(
            conn,
            state.storage,
            false
        )
        .unwrap()
        .is_none());
        validate_protected_roster_recovery_state_sync(conn, state.storage)
            .expect("intact signed history recovers after its certificate is cleared");
        assert_eq!(
            conn.execute("DELETE FROM consensus_protected_roster_witness", [])
                .unwrap(),
            1
        );
        let error = validate_protected_roster_recovery_state_sync(conn, state.storage)
            .expect_err("clearing the certificate never permits loss of the history witness");
        let message = error.to_string();
        assert!(message.contains("corrupt"), "{message}");
        assert!(message.contains("mandatory roster witness"), "{message}");
        assert!(message.contains("reinitialized"), "{message}");
    });
}

#[test]
fn roster_maintenance_profile_missing_v2_defers_during_second_pending_transition() {
    with_inactive_history_after_cutover(false, |conn, backend, mut state| {
        let before = roster_image(conn);
        let advanced = state.apply(
            conn,
            backend,
            state.due,
            SessionMutationIntent::AdvanceLogicalTime,
        );
        assert_eq!(
            advanced.responses[0].result,
            Ok(SessionMutationOutcome::Unit)
        );
        assert_eq!(roster_image(conn), before);
        let desired = members(&[7, 8, 9, 10, 11, 12, 13]);
        let desired_identity = SessionConsensusIdentity::new(
            state.storage.cluster_id(),
            SessionConsensusConfigurationId::from_bytes([0xE1; 32]),
            SessionConsensusConfigurationEpoch::new(
                state.successor_identity.configuration_epoch().get() + 1,
            )
            .unwrap(),
        );
        for intent in [
            SessionMutationIntent::PrepareTopologyTransition {
                transition_id: [0xE2; MEMBERSHIP_TRANSITION_ID_BYTES],
                request_digest: [0xE3; 32],
                desired_identity,
                desired_bindings: test_member_bindings(&desired),
                desired_members: desired,
            },
            SessionMutationIntent::AcquireLease {
                key: key(),
                owner: OwnerId::new("pending-transition-owner").unwrap(),
                ttl: Duration::from_secs(300),
            },
            SessionMutationIntent::AdvanceLogicalTime,
        ] {
            let write = matches!(intent, SessionMutationIntent::AcquireLease { .. });
            let applied = state.apply(conn, backend, state.due, intent);
            assert!(matches!(
                (&applied.responses[0].result, write),
                (Ok(SessionMutationOutcome::Lease(_)), true)
                    | (Ok(SessionMutationOutcome::Unit), false)
            ));
            assert!(read_membership_scope_sync(conn, state.storage)
                .unwrap()
                .pending
                .is_some());
            assert_eq!(
                roster_image(conn),
                before,
                "a deferred pending-scope turn changes no roster row or witness"
            );
        }
        let changes = conn.total_changes();
        assert!(
            !maintain_due_protected_roster_reclaim_sync(conn, state.storage, state.due).unwrap()
        );
        assert_eq!(conn.total_changes(), changes);
        assert_eq!(roster_image(conn), before);
        // This tests committed apply, not the distinct reopen/snapshot rule.
    });
}

#[test]
fn roster_maintenance_profile_generic_v1_defers_until_roster_activation() {
    with_inactive_history_after_cutover(true, |conn, backend, mut state| {
        let generic_digest =
            fenced_transition_voter_set_digest(state.successor_identity, &state.successor);
        let generic = state.apply(
            conn,
            backend,
            state.now,
            SessionMutationIntent::ActivateFencedTransitionCapability {
                schema_version: FENCED_TRANSITION_SCHEMA_V1,
                scope_identity: state.successor_identity,
                voter_set_digest: generic_digest,
            },
        );
        assert_eq!(
            generic.responses[0].result,
            Ok(SessionMutationOutcome::Unit)
        );
        assert_eq!(
            read_fenced_transition_activation_certificate_sync(conn, state.storage, false).unwrap(),
            Some((state.successor_identity, generic_digest))
        );
        let before = roster_image(conn);
        let advanced = state.apply(
            conn,
            backend,
            state.due,
            SessionMutationIntent::AdvanceLogicalTime,
        );
        assert_eq!(
            advanced.responses[0].result,
            Ok(SessionMutationOutcome::Unit)
        );
        assert_eq!(
            roster_image(conn),
            before,
            "generic activation does not authorize roster maintenance"
        );
        let changes = conn.total_changes();
        assert!(
            !maintain_due_protected_roster_reclaim_sync(conn, state.storage, state.due).unwrap()
        );
        assert_eq!(conn.total_changes(), changes);
        assert_eq!(roster_image(conn), before);

        reactivate_v2(
            conn,
            backend,
            state.storage,
            state.successor_identity,
            &state.successor,
            state.due,
        );
        let roster_activation = activation(true, state.successor_identity, &state.successor);
        let activated = state.apply(conn, backend, state.due, roster_activation);
        assert_eq!(
            activated.responses[0].result,
            Ok(SessionMutationOutcome::Unit)
        );
        assert_eq!(
            row_states(conn),
            vec![3, 3],
            "roster activation resumes reclaim"
        );
        let retired = state.apply(
            conn,
            backend,
            state.due,
            SessionMutationIntent::AdvanceLogicalTime,
        );
        assert_eq!(
            retired.responses[0].result,
            Ok(SessionMutationOutcome::Unit)
        );
        assert!(
            row_states(conn).is_empty(),
            "the next turn retires the eligible prefix"
        );
        assert_eq!(
            retirement_fixture_durable_bindings(
                protected_roster_read_witness_sync(conn, state.storage)
                    .unwrap()
                    .unwrap()
            ),
            0
        );
        validate_protected_roster_state_sync(conn, state.storage)
            .expect("exact shared witness after resumed retirement");
    });
}

#[test]
fn roster_maintenance_profile_active_v1_reclaims_while_inactive_v2_blocks_retirement() {
    with_inactive_history_after_cutover(true, |conn, backend, mut state| {
        let roster_activation = activation(true, state.successor_identity, &state.successor);
        let activated = state.apply(conn, backend, state.now, roster_activation);
        assert_eq!(
            activated.responses[0].result,
            Ok(SessionMutationOutcome::Unit)
        );
        let before_v2 = roster_image(conn)[PROTECTED_ROSTER_TABLES.len()..].to_vec();
        let floors = conn
            .prepare(
                "SELECT canonical_floor FROM consensus_protected_roster_floors ORDER BY partition",
            )
            .unwrap()
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        for _ in 0..2 {
            let advanced = state.apply(
                conn,
                backend,
                state.due,
                SessionMutationIntent::AdvanceLogicalTime,
            );
            assert_eq!(
                advanced.responses[0].result,
                Ok(SessionMutationOutcome::Unit)
            );
            assert_eq!(
                conn.query_row(
                    "SELECT state FROM consensus_protected_roster_rows",
                    [],
                    |row| row.get::<_, i64>(0)
                )
                .unwrap(),
                3,
                "ready V1 reclaims even while V2 remains inactive"
            );
            assert_eq!(
                roster_image(conn)[PROTECTED_ROSTER_TABLES.len()..],
                before_v2
            );
            assert_eq!(
                row_states(conn),
                vec![2, 3],
                "older inactive V2 history must still hold the global retirement prefix"
            );
            assert_eq!(conn.prepare("SELECT canonical_floor FROM consensus_protected_roster_floors ORDER BY partition").unwrap()
                .query_map([], |row| row.get::<_, Vec<u8>>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap(), floors);
            let witness = protected_roster_read_witness_sync(conn, state.storage)
                .unwrap()
                .unwrap();
            assert_eq!(witness.retired_terminal_sequence(), 0);
            assert_eq!(retirement_fixture_durable_bindings(witness), 2);
            validate_protected_roster_state_sync(conn, state.storage)
                .expect("deferred V2 still participates in shared floor and witness validation");
        }
    });
}

#[test]
fn roster_maintenance_profile_active_v1_retires_with_empty_inactive_v2() {
    with_inactive_history_layout_after_cutover(true, false, false, |conn, backend, mut state| {
        let v2_before = table_image(conn, PROTECTED_ROSTER_V2_TABLES.iter().copied());
        let roster_activation = activation(true, state.successor_identity, &state.successor);
        let activated = state.apply(conn, backend, state.now, roster_activation);
        assert_eq!(
            activated.responses[0].result,
            Ok(SessionMutationOutcome::Unit)
        );
        let reclaimed = state.apply(
            conn,
            backend,
            state.due,
            SessionMutationIntent::AdvanceLogicalTime,
        );
        assert_eq!(
            reclaimed.responses[0].result,
            Ok(SessionMutationOutcome::Unit)
        );
        assert_eq!(
            row_states(conn),
            vec![3],
            "inactive empty V2 cannot suppress ready V1 reclaim"
        );
        assert_eq!(
            table_image(conn, PROTECTED_ROSTER_V2_TABLES.iter().copied()),
            v2_before
        );
        let retired = state.apply(
            conn,
            backend,
            state.due,
            SessionMutationIntent::AdvanceLogicalTime,
        );
        assert_eq!(
            retired.responses[0].result,
            Ok(SessionMutationOutcome::Unit)
        );
        assert!(
            row_states(conn).is_empty(),
            "without a lower survivor V1 retirement must progress"
        );
        assert_eq!(
            table_image(conn, PROTECTED_ROSTER_V2_TABLES.iter().copied()),
            v2_before
        );
        for table in [
            "consensus_protected_roster_floors",
            "consensus_protected_roster_retirement_cursors",
        ] {
            assert_eq!(
                conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
        let witness = protected_roster_read_witness_sync(conn, state.storage)
            .unwrap()
            .unwrap();
        assert_eq!(retirement_fixture_durable_bindings(witness), 0);
        assert!(witness.retired_terminal_sequence() > 0);
        validate_protected_roster_state_sync(conn, state.storage)
            .expect("empty inactive V2 and released V1 floors remain valid");
    });
}

#[test]
fn roster_maintenance_profile_inactive_v2_tombstone_holds_retirement_prefix() {
    with_inactive_history_layout_after_cutover(true, true, true, |conn, backend, mut state| {
        assert_eq!(
            row_states(conn),
            vec![3, 3],
            "pending cutover must preserve the reclaimed history"
        );
        let before = roster_image(conn);
        let roster_activation = activation(true, state.successor_identity, &state.successor);
        let activated = state.apply(conn, backend, state.due, roster_activation);
        assert_eq!(
            activated.responses[0].result,
            Ok(SessionMutationOutcome::Unit)
        );
        for _ in 0..2 {
            let advanced = state.apply(
                conn,
                backend,
                state.due,
                SessionMutationIntent::AdvanceLogicalTime,
            );
            assert_eq!(
                advanced.responses[0].result,
                Ok(SessionMutationOutcome::Unit)
            );
            assert_eq!(
                roster_image(conn),
                before,
                "ready V1 cannot retire across an older inactive V2 tombstone"
            );
            let witness = protected_roster_read_witness_sync(conn, state.storage)
                .unwrap()
                .unwrap();
            assert_eq!(witness.retired_terminal_sequence(), 0);
            assert_eq!(retirement_fixture_durable_bindings(witness), 2);
            validate_protected_roster_state_sync(conn, state.storage)
                .expect("inactive tombstone still holds the shared floor and terminal horizon");
        }
        let changes = conn.total_changes();
        assert!(
            !maintain_due_protected_roster_reclaim_sync(conn, state.storage, state.due).unwrap()
        );
        assert_eq!(conn.total_changes(), changes);
        assert_eq!(roster_image(conn), before);
    });
}
