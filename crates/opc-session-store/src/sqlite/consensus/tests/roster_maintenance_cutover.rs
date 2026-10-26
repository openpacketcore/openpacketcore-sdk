use super::*;
use crate::consensus::v1_fixture;

fn command(
    storage: SessionConsensusIdentity,
    authority: SessionConsensusIdentity,
    index: u64,
    now: Timestamp,
    intent: SessionMutationIntent,
) -> Entry<SessionRaftTypeConfig> {
    let intent = match intent {
        SessionMutationIntent::MarkTopologyLearnersReady { .. }
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

fn roster_image(conn: &Connection) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    PROTECTED_ROSTER_TABLES
        .iter()
        .chain(PROTECTED_ROSTER_V2_TABLES)
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

fn assert_inactive_history_defers_until_reactivation(v1: bool, write_first: bool) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("retained-cutover.sqlite");
    let predecessor = members(&[7, 8, 9]);
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
    let now = v2_persistence_logical_time();
    let due = now.add_seconds(24 * 60 * 60 + 1).unwrap();
    let mut next = 3;
    if v1 {
        let admitted = crate::sqlite::consensus::roster_rows::tests::signed_v1_command(&signed);
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
    let retained_count = if v1 { 2 } else { 1 };
    assert_eq!(row_states(&conn), vec![2; retained_count]);
    validate_protected_roster_state_sync(&conn, storage).expect("valid signed retained history");

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
    if v1 {
        // Restore V2 while all history is young, leaving only V1 inactive.
        // Otherwise a V2 failure could mask the independent V1 regression.
        reactivate_v2(
            &conn,
            &backend,
            storage,
            successor_identity,
            &successor,
            now,
        );
        // An inactive V1 profile must not hide a present foreign V2 policy.
        conn.execute(
            "UPDATE consensus_protected_roster_v2_activation SET voter_set_digest=?1",
            [[0xCE_u8; 32].as_slice()],
        )
        .unwrap();
        let foreign = roster_image(&conn);
        let changes = conn.total_changes();
        assert!(maintain_due_protected_roster_reclaim_sync(&conn, storage, due).is_err());
        assert_eq!(conn.total_changes(), changes);
        assert_eq!(roster_image(&conn), foreign);
        reactivate_v2(
            &conn,
            &backend,
            storage,
            successor_identity,
            &successor,
            now,
        );
    }
    validate_existing_schema(&conn, storage).expect("post-cutover inactive layout is valid");
    validate_protected_roster_state_sync(&conn, storage).expect("inactive history remains valid");
    let before = roster_image(&conn);
    let witness = protected_roster_read_witness_sync(&conn, storage).unwrap();
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
    for intent in intents {
        let is_write = matches!(intent, SessionMutationIntent::AcquireLease { .. });
        let applied = apply_cutover_entries(
            &conn,
            &backend,
            storage,
            vec![command(storage, successor_identity, next, due, intent)],
        );
        assert!(matches!(
            (&applied.responses[0].result, is_write),
            (Ok(SessionMutationOutcome::Lease(_)), true)
                | (Ok(SessionMutationOutcome::Unit), false)
        ));
        assert_eq!(
            read_applied_sync(&conn, storage).unwrap(),
            Some(log_id(next))
        );
        assert_eq!(proposal_state_sync(&conn, storage).unwrap().2, Some(due));
        assert_eq!(
            roster_image(&conn),
            before,
            "inactive maintenance changes no roster state"
        );
        assert_eq!(
            protected_roster_read_witness_sync(&conn, storage).unwrap(),
            witness
        );
        next += 1;
    }
    let changes = conn.total_changes();
    assert!(!maintain_due_protected_roster_reclaim_sync(&conn, storage, due).unwrap());
    assert_eq!(
        conn.total_changes(),
        changes,
        "deferred turn performs no writes"
    );
    if v1 {
        assert!(
            read_fenced_transition_activation_certificate_sync(&conn, storage, false)
                .unwrap()
                .is_none()
        );
    } else {
        assert!(
            read_protected_roster_v2_activation_certificate_in_sync(&conn, storage, false)
                .unwrap()
                .is_none()
        );
    }

    let resume = if v1 {
        activation(true, successor_identity, &successor)
    } else {
        reactivate_v2(
            &conn,
            &backend,
            storage,
            successor_identity,
            &successor,
            due,
        );
        SessionMutationIntent::AdvanceLogicalTime
    };
    let activated = apply_cutover_entries(
        &conn,
        &backend,
        storage,
        vec![command(storage, successor_identity, next, due, resume)],
    );
    assert_eq!(
        activated.responses[0].result,
        Ok(SessionMutationOutcome::Unit)
    );
    assert_eq!(
        row_states(&conn),
        vec![3; retained_count],
        "activation resumes bounded reclaim"
    );
    next += 1;
    let retired = apply_cutover_entries(
        &conn,
        &backend,
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
        row_states(&conn).is_empty(),
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
            protected_roster_read_witness_sync(&conn, storage)
                .unwrap()
                .unwrap()
        ),
        0
    );
    validate_protected_roster_state_sync(&conn, storage)
        .expect("resumed maintenance remains valid");
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
