use super::*;
use crate::consensus::native::roster::v1_fixture;
use crate::consensus::types::protected_roster_profile_voter_set_digest;
use crate::fenced_mutation_roster::EstablishedMutation;
use crate::sqlite::consensus::roster_rows::tests::signed_v1_command_with_mutation;
use crate::sqlite::consensus::tests::native::ordinary::rows;
use std::cell::Cell;

mod durable_install;
pub(in crate::sqlite::consensus::tests::native) mod import;
mod install;
mod install_base;
mod public_reads;

fn setup(signed: &RosterV2PersistenceFixture) -> Vec<Entry<SessionRaftTypeConfig>> {
    let mut lease = ordinary(
        signed,
        1,
        SessionMutationIntent::AcquireLease {
            key: signed.authority.key().clone(),
            owner: signed.authority.owner().clone(),
            ttl: Duration::from_secs(60),
        },
    );
    let EntryPayload::Normal(command) = &mut lease.payload else {
        unreachable!()
    };
    command.logical_time = signed.authority.acquired_at();
    let profile = Profile::v2();
    vec![
        formation(),
        lease,
        ordinary(
            signed,
            2,
            SessionMutationIntent::ActivateProtectedRosterProfileV2 {
                schema_version: profile.schema(),
                consumer_revision: profile.consumer_revision(),
                scope_identity: signed.identity,
                voter_set_digest: protected_roster_profile_v2_voter_set_digest(
                    signed.identity,
                    &fixed_members(),
                ),
                profile_digest: profile.digest(),
            },
        ),
    ]
}

fn fresh(
    phase: Phase,
) -> (
    tempfile::TempDir,
    SqliteSessionBackend,
    RosterV2PersistenceFixture,
    Wal,
) {
    let directory = tempfile::tempdir().unwrap();
    let signed = roster_v2_fresh_wal_persistence_fixture(phase);
    let backend = SqliteSessionBackend::open(directory.path().join("oracle.sqlite")).unwrap();
    initialize(&backend, &signed);
    let wal = Wal::create_native_with_root(
        &directory.path().join("wal"),
        &backend.conn.blocking_lock(),
        signed.identity,
        [0xD2; 32],
        Some(Arc::new(signed.root.clone())),
        Limits::default(),
        IoControl::default(),
    )
    .unwrap();
    let applied = parity(&wal, &backend, &signed, &setup(&signed));
    assert!(applied
        .responses
        .iter()
        .all(|response| response.result.is_ok()));
    (directory, backend, signed, wal)
}

fn database(conn: &Connection) -> BTreeMap<String, Vec<Vec<String>>> {
    let tables = conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap()
        .query_map([], |row| row.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    let mut result = tables
        .into_iter()
        .map(|table| {
            let contents = rows(conn, &table);
            (table, contents)
        })
        .collect::<BTreeMap<_, _>>();
    let schema = conn.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").unwrap()
        .query_map([], |row| (0..4).map(|column| row.get::<_, String>(column)).collect::<rusqlite::Result<Vec<_>>>()).unwrap()
        .collect::<rusqlite::Result<Vec<_>>>().unwrap();
    result.insert("sqlite_master".into(), schema);
    result
}

fn exported(
    wal: &Wal,
    backend: &SqliteSessionBackend,
    signed: &RosterV2PersistenceFixture,
) -> Connection {
    let applied = wal.with_native_read(|state| Ok(state.applied())).unwrap();
    let conn = wal.native_export_snapshot().unwrap();
    assert_eq!(
        database(&conn),
        database(&backend.conn.blocking_lock()),
        "every original schema object, column and canonical carrier"
    );
    validate_protected_roster_recovery_state_sync(&conn, signed.identity).unwrap();
    validate_lease_state_sync(&conn).unwrap();
    assert_eq!(
        wal.with_native_read(|state| Ok(state.applied())).unwrap(),
        applied
    );
    assert_eq!(wal.native_sql_fallback_count().unwrap(), 0);
    import::roundtrip(&conn, [0xDB; 32], signed);
    conn
}

fn reopen(wal: &Wal, directory: &Path, signed: &RosterV2PersistenceFixture) -> Wal {
    wal.checkpoint().unwrap();
    wal.shutdown().unwrap();
    Opening::new(
        &directory.join("wal"),
        wal.binding(),
        Some(Arc::new(signed.root.clone())),
        Limits::default(),
        IoControl::default(),
    )
    .unwrap()
    .finish(|| Ok(()))
    .unwrap()
}

fn count(conn: &Connection, table: &str) -> u64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

fn state(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT state FROM {table}"), [], |row| row.get(0))
        .unwrap()
}

fn tick(
    signed: &RosterV2PersistenceFixture,
    index: u64,
    time: Timestamp,
) -> Entry<SessionRaftTypeConfig> {
    let mut entry = ordinary(signed, index, SessionMutationIntent::AdvanceLogicalTime);
    let EntryPayload::Normal(command) = &mut entry.payload else {
        unreachable!()
    };
    command.logical_time = time;
    entry
}

#[test]
fn native_roster_snapshot_v2_empty_live_terminal_compacted_and_retired_match_every_sql_column() {
    for phase in [Phase::Established, Phase::Aborted] {
        let (directory, backend, signed, mut wal) = fresh(phase);
        let empty = exported(&wal, &backend, &signed);
        assert_eq!(count(&empty, "consensus_protected_roster_v2_activation"), 1);
        assert_eq!(count(&empty, "consensus_protected_roster_v2_admissions"), 0);
        let q1 = parity(&wal, &backend, &signed, &[admission(&signed)]);
        assert!(matches!(
            &q1.responses[0].result,
            Ok(SessionMutationOutcome::RosterAdmissionV2(
                ConsensusRosterAdmissionOutcome::Admitted { .. }
            ))
        ));
        let live = exported(&wal, &backend, &signed);
        assert_eq!(state(&live, "consensus_protected_roster_v2_admissions"), 1);
        assert_eq!(
            count(&live, "consensus_protected_roster_v2_absence_reservations"),
            1
        );
        wal = reopen(&wal, directory.path(), &signed);
        exported(&wal, &backend, &signed);
        let q2 = parity(&wal, &backend, &signed, &[terminal(&signed, 4)]);
        assert!(matches!(
            &q2.responses[0].result,
            Ok(SessionMutationOutcome::RosterTerminalV2(
                ConsensusRosterTerminalOutcome::Committed {
                    replayed: false,
                    ..
                }
            ))
        ));
        let retained = exported(&wal, &backend, &signed);
        assert_eq!(
            state(&retained, "consensus_protected_roster_v2_admissions"),
            2
        );
        assert_eq!(
            count(
                &retained,
                "consensus_protected_roster_v2_absence_reservations"
            ),
            0
        );
        wal.checkpoint().unwrap();
        exported(&wal, &backend, &signed);
        let due = signed
            .authority
            .acquired_at()
            .add_seconds(1 + 24 * 60 * 60)
            .unwrap();
        parity(
            &wal,
            &backend,
            &signed,
            &[tick(&signed, 5, due.add_seconds(-1).unwrap())],
        );
        assert_eq!(
            state(
                &exported(&wal, &backend, &signed),
                "consensus_protected_roster_v2_admissions"
            ),
            2
        );
        parity(&wal, &backend, &signed, &[tick(&signed, 6, due)]);
        assert_eq!(
            state(
                &exported(&wal, &backend, &signed),
                "consensus_protected_roster_v2_admissions"
            ),
            3
        );
        wal = reopen(&wal, directory.path(), &signed);
        exported(&wal, &backend, &signed);
        parity(&wal, &backend, &signed, &[tick(&signed, 7, due)]);
        let retired = exported(&wal, &backend, &signed);
        assert_eq!(
            count(&retired, "consensus_protected_roster_v2_admissions"),
            0
        );
        assert_eq!(count(&retired, "consensus_protected_roster_floors"), 0);
        assert_eq!(
            count(&retired, "consensus_protected_roster_retirement_cursors"),
            0
        );
        assert_eq!(count(&retired, "consensus_protected_roster_witness"), 1);
        wal.shutdown().unwrap();
    }
}

#[test]
fn native_roster_snapshot_signed_v1_and_v2_share_exact_history_across_cold_reopen() {
    for delete in [false, true] {
        for phase in [Phase::Established, Phase::Aborted] {
            let (directory, backend, signed, mut wal) = fresh(Phase::Established);
            parity(
                &wal,
                &backend,
                &signed,
                &[admission(&signed), terminal(&signed, 4)],
            );
            let activation = ordinary(
                &signed,
                5,
                SessionMutationIntent::ActivateFencedTransitionCapability {
                    schema_version: crate::fenced_transition::FENCED_TRANSITION_SCHEMA_V1,
                    scope_identity: signed.identity,
                    voter_set_digest: protected_roster_profile_voter_set_digest(
                        signed.identity,
                        &fixed_members(),
                    ),
                },
            );
            parity(&wal, &backend, &signed, &[activation]);
            exported(&wal, &backend, &signed);
            let q1 = signed_v1_command_with_mutation(
                &signed,
                if delete {
                    EstablishedMutation::delete()
                } else {
                    EstablishedMutation::no_op()
                },
            );
            let q2 = v1_fixture::terminal(&signed, &q1, 6, phase);
            let admitted = parity(
                &wal,
                &backend,
                &signed,
                &[entry(
                    &signed,
                    6,
                    q1.request_id().unwrap(),
                    SessionMutationIntent::RosterAdmission(Box::new(q1)),
                )],
            );
            assert!(matches!(
                &admitted.responses[0].result,
                Ok(SessionMutationOutcome::RosterAdmission(
                    ConsensusRosterAdmissionOutcome::Admitted { .. }
                ))
            ));
            let live = exported(&wal, &backend, &signed);
            assert_eq!(state(&live, "consensus_protected_roster_rows"), 1);
            assert_eq!(count(&live, "consensus_protected_roster_business"), 1);
            assert_eq!(
                count(&live, "consensus_protected_roster_floors"),
                1,
                "one shared partition across profiles and epochs"
            );
            wal = reopen(&wal, directory.path(), &signed);
            exported(&wal, &backend, &signed);
            let committed = parity(
                &wal,
                &backend,
                &signed,
                &[entry(
                    &signed,
                    7,
                    q2.request_id().unwrap(),
                    SessionMutationIntent::RosterTerminal(Box::new(q2)),
                )],
            );
            assert!(matches!(
                &committed.responses[0].result,
                Ok(SessionMutationOutcome::RosterTerminal(
                    ConsensusRosterTerminalOutcome::Committed {
                        replayed: false,
                        ..
                    }
                ))
            ));
            let retained = exported(&wal, &backend, &signed);
            assert_eq!(state(&retained, "consensus_protected_roster_rows"), 2);
            assert_eq!(count(&retained, "consensus_protected_roster_business"), 0);
            let due = signed
                .authority
                .acquired_at()
                .add_seconds(1 + 24 * 60 * 60)
                .unwrap();
            parity(&wal, &backend, &signed, &[tick(&signed, 8, due)]);
            let compact = exported(&wal, &backend, &signed);
            assert_eq!(state(&compact, "consensus_protected_roster_rows"), 3);
            assert_eq!(
                state(&compact, "consensus_protected_roster_v2_admissions"),
                3
            );
            wal = reopen(&wal, directory.path(), &signed);
            exported(&wal, &backend, &signed);
            parity(&wal, &backend, &signed, &[tick(&signed, 9, due)]);
            let partial = exported(&wal, &backend, &signed);
            assert_eq!(
                count(&partial, "consensus_protected_roster_v2_admissions"),
                0
            );
            assert_eq!(count(&partial, "consensus_protected_roster_rows"), 1);
            let bytes: Vec<u8> = partial
                .query_row(
                    "SELECT canonical_floor FROM consensus_protected_roster_floors",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                crate::fenced_mutation_roster::IrreversibleHistoryFloor::from_canonical_bytes(
                    &bytes
                )
                .unwrap()
                .retired_through(),
                3
            );
            wal = reopen(&wal, directory.path(), &signed);
            exported(&wal, &backend, &signed);
            parity(&wal, &backend, &signed, &[tick(&signed, 10, due)]);
            let retired = exported(&wal, &backend, &signed);
            for table in [
                "consensus_protected_roster_rows",
                "consensus_protected_roster_admissions",
                "consensus_protected_roster_floors",
                "consensus_protected_roster_retirement_cursors",
            ] {
                assert_eq!(count(&retired, table), 0);
            }
            assert_eq!(count(&retired, "consensus_protected_roster_witness"), 1);
            wal.shutdown().unwrap();
        }
    }
}

#[test]
fn native_roster_snapshot_v1_only_preserves_activation_and_immutable_admission_children() {
    for delete in [false, true] {
        for phase in [Phase::Established, Phase::Aborted] {
            let directory = tempfile::tempdir().unwrap();
            let signed = roster_v2_fresh_wal_persistence_fixture(Phase::Established);
            let backend =
                SqliteSessionBackend::open(directory.path().join("oracle.sqlite")).unwrap();
            initialize(&backend, &signed);
            let mut wal = Wal::create_native_with_root(
                &directory.path().join("wal"),
                &backend.conn.blocking_lock(),
                signed.identity,
                [0xD4; 32],
                Some(Arc::new(signed.root.clone())),
                Limits::default(),
                IoControl::default(),
            )
            .unwrap();
            parity(&wal, &backend, &signed, &setup(&signed)[..2]);
            let guard = crate::LeaseGuard::new(
                signed.authority.key().clone(),
                signed.authority.owner().clone(),
                signed.authority.fence(),
                signed.authority.acquired_at(),
                signed.authority.expires_at(),
                signed.authority.credential_id(),
            );
            let request = sdk741_component_request(Sdk741Payload::Create, 41, 0, None);
            let mut record = request.mutation().record().unwrap().clone();
            record.key = guard.key().clone();
            record.owner = guard.owner().clone();
            record.fence = guard.fence();
            record.generation = Generation::new(1);
            record.expires_at = None;
            sdk741_seal_record(&mut record, 41_000, true);
            let created = parity(
                &wal,
                &backend,
                &signed,
                &[
                    ordinary(
                        &signed,
                        2,
                        SessionMutationIntent::CompareAndSet(Arc::new(crate::CompareAndSet {
                            key: guard.key().clone(),
                            lease: guard,
                            expected_generation: None,
                            new_record: record,
                        })),
                    ),
                    ordinary(
                        &signed,
                        3,
                        SessionMutationIntent::ActivateFencedTransitionCapability {
                            schema_version: crate::fenced_transition::FENCED_TRANSITION_SCHEMA_V1,
                            scope_identity: signed.identity,
                            voter_set_digest: protected_roster_profile_voter_set_digest(
                                signed.identity,
                                &fixed_members(),
                            ),
                        },
                    ),
                ],
            );
            assert!(matches!(
                &created.responses[0].result,
                Ok(SessionMutationOutcome::CompareAndSet(
                    crate::CompareAndSetResult::Success
                ))
            ));
            assert!(!database(&exported(&wal, &backend, &signed))
                .contains_key("consensus_protected_roster_v2_activation"));
            let q1 = signed_v1_command_with_mutation(
                &signed,
                if delete {
                    EstablishedMutation::delete()
                } else {
                    EstablishedMutation::no_op()
                },
            );
            let q2 = v1_fixture::terminal(&signed, &q1, 4, phase);
            let admitted = parity(
                &wal,
                &backend,
                &signed,
                &[entry(
                    &signed,
                    4,
                    q1.request_id().unwrap(),
                    SessionMutationIntent::RosterAdmission(Box::new(q1)),
                )],
            );
            assert!(matches!(
                &admitted.responses[0].result,
                Ok(SessionMutationOutcome::RosterAdmission(
                    ConsensusRosterAdmissionOutcome::Admitted { .. }
                ))
            ));
            assert_eq!(
                count(
                    &exported(&wal, &backend, &signed),
                    "consensus_protected_roster_business"
                ),
                1
            );
            wal = reopen(&wal, directory.path(), &signed);
            exported(&wal, &backend, &signed);
            let committed = parity(
                &wal,
                &backend,
                &signed,
                &[entry(
                    &signed,
                    5,
                    q2.request_id().unwrap(),
                    SessionMutationIntent::RosterTerminal(Box::new(q2)),
                )],
            );
            assert!(matches!(
                &committed.responses[0].result,
                Ok(SessionMutationOutcome::RosterTerminal(
                    ConsensusRosterTerminalOutcome::Committed {
                        replayed: false,
                        ..
                    }
                ))
            ));
            assert_eq!(
                state(
                    &exported(&wal, &backend, &signed),
                    "consensus_protected_roster_rows"
                ),
                2
            );
            let due = signed
                .authority
                .acquired_at()
                .add_seconds(1 + 24 * 60 * 60)
                .unwrap();
            parity(&wal, &backend, &signed, &[tick(&signed, 6, due)]);
            let compacted = exported(&wal, &backend, &signed);
            assert_eq!(state(&compacted, "consensus_protected_roster_rows"), 3);
            assert_eq!(
                count(&compacted, "consensus_protected_roster_admissions"),
                1
            );
            assert_eq!(count(&compacted, "consensus_protected_roster_business"), 0);
            wal = reopen(&wal, directory.path(), &signed);
            exported(&wal, &backend, &signed);
            parity(&wal, &backend, &signed, &[tick(&signed, 7, due)]);
            let retired = exported(&wal, &backend, &signed);
            assert_eq!(count(&retired, "consensus_protected_roster_rows"), 0);
            assert_eq!(count(&retired, "consensus_protected_roster_admissions"), 0);
            assert!(!database(&retired).contains_key("consensus_protected_roster_v2_activation"));
            wal.shutdown().unwrap();
        }
    }
}

#[test]
fn native_roster_snapshot_requires_independent_root_before_writing_and_rolls_back_failed_output() {
    let (directory, backend, signed, wal) = fresh(Phase::Established);
    parity(&wal, &backend, &signed, &[admission(&signed)]);
    let entries = wal.native_log_read(0, None, Some(8)).unwrap();
    let mut storage = NativeStorage::empty_with_roster_root(
        signed.identity,
        fixed_members(),
        Some(Arc::new(signed.root.clone())),
    )
    .unwrap();
    storage
        .log
        .project(&append(&entries), &storage.business, None)
        .unwrap();
    storage
        .log
        .project(
            &Operation::Committed(Some(log_id(3))),
            &storage.business,
            None,
        )
        .unwrap();
    storage.replay_committed().unwrap();
    storage.validate_image().unwrap();
    for configured in [
        None,
        Some(wrong_root(&signed)),
        Some(Arc::new(
            RosterAttestationTrustRootV1::new([0xD3; 32], signed.root.compressed_public_key())
                .unwrap(),
        )),
    ] {
        let output = SqliteSessionBackend::in_memory().unwrap();
        let conn = output.conn.blocking_lock();
        initialize_schema_with_storage_anchor_and_pending_and_bindings(
            &conn,
            None,
            signed.identity,
            &fixed_members(),
            &test_member_bindings(&fixed_members()),
            None,
            ConsensusAuthorityProfile::FixedImmutable,
            FIXED_TEST_PLACEMENT_POLICY,
            configured.as_deref(),
        )
        .unwrap();
        conn.pragma_update(None, "query_only", true).unwrap();
        let before = database(&conn);
        let error = storage
            .export_cold_snapshot_checked(&conn, &|| Ok(()))
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "native snapshot configured roster root differs from cold basis"
        );
        assert_eq!(database(&conn), before);
        assert!(conn
            .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
            .unwrap());
    }
    for corrupt_output in [false, true] {
        let output = SqliteSessionBackend::open(
            directory
                .path()
                .join(format!("output-{corrupt_output}.sqlite")),
        )
        .unwrap();
        initialize(&output, &signed);
        let conn = output.conn.blocking_lock();
        let before = database(&conn);
        let triggered = Cell::new(false);
        let check = || {
            let exists: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='consensus_protected_roster_v2_admissions')", [], |row| row.get(0)).unwrap();
            if !triggered.get()
                && exists
                && count(&conn, "consensus_protected_roster_v2_admissions") == 1
            {
                triggered.set(true);
                if !corrupt_output {
                    return Err(io::Error::other("cancel after roster output"));
                }
                conn.execute(
                    "DELETE FROM consensus_protected_roster_v2_absence_reservations",
                    [],
                )
                .unwrap();
            }
            Ok(())
        };
        let error = storage
            .export_cold_snapshot_checked(&conn, &check)
            .unwrap_err();
        assert!(triggered.get());
        assert_eq!(
            error.to_string(),
            if corrupt_output {
                "native snapshot exported roster recovery validation failed"
            } else {
                "cancel after roster output"
            }
        );
        assert_eq!(
            database(&conn),
            before,
            "all business, roster, schema and frontier writes roll back"
        );
        storage.validate_image().unwrap();
    }
    exported(&wal, &backend, &signed);
    wal.shutdown().unwrap();
}
