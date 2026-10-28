use super::*;

fn empty_predecessor(conn: &Connection, format: i64) {
    initialize_schema(conn, identity(), &expected_members()).unwrap();
    assert!(matches!(format, 1 | 4));
    if format == 4 {
        // Exact empty format-four predecessor, as accepted by offline recovery.
        conn.execute(
            "UPDATE consensus_identity SET schema_version=4 WHERE singleton=1",
            [],
        )
        .unwrap();
    }
    assert_eq!(
        persisted_schema_version_in_sync(conn, false).unwrap(),
        format
    );
    assert!(protected_roster_read_witness_sync(conn, identity())
        .unwrap()
        .is_none());
}

fn activate(conn: &Connection) -> io::Result<()> {
    activate_protected_roster_profile_v2_scope_sync(
        conn,
        identity(),
        identity(),
        &expected_members(),
        crate::fenced_mutation_roster::Profile::v2().digest(),
    )
}

fn assert_atomic_initial_witness(format: i64) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("initial-witness.sqlite");
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let conn = backend.conn.blocking_lock();
    empty_predecessor(&conn, format);
    let observer = Connection::open(&path).unwrap();
    let tx = conn.unchecked_transaction().unwrap();
    activate(&tx).expect("first format-five publication provisions its witness");
    assert_eq!(persisted_schema_version_in_sync(&tx, false).unwrap(), 5);
    assert_eq!(
        protected_roster_read_witness_sync(&tx, identity()).unwrap(),
        Some(GlobalChargeWitness::empty()),
    );
    assert_eq!(
        persisted_schema_version_in_sync(&observer, false).unwrap(),
        format
    );
    assert!(protected_roster_read_witness_sync(&observer, identity())
        .unwrap()
        .is_none());
    tx.commit().unwrap();
    assert_eq!(
        persisted_schema_version_in_sync(&observer, false).unwrap(),
        5
    );
    assert_eq!(
        protected_roster_read_witness_sync(&observer, identity()).unwrap(),
        Some(GlobalChargeWitness::empty()),
    );
    validate_protected_roster_recovery_state_sync(&conn, identity())
        .expect("empty format five is recoverable");
}

#[test]
fn fresh_format_five_publishes_initial_witness_atomically() {
    assert_atomic_initial_witness(1);
}

#[test]
fn format_four_upgrade_publishes_initial_witness_atomically() {
    assert_atomic_initial_witness(4);
}

#[test]
fn format_five_witness_insert_failure_rolls_back_the_format_and_namespace() {
    for format in [1, 4] {
        let backend = SqliteSessionBackend::in_memory().unwrap();
        let conn = backend.conn.blocking_lock();
        empty_predecessor(&conn, format);
        conn.execute_batch(
            "CREATE TEMP TRIGGER refuse_initial_roster_witness \
             BEFORE INSERT ON consensus_protected_roster_witness \
             BEGIN SELECT RAISE(ABORT, 'initial witness write refused'); END;",
        )
        .unwrap();
        let tx = conn.unchecked_transaction().unwrap();
        let error = activate(&tx).expect_err("injected witness insertion must fail");
        assert!(
            error.to_string().contains("initial witness is unavailable"),
            "{error}"
        );
        drop(tx);
        assert_eq!(
            persisted_schema_version_in_sync(&conn, false).unwrap(),
            format
        );
        assert_eq!(
            protected_roster_v2_layout_in_sync(&conn, false).unwrap(),
            ProtectedRosterV2Layout::Absent,
        );
        assert!(protected_roster_read_witness_sync(&conn, identity())
            .unwrap()
            .is_none());
    }
}

#[test]
fn format_five_missing_witness_rejects_reopen_and_recovery_with_reinitialize_reason() {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    empty_predecessor(&conn, 1);
    let tx = conn.unchecked_transaction().unwrap();
    activate(&tx).unwrap();
    tx.commit().unwrap();
    validate_protected_roster_recovery_state_sync(&conn, identity()).unwrap();
    assert_eq!(
        conn.execute("DELETE FROM consensus_protected_roster_witness", [])
            .unwrap(),
        1
    );
    let recovery = validate_protected_roster_recovery_state_sync(&conn, identity())
        .expect_err("format five cannot recover without its witness");
    let reopen = initialize_schema(&conn, identity(), &expected_members())
        .expect_err("format five cannot reopen without its witness");
    for error in [recovery, reopen] {
        let message = error.to_string();
        assert!(message.contains("corrupt"), "{message}");
        assert!(message.contains("mandatory roster witness"), "{message}");
        assert!(message.contains("pre-release"), "{message}");
        assert!(message.contains("reinitialized"), "{message}");
    }
    assert!(protected_roster_read_witness_sync(&conn, identity())
        .unwrap()
        .is_none());
}

fn missing_witness_reader_fixture(format: i64) -> SqliteSessionBackend {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    {
        let conn = backend.conn.blocking_lock();
        empty_predecessor(&conn, 1);
        if format == 4 {
            activate_protected_roster_schema_sync(&conn).unwrap();
        } else {
            activate(&conn).unwrap();
        }
        assert_eq!(
            persisted_schema_version_in_sync(&conn, false).unwrap(),
            format
        );
        assert_eq!(
            conn.execute("DELETE FROM consensus_protected_roster_witness", [])
                .unwrap(),
            1,
        );
    }
    backend
}

#[test]
fn maintenance_witness_reader_format_four_diagnostic_keeps_missing_as_empty() {
    let backend = missing_witness_reader_fixture(4);
    assert!(
        protected_roster_diagnostic_occupancy_sync(&backend.conn.blocking_lock(), identity())
            .unwrap()
            == ProtectedRosterLedgerOccupancy::default(),
    );
}

#[test]
fn maintenance_witness_reader_format_four_probe_keeps_missing_as_empty() {
    let backend = missing_witness_reader_fixture(4);
    assert!(
        protected_roster_maintenance_due_sync(
            &backend.conn.blocking_lock(),
            identity(),
            timestamp(2)
        )
        .unwrap()
            == (ProtectedRosterLedgerOccupancy::default(), false),
    );
}

#[test]
fn maintenance_witness_reader_format_five_diagnostic_rejects_missing() {
    let backend = missing_witness_reader_fixture(5);
    let error =
        protected_roster_diagnostic_occupancy_sync(&backend.conn.blocking_lock(), identity())
            .err()
            .expect("a corrupt format-five store cannot publish valid empty occupancy");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

#[test]
fn maintenance_witness_reader_format_five_probe_rejects_missing() {
    let backend = missing_witness_reader_fixture(5);
    let error = protected_roster_maintenance_due_sync(
        &backend.conn.blocking_lock(),
        identity(),
        timestamp(2),
    )
    .err()
    .expect("a corrupt format-five store cannot be scheduled as an empty ledger");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}
