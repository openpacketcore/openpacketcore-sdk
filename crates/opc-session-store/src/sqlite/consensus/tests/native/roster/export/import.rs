use super::install_base::copy;
use super::*;
use crate::consensus::native::generation::{Catalog, SqlitePreparedBase};
use std::io::Write;

const MAXIMUM: u64 = crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES;
const BLOCK: usize = 64 * 1024;
const CUT: [u8; 32] = [0xDA; 32];

fn prepare<'a>(
    conn: &'a mut Connection,
    binding: [u8; 32],
    signed: &'a RosterV2PersistenceFixture,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<SqlitePreparedBase<'a>> {
    SqlitePreparedBase::prepare(
        conn,
        signed.identity,
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        FIXED_TEST_PLACEMENT_POLICY.unwrap(),
        Some(&signed.root),
        binding,
        1,
        1,
        7,
        CUT,
        BLOCK,
        MAXIMUM,
        check,
    )
}

fn admitted(
    conn: &Connection,
    binding: [u8; 32],
    scope: SessionConsensusIdentity,
    root: Option<&RosterAttestationTrustRootV1>,
) -> (tempfile::TempDir, NativeStorage) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("import.native");
    let mut source = copy(conn);
    let before = database(&source);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let identity = {
        let prepared = SqlitePreparedBase::prepare(
            &mut source,
            scope,
            &fixed_members(),
            &test_member_bindings(&fixed_members()),
            FIXED_TEST_PLACEMENT_POLICY.unwrap(),
            root,
            binding,
            1,
            1,
            7,
            CUT,
            BLOCK,
            MAXIMUM,
            &|| Ok(()),
        )
        .unwrap();
        let mut writer = io::BufWriter::new(&mut file);
        let identity = prepared.write_to(&mut writer, &|| Ok(())).unwrap();
        writer.flush().unwrap();
        identity
    };
    assert!(source.is_autocommit());
    assert!(source
        .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
        .unwrap());
    assert_eq!(database(&source), before);
    file.sync_all().unwrap();
    drop(file);
    let (_owner, catalog) = Catalog::open(
        &path,
        identity,
        MAXIMUM,
        crate::consensus::native::generation::CatalogScope {
            identity: scope,
            members: &fixed_members(),
            roster_root: root.cloned().map(Arc::new),
        },
        CUT,
        &|| Ok(()),
    )
    .unwrap();
    let storage = catalog.into_storage(&|| Ok(())).unwrap();
    storage.validate_image().unwrap();
    (directory, storage)
}

pub(super) fn roundtrip(conn: &Connection, binding: [u8; 32], signed: &RosterV2PersistenceFixture) {
    let (_directory, storage) = admitted(conn, binding, signed.identity, Some(&signed.root));
    let backend = SqliteSessionBackend::in_memory().unwrap();
    initialize(&backend, signed);
    let target = backend.conn.blocking_lock();
    complete_roundtrip(conn, &target, &storage);
}

pub(in crate::sqlite::consensus::tests::native) fn rootless_roundtrip(conn: &Connection) {
    let (_directory, storage) = admitted(conn, [0xDB; 32], identity(), None);
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let target = backend.conn.blocking_lock();
    initialize_schema_with_profile(
        &target,
        identity(),
        &fixed_members(),
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    complete_roundtrip(conn, &target, &storage);
}

pub(super) fn complete_roundtrip(conn: &Connection, target: &Connection, storage: &NativeStorage) {
    // This converter handles replicated state. The install owner retains the
    // original locally chosen cursor incarnation in its cold template.
    let (epoch, key): (Vec<u8>, Vec<u8>) = conn
        .query_row(
            "SELECT epoch,cursor_key FROM restore_scan_state WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    target
        .execute(
            "UPDATE restore_scan_state SET epoch=?1,cursor_key=?2 WHERE singleton=1",
            params![epoch, key],
        )
        .unwrap();
    storage
        .export_cold_install_base_checked(target, &|| Ok(()))
        .unwrap();
    assert_eq!(
        database(target),
        database(conn),
        "SQL -> streamed V4 -> complete cold SQL preserves every schema object and column"
    );
}

#[test]
fn native_snapshot_sqlite_empty_and_unapplied_roundtrip_preserves_original_image() {
    let signed = roster_v2_fresh_wal_persistence_fixture(Phase::Established);
    let backend = SqliteSessionBackend::in_memory().unwrap();
    initialize(&backend, &signed);
    let conn = backend.conn.blocking_lock();
    roundtrip(&conn, [0xDB; 32], &signed);
    append_logs_sync(&conn, signed.identity, &[formation()]).unwrap();
    save_committed_sync(&conn, signed.identity, Some(log_id(0))).unwrap();
    roundtrip(&conn, [0xDB; 32], &signed);
    assert!(read_applied_sync(&conn, signed.identity).unwrap().is_none());
}

#[test]
fn native_snapshot_sqlite_stream_rejects_wrong_authority_projection_and_bound() {
    let (_directory, backend, signed, wal) = fresh(Phase::Established);
    parity(&wal, &backend, &signed, &[admission(&signed)]);
    let source = wal.native_export_snapshot().unwrap();
    let before = database(&source);
    for root in [None, Some(wrong_root(&signed))] {
        let mut candidate = copy(&source);
        assert!(SqlitePreparedBase::prepare(
            &mut candidate,
            signed.identity,
            &fixed_members(),
            &test_member_bindings(&fixed_members()),
            FIXED_TEST_PLACEMENT_POLICY.unwrap(),
            root.as_deref(),
            [0xDB; 32],
            1,
            1,
            7,
            CUT,
            BLOCK,
            MAXIMUM,
            &|| Ok(())
        )
        .is_err());
        assert_eq!(database(&candidate), before);
    }
    let mut candidate = copy(&source);
    assert!(SqlitePreparedBase::prepare(
        &mut candidate,
        signed.identity,
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        PlacementResiliencePolicy::AllowReducedResilience,
        Some(&signed.root),
        [0xDB; 32],
        1,
        1,
        7,
        CUT,
        BLOCK,
        MAXIMUM,
        &|| Ok(())
    )
    .is_err());
    assert_eq!(database(&candidate), before);
    let mut candidate = copy(&source);
    assert!(SqlitePreparedBase::prepare(
        &mut candidate,
        signed.identity,
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        FIXED_TEST_PLACEMENT_POLICY.unwrap(),
        Some(&signed.root),
        [0xDB; 32],
        1,
        1,
        7,
        CUT,
        BLOCK,
        1,
        &|| Ok(())
    )
    .is_err());
    assert_eq!(database(&candidate), before);
    for mutation in [
        "UPDATE consensus_protected_roster_v2_admissions SET terminal_request_id=randomblob(16)",
        "DELETE FROM consensus_protected_roster_v2_absence_reservations",
        "UPDATE consensus_protected_roster_v2_admissions SET original_credential_id=original_credential_id+1",
        "DELETE FROM consensus_protected_roster_v2_activation",
        "UPDATE consensus_operator_recovery SET recovery_epoch=1,last_plan_digest=randomblob(32)",
        "UPDATE consensus_log SET term=term+1 WHERE log_index=0",
    ] {
        let mut candidate = copy(&source);
        candidate.pragma_update(None,"query_only",false).unwrap();
        candidate.execute(mutation,[]).unwrap();
        let corrupt = database(&candidate);
        assert!(prepare(&mut candidate,[0xDB;32],&signed,&|| Ok(())).is_err(),"{mutation}");
        assert_eq!(database(&candidate),corrupt);
    }
    assert_eq!(database(&source), before);
    wal.shutdown().unwrap();
}

#[test]
fn native_snapshot_sqlite_cancelled_count_and_write_release_read_transaction() {
    let (_directory, backend, signed, wal) = fresh(Phase::Established);
    parity(&wal, &backend, &signed, &[admission(&signed)]);
    let mut source = wal.native_export_snapshot().unwrap();
    let before = database(&source);
    let calls = Cell::new(0usize);
    let result = prepare(&mut source, [0xDB; 32], &signed, &|| {
        calls.set(calls.get() + 1);
        if calls.get() == 12 {
            Err(io::Error::other("cancel SQL count"))
        } else {
            Ok(())
        }
    });
    assert!(matches!(result,Err(ref error) if error.to_string() == "cancel SQL count"));
    drop(result);
    assert!(source.is_autocommit());
    assert_eq!(database(&source), before);
    let prepared = prepare(&mut source, [0xDB; 32], &signed, &|| Ok(())).unwrap();
    calls.set(0);
    let mut output = Vec::new();
    let error = prepared
        .write_to(&mut output, &|| {
            calls.set(calls.get() + 1);
            if calls.get() == 5 {
                Err(io::Error::other("cancel SQL write"))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "cancel SQL write");
    assert!(!output.is_empty());
    drop(prepared);
    assert!(source.is_autocommit());
    assert_eq!(database(&source), before);
    roundtrip(&source, [0xDB; 32], &signed);
    wal.shutdown().unwrap();
}

#[test]
fn native_snapshot_sqlite_oversized_absence_projection_rejects_before_decoding() {
    let (_directory, backend, signed, wal) = fresh(Phase::Established);
    parity(&wal, &backend, &signed, &[admission(&signed)]);
    let mut source = wal.native_export_snapshot().unwrap();
    source.pragma_update(None, "query_only", false).unwrap();
    source
        .pragma_update(None, "ignore_check_constraints", true)
        .unwrap();
    let size = 2 * SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES + 1;
    source.execute("UPDATE consensus_protected_roster_v2_absence_reservations SET business_key=zeroblob(?1)",[size]).unwrap();
    source
        .pragma_update(None, "ignore_check_constraints", false)
        .unwrap();
    let result = prepare(&mut source, [0xDB; 32], &signed, &|| Ok(()));
    assert!(
        matches!(result,Err(ref error) if error.to_string() == "native snapshot SQL value exceeds generation bound")
    );
    drop(result);
    assert!(source.is_autocommit());
    assert_eq!(source.query_row("SELECT length(business_key) FROM consensus_protected_roster_v2_absence_reservations",[],|row| row.get::<_,usize>(0)).unwrap(),size);
    assert_eq!(
        count(&source, "consensus_protected_roster_v2_admissions"),
        1
    );
    wal.shutdown().unwrap();
}

#[test]
fn native_snapshot_sqlite_read_transaction_pins_both_passes_across_concurrent_commit() {
    let signed = roster_v2_fresh_wal_persistence_fixture(Phase::Established);
    let backend = SqliteSessionBackend::in_memory().unwrap();
    initialize(&backend, &signed);
    sql_apply(&backend, &signed, &[formation()]);
    let conn = backend.conn.blocking_lock();
    let mut expected_source = copy(&conn);
    let mut expected = Vec::new();
    let expected_id = prepare(&mut expected_source, [0xDB; 32], &signed, &|| Ok(()))
        .unwrap()
        .write_to(&mut expected, &|| Ok(()))
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let mut source = Connection::open(&path).unwrap();
    rusqlite::backup::Backup::new(&conn, &mut source)
        .unwrap()
        .run_to_completion(128, Duration::ZERO, None)
        .unwrap();
    source.pragma_update(None, "journal_mode", "WAL").unwrap();
    let prepared = prepare(&mut source, [0xDB; 32], &signed, &|| Ok(())).unwrap();
    let writer = Connection::open(&path).unwrap();
    let suffix = Entry {
        log_id: log_id(1),
        payload: EntryPayload::Blank,
    };
    append_logs_sync(&writer, signed.identity, std::slice::from_ref(&suffix)).unwrap();
    save_committed_sync(&writer, signed.identity, Some(suffix.log_id)).unwrap();
    assert_eq!(
        count(&writer, "consensus_log"),
        2,
        "the writer commits while the source read transaction remains open"
    );
    let mut actual = Vec::new();
    assert_eq!(
        prepared.write_to(&mut actual, &|| Ok(())).unwrap(),
        expected_id
    );
    assert_eq!(
        actual, expected,
        "both stream passes retain the same SQL snapshot despite a concurrent commit"
    );
    drop(prepared);
    assert!(source.is_autocommit());
    assert_eq!(count(&source, "consensus_log"), 2);
    let mut successor = Vec::new();
    let successor_id = prepare(&mut source, [0xDB; 32], &signed, &|| Ok(()))
        .unwrap()
        .write_to(&mut successor, &|| Ok(()))
        .unwrap();
    assert_ne!(successor_id, expected_id);
    assert_ne!(successor, expected);
    roundtrip(&source, [0xDB; 32], &signed);
}

#[test]
fn native_snapshot_sqlite_padded_metadata_reservation_spans_header_and_releases_scratch() {
    use crate::consensus::verified_snapshot::VerificationMemory;
    const CHILD: &str = "OPC_NATIVE_SQL_PADDED_METADATA_CHILD";
    const TEST:&str = "sqlite::consensus::tests::native::roster::export::import::native_snapshot_sqlite_padded_metadata_reservation_spans_header_and_releases_scratch";
    if std::env::var_os(CHILD).is_none() {
        // The probe reserves accounting only. Isolate its process counter so
        // unrelated parallel tests cannot affect the fixed 128 MiB limit.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        println!(
            "native_sql_padded_metadata_child={}",
            serde_json::json!({"exit_code":output.status.code(),"stdout":stdout,"stderr":stderr,
            "original_process_verification_limit_bytes":128 * 1024 * 1024,"sql_padding_bytes":4 * 1024 * 1024})
        );
        assert!(output.status.success());
        assert!(
            stdout.contains(&format!("test {TEST} ... ok"))
                && stdout.contains("test result: ok. 1 passed; 0 failed; 0 ignored;")
        );
        return;
    }
    let signed = roster_v2_fresh_wal_persistence_fixture(Phase::Established);
    let backend = SqliteSessionBackend::in_memory().unwrap();
    initialize(&backend, &signed);
    sql_apply(&backend, &signed, &[formation()]);
    let conn = backend.conn.blocking_lock();
    let mut source = copy(&conn);
    let mut expected = Vec::new();
    let expected_id = prepare(&mut source, [0xDB; 32], &signed, &|| Ok(()))
        .unwrap()
        .write_to(&mut expected, &|| Ok(()))
        .unwrap();
    source.pragma_update(None, "query_only", false).unwrap();
    let mut padded: Vec<u8> = source
        .query_row(
            "SELECT membership_json FROM consensus_membership",
            [],
            |row| row.get(0),
        )
        .unwrap();
    padded.resize(padded.len() + 4 * 1024 * 1024, b' ');
    source
        .execute(
            "UPDATE consensus_membership SET membership_json=?1",
            [&padded],
        )
        .unwrap();
    drop(padded);
    let validation_calls = Cell::new(0usize);
    let metadata = crate::sqlite::consensus::native_snapshot::validate(
        &source,
        signed.identity,
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        FIXED_TEST_PLACEMENT_POLICY.unwrap(),
        Some(&signed.root),
        &|| {
            validation_calls.set(validation_calls.get() + 1);
            Ok(())
        },
    )
    .unwrap();
    assert!(
        VerificationMemory::reserve(96 * 1024 * 1024).is_err(),
        "SQL metadata owns its original scratch reservation on return"
    );
    drop(metadata);
    let calls = Cell::new(0usize);
    let observed = Cell::new(false);
    let prepared = prepare(&mut source, [0xDB; 32], &signed, &|| {
        calls.set(calls.get() + 1);
        if calls.get() == validation_calls.get() + 2 {
            assert!(
                VerificationMemory::reserve(96 * 1024 * 1024).is_err(),
                "raw metadata reservation is still held at the first header boundary"
            );
            observed.set(true);
        }
        Ok(())
    })
    .unwrap();
    assert!(observed.get());
    let mut actual = Vec::new();
    assert_eq!(
        prepared.write_to(&mut actual, &|| Ok(())).unwrap(),
        expected_id
    );
    assert_eq!(
        actual, expected,
        "valid SQL padding preserves the exact bounded canonical native generation"
    );
    let probe = VerificationMemory::reserve(96 * 1024 * 1024).unwrap();
    drop(probe);
    drop(prepared);
    assert!(source.is_autocommit());
}
