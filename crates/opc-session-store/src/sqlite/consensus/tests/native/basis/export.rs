use super::*;
use crate::sqlite::consensus::tests::native::ordinary::rows;

#[test]
fn native_snapshot_export_reuses_insert_preparations_and_preserves_exact_rows() {
    let fixture = Fixture::new();
    let first = fenced_transition_v2_request(0xC1, 1, "native-export-preparation");
    fixture.parity(&[formation(), activation(1, first, timestamp(1))]);
    let requests = (0..128)
        .map(|slot| sdk741_component_request(Sdk741Payload::Create, 2, slot, None))
        .collect::<Vec<_>>();
    fixture.parity(&[fenced_transition_v2_batch_entry(2, requests, timestamp(2))]);
    let clocks = (3..=130)
        .map(|index| Entry {
            log_id: log_id(index),
            payload: EntryPayload::Normal(SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity: identity(),
                request_id: SessionConsensusRequestId::from_bytes(
                    (0xEA00_0000_0000_0000u128 + u128::from(index)).to_be_bytes(),
                ),
                logical_time: timestamp(3),
                intent: SessionMutationIntent::Authorized {
                    origin: node_id(),
                    authority_identity: identity(),
                    mutation: Box::new(SessionMutationIntent::AdvanceLogicalTime),
                },
            }),
        })
        .collect::<Vec<_>>();
    fixture.parity(&clocks);
    let entries = fixture.wal.native_log_read(0, None, Some(131)).unwrap();
    assert_eq!(entries.len(), 131);
    let mut storage = NativeStorage::empty(identity(), fixed_members()).unwrap();
    for chunk in entries.chunks(64) {
        storage
            .log
            .project(&append(chunk), &storage.business, None)
            .unwrap();
    }
    storage
        .log
        .project(
            &Operation::Committed(Some(log_id(130))),
            &storage.business,
            None,
        )
        .unwrap();
    storage.replay_committed().unwrap();
    let basis = SqliteSessionBackend::in_memory().unwrap();
    let conn = basis.conn.blocking_lock();
    initialize_schema_with_profile(
        &conn,
        identity(),
        &fixed_members(),
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    let preparations = Arc::new([const { AtomicUsize::new(0) }; 3]);
    let observed = Arc::clone(&preparations);
    conn.authorizer(Some(move |context: rusqlite::hooks::AuthContext<'_>| {
        let slot = match context.action {
            rusqlite::hooks::AuthAction::Insert {
                table_name: "consensus_log",
            } => Some(0),
            rusqlite::hooks::AuthAction::Insert {
                table_name: "consensus_request_outcomes",
            } => Some(1),
            rusqlite::hooks::AuthAction::Insert {
                table_name: "session_replication_log",
            } => Some(2),
            _ => None,
        };
        if let Some(slot) = slot {
            observed[slot].fetch_add(1, Ordering::Relaxed);
        }
        rusqlite::hooks::Authorization::Allow
    }));
    let started = Instant::now();
    storage
        .export_cold_install_base_checked(&conn, &|| Ok(()))
        .unwrap();
    let elapsed = started.elapsed();
    let counts = preparations
        .each_ref()
        .map(|value| value.load(Ordering::Relaxed));
    let oracle = fixture.oracle.conn.blocking_lock();
    for table in [
        "session_records",
        "leases",
        "key_fences",
        "lease_globals",
        "consensus_machine",
        "consensus_applied",
        "consensus_committed",
        "consensus_membership",
        "consensus_request_outcomes",
        "consensus_fenced_transition_v2_receipts",
        "session_replication_log",
        "consensus_log",
    ] {
        assert_eq!(
            rows(&conn, table),
            rows(&oracle, table),
            "exact table {table}"
        );
    }
    let row_counts: [usize; 3] = [
        "consensus_log",
        "consensus_request_outcomes",
        "session_replication_log",
    ]
    .map(|table| rows(&conn, table).len());
    assert!(row_counts.iter().all(|count| *count >= 128));
    drop(oracle);
    fixture.wal.shutdown().unwrap();
    eprintln!(
        "native_export_insert_preparations rows={row_counts:?} preparations={counts:?} elapsed_us={}",
        elapsed.as_micros(),
    );
    // Authorizers run when SQLite prepares the program. Every row above is
    // still executed and compared to an independently applied SQL oracle.
    assert_eq!(
        counts, [1; 3],
        "repeated export inserts must reuse their programs"
    );
}

fn populated() -> Fixture {
    let fixture = Fixture::new();
    let first = fenced_transition_v2_request(0xC1, 1, "native-file-export");
    fixture.parity(&[formation(), activation(1, first.clone(), timestamp(1))]);
    for index in 2..=8 {
        fixture.parity(&[fenced_transition_v2_authorized_entry(
            index,
            fenced_transition_v2_request(0xC1 + index as u8, 1, "native-file-export"),
            timestamp(2),
            node_id(),
            identity(),
        )]);
    }
    fixture.wal.checkpoint().unwrap();
    until(|| {
        fixture
            .wal
            .native_cold_counts_for_test()
            .is_ok_and(|counts| counts[0] == 8)
    });
    fixture
}

#[test]
fn native_portable_snapshot_fits_without_discarded_raft_log_pages() {
    let fixture = Fixture::new();
    let request = fenced_transition_v2_request(0xC1, 1, "native-portable-capacity");
    fixture.parity(&[formation(), activation(1, request.clone(), timestamp(1))]);
    // Exact retries retain physical Raft entries without adding business rows.
    // A portable snapshot must not need disk capacity for those local entries.
    let retries = (2..=65)
        .map(|index| {
            fenced_transition_v2_authorized_entry(
                index,
                request.clone(),
                timestamp(2),
                node_id(),
                identity(),
            )
        })
        .collect::<Vec<_>>();
    fixture.parity(&retries);
    let members = fixed_members();
    let bindings = test_member_bindings(&members);
    let authority = || SnapshotBuildAuthority {
        identity: identity(),
        profile: ConsensusAuthorityProfile::FixedImmutable,
        expected_members: &members,
        expected_bindings: &bindings,
        fixed_placement_policy: FIXED_TEST_PLACEMENT_POLICY,
    };
    let oracle = fixture.oracle.conn.blocking_lock();
    let (cut, reference) = build_snapshot_database_pinned_with_authority_sync(
        &oracle,
        authority(),
        &fixture.directory.path().join("reference.sqlite"),
    )
    .unwrap();
    let reference_conn = open_pinned_snapshot_database(&reference).unwrap();
    let (reference_pages, page_size) = snapshot_database_extent_sync(&reference_conn).unwrap();
    let log_bytes: i64 = oracle
        .query_row(
            "SELECT sum(length(entry_json)) FROM consensus_log",
            [],
            |row| row.get(0),
        )
        .unwrap();
    drop(oracle);
    let entries = fixture.wal.native_log_read(0, None, Some(66)).unwrap();
    let mut storage = NativeStorage::empty(identity(), members.clone()).unwrap();
    for chunk in entries.chunks(64) {
        storage
            .log
            .project(&append(chunk), &storage.business, None)
            .unwrap();
    }
    storage
        .log
        .project(
            &Operation::Committed(Some(log_id(65))),
            &storage.business,
            None,
        )
        .unwrap();
    storage.replay_committed().unwrap();
    let output_path = fixture.directory.path().join("portable.sqlite");
    let basis = SqliteSessionBackend::in_memory().unwrap();
    let basis_conn = basis.conn.blocking_lock();
    initialize_schema_with_profile(
        &basis_conn,
        identity(),
        &fixed_members(),
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    let pin = create_pinned_snapshot_database(&output_path).unwrap();
    let mut conn = open_pinned_snapshot_database(&pin).unwrap();
    rusqlite::backup::Backup::new(&basis_conn, &mut conn)
        .unwrap()
        .run_to_completion(128, Duration::ZERO, None)
        .unwrap();
    disable_snapshot_database_journal_sync(&conn).unwrap();
    // Allow B-tree insertion-order headroom over an independently built SQL
    // snapshot. The limit applies to actual SQLite writes, not an estimator.
    let page_limit = reference_pages + 16;
    conn.pragma_update(None, "max_page_count", page_limit)
        .unwrap();
    eprintln!("portable capacity regression: reference_pages={reference_pages} page_limit={page_limit} page_size={page_size} omitted_log_bytes={log_bytes}");
    let exported = storage.export_cold_portable_snapshot_checked(&conn, &|| Ok(()));
    assert!(
        exported.is_ok(),
        "portable export within its page budget: {exported:?}"
    );
    assert!(std::fs::metadata(&output_path).unwrap().len() <= page_limit as u64 * page_size);
    let finalized = finalize_native_snapshot_database_sync(conn, pin, authority(), &cut).unwrap();
    assert!(finalized.file().metadata().unwrap().len() <= page_limit as u64 * page_size);
    let conn = open_pinned_snapshot_database(&finalized).unwrap();
    assert_portable_tables_equal(&conn, &reference_conn);
    fixture.wal.shutdown().unwrap();
}

fn assert_portable_tables_equal(actual: &Connection, expected: &Connection) {
    let tables = |conn: &Connection| {
        conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap()
        .query_map([], |row| row.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    };
    assert_eq!(tables(actual), tables(expected));
    for table in tables(expected) {
        if table == "restore_scan_state" {
            let state = |conn: &Connection| {
                conn.query_row(
                    "SELECT singleton, epoch, revision FROM restore_scan_state",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    },
                )
                .unwrap()
            };
            let left = state(actual);
            let right = state(expected);
            assert_eq!((left.0, left.2), (right.0, right.2));
            assert_ne!(
                left.1, right.1,
                "each finalization rotates its restore incarnation"
            );
        } else {
            assert_eq!(
                rows(actual, &table),
                rows(expected, &table),
                "portable table {table}"
            );
        }
    }
}

#[test]
fn native_portable_snapshot_finalization_preserves_cold_rows_cut_and_cleanup() {
    let fixture = populated();
    let members = fixed_members();
    let bindings = test_member_bindings(&members);
    let authority = || SnapshotBuildAuthority {
        identity: identity(),
        profile: ConsensusAuthorityProfile::FixedImmutable,
        expected_members: &members,
        expected_bindings: &bindings,
        fixed_placement_policy: FIXED_TEST_PLACEMENT_POLICY,
    };
    let (expected_cut, reference) = build_snapshot_database_pinned_with_authority_sync(
        &fixture.oracle.conn.blocking_lock(),
        authority(),
        &fixture.directory.path().join("reference-portable.sqlite"),
    )
    .unwrap();
    let path = fixture.directory.path().join("direct-portable.sqlite");
    let pin = create_pinned_snapshot_database(&path).unwrap();
    let (exported, cut) = fixture
        .wal
        .native_export_portable_snapshot_into(&pin, &|| false)
        .unwrap()
        .unwrap();
    assert_eq!(cut, expected_cut);
    let mut wrong_cut = cut.clone();
    wrong_cut.0 = Some(log_id(999));
    assert!(
        validate_native_snapshot_export_sync(&exported, &pin, authority(), &wrong_cut).is_err()
    );
    let finalized =
        finalize_native_snapshot_database_sync(exported, pin, authority(), &cut).unwrap();
    let conn = open_pinned_snapshot_database(&finalized).unwrap();
    assert_portable_tables_equal(&conn, &open_pinned_snapshot_database(&reference).unwrap());
    validate_native_snapshot_export_sync(&conn, &finalized, authority(), &cut).unwrap();
    drop(conn);
    drop(finalized);
    assert!(
        !path.exists(),
        "unpublished portable output retains exact cleanup"
    );
    fixture.wal.shutdown().unwrap();
}

#[test]
fn native_portable_snapshot_rejects_corruption_in_omitted_selected_log_bytes() {
    use crate::consensus::native::generation::{Catalog, PreparedBase};
    use std::os::unix::fs::FileExt;

    let fixture = populated();
    let entries = fixture.wal.native_log_read(0, None, Some(9)).unwrap();
    let mut storage = NativeStorage::empty(identity(), fixed_members()).unwrap();
    storage
        .log
        .project(&append(&entries), &storage.business, None)
        .unwrap();
    storage
        .log
        .project(
            &Operation::Committed(Some(log_id(8))),
            &storage.business,
            None,
        )
        .unwrap();
    storage.replay_committed().unwrap();
    let path = fixture.directory.path().join("selected.native");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let prepared = PreparedBase::prepare(
        &storage,
        crate::consensus::native::generation::BaseParameters {
            binding: [3; 32],
            file_epoch: 1,
            checkpoint_epoch: 1,
            operation_sequence: 1,
            cut_binding: [4; 32],
            block_bytes: 64 * 1024,
            maximum: 16 * 1024 * 1024,
        },
        &|| Ok(()),
    )
    .unwrap();
    let prefix = prepared.write_to(&mut file, &|| Ok(())).unwrap();
    file.sync_all().unwrap();
    let (_owner, catalog) = Catalog::open(
        &path,
        prefix,
        16 * 1024 * 1024,
        crate::consensus::native::generation::CatalogScope {
            identity: identity(),
            members: &fixed_members(),
            roster_root: None,
        },
        [4; 32],
        &|| Ok(()),
    )
    .unwrap();
    let cold = catalog.into_storage(&|| Ok(())).unwrap();
    assert_eq!(cold.cold_counts_for_test()[2], 9);
    let encoded_log = encode_json(&entries[0]).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let offset = bytes
        .windows(encoded_log.len())
        .position(|bytes| bytes == encoded_log)
        .unwrap();
    file.write_all_at(&[encoded_log[0] ^ 1], offset as u64)
        .unwrap();
    file.sync_all().unwrap();
    // The admitted compact facts still pass. Export must read and authenticate
    // the covered log bytes even though consensus_log will remain empty.
    cold.validate_image().unwrap();
    let output = SqliteSessionBackend::in_memory().unwrap();
    let conn = output.conn.blocking_lock();
    initialize_schema_with_profile(
        &conn,
        identity(),
        &fixed_members(),
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    let error = cold
        .export_cold_portable_snapshot_checked(&conn, &|| Ok(()))
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(rows(&conn, "consensus_log").is_empty());
    assert!(
        rows(&conn, "session_records").is_empty(),
        "failed export rolls back"
    );
    fixture.wal.shutdown().unwrap();
}

#[test]
fn native_snapshot_file_export_preserves_every_sql_column_and_captured_cut() {
    let fixture = populated();
    let path = fixture.directory.path().join("raw.sqlite");
    let raw = create_pinned_snapshot_database(&path).unwrap();
    let (exported, cut) = fixture
        .wal
        .native_export_snapshot_into(&raw, &|| false)
        .unwrap()
        .unwrap();
    verify_pinned_snapshot_descriptor(&raw, &exported).unwrap();
    assert!(raw.file().metadata().unwrap().len() > 0);
    let members = fixed_members();
    let bindings = test_member_bindings(&members);
    let authority = || SnapshotBuildAuthority {
        identity: identity(),
        profile: ConsensusAuthorityProfile::FixedImmutable,
        expected_members: &members,
        expected_bindings: &bindings,
        fixed_placement_policy: FIXED_TEST_PLACEMENT_POLICY,
    };
    validate_native_snapshot_export_sync(&exported, &raw, authority(), &cut).unwrap();
    let mut wrong_cut = cut.clone();
    wrong_cut.0 = Some(log_id(999));
    assert!(
        validate_native_snapshot_export_sync(&exported, &raw, authority(), &wrong_cut).is_err()
    );
    let oracle = fixture.oracle.conn.blocking_lock();
    let tables = oracle.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap()
        .query_map([], |row| row.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    for table in tables {
        assert_eq!(
            rows(&exported, &table),
            rows(&oracle, &table),
            "complete original table {table}"
        );
    }
    assert_eq!(
        snapshot_applied_membership_sync(&oracle, identity()).unwrap(),
        cut
    );
    drop(oracle);
    drop(exported);
    let final_path = fixture.directory.path().join("compacted.sqlite");
    let compacted = finalize_captured_snapshot_database_into_sync(
        identity(),
        ConsensusAuthorityProfile::FixedImmutable,
        &members,
        &bindings,
        FIXED_TEST_PLACEMENT_POLICY,
        &cut,
        raw,
        create_pinned_snapshot_database(&final_path).unwrap(),
        &ConsensusSnapshotForegroundPacer::default(),
    )
    .unwrap();
    let conn = open_pinned_snapshot_database(&compacted).unwrap();
    validate_existing_schema(&conn, identity()).unwrap();
    validate_sealed_state_sync(&conn).unwrap();
    assert_eq!(
        snapshot_applied_membership_sync(&conn, identity()).unwrap(),
        cut
    );
    drop(conn);
    assert!(
        !path.exists(),
        "the original finalizer reclaims the raw inode"
    );
    drop(compacted);
    assert!(
        !final_path.exists(),
        "unpublished final output retains exact cleanup"
    );
    fixture.wal.shutdown().unwrap();
}

#[test]
fn native_snapshot_export_cancellation_discards_staging_without_masking_io_failure() {
    for portable in [false, true] {
        snapshot_export_cancellation_case(portable);
    }
}

fn export_into(
    wal: &Wal,
    pin: &crate::consensus::snapshot::PinnedSqliteFile,
    portable: bool,
    cancelled: &impl Fn() -> bool,
) -> io::Result<Option<(Connection, ConsensusAppliedMembership)>> {
    if portable {
        wal.native_export_portable_snapshot_into(pin, cancelled)
    } else {
        wal.native_export_snapshot_into(pin, cancelled)
    }
}

fn snapshot_export_cancellation_case(portable: bool) {
    let fixture = populated();
    let path = fixture.directory.path().join("cancelled.sqlite");
    let cancelled = AtomicBool::new(false);
    let checks = AtomicUsize::new(0);
    let gate = Gate::new(Point::BeforeNativeSnapshotRead, 1);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let raw = create_pinned_snapshot_database(&path).unwrap();
            let result = export_into(&fixture.wal, &raw, portable, &|| {
                if checks.fetch_add(1, Ordering::SeqCst) == 16 {
                    gate.hook(Point::BeforeNativeSnapshotRead).unwrap();
                }
                cancelled.load(Ordering::Acquire)
            })
            .unwrap();
            assert!(result.is_none());
            drop(raw);
        });
        gate.entered();
        assert!(
            std::fs::metadata(&path).unwrap().len() > 0,
            "cancel a populated staging database"
        );
        fixture
            .wal
            .submit(Operation::Barrier)
            .unwrap()
            .wait()
            .unwrap();
        cancelled.store(true, Ordering::Release);
        assert!(
            !worker.is_finished(),
            "the actual worker still owns its blocked export"
        );
        gate.release();
        worker.join().unwrap();
    });
    assert!(!path.exists());
    fixture
        .wal
        .submit(Operation::Barrier)
        .unwrap()
        .wait()
        .unwrap();
    let expected = fixture
        .wal
        .with_native_read(|state| Ok(state.applied()))
        .unwrap();
    let reopened = fixture.reopened();
    assert_eq!(
        reopened
            .with_native_read(|state| Ok(state.applied()))
            .unwrap(),
        expected
    );
    reopened.shutdown().unwrap();

    let control = IoControl {
        hook: Arc::new(|point| {
            if point == Point::BeforeNativeSnapshotRead {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "injected export I/O interruption",
                ));
            }
            Ok(())
        }),
        ..IoControl::default()
    };
    let failed = Fixture::with_control(Limits::default(), control);
    let raw =
        create_pinned_snapshot_database(&failed.directory.path().join("failed.sqlite")).unwrap();
    let error = export_into(&failed.wal, &raw, portable, &|| true)
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(error.to_string(), "injected export I/O interruption");
    assert!(failed.wal.submit(Operation::Barrier).is_err());
    assert!(failed.wal.shutdown().is_err());
}
