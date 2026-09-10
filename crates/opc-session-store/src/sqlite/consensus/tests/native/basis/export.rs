use super::*;
use crate::sqlite::consensus::tests::native::ordinary::rows;

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
    let fixture = populated();
    let path = fixture.directory.path().join("cancelled.sqlite");
    let cancelled = AtomicBool::new(false);
    let checks = AtomicUsize::new(0);
    let gate = Gate::new(Point::BeforeNativeSnapshotRead, 1);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let raw = create_pinned_snapshot_database(&path).unwrap();
            let result = fixture
                .wal
                .native_export_snapshot_into(&raw, &|| {
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
    let error = failed
        .wal
        .native_export_snapshot_into(&raw, &|| true)
        .err()
        .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(error.to_string(), "injected export I/O interruption");
    assert!(failed.wal.submit(Operation::Barrier).is_err());
    assert!(failed.wal.shutdown().is_err());
}
