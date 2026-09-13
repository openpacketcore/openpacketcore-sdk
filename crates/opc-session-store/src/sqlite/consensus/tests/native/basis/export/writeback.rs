use super::*;

const LAST_WRITEBACK_BATCH: u64 = 17;

fn writeback_fixture(control: IoControl) -> Fixture {
    let fixture = Fixture::with_control(Limits::default(), control);
    let initial = fenced_transition_v2_request(0xE7, 1, "native-writeback-first");
    fixture.parity(&[formation(), activation(1, initial, timestamp(1))]);
    for index in 2..=LAST_WRITEBACK_BATCH {
        let requests = (0..256)
            .map(|slot| sdk741_component_request(Sdk741Payload::Create, index * 32, slot, None))
            .collect();
        fixture.parity(&[fenced_transition_v2_batch_entry(
            index,
            requests,
            timestamp(2),
        )]);
    }
    fixture
}

#[test]
fn native_snapshot_writeback_releases_live_owner_and_preserves_captured_cut() {
    let gate = Gate::new(Point::BeforeNativeSnapshotWriteback, 1);
    let fixture = writeback_fixture(gate.control());
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
        &fixture.directory.path().join("reference-writeback.sqlite"),
    )
    .unwrap();
    assert!(reference.file().metadata().unwrap().len() > 8 * 1024 * 1024);
    assert_eq!(expected_cut.0, Some(log_id(LAST_WRITEBACK_BATCH)));
    let path = fixture.directory.path().join("writeback.sqlite");
    let pin = create_pinned_snapshot_database(&path).unwrap();
    let later = sdk741_component_request(Sdk741Payload::Create, 1024, 0, None);
    let ((exported, cut), paused_extent) = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            fixture
                .wal
                .native_export_portable_snapshot_into(&pin, &|| false)
                .unwrap()
                .unwrap()
        });
        gate.entered();
        let paused_extent = pin.file().metadata().unwrap().len();
        assert!(paused_extent >= 8 * 1024 * 1024);
        // The real output flush is paused. A new durable mutation must still
        // append, commit and apply through the live owner before it resumes.
        fixture.parity(&[fenced_transition_v2_batch_entry(
            LAST_WRITEBACK_BATCH + 1,
            vec![later.clone()],
            timestamp(3),
        )]);
        fixture
            .wal
            .submit(Operation::Barrier)
            .unwrap()
            .wait()
            .unwrap();
        assert!(!worker.is_finished());
        gate.release();
        (worker.join().unwrap(), paused_extent)
    });
    assert_eq!(
        cut, expected_cut,
        "export retains its original immutable cut"
    );
    let finalized =
        finalize_native_snapshot_database_sync(exported, pin, authority(), &cut).unwrap();
    assert!(finalized.file().metadata().unwrap().len() > paused_extent);
    let conn = open_pinned_snapshot_database(&finalized).unwrap();
    assert_portable_tables_equal(&conn, &open_pinned_snapshot_database(&reference).unwrap());
    validate_native_snapshot_export_sync(&conn, &finalized, authority(), &cut).unwrap();
    drop(conn);
    drop(finalized);
    assert!(
        !path.exists(),
        "unpublished output is reclaimed after finalization"
    );
    let expected_later = read_fenced_transition_v2_status_sync(
        &fixture.oracle.conn.blocking_lock(),
        identity(),
        identity(),
        &later,
    )
    .unwrap();
    let reopened = fixture.reopened();
    assert_eq!(
        reopened
            .with_native_read(|state| Ok(state.applied()))
            .unwrap(),
        Some(log_id(LAST_WRITEBACK_BATCH + 1))
    );
    assert_eq!(status(&reopened, &later), expected_later);
    assert!(matches!(
        expected_later,
        FencedTransitionV2Status::Recorded(_)
    ));
    reopened.shutdown().unwrap();
}

#[test]
fn native_snapshot_writeback_io_failure_fences_wakes_and_survives_cancellation() {
    let writeback = Gate::new(Point::BeforeNativeSnapshotWriteback, 1);
    let cut = Gate::new(Point::BeforeCutPublish, 1);
    let armed = Arc::new(AtomicBool::new(false));
    let hooks = (Arc::clone(&writeback), Arc::clone(&cut), Arc::clone(&armed));
    let fixture = writeback_fixture(IoControl {
        hook: Arc::new(move |point| {
            if hooks.2.load(Ordering::Acquire) {
                hooks.1.hook(point)?;
            }
            hooks.0.hook(point)?;
            if point == Point::BeforeNativeSnapshotWriteback {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "injected native snapshot writeback failure",
                ));
            }
            Ok(())
        }),
        ..IoControl::default()
    });
    let path = fixture.directory.path().join("failed-writeback.sqlite");
    let pin = create_pinned_snapshot_database(&path).unwrap();
    let cancelled = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            fixture
                .wal
                .native_export_portable_snapshot_into(&pin, &|| cancelled.load(Ordering::Acquire))
        });
        writeback.entered();
        assert!(pin.file().metadata().unwrap().len() >= 8 * 1024 * 1024);
        armed.store(true, Ordering::Release);
        let inflight = fixture
            .wal
            .submit(append(&[Entry {
                log_id: log_id(LAST_WRITEBACK_BATCH + 1),
                payload: EntryPayload::Blank,
            }]))
            .unwrap();
        cut.entered();
        let queued = fixture.wal.submit(Operation::Barrier).unwrap();
        cancelled.store(true, Ordering::Release);
        writeback.release();
        let error = worker.join().unwrap().err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(
            error.to_string(),
            "injected native snapshot writeback failure"
        );
        assert!(fixture.wal.submit(Operation::Barrier).is_err());
        assert!(queued.try_recv().unwrap().is_err());
        assert!(matches!(
            queued.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
        assert!(matches!(
            inflight.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        cut.release();
        assert!(inflight.wait().is_err());
    });
    assert!(fixture.wal.shutdown().is_err());
    drop(pin);
    assert!(!path.exists(), "failed unpublished staging is reclaimed");
    let reopened = Wal::open(
        &fixture.directory.path().join("wal"),
        fixture.wal.binding(),
        Limits::default(),
        IoControl::default(),
    )
    .unwrap();
    assert_eq!(
        reopened
            .with_native_read(|state| Ok(state.applied()))
            .unwrap(),
        Some(log_id(LAST_WRITEBACK_BATCH))
    );
    let request =
        sdk741_component_request(Sdk741Payload::Create, LAST_WRITEBACK_BATCH * 32, 255, None);
    let expected = read_fenced_transition_v2_status_sync(
        &fixture.oracle.conn.blocking_lock(),
        identity(),
        identity(),
        &request,
    )
    .unwrap();
    assert_eq!(status(&reopened, &request), expected);
    assert!(matches!(expected, FencedTransitionV2Status::Recorded(_)));
    reopened.shutdown().unwrap();
}
