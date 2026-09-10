use super::*;

fn oracle_apply(fixture: &Fixture, entries: &[Entry<SessionRaftTypeConfig>]) -> AppliedBatch {
    let conn = fixture.oracle.conn.blocking_lock();
    append_logs_with_authority_sync(
        &conn,
        identity(),
        ConsensusAuthorityProfile::FixedImmutable,
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        FIXED_TEST_PLACEMENT_POLICY,
        entries,
    )
    .unwrap();
    save_committed_with_authority_sync(
        &conn,
        identity(),
        ConsensusAuthorityProfile::FixedImmutable,
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        FIXED_TEST_PLACEMENT_POLICY,
        entries.last().map(|entry| entry.log_id),
    )
    .unwrap();
    apply_entries_with_authority_sync(
        &conn,
        identity(),
        &fixture.oracle.caps,
        ConsensusAuthorityProfile::FixedImmutable,
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        FIXED_TEST_PLACEMENT_POLICY,
        entries.to_vec(),
    )
    .unwrap()
}

#[test]
fn native_detached_application_allows_queue_snapshot_and_relocation_then_retries_exactly() {
    for cold in [false, true] {
        let gate = Gate::new(Point::BeforeNativeApplyPublish, 2);
        let fixture = Fixture::with_control(Limits::default(), gate.control());
        let first = fenced_transition_v2_request(0xB1, 1, "native-detached-application");
        fixture.parity(&[formation(), activation(1, first.clone(), timestamp(1))]);
        if cold {
            fixture.wal.checkpoint().unwrap();
            until(|| {
                fixture
                    .wal
                    .native_cold_counts_for_test()
                    .is_ok_and(|counts| counts == [1, 1, 2])
            });
        }
        let second = sdk741_component_request(Sdk741Payload::Create, 2, 0, None);
        let entries = [
            fenced_transition_v2_entry(2, first.clone(), timestamp(2)),
            fenced_transition_v2_entry(3, second.clone(), timestamp(3)),
        ];
        fixture.append_commit(&entries);
        let (applied, candidate) = std::thread::scope(|scope| {
            let applying = scope.spawn(|| fixture.wal.native_apply_committed(&entries));
            gate.entered();
            assert_eq!(
                fixture
                    .wal
                    .with_native_read(|state| Ok(state.applied()))
                    .unwrap(),
                Some(log_id(1))
            );
            assert_eq!(
                status(&fixture.wal, &second),
                FencedTransitionV2Status::NotFound
            );
            let tail = Entry {
                log_id: log_id(4),
                payload: EntryPayload::Blank,
            };
            fixture
                .wal
                .submit(append(std::slice::from_ref(&tail)))
                .unwrap()
                .wait()
                .unwrap();
            fixture
                .wal
                .submit(Operation::Barrier)
                .unwrap()
                .wait()
                .unwrap();
            assert_eq!(
                encode_json(&fixture.wal.read(4, 5).unwrap()).unwrap(),
                encode_json(&[tail]).unwrap()
            );
            let meta = opc_consensus::engine::SnapshotMeta {
                last_log_id: Some(log_id(1)),
                last_membership: fixture
                    .wal
                    .with_native_read(|state| Ok(state.membership()))
                    .unwrap(),
                snapshot_id: fixture.wal.native_snapshot_id().unwrap(),
            };
            let candidate = (
                meta,
                format!("snapshot-{}.opc", uuid::Uuid::new_v4()),
                [0xB2; 32],
                100,
            );
            fixture
                .wal
                .native_publish_snapshot(candidate.clone())
                .unwrap();
            until(|| {
                fixture
                    .wal
                    .native_cold_counts_for_test()
                    .is_ok_and(|counts| counts == [1, 1, 5])
            });
            assert_eq!(
                fixture
                    .wal
                    .with_native_read(|state| Ok(state.current_snapshot()))
                    .unwrap(),
                Some(candidate.clone())
            );
            gate.release();
            (applying.join().unwrap().unwrap(), candidate)
        });
        assert_eq!(
            gate.hits.load(Ordering::SeqCst),
            3,
            "one initial apply, one stale preparation and one exact retry"
        );
        let oracle = oracle_apply(&fixture, &entries);
        assert_eq!(
            encode_json(&applied.responses).unwrap(),
            encode_json(&oracle.responses).unwrap()
        );
        assert_eq!(
            encode_json(&applied.notifications).unwrap(),
            encode_json(&oracle.notifications).unwrap()
        );
        assert_eq!(
            applied.notifications.len(),
            1,
            "retry publishes the business effect once"
        );
        let first_status = status(&fixture.wal, &first);
        let second_status = status(&fixture.wal, &second);
        assert!(matches!(
            second_status,
            FencedTransitionV2Status::Recorded(_)
        ));
        fixture.wal.checkpoint().unwrap();
        let reopened = fixture.reopened();
        assert_eq!(status(&reopened, &first), first_status);
        assert_eq!(status(&reopened, &second), second_status);
        assert_eq!(
            reopened
                .with_native_read(|state| Ok(state.current_snapshot()))
                .unwrap(),
            Some(candidate)
        );
        assert_eq!(
            reopened
                .with_native_read(|state| Ok(state.applied()))
                .unwrap(),
            Some(log_id(3))
        );
        assert_eq!(reopened.read(4, 5).unwrap().len(), 1);
        reopened.shutdown().unwrap();
    }
}

#[test]
fn native_detached_application_cannot_publish_after_writer_closes() {
    let gate = Gate::new(Point::BeforeNativeApplyPublish, 2);
    let fixture = Fixture::with_control(Limits::default(), gate.control());
    let first = fenced_transition_v2_request(0xB3, 1, "native-detached-close");
    fixture.parity(&[formation(), activation(1, first.clone(), timestamp(1))]);
    let second = sdk741_component_request(Sdk741Payload::Create, 2, 0, None);
    let entries = [fenced_transition_v2_entry(2, second.clone(), timestamp(2))];
    fixture.append_commit(&entries);
    std::thread::scope(|scope| {
        let applying = scope.spawn(|| fixture.wal.native_apply_committed(&entries));
        gate.entered();
        fixture.wal.shutdown().unwrap();
        gate.release();
        assert!(applying.join().unwrap().is_err());
    });
    assert_eq!(
        fixture
            .wal
            .with_native_read(|state| Ok(state.applied()))
            .unwrap(),
        Some(log_id(1))
    );
    assert_eq!(
        status(&fixture.wal, &second),
        FencedTransitionV2Status::NotFound
    );
    assert!(fixture.wal.native_apply_committed(&entries).is_err());
    let reopened = fixture.reopened();
    assert!(matches!(
        status(&reopened, &first),
        FencedTransitionV2Status::Recorded(_)
    ));
    assert!(
        matches!(
            status(&reopened, &second),
            FencedTransitionV2Status::Recorded(_)
        ),
        "the exact durable but unapplied commit is replayed on reopen"
    );
    assert_eq!(
        reopened
            .with_native_read(|state| Ok(state.applied()))
            .unwrap(),
        Some(log_id(2))
    );
    reopened.shutdown().unwrap();
}
