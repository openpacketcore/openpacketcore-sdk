use super::*;
use crate::consensus::native::lifecycle_tests as native_fixture;

fn maintenance(
    index: u64,
    history: FencedTransitionV2HistoryState,
    now: Timestamp,
) -> Entry<SessionRaftTypeConfig> {
    Entry {
        log_id: log_id(index),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(),
            request_id: SessionConsensusRequestId::from_bytes([0xED; 16]),
            logical_time: now,
            intent: SessionMutationIntent::MaintainFencedTransitionV2History {
                expected_generation: history.generation(),
                expected_active_epoch: history.active_epoch(),
                expected_retired_through: history.retired_through().map_or(0, |epoch| epoch.get()),
                expected_bound_entries: history.bound_entries() as u64,
            },
        }),
    }
}

fn history_parity(wal: &Wal, oracle: &SqliteSessionBackend) {
    let exported = wal.native_export_snapshot().unwrap();
    let conn = oracle.conn.blocking_lock();
    for table in [
        "consensus_fenced_transition_v2_history",
        "consensus_fenced_transition_v2_receipts",
        "consensus_request_outcomes",
        "session_replication_log",
    ] {
        assert_eq!(
            super::ordinary::rows(&exported, table),
            super::ordinary::rows(&conn, table),
            "complete maintenance table {table}"
        );
    }
    validate_fenced_transition_v2_receipts_sync(&exported, identity()).unwrap();
    assert_eq!(wal.native_sql_fallback_count().unwrap(), 0);
    super::roster::export::import::rootless_roundtrip(&conn);
}

#[test]
fn native_history_maintenance_noop_retry_stale_and_selected_reopen_match_sql() {
    let fixture = Fixture::new();
    fixture.parity(&[formation()]);
    let absent = fixture
        .wal
        .with_native_read(|state| state.history_state())
        .unwrap();
    let rejected = fixture.parity(&[maintenance(1, absent, timestamp(1))]);
    assert_eq!(
        rejected.responses[0].result,
        Err(StoreError::FencedTransitionHistoryEpochNotActive)
    );
    let request = fenced_transition_v2_request(0xED, 1, "native-maintenance");
    let original = fixture.parity(&[activation(2, request, timestamp(2))]);
    let history = fixture
        .wal
        .with_native_read(|state| state.history_state())
        .unwrap();
    let noop = fixture.parity(&[
        maintenance(3, history, timestamp(3)),
        maintenance(4, history, timestamp(4)),
    ]);
    assert!(noop.notifications.is_empty());
    assert!(noop
        .responses
        .iter()
        .all(|response| matches!(response.result, Ok(SessionMutationOutcome::Unit))));
    assert_eq!(
        noop.responses[1].sequence,
        original.responses[0].sequence + 2,
        "an exact repeated raw maintenance command is not a generic retry"
    );
    assert_eq!(
        fixture
            .wal
            .with_native_read(|state| state.history_state())
            .unwrap(),
        history
    );
    for field in 0..4 {
        let mut stale = maintenance(5 + field, history, timestamp(5));
        let EntryPayload::Normal(command) = &mut stale.payload else {
            unreachable!()
        };
        let SessionMutationIntent::MaintainFencedTransitionV2History {
            expected_generation,
            expected_active_epoch,
            expected_retired_through,
            expected_bound_entries,
        } = &mut command.intent
        else {
            unreachable!()
        };
        match field {
            0 => *expected_generation += 1,
            1 => *expected_active_epoch = Some(FencedTransitionV2HistoryEpoch::new(2).unwrap()),
            2 => *expected_retired_through = 1,
            3 => *expected_bound_entries = 0,
            _ => unreachable!(),
        }
        let response = fixture.parity(&[stale]);
        assert_eq!(
            response.responses[0].result,
            Err(StoreError::FencedTransitionHistoryEpochNotActive)
        );
        assert_eq!(response.responses[0].sequence, noop.responses[1].sequence);
    }
    history_parity(&fixture.wal, &fixture.oracle);
    fixture.wal.checkpoint().unwrap();
    let reopened = fixture.reopened();
    history_parity(&reopened, &fixture.oracle);
    assert_eq!(
        reopened.native_log_read(0, None, Some(64)).unwrap().len(),
        9
    );
    reopened.shutdown().unwrap();
}

fn direct_parity(
    storage: &mut NativeStorage,
    oracle: &SqliteSessionBackend,
    entries: &[Entry<SessionRaftTypeConfig>],
) -> AppliedBatch {
    let conn = oracle.conn.blocking_lock();
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
    let expected = apply_entries_with_authority_sync(
        &conn,
        identity(),
        &oracle.caps,
        ConsensusAuthorityProfile::FixedImmutable,
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        FIXED_TEST_PLACEMENT_POLICY,
        entries.to_vec(),
    )
    .unwrap();
    storage
        .log
        .project(&append(entries), &storage.business, None)
        .unwrap();
    storage
        .log
        .project(
            &Operation::Committed(entries.last().map(|entry| entry.log_id)),
            &storage.business,
            None,
        )
        .unwrap();
    let actual = storage.business.apply(entries).unwrap();
    assert_eq!(
        encode_json(&actual.responses).unwrap(),
        encode_json(&expected.responses).unwrap()
    );
    assert_eq!(
        encode_json(&actual.notifications).unwrap(),
        encode_json(&expected.notifications).unwrap()
    );
    assert_eq!(
        storage.business.history_state().unwrap(),
        read_fenced_transition_v2_history_state_sync(&conn, identity()).unwrap()
    );
    expected
}

#[test]
fn native_history_full_epoch_rotation_preserves_retained_replay_and_per_epoch_ordinals() {
    let oracle = SqliteSessionBackend::in_memory().unwrap();
    initialize_schema_with_profile(
        &oracle.conn.blocking_lock(),
        identity(),
        &fixed_members(),
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    let mut storage = NativeStorage::empty(identity(), fixed_members()).unwrap();
    let request = fenced_transition_v2_request(0xEE, 1, "native-rotation");
    let initial = direct_parity(
        &mut storage,
        &oracle,
        &[formation(), activation(1, request.clone(), timestamp(1))],
    );
    let response = initial.responses[1].clone();
    let until = response
        .logical_time
        .unwrap()
        .add_seconds(FENCED_TRANSITION_OUTCOME_RETENTION.as_secs() as i64)
        .unwrap();
    let full = FencedTransitionV2HistoryState::new(
        Some(FencedTransitionV2HistoryEpoch::new(1).unwrap()),
        None,
        None,
        0,
        0,
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES,
        0,
    )
    .unwrap();
    {
        let conn = oracle.conn.blocking_lock();
        conn.execute_batch("BEGIN IMMEDIATE").unwrap();
        insert_v2_recorded_rows_in_epoch(
            &conn,
            1,
            2,
            FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - 1,
            &response,
            until,
        );
        conn.execute(
            "UPDATE consensus_fenced_transition_v2_history SET current_bound_count=?1",
            [FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u64],
        )
        .unwrap();
        conn.execute_batch("COMMIT").unwrap();
        validate_fenced_transition_v2_receipts_sync(&conn, identity()).unwrap();
    }
    native_fixture::seed(
        &mut storage,
        full,
        timestamp(1),
        Some(response.clone()),
        true,
    );
    direct_parity(&mut storage, &oracle, &[maintenance(2, full, timestamp(2))]);
    let rotated = storage.business.history_state().unwrap();
    assert_eq!(rotated.active_epoch().unwrap().get(), 2);
    assert_eq!(rotated.bound_entries(), 0);
    assert_eq!(rotated.generation(), 1);
    let replay = direct_parity(
        &mut storage,
        &oracle,
        &[fenced_transition_v2_entry(3, request.clone(), timestamp(3))],
    );
    assert_eq!(
        replay.responses[0], response,
        "closed unretired epoch keeps the complete original response"
    );
    let next = FencedTransitionV2Request::new(
        FencedTransitionV2HistoryEpoch::new(2).unwrap(),
        crate::FencedTransitionV2CallerNonce::from_bytes([0xEF; 16]),
        request.lease().clone(),
        request.mutation().clone(),
    )
    .unwrap();
    direct_parity(
        &mut storage,
        &oracle,
        &[fenced_transition_v2_entry(4, next, timestamp(4))],
    );
    assert_eq!(
        storage.business.history_state().unwrap().bound_entries(),
        1,
        "successor epoch starts at ordinal one"
    );
    storage.validate_image().unwrap();
}

#[test]
fn native_history_partial_reclaim_matches_sql_exact_cursor_and_snapshot_columns() {
    let oracle = SqliteSessionBackend::in_memory().unwrap();
    initialize_schema_with_profile(
        &oracle.conn.blocking_lock(),
        identity(),
        &fixed_members(),
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    let mut storage = NativeStorage::empty(identity(), fixed_members()).unwrap();
    let request = fenced_transition_v2_request(0xEF, 1, "native-reclaim");
    direct_parity(
        &mut storage,
        &oracle,
        &[formation(), activation(1, request, timestamp(1))],
    );
    let remaining = 2 * FENCED_TRANSITION_V2_RECLAIM_BATCH + 1;
    let cursor = FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES - remaining;
    let history = FencedTransitionV2HistoryState::new(
        Some(FencedTransitionV2HistoryEpoch::new(2).unwrap()),
        Some(FencedTransitionV2HistoryEpoch::new(1).unwrap()),
        Some(FencedTransitionV2HistoryEpoch::new(1).unwrap()),
        remaining,
        1,
        0,
        cursor as u64,
    )
    .unwrap();
    {
        let conn = oracle.conn.blocking_lock();
        conn.execute_batch("BEGIN IMMEDIATE; DELETE FROM consensus_fenced_transition_v2_receipts")
            .unwrap();
        insert_v2_tombstone_rows(&conn, cursor as u64 + 1, remaining, timestamp(10));
        conn.execute("UPDATE consensus_fenced_transition_v2_history SET active_epoch=2,retired_through_epoch=1,reclaim_epoch=1,reclaim_cursor_ordinal=?1,reclaim_remaining=?2,reclaimed_entries=?1,generation=1,current_bound_count=0",params![cursor as u64,remaining as u64]).unwrap();
        conn.execute(
            "UPDATE consensus_machine SET logical_time=?1",
            [ops::format_rfc3339_normalized(timestamp(10))],
        )
        .unwrap();
        conn.execute_batch("COMMIT").unwrap();
        validate_fenced_transition_v2_receipts_sync(&conn, identity()).unwrap();
    }
    native_fixture::seed(&mut storage, history, timestamp(10), None, false);
    for index in 2..=4 {
        let entry = maintenance(
            index,
            storage.business.history_state().unwrap(),
            timestamp(u8::try_from(10 + index).unwrap()),
        );
        let applied = direct_parity(&mut storage, &oracle, &[entry]);
        assert!(applied.notifications.is_empty());
        let exported = SqliteSessionBackend::in_memory().unwrap();
        let output = exported.conn.blocking_lock();
        initialize_schema_with_profile(
            &output,
            identity(),
            &fixed_members(),
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .unwrap();
        storage
            .export_cold_snapshot_checked(&output, &|| Ok(()))
            .unwrap();
        let conn = oracle.conn.blocking_lock();
        for table in [
            "consensus_fenced_transition_v2_history",
            "consensus_fenced_transition_v2_receipts",
            "consensus_request_outcomes",
            "session_replication_log",
        ] {
            assert_eq!(
                super::ordinary::rows(&output, table),
                super::ordinary::rows(&conn, table),
                "exact reclaim state at index {index}, table {table}"
            );
        }
        validate_fenced_transition_v2_receipts_sync(&output, identity()).unwrap();
        super::roster::export::import::rootless_roundtrip(&conn);
    }
    let final_history = storage.business.history_state().unwrap();
    assert_eq!(final_history.reclaim_epoch(), None);
    assert_eq!(final_history.reclaim_remaining(), 0);
    assert_eq!(
        final_history.reclaimed_entries(),
        FENCED_TRANSITION_V2_MAX_HISTORY_ENTRIES as u64
    );
    assert_eq!(final_history.generation(), 4);
}
