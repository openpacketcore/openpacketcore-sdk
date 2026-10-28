use super::*;
use crate::fenced_mutation_roster_executor::{RecoveryLookup, RecoveryRequestInput};
use crate::fenced_mutation_roster_storage::{
    prepare_production_retirement, retired_admission_witness_fence_for_test as witness_fence,
    ProductionRetirementPrefix,
};

fn retired_v2(
    path: &Path,
) -> (
    crate::consensus::types::RosterV2PersistenceFixture,
    Timestamp,
) {
    let signed = crate::consensus::types::roster_v2_aborted_persistence_fixture();
    initialize_protected_roster_v2_recovery_fixture(
        path,
        ProtectedRosterV2RecoveryFixtureState::Aborted,
    )
    .unwrap();
    let due = v2_persistence_logical_time()
        .add_seconds(24 * 60 * 60)
        .unwrap();
    let backend = SqliteSessionBackend::open(path).unwrap();
    let conn = backend.conn.blocking_lock();
    let origin = *expected_members().first().unwrap();
    let entries = [3, 4]
        .into_iter()
        .map(|index| Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, origin), index),
            payload: EntryPayload::Normal(SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity: signed.identity,
                request_id: SessionConsensusRequestId::from_bytes(
                    (0xE000 + u128::from(index)).to_be_bytes(),
                ),
                logical_time: due,
                intent: SessionMutationIntent::Authorized {
                    origin,
                    authority_identity: signed.identity,
                    mutation: Box::new(SessionMutationIntent::AdvanceLogicalTime),
                },
            }),
        })
        .collect::<Vec<_>>();
    append_logs_sync(&conn, signed.identity, &entries).unwrap();
    save_committed_sync(
        &conn,
        signed.identity,
        entries.last().map(|entry| entry.log_id),
    )
    .unwrap();
    let applied = apply_entries_sync(&conn, signed.identity, &backend.caps, entries).unwrap();
    assert!(applied
        .responses
        .iter()
        .all(|response| response.result.is_ok()));
    assert_eq!(count(&conn, "consensus_protected_roster_v2_admissions"), 0);
    assert_eq!(count(&conn, "consensus_protected_roster_floors"), 0);
    assert_eq!(
        count(&conn, "consensus_protected_roster_retirement_cursors"),
        0
    );
    assert_eq!(
        protected_roster_read_witness_sync(&conn, signed.identity)
            .unwrap()
            .unwrap()
            .retired_terminal_sequence(),
        2
    );
    (signed, due)
}

fn count(conn: &Connection, table: &str) -> i64 {
    conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })
    .unwrap()
}

fn authority(scope: crate::fenced_mutation_roster::Scope, guard: &LeaseGuard) -> AuthorityBinding {
    AuthorityBinding::from_consensus_parts(
        scope.digest(),
        guard.key().clone(),
        guard.owner().clone(),
        guard.fence(),
        AuthorityLeaseMetadata::new(
            guard.credential_id(),
            Generation::new(1),
            guard.acquired_at(),
            guard.expires_at(),
        ),
    )
    .unwrap()
}

fn recovery(
    signed: &crate::consensus::types::RosterV2PersistenceFixture,
    original: u64,
    successor: AuthorityBinding,
) -> RecoveryRequest {
    RecoveryRequest::new(RecoveryRequestInput::new(
        RecoveryLookup::new(
            signed.admission.scope(),
            RosterId::from_bytes([0xE1; 16]).unwrap(),
        ),
        signed.authority.owner().clone(),
        FenceToken::new(original),
        successor,
    ))
    .and_then(|request| request.bind_original_key(signed.authority.key().clone()))
    .unwrap()
}

fn successor_after_new_absence(
    conn: &Connection,
    signed: &crate::consensus::types::RosterV2PersistenceFixture,
    due: Timestamp,
) -> (LeaseGuard, Timestamp) {
    let absent_original = crate::sqlite::lease::acquire_sync(
        conn,
        signed.authority.key(),
        signed.authority.owner().clone(),
        Duration::from_secs(60),
        due,
    )
    .unwrap();
    assert_eq!(
        absent_original.fence().get(),
        signed.authority.fence().get() + 1
    );
    assert_eq!(
        count(conn, "consensus_protected_roster_v2_admissions"),
        0,
        "the newly acquired original lease never submitted an admission"
    );
    let now = due.add_seconds(61).unwrap();
    let successor = crate::sqlite::lease::acquire_sync(
        conn,
        signed.authority.key(),
        OwnerId::new("witness-successor").unwrap(),
        Duration::from_secs(60),
        now,
    )
    .unwrap();
    assert!(successor.fence() > absent_original.fence());
    (successor, now)
}

#[test]
fn retired_admission_witness_sqlite_last_partition_survives_cold_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("retired.sqlite");
    let (signed, _) = retired_v2(&path);
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let conn = backend.conn.blocking_lock();
    assert_eq!(count(&conn, "consensus_protected_roster_v2_admissions"), 0);
    assert_eq!(count(&conn, "consensus_protected_roster_floors"), 0);
    let witness = protected_roster_read_witness_sync(&conn, signed.identity)
        .unwrap()
        .unwrap();
    assert_eq!(
        witness_fence(witness),
        Some(signed.authority.fence().get()),
        "cold reopen of an empty ledger must retain the last removed original fence"
    );
}

#[test]
fn retired_admission_witness_sqlite_above_maximum_remains_verified_missing() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("above.sqlite");
    let (signed, due) = retired_v2(&path);
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let conn = backend.conn.blocking_lock();
    let (successor, now) = successor_after_new_absence(&conn, &signed, due);
    let request = recovery(
        &signed,
        signed.authority.fence().get() + 1,
        authority(signed.admission.scope(), &successor),
    );
    assert!(matches!(read_protected_roster_v2_recovery_sync(&conn, signed.identity, &request, now).unwrap(), ProtectedRosterV2ReadResult::Missing),
        "unrelated history retired at fence 9 must not make never-committed original fence 10 inconclusive");
}

#[test]
fn retired_admission_witness_sqlite_below_and_equal_are_inconclusive_controls() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("below-equal.sqlite");
    let (signed, due) = retired_v2(&path);
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let conn = backend.conn.blocking_lock();
    let (successor, now) = successor_after_new_absence(&conn, &signed, due);
    for original in [
        signed.authority.fence().get() - 1,
        signed.authority.fence().get(),
    ] {
        let request = recovery(
            &signed,
            original,
            authority(signed.admission.scope(), &successor),
        );
        assert!(matches!(
            read_protected_roster_v2_recovery_sync(&conn, signed.identity, &request, now).unwrap(),
            ProtectedRosterV2ReadResult::HistoryUnavailable
        ));
    }
}

#[test]
fn retired_admission_witness_sqlite_missing_witness_never_means_virgin_history() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing-witness.sqlite");
    let (signed, due) = retired_v2(&path);
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let conn = backend.conn.blocking_lock();
    let (successor, now) = successor_after_new_absence(&conn, &signed, due);
    let request = recovery(
        &signed,
        signed.authority.fence().get(),
        authority(signed.admission.scope(), &successor),
    );
    assert!(matches!(
        read_protected_roster_v2_recovery_sync(&conn, signed.identity, &request, now).unwrap(),
        ProtectedRosterV2ReadResult::HistoryUnavailable
    ));
    assert_eq!(
        conn.execute("DELETE FROM consensus_protected_roster_witness", [])
            .unwrap(),
        1
    );
    assert!(
        read_protected_roster_v2_recovery_sync(&conn, signed.identity, &request, now).is_err(),
        "loss of the persisted witness must fail closed before an absent result is classified"
    );
    assert!(
        activate_protected_roster_profile_v2_scope_sync(
            &conn,
            signed.identity,
            signed.identity,
            &expected_members(),
            crate::fenced_mutation_roster::Profile::v2().digest(),
        )
        .is_err(),
        "reactivation cannot reconstruct lost history as zero"
    );
    assert!(protected_roster_read_witness_sync(&conn, signed.identity)
        .unwrap()
        .is_none());
    assert!(validate_protected_roster_state_sync(&conn, signed.identity).is_err());
}

#[test]
fn retired_admission_witness_sqlite_empty_snapshot_rejects_regressed_maximum() {
    let directory = tempfile::tempdir().unwrap();
    let local_path = directory.path().join("local.sqlite");
    let incoming_path = directory.path().join("incoming.sqlite");
    retired_v2(&local_path);
    retired_v2(&incoming_path);
    let backend = SqliteSessionBackend::open(&local_path).unwrap();
    let conn = backend.conn.blocking_lock();
    conn.execute(
        "ATTACH DATABASE ?1 AS consensus_incoming",
        [incoming_path.to_str().unwrap()],
    )
    .unwrap();
    let local = protected_roster_snapshot_witness_sync(&conn, ProtectedRosterSnapshotSchema::Local)
        .unwrap()
        .unwrap();
    let incoming =
        protected_roster_snapshot_witness_sync(&conn, ProtectedRosterSnapshotSchema::Incoming)
            .unwrap()
            .unwrap();
    assert!(
        validate_attached_snapshot_protected_roster_floors_and_cursors(
            &conn,
            Some(&local),
            Some(&incoming)
        )
        .is_ok()
    );
    let mut value = serde_json::to_value(incoming.witness).unwrap();
    value["highest_retired_admission_fence"] = 8.into();
    let regressed = ProtectedRosterSnapshotWitness {
        configuration_epoch: incoming.configuration_epoch,
        witness: serde_json::from_value(value).unwrap(),
    };
    assert!(
        validate_attached_snapshot_protected_roster_floors_and_cursors(
            &conn,
            Some(&local),
            Some(&regressed)
        )
        .is_err()
    );
    assert!(
        validate_attached_snapshot_protected_roster_floors_and_cursors(&conn, Some(&local), None)
            .is_err()
    );
}

fn retired_v1(alternate_adapter: bool) -> GlobalChargeWitness {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let conn = backend.conn.blocking_lock();
    initialize_schema(&conn, identity(), &expected_members()).unwrap();
    activate_protected_roster_schema_sync(&conn).unwrap();
    let at = Timestamp::from_str("2026-01-01T00:00:00Z").unwrap();
    let record = retirement_fixture_retained(0x31, 1, 7, at);
    write_retirement_fixture_record(&conn, &record, at);
    let (floor, _) = write_retirement_fixture_floor(&conn, record.binding());
    write_retirement_fixture_witness(&conn, std::slice::from_ref(&record));
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    maintain_due_protected_roster_reclaim_sync(
        &conn,
        identity(),
        at.add_seconds(24 * 60 * 60).unwrap(),
    )
    .unwrap();
    if alternate_adapter {
        let row = protected_roster_read_record_sync(&conn, identity(), record.binding())
            .unwrap()
            .unwrap()
            .into_record();
        let next = floor.advance_to(row.binding().history_epoch()).unwrap();
        let selected = vec![(row.binding(), row)];
        let witness = protected_roster_read_witness_sync(&conn, identity())
            .unwrap()
            .unwrap();
        let plan = prepare_production_retirement(
            ProductionRetirementPrefix::new(floor, next, &selected, true, true).unwrap(),
            floor,
            next,
            None,
            witness,
            GlobalChargeBudget::production(),
            ChargeProfile::v1(),
        )
        .unwrap();
        SqliteProductionReservationTransactionAdapter {
            conn: &conn,
            identity: identity(),
            admission_command: None,
            terminal_authority: None,
        }
        .compare_and_apply_production(plan)
        .unwrap();
    } else {
        assert!(retire_protected_rosters_sync(&conn, identity()).unwrap());
    }
    conn.execute_batch("COMMIT").unwrap();
    assert_eq!(count(&conn, "consensus_protected_roster_rows"), 0);
    assert_eq!(count(&conn, "consensus_protected_roster_admissions"), 0);
    assert_eq!(count(&conn, "consensus_protected_roster_floors"), 0);
    protected_roster_read_witness_sync(&conn, identity())
        .unwrap()
        .unwrap()
}

#[test]
fn retired_admission_witness_sqlite_v1_parent_and_child_deletion_advance_witness() {
    assert_eq!(
        witness_fence(retired_v1(false)),
        Some(1),
        "V1 parent/child removal must contribute to the same original-fence maximum"
    );
}

#[test]
fn retired_admission_witness_sqlite_alternate_transaction_deletion_advances_witness() {
    assert_eq!(
        witness_fence(retired_v1(true)),
        Some(1),
        "the alternate SQLite row-delete adapter must preserve retired original authority"
    );
}

#[test]
fn retired_admission_witness_later_expected_fence_lease_can_remain_below_retirement_control() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lease-order.sqlite");
    let (signed, due) = retired_v2(&path);
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let conn = backend.conn.blocking_lock();
    let mut low_key = signed.authority.key().clone();
    low_key.stable_id = StableId::new(Bytes::from_static(b"later-low-fence")).unwrap();
    let low = crate::sqlite::lease::acquire_exact_sync(
        &conn,
        &low_key,
        OwnerId::new("later-low-owner").unwrap(),
        FenceToken::new(0),
        Duration::from_secs(60),
        due,
    )
    .unwrap();
    assert_eq!(low.fence().get(), 1);
    assert!(low.fence() < signed.authority.fence());
    let later = due.add_seconds(61).unwrap();
    let successor = crate::sqlite::lease::acquire_exact_sync(
        &conn,
        &low_key,
        OwnerId::new("later-low-successor").unwrap(),
        low.fence(),
        Duration::from_secs(60),
        later,
    )
    .unwrap();
    assert_eq!(successor.fence().get(), 2);
    let request = RecoveryRequest::new(RecoveryRequestInput::new(
        RecoveryLookup::new(
            signed.admission.scope(),
            RosterId::from_bytes([0xE2; 16]).unwrap(),
        ),
        low.owner().clone(),
        low.fence(),
        authority(signed.admission.scope(), &successor),
    ))
    .and_then(|request| request.bind_original_key(low_key))
    .unwrap();
    assert!(matches!(
        read_protected_roster_v2_recovery_sync(&conn, signed.identity, &request, later).unwrap(),
        ProtectedRosterV2ReadResult::HistoryUnavailable
    ));
    let ordinary = crate::sqlite::lease::acquire_sync(
        &conn,
        signed.authority.key(),
        OwnerId::new("later-global-owner").unwrap(),
        Duration::from_secs(60),
        later,
    )
    .unwrap();
    assert!(ordinary.fence() > signed.authority.fence(), "ordinary acquisition uses the global frontier; expected-fence acquisition uses the key frontier");
}

#[test]
fn retired_admission_witness_sqlite_snapshot_replacement_preserves_history_after_reopen() {
    let directory = tempfile::tempdir().unwrap();
    let source_path = directory.path().join("source.sqlite");
    let target_path = directory.path().join("target.sqlite");
    let snapshot_path = directory.path().join("snapshot.sqlite");
    let (signed, due) = retired_v2(&source_path);
    initialize_protected_roster_v2_recovery_fixture(
        &target_path,
        ProtectedRosterV2RecoveryFixtureState::Aborted,
    )
    .unwrap();
    let source = SqliteSessionBackend::open(&source_path).unwrap();
    let (last_log_id, last_membership) = build_snapshot_database_sync(
        &source.conn.blocking_lock(),
        signed.identity,
        &snapshot_path,
    )
    .unwrap();
    let meta = opc_consensus::engine::SnapshotMeta {
        last_log_id,
        last_membership,
        snapshot_id: "retired-admission-witness".into(),
    };
    {
        let target = SqliteSessionBackend::open(&target_path).unwrap();
        let conn = target.conn.blocking_lock();
        // Replacement may omit only a locally compacted terminal. Preserve
        // the real first maintenance entry; the source has also retired it.
        let origin = *expected_members().first().unwrap();
        let entries = vec![Entry {
            log_id: LogId::new(CommittedLeaderId::new(1, origin), 3),
            payload: EntryPayload::Normal(SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity: signed.identity,
                request_id: SessionConsensusRequestId::from_bytes(0xE003_u128.to_be_bytes()),
                logical_time: due,
                intent: SessionMutationIntent::Authorized {
                    origin,
                    authority_identity: signed.identity,
                    mutation: Box::new(SessionMutationIntent::AdvanceLogicalTime),
                },
            }),
        }];
        append_logs_sync(&conn, signed.identity, &entries).unwrap();
        save_committed_sync(
            &conn,
            signed.identity,
            entries.last().map(|entry| entry.log_id),
        )
        .unwrap();
        let applied = apply_entries_sync(&conn, signed.identity, &target.caps, entries).unwrap();
        assert!(applied
            .responses
            .iter()
            .all(|response| response.result.is_ok()));
        assert_eq!(count(&conn, "consensus_protected_roster_v2_admissions"), 1);
        let canonical: Vec<u8> = conn
            .query_row(
                "SELECT canonical_record FROM consensus_protected_roster_v2_admissions",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(matches!(
            ProductionReservationRecordV2::from_canonical_bytes(&canonical)
                .unwrap()
                .state(),
            ProductionReservationStateV2::Tombstone
        ));
        install_snapshot_database_sync(
            &conn,
            signed.identity,
            &snapshot_path,
            &meta,
            "snapshot-00000000-0000-4000-8000-000000001306.opc",
            [0xE6; 32],
            std::fs::metadata(&snapshot_path).unwrap().len(),
        )
        .unwrap();
        assert_eq!(
            count(&conn, "consensus_protected_roster_v2_admissions"),
            0,
            "validated snapshot replacement deletes the exact previously retained target slot"
        );
    }
    let target = SqliteSessionBackend::open(&target_path).unwrap();
    let conn = target.conn.blocking_lock();
    assert_eq!(count(&conn, "consensus_protected_roster_v2_admissions"), 0);
    assert_eq!(count(&conn, "consensus_protected_roster_floors"), 0);
    assert_eq!(witness_fence(protected_roster_read_witness_sync(&conn, signed.identity).unwrap().unwrap()), Some(signed.authority.fence().get()),
        "snapshot install and a subsequent backend reopen must preserve original retirement authority");
}
