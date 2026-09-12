use super::*;
use crate::consensus::types::{
    ConsensusRosterAdmissionOutcome, ConsensusRosterRejection, ConsensusRosterTerminalOutcome,
};
use crate::sqlite::consensus::roster_engine;
use crate::sqlite::consensus::{
    initialize_protected_roster_v2_recovery_fixture, ProtectedRosterV2RecoveryFixtureState,
};
use rusqlite::Connection;

use crate::consensus::native::roster::v1_fixture;
#[path = "changes_tests.rs"]
mod changes_tests;
#[path = "frame_tests.rs"]
mod frame_tests;
#[path = "publication_tests.rs"]
mod publication_tests;
#[path = "row_tests.rs"]
mod row_tests;

fn command(
    signed: &crate::consensus::types::RosterV2PersistenceFixture,
) -> ConsensusRosterAdmissionCommand {
    ConsensusRosterAdmissionCommand::new_with_provenance_and_ingress_request_id_v2(
        signed.admission.clone(),
        signed.authority.clone(),
        signed.admission_ingress.request_id(),
        signed.admission_ingress.clone(),
        signed.admission_provenance.clone(),
    )
    .unwrap()
}

fn predecessor(
    signed: &crate::consensus::types::RosterV2PersistenceFixture,
    record: Option<StoredSessionRecord>,
) -> NativeState {
    let members = [7, 8, 9]
        .into_iter()
        .map(|id| SessionConsensusNodeId::new(id).unwrap())
        .collect();
    let mut state = NativeState::empty(signed.identity, members).unwrap();
    let authority = &signed.authority;
    let guard = LeaseGuard::new(
        authority.key().clone(),
        authority.owner().clone(),
        authority.fence(),
        authority.acquired_at(),
        authority.expires_at(),
        authority.credential_id(),
    );
    state.keys.insert(
        authority.key().clone(),
        SharedRow::new(NativeKeyState {
            record,
            lease: Some(NativeLease::from_guard(&guard).unwrap()),
            fence: authority.fence().get(),
            reserved: false,
        })
        .unwrap(),
    );
    state.frontiers.next_fence = authority.fence().get() + 1;
    state.frontiers.next_credential = authority.credential_id() + 1;
    state.frontiers.logical_time = Some(authority.acquired_at().add_seconds(1).unwrap());
    state.admit_business().unwrap();
    state
}

fn sql_row(conn: &Connection, binding: RequestBindingKey) -> Vec<u8> {
    conn.query_row(
        "SELECT canonical_record FROM consensus_protected_roster_v2_admissions WHERE binding=?1",
        [binding.to_bytes().as_slice()],
        |row| row.get(0),
    )
    .unwrap()
}

fn sql_witness(conn: &Connection) -> GlobalChargeWitness {
    let bytes: Vec<u8> = conn
        .query_row(
            "SELECT canonical_witness FROM consensus_protected_roster_witness WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    GlobalChargeWitness::from_canonical_bytes(&bytes).unwrap()
}

#[test]
fn native_roster_store_v2_q1_q2_and_retries_match_the_signed_sql_ledger() {
    run_v2_sql_ledger(false);
}

fn run_v2_sql_ledger(selected: bool) {
    for established in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("oracle.sqlite");
        let shape = if established {
            ProtectedRosterV2RecoveryFixtureState::Established
        } else {
            ProtectedRosterV2RecoveryFixtureState::Aborted
        };
        initialize_protected_roster_v2_recovery_fixture(&path, shape).unwrap();
        let sql = Connection::open(&path).unwrap();
        let signed = if established {
            crate::consensus::types::roster_v2_persistence_fixture()
        } else {
            crate::consensus::types::roster_v2_aborted_persistence_fixture()
        };
        let state = predecessor(&signed, None);
        let before = postcard::to_allocvec(&state).unwrap();
        let delta = state.prepare(&[]).unwrap();
        let check = || Ok(());
        let mut store =
            Store::new_detached(&delta, &Ledger::empty(), &signed.root, &check).unwrap();
        let mut selected_files = Vec::new();
        let q1 = command(&signed);
        let now = signed.authority.acquired_at().add_seconds(1).unwrap();
        let binding = signed.admission.binding_key(1).unwrap();
        let admitted =
            roster_engine::admit_v2(&mut store, signed.identity, signed.identity, 1, now, &q1)
                .unwrap_or_else(|_| panic!("native signed Q1"));
        assert!(matches!(
            admitted,
            ConsensusRosterAdmissionOutcome::Admitted { .. }
        ));
        assert_eq!(
            store.ledger.index.reservation(signed.authority.key()),
            Some(binding)
        );
        assert!(store.key(signed.authority.key()).reserved);
        let q1_bytes = store.ledger.rows[&binding].canonical().unwrap().to_vec();
        if selected {
            selected_files.extend(row_tests::select_all(&mut store));
        }
        frame_tests::assert_ledger_frames(&store, 1);
        let replay =
            roster_engine::admit_v2(&mut store, signed.identity, signed.identity, 3, now, &q1)
                .unwrap_or_else(|_| panic!("native signed Q1 replay"));
        assert!(matches!(
            replay,
            ConsensusRosterAdmissionOutcome::Replayed { .. }
        ));
        assert_eq!(
            store.hydrate_row(binding).unwrap().unwrap().canonical(),
            q1_bytes
        );
        let (terminal, replication) = roster_engine::terminal_v2(
            &mut store,
            signed.identity,
            signed.identity,
            2,
            2,
            now,
            &signed.terminal_command,
        )
        .unwrap_or_else(|_| panic!("native signed Q2"));
        assert!(matches!(
            terminal,
            ConsensusRosterTerminalOutcome::Committed {
                replayed: false,
                ..
            }
        ));
        assert_eq!(replication.is_some(), established);
        assert_eq!(
            store.ledger.rows[&binding].canonical().unwrap(),
            sql_row(&sql, binding)
        );
        assert!(store.ledger.witness == Some(sql_witness(&sql)));
        assert!(!store.key(signed.authority.key()).reserved);
        assert_eq!(store.ledger.index.reservation(signed.authority.key()), None);
        let current = crate::sqlite::ops::get_raw_sync(&sql, signed.authority.key()).unwrap();
        assert_eq!(store.key(signed.authority.key()).record, current);
        frame_tests::assert_ledger_frames(&store, 2);
        let before_replay = store.ledger.rows[&binding].canonical().unwrap().to_vec();
        if selected {
            selected_files.extend(row_tests::select_all(&mut store));
        }
        let revision = store.restore_revision;
        let (replay, replication) = roster_engine::terminal_v2(
            &mut store,
            signed.identity,
            signed.identity,
            3,
            3,
            now,
            &signed.terminal_command,
        )
        .unwrap_or_else(|_| panic!("native signed Q2 replay"));
        assert!(matches!(
            replay,
            ConsensusRosterTerminalOutcome::Committed { replayed: true, .. }
        ));
        assert!(replication.is_none());
        assert_eq!(
            store.hydrate_row(binding).unwrap().unwrap().canonical(),
            before_replay
        );
        assert_eq!(store.restore_revision, revision);
        let (ledger, keys, _) = store.finish();
        let rebuilt = Ledger::admit_detached(
            &signed.root,
            &fixed_scope(signed.identity, &state.members),
            3,
            Some(3),
            ledger.rows.values().cloned(),
            ledger
                .partitions
                .iter()
                .map(|(key, row)| (*key, (**row).clone())),
            ledger.witness,
            |key| Ok(keys.get(key).and_then(|row| row.record.clone())),
            &check,
        )
        .unwrap();
        assert_eq!(rebuilt.index.len(), 1);
        assert_eq!(rebuilt.index.terminal_prefix(0).unwrap().len(), 1);
        assert_eq!(
            postcard::to_allocvec(&state).unwrap(),
            before,
            "savepoint has not published business state"
        );
    }
}

#[test]
fn native_roster_store_failures_discard_all_staged_business_and_witness_effects() {
    let signed = crate::consensus::types::roster_v2_persistence_fixture();
    let state = predecessor(&signed, None);
    let delta = state.prepare(&[]).unwrap();
    let q1 = command(&signed);
    let now = signed.authority.acquired_at().add_seconds(1).unwrap();
    let binding = signed.admission.binding_key(1).unwrap();
    let mut rejected = Store::new(&delta, &Ledger::empty(), &signed.root).unwrap();
    assert!(matches!(
        roster_engine::admit_v2(
            &mut rejected,
            signed.identity,
            signed.identity,
            1,
            signed.authority.expires_at(),
            &q1
        ),
        Err(ApplyError::Rejected(ConsensusRosterRejection::Authority))
    ));
    let (ledger, keys, revision) = rejected.finish();
    assert_eq!(ledger.index.len(), 0);
    assert!(ledger.witness.is_none());
    assert!(ledger.partitions.is_empty());
    assert!(keys.is_empty());
    assert_eq!(revision, state.frontiers.restore_revision);

    let mut store = Store::new(&delta, &Ledger::empty(), &signed.root).unwrap();
    roster_engine::admit_v2(&mut store, signed.identity, signed.identity, 1, now, &q1)
        .unwrap_or_else(|_| panic!("signed Q1"));
    let baseline = store.ledger.clone();
    let bytes = baseline.rows[&binding].canonical().unwrap().to_vec();
    // A disappeared exact reservation is local divergence, never a replicated
    // capacity/terminal rejection. The evaluator must fail before any Q2 write.
    store.keys.get_mut(signed.authority.key()).unwrap().reserved = false;
    assert!(matches!(
        roster_engine::terminal_v2(
            &mut store,
            signed.identity,
            signed.identity,
            2,
            2,
            now,
            &signed.terminal_command
        ),
        Err(ApplyError::Fatal)
    ));
    assert_eq!(store.ledger.rows[&binding].canonical().unwrap(), bytes);
    assert!(store.ledger.witness == baseline.witness);
    assert!(store.key(signed.authority.key()).record.is_none());
    drop(store);
    assert!(!state.keys[signed.authority.key()].reserved);
    assert!(state.keys[signed.authority.key()].record.is_none());
}

#[test]
fn native_roster_store_v1_admission_compares_and_reserves_the_original_business_row() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("v1-business.sqlite");
    initialize_protected_roster_v2_recovery_fixture(
        &path,
        ProtectedRosterV2RecoveryFixtureState::Established,
    )
    .unwrap();
    let sql = Connection::open(&path).unwrap();
    let signed = crate::consensus::types::roster_v2_persistence_fixture();
    let original = crate::sqlite::ops::get_raw_sync(&sql, signed.authority.key())
        .unwrap()
        .unwrap();
    let state = predecessor(&signed, Some(original.clone()));
    let delta = state.prepare(&[]).unwrap();
    let q1 = carrier::tests::signed_v1_command(&signed);
    let now = signed.authority.acquired_at().add_seconds(1).unwrap();
    let binding = q1.admission().binding_key(3).unwrap();
    let mut store = Store::new(&delta, &Ledger::empty(), &signed.root).unwrap();
    assert!(matches!(
        roster_engine::admit_v1(&mut store, signed.identity, signed.identity, 3, now, &q1),
        Ok(ConsensusRosterAdmissionOutcome::Admitted { .. })
    ));
    assert_eq!(
        store.key(signed.authority.key()).record,
        Some(original.clone())
    );
    assert!(store.key(signed.authority.key()).reserved);
    assert_eq!(
        store.ledger.index.reservation(signed.authority.key()),
        Some(binding)
    );
    assert!(matches!(
        roster_engine::admit_v1(&mut store, signed.identity, signed.identity, 4, now, &q1),
        Ok(ConsensusRosterAdmissionOutcome::Replayed { .. })
    ));
    let ledger = &store.ledger;
    Ledger::admit(
        &signed.root,
        &fixed_scope(signed.identity, &state.members),
        4,
        Some(4),
        ledger.rows.values().cloned(),
        ledger
            .partitions
            .iter()
            .map(|(key, row)| (*key, (**row).clone())),
        ledger.witness,
        |_| Ok(Some(original.clone())),
    )
    .unwrap();
    assert!(Ledger::admit(
        &signed.root,
        &fixed_scope(signed.identity, &state.members),
        4,
        Some(4),
        ledger.rows.values().cloned(),
        ledger
            .partitions
            .iter()
            .map(|(key, row)| (*key, (**row).clone())),
        ledger.witness,
        |_| Ok(None)
    )
    .is_err());
    assert!(store
        .ledger
        .index
        .replaced(binding, None, Some(&store.ledger.rows[&binding]))
        .is_err());
    assert_eq!(store.ledger.index.len(), 1);
}

#[test]
fn native_roster_indexes_preserve_alias_rejection_and_bounded_mixed_history_prefixes() {
    use crate::fenced_mutation_roster_storage::ConsensusMaintenanceTimestamp;
    let signed = crate::consensus::types::roster_v2_persistence_fixture();
    let state = predecessor(&signed, None);
    let delta = state.prepare(&[]).unwrap();
    let mut store = Store::new(&delta, &Ledger::empty(), &signed.root).unwrap();
    let now = signed.authority.acquired_at().add_seconds(1).unwrap();
    roster_engine::admit_v2(
        &mut store,
        signed.identity,
        signed.identity,
        1,
        now,
        &command(&signed),
    )
    .unwrap_or_else(|_| panic!("signed index template"));
    let binding = signed.admission.binding_key(1).unwrap();
    let template = &store.ledger.rows[&binding];
    // Only scalar index mechanics are under test below. These synthetic rows
    // are never admitted as canonical carriers, serialized, or published.
    let make = |number: u64, epoch: u64, state: State| {
        let mut bytes = binding.to_bytes();
        bytes[..8].copy_from_slice(&epoch.to_be_bytes());
        bytes[112..].copy_from_slice(&number.to_be_bytes());
        let mut projection = template.projection.clone();
        projection.profile = if number.is_multiple_of(2) {
            Profile::V1
        } else {
            Profile::V2
        };
        projection.stable_slot[..8].copy_from_slice(&number.to_be_bytes());
        projection.terminal_slot[..8].copy_from_slice(&number.to_be_bytes());
        Row::index_fixture(
            RequestBindingKey::from_bytes(bytes).unwrap(),
            projection,
            Facts {
                state,
                terminalized_at: Some(
                    ConsensusMaintenanceTimestamp::from_consensus_timestamp(now).unwrap(),
                ),
                terminal_sequence: Some(number + 1),
                terminal_raft_log_index: Some(epoch + 1),
            },
        )
        .unwrap()
    };
    let mut index = Index::default();
    for number in 0..1026 {
        let row = make(number, 1, State::Retained);
        index = index.replaced(row.binding, None, Some(&row)).unwrap();
    }
    let partition = ProductionFloorKey::from_binding(binding).unwrap();
    let original = index.clone();
    assert_eq!(index.len(), 1026);
    assert_eq!(index.epoch_count(partition, 1), 1026);
    assert_eq!(index.epoch_count(partition, 9), 0);
    assert_eq!(index.partition_prefix(partition, 1, None).len(), 1025);
    assert_eq!(
        index
            .partition_prefix(partition, 1, Some(make(1023, 1, State::Retained).binding))
            .len(),
        2
    );
    let terminalized_at = ConsensusMaintenanceTimestamp::from_consensus_timestamp(now)
        .unwrap()
        .as_nanos();
    assert_eq!(index.reclaim_prefix(terminalized_at).len(), 1024);
    assert_eq!(index.reclaim_prefix(terminalized_at - 1).len(), 0);
    assert_eq!(index.terminal_prefix(0).unwrap().len(), 1025);
    assert_eq!(index.terminal_prefix(1024).unwrap().len(), 2);
    for number in 0..3 {
        let before = make(number, 1, State::Retained);
        let after = make(number, 1, State::Tombstone);
        index = index
            .replaced(before.binding, Some(&before), Some(&after))
            .unwrap();
    }
    assert_eq!(
        index
            .terminal_prefix(0)
            .unwrap()
            .iter()
            .take_while(|(_, _, state)| *state == State::Tombstone)
            .count(),
        3
    );
    assert_eq!(
        original
            .terminal_prefix(0)
            .unwrap()
            .iter()
            .take_while(|(_, _, state)| *state == State::Tombstone)
            .count(),
        0
    );
    let higher = make(1026, 9, State::Retained);
    index = index.replaced(higher.binding, None, Some(&higher)).unwrap();
    let (first, last) = index.partition_bounds(partition).unwrap();
    assert_eq!(first.history_epoch(), 1);
    assert_eq!(last.history_epoch(), 9);
    assert_eq!(index.epoch_count(partition, 1), 1026);
    assert_eq!(index.epoch_count(partition, 9), 1);
    assert_eq!(
        index
            .partition_prefix(partition, 1, Some(make(1023, 1, State::Retained).binding))
            .len(),
        2
    );
    let mut alias = make(1027, 9, State::Retained);
    alias.projection.stable_slot = higher.projection.stable_slot;
    assert!(index.replaced(alias.binding, None, Some(&alias)).is_err());
    alias = make(1027, 9, State::Retained);
    alias.projection.terminal_slot = higher.projection.terminal_slot;
    assert!(index.replaced(alias.binding, None, Some(&alias)).is_err());
    alias = make(1027, 9, State::Retained);
    alias.facts.terminal_sequence = higher.facts.terminal_sequence;
    assert!(index.replaced(alias.binding, None, Some(&alias)).is_err());
    assert_eq!(index.len(), 1027);
    for number in 0..3 {
        let row = make(number, 1, State::Tombstone);
        index = index.replaced(row.binding, Some(&row), None).unwrap();
    }
    assert_eq!(index.len(), 1024);
    assert_eq!(original.len(), 1026);
    assert_eq!(index.epoch_count(partition, 1), 1023);
    assert_eq!(index.epoch_count(partition, 9), 1);
    assert_eq!(original.epoch_count(partition, 1), 1026);
    assert_eq!(index.terminal_prefix(3).unwrap()[0].0, 4);
}

#[test]
fn native_roster_maintenance_matches_sql_at_retention_and_empty_partition_release() {
    use crate::sqlite::consensus::native_roster_maintenance_fixture;
    for established in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("maintenance-oracle.sqlite");
        let shape = if established {
            ProtectedRosterV2RecoveryFixtureState::Established
        } else {
            ProtectedRosterV2RecoveryFixtureState::Aborted
        };
        initialize_protected_roster_v2_recovery_fixture(&path, shape).unwrap();
        let sql = Connection::open(&path).unwrap();
        let signed = if established {
            crate::consensus::types::roster_v2_persistence_fixture()
        } else {
            crate::consensus::types::roster_v2_aborted_persistence_fixture()
        };
        let state = predecessor(&signed, None);
        let delta = state.prepare(&[]).unwrap();
        let now = signed.authority.acquired_at().add_seconds(1).unwrap();
        let due = now.add_seconds(24 * 60 * 60).unwrap();
        let binding = signed.admission.binding_key(1).unwrap();
        let mut store = Store::new(&delta, &Ledger::empty(), &signed.root).unwrap();
        roster_engine::admit_v2(
            &mut store,
            signed.identity,
            signed.identity,
            1,
            now,
            &command(&signed),
        )
        .unwrap_or_else(|_| panic!("signed maintenance Q1"));
        roster_engine::terminal_v2(
            &mut store,
            signed.identity,
            signed.identity,
            2,
            2,
            now,
            &signed.terminal_command,
        )
        .unwrap_or_else(|_| panic!("signed maintenance Q2"));
        let record = store.key(signed.authority.key()).record;
        let revision = store.restore_revision;
        assert!(!store.maintain_due(due.add_seconds(-1).unwrap()).unwrap());
        assert!(!native_roster_maintenance_fixture(
            &path,
            signed.identity,
            due.add_seconds(-1).unwrap()
        )
        .unwrap());
        assert!(store.ledger.rows[&binding].facts.state == State::Retained);
        assert!(store.maintain_due(due).unwrap());
        assert!(native_roster_maintenance_fixture(&path, signed.identity, due).unwrap());
        assert!(store.ledger.rows[&binding].facts.state == State::Tombstone);
        assert_eq!(
            store.ledger.rows[&binding].canonical().unwrap(),
            sql_row(&sql, binding)
        );
        assert!(store.ledger.witness == Some(sql_witness(&sql)));
        assert_eq!(store.ledger.partitions.len(), 1);
        Ledger::admit(
            &signed.root,
            &fixed_scope(signed.identity, &state.members),
            2,
            Some(2),
            store.ledger.rows.values().cloned(),
            store
                .ledger
                .partitions
                .iter()
                .map(|(key, row)| (*key, (**row).clone())),
            store.ledger.witness,
            |_| Ok(record.clone()),
        )
        .unwrap();
        assert!(store.maintain_due(due).unwrap());
        assert!(native_roster_maintenance_fixture(&path, signed.identity, due).unwrap());
        assert!(store.ledger.rows.is_empty());
        assert!(store.ledger.partitions.is_empty());
        assert_eq!(store.ledger.index.len(), 0);
        assert!(store.ledger.witness == Some(sql_witness(&sql)));
        assert_eq!(store.ledger.witness.unwrap().retired_terminal_sequence(), 2);
        assert_eq!(
            sql.query_row(
                "SELECT COUNT(*) FROM consensus_protected_roster_v2_admissions",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            sql.query_row(
                "SELECT COUNT(*) FROM consensus_protected_roster_floors",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert!(!store.maintain_due(due).unwrap());
        assert!(!native_roster_maintenance_fixture(&path, signed.identity, due).unwrap());
        assert_eq!(store.key(signed.authority.key()).record, record);
        assert_eq!(store.restore_revision, revision);
        assert!(!store.key(signed.authority.key()).reserved);
        Ledger::admit(
            &signed.root,
            &fixed_scope(signed.identity, &state.members),
            2,
            Some(2),
            store.ledger.rows.values().cloned(),
            store
                .ledger
                .partitions
                .iter()
                .map(|(key, row)| (*key, (**row).clone())),
            store.ledger.witness,
            |_| Ok(record.clone()),
        )
        .unwrap();
    }
}

#[test]
fn native_roster_maintenance_streams_atomic_reclaim_and_stops_at_the_next_partition_epoch() {
    let first = crate::consensus::types::roster_v2_aborted_persistence_fixture();
    let second =
        crate::consensus::types::roster_v2_aborted_persistence_fixture_for_history([0x92; 16], 3);
    let state = predecessor(&first, None);
    let delta = state.prepare(&[]).unwrap();
    let now = first.authority.acquired_at().add_seconds(1).unwrap();
    let due = now.add_seconds(24 * 60 * 60).unwrap();
    let mut store = Store::new(&delta, &Ledger::empty(), &first.root).unwrap();
    for (epoch, signed) in [(1, &first), (3, &second)] {
        roster_engine::admit_v2(
            &mut store,
            signed.identity,
            signed.identity,
            epoch,
            now,
            &command(signed),
        )
        .unwrap_or_else(|_| panic!("signed history Q1"));
        roster_engine::terminal_v2(
            &mut store,
            signed.identity,
            signed.identity,
            epoch + 1,
            epoch + 1,
            now,
            &signed.terminal_command,
        )
        .unwrap_or_else(|_| panic!("signed history Q2"));
    }
    let first_binding = first.admission.binding_key(1).unwrap();
    let second_binding = second.admission.binding_key(3).unwrap();
    let key = ProductionFloorKey::from_binding(first_binding).unwrap();
    assert_eq!(
        store
            .ledger
            .index
            .reclaim_prefix(i128::MAX)
            .iter()
            .map(|(_, binding)| *binding)
            .collect::<Vec<_>>(),
        [first_binding, second_binding]
    );
    let old_second = store.ledger.rows[&second_binding].clone();
    let mut corrupt =
        Row::from_hydration(&old_second.hydrate(&first.root, &store.scope).unwrap()).unwrap();
    *corrupt.canonical.last_mut().unwrap() ^= 1;
    store
        .ledger
        .rows
        .insert(second_binding, SharedRow::new(corrupt).unwrap());
    let before_first = store.ledger.rows[&first_binding]
        .canonical()
        .unwrap()
        .to_vec();
    let before_witness = store.ledger.witness;
    let before_partitions = store.ledger.partitions.clone();
    assert!(store.maintain_due(due).is_err());
    assert_eq!(
        store.ledger.rows[&first_binding].canonical().unwrap(),
        before_first
    );
    assert!(store.ledger.witness == before_witness);
    assert!(store.ledger.partitions.ptr_eq(&before_partitions));
    assert_eq!(store.ledger.index.reclaim_prefix(i128::MAX).len(), 2);
    store.ledger.rows.insert(second_binding, old_second);
    assert!(store.maintain_due(due).unwrap());
    assert!(store
        .ledger
        .rows
        .values()
        .all(|row| row.facts.state == State::Tombstone));
    Ledger::admit(
        &first.root,
        &fixed_scope(first.identity, &state.members),
        4,
        Some(4),
        store.ledger.rows.values().cloned(),
        store
            .ledger
            .partitions
            .iter()
            .map(|(key, row)| (*key, (**row).clone())),
        store.ledger.witness,
        |_| Ok(None),
    )
    .unwrap();
    // Both tombstones are eligible, but the shared floor receives one epoch
    // action per turn. The global terminal prefix cannot skip epoch three.
    assert!(store.maintain_due(due).unwrap());
    assert!(!store.ledger.rows.contains_key(&first_binding));
    assert!(store.ledger.rows.contains_key(&second_binding));
    assert_eq!(store.ledger.partitions[&key].floor.retired_through(), 1);
    assert_eq!(store.ledger.witness.unwrap().retired_terminal_sequence(), 2);
    assert_eq!(store.ledger.index.epoch_count(key, 1), 0);
    assert_eq!(store.ledger.index.epoch_count(key, 3), 1);
    Ledger::admit(
        &first.root,
        &fixed_scope(first.identity, &state.members),
        4,
        Some(4),
        store.ledger.rows.values().cloned(),
        store
            .ledger
            .partitions
            .iter()
            .map(|(key, row)| (*key, (**row).clone())),
        store.ledger.witness,
        |_| Ok(None),
    )
    .unwrap();
    assert!(store.maintain_due(due).unwrap());
    assert!(store.ledger.rows.is_empty());
    assert!(store.ledger.partitions.is_empty());
    assert_eq!(store.ledger.witness.unwrap().retired_terminal_sequence(), 4);
    assert!(!store.maintain_due(due).unwrap());
}

fn assert_mixed_sql_ledger(store: &Store<'_, '_>, sql: &Connection, sequence: u64) {
    frame_tests::assert_ledger_frames(store, sequence);
    for (binding, row) in &store.ledger.rows {
        let query = match row.projection.profile {
            Profile::V1 => "SELECT canonical_record FROM consensus_protected_roster_rows WHERE binding=?1",
            Profile::V2 => "SELECT canonical_record FROM consensus_protected_roster_v2_admissions WHERE binding=?1",
        };
        let canonical: Vec<u8> = sql
            .query_row(query, [binding.to_bytes().as_slice()], |row| row.get(0))
            .unwrap();
        assert_eq!(
            store.hydrate_row(*binding).unwrap().unwrap().canonical(),
            canonical
        );
    }
    let rows:i64 = sql.query_row("SELECT (SELECT COUNT(*) FROM consensus_protected_roster_rows) + (SELECT COUNT(*) FROM consensus_protected_roster_v2_admissions)",[],|row| row.get(0)).unwrap();
    assert_eq!(store.ledger.rows.len(), usize::try_from(rows).unwrap());
    assert!(store.ledger.witness == Some(sql_witness(sql)));
    for (key, partition) in &store.ledger.partitions {
        let bytes: Vec<u8> = sql
            .query_row(
                "SELECT canonical_floor FROM consensus_protected_roster_floors WHERE partition=?1",
                [key.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(partition.floor.to_canonical_bytes().unwrap(), bytes);
        assert!(partition.cursor.is_none());
    }
    assert_eq!(
        sql.query_row(
            "SELECT COUNT(*) FROM consensus_protected_roster_floors",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        i64::try_from(store.ledger.partitions.len()).unwrap()
    );
    assert_eq!(
        sql.query_row(
            "SELECT COUNT(*) FROM consensus_protected_roster_retirement_cursors",
            [],
            |row| row.get::<_, i64>(0)
        )
        .unwrap(),
        0
    );
    assert_eq!(
        store.restore_revision,
        crate::sqlite::ops::read_restore_scan_state_sync(sql)
            .unwrap()
            .1
    );
    let key = store
        .keys
        .keys()
        .next()
        .unwrap_or_else(|| store.base.keys.keys().next().unwrap());
    assert_eq!(
        store.key(key).record,
        crate::sqlite::ops::get_raw_sync(sql, key).unwrap()
    );
    Ledger::admit_detached(
        store.root.unwrap(),
        &store.scope,
        sequence,
        Some(sequence),
        store.ledger.rows.values().cloned(),
        store
            .ledger
            .partitions
            .iter()
            .map(|(key, row)| (*key, (**row).clone())),
        store.ledger.witness,
        |key| Ok(store.key(key).record),
        &|| Ok(()),
    )
    .unwrap();
}

#[test]
fn native_roster_store_signed_v1_terminals_and_mixed_maintenance_match_sql() {
    run_signed_v1_sql_ledger(false);
}

fn run_signed_v1_sql_ledger(selected: bool) {
    use crate::consensus::types::{
        protected_roster_profile_voter_set_digest, SESSION_CONSENSUS_SCHEMA_VERSION,
    };
    use crate::fenced_mutation_roster::{EstablishedMutation, Phase};
    use crate::sqlite::consensus::{
        native_roster_apply_fixture, native_roster_maintenance_fixture,
    };
    use opc_consensus::engine::CommittedLeaderId;
    for delete in [false, true] {
        for phase in [Phase::Established, Phase::Aborted] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("signed-v1-oracle.sqlite");
            let sql_fixture = initialize_protected_roster_v2_recovery_fixture(
                &path,
                ProtectedRosterV2RecoveryFixtureState::Established,
            )
            .unwrap();
            let sql = Connection::open(&path).unwrap();
            let signed = crate::consensus::types::roster_v2_persistence_fixture();
            let state = predecessor(&signed, None);
            let mut delta = state.prepare(&[]).unwrap();
            let before = postcard::to_allocvec(&state).unwrap();
            let now = signed.authority.acquired_at().add_seconds(1).unwrap();
            let q1 = carrier::tests::signed_v1_command_with_mutation(
                &signed,
                if delete {
                    EstablishedMutation::delete()
                } else {
                    EstablishedMutation::no_op()
                },
            );
            let q2 = v1_fixture::terminal(&signed, &q1, 4, phase);
            let origin = SessionConsensusNodeId::new(7).unwrap();
            let entry = |index, request_id, mutation| Entry {
                log_id: LogId::new(CommittedLeaderId::new(1, origin), index),
                payload: EntryPayload::Normal(SessionConsensusCommand {
                    schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                    identity: signed.identity,
                    request_id,
                    logical_time: now,
                    intent: SessionMutationIntent::Authorized {
                        origin,
                        authority_identity: signed.identity,
                        mutation: Box::new(mutation),
                    },
                }),
            };
            let activation = entry(
                3,
                SessionConsensusRequestId::from_bytes([0xC8; 16]),
                SessionMutationIntent::ActivateFencedTransitionCapability {
                    schema_version: crate::fenced_transition::FENCED_TRANSITION_SCHEMA_V1,
                    scope_identity: signed.identity,
                    voter_set_digest: protected_roster_profile_voter_set_digest(
                        signed.identity,
                        &sql_fixture.members,
                    ),
                },
            );
            let activated =
                native_roster_apply_fixture(&path, signed.identity, vec![activation]).unwrap();
            assert_eq!(
                activated.responses[0].result,
                Ok(SessionMutationOutcome::Unit)
            );
            let check = || Ok(());
            let mut store =
                Store::new_detached(&delta, &Ledger::empty(), &signed.root, &check).unwrap();
            let mut selected_files = Vec::new();
            roster_engine::admit_v2(
                &mut store,
                signed.identity,
                signed.identity,
                1,
                now,
                &command(&signed),
            )
            .unwrap_or_else(|_| panic!("signed V2 predecessor Q1"));
            roster_engine::terminal_v2(
                &mut store,
                signed.identity,
                signed.identity,
                2,
                2,
                now,
                &signed.terminal_command,
            )
            .unwrap_or_else(|_| panic!("signed V2 predecessor Q2"));
            let v2 = signed.admission.binding_key(1).unwrap();
            let v1 = q1.admission().binding_key(4).unwrap();
            let original_business = store.key(signed.authority.key()).record;
            let admitted =
                roster_engine::admit_v1(&mut store, signed.identity, signed.identity, 4, now, &q1)
                    .unwrap_or_else(|_| panic!("signed V1 Q1"));
            assert!(matches!(
                admitted,
                ConsensusRosterAdmissionOutcome::Admitted { .. }
            ));
            let applied = native_roster_apply_fixture(
                &path,
                signed.identity,
                vec![entry(
                    4,
                    q1.request_id().unwrap(),
                    SessionMutationIntent::RosterAdmission(Box::new(q1.clone())),
                )],
            )
            .unwrap();
            assert_eq!(
                applied.responses[0].result,
                Ok(SessionMutationOutcome::RosterAdmission(admitted))
            );
            assert!(store.key(signed.authority.key()).reserved);
            assert_eq!(
                store.ledger.index.reservation(signed.authority.key()),
                Some(v1)
            );
            if selected {
                selected_files.extend(row_tests::select_all(&mut store));
            }
            assert_mixed_sql_ledger(&store, &sql, 4);
            let (terminal, replication) = roster_engine::terminal_v1(
                &mut store,
                signed.identity,
                signed.identity,
                5,
                5,
                now,
                &q2,
            )
            .unwrap_or_else(|_| panic!("signed V1 Q2"));
            assert!(matches!(
                terminal,
                ConsensusRosterTerminalOutcome::Committed {
                    replayed: false,
                    ..
                }
            ));
            let changed_business = delete && phase == Phase::Established;
            assert_eq!(replication.is_some(), phase == Phase::Established);
            let applied = native_roster_apply_fixture(
                &path,
                signed.identity,
                vec![entry(
                    5,
                    q2.request_id().unwrap(),
                    SessionMutationIntent::RosterTerminal(Box::new(q2.clone())),
                )],
            )
            .unwrap();
            assert_eq!(
                applied.responses[0].result,
                Ok(SessionMutationOutcome::RosterTerminal(terminal))
            );
            assert_eq!(
                applied.notifications.len(),
                usize::from(phase == Phase::Established)
            );
            assert!(!store.key(signed.authority.key()).reserved);
            assert_eq!(store.ledger.index.reservation(signed.authority.key()), None);
            assert_eq!(
                store.key(signed.authority.key()).record,
                if changed_business {
                    None
                } else {
                    original_business
                }
            );
            assert_mixed_sql_ledger(&store, &sql, 5);
            let retained = store.ledger.rows[&v1].canonical().unwrap().to_vec();
            if selected {
                selected_files.extend(row_tests::select_all(&mut store));
            }
            let witness = store.ledger.witness;
            let revision = store.restore_revision;
            let (replay, notification) = roster_engine::terminal_v1(
                &mut store,
                signed.identity,
                signed.identity,
                6,
                6,
                now,
                &q2,
            )
            .unwrap_or_else(|_| panic!("signed V1 Q2 replay"));
            assert!(matches!(
                replay,
                ConsensusRosterTerminalOutcome::Committed { replayed: true, .. }
            ));
            assert!(notification.is_none());
            let replayed = native_roster_apply_fixture(
                &path,
                signed.identity,
                vec![entry(
                    6,
                    q2.request_id().unwrap(),
                    SessionMutationIntent::RosterTerminal(Box::new(q2.clone())),
                )],
            )
            .unwrap();
            assert_eq!(
                replayed.responses[0].result,
                Ok(SessionMutationOutcome::RosterTerminal(replay))
            );
            assert!(replayed.notifications.is_empty());
            assert_eq!(
                store.hydrate_row(v1).unwrap().unwrap().canonical(),
                retained
            );
            assert!(store.ledger.witness == witness);
            assert_eq!(store.restore_revision, revision);
            assert_mixed_sql_ledger(&store, &sql, 6);
            // Release every Q1/Q2 hydration reservation before the separate
            // maintenance savepoint. Neither savepoint publishes base state.
            let (ledger, keys, restore_revision) = store.finish();
            delta.keys = keys;
            delta.frontiers.restore_revision = restore_revision;
            let mut maintenance =
                Store::new_detached(&delta, &ledger, &signed.root, &check).unwrap();
            let due = now.add_seconds(24 * 60 * 60).unwrap();
            // A nonnegative clock within the first retention period yields
            // a negative signed cutoff, never an eligible SQL byte range.
            assert!(!maintenance.maintain_due(now).unwrap());
            assert!(!native_roster_maintenance_fixture(&path, signed.identity, now).unwrap());
            assert_mixed_sql_ledger(&maintenance, &sql, 6);
            assert!(!maintenance
                .maintain_due(due.add_seconds(-1).unwrap())
                .unwrap());
            assert!(!native_roster_maintenance_fixture(
                &path,
                signed.identity,
                due.add_seconds(-1).unwrap()
            )
            .unwrap());
            for turn in 0..3 {
                if selected {
                    selected_files.extend(row_tests::select_all(&mut maintenance));
                }
                assert!(maintenance.maintain_due(due).unwrap());
                assert!(native_roster_maintenance_fixture(&path, signed.identity, due).unwrap());
                assert_mixed_sql_ledger(&maintenance, &sql, 6);
                match turn {
                    0 => assert!(maintenance
                        .ledger
                        .rows
                        .values()
                        .all(|row| row.facts.state == State::Tombstone)),
                    1 => {
                        assert!(!maintenance.ledger.rows.contains_key(&v2));
                        assert!(maintenance.ledger.rows.contains_key(&v1));
                        assert_eq!(
                            maintenance
                                .ledger
                                .witness
                                .unwrap()
                                .retired_terminal_sequence(),
                            2
                        );
                    }
                    2 => {
                        assert!(maintenance.ledger.rows.is_empty());
                        assert!(maintenance.ledger.partitions.is_empty());
                        assert_eq!(
                            maintenance
                                .ledger
                                .witness
                                .unwrap()
                                .retired_terminal_sequence(),
                            5
                        );
                    }
                    _ => unreachable!(),
                }
            }
            assert!(!maintenance.maintain_due(due).unwrap());
            assert!(!native_roster_maintenance_fixture(&path, signed.identity, due).unwrap());
            assert_eq!(maintenance.restore_revision, revision);
            assert_eq!(postcard::to_allocvec(&state).unwrap(), before);
        }
    }
}
