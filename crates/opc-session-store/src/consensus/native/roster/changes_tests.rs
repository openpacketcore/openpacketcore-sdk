use super::*;

fn assert_journal(store: &Store<'_, '_>) {
    store.changes.require_current(&store.ledger).unwrap();
    store
        .changes
        .validate_detached(store.root.unwrap(), &store.scope, &|| Ok(()))
        .unwrap();
}

#[test]
fn native_roster_journal_preserves_transient_rows_and_partitions() {
    let first = crate::consensus::types::roster_v2_aborted_persistence_fixture();
    let second =
        crate::consensus::types::roster_v2_aborted_persistence_fixture_for_history([0x92; 16], 3);
    let state = predecessor(&first, None);
    let delta = state.prepare(&[]).unwrap();
    let empty = Ledger::empty();
    let initial = Arc::clone(empty.certificate().unwrap());
    let now = first.authority.acquired_at().add_seconds(1).unwrap();
    let mut store = Store::new(&delta, &empty, &first.root).unwrap();
    for (epoch, signed) in [(1, &first), (3, &second)] {
        roster_engine::admit_v2(
            &mut store,
            signed.identity,
            signed.identity,
            epoch,
            now,
            &command(signed),
        )
        .unwrap_or_else(|_| panic!("signed native roster change"));
        roster_engine::terminal_v2(
            &mut store,
            signed.identity,
            signed.identity,
            epoch + 1,
            epoch + 1,
            now,
            &signed.terminal_command,
        )
        .unwrap_or_else(|_| panic!("signed native roster change"));
        assert_journal(&store);
    }
    let due = now.add_seconds(24 * 60 * 60).unwrap();
    for _ in 0..3 {
        assert!(store.maintain_due(due).unwrap());
        assert_journal(&store);
    }
    assert!(!store.maintain_due(due).unwrap());
    let (ledger, mut journal, keys, revision) = store.finish_with_changes().unwrap();
    assert!(ledger.rows.is_empty() && ledger.partitions.is_empty());
    assert_eq!(ledger.witness.unwrap().retired_terminal_sequence(), 4);
    assert!(journal.starts_at(&initial));
    assert_eq!(journal.rows.len(), 2);
    assert_eq!(journal.partitions.len(), 1);
    assert!(journal
        .rows
        .values()
        .all(|row| row.before.is_none() && row.after.is_none()));
    assert!(journal
        .partitions
        .values()
        .all(|row| row.before.is_none() && row.after.is_none()));
    assert_eq!(journal.target().counts(), [0, 0]);
    assert_eq!(journal.target().content(), [[0; 32]; 2]);
    assert!(keys
        .values()
        .all(|key| key.record.is_none() && !key.reserved));
    assert_eq!(revision, delta.frontiers.restore_revision);
    let binding = first.admission.binding_key(1).unwrap();
    let row = journal.rows.remove(&binding).unwrap();
    assert!(
        journal.validate(&|| Ok(())).is_err(),
        "transient row omitted with equal endpoint summaries"
    );
    let mut wrong_bytes = binding.to_bytes();
    wrong_bytes[8] ^= 1;
    let wrong = RequestBindingKey::from_bytes(wrong_bytes).unwrap();
    journal.rows.insert(wrong, row);
    assert!(
        journal.validate(&|| Ok(())).is_err(),
        "transient row was assigned to another binding"
    );
    let row = journal.rows.remove(&wrong).unwrap();
    journal.rows.insert(binding, row);
    let key = ProductionFloorKey::from_binding(binding).unwrap();
    let partition = journal.partitions.remove(&key).unwrap();
    assert!(
        journal.validate(&|| Ok(())).is_err(),
        "transient partition omitted with equal endpoint summaries"
    );
    journal.partitions.insert(key, partition);
    let target = Arc::clone(journal.target());
    let calls = std::cell::Cell::new(0);
    assert!(journal
        .validate(&|| {
            calls.set(calls.get() + 1);
            if calls.get() == 3 {
                Err(invalid("cancel journal"))
            } else {
                Ok(())
            }
        })
        .is_err());
    assert!(Arc::ptr_eq(&target, journal.target()));
    journal.require_current(&ledger).unwrap();
    journal.validate(&|| Ok(())).unwrap();
}

#[test]
fn native_roster_journal_requires_exact_row_partition_and_ledger_revisions() {
    let signed = crate::consensus::types::roster_v2_persistence_fixture();
    let state = predecessor(&signed, None);
    let delta = state.prepare(&[]).unwrap();
    let empty = Ledger::empty();
    let mut store = Store::new(&delta, &empty, &signed.root).unwrap();
    let now = signed.authority.acquired_at().add_seconds(1).unwrap();
    roster_engine::admit_v2(
        &mut store,
        signed.identity,
        signed.identity,
        1,
        now,
        &command(&signed),
    )
    .unwrap_or_else(|_| panic!("signed native roster change"));
    let binding = signed.admission.binding_key(1).unwrap();
    let scope = store.scope.clone();
    let (ledger, mut journal, _, _) = store.finish_with_changes().unwrap();
    let original = journal.rows[&binding].after.as_ref().unwrap().clone();
    let equal = Row::from_hydration(&original.hydrate(&signed.root, &scope).unwrap()).unwrap();
    journal.rows.get_mut(&binding).unwrap().after = Some(SharedRow::new(equal));
    assert!(journal.require_current(&ledger).is_err());
    assert!(journal.validate(&|| Ok(())).is_err());
    journal.rows.get_mut(&binding).unwrap().after = Some(original);
    let key = ProductionFloorKey::from_binding(binding).unwrap();
    let original = journal.partitions[&key].after.as_ref().unwrap().clone();
    journal.partitions.get_mut(&key).unwrap().after = Some(SharedRow::new((*original).clone()));
    assert!(journal.require_current(&ledger).is_err());
    assert!(journal.validate(&|| Ok(())).is_err());
    journal.partitions.get_mut(&key).unwrap().after = Some(original);
    journal
        .validate_detached(&signed.root, &scope, &|| Ok(()))
        .unwrap();
    let mut wrong = Journal::empty(&Ledger::empty()).unwrap();
    let before = Arc::clone(wrong.target());
    assert!(
        wrong.append(journal).is_err(),
        "equal empty content is not the same ledger predecessor"
    );
    assert!(Arc::ptr_eq(&before, wrong.target()));
    assert!(wrong.rows.is_empty() && wrong.partitions.is_empty());
    wrong.validate(&|| Ok(())).unwrap();
}

#[test]
fn native_roster_journal_preflight_failure_discards_business_witness_and_index_changes() {
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
    .unwrap_or_else(|_| panic!("signed native roster change"));
    let binding = signed.admission.binding_key(1).unwrap();
    let original = store.changes.rows[&binding].after.as_ref().unwrap().clone();
    let equal =
        Row::from_hydration(&original.hydrate(&signed.root, &store.scope).unwrap()).unwrap();
    store.changes.rows.get_mut(&binding).unwrap().after = Some(SharedRow::new(equal));
    let ledger = store.ledger.clone();
    let key = store.key(signed.authority.key());
    let revision = store.restore_revision;
    assert!(roster_engine::terminal_v2(
        &mut store,
        signed.identity,
        signed.identity,
        2,
        2,
        now,
        &signed.terminal_command
    )
    .is_err());
    assert!(Arc::ptr_eq(
        ledger.certificate().unwrap(),
        store.ledger.certificate().unwrap()
    ));
    assert!(store.ledger.rows[&binding].ptr_eq(&ledger.rows[&binding]));
    assert!(store.ledger.partitions.ptr_eq(&ledger.partitions));
    assert!(store.ledger.witness == ledger.witness);
    assert_eq!(
        store.ledger.index.reservation(signed.authority.key()),
        Some(binding)
    );
    assert_eq!(
        postcard::to_allocvec(&store.key(signed.authority.key())).unwrap(),
        postcard::to_allocvec(&key).unwrap()
    );
    assert_eq!(store.restore_revision, revision);
    store.changes.rows.get_mut(&binding).unwrap().after = Some(original);
    let (outcome, notification) = roster_engine::terminal_v2(
        &mut store,
        signed.identity,
        signed.identity,
        2,
        2,
        now,
        &signed.terminal_command,
    )
    .unwrap_or_else(|_| panic!("signed native roster change"));
    assert!(matches!(
        outcome,
        ConsensusRosterTerminalOutcome::Committed {
            replayed: false,
            ..
        }
    ));
    assert!(notification.is_some());
    assert!(store.key(signed.authority.key()).record.is_some());
    assert!(!store.key(signed.authority.key()).reserved);
    assert_journal(&store);
}

#[test]
fn native_roster_journal_only_hydrates_touched_selected_history() {
    let first = crate::consensus::types::roster_v2_aborted_persistence_fixture();
    let second =
        crate::consensus::types::roster_v2_aborted_persistence_fixture_for_history([0x92; 16], 3);
    let state = predecessor(&first, None);
    let mut delta = state.prepare(&[]).unwrap();
    let check = || Ok(());
    let now = first.authority.acquired_at().add_seconds(1).unwrap();
    let mut store = Store::new_detached(&delta, &Ledger::empty(), &first.root, &check).unwrap();
    roster_engine::admit_v2(
        &mut store,
        first.identity,
        first.identity,
        1,
        now,
        &command(&first),
    )
    .unwrap_or_else(|_| panic!("signed native roster change"));
    roster_engine::terminal_v2(
        &mut store,
        first.identity,
        first.identity,
        2,
        2,
        now,
        &first.terminal_command,
    )
    .unwrap_or_else(|_| panic!("signed native roster change"));
    roster_engine::admit_v2(
        &mut store,
        second.identity,
        second.identity,
        3,
        now,
        &command(&second),
    )
    .unwrap_or_else(|_| panic!("signed native roster change"));
    let files = row_tests::select_all(&mut store);
    assert_journal(&store);
    let first_binding = first.admission.binding_key(1).unwrap();
    let second_binding = second.admission.binding_key(3).unwrap();
    let scope = store.scope.clone();
    let (ledger, history, keys, revision) = store.finish_with_changes().unwrap();
    drop(history);
    delta.keys = keys;
    delta.frontiers.restore_revision = revision;
    files
        .iter()
        .find(|(binding, _)| *binding == first_binding)
        .unwrap()
        .1
        .corrupt_prefix();
    let untouched = ledger.rows[&first_binding].clone();
    let mut next = Store::new_detached(&delta, &ledger, &first.root, &check).unwrap();
    roster_engine::terminal_v2(
        &mut next,
        second.identity,
        second.identity,
        4,
        4,
        now,
        &second.terminal_command,
    )
    .unwrap_or_else(|_| panic!("signed native roster change"));
    let (ledger, changes, _, _) = next.finish_with_changes().unwrap();
    assert_eq!(changes.rows.len(), 1);
    assert!(changes.rows.contains_key(&second_binding));
    assert!(changes.partitions.is_empty());
    assert!(changes.rows[&second_binding]
        .before
        .as_ref()
        .unwrap()
        .is_cold());
    assert!(ledger.rows[&first_binding].ptr_eq(&untouched));
    changes
        .validate_detached(&first.root, &scope, &check)
        .unwrap();
    // Complete cold admission still detects the independently damaged old
    // carrier. Bounded command preparation never claims to re-admit history.
    assert!(Ledger::admit_detached(
        &first.root,
        &scope,
        4,
        Some(4),
        ledger.rows.values().cloned(),
        ledger
            .partitions
            .iter()
            .map(|(key, row)| (*key, (**row).clone())),
        ledger.witness,
        |_| Ok(None),
        &check
    )
    .is_err());
    changes
        .validate_detached(&first.root, &scope, &check)
        .unwrap();
}

#[test]
fn native_roster_journal_selected_before_image_is_rechecked_after_capture() {
    let signed = crate::consensus::types::roster_v2_aborted_persistence_fixture();
    let state = predecessor(&signed, None);
    let mut delta = state.prepare(&[]).unwrap();
    let check = || Ok(());
    let now = signed.authority.acquired_at().add_seconds(1).unwrap();
    let mut store = Store::new_detached(&delta, &Ledger::empty(), &signed.root, &check).unwrap();
    roster_engine::admit_v2(
        &mut store,
        signed.identity,
        signed.identity,
        1,
        now,
        &command(&signed),
    )
    .unwrap_or_else(|_| panic!("signed native roster change"));
    let files = row_tests::select_all(&mut store);
    let scope = store.scope.clone();
    let (ledger, history, keys, revision) = store.finish_with_changes().unwrap();
    drop(history);
    delta.keys = keys;
    delta.frontiers.restore_revision = revision;
    let mut next = Store::new_detached(&delta, &ledger, &signed.root, &check).unwrap();
    roster_engine::terminal_v2(
        &mut next,
        signed.identity,
        signed.identity,
        2,
        2,
        now,
        &signed.terminal_command,
    )
    .unwrap_or_else(|_| panic!("signed native roster change"));
    let (ledger, changes, _, _) = next.finish_with_changes().unwrap();
    let target = Arc::clone(changes.target());
    changes
        .validate_detached(&signed.root, &scope, &check)
        .unwrap();
    files[0].1.corrupt_prefix();
    changes.validate(&check).unwrap();
    assert!(changes
        .validate_detached(&signed.root, &scope, &check)
        .is_err());
    assert!(Arc::ptr_eq(&target, changes.target()));
    changes.require_current(&ledger).unwrap();
}
