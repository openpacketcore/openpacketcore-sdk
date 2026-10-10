use super::*;
use crate::consensus::native::voter_slot_tests as fixture;
use opc_consensus::voter_slots::*;

fn initialize(
    conn: &Connection,
    initial: &VoterSlotTable,
    slots: bool,
) -> Result<SessionConsensusIdentity, SessionConsensusStorageError> {
    let identity = initial
        .current_configuration()
        .identity(initial.cluster_instance, initial.manifest_digest)
        .unwrap();
    let members = initial
        .current_configuration()
        .members
        .iter()
        .map(|member| member.identity.node_id())
        .collect();
    let seed = crate::sqlite::consensus::voter_slots::Seed::genesis(initial.clone()).unwrap();
    initialize_schema_with_storage_anchor_and_pending_and_bindings_and_fenced_profile_and_voter_slots(
        conn, None, identity, &members, &test_member_bindings(&members), None,
        ConsensusAuthorityProfile::FixedImmutable,
        Some(PlacementResiliencePolicy::RequireIndependentFailureDomains), None,
        crate::FencedTransitionV2Profile::V2, slots.then_some(&seed),
    )
}

#[test]
fn slot_seed_profile_cannot_be_adopted_by_legacy_or_created_over_legacy() {
    for old_first in [false, true] {
        let backend = SqliteSessionBackend::in_memory().unwrap();
        let conn = backend.conn.blocking_lock();
        let initial = fixture::genesis(3);
        initialize(&conn, &initial, !old_first).unwrap();
        let before: i64 = conn
            .query_row("PRAGMA schema_version", [], |row| row.get(0))
            .unwrap();
        assert!(matches!(
            initialize(&conn, &initial, old_first),
            Err(SessionConsensusStorageError::SchemaVersionMismatch)
        ));
        assert_eq!(
            conn.query_row("PRAGMA schema_version", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            before
        );
        initialize(&conn, &initial, !old_first).unwrap();
    }
}

#[test]
fn native_wal_slot_reader_never_releases_an_unflushed_truncation() {
    use crate::sqlite::consensus::wal::Point;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    };
    for size in [3, 5, 9] {
        let directory = tempfile::tempdir().unwrap();
        let backend = SqliteSessionBackend::open(directory.path().join("seed.sqlite")).unwrap();
        let initial = fixture::genesis(size);
        let conn = backend.conn.blocking_lock();
        let identity = initialize(&conn, &initial, true).unwrap();
        let held = Arc::new(AtomicBool::new(false));
        let latch = Arc::new((Mutex::new((false, false)), Condvar::new()));
        let wal_dir = directory.path().join("wal");
        let wal = Wal::create_native(
            &wal_dir,
            &conn,
            identity,
            [0xE4; 32],
            Limits::default(),
            IoControl::default(),
        )
        .unwrap();
        drop(conn);
        let members = initial
            .current_configuration()
            .members
            .iter()
            .map(|member| member.identity.node_id())
            .collect::<BTreeSet<_>>();
        let formation = Entry {
            log_id: fixture::cut(0),
            payload: EntryPayload::Membership(opc_consensus::engine::Membership::new(
                vec![members],
                None,
            )),
        };
        wal.submit(append(std::slice::from_ref(&formation)))
            .unwrap()
            .wait()
            .unwrap();
        wal.submit(Operation::Committed(Some(formation.log_id)))
            .unwrap()
            .wait()
            .unwrap();
        wal.native_apply_committed(std::slice::from_ref(&formation))
            .unwrap();
        let prepare = fixture::command(
            &initial,
            1,
            VoterSlotControl::Begin(Box::new(fixture::request(&initial, size))),
        );
        wal.submit(append(std::slice::from_ref(&prepare)))
            .unwrap()
            .wait()
            .unwrap();
        let provisional = wal.native_voter_slot_state().unwrap();
        assert!(provisional.intent().is_some());
        wal.shutdown().unwrap();
        let wal = Wal::open(
            &wal_dir,
            wal.binding(),
            Limits::default(),
            IoControl::default(),
        )
        .unwrap();
        assert_eq!(wal.native_voter_slot_state().unwrap(), provisional);
        wal.shutdown().unwrap();
        let control = IoControl {
            hook: Arc::new({
                let held = held.clone();
                let latch = latch.clone();
                move |point| {
                    if point == Point::AfterIntentPublish && held.load(Ordering::Acquire) {
                        let (lock, wake) = &*latch;
                        let mut state = lock.lock().unwrap();
                        state.0 = true;
                        wake.notify_all();
                        while !state.1 {
                            state = wake.wait(state).unwrap();
                        }
                    }
                    Ok(())
                }
            }),
            ..IoControl::default()
        };
        let wal = Wal::open(&wal_dir, wal.binding(), Limits::default(), control).unwrap();
        held.store(true, Ordering::Release);
        let completion = wal.submit(Operation::Truncate(prepare.log_id)).unwrap();
        let reached = {
            let (lock, wake) = &*latch;
            let state = lock.lock().unwrap();
            let (state, _) = wake
                .wait_timeout_while(state, std::time::Duration::from_secs(5), |state| !state.0)
                .unwrap();
            state.0
        };
        let result = wal.native_voter_slot_state();
        {
            let (lock, wake) = &*latch;
            let mut state = lock.lock().unwrap();
            state.1 = true;
            wake.notify_all();
        }
        completion.wait().unwrap();
        assert!(
            reached,
            "writer must reach the held durable-intent boundary"
        );
        assert!(
            result.is_err(),
            "admitted log projection is ahead of fsync and cannot release a fence"
        );
        assert!(wal.native_voter_slot_state().unwrap().intent().is_none());
        wal.shutdown().unwrap();
        let wal = Wal::open(
            &wal_dir,
            wal.binding(),
            Limits::default(),
            IoControl::default(),
        )
        .unwrap();
        assert!(wal.native_voter_slot_state().unwrap().intent().is_none());
        wal.shutdown().unwrap();
    }
}

#[test]
fn native_slot_export_carries_the_current_table_and_exact_pending_intent() {
    let directory = tempfile::tempdir().unwrap();
    let backend = SqliteSessionBackend::open(directory.path().join("seed.sqlite")).unwrap();
    let initial = fixture::genesis(3);
    let conn = backend.conn.blocking_lock();
    let identity = initialize(&conn, &initial, true).unwrap();
    let wal = Wal::create_native(
        &directory.path().join("wal"),
        &conn,
        identity,
        [0xE5; 32],
        Limits::default(),
        IoControl::default(),
    )
    .unwrap();
    drop(conn);
    let members = initial
        .current_configuration()
        .members
        .iter()
        .map(|member| member.identity.node_id())
        .collect::<BTreeSet<_>>();
    let formation = Entry {
        log_id: fixture::cut(0),
        payload: EntryPayload::Membership(opc_consensus::engine::Membership::new(
            vec![members],
            None,
        )),
    };
    wal.submit(append(std::slice::from_ref(&formation)))
        .unwrap()
        .wait()
        .unwrap();
    wal.submit(Operation::Committed(Some(formation.log_id)))
        .unwrap()
        .wait()
        .unwrap();
    wal.native_apply_committed(std::slice::from_ref(&formation))
        .unwrap();
    let prepare = fixture::command(
        &initial,
        1,
        VoterSlotControl::Begin(Box::new(fixture::request(&initial, 3))),
    );
    wal.submit(append(std::slice::from_ref(&prepare)))
        .unwrap()
        .wait()
        .unwrap();
    let expected = wal.native_voter_slot_state().unwrap();
    let local_image = wal.native_export_install_base_for_test().unwrap();
    assert_eq!(
        crate::sqlite::consensus::voter_slots::read_state(&local_image)
            .unwrap()
            .unwrap(),
        expected
    );
    drop(local_image);
    wal.submit(Operation::Committed(Some(prepare.log_id)))
        .unwrap()
        .wait()
        .unwrap();
    wal.native_apply_committed(std::slice::from_ref(&prepare))
        .unwrap();
    let expected = wal.native_voter_slot_state().unwrap();
    let snapshot = wal.native_export_snapshot().unwrap();
    assert_eq!(
        crate::sqlite::consensus::voter_slots::read_state(&snapshot)
            .unwrap()
            .unwrap(),
        expected
    );
    drop(snapshot);
    wal.shutdown().unwrap();
    let reopened = Wal::open(
        &directory.path().join("wal"),
        wal.binding(),
        Limits::default(),
        IoControl::default(),
    )
    .unwrap();
    assert_eq!(reopened.native_voter_slot_state().unwrap(), expected);
    reopened.shutdown().unwrap();
}

#[test]
fn native_installed_snapshot_cut_preserves_or_resolves_intent_after_selected_reopen() {
    use crate::sqlite::consensus::tests::sequential_wal::IncomingSnapshot;
    use crate::sqlite::consensus::wal::native::Opening;
    for retired in [false, true] {
        let initial = fixture::genesis(3);
        let make = || {
            let directory = tempfile::tempdir().unwrap();
            let backend = SqliteSessionBackend::open(directory.path().join("seed.sqlite")).unwrap();
            let conn = backend.conn.blocking_lock();
            let identity = initialize(&conn, &initial, true).unwrap();
            let wal = Wal::create_native(
                &directory.path().join("wal"),
                &conn,
                identity,
                [0xB5; 32],
                Limits::default(),
                IoControl::default(),
            )
            .unwrap();
            drop(conn);
            (directory, backend, wal, identity)
        };
        let (_source_dir, _source_backend, source, identity) = make();
        let (target_dir, target_backend, mut target, _) = make();
        let members = initial
            .current_configuration()
            .members
            .iter()
            .map(|member| member.identity.node_id())
            .collect();
        let formation = Entry {
            log_id: fixture::cut(0),
            payload: EntryPayload::Membership(opc_consensus::engine::Membership::new(
                vec![members],
                None,
            )),
        };
        let apply = |wal: &Wal, entries: &[Entry<SessionRaftTypeConfig>]| {
            wal.submit(append(entries)).unwrap().wait().unwrap();
            wal.submit(Operation::Committed(Some(entries.last().unwrap().log_id)))
                .unwrap()
                .wait()
                .unwrap();
            wal.native_apply_committed(entries).unwrap();
        };
        apply(&source, std::slice::from_ref(&formation));
        apply(&target, std::slice::from_ref(&formation));
        let blank = Entry {
            log_id: fixture::cut(1),
            payload: EntryPayload::Blank,
        };
        apply(&source, std::slice::from_ref(&blank));
        let prepare = fixture::command(
            &initial,
            2,
            VoterSlotControl::Begin(Box::new(fixture::request(&initial, 3))),
        );
        target
            .submit(append(&[blank, prepare.clone()]))
            .unwrap()
            .wait()
            .unwrap();
        let intent = target
            .native_voter_slot_state()
            .unwrap()
            .intent()
            .cloned()
            .unwrap();
        let below =
            IncomingSnapshot::with_identity(&source.native_export_snapshot().unwrap(), identity);
        target
            .install_snapshot(
                &target_backend.conn.blocking_lock(),
                below.source().unwrap(),
            )
            .unwrap();
        assert_eq!(
            target.native_voter_slot_state().unwrap().intent(),
            Some(&intent)
        );
        let reopen = |wal: Wal, incoming: &IncomingSnapshot| {
            wal.shutdown().unwrap();
            let binding = wal.binding();
            drop(wal);
            let opening = Opening::new(
                &target_dir.path().join("wal"),
                binding,
                None,
                Limits::default(),
                IoControl::default(),
            )
            .unwrap();
            let source = incoming.source().unwrap();
            opening
                .finish_with_install_source(Some(&source), || source.verify())
                .unwrap()
        };
        target = reopen(target, &below);
        assert_eq!(
            target.native_voter_slot_state().unwrap().intent(),
            Some(&intent)
        );
        let second = if retired {
            prepare
        } else {
            Entry {
                log_id: crate::sqlite::consensus::voter_slots::engine_cut(VoterSlotLogId {
                    term: 3,
                    index: 2,
                }),
                payload: EntryPayload::Blank,
            }
        };
        let third = Entry {
            log_id: crate::sqlite::consensus::voter_slots::engine_cut(VoterSlotLogId {
                term: second.log_id.leader_id.term,
                index: 3,
            }),
            payload: EntryPayload::Blank,
        };
        apply(&source, &[second, third]);
        let above =
            IncomingSnapshot::with_identity(&source.native_export_snapshot().unwrap(), identity);
        target
            .install_snapshot(
                &target_backend.conn.blocking_lock(),
                above.source().unwrap(),
            )
            .unwrap();
        target = reopen(target, &above);
        let published = target.native_voter_slot_state().unwrap();
        assert!(published.intent().is_none());
        assert_eq!(
            published
                .table()
                .is_retired(fixture::member(3, 1).identity.node_id()),
            retired
        );
        assert_eq!(target.native_sql_fallback_count().unwrap(), 0);
        target.shutdown().unwrap();
        source.shutdown().unwrap();
    }
}
