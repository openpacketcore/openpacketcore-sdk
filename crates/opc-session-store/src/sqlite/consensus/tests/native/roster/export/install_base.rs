use super::*;
use crate::consensus::native::generation::{Catalog, PreparedBase};
use opc_consensus::engine::{SnapshotMeta, Vote};
use rusqlite::backup::Backup;
use std::io::Write;

pub(super) fn copy(conn: &Connection) -> Connection {
    let mut output = Connection::open_in_memory().unwrap();
    Backup::new(conn, &mut output)
        .unwrap()
        .run_to_completion(128, Duration::ZERO, None)
        .unwrap();
    output.pragma_update(None, "query_only", true).unwrap();
    output
}

fn frozen(
    storage: NativeStorage,
    directory: &Path,
    root: [u8; 32],
    signed: &RosterV2PersistenceFixture,
) -> NativeStorage {
    let path = directory.join("complete.native");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let identity = {
        let prepared = PreparedBase::prepare(
            &storage,
            crate::consensus::native::generation::BaseParameters {
                binding: root,
                file_epoch: 1,
                checkpoint_epoch: 1,
                operation_sequence: 7,
                cut_binding: [0xD7; 32],
                block_bytes: 64 * 1024,
                maximum: crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES,
            },
            &|| Ok(()),
        )
        .unwrap();
        let mut output = io::BufWriter::new(&mut file);
        let identity = prepared.write_to(&mut output, &|| Ok(())).unwrap();
        output.flush().unwrap();
        identity
    };
    file.sync_all().unwrap();
    drop(file);
    drop(storage);
    let (_owner, catalog) = Catalog::open(
        &path,
        identity,
        crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES,
        crate::consensus::native::generation::CatalogScope {
            identity: signed.identity,
            members: &fixed_members(),
            roster_root: Some(Arc::new(signed.root.clone())),
        },
        [0xD7; 32],
        &|| Ok(()),
    )
    .unwrap();
    catalog.into_storage(&|| Ok(())).unwrap()
}

#[test]
fn native_roster_install_base_preserves_complete_cold_predecessor_and_exact_raft_pointers() {
    for phase in [Phase::Established, Phase::Aborted] {
        let directory = tempfile::tempdir().unwrap();
        let signed = roster_v2_fresh_wal_persistence_fixture(phase);
        let oracle = SqliteSessionBackend::in_memory().unwrap();
        initialize(&oracle, &signed);
        let template = copy(&oracle.conn.blocking_lock());
        let mut entries = setup(&signed);
        entries.extend([admission(&signed), terminal(&signed, 4)]);
        sql_apply(&oracle, &signed, &entries);
        let mut storage = NativeStorage::empty_with_roster_root(
            signed.identity,
            fixed_members(),
            Some(Arc::new(signed.root.clone())),
        )
        .unwrap();
        storage
            .log
            .project(&append(&entries), &storage.business, None)
            .unwrap();
        storage
            .log
            .project(
                &Operation::Committed(Some(log_id(4))),
                &storage.business,
                None,
            )
            .unwrap();
        storage.replay_committed().unwrap();
        let root = [0xD6; 32];
        let candidate = (
            SnapshotMeta {
                last_log_id: Some(log_id(3)),
                last_membership: storage.business.membership(),
                snapshot_id: format!(
                    "{}{}",
                    crate::consensus::native::snapshot_prefix(root),
                    uuid::Uuid::new_v4()
                ),
            },
            format!("snapshot-{}.opc", uuid::Uuid::new_v4()),
            [0xD8; 32],
            1234,
        );
        storage.begin_changes().unwrap();
        let (capture, selected) = storage
            .take_checkpoint_changes(Some(candidate.clone()))
            .unwrap();
        capture.validate(&|| Ok(())).unwrap();
        storage
            .business
            .publish_checkpoint_snapshot(selected.unwrap())
            .unwrap();
        let suffix = [
            ordinary(&signed, 5, SessionMutationIntent::AdvanceLogicalTime),
            ordinary(&signed, 6, SessionMutationIntent::AdvanceLogicalTime),
        ];
        let vote = Vote::new_committed(9, node_id());
        for operation in [
            Operation::Vote(vote),
            append(&suffix),
            Operation::Committed(Some(log_id(5))),
            Operation::Purge(log_id(2)),
        ] {
            storage
                .log
                .project(&operation, &storage.business, Some(log_id(4)))
                .unwrap();
        }
        {
            let conn = oracle.conn.blocking_lock();
            save_current_snapshot_sync(
                &conn,
                signed.identity,
                &candidate.0,
                &candidate.1,
                candidate.2,
                candidate.3,
            )
            .unwrap();
            save_vote_sync(&conn, signed.identity, &vote).unwrap();
            append_logs_sync(&conn, signed.identity, &suffix).unwrap();
            save_committed_sync(&conn, signed.identity, Some(log_id(5))).unwrap();
            purge_logs_with_authority_sync(
                &conn,
                signed.identity,
                ConsensusAuthorityProfile::FixedImmutable,
                &fixed_members(),
                &test_member_bindings(&fixed_members()),
                FIXED_TEST_PLACEMENT_POLICY,
                &log_id(2),
            )
            .unwrap();
        }
        storage.validate_image().unwrap();
        let mut storage = Some(storage);
        for cold in [false, true] {
            if cold {
                storage = Some(frozen(
                    storage.take().unwrap(),
                    directory.path(),
                    root,
                    &signed,
                ));
            }
            let storage = storage.as_ref().unwrap();
            if cold {
                assert_eq!(storage.cold_counts_for_test()[2], 7);
            }
            let output = copy(&template);
            storage
                .export_cold_install_base_checked(&output, &|| Ok(()))
                .unwrap();
            assert_eq!(
                database(&output),
                database(&oracle.conn.blocking_lock()),
                "every predecessor schema object, column and canonical body"
            );
            assert_eq!(
                read_applied_sync(&output, signed.identity).unwrap(),
                Some(log_id(4))
            );
            assert_eq!(
                read_committed_sync(&output, signed.identity).unwrap(),
                Some(log_id(5))
            );
            assert_eq!(
                read_purged_sync(&output, signed.identity).unwrap(),
                Some(log_id(2))
            );
            assert_eq!(
                read_vote_sync(&output, signed.identity).unwrap(),
                Some(vote)
            );
            assert_eq!(
                read_current_snapshot_sync(&output, signed.identity).unwrap(),
                Some(candidate.clone())
            );
            assert_eq!(
                count(&output, "consensus_log"),
                7,
                "covered, applied, committed-unapplied and uncommitted rows all survive"
            );
            validate_fixed_durable_state_sync(&output, signed.identity, &fixed_members()).unwrap();
            validate_protected_roster_recovery_state_sync(&output, signed.identity).unwrap();
            super::import::roundtrip(&output, root, &signed);
            let portable = copy(&template);
            storage
                .export_cold_snapshot_checked(&portable, &|| Ok(()))
                .unwrap();
            assert_eq!(
                read_committed_sync(&portable, signed.identity).unwrap(),
                Some(log_id(4))
            );
            assert_eq!(count(&portable, "consensus_log"), 5);
            assert!(read_purged_sync(&portable, signed.identity)
                .unwrap()
                .is_none());
            assert!(read_current_snapshot_sync(&portable, signed.identity)
                .unwrap()
                .is_none());
            assert_eq!(storage.business.applied(), Some(log_id(4)));
            assert_eq!(storage.log.committed, Some(log_id(5)));
        }
    }
}

#[test]
fn native_roster_install_base_unapplied_copy_rejects_wrong_root_and_rolls_back_cancellation() {
    let signed = roster_v2_fresh_wal_persistence_fixture(Phase::Established);
    let oracle = SqliteSessionBackend::in_memory().unwrap();
    initialize(&oracle, &signed);
    let template = copy(&oracle.conn.blocking_lock());
    let mut storage = NativeStorage::empty_with_roster_root(
        signed.identity,
        fixed_members(),
        Some(Arc::new(signed.root.clone())),
    )
    .unwrap();
    let empty = copy(&template);
    storage
        .export_cold_install_base_checked(&empty, &|| Ok(()))
        .unwrap();
    assert_eq!(database(&empty), database(&template));
    let entries = [formation()];
    let vote = Vote::new_committed(2, node_id());
    for operation in [
        Operation::Vote(vote),
        append(&entries),
        Operation::Committed(Some(log_id(0))),
    ] {
        storage
            .log
            .project(&operation, &storage.business, None)
            .unwrap();
    }
    {
        let conn = oracle.conn.blocking_lock();
        save_vote_sync(&conn, signed.identity, &vote).unwrap();
        append_logs_sync(&conn, signed.identity, &entries).unwrap();
        save_committed_sync(&conn, signed.identity, Some(log_id(0))).unwrap();
    }
    let output = copy(&template);
    storage
        .export_cold_install_base_checked(&output, &|| Ok(()))
        .unwrap();
    assert_eq!(database(&output), database(&oracle.conn.blocking_lock()));
    assert_eq!(read_applied_sync(&output, signed.identity).unwrap(), None);
    assert_eq!(count(&output, "consensus_log"), 1);
    super::import::roundtrip(&output, [0xD9; 32], &signed);
    let failed = copy(&template);
    let before = database(&failed);
    let reached = Cell::new(false);
    let error = storage
        .export_cold_install_base_checked(&failed, &|| {
            if count(&failed, "consensus_log") == 1 {
                reached.set(true);
                return Err(io::Error::other("cancel complete install predecessor"));
            }
            Ok(())
        })
        .unwrap_err();
    assert!(reached.get());
    assert_eq!(error.to_string(), "cancel complete install predecessor");
    assert_eq!(database(&failed), before);
    for root in [None, Some(wrong_root(&signed))] {
        let backend = SqliteSessionBackend::in_memory().unwrap();
        let conn = backend.conn.blocking_lock();
        initialize_schema_with_storage_anchor_and_pending_and_bindings(
            &conn,
            None,
            signed.identity,
            &fixed_members(),
            &test_member_bindings(&fixed_members()),
            None,
            ConsensusAuthorityProfile::FixedImmutable,
            FIXED_TEST_PLACEMENT_POLICY,
            root.as_deref(),
        )
        .unwrap();
        conn.pragma_update(None, "query_only", true).unwrap();
        let before = database(&conn);
        assert_eq!(
            storage
                .export_cold_install_base_checked(&conn, &|| Ok(()))
                .unwrap_err()
                .to_string(),
            "native snapshot configured roster root differs from cold basis"
        );
        assert_eq!(database(&conn), before);
        assert!(conn
            .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
            .unwrap());
    }
    storage.validate_image().unwrap();
    assert!(storage.business.applied().is_none());
    assert_eq!(storage.log.committed, Some(log_id(0)));
}
