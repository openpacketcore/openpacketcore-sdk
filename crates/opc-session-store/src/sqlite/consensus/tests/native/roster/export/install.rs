use super::install_base::copy;
use super::*;
use crate::consensus::native::generation::{
    Catalog, PreparedBase, PreparedDelta, SqlitePreparedBase, Version,
};
use crate::consensus::native::prefix::PrefixIdentity;
use crate::sqlite::consensus::tests::sequential_wal::IncomingSnapshot;
use crate::sqlite::consensus::wal::{snapshot::NativeSnapshotAuthority, Binding};
use crate::sqlite::ops::RestoreScanIncarnation;
use opc_consensus::engine::Vote;
use std::io::Write;

#[path = "validated_source.rs"]
mod validated_source;

const MAXIMUM: u64 = crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES;
const BLOCK: usize = 64 * 1024;
const CUT: [u8; 32] = [0xEA; 32];

fn empty(signed: &RosterV2PersistenceFixture) -> SqliteSessionBackend {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    initialize(&backend, signed);
    backend
}

fn install(
    source: &IncomingSnapshot,
    conn: &Connection,
    binding: Binding,
    signed: &RosterV2PersistenceFixture,
) -> Arc<NativeSnapshotAuthority> {
    source
        .source()
        .unwrap()
        .apply_native_original(
            conn,
            binding,
            Some(&signed.root),
            &RestoreScanIncarnation::new().unwrap(),
            &|| Ok(()),
        )
        .unwrap()
}

fn written(
    conn: &mut Connection,
    path: &Path,
    binding: Binding,
    origin: Arc<NativeSnapshotAuthority>,
    signed: &RosterV2PersistenceFixture,
) -> PrefixIdentity {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .unwrap();
    let prepared = SqlitePreparedBase::prepare_with_origin(
        conn,
        signed.identity,
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        FIXED_TEST_PLACEMENT_POLICY.unwrap(),
        Some(&signed.root),
        Some(origin),
        binding.digest().unwrap(),
        1,
        1,
        0,
        CUT,
        BLOCK,
        MAXIMUM,
        &|| Ok(()),
    )
    .unwrap();
    let mut output = io::BufWriter::new(&mut file);
    let prefix = prepared.write_to(&mut output, &|| Ok(())).unwrap();
    output.flush().unwrap();
    drop(output);
    file.sync_all().unwrap();
    prefix
}

fn admitted(
    path: &Path,
    prefix: PrefixIdentity,
    origin: Arc<NativeSnapshotAuthority>,
    signed: &RosterV2PersistenceFixture,
) -> NativeStorage {
    let (_owner, catalog) = Catalog::open_with_origin(
        path,
        prefix,
        MAXIMUM,
        crate::consensus::native::generation::CatalogScope {
            identity: signed.identity,
            members: &fixed_members(),
            roster_root: Some(Arc::new(signed.root.clone())),
        },
        Some(origin),
        CUT,
        &|| Ok(()),
    )
    .unwrap();
    let storage = catalog.into_storage(&|| Ok(())).unwrap();
    storage.validate_image().unwrap();
    storage
}

fn complete_equal(conn: &Connection, storage: &NativeStorage, signed: &RosterV2PersistenceFixture) {
    let target = empty(signed);
    storage
        .export_cold_install_base_checked(&target.conn.blocking_lock(), &|| Ok(()))
        .unwrap();
    assert!(database(&target.conn.blocking_lock()) == database(conn),"installed native bases preserve every column including the local restore identity without normalization");
}

#[test]
fn native_snapshot_origin_original_install_preserves_local_vote_suffix_and_every_business_column() {
    for phase in [Phase::Established, Phase::Aborted] {
        for retained in [false, true] {
            let (directory, producer, signed, wal) = fresh(phase);
            parity(
                &wal,
                &producer,
                &signed,
                &[admission(&signed), terminal(&signed, 4)],
            );
            let incoming =
                IncomingSnapshot::with_identity(&producer.conn.blocking_lock(), signed.identity);
            assert_eq!(
                count(&Connection::open(&incoming.raw).unwrap(), "consensus_log"),
                0,
                "portable input contains no Raft log witnesses"
            );
            let local = empty(&signed);
            let suffix = [
                ordinary(&signed, 5, SessionMutationIntent::AdvanceLogicalTime),
                ordinary(&signed, 6, SessionMutationIntent::AdvanceLogicalTime),
            ];
            if retained {
                sql_apply(&local, &signed, &setup(&signed));
                let entries = [
                    admission(&signed),
                    terminal(&signed, 4),
                    suffix[0].clone(),
                    suffix[1].clone(),
                ];
                append_logs_with_authority_sync(
                    &local.conn.blocking_lock(),
                    signed.identity,
                    ConsensusAuthorityProfile::FixedImmutable,
                    &fixed_members(),
                    &test_member_bindings(&fixed_members()),
                    FIXED_TEST_PLACEMENT_POLICY,
                    &entries,
                )
                .unwrap();
            }
            let vote = Vote::new_committed(9, node_id());
            save_vote_sync(&local.conn.blocking_lock(), signed.identity, &vote).unwrap();
            let before = database(&local.conn.blocking_lock());
            let mut installed = copy(&local.conn.blocking_lock());
            let origin = install(&incoming, &installed, wal.binding(), &signed);
            assert_eq!(
                database(&local.conn.blocking_lock()),
                before,
                "only the disposable predecessor is installed"
            );
            assert_eq!(
                read_vote_sync(&installed, signed.identity).unwrap(),
                Some(vote)
            );
            assert_eq!(
                read_applied_sync(&installed, signed.identity).unwrap(),
                Some(log_id(4))
            );
            assert_eq!(
                read_committed_sync(&installed, signed.identity).unwrap(),
                Some(log_id(4))
            );
            assert_eq!(
                read_purged_sync(&installed, signed.identity).unwrap(),
                Some(log_id(4))
            );
            assert_eq!(
                count(&installed, "consensus_log"),
                if retained { 2 } else { 0 }
            );
            let path = directory.path().join("installed.native");
            let prefix = written(
                &mut installed,
                &path,
                wal.binding(),
                Arc::clone(&origin),
                &signed,
            );
            assert!(
                Catalog::open(
                    &path,
                    prefix,
                    MAXIMUM,
                    crate::consensus::native::generation::CatalogScope {
                        identity: signed.identity,
                        members: &fixed_members(),
                        roster_root: Some(Arc::new(signed.root.clone()))
                    },
                    CUT,
                    &|| Ok(()),
                )
                .is_err(),
                "serialized metadata cannot admit a foreign snapshot or missing membership"
            );
            let mut storage = admitted(&path, prefix, origin, &signed);
            complete_equal(&installed, &storage, &signed);
            assert!(
                serde_json::to_vec(&storage.business).is_err(),
                "legacy images cannot silently drop installed authority"
            );
            let mut changed = incoming.candidate.clone();
            changed.0.snapshot_id.push_str("-substituted");
            assert!(
                storage.validate_snapshot(&changed).is_err(),
                "same cut with different metadata is not the admitted incoming snapshot"
            );
            changed = incoming.candidate.clone();
            changed.0.last_log_id.as_mut().unwrap().leader_id.term += 1;
            assert!(
                storage.validate_snapshot(&changed).is_err(),
                "the complete LogId remains exact"
            );
            if retained {
                storage.begin_changes().unwrap();
                storage
                    .log
                    .project(
                        &Operation::Committed(Some(log_id(5))),
                        &storage.business,
                        Some(log_id(4)),
                    )
                    .unwrap();
                storage.replay_committed().unwrap();
                let capture = storage.take_changes().unwrap();
                capture.validate(&|| Ok(())).unwrap();
                assert_eq!(storage.business.applied(), Some(log_id(5)));
                storage.validate_image().unwrap();
            }
            wal.shutdown().unwrap();
        }
    }
}

#[test]
fn native_snapshot_origin_rejects_wrong_local_root_and_other_local_generation() {
    let (directory, producer, signed, wal) = fresh(Phase::Established);
    parity(&wal, &producer, &signed, &[admission(&signed)]);
    let incoming = IncomingSnapshot::with_identity(&producer.conn.blocking_lock(), signed.identity);
    let local = empty(&signed);
    let before = database(&local.conn.blocking_lock());
    for root in [None, Some(wrong_root(&signed))] {
        let conn = copy(&local.conn.blocking_lock());
        assert!(incoming
            .source()
            .unwrap()
            .apply_native_original(
                &conn,
                wal.binding(),
                root.as_deref(),
                &RestoreScanIncarnation::new().unwrap(),
                &|| Ok(())
            )
            .is_err());
        assert_eq!(database(&conn), before);
    }
    let mut installed = copy(&local.conn.blocking_lock());
    let origin = install(&incoming, &installed, wal.binding(), &signed);
    let path = directory.path().join("installed.native");
    let prefix = written(
        &mut installed,
        &path,
        wal.binding(),
        Arc::clone(&origin),
        &signed,
    );
    let mut other = wal.binding();
    other.generation[0] ^= 1;
    let other_origin = install(
        &incoming,
        &copy(&local.conn.blocking_lock()),
        other,
        &signed,
    );
    let before_files = files(directory.path());
    assert!(Catalog::open_with_origin(
        &path,
        prefix,
        MAXIMUM,
        crate::consensus::native::generation::CatalogScope {
            identity: signed.identity,
            members: &fixed_members(),
            roster_root: Some(Arc::new(signed.root.clone()))
        },
        Some(other_origin),
        CUT,
        &|| Ok(()),
    )
    .is_err());
    assert!(Catalog::open_with_origin(
        &path,
        prefix,
        MAXIMUM,
        crate::consensus::native::generation::CatalogScope {
            identity: signed.identity,
            members: &fixed_members(),
            roster_root: Some(wrong_root(&signed))
        },
        Some(origin),
        CUT,
        &|| Ok(()),
    )
    .is_err());
    assert_eq!(
        files(directory.path()),
        before_files,
        "failed admission cannot repair or publish files"
    );
    wal.shutdown().unwrap();
}

#[test]
fn native_snapshot_origin_requires_original_source_metadata_and_continuously_pinned_envelope() {
    let (directory, producer, signed, wal) = fresh(Phase::Established);
    parity(&wal, &producer, &signed, &[admission(&signed)]);
    let mut incoming =
        IncomingSnapshot::with_identity(&producer.conn.blocking_lock(), signed.identity);
    let original = incoming.candidate.clone();
    let local = empty(&signed);
    let before = database(&local.conn.blocking_lock());
    incoming.candidate.0.last_log_id.as_mut().unwrap().index += 1;
    let conn = copy(&local.conn.blocking_lock());
    assert!(incoming
        .source()
        .unwrap()
        .apply_native_original(
            &conn,
            wal.binding(),
            Some(&signed.root),
            &RestoreScanIncarnation::new().unwrap(),
            &|| Ok(())
        )
        .is_err());
    assert_eq!(
        database(&conn),
        before,
        "invalid original metadata rolls back the disposable install"
    );
    incoming.candidate = original;
    let mut installed = copy(&local.conn.blocking_lock());
    let origin = install(&incoming, &installed, wal.binding(), &signed);
    let path = directory.path().join("installed.native");
    let prefix = written(
        &mut installed,
        &path,
        wal.binding(),
        Arc::clone(&origin),
        &signed,
    );
    let replacement = directory.path().join("replacement.opc");
    fs::write(&replacement, fs::read(&incoming.published).unwrap()).unwrap();
    fs::rename(&replacement, &incoming.published).unwrap();
    assert!(
        origin.verify().is_err(),
        "identical bytes in a substituted inode do not retain the original admission"
    );
    let before_files = files(directory.path());
    assert!(Catalog::open_with_origin(
        &path,
        prefix,
        MAXIMUM,
        crate::consensus::native::generation::CatalogScope {
            identity: signed.identity,
            members: &fixed_members(),
            roster_root: Some(Arc::new(signed.root.clone()))
        },
        Some(origin),
        CUT,
        &|| Ok(()),
    )
    .is_err());
    assert_eq!(files(directory.path()), before_files);
    wal.shutdown().unwrap();
}

#[test]
fn native_snapshot_origin_rejects_oversized_candidate_before_reading_or_writing_predecessor() {
    let (_directory, producer, signed, wal) = fresh(Phase::Established);
    let mut incoming =
        IncomingSnapshot::with_identity(&producer.conn.blocking_lock(), signed.identity);
    let local = empty(&signed);
    let before = database(&local.conn.blocking_lock());
    for length in [257, 4 * 1024 * 1024] {
        incoming.candidate.0.snapshot_id = "x".repeat(length);
        let source = incoming.source().unwrap();
        let mut conn = copy(&local.conn.blocking_lock());
        conn.pragma_update(None, "query_only", true).unwrap();
        let checks = std::cell::Cell::new(0);
        let error = match source.apply_native_original(
            &conn,
            wal.binding(),
            Some(&signed.root),
            &RestoreScanIncarnation::new().unwrap(),
            &|| {
                checks.set(checks.get() + 1);
                Ok(())
            },
        ) {
            Err(error) => error,
            Ok(_) => panic!("oversized candidate obtained installed authority"),
        };
        assert_eq!(
            error.to_string(),
            "native current snapshot metadata invalid"
        );
        assert_eq!(
            checks.get(),
            1,
            "reject before SQL row preflight and the original allocating transaction"
        );
        assert!(conn
            .pragma_query_value(None, "query_only", |row| row.get::<_, bool>(0))
            .unwrap());
        assert_eq!(database(&conn), before);
        // The same early metadata error must be independent of SQL authority.
        conn = Connection::open_in_memory().unwrap();
        assert_eq!(
            source
                .apply_native_original(
                    &conn,
                    wal.binding(),
                    Some(&signed.root),
                    &RestoreScanIncarnation::new().unwrap(),
                    &|| Ok(())
                )
                .err()
                .unwrap()
                .to_string(),
            "native current snapshot metadata invalid"
        );
    }
    wal.shutdown().unwrap();
}

#[test]
fn native_snapshot_origin_cold_rewrite_and_original_portable_reexport_preserve_authority() {
    let (directory, producer, signed, wal) = fresh(Phase::Established);
    parity(
        &wal,
        &producer,
        &signed,
        &[admission(&signed), terminal(&signed, 4)],
    );
    let incoming = IncomingSnapshot::with_identity(&producer.conn.blocking_lock(), signed.identity);
    let local = empty(&signed);
    let mut installed = copy(&local.conn.blocking_lock());
    let origin = install(&incoming, &installed, wal.binding(), &signed);
    let path = directory.path().join("installed.native");
    let prefix = written(
        &mut installed,
        &path,
        wal.binding(),
        Arc::clone(&origin),
        &signed,
    );
    let storage = admitted(&path, prefix, Arc::clone(&origin), &signed);
    let next_path = directory.path().join("next.native");
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&next_path)
        .unwrap();
    let prepared = PreparedBase::prepare(
        &storage,
        crate::consensus::native::generation::BaseParameters {
            binding: wal.binding().digest().unwrap(),
            file_epoch: 2,
            checkpoint_epoch: 2,
            operation_sequence: 0,
            cut_binding: CUT,
            block_bytes: BLOCK,
            maximum: MAXIMUM,
        },
        &|| Ok(()),
    )
    .unwrap();
    let mut output = io::BufWriter::new(&mut file);
    let next = prepared.write_to(&mut output, &|| Ok(())).unwrap();
    output.flush().unwrap();
    drop(output);
    drop(prepared);
    file.sync_all().unwrap();
    drop(file);
    drop(storage);
    let storage = admitted(&next_path, next, Arc::clone(&origin), &signed);
    complete_equal(&installed, &storage, &signed);
    let target = empty(&signed);
    storage
        .export_cold_snapshot_checked(&target.conn.blocking_lock(), &|| Ok(()))
        .unwrap();
    let reexport = IncomingSnapshot::with_identity(&target.conn.blocking_lock(), signed.identity);
    assert_eq!(
        reexport.candidate.0.last_log_id,
        incoming.candidate.0.last_log_id
    );
    assert_eq!(
        reexport.candidate.0.last_membership,
        incoming.candidate.0.last_membership
    );
    let second = install(
        &reexport,
        &copy(&local.conn.blocking_lock()),
        wal.binding(),
        &signed,
    );
    assert!(
        Catalog::open_with_origin(
            &path,
            prefix,
            MAXIMUM,
            crate::consensus::native::generation::CatalogScope {
                identity: signed.identity,
                members: &fixed_members(),
                roster_root: Some(Arc::new(signed.root.clone()))
            },
            Some(second),
            CUT,
            &|| Ok(()),
        )
        .is_err(),
        "a newer current snapshot cannot stand in for the original generation source"
    );
    origin.verify().unwrap();
    wal.shutdown().unwrap();
}

#[test]
fn native_snapshot_origin_empty_source_repeated_install_cold_reopen_and_first_membership() {
    let directory = tempfile::tempdir().unwrap();
    let signed = roster_v2_fresh_wal_persistence_fixture(Phase::Established);
    let local = empty(&signed);
    let wal = Wal::create_native_with_root(
        &directory.path().join("wal"),
        &local.conn.blocking_lock(),
        signed.identity,
        [0xEB; 32],
        Some(Arc::new(signed.root.clone())),
        Limits::default(),
        IoControl::default(),
    )
    .unwrap();
    let mut incoming =
        IncomingSnapshot::with_identity(&local.conn.blocking_lock(), signed.identity);
    assert!(incoming.candidate.0.last_log_id.is_none());
    let original = incoming.candidate.clone();
    for malformed in 0..2 {
        if malformed == 0 {
            incoming.candidate.0.last_log_id = Some(log_id(0));
        } else {
            incoming.candidate.0.last_membership = opc_consensus::engine::StoredMembership::new(
                None,
                opc_consensus::engine::Membership::new(vec![fixed_members()], fixed_members()),
            );
        }
        let conn = copy(&local.conn.blocking_lock());
        let before = database(&conn);
        assert!(
            incoming
                .source()
                .unwrap()
                .apply_native_original(
                    &conn,
                    wal.binding(),
                    Some(&signed.root),
                    &RestoreScanIncarnation::new().unwrap(),
                    &|| Ok(())
                )
                .is_err(),
            "empty admission still binds exact source metadata and membership shape"
        );
        assert_eq!(database(&conn), before);
        incoming.candidate = original.clone();
    }
    let mut installed = copy(&local.conn.blocking_lock());
    let mut last = None;
    for round in 0..2 {
        let origin = install(&incoming, &installed, wal.binding(), &signed);
        assert!(read_applied_sync(&installed, signed.identity)
            .unwrap()
            .is_none());
        assert!(read_committed_sync(&installed, signed.identity)
            .unwrap()
            .is_none());
        assert!(read_purged_sync(&installed, signed.identity)
            .unwrap()
            .is_none());
        let path = directory.path().join(format!("empty-{round}.native"));
        let prefix = written(
            &mut installed,
            &path,
            wal.binding(),
            Arc::clone(&origin),
            &signed,
        );
        assert_eq!(prefix.operation_sequence, 0);
        let storage = admitted(&path, prefix, Arc::clone(&origin), &signed);
        complete_equal(&installed, &storage, &signed);
        assert!(storage.business.applied().is_none());
        assert!(Catalog::open(
            &path,
            prefix,
            MAXIMUM,
            crate::consensus::native::generation::CatalogScope {
                identity: signed.identity,
                members: &fixed_members(),
                roster_root: Some(Arc::new(signed.root.clone()))
            },
            CUT,
            &|| Ok(()),
        )
        .is_err());
        last = Some((path, prefix, origin));
    }
    let (path, prefix, origin) = last.unwrap();
    let (mut owner, catalog) = Catalog::open_with_origin(
        &path,
        prefix,
        MAXIMUM,
        crate::consensus::native::generation::CatalogScope {
            identity: signed.identity,
            members: &fixed_members(),
            roster_root: Some(Arc::new(signed.root.clone())),
        },
        Some(Arc::clone(&origin)),
        CUT,
        &|| Ok(()),
    )
    .unwrap();
    let mut storage = catalog.into_storage(&|| Ok(())).unwrap();
    let version = Version::capture(&storage).unwrap();
    storage.begin_changes().unwrap();
    storage
        .log
        .project(&append(&[formation()]), &storage.business, None)
        .unwrap();
    storage
        .log
        .project(
            &Operation::Committed(Some(log_id(0))),
            &storage.business,
            None,
        )
        .unwrap();
    storage.replay_committed().unwrap();
    assert_eq!(storage.business.applied(), Some(log_id(0)));
    assert_eq!(
        storage.business.current_snapshot(),
        Some(incoming.candidate)
    );
    let prepared = PreparedDelta::prepare(
        owner.current(),
        &version,
        2,
        3,
        CUT,
        storage.take_changes().unwrap(),
        &|| Ok(()),
    )
    .unwrap();
    prepared.append(&mut owner, &|| Ok(())).unwrap();
    let selected = owner.current().identity();
    drop(prepared);
    drop(storage);
    drop(owner);
    let storage = admitted(&path, selected, origin, &signed);
    assert_eq!(storage.business.applied(), Some(log_id(0)));
    assert_eq!(storage.business.membership().log_id(), &Some(log_id(0)));
    storage.validate_image().unwrap();
    wal.shutdown().unwrap();
}

#[test]
fn native_snapshot_origin_logical_purge_keeps_exact_physical_prefix_through_export_and_cold_catalog(
) {
    let (directory, producer, signed, wal) = fresh(Phase::Established);
    parity(
        &wal,
        &producer,
        &signed,
        &[admission(&signed), terminal(&signed, 4)],
    );
    let incoming = IncomingSnapshot::with_identity(&producer.conn.blocking_lock(), signed.identity);
    let local = empty(&signed);
    let mut installed = copy(&local.conn.blocking_lock());
    let origin = install(&incoming, &installed, wal.binding(), &signed);
    assert!(origin.matches_cut(log_id(4)));
    let path = directory.path().join("installed-purge.native");
    let prefix = written(
        &mut installed,
        &path,
        wal.binding(),
        Arc::clone(&origin),
        &signed,
    );
    let (mut owner, catalog) = Catalog::open_with_origin(
        &path,
        prefix,
        MAXIMUM,
        crate::consensus::native::generation::CatalogScope {
            identity: signed.identity,
            members: &fixed_members(),
            roster_root: Some(Arc::new(signed.root.clone())),
        },
        Some(Arc::clone(&origin)),
        CUT,
        &|| Ok(()),
    )
    .unwrap();
    let mut storage = catalog.into_storage(&|| Ok(())).unwrap();
    let version = Version::capture(&storage).unwrap();
    storage.begin_changes().unwrap();
    let suffix =
        [5, 6, 7].map(|index| ordinary(&signed, index, SessionMutationIntent::AdvanceLogicalTime));
    storage
        .log
        .project(&append(&suffix), &storage.business, Some(log_id(4)))
        .unwrap();
    storage
        .log
        .project(
            &Operation::Committed(Some(log_id(7))),
            &storage.business,
            Some(log_id(4)),
        )
        .unwrap();
    storage.replay_committed().unwrap();
    // Purge admission must be backed by a genuinely selected applied basis,
    // not merely by a later live applied value supplied to the projector.
    let prepared = PreparedDelta::prepare(
        owner.current(),
        &version,
        2,
        2,
        CUT,
        storage.take_changes().unwrap(),
        &|| Ok(()),
    )
    .unwrap();
    prepared.append(&mut owner, &|| Ok(())).unwrap();
    let version = prepared.target_version();
    let applied_basis = owner.current().identity();
    drop(prepared);
    assert_eq!(
        admitted(&path, applied_basis, Arc::clone(&origin), &signed)
            .business
            .applied(),
        Some(log_id(7)),
        "independent cold admission proves the selected predecessor before purge"
    );
    storage
        .log
        .project(
            &Operation::Purge(log_id(6)),
            &storage.business,
            Some(log_id(7)),
        )
        .unwrap();
    assert_eq!(storage.log.purged, Some(log_id(6)));
    assert_eq!(
        storage.log.entries.keys().copied().collect::<Vec<_>>(),
        [5, 6, 7]
    );
    storage.validate_image().expect(
        "a logical purge preserves the physical suffix of the authenticated install origin",
    );
    let mut hole = storage.clone();
    hole.log.entries.remove(&5);
    assert!(
        hole.validate_image().is_err(),
        "an origin cannot authorize a missing first physical suffix row"
    );
    let target = empty(&signed);
    storage
        .export_cold_install_base_checked(&target.conn.blocking_lock(), &|| Ok(()))
        .unwrap();
    let exported = database(&target.conn.blocking_lock());
    let portable = empty(&signed);
    storage
        .export_cold_portable_snapshot_checked(&portable.conn.blocking_lock(), &|| Ok(()))
        .unwrap();
    assert_eq!(count(&portable.conn.blocking_lock(), "consensus_log"), 0);
    let prepared = PreparedDelta::prepare(
        owner.current(),
        &version,
        3,
        3,
        CUT,
        storage.take_changes().unwrap(),
        &|| Ok(()),
    )
    .unwrap();
    prepared.append(&mut owner, &|| Ok(())).unwrap();
    let selected = owner.current().identity();
    drop(prepared);
    drop(storage);
    drop(owner);
    let storage = admitted(&path, selected, Arc::clone(&origin), &signed);
    assert_eq!(storage.log.purged, Some(log_id(6)));
    assert_eq!(storage.business.applied(), Some(log_id(7)));
    assert_eq!(
        storage.log.entries.keys().copied().collect::<Vec<_>>(),
        [5, 6, 7]
    );
    let cold = empty(&signed);
    storage
        .export_cold_install_base_checked(&cold.conn.blocking_lock(), &|| Ok(()))
        .unwrap();
    assert_eq!(database(&cold.conn.blocking_lock()), exported);
    origin.verify().unwrap();
    wal.shutdown().unwrap();
}

#[test]
fn native_snapshot_origin_cold_catalog_rejects_present_wrong_log_id_and_membership_payload() {
    use sha2::{Digest as _, Sha256};
    #[derive(serde::Serialize)]
    struct LogContext {
        vote: Option<Vote<SessionConsensusNodeId>>,
        committed: Option<opc_consensus::engine::LogId<SessionConsensusNodeId>>,
        purged: Option<opc_consensus::engine::LogId<SessionConsensusNodeId>>,
        count: usize,
        content: [u8; 32],
        first: Option<opc_consensus::engine::LogId<SessionConsensusNodeId>>,
        last: Option<opc_consensus::engine::LogId<SessionConsensusNodeId>>,
    }
    let directory = tempfile::tempdir().unwrap();
    let signed = roster_v2_fresh_wal_persistence_fixture(Phase::Established);
    let local = empty(&signed);
    let wal = Wal::create_native_with_root(
        &directory.path().join("wal"),
        &local.conn.blocking_lock(),
        signed.identity,
        [0xEC; 32],
        Some(Arc::new(signed.root.clone())),
        Limits::default(),
        IoControl::default(),
    )
    .unwrap();
    let pristine = copy(&local.conn.blocking_lock());
    sql_apply(&local, &signed, &[formation()]);
    let incoming = IncomingSnapshot::with_identity(&local.conn.blocking_lock(), signed.identity);
    let mut installed = copy(&pristine);
    let origin = install(&incoming, &installed, wal.binding(), &signed);
    let path = directory.path().join("missing.native");
    let prefix = written(
        &mut installed,
        &path,
        wal.binding(),
        Arc::clone(&origin),
        &signed,
    );
    admitted(&path, prefix, Arc::clone(&origin), &signed);
    let original = fs::read(&path).unwrap();
    let length = u32::from_le_bytes(original[8..12].try_into().unwrap()) as usize;
    let header = std::str::from_utf8(&original[12..12 + length]).unwrap();
    assert_eq!(
        &original[12 + length..20 + length],
        b"OPCNJEND",
        "membership-only image has no materialized rows"
    );
    // Give each forged image correct framing, row/content/context hashes and
    // descriptor identity. Rejection must come from complete lineage, not a
    // stale checksum or count. Case zero is the retained-witness control.
    for case in 0..3 {
        let mut entry = formation();
        if case == 1 {
            entry.log_id.leader_id.term += 1;
        }
        if case == 2 {
            entry.payload = EntryPayload::Blank;
        }
        let encoded = encode_json(&entry).unwrap();
        let mut row_hash = Sha256::new();
        row_hash.update(b"OPC-native-log-row-v1\0");
        row_hash.update(0u64.to_le_bytes());
        row_hash.update((encoded.len() as u64).to_le_bytes());
        row_hash.update(&encoded);
        let log = LogContext {
            vote: None,
            committed: Some(log_id(0)),
            purged: Some(log_id(0)),
            count: 1,
            content: row_hash.finalize().into(),
            first: Some(entry.log_id),
            last: Some(entry.log_id),
        };
        let mut next_header = header[..header.rfind(",\"log\":").unwrap() + 7].to_owned();
        next_header.push_str(&serde_json::to_string(&log).unwrap());
        next_header.push_str("}}");
        let context =
            &next_header[next_header.find("\"context\":").unwrap() + 10..next_header.len() - 1];
        let mut context_hash = Sha256::new();
        context_hash.update(b"OPC-native-generation-context-v1\0");
        context_hash.update(context.as_bytes());
        let mut bytes = original[..8].to_vec();
        bytes.extend_from_slice(&(next_header.len() as u32).to_le_bytes());
        bytes.extend_from_slice(next_header.as_bytes());
        bytes.push(4);
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&[0, 1]);
        bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&encoded);
        bytes.extend_from_slice(b"OPCNJEND");
        bytes.resize(BLOCK, 0);
        let expected = PrefixIdentity {
            frontiers: context_hash.finalize().into(),
            digest: Sha256::digest(&bytes).into(),
            ..prefix
        };
        let path = directory.path().join(format!("retained-{case}.native"));
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let result = Catalog::open_with_origin(
            &path,
            expected,
            MAXIMUM,
            crate::consensus::native::generation::CatalogScope {
                identity: signed.identity,
                members: &fixed_members(),
                roster_root: Some(Arc::new(signed.root.clone())),
            },
            Some(Arc::clone(&origin)),
            CUT,
            &|| Ok(()),
        );
        if case == 0 {
            result
                .unwrap()
                .1
                .into_storage(&|| Ok(()))
                .unwrap()
                .validate_image()
                .unwrap();
        } else {
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("admitted a conflicting retained witness"),
            };
            assert_eq!(
                error.to_string(),
                if case == 1 {
                    "native log pointer lacks exact retained lineage"
                } else {
                    "native membership payload differs from exact log witness"
                }
            );
        }
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
    wal.shutdown().unwrap();
}
