use super::*;
use crate::consensus::native::generation::{Catalog, CatalogScope, SqlitePreparedBase};
use crate::sqlite::consensus::wal::async_authority::Reservation;
use std::fs;
use std::io::Write;

fn apply_native(storage: &mut NativeStorage, entries: &[Entry<SessionRaftTypeConfig>]) {
    storage
        .log
        .project(&append(entries), &storage.business, None)
        .unwrap();
    storage
        .log
        .project(
            &Operation::Committed(entries.last().map(|e| e.log_id)),
            &storage.business,
            None,
        )
        .unwrap();
    assert!(storage
        .business
        .apply(entries)
        .unwrap()
        .responses
        .iter()
        .all(|r| r.result.is_ok()));
    storage.validate_image().unwrap();
}

#[test]
fn native_async_boundary_portable_snapshot_roundtrip_preserves_retired_authority() {
    let mut storage = NativeStorage::empty(identity(), fixed_members()).unwrap();
    let request = fenced_transition_v2_request(0xD4, 1, "async-snapshot");
    apply_native(
        &mut storage,
        &[formation(), activation(1, request.clone(), timestamp(1))],
    );
    let floor = Reservation::initial().ceiling();
    let boundary = Entry {
        log_id: LogId::new(
            opc_consensus::engine::CommittedLeaderId::new(floor + 2, node_id()),
            2,
        ),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(),
            request_id: SessionConsensusRequestId::from_bytes([0xD5; 16]),
            logical_time: timestamp(2),
            intent: SessionMutationIntent::AsyncRecoveryBoundary {
                era: 2,
                plan: [0xD6; 32],
            },
        }),
    };
    apply_native(&mut storage, &[boundary]);
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let mut conn = backend.conn.blocking_lock();
    initialize_schema_with_profile(
        &conn,
        identity(),
        &fixed_members(),
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    storage
        .export_cold_snapshot_checked(&conn, &|| Ok(()))
        .unwrap();
    let boundary = crate::sqlite::consensus::async_recovery::read(&conn)
        .unwrap()
        .unwrap();
    assert_eq!(boundary.era, 2);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("recovered.native");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let prefix = {
        let prepared = SqlitePreparedBase::prepare(
            &mut conn,
            identity(),
            &fixed_members(),
            &test_member_bindings(&fixed_members()),
            FIXED_TEST_PLACEMENT_POLICY.unwrap(),
            None,
            [0xD7; 32],
            1,
            1,
            7,
            [0xD8; 32],
            64 * 1024,
            crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES,
            &|| Ok(()),
        )
        .unwrap();
        let mut writer = io::BufWriter::new(&mut file);
        let prefix = prepared.write_to(&mut writer, &|| Ok(())).unwrap();
        writer.flush().unwrap();
        prefix
    };
    file.sync_all().unwrap();
    drop(file);
    let (_owner, catalog) = Catalog::open(
        &path,
        prefix,
        crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES,
        CatalogScope {
            identity: identity(),
            members: &fixed_members(),
            roster_root: None,
        },
        [0xD8; 32],
        &|| Ok(()),
    )
    .unwrap();
    let cold = catalog.into_storage(&|| Ok(())).unwrap();
    cold.validate_image().unwrap();
    assert_eq!(
        cold.business
            .history_state()
            .unwrap()
            .retired_through()
            .unwrap()
            .get(),
        floor
    );
    assert!(matches!(
        cold.business.status(&request).unwrap(),
        FencedTransitionV2Status::Retired
    ));
    assert!(
        cold.business
            .observe_at(request.lease().key(), timestamp(2))
            .unwrap()
            .current_fence()
            .get()
            >= floor
    );
    assert!(matches!(
        cold.business.replication_log(1, 1, &|| Ok(())),
        Err(StoreError::ReplicationLogCursorCompacted { .. })
    ));
}

#[test]
fn native_async_boundary_snapshot_schema_and_downgrade_fail_closed() {
    let mut conn = Connection::open_in_memory().unwrap();
    let floor = Reservation::initial().ceiling();
    let json = serde_json::json!({"era":2,"plan":[212,212],"applied":{"leader_id":{"term":floor+2,"node_id":7},"index":2}});
    // Arbitrary tables/views and unbounded carrier values are rejected before
    // a recovery boundary can be read as native metadata.
    conn.execute_batch(
        "CREATE VIEW consensus_async_recovery AS SELECT 1 AS singleton, zeroblob(2049) AS boundary",
    )
    .unwrap();
    assert!(crate::sqlite::consensus::async_recovery::read(&conn).is_err());
    conn.execute_batch("DROP VIEW consensus_async_recovery")
        .unwrap();
    let boundary = crate::consensus::native::async_recovery::Boundary::from_entry(
        2,
        [0xD4; 32],
        LogId::new(
            opc_consensus::engine::CommittedLeaderId::new(floor + 2, node_id()),
            2,
        ),
    );
    let tx = conn.transaction().unwrap();
    crate::sqlite::consensus::async_recovery::write(&tx, Some(&boundary)).unwrap();
    tx.commit().unwrap();
    assert!(crate::sqlite::consensus::async_recovery::transition(Some(&boundary), None).is_err());
    let mut conflict = boundary.clone();
    conflict.plan[0] ^= 1;
    assert!(
        crate::sqlite::consensus::async_recovery::transition(Some(&boundary), Some(&conflict))
            .is_err()
    );
    conn.execute(
        "UPDATE consensus_async_recovery SET boundary=?1",
        [serde_json::to_vec(&json).unwrap()],
    )
    .unwrap();
    assert!(crate::sqlite::consensus::async_recovery::read(&conn).is_err());
}
