//! Native SQLite row/decoder components on private disk-backed WAL files.
//! This fixture is not retained-authority or real multi-node qualification.

use super::*;
use opc_consensus::engine::{CommittedLeaderId, Membership};
use std::ops::ControlFlow;

const PROFILE: ConfigCapacityProfile = ConfigCapacityProfile::BoundedV1;

fn identity() -> ConsensusIdentity {
    ConsensusIdentity::new(
        opc_consensus::ConsensusClusterId::from_bytes([0xB1; 32]),
        opc_consensus::ConsensusConfigurationId::from_bytes([0xB2; 32]),
        opc_consensus::ConsensusConfigurationEpoch::new(1).unwrap(),
    )
}
fn node() -> ConsensusNodeId {
    ConsensusNodeId::new(1).unwrap()
}
fn members(count: u64) -> BTreeSet<ConsensusNodeId> {
    (1..=count)
        .map(|id| ConsensusNodeId::new(id).unwrap())
        .collect()
}
fn entry(index: u64) -> Entry<ConfigRaftTypeConfig> {
    Entry {
        log_id: LogId::new(CommittedLeaderId::new(1, node()), index),
        payload: EntryPayload::Blank,
    }
}
fn fixture(count: u64) -> (tempfile::TempDir, Connection) {
    let directory = tempfile::tempdir().unwrap();
    let conn = Connection::open(directory.path().join("log.sqlite")).unwrap();
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=EXTRA;")
        .unwrap();
    assert!(crate::schema::verify_wal_mode(&conn).unwrap());
    assert!(crate::schema::verify_synchronous_extra(&conn).unwrap());
    conn.execute_batch(CONFIG_RAFT_SCHEMA).unwrap();
    let tx = Transaction::new_unchecked(&conn, TransactionBehavior::Immediate).unwrap();
    for index in 0..count {
        tx.execute(
            "INSERT INTO config_raft_log VALUES (?1, 1, 1, ?2)",
            params![index as i64, serde_json::to_vec(&entry(index)).unwrap()],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    (directory, conn)
}
fn read(cancellation: &SqliteWorkCancellation) -> LogRowRead<'_> {
    LogRowRead {
        start: 0,
        end: None,
        limit: None,
        cancellation: Some(cancellation),
        append_entries_batch: false,
        capacity_profile: PROFILE,
    }
}

#[test]
fn config_capacity_native_log_validation_streams_rows_and_honors_cancellation() {
    let (_directory, conn) = fixture(257);
    let key = AuditKey::new([0xB3; 32]).unwrap();
    validate_durable_log_state_sync(
        &conn,
        identity(),
        &members(1),
        &key,
        PROFILE,
        false,
        &SqliteWorkCancellation::new(),
    )
    .unwrap();
    let cancellation = SqliteWorkCancellation::new();
    let mut visited = 0;
    let result = visit_log_rows_unchecked_sync(
        &conn,
        identity(),
        &members(1),
        read(&cancellation),
        |entry| {
            assert_eq!(entry.log_id.index, visited);
            visited += 1;
            assert!(cancellation.cancel_before_commit());
            Ok(ControlFlow::Continue(()))
        },
    );
    assert_eq!(
        visited, 1,
        "the next row is not materialized before this callback"
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    assert_eq!(
        conn.query_row("SELECT COUNT(*) FROM config_raft_log", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        257
    );

    let mut visited = 0;
    visit_log_rows_unchecked_sync(
        &conn,
        identity(),
        &members(1),
        read(&SqliteWorkCancellation::new()),
        |_| {
            visited += 1;
            Ok(ControlFlow::Break(()))
        },
    )
    .unwrap();
    assert_eq!(visited, 1);
    conn.execute("DELETE FROM config_raft_log WHERE log_index = 128", [])
        .unwrap();
    assert!(validate_durable_log_state_sync(
        &conn,
        identity(),
        &members(1),
        &key,
        PROFILE,
        false,
        &SqliteWorkCancellation::new()
    )
    .is_err());
}

#[test]
fn config_capacity_native_log_reads_use_independent_profile_and_preserve_lineage() {
    let (_directory, conn) = fixture(2);
    let mut source = entry(1);
    source.payload = EntryPayload::Membership(Membership::new(vec![members(10)], ()));
    conn.execute(
        "UPDATE config_raft_log SET entry_json=?1 WHERE log_index=1",
        [serde_json::to_vec(&source).unwrap()],
    )
    .unwrap();
    assert_eq!(
        last_log_sync(&conn, identity(), ConfigCapacityProfile::Legacy).unwrap(),
        Some(source.log_id)
    );
    assert!(last_log_sync(&conn, identity(), PROFILE).is_err());
    assert!(read_log_id_at_sync(&conn, identity(), 1, PROFILE).is_err());
    assert!(read_log_range_sync(&conn, identity(), &members(10), 0, None, None, PROFILE).is_err());
    assert!(read_log_range_sync(
        &conn,
        identity(),
        &members(10),
        0,
        None,
        None,
        ConfigCapacityProfile::Legacy
    )
    .is_ok());
    assert!(save_committed_sync(&conn, identity(), Some(source.log_id), PROFILE).is_err());
    assert_eq!(read_committed_sync(&conn, identity()).unwrap(), None);
    // A stale row scalar cannot substitute for the serialized entry's lineage.
    conn.execute("UPDATE config_raft_log SET term=2 WHERE log_index=1", [])
        .unwrap();
    assert!(last_log_sync(&conn, identity(), ConfigCapacityProfile::Legacy).is_err());
}

#[test]
fn config_capacity_native_metadata_readers_bound_before_owned_column_copies() {
    let (_directory, conn) = fixture(0);
    let stored =
        StoredMembership::new(Some(entry(0).log_id), Membership::new(vec![members(1)], ()));
    conn.execute(
        "INSERT INTO config_raft_membership VALUES (1, 1, ?1)",
        [serde_json::to_vec(&stored).unwrap()],
    )
    .unwrap();
    assert_eq!(
        read_membership_sync(&conn, identity(), &members(1), PROFILE).unwrap(),
        stored
    );
    let mut meta = SnapshotMeta {
        last_log_id: Some(entry(0).log_id),
        last_membership: stored,
        snapshot_id: "x".repeat(128),
    };
    save_current_snapshot_sync(
        &conn,
        identity(),
        &members(1),
        &meta,
        "snapshot-test.opc",
        [0xB4; 32],
        128,
    )
    .unwrap();
    assert_eq!(
        read_current_snapshot_sync(&conn, identity(), &members(1), PROFILE)
            .unwrap()
            .unwrap()
            .0,
        meta
    );
    meta.snapshot_id.push('x');
    conn.execute(
        "UPDATE config_raft_snapshot SET meta_json=?1",
        [serde_json::to_vec(&meta).unwrap()],
    )
    .unwrap();
    assert!(read_current_snapshot_sync(&conn, identity(), &members(1), PROFILE).is_err());
    assert!(read_snapshot_log_id_unchecked_sync(&conn, identity(), PROFILE).is_err());
    assert!(read_current_snapshot_sync(
        &conn,
        identity(),
        &members(1),
        ConfigCapacityProfile::Legacy
    )
    .is_ok());
    conn.execute(
        "UPDATE config_raft_snapshot SET file_name=?1",
        ["x".repeat(256)],
    )
    .unwrap();
    assert!(read_current_snapshot_sync(&conn, identity(), &members(1), PROFILE).is_err());
    conn.execute(
        "UPDATE config_raft_membership SET membership_json=zeroblob(16777217)",
        [],
    )
    .unwrap();
    assert!(read_membership_unchecked_sync(&conn, identity(), PROFILE).is_err());
}
