//! Committed native notification windows survive portable and cold catalogs.

use super::*;
use crate::consensus::native::generation::{Catalog, CatalogScope, SqlitePreparedBase};
use std::io::Write;

#[test]
fn canonical_native_notification_history_round_trips_through_cold_native_catalog() {
    const HEAD: u64 = 65_537;
    let fixture = Fixture::new();
    let clock = Entry {
        log_id: log_id(1),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(),
            request_id: SessionConsensusRequestId::from_bytes([0xB5; 16]),
            logical_time: timestamp(1),
            intent: SessionMutationIntent::Authorized {
                origin: node_id(),
                authority_identity: identity(),
                mutation: Box::new(SessionMutationIntent::AdvanceLogicalTime),
            },
        }),
    };
    assert!(fixture
        .parity(&[formation(), clock])
        .responses
        .iter()
        .all(|r| r.result.is_ok()));
    let mut conn = fixture.oracle.conn.blocking_lock();
    let tx = Transaction::new_unchecked(&conn, TransactionBehavior::Immediate).unwrap();
    for sequence in 2..=HEAD {
        let row = sealed_audit_fixture_row(sequence);
        tx.execute("INSERT INTO session_replication_log(sequence,tx_id,entry_json,timestamp) VALUES(?1,?2,?3,?4)",
            params![row.sequence, row.tx_id, row.encoded, crate::sqlite::ops::format_rfc3339_normalized(timestamp(1))]).unwrap();
    }
    tx.execute("UPDATE consensus_machine SET watch_sequence=?1", [HEAD])
        .unwrap();
    let retention = crate::consensus::native::retention::Retention {
        watch_retired_through: 1,
        ..Default::default()
    };
    native_retention::write(&tx, retention).unwrap();
    tx.commit().unwrap();
    validate_sealed_state_sync(&conn).expect("the exact committed native prefix is valid");
    assert_eq!(read_watch_cursor_invalidation_floor_sync(&conn).unwrap(), 0);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("retained.native");
    let mut file = std::fs::OpenOptions::new()
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
            [0xB6; 32],
            1,
            1,
            7,
            [0xB7; 32],
            64 * 1024,
            crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES,
            &|| Ok(()),
        )
        .expect("the complete committed prefix validates before conversion");
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
        [0xB7; 32],
        &|| Ok(()),
    )
    .unwrap();
    let cold = catalog.into_storage(&|| Ok(())).unwrap();
    cold.validate_image().unwrap();
    assert!(matches!(
        cold.business.replication_log(0, 1, &|| Ok(())),
        Err(StoreError::ReplicationLogCursorCompacted { resume_from: 2 })
    ));
    let mut next = 2;
    let mut count = 0;
    while next <= HEAD {
        let entries = cold
            .business
            .replication_log(next, 512, &|| Ok(()))
            .unwrap();
        assert!(!entries.is_empty());
        assert!(entries.len() <= 512);
        for entry in entries {
            assert_eq!(entry.sequence, next);
            next += 1;
            count += 1;
        }
    }
    assert_eq!(count, 65_536);
    assert_eq!(next, HEAD + 1);
    assert!(cold
        .business
        .replication_log(HEAD + 1, 1, &|| Ok(()))
        .unwrap()
        .is_empty());
    assert_eq!(
        conn.query_row("SELECT count(*) FROM session_replication_log", [], |r| {
            r.get::<_, usize>(0)
        })
        .unwrap(),
        65_536
    );
    let output = SqliteSessionBackend::in_memory().unwrap();
    let output = output.conn.blocking_lock();
    initialize_schema_with_storage_anchor_and_pending_and_bindings_and_fenced_profile(
        &output,
        None,
        identity(),
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        None,
        ConsensusAuthorityProfile::FixedImmutable,
        FIXED_TEST_PLACEMENT_POLICY,
        None,
        crate::FencedTransitionV2Profile::V2,
    )
    .unwrap();
    cold.export_cold_snapshot_checked(&output, &|| Ok(()))
        .unwrap();
    validate_sealed_state_sync(&output).expect("the canonical retained SQL projection validates");
    assert_eq!(
        output
            .query_row("SELECT count(*) FROM session_replication_log", [], |r| {
                r.get::<_, usize>(0)
            })
            .unwrap(),
        65_536
    );
    assert_eq!(
        read_watch_cursor_invalidation_floor_sync(&output).unwrap(),
        0
    );
}

#[test]
fn retained_snapshot_key_fence_floor_keeps_a_live_older_lease() {
    let fixture = Fixture::new();
    let entry = Entry {
        log_id: log_id(1),
        payload: EntryPayload::Normal(SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(),
            request_id: SessionConsensusRequestId::from_bytes([0xB8; 16]),
            logical_time: timestamp(1),
            intent: SessionMutationIntent::Authorized {
                origin: node_id(),
                authority_identity: identity(),
                mutation: Box::new(SessionMutationIntent::AcquireLease {
                    key: key(),
                    owner: OwnerId::new("retained-snapshot-owner").unwrap(),
                    ttl: Duration::from_secs(60),
                }),
            },
        }),
    };
    let applied = fixture.parity(&[formation(), entry]);
    let Ok(SessionMutationOutcome::Lease(guard)) = &applied.responses[1].result else {
        panic!("the live lease is admitted before the sparse fence frontier");
    };
    let conn = fixture.oracle.conn.blocking_lock();
    // Global fences are not a dense retained row sequence. An old live key
    // remains authoritative even after newer credentials cross the window.
    let next_fence = 65_544u64;
    assert!(guard.fence().get() < next_fence - 65_536);
    conn.execute(
        "UPDATE lease_globals SET val=?1 WHERE key='next_fence'",
        [next_fence],
    )
    .unwrap();
    validate_sealed_state_sync(&conn).unwrap();
    super::roster::export::import::rootless_roundtrip(&conn);
    assert_eq!(
        conn.query_row(
            "SELECT val FROM lease_globals WHERE key='next_fence'",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        next_fence
    );
}
