use super::*;
use crate::consensus::native::generation::{Catalog, CatalogScope, SqlitePreparedBase};
use crate::consensus::native::ordinary_retention_tests::retired_notification_fixture;
use crate::consensus::native::test_journal::journal_page_for_test_sync;
use crate::sqlite::consensus::tests::sequential_wal::IncomingSnapshot;
use crate::sqlite::consensus::wal::Binding;
use crate::sqlite::ops::RestoreScanIncarnation;
use crate::SessionPersistenceMode;
use std::io::Write;

#[test]
fn native_key_retention_portable_snapshot_preserves_absent_fence() {
    let (storage, old) = crate::consensus::native::key_retention_tests::retired_key_fixture();
    let identity = storage.business.identity();
    let members = storage.business.members();
    let source = SqliteSessionBackend::in_memory().unwrap();
    let conn = source.conn.blocking_lock();
    initialize_schema_with_profile(
        &conn,
        identity,
        members,
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    storage
        .export_cold_snapshot_checked(&conn, &|| Ok(()))
        .unwrap();
    let floor = ops::current_fence_sync(&conn, old.key()).unwrap();
    assert_eq!(floor, old.fence().get());
    assert_eq!(native_retired::read(&conn, old.key()).unwrap(), Some(0));
    let retention = native_retention::read(&conn).unwrap().unwrap();
    assert_eq!(retention.keys.retired_count, 1);
    assert_eq!(retention.keys.retired_max, floor);
    assert_eq!(
        (retention.keys.floor_prev, retention.keys.floor_cur),
        (0, 0)
    );
    let mut fresh = old.key().clone();
    fresh.stable_id = bytes::Bytes::from_static(b"snapshot-fresh-key")
        .try_into()
        .unwrap();
    assert_eq!(ops::current_fence_sync(&conn, &fresh).unwrap(), 0);
    assert_eq!(
        conn.query_row("SELECT count(*) FROM key_fences", [], |row| row
            .get::<_, u64>(0))
            .unwrap(),
        2
    );
    let incoming = IncomingSnapshot::with_identity(&conn, identity);
    let target = SqliteSessionBackend::in_memory().unwrap();
    let target = target.conn.blocking_lock();
    initialize_schema_with_profile(
        &target,
        identity,
        members,
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    incoming
        .source()
        .unwrap()
        .apply_native_original(
            &target,
            Binding {
                identity,
                generation: [0xDB; 32],
                basis: [0xDC; 32],
                native: true,
                persistence: SessionPersistenceMode::Durable,
                async_closed_format: false,
                async_recovery_format: false,
            },
            None,
            &RestoreScanIncarnation::new().unwrap(),
            &|| Ok(()),
        )
        .unwrap();
    assert_eq!(ops::current_fence_sync(&target, old.key()).unwrap(), floor);
    assert_eq!(native_retired::read(&target, old.key()).unwrap(), Some(0));
    assert!(native_retention::read(&target).unwrap().unwrap() == retention);
    assert_eq!(ops::current_fence_sync(&target, &fresh).unwrap(), 0);
    assert_eq!(
        target
            .query_row("SELECT count(*) FROM key_fences", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        2
    );
}

#[test]
fn native_notification_retention_portable_snapshot_roundtrip_and_install() {
    let (storage, identity, members) = retired_notification_fixture();
    let backend = SqliteSessionBackend::in_memory().unwrap();
    let mut conn = backend.conn.blocking_lock();
    initialize_schema_with_profile(
        &conn,
        identity,
        &members,
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    storage
        .export_cold_snapshot_checked(&conn, &|| Ok(()))
        .unwrap();
    assert_eq!(
        native_retention::read(&conn)
            .unwrap()
            .unwrap()
            .watch_retired_through,
        1
    );
    validate_sealed_replication_log_sync(&conn).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("retained.native");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let maximum = crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES;
    let prefix = {
        let prepared = SqlitePreparedBase::prepare(
            &mut conn,
            identity,
            &members,
            &test_member_bindings(&members),
            FIXED_TEST_PLACEMENT_POLICY.unwrap(),
            None,
            [0xD7; 32],
            1,
            1,
            7,
            [0xD8; 32],
            64 * 1024,
            maximum,
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
        maximum,
        CatalogScope {
            identity,
            members: &members,
            roster_root: None,
        },
        [0xD8; 32],
        &|| Ok(()),
    )
    .unwrap();
    let cold = catalog.into_storage(&|| Ok(())).unwrap();
    cold.validate_image().unwrap();
    assert_eq!(
        cold.business.replication_log(1, 1, &|| Ok(())).unwrap_err(),
        StoreError::ReplicationLogCursorCompacted { resume_from: 2 }
    );
    assert_eq!(
        journal_page_for_test_sync(|| cold.business.replication_log(2, 1, &|| Ok(())))[0].sequence,
        2
    );

    let incoming = IncomingSnapshot::with_identity(&conn, identity);
    let target = SqliteSessionBackend::in_memory().unwrap();
    let target = target.conn.blocking_lock();
    initialize_schema_with_profile(
        &target,
        identity,
        &members,
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    let binding = Binding {
        identity,
        generation: [0xD9; 32],
        basis: [0xDA; 32],
        native: true,
        persistence: SessionPersistenceMode::Durable,
        async_closed_format: false,
        async_recovery_format: false,
    };
    incoming
        .source()
        .unwrap()
        .apply_native_original(
            &target,
            binding,
            None,
            &RestoreScanIncarnation::new().unwrap(),
            &|| Ok(()),
        )
        .unwrap();
    assert_eq!(
        native_retention::read(&target)
            .unwrap()
            .unwrap()
            .watch_retired_through,
        1
    );
    validate_sealed_replication_log_sync(&target).unwrap();
    assert_eq!(
        target
            .query_row("SELECT count(*) FROM session_replication_log", [], |row| {
                row.get::<_, u64>(0)
            })
            .unwrap(),
        65_536
    );
}

fn capacity_snapshot_fixture() -> (
    crate::consensus::native::NativeStorage,
    SqliteSessionBackend,
) {
    let (storage, _old) =
        crate::consensus::native::key_retention_tests::rotated_application_fixture();
    let entries =
        journal_page_for_test_sync(|| storage.business.replication_log(1, 16, &|| Ok(())));
    assert!(entries.last().unwrap().replay_policy.capacity_rotations == 2);
    let backend = SqliteSessionBackend::in_memory().unwrap();
    {
        let conn = backend.conn.blocking_lock();
        initialize_schema_with_profile(
            &conn,
            storage.business.identity(),
            storage.business.members(),
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .unwrap();
        storage
            .export_cold_snapshot_checked(&conn, &|| Ok(()))
            .unwrap();
    }
    (storage, backend)
}

fn export_policy_fixture(
    storage: crate::consensus::native::NativeStorage,
) -> (
    crate::consensus::native::NativeStorage,
    SqliteSessionBackend,
) {
    let backend = SqliteSessionBackend::in_memory().unwrap();
    {
        let conn = backend.conn.blocking_lock();
        initialize_schema_with_profile(
            &conn,
            storage.business.identity(),
            storage.business.members(),
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .unwrap();
        storage
            .export_cold_snapshot_checked(&conn, &|| Ok(()))
            .unwrap();
        assert!(
            native_retention::read(&conn).unwrap().is_some(),
            "native replay profile is explicit even at genesis"
        );
    }
    (storage, backend)
}

fn explicit_policy_snapshot_fixture() -> (
    crate::consensus::native::NativeStorage,
    SqliteSessionBackend,
) {
    export_policy_fixture(
        crate::consensus::native::key_retention_tests::explicit_replay_policy_fixture(),
    )
}

fn default_policy_snapshot_fixture() -> (
    crate::consensus::native::NativeStorage,
    SqliteSessionBackend,
) {
    let (storage, _) = crate::consensus::native::key_retention_tests::acquired_fixture();
    export_policy_fixture(storage)
}

fn current_policy_entries(
    storage: &crate::consensus::native::NativeStorage,
) -> Vec<ReplicationEntry> {
    match crate::consensus::native::test_journal::journal_page_result_for_test(|| {
        storage.business.replication_log(1, 256, &|| Ok(()))
    }) {
        Ok(entries) => entries,
        Err(StoreError::ReplicationLogCursorCompacted { resume_from }) => {
            journal_page_for_test_sync(|| {
                storage
                    .business
                    .replication_log(resume_from, 256, &|| Ok(()))
            })
        }
        Err(error) => panic!("unexpected journal read: {error:?}"),
    }
}

fn has_policy_recovery(conn: &Connection) -> bool {
    capacity_snapshot_entries(conn).iter().any(|entry| {
        matches!(
            entry.replay_policy.recovery,
            crate::ReplicationRecoveryBoundary::Recover { .. }
        )
    })
}

fn outward_policy_entries(mut entries: Vec<ReplicationEntry>) -> Vec<ReplicationEntry> {
    if let Some((raw, floor)) = entries.iter().rev().find_map(|entry| {
        matches!(
            entry.replay_policy.recovery,
            crate::ReplicationRecoveryBoundary::Recover { .. }
        )
        .then_some((entry.sequence, entry.replay_policy.async_fence_floor))
    }) {
        entries.retain(|entry| entry.sequence >= raw);
        for entry in &mut entries {
            entry.sequence = floor + 1 + entry.sequence - raw;
        }
    }
    entries
}

fn capacity_snapshot_entries(conn: &Connection) -> Vec<ReplicationEntry> {
    let mut statement = conn
        .prepare("SELECT entry_json FROM session_replication_log ORDER BY sequence")
        .unwrap();
    let rows = statement
        .query_map([], |row| {
            let value = row.get_ref(0)?;
            Ok(serde_json::from_slice(value.as_bytes().unwrap()).unwrap())
        })
        .unwrap();
    rows.collect::<rusqlite::Result<Vec<ReplicationEntry>>>()
        .unwrap()
}

#[test]
fn native_capacity_portable_snapshot_seal_admits_retention_entries() {
    for fixture in [
        capacity_snapshot_fixture,
        capacity_boundary_snapshot_fixture,
        explicit_policy_snapshot_fixture,
        default_policy_snapshot_fixture,
    ] {
        let (storage, backend) = fixture();
        let conn = backend.conn.blocking_lock();
        validate_sealed_replication_log_sync(&conn).unwrap();
        validate_sealed_state_sync(&conn).unwrap();
        assert_eq!(
            outward_policy_entries(capacity_snapshot_entries(&conn)),
            current_policy_entries(&storage)
        );
    }
}

#[test]
fn native_capacity_portable_snapshot_install_preserves_retention_entries() {
    for fixture in [
        capacity_snapshot_fixture,
        capacity_boundary_snapshot_fixture,
        explicit_policy_snapshot_fixture,
        default_policy_snapshot_fixture,
    ] {
        let (storage, backend) = fixture();
        let conn = backend.conn.blocking_lock();
        let identity = storage.business.identity();
        let incoming = IncomingSnapshot::with_identity(&conn, identity);
        let target = SqliteSessionBackend::in_memory().unwrap();
        let target = target.conn.blocking_lock();
        initialize_schema_with_profile(
            &target,
            identity,
            storage.business.members(),
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .unwrap();
        incoming
            .source()
            .unwrap()
            .apply_native_original(
                &target,
                Binding {
                    identity,
                    generation: [0x71; 32],
                    basis: [0x72; 32],
                    native: true,
                    persistence: if has_policy_recovery(&conn) {
                        SessionPersistenceMode::Async
                    } else {
                        SessionPersistenceMode::Durable
                    },
                    async_closed_format: has_policy_recovery(&conn),
                    async_recovery_format: has_policy_recovery(&conn),
                },
                None,
                &RestoreScanIncarnation::new().unwrap(),
                &|| Ok(()),
            )
            .unwrap();
        validate_sealed_state_sync(&target).unwrap();
        assert!(native_retention::read(&target).unwrap() == native_retention::read(&conn).unwrap());
        assert_eq!(
            capacity_snapshot_entries(&target),
            capacity_snapshot_entries(&conn)
        );
    }
}

#[test]
fn native_capacity_sqlite_generation_conversion_preserves_retention_entries() {
    for fixture in [
        capacity_snapshot_fixture,
        capacity_boundary_snapshot_fixture,
        explicit_policy_snapshot_fixture,
        default_policy_snapshot_fixture,
    ] {
        let (storage, backend) = fixture();
        let mut conn = backend.conn.blocking_lock();
        let identity = storage.business.identity();
        let members = storage.business.members();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("capacity.native");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let maximum = crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES;
        let prefix = {
            let prepared = SqlitePreparedBase::prepare(
                &mut conn,
                identity,
                members,
                &test_member_bindings(members),
                FIXED_TEST_PLACEMENT_POLICY.unwrap(),
                None,
                [0x73; 32],
                1,
                1,
                7,
                [0x74; 32],
                64 * 1024,
                maximum,
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
            maximum,
            CatalogScope {
                identity,
                members,
                roster_root: None,
            },
            [0x74; 32],
            &|| Ok(()),
        )
        .unwrap();
        let cold = catalog.into_storage(&|| Ok(())).unwrap();
        cold.validate_image().unwrap();
        assert_eq!(
            current_policy_entries(&cold),
            current_policy_entries(&storage)
        );
        let roundtrip = SqliteSessionBackend::in_memory().unwrap();
        let roundtrip = roundtrip.conn.blocking_lock();
        initialize_schema_with_profile(
            &roundtrip,
            identity,
            members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .unwrap();
        cold.export_cold_snapshot_checked(&roundtrip, &|| Ok(()))
            .unwrap();
        assert_eq!(
            capacity_snapshot_entries(&roundtrip),
            capacity_snapshot_entries(&conn)
        );
        assert!(
            native_retention::read(&roundtrip).unwrap() == native_retention::read(&conn).unwrap()
        );
    }
}

#[test]
fn native_retention_snapshot_admission_requires_the_canonical_namespace() {
    let (_, backend) = capacity_snapshot_fixture();
    let conn = backend.conn.blocking_lock();
    validate_sealed_replication_log_sync(&conn).unwrap();
    // The exported fixture is read-only; deliberately damage this owned copy.
    conn.pragma_update(None, "query_only", false).unwrap();
    conn.execute_batch("DROP TABLE consensus_native_retention")
        .unwrap();
    assert!(
        validate_sealed_replication_log_sync(&conn).is_err(),
        "ordinary SQL snapshots reject retention operations"
    );
    conn.execute_batch(
        "CREATE TABLE consensus_native_retention(singleton INTEGER, frontiers BLOB)",
    )
    .unwrap();
    assert!(
        validate_sealed_replication_log_sync(&conn).is_err(),
        "a namespace name alone cannot enable native retention"
    );
}

fn capacity_boundary_snapshot_fixture() -> (
    crate::consensus::native::NativeStorage,
    SqliteSessionBackend,
) {
    let storage =
        crate::consensus::native::key_retention_tests::capacity_boundary_application_fixture();
    let backend = SqliteSessionBackend::in_memory().unwrap();
    {
        let conn = backend.conn.blocking_lock();
        initialize_schema_with_profile(
            &conn,
            storage.business.identity(),
            storage.business.members(),
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .unwrap();
        storage
            .export_cold_snapshot_checked(&conn, &|| Ok(()))
            .unwrap();
    }
    (storage, backend)
}

#[test]
fn sqlite_transition_replay_preserves_unrelated_expired_rows() {
    let fixture = Fixture::new();
    let initial = finite_fenced_transition_create_request(0xE1, "policy-owner", timestamp(2));
    let initial = FencedTransitionV2Request::new(
        crate::FencedTransitionV2HistoryEpoch::new(1).unwrap(),
        crate::FencedTransitionV2CallerNonce::from_bytes([0xE1; 16]),
        initial.lease().clone(),
        initial.mutation().clone(),
    )
    .unwrap();
    let entries = [
        formation(),
        activation(1, initial, timestamp(1)),
        fenced_transition_v2_authorized_entry(
            2,
            sdk741_component_request(Sdk741Payload::Create, 701, 0, None),
            timestamp(3),
            node_id(),
            identity(),
        ),
        fenced_transition_v2_batch_entry(
            3,
            vec![
                sdk741_component_request(Sdk741Payload::Create, 702, 0, None),
                sdk741_component_request(Sdk741Payload::Create, 702, 1, None),
            ],
            timestamp(4),
        ),
    ];
    let conn = fixture.oracle.conn.blocking_lock();
    append_logs_with_authority_sync(
        &conn,
        identity(),
        ConsensusAuthorityProfile::FixedImmutable,
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        FIXED_TEST_PLACEMENT_POLICY,
        &entries,
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
    let applied = apply_entries_with_authority_sync(
        &conn,
        identity(),
        &fixture.oracle.caps,
        ConsensusAuthorityProfile::FixedImmutable,
        &fixed_members(),
        &test_member_bindings(&fixed_members()),
        FIXED_TEST_PLACEMENT_POLICY,
        entries.to_vec(),
    )
    .unwrap();
    assert!(applied
        .responses
        .iter()
        .all(|response| response.result.is_ok()));
    assert_eq!(applied.notifications.len(), 4);
    assert_eq!(
        conn.query_row("SELECT count(*) FROM session_records", [], |row| row
            .get::<_, usize>(0))
            .unwrap(),
        4
    );
    assert!(ops::get_raw_sync(&conn, &key()).unwrap().is_some());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let fake = crate::FakeSessionBackend::new();
        for (index, entry) in applied.notifications.into_iter().enumerate() {
            crate::SessionBackend::replicate_entry(&fake, entry)
                .await
                .unwrap();
            assert_eq!(
                crate::fake::tests::retained_record_count_for_test(&fake).await,
                index + 1,
                "replay must preserve the source's unrelated expired row at every entry"
            );
        }
    });
}
