//! Physical recovery rows survive retained snapshots without cursor projection.
use super::*;
use crate::consensus::native::generation::{Catalog, CatalogScope, SqlitePreparedBase};
use crate::consensus::native::ordinary_retention_tests::{
    notify_after_retained_recovery_reopen, retained_recovery_notification_fixture,
};
use crate::sqlite::consensus::tests::sequential_wal::IncomingSnapshot;
use crate::sqlite::consensus::wal::Binding;
use crate::sqlite::ops::RestoreScanIncarnation;
use crate::SessionPersistenceMode;
use std::io::Write;

fn raw_entries(conn: &Connection) -> Vec<ReplicationEntry> {
    let mut statement = conn
        .prepare("SELECT sequence,entry_json FROM session_replication_log ORDER BY sequence")
        .unwrap();
    statement
        .query_map([], |row| {
            let sequence: u64 = row.get(0)?;
            let bytes = row.get_ref(1)?;
            let entry: ReplicationEntry =
                serde_json::from_slice(bytes.as_bytes().unwrap()).unwrap();
            assert_eq!(
                entry.sequence, sequence,
                "snapshot rows stay in physical coordinates"
            );
            Ok(entry)
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn retained_recovery_snapshot_preserves_physical_rows_through_install_and_cold_reopen() {
    const CHILD: &str = "OPC_RETAINED_RECOVERY_SNAPSHOT_CHILD";
    const TEST: &str = "sqlite::consensus::tests::native::recovery_snapshot::retained_recovery_snapshot_preserves_physical_rows_through_install_and_cold_reopen";
    if std::env::var_os(CHILD).is_none() {
        use crate::test_process::CommandExt as _;
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD, "1")
            .test_output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated retained recovery probe failed: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed; 0 failed; 0 ignored"));
        return;
    }
    let (storage, first) = retained_recovery_notification_fixture();
    let identity = storage.business.identity();
    let members = storage.business.members().clone();
    let source = SqliteSessionBackend::in_memory().unwrap();
    let source = source.conn.blocking_lock();
    initialize_schema_with_profile(
        &source,
        identity,
        &members,
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    storage
        .export_cold_snapshot_checked(&source, &|| Ok(()))
        .unwrap();
    validate_sealed_state_sync(&source).unwrap();
    let rows = raw_entries(&source);
    drop(storage);
    assert_eq!(rows.len(), 65_536);
    assert_eq!(rows[0].sequence, first);
    assert!(matches!(
        rows[0].replay_policy.recovery,
        crate::ReplicationRecoveryBoundary::Recover { .. }
    ));
    assert!(rows[0].sequence < rows[0].replay_policy.async_fence_floor);
    let target = SqliteSessionBackend::in_memory().unwrap();
    let mut target = target.conn.blocking_lock();
    initialize_schema_with_profile(
        &target,
        identity,
        &members,
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    let incoming = IncomingSnapshot::with_identity(&source, identity);
    let binding = Binding {
        identity,
        generation: [0xC1; 32],
        basis: [0xC2; 32],
        native: true,
        persistence: SessionPersistenceMode::Async,
        async_closed_format: true,
        async_recovery_format: true,
    };
    let origin = incoming
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
    drop(source);
    validate_sealed_state_sync(&target).unwrap();
    assert_eq!(raw_entries(&target), rows);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("retained-recovery.native");
    let maximum = crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let prefix = {
        let prepared = SqlitePreparedBase::prepare_with_origin(
            &mut target,
            identity,
            &members,
            &test_member_bindings(&members),
            FIXED_TEST_PLACEMENT_POLICY.unwrap(),
            None,
            Some(Arc::clone(&origin)),
            binding.digest().unwrap(),
            1,
            1,
            7,
            [0xC4; 32],
            64 * 1024,
            maximum,
            &|| Ok(()),
        )
        .unwrap();
        let mut writer = io::BufWriter::new(&mut output);
        let prefix = prepared.write_to(&mut writer, &|| Ok(())).unwrap();
        writer.flush().unwrap();
        prefix
    };
    output.sync_all().unwrap();
    drop(output);
    drop(target);
    let (_owner, catalog) = Catalog::open_with_origin(
        &path,
        prefix,
        maximum,
        CatalogScope {
            identity,
            members: &members,
            roster_root: None,
        },
        Some(origin),
        [0xC4; 32],
        &|| Ok(()),
    )
    .unwrap();
    let mut cold = catalog.into_storage(&|| Ok(())).unwrap();
    cold.validate_image().unwrap();
    let outward = rows[0].replay_policy.async_fence_floor + 1;
    assert_eq!(
        cold.business
            .replication_log(outward, 1, &|| Ok(()))
            .unwrap()[0]
            .sequence,
        outward
    );
    let projected = SqliteSessionBackend::in_memory().unwrap();
    let projected = projected.conn.blocking_lock();
    initialize_schema_with_profile(
        &projected,
        identity,
        &members,
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    cold.export_cold_snapshot_checked(&projected, &|| Ok(()))
        .unwrap();
    validate_sealed_state_sync(&projected).unwrap();
    assert_eq!(raw_entries(&projected), rows);
    notify_after_retained_recovery_reopen(&mut cold);
    assert_eq!(
        cold.business
            .replication_log(outward, 1, &|| Ok(()))
            .unwrap_err(),
        StoreError::ReplicationLogCursorCompacted {
            resume_from: outward + 1
        }
    );
    let after = SqliteSessionBackend::in_memory().unwrap();
    let after = after.conn.blocking_lock();
    initialize_schema_with_profile(
        &after,
        identity,
        &members,
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    cold.export_cold_snapshot_checked(&after, &|| Ok(()))
        .unwrap();
    validate_sealed_state_sync(&after).unwrap();
    let after_rows = raw_entries(&after);
    assert_eq!(after_rows.len(), 65_536);
    assert_eq!(after_rows[0].sequence, first + 1);
    assert_eq!(
        native_retention::read(&after)
            .unwrap()
            .unwrap()
            .watch_retired_through,
        first
    );
    assert!(after_rows.iter().all(|entry| !matches!(
        entry.replay_policy.recovery,
        crate::ReplicationRecoveryBoundary::Recover { .. }
    )));
}

#[test]
fn durable_snapshot_install_requires_reserved_authority_for_recovery_metadata() {
    let storage = crate::consensus::native::key_retention_tests::explicit_replay_policy_fixture();
    let identity = storage.business.identity();
    let source = SqliteSessionBackend::in_memory().unwrap();
    let source = source.conn.blocking_lock();
    initialize_schema_with_profile(
        &source,
        identity,
        storage.business.members(),
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    storage
        .export_cold_snapshot_checked(&source, &|| Ok(()))
        .unwrap();
    assert!(raw_entries(&source).iter().any(|entry| matches!(
        entry.replay_policy.recovery,
        crate::ReplicationRecoveryBoundary::Recover { .. }
    )));
    let target = SqliteSessionBackend::in_memory().unwrap();
    let target = target.conn.blocking_lock();
    initialize_schema_with_profile(
        &target,
        identity,
        storage.business.members(),
        ConsensusAuthorityProfile::FixedImmutable,
    )
    .unwrap();
    let error = IncomingSnapshot::with_identity(&source, identity)
        .source()
        .unwrap()
        .apply_native_original(
            &target,
            Binding {
                identity,
                generation: [0xC5; 32],
                basis: [0xC6; 32],
                native: true,
                persistence: SessionPersistenceMode::Durable,
                async_closed_format: false,
                async_recovery_format: false,
            },
            None,
            &RestoreScanIncarnation::new().unwrap(),
            &|| Ok(()),
        )
        .err()
        .expect("an unreserved durable root refuses asynchronous recovery authority");
    assert_eq!(
        error.to_string(),
        "native asynchronous snapshot requires a reserved authority root"
    );
}
