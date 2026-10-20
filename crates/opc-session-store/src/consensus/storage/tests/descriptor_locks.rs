use super::*;
use crate::test_process::sqlite_lock_probe as probe;

#[tokio::test]
async fn snapshot_build_identity_fence_preserves_sqlite_record_locks() {
    const TEST: &str = "consensus::storage::tests::descriptor_locks::snapshot_build_identity_fence_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let source =
        PinnedSqliteFile::from_file(std::fs::File::open(&path).unwrap(), path.clone()).unwrap();
    {
        let connection = backend.lock_connection_for_test().await;
        probe::begin(&connection);
        probe::assert_state(
            &path,
            TEST,
            true,
            "before the snapshot build identity fence",
        );
        {
            let actual = snapshot_build_live_identity(&connection).unwrap();
            assert_eq!(actual, source.identity());
        }
        probe::assert_state(
            &path,
            TEST,
            true,
            "after the snapshot build identity descriptor closes",
        );
        connection.execute_batch("ROLLBACK;").unwrap();
    }
    drop(backend);
    drop(source);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}

#[tokio::test]
async fn snapshot_lease_preserves_sqlite_record_locks() {
    const TEST: &str =
        "consensus::storage::tests::descriptor_locks::snapshot_lease_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let backend = SqliteSessionBackend::open(&path).unwrap();
    {
        let connection = backend.lock_connection_for_test().await;
        probe::begin(&connection);
    }
    probe::assert_state(&path, TEST, true, "before snapshot lease admission");
    let lease = acquire_snapshot_directory_lease(&backend, &directory.path().join("snapshots"))
        .await
        .unwrap();
    probe::assert_state(
        &path,
        TEST,
        true,
        "after snapshot lease admission closes its pathname check",
    );
    drop(lease);
    probe::assert_state(&path, TEST, true, "after snapshot lease retirement");
    backend
        .lock_connection_for_test()
        .await
        .execute_batch("ROLLBACK;")
        .unwrap();
    drop(backend);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}
