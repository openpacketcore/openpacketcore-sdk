use super::*;
use crate::test_process::sqlite_lock_probe as probe;

#[test]
fn proactive_checkpoint_verification_preserves_sqlite_record_locks() {
    const TEST: &str = "sqlite::consensus::tests::descriptor_locks::proactive_checkpoint_verification_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let source = crate::consensus::snapshot::PinnedSqliteFile::from_file(
        std::fs::File::open(&path).unwrap(),
        path.clone(),
    )
    .unwrap();
    {
        let connection = backend.conn.blocking_lock();
        probe::begin(&connection);
        probe::assert_state(
            &path,
            TEST,
            true,
            "before proactive checkpoint verification",
        );
        verify_proactive_checkpoint_connection(&connection, &source).unwrap();
        probe::assert_state(
            &path,
            TEST,
            true,
            "after the checkpoint verification descriptor closes",
        );
        connection.execute_batch("ROLLBACK;").unwrap();
    }
    drop(backend);
    drop(source);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}

#[test]
fn pinned_snapshot_verification_preserves_sqlite_record_locks() {
    const TEST: &str = "sqlite::consensus::tests::descriptor_locks::pinned_snapshot_verification_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let source = crate::consensus::snapshot::PinnedSqliteFile::from_file(
        std::fs::File::open(&path).unwrap(),
        path.clone(),
    )
    .unwrap();
    {
        let connection = backend.conn.blocking_lock();
        probe::begin(&connection);
        probe::assert_state(&path, TEST, true, "before pinned snapshot verification");
        verify_pinned_snapshot_descriptor(&source, &connection).unwrap();
        probe::assert_state(&path, TEST, true, "after pinned snapshot verification");
        connection.execute_batch("ROLLBACK;").unwrap();
    }
    drop(backend);
    drop(source);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}

#[test]
fn snapshot_reader_lifetime_preserves_sqlite_record_locks() {
    const TEST: &str = "sqlite::consensus::tests::descriptor_locks::snapshot_reader_lifetime_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let source = Arc::new(
        crate::consensus::snapshot::PinnedSqliteFile::from_file(
            std::fs::File::open(&path).unwrap(),
            path.clone(),
        )
        .unwrap(),
    );
    {
        let connection = backend.conn.blocking_lock();
        probe::begin(&connection);
        probe::assert_state(&path, TEST, true, "before snapshot reader admission");
        let reader = open_snapshot_read_connection(&source).unwrap();
        probe::assert_state(&path, TEST, true, "after snapshot reader admission");
        verify_snapshot_read_connection(&reader).unwrap();
        probe::assert_state(&path, TEST, true, "after snapshot reader verification");
        drop(reader);
        probe::assert_state(&path, TEST, true, "after snapshot reader retirement");
        connection.execute_batch("ROLLBACK;").unwrap();
    }
    drop(backend);
    drop(source);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}
