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
