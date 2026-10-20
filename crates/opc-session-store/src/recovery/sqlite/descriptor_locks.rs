use super::*;
use crate::test_process::sqlite_lock_probe as probe;

fn fixture() -> (tempfile::TempDir, PathBuf, Connection, PinnedSnapshotFile) {
    let directory = match std::env::var_os("OPC_FS_VERITY_SNAPSHOT_ROOT") {
        Some(root) => tempfile::tempdir_in(root).unwrap(),
        None => tempfile::tempdir().unwrap(),
    };
    let path = directory.path().join("source.sqlite");
    let connection = Connection::open(&path).unwrap();
    connection
        .execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE example(value INTEGER);")
        .unwrap();
    let source = PinnedSnapshotFile::open(&path).unwrap();
    (directory, path, connection, source)
}

#[test]
fn recovery_path_verification_preserves_sqlite_record_locks() {
    const TEST: &str = "recovery::sqlite::descriptor_locks::recovery_path_verification_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let (_directory, path, connection, source) = fixture();
    probe::begin(&connection);
    probe::assert_state(&path, TEST, true, "before recovery pathname verification");
    source.verify_path_identity(&path).unwrap();
    probe::assert_state(&path, TEST, true, "after recovery pathname verification");
    connection.execute_batch("ROLLBACK;").unwrap();
    drop(connection);
    drop(source);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}

#[test]
fn recovery_main_binding_preserves_sqlite_record_locks() {
    const TEST: &str =
        "recovery::sqlite::descriptor_locks::recovery_main_binding_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let (_directory, path, connection, source) = fixture();
    probe::begin(&connection);
    probe::assert_state(
        &path,
        TEST,
        true,
        "before recovery main binding verification",
    );
    verify_sqlite_main_file_binding(&source.file, &connection).unwrap();
    probe::assert_state(
        &path,
        TEST,
        true,
        "after recovery main binding verification",
    );
    connection.execute_batch("ROLLBACK;").unwrap();
    drop(connection);
    drop(source);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}

#[test]
fn recovery_pin_retirement_preserves_sqlite_record_locks() {
    const TEST: &str =
        "recovery::sqlite::descriptor_locks::recovery_pin_retirement_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let (_directory, path, connection, source) = fixture();
    probe::begin(&connection);
    probe::assert_state(&path, TEST, true, "before final recovery pin retirement");
    drop(source);
    probe::assert_state(&path, TEST, true, "after final recovery pin retirement");
    connection.execute_batch("ROLLBACK;").unwrap();
    drop(connection);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}

#[test]
fn rollback_journal_recovery_pin_retirement_preserves_sqlite_record_locks() {
    const TEST: &str = "recovery::sqlite::descriptor_locks::rollback_journal_recovery_pin_retirement_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let (_directory, path, connection, source) = fixture();
    assert_eq!(
        connection
            .query_row("PRAGMA journal_mode=DELETE", [], |row| row
                .get::<_, String>(0))
            .unwrap(),
        "delete"
    );
    connection.execute_batch("BEGIN IMMEDIATE;").unwrap();
    probe::assert_state(
        &path,
        TEST,
        true,
        "before rollback-journal recovery pin retirement",
    );
    drop(source);
    probe::assert_state(
        &path,
        TEST,
        true,
        "after rollback-journal recovery pin retirement",
    );
    connection.execute_batch("ROLLBACK;").unwrap();
    drop(connection);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}

#[test]
fn recovery_portable_pin_retirement_preserves_sqlite_record_locks() {
    const TEST: &str = "recovery::sqlite::descriptor_locks::recovery_portable_pin_retirement_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let (_directory, path, connection, mut source) = fixture();
    // The verification source must retain the same close owner even when an
    // independent SQLite connection holds a lock on the captured inode.
    source
        .admit_fixed_integrity(
            SnapshotIntegrityPolicy::PortableVerified,
            SNAPSHOT_DATABASE_MAX_BYTES,
        )
        .unwrap();
    assert!(source.portable.is_some());
    probe::begin(&connection);
    probe::assert_state(
        &path,
        TEST,
        true,
        "before final portable recovery pin retirement",
    );
    drop(source);
    probe::assert_state(
        &path,
        TEST,
        true,
        "after final portable recovery pin retirement",
    );
    connection.execute_batch("ROLLBACK;").unwrap();
    drop(connection);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}
