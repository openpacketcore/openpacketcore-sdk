use super::*;
use crate::test_process::sqlite_lock_probe as probe;

#[test]
fn absent_recovery_classifier_preserves_sqlite_record_locks() {
    const TEST: &str = "sqlite::consensus::tests::descriptor_locks::absent_recovery_classifier_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let backend = SqliteSessionBackend::open(&path).unwrap();
    {
        let connection = backend.conn.blocking_lock();
        probe::begin(&connection);
        probe::assert_state(&path, TEST, true, "before absent recovery classification");
        let classification =
            classify_operator_recovery_latch_with_connection_sync(&path, &connection).unwrap();
        assert!(classification.latch.is_none());
        probe::assert_state(&path, TEST, true, "after absent recovery classification");
        connection.execute_batch("ROLLBACK;").unwrap();
    }
    drop(backend);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}

#[test]
fn absent_live_recovery_probe_preserves_sqlite_record_locks() {
    const TEST: &str = "sqlite::consensus::tests::descriptor_locks::absent_live_recovery_probe_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let backend = SqliteSessionBackend::open(&path).unwrap();
    {
        let connection = backend.conn.blocking_lock();
        probe::begin(&connection);
        probe::assert_state(&path, TEST, true, "before absent live recovery probe");
        assert!(matches!(
            probe_live_terminal_recovery_handoff_with_connection_sync(&path, &connection).unwrap(),
            LiveTerminalRecoveryHandoffProbe::Clear
        ));
        probe::assert_state(&path, TEST, true, "after absent live recovery probe");
        connection.execute_batch("ROLLBACK;").unwrap();
    }
    drop(backend);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}

#[test]
fn independent_backend_retirement_preserves_sqlite_record_locks() {
    const TEST: &str = "sqlite::consensus::tests::descriptor_locks::independent_backend_retirement_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let retiring = SqliteSessionBackend::open(&path).unwrap();
    let surviving = SqliteSessionBackend::open(&path).unwrap();
    {
        let connection = surviving.conn.blocking_lock();
        probe::begin(&connection);
        probe::assert_state(&path, TEST, true, "before independent backend retirement");
        drop(retiring);
        probe::assert_state(&path, TEST, true, "after independent backend retirement");
        connection.execute_batch("ROLLBACK;").unwrap();
    }
    drop(surviving);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_worker_retirement_preserves_sqlite_record_locks() {
    const TEST: &str = "sqlite::consensus::tests::descriptor_locks::cancelled_worker_retirement_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let workers = Arc::clone(&backend.operation_workers);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let task = tokio::spawn(async move {
        backend
            .run_sqlite_task(move |connection| {
                probe::begin(connection);
                started_tx.send(()).unwrap();
                // Dropping the sender also releases the worker if a probe panics.
                let _ = release_rx.recv();
                connection.execute_batch("ROLLBACK;")
            })
            .await
    });
    started_rx.await.unwrap();
    probe::assert_state(&path, TEST, true, "before cancelling the backend owner");
    task.abort();
    assert!(task.await.err().unwrap().is_cancelled());
    assert_eq!(workers.available_permits(), 0);
    probe::assert_state(
        &path,
        TEST,
        true,
        "after backend retirement with a live worker",
    );
    release_tx.send(()).unwrap();
    drop(
        tokio::time::timeout(Duration::from_secs(1), workers.acquire())
            .await
            .expect("blocking worker releases its connection and permit")
            .unwrap(),
    );
    probe::assert_state(&path, TEST, false, "after final worker shutdown");
}

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
