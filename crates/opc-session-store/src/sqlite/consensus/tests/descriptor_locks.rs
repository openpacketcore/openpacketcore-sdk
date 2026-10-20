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

#[tokio::test]
async fn existing_wal_reopen_and_standalone_request_preserve_sqlite_record_locks() {
    use crate::backend::SessionBackend as _;
    const TEST: &str = "sqlite::consensus::tests::descriptor_locks::existing_wal_reopen_and_standalone_request_preserve_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    drop(SqliteSessionBackend::open(&path).unwrap());
    let observer = Connection::open(&path).unwrap();
    observer
        .query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();
    probe::assert_state(
        &path,
        TEST,
        true,
        "before reopening an existing WAL database",
    );
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let opened = probe::check_state(&path, TEST, true, "after existing WAL backend open");
    assert!(backend.get(&key()).await.unwrap().is_none());
    let requested = probe::check_state(
        &path,
        TEST,
        true,
        "after the reopened backend's standalone request",
    );
    drop(backend);
    drop(observer);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
    assert!(
        opened.is_ok() && requested.is_ok(),
        "{opened:?}\n{requested:?}"
    );
}

#[tokio::test]
async fn first_standalone_request_preserves_sqlite_record_locks() {
    use crate::backend::SessionBackend as _;
    const TEST: &str = "sqlite::consensus::tests::descriptor_locks::first_standalone_request_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let backend = SqliteSessionBackend::open(&path).unwrap();
    probe::assert_state(
        &path,
        TEST,
        true,
        "before the fresh backend's first standalone request",
    );
    assert!(backend.get(&key()).await.unwrap().is_none());
    probe::assert_state(
        &path,
        TEST,
        true,
        "after the fresh backend's first standalone request",
    );
    drop(backend);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}

async fn initialize_fixed_lock_fixture(path: &Path) -> SqliteSessionBackend {
    let backend = SqliteSessionBackend::open(path).unwrap();
    let identity = identity();
    let members = members(&[7, 8, 9]);
    let bindings = test_member_bindings(&members);
    let placement = FIXED_TEST_PLACEMENT_POLICY.unwrap();
    {
        let conn = backend.conn.lock().await;
        initialize_schema_with_profile(
            &conn,
            identity,
            &members,
            ConsensusAuthorityProfile::FixedImmutable,
        )
        .unwrap();
        let entry = membership_entry_at(0, vec![members.clone()], members.clone());
        append_logs_with_authority_sync(
            &conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            Some(placement),
            std::slice::from_ref(&entry),
        )
        .unwrap();
        save_committed_with_authority_sync(
            &conn,
            identity,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            Some(placement),
            Some(entry.log_id),
        )
        .unwrap();
        apply_entries_with_authority_sync(
            &conn,
            identity,
            &backend.caps,
            ConsensusAuthorityProfile::FixedImmutable,
            &members,
            &bindings,
            Some(placement),
            vec![entry],
        )
        .unwrap();
        activate_fenced_transition_v2_scope_sync(
            &conn,
            identity,
            identity,
            &members,
            fenced_transition_v2_profile_digest(),
            FencedTransitionV2HistoryEpoch::new(FENCED_TRANSITION_V2_INITIAL_HISTORY_EPOCH)
                .unwrap(),
        )
        .unwrap();
    }
    backend
}

async fn probe_fixed_requests(
    path: &Path,
    backend: &SqliteSessionBackend,
    test: &str,
) -> Vec<Result<(), String>> {
    let identity = identity();
    let members = members(&[7, 8, 9]);
    let bindings = test_member_bindings(&members);
    let placement = FIXED_TEST_PLACEMENT_POLICY.unwrap();
    let mut results = Vec::new();
    assert!(backend
        .fixed_quorum_application_traffic_authority_is_exact(
            identity,
            members.clone(),
            bindings.clone(),
            placement
        )
        .await
        .unwrap());
    results.push(probe::check_state(
        path,
        test,
        true,
        "after fixed-quorum authority read",
    ));
    let mutation = backend
        .fixed_quorum_activated_v2_mutation_snapshot(
            crate::sqlite::FixedQuorumActivatedV2MutationSnapshotRequest {
                storage_identity: identity,
                scope_identity: identity,
                voters: members.clone(),
                expected_members: members.clone(),
                expected_bindings: bindings.clone(),
                expected_placement_policy: placement,
                profile_digest: fenced_transition_v2_profile_digest(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        mutation,
        crate::sqlite::FixedQuorumActivatedV2MutationSnapshot::Activated { .. }
    ));
    results.push(probe::check_state(
        path,
        test,
        true,
        "after mutation acceptance read",
    ));
    let status = backend
        .fixed_quorum_fenced_transition_v2_status_at_scope(
            crate::sqlite::FixedQuorumFencedTransitionV2StatusReadRequest {
                storage_identity: identity,
                scope_identity: identity,
                voters: members.clone(),
                expected_members: members,
                expected_bindings: bindings,
                expected_placement_policy: placement,
                profile_digest: fenced_transition_v2_profile_digest(),
                require_activation: true,
            },
            &fenced_transition_v2_request(0x74, 1, "descriptor-locks"),
        )
        .await
        .unwrap();
    assert!(matches!(
        status,
        crate::sqlite::FixedQuorumFencedTransitionV2StatusRead::Activated(
            FencedTransitionV2Status::NotFound
        )
    ));
    results.push(probe::check_state(
        path,
        test,
        true,
        "after status acceptance read",
    ));
    results
}

#[tokio::test]
async fn existing_wal_quorum_and_acceptance_reads_preserve_sqlite_record_locks() {
    const TEST: &str = "sqlite::consensus::tests::descriptor_locks::existing_wal_quorum_and_acceptance_reads_preserve_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    drop(initialize_fixed_lock_fixture(&path).await);
    let observer = Connection::open(&path).unwrap();
    observer
        .query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| {
            row.get::<_, i64>(0)
        })
        .unwrap();
    probe::assert_state(
        &path,
        TEST,
        true,
        "before reopening an existing fixed WAL database",
    );
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let mut results = vec![probe::check_state(
        &path,
        TEST,
        true,
        "after existing fixed WAL backend open",
    )];
    results.extend(probe_fixed_requests(&path, &backend, TEST).await);
    drop(backend);
    drop(observer);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
    assert!(results.iter().all(Result::is_ok), "{results:?}");
}

#[tokio::test]
async fn first_quorum_and_acceptance_reads_preserve_sqlite_record_locks() {
    const TEST: &str = "sqlite::consensus::tests::descriptor_locks::first_quorum_and_acceptance_reads_preserve_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let backend = initialize_fixed_lock_fixture(&path).await;
    probe::assert_state(&path, TEST, true, "before fresh fixed-quorum requests");
    let results = probe_fixed_requests(&path, &backend, TEST).await;
    drop(backend);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
    assert!(results.iter().all(Result::is_ok), "{results:?}");
}

#[test]
fn rollback_journal_standalone_transaction_preserves_sqlite_record_locks() {
    const TEST: &str = "sqlite::consensus::tests::descriptor_locks::rollback_journal_standalone_transaction_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let writer = Connection::open(&path).unwrap();
    SqliteSessionBackend::initialize_backend_schema(&writer, false).unwrap();
    assert_eq!(
        writer
            .query_row("PRAGMA journal_mode=DELETE", [], |row| row
                .get::<_, String>(0))
            .unwrap(),
        "delete"
    );
    let reader = Connection::open(&path).unwrap();
    reader
        .execute_batch("BEGIN DEFERRED; SELECT COUNT(*) FROM sqlite_schema;")
        .unwrap();
    probe::assert_state(
        &path,
        TEST,
        true,
        "before rollback-journal standalone admission",
    );
    let transaction = crate::sqlite::standalone_transaction(&writer).unwrap();
    probe::assert_state(
        &path,
        TEST,
        true,
        "after rollback-journal standalone admission",
    );
    transaction.rollback().unwrap();
    reader.execute_batch("ROLLBACK;").unwrap();
    drop(reader);
    drop(writer);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}

#[test]
fn attached_snapshot_verification_preserves_rollback_journal_record_locks() {
    const TEST: &str = "sqlite::consensus::tests::descriptor_locks::attached_snapshot_verification_preserves_rollback_journal_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let writer = Connection::open(&path).unwrap();
    writer
        .execute_batch("PRAGMA journal_mode=DELETE; CREATE TABLE example(value INTEGER);")
        .unwrap();
    let source = crate::consensus::snapshot::PinnedSqliteFile::from_file(
        File::open(&path).unwrap(),
        path.clone(),
    )
    .unwrap();
    let attached = Connection::open_in_memory().unwrap();
    attached
        .execute("ATTACH DATABASE ?1 AS pinned", [path.to_str().unwrap()])
        .unwrap();
    writer.execute_batch("BEGIN IMMEDIATE;").unwrap();
    probe::assert_state(
        &path,
        TEST,
        true,
        "before attached rollback-journal verification",
    );
    verify_attached_snapshot_descriptor(&source, &attached, "pinned").unwrap();
    probe::assert_state(
        &path,
        TEST,
        true,
        "after attached rollback-journal verification",
    );
    writer.execute_batch("ROLLBACK;").unwrap();
    drop(attached);
    drop(writer);
    drop(source);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}

#[test]
fn snapshot_reader_final_pin_retirement_preserves_sqlite_record_locks() {
    const TEST: &str = "sqlite::consensus::tests::descriptor_locks::snapshot_reader_final_pin_retirement_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let source = Arc::new(pin_live_database_file(&backend.conn.blocking_lock(), &path).unwrap());
    let reader = open_snapshot_read_connection(&source).unwrap();
    drop(source);
    {
        let connection = backend.conn.blocking_lock();
        probe::begin(&connection);
        probe::assert_state(
            &path,
            TEST,
            true,
            "after reader admission, before final pin retirement",
        );
        drop(reader);
        probe::assert_state(
            &path,
            TEST,
            true,
            "after reader retires its final source pin",
        );
        connection.execute_batch("ROLLBACK;").unwrap();
    }
    drop(backend);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}

#[tokio::test]
async fn failed_core_initialization_preserves_sqlite_record_locks() {
    const TEST: &str = "sqlite::consensus::tests::descriptor_locks::failed_core_initialization_preserves_sqlite_record_locks";
    if probe::child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("source.sqlite");
    let mut backend = SqliteSessionBackend::open(&path).unwrap();
    // Fail the real secondary-lane open after the core has acquired its main
    // file pin. The primary backend remains available for a caller's retry.
    backend.checkpoint_vfs_name = Some(Arc::from("missing-descriptor-lock-test-vfs"));
    probe::assert_state(
        &path,
        TEST,
        true,
        "before the core's failing secondary-lane admission",
    );
    let result = SqliteConsensusCore::initialize(
        &backend,
        directory.path().join("snapshots"),
        identity(),
        expected_members(),
        test_member_bindings(&expected_members()),
        ConsensusAuthorityProfile::Dynamic,
        None,
    )
    .await;
    assert!(matches!(
        result,
        Err(SessionConsensusStorageError::BackendUnavailable)
    ));
    probe::assert_state(
        &path,
        TEST,
        true,
        "after failed core initialization retires its pin",
    );
    drop(backend);
    probe::assert_state(&path, TEST, false, "after final connection shutdown");
}
