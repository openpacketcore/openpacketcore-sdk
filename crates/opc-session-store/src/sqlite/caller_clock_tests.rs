use super::*;

fn progress_query(conn: &Connection) -> rusqlite::Result<i64> {
    // Exercise the installed worker progress hook with a bounded, read-only query.
    conn.query_row(
        "WITH RECURSIVE numbers(n) AS (VALUES(1) UNION ALL \
         SELECT n + 1 FROM numbers WHERE n < 10000) SELECT SUM(n) FROM numbers",
        [],
        |row| row.get(0),
    )
}

#[tokio::test]
async fn sqlite_clock_frozen_setup_does_not_spend_a_new_worker_budget() {
    let backend = SqliteSessionBackend::in_memory().expect("SQLite backend");
    tokio::time::pause();
    let frozen = tokio::time::Instant::now();
    std::thread::sleep(SQLITE_OPERATION_MAX_WORK + Duration::from_millis(20));
    assert_eq!(tokio::time::Instant::now(), frozen);
    assert!(std::time::Instant::now() > (frozen + SQLITE_OPERATION_MAX_WORK).into_std());

    let query = backend
        .run_sqlite_task(progress_query)
        .await
        .unwrap_or_else(|_| panic!("fresh worker admission must retain its full budget"));
    assert_eq!(
        query.expect("real time cannot exhaust a frozen Tokio budget"),
        50_005_000
    );
    assert_eq!(tokio::time::Instant::now(), frozen);
}

#[tokio::test]
async fn sqlite_clock_advance_interrupts_progress_without_polling_the_caller() {
    let backend = SqliteSessionBackend::in_memory().expect("SQLite backend");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    tokio::time::pause();
    let mut operation = std::pin::pin!(backend.run_sqlite_task(move |conn| {
        ready_tx.send(()).expect("worker ready");
        release_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("worker release");
        let query = progress_query(conn);
        result_tx
            .send(matches!(
                &query,
                Err(rusqlite::Error::SqliteFailure(error, _))
                    if error.code == rusqlite::ErrorCode::OperationInterrupted
            ))
            .expect("worker result");
        query
    }));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(operation.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("worker starts");
    // Do not poll the timeout future again until the worker reports its own
    // result: cancellation by the caller cannot make this assertion pass.
    tokio::time::advance(SQLITE_OPERATION_MAX_WORK).await;
    release_tx.send(()).expect("release expired worker");
    let interrupted = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("worker finishes");
    let _ = operation.await;
    assert!(
        interrupted,
        "advancing the caller's clock must interrupt SQLite work"
    );
}

#[tokio::test]
async fn sqlite_clock_frozen_setup_preserves_acceptance_reader_budget() {
    let directory = tempfile::tempdir().expect("SQLite directory");
    let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
        .expect("file-backed SQLite backend");
    let pool = Arc::clone(
        backend
            .consensus_acceptance_reader_pool
            .as_ref()
            .expect("reader pool"),
    );
    tokio::time::pause();
    let frozen = tokio::time::Instant::now();
    std::thread::sleep(SQLITE_OPERATION_MAX_WORK + Duration::from_millis(20));
    assert_eq!(tokio::time::Instant::now(), frozen);
    assert!(std::time::Instant::now() > (frozen + SQLITE_OPERATION_MAX_WORK).into_std());
    let query = backend
        .run_sqlite_task_on_consensus_acceptance_reader(pool, progress_query)
        .await
        .unwrap_or_else(|_| panic!("fresh acceptance reader must be admitted"));
    assert_eq!(query.expect("frozen acceptance reader budget"), 50_005_000);
    assert_eq!(tokio::time::Instant::now(), frozen);
}

#[tokio::test]
async fn sqlite_clock_advance_interrupts_acceptance_reader_without_polling_caller() {
    let directory = tempfile::tempdir().expect("SQLite directory");
    let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
        .expect("file-backed SQLite backend");
    let pool = Arc::clone(
        backend
            .consensus_acceptance_reader_pool
            .as_ref()
            .expect("reader pool"),
    );
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let (result_tx, result_rx) = std::sync::mpsc::channel();
    tokio::time::pause();
    let mut operation = std::pin::pin!(backend.run_sqlite_task_on_consensus_acceptance_reader(
        pool,
        move |conn| {
            ready_tx.send(()).expect("reader ready");
            release_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("reader release");
            let query = progress_query(conn);
            result_tx
                .send(matches!(
                    &query,
                    Err(rusqlite::Error::SqliteFailure(error, _))
                        if error.code == rusqlite::ErrorCode::OperationInterrupted
                ))
                .expect("reader result");
            query
        }
    ));
    std::future::poll_fn(|cx| {
        assert!(std::future::Future::poll(operation.as_mut(), cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("reader starts");
    tokio::time::advance(SQLITE_OPERATION_MAX_WORK).await;
    release_tx.send(()).expect("release expired reader");
    let interrupted = result_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("reader finishes");
    let _ = operation.await;
    assert!(
        interrupted,
        "acceptance reader must observe the advanced caller clock"
    );
}

#[tokio::test]
async fn sqlite_clock_retains_originating_runtime_on_foreign_threads() {
    tokio::time::pause();
    let frozen = tokio::time::Instant::now();
    let budget = Duration::from_millis(20);
    let deadline = SqliteWorkDeadline::tokio(frozen + budget);
    std::thread::sleep(Duration::from_millis(40));
    let pending = deadline.clone();
    assert!(!std::thread::spawn(move || {
        assert!(tokio::runtime::Handle::try_current().is_err());
        let elapsed = pending.is_elapsed();
        assert!(tokio::runtime::Handle::try_current().is_err());
        elapsed
    })
    .join()
    .expect("foreign-thread check"));
    assert_eq!(tokio::time::Instant::now(), frozen);
    tokio::time::advance(budget).await;
    assert!(std::thread::spawn(move || deadline.is_elapsed())
        .join()
        .expect("advanced check"));
}

#[tokio::test]
async fn sqlite_clock_frozen_setup_preserves_restore_row_budget() {
    use crate::model::{FenceToken, Generation, SessionKeyType, StateClass, StateType};
    use crate::record::EncryptedSessionPayload;

    let backend = SqliteSessionBackend::in_memory().expect("SQLite backend");
    let record = StoredSessionRecord {
        key: SessionKey {
            tenant: opc_types::TenantId::from_static("caller-clock"),
            nf_kind: opc_types::NetworkFunctionKind::smf(),
            key_type: SessionKeyType::PduSession,
            stable_id: bytes::Bytes::from_static(b"restore-clock")
                .try_into()
                .expect("stable ID"),
        },
        generation: Generation::new(1),
        owner: OwnerId::new("caller-clock").expect("owner"),
        fence: FenceToken::new(1),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("caller-clock").expect("state type"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(vec![0x5a]),
    };
    {
        let conn = backend.conn.lock().await;
        ops::insert_or_replace_record_sync(&conn, &record).expect("restore row");
    }
    tokio::time::pause();
    let frozen = tokio::time::Instant::now();
    let budget = Duration::from_millis(20);
    std::thread::sleep(Duration::from_millis(40));
    assert_eq!(tokio::time::Instant::now(), frozen);
    let page = backend
        .run_restore_scan(
            RestoreScanRequest::all(1),
            backend.clock.now_utc(),
            frozen + budget,
            RestoreScanValidationProfile::Standalone,
        )
        .await
        .expect("frozen restore operation retains its row-loading budget");
    assert_eq!(page.records, vec![record]);
    assert_eq!(page.loaded_count, 1);
    assert!(page.complete);
    assert_eq!(tokio::time::Instant::now(), frozen);
}
