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
