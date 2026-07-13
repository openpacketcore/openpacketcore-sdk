use std::time::Duration;

use futures_util::StreamExt;
use opc_session_store::{
    FakeSessionBackend, ReplicationEntry, ReplicationOp, ReplicationTxId, SessionBackend,
    SqliteSessionBackend, StoreError, MAX_REPLICATION_WATCH_BACKLOG_ENTRIES,
};
use opc_types::Timestamp;

fn entry(sequence: u64) -> ReplicationEntry {
    ReplicationEntry {
        sequence,
        tx_id: ReplicationTxId::new(format!("watch-{sequence}").as_str()).expect("transaction ID"),
        op: ReplicationOp::Batch { ops: Vec::new() },
        timestamp: Timestamp::now_utc(),
    }
}

async fn next_sequence(
    stream: &mut futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
) -> u64 {
    tokio::time::timeout(Duration::from_secs(1), stream.next())
        .await
        .expect("watch item deadline")
        .expect("watch remains open")
        .expect("valid watch item")
        .sequence
}

async fn assert_cursor_contract<B: SessionBackend>(backend: &B) {
    backend.replicate_entry(entry(1)).await.expect("append one");
    backend.replicate_entry(entry(2)).await.expect("append two");

    let mut from_zero = backend.watch(0).await.expect("zero cursor");
    assert_eq!(next_sequence(&mut from_zero).await, 1);
    assert_eq!(next_sequence(&mut from_zero).await, 2);
    drop(from_zero);

    let mut from_one = backend.watch(1).await.expect("one cursor");
    assert_eq!(next_sequence(&mut from_one).await, 1);
    drop(from_one);

    let mut existing = backend.watch(2).await.expect("existing cursor");
    assert_eq!(next_sequence(&mut existing).await, 2);
    drop(existing);

    let mut future = backend.watch(4).await.expect("future cursor");
    backend
        .replicate_entry(entry(3))
        .await
        .expect("append below future cursor");
    assert!(
        tokio::time::timeout(Duration::from_millis(25), future.next())
            .await
            .is_err(),
        "future watcher must not receive a lower live entry"
    );
    backend
        .replicate_entry(entry(4))
        .await
        .expect("append future cursor");
    assert_eq!(next_sequence(&mut future).await, 4);
    drop(future);

    let mut terminal = backend.watch(u64::MAX).await.expect("terminal cursor");
    backend
        .replicate_entry(entry(5))
        .await
        .expect("append below terminal cursor");
    assert!(
        tokio::time::timeout(Duration::from_millis(25), terminal.next())
            .await
            .is_err(),
        "terminal watcher must not receive a lower live entry"
    );
    drop(terminal);

    let mut reconnected = backend.watch(5).await.expect("reconnect cursor");
    assert_eq!(next_sequence(&mut reconnected).await, 5);
    drop(reconnected);
    backend
        .replicate_entry(entry(6))
        .await
        .expect("append after reconnect");
    let mut resumed = backend.watch(6).await.expect("resumed cursor");
    assert_eq!(next_sequence(&mut resumed).await, 6);
}

#[tokio::test]
async fn fake_watch_cursor_contract_is_inclusive_and_gap_free() {
    assert_cursor_contract(&FakeSessionBackend::new()).await;
}

#[tokio::test]
async fn file_backed_sqlite_watch_cursor_contract_is_inclusive_and_gap_free() {
    let directory = tempfile::tempdir().expect("watch SQLite directory");
    let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
        .expect("file-backed SQLite");
    assert_cursor_contract(&backend).await;
}

#[tokio::test]
async fn compacted_fake_cursor_requires_snapshot_before_resume() {
    let backend = FakeSessionBackend::with_limits(opc_session_store::fake::FakeBackendLimits {
        max_tracked_keys: 8,
        max_replication_entries: 2,
    });
    for sequence in 1..=3 {
        backend
            .replicate_entry(entry(sequence))
            .await
            .expect("append compacted fixture");
    }

    let error = match backend.watch(0).await {
        Ok(_) => panic!("compacted watch must fail"),
        Err(error) => error,
    };
    assert_eq!(
        error,
        StoreError::ReplicationLogCursorCompacted { resume_from: 2 }
    );
}

async fn assert_oversized_backlog_requires_catch_up<B: SessionBackend>(backend: &B) {
    for sequence in
        1..=u64::try_from(MAX_REPLICATION_WATCH_BACKLOG_ENTRIES + 1).expect("bounded fixture width")
    {
        backend
            .replicate_entry(entry(sequence))
            .await
            .expect("append backlog fixture");
    }
    let error = match backend.watch(1).await {
        Ok(_) => panic!("over-window watch must fail"),
        Err(error) => error,
    };
    assert_eq!(error, StoreError::ReplicationWatchCatchUpRequired);

    let catch_up_width = MAX_REPLICATION_WATCH_BACKLOG_ENTRIES + 1;
    let retained = backend
        .get_replication_log(1, catch_up_width)
        .await
        .expect("read full retained log for coherent catch-up");
    assert_eq!(retained.len(), catch_up_width);
    for (expected, observed) in (1_u64..).zip(&retained) {
        assert_eq!(
            observed.sequence, expected,
            "coherent catch-up must validate the exact retained prefix"
        );
    }
    let caught_up_through = retained.last().expect("non-empty retained log").sequence;
    let current = backend
        .max_replication_sequence()
        .await
        .expect("read head after coherent catch-up");
    assert_eq!(
        caught_up_through, current,
        "validated prefix must cover the complete retained log"
    );
    let live = backend
        .watch(caught_up_through.checked_add(1).expect("reconnect cursor"))
        .await
        .expect("coherently caught-up cursor can reconnect");
    drop(live);
}

#[tokio::test]
async fn fake_oversized_backlog_requires_coherent_catch_up() {
    assert_oversized_backlog_requires_catch_up(&FakeSessionBackend::new()).await;
}

#[tokio::test]
async fn file_backed_sqlite_oversized_backlog_requires_coherent_catch_up() {
    let directory = tempfile::tempdir().expect("watch SQLite directory");
    let backend = SqliteSessionBackend::open(directory.path().join("store.sqlite"))
        .expect("file-backed SQLite");
    assert_oversized_backlog_requires_catch_up(&backend).await;
}
