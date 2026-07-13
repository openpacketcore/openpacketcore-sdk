use opc_session_store::{
    FakeSessionBackend, ReplicationEntry, ReplicationOp, SessionBackend, SqliteSessionBackend,
    StoreError, MAX_REPLICATION_LOG_PAGE_ENTRIES,
};
use opc_types::Timestamp;
use tempfile::NamedTempFile;

fn entry(sequence: u64, tx_id: &str) -> ReplicationEntry {
    ReplicationEntry {
        sequence,
        tx_id: tx_id.try_into().expect("valid transaction ID"),
        op: ReplicationOp::Batch { ops: Vec::new() },
        timestamp: Timestamp::from_offset_datetime(time::OffsetDateTime::UNIX_EPOCH),
    }
}

async fn replication_snapshot<B>(backend: &B) -> (u64, Vec<ReplicationEntry>)
where
    B: SessionBackend,
{
    let head = backend
        .max_replication_sequence()
        .await
        .expect("read replication head");
    let log = backend
        .get_replication_log(1, 32)
        .await
        .expect("read replication log");
    (head, log)
}

async fn assert_append_sequence_contract<B>(backend: B)
where
    B: SessionBackend,
{
    let zero = entry(0, "zero");
    assert_eq!(
        backend
            .replicate_entry(zero)
            .await
            .expect_err("sequence zero must be rejected"),
        StoreError::InvalidReplicationSequence
    );
    assert_eq!(replication_snapshot(&backend).await, (0, Vec::new()));

    let first = entry(1, "first");
    backend
        .replicate_entry(first.clone())
        .await
        .expect("sequence one must be accepted on an empty log");
    let after_first = (1, vec![first.clone()]);
    assert_eq!(replication_snapshot(&backend).await, after_first);

    backend
        .replicate_entry(first.clone())
        .await
        .expect("an exact duplicate must be idempotent");
    assert_eq!(replication_snapshot(&backend).await, after_first);

    let mut forged_duplicate = first.clone();
    forged_duplicate.timestamp = Timestamp::from_offset_datetime(
        time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1),
    );
    assert_eq!(
        backend
            .replicate_entry(forged_duplicate)
            .await
            .expect_err("the transaction ID alone must not make a changed entry idempotent"),
        StoreError::BackendUnavailable("divergent replication entry sequence".into())
    );
    assert_eq!(replication_snapshot(&backend).await, after_first);

    let divergent = entry(1, "divergent");
    assert_eq!(
        backend
            .replicate_entry(divergent)
            .await
            .expect_err("a divergent duplicate must be rejected"),
        StoreError::BackendUnavailable("divergent replication entry sequence".into())
    );
    assert_eq!(replication_snapshot(&backend).await, after_first);

    let gap = entry(3, "gap");
    assert_eq!(
        backend
            .replicate_entry(gap)
            .await
            .expect_err("a replication gap must be rejected"),
        StoreError::BackendUnavailable("replication log sequence gap".into())
    );
    assert_eq!(replication_snapshot(&backend).await, after_first);

    let maximum = entry(u64::MAX, "maximum");
    backend
        .replicate_entry(maximum)
        .await
        .expect_err("u64::MAX must be rejected without overflow");
    assert_eq!(replication_snapshot(&backend).await, after_first);

    let second = entry(2, "second");
    backend
        .replicate_entry(second.clone())
        .await
        .expect("the next contiguous sequence must remain appendable");
    assert_eq!(
        replication_snapshot(&backend).await,
        (2, vec![first, second])
    );
}

async fn assert_rebuild_sequence_contract<B, F>(new_backend: F)
where
    B: SessionBackend,
    F: Fn() -> B,
{
    let invalid_prefixes = [
        vec![entry(0, "zero")],
        vec![entry(2, "starts-at-two")],
        vec![entry(1, "replacement"), entry(1, "duplicate")],
        vec![entry(1, "replacement"), entry(3, "gap")],
        vec![entry(u64::MAX, "maximum")],
    ];

    for invalid_prefix in invalid_prefixes {
        let backend = new_backend();
        let original = entry(1, "original");
        backend
            .replicate_entry(original.clone())
            .await
            .expect("seed original replication state");
        let before = (1, vec![original]);

        assert_eq!(
            backend
                .rebuild_replication_state(invalid_prefix)
                .await
                .expect_err("an invalid prefix must be rejected"),
            StoreError::InvalidReplicationSequence
        );
        assert_eq!(
            replication_snapshot(&backend).await,
            before,
            "a rejected rebuild must preserve the prior log and head"
        );
    }

    let backend = new_backend();
    let original = entry(1, "original");
    backend
        .replicate_entry(original)
        .await
        .expect("seed original replication state");

    let replacement = vec![entry(1, "replacement-one"), entry(2, "replacement-two")];
    backend
        .rebuild_replication_state(replacement.clone())
        .await
        .expect("a valid contiguous prefix must rebuild state");
    assert_eq!(replication_snapshot(&backend).await, (2, replacement));
}

#[tokio::test]
async fn fake_replication_append_sequence_boundaries() {
    assert_append_sequence_contract(FakeSessionBackend::new()).await;
}

#[tokio::test]
async fn sqlite_replication_append_sequence_boundaries() {
    assert_append_sequence_contract(
        SqliteSessionBackend::in_memory().expect("create in-memory SQLite backend"),
    )
    .await;
}

#[tokio::test]
async fn fake_rebuild_validates_the_entire_prefix_before_mutation() {
    assert_rebuild_sequence_contract(FakeSessionBackend::new).await;
}

#[tokio::test]
async fn sqlite_rebuild_validates_the_entire_prefix_before_mutation() {
    assert_rebuild_sequence_contract(|| {
        SqliteSessionBackend::in_memory().expect("create in-memory SQLite backend")
    })
    .await;
}

#[tokio::test]
async fn sqlite_checks_signed_query_and_entry_boundaries() {
    let backend = SqliteSessionBackend::in_memory().expect("create in-memory SQLite backend");
    let first = entry(1, "first");
    backend
        .replicate_entry(first.clone())
        .await
        .expect("seed SQLite replication log");

    assert_eq!(
        backend
            .replicate_entry(entry(u64::MAX, "maximum"))
            .await
            .expect_err("SQLite cannot represent u64::MAX"),
        StoreError::InvalidReplicationSequence
    );
    assert!(backend
        .get_replication_log(u64::MAX, 1)
        .await
        .expect("an out-of-range start must be an empty bounded query")
        .is_empty());
    assert_eq!(
        backend
            .get_replication_log(1, MAX_REPLICATION_LOG_PAGE_ENTRIES + 1)
            .await
            .expect_err("an oversized page request must be rejected"),
        StoreError::ReplicationLogPageTooLarge {
            requested: MAX_REPLICATION_LOG_PAGE_ENTRIES + 1,
            max: MAX_REPLICATION_LOG_PAGE_ENTRIES,
        }
    );
}

#[tokio::test]
async fn sqlite_rejects_legacy_negative_sequence_rows() {
    let file = NamedTempFile::new().expect("temporary SQLite file");
    let conn = rusqlite::Connection::open(file.path()).expect("open raw SQLite database");
    conn.execute_batch(
        r#"
        CREATE TABLE session_replication_log (
            sequence INTEGER PRIMARY KEY,
            tx_id TEXT NOT NULL,
            entry_json TEXT NOT NULL,
            timestamp TEXT NOT NULL
        );
        INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp)
        VALUES (-1, 'legacy-negative', '{}', '1970-01-01T00:00:00Z');
        "#,
    )
    .expect("create legacy corrupt replication row");
    drop(conn);

    let backend = SqliteSessionBackend::open(file.path()).expect("open legacy SQLite database");
    assert_eq!(
        backend
            .max_replication_sequence()
            .await
            .expect_err("negative persisted sequence must fail closed"),
        StoreError::InvalidReplicationSequence
    );
}

#[tokio::test]
async fn sqlite_rejects_row_and_payload_sequence_disagreement() {
    let file = NamedTempFile::new().expect("temporary SQLite file");
    let first = entry(1, "first");
    {
        let backend =
            SqliteSessionBackend::open(file.path()).expect("create file-backed SQLite backend");
        backend
            .replicate_entry(first.clone())
            .await
            .expect("seed SQLite replication log");
    }

    let forged = ReplicationEntry {
        sequence: 2,
        ..first
    };
    let conn = rusqlite::Connection::open(file.path()).expect("reopen raw SQLite database");
    conn.execute(
        "UPDATE session_replication_log SET entry_json = ?1 WHERE sequence = 1",
        [serde_json::to_string(&forged).expect("serialize forged entry")],
    )
    .expect("forge mismatched replication payload");
    drop(conn);

    let backend = SqliteSessionBackend::open(file.path()).expect("reopen SQLite backend");
    assert_eq!(
        backend
            .get_replication_log(1, 1)
            .await
            .expect_err("row key and payload sequence must agree"),
        StoreError::InvalidReplicationSequence
    );
}
