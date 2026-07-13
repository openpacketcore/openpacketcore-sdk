use opc_session_store::fake::FakeBackendLimits;
use opc_session_store::{
    validate_replication_log_page, FakeSessionBackend, ReplicationEntry, ReplicationLogRange,
    ReplicationOp, ReplicationTxId, SessionBackend, SqliteSessionBackend, StoreError,
    MAX_REPLICATION_LOG_PAGE_ENTRIES,
};
use opc_types::Timestamp;

fn entry(sequence: u64) -> ReplicationEntry {
    ReplicationEntry {
        sequence,
        tx_id: ReplicationTxId::new(&format!("range-{sequence}")).expect("valid transaction ID"),
        op: ReplicationOp::Batch { ops: Vec::new() },
        timestamp: Timestamp::now_utc(),
    }
}

#[test]
fn range_normalizes_zero_and_checks_exact_boundaries_before_io() {
    let empty = ReplicationLogRange::try_new(0, 0).expect("zero-limit sentinel range");
    assert_eq!(empty.first_sequence(), 1);
    assert_eq!(empty.last_sequence(), None);
    assert_eq!(empty.limit(), 0);
    assert!(empty.is_empty());

    for start in [0, 1] {
        let range = ReplicationLogRange::try_new(start, 1).expect("one-entry range");
        assert_eq!(range.first_sequence(), 1);
        assert_eq!(range.last_sequence(), Some(1));
    }

    let first = u64::MAX - (MAX_REPLICATION_LOG_PAGE_ENTRIES as u64 - 1);
    let maximum = ReplicationLogRange::try_new(first, MAX_REPLICATION_LOG_PAGE_ENTRIES)
        .expect("exact maximum interval ending at u64::MAX");
    assert_eq!(maximum.first_sequence(), first);
    assert_eq!(maximum.last_sequence(), Some(u64::MAX));

    assert_eq!(
        ReplicationLogRange::try_new(1, MAX_REPLICATION_LOG_PAGE_ENTRIES + 1)
            .expect_err("one over the model page limit"),
        StoreError::ReplicationLogPageTooLarge {
            requested: MAX_REPLICATION_LOG_PAGE_ENTRIES + 1,
            max: MAX_REPLICATION_LOG_PAGE_ENTRIES,
        }
    );
    assert!(ReplicationLogRange::try_new(u64::MAX, 0)
        .expect("empty maximum cursor")
        .is_empty());
    assert_eq!(
        ReplicationLogRange::try_new(u64::MAX, 1)
            .expect("terminal single-entry interval")
            .last_sequence(),
        Some(u64::MAX)
    );
    assert_eq!(
        ReplicationLogRange::try_new(u64::MAX, 2).expect_err("checked interval overflow"),
        StoreError::InvalidReplicationLogRange
    );
}

#[test]
fn page_validation_requires_the_exact_requested_prefix_and_interval() {
    for start in [0, 1] {
        validate_replication_log_page(start, 3, &[entry(1), entry(2), entry(3)])
            .expect("complete sentinel page");
        validate_replication_log_page(start, 3, &[entry(1)])
            .expect("short exact prefix at the current head");
    }
    validate_replication_log_page(2, 2, &[entry(2), entry(3)]).expect("exact middle page");
    validate_replication_log_page(4, 2, &[]).expect("terminal or future empty page");
    validate_replication_log_page(u64::MAX, 1, &[]).expect("future maximum empty page");
    validate_replication_log_page(1, 0, &[]).expect("zero-limit page");

    for (start, limit, entries) in [
        (2, 2, vec![entry(1), entry(2)]),
        (2, 2, vec![entry(3), entry(4)]),
        (2, 2, vec![entry(2), entry(4)]),
        (2, 1, vec![entry(2), entry(3)]),
        (1, 0, vec![entry(1)]),
    ] {
        assert_eq!(
            validate_replication_log_page(start, limit, &entries)
                .expect_err("page outside the requested interval"),
            StoreError::InvalidReplicationSequence
        );
    }
}

#[test]
fn compaction_is_typed_and_zero_limit_never_consults_the_floor() {
    let start_two = ReplicationLogRange::try_new(2, 1).expect("range");
    start_two
        .ensure_not_compacted(1)
        .expect("compaction before the requested cursor");
    assert_eq!(
        start_two
            .ensure_not_compacted(2)
            .expect_err("compaction at the requested cursor"),
        StoreError::ReplicationLogCursorCompacted { resume_from: 3 }
    );
    assert_eq!(
        start_two
            .ensure_not_compacted(3)
            .expect_err("compaction after the requested cursor"),
        StoreError::ReplicationLogCursorCompacted { resume_from: 4 }
    );
    assert_eq!(
        ReplicationLogRange::try_new(0, 1)
            .expect("sentinel range")
            .ensure_not_compacted(1)
            .expect_err("zero sentinel names sequence one"),
        StoreError::ReplicationLogCursorCompacted { resume_from: 2 }
    );
    ReplicationLogRange::try_new(u64::MAX, 0)
        .expect("empty maximum range")
        .ensure_not_compacted(u64::MAX)
        .expect("zero limit returns before compaction arithmetic");
}

async fn append(backend: &dyn SessionBackend, sequence: u64) {
    backend
        .replicate_entry(entry(sequence))
        .await
        .expect("append replication entry");
}

fn sequences(entries: &[ReplicationEntry]) -> Vec<u64> {
    entries.iter().map(|entry| entry.sequence).collect()
}

#[tokio::test]
async fn fake_and_sqlite_apply_identical_terminal_future_and_limit_semantics() {
    let fake = FakeSessionBackend::new();
    let sqlite = SqliteSessionBackend::in_memory().expect("SQLite backend");
    for backend in [&fake as &dyn SessionBackend, &sqlite as &dyn SessionBackend] {
        for sequence in 1..=3 {
            append(backend, sequence).await;
        }
        assert_eq!(
            sequences(
                &backend
                    .get_replication_log(0, MAX_REPLICATION_LOG_PAGE_ENTRIES)
                    .await
                    .expect("zero-sentinel page"),
            ),
            vec![1, 2, 3]
        );
        assert_eq!(
            sequences(
                &backend
                    .get_replication_log(2, 1)
                    .await
                    .expect("middle page"),
            ),
            vec![2]
        );
        for start in [4, 5, u64::MAX] {
            assert!(backend
                .get_replication_log(start, 1)
                .await
                .expect("terminal or future page")
                .is_empty());
        }
        assert!(backend
            .get_replication_log(u64::MAX, 0)
            .await
            .expect("empty maximum range")
            .is_empty());
        assert_eq!(
            backend
                .get_replication_log(u64::MAX, 2)
                .await
                .expect_err("interval overflow"),
            StoreError::InvalidReplicationLogRange
        );
        assert_eq!(
            backend
                .get_replication_log(1, MAX_REPLICATION_LOG_PAGE_ENTRIES + 1)
                .await
                .expect_err("one over page limit"),
            StoreError::ReplicationLogPageTooLarge {
                requested: MAX_REPLICATION_LOG_PAGE_ENTRIES + 1,
                max: MAX_REPLICATION_LOG_PAGE_ENTRIES,
            }
        );
    }
}

#[tokio::test]
async fn fake_compaction_never_skips_to_its_first_retained_entry() {
    let fake = FakeSessionBackend::with_limits(FakeBackendLimits {
        max_tracked_keys: 8,
        max_replication_entries: 2,
    });
    for sequence in 1..=3 {
        append(&fake, sequence).await;
    }

    for start in [0, 1] {
        assert_eq!(
            fake.get_replication_log(start, 2)
                .await
                .expect_err("sequence one was compacted"),
            StoreError::ReplicationLogCursorCompacted { resume_from: 2 }
        );
    }
    assert_eq!(
        sequences(
            &fake
                .get_replication_log(2, 2)
                .await
                .expect("first retained page"),
        ),
        vec![2, 3]
    );
    assert!(fake
        .get_replication_log(0, 0)
        .await
        .expect("zero limit bypasses compaction")
        .is_empty());
}
