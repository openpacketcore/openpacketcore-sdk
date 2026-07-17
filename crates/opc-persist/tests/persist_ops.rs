mod persist_common;

use opc_persist::{
    ConfigStore, ConfirmedCommitResolution, MockConfigStore, PersistErrorKind, RollbackTarget,
    SqliteBackend, CONFIG_HISTORY_PAGE_MAX_ENTRIES,
};
use opc_types::{ConfigVersion, Timestamp, TxId};
use std::sync::Arc;

use persist_common::{make_audit_record, make_commit_record};

#[tokio::test]
async fn append_commit_inserts_record_and_audit_atomically() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_atomicity.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let tx_id = TxId::new();
    let record = make_commit_record(tx_id, 1);
    let audit = vec![
        make_audit_record(tx_id, 0, "/test:config/value"),
        make_audit_record(tx_id, 1, "/test:config/enabled"),
    ];

    backend
        .append_commit(record.clone(), audit.clone())
        .await
        .expect("append_commit should succeed");

    let loaded = backend
        .load_latest()
        .await
        .expect("load_latest should succeed")
        .expect("should have a latest config");

    assert_eq!(loaded.record.tx_id, tx_id);
    assert_eq!(loaded.audit.len(), 2);
    assert_eq!(loaded.audit[0].sequence, 0);
    assert_eq!(loaded.audit[1].sequence, 1);
    assert_eq!(loaded.audit[0].yang_path, "/test:config/value");
    assert_eq!(loaded.audit[1].yang_path, "/test:config/enabled");
}

#[tokio::test]
async fn append_commit_rejects_duplicate_tx_id() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_duplicate.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let tx_id = TxId::new();
    let record = make_commit_record(tx_id, 1);
    let audit = vec![make_audit_record(tx_id, 0, "/test:config/value")];

    backend
        .append_commit(record.clone(), audit.clone())
        .await
        .expect("first append should succeed");

    let err = backend
        .append_commit(record, audit)
        .await
        .expect_err("duplicate tx_id should fail");

    match err.kind() {
        PersistErrorKind::ConstraintViolation(_) => {}
        _ => panic!("expected constraint violation, got: {err}"),
    }
}

#[tokio::test]
async fn append_commit_multiple_versions_can_be_loaded() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_versions.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let tx1 = TxId::new();
    let rec1 = make_commit_record(tx1, 1);
    backend
        .append_commit(rec1, vec![])
        .await
        .expect("append v1");

    let tx2 = TxId::new();
    let mut rec2 = make_commit_record(tx2, 2);
    rec2.parent_tx_id = Some(tx1);
    backend
        .append_commit(rec2.clone(), vec![])
        .await
        .expect("append v2");

    let latest = backend
        .load_latest()
        .await
        .expect("load_latest should succeed")
        .expect("should have latest");
    assert_eq!(latest.record.version.get(), 2);

    let by_tx = backend
        .load_rollback(RollbackTarget::ByTxId(tx1))
        .await
        .expect("load_rollback by tx_id should succeed");
    assert_eq!(by_tx.record.version.get(), 1);
}

async fn assert_ordered_bounded_history_pages(store: &dyn ConfigStore) {
    let mut parent = None;
    for version in 1..=5 {
        let tx_id = TxId::new();
        let mut record = make_commit_record(tx_id, version);
        record.parent_tx_id = parent;
        store
            .append_commit(record, Vec::new())
            .await
            .expect("append page fixture");
        parent = Some(tx_id);
    }

    let page = store
        .load_since(ConfigVersion::new(1), 2)
        .await
        .expect("bounded middle page");
    assert_eq!(2, page.len());
    assert_eq!(ConfigVersion::new(2), page[0].record.version);
    assert_eq!(ConfigVersion::new(3), page[1].record.version);

    let tail = store
        .load_since(ConfigVersion::new(3), CONFIG_HISTORY_PAGE_MAX_ENTRIES)
        .await
        .expect("ordered tail page");
    assert_eq!(2, tail.len());
    assert_eq!(ConfigVersion::new(4), tail[0].record.version);
    assert_eq!(ConfigVersion::new(5), tail[1].record.version);

    let empty = store
        .load_since(ConfigVersion::new(5), CONFIG_HISTORY_PAGE_MAX_ENTRIES)
        .await
        .expect("page at head");
    assert!(empty.is_empty());

    let oversized = store
        .load_since(ConfigVersion::INITIAL, CONFIG_HISTORY_PAGE_MAX_ENTRIES + 1)
        .await
        .expect_err("over-contract page rejected");
    assert!(matches!(
        oversized.kind(),
        PersistErrorKind::ConstraintViolation(_)
    ));
}

async fn append_cleared_prefix_and_fenced_tail(store: &dyn ConfigStore) -> (TxId, TxId) {
    let cleared_tx_id = TxId::new();
    store
        .append_commit(make_commit_record(cleared_tx_id, 1), Vec::new())
        .await
        .expect("append cleared prefix");

    let fenced_tx_id = TxId::new();
    let mut fenced = make_commit_record(fenced_tx_id, 2);
    fenced.parent_tx_id = Some(cleared_tx_id);
    fenced.confirmed_deadline = Some(Timestamp::now_utc());
    fenced.principal = serde_json::json!({
        "principal": fenced.principal,
        "recovery_required": true,
    })
    .to_string();
    store
        .append_commit(fenced, Vec::new())
        .await
        .expect("append fenced tail");
    (cleared_tx_id, fenced_tx_id)
}

async fn assert_fenced_tail_visibility(store: &dyn ConfigStore) {
    let (cleared_tx_id, fenced_tx_id) = append_cleared_prefix_and_fenced_tail(store).await;
    let durable = store
        .load_latest()
        .await
        .expect("durable head")
        .expect("fenced durable tail");
    assert_eq!(fenced_tx_id, durable.record.tx_id);
    let visible = store
        .load_committed_latest()
        .await
        .expect("publish-safe head")
        .expect("cleared prefix");
    assert_eq!(cleared_tx_id, visible.record.tx_id);
    assert!(store
        .load_since(ConfigVersion::new(1), CONFIG_HISTORY_PAGE_MAX_ENTRIES)
        .await
        .expect("publish-safe page")
        .is_empty());

    store
        .clear_recovery_required(fenced_tx_id)
        .await
        .expect("clear fenced tail");
    let visible = store
        .load_committed_latest()
        .await
        .expect("publish-safe head")
        .expect("cleared tail");
    assert_eq!(fenced_tx_id, visible.record.tx_id);
    assert!(visible.record.confirmed_deadline.is_some());
    let page = store
        .load_since(ConfigVersion::new(1), CONFIG_HISTORY_PAGE_MAX_ENTRIES)
        .await
        .expect("cleared tail page");
    assert_eq!(1, page.len());
    assert_eq!(fenced_tx_id, page[0].record.tx_id);
}

async fn assert_publication_fence_blocks_a_successor(store: &dyn ConfigStore) {
    let first_id = TxId::new();
    store
        .append_commit(make_commit_record(first_id, 1), Vec::new())
        .await
        .expect("append cleared prefix");
    let fenced_id = TxId::new();
    let mut fenced = make_commit_record(fenced_id, 2);
    fenced.parent_tx_id = Some(first_id);
    fenced.principal = serde_json::json!({
        "principal": fenced.principal,
        "recovery_required": true,
    })
    .to_string();
    store
        .append_commit(fenced, Vec::new())
        .await
        .expect("append fenced tail");

    let successor_id = TxId::new();
    let mut successor = make_commit_record(successor_id, 3);
    successor.parent_tx_id = Some(fenced_id);
    let error = store
        .append_commit(successor, Vec::new())
        .await
        .expect_err("a successor cannot skip the publication fence");
    assert!(matches!(
        error.kind(),
        PersistErrorKind::ConstraintViolation(_)
    ));
}

#[tokio::test]
async fn sqlite_history_pages_are_ordered_and_bounded() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let backend = SqliteBackend::open(temp_dir.path().join("history-page.db"), true, 0)
        .await
        .expect("open backend");
    assert_ordered_bounded_history_pages(&backend).await;
}

#[tokio::test]
async fn mock_history_pages_match_the_sqlite_contract() {
    assert_ordered_bounded_history_pages(&MockConfigStore::new()).await;
}

#[tokio::test]
async fn sqlite_committed_history_stops_at_the_publication_fence() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let backend = SqliteBackend::open(temp_dir.path().join("fenced-history.db"), true, 0)
        .await
        .expect("open backend");
    assert_fenced_tail_visibility(&backend).await;
}

#[tokio::test]
async fn mock_committed_history_stops_at_the_publication_fence() {
    assert_fenced_tail_visibility(&MockConfigStore::new()).await;
}

#[tokio::test]
async fn sqlite_publication_fence_blocks_a_successor() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let backend = SqliteBackend::open(temp_dir.path().join("fenced-successor.db"), true, 0)
        .await
        .expect("open backend");
    assert_publication_fence_blocks_a_successor(&backend).await;
}

#[tokio::test]
async fn mock_publication_fence_blocks_a_successor() {
    assert_publication_fence_blocks_a_successor(&MockConfigStore::new()).await;
}

#[tokio::test]
async fn sqlite_restart_keeps_a_fenced_tail_out_of_the_visible_prefix() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let path = temp_dir.path().join("fenced-restart.db");
    let backend = SqliteBackend::open(&path, true, 0)
        .await
        .expect("open backend");
    let (cleared_tx_id, fenced_tx_id) = append_cleared_prefix_and_fenced_tail(&backend).await;
    drop(backend);

    let reopened = SqliteBackend::open(&path, true, 0)
        .await
        .expect("reopen backend");
    let visible = reopened
        .load_committed_latest()
        .await
        .expect("publish-safe head after restart")
        .expect("cleared prefix after restart");
    assert_eq!(cleared_tx_id, visible.record.tx_id);
    assert!(reopened
        .load_since(ConfigVersion::new(1), CONFIG_HISTORY_PAGE_MAX_ENTRIES)
        .await
        .expect("publish-safe page after restart")
        .is_empty());
    reopened
        .clear_recovery_required(fenced_tx_id)
        .await
        .expect("operator reconciliation clears tail");
    assert_eq!(
        fenced_tx_id,
        reopened
            .load_committed_latest()
            .await
            .expect("publish-safe head after reconciliation")
            .expect("cleared tail")
            .record
            .tx_id
    );
}

#[tokio::test]
async fn load_latest_returns_none_when_empty() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_empty.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let result = backend
        .load_latest()
        .await
        .expect("load_latest should not error on empty store");
    assert!(result.is_none(), "expected None for empty store");
}

#[tokio::test]
async fn load_latest_returns_most_recent_by_version() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_latest.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let tx1 = TxId::new();
    let mut rec1 = make_commit_record(tx1, 1);
    rec1.rollback_point = false;
    backend
        .append_commit(rec1, vec![])
        .await
        .expect("append v1");

    let tx2 = TxId::new();
    let mut rec2 = make_commit_record(tx2, 2);
    rec2.rollback_point = false;
    rec2.parent_tx_id = Some(tx1);
    backend
        .append_commit(rec2.clone(), vec![])
        .await
        .expect("append v2");

    let tx3 = TxId::new();
    let mut rec3 = make_commit_record(tx3, 3);
    rec3.rollback_point = false;
    rec3.parent_tx_id = Some(tx2);
    backend
        .append_commit(rec3.clone(), vec![])
        .await
        .expect("append v3");

    let latest = backend
        .load_latest()
        .await
        .expect("load_latest should succeed")
        .expect("should have latest");
    assert_eq!(latest.record.version.get(), 3);
    assert_eq!(latest.record.tx_id, tx3);
}

#[tokio::test]
async fn corrupt_blob_stored_as_is_but_can_be_loaded() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_corrupt_blob.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let tx_id = TxId::new();
    let mut record = make_commit_record(tx_id, 1);
    record.encrypted_blob = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xFF, 0xFF, 0xFF];

    backend
        .append_commit(record.clone(), vec![])
        .await
        .expect("append with corrupt-looking blob should succeed");

    let loaded = backend
        .load_latest()
        .await
        .expect("load_latest should succeed")
        .expect("should have config");
    assert_eq!(
        loaded.record.encrypted_blob,
        &[0xDE, 0xAD, 0xBE, 0xEF, 0xFF, 0xFF, 0xFF, 0xFF]
    );
}

#[tokio::test]
async fn append_commit_with_empty_blob_fails_gracefully() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_empty_blob.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let tx_id = TxId::new();
    let mut record = make_commit_record(tx_id, 1);
    record.encrypted_blob = vec![];

    let result = backend.append_commit(record, vec![]).await;
    assert!(
        result.is_ok(),
        "empty blob should be storable (crypto layer rejects at decrypt time)"
    );
}

#[tokio::test]
async fn rollback_by_version_loads_correct_commit() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_rollback_version.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let tx1 = TxId::new();
    let tx2 = TxId::new();

    let mut rec1 = make_commit_record(tx1, 1);
    rec1.parent_tx_id = None;
    backend
        .append_commit(rec1.clone(), vec![])
        .await
        .expect("append v1");

    let mut rec2 = make_commit_record(tx2, 2);
    rec2.parent_tx_id = Some(tx1);
    backend
        .append_commit(rec2.clone(), vec![])
        .await
        .expect("append v2");

    let by_version = backend
        .load_rollback(RollbackTarget::ByVersion(opc_types::ConfigVersion::new(1)))
        .await
        .expect("rollback by version should succeed");
    assert_eq!(by_version.record.version.get(), 1);

    let err = backend
        .load_rollback(RollbackTarget::ByVersion(opc_types::ConfigVersion::new(99)))
        .await
        .expect_err("non-existent version should fail");
    assert!(matches!(err.kind(), PersistErrorKind::RollbackNotFound));
}

#[tokio::test]
async fn mark_confirmed_updates_commit_record() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_confirmed.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let tx_id = TxId::new();
    let mut record = make_commit_record(tx_id, 1);
    record.confirmed_deadline = Some(Timestamp::now_utc());
    backend
        .append_commit(record, vec![])
        .await
        .expect("append should succeed");

    backend
        .mark_confirmed(tx_id)
        .await
        .expect("mark_confirmed should succeed");

    let loaded = backend
        .load_latest()
        .await
        .expect("load_latest should succeed")
        .expect("should have config");
    assert_eq!(loaded.record.tx_id, tx_id);
}

#[tokio::test]
async fn mock_mark_confirmed_clears_pending_deadline() {
    let mock = MockConfigStore::new();

    let tx_id = TxId::new();
    let mut record = make_commit_record(tx_id, 1);
    record.confirmed_deadline = Some(Timestamp::from(time::OffsetDateTime::UNIX_EPOCH));

    mock.append_commit(record, vec![])
        .await
        .expect("mock append should succeed");
    mock.mark_confirmed(tx_id)
        .await
        .expect("mock mark_confirmed should succeed");

    let latest = mock
        .load_latest()
        .await
        .expect("mock load_latest should succeed")
        .expect("latest should exist");
    assert!(
        latest.record.confirmed_deadline.is_none(),
        "mock load_latest should mirror SQLite by hiding confirmed deadlines"
    );

    let rollback = mock
        .load_rollback(RollbackTarget::ByTxId(tx_id))
        .await
        .expect("confirmed commit should be a rollback target");
    assert!(rollback.record.confirmed_deadline.is_none());
}

async fn race_confirm_and_rollback(store: Arc<dyn ConfigStore>) -> TxId {
    let pending_tx_id = TxId::new();
    let mut pending = make_commit_record(pending_tx_id, 1);
    pending.confirmed_deadline = Some(Timestamp::now_utc());
    store
        .append_commit(pending, Vec::new())
        .await
        .expect("append pending head");

    let confirm_tx_id = TxId::new();
    let mut confirm = make_commit_record(confirm_tx_id, 2);
    confirm.parent_tx_id = Some(pending_tx_id);
    let rollback_tx_id = TxId::new();
    let mut rollback = make_commit_record(rollback_tx_id, 2);
    rollback.parent_tx_id = Some(pending_tx_id);

    let confirm_store = Arc::clone(&store);
    let rollback_store = Arc::clone(&store);
    let (confirm_result, rollback_result) = tokio::join!(
        confirm_store.append_commit_resolving(
            confirm,
            Vec::new(),
            ConfirmedCommitResolution::Confirm { pending_tx_id },
        ),
        rollback_store.append_commit_resolving(
            rollback,
            Vec::new(),
            ConfirmedCommitResolution::Rollback { pending_tx_id },
        ),
    );

    assert_ne!(
        confirm_result.is_ok(),
        rollback_result.is_ok(),
        "exactly one persisted decision must win"
    );
    let expected_tx_id = if confirm_result.is_ok() {
        confirm_tx_id
    } else {
        rollback_tx_id
    };
    let latest = store
        .load_latest()
        .await
        .expect("load decided head")
        .expect("decided head exists");
    assert_eq!(expected_tx_id, latest.record.tx_id);
    assert_eq!(2, latest.record.version.get());

    let stale_confirm = store
        .mark_confirmed(pending_tx_id)
        .await
        .expect_err("a successor makes the old pending decision immutable");
    assert!(matches!(
        stale_confirm.kind(),
        PersistErrorKind::RollbackNotFound | PersistErrorKind::ConstraintViolation(_)
    ));
    expected_tx_id
}

#[tokio::test]
async fn sqlite_confirm_and_rollback_are_one_atomic_decision() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("confirmed_decision_race.db");
    let backend: Arc<dyn ConfigStore> = Arc::new(
        SqliteBackend::open(&db_path, true, 0)
            .await
            .expect("open backend"),
    );
    let expected_tx_id = race_confirm_and_rollback(backend).await;

    let reopened = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("reopen backend");
    let latest = reopened
        .load_latest()
        .await
        .expect("load decision after restart")
        .expect("decision survives restart");
    assert_eq!(2, latest.record.version.get());
    assert_eq!(expected_tx_id, latest.record.tx_id);
}

#[tokio::test]
async fn mock_confirm_and_rollback_are_one_atomic_decision() {
    let _ = race_confirm_and_rollback(Arc::new(MockConfigStore::new())).await;
}

async fn assert_recovery_marker_lifecycle(store: &dyn ConfigStore) {
    let tx_id = TxId::new();
    let mut record = make_commit_record(tx_id, 1);
    record.principal = serde_json::json!({
        "principal": "spiffe://test.invalid/config-writer",
        "recovery_required": true,
    })
    .to_string();
    store
        .append_commit(record, Vec::new())
        .await
        .expect("append recovery-marked commit");

    store
        .clear_recovery_required(tx_id)
        .await
        .expect("clear current recovery marker");
    store
        .clear_recovery_required(tx_id)
        .await
        .expect("repeated clear is idempotent");
    let latest = store
        .load_latest()
        .await
        .expect("load cleared record")
        .expect("cleared record exists");
    let metadata: serde_json::Value =
        serde_json::from_str(&latest.record.principal).expect("decode recovery metadata");
    assert_eq!(Some(false), metadata["recovery_required"].as_bool());
}

#[tokio::test]
async fn sqlite_recovery_marker_clear_is_durable_and_idempotent() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("recovery_marker.db");
    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");
    assert_recovery_marker_lifecycle(&backend).await;
    drop(backend);

    let reopened = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("reopen backend");
    let latest = reopened
        .load_latest()
        .await
        .expect("load cleared record after restart")
        .expect("cleared record survives restart");
    let metadata: serde_json::Value =
        serde_json::from_str(&latest.record.principal).expect("decode recovery metadata");
    assert_eq!(Some(false), metadata["recovery_required"].as_bool());
}

#[tokio::test]
async fn mock_recovery_marker_clear_is_idempotent() {
    assert_recovery_marker_lifecycle(&MockConfigStore::new()).await;
}

#[tokio::test]
async fn create_rollback_point_marks_commit() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_rollback_point.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let tx_id = TxId::new();
    let record = make_commit_record(tx_id, 1);
    backend
        .append_commit(record, vec![])
        .await
        .expect("append should succeed");

    backend
        .create_rollback_point(tx_id, Some("golden-config".to_string()))
        .await
        .expect("create_rollback_point should succeed");

    let loaded = backend
        .load_rollback(RollbackTarget::ByLabel("golden-config".to_string()))
        .await
        .expect("load by label should succeed");
    assert_eq!(loaded.record.tx_id, tx_id);
}

#[tokio::test]
async fn lifecycle_mutations_record_audit_rows_with_principal() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_lifecycle_audit.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let tx_id = TxId::new();
    let mut record = make_commit_record(tx_id, 1);
    record.confirmed_deadline = Some(Timestamp::now_utc());
    let principal = record.principal.clone();
    backend
        .append_commit(record, vec![])
        .await
        .expect("append pending commit");

    backend
        .mark_confirmed(tx_id)
        .await
        .expect("mark_confirmed should succeed");
    backend
        .create_rollback_point(tx_id, Some("golden-config".to_string()))
        .await
        .expect("create_rollback_point should succeed");

    let conn = rusqlite::Connection::open(&db_path).expect("open database");
    let mut stmt = conn
        .prepare(
            "SELECT action, principal FROM config_lifecycle_audit WHERE tx_id = ?1 ORDER BY id ASC",
        )
        .expect("prepare lifecycle audit query");
    let rows = stmt
        .query_map(rusqlite::params![tx_id.as_uuid().as_bytes()], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .expect("query lifecycle audit");
    let rows: Vec<_> = rows
        .map(|row| row.expect("read lifecycle audit row"))
        .collect();

    assert_eq!(
        rows,
        vec![
            ("MARK_CONFIRMED".to_string(), principal.clone()),
            ("CREATE_ROLLBACK_POINT".to_string(), principal),
        ]
    );
}

#[tokio::test]
async fn concurrent_load_latest_does_not_block() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_concurrent.db");

    let backend = Arc::new(
        SqliteBackend::open(&db_path, true, 0)
            .await
            .expect("open backend"),
    );

    let tx_id = TxId::new();
    backend
        .append_commit(make_commit_record(tx_id, 1), vec![])
        .await
        .expect("append should succeed");

    let handles: Vec<_> = (0..10)
        .map(|_| {
            let backend = backend.clone();
            tokio::spawn(async move {
                for _ in 0..100 {
                    let _ = backend.load_latest().await;
                }
            })
        })
        .collect();

    for h in handles {
        h.await.expect("task should complete");
    }
}

#[tokio::test]
async fn rollback_target_previous_returns_parent_not_newest() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_rollback_previous.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let tx1 = TxId::new();
    let rec1 = make_commit_record(tx1, 1);
    backend
        .append_commit(rec1, vec![])
        .await
        .expect("append v1");

    let tx2 = TxId::new();
    let mut rec2 = make_commit_record(tx2, 2);
    rec2.parent_tx_id = Some(tx1);
    backend
        .append_commit(rec2, vec![])
        .await
        .expect("append v2");

    let previous = backend
        .load_rollback(RollbackTarget::Previous)
        .await
        .expect("Previous target should exist");

    assert_eq!(
        previous.record.version.get(),
        1,
        "RollbackTarget::Previous must return the parent (v1), not the newest row (v2)"
    );
    assert_eq!(
        previous.record.tx_id, tx1,
        "RollbackTarget::Previous tx_id must match v1's tx_id"
    );
}

#[tokio::test]
async fn append_commit_ignores_entry_tx_id_uses_record_tx_id() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_audit_txid_binding.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let record_tx_id = TxId::new();
    let wrong_tx_id = TxId::new();

    let record = make_commit_record(record_tx_id, 1);
    let mut audit_entry = make_audit_record(wrong_tx_id, 0, "/test:wrong-path");
    audit_entry.tx_id = wrong_tx_id;

    backend
        .append_commit(record, vec![audit_entry])
        .await
        .expect("append should succeed");

    let loaded = backend
        .load_latest()
        .await
        .expect("load_latest should succeed")
        .expect("should have config");

    assert_eq!(
        loaded.record.tx_id, record_tx_id,
        "commit record should use the correct tx_id"
    );
    assert_eq!(
        loaded.audit.len(),
        1,
        "audit entry should be stored under record_tx_id, not wrong_tx_id"
    );
    assert_eq!(
        loaded.audit[0].sequence, 0,
        "audit sequence should match what was inserted"
    );
    assert_eq!(
        loaded.audit[0].yang_path, "/test:wrong-path",
        "audit content should be preserved even though tx_id was overridden"
    );
}

#[tokio::test]
async fn mock_store_append_and_load_latest_round_trip() {
    let mock = MockConfigStore::new();

    let tx_id = TxId::new();
    let record = make_commit_record(tx_id, 1);
    let audit = vec![make_audit_record(tx_id, 0, "/test:path")];

    mock.append_commit(record.clone(), audit.clone())
        .await
        .expect("mock append should succeed");

    let loaded = mock
        .load_latest()
        .await
        .expect("mock load_latest should succeed")
        .expect("should have config");

    assert_eq!(loaded.record.tx_id, tx_id);
    assert_eq!(loaded.audit.len(), 1);
}

#[tokio::test]
async fn indexed_replay_lookup_finds_a_record_beyond_the_legacy_history_bound() {
    const HISTORY_LEN: usize = 16_385;
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("long_replay_history.db");
    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("initialize backend");
    drop(backend);

    let digest = "a".repeat(64);
    let target_principal = serde_json::json!({
        "principal": "spiffe://test.example/tenant/tenant-a/ns/core/sa/config",
        "replay_lookup_digest": digest,
        "recovery_required": false,
    })
    .to_string();
    let mut conn = rusqlite::Connection::open(&db_path).expect("open direct fixture connection");
    let tx = conn.transaction().expect("begin long-history fixture");
    {
        let mut insert = tx
            .prepare(
                r#"INSERT INTO config_history
                   (tx_id, parent_tx_id, version, committed_at, principal, source,
                    schema_digest, plaintext_digest, encrypted_blob, rollback_point,
                    rollback_label, confirmed_deadline, confirmed_at, audit_count,
                    audit_terminal_hash)
                   VALUES (?1, ?2, ?3, '2026-01-01T00:00:00Z', ?4, 'gnmi',
                           ?5, ?6, ?7, 0, NULL, NULL, NULL, 0, ?8)"#,
            )
            .expect("prepare long-history insert");
        let mut parent: Option<[u8; 16]> = None;
        for offset in 0..HISTORY_LEN {
            let tx_id = u128::try_from(offset + 1)
                .expect("bounded fixture index")
                .to_be_bytes();
            let principal = if offset == 0 {
                target_principal.as_str()
            } else {
                "spiffe://test.example/tenant/tenant-a/ns/core/sa/config"
            };
            insert
                .execute(rusqlite::params![
                    tx_id.as_slice(),
                    parent.as_ref().map(<[u8; 16]>::as_slice),
                    i64::try_from(offset + 1).expect("bounded fixture version"),
                    principal,
                    [0x11_u8; 32].as_slice(),
                    [0x22_u8; 32].as_slice(),
                    [0x33_u8; 32].as_slice(),
                    [0_u8; 32].as_slice(),
                ])
                .expect("insert long-history row");
            parent = Some(tx_id);
        }
    }
    tx.commit().expect("commit long-history fixture");
    drop(conn);

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("reopen long-history backend");
    let record = backend
        .load_by_replay_lookup_digest(&"a".repeat(64))
        .await
        .expect("indexed authoritative lookup")
        .expect("oldest record remains addressable");
    assert_eq!(record.record.version.get(), 1);
    assert_eq!(
        record.record.tx_id.as_uuid().as_bytes(),
        &1_u128.to_be_bytes()
    );
}

fn replay_metadata(digest: char) -> String {
    serde_json::json!({
        "principal": "spiffe://test.invalid/tenant/test/ns/default/sa/config",
        "replay_lookup_digest": digest.to_string().repeat(64),
        "recovery_required": false,
    })
    .to_string()
}

async fn assert_duplicate_replay_digest_is_a_recoverable_conflict(store: &dyn ConfigStore) {
    let first_tx_id = TxId::new();
    let mut first = make_commit_record(first_tx_id, 1);
    first.principal = replay_metadata('a');
    store
        .append_commit(first, Vec::new())
        .await
        .expect("append first replay identity");

    let mut duplicate = make_commit_record(TxId::new(), 2);
    duplicate.parent_tx_id = Some(first_tx_id);
    duplicate.principal = replay_metadata('a');
    let error = store
        .append_commit(duplicate, Vec::new())
        .await
        .expect_err("duplicate replay identity must be rejected");
    assert!(matches!(
        error.kind(),
        PersistErrorKind::ConstraintViolation(_)
    ));

    let successor_tx_id = TxId::new();
    let mut successor = make_commit_record(successor_tx_id, 2);
    successor.parent_tx_id = Some(first_tx_id);
    successor.principal = replay_metadata('b');
    store
        .append_commit(successor, Vec::new())
        .await
        .expect("a later non-conflicting command still applies");
    assert_eq!(
        successor_tx_id,
        store
            .load_latest()
            .await
            .expect("load latest")
            .expect("latest record")
            .record
            .tx_id
    );
}

#[tokio::test]
async fn sqlite_duplicate_replay_digest_is_a_recoverable_conflict() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let store = SqliteBackend::open(temp_dir.path().join("replay-conflict.db"), true, 0)
        .await
        .expect("open backend");
    assert_duplicate_replay_digest_is_a_recoverable_conflict(&store).await;
}

#[tokio::test]
async fn mock_duplicate_replay_digest_is_a_recoverable_conflict() {
    assert_duplicate_replay_digest_is_a_recoverable_conflict(&MockConfigStore::new()).await;
}

async fn assert_invalid_metadata_is_rejected_without_mutation(store: &dyn ConfigStore) {
    let malformed = [
        format!(
            "{{\"replay_lookup_digest\":\"{}\",\"recovery_required\":true}}",
            "a".repeat(64)
        ),
        "{\"principal\":\"first\",\"principal\":\"second\",\"recovery_required\":false}"
            .to_owned(),
        format!(
            "{{\"principal\":\"spiffe://test.invalid/tenant/test\",\"replay_lookup_digest\":\"{}\",\"replay_lookup_digest\":\"{}\",\"recovery_required\":false}}",
            "a".repeat(64),
            "b".repeat(64)
        ),
        "{\"principal\":\"spiffe://test.invalid/tenant/test\",\"recovery_required\":true,\"recovery_required\":false}"
            .to_owned(),
    ];
    for principal in malformed {
        let mut record = make_commit_record(TxId::new(), 1);
        record.principal = principal;
        let error = store
            .append_commit(record, Vec::new())
            .await
            .expect_err("malformed metadata must fail standalone admission");
        assert!(matches!(
            error.kind(),
            PersistErrorKind::ConstraintViolation(_)
        ));
        assert!(store
            .load_latest()
            .await
            .expect("authoritative empty-state read")
            .is_none());
    }

    store
        .append_commit(make_commit_record(TxId::new(), 1), Vec::new())
        .await
        .expect("valid legacy metadata still applies after rejections");
}

#[tokio::test]
async fn sqlite_standalone_admission_rejects_ambiguous_metadata() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let store = SqliteBackend::open(temp_dir.path().join("metadata-admission.db"), true, 0)
        .await
        .expect("open backend");
    assert_invalid_metadata_is_rejected_without_mutation(&store).await;
}

#[tokio::test]
async fn mock_standalone_admission_rejects_ambiguous_metadata() {
    assert_invalid_metadata_is_rejected_without_mutation(&MockConfigStore::new()).await;
}

#[tokio::test]
async fn indexed_replay_lookup_fails_closed_on_ambiguous_stored_metadata() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let path = temp_dir.path().join("ambiguous-index-metadata.db");
    let store = SqliteBackend::open(&path, true, 0)
        .await
        .expect("open backend");
    let tx_id = TxId::new();
    let mut record = make_commit_record(tx_id, 1);
    record.principal = replay_metadata('a');
    store
        .append_commit(record, Vec::new())
        .await
        .expect("append valid indexed metadata");
    drop(store);

    let conn = rusqlite::Connection::open(&path).expect("open fixture database");
    let malformed = format!(
        "{{\"replay_lookup_digest\":\"{}\",\"recovery_required\":false}}",
        "a".repeat(64)
    );
    conn.execute(
        "UPDATE config_history SET principal = ?1 WHERE tx_id = ?2",
        rusqlite::params![malformed, tx_id.as_uuid().as_bytes().as_slice()],
    )
    .expect("inject wrapper-only indexed metadata");
    drop(conn);

    let store = SqliteBackend::open(&path, true, 0)
        .await
        .expect("reopen backend");
    let error = store
        .load_by_replay_lookup_digest(&"a".repeat(64))
        .await
        .expect_err("indexed corrupt metadata must fail closed");
    assert!(matches!(error.kind(), PersistErrorKind::CorruptBlob));
}
