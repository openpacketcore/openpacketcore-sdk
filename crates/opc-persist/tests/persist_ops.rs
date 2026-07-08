mod persist_common;

use opc_persist::{ConfigStore, MockConfigStore, PersistErrorKind, RollbackTarget, SqliteBackend};
use opc_types::{Timestamp, TxId};
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
    backend
        .append_commit(rec2.clone(), vec![])
        .await
        .expect("append v2");

    let tx3 = TxId::new();
    let mut rec3 = make_commit_record(tx3, 3);
    rec3.rollback_point = false;
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
    let record = make_commit_record(tx_id, 1);
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
