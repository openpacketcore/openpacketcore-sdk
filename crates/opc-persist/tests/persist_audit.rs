mod persist_common;

use opc_persist::{AuditOpType, AuditRecord, ConfigStore, PersistErrorKind, SqliteBackend};
use opc_types::TxId;

use persist_common::{make_audit_record, make_audit_record_with_op, make_commit_record};

#[tokio::test]
async fn audit_hash_chain_fields_are_populated() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_audit_chain.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let tx_id = TxId::new();

    let audit = vec![
        AuditRecord {
            tx_id,
            sequence: 0,
            yang_path: "/test:config/a".to_string(),
            op_type: AuditOpType::Create,
            previous_value: None,
            new_value: Some(r#""alpha""#.to_string()),
            redaction_applied: false,
            previous_hash: [0u8; 32],
            entry_hmac: [1u8; 32],
        },
        AuditRecord {
            tx_id,
            sequence: 1,
            yang_path: "/test:config/b".to_string(),
            op_type: AuditOpType::Update,
            previous_value: Some(r#""old""#.to_string()),
            new_value: Some(r#""beta""#.to_string()),
            redaction_applied: true,
            previous_hash: [1u8; 32],
            entry_hmac: [2u8; 32],
        },
        AuditRecord {
            tx_id,
            sequence: 2,
            yang_path: "/test:config/c".to_string(),
            op_type: AuditOpType::Delete,
            previous_value: Some(r#""gamma""#.to_string()),
            new_value: None,
            redaction_applied: false,
            previous_hash: [2u8; 32],
            entry_hmac: [3u8; 32],
        },
    ];

    let record = make_commit_record(tx_id, 1);
    backend
        .append_commit(record, audit)
        .await
        .expect("append should succeed");

    let loaded = backend
        .load_latest()
        .await
        .expect("load_latest should succeed")
        .expect("should have config");

    assert_eq!(loaded.audit.len(), 3);
    assert_eq!(loaded.audit[0].previous_hash, [0u8; 32]);
    assert_eq!(loaded.audit[1].previous_hash, loaded.audit[0].entry_hmac);
    assert_eq!(loaded.audit[2].previous_hash, loaded.audit[1].entry_hmac);

    backend
        .verify_audit_chain(&loaded)
        .expect("audit chain verification should pass");

    assert!(matches!(loaded.audit[1].op_type, AuditOpType::Update));
    assert!(loaded.audit[1].redaction_applied);
}

#[tokio::test]
async fn audit_hash_chain_op_types_are_all_supported() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_op_types.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let tx_id = TxId::new();

    let audit = vec![
        make_audit_record_with_op(tx_id, 0, "/test:create", AuditOpType::Create),
        make_audit_record_with_op(tx_id, 1, "/test:update", AuditOpType::Update),
        make_audit_record_with_op(tx_id, 2, "/test:replace", AuditOpType::Replace),
        make_audit_record_with_op(tx_id, 3, "/test:delete", AuditOpType::Delete),
    ];

    let record = make_commit_record(tx_id, 1);
    backend
        .append_commit(record, audit)
        .await
        .expect("append should succeed");

    let loaded = backend
        .load_latest()
        .await
        .expect("load_latest should succeed")
        .expect("should have config");

    assert_eq!(loaded.audit.len(), 4);
    assert!(matches!(loaded.audit[0].op_type, AuditOpType::Create));
    assert!(matches!(loaded.audit[1].op_type, AuditOpType::Update));
    assert!(matches!(loaded.audit[2].op_type, AuditOpType::Replace));
    assert!(matches!(loaded.audit[3].op_type, AuditOpType::Delete));
}

#[tokio::test]
async fn load_latest_fails_closed_on_wrong_length_audit_hash() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("corrupt_hash.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");
    let tx_id = TxId::new();
    backend
        .append_commit(
            make_commit_record(tx_id, 1),
            vec![make_audit_record(tx_id, 0, "/test:path")],
        )
        .await
        .expect("append commit with audit");

    let conn = rusqlite::Connection::open(&db_path).expect("open direct conn");
    let short_hash = vec![0u8; 16];
    conn.execute(
        "UPDATE audit_trail SET previous_hash = ?1 WHERE tx_id = ?2",
        rusqlite::params![short_hash, tx_id.as_uuid().as_bytes()],
    )
    .expect("corrupt previous_hash length");

    let err = backend
        .load_latest()
        .await
        .expect_err("load_latest should fail on wrong-length audit hash");
    assert!(
        matches!(err.kind(), PersistErrorKind::CorruptBlob),
        "expected CorruptBlob for wrong-length previous_hash, got: {err:?}"
    );
}

#[tokio::test]
async fn load_latest_fails_closed_on_wrong_length_entry_hmac() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("corrupt_hmac.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");
    let tx_id = TxId::new();
    backend
        .append_commit(
            make_commit_record(tx_id, 1),
            vec![make_audit_record(tx_id, 0, "/test:path")],
        )
        .await
        .expect("append commit with audit");

    let conn = rusqlite::Connection::open(&db_path).expect("open direct conn");
    conn.execute(
        "UPDATE audit_trail SET entry_hmac = ?1 WHERE tx_id = ?2",
        rusqlite::params![vec![0_u8; 16], tx_id.as_uuid().as_bytes()],
    )
    .expect("corrupt entry_hmac length");

    let err = backend
        .load_latest()
        .await
        .expect_err("load_latest should fail on wrong-length entry_hmac");
    assert!(
        matches!(err.kind(), PersistErrorKind::CorruptBlob),
        "expected CorruptBlob for wrong-length entry_hmac, got: {err:?}"
    );
}

#[tokio::test]
async fn test_audit_trail_redaction_and_chain_verification() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("audit_redaction.db");
    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let tx_id = TxId::new();

    let audit = vec![
        AuditRecord {
            tx_id,
            sequence: 0,
            yang_path: "/test:config/password".to_string(),
            op_type: AuditOpType::Create,
            previous_value: None,
            new_value: Some(r#""super-secret-password-123""#.to_string()),
            redaction_applied: false,
            previous_hash: [0u8; 32],
            entry_hmac: [0u8; 32],
        },
        AuditRecord {
            tx_id,
            sequence: 1,
            yang_path: "/test:config/normal".to_string(),
            op_type: AuditOpType::Update,
            previous_value: Some(r#""old-value""#.to_string()),
            new_value: Some(r#""new-value""#.to_string()),
            redaction_applied: false,
            previous_hash: [0u8; 32],
            entry_hmac: [0u8; 32],
        },
        AuditRecord {
            tx_id,
            sequence: 2,
            yang_path: "/test:config/ip-address".to_string(),
            op_type: AuditOpType::Update,
            previous_value: Some(r#""192.168.1.1""#.to_string()),
            new_value: Some(r#""10.0.0.1""#.to_string()),
            redaction_applied: false,
            previous_hash: [0u8; 32],
            entry_hmac: [0u8; 32],
        },
        AuditRecord {
            tx_id,
            sequence: 3,
            yang_path: "/test:config/some-identifier".to_string(),
            op_type: AuditOpType::Update,
            previous_value: Some(r#""208950000000001""#.to_string()),
            new_value: Some(r#""208950000000002""#.to_string()),
            redaction_applied: false,
            previous_hash: [0u8; 32],
            entry_hmac: [0u8; 32],
        },
    ];

    let record = make_commit_record(tx_id, 1);
    backend
        .append_commit(record, audit)
        .await
        .expect("append should succeed");

    let loaded = backend
        .load_latest()
        .await
        .expect("load_latest should succeed")
        .expect("should have config");

    assert_eq!(loaded.audit.len(), 4);

    assert_eq!(
        loaded.audit[0].new_value,
        Some("\"<redacted>\"".to_string())
    );
    assert!(loaded.audit[0].redaction_applied);

    assert_eq!(
        loaded.audit[1].previous_value,
        Some("\"old-value\"".to_string())
    );
    assert_eq!(loaded.audit[1].new_value, Some("\"new-value\"".to_string()));
    assert!(!loaded.audit[1].redaction_applied);

    assert_eq!(
        loaded.audit[2].previous_value,
        Some("\"<redacted>\"".to_string())
    );
    assert_eq!(
        loaded.audit[2].new_value,
        Some("\"<redacted>\"".to_string())
    );
    assert!(loaded.audit[2].redaction_applied);

    assert_eq!(
        loaded.audit[3].previous_value,
        Some("\"<redacted>\"".to_string())
    );
    assert_eq!(
        loaded.audit[3].new_value,
        Some("\"<redacted>\"".to_string())
    );
    assert!(loaded.audit[3].redaction_applied);

    let conn = rusqlite::Connection::open(&db_path).expect("open direct conn");
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM audit_trail WHERE previous_value LIKE '%20895%' OR new_value LIKE '%20895%' OR new_value LIKE '%secret%' OR new_value LIKE '%10.0.0.1%'",
            [],
            |row| row.get(0),
        )
        .expect("query database directly");
    assert_eq!(
        count, 0,
        "No raw sensitive identifiers or secrets should exist in audit_trail table"
    );

    backend
        .verify_audit_chain(&loaded)
        .expect("audit chain verification should pass");

    conn.execute(
        "UPDATE audit_trail SET new_value = '\"tampered\"' WHERE sequence = 0",
        [],
    )
    .expect("tamper with database");

    let err = backend
        .load_latest()
        .await
        .expect_err("tampering should break load-time audit-chain verification");
    assert!(
        matches!(err.kind(), PersistErrorKind::AuditChainBroken),
        "expected AuditChainBroken after audit row tampering, got: {err:?}"
    );
}
