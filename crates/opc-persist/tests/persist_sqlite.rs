mod persist_common;

use opc_persist::{AuditKey, ConfigStore, MockConfigStore, PersistErrorKind, SqliteBackend};
use opc_types::TxId;

use persist_common::{make_commit_record, test_audit_key};

#[tokio::test]
async fn open_migrates_schema_version_1_0_0_to_alarm_audit_schema() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_schema_migration.db");

    {
        let conn = rusqlite::Connection::open(&db_path).expect("open legacy database");
        conn.execute_batch(
            r#"
            CREATE TABLE schema_version (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                schema_digest TEXT NOT NULL,
                sdk_version TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            INSERT INTO schema_version (id, schema_digest, sdk_version, created_at)
            VALUES (1, 'legacy-digest', '1.0.0', datetime('now'));
            "#,
        )
        .expect("seed legacy schema version");
    }

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open and migrate backend");
    backend
        .record_alarm_audit(
            "acknowledge",
            "authorized",
            "alarm-1",
            "link.down",
            "peer-unreachable",
            "admin-user",
            Some("tenant-a"),
            "maintenance",
            "alarm:alarm-1",
            Some("corr-1"),
            "2026-06-06T00:00:00Z",
        )
        .await
        .expect("write alarm audit after migration");

    let conn = rusqlite::Connection::open(&db_path).expect("open migrated database");
    let sdk_version: String = conn
        .query_row(
            "SELECT sdk_version FROM schema_version WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .expect("read migrated schema version");
    let schema_digest: String = conn
        .query_row(
            "SELECT schema_digest FROM schema_version WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .expect("read migrated schema digest");
    let alarm_audit_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM alarm_audit", [], |row| row.get(0))
        .expect("query migrated alarm audit table");

    assert_eq!(sdk_version, "1.8.0");
    assert_ne!(schema_digest, "legacy-digest");
    assert_eq!(alarm_audit_count, 1);
}

#[tokio::test]
async fn open_migrates_schema_version_1_4_0_to_current_schema() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_schema_migration_1_4_0.db");

    {
        let conn = rusqlite::Connection::open(&db_path).expect("open legacy database");
        conn.execute_batch(
            r#"
            CREATE TABLE schema_version (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                schema_digest TEXT NOT NULL,
                sdk_version TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            INSERT INTO schema_version (id, schema_digest, sdk_version, created_at)
            VALUES (1, 'legacy-digest-1-4', '1.4.0', datetime('now'));
            "#,
        )
        .expect("seed legacy 1.4.0 schema version");
    }

    SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open and migrate 1.4.0 backend");

    let conn = rusqlite::Connection::open(&db_path).expect("open migrated database");
    let sdk_version: String = conn
        .query_row(
            "SELECT sdk_version FROM schema_version WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .expect("read migrated schema version");
    let schema_digest: String = conn
        .query_row(
            "SELECT schema_digest FROM schema_version WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .expect("read migrated schema digest");

    assert_eq!(sdk_version, "1.8.0");
    assert_ne!(schema_digest, "legacy-digest-1-4");
}

#[tokio::test]
async fn open_migrates_legacy_audit_hmacs_to_count_bound_anchor() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("legacy_audit_hmacs.db");
    let audit_key = test_audit_key();
    let tx_id = TxId::new();
    let record = make_commit_record(tx_id, 1);
    let mut audit = vec![
        persist_common::make_audit_record(tx_id, 0, "/legacy/a"),
        persist_common::make_audit_record(tx_id, 1, "/legacy/b"),
    ];

    let mut prev_hash = [0u8; 32];
    for entry in &mut audit {
        entry.previous_hash = prev_hash;
        entry.entry_hmac = entry.calculate_hmac(&audit_key, "test");
        prev_hash = entry.entry_hmac;
    }
    let legacy_first_hmac = audit[0].entry_hmac;

    {
        let conn = rusqlite::Connection::open(&db_path).expect("open legacy database");
        conn.execute_batch(
            r#"
            CREATE TABLE schema_version (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                schema_digest TEXT NOT NULL,
                sdk_version TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            INSERT INTO schema_version (id, schema_digest, sdk_version, created_at)
            VALUES (1, 'legacy-digest', '1.5.0', datetime('now'));

            CREATE TABLE config_history (
                tx_id BLOB PRIMARY KEY,
                parent_tx_id BLOB NULL,
                version INTEGER NOT NULL UNIQUE,
                committed_at TEXT NOT NULL,
                principal TEXT NOT NULL,
                source TEXT NOT NULL,
                schema_digest BLOB NOT NULL,
                plaintext_digest BLOB NOT NULL,
                encrypted_blob BLOB NOT NULL,
                rollback_point INTEGER NOT NULL DEFAULT 0,
                rollback_label TEXT NULL,
                confirmed_deadline TEXT NULL,
                confirmed_at TEXT NULL
            );

            CREATE TABLE audit_trail (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_id BLOB NOT NULL,
                sequence INTEGER NOT NULL,
                yang_path TEXT NOT NULL,
                op_type TEXT NOT NULL,
                previous_value TEXT NULL,
                new_value TEXT NULL,
                redaction_applied INTEGER NOT NULL DEFAULT 0,
                previous_hash BLOB NOT NULL,
                entry_hmac BLOB NOT NULL,
                UNIQUE(tx_id, sequence)
            );
            "#,
        )
        .expect("seed legacy schema");

        conn.execute(
            "INSERT INTO config_history (tx_id, parent_tx_id, version, committed_at, principal, source, schema_digest, plaintext_digest, encrypted_blob, rollback_point, rollback_label, confirmed_deadline, confirmed_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                tx_id.as_uuid().as_bytes(),
                Option::<&[u8]>::None,
                1_i64,
                record.committed_at.to_string(),
                record.principal,
                "local_operator",
                record.schema_digest.as_bytes(),
                record.plaintext_digest,
                record.encrypted_blob,
                0_i64,
                Option::<&str>::None,
                Option::<&str>::None,
                Option::<&str>::None,
            ],
        )
        .expect("insert legacy config");

        for entry in &audit {
            conn.execute(
                "INSERT INTO audit_trail (tx_id, sequence, yang_path, op_type, previous_value, new_value, redaction_applied, previous_hash, entry_hmac) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                rusqlite::params![
                    tx_id.as_uuid().as_bytes(),
                    i64::from(entry.sequence),
                    entry.yang_path.as_str(),
                    "CREATE",
                    entry.previous_value.as_deref(),
                    entry.new_value.as_deref(),
                    0_i64,
                    &entry.previous_hash[..],
                    &entry.entry_hmac[..],
                ],
            )
            .expect("insert legacy audit row");
        }
    }

    let backend = SqliteBackend::open_with_audit_key(&db_path, true, 0, audit_key.clone())
        .await
        .expect("open and reseal legacy audit rows");
    let loaded = backend
        .load_latest()
        .await
        .expect("load migrated config")
        .expect("config exists");

    assert_eq!(loaded.audit.len(), 2);
    assert_ne!(loaded.audit[0].entry_hmac, legacy_first_hmac);
    loaded
        .verify_audit_chain(&audit_key)
        .expect("migrated audit chain uses count-bound HMACs");

    let conn = rusqlite::Connection::open(&db_path).expect("open migrated database");
    let (audit_count, terminal_hash): (i64, Vec<u8>) = conn
        .query_row(
            "SELECT audit_count, audit_terminal_hash FROM config_history WHERE tx_id = ?1",
            rusqlite::params![tx_id.as_uuid().as_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read migrated audit anchor");
    assert_eq!(audit_count, 2);
    assert_eq!(terminal_hash, loaded.audit[1].entry_hmac.to_vec());
}

#[tokio::test]
async fn wal_pragma_verification_journal_mode_is_wal() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_wal.db");

    let _backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let conn = rusqlite::Connection::open(&db_path).expect("open direct connection");
    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("query journal_mode");

    assert_eq!(
        journal_mode.to_lowercase(),
        "wal",
        "journal_mode should be WAL, got: {journal_mode}"
    );

    let synchronous: i32 = conn
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .expect("query synchronous");
    assert!(
        synchronous > 0,
        "synchronous should not be OFF (0), got: {synchronous}"
    );

    let foreign_keys: i32 = conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .expect("query foreign_keys");
    assert_eq!(
        foreign_keys, 1,
        "foreign_keys should be ON (1), got: {foreign_keys}"
    );

    let busy_timeout: i32 = conn
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .expect("query busy_timeout");
    assert_eq!(
        busy_timeout, 5000,
        "busy_timeout should be 5000ms, got: {busy_timeout}"
    );
}

#[tokio::test]
async fn wal_pragma_verification_locking_mode_normal() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_locking.db");

    let _backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let conn = rusqlite::Connection::open(&db_path).expect("open direct connection");
    let locking_mode: String = conn
        .query_row("PRAGMA locking_mode", [], |row| row.get(0))
        .expect("query locking_mode");

    assert_eq!(
        locking_mode.to_lowercase(),
        "normal",
        "locking_mode should be NORMAL, got: {locking_mode}"
    );
}

#[tokio::test]
async fn preflight_rejected_when_store_returns_unsafe_capabilities() {
    use opc_persist::PersistCapabilities;

    let mock = MockConfigStore::new();

    let unsafe_caps = PersistCapabilities {
        ephemeral_mode: false,
        storage_path: "/mnt/nfs/test.db".to_string(),
        fsync_available: true,
        locking_compatible: false,
        same_filesystem: true,
        safe_filesystem: false,
        free_bytes: 1024 * 1024 * 1024,
        min_free_bytes: 100 * 1024 * 1024,
        directory_permissions_safe: true,
        wal_autocheckpoint_pages: 1000,
        journal_mode: "wal".to_string(),
        synchronous_setting: "extra".to_string(),
        foreign_keys_on: true,
        wal_mode: true,
    };
    mock.set_preflight_result(unsafe_caps);

    let caps = mock.preflight().await.expect("preflight should succeed");
    assert!(
        !caps.is_safe_for_writes(),
        "unsafe capabilities should fail is_safe_for_writes()"
    );
}

#[tokio::test]
async fn preflight_rejected_when_mock_injects_preflight_error() {
    use opc_persist::UnsafePathMock;

    let mock = UnsafePathMock::new("network filesystem /mnt/nfs is not supported");

    let err = mock
        .preflight()
        .await
        .expect_err("preflight should fail for unsafe path");
    assert!(format!("{err}").contains("not supported"));
}

#[tokio::test]
async fn mock_store_unsafe_path_preflight_error_prevents_usage() {
    use opc_persist::UnsafePathMock;

    let mock = UnsafePathMock::new("/mnt/ceph/vol is not a safe storage path");

    let err = mock
        .load_latest()
        .await
        .expect_err("load_latest should fail");
    assert!(format!("{err}").contains("not a safe storage path"));

    let err = mock
        .append_commit(make_commit_record(TxId::new(), 1), vec![])
        .await
        .expect_err("append_commit should fail");
    assert!(format!("{err}").contains("not a safe storage path"));
}

#[tokio::test]
async fn preflight_returns_capabilities() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_preflight.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    let caps = backend.preflight().await.expect("preflight should succeed");

    assert_eq!(caps.journal_mode, "wal");
    assert_eq!(caps.synchronous_setting, "extra");
    assert!(caps.foreign_keys_on);
    assert!(caps.wal_mode);
    assert!(caps.is_safe_for_writes());
}

#[tokio::test]
async fn preflight_ephemeral_file_mode_reports_unchecked_durability_caps() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_ephemeral.db");

    let backend = SqliteBackend::open(&db_path, true, u64::MAX)
        .await
        .expect("open in ephemeral mode");

    let caps = backend.preflight().await.expect("preflight should succeed");

    assert!(caps.ephemeral_mode);
    assert!(!caps.fsync_available);
    assert!(!caps.locking_compatible);
    assert!(!caps.same_filesystem);
    assert!(!caps.safe_filesystem);
    assert!(!caps.directory_permissions_safe);
    assert_eq!(caps.free_bytes, 0);
    assert!(!caps.is_safe_for_writes());
}

#[tokio::test]
async fn in_memory_open_reports_memory_journal_mode() {
    let backend = SqliteBackend::open(":memory:", true, 0)
        .await
        .expect("open in-memory backend");

    let caps = backend.preflight().await.expect("preflight should succeed");

    assert!(
        caps.ephemeral_mode,
        "in-memory preflight must report ephemeral_mode=true"
    );
    assert_eq!(
        caps.journal_mode, "memory",
        "journal_mode must be 'memory' for in-memory database, not 'wal'"
    );
    assert!(
        !caps.wal_mode,
        "wal_mode must be false for in-memory database"
    );
    assert_eq!(
        caps.wal_autocheckpoint_pages, 0,
        "wal_autocheckpoint_pages must be 0 for in-memory (WAL is not applicable)"
    );
    assert_eq!(
        caps.synchronous_setting, "extra",
        "synchronous_setting must be 'extra' for in-memory (pragma profile still applies)"
    );
}

#[tokio::test]
async fn in_memory_open_rejects_ephemeral_false() {
    let err = SqliteBackend::open(":memory:", false, 0)
        .await
        .expect_err(":memory: with ephemeral=false should be rejected");

    match err.kind() {
        PersistErrorKind::PreflightFailed(msg) => {
            assert!(
                msg.contains(":memory:"),
                "error message should mention :memory:, got: {msg}"
            );
        }
        other => panic!(
            "expected PreflightFailed for contradictory :memory: + ephemeral=false, got: {other:?}"
        ),
    }
}

#[tokio::test]
async fn in_memory_open_succeeds_in_ephemeral_mode() {
    let backend = SqliteBackend::open(":memory:", true, 0)
        .await
        .expect("open in-memory backend");

    let tx_id = TxId::new();
    backend
        .append_commit(make_commit_record(tx_id, 1), vec![])
        .await
        .expect("append in-memory commit");

    let loaded = backend
        .load_latest()
        .await
        .expect("load_latest should succeed")
        .expect("in-memory backend should contain the commit");

    assert_eq!(loaded.record.tx_id, tx_id);
    assert!(
        backend
            .preflight()
            .await
            .expect("preflight should succeed")
            .ephemeral_mode
    );
}

#[tokio::test]
async fn durable_open_requires_explicit_audit_key() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("durable-requires-audit-key.db");

    let err = SqliteBackend::open(&db_path, false, 0)
        .await
        .expect_err("durable open without audit key should fail closed");

    match err.kind() {
        PersistErrorKind::PreflightFailed(msg) => {
            assert!(
                msg.contains("audit HMAC key"),
                "error should mention the missing audit key, got: {msg}"
            );
        }
        other => panic!("expected PreflightFailed for missing audit key, got: {other:?}"),
    }
}

#[test]
fn audit_key_rejects_all_zero_material() {
    let err = AuditKey::new([0u8; 32]).expect_err("zero audit keys must be rejected");
    assert!(
        matches!(err.kind(), PersistErrorKind::PreflightFailed(_)),
        "expected PreflightFailed for zero audit key, got: {err:?}"
    );
}

#[tokio::test]
async fn ephemeral_backends_use_distinct_audit_hmac_keys() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path_a = temp_dir.path().join("ephemeral_a.db");
    let db_path_b = temp_dir.path().join("ephemeral_b.db");

    let backend_a = SqliteBackend::open(&db_path_a, true, 0)
        .await
        .expect("open first ephemeral backend");
    let backend_b = SqliteBackend::open(&db_path_b, true, 0)
        .await
        .expect("open second ephemeral backend");

    assert_ne!(
        backend_a.audit_key().as_bytes(),
        backend_b.audit_key().as_bytes(),
        "ephemeral audit HMAC keys must not be a shared compile-time constant"
    );
}

#[tokio::test]
async fn durable_open_succeeds_when_database_directory_contains_single_quote() {
    let temp_dir = tempfile::Builder::new()
        .prefix("it's-safe-")
        .tempdir()
        .expect("create temp dir with single quote");
    let db_path = temp_dir.path().join("quoted-path.db");

    let backend = SqliteBackend::open_with_audit_key(&db_path, false, 0, test_audit_key())
        .await
        .expect("durable open should succeed for paths containing a single quote");

    let caps = backend.preflight().await.expect("preflight should succeed");
    assert!(
        caps.fsync_available,
        "fsync probe should succeed for quoted path"
    );
    assert!(
        caps.is_safe_for_writes(),
        "quoted path should remain safe for writes"
    );
}

#[tokio::test]
async fn sqlite_backend_busy_timeout_is_capped_for_async_worker_profile() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("test_busy_timeout_cap.db");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");

    assert_eq!(SqliteBackend::MAX_CONCURRENT_DB_OPERATIONS, 1);

    let conn = backend.conn();
    let guard = conn.lock().await;
    let busy_timeout_ms: u32 = guard
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .expect("query backend busy_timeout");

    assert!(
        busy_timeout_ms <= 100,
        "busy_timeout must be capped to avoid pinning async workers, got {busy_timeout_ms}ms"
    );
}

#[tokio::test]
async fn load_latest_fails_closed_on_corrupt_timestamp() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("corrupt_ts.db");

    {
        let backend = SqliteBackend::open(&db_path, true, 0)
            .await
            .expect("open backend");
        let tx_id = TxId::new();
        backend
            .append_commit(make_commit_record(tx_id, 1), vec![])
            .await
            .expect("append valid commit");
    }

    let conn = rusqlite::Connection::open(&db_path).expect("open direct conn");
    conn.execute(
        "UPDATE config_history SET committed_at = 'not-a-timestamp' WHERE tx_id = (SELECT tx_id FROM config_history LIMIT 1)",
        [],
    )
    .expect("corrupt timestamp");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");
    let err = backend
        .load_latest()
        .await
        .expect_err("load_latest should fail on corrupt timestamp");
    assert!(
        matches!(err.kind(), PersistErrorKind::InconsistentState(_)),
        "expected InconsistentState for corrupt timestamp, got: {err:?}"
    );
}

#[tokio::test]
async fn load_latest_fails_closed_on_corrupt_commit_source() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("corrupt_src.db");

    {
        let backend = SqliteBackend::open(&db_path, true, 0)
            .await
            .expect("open backend");
        let tx_id = TxId::new();
        backend
            .append_commit(make_commit_record(tx_id, 1), vec![])
            .await
            .expect("append valid commit");
    }

    let conn = rusqlite::Connection::open(&db_path).expect("open direct conn");
    conn.execute(
        "UPDATE config_history SET source = 'not_a_real_source' WHERE tx_id = (SELECT tx_id FROM config_history LIMIT 1)",
        [],
    )
    .expect("corrupt source");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");
    let err = backend
        .load_latest()
        .await
        .expect_err("load_latest should fail on corrupt CommitSource");
    assert!(
        matches!(err.kind(), PersistErrorKind::InconsistentState(_)),
        "expected InconsistentState for corrupt source, got: {err:?}"
    );
}

#[tokio::test]
async fn load_latest_fails_closed_on_wrong_length_schema_digest() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("corrupt_digest.db");

    {
        let backend = SqliteBackend::open(&db_path, true, 0)
            .await
            .expect("open backend");
        let tx_id = TxId::new();
        backend
            .append_commit(make_commit_record(tx_id, 1), vec![])
            .await
            .expect("append valid commit");
    }

    let conn = rusqlite::Connection::open(&db_path).expect("open direct conn");
    let short_blob = vec![0u8; 16];
    conn.execute(
        "UPDATE config_history SET schema_digest = ?1 WHERE tx_id = (SELECT tx_id FROM config_history LIMIT 1)",
        rusqlite::params![short_blob],
    )
    .expect("corrupt schema_digest length");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");
    let err = backend
        .load_latest()
        .await
        .expect_err("load_latest should fail on wrong-length schema_digest");
    assert!(
        matches!(err.kind(), PersistErrorKind::CorruptBlob),
        "expected CorruptBlob for wrong-length schema_digest, got: {err:?}"
    );
}

#[tokio::test]
async fn load_latest_fails_closed_on_wrong_length_parent_tx_id() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("corrupt_parent_txid.db");

    {
        let backend = SqliteBackend::open(&db_path, true, 0)
            .await
            .expect("open backend");
        let tx1 = TxId::new();
        let tx2 = TxId::new();
        backend
            .append_commit(make_commit_record(tx1, 1), vec![])
            .await
            .expect("append genesis commit");

        let mut child = make_commit_record(tx2, 2);
        child.parent_tx_id = Some(tx1);
        backend
            .append_commit(child, vec![])
            .await
            .expect("append child commit");
    }

    let conn = rusqlite::Connection::open(&db_path).expect("open direct conn");
    conn.execute("PRAGMA foreign_keys = OFF", [])
        .expect("disable foreign_keys for corruption test");
    conn.execute(
        "UPDATE config_history SET parent_tx_id = ?1 WHERE version = 2",
        rusqlite::params![vec![0x01_u8, 0x02_u8]],
    )
    .expect("corrupt parent_tx_id length");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");
    let err = backend
        .load_latest()
        .await
        .expect_err("load_latest should fail on wrong-length parent_tx_id");
    assert!(
        matches!(err.kind(), PersistErrorKind::CorruptBlob),
        "expected CorruptBlob for wrong-length parent_tx_id, got: {err:?}"
    );
}

#[tokio::test]
async fn load_latest_fails_closed_on_negative_version() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("negative_version.db");

    {
        let backend = SqliteBackend::open(&db_path, true, 0)
            .await
            .expect("open backend");
        let tx_id = TxId::new();
        backend
            .append_commit(make_commit_record(tx_id, 1), vec![])
            .await
            .expect("append valid commit");
    }

    let conn = rusqlite::Connection::open(&db_path).expect("open direct conn");
    conn.execute(
        "UPDATE config_history SET version = -1 WHERE tx_id = (SELECT tx_id FROM config_history LIMIT 1)",
        [],
    )
    .expect("corrupt version");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");
    let err = backend
        .load_latest()
        .await
        .expect_err("load_latest should fail on negative version");
    assert!(
        matches!(err.kind(), PersistErrorKind::InconsistentState(_)),
        "expected InconsistentState for negative version, got: {err:?}"
    );
}

#[tokio::test]
async fn load_latest_fails_closed_on_corrupt_confirmed_deadline() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("corrupt_confirmed_deadline.db");

    {
        let backend = SqliteBackend::open(&db_path, true, 0)
            .await
            .expect("open backend");
        let tx_id = TxId::new();
        backend
            .append_commit(make_commit_record(tx_id, 1), vec![])
            .await
            .expect("append valid commit");
        backend
            .mark_confirmed(tx_id)
            .await
            .expect("mark commit confirmed");
    }

    let conn = rusqlite::Connection::open(&db_path).expect("open direct conn");
    conn.execute(
        "UPDATE config_history SET confirmed_deadline = 'garbage-deadline' WHERE tx_id = (SELECT tx_id FROM config_history LIMIT 1)",
        [],
    )
    .expect("corrupt confirmed_deadline");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");
    let err = backend
        .load_latest()
        .await
        .expect_err("load_latest should fail on corrupt confirmed_deadline");
    assert!(
        matches!(err.kind(), PersistErrorKind::InconsistentState(_)),
        "expected InconsistentState for corrupt confirmed_deadline, got: {err:?}"
    );
}

#[tokio::test]
async fn load_latest_fails_closed_on_corrupt_confirmed_at() {
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let db_path = temp_dir.path().join("corrupt_confirmed_at.db");

    {
        let backend = SqliteBackend::open(&db_path, true, 0)
            .await
            .expect("open backend");
        let tx_id = TxId::new();
        backend
            .append_commit(make_commit_record(tx_id, 1), vec![])
            .await
            .expect("append valid commit");
        backend
            .mark_confirmed(tx_id)
            .await
            .expect("mark commit confirmed");
    }

    let conn = rusqlite::Connection::open(&db_path).expect("open direct conn");
    conn.execute(
        "UPDATE config_history SET confirmed_at = 'garbage-confirmed-at' WHERE tx_id = (SELECT tx_id FROM config_history LIMIT 1)",
        [],
    )
    .expect("corrupt confirmed_at");

    let backend = SqliteBackend::open(&db_path, true, 0)
        .await
        .expect("open backend");
    let err = backend
        .load_latest()
        .await
        .expect_err("load_latest should fail on corrupt confirmed_at");
    assert!(
        matches!(err.kind(), PersistErrorKind::InconsistentState(_)),
        "expected InconsistentState for corrupt confirmed_at, got: {err:?}"
    );
}
