use bytes::Bytes;
use opc_session_store::sqlite::audit::{
    audit_sqlite_identity_invariants, SqliteIdentityAuditIncompleteReason,
    SqliteIdentityAuditLimits, SqliteIdentityAuditStatus, SQLITE_IDENTITY_AUDIT_REPORT_VERSION,
};
use opc_session_store::{
    FenceToken, OwnerId, ReplicationEntry, ReplicationOp, SessionKey, SessionKeyType,
    SqliteSessionBackend, OWNER_ID_MAX_BYTES, REPLICATION_TX_ID_MAX_BYTES,
    SESSION_KEY_TYPE_MAX_BYTES, STABLE_ID_MAX_BYTES,
};
use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
use rusqlite::{params, Connection};
use tempfile::TempDir;

fn database() -> (TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("sessions.db");
    drop(SqliteSessionBackend::open(&path).expect("create schema"));
    (dir, path)
}

fn limits(max_rows: u64, max_entry: u64, max_total: u64) -> SqliteIdentityAuditLimits {
    SqliteIdentityAuditLimits::try_new(max_rows, max_entry, max_total).expect("valid limits")
}

fn insert_session_record(conn: &Connection, rowid: i64, owner: &str, key_type: &str) {
    conn.execute(
        r#"
        INSERT INTO session_records (
            rowid, tenant, nf_kind, key_type, stable_id, generation, owner,
            fence, state_class, state_type, expires_at, payload, encoding
        ) VALUES (?1, 'tenant-a', 'smf', ?2, ?3, 1, ?4, 1,
                  'authoritative-session', 'test-state', NULL, X'', 0)
        "#,
        params![
            rowid,
            key_type,
            format!("stable-{rowid}").into_bytes(),
            owner
        ],
    )
    .expect("insert session row");
}

fn insert_lease(conn: &Connection, rowid: i64, owner: &str, key_type: &str) {
    conn.execute(
        r#"
        INSERT INTO leases (
            rowid, tenant, nf_kind, key_type, stable_id, active,
            credential_id, owner, fence, expires_at_unix_ms, guard_expires_at
        ) VALUES (?1, 'tenant-a', 'smf', ?2, ?3, 1, 1, ?4, 1, 1,
                  '2030-01-01T00:00:00Z')
        "#,
        params![
            rowid,
            key_type,
            format!("lease-{rowid}").into_bytes(),
            owner
        ],
    )
    .expect("insert lease row");
}

fn insert_fence(conn: &Connection, rowid: i64, key_type: &str) {
    conn.execute(
        r#"
        INSERT INTO key_fences (rowid, tenant, nf_kind, key_type, stable_id, fence)
        VALUES (?1, 'tenant-a', 'smf', ?2, ?3, 1)
        "#,
        params![rowid, key_type, format!("fence-{rowid}").into_bytes()],
    )
    .expect("insert fence row");
}

fn replication_entry(sequence: u64, owner: &str) -> ReplicationEntry {
    let key = SessionKey {
        tenant: TenantId::new("tenant-a").expect("tenant"),
        nf_kind: NetworkFunctionKind::new("smf").expect("nf kind"),
        key_type: SessionKeyType::other("audit-custom-key").expect("custom key"),
        stable_id: Bytes::from(format!("session-{sequence}"))
            .try_into()
            .expect("valid stable ID"),
    };
    ReplicationEntry {
        sequence,
        tx_id: format!("tx-{sequence}")
            .try_into()
            .expect("valid transaction ID"),
        op: ReplicationOp::DeleteFenced {
            key,
            owner: OwnerId::new(owner).expect("owner"),
            fence: FenceToken::new(1),
        },
        timestamp: Timestamp::now_utc(),
    }
}

fn insert_replication_json(conn: &Connection, sequence: i64, json: &str) {
    conn.execute(
        r#"
        INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp)
        VALUES (?1, ?2, ?3, '2030-01-01T00:00:00Z')
        "#,
        params![sequence, format!("tx-{sequence}"), json],
    )
    .expect("insert replication row");
}

fn replace_first_field(value: &mut serde_json::Value, field: &str, replacement: &str) -> bool {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(found) = object.get_mut(field) {
                *found = serde_json::Value::String(replacement.to_string());
                return true;
            }
            object
                .values_mut()
                .any(|value| replace_first_field(value, field, replacement))
        }
        serde_json::Value::Array(values) => values
            .iter_mut()
            .any(|value| replace_first_field(value, field, replacement)),
        _ => false,
    }
}

#[test]
fn valid_empty_snapshot_is_compliant_and_count_only() {
    let (_dir, path) = database();
    let report =
        audit_sqlite_identity_invariants(&path, limits(1, 1024, 1024)).expect("audit succeeds");

    assert_eq!(report.status(), SqliteIdentityAuditStatus::Compliant);
    assert_eq!(report.scanned().session_records(), 0);
    assert_eq!(report.scanned().leases(), 0);
    assert_eq!(report.scanned().key_fences(), 0);
    assert_eq!(report.scanned().replication_entries(), 0);
    assert_eq!(report.incomplete_reason(), None);

    let encoded = serde_json::to_string(&report).expect("serialize report");
    assert!(!encoded.contains(path.to_string_lossy().as_ref()));
    assert!(!encoded.contains("database"));
}

#[test]
fn relational_identity_violations_are_counted_without_values() {
    let (_dir, path) = database();
    let oversized_owner = "owner-sensitive".repeat(20);
    let oversized_key_type = "key-sensitive".repeat(20);
    let conn = Connection::open(&path).expect("open fixture");
    insert_session_record(&conn, 1, "", "valid-custom");
    insert_lease(&conn, 2, &oversized_owner, "");
    insert_fence(&conn, 3, &oversized_key_type);
    drop(conn);

    let report =
        audit_sqlite_identity_invariants(&path, limits(10, 1024, 1024)).expect("audit succeeds");
    assert_eq!(report.status(), SqliteIdentityAuditStatus::ViolationsFound);
    assert_eq!(report.violations().invalid_owner_fields(), 2);
    assert_eq!(report.violations().invalid_session_key_type_fields(), 2);

    let rendered = serde_json::to_string(&report).expect("serialize report");
    for sensitive in ["owner-sensitive", "key-sensitive", "tenant-a", "stable-"] {
        assert!(!rendered.contains(sensitive), "leaked {sensitive}");
    }
}

#[test]
fn stable_id_audit_covers_exact_bounds_and_sqlite_types_without_values() {
    let (_dir, path) = database();
    let conn = Connection::open(&path).expect("open fixture");
    conn.execute_batch("PRAGMA ignore_check_constraints = ON")
        .expect("allow legacy-invalid audit fixtures");
    for (rowid, stable_id) in [
        (1_i64, vec![0x11_u8; 1]),
        (2_i64, vec![0x22_u8; STABLE_ID_MAX_BYTES]),
        (3_i64, Vec::new()),
    ] {
        conn.execute(
            r#"
            INSERT INTO session_records (
                rowid, tenant, nf_kind, key_type, stable_id, generation, owner,
                fence, state_class, state_type, expires_at, payload, encoding
            ) VALUES (?1, 'tenant-a', 'smf', 'pdu-session', ?2, 1, 'owner-a', 1,
                      'authoritative-session', 'test-state', NULL, X'', 0)
            "#,
            params![rowid, stable_id],
        )
        .expect("insert stable ID fixture");
    }
    conn.execute(
        r#"
        INSERT INTO leases (
            rowid, tenant, nf_kind, key_type, stable_id, active,
            credential_id, owner, fence, expires_at_unix_ms, guard_expires_at
        ) VALUES (4, 'tenant-a', 'smf', 'pdu-session', ?1, 1, 1,
                  'owner-a', 1, 1, '2030-01-01T00:00:00Z')
        "#,
        params![vec![0x33_u8; STABLE_ID_MAX_BYTES + 1]],
    )
    .expect("insert oversized lease stable ID");
    let sensitive = "raw-subscriber-id-must-not-leak";
    conn.execute(
        r#"
        INSERT INTO key_fences (
            rowid, tenant, nf_kind, key_type, stable_id, fence
        ) VALUES (5, 'tenant-a', 'smf', 'pdu-session', ?1, 1)
        "#,
        params![sensitive],
    )
    .expect("insert wrong-type fence stable ID");
    drop(conn);

    let report =
        audit_sqlite_identity_invariants(&path, limits(10, 1024, 1024)).expect("audit succeeds");
    assert_eq!(report.status(), SqliteIdentityAuditStatus::ViolationsFound);
    assert_eq!(report.violations().invalid_stable_id_fields(), 3);
    assert_eq!(report.scanned().session_records(), 3);
    assert_eq!(report.scanned().leases(), 1);
    assert_eq!(report.scanned().key_fences(), 1);
    assert!(!serde_json::to_string(&report)
        .expect("report JSON")
        .contains(sensitive));
}

#[test]
fn exact_utf8_byte_limits_pass_and_one_over_fails() {
    let (_dir, path) = database();
    let exact_owner = "é".repeat(OWNER_ID_MAX_BYTES / 2);
    let exact_key_type = "é".repeat(SESSION_KEY_TYPE_MAX_BYTES / 2);
    let conn = Connection::open(&path).expect("open fixture");
    insert_session_record(&conn, 1, &exact_owner, &exact_key_type);
    insert_lease(
        &conn,
        2,
        &format!("{exact_owner}x"),
        &format!("{exact_key_type}x"),
    );
    drop(conn);

    let report =
        audit_sqlite_identity_invariants(&path, limits(10, 1024, 1024)).expect("audit succeeds");
    assert_eq!(report.status(), SqliteIdentityAuditStatus::ViolationsFound);
    assert_eq!(report.violations().invalid_owner_fields(), 1);
    assert_eq!(report.violations().invalid_session_key_type_fields(), 1);
}

#[test]
fn strict_replication_decode_reuses_nested_identity_validation() {
    let (_dir, path) = database();
    let conn = Connection::open(&path).expect("open fixture");
    let valid = serde_json::to_string(&replication_entry(1, "owner-a")).expect("valid JSON");
    insert_replication_json(&conn, 1, &valid);

    let mut invalid: serde_json::Value =
        serde_json::to_value(replication_entry(2, "owner-b")).expect("entry value");
    let sensitive = "nested-sensitive-owner".repeat(10);
    assert!(replace_first_field(&mut invalid, "owner", &sensitive));
    let invalid = serde_json::to_string(&invalid).expect("invalid JSON fixture");
    insert_replication_json(&conn, 2, &invalid);
    drop(conn);

    let total = u64::try_from(valid.len() + invalid.len()).expect("fixture length");
    let report =
        audit_sqlite_identity_invariants(&path, limits(10, total, total)).expect("audit succeeds");
    assert_eq!(report.status(), SqliteIdentityAuditStatus::ViolationsFound);
    assert_eq!(report.scanned().replication_entries(), 2);
    assert_eq!(report.violations().invalid_replication_entries(), 1);
    assert!(!serde_json::to_string(&report)
        .expect("report JSON")
        .contains("nested-sensitive-owner"));
}

#[test]
fn replication_transaction_id_audit_is_exact_bounded_and_cross_checks_json() {
    let (_dir, path) = database();
    let conn = Connection::open(&path).expect("open fixture");
    conn.execute_batch("PRAGMA ignore_check_constraints = ON")
        .expect("allow legacy-invalid audit fixtures");

    let fixtures = [
        (rusqlite::types::Value::Text("x".into()), "x".to_string()),
        (
            rusqlite::types::Value::Text("m".repeat(REPLICATION_TX_ID_MAX_BYTES)),
            "m".repeat(REPLICATION_TX_ID_MAX_BYTES),
        ),
        (
            rusqlite::types::Value::Text(String::new()),
            "encoded-3".into(),
        ),
        (
            rusqlite::types::Value::Text("o".repeat(REPLICATION_TX_ID_MAX_BYTES + 1)),
            "encoded-4".into(),
        ),
        (rusqlite::types::Value::Blob(vec![b'b']), "encoded-5".into()),
        (
            rusqlite::types::Value::Text("Case-Sensitive".into()),
            "case-sensitive".into(),
        ),
        (
            rusqlite::types::Value::Text("encoded-7".into()),
            String::new(),
        ),
        (
            rusqlite::types::Value::Text("encoded-8".into()),
            "j".repeat(REPLICATION_TX_ID_MAX_BYTES + 1),
        ),
    ];
    let mut total_json_bytes = 0_u64;
    for (offset, (stored_tx_id, encoded_tx_id)) in fixtures.into_iter().enumerate() {
        let sequence = u64::try_from(offset + 1).expect("fixture sequence");
        let mut entry =
            serde_json::to_value(replication_entry(sequence, "owner-a")).expect("entry JSON value");
        entry["tx_id"] = serde_json::Value::String(encoded_tx_id);
        let encoded = serde_json::to_string(&entry).expect("entry JSON");
        total_json_bytes += u64::try_from(encoded.len()).expect("entry width");
        conn.execute(
            r#"
            INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp)
            VALUES (?1, ?2, ?3, '2030-01-01T00:00:00Z')
            "#,
            params![sequence, stored_tx_id, encoded],
        )
        .expect("insert transaction-ID fixture");
    }
    drop(conn);

    let report =
        audit_sqlite_identity_invariants(&path, limits(10, total_json_bytes, total_json_bytes))
            .expect("audit succeeds");
    assert_eq!(
        report.report_version(),
        SQLITE_IDENTITY_AUDIT_REPORT_VERSION
    );
    assert_eq!(SQLITE_IDENTITY_AUDIT_REPORT_VERSION, 3);
    assert_eq!(report.status(), SqliteIdentityAuditStatus::ViolationsFound);
    assert_eq!(report.scanned().replication_entries(), 8);
    assert_eq!(report.violations().invalid_replication_tx_id_fields(), 6);
    assert_eq!(report.violations().invalid_replication_entries(), 2);
}

#[test]
fn replication_json_sequence_must_match_a_positive_stored_sequence() {
    let (_dir, path) = database();
    let conn = Connection::open(&path).expect("open fixture");
    conn.execute_batch("PRAGMA ignore_check_constraints = ON")
        .expect("disable fixture check constraints");
    let first = serde_json::to_string(&replication_entry(1, "owner-a")).expect("entry JSON");
    let second = serde_json::to_string(&replication_entry(3, "owner-b")).expect("entry JSON");
    insert_replication_json(&conn, -1, &first);
    insert_replication_json(&conn, 2, &second);
    drop(conn);

    let total = u64::try_from(first.len() + second.len()).expect("fixture length");
    let report =
        audit_sqlite_identity_invariants(&path, limits(10, total, total)).expect("audit succeeds");
    assert_eq!(report.status(), SqliteIdentityAuditStatus::ViolationsFound);
    assert_eq!(report.scanned().replication_entries(), 2);
    assert_eq!(report.violations().invalid_replication_entries(), 2);
}

#[test]
fn row_budget_is_exact_and_never_returns_a_partial_pass() {
    let (_dir, path) = database();
    let conn = Connection::open(&path).expect("open fixture");
    insert_fence(&conn, i64::MIN, "custom-a");
    insert_fence(&conn, 9, "custom-b");
    drop(conn);

    let incomplete =
        audit_sqlite_identity_invariants(&path, limits(1, 1024, 1024)).expect("audit succeeds");
    assert_eq!(incomplete.status(), SqliteIdentityAuditStatus::Incomplete);
    assert_eq!(
        incomplete.incomplete_reason(),
        Some(SqliteIdentityAuditIncompleteReason::RowBudgetExceeded)
    );
    assert_eq!(incomplete.scanned().key_fences(), 1);

    let complete =
        audit_sqlite_identity_invariants(&path, limits(2, 1024, 1024)).expect("audit succeeds");
    assert_eq!(complete.status(), SqliteIdentityAuditStatus::Compliant);
    assert_eq!(complete.scanned().key_fences(), 2);
}

#[test]
fn keyset_paging_crosses_the_fixed_page_boundary() {
    let (_dir, path) = database();
    let conn = Connection::open(&path).expect("open fixture");
    conn.execute(
        r#"
        WITH RECURSIVE counter(value) AS (
            SELECT 1
            UNION ALL
            SELECT value + 1 FROM counter WHERE value < 257
        )
        INSERT INTO key_fences (tenant, nf_kind, key_type, stable_id, fence)
        SELECT 'tenant-a', 'smf', 'custom-key', CAST(value AS BLOB), 1
        FROM counter
        "#,
        [],
    )
    .expect("insert paged fixture");
    drop(conn);

    let report =
        audit_sqlite_identity_invariants(&path, limits(257, 1024, 1024)).expect("audit succeeds");
    assert_eq!(report.status(), SqliteIdentityAuditStatus::Compliant);
    assert_eq!(report.scanned().key_fences(), 257);
}

#[test]
fn replication_json_budgets_fail_incomplete_before_claiming_validity() {
    let (_dir, path) = database();
    let conn = Connection::open(&path).expect("open fixture");
    let first = serde_json::to_string(&replication_entry(1, "owner-a")).expect("entry JSON");
    let second = serde_json::to_string(&replication_entry(2, "owner-b")).expect("entry JSON");
    insert_replication_json(&conn, 1, &first);
    insert_replication_json(&conn, 2, &second);
    drop(conn);

    let max_entry = u64::try_from(first.len().max(second.len())).expect("entry size");
    let smaller_entry = max_entry - 1;
    let per_entry =
        audit_sqlite_identity_invariants(&path, limits(10, smaller_entry, max_entry * 2))
            .expect("audit succeeds");
    assert_eq!(per_entry.status(), SqliteIdentityAuditStatus::Incomplete);
    assert_eq!(
        per_entry.incomplete_reason(),
        Some(SqliteIdentityAuditIncompleteReason::EntryJsonBudgetExceeded)
    );

    let total = u64::try_from(first.len() + second.len()).expect("total size");
    let cumulative = audit_sqlite_identity_invariants(&path, limits(10, max_entry, total - 1))
        .expect("audit succeeds");
    assert_eq!(cumulative.status(), SqliteIdentityAuditStatus::Incomplete);
    assert_eq!(
        cumulative.incomplete_reason(),
        Some(SqliteIdentityAuditIncompleteReason::TotalJsonBudgetExceeded)
    );
    assert_eq!(cumulative.scanned().replication_entries(), 1);
}

#[test]
fn unsupported_schema_is_incomplete_and_database_remains_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("unsupported.db");
    let conn = Connection::open(&path).expect("create database");
    conn.execute("CREATE TABLE unrelated (value TEXT NOT NULL)", [])
        .expect("create unrelated table");
    conn.execute("INSERT INTO unrelated (value) VALUES ('sentinel')", [])
        .expect("insert sentinel");
    drop(conn);
    let before = std::fs::read(&path).expect("read fixture");

    let report = audit_sqlite_identity_invariants(&path, limits(10, 1024, 1024))
        .expect("audit returns report");
    assert_eq!(report.status(), SqliteIdentityAuditStatus::Incomplete);
    assert_eq!(
        report.incomplete_reason(),
        Some(SqliteIdentityAuditIncompleteReason::UnsupportedSchema)
    );
    let after = std::fs::read(&path).expect("read fixture after audit");
    assert_eq!(before, after, "read-only audit modified the database");
}

#[test]
fn lookalike_schema_without_unique_replication_sequence_is_not_certified() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("lookalike.db");
    let conn = Connection::open(&path).expect("create database");
    for statement in [
        "CREATE TABLE session_records (owner TEXT, key_type TEXT)",
        "CREATE TABLE leases (owner TEXT, key_type TEXT)",
        "CREATE TABLE key_fences (key_type TEXT)",
        "CREATE TABLE session_replication_log (sequence INTEGER, entry_json TEXT, discriminator TEXT, PRIMARY KEY (sequence, discriminator))",
    ] {
        conn.execute(statement, []).expect("create lookalike table");
    }
    drop(conn);

    let report = audit_sqlite_identity_invariants(&path, limits(10, 1024, 1024))
        .expect("audit returns report");
    assert_eq!(report.status(), SqliteIdentityAuditStatus::Incomplete);
    assert_eq!(
        report.incomplete_reason(),
        Some(SqliteIdentityAuditIncompleteReason::UnsupportedSchema)
    );
}

#[test]
fn case_insensitive_rowid_shadow_is_not_certified() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rowid-shadow.db");
    let conn = Connection::open(&path).expect("create database");
    for statement in [
        "CREATE TABLE session_records (ROWID INTEGER, owner TEXT, key_type TEXT)",
        "CREATE TABLE leases (owner TEXT, key_type TEXT)",
        "CREATE TABLE key_fences (key_type TEXT)",
        "CREATE TABLE session_replication_log (sequence INTEGER PRIMARY KEY, entry_json TEXT)",
    ] {
        conn.execute(statement, []).expect("create lookalike table");
    }
    drop(conn);

    let report = audit_sqlite_identity_invariants(&path, limits(10, 1024, 1024))
        .expect("audit returns report");
    assert_eq!(report.status(), SqliteIdentityAuditStatus::Incomplete);
    assert_eq!(
        report.incomplete_reason(),
        Some(SqliteIdentityAuditIncompleteReason::UnsupportedSchema)
    );
}

#[test]
fn malformed_replication_json_is_a_count_only_violation() {
    let (_dir, path) = database();
    let conn = Connection::open(&path).expect("open fixture");
    let sensitive = r#"{"owner":"raw-owner-must-not-leak""#;
    insert_replication_json(&conn, 1, sensitive);
    drop(conn);

    let report =
        audit_sqlite_identity_invariants(&path, limits(10, 1024, 1024)).expect("audit succeeds");
    assert_eq!(report.status(), SqliteIdentityAuditStatus::ViolationsFound);
    assert_eq!(report.violations().invalid_replication_entries(), 1);
    let rendered = format!("{report:?} {}", serde_json::to_string(&report).unwrap());
    assert!(!rendered.contains("raw-owner-must-not-leak"));
}

#[test]
fn zero_or_inconsistent_limits_are_rejected() {
    assert!(SqliteIdentityAuditLimits::try_new(0, 1, 1).is_err());
    assert!(SqliteIdentityAuditLimits::try_new(1, 0, 1).is_err());
    assert!(SqliteIdentityAuditLimits::try_new(1, 2, 1).is_err());
    assert!(SqliteIdentityAuditLimits::try_new(1, i64::MAX as u64 + 1, u64::MAX).is_err());
}
