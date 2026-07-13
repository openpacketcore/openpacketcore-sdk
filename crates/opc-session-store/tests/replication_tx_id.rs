use opc_session_store::{
    ReplicationEntry, ReplicationOp, ReplicationTxId, SessionBackend, SqliteSessionBackend,
    StoreError, REPLICATION_TX_ID_CANONICAL_BYTES, REPLICATION_TX_ID_MAX_BYTES,
};
use opc_types::Timestamp;
use rusqlite::{params, Connection};

fn entry(sequence: u64, tx_id: &str) -> ReplicationEntry {
    ReplicationEntry {
        sequence,
        tx_id: ReplicationTxId::new(tx_id).expect("valid transaction ID"),
        op: ReplicationOp::Batch { ops: Vec::new() },
        timestamp: Timestamp::now_utc(),
    }
}

#[test]
fn direct_and_serde_boundaries_are_exact_redacted_and_utf8_byte_based() {
    assert!(ReplicationTxId::new("").is_err());
    assert_eq!(ReplicationTxId::new("x").expect("one byte").len(), 1);

    let maximum = "x".repeat(REPLICATION_TX_ID_MAX_BYTES);
    let maximum_id = ReplicationTxId::new(&maximum).expect("maximum ID");
    assert_eq!(maximum_id.as_str(), maximum);
    assert!(ReplicationTxId::new(&"x".repeat(REPLICATION_TX_ID_MAX_BYTES + 1)).is_err());

    let utf8_maximum = "é".repeat(REPLICATION_TX_ID_MAX_BYTES / 2);
    assert_eq!(utf8_maximum.len(), REPLICATION_TX_ID_MAX_BYTES);
    assert!(ReplicationTxId::new(&utf8_maximum).is_ok());
    assert!(ReplicationTxId::new(&format!("{utf8_maximum}x")).is_err());

    let encoded = serde_json::to_string(&maximum_id).expect("serialize maximum ID");
    assert_eq!(
        serde_json::from_str::<ReplicationTxId>(&encoded).expect("deserialize maximum ID"),
        maximum_id
    );
    for hostile in [String::new(), "z".repeat(REPLICATION_TX_ID_MAX_BYTES + 1)] {
        let encoded = serde_json::to_string(&hostile).expect("serialize hostile fixture");
        let error = serde_json::from_str::<ReplicationTxId>(&encoded)
            .expect_err("reject hostile transaction ID");
        if !hostile.is_empty() {
            assert!(!error.to_string().contains(&hostile));
        }
    }

    let sensitive = ReplicationTxId::new("sensitive-transaction-value").expect("valid ID");
    assert_eq!(format!("{sensitive:?}"), "ReplicationTxId([redacted])");
    assert!(!ReplicationTxId::new("Legacy-TX")
        .expect("legacy ID")
        .is_canonical());

    for _ in 0..1_000 {
        assert!(ReplicationTxId::new(&"h".repeat(REPLICATION_TX_ID_MAX_BYTES + 1)).is_err());
    }
}

#[test]
fn coordinator_mint_is_fixed_lowercase_hex_without_legacy_normalization() {
    let request_id = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let canonical = ReplicationTxId::from_request_bytes(request_id);
    assert_eq!(canonical.len(), REPLICATION_TX_ID_CANONICAL_BYTES);
    assert_eq!(canonical.as_str(), "000102030405060708090a0b0c0d0e0f");
    assert!(canonical.is_canonical());

    let lowercase = ReplicationTxId::new("abcdefabcdefabcdefabcdefabcdefab").expect("legacy ID");
    let uppercase = ReplicationTxId::new("ABCDEFABCDEFABCDEFABCDEFABCDEFAB").expect("legacy ID");
    assert_ne!(lowercase, uppercase);
    assert_eq!(uppercase.as_str(), "ABCDEFABCDEFABCDEFABCDEFABCDEFAB");
    assert!(!uppercase.is_canonical());
}

#[test]
fn new_sqlite_schema_enforces_text_and_exact_width_bounds() {
    let file = tempfile::NamedTempFile::new().expect("temporary database");
    drop(SqliteSessionBackend::open(file.path()).expect("initialize schema"));
    let conn = Connection::open(file.path()).expect("open database");

    for (sequence, tx_id) in [(1_i64, "x".to_string()), (2, "x".repeat(128))] {
        let encoded = serde_json::to_string(&entry(sequence as u64, &tx_id)).expect("entry JSON");
        conn.execute(
            "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) \
             VALUES (?1, ?2, ?3, '2030-01-01T00:00:00Z')",
            params![sequence, tx_id, encoded],
        )
        .expect("valid transaction ID persists");
    }

    for invalid in [String::new(), "x".repeat(REPLICATION_TX_ID_MAX_BYTES + 1)] {
        assert!(conn
            .execute(
                "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) \
                 VALUES (3, ?1, '{}', '2030-01-01T00:00:00Z')",
                params![invalid],
            )
            .is_err());
    }
    assert!(conn
        .execute(
            "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) \
             VALUES (3, ?1, '{}', '2030-01-01T00:00:00Z')",
            params![vec![b'x']],
        )
        .is_err());
    assert_eq!(
        conn.query_row("SELECT count(*) FROM session_replication_log", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect("count rows"),
        2
    );
}

#[tokio::test]
async fn replay_rebuild_restart_and_fork_identity_preserve_exact_legacy_bytes() {
    let file = tempfile::NamedTempFile::new().expect("temporary database");
    let original = entry(1, "Legacy-TX");
    let backend = SqliteSessionBackend::open(file.path()).expect("open backend");
    backend
        .replicate_entry(original.clone())
        .await
        .expect("first delivery");
    backend
        .replicate_entry(original.clone())
        .await
        .expect("same-ID redelivery is idempotent");

    let distinct = entry(1, "legacy-tx");
    assert_eq!(
        backend.replicate_entry(distinct).await,
        Err(StoreError::BackendUnavailable(
            "divergent replication entry sequence".into()
        ))
    );
    assert_eq!(
        backend
            .get_replication_log(1, 10)
            .await
            .expect("read exact entry"),
        vec![original.clone()]
    );
    drop(backend);

    let restarted = SqliteSessionBackend::open(file.path()).expect("restart backend");
    assert_eq!(
        restarted
            .get_replication_log(1, 10)
            .await
            .expect("read after restart"),
        vec![original.clone()]
    );
    drop(restarted);

    let rebuilt_file = tempfile::NamedTempFile::new().expect("rebuild database");
    let rebuilt = SqliteSessionBackend::open(rebuilt_file.path()).expect("open rebuild backend");
    rebuilt
        .rebuild_replication_state(vec![original.clone()])
        .await
        .expect("rebuild legacy identity");
    assert_eq!(
        rebuilt
            .get_replication_log(1, 10)
            .await
            .expect("read rebuilt entry"),
        vec![original]
    );
}

#[tokio::test]
async fn hostile_or_inconsistent_persisted_ids_fail_closed_without_rewrite() {
    for (stored_tx_id, expected_message) in [
        (
            "different".to_string(),
            "persisted replication transaction ID is inconsistent",
        ),
        (
            "H".repeat(1_048_576),
            "persisted replication transaction ID is invalid",
        ),
    ] {
        let file = tempfile::NamedTempFile::new().expect("temporary database");
        drop(SqliteSessionBackend::open(file.path()).expect("initialize schema"));
        let expected = entry(1, "expected");
        let encoded = serde_json::to_string(&expected).expect("entry JSON");
        let conn = Connection::open(file.path()).expect("open raw database");
        conn.execute_batch("PRAGMA ignore_check_constraints = ON")
            .expect("allow legacy-invalid fixture");
        conn.execute(
            "INSERT INTO session_replication_log (sequence, tx_id, entry_json, timestamp) \
             VALUES (1, ?1, ?2, '2030-01-01T00:00:00Z')",
            params![stored_tx_id, encoded],
        )
        .expect("insert hostile fixture");
        drop(conn);

        let backend = SqliteSessionBackend::open(file.path()).expect("open backend");
        for _ in 0..64 {
            assert_eq!(
                backend.get_replication_log(1, 1).await,
                Err(StoreError::Serialization(expected_message.into()))
            );
        }
        drop(backend);
        let conn = Connection::open(file.path()).expect("reopen raw database");
        assert_eq!(
            conn.query_row(
                "SELECT length(CAST(tx_id AS BLOB)) FROM session_replication_log",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("read retained width"),
            if expected_message.ends_with("invalid") {
                1_048_576
            } else {
                9
            }
        );
    }
}
