//! Retained portable notification prefixes remain exact authenticated windows.

use super::*;

const WINDOW: usize = 65_536;

fn retained_fixture(head: u64) -> SqliteSessionBackend {
    let backend = sealed_audit_fixture(head - WINDOW as u64 + 1, WINDOW, 0);
    backend
        .conn
        .blocking_lock()
        .execute(
            "UPDATE consensus_operator_recovery SET watch_cursor_invalidation_floor = 0",
            [],
        )
        .unwrap();
    {
        let conn = backend.conn.blocking_lock();
        let tx = conn.unchecked_transaction().unwrap();
        let retention = crate::consensus::native::retention::Retention {
            watch_retired_through: head - WINDOW as u64,
            ..Default::default()
        };
        native_retention::write(&tx, retention).unwrap();
        tx.commit().unwrap();
    }
    backend
}

#[test]
fn retained_snapshot_notification_boundary_keeps_operator_floor_separate() {
    for head in [65_536, 65_537, 65_538] {
        let backend = retained_fixture(head);
        let conn = backend.conn.blocking_lock();
        validate_sealed_state_sync(&conn)
            .expect("the exact committed retained window must validate");
        assert_eq!(read_watch_cursor_invalidation_floor_sync(&conn).unwrap(), 0);
        let count: usize = conn
            .query_row("SELECT count(*) FROM session_replication_log", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, WINDOW);
    }
}

#[test]
fn retained_snapshot_notification_pre_format_full_history_is_refused() {
    let backend = sealed_audit_fixture(1, WINDOW + 1, 0);
    let conn = backend.conn.blocking_lock();
    // These bytes were emitted and validated by the previous journal encoder.
    let old = r#"{"sequence":1,"tx_id":"old-format-row","op":{"Batch":{"ops":[]}},"timestamp":"2026-07-12T00:00:01Z"}"#;
    let tx = conn.unchecked_transaction().unwrap();
    for sequence in 1..=WINDOW as u64 + 1 {
        let encoded = old
            .replace("\"sequence\":1", &format!("\"sequence\":{sequence}"))
            .replace("old-format-row", &format!("sealed-audit-{sequence}"));
        tx.execute("UPDATE session_replication_log SET entry_json=?1, timestamp='2026-07-12T00:00:01Z' WHERE sequence=?2", params![encoded, sequence]).unwrap();
    }
    tx.commit().unwrap();
    assert_eq!(
        validate_sealed_state_sync(&conn).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(read_watch_cursor_invalidation_floor_sync(&conn).unwrap(), 0);
}

#[test]
fn retained_snapshot_notification_rejects_unexpected_missing_prefix() {
    for head in [65_536, 65_537] {
        let backend = retained_fixture(head);
        let conn = backend.conn.blocking_lock();
        let first = head - WINDOW as u64 + 1;
        conn.execute(
            "DELETE FROM session_replication_log WHERE sequence = ?1",
            [first],
        )
        .unwrap();
        assert_eq!(
            validate_sealed_state_sync(&conn).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[test]
fn retained_snapshot_notification_rejects_interior_gap() {
    let backend = retained_fixture(65_537);
    let conn = backend.conn.blocking_lock();
    conn.execute(
        "DELETE FROM session_replication_log WHERE sequence = 32_768",
        [],
    )
    .unwrap();
    assert_eq!(
        validate_sealed_state_sync(&conn).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn retained_snapshot_notification_rejects_duplicate_positions() {
    let backend = retained_fixture(65_538);
    let conn = backend.conn.blocking_lock();
    conn.execute_batch(
        "ALTER TABLE session_replication_log RENAME TO original_log;
        CREATE TABLE session_replication_log AS SELECT * FROM original_log;
        INSERT INTO session_replication_log SELECT * FROM original_log WHERE sequence = 32768;",
    )
    .unwrap();
    assert_eq!(
        validate_sealed_state_sync(&conn).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn retained_snapshot_notification_rejects_altered_entry_sequence() {
    let backend = retained_fixture(65_537);
    let conn = backend.conn.blocking_lock();
    let row = sealed_audit_fixture_row(3);
    conn.execute(
        "UPDATE session_replication_log SET entry_json = ?1 WHERE sequence = 2",
        [row.encoded],
    )
    .unwrap();
    assert_eq!(
        validate_sealed_state_sync(&conn).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn retained_snapshot_notification_rejects_mismatched_head() {
    for head in [65_536, 65_538] {
        let backend = retained_fixture(65_537);
        let conn = backend.conn.blocking_lock();
        conn.execute("UPDATE consensus_machine SET watch_sequence = ?1", [head])
            .unwrap();
        assert_eq!(
            validate_sealed_state_sync(&conn).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}

#[test]
fn retained_snapshot_notification_operator_recovery_prefix_still_validates() {
    let backend = sealed_audit_fixture(7, 3, 0);
    let conn = backend.conn.blocking_lock();
    validate_sealed_state_sync(&conn).expect("the separate recovery prefix remains supported");
    assert_eq!(read_watch_cursor_invalidation_floor_sync(&conn).unwrap(), 6);
}

#[test]
fn retained_snapshot_notification_rejects_partial_legacy_prefix() {
    let backend = sealed_audit_fixture(1, WINDOW + 2, 0);
    let conn = backend.conn.blocking_lock();
    conn.execute("DELETE FROM session_replication_log WHERE sequence = 1", [])
        .unwrap();
    assert_eq!(
        validate_sealed_state_sync(&conn).unwrap_err().kind(),
        io::ErrorKind::InvalidData,
        "accept neither an arbitrary first surviving row nor a partially retired legacy prefix"
    );
}

#[test]
fn retained_snapshot_notification_rejects_stale_committed_metadata() {
    let backend = sealed_audit_fixture(1, WINDOW + 1, 0);
    let conn = backend.conn.blocking_lock();
    let tx = conn.unchecked_transaction().unwrap();
    native_retention::write(
        &tx,
        crate::consensus::native::retention::Retention::default(),
    )
    .unwrap();
    tx.commit().unwrap();
    assert_eq!(
        validate_sealed_state_sync(&conn).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn retained_snapshot_notification_rejects_malformed_committed_metadata() {
    let backend = retained_fixture(65_537);
    let conn = backend.conn.blocking_lock();
    conn.execute(
        "UPDATE consensus_native_retention SET frontiers=?1",
        [b"{".as_slice()],
    )
    .unwrap();
    assert_eq!(
        validate_sealed_state_sync(&conn).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn retained_snapshot_notification_requires_native_namespace_for_suffix() {
    let backend = retained_fixture(65_537);
    let conn = backend.conn.blocking_lock();
    conn.execute_batch("DROP TABLE consensus_native_retention")
        .unwrap();
    assert_eq!(
        validate_sealed_state_sync(&conn).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn retained_snapshot_notification_truncated_tail_reaches_head_guard() {
    let backend = retained_fixture(65_537);
    let conn = backend.conn.blocking_lock();
    conn.execute(
        "DELETE FROM session_replication_log WHERE sequence=65537",
        [],
    )
    .unwrap();
    assert_eq!(
        validate_sealed_state_sync(&conn).unwrap_err().to_string(),
        "session replication cursor does not match the persisted log"
    );
}
