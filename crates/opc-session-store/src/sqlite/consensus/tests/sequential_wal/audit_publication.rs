use super::*;

#[test]
fn application_open_audit_covers_connection_token_writes() {
    let fixture = fixture();
    let source =
        SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
    let conn = source.conn.blocking_lock();
    application_seed_applied_one(&fixture, &conn, &source.caps);
    fixture.wal.shutdown().unwrap();
    conn.execute_batch(
        "CREATE TEMP TRIGGER change_log_after_connection_token \
         AFTER INSERT ON consensus_wal_application_connection BEGIN \
         UPDATE consensus_log SET entry_json = CAST('invalid' AS BLOB) \
         WHERE log_index = (SELECT MAX(log_index) FROM consensus_log); END;",
    )
    .unwrap();
    let before = super::super::super::wal::application::full_image_digest(&conn).unwrap();
    let result = open_snapshot_cache(&fixture, &source, &conn, IoControl::default());
    let error = match result {
        Ok(wal) => {
            wal.shutdown().unwrap();
            panic!("opening must audit its final connection-token effects")
        }
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "session consensus decoding failed");
    assert_eq!(
        super::super::super::wal::application::full_image_digest(&conn).unwrap(),
        before
    );
    assert_eq!(
        super::super::super::last_log_sync(&conn, identity()).unwrap(),
        Some(log_id(1))
    );
}

#[test]
fn application_open_discards_an_audit_after_a_later_transaction_write() {
    let fixture = fixture();
    let source =
        SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
    let conn = source.conn.blocking_lock();
    application_seed_applied_one(&fixture, &conn, &source.caps);
    fixture.wal.shutdown().unwrap();
    let before = super::super::super::wal::application::full_image_digest(&conn).unwrap();
    let opening = super::super::super::wal::snapshot::Opening::new(
        &fixture.path(),
        fixture.wal.binding(),
        Limits::default(),
        IoControl::default(),
    )
    .unwrap();
    let result = opening.finish(&conn, &source.caps, || {
        assert!(!conn.is_autocommit());
        assert_eq!(
            conn.execute(
                "UPDATE consensus_log SET entry_json = ?1 WHERE log_index = 1",
                params![encode_json(&blank(1)).unwrap()]
            )
            .unwrap(),
            1
        );
        Ok(())
    });
    let error = match result {
        Ok(wal) => {
            wal.shutdown().unwrap();
            panic!("a write after audit must prevent publication")
        }
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error.to_string(),
        "private WAL application cache changed outside its owner"
    );
    assert_eq!(
        super::super::super::wal::application::full_image_digest(&conn).unwrap(),
        before,
        "a write after the audit must be rejected before committing the opening transaction"
    );
    assert_eq!(
        super::super::super::last_log_sync(&conn, identity()).unwrap(),
        Some(log_id(1))
    );
}

fn application_seed_applied_one(fixture: &Fixture, conn: &Connection, caps: &BackendCapabilities) {
    fixture
        .wal
        .submit(append(&[batch(1)]))
        .unwrap()
        .wait()
        .unwrap();
    fixture
        .wal
        .submit(Operation::Committed(Some(log_id(1))))
        .unwrap()
        .wait()
        .unwrap();
    fixture
        .wal
        .apply_committed(conn, caps, vec![batch(1)], ApplyControl::Normal)
        .unwrap();
    assert_eq!(fixture.wal.with_application_read(conn, || 7).unwrap(), 7);
}

#[test]
fn application_restore_audit_covers_connection_token_writes() {
    let fixture = fixture();
    let source =
        SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
    let conn = source.conn.blocking_lock();
    application_seed_applied_one(&fixture, &conn, &source.caps);
    fixture.wal.shutdown().unwrap();
    conn.execute_batch(
        "CREATE TEMP TRIGGER application_change_log_after_connection_token \
         AFTER INSERT ON consensus_wal_application_connection BEGIN \
         UPDATE consensus_log SET entry_json = CAST('invalid' AS BLOB) \
         WHERE log_index = (SELECT MAX(log_index) FROM consensus_log); END;",
    )
    .unwrap();
    let before = super::super::super::wal::application::full_image_digest(&conn).unwrap();
    let reopened = fixture
        .reopen(Limits::default(), IoControl::default())
        .unwrap();
    let restored = reopened.restore_application(&conn, &source.caps);
    if let Err(error) = restored {
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "session consensus decoding failed");
        assert_eq!(
            super::super::super::wal::application::full_image_digest(&conn).unwrap(),
            before,
            "a rejected restore must roll back its post-audit SQL write"
        );
        let called = std::cell::Cell::new(false);
        assert!(reopened
            .with_application_read(&conn, || called.set(true))
            .is_err());
        assert!(!called.get());
        assert!(reopened.vote().is_err());
        assert!(reopened.shutdown().is_err());
        return;
    }
    let stored: Vec<u8> = conn
        .query_row(
            "SELECT entry_json FROM consensus_log WHERE log_index = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored, b"invalid");
    let original_error = super::super::super::last_log_sync(&conn, identity()).unwrap_err();
    assert_eq!(original_error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        original_error.to_string(),
        "session consensus decoding failed"
    );
    let called = std::cell::Cell::new(false);
    let observed = reopened.with_application_read(&conn, || {
        called.set(true);
        7
    });
    let error = observed.expect_err("a restore token write cannot authorize unaudited log bytes");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(!called.get());
    assert!(reopened.vote().is_err());
    assert!(reopened.shutdown().is_err());
}

#[test]
fn application_snapshot_audit_covers_metadata_trigger_writes() {
    let fixture = fixture();
    let source =
        SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
    let conn = source.conn.blocking_lock();
    application_seed_applied_one(&fixture, &conn, &source.caps);
    conn.execute_batch(
        "CREATE TEMP TRIGGER change_log_after_snapshot_metadata \
         AFTER INSERT ON consensus_snapshot BEGIN \
         UPDATE consensus_log SET entry_json = CAST('invalid' AS BLOB) \
         WHERE log_index = (SELECT MAX(log_index) FROM consensus_log); END;",
    )
    .unwrap();
    fixture
        .wal
        .restore_application(&conn, &source.caps)
        .unwrap();
    let before = super::super::super::wal::application::full_image_digest(&conn).unwrap();
    let candidate = snapshot_metadata_candidate(&conn);
    let error = fixture
        .wal
        .publish_snapshot(&conn, candidate)
        .expect_err("snapshot metadata effects must precede the final audit");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "session consensus decoding failed");
    assert_eq!(
        super::super::super::wal::application::full_image_digest(&conn).unwrap(),
        before
    );
    assert_eq!(
        super::super::super::last_log_sync(&conn, identity()).unwrap(),
        Some(log_id(1))
    );
    let called = std::cell::Cell::new(false);
    assert!(fixture
        .wal
        .with_application_read(&conn, || called.set(true))
        .is_err());
    assert!(!called.get());
    assert!(fixture.wal.shutdown().is_err());
}

#[test]
fn application_snapshot_publication_discards_an_audit_after_a_later_write() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let incoming = install_source_at(2);
    for transform in ["metadata", "compact", "install"] {
        let cache_path = Arc::new(Mutex::new(None::<PathBuf>));
        let hook_path = Arc::clone(&cache_path);
        let wrote = Arc::new(AtomicBool::new(false));
        let hook_wrote = Arc::clone(&wrote);
        let control = IoControl {
            hook: Arc::new(move |point| {
                if point == Point::AfterSnapshotCacheCommit {
                    let path = hook_path.lock().unwrap().clone().unwrap();
                    let other = Connection::open(path).unwrap();
                    assert_eq!(other.execute(
                        "UPDATE consensus_machine SET application_sequence = application_sequence + 1 WHERE singleton = 1", [],
                    ).unwrap(), 1);
                    hook_wrote.store(true, Ordering::SeqCst);
                }
                Ok(())
            }),
            ..IoControl::default()
        };
        let fixture = Fixture::new(Limits::default(), control, None, true);
        let path = fixture.directory.path().join("source.sqlite");
        let source = SqliteSessionBackend::open(&path).unwrap();
        let conn = source.conn.blocking_lock();
        *cache_path.lock().unwrap() = Some(path);
        application_seed_applied_one(&fixture, &conn, &source.caps);
        let candidate = if transform == "install" {
            incoming.candidate.clone()
        } else {
            snapshot_metadata_candidate(&conn)
        };
        let result = match transform {
            "metadata" => fixture.wal.publish_snapshot(&conn, candidate.clone()),
            "compact" => fixture
                .wal
                .publish_compacting_snapshot(&conn, candidate.clone()),
            "install" => fixture
                .wal
                .install_snapshot(&conn, incoming.source().unwrap()),
            _ => unreachable!(),
        };
        assert!(wrote.load(Ordering::SeqCst), "{transform}");
        let error = result.expect_err("post-commit writes cannot inherit the transaction audit");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{transform}");
        assert_eq!(
            error.to_string(),
            "private WAL application cache changed outside its owner",
            "{transform}"
        );
        assert_eq!(
            read_current_snapshot_sync(&conn, identity()).unwrap(),
            Some(candidate)
        );
        let called = std::cell::Cell::new(false);
        assert!(fixture
            .wal
            .with_application_read(&conn, || called.set(true))
            .is_err());
        assert!(!called.get());
        assert!(fixture.wal.vote().is_err());
        assert!(fixture.wal.shutdown().is_err());
    }
}

fn application_marker_change_is_rejected(statement: &str, expected_reason: &str) {
    let fixture = fixture();
    let source =
        SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
    let conn = source.conn.blocking_lock();
    application_seed_applied_one(&fixture, &conn, &source.caps);
    fixture.wal.shutdown().unwrap();
    conn.execute_batch(&format!(
        "CREATE TRIGGER application_change_final_row AFTER INSERT ON consensus_wal_application \
         BEGIN {statement}; END;"
    ))
    .unwrap();
    let reopened = fixture
        .reopen(Limits::default(), IoControl::default())
        .unwrap();
    reopened.restore_application(&conn, &source.caps).unwrap();
    assert_eq!(reopened.with_application_read(&conn, || 7).unwrap(), 7);
    let before = super::super::super::wal::application::full_image_digest(&conn).unwrap();
    reopened
        .submit(append(&[batch(2)]))
        .unwrap()
        .wait()
        .unwrap();
    reopened
        .submit(Operation::Committed(Some(log_id(2))))
        .unwrap()
        .wait()
        .unwrap();
    let error = reopened
        .apply_committed(&conn, &source.caps, vec![batch(2)], ApplyControl::Normal)
        .expect_err("the final SQL row must satisfy the complete original audit");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), expected_reason);
    assert_eq!(
        super::super::super::wal::application::full_image_digest(&conn).unwrap(),
        before
    );
    let called = std::cell::Cell::new(false);
    assert!(reopened
        .with_application_read(&conn, || called.set(true))
        .is_err());
    assert!(!called.get());
    assert!(reopened.shutdown().is_err());
}

#[test]
fn application_log_audit_rejects_an_intervening_same_connection_write() {
    use super::super::super::log_row_reuse_test_observer::Scope;
    let fixture = fixture();
    let source =
        SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
    let conn = source.conn.blocking_lock();
    application_seed_applied_one(&fixture, &conn, &source.caps);
    fixture
        .wal
        .submit(append(&[batch(2)]))
        .unwrap()
        .wait()
        .unwrap();
    fixture
        .wal
        .submit(Operation::Committed(Some(log_id(2))))
        .unwrap()
        .wait()
        .unwrap();
    let observation = Scope::new();
    observation.after_highest_audit(|private| {
        assert_eq!(
            private
                .execute(
                    "UPDATE consensus_log SET entry_json = entry_json WHERE log_index = 2",
                    [],
                )
                .unwrap(),
            1
        );
    });
    let error = fixture
        .wal
        .apply_committed(&conn, &source.caps, vec![batch(2)], ApplyControl::Normal)
        .expect_err("a write during the audit must not establish payload reuse");
    observation.finish();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error.to_string(),
        "private WAL application log changed during audit"
    );
    assert_eq!(
        super::super::super::last_log_sync(&conn, identity()).unwrap(),
        Some(log_id(1)),
        "the cache transaction must not apply the rejected entry"
    );
    assert!(fixture.wal.shutdown().is_err());
}

#[test]
fn application_final_audit_reuses_the_exact_private_log_decode() {
    use super::super::super::log_row_reuse_test_observer::{Event, Scope};
    let fixture = fixture();
    let source =
        SqliteSessionBackend::open(fixture.directory.path().join("source.sqlite")).unwrap();
    let conn = source.conn.blocking_lock();
    application_seed_applied_one(&fixture, &conn, &source.caps);
    for index in 2..=3 {
        fixture
            .wal
            .submit(append(&[batch(index)]))
            .unwrap()
            .wait()
            .unwrap();
        fixture
            .wal
            .submit(Operation::Committed(Some(log_id(index))))
            .unwrap()
            .wait()
            .unwrap();
        let observation = Scope::new();
        fixture
            .wal
            .apply_committed(
                &conn,
                &source.caps,
                vec![batch(index)],
                ApplyControl::Normal,
            )
            .unwrap();
        let events = observation.finish();
        let begin = events
            .iter()
            .position(|event| *event == Event::ApplicationFinalAuditStart)
            .expect("apply performs its final transaction audit");
        let end = events
            .iter()
            .position(|event| *event == Event::ApplicationFinalAuditEnd)
            .expect("the final transaction audit completed");
        assert!(events[..begin].contains(&Event::FullDecode));
        assert!(events[begin..end].contains(&Event::HighestAudit));
        assert!(
            !events[begin..end].contains(&Event::FullDecode),
            "exact stored-byte equality must reuse the earlier complete payload decode"
        );
        assert_eq!(
            super::super::super::last_log_sync(&conn, identity()).unwrap(),
            Some(log_id(index))
        );
        assert_eq!(fixture.wal.with_application_read(&conn, || 7).unwrap(), 7);
    }
    fixture.wal.shutdown().unwrap();
}

#[test]
fn application_final_application_audit_rejects_a_different_valid_payload() {
    let statement = format!(
        "UPDATE consensus_log SET entry_json = X'{}' WHERE log_index = 2",
        hex::encode(encode_json(&blank(2)).unwrap())
    );
    application_marker_change_is_rejected(&statement, "private WAL application final log differs");
}

#[test]
fn application_final_application_audit_checks_row_metadata() {
    application_marker_change_is_rejected(
        "UPDATE consensus_log SET term = term + 1 WHERE log_index = 2",
        "persisted session consensus log row mismatch",
    );
}

#[test]
fn application_final_application_audit_checks_the_highest_row() {
    let statement = format!(
        "INSERT INTO consensus_log(log_index, configuration_epoch, term, entry_json) \
         SELECT 3, configuration_epoch, term, X'{}' FROM consensus_log WHERE log_index = 2",
        hex::encode(encode_json(&blank(3)).unwrap())
    );
    application_marker_change_is_rejected(&statement, "private WAL application final log differs");
}

#[test]
fn application_final_application_audit_rejects_a_missing_final_row() {
    application_marker_change_is_rejected(
        "DELETE FROM consensus_log WHERE log_index = 2",
        "private WAL application final log differs",
    );
}

#[test]
fn application_frontier_cache_detects_same_connection_schema_change() {
    use super::super::super::log_row_reuse_test_observer::{Event, Scope};
    let fixture = fixture();
    let path = fixture.directory.path().join("source.sqlite");
    let source = SqliteSessionBackend::open(&path).unwrap();
    let conn = source.conn.blocking_lock();
    application_seed_applied_one(&fixture, &conn, &source.caps);
    let changes = conn.total_changes();
    let data_version: i64 = conn
        .pragma_query_value(Some("main"), "data_version", |row| row.get(0))
        .unwrap();
    conn.execute_batch("ALTER TABLE consensus_log RENAME TO consensus_log_detached")
        .unwrap();
    assert_eq!(conn.total_changes(), changes);
    assert_eq!(
        conn.pragma_query_value(Some("main"), "data_version", |row| row.get::<_, i64>(0))
            .unwrap(),
        data_version,
        "the schema counter must catch changes missed by both write counters"
    );
    let observation = Scope::new();
    let called = std::cell::Cell::new(false);
    let error = fixture
        .wal
        .with_application_read(&conn, || called.set(true))
        .expect_err("a schema change must invalidate the published frontier");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error.to_string(),
        "private WAL application cache changed outside its owner"
    );
    assert!(!called.get());
    assert!(!observation.finish().contains(&Event::FullDecode));
    assert!(fixture.wal.shutdown().is_err());
}

#[test]
fn application_frontier_cache_detects_deletion_and_same_connection_rollback() {
    use super::super::super::log_row_reuse_test_observer::{Event, Scope};
    for separate_connection in [false, true] {
        for rollback in [false, true] {
            let fixture = fixture();
            let path = fixture.directory.path().join("source.sqlite");
            let source = SqliteSessionBackend::open(&path).unwrap();
            let conn = source.conn.blocking_lock();
            application_seed_applied_one(&fixture, &conn, &source.caps);
            let other = separate_connection.then(|| Connection::open(&path).unwrap());
            let writer = other.as_ref().unwrap_or(&conn);
            let tx = writer.unchecked_transaction().unwrap();
            assert_eq!(
                tx.execute("DELETE FROM consensus_log WHERE log_index = 1", [])
                    .unwrap(),
                1
            );
            if rollback {
                tx.rollback().unwrap();
            } else {
                tx.commit().unwrap();
            }
            let observation = Scope::new();
            let called = std::cell::Cell::new(false);
            let read = fixture.wal.with_application_read(&conn, || {
                called.set(true);
                7
            });
            assert!(!observation.finish().contains(&Event::FullDecode));
            if separate_connection && rollback {
                assert_eq!(
                    read.unwrap(),
                    7,
                    "a rolled-back foreign write changes no visible bytes"
                );
                assert!(called.get());
                fixture.wal.shutdown().unwrap();
            } else {
                let error = read.expect_err("the existing connection counters must reject reuse");
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert_eq!(
                    error.to_string(),
                    "private WAL application cache changed outside its owner"
                );
                assert!(!called.get());
                assert!(fixture.wal.shutdown().is_err());
            }
        }
    }
}

#[test]
fn application_frontier_cache_rejects_another_read_connection() {
    let fixture = fixture();
    let path = fixture.directory.path().join("source.sqlite");
    let source = SqliteSessionBackend::open(&path).unwrap();
    let conn = source.conn.blocking_lock();
    application_seed_applied_one(&fixture, &conn, &source.caps);
    let other = Connection::open(&path).unwrap();
    other
        .execute_batch(
            "CREATE TEMP TABLE consensus_wal_application_connection \
             (singleton INTEGER PRIMARY KEY CHECK(singleton = 1), token BLOB NOT NULL); \
             INSERT INTO consensus_wal_application_connection VALUES (1, zeroblob(16));",
        )
        .unwrap();
    let called = std::cell::Cell::new(false);
    let error = fixture
        .wal
        .with_application_read(&other, || called.set(true))
        .expect_err("a different connection cannot inherit the attached cache proof");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        error.to_string(),
        "private WAL application cache changed outside its owner"
    );
    assert!(!called.get());
    assert!(fixture.wal.shutdown().is_err());
}
