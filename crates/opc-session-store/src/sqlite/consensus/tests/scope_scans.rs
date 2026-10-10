//! Retained SQLite transactions use the actual writer descriptor and one cut.

use super::*;
use crate::consensus::snapshot::PinnedSqliteFile;
use crate::sqlite::scope_scan::SqliteScopeScan;
use std::cell::Cell;

struct Fixture {
    backend: SqliteSessionBackend,
    source: PinnedSqliteFile,
    directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("scope-scan.sqlite");
        let backend = SqliteSessionBackend::open(&path).unwrap();
        let connection = backend.conn.blocking_lock();
        initialize_schema(&connection, identity(), &expected_members()).unwrap();
        apply_entries_sync(
            &connection,
            identity(),
            &backend.caps,
            vec![membership_entry_at(
                0,
                vec![expected_members()],
                expected_members(),
            )],
        )
        .unwrap();
        connection.execute("INSERT INTO session_records (tenant,nf_kind,key_type,stable_id,generation,owner,fence,state_class,state_type,expires_at,payload,encoding) VALUES ('scope-scan','smf','opc-scope-child',?1,1,'scope-state',0,'authoritative-session','opc-scope-state-v4',NULL,?2,0)", params![vec![0x31u8;64], b"before".as_slice()]).unwrap();
        let source = PinnedSqliteFile::from_file(
            opc_sqlite_file_control_sys::main_file_descriptor(&connection).unwrap(),
            path,
        )
        .unwrap();
        drop(connection);
        Self {
            backend,
            source,
            directory,
        }
    }

    fn capture(&self) -> SqliteScopeScan {
        SqliteScopeScan::capture(&self.source, identity(), &|| Ok(())).unwrap()
    }

    fn advance(&self) {
        let connection = self.backend.conn.blocking_lock();
        apply_entries_sync(
            &connection,
            identity(),
            &self.backend.caps,
            vec![blank_entry(1)],
        )
        .unwrap();
        connection
            .execute(
                "UPDATE session_records SET payload = ?1 WHERE tenant='scope-scan'",
                [b"after".as_slice()],
            )
            .unwrap();
    }
}

fn payload(connection: &Connection) -> io::Result<Vec<u8>> {
    connection
        .query_row(
            "SELECT payload FROM session_records WHERE tenant='scope-scan'",
            [],
            |row| row.get(0),
        )
        .map_err(db_error)
}

#[test]
fn sqlite_scope_scan_indexes_allow_plain_sqlite_writes_and_integrity_checks() {
    let fixture = Fixture::new();
    // No SDK connection setup: old consumers and SQLite tools must be able to
    // maintain these derived indexes without application-defined functions.
    let connection = Connection::open(fixture.source.path()).unwrap();
    connection
        .execute_batch("PRAGMA trusted_schema=OFF")
        .unwrap();
    for key_type in ["ordinary", "opc-scope-child", "opc-scope-claim"] {
        for length in [7, 32, 48, 64] {
            let key = vec![length as u8; length];
            connection.execute("INSERT INTO session_records (tenant,nf_kind,key_type,stable_id,generation,owner,fence,state_class,state_type,expires_at,payload,encoding) VALUES ('plain-sqlite','smf',?1,?2,1,'fixture',0,'authoritative-session','fixture',NULL,x'00',0)", params![key_type, key]).unwrap();
            assert_eq!(connection.execute("UPDATE session_records SET payload=x'01' WHERE tenant='plain-sqlite' AND key_type=?1 AND stable_id=?2", params![key_type, key]).unwrap(), 1);
            assert_eq!(connection.execute("DELETE FROM session_records WHERE tenant='plain-sqlite' AND key_type=?1 AND stable_id=?2", params![key_type, key]).unwrap(), 1);
        }
    }
    let check: String = connection
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .unwrap();
    assert_eq!(check, "ok");
    connection.execute_batch("VACUUM").unwrap();
    assert_eq!(payload(&connection).unwrap(), b"before");
}

#[test]
fn sqlite_scope_scan_wal_admission_waits_ahead_of_later_writers() {
    use crate::scope_scan::{admission::CaptureCost, registry::ViewRegistry};
    use crate::scope_scheduler::{ScopeSchedulerKey, ScopeSchedulerOwner, ScopeWorkClass};
    let fixture = Fixture::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::pause();
        let owner = ScopeSchedulerOwner::default();
        let scheduler = owner.scheduler();
        let registry =
            ViewRegistry::<Option<()>>::new(Default::default(), Duration::from_secs(30)).unwrap();
        let writer = fixture.backend.conn.lock().await;
        registry.set_wal_probe(crate::sqlite::scope_scan::wal_probe(
            Arc::downgrade(&fixture.backend.conn),
            Arc::new(fixture.source),
        ));
        let key = ScopeSchedulerKey::from_bytes([9; 32]);
        let mut admission = Box::pin(
            registry.admit(
                key,
                CaptureCost::Sqlite,
                None,
                scheduler
                    .reserve(key, ScopeWorkClass::Normal)
                    .await
                    .unwrap(),
            ),
        );
        assert!(futures_util::poll!(admission.as_mut()).is_pending());
        let mut next_writer = Box::pin(fixture.backend.conn.lock());
        assert!(futures_util::poll!(next_writer.as_mut()).is_pending());
        drop(writer);
        let std::task::Poll::Ready(Ok(view)) = futures_util::poll!(admission.as_mut()) else {
            panic!(
                "WAL admission lost its fair writer-lock position and waited for a timer sample"
            );
        };
        assert!(futures_util::poll!(next_writer.as_mut()).is_ready());
        assert!(registry.metrics().retained_wal_bytes.is_some());
        drop(view);
    });
}

#[test]
fn sqlite_scope_scan_current_headers_wait_for_writer_ownership() {
    let fixture = Arc::new(Fixture::new());
    let writer = fixture.backend.conn.blocking_lock();
    let (entered, entering) = std::sync::mpsc::channel();
    let (finished, finishing) = std::sync::mpsc::channel();
    let observer = Arc::clone(&fixture);
    let worker = std::thread::spawn(move || {
        let state = crate::scope_authority::tests::admitted();
        let stamp = state.view.stamp().unwrap();
        entered.send(()).unwrap();
        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(observer.backend.scope_scan_current_headers(
                &observer.source,
                identity(),
                stamp.namespace(),
                stamp,
                &crate::scope_scan::runtime::ViewCancellation::default(),
            ));
        finished.send(result.is_ok()).unwrap();
    });
    entering.recv_timeout(Duration::from_secs(2)).unwrap();
    let before_unlock = finishing.recv_timeout(Duration::from_millis(100));
    drop(writer);
    let observed = before_unlock
        .as_ref()
        .copied()
        .unwrap_or_else(|_| finishing.recv_timeout(Duration::from_secs(2)).unwrap());
    worker.join().unwrap();
    assert!(
        before_unlock.is_err(),
        "writer contention completed the guard early"
    );
    assert!(observed, "writer contention became an operational refusal");
}

#[test]
fn sqlite_scope_scan_writer_wait_cancellation_preserves_next_waiter() {
    let fixture = Fixture::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let state = crate::scope_authority::tests::admitted();
        let stamp = state.view.stamp().unwrap();
        let cancellation = crate::scope_scan::runtime::ViewCancellation::default();
        let writer = fixture.backend.conn.lock().await;
        let mut guard = Box::pin(fixture.backend.scope_scan_current_headers(
            &fixture.source,
            identity(),
            stamp.namespace(),
            stamp,
            &cancellation,
        ));
        assert!(futures_util::poll!(guard.as_mut()).is_pending());
        let mut next = Box::pin(fixture.backend.conn.lock());
        assert!(futures_util::poll!(next.as_mut()).is_pending());
        drop(guard);
        drop(writer);
        let _next_writer = tokio::time::timeout(Duration::from_secs(1), next)
            .await
            .unwrap();
    });
}

#[test]
fn sqlite_scope_scan_capture_requires_the_complete_exact_index_pair() {
    for damage in ["absent", "partial", "changed-filter"] {
        let fixture = Fixture::new();
        drop(fixture.capture());
        {
            let connection = fixture.backend.conn.blocking_lock();
            let ddl: String = connection
                .query_row(
                    "SELECT sql FROM sqlite_master WHERE name='scope_scan_keys'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            connection
                .execute_batch("DROP INDEX scope_scan_keys")
                .unwrap();
            match damage {
                "absent" => connection
                    .execute_batch("DROP INDEX scope_scan_bad_keys")
                    .unwrap(),
                "changed-filter" => connection
                    .execute_batch(&ddl.replace("length(stable_id)=64", "length(stable_id)=63"))
                    .unwrap(),
                _ => {}
            }
        }
        let result = SqliteScopeScan::capture(&fixture.source, identity(), &|| Ok(()));
        assert!(
            matches!(result, Err(ref error) if error.kind() == io::ErrorKind::InvalidData),
            "capture must refuse missing or damaged scan indexes: {damage}",
        );
    }
}

#[test]
fn sqlite_scope_scan_keeps_rows_and_applied_position_at_one_cut() {
    let fixture = Fixture::new();
    let scan = fixture.capture();
    let applied = scan.applied();
    fixture.advance();
    let (bytes, at, autocommit) = scan
        .read(
            || false,
            |connection, check| {
                check()?;
                Ok((
                    payload(connection)?,
                    read_applied_sync(connection, identity())?,
                    connection.is_autocommit(),
                ))
            },
        )
        .unwrap();
    assert_eq!(
        bytes, b"before",
        "pages must retain the opening transaction"
    );
    assert_eq!(at, applied);
    assert!(
        !autocommit,
        "a retained reader must keep its read transaction"
    );
    assert_eq!(fixture.capture().applied().unwrap().index, 1);
}

#[test]
fn sqlite_scope_scan_reader_is_read_only_and_work_errors_preserve_the_cut() {
    let fixture = Fixture::new();
    let scan = fixture.capture();
    assert!(scan
        .read(
            || false,
            |connection, _| connection
                .execute("DELETE FROM session_records", [])
                .map_err(db_error)
        )
        .is_err());
    assert_eq!(
        scan.read(|| false, |connection, _| payload(connection))
            .unwrap(),
        b"before"
    );
}

#[test]
fn sqlite_scope_scan_cancellation_before_work_never_executes_the_callback() {
    let fixture = Fixture::new();
    let scan = fixture.capture();
    let entered = Cell::new(false);
    let result = scan.read(
        || true,
        |_, _| {
            entered.set(true);
            Ok(())
        },
    );
    assert!(result.is_err(), "cancelled SQLite work must not execute");
    assert!(!entered.get());
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
}

#[test]
fn sqlite_scope_scan_cancellation_after_work_discards_the_result() {
    let fixture = Fixture::new();
    let scan = fixture.capture();
    let cancelled = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&cancelled);
    let result = scan.read(
        move || observed.load(Ordering::SeqCst),
        |connection, _| {
            let value = payload(connection)?;
            cancelled.store(true, Ordering::SeqCst);
            Ok(value)
        },
    );
    assert!(result.is_err(), "cancelled SQLite result must not escape");
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
}

#[test]
fn sqlite_scope_scan_vm_progress_budget_interrupts_and_unhooks_each_operation() {
    let fixture = Fixture::new();
    let scan = fixture.capture();
    let checks = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&checks);
    let result = scan.read(move || counted.fetch_add(1, Ordering::SeqCst) >= 5, |connection, _| {
        connection.query_row("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000) SELECT max(x) FROM n", [], |row| row.get::<_, i64>(0)).map_err(db_error)
    });
    assert!(
        result.is_err(),
        "SQLite VM work must observe the page budget"
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
    assert!(checks.load(Ordering::SeqCst) >= 6);
    assert_eq!(
        scan.read(|| false, |connection, _| payload(connection))
            .unwrap(),
        b"before"
    );
}

#[test]
fn sqlite_scope_scan_open_cancellation_keeps_no_transaction() {
    let fixture = Fixture::new();
    assert!(
        SqliteScopeScan::capture(&fixture.source, identity(), &|| Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "cancelled"
        )))
        .is_err(),
        "cancelled open must refuse before pinning"
    );
}

#[test]
fn sqlite_scope_scan_measures_live_wal_growth_without_evicting_the_reader() {
    let fixture = Fixture::new();
    let scan = fixture.capture();
    let before = scan.wal_bytes().unwrap();
    fixture.advance();
    let connection = fixture.backend.conn.blocking_lock();
    let expected = opc_sqlite_file_control_sys::main_journal_descriptor(&connection)
        .unwrap()
        .metadata()
        .unwrap()
        .len();
    assert!(expected > before);
    assert_eq!(
        scan.wal_bytes().unwrap(),
        expected,
        "measure the actual shared WAL descriptor"
    );
    assert_eq!(
        scan.read(|| false, |connection, _| payload(connection))
            .unwrap(),
        b"before"
    );
}

#[test]
fn sqlite_scope_scan_drop_releases_the_real_wal_reader_lock() {
    let fixture = Fixture::new();
    let scan = fixture.capture();
    fixture.advance();
    let connection = fixture.backend.conn.blocking_lock();
    connection.busy_timeout(Duration::ZERO).unwrap();
    let checkpoint = || {
        connection
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap()
    };
    assert_eq!(checkpoint(), 1, "retained cut must pin older WAL frames");
    drop(scan);
    assert_eq!(
        checkpoint(),
        0,
        "closing the view must release WAL retention"
    );
}

#[test]
fn sqlite_scope_scan_rejects_main_path_replacement_after_capture() {
    let fixture = Fixture::new();
    let scan = fixture.capture();
    let source = fixture.directory.path().join("scope-scan.sqlite");
    std::fs::rename(&source, fixture.directory.path().join("old.sqlite")).unwrap();
    std::fs::write(&source, b"foreign file").unwrap();
    assert!(
        scan.read(|| false, |_, _| Ok(())).is_err(),
        "replaced main identity must invalidate the reader"
    );
}

#[test]
fn sqlite_scope_scan_never_reports_an_unlinked_wal_as_zero() {
    let fixture = Fixture::new();
    let scan = fixture.capture();
    let wal = fixture.directory.path().join("scope-scan.sqlite-wal");
    std::fs::remove_file(&wal).unwrap();
    std::fs::write(&wal, []).unwrap();
    assert!(
        scan.wal_bytes().is_err(),
        "lost WAL identity must not become a zero sample"
    );
    assert!(scan.read(|| false, |_, _| Ok(())).is_err());
}

fn wal_probe(fixture: &Fixture) -> crate::scope_scan::registry::WalProbe {
    crate::sqlite::scope_scan::wal_probe(
        Arc::downgrade(&fixture.backend.conn),
        Arc::new(fixture.source.try_clone().unwrap()),
    )
}

#[test]
fn sqlite_scope_wal_probe_reports_actual_growth_and_truncated_zero() {
    let fixture = Fixture::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let probe = wal_probe(&fixture);
    let before = runtime.block_on(probe()).unwrap();
    fixture.advance();
    let actual = {
        let conn = fixture.backend.conn.blocking_lock();
        opc_sqlite_file_control_sys::main_journal_descriptor(&conn)
            .unwrap()
            .metadata()
            .unwrap()
            .len()
    };
    assert!(actual > before);
    assert_eq!(runtime.block_on(probe()), Some(actual));
    {
        let conn = fixture.backend.conn.blocking_lock();
        let busy: i64 = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
            .unwrap();
        assert_eq!(busy, 0);
        assert_eq!(
            opc_sqlite_file_control_sys::main_journal_descriptor(&conn)
                .unwrap()
                .metadata()
                .unwrap()
                .len(),
            0
        );
    }
    assert_eq!(
        runtime.block_on(probe()),
        Some(0),
        "only an actual truncated descriptor can report zero"
    );
}

#[test]
fn sqlite_scope_wal_probe_waits_for_writer_and_cancellation_releases_its_place() {
    let fixture = Fixture::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let probe = wal_probe(&fixture);
    let primary = fixture.backend.conn.blocking_lock();
    runtime.block_on(async {
        tokio::time::pause();
        let mut waiting = probe();
        assert!(futures_util::poll!(waiting.as_mut()).is_pending());
        let mut next_writer = Box::pin(fixture.backend.conn.lock());
        assert!(futures_util::poll!(next_writer.as_mut()).is_pending());
        assert!(
            tokio::time::timeout(Duration::from_secs(3), waiting.as_mut())
                .await
                .is_err()
        );
        drop(waiting);
        drop(primary);
        assert!(
            futures_util::poll!(next_writer.as_mut()).is_ready(),
            "a cancelled measurement must release its writer-lock queue position"
        );
    });
    assert!(runtime.block_on(probe()).is_some());
    let weak = Arc::downgrade(&fixture.backend.conn);
    drop(fixture);
    assert!(
        weak.upgrade().is_none(),
        "the probe must not own the backend connection"
    );
    assert_eq!(
        runtime.block_on(probe()),
        None,
        "a disappeared owner cannot become a zero-byte WAL"
    );
}

#[test]
fn sqlite_scope_wal_probe_rejects_a_replaced_main_path() {
    let fixture = Fixture::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let probe = wal_probe(&fixture);
    assert!(runtime.block_on(probe()).is_some());
    let path = fixture.directory.path().join("scope-scan.sqlite");
    std::fs::rename(&path, fixture.directory.path().join("old.sqlite")).unwrap();
    std::fs::write(&path, b"foreign main").unwrap();
    assert_eq!(runtime.block_on(probe()), None);
}

#[test]
fn sqlite_scope_wal_probe_rejects_an_unlinked_writer_wal() {
    let fixture = Fixture::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let probe = wal_probe(&fixture);
    assert!(runtime.block_on(probe()).is_some());
    std::fs::remove_file(fixture.directory.path().join("scope-scan.sqlite-wal")).unwrap();
    assert_eq!(
        runtime.block_on(probe()),
        None,
        "unlinked retained WAL is not absent or empty"
    );
}

fn scope_raw_key() -> crate::SessionKey {
    crate::SessionKey {
        tenant: opc_types::TenantId::from_static("scope-scan"),
        nf_kind: opc_types::NetworkFunctionKind::smf(),
        key_type: crate::SessionKeyType::other("opc-scope-child").unwrap(),
        stable_id: crate::StableId::new(bytes::Bytes::from(vec![0x31; 64])).unwrap(),
    }
}

#[test]
fn sqlite_scope_scan_raw_point_read_keeps_missing_distinct_from_a_record() {
    use crate::scope_scan::headers::RawScopeRecord;
    use crate::sqlite::scope_scan::read_raw_record;
    let fixture = Fixture::new();
    let connection = fixture.backend.conn.blocking_lock();
    let key = scope_raw_key();
    match read_raw_record(&connection, &key, 64).unwrap() {
        RawScopeRecord::Present(row) => {
            assert_eq!(row.key, key);
            assert_eq!(row.payload.as_bytes(), b"before");
        }
        _ => panic!("an existing bounded raw row is present"),
    }
    let mut absent = key;
    absent.stable_id = crate::StableId::new(bytes::Bytes::from(vec![0x32; 64])).unwrap();
    assert!(matches!(
        read_raw_record(&connection, &absent, 64).unwrap(),
        RawScopeRecord::Missing
    ));
}

#[test]
fn sqlite_scope_scan_raw_payload_is_bounded_before_rust_allocation() {
    use crate::scope_scan::headers::RawScopeRecord;
    use crate::sqlite::scope_scan::read_raw_record;
    let fixture = Fixture::new();
    let connection = fixture.backend.conn.blocking_lock();
    connection
        .execute("UPDATE session_records SET payload=zeroblob(2000000)", [])
        .unwrap();
    let key = scope_raw_key();
    let mut verdict = None;
    let measured = allocation_counter::measure(|| {
        verdict = Some(read_raw_record(&connection, &key, 4096).unwrap());
    });
    assert!(matches!(verdict, Some(RawScopeRecord::Corrupt)));
    assert!(
        measured.bytes_max < 128 * 1024,
        "oversized payload was materialized before checking its bound: {measured:?}"
    );
}

#[test]
fn sqlite_scope_scan_raw_metadata_is_bounded_before_rust_allocation() {
    use crate::scope_scan::headers::RawScopeRecord;
    use crate::sqlite::scope_scan::read_raw_record;
    for field in ["owner", "state_type", "state_class", "expires_at"] {
        let fixture = Fixture::new();
        let connection = fixture.backend.conn.blocking_lock();
        connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        connection
            .execute(
                &format!("UPDATE session_records SET {field}=printf('%02000000d',0)"),
                [],
            )
            .unwrap();
        let key = scope_raw_key();
        let mut verdict = None;
        let measured = allocation_counter::measure(|| {
            verdict = Some(read_raw_record(&connection, &key, 4096).unwrap());
        });
        assert!(
            matches!(verdict, Some(RawScopeRecord::Corrupt)),
            "field {field}"
        );
        assert!(
            measured.bytes_max < 128 * 1024,
            "oversized {field} was materialized before checking its bound: {measured:?}"
        );
    }
}

#[test]
fn sqlite_scope_scan_raw_wrong_column_types_are_final_corruption() {
    use crate::scope_scan::headers::RawScopeRecord;
    use crate::sqlite::scope_scan::read_raw_record;
    for mutation in [
        "payload='not-a-blob'",
        "owner=x'ff'",
        "generation='invalid'",
        "fence=-1",
        "encoding=2",
        "expires_at='2020-01-01T00:00:00Z'",
    ] {
        let fixture = Fixture::new();
        let connection = fixture.backend.conn.blocking_lock();
        connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        connection
            .execute(&format!("UPDATE session_records SET {mutation}"), [])
            .unwrap();
        assert!(
            matches!(
                read_raw_record(&connection, &scope_raw_key(), 4096).unwrap(),
                RawScopeRecord::Corrupt
            ),
            "invalid reserved envelope {mutation}"
        );
    }
}

#[test]
fn sqlite_scope_scan_raw_invalid_fields_do_not_materialize_in_sqlite_memory() {
    use crate::scope_scan::headers::RawScopeRecord;
    use crate::sqlite::scope_scan::{read_raw_record, RAW_RECORD_STATEMENT_BYTES};
    for field in [
        "owner",
        "state_type",
        "state_class",
        "expires_at",
        "generation",
        "fence",
        "encoding",
    ] {
        let fixture = Fixture::new();
        let connection = fixture.backend.conn.blocking_lock();
        connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        connection
            .execute(
                &format!("UPDATE session_records SET {field}=printf('%02000000d',0) || 'x'"),
                [],
            )
            .unwrap();
        assert!(matches!(
            read_raw_record(&connection, &scope_raw_key(), 4096).unwrap(),
            RawScopeRecord::Corrupt,
        ));
        let bytes = RAW_RECORD_STATEMENT_BYTES.get();
        assert!(
            (1..128 * 1024).contains(&bytes),
            "oversized {field} allocated {bytes} bytes inside SQLite before rejection",
        );
    }
}

#[test]
fn sqlite_scope_scan_bounded_work_returns_completed_prefix_after_budget_exhaustion() {
    let fixture = Fixture::new();
    let scan = fixture.capture();
    let exhausted = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&exhausted);
    let result = scan
        .read_bounded(
            || false,
            move || observed.load(Ordering::SeqCst),
            |connection, check, _work_exhausted| {
                check()?;
                let complete = payload(connection)?;
                exhausted.store(true, Ordering::SeqCst);
                Ok(complete)
            },
        )
        .expect("work exhaustion preserves the completed prefix");
    assert_eq!(result, b"before");
}

#[test]
fn sqlite_scope_scan_bounded_vm_interruption_can_return_the_completed_prefix() {
    let fixture = Fixture::new();
    let scan = fixture.capture();
    let calls = Arc::new(AtomicUsize::new(0));
    let measured = Arc::clone(&calls);
    let result = scan.read_bounded(
        || false,
        move || measured.fetch_add(1, Ordering::SeqCst) >= 5,
        |connection, check, _work_exhausted| {
            check()?;
            let complete = payload(connection)?;
            assert!(connection.query_row("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000) SELECT max(x) FROM n", [], |row| row.get::<_, i64>(0)).is_err());
            Ok(complete)
        },
    ).expect("a VM budget interruption is not cancellation of the completed prefix");
    assert_eq!(result, b"before");
    assert!(calls.load(Ordering::SeqCst) >= 6);
    assert_eq!(scan.read(|| false, |connection, _| connection.query_row("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<20000) SELECT max(x) FROM n", [], |row| row.get::<_, i64>(0)).map_err(db_error)).unwrap(), 20000);
}

#[test]
fn sqlite_scope_scan_bounded_work_still_discards_cancelled_completed_prefix() {
    let fixture = Fixture::new();
    let scan = fixture.capture();
    let cancelled = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&cancelled);
    let result = scan.read_bounded(
        move || observed.load(Ordering::SeqCst),
        || false,
        |connection, check, _work_exhausted| {
            check()?;
            let complete = payload(connection)?;
            cancelled.store(true, Ordering::SeqCst);
            Ok(complete)
        },
    );
    assert!(
        result.is_err(),
        "cancellation still suppresses a completed prefix"
    );
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
}

fn inventory_source_rows() -> (
    crate::scope_authority::ScopeNamespace,
    Vec<StoredSessionRecord>,
) {
    use crate::scope_authority::{ScopeIncarnation, ScopeNamespace};
    use crate::scope_batch::{
        tests::{claim, key, value},
        ScopeChildRecord, ScopeChildRevision,
    };
    use crate::scope_storage::{ClaimOwner, ClaimRow, ScopeRow};
    let namespace = ScopeNamespace::new(
        crate::scope_authority::tests::scope(),
        ScopeIncarnation::new(1).unwrap(),
    )
    .unwrap();
    let child = ScopeRow::Child(ScopeChildRecord {
        namespace: namespace.clone(),
        key: key(1),
        revision: ScopeChildRevision::new(1, 1).unwrap(),
        batch_revision: 1,
        value: Some(value(1)),
        claims: vec![claim(11)],
    })
    .to_record()
    .unwrap();
    let claim = ScopeRow::Claim(ClaimRow {
        namespace: namespace.clone(),
        key: claim(11),
        revision: 1,
        owner: Some(ClaimOwner {
            child: key(1),
            birth: 1,
        }),
    })
    .to_record()
    .unwrap();
    (namespace, vec![child, claim])
}

#[test]
fn sqlite_scope_scan_inventory_source_keyset_reads_the_retained_cut_after_writes() {
    use crate::scope_scan::{engine, integrity, progress, sources};
    use crate::scope_storage::ScopeRow;
    let fixture = Fixture::new();
    let (namespace, rows) = inventory_source_rows();
    {
        let connection = fixture.backend.conn.blocking_lock();
        for row in &rows {
            crate::sqlite::ops::insert_or_replace_record_sync(&connection, row).unwrap();
        }
    }
    let captured = fixture.capture();
    {
        let connection = fixture.backend.conn.blocking_lock();
        for row in &rows {
            let mut decoded = ScopeRow::from_record(row).unwrap();
            match &mut decoded {
                ScopeRow::Child(row) => {
                    row.value = None;
                    row.claims.clear();
                    row.batch_revision = 2;
                }
                ScopeRow::Claim(row) => {
                    row.owner = None;
                    row.revision = 2;
                }
                _ => unreachable!(),
            }
            crate::sqlite::ops::insert_or_replace_record_sync(
                &connection,
                &decoded.to_record().unwrap(),
            )
            .unwrap();
        }
    }
    for (capture, live) in [(captured, true), (fixture.capture(), false)] {
        capture
            .read_bounded(
                || false,
                || false,
                |connection, check, work_exhausted| {
                    let mut source = sources::SqliteSource {
                        connection,
                        check,
                        work_exhausted,
                    };
                    let floors = integrity::InventoryFloors {
                        batch_revision: if live { 1 } else { 2 },
                        birth: 1,
                    };
                    let first = engine::page(
                        &mut source,
                        &namespace,
                        floors,
                        progress::PageLimits {
                            rows: 1,
                            ..progress::PageLimits::default()
                        },
                        None,
                        progress::InventoryTotals::default(),
                        false,
                    )
                    .unwrap();
                    assert_eq!(
                        first.items.len(),
                        1,
                        "SQLite keyset emits the retained child"
                    );
                    assert_eq!(
                        first.items[0].inspection.disposition,
                        if live {
                            integrity::ItemDisposition::LiveChild
                        } else {
                            integrity::ItemDisposition::ChildTombstone
                        }
                    );
                    let progress::PageBoundary::Continue { after, totals } = first.boundary else {
                        panic!("first page advances");
                    };
                    let second = engine::page(
                        &mut source,
                        &namespace,
                        floors,
                        progress::PageLimits::default(),
                        Some(after),
                        totals,
                        false,
                    )
                    .unwrap();
                    assert_eq!(
                        second.items.len(),
                        1,
                        "SQLite range does not restart the child scan"
                    );
                    if live {
                        assert!(matches!(
                            second.items[0].inspection.disposition,
                            integrity::ItemDisposition::ClaimHeld(_)
                        ));
                    } else {
                        assert_eq!(
                            second.items[0].inspection.disposition,
                            integrity::ItemDisposition::ClaimReleased
                        );
                    }
                    assert!(matches!(
                        second.boundary,
                        progress::PageBoundary::Complete {
                            totals: progress::InventoryTotals {
                                items: 2,
                                failures: 0,
                                ..
                            },
                            ..
                        }
                    ));
                    assert_eq!(
                        engine::lookup(&mut source, &namespace, floors, &rows[0].key)
                            .unwrap()
                            .inspection
                            .disposition,
                        if live {
                            integrity::ItemDisposition::LiveChild
                        } else {
                            integrity::ItemDisposition::ChildTombstone
                        }
                    );
                    Ok(())
                },
            )
            .unwrap();
    }
}

#[test]
fn sqlite_scope_scan_inventory_source_keeps_oversized_bodies_final_and_allocation_bounded() {
    use crate::scope_scan::{engine, integrity, progress, sources};
    let fixture = Fixture::new();
    let (namespace, mut rows) = inventory_source_rows();
    rows[0].payload = EncryptedSessionPayload::new(vec![7; 2 * 1024 * 1024]);
    {
        let connection = fixture.backend.conn.blocking_lock();
        for row in &rows {
            crate::sqlite::ops::insert_or_replace_record_sync(&connection, row).unwrap();
        }
    }
    let capture = fixture.capture();
    capture
        .read_bounded(
            || false,
            || false,
            |connection, check, work_exhausted| {
                let mut source = sources::SqliteSource {
                    connection,
                    check,
                    work_exhausted,
                };
                let mut result = None;
                let measured = allocation_counter::measure(|| {
                    result = Some(
                        engine::page(
                            &mut source,
                            &namespace,
                            integrity::InventoryFloors {
                                batch_revision: 1,
                                birth: 1,
                            },
                            progress::PageLimits::default(),
                            None,
                            progress::InventoryTotals::default(),
                            false,
                        )
                        .unwrap(),
                    );
                });
                let result = result.unwrap();
                assert_eq!(result.items.len(), 2);
                assert_eq!(
                    result.items[0].inspection.disposition,
                    integrity::ItemDisposition::UnrestorableChild
                );
                assert_eq!(
                    result.items[1].inspection.disposition,
                    integrity::ItemDisposition::ClaimHeldUnknown
                );
                assert!(
                    measured.bytes_total < 128 * 1024,
                    "oversized raw body must be rejected before ownership: {measured:?}"
                );
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn sqlite_scope_scan_inventory_source_enumerates_unreadable_claim_keys() {
    use crate::scope_scan::{engine, integrity, progress, sources};
    let fixture = Fixture::new();
    let (namespace, mut rows) = inventory_source_rows();
    rows[1].key.stable_id = bytes::Bytes::copy_from_slice(&rows[1].key.stable_id.as_ref()[..48])
        .try_into()
        .unwrap();
    {
        let connection = fixture.backend.conn.blocking_lock();
        for row in &rows {
            crate::sqlite::ops::insert_or_replace_record_sync(&connection, row).unwrap();
        }
    }
    let capture = fixture.capture();
    capture
        .read_bounded(
            || false,
            || false,
            |connection, check, work_exhausted| {
                let mut source = sources::SqliteSource {
                    connection,
                    check,
                    work_exhausted,
                };
                let result = engine::page(
                    &mut source,
                    &namespace,
                    integrity::InventoryFloors {
                        batch_revision: 1,
                        birth: 1,
                    },
                    progress::PageLimits::default(),
                    None,
                    progress::InventoryTotals::default(),
                    false,
                )
                .unwrap();
                assert_eq!(result.items.len(), 2);
                assert!(result.items[1].inspection.inventory_incomplete);
                assert_eq!(
                    result.items[1].inspection.disposition,
                    integrity::ItemDisposition::ClaimHeldUnknown
                );
                assert!(matches!(
                    result.boundary,
                    progress::PageBoundary::Complete {
                        totals: progress::InventoryTotals {
                            claims_incomplete: true,
                            ..
                        },
                        ..
                    }
                ));
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn sqlite_scope_scan_vm_instruction_bound_reports_work_exhaustion_and_keeps_prefix() {
    let fixture = Fixture::new();
    let scan = fixture.capture();
    let result = scan.read_bounded(|| false, || false, |connection, check, work_exhausted| {
        check()?;
        let complete = payload(connection)?;
        let mut statement = connection.prepare("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000) SELECT max(x) FROM n").map_err(db_error)?;
        let attempted = statement.query_row([], |row| row.get::<_, i64>(0));
        assert!(attempted.is_err(), "the fixed VM budget must interrupt even before the wall-time bound");
        assert!(work_exhausted(), "the engine must distinguish the VM work bound from cancellation or corruption");
        assert!(statement.get_status(rusqlite::StatementStatus::VmStep) <= crate::RESTORE_SCAN_MAX_SQLITE_VM_STEPS as i32);
        check()?;
        Ok(complete)
    }).expect("bounded work can retain a completed prefix");
    assert_eq!(result, b"before");
    assert_eq!(
        scan.read(|| false, |connection, _| payload(connection))
            .unwrap(),
        b"before"
    );
}

// Physical corruption can bypass the typed SessionKey constructor. These tests
// exercise actual SQLite rows and the retained reader, never invented keys.
fn sqlite_scope_scan_bad_physical_key(key: rusqlite::types::Value) {
    use crate::scope_scan::{engine, integrity, progress, sources};
    let fixture = Fixture::new();
    let (namespace, rows) = inventory_source_rows();
    {
        let connection = fixture.backend.conn.blocking_lock();
        // Simulate physical corruption below the admitted typed schema.
        connection
            .execute_batch("PRAGMA ignore_check_constraints=ON")
            .unwrap();
        for (number, row) in rows.iter().enumerate() {
            crate::sqlite::ops::insert_or_replace_record_sync(&connection, row).unwrap();
            connection.execute(
                "INSERT INTO session_records (rowid,tenant,nf_kind,key_type,stable_id,generation,owner,fence,state_class,state_type,expires_at,payload,encoding)
                 SELECT ?5,tenant,nf_kind,key_type,?4,generation,owner,fence,state_class,state_type,expires_at,payload,encoding
                 FROM session_records WHERE tenant=?1 AND nf_kind=?2 AND key_type=?3 AND stable_id=?6",
                params![row.key.tenant.as_str(),row.key.nf_kind.as_str(),row.key.key_type.as_str(),key,if number==0 {i64::MIN} else {i64::MAX},row.key.stable_id.as_ref()],
            ).unwrap();
        }
        connection
            .execute_batch("PRAGMA ignore_check_constraints=OFF")
            .unwrap();
    }
    let capture = fixture.capture();
    capture
        .read_bounded(
            || false,
            || false,
            |connection, check, work_exhausted| {
                let collect = |failures_only| {
                    let mut source = sources::SqliteSource {
                        connection,
                        check,
                        work_exhausted,
                    };
                    let mut after = None;
                    let mut totals = progress::InventoryTotals::default();
                    let mut items = Vec::new();
                    for _ in 0..12 {
                        let result = engine::page(
                            &mut source,
                            &namespace,
                            integrity::InventoryFloors {
                                batch_revision: 1,
                                birth: 1,
                            },
                            progress::PageLimits {
                                rows: 1,
                                ..progress::PageLimits::default()
                            },
                            after,
                            totals,
                            failures_only,
                        )
                        .expect(
                            "a malformed physical key is a final item, not an operational retry",
                        );
                        items.extend(result.items);
                        match result.boundary {
                            progress::PageBoundary::Continue {
                                after: next,
                                totals: next_totals,
                            } => {
                                after = Some(next);
                                totals = next_totals;
                            }
                            progress::PageBoundary::Complete { totals, .. } => {
                                return (items, totals)
                            }
                            progress::PageBoundary::NoProgress => {
                                panic!("one malformed key must never pin a page")
                            }
                        }
                    }
                    panic!("bounded inventory must reach explicit Complete");
                };
                let mut actual = None;
                let allocation = allocation_counter::measure(|| actual = Some(collect(false)));
                let (items, totals) = actual.unwrap();
                assert_eq!(
                    totals.items, 4,
                    "include both malformed physical keys as well as both healthy rows"
                );
                assert_eq!(totals.failed_items, 2);
                assert_eq!(totals.failures, 2);
                assert!(totals.claims_incomplete);
                assert_eq!(
                    items
                        .iter()
                        .filter(|item| item.inspection.disposition
                            == integrity::ItemDisposition::LiveChild)
                        .count(),
                    1
                );
                assert_eq!(
                    items
                        .iter()
                        .filter(|item| matches!(
                            item.inspection.disposition,
                            integrity::ItemDisposition::ClaimHeld(_)
                        ))
                        .count(),
                    1
                );
                assert!(
                    items
                        .windows(2)
                        .all(|pair| pair[0].position < pair[1].position),
                    "every physical failure has a unique advancing position"
                );
                let failures: Vec<_> = items
                    .iter()
                    .filter(|item| !item.inspection.failures.is_empty())
                    .collect();
                assert!(failures
                    .iter()
                    .all(|item| item.child.is_none() && item.claim.is_none()));
                assert!(failures.iter().all(|item| matches!(
                    item.inspection.failures.as_slice(),
                    [integrity::ItemFailure::Corrupt {
                        key: None,
                        reason: integrity::IntegrityFault::Key,
                        ..
                    }]
                )));
                assert!(failures.iter().any(|item| item.inspection.disposition
                    == integrity::ItemDisposition::ClaimHeldUnknown
                    && item.inspection.inventory_incomplete));
                assert!(
                    allocation.bytes_max < 256 * 1024,
                    "physical key bytes are bounded before Rust ownership: {allocation:?}"
                );
                let (manifest, manifest_totals) = collect(true);
                assert_eq!(manifest_totals, totals);
                assert_eq!(
                    manifest
                        .iter()
                        .map(|item| &item.position)
                        .collect::<Vec<_>>(),
                    failures
                        .iter()
                        .map(|item| &item.position)
                        .collect::<Vec<_>>()
                );
                Ok(())
            },
        )
        .unwrap();
}

#[test]
fn sqlite_scope_scan_short_physical_keys_are_final_and_do_not_hide_healthy_rows() {
    sqlite_scope_scan_bad_physical_key(rusqlite::types::Value::Blob(vec![1; 7]));
}
#[test]
fn sqlite_scope_scan_empty_physical_keys_are_final_and_advance() {
    sqlite_scope_scan_bad_physical_key(rusqlite::types::Value::Blob(vec![]));
}
#[test]
fn sqlite_scope_scan_text_physical_keys_are_final_and_advance() {
    sqlite_scope_scan_bad_physical_key(rusqlite::types::Value::Text("unreadable key".into()));
}
#[test]
fn sqlite_scope_scan_integer_physical_keys_are_final_and_advance() {
    sqlite_scope_scan_bad_physical_key(rusqlite::types::Value::Integer(7));
}
#[test]
fn sqlite_scope_scan_oversized_physical_keys_are_final_and_allocation_bounded() {
    let (namespace, _) = inventory_source_rows();
    let mut key = crate::scope_storage::namespace_prefix(&namespace)
        .unwrap()
        .to_vec();
    key.resize(4 * 1024 * 1024, 8);
    sqlite_scope_scan_bad_physical_key(rusqlite::types::Value::Blob(key));
}

#[test]
fn sqlite_scope_scan_malformed_key_seek_uses_the_complete_index_and_bounded_vm_work() {
    use crate::scope_scan::sources::MALFORMED_QUERY;
    let fixture = Fixture::new();
    let (namespace, _) = inventory_source_rows();
    let connection = fixture.backend.conn.blocking_lock();
    // Thousands of other namespaces and earlier positions cannot make a late
    // page walk the malformed inventory from its start.
    connection.execute_batch("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<4096)
        INSERT INTO session_records(tenant,nf_kind,key_type,stable_id,generation,owner,fence,state_class,state_type,expires_at,payload,encoding)
        SELECT 'scope-index','smf','opc-scope-claim',CAST(printf('%040d',x) AS BLOB),1,'scope-state',0,'authoritative-session','opc-scope-state-v4',NULL,x'',0 FROM n").unwrap();
    let mut plan = connection
        .prepare(&format!("EXPLAIN QUERY PLAN {MALFORMED_QUERY}"))
        .unwrap();
    let args = params![
        namespace.scope().tenant().as_str(),
        namespace.scope().nf_kind().as_str(),
        "opc-scope-claim",
        b"".as_slice(),
        4000_i64
    ];
    let details = plan
        .query_map(args, |row| row.get::<_, String>(3))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
        .join(" ");
    assert!(
        details.contains("scope_scan_bad_keys") && details.contains("rowid>"),
        "all equalities and rowid must constrain the indexed seek: {details}"
    );
    assert!(
        !details.contains("TEMP B-TREE"),
        "no sorting the namespace at page time: {details}"
    );
    let mut statement = connection.prepare(MALFORMED_QUERY).unwrap();
    let result = statement
        .query_row(args, |row| row.get::<_, i64>(0))
        .optional()
        .unwrap();
    assert!(result.is_none());
    assert_eq!(
        statement.get_status(rusqlite::StatementStatus::FullscanStep),
        0
    );
    assert!(statement.get_status(rusqlite::StatementStatus::VmStep) < 128);
}

#[test]
fn sqlite_scope_scan_damaged_namespace_prefix_cannot_be_attributed_from_the_body() {
    use crate::scope_scan::{engine, integrity, progress, sources};
    // The persistent indexes are payload-independent so older SDKs and plain
    // SQLite can maintain them. A damaged 32..64-byte prefix cannot be assigned
    // back to the namespace in its intact body without an unbounded body scan.
    for length in [32, 48, 64] {
        let fixture = Fixture::new();
        let (namespace, rows) = inventory_source_rows();
        {
            let connection = fixture.backend.conn.blocking_lock();
            for row in &rows {
                let mut damaged = row.key.stable_id.as_ref()[..length].to_vec();
                damaged[0] ^= 1;
                crate::sqlite::ops::insert_or_replace_record_sync(&connection, row).unwrap();
                connection
                    .execute(
                        "UPDATE session_records SET stable_id=?1 WHERE tenant=?2 AND key_type=?3",
                        params![damaged, row.key.tenant.as_str(), row.key.key_type.as_str()],
                    )
                    .unwrap();
            }
        }
        fixture
            .capture()
            .read_bounded(
                || false,
                || false,
                |connection, check, work_exhausted| {
                    let result = engine::page(
                        &mut sources::SqliteSource {
                            connection,
                            check,
                            work_exhausted,
                        },
                        &namespace,
                        integrity::InventoryFloors {
                            batch_revision: 1,
                            birth: 1,
                        },
                        progress::PageLimits::default(),
                        None,
                        progress::InventoryTotals::default(),
                        false,
                    )
                    .unwrap();
                    assert!(result.items.is_empty());
                    assert!(matches!(
                        result.boundary,
                        progress::PageBoundary::Complete { .. }
                    ));
                    Ok(())
                },
            )
            .unwrap();
    }
}
