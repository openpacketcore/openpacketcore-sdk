use super::*;

// The heap limit is process-global. Only the isolated child enables this hook,
// after normal database opening and immediately before the real metadata read.
static METADATA_HEAP_OUTAGE: AtomicBool = AtomicBool::new(false);

pub(super) fn before_metadata_read(conn: &rusqlite::Connection) -> Vec<rusqlite::Statement<'_>> {
    if METADATA_HEAP_OUTAGE.load(Ordering::Acquire) {
        let pressure = crate::error::exhaust_sqlite_heap(conn);
        let error = conn
            .query_row("SELECT COUNT(*) FROM sqlite_schema", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::OutOfMemory)
        );
        pressure
    } else {
        Vec::new()
    }
}

#[test]
fn open_metadata_heap_outage_is_unavailable_without_changing_bytes() {
    const CHILD: &str = "OPC_OPEN_METADATA_HEAP_CHILD";
    if let Some(directory) = std::env::var_os(CHILD) {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let path = Path::new(&directory).join("config.sqlite");
            let original = SqliteBackend::open_with_audit_key(
                &path,
                true,
                0,
                AuditKey::new([0x71; 32]).unwrap(),
            )
            .await
            .unwrap();
            let before = std::fs::read(&path).unwrap();
            let wal = path.with_extension("sqlite-wal");
            let wal_before = std::fs::read(&wal).unwrap_or_default();
            METADATA_HEAP_OUTAGE.store(true, Ordering::Release);
            let error = match SqliteBackend::open_with_audit_key(
                &path,
                true,
                0,
                AuditKey::new([0x71; 32]).unwrap(),
            )
            .await
            {
                Ok(_) => panic!("metadata read must fail during the outage"),
                Err(error) => error,
            };
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert_eq!(std::fs::read(&wal).unwrap_or_default(), wal_before);
            assert!(
                matches!(error.kind(), crate::PersistErrorKind::Unavailable),
                "{error:?}"
            );
            drop(original);
        });
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "backend::tests::open_metadata_heap_outage_is_unavailable_without_changing_bytes",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(CHILD, directory.path())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(String::from_utf8_lossy(&child.stdout)
        .contains("test result: ok. 1 passed; 0 failed; 0 ignored;"));
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let repaired = SqliteBackend::open_with_audit_key(
            directory.path().join("config.sqlite"),
            true,
            0,
            AuditKey::new([0x71; 32]).unwrap(),
        )
        .await
        .unwrap();
        assert!(crate::ConfigStore::load_latest(&repaired)
            .await
            .unwrap()
            .is_none());
    });
}
