use super::*;
use crate::sqlite::SqliteSessionBackend;
use crate::test_process::CommandExt as _;
use std::fs::File;
use std::path::Path;

const PROBE_PATH: &str = "OPC_TERMINAL_OBSERVER_LOCK_PROBE_PATH";
const PROBE_BLOCKED: &str = "OPC_TERMINAL_OBSERVER_LOCK_PROBE_BLOCKED";

fn lock_probe_child() -> bool {
    let Some(path) = std::env::var_os(PROBE_PATH) else {
        return false;
    };
    let file = File::options().read(true).write(true).open(path).unwrap();
    let lock = libc::flock {
        l_type: libc::F_WRLCK.try_into().unwrap(),
        l_whence: libc::SEEK_SET.try_into().unwrap(),
        // SQLite's SHARED_FIRST and SHARED_SIZE: exclude the parent's actual
        // database read lock without relying on another SQLite connection.
        l_start: 1_073_741_826,
        l_len: 510,
        l_pid: 0,
    };
    let result = nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_SETLK(&lock));
    if std::env::var(PROBE_BLOCKED).unwrap() == "1" {
        assert!(
            matches!(
                result,
                Err(nix::errno::Errno::EACCES | nix::errno::Errno::EAGAIN)
            ),
            "another process must remain excluded by SQLite's shared database lock: {result:?}"
        );
    } else {
        assert!(
            result.is_ok(),
            "the final SQLite close releases its lock: {result:?}"
        );
    }
    true
}

#[track_caller]
fn assert_lock_state(path: &Path, test: &str, blocked: bool) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--test-threads=4", "--nocapture"])
        .env(PROBE_PATH, path)
        .env(PROBE_BLOCKED, if blocked { "1" } else { "0" })
        .test_output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed; 0 failed;"),
        "independent SQLite lock probe: {stdout}\n{stderr}"
    );
}

async fn begin_transaction(backend: &SqliteSessionBackend) {
    let conn = backend.conn.lock().await;
    assert_eq!(
        conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "wal"
    );
    conn.execute_batch("PRAGMA locking_mode=NORMAL; BEGIN IMMEDIATE;")
        .unwrap();
}

#[tokio::test]
async fn observer_lookup_preserves_sqlite_locks_for_selected_and_unrelated_databases() {
    const TEST: &str = "sqlite::consensus::terminal_observer::tests::observer_lookup_preserves_sqlite_locks_for_selected_and_unrelated_databases";
    if lock_probe_child() {
        return;
    }
    for selected in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let selected_path = directory.path().join("selected.sqlite");
        let observed = SqliteSessionBackend::open(&selected_path).unwrap();
        let other_path = directory.path().join("unrelated.sqlite");
        let other = SqliteSessionBackend::open(&other_path).unwrap();
        let observation =
            ProtectedRosterTerminalObservationForTest::new(std::slice::from_ref(&observed))
                .await
                .unwrap();
        let (backend, path) = if selected {
            (&observed, &selected_path)
        } else {
            (&other, &other_path)
        };
        begin_transaction(backend).await;
        assert_lock_state(path, TEST, true);
        {
            let conn = backend.conn.lock().await;
            assert!(database_key(&conn).is_some());
        }
        assert_lock_state(path, TEST, true);
        backend
            .conn
            .lock()
            .await
            .execute_batch("ROLLBACK;")
            .unwrap();
        drop(observation);
        drop(observed);
        drop(other);
        assert_lock_state(
            if selected {
                &selected_path
            } else {
                &other_path
            },
            TEST,
            false,
        );
    }
}

#[tokio::test]
async fn observer_retirement_preserves_sqlite_locks_while_another_observer_is_active() {
    const TEST: &str = "sqlite::consensus::terminal_observer::tests::observer_retirement_preserves_sqlite_locks_while_another_observer_is_active";
    if lock_probe_child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("observed.sqlite");
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let retired = ProtectedRosterTerminalObservationForTest::new(std::slice::from_ref(&backend))
        .await
        .unwrap();
    let remaining = ProtectedRosterTerminalObservationForTest::new(std::slice::from_ref(&backend))
        .await
        .unwrap();
    begin_transaction(&backend).await;
    assert_lock_state(&path, TEST, true);
    drop(retired);
    assert_lock_state(&path, TEST, true);
    assert_eq!(
        remaining.timings(),
        ProtectedRosterTerminalApplyTimings::default()
    );
    backend
        .conn
        .lock()
        .await
        .execute_batch("ROLLBACK;")
        .unwrap();
    drop(remaining);
    drop(backend);
    assert_lock_state(&path, TEST, false);
}

#[tokio::test]
async fn failed_observer_construction_preserves_sqlite_locks() {
    const TEST: &str = "sqlite::consensus::terminal_observer::tests::failed_observer_construction_preserves_sqlite_locks";
    if lock_probe_child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("observed.sqlite");
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let unsupported = SqliteSessionBackend::in_memory().unwrap();
    begin_transaction(&backend).await;
    assert_lock_state(&path, TEST, true);
    assert!(
        ProtectedRosterTerminalObservationForTest::new(&[backend.clone(), unsupported])
            .await
            .is_err()
    );
    assert_lock_state(&path, TEST, true);
    backend
        .conn
        .lock()
        .await
        .execute_batch("ROLLBACK;")
        .unwrap();
    drop(backend);
    assert_lock_state(&path, TEST, false);
}

#[tokio::test]
async fn cancelled_observer_construction_preserves_sqlite_locks() {
    const TEST: &str = "sqlite::consensus::terminal_observer::tests::cancelled_observer_construction_preserves_sqlite_locks";
    if lock_probe_child() {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("observed.sqlite");
    let backend = SqliteSessionBackend::open(&path).unwrap();
    let second = SqliteSessionBackend::open(directory.path().join("second.sqlite")).unwrap();
    let held_second = second.conn.lock().await;
    begin_transaction(&backend).await;
    assert_lock_state(&path, TEST, true);
    let backends = [backend.clone(), second.clone()];
    let mut constructing = Box::pin(ProtectedRosterTerminalObservationForTest::new(&backends));
    assert!(matches!(
        futures_util::poll!(&mut constructing),
        std::task::Poll::Pending
    ));
    // The first connection was available; construction is now waiting on the
    // second one. Cancellation must retire the partially collected owners.
    drop(constructing);
    assert_lock_state(&path, TEST, true);
    drop(held_second);
    backend
        .conn
        .lock()
        .await
        .execute_batch("ROLLBACK;")
        .unwrap();
    drop(backends);
    drop(backend);
    assert_lock_state(&path, TEST, false);
}
