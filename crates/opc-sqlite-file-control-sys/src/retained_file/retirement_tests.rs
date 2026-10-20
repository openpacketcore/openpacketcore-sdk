use super::*;
use std::process::Command;

const FIXTURE: &str = "OPC_RETAINED_CLOSE_FIXTURE";
const PROBE_PATH: &str = "OPC_RETAINED_CLOSE_PROBE_PATH";
const PROBE_BLOCKED: &str = "OPC_RETAINED_CLOSE_PROBE_BLOCKED";

fn probe_child() -> bool {
    let Some(path) = std::env::var_os(PROBE_PATH) else {
        return false;
    };
    let file = File::options().read(true).write(true).open(path).unwrap();
    let lock = libc::flock {
        l_type: libc::F_WRLCK.try_into().unwrap(),
        l_whence: libc::SEEK_SET.try_into().unwrap(),
        l_start: 1_073_741_826,
        l_len: 510,
        l_pid: 0,
    };
    // SAFETY: fcntl borrows the live descriptor and a complete flock structure
    // only for this synchronous, nonblocking independent-process lock attempt.
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) };
    let error = io::Error::last_os_error().raw_os_error();
    if std::env::var(PROBE_BLOCKED).unwrap() == "1" {
        assert!(
            result == -1 && matches!(error, Some(libc::EACCES | libc::EAGAIN)),
            "native SQLite locks must exclude the child: {result}, {error:?}"
        );
    } else {
        assert_eq!(result, 0, "last native unlock must release the lock");
    }
    true
}

fn assert_success(output: std::process::Output) {
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed; 0 failed;"),
        "isolated close fixture must run exactly once: {stdout}\n{stderr}"
    );
}

fn isolate(test: &str) -> bool {
    if std::env::var(FIXTURE).as_deref() == Ok(test) {
        return false;
    }
    assert_success(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--test-threads=1", "--nocapture"])
            .env(FIXTURE, test)
            .output()
            .unwrap(),
    );
    true
}

fn probe(path: &Path, test: &str, blocked: bool) {
    assert_success(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--test-threads=1", "--nocapture"])
            .env(PROBE_PATH, path)
            .env(PROBE_BLOCKED, if blocked { "1" } else { "0" })
            .output()
            .unwrap(),
    );
}

fn locked_database(path: &Path) -> Connection {
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA locking_mode=NORMAL;
             CREATE TABLE sentinel(value INTEGER); INSERT INTO sentinel VALUES(42);
             BEGIN IMMEDIATE;",
        )
        .unwrap();
    connection
}

#[test]
fn retained_pin_failed_name_fence_preserves_native_record_locks() {
    const TEST: &str = "retained_file::retirement_tests::retained_pin_failed_name_fence_preserves_native_record_locks";
    if probe_child() || isolate(TEST) {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("database");
    let moved = directory.path().join("held-database");
    let connection = locked_database(&path);
    probe(&path, TEST, true);
    let substituted = path.clone();
    let held = moved.clone();
    BEFORE_READABLE_OPEN.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            std::fs::rename(&substituted, &held).unwrap();
            std::fs::write(&substituted, []).unwrap();
        }));
    });
    assert!(RetainedSqliteFile::open_nofollow(&path).is_err());
    probe(&moved, TEST, true);
    connection.execute_batch("ROLLBACK;").unwrap();
    drop(connection);
    probe(&moved, TEST, false);
}

#[test]
fn retained_pin_sequential_retirement_stays_within_descriptor_budget() {
    const TEST: &str = "retained_file::retirement_tests::retained_pin_sequential_retirement_stays_within_descriptor_budget";
    if probe_child() || isolate(TEST) {
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("database");
    let connection = locked_database(&path);
    probe(&path, TEST, true);
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes a complete rlimit into this live initialized value.
    let result = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) };
    assert_eq!(result, 0);
    limit.rlim_cur = limit.rlim_cur.min(64);
    // SAFETY: only this isolated child lowers its own soft descriptor limit;
    // the hard limit is preserved and the parent harness is unaffected.
    let result = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
    assert_eq!(result, 0);
    for _ in 0..128 {
        let mut pin = RetainedSqliteFile::open_nofollow(&path)
            .expect("sequential pins must not exhaust the descriptor budget");
        let mut header = [0; 16];
        pin.read_exact(&mut header).unwrap();
        assert_eq!(&header, b"SQLite format 3\0");
        drop(pin);
    }
    probe(&path, TEST, true);
    connection.execute_batch("ROLLBACK;").unwrap();
    drop(connection);
    probe(&path, TEST, false);
}

#[test]
fn retained_pin_native_queue_preserves_locks_and_reclaims_descriptors() {
    const TEST: &str = "retained_file::retirement_tests::retained_pin_native_queue_preserves_locks_and_reclaims_descriptors";
    if probe_child() || isolate(TEST) {
        return;
    }
    // Isolation makes the post-unlock EBADF assertion meaningful: unrelated
    // tests cannot reuse this descriptor number between unlock and inspection.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("database");
    let connection = locked_database(&path);
    let pin = RetainedSqliteFile::open_nofollow(&path).unwrap();
    let clone = pin.clone();
    let descriptor = pin.as_raw_fd();
    assert_eq!(descriptor, clone.as_raw_fd());
    probe(&path, TEST, true);

    let start = Arc::new(std::sync::Barrier::new(5));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let path = path.clone();
            let start = Arc::clone(&start);
            std::thread::spawn(move || {
                let reader = Connection::open(&path).unwrap();
                start.wait();
                for _ in 0..10 {
                    let pin = RetainedSqliteFile::from_connection(&reader).unwrap();
                    assert_eq!(
                        reader
                            .query_row("SELECT value FROM sentinel", [], |row| row.get::<_, i64>(0))
                            .unwrap(),
                        42
                    );
                    drop(pin);
                }
            })
        })
        .collect();
    start.wait();
    for thread in threads {
        thread.join().unwrap();
    }
    drop(pin);
    assert_eq!(clone.as_raw_fd(), descriptor);
    drop(clone);
    let native_reader =
        Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let native_descriptor = crate::with_borrowed_sqlite_descriptor(
        &native_reader,
        c"main",
        rusqlite::ffi::SQLITE_FCNTL_FILE_POINTER,
        Ok,
    )
    .unwrap();
    assert_ne!(
        native_descriptor, descriptor,
        "native SQLite must not adopt the queued non-native reader"
    );
    drop(native_reader);
    probe(&path, TEST, true);
    // SAFETY: F_GETFD only inspects this integer; it neither borrows Rust file
    // ownership nor closes a descriptor still retained in SQLite's queue.
    assert_ne!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) }, -1);
    connection.execute_batch("ROLLBACK;").unwrap();
    // SAFETY: the same non-owning query proves the final native unlock reclaimed
    // the queued reader rather than leaking it or keeping a permanent anchor.
    assert_eq!(unsafe { libc::fcntl(descriptor, libc::F_GETFD) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    drop(connection);
    probe(&path, TEST, false);
}
