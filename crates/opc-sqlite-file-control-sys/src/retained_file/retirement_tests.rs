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
