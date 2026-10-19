//! Probe SQLite's real POSIX record lock from an independent process.

use super::CommandExt as _;
use std::fs::File;
use std::path::Path;

const PATH: &str = "OPC_SQLITE_RECORD_LOCK_PROBE_PATH";
const BLOCKED: &str = "OPC_SQLITE_RECORD_LOCK_PROBE_BLOCKED";

pub(crate) fn child() -> bool {
    let Some(path) = std::env::var_os(PATH) else {
        return false;
    };
    let file = File::options().read(true).write(true).open(path).unwrap();
    let lock = libc::flock {
        l_type: libc::F_WRLCK.try_into().unwrap(),
        l_whence: libc::SEEK_SET.try_into().unwrap(),
        // SQLite's SHARED_FIRST and SHARED_SIZE, independent of its API.
        l_start: 1_073_741_826,
        l_len: 510,
        l_pid: 0,
    };
    let result = nix::fcntl::fcntl(&file, nix::fcntl::FcntlArg::F_SETLK(&lock));
    if std::env::var(BLOCKED).unwrap() == "1" {
        assert!(
            matches!(
                result,
                Err(nix::errno::Errno::EACCES | nix::errno::Errno::EAGAIN)
            ),
            "SQLite's live lock must exclude another process: {result:?}"
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
pub(crate) fn assert_state(path: &Path, test: &str, blocked: bool, phase: &str) {
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--test-threads=4", "--nocapture"])
        .env(PATH, path)
        .env(BLOCKED, if blocked { "1" } else { "0" })
        .test_output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed; 0 failed;"),
        "independent lock probe {phase}: {stdout}\n{stderr}"
    );
}

pub(crate) fn begin(connection: &rusqlite::Connection) {
    assert_eq!(
        connection
            .query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))
            .unwrap(),
        "wal"
    );
    connection
        .execute_batch("PRAGMA locking_mode=NORMAL; BEGIN IMMEDIATE;")
        .unwrap();
}
