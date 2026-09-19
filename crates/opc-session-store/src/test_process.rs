//! Coordinate child launches with fs-verity in the shared unit-test process.
//!
//! CLOEXEC descriptors still exist in a forked child until exec. A concurrent
//! fixture can therefore close its last writer and get ETXTBSY while that child
//! retains an inherited writer. Seals take a shared gate; a launch takes the
//! exclusive gate only until `spawn` completes its exec handshake. Waiting for
//! a child's result must remain outside this gate. Actual writers still cause
//! the unchanged kernel validation to fail. None of this is production code.

use std::io;
#[cfg(target_os = "linux")]
use std::process::ExitStatus;
use std::process::{Child, Command, Output, Stdio};
#[cfg(target_os = "linux")]
use std::sync::RwLock;

#[cfg(target_os = "linux")]
pub(crate) static SNAPSHOT_PROCESS_FD_GATE: RwLock<()> = RwLock::new(());

/// Use for every child launch in this crate's shared unit-test process.
pub(crate) trait CommandExt {
    fn test_spawn(&mut self) -> io::Result<Child>;
    #[cfg(target_os = "linux")]
    fn test_status(&mut self) -> io::Result<ExitStatus>;
    /// Capture both output streams, with null stdin, for an isolated fixture.
    fn test_output(&mut self) -> io::Result<Output>;
}

impl CommandExt for Command {
    fn test_spawn(&mut self) -> io::Result<Child> {
        #[cfg(target_os = "linux")]
        let _launch = SNAPSHOT_PROCESS_FD_GATE
            .write()
            .expect("test child-launch gate remains available");
        self.spawn()
    }

    #[cfg(target_os = "linux")]
    fn test_status(&mut self) -> io::Result<ExitStatus> {
        self.test_spawn()?.wait()
    }

    fn test_output(&mut self) -> io::Result<Output> {
        self.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .test_spawn()?
            .wait_with_output()
    }
}
