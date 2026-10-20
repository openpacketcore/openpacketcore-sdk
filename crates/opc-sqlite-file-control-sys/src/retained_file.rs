//! Pins whose final close remains in SQLite's Unix inode bookkeeping.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek};
use std::mem::ManuallyDrop;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::Arc;

use rusqlite::Connection;

use crate::with_main_file;

mod unix_retirement;
use unix_retirement::Retirement;

#[cfg(test)]
mod retirement_tests;

#[cfg(test)]
thread_local! {
    static BEFORE_READABLE_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

/// A regular file whose final close is coordinated with SQLite.
///
/// Clones share ownership; they never duplicate the OS descriptor. Admission
/// reads the exact regular inode through its pinned descriptor. Final release
/// joins the bundled Unix VFS's deferred-close queue while another SQLite
/// connection holds POSIX locks on that inode. This includes independently
/// opened connections and cancelled workers. No SQL or checkpoint is executed.
#[derive(Clone)]
pub struct RetainedSqliteFile {
    inner: Arc<Inner>,
}

struct Inner {
    // Always retire through the native close coordinator, including failed
    // admission and unwinding. Both fields are consumed exactly once in Drop.
    file: ManuallyDrop<File>,
    retirement: ManuallyDrop<Retirement>,
    identity: (u64, u64),
}

impl Drop for Inner {
    fn drop(&mut self) {
        // SAFETY: these fields were initialized together and are never taken
        // elsewhere. Arc invokes this destructor once after the last borrower.
        let (file, retirement) = unsafe {
            (
                ManuallyDrop::take(&mut self.file),
                ManuallyDrop::take(&mut self.retirement),
            )
        };
        retirement.close(file, self.identity);
    }
}

impl RetainedSqliteFile {
    /// Open an existing regular file without admitting a final symlink.
    ///
    /// An O_PATH pin establishes regular-file identity before any readable
    /// open. The reader opens only that exact descriptor through procfs, never
    /// its resolved pathname. A final public-name fence rejects substitution;
    /// even failed admission retires the reader through SQLite's close queue.
    pub fn open_nofollow(path: &Path) -> io::Result<Self> {
        let pin = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let retained = Self::open_exact(&pin)?;
        let named = std::fs::symlink_metadata(path)?;
        let expected = pin.metadata()?;
        if !named.is_file() || identity(&named) != identity(&expected) {
            return Err(unavailable());
        }
        Ok(retained)
    }

    /// Retain SQLite's admitted main inode without duplicating its descriptor.
    pub fn from_connection(connection: &Connection) -> io::Result<Self> {
        with_main_file(connection, Self::open_exact).map_err(|_| unavailable())?
    }

    fn open_exact(expected: &File) -> io::Result<Self> {
        let expected_metadata = expected.metadata()?;
        if !expected_metadata.is_file() {
            return Err(unavailable());
        }
        // Allocate close coordination before any readable descriptor exists.
        // Following this procfs descriptor link reopens the held regular inode
        // even if its old public pathname is concurrently replaced or removed.
        let retirement = Retirement::prepare()?;
        let path = format!("/proc/self/fd/{}", expected.as_raw_fd());
        #[cfg(test)]
        BEFORE_READABLE_OPEN.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook();
            }
        });
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        let mut inner = Inner {
            file: ManuallyDrop::new(file),
            retirement: ManuallyDrop::new(retirement),
            identity: identity(&expected_metadata),
        };
        // The live descriptor supplied above fixes identity even if this fstat
        // fails. Wrap before checking so every subsequent error uses the queue.
        let metadata = inner.file.metadata()?;
        inner.identity = identity(&metadata);
        if !metadata.is_file() || inner.identity != identity(&expected_metadata) {
            return Err(unavailable());
        }
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// Borrow the retained descriptor without transferring close authority.
    ///
    /// Do not duplicate this file: closing a raw duplicate would bypass
    /// SQLite's lock-preserving close. Clone this wrapper instead.
    pub fn file(&self) -> &File {
        &self.inner.file
    }
}

impl AsFd for RetainedSqliteFile {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file().as_fd()
    }
}

impl AsRawFd for RetainedSqliteFile {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.file().as_raw_fd()
    }
}

impl Read for RetainedSqliteFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file().read(buffer)
    }
}

impl Seek for RetainedSqliteFile {
    fn seek(&mut self, position: io::SeekFrom) -> io::Result<u64> {
        self.file().seek(position)
    }
}

impl std::fmt::Debug for RetainedSqliteFile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RetainedSqliteFile(<redacted>)")
    }
}

fn identity(metadata: &std::fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn unavailable() -> io::Error {
    io::Error::other("SQLite retained file is unavailable")
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use std::io::{BufRead, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn fifo(path: &Path) {
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is a live NUL-terminated pathname; mkfifo retains no pointer.
        let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
        assert_eq!(result, 0);
    }

    struct ResetHook;

    impl Drop for ResetHook {
        fn drop(&mut self) {
            BEFORE_READABLE_OPEN.with(|hook| {
                hook.borrow_mut().take();
            });
        }
    }

    #[test]
    fn retained_pin_rejects_non_regular_before_readable_open() {
        let directory = tempfile::tempdir().unwrap();
        let fifo_path = directory.path().join("fifo");
        fifo(&fifo_path);
        let socket_path = directory.path().join("socket");
        let _socket = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        let link_path = directory.path().join("link");
        std::os::unix::fs::symlink(&fifo_path, &link_path).unwrap();
        for path in [directory.path(), &fifo_path, &socket_path, &link_path] {
            let opened = std::rc::Rc::new(std::cell::Cell::new(false));
            let observed = opened.clone();
            let _reset = ResetHook;
            BEFORE_READABLE_OPEN.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || observed.set(true)));
            });
            assert!(RetainedSqliteFile::open_nofollow(path).is_err());
            assert!(!opened.get(), "non-regular input reached the readable open");
        }
    }

    #[test]
    fn retained_pin_fifo_substitution_without_writer_does_not_block() {
        const CHILD_PATH: &str = "OPC_RETAINED_PIN_FIFO_CHILD_PATH";
        const READY: &str = "retained-pin-substituted";
        const TEST: &str =
            "retained_file::admission_tests::retained_pin_fifo_substitution_without_writer_does_not_block";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            let path = std::path::PathBuf::from(path);
            let substituted = path.clone();
            BEFORE_READABLE_OPEN.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    std::fs::rename(&substituted, substituted.with_extension("pinned")).unwrap();
                    fifo(&substituted);
                    println!("\n{READY}");
                    std::io::stdout().flush().unwrap();
                }));
            });
            assert!(RetainedSqliteFile::open_nofollow(&path).is_err());
            return;
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("database");
        std::fs::write(&path, []).unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
            .env(CHILD_PATH, &path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (ready, observed) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut output = String::new();
            for line in std::io::BufReader::new(stdout).lines() {
                let line = line.unwrap();
                if line == READY {
                    ready.send(()).unwrap();
                }
                output.push_str(&line);
                output.push('\n');
            }
            output
        });
        let substituted = observed.recv_timeout(Duration::from_secs(5));
        let deadline = Instant::now() + Duration::from_secs(5);
        let completed = loop {
            if child.try_wait().unwrap().is_some() {
                break true;
            }
            if substituted.is_err() || Instant::now() >= deadline {
                child.kill().unwrap();
                break false;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        let output = child.wait_with_output().unwrap();
        let stdout = reader.join().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            substituted.is_ok(),
            "child never substituted the FIFO: {stdout}\n{stderr}"
        );
        assert!(
            completed,
            "opening a substituted FIFO without a writer blocked: {stdout}\n{stderr}"
        );
        assert!(
            output.status.success() && stdout.contains("test result: ok. 1 passed; 0 failed;"),
            "isolated FIFO admission must reject exactly once: {stdout}\n{stderr}"
        );
    }
}
