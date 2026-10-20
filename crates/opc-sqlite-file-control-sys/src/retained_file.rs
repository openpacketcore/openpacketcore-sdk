//! Pins whose final close remains in SQLite's Unix inode bookkeeping.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek};
use std::mem::ManuallyDrop;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OpenFlags};

use crate::{with_borrowed_sqlite_descriptor, with_main_file};

#[cfg(test)]
mod retirement_tests;

/// A regular file whose descriptor is owned and closed by SQLite.
///
/// Clones share ownership; they never duplicate the OS descriptor. The private
/// connection is never queried, so it neither acquires database locks nor
/// checkpoints a WAL. Its Unix VFS defers the final descriptor close while
/// another SQLite connection holds POSIX locks on this inode. This also covers
/// independently opened connections and cancelled workers.
///
/// Clone the wrapper to retain close ownership. A raw `File` cannot be obtained:
///
/// ```compile_fail
/// use opc_sqlite_file_control_sys::RetainedSqliteFile;
/// fn duplicate(pin: &RetainedSqliteFile) {
///     let _ = pin.file().try_clone();
/// }
/// ```
#[derive(Clone)]
pub struct RetainedSqliteFile {
    inner: Arc<Inner>,
}

struct Inner {
    // This is only a borrowed view. SQLite alone closes the actual descriptor.
    file: ManuallyDrop<File>,
    // A mutex gives the unqueried, private connection a Sync owner. No caller
    // can execute SQL, replace the main descriptor or close it independently.
    _connection: Mutex<Connection>,
}

impl RetainedSqliteFile {
    /// Open an existing regular file without admitting a final symlink.
    ///
    /// An O_PATH pin establishes regular-file identity before SQLite opens the
    /// reader. Both the SQLite descriptor and the public name must match that
    /// held inode before the pin is returned. No raw readable descriptor is
    /// created, including on failed admission.
    ///
    /// SQLite reopens the resolved pathname, so a concurrent replacement can
    /// be opened before the identity fence rejects it; a substituted FIFO can
    /// block that open. The store requires an SDK-controlled namespace. Root
    /// and noncooperating same-UID actors, who can also modify the stored bytes,
    /// are outside its integrity model. This is not adversarial path admission.
    /// SQLite's native pathname limit also applies (about 504 usable bytes with
    /// the bundled Unix VFS); longer canonical names fail closed.
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
        // Resolve only the held descriptor. SQLite's NOFOLLOW flag rejects a
        // substituted symlink; the later fence rejects a different inode only
        // after open. A same-UID/root replacement with a FIFO can block before
        // that fence. The SDK-owned namespace excludes those actors from its
        // integrity model; this does not provide exact-inode open authority.
        // SQLite's native pathname limit applies. No SQL is executed.
        let path = std::fs::read_link(format!("/proc/self/fd/{}", expected.as_raw_fd()))?;
        let connection = Connection::open_with_flags_and_vfs(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            "unix",
        )
        .map_err(|_| unavailable())?;
        with_main_file(&connection, |observed| {
            let metadata = observed.metadata()?;
            if !metadata.is_file() || identity(&metadata) != identity(&expected_metadata) {
                return Err(unavailable());
            }
            Ok(())
        })
        .map_err(|_| unavailable())??;
        let mut file = with_borrowed_sqlite_descriptor(
            &connection,
            c"main",
            rusqlite::ffi::SQLITE_FCNTL_FILE_POINTER,
            |descriptor| {
                // SAFETY: the private connection moves into Inner below and
                // cannot be accessed by callers. It owns this descriptor for
                // the entire Arc lifetime. ManuallyDrop cannot close it.
                Ok(ManuallyDrop::new(unsafe { File::from_raw_fd(descriptor) }))
            },
        )
        .map_err(|_| unavailable())?;
        // The Unix VFS may reuse a deferred descriptor. Give each independent
        // reader a fresh cursor while SQLite still owns every error-path close.
        file.seek(io::SeekFrom::Start(0))?;
        Ok(Self {
            inner: Arc::new(Inner {
                file,
                _connection: Mutex::new(connection),
            }),
        })
    }

    fn file(&self) -> &File {
        &self.inner.file
    }

    /// Inspect this descriptor without resolving a pathname or duplicating it.
    pub fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.file().metadata()
    }

    /// Read bytes at an offset without changing the shared reader cursor.
    pub fn read_exact_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<()> {
        self.file().read_exact_at(buffer, offset)
    }
}

/// Borrow only for descriptor operations that do not duplicate or close it.
/// Closing a duplicate would bypass SQLite's lock-preserving close owner.
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

impl Read for &RetainedSqliteFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file().read(buffer)
    }
}

impl Seek for RetainedSqliteFile {
    fn seek(&mut self, position: io::SeekFrom) -> io::Result<u64> {
        self.file().seek(position)
    }
}

impl Seek for &RetainedSqliteFile {
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

    #[test]
    fn retained_pin_rejects_paths_beyond_sqlite_path_limit() {
        let directory = tempfile::tempdir().unwrap();
        let mut parent = directory.path().to_path_buf();
        for index in 0..10 {
            parent.push(format!("{index:064}"));
            std::fs::create_dir(&parent).unwrap();
        }
        let path = parent.join("database");
        std::fs::write(&path, b"ordinary regular artifact").unwrap();
        assert!(path.canonicalize().unwrap().as_os_str().len() > 512);
        assert!(RetainedSqliteFile::open_nofollow(&path).is_err());
        // The limitation belongs to SQLite pathname admission.
        assert!(File::open(&path).unwrap().metadata().unwrap().is_file());
    }
}
