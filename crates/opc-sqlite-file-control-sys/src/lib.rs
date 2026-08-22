//! Narrow safe access to SQLite's main-file movement probe.
//!
//! SQLite owns the VFS file handle behind a [`rusqlite::Connection`].  This
//! crate contains the sole audited raw-handle call required to ask that VFS
//! whether its main database file has moved.  It exposes neither the handle
//! nor any file name, and fails closed when the pinned SQLite build does not
//! implement the opcode.

#![allow(unsafe_code)]
#![deny(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{c_void, CStr, CString};
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd as _;
#[cfg(feature = "test-vfs")]
use std::sync::OnceLock;

use rusqlite::{ffi, Connection};

/// Failure from the SQLite main-file movement probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileControlError;

/// The name of the test-only VFS that fails SQLite unnamed temporary opens.
///
/// This is available only with the `test-vfs` feature.  It is deliberately a
/// separate VFS rather than a process-wide temporary-directory setting, so a
/// caller opts in by selecting this name in a SQLite URI.
#[cfg(feature = "test-vfs")]
pub const TEST_TEMP_PATH_FAILURE_VFS_NAME: &str = "opc-test-fail-temp-vfs";

#[cfg(feature = "test-vfs")]
const TEST_TEMP_PATH_FAILURE_VFS_CSTR: &CStr = c"opc-test-fail-temp-vfs";

/// Register a test-only VFS that returns `SQLITE_IOERR_GETTEMPPATH` for an
/// unnamed SQLite temporary-file open while delegating every named open to the
/// bundled default VFS.
///
/// This feature-gated helper is intended only for an isolated test process.
/// It never becomes the SQLite default VFS and therefore cannot alter a
/// production process's temporary-directory behavior.
#[cfg(feature = "test-vfs")]
pub fn install_test_temp_path_failure_vfs() -> Result<(), FileControlError> {
    static REGISTER: OnceLock<Result<(), FileControlError>> = OnceLock::new();
    *REGISTER.get_or_init(|| {
        // SAFETY: SQLite owns the returned default VFS for the process.  We
        // copy its stable callback table, replace only `xOpen`, leak that
        // table for SQLite's registration lifetime, and never make it the
        // process default.  The callback delegates named opens to the
        // original VFS pointer without retaining caller-owned arguments.
        unsafe {
            let default_vfs = ffi::sqlite3_vfs_find(std::ptr::null());
            if default_vfs.is_null() {
                return Err(FileControlError);
            }
            let mut vfs = *default_vfs;
            vfs.zName = TEST_TEMP_PATH_FAILURE_VFS_CSTR.as_ptr();
            vfs.xOpen = Some(test_temp_path_failure_vfs_open);
            let vfs = Box::leak(Box::new(vfs));
            if ffi::sqlite3_vfs_register(vfs, 0) != ffi::SQLITE_OK {
                return Err(FileControlError);
            }
        }
        Ok(())
    })
}

#[cfg(feature = "test-vfs")]
unsafe extern "C" fn test_temp_path_failure_vfs_open(
    _vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: libc::c_int,
    out_flags: *mut libc::c_int,
) -> libc::c_int {
    // SQLite uses either a null filename or the empty string for the unnamed
    // `ATTACH ''` artifact behind ordinary `VACUUM`.
    if name.is_null() || unsafe { *name } == 0 {
        return ffi::SQLITE_IOERR_GETTEMPPATH;
    }
    // SAFETY: registration above preserves the original default VFS as the
    // process default.  SQLite provides the callback arguments for this
    // invocation, and the original xOpen accepts the same ABI and file size.
    let default_vfs = unsafe { ffi::sqlite3_vfs_find(std::ptr::null()) };
    if default_vfs.is_null() {
        return ffi::SQLITE_IOERR;
    }
    let Some(open) = (unsafe { (*default_vfs).xOpen }) else {
        return ffi::SQLITE_IOERR;
    };
    unsafe { open(default_vfs, name, file, flags, out_flags) }
}

/// The unix VFS prefix used by the bundled SQLite build on Linux.
///
/// SQLite deliberately exposes only an opaque `sqlite3_file`. The bundled Unix
/// VFS stores its descriptor after the VFS and inode pointers. This layout is
/// kept in this narrow crate so higher-level SDK crates never need raw
/// SQLite/VFS access.
#[cfg(target_os = "linux")]
#[repr(C)]
struct BundledUnixFilePrefix {
    _methods: *const c_void,
    _vfs: *mut c_void,
    _inode: *mut c_void,
    descriptor: libc::c_int,
}

/// Return whether SQLite's currently open main database file has moved.
///
/// This invokes the pinned SQLite `SQLITE_FCNTL_HAS_MOVED` file-control on the
/// `main` database.  A non-`SQLITE_OK` result, including an unavailable
/// opcode, is returned as [`FileControlError`] so callers can fail closed.
pub fn main_file_has_moved(connection: &Connection) -> Result<bool, FileControlError> {
    sqlite_file_has_moved(connection, c"main")
}

fn sqlite_file_has_moved(
    connection: &Connection,
    database: &CStr,
) -> Result<bool, FileControlError> {
    let mut moved = 0_i32;
    // SAFETY: `Connection::handle` is borrowed only for this synchronous
    // SQLite call; `database` is NUL-terminated and lives through the call;
    // `moved` is a writable `int` as required by SQLITE_FCNTL_HAS_MOVED.
    let result = unsafe {
        ffi::sqlite3_file_control(
            connection.handle(),
            database.as_ptr(),
            ffi::SQLITE_FCNTL_HAS_MOVED,
            (&mut moved as *mut i32).cast::<c_void>(),
        )
    };
    if result != ffi::SQLITE_OK {
        return Err(FileControlError);
    }
    Ok(moved != 0)
}

/// Duplicate the descriptor backing SQLite's currently open main database.
///
/// The returned descriptor is independent of its pathname and remains valid
/// after a rename. It fails closed on a moved file, an unavailable file-control
/// opcode, or a VFS other than the bundled Unix implementations.
#[cfg(target_os = "linux")]
pub fn main_file_descriptor(connection: &Connection) -> Result<std::fs::File, FileControlError> {
    duplicate_sqlite_file_descriptor(connection, c"main", ffi::SQLITE_FCNTL_FILE_POINTER)
}

/// Duplicate the descriptor backing one named SQLite database handle.
///
/// The database name is passed only to SQLite's file-control API; it is never
/// opened as a filesystem path.
#[cfg(target_os = "linux")]
pub fn database_file_descriptor(
    connection: &Connection,
    database: &str,
) -> Result<std::fs::File, FileControlError> {
    let database = CString::new(database).map_err(|_| FileControlError)?;
    duplicate_sqlite_file_descriptor(
        connection,
        database.as_c_str(),
        ffi::SQLITE_FCNTL_FILE_POINTER,
    )
}

/// Duplicate the descriptor backing SQLite's active WAL or rollback journal.
///
/// A WAL reader uses this to measure the bytes it actually pins. A missing
/// journal pointer is rejected rather than interpreted as zero bytes.
#[cfg(target_os = "linux")]
pub fn main_journal_descriptor(connection: &Connection) -> Result<std::fs::File, FileControlError> {
    duplicate_sqlite_file_descriptor(connection, c"main", ffi::SQLITE_FCNTL_JOURNAL_POINTER)
}

#[cfg(target_os = "linux")]
fn duplicate_sqlite_file_descriptor(
    connection: &Connection,
    database: &CStr,
    opcode: libc::c_int,
) -> Result<std::fs::File, FileControlError> {
    if sqlite_file_has_moved(connection, database)? {
        return Err(FileControlError);
    }
    let mut vfs_name: *mut libc::c_char = std::ptr::null_mut();
    // SAFETY: SQLite allocates `vfs_name` for this documented file-control
    // opcode. The pointer is freed with SQLite's allocator before return.
    let vfs_result = unsafe {
        ffi::sqlite3_file_control(
            connection.handle(),
            database.as_ptr(),
            ffi::SQLITE_FCNTL_VFSNAME,
            (&mut vfs_name as *mut *mut libc::c_char).cast::<c_void>(),
        )
    };
    if vfs_result != ffi::SQLITE_OK || vfs_name.is_null() {
        return Err(FileControlError);
    }
    // SAFETY: SQLite returned a NUL-terminated allocation for VFSNAME.
    let accepted_vfs = unsafe {
        matches!(
            CStr::from_ptr(vfs_name).to_bytes(),
            b"unix" | b"unix-excl" | b"unix-dotfile" | b"unix-none"
        )
    };
    // SAFETY: `vfs_name` is owned by SQLite per SQLITE_FCNTL_VFSNAME.
    unsafe { ffi::sqlite3_free(vfs_name.cast::<c_void>()) };
    if !accepted_vfs {
        return Err(FileControlError);
    }

    let mut sqlite_file: *mut c_void = std::ptr::null_mut();
    // SAFETY: SQLite writes the documented opaque `sqlite3_file*` into the
    // pointer. It remains borrowed only during this synchronous call chain.
    let result = unsafe {
        ffi::sqlite3_file_control(
            connection.handle(),
            database.as_ptr(),
            opcode,
            (&mut sqlite_file as *mut *mut c_void).cast::<c_void>(),
        )
    };
    if result != ffi::SQLITE_OK || sqlite_file.is_null() {
        return Err(FileControlError);
    }
    // SAFETY: the VFS name was admitted above and this workspace pins
    // rusqlite's bundled SQLite Unix VFS, whose prefix is declared above.
    let descriptor = unsafe {
        (sqlite_file.cast::<BundledUnixFilePrefix>())
            .as_ref()
            .ok_or(FileControlError)?
            .descriptor
    };
    if descriptor < 0 {
        return Err(FileControlError);
    }
    // SAFETY: `descriptor` belongs to SQLite; F_DUPFD_CLOEXEC returns a new
    // owned descriptor or -1, without changing SQLite's ownership.
    let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 || sqlite_file_has_moved(connection, database)? {
        if duplicate >= 0 {
            // SAFETY: this branch owns only the just-created duplicate.
            unsafe { libc::close(duplicate) };
        }
        return Err(FileControlError);
    }
    // SAFETY: the successful fcntl result is a unique owned descriptor.
    Ok(unsafe { std::fs::File::from_raw_fd(duplicate) })
}

#[cfg(not(target_os = "linux"))]
/// Descriptor pinning is not available on this platform.
pub fn main_file_descriptor(_connection: &Connection) -> Result<std::fs::File, FileControlError> {
    Err(FileControlError)
}

#[cfg(not(target_os = "linux"))]
/// Descriptor pinning is not available on this platform.
pub fn database_file_descriptor(
    _connection: &Connection,
    _database: &str,
) -> Result<std::fs::File, FileControlError> {
    Err(FileControlError)
}

#[cfg(not(target_os = "linux"))]
/// Descriptor pinning is not available on this platform.
pub fn main_journal_descriptor(
    _connection: &Connection,
) -> Result<std::fs::File, FileControlError> {
    Err(FileControlError)
}
