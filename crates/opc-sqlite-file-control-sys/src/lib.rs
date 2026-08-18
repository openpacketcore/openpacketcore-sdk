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

use std::ffi::c_void;

use rusqlite::{ffi, Connection};

/// Failure from the SQLite main-file movement probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileControlError;

/// Return whether SQLite's currently open main database file has moved.
///
/// This invokes the pinned SQLite `SQLITE_FCNTL_HAS_MOVED` file-control on the
/// `main` database.  A non-`SQLITE_OK` result, including an unavailable
/// opcode, is returned as [`FileControlError`] so callers can fail closed.
pub fn main_file_has_moved(connection: &Connection) -> Result<bool, FileControlError> {
    let database = b"main\0";
    let mut moved = 0_i32;
    // SAFETY: `Connection::handle` is borrowed only for this synchronous
    // SQLite call; `database` is NUL-terminated and lives through the call;
    // `moved` is a writable `int` as required by SQLITE_FCNTL_HAS_MOVED.
    let result = unsafe {
        ffi::sqlite3_file_control(
            connection.handle(),
            database.as_ptr().cast(),
            ffi::SQLITE_FCNTL_HAS_MOVED,
            (&mut moved as *mut i32).cast::<c_void>(),
        )
    };
    if result != ffi::SQLITE_OK {
        return Err(FileControlError);
    }
    Ok(moved != 0)
}
