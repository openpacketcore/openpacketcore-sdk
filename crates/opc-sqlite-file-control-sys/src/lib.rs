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

#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::ffi::{c_void, CStr};
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd as _;
#[cfg(feature = "test-vfs")]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(feature = "test-vfs")]
use std::sync::{Condvar, Mutex, OnceLock};
#[cfg(feature = "test-vfs")]
use std::time::Duration;

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

/// The test-only VFS that pauses only main-database `xSync` callbacks.
///
/// A caller must select this VFS explicitly through a SQLite URI. WAL-file
/// syncs continue to delegate immediately, which makes the hook suitable for
/// proving whether an automatic checkpoint has entered a transaction's commit
/// path without weakening or bypassing the WAL commit durability path.
#[cfg(feature = "test-vfs")]
pub const TEST_MAIN_SYNC_BLOCK_VFS_NAME: &str = "opc-test-block-main-sync-vfs";

#[cfg(feature = "test-vfs")]
const TEST_TEMP_PATH_FAILURE_VFS_CSTR: &CStr = c"opc-test-fail-temp-vfs";

#[cfg(feature = "test-vfs")]
const TEST_MAIN_SYNC_BLOCK_VFS_CSTR: &CStr = c"opc-test-block-main-sync-vfs";

#[cfg(feature = "test-vfs")]
const TEST_SYNC_FILE_MAIN: u8 = 1;
#[cfg(feature = "test-vfs")]
const TEST_SYNC_FILE_WAL: u8 = 2;
#[cfg(feature = "test-vfs")]
const TEST_SYNC_FILE_OTHER: u8 = 3;

#[cfg(feature = "test-vfs")]
struct MainSyncBlockState {
    armed: AtomicBool,
    claimed: AtomicBool,
    fail_held_main_sync: AtomicBool,
    main_syncs: AtomicUsize,
    wal_syncs: AtomicUsize,
    gate: Mutex<bool>,
    observed: Condvar,
}

#[cfg(feature = "test-vfs")]
impl MainSyncBlockState {
    fn reset_and_arm(&self) {
        self.claimed.store(false, Ordering::Release);
        self.fail_held_main_sync.store(false, Ordering::Release);
        self.main_syncs.store(0, Ordering::Release);
        self.wal_syncs.store(0, Ordering::Release);
        let mut observed = self.gate.lock().expect("test VFS gate mutex");
        *observed = false;
        self.armed.store(true, Ordering::Release);
    }

    fn release(&self, fail_held_main_sync: bool) {
        self.fail_held_main_sync
            .store(fail_held_main_sync, Ordering::Release);
        self.armed.store(false, Ordering::Release);
        self.observed.notify_all();
    }
}

#[cfg(feature = "test-vfs")]
fn main_sync_block_state() -> &'static MainSyncBlockState {
    static STATE: OnceLock<MainSyncBlockState> = OnceLock::new();
    STATE.get_or_init(|| MainSyncBlockState {
        armed: AtomicBool::new(false),
        claimed: AtomicBool::new(false),
        fail_held_main_sync: AtomicBool::new(false),
        main_syncs: AtomicUsize::new(0),
        wal_syncs: AtomicUsize::new(0),
        gate: Mutex::new(false),
        observed: Condvar::new(),
    })
}

/// One armed pause of a test VFS main-database `xSync` callback.
///
/// Dropping this guard releases the VFS callback so a failing test cannot leave
/// a SQLite worker blocked.
#[cfg(feature = "test-vfs")]
pub struct TestMainSyncBlock {
    released: bool,
}

#[cfg(feature = "test-vfs")]
impl TestMainSyncBlock {
    /// Wait until the selected VFS has entered a main-database `xSync`.
    pub fn wait_until_main_sync(&self, timeout: Duration) -> bool {
        let state = main_sync_block_state();
        let observed = state.gate.lock().expect("test VFS gate mutex");
        let (observed, _) = state
            .observed
            .wait_timeout_while(observed, timeout, |observed| !*observed)
            .expect("test VFS gate mutex");
        *observed
    }

    /// Release the paused main-database sync callback.
    pub fn release(&mut self) {
        if !self.released {
            main_sync_block_state().release(false);
            self.released = true;
        }
    }

    /// Release the held main-database sync as a one-shot SQLite I/O failure.
    ///
    /// This is deliberately attached to the callback already observed by
    /// [`Self::wait_until_main_sync`], so it unambiguously exercises the
    /// selected checkpoint worker rather than a later writer operation.
    pub fn fail_and_release(&mut self) {
        if !self.released {
            main_sync_block_state().release(true);
            self.released = true;
        }
    }

    /// Return the number of main-database sync callbacks since arming.
    pub fn main_sync_count(&self) -> usize {
        main_sync_block_state().main_syncs.load(Ordering::Acquire)
    }

    /// Return the number of WAL-file sync callbacks since arming.
    pub fn wal_sync_count(&self) -> usize {
        main_sync_block_state().wal_syncs.load(Ordering::Acquire)
    }
}

#[cfg(feature = "test-vfs")]
impl Drop for TestMainSyncBlock {
    fn drop(&mut self) {
        self.release();
    }
}

/// Arm the selected test VFS to pause the next main-database sync callback.
///
/// The VFS must have been registered with
/// [`install_test_main_sync_block_vfs`] and selected explicitly by the SQLite
/// connection under test. WAL-file sync callbacks are counted but never paused.
#[cfg(feature = "test-vfs")]
pub fn block_test_main_sync() -> TestMainSyncBlock {
    main_sync_block_state().reset_and_arm();
    TestMainSyncBlock { released: false }
}

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
#[derive(Clone, Copy)]
struct MainSyncBlockVfsLayout {
    default_vfs: usize,
    metadata_offset: usize,
}

#[cfg(feature = "test-vfs")]
#[repr(C)]
struct MainSyncBlockFileState {
    original_methods: *const ffi::sqlite3_io_methods,
    methods: ffi::sqlite3_io_methods,
    file_kind: u8,
}

#[cfg(feature = "test-vfs")]
fn main_sync_block_vfs_layout() -> Result<MainSyncBlockVfsLayout, FileControlError> {
    static REGISTER: OnceLock<Result<MainSyncBlockVfsLayout, FileControlError>> = OnceLock::new();
    *REGISTER.get_or_init(|| {
        // SAFETY: SQLite owns the default VFS pointer for the process. We copy
        // its callback table, increase its private file storage by one
        // metadata record, and replace only xOpen. The registration is
        // non-default and leaked for SQLite's required VFS lifetime.
        unsafe {
            let default_vfs = ffi::sqlite3_vfs_find(std::ptr::null());
            if default_vfs.is_null() || (*default_vfs).szOsFile < 0 {
                return Err(FileControlError);
            }
            let original_file_bytes =
                usize::try_from((*default_vfs).szOsFile).map_err(|_| FileControlError)?;
            let metadata_alignment = std::mem::align_of::<MainSyncBlockFileState>();
            let metadata_offset = original_file_bytes
                .checked_add(metadata_alignment.saturating_sub(1))
                .ok_or(FileControlError)?
                / metadata_alignment
                * metadata_alignment;
            let file_bytes = metadata_offset
                .checked_add(std::mem::size_of::<MainSyncBlockFileState>())
                .ok_or(FileControlError)?;
            let file_bytes = i32::try_from(file_bytes).map_err(|_| FileControlError)?;
            let mut vfs = *default_vfs;
            vfs.zName = TEST_MAIN_SYNC_BLOCK_VFS_CSTR.as_ptr();
            vfs.szOsFile = file_bytes;
            vfs.xOpen = Some(test_main_sync_block_vfs_open);
            let vfs = Box::leak(Box::new(vfs));
            if ffi::sqlite3_vfs_register(vfs, 0) != ffi::SQLITE_OK {
                return Err(FileControlError);
            }
            Ok(MainSyncBlockVfsLayout {
                default_vfs: default_vfs.cast::<c_void>() as usize,
                metadata_offset,
            })
        }
    })
}

/// Register a test-only VFS that waits at main-database `xSync` callbacks.
///
/// It delegates every SQLite operation to the bundled default VFS. The VFS is
/// never made process-default; a test must opt in with
/// [`TEST_MAIN_SYNC_BLOCK_VFS_NAME`] in the database URI.
#[cfg(feature = "test-vfs")]
pub fn install_test_main_sync_block_vfs() -> Result<(), FileControlError> {
    let _ = main_sync_block_vfs_layout()?;
    Ok(())
}

#[cfg(feature = "test-vfs")]
unsafe fn main_sync_block_file_metadata(
    file: *mut ffi::sqlite3_file,
) -> Result<*mut MainSyncBlockFileState, FileControlError> {
    let layout = main_sync_block_vfs_layout()?;
    if file.is_null() {
        return Err(FileControlError);
    }
    // SAFETY: the registered VFS reserved the original VFS file storage plus
    // this aligned state record for every SQLite file handle. SQLite passes
    // the same base pointer that xOpen initialized for all I/O callbacks.
    Ok(unsafe {
        file.cast::<u8>()
            .add(layout.metadata_offset)
            .cast::<MainSyncBlockFileState>()
    })
}

#[cfg(feature = "test-vfs")]
// SAFETY: SQLite calls this callback with arguments matching `sqlite3_vfs::xOpen`.
unsafe extern "C" fn test_main_sync_block_vfs_open(
    _vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: libc::c_int,
    out_flags: *mut libc::c_int,
) -> libc::c_int {
    let Ok(layout) = main_sync_block_vfs_layout() else {
        return ffi::SQLITE_IOERR;
    };
    let default_vfs = layout.default_vfs as *mut ffi::sqlite3_vfs;
    if default_vfs.is_null() {
        return ffi::SQLITE_IOERR;
    }
    // SAFETY: registration stored the original default VFS pointer, which
    // remains valid for the process lifetime. SQLite supplied ABI-compatible
    // arguments and the wrapper reserved at least the original VFS file size.
    let Some(open) = (unsafe { (*default_vfs).xOpen }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: the original xOpen accepts the original VFS and the callback's
    // unchanged SQLite-provided arguments.
    let result = unsafe { open(default_vfs, name, file, flags, out_flags) };
    if result != ffi::SQLITE_OK || file.is_null() {
        return result;
    }
    // SAFETY: successful xOpen initializes the sqlite3_file method table; the
    // metadata location is inside the additional VFS-owned storage reserved
    // above and has suitable alignment.
    let original_methods = unsafe { (*file).pMethods };
    if original_methods.is_null() {
        return ffi::SQLITE_IOERR;
    }
    let file_kind = if flags & ffi::SQLITE_OPEN_MAIN_DB != 0 {
        TEST_SYNC_FILE_MAIN
    } else if flags & ffi::SQLITE_OPEN_WAL != 0 {
        TEST_SYNC_FILE_WAL
    } else {
        TEST_SYNC_FILE_OTHER
    };
    let metadata = match unsafe { main_sync_block_file_metadata(file) } {
        Ok(metadata) => metadata,
        Err(_) => return ffi::SQLITE_IOERR,
    };
    // SAFETY: metadata points to uninitialized VFS-reserved bytes and this is
    // its one initialization before SQLite can invoke I/O callbacks. The
    // copied method table lives in that same per-file storage until xClose,
    // so the replacement xSync cannot outlive its table or allocate a
    // process-lifetime table for every opened SQLite file.
    unsafe {
        let mut methods = *original_methods;
        methods.xSync = Some(test_main_sync_block_vfs_sync);
        std::ptr::write(
            metadata,
            MainSyncBlockFileState {
                original_methods,
                methods,
                file_kind,
            },
        );
        (*file).pMethods = std::ptr::addr_of!((*metadata).methods);
    }
    result
}

#[cfg(feature = "test-vfs")]
// SAFETY: SQLite calls this callback with the file handle initialized by xOpen.
unsafe extern "C" fn test_main_sync_block_vfs_sync(
    file: *mut ffi::sqlite3_file,
    flags: libc::c_int,
) -> libc::c_int {
    let Ok(metadata) = (unsafe { main_sync_block_file_metadata(file) }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: xOpen initialized this metadata before installing this xSync.
    let (original_methods, file_kind) =
        unsafe { ((*metadata).original_methods, (*metadata).file_kind) };
    if original_methods.is_null() {
        return ffi::SQLITE_IOERR;
    }
    let state = main_sync_block_state();
    match file_kind {
        TEST_SYNC_FILE_MAIN => {
            state.main_syncs.fetch_add(1, Ordering::AcqRel);
            // Holding exactly one callback makes a concurrent test prove the
            // worker boundary, rather than serializing every database handle
            // that happens to checkpoint while the gate is armed.
            if state.armed.load(Ordering::Acquire) && !state.claimed.swap(true, Ordering::AcqRel) {
                let mut observed = state.gate.lock().expect("test VFS gate mutex");
                *observed = true;
                state.observed.notify_all();
                while state.armed.load(Ordering::Acquire) {
                    observed = state.observed.wait(observed).expect("test VFS gate mutex");
                }
                if state.fail_held_main_sync.swap(false, Ordering::AcqRel) {
                    return ffi::SQLITE_IOERR;
                }
            }
        }
        TEST_SYNC_FILE_WAL => {
            state.wal_syncs.fetch_add(1, Ordering::AcqRel);
        }
        _ => {}
    }
    // SAFETY: xOpen retained the original table for this file and only replaced
    // xSync in the table SQLite dispatches through.
    let Some(sync) = (unsafe { (*original_methods).xSync }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: the original VFS xSync accepts this same SQLite-owned file
    // handle and flags unchanged.
    unsafe { sync(file, flags) }
}

#[cfg(feature = "test-vfs")]
// SAFETY: SQLite invokes this callback only after registration with its
// documented VFS callback ABI and supplies the callback arguments.
unsafe extern "C" fn test_temp_path_failure_vfs_open(
    _vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: libc::c_int,
    out_flags: *mut libc::c_int,
) -> libc::c_int {
    // SQLite uses either a null filename or the empty string for the unnamed
    // `ATTACH ''` artifact behind ordinary `VACUUM`.
    // SAFETY: SQLite passes either a null filename or a valid NUL-terminated
    // filename pointer to `xOpen`; after the null check, reading its first byte
    // distinguishes the empty `ATTACH ''` artifact behind ordinary `VACUUM`.
    if name.is_null() || unsafe { *name } == 0 {
        return ffi::SQLITE_IOERR_GETTEMPPATH;
    }
    // SAFETY: registration above preserves the original default VFS as the
    // process default.  SQLite provides the callback arguments for this
    // invocation, and the original xOpen accepts the same ABI and file size.
    // SAFETY: SQLite exposes the process default VFS pointer for the duration
    // of this callback invocation.
    let default_vfs = unsafe { ffi::sqlite3_vfs_find(std::ptr::null()) };
    if default_vfs.is_null() {
        return ffi::SQLITE_IOERR;
    }
    // SAFETY: SQLite owns the default VFS callback table for this callback
    // invocation, so its `xOpen` field may be read.
    let Some(open) = (unsafe { (*default_vfs).xOpen }) else {
        return ffi::SQLITE_IOERR;
    };
    // SAFETY: the default VFS callback table and `xOpen` function pointer are
    // valid for this invocation, and the arguments retain SQLite's ABI.
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
