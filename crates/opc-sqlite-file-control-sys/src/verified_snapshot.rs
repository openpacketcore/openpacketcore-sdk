//! The ADR 0020 read-only snapshot VFS. Cryptographic verification belongs to
//! the safe source implementation; this module owns only SQLite's I/O ABI.

use std::collections::BTreeMap;
use std::ffi::{c_char, c_int, c_void, CStr};
use std::fs::File;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use rusqlite::{ffi, Connection};

use crate::FileControlError;

const VFS_NAME: &CStr = c"opc-verified-snapshot-v1";
const NAME_PREFIX: &str = "opc-verified-";
const MAX_REGISTRATIONS: usize = 256;
const MAX_READ_BYTES: usize = 2 * 1024 * 1024;
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// An owned, immutable logical byte image supplied to the read-only VFS.
///
/// A successful read must return bytes authenticated against one retained
/// image, never bytes from a newly observed generation. Implementations must
/// bound their allocations and reject integrity failures. No raw SQLite
/// handle or pointer crosses this safe interface.
pub trait VerifiedSnapshotSource: Send + Sync + 'static {
    /// The fixed logical image length.
    fn len(&self) -> u64;

    /// Whether the image is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Authenticate and copy exactly this range into the owned output buffer.
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> io::Result<()>;

    /// Recheck the held image's descriptor and generation fences.
    fn validate(&self) -> io::Result<()>;

    /// Duplicate the held descriptor for identity inspection, not content I/O.
    fn duplicate_descriptor(&self) -> io::Result<File>;
}

type Registry = BTreeMap<u64, Weak<dyn VerifiedSnapshotSource>>;

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

struct Registration {
    id: u64,
    _source: Arc<dyn VerifiedSnapshotSource>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Ok(mut entries) = registry().lock() {
            entries.remove(&self.id);
        }
    }
}

/// An explicitly selected, process-local read-only snapshot registration.
///
/// Clones retain the same registration. Dropping its last owner forbids new
/// opens; SQLite handles that were already opened retain their own source.
/// This VFS never becomes the process default and never opens an OS pathname.
#[derive(Clone)]
pub struct RegisteredSnapshot(Arc<Registration>);

impl RegisteredSnapshot {
    /// Register one already authenticated source behind an opaque SQLite URI.
    pub fn new(source: Arc<dyn VerifiedSnapshotSource>) -> Result<Self, FileControlError> {
        source.validate().map_err(|_| FileControlError)?;
        if source.is_empty() || source.len() > i64::MAX as u64 {
            return Err(FileControlError);
        }
        install_vfs()?;
        let id = NEXT_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .map_err(|_| FileControlError)?;
        let mut entries = registry().lock().map_err(|_| FileControlError)?;
        if entries.len() >= MAX_REGISTRATIONS {
            return Err(FileControlError);
        }
        entries.insert(id, Arc::downgrade(&source));
        Ok(Self(Arc::new(Registration {
            id,
            _source: source,
        })))
    }

    /// The opaque, read-only SQLite URI for this retained image.
    pub fn uri(&self) -> String {
        format!(
            "file:{NAME_PREFIX}{:016x}?mode=ro&immutable=1&cache=private&vfs=opc-verified-snapshot-v1",
            self.0.id
        )
    }
}

#[repr(C)]
struct SnapshotFile {
    base: ffi::sqlite3_file,
    source: *mut Arc<dyn VerifiedSnapshotSource>,
}

fn install_vfs() -> Result<(), FileControlError> {
    static INSTALLED: OnceLock<Result<(), FileControlError>> = OnceLock::new();
    *INSTALLED.get_or_init(|| {
        // SAFETY: SQLite owns its default VFS for the process lifetime. Copy
        // its platform services, replace every filesystem operation, and leak
        // the non-default registration for SQLite's documented VFS lifetime.
        unsafe {
            let default_vfs = ffi::sqlite3_vfs_find(std::ptr::null());
            if default_vfs.is_null() {
                return Err(FileControlError);
            }
            let mut vfs = *default_vfs;
            vfs.szOsFile = c_int::try_from(std::mem::size_of::<SnapshotFile>())
                .map_err(|_| FileControlError)?;
            vfs.mxPathname = 96;
            vfs.zName = VFS_NAME.as_ptr();
            vfs.xOpen = Some(open);
            vfs.xDelete = Some(delete);
            vfs.xAccess = Some(access);
            vfs.xFullPathname = Some(full_pathname);
            let vfs = Box::leak(Box::new(vfs));
            if ffi::sqlite3_vfs_register(vfs, 0) != ffi::SQLITE_OK {
                return Err(FileControlError);
            }
        }
        Ok(())
    })
}

fn callback(body: impl FnOnce() -> c_int) -> c_int {
    // Safe source implementations cannot unwind through SQLite's C frames.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)).unwrap_or(ffi::SQLITE_IOERR)
}

fn identifier(name: &CStr) -> Option<u64> {
    let text = name.to_str().ok()?;
    let suffix = text.strip_prefix(NAME_PREFIX)?;
    if suffix.len() != 16
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    u64::from_str_radix(suffix, 16).ok()
}

// SAFETY: SQLite supplies an allocation of this VFS's szOsFile and a valid
// optional NUL-terminated filename, as specified by sqlite3_vfs::xOpen.
unsafe extern "C" fn open(
    _vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    callback(|| {
        if file.is_null() {
            return ffi::SQLITE_CANTOPEN;
        }
        // SAFETY: xOpen owns the VFS-sized, not-yet-initialized allocation.
        // Null methods prohibit SQLite from calling xClose after a failure.
        unsafe { (*file).pMethods = std::ptr::null() };
        if name.is_null()
            || flags & ffi::SQLITE_OPEN_MAIN_DB == 0
            || flags & ffi::SQLITE_OPEN_READONLY == 0
            || flags
                & (ffi::SQLITE_OPEN_READWRITE
                    | ffi::SQLITE_OPEN_CREATE
                    | ffi::SQLITE_OPEN_DELETEONCLOSE
                    | ffi::SQLITE_OPEN_MEMORY
                    | ffi::SQLITE_OPEN_TEMP_DB
                    | ffi::SQLITE_OPEN_TRANSIENT_DB
                    | ffi::SQLITE_OPEN_MAIN_JOURNAL
                    | ffi::SQLITE_OPEN_TEMP_JOURNAL
                    | ffi::SQLITE_OPEN_SUBJOURNAL
                    | ffi::SQLITE_OPEN_SUPER_JOURNAL
                    | ffi::SQLITE_OPEN_WAL)
                != 0
        {
            return ffi::SQLITE_CANTOPEN;
        }
        // SAFETY: SQLite guarantees this non-null filename is NUL-terminated.
        let Some(id) = identifier(unsafe { CStr::from_ptr(name) }) else {
            return ffi::SQLITE_CANTOPEN;
        };
        let source = match registry().lock() {
            Ok(entries) => entries.get(&id).and_then(Weak::upgrade),
            Err(_) => None,
        };
        let Some(source) = source else {
            return ffi::SQLITE_CANTOPEN;
        };
        if source.validate().is_err() {
            return ffi::SQLITE_IOERR;
        }
        let source = Box::into_raw(Box::new(source));
        // SAFETY: the allocation has SnapshotFile's registered size and
        // alignment. xClose takes ownership of this one boxed Arc exactly
        // once. pMethods is installed only after all fallible setup succeeds.
        unsafe {
            file.cast::<SnapshotFile>().write(SnapshotFile {
                base: ffi::sqlite3_file { pMethods: &METHODS },
                source,
            });
            if !out_flags.is_null() {
                *out_flags = ffi::SQLITE_OPEN_READONLY;
            }
        }
        ffi::SQLITE_OK
    })
}

// SAFETY: caller retains a live SQLite file throughout the returned borrow;
// method-table identity is checked before interpreting our private layout.
unsafe fn source<'a>(file: *mut ffi::sqlite3_file) -> Option<&'a Arc<dyn VerifiedSnapshotSource>> {
    if file.is_null() {
        return None;
    }
    // SAFETY: a live sqlite3_file always contains its readable base header.
    if unsafe { (*file).pMethods } != &METHODS {
        return None;
    }
    // SAFETY: only our xOpen installs METHODS, and it initialized this layout.
    let owned = unsafe { (*file.cast::<SnapshotFile>()).source };
    // SAFETY: xOpen owns the boxed Arc until xClose, which is not concurrent.
    unsafe { owned.as_ref() }
}

// SAFETY: SQLite calls xClose once for a file initialized by this VFS.
unsafe extern "C" fn close(file: *mut ffi::sqlite3_file) -> c_int {
    callback(|| {
        // SAFETY: this synchronous callback retains the live file allocation.
        if unsafe { source(file) }.is_none() {
            return ffi::SQLITE_IOERR_CLOSE;
        }
        // SAFETY: source() admitted our layout and xClose exclusively owns
        // the boxed Arc. Clear the fields before dropping the source.
        unsafe {
            let snapshot = &mut *file.cast::<SnapshotFile>();
            let owned = snapshot.source;
            snapshot.source = std::ptr::null_mut();
            snapshot.base.pMethods = std::ptr::null();
            drop(Box::from_raw(owned));
        }
        ffi::SQLITE_OK
    })
}

// SAFETY: SQLite supplies a writable amount-byte output allocation and a
// live file. Negative or oversized amounts and offsets are rejected first.
unsafe extern "C" fn read(
    file: *mut ffi::sqlite3_file,
    output: *mut c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    callback(|| {
        let (Ok(amount), Ok(offset)) = (usize::try_from(amount), u64::try_from(offset)) else {
            return ffi::SQLITE_IOERR_READ;
        };
        if amount > MAX_READ_BYTES || (output.is_null() && amount != 0) {
            return ffi::SQLITE_IOERR_READ;
        }
        if amount == 0 {
            return ffi::SQLITE_OK;
        }
        // SAFETY: amount is bounded and SQLite owns this writable allocation.
        let output = unsafe { std::slice::from_raw_parts_mut(output.cast::<u8>(), amount) };
        output.fill(0);
        // SAFETY: SQLite retains this live file for the callback duration.
        let Some(source) = (unsafe { source(file) }) else {
            return ffi::SQLITE_IOERR_READ;
        };
        if source.validate().is_err() {
            return ffi::SQLITE_IOERR_READ;
        }
        let available = usize::try_from(source.len().saturating_sub(offset))
            .unwrap_or(usize::MAX)
            .min(amount);
        let result = callback(|| {
            if available != 0
                && source
                    .read_exact_at(offset, &mut output[..available])
                    .is_err()
            {
                ffi::SQLITE_IOERR_READ
            } else {
                ffi::SQLITE_OK
            }
        });
        if result != ffi::SQLITE_OK {
            output.fill(0);
            return ffi::SQLITE_IOERR_READ;
        }
        if available != amount {
            ffi::SQLITE_IOERR_SHORT_READ
        } else {
            ffi::SQLITE_OK
        }
    })
}

// SAFETY: no argument is dereferenced; writes are never admitted.
unsafe extern "C" fn write(
    _file: *mut ffi::sqlite3_file,
    _input: *const c_void,
    _amount: c_int,
    _offset: i64,
) -> c_int {
    ffi::SQLITE_READONLY
}

// SAFETY: no argument is dereferenced; truncation is never admitted.
unsafe extern "C" fn truncate(_file: *mut ffi::sqlite3_file, _size: i64) -> c_int {
    ffi::SQLITE_READONLY
}

// SAFETY: no argument is dereferenced; a read-only image cannot require sync.
unsafe extern "C" fn sync(_file: *mut ffi::sqlite3_file, _flags: c_int) -> c_int {
    ffi::SQLITE_READONLY
}

// SAFETY: SQLite supplies a writable sqlite3_int64 output and a live file.
unsafe extern "C" fn file_size(file: *mut ffi::sqlite3_file, size: *mut i64) -> c_int {
    callback(|| {
        if size.is_null() {
            return ffi::SQLITE_IOERR_FSTAT;
        }
        // SAFETY: SQLite retains the file throughout this synchronous call.
        let Some(source) = (unsafe { source(file) }) else {
            return ffi::SQLITE_IOERR_FSTAT;
        };
        let Ok(length) = i64::try_from(source.len()) else {
            return ffi::SQLITE_IOERR_FSTAT;
        };
        if source.validate().is_err() {
            return ffi::SQLITE_IOERR_FSTAT;
        }
        // SAFETY: SQLite supplied the correctly typed writable output slot.
        unsafe { *size = length };
        ffi::SQLITE_OK
    })
}

// SAFETY: no argument is dereferenced. Only read locks are meaningful here.
unsafe extern "C" fn lock(_file: *mut ffi::sqlite3_file, level: c_int) -> c_int {
    if matches!(level, ffi::SQLITE_LOCK_NONE | ffi::SQLITE_LOCK_SHARED) {
        ffi::SQLITE_OK
    } else {
        ffi::SQLITE_READONLY
    }
}

// SAFETY: SQLite supplies a writable int output; this VFS has no writers.
unsafe extern "C" fn reserved_lock(_file: *mut ffi::sqlite3_file, output: *mut c_int) -> c_int {
    if output.is_null() {
        return ffi::SQLITE_IOERR_CHECKRESERVEDLOCK;
    }
    // SAFETY: output is the callback's documented writable int slot.
    unsafe { *output = 0 };
    ffi::SQLITE_OK
}

// SAFETY: SQLite supplies opcode-specific output slots. Only the existing
// allowlisted HAS_MOVED control is handled; unknown controls return NOTFOUND.
unsafe extern "C" fn file_control(
    file: *mut ffi::sqlite3_file,
    opcode: c_int,
    argument: *mut c_void,
) -> c_int {
    callback(|| {
        if opcode != ffi::SQLITE_FCNTL_HAS_MOVED {
            return ffi::SQLITE_NOTFOUND;
        }
        if argument.is_null() {
            return ffi::SQLITE_IOERR;
        }
        // SAFETY: SQLite retains the live file during this callback.
        let moved = unsafe { source(file) }.is_none_or(|source| source.validate().is_err());
        // SAFETY: HAS_MOVED's argument is documented as a writable int.
        unsafe { *argument.cast::<c_int>() = c_int::from(moved) };
        ffi::SQLITE_OK
    })
}

// SAFETY: no argument is dereferenced; snapshots are read-only.
unsafe extern "C" fn sector_size(_file: *mut ffi::sqlite3_file) -> c_int {
    4096
}

// SAFETY: no argument is dereferenced. Logical bytes are fixed by the retained
// authenticated source; corruption returns I/O failure, never changed bytes.
unsafe extern "C" fn characteristics(_file: *mut ffi::sqlite3_file) -> c_int {
    ffi::SQLITE_IOCAP_IMMUTABLE
}

// Version 1 deliberately has no shared-memory or mmap callbacks. Every byte
// must pass through xRead; SQLite cannot obtain an unchecked mapped pointer.
static METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 1,
    xClose: Some(close),
    xRead: Some(read),
    xWrite: Some(write),
    xTruncate: Some(truncate),
    xSync: Some(sync),
    xFileSize: Some(file_size),
    xLock: Some(lock),
    xUnlock: Some(lock),
    xCheckReservedLock: Some(reserved_lock),
    xFileControl: Some(file_control),
    xSectorSize: Some(sector_size),
    xDeviceCharacteristics: Some(characteristics),
    xShmMap: None,
    xShmLock: None,
    xShmBarrier: None,
    xShmUnmap: None,
    xFetch: None,
    xUnfetch: None,
};

// SAFETY: no argument is dereferenced; this VFS never deletes filesystem data.
unsafe extern "C" fn delete(
    _vfs: *mut ffi::sqlite3_vfs,
    _name: *const c_char,
    _sync_directory: c_int,
) -> c_int {
    ffi::SQLITE_READONLY
}

// SAFETY: SQLite supplies a valid optional filename and writable int output.
unsafe extern "C" fn access(
    _vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    flags: c_int,
    output: *mut c_int,
) -> c_int {
    callback(|| {
        if output.is_null() {
            return ffi::SQLITE_IOERR_ACCESS;
        }
        let present = if name.is_null() || flags == ffi::SQLITE_ACCESS_READWRITE {
            false
        } else {
            // SAFETY: SQLite supplies a valid NUL-terminated filename.
            let id = identifier(unsafe { CStr::from_ptr(name) });
            match (id, registry().lock()) {
                (Some(id), Ok(entries)) => entries.get(&id).and_then(Weak::upgrade).is_some(),
                _ => false,
            }
        };
        // SAFETY: output is the callback's documented writable int slot.
        unsafe { *output = c_int::from(present) };
        ffi::SQLITE_OK
    })
}

// SAFETY: SQLite supplies a NUL-terminated input and an output allocation of
// output_bytes bytes. This callback copies only a validated opaque token.
unsafe extern "C" fn full_pathname(
    _vfs: *mut ffi::sqlite3_vfs,
    name: *const c_char,
    output_bytes: c_int,
    output: *mut c_char,
) -> c_int {
    callback(|| {
        if name.is_null() || output.is_null() || output_bytes <= 0 {
            return ffi::SQLITE_CANTOPEN;
        }
        // SAFETY: the callback input is a valid NUL-terminated filename.
        let name = unsafe { CStr::from_ptr(name) };
        if identifier(name).is_none() || name.to_bytes_with_nul().len() > output_bytes as usize {
            return ffi::SQLITE_CANTOPEN;
        }
        // SAFETY: bounds were checked, the input/output allocations are
        // distinct per xFullPathname's ABI, and the copied bytes include NUL.
        unsafe {
            std::ptr::copy_nonoverlapping(name.as_ptr(), output, name.to_bytes_with_nul().len());
        }
        ffi::SQLITE_OK
    })
}

pub(super) fn duplicate_descriptor(
    connection: &Connection,
    database: &CStr,
) -> Result<Option<File>, FileControlError> {
    let mut file: *mut ffi::sqlite3_file = std::ptr::null_mut();
    // SAFETY: the connection and database name live through this synchronous
    // file-control call; SQLite writes its borrowed file pointer into file.
    let result = unsafe {
        ffi::sqlite3_file_control(
            connection.handle(),
            database.as_ptr(),
            ffi::SQLITE_FCNTL_FILE_POINTER,
            (&mut file as *mut *mut ffi::sqlite3_file).cast::<c_void>(),
        )
    };
    if result != ffi::SQLITE_OK || file.is_null() {
        return Err(FileControlError);
    }
    // SAFETY: the connection retains this file; source() checks method-table
    // identity before touching the private snapshot layout.
    let Some(source) = (unsafe { source(file) }) else {
        return Ok(None);
    };
    source.validate().map_err(|_| FileControlError)?;
    let descriptor = source
        .duplicate_descriptor()
        .map_err(|_| FileControlError)?;
    source.validate().map_err(|_| FileControlError)?;
    Ok(Some(descriptor))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU8;

    struct TestSource {
        fault: AtomicU8,
    }

    impl VerifiedSnapshotSource for TestSource {
        fn len(&self) -> u64 {
            4
        }
        fn validate(&self) -> io::Result<()> {
            Ok(())
        }
        fn duplicate_descriptor(&self) -> io::Result<File> {
            File::open("/dev/null")
        }
        fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
            for (index, byte) in output.iter_mut().enumerate() {
                *byte = (offset as usize + index + 1) as u8;
            }
            match self.fault.load(Ordering::Acquire) {
                1 => Err(io::Error::other("injected read failure")),
                2 => panic!("injected source panic"),
                _ => Ok(()),
            }
        }
    }

    fn empty_file() -> SnapshotFile {
        SnapshotFile {
            base: ffi::sqlite3_file {
                pMethods: std::ptr::null(),
            },
            source: std::ptr::null_mut(),
        }
    }

    #[test]
    fn verified_vfs_zeroes_short_reads_errors_and_panics() {
        let source = Arc::new(TestSource {
            fault: AtomicU8::new(0),
        });
        let registration = RegisteredSnapshot::new(source.clone()).expect("register source");
        let name = std::ffi::CString::new(format!("{NAME_PREFIX}{:016x}", registration.0.id))
            .expect("opaque name");
        let mut file = empty_file();
        let mut output = [0xa5_u8; 6];
        // SAFETY: each callback gets a correctly sized, live allocation and
        // the matching output extent; xOpen initializes the sole owned Arc.
        unsafe {
            assert_eq!(
                ffi::SQLITE_OK,
                open(
                    std::ptr::null_mut(),
                    name.as_ptr(),
                    &mut file.base,
                    ffi::SQLITE_OPEN_READONLY | ffi::SQLITE_OPEN_MAIN_DB,
                    std::ptr::null_mut()
                )
            );
            assert_eq!(
                ffi::SQLITE_IOERR_SHORT_READ,
                read(&mut file.base, output.as_mut_ptr().cast(), 6, 2)
            );
            assert_eq!([3, 4, 0, 0, 0, 0], output);
            output.fill(0xa5);
            assert_eq!(
                ffi::SQLITE_IOERR_SHORT_READ,
                read(&mut file.base, output.as_mut_ptr().cast(), 6, 9)
            );
            assert_eq!([0; 6], output);
            for fault in [1, 2] {
                source.fault.store(fault, Ordering::Release);
                output.fill(0xa5);
                assert_eq!(
                    ffi::SQLITE_IOERR_READ,
                    read(&mut file.base, output.as_mut_ptr().cast(), 4, 0)
                );
                assert_eq!([0, 0, 0, 0, 0xa5, 0xa5], output);
            }
            assert_eq!(
                ffi::SQLITE_READONLY,
                write(&mut file.base, std::ptr::null(), 0, 0)
            );
            assert_eq!(ffi::SQLITE_READONLY, truncate(&mut file.base, 0));
            assert_eq!(
                ffi::SQLITE_READONLY,
                lock(&mut file.base, ffi::SQLITE_LOCK_EXCLUSIVE)
            );
            assert_eq!(
                ffi::SQLITE_NOTFOUND,
                file_control(
                    &mut file.base,
                    ffi::SQLITE_FCNTL_MMAP_SIZE,
                    std::ptr::null_mut()
                )
            );
            assert_eq!(ffi::SQLITE_OK, close(&mut file.base));
        }
        assert!(file.base.pMethods.is_null());
    }

    #[test]
    fn registration_drop_forbids_new_opens_but_preserves_live_file() {
        let source: Arc<dyn VerifiedSnapshotSource> = Arc::new(TestSource {
            fault: AtomicU8::new(0),
        });
        let weak = Arc::downgrade(&source);
        let registration = RegisteredSnapshot::new(source).expect("register source");
        let name = std::ffi::CString::new(format!("{NAME_PREFIX}{:016x}", registration.0.id))
            .expect("opaque name");
        let mut file = empty_file();
        let mut refused = empty_file();
        // SAFETY: all callback allocations have the registered layout and
        // remain live; only a successfully opened handle is closed.
        unsafe {
            assert_eq!(
                ffi::SQLITE_CANTOPEN,
                open(
                    std::ptr::null_mut(),
                    name.as_ptr(),
                    &mut refused.base,
                    ffi::SQLITE_OPEN_READONLY | ffi::SQLITE_OPEN_MAIN_DB | ffi::SQLITE_OPEN_WAL,
                    std::ptr::null_mut()
                )
            );
            assert!(refused.base.pMethods.is_null());
            assert_eq!(
                ffi::SQLITE_OK,
                open(
                    std::ptr::null_mut(),
                    name.as_ptr(),
                    &mut file.base,
                    ffi::SQLITE_OPEN_READONLY | ffi::SQLITE_OPEN_MAIN_DB,
                    std::ptr::null_mut()
                )
            );
            drop(registration);
            assert_eq!(
                ffi::SQLITE_CANTOPEN,
                open(
                    std::ptr::null_mut(),
                    name.as_ptr(),
                    &mut refused.base,
                    ffi::SQLITE_OPEN_READONLY | ffi::SQLITE_OPEN_MAIN_DB,
                    std::ptr::null_mut()
                )
            );
            let mut output = [0_u8; 4];
            assert_eq!(
                ffi::SQLITE_OK,
                read(&mut file.base, output.as_mut_ptr().cast(), 4, 0)
            );
            assert_eq!([1, 2, 3, 4], output);
            assert!(weak.upgrade().is_some());
            assert_eq!(ffi::SQLITE_OK, close(&mut file.base));
        }
        assert!(
            weak.upgrade().is_none(),
            "last SQLite close releases the source"
        );
    }

    #[test]
    fn sqlite_file_layout_and_read_bypass_contract() {
        assert_eq!(0, std::mem::offset_of!(SnapshotFile, base));
        assert_eq!(
            std::mem::size_of::<ffi::sqlite3_file>(),
            std::mem::offset_of!(SnapshotFile, source)
        );
        assert_eq!(
            std::mem::align_of::<ffi::sqlite3_file>(),
            std::mem::align_of::<SnapshotFile>()
        );
        assert_eq!(1, METHODS.iVersion);
        assert!(METHODS.xFetch.is_none());
        assert!(METHODS.xShmMap.is_none());
    }

    #[test]
    fn registration_name_is_not_a_path() {
        assert_eq!(Some(1), identifier(c"opc-verified-0000000000000001"));
        for rejected in [
            c"/tmp/snapshot.sqlite",
            c"opc-verified-0000000000000001-journal",
            c"opc-verified-000000000000000A",
            c"opc-verified-1",
        ] {
            assert_eq!(None, identifier(rejected));
        }
    }
}
