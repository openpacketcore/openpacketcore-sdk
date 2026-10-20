//! Join the pinned Unix VFS's deferred-close queue without reopening a name.
//!
//! This mirrors SQLite 3.53.2's `unixClose`/`setPendingFd` locking protocol.
//! `unixInodeInfo` uses the global STATIC_VFS1 mutex for list membership and
//! each inode's pLockMutex for nLock/pUnused. Always acquire them in that order.
//! A private, unqueried native connection keeps one list member alive, allowing
//! lookup of independently opened SQLite connections as well as SDK owners.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::ManuallyDrop;
use std::os::fd::IntoRawFd;
use std::ptr::{addr_of, addr_of_mut, NonNull};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use rusqlite::{ffi, Connection, OpenFlags};

use super::unavailable;
use crate::{with_borrowed_sqlite_descriptor, BundledUnixFilePrefix};

const SQLITE_UNIX_ABI: i32 = 3_053_002;

// These prefixes match unixFileId, unixInodeInfo and UnixUnusedFd in the
// bundled SQLite above. Its inode number is explicitly u64 even on i686.
// Optional platform fields occur after the list pointers; this module is Linux-only.
#[repr(C)]
struct UnixFileId {
    device: libc::dev_t,
    inode: u64,
}

#[repr(C)]
struct UnixInode {
    identity: UnixFileId,
    lock_mutex: *mut ffi::sqlite3_mutex,
    _shared: libc::c_int,
    locks: libc::c_int,
    _file_lock: u8,
    _process_lock: u8,
    unused: *mut UnusedFd,
    _references: libc::c_int,
    _shared_memory: *mut c_void,
    next: *mut Self,
    previous: *mut Self,
}

#[repr(C)]
struct UnusedFd {
    descriptor: libc::c_int,
    flags: libc::c_int,
    next: *mut Self,
}

struct Domain {
    // No API exposes or queries this connection. Its native inode reference
    // keeps anchor valid until the final reservation has retired its file.
    _connection: Mutex<Connection>,
    anchor: NonNull<UnixInode>,
    global: NonNull<ffi::sqlite3_mutex>,
}

// SAFETY: the owned Connection is Send and held behind a mutex. The native
// pointers remain live through it and are accessed only under SQLite's mutexes.
unsafe impl Send for Domain {}
// SAFETY: no connection access escapes; all shared native field access follows
// the global-then-inode locking protocol described above.
unsafe impl Sync for Domain {}

impl Domain {
    fn acquire() -> io::Result<Arc<Self>> {
        static DOMAIN: OnceLock<Mutex<Weak<Domain>>> = OnceLock::new();
        let mut shared = DOMAIN
            .get_or_init(Mutex::default)
            .lock()
            .map_err(|_| unavailable())?;
        if let Some(domain) = shared.upgrade() {
            return Ok(domain);
        }
        // SAFETY: this query has no pointer arguments or initialization side effects.
        let version = unsafe { ffi::sqlite3_libversion_number() };
        if version != SQLITE_UNIX_ABI || ffi::SQLITE_VERSION_NUMBER != SQLITE_UNIX_ABI {
            return Err(unavailable());
        }
        // This kernel-owned regular procfs entry cannot be replaced by a caller
        // renaming the admitted database. Only this fixed anchor is opened
        // through SQLite's pathname API. Existing descriptor admission already
        // requires the process's procfs /proc/self/fd view.
        let connection = Connection::open_with_flags_and_vfs(
            "/proc/self/stat",
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX
                | OpenFlags::SQLITE_OPEN_PRIVATE_CACHE,
            "unix",
        )
        .map_err(|_| unavailable())?;
        // FULL_MUTEX must yield a real DB mutex: sqlite3_threadsafe alone would
        // not detect runtime SQLITE_CONFIG_SINGLETHREAD, which disables the
        // Unix VFS's internal global and inode mutexes.
        // SAFETY: the private connection is live and exclusively owned here.
        if unsafe { ffi::sqlite3_db_mutex(connection.handle()) }.is_null() {
            return Err(unavailable());
        }
        with_borrowed_sqlite_descriptor(
            &connection,
            c"main",
            ffi::SQLITE_FCNTL_FILE_POINTER,
            |_| Ok(()),
        )
        .map_err(|_| unavailable())?;
        let mut file: *mut c_void = std::ptr::null_mut();
        // SAFETY: FILE_POINTER writes one borrowed pointer into file; the
        // private, native Unix connection retains it through Domain's lifetime.
        let result = unsafe {
            ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_FILE_POINTER,
                (&mut file as *mut *mut c_void).cast(),
            )
        };
        if result != ffi::SQLITE_OK || file.is_null() {
            return Err(unavailable());
        }
        // SAFETY: the exact bundled version and native VFS were checked above.
        // This private file is never queried, replaced or concurrently closed.
        let inode = unsafe { addr_of!((*file.cast::<BundledUnixFilePrefix>())._inode).read() };
        let anchor = NonNull::new(inode.cast::<UnixInode>()).ok_or_else(unavailable)?;
        let global = NonNull::new(
            // SAFETY: with core mutexes enabled, the public static allocation is
            // the mutex used by SQLite's unixEnterMutex. It is never freed here.
            unsafe { ffi::sqlite3_mutex_alloc(ffi::SQLITE_MUTEX_STATIC_VFS1) },
        )
        .ok_or_else(unavailable)?;
        // SAFETY: the anchor connection holds nRef > 0, making pLockMutex
        // immutable and live even before the global mutex is acquired.
        if unsafe { addr_of!((*anchor.as_ptr()).lock_mutex).read() }.is_null() {
            return Err(unavailable());
        }
        let domain = Arc::new(Self {
            _connection: Mutex::new(connection),
            anchor,
            global,
        });
        *shared = Arc::downgrade(&domain);
        Ok(domain)
    }
}

struct PendingNode(NonNull<UnusedFd>);

// SAFETY: this uniquely owned allocation is only accessed on its owning thread,
// or transferred to SQLite under the inode mutex. SQLite's allocator is shared.
unsafe impl Send for PendingNode {}
// SAFETY: no method permits mutation or deallocation through a shared reference.
unsafe impl Sync for PendingNode {}

impl PendingNode {
    fn allocate() -> io::Result<Self> {
        // SAFETY: SQLite's allocator supplies suitably aligned storage for
        // its own UnusedFd layout. No uninitialized field is read.
        NonNull::new(unsafe { ffi::sqlite3_malloc64(size_of::<UnusedFd>() as u64) }.cast())
            .map(Self)
            .ok_or_else(unavailable)
    }

    fn into_raw(self) -> *mut UnusedFd {
        ManuallyDrop::new(self).0.as_ptr()
    }
}

impl Drop for PendingNode {
    fn drop(&mut self) {
        // SAFETY: ownership has not transferred to SQLite; this is the matching
        // allocator and the allocation has no Rust fields requiring destruction.
        unsafe { ffi::sqlite3_free(self.0.as_ptr().cast()) };
    }
}

struct NativeMutexGuard(NonNull<ffi::sqlite3_mutex>);

impl NativeMutexGuard {
    // SAFETY: the caller must retain a live native mutex through guard drop and
    // follow global-then-inode lock order whenever both mutexes are acquired.
    unsafe fn enter(mutex: NonNull<ffi::sqlite3_mutex>) -> Self {
        // SAFETY: the caller supplies a live mutex and follows native lock order.
        unsafe { ffi::sqlite3_mutex_enter(mutex.as_ptr()) };
        Self(mutex)
    }
}

impl Drop for NativeMutexGuard {
    fn drop(&mut self) {
        // SAFETY: enter acquired this still-live mutex on the current thread.
        unsafe { ffi::sqlite3_mutex_leave(self.0.as_ptr()) };
    }
}

/// Reserve every resource needed for coordinated close before opening a reader.
pub(super) struct Retirement {
    domain: Arc<Domain>,
    pending: PendingNode,
}

impl Retirement {
    pub(super) fn prepare() -> io::Result<Self> {
        Ok(Self {
            domain: Domain::acquire()?,
            pending: PendingNode::allocate()?,
        })
    }

    pub(super) fn close(self, file: File, identity: (u64, u64)) {
        // SAFETY: domain retains its anchor connection and the static mutex.
        let _global = unsafe { NativeMutexGuard::enter(self.domain.global) };
        // SAFETY: anchor has a live native reference. The global mutex keeps
        // every linked inode and its links stable. Read only raw fields, never
        // create Rust references to C storage mutated by other connections.
        let inode = unsafe {
            let mut inode = self.domain.anchor.as_ptr();
            while !(*inode).previous.is_null() {
                inode = addr_of!((*inode).previous).read();
            }
            while !inode.is_null() {
                let device = addr_of!((*inode).identity.device).read();
                let number = addr_of!((*inode).identity.inode).read();
                if device == identity.0 && number == identity.1 {
                    break;
                }
                inode = addr_of!((*inode).next).read();
            }
            inode
        };
        if !inode.is_null() {
            // SAFETY: core mutexes were required at admission; every native
            // inode has a nonnull mutex. The global guard prevents its release.
            let mutex = unsafe { NonNull::new_unchecked(addr_of!((*inode).lock_mutex).read()) };
            // SAFETY: global precedes inode, matching unixClose/findReusableFd.
            let _inode = unsafe { NativeMutexGuard::enter(mutex) };
            // SAFETY: pLockMutex protects nLock and pUnused. If any native lock
            // survives, transfer both FD and SQLite-allocated node exactly once.
            // flags=0 deliberately prevents findReusableFd from adopting this
            // non-native reader; closePendingFds still closes/frees it normally.
            unsafe {
                if addr_of!((*inode).locks).read() != 0 {
                    let descriptor = file.into_raw_fd();
                    let pending = self.pending.into_raw();
                    pending.write(UnusedFd {
                        descriptor,
                        flags: 0,
                        next: addr_of!((*inode).unused).read(),
                    });
                    addr_of_mut!((*inode).unused).write(pending);
                    return;
                }
            }
            // Keep both guards until close completes: the inode mutex excludes
            // concurrent acquisition of the first native lock on this inode.
            drop(file);
        } else {
            // The global guard excludes registration of a new native inode.
            // A connection awaiting registration cannot acquire its first lock.
            drop(file);
        }
    }
}
