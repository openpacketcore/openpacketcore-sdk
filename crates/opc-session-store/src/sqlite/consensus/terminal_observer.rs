//! Backend-bound observations of real roster work across Raft and WAL threads.

#[cfg(target_os = "linux")]
use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs::File;
#[cfg(any(target_os = "linux", feature = "test-control"))]
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "test-control")]
use std::sync::Arc;
use std::sync::{Mutex, Weak};
use std::time::Instant;

use rusqlite::Connection;

use super::{
    ProtectedRosterTerminalApplyTimings, ProtectedRosterV2TerminalStatusValidationStagesForTest,
};

#[cfg(all(test, feature = "test-control", target_os = "linux"))]
mod tests;

static ACTIVE: AtomicUsize = AtomicUsize::new(0);
static OBSERVERS: Mutex<Vec<Weak<Observation>>> = Mutex::new(Vec::new());

#[cfg(target_os = "linux")]
thread_local! {
    static HYDRATION_DATABASE: Cell<Option<DatabaseKey>> = const { Cell::new(None) };
}

/// Pure carrier verification has no backend argument. Its synchronous owner
/// installs the identity on the actual worker after the WAL capture crossed
/// threads. This scope is never entered by an async caller or held over await.
#[cfg(target_os = "linux")]
pub(crate) struct HydrationScope {
    previous: Option<DatabaseKey>,
    _same_thread: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(target_os = "linux")]
impl HydrationScope {
    pub(crate) fn enter(database: Option<DatabaseKey>) -> Self {
        Self {
            previous: HYDRATION_DATABASE.replace(database),
            _same_thread: std::marker::PhantomData,
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for HydrationScope {
    fn drop(&mut self) {
        HYDRATION_DATABASE.set(self.previous);
    }
}

#[cfg(target_os = "linux")]
pub(super) fn hydration_database() -> Option<DatabaseKey> {
    HYDRATION_DATABASE.get()
}

/// The actual SQLite backing file, independent of path or consensus identity.
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct DatabaseKey(u64, u64);

impl DatabaseKey {
    #[cfg(target_os = "linux")]
    pub(crate) fn for_file(file: &File) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::other(
                "terminal observation requires a database file",
            ));
        }
        Ok(Self(metadata.dev(), metadata.ino()))
    }
}

/// Resolve the real SQLite writer, including transactions and savepoints.
pub(super) fn database_key(conn: &Connection) -> Option<DatabaseKey> {
    if ACTIVE.load(Ordering::Acquire) == 0 {
        return None;
    }
    #[cfg(target_os = "linux")]
    {
        let file = opc_sqlite_file_control_sys::main_file_descriptor(conn).ok()?;
        DatabaseKey::for_file(&file).ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = conn;
        None
    }
}

#[derive(Default)]
struct Counts {
    timings: ProtectedRosterTerminalApplyTimings,
    stages: ProtectedRosterV2TerminalStatusValidationStagesForTest,
}

struct Observation {
    databases: BTreeSet<DatabaseKey>,
    // Retain the actual descriptors so an observed inode cannot be recycled.
    _files: Vec<File>,
    counts: Mutex<Counts>,
}

/// Aggregate-only terminal observations for explicitly selected SQLite backends.
///
/// The file identities follow their real native WAL workers and detached reads;
/// neither task ancestry nor a reused consensus identity selects an observation.
/// Each observer starts at zero and owns its snapshots independently, including
/// when two observers select the same database. Dropping one retires only that
/// observation. No commands, identities or error material appear in snapshots.
///
/// This test-control facility requires file-backed Linux SQLite databases.
#[cfg(feature = "test-control")]
pub struct ProtectedRosterTerminalObservationForTest(Arc<Observation>);

#[cfg(feature = "test-control")]
impl ProtectedRosterTerminalObservationForTest {
    /// Begin observing the selected databases from this point forward.
    ///
    /// Returns an error for an empty selection or an unsupported backing file.
    pub async fn new(backends: &[crate::sqlite::SqliteSessionBackend]) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let mut files = Vec::with_capacity(backends.len());
            for backend in backends {
                let conn = backend.conn.lock().await;
                files.push(
                    opc_sqlite_file_control_sys::main_file_descriptor(&conn).map_err(|_| {
                        io::Error::other("terminal observation database descriptor unavailable")
                    })?,
                );
            }
            Self::from_files(files)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = backends;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "terminal observations require Linux database descriptors",
            ))
        }
    }

    #[cfg(target_os = "linux")]
    fn from_files(files: Vec<File>) -> io::Result<Self> {
        if files.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "terminal observation requires at least one database",
            ));
        }
        let databases = files
            .iter()
            .map(DatabaseKey::for_file)
            .collect::<io::Result<_>>()?;
        let observation = Arc::new(Observation {
            databases,
            _files: files,
            counts: Mutex::default(),
        });
        OBSERVERS
            .lock()
            .expect("terminal observation registry")
            .push(Arc::downgrade(&observation));
        ACTIVE.fetch_add(1, Ordering::Release);
        Ok(Self(observation))
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn from_connection(conn: &Connection) -> io::Result<Self> {
        Self::from_files(vec![opc_sqlite_file_control_sys::main_file_descriptor(
            conn,
        )
        .map_err(|_| {
            io::Error::other("terminal observation database descriptor unavailable")
        })?])
    }

    /// Snapshot all six terminal-apply phase counts and durations.
    pub fn timings(&self) -> ProtectedRosterTerminalApplyTimings {
        self.0
            .counts
            .lock()
            .expect("terminal observation counts")
            .timings
    }

    /// Snapshot the fixed, redacted Profile-V2 validation checkpoints.
    pub fn validation_stages(&self) -> ProtectedRosterV2TerminalStatusValidationStagesForTest {
        self.0
            .counts
            .lock()
            .expect("terminal observation counts")
            .stages
    }
}

#[cfg(feature = "test-control")]
impl Drop for ProtectedRosterTerminalObservationForTest {
    fn drop(&mut self) {
        let own = Arc::downgrade(&self.0);
        OBSERVERS
            .lock()
            .expect("terminal observation registry")
            .retain(|observer| !observer.ptr_eq(&own));
        ACTIVE.fetch_sub(1, Ordering::Release);
    }
}

fn record(database: Option<DatabaseKey>, mut update: impl FnMut(&mut Counts)) {
    let Some(database) = database else { return };
    if ACTIVE.load(Ordering::Acquire) == 0 {
        return;
    }
    let observers = OBSERVERS.lock().expect("terminal observation registry");
    for observer in observers.iter().filter_map(Weak::upgrade) {
        if observer.databases.contains(&database) {
            update(&mut observer.counts.lock().expect("terminal observation counts"));
        }
    }
}

pub(super) fn record_timing(
    database: Option<DatabaseKey>,
    select: fn(&mut ProtectedRosterTerminalApplyTimings) -> (&mut u64, &mut u64),
    start: Instant,
) {
    let elapsed = u64::try_from(start.elapsed().as_nanos()).unwrap_or(u64::MAX);
    record(database, |counts| {
        let (count, nanos) = select(&mut counts.timings);
        *count = count.wrapping_add(1);
        *nanos = nanos.wrapping_add(elapsed);
    });
}

pub(super) fn record_stage(
    database: Option<DatabaseKey>,
    select: fn(&mut ProtectedRosterV2TerminalStatusValidationStagesForTest) -> &mut u64,
) {
    record(database, |counts| {
        let count = select(&mut counts.stages);
        *count = count.wrapping_add(1);
    });
}
