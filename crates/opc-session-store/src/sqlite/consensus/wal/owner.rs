//! Ordinary fixed-store selection and descriptor-bound native reopen.

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use rusqlite::Connection;
use sha2::{Digest, Sha256};

use super::{invalid_data, Binding, IoControl, Limits, Wal};
use crate::consensus::SessionPersistenceMode;
use crate::sqlite::consensus::{self, SqliteConsensusCore};

pub(super) const ROOT_BYTES: u64 = 168;
// Readers predating frontier-implied log removal must fail before reading
// CURRENT. Both formats retain the existing selector and root record layout.
const ROOT_MAGIC: &[u8; 8] = b"OPCNR002";
const ASYNC_RECOVERY_ROOT_MAGIC: &[u8; 8] = b"OPCNA004";
const SELECTION_ATTRIBUTE: &str = "user.opc.native-root-v1";

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
struct MissingNativeRoot(io::Error);

#[track_caller]
fn missing_native_root(message: &'static str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        MissingNativeRoot(invalid_data(message)),
    )
}

pub(crate) fn is_missing_native_root(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<MissingNativeRoot>())
}

#[cfg(any(test, feature = "test-control"))]
type GenerationHookForTest = Arc<dyn Fn(&'static str) -> io::Result<()> + Send + Sync>;

#[cfg(test)]
pub(crate) type IoHookForTest = Arc<dyn Fn(super::Point) -> io::Result<()> + Send + Sync>;

#[cfg(test)]
type PreflightHookForTest = Arc<dyn Fn() -> io::Result<()> + Send + Sync>;

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RootPointForTest {
    BeforeCreate,
    AfterCreate,
    AfterWrite,
    AfterFileSync,
    AfterDirectorySync,
    AfterParentSync,
    AfterSelection,
    AfterSelectionSync,
}

#[cfg(test)]
pub(crate) type RootHookForTest = Arc<dyn Fn(RootPointForTest) -> io::Result<()> + Send + Sync>;

fn read_selection(database: &File) -> io::Result<Option<[u8; ROOT_BYTES as usize]>> {
    let mut bytes = [0; ROOT_BYTES as usize];
    match rustix::fs::fgetxattr(database, SELECTION_ATTRIBUTE, &mut bytes[..]) {
        Ok(len) if len == bytes.len() => Ok(Some(bytes)),
        Ok(_) => Err(invalid_data("native database selection extent differs")),
        Err(rustix::io::Errno::NODATA) => Ok(None),
        // Ordinary SQLite may use a filesystem without user attributes.
        // Selecting native storage there still fails at the durable write.
        Err(rustix::io::Errno::OPNOTSUPP) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn identity(metadata: &fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn check_open_cancelled(cancellation: &AtomicBool) -> io::Result<()> {
    if cancellation.load(Ordering::Acquire) {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "native generation admission cancelled",
        ))
    } else {
        Ok(())
    }
}

fn open_directory(path: &Path) -> io::Result<Arc<File>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(path)?;
    if !file.metadata()?.is_dir() {
        return Err(invalid_data("native parent is not a directory"));
    }
    Ok(Arc::new(file))
}

pub(super) fn pin_directory(path: &Path) -> io::Result<Arc<File>> {
    let file = open_directory(path)?;
    let metadata = file.metadata()?;
    if metadata.uid() != nix::unistd::geteuid().as_raw() || metadata.mode() & 0o777 != 0o700 {
        return Err(invalid_data("native directory ownership or mode differs"));
    }
    Ok(file)
}

pub(super) fn directory_path(file: &File) -> PathBuf {
    // The final dot names the directory itself, allowing O_NOFOLLOW on each
    // child without resolving the consumer's mutable parent pathname again.
    PathBuf::from(format!("/proc/self/fd/{}/.", file.as_raw_fd()))
}

/// Clones share a sticky selection and the current live owner. An absent,
/// incomplete or closed selected owner cannot dispatch to the SQLite basis.
pub(crate) struct NativeOwner {
    parent: Arc<File>,
    database: File,
    database_name: OsString,
    database_identity: (u64, u64),
    native_name: OsString,
    selected: AtomicBool,
    current: Mutex<Weak<Wal>>,
    #[cfg(any(test, feature = "test-control"))]
    generation_hook: Mutex<Option<GenerationHookForTest>>,
    #[cfg(test)]
    root_hook: Mutex<Option<RootHookForTest>>,
    #[cfg(test)]
    io_hook: Mutex<Option<IoHookForTest>>,
    #[cfg(test)]
    preflight_hook: Mutex<Option<PreflightHookForTest>>,
}

impl NativeOwner {
    pub(crate) fn discover(path: &Path, conn: &Connection) -> io::Result<Self> {
        let parent = open_directory(
            path.parent()
                .ok_or_else(|| invalid_data("native database parent missing"))?,
        )?;
        let database_name = path
            .file_name()
            .ok_or_else(|| invalid_data("native database name missing"))?
            .to_os_string();
        let mut native_name = database_name.clone();
        native_name.push(".native-wal");
        let file = opc_sqlite_file_control_sys::main_file_descriptor(conn)
            .map_err(|_| invalid_data("native database descriptor unavailable"))?;
        let metadata = file.metadata()?;
        let named = fs::symlink_metadata(directory_path(&parent).join(&database_name))?;
        if !metadata.is_file() || !named.is_file() || identity(&metadata) != identity(&named) {
            return Err(invalid_data(
                "native database descriptor differs from namespace",
            ));
        }
        let namespace_exists =
            match fs::symlink_metadata(directory_path(&parent).join(&native_name)) {
                Ok(_) => true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(error) => return Err(error),
            };
        let selected = read_selection(&file)?.is_some() || namespace_exists;
        Ok(Self {
            parent,
            database: file,
            database_name,
            database_identity: identity(&metadata),
            native_name,
            selected: AtomicBool::new(selected),
            current: Mutex::new(Weak::new()),
            #[cfg(any(test, feature = "test-control"))]
            generation_hook: Mutex::new(None),
            #[cfg(test)]
            root_hook: Mutex::new(None),
            #[cfg(test)]
            io_hook: Mutex::new(None),
            #[cfg(test)]
            preflight_hook: Mutex::new(None),
        })
    }

    /// Inject only an I/O boundary before ordinary owner construction. This
    /// never selects a persistence mode or substitutes a test storage owner.
    #[cfg(any(test, feature = "test-control"))]
    pub(crate) fn set_generation_hook_for_test(
        &self,
        hook: Arc<dyn Fn() -> io::Result<()> + Send + Sync>,
    ) -> io::Result<()> {
        self.set_checkpoint_hook_for_test(Arc::new(move |cut| {
            if cut == "before_append" {
                hook()
            } else {
                Ok(())
            }
        }))
    }

    #[cfg(any(test, feature = "test-control"))]
    pub(crate) fn set_checkpoint_hook_for_test(
        &self,
        hook: GenerationHookForTest,
    ) -> io::Result<()> {
        if self
            .current
            .lock()
            .map_err(|_| invalid_data("native test owner lock poisoned"))?
            .upgrade()
            .is_some()
        {
            return Err(invalid_data(
                "native test fault must precede owner construction",
            ));
        }
        *self
            .generation_hook
            .lock()
            .map_err(|_| invalid_data("native test fault lock poisoned"))? = Some(hook);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn set_root_hook_for_test(&self, hook: RootHookForTest) {
        assert!(self.current.lock().unwrap().upgrade().is_none());
        *self.root_hook.lock().unwrap() = Some(hook);
    }

    #[cfg(test)]
    pub(crate) fn set_io_hook_for_test(&self, hook: IoHookForTest) {
        assert!(self.current.lock().unwrap().upgrade().is_none());
        *self.io_hook.lock().unwrap() = Some(hook);
    }

    #[cfg(test)]
    pub(crate) fn set_preflight_hook_for_test(&self, hook: PreflightHookForTest) {
        assert!(self.current.lock().unwrap().upgrade().is_none());
        *self.preflight_hook.lock().unwrap() = Some(hook);
    }

    #[cfg(test)]
    fn root_point_for_test(&self, point: RootPointForTest) -> io::Result<()> {
        let hook = self.root_hook.lock().unwrap().clone();
        hook.map_or(Ok(()), |hook| hook(point))
    }

    fn io_control(&self) -> IoControl {
        #[cfg(test)]
        if let Some(hook) = self.io_hook.lock().unwrap().clone() {
            assert!(self.generation_hook.lock().unwrap().is_none());
            return IoControl {
                hook,
                ..IoControl::default()
            };
        }
        #[cfg(any(test, feature = "test-control"))]
        {
            let hook = match self.generation_hook.lock() {
                Ok(slot) => slot.clone(),
                Err(_) => {
                    return IoControl {
                        hook: Arc::new(|_| Err(invalid_data("native test fault lock poisoned"))),
                        ..IoControl::default()
                    };
                }
            };
            if let Some(hook) = hook {
                return IoControl {
                    hook: Arc::new(move |point| {
                        let cut = match point {
                            super::Point::AfterNativeGenerationCapture => Some("capture"),
                            super::Point::BeforeNativeGenerationAppend => Some("before_append"),
                            super::Point::AfterNativeGenerationAppend => Some("append"),
                            super::Point::AfterBasisSelectorRename => Some("selection"),
                            super::Point::AfterBasisReclaimFile => Some("reclaim_covered"),
                            _ => None,
                        };
                        if let Some(cut) = cut {
                            hook(cut)?;
                        }
                        Ok(())
                    }),
                    ..IoControl::default()
                };
            }
        }
        IoControl::default()
    }

    pub(crate) fn selected(&self) -> bool {
        if self.selected.load(Ordering::Acquire) {
            return true;
        }
        // Another ordinary backend may have selected this database since
        // this handle opened. Once discovered, selection stays irreversible.
        if !matches!(read_selection(&self.database), Ok(None)) {
            self.select();
            return true;
        }
        match fs::symlink_metadata(directory_path(&self.parent).join(&self.native_name)) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            _ => {
                self.select();
                true
            }
        }
    }

    pub(crate) fn select(&self) {
        self.selected.store(true, Ordering::Release);
    }

    /// Read-only admission before initialization or snapshot cleanup. A mode
    /// change is never an implicit migration, even when the selected cut is
    /// empty. Recheck the full descriptor/inode binding again during attach.
    pub(crate) fn persistence_mode(
        &self,
        identity_expected: consensus::SessionConsensusIdentity,
    ) -> io::Result<Option<SessionPersistenceMode>> {
        let path = directory_path(&self.parent).join(&self.native_name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let pin = pin_directory(&path)?;
                Ok(Some(self.read_root(&pin, identity_expected)?.persistence))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if read_selection(&self.database)?.is_some() {
                    return Err(missing_native_root("selected native root is missing"));
                }
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn current(&self) -> io::Result<Arc<Wal>> {
        self.current
            .lock()
            .map_err(|_| invalid_data("native owner slot poisoned"))?
            .upgrade()
            .ok_or_else(|| invalid_data("native owner unavailable"))
    }

    /// Refuse unknown generation vocabularies before initialization can write.
    /// This compatibility pass does not admit rows or replace the later full
    /// catalog, WAL suffix and strict snapshot verification during attachment.
    pub(crate) fn preflight_formats(
        &self,
        identity_expected: consensus::SessionConsensusIdentity,
        cancellation: &AtomicBool,
    ) -> io::Result<Vec<super::super::CurrentSnapshot>> {
        let pin = pin_directory(&directory_path(&self.parent).join(&self.native_name))?;
        let binding = self.read_root(&pin, identity_expected)?;
        let directory = directory_path(&pin);
        let anchor = super::checkpoint::read(&directory, binding, Limits::default())?
            .ok_or_else(|| invalid_data("native selected generation is missing"))?;
        self.preflight_generation_format(&directory, &anchor, cancellation)
    }

    /// Compatibility inspection precedes even the SQLite query that classifies
    /// a caller identity mismatch. ROOT's checksum, selection and inode binding
    /// are checked here; its scope binding remains the ordinary opener's job.
    pub(crate) fn preflight_formats_before_scope_lookup(
        &self,
        cancellation: &AtomicBool,
    ) -> io::Result<Vec<super::super::CurrentSnapshot>> {
        let pin = pin_directory(&directory_path(&self.parent).join(&self.native_name))?;
        let (bytes, persistence) = self.read_root_record(&pin)?;
        let mut root = [0; 32];
        root.copy_from_slice(&bytes[104..136]);
        let directory = directory_path(&pin);
        let anchor = super::checkpoint::read_for_native_format_preflight(
            &directory,
            root,
            persistence,
            Limits::default(),
        )?
        .ok_or_else(|| invalid_data("native selected generation is missing"))?;
        self.preflight_generation_format(&directory, &anchor, cancellation)
    }

    fn preflight_generation_format(
        &self,
        directory: &Path,
        anchor: &super::checkpoint::Anchor,
        cancellation: &AtomicBool,
    ) -> io::Result<Vec<super::super::CurrentSnapshot>> {
        #[cfg(test)]
        let hook = self.preflight_hook.lock().unwrap().clone();
        let prefix = anchor
            .native_prefix()?
            .ok_or_else(|| invalid_data("native generation discriminator differs"))?;
        let current = crate::consensus::native::generation::preflight_format(
            &anchor.basis_path(directory),
            prefix,
            super::MAX_BASIS,
            anchor.native_cut_binding()?,
            &|| {
                if cancellation.load(Ordering::Acquire) {
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "native generation preflight cancelled",
                    ));
                }
                #[cfg(test)]
                if let Some(hook) = &hook {
                    hook()?;
                    if cancellation.load(Ordering::Acquire) {
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "native generation preflight cancelled",
                        ));
                    }
                }
                Ok(())
            },
        )?;
        let mut snapshots = anchor
            .native_snapshots
            .as_ref()
            .map_or_else(Vec::new, |snapshots| snapshots.retained());
        if let Some(current) = current {
            if !snapshots.contains(&current) {
                snapshots.push(current);
            }
        }
        Ok(snapshots)
    }

    fn verify_database(&self, core: &SqliteConsensusCore) -> io::Result<()> {
        let database = core
            .database_file
            .as_ref()
            .ok_or_else(|| invalid_data("native database pin missing"))?;
        let metadata = database.file().metadata()?;
        let named = fs::symlink_metadata(directory_path(&self.parent).join(&self.database_name))?;
        if !named.is_file()
            || identity(&metadata) != self.database_identity
            || identity(&named) != self.database_identity
        {
            return Err(invalid_data("native database namespace changed"));
        }
        Ok(())
    }

    pub(crate) async fn attach_with_descriptors<V, F>(
        self: &Arc<Self>,
        core: &mut SqliteConsensusCore,
        persistence: SessionPersistenceMode,
        validate: impl FnOnce(Vec<consensus::CurrentSnapshot>, Option<consensus::CurrentSnapshot>) -> F,
        verify: impl FnOnce(&V) -> io::Result<()> + Send + 'static,
        install_source: impl FnOnce(&V) -> Option<&super::snapshot::InstallSource> + Send + 'static,
    ) -> io::Result<()>
    where
        F: std::future::Future<Output = io::Result<V>>,
        V: Send + 'static,
    {
        if !self.selected()
            || core.private_wal.is_some()
            || core.authority_profile != consensus::ConsensusAuthorityProfile::FixedImmutable
        {
            return Err(invalid_data("native fixed owner admission differs"));
        }
        self.verify_database(core)?;
        let conn = Arc::clone(&core.conn).lock_owned().await;
        let path = directory_path(&self.parent).join(&self.native_name);
        let existing = match fs::symlink_metadata(&path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error),
        };
        let (wal, _conn) = if existing {
            let pin = pin_directory(&path)?;
            let binding = self.read_root(&pin, core.storage_identity)?;
            if binding.persistence != persistence {
                return Err(invalid_data("native persistence mode differs"));
            }
            let owner = Arc::clone(self);
            let roster_root = core.configured_roster_root.clone();
            // The worker owns the connection guard as well as the descriptor
            // owner. Cancelling an open must not release either underneath a
            // running scan; queued captures are retired by the shared guard.
            let (opening, conn, owner) =
                crate::sqlite::SqliteSessionBackend::run_native_open_blocking(move |cancel| {
                    let opening = super::native::Opening::new_with_check(
                        &directory_path(&pin),
                        binding,
                        roster_root,
                        Limits::default(),
                        owner.io_control(),
                        &|| check_open_cancelled(cancel),
                    )?;
                    Ok((opening, conn, owner))
                })
                .await
                .map_err(io::Error::other)?;
            let descriptors = validate(opening.snapshots(), opening.install_candidate()).await?;
            crate::sqlite::SqliteSessionBackend::run_native_open_blocking(move |cancel| {
                let _owner = owner;
                let wal = opening.finish_with_install_source_checked(
                    install_source(&descriptors),
                    || verify(&descriptors),
                    &|| check_open_cancelled(cancel),
                )?;
                Ok((wal, conn))
            })
            .await
            .map_err(io::Error::other)?
        } else {
            if !core.fresh_native_basis || read_selection(&self.database)?.is_some() {
                return Err(missing_native_root(
                    "existing fixed storage is missing its native root",
                ));
            }
            let descriptors = validate(Vec::new(), None).await?;
            verify(&descriptors)?;
            let mut generation = [0; 32];
            generation[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
            generation[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
            let wal = Wal::create_native_with_persistence(
                &path,
                &conn,
                core.storage_identity,
                generation,
                core.configured_roster_root.clone(),
                Limits::default(),
                self.io_control(),
                persistence,
            )?;
            self.write_root(&wal)?;
            (wal, conn)
        };
        self.verify_database(core)?;
        let placement = core
            .fixed_placement_policy
            .ok_or_else(|| invalid_data("native fixed placement missing"))?;
        wal.admit_native_fixed_open(
            crate::sqlite::consensus::wal::native::FixedReadExpectation {
                identity: core.storage_identity,
                members: &core.expected_members,
                bindings: &core.expected_bindings,
                placement,
                pristine: true,
                database_path: None,
            },
        )?;
        core.applied_progress
            .send_replace(wal.with_native_read(|state| Ok(state.applied()))?);
        if let Some(diagnostics) = &core.diagnostics {
            wal.publish_native_roster_occupancy(diagnostics);
        }
        #[cfg(any(test, feature = "test-control"))]
        wal.bind_terminal_observation_database_for_test(
            consensus::terminal_observer::PinnedDatabase::from_identity(
                self.database_identity,
                Arc::clone(&core.conn),
            ),
        )?;
        let wal = Arc::new(wal);
        *self
            .current
            .lock()
            .map_err(|_| invalid_data("native owner slot poisoned"))? = Arc::downgrade(&wal);
        core.private_wal = Some(wal);
        Ok(())
    }

    fn write_root(&self, wal: &Wal) -> io::Result<()> {
        let directory = wal
            .directory_pin
            .as_ref()
            .ok_or_else(|| invalid_data("native directory pin missing"))?;
        let directory_identity = identity(&directory.metadata()?);
        let mut bytes = [0; ROOT_BYTES as usize];
        bytes[..8].copy_from_slice(match wal.binding.persistence {
            SessionPersistenceMode::Durable => ROOT_MAGIC,
            SessionPersistenceMode::Async
                if wal.binding.async_recovery_format && wal.binding.async_closed_format =>
            {
                ASYNC_RECOVERY_ROOT_MAGIC
            }
            SessionPersistenceMode::Async => {
                return Err(invalid_data("asynchronous recovery root format differs"));
            }
        });
        for (chunk, value) in bytes[8..40].as_chunks_mut::<8>().0.iter_mut().zip([
            self.database_identity.0,
            self.database_identity.1,
            directory_identity.0,
            directory_identity.1,
        ]) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        bytes[40..72].copy_from_slice(&wal.binding.generation);
        bytes[72..104].copy_from_slice(&wal.binding.basis);
        bytes[104..136].copy_from_slice(&wal.binding.digest()?);
        let checksum = Sha256::digest(&bytes[..136]);
        bytes[136..].copy_from_slice(&checksum);
        #[cfg(test)]
        self.root_point_for_test(RootPointForTest::BeforeCreate)?;
        let mut file = super::file_create(&directory_path(directory).join("ROOT"))?;
        #[cfg(test)]
        self.root_point_for_test(RootPointForTest::AfterCreate)?;
        file.write_all(&bytes)?;
        #[cfg(test)]
        self.root_point_for_test(RootPointForTest::AfterWrite)?;
        file.sync_all()?;
        #[cfg(test)]
        self.root_point_for_test(RootPointForTest::AfterFileSync)?;
        directory.sync_all()?;
        #[cfg(test)]
        self.root_point_for_test(RootPointForTest::AfterDirectorySync)?;
        self.parent.sync_all()?;
        #[cfg(test)]
        self.root_point_for_test(RootPointForTest::AfterParentSync)?;
        // Retain the complete ROOT proof on the actual database inode,
        // independently of the removable native namespace and its spelling.
        // CREATE prevents replacing a prior selection. The inode sync must
        // finish before publishing a live owner or admitting any native work.
        rustix::fs::fsetxattr(
            &self.database,
            SELECTION_ATTRIBUTE,
            &bytes,
            rustix::fs::XattrFlags::CREATE,
        )?;
        #[cfg(test)]
        self.root_point_for_test(RootPointForTest::AfterSelection)?;
        self.database.sync_all()?;
        #[cfg(test)]
        self.root_point_for_test(RootPointForTest::AfterSelectionSync)?;
        Ok(())
    }

    fn read_root_record(
        &self,
        directory: &File,
    ) -> io::Result<([u8; ROOT_BYTES as usize], SessionPersistenceMode)> {
        let mut file = super::file_read(&directory_path(directory).join("ROOT"))?;
        let metadata = file.metadata()?;
        if metadata.len() != ROOT_BYTES
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(invalid_data(
                "native root record extent or ownership differs",
            ));
        }
        let mut bytes = [0; ROOT_BYTES as usize];
        file.read_exact(&mut bytes)?;
        if read_selection(&self.database)? != Some(bytes) {
            return Err(invalid_data(
                "native root differs from durable database selection",
            ));
        }
        if Sha256::digest(&bytes[..136])[..] != bytes[136..] {
            return Err(invalid_data("native root record proof differs"));
        }
        let persistence = match &bytes[..8] {
            magic if magic == ROOT_MAGIC => SessionPersistenceMode::Durable,
            magic if magic == ASYNC_RECOVERY_ROOT_MAGIC => SessionPersistenceMode::Async,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    crate::consensus::storage::SessionConsensusStorageError::PersistenceFormatMismatch,
                ));
            }
        };
        let directory_identity = identity(&directory.metadata()?);
        for (chunk, expected) in bytes[8..40].as_chunks::<8>().0.iter().zip([
            self.database_identity.0,
            self.database_identity.1,
            directory_identity.0,
            directory_identity.1,
        ]) {
            if *chunk != expected.to_be_bytes() {
                return Err(invalid_data("native root namespace identity differs"));
            }
        }
        Ok((bytes, persistence))
    }

    fn read_root(
        &self,
        directory: &File,
        identity_expected: consensus::SessionConsensusIdentity,
    ) -> io::Result<Binding> {
        let (bytes, persistence) = self.read_root_record(directory)?;
        let mut generation = [0; 32];
        let mut basis = [0; 32];
        generation.copy_from_slice(&bytes[40..72]);
        basis.copy_from_slice(&bytes[72..104]);
        let binding = Binding {
            identity: identity_expected,
            generation,
            basis,
            native: true,
            persistence,
            async_closed_format: &bytes[..8] == ASYNC_RECOVERY_ROOT_MAGIC,
            async_recovery_format: &bytes[..8] == ASYNC_RECOVERY_ROOT_MAGIC,
        };
        if binding.digest()? != bytes[104..136] {
            return Err(invalid_data("native root authority binding differs"));
        }
        Ok(binding)
    }
}

#[cfg(test)]
#[path = "owner_format_tests.rs"]
mod format_tests;
