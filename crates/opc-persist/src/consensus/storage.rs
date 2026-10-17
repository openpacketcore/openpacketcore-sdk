//! Openraft storage adapters backed by the config SQLite database.

use std::io;
use std::ops::{Bound, RangeBounds};
#[cfg(unix)]
use std::os::fd::AsRawFd as _;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use opc_consensus::engine::storage::{LogFlushed, RaftLogStorage, RaftStateMachine};
use opc_consensus::engine::{
    Entry, ErrorSubject, ErrorVerb, LogId, LogState, RaftLogReader, RaftSnapshotBuilder, Snapshot,
    SnapshotMeta, StorageError, StoredMembership, Vote,
};
use opc_consensus::{ConsensusIdentity, ConsensusNodeId, DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use super::snapshot_file::ConfigSnapshotFile;
use super::{sqlite, ApprovedLegacyConfigRecovery, ConfigConsensusResponse, ConfigRaftTypeConfig};
use crate::backend::SqliteBackend;

const SNAPSHOT_FOOTER_MAGIC: &[u8; 8] = b"OPCCFG01";
const SNAPSHOT_FOOTER_BYTES: u64 = 8 + 2 + 8 + 32;
pub(crate) const SNAPSHOT_MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;
pub(crate) const SNAPSHOT_MAX_ENVELOPE_BYTES: u64 = SNAPSHOT_MAX_BYTES + SNAPSHOT_FOOTER_BYTES;
const SNAPSHOT_DIRECTORY_MAX_ENTRIES: usize = 8_192;
const SNAPSHOT_OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

#[cfg(test)]
mod snapshot_staging_tests;

#[cfg(test)]
#[derive(Default)]
pub(crate) struct SnapshotTestHooks {
    before_snapshot_commit: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
    pause_pinned_read: AtomicBool,
    read_pinned: tokio::sync::Notify,
    resume_pinned_read: tokio::sync::Notify,
    pub(crate) pause_open_read: AtomicBool,
    pub(crate) read_opened: tokio::sync::Notify,
    pub(crate) resume_read: tokio::sync::Notify,
    build_gate_acquired: AtomicBool,
    pub(crate) pause_build: AtomicBool,
    pub(crate) build_started: tokio::sync::Notify,
    pub(crate) resume_build: tokio::sync::Notify,
    pub(crate) reads_started: AtomicU64,
    pub(crate) builds_started: AtomicU64,
    pub(crate) pause_captured_build: AtomicBool,
    pub(crate) build_captured: tokio::sync::Notify,
    pub(crate) resume_captured_build: tokio::sync::Notify,
    pub(crate) pause_published_build: AtomicBool,
    pub(crate) build_published: tokio::sync::Notify,
    pub(crate) builds_returned_ok: AtomicU64,
    pub(crate) build_returned_ok: tokio::sync::Notify,
    pub(crate) read_gate_blocked: tokio::sync::Notify,
}

#[cfg(test)]
impl SnapshotTestHooks {
    fn before_commit(
        &self,
        conn: &rusqlite::Connection,
        cancellation: &Arc<sqlite::SqliteWorkCancellation>,
    ) -> io::Result<()> {
        if let Some(hook) = self
            .before_snapshot_commit
            .lock()
            .expect("snapshot commit hook")
            .take()
        {
            cancellation.before_commit_for_test(conn, hook)?;
        }
        Ok(())
    }
}

/// The last durable publication, independent of the SQLite worker. Readers
/// retain this record until they have opened their own descriptor. Replacing
/// the record retires its path only after those opens finish or are cancelled.
pub(crate) struct PublishedSnapshot {
    meta: SnapshotMeta<ConsensusNodeId, opc_consensus::engine::EmptyNode>,
    path: PathBuf,
    checksum: [u8; 32],
    length: u64,
    retired: AtomicBool,
}

impl PublishedSnapshot {
    fn new(
        meta: SnapshotMeta<ConsensusNodeId, opc_consensus::engine::EmptyNode>,
        path: PathBuf,
        checksum: [u8; 32],
        length: u64,
    ) -> Self {
        Self {
            meta,
            path,
            checksum,
            length,
            retired: AtomicBool::new(false),
        }
    }
}

impl Drop for PublishedSnapshot {
    fn drop(&mut self) {
        // The current durable artifact must survive shutdown. Only a completed
        // successor publication can retire it; startup removes crash orphans.
        if self.retired.load(Ordering::Acquire) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

async fn publish_snapshot(
    core: &sqlite::ConfigConsensusCore,
    published: PublishedSnapshot,
) -> io::Result<()> {
    let published = Arc::new(published);
    let previous = {
        // The commit may have drained beyond its work deadline. This short
        // publication has its own wait budget and performs no I/O under the gate.
        let mut current =
            tokio::time::timeout(SNAPSHOT_OPERATION_TIMEOUT, core.snapshot_gate.lock())
                .await
                .map_err(|_| {
                    sqlite::invalid_data("config consensus snapshot publication gate timed out")
                })?;
        current.replace(published)
    };
    if let Some(previous) = previous {
        previous.retired.store(true, Ordering::Release);
        // Drop and any resulting unlink happen outside the publication gate.
    }
    Ok(())
}

#[must_use = "staging artifacts must stay guarded until they are durably referenced"]
struct StagingArtifact {
    path: PathBuf,
    sqlite_sidecars: bool,
    armed: bool,
    _owner: Option<Arc<SnapshotDirectoryOwner>>,
}

impl StagingArtifact {
    async fn create(
        path: PathBuf,
        sqlite_sidecars: bool,
        owner: Arc<SnapshotDirectoryOwner>,
    ) -> io::Result<(tokio::fs::File, Self)> {
        Self::create_with_hook(
            path,
            sqlite_sidecars,
            owner,
            #[cfg(test)]
            None,
        )
        .await
    }

    async fn create_with_hook(
        path: PathBuf,
        sqlite_sidecars: bool,
        owner: Arc<SnapshotDirectoryOwner>,
        #[cfg(test)] before_create: Option<Box<dyn FnOnce() + Send>>,
    ) -> io::Result<(tokio::fs::File, Self)> {
        // Opening a file can outlive cancellation of its async caller. The
        // blocking task must own both cleanup and admission before it opens.
        let worker = tokio::task::spawn_blocking(move || {
            let mut cleanup = Self {
                path,
                sqlite_sidecars,
                armed: false,
                _owner: Some(owner),
            };
            #[cfg(test)]
            if let Some(hook) = before_create {
                hook();
            }
            let mut options = std::fs::OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            options.mode(0o600);
            let file = options.open(&cleanup.path)?;
            cleanup.armed = true;
            Ok((tokio::fs::File::from_std(file), cleanup))
        });
        tokio::time::timeout(SNAPSHOT_OPERATION_TIMEOUT, worker)
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "snapshot creation timed out"))?
            .map_err(|_| io::Error::other("config snapshot creation failed"))?
    }

    fn file(path: PathBuf) -> Self {
        Self {
            path,
            sqlite_sidecars: false,
            armed: true,
            _owner: None,
        }
    }

    fn sqlite(path: PathBuf) -> Self {
        Self {
            path,
            sqlite_sidecars: true,
            armed: true,
            _owner: None,
        }
    }

    fn with_owner(mut self, owner: Arc<SnapshotDirectoryOwner>) -> Self {
        self._owner = Some(owner);
        self
    }

    fn replace_path(&mut self, path: PathBuf) {
        self.path = path;
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingArtifact {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let _ = std::fs::remove_file(&self.path);
        if self.sqlite_sidecars {
            for suffix in ["-journal", "-wal", "-shm"] {
                let mut sidecar = self.path.as_os_str().to_os_string();
                sidecar.push(suffix);
                let _ = std::fs::remove_file(PathBuf::from(sidecar));
            }
        }
    }
}

/// Fail-closed durable binding error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ConfigConsensusStorageError {
    /// Nonempty authority cannot be silently adopted because the legacy log
    /// cannot prove its committed prefix.
    #[error("config consensus recovery requires an operator-approved authoritative snapshot")]
    RecoveryRequired,
    /// Persisted cluster/configuration/epoch differs from this deployment.
    #[error("config consensus storage identity does not match configuration")]
    IdentityMismatch,
    /// Durable schema is from an unsupported consensus version.
    #[error("unsupported config consensus storage schema")]
    SchemaVersionMismatch,
    /// A durable row or invariant is corrupt.
    #[error("config consensus durable state is corrupt")]
    CorruptState,
    /// Identity or membership could not be represented safely.
    #[error("invalid config consensus storage identity")]
    InvalidIdentity,
    /// SQLite or snapshot storage is unavailable.
    #[error("config consensus storage is unavailable")]
    BackendUnavailable,
}

#[derive(Clone)]
pub(crate) struct SqliteConfigLogStore {
    pub(crate) core: sqlite::ConfigConsensusCore,
}

#[derive(Clone)]
pub(crate) struct SqliteConfigStateMachine {
    core: sqlite::ConfigConsensusCore,
}

pub(crate) struct SqliteConfigSnapshotBuilder {
    core: sqlite::ConfigConsensusCore,
}

#[derive(Debug)]
pub(crate) struct ConfigDurableProgress {
    committed_present: AtomicBool,
    committed_index: AtomicU64,
    applied_epoch: tokio::sync::watch::Sender<u64>,
}

impl Default for ConfigDurableProgress {
    fn default() -> Self {
        let (applied_epoch, _) = tokio::sync::watch::channel(0);
        Self {
            committed_present: AtomicBool::new(false),
            committed_index: AtomicU64::new(0),
            applied_epoch,
        }
    }
}

impl ConfigDurableProgress {
    fn set_committed(&self, committed: Option<LogId<ConsensusNodeId>>) {
        if let Some(committed) = committed {
            self.committed_index
                .store(committed.index, Ordering::Release);
            self.committed_present.store(true, Ordering::Release);
        } else {
            self.committed_present.store(false, Ordering::Release);
            self.committed_index.store(0, Ordering::Release);
        }
    }

    pub(crate) fn committed_index(&self) -> Option<u64> {
        self.committed_present
            .load(Ordering::Acquire)
            .then(|| self.committed_index.load(Ordering::Acquire))
    }

    fn notify_applied(&self) {
        self.applied_epoch
            .send_modify(|epoch| *epoch = epoch.saturating_add(1));
    }

    pub(crate) fn subscribe_applied(&self) -> tokio::sync::watch::Receiver<u64> {
        self.applied_epoch.subscribe()
    }
}

type OpenedConfigStorage = (
    SqliteConfigLogStore,
    SqliteConfigStateMachine,
    Arc<ConfigDurableProgress>,
);

pub(crate) struct AdmittedSnapshotDirectory {
    pub(crate) path: PathBuf,
    pub(crate) binding_path: PathBuf,
    pub(crate) guard: Arc<std::fs::File>,
    pub(crate) owner: Arc<SnapshotDirectoryOwner>,
}

/// Keep both the descriptor-relative namespace and shutdown accounting alive
/// until an asynchronous receiver or blocking commit has disposed of its files.
pub(crate) struct SnapshotDirectoryOwner {
    _directory: Arc<std::fs::File>,
    _lock: Arc<crate::local_sqlite::AdmissionFileLock>,
    // Drop after the directory descriptor, as in ConfigConsensusCore.
    pub(crate) storage_owner: tokio::sync::watch::Sender<()>,
}

impl SnapshotDirectoryOwner {
    pub(crate) fn new(
        directory: Arc<std::fs::File>,
        lock: Arc<crate::local_sqlite::AdmissionFileLock>,
        storage_owner: tokio::sync::watch::Sender<()>,
    ) -> Self {
        Self {
            _directory: directory,
            _lock: lock,
            storage_owner,
        }
    }
}

pub(crate) async fn open(
    backend: &SqliteBackend,
    snapshot_dir: impl Into<PathBuf>,
    identity: ConsensusIdentity,
    expected_members: std::collections::BTreeSet<ConsensusNodeId>,
) -> Result<OpenedConfigStorage, ConfigConsensusStorageError> {
    open_with_recovery(backend, snapshot_dir, identity, expected_members, None).await
}

pub(crate) async fn open_with_recovery(
    backend: &SqliteBackend,
    snapshot_dir: impl Into<PathBuf>,
    identity: ConsensusIdentity,
    expected_members: std::collections::BTreeSet<ConsensusNodeId>,
    recovery: Option<ApprovedLegacyConfigRecovery>,
) -> Result<OpenedConfigStorage, ConfigConsensusStorageError> {
    let snapshot_directory = admit_snapshot_directory(backend, snapshot_dir.into())?;
    let already_completed = if let Some(approval) = recovery.as_ref() {
        let approval = approval.clone();
        sqlite::run_backend_sqlite_with_timeout(
            backend,
            std::time::Duration::from_secs(30),
            move |conn, cancellation| {
                cancellation.check_io()?;
                sqlite::completed_legacy_recovery_matches_sync(conn, &approval)
                    .map_err(|_| sqlite::invalid_data("legacy recovery probe failed"))
            },
        )
        .await
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
    } else {
        false
    };
    let staged = match recovery {
        Some(approval) if !already_completed => Some(
            tokio::time::timeout(
                SNAPSHOT_OPERATION_TIMEOUT,
                stage_legacy_recovery_snapshot(
                    &snapshot_directory.path,
                    approval,
                    snapshot_directory.owner.clone(),
                ),
            )
            .await
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)??,
        ),
        Some(_) | None => None,
    };
    let progress = Arc::new(ConfigDurableProgress::default());
    let core = sqlite::ConfigConsensusCore::initialize(
        backend,
        snapshot_directory,
        identity,
        expected_members,
        progress.clone(),
        staged,
    )
    .await?;
    validate_and_clean_snapshot_directory(&core).await?;
    let identity = core.identity;
    progress.set_committed(
        core.run_sqlite(move |conn| sqlite::read_committed_sync(conn, identity))
            .await
            .map_err(|_| ConfigConsensusStorageError::CorruptState)?,
    );
    Ok((
        SqliteConfigLogStore { core: core.clone() },
        SqliteConfigStateMachine { core },
        progress,
    ))
}

pub(crate) async fn open_with_voter_slots(
    backend: &SqliteBackend,
    snapshot_dir: PathBuf,
    identity: ConsensusIdentity,
    expected_members: std::collections::BTreeSet<ConsensusNodeId>,
    initial_slots: opc_consensus::voter_slots::VoterSlotTable,
) -> Result<OpenedConfigStorage, ConfigConsensusStorageError> {
    let directory = admit_snapshot_directory(backend, snapshot_dir)?;
    let progress = Arc::new(ConfigDurableProgress::default());
    let core = sqlite::ConfigConsensusCore::initialize_with_voter_slots(
        backend,
        directory,
        identity,
        expected_members,
        progress.clone(),
        initial_slots,
    )
    .await?;
    validate_and_clean_snapshot_directory(&core).await?;
    progress.set_committed(
        core.run_sqlite(move |conn| sqlite::read_committed_sync(conn, identity))
            .await
            .map_err(|_| ConfigConsensusStorageError::CorruptState)?,
    );
    Ok((
        SqliteConfigLogStore { core: core.clone() },
        SqliteConfigStateMachine { core },
        progress,
    ))
}

#[cfg(unix)]
fn admit_snapshot_directory(
    backend: &SqliteBackend,
    path: PathBuf,
) -> Result<AdmittedSnapshotDirectory, ConfigConsensusStorageError> {
    let created = match std::fs::create_dir(&path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(_) => return Err(ConfigConsensusStorageError::BackendUnavailable),
    };
    if created {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    }
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ConfigConsensusStorageError::InvalidIdentity);
    }
    let canonical = std::fs::canonicalize(&path)
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&canonical)
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    let opened = directory
        .metadata()
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err(ConfigConsensusStorageError::IdentityMismatch);
    }
    if !backend.is_ephemeral()
        && backend
            .durable_device_id()
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
            != opened.dev()
    {
        return Err(ConfigConsensusStorageError::InvalidIdentity);
    }
    directory
        .sync_all()
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    // A second opener must not sweep staging still owned by a live receiver,
    // builder, installer, or detached SQLite worker. This acquisition never
    // waits; process death releases the lock before the next bounded sweep.
    let lock = Arc::new(
        crate::local_sqlite::AdmissionFileLock::acquire(
            directory
                .try_clone()
                .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?,
        )
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?,
    );
    let directory = Arc::new(directory);
    let owner = Arc::new(SnapshotDirectoryOwner::new(
        directory.clone(),
        lock,
        tokio::sync::watch::channel(()).0,
    ));
    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    Ok(AdmittedSnapshotDirectory {
        path: descriptor_path,
        binding_path: canonical,
        guard: directory,
        owner,
    })
}

#[cfg(not(unix))]
fn admit_snapshot_directory(
    _backend: &SqliteBackend,
    _path: PathBuf,
) -> Result<AdmittedSnapshotDirectory, ConfigConsensusStorageError> {
    Err(ConfigConsensusStorageError::InvalidIdentity)
}

#[cfg(unix)]
fn validate_snapshot_binding(core: &sqlite::ConfigConsensusCore) -> io::Result<()> {
    let path = std::fs::symlink_metadata(core.snapshot_binding_path.as_ref())?;
    let opened = core._snapshot_dir_guard.metadata()?;
    if path.file_type().is_symlink()
        || !path.file_type().is_dir()
        || path.dev() != opened.dev()
        || path.ino() != opened.ino()
        || path.permissions().mode() & 0o077 != 0
    {
        return Err(sqlite::invalid_data(
            "config snapshot directory binding changed",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_snapshot_binding(_core: &sqlite::ConfigConsensusCore) -> io::Result<()> {
    Err(sqlite::invalid_data(
        "config snapshot directory binding is unsupported",
    ))
}

async fn stage_legacy_recovery_snapshot(
    snapshot_dir: &std::path::Path,
    approval: ApprovedLegacyConfigRecovery,
    owner: Arc<SnapshotDirectoryOwner>,
) -> Result<sqlite::StagedLegacyRecovery, ConfigConsensusStorageError> {
    let source = approval.snapshot_path();
    let source_file =
        open_read_nofollow(source).map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    validate_open_file_binding(source, &source_file)
        .map_err(|_| ConfigConsensusStorageError::IdentityMismatch)?;
    ensure_legacy_wal_is_offline(source)?;
    let source_binding = source_file
        .try_clone()
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    let metadata = source_file
        .metadata()
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > SNAPSHOT_MAX_BYTES {
        return Err(ConfigConsensusStorageError::InvalidIdentity);
    }
    let staged_path = snapshot_dir.join(format!("approved-legacy-{}.sqlite", uuid::Uuid::new_v4()));
    let mut input = tokio::fs::File::from_std(source_file);
    let (mut output, mut staged_cleanup) =
        StagingArtifact::create(staged_path.clone(), true, owner)
            .await
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .await
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(
                u64::try_from(read).map_err(|_| ConfigConsensusStorageError::InvalidIdentity)?,
            )
            .ok_or(ConfigConsensusStorageError::InvalidIdentity)?;
        if copied > SNAPSHOT_MAX_BYTES {
            let _ = tokio::fs::remove_file(&staged_path).await;
            return Err(ConfigConsensusStorageError::InvalidIdentity);
        }
        hasher.update(&buffer[..read]);
        output
            .write_all(&buffer[..read])
            .await
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    }
    output
        .sync_all()
        .await
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    drop(output);
    validate_open_file_binding(source, &source_binding)
        .map_err(|_| ConfigConsensusStorageError::IdentityMismatch)?;
    ensure_legacy_wal_is_offline(source)?;
    let checksum: [u8; 32] = hasher.finalize().into();
    if copied != metadata.len() || checksum != approval.expected_sha256() {
        let _ = tokio::fs::remove_file(&staged_path).await;
        return Err(ConfigConsensusStorageError::IdentityMismatch);
    }
    let mut permissions = tokio::fs::metadata(&staged_path)
        .await
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
        .permissions();
    permissions.set_readonly(true);
    tokio::fs::set_permissions(&staged_path, permissions)
        .await
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    staged_cleanup.disarm();
    Ok(sqlite::StagedLegacyRecovery {
        path: staged_path,
        approval,
    })
}

fn ensure_legacy_wal_is_offline(source: &Path) -> Result<(), ConfigConsensusStorageError> {
    let mut wal_name = source.as_os_str().to_os_string();
    wal_name.push("-wal");
    match std::fs::symlink_metadata(PathBuf::from(wal_name)) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(metadata) if metadata.file_type().is_file() && metadata.len() == 0 => Ok(()),
        Ok(_) => Err(ConfigConsensusStorageError::RecoveryRequired),
        Err(_) => Err(ConfigConsensusStorageError::BackendUnavailable),
    }
}

#[cfg(unix)]
fn validate_open_file_binding(path: &Path, opened: &std::fs::File) -> io::Result<()> {
    let path_metadata = std::fs::symlink_metadata(path)?;
    let opened_metadata = opened.metadata()?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_file()
        || path_metadata.dev() != opened_metadata.dev()
        || path_metadata.ino() != opened_metadata.ino()
        || path_metadata.len() != opened_metadata.len()
    {
        return Err(sqlite::invalid_data(
            "legacy config snapshot binding changed",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_open_file_binding(path: &Path, opened: &std::fs::File) -> io::Result<()> {
    let path_metadata = std::fs::symlink_metadata(path)?;
    let opened_metadata = opened.metadata()?;
    if !path_metadata.file_type().is_file() || path_metadata.len() != opened_metadata.len() {
        return Err(sqlite::invalid_data(
            "legacy config snapshot binding changed",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_read_nofollow(path: &Path) -> io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(unix))]
fn open_read_nofollow(path: &Path) -> io::Result<std::fs::File> {
    std::fs::File::open(path)
}

async fn validate_and_clean_snapshot_directory(
    core: &sqlite::ConfigConsensusCore,
) -> Result<(), ConfigConsensusStorageError> {
    let identity = core.identity;
    let members = core.expected_members.clone();
    let current = core
        .run_sqlite(move |conn| sqlite::read_current_snapshot_sync(conn, identity, &members))
        .await
        .map_err(|_| ConfigConsensusStorageError::CorruptState)?;
    let current_file_name = current
        .as_ref()
        .map(|(_, file_name, _, _)| file_name.as_str());
    if let Some((_, file_name, expected_checksum, expected_length)) = &current {
        let path = core.snapshot_dir.join(file_name);
        let file_type = tokio::time::timeout(
            SNAPSHOT_OPERATION_TIMEOUT,
            tokio::fs::symlink_metadata(&path),
        )
        .await
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
        .map_err(|_| ConfigConsensusStorageError::CorruptState)?
        .file_type();
        if !file_type.is_file() {
            return Err(ConfigConsensusStorageError::CorruptState);
        }
        let (_, checksum, length) =
            tokio::time::timeout(SNAPSHOT_OPERATION_TIMEOUT, verify_snapshot_envelope(&path))
                .await
                .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
                .map_err(|_| ConfigConsensusStorageError::CorruptState)?;
        if checksum != *expected_checksum || length != *expected_length {
            return Err(ConfigConsensusStorageError::CorruptState);
        }
    }

    let mut directory =
        snapshot_directory_io(tokio::fs::read_dir(core.snapshot_dir.as_ref())).await?;
    let mut inspected = 0_usize;
    let mut removed = false;
    while let Some(entry) = snapshot_directory_io(directory.next_entry()).await? {
        inspected = inspected
            .checked_add(1)
            .ok_or(ConfigConsensusStorageError::CorruptState)?;
        if inspected > SNAPSHOT_DIRECTORY_MAX_ENTRIES {
            return Err(ConfigConsensusStorageError::CorruptState);
        }
        let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let part_staging = ["incoming-", "promote-", "seal-", "snapshot-"]
            .iter()
            .any(|prefix| file_name.starts_with(prefix) && file_name.ends_with(".part"));
        let sqlite_staging = ["install-", "build-", "inspect-", "approved-legacy-"]
            .iter()
            .any(|prefix| file_name.starts_with(prefix))
            && [".sqlite", ".sqlite-journal", ".sqlite-wal", ".sqlite-shm"]
                .iter()
                .any(|suffix| file_name.ends_with(suffix));
        let orphan_snapshot = file_name.starts_with("snapshot-")
            && file_name.ends_with(".opc")
            && current_file_name != Some(file_name.as_str());
        if !part_staging && !sqlite_staging && !orphan_snapshot {
            continue;
        }
        let file_type = snapshot_directory_io(entry.file_type()).await?;
        if !file_type.is_file() && !file_type.is_symlink() {
            return Err(ConfigConsensusStorageError::CorruptState);
        }
        snapshot_directory_io(tokio::fs::remove_file(entry.path())).await?;
        removed = true;
    }
    if removed {
        snapshot_directory_io(sync_directory(core.snapshot_dir.as_ref())).await?;
    }
    let published = current.map(|(meta, file_name, checksum, length)| {
        Arc::new(PublishedSnapshot::new(
            meta,
            core.snapshot_dir.join(file_name),
            checksum,
            length,
        ))
    });
    *core.snapshot_gate.lock().await = published;
    Ok(())
}

async fn snapshot_directory_io<T>(
    operation: impl std::future::Future<Output = io::Result<T>>,
) -> Result<T, ConfigConsensusStorageError> {
    tokio::time::timeout(SNAPSHOT_OPERATION_TIMEOUT, operation)
        .await
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)
}

fn storage_error(
    subject: ErrorSubject<ConsensusNodeId>,
    verb: ErrorVerb,
    error: io::Error,
) -> StorageError<ConsensusNodeId> {
    StorageError::from_io_error(subject, verb, error)
}

fn range_to_half_open<R: RangeBounds<u64>>(range: &R) -> io::Result<(u64, Option<u64>)> {
    let start = match range.start_bound() {
        Bound::Included(value) => *value,
        Bound::Excluded(value) => value
            .checked_add(1)
            .ok_or_else(|| sqlite::invalid_data("config consensus log range overflow"))?,
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(value) => Some(
            value
                .checked_add(1)
                .ok_or_else(|| sqlite::invalid_data("config consensus log range overflow"))?,
        ),
        Bound::Excluded(value) => Some(*value),
        Bound::Unbounded => None,
    };
    Ok((start, end))
}

fn collect_bounded_entries<I>(entries: I) -> io::Result<Vec<Entry<ConfigRaftTypeConfig>>>
where
    I: IntoIterator<Item = Entry<ConfigRaftTypeConfig>>,
{
    let mut incoming = entries.into_iter();
    let mut bounded = Vec::with_capacity(
        incoming
            .size_hint()
            .0
            .min(sqlite::CONFIG_CONSENSUS_LOG_APPEND_MAX_ENTRIES),
    );
    for entry in incoming.by_ref() {
        if bounded.len() == sqlite::CONFIG_CONSENSUS_LOG_APPEND_MAX_ENTRIES {
            return Err(sqlite::invalid_data(
                "config consensus entry batch exceeds entry-count limit",
            ));
        }
        bounded.push(entry);
    }
    Ok(bounded)
}

impl RaftLogReader<ConfigRaftTypeConfig> for SqliteConfigLogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<ConfigRaftTypeConfig>>, StorageError<ConsensusNodeId>> {
        let (start, end) = range_to_half_open(&range)
            .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Read, error))?;
        if end.is_some_and(|end| start >= end) {
            return Ok(Vec::new());
        }
        let identity = self.core.identity;
        let members = self.core.expected_members.clone();
        self.core
            .run_sqlite(move |conn| {
                sqlite::read_log_range_sync(conn, identity, &members, start, end, None)
            })
            .await
            .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Read, error))
    }

    async fn limited_get_log_entries(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<Vec<Entry<ConfigRaftTypeConfig>>, StorageError<ConsensusNodeId>> {
        if start >= end {
            return Ok(Vec::new());
        }
        let identity = self.core.identity;
        let members = self.core.expected_members.clone();
        self.core
            .run_sqlite(move |conn| {
                let entries = sqlite::read_limited_log_range_sync(
                    conn,
                    identity,
                    &members,
                    start,
                    end,
                    DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES,
                )?;
                if entries.is_empty() {
                    return Err(sqlite::invalid_data(
                        "config consensus limited nonempty log range returned no entry",
                    ));
                }
                Ok(entries)
            })
            .await
            .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Read, error))
    }
}

impl RaftLogStorage<ConfigRaftTypeConfig> for SqliteConfigLogStore {
    type LogReader = Self;

    async fn get_log_state(
        &mut self,
    ) -> Result<LogState<ConfigRaftTypeConfig>, StorageError<ConsensusNodeId>> {
        let identity = self.core.identity;
        self.core
            .run_sqlite(move |conn| {
                Ok(LogState {
                    last_purged_log_id: sqlite::read_purged_sync(conn, identity)?,
                    last_log_id: sqlite::last_log_sync(conn, identity)?,
                })
            })
            .await
            .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Read, error))
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(
        &mut self,
        vote: &Vote<ConsensusNodeId>,
    ) -> Result<(), StorageError<ConsensusNodeId>> {
        let identity = self.core.identity;
        let members = self.core.expected_members.clone();
        let vote = *vote;
        self.core
            .run_sqlite(move |conn| sqlite::save_vote_sync(conn, identity, &members, &vote))
            .await
            .map_err(|error| storage_error(ErrorSubject::Vote, ErrorVerb::Write, error))
    }

    async fn read_vote(
        &mut self,
    ) -> Result<Option<Vote<ConsensusNodeId>>, StorageError<ConsensusNodeId>> {
        let identity = self.core.identity;
        let members = self.core.expected_members.clone();
        self.core
            .run_sqlite(move |conn| sqlite::read_vote_sync(conn, identity, &members))
            .await
            .map_err(|error| storage_error(ErrorSubject::Vote, ErrorVerb::Read, error))
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<ConsensusNodeId>>,
    ) -> Result<(), StorageError<ConsensusNodeId>> {
        let identity = self.core.identity;
        self.core
            .run_sqlite(move |conn| sqlite::save_committed_sync(conn, identity, committed))
            .await
            .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Write, error))?;
        self.core.durable_progress.set_committed(committed);
        Ok(())
    }

    async fn read_committed(
        &mut self,
    ) -> Result<Option<LogId<ConsensusNodeId>>, StorageError<ConsensusNodeId>> {
        let identity = self.core.identity;
        self.core
            .run_sqlite(move |conn| sqlite::read_committed_sync(conn, identity))
            .await
            .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Read, error))
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<ConfigRaftTypeConfig>,
    ) -> Result<(), StorageError<ConsensusNodeId>>
    where
        I: IntoIterator<Item = Entry<ConfigRaftTypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let entries = match collect_bounded_entries(entries) {
            Ok(entries) => entries,
            Err(error) => {
                callback.log_io_completed(Err(io::Error::other(
                    "config consensus log append exceeds entry-count limit",
                )));
                return Err(storage_error(ErrorSubject::Logs, ErrorVerb::Write, error));
            }
        };
        let hook = self.core.voter_admission.get().cloned();
        let identity = self.core.identity;
        let members = self.core.expected_members.clone();
        match self
            .core
            .run_sqlite_cancellable(move |conn, cancellation| {
                sqlite::voter_slots::check_fences_sync(
                    conn,
                    identity,
                    &entries,
                    hook.as_ref().and_then(std::sync::Weak::upgrade).as_deref(),
                )?;
                sqlite::append_logs_cancellable_sync(
                    conn,
                    identity,
                    &members,
                    &entries,
                    cancellation,
                )
            })
            .await
        {
            Ok(()) => {
                self.core.notify_voter_slots();
                callback.log_io_completed(Ok(()));
                Ok(())
            }
            Err(error) => {
                callback
                    .log_io_completed(Err(io::Error::other("config consensus log append failed")));
                Err(storage_error(ErrorSubject::Logs, ErrorVerb::Write, error))
            }
        }
    }

    async fn truncate(
        &mut self,
        log_id: LogId<ConsensusNodeId>,
    ) -> Result<(), StorageError<ConsensusNodeId>> {
        let identity = self.core.identity;
        self.core
            .run_sqlite(move |conn| sqlite::truncate_logs_sync(conn, identity, &log_id))
            .await
            .map_err(|error| storage_error(ErrorSubject::Log(log_id), ErrorVerb::Delete, error))?;
        self.core.notify_voter_slots();
        Ok(())
    }

    async fn purge(
        &mut self,
        log_id: LogId<ConsensusNodeId>,
    ) -> Result<(), StorageError<ConsensusNodeId>> {
        validate_snapshot_binding(&self.core)
            .map_err(|error| storage_error(ErrorSubject::Log(log_id), ErrorVerb::Delete, error))?;
        let identity = self.core.identity;
        // Openraft queues snapshot installation on its independent state-machine
        // worker before issuing purge. Do not mistake that in-flight install
        // for durable application, or remove its logs before it commits. Wait
        // outside SQLite's worker/connection under the existing 30-second bound.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut progress = self.core.durable_progress.subscribe_applied();
        let result = async {
            loop {
                let purged = self
                    .core
                    .run_sqlite_cancellable_until(deadline, move |conn, cancellation| {
                        cancellation.check_io()?;
                        if sqlite::read_applied_sync(conn, identity)?
                            .is_none_or(|applied| applied.index < log_id.index)
                        {
                            return Ok(false);
                        }
                        sqlite::purge_logs_sync(conn, identity, &log_id)?;
                        Ok(true)
                    })
                    .await?;
                if purged {
                    return Ok(());
                }
                tokio::time::timeout_at(deadline, progress.changed())
                    .await
                    .map_err(|_| {
                        sqlite::invalid_data("config consensus purge application wait expired")
                    })?
                    .map_err(|_| {
                        sqlite::invalid_data("config consensus application progress unavailable")
                    })?;
                validate_snapshot_binding(&self.core)?;
            }
        }
        .await;
        result.map_err(|error| storage_error(ErrorSubject::Log(log_id), ErrorVerb::Delete, error))
    }
}

impl RaftStateMachine<ConfigRaftTypeConfig> for SqliteConfigStateMachine {
    type SnapshotBuilder = SqliteConfigSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<
        (
            Option<LogId<ConsensusNodeId>>,
            StoredMembership<ConsensusNodeId, opc_consensus::engine::EmptyNode>,
        ),
        StorageError<ConsensusNodeId>,
    > {
        let identity = self.core.identity;
        let members = self.core.expected_members.clone();
        self.core
            .run_sqlite(move |conn| {
                Ok((
                    sqlite::read_applied_sync(conn, identity)?,
                    sqlite::read_membership_sync(conn, identity, &members)?,
                ))
            })
            .await
            .map_err(|error| storage_error(ErrorSubject::StateMachine, ErrorVerb::Read, error))
    }

    async fn apply<I>(
        &mut self,
        entries: I,
    ) -> Result<Vec<ConfigConsensusResponse>, StorageError<ConsensusNodeId>>
    where
        I: IntoIterator<Item = Entry<ConfigRaftTypeConfig>> + Send,
        I::IntoIter: Send,
    {
        #[cfg(test)]
        let _apply_permit = self.core.apply_gate.acquire().await.map_err(|_| {
            storage_error(
                ErrorSubject::StateMachine,
                ErrorVerb::Write,
                io::Error::other("config consensus test apply gate closed"),
            )
        })?;
        let identity = self.core.identity;
        let members = self.core.expected_members.clone();
        let audit_key = self.core.audit_key.clone();
        let audit_keys = self.core.management_audit_keys.clone();
        let entries = collect_bounded_entries(entries)
            .map_err(|error| storage_error(ErrorSubject::StateMachine, ErrorVerb::Write, error))?;
        let responses = self
            .core
            .run_sqlite_cancellable(move |conn, cancellation| {
                sqlite::apply_entries_cancellable_sync(
                    conn,
                    identity,
                    &members,
                    entries,
                    cancellation,
                    &audit_key,
                    audit_keys.as_deref(),
                )
            })
            .await
            .map_err(|error| storage_error(ErrorSubject::StateMachine, ErrorVerb::Write, error))?;
        self.core.notify_voter_slots();
        self.core.durable_progress.notify_applied();
        Ok(responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        SqliteConfigSnapshotBuilder {
            core: self.core.clone(),
        }
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<ConfigSnapshotFile>, StorageError<ConsensusNodeId>> {
        validate_snapshot_binding(&self.core).map_err(|error| {
            storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
        })?;
        let owner = self.core.snapshot_directory_owner().map_err(|error| {
            storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
        })?;
        tokio::time::timeout(
            SNAPSHOT_OPERATION_TIMEOUT,
            ConfigSnapshotFile::create_owned(
                self.core
                    .snapshot_dir
                    .join(format!("incoming-{}.part", uuid::Uuid::new_v4())),
                owner,
            ),
        )
        .await
        .map_err(|_| {
            storage_error(
                ErrorSubject::Snapshot(None),
                ErrorVerb::Write,
                sqlite::invalid_data("config consensus snapshot receiver timed out"),
            )
        })?
        .map(Box::new)
        .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<ConsensusNodeId, opc_consensus::engine::EmptyNode>,
        mut snapshot: Box<ConfigSnapshotFile>,
    ) -> Result<(), StorageError<ConsensusNodeId>> {
        let deadline = tokio::time::Instant::now()
            .checked_add(SNAPSHOT_OPERATION_TIMEOUT)
            .ok_or_else(|| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    sqlite::invalid_data("config consensus snapshot install deadline overflow"),
                )
            })?;
        let result = async {
            let owner = self.core.snapshot_directory_owner().map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            validate_snapshot_binding(&self.core).map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            let _guard = tokio::time::timeout_at(deadline, self.core.snapshot_build_gate.lock())
                .await
                .map_err(|_| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Write,
                        sqlite::invalid_data("config consensus snapshot install timed out"),
                    )
                })?;
            tokio::time::timeout_at(deadline, snapshot.sync_all())
                .await
                .map_err(|_| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Write,
                        sqlite::invalid_data("config consensus snapshot install timed out"),
                    )
                })?
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Write,
                        error,
                    )
                })?;
            let incoming = snapshot.path().to_path_buf();
            snapshot.disarm_cleanup();
            drop(snapshot);
            let incoming_cleanup =
                StagingArtifact::file(incoming.clone()).with_owner(owner.clone());
            let (payload_length, checksum, total_length) =
                tokio::time::timeout_at(deadline, verify_snapshot_envelope(&incoming))
                    .await
                    .map_err(|_| {
                        storage_error(
                            ErrorSubject::Snapshot(Some(meta.signature())),
                            ErrorVerb::Read,
                            sqlite::invalid_data("config consensus snapshot install timed out"),
                        )
                    })?
                    .map_err(|error| {
                        storage_error(
                            ErrorSubject::Snapshot(Some(meta.signature())),
                            ErrorVerb::Read,
                            error,
                        )
                    })?;
            let raw = self
                .core
                .snapshot_dir
                .join(format!("install-{}.sqlite", uuid::Uuid::new_v4()));
            let raw_cleanup = tokio::time::timeout_at(
                deadline,
                extract_snapshot_database(&incoming, &raw, payload_length, owner.clone()),
            )
            .await
            .map_err(|_| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    sqlite::invalid_data("config consensus snapshot install timed out"),
                )
            })?
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            let file_name = format!("snapshot-{}.opc", uuid::Uuid::new_v4());
            let final_path = self.core.snapshot_dir.join(&file_name);
            let promoting = self
                .core
                .snapshot_dir
                .join(format!("promote-{}.part", uuid::Uuid::new_v4()));
            let mut final_cleanup = tokio::time::timeout_at(
                deadline,
                copy_and_promote(&incoming, &promoting, &final_path, owner),
            )
            .await
            .map_err(|_| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    sqlite::invalid_data("config consensus snapshot install timed out"),
                )
            })?
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            let identity = self.core.identity;
            let members = self.core.expected_members.clone();
            let audit_key = self.core.audit_key.clone();
            let raw_for_install = raw.clone();
            let meta_for_install = meta.clone();
            let file_name_for_install = file_name.clone();
            let voter_hook = self.core.voter_admission.get().cloned();
            #[cfg(test)]
            let hooks = self.core.snapshot_test_hooks.clone();
            self.core
                .run_sqlite_cancellable_until(deadline, move |conn, cancellation| {
                    let _incoming_cleanup = incoming_cleanup;
                    let _raw_cleanup = raw_cleanup;
                    #[cfg(test)]
                    hooks.before_commit(conn, cancellation)?;
                    sqlite::read_current_snapshot_sync(conn, identity, &members)?;
                    if let Some(runtime) = voter_hook.as_ref().and_then(std::sync::Weak::upgrade) {
                        let source = sqlite::validate_snapshot_database_sync(
                            &raw_for_install,
                            identity,
                            &members,
                            &audit_key,
                            &meta_for_install,
                            cancellation,
                        )?;
                        let state = sqlite::voter_slots::read_sync(&source)?.ok_or_else(|| {
                            sqlite::invalid_data("snapshot lacks config voter profile")
                        })?;
                        let incoming_members = meta_for_install
                            .last_membership
                            .nodes()
                            .map(|(node, _)| *node)
                            .collect();
                        if !runtime.snapshot_fences_acknowledged(state.table(), &incoming_members) {
                            return Err(sqlite::invalid_data(
                                "config snapshot lacks acknowledged voter fences",
                            ));
                        }
                    }
                    sqlite::install_snapshot_database_cancellable_sync(
                        conn,
                        identity,
                        &members,
                        &audit_key,
                        &raw_for_install,
                        &meta_for_install,
                        &file_name_for_install,
                        checksum,
                        total_length,
                        cancellation,
                    )?;
                    // The transaction owns this decision even if its awaiting
                    // runtime has gone away after commit authorization.
                    final_cleanup.disarm();
                    Ok(())
                })
                .await
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Write,
                        error,
                    )
                })?;
            publish_snapshot(
                &self.core,
                PublishedSnapshot::new(meta.clone(), final_path, checksum, total_length),
            )
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            Ok(())
        }
        .await;
        if result.is_err() {
            opc_redaction::metrics::METRICS
                .persist_snapshot_install_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            self.core.notify_voter_slots();
            self.core.durable_progress.notify_applied();
        }
        result
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<ConfigRaftTypeConfig>>, StorageError<ConsensusNodeId>> {
        #[cfg(test)]
        self.core
            .snapshot_test_hooks
            .reads_started
            .fetch_add(1, Ordering::AcqRel);
        validate_snapshot_binding(&self.core)
            .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, error))?;
        // Clone only the immutable record under the publication gate. No read
        // enters the SQLite worker, which can still be draining a build commit.
        let published = {
            #[cfg(test)]
            if self.core.snapshot_gate.try_lock().is_err() {
                self.core.snapshot_test_hooks.read_gate_blocked.notify_one();
            }
            let current =
                tokio::time::timeout(SNAPSHOT_OPERATION_TIMEOUT, self.core.snapshot_gate.lock())
                    .await
                    .map_err(|_| {
                        storage_error(
                            ErrorSubject::Snapshot(None),
                            ErrorVerb::Read,
                            sqlite::invalid_data("config consensus snapshot read gate timed out"),
                        )
                    })?;
            current.clone()
        };
        let Some(published) = published else {
            return Ok(None);
        };
        #[cfg(test)]
        if self
            .core
            .snapshot_test_hooks
            .pause_pinned_read
            .load(Ordering::Acquire)
        {
            self.core.snapshot_test_hooks.read_pinned.notify_one();
            self.core
                .snapshot_test_hooks
                .resume_pinned_read
                .notified()
                .await;
        }
        let meta = published.meta.clone();
        let expected_checksum = published.checksum;
        let expected_length = published.length;
        // A fresh open has an independent file offset. The record pins the path
        // through open, then the descriptor itself survives a concurrent unlink.
        let mut file = tokio::time::timeout(
            SNAPSHOT_OPERATION_TIMEOUT,
            ConfigSnapshotFile::open(published.path.clone()),
        )
        .await
        .map_err(|_| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Read,
                sqlite::invalid_data("config consensus snapshot read timed out"),
            )
        })?
        .map_err(|error| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Read,
                error,
            )
        })?;
        drop(published);
        let (_, checksum, length) = async {
            #[cfg(test)]
            if self
                .core
                .snapshot_test_hooks
                .pause_open_read
                .load(Ordering::Acquire)
            {
                self.core.snapshot_test_hooks.read_opened.notify_one();
                snapshot_read_step(async {
                    self.core.snapshot_test_hooks.resume_read.notified().await;
                    Ok(())
                })
                .await?;
            }
            verify_open_snapshot_envelope(&mut file).await
        }
        .await
        .map_err(|error| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Read,
                error,
            )
        })?;
        if checksum != expected_checksum || length != expected_length {
            return Err(storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Read,
                sqlite::invalid_data("config consensus snapshot metadata mismatch"),
            ));
        }
        Ok(Some(Snapshot {
            meta,
            snapshot: Box::new(file),
        }))
    }
}

impl RaftSnapshotBuilder<ConfigRaftTypeConfig> for SqliteConfigSnapshotBuilder {
    async fn build_snapshot(
        &mut self,
    ) -> Result<Snapshot<ConfigRaftTypeConfig>, StorageError<ConsensusNodeId>> {
        validate_snapshot_binding(&self.core).map_err(|error| {
            storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
        })?;
        let _guard = tokio::time::timeout(
            SNAPSHOT_OPERATION_TIMEOUT,
            self.core.snapshot_build_gate.lock(),
        )
        .await
        .map_err(|_| {
            storage_error(
                ErrorSubject::Snapshot(None),
                ErrorVerb::Write,
                sqlite::invalid_data("config consensus snapshot build gate timed out"),
            )
        })?;
        let deadline = tokio::time::Instant::now()
            .checked_add(SNAPSHOT_OPERATION_TIMEOUT)
            .ok_or_else(|| {
                storage_error(
                    ErrorSubject::Snapshot(None),
                    ErrorVerb::Write,
                    sqlite::invalid_data("config consensus snapshot build deadline overflow"),
                )
            })?;
        #[cfg(test)]
        self.core
            .snapshot_test_hooks
            .build_gate_acquired
            .store(true, Ordering::Release);
        #[cfg(test)]
        self.core
            .snapshot_test_hooks
            .builds_started
            .fetch_add(1, Ordering::AcqRel);
        #[cfg(test)]
        if self
            .core
            .snapshot_test_hooks
            .pause_build
            .load(Ordering::Acquire)
        {
            self.core.snapshot_test_hooks.build_started.notify_one();
            self.core.snapshot_test_hooks.resume_build.notified().await;
        }
        let raw = self
            .core
            .snapshot_dir
            .join(format!("build-{}.sqlite", uuid::Uuid::new_v4()));
        let owner = self.core.snapshot_directory_owner().map_err(|error| {
            storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
        })?;
        let raw_cleanup = StagingArtifact::sqlite(raw.clone()).with_owner(owner.clone());
        let identity = self.core.identity;
        let members = self.core.expected_members.clone();
        let audit_key = self.core.audit_key.clone();
        let raw_for_build = raw.clone();
        let (last_log_id, last_membership, raw_cleanup) = self
            .core
            .run_sqlite_cancellable_until(deadline, move |conn, cancellation| {
                let cleanup = raw_cleanup;
                let (last_log_id, last_membership) =
                    sqlite::build_snapshot_database_cancellable_sync(
                        conn,
                        identity,
                        &members,
                        &audit_key,
                        &raw_for_build,
                        cancellation,
                    )?;
                Ok((last_log_id, last_membership, cleanup))
            })
            .await
            .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, error))?;
        #[cfg(test)]
        if self
            .core
            .snapshot_test_hooks
            .pause_captured_build
            .load(Ordering::Acquire)
        {
            self.core.snapshot_test_hooks.build_captured.notify_one();
            self.core
                .snapshot_test_hooks
                .resume_captured_build
                .notified()
                .await;
        }
        let snapshot_id = uuid::Uuid::new_v4().to_string();
        let file_name = format!("snapshot-{snapshot_id}.opc");
        let final_path = self.core.snapshot_dir.join(&file_name);
        let staging = self
            .core
            .snapshot_dir
            .join(format!("snapshot-{snapshot_id}.part"));
        let (checksum, length, mut final_cleanup) =
            tokio::time::timeout_at(deadline, envelope_snapshot_database(&raw, &staging, owner))
                .await
                .map_err(|_| {
                    storage_error(
                        ErrorSubject::Snapshot(None),
                        ErrorVerb::Write,
                        sqlite::invalid_data("config consensus snapshot build timed out"),
                    )
                })?
                .map_err(|error| {
                    storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
                })?;
        std::fs::rename(&staging, &final_path).map_err(|error| {
            storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
        })?;
        final_cleanup.replace_path(final_path.clone());
        tokio::time::timeout_at(deadline, sync_directory(&self.core.snapshot_dir))
            .await
            .map_err(|_| {
                storage_error(
                    ErrorSubject::Snapshot(None),
                    ErrorVerb::Write,
                    sqlite::invalid_data("config consensus snapshot build timed out"),
                )
            })?
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
        let _ = tokio::time::timeout_at(deadline, tokio::fs::remove_file(&raw)).await;
        let meta = SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id,
        };
        let snapshot =
            tokio::time::timeout_at(deadline, ConfigSnapshotFile::open(final_path.clone()))
                .await
                .map_err(|_| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        sqlite::invalid_data("config consensus snapshot build timed out"),
                    )
                })?
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        error,
                    )
                })?;
        let identity = self.core.identity;
        let members = self.core.expected_members.clone();
        let meta_for_save = meta.clone();
        let file_name_for_save = file_name.clone();
        #[cfg(test)]
        let hooks = self.core.snapshot_test_hooks.clone();
        self.core
            .run_sqlite_cancellable_until(deadline, move |conn, cancellation| {
                let _raw_cleanup = raw_cleanup;
                #[cfg(test)]
                hooks.before_commit(conn, cancellation)?;
                cancellation.check_io()?;
                sqlite::read_current_snapshot_sync(conn, identity, &members)?;
                sqlite::save_current_snapshot_sync(
                    conn,
                    identity,
                    &members,
                    &meta_for_save,
                    &file_name_for_save,
                    checksum,
                    length,
                )?;
                // Disarm in the worker that knows the durable outcome, never
                // in the cancellable future awaiting that outcome.
                final_cleanup.disarm();
                #[cfg(test)]
                if hooks.pause_published_build.load(Ordering::Acquire) {
                    // Hold only the return after an actual successful commit.
                    // An authorized SQLite commit remains owned past its deadline.
                    hooks.build_published.notify_one();
                    while hooks.pause_published_build.load(Ordering::Acquire) {
                        std::thread::park_timeout(std::time::Duration::from_millis(1));
                    }
                }
                Ok(())
            })
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
        publish_snapshot(
            &self.core,
            PublishedSnapshot::new(meta.clone(), final_path, checksum, length),
        )
        .await
        .map_err(|error| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Write,
                error,
            )
        })?;
        #[cfg(test)]
        {
            self.core
                .snapshot_test_hooks
                .builds_returned_ok
                .fetch_add(1, Ordering::AcqRel);
            self.core.snapshot_test_hooks.build_returned_ok.notify_one();
        }
        Ok(Snapshot {
            meta,
            snapshot: Box::new(snapshot),
        })
    }
}

async fn envelope_snapshot_database(
    raw: &Path,
    output: &Path,
    owner: Arc<SnapshotDirectoryOwner>,
) -> io::Result<([u8; 32], u64, StagingArtifact)> {
    let metadata = tokio::fs::metadata(raw).await?;
    if metadata.len() == 0 || metadata.len() > SNAPSHOT_MAX_BYTES {
        return Err(sqlite::invalid_data(
            "config consensus snapshot size is invalid",
        ));
    }
    let mut source = tokio::fs::File::from_std(open_read_nofollow(raw)?);
    let (mut destination, cleanup) =
        StagingArtifact::create(output.to_path_buf(), false, owner).await?;
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = source.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        copied =
            copied
                .checked_add(u64::try_from(read).map_err(|_| {
                    sqlite::invalid_data("config consensus snapshot length overflow")
                })?)
                .ok_or_else(|| sqlite::invalid_data("config consensus snapshot length overflow"))?;
        if copied > SNAPSHOT_MAX_BYTES {
            return Err(sqlite::invalid_data(
                "config consensus snapshot is oversized",
            ));
        }
        hasher.update(&buffer[..read]);
        destination.write_all(&buffer[..read]).await?;
    }
    if copied != metadata.len() {
        return Err(sqlite::invalid_data(
            "config consensus snapshot copy length mismatch",
        ));
    }
    let checksum: [u8; 32] = hasher.finalize().into();
    destination.write_all(SNAPSHOT_FOOTER_MAGIC).await?;
    destination
        .write_all(&super::types::CONFIG_CONSENSUS_SNAPSHOT_VERSION.to_be_bytes())
        .await?;
    destination.write_all(&copied.to_be_bytes()).await?;
    destination.write_all(&checksum).await?;
    destination.sync_all().await?;
    let total = copied
        .checked_add(SNAPSHOT_FOOTER_BYTES)
        .ok_or_else(|| sqlite::invalid_data("config consensus snapshot length overflow"))?;
    Ok((checksum, total, cleanup))
}

pub(crate) async fn verify_snapshot_envelope(path: &Path) -> io::Result<(u64, [u8; 32], u64)> {
    let mut file = ConfigSnapshotFile::open(path.to_path_buf()).await?;
    verify_open_snapshot_envelope(&mut file).await
}

/// Verify the selected descriptor even if publication has unlinked its path.
/// A successful verification rewinds it for the snapshot transport reader.
pub(crate) async fn verify_open_snapshot_envelope(
    file: &mut ConfigSnapshotFile,
) -> io::Result<(u64, [u8; 32], u64)> {
    verify_snapshot_reader(file).await
}

// Limit stalls, not the size-dependent duration of a healthy verification.
// Each bounded chunk must make progress before a fresh idle budget starts.
async fn snapshot_read_step<T>(
    operation: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::time::timeout(SNAPSHOT_OPERATION_TIMEOUT, operation)
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "config consensus snapshot verification stalled",
            )
        })?
}

async fn verify_snapshot_reader(
    file: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin),
) -> io::Result<(u64, [u8; 32], u64)> {
    let total = snapshot_read_step(file.seek(io::SeekFrom::End(0))).await?;
    if total <= SNAPSHOT_FOOTER_BYTES || total > SNAPSHOT_MAX_BYTES + SNAPSHOT_FOOTER_BYTES {
        return Err(sqlite::invalid_data(
            "config consensus snapshot size is invalid",
        ));
    }
    let payload_length = total - SNAPSHOT_FOOTER_BYTES;
    snapshot_read_step(file.seek(io::SeekFrom::Start(payload_length))).await?;
    let mut magic = [0_u8; 8];
    snapshot_read_step(file.read_exact(&mut magic)).await?;
    if &magic != SNAPSHOT_FOOTER_MAGIC {
        return Err(sqlite::invalid_data(
            "config consensus snapshot footer is invalid",
        ));
    }
    let mut revision = [0_u8; 2];
    snapshot_read_step(file.read_exact(&mut revision)).await?;
    if u16::from_be_bytes(revision) != super::types::CONFIG_CONSENSUS_SNAPSHOT_VERSION {
        return Err(sqlite::invalid_data(
            "config consensus snapshot revision is unsupported",
        ));
    }
    let mut length = [0_u8; 8];
    snapshot_read_step(file.read_exact(&mut length)).await?;
    if u64::from_be_bytes(length) != payload_length {
        return Err(sqlite::invalid_data(
            "config consensus snapshot length footer mismatch",
        ));
    }
    let mut expected = [0_u8; 32];
    snapshot_read_step(file.read_exact(&mut expected)).await?;
    snapshot_read_step(file.seek(io::SeekFrom::Start(0))).await?;
    let mut remaining = payload_length;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| sqlite::invalid_data("config consensus snapshot read overflow"))?;
        let read = snapshot_read_step(file.read(&mut buffer[..requested])).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "config consensus snapshot was truncated",
            ));
        }
        remaining -= u64::try_from(read)
            .map_err(|_| sqlite::invalid_data("config consensus snapshot read overflow"))?;
        hasher.update(&buffer[..read]);
    }
    let actual: [u8; 32] = hasher.finalize().into();
    if actual != expected {
        return Err(sqlite::invalid_data(
            "config consensus snapshot checksum mismatch",
        ));
    }
    snapshot_read_step(file.seek(io::SeekFrom::Start(0))).await?;
    Ok((payload_length, actual, total))
}

/// Verify the complete artifact outside the engine callback, before admission changes.
pub(crate) async fn inspect_voter_snapshot(
    core: &sqlite::ConfigConsensusCore,
    snapshot: &mut ConfigSnapshotFile,
    meta: &SnapshotMeta<ConsensusNodeId, opc_consensus::engine::EmptyNode>,
    deadline: tokio::time::Instant,
) -> io::Result<opc_consensus::voter_slots::VoterSlotTable> {
    let owner = core.snapshot_directory_owner()?;
    let budget = deadline.saturating_duration_since(tokio::time::Instant::now());
    if budget.is_zero() {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "config voter snapshot inspection deadline",
        ));
    }
    snapshot.sync_all().await?;
    let (length, _, _) = verify_snapshot_envelope(snapshot.path()).await?;
    let raw = core
        .snapshot_dir
        .join(format!("inspect-{}.sqlite", uuid::Uuid::new_v4()));
    let cleanup = extract_snapshot_database(snapshot.path(), &raw, length, owner).await?;
    let identity = core.identity;
    let members = core.expected_members.clone();
    let key = core.audit_key.clone();
    let meta = meta.clone();
    // The accepted file copy makes progress independently of its caller.
    // Admission to the serialized validator gets a fresh bounded wait.
    core.run_sqlite_cancellable_until(
        tokio::time::Instant::now() + budget,
        move |conn, cancellation| {
            let _cleanup = cleanup;
            let source = sqlite::validate_snapshot_database_sync(
                &raw,
                identity,
                &members,
                &key,
                &meta,
                cancellation,
            )?;
            let incoming = sqlite::voter_slots::read_sync(&source)?
                .ok_or_else(|| sqlite::invalid_data("snapshot lacks config voter profile"))?;
            let current = sqlite::voter_slots::read_sync(conn)?
                .ok_or_else(|| sqlite::invalid_data("store lacks config voter profile"))?;
            incoming
                .table()
                .validate_successor_of(current.table())
                .map_err(|_| sqlite::invalid_data("config voter snapshot regressed"))?;
            Ok(incoming.table().clone())
        },
    )
    .await
}

async fn extract_snapshot_database(
    envelope: &Path,
    destination: &Path,
    payload_length: u64,
    owner: Arc<SnapshotDirectoryOwner>,
) -> io::Result<StagingArtifact> {
    let mut source = tokio::fs::File::from_std(open_read_nofollow(envelope)?);
    let (mut output, cleanup) =
        StagingArtifact::create(destination.to_path_buf(), true, owner).await?;
    let mut remaining = payload_length;
    let mut buffer = vec![0_u8; 1024 * 1024];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| sqlite::invalid_data("config consensus snapshot extract overflow"))?;
        let read = source.read(&mut buffer[..requested]).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "config consensus snapshot was truncated",
            ));
        }
        output.write_all(&buffer[..read]).await?;
        remaining -= u64::try_from(read)
            .map_err(|_| sqlite::invalid_data("config consensus snapshot extract overflow"))?;
    }
    output.sync_all().await?;
    Ok(cleanup)
}

async fn copy_and_promote(
    source: &Path,
    staging: &Path,
    final_path: &Path,
    owner: Arc<SnapshotDirectoryOwner>,
) -> io::Result<StagingArtifact> {
    let mut input = tokio::fs::File::from_std(open_read_nofollow(source)?);
    let (mut output, mut cleanup) =
        StagingArtifact::create(staging.to_path_buf(), false, owner).await?;
    tokio::io::copy(&mut input, &mut output).await?;
    output.sync_all().await?;
    drop(output);
    std::fs::rename(staging, final_path)?;
    cleanup.replace_path(final_path.to_path_buf());
    sync_directory(
        final_path
            .parent()
            .ok_or_else(|| sqlite::invalid_data("config snapshot directory is missing"))?,
    )
    .await?;
    Ok(cleanup)
}

async fn sync_directory(path: &std::path::Path) -> io::Result<()> {
    tokio::fs::File::open(path).await?.sync_all().await
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::Duration;

    use opc_consensus::engine::{CommittedLeaderId, EntryPayload, Membership, RaftSnapshotBuilder};
    use opc_crypto::{encrypt_envelope_with_handle_and_nonce, CryptoEnvelopeV1};
    use opc_key::{
        serialize_bound_aad, AeadAlgorithm, ConfigAad, EnvelopeAad, KeyHandle, KeyId, KeyPurpose,
        Zeroizing, AEAD_TAG_LEN, AES_256_GCM_SIV_KEY_LEN, AES_256_GCM_SIV_NONCE_LEN,
    };
    use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

    use super::*;
    use crate::consensus::{
        ConfigConsensusClusterId, ConfigConsensusCommand, ConfigConsensusConfigurationEpoch,
        ConfigConsensusConfigurationId, ConfigConsensusRequestId, ConfigMutationIntent,
        PreparedConfigCommit, CONFIG_CONSENSUS_COMMAND_VERSION,
    };
    use crate::{CommitRecord, CommitSource};

    fn identity() -> ConsensusIdentity {
        ConsensusIdentity::new(
            ConfigConsensusClusterId::new("config-snapshot-install-tests").expect("cluster ID"),
            ConfigConsensusConfigurationId::from_bytes([0x83; 32]),
            ConfigConsensusConfigurationEpoch::new(1).expect("configuration epoch"),
        )
    }

    fn node_id() -> ConsensusNodeId {
        ConsensusNodeId::new(9).expect("node ID")
    }

    fn members() -> BTreeSet<ConsensusNodeId> {
        BTreeSet::from([node_id()])
    }

    fn shared_audit_key() -> crate::AuditKey {
        crate::AuditKey::new([0x54; 32]).expect("shared audit key")
    }

    fn log_id(index: u64) -> LogId<ConsensusNodeId> {
        LogId::new(CommittedLeaderId::new(1, node_id()), index)
    }

    fn membership_entry() -> Entry<ConfigRaftTypeConfig> {
        Entry {
            log_id: log_id(0),
            payload: EntryPayload::Membership(Membership::new(vec![members()], members())),
        }
    }

    struct HostileSizeHintOnce(Option<Entry<ConfigRaftTypeConfig>>);

    impl Iterator for HostileSizeHintOnce {
        type Item = Entry<ConfigRaftTypeConfig>;

        fn next(&mut self) -> Option<Self::Item> {
            self.0.take()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (usize::MAX, Some(usize::MAX))
        }
    }

    #[test]
    fn entry_collection_caps_hostile_hints_and_rejects_oversized_batches() {
        let bounded = collect_bounded_entries(HostileSizeHintOnce(Some(membership_entry())))
            .expect("hostile hint is capped");
        assert_eq!(1, bounded.len());
        assert!(bounded.capacity() <= sqlite::CONFIG_CONSENSUS_LOG_APPEND_MAX_ENTRIES);

        let oversized = std::iter::repeat_with(membership_entry)
            .take(sqlite::CONFIG_CONSENSUS_LOG_APPEND_MAX_ENTRIES + 1);
        assert!(collect_bounded_entries(oversized).is_err());
    }

    fn snapshot_commit_record(
        tx_id: TxId,
        parent_tx_id: Option<TxId>,
        version: u64,
        committed_at: Timestamp,
        confirmed_deadline: Option<Timestamp>,
        marker: u8,
    ) -> CommitRecord {
        let principal = "spiffe://test.example/tenant/tenant-a/ns/core/sa/config".to_owned();
        let schema_digest = SchemaDigest::from_bytes([marker; 32]);
        let tenant = TenantId::from_static("tenant-a");
        let key_id = KeyId::new("config-snapshot-install-key").expect("key ID");
        let handle = KeyHandle::new(
            key_id,
            KeyPurpose::Config,
            tenant.clone(),
            Zeroizing::new([0x73; AES_256_GCM_SIV_KEY_LEN]),
        );
        let aad = EnvelopeAad::config(
            tenant,
            version,
            ConfigAad::new(
                tx_id,
                parent_tx_id,
                committed_at,
                &principal,
                schema_digest,
                "running",
            )
            .expect("config AAD"),
        );
        let plaintext = [marker; 32];
        let encrypted_blob = encrypt_envelope_with_handle_and_nonce(
            &handle,
            &aad,
            &plaintext,
            [marker; AES_256_GCM_SIV_NONCE_LEN],
        )
        .expect("encrypted config envelope");
        CommitRecord {
            tx_id,
            parent_tx_id,
            version: ConfigVersion::new(version),
            committed_at,
            principal,
            source: CommitSource::Gnmi,
            schema_digest,
            plaintext_digest: Sha256::digest(plaintext).to_vec(),
            encrypted_blob,
            rollback_point: false,
            confirmed_deadline,
        }
    }

    fn mutation_entry() -> Entry<ConfigRaftTypeConfig> {
        Entry {
            log_id: log_id(1),
            payload: EntryPayload::Normal(ConfigConsensusCommand {
                schema_version: CONFIG_CONSENSUS_COMMAND_VERSION,
                identity: identity(),
                request_id: ConfigConsensusRequestId::from_bytes([0x91; 16]),
                logical_time: opc_types::Timestamp::now_utc(),
                intent: ConfigMutationIntent::MarkConfirmed {
                    tx_id: opc_types::TxId::new(),
                },
            }),
        }
    }

    fn snapshot_commit_entry(
        index: u64,
        request_byte: u8,
        record: CommitRecord,
    ) -> Entry<ConfigRaftTypeConfig> {
        let logical_time = record.committed_at;
        let prepared = PreparedConfigCommit::prepare(record, Vec::new(), &shared_audit_key())
            .expect("prepared config commit");
        Entry {
            log_id: log_id(index),
            payload: EntryPayload::Normal(ConfigConsensusCommand {
                schema_version: CONFIG_CONSENSUS_COMMAND_VERSION,
                identity: identity(),
                request_id: ConfigConsensusRequestId::from_bytes([request_byte; 16]),
                logical_time,
                intent: ConfigMutationIntent::AppendCommit(Box::new(prepared)),
            }),
        }
    }

    fn large_mutation_entry(
        index: u64,
        request_byte: u8,
        opaque_bytes: usize,
    ) -> Entry<ConfigRaftTypeConfig> {
        let tx_id = opc_types::TxId::new();
        let version = ConfigVersion::new(index);
        let committed_at = opc_types::Timestamp::now_utc();
        let principal = "spiffe://test.example/tenant/tenant-a/ns/core/sa/config".to_owned();
        let schema_digest = SchemaDigest::from_bytes([request_byte; 32]);
        let key_id = KeyId::new("config-bounded-log-read").expect("key ID");
        let aad = EnvelopeAad::config(
            TenantId::from_static("tenant-a"),
            version.get(),
            ConfigAad::new(
                tx_id,
                None,
                committed_at,
                &principal,
                schema_digest,
                "running",
            )
            .expect("config AAD"),
        );
        let mut ciphertext_and_tag = vec![request_byte; opaque_bytes];
        ciphertext_and_tag.extend_from_slice(&[0xa5; AEAD_TAG_LEN]);
        let encrypted_blob = CryptoEnvelopeV1 {
            algorithm: AeadAlgorithm::Aes256GcmSiv,
            key_id: key_id.clone(),
            nonce: vec![0x42; AES_256_GCM_SIV_NONCE_LEN],
            aad: serialize_bound_aad(&aad, &key_id).expect("bound AAD"),
            ciphertext_and_tag,
        }
        .encode()
        .expect("config envelope");
        let record = CommitRecord {
            tx_id,
            parent_tx_id: None,
            version,
            committed_at,
            principal,
            source: CommitSource::Gnmi,
            schema_digest,
            plaintext_digest: vec![request_byte; 32],
            encrypted_blob,
            rollback_point: false,
            confirmed_deadline: None,
        };
        let prepared = PreparedConfigCommit::prepare(record, Vec::new(), &shared_audit_key())
            .expect("prepared config commit");
        Entry {
            log_id: log_id(index),
            payload: EntryPayload::Normal(ConfigConsensusCommand {
                schema_version: CONFIG_CONSENSUS_COMMAND_VERSION,
                identity: identity(),
                request_id: ConfigConsensusRequestId::from_bytes([request_byte; 16]),
                logical_time: committed_at,
                intent: ConfigMutationIntent::AppendCommit(Box::new(prepared)),
            }),
        }
    }

    #[tokio::test]
    async fn limited_log_reads_are_nonempty_gap_free_and_byte_bounded() {
        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let backend = SqliteBackend::open_with_audit_key(
            temp.path().join("config.sqlite"),
            true,
            0,
            shared_audit_key(),
        )
        .await
        .expect("config backend");
        let (mut log_store, _, _) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(),
            members(),
        )
        .await
        .expect("config consensus storage");
        let entries = [
            membership_entry(),
            large_mutation_entry(1, 11, 600 * 1024),
            large_mutation_entry(2, 12, 600 * 1024),
            large_mutation_entry(
                3,
                13,
                opc_consensus::DURABLE_OPENRAFT_APPEND_ENTRIES_TARGET_BYTES + 64 * 1024,
            ),
        ];
        {
            let conn = backend.conn();
            let conn = conn.lock().await;
            sqlite::append_logs_sync(&conn, identity(), &members(), &entries)
                .expect("append bounded-read fixtures");
        }

        let full = log_store
            .try_get_log_entries(1..4)
            .await
            .expect("full read remains unbounded by replication budget");
        assert_eq!(
            full.iter()
                .map(|entry| entry.log_id.index)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        for (start, expected) in [(1, 1), (2, 2), (3, 3)] {
            let page = log_store
                .limited_get_log_entries(start, 4)
                .await
                .expect("nonempty limited page");
            assert_eq!(
                page.iter()
                    .map(|entry| entry.log_id.index)
                    .collect::<Vec<_>>(),
                vec![expected]
            );
        }
        assert!(log_store.limited_get_log_entries(4, 5).await.is_err());
    }

    async fn snapshot_file_name(backend: &SqliteBackend) -> String {
        let conn = backend.conn();
        let conn = conn.lock().await;
        sqlite::read_current_snapshot_sync(&conn, identity(), &members())
            .expect("current snapshot row")
            .expect("current snapshot")
            .1
    }

    async fn create_referenced_snapshot(backend: &SqliteBackend, snapshot_dir: &Path) -> String {
        let (_, mut machine, _) = open(backend, snapshot_dir, identity(), members())
            .await
            .expect("snapshot storage");
        machine
            .apply([membership_entry(), mutation_entry()])
            .await
            .expect("snapshot source state");
        let snapshot = machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("referenced snapshot");
        drop(snapshot);
        snapshot_file_name(backend).await
    }

    #[tokio::test]
    async fn current_snapshot_read_survives_concurrent_snapshot_replacement() {
        use std::future::{poll_fn, Future};
        use std::task::Poll;

        tokio::time::timeout(Duration::from_secs(10), async {
            let temp = tempfile::tempdir().expect("snapshot tempdir");
            let backend = SqliteBackend::open_with_audit_key(
                temp.path().join("config.sqlite"),
                true,
                0,
                shared_audit_key(),
            )
            .await
            .expect("config backend");
            let (_, mut machine, _) = open(
                &backend,
                temp.path().join("snapshots"),
                identity(),
                members(),
            )
            .await
            .expect("config consensus storage");
            machine
                .apply([membership_entry(), mutation_entry()])
                .await
                .expect("initial snapshot state");
            let original = machine
                .get_snapshot_builder()
                .await
                .build_snapshot()
                .await
                .expect("original snapshot");
            let original_meta = original.meta.clone();
            let original_path = original.snapshot.path().to_path_buf();
            let original_bytes = tokio::fs::read(&original_path)
                .await
                .expect("original snapshot bytes");
            drop(original);
            machine
                .apply([Entry {
                    log_id: log_id(2),
                    payload: EntryPayload::Blank,
                }])
                .await
                .expect("replacement snapshot state");

            let hooks = Arc::clone(&machine.core.snapshot_test_hooks);
            hooks.pause_open_read.store(true, Ordering::Release);
            hooks.build_gate_acquired.store(false, Ordering::Release);
            let mut reader = machine.clone();
            let read = tokio::spawn(async move { reader.get_current_snapshot().await });
            hooks.read_opened.notified().await;

            let mut builder = machine.get_snapshot_builder().await;
            let replacement = builder.build_snapshot();
            tokio::pin!(replacement);
            // Poll exactly once to attempt the gate, then publish and unlink
            // before verifying the opened descriptor. No scheduler delay
            // creates the race.
            let first_poll = poll_fn(|cx| Poll::Ready(replacement.as_mut().poll(cx))).await;
            let published_before_read = if hooks.build_gate_acquired.load(Ordering::Acquire) {
                let result = match first_poll {
                    Poll::Ready(result) => result,
                    Poll::Pending => replacement.as_mut().await,
                };
                Some(result.expect("concurrent replacement snapshot"))
            } else {
                assert!(
                    first_poll.is_pending(),
                    "replacement must wait for the read"
                );
                None
            };
            assert!(
                published_before_read.is_some(),
                "an opened read must release the gate before verification"
            );
            hooks.pause_open_read.store(false, Ordering::Release);
            hooks.resume_read.notify_one();
            let read = read.await.expect("snapshot reader joined");
            let replacement = match published_before_read {
                Some(snapshot) => snapshot,
                None => replacement.as_mut().await.expect("replacement after read"),
            };
            assert_eq!(Some(log_id(2)), replacement.meta.last_log_id);
            assert_ne!(original_meta.snapshot_id, replacement.meta.snapshot_id);
            assert!(
                !original_path.exists(),
                "superseded snapshot must be removed"
            );

            let mut read = read
                .expect("a current snapshot read must survive concurrent replacement")
                .expect("current snapshot");
            assert_eq!(
                original_meta, read.meta,
                "read must retain its selected cut"
            );
            let mut bytes = Vec::new();
            read.snapshot
                .read_to_end(&mut bytes)
                .await
                .expect("selected snapshot remains readable after path removal");
            assert_eq!(
                original_bytes, bytes,
                "selected envelope must remain intact"
            );
        })
        .await
        .expect("snapshot replacement race must complete within its bound");
    }

    async fn pinned_snapshot_replacement(cancel_first: bool) {
        let temp = tempfile::tempdir().expect("snapshot directory");
        let backend = SqliteBackend::in_memory_for_test().await.expect("backend");
        let (_, mut machine, _) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(),
            members(),
        )
        .await
        .expect("storage");
        machine
            .apply([membership_entry(), mutation_entry()])
            .await
            .expect("initial state");
        let original = machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("initial snapshot");
        let original_meta = original.meta;
        let original_path = original.snapshot.path().to_path_buf();
        let original_bytes = tokio::fs::read(&original_path).await.unwrap();
        drop(original.snapshot);

        let hooks = machine.core.snapshot_test_hooks.clone();
        hooks.pause_pinned_read.store(true, Ordering::Release);
        let mut first_machine = machine.clone();
        let first = tokio::spawn(async move { first_machine.get_current_snapshot().await });
        hooks.read_pinned.notified().await;
        let mut second_machine = machine.clone();
        let second = tokio::spawn(async move { second_machine.get_current_snapshot().await });
        hooks.read_pinned.notified().await;
        machine
            .apply([Entry {
                log_id: log_id(2),
                payload: EntryPayload::Blank,
            }])
            .await
            .expect("successor state");
        let replacement = machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("publication must finish while readers are pinned before open");
        assert_eq!(replacement.meta.last_log_id, Some(log_id(2)));
        assert_ne!(replacement.meta, original_meta);
        assert!(
            original_path.is_file(),
            "pending opens pin the retired path"
        );

        let first = if cancel_first {
            first.abort();
            assert!(first.await.unwrap_err().is_cancelled());
            assert!(
                original_path.is_file(),
                "the other pending open still pins the path"
            );
            None
        } else {
            Some(first)
        };
        hooks.pause_pinned_read.store(false, Ordering::Release);
        hooks.resume_pinned_read.notify_waiters();
        let mut second = second.await.unwrap().expect("pinned read").unwrap();
        assert_eq!(second.meta, original_meta);
        if let Some(first) = first {
            let mut first = first.await.unwrap().expect("first pinned read").unwrap();
            assert_eq!(first.meta, original_meta);
            let mut prefix = [0_u8; 16];
            first.snapshot.read_exact(&mut prefix).await.unwrap();
            assert_eq!(prefix.as_slice(), &original_bytes[..16]);
        }
        assert!(
            !original_path.exists(),
            "the last opened descriptor releases the retired path"
        );
        let mut bytes = Vec::new();
        second.snapshot.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(
            bytes, original_bytes,
            "each descriptor has an independent offset"
        );
        let current = machine.get_current_snapshot().await.unwrap().unwrap();
        assert_eq!(current.meta, replacement.meta);
    }

    #[tokio::test]
    async fn snapshot_pinned_before_open_survives_concurrent_publication() {
        snapshot_budget_watchdog(pinned_snapshot_replacement(false)).await;
    }

    #[tokio::test]
    async fn snapshot_cancelled_pin_preserves_other_readers_and_releases_retired_path() {
        snapshot_budget_watchdog(pinned_snapshot_replacement(true)).await;
    }

    async fn snapshot_budget_watchdog(operation: impl std::future::Future<Output = ()>) {
        let (release, held) = std::sync::mpsc::channel::<()>();
        let (finished, mut watchdog) = tokio::sync::oneshot::channel();
        // A Tokio blocking task inhibits paused-clock auto-advance. Keep the
        // real-time watchdog outside that pool so simulated reads can progress.
        let worker = std::thread::spawn(move || {
            let _ = finished.send(held.recv_timeout(Duration::from_secs(10)));
        });
        tokio::select! {
            () = operation => {},
            result = &mut watchdog => panic!("snapshot budget watchdog expired: {result:?}"),
        }
        drop(release);
        assert!(matches!(
            watchdog.await.unwrap(),
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected)
        ));
        worker.join().expect("snapshot watchdog joined");
    }

    async fn queued_snapshot_keeps_work_budget(build: bool, expire_gate: bool) {
        use std::future::{poll_fn, Future};
        use std::task::Poll;

        let temp = tempfile::tempdir().expect("snapshot directory");
        let backend = SqliteBackend::in_memory_for_test().await.expect("backend");
        let (_, mut machine, _) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(),
            members(),
        )
        .await
        .expect("storage");
        machine
            .apply([membership_entry(), mutation_entry()])
            .await
            .expect("snapshot state");
        machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .unwrap();
        let hooks = machine.core.snapshot_test_hooks.clone();
        let held = if build {
            (
                Some(machine.core.snapshot_build_gate.clone().lock_owned().await),
                None,
            )
        } else {
            (
                None,
                Some(machine.core.snapshot_gate.clone().lock_owned().await),
            )
        };
        let operation = async move {
            if build {
                machine.get_snapshot_builder().await.build_snapshot().await
            } else {
                machine
                    .get_current_snapshot()
                    .await
                    .map(|snapshot| snapshot.expect("current snapshot"))
            }
        };
        let mut operation = Box::pin(operation);
        assert!(poll_fn(|cx| Poll::Ready(operation.as_mut().poll(cx)))
            .await
            .is_pending());

        // All real SQLite setup is complete. Advance only while the gate or
        // explicit test hook prevents filesystem work, then restore real time.
        tokio::time::pause();
        tokio::time::advance(if expire_gate {
            SNAPSHOT_OPERATION_TIMEOUT + Duration::from_millis(1)
        } else {
            SNAPSHOT_OPERATION_TIMEOUT - Duration::from_secs(1)
        })
        .await;
        tokio::time::resume();
        if expire_gate {
            let error = operation
                .await
                .expect_err("snapshot gate wait must stay bounded");
            assert!(error.to_string().contains("gate timed out"));
            drop(held);
            return;
        }

        if build {
            hooks.pause_build.store(true, Ordering::Release);
        } else {
            hooks.pause_open_read.store(true, Ordering::Release);
        }
        drop(held);
        let operation = tokio::spawn(operation);
        if build {
            hooks.build_started.notified().await;
        } else {
            hooks.read_opened.notified().await;
        }
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(2)).await;
        tokio::time::resume();
        if build {
            hooks.pause_build.store(false, Ordering::Release);
            hooks.resume_build.notify_one();
        } else {
            hooks.pause_open_read.store(false, Ordering::Release);
            hooks.resume_read.notify_one();
        }
        let snapshot = operation
            .await
            .expect("snapshot task joined")
            .expect("gate queue time must not consume the work budget");
        assert_eq!(snapshot.meta.last_log_id, Some(log_id(1)));
    }

    #[tokio::test]
    async fn snapshot_gate_queue_does_not_consume_verification_budget() {
        snapshot_budget_watchdog(queued_snapshot_keeps_work_budget(false, false)).await;
    }

    #[tokio::test]
    async fn snapshot_gate_queue_does_not_consume_build_budget() {
        snapshot_budget_watchdog(queued_snapshot_keeps_work_budget(true, false)).await;
    }

    #[tokio::test]
    async fn snapshot_read_and_build_gate_waits_remain_bounded() {
        snapshot_budget_watchdog(async {
            queued_snapshot_keeps_work_budget(false, true).await;
            queued_snapshot_keeps_work_budget(true, true).await;
        })
        .await;
    }

    struct PacedSnapshotReader {
        data: io::Cursor<Vec<u8>>,
        delay: Duration,
        waiting: Option<std::pin::Pin<Box<tokio::time::Sleep>>>,
    }

    impl tokio::io::AsyncRead for PacedSnapshotReader {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            use std::future::Future;
            if self.waiting.is_none() {
                self.waiting = Some(Box::pin(tokio::time::sleep(self.delay)));
            }
            std::task::ready!(self.waiting.as_mut().unwrap().as_mut().poll(cx));
            self.waiting = None;
            std::pin::Pin::new(&mut self.data).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncSeek for PacedSnapshotReader {
        fn start_seek(
            mut self: std::pin::Pin<&mut Self>,
            position: io::SeekFrom,
        ) -> io::Result<()> {
            std::pin::Pin::new(&mut self.data).start_seek(position)
        }

        fn poll_complete(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<u64>> {
            std::pin::Pin::new(&mut self.data).poll_complete(cx)
        }
    }

    fn paced_snapshot(delay: Duration) -> (PacedSnapshotReader, [u8; 32]) {
        let mut bytes = vec![0x6a; 3 * 1024 * 1024];
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        let length = bytes.len() as u64;
        bytes.extend_from_slice(SNAPSHOT_FOOTER_MAGIC);
        bytes.extend_from_slice(
            &super::super::types::CONFIG_CONSENSUS_SNAPSHOT_VERSION.to_be_bytes(),
        );
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&digest);
        (
            PacedSnapshotReader {
                data: io::Cursor::new(bytes),
                delay,
                waiting: None,
            },
            digest,
        )
    }

    #[tokio::test(start_paused = true)]
    async fn snapshot_verification_keeps_progress_beyond_the_operation_budget() {
        snapshot_budget_watchdog(async {
            let (mut reader, digest) = paced_snapshot(Duration::from_secs(20));
            let started = tokio::time::Instant::now();
            let result = verify_snapshot_reader(&mut reader)
                .await
                .expect("healthy reads must not expire a whole-file budget");
            assert!(started.elapsed() > SNAPSHOT_OPERATION_TIMEOUT);
            assert_eq!(
                result,
                (3 * 1024 * 1024, digest, reader.data.get_ref().len() as u64)
            );
            assert_eq!(
                reader.data.position(),
                0,
                "verified transport starts at byte zero"
            );
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn snapshot_verification_still_rejects_a_stalled_reader() {
        snapshot_budget_watchdog(async {
            let (mut reader, _) =
                paced_snapshot(SNAPSHOT_OPERATION_TIMEOUT + Duration::from_secs(1));
            let started = tokio::time::Instant::now();
            let error = verify_snapshot_reader(&mut reader)
                .await
                .expect_err("stalled read");
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert!(error.to_string().contains("verification stalled"));
            assert_eq!(started.elapsed(), SNAPSHOT_OPERATION_TIMEOUT);
        })
        .await;
    }

    #[tokio::test]
    async fn committed_progress_does_not_mirror_unapplied_state() {
        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let backend = SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
            .await
            .expect("backend");
        let (mut log, mut machine, progress) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(),
            members(),
        )
        .await
        .expect("storage");
        let entry = Entry {
            log_id: log_id(0),
            payload: EntryPayload::Blank,
        };
        let expected_members = log.core.expected_members.clone();
        log.core
            .run_sqlite(move |conn| {
                sqlite::append_logs_sync(conn, identity(), &expected_members, &[entry])
            })
            .await
            .expect("durable log entry");
        log.save_committed(Some(log_id(0)))
            .await
            .expect("durable committed pointer");

        assert_eq!(Some(0), progress.committed_index());
        let (applied, _) = machine.applied_state().await.expect("applied state");
        assert_eq!(None, applied, "committed must not be reported as applied");
    }

    #[tokio::test]
    async fn sqlite_deadline_cancels_work_and_releases_the_single_worker() {
        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let backend = SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
            .await
            .expect("backend");
        let (log, _, _) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(),
            members(),
        )
        .await
        .expect("storage");
        log.core
            .run_sqlite(|conn| {
                conn.execute("CREATE TABLE timeout_probe (value INTEGER NOT NULL)", [])
                    .map(|_| ())
                    .map_err(|_| sqlite::invalid_data("create timeout probe failed"))
            })
            .await
            .expect("timeout probe table");
        let started = std::time::Instant::now();
        let interrupted = log
            .core
            .run_sqlite_with_test_timeout_controlled(
                Duration::from_millis(25),
                |conn, cancellation| {
                    let tx = conn
                        .unchecked_transaction()
                        .map_err(|_| sqlite::invalid_data("timeout probe transaction failed"))?;
                    tx.execute("INSERT INTO timeout_probe (value) VALUES (1)", [])
                        .map_err(|_| sqlite::invalid_data("timeout probe insert failed"))?;
                    while !cancellation.is_cancelled() {
                        std::thread::yield_now();
                    }
                    tx.commit()
                        .map_err(|_| sqlite::invalid_data("timeout probe commit failed"))
                },
            )
            .await;
        assert!(interrupted.is_err());
        assert!(started.elapsed() < Duration::from_secs(2));

        let committed = log
            .core
            .run_sqlite(|conn| {
                conn.query_row("SELECT COUNT(*) FROM timeout_probe", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(|_| sqlite::invalid_data("timeout probe count failed"))
            })
            .await
            .expect("timeout probe count");
        assert_eq!(0, committed, "timed-out transaction must be rolled back");
        tokio::time::sleep(Duration::from_millis(50)).await;
        let committed_after_delay = log
            .core
            .run_sqlite(|conn| {
                conn.query_row("SELECT COUNT(*) FROM timeout_probe", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(|_| sqlite::invalid_data("delayed timeout probe count failed"))
            })
            .await
            .expect("delayed timeout probe count");
        assert_eq!(
            0, committed_after_delay,
            "no SQLite work may commit after the timeout error returns"
        );

        let follow_up = tokio::time::timeout(
            Duration::from_secs(2),
            log.core.run_sqlite(|conn| {
                conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                    .map_err(|_| sqlite::invalid_data("follow-up SQLite query failed"))
            }),
        )
        .await
        .expect("canceled worker releases admission")
        .expect("follow-up query");
        assert_eq!(1, follow_up);
    }

    #[tokio::test]
    async fn sqlite_deadline_winner_rejects_a_late_success_and_reuses_connection() {
        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let backend = SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
            .await
            .expect("backend");
        let (log, _, _) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(),
            members(),
        )
        .await
        .expect("storage");

        let late_success = log
            .core
            .run_sqlite_with_test_timeout_controlled(
                Duration::from_millis(25),
                |_conn, cancellation| {
                    while !cancellation.is_cancelled() {
                        std::thread::yield_now();
                    }
                    Ok(7_i64)
                },
            )
            .await;
        let error = late_success.expect_err("deadline winner must reject late success");
        assert_eq!(io::ErrorKind::TimedOut, error.kind());
        assert_eq!(
            "config consensus SQLite operation timed out",
            error.to_string()
        );

        let follow_up = tokio::time::timeout(
            Duration::from_secs(2),
            log.core.run_sqlite(|conn| {
                conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                    .map_err(|_| sqlite::invalid_data("follow-up SQLite query failed"))
            }),
        )
        .await
        .expect("late-success worker releases admission")
        .expect("follow-up query");
        assert_eq!(1, follow_up);
    }

    #[tokio::test]
    async fn dropped_sqlite_future_cancels_worker_and_reuses_connection() {
        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let backend = SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
            .await
            .expect("backend");
        let (log, _, _) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(),
            members(),
        )
        .await
        .expect("storage");
        log.core
            .run_sqlite(|conn| {
                conn.execute("CREATE TABLE drop_probe (value INTEGER NOT NULL)", [])
                    .map(|_| ())
                    .map_err(|_| sqlite::invalid_data("create drop probe failed"))
            })
            .await
            .expect("drop probe table");

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (exited_tx, exited_rx) = tokio::sync::oneshot::channel();
        let core = log.core.clone();
        let caller = tokio::spawn(async move {
            core.run_sqlite_with_test_timeout_controlled(
                Duration::from_secs(10),
                move |conn, cancellation| {
                    let tx = conn
                        .unchecked_transaction()
                        .map_err(|_| sqlite::invalid_data("drop probe transaction failed"))?;
                    tx.execute("INSERT INTO drop_probe (value) VALUES (1)", [])
                        .map_err(|_| sqlite::invalid_data("drop probe insert failed"))?;
                    let _ = started_tx.send(());
                    while !cancellation.is_cancelled() {
                        std::thread::yield_now();
                    }
                    let commit_rejected = tx.commit().is_err();
                    let _ = exited_tx.send(commit_rejected);
                    cancellation.check_io()
                },
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), started_rx)
            .await
            .expect("controlled worker starts")
            .expect("controlled worker start signal");
        caller.abort();
        assert!(caller
            .await
            .expect_err("caller must be canceled")
            .is_cancelled());
        let commit_rejected = tokio::time::timeout(Duration::from_secs(2), exited_rx)
            .await
            .expect("dropped caller cancels controlled worker")
            .expect("controlled worker exit signal");
        assert!(commit_rejected, "dropped work must not commit");

        let committed = tokio::time::timeout(
            Duration::from_secs(2),
            log.core.run_sqlite(|conn| {
                conn.query_row("SELECT COUNT(*) FROM drop_probe", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(|_| sqlite::invalid_data("drop probe count failed"))
            }),
        )
        .await
        .expect("dropped worker releases admission and connection")
        .expect("drop probe count");
        assert_eq!(0, committed, "dropped work must be rolled back");
    }

    #[tokio::test]
    async fn cancelled_sqlite_worker_keeps_shutdown_pending_until_connection_release() {
        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let backend = SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
            .await
            .expect("backend");
        let connection = Arc::downgrade(&backend.conn());
        let (log, _, _) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(),
            members(),
        )
        .await
        .expect("storage");
        let mut shutdown = log.core.storage_shutdown_observer();
        let (started, running) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let caller = tokio::spawn(async move {
            log.core
                .run_sqlite_cancellable(move |conn, cancellation| {
                    let _: i64 = conn
                        .query_row("SELECT 1", [], |row| row.get(0))
                        .map_err(|_| sqlite::invalid_data("worker probe failed"))?;
                    let _ = started.send(());
                    released
                        .recv()
                        .map_err(|_| sqlite::invalid_data("worker release unavailable"))?;
                    cancellation.check_io()
                })
                .await
        });
        tokio::time::timeout(Duration::from_secs(2), running)
            .await
            .expect("actual SQLite worker starts")
            .expect("worker start signal");
        caller.abort();
        assert!(caller
            .await
            .expect_err("cancel awaiting future")
            .is_cancelled());
        drop(backend);
        let shutdown_pending = shutdown.has_changed().is_ok();
        let connection_retained = connection.strong_count() > 0;
        release.send(()).expect("release the actual worker");
        tokio::time::timeout(Duration::from_secs(2), shutdown.changed())
            .await
            .expect("worker releases all storage owners")
            .expect_err("only owner exhaustion closes the completion channel");
        assert!(
            shutdown_pending,
            "caller cancellation cannot complete the drain"
        );
        assert!(connection_retained, "the blocked worker still owns SQLite");
        assert_eq!(
            connection.strong_count(),
            0,
            "connection released before completion"
        );
    }

    #[tokio::test]
    async fn frozen_setup_does_not_spend_new_backend_probe_budget() {
        let backend = SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
            .await
            .expect("backend");
        tokio::time::pause();
        let frozen = tokio::time::Instant::now();
        std::thread::sleep(Duration::from_secs(4));
        assert_eq!(tokio::time::Instant::now(), frozen);
        assert!(std::time::Instant::now() > (frozen + Duration::from_secs(3)).into_std());

        let value = sqlite::run_backend_sqlite_with_timeout(
            &backend,
            Duration::from_secs(3),
            |conn, cancellation| {
                cancellation.check_io()?;
                conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                    .map_err(|_| sqlite::invalid_data("fresh backend query failed"))
            },
        )
        .await;
        tokio::time::resume();
        assert_eq!(
            value.expect("new operation has its own three-second budget"),
            1
        );
    }

    #[tokio::test]
    async fn sqlite_clock_paused_progress_keeps_the_callers_budget() {
        let backend = SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
            .await
            .expect("backend");
        tokio::time::pause();
        let frozen = tokio::time::Instant::now();
        let budget = Duration::from_millis(20);
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(tokio::time::Instant::now(), frozen);
        assert!(std::time::Instant::now() > (frozen + budget).into_std());

        let sum = sqlite::run_backend_sqlite_with_timeout(&backend, budget, |conn, _| {
            // Enough SQLite instructions to invoke the worker's progress hook.
            conn.query_row(
                "WITH RECURSIVE numbers(n) AS (VALUES(1) UNION ALL \
                 SELECT n + 1 FROM numbers WHERE n < 10000) SELECT SUM(n) FROM numbers",
                [],
                |row| row.get::<_, i64>(0),
            )
            .map_err(|_| sqlite::invalid_data("progress probe failed"))
        })
        .await
        .expect("real time cannot exhaust a frozen Tokio budget");
        assert_eq!(sum, 50_005_000);
        assert_eq!(tokio::time::Instant::now(), frozen);
    }

    #[tokio::test]
    async fn sqlite_clock_advanced_deadline_rejects_commit_without_polling_caller() {
        let backend = SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
            .await
            .expect("backend");
        backend
            .conn()
            .lock()
            .await
            .execute("CREATE TABLE clock_probe (value INTEGER NOT NULL)", [])
            .expect("probe table");
        tokio::time::pause();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (committed_tx, committed_rx) = std::sync::mpsc::channel();
        let budget = Duration::from_secs(30);
        let mut operation = std::pin::pin!(sqlite::run_backend_sqlite_with_timeout(
            &backend,
            budget,
            move |conn, _| {
                let tx = conn.unchecked_transaction().expect("probe transaction");
                tx.execute("INSERT INTO clock_probe VALUES (1)", [])
                    .expect("probe insert");
                ready_tx.send(()).expect("worker ready");
                release_rx.recv().expect("worker release");
                let committed = tx.commit().is_ok();
                committed_tx.send(committed).expect("commit result");
                Ok(())
            },
        ));
        // Leave the timeout future unpolled while advancing time. The worker
        // must reject the commit itself, before the caller can cancel it.
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(operation.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("worker starts");
        tokio::time::advance(budget).await;
        release_tx.send(()).expect("release after deadline");
        let committed = committed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("worker finishes");
        let result = operation.await;
        let count: i64 = backend
            .conn()
            .lock()
            .await
            .query_row("SELECT COUNT(*) FROM clock_probe", [], |row| row.get(0))
            .expect("connection reused");
        assert!(!committed, "the worker must reject the expired commit");
        assert_eq!(
            result.expect_err("expired worker").kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(count, 0, "expired work leaves no durable row");
    }

    #[tokio::test]
    async fn sqlite_clock_advanced_progress_stays_bounded_after_commit() {
        let backend = SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
            .await
            .expect("backend");
        backend
            .conn()
            .lock()
            .await
            .execute("CREATE TABLE clock_probe (value INTEGER NOT NULL)", [])
            .expect("probe table");
        tokio::time::pause();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let budget = Duration::from_secs(30);
        let mut operation = std::pin::pin!(sqlite::run_backend_sqlite_with_timeout(
            &backend,
            budget,
            move |conn, _| {
                conn.execute("INSERT INTO clock_probe VALUES (1)", [])
                    .expect("authorized commit");
                ready_tx.send(()).expect("commit ready");
                release_rx.recv().expect("worker release");
                let query = conn.query_row(
                    "WITH RECURSIVE numbers(n) AS (VALUES(1) UNION ALL \
                     SELECT n + 1 FROM numbers WHERE n < 10000) SELECT SUM(n) FROM numbers",
                    [],
                    |row| row.get::<_, i64>(0),
                );
                Ok(
                    matches!(query, Err(rusqlite::Error::SqliteFailure(error, _))
                    if error.code == rusqlite::ErrorCode::OperationInterrupted),
                )
            },
        ));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(operation.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        ready_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("commit finishes");
        tokio::time::advance(budget).await;
        release_tx.send(()).expect("release after deadline");
        let interrupted = operation
            .await
            .expect("report the commit winner's actual result");
        let count: i64 = backend
            .conn()
            .lock()
            .await
            .query_row("SELECT COUNT(*) FROM clock_probe", [], |row| row.get(0))
            .expect("connection reused");
        assert!(
            interrupted,
            "SQL progress remains bounded after commit authorization"
        );
        assert_eq!(count, 1, "the authorized commit remains durable");
    }

    #[tokio::test]
    async fn sqlite_clock_paused_initialization_keeps_the_callers_budget() {
        let temp = tempfile::tempdir().expect("snapshot directory");
        let backend = SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
            .await
            .expect("backend");
        let admitted = admit_snapshot_directory(&backend, temp.path().join("snapshots"))
            .expect("admitted directory");
        tokio::time::pause();
        let frozen = tokio::time::Instant::now();
        let core = sqlite::ConfigConsensusCore::initialize_with_test_timeout(
            &backend,
            admitted,
            identity(),
            members(),
            Arc::new(ConfigDurableProgress::default()),
            None,
            Duration::from_millis(20),
            move |_| {
                std::thread::sleep(Duration::from_millis(40));
                assert_eq!(tokio::time::Instant::now(), frozen);
            },
        )
        .await
        .expect("real time cannot exhaust the frozen initialization budget");
        assert_eq!(tokio::time::Instant::now(), frozen);
        let count: i64 = backend
            .conn()
            .lock()
            .await
            .query_row("SELECT COUNT(*) FROM config_raft_identity", [], |row| {
                row.get(0)
            })
            .expect("initialized identity");
        assert_eq!(count, 1);
        drop(core);
    }

    #[tokio::test]
    async fn sqlite_clock_rejected_commit_never_returns_late_success_in_real_time() {
        let backend = SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
            .await
            .expect("backend");
        backend
            .conn()
            .lock()
            .await
            .execute("CREATE TABLE clock_probe (value INTEGER NOT NULL)", [])
            .expect("probe table");
        let (committed_tx, committed_rx) = std::sync::mpsc::channel();
        let mut operation = std::pin::pin!(sqlite::run_backend_sqlite_with_timeout(
            &backend,
            Duration::from_millis(20),
            move |conn, _| {
                let tx = conn.unchecked_transaction().expect("probe transaction");
                tx.execute("INSERT INTO clock_probe VALUES (1)", [])
                    .expect("probe insert");
                std::thread::sleep(Duration::from_millis(40));
                committed_tx
                    .send(tx.commit().is_ok())
                    .expect("commit result");
                Ok(7)
            },
        ));
        std::future::poll_fn(|cx| {
            assert!(std::future::Future::poll(operation.as_mut(), cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        // Hold the caller until the worker rejects its own expired commit.
        // This exercises both the deadline and cancellation without a timer
        // future getting the first chance to cancel the operation.
        let committed = committed_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("worker finishes");
        let result = operation.await;
        let count: i64 = backend
            .conn()
            .lock()
            .await
            .query_row("SELECT COUNT(*) FROM clock_probe", [], |row| row.get(0))
            .expect("connection reused");
        assert!(!committed, "the expired commit is rejected");
        assert_eq!(count, 0, "rejected work leaves no durable row");
        assert_eq!(
            result
                .expect_err("cancelled work cannot return success")
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[tokio::test]
    async fn pre_core_probe_timeout_never_queues_late_work_and_reuses_backend() {
        let backend = SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
            .await
            .expect("backend");
        let shared = backend.conn();
        let held = shared.clone().lock_owned().await;
        let ran = Arc::new(AtomicBool::new(false));
        let ran_in_worker = ran.clone();
        let error = sqlite::run_backend_sqlite_with_timeout(
            &backend,
            Duration::from_millis(25),
            move |_conn, _cancellation| {
                ran_in_worker.store(true, Ordering::Release);
                Ok(())
            },
        )
        .await
        .expect_err("held connection must time out");
        assert_eq!(io::ErrorKind::TimedOut, error.kind());
        drop(held);
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!ran.load(Ordering::Acquire), "timed-out work ran late");

        let value = sqlite::run_backend_sqlite_with_timeout(
            &backend,
            Duration::from_secs(1),
            |conn, cancellation| {
                cancellation.check_io()?;
                conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                    .map_err(|_| sqlite::invalid_data("reused backend query failed"))
            },
        )
        .await
        .expect("backend is reusable after timeout");
        assert_eq!(1, value);
    }

    #[tokio::test]
    async fn initialization_timeout_cancels_before_authority_and_allows_retry() {
        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let backend = SqliteBackend::open_with_audit_key(
            temp.path().join("config.sqlite"),
            true,
            0,
            shared_audit_key(),
        )
        .await
        .expect("backend");
        let snapshot_path = temp.path().join("snapshots");
        let admitted = admit_snapshot_directory(&backend, snapshot_path.clone())
            .expect("admitted snapshot directory");
        let progress = Arc::new(ConfigDurableProgress::default());

        let result = sqlite::ConfigConsensusCore::initialize_with_test_timeout(
            &backend,
            admitted,
            identity(),
            members(),
            progress,
            None,
            Duration::from_millis(25),
            |cancellation| {
                while !cancellation.is_cancelled() {
                    std::thread::yield_now();
                }
            },
        )
        .await;
        assert!(
            matches!(result, Err(ConfigConsensusStorageError::BackendUnavailable)),
            "initialization must lose authority when timeout wins"
        );

        let identity_tables = {
            let conn = backend.conn();
            let conn = tokio::time::timeout(Duration::from_secs(1), conn.lock())
                .await
                .expect("timed-out initialization releases connection");
            conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'config_raft_identity'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("identity table count")
        };
        assert_eq!(0, identity_tables, "timeout must roll back identity claim");
        tokio::time::sleep(Duration::from_millis(50)).await;
        {
            let conn = backend.conn();
            let conn = conn.lock().await;
            let identity_tables: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'config_raft_identity'",
                    [],
                    |row| row.get(0),
                )
                .expect("delayed identity table count");
            assert_eq!(
                0, identity_tables,
                "no identity authority may appear after timeout returns"
            );
        }

        open(&backend, &snapshot_path, identity(), members())
            .await
            .expect("clean retry after canceled initialization");
    }

    #[tokio::test]
    async fn dropped_initialization_cancels_before_authority_and_allows_retry() {
        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let backend = Arc::new(
            SqliteBackend::open_with_audit_key(
                temp.path().join("config.sqlite"),
                true,
                0,
                shared_audit_key(),
            )
            .await
            .expect("backend"),
        );
        let snapshot_path = temp.path().join("snapshots");
        let admitted = admit_snapshot_directory(&backend, snapshot_path.clone())
            .expect("admitted snapshot directory");
        let progress = Arc::new(ConfigDurableProgress::default());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (exited_tx, exited_rx) = tokio::sync::oneshot::channel();
        let worker_backend = backend.clone();
        let caller = tokio::spawn(async move {
            sqlite::ConfigConsensusCore::initialize_with_test_timeout(
                &worker_backend,
                admitted,
                identity(),
                members(),
                progress,
                None,
                Duration::from_secs(10),
                move |cancellation| {
                    let _ = started_tx.send(());
                    while !cancellation.is_cancelled() {
                        std::thread::yield_now();
                    }
                    let _ = exited_tx.send(());
                },
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), started_rx)
            .await
            .expect("controlled initialization starts")
            .expect("controlled initialization start signal");
        caller.abort();
        match caller.await {
            Err(error) => assert!(error.is_cancelled()),
            Ok(_) => panic!("initialization caller must be canceled"),
        }
        tokio::time::timeout(Duration::from_secs(2), exited_rx)
            .await
            .expect("dropped initialization cancels worker")
            .expect("controlled initialization exit signal");

        let identity_tables = {
            let conn = backend.conn();
            let conn = tokio::time::timeout(Duration::from_secs(2), conn.lock())
                .await
                .expect("dropped initialization releases connection");
            conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'config_raft_identity'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("identity table count")
        };
        assert_eq!(0, identity_tables, "dropped initialization must roll back");
        open(&backend, snapshot_path, identity(), members())
            .await
            .expect("clean retry after dropped initialization");
    }

    #[tokio::test]
    async fn purge_waits_for_snapshot_application_and_requires_exact_durable_lineage() {
        let temp = tempfile::tempdir().expect("snapshot directory");
        let source = SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
            .await
            .expect("source");
        let (_, mut source_machine, _) =
            open(&source, temp.path().join("source"), identity(), members())
                .await
                .expect("source storage");
        source_machine
            .apply([membership_entry()])
            .await
            .expect("source membership");
        let mut snapshot = source_machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("source snapshot");
        let destination =
            SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
                .await
                .expect("destination");
        let (mut log, mut machine, _) = open(
            &destination,
            temp.path().join("destination"),
            identity(),
            members(),
        )
        .await
        .expect("destination storage");
        let mut receiving = machine.begin_receiving_snapshot().await.expect("receiver");
        tokio::io::copy(&mut snapshot.snapshot, &mut receiving)
            .await
            .expect("snapshot copy");
        let through = snapshot.meta.last_log_id.expect("snapshot log identity");
        {
            let mut purge = std::pin::pin!(log.purge(through));
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(25), &mut purge)
                    .await
                    .is_err(),
                "purge must wait while the snapshot is not applied"
            );
            {
                let conn = destination.conn();
                let conn = conn.lock().await;
                assert_eq!(
                    sqlite::read_purged_sync(&conn, identity()).expect("no purge"),
                    None
                );
                assert_eq!(
                    sqlite::read_applied_sync(&conn, identity()).expect("no applied state"),
                    None
                );
            }
            machine
                .install_snapshot(&snapshot.meta, receiving)
                .await
                .expect("install snapshot");
            tokio::time::timeout(std::time::Duration::from_secs(1), &mut purge)
                .await
                .expect("durable application wakes purge")
                .expect("snapshot proves exact purge boundary");
        }
        let mut wrong = through;
        wrong.leader_id.term += 1;
        assert!(
            log.purge(wrong).await.is_err(),
            "same index with another term is not authority"
        );
        let conn = destination.conn();
        let conn = conn.lock().await;
        assert_eq!(
            sqlite::read_purged_sync(&conn, identity()).expect("unchanged exact floor"),
            Some(through)
        );
    }

    #[tokio::test]
    async fn snapshot_install_validates_destination_schema_before_replacing_authority() {
        let temp = tempfile::tempdir().expect("snapshot directory");
        let at = Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(1_767_225_600).expect("fixed timestamp"),
        );
        let protected_tx = TxId::from_uuid(uuid::Uuid::from_bytes([0x61; 16]));
        let latest_tx = TxId::from_uuid(uuid::Uuid::from_bytes([0x62; 16]));
        let previous_tx = TxId::from_uuid(uuid::Uuid::from_bytes([0x63; 16]));
        let mut protected = snapshot_commit_record(protected_tx, None, 1, at, None, 0x61);
        protected.rollback_point = true;
        let source = SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
            .await
            .expect("source backend");
        let (_, mut source_machine, _) =
            open(&source, temp.path().join("source"), identity(), members())
                .await
                .expect("source storage");
        let responses = source_machine
            .apply([
                membership_entry(),
                snapshot_commit_entry(1, 0x61, protected),
                snapshot_commit_entry(
                    2,
                    0x62,
                    snapshot_commit_record(latest_tx, Some(protected_tx), 2, at, None, 0x62),
                ),
            ])
            .await
            .expect("source apply");
        assert!(responses.iter().all(|response| response.result.is_ok()));
        let mut snapshot = source_machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("authenticated source snapshot");

        for (name, schema_change, schema_restore) in [
            (
                "trigger",
                "CREATE TRIGGER fixture_snapshot_write AFTER INSERT ON config_history BEGIN UPDATE config_history SET rollback_point = 0 WHERE tx_id = NEW.tx_id; END",
                "DROP TRIGGER fixture_snapshot_write",
            ),
            (
                "temporary",
                "CREATE TEMP TABLE config_history AS SELECT * FROM main.config_history",
                "DROP TABLE temp.config_history",
            ),
            (
                "index",
                "CREATE INDEX fixture_snapshot_index ON config_history(rollback_point)",
                "DROP INDEX fixture_snapshot_index",
            ),
        ] {
            let destination =
                SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
                    .await
                    .expect("destination backend");
            let (_, mut machine, progress) =
                open(&destination, temp.path().join(name), identity(), members())
                    .await
                    .expect("destination storage");
            let responses = machine
                .apply([
                    membership_entry(),
                    snapshot_commit_entry(
                        1,
                        0x63,
                        snapshot_commit_record(previous_tx, None, 1, at, None, 0x63),
                    ),
                ])
                .await
                .expect("previous destination state");
            assert!(responses.iter().all(|response| response.result.is_ok()));
            let previous = machine.applied_state().await.expect("previous applied state");
            let previous_snapshot = machine
                .get_snapshot_builder()
                .await
                .build_snapshot()
                .await
                .expect("previous destination snapshot");
            let applied_notifications = progress.subscribe_applied();
            {
                let conn = destination.conn();
                conn.lock()
                    .await
                    .execute_batch(schema_change)
                    .expect("isolated destination schema fixture");
            }
            snapshot.snapshot.rewind().await.expect("rewind snapshot");
            let mut receiving = machine.begin_receiving_snapshot().await.expect("receiver");
            tokio::io::copy(&mut snapshot.snapshot, &mut receiving)
                .await
                .expect("copy source snapshot");
            let installed = machine.install_snapshot(&snapshot.meta, receiving).await;
            {
                let conn = destination.conn();
                conn.lock()
                    .await
                    .execute_batch(schema_restore)
                    .expect("restore destination schema");
            }
            assert!(
                installed.is_err(),
                "snapshot installation must reject an unadmitted destination schema"
            );
            assert!(
                !applied_notifications.has_changed().expect("progress sender"),
                "rejected repair must not report durable application"
            );
            assert_eq!(previous, machine.applied_state().await.expect("unchanged applied state"));
            let current = machine
                .get_current_snapshot()
                .await
                .expect("unchanged current snapshot")
                .expect("previous snapshot retained");
            assert_eq!(previous_snapshot.meta, current.meta);
            let previous = crate::ConfigStore::load_latest(&destination)
                .await
                .expect("previous history still authenticates")
                .expect("previous history retained");
            assert!(previous.record.tx_id == previous_tx);

            // Repair must replace damaged rows when the destination schema is
            // valid; authenticating the old row chain would prevent recovery.
            {
                let conn = destination.conn();
                conn.lock()
                    .await
                    .execute("UPDATE config_history SET rollback_point = 1", [])
                    .expect("damage destination row without changing its schema");
            }
            assert!(crate::ConfigStore::load_latest(&destination).await.is_err());
            snapshot.snapshot.rewind().await.expect("rewind repair source");
            let mut receiving = machine.begin_receiving_snapshot().await.expect("repair receiver");
            tokio::io::copy(&mut snapshot.snapshot, &mut receiving)
                .await
                .expect("copy authenticated repair source");
            machine
                .install_snapshot(&snapshot.meta, receiving)
                .await
                .expect("valid schema permits repair of damaged rows");
            assert!(applied_notifications.has_changed().expect("repair notification"));
            assert_eq!(
                snapshot.meta.last_log_id,
                machine.applied_state().await.expect("repaired applied state").0
            );
            let repaired = crate::ConfigStore::load_latest(&destination)
                .await
                .expect("repaired history authenticates")
                .expect("repaired latest history");
            assert!(repaired.record.tx_id == latest_tx);
            let protected = crate::ConfigStore::load_rollback(
                &destination,
                crate::RollbackTarget::ByTxId(protected_tx),
            )
            .await
            .expect("repaired protected history authenticates");
            assert!(protected.record.rollback_point);
        }
    }

    #[tokio::test]
    async fn file_snapshot_install_is_checksummed_atomic_and_replaces_applied_state() {
        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let genesis_tx = TxId::from_uuid(uuid::Uuid::from_bytes([0x31; 16]));
        let child_tx = TxId::from_uuid(uuid::Uuid::from_bytes([0x32; 16]));
        let genesis_at = Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(1_767_225_600)
                .expect("fixed genesis timestamp"),
        );
        let child_at = Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(1_767_225_660)
                .expect("fixed child timestamp"),
        );
        let child_deadline = Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(1_767_225_960)
                .expect("fixed confirmation deadline"),
        );
        let genesis = snapshot_commit_record(genesis_tx, None, 1, genesis_at, None, 0x41);
        let child = snapshot_commit_record(
            child_tx,
            Some(genesis_tx),
            2,
            child_at,
            Some(child_deadline),
            0x42,
        );
        let expected_ciphertext = child.encrypted_blob.clone();
        let source_backend =
            SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
                .await
                .expect("source backend");
        let (_, mut source_machine, _) = open(
            &source_backend,
            temp.path().join("source"),
            identity(),
            members(),
        )
        .await
        .expect("source storage");
        let responses = source_machine
            .apply([
                membership_entry(),
                snapshot_commit_entry(1, 0x91, genesis),
                snapshot_commit_entry(2, 0x92, child),
            ])
            .await
            .expect("source apply");
        assert!(
            responses.iter().all(|response| response.result.is_ok()),
            "snapshot source entries must all apply"
        );
        let mut snapshot = source_machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("source snapshot");
        assert_eq!(Some(log_id(2)), snapshot.meta.last_log_id);

        let rejected_backend =
            SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
                .await
                .expect("rejected destination backend");
        let (_, mut rejected_machine, _) = open(
            &rejected_backend,
            temp.path().join("rejected"),
            identity(),
            members(),
        )
        .await
        .expect("rejected destination storage");
        let mut corrupted = rejected_machine
            .begin_receiving_snapshot()
            .await
            .expect("corrupt receiver");
        tokio::io::copy(&mut snapshot.snapshot, &mut corrupted)
            .await
            .expect("copy corrupt candidate");
        corrupted
            .seek(std::io::SeekFrom::Start(0))
            .await
            .expect("seek corrupt candidate");
        corrupted
            .write_all(b"X")
            .await
            .expect("corrupt snapshot payload");
        assert!(rejected_machine
            .install_snapshot(&snapshot.meta, corrupted)
            .await
            .is_err());
        assert_eq!(
            None,
            rejected_machine
                .applied_state()
                .await
                .expect("rejected applied state")
                .0
        );

        snapshot
            .snapshot
            .seek(std::io::SeekFrom::Start(0))
            .await
            .expect("rewind source snapshot");
        let destination_backend =
            SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
                .await
                .expect("destination backend");
        let (_, mut destination_machine, _) = open(
            &destination_backend,
            temp.path().join("destination"),
            identity(),
            members(),
        )
        .await
        .expect("destination storage");
        let stale = temp.path().join("stale-incoming.sqlite");
        drop(rusqlite::Connection::open(&stale).expect("stale attached database"));
        {
            let conn = destination_backend.conn();
            let conn = conn.lock().await;
            conn.execute(
                "ATTACH DATABASE ?1 AS config_raft_incoming",
                [stale.to_string_lossy().as_ref()],
            )
            .expect("inject stale incoming attachment");
        }
        let mut receiving = destination_machine
            .begin_receiving_snapshot()
            .await
            .expect("snapshot receiver");
        tokio::io::copy(&mut snapshot.snapshot, &mut receiving)
            .await
            .expect("copy valid snapshot");
        destination_machine
            .install_snapshot(&snapshot.meta, receiving)
            .await
            .expect("install valid snapshot");
        let published = destination_machine
            .get_current_snapshot()
            .await
            .expect("installed publication is readable")
            .expect("installed snapshot");
        assert_eq!(published.meta, snapshot.meta);
        let (applied, membership) = destination_machine
            .applied_state()
            .await
            .expect("installed applied state");
        assert_eq!(snapshot.meta.last_log_id, applied);
        assert_eq!(snapshot.meta.last_membership, membership);

        let restored = crate::ConfigStore::load_latest(&destination_backend)
            .await
            .expect("load installed config history")
            .expect("installed config history");
        assert!(
            restored.record.tx_id == child_tx,
            "snapshot must restore the exact child transaction"
        );
        assert!(
            restored.record.version == ConfigVersion::new(2),
            "snapshot must restore the exact child version"
        );
        assert!(
            restored.record.parent_tx_id == Some(genesis_tx),
            "snapshot must restore the exact parent transaction"
        );
        assert!(
            restored.record.confirmed_deadline == Some(child_deadline),
            "snapshot must restore the exact confirmation deadline"
        );
        assert!(
            restored.record.encrypted_blob == expected_ciphertext,
            "snapshot must restore the exact sealed ciphertext"
        );

        let conn = destination_backend.conn();
        let conn = conn.lock().await;
        let sequence: i64 = conn
            .query_row(
                "SELECT application_sequence FROM config_raft_machine WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .expect("installed sequence");
        let outcomes: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM config_raft_request_outcomes",
                [],
                |row| row.get(0),
            )
            .expect("installed outcomes");
        let history: i64 = conn
            .query_row("SELECT COUNT(*) FROM config_history", [], |row| row.get(0))
            .expect("installed history count");
        let logs: i64 = conn
            .query_row("SELECT COUNT(*) FROM config_raft_log", [], |row| row.get(0))
            .expect("installed log count");
        let stale_attachments: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_database_list WHERE name = 'config_raft_incoming'",
                [],
                |row| row.get(0),
            )
            .expect("stale attachment count");
        assert_eq!(2, sequence);
        assert_eq!(2, outcomes);
        assert_eq!(2, history);
        assert_eq!(0, logs, "snapshot must not import log-store authority");
        assert_eq!(0, stale_attachments, "install must detach stale aliases");
    }

    #[tokio::test]
    async fn cancelled_snapshot_receivers_leave_no_staging_files() {
        let temp = tempfile::tempdir().expect("snapshot tempdir");
        for iteration in 0..32_u8 {
            let path = temp.path().join(format!("incoming-{iteration}.part"));
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                let mut file = ConfigSnapshotFile::create(path)
                    .await
                    .expect("snapshot receiver");
                file.write_all(&[iteration; 4_096])
                    .await
                    .expect("staged bytes");
                let _ = ready_tx.send(());
                std::future::pending::<()>().await;
            });
            ready_rx.await.expect("receiver reached cancellation point");
            task.abort();
            assert!(task.await.is_err());
        }
        assert!(
            std::fs::read_dir(temp.path())
                .expect("snapshot directory")
                .next()
                .is_none(),
            "drop-safe cancellation must remove every incoming staging file"
        );
    }

    #[tokio::test]
    async fn startup_keeps_verified_current_snapshot_and_cleans_all_known_orphans() {
        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let snapshot_dir = temp.path().join("snapshots");
        let backend = SqliteBackend::in_memory_for_test()
            .await
            .expect("config backend");
        let current = create_referenced_snapshot(&backend, &snapshot_dir).await;
        let artifacts = [
            "incoming-aborted.part",
            "promote-aborted.part",
            "seal-aborted.part",
            "snapshot-aborted.part",
            "snapshot-orphan.opc",
            "install-aborted.sqlite",
            "install-aborted.sqlite-journal",
            "install-aborted.sqlite-wal",
            "install-aborted.sqlite-shm",
            "build-aborted.sqlite",
            "build-aborted.sqlite-journal",
            "build-aborted.sqlite-wal",
            "build-aborted.sqlite-shm",
            "approved-legacy-aborted.sqlite",
            "approved-legacy-aborted.sqlite-journal",
            "approved-legacy-aborted.sqlite-wal",
            "approved-legacy-aborted.sqlite-shm",
        ];
        for artifact in artifacts {
            tokio::fs::write(snapshot_dir.join(artifact), b"interrupted")
                .await
                .expect("interrupted artifact");
        }

        let (_, mut reopened, _) = open(&backend, &snapshot_dir, identity(), members())
            .await
            .expect("restart cleans interrupted artifacts");
        let published = reopened
            .get_current_snapshot()
            .await
            .expect("startup restores the published record")
            .expect("restored snapshot");
        assert_eq!(
            std::fs::canonicalize(published.snapshot.path()).expect("published artifact path"),
            std::fs::canonicalize(snapshot_dir.join(&current)).expect("durable artifact path")
        );
        assert!(snapshot_dir.join(&current).is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                0,
                std::fs::metadata(snapshot_dir.join(&current))
                    .expect("snapshot metadata")
                    .permissions()
                    .mode()
                    & 0o077,
                "durable snapshot artifacts must not be group/world accessible"
            );
        }
        for artifact in artifacts {
            assert!(
                !snapshot_dir.join(artifact).exists(),
                "restart left {artifact}"
            );
        }
    }

    #[tokio::test]
    async fn startup_verifies_current_snapshot_before_removing_orphans() {
        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let snapshot_dir = temp.path().join("snapshots");
        let backend = SqliteBackend::in_memory_for_test()
            .await
            .expect("config backend");
        let current = create_referenced_snapshot(&backend, &snapshot_dir).await;
        tokio::fs::write(snapshot_dir.join(&current), b"corrupt")
            .await
            .expect("corrupt referenced snapshot");
        let orphan = snapshot_dir.join("snapshot-must-remain-until-validation.opc");
        tokio::fs::write(&orphan, b"orphan")
            .await
            .expect("orphan snapshot");

        assert!(matches!(
            open(&backend, &snapshot_dir, identity(), members()).await,
            Err(ConfigConsensusStorageError::CorruptState)
        ));
        assert!(
            orphan.exists(),
            "cleanup must not run after referenced authority fails verification"
        );
    }

    #[tokio::test]
    async fn snapshot_envelope_revision_is_exact() {
        use std::io::{Seek as _, Write as _};

        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let snapshot_dir = temp.path().join("snapshots");
        let backend = SqliteBackend::in_memory_for_test()
            .await
            .expect("config backend");
        let current = create_referenced_snapshot(&backend, &snapshot_dir).await;
        let path = snapshot_dir.join(current);
        let length = std::fs::metadata(&path).expect("snapshot metadata").len();
        let revision_offset = length
            .checked_sub(SNAPSHOT_FOOTER_BYTES)
            .and_then(|footer| footer.checked_add(SNAPSHOT_FOOTER_MAGIC.len() as u64))
            .expect("revision offset");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open snapshot for revision injection");
        file.seek(std::io::SeekFrom::Start(revision_offset))
            .expect("seek revision");
        file.write_all(&(super::super::types::CONFIG_CONSENSUS_SNAPSHOT_VERSION + 1).to_be_bytes())
            .expect("write future revision");
        file.sync_all().expect("sync future revision");

        let error = verify_snapshot_envelope(&path)
            .await
            .expect_err("future snapshot revision must fail closed");
        assert_eq!(io::ErrorKind::InvalidData, error.kind());
    }

    #[tokio::test]
    async fn startup_rejects_unsafe_staging_types() {
        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let snapshot_dir = temp.path().join("snapshots");
        let backend = SqliteBackend::in_memory_for_test()
            .await
            .expect("config backend");
        open(&backend, &snapshot_dir, identity(), members())
            .await
            .expect("initial storage");
        tokio::fs::create_dir(snapshot_dir.join("incoming-unsafe.part"))
            .await
            .expect("unsafe staging directory");

        assert!(matches!(
            open(&backend, &snapshot_dir, identity(), members()).await,
            Err(ConfigConsensusStorageError::CorruptState)
        ));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn snapshot_root_must_be_private_nonsymlink_and_remain_bound_before_purge() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let backend = SqliteBackend::open_with_audit_key(":memory:", true, 0, shared_audit_key())
            .await
            .expect("backend");
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o755))
            .expect("make non-private snapshot root");
        assert_eq!(
            open(&backend, temp.path(), identity(), members())
                .await
                .map(|_| ()),
            Err(ConfigConsensusStorageError::InvalidIdentity),
        );
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restore private fixture parent");

        let target = temp.path().join("real-target");
        std::fs::create_dir(&target).expect("target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700))
            .expect("private target");
        let link = temp.path().join("snapshot-link");
        symlink(&target, &link).expect("snapshot symlink");
        assert!(matches!(
            open(&backend, &link, identity(), members()).await,
            Err(ConfigConsensusStorageError::InvalidIdentity)
        ));

        let bound = temp.path().join("bound");
        let (mut log, _, _) = open(&backend, &bound, identity(), members())
            .await
            .expect("private bound root");
        let moved = temp.path().join("moved");
        std::fs::rename(&bound, &moved).expect("rename admitted root");
        assert!(log.purge(log_id(0)).await.is_err());
    }

    #[tokio::test]
    async fn startup_snapshot_directory_scan_is_bounded() {
        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let snapshot_dir = temp.path().join("snapshots");
        let backend = SqliteBackend::in_memory_for_test()
            .await
            .expect("config backend");
        open(&backend, &snapshot_dir, identity(), members())
            .await
            .expect("initial storage");
        for index in 0..=SNAPSHOT_DIRECTORY_MAX_ENTRIES {
            std::fs::File::create(snapshot_dir.join(format!("operator-file-{index}")))
                .expect("directory entry");
        }

        assert!(matches!(
            open(&backend, &snapshot_dir, identity(), members()).await,
            Err(ConfigConsensusStorageError::CorruptState)
        ));
    }

    #[test]
    fn sqlite_staging_guard_removes_sidecars() {
        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let path = temp.path().join("build-cancelled.sqlite");
        std::fs::File::create(&path).expect("staging database");
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut sidecar = path.as_os_str().to_os_string();
            sidecar.push(suffix);
            std::fs::File::create(PathBuf::from(sidecar)).expect("SQLite sidecar");
        }
        drop(StagingArtifact::sqlite(path));
        assert!(std::fs::read_dir(temp.path())
            .expect("snapshot directory")
            .next()
            .is_none());
    }
}
