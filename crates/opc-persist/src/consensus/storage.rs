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
use opc_consensus::{ConsensusIdentity, ConsensusNodeId};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use super::snapshot_file::ConfigSnapshotFile;
use super::{sqlite, ApprovedLegacyConfigRecovery, ConfigConsensusResponse, ConfigRaftTypeConfig};
use crate::backend::SqliteBackend;

const SNAPSHOT_FOOTER_MAGIC: &[u8; 8] = b"OPCCFG01";
const SNAPSHOT_FOOTER_BYTES: u64 = 8 + 2 + 8 + 32;
const SNAPSHOT_MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const LIMITED_LOG_READ_ENTRIES: usize = 1_024;
const SNAPSHOT_DIRECTORY_MAX_ENTRIES: usize = 8_192;
const SNAPSHOT_OPERATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

#[must_use = "staging artifacts must stay guarded until they are durably referenced"]
struct StagingArtifact {
    path: PathBuf,
    sqlite_sidecars: bool,
    armed: bool,
}

impl StagingArtifact {
    fn file(path: PathBuf) -> Self {
        Self {
            path,
            sqlite_sidecars: false,
            armed: true,
        }
    }

    fn sqlite(path: PathBuf) -> Self {
        Self {
            path,
            sqlite_sidecars: true,
            armed: true,
        }
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
    core: sqlite::ConfigConsensusCore,
}

#[derive(Clone)]
pub(crate) struct SqliteConfigStateMachine {
    core: sqlite::ConfigConsensusCore,
}

pub(crate) struct SqliteConfigSnapshotBuilder {
    core: sqlite::ConfigConsensusCore,
}

#[derive(Debug, Default)]
pub(crate) struct ConfigDurableProgress {
    committed_present: AtomicBool,
    committed_index: AtomicU64,
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
}

type OpenedConfigStorage = (
    SqliteConfigLogStore,
    SqliteConfigStateMachine,
    Arc<ConfigDurableProgress>,
);

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
    let (snapshot_dir, snapshot_binding_path, snapshot_dir_guard) =
        admit_snapshot_directory(backend, snapshot_dir.into())?;
    let already_completed = if let Some(approval) = recovery.as_ref() {
        let conn = backend.conn();
        let approval = approval.clone();
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::task::spawn_blocking(move || {
                let conn = conn.blocking_lock();
                sqlite::completed_legacy_recovery_matches_sync(&conn, &approval)
            }),
        )
        .await
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)??
    } else {
        false
    };
    let staged = match recovery {
        Some(approval) if !already_completed => Some(
            tokio::time::timeout(
                SNAPSHOT_OPERATION_TIMEOUT,
                stage_legacy_recovery_snapshot(&snapshot_dir, approval),
            )
            .await
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)??,
        ),
        Some(_) | None => None,
    };
    let progress = Arc::new(ConfigDurableProgress::default());
    let core = sqlite::ConfigConsensusCore::initialize(
        backend,
        snapshot_dir,
        identity,
        expected_members,
        snapshot_dir_guard,
        snapshot_binding_path,
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

#[cfg(unix)]
fn admit_snapshot_directory(
    backend: &SqliteBackend,
    path: PathBuf,
) -> Result<(PathBuf, PathBuf, Arc<std::fs::File>), ConfigConsensusStorageError> {
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
    let directory = Arc::new(directory);
    let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
    Ok((descriptor_path, canonical, directory))
}

#[cfg(not(unix))]
fn admit_snapshot_directory(
    _backend: &SqliteBackend,
    _path: PathBuf,
) -> Result<(PathBuf, PathBuf, Arc<std::fs::File>), ConfigConsensusStorageError> {
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
    let mut output = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&staged_path)
        .await
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    set_private_file_permissions(&staged_path)
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    let mut staged_cleanup = StagingArtifact::sqlite(staged_path.clone());
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

fn ensure_legacy_wal_is_offline(
    source: &Path,
) -> Result<(), ConfigConsensusStorageError> {
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
fn set_private_file_permissions(path: &Path) -> io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> io::Result<()> {
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
        let file_type = tokio::fs::symlink_metadata(&path)
            .await
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

    let mut directory = tokio::fs::read_dir(core.snapshot_dir.as_ref())
        .await
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    let mut inspected = 0_usize;
    let mut removed = false;
    while let Some(entry) = directory
        .next_entry()
        .await
        .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?
    {
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
        let sqlite_staging = ["install-", "build-", "approved-legacy-"]
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
        let file_type = entry
            .file_type()
            .await
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
        if !file_type.is_file() && !file_type.is_symlink() {
            return Err(ConfigConsensusStorageError::CorruptState);
        }
        tokio::fs::remove_file(entry.path())
            .await
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
        removed = true;
    }
    if removed {
        sync_directory(core.snapshot_dir.as_ref())
            .await
            .map_err(|_| ConfigConsensusStorageError::BackendUnavailable)?;
    }
    Ok(())
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
                sqlite::read_log_range_sync(
                    conn,
                    identity,
                    &members,
                    start,
                    Some(end),
                    Some(LIMITED_LOG_READ_ENTRIES),
                )
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
        let vote = vote.clone();
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
        let entries = entries.into_iter().collect::<Vec<_>>();
        let identity = self.core.identity;
        let members = self.core.expected_members.clone();
        match self
            .core
            .run_sqlite(move |conn| sqlite::append_logs_sync(conn, identity, &members, &entries))
            .await
        {
            Ok(()) => {
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
            .map_err(|error| storage_error(ErrorSubject::Log(log_id), ErrorVerb::Delete, error))
    }

    async fn purge(
        &mut self,
        log_id: LogId<ConsensusNodeId>,
    ) -> Result<(), StorageError<ConsensusNodeId>> {
        validate_snapshot_binding(&self.core)
            .map_err(|error| storage_error(ErrorSubject::Log(log_id), ErrorVerb::Delete, error))?;
        let identity = self.core.identity;
        self.core
            .run_sqlite(move |conn| sqlite::purge_logs_sync(conn, identity, &log_id))
            .await
            .map_err(|error| storage_error(ErrorSubject::Log(log_id), ErrorVerb::Delete, error))
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
        let identity = self.core.identity;
        let members = self.core.expected_members.clone();
        let entries = entries.into_iter().collect();
        self.core
            .run_sqlite(move |conn| sqlite::apply_entries_sync(conn, identity, &members, entries))
            .await
            .map_err(|error| storage_error(ErrorSubject::StateMachine, ErrorVerb::Write, error))
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
        ConfigSnapshotFile::create(
            self.core
                .snapshot_dir
                .join(format!("incoming-{}.part", uuid::Uuid::new_v4())),
        )
        .await
        .map(Box::new)
        .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<ConsensusNodeId, opc_consensus::engine::EmptyNode>,
        mut snapshot: Box<ConfigSnapshotFile>,
    ) -> Result<(), StorageError<ConsensusNodeId>> {
        let result = match tokio::time::timeout(SNAPSHOT_OPERATION_TIMEOUT, async {
            validate_snapshot_binding(&self.core).map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            let _guard = self.core.snapshot_gate.lock().await;
            snapshot.sync_all().await.map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            let incoming = snapshot.path().to_path_buf();
            snapshot.disarm_cleanup();
            drop(snapshot);
            let _incoming_cleanup = StagingArtifact::file(incoming.clone());
            let (payload_length, checksum, total_length) =
                verify_snapshot_envelope(&incoming).await.map_err(|error| {
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
            let _raw_cleanup = extract_snapshot_database(&incoming, &raw, payload_length)
                .await
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
            let mut final_cleanup = copy_and_promote(&incoming, &promoting, &final_path)
                .await
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
            let previous = self
                .core
                .run_sqlite(move |conn| {
                    let previous = sqlite::read_current_snapshot_sync(conn, identity, &members)?;
                    sqlite::install_snapshot_database_sync(
                        conn,
                        identity,
                        &members,
                        &audit_key,
                        &raw_for_install,
                        &meta_for_install,
                        &file_name_for_install,
                        checksum,
                        total_length,
                    )?;
                    Ok(previous)
                })
                .await
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Write,
                        error,
                    )
                })?;
            final_cleanup.disarm();
            remove_old_snapshot(&self.core.snapshot_dir, previous, &file_name).await;
            Ok(())
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Write,
                sqlite::invalid_data("config consensus snapshot install timed out"),
            )),
        };
        if result.is_err() {
            opc_redaction::metrics::METRICS
                .persist_snapshot_install_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        result
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<ConfigRaftTypeConfig>>, StorageError<ConsensusNodeId>> {
        validate_snapshot_binding(&self.core)
            .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, error))?;
        let identity = self.core.identity;
        let members = self.core.expected_members.clone();
        let current = self
            .core
            .run_sqlite(move |conn| sqlite::read_current_snapshot_sync(conn, identity, &members))
            .await
            .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, error))?;
        let Some((meta, file_name, expected_checksum, expected_length)) = current else {
            return Ok(None);
        };
        let path = self.core.snapshot_dir.join(file_name);
        let (_, checksum, length) =
            tokio::time::timeout(SNAPSHOT_OPERATION_TIMEOUT, verify_snapshot_envelope(&path))
                .await
                .map_err(|_| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        sqlite::invalid_data("config consensus snapshot verification timed out"),
                    )
                })?
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
        let file = ConfigSnapshotFile::open(path).await.map_err(|error| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Read,
                error,
            )
        })?;
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
        let _guard = self.core.snapshot_gate.lock().await;
        let raw = self
            .core
            .snapshot_dir
            .join(format!("build-{}.sqlite", uuid::Uuid::new_v4()));
        let identity = self.core.identity;
        let members = self.core.expected_members.clone();
        let audit_key = self.core.audit_key.clone();
        let raw_for_build = raw.clone();
        let (last_log_id, last_membership) = self
            .core
            .run_sqlite(move |conn| {
                sqlite::build_snapshot_database_sync(
                    conn,
                    identity,
                    &members,
                    &audit_key,
                    &raw_for_build,
                )
            })
            .await
            .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, error))?;
        let _raw_cleanup = StagingArtifact::sqlite(raw.clone());
        let snapshot_id = uuid::Uuid::new_v4().to_string();
        let file_name = format!("snapshot-{snapshot_id}.opc");
        let final_path = self.core.snapshot_dir.join(&file_name);
        let staging = self
            .core
            .snapshot_dir
            .join(format!("snapshot-{snapshot_id}.part"));
        let (checksum, length, mut final_cleanup) = tokio::time::timeout(
            SNAPSHOT_OPERATION_TIMEOUT,
            envelope_snapshot_database(&raw, &staging),
        )
        .await
        .map_err(|_| {
            storage_error(
                ErrorSubject::Snapshot(None),
                ErrorVerb::Write,
                sqlite::invalid_data("config consensus snapshot build timed out"),
            )
        })?
        .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error))?;
        std::fs::rename(&staging, &final_path).map_err(|error| {
            storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
        })?;
        final_cleanup.replace_path(final_path.clone());
        sync_directory(&self.core.snapshot_dir)
            .await
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
        let _ = tokio::fs::remove_file(&raw).await;
        let meta = SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id,
        };
        let identity = self.core.identity;
        let members = self.core.expected_members.clone();
        let meta_for_save = meta.clone();
        let file_name_for_save = file_name.clone();
        let previous = self
            .core
            .run_sqlite(move |conn| {
                let previous = sqlite::read_current_snapshot_sync(conn, identity, &members)?;
                sqlite::save_current_snapshot_sync(
                    conn,
                    identity,
                    &members,
                    &meta_for_save,
                    &file_name_for_save,
                    checksum,
                    length,
                )?;
                Ok(previous)
            })
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
        final_cleanup.disarm();
        remove_old_snapshot(&self.core.snapshot_dir, previous, &file_name).await;
        let snapshot = ConfigSnapshotFile::open(final_path)
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Read,
                    error,
                )
            })?;
        Ok(Snapshot {
            meta,
            snapshot: Box::new(snapshot),
        })
    }
}

async fn envelope_snapshot_database(
    raw: &Path,
    output: &Path,
) -> io::Result<([u8; 32], u64, StagingArtifact)> {
    let metadata = tokio::fs::metadata(raw).await?;
    if metadata.len() == 0 || metadata.len() > SNAPSHOT_MAX_BYTES {
        return Err(sqlite::invalid_data(
            "config consensus snapshot size is invalid",
        ));
    }
    let mut source = tokio::fs::File::from_std(open_read_nofollow(raw)?);
    let mut destination = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output)
        .await?;
    set_private_file_permissions(output)?;
    let cleanup = StagingArtifact::file(output.to_path_buf());
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

async fn verify_snapshot_envelope(path: &PathBuf) -> io::Result<(u64, [u8; 32], u64)> {
    let source = open_read_nofollow(path)?;
    let metadata = source.metadata()?;
    let total = metadata.len();
    if total <= SNAPSHOT_FOOTER_BYTES || total > SNAPSHOT_MAX_BYTES + SNAPSHOT_FOOTER_BYTES {
        return Err(sqlite::invalid_data(
            "config consensus snapshot size is invalid",
        ));
    }
    let payload_length = total - SNAPSHOT_FOOTER_BYTES;
    let mut file = tokio::fs::File::from_std(source);
    file.seek(io::SeekFrom::Start(payload_length)).await?;
    let mut magic = [0_u8; 8];
    file.read_exact(&mut magic).await?;
    if &magic != SNAPSHOT_FOOTER_MAGIC {
        return Err(sqlite::invalid_data(
            "config consensus snapshot footer is invalid",
        ));
    }
    let mut revision = [0_u8; 2];
    file.read_exact(&mut revision).await?;
    if u16::from_be_bytes(revision) != super::types::CONFIG_CONSENSUS_SNAPSHOT_VERSION {
        return Err(sqlite::invalid_data(
            "config consensus snapshot revision is unsupported",
        ));
    }
    let mut length = [0_u8; 8];
    file.read_exact(&mut length).await?;
    if u64::from_be_bytes(length) != payload_length {
        return Err(sqlite::invalid_data(
            "config consensus snapshot length footer mismatch",
        ));
    }
    let mut expected = [0_u8; 32];
    file.read_exact(&mut expected).await?;
    file.seek(io::SeekFrom::Start(0)).await?;
    let mut remaining = payload_length;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| sqlite::invalid_data("config consensus snapshot read overflow"))?;
        let read = file.read(&mut buffer[..requested]).await?;
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
    Ok((payload_length, actual, total))
}

async fn extract_snapshot_database(
    envelope: &Path,
    destination: &Path,
    payload_length: u64,
) -> io::Result<StagingArtifact> {
    let mut source = tokio::fs::File::from_std(open_read_nofollow(envelope)?);
    let mut output = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(destination)
        .await?;
    set_private_file_permissions(destination)?;
    let cleanup = StagingArtifact::sqlite(destination.to_path_buf());
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
) -> io::Result<StagingArtifact> {
    let mut input = tokio::fs::File::from_std(open_read_nofollow(source)?);
    let mut output = tokio::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(staging)
        .await?;
    set_private_file_permissions(staging)?;
    let mut cleanup = StagingArtifact::file(staging.to_path_buf());
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

async fn remove_old_snapshot(
    snapshot_dir: &std::path::Path,
    previous: Option<sqlite::CurrentSnapshot>,
    current_file_name: &str,
) {
    if let Some((_, previous_file_name, _, _)) = previous {
        if previous_file_name != current_file_name {
            let _ = tokio::fs::remove_file(snapshot_dir.join(previous_file_name)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use opc_consensus::engine::{CommittedLeaderId, EntryPayload, Membership, RaftSnapshotBuilder};
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

    use super::*;
    use crate::consensus::{
        ConfigConsensusClusterId, ConfigConsensusCommand, ConfigConsensusConfigurationEpoch,
        ConfigConsensusConfigurationId, ConfigConsensusRequestId, ConfigMutationIntent,
        CONFIG_CONSENSUS_COMMAND_VERSION,
    };

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
    async fn file_snapshot_install_is_checksummed_atomic_and_replaces_applied_state() {
        let temp = tempfile::tempdir().expect("snapshot tempdir");
        let source_backend = SqliteBackend::open_with_audit_key(
            ":memory:",
            true,
            0,
            shared_audit_key(),
        )
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
        source_machine
            .apply([membership_entry(), mutation_entry()])
            .await
            .expect("source apply");
        let mut snapshot = source_machine
            .get_snapshot_builder()
            .await
            .build_snapshot()
            .await
            .expect("source snapshot");
        assert_eq!(Some(log_id(1)), snapshot.meta.last_log_id);

        let rejected_backend = SqliteBackend::open_with_audit_key(
            ":memory:",
            true,
            0,
            shared_audit_key(),
        )
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
        let destination_backend = SqliteBackend::open_with_audit_key(
            ":memory:",
            true,
            0,
            shared_audit_key(),
        )
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
        let (applied, membership) = destination_machine
            .applied_state()
            .await
            .expect("installed applied state");
        assert_eq!(snapshot.meta.last_log_id, applied);
        assert_eq!(snapshot.meta.last_membership, membership);

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
        let logs: i64 = conn
            .query_row("SELECT COUNT(*) FROM config_raft_log", [], |row| row.get(0))
            .expect("installed log count");
        assert_eq!(1, sequence);
        assert_eq!(1, outcomes);
        assert_eq!(0, logs, "snapshot must not import log-store authority");
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

        open(&backend, &snapshot_dir, identity(), members())
            .await
            .expect("restart cleans interrupted artifacts");
        assert!(snapshot_dir.join(&current).is_file());
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
        let backend = SqliteBackend::open_with_audit_key(
            ":memory:",
            true,
            0,
            shared_audit_key(),
        )
        .await
        .expect("backend");
        assert!(matches!(
            open(&backend, temp.path(), identity(), members()).await,
            Err(ConfigConsensusStorageError::InvalidIdentity)
        ));

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
