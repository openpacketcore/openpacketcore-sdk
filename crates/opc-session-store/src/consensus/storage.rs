//! Openraft storage adapters backed by the session SQLite database.
//!
//! Openraft exclusively owns election, commit, and membership decisions. This
//! adapter only provides serialized durable I/O and deterministic application
//! of entries Openraft has already committed.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::ops::{Bound, RangeBounds};
use std::path::{Path, PathBuf};

use opc_consensus::engine::storage::{LogFlushed, RaftLogStorage, RaftStateMachine};
use opc_consensus::engine::{
    Entry, EntryPayload, ErrorSubject, ErrorVerb, LogId, LogState, RaftLogReader,
    RaftSnapshotBuilder, Snapshot, SnapshotMeta, StorageError, StoredMembership, Vote,
};
use opc_consensus::DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use super::raft_adapter::{SessionRaftAdapterError, SessionRaftPeerDirectory};
use super::snapshot::{PinnedSqliteFile, SessionSnapshotFile, UnpublishedSnapshotArtifact};
use super::{
    SessionConsensusIdentity, SessionConsensusNodeId, SessionRaftTypeConfig,
    SessionTopologyMemberBinding,
};
use crate::backend::ReplicationEntry;
use crate::readiness::PlacementResiliencePolicy;
use crate::sqlite::consensus::{self, SqliteConsensusCore};
use crate::sqlite::SqliteSessionBackend;

const SNAPSHOT_FOOTER_MAGIC: &[u8; 8] = b"OPCSNP01";
const SNAPSHOT_FOOTER_BYTES: u64 = 8 + 8 + 32;
const SNAPSHOT_MAX_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const SNAPSHOT_DIRECTORY_MAX_ENTRIES: usize = 8_192;
const SNAPSHOT_APPLY_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Fail-closed errors emitted while binding an existing SQLite database to a
/// durable consensus identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SessionConsensusStorageError {
    /// Durable consensus initialization is unsupported on this platform.
    #[error("session consensus storage is unsupported on this platform")]
    UnsupportedPlatform,
    /// Legacy session authority exists without a durable consensus identity.
    #[error("session consensus recovery is required before this database can join a cluster")]
    RecoveryRequired,
    /// The persisted cluster/configuration/epoch differs from the requested scope.
    #[error("session consensus storage identity does not match this configuration")]
    IdentityMismatch,
    /// The database was created by another consensus storage schema.
    #[error("unsupported session consensus storage schema")]
    SchemaVersionMismatch,
    /// A required row, constraint, or typed high-water mark is invalid.
    #[error("session consensus durable state is corrupt")]
    CorruptState,
    /// The supplied identity could not be represented by the durable schema.
    #[error("invalid session consensus storage identity")]
    InvalidIdentity,
    /// SQLite or snapshot storage could not be initialized.
    #[error("session consensus storage is unavailable")]
    BackendUnavailable,
}

/// Immutable authority model bound to one durable consensus database.
///
/// Dynamic authority permits the existing staged membership-transition model.
/// Fixed authority is set only when a pristine database is first admitted and
/// requires the original storage identity on every later open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConsensusAuthorityProfile {
    /// The durable store uses the normal dynamic-membership authority model.
    Dynamic,
    /// The durable store is permanently bound to one exact fixed quorum.
    FixedImmutable,
}

/// Serialized Openraft vote/log persistence.
#[derive(Clone)]
pub(crate) struct SqliteConsensusLogStore {
    core: SqliteConsensusCore,
}

/// Persistent session state machine and snapshot owner.
#[derive(Clone)]
pub(crate) struct SqliteConsensusStateMachine {
    core: SqliteConsensusCore,
    membership_admission: Option<SessionRaftPeerDirectory>,
}

impl SqliteConsensusStateMachine {
    async fn begin_membership_apply(&self) -> Option<tokio::sync::OwnedRwLockWriteGuard<()>> {
        match self.membership_admission.as_ref() {
            Some(admission) => Some(admission.begin_membership_apply().await),
            None => None,
        }
    }

    fn observe_applied_membership(
        &self,
        membership: &StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
    ) -> Result<(), SessionRaftAdapterError> {
        let Some(admission) = self.membership_admission.as_ref() else {
            return Ok(());
        };
        admission.observe_applied_membership(membership)
    }

    /// Read the durable application chain head for storage qualification.
    #[cfg(test)]
    pub(crate) async fn proposal_state(
        &self,
    ) -> Result<
        (
            u64,
            super::SessionConsensusEntryDigest,
            Option<opc_types::Timestamp>,
        ),
        SessionConsensusStorageError,
    > {
        let conn = self.core.conn.lock().await;
        consensus::proposal_state_sync(&conn, self.core.storage_identity)
            .map_err(|_| SessionConsensusStorageError::CorruptState)
    }
}

/// Snapshot builder holding a point-in-time SQLite backup, not an in-memory
/// serialization of the session database.
pub(crate) struct SqliteConsensusSnapshotBuilder {
    core: SqliteConsensusCore,
}

pub(crate) async fn open_with_member_bindings(
    backend: &SqliteSessionBackend,
    snapshot_dir: impl Into<PathBuf>,
    identity: SessionConsensusIdentity,
    expected_members: BTreeSet<SessionConsensusNodeId>,
    expected_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    membership_admission: SessionRaftPeerDirectory,
) -> Result<
    (
        SqliteConsensusLogStore,
        SqliteConsensusStateMachine,
        SessionConsensusIdentity,
    ),
    SessionConsensusStorageError,
> {
    open_with_member_bindings_for_profile(
        backend,
        snapshot_dir,
        identity,
        expected_members,
        expected_bindings,
        membership_admission,
        ConsensusAuthorityProfile::Dynamic,
        None,
    )
    .await
}

/// Open one durable fixed-quorum authority store.
///
/// Unlike the dynamic entry point, this binds the original durable storage
/// identity to `identity` permanently and rejects membership transitions.
pub(crate) async fn open_fixed_with_member_bindings(
    backend: &SqliteSessionBackend,
    snapshot_dir: impl Into<PathBuf>,
    identity: SessionConsensusIdentity,
    expected_members: BTreeSet<SessionConsensusNodeId>,
    expected_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    membership_admission: SessionRaftPeerDirectory,
    placement_policy: PlacementResiliencePolicy,
) -> Result<
    (
        SqliteConsensusLogStore,
        SqliteConsensusStateMachine,
        SessionConsensusIdentity,
    ),
    SessionConsensusStorageError,
> {
    open_with_member_bindings_for_profile(
        backend,
        snapshot_dir,
        identity,
        expected_members,
        expected_bindings,
        membership_admission,
        ConsensusAuthorityProfile::FixedImmutable,
        Some(placement_policy),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn open_with_member_bindings_for_profile(
    backend: &SqliteSessionBackend,
    snapshot_dir: impl Into<PathBuf>,
    identity: SessionConsensusIdentity,
    expected_members: BTreeSet<SessionConsensusNodeId>,
    expected_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    membership_admission: SessionRaftPeerDirectory,
    authority_profile: ConsensusAuthorityProfile,
    fixed_placement_policy: Option<PlacementResiliencePolicy>,
) -> Result<
    (
        SqliteConsensusLogStore,
        SqliteConsensusStateMachine,
        SessionConsensusIdentity,
    ),
    SessionConsensusStorageError,
> {
    let core = SqliteConsensusCore::initialize(
        backend,
        snapshot_dir.into(),
        identity,
        expected_members,
        expected_bindings,
        authority_profile,
        fixed_placement_policy,
    )
    .await?;
    validate_and_clean_snapshot_directory(&core).await?;
    let storage_identity = core.storage_identity;
    Ok((
        SqliteConsensusLogStore { core: core.clone() },
        SqliteConsensusStateMachine {
            core,
            membership_admission: Some(membership_admission),
        },
        storage_identity,
    ))
}

#[cfg(test)]
async fn open(
    backend: &SqliteSessionBackend,
    snapshot_dir: impl Into<PathBuf>,
    identity: SessionConsensusIdentity,
    expected_members: BTreeSet<SessionConsensusNodeId>,
) -> Result<(SqliteConsensusLogStore, SqliteConsensusStateMachine), SessionConsensusStorageError> {
    let bindings = expected_members
        .iter()
        .copied()
        .map(|node| {
            let mut descriptor = [0x11; 32];
            descriptor[..8].copy_from_slice(&node.get().to_be_bytes());
            let mut endpoint = [0x22; 32];
            endpoint[..8].copy_from_slice(&node.get().to_be_bytes());
            let mut tls = [0x33; 32];
            tls[..8].copy_from_slice(&node.get().to_be_bytes());
            let mut backing = [0x44; 32];
            backing[..8].copy_from_slice(&node.get().to_be_bytes());
            (
                node,
                SessionTopologyMemberBinding::new(descriptor, endpoint, tls, backing),
            )
        })
        .collect();
    let core = SqliteConsensusCore::initialize(
        backend,
        snapshot_dir.into(),
        identity,
        expected_members,
        bindings,
        ConsensusAuthorityProfile::Dynamic,
        None,
    )
    .await?;
    validate_and_clean_snapshot_directory(&core).await?;
    Ok((
        SqliteConsensusLogStore { core: core.clone() },
        SqliteConsensusStateMachine {
            core,
            membership_admission: None,
        },
    ))
}

/// Open a pristine or restarted candidate with one exact successor scope
/// durably staged in the same SQLite transaction as schema admission.
///
/// The candidate's node may be absent from `expected_members`; membership and
/// transport admission remain driver responsibilities. Snapshot installation
/// subsequently requires the source to carry this exact pending scope.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn open_with_pending_membership(
    backend: &SqliteSessionBackend,
    snapshot_dir: impl Into<PathBuf>,
    storage_identity: SessionConsensusIdentity,
    current_identity: SessionConsensusIdentity,
    current_members: BTreeSet<SessionConsensusNodeId>,
    current_bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    local_candidate_node_id: SessionConsensusNodeId,
    transition_id: [u8; 16],
    transition_digest: [u8; 32],
    desired_identity: SessionConsensusIdentity,
    desired_members: &BTreeSet<SessionConsensusNodeId>,
    desired_bindings: &BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    membership_admission: SessionRaftPeerDirectory,
) -> Result<
    (
        SqliteConsensusLogStore,
        SqliteConsensusStateMachine,
        SessionConsensusIdentity,
    ),
    SessionConsensusStorageError,
> {
    let core = SqliteConsensusCore::initialize_with_pending(
        backend,
        snapshot_dir.into(),
        storage_identity,
        current_identity,
        current_members,
        current_bindings,
        consensus::PendingMembershipBootstrap {
            local_candidate_node_id: Some(local_candidate_node_id),
            transition_id,
            transition_digest,
            desired_identity,
            desired_members,
            desired_bindings,
        },
        ConsensusAuthorityProfile::Dynamic,
        None,
    )
    .await?;
    validate_and_clean_snapshot_directory(&core).await?;
    let storage_identity = core.storage_identity;
    Ok((
        SqliteConsensusLogStore { core: core.clone() },
        SqliteConsensusStateMachine {
            core,
            membership_admission: Some(membership_admission),
        },
        storage_identity,
    ))
}

async fn validate_and_clean_snapshot_directory(
    core: &SqliteConsensusCore,
) -> Result<(), SessionConsensusStorageError> {
    let current = {
        let conn = core.conn.lock().await;
        consensus::read_current_snapshot_sync(&conn, core.storage_identity)
            .map_err(|_| SessionConsensusStorageError::CorruptState)?
    };
    let current_file_name = current
        .as_ref()
        .map(|(_, file_name, _, _)| file_name.as_str());
    if let Some((_, file_name, expected_checksum, expected_length)) = &current {
        let path = core.snapshot_dir.join(file_name);
        let mut snapshot = SessionSnapshotFile::open(path)
            .await
            .map_err(|_| SessionConsensusStorageError::CorruptState)?;
        let (_, checksum, length) = verify_snapshot_envelope_reader(&mut snapshot)
            .await
            .map_err(|_| SessionConsensusStorageError::CorruptState)?;
        if checksum != *expected_checksum || length != *expected_length {
            return Err(SessionConsensusStorageError::CorruptState);
        }
    }

    let mut directory = tokio::fs::read_dir(core.snapshot_dir.as_ref())
        .await
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    let mut inspected = 0_usize;
    let mut removed = false;
    while let Some(entry) = directory
        .next_entry()
        .await
        .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?
    {
        inspected = inspected
            .checked_add(1)
            .ok_or(SessionConsensusStorageError::CorruptState)?;
        if inspected > SNAPSHOT_DIRECTORY_MAX_ENTRIES {
            return Err(SessionConsensusStorageError::CorruptState);
        }
        let Some(file_name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let part_staging = [
            ("incoming-", ".part"),
            ("promote-", ".part"),
            ("seal-", ".part"),
        ]
        .iter()
        .any(|(prefix, suffix)| file_name.starts_with(prefix) && file_name.ends_with(suffix));
        let sqlite_staging = ["install-", "build-"]
            .iter()
            .any(|prefix| file_name.starts_with(prefix))
            && [".sqlite", ".sqlite-journal", ".sqlite-wal", ".sqlite-shm"]
                .iter()
                .any(|suffix| file_name.ends_with(suffix));
        let staging = part_staging || sqlite_staging;
        let orphan_snapshot = file_name.starts_with("snapshot-")
            && file_name.ends_with(".opc")
            && current_file_name != Some(file_name.as_str());
        if !staging && !orphan_snapshot {
            continue;
        }
        let file_type = entry
            .file_type()
            .await
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        if !file_type.is_file() && !file_type.is_symlink() {
            return Err(SessionConsensusStorageError::CorruptState);
        }
        tokio::fs::remove_file(entry.path())
            .await
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
        removed = true;
    }
    if removed {
        sync_directory(core.snapshot_dir.as_ref())
            .map_err(|_| SessionConsensusStorageError::BackendUnavailable)?;
    }
    Ok(())
}

fn storage_error(
    subject: ErrorSubject<SessionConsensusNodeId>,
    verb: ErrorVerb,
    error: io::Error,
) -> StorageError<SessionConsensusNodeId> {
    StorageError::from_io_error(subject, verb, error)
}

fn membership_admission_storage_error(
    _error: SessionRaftAdapterError,
) -> StorageError<SessionConsensusNodeId> {
    storage_error(
        ErrorSubject::StateMachine,
        ErrorVerb::Write,
        io::Error::other("session consensus membership admission is unavailable"),
    )
}

fn range_to_half_open<R: RangeBounds<u64>>(range: &R) -> io::Result<(u64, Option<u64>)> {
    let start = match range.start_bound() {
        Bound::Included(value) => *value,
        Bound::Excluded(value) => value
            .checked_add(1)
            .ok_or_else(|| consensus::invalid_data("session consensus log range overflow"))?,
        Bound::Unbounded => 0,
    };
    let end = match range.end_bound() {
        Bound::Included(value) => Some(
            value
                .checked_add(1)
                .ok_or_else(|| consensus::invalid_data("session consensus log range overflow"))?,
        ),
        Bound::Excluded(value) => Some(*value),
        Bound::Unbounded => None,
    };
    Ok((start, end))
}

impl RaftLogReader<SessionRaftTypeConfig> for SqliteConsensusLogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + std::fmt::Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<SessionRaftTypeConfig>>, StorageError<SessionConsensusNodeId>> {
        let (start, end) = range_to_half_open(&range)
            .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Read, error))?;
        let conn = self.core.conn.lock().await;
        consensus::with_durable_authority_raw_read_sync(
            &conn,
            self.core.storage_identity,
            self.core.authority_profile,
            &self.core.expected_members,
            &self.core.expected_bindings,
            self.core.fixed_placement_policy,
            |conn| {
                if end.is_some_and(|end| start >= end) {
                    return Ok(Vec::new());
                }
                consensus::read_log_range_sync(conn, self.core.storage_identity, start, end, None)
            },
        )
        .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Read, error))
    }

    async fn limited_get_log_entries(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<Vec<Entry<SessionRaftTypeConfig>>, StorageError<SessionConsensusNodeId>> {
        let conn = self.core.conn.lock().await;
        let entries = consensus::with_durable_authority_raw_read_sync(
            &conn,
            self.core.storage_identity,
            self.core.authority_profile,
            &self.core.expected_members,
            &self.core.expected_bindings,
            self.core.fixed_placement_policy,
            |conn| {
                if start >= end {
                    return Ok(Vec::new());
                }
                consensus::read_limited_log_range_sync(
                    conn,
                    self.core.storage_identity,
                    start,
                    end,
                    DURABLE_OPENRAFT_MAX_PAYLOAD_ENTRIES,
                )
            },
        )
        .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Read, error))?;
        if start >= end {
            return Ok(entries);
        }
        if entries.is_empty() {
            return Err(storage_error(
                ErrorSubject::Logs,
                ErrorVerb::Read,
                consensus::invalid_data(
                    "session consensus limited nonempty log range returned no entry",
                ),
            ));
        }
        Ok(entries)
    }
}

impl RaftLogStorage<SessionRaftTypeConfig> for SqliteConsensusLogStore {
    type LogReader = Self;

    async fn get_log_state(
        &mut self,
    ) -> Result<LogState<SessionRaftTypeConfig>, StorageError<SessionConsensusNodeId>> {
        let conn = self.core.conn.lock().await;
        let (last_purged_log_id, last_log_id) = consensus::with_durable_authority_raw_read_sync(
            &conn,
            self.core.storage_identity,
            self.core.authority_profile,
            &self.core.expected_members,
            &self.core.expected_bindings,
            self.core.fixed_placement_policy,
            |conn| {
                Ok((
                    consensus::read_purged_sync(conn, self.core.storage_identity)?,
                    consensus::last_log_sync(conn, self.core.storage_identity)?,
                ))
            },
        )
        .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Read, error))?;
        Ok(LogState {
            last_purged_log_id,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(
        &mut self,
        vote: &Vote<SessionConsensusNodeId>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>> {
        let conn = self.core.conn.lock().await;
        consensus::save_vote_with_authority_sync(
            &conn,
            self.core.storage_identity,
            self.core.authority_profile,
            &self.core.expected_members,
            &self.core.expected_bindings,
            self.core.fixed_placement_policy,
            vote,
        )
        .map_err(|error| storage_error(ErrorSubject::Vote, ErrorVerb::Write, error))
    }

    async fn read_vote(
        &mut self,
    ) -> Result<Option<Vote<SessionConsensusNodeId>>, StorageError<SessionConsensusNodeId>> {
        let conn = self.core.conn.lock().await;
        consensus::with_durable_authority_raw_read_sync(
            &conn,
            self.core.storage_identity,
            self.core.authority_profile,
            &self.core.expected_members,
            &self.core.expected_bindings,
            self.core.fixed_placement_policy,
            |conn| consensus::read_vote_sync(conn, self.core.storage_identity),
        )
        .map_err(|error| storage_error(ErrorSubject::Vote, ErrorVerb::Read, error))
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<SessionConsensusNodeId>>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>> {
        let conn = self.core.conn.lock().await;
        consensus::save_committed_with_authority_sync(
            &conn,
            self.core.storage_identity,
            self.core.authority_profile,
            &self.core.expected_members,
            &self.core.expected_bindings,
            self.core.fixed_placement_policy,
            committed,
        )
        .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Write, error))
    }

    async fn read_committed(
        &mut self,
    ) -> Result<Option<LogId<SessionConsensusNodeId>>, StorageError<SessionConsensusNodeId>> {
        let conn = self.core.conn.lock().await;
        consensus::with_durable_authority_raw_read_sync(
            &conn,
            self.core.storage_identity,
            self.core.authority_profile,
            &self.core.expected_members,
            &self.core.expected_bindings,
            self.core.fixed_placement_policy,
            |conn| consensus::read_committed_sync(conn, self.core.storage_identity),
        )
        .map_err(|error| storage_error(ErrorSubject::Logs, ErrorVerb::Read, error))
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<SessionRaftTypeConfig>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>>
    where
        I: IntoIterator<Item = Entry<SessionRaftTypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let entries: Vec<_> = entries.into_iter().collect();
        let conn = self.core.conn.lock().await;
        match consensus::append_logs_with_authority_sync(
            &conn,
            self.core.storage_identity,
            self.core.authority_profile,
            &self.core.expected_members,
            &self.core.expected_bindings,
            self.core.fixed_placement_policy,
            &entries,
        ) {
            Ok(()) => {
                callback.log_io_completed(Ok(()));
                Ok(())
            }
            Err(error) => {
                callback
                    .log_io_completed(Err(io::Error::other("session consensus log append failed")));
                Err(storage_error(ErrorSubject::Logs, ErrorVerb::Write, error))
            }
        }
    }

    async fn truncate(
        &mut self,
        log_id: LogId<SessionConsensusNodeId>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>> {
        let conn = self.core.conn.lock().await;
        consensus::truncate_logs_with_authority_sync(
            &conn,
            self.core.storage_identity,
            self.core.authority_profile,
            &self.core.expected_members,
            &self.core.expected_bindings,
            self.core.fixed_placement_policy,
            &log_id,
        )
        .map_err(|error| storage_error(ErrorSubject::Log(log_id), ErrorVerb::Delete, error))
    }

    async fn purge(
        &mut self,
        log_id: LogId<SessionConsensusNodeId>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>> {
        wait_until_applied(&self.core, &log_id)
            .await
            .map_err(|error| storage_error(ErrorSubject::Log(log_id), ErrorVerb::Delete, error))?;
        let conn = self.core.conn.lock().await;
        consensus::purge_logs_with_authority_sync(
            &conn,
            self.core.storage_identity,
            self.core.authority_profile,
            &self.core.expected_members,
            &self.core.expected_bindings,
            self.core.fixed_placement_policy,
            &log_id,
        )
        .map_err(|error| storage_error(ErrorSubject::Log(log_id), ErrorVerb::Delete, error))
    }
}

impl RaftStateMachine<SessionRaftTypeConfig> for SqliteConsensusStateMachine {
    type SnapshotBuilder = SqliteConsensusSnapshotBuilder;

    async fn applied_state(
        &mut self,
    ) -> Result<
        (
            Option<LogId<SessionConsensusNodeId>>,
            StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
        ),
        StorageError<SessionConsensusNodeId>,
    > {
        let (applied, membership) = {
            let _membership_apply = self.begin_membership_apply().await;
            let conn = self.core.conn.lock().await;
            let (applied, membership) = consensus::with_durable_authority_raw_read_sync(
                &conn,
                self.core.storage_identity,
                self.core.authority_profile,
                &self.core.expected_members,
                &self.core.expected_bindings,
                self.core.fixed_placement_policy,
                |conn| {
                    Ok((
                        consensus::read_applied_sync(conn, self.core.storage_identity)?,
                        consensus::read_membership_sync(conn, self.core.storage_identity)?,
                    ))
                },
            )
            .map_err(|error| storage_error(ErrorSubject::StateMachine, ErrorVerb::Read, error))?;
            self.observe_applied_membership(&membership)
                .map_err(membership_admission_storage_error)?;
            (applied, membership)
        };
        Ok((applied, membership))
    }

    async fn apply<I>(
        &mut self,
        entries: I,
    ) -> Result<Vec<super::SessionConsensusResponse>, StorageError<SessionConsensusNodeId>>
    where
        I: IntoIterator<Item = Entry<SessionRaftTypeConfig>> + Send,
        I::IntoIter: Send,
    {
        #[cfg(test)]
        let _apply_permit = self.core.apply_gate.acquire().await.map_err(|_| {
            storage_error(
                ErrorSubject::StateMachine,
                ErrorVerb::Write,
                io::Error::other("session consensus test apply gate closed"),
            )
        })?;
        let entries: Vec<_> = entries.into_iter().collect();
        let applies_membership = entries
            .iter()
            .any(|entry| matches!(&entry.payload, EntryPayload::Membership(_)));
        let applies_uniform_cutover = self.membership_admission.as_ref().is_some_and(|admission| {
            entries.iter().any(|entry| {
                let EntryPayload::Membership(membership) = &entry.payload else {
                    return false;
                };
                admission.requires_uniform_membership_fence(membership)
            })
        });
        let last_applied = entries.last().map(|entry| entry.log_id);
        let applied = {
            let _membership_apply = if applies_uniform_cutover {
                self.begin_membership_apply().await
            } else {
                None
            };
            let conn = self.core.conn.lock().await;
            let applied = consensus::apply_entries_with_authority_sync(
                &conn,
                self.core.storage_identity,
                &self.core.caps,
                self.core.authority_profile,
                &self.core.expected_members,
                &self.core.expected_bindings,
                self.core.fixed_placement_policy,
                entries,
            )
            .map_err(|error| storage_error(ErrorSubject::StateMachine, ErrorVerb::Write, error))?;
            if applies_membership {
                let membership = consensus::read_membership_sync(&conn, self.core.storage_identity)
                    .map_err(|error| {
                        storage_error(ErrorSubject::StateMachine, ErrorVerb::Read, error)
                    })?;
                self.observe_applied_membership(&membership)
                    .map_err(membership_admission_storage_error)?;
            }
            applied
        };
        if let Some(last_applied) = last_applied {
            self.core.applied_progress.send_replace(Some(last_applied));
        }
        notify_watchers(&self.core, &applied.notifications).await;
        Ok(applied.responses)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        SqliteConsensusSnapshotBuilder {
            core: self.core.clone(),
        }
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<SessionSnapshotFile>, StorageError<SessionConsensusNodeId>> {
        let path = self
            .core
            .snapshot_dir
            .join(format!("incoming-{}.part", uuid::Uuid::new_v4()));
        SessionSnapshotFile::create(path)
            .await
            .map(Box::new)
            .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
        mut snapshot: Box<SessionSnapshotFile>,
    ) -> Result<(), StorageError<SessionConsensusNodeId>> {
        let _snapshot_guard = self.core.snapshot_gate.lock().await;
        snapshot.sync_all().await.map_err(|error| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Write,
                error,
            )
        })?;
        let incoming_path = snapshot.path().to_path_buf();
        let (payload_length, checksum, total_length) =
            verify_snapshot_envelope_reader(&mut snapshot)
                .await
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        error,
                    )
                })?;
        let raw_path = self
            .core
            .snapshot_dir
            .join(format!("install-{}.sqlite", uuid::Uuid::new_v4()));
        let raw_snapshot =
            extract_snapshot_database_from_reader(&mut snapshot, &raw_path, payload_length)
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
        let promoted_path = self
            .core
            .snapshot_dir
            .join(format!("promote-{}.part", uuid::Uuid::new_v4()));
        if let Err(error) =
            copy_and_promote_from_reader(&mut snapshot, &promoted_path, &final_path, total_length)
                .await
        {
            let _ = tokio::fs::remove_file(&raw_path).await;
            return Err(storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Write,
                error,
            ));
        }
        drop(snapshot);

        let mut promoted_snapshot = SessionSnapshotFile::open(final_path.clone())
            .await
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Read,
                    error,
                )
            })?;
        let (_, promoted_checksum, promoted_length) =
            verify_snapshot_envelope_reader(&mut promoted_snapshot)
                .await
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        error,
                    )
                })?;
        if promoted_checksum != checksum || promoted_length != total_length {
            let _ = tokio::fs::remove_file(&final_path).await;
            let _ = tokio::fs::remove_file(&raw_path).await;
            return Err(storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Read,
                consensus::invalid_data("session consensus promoted snapshot is inconsistent"),
            ));
        }
        let promoted_pin =
            if self.core.authority_profile == ConsensusAuthorityProfile::FixedImmutable {
                Some(
                    snapshot_handle_pin(&promoted_snapshot, &final_path)
                        .await
                        .map_err(|error| {
                            storage_error(
                                ErrorSubject::Snapshot(Some(meta.signature())),
                                ErrorVerb::Read,
                                error,
                            )
                        })?,
                )
            } else {
                None
            };

        let installs_uniform_cutover =
            self.membership_admission.as_ref().is_some_and(|admission| {
                admission.requires_uniform_membership_fence(meta.last_membership.membership())
            });
        let install_result = {
            let _membership_apply = if installs_uniform_cutover {
                self.begin_membership_apply().await
            } else {
                None
            };
            let conn = self.core.conn.lock().await;
            let previous = consensus::read_current_snapshot_sync(&conn, self.core.storage_identity)
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        error,
                    )
                })?;
            if let Some(promoted_pin) = &promoted_pin {
                if !promoted_pin
                    .path_matches_identity(&final_path)
                    .map_err(|error| {
                        storage_error(
                            ErrorSubject::Snapshot(Some(meta.signature())),
                            ErrorVerb::Read,
                            error,
                        )
                    })?
                {
                    return Err(storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        consensus::invalid_data(
                            "session consensus published snapshot was replaced",
                        ),
                    ));
                }
            }
            match consensus::install_snapshot_database_from_pinned_with_authority_sync(
                &conn,
                self.core.storage_identity,
                self.core.authority_profile,
                Some(&self.core.expected_members),
                Some(&self.core.expected_bindings),
                self.core.fixed_placement_policy,
                raw_snapshot,
                promoted_pin.as_ref().map(|pin| (pin, final_path.as_path())),
                meta,
                &file_name,
                checksum,
                total_length,
            ) {
                Err(error) => Err(storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )),
                Ok(()) => {
                    self.observe_applied_membership(&meta.last_membership)
                        .map_err(membership_admission_storage_error)?;
                    Ok(previous)
                }
            }
        };
        let previous = match install_result {
            Ok(previous) => previous,
            Err(error) => {
                let _ = tokio::fs::remove_file(&final_path).await;
                let _ = tokio::fs::remove_file(&raw_path).await;
                return Err(error);
            }
        };
        self.core.applied_progress.send_replace(meta.last_log_id);
        let _ = tokio::fs::remove_file(&raw_path).await;
        let _ = tokio::fs::remove_file(&incoming_path).await;
        remove_old_snapshot(&self.core.snapshot_dir, previous, &file_name).await;
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<SessionRaftTypeConfig>>, StorageError<SessionConsensusNodeId>> {
        let current = {
            let conn = self.core.conn.lock().await;
            consensus::with_durable_authority_raw_read_sync(
                &conn,
                self.core.storage_identity,
                self.core.authority_profile,
                &self.core.expected_members,
                &self.core.expected_bindings,
                self.core.fixed_placement_policy,
                |conn| consensus::read_current_snapshot_sync(conn, self.core.storage_identity),
            )
            .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, error))?
        };
        let Some((meta, file_name, expected_checksum, expected_length)) = current else {
            return Ok(None);
        };
        let path = self.core.snapshot_dir.join(file_name);
        let mut snapshot = SessionSnapshotFile::open(path).await.map_err(|error| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Read,
                error,
            )
        })?;
        let (_, checksum, length) = verify_snapshot_envelope_reader(&mut snapshot)
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
                consensus::invalid_data("session consensus snapshot metadata is inconsistent"),
            ));
        }
        snapshot.rewind().await.map_err(|error| {
            storage_error(
                ErrorSubject::Snapshot(Some(meta.signature())),
                ErrorVerb::Read,
                error,
            )
        })?;
        {
            let conn = self.core.conn.lock().await;
            consensus::with_durable_authority_raw_read_sync(
                &conn,
                self.core.storage_identity,
                self.core.authority_profile,
                &self.core.expected_members,
                &self.core.expected_bindings,
                self.core.fixed_placement_policy,
                |_| Ok(()),
            )
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Read,
                    error,
                )
            })?;
        }
        Ok(Some(Snapshot {
            meta,
            snapshot: Box::new(snapshot),
        }))
    }
}

async fn wait_until_applied(
    core: &SqliteConsensusCore,
    through: &LogId<SessionConsensusNodeId>,
) -> io::Result<()> {
    let deadline = tokio::time::Instant::now()
        .checked_add(SNAPSHOT_APPLY_WAIT)
        .ok_or_else(|| consensus::invalid_data("session consensus apply wait is invalid"))?;
    let mut applied_progress = core.applied_progress.subscribe();
    loop {
        let applied = *applied_progress.borrow_and_update();
        if let Some(applied) = applied {
            if applied.index > through.index || &applied == through {
                return Ok(());
            }
            if applied.index == through.index {
                return Err(consensus::invalid_data(
                    "session consensus applied log conflicts with purge",
                ));
            }
        }
        tokio::time::timeout_at(deadline, applied_progress.changed())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "session consensus apply wait timed out",
                )
            })?
            .map_err(|_| {
                consensus::invalid_data("session consensus apply progress channel closed")
            })?;
    }
}

/// Build a file-backed snapshot from one independent WAL reader. The live
/// consensus connection is held only long enough to pin and compare the exact
/// applied/membership cut; validation, backup, and destination work never
/// retain that mutex.
#[allow(clippy::result_large_err)] // Openraft storage callbacks require this concrete error type.
async fn build_file_backed_snapshot_database(
    core: &SqliteConsensusCore,
    raw_path: &Path,
    snapshot_guard: tokio::sync::OwnedMutexGuard<()>,
) -> Result<
    (
        tokio::sync::OwnedMutexGuard<()>,
        Option<(
            (
                Option<LogId<SessionConsensusNodeId>>,
                StoredMembership<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
            ),
            PinnedSqliteFile,
        )>,
    ),
    StorageError<SessionConsensusNodeId>,
> {
    let (Some(database_path), Some(database_file_identity)) =
        (&core.database_path, core.database_file_identity)
    else {
        return Ok((snapshot_guard, None));
    };
    let reader = consensus::open_snapshot_read_connection(database_path, database_file_identity)
        .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, error))?;
    let source_cut = {
        let conn = core.conn.lock().await;
        match consensus::begin_snapshot_read_sync(&reader, core.storage_identity) {
            Ok(source_cut) => {
                match consensus::with_durable_authority_raw_read_sync(
                    &conn,
                    core.storage_identity,
                    core.authority_profile,
                    &core.expected_members,
                    &core.expected_bindings,
                    core.fixed_placement_policy,
                    |conn| consensus::snapshot_applied_membership_sync(conn, core.storage_identity),
                ) {
                    Ok(live_cut) if live_cut == source_cut => Ok(source_cut),
                    Ok(_) => Err(consensus::invalid_data(
                        "session consensus snapshot reader does not match the live cut",
                    )),
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    };
    let source_cut = match source_cut {
        Ok(source_cut) => source_cut,
        Err(error) => {
            let _ = consensus::release_snapshot_read_sync(&reader);
            return Err(storage_error(
                ErrorSubject::Snapshot(None),
                ErrorVerb::Read,
                error,
            ));
        }
    };

    let storage_identity = core.storage_identity;
    let authority_profile = core.authority_profile;
    let expected_members = core.expected_members.clone();
    let expected_bindings = core.expected_bindings.clone();
    let fixed_placement_policy = core.fixed_placement_policy;
    let raw_path = raw_path.to_path_buf();
    #[cfg(test)]
    let snapshot_capture_gate = std::sync::Arc::clone(&core.snapshot_capture_gate);

    // The owned guard moves into the worker and comes back with its result.
    // Cancellation of the async caller therefore cannot detach a second
    // snapshot worker or a second WAL-pinning reader for this consensus core.
    let (snapshot_guard, captured) = tokio::task::spawn_blocking(move || {
        #[cfg(test)]
        snapshot_capture_gate.block_after_capture();

        let captured = consensus::capture_snapshot_database_from_reader_sync(
            &reader,
            storage_identity,
            authority_profile,
            &expected_members,
            &expected_bindings,
            fixed_placement_policy,
            &source_cut,
            &raw_path,
        );
        // The source transaction is retained only through `Backup`; all
        // cleanup, VACUUM, validation, hashing, and sealing follow this
        // release and therefore cannot retain WAL frames.
        let released = consensus::release_snapshot_read_sync(&reader);
        let captured = match (captured, released) {
            (Ok(captured), Ok(())) => {
                let (captured_cut, raw_snapshot) = captured;
                consensus::finalize_captured_snapshot_database_sync(
                    storage_identity,
                    &captured_cut,
                    raw_snapshot,
                )
                .map(|raw_snapshot| (captured_cut, raw_snapshot))
            }
            (Err(error), _) | (Ok(_), Err(error)) => Err(error),
        };
        (snapshot_guard, captured)
    })
    .await
    .map_err(|_| {
        storage_error(
            ErrorSubject::Snapshot(None),
            ErrorVerb::Write,
            io::Error::other("session consensus snapshot worker is unavailable"),
        )
    })?;
    let (captured_cut, raw_snapshot) = captured
        .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error))?;
    Ok((snapshot_guard, Some((captured_cut, raw_snapshot))))
}

impl RaftSnapshotBuilder<SessionRaftTypeConfig> for SqliteConsensusSnapshotBuilder {
    async fn build_snapshot(
        &mut self,
    ) -> Result<Snapshot<SessionRaftTypeConfig>, StorageError<SessionConsensusNodeId>> {
        let snapshot_guard = std::sync::Arc::clone(&self.core.snapshot_gate)
            .lock_owned()
            .await;
        let raw_path = self
            .core
            .snapshot_dir
            .join(format!("build-{}.sqlite", uuid::Uuid::new_v4()));
        let file_name = format!("snapshot-{}.opc", uuid::Uuid::new_v4());
        let final_path = self.core.snapshot_dir.join(&file_name);
        let temporary_path = self
            .core
            .snapshot_dir
            .join(format!("seal-{}.part", uuid::Uuid::new_v4()));
        let (_snapshot_guard, file_backed) =
            build_file_backed_snapshot_database(&self.core, &raw_path, snapshot_guard).await?;
        let (
            (last_log_id, last_membership),
            (mut snapshot, checksum, byte_length, raw_cleanup, mut published_cleanup),
        ) = if let Some((membership, raw_snapshot)) = file_backed {
            let sealed = seal_snapshot_database(raw_snapshot, &temporary_path, &final_path)
                .await
                .map_err(|error| {
                    storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
                })?;
            (membership, sealed)
        } else {
            let (membership, raw_snapshot) = {
                let conn = self.core.conn.lock().await;
                consensus::build_snapshot_database_pinned_with_authority_sync(
                    &conn,
                    self.core.storage_identity,
                    self.core.authority_profile,
                    &self.core.expected_members,
                    &self.core.expected_bindings,
                    self.core.fixed_placement_policy,
                    &raw_path,
                )
            }
            .map_err(|error| {
                storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
            })?;
            let sealed = seal_snapshot_database(raw_snapshot, &temporary_path, &final_path)
                .await
                .map_err(|error| {
                    storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
                })?;
            (membership, sealed)
        };
        // Promotion and guard rebinding form one cancellation-free local
        // filesystem step. If promotion fails the still-armed guard removes
        // only the exact temporary inode; once it succeeds the same guard owns
        // the exact final name until durable metadata publishes it.
        std::fs::rename(&temporary_path, &final_path).map_err(|error| {
            storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
        })?;
        published_cleanup.rebind_path(final_path.clone());
        sync_directory(&self.core.snapshot_dir).map_err(|error| {
            storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, error)
        })?;
        let (_, observed_checksum, observed_length) =
            verify_snapshot_envelope_reader(&mut snapshot)
                .await
                .map_err(|error| {
                    storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, error)
                })?;
        if observed_checksum != checksum || observed_length != byte_length {
            return Err(storage_error(
                ErrorSubject::Snapshot(None),
                ErrorVerb::Read,
                consensus::invalid_data("session consensus sealed snapshot is inconsistent"),
            ));
        }
        snapshot
            .rewind()
            .await
            .map_err(|error| storage_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, error))?;
        let snapshot_id = format!("session-{}", uuid::Uuid::new_v4());
        let meta = SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id,
        };
        let published_pin =
            if self.core.authority_profile == ConsensusAuthorityProfile::FixedImmutable {
                Some(
                    snapshot_handle_pin(&snapshot, &final_path)
                        .await
                        .map_err(|error| {
                            storage_error(
                                ErrorSubject::Snapshot(Some(meta.signature())),
                                ErrorVerb::Read,
                                error,
                            )
                        })?,
                )
            } else {
                None
            };
        let previous = {
            let conn = self.core.conn.lock().await;
            let previous = consensus::read_current_snapshot_sync(&conn, self.core.storage_identity)
                .map_err(|error| {
                    storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        error,
                    )
                })?;
            if let Some(published_pin) = &published_pin {
                if !published_pin
                    .path_matches_identity(&final_path)
                    .map_err(|error| {
                        storage_error(
                            ErrorSubject::Snapshot(Some(meta.signature())),
                            ErrorVerb::Read,
                            error,
                        )
                    })?
                {
                    return Err(storage_error(
                        ErrorSubject::Snapshot(Some(meta.signature())),
                        ErrorVerb::Read,
                        consensus::invalid_data(
                            "session consensus published snapshot was replaced",
                        ),
                    ));
                }
            }
            publish_snapshot_metadata_with_readback(
                &conn,
                self.core.storage_identity,
                &meta,
                &file_name,
                checksum,
                byte_length,
                &mut published_cleanup,
                || {
                    consensus::save_current_snapshot_with_authority_sync(
                        &conn,
                        self.core.storage_identity,
                        self.core.authority_profile,
                        &self.core.expected_members,
                        &self.core.expected_bindings,
                        self.core.fixed_placement_policy,
                        &meta,
                        &file_name,
                        checksum,
                        byte_length,
                    )
                },
            )
            .map_err(|error| {
                storage_error(
                    ErrorSubject::Snapshot(Some(meta.signature())),
                    ErrorVerb::Write,
                    error,
                )
            })?;
            previous
        };
        // The raw SQLite artifact is no longer needed once the sealed file is
        // durably named by snapshot metadata. The publication helper has
        // already disarmed the sealed-file cleanup without an await boundary.
        if let Some(raw_cleanup) = raw_cleanup {
            drop(raw_cleanup);
        }
        remove_old_snapshot(&self.core.snapshot_dir, previous, &file_name).await;
        Ok(Snapshot {
            meta,
            snapshot: Box::new(snapshot),
        })
    }
}

async fn notify_watchers(core: &SqliteConsensusCore, notifications: &[ReplicationEntry]) {
    if notifications.is_empty() {
        return;
    }
    let mut watchers = core.watchers.lock().await;
    for notification in notifications {
        watchers.retain_mut(|watcher| watcher.notify(notification));
    }
    drop(watchers);

    let mut consumer_watchers = core.consumer_watchers.lock().await;
    for notification in notifications {
        let projected = crate::consumer::session_consumer_change(notification);
        let Ok(projected) = projected else {
            // Invalid replay shape cannot be safely projected. Closing the
            // affected consumers forces coherent catch-up instead of exposing
            // raw state or retaining it in an unbounded queue.
            consumer_watchers.clear();
            return;
        };
        let Ok(encoded_bytes) = crate::consumer::session_consumer_change_encoded_bytes(&projected)
        else {
            consumer_watchers.clear();
            return;
        };
        consumer_watchers.retain_mut(|watcher| watcher.notify(&projected, encoded_bytes));
    }
}

fn secure_snapshot_create_options(read: bool) -> tokio::fs::OpenOptions {
    let mut options = tokio::fs::OpenOptions::new();
    options.create_new(true).read(read).write(true);
    #[cfg(unix)]
    {
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
}

fn create_unpublished_snapshot_output(
    path: &Path,
    read: bool,
) -> io::Result<(tokio::fs::File, UnpublishedSnapshotArtifact)> {
    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).read(read).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let output = options.open(path)?;
    let cleanup = UnpublishedSnapshotArtifact::from_file(&output, path.to_path_buf(), false)?;
    Ok((tokio::fs::File::from_std(output), cleanup))
}

async fn snapshot_handle_pin(
    snapshot: &SessionSnapshotFile,
    path: &Path,
) -> io::Result<PinnedSqliteFile> {
    let cloned = snapshot.try_clone().await?;
    PinnedSqliteFile::from_file(cloned.into_std().await, path.to_path_buf())
}

async fn seal_snapshot_database(
    raw_snapshot: PinnedSqliteFile,
    output_path: &Path,
    final_path: &Path,
) -> io::Result<(
    SessionSnapshotFile,
    [u8; 32],
    u64,
    Option<UnpublishedSnapshotArtifact>,
    UnpublishedSnapshotArtifact,
)> {
    raw_snapshot.verify_identity()?;
    let payload_length = raw_snapshot.file().metadata()?.len();
    if payload_length == 0 || payload_length > SNAPSHOT_MAX_BYTES {
        return Err(consensus::invalid_data(
            "session consensus snapshot size is invalid",
        ));
    }
    let (raw_file, raw_cleanup) = raw_snapshot.into_file_with_cleanup();
    let mut source = tokio::fs::File::from_std(raw_file);
    // Creation and cleanup arming contain no await point. Dropping this future
    // at any later write/flush/sync boundary therefore removes the exact
    // unpublished inode.
    let (mut output, output_cleanup) = create_unpublished_snapshot_output(output_path, true)?;
    let mut hasher = Sha256::new();
    let mut copied = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        copied = copied
            .checked_add(u64::try_from(read).map_err(|_| {
                consensus::invalid_data("session consensus snapshot length overflow")
            })?)
            .ok_or_else(|| consensus::invalid_data("session consensus snapshot length overflow"))?;
        if copied > SNAPSHOT_MAX_BYTES {
            return Err(consensus::invalid_data(
                "session consensus snapshot exceeds size limit",
            ));
        }
        hasher.update(&buffer[..read]);
        output.write_all(&buffer[..read]).await?;
    }
    if copied != payload_length {
        return Err(consensus::invalid_data(
            "session consensus snapshot changed while sealing",
        ));
    }
    let checksum: [u8; 32] = hasher.finalize().into();
    output.write_all(SNAPSHOT_FOOTER_MAGIC).await?;
    output.write_all(&payload_length.to_be_bytes()).await?;
    output.write_all(&checksum).await?;
    output.flush().await?;
    output.sync_all().await?;
    // `output` is the same descriptor that will survive the caller's atomic
    // promotion from `output_path` to `final_path`; the diagnostic path is
    // therefore deliberately the eventual published name, never reopened.
    let snapshot = SessionSnapshotFile::from_file(output, final_path.to_path_buf()).await?;
    let total = payload_length
        .checked_add(SNAPSHOT_FOOTER_BYTES)
        .ok_or_else(|| consensus::invalid_data("session consensus snapshot length overflow"))?;
    Ok((snapshot, checksum, total, raw_cleanup, output_cleanup))
}

async fn verify_snapshot_envelope_reader<R>(file: &mut R) -> io::Result<(u64, [u8; 32], u64)>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin,
{
    let total_length = file.seek(io::SeekFrom::End(0)).await?;
    if total_length <= SNAPSHOT_FOOTER_BYTES
        || total_length > SNAPSHOT_MAX_BYTES.saturating_add(SNAPSHOT_FOOTER_BYTES)
    {
        return Err(consensus::invalid_data(
            "session consensus snapshot size is invalid",
        ));
    }
    file.seek(io::SeekFrom::End(
        -i64::try_from(SNAPSHOT_FOOTER_BYTES).map_err(|_| {
            consensus::invalid_data("session consensus snapshot footer size is invalid")
        })?,
    ))
    .await?;
    let mut magic = [0_u8; 8];
    let mut encoded_length = [0_u8; 8];
    let mut expected_checksum = [0_u8; 32];
    file.read_exact(&mut magic).await?;
    file.read_exact(&mut encoded_length).await?;
    file.read_exact(&mut expected_checksum).await?;
    if &magic != SNAPSHOT_FOOTER_MAGIC {
        return Err(consensus::invalid_data(
            "session consensus snapshot magic is invalid",
        ));
    }
    let payload_length = u64::from_be_bytes(encoded_length);
    if payload_length == 0
        || payload_length > SNAPSHOT_MAX_BYTES
        || payload_length.checked_add(SNAPSHOT_FOOTER_BYTES) != Some(total_length)
    {
        return Err(consensus::invalid_data(
            "session consensus snapshot length is invalid",
        ));
    }
    file.seek(io::SeekFrom::Start(0)).await?;
    let mut limited = file.take(payload_length);
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = limited.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        observed = observed
            .checked_add(u64::try_from(read).map_err(|_| {
                consensus::invalid_data("session consensus snapshot length overflow")
            })?)
            .ok_or_else(|| consensus::invalid_data("session consensus snapshot length overflow"))?;
        hasher.update(&buffer[..read]);
    }
    let actual_checksum: [u8; 32] = hasher.finalize().into();
    if observed != payload_length || actual_checksum != expected_checksum {
        return Err(consensus::invalid_data(
            "session consensus snapshot checksum mismatch",
        ));
    }
    Ok((payload_length, actual_checksum, total_length))
}

async fn extract_snapshot_database_from_reader<R>(
    source: &mut R,
    destination: &Path,
    length: u64,
) -> io::Result<PinnedSqliteFile>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin,
{
    source.seek(io::SeekFrom::Start(0)).await?;
    let mut source = source.take(length);
    let destination_path = destination.to_path_buf();
    let mut destination = secure_snapshot_create_options(false)
        .open(destination)
        .await?;
    let copied = tokio::io::copy(&mut source, &mut destination).await?;
    if copied != length {
        return Err(consensus::invalid_data(
            "session consensus snapshot extraction was incomplete",
        ));
    }
    destination.flush().await?;
    destination.sync_all().await?;
    PinnedSqliteFile::from_file(destination.into_std().await, destination_path)
}

async fn copy_and_promote_from_reader<R>(
    source: &mut R,
    temporary: &Path,
    final_path: &Path,
    expected_length: u64,
) -> io::Result<()>
where
    R: tokio::io::AsyncRead + tokio::io::AsyncSeek + Unpin,
{
    source.seek(io::SeekFrom::Start(0)).await?;
    let mut output = secure_snapshot_create_options(false)
        .open(temporary)
        .await?;
    let copied = tokio::io::copy(source, &mut output).await?;
    if copied != expected_length {
        return Err(consensus::invalid_data(
            "session consensus promoted snapshot length changed",
        ));
    }
    output.flush().await?;
    output.sync_all().await?;
    drop(output);
    tokio::fs::rename(temporary, final_path).await?;
    let parent = final_path
        .parent()
        .ok_or_else(|| consensus::invalid_data("session consensus snapshot has no parent"))?;
    sync_directory(parent)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

async fn remove_old_snapshot(
    snapshot_dir: &Path,
    previous: Option<consensus::CurrentSnapshot>,
    current_file_name: &str,
) {
    if let Some((_, file_name, _, _)) = previous {
        if file_name != current_file_name {
            let _ = tokio::fs::remove_file(snapshot_dir.join(file_name)).await;
        }
    }
}

/// Publish one already-durable snapshot file without deleting it after an
/// ambiguous SQLite commit result.
///
/// SQLite may durably commit a transaction and then report an I/O/finalization
/// error. The same locked connection therefore reads the singleton back before
/// an armed error-path guard is allowed to unlink the candidate. An exact
/// candidate or an unavailable readback is preserved; only a conclusive
/// different/absent row leaves cleanup armed.
#[allow(clippy::too_many_arguments)]
fn publish_snapshot_metadata_with_readback<F>(
    conn: &rusqlite::Connection,
    identity: SessionConsensusIdentity,
    meta: &SnapshotMeta<SessionConsensusNodeId, opc_consensus::engine::EmptyNode>,
    file_name: &str,
    checksum: [u8; 32],
    byte_length: u64,
    cleanup: &mut UnpublishedSnapshotArtifact,
    publish: F,
) -> io::Result<()>
where
    F: FnOnce() -> io::Result<()>,
{
    match publish() {
        Ok(()) => {
            cleanup.disarm();
            Ok(())
        }
        Err(error) => {
            let preserve = match consensus::read_current_snapshot_sync(conn, identity) {
                Ok(Some((
                    observed_meta,
                    observed_file_name,
                    observed_checksum,
                    observed_length,
                ))) => {
                    observed_meta == *meta
                        && observed_file_name == file_name
                        && observed_checksum == checksum
                        && observed_length == byte_length
                }
                Ok(None) => false,
                Err(_) => true,
            };
            if preserve {
                cleanup.disarm();
            }
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::time::Duration;

    use bytes::Bytes;
    use opc_consensus::engine::storage::{RaftLogStorage, RaftStateMachine};
    use opc_consensus::engine::{CommittedLeaderId, EntryPayload, RaftSnapshotBuilder};
    use opc_crypto::CryptoEnvelopeV1;
    use opc_key::{
        serialize_bound_aad, AeadAlgorithm, EnvelopeAad, KeyId, SessionAad, AEAD_TAG_LEN,
        AES_256_GCM_SIV_NONCE_LEN,
    };
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};

    use super::*;
    use crate::backend::CompareAndSet;
    use crate::consensus::{
        SessionConsensusClusterId, SessionConsensusCommand, SessionConsensusConfigurationEpoch,
        SessionConsensusConfigurationId, SessionConsensusEntryDigest, SessionConsensusRequestId,
        SessionMutationIntent, SessionMutationOutcome, SESSION_CONSENSUS_SCHEMA_VERSION,
    };
    use crate::lease::SessionLeaseManager;
    use crate::model::{Generation, OwnerId, SessionKey, SessionKeyType, StateClass, StateType};
    use crate::record::{EncryptedSessionPayload, StoredSessionRecord};

    const PLAINTEXT_CANARY: &[u8] = b"never-persist-this-plaintext-canary";

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn publication_identity_check_rejects_atomic_aba_replacement() {
        let directory = tempfile::tempdir().expect("snapshot directory");
        let published = directory.path().join("snapshot.opc");
        tokio::fs::write(&published, b"verified envelope A")
            .await
            .expect("write first envelope");
        let snapshot = SessionSnapshotFile::open(published.clone())
            .await
            .expect("open first envelope");
        let pinned = snapshot_handle_pin(&snapshot, &published)
            .await
            .expect("pin first envelope");

        let replacement = directory.path().join("replacement.opc");
        tokio::fs::write(&replacement, b"different valid envelope B")
            .await
            .expect("write replacement envelope");
        tokio::fs::rename(&replacement, &published)
            .await
            .expect("replace published name");

        assert!(
            !pinned
                .path_matches_identity(&published)
                .expect("compare published inode"),
            "a verified handle must not authorize a replacement published name"
        );
    }

    #[tokio::test]
    async fn publication_error_after_durable_metadata_never_unlinks_current_snapshot() {
        let directory = tempfile::tempdir().expect("snapshot publication directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("snapshot publication backend");
        let (_, mut state_machine) = open(
            &backend,
            directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("snapshot publication storage");
        state_machine
            .apply([initial_membership_entry()])
            .await
            .expect("snapshot publication membership");
        let (last_log_id, last_membership) = state_machine
            .applied_state()
            .await
            .expect("snapshot publication applied state");
        let meta = SnapshotMeta {
            last_log_id,
            last_membership,
            snapshot_id: "publication-error-after-commit".to_owned(),
        };
        let file_name = "snapshot-publication-error.opc";
        let candidate_path = directory.path().join("snapshots").join(file_name);
        std::fs::write(&candidate_path, b"durable sealed snapshot fixture")
            .expect("write snapshot publication candidate");
        let candidate =
            std::fs::File::open(&candidate_path).expect("open snapshot publication candidate");
        let mut cleanup =
            UnpublishedSnapshotArtifact::from_file(&candidate, candidate_path.clone(), false)
                .expect("arm snapshot publication cleanup");
        let checksum = [0x5a; 32];
        let byte_length = candidate.metadata().expect("candidate metadata").len();

        let conn = state_machine.core.conn.lock().await;
        let publication = publish_snapshot_metadata_with_readback(
            &conn,
            state_machine.core.storage_identity,
            &meta,
            file_name,
            checksum,
            byte_length,
            &mut cleanup,
            || {
                consensus::save_current_snapshot_sync(
                    &conn,
                    state_machine.core.storage_identity,
                    &meta,
                    file_name,
                    checksum,
                    byte_length,
                )?;
                Err(io::Error::other(
                    "injected snapshot publication error after durable metadata",
                ))
            },
        );
        assert!(
            publication.is_err(),
            "the injected finalization error remains visible"
        );
        let observed =
            consensus::read_current_snapshot_sync(&conn, state_machine.core.storage_identity)
                .expect("read committed snapshot metadata")
                .expect("snapshot metadata was durably committed");
        assert_eq!(meta, observed.0);
        assert_eq!(file_name, observed.1);
        assert_eq!(checksum, observed.2);
        assert_eq!(byte_length, observed.3);
        drop(conn);

        drop(cleanup);
        assert!(
            candidate_path.is_file(),
            "an error-path guard must preserve the exact durably published snapshot"
        );
    }

    #[tokio::test]
    async fn receiving_snapshot_rejects_sparse_or_oversized_offsets_and_cleans_abandoned_artifacts()
    {
        let directory = tempfile::tempdir().expect("receiving snapshot directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("receiving snapshot backend");
        let (_, mut state_machine) = open(
            &backend,
            directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("receiving snapshot storage");

        for _ in 0..2 {
            let receiving = state_machine
                .begin_receiving_snapshot()
                .await
                .expect("fresh receiving snapshot");
            let path = receiving.path().to_path_buf();
            assert!(path.is_file(), "fresh receive artifact exists while owned");
            drop(receiving);
            assert!(
                !path.exists(),
                "a later fresh snapshot must not retain an abandoned receive artifact"
            );
        }

        let mut receiving = state_machine
            .begin_receiving_snapshot()
            .await
            .expect("bounded receiving snapshot");
        let path = receiving.path().to_path_buf();
        assert!(
            receiving
                .seek(io::SeekFrom::Start(
                    SNAPSHOT_MAX_BYTES + SNAPSHOT_FOOTER_BYTES + 1
                ))
                .await
                .is_err(),
            "a receive cursor beyond the snapshot envelope must fail before writing"
        );
        assert_eq!(
            0,
            receiving.metadata().await.expect("receive metadata").len(),
            "an oversized receive cursor must not grow the artifact"
        );
        receiving
            .seek(io::SeekFrom::Start(1))
            .await
            .expect("position sparse receive cursor");
        assert!(
            receiving.write_all(b"x").await.is_err(),
            "a sparse receive write must fail closed"
        );
        assert_eq!(
            0,
            receiving.metadata().await.expect("receive metadata").len(),
            "a rejected sparse write must not grow the artifact"
        );
        drop(receiving);
        assert!(
            !path.exists(),
            "bounded receive artifact is cleaned on drop"
        );
    }

    #[tokio::test]
    async fn snapshot_install_detach_error_preserves_durably_current_candidate() {
        use rusqlite::hooks::{AuthAction, AuthContext, Authorization};

        let source_directory = tempfile::tempdir().expect("snapshot source directory");
        let source_backend =
            SqliteSessionBackend::open(source_directory.path().join("sessions.sqlite"))
                .expect("snapshot source backend");
        let (_, mut source) = open(
            &source_backend,
            source_directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("snapshot source storage");
        source
            .apply([initial_membership_entry()])
            .await
            .expect("snapshot source membership");
        let mut builder = source.get_snapshot_builder().await;
        let mut built = builder
            .build_snapshot()
            .await
            .expect("build source snapshot");

        let target_directory = tempfile::tempdir().expect("snapshot target directory");
        let target_backend =
            SqliteSessionBackend::open(target_directory.path().join("sessions.sqlite"))
                .expect("snapshot target backend");
        let (_, mut target) = open(
            &target_backend,
            target_directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("snapshot target storage");
        let mut receiving = target
            .begin_receiving_snapshot()
            .await
            .expect("target receive snapshot");
        built
            .snapshot
            .rewind()
            .await
            .expect("rewind source snapshot");
        tokio::io::copy(&mut built.snapshot, &mut receiving)
            .await
            .expect("copy source snapshot");

        {
            let conn = target.core.conn.lock().await;
            conn.authorizer(Some(|context: AuthContext<'_>| {
                if matches!(context.action, AuthAction::Detach { .. }) {
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }));
        }
        assert!(
            target
                .install_snapshot(&built.meta, receiving)
                .await
                .is_err(),
            "the injected post-commit DETACH denial remains observable"
        );
        {
            let conn = target.core.conn.lock().await;
            conn.authorizer(Some(|_: AuthContext<'_>| Authorization::Allow));
            let (_, file_name, _, _) =
                consensus::read_current_snapshot_sync(&conn, target.core.storage_identity)
                    .expect("read durably installed snapshot metadata")
                    .expect("post-commit installation remains current");
            assert!(
                target_directory
                    .path()
                    .join("snapshots")
                    .join(file_name)
                    .is_file(),
                "a current snapshot candidate survives a post-commit DETACH error"
            );
        }
        drop(target);
        let (_, mut restarted) = open(
            &target_backend,
            target_directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("restart preserves the current installed snapshot");
        assert!(
            restarted
                .get_current_snapshot()
                .await
                .expect("read current snapshot after restart")
                .is_some(),
            "restart reads the candidate that durable metadata references"
        );
    }

    #[tokio::test]
    async fn cancelled_seal_output_removes_its_exact_unpublished_inode() {
        let directory = tempfile::tempdir().expect("snapshot seal cancellation directory");
        let output_path = directory.path().join("seal-cancelled.part");
        let task_path = output_path.clone();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let (output, cleanup) = create_unpublished_snapshot_output(&task_path, true)
                .expect("create guarded seal output");
            started_tx.send(()).expect("signal guarded output");
            std::future::pending::<()>().await;
            drop((output, cleanup));
        });

        started_rx.await.expect("guarded output is armed");
        assert!(output_path.exists());
        task.abort();
        assert!(task
            .await
            .expect_err("seal output task is cancelled")
            .is_cancelled());
        assert!(!output_path.exists());
    }

    fn identity(configuration_byte: u8) -> SessionConsensusIdentity {
        SessionConsensusIdentity::new(
            SessionConsensusClusterId::new("storage-tests").expect("cluster identity"),
            SessionConsensusConfigurationId::from_bytes([configuration_byte; 32]),
            SessionConsensusConfigurationEpoch::new(1).expect("configuration epoch"),
        )
    }

    fn node_id() -> SessionConsensusNodeId {
        SessionConsensusNodeId::new(7).expect("node ID")
    }

    fn expected_members() -> BTreeSet<SessionConsensusNodeId> {
        BTreeSet::from([node_id()])
    }

    fn fixed_raw_read_members() -> BTreeSet<SessionConsensusNodeId> {
        BTreeSet::from([
            SessionConsensusNodeId::new(7).expect("fixed node ID"),
            SessionConsensusNodeId::new(8).expect("fixed node ID"),
            SessionConsensusNodeId::new(9).expect("fixed node ID"),
        ])
    }

    fn fixed_raw_read_bindings(
        members: &BTreeSet<SessionConsensusNodeId>,
    ) -> BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding> {
        members
            .iter()
            .copied()
            .map(|node| {
                let mut descriptor = [0x11; 32];
                descriptor[..8].copy_from_slice(&node.get().to_be_bytes());
                let mut endpoint = [0x22; 32];
                endpoint[..8].copy_from_slice(&node.get().to_be_bytes());
                let mut tls = [0x33; 32];
                tls[..8].copy_from_slice(&node.get().to_be_bytes());
                let mut backing = [0x44; 32];
                backing[..8].copy_from_slice(&node.get().to_be_bytes());
                (
                    node,
                    SessionTopologyMemberBinding::new(descriptor, endpoint, tls, backing),
                )
            })
            .collect()
    }

    async fn open_fixed_raw_read_store(
        directory: &tempfile::TempDir,
    ) -> (
        SqliteConsensusLogStore,
        SqliteConsensusStateMachine,
        PathBuf,
    ) {
        let database = directory.path().join("fixed-raw-read.sqlite");
        let backend = SqliteSessionBackend::open(&database).expect("fixed raw-read backend");
        let members = fixed_raw_read_members();
        let core = SqliteConsensusCore::initialize(
            &backend,
            directory.path().join("fixed-raw-read-snapshots"),
            identity(1),
            members.clone(),
            fixed_raw_read_bindings(&members),
            ConsensusAuthorityProfile::FixedImmutable,
            Some(PlacementResiliencePolicy::AllowReducedResilience),
        )
        .await
        .expect("open exact fixed raw-read store");
        (
            SqliteConsensusLogStore { core: core.clone() },
            SqliteConsensusStateMachine {
                core,
                membership_admission: None,
            },
            database,
        )
    }

    async fn assert_fixed_raw_reads_fail_closed(
        log_store: &mut SqliteConsensusLogStore,
        state_machine: &mut SqliteConsensusStateMachine,
    ) {
        assert!(log_store.try_get_log_entries(0..0).await.is_err());
        assert!(log_store.limited_get_log_entries(0, 0).await.is_err());
        assert!(log_store.get_log_state().await.is_err());
        assert!(log_store.read_vote().await.is_err());
        assert!(log_store.read_committed().await.is_err());
        assert!(state_machine.applied_state().await.is_err());
        assert!(state_machine.get_current_snapshot().await.is_err());
    }

    fn log_id(index: u64) -> LogId<SessionConsensusNodeId> {
        log_id_with_term(1, index)
    }

    fn log_id_with_term(term: u64, index: u64) -> LogId<SessionConsensusNodeId> {
        LogId::new(CommittedLeaderId::new(term, node_id()), index)
    }

    fn timestamp(second: u8) -> Timestamp {
        Timestamp::from_str(&format!("2026-07-12T00:00:{second:02}Z")).expect("timestamp")
    }

    fn key() -> SessionKey {
        SessionKey {
            tenant: TenantId::from_static("storage-test"),
            nf_kind: NetworkFunctionKind::from_static("smf"),
            key_type: SessionKeyType::PduSession,
            stable_id: Bytes::from_static(b"opaque-stable-id")
                .try_into()
                .expect("valid stable ID"),
        }
    }

    fn test_envelope(record: &StoredSessionRecord, opaque: &[u8]) -> Vec<u8> {
        let key_id = KeyId::new("storage-test-key").expect("key ID");
        let aad = EnvelopeAad::session(
            record.key.tenant.clone(),
            1,
            SessionAad::new(
                record.key.nf_kind.as_str(),
                "opaque-test-keyed-session-digest",
                record.state_type.as_str(),
                record.generation.get(),
                record.fence.get(),
                "storage-test-backend",
            )
            .expect("session AAD"),
        );
        let mut ciphertext_and_tag = opaque.to_vec();
        ciphertext_and_tag.extend_from_slice(&[0xA5; AEAD_TAG_LEN]);
        CryptoEnvelopeV1 {
            algorithm: AeadAlgorithm::Aes256GcmSiv,
            key_id: key_id.clone(),
            nonce: vec![0x42; AES_256_GCM_SIV_NONCE_LEN],
            aad: serialize_bound_aad(&aad, &key_id).expect("bound AAD"),
            ciphertext_and_tag,
        }
        .encode()
        .expect("test envelope")
    }

    fn acquire_command(
        identity: SessionConsensusIdentity,
        request_id: SessionConsensusRequestId,
    ) -> SessionConsensusCommand {
        SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity,
            request_id,
            logical_time: timestamp(1),
            intent: SessionMutationIntent::AcquireLease {
                key: key(),
                owner: OwnerId::new("replica-a").expect("owner"),
                ttl: Duration::from_secs(300),
            },
        }
    }

    fn normal_entry(index: u64, command: SessionConsensusCommand) -> Entry<SessionRaftTypeConfig> {
        normal_entry_with_term(1, index, command)
    }

    fn normal_entry_with_term(
        term: u64,
        index: u64,
        command: SessionConsensusCommand,
    ) -> Entry<SessionRaftTypeConfig> {
        Entry {
            log_id: log_id_with_term(term, index),
            payload: EntryPayload::Normal(command),
        }
    }

    fn sealed_cas_entry(
        index: u64,
        request_byte: u8,
        payload_bytes: usize,
    ) -> Entry<SessionRaftTypeConfig> {
        let key = key();
        let owner = OwnerId::new("replica-a").expect("owner");
        let fence = crate::model::FenceToken::new(1);
        let lease = crate::lease::LeaseGuard::new(
            key.clone(),
            owner.clone(),
            fence,
            timestamp(1),
            timestamp(59),
            1,
        );
        let mut record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(index),
            owner,
            fence,
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("bounded-log-read").expect("state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([]),
        };
        let envelope_overhead = test_envelope(&record, &[]).len();
        let opaque_bytes = payload_bytes
            .checked_sub(envelope_overhead)
            .expect("payload length exceeds envelope overhead");
        let sealed = test_envelope(&record, &vec![request_byte; opaque_bytes]);
        assert_eq!(sealed.len(), payload_bytes);
        record.payload =
            EncryptedSessionPayload::try_envelope(sealed).expect("structurally valid envelope");
        normal_entry(
            index,
            SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity: identity(1),
                request_id: SessionConsensusRequestId::from_bytes([request_byte; 16]),
                logical_time: timestamp(request_byte),
                intent: SessionMutationIntent::CompareAndSet(Box::new(CompareAndSet {
                    key,
                    lease,
                    expected_generation: None,
                    new_record: record,
                })),
            },
        )
    }

    fn advance_time_command(
        identity: SessionConsensusIdentity,
        request_byte: u8,
        second: u8,
    ) -> SessionConsensusCommand {
        SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity,
            request_id: SessionConsensusRequestId::from_bytes([request_byte; 16]),
            logical_time: timestamp(second),
            intent: SessionMutationIntent::AdvanceLogicalTime,
        }
    }

    fn initial_membership_entry() -> Entry<SessionRaftTypeConfig> {
        Entry {
            log_id: log_id(0),
            payload: EntryPayload::Membership(opc_consensus::engine::Membership::new(
                vec![expected_members()],
                expected_members(),
            )),
        }
    }

    #[tokio::test]
    async fn limited_log_reads_are_nonempty_gap_free_and_byte_bounded() {
        let temp = tempfile::tempdir().expect("tempdir");
        let backend =
            SqliteSessionBackend::open(temp.path().join("sessions.sqlite")).expect("backend");
        let (mut log_store, _) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("consensus storage");
        let entries = [
            initial_membership_entry(),
            sealed_cas_entry(1, 11, 600 * 1024),
            sealed_cas_entry(2, 12, 600 * 1024),
            sealed_cas_entry(3, 13, crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES),
        ];
        {
            let conn = log_store.core.conn.lock().await;
            consensus::append_logs_sync(&conn, identity(1), &entries)
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

    #[tokio::test]
    async fn fixed_raw_reads_reject_persisted_profile_policy_and_scope_drift() {
        for drift in [
            "UPDATE consensus_identity SET authority_profile = 1 WHERE singleton = 1",
            "UPDATE consensus_identity SET fixed_placement_policy = 1 WHERE singleton = 1",
            "UPDATE consensus_membership_scope SET application_authority_epoch = application_authority_epoch + 1 WHERE singleton = 1",
        ] {
            let directory = tempfile::tempdir().expect("fixed raw-read directory");
            let (mut log_store, mut state_machine, database) =
                open_fixed_raw_read_store(&directory).await;
            let connection = rusqlite::Connection::open(database).expect("open fixed raw-read db");
            connection
                .execute(drift, [])
                .expect("persist fixed raw-read drift");
            drop(connection);

            assert_fixed_raw_reads_fail_closed(&mut log_store, &mut state_machine).await;
        }
    }

    #[tokio::test]
    async fn dynamic_raw_reads_do_not_require_fixed_authority() {
        let directory = tempfile::tempdir().expect("dynamic raw-read directory");
        let backend = SqliteSessionBackend::open(directory.path().join("dynamic-raw-read.sqlite"))
            .expect("dynamic raw-read backend");
        let (mut log_store, mut state_machine) = open(
            &backend,
            directory.path().join("dynamic-raw-read-snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("open dynamic raw-read store");

        assert!(log_store.try_get_log_entries(0..0).await.is_ok());
        assert!(log_store.limited_get_log_entries(0, 0).await.is_ok());
        assert!(log_store.get_log_state().await.is_ok());
        assert!(log_store.read_vote().await.is_ok());
        assert!(log_store.read_committed().await.is_ok());
        assert!(state_machine.applied_state().await.is_ok());
        assert!(state_machine.get_current_snapshot().await.is_ok());
    }

    #[tokio::test]
    async fn empty_migration_is_idempotent_and_identity_bound() {
        let temp = tempfile::tempdir().expect("tempdir");
        let database = temp.path().join("sessions.sqlite");
        let snapshots = temp.path().join("snapshots");
        let backend = SqliteSessionBackend::open(&database).expect("backend");

        let _ = open(&backend, &snapshots, identity(1), expected_members())
            .await
            .expect("first initialization");
        let cancelled_receive = snapshots.join("incoming-cancelled.part");
        let interrupted_build = snapshots.join("build-interrupted.sqlite");
        let interrupted_install_wal = snapshots.join("install-interrupted.sqlite-wal");
        let orphan_promoted = snapshots.join("snapshot-orphan.opc");
        tokio::fs::write(&cancelled_receive, b"partial authenticated stream")
            .await
            .expect("write cancelled receive artifact");
        tokio::fs::write(&interrupted_build, b"partial SQLite snapshot")
            .await
            .expect("write interrupted build artifact");
        tokio::fs::write(&interrupted_install_wal, b"partial SQLite WAL")
            .await
            .expect("write interrupted install WAL artifact");
        tokio::fs::write(&orphan_promoted, b"promoted before metadata commit")
            .await
            .expect("write orphan promoted artifact");
        let _ = open(&backend, &snapshots, identity(1), expected_members())
            .await
            .expect("idempotent initialization cleans interrupted staging");
        assert!(!cancelled_receive.exists());
        assert!(!interrupted_build.exists());
        assert!(!interrupted_install_wal.exists());
        assert!(!orphan_promoted.exists());
        let error = match open(&backend, &snapshots, identity(2), expected_members()).await {
            Ok(_) => panic!("different configuration must fail"),
            Err(error) => error,
        };
        assert_eq!(SessionConsensusStorageError::IdentityMismatch, error);
    }

    #[tokio::test]
    async fn nonempty_legacy_authority_requires_explicit_recovery() {
        let temp = tempfile::tempdir().expect("tempdir");
        let backend =
            SqliteSessionBackend::open(temp.path().join("sessions.sqlite")).expect("backend");
        backend
            .acquire(
                &key(),
                OwnerId::new("legacy-owner").expect("owner"),
                Duration::from_secs(60),
            )
            .await
            .expect("legacy lease");

        let error = match open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        {
            Ok(_) => panic!("legacy authority must not be silently adopted"),
            Err(error) => error,
        };
        assert_eq!(SessionConsensusStorageError::RecoveryRequired, error);
    }

    #[tokio::test(start_paused = true)]
    async fn covered_log_purge_wait_is_bounded_when_apply_never_arrives() {
        let temp = tempfile::tempdir().expect("tempdir");
        let backend =
            SqliteSessionBackend::open(temp.path().join("sessions.sqlite")).expect("backend");
        let (mut log_store, _) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("consensus storage");

        assert!(log_store.purge(log_id(1)).await.is_err());
        let conn = log_store.core.conn.lock().await;
        assert_eq!(
            None,
            consensus::read_purged_sync(&conn, identity(1)).expect("purged pointer")
        );
    }

    #[tokio::test]
    async fn covered_log_purge_waits_for_asynchronous_snapshot_apply() {
        let temp = tempfile::tempdir().expect("tempdir");
        let backend =
            SqliteSessionBackend::open(temp.path().join("sessions.sqlite")).expect("backend");
        let (mut log_store, mut state_machine) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("consensus storage");
        let membership = initial_membership_entry();
        let command = normal_entry(1, advance_time_command(identity(1), 16, 1));
        {
            let conn = state_machine.core.conn.lock().await;
            consensus::append_logs_sync(&conn, identity(1), &[membership.clone(), command.clone()])
                .expect("append snapshot-covered logs");
        }

        let purge = tokio::spawn(async move { log_store.purge(log_id(1)).await });
        tokio::task::yield_now().await;
        state_machine
            .apply([membership, command])
            .await
            .expect("asynchronous snapshot apply");
        purge
            .await
            .expect("purge task")
            .expect("purge succeeds after applied notification");

        let conn = state_machine.core.conn.lock().await;
        assert_eq!(
            Some(log_id(1)),
            consensus::read_purged_sync(&conn, identity(1)).expect("purged pointer")
        );
        assert_eq!(
            0_i64,
            conn.query_row("SELECT COUNT(*) FROM consensus_log", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("covered log count")
        );
    }

    #[tokio::test]
    async fn log_is_gap_free_and_rejects_unsealed_payloads_before_persistence() {
        let temp = tempfile::tempdir().expect("tempdir");
        let backend =
            SqliteSessionBackend::open(temp.path().join("sessions.sqlite")).expect("backend");
        let (store, _) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("consensus storage");
        let acquire = acquire_command(identity(1), SessionConsensusRequestId::from_bytes([1; 16]));
        {
            let conn = store.core.conn.lock().await;
            consensus::append_logs_sync(
                &conn,
                identity(1),
                &[initial_membership_entry(), normal_entry(1, acquire.clone())],
            )
            .expect("initial and first application logs");
            let gap = consensus::append_logs_sync(
                &conn,
                identity(1),
                &[normal_entry(3, acquire.clone())],
            );
            assert!(gap.is_err());

            let guard = crate::lease::LeaseGuard::new(
                key(),
                OwnerId::new("replica-a").expect("owner"),
                crate::model::FenceToken::new(1),
                timestamp(1),
                timestamp(59),
                1,
            );
            let unsealed = SessionConsensusCommand {
                request_id: SessionConsensusRequestId::from_bytes([2; 16]),
                logical_time: timestamp(2),
                intent: SessionMutationIntent::CompareAndSet(Box::new(CompareAndSet {
                    key: key(),
                    lease: guard.clone(),
                    expected_generation: None,
                    new_record: StoredSessionRecord {
                        key: key(),
                        generation: Generation::new(1),
                        owner: guard.owner().clone(),
                        fence: guard.fence(),
                        state_class: StateClass::AuthoritativeSession,
                        state_type: StateType::new("sealed-canary").expect("state type"),
                        expires_at: None,
                        payload: EncryptedSessionPayload::new(PLAINTEXT_CANARY),
                    },
                })),
                ..acquire
            };
            let rejected =
                consensus::append_logs_sync(&conn, identity(1), &[normal_entry(2, unsealed)]);
            assert!(rejected.is_err());
            assert_eq!(
                2_i64,
                conn.query_row("SELECT COUNT(*) FROM consensus_log", [], |row| row
                    .get::<_, i64>(0))
                    .expect("log count")
            );
        }
    }

    #[tokio::test]
    async fn committed_application_replays_outcome_and_persists_only_sealed_bytes() {
        let temp = tempfile::tempdir().expect("tempdir");
        let database = temp.path().join("sessions.sqlite");
        let backend = SqliteSessionBackend::open(&database).expect("backend");
        let (_, mut state_machine) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("consensus storage");
        let acquire = acquire_command(identity(1), SessionConsensusRequestId::from_bytes([3; 16]));
        state_machine
            .apply([initial_membership_entry()])
            .await
            .expect("apply initial entry");
        let response = state_machine
            .apply([normal_entry(1, acquire.clone())])
            .await
            .expect("apply acquire")
            .remove(0);
        let SessionMutationOutcome::Lease(guard) = response.result.expect("lease outcome") else {
            panic!("expected lease outcome");
        };
        let first_digest = acquire
            .calculate_applied_digest(1, SessionConsensusEntryDigest::GENESIS, timestamp(1))
            .expect("digest");
        assert_eq!(
            (1, first_digest, Some(timestamp(1))),
            state_machine
                .proposal_state()
                .await
                .expect("proposal state")
        );

        let opaque = b"opaque-envelope-with-key-id-preserved-byte-for-byte";
        let record_template = StoredSessionRecord {
            key: key(),
            generation: Generation::new(1),
            owner: guard.owner().clone(),
            fence: guard.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("sealed-canary").expect("state type"),
            expires_at: None,
            payload: EncryptedSessionPayload::new([]),
        };
        let sealed_bytes = test_envelope(&record_template, opaque);
        let cas = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(1),
            request_id: SessionConsensusRequestId::from_bytes([4; 16]),
            logical_time: timestamp(2),
            intent: SessionMutationIntent::CompareAndSet(Box::new(CompareAndSet {
                key: key(),
                lease: guard.clone(),
                expected_generation: None,
                new_record: StoredSessionRecord {
                    payload: EncryptedSessionPayload::try_envelope(&sealed_bytes)
                        .expect("valid envelope"),
                    ..record_template
                },
            })),
        };
        let first = state_machine
            .apply([normal_entry(2, cas.clone())])
            .await
            .expect("apply CAS")
            .remove(0);
        let replay_command = SessionConsensusCommand {
            logical_time: timestamp(3),
            ..cas
        };
        let replay = state_machine
            .apply([normal_entry(3, replay_command)])
            .await
            .expect("replay CAS after response loss and leader change")
            .remove(0);
        assert_eq!(first, replay);

        let stored = backend
            .consensus_get_at(&key(), timestamp(3))
            .await
            .expect("read")
            .expect("stored record");
        assert_eq!(sealed_bytes.as_slice(), stored.payload.as_bytes());
        let conn = state_machine.core.conn.lock().await;
        assert_eq!(
            2_i64,
            conn.query_row("SELECT COUNT(*) FROM session_replication_log", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("replication count")
        );
        for table_and_column in [
            ("consensus_request_outcomes", "response_json"),
            ("session_replication_log", "entry_json"),
        ] {
            let sql = format!(
                "SELECT CAST({1} AS BLOB) FROM {0}",
                table_and_column.0, table_and_column.1
            );
            let mut statement = conn.prepare(&sql).expect("statement");
            let rows = statement
                .query_map([], |row| row.get::<_, Vec<u8>>(0))
                .expect("rows");
            for row in rows {
                let bytes = row.expect("row");
                assert!(!bytes
                    .windows(PLAINTEXT_CANARY.len())
                    .any(|window| window == PLAINTEXT_CANARY));
            }
        }
    }

    #[tokio::test]
    async fn divergent_uncommitted_tails_are_replaceable_but_committed_prefix_is_immutable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let backend =
            SqliteSessionBackend::open(temp.path().join("sessions.sqlite")).expect("backend");
        let (_, mut state_machine) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("consensus storage");

        let membership = initial_membership_entry();
        let committed_command = advance_time_command(identity(1), 11, 1);
        let committed_digest = committed_command
            .calculate_applied_digest(1, SessionConsensusEntryDigest::GENESIS, timestamp(1))
            .expect("committed digest");
        let committed = normal_entry(1, committed_command);
        let first_tail = normal_entry(2, advance_time_command(identity(1), 12, 2));
        {
            let conn = state_machine.core.conn.lock().await;
            consensus::append_logs_sync(
                &conn,
                identity(1),
                &[membership.clone(), committed.clone(), first_tail],
            )
            .expect("append committed prefix and first uncommitted tail");
        }
        state_machine
            .apply([membership, committed.clone()])
            .await
            .expect("apply proven committed prefix");
        {
            let conn = state_machine.core.conn.lock().await;
            consensus::save_committed_sync(&conn, identity(1), Some(committed.log_id))
                .expect("persist committed proof");

            assert!(consensus::truncate_logs_sync(&conn, identity(1), &committed.log_id).is_err());
            assert_eq!(
                3_i64,
                conn.query_row("SELECT COUNT(*) FROM consensus_log", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("log count after rejected committed truncation")
            );

            consensus::truncate_logs_sync(&conn, identity(1), &log_id(2))
                .expect("truncate only the uncommitted tail");
            let second_tail =
                normal_entry_with_term(2, 2, advance_time_command(identity(1), 13, 3));
            consensus::append_logs_sync(&conn, identity(1), std::slice::from_ref(&second_tail))
                .expect("append second branch at the same index");

            consensus::truncate_logs_sync(&conn, identity(1), &second_tail.log_id)
                .expect("replace a second uncommitted branch");
            let third_tail = normal_entry_with_term(3, 2, advance_time_command(identity(1), 14, 4));
            consensus::append_logs_sync(&conn, identity(1), std::slice::from_ref(&third_tail))
                .expect("append authoritative replacement tail");

            assert_eq!(
                Some(committed.log_id),
                consensus::read_committed_sync(&conn, identity(1)).expect("committed pointer")
            );
            assert_eq!(
                Some(committed.log_id),
                consensus::read_applied_sync(&conn, identity(1)).expect("applied pointer")
            );
            let logs = consensus::read_log_range_sync(&conn, identity(1), 0, Some(3), None)
                .expect("read repaired log");
            assert_eq!(3, logs.len());
            assert_eq!(committed.log_id, logs[1].log_id);
            assert_eq!(third_tail.log_id, logs[2].log_id);
        }

        assert_eq!(
            (1, committed_digest, Some(timestamp(1))),
            state_machine
                .proposal_state()
                .await
                .expect("state-machine head")
        );
        drop(state_machine);

        let (_, reopened_state_machine) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("restart storage after divergent-tail replacement");
        assert_eq!(
            (1, committed_digest, Some(timestamp(1))),
            reopened_state_machine
                .proposal_state()
                .await
                .expect("restarted state-machine head")
        );
        let conn = reopened_state_machine.core.conn.lock().await;
        assert_eq!(
            Some(committed.log_id),
            consensus::read_committed_sync(&conn, identity(1)).expect("restarted commit proof")
        );
        let restarted_logs = consensus::read_log_range_sync(&conn, identity(1), 0, Some(3), None)
            .expect("restarted repaired log");
        assert_eq!(log_id_with_term(3, 2), restarted_logs[2].log_id);
    }

    #[tokio::test]
    async fn committed_apply_allocates_sequence_and_time_for_inflight_proposals() {
        let temp = tempfile::tempdir().expect("tempdir");
        let backend =
            SqliteSessionBackend::open(temp.path().join("sessions.sqlite")).expect("backend");
        let (_, mut state_machine) = open(
            &backend,
            temp.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("consensus storage");
        let mut first =
            acquire_command(identity(1), SessionConsensusRequestId::from_bytes([9; 16]));
        first.logical_time = timestamp(5);
        let second = SessionConsensusCommand {
            schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
            identity: identity(1),
            request_id: SessionConsensusRequestId::from_bytes([10; 16]),
            // Simulate a later proposal built before the first command applied
            // and after the proposing clock moved backwards.
            logical_time: timestamp(1),
            intent: SessionMutationIntent::AdvanceLogicalTime,
        };

        let responses = state_machine
            .apply([
                initial_membership_entry(),
                normal_entry(1, first.clone()),
                normal_entry(2, second.clone()),
            ])
            .await
            .expect("apply concurrently prepared commands");
        assert_eq!(responses[1].sequence, 1);
        assert_eq!(responses[1].logical_time, Some(timestamp(5)));
        assert_eq!(responses[2].sequence, 2);
        assert_eq!(responses[2].logical_time, Some(timestamp(5)));

        let first_digest = first
            .calculate_applied_digest(1, SessionConsensusEntryDigest::GENESIS, timestamp(5))
            .expect("first digest");
        let second_digest = second
            .calculate_applied_digest(2, first_digest, timestamp(5))
            .expect("second digest");
        assert_eq!(
            (2, second_digest, Some(timestamp(5))),
            state_machine.proposal_state().await.expect("applied state")
        );
    }

    #[tokio::test]
    async fn snapshot_is_file_backed_checksummed_and_installs_atomically() {
        let source_dir = tempfile::tempdir().expect("source tempdir");
        let source_backend =
            SqliteSessionBackend::open(source_dir.path().join("sessions.sqlite")).expect("backend");
        let (_, mut source_sm) = open(
            &source_backend,
            source_dir.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("source storage");
        let command = acquire_command(identity(1), SessionConsensusRequestId::from_bytes([5; 16]));
        source_sm
            .apply([initial_membership_entry()])
            .await
            .expect("apply initial entry");
        source_sm
            .apply([normal_entry(1, command)])
            .await
            .expect("apply");
        let mut builder = source_sm.get_snapshot_builder().await;
        let mut snapshot = builder.build_snapshot().await.expect("build snapshot");
        let snapshot_bytes = tokio::fs::read(snapshot.snapshot.path())
            .await
            .expect("snapshot bytes");
        assert!(!snapshot_bytes
            .windows(PLAINTEXT_CANARY.len())
            .any(|window| window == PLAINTEXT_CANARY));

        let target_dir = tempfile::tempdir().expect("target tempdir");
        let target_backend =
            SqliteSessionBackend::open(target_dir.path().join("sessions.sqlite")).expect("backend");
        let (_, mut target_sm) = open(
            &target_backend,
            target_dir.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("target storage");
        let mut receiving = target_sm
            .begin_receiving_snapshot()
            .await
            .expect("receiving file");
        snapshot
            .snapshot
            .seek(io::SeekFrom::Start(0))
            .await
            .expect("rewind snapshot");
        tokio::io::copy(&mut snapshot.snapshot, &mut receiving)
            .await
            .expect("stream snapshot");
        receiving.flush().await.expect("flush receiving");
        target_sm
            .install_snapshot(&snapshot.meta, receiving)
            .await
            .expect("install snapshot");
        assert_eq!(
            source_sm.proposal_state().await.expect("source state"),
            target_sm.proposal_state().await.expect("target state")
        );
        {
            let conn = target_sm.core.conn.lock().await;
            assert_eq!(
                1_i64,
                conn.query_row("SELECT MAX(fence) FROM key_fences", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("restored fence high-water mark")
            );
            assert_eq!(
                1_i64,
                conn.query_row("SELECT MAX(credential_id) FROM leases", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("restored credential high-water mark")
            );
        }
        let current = target_sm
            .get_current_snapshot()
            .await
            .expect("current snapshot")
            .expect("snapshot exists");
        assert_eq!(snapshot.meta, current.meta);

        let advanced = advance_time_command(identity(1), 15, 2);
        let advanced_digest = advanced
            .calculate_applied_digest(
                2,
                source_sm
                    .proposal_state()
                    .await
                    .expect("source proposal state")
                    .1,
                timestamp(2),
            )
            .expect("advanced digest");
        target_sm
            .apply([normal_entry(2, advanced)])
            .await
            .expect("advance target beyond snapshot");
        {
            let conn = target_sm.core.conn.lock().await;
            consensus::save_committed_sync(&conn, identity(1), Some(log_id(2)))
                .expect("persist newer committed floor");
        }
        let mut stale_receiving = target_sm
            .begin_receiving_snapshot()
            .await
            .expect("stale receiving file");
        snapshot
            .snapshot
            .seek(io::SeekFrom::Start(0))
            .await
            .expect("rewind stale snapshot");
        tokio::io::copy(&mut snapshot.snapshot, &mut stale_receiving)
            .await
            .expect("stream stale snapshot");
        stale_receiving.flush().await.expect("flush stale snapshot");
        assert!(target_sm
            .install_snapshot(&snapshot.meta, stale_receiving)
            .await
            .is_err());
        assert_eq!(
            (2, advanced_digest, Some(timestamp(2))),
            target_sm
                .proposal_state()
                .await
                .expect("newer target state survives stale snapshot")
        );

        let wrong_identity_dir = tempfile::tempdir().expect("wrong identity tempdir");
        let wrong_identity_backend =
            SqliteSessionBackend::open(wrong_identity_dir.path().join("sessions.sqlite"))
                .expect("wrong identity backend");
        let (_, mut wrong_identity_sm) = open(
            &wrong_identity_backend,
            wrong_identity_dir.path().join("snapshots"),
            identity(2),
            expected_members(),
        )
        .await
        .expect("wrong identity target storage");
        let mut wrong_identity_receiving = wrong_identity_sm
            .begin_receiving_snapshot()
            .await
            .expect("wrong identity receiving file");
        snapshot
            .snapshot
            .seek(io::SeekFrom::Start(0))
            .await
            .expect("rewind cross-identity snapshot");
        tokio::io::copy(&mut snapshot.snapshot, &mut wrong_identity_receiving)
            .await
            .expect("stream cross-identity snapshot");
        wrong_identity_receiving
            .flush()
            .await
            .expect("flush cross-identity snapshot");
        assert!(wrong_identity_sm
            .install_snapshot(&snapshot.meta, wrong_identity_receiving)
            .await
            .is_err());
        assert_eq!(
            (0, SessionConsensusEntryDigest::GENESIS, None),
            wrong_identity_sm
                .proposal_state()
                .await
                .expect("wrong-identity target remains pristine")
        );

        let corrupt_dir = tempfile::tempdir().expect("corrupt target tempdir");
        let corrupt_backend =
            SqliteSessionBackend::open(corrupt_dir.path().join("sessions.sqlite"))
                .expect("corrupt target backend");
        let (_, mut corrupt_target_sm) = open(
            &corrupt_backend,
            corrupt_dir.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("corrupt target storage");
        let mut corrupt_receiving = corrupt_target_sm
            .begin_receiving_snapshot()
            .await
            .expect("corrupt receiving file");
        let mut corrupted_snapshot = snapshot_bytes.clone();
        corrupted_snapshot[64] ^= 0xff;
        corrupt_receiving
            .write_all(&corrupted_snapshot)
            .await
            .expect("write corrupt snapshot");
        corrupt_receiving
            .flush()
            .await
            .expect("flush corrupt snapshot");
        assert!(corrupt_target_sm
            .install_snapshot(&snapshot.meta, corrupt_receiving)
            .await
            .is_err());
        assert_eq!(
            (0, SessionConsensusEntryDigest::GENESIS, None),
            corrupt_target_sm
                .proposal_state()
                .await
                .expect("corrupt target remains pristine")
        );

        let path = current.snapshot.path().to_path_buf();
        drop(current);
        let mut file = tokio::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .await
            .expect("open current snapshot");
        file.seek(io::SeekFrom::Start(64)).await.expect("seek");
        file.write_all(b"corrupt").await.expect("corrupt snapshot");
        file.sync_all().await.expect("sync corruption");
        assert!(target_sm.get_current_snapshot().await.is_err());
        drop(file);
        let reopen_error = match open(
            &target_backend,
            target_dir.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        {
            Ok(_) => panic!("restart must reject a corrupt current snapshot"),
            Err(error) => error,
        };
        assert_eq!(SessionConsensusStorageError::CorruptState, reopen_error);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_snapshot_build_retains_its_single_worker_ownership() {
        let directory = tempfile::tempdir().expect("snapshot cancellation directory");
        let backend = SqliteSessionBackend::open(directory.path().join("sessions.sqlite"))
            .expect("snapshot cancellation backend");
        let (_, mut state_machine) = open(
            &backend,
            directory.path().join("snapshots"),
            identity(1),
            expected_members(),
        )
        .await
        .expect("snapshot cancellation storage");
        state_machine
            .apply([initial_membership_entry()])
            .await
            .expect("snapshot cancellation membership");

        let capture_gate = backend.snapshot_capture_gate();
        capture_gate.arm();
        let core = state_machine.core.clone();
        let mut builder = state_machine.get_snapshot_builder().await;
        let build = tokio::spawn(async move { builder.build_snapshot().await });
        tokio::time::timeout(Duration::from_secs(5), capture_gate.wait_started())
            .await
            .expect("snapshot worker reaches its fixed source cut");

        build.abort();
        assert!(
            build
                .await
                .expect_err("snapshot future is cancelled")
                .is_cancelled(),
            "the fixture must cancel only the async snapshot caller"
        );
        assert!(
            std::sync::Arc::clone(&core.snapshot_gate)
                .try_lock_owned()
                .is_err(),
            "the detached blocking capture must retain the sole snapshot owner"
        );

        capture_gate.release();
        let worker_released = tokio::time::timeout(
            Duration::from_secs(5),
            std::sync::Arc::clone(&core.snapshot_gate).lock_owned(),
        )
        .await
        .expect("cancelled snapshot worker exits within the existing bounded test window");
        drop(worker_released);
        let mut entries = tokio::fs::read_dir(directory.path().join("snapshots"))
            .await
            .expect("read snapshot directory after cancellation");
        while let Some(entry) = entries
            .next_entry()
            .await
            .expect("read snapshot cancellation artifact")
        {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            assert!(
                !name.starts_with("build-") && !name.starts_with("seal-"),
                "cancelled snapshot build must not retain an unpublished artifact"
            );
        }
    }
}
