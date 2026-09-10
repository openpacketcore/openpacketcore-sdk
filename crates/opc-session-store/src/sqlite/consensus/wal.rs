//! Private executable WAL candidate for ADR 0021. This module is test-only.
//!
//! A selected SQLite image is the complete authority/application basis. A bounded
//! anonymous, disposable projection uses the existing SQL admission/projection functions; it is
//! only a pending read view, never a durability authority. Application binds
//! a committed cut to the original SQLite business transaction. Legacy
//! migration, snapshot publication/install, live recovery sidecars and production routing remain integration
//! boundaries. Only pristine operator-recovery state is admitted. Fixed
//! authority retains its complete original validators and frozen tuple.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bytes::Bytes;
use opc_consensus::engine::storage::LogFlushed;
use opc_consensus::engine::{Entry, LogId, Vote};
use rusqlite::{backup::Backup, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) mod adapter;
pub(crate) mod application;
mod checkpoint;
pub(crate) mod integration;
pub(crate) mod native;
mod native_basis;
pub(crate) mod owner;
mod record;
pub(crate) mod snapshot;
#[cfg(feature = "test-control")]
mod volatile_experiment;

use record::{Decoder, Record, MAX_FRAGMENT};

use super::{
    append_logs_in_tx, db_error, decode_consensus_log_entry, decode_json, encode_json,
    invalid_data, last_log_sync, logical_purge_logs_in_tx, read_applied_sync, read_committed_sync,
    read_consensus_authority_profile_sync, read_log_range_sync, read_storage_identity_sync,
    read_vote_sync, save_committed_in_tx, save_vote_in_tx, truncate_logs_in_tx,
    validate_current_operator_recovery_image_sync, validate_exact_log_prefix_through_sync,
    validate_log_id, ConsensusAuthorityProfile, MembershipLogProjection, SessionConsensusIdentity,
    SessionConsensusNodeId, SessionRaftTypeConfig, SessionTopologyMemberBinding,
    SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES,
};
use crate::fenced_mutation_roster::RosterAttestationTrustRootV1;
use crate::readiness::PlacementResiliencePolicy;

const SEGMENT_HEADER: usize = 80;
const FRAME_HEADER: usize = 100;
const CUT_SIZE: usize = 160;
const INTENT_SIZE: usize = 192;
const MAX_ENTRIES: usize = 64;
const MAX_BASIS: u64 = crate::consensus::snapshot::SNAPSHOT_DATABASE_MAX_BYTES;

#[derive(Clone, Copy, Debug)]
pub(super) struct Limits {
    pub(super) outstanding: usize,
    pub(super) outstanding_bytes: usize,
    pub(super) group_count: usize,
    pub(super) group_bytes: usize,
    pub(super) segment_bytes: usize,
    pub(super) history_count: usize,
    pub(super) history_bytes: usize,
    pub(super) segments: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            outstanding: 64,
            outstanding_bytes: 32 * 1024 * 1024,
            group_count: 16,
            group_bytes: 16 * 1024 * 1024,
            segment_bytes: 32 * 1024 * 1024,
            history_count: 1024,
            history_bytes: 2 * 1024 * 1024 * 1024,
            segments: 128,
        }
    }
}

impl Limits {
    fn fragment_bytes(self) -> usize {
        MAX_FRAGMENT.min(self.segment_bytes - SEGMENT_HEADER - FRAME_HEADER)
    }

    fn validate(self) -> io::Result<Self> {
        if self.outstanding == 0
            || self.outstanding > 1024
            || self.outstanding_bytes > 64 * 1024 * 1024
            || self.group_count == 0
            || self.group_count > self.outstanding
            || self.group_bytes <= FRAME_HEADER
            || self.group_bytes > self.outstanding_bytes
            || self.segment_bytes < self.group_bytes + SEGMENT_HEADER
            || self.history_count == 0
            || self.history_count > 4096
            || self.history_bytes as u64 > 4 * 1024 * 1024 * 1024
            || self.segments == 0
            || self.segments > 128
        {
            return Err(invalid_data("private WAL limits are invalid"));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct Binding {
    pub(super) identity: SessionConsensusIdentity,
    pub(super) generation: [u8; 32],
    pub(super) basis: [u8; 32],
    pub(super) native: bool,
}

impl Binding {
    pub(super) fn digest(self) -> io::Result<[u8; 32]> {
        let mut hash = Sha256::new();
        if self.native {
            hash.update(b"opc-session-native-wal-v1");
        } else {
            hash.update(b"opc-session-wal-private-v3");
        }
        hash.update(encode_json(&self.identity)?);
        hash.update(self.generation);
        hash.update(self.basis);
        Ok(hash.finalize().into())
    }
}

pub(crate) enum Operation {
    Append(Vec<Bytes>),
    Vote(Vote<SessionConsensusNodeId>),
    Committed(Option<LogId<SessionConsensusNodeId>>),
    Truncate(LogId<SessionConsensusNodeId>),
    Purge(LogId<SessionConsensusNodeId>),
    Barrier,
}

/// Configuration is loaded from the hash-bound image. Fixed-authority
/// operations still revalidate that exact tuple through the original helpers.
struct Authority {
    profile: ConsensusAuthorityProfile,
    scope: super::MembershipValidationScope,
    members: BTreeSet<SessionConsensusNodeId>,
    bindings: BTreeMap<SessionConsensusNodeId, SessionTopologyMemberBinding>,
    placement: Option<PlacementResiliencePolicy>,
    frozen_applied: Option<LogId<SessionConsensusNodeId>>,
}

impl Authority {
    fn load(conn: &Connection, identity: SessionConsensusIdentity) -> io::Result<Self> {
        let scope = super::read_membership_scope_sync(conn, identity)?;
        let authority = Self {
            profile: read_consensus_authority_profile_sync(conn)
                .map_err(|_| invalid_data("private WAL authority invalid"))?,
            members: scope.current_members.clone(),
            bindings: scope.current_bindings.clone(),
            scope,
            placement: super::read_fixed_placement_policy_sync(conn)
                .map_err(|_| invalid_data("private WAL placement invalid"))?,
            frozen_applied: read_applied_sync(conn, identity)?,
        };
        authority.validate(conn, identity)?;
        Ok(authority)
    }

    fn validate(&self, conn: &Connection, identity: SessionConsensusIdentity) -> io::Result<()> {
        super::validate_durable_authority_for_raw_access(
            conn,
            identity,
            self.profile,
            &self.members,
            &self.bindings,
            self.placement,
        )
    }
}

impl Operation {
    pub(super) fn encode(&self) -> io::Result<Record> {
        Record::encode(self)
    }

    fn validate_and_project(
        &self,
        conn: &Connection,
        identity: SessionConsensusIdentity,
        authority: &Authority,
    ) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
        let tx = conn.unchecked_transaction().map_err(db_error)?;
        authority.validate(&tx, identity)?;
        match self {
            Self::Append(bytes) => {
                let entries = bytes
                    .iter()
                    .map(|bytes| decode_consensus_log_entry(bytes))
                    .collect::<io::Result<Vec<_>>>()?;
                if authority.profile == ConsensusAuthorityProfile::FixedImmutable {
                    for entry in &entries {
                        super::validate_fixed_log_id(&entry.log_id)?;
                        if super::fixed_profile_entry_changes_topology(entry, &authority.members) {
                            return Err(invalid_data(
                                "private WAL fixed authority rejects topology change",
                            ));
                        }
                    }
                }
                // This is the original complete membership/receipt/V2
                // projection, including replay of the unapplied prefix.
                append_logs_in_tx(&tx, identity, &entries)?;
            }
            Self::Vote(vote) => {
                if authority.profile == ConsensusAuthorityProfile::FixedImmutable {
                    super::validate_fixed_vote_member(vote, &authority.members)?;
                }
                save_vote_in_tx(&tx, identity, vote)?;
            }
            Self::Committed(log_id) => save_committed_in_tx(&tx, identity, *log_id)?,
            Self::Truncate(log_id) => {
                let (_, index) = validate_log_id(log_id)?;
                truncate_logs_in_tx(&tx, identity, log_id, index)?;
            }
            Self::Purge(log_id) => {
                if !authority.frozen_applied.is_some_and(|applied| {
                    log_id.index <= applied.index
                        && (log_id.index != applied.index || *log_id == applied)
                }) {
                    return Err(invalid_data(
                        "private WAL purge exceeds frozen recovery basis",
                    ));
                }
                let (_, index) = validate_log_id(log_id)?;
                // Raft's logical floor advances under the original complete
                // validation. Keep the materialized rows on both sides of
                // the application audit until coordinated snapshot/cache
                // compaction selects their replacement. A WAL-only physical
                // delete would make a valid durable cache fail exact restore.
                logical_purge_logs_in_tx(&tx, identity, log_id, index)?;
            }
            Self::Barrier => {}
        }
        let committed = read_committed_sync(&tx, identity)?;
        tx.commit().map_err(db_error)?;
        Ok(committed)
    }
}

fn take_u32(input: &mut &[u8]) -> io::Result<u32> {
    let bytes = input
        .get(..4)
        .ok_or_else(|| invalid_data("private WAL truncated length"))?;
    let mut value = [0; 4];
    value.copy_from_slice(bytes);
    *input = &input[4..];
    Ok(u32::from_le_bytes(value))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Point {
    BeforeGroup,
    BeforeIntent,
    AfterIntentCreate,
    BeforeIntentSync,
    AfterIntentSync,
    AfterIntentRename,
    AfterIntentPublish,
    BeforeWrite,
    BeforeDataSync,
    AfterDataSync,
    BeforeCutPublish,
    AfterCutRename,
    AfterCutPublish,
    AfterFragment,
    BeforeRollover,
    AfterRollover,
    BeforeTailRepair,
    BeforeTailDataSync,
    AfterTailTruncate,
    AfterTailSegmentRemove,
    BeforeTailDirectorySync,
    BeforePendingRemove,
    AfterPendingUnlink,
    AfterPendingRemove,
    BeforeRecoveryPublicationSync,
    AfterRecoveryPublicationSync,
    AfterNativeBasisAdmission,
    BeforeNativeApplyPrepare,
    BeforeNativeApplyPublish,
    BeforeNativeReceiptRead,
    BeforeNativeLogRead,
    BeforeNativeSnapshotRead,
    BeforeNativePublicRead,
    BeforeNativeGenerationAppend,
    AfterNativeGenerationAppend,
    AfterNativeRelocationStep,
    BeforeBasisCreate,
    AfterBasisCreate,
    BeforeBasisSync,
    AfterBasisSync,
    AfterBasisRename,
    AfterBasisDirectorySync,
    BeforeBasisSelector,
    BeforeBasisSelectorSync,
    AfterBasisSelectorSync,
    AfterBasisSelectorRename,
    BeforeBasisPublicationSync,
    AfterBasisPublicationSync,
    BeforeBasisReclaim,
    AfterBasisReclaimFile,
    BeforeBasisReclaimSync,
    AfterBasisReclaimSync,
    AfterSnapshotSourceCut,
    BeforeSnapshotProof,
    AfterSnapshotProofCreate,
    BeforeSnapshotProofSync,
    AfterSnapshotProofSync,
    AfterSnapshotProofRename,
    AfterSnapshotProofDirectorySync,
    BeforeSnapshotCacheWrite,
    BeforeSnapshotCacheCommit,
    AfterSnapshotCacheCommit,
    BeforeSnapshotProofRetire,
    AfterSnapshotProofUnlink,
    BeforeSnapshotProofRetireSync,
    AfterSnapshotProofRetireSync,
}

#[derive(Clone)]
pub(super) struct IoControl {
    pub(super) hook: Arc<dyn Fn(Point) -> io::Result<()> + Send + Sync>,
    pub(super) write_chunk: usize,
    pub(super) fail_after_bytes: Option<usize>,
    pub(super) intent_fail_after_bytes: Option<usize>,
    pub(super) cut_fail_after_bytes: Option<usize>,
}

impl Default for IoControl {
    fn default() -> Self {
        Self {
            hook: Arc::new(|_| Ok(())),
            write_chunk: usize::MAX,
            fail_after_bytes: None,
            intent_fail_after_bytes: None,
            cut_fail_after_bytes: None,
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct AdmissionObservation {
    pub(super) operation: &'static str,
    pub(super) entries: usize,
    pub(super) encode: Duration,
    pub(super) lock_wait: Duration,
    pub(super) projection: Duration,
    pub(super) total: Duration,
}

#[derive(Clone, Debug)]
pub(super) struct FlushObservation {
    pub(super) first: u64,
    pub(super) last: u64,
    pub(super) bytes: usize,
    pub(super) queue_wait: Vec<Duration>,
    pub(super) admission: Vec<AdmissionObservation>,
    pub(super) submit_to_callback: Vec<Duration>,
    pub(super) rollover: Duration,
    pub(super) write: Duration,
    pub(super) intent: Duration,
    pub(super) data_sync: Duration,
    pub(super) publication: Duration,
    pub(super) callback_delay: Duration,
    pub(super) sync_calls: usize,
}

#[cfg(test)]
pub(super) struct ProjectionStorageObservation {
    pub(super) path: String,
    pub(super) cache: i64,
    pub(super) journal: String,
    pub(super) synchronous: i64,
    pub(super) bytes: u64,
    pub(super) page_size: u64,
    pub(super) maximum_pages: u64,
}

pub(super) struct Ticket(mpsc::Receiver<io::Result<u64>>);

impl Ticket {
    pub(super) fn wait(self) -> io::Result<u64> {
        self.0
            .recv()
            .map_err(|_| io::Error::other("private WAL writer lost completion"))?
    }

    pub(super) fn try_recv(&self) -> Result<io::Result<u64>, mpsc::TryRecvError> {
        self.0.try_recv()
    }
}

pub(super) struct AsyncTicket(tokio::sync::oneshot::Receiver<io::Result<u64>>);

impl AsyncTicket {
    pub(super) async fn wait(self) -> io::Result<u64> {
        self.0
            .await
            .map_err(|_| io::Error::other("private WAL writer lost async completion"))?
    }
}

enum CompletionTarget {
    Blocking(mpsc::SyncSender<io::Result<u64>>),
    Async(tokio::sync::oneshot::Sender<io::Result<u64>>),
    Append(LogFlushed<SessionRaftTypeConfig>),
}

struct Completion(Option<CompletionTarget>);

impl Completion {
    fn finish(&mut self, result: io::Result<u64>) {
        match self.0.take() {
            Some(CompletionTarget::Blocking(sender)) => {
                let _ = sender.send(result);
            }
            Some(CompletionTarget::Async(sender)) => {
                let _ = sender.send(result);
            }
            Some(CompletionTarget::Append(callback)) => {
                callback.log_io_completed(result.map(|_| ()))
            }
            None => {}
        }
    }
}

impl Drop for Completion {
    fn drop(&mut self) {
        self.finish(Err(io::Error::other(
            "private WAL accepted write abandoned",
        )));
    }
}

struct Request {
    sequence: u64,
    record: Record,
    charge: usize,
    admitted: Instant,
    submitted: Instant,
    admission: AdmissionObservation,
    committed_after: Option<LogId<SessionConsensusNodeId>>,
    completion: Completion,
}

impl Request {
    fn finish(mut self, result: io::Result<u64>) {
        self.completion.finish(result);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Running,
    Closing,
    Closed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableCut {
    chain: [u8; 32],
    committed: Option<LogId<SessionConsensusNodeId>>,
    // A selected full snapshot can advance committed without a Raft WAL op.
    // Ordinary cuts keep their exact prior encoding; old readers reject this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    installed: Option<snapshot::InstalledCut>,
}

struct State {
    // Immutable cold legacy-import template on the native route. Native
    // admission, business application and reads branch before touching it.
    conn: Connection,
    authority: Authority,
    native: Option<crate::consensus::native::NativeStorage>,
    native_snapshot_pending: Option<super::CurrentSnapshot>,
    native_checkpoint_target: Option<native_basis::Target>,
    native_basis_active: bool,
    native_basis_ready: bool,
    native_relocations_pending: bool,
    native_install_pending: bool,
    native_operations: usize,
    native_sql_fallbacks: u64,
    #[cfg(feature = "test-control")]
    volatile_experiment: Option<volatile_experiment::Observation>,
    queue: VecDeque<Request>,
    outstanding: usize,
    outstanding_bytes: usize,
    sequence: u64,
    base_sequence: u64,
    history_bytes: usize,
    checkpoint_requested: bool,
    checkpoint_epoch: u64,
    snapshot: Option<snapshot::Handoff>,
    status: Status,
    observations: VecDeque<FlushObservation>,
    observation_requests: usize,
    observation_totals: integration::FlushCosts,
    cache_validation_costs: integration::CacheCosts,
    cache_read_costs: integration::CacheCosts,
    application_costs: integration::ApplicationCosts,
    checkpoint_costs: integration::CheckpointCosts,
    durable_committed: Option<LogId<SessionConsensusNodeId>>,
    durable_cuts: BTreeMap<u64, DurableCut>,
    application_guard: Option<application::CacheGuard>,
    application_marker: Option<application::Marker>,
    applied_prefix: Option<application::AppliedPrefix>,
}

struct Shared {
    state: Mutex<State>,
    ready: Condvar,
}

pub(crate) struct Wal {
    binding: Binding,
    directory: PathBuf,
    limits: Limits,
    shared: Arc<Shared>,
    writer: Mutex<Option<JoinHandle<io::Result<()>>>>,
    control: IoControl,
    configured_roster_root: Option<Arc<RosterAttestationTrustRootV1>>,
    // Retain the namespace through writer/basis drain and every detached read.
    directory_pin: Option<Arc<File>>,
}

impl State {
    fn volatile_mode(&self) -> bool {
        #[cfg(feature = "test-control")]
        if self.volatile_experiment.is_some() {
            return true;
        }
        false
    }

    fn committed_for_application(&self) -> Option<LogId<SessionConsensusNodeId>> {
        #[cfg(feature = "test-control")]
        if self.volatile_experiment.is_some() {
            return self.native.as_ref().and_then(|native| native.log.committed);
        }
        self.durable_committed
    }

    fn recovered(
        binding: Binding,
        conn: Connection,
        history_bytes: usize,
        position: CutPosition,
        anchor: Option<&checkpoint::Anchor>,
        cuts: BTreeMap<u64, DurableCut>,
        native: Option<crate::consensus::native::NativeStorage>,
    ) -> io::Result<Self> {
        if binding.native != native.is_some() {
            return Err(invalid_data("native recovered owner format differs"));
        }
        let authority = Authority::load(&conn, binding.identity)?;
        let durable_committed = match &native {
            Some(native) => native.log.committed,
            None => read_committed_sync(&conn, binding.identity)?,
        };
        Ok(Self {
            conn,
            authority,
            native,
            native_snapshot_pending: None,
            native_checkpoint_target: None,
            native_basis_active: false,
            native_basis_ready: false,
            native_relocations_pending: false,
            native_install_pending: false,
            native_operations: 0,
            native_sql_fallbacks: 0,
            #[cfg(feature = "test-control")]
            volatile_experiment: None,
            queue: VecDeque::new(),
            outstanding: 0,
            outstanding_bytes: 0,
            sequence: position.sequence,
            base_sequence: anchor.map_or(0, |anchor| anchor.position.sequence),
            history_bytes,
            checkpoint_requested: false,
            checkpoint_epoch: anchor.map_or(0, |anchor| anchor.epoch),
            snapshot: None,
            status: Status::Running,
            observations: VecDeque::new(),
            observation_requests: 0,
            observation_totals: Default::default(),
            cache_validation_costs: Default::default(),
            cache_read_costs: Default::default(),
            application_costs: Default::default(),
            checkpoint_costs: Default::default(),
            durable_committed,
            durable_cuts: cuts,
            application_guard: None,
            application_marker: anchor.and_then(|anchor| anchor.marker.clone()),
            applied_prefix: None,
        })
    }
}

impl Wal {
    pub(super) fn create(
        directory: &Path,
        basis: &Connection,
        identity: SessionConsensusIdentity,
        generation: [u8; 32],
        limits: Limits,
        control: IoControl,
    ) -> io::Result<Self> {
        Self::create_with_format(
            directory, basis, identity, generation, limits, control, false, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_with_format(
        directory: &Path,
        basis: &Connection,
        identity: SessionConsensusIdentity,
        generation: [u8; 32],
        limits: Limits,
        control: IoControl,
        native: bool,
        roster_root: Option<Arc<RosterAttestationTrustRootV1>>,
    ) -> io::Result<Self> {
        let limits = limits.validate()?;
        validate_basis(basis, identity)?;
        if native {
            native::validate_roster_root(basis, roster_root.as_deref())?;
        }
        if let Some(path) = basis.path().filter(|path| !path.is_empty()) {
            let recovery = super::classify_operator_recovery_latch_with_connection_sync(
                Path::new(path),
                basis,
            )?;
            if recovery.latch().is_some() || recovery.has_consumed_terminal() {
                return Err(invalid_data(
                    "private WAL live recovery sidecar is unsupported",
                ));
            }
        }
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        if let Some(parent) = directory.parent() {
            File::open(parent)?.sync_all()?;
        }
        let directory_pin = owner::pin_directory(directory)?;
        let pinned_path = owner::directory_path(&directory_pin);
        let directory = pinned_path.as_path();
        let lock = file_create(&directory.join("LOCK"))?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        lock.sync_all()?;
        let basis_path = directory.join("basis.sqlite");
        file_create(&basis_path)?.sync_all()?;
        let mut frozen = Connection::open(&basis_path).map_err(db_error)?;
        Backup::new(basis, &mut frozen)
            .map_err(db_error)?
            .run_to_completion(128, Duration::ZERO, None)
            .map_err(db_error)?;
        frozen
            .pragma_update(None, "journal_mode", "DELETE")
            .map_err(db_error)?;
        frozen.close().map_err(|(_, error)| db_error(error))?;
        file_read(&basis_path)?.sync_all()?;
        let binding = Binding {
            identity,
            generation,
            basis: hash_file(&basis_path, MAX_BASIS)?,
            native,
        };
        let digest = binding.digest()?;
        let segment = create_segment(directory, 0, digest, [0; 32])?;
        File::open(directory)?.sync_all()?;
        let conn = if native {
            native::cold_basis(directory, binding)?
        } else {
            load_basis(directory, binding)?
        };
        let disk = Disk {
            directory: directory.to_path_buf(),
            _lock: lock,
            file: segment,
            binding: digest,
            segment: 0,
            offset: SEGMENT_HEADER as u64,
            chain: [0; 32],
            sequence: 0,
            cut: 0,
            cut_chain: [0; 32],
            anchor: None,
            cuts: BTreeMap::from([(
                0,
                DurableCut {
                    chain: [0; 32],
                    committed: read_committed_sync(&conn, identity)?,
                    installed: None,
                },
            )]),
        };
        let mut wal = Self::start(binding, limits, conn, 0, disk, control, roster_root)?;
        wal.directory_pin = Some(directory_pin);
        Ok(wal)
    }

    pub(super) fn open(
        directory: &Path,
        binding: Binding,
        limits: Limits,
        control: IoControl,
    ) -> io::Result<Self> {
        if binding.native {
            return native::open(directory, binding, None, limits, control);
        }
        let limits = limits.validate()?;
        if !fs::symlink_metadata(directory)?.is_dir() {
            return Err(invalid_data("private WAL directory is invalid"));
        }
        let lock = file_read(&directory.join("LOCK"))?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)?;
        let anchor = checkpoint::read(directory, binding, limits)?;
        let conn = match &anchor {
            Some(anchor) => anchor.load_basis(directory, binding)?,
            None => load_basis(directory, binding)?,
        };
        let (disk, history_bytes) =
            recover(directory, binding, limits, &conn, lock, &control, anchor)?;
        Self::start(binding, limits, conn, history_bytes, disk, control, None)
    }

    fn start(
        binding: Binding,
        limits: Limits,
        conn: Connection,
        history_bytes: usize,
        mut disk: Disk,
        control: IoControl,
        roster_root: Option<Arc<RosterAttestationTrustRootV1>>,
    ) -> io::Result<Self> {
        let native = if binding.native {
            let authority = Authority::load(&conn, binding.identity)?;
            Some(native::from_pristine_basis(
                &conn,
                binding,
                &authority,
                roster_root,
            )?)
        } else {
            None
        };
        let mut state = State::recovered(
            binding,
            conn,
            history_bytes,
            disk.position(),
            disk.anchor.as_ref(),
            disk.cuts.clone(),
            native,
        )?;
        let selected = if binding.native {
            let native = state
                .native
                .take()
                .ok_or_else(|| invalid_data("native creation resident owner missing"))?;
            let (native, selected) =
                native_basis::bootstrap(native, &mut disk, binding, limits, &control)?;
            let anchor = disk
                .anchor
                .as_ref()
                .ok_or_else(|| invalid_data("native creation selected anchor missing"))?;
            state.base_sequence = anchor.position.sequence;
            state.checkpoint_epoch = anchor.epoch;
            state.history_bytes = 0;
            state.authority.frozen_applied = anchor.applied;
            state.durable_cuts = disk.cuts.clone();
            state.durable_committed = native.log.committed;
            state.native = Some(native);
            Some(selected)
        } else {
            None
        };
        Self::start_state(binding, limits, state, disk, control, selected)
    }

    fn start_state(
        binding: Binding,
        limits: Limits,
        mut state: State,
        disk: Disk,
        control: IoControl,
        selected: Option<native_basis::Selected>,
    ) -> io::Result<Self> {
        if binding.native != selected.is_some() || binding.native != state.native.is_some() {
            return Err(invalid_data(
                "native live creation requires its selected generation owner",
            ));
        }
        // Bootstrap replaces its prospective state with the admitted Catalog.
        // Bind local cursor authority to that final state before the writer
        // starts; this local secret is intentionally absent from shared bases.
        if let Some(native) = &mut state.native {
            native.business.set_local_restore_incarnation(
                crate::sqlite::ops::RestoreScanIncarnation::from_installed_sync(&state.conn)
                    .map_err(|_| invalid_data("native local restore identity unavailable"))?,
            );
        }
        // Native creation/cold admission received this root from the caller
        // and compared the cold basis against it before any replay. Retain
        // that configured object for joined-owner audits of the same WAL.
        let configured_roster_root = state
            .native
            .as_ref()
            .and_then(|native| native.business.roster_root().cloned());
        let shared = Arc::new(Shared {
            state: Mutex::new(state),
            ready: Condvar::new(),
        });
        let writer_shared = Arc::clone(&shared);
        let caller_control = control.clone();
        let directory = disk.directory.clone();
        let writer = std::thread::Builder::new()
            .name("session-wal-private".into())
            .spawn(move || {
                let _exit = WriterExit(Arc::clone(&writer_shared));
                write_loop(writer_shared, disk, binding, limits, control, selected)
            })?;
        Ok(Self {
            binding,
            directory,
            limits,
            shared,
            writer: Mutex::new(Some(writer)),
            control: caller_control,
            configured_roster_root,
            directory_pin: None,
        })
    }

    pub(super) fn binding(&self) -> Binding {
        self.binding
    }

    pub(super) fn submit(&self, operation: Operation) -> io::Result<Ticket> {
        let (sender, receiver) = mpsc::sync_channel(1);
        self.admit(
            operation,
            Completion(Some(CompletionTarget::Blocking(sender))),
        )?;
        Ok(Ticket(receiver))
    }

    /// The actual Raft adapter cannot treat retained-history pressure as a
    /// failed disk. It requests the existing durable basis handoff before
    /// admitting the original operation, under the same fixed format limits.
    fn submit_adapter_async(&self, operation: Operation) -> io::Result<AsyncTicket> {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        self.admit_inner(
            operation,
            Completion(Some(CompletionTarget::Async(sender))),
            true,
        )?;
        Ok(AsyncTicket(receiver))
    }

    fn append_callback(
        &self,
        operation: Operation,
        callback: LogFlushed<SessionRaftTypeConfig>,
    ) -> io::Result<()> {
        self.admit_inner(
            operation,
            Completion(Some(CompletionTarget::Append(callback))),
            true,
        )
    }

    fn admit(&self, operation: Operation, completion: Completion) -> io::Result<()> {
        self.admit_inner(operation, completion, false)
    }

    fn admit_inner(
        &self,
        operation: Operation,
        completion: Completion,
        checkpoint_on_retention: bool,
    ) -> io::Result<()> {
        let submitted = Instant::now();
        let (operation_name, entries) = match &operation {
            Operation::Append(entries) => ("append", entries.len()),
            Operation::Vote(_) => ("vote", 0),
            Operation::Committed(_) => ("committed", 0),
            Operation::Truncate(_) => ("truncate", 0),
            Operation::Purge(_) => ("purge", 0),
            Operation::Barrier => ("barrier", 0),
        };
        let record = operation.encode()?;
        let charge = record.charge(self.limits.fragment_bytes())?;
        let encode = submitted.elapsed();
        let lock_started = Instant::now();
        let mut state = lock_state(&self.shared)?;
        #[cfg(feature = "test-control")]
        if state.volatile_experiment.is_some() {
            return volatile_experiment::admit(self, &mut state, &operation, completion, charge);
        }
        loop {
            while ((!self.binding.native && state.checkpoint_requested)
                || state.snapshot.is_some()
                || state.native_install_pending)
                && state.status == Status::Running
            {
                state = self
                    .shared
                    .ready
                    .wait(state)
                    .map_err(|_| io::Error::other("private WAL checkpoint wait poisoned"))?;
            }
            if state.status != Status::Running {
                return Err(io::Error::other("private WAL writer is fenced"));
            }
            let retained_capacity_exhausted = state.sequence.saturating_sub(state.base_sequence)
                >= self.limits.history_count as u64
                || state
                    .history_bytes
                    .checked_add(charge)
                    .is_none_or(|total| total > self.limits.history_bytes);
            // These two bounds cannot be repaired by moving a basis. Keep
            // the original bounded rejection instead of an endless handoff.
            if !checkpoint_on_retention
                || !retained_capacity_exhausted
                || charge > self.limits.history_bytes
                || state.sequence == u64::MAX
            {
                break;
            }
            state.checkpoint_requested = true;
            state.checkpoint_costs.automatic_requests += 1;
            self.shared.ready.notify_all();
            // This operation has not changed the projection, sequence or
            // queue. Its callback stays here while earlier accepted owners
            // drain, and is admitted exactly once after the selected basis.
            if self.binding.native {
                // Preparation does not stop admission. At the unchanged hard
                // bound, wait for real publication progress instead of spinning
                // on an already requested or running background capture.
                state = self
                    .shared
                    .ready
                    .wait(state)
                    .map_err(|_| io::Error::other("native WAL retention wait poisoned"))?;
            }
        }
        let lock_wait = lock_started.elapsed();
        if state.status != Status::Running {
            return Err(io::Error::other("private WAL writer is fenced"));
        }
        // A maximum legal append may exceed the ordinary queue/group budget.
        // It is admitted alone, with its own fixed format bound. No second
        // request can consume bytes until that whole operation completes.
        if state.outstanding >= self.limits.outstanding
            || (state.outstanding != 0
                && state.outstanding_bytes.saturating_add(charge) > self.limits.outstanding_bytes)
            || state.sequence.saturating_sub(state.base_sequence)
                >= self.limits.history_count as u64
            || state.sequence == u64::MAX
            || state
                .history_bytes
                .checked_add(charge)
                .is_none_or(|total| total > self.limits.history_bytes)
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "private WAL admission limit",
            ));
        }
        let projection_started = Instant::now();
        let committed_after =
            match application::project_operation(&mut state, self.binding, &operation) {
                Ok(committed) => committed,
                Err(error) => {
                    if state.status == Status::Failed {
                        self.shared.ready.notify_all();
                    }
                    return Err(error);
                }
            };
        let projection = projection_started.elapsed();
        state.sequence += 1;
        let sequence = state.sequence;
        state.history_bytes += charge;
        state.outstanding += 1;
        state.outstanding_bytes += charge;
        state.queue.push_back(Request {
            sequence,
            record,
            charge,
            admitted: Instant::now(),
            submitted,
            admission: AdmissionObservation {
                operation: operation_name,
                entries,
                encode,
                lock_wait,
                projection,
                total: submitted.elapsed(),
            },
            committed_after,
            completion,
        });
        // Native checkpoint/snapshot publishers can wait concurrently with
        // admission. notify_one could wake only one of those publishers and
        // strand the writer despite queued work. Every predicate uses State.
        if self.binding.native {
            self.shared.ready.notify_all();
        } else {
            self.shared.ready.notify_one();
        }
        Ok(())
    }

    pub(super) fn read(
        &self,
        start: u64,
        end: u64,
    ) -> io::Result<Vec<Entry<SessionRaftTypeConfig>>> {
        if self.binding.native {
            return self.native_log_read(start, Some(end), Some(MAX_ENTRIES));
        }
        let state = lock_state(&self.shared)?;
        ensure_readable(&state)?;
        state
            .authority
            .validate(&state.conn, self.binding.identity)?;
        read_log_range_sync(
            &state.conn,
            self.binding.identity,
            start,
            Some(end),
            Some(MAX_ENTRIES),
        )
    }

    pub(super) fn vote(&self) -> io::Result<Option<Vote<SessionConsensusNodeId>>> {
        let state = lock_state(&self.shared)?;
        ensure_readable(&state)?;
        if let Some(native) = &state.native {
            return Ok(native.log.vote);
        }
        state
            .authority
            .validate(&state.conn, self.binding.identity)?;
        read_vote_sync(&state.conn, self.binding.identity)
    }

    pub(super) fn committed(&self) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
        let state = lock_state(&self.shared)?;
        ensure_readable(&state)?;
        if let Some(native) = &state.native {
            return Ok(native.log.committed);
        }
        state
            .authority
            .validate(&state.conn, self.binding.identity)?;
        read_committed_sync(&state.conn, self.binding.identity)
    }

    pub(super) fn observations(&self) -> io::Result<Vec<FlushObservation>> {
        Ok(lock_state(&self.shared)?
            .observations
            .iter()
            .cloned()
            .collect())
    }

    #[cfg(test)]
    pub(in crate::sqlite::consensus) fn projection_storage_for_test(
        &self,
    ) -> io::Result<ProjectionStorageObservation> {
        let state = lock_state(&self.shared)?;
        let conn = &state.conn;
        let cache: i64 = conn
            .pragma_query_value(None, "cache_size", |row| row.get(0))
            .map_err(db_error)?;
        let journal: String = conn
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .map_err(db_error)?;
        let synchronous: i64 = conn
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .map_err(db_error)?;
        let pages: u64 = conn
            .pragma_query_value(None, "page_count", |row| row.get(0))
            .map_err(db_error)?;
        let page_size: u64 = conn
            .pragma_query_value(None, "page_size", |row| row.get(0))
            .map_err(db_error)?;
        let maximum_pages: u64 = conn
            .pragma_query_value(None, "max_page_count", |row| row.get(0))
            .map_err(db_error)?;
        Ok(ProjectionStorageObservation {
            path: conn.path().unwrap_or_default().to_owned(),
            cache,
            journal,
            synchronous,
            bytes: pages * page_size,
            page_size,
            maximum_pages,
        })
    }

    pub(crate) fn shutdown(&self) -> io::Result<()> {
        if let Ok(mut state) = self.shared.state.lock() {
            if state.status == Status::Running {
                state.status = Status::Closing;
            }
            self.shared.ready.notify_all();
        }
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| io::Error::other("private WAL join poisoned"))?;
        if let Some(writer) = writer.take() {
            writer
                .join()
                .map_err(|_| io::Error::other("private WAL writer panicked"))??;
        }
        ensure_readable(&*lock_state(&self.shared)?)
    }
}

impl Drop for Wal {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn lock_state(shared: &Shared) -> io::Result<MutexGuard<'_, State>> {
    shared
        .state
        .lock()
        .map_err(|_| io::Error::other("private WAL pending view poisoned"))
}

fn ensure_readable(state: &State) -> io::Result<()> {
    if state.status == Status::Failed {
        return Err(io::Error::other("private WAL pending view is fenced"));
    }
    Ok(())
}

struct WriterExit(Arc<Shared>);

impl Drop for WriterExit {
    fn drop(&mut self) {
        // Poison is a terminal failure, but must not strand accepted owners.
        let mut state = match self.0.state.lock() {
            Ok(state) => state,
            Err(poison) => poison.into_inner(),
        };
        if state.status != Status::Closed {
            state.status = Status::Failed;
            state.queue.clear(); // Request::drop owns each failure completion.
        }
        self.0.ready.notify_all();
    }
}

struct Group {
    shared: Arc<Shared>,
    requests: Vec<Request>,
    completed: bool,
}

impl Drop for Group {
    fn drop(&mut self) {
        if !self.completed {
            let mut state = match self.shared.state.lock() {
                Ok(state) => state,
                Err(poison) => poison.into_inner(),
            };
            // Fence pending reads/admission before either queued or in-flight
            // failure completion becomes observable, including unwind.
            state.status = Status::Failed;
            state.queue.clear();
        }
    }
}

struct Disk {
    directory: PathBuf,
    _lock: File,
    file: File,
    binding: [u8; 32],
    segment: u64,
    offset: u64,
    chain: [u8; 32],
    sequence: u64,
    cut: u64,
    cut_chain: [u8; 32],
    anchor: Option<checkpoint::Anchor>,
    cuts: BTreeMap<u64, DurableCut>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CutPosition {
    segment: u64,
    offset: u64,
    sequence: u64,
    chain: [u8; 32],
}

impl CutPosition {
    fn initial() -> Self {
        Self {
            segment: 0,
            offset: SEGMENT_HEADER as u64,
            sequence: 0,
            chain: [0; 32],
        }
    }

    fn decode(bytes: &[u8], limits: Limits) -> io::Result<Self> {
        let position = Self {
            segment: number(&bytes[8..16])?,
            offset: number(&bytes[16..24])?,
            sequence: number(&bytes[24..32])?,
            chain: bytes[32..64]
                .try_into()
                .map_err(|_| invalid_data("private WAL cut chain truncated"))?,
        };
        if position.offset < SEGMENT_HEADER as u64 || position.offset > limits.segment_bytes as u64
        {
            return Err(invalid_data("private WAL cut position exceeds bounds"));
        }
        Ok(position)
    }

    fn encode(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.segment.to_le_bytes());
        bytes.extend_from_slice(&self.offset.to_le_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes.extend_from_slice(&self.chain);
    }
}

impl Disk {
    fn base_position(&self) -> CutPosition {
        self.anchor
            .as_ref()
            .map_or_else(CutPosition::initial, |anchor| anchor.position)
    }

    fn position(&self) -> CutPosition {
        CutPosition {
            segment: self.segment,
            offset: self.offset,
            sequence: self.sequence,
            chain: self.chain,
        }
    }
}

/// This prefix is never overwritten. Its durable `.pending` name must be
/// removed by publishing the complete cut before any callback can succeed.
struct GroupIntent {
    start: CutPosition,
    previous_cut: [u8; 32],
    binding: [u8; 32],
    last: u64,
    bytes: usize,
    end_segment: u64,
    end_offset: u64,
}

impl GroupIntent {
    fn plan(disk: &Disk, requests: &[Request], limits: Limits) -> io::Result<Self> {
        let start = disk.position();
        let mut end = start;
        let mut bytes = 0_usize;
        for request in requests {
            if request.sequence != end.sequence + 1 {
                return Err(invalid_data("private WAL planned operation sequence gap"));
            }
            let mut remaining = request.record.len();
            while remaining > 0 {
                let size = remaining.min(limits.fragment_bytes());
                let physical = (FRAME_HEADER + size) as u64;
                if end
                    .offset
                    .checked_add(physical)
                    .is_none_or(|offset| offset > limits.segment_bytes as u64)
                {
                    end.segment += 1;
                    if end.segment.saturating_sub(disk.base_position().segment)
                        >= limits.segments as u64
                    {
                        return Err(io::Error::other("private WAL retained segment limit"));
                    }
                    end.offset = SEGMENT_HEADER as u64;
                }
                end.offset = end
                    .offset
                    .checked_add(physical)
                    .ok_or_else(|| invalid_data("private WAL planned segment extent overflow"))?;
                bytes = bytes
                    .checked_add(FRAME_HEADER + size)
                    .ok_or_else(|| invalid_data("private WAL planned bytes overflow"))?;
                remaining -= size;
            }
            end.sequence = request.sequence;
        }
        Ok(Self {
            start,
            previous_cut: disk.cut_chain,
            binding: disk.binding,
            last: end.sequence,
            bytes,
            end_segment: end.segment,
            end_offset: end.offset,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(INTENT_SIZE);
        bytes.extend_from_slice(b"OPCWINT3");
        self.start.encode(&mut bytes);
        bytes.extend_from_slice(&self.previous_cut);
        bytes.extend_from_slice(&self.binding);
        bytes.extend_from_slice(&self.last.to_le_bytes());
        bytes.extend_from_slice(&(self.bytes as u64).to_le_bytes());
        bytes.extend_from_slice(&self.end_segment.to_le_bytes());
        bytes.extend_from_slice(&self.end_offset.to_le_bytes());
        bytes.extend_from_slice(&Sha256::digest(&bytes));
        bytes
    }

    fn decode(bytes: &[u8], binding: [u8; 32], limits: Limits) -> io::Result<Self> {
        if bytes.len() != INTENT_SIZE
            || &bytes[..8] != b"OPCWINT3"
            || bytes[96..128] != binding
            || bytes[160..] != Sha256::digest(&bytes[..160])[..]
        {
            return Err(invalid_data(
                "private WAL intent checksum or binding differs",
            ));
        }
        let intent = Self {
            start: CutPosition::decode(bytes, limits)?,
            previous_cut: bytes[64..96]
                .try_into()
                .map_err(|_| invalid_data("private WAL intent lineage truncated"))?,
            binding,
            last: number(&bytes[128..136])?,
            bytes: usize::try_from(number(&bytes[136..144])?)
                .map_err(|_| invalid_data("private WAL intent bytes exceed platform"))?,
            end_segment: number(&bytes[144..152])?,
            end_offset: number(&bytes[152..160])?,
        };
        let count = intent
            .last
            .checked_sub(intent.start.sequence)
            .filter(|count| *count > 0 && *count <= limits.group_count as u64)
            .ok_or_else(|| invalid_data("private WAL intent operation count invalid"))?;
        if intent.bytes < count as usize * (FRAME_HEADER + 1)
            || intent.bytes > limits.history_bytes
            || (count > 1 && intent.bytes > limits.group_bytes)
            || intent.end_segment < intent.start.segment
            || intent.end_segment.saturating_sub(intent.start.segment) >= limits.segments as u64
            || intent.end_offset <= SEGMENT_HEADER as u64
            || intent.end_offset > limits.segment_bytes as u64
            || (intent.end_segment == intent.start.segment
                && intent.end_offset <= intent.start.offset)
        {
            return Err(invalid_data("private WAL intent extent invalid"));
        }
        let new_segments = intent.end_segment - intent.start.segment;
        let remaining = limits.segment_bytes as u64 - intent.start.offset;
        let maximum_fragments = count as usize
            + (intent.bytes - count as usize * (FRAME_HEADER + 1))
                / (limits.fragment_bytes() + FRAME_HEADER);
        let span = if new_segments == 0 {
            u128::from(intent.end_offset - intent.start.offset)
        } else {
            u128::from(remaining)
                + u128::from(new_segments - 1) * (limits.segment_bytes - SEGMENT_HEADER) as u128
                + u128::from(intent.end_offset - SEGMENT_HEADER as u64)
        };
        if new_segments > maximum_fragments as u64
            || intent.bytes as u128 > span
            || (new_segments == 0 && intent.bytes as u128 != span)
            || (new_segments > 0
                && (intent.bytes as u64 <= remaining
                    || intent.end_offset < (SEGMENT_HEADER + FRAME_HEADER + 1) as u64))
        {
            return Err(invalid_data("private WAL intent plan geometry invalid"));
        }
        Ok(intent)
    }

    fn follows(&self, position: CutPosition, cut_chain: [u8; 32]) -> bool {
        self.start == position && self.previous_cut == cut_chain
    }
}

fn write_loop(
    shared: Arc<Shared>,
    mut disk: Disk,
    binding: Binding,
    limits: Limits,
    control: IoControl,
    selected: Option<native_basis::Selected>,
) -> io::Result<()> {
    // Catch the body while Disk (including directory LOCK) and the worker
    // owner stay in this frame. Unwind drops every State guard before join.
    let mut basis = native_basis::Owner::new(selected);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        write_loop_body(
            Arc::clone(&shared),
            &mut disk,
            binding,
            limits,
            &control,
            &mut basis,
        )
    }))
    .unwrap_or_else(|_| Err(io::Error::other("private WAL writer panicked")));
    if result.is_err() {
        let mut state = match shared.state.lock() {
            Ok(state) => state,
            Err(poison) => poison.into_inner(),
        };
        application::fence(&mut state);
        shared.ready.notify_all();
    }
    let joined = basis.join();
    // No return can release directory ownership before this join completes.
    result.and(joined.map(|_| ()))
}

fn write_loop_body(
    shared: Arc<Shared>,
    disk: &mut Disk,
    binding: Binding,
    limits: Limits,
    control: &IoControl,
    basis: &mut native_basis::Owner,
) -> io::Result<()> {
    loop {
        // Fault gates are outside the admission mutex and have no production
        // timer: singleton work flushes as soon as the writer can execute it.
        (control.hook)(Point::BeforeGroup)?;
        let mut state = lock_state(&shared)?;
        while state.queue.is_empty()
            && !state.volatile_mode()
            && (if binding.native {
                !basis.has_relocations()
                    && !state.native_basis_ready
                    && !native_basis::needed(&state, disk, limits)
            } else {
                !state.checkpoint_requested
            })
            && !state
                .snapshot
                .as_ref()
                .is_some_and(snapshot::Handoff::writer_ready)
            && state.status == Status::Running
        {
            state = shared
                .ready
                .wait(state)
                .map_err(|_| io::Error::other("private WAL wait poisoned"))?;
        }
        ensure_readable(&state)?;
        #[cfg(feature = "test-control")]
        if state.volatile_experiment.is_some()
            && state.queue.is_empty()
            && state.outstanding == 0
            && !state.native_basis_active
            && !basis.has_relocations()
        {
            drop(state);
            return volatile_experiment::write_loop(&shared, basis, binding, control);
        }
        if binding.native && state.native_basis_ready {
            drop(state);
            let prepared = basis
                .join()?
                .ok_or_else(|| invalid_data("native ready basis has no worker"))?;
            if let Err(error) = basis.select(&shared, disk, prepared, binding, limits, control) {
                let mut state = lock_state(&shared)?;
                state.checkpoint_costs.failures += 1;
                application::fence(&mut state);
                shared.ready.notify_all();
                return Err(error);
            }
            shared.ready.notify_all();
            continue;
        }
        if binding.native && basis.has_relocations() {
            drop(state);
            basis.relocate_step(&shared, disk, control)?;
            // One ordinary WAL group is serviced before the next unit even
            // when more rows remain. With no queue, continue immediately; do
            // not wait or start a second preparation over pending ownership.
            state = lock_state(&shared)?;
            ensure_readable(&state)?;
            if state.queue.is_empty() {
                continue;
            }
        }
        if binding.native && state.queue.is_empty() {
            if native_basis::needed(&state, disk, limits) {
                basis.start(&shared, &mut state, disk, binding, limits, control)?;
                shared.ready.notify_all();
                continue;
            }
            if state.native_basis_active {
                // Closing drains an active job as well as accepted WAL work.
                // The worker reports completion under State, preventing a
                // lost wakeup even when shutdown raced its final notification.
                drop(
                    shared
                        .ready
                        .wait(state)
                        .map_err(|_| io::Error::other("native basis shutdown wait poisoned"))?,
                );
                continue;
            }
        }
        if state.queue.is_empty() && state.snapshot.is_some() {
            if binding.native {
                drop(state);
                snapshot::advance_native(&shared, disk, basis, binding, limits, control)?;
                shared.ready.notify_all();
                continue;
            }
            if let Err(error) = snapshot::advance(&mut state, disk, binding, limits, control) {
                // Fence before releasing State. A spurious condvar wake must
                // not turn a consumed phase into success before WriterExit.
                application::fence(&mut state);
                shared.ready.notify_all();
                return Err(error);
            }
            shared.ready.notify_all();
            continue;
        }
        if !binding.native && state.queue.is_empty() && state.checkpoint_requested {
            let started = Instant::now();
            let result = checkpoint::publish(&mut state, disk, binding, limits, control);
            let elapsed = started.elapsed();
            state.checkpoint_costs.elapsed += elapsed;
            state.checkpoint_costs.maximum = state.checkpoint_costs.maximum.max(elapsed);
            if let Err(error) = result {
                state.checkpoint_costs.failures += 1;
                // Fence before the state mutex is released, including a
                // publication failure which left a recoverable CURRENT.
                application::fence(&mut state);
                shared.ready.notify_all();
                return Err(error);
            }
            state.checkpoint_costs.completed += 1;
            state.checkpoint_requested = false;
            shared.ready.notify_all();
            continue;
        }
        if state.queue.is_empty() {
            state.status = Status::Closed;
            return Ok(());
        }
        let mut group = Vec::new();
        let mut charge = 0;
        while group.len() < limits.group_count {
            let Some(next) = state.queue.front() else {
                break;
            };
            let next_charge = next.charge;
            if !group.is_empty() && charge + next_charge > limits.group_bytes {
                break;
            }
            if let Some(request) = state.queue.pop_front() {
                charge += next_charge;
                group.push(request);
            }
        }
        drop(state);
        let mut group = Group {
            shared: Arc::clone(&shared),
            requests: group,
            completed: false,
        };
        let first = group
            .requests
            .first()
            .ok_or_else(|| invalid_data("private WAL empty flush"))?
            .sequence;
        let last = group
            .requests
            .last()
            .ok_or_else(|| invalid_data("private WAL empty flush"))?
            .sequence;
        let queue_wait = group
            .requests
            .iter()
            .map(|request| request.admitted.elapsed())
            .collect();
        let admission = group
            .requests
            .iter()
            .map(|request| request.admission.clone())
            .collect();
        let mut sync_calls = 4; // durable intent and final cut, each file + directory
        let mut rollover = Duration::ZERO;
        let mut data_sync = Duration::ZERO;
        let mut write = Duration::ZERO;
        let mut dirty = false;
        let intent_started = Instant::now();
        (control.hook)(Point::BeforeIntent)?;
        let planned = GroupIntent::plan(&disk, &group.requests, limits)?;
        if planned.last != last || planned.bytes != charge {
            return Err(invalid_data(
                "private WAL intent charge differs from admitted group",
            ));
        }
        let next_cut = disk.cut + 1;
        let preparing = disk.directory.join(format!("cut-{next_cut:020}.preparing"));
        let pending = disk.directory.join(format!("cut-{next_cut:020}.pending"));
        let mut publication_file = file_create(&preparing)?;
        (control.hook)(Point::AfterIntentCreate)?;
        let intent_bytes = planned.encode();
        let intent_control = IoControl {
            fail_after_bytes: control.intent_fail_after_bytes,
            ..control.clone()
        };
        let mut intent_written = 0;
        write_controlled(
            &mut publication_file,
            &intent_bytes,
            &intent_control,
            &mut intent_written,
        )?;
        (control.hook)(Point::BeforeIntentSync)?;
        publication_file.sync_all()?;
        (control.hook)(Point::AfterIntentSync)?;
        fs::rename(&preparing, &pending)?;
        (control.hook)(Point::AfterIntentRename)?;
        File::open(&disk.directory)?.sync_all()?;
        (control.hook)(Point::AfterIntentPublish)?;
        let intent = intent_started.elapsed();
        (control.hook)(Point::BeforeWrite)?;
        let mut written = 0;
        let buffer_size = group
            .requests
            .iter()
            .map(|request| request.record.len())
            .max()
            .unwrap_or(1)
            .min(limits.fragment_bytes());
        let mut body = vec![0; buffer_size];
        for request in &group.requests {
            if request.sequence != disk.sequence + 1 {
                return Err(invalid_data("private WAL writer sequence gap"));
            }
            let mut reader = request.record.reader();
            let mut record_offset = 0;
            while record_offset < request.record.len() {
                let size = body.len().min(request.record.len() - record_offset);
                if disk.offset + (FRAME_HEADER + size) as u64 > limits.segment_bytes as u64 {
                    (control.hook)(Point::BeforeRollover)?;
                    if disk.segment + 1 - disk.base_position().segment >= limits.segments as u64 {
                        return Err(io::Error::other("private WAL retained segment limit"));
                    }
                    // A whole operation may cross segments. Every prior dirty
                    // segment must be durable before its descriptor is closed.
                    if dirty {
                        (control.hook)(Point::BeforeDataSync)?;
                        let started = Instant::now();
                        disk.file.sync_all()?;
                        data_sync += started.elapsed();
                        sync_calls += 1;
                        (control.hook)(Point::AfterDataSync)?;
                    }
                    let started = Instant::now();
                    disk.segment += 1;
                    disk.file =
                        create_segment(&disk.directory, disk.segment, disk.binding, disk.chain)?;
                    disk.offset = SEGMENT_HEADER as u64;
                    rollover += started.elapsed();
                    sync_calls += 2;
                    (control.hook)(Point::AfterRollover)?;
                }
                let started = Instant::now();
                reader.read_exact(&mut body[..size])?;
                let header = frame_header(
                    request.sequence,
                    request.record.len(),
                    record_offset,
                    disk.chain,
                    &body[..size],
                );
                write_controlled(&mut disk.file, &header, &control, &mut written)?;
                write_controlled(&mut disk.file, &body[..size], &control, &mut written)?;
                disk.chain.copy_from_slice(&header[68..100]);
                disk.offset += (FRAME_HEADER + size) as u64;
                record_offset += size;
                dirty = true;
                write += started.elapsed();
                (control.hook)(Point::AfterFragment)?;
            }
            // Fragment publication is never an operation or callback cut.
            disk.sequence = request.sequence;
        }
        if disk.segment != planned.end_segment || disk.offset != planned.end_offset {
            return Err(invalid_data(
                "private WAL actual extent differs from durable intent",
            ));
        }
        (control.hook)(Point::BeforeDataSync)?;
        let sync_started = Instant::now();
        disk.file.sync_all()?;
        data_sync += sync_started.elapsed();
        sync_calls += 1;
        (control.hook)(Point::AfterDataSync)?;
        let publication_started = Instant::now();
        let cut = encode_cut(&disk);
        // Append the final cut; a failed/partial write cannot erase the
        // previously durable proof that this group has no success callback.
        let cut_control = IoControl {
            fail_after_bytes: control.cut_fail_after_bytes,
            ..control.clone()
        };
        let mut cut_written = 0;
        write_controlled(&mut publication_file, &cut, &cut_control, &mut cut_written)?;
        publication_file.sync_all()?;
        (control.hook)(Point::BeforeCutPublish)?;
        fs::rename(
            &pending,
            disk.directory.join(format!("cut-{next_cut:020}.cut")),
        )?;
        (control.hook)(Point::AfterCutRename)?;
        File::open(&disk.directory)?.sync_all()?;
        disk.cut = next_cut;
        let mut cut_hash = Sha256::new();
        cut_hash.update(&intent_bytes);
        cut_hash.update(&cut);
        disk.cut_chain = cut_hash.finalize().into();
        let publication = publication_started.elapsed();
        (control.hook)(Point::AfterCutPublish)?;
        // Application failure fences this same mutex. Keep success
        // completions inside it so no callback can cross that fence.
        let mut state = lock_state(&shared)?;
        ensure_readable(&state)?;
        let committed = group
            .requests
            .last()
            .and_then(|request| request.committed_after);
        state.durable_committed = committed;
        state.durable_cuts.insert(
            last,
            DurableCut {
                chain: disk.chain,
                committed,
                installed: None,
            },
        );
        if binding.native {
            disk.cuts.insert(
                last,
                DurableCut {
                    chain: disk.chain,
                    committed,
                    installed: None,
                },
            );
        }
        let callback_started = Instant::now();
        let count = group.requests.len();
        let mut submit_to_callback = Vec::with_capacity(count);
        for request in group.requests.drain(..) {
            let sequence = request.sequence;
            submit_to_callback.push(request.submitted.elapsed());
            request.finish(Ok(sequence));
        }
        group.completed = true;
        let callback_delay = callback_started.elapsed();
        state.outstanding -= count;
        state.outstanding_bytes -= charge;
        #[cfg(feature = "test-control")]
        if state.volatile_experiment.is_some() {
            shared.ready.notify_all();
        }
        let observation = FlushObservation {
            first,
            last,
            bytes: charge,
            queue_wait,
            admission,
            submit_to_callback,
            rollover,
            write,
            intent,
            data_sync,
            publication,
            callback_delay,
            sync_calls,
        };
        state.observation_totals.record(&observation);
        // Bound the retained per-request vectors, not merely the number of
        // groups. Checkpoints must not turn diagnostic memory into a second
        // unbounded history. Fixed-size totals retain all completed flushes.
        while state.observation_requests + count > limits.history_count {
            let Some(old) = state.observations.pop_front() else {
                break;
            };
            state.observation_requests -= old.admission.len();
        }
        if count <= limits.history_count {
            state.observation_requests += count;
            state.observations.push_back(observation);
        }
    }
}

fn write_controlled(
    file: &mut File,
    mut bytes: &[u8],
    control: &IoControl,
    written: &mut usize,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if control
            .fail_after_bytes
            .is_some_and(|limit| *written >= limit)
        {
            return Err(io::Error::from_raw_os_error(libc::ENOSPC));
        }
        let remaining = control
            .fail_after_bytes
            .map_or(usize::MAX, |limit| limit - *written);
        let len = bytes.len().min(control.write_chunk).min(remaining);
        let count = match file.write(&bytes[..len]) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "private WAL short write made no progress",
            ));
        }
        *written += count;
        bytes = &bytes[count..];
    }
    Ok(())
}

fn frame_header(
    sequence: u64,
    total: usize,
    offset: usize,
    previous: [u8; 32],
    body: &[u8],
) -> [u8; FRAME_HEADER] {
    let mut bytes = [0; FRAME_HEADER];
    bytes[..8].copy_from_slice(b"OPCWREC3");
    bytes[8..16].copy_from_slice(&sequence.to_le_bytes());
    bytes[16..20].copy_from_slice(&(body.len() as u32).to_le_bytes());
    bytes[20..28].copy_from_slice(&(total as u64).to_le_bytes());
    bytes[28..36].copy_from_slice(&(offset as u64).to_le_bytes());
    bytes[36..68].copy_from_slice(&previous);
    let mut hash = Sha256::new();
    hash.update(&bytes[..68]);
    hash.update(body);
    bytes[68..100].copy_from_slice(&hash.finalize());
    bytes
}

fn encode_cut(disk: &Disk) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(CUT_SIZE);
    bytes.extend_from_slice(b"OPCWCUT3");
    disk.position().encode(&mut bytes);
    bytes.extend_from_slice(&disk.cut_chain);
    bytes.extend_from_slice(&disk.binding);
    bytes.extend_from_slice(&Sha256::digest(&bytes));
    bytes
}

fn segment_header(number: u64, binding: [u8; 32], previous: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(SEGMENT_HEADER);
    bytes.extend_from_slice(b"OPCWSEG3");
    bytes.extend_from_slice(&number.to_le_bytes());
    bytes.extend_from_slice(&binding);
    bytes.extend_from_slice(&previous);
    bytes
}

fn create_segment(
    directory: &Path,
    number: u64,
    binding: [u8; 32],
    previous: [u8; 32],
) -> io::Result<File> {
    let mut file = file_create(&directory.join(format!("segment-{number:020}.wal")))?;
    file.write_all(&segment_header(number, binding, previous))?;
    file.sync_all()?;
    File::open(directory)?.sync_all()?;
    Ok(file)
}

fn file_create(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

fn file_read(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid_data("private WAL path is not a regular file"));
    }
    Ok(file)
}

fn hash_file(path: &Path, limit: u64) -> io::Result<[u8; 32]> {
    let mut file = file_read(path)?;
    if file.metadata()?.len() > limit {
        return Err(invalid_data("private WAL basis exceeds limit"));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 16 * 1024];
    let mut total = 0;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > limit {
            return Err(invalid_data("private WAL basis grew beyond limit"));
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize().into())
}

fn validate_basis(conn: &Connection, identity: SessionConsensusIdentity) -> io::Result<()> {
    if read_storage_identity_sync(conn)
        .map_err(|_| invalid_data("private WAL basis identity invalid"))?
        != identity
    {
        return Err(invalid_data("private WAL basis identity differs"));
    }
    Authority::load(conn, identity)?;
    let page_count: u64 = conn
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .map_err(db_error)?;
    let page_size: u64 = conn
        .pragma_query_value(None, "page_size", |row| row.get(0))
        .map_err(db_error)?;
    if page_count
        .checked_mul(page_size)
        .filter(|bytes| *bytes <= MAX_BASIS)
        .is_none()
    {
        return Err(invalid_data("private WAL basis exceeds snapshot limit"));
    }
    let recovery = validate_current_operator_recovery_image_sync(conn, identity)?;
    if recovery.recovery_epoch != 0 || recovery.pending_epoch.is_some() || recovery.v2_activated {
        return Err(invalid_data(
            "private WAL live operator recovery is unsupported",
        ));
    }
    let applied = read_applied_sync(conn, identity)?;
    let last = last_log_sync(conn, identity)?;
    // A migration must retain acknowledged but unapplied/uncommitted suffixes
    // as well as business state. The complete frozen image is the initial
    // log authority, and the original pointer/membership audit still applies.
    super::validate_retained_durable_log_sync(conn, identity, |_| Ok(()))?;
    MembershipLogProjection::load(conn, identity, false)?;
    if let Some(last) = last {
        validate_exact_log_prefix_through_sync(conn, identity, &last, false)?;
        let mut next = applied.map_or(Ok(0), |applied| {
            applied
                .index
                .checked_add(1)
                .ok_or_else(|| invalid_data("private WAL basis index exhausted"))
        })?;
        let end = last
            .index
            .checked_add(1)
            .ok_or_else(|| invalid_data("private WAL basis index exhausted"))?;
        while next < end {
            let batch_end = next.saturating_add(MAX_ENTRIES as u64).min(end);
            let entries =
                read_log_range_sync(conn, identity, next, Some(batch_end), Some(MAX_ENTRIES))?;
            if entries.len() as u64 != batch_end - next {
                return Err(invalid_data(
                    "private WAL basis unapplied prefix contains a hole",
                ));
            }
            next = batch_end;
        }
    }
    read_vote_sync(conn, identity)?;
    Ok(())
}

fn load_basis(directory: &Path, binding: Binding) -> io::Result<Connection> {
    let path = directory.join("basis.sqlite");
    load_basis_image(&path, binding.identity, binding.basis)
}

fn load_basis_image(
    path: &Path,
    identity: SessionConsensusIdentity,
    expected: [u8; 32],
) -> io::Result<Connection> {
    if hash_file(path, MAX_BASIS)? != expected {
        return Err(invalid_data("private WAL basis digest differs"));
    }
    let source =
        Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(db_error)?;
    // SQLite's empty filename selects a private TEMP_DB. On the bundled
    // Unix VFS it is created exclusively with DELETEONCLOSE and immediately
    // unlinked. No reusable path or second connection can own this image.
    // Journaling remains enabled for rollback; this disposable image is never
    // a durability authority and is reconstructed from the hash-bound basis.
    let mut conn = Connection::open("").map_err(db_error)?;
    conn.execute_batch("PRAGMA temp_store = FILE; PRAGMA cache_size = -8192; PRAGMA journal_mode = DELETE; PRAGMA synchronous = OFF;")
        .map_err(db_error)?;
    Backup::new(&source, &mut conn)
        .map_err(db_error)?
        .run_to_completion(128, Duration::ZERO, None)
        .map_err(db_error)?;
    // Backup may change the destination page size. Install the same writer
    // extent policy used by normal SDK opens only after its actual size is set.
    super::install_snapshot_database_extent_guard_sync(&conn)?;
    // Recompute SQLite's cache target using the post-backup page size. This
    // is a page-cache target, not a bound on the process or returned rows.
    conn.pragma_update(None, "cache_size", -8192)
        .map_err(db_error)?;
    if hash_file(path, MAX_BASIS)? != expected {
        return Err(invalid_data("private WAL basis changed during open"));
    }
    validate_basis(&conn, identity)?;
    Ok(conn)
}

fn number(bytes: &[u8]) -> io::Result<u64> {
    Ok(u64::from_le_bytes(bytes.try_into().map_err(|_| {
        invalid_data("private WAL truncated integer")
    })?))
}

fn numbered_name(name: &str, prefix: &str, suffix: &str) -> Option<u64> {
    let middle = name.strip_prefix(prefix)?.strip_suffix(suffix)?;
    let number = middle.parse().ok()?;
    (format!("{prefix}{number:020}{suffix}") == name).then_some(number)
}

struct PublishedCut {
    intent: GroupIntent,
    end: CutPosition,
    hash: [u8; 32],
}

impl PublishedCut {
    fn read(path: &Path, binding: [u8; 32], limits: Limits) -> io::Result<Self> {
        let mut file = file_read(path)?;
        if file.metadata()?.len() != (INTENT_SIZE + CUT_SIZE) as u64 {
            return Err(invalid_data("private WAL publication length invalid"));
        }
        let mut bytes = [0; INTENT_SIZE + CUT_SIZE];
        file.read_exact(&mut bytes)?;
        let intent = GroupIntent::decode(&bytes[..INTENT_SIZE], binding, limits)?;
        let cut = &bytes[INTENT_SIZE..];
        let end = CutPosition::decode(cut, limits)?;
        if &cut[..8] != b"OPCWCUT3"
            || cut[64..96] != intent.previous_cut
            || cut[96..128] != binding
            || cut[128..] != Sha256::digest(&cut[..128])[..]
            || end.sequence != intent.last
            || end.segment != intent.end_segment
            || end.offset != intent.end_offset
            || end.segment < intent.start.segment
            || end.offset == SEGMENT_HEADER as u64
            || (end.segment == intent.start.segment && end.offset <= intent.start.offset)
        {
            return Err(invalid_data(
                "private WAL publication differs from its intent",
            ));
        }
        Ok(Self {
            intent,
            end,
            hash: Sha256::digest(bytes).into(),
        })
    }
}

enum RepairStage {
    Preparing(PathBuf),
    Pending { path: PathBuf, intent: GroupIntent },
}

impl RepairStage {
    fn path(&self) -> &Path {
        match self {
            Self::Preparing(path) | Self::Pending { path, .. } => path,
        }
    }
}

fn validate_tail_geometry(
    segments: &BTreeMap<u64, (PathBuf, u64)>,
    end: CutPosition,
    intent: &GroupIntent,
    limits: Limits,
) -> io::Result<()> {
    let count = usize::try_from(intent.last - end.sequence)
        .map_err(|_| invalid_data("private WAL intent count exceeds platform"))?;
    // Each operation has one final fragment. Any additional fragment has
    // the full canonical physical size, including its header. A rollover
    // requires at least one planned fragment, even if its write never starts.
    let full_fragment = limits.fragment_bytes() + FRAME_HEADER;
    let maximum_fragments = count + (intent.bytes - count * (FRAME_HEADER + 1)) / full_fragment;
    let last = *segments
        .last_key_value()
        .ok_or_else(|| invalid_data("private WAL tail segments missing"))?
        .0;
    if last > intent.end_segment
        || last - end.segment > maximum_fragments as u64
        || (last > end.segment && intent.bytes as u64 <= limits.segment_bytes as u64 - end.offset)
    {
        return Err(invalid_data(
            "private WAL tail segment range exceeds planned group",
        ));
    }
    if segments
        .get(&intent.end_segment)
        .is_some_and(|(_, len)| *len > intent.end_offset)
    {
        return Err(invalid_data(
            "private WAL tail exceeds planned final segment offset",
        ));
    }
    for (&segment, (path, len)) in segments.range((end.segment + 1)..) {
        // A prior segment must have been written and synced before another
        // was created. Only the final new header may itself be incomplete.
        if segment < last
            && (*len < (SEGMENT_HEADER + FRAME_HEADER + 1) as u64
                || *len + full_fragment as u64 <= limits.segment_bytes as u64)
        {
            return Err(invalid_data(
                "private WAL unrelated empty or short tail segment",
            ));
        }
        let mut file = file_read(path)?;
        let mut header = [0; SEGMENT_HEADER];
        let available = usize::try_from((*len).min(SEGMENT_HEADER as u64))
            .map_err(|_| invalid_data("private WAL partial header exceeds platform"))?;
        file.read_exact(&mut header[..available])?;
        let known = available.min(48);
        if header[..known] != segment_header(segment, intent.binding, [0; 32])[..known] {
            return Err(invalid_data(
                "private WAL tail segment belongs to another namespace",
            ));
        }
    }
    Ok(())
}

fn recover(
    directory: &Path,
    binding: Binding,
    limits: Limits,
    conn: &Connection,
    lock: File,
    control: &IoControl,
    anchor: Option<checkpoint::Anchor>,
) -> io::Result<(Disk, usize)> {
    audit_recovery(directory, binding, limits, conn, anchor, false)?
        .finish(directory, lock, control)
}

/// No durable mutation and no usable log owner precedes this audit. Pending
/// snapshot resolution additionally verifies both complete images and the
/// external descriptors before it consumes this repair plan.
struct RecoveryAudit {
    digest: [u8; 32],
    end: CutPosition,
    cut: u64,
    cut_chain: [u8; 32],
    anchor: Option<checkpoint::Anchor>,
    verified_cuts: BTreeMap<u64, DurableCut>,
    history_bytes: usize,
    segments: BTreeMap<u64, (PathBuf, u64)>,
    stage: Option<RepairStage>,
    retired: Vec<PathBuf>,
}

fn audit_recovery(
    directory: &Path,
    binding: Binding,
    limits: Limits,
    conn: &Connection,
    anchor: Option<checkpoint::Anchor>,
    allow_snapshot_proof: bool,
) -> io::Result<RecoveryAudit> {
    let authority = Authority::load(conn, binding.identity)?;
    let basis_committed = read_committed_sync(conn, binding.identity)?;
    audit_recovery_projected(
        directory,
        binding,
        limits,
        anchor,
        allow_snapshot_proof,
        basis_committed,
        |operation| operation.validate_and_project(conn, binding.identity, &authority),
    )
}

fn audit_recovery_projected(
    directory: &Path,
    binding: Binding,
    limits: Limits,
    anchor: Option<checkpoint::Anchor>,
    allow_snapshot_proof: bool,
    basis_committed: Option<LogId<SessionConsensusNodeId>>,
    mut project: impl FnMut(&Operation) -> io::Result<Option<LogId<SessionConsensusNodeId>>>,
) -> io::Result<RecoveryAudit> {
    let base = anchor
        .as_ref()
        .map_or_else(CutPosition::initial, |anchor| anchor.position);
    let base_cut = anchor.as_ref().map_or(0, |anchor| anchor.cut);
    let mut segments = BTreeMap::new();
    let mut cuts = BTreeMap::new();
    let mut stages = Vec::new();
    let mut retired = Vec::new();
    let mut basis_namespace = checkpoint::Namespace::default();
    let mut retired_segments = 0;
    let mut retired_cuts = 0;
    let mut file_count = 0;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        file_count += 1;
        if file_count
            > 2 * (limits.segments + limits.history_count)
                + 8
                + 2 * usize::from(allow_snapshot_proof)
            || !entry.file_type()?.is_file()
        {
            return Err(invalid_data("private WAL directory exceeds format bounds"));
        }
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| invalid_data("private WAL filename invalid"))?;
        if let Some(number) = numbered_name(name, "segment-", ".wal") {
            let len = entry.metadata()?.len();
            if len > limits.segment_bytes as u64 {
                return Err(invalid_data("private WAL segment length exceeds limit"));
            }
            if number < base.segment {
                retired_segments += 1;
                retired.push(entry.path());
            } else {
                segments.insert(number, (entry.path(), len));
            }
        } else if let Some(number) = numbered_name(name, "cut-", ".cut") {
            if number == 0 {
                return Err(invalid_data("private WAL zero publication ordinal"));
            }
            if number <= base_cut {
                if entry.metadata()?.len() != (INTENT_SIZE + CUT_SIZE) as u64 {
                    return Err(invalid_data(
                        "private WAL retired publication extent differs",
                    ));
                }
                retired_cuts += 1;
                retired.push(entry.path());
            } else {
                cuts.insert(number, entry.path());
            }
        } else if let Some(number) = numbered_name(name, "cut-", ".pending") {
            stages.push((number, false, entry.path()));
        } else if let Some(number) = numbered_name(name, "cut-", ".preparing") {
            stages.push((number, true, entry.path()));
        } else if allow_snapshot_proof && snapshot::is_proof_file(name, entry.metadata()?.len())? {
            // The exact two-image protocol owns these files. They must not
            // enter an ordinary checkpoint/tail cleanup plan.
        } else if !basis_namespace.visit(
            name,
            entry.path(),
            entry.metadata()?.len(),
            anchor.as_ref(),
            &mut retired,
        )? {
            return Err(invalid_data("private WAL unexplained publication file"));
        }
    }
    if segments.is_empty()
        || segments.len() > limits.segments
        || cuts.len() > limits.history_count
        || stages.len() > 1
        || retired_segments > limits.segments
        || retired_cuts > limits.history_count
    {
        return Err(invalid_data("private WAL file counts invalid"));
    }
    for segment in segments.keys() {
        if *segment - base.segment >= limits.segments as u64 {
            return Err(invalid_data("private WAL segment number exceeds limit"));
        }
    }

    // Read publication authority before looking at any unacknowledged bytes.
    // Every later cut must retain its complete predecessor intent and hash.
    let digest = binding.digest()?;
    if let Some(anchor) = &anchor {
        anchor.validate_prefix(directory, binding)?;
    }
    let mut end = base;
    let mut cut_chain = anchor.as_ref().map_or([0; 32], |anchor| anchor.cut_chain);
    let mut publications = Vec::new();
    for (expected, (&ordinal, path)) in cuts.iter().enumerate() {
        if ordinal != base_cut + expected as u64 + 1 {
            return Err(invalid_data("private WAL publication gap"));
        }
        let cut = PublishedCut::read(path, digest, limits)?;
        if cut.end.sequence.saturating_sub(base.sequence) > limits.history_count as u64
            || cut.end.segment.saturating_sub(base.segment) >= limits.segments as u64
        {
            return Err(invalid_data(
                "private WAL publication exceeds retained basis bounds",
            ));
        }
        if !cut.intent.follows(end, cut_chain) {
            return Err(invalid_data(
                "private WAL publication start differs from prior cut",
            ));
        }
        end = cut.end;
        cut_chain = cut.hash;
        publications.push(cut);
    }
    if !segments.contains_key(&end.segment) {
        return Err(invalid_data(
            "private WAL acknowledged final segment missing",
        ));
    }
    for (expected, (&segment, _)) in segments.range(..=end.segment).enumerate() {
        if segment != base.segment + expected as u64 {
            return Err(invalid_data("private WAL acknowledged segment gap"));
        }
    }

    let stage = if let Some((ordinal, preparing, path)) = stages.pop() {
        if ordinal != base_cut + cuts.len() as u64 + 1 || cuts.len() == limits.history_count {
            return Err(invalid_data(
                "private WAL interrupted publication ordinal invalid",
            ));
        }
        let mut file = file_read(&path)?;
        let len = file.metadata()?.len();
        if preparing {
            // This name never authorizes a data write. It may contain a
            // partial intent; only an otherwise exact data prefix permits
            // removing it, after all acknowledged content has been audited.
            if len > INTENT_SIZE as u64 {
                return Err(invalid_data("private WAL preparation extent invalid"));
            }
            Some(RepairStage::Preparing(path))
        } else {
            if !(INTENT_SIZE as u64..=(INTENT_SIZE + CUT_SIZE) as u64).contains(&len) {
                return Err(invalid_data("private WAL pending intent extent invalid"));
            }
            let mut bytes = [0; INTENT_SIZE];
            file.read_exact(&mut bytes)?;
            let intent = GroupIntent::decode(&bytes, digest, limits)?;
            if intent.last.saturating_sub(base.sequence) > limits.history_count as u64
                || intent.end_segment.saturating_sub(base.segment) >= limits.segments as u64
            {
                return Err(invalid_data(
                    "private WAL pending intent exceeds retained basis bounds",
                ));
            }
            if !intent.follows(end, cut_chain) {
                return Err(invalid_data(
                    "private WAL pending intent does not follow acknowledged cut",
                ));
            }
            Some(RepairStage::Pending { path, intent })
        }
    } else {
        None
    };

    let mut chain = base.chain;
    let mut sequence = base.sequence;
    let mut history_bytes = 0_usize;
    let mut points = BTreeMap::new();
    let mut decoder: Option<Decoder> = None;
    let mut position = base;
    for (&segment, (path, physical_len)) in segments.range(..=end.segment) {
        let len = if segment == end.segment {
            end.offset
        } else {
            *physical_len
        };
        if len < SEGMENT_HEADER as u64 || *physical_len < len {
            return Err(invalid_data(
                "private WAL acknowledged segment length invalid",
            ));
        }
        let mut file = file_read(path)?;
        let mut header = [0; SEGMENT_HEADER];
        file.read_exact(&mut header)?;
        if !(anchor.is_some() && segment == base.segment)
            && header.as_slice() != segment_header(segment, digest, chain)
        {
            return Err(invalid_data("private WAL segment binding differs"));
        }
        let mut offset = if segment == base.segment {
            base.offset
        } else {
            SEGMENT_HEADER as u64
        };
        file.seek(SeekFrom::Start(offset))?;
        while offset < len {
            if sequence >= end.sequence || len - offset < FRAME_HEADER as u64 {
                return Err(invalid_data(
                    "private WAL incomplete or excess acknowledged frame",
                ));
            }
            let mut header = [0; FRAME_HEADER];
            file.read_exact(&mut header)?;
            let mut size = &header[16..20];
            let size = take_u32(&mut size)? as usize;
            let total = usize::try_from(number(&header[20..28])?)
                .map_err(|_| invalid_data("private WAL operation length exceeds platform"))?;
            let record_offset = usize::try_from(number(&header[28..36])?)
                .map_err(|_| invalid_data("private WAL fragment offset exceeds platform"))?;
            if &header[..8] != b"OPCWREC3"
                || number(&header[8..16])? != sequence + 1
                || header[36..68] != chain
                || size == 0
                || size > limits.fragment_bytes()
                || size as u64 + FRAME_HEADER as u64 > len - offset
                || history_bytes
                    .checked_add(size + FRAME_HEADER)
                    .is_none_or(|total| total > limits.history_bytes)
            {
                return Err(invalid_data("private WAL frame bounds or lineage invalid"));
            }
            if decoder.is_none() {
                if record_offset != 0 {
                    return Err(invalid_data(
                        "private WAL first fragment offset is not zero",
                    ));
                }
                decoder = Some(Decoder::new(total)?);
            }
            let pending = decoder
                .as_mut()
                .ok_or_else(|| invalid_data("private WAL operation decoder is missing"))?;
            if pending.total() != total
                || pending.received() != record_offset
                || size != (total - record_offset).min(limits.fragment_bytes())
            {
                return Err(invalid_data("private WAL fragment order or length differs"));
            }
            let mut body = vec![0; size];
            file.read_exact(&mut body)?;
            if frame_header(sequence + 1, total, record_offset, chain, &body) != header {
                return Err(invalid_data("private WAL frame checksum differs"));
            }
            pending.push(&body)?;
            chain.copy_from_slice(&header[68..100]);
            offset += (FRAME_HEADER + size) as u64;
            history_bytes += FRAME_HEADER + size;
            if pending.received() == total {
                let operation = decoder
                    .take()
                    .ok_or_else(|| invalid_data("private WAL completed decoder is missing"))?
                    .finish()?;
                let committed = project(&operation)?;
                sequence += 1;
                let point = CutPosition {
                    segment,
                    offset,
                    sequence,
                    chain,
                };
                points.insert(sequence, (point, committed, history_bytes));
            }
        }
        if segment > base.segment && offset == SEGMENT_HEADER as u64 {
            return Err(invalid_data("private WAL acknowledged empty segment"));
        }
        position = CutPosition {
            segment,
            offset,
            sequence,
            chain,
        };
    }
    if decoder.is_some() || position != end {
        return Err(invalid_data(
            "private WAL acknowledged cut is not a whole operation",
        ));
    }

    let mut verified_cuts = anchor.as_ref().map_or_else(
        || {
            BTreeMap::from([(
                base.sequence,
                DurableCut {
                    chain: base.chain,
                    committed: basis_committed,
                    installed: None,
                },
            )])
        },
        |anchor| anchor.cuts.clone(),
    );
    let mut prior_bytes = 0;
    for cut in publications {
        let (point, committed, bytes) = points
            .get(&cut.end.sequence)
            .ok_or_else(|| invalid_data("private WAL cut point missing"))?;
        if *point != cut.end || bytes.checked_sub(prior_bytes) != Some(cut.intent.bytes) {
            return Err(invalid_data(
                "private WAL publication does not bind exact whole prefix",
            ));
        }
        verified_cuts.insert(
            cut.end.sequence,
            DurableCut {
                chain: point.chain,
                committed: *committed,
                installed: None,
            },
        );
        prior_bytes = *bytes;
    }

    let mut tail_bytes = 0_usize;
    let mut has_tail = false;
    for (&segment, (_, len)) in segments.range(end.segment..) {
        let retained = if segment == end.segment {
            end.offset
        } else {
            SEGMENT_HEADER as u64
        };
        has_tail |= segment > end.segment || *len > retained;
        tail_bytes = tail_bytes
            .checked_add(
                usize::try_from(len.saturating_sub(retained))
                    .map_err(|_| invalid_data("private WAL tail exceeds platform"))?,
            )
            .ok_or_else(|| invalid_data("private WAL tail extent overflow"))?;
    }
    match &stage {
        None if has_tail => {
            return Err(invalid_data(
                "private WAL tail has no durable non-acknowledgement proof",
            ))
        }
        Some(RepairStage::Preparing(_)) if has_tail => {
            return Err(invalid_data(
                "private WAL preparation cannot authorize data-tail discard",
            ))
        }
        Some(RepairStage::Pending { intent, .. })
            if tail_bytes > intent.bytes
                || history_bytes
                    .checked_add(intent.bytes)
                    .is_none_or(|bytes| bytes > limits.history_bytes) =>
        {
            return Err(invalid_data("private WAL tail exceeds its durable intent"))
        }
        _ => {}
    }
    if let Some(RepairStage::Pending { intent, .. }) = &stage {
        validate_tail_geometry(&segments, end, intent, limits)?;
    }

    Ok(RecoveryAudit {
        digest,
        end,
        cut: base_cut + cuts.len() as u64,
        cut_chain,
        anchor,
        verified_cuts,
        history_bytes,
        segments,
        stage,
        retired,
    })
}

impl RecoveryAudit {
    fn finish(
        self,
        directory: &Path,
        lock: File,
        control: &IoControl,
    ) -> io::Result<(Disk, usize)> {
        let Self {
            digest,
            end,
            cut,
            cut_chain,
            anchor,
            verified_cuts,
            history_bytes,
            segments,
            stage,
            retired,
        } = self;

        // No file mutation occurs before all published cuts, exact original
        // entries, authority projection and the surviving intent have passed.
        // Keep the durable intent until truncation and descending segment
        // removals are synced, so an interruption can repeat this safely. An
        // interrupted directory sync may persist only some removals; holes are
        // accepted exclusively beyond the acknowledged cut, within this intent.
        if let Some(stage) = stage {
            (control.hook)(Point::BeforeTailRepair)?;
            let (last_path, last_len) = segments
                .get(&end.segment)
                .ok_or_else(|| invalid_data("private WAL repair segment missing"))?;
            let file = OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(last_path)?;
            if *last_len > end.offset {
                file.set_len(end.offset)?;
            }
            // A prior repair may have changed the observed length and then
            // failed before its sync. Repeat the sync even at the correct length
            // before ever retiring the durable intent.
            (control.hook)(Point::BeforeTailDataSync)?;
            file.sync_all()?;
            (control.hook)(Point::AfterTailTruncate)?;
            for (_, (path, _)) in segments.range((end.segment + 1)..).rev() {
                fs::remove_file(path)?;
                (control.hook)(Point::AfterTailSegmentRemove)?;
            }
            (control.hook)(Point::BeforeTailDirectorySync)?;
            File::open(directory)?.sync_all()?;
            (control.hook)(Point::BeforePendingRemove)?;
            fs::remove_file(stage.path())?;
            (control.hook)(Point::AfterPendingUnlink)?;
            File::open(directory)?.sync_all()?;
            (control.hook)(Point::AfterPendingRemove)?;
        }

        // A prior owner may have synced cut contents and renamed pending to cut,
        // then died before syncing the directory. Merely observing that complete
        // cut cannot make it durable for this owner: a later power loss could
        // otherwise restore pending and authorize discarding exposed history.
        // Stabilize every surviving publication, including the no-stage path,
        // after validation and before returning any readable/durable log state.
        (control.hook)(Point::BeforeRecoveryPublicationSync)?;
        File::open(directory)?.sync_all()?;
        (control.hook)(Point::AfterRecoveryPublicationSync)?;

        // The selected basis now survives power loss. Only its covered namespace
        // can be reclaimed; validation above precedes every such mutation.
        checkpoint::reclaim(directory, &retired, control)?;

        let file = OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join(format!("segment-{:020}.wal", end.segment)))?;
        Ok((
            Disk {
                directory: directory.to_path_buf(),
                _lock: lock,
                file,
                binding: digest,
                segment: end.segment,
                offset: end.offset,
                chain: end.chain,
                sequence: end.sequence,
                cut,
                cut_chain,
                anchor,
                cuts: verified_cuts,
            },
            history_bytes,
        ))
    }
}
