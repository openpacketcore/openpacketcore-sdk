//! Storage API for session state (RFC 004 §7): the `SessionBackend` trait,
//! fenced compare-and-set and batch operations, the ordered replication-log
//! entry format consumed by the quorum layer, and `EncryptingSessionBackend`,
//! a wrapper that seals payloads before they leave process memory.
//!
//! Every mutation is authorized by a `LeaseGuard`; backends enforce the
//! fencing rule that a write carrying a token lower than the key's recorded
//! fence is rejected, so a stale owner can never overwrite a newer one.

use std::{future::Future, sync::Arc, time::Duration};

use async_trait::async_trait;
use futures_util::future::join_all;
use opc_key::{KeyProvider, RemoteSealProvider};
use opc_types::Timestamp;

use crate::{
    capability::BackendCapabilities,
    error::{LeaseError, StoreError},
    lease::{LeaseGuard, SessionLeaseManager},
    model::{FenceToken, Generation, OwnerId, SessionKey},
    record::{EncryptedSessionPayload, StoredSessionRecord},
    restore::{RestoreScanPage, RestoreScanRequest},
    topology::{ReplicaId, ReplicaTlsIdentity},
    ttl::{checked_session_deadline, validate_session_ttl},
};

/// Per-watcher buffer size for replication watch streams.
///
/// Slow consumers are disconnected once this many entries are queued so watch
/// fan-out cannot grow memory without bound. Consumers should resume from the
/// last processed sequence.
pub const WATCH_CHANNEL_CAPACITY: usize = 64;

/// Maximum depth of a replication operation tree, counting its root as one.
///
/// This fixed fleet-wide admission limit keeps post-decode validation,
/// cryptographic-provider work, and the built-in replay adapters bounded. It
/// is deliberately not configurable per replica because different limits
/// could make replicas disagree about the same ordered log entry. Versioned
/// `opc-session-net` protocol v4 pins and enforces this limit during
/// pre-allocation wire decoding.
pub const MAX_REPLICATION_OPERATION_DEPTH: usize = 16;

/// Maximum number of operation nodes in one replication entry.
///
/// Every leaf and every [`ReplicationOp::Batch`] container counts as one node.
/// The limit is fixed across the SDK so all replicas make the same admission
/// decision and a nested entry cannot trigger unbounded provider calls.
pub const MAX_REPLICATION_OPERATIONS_PER_ENTRY: usize = 256;

/// Atomic compare-and-set operation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CompareAndSet {
    /// Key being mutated. Must equal both the lease's key and the new
    /// record's key, otherwise the backend rejects the op with
    /// `StoreError::InvalidKey` before touching state.
    pub key: SessionKey,
    /// Lease credential authorizing this fenced mutation.
    pub lease: LeaseGuard,
    /// `None` means the key must not exist yet.
    pub expected_generation: Option<Generation>,
    /// Replacement record written if the expectation holds. Its `owner` and
    /// `fence` must match the lease, and for state classes that require
    /// monotonic generations its `generation` must be strictly greater than
    /// the current record's, or the CAS reports a conflict.
    pub new_record: StoredSessionRecord,
}

/// Outcome of a compare-and-set operation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum CompareAndSetResult {
    /// The generation expectation held and the new record was written
    /// (durably, for backends that persist).
    Success,
    /// The expectation failed — the current generation differed from
    /// `expected_generation`, or the existence expectation was wrong — and
    /// nothing was written. Callers should re-read (or use `current`) to
    /// re-derive the mutation before retrying.
    Conflict {
        /// The current record, if any.
        current: Option<StoredSessionRecord>,
    },
}

/// A single operation inside a batch.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum SessionOp {
    /// Unfenced point read of one record (expired records read as absent).
    Get {
        /// Key to look up.
        key: SessionKey,
    },
    /// Fenced compare-and-set, with the same expectation semantics as
    /// `SessionBackend::compare_and_set`.
    CompareAndSet(CompareAndSet),
    /// Fenced delete of the record covered by the lease. The key's recorded
    /// fence is retained after deletion so stale owners stay fenced out.
    DeleteFenced {
        /// Lease credential naming the key to delete and proving ownership.
        lease: LeaseGuard,
    },
    /// Fenced extension of the record's TTL without changing its payload or
    /// generation.
    RefreshTtl {
        /// Lease credential naming the key and proving ownership.
        lease: LeaseGuard,
        /// New time-to-live measured from the backend's current clock; it
        /// replaces (rather than adds to) the previous deadline.
        ttl: Duration,
    },
}

impl SessionOp {
    /// Validate every caller-supplied TTL carried by this operation.
    ///
    /// Adapters should preflight an entire batch before performing any slot so
    /// a malformed later TTL cannot leave an earlier mutation committed.
    pub fn validate_ttls(&self) -> Result<(), StoreError> {
        match self {
            Self::RefreshTtl { ttl, .. } => validate_session_ttl(*ttl),
            Self::Get { .. } | Self::CompareAndSet(_) | Self::DeleteFenced { .. } => Ok(()),
        }
    }
}

/// Validate all TTL-bearing operations in a batch before executing any slot.
pub fn validate_session_ops_ttls(ops: &[SessionOp]) -> Result<(), StoreError> {
    ops.iter().try_for_each(SessionOp::validate_ttls)
}

/// Result of a single batched operation.
///
/// `SessionBackend::batch` returns one entry per submitted op, in submission
/// order; partial failure is expressed per-slot rather than failing the whole
/// batch.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SessionOpResult {
    /// Outcome of a `SessionOp::Get`: `Ok(None)` means no live record.
    Get(Result<Option<StoredSessionRecord>, StoreError>),
    /// Outcome of a `SessionOp::CompareAndSet`; a CAS conflict is reported
    /// inside the `Ok` value, not as a `StoreError`.
    CompareAndSet(Result<CompareAndSetResult, StoreError>),
    /// Outcome of a `SessionOp::DeleteFenced`.
    DeleteFenced(Result<(), StoreError>),
    /// Outcome of a `SessionOp::RefreshTtl`; `Err(StoreError::NotFound)`
    /// means the record no longer exists (e.g. its TTL already elapsed).
    RefreshTtl(Result<(), StoreError>),
}

/// One position in the ordered replication log (RFC 004 §11.2).
///
/// The Openraft state machine emits this application journal only after commit;
/// caches, watches, and restore consumers use it as a domain cursor. It is not
/// a second election or consensus log.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReplicationEntry {
    /// 1-based, gap-free committed application position. Local adapters reject
    /// entries that would create a gap or diverge from an already-applied
    /// sequence.
    pub sequence: u64,
    /// Unique id of the originating write, used to tell idempotent
    /// re-delivery of the same entry apart from a divergent entry that
    /// collides on `sequence`.
    pub tx_id: String,
    /// The fenced mutation to replay when applying this entry.
    pub op: ReplicationOp,
    /// Coordinator wall-clock time when the entry was created. Informational;
    /// ordering authority is `sequence`, never this timestamp — no wall-clock
    /// last-writer-wins.
    pub timestamp: Timestamp,
}

impl ReplicationEntry {
    /// Validate the entry's sequence, operation-tree bounds, and all nested
    /// TTL/deadline metadata.
    ///
    /// A replicated absolute deadline may be earlier than the requested TTL
    /// (which is fail-closed), but it may not materially extend beyond
    /// `entry.timestamp + ttl`. A one-microsecond compatibility tolerance
    /// admits nanosecond rounding from legacy floating-point entries. This
    /// prevents a compatibility peer from pairing a bounded audit TTL with a
    /// deadline far beyond its claimed entry timestamp. In the production
    /// profile Openraft commits the application entry and its effective
    /// logical time.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.validate_sequence()?;
        self.op.validate_ttls_at(self.timestamp)
    }

    /// Consume and return this entry only when all replication invariants hold.
    ///
    /// On rejection, the operation tree is dismantled iteratively before the
    /// error is returned. Backend and protocol boundaries should prefer this
    /// method for caller-owned entries so even an extremely deep value built
    /// through the direct Rust API cannot overflow the stack while being
    /// dropped.
    pub fn into_validated(self) -> Result<Self, StoreError> {
        match self.validate() {
            Ok(()) => Ok(self),
            Err(error) => {
                self.discard_operation_iteratively();
                Err(error)
            }
        }
    }

    /// Validate the scalar replication-log position.
    ///
    /// Sequence zero is reserved for an empty log head and is never a valid
    /// entry position. This check is deliberately cheap so adapters can call
    /// it before locking state, invoking cryptography, or performing I/O.
    /// It does not prove contiguity, uniqueness, leadership, or commitment.
    pub fn validate_sequence(&self) -> Result<(), StoreError> {
        if self.sequence == 0 {
            return Err(StoreError::InvalidReplicationSequence);
        }
        Ok(())
    }

    fn discard_operation_iteratively(self) {
        let Self { op, .. } = self;
        discard_replication_op_iteratively(op);
    }
}

fn discard_replication_op_iteratively(root: ReplicationOp) {
    let mut pending = vec![vec![root].into_iter()];
    while let Some(current) = pending.last_mut() {
        match current.next() {
            Some(ReplicationOp::Batch { ops }) => pending.push(ops.into_iter()),
            Some(_) => {}
            None => {
                pending.pop();
            }
        }
    }
}

fn discard_replication_entries_iteratively(entries: Vec<ReplicationEntry>) {
    for entry in entries {
        entry.discard_operation_iteratively();
    }
}

/// Return the position immediately after `current` without wrapping.
///
/// `current == 0` represents an empty log and therefore yields sequence one.
/// Exhaustion is a backend availability failure: no further ordered mutation
/// can be represented until the replication design introduces a new epoch.
/// This arithmetic helper neither reserves a position nor grants write
/// authority.
pub fn next_replication_sequence(current: u64) -> Result<u64, StoreError> {
    current
        .checked_add(1)
        .ok_or_else(|| StoreError::BackendUnavailable("replication sequence exhausted".to_string()))
}

/// Validate a complete replication-log prefix before rebuilding state.
///
/// Empty input is valid. Non-empty input must start at one and contain every
/// subsequent position exactly once, in order.
pub fn validate_replication_prefix(entries: &[ReplicationEntry]) -> Result<(), StoreError> {
    let mut expected = 1_u64;
    let mut entries = entries.iter().peekable();
    while let Some(entry) = entries.next() {
        entry.validate()?;
        if entry.sequence != expected {
            return Err(StoreError::InvalidReplicationSequence);
        }
        if entries.peek().is_some() {
            expected = next_replication_sequence(expected)
                .map_err(|_| StoreError::InvalidReplicationSequence)?;
        }
    }
    Ok(())
}

/// Consume and validate a complete replication-log prefix.
///
/// This is the by-value counterpart to [`validate_replication_prefix`]. On
/// rejection it iteratively dismantles every supplied operation tree before
/// returning the error, avoiding recursive drop exposure at public backend
/// and wire boundaries.
pub fn validate_replication_prefix_owned(
    entries: Vec<ReplicationEntry>,
) -> Result<Vec<ReplicationEntry>, StoreError> {
    match validate_replication_prefix(&entries) {
        Ok(()) => Ok(entries),
        Err(error) => {
            discard_replication_entries_iteratively(entries);
            Err(error)
        }
    }
}

/// Validate a contiguous replication-log page returned by an adapter.
///
/// Unlike [`validate_replication_prefix`], a page may begin at any non-zero
/// sequence. Empty pages are valid.
pub fn validate_replication_page(entries: &[ReplicationEntry]) -> Result<(), StoreError> {
    let mut previous = None;
    for entry in entries {
        entry.validate()?;
        if let Some(sequence) = previous {
            let expected = next_replication_sequence(sequence)
                .map_err(|_| StoreError::InvalidReplicationSequence)?;
            if entry.sequence != expected {
                return Err(StoreError::InvalidReplicationSequence);
            }
        }
        previous = Some(entry.sequence);
    }
    Ok(())
}

/// Consume and validate a contiguous replication-log page.
///
/// This is the by-value counterpart to [`validate_replication_page`]. Invalid
/// operation trees are dismantled iteratively before the error is returned.
pub fn validate_replication_page_owned(
    entries: Vec<ReplicationEntry>,
) -> Result<Vec<ReplicationEntry>, StoreError> {
    match validate_replication_page(&entries) {
        Ok(()) => Ok(entries),
        Err(error) => {
            discard_replication_entries_iteratively(entries);
            Err(error)
        }
    }
}

/// Mutation payload carried by a `ReplicationEntry`.
///
/// Each variant captures everything a replica needs to re-validate the write
/// during replay: in particular the fence token (so a replica can reject
/// stale-owner mutations exactly as the original backend would) and, for
/// lease operations, the credential id that ties guards to lease entries.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ReplicationOp {
    /// Replay of a fenced compare-and-set write.
    CompareAndSet {
        /// Key being mutated.
        key: SessionKey,
        /// Generation the record must currently have (`None` = must not
        /// exist); replay fails with a CAS conflict otherwise.
        expected_generation: Option<Generation>,
        /// Lease credential id that authorized the CAS.
        credential_id: u64,
        /// Exact guard deadline from the authorizing lease.
        guard_expires_at: Timestamp,
        /// Record to install; its `fence` must not be lower than the
        /// replica's recorded fence for the key.
        new_record: StoredSessionRecord,
    },
    /// Replay of a fenced record deletion. The fence is retained on the key
    /// after deletion so stale owners remain fenced out.
    DeleteFenced {
        /// Key whose record is removed.
        key: SessionKey,
        /// Owner that issued the delete.
        owner: OwnerId,
        /// Fence under which the delete was authorized; replicas reject the
        /// replay if their recorded fence is higher.
        fence: FenceToken,
    },
    /// Replay of a fenced TTL refresh; payload and generation are unchanged.
    RefreshTtl {
        /// Key whose record deadline is extended.
        key: SessionKey,
        /// Owner that issued the refresh.
        owner: OwnerId,
        /// Fence under which the refresh was authorized.
        fence: FenceToken,
        /// Requested time-to-live, retained for audit and compatibility.
        ttl: Duration,
        /// Absolute deadline computed once by the mutation coordinator.
        expires_at: Timestamp,
    },
    /// Replay of a lease acquisition, installing the lease entry and bumping
    /// the key's recorded fence to `fence`.
    AcquireLease {
        /// Key being leased.
        key: SessionKey,
        /// Replica that acquired the lease.
        owner: OwnerId,
        /// Newly minted fence token; must be at least the replica's recorded
        /// fence for the key or the replay is rejected as stale.
        fence: FenceToken,
        /// Credential id minted with the guard; fenced mutations must present
        /// a guard with this exact id to be accepted.
        credential_id: u64,
        /// Requested lease time-to-live, retained for audit and compatibility.
        ttl: Duration,
        /// Absolute guard deadline computed once by the mutation coordinator.
        expires_at: Timestamp,
    },
    /// Replay of a lease renewal: the same fence and credential id with an
    /// extended expiry (renewal never changes the fence).
    RenewLease {
        /// Key whose lease is renewed.
        key: SessionKey,
        /// Holder renewing the lease.
        owner: OwnerId,
        /// Existing fence token, unchanged by renewal.
        fence: FenceToken,
        /// Existing credential id, unchanged by renewal.
        credential_id: u64,
        /// Requested new time-to-live, retained for audit and compatibility.
        ttl: Duration,
        /// Absolute renewed guard deadline computed once by the mutation coordinator.
        expires_at: Timestamp,
    },
    /// Replay of an explicit lease release. Marks the lease inactive but does
    /// NOT lower the key's recorded fence, so writes from the released guard
    /// keep failing with a stale fence.
    ReleaseLease {
        /// Key whose lease is released.
        key: SessionKey,
        /// Holder releasing the lease.
        owner: OwnerId,
        /// Fence of the released lease (retained as the key's fence floor).
        fence: FenceToken,
        /// Credential id of the released guard; only the matching lease entry
        /// is deactivated.
        credential_id: u64,
    },
    /// Replay of a batch: the nested ops are applied sequentially and the
    /// first failure aborts the rest of the batch replay.
    Batch {
        /// Mutations in original submission order.
        ops: Vec<ReplicationOp>,
    },
}

impl ReplicationOp {
    /// Validate the fixed fleet-wide depth and operation-count limits.
    ///
    /// Validation uses a bounded explicit stack. It accounts for already
    /// scheduled siblings before extending that stack, so a wide untrusted
    /// batch is rejected without allocating work proportional to its length.
    pub fn validate_structure(&self) -> Result<(), StoreError> {
        let mut pending = Vec::with_capacity(MAX_REPLICATION_OPERATION_DEPTH);
        pending.push((self, 1_usize));
        let mut visited = 0_usize;

        while let Some((op, depth)) = pending.pop() {
            visited = visited
                .checked_add(1)
                .ok_or(StoreError::ReplicationOperationLimitExceeded)?;
            if visited > MAX_REPLICATION_OPERATIONS_PER_ENTRY
                || depth > MAX_REPLICATION_OPERATION_DEPTH
            {
                return Err(StoreError::ReplicationOperationLimitExceeded);
            }

            let Self::Batch { ops } = op else {
                continue;
            };
            if !ops.is_empty() && depth >= MAX_REPLICATION_OPERATION_DEPTH {
                return Err(StoreError::ReplicationOperationLimitExceeded);
            }

            let scheduled = visited
                .checked_add(pending.len())
                .ok_or(StoreError::ReplicationOperationLimitExceeded)?;
            let remaining = MAX_REPLICATION_OPERATIONS_PER_ENTRY
                .checked_sub(scheduled)
                .ok_or(StoreError::ReplicationOperationLimitExceeded)?;
            if ops.len() > remaining {
                return Err(StoreError::ReplicationOperationLimitExceeded);
            }

            let child_depth = depth
                .checked_add(1)
                .ok_or(StoreError::ReplicationOperationLimitExceeded)?;
            pending.extend(ops.iter().rev().map(|child| (child, child_depth)));
        }

        Ok(())
    }

    /// Validate all TTL-bearing operations, including arbitrarily nested
    /// batches, against their replication-entry timestamp.
    ///
    /// Validation is iterative so hostile nesting cannot consume the call
    /// stack. It completes before any replay or rebuild mutation begins.
    pub fn validate_ttls_at(&self, reference_timestamp: Timestamp) -> Result<(), StoreError> {
        self.validate_structure()?;
        let mut pending = Vec::with_capacity(MAX_REPLICATION_OPERATION_DEPTH);
        pending.push(self);
        while let Some(op) = pending.pop() {
            match op {
                Self::RefreshTtl {
                    ttl, expires_at, ..
                }
                | Self::AcquireLease {
                    ttl, expires_at, ..
                }
                | Self::RenewLease {
                    ttl, expires_at, ..
                } => {
                    let latest = checked_session_deadline(reference_timestamp, *ttl)?;
                    let latest_with_legacy_tolerance = latest
                        .as_offset_datetime()
                        .checked_add(time::Duration::microseconds(1))
                        .map(Timestamp::from_offset_datetime)
                        .unwrap_or_else(|| {
                            Timestamp::from_offset_datetime(
                                time::PrimitiveDateTime::MAX.assume_utc(),
                            )
                        });
                    if *expires_at > latest_with_legacy_tolerance {
                        return Err(StoreError::InvalidSessionTtl);
                    }
                }
                Self::Batch { ops } => pending.extend(ops),
                Self::CompareAndSet { .. }
                | Self::DeleteFenced { .. }
                | Self::ReleaseLease { .. } => {}
            }
        }
        Ok(())
    }
}

#[allow(clippy::large_enum_variant)] // bounded to 256 nodes; boxing would allocate per node
enum ReplicationTransformWork {
    Visit(ReplicationOp),
    FinishBatch { child_count: usize },
}

fn replication_transform_invariant_error() -> StoreError {
    StoreError::Serialization("replication operation transform failed".to_string())
}

async fn transform_replication_op<F, Fut>(
    root: ReplicationOp,
    mut transform_record: F,
) -> Result<ReplicationOp, StoreError>
where
    F: FnMut(StoredSessionRecord) -> Fut + Send,
    Fut: Future<Output = Result<StoredSessionRecord, StoreError>> + Send,
{
    let mut work = Vec::with_capacity(MAX_REPLICATION_OPERATION_DEPTH);
    let mut transformed = Vec::with_capacity(MAX_REPLICATION_OPERATION_DEPTH);
    work.push(ReplicationTransformWork::Visit(root));

    while let Some(item) = work.pop() {
        match item {
            ReplicationTransformWork::Visit(ReplicationOp::CompareAndSet {
                key,
                expected_generation,
                credential_id,
                guard_expires_at,
                new_record,
            }) => {
                transformed.push(ReplicationOp::CompareAndSet {
                    key,
                    expected_generation,
                    credential_id,
                    guard_expires_at,
                    new_record: transform_record(new_record).await?,
                });
            }
            ReplicationTransformWork::Visit(ReplicationOp::Batch { ops }) => {
                let child_count = ops.len();
                work.push(ReplicationTransformWork::FinishBatch { child_count });
                work.extend(ops.into_iter().rev().map(ReplicationTransformWork::Visit));
            }
            ReplicationTransformWork::Visit(other) => transformed.push(other),
            ReplicationTransformWork::FinishBatch { child_count } => {
                let start = transformed
                    .len()
                    .checked_sub(child_count)
                    .ok_or_else(replication_transform_invariant_error)?;
                let ops = transformed.split_off(start);
                transformed.push(ReplicationOp::Batch { ops });
            }
        }
    }

    if transformed.len() != 1 {
        return Err(replication_transform_invariant_error());
    }
    transformed
        .pop()
        .ok_or_else(replication_transform_invariant_error)
}

async fn transform_replication_entry<F, Fut>(
    entry: ReplicationEntry,
    transform_record: F,
) -> Result<ReplicationEntry, StoreError>
where
    F: FnMut(StoredSessionRecord) -> Fut + Send,
    Fut: Future<Output = Result<StoredSessionRecord, StoreError>> + Send,
{
    let ReplicationEntry {
        sequence,
        tx_id,
        op,
        timestamp,
    } = entry;
    Ok(ReplicationEntry {
        sequence,
        tx_id,
        op: transform_replication_op(op, transform_record).await?,
        timestamp,
    })
}

/// Storage backend trait for session state.
///
/// Implementations MUST enforce their declared [`BackendCapabilities`]. In
/// particular, backends that do not support `atomic_compare_and_set` or
/// `monotonic_fencing_token` MUST reject the corresponding operations rather
/// than approximate them. Fenced mutations carry a [`LeaseGuard`] and MUST
/// fail with `StoreError::StaleFence` when the guard's token is lower than
/// the key's recorded fence (RFC 004 §9.2).
///
/// The replication-log data and mutation methods have fail-closed defaults
/// that return `StoreError::CapabilityNotSupported`; backends declaring
/// `ordered_replication_log` or `watch` must override them. The fresh-head
/// readiness method delegates to `max_replication_sequence` by default and
/// network adapters should override it to retain typed transport failures.
///
/// Durable adapters that reconstruct [`StoredSessionRecord`] from persisted
/// bytes MUST preserve payload encoding explicitly: use
/// [`EncryptedSessionPayload::try_envelope`] for RFC 003 ciphertext rows and
/// [`EncryptedSessionPayload::legacy_plaintext`] only for intentional
/// migrations of pre-envelope plaintext rows.
///
/// Standalone forwarding/compatibility adapters may expose a process-local
/// instance root and an authenticated legacy peer binding. Production
/// consensus topology is descriptor-only and never derives votes, membership,
/// or peer identity from these adapter tokens.
#[async_trait]
pub trait SessionBackend: Send + Sync {
    /// Process-local instance root declared by this backend adapter.
    ///
    /// Clone-sharing standalone backends and forwarding wrappers should share
    /// or delegate this token when callers need to detect adapter aliasing.
    /// Remote clients identify their local client instance, not the remote
    /// store. This value is never serialized, displayed, or used as an
    /// Openraft node, vote, membership, or authenticated peer identity.
    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        None
    }

    /// Immutable configured identity scope for a peer-authenticated adapter.
    ///
    /// The default is deliberately absent. A network adapter may return a
    /// binding only when every connection and reconnect verifies the declared
    /// peer before exposing backend operations. Forwarding wrappers must
    /// delegate this value unchanged.
    ///
    /// This is legacy remote-backend composition evidence, not a cached
    /// liveness result. The dedicated consensus transport binds its own exact
    /// descriptor identity and does not consult this value.
    fn peer_binding(&self) -> Option<BackendPeerBinding> {
        None
    }

    /// Return the capability declaration for this backend.
    async fn capabilities(&self) -> BackendCapabilities;

    /// Retrieve a record by key.
    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError>;

    /// Atomically compare the current generation and write the new record if it
    /// matches. Implementations MUST require a current [`LeaseGuard`] and MUST
    /// reject writes whose record owner/fence do not match that lease.
    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError>;

    /// Delete a record using the caller's current lease credential.
    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError>;

    /// Refresh the TTL of a record using the caller's current lease credential.
    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError>;

    /// Execute a batch of operations. TTL-bearing slots are all validated
    /// before any slot executes; an invalid TTL returns an outer
    /// [`StoreError::InvalidSessionTtl`] with no partial mutation. A valid batch
    /// is processed sequentially and operational failures are represented by
    /// individual [`SessionOpResult`] variants.
    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError>;

    /// Scan live session records for startup/failover restore.
    ///
    /// Implementations must apply the same expiry/pruning behavior as
    /// [`Self::get`] and return records in deterministic order for stable
    /// pagination. Backends that do not provide restore scans must keep this
    /// default fail-closed implementation.
    async fn scan_restore_records(
        &self,
        _request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        Err(StoreError::CapabilityNotSupported("restore_scan".into()))
    }

    /// Check if this backend is suitable for a specific session state profile.
    async fn assert_suitable_for(
        &self,
        profile: crate::capability::SessionStateProfile,
    ) -> Result<(), crate::capability::CapabilityError> {
        let caps = self.capabilities().await;
        crate::capability::validate_backend_for_profile(profile, &caps)
    }

    /// Get the maximum sequence number in the replication log.
    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "ordered_replication_log".into(),
        ))
    }

    /// Obtain a fresh replication head for durable-readiness assessment.
    ///
    /// Network adapters should override this method to preserve typed
    /// transport, authentication, timeout, and protocol failures. The default
    /// performs a real backend request and maps its opaque failure to the
    /// generic backend category; it never consults cached capabilities.
    async fn probe_replication_head(
        &self,
    ) -> Result<u64, crate::readiness::ReplicaReadinessFailure> {
        self.max_replication_sequence()
            .await
            .map_err(|_| crate::readiness::ReplicaReadinessFailure::Backend)
    }

    /// Retrieve log entries in the range [start, start + limit).
    async fn get_replication_log(
        &self,
        _start: u64,
        _limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "ordered_replication_log".into(),
        ))
    }

    /// Append a replication log entry and apply its complete operation tree
    /// locally in one atomic transaction.
    ///
    /// Implementations must reject invalid sequence and TTL/deadline metadata
    /// before locking, mutating, or invoking an external provider. If any
    /// nested operation fails, every record, lease, fence, counter, log
    /// position, and watcher-visible event must remain unchanged.
    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let _entry = entry.into_validated()?;
        Err(StoreError::CapabilityNotSupported(
            "ordered_replication_log".into(),
        ))
    }

    /// Replace a standalone/legacy compatibility backend from a caller-verified
    /// application-journal prefix.
    ///
    /// Production Openraft recovery and snapshots never use this authority and
    /// [`crate::ConsensusSessionStore`] rejects it. Compatibility implementations
    /// must replace both durable state and the journal only after complete replay;
    /// failure preserves prior state, counters, and subscriptions.
    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        let _entries = validate_replication_prefix_owned(entries)?;
        Err(StoreError::CapabilityNotSupported(
            "ordered_replication_log".into(),
        ))
    }

    /// Watch for session changes starting from a specific sequence number.
    async fn watch(
        &self,
        _start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        Err(StoreError::CapabilityNotSupported("watch".into()))
    }

    /// Get the next fence and credential ID globals for lease coordination.
    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        Err(StoreError::CapabilityNotSupported(
            "lease_coordination".into(),
        ))
    }
}

/// Opaque process-local identity for standalone adapter-alias detection.
///
/// Debug output is redacted because the value is derived from an allocation
/// address. It is intentionally not hashable, persistent, network-visible, or
/// an authentication identity.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BackendInstanceIdentity(usize);

impl BackendInstanceIdentity {
    /// Derive one identity shared by every clone holding the same `Arc`.
    pub fn for_shared<T: ?Sized>(value: &Arc<T>) -> Self {
        Self(Arc::as_ptr(value).cast::<()>() as usize)
    }
}

impl std::fmt::Debug for BackendInstanceIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackendInstanceIdentity(<redacted>)")
    }
}

/// Fixed-width identity shared by all peer bindings in one configured scope.
///
/// Network adapters use this value to bind connections to one cluster and
/// configuration generation. Its contents are intentionally opaque to the
/// session-store core and redacted from diagnostics.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackendPeerScopeIdentity([u8; 32]);

impl BackendPeerScopeIdentity {
    /// Construct an opaque scope identity from its fixed-width representation.
    pub const fn new(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// Return the fixed-width representation for protocol adapters.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for BackendPeerScopeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BackendPeerScopeIdentity(<redacted>)")
    }
}

/// Configured peer identity exposed by an authenticated backend adapter.
///
/// The binding connects one local topology member to one remote member under a
/// shared cluster/configuration scope. It contains no runtime health state and
/// does not replace a fresh authenticated request. Debug output deliberately
/// hides descriptor fingerprints and all identity values.
#[derive(Clone, PartialEq, Eq)]
pub struct BackendPeerBinding {
    local_replica_id: ReplicaId,
    remote_replica_id: ReplicaId,
    remote_tls_identity: ReplicaTlsIdentity,
    local_descriptor_fingerprint: [u8; 32],
    remote_descriptor_fingerprint: [u8; 32],
    configured_member_count: u16,
    scope: BackendPeerScopeIdentity,
}

impl BackendPeerBinding {
    /// Construct immutable composition evidence for one peer adapter.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_replica_id: ReplicaId,
        remote_replica_id: ReplicaId,
        remote_tls_identity: ReplicaTlsIdentity,
        local_descriptor_fingerprint: [u8; 32],
        remote_descriptor_fingerprint: [u8; 32],
        configured_member_count: u16,
        scope: BackendPeerScopeIdentity,
    ) -> Self {
        Self {
            local_replica_id,
            remote_replica_id,
            remote_tls_identity,
            local_descriptor_fingerprint,
            remote_descriptor_fingerprint,
            configured_member_count,
            scope,
        }
    }

    /// Configured local logical replica identity.
    pub const fn local_replica_id(&self) -> &ReplicaId {
        &self.local_replica_id
    }

    /// Authenticated remote logical replica identity.
    pub const fn remote_replica_id(&self) -> &ReplicaId {
        &self.remote_replica_id
    }

    /// Exact TLS identity expected from the remote replica.
    pub const fn remote_tls_identity(&self) -> &ReplicaTlsIdentity {
        &self.remote_tls_identity
    }

    /// Fingerprint of the configured local descriptor.
    pub const fn local_descriptor_fingerprint(&self) -> &[u8; 32] {
        &self.local_descriptor_fingerprint
    }

    /// Fingerprint of the configured remote descriptor.
    pub const fn remote_descriptor_fingerprint(&self) -> &[u8; 32] {
        &self.remote_descriptor_fingerprint
    }

    /// Configured voting-member count under this binding.
    pub const fn configured_member_count(&self) -> u16 {
        self.configured_member_count
    }

    /// Shared cluster/configuration scope.
    pub const fn scope(&self) -> &BackendPeerScopeIdentity {
        &self.scope
    }
}

impl std::fmt::Debug for BackendPeerBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendPeerBinding")
            .field("local_replica_id", &self.local_replica_id)
            .field("remote_replica_id", &self.remote_replica_id)
            .field("remote_tls_identity", &self.remote_tls_identity)
            .field("local_descriptor_fingerprint", &"<redacted>")
            .field("remote_descriptor_fingerprint", &"<redacted>")
            .field("configured_member_count", &self.configured_member_count)
            .field("scope", &self.scope)
            .finish()
    }
}

/// Session-backend wrapper that encrypts payloads before persistence and
/// decrypts them on reads using `opc-crypto` / `opc-key`.
pub struct EncryptingSessionBackend<B: ?Sized, P: ?Sized> {
    inner: Arc<B>,
    provider: Arc<P>,
    backend_namespace: Arc<str>,
}

impl<B: ?Sized, P: ?Sized> Clone for EncryptingSessionBackend<B, P> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            provider: Arc::clone(&self.provider),
            backend_namespace: Arc::clone(&self.backend_namespace),
        }
    }
}

impl<B: ?Sized, P: ?Sized> EncryptingSessionBackend<B, P> {
    /// Wrap `inner` so every record payload is sealed with keys from
    /// `provider` before persistence and unsealed on reads.
    ///
    /// `backend_namespace` is bound into the AEAD AAD of every envelope:
    /// ciphertext written under one namespace cannot be decrypted when read
    /// back under another, which prevents records from being silently
    /// replayed across backends or environments.
    pub fn new(inner: Arc<B>, provider: Arc<P>, backend_namespace: impl Into<String>) -> Self {
        Self {
            inner,
            provider,
            backend_namespace: Arc::<str>::from(backend_namespace.into()),
        }
    }

    /// The key provider used to resolve the tenant's active session key for
    /// encryption and to look up keys by id for decryption.
    pub fn provider(&self) -> &Arc<P> {
        &self.provider
    }

    /// The namespace string bound into every envelope's AAD (see
    /// `EncryptingSessionBackend::new`).
    pub fn backend_namespace(&self) -> &str {
        &self.backend_namespace
    }
}

impl<B, P> EncryptingSessionBackend<B, P>
where
    B: SessionBackend + ?Sized,
    P: KeyProvider + ?Sized,
{
    async fn encrypt_record(
        &self,
        mut record: StoredSessionRecord,
    ) -> Result<StoredSessionRecord, StoreError> {
        record.payload = EncryptedSessionPayload::encrypt(
            self.provider.as_ref(),
            &record,
            self.backend_namespace(),
        )
        .await?;
        Ok(record)
    }

    async fn decrypt_record(
        &self,
        mut record: StoredSessionRecord,
    ) -> Result<StoredSessionRecord, StoreError> {
        let plaintext = record
            .payload
            .decrypt(
                self.provider.as_ref(),
                &record.key,
                &record.state_type,
                record.generation,
                record.fence,
                self.backend_namespace(),
            )
            .await?;
        record.payload = EncryptedSessionPayload::new_zeroizing(plaintext);
        Ok(record)
    }

    async fn decrypt_optional_record(
        &self,
        record: Option<StoredSessionRecord>,
    ) -> Result<Option<StoredSessionRecord>, StoreError> {
        match record {
            Some(record) => self.decrypt_record(record).await.map(Some),
            None => Ok(None),
        }
    }

    async fn decrypt_cas_result(
        &self,
        result: CompareAndSetResult,
    ) -> Result<CompareAndSetResult, StoreError> {
        match result {
            CompareAndSetResult::Success => Ok(CompareAndSetResult::Success),
            CompareAndSetResult::Conflict { current } => Ok(CompareAndSetResult::Conflict {
                current: self.decrypt_optional_record(current).await?,
            }),
        }
    }

    async fn decrypt_batch_result(&self, result: SessionOpResult) -> SessionOpResult {
        match result {
            SessionOpResult::Get(result) => SessionOpResult::Get(match result {
                Ok(record) => self.decrypt_optional_record(record).await,
                Err(err) => Err(err),
            }),
            SessionOpResult::CompareAndSet(result) => {
                SessionOpResult::CompareAndSet(match result {
                    Ok(result) => self.decrypt_cas_result(result).await,
                    Err(err) => Err(err),
                })
            }
            SessionOpResult::DeleteFenced(result) => SessionOpResult::DeleteFenced(result),
            SessionOpResult::RefreshTtl(result) => SessionOpResult::RefreshTtl(result),
        }
    }
}

async fn decrypt_record_helper<P: KeyProvider + ?Sized>(
    provider: &P,
    mut record: StoredSessionRecord,
    backend_namespace: &str,
) -> Result<StoredSessionRecord, StoreError> {
    let plaintext = record
        .payload
        .decrypt(
            provider,
            &record.key,
            &record.state_type,
            record.generation,
            record.fence,
            backend_namespace,
        )
        .await?;
    record.payload = EncryptedSessionPayload::new_zeroizing(plaintext);
    Ok(record)
}

enum EncryptedBatchSlot {
    BackendResult,
    SyntheticResult(Box<SessionOpResult>),
}

#[async_trait]
impl<B, P> SessionBackend for EncryptingSessionBackend<B, P>
where
    B: SessionBackend + 'static + ?Sized,
    P: KeyProvider + 'static + ?Sized,
{
    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        self.inner.backend_instance_identity()
    }

    fn peer_binding(&self) -> Option<BackendPeerBinding> {
        self.inner.peer_binding()
    }

    async fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities().await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        let record = self.inner.get(key).await?;
        self.decrypt_optional_record(record).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        let encrypted_record = self.encrypt_record(op.new_record).await?;
        let result = self
            .inner
            .compare_and_set(CompareAndSet {
                key: op.key,
                lease: op.lease,
                expected_generation: op.expected_generation,
                new_record: encrypted_record,
            })
            .await?;
        self.decrypt_cas_result(result).await
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        self.inner.delete_fenced(lease).await
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        validate_session_ttl(ttl)?;
        self.inner.refresh_ttl(lease, ttl).await
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        validate_session_ops_ttls(&ops)?;
        if !self.inner.capabilities().await.batch_write {
            return Err(StoreError::CapabilityNotSupported("batch_write".into()));
        }

        let mut encrypted_ops = Vec::with_capacity(ops.len());
        let mut slots = Vec::with_capacity(ops.len());
        for op in ops {
            match op {
                SessionOp::Get { key } => {
                    encrypted_ops.push(SessionOp::Get { key });
                    slots.push(EncryptedBatchSlot::BackendResult);
                }
                SessionOp::CompareAndSet(cas) => match self.encrypt_record(cas.new_record).await {
                    Ok(new_record) => {
                        encrypted_ops.push(SessionOp::CompareAndSet(CompareAndSet {
                            key: cas.key,
                            lease: cas.lease,
                            expected_generation: cas.expected_generation,
                            new_record,
                        }));
                        slots.push(EncryptedBatchSlot::BackendResult);
                    }
                    Err(err) => {
                        slots.push(EncryptedBatchSlot::SyntheticResult(Box::new(
                            SessionOpResult::CompareAndSet(Err(err)),
                        )));
                    }
                },
                SessionOp::DeleteFenced { lease } => {
                    encrypted_ops.push(SessionOp::DeleteFenced { lease });
                    slots.push(EncryptedBatchSlot::BackendResult);
                }
                SessionOp::RefreshTtl { lease, ttl } => {
                    encrypted_ops.push(SessionOp::RefreshTtl { lease, ttl });
                    slots.push(EncryptedBatchSlot::BackendResult);
                }
            }
        }

        let backend_results = if encrypted_ops.is_empty() && !slots.is_empty() {
            Vec::new()
        } else {
            self.inner.batch(encrypted_ops).await?
        };

        let mut backend_results = backend_results.into_iter();
        let mut decrypted = vec![None; slots.len()];
        let mut pending = Vec::new();
        for (index, slot) in slots.into_iter().enumerate() {
            match slot {
                EncryptedBatchSlot::BackendResult => {
                    let Some(result) = backend_results.next() else {
                        return Err(StoreError::BackendUnavailable(
                            "session batch returned fewer results than requested".into(),
                        ));
                    };
                    pending.push(async move { (index, self.decrypt_batch_result(result).await) });
                }
                EncryptedBatchSlot::SyntheticResult(result) => decrypted[index] = Some(*result),
            }
        }

        if backend_results.next().is_some() {
            return Err(StoreError::BackendUnavailable(
                "session batch returned more results than requested".into(),
            ));
        }

        for (index, result) in join_all(pending).await {
            decrypted[index] = Some(result);
        }

        decrypted
            .into_iter()
            .map(|result| {
                result.ok_or_else(|| {
                    StoreError::BackendUnavailable(
                        "session batch returned fewer results than requested".into(),
                    )
                })
            })
            .collect()
    }

    async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        let mut page = self.inner.scan_restore_records(request).await?;
        let mut decrypted = Vec::with_capacity(page.records.len());
        for record in page.records {
            decrypted.push(self.decrypt_record(record).await?);
        }
        page.records = decrypted;
        page.loaded_count = page.records.len();
        Ok(page)
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.inner.max_replication_sequence().await
    }

    async fn probe_replication_head(
        &self,
    ) -> Result<u64, crate::readiness::ReplicaReadinessFailure> {
        self.inner.probe_replication_head().await
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let entries =
            validate_replication_page_owned(self.inner.get_replication_log(start, limit).await?)?;
        let mut decrypted = Vec::with_capacity(entries.len());
        for entry in entries {
            decrypted.push(
                transform_replication_entry(entry, |record| self.decrypt_record(record)).await?,
            );
        }
        Ok(decrypted)
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let entry = entry.into_validated()?;
        let entry =
            transform_replication_entry(entry, |record| self.encrypt_record(record)).await?;
        self.inner.replicate_entry(entry).await
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        let entries = validate_replication_prefix_owned(entries)?;
        let mut encrypted = Vec::with_capacity(entries.len());
        for entry in entries {
            encrypted.push(
                transform_replication_entry(entry, |record| self.encrypt_record(record)).await?,
            );
        }
        self.inner.rebuild_replication_state(encrypted).await
    }

    fn watch<'life0, 'async_trait>(
        &'life0 self,
        start_sequence: u64,
    ) -> std::pin::Pin<
        Box<
            dyn futures_util::Future<
                    Output = Result<
                        futures_util::stream::BoxStream<
                            'static,
                            Result<ReplicationEntry, StoreError>,
                        >,
                        StoreError,
                    >,
                > + Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        let inner = self.inner.clone();
        let provider = self.provider.clone();
        let backend_namespace = self.backend_namespace.clone();
        Box::pin(async move {
            let stream = inner.watch(start_sequence).await?;
            use futures_util::StreamExt;
            let stream = stream.then(move |res| {
                let provider = provider.clone();
                let backend_namespace = backend_namespace.clone();
                async move {
                    match res {
                        Ok(entry) => {
                            let entry = entry.into_validated()?;
                            transform_replication_entry(entry, |record| {
                                decrypt_record_helper(provider.as_ref(), record, &backend_namespace)
                            })
                            .await
                        }
                        Err(e) => Err(e),
                    }
                }
            });
            Ok(stream.boxed())
        })
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        self.inner.next_lease_info().await
    }
}

#[async_trait]
impl<B, P> SessionLeaseManager for EncryptingSessionBackend<B, P>
where
    B: SessionLeaseManager + Send + Sync + ?Sized,
    P: KeyProvider + ?Sized,
{
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: crate::model::OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        self.inner.acquire(key, owner, ttl).await
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        self.inner.renew(lease, ttl).await
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        self.inner.release(lease).await
    }
}

/// Session-backend wrapper that delegates payload sealing to a remote KMS/HSM.
///
/// This is an opt-in alternative to [`EncryptingSessionBackend`]. The default
/// local-AEAD path is unchanged; consumers choose one seal mode per durable
/// store. Do not mix local-AEAD and remote-seal records in the same store:
/// they share the record/AAD metadata shape, but key custody differs and a
/// record written in one mode is not required to decrypt in the other.
///
/// Remote seal adds one KMS round-trip per seal (for example, each checkpoint,
/// normally off the hot path) and one KMS round-trip per unseal (each restored
/// session during failover), adding KMS latency and a KMS availability
/// dependency to restore.
#[derive(Clone)]
pub struct RemoteSealingSessionBackend<B: ?Sized, S: ?Sized> {
    inner: Arc<B>,
    provider: Arc<S>,
    backend_namespace: Arc<str>,
}

impl<B: ?Sized, S: ?Sized> RemoteSealingSessionBackend<B, S> {
    /// Wrap `inner` so every record payload is sealed by `provider` before
    /// persistence and unsealed on reads.
    pub fn new(inner: Arc<B>, provider: Arc<S>, backend_namespace: impl Into<String>) -> Self {
        Self {
            inner,
            provider,
            backend_namespace: Arc::<str>::from(backend_namespace.into()),
        }
    }

    /// The remote seal provider used for payload seal/unseal.
    pub fn provider(&self) -> &Arc<S> {
        &self.provider
    }

    /// The namespace string bound into every envelope's AAD.
    pub fn backend_namespace(&self) -> &str {
        &self.backend_namespace
    }
}

impl<B, S> RemoteSealingSessionBackend<B, S>
where
    B: SessionBackend + ?Sized,
    S: RemoteSealProvider + ?Sized,
{
    async fn seal_record(
        &self,
        mut record: StoredSessionRecord,
    ) -> Result<StoredSessionRecord, StoreError> {
        record.payload = EncryptedSessionPayload::remote_seal(
            self.provider.as_ref(),
            &record,
            self.backend_namespace(),
        )
        .await?;
        Ok(record)
    }

    async fn unseal_record(
        &self,
        mut record: StoredSessionRecord,
    ) -> Result<StoredSessionRecord, StoreError> {
        let plaintext = record
            .payload
            .remote_unseal(
                self.provider.as_ref(),
                &record.key,
                &record.state_type,
                record.generation,
                record.fence,
                self.backend_namespace(),
            )
            .await?;
        record.payload = EncryptedSessionPayload::new_zeroizing(plaintext);
        Ok(record)
    }

    async fn unseal_optional_record(
        &self,
        record: Option<StoredSessionRecord>,
    ) -> Result<Option<StoredSessionRecord>, StoreError> {
        match record {
            Some(record) => self.unseal_record(record).await.map(Some),
            None => Ok(None),
        }
    }

    async fn unseal_cas_result(
        &self,
        result: CompareAndSetResult,
    ) -> Result<CompareAndSetResult, StoreError> {
        match result {
            CompareAndSetResult::Success => Ok(CompareAndSetResult::Success),
            CompareAndSetResult::Conflict { current } => Ok(CompareAndSetResult::Conflict {
                current: self.unseal_optional_record(current).await?,
            }),
        }
    }

    async fn unseal_batch_result(&self, result: SessionOpResult) -> SessionOpResult {
        match result {
            SessionOpResult::Get(result) => SessionOpResult::Get(match result {
                Ok(record) => self.unseal_optional_record(record).await,
                Err(err) => Err(err),
            }),
            SessionOpResult::CompareAndSet(result) => {
                SessionOpResult::CompareAndSet(match result {
                    Ok(result) => self.unseal_cas_result(result).await,
                    Err(err) => Err(err),
                })
            }
            SessionOpResult::DeleteFenced(result) => SessionOpResult::DeleteFenced(result),
            SessionOpResult::RefreshTtl(result) => SessionOpResult::RefreshTtl(result),
        }
    }
}

async fn remote_unseal_record_helper<S: RemoteSealProvider + ?Sized>(
    provider: &S,
    mut record: StoredSessionRecord,
    backend_namespace: &str,
) -> Result<StoredSessionRecord, StoreError> {
    let plaintext = record
        .payload
        .remote_unseal(
            provider,
            &record.key,
            &record.state_type,
            record.generation,
            record.fence,
            backend_namespace,
        )
        .await?;
    record.payload = EncryptedSessionPayload::new_zeroizing(plaintext);
    Ok(record)
}

#[async_trait]
impl<B, S> SessionBackend for RemoteSealingSessionBackend<B, S>
where
    B: SessionBackend + 'static + ?Sized,
    S: RemoteSealProvider + 'static + ?Sized,
{
    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        self.inner.backend_instance_identity()
    }

    fn peer_binding(&self) -> Option<BackendPeerBinding> {
        self.inner.peer_binding()
    }

    async fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities().await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        let record = self.inner.get(key).await?;
        self.unseal_optional_record(record).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        let sealed_record = self.seal_record(op.new_record).await?;
        let result = self
            .inner
            .compare_and_set(CompareAndSet {
                key: op.key,
                lease: op.lease,
                expected_generation: op.expected_generation,
                new_record: sealed_record,
            })
            .await?;
        self.unseal_cas_result(result).await
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        self.inner.delete_fenced(lease).await
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        validate_session_ttl(ttl)?;
        self.inner.refresh_ttl(lease, ttl).await
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        validate_session_ops_ttls(&ops)?;
        if !self.inner.capabilities().await.batch_write {
            return Err(StoreError::CapabilityNotSupported("batch_write".into()));
        }

        let mut sealed_ops = Vec::with_capacity(ops.len());
        let mut slots = Vec::with_capacity(ops.len());
        for op in ops {
            match op {
                SessionOp::Get { key } => {
                    sealed_ops.push(SessionOp::Get { key });
                    slots.push(EncryptedBatchSlot::BackendResult);
                }
                SessionOp::CompareAndSet(cas) => match self.seal_record(cas.new_record).await {
                    Ok(new_record) => {
                        sealed_ops.push(SessionOp::CompareAndSet(CompareAndSet {
                            key: cas.key,
                            lease: cas.lease,
                            expected_generation: cas.expected_generation,
                            new_record,
                        }));
                        slots.push(EncryptedBatchSlot::BackendResult);
                    }
                    Err(err) => {
                        slots.push(EncryptedBatchSlot::SyntheticResult(Box::new(
                            SessionOpResult::CompareAndSet(Err(err)),
                        )));
                    }
                },
                SessionOp::DeleteFenced { lease } => {
                    sealed_ops.push(SessionOp::DeleteFenced { lease });
                    slots.push(EncryptedBatchSlot::BackendResult);
                }
                SessionOp::RefreshTtl { lease, ttl } => {
                    sealed_ops.push(SessionOp::RefreshTtl { lease, ttl });
                    slots.push(EncryptedBatchSlot::BackendResult);
                }
            }
        }

        let backend_results = if sealed_ops.is_empty() && !slots.is_empty() {
            Vec::new()
        } else {
            self.inner.batch(sealed_ops).await?
        };

        let mut backend_results = backend_results.into_iter();
        let mut unsealed = vec![None; slots.len()];
        let mut pending = Vec::new();
        for (index, slot) in slots.into_iter().enumerate() {
            match slot {
                EncryptedBatchSlot::BackendResult => {
                    let Some(result) = backend_results.next() else {
                        return Err(StoreError::BackendUnavailable(
                            "session batch returned fewer results than requested".into(),
                        ));
                    };
                    pending.push(async move { (index, self.unseal_batch_result(result).await) });
                }
                EncryptedBatchSlot::SyntheticResult(result) => unsealed[index] = Some(*result),
            }
        }

        if backend_results.next().is_some() {
            return Err(StoreError::BackendUnavailable(
                "session batch returned more results than requested".into(),
            ));
        }

        for (index, result) in join_all(pending).await {
            unsealed[index] = Some(result);
        }

        unsealed
            .into_iter()
            .map(|result| {
                result.ok_or_else(|| {
                    StoreError::BackendUnavailable(
                        "session batch returned fewer results than requested".into(),
                    )
                })
            })
            .collect()
    }

    async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        let mut page = self.inner.scan_restore_records(request).await?;
        let mut unsealed = Vec::with_capacity(page.records.len());
        for record in page.records {
            unsealed.push(self.unseal_record(record).await?);
        }
        page.records = unsealed;
        page.loaded_count = page.records.len();
        Ok(page)
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.inner.max_replication_sequence().await
    }

    async fn probe_replication_head(
        &self,
    ) -> Result<u64, crate::readiness::ReplicaReadinessFailure> {
        self.inner.probe_replication_head().await
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let entries =
            validate_replication_page_owned(self.inner.get_replication_log(start, limit).await?)?;
        let mut unsealed = Vec::with_capacity(entries.len());
        for entry in entries {
            unsealed.push(
                transform_replication_entry(entry, |record| self.unseal_record(record)).await?,
            );
        }
        Ok(unsealed)
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let entry = entry.into_validated()?;
        let entry = transform_replication_entry(entry, |record| self.seal_record(record)).await?;
        self.inner.replicate_entry(entry).await
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        let entries = validate_replication_prefix_owned(entries)?;
        let mut sealed = Vec::with_capacity(entries.len());
        for entry in entries {
            sealed
                .push(transform_replication_entry(entry, |record| self.seal_record(record)).await?);
        }
        self.inner.rebuild_replication_state(sealed).await
    }

    fn watch<'life0, 'async_trait>(
        &'life0 self,
        start_sequence: u64,
    ) -> std::pin::Pin<
        Box<
            dyn futures_util::Future<
                    Output = Result<
                        futures_util::stream::BoxStream<
                            'static,
                            Result<ReplicationEntry, StoreError>,
                        >,
                        StoreError,
                    >,
                > + Send
                + 'async_trait,
        >,
    >
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        let inner = self.inner.clone();
        let provider = self.provider.clone();
        let backend_namespace = self.backend_namespace.clone();
        Box::pin(async move {
            let stream = inner.watch(start_sequence).await?;
            use futures_util::StreamExt;
            let stream = stream.then(move |res| {
                let provider = provider.clone();
                let backend_namespace = backend_namespace.clone();
                async move {
                    match res {
                        Ok(entry) => {
                            let entry = entry.into_validated()?;
                            transform_replication_entry(entry, |record| {
                                remote_unseal_record_helper(
                                    provider.as_ref(),
                                    record,
                                    &backend_namespace,
                                )
                            })
                            .await
                        }
                        Err(e) => Err(e),
                    }
                }
            });
            Ok(stream.boxed())
        })
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        self.inner.next_lease_info().await
    }
}

#[async_trait]
impl<B, S> SessionLeaseManager for RemoteSealingSessionBackend<B, S>
where
    B: SessionLeaseManager + Send + Sync + ?Sized,
    S: RemoteSealProvider + ?Sized,
{
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: crate::model::OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        self.inner.acquire(key, owner, ttl).await
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        self.inner.renew(lease, ttl).await
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        self.inner.release(lease).await
    }
}
