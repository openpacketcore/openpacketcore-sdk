//! Deterministic in-memory test double for the storage and lease APIs.
//!
//! `FakeSessionBackend` implements the full `SessionBackend` and
//! `SessionLeaseManager` contracts — fenced CAS, lease lifecycle, TTL
//! pruning, the ordered replication log, and watch streams — entirely in
//! process. Combined with `TokioVirtualClock` it lets split-brain, stale
//! fence, lease-expiry, and quorum scenarios run deterministically without
//! I/O or real waiting. Suitable for tests and single-replica development
//! only; nothing is persisted.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use opc_types::Timestamp;
use tokio::sync::Mutex;

use crate::{
    backend::{
        next_replication_sequence, validate_replication_log_page_owned,
        validate_replication_prefix, validate_replication_prefix_owned, validate_session_ops_at,
        BackendInstanceIdentity, CompareAndSet, CompareAndSetResult,
        ProtectedRosterEstablishedSuccessor, ReplicationEntry, ReplicationLogRange, ReplicationOp,
        ReplicationTxId, ReplicationWatchCursor, SessionBackend, SessionOp, SessionOpResult,
        MAX_REPLICATION_WATCH_BACKLOG_ENTRIES,
    },
    capability::BackendCapabilities,
    clock::{Clock, TokioVirtualClock},
    error::{LeaseError, StoreError},
    lease::{LeaseGuard, SessionLeaseManager},
    model::{FenceToken, OwnerId, SessionKey, SessionKeyType, StableId},
    record::StoredSessionRecord,
    replication_watch::{prepare_watch_registration, ReplicationWatcher},
    restore::{
        compare_restore_records, restore_record_retained_bytes, RestoreScanCursor, RestoreScanPage,
        RestoreScanRequest, RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES,
        RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES,
    },
    ttl::{checked_session_deadline, validate_session_ttl, validate_stored_record_expiry_at},
};

#[cfg(feature = "lab-memory")]
mod lab;
mod read_expiry;

/// In-memory session backend and lease manager for deterministic tests.
///
/// `Clone` is cheap (Arc) so multiple tasks can share the same logical backend.
#[derive(Clone)]
pub struct FakeSessionBackend {
    inner: Arc<Mutex<FakeBackendState>>,
    caps: BackendCapabilities,
    limits: FakeBackendLimits,
    clock: Arc<dyn Clock>,
    // Shared by clones, but never consulted by command execution or replay.
    read_expiry: Arc<std::sync::Mutex<read_expiry::ReadExpiry>>,
    // Writer attempts retain their application clock without publishing data.
    // Reads and preflights never sample or advance this clock.
    writer_time: Arc<std::sync::Mutex<Option<Timestamp>>>,
    #[cfg(feature = "lab-memory")]
    lab_identity: Option<[u8; 32]>,
    #[cfg(feature = "lab-memory")]
    lab_restore_authority: Option<Arc<lab::RestoreAuthority>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingReplayCommand {
    // Shared persistent root; at most the previously admitted tracked-key bound.
    // It survives at most 255 contiguous effects, then releases the old history.
    fences: imbl::HashMap<FakeMapKey, FenceToken>,
    floor_prev: u64,
    remaining: u16,
    id: [u8; 16],
    async_fence_floor: u64,
    timestamp: Timestamp,
}

struct FakeBackendState {
    records: imbl::OrdMap<FakeMapKey, StoredSessionRecord>,
    leases: imbl::HashMap<FakeMapKey, LeaseEntry>,
    key_fences: imbl::HashMap<FakeMapKey, FenceToken>,
    key_retention: crate::key_retention::KeyRetention,
    async_fence_floor: u64,
    internal_key_count: u32,
    pending_replay_command: Option<PendingReplayCommand>,
    retired_keys: imbl::HashMap<FakeMapKey, u64>,
    retired_index: imbl::OrdSet<(u64, FakeMapKey)>,
    retirement_candidates: imbl::OrdSet<FakeMapKey>,
    committed_time: Option<Timestamp>,
    next_fence: u64,
    next_credential_id: u64,
    compacted_replication_sequence: u64,
    last_replication_sequence: u64,
    replication_log: imbl::Vector<ReplicationEntry>,
    watchers: Vec<ReplicationWatcher>,
    #[cfg(feature = "lab-memory")]
    lab_transitions: imbl::HashMap<crate::FencedTransitionRequestId, lab::Receipt>,
    #[cfg(feature = "lab-memory")]
    lab_restore_revision: u64,
}

/// Canonical raw tuple used for fake-backend lookup and restore ordering.
///
/// A typed tuple avoids the delimiter-ordering and collision hazards of a
/// formatted string while retaining the same private in-memory lookup role.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct FakeMapKey {
    tenant: String,
    nf_kind: String,
    key_type: SessionKeyType,
    stable_id: StableId,
}

impl FakeBackendState {
    fn empty() -> Self {
        Self {
            records: imbl::OrdMap::new(),
            leases: imbl::HashMap::new(),
            key_fences: imbl::HashMap::new(),
            key_retention: crate::key_retention::KeyRetention::default(),
            async_fence_floor: 0,
            internal_key_count: 0,
            pending_replay_command: None,
            retired_keys: imbl::HashMap::new(),
            retired_index: imbl::OrdSet::new(),
            retirement_candidates: imbl::OrdSet::new(),
            committed_time: None,
            next_fence: 1,
            next_credential_id: 1,
            compacted_replication_sequence: 0,
            last_replication_sequence: 0,
            replication_log: imbl::Vector::new(),
            watchers: Vec::new(),
            #[cfg(feature = "lab-memory")]
            lab_transitions: imbl::HashMap::new(),
            #[cfg(feature = "lab-memory")]
            lab_restore_revision: 0,
        }
    }

    fn stage_data(&self) -> Self {
        Self {
            records: self.records.clone(),
            leases: self.leases.clone(),
            key_fences: self.key_fences.clone(),
            key_retention: self.key_retention,
            async_fence_floor: self.async_fence_floor,
            internal_key_count: self.internal_key_count,
            pending_replay_command: self.pending_replay_command.clone(),
            retired_keys: self.retired_keys.clone(),
            retired_index: self.retired_index.clone(),
            retirement_candidates: self.retirement_candidates.clone(),
            committed_time: self.committed_time,
            next_fence: self.next_fence,
            next_credential_id: self.next_credential_id,
            compacted_replication_sequence: self.compacted_replication_sequence,
            last_replication_sequence: self.last_replication_sequence,
            replication_log: self.replication_log.clone(),
            watchers: Vec::new(),
            #[cfg(feature = "lab-memory")]
            lab_transitions: self.lab_transitions.clone(),
            #[cfg(feature = "lab-memory")]
            lab_restore_revision: self.lab_restore_revision,
        }
    }

    fn commit_staged_data(&mut self, mut staged: Self) {
        #[cfg(feature = "lab-memory")]
        {
            // Imports cannot restore an earlier revision; lease-only changes
            // leave an existing record scan valid.
            staged.lab_restore_revision =
                staged
                    .lab_restore_revision
                    .max(self.lab_restore_revision.saturating_add(u64::from(
                        self.records.diff(&staged.records).next().is_some(),
                    )));
        }
        staged.watchers = std::mem::take(&mut self.watchers);
        *self = staged;
    }

    #[cfg(feature = "lab-memory")]
    fn invalidate_lab_restore_snapshot(&mut self) {
        // Exhaustion permanently disables scans rather than reusing a revision.
        self.lab_restore_revision = self.lab_restore_revision.saturating_add(1);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LeaseEntry {
    active: bool,
    credential_id: u64,
    owner: OwnerId,
    fence: FenceToken,
    /// The lease issuance time is distinct from its renewable expiry. The
    /// protected-roster replication command authenticates both fields.
    acquired_at: Timestamp,
    expires_at: Timestamp,
    guard_expires_at: Timestamp,
}

/// Resource limits for the deterministic in-memory backend.
///
/// `max_tracked_keys` bounds the union of session records, leases, and fence
/// floors, including the bounded exact window of recently retired keys.
/// Live and recently dead keys retain their own fences. Dead history is
/// reclaimed by rotating that window inside a successful committing command;
/// capacity is refused when live or otherwise non-retirable rows fill the limit.
/// Capacity decisions travel in [`crate::ReplicationReplayPolicy`]. A
/// replica replays those rotations and refuses an entry atomically if its local
/// limit cannot hold the committed result. Rebuild follows the same rule.
/// `max_replication_entries` bounds retained log history; older committed entries are compacted from the
/// in-memory log while the maximum sequence still advances monotonically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FakeBackendLimits {
    /// Maximum number of distinct session keys the fake will track.
    pub max_tracked_keys: usize,
    /// Maximum number of committed replication entries retained in memory.
    pub max_replication_entries: usize,
}

impl Default for FakeBackendLimits {
    fn default() -> Self {
        Self {
            max_tracked_keys: 1_000_000,
            max_replication_entries: 1_000_000,
        }
    }
}

impl FakeSessionBackend {
    const PROTECTED_ROSTER_PROFILE_V2_CAPABILITY: &'static str =
        "protected_roster_profile_v2_not_activated";

    /// Create a new fake backend with all capabilities enabled.
    pub fn new() -> Self {
        Self::with_capabilities(BackendCapabilities::all_enabled())
    }

    /// Create a new fake backend with a specific capability set.
    pub fn with_capabilities(caps: BackendCapabilities) -> Self {
        Self::with_capabilities_and_limits(caps, FakeBackendLimits::default())
    }

    /// Create a new fake backend with all capabilities and explicit resource limits.
    pub fn with_limits(limits: FakeBackendLimits) -> Self {
        Self::with_capabilities_and_limits(BackendCapabilities::all_enabled(), limits)
    }

    /// Create a new fake backend with a specific capability set and resource limits.
    pub fn with_capabilities_and_limits(
        caps: BackendCapabilities,
        limits: FakeBackendLimits,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FakeBackendState::empty())),
            caps,
            limits,
            clock: Arc::new(TokioVirtualClock::new()),
            read_expiry: Arc::new(std::sync::Mutex::new(read_expiry::ReadExpiry::default())),
            writer_time: Arc::new(std::sync::Mutex::new(None)),
            #[cfg(feature = "lab-memory")]
            lab_identity: None,
            #[cfg(feature = "lab-memory")]
            lab_restore_authority: None,
        }
    }

    /// Replace the default tokio-virtual-time clock.
    ///
    /// The clock decides record TTL expiry, lease expiry, and pruning. Share
    /// one clock instance across the backends and coordinators under test so
    /// "owner pauses past its lease TTL" scenarios stay coherent. Local expiry
    /// observations survive a clock rewind until the observed record changes.
    /// Writes clamp their own sample by prior writer attempts and committed time.
    /// Replication uses each committed entry's time.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    fn command_time(&self, state: &FakeBackendState) -> Timestamp {
        let sampled = self.clock.now_utc();
        let mut executed = self
            .writer_time
            .lock()
            .expect("fake command clock remains available");
        let now = state
            .committed_time
            .into_iter()
            .chain(*executed)
            .fold(sampled, Timestamp::max);
        *executed = Some(now);
        now
    }

    #[cfg(all(test, feature = "lab-memory"))]
    pub(crate) async fn key_retention_for_test(
        &self,
    ) -> (crate::key_retention::KeyRetention, usize, usize) {
        let state = self.inner.lock().await;
        (
            state.key_retention,
            state.key_fences.len(),
            state.retired_keys.len(),
        )
    }

    /// Return the canonical composite key for bounded map lookups.
    fn map_key(key: &SessionKey) -> FakeMapKey {
        FakeMapKey {
            tenant: key.tenant.as_str().to_owned(),
            nf_kind: key.nf_kind.as_str().to_owned(),
            key_type: key.key_type.clone(),
            stable_id: key.stable_id.clone(),
        }
    }

    /// Get the current recorded fence for a key.
    fn current_fence(state: &FakeBackendState, map_key: &FakeMapKey) -> FenceToken {
        let fence = state.key_fences.get(map_key).map_or_else(
            || {
                if Self::scope_key(map_key) {
                    0
                } else {
                    state.key_retention.observed_absent_fence(0)
                }
            },
            |fence| fence.get(),
        );
        FenceToken::new(fence.max(state.async_fence_floor))
    }

    fn scope_key(key: &FakeMapKey) -> bool {
        crate::scope_storage::RESERVED_KEY_TYPES.contains(&key.key_type.as_str())
    }

    fn set_fence(state: &mut FakeBackendState, key: FakeMapKey, fence: FenceToken) {
        state.key_fences.insert(key.clone(), fence);
        if state.records.contains_key(&key) || state.leases.contains_key(&key) {
            if let Some(epoch) = state.retired_keys.remove(&key) {
                state.retired_index.remove(&(epoch, key.clone()));
            }
        }
        state.retirement_candidates.insert(key);
    }

    fn ensure_key_capacity(
        state: &FakeBackendState,
        map_key: &FakeMapKey,
        max_tracked_keys: usize,
    ) -> Result<(), StoreError> {
        if state.key_fences.contains_key(map_key)
            || state
                .key_fences
                .len()
                .saturating_add(state.internal_key_count as usize)
                < max_tracked_keys
        {
            return Ok(());
        }
        // Permit temporary staging only when dead history can make room at
        // command finalization. Do not rotate between Batch children.
        let pending_dead = state
            .retirement_candidates
            .iter()
            .filter(|key| {
                !Self::scope_key(key)
                    && !state.retired_keys.contains_key(*key)
                    && !state.records.contains_key(*key)
                    && !state.leases.contains_key(*key)
                    && state
                        .key_fences
                        .get(*key)
                        .is_some_and(|fence| fence.get() < state.next_fence)
            })
            .count();
        let live = state
            .key_fences
            .len()
            .checked_sub(state.retired_keys.len())
            .and_then(|count| count.checked_sub(pending_dead))
            .ok_or_else(|| {
                StoreError::BackendUnavailable("fake key capacity index differs".into())
            })?;
        if live.saturating_add(state.internal_key_count as usize) < max_tracked_keys {
            return Ok(());
        }
        Err(StoreError::BackendUnavailable(
            "fake backend tracked-key limit reached".into(),
        ))
    }

    fn get_with_state(
        state: &FakeBackendState,
        key: &SessionKey,
        now: Timestamp,
    ) -> Option<StoredSessionRecord> {
        let mk = Self::map_key(key);
        state
            .records
            .get(&mk)
            .filter(|r| !r.is_expired_at(now))
            .cloned()
    }

    fn notify_watchers(state: &mut FakeBackendState, entry: &ReplicationEntry) {
        state.watchers.retain_mut(|watcher| watcher.notify(entry));
    }

    fn apply_visible_recovery_boundary(state: &mut FakeBackendState, entry: &ReplicationEntry) {
        if matches!(
            entry.replay_policy.recovery,
            crate::ReplicationRecoveryBoundary::Recover { .. }
        ) {
            state.replication_log.clear();
            state.compacted_replication_sequence = entry.replay_policy.async_fence_floor;
        }
    }

    fn compact_replication_log(state: &mut FakeBackendState, max_replication_entries: usize) {
        if state.replication_log.len() <= max_replication_entries {
            return;
        }

        if max_replication_entries == 0 {
            if let Some(entry) = state.replication_log.back() {
                state.compacted_replication_sequence =
                    state.compacted_replication_sequence.max(entry.sequence);
            }
            state.replication_log.clear();
            return;
        }

        let drop_count = state.replication_log.len() - max_replication_entries;
        let compacted_sequence = state.replication_log[drop_count - 1].sequence;
        for _ in 0..drop_count {
            state.replication_log.pop_front();
        }
        state.compacted_replication_sequence =
            state.compacted_replication_sequence.max(compacted_sequence);
    }

    fn prune_state(state: &mut FakeBackendState, now: Timestamp) {
        #[cfg(feature = "lab-memory")]
        let previous_records = state.records.len();
        let expired: Vec<_> = state
            .records
            .iter()
            .filter(|(_, record)| record.is_expired_at(now))
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            Self::apply_async_floor_to_key(state, &key);
            state.records.remove(&key);
            state.retirement_candidates.insert(key);
        }
        #[cfg(feature = "lab-memory")]
        if state.records.len() != previous_records {
            state.invalidate_lab_restore_snapshot();
        }
        let expired: Vec<_> = state
            .leases
            .iter()
            .filter(|(_, entry)| !entry.active || entry.expires_at <= now)
            .map(|(key, _)| key.clone())
            .collect();
        for key in expired {
            Self::apply_async_floor_to_key(state, &key);
            state.leases.remove(&key);
            state.retirement_candidates.insert(key);
        }
    }

    fn apply_async_floor_to_key(state: &mut FakeBackendState, key: &FakeMapKey) {
        if let Some(fence) = state.key_fences.get_mut(key) {
            *fence = FenceToken::new(fence.get().max(state.async_fence_floor));
        }
        if let Some(lease) = state.leases.get_mut(key) {
            if lease.fence.get() <= state.async_fence_floor
                || lease.credential_id <= state.async_fence_floor
            {
                lease.active = false;
            }
        }
    }

    fn retire_dead_keys(state: &mut FakeBackendState) -> Result<(), StoreError> {
        // Finalization happens once per successful command, after all children.
        let mut candidates: Vec<_> = std::mem::take(&mut state.retirement_candidates)
            .into_iter()
            .collect();
        candidates.sort_unstable_by(|left, right| {
            crate::key_retention::compare_key_parts(
                (
                    &left.tenant,
                    &left.nf_kind,
                    &left.key_type,
                    left.stable_id.as_bytes(),
                ),
                (
                    &right.tenant,
                    &right.nf_kind,
                    &right.key_type,
                    right.stable_id.as_bytes(),
                ),
            )
        });
        for key in candidates {
            if state.records.contains_key(&key) || state.leases.contains_key(&key) {
                if let Some(epoch) = state.retired_keys.remove(&key) {
                    state.retired_index.remove(&(epoch, key));
                }
                continue;
            }
            if Self::scope_key(&key) || state.retired_keys.contains_key(&key) {
                continue;
            }
            let Some(fence) = state.key_fences.get(&key).copied() else {
                continue;
            };
            if fence.get() >= state.next_fence {
                continue;
            }
            state.key_retention.retired_count = state
                .key_retention
                .retired_count
                .checked_add(1)
                .ok_or(StoreError::FencedTransitionStorageExhausted)?;
            state.key_retention.retired_max = state.key_retention.retired_max.max(fence.get());
            let epoch = state.key_retention.epoch;
            state.retired_keys.insert(key.clone(), epoch);
            state.retired_index.insert((epoch, key));
            if state.key_retention.retired_count == crate::key_retention::RETIRED_KEYS_PER_EPOCH {
                Self::rotate_keys(state, crate::key_retention::RotationReason::Threshold)?;
            }
        }
        Ok(())
    }

    fn finalize_key_capacity(
        state: &mut FakeBackendState,
        maximum: usize,
    ) -> Result<u8, StoreError> {
        let mut rotations = 0;
        while state
            .key_fences
            .len()
            .saturating_add(state.internal_key_count as usize)
            > maximum
        {
            if state.retired_keys.is_empty() {
                return Err(StoreError::BackendUnavailable(
                    "fake backend tracked-key limit reached".into(),
                ));
            }
            Self::rotate_keys(state, crate::key_retention::RotationReason::Capacity)?;
            rotations += 1;
        }
        Ok(rotations)
    }

    fn rotate_keys(
        state: &mut FakeBackendState,
        reason: crate::key_retention::RotationReason,
    ) -> Result<(), StoreError> {
        Self::rotate_keys_with_floor(state, reason, state.async_fence_floor)
    }

    fn rotate_keys_with_floor(
        state: &mut FakeBackendState,
        reason: crate::key_retention::RotationReason,
        async_floor: u64,
    ) -> Result<(), StoreError> {
        let through =
            state
                .key_retention
                .rotate(&mut state.next_fence, u64::MAX, async_floor, reason)?;
        if let Some(through) = through {
            while let Some((epoch, key)) = state
                .retired_index
                .get_min()
                .filter(|(epoch, _)| *epoch <= through)
                .cloned()
            {
                if state.retired_keys.get(&key) != Some(&epoch)
                    || state
                        .key_fences
                        .get(&key)
                        .is_none_or(|fence| fence.get() >= state.key_retention.floor_prev)
                {
                    return Err(StoreError::BackendUnavailable(
                        "fake exact retirement index differs".into(),
                    ));
                }
                state.retired_index.remove(&(epoch, key.clone()));
                state.retired_keys.remove(&key);
                state.key_fences.remove(&key);
            }
        }
        Ok(())
    }

    fn validate_fenced_mutation(
        state: &FakeBackendState,
        lease: &LeaseGuard,
        now: Timestamp,
    ) -> Result<FakeMapKey, StoreError> {
        let map_key = Self::map_key(lease.key());
        // A retired missing key has no newer owner. Its global absent floor
        // must not mask expiry; a tracked key still keeps stale-fence priority.
        if lease.expires_at() <= now && !state.key_fences.contains_key(&map_key) {
            return Err(StoreError::LeaseExpired);
        }

        let current_fence = Self::current_fence(state, &map_key);
        if lease.fence() < current_fence {
            return Err(StoreError::StaleFence);
        }
        if lease.expires_at() <= now {
            return Err(StoreError::LeaseExpired);
        }

        let Some(entry) = state.leases.get(&map_key) else {
            return Err(StoreError::StaleFence);
        };

        if !entry.active {
            return Err(StoreError::StaleFence);
        }
        if entry.credential_id != lease.credential_id() {
            return Err(StoreError::StaleFence);
        }
        if entry.owner != *lease.owner() {
            return Err(StoreError::StaleFence);
        }
        if entry.fence != lease.fence() {
            return Err(StoreError::StaleFence);
        }
        if entry.guard_expires_at != lease.expires_at() {
            return Err(StoreError::StaleFence);
        }

        if lease.expires_at() <= now {
            return Err(StoreError::LeaseExpired);
        }
        if entry.expires_at <= now {
            return Err(StoreError::LeaseExpired);
        }

        Ok(map_key)
    }

    fn compare_and_set_with_state(
        &self,
        state: &mut FakeBackendState,
        op: CompareAndSet,
        now: Timestamp,
    ) -> Result<CompareAndSetResult, StoreError> {
        #[cfg(feature = "lab-memory")]
        state.invalidate_lab_restore_snapshot();
        validate_stored_record_expiry_at(&op.new_record, now)?;
        if !self.caps.atomic_compare_and_set {
            return Err(StoreError::CapabilityNotSupported(
                "atomic_compare_and_set".into(),
            ));
        }
        if !self.caps.monotonic_fencing_token {
            return Err(StoreError::CapabilityNotSupported(
                "monotonic_fencing_token".into(),
            ));
        }
        if op.lease.key() != &op.key {
            return Err(StoreError::InvalidKey(
                "compare-and-set key does not match lease key".into(),
            ));
        }
        if op.new_record.key != op.key {
            return Err(StoreError::InvalidKey(
                "compare-and-set key does not match record key".into(),
            ));
        }
        if op.new_record.owner != *op.lease.owner() || op.new_record.fence != op.lease.fence() {
            return Err(StoreError::StaleFence);
        }
        if op.new_record.payload.len() > self.caps.max_value_bytes {
            return Err(StoreError::PayloadTooLarge {
                actual: op.new_record.payload.len(),
                max: self.caps.max_value_bytes,
            });
        }

        let mk = Self::validate_fenced_mutation(state, &op.lease, now)?;
        let current_fence = Self::current_fence(state, &mk);

        if op.lease.fence() < current_fence {
            return Err(StoreError::StaleFence);
        }
        Self::ensure_key_capacity(state, &mk, self.limits.max_tracked_keys)?;

        let existing = state
            .records
            .get(&mk)
            .filter(|r| !r.is_expired_at(now))
            .cloned();

        match (op.expected_generation, existing) {
            (None, None) => {
                state.records.insert(mk.clone(), op.new_record.clone());
                Self::set_fence(state, mk, op.lease.fence());
                Ok(CompareAndSetResult::Success)
            }
            (Some(expected), Some(current)) => {
                if current.generation != expected {
                    return Ok(CompareAndSetResult::Conflict {
                        current: Some(current),
                    });
                }
                if (current.state_class.requires_monotonic_generation()
                    || op.new_record.state_class.requires_monotonic_generation())
                    && op.new_record.generation <= current.generation
                {
                    return Ok(CompareAndSetResult::Conflict {
                        current: Some(current),
                    });
                }
                state.records.insert(mk.clone(), op.new_record.clone());
                Self::set_fence(state, mk, op.lease.fence());
                Ok(CompareAndSetResult::Success)
            }
            (None, Some(current)) => Ok(CompareAndSetResult::Conflict {
                current: Some(current),
            }),
            (Some(_), None) => Ok(CompareAndSetResult::Conflict { current: None }),
        }
    }

    fn delete_fenced_with_state(
        &self,
        state: &mut FakeBackendState,
        lease: &LeaseGuard,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        if !self.caps.monotonic_fencing_token {
            return Err(StoreError::CapabilityNotSupported(
                "monotonic_fencing_token".into(),
            ));
        }

        let mk = Self::validate_fenced_mutation(state, lease, now)?;
        let current_fence = Self::current_fence(state, &mk);

        if lease.fence() < current_fence {
            return Err(StoreError::StaleFence);
        }
        Self::ensure_key_capacity(state, &mk, self.limits.max_tracked_keys)?;

        if state.records.remove(&mk).is_some() {
            #[cfg(feature = "lab-memory")]
            state.invalidate_lab_restore_snapshot();
        }
        Self::set_fence(state, mk, lease.fence());
        Ok(())
    }

    fn refresh_ttl_with_state(
        &self,
        state: &mut FakeBackendState,
        lease: &LeaseGuard,
        ttl: Duration,
        now: Timestamp,
    ) -> Result<Timestamp, StoreError> {
        #[cfg(feature = "lab-memory")]
        state.invalidate_lab_restore_snapshot();
        let expires_at = checked_session_deadline(now, ttl)?;
        if !self.caps.per_key_ttl {
            return Err(StoreError::CapabilityNotSupported("per_key_ttl".into()));
        }
        if !self.caps.monotonic_fencing_token {
            return Err(StoreError::CapabilityNotSupported(
                "monotonic_fencing_token".into(),
            ));
        }

        let mk = Self::validate_fenced_mutation(state, lease, now)?;
        let current_fence = Self::current_fence(state, &mk);

        if lease.fence() < current_fence {
            return Err(StoreError::StaleFence);
        }
        Self::ensure_key_capacity(state, &mk, self.limits.max_tracked_keys)?;

        let Some(record) = state.records.get_mut(&mk) else {
            return Err(StoreError::NotFound);
        };

        if record.is_expired_at(now) {
            return Err(StoreError::NotFound);
        }

        record.expires_at = Some(expires_at);
        Self::set_fence(state, mk, lease.fence());
        Ok(expires_at)
    }

    fn apply_replicated_op_with_state(
        state: &mut FakeBackendState,
        op: ReplicationOp,
        now: Timestamp,
        max_tracked_keys: usize,
    ) -> Result<(), StoreError> {
        #[cfg(feature = "lab-memory")]
        if matches!(
            &op,
            ReplicationOp::CompareAndSet { .. } | ReplicationOp::RefreshTtl { .. }
        ) {
            state.invalidate_lab_restore_snapshot();
        }
        if Self::contains_protected_roster_established_create(&op) {
            return Err(StoreError::CapabilityNotSupported(
                Self::PROTECTED_ROSTER_PROFILE_V2_CAPABILITY.into(),
            ));
        }
        match op {
            ReplicationOp::CompareAndSet {
                key,
                expected_generation,
                credential_id,
                guard_expires_at,
                new_record,
            } => {
                let mk = Self::map_key(&key);
                let current_fence = Self::current_fence(state, &mk);
                if new_record.fence < current_fence {
                    return Err(StoreError::StaleFence);
                }
                Self::ensure_key_capacity(state, &mk, max_tracked_keys)?;

                let Some(lease_entry) = state.leases.get(&mk) else {
                    return Err(StoreError::StaleFence);
                };
                if !lease_entry.active
                    || lease_entry.credential_id != credential_id
                    || lease_entry.owner != new_record.owner
                    || lease_entry.fence != new_record.fence
                    || lease_entry.guard_expires_at != guard_expires_at
                {
                    return Err(StoreError::StaleFence);
                }
                if guard_expires_at <= now || lease_entry.expires_at <= now {
                    return Err(StoreError::LeaseExpired);
                }

                let existing = Self::get_with_state(state, &key, now);
                match (expected_generation, existing) {
                    (None, None) => {
                        state.records.insert(mk.clone(), new_record.clone());
                        Self::set_fence(state, mk, new_record.fence);
                        Ok(())
                    }
                    (Some(expected), Some(current)) => {
                        if current.generation != expected {
                            return Err(StoreError::CasConflict);
                        }
                        if (current.state_class.requires_monotonic_generation()
                            || new_record.state_class.requires_monotonic_generation())
                            && new_record.generation <= current.generation
                        {
                            return Err(StoreError::CasConflict);
                        }
                        state.records.insert(mk.clone(), new_record.clone());
                        Self::set_fence(state, mk, new_record.fence);
                        Ok(())
                    }
                    _ => Err(StoreError::CasConflict),
                }
            }
            ReplicationOp::DeleteFenced { key, owner, fence } => {
                let mk = Self::map_key(&key);
                Self::validate_replicated_owner(state, &mk, &owner, fence)?;
                Self::ensure_key_capacity(state, &mk, max_tracked_keys)?;
                if state.records.remove(&mk).is_some() {
                    #[cfg(feature = "lab-memory")]
                    state.invalidate_lab_restore_snapshot();
                }
                Self::set_fence(state, mk, fence);
                state.next_fence = state.next_fence.max(fence.get().saturating_add(1));
                Ok(())
            }
            ReplicationOp::RefreshTtl {
                key,
                owner,
                fence,
                ttl: _,
                expires_at,
            } => {
                let mk = Self::map_key(&key);
                Self::validate_replicated_owner(state, &mk, &owner, fence)?;
                Self::ensure_key_capacity(state, &mk, max_tracked_keys)?;
                if let Some(record) = state.records.get_mut(&mk) {
                    record.expires_at = Some(expires_at);
                    Self::set_fence(state, mk, fence);
                    state.next_fence = state.next_fence.max(fence.get().saturating_add(1));
                    Ok(())
                } else {
                    Err(StoreError::NotFound)
                }
            }
            ReplicationOp::AcquireLease {
                key,
                owner,
                fence,
                credential_id,
                ttl: _,
                expires_at,
            } => {
                let mk = Self::map_key(&key);
                Self::apply_async_floor_to_key(state, &mk);
                let previous = state
                    .key_fences
                    .get(&mk)
                    .or_else(|| {
                        state
                            .pending_replay_command
                            .as_ref()
                            .and_then(|pending| pending.fences.get(&mk))
                    })
                    .map_or(
                        if Self::scope_key(&mk) {
                            0
                        } else {
                            state
                                .pending_replay_command
                                .as_ref()
                                .map_or(state.key_retention.floor_prev, |pending| {
                                    pending.floor_prev
                                })
                        },
                        |current| current.get(),
                    );
                let previous = previous.max(state.async_fence_floor);
                if fence.get() <= previous {
                    return Err(StoreError::StaleFence);
                }
                Self::ensure_key_capacity(state, &mk, max_tracked_keys)?;
                if let Some(entry) = state.leases.get(&mk) {
                    if entry.active && entry.owner != owner && entry.expires_at > now {
                        return Err(StoreError::LeaseHeld);
                    }
                }
                state.leases.insert(
                    mk.clone(),
                    LeaseEntry {
                        active: true,
                        credential_id,
                        owner,
                        fence,
                        acquired_at: now,
                        expires_at,
                        guard_expires_at: expires_at,
                    },
                );
                Self::set_fence(state, mk, fence);
                state.next_fence = state.next_fence.max(fence.get() + 1);
                state.next_credential_id = state.next_credential_id.max(credential_id + 1);
                Ok(())
            }
            ReplicationOp::RenewLease {
                key,
                owner,
                fence,
                credential_id,
                ttl: _,
                expires_at,
            } => {
                let mk = Self::map_key(&key);
                Self::validate_replicated_owner(state, &mk, &owner, fence)?;
                let entry = state.leases.get(&mk).ok_or(StoreError::StaleFence)?;
                if entry.credential_id != credential_id {
                    return Err(StoreError::StaleFence);
                }
                let acquired_at = entry.acquired_at;
                Self::ensure_key_capacity(state, &mk, max_tracked_keys)?;
                state.leases.insert(
                    mk.clone(),
                    LeaseEntry {
                        active: true,
                        credential_id,
                        owner,
                        fence,
                        acquired_at,
                        expires_at,
                        guard_expires_at: expires_at,
                    },
                );
                Self::set_fence(state, mk, fence);
                state.next_fence = state.next_fence.max(fence.get() + 1);
                state.next_credential_id = state.next_credential_id.max(credential_id + 1);
                Ok(())
            }
            ReplicationOp::ReleaseLease {
                key,
                owner,
                fence,
                credential_id,
            } => {
                let mk = Self::map_key(&key);
                Self::validate_replicated_owner(state, &mk, &owner, fence)?;
                let entry = state.leases.get_mut(&mk).ok_or(StoreError::StaleFence)?;
                if entry.credential_id != credential_id {
                    return Err(StoreError::StaleFence);
                }
                entry.active = false;
                // Match the committed release: preserve physical lease expiry,
                // while the guard deadline records the release timestamp.
                entry.guard_expires_at = now;
                Self::ensure_key_capacity(state, &mk, max_tracked_keys)?;
                Self::set_fence(state, mk, fence);
                state.next_fence = state.next_fence.max(fence.get().saturating_add(1));
                Ok(())
            }
            ReplicationOp::ProtectedRosterEstablished {
                key,
                expected_record,
                successor,
                owner,
                fence,
                credential_id,
                guard_acquired_at,
                guard_expires_at,
            } => {
                // This cannot reuse generic CAS: recovery can establish the
                // terminal under a higher current guard while the immutable
                // admitted row deliberately retains its original provenance.
                if expected_record.key != key
                    || expected_record.expires_at.is_some()
                    || credential_id == 0
                    || guard_expires_at <= guard_acquired_at
                    || fence < expected_record.fence
                {
                    return Err(StoreError::StaleFence);
                }
                let mk = Self::map_key(&key);
                let current_fence = Self::current_fence(state, &mk);
                if current_fence > fence {
                    return Err(StoreError::StaleFence);
                }
                Self::ensure_key_capacity(state, &mk, max_tracked_keys)?;
                let Some(lease_entry) = state.leases.get(&mk) else {
                    return Err(StoreError::StaleFence);
                };
                if !lease_entry.active
                    || lease_entry.credential_id != credential_id
                    || lease_entry.owner != owner
                    || lease_entry.fence != fence
                    || lease_entry.acquired_at != guard_acquired_at
                    || lease_entry.guard_expires_at != guard_expires_at
                {
                    return Err(StoreError::StaleFence);
                }
                if guard_expires_at <= now || lease_entry.expires_at <= now {
                    return Err(StoreError::LeaseExpired);
                }
                if state.records.get(&mk) != Some(&expected_record) {
                    return Err(StoreError::CasConflict);
                }

                match *successor {
                    ProtectedRosterEstablishedSuccessor::Put { record } => {
                        if record.key != key
                            || record.expires_at.is_some()
                            || record.owner != expected_record.owner
                            || record.fence != expected_record.fence
                            || record.generation <= expected_record.generation
                        {
                            return Err(StoreError::CasConflict);
                        }
                        state.records.insert(mk.clone(), *record);
                        #[cfg(feature = "lab-memory")]
                        state.invalidate_lab_restore_snapshot();
                    }
                    ProtectedRosterEstablishedSuccessor::Delete => {
                        if state.records.remove(&mk).is_none() {
                            return Err(StoreError::CasConflict);
                        }
                        #[cfg(feature = "lab-memory")]
                        state.invalidate_lab_restore_snapshot();
                    }
                    ProtectedRosterEstablishedSuccessor::NoOp => {}
                }
                Self::set_fence(state, mk, fence);
                state.next_fence = state.next_fence.max(fence.get().saturating_add(1));
                Ok(())
            }
            ReplicationOp::ProtectedRosterEstablishedCreate { .. } => {
                Err(StoreError::CapabilityNotSupported(
                    Self::PROTECTED_ROSTER_PROFILE_V2_CAPABILITY.into(),
                ))
            }
            ReplicationOp::Batch { ops } => {
                for op in ops {
                    Self::apply_replicated_op_with_state(state, op, now, max_tracked_keys)?;
                }
                Ok(())
            }
        }
    }

    fn validate_replicated_owner(
        state: &FakeBackendState,
        key: &FakeMapKey,
        owner: &OwnerId,
        fence: FenceToken,
    ) -> Result<(), StoreError> {
        if state.key_fences.get(key) != Some(&fence)
            || !state
                .leases
                .get(key)
                .is_some_and(|entry| entry.active && entry.owner == *owner && entry.fence == fence)
        {
            return Err(StoreError::StaleFence);
        }
        Ok(())
    }

    fn contains_protected_roster_established_create(op: &ReplicationOp) -> bool {
        let mut pending = vec![op];
        while let Some(operation) = pending.pop() {
            match operation {
                ReplicationOp::ProtectedRosterEstablishedCreate { .. } => return true,
                ReplicationOp::Batch { ops } => pending.extend(ops),
                ReplicationOp::CompareAndSet { .. }
                | ReplicationOp::DeleteFenced { .. }
                | ReplicationOp::RefreshTtl { .. }
                | ReplicationOp::AcquireLease { .. }
                | ReplicationOp::RenewLease { .. }
                | ReplicationOp::ReleaseLease { .. }
                | ReplicationOp::ProtectedRosterEstablished { .. } => {}
            }
        }
        false
    }

    fn require_complete_replay_command(state: &FakeBackendState) -> Result<(), StoreError> {
        if state.pending_replay_command.is_some() {
            return Err(StoreError::BackendUnavailable(
                "replication command is incomplete".into(),
            ));
        }
        Ok(())
    }

    fn next_direct_replication_sequence(
        &self,
        state: &FakeBackendState,
    ) -> Result<Option<u64>, StoreError> {
        Self::require_complete_replay_command(state)?;
        if !self.caps.ordered_replication_log {
            return Ok(None);
        }
        next_replication_sequence(state.last_replication_sequence).map(Some)
    }

    fn append_direct_replication_entry(
        &self,
        state: &mut FakeBackendState,
        sequence: Option<u64>,
        op: ReplicationOp,
        timestamp: Timestamp,
        replay_policy: crate::ReplicationReplayPolicy,
    ) -> Option<ReplicationEntry> {
        let sequence = sequence?;

        state.last_replication_sequence = sequence;
        let mut request_bytes = [0_u8; 16];
        request_bytes[8..].copy_from_slice(&sequence.to_be_bytes());
        let entry = ReplicationEntry {
            replay_policy,
            sequence,
            tx_id: ReplicationTxId::from_request_bytes(request_bytes),
            op,
            timestamp,
        };
        state.replication_log.push_back(entry.clone());
        Self::compact_replication_log(state, self.limits.max_replication_entries);
        Some(entry)
    }

    fn commit_direct_data(
        &self,
        state: &mut FakeBackendState,
        mut staged: FakeBackendState,
        sequence: Option<u64>,
        op: ReplicationOp,
        timestamp: Timestamp,
    ) -> Result<(), StoreError> {
        Self::retire_dead_keys(&mut staged)?;
        let capacity_rotations =
            Self::finalize_key_capacity(&mut staged, self.limits.max_tracked_keys)?;
        if sequence.is_some() {
            op.validate_structure()?;
        }
        let mut policy = crate::ReplicationReplayPolicy::prune_and_retire();
        policy.async_fence_floor = staged.async_fence_floor;
        policy.internal_key_count = staged.internal_key_count;
        policy.capacity_rotations = capacity_rotations;
        policy.validate()?;
        let entry =
            self.append_direct_replication_entry(&mut staged, sequence, op, timestamp, policy);
        staged.committed_time = Some(timestamp);
        self.publish_staged_data(state, staged);
        if self.caps.watch {
            if let Some(entry) = entry {
                Self::notify_watchers(state, &entry);
            }
        }
        Ok(())
    }

    fn stage_rebuilt_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<FakeBackendState, StoreError> {
        validate_replication_prefix(&entries)?;
        if entries
            .iter()
            .any(|entry| Self::contains_protected_roster_established_create(&entry.op))
        {
            return Err(StoreError::CapabilityNotSupported(
                Self::PROTECTED_ROSTER_PROFILE_V2_CAPABILITY.into(),
            ));
        }
        let mut staged = FakeBackendState::empty();

        for entry in entries {
            self.apply_committed_replication_entry(&mut staged, &entry)?;
            Self::apply_visible_recovery_boundary(&mut staged, &entry);
            staged.last_replication_sequence = entry.sequence;
            staged.replication_log.push_back(entry);
            Self::compact_replication_log(&mut staged, self.limits.max_replication_entries);
        }

        Ok(staged)
    }

    fn apply_committed_replication_entry(
        &self,
        state: &mut FakeBackendState,
        entry: &ReplicationEntry,
    ) -> Result<(), StoreError> {
        use crate::{
            ReplicationCommandBoundary as Boundary, ReplicationRecoveryBoundary as Recovery,
        };
        let policy = entry.replay_policy;
        let continuing = state.pending_replay_command.is_some();
        crate::replay_policy::ReplayCommandCursor::advance(
            state.pending_replay_command.as_ref().map(|pending| {
                crate::replay_policy::ReplayCommandCursor {
                    id: pending.id,
                    remaining: pending.remaining,
                    timestamp: pending.timestamp,
                    async_fence_floor: pending.async_fence_floor,
                }
            }),
            entry,
        )?;
        match policy.recovery {
            Recovery::None if policy.async_fence_floor == state.async_fence_floor => {}
            Recovery::Recover { previous_sequence }
                if !continuing
                    && previous_sequence == state.last_replication_sequence
                    && policy.async_fence_floor > state.async_fence_floor
                    && entry.sequence == policy.async_fence_floor + 1 =>
            {
                state.async_fence_floor = policy.async_fence_floor;
                state.next_fence = state.next_fence.max(policy.async_fence_floor + 1);
                state.next_credential_id =
                    state.next_credential_id.max(policy.async_fence_floor + 1);
            }
            _ => {
                return Err(StoreError::Serialization(
                    "inconsistent replication recovery floor".into(),
                ))
            }
        }
        state.internal_key_count = policy.internal_key_count;
        if policy.prune_expired {
            Self::prune_state(state, entry.timestamp);
        }
        Self::apply_replicated_op_with_state(
            state,
            entry.op.clone(),
            entry.timestamp,
            self.limits.max_tracked_keys,
        )?;
        if policy.retire_dead_keys {
            Self::retire_dead_keys(state)?;
        }
        if let Boundary::Start {
            id,
            following_entries,
        } = policy.command
        {
            entry
                .sequence
                .checked_add(u64::from(following_entries))
                .ok_or(StoreError::ReplicationOperationLimitExceeded)?;
            state.pending_replay_command = Some(PendingReplayCommand {
                fences: state.key_fences.clone(),
                floor_prev: state.key_retention.floor_prev,
                remaining: following_entries,
                id,
                async_fence_floor: policy.async_fence_floor,
                timestamp: entry.timestamp,
            });
        }
        for _ in 0..policy.capacity_rotations {
            if state.retired_keys.is_empty() {
                return Err(StoreError::Serialization(
                    "committed capacity rotation has no retired history".into(),
                ));
            }
            Self::rotate_keys_with_floor(
                state,
                crate::key_retention::RotationReason::Capacity,
                policy.async_fence_floor,
            )?;
        }
        if continuing {
            let pending = state.pending_replay_command.as_mut().ok_or_else(|| {
                StoreError::Serialization("replication command continuation absent".into())
            })?;
            pending.remaining -= 1;
            if pending.remaining == 0 {
                state.pending_replay_command = None;
            }
        }
        if state
            .key_fences
            .len()
            .saturating_add(state.internal_key_count as usize)
            > self.limits.max_tracked_keys
        {
            return Err(StoreError::BackendUnavailable(
                "fake backend tracked-key limit reached".into(),
            ));
        }
        state.committed_time = Some(
            state
                .committed_time
                .map_or(entry.timestamp, |prior| prior.max(entry.timestamp)),
        );
        Ok(())
    }
}

impl Default for FakeSessionBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionBackend for FakeSessionBackend {
    fn restore_scan_cursor_profile(&self) -> Option<crate::RestoreScanCursorProfile> {
        #[cfg(feature = "lab-memory")]
        if self.caps.restore_scan && self.lab_restore_authority.is_some() {
            return Some(crate::RestoreScanCursorProfile::DurableOpaqueV1);
        }
        self.caps
            .restore_scan
            .then_some(crate::RestoreScanCursorProfile::LegacyCompatibility)
    }

    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        Some(BackendInstanceIdentity::for_shared(&self.inner))
    }

    async fn capabilities(&self) -> BackendCapabilities {
        self.caps
    }

    fn record_expiry_reference(&self) -> Option<Timestamp> {
        Some(self.clock.now_utc())
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        let state = self.inner.lock().await;
        let now = self.clock.now_utc();
        Ok(self.get_for_read(&state, key, now))
    }

    #[cfg(feature = "lab-memory")]
    async fn observe_fenced_transition(
        &self,
        key: &SessionKey,
    ) -> Result<crate::FencedTransitionObservation, StoreError> {
        self.require_lab_identity()?;
        let state = self.inner.lock().await;
        let now = self.clock.now_utc();
        crate::FencedTransitionObservation::new(
            self.get_for_read(&state, key, now),
            Self::current_fence(&state, &Self::map_key(key)),
        )
    }

    #[cfg(feature = "lab-memory")]
    async fn fenced_transition_capability(
        &self,
    ) -> Result<Option<crate::AtomicFencedTransitionCapability>, StoreError> {
        Ok(self
            .lab_identity
            .map(|_| crate::AtomicFencedTransitionCapability::V1))
    }

    #[cfg(feature = "lab-memory")]
    fn fenced_transition_preserves_protected_payloads(&self) -> bool {
        self.lab_identity.is_some()
    }

    #[cfg(feature = "lab-memory")]
    fn fenced_transition_accepts_prepared_physical_token(
        &self,
        prepared: &crate::PreparedFencedTransition,
    ) -> bool {
        self.lab_request(prepared).is_ok()
    }

    #[cfg(feature = "lab-memory")]
    async fn prepare_fenced_transition(
        &self,
        request: crate::FencedTransitionRequest,
    ) -> Result<crate::PreparedFencedTransition, StoreError> {
        let identity = self.require_lab_identity()?;
        request.validate_at(self.clock.now_utc())?;
        crate::PreparedFencedTransition::from_unprotected_request(request)?.with_protection(
            crate::fenced_transition::PreparedFencedTransitionProtection::LabMemoryPhysicalV1 {
                instance_commitment: identity,
            },
        )
    }

    #[cfg(feature = "lab-memory")]
    async fn fenced_transition(
        &self,
        prepared: &crate::PreparedFencedTransition,
    ) -> Result<crate::FencedTransitionOutcome, crate::FencedTransitionExecuteError> {
        self.lab_execute(prepared)
            .await
            .map_err(crate::FencedTransitionExecuteError::Rejected)
    }

    #[cfg(feature = "lab-memory")]
    async fn fenced_transition_status(
        &self,
        prepared: &crate::PreparedFencedTransition,
    ) -> Result<crate::FencedTransitionStatus, StoreError> {
        self.lab_status(prepared).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        let mut committed = self.inner.lock().await;
        let now = self.command_time(&committed);
        let _ = self.get_for_read(&committed, &op.key, now);
        validate_stored_record_expiry_at(&op.new_record, now)?;
        let mut state = committed.stage_data();
        Self::prune_state(&mut state, now);
        let replication_sequence = self.next_direct_replication_sequence(&state)?;
        let replication_op = ReplicationOp::CompareAndSet {
            key: op.key.clone(),
            expected_generation: op.expected_generation,
            credential_id: op.lease.credential_id(),
            guard_expires_at: op.lease.expires_at(),
            new_record: op.new_record.clone(),
        };
        let result = self.compare_and_set_with_state(&mut state, op, now)?;
        if result == CompareAndSetResult::Success {
            self.commit_direct_data(
                &mut committed,
                state,
                replication_sequence,
                replication_op,
                now,
            )?;
        }
        Ok(result)
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        let mut committed = self.inner.lock().await;
        let mut state = committed.stage_data();
        let now = self.command_time(&committed);
        Self::prune_state(&mut state, now);
        let replication_sequence = self.next_direct_replication_sequence(&state)?;
        self.delete_fenced_with_state(&mut state, lease, now)?;
        self.commit_direct_data(
            &mut committed,
            state,
            replication_sequence,
            ReplicationOp::DeleteFenced {
                key: lease.key().clone(),
                owner: lease.owner().clone(),
                fence: lease.fence(),
            },
            now,
        )?;
        Ok(())
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        validate_session_ttl(ttl)?;
        let mut committed = self.inner.lock().await;
        let now = self.command_time(&committed);
        let _ = self.get_for_read(&committed, lease.key(), now);
        checked_session_deadline(now, ttl)?;
        let mut state = committed.stage_data();
        Self::prune_state(&mut state, now);
        let replication_sequence = self.next_direct_replication_sequence(&state)?;
        let expires_at = self.refresh_ttl_with_state(&mut state, lease, ttl, now)?;
        self.commit_direct_data(
            &mut committed,
            state,
            replication_sequence,
            ReplicationOp::RefreshTtl {
                key: lease.key().clone(),
                owner: lease.owner().clone(),
                fence: lease.fence(),
                ttl,
                expires_at,
            },
            now,
        )?;
        Ok(())
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        // Sample after acquiring the same lock as the records and commit clock.
        let mut committed = self.inner.lock().await;
        let writes = ops.iter().any(|op| !matches!(op, SessionOp::Get { .. }));
        if writes {
            Self::require_complete_replay_command(&committed)?;
        }
        let now = if writes {
            self.command_time(&committed)
        } else {
            self.clock.now_utc()
        };
        validate_session_ops_at(&ops, now)?;
        for op in &ops {
            if let SessionOp::RefreshTtl { ttl, .. } = op {
                checked_session_deadline(now, *ttl)?;
            }
        }
        if !self.caps.batch_write {
            return Err(StoreError::CapabilityNotSupported("batch_write".into()));
        }

        let mut state = committed.stage_data();
        if writes {
            Self::prune_state(&mut state, now);
        }
        let mut replication = Vec::new();
        let mut expired_reads = Vec::new();
        let mut results = Vec::with_capacity(ops.len());
        for op in ops {
            let res = match op {
                SessionOp::Get { key } => {
                    let map_key = Self::map_key(&key);
                    let current = state.records.get(&map_key);
                    let prior = committed.records.get(&map_key);
                    if let Some(record) = current.or(prior) {
                        if record.is_expired_at(now) {
                            expired_reads.push(record.clone());
                        }
                    }
                    let visible = current
                        .filter(|record| {
                            !record.is_expired_at(now)
                                && (Some(*record) != prior || !self.record_hidden(&map_key))
                        })
                        .cloned();
                    SessionOpResult::Get(Ok(visible))
                }
                SessionOp::CompareAndSet(cas) => {
                    let op = ReplicationOp::CompareAndSet {
                        key: cas.key.clone(),
                        expected_generation: cas.expected_generation,
                        credential_id: cas.lease.credential_id(),
                        guard_expires_at: cas.lease.expires_at(),
                        new_record: cas.new_record.clone(),
                    };
                    let mut child = state.stage_data();
                    let result = self.compare_and_set_with_state(&mut child, cas, now);
                    if matches!(result, Ok(CompareAndSetResult::Success)) {
                        state = child;
                        replication.push(op);
                    }
                    SessionOpResult::CompareAndSet(result)
                }
                SessionOp::DeleteFenced { lease } => {
                    let mut child = state.stage_data();
                    let result = self.delete_fenced_with_state(&mut child, &lease, now);
                    if result.is_ok() {
                        state = child;
                        replication.push(ReplicationOp::DeleteFenced {
                            key: lease.key().clone(),
                            owner: lease.owner().clone(),
                            fence: lease.fence(),
                        });
                    }
                    SessionOpResult::DeleteFenced(result)
                }
                SessionOp::RefreshTtl { lease, ttl } => {
                    let mut child = state.stage_data();
                    let result = self.refresh_ttl_with_state(&mut child, &lease, ttl, now);
                    if let Ok(expires_at) = result {
                        state = child;
                        replication.push(ReplicationOp::RefreshTtl {
                            key: lease.key().clone(),
                            owner: lease.owner().clone(),
                            fence: lease.fence(),
                            ttl,
                            expires_at,
                        });
                    }
                    SessionOpResult::RefreshTtl(result.map(|_| ()))
                }
            };
            results.push(res);
        }
        if !replication.is_empty() {
            let sequence = self.next_direct_replication_sequence(&committed)?;
            self.commit_direct_data(
                &mut committed,
                state,
                sequence,
                ReplicationOp::Batch { ops: replication },
                now,
            )?;
        }
        for record in expired_reads {
            if committed.records.get(&Self::map_key(&record.key)) == Some(&record) {
                self.record_expired(&record, now);
            }
        }
        Ok(results)
    }

    async fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        if !self.caps.restore_scan {
            return Err(StoreError::CapabilityNotSupported("restore_scan".into()));
        }
        #[cfg(feature = "lab-memory")]
        if self.lab_restore_authority.is_some() {
            return self.lab_scan_restore_records(request).await;
        }
        request.validate()?;
        if request
            .cursor
            .as_ref()
            .is_some_and(|cursor| !cursor.is_legacy())
        {
            return Err(StoreError::RestoreScanCursorStale);
        }

        let state = self.inner.lock().await;
        let now = self.clock.now_utc();

        let start = request
            .cursor
            .as_ref()
            .map(RestoreScanCursor::offset)
            .unwrap_or(0);
        let mut records = Vec::with_capacity(request.limit.min(64));
        let mut payload_bytes = 0_usize;
        let mut retained_page_bytes = std::mem::size_of::<RestoreScanPage>();
        let continuation_bytes = RestoreScanCursor::from_offset(0).retained_token_bytes();
        let mut matching_position = 0_usize;
        let mut has_more = false;
        for record in state.records.values() {
            if self.record_expired(record, now) || !request.scope.matches_record(record) {
                continue;
            }
            if matching_position < start {
                matching_position += 1;
                continue;
            }
            if records.len() == request.limit {
                has_more = true;
                break;
            }
            let next_payload_bytes = payload_bytes
                .checked_add(record.payload.len())
                .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
            if next_payload_bytes > RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES {
                if records.is_empty() {
                    return Err(StoreError::RestoreScanResponseTooLarge {
                        max_bytes: RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES,
                    });
                }
                has_more = true;
                break;
            }
            if record.key.stable_id.len() > crate::SESSION_CONSENSUS_MAX_RPC_PAYLOAD_BYTES {
                return Err(StoreError::RestoreScanWorkBudgetExceeded);
            }
            let next_retained_page_bytes = retained_page_bytes
                .checked_add(restore_record_retained_bytes(record)?)
                .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
            if next_retained_page_bytes
                .checked_add(continuation_bytes)
                .is_none_or(|bytes| bytes > RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES)
            {
                if records.is_empty() {
                    return Err(StoreError::RestoreScanResponseTooLarge {
                        max_bytes: RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES,
                    });
                }
                has_more = true;
                break;
            }
            payload_bytes = next_payload_bytes;
            retained_page_bytes = next_retained_page_bytes;
            records.push(record.clone());
            matching_position += 1;
        }
        let end = start
            .checked_add(records.len())
            .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
        let next_cursor = has_more.then(|| RestoreScanCursor::from_offset(end));

        records.sort_by(compare_restore_records);
        Ok(RestoreScanPage::new(records, 0, next_cursor))
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        let state = self.inner.lock().await;
        Ok(state.last_replication_sequence)
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let range = ReplicationLogRange::try_new(start, limit)?;
        if range.is_empty() {
            return Ok(Vec::new());
        }
        let state = self.inner.lock().await;
        range.ensure_not_compacted(state.compacted_replication_sequence)?;
        let entries: Vec<ReplicationEntry> = state
            .replication_log
            .iter()
            .filter(|entry| entry.sequence >= range.first_sequence())
            .take(range.limit())
            .cloned()
            .collect();
        validate_replication_log_page_owned(start, limit, entries)
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let entry = entry.into_validated()?;
        if Self::contains_protected_roster_established_create(&entry.op) {
            return Err(StoreError::CapabilityNotSupported(
                Self::PROTECTED_ROSTER_PROFILE_V2_CAPABILITY.into(),
            ));
        }
        let mut state = self.inner.lock().await;
        let max_seq = state.last_replication_sequence;

        // Check if we already have it
        if entry.sequence <= max_seq {
            if entry.sequence <= state.compacted_replication_sequence {
                return Ok(());
            }
            // Check for duplicate delivery and idempotency
            if let Some(existing) = state
                .replication_log
                .iter()
                .find(|e| e.sequence == entry.sequence)
            {
                if existing == &entry {
                    return Ok(()); // Idempotent success
                } else {
                    return Err(StoreError::BackendUnavailable(
                        "divergent replication entry sequence".into(),
                    ));
                }
            }
            return Err(StoreError::BackendUnavailable(
                "divergent replication entry sequence".into(),
            ));
        }

        // Check for log gap
        if !crate::backend::replication_entry_follows(max_seq, &entry)? {
            return Err(StoreError::BackendUnavailable(
                "replication log sequence gap".into(),
            ));
        }

        let mut staged = state.stage_data();
        self.apply_committed_replication_entry(&mut staged, &entry)?;

        // Publish the same outward recovery window as the source.
        Self::apply_visible_recovery_boundary(&mut staged, &entry);
        staged.last_replication_sequence = entry.sequence;
        staged.replication_log.push_back(entry.clone());
        Self::compact_replication_log(&mut staged, self.limits.max_replication_entries);

        self.publish_staged_data(&mut state, staged);

        // Notify watchers
        Self::notify_watchers(&mut state, &entry);

        Ok(())
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        let entries = validate_replication_prefix_owned(entries)?;
        let staged = self.stage_rebuilt_replication_state(entries)?;
        let mut state = self.inner.lock().await;
        self.publish_staged_data(&mut state, staged);
        Ok(())
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        let mut state = self.inner.lock().await;
        let cursor = ReplicationWatchCursor::new(start_sequence);
        cursor.ensure_not_compacted(state.compacted_replication_sequence)?;
        let existing = state
            .replication_log
            .iter()
            .filter(|entry| entry.sequence >= cursor.first_sequence())
            .take(MAX_REPLICATION_WATCH_BACKLOG_ENTRIES + 1)
            .cloned()
            .collect();
        let (stream, watcher) = prepare_watch_registration(cursor, existing)?;

        state.watchers.retain(|watcher| !watcher.is_closed());
        if let Some(watcher) = watcher {
            state.watchers.push(watcher);
        }
        use futures_util::StreamExt;
        Ok(stream.boxed())
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        let state = self.inner.lock().await;
        Ok((state.next_fence, state.next_credential_id))
    }
}

#[async_trait]
impl SessionLeaseManager for FakeSessionBackend {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        let mut committed = self.inner.lock().await;
        let now = self.command_time(&committed);
        let expires_at = checked_session_deadline(now, ttl).map_err(LeaseError::from)?;
        let mut state = committed.stage_data();
        Self::prune_state(&mut state, now);
        let replication_sequence = self
            .next_direct_replication_sequence(&state)
            .map_err(LeaseError::from)?;
        let mk = Self::map_key(key);
        Self::apply_async_floor_to_key(&mut state, &mk);

        if let Some(entry) = state.leases.get(&mk) {
            if entry.active && entry.owner != owner && entry.expires_at > now {
                return Err(LeaseError::AlreadyHeld);
            }
        }
        Self::ensure_key_capacity(&state, &mk, self.limits.max_tracked_keys).map_err(|err| {
            match err {
                StoreError::BackendUnavailable(message) => LeaseError::Backend(message),
                other => LeaseError::from(other),
            }
        })?;

        let current_fence = Self::current_fence(&state, &mk);
        let next_for_key = current_fence
            .get()
            .checked_add(1)
            .ok_or_else(|| LeaseError::Backend("fence token exhausted".into()))?;
        let next_fence = state.next_fence.max(next_for_key);
        let fence = FenceToken::new(next_fence);
        state.next_fence = next_fence.saturating_add(1);
        let credential_id = state.next_credential_id;
        state.next_credential_id = state.next_credential_id.saturating_add(1);

        state.leases.insert(
            mk.clone(),
            LeaseEntry {
                active: true,
                credential_id,
                owner: owner.clone(),
                fence,
                acquired_at: now,
                expires_at,
                guard_expires_at: expires_at,
            },
        );
        Self::set_fence(&mut state, mk, fence);

        self.commit_direct_data(
            &mut committed,
            state,
            replication_sequence,
            ReplicationOp::AcquireLease {
                key: key.clone(),
                owner: owner.clone(),
                fence,
                credential_id,
                ttl,
                expires_at,
            },
            now,
        )?;

        Ok(LeaseGuard::new(
            key.clone(),
            owner,
            fence,
            now,
            expires_at,
            credential_id,
        ))
    }

    async fn renew(&self, lease: &LeaseGuard, ttl: Duration) -> Result<LeaseGuard, LeaseError> {
        validate_session_ttl(ttl).map_err(LeaseError::from)?;
        let mut committed = self.inner.lock().await;
        let now = self.command_time(&committed);
        let expires_at = checked_session_deadline(now, ttl).map_err(LeaseError::from)?;
        let mut state = committed.stage_data();
        Self::prune_state(&mut state, now);
        let replication_sequence = self
            .next_direct_replication_sequence(&state)
            .map_err(LeaseError::from)?;

        let mk = Self::map_key(lease.key());
        Self::apply_async_floor_to_key(&mut state, &mk);
        if lease.fence().get() <= state.async_fence_floor
            || lease.credential_id() <= state.async_fence_floor
        {
            return Err(LeaseError::StaleFence);
        }
        if lease.expires_at() <= now {
            return Err(LeaseError::Expired);
        }
        let Some(entry) = state.leases.get_mut(&mk) else {
            let current_fence = Self::current_fence(&state, &mk);
            if lease.fence() <= current_fence {
                return Err(LeaseError::StaleFence);
            }
            return Err(LeaseError::NotFound);
        };

        if !entry.active {
            return Err(LeaseError::StaleFence);
        }
        if entry.credential_id != lease.credential_id() {
            return Err(LeaseError::StaleFence);
        }
        if entry.owner != *lease.owner() {
            return Err(LeaseError::AlreadyHeld);
        }
        if entry.fence != lease.fence() || entry.guard_expires_at != lease.expires_at() {
            return Err(LeaseError::StaleFence);
        }

        if entry.expires_at <= now {
            return Err(LeaseError::Expired);
        }

        // Fence stays the same on renewal.
        let fence = lease.fence();
        let acquired_at = lease.acquired_at();
        let credential_id = entry.credential_id;

        entry.expires_at = expires_at;
        entry.guard_expires_at = expires_at;

        self.commit_direct_data(
            &mut committed,
            state,
            replication_sequence,
            ReplicationOp::RenewLease {
                key: lease.key().clone(),
                owner: lease.owner().clone(),
                fence,
                credential_id,
                ttl,
                expires_at,
            },
            now,
        )?;

        Ok(LeaseGuard::new(
            lease.key().clone(),
            lease.owner().clone(),
            fence,
            acquired_at,
            expires_at,
            credential_id,
        ))
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        let mut committed = self.inner.lock().await;
        let mut state = committed.stage_data();
        let now = self.command_time(&committed);
        Self::prune_state(&mut state, now);
        let replication_sequence = self
            .next_direct_replication_sequence(&state)
            .map_err(LeaseError::from)?;

        let mk = Self::map_key(lease.key());
        Self::apply_async_floor_to_key(&mut state, &mk);
        if lease.fence().get() <= state.async_fence_floor
            || lease.credential_id() <= state.async_fence_floor
        {
            return Err(LeaseError::StaleFence);
        }
        let Some(entry) = state.leases.get_mut(&mk) else {
            let current_fence = Self::current_fence(&state, &mk);
            if lease.fence() <= current_fence {
                return Err(LeaseError::StaleFence);
            }
            return Err(LeaseError::NotFound);
        };

        if !entry.active {
            return Err(LeaseError::StaleFence);
        }
        if entry.credential_id != lease.credential_id() {
            return Err(LeaseError::StaleFence);
        }
        if entry.owner != *lease.owner() {
            return Err(LeaseError::AlreadyHeld);
        }
        if entry.fence != lease.fence() || entry.guard_expires_at != lease.expires_at() {
            return Err(LeaseError::StaleFence);
        }

        entry.active = false;
        entry.guard_expires_at = now;
        self.commit_direct_data(
            &mut committed,
            state,
            replication_sequence,
            ReplicationOp::ReleaseLease {
                key: lease.key().clone(),
                owner: lease.owner().clone(),
                fence: lease.fence(),
                credential_id: lease.credential_id(),
            },
            now,
        )?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
