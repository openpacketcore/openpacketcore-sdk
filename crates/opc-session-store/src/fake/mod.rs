//! Deterministic in-memory test double for the storage and lease APIs.
//!
//! `FakeSessionBackend` implements the full `SessionBackend` and
//! `SessionLeaseManager` contracts — fenced CAS, lease lifecycle, TTL
//! pruning, the ordered replication log, and watch streams — entirely in
//! process. Combined with `TokioVirtualClock` it lets split-brain, stale
//! fence, lease-expiry, and quorum scenarios run deterministically without
//! I/O or real waiting. Suitable for tests and single-replica development
//! only; nothing is persisted.

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use opc_types::Timestamp;
use tokio::sync::Mutex;

use crate::{
    backend::{
        CompareAndSet, CompareAndSetResult, ReplicationEntry, ReplicationOp, SessionBackend,
        SessionOp, SessionOpResult,
    },
    capability::BackendCapabilities,
    clock::{Clock, TokioVirtualClock},
    error::{LeaseError, StoreError},
    hex::encode_lower,
    lease::{LeaseGuard, SessionLeaseManager},
    model::{FenceToken, OwnerId, SessionKey},
    record::StoredSessionRecord,
};

/// In-memory session backend and lease manager for deterministic tests.
///
/// `Clone` is cheap (Arc) so multiple tasks can share the same logical backend.
#[derive(Clone)]
pub struct FakeSessionBackend {
    inner: Arc<Mutex<FakeBackendState>>,
    caps: BackendCapabilities,
    clock: Arc<dyn Clock>,
}

struct FakeBackendState {
    records: HashMap<String, StoredSessionRecord>,
    leases: HashMap<String, LeaseEntry>,
    key_fences: HashMap<String, FenceToken>,
    next_fence: u64,
    next_credential_id: u64,
    replication_log: Vec<ReplicationEntry>,
    watchers: Vec<tokio::sync::mpsc::UnboundedSender<Result<ReplicationEntry, StoreError>>>,
}

struct LeaseEntry {
    active: bool,
    credential_id: u64,
    owner: OwnerId,
    fence: FenceToken,
    expires_at: Timestamp,
    guard_expires_at: Timestamp,
}

impl FakeSessionBackend {
    /// Create a new fake backend with all capabilities enabled.
    pub fn new() -> Self {
        Self::with_capabilities(BackendCapabilities::all_enabled())
    }

    /// Create a new fake backend with a specific capability set.
    pub fn with_capabilities(caps: BackendCapabilities) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FakeBackendState {
                records: HashMap::new(),
                leases: HashMap::new(),
                key_fences: HashMap::new(),
                next_fence: 1,
                next_credential_id: 1,
                replication_log: Vec::new(),
                watchers: Vec::new(),
            })),
            caps,
            clock: Arc::new(TokioVirtualClock::new()),
        }
    }

    /// Replace the default tokio-virtual-time clock.
    ///
    /// The clock decides record TTL expiry, lease expiry, and pruning. Share
    /// one clock instance across the backends and coordinators under test so
    /// "owner pauses past its lease TTL" scenarios stay coherent.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Return a simple string key for HashMap lookups.
    fn map_key(key: &SessionKey) -> String {
        format!(
            "{}/{}/{}/{}",
            key.tenant.as_str(),
            key.nf_kind.as_str(),
            key.key_type,
            encode_lower(key.stable_id.as_ref())
        )
    }

    /// Get the current recorded fence for a key.
    fn current_fence(state: &FakeBackendState, map_key: &str) -> FenceToken {
        state
            .key_fences
            .get(map_key)
            .copied()
            .unwrap_or_else(|| FenceToken::new(0))
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

    fn prune_state(state: &mut FakeBackendState, now: Timestamp) {
        state.records.retain(|_, record| {
            if let Some(expires_at) = record.expires_at {
                expires_at > now
            } else {
                true
            }
        });
        state
            .leases
            .retain(|_, entry| entry.active && entry.expires_at > now);
    }

    fn validate_fenced_mutation(
        state: &FakeBackendState,
        lease: &LeaseGuard,
        now: Timestamp,
    ) -> Result<String, StoreError> {
        let map_key = Self::map_key(lease.key());
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

        let existing = state
            .records
            .get(&mk)
            .filter(|r| !r.is_expired_at(now))
            .cloned();

        match (op.expected_generation, existing) {
            (None, None) => {
                state.records.insert(mk.clone(), op.new_record.clone());
                state.key_fences.insert(mk, op.lease.fence());
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
                state.key_fences.insert(mk, op.lease.fence());
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

        state.records.remove(&mk);
        state.key_fences.insert(mk, lease.fence());
        Ok(())
    }

    fn refresh_ttl_with_state(
        &self,
        state: &mut FakeBackendState,
        lease: &LeaseGuard,
        ttl: Duration,
        now: Timestamp,
    ) -> Result<(), StoreError> {
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

        let Some(record) = state.records.get_mut(&mk) else {
            return Err(StoreError::NotFound);
        };

        if record.is_expired_at(now) {
            return Err(StoreError::NotFound);
        }

        let expires = *now.as_offset_datetime() + time::Duration::seconds_f64(ttl.as_secs_f64());
        record.expires_at = Some(Timestamp::from_offset_datetime(expires));
        state.key_fences.insert(mk, lease.fence());
        Ok(())
    }

    fn apply_replicated_op_with_state(
        state: &mut FakeBackendState,
        op: ReplicationOp,
        now: Timestamp,
    ) -> Result<(), StoreError> {
        match op {
            ReplicationOp::CompareAndSet {
                key,
                expected_generation,
                new_record,
            } => {
                let mk = Self::map_key(&key);
                let current_fence = Self::current_fence(state, &mk);
                if new_record.fence < current_fence {
                    return Err(StoreError::StaleFence);
                }

                // Verify lease in state is active and not expired
                let lease_valid = if let Some(lease_entry) = state.leases.get(&mk) {
                    lease_entry.active
                        && lease_entry.owner == new_record.owner
                        && lease_entry.fence == new_record.fence
                        && lease_entry.guard_expires_at > now
                } else {
                    false
                };

                if !lease_valid {
                    return Err(StoreError::LeaseExpired);
                }

                let existing = Self::get_with_state(state, &key, now);
                match (expected_generation, existing) {
                    (None, None) => {
                        state.records.insert(mk.clone(), new_record.clone());
                        state.key_fences.insert(mk, new_record.fence);
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
                        state.key_fences.insert(mk, new_record.fence);
                        Ok(())
                    }
                    _ => Err(StoreError::CasConflict),
                }
            }
            ReplicationOp::DeleteFenced {
                key,
                owner: _,
                fence,
            } => {
                let mk = Self::map_key(&key);
                let current_fence = Self::current_fence(state, &mk);
                if fence < current_fence {
                    return Err(StoreError::StaleFence);
                }
                state.records.remove(&mk);
                state.key_fences.insert(mk, fence);
                Ok(())
            }
            ReplicationOp::RefreshTtl {
                key,
                owner: _,
                fence,
                ttl,
            } => {
                let mk = Self::map_key(&key);
                let current_fence = Self::current_fence(state, &mk);
                if fence < current_fence {
                    return Err(StoreError::StaleFence);
                }
                if let Some(record) = state.records.get_mut(&mk) {
                    let expires =
                        *now.as_offset_datetime() + time::Duration::seconds_f64(ttl.as_secs_f64());
                    record.expires_at = Some(Timestamp::from_offset_datetime(expires));
                    state.key_fences.insert(mk, fence);
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
                ttl,
            } => {
                let mk = Self::map_key(&key);
                let current_fence = Self::current_fence(state, &mk);
                if fence < current_fence {
                    return Err(StoreError::StaleFence);
                }
                if let Some(entry) = state.leases.get(&mk) {
                    if entry.active && entry.owner != owner && entry.expires_at > now {
                        return Err(StoreError::LeaseHeld);
                    }
                }
                let expires_at =
                    *now.as_offset_datetime() + time::Duration::seconds_f64(ttl.as_secs_f64());
                let expires_at = Timestamp::from_offset_datetime(expires_at);
                state.leases.insert(
                    mk.clone(),
                    LeaseEntry {
                        active: true,
                        credential_id,
                        owner,
                        fence,
                        expires_at,
                        guard_expires_at: expires_at,
                    },
                );
                state.key_fences.insert(mk, fence);
                state.next_fence = state.next_fence.max(fence.get() + 1);
                state.next_credential_id = state.next_credential_id.max(credential_id + 1);
                Ok(())
            }
            ReplicationOp::RenewLease {
                key,
                owner,
                fence,
                credential_id,
                ttl,
            } => {
                let mk = Self::map_key(&key);
                let current_fence = Self::current_fence(state, &mk);
                if fence < current_fence {
                    return Err(StoreError::StaleFence);
                }
                let expires_at =
                    *now.as_offset_datetime() + time::Duration::seconds_f64(ttl.as_secs_f64());
                let expires_at = Timestamp::from_offset_datetime(expires_at);
                state.leases.insert(
                    mk.clone(),
                    LeaseEntry {
                        active: true,
                        credential_id,
                        owner,
                        fence,
                        expires_at,
                        guard_expires_at: expires_at,
                    },
                );
                state.key_fences.insert(mk, fence);
                state.next_fence = state.next_fence.max(fence.get() + 1);
                state.next_credential_id = state.next_credential_id.max(credential_id + 1);
                Ok(())
            }
            ReplicationOp::ReleaseLease {
                key,
                owner: _,
                fence,
                credential_id,
            } => {
                let mk = Self::map_key(&key);
                let current_fence = Self::current_fence(state, &mk);
                if fence < current_fence {
                    return Err(StoreError::StaleFence);
                }
                if let Some(entry) = state.leases.get_mut(&mk) {
                    if entry.credential_id == credential_id {
                        entry.active = false;
                    }
                }
                state.key_fences.insert(mk, fence);
                Ok(())
            }
            ReplicationOp::Batch { ops } => {
                for op in ops {
                    Self::apply_replicated_op_with_state(state, op, now)?;
                }
                Ok(())
            }
        }
    }

    fn rebuild_replication_state_with_entries(
        &self,
        state: &mut FakeBackendState,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        state.records.clear();
        state.leases.clear();
        state.key_fences.clear();
        state.next_fence = 1;
        state.next_credential_id = 1;
        state.replication_log.clear();

        for (expected_sequence, entry) in (1_u64..).zip(entries) {
            if entry.sequence != expected_sequence {
                return Err(StoreError::BackendUnavailable(
                    "replication log sequence gap".into(),
                ));
            }
            Self::apply_replicated_op_with_state(state, entry.op.clone(), entry.timestamp)?;
            state.replication_log.push(entry);
        }

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
    async fn capabilities(&self) -> BackendCapabilities {
        self.caps
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        let mut state = self.inner.lock().await;
        let now = self.clock.now_utc();
        Self::prune_state(&mut state, now);
        Ok(Self::get_with_state(&state, key, now))
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        let mut state = self.inner.lock().await;
        let now = self.clock.now_utc();
        Self::prune_state(&mut state, now);
        self.compare_and_set_with_state(&mut state, op, now)
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        let mut state = self.inner.lock().await;
        let now = self.clock.now_utc();
        Self::prune_state(&mut state, now);
        self.delete_fenced_with_state(&mut state, lease, now)
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        let mut state = self.inner.lock().await;
        let now = self.clock.now_utc();
        Self::prune_state(&mut state, now);
        self.refresh_ttl_with_state(&mut state, lease, ttl, now)
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        if !self.caps.batch_write {
            return Err(StoreError::CapabilityNotSupported("batch_write".into()));
        }

        let mut state = self.inner.lock().await;
        let now = self.clock.now_utc();
        Self::prune_state(&mut state, now);
        let mut results = Vec::with_capacity(ops.len());
        for op in ops {
            let res = match op {
                SessionOp::Get { key } => {
                    SessionOpResult::Get(Ok(Self::get_with_state(&state, &key, now)))
                }
                SessionOp::CompareAndSet(cas) => SessionOpResult::CompareAndSet(
                    self.compare_and_set_with_state(&mut state, cas, now),
                ),
                SessionOp::DeleteFenced { lease } => SessionOpResult::DeleteFenced(
                    self.delete_fenced_with_state(&mut state, &lease, now),
                ),
                SessionOp::RefreshTtl { lease, ttl } => SessionOpResult::RefreshTtl(
                    self.refresh_ttl_with_state(&mut state, &lease, ttl, now),
                ),
            };
            results.push(res);
        }
        Ok(results)
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        let state = self.inner.lock().await;
        Ok(state
            .replication_log
            .last()
            .map(|e| e.sequence)
            .unwrap_or(0))
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let state = self.inner.lock().await;
        let entries: Vec<ReplicationEntry> = state
            .replication_log
            .iter()
            .filter(|e| e.sequence >= start)
            .take(limit)
            .cloned()
            .collect();
        Ok(entries)
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let mut state = self.inner.lock().await;
        let now = self.clock.now_utc();
        Self::prune_state(&mut state, now);

        let max_seq = state
            .replication_log
            .last()
            .map(|e| e.sequence)
            .unwrap_or(0);

        // Check if we already have it
        if entry.sequence <= max_seq {
            // Check for duplicate delivery and idempotency
            if let Some(existing) = state
                .replication_log
                .iter()
                .find(|e| e.sequence == entry.sequence)
            {
                if existing.tx_id == entry.tx_id {
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
        if entry.sequence > max_seq + 1 {
            return Err(StoreError::BackendUnavailable(
                "replication log sequence gap".into(),
            ));
        }

        // Apply mutation
        Self::apply_replicated_op_with_state(&mut state, entry.op.clone(), now)?;

        // Append to replication log
        state.replication_log.push(entry.clone());

        // Notify watchers
        state.watchers.retain(|w| w.send(Ok(entry.clone())).is_ok());

        Ok(())
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        let mut state = self.inner.lock().await;
        self.rebuild_replication_state_with_entries(&mut state, entries)
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        let mut state = self.inner.lock().await;
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        // Send existing entries
        for entry in state
            .replication_log
            .iter()
            .filter(|e| e.sequence >= start_sequence)
        {
            let _ = tx.send(Ok(entry.clone()));
        }

        state.watchers.push(tx);
        use futures_util::StreamExt;
        let stream = WatchStream { rx };
        Ok(stream.boxed())
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        let state = self.inner.lock().await;
        Ok((state.next_fence, state.next_credential_id))
    }
}

struct WatchStream {
    rx: tokio::sync::mpsc::UnboundedReceiver<Result<ReplicationEntry, StoreError>>,
}

impl futures_util::Stream for WatchStream {
    type Item = Result<ReplicationEntry, StoreError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
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
        let mut state = self.inner.lock().await;
        let now = self.clock.now_utc();
        Self::prune_state(&mut state, now);
        let mk = Self::map_key(key);

        if let Some(entry) = state.leases.get(&mk) {
            if entry.active && entry.owner != owner && entry.expires_at > now {
                return Err(LeaseError::AlreadyHeld);
            }
        }

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

        let expires_at = *now.as_offset_datetime() + time::Duration::seconds_f64(ttl.as_secs_f64());
        let expires_at = Timestamp::from_offset_datetime(expires_at);

        state.leases.insert(
            mk.clone(),
            LeaseEntry {
                active: true,
                credential_id,
                owner: owner.clone(),
                fence,
                expires_at,
                guard_expires_at: expires_at,
            },
        );
        state.key_fences.insert(mk, fence);

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
        let mut state = self.inner.lock().await;
        let now = self.clock.now_utc();
        Self::prune_state(&mut state, now);

        if lease.expires_at() <= now {
            return Err(LeaseError::Expired);
        }

        let mk = Self::map_key(lease.key());
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
        let expires_at = *now.as_offset_datetime() + time::Duration::seconds_f64(ttl.as_secs_f64());
        let expires_at = Timestamp::from_offset_datetime(expires_at);
        let credential_id = entry.credential_id;

        entry.expires_at = expires_at;
        entry.guard_expires_at = expires_at;

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
        let mut state = self.inner.lock().await;
        let now = self.clock.now_utc();
        Self::prune_state(&mut state, now);

        let mk = Self::map_key(lease.key());
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
        entry.expires_at = now;
        // Fence is NOT reduced; it remains the current recorded token.
        Ok(())
    }
}

#[cfg(test)]
mod tests;
