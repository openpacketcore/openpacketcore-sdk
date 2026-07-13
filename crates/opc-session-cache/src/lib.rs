//! Read-through session cache with key-scoped invalidation, sequence tracking,
//! and resume recovery.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

use opc_session_store::{
    next_replication_sequence, validate_replication_log_page_owned,
    validate_replication_prefix_owned, validate_session_ttl, BackendCapabilities,
    BackendInstanceIdentity, BackendPeerBinding, CompareAndSet, CompareAndSetResult,
    ReplicationEntry, ReplicationLogRange, ReplicationOp, SessionBackend, SessionKey, SessionOp,
    SessionOpResult, StoreError, StoredSessionRecord,
};

/// A local, in-memory read-through session cache that stays coherent with the
/// authoritative session store by consuming its replication watch stream.
pub struct SessionCache {
    backend: Arc<dyn SessionBackend>,
    cache: Arc<RwLock<HashMap<SessionKey, StoredSessionRecord>>>,
    last_sequence: Arc<AtomicU64>,
    watch_ready: Arc<AtomicBool>,
    resync_tx: mpsc::UnboundedSender<()>,
    is_syncing: Arc<AtomicBool>,
    watch_error_count: Arc<AtomicU64>,
    watch_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl SessionCache {
    /// Create a new `SessionCache` wrapping the given backend and start the background watch.
    pub fn new(backend: Arc<dyn SessionBackend>) -> Arc<Self> {
        let cache = Arc::new(RwLock::new(HashMap::new()));
        let last_sequence = Arc::new(AtomicU64::new(0));
        let watch_ready = Arc::new(AtomicBool::new(false));
        let (resync_tx, resync_rx) = mpsc::unbounded_channel();
        let is_syncing = Arc::new(AtomicBool::new(false));
        let watch_error_count = Arc::new(AtomicU64::new(0));

        let cache_clone = cache.clone();
        let last_seq_clone = last_sequence.clone();
        let watch_ready_clone = watch_ready.clone();
        let is_syncing_clone = is_syncing.clone();
        let watch_err_clone = watch_error_count.clone();
        let backend_clone = backend.clone();

        let cache_inst = Arc::new(Self {
            backend,
            cache,
            last_sequence,
            watch_ready,
            resync_tx,
            is_syncing,
            watch_error_count,
            watch_task: Mutex::new(None),
        });

        let handle = tokio::spawn(async move {
            Self::run_watch_loop(
                backend_clone,
                cache_clone,
                last_seq_clone,
                watch_ready_clone,
                resync_rx,
                is_syncing_clone,
                watch_err_clone,
            )
            .await;
        });

        if let Ok(mut guard) = cache_inst.watch_task.try_lock() {
            *guard = Some(handle);
        } else {
            handle.abort();
        }

        cache_inst
    }

    /// Retrieve a session record, serving it from the local cache if present and valid.
    /// On a cache miss, the record is fetched from the backend and populated.
    pub async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        let cache_reads_allowed = self.cache_reads_allowed().await;

        if cache_reads_allowed {
            let lock = self.cache.read().await;
            if let Some(record) = lock.get(key) {
                if record.is_expired() {
                    drop(lock);
                    let mut write_lock = self.cache.write().await;
                    write_lock.remove(key);
                    debug!("Local cache entry for key {:?} was expired; evicting", key);
                } else {
                    debug!("Local cache hit for key {:?}", key);
                    return Ok(Some(record.clone()));
                }
            }
        } else {
            debug!(
                "Local cache bypass for key {:?}; watch cursor is not coherent",
                key
            );
        }

        debug!("Local cache miss for key {:?}; querying backend", key);
        let record_opt = self.backend.get(key).await?;

        if let Some(ref record) = record_opt {
            // Verify record is not expired
            if record.is_expired() {
                debug!(
                    "Backend record for key {:?} is expired; returning None",
                    key
                );
                return Ok(None);
            }

            if self.cache_reads_allowed().await {
                self.insert_if_newer(key.clone(), record.clone()).await;
            }
        }

        Ok(record_opt)
    }

    async fn insert_if_newer(&self, key: SessionKey, record: StoredSessionRecord) {
        let mut write_lock = self.cache.write().await;
        if let Some(cached) = write_lock.get(&key) {
            if record.generation.get() > cached.generation.get() {
                write_lock.insert(key, record);
            }
        } else {
            write_lock.insert(key, record);
        }
    }

    async fn cache_reads_allowed(&self) -> bool {
        if !self.watch_ready.load(Ordering::Acquire) || self.is_syncing.load(Ordering::Acquire) {
            return false;
        }

        match self.backend.max_replication_sequence().await {
            Ok(max_sequence) => {
                let last = self.last_sequence.load(Ordering::Acquire);
                if last >= max_sequence {
                    true
                } else {
                    warn!(
                        "Session cache watch cursor lagged committed sequence; clearing cache and bypassing local reads"
                    );
                    self.watch_ready.store(false, Ordering::Release);
                    self.watch_error_count.fetch_add(1, Ordering::Relaxed);
                    self.clear().await;
                    false
                }
            }
            Err(err) => {
                warn!(
                    "Session cache could not verify replication sequence; clearing cache and bypassing local reads: {}",
                    store_error_kind(&err)
                );
                self.watch_ready.store(false, Ordering::Release);
                self.watch_error_count.fetch_add(1, Ordering::Relaxed);
                self.clear().await;
                false
            }
        }
    }

    /// Explicitly invalidate a key from the cache.
    pub async fn invalidate(&self, key: &SessionKey) -> bool {
        let mut lock = self.cache.write().await;
        let removed = lock.remove(key).is_some();
        if removed {
            debug!("Manually invalidated key {:?}", key);
        }
        removed
    }

    /// Retrieve the last replication log sequence processed by the cache watch stream.
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence.load(Ordering::Relaxed)
    }

    /// Manually trigger a full cache resync (clears cache and catches up sequence cursor).
    pub fn resync(&self) -> Result<(), StoreError> {
        self.resync_tx
            .send(())
            .map_err(|_| StoreError::BackendUnavailable("Resync channel closed".into()))
    }

    /// Returns true if the cache is currently performing a resync.
    pub fn is_syncing(&self) -> bool {
        self.is_syncing.load(Ordering::Relaxed)
    }

    /// Returns true when the background watch stream is active and the latest
    /// observed sequence can be used to validate cache reads.
    pub fn is_watch_ready(&self) -> bool {
        self.watch_ready.load(Ordering::Acquire)
    }

    /// Get current cache size (number of keys).
    pub async fn len(&self) -> usize {
        let lock = self.cache.read().await;
        lock.len()
    }

    /// Checks if cache is empty.
    pub async fn is_empty(&self) -> bool {
        let lock = self.cache.read().await;
        lock.is_empty()
    }

    /// Clear all cached entries.
    pub async fn clear(&self) {
        let mut lock = self.cache.write().await;
        lock.clear();
        debug!("Cleared local session cache");
    }

    /// Retrieve total count of watch stream errors.
    pub fn watch_error_count(&self) -> u64 {
        self.watch_error_count.load(Ordering::Relaxed)
    }

    /// Background loop that consumes the backend watch stream and invalidates keys.
    async fn run_watch_loop(
        backend: Arc<dyn SessionBackend>,
        cache: Arc<RwLock<HashMap<SessionKey, StoredSessionRecord>>>,
        last_sequence: Arc<AtomicU64>,
        watch_ready: Arc<AtomicBool>,
        mut resync_rx: mpsc::UnboundedReceiver<()>,
        is_syncing: Arc<AtomicBool>,
        watch_error_count: Arc<AtomicU64>,
    ) {
        let caps = backend.capabilities().await;
        if !caps.watch || !caps.ordered_replication_log {
            warn!(
                "Session backend does not support ordered watch. Local cache reads will be bypassed."
            );
            watch_ready.store(false, Ordering::Release);
            return;
        }

        let mut seq = 0;
        let mut initialized = false;

        loop {
            while resync_rx.try_recv().is_ok() {
                watch_ready.store(false, Ordering::Release);
                is_syncing.store(true, Ordering::Release);
                {
                    let mut lock = cache.write().await;
                    lock.clear();
                }
                is_syncing.store(false, Ordering::Release);
                initialized = false;
            }

            if !initialized {
                watch_ready.store(false, Ordering::Release);
                match backend.max_replication_sequence().await {
                    Ok(s) => {
                        seq = s;
                        last_sequence.store(seq, Ordering::Release);
                        initialized = true;
                    }
                    Err(err) => {
                        warn!(
                            "Failed to get initial max replication sequence. Retrying: {}",
                            store_error_kind(&err)
                        );
                        watch_error_count.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                        continue;
                    }
                }
            }

            let watch_start = match next_replication_sequence(seq) {
                Ok(sequence) => sequence,
                Err(err) => {
                    warn!(
                        "Cannot advance the replication watch cursor. Retrying: {}",
                        store_error_kind(&err)
                    );
                    watch_error_count.fetch_add(1, Ordering::Relaxed);
                    watch_ready.store(false, Ordering::Release);
                    is_syncing.store(true, Ordering::Release);
                    cache.write().await.clear();
                    is_syncing.store(false, Ordering::Release);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    initialized = false;
                    continue;
                }
            };

            watch_ready.store(false, Ordering::Release);
            let mut watch_stream = match backend.watch(watch_start).await {
                Ok(stream) => {
                    info!(
                        "Successfully started watch stream from sequence {}",
                        watch_start
                    );
                    watch_ready.store(true, Ordering::Release);
                    stream
                }
                Err(err) => {
                    warn!(
                        "Failed to start watch stream from sequence {}. Retrying after resync: {}",
                        watch_start,
                        store_error_kind(&err)
                    );
                    watch_error_count.fetch_add(1, Ordering::Relaxed);

                    is_syncing.store(true, Ordering::Release);
                    {
                        let mut lock = cache.write().await;
                        lock.clear();
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    match backend.max_replication_sequence().await {
                        Ok(s) => {
                            seq = s;
                            last_sequence.store(seq, Ordering::Release);
                            initialized = true;
                        }
                        Err(err) => {
                            error!(
                                "Failed to get max sequence during retry: {}",
                                store_error_kind(&err)
                            );
                            initialized = false;
                        }
                    }
                    is_syncing.store(false, Ordering::Release);
                    continue;
                }
            };

            let mut should_resync = false;
            use futures_util::StreamExt;

            loop {
                tokio::select! {
                    res = watch_stream.next() => {
                    match res {
                        Some(Ok(entry)) => {
                            let entry = match entry.into_validated() {
                                Ok(entry) => entry,
                                Err(err) => {
                                    warn!(
                                        "Invalid replication watch entry. Triggering resync: {}",
                                        store_error_kind(&err)
                                    );
                                    watch_error_count.fetch_add(1, Ordering::Relaxed);
                                    watch_ready.store(false, Ordering::Release);
                                    should_resync = true;
                                    break;
                                }
                            };
                            let entry_seq = entry.sequence;
                            let current_last = last_sequence.load(Ordering::Acquire);

                            if entry_seq <= current_last {
                                debug!("Ignoring duplicate entry at seq {}", entry_seq);
                                continue;
                            }
                            let expected = match next_replication_sequence(current_last) {
                                Ok(sequence) => sequence,
                                Err(err) => {
                                    warn!(
                                        "Cannot advance the replication cursor. Triggering resync: {}",
                                        store_error_kind(&err)
                                    );
                                    watch_error_count.fetch_add(1, Ordering::Relaxed);
                                    watch_ready.store(false, Ordering::Release);
                                    should_resync = true;
                                    break;
                                }
                            };
                            if entry_seq > expected {
                                warn!(
                                    "Sequence gap detected: entry_seq={}, expected={}. Triggering resync.",
                                    entry_seq,
                                    expected
                                );
                                watch_error_count.fetch_add(1, Ordering::Relaxed);
                                watch_ready.store(false, Ordering::Release);
                                should_resync = true;
                                break;
                            }

                            let mut lock = cache.write().await;
                            Self::apply_invalidation_op(&mut lock, entry.op);
                            last_sequence.store(entry_seq, Ordering::Release);
                            seq = entry_seq;
                        }
                        Some(Err(err)) => {
                            error!(
                                "Error in watch stream. Triggering resync: {}",
                                store_error_kind(&err)
                            );
                            watch_error_count.fetch_add(1, Ordering::Relaxed);
                            watch_ready.store(false, Ordering::Release);
                            should_resync = true;
                            break;
                        }
                        None => {
                            warn!("Watch stream ended. Reconnecting.");
                            watch_ready.store(false, Ordering::Release);
                            break;
                        }
                    }
                }
                manual = resync_rx.recv() => {
                    if manual.is_none() {
                        // Channel closed, cache is dropping. Terminate watch loop.
                        return;
                    }
                    info!("Manual resync triggered.");
                    watch_ready.store(false, Ordering::Release);
                    should_resync = true;
                    break;
                    }
                }
            }

            if should_resync {
                watch_ready.store(false, Ordering::Release);
                is_syncing.store(true, Ordering::Release);
                {
                    let mut lock = cache.write().await;
                    lock.clear();
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                match backend.max_replication_sequence().await {
                    Ok(s) => {
                        seq = s;
                        last_sequence.store(seq, Ordering::Release);
                        initialized = true;
                        info!("Resync complete, updated seq to {}", seq);
                    }
                    Err(err) => {
                        error!(
                            "Resync failed to get max sequence: {}",
                            store_error_kind(&err)
                        );
                        initialized = false;
                    }
                }
                is_syncing.store(false, Ordering::Release);
            }
        }
    }

    fn apply_invalidation_op(
        lock: &mut HashMap<SessionKey, StoredSessionRecord>,
        op: ReplicationOp,
    ) {
        let mut pending = vec![op];
        while let Some(op) = pending.pop() {
            match op {
                ReplicationOp::CompareAndSet { key, .. } => {
                    debug!("Invalidating key from cache (CAS): {:?}", key);
                    lock.remove(&key);
                }
                ReplicationOp::DeleteFenced { key, .. } => {
                    debug!("Invalidating key from cache (Delete): {:?}", key);
                    lock.remove(&key);
                }
                ReplicationOp::RefreshTtl { key, .. } => {
                    debug!("Invalidating key from cache (RefreshTtl): {:?}", key);
                    lock.remove(&key);
                }
                ReplicationOp::AcquireLease { key, .. } => {
                    debug!("Invalidating key from cache (AcquireLease): {:?}", key);
                    lock.remove(&key);
                }
                ReplicationOp::RenewLease { key, .. } => {
                    debug!("Invalidating key from cache (RenewLease): {:?}", key);
                    lock.remove(&key);
                }
                ReplicationOp::ReleaseLease { key, .. } => {
                    debug!("Invalidating key from cache (ReleaseLease): {:?}", key);
                    lock.remove(&key);
                }
                ReplicationOp::Batch { ops } => pending.extend(ops),
            }
        }
    }
}

impl Drop for SessionCache {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.watch_task.try_lock() {
            if let Some(handle) = guard.take() {
                handle.abort();
            }
        }
    }
}

#[async_trait::async_trait]
impl SessionBackend for SessionCache {
    fn backend_instance_identity(&self) -> Option<BackendInstanceIdentity> {
        self.backend.backend_instance_identity()
    }

    fn peer_binding(&self) -> Option<BackendPeerBinding> {
        self.backend.peer_binding()
    }

    async fn capabilities(&self) -> BackendCapabilities {
        self.backend.capabilities().await
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        SessionCache::get(self, key).await
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        let key = op.key.clone();
        self.invalidate(&key).await;
        let result = self.backend.compare_and_set(op).await;
        if matches!(result, Ok(CompareAndSetResult::Success)) {
            self.invalidate(&key).await;
        }
        result
    }

    async fn delete_fenced(&self, lease: &opc_session_store::LeaseGuard) -> Result<(), StoreError> {
        let key = lease.key().clone();
        self.invalidate(&key).await;
        let result = self.backend.delete_fenced(lease).await;
        if result.is_ok() {
            self.invalidate(&key).await;
        }
        result
    }

    async fn refresh_ttl(
        &self,
        lease: &opc_session_store::LeaseGuard,
        ttl: Duration,
    ) -> Result<(), StoreError> {
        validate_session_ttl(ttl)?;
        let key = lease.key().clone();
        self.invalidate(&key).await;
        let result = self.backend.refresh_ttl(lease, ttl).await;
        if result.is_ok() {
            self.invalidate(&key).await;
        }
        result
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        ops.iter().try_for_each(SessionOp::validate_ttls)?;
        let results = self.backend.batch(ops.clone()).await?;
        for (op, result) in ops.iter().zip(results.iter()) {
            self.invalidate_successful_session_op(op, result).await;
        }
        Ok(results)
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.backend.max_replication_sequence().await
    }

    async fn probe_replication_head(
        &self,
    ) -> Result<u64, opc_session_store::ReplicaReadinessFailure> {
        self.backend.probe_replication_head().await
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
        let entries = self.backend.get_replication_log(start, limit).await?;
        validate_replication_log_page_owned(start, limit, entries)
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let entry = entry.into_validated()?;
        self.invalidate_replication_op(&entry.op).await;
        let result = self.backend.replicate_entry(entry.clone()).await;
        if result.is_ok() {
            self.invalidate_replication_op(&entry.op).await;
        }
        result
    }

    async fn rebuild_replication_state(
        &self,
        entries: Vec<ReplicationEntry>,
    ) -> Result<(), StoreError> {
        let entries = validate_replication_prefix_owned(entries)?;
        self.clear().await;
        let result = self.backend.rebuild_replication_state(entries).await;
        self.clear().await;
        result
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        let stream = self.backend.watch(start_sequence).await?;
        use futures_util::StreamExt;
        Ok(stream
            .map(|result| result.and_then(ReplicationEntry::into_validated))
            .boxed())
    }

    async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
        self.backend.next_lease_info().await
    }
}

impl SessionCache {
    async fn invalidate_successful_session_op(&self, op: &SessionOp, result: &SessionOpResult) {
        match (op, result) {
            (
                SessionOp::CompareAndSet(cas),
                SessionOpResult::CompareAndSet(Ok(CompareAndSetResult::Success)),
            ) => {
                self.invalidate(&cas.key).await;
            }
            (SessionOp::DeleteFenced { lease }, SessionOpResult::DeleteFenced(Ok(())))
            | (SessionOp::RefreshTtl { lease, .. }, SessionOpResult::RefreshTtl(Ok(()))) => {
                self.invalidate(lease.key()).await;
            }
            _ => {}
        }
    }

    async fn invalidate_replication_op(&self, op: &ReplicationOp) {
        let mut keys = Vec::new();
        collect_replication_op_keys(op, &mut keys);
        for key in keys {
            self.invalidate(&key).await;
        }
    }
}

fn collect_replication_op_keys(op: &ReplicationOp, keys: &mut Vec<SessionKey>) {
    let mut pending = vec![op];
    while let Some(op) = pending.pop() {
        match op {
            ReplicationOp::CompareAndSet { key, .. }
            | ReplicationOp::DeleteFenced { key, .. }
            | ReplicationOp::RefreshTtl { key, .. }
            | ReplicationOp::AcquireLease { key, .. }
            | ReplicationOp::RenewLease { key, .. }
            | ReplicationOp::ReleaseLease { key, .. } => {
                keys.push(key.clone());
            }
            ReplicationOp::Batch { ops } => pending.extend(ops),
        }
    }
}

fn store_error_kind(err: &StoreError) -> &'static str {
    match err {
        StoreError::NotFound => "not_found",
        StoreError::StaleFence => "stale_fence",
        StoreError::CasConflict => "cas_conflict",
        StoreError::CasIdempotencyConflict => "cas_idempotency_conflict",
        StoreError::CasIdempotencyOutcomeUnavailable => "cas_idempotency_outcome_unavailable",
        StoreError::BackendOperationOutcomeUnavailable => "backend_operation_outcome_unavailable",
        StoreError::CapabilityNotSupported(_) => "capability_not_supported",
        StoreError::BackendUnavailable(_) => "backend_unavailable",
        StoreError::InvalidKey(_) => "invalid_key",
        StoreError::InvalidReplicationSequence => "invalid_replication_sequence",
        StoreError::InvalidReplicationLogRange => "invalid_replication_log_range",
        StoreError::ReplicationLogPageTooLarge { .. } => "replication_log_page_too_large",
        StoreError::ReplicationLogCursorCompacted { .. } => "replication_log_cursor_compacted",
        StoreError::ReplicationWatchCatchUpRequired => "replication_watch_catch_up_required",
        StoreError::ReplicationOperationLimitExceeded => "replication_operation_limit_exceeded",
        StoreError::InvalidSessionTtl => "invalid_session_ttl",
        StoreError::LeaseHeld => "lease_held",
        StoreError::LeaseExpired => "lease_expired",
        StoreError::Crypto(_) => "crypto",
        StoreError::Serialization(_) => "serialization",
        StoreError::PayloadTooLarge { .. } => "payload_too_large",
        StoreError::InvalidRestoreScanRequest(_) => "invalid_restore_scan_request",
        StoreError::InvalidRestoreScanResponse(_) => "invalid_restore_scan_response",
        StoreError::RestoreScanPageTooLarge { .. } => "restore_scan_page_too_large",
        StoreError::RestoreScanResponseTooLarge { .. } => "restore_scan_response_too_large",
        StoreError::RestoreScanCursorStale => "restore_scan_cursor_stale",
        StoreError::RestoreScanWorkBudgetExceeded => "restore_scan_work_budget_exceeded",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bytes::Bytes;
    use futures_util::{stream, StreamExt};
    use opc_session_store::{
        validate_replication_page_owned, EncryptedSessionPayload, FakeSessionBackend, FenceToken,
        Generation, OwnerId, SessionKeyType, SessionLeaseManager, StateClass, StateType,
        MAX_REPLICATION_OPERATIONS_PER_ENTRY, MAX_REPLICATION_OPERATION_DEPTH, MAX_SESSION_TTL,
    };
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
    use std::sync::atomic::Ordering;
    use tokio::sync::mpsc;

    struct ScriptedWatchBackend {
        max_sequence: AtomicU64,
        watch_rx: Mutex<Option<mpsc::UnboundedReceiver<Result<ReplicationEntry, StoreError>>>>,
        yielded_tx: mpsc::UnboundedSender<()>,
        watch_calls: AtomicU64,
        refresh_calls: AtomicU64,
        batch_calls: AtomicU64,
        log_entries: Mutex<Vec<ReplicationEntry>>,
        replicate_calls: AtomicU64,
        rebuild_calls: AtomicU64,
    }

    #[async_trait]
    impl SessionBackend for ScriptedWatchBackend {
        async fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities {
                ordered_replication_log: true,
                watch: true,
                ..BackendCapabilities::minimal()
            }
        }

        async fn get(&self, _key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
            Ok(None)
        }

        async fn compare_and_set(
            &self,
            _op: CompareAndSet,
        ) -> Result<CompareAndSetResult, StoreError> {
            Err(StoreError::CapabilityNotSupported(
                "compare_and_set".to_string(),
            ))
        }

        async fn delete_fenced(
            &self,
            _lease: &opc_session_store::LeaseGuard,
        ) -> Result<(), StoreError> {
            Err(StoreError::CapabilityNotSupported(
                "delete_fenced".to_string(),
            ))
        }

        async fn refresh_ttl(
            &self,
            _lease: &opc_session_store::LeaseGuard,
            _ttl: Duration,
        ) -> Result<(), StoreError> {
            self.refresh_calls.fetch_add(1, Ordering::Relaxed);
            Err(StoreError::CapabilityNotSupported(
                "refresh_ttl".to_string(),
            ))
        }

        async fn batch(&self, _ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
            self.batch_calls.fetch_add(1, Ordering::Relaxed);
            Err(StoreError::CapabilityNotSupported("batch".to_string()))
        }

        async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
            Ok(self.max_sequence.load(Ordering::Acquire))
        }

        async fn get_replication_log(
            &self,
            _start: u64,
            _limit: usize,
        ) -> Result<Vec<ReplicationEntry>, StoreError> {
            Ok(self.log_entries.lock().await.clone())
        }

        async fn replicate_entry(&self, _entry: ReplicationEntry) -> Result<(), StoreError> {
            self.replicate_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn rebuild_replication_state(
            &self,
            _entries: Vec<ReplicationEntry>,
        ) -> Result<(), StoreError> {
            self.rebuild_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn watch(
            &self,
            _start_sequence: u64,
        ) -> Result<
            futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
            StoreError,
        > {
            self.watch_calls.fetch_add(1, Ordering::Relaxed);
            let rx = self
                .watch_rx
                .lock()
                .await
                .take()
                .expect("watch stream should be requested once");
            let yielded_tx = self.yielded_tx.clone();
            Ok(stream::unfold(rx, move |mut rx| {
                let yielded_tx = yielded_tx.clone();
                async move {
                    let item = rx.recv().await?;
                    let _ = yielded_tx.send(());
                    Some((item, rx))
                }
            })
            .boxed())
        }

        async fn next_lease_info(&self) -> Result<(u64, u64), StoreError> {
            Ok((1, 1))
        }
    }

    fn idle_scripted_backend(max_sequence: u64) -> Arc<ScriptedWatchBackend> {
        let (_entry_tx, entry_rx) = mpsc::unbounded_channel();
        let (yielded_tx, _yielded_rx) = mpsc::unbounded_channel();
        Arc::new(ScriptedWatchBackend {
            max_sequence: AtomicU64::new(max_sequence),
            watch_rx: Mutex::new(Some(entry_rx)),
            yielded_tx,
            watch_calls: AtomicU64::new(0),
            refresh_calls: AtomicU64::new(0),
            batch_calls: AtomicU64::new(0),
            log_entries: Mutex::new(Vec::new()),
            replicate_calls: AtomicU64::new(0),
            rebuild_calls: AtomicU64::new(0),
        })
    }

    fn cache_without_watch(backend: Arc<dyn SessionBackend>) -> SessionCache {
        let (resync_tx, _resync_rx) = mpsc::unbounded_channel();
        SessionCache {
            backend,
            cache: Arc::new(RwLock::new(HashMap::new())),
            last_sequence: Arc::new(AtomicU64::new(0)),
            watch_ready: Arc::new(AtomicBool::new(false)),
            resync_tx,
            is_syncing: Arc::new(AtomicBool::new(false)),
            watch_error_count: Arc::new(AtomicU64::new(0)),
            watch_task: Mutex::new(None),
        }
    }

    fn test_key() -> SessionKey {
        SessionKey {
            tenant: TenantId::new("tenant-a").expect("tenant"),
            nf_kind: NetworkFunctionKind::from_static("amf"),
            key_type: SessionKeyType::SubscriberContext,
            stable_id: Bytes::copy_from_slice(b"cache-key")
                .try_into()
                .expect("valid stable ID"),
        }
    }

    fn test_record(key: SessionKey, generation: u64) -> StoredSessionRecord {
        StoredSessionRecord {
            key,
            generation: Generation::new(generation),
            owner: OwnerId::new("owner-a").expect("owner"),
            fence: FenceToken::new(1),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::from_static("amf-state"),
            expires_at: None,
            payload: EncryptedSessionPayload::new(b"payload"),
        }
    }

    async fn test_lease(key: &SessionKey) -> opc_session_store::LeaseGuard {
        FakeSessionBackend::new()
            .acquire(
                key,
                OwnerId::new("owner-a").expect("owner"),
                Duration::from_secs(30),
            )
            .await
            .expect("test lease")
    }

    fn invalid_ttl_entry(sequence: u64, key: SessionKey) -> ReplicationEntry {
        let timestamp = Timestamp::now_utc();
        ReplicationEntry {
            sequence,
            tx_id: format!("invalid-ttl-{sequence}")
                .try_into()
                .expect("valid transaction ID"),
            op: ReplicationOp::RefreshTtl {
                key,
                owner: OwnerId::new("owner-a").expect("owner"),
                fence: FenceToken::new(1),
                ttl: MAX_SESSION_TTL + Duration::from_nanos(1),
                expires_at: timestamp,
            },
            timestamp,
        }
    }

    fn delete_op(key: SessionKey) -> ReplicationOp {
        ReplicationOp::DeleteFenced {
            key,
            owner: OwnerId::new("owner-a").expect("owner"),
            fence: FenceToken::new(1),
        }
    }

    fn operation_tree_at_depth(depth: usize, key: SessionKey) -> ReplicationOp {
        let mut op = delete_op(key);
        for _ in 1..depth {
            op = ReplicationOp::Batch { ops: vec![op] };
        }
        op
    }

    fn over_depth_entry(sequence: u64, key: SessionKey) -> ReplicationEntry {
        ReplicationEntry {
            sequence,
            tx_id: format!("over-depth-{sequence}")
                .try_into()
                .expect("valid transaction ID"),
            op: operation_tree_at_depth(MAX_REPLICATION_OPERATION_DEPTH + 1, key),
            timestamp: Timestamp::now_utc(),
        }
    }

    fn over_count_entry(sequence: u64, key: SessionKey) -> ReplicationEntry {
        let mut ops = Vec::with_capacity(MAX_REPLICATION_OPERATIONS_PER_ENTRY);
        ops.push(delete_op(key));
        ops.extend(
            (1..MAX_REPLICATION_OPERATIONS_PER_ENTRY)
                .map(|_| ReplicationOp::Batch { ops: Vec::new() }),
        );
        ReplicationEntry {
            sequence,
            tx_id: format!("over-count-{sequence}")
                .try_into()
                .expect("valid transaction ID"),
            op: ReplicationOp::Batch { ops },
            timestamp: Timestamp::now_utc(),
        }
    }

    async fn wait_until_watch_ready(watch_ready: &AtomicBool) {
        for _ in 0..50 {
            if watch_ready.load(Ordering::Acquire) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("watch loop did not become ready");
    }

    #[tokio::test]
    async fn watch_cursor_waits_for_invalidation_before_advancing() {
        let key = test_key();
        let cache = Arc::new(RwLock::new(HashMap::from([(
            key.clone(),
            test_record(key.clone(), 1),
        )])));
        let last_sequence = Arc::new(AtomicU64::new(0));
        let watch_ready = Arc::new(AtomicBool::new(false));
        let is_syncing = Arc::new(AtomicBool::new(false));
        let watch_error_count = Arc::new(AtomicU64::new(0));
        let (_resync_tx, resync_rx) = mpsc::unbounded_channel();
        let (entry_tx, entry_rx) = mpsc::unbounded_channel();
        let (yielded_tx, mut yielded_rx) = mpsc::unbounded_channel();
        let backend = Arc::new(ScriptedWatchBackend {
            max_sequence: AtomicU64::new(0),
            watch_rx: Mutex::new(Some(entry_rx)),
            yielded_tx,
            watch_calls: AtomicU64::new(0),
            refresh_calls: AtomicU64::new(0),
            batch_calls: AtomicU64::new(0),
            log_entries: Mutex::new(Vec::new()),
            replicate_calls: AtomicU64::new(0),
            rebuild_calls: AtomicU64::new(0),
        });

        let handle = tokio::spawn(SessionCache::run_watch_loop(
            backend.clone(),
            cache.clone(),
            last_sequence.clone(),
            watch_ready.clone(),
            resync_rx,
            is_syncing,
            watch_error_count,
        ));
        wait_until_watch_ready(&watch_ready).await;

        let read_guard = cache.read().await;
        backend.max_sequence.store(1, Ordering::Release);
        entry_tx
            .send(Ok(ReplicationEntry {
                sequence: 1,
                tx_id: "tx-1".try_into().expect("valid transaction ID"),
                op: ReplicationOp::CompareAndSet {
                    key: key.clone(),
                    expected_generation: Some(Generation::new(1)),
                    credential_id: 1,
                    guard_expires_at: Timestamp::now_utc(),
                    new_record: test_record(key.clone(), 2),
                },
                timestamp: Timestamp::now_utc(),
            }))
            .expect("send watch entry");
        yielded_rx.recv().await.expect("watch entry yielded");

        for _ in 0..10 {
            tokio::task::yield_now().await;
            if last_sequence.load(Ordering::Acquire) == 1 {
                break;
            }
        }
        assert_eq!(
            last_sequence.load(Ordering::Acquire),
            0,
            "watch cursor advanced while the stale cache entry was still readable"
        );

        drop(read_guard);
        for _ in 0..50 {
            if last_sequence.load(Ordering::Acquire) == 1 && cache.read().await.is_empty() {
                handle.abort();
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        handle.abort();
        panic!("watch loop did not apply invalidation after cache lock was released");
    }

    #[tokio::test]
    async fn exhausted_watch_sequence_stays_alive_and_fail_closed() {
        let backend = idle_scripted_backend(u64::MAX);
        let cache = SessionCache::new(backend.clone());

        tokio::time::timeout(Duration::from_secs(1), async {
            while cache.watch_error_count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("sequence exhaustion must be observed without killing the watch task");

        assert_eq!(cache.last_sequence(), u64::MAX);
        assert!(!cache.is_watch_ready());
        assert_eq!(backend.watch_calls.load(Ordering::Relaxed), 0);
        assert!(
            !cache
                .watch_task
                .lock()
                .await
                .as_ref()
                .expect("watch task")
                .is_finished(),
            "sequence exhaustion must not panic or terminate the watch task"
        );
    }

    #[tokio::test]
    async fn oversized_direct_refresh_is_rejected_before_invalidation_or_delegation() {
        let backend = idle_scripted_backend(0);
        let cache = cache_without_watch(backend.clone());
        let key = test_key();
        let record = test_record(key.clone(), 1);
        let lease = test_lease(&key).await;
        cache
            .cache
            .write()
            .await
            .insert(key.clone(), record.clone());

        let error = cache
            .refresh_ttl(&lease, Duration::MAX)
            .await
            .expect_err("an oversized direct refresh must be rejected");

        assert_eq!(error, StoreError::InvalidSessionTtl);
        assert_eq!(backend.refresh_calls.load(Ordering::Relaxed), 0);
        assert_eq!(cache.cache.read().await.get(&key), Some(&record));
    }

    #[tokio::test]
    async fn oversized_later_batch_ttl_is_rejected_before_any_delegation() {
        let backend = idle_scripted_backend(0);
        let cache = cache_without_watch(backend.clone());
        let key = test_key();
        let record = test_record(key.clone(), 1);
        let lease = test_lease(&key).await;
        cache
            .cache
            .write()
            .await
            .insert(key.clone(), record.clone());

        let error = cache
            .batch(vec![
                SessionOp::Get { key: key.clone() },
                SessionOp::RefreshTtl {
                    lease,
                    ttl: MAX_SESSION_TTL + Duration::from_nanos(1),
                },
            ])
            .await
            .expect_err("the entire batch must be preflighted");

        assert_eq!(error, StoreError::InvalidSessionTtl);
        assert_eq!(backend.batch_calls.load(Ordering::Relaxed), 0);
        assert_eq!(cache.cache.read().await.get(&key), Some(&record));
    }

    #[tokio::test]
    async fn nested_replication_ttl_is_rejected_before_invalidation_or_delegation() {
        let backend = idle_scripted_backend(0);
        let cache = cache_without_watch(backend.clone());
        let key = test_key();
        let record = test_record(key.clone(), 1);
        cache
            .cache
            .write()
            .await
            .insert(key.clone(), record.clone());
        let invalid_op = invalid_ttl_entry(1, key.clone()).op;

        let error = cache
            .replicate_entry(ReplicationEntry {
                sequence: 1,
                tx_id: "nested-invalid-ttl"
                    .try_into()
                    .expect("valid transaction ID"),
                op: ReplicationOp::Batch {
                    ops: vec![
                        ReplicationOp::DeleteFenced {
                            key: key.clone(),
                            owner: OwnerId::new("owner-a").expect("owner"),
                            fence: FenceToken::new(1),
                        },
                        invalid_op,
                    ],
                },
                timestamp: Timestamp::now_utc(),
            })
            .await
            .expect_err("a nested oversized TTL must reject the whole entry");

        assert_eq!(error, StoreError::InvalidSessionTtl);
        assert_eq!(backend.replicate_calls.load(Ordering::Relaxed), 0);
        assert_eq!(cache.cache.read().await.get(&key), Some(&record));
    }

    #[tokio::test]
    async fn operation_limits_are_rejected_before_invalidation_clear_or_delegation() {
        let backend = idle_scripted_backend(0);
        let cache = cache_without_watch(backend.clone());
        let key = test_key();
        let record = test_record(key.clone(), 1);
        cache
            .cache
            .write()
            .await
            .insert(key.clone(), record.clone());

        let replicate_error = cache
            .replicate_entry(over_depth_entry(1, key.clone()))
            .await
            .expect_err("an over-depth entry must be rejected");
        assert_eq!(
            replicate_error,
            StoreError::ReplicationOperationLimitExceeded
        );
        assert_eq!(backend.replicate_calls.load(Ordering::Relaxed), 0);
        assert_eq!(cache.cache.read().await.get(&key), Some(&record));

        let rebuild_error = cache
            .rebuild_replication_state(vec![over_count_entry(1, key.clone())])
            .await
            .expect_err("an over-count rebuild must be rejected");
        assert_eq!(rebuild_error, StoreError::ReplicationOperationLimitExceeded);
        assert_eq!(backend.rebuild_calls.load(Ordering::Relaxed), 0);
        assert_eq!(cache.cache.read().await.get(&key), Some(&record));
    }

    #[tokio::test]
    async fn operation_limits_are_not_exposed_by_log_or_public_watch() {
        let backend = idle_scripted_backend(0);
        let cache = cache_without_watch(backend.clone());
        let key = test_key();
        backend
            .log_entries
            .lock()
            .await
            .push(over_depth_entry(1, key.clone()));

        let log_error = match cache.get_replication_log(1, 1).await {
            Err(error) => error,
            Ok(entries) => {
                drop(validate_replication_page_owned(entries));
                panic!("an over-depth log entry must not be exposed")
            }
        };
        assert_eq!(log_error, StoreError::ReplicationOperationLimitExceeded);
        let retained_entries = std::mem::take(&mut *backend.log_entries.lock().await);
        drop(validate_replication_page_owned(retained_entries));

        backend.log_entries.lock().await.push(ReplicationEntry {
            sequence: 100,
            tx_id: "wrong-range".try_into().expect("valid transaction ID"),
            op: ReplicationOp::Batch { ops: Vec::new() },
            timestamp: Timestamp::now_utc(),
        });
        assert_eq!(
            cache
                .get_replication_log(2, 1)
                .await
                .expect_err("a cache wrapper must reject a page after its requested range"),
            StoreError::InvalidReplicationSequence
        );
        backend.log_entries.lock().await.clear();

        let (entry_tx, entry_rx) = mpsc::unbounded_channel();
        let (yielded_tx, _yielded_rx) = mpsc::unbounded_channel();
        let watch_backend = Arc::new(ScriptedWatchBackend {
            max_sequence: AtomicU64::new(0),
            watch_rx: Mutex::new(Some(entry_rx)),
            yielded_tx,
            watch_calls: AtomicU64::new(0),
            refresh_calls: AtomicU64::new(0),
            batch_calls: AtomicU64::new(0),
            log_entries: Mutex::new(Vec::new()),
            replicate_calls: AtomicU64::new(0),
            rebuild_calls: AtomicU64::new(0),
        });
        let watch_cache = cache_without_watch(watch_backend);
        let mut stream = watch_cache.watch(1).await.expect("watch stream");
        entry_tx
            .send(Ok(over_count_entry(1, key)))
            .expect("send over-count watch entry");

        let item = stream.next().await.expect("watch item");
        let watch_error = match item {
            Err(error) => error,
            Ok(entry) => {
                drop(entry.into_validated());
                panic!("an over-count watch entry must not be exposed")
            }
        };
        assert_eq!(watch_error, StoreError::ReplicationOperationLimitExceeded);
    }

    #[tokio::test]
    async fn background_watch_rejects_operation_limit_before_touching_cached_state() {
        let key = test_key();
        let record = test_record(key.clone(), 1);
        let cache = Arc::new(RwLock::new(HashMap::from([(key.clone(), record.clone())])));
        let last_sequence = Arc::new(AtomicU64::new(0));
        let watch_ready = Arc::new(AtomicBool::new(false));
        let is_syncing = Arc::new(AtomicBool::new(false));
        let watch_error_count = Arc::new(AtomicU64::new(0));
        let (_resync_tx, resync_rx) = mpsc::unbounded_channel();
        let (entry_tx, entry_rx) = mpsc::unbounded_channel();
        let (yielded_tx, mut yielded_rx) = mpsc::unbounded_channel();
        let backend = Arc::new(ScriptedWatchBackend {
            max_sequence: AtomicU64::new(0),
            watch_rx: Mutex::new(Some(entry_rx)),
            yielded_tx,
            watch_calls: AtomicU64::new(0),
            refresh_calls: AtomicU64::new(0),
            batch_calls: AtomicU64::new(0),
            log_entries: Mutex::new(Vec::new()),
            replicate_calls: AtomicU64::new(0),
            rebuild_calls: AtomicU64::new(0),
        });

        let handle = tokio::spawn(SessionCache::run_watch_loop(
            backend.clone(),
            cache.clone(),
            last_sequence.clone(),
            watch_ready.clone(),
            resync_rx,
            is_syncing,
            watch_error_count.clone(),
        ));
        wait_until_watch_ready(&watch_ready).await;

        let read_guard = cache.read().await;
        backend.max_sequence.store(1, Ordering::Release);
        entry_tx
            .send(Ok(over_depth_entry(1, key.clone())))
            .expect("send over-depth watch entry");
        yielded_rx.recv().await.expect("watch entry yielded");
        tokio::time::timeout(Duration::from_secs(1), async {
            while watch_error_count.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("operation limit must be observed before waiting for the cache write lock");

        assert_eq!(last_sequence.load(Ordering::Acquire), 0);
        assert_eq!(read_guard.get(&key), Some(&record));
        assert!(!watch_ready.load(Ordering::Acquire));
        handle.abort();
        drop(read_guard);
    }

    #[tokio::test]
    async fn invalid_replication_ttl_is_not_exposed_by_log_or_watch() {
        let backend = idle_scripted_backend(0);
        let cache = cache_without_watch(backend.clone());
        let key = test_key();
        backend
            .log_entries
            .lock()
            .await
            .push(invalid_ttl_entry(1, key.clone()));

        assert_eq!(
            cache
                .get_replication_log(1, 1)
                .await
                .expect_err("invalid log entry must not be exposed"),
            StoreError::InvalidSessionTtl
        );

        let (entry_tx, entry_rx) = mpsc::unbounded_channel();
        let (yielded_tx, _yielded_rx) = mpsc::unbounded_channel();
        let watch_backend = Arc::new(ScriptedWatchBackend {
            max_sequence: AtomicU64::new(0),
            watch_rx: Mutex::new(Some(entry_rx)),
            yielded_tx,
            watch_calls: AtomicU64::new(0),
            refresh_calls: AtomicU64::new(0),
            batch_calls: AtomicU64::new(0),
            log_entries: Mutex::new(Vec::new()),
            replicate_calls: AtomicU64::new(0),
            rebuild_calls: AtomicU64::new(0),
        });
        let watch_cache = cache_without_watch(watch_backend);
        let mut stream = watch_cache.watch(1).await.expect("watch stream");
        entry_tx
            .send(Ok(invalid_ttl_entry(1, key)))
            .expect("send invalid watch entry");

        assert_eq!(
            stream
                .next()
                .await
                .expect("watch item")
                .expect_err("invalid watch entry must not be exposed"),
            StoreError::InvalidSessionTtl
        );
    }

    #[tokio::test]
    async fn background_watch_validates_ttl_before_touching_cached_state() {
        let key = test_key();
        let record = test_record(key.clone(), 1);
        let cache = Arc::new(RwLock::new(HashMap::from([(key.clone(), record.clone())])));
        let last_sequence = Arc::new(AtomicU64::new(0));
        let watch_ready = Arc::new(AtomicBool::new(false));
        let is_syncing = Arc::new(AtomicBool::new(false));
        let watch_error_count = Arc::new(AtomicU64::new(0));
        let (_resync_tx, resync_rx) = mpsc::unbounded_channel();
        let (entry_tx, entry_rx) = mpsc::unbounded_channel();
        let (yielded_tx, mut yielded_rx) = mpsc::unbounded_channel();
        let backend = Arc::new(ScriptedWatchBackend {
            max_sequence: AtomicU64::new(0),
            watch_rx: Mutex::new(Some(entry_rx)),
            yielded_tx,
            watch_calls: AtomicU64::new(0),
            refresh_calls: AtomicU64::new(0),
            batch_calls: AtomicU64::new(0),
            log_entries: Mutex::new(Vec::new()),
            replicate_calls: AtomicU64::new(0),
            rebuild_calls: AtomicU64::new(0),
        });

        let handle = tokio::spawn(SessionCache::run_watch_loop(
            backend.clone(),
            cache.clone(),
            last_sequence.clone(),
            watch_ready.clone(),
            resync_rx,
            is_syncing,
            watch_error_count.clone(),
        ));
        wait_until_watch_ready(&watch_ready).await;

        let read_guard = cache.read().await;
        backend.max_sequence.store(1, Ordering::Release);
        entry_tx
            .send(Ok(invalid_ttl_entry(1, key.clone())))
            .expect("send invalid watch entry");
        yielded_rx.recv().await.expect("watch entry yielded");
        tokio::time::timeout(Duration::from_secs(1), async {
            while watch_error_count.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("invalid TTL must be observed before waiting for the cache write lock");

        assert_eq!(last_sequence.load(Ordering::Acquire), 0);
        assert_eq!(read_guard.get(&key), Some(&record));
        assert!(!watch_ready.load(Ordering::Acquire));
        drop(read_guard);
        handle.abort();
    }

    #[tokio::test]
    async fn invalid_rebuild_ttl_is_rejected_before_delegation_or_cache_clear() {
        let backend = idle_scripted_backend(0);
        let cache = cache_without_watch(backend.clone());
        let key = test_key();
        let record = test_record(key.clone(), 1);
        cache
            .cache
            .write()
            .await
            .insert(key.clone(), record.clone());

        let error = cache
            .rebuild_replication_state(vec![invalid_ttl_entry(1, key.clone())])
            .await
            .expect_err("an invalid TTL must reject the whole rebuild");

        assert_eq!(error, StoreError::InvalidSessionTtl);
        assert_eq!(backend.rebuild_calls.load(Ordering::Relaxed), 0);
        assert_eq!(cache.cache.read().await.get(&key), Some(&record));
    }

    #[tokio::test]
    async fn zero_replication_entry_is_rejected_before_delegation_or_invalidation() {
        let backend = idle_scripted_backend(0);
        let cache = cache_without_watch(backend.clone());
        let key = test_key();
        let record = test_record(key.clone(), 1);
        cache
            .cache
            .write()
            .await
            .insert(key.clone(), record.clone());

        let error = cache
            .replicate_entry(ReplicationEntry {
                sequence: 0,
                tx_id: "zero-sequence".try_into().expect("valid transaction ID"),
                op: ReplicationOp::DeleteFenced {
                    key: key.clone(),
                    owner: OwnerId::new("owner-a").expect("owner"),
                    fence: FenceToken::new(1),
                },
                timestamp: Timestamp::now_utc(),
            })
            .await
            .expect_err("sequence zero must be rejected");

        assert_eq!(error, StoreError::InvalidReplicationSequence);
        assert_eq!(backend.replicate_calls.load(Ordering::Relaxed), 0);
        assert_eq!(cache.cache.read().await.get(&key), Some(&record));
    }

    #[tokio::test]
    async fn malformed_rebuild_prefix_is_rejected_before_delegation_or_cache_clear() {
        let backend = idle_scripted_backend(0);
        let cache = cache_without_watch(backend.clone());
        let key = test_key();
        let record = test_record(key.clone(), 1);
        cache
            .cache
            .write()
            .await
            .insert(key.clone(), record.clone());
        let timestamp = Timestamp::now_utc();

        let error = cache
            .rebuild_replication_state(vec![
                ReplicationEntry {
                    sequence: 1,
                    tx_id: "prefix-one".try_into().expect("valid transaction ID"),
                    op: ReplicationOp::Batch { ops: Vec::new() },
                    timestamp,
                },
                ReplicationEntry {
                    sequence: 3,
                    tx_id: "prefix-gap".try_into().expect("valid transaction ID"),
                    op: ReplicationOp::Batch { ops: Vec::new() },
                    timestamp,
                },
            ])
            .await
            .expect_err("a gapped rebuild prefix must be rejected");

        assert_eq!(error, StoreError::InvalidReplicationSequence);
        assert_eq!(backend.rebuild_calls.load(Ordering::Relaxed), 0);
        assert_eq!(cache.cache.read().await.get(&key), Some(&record));
    }
}
