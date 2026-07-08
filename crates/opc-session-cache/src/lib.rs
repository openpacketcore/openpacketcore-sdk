//! Production-grade session cache with key-scoped invalidation, sequence tracking,
//! and resume recovery (GAP-004-006).

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, warn};

use opc_session_store::{
    BackendCapabilities, CompareAndSet, CompareAndSetResult, ReplicationEntry, ReplicationOp,
    SessionBackend, SessionKey, SessionOp, SessionOpResult, StoreError, StoredSessionRecord,
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

            watch_ready.store(false, Ordering::Release);
            let mut watch_stream = match backend.watch(seq + 1).await {
                Ok(stream) => {
                    info!(
                        "Successfully started watch stream from sequence {}",
                        seq + 1
                    );
                    watch_ready.store(true, Ordering::Release);
                    stream
                }
                Err(err) => {
                    warn!(
                        "Failed to start watch stream from sequence {}. Retrying after resync: {}",
                        seq + 1,
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
                            let entry_seq = entry.sequence;
                            let current_last = last_sequence.load(Ordering::Acquire);

                            if entry_seq <= current_last {
                                debug!("Ignoring duplicate entry at seq {}", entry_seq);
                                continue;
                            } else if entry_seq > current_last + 1 {
                                warn!(
                                    "Sequence gap detected: entry_seq={}, expected={}. Triggering resync.",
                                    entry_seq,
                                    current_last + 1
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
            ReplicationOp::Batch { ops } => {
                for nested in ops {
                    Self::apply_invalidation_op(lock, nested);
                }
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
        let key = lease.key().clone();
        self.invalidate(&key).await;
        let result = self.backend.refresh_ttl(lease, ttl).await;
        if result.is_ok() {
            self.invalidate(&key).await;
        }
        result
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        let results = self.backend.batch(ops.clone()).await?;
        for (op, result) in ops.iter().zip(results.iter()) {
            self.invalidate_successful_session_op(op, result).await;
        }
        Ok(results)
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        self.backend.max_replication_sequence().await
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        self.backend.get_replication_log(start, limit).await
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
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
        self.backend.watch(start_sequence).await
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
    match op {
        ReplicationOp::CompareAndSet { key, .. }
        | ReplicationOp::DeleteFenced { key, .. }
        | ReplicationOp::RefreshTtl { key, .. }
        | ReplicationOp::AcquireLease { key, .. }
        | ReplicationOp::RenewLease { key, .. }
        | ReplicationOp::ReleaseLease { key, .. } => {
            keys.push(key.clone());
        }
        ReplicationOp::Batch { ops } => {
            for op in ops {
                collect_replication_op_keys(op, keys);
            }
        }
    }
}

fn store_error_kind(err: &StoreError) -> &'static str {
    match err {
        StoreError::NotFound => "not_found",
        StoreError::StaleFence => "stale_fence",
        StoreError::CasConflict => "cas_conflict",
        StoreError::CapabilityNotSupported(_) => "capability_not_supported",
        StoreError::BackendUnavailable(_) => "backend_unavailable",
        StoreError::InvalidKey(_) => "invalid_key",
        StoreError::LeaseHeld => "lease_held",
        StoreError::LeaseExpired => "lease_expired",
        StoreError::Crypto(_) => "crypto",
        StoreError::Serialization(_) => "serialization",
        StoreError::PayloadTooLarge { .. } => "payload_too_large",
        StoreError::InvalidRestoreScanRequest(_) => "invalid_restore_scan_request",
        StoreError::RestoreScanPageTooLarge { .. } => "restore_scan_page_too_large",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use bytes::Bytes;
    use futures_util::{stream, StreamExt};
    use opc_session_store::{
        EncryptedSessionPayload, FenceToken, Generation, OwnerId, SessionKeyType, StateClass,
        StateType,
    };
    use opc_types::{NetworkFunctionKind, TenantId, Timestamp};
    use std::sync::atomic::Ordering;
    use tokio::sync::mpsc;

    struct ScriptedWatchBackend {
        max_sequence: AtomicU64,
        watch_rx: Mutex<Option<mpsc::UnboundedReceiver<Result<ReplicationEntry, StoreError>>>>,
        yielded_tx: mpsc::UnboundedSender<()>,
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
            Err(StoreError::CapabilityNotSupported(
                "refresh_ttl".to_string(),
            ))
        }

        async fn batch(&self, _ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
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
            Ok(Vec::new())
        }

        async fn replicate_entry(&self, _entry: ReplicationEntry) -> Result<(), StoreError> {
            Err(StoreError::CapabilityNotSupported(
                "replicate_entry".to_string(),
            ))
        }

        async fn rebuild_replication_state(
            &self,
            _entries: Vec<ReplicationEntry>,
        ) -> Result<(), StoreError> {
            Err(StoreError::CapabilityNotSupported(
                "rebuild_replication_state".to_string(),
            ))
        }

        async fn watch(
            &self,
            _start_sequence: u64,
        ) -> Result<
            futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
            StoreError,
        > {
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

    fn test_key() -> SessionKey {
        SessionKey {
            tenant: TenantId::new("tenant-a").expect("tenant"),
            nf_kind: NetworkFunctionKind::from_static("amf"),
            key_type: SessionKeyType::SubscriberContext,
            stable_id: Bytes::copy_from_slice(b"cache-key"),
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
                tx_id: "tx-1".to_string(),
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
}
