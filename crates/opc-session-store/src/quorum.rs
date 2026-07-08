//! In-process quorum coordination over a set of session replicas.
//!
//! `QuorumSessionStore` composes its replica backends directly in this
//! process and drives them through a shared, gap-free replication log: a
//! mutation commits once a strict majority (`n/2 + 1`) of replicas have
//! durably appended the identical log entry, and divergent or partially
//! written replicas are repaired back to the committed prefix before the next
//! operation proceeds. The networked transport that exposes a replica over a
//! wire protocol lives in the separate `opc-session-net` crate; from this
//! module's perspective a remote replica is simply another
//! `SessionStoreBackend` implementation handed to the coordinator.
//!
//! `FencedSessionReplica` wraps each replica with controllable online flags
//! and artificial lag so partition, failover, and split-brain scenarios can
//! be exercised in-process without real networking.

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use crate::backend::{
    CompareAndSet, CompareAndSetResult, ReplicationEntry, ReplicationOp, SessionBackend, SessionOp,
    SessionOpResult,
};
use crate::capability::BackendCapabilities;
use crate::clock::{Clock, SystemClock};
use crate::error::{LeaseError, StoreError};
use crate::lease::{LeaseGuard, SessionLeaseManager};
use crate::model::{FenceToken, OwnerId, SessionKey};
use crate::record::StoredSessionRecord;
use opc_types::Timestamp;

/// Helper trait combining SessionBackend and SessionLeaseManager
pub trait SessionStoreBackend: SessionBackend + SessionLeaseManager {}
impl<T: SessionBackend + SessionLeaseManager> SessionStoreBackend for T {}

/// A wrapper around a session replica node that supports simulated network lag,
/// online/offline states, and epoch/fencing checks.
#[derive(Clone)]
pub struct FencedSessionReplica {
    /// Position of this replica in the coordinator's replica set; used to
    /// address it during read-repair and partial-write rollback.
    pub id: usize,
    /// The actual backend plus lease manager for this replica — an in-memory
    /// or SQLite backend in tests, or a remote backend from `opc-session-net`
    /// in a distributed deployment.
    pub inner: Arc<dyn SessionStoreBackend>,
    /// Simulates the replica process itself being up. While `false`, every
    /// call through this wrapper fails with `StoreError::BackendUnavailable`,
    /// and the replica stops counting toward quorum.
    pub node_online: Arc<tokio::sync::Mutex<bool>>,
    /// Simulates the network path from this coordinator to the replica.
    /// Toggling it independently of `node_online` models an asymmetric
    /// partition: the replica is healthy but unreachable from here.
    pub client_online: Arc<tokio::sync::Mutex<bool>>,
    /// Optional artificial one-way delay injected before each call, for
    /// exercising slow-replica and replication-lag behavior.
    pub lag: Arc<tokio::sync::Mutex<Option<Duration>>>,
}

impl FencedSessionReplica {
    /// Wrap a backend as replica `id`, initially online with no injected lag.
    pub fn new(id: usize, inner: Arc<dyn SessionStoreBackend>) -> Self {
        Self {
            id,
            inner,
            node_online: Arc::new(tokio::sync::Mutex::new(true)),
            client_online: Arc::new(tokio::sync::Mutex::new(true)),
            lag: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Whether the replica is reachable: both the node itself and the client
    /// network path must be up. Offline replicas are skipped by the
    /// coordinator but still count in the quorum denominator.
    pub async fn is_online(&self) -> bool {
        *self.node_online.lock().await && *self.client_online.lock().await
    }

    /// Simulate the replica process going down (`false`) or recovering
    /// (`true`). A recovered replica is read-repaired to the committed log
    /// prefix before it serves quorum operations again.
    pub async fn set_node_online(&self, online: bool) {
        *self.node_online.lock().await = online;
    }

    /// Simulate losing (`false`) or restoring (`true`) the network path from
    /// the coordinator to this replica, independent of node health.
    pub async fn set_client_online(&self, online: bool) {
        *self.client_online.lock().await = online;
    }

    /// Inject (`Some`) or clear (`None`) an artificial delay applied before
    /// every call to this replica.
    pub async fn set_lag(&self, lag: Option<Duration>) {
        *self.lag.lock().await = lag;
    }

    /// Helper to simulate latency or check offline status.
    async fn check_network(&self) -> Result<(), StoreError> {
        if !self.is_online().await {
            return Err(StoreError::BackendUnavailable(
                "replica offline".to_string(),
            ));
        }
        let lag = *self.lag.lock().await;
        if let Some(dur) = lag {
            tokio::time::sleep(dur).await;
        }
        Ok(())
    }
}

/// Production-ready replicated quorum session-store adapter over a set of replicas.
///
/// This adapter coordinates CAS and lease operations across a majority of
/// replicas, backed by a durable replication log and read-repair recovery.
#[derive(Clone)]
pub struct QuorumSessionStore {
    replicas: Vec<FencedSessionReplica>,
    caps: BackendCapabilities,
    clock: Arc<dyn Clock>,
}

fn next_replication_sequence(committed_entries: &[ReplicationEntry]) -> Result<u64, StoreError> {
    committed_entries
        .last()
        .map(|entry| {
            entry.sequence.checked_add(1).ok_or_else(|| {
                StoreError::BackendUnavailable("replication sequence exhausted".into())
            })
        })
        .unwrap_or(Ok(1))
}

impl QuorumSessionStore {
    /// Build a coordinator over `replicas`, timestamping log entries with the
    /// real system clock.
    ///
    /// Quorum is a strict majority of the full replica set — `n/2 + 1` of all
    /// configured replicas, with offline ones still counted in the
    /// denominator — so a set of `n` replicas tolerates `(n-1)/2` failures.
    /// Reads likewise require a majority of replicas to return an identical
    /// record before a value is trusted, and every operation read-repairs
    /// divergent replicas to the committed log prefix first.
    pub fn new(replicas: Vec<FencedSessionReplica>) -> Self {
        let caps = BackendCapabilities {
            atomic_compare_and_set: true,
            monotonic_fencing_token: true,
            per_key_ttl: true,
            server_side_lease_expiry: true,
            ordered_replication_log: true,
            batch_write: true,
            watch: true,
            max_value_bytes: usize::MAX,
        };
        Self {
            replicas,
            caps,
            clock: Arc::new(SystemClock),
        }
    }

    /// Replace the clock used to timestamp replication entries and to compute
    /// lease `expires_at` deadlines — pair it with the replicas' clocks (e.g.
    /// a shared `TokioVirtualClock`) so lease-expiry tests are deterministic.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    fn quorum_size(&self) -> usize {
        (self.replicas.len() / 2) + 1
    }

    async fn online_replica_indices(&self) -> Result<Vec<usize>, StoreError> {
        let mut online_ids = Vec::new();
        for (idx, replica) in self.replicas.iter().enumerate() {
            if replica.check_network().await.is_err() {
                continue;
            }
            if replica.inner.max_replication_sequence().await.is_ok() {
                online_ids.push(idx);
            }
        }
        Ok(online_ids)
    }

    async fn committed_log_state(&self) -> Result<(Vec<usize>, Vec<ReplicationEntry>), StoreError> {
        let online_ids = self.online_replica_indices().await?;
        let quorum = self.quorum_size();
        if online_ids.len() < quorum {
            return Err(StoreError::BackendUnavailable("quorum not reached".into()));
        }

        let mut logs = Vec::with_capacity(online_ids.len());
        let mut max_seq = 0;
        for &id in &online_ids {
            let replica = &self.replicas[id];
            let seq = replica.inner.max_replication_sequence().await?;
            max_seq = max_seq.max(seq);
            let entries = if seq == 0 {
                Vec::new()
            } else {
                replica.inner.get_replication_log(1, seq as usize).await?
            };
            logs.push(entries);
        }

        let mut committed = Vec::new();
        for sequence in 1..=max_seq {
            let mut votes: HashMap<String, (ReplicationEntry, usize)> = HashMap::new();
            for log in &logs {
                let Some(entry) = log.get((sequence - 1) as usize) else {
                    continue;
                };
                if entry.sequence != sequence {
                    continue;
                }
                let key = serde_json::to_string(entry)
                    .map_err(|e| StoreError::Serialization(e.to_string()))?;
                votes
                    .entry(key)
                    .and_modify(|(_, count)| *count += 1)
                    .or_insert((entry.clone(), 1));
            }

            let Some((entry, _)) = votes.into_values().find(|(_, count)| *count >= quorum) else {
                break;
            };
            committed.push(entry);
        }

        Ok((online_ids, committed))
    }

    async fn repair_online_replicas(
        &self,
        online_ids: &[usize],
        committed_entries: &[ReplicationEntry],
    ) -> Result<(), StoreError> {
        for &id in online_ids {
            let replica = &self.replicas[id];
            let seq = replica.inner.max_replication_sequence().await.unwrap_or(0);
            let current = if seq == 0 {
                Vec::new()
            } else {
                replica
                    .inner
                    .get_replication_log(1, seq as usize)
                    .await
                    .unwrap_or_default()
            };
            if current != committed_entries {
                opc_redaction::metrics::METRICS
                    .session_replica_repair
                    .fetch_add(1, Ordering::Relaxed);
                opc_redaction::metrics::METRICS
                    .session_replica_catchup
                    .fetch_add(1, Ordering::Relaxed);
                replica
                    .inner
                    .rebuild_replication_state(committed_entries.to_vec())
                    .await?;
            }
        }
        Ok(())
    }

    async fn committed_and_repaired(
        &self,
    ) -> Result<(Vec<usize>, Vec<ReplicationEntry>), StoreError> {
        let (online_ids, committed_entries) = self.committed_log_state().await?;
        self.repair_online_replicas(&online_ids, &committed_entries)
            .await?;
        Ok((online_ids, committed_entries))
    }

    async fn replicate_mutation(&self, op: ReplicationOp) -> Result<(), StoreError> {
        let (online_ids, committed_entries) = self.committed_and_repaired().await?;
        let quorum = self.quorum_size();
        let next_seq = next_replication_sequence(&committed_entries)?;
        let tx_id = uuid::Uuid::new_v4().to_string();
        let entry = ReplicationEntry {
            sequence: next_seq,
            tx_id,
            op,
            timestamp: self.clock.now_utc(),
        };

        let mut successes = 0;
        let mut successful_ids = Vec::new();
        let mut last_err = None;
        for id in &online_ids {
            let replica = &self.replicas[*id];
            match replica.inner.replicate_entry(entry.clone()).await {
                Ok(()) => {
                    successes += 1;
                    successful_ids.push(*id);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        if successes >= quorum {
            opc_redaction::metrics::METRICS
                .session_quorum_write_success
                .fetch_add(1, Ordering::Relaxed);
            opc_redaction::metrics::METRICS
                .session_committed_replication_sequence
                .store(entry.sequence, Ordering::Relaxed);
            Ok(())
        } else {
            opc_redaction::metrics::METRICS
                .session_quorum_write_failure
                .fetch_add(1, Ordering::Relaxed);
            for id in successful_ids {
                opc_redaction::metrics::METRICS
                    .session_failed_partial_write_rollback
                    .fetch_add(1, Ordering::Relaxed);
                let _ = self.replicas[id]
                    .inner
                    .rebuild_replication_state(committed_entries.clone())
                    .await;
            }
            if let Some(err) = last_err {
                Err(err)
            } else {
                Err(StoreError::BackendUnavailable(
                    "quorum not reached for replication".into(),
                ))
            }
        }
    }

    pub(crate) async fn get_inner(
        &self,
        key: &SessionKey,
    ) -> Result<Option<StoredSessionRecord>, StoreError> {
        let (online_ids, _) = self.committed_and_repaired().await?;
        let quorum = self.quorum_size();

        // Query all online replicas and count occurrences of each result
        let mut results: Vec<Option<StoredSessionRecord>> = Vec::new();
        for id in &online_ids {
            let replica = &self.replicas[*id];
            if let Ok(rec) = replica.inner.get(key).await {
                results.push(rec);
            }
        }

        // Find the majority consensus
        let mut consensus_val = None;
        let mut consensus_found = false;

        for candidate in &results {
            let mut count = 0;
            for r in &results {
                match (candidate, r) {
                    (None, None) => count += 1,
                    (Some(c), Some(x))
                        if c.generation == x.generation
                            && c.owner == x.owner
                            && c.fence == x.fence
                            && c.state_class == x.state_class
                            && c.state_type == x.state_type
                            && c.expires_at == x.expires_at
                            && c.payload == x.payload =>
                    {
                        count += 1;
                    }
                    _ => {}
                }
            }
            if count >= quorum {
                consensus_val = candidate.clone();
                consensus_found = true;
                break;
            }
        }

        if consensus_found {
            Ok(consensus_val)
        } else {
            Err(StoreError::BackendUnavailable(
                "no quorum consensus for session record".into(),
            ))
        }
    }

    pub(crate) async fn watch_inner(
        &self,
        start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        let (online_ids, committed_entries) = self.committed_and_repaired().await?;
        let committed_seq = committed_entries
            .last()
            .map(|entry| entry.sequence)
            .unwrap_or(0);
        for id in online_ids {
            let replica = &self.replicas[id];
            if let Ok(seq) = replica.inner.max_replication_sequence().await {
                if seq >= committed_seq {
                    return replica.inner.watch(start_sequence).await;
                }
            }
        }
        Err(StoreError::BackendUnavailable(
            "no caught-up replica available for watch".into(),
        ))
    }
}

#[async_trait]
impl SessionBackend for QuorumSessionStore {
    async fn capabilities(&self) -> BackendCapabilities {
        let mut caps = self.caps;

        for replica in &self.replicas {
            let replica_caps = replica.inner.capabilities().await;
            caps.atomic_compare_and_set &= replica_caps.atomic_compare_and_set;
            caps.monotonic_fencing_token &= replica_caps.monotonic_fencing_token;
            caps.per_key_ttl &= replica_caps.per_key_ttl;
            caps.server_side_lease_expiry &= replica_caps.server_side_lease_expiry;
            caps.batch_write &= replica_caps.batch_write;
            caps.max_value_bytes = caps.max_value_bytes.min(replica_caps.max_value_bytes);
        }

        caps
    }

    async fn get(&self, key: &SessionKey) -> Result<Option<StoredSessionRecord>, StoreError> {
        let res = self.get_inner(key).await;
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .session_quorum_read_success
                .fetch_add(1, Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .session_quorum_read_failure
                .fetch_add(1, Ordering::Relaxed);
        }
        res
    }

    async fn compare_and_set(&self, op: CompareAndSet) -> Result<CompareAndSetResult, StoreError> {
        let op_clone = ReplicationOp::CompareAndSet {
            key: op.key.clone(),
            expected_generation: op.expected_generation,
            credential_id: op.lease.credential_id(),
            guard_expires_at: op.lease.expires_at(),
            new_record: op.new_record,
        };
        match self.replicate_mutation(op_clone).await {
            Ok(()) => Ok(CompareAndSetResult::Success),
            Err(StoreError::CasConflict) => {
                let current = self.get(op.lease.key()).await.unwrap_or(None);
                Ok(CompareAndSetResult::Conflict { current })
            }
            Err(e) => Err(e),
        }
    }

    async fn delete_fenced(&self, lease: &LeaseGuard) -> Result<(), StoreError> {
        let op = ReplicationOp::DeleteFenced {
            key: lease.key().clone(),
            owner: lease.owner().clone(),
            fence: lease.fence(),
        };
        let res = self.replicate_mutation(op).await;
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .session_lease_delete
                .fetch_add(1, Ordering::Relaxed);
        }
        res
    }

    async fn refresh_ttl(&self, lease: &LeaseGuard, ttl: Duration) -> Result<(), StoreError> {
        let now = self.clock.now_utc();
        let expires = *now.as_offset_datetime() + time::Duration::seconds_f64(ttl.as_secs_f64());
        let expires_at = Timestamp::from_offset_datetime(expires);
        let op = ReplicationOp::RefreshTtl {
            key: lease.key().clone(),
            owner: lease.owner().clone(),
            fence: lease.fence(),
            ttl,
            expires_at,
        };
        self.replicate_mutation(op).await
    }

    async fn batch(&self, ops: Vec<SessionOp>) -> Result<Vec<SessionOpResult>, StoreError> {
        let mut results = Vec::with_capacity(ops.len());
        for op in ops {
            let result = match op {
                SessionOp::Get { key } => SessionOpResult::Get(self.get(&key).await),
                SessionOp::CompareAndSet(cas) => {
                    SessionOpResult::CompareAndSet(self.compare_and_set(cas).await)
                }
                SessionOp::DeleteFenced { lease } => {
                    SessionOpResult::DeleteFenced(self.delete_fenced(&lease).await)
                }
                SessionOp::RefreshTtl { lease, ttl } => {
                    SessionOpResult::RefreshTtl(self.refresh_ttl(&lease, ttl).await)
                }
            };
            results.push(result);
        }
        Ok(results)
    }

    async fn max_replication_sequence(&self) -> Result<u64, StoreError> {
        let (_, committed_entries) = self.committed_log_state().await?;
        Ok(committed_entries
            .last()
            .map(|entry| entry.sequence)
            .unwrap_or(0))
    }

    async fn get_replication_log(
        &self,
        start: u64,
        limit: usize,
    ) -> Result<Vec<ReplicationEntry>, StoreError> {
        let (_, committed_entries) = self.committed_log_state().await?;
        Ok(committed_entries
            .into_iter()
            .filter(|entry| entry.sequence >= start)
            .take(limit)
            .collect())
    }

    async fn replicate_entry(&self, entry: ReplicationEntry) -> Result<(), StoreError> {
        let (online_ids, committed_entries) = self.committed_and_repaired().await?;
        let committed_seq = committed_entries
            .last()
            .map(|entry| entry.sequence)
            .unwrap_or(0);

        if entry.sequence <= committed_seq {
            let committed_entry = committed_entries
                .get((entry.sequence - 1) as usize)
                .ok_or_else(|| {
                    StoreError::BackendUnavailable("replication log sequence gap".into())
                })?;
            if committed_entry == &entry {
                return Ok(());
            }
            return Err(StoreError::BackendUnavailable(
                "divergent committed replication entry".into(),
            ));
        }

        if entry.sequence != committed_seq + 1 {
            return Err(StoreError::BackendUnavailable(
                "replication log sequence gap".into(),
            ));
        }

        let mut successes = 0;
        let mut successful_ids = Vec::new();
        let mut last_err = None;
        for id in online_ids {
            let replica = &self.replicas[id];
            match replica.inner.replicate_entry(entry.clone()).await {
                Ok(()) => {
                    successes += 1;
                    successful_ids.push(id);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }
        if successes >= self.quorum_size() {
            opc_redaction::metrics::METRICS
                .session_committed_replication_sequence
                .store(entry.sequence, Ordering::Relaxed);
            Ok(())
        } else {
            for id in successful_ids {
                opc_redaction::metrics::METRICS
                    .session_failed_partial_write_rollback
                    .fetch_add(1, Ordering::Relaxed);
                let _ = self.replicas[id]
                    .inner
                    .rebuild_replication_state(committed_entries.clone())
                    .await;
            }
            if let Some(err) = last_err {
                Err(err)
            } else {
                Err(StoreError::BackendUnavailable("quorum not reached".into()))
            }
        }
    }

    async fn watch(
        &self,
        start_sequence: u64,
    ) -> Result<
        futures_util::stream::BoxStream<'static, Result<ReplicationEntry, StoreError>>,
        StoreError,
    > {
        let res = self.watch_inner(start_sequence).await;
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .session_watch_resume_success
                .fetch_add(1, Ordering::Relaxed);
        } else {
            opc_redaction::metrics::METRICS
                .session_watch_resume_failure
                .fetch_add(1, Ordering::Relaxed);
        }
        res
    }
}

#[async_trait]
impl SessionLeaseManager for QuorumSessionStore {
    async fn acquire(
        &self,
        key: &SessionKey,
        owner: OwnerId,
        ttl: Duration,
    ) -> Result<LeaseGuard, LeaseError> {
        let (online_ids, _) = self
            .committed_and_repaired()
            .await
            .map_err(|e| LeaseError::Backend(e.to_string()))?;

        let mut max_fence = 0;
        let mut max_cred_id = 0;
        for &id in &online_ids {
            let replica = &self.replicas[id];
            let (f, c) = replica
                .inner
                .next_lease_info()
                .await
                .map_err(|e| LeaseError::Backend(e.to_string()))?;
            max_fence = max_fence.max(f);
            max_cred_id = max_cred_id.max(c);
        }

        let fence = FenceToken::new(max_fence);
        let credential_id = max_cred_id;
        let now = self.clock.now_utc();
        let expires = *now.as_offset_datetime() + time::Duration::seconds_f64(ttl.as_secs_f64());
        let expires_at = Timestamp::from_offset_datetime(expires);

        let op = ReplicationOp::AcquireLease {
            key: key.clone(),
            owner: owner.clone(),
            fence,
            credential_id,
            ttl,
            expires_at,
        };

        let res = self.replicate_mutation(op).await;
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .session_lease_acquire
                .fetch_add(1, Ordering::Relaxed);
        }
        res.map_err(LeaseError::from)?;

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
        let now = self.clock.now_utc();
        let expires = *now.as_offset_datetime() + time::Duration::seconds_f64(ttl.as_secs_f64());
        let expires_at = Timestamp::from_offset_datetime(expires);
        let op = ReplicationOp::RenewLease {
            key: lease.key().clone(),
            owner: lease.owner().clone(),
            fence: lease.fence(),
            credential_id: lease.credential_id(),
            ttl,
            expires_at,
        };

        let res = self.replicate_mutation(op).await;
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .session_lease_renew
                .fetch_add(1, Ordering::Relaxed);
        }
        res.map_err(LeaseError::from)?;

        Ok(LeaseGuard::new(
            lease.key().clone(),
            lease.owner().clone(),
            lease.fence(),
            now,
            expires_at,
            lease.credential_id(),
        ))
    }

    async fn release(&self, lease: LeaseGuard) -> Result<(), LeaseError> {
        let op = ReplicationOp::ReleaseLease {
            key: lease.key().clone(),
            owner: lease.owner().clone(),
            fence: lease.fence(),
            credential_id: lease.credential_id(),
        };

        let res = self.replicate_mutation(op).await;
        if res.is_ok() {
            opc_redaction::metrics::METRICS
                .session_lease_release
                .fetch_add(1, Ordering::Relaxed);
        }
        res.map_err(LeaseError::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_replication_sequence_reports_overflow() {
        let entry = ReplicationEntry {
            sequence: u64::MAX,
            tx_id: "max-sequence".into(),
            op: ReplicationOp::Batch { ops: Vec::new() },
            timestamp: Timestamp::now_utc(),
        };

        let err = next_replication_sequence(&[entry]).expect_err("sequence overflow must error");
        assert_eq!(
            err,
            StoreError::BackendUnavailable("replication sequence exhausted".into())
        );
    }
}
