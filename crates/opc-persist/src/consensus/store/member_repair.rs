//! Restore a lost fixed voter's prefix before admitting any engine response.
//!
//! The incumbent leader's recorded matching index must never be reset. Its
//! snapshot covers the complete log present when recovery starts, including
//! any accepted tail, and comes from a fresh quorum read with this empty
//! replacement unable to vote or acknowledge heartbeats. Ordinary replication
//! resumes only after Openraft has durably installed that snapshot and vote.

use opc_consensus::engine::{Snapshot, SnapshotMeta, Vote};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::time::Instant;

use super::*;
use crate::consensus::snapshot_timing::{snapshot_transfer_budget, SNAPSHOT_WORK_BASE_BUDGET};

#[cfg(test)]
#[path = "member_repair_snapshot_tests.rs"]
mod tests;

const CHUNK_BYTES: usize = 128 * 1024;

/// The cursor offset reserved for a cheap snapshot-size probe. A normal repair
/// chunk never uses this offset because it would exceed every admissible
/// artifact length.
const REPAIR_PROBE_OFFSET: u64 = u64::MAX;

#[derive(Serialize, Deserialize)]
struct RepairRequest {
    compatibility: ConfigPeerCompatibility,
    budget: ForwardedBudget,
    cursor: Option<RepairCursor>,
}

#[derive(Serialize, Deserialize)]
struct RepairCursor {
    vote: Vote<ConsensusNodeId>,
    snapshot_id: String,
    offset: u64,
}

#[derive(Serialize, Deserialize)]
struct RepairChunk {
    vote: Vote<ConsensusNodeId>,
    meta: SnapshotMeta<ConsensusNodeId, EmptyNode>,
    offset: u64,
    bytes: Vec<u8>,
    done: bool,
}

/// One transfer's verified snapshot. Built by the first chunk request and
/// reused by every later chunk request for the same vote and snapshot ID, so a
/// snapshot is verified once per transfer instead of once per 128 KiB cursor
/// chunk (#1339).
#[derive(Default)]
pub(super) struct RepairSnapshotCache {
    entry: tokio::sync::Mutex<Option<CachedRepairSnapshot>>,
}

struct CachedRepairSnapshot {
    vote: Vote<ConsensusNodeId>,
    meta: SnapshotMeta<ConsensusNodeId, EmptyNode>,
    length: u64,
    snapshot: Snapshot<ConfigRaftTypeConfig>,
}

fn valid_repair_probe(
    source: ConsensusNodeId,
    chunk: &RepairChunk,
    members: &BTreeSet<ConsensusNodeId>,
) -> bool {
    chunk.vote.is_committed()
        && chunk.vote.leader_id.voted_for() == Some(source)
        && chunk.meta.last_log_id.is_some()
        && exact_uniform_voter_membership(&chunk.meta.last_membership, members)
        && chunk.offset > 0
        // Mirror the leader's own reply bound: a compromised member cannot
        // claim an arbitrarily large envelope and stretch the derived repair
        // attempt deadline to the 8 h ceiling.
        && chunk.offset <= storage::SNAPSHOT_MAX_ENVELOPE_BYTES
        && chunk.bytes.is_empty()
        && chunk.done
}

pub(super) struct RepairDownload {
    source: ConsensusNodeId,
    vote: Vote<ConsensusNodeId>,
    meta: SnapshotMeta<ConsensusNodeId, EmptyNode>,
    snapshot: Box<crate::consensus::snapshot_file::ConfigSnapshotFile>,
    offset: u64,
    chunk: Option<RepairChunk>,
    done: bool,
    rediscover: bool,
}

fn valid_first_repair_chunk(
    source: ConsensusNodeId,
    chunk: &RepairChunk,
    members: &BTreeSet<ConsensusNodeId>,
) -> bool {
    chunk.vote.is_committed()
        && chunk.vote.leader_id.voted_for() == Some(source)
        && chunk.meta.last_log_id.is_some()
        && exact_uniform_voter_membership(&chunk.meta.last_membership, members)
        && chunk.offset == 0
        && chunk.bytes.len() <= CHUNK_BYTES
        && (!chunk.bytes.is_empty() || chunk.done)
}

fn same_repair_snapshot(
    download: &RepairDownload,
    source: ConsensusNodeId,
    first: &RepairChunk,
) -> bool {
    download.source == source && download.vote == first.vote && download.meta == first.meta
}

async fn read_cached_repair_chunk(
    entry: &mut CachedRepairSnapshot,
    offset: u64,
) -> Result<RepairChunk, PersistError> {
    let length = entry.length;
    if offset > length || length > storage::SNAPSHOT_MAX_ENVELOPE_BYTES {
        return Err(consensus_unavailable());
    }
    let chunk_bytes = (length - offset).min(CHUNK_BYTES as u64);
    let mut bytes = vec![0; chunk_bytes as usize];
    // The cached descriptor is owned by this request while the cache lock is
    // held; the read is bounded by one chunk.
    entry
        .snapshot
        .snapshot
        .seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|_| consensus_unavailable())?;
    entry
        .snapshot
        .snapshot
        .read_exact(&mut bytes)
        .await
        .map_err(|_| consensus_unavailable())?;
    Ok(RepairChunk {
        vote: entry.vote,
        meta: entry.meta.clone(),
        offset,
        bytes,
        done: offset + chunk_bytes == length,
    })
}

pub(super) async fn handle(store: &ConsensusConfigStore, payload: &[u8]) -> ConsensusWireResponse {
    let request: RepairRequest = match decode_config_wire(payload) {
        Ok(request) => request,
        Err(_) => return protocol_rejection(),
    };
    if request.compatibility != store.peer_compatibility() || store.inner.voter_profile.is_some() {
        return ConsensusWireResponse {
            result: Err(ConsensusPeerError::ScopeMismatch),
        };
    }
    let Some(deadline) = request
        .budget
        .inbound_deadline(store.inner.operation_timeout)
    else {
        return protocol_rejection();
    };
    match tokio::time::timeout_at(
        deadline,
        store.repair_snapshot_chunk(request.cursor, deadline),
    )
    .await
    {
        Ok(Ok(chunk)) => encode_service_reply(&chunk),
        _ => ConsensusWireResponse {
            result: Err(ConsensusPeerError::Unavailable),
        },
    }
}

impl ConsensusConfigStore {
    fn repair_source_vote(&self) -> Option<Vote<ConsensusNodeId>> {
        self.require_admission().ok()?;
        map_watch_snapshot(&self.inner.raft.metrics(), |metrics| {
            (metrics.running_state.is_ok()
                && metrics.current_leader == Some(self.inner.local_node_id)
                && metrics.vote.is_committed())
            .then_some(metrics.vote)
        })
    }

    async fn repair_snapshot_chunk(
        &self,
        cursor: Option<RepairCursor>,
        deadline: Instant,
    ) -> Result<RepairChunk, PersistError> {
        let vote = self
            .repair_source_vote()
            .ok_or_else(consensus_unavailable)?;
        if let Some(cursor) = cursor.as_ref() {
            if cursor.offset == REPAIR_PROBE_OFFSET {
                // Cheap size probe: read the durable published-snapshot row
                // instead of hashing the artifact. The requester derives its
                // transfer deadline from this exact envelope length.
                return self.repair_probe_snapshot(vote, deadline).await;
            }
            if cursor.vote != vote || cursor.snapshot_id.len() > 128 {
                return Err(consensus_unavailable());
            }
        }

        // Wait for the required cut before taking the cache lock so a slow
        // snapshot build cannot block other repair requests behind it.
        let required_cut = if cursor.is_none() {
            // Matching may include an accepted but not yet applied suffix.
            // A snapshot of only the current committed cut is insufficient.
            let required = self.inner.raft.metrics().borrow().last_log_index;
            self.wait_for_snapshot_cut(required, vote, deadline).await?;
            required
        } else {
            None
        };

        let mut cache = self.inner.repair_snapshot_cache.entry.lock().await;
        let requested_snapshot_id = cursor.as_ref().map(|cursor| cursor.snapshot_id.as_str());
        let refresh = match cache.as_ref() {
            Some(entry) => {
                let vote_changed = entry.vote != vote;
                let snapshot_changed = requested_snapshot_id
                    .is_some_and(|snapshot_id| entry.meta.snapshot_id != snapshot_id);
                let cut_not_covered = required_cut.is_some_and(|required| {
                    entry
                        .meta
                        .last_log_id
                        .is_none_or(|cut| cut.index < required)
                });
                vote_changed || snapshot_changed || cut_not_covered
            }
            None => true,
        };
        if refresh {
            *cache = Some(
                self.load_repair_snapshot(vote, requested_snapshot_id, required_cut, deadline)
                    .await?,
            );
        }
        let entry = cache.as_mut().ok_or_else(consensus_unavailable)?;
        let offset = cursor.as_ref().map_or(0, |cursor| cursor.offset);
        let chunk = read_cached_repair_chunk(entry, offset).await?;
        drop(cache);

        // The supervised check starts after this request was admitted; it
        // never reuses a read lease or joins an already-started read round.
        if !matches!(
            self.local_read_barrier(deadline).await,
            ReadBarrierReply::Ready(_)
        ) || self.repair_source_vote() != Some(vote)
        {
            return Err(consensus_unavailable());
        }
        Ok(chunk)
    }

    /// Verify the snapshot once and cache it for every later chunk request.
    async fn load_repair_snapshot(
        &self,
        vote: Vote<ConsensusNodeId>,
        snapshot_id: Option<&str>,
        required: Option<u64>,
        deadline: Instant,
    ) -> Result<CachedRepairSnapshot, PersistError> {
        let snapshot = tokio::time::timeout_at(deadline, self.inner.raft.get_snapshot())
            .await
            .map_err(|_| consensus_unavailable())?
            .map_err(|_| consensus_unavailable())?
            .ok_or_else(consensus_unavailable)?;
        if snapshot.meta.last_log_id.is_none()
            || !exact_uniform_voter_membership(&snapshot.meta.last_membership, &self.inner.members)
            || required.is_some_and(|required| {
                snapshot
                    .meta
                    .last_log_id
                    .is_none_or(|cut| cut.index < required)
            })
            || snapshot_id.is_some_and(|snapshot_id| snapshot.meta.snapshot_id != snapshot_id)
        {
            return Err(consensus_unavailable());
        }
        let mut snapshot = snapshot;
        let length = snapshot
            .snapshot
            .seek(std::io::SeekFrom::End(0))
            .await
            .map_err(|_| consensus_unavailable())?;
        if length == 0 || length > storage::SNAPSHOT_MAX_ENVELOPE_BYTES {
            return Err(consensus_unavailable());
        }
        snapshot
            .snapshot
            .seek(std::io::SeekFrom::Start(0))
            .await
            .map_err(|_| consensus_unavailable())?;
        let meta = snapshot.meta.clone();
        Ok(CachedRepairSnapshot {
            vote,
            meta,
            length,
            snapshot,
        })
    }

    /// Cheap, non-verifying published snapshot size probe.
    async fn repair_probe_snapshot(
        &self,
        vote: Vote<ConsensusNodeId>,
        deadline: Instant,
    ) -> Result<RepairChunk, PersistError> {
        let budget = deadline
            .saturating_duration_since(Instant::now())
            .min(SNAPSHOT_WORK_BASE_BUDGET);
        if budget.is_zero() {
            return Err(consensus_unavailable());
        }
        let identity = self.inner.identity;
        let members = self.inner.members.clone();
        let current = super::super::run_backend_sqlite_with_timeout(
            &self.inner.backend,
            budget,
            move |conn, _cancellation| {
                super::super::sqlite::read_current_snapshot_sync(conn, identity, &members)
            },
        )
        .await
        .map_err(|_| consensus_unavailable())?;
        let (meta, _file_name, _checksum, length) = current.ok_or_else(consensus_unavailable)?;
        if meta.last_log_id.is_none()
            || !exact_uniform_voter_membership(&meta.last_membership, &self.inner.members)
            || length == 0
            || length > storage::SNAPSHOT_MAX_ENVELOPE_BYTES
        {
            return Err(consensus_unavailable());
        }
        Ok(RepairChunk {
            vote,
            meta,
            offset: length,
            bytes: Vec::new(),
            done: true,
        })
    }

    /// Discover the authenticated leader snapshot's exact envelope length.
    ///
    /// The bounded probe lets the caller derive one size-following repair
    /// attempt deadline; an unknown or incompatible peer keeps the existing
    /// fixed attempt deadline.
    pub(super) async fn probe_repair_snapshot_size(&self, deadline: Instant) -> Option<u64> {
        let mut requests = futures_util::stream::FuturesUnordered::new();
        for target in self.inner.peers.keys().copied() {
            requests.push(async move { (target, self.fetch_repair_probe(target, deadline).await) });
        }
        use futures_util::StreamExt;
        while let Some((target, result)) = requests.next().await {
            if let Ok(chunk) = result {
                if valid_repair_probe(target, &chunk, &self.inner.members) {
                    return Some(chunk.offset);
                }
            }
        }
        None
    }

    /// A bounded repair attempt deadline derived from the snapshot size.
    pub(super) async fn repair_attempt_deadline(&self, fallback: Instant) -> Instant {
        match self.probe_repair_snapshot_size(fallback).await {
            Some(length) => super::super::snapshot_timing::derived_deadline(
                Instant::now(),
                snapshot_transfer_budget(length),
            )
            .map(|derived| derived.max(fallback))
            .unwrap_or(fallback),
            None => fallback,
        }
    }

    async fn fetch_repair_probe(
        &self,
        target: ConsensusNodeId,
        deadline: Instant,
    ) -> Result<RepairChunk, PersistError> {
        self.fetch_repair_chunk(
            target,
            Some(RepairCursor {
                vote: Vote::new(0, self.inner.local_node_id),
                snapshot_id: String::new(),
                offset: REPAIR_PROBE_OFFSET,
            }),
            deadline,
        )
        .await
    }

    pub(super) async fn recover_member_before_participation(
        &self,
        deadline: Instant,
    ) -> Result<(), ConfigConsensusOpenError> {
        let mut saved = tokio::select! {
            biased;
            _ = self.inner.shutdown.wait_started() => {
                return Err(ConfigConsensusOpenError::EngineUnavailable);
            }
            result = tokio::time::timeout_at(deadline, self.inner.repair_progress.lock()) => {
                result.map_err(|_| ConfigConsensusOpenError::ClusterFormationRejected)?
            }
        };
        // While an attempt runs, it owns the file locally. External
        // cancellation therefore drops it, including a resumed checkpoint.
        let mut progress = saved.take();
        let previous = progress.as_ref().map(|download| {
            (
                download.source,
                download.vote,
                download.meta.clone(),
                download.offset,
            )
        });
        let result = tokio::select! {
            biased;
            _ = self.inner.shutdown.wait_started() => {
                Err(ConfigConsensusOpenError::EngineUnavailable)
            }
            result = tokio::time::timeout_at(
                deadline,
                self.continue_member_recovery(&mut progress, deadline),
            ) => result.unwrap_or(Err(ConfigConsensusOpenError::ClusterFormationRejected)),
        };
        // An ordinary bounded attempt may need several calls for a large
        // snapshot. Preserve its verified cursor without extending this call.
        if Instant::now() >= deadline && !self.inner.shutdown.is_started() {
            if let Some(download) = progress.as_mut() {
                if !download.done
                    && previous
                        .as_ref()
                        .is_some_and(|(source, vote, meta, offset)| {
                            *source == download.source
                                && *vote == download.vote
                                && *meta == download.meta
                                && *offset == download.offset
                        })
                {
                    // A route that consumes the whole deadline must not pin
                    // every later attempt to a former leader. Keep the bytes
                    // while requiring fresh authority before using them again.
                    download.rediscover = true;
                }
            }
            *saved = progress;
        }
        result
    }

    async fn continue_member_recovery(
        &self,
        progress: &mut Option<RepairDownload>,
        deadline: Instant,
    ) -> Result<(), ConfigConsensusOpenError> {
        while self.inner.repair_pending.load(Ordering::Acquire) {
            if self.inner.shutdown.is_started() {
                return Err(ConfigConsensusOpenError::EngineUnavailable);
            }
            // Installation belongs to the engine once dispatched and can
            // finish after an earlier caller's deadline or cancellation.
            // Engine RPCs remain gated, so only this recovery could have
            // installed a snapshot on this initially empty repair root.
            if self.installed_repair_is_ready().await {
                *progress = None;
                self.inner.repair_pending.store(false, Ordering::Release);
                self.inner.raft.runtime_config().elect(true);
                self.inner.raft.runtime_config().heartbeat(true);
                return Ok(());
            }
            if progress.as_ref().is_none_or(|download| download.rediscover) {
                // A follower rejects immediately; an unreachable route must
                // not delay trying the actual leader.
                let mut requests = futures_util::stream::FuturesUnordered::new();
                for target in self.inner.peers.keys().copied() {
                    requests.push(async move {
                        (
                            target,
                            self.fetch_repair_chunk(target, None, deadline).await,
                        )
                    });
                }
                use futures_util::StreamExt;
                let mut source = None;
                while let Some((target, result)) = requests.next().await {
                    if let Ok(chunk) = result {
                        if valid_first_repair_chunk(target, &chunk, &self.inner.members) {
                            source = Some((target, chunk));
                            break;
                        }
                    }
                }
                drop(requests);
                if let Some((source, first)) = source {
                    if let Some(download) = progress
                        .as_mut()
                        .filter(|download| same_repair_snapshot(download, source, &first))
                    {
                        // The fresh quorum authenticated exactly the same
                        // snapshot. Its first chunk is a probe, not new data.
                        download.rediscover = false;
                    } else if let Ok(download) = self.start_repair_snapshot(source, first).await {
                        // Allocate and validate before dropping the old file.
                        // A new vote or snapshot always starts at offset zero.
                        *progress = Some(download);
                    }
                }
            }
            if progress
                .as_ref()
                .is_some_and(|download| !download.rediscover)
            {
                let restored = self.restore_repair_snapshot(progress, deadline).await;
                if restored.is_ok() {
                    continue;
                }
                if Instant::now() >= deadline {
                    return Err(ConfigConsensusOpenError::ClusterFormationRejected);
                }
                // Rejection before the deadline can mean the leader or its
                // snapshot changed. Keep verified bytes until fresh discovery
                // proves whether that exact checkpoint can still be resumed.
                if let Some(download) = progress.as_mut().filter(|download| !download.done) {
                    download.rediscover = true;
                    download.chunk = None;
                } else {
                    *progress = None;
                }
            }
            tokio::time::sleep_until((Instant::now() + ROUTE_RETRY_BACKOFF).min(deadline)).await;
        }
        Ok(())
    }

    async fn installed_repair_is_ready(&self) -> bool {
        let Ok(Some(snapshot)) = self.inner.raft.get_snapshot().await else {
            return false;
        };
        if snapshot.meta.last_log_id.is_none()
            || !exact_uniform_voter_membership(&snapshot.meta.last_membership, &self.inner.members)
            || self.inner.shutdown.is_started()
        {
            return false;
        }
        map_watch_snapshot(&self.inner.raft.metrics(), |current| {
            current.running_state.is_ok()
                && current.last_applied >= snapshot.meta.last_log_id
                && exact_uniform_voter_membership(
                    current.membership_config.as_ref(),
                    &self.inner.members,
                )
        })
    }

    async fn fetch_repair_chunk(
        &self,
        target: ConsensusNodeId,
        cursor: Option<RepairCursor>,
        deadline: Instant,
    ) -> Result<RepairChunk, PersistError> {
        self.call_peer(
            target,
            ConsensusRpcFamily::MemberRepair,
            &RepairRequest {
                compatibility: self.peer_compatibility(),
                budget: ForwardedBudget::from_deadline(deadline)?,
                cursor,
            },
            deadline,
        )
        .await
    }

    async fn start_repair_snapshot(
        &self,
        source: ConsensusNodeId,
        chunk: RepairChunk,
    ) -> Result<RepairDownload, PersistError> {
        if !valid_first_repair_chunk(source, &chunk, &self.inner.members) {
            return Err(consensus_unavailable());
        }
        let snapshot = self
            .inner
            .raft
            .begin_receiving_snapshot()
            .await
            .map_err(|_| consensus_unavailable())?;
        Ok(RepairDownload {
            source,
            vote: chunk.vote,
            meta: chunk.meta.clone(),
            snapshot,
            offset: 0,
            chunk: Some(chunk),
            done: false,
            rediscover: false,
        })
    }

    async fn restore_repair_snapshot(
        &self,
        progress: &mut Option<RepairDownload>,
        deadline: Instant,
    ) -> Result<(), PersistError> {
        let download = progress.as_mut().ok_or_else(consensus_unavailable)?;
        while !download.done {
            if download.chunk.is_none() {
                download.chunk = Some(
                    self.fetch_repair_chunk(
                        download.source,
                        Some(RepairCursor {
                            vote: download.vote,
                            snapshot_id: download.meta.snapshot_id.clone(),
                            offset: download.offset,
                        }),
                        deadline,
                    )
                    .await?,
                );
            }
            let chunk = download.chunk.as_ref().ok_or_else(consensus_unavailable)?;
            if chunk.vote != download.vote
                || chunk.meta != download.meta
                || chunk.offset != download.offset
                || chunk.bytes.len() > CHUNK_BYTES
                || chunk.bytes.is_empty() && !chunk.done
                || download.offset + chunk.bytes.len() as u64 > storage::SNAPSHOT_MAX_ENVELOPE_BYTES
            {
                return Err(consensus_unavailable());
            }
            // write_all is cancellable after a partial write. Always resume
            // at the last complete chunk, overwriting any uncommitted bytes.
            download
                .snapshot
                .seek(std::io::SeekFrom::Start(download.offset))
                .await
                .map_err(|_| consensus_unavailable())?;
            download
                .snapshot
                .write_all(&chunk.bytes)
                .await
                .map_err(|_| consensus_unavailable())?;
            download.offset += chunk.bytes.len() as u64;
            download.done = chunk.done;
            download.chunk = None;
        }
        download
            .snapshot
            .sync_all()
            .await
            .map_err(|_| consensus_unavailable())?;
        let download = progress.take().ok_or_else(consensus_unavailable)?;
        let response = self
            .inner
            .raft
            .install_full_snapshot(
                download.vote,
                Snapshot {
                    meta: download.meta.clone(),
                    snapshot: download.snapshot,
                },
            )
            .await
            .map_err(|_| consensus_unavailable())?;
        if response.vote != download.vote || self.inner.shutdown.is_started() {
            return Err(consensus_unavailable());
        }
        let mut metrics = self.inner.raft.metrics();
        loop {
            {
                let current = metrics.borrow_and_update();
                if current.running_state.is_err() || self.inner.shutdown.is_started() {
                    return Err(consensus_unavailable());
                }
                if current.last_applied >= download.meta.last_log_id
                    && exact_uniform_voter_membership(
                        current.membership_config.as_ref(),
                        &self.inner.members,
                    )
                {
                    return Ok(());
                }
            }
            metrics
                .changed()
                .await
                .map_err(|_| consensus_unavailable())?;
        }
    }
}
