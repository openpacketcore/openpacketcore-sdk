//! Restore a lost voter's prefix under its selected new identity.
//!
//! The incumbent leader's recorded matching index must never be reset. Its
//! snapshot covers the complete log present when recovery starts, including
//! any accepted tail, and comes from a fresh quorum read with this empty
//! replacement unable to vote or acknowledge heartbeats. Installation leaves
//! the candidate nonvoting until learner catch-up and membership promotion.

use opc_consensus::engine::{Snapshot, SnapshotMeta, Vote};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::time::Instant;

use super::*;

#[cfg(test)]
#[path = "member_repair_snapshot_tests.rs"]
mod tests;

const CHUNK_BYTES: usize = 128 * 1024;

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

pub(super) async fn handle(store: &ConsensusConfigStore, payload: &[u8]) -> ConsensusWireResponse {
    let request: RepairRequest = match decode_config_wire(payload) {
        Ok(request) => request,
        Err(_) => return protocol_rejection(),
    };
    if request.compatibility != store.peer_compatibility() {
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
    fn repair_source_members(&self) -> Option<BTreeSet<ConsensusNodeId>> {
        match &self.inner.voter_profile {
            Some(profile) => Some(
                profile
                    .admission
                    .durable_view()
                    .ok()?
                    .table()
                    .current_configuration()
                    .members
                    .iter()
                    .map(|member| member.identity.node_id())
                    .collect(),
            ),
            None => Some(self.inner.members.clone()),
        }
    }

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
        let (mut snapshot, offset) = if let Some(cursor) = cursor {
            if cursor.vote != vote || cursor.snapshot_id.len() > 128 {
                return Err(consensus_unavailable());
            }
            let snapshot = self
                .inner
                .raft
                .get_snapshot()
                .await
                .map_err(|_| consensus_unavailable())?
                .filter(|snapshot| snapshot.meta.snapshot_id == cursor.snapshot_id)
                .ok_or_else(consensus_unavailable)?;
            (snapshot, cursor.offset)
        } else {
            // Matching may include an accepted but not yet applied suffix.
            // A snapshot of only the current committed cut is insufficient.
            let required = self.inner.raft.metrics().borrow().last_log_index;
            self.wait_for_snapshot_cut(required, vote, deadline).await?;
            let snapshot = self
                .inner
                .raft
                .get_snapshot()
                .await
                .map_err(|_| consensus_unavailable())?
                .filter(|snapshot| snapshot.meta.last_log_id.map(|log| log.index) >= required)
                .ok_or_else(consensus_unavailable)?;
            (snapshot, 0)
        };
        let members = self
            .repair_source_members()
            .ok_or_else(consensus_unavailable)?;
        if !exact_uniform_voter_membership(&snapshot.meta.last_membership, &members)
            || snapshot.meta.last_log_id.is_none()
        {
            return Err(consensus_unavailable());
        }
        let length = snapshot
            .snapshot
            .seek(std::io::SeekFrom::End(0))
            .await
            .map_err(|_| consensus_unavailable())?;
        if offset > length || length > storage::SNAPSHOT_MAX_ENVELOPE_BYTES {
            return Err(consensus_unavailable());
        }
        snapshot
            .snapshot
            .seek(std::io::SeekFrom::Start(offset))
            .await
            .map_err(|_| consensus_unavailable())?;
        let mut bytes = vec![0; (length - offset).min(CHUNK_BYTES as u64) as usize];
        snapshot
            .snapshot
            .read_exact(&mut bytes)
            .await
            .map_err(|_| consensus_unavailable())?;
        // The supervised check starts after this request was admitted; it
        // never reuses a read lease or joins an already-started read round.
        if !matches!(
            self.local_read_barrier(deadline).await,
            ReadBarrierReply::Ready(_)
        ) || self.repair_source_vote() != Some(vote)
        {
            return Err(consensus_unavailable());
        }
        Ok(RepairChunk {
            vote,
            meta: snapshot.meta,
            offset,
            done: offset + bytes.len() as u64 == length,
            bytes,
        })
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
                if self.inner.voter_profile.is_none() {
                    self.inner.raft.runtime_config().elect(true);
                    self.inner.raft.runtime_config().heartbeat(true);
                }
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
        if let Some(profile) = &self.inner.voter_profile {
            // Pending candidates reject ordinary appends until a selected
            // snapshot has been installed. Its applied cut is sufficient to
            // finish downloading; application/voting admission still waits
            // for the separate learner and membership transitions.
            return profile.pulled_snapshot_is_applied(self).await;
        }
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
        if let Some(profile) = &self.inner.voter_profile {
            return profile
                .install_pulled_snapshot(
                    self,
                    download.source,
                    download.vote,
                    Snapshot {
                        meta: download.meta,
                        snapshot: download.snapshot,
                    },
                    deadline,
                )
                .await
                .map_err(|_| consensus_unavailable());
        }
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
