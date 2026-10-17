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
            let mut metrics = self.inner.raft.metrics();
            let required = metrics.borrow_and_update().last_log_index;
            loop {
                let applied = metrics
                    .borrow_and_update()
                    .last_applied
                    .map(|log| log.index);
                if self.repair_source_vote() != Some(vote) {
                    return Err(consensus_unavailable());
                }
                if applied >= required {
                    break;
                }
                tokio::time::timeout_at(deadline, metrics.changed())
                    .await
                    .map_err(|_| consensus_unavailable())?
                    .map_err(|_| consensus_unavailable())?;
            }
            let snapshot = loop {
                drop(metrics.borrow_and_update());
                if self.repair_source_vote() != Some(vote) {
                    return Err(consensus_unavailable());
                }
                if let Some(snapshot) = self
                    .inner
                    .raft
                    .get_snapshot()
                    .await
                    .map_err(|_| consensus_unavailable())?
                {
                    if snapshot.meta.last_log_id.map(|log| log.index) >= required {
                        break snapshot;
                    }
                }
                self.inner
                    .raft
                    .trigger()
                    .snapshot()
                    .await
                    .map_err(|_| consensus_unavailable())?;
                tokio::time::timeout_at(deadline, metrics.changed())
                    .await
                    .map_err(|_| consensus_unavailable())?
                    .map_err(|_| consensus_unavailable())?;
            };
            (snapshot, 0)
        };
        if !exact_uniform_voter_membership(&snapshot.meta.last_membership, &self.inner.members)
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
        let recovery = async {
            let _guard = self.inner.repair_lock.lock().await;
            while self.inner.repair_pending.load(Ordering::Acquire) {
                if self.inner.shutdown.is_started() {
                    return Err(ConfigConsensusOpenError::EngineUnavailable);
                }
                // Discover in parallel: a follower rejects immediately and
                // an unreachable route cannot delay trying the actual leader.
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
                        source = Some((target, chunk));
                        break;
                    }
                }
                drop(requests);
                if let Some((source, first)) = source {
                    if self
                        .restore_repair_snapshot(source, first, deadline)
                        .await
                        .is_ok()
                    {
                        self.inner.repair_pending.store(false, Ordering::Release);
                        self.inner.raft.runtime_config().elect(true);
                        self.inner.raft.runtime_config().heartbeat(true);
                        return Ok(());
                    }
                }
                tokio::time::sleep_until((Instant::now() + ROUTE_RETRY_BACKOFF).min(deadline))
                    .await;
            }
            Ok(())
        };
        tokio::time::timeout_at(deadline, recovery)
            .await
            .unwrap_or(Err(ConfigConsensusOpenError::ClusterFormationRejected))
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

    async fn restore_repair_snapshot(
        &self,
        source: ConsensusNodeId,
        mut chunk: RepairChunk,
        deadline: Instant,
    ) -> Result<(), PersistError> {
        let vote = chunk.vote;
        let meta = chunk.meta.clone();
        if !vote.is_committed()
            || vote.leader_id.voted_for() != Some(source)
            || meta.last_log_id.is_none()
            || !exact_uniform_voter_membership(&meta.last_membership, &self.inner.members)
        {
            return Err(consensus_unavailable());
        }
        let mut snapshot = self
            .inner
            .raft
            .begin_receiving_snapshot()
            .await
            .map_err(|_| consensus_unavailable())?;
        let mut offset = 0_u64;
        loop {
            if chunk.vote != vote
                || chunk.meta != meta
                || chunk.offset != offset
                || chunk.bytes.len() > CHUNK_BYTES
                || chunk.bytes.is_empty() && !chunk.done
                || offset + chunk.bytes.len() as u64 > storage::SNAPSHOT_MAX_ENVELOPE_BYTES
            {
                return Err(consensus_unavailable());
            }
            snapshot
                .write_all(&chunk.bytes)
                .await
                .map_err(|_| consensus_unavailable())?;
            offset += chunk.bytes.len() as u64;
            if chunk.done {
                break;
            }
            chunk = self
                .fetch_repair_chunk(
                    source,
                    Some(RepairCursor {
                        vote,
                        snapshot_id: meta.snapshot_id.clone(),
                        offset,
                    }),
                    deadline,
                )
                .await?;
        }
        snapshot
            .sync_all()
            .await
            .map_err(|_| consensus_unavailable())?;
        let response = self
            .inner
            .raft
            .install_full_snapshot(
                vote,
                Snapshot {
                    meta: meta.clone(),
                    snapshot,
                },
            )
            .await
            .map_err(|_| consensus_unavailable())?;
        if response.vote != vote || self.inner.shutdown.is_started() {
            return Err(consensus_unavailable());
        }
        let mut metrics = self.inner.raft.metrics();
        loop {
            {
                let current = metrics.borrow_and_update();
                if current.running_state.is_err() || self.inner.shutdown.is_started() {
                    return Err(consensus_unavailable());
                }
                if current.last_applied >= meta.last_log_id
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
