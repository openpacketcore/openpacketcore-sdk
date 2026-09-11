//! Restore a cold voter's missing volatile prefix without reverting the live
//! leader's remembered replication progress. Admission still requires the
//! original nonce-bound quorum cut and a real matching AppendEntries response.

use std::io::SeekFrom;

use opc_consensus::engine::error::InstallSnapshotError;
use opc_consensus::engine::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::*;
use crate::consensus::persistence_protocol::ColdRepairRequest;

impl ConsensusSessionStore {
    /// Serve a same-scope cold repair through ordinary snapshot installation.
    pub(crate) async fn handle_async_cold_repair(
        &self,
        sender: SessionConsensusNodeId,
        payload: &[u8],
    ) -> SessionConsensusWireResponse {
        let request = match decode_bounded::<ColdRepairRequest>(payload) {
            Ok(request) if request.is_valid() => request,
            _ => return protocol_rejection(),
        };
        let deadline = self.operation_deadline_from(tokio::time::Instant::now());
        let result = tokio::time::timeout_at(
            deadline,
            self.send_async_cold_snapshot_before(sender, request.cut, deadline),
        )
        .await;
        #[cfg(test)]
        eprintln!("async_cold_repair result={result:?}");
        match result {
            Ok(Ok(())) => encode_service_reply(&()),
            _ => SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::Rejected),
            },
        }
    }

    fn async_repair_leader_matches(&self, cut: ColdQuorumCut) -> bool {
        let metrics = self.inner.raft.metrics();
        let current = metrics.borrow();
        self.inner.persistence_protocol.is_active()
            && current.running_state.is_ok()
            && current.current_leader == Some(self.inner.local_node_id)
            && current.vote == cut.vote
            && *current.membership_config.log_id() == cut.membership
            && exact_uniform_voter_membership(
                &current.membership_config,
                &self.inner.bootstrap_members,
            )
            && current
                .last_applied
                .is_some_and(|last| persistence_protocol::covers(last, cut.barrier))
    }

    async fn send_async_cold_snapshot_before(
        &self,
        sender: SessionConsensusNodeId,
        cut: ColdQuorumCut,
        deadline: tokio::time::Instant,
    ) -> Result<(), SessionConsensusPeerError> {
        if self.persistence_mode() != SessionPersistenceMode::Async
            || sender == self.inner.local_node_id
            || cut.requester != sender
            || !self.inner.bootstrap_members.contains(&sender)
            || cut.identity != self.inner.storage_identity
            || cut.voters
                != fenced_transition_voter_set_digest(
                    self.inner.storage_identity,
                    &self.inner.bootstrap_members,
                )
            || !cut.vote.is_committed()
            || cut.vote.leader_id.voted_for() != Some(self.inner.local_node_id)
            || cut.vote.leader_id.term == 0
            || cut.barrier.index == 0
            || cut.barrier.leader_id
                != CommittedLeaderId::new(cut.vote.leader_id.term, self.inner.local_node_id)
            || !self.async_repair_leader_matches(cut)
        {
            return Err(SessionConsensusPeerError::Rejected);
        }
        self.require_application_traffic_authority_before(deadline)
            .await
            .map_err(|_| SessionConsensusPeerError::Rejected)?;

        // Reuse normal snapshot creation, authenticated scope/lineage, bounded
        // descriptor reads and the receiver's strict engine installation. A
        // pre-existing build may finish below the cut; request its successor
        // only after that publication, within this same operation deadline.
        let mut metrics = self.inner.raft.metrics();
        let mut requested_at = None;
        loop {
            let current_snapshot = metrics.borrow_and_update().snapshot;
            #[cfg(test)]
            eprintln!(
                "async_cold_repair stage=snapshot_wait selected={current_snapshot:?} cut={:?}",
                cut.barrier
            );
            if !self.async_repair_leader_matches(cut) {
                return Err(SessionConsensusPeerError::Rejected);
            }
            if current_snapshot.is_some_and(|last| persistence_protocol::covers(last, cut.barrier))
            {
                break;
            }
            if requested_at != Some(current_snapshot) {
                self.inner
                    .raft
                    .trigger()
                    .snapshot()
                    .await
                    .map_err(|_| SessionConsensusPeerError::Unavailable)?;
                requested_at = Some(current_snapshot);
            }
            metrics
                .changed()
                .await
                .map_err(|_| SessionConsensusPeerError::Unavailable)?;
        }
        let mut snapshot = self
            .inner
            .raft
            .get_snapshot()
            .await
            .map_err(|_| SessionConsensusPeerError::Unavailable)?
            .ok_or(SessionConsensusPeerError::Unavailable)?;
        #[cfg(test)]
        eprintln!(
            "async_cold_repair stage=snapshot_open selected={:?}",
            snapshot.meta.last_log_id
        );
        if *snapshot.meta.last_membership.log_id() != cut.membership
            || !exact_uniform_voter_membership(
                &snapshot.meta.last_membership,
                &self.inner.bootstrap_members,
            )
            || !snapshot
                .meta
                .last_log_id
                .is_some_and(|last| persistence_protocol::covers(last, cut.barrier))
        {
            return Err(SessionConsensusPeerError::Rejected);
        }
        let end = snapshot
            .snapshot
            .seek(SeekFrom::End(0))
            .await
            .map_err(|_| SessionConsensusPeerError::Unavailable)?;
        snapshot
            .snapshot
            .seek(SeekFrom::Start(0))
            .await
            .map_err(|_| SessionConsensusPeerError::Unavailable)?;
        let chunk_bytes = self.inner.raft.config().snapshot_max_chunk_size;
        #[cfg(test)]
        eprintln!("async_cold_repair stage=snapshot_read extent={end} chunk_limit={chunk_bytes}");
        if chunk_bytes == 0 {
            return Err(SessionConsensusPeerError::Rejected);
        }
        let mut offset = 0;
        loop {
            if !self.async_repair_leader_matches(cut) {
                return Err(SessionConsensusPeerError::Rejected);
            }
            let length = usize::try_from((end - offset).min(chunk_bytes))
                .map_err(|_| SessionConsensusPeerError::Protocol)?;
            let mut data = vec![0; length];
            snapshot
                .snapshot
                .read_exact(&mut data)
                .await
                .map_err(|_| SessionConsensusPeerError::Unavailable)?;
            #[cfg(test)]
            eprintln!("async_cold_repair stage=snapshot_chunk_read offset={offset} length={length} remaining_us={}", deadline.saturating_duration_since(tokio::time::Instant::now()).as_micros());
            let done = end - offset == length as u64;
            let rpc = InstallSnapshotRequest::<SessionRaftTypeConfig> {
                vote: cut.vote,
                meta: snapshot.meta.clone(),
                offset,
                data,
                done,
            };
            let response = self
                .call_peer::<_, Result<
                    InstallSnapshotResponse<SessionConsensusNodeId>,
                    RaftError<SessionConsensusNodeId, InstallSnapshotError>,
                >>(
                    sender,
                    SessionConsensusRpcFamily::InstallSnapshot,
                    &rpc,
                    deadline,
                )
                .await
                .map_err(|_| SessionConsensusPeerError::Unavailable)?
                .map_err(|_| SessionConsensusPeerError::Rejected)?;
            #[cfg(test)]
            eprintln!(
                "async_cold_repair stage=snapshot_sent offset={offset} length={length} done={done}"
            );
            if response.vote != cut.vote {
                return Err(SessionConsensusPeerError::Rejected);
            }
            if done {
                break;
            }
            offset += length as u64;
        }
        if !self.async_repair_leader_matches(cut) {
            return Err(SessionConsensusPeerError::Rejected);
        }
        // Prove a real matching prefix now; the engine's replication worker
        // may still be backing off after the cold incarnation rejected it.
        // The snapshot's applied LogId was committed by this exact leader.
        // This is an ordinary validated engine RPC, never a synthetic success.
        let matched =
            self.call_peer::<_, Result<
                AppendEntriesResponse<SessionConsensusNodeId>,
                RaftError<SessionConsensusNodeId>,
            >>(
                sender,
                SessionConsensusRpcFamily::AppendEntries,
                &AppendEntriesRequest::<SessionRaftTypeConfig> {
                    vote: cut.vote,
                    prev_log_id: snapshot.meta.last_log_id,
                    entries: Vec::new(),
                    leader_commit: snapshot.meta.last_log_id,
                },
                deadline,
            )
            .await
            .map_err(|_| SessionConsensusPeerError::Unavailable)?;
        match matched {
            Ok(AppendEntriesResponse::Success) => Ok(()),
            _ => Err(SessionConsensusPeerError::Rejected),
        }
    }
}
