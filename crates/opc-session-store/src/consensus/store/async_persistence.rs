//! Ordinary cold-voter repair through a newly committed live-quorum cut.

#[cfg(all(test, target_os = "linux"))]
mod tests;

mod cold_repair;

use futures_util::stream::FuturesUnordered;
use opc_consensus::engine::CommittedLeaderId;

use super::*;
use crate::consensus::persistence_protocol::{ColdBarrierRequest, ColdQuorumCut};

pub(super) struct ColdProposalCompletion {
    pub request_id: SessionConsensusRequestId,
    pub log_id: LogId<SessionConsensusNodeId>,
}

impl ConsensusSessionStore {
    /// Explicitly persist the local resident generation captured by this call.
    ///
    /// Uses the existing background writer and the original operation deadline.
    /// Concurrent later mutations need not finish before this cut completes.
    /// Cancellation or timeout leaves the writer's accepted work intact. This
    /// local completion does not prove quorum persistence or authorize recovery.
    pub async fn drain_async_persistence(
        &self,
    ) -> Result<SessionPersistenceHealth, SessionPersistenceDrainError> {
        if self.persistence_mode() != SessionPersistenceMode::Async {
            return Err(SessionPersistenceDrainError::NotAsync);
        }
        #[cfg(target_os = "linux")]
        {
            self.drain_async_persistence_before(
                self.operation_deadline_from(tokio::time::Instant::now()),
            )
            .await
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(SessionPersistenceDrainError::Unavailable)
        }
    }

    #[cfg(target_os = "linux")]
    async fn drain_async_persistence_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<SessionPersistenceHealth, SessionPersistenceDrainError> {
        let cut = self
            .inner
            .private_wal
            .as_ref()
            .ok_or(SessionPersistenceDrainError::Unavailable)?
            .request_async_persistence()?;
        loop {
            let health = self.persistence_health();
            let progress = health
                .asynchronous
                .ok_or(SessionPersistenceDrainError::Unavailable)?;
            if let Some(failure) = progress.background_failure.or(health.storage_failure) {
                return Err(SessionPersistenceDrainError::Failed(failure));
            }
            if progress.completed_generation >= cut.0 && progress.completed_sequence >= cut.1 {
                return Ok(health);
            }
            if health.storage_state != SessionStorageState::Running {
                return Err(SessionPersistenceDrainError::Unavailable);
            }
            tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(10)))
                .await
                .map_err(|_| SessionPersistenceDrainError::DeadlineExceeded)?;
        }
    }

    pub(super) async fn recover_async_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), ConsensusSessionStoreOpenError> {
        let protocol = &self.inner.persistence_protocol;
        let _attempt = tokio::time::timeout_at(deadline, protocol.recovery_attempt.lock())
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::RecoveryRequired)?;
        if protocol.is_active() || self.activate_caught_up_async_before(deadline).await? {
            return Ok(());
        }
        // No old permitted RPC may be in flight when this nonce is created.
        // Repeated initialize calls may replace an unavailable leader's cut;
        // any already running strict snapshot install first drains here.
        let request = protocol
            .quarantine_before(deadline)
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::RecoveryRequired)?;
        let mut responses: FuturesUnordered<_> = self
            .inner
            .bootstrap_members
            .iter()
            .copied()
            .filter(|target| *target != self.inner.local_node_id)
            .map(|target| async move {
                (
                    target,
                    self.call_peer::<_, ColdQuorumCut>(
                        target,
                        SessionConsensusRpcFamily::ReadBarrier,
                        &request,
                        deadline,
                    )
                    .await,
                )
            })
            .collect();
        let mut witness = None;
        while let Ok(Some((target, response))) =
            tokio::time::timeout_at(deadline, responses.next()).await
        {
            let Ok(cut) = response else {
                continue;
            };
            if cut.identity == self.inner.storage_identity
                && cut.request == request
                && cut.requester == self.inner.local_node_id
                && cut.voters
                    == fenced_transition_voter_set_digest(
                        self.inner.storage_identity,
                        &self.inner.bootstrap_members,
                    )
                && cut.vote.is_committed()
                && cut.vote.leader_id.voted_for() == Some(target)
                && cut.vote.leader_id.term != 0
                && cut.barrier.leader_id == CommittedLeaderId::new(cut.vote.leader_id.term, target)
                && cut.barrier.index != 0
            {
                witness = Some(cut);
                break;
            }
        }
        drop(responses);
        let cut = witness.ok_or(ConsensusSessionStoreOpenError::RecoveryRequired)?;
        protocol
            .accept_cut_before(cut, deadline)
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::RecoveryRequired)?;
        // The live leader may already know that this incarnation lost an
        // acknowledged volatile tail. Start ordinary snapshot repair now,
        // without spending this operation's deadline on its replication
        // worker's unreachable-peer backoff. This hint grants no authority.
        if cut.remembered_match.is_some_and(|remembered| {
            self.inner.raft.metrics().borrow().last_log_index < Some(remembered.index)
        }) {
            protocol
                .engine_before(deadline)
                .await
                .map_err(|_| ConsensusSessionStoreOpenError::RecoveryRequired)?
                .request_cold_repair();
        }
        let mut metrics = self.inner.raft.metrics();
        loop {
            metrics.borrow_and_update();
            if self.activate_caught_up_async_before(deadline).await? {
                return Ok(());
            }
            if let Some(cut) = protocol
                .take_repair_before(deadline)
                .await
                .map_err(|_| ConsensusSessionStoreOpenError::RecoveryRequired)?
            {
                let leader = cut
                    .vote
                    .leader_id
                    .voted_for()
                    .ok_or(ConsensusSessionStoreOpenError::RecoveryRequired)?;
                self.call_peer::<_, ()>(
                    leader,
                    SessionConsensusRpcFamily::ReadBarrier,
                    &persistence_protocol::ColdRepairRequest::new(cut),
                    deadline,
                )
                .await
                .map_err(|_| ConsensusSessionStoreOpenError::RecoveryRequired)?;
                continue;
            }
            let changed = async {
                tokio::select! {
                    changed = metrics.changed() => changed.map_err(|_| ConsensusSessionStoreOpenError::EngineUnavailable),
                    () = protocol.progress.notified() => Ok(()),
                }
            };
            tokio::time::timeout_at(deadline, changed)
                .await
                .map_err(|_| ConsensusSessionStoreOpenError::RecoveryRequired)??;
        }
    }

    async fn activate_caught_up_async_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<bool, ConsensusSessionStoreOpenError> {
        if self.inner.persistence_protocol.is_active() {
            return Ok(true);
        }
        let active = self
            .inner
            .persistence_protocol
            .activate_before(deadline, |cut| async move {
                if !matches!(self.durable_fixed_quorum_scope_is_exact().await, Ok(true)) {
                    return false;
                }
                // No await follows this exact full-vote/membership/application
                // snapshot while the attempt's exclusive activation fence is held.
                let metrics = self.inner.raft.metrics();
                let current = metrics.borrow();
                current.running_state.is_ok()
                    && current.vote == cut.vote
                    && current.current_leader == cut.vote.leader_id.voted_for()
                    && *current.membership_config.log_id() == cut.membership
                    && exact_uniform_voter_membership(
                        &current.membership_config,
                        &self.inner.bootstrap_members,
                    )
                    && current
                        .last_applied
                        .is_some_and(|applied| persistence_protocol::covers(applied, cut.barrier))
            })
            .await
            .map_err(|_| ConsensusSessionStoreOpenError::RecoveryRequired)?;
        if active {
            self.inner.raft.runtime_config().elect(true);
        }
        Ok(active)
    }

    pub(super) async fn handle_async_cold_barrier(
        &self,
        sender: SessionConsensusNodeId,
        payload: &[u8],
    ) -> SessionConsensusWireResponse {
        let rejected = || SessionConsensusWireResponse {
            result: Err(SessionConsensusPeerError::Rejected),
        };
        if self.persistence_mode() != SessionPersistenceMode::Async
            || !self.inner.persistence_protocol.is_active()
            || sender == self.inner.local_node_id
        {
            return rejected();
        }
        let request = match decode_bounded::<ColdBarrierRequest>(payload) {
            Ok(request) if request.is_valid() => request,
            Ok(_) => return protocol_rejection(),
            Err(_) => return protocol_rejection(),
        };
        let deadline = self.operation_deadline_from(tokio::time::Instant::now());
        if self
            .require_application_traffic_authority_before(deadline)
            .await
            .is_err()
        {
            return rejected();
        }
        let (vote, membership, before_index) = {
            let metrics = self.inner.raft.metrics();
            let current = metrics.borrow();
            if current.running_state.is_err()
                || current.current_leader != Some(self.inner.local_node_id)
                || !current.vote.is_committed()
                || current.vote.leader_id.voted_for() != Some(self.inner.local_node_id)
                || !exact_uniform_voter_membership(
                    &current.membership_config,
                    &self.inner.bootstrap_members,
                )
            {
                return rejected();
            }
            (
                current.vote,
                *current.membership_config.log_id(),
                current.last_log_index,
            )
        };
        // A real new proposal, not the coalesced logical-time read ticket or
        // ensure_linearizable heartbeat. The caller is quarantined until the
        // response, so this new index requires a live majority without it.
        let intent = SessionMutationIntent::AdvanceLogicalTime;
        let (completion, mut completed) = tokio::sync::oneshot::channel();
        let reply = self
            .apply_on_local_leader_observed(
                ForwardMutationRequest {
                    request_id: request.nonce,
                    intent: intent.clone(),
                    required_consumer_scope: ForwardConsumerScope::Internal,
                },
                sender,
                deadline,
                false,
                None,
                Some(completion),
            )
            .await;
        let ForwardMutationReply::Applied(response) = reply else {
            return rejected();
        };
        let Ok(completed) = completed.try_recv() else {
            return rejected();
        };
        if !committed_response_matches_intent(&intent, &response)
            || response.result != Ok(SessionMutationOutcome::Unit)
            || completed.request_id != request.nonce
            || completed.log_id.index != response.raft_log_index
            || completed.log_id.leader_id
                != CommittedLeaderId::new(vote.leader_id.term, self.inner.local_node_id)
            || Some(response.raft_log_index) <= before_index
        {
            return rejected();
        }
        let remembered_match = {
            let metrics = self.inner.raft.metrics();
            let current = metrics.borrow();
            if current.running_state.is_err()
                || current.current_leader != Some(self.inner.local_node_id)
                || current.vote != vote
                || *current.membership_config.log_id() != membership
                || !exact_uniform_voter_membership(
                    &current.membership_config,
                    &self.inner.bootstrap_members,
                )
            {
                return rejected();
            }
            current
                .replication
                .as_ref()
                .and_then(|replication| replication.get(&sender).copied().flatten())
        };
        encode_service_reply(&ColdQuorumCut {
            identity: self.inner.storage_identity,
            request,
            requester: sender,
            voters: fenced_transition_voter_set_digest(
                self.inner.storage_identity,
                &self.inner.bootstrap_members,
            ),
            membership,
            vote,
            barrier: completed.log_id,
            remembered_match,
        })
    }
}
