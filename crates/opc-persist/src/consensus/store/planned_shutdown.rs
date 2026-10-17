//! One owned shutdown: fence admission, attempt handoff, then join the engine.

use futures_util::{stream::FuturesUnordered, StreamExt};
use opc_consensus::engine::raft::{TransferLeaderError, TransferLeaderRequest};
use opc_consensus::{planned_shutdown_timeout, PlannedShutdownFallback, PlannedShutdownOutcome};
use tokio::sync::watch;
use tokio::time::Instant;

use super::*;

#[cfg(test)]
#[path = "planned_shutdown_tests.rs"]
mod tests;

type Completion = Option<Result<PlannedShutdownOutcome, PersistError>>;
type Scope = (BTreeSet<ConsensusNodeId>, Option<LogId<ConsensusNodeId>>);

pub(super) struct ConfigShutdownCoordinator {
    started: AtomicBool,
    started_notify: tokio::sync::Notify,
    completion: std::sync::Mutex<Option<watch::Receiver<Completion>>>,
}

impl ConfigShutdownCoordinator {
    pub(super) fn new() -> Self {
        Self {
            started: AtomicBool::new(false),
            started_notify: tokio::sync::Notify::new(),
            completion: std::sync::Mutex::new(None),
        }
    }

    pub(super) fn is_started(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }

    pub(super) async fn wait_started(&self) {
        let notified = self.started_notify.notified();
        tokio::pin!(notified);
        // Register before checking the flag so shutdown cannot be missed.
        notified.as_mut().enable();
        if !self.is_started() {
            notified.await;
        }
    }

    fn start_or_subscribe(&self, store: ConsensusConfigStore) -> watch::Receiver<Completion> {
        let mut completion = self
            .completion
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(receiver) = completion.as_ref() {
            return receiver.clone();
        }
        let deadline = Instant::now() + planned_shutdown_timeout(store.inner.operation_timeout);
        let (sender, receiver) = watch::channel(None);
        *completion = Some(receiver.clone());
        // Config reads never reuse cached leases. Fence every public/forwarded
        // application path before the engine can release a leader vote lease.
        self.started.store(true, Ordering::Release);
        self.started_notify.notify_waiters();
        tokio::spawn(async move {
            // Active recovery observes the shutdown notification and drops
            // its local download. Also discard a checkpoint left by a prior
            // bounded attempt before publishing shutdown completion.
            drop(store.inner.repair_progress.lock().await.take());
            let mut timeout_reason = PlannedShutdownFallback::DeadlineElapsed;
            let preparation = tokio::time::timeout_at(
                deadline,
                store.transfer_before_shutdown(deadline, &mut timeout_reason),
            )
            .await
            .unwrap_or(Err(timeout_reason));
            let outcome = match preparation {
                Ok(outcome) => outcome,
                Err(reason) => {
                    tracing::warn!(?reason, "config consensus handoff fell back to shutdown");
                    PlannedShutdownOutcome::Fallback { reason }
                }
            };
            // Never cancel this join when a caller times out. Later clones
            // must observe this exact drain before reopening durable storage.
            let result = store
                .inner
                .raft
                .shutdown()
                .await
                .map(|()| outcome)
                .map_err(|_| consensus_unavailable());
            // Raft joins its core and replication tasks, but its state-machine
            // worker and snapshot builders can still own storage afterwards.
            // Keep this drain owned across every caller timeout until all of
            // those handles, including cancelled SQLite workers, have exited.
            let mut storage_shutdown = store.inner.storage_shutdown.clone();
            while storage_shutdown.changed().await.is_ok() {}
            drop(store);
            sender.send_replace(Some(result));
        });
        receiver
    }
}

impl ConsensusConfigStore {
    /// Perform [`Self::shutdown`] and return its retained, typed handoff result.
    ///
    /// `Fallback` still joins the engine. Keep replication transport available
    /// throughout this call; after a caller timeout, the owned drain continues
    /// and a later clone can wait for its completion without another handoff.
    pub async fn shutdown_with_report(&self) -> Result<PlannedShutdownOutcome, PersistError> {
        let mut completion = self.inner.shutdown.start_or_subscribe(self.clone());
        tokio::time::timeout(self.inner.operation_timeout, async {
            loop {
                if let Some(result) = completion.borrow_and_update().clone() {
                    return result;
                }
                completion
                    .changed()
                    .await
                    .map_err(|_| consensus_unavailable())?;
            }
        })
        .await
        .unwrap_or_else(|_| Err(consensus_unavailable()))
    }

    fn shutdown_scope_is_current(&self, scope: &Scope) -> bool {
        if !self.exact_membership_is_admitted() {
            return false;
        }
        let metrics = self.inner.raft.metrics();
        let current = metrics.borrow();
        current.running_state.is_ok()
            && current.membership_config.log_id() == &scope.1
            && exact_uniform_voter_membership(current.membership_config.as_ref(), &scope.0)
    }

    async fn transfer_before_shutdown(
        &self,
        deadline: Instant,
        timeout_reason: &mut PlannedShutdownFallback,
    ) -> Result<PlannedShutdownOutcome, PlannedShutdownFallback> {
        use PlannedShutdownFallback as Reason;

        if !self.exact_membership_is_admitted() {
            return Err(Reason::NotAdmitted);
        }
        let (scope, mut candidates) = {
            let metrics = self.inner.raft.metrics();
            let current = metrics.borrow();
            let members: BTreeSet<_> = current.membership_config.membership().voter_ids().collect();
            let mut candidates: Vec<_> = members
                .iter()
                .copied()
                .filter(|node| *node != self.inner.local_node_id)
                .collect();
            candidates.sort_by_key(|node| {
                current
                    .replication
                    .as_ref()
                    .and_then(|replication| replication.get(node))
                    .copied()
                    .flatten()
            });
            ((members, *current.membership_config.log_id()), candidates)
        };
        if !self.shutdown_scope_is_current(&scope) {
            return Err(Reason::ScopeChanged);
        }
        // The core decides its role atomically, including candidates with
        // delayed vote responses. A fenced target may be skipped only before
        // preparation succeeds; a retained handoff is never retargeted.
        let handoff = loop {
            let candidate = candidates.pop();
            match self.inner.raft.prepare_shutdown(candidate).await {
                Ok(handoff) => break handoff,
                Err(RaftError::APIError(TransferLeaderError::InvalidTarget)) => {
                    if candidates.is_empty() {
                        return Err(Reason::NoEligibleVoter);
                    }
                }
                Err(RaftError::APIError(TransferLeaderError::MembershipChanged)) => {
                    return Err(Reason::ScopeChanged);
                }
                Err(_) => return Err(Reason::EngineUnavailable),
            }
        };
        let Some(request) = handoff else {
            return Ok(PlannedShutdownOutcome::FollowerRetired);
        };
        let quorum = scope.0.len() / 2 + 1;
        if scope.0.len().saturating_sub(1) < quorum {
            return Err(Reason::InsufficientSurvivingVoters);
        }

        *timeout_reason = Reason::SurvivingQuorumUnavailable;
        // Borrowed calls are cancelled synchronously with this preparation.
        // No detached release task may retain a store after shutdown completes.
        let mut releases = FuturesUnordered::new();
        for node in scope
            .0
            .iter()
            .copied()
            .filter(|node| *node != self.inner.local_node_id && node != request.to())
        {
            releases.push(self.deliver_shutdown_transfer(node, &request, deadline));
        }
        let mut released = 0;
        while let Some(result) = releases.next().await {
            if !self.shutdown_scope_is_current(&scope) {
                return Err(Reason::ScopeChanged);
            }
            if matches!(result, Ok(Ok(()))) {
                released += 1;
                if released >= quorum - 1 {
                    break;
                }
            }
        }
        if released < quorum - 1 {
            return Err(Reason::SurvivingQuorumUnavailable);
        }
        drop(releases);

        *timeout_reason = Reason::NoUpToDateVoter;
        loop {
            if !self.shutdown_scope_is_current(&scope) {
                return Err(Reason::ScopeChanged);
            }
            match self
                .deliver_shutdown_transfer(*request.to(), &request, deadline)
                .await
            {
                Ok(Ok(())) => break,
                Ok(Err(RaftError::APIError(TransferLeaderError::LogNotApplied))) => {
                    self.wait_for_route_refresh(self.inner.local_node_id, deadline)
                        .await
                        .map_err(|_| Reason::NoUpToDateVoter)?;
                }
                Err(_) => return Err(Reason::NoUpToDateVoter),
                _ => return Err(Reason::SuccessorRejected),
            }
        }

        *timeout_reason = Reason::SuccessorUnconfirmed;
        let successor = *request.to();
        let mut metrics = self.inner.raft.metrics();
        loop {
            if !self.shutdown_scope_is_current(&scope) {
                return Err(Reason::ScopeChanged);
            }
            let observed = {
                let current = metrics.borrow_and_update();
                (current.current_leader == Some(successor)
                    && current.vote.is_committed()
                    && current.vote.leader_id.term > request.from().leader_id.term)
                    .then_some(current.vote)
            };
            if let Some(vote) = observed {
                let read = ReadBarrierRequest {
                    compatibility: self.peer_compatibility(),
                    compatibility_probe: false,
                    budget: ForwardedBudget::from_deadline(deadline)
                        .map_err(|_| Reason::SuccessorUnconfirmed)?,
                };
                if let Ok(ReadBarrierReply::Ready(read_log_id)) = self
                    .call_peer(successor, ConsensusRpcFamily::ReadBarrier, &read, deadline)
                    .await
                {
                    let current_matches = {
                        let current = metrics.borrow();
                        current.current_leader == Some(successor) && current.vote == vote
                    };
                    if current_matches
                        && self.shutdown_scope_is_current(&scope)
                        && request.last_log_id().is_none_or(|required| {
                            read_log_id.is_some_and(|read| read.index >= required.index)
                        })
                    {
                        return Ok(PlannedShutdownOutcome::LeaderTransferred { successor });
                    }
                }
                self.wait_for_route_refresh(successor, deadline)
                    .await
                    .map_err(|_| Reason::SuccessorUnconfirmed)?;
            } else {
                tokio::time::timeout_at(deadline, metrics.changed())
                    .await
                    .map_err(|_| Reason::SuccessorUnconfirmed)?
                    .map_err(|_| Reason::EngineUnavailable)?;
            }
        }
    }

    async fn deliver_shutdown_transfer(
        &self,
        target: ConsensusNodeId,
        request: &TransferLeaderRequest<ConsensusNodeId>,
        deadline: Instant,
    ) -> Result<Result<(), RaftError<ConsensusNodeId, TransferLeaderError>>, PersistError> {
        self.call_peer(
            target,
            ConsensusRpcFamily::LeadershipTransfer,
            request,
            deadline,
        )
        .await
    }
}
