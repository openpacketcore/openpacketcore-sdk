//! Planned retirement composes engine-owned handoff with authenticated peers.

use futures_util::stream::FuturesUnordered;
use opc_consensus::engine::raft::{TransferLeaderError, TransferLeaderRequest};
use opc_consensus::{PlannedShutdownFallback, PlannedShutdownOutcome};

use super::*;

/// One retained preparation per store incarnation. A cancelled observer must
/// neither resume local admission nor select another successor.
pub(super) struct ConsensusRetirementCoordinator {
    started: AtomicBool,
    unplanned: tokio::sync::watch::Sender<bool>,
    completion: Mutex<Option<tokio::sync::watch::Receiver<Option<RetirementResult>>>>,
}

type RetirementResult = Result<PlannedShutdownOutcome, PlannedShutdownFallback>;

impl ConsensusRetirementCoordinator {
    pub(super) fn new() -> Self {
        Self {
            started: AtomicBool::new(false),
            unplanned: tokio::sync::watch::channel(false).0,
            completion: Mutex::new(None),
        }
    }

    pub(super) fn is_started(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }

    pub(super) fn prevent_handoff(&self, store: &ConsensusSessionStore) {
        // Retain the failure-route choice even before a coordinator subscribes.
        // Fence admission synchronously, before the caller can be cancelled.
        store.inner.raw_v2_read_barrier.disable_lease_reuse();
        store.inner.read_barrier.disable_lease_reuse();
        // Publish the unplanned choice before marking preparation started, so a
        // concurrent planned preparation that observes `started` also observes
        // the flag and reports Unplanned rather than a spurious NotAdmitted.
        self.unplanned.send_replace(true);
        self.started.store(true, Ordering::Release);
    }

    fn start_or_subscribe(
        &self,
        store: ConsensusSessionStore,
        deadline: tokio::time::Instant,
    ) -> tokio::sync::watch::Receiver<Option<RetirementResult>> {
        let mut completion = self
            .completion
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(receiver) = completion.as_ref() {
            return receiver.clone();
        }
        let (sender, receiver) = tokio::sync::watch::channel(None);
        *completion = Some(receiver.clone());
        let mut unplanned = self.unplanned.subscribe();
        tokio::spawn(async move {
            // Explicit preparation keeps its complete-operation budget.
            // Automatic preparation reserves time for drain. Later callers
            // observe the first deadline and result, never extend or restart it.
            let mut timeout_reason = PlannedShutdownFallback::DeadlineElapsed;
            let result = select_preparation(&mut unplanned, async {
                tokio::time::timeout_at(
                    deadline,
                    store.prepare_shutdown_before(deadline, &mut timeout_reason),
                )
                .await
                .unwrap_or(Err(timeout_reason))
            })
            .await;
            sender.send_replace(Some(result));
        });
        receiver
    }
}

async fn select_preparation(
    unplanned: &mut tokio::sync::watch::Receiver<bool>,
    preparation: impl std::future::Future<Output = RetirementResult>,
) -> RetirementResult {
    let result = tokio::select! {
        biased;
        _ = unplanned.wait_for(|requested| *requested) => {
            Err(PlannedShutdownFallback::Unplanned)
        }
        result = preparation => result,
    };
    prefer_unplanned(result, unplanned)
}

impl ConsensusSessionStore {
    /// Prepare one planned voter retirement while its authenticated replication
    /// listener and storage remain alive.
    ///
    /// Stop external consumer admission first. This clone-wide operation then
    /// permanently stops local application admission and asks the consensus
    /// engine to stop campaigning atomically with deciding its role. A leader
    /// hands off its exact accepted log prefix to one current voter; a follower
    /// or candidate retires without campaigning. Previously accepted mutations
    /// retain their original response/status path and are never resubmitted.
    ///
    /// Success means a different current voter supplied a fresh engine quorum
    /// read proof after local preparation, in the same membership scope. The
    /// retiring voter can still participate in that quorum. This is not proof
    /// that enough peers will remain available after another simultaneous loss.
    /// The operator must preserve the surviving quorum and serialize conflicting
    /// voter retirements. No membership, election timer or lease is weakened.
    ///
    /// Preparation has one complete-operation deadline and retained result.
    /// Cancelling a caller does not cancel the owned preparation or resume the
    /// voter; a later clone observes that same result. A failed preparation is
    /// not a successful handoff. Keep replication alive until the result is
    /// known, then remove the RPC handler and use [`Self::shutdown`] for the
    /// separate engine/storage drain. Shutdown and native close proofs retain
    /// their existing contract. Reopening creates a new retirement incarnation.
    pub async fn prepare_shutdown(&self) -> Result<(), StoreError> {
        let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
        let completion = self
            .inner
            .retirement
            .start_or_subscribe(self.clone(), deadline);
        tokio::time::timeout_at(deadline, await_preparation(completion))
            .await
            .map_err(|_| consensus_unavailable())?
            .map(|_| ())
            .map_err(|_| consensus_unavailable())
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) async fn prepare_shutdown_for_stop(&self) -> PlannedShutdownOutcome {
        self.prepare_shutdown_for_stop_before(
            tokio::time::Instant::now()
                + opc_consensus::planned_shutdown_timeout(self.inner.operation_timeout),
        )
        .await
    }

    pub(super) async fn prepare_shutdown_for_stop_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> PlannedShutdownOutcome {
        let completion = self
            .inner
            .retirement
            .start_or_subscribe(self.clone(), deadline);
        // The coordinator itself has an original absolute deadline. Join that
        // owned preparation before draining storage, even if the shutdown
        // observer goes away; a prior explicit preparation is not abandoned.
        let result = await_preparation(completion).await;
        self.inner.raw_v2_read_barrier.disable_lease_reuse();
        self.inner.read_barrier.disable_lease_reuse();
        self.inner.retirement.started.store(true, Ordering::Release);
        match result {
            Ok(outcome) => outcome,
            Err(PlannedShutdownFallback::Unplanned) => PlannedShutdownOutcome::Fallback {
                reason: PlannedShutdownFallback::Unplanned,
            },
            Err(reason) => {
                tracing::warn!(?reason, "session consensus handoff fell back to shutdown");
                PlannedShutdownOutcome::Fallback { reason }
            }
        }
    }

    async fn prepare_shutdown_before(
        &self,
        deadline: tokio::time::Instant,
        timeout_reason: &mut PlannedShutdownFallback,
    ) -> RetirementResult {
        use PlannedShutdownFallback as Reason;
        // An expired timeout can still poll a ready inner future. Classify the
        // exhausted budget before admission checks or engine preparation run.
        if tokio::time::Instant::now() >= deadline {
            return Err(Reason::DeadlineElapsed);
        }
        // Shared with ordinary operations, exclusive only against a topology
        // transition. No unrelated session is put behind a shutdown write lock.
        let _scope_guard = tokio::time::timeout_at(
            deadline,
            self.inner
                .topology_coordinator
                .operation_gate()
                .read_owned(),
        )
        .await
        .map_err(|_| Reason::DeadlineElapsed)?;
        self.require_durable_fixed_quorum_admission_before(deadline)
            .await
            .map_err(|_| Reason::NotAdmitted)?;
        if !matches!(
            self.operator_recovery_gate_before(deadline).await,
            OperatorRecoveryGate::Clear
        ) || !self
            .durable_uniform_scope_is_admitted()
            .await
            .map_err(|_| Reason::NotAdmitted)?
        {
            return Err(Reason::NotAdmitted);
        }
        let scope = self.current_scope().map_err(|_| Reason::ScopeChanged)?;
        let local = self.inner.local_node_id;
        let quorum = scope.1.len() / 2 + 1;
        if scope.1.len().saturating_sub(1) < quorum {
            return Err(Reason::InsufficientSurvivingVoters);
        }
        let successor = {
            let metrics = self.inner.raft.metrics();
            let current = metrics.borrow();
            scope
                .1
                .iter()
                .copied()
                .filter(|node| *node != local)
                .max_by_key(|node| {
                    current
                        .replication
                        .as_ref()
                        .and_then(|replication| replication.get(node))
                        .copied()
                        .flatten()
                })
                .ok_or(Reason::NoEligibleVoter)?
        };

        // Invalidate cached proofs before the engine can release a vote lease.
        // The separate engine admission bit remains set: replication and votes
        // for other candidates must keep working through the actual drain.
        self.inner.raw_v2_read_barrier.disable_lease_reuse();
        self.inner.read_barrier.disable_lease_reuse();
        self.inner.retirement.started.store(true, Ordering::Release);
        let handoff = self
            .inner
            .raft
            .prepare_shutdown(Some(successor))
            .await
            .map_err(|_| Reason::EngineUnavailable)?;
        if let Some(request) = handoff.as_ref() {
            *timeout_reason = Reason::SurvivingQuorumUnavailable;
            self.release_surviving_vote_leases(&scope, request, quorum, deadline)
                .await
                .map_err(|_| Reason::SurvivingQuorumUnavailable)?;
            *timeout_reason = Reason::NoUpToDateVoter;
            self.start_successor_election(&scope, request, deadline)
                .await?;
        }
        *timeout_reason = Reason::SuccessorUnconfirmed;
        self.confirm_surviving_leader(&scope, handoff.as_ref(), deadline)
            .await
            .map_err(|_| Reason::SuccessorUnconfirmed)?;
        Ok(match handoff {
            Some(request) => PlannedShutdownOutcome::LeaderTransferred {
                successor: *request.to(),
            },
            None => PlannedShutdownOutcome::FollowerRetired,
        })
    }

    async fn release_surviving_vote_leases(
        &self,
        scope: &(SessionConsensusIdentity, BTreeSet<SessionConsensusNodeId>),
        request: &TransferLeaderRequest<SessionConsensusNodeId>,
        quorum: usize,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        let mut calls = scope
            .1
            .iter()
            .copied()
            .filter(|node| *node != self.inner.local_node_id && node != request.to())
            .map(|node| self.deliver_leadership_transfer(node, request, deadline))
            .collect::<FuturesUnordered<_>>();
        let mut released = 0;
        // Reach enough *other surviving* voters before asking the successor to
        // campaign. A slow surplus peer does not become an all-member barrier.
        while let Some(result) = calls.next().await {
            if self.current_scope()? != *scope || !self.inner.persistence_protocol.is_active() {
                return Err(consensus_unavailable());
            }
            if matches!(result, Ok(Ok(()))) {
                released += 1;
                if released >= quorum.saturating_sub(1) {
                    return Ok(());
                }
            }
        }
        Err(consensus_unavailable())
    }

    async fn deliver_leadership_transfer(
        &self,
        node: SessionConsensusNodeId,
        request: &TransferLeaderRequest<SessionConsensusNodeId>,
        deadline: tokio::time::Instant,
    ) -> Result<
        Result<(), RaftError<SessionConsensusNodeId, TransferLeaderError>>,
        ConsensusPeerCallFailure,
    > {
        self.call_peer(
            node,
            SessionConsensusRpcFamily::LeadershipTransfer,
            request,
            deadline,
        )
        .await
    }

    async fn start_successor_election(
        &self,
        scope: &(SessionConsensusIdentity, BTreeSet<SessionConsensusNodeId>),
        request: &TransferLeaderRequest<SessionConsensusNodeId>,
        deadline: tokio::time::Instant,
    ) -> Result<(), PlannedShutdownFallback> {
        use PlannedShutdownFallback as Reason;
        loop {
            if self.current_scope().map_err(|_| Reason::ScopeChanged)? != *scope
                || !self.inner.persistence_protocol.is_active()
            {
                return Err(Reason::ScopeChanged);
            }
            match self
                .deliver_leadership_transfer(*request.to(), request, deadline)
                .await
            {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(RaftError::APIError(TransferLeaderError::LogNotApplied))) => {
                    // Redeliver only this engine-issued control request. Wait
                    // on existing route/replication progress and its bounded
                    // retry interval, under the original operation deadline.
                    self.wait_for_route_refresh(self.inner.local_node_id, deadline)
                        .await
                        .map_err(|_| Reason::NoUpToDateVoter)?;
                }
                Err(_) => return Err(Reason::NoUpToDateVoter),
                _ => return Err(Reason::SuccessorRejected),
            }
        }
    }

    async fn confirm_surviving_leader(
        &self,
        scope: &(SessionConsensusIdentity, BTreeSet<SessionConsensusNodeId>),
        handoff: Option<&TransferLeaderRequest<SessionConsensusNodeId>>,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
        let mut metrics = self.inner.raft.metrics();
        loop {
            if self.current_scope()? != *scope || !self.inner.persistence_protocol.is_active() {
                return Err(consensus_unavailable());
            }
            let observed = {
                let current = metrics.borrow_and_update();
                current
                    .current_leader
                    .filter(|leader| {
                        *leader != self.inner.local_node_id
                            && scope.1.contains(leader)
                            && current.running_state.is_ok()
                            && current.vote.is_committed()
                            && handoff.is_none_or(|request| {
                                leader == request.to()
                                    && current.vote.leader_id.term > request.from().leader_id.term
                            })
                    })
                    .map(|leader| (leader, current.vote))
            };
            if let Some((leader, vote)) = observed {
                let reply = self
                    .call_peer::<_, ReadBarrierReply>(
                        leader,
                        SessionConsensusRpcFamily::ReadBarrier,
                        &ReadBarrierRequest,
                        deadline,
                    )
                    .await;
                if let Ok(ReadBarrierReply::Ready(read_log_id)) = reply {
                    let current = metrics.borrow();
                    let prefix_applied = handoff.is_none_or(|request| {
                        request.last_log_id().is_none_or(|required| {
                            read_log_id.is_some_and(|read| read.index >= required.index)
                        })
                    });
                    if current.current_leader == Some(leader)
                        && current.vote == vote
                        && current.running_state.is_ok()
                        && prefix_applied
                        && self.current_scope()? == *scope
                        && self.inner.persistence_protocol.is_active()
                    {
                        return Ok(());
                    }
                }
                self.wait_for_route_refresh(leader, deadline).await?;
            } else {
                tokio::time::timeout_at(deadline, metrics.changed())
                    .await
                    .map_err(|_| consensus_unavailable())?
                    .map_err(|_| consensus_unavailable())?;
            }
        }
    }
}

async fn await_preparation(
    mut completion: tokio::sync::watch::Receiver<Option<RetirementResult>>,
) -> RetirementResult {
    loop {
        if let Some(result) = *completion.borrow_and_update() {
            return result;
        }
        completion
            .changed()
            .await
            .map_err(|_| PlannedShutdownFallback::EngineUnavailable)?;
    }
}

/// Prefer the unplanned fallback whenever the coordinator flag is set.
///
/// The flag is published before `started`, and this second check closes the
/// remaining window where a planned preparation resolves at the same instant
/// the flag is set: the caller-visible report must say Unplanned, not a
/// not-admitted or other handoff failure.
fn prefer_unplanned(
    result: RetirementResult,
    unplanned: &tokio::sync::watch::Receiver<bool>,
) -> RetirementResult {
    if *unplanned.borrow() {
        Err(PlannedShutdownFallback::Unplanned)
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unplanned_flag_wins_over_other_fallbacks() {
        let (sender, receiver) = tokio::sync::watch::channel(false);
        assert_eq!(
            prefer_unplanned(Err(PlannedShutdownFallback::NotAdmitted), &receiver),
            Err(PlannedShutdownFallback::NotAdmitted)
        );
        sender.send_replace(true);
        assert_eq!(
            prefer_unplanned(Err(PlannedShutdownFallback::NotAdmitted), &receiver),
            Err(PlannedShutdownFallback::Unplanned)
        );
        assert_eq!(
            prefer_unplanned(Err(PlannedShutdownFallback::DeadlineElapsed), &receiver),
            Err(PlannedShutdownFallback::Unplanned)
        );
        // A flag that lands after a completed transfer still yields the weaker
        // Unplanned report; it never claims successor authority.
        assert_eq!(
            prefer_unplanned(Ok(PlannedShutdownOutcome::FollowerRetired), &receiver),
            Err(PlannedShutdownFallback::Unplanned)
        );
    }
    #[tokio::test]
    async fn unplanned_request_racing_preparation_result_keeps_its_reason() {
        for result in [
            Err(PlannedShutdownFallback::NotAdmitted),
            Err(PlannedShutdownFallback::DeadlineElapsed),
            Ok(PlannedShutdownOutcome::FollowerRetired),
        ] {
            let (requested, mut unplanned) = tokio::sync::watch::channel(false);
            let observed = select_preparation(&mut unplanned, async {
                // The unplanned branch has already observed false in this
                // poll. A concurrent request arrives as preparation finishes.
                requested.send_replace(true);
                result
            })
            .await;
            assert_eq!(observed, Err(PlannedShutdownFallback::Unplanned));
        }
    }

    #[tokio::test]
    async fn preparation_result_without_unplanned_request_is_preserved() {
        for result in [
            Err(PlannedShutdownFallback::NotAdmitted),
            Ok(PlannedShutdownOutcome::FollowerRetired),
        ] {
            let (requested, mut unplanned) = tokio::sync::watch::channel(false);
            assert_eq!(
                select_preparation(&mut unplanned, async { result }).await,
                result
            );
            drop(requested);
        }
    }
}
