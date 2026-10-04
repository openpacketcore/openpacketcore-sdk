//! Planned retirement composes engine-owned handoff with authenticated peers.

use futures_util::stream::FuturesUnordered;
use opc_consensus::engine::raft::{TransferLeaderError, TransferLeaderRequest};

use super::*;

/// One retained preparation per store incarnation. A cancelled observer must
/// neither resume local admission nor select another successor.
pub(super) struct ConsensusRetirementCoordinator {
    started: AtomicBool,
    completion: Mutex<Option<tokio::sync::watch::Receiver<ConsensusShutdownCompletion>>>,
}

impl ConsensusRetirementCoordinator {
    pub(super) const fn new() -> Self {
        Self {
            started: AtomicBool::new(false),
            completion: Mutex::new(None),
        }
    }

    pub(super) fn is_started(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }

    fn start_or_subscribe(
        &self,
        store: ConsensusSessionStore,
    ) -> tokio::sync::watch::Receiver<ConsensusShutdownCompletion> {
        let mut completion = self
            .completion
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(receiver) = completion.as_ref() {
            return receiver.clone();
        }
        let deadline = store.operation_deadline_from(tokio::time::Instant::now());
        let (sender, receiver) = tokio::sync::watch::channel(ConsensusShutdownCompletion::Running);
        *completion = Some(receiver.clone());
        tokio::spawn(async move {
            // This is the original complete-operation budget. Later callers
            // observe its retained outcome; they cannot extend the handoff.
            let result = tokio::time::timeout_at(deadline, store.prepare_shutdown_before(deadline))
                .await
                .unwrap_or_else(|_| Err(consensus_unavailable()));
            sender.send_replace(ConsensusShutdownCompletion::Finished(result));
        });
        receiver
    }
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
        let completion = self.inner.retirement.start_or_subscribe(self.clone());
        tokio::time::timeout(
            self.inner.operation_timeout,
            await_consensus_session_store_shutdown(completion),
        )
        .await
        .unwrap_or_else(|_| Err(consensus_unavailable()))
    }

    async fn prepare_shutdown_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> Result<(), StoreError> {
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
        .map_err(|_| consensus_unavailable())?;
        self.require_durable_fixed_quorum_admission_before(deadline)
            .await?;
        if !matches!(
            self.operator_recovery_gate_before(deadline).await,
            OperatorRecoveryGate::Clear
        ) || !self
            .durable_uniform_scope_is_admitted()
            .await
            .map_err(|_| consensus_unavailable())?
        {
            return Err(consensus_unavailable());
        }
        let scope = self.current_scope()?;
        let local = self.inner.local_node_id;
        let quorum = scope.1.len() / 2 + 1;
        if scope.1.len().saturating_sub(1) < quorum {
            return Err(consensus_unavailable());
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
                .ok_or_else(consensus_unavailable)?
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
            .map_err(|_| consensus_unavailable())?;
        if let Some(request) = handoff.as_ref() {
            self.release_surviving_vote_leases(&scope, request, quorum, deadline)
                .await?;
            self.start_successor_election(&scope, request, deadline)
                .await?;
        }
        self.confirm_surviving_leader(&scope, handoff.as_ref(), deadline)
            .await
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
    ) -> Result<(), StoreError> {
        loop {
            if self.current_scope()? != *scope || !self.inner.persistence_protocol.is_active() {
                return Err(consensus_unavailable());
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
                        .await?;
                }
                _ => return Err(consensus_unavailable()),
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
