//! Unanimous fixed-roster recovery. All retained owners promise a new finite
//! range before any participant selects a candidate. Real Raft voting, matching
//! replication, committed application and selected generations finish recovery.

use super::*;
use crate::consensus::persistence_protocol::{Coordinator, LocalRecovery};
use crate::consensus::recovery_types::{
    Action, Capability, Prepared, Ready, Reply, Request, Round, Selection, Status,
};
use crate::sqlite::consensus::wal::async_authority::Reservation;
use opc_consensus::engine::raft::VoteRequest;
use opc_consensus::engine::Vote;

type PeerResult<T> = Result<T, SessionConsensusPeerError>;

fn unavailable<T>(_: T) -> SessionConsensusPeerError {
    SessionConsensusPeerError::Unavailable
}
fn rejected<T>(_: T) -> SessionConsensusPeerError {
    SessionConsensusPeerError::Rejected
}

fn live_rejoin_is_compatible(
    statuses: &BTreeMap<SessionConsensusNodeId, Status>,
    local: SessionConsensusNodeId,
    voters: usize,
) -> bool {
    let Some(own) = statuses.get(&local) else {
        return false;
    };
    !own.recovering
        && statuses
            .values()
            .filter(|status| {
                status.active && status.era == own.era && status.promise == own.promise
            })
            .count()
            > voters / 2
}

fn reservation(round: &Round) -> PeerResult<Reservation> {
    Reservation::recovery(round.era, round.digest()?).map_err(rejected)
}

fn election_vote(selection: &Selection) -> PeerResult<Vote<SessionConsensusNodeId>> {
    Ok(Vote::new(
        reservation(&selection.round)?.retired_through() + 2,
        selection.leader,
    ))
}

fn committed_vote(selection: &Selection) -> PeerResult<Vote<SessionConsensusNodeId>> {
    let mut expected = election_vote(selection)?;
    // Comparison only: this value is never passed to the engine as a vote or
    // returned as evidence. The observed committed vote must equal it.
    expected.commit();
    Ok(expected)
}

fn validate_selection(selection: &Selection) -> PeerResult<()> {
    let round = &selection.round;
    if selection.prepared.len() != round.participants.len()
        || selection.prepared.keys().ne(round.participants.keys())
    {
        return Err(SessionConsensusPeerError::ScopeMismatch);
    }
    let promised = reservation(round)?;
    for (node, prepared) in &selection.prepared {
        let cut = &prepared.retained;
        if round.participants.get(node) != Some(&prepared.participant)
            || prepared.promise != promised.plan()
            || cut.vote != Some(Vote::new(promised.retired_through() + 1, *node))
            || cut.busy
            || cut.generation != cut.completed_generation
            || cut.sequence != cut.completed_sequence
            || cut.applied != cut.committed
            || cut.membership.is_none()
            || cut.last.is_none()
            || cut.last < cut.applied
        {
            return Err(SessionConsensusPeerError::Rejected);
        }
    }
    let candidate = selection
        .prepared
        .iter()
        .max_by(|(a, left), (b, right)| {
            left.retained
                .last
                .cmp(&right.retained.last)
                .then_with(|| b.cmp(a))
        })
        .ok_or(SessionConsensusPeerError::Rejected)?;
    if *candidate.0 != selection.leader {
        return Err(SessionConsensusPeerError::Rejected);
    }
    let last = candidate
        .1
        .retained
        .last
        .ok_or(SessionConsensusPeerError::Rejected)?;
    let membership = candidate.1.retained.membership;
    for prepared in selection.prepared.values() {
        if prepared.retained.membership != membership
            || [prepared.retained.applied, prepared.retained.committed]
                .into_iter()
                .flatten()
                .any(|cut| {
                    cut.index > last.index
                        || cut.leader_id > last.leader_id
                        || (cut.index == last.index && cut != last)
                })
        {
            return Err(SessionConsensusPeerError::Rejected);
        }
    }
    Ok(())
}

impl ConsensusSessionStore {
    /// Install the complete provider retirement authority for this protected
    /// Async configuration. Configure every voter with the same root-signed
    /// inventory before recovery. This is one-time configuration, not permission
    /// to bypass quarantine; readiness still requires real committed application
    /// and completed generations on every retained voter.
    ///
    /// Provider owners must implement the scope-wide retirement contract in
    /// [`crate::consensus::protected_recovery::ProtectedAsyncRecoveryOwner`].
    /// Replacing the configured authority in an open store is rejected.
    pub fn configure_protected_async_recovery(
        &self,
        authority: Arc<crate::consensus::protected_recovery::ProtectedAsyncRecovery>,
    ) -> Result<(), crate::consensus::protected_recovery::ProtectedRecoveryError> {
        use crate::consensus::protected_recovery::ProtectedRecoveryError::AuthorityRejected;
        if self.persistence_mode() != SessionPersistenceMode::Async {
            return Err(AuthorityRejected);
        }
        let root = self
            .inner
            .roster_attestation_trust_root
            .as_ref()
            .ok_or(AuthorityRejected)?;
        authority.inventory().matches(
            self.inner.storage_identity,
            &self.inner.bootstrap_members,
            root,
        )?;
        let inventory = authority.inventory().commitment()?;
        self.inner
            .private_wal
            .as_ref()
            .ok_or(AuthorityRejected)?
            .native_public_scalar_read(|state| {
                state.validate_protected_recovery_inventory(inventory)
            })
            .map_err(|_| AuthorityRejected)?;
        self.inner
            .persistence_protocol
            .protected_recovery
            .set(authority)
            .map_err(|_| AuthorityRejected)
    }

    async fn recovery_scope_before(&self, deadline: tokio::time::Instant) -> PeerResult<()> {
        if self.persistence_mode() != SessionPersistenceMode::Async
            || !self.engine_is_running_in_local_scope()
            || !matches!(
                tokio::time::timeout_at(deadline, self.durable_fixed_quorum_scope_is_exact()).await,
                Ok(Ok(true))
            )
        {
            if self.inner.private_wal.as_ref().is_some_and(|wal| {
                wal.async_retained()
                    .is_ok_and(|cut| cut.membership.is_none())
            }) {
                self.inner.persistence_protocol.recovery_restriction(
                    crate::SessionAsyncRecoveryState::RetainedMembershipRequired,
                );
            }
            return Err(SessionConsensusPeerError::ScopeMismatch);
        }
        Ok(())
    }

    async fn recovery_status_before(&self, deadline: tokio::time::Instant) -> PeerResult<Status> {
        self.recovery_scope_before(deadline).await?;
        let wal = self
            .inner
            .private_wal
            .as_ref()
            .ok_or(SessionConsensusPeerError::Rejected)?;
        let authority = wal.async_authority().map_err(unavailable)?;
        let supported = wal
            .native_public_scalar_read(|state| Ok(state.async_recovery_supported()))
            .map_err(unavailable)?;
        let protected_inventory = self
            .inner
            .persistence_protocol
            .protected_recovery
            .get()
            .map(|authority| authority.inventory().commitment())
            .transpose()
            .map_err(rejected)?;
        if let Some(inventory) = protected_inventory {
            wal.native_public_scalar_read(|state| {
                state.validate_protected_recovery_inventory(inventory)
            })
            .map_err(rejected)?;
        }
        let capability = if authority.is_none() {
            Capability::Legacy
        } else if supported || protected_inventory.is_some() {
            Capability::Reserved
        } else {
            Capability::ProtectedAuthority
        };
        self.inner.persistence_protocol.recovery_limit(capability);
        Ok(Status {
            node: self.inner.local_node_id,
            boot: self.inner.persistence_protocol.boot(),
            root: authority.map_or([0; 32], |(root, _)| root),
            era: authority.map_or(0, |(_, bound)| bound.era()),
            promise: authority.map_or([0; 32], |(_, bound)| bound.plan()),
            active: self.inner.persistence_protocol.is_active(),
            recovering: self
                .inner
                .persistence_protocol
                .is_reforming(deadline)
                .await?,
            capability,
            protected_inventory,
        })
    }

    pub(super) fn recovery_call(
        &self,
        target: SessionConsensusNodeId,
        action: Action,
        deadline: tokio::time::Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = PeerResult<Reply>> + Send + '_>> {
        Box::pin(async move {
            if target == self.inner.local_node_id {
                if matches!(action, Action::Drive) {
                    let owner = self.clone();
                    let (send, receive) = tokio::sync::oneshot::channel();
                    let permit = tokio::time::timeout_at(
                        deadline,
                        Arc::clone(&self.inner.persistence_protocol.cold_rpc_admission)
                            .acquire_owned(),
                    )
                    .await
                    .map_err(|_| SessionConsensusPeerError::Timeout)?
                    .map_err(unavailable)?;
                    tokio::spawn(async move {
                        let result = owner
                            .recovery_action(owner.inner.local_node_id, action, deadline)
                            .await;
                        let _ = send.send(result);
                        drop(permit);
                    });
                    tokio::time::timeout_at(deadline, receive)
                        .await
                        .map_err(|_| SessionConsensusPeerError::Timeout)?
                        .map_err(unavailable)?
                } else {
                    self.recovery_action(self.inner.local_node_id, action, deadline)
                        .await
                }
            } else {
                self.call_peer(
                    target,
                    SessionConsensusRpcFamily::ReadBarrier,
                    &Request::new(action),
                    deadline,
                )
                .await
                .map_err(|failure| match failure {
                    ConsensusPeerCallFailure::AuthenticatedRejection(error) => error,
                    _ => SessionConsensusPeerError::Unavailable,
                })
            }
        })
    }

    async fn recovery_statuses(
        &self,
        deadline: tokio::time::Instant,
        allow_live: bool,
    ) -> PeerResult<BTreeMap<SessionConsensusNodeId, Status>> {
        let mut responses: FuturesUnordered<_> = self
            .inner
            .bootstrap_members
            .iter()
            .copied()
            .map(|node| async move {
                (
                    node,
                    self.recovery_call(node, Action::Status, deadline).await,
                )
            })
            .collect();
        let mut statuses = BTreeMap::new();
        while let Some((node, reply)) = tokio::time::timeout_at(deadline, responses.next())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?
        {
            let reply = match reply {
                Ok(reply) => reply,
                // One unavailable member must not prevent the existing live
                // majority from admitting an ordinary sequential rejoin.
                // An incomplete set can never authorize unanimous recovery.
                Err(_) if allow_live => continue,
                Err(error) => return Err(error),
            };
            let Reply::Status(status) = reply else {
                return Err(SessionConsensusPeerError::Protocol);
            };
            if status.node != node {
                return Err(SessionConsensusPeerError::ScopeMismatch);
            }
            statuses.insert(node, status);
            if allow_live
                && live_rejoin_is_compatible(
                    &statuses,
                    self.inner.local_node_id,
                    self.inner.bootstrap_members.len(),
                )
            {
                break;
            }
        }
        Ok(statuses)
    }

    pub(super) async fn try_majority_recovery_before(
        &self,
        deadline: tokio::time::Instant,
    ) -> PeerResult<bool> {
        // Resolve local unsupported/repair-required posture before reporting
        // unavailable peers. These fixed reasons contain no authority values.
        self.recovery_status_before(deadline).await?;
        let statuses = match self.recovery_statuses(deadline, true).await {
            Ok(statuses) => statuses,
            Err(error) => {
                self.inner.persistence_protocol.recovery_restriction(
                    crate::SessionAsyncRecoveryState::AwaitingRecoveryParticipants,
                );
                return Err(error);
            }
        };
        if live_rejoin_is_compatible(
            &statuses,
            self.inner.local_node_id,
            self.inner.bootstrap_members.len(),
        ) {
            return Ok(false);
        }
        if statuses.len() != self.inner.bootstrap_members.len() {
            self.inner.persistence_protocol.recovery_restriction(
                crate::SessionAsyncRecoveryState::AwaitingRecoveryParticipants,
            );
            return Ok(false);
        }
        if let Some(status) = statuses
            .values()
            .find(|status| status.capability != Capability::Reserved)
        {
            self.inner
                .persistence_protocol
                .recovery_limit(status.capability);
            return Err(SessionConsensusPeerError::Rejected);
        }
        let coordinator = self
            .inner
            .bootstrap_members
            .first()
            .copied()
            .ok_or(SessionConsensusPeerError::Rejected)?;
        self.recovery_call(coordinator, Action::Drive, deadline)
            .await?;
        Ok(self.inner.persistence_protocol.is_active())
    }

    pub(in crate::consensus::store) async fn handle_majority_recovery(
        &self,
        sender: SessionConsensusNodeId,
        payload: &[u8],
    ) -> SessionConsensusWireResponse {
        let request = match decode_bounded::<Request>(payload) {
            Ok(request) if request.is_valid() => request,
            _ => return protocol_rejection(),
        };
        let deadline = self.operation_deadline_from(tokio::time::Instant::now());
        let permit = match tokio::time::timeout_at(
            deadline,
            Arc::clone(&self.inner.persistence_protocol.cold_rpc_admission).acquire_owned(),
        )
        .await
        {
            Ok(Ok(permit)) => permit,
            _ => {
                return SessionConsensusWireResponse {
                    result: Err(SessionConsensusPeerError::Timeout),
                }
            }
        };
        let owner = self.clone();
        let (send, receive) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = owner
                .recovery_action(sender, request.action, deadline)
                .await;
            let response = match result {
                Ok(reply) => encode_service_reply(&reply),
                Err(error) => SessionConsensusWireResponse { result: Err(error) },
            };
            let _ = send.send(response);
            drop(permit);
        });
        match tokio::time::timeout_at(deadline, receive).await {
            Ok(Ok(response)) => response,
            _ => SessionConsensusWireResponse {
                result: Err(SessionConsensusPeerError::Timeout),
            },
        }
    }

    async fn recovery_action(
        &self,
        sender: SessionConsensusNodeId,
        action: Action,
        deadline: tokio::time::Instant,
    ) -> PeerResult<Reply> {
        self.recovery_scope_before(deadline).await?;
        if !self.inner.bootstrap_members.contains(&sender) {
            return Err(SessionConsensusPeerError::ScopeMismatch);
        }
        if !matches!(action, Action::Status | Action::Drive)
            && self.inner.bootstrap_members.first().copied() != Some(sender)
        {
            return Err(SessionConsensusPeerError::ScopeMismatch);
        }
        match action {
            Action::Status => Ok(Reply::Status(self.recovery_status_before(deadline).await?)),
            Action::Drive => self.drive_recovery_before(deadline).await,
            Action::Prepare(round) => self
                .prepare_recovery(round, deadline)
                .await
                .map(|prepared| Reply::Prepared(Box::new(prepared))),
            Action::Select(selection) => {
                self.select_recovery(selection, deadline).await?;
                Ok(Reply::Selected)
            }
            Action::Commit(selection) => self
                .commit_recovery(selection, deadline)
                .await
                .map(Reply::Committed),
            Action::CommitStatus(selection) => self
                .protected_commit_status(&selection, deadline)
                .await
                .map(Reply::CommitStatus),
            Action::Ready {
                selection,
                boundary,
            } => self
                .ready_recovery(&selection, boundary, deadline)
                .await
                .map(Reply::Ready),
            Action::Activate { selection, ready } => {
                self.activate_recovery(&selection, &ready, deadline).await
            }
        }
    }

    async fn prepare_recovery(
        &self,
        round: Round,
        deadline: tokio::time::Instant,
    ) -> PeerResult<Prepared> {
        round.validate(self.inner.storage_identity, &self.inner.bootstrap_members)?;
        let protocol = &self.inner.persistence_protocol;
        let mut local = tokio::time::timeout_at(deadline, protocol.recovery_local.lock())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?;
        if let Some(prior) = local.as_ref().filter(|prior| prior.round == round) {
            if let Some(prepared) = &prior.prepared {
                return Ok(prepared.clone());
            }
        }
        let status = self.recovery_status_before(deadline).await?;
        let original = round
            .participants
            .get(&self.inner.local_node_id)
            .ok_or(SessionConsensusPeerError::ScopeMismatch)?;
        let bound = reservation(&round)?;
        let before = if original.era == 1 {
            Reservation::initial()
        } else {
            Reservation::recovery(original.era, original.promise).map_err(rejected)?
        };
        if status.boot != original.boot
            || status.root != original.root
            || status.protected_inventory != original.protected_inventory
            || status.capability != Capability::Reserved
            || !((status.era == before.era() && status.promise == before.plan())
                || (local.as_ref().is_some_and(|prior| prior.round == round)
                    && status.era == bound.era()
                    && status.promise == bound.plan()))
        {
            return Err(SessionConsensusPeerError::Rejected);
        }
        *local = Some(LocalRecovery {
            round: round.clone(),
            prepared: None,
            selection: None,
            proposal: None,
        });
        self.inner.raft.runtime_config().elect(false);
        self.inner.raft.runtime_config().heartbeat(false);
        protocol
            .prepare_recovery_before(bound.plan(), bound.era(), deadline, || async {
                let wal = Arc::clone(
                    self.inner
                        .private_wal
                        .as_ref()
                        .ok_or(SessionConsensusPeerError::Rejected)?,
                );
                // Join accepted disk publication even after caller cancellation or
                // deadline expiry. The outer transport supervisor owns this turn.
                tokio::task::spawn_blocking(move || wal.promise_async_authority(before, bound))
                    .await
                    .map_err(unavailable)?
                    .map_err(unavailable)?;
                let vote = Vote::new(bound.retired_through() + 1, self.inner.local_node_id);
                loop {
                    if tokio::time::Instant::now() >= deadline {
                        return Err(SessionConsensusPeerError::Timeout);
                    }
                    let wal = self
                        .inner
                        .private_wal
                        .as_ref()
                        .ok_or(SessionConsensusPeerError::Rejected)?;
                    let last = wal.async_retained().map_err(unavailable)?.last;
                    // This is the actual candidate's log, including its full
                    // LogId. The engine's leader lease and vote checks stay intact.
                    let reply = self
                        .inner
                        .raft
                        .vote(VoteRequest::new(vote, last))
                        .await
                        .map_err(unavailable)?;
                    if reply.vote_granted && reply.vote == vote && reply.last_log_id == last {
                        break;
                    }
                    tokio::time::timeout_at(
                        deadline,
                        tokio::time::sleep(Duration::from_millis(10)),
                    )
                    .await
                    .map_err(|_| SessionConsensusPeerError::Timeout)?;
                }
                loop {
                    self.drain_async_persistence_before(deadline)
                        .await
                        .map_err(unavailable)?;
                    let cut = self
                        .inner
                        .private_wal
                        .as_ref()
                        .ok_or(SessionConsensusPeerError::Rejected)?
                        .async_retained()
                        .map_err(unavailable)?;
                    if cut.vote == Some(vote)
                        && cut.applied == cut.committed
                        && !cut.busy
                        && cut.generation == cut.completed_generation
                        && cut.sequence == cut.completed_sequence
                    {
                        return Ok(());
                    }
                    tokio::time::timeout_at(
                        deadline,
                        tokio::time::sleep(Duration::from_millis(10)),
                    )
                    .await
                    .map_err(|_| SessionConsensusPeerError::Timeout)?;
                }
            })
            .await?;
        let prepared = Prepared {
            participant: original.clone(),
            promise: bound.plan(),
            retained: self
                .inner
                .private_wal
                .as_ref()
                .ok_or(SessionConsensusPeerError::Rejected)?
                .async_retained()
                .map_err(unavailable)?,
        };
        local
            .as_mut()
            .ok_or(SessionConsensusPeerError::Rejected)?
            .prepared = Some(prepared.clone());
        Ok(prepared)
    }

    async fn select_recovery(
        &self,
        selection: Selection,
        deadline: tokio::time::Instant,
    ) -> PeerResult<()> {
        selection
            .round
            .validate(self.inner.storage_identity, &self.inner.bootstrap_members)?;
        validate_selection(&selection)?;
        let protocol = &self.inner.persistence_protocol;
        let mut local = tokio::time::timeout_at(deadline, protocol.recovery_local.lock())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?;
        let local = local.as_mut().ok_or(SessionConsensusPeerError::Rejected)?;
        if local.round != selection.round
            || local.prepared.as_ref() != selection.prepared.get(&self.inner.local_node_id)
            || local
                .selection
                .as_ref()
                .is_some_and(|prior| prior != &selection)
        {
            return Err(SessionConsensusPeerError::Rejected);
        }
        if self.inner.local_node_id == selection.leader {
            let cuts = selection
                .prepared
                .values()
                .flat_map(|p| [p.retained.committed, p.retained.applied])
                .flatten()
                .collect::<Vec<_>>();
            if !self
                .inner
                .private_wal
                .as_ref()
                .ok_or(SessionConsensusPeerError::Rejected)?
                .async_covers_committed(&cuts)
                .map_err(unavailable)?
            {
                protocol.recovery_restriction(
                    crate::SessionAsyncRecoveryState::RetainedHistoryConflict,
                );
                return Err(SessionConsensusPeerError::Rejected);
            }
        }
        protocol
            .select_recovery_before(
                selection.round.digest()?,
                selection.round.era,
                election_vote(&selection)?,
                deadline,
            )
            .await?;
        local.selection = Some(selection);
        Ok(())
    }

    async fn commit_recovery(
        &self,
        selection: Selection,
        deadline: tokio::time::Instant,
    ) -> PeerResult<LogId<SessionConsensusNodeId>> {
        if selection.leader != self.inner.local_node_id {
            return Err(SessionConsensusPeerError::Rejected);
        }
        validate_selection(&selection)?;
        let protocol = &self.inner.persistence_protocol;
        let mut owner = tokio::time::timeout_at(deadline, protocol.recovery_local.lock())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?;
        let local = owner.as_mut().ok_or(SessionConsensusPeerError::Rejected)?;
        if local.selection.as_ref() != Some(&selection) {
            return Err(SessionConsensusPeerError::Rejected);
        }
        let guard = protocol.engine_before(deadline).await?;
        if !guard.recovery_matches(selection.round.digest()?, selection.round.era) {
            return Err(SessionConsensusPeerError::Rejected);
        }
        let mut receive = if let Some(receive) = &local.proposal {
            receive.clone()
        } else {
            let expected = committed_vote(&selection)?;
            let current = self.inner.raft.metrics().borrow().vote;
            if current != expected {
                if current
                    != Vote::new(
                        reservation(&selection.round)?.retired_through() + 1,
                        self.inner.local_node_id,
                    )
                    && current != election_vote(&selection)?
                {
                    return Err(SessionConsensusPeerError::Rejected);
                }
                if current != election_vote(&selection)? {
                    self.inner
                        .raft
                        .trigger()
                        .elect()
                        .await
                        .map_err(unavailable)?;
                }
                let mut metrics = self.inner.raft.metrics();
                loop {
                    if metrics.borrow_and_update().vote == expected {
                        break;
                    }
                    tokio::time::timeout_at(deadline, metrics.changed())
                        .await
                        .map_err(|_| SessionConsensusPeerError::Timeout)?
                        .map_err(unavailable)?;
                }
            }
            let command = SessionConsensusCommand {
                schema_version: SESSION_CONSENSUS_SCHEMA_VERSION,
                identity: self.inner.storage_identity,
                request_id: selection.round.nonce,
                logical_time: self.inner.clock.now_utc(),
                intent: SessionMutationIntent::AsyncRecoveryBoundary {
                    era: selection.round.era,
                    plan: selection.round.digest()?,
                    protected: match self.inner.persistence_protocol.protected_recovery.get() {
                        Some(authority) => {
                            protocol.recovery_restriction(
                                crate::SessionAsyncRecoveryState::AwaitingProtectedRetirement,
                            );
                            let proof = authority.retire_before(&selection, deadline).await.map_err(|error| {
                                use crate::consensus::protected_recovery::ProtectedRecoveryError;
                                if error == ProtectedRecoveryError::AuthorityRejected {
                                    protocol.recovery_restriction(crate::SessionAsyncRecoveryState::ProtectedAuthorityRejected);
                                }
                                match error {
                                    ProtectedRecoveryError::Deadline => SessionConsensusPeerError::Timeout,
                                    ProtectedRecoveryError::OwnerPending => SessionConsensusPeerError::Unavailable,
                                    ProtectedRecoveryError::AuthorityRejected => SessionConsensusPeerError::Rejected,
                                }
                            })?;
                            Some(Box::new(proof))
                        }
                        None => None,
                    },
                },
            };
            let response = self
                .inner
                .raft
                .client_write_ff(command)
                .await
                .map_err(unavailable)?;
            let (send, receive) = tokio::sync::watch::channel(None);
            tokio::spawn(async move {
                let result = match response.await {
                    Ok(Ok(response))
                        if response.data.result == Ok(SessionMutationOutcome::Unit)
                            && response.log_id.leader_id
                                == CommittedLeaderId::new(
                                    expected.leader_id.term,
                                    selection.leader,
                                )
                            && response.data.raft_log_index == response.log_id.index =>
                    {
                        Ok(response.log_id)
                    }
                    _ => Err(()),
                };
                let _ = send.send(Some(result));
            });
            local.proposal = Some(receive.clone());
            receive
        };
        drop(guard);
        drop(owner);
        // Never hold preparation's mutex/fence through a possibly uncommittable
        // accepted proposal. A newer round must be able to retire this owner.
        loop {
            if let Some(result) = *receive.borrow_and_update() {
                return result.map_err(unavailable);
            }
            tokio::time::timeout_at(deadline, receive.changed())
                .await
                .map_err(|_| SessionConsensusPeerError::Timeout)?
                .map_err(unavailable)?;
        }
    }

    async fn protected_commit_status(
        &self,
        selection: &Selection,
        deadline: tokio::time::Instant,
    ) -> PeerResult<bool> {
        validate_selection(selection)?;
        if selection.leader != self.inner.local_node_id
            || self
                .inner
                .persistence_protocol
                .protected_recovery
                .get()
                .is_none()
        {
            return Ok(false);
        }
        let protocol = &self.inner.persistence_protocol;
        let owner = tokio::time::timeout_at(deadline, protocol.recovery_local.lock())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?;
        let Some(local) = owner
            .as_ref()
            .filter(|local| local.selection.as_ref() == Some(selection))
        else {
            return Ok(false);
        };
        let guard = protocol.engine_before(deadline).await?;
        if !guard.recovery_matches(selection.round.digest()?, selection.round.era)
            || self.inner.raft.metrics().borrow().vote != committed_vote(selection)?
        {
            return Ok(false);
        }
        // A current real committed election permits another observation of
        // its owned retirement/proposal. It does not prove either completed.
        // A failed accepted proposal must instead be retired by a newer round.
        Ok(local
            .proposal
            .as_ref()
            .is_none_or(|completion| !matches!(*completion.borrow(), Some(Err(())))))
    }

    async fn ready_recovery(
        &self,
        selection: &Selection,
        boundary: LogId<SessionConsensusNodeId>,
        deadline: tokio::time::Instant,
    ) -> PeerResult<Ready> {
        validate_selection(selection)?;
        let protocol = &self.inner.persistence_protocol;
        let plan = selection.round.digest()?;
        let vote = committed_vote(selection)?;
        if boundary.leader_id != CommittedLeaderId::new(vote.leader_id.term, selection.leader) {
            return Err(SessionConsensusPeerError::Rejected);
        }
        loop {
            let guard = protocol.engine_before(deadline).await?;
            if !guard.recovery_matches(plan, selection.round.era) {
                return Err(SessionConsensusPeerError::Rejected);
            }
            self.drain_async_persistence_before(deadline)
                .await
                .map_err(unavailable)?;
            self.recovery_scope_before(deadline).await?;
            let wal = self
                .inner
                .private_wal
                .as_ref()
                .ok_or(SessionConsensusPeerError::Rejected)?;
            let retained = wal.async_retained().map_err(unavailable)?;
            let matched =
                self.inner.local_node_id == selection.leader || guard.recovery_matched(boundary);
            let metrics = self.inner.raft.metrics().borrow().clone();
            if matched
                && retained.boundary == Some((selection.round.era, plan, boundary))
                && retained.vote == Some(vote)
                && retained.generation == retained.completed_generation
                && retained.sequence == retained.completed_sequence
                && !retained.busy
                && retained
                    .applied
                    .is_some_and(|cut| persistence_protocol::covers(cut, boundary))
                && metrics.vote == vote
                && metrics.current_leader == Some(selection.leader)
                && metrics.last_applied == retained.applied
                && *metrics.membership_config.log_id() == retained.membership
                && wal
                    .native_public_scalar_read(|state| {
                        Ok(state.protected_recovery_matches(selection))
                    })
                    .map_err(rejected)?
            {
                let status = selection
                    .round
                    .participants
                    .get(&self.inner.local_node_id)
                    .ok_or(SessionConsensusPeerError::Rejected)?;
                return Ok(Ready {
                    node: self.inner.local_node_id,
                    boot: protocol.boot(),
                    root: status.root,
                    promise: plan,
                    vote,
                    boundary,
                    membership: retained.membership,
                    completed_generation: retained.completed_generation,
                    completed_sequence: retained.completed_sequence,
                });
            }
            drop(guard);
            tokio::time::timeout_at(deadline, tokio::time::sleep(Duration::from_millis(10)))
                .await
                .map_err(|_| SessionConsensusPeerError::Timeout)?;
        }
    }

    async fn activate_recovery(
        &self,
        selection: &Selection,
        ready: &BTreeMap<SessionConsensusNodeId, Ready>,
        deadline: tokio::time::Instant,
    ) -> PeerResult<Reply> {
        selection
            .round
            .validate(self.inner.storage_identity, &self.inner.bootstrap_members)?;
        validate_selection(selection)?;
        if ready.len() != selection.round.participants.len()
            || ready.keys().ne(selection.round.participants.keys())
        {
            return Err(SessionConsensusPeerError::Rejected);
        }
        let own = ready
            .get(&self.inner.local_node_id)
            .ok_or(SessionConsensusPeerError::Rejected)?;
        let plan = selection.round.digest()?;
        let vote = committed_vote(selection)?;
        for (node, response) in ready {
            let expected = &selection.round.participants[node];
            if response.node != *node
                || response.boot != expected.boot
                || response.root != expected.root
                || response.promise != plan
                || response.vote != vote
                || response.boundary != own.boundary
                || response.membership != own.membership
            {
                return Err(SessionConsensusPeerError::Rejected);
            }
        }
        if own.boot != self.inner.persistence_protocol.boot() {
            return Err(SessionConsensusPeerError::Rejected);
        }
        let protocol = &self.inner.persistence_protocol;
        let current = tokio::time::timeout_at(deadline, protocol.recovery_local.lock())
            .await
            .map_err(|_| SessionConsensusPeerError::Timeout)?;
        if current.as_ref().and_then(|local| local.selection.as_ref()) != Some(selection) {
            return Err(SessionConsensusPeerError::Rejected);
        }
        let check = || async {
            if self.recovery_scope_before(deadline).await.is_err() {
                return false;
            }
            let Some(wal) = &self.inner.private_wal else {
                return false;
            };
            let Ok(cut) = wal.async_retained() else {
                return false;
            };
            let metrics = self.inner.raft.metrics().borrow().clone();
            cut.boundary == Some((selection.round.era, plan, own.boundary))
                && cut.vote.is_some_and(|current| current >= vote)
                && cut.completed_generation >= own.completed_generation
                && cut.completed_sequence >= own.completed_sequence
                && Some(metrics.vote) == cut.vote
                && *metrics.membership_config.log_id() == own.membership
                && metrics.last_applied.is_some_and(|applied| {
                    applied.index >= own.boundary.index
                        && applied.leader_id >= own.boundary.leader_id
                        && (applied.index != own.boundary.index || applied == own.boundary)
                })
        };
        if protocol.is_active() {
            if !check().await {
                return Err(SessionConsensusPeerError::Rejected);
            }
        } else if !protocol
            .activate_recovery_before(plan, selection.round.era, deadline, check)
            .await?
        {
            return Err(SessionConsensusPeerError::Rejected);
        }
        self.inner.raft.runtime_config().elect(true);
        self.inner.raft.runtime_config().heartbeat(true);
        Ok(Reply::Active)
    }

    async fn drive_recovery_before(&self, deadline: tokio::time::Instant) -> PeerResult<Reply> {
        if self.inner.bootstrap_members.first().copied() != Some(self.inner.local_node_id) {
            return Err(SessionConsensusPeerError::Rejected);
        }
        let mut current = tokio::time::timeout_at(
            deadline,
            self.inner.persistence_protocol.recovery_coordinator.lock(),
        )
        .await
        .map_err(|_| SessionConsensusPeerError::Timeout)?;
        let statuses = self.recovery_statuses(deadline, false).await?;
        if statuses.values().all(|status| status.active) {
            *current = None;
            return Ok(Reply::Active);
        }
        if statuses.len() != self.inner.bootstrap_members.len()
            || statuses
                .values()
                .any(|s| s.capability != Capability::Reserved)
        {
            return Err(SessionConsensusPeerError::Rejected);
        }
        if current.as_ref().is_some_and(|prior| {
            let Ok(plan) = prior.round.digest() else {
                return true;
            };
            statuses.iter().any(|(node, status)| {
                let old = &prior.round.participants[node];
                status.boot != old.boot
                    || status.root != old.root
                    || !((status.era == old.era && status.promise == old.promise)
                        || (status.era == prior.round.era && status.promise == plan))
            })
        }) {
            *current = None;
        }
        if let Some(prior) = current.as_mut().filter(|prior| prior.restart) {
            let can_resume = if let Some(selection) = prior.selection.as_ref().filter(|selection| {
                prior.resume_owned_commit
                    && selection
                        .round
                        .participants
                        .values()
                        .all(|status| status.protected_inventory.is_some())
            }) {
                match self
                    .recovery_call(
                        selection.leader,
                        Action::CommitStatus(selection.clone()),
                        deadline,
                    )
                    .await?
                {
                    Reply::CommitStatus(value) => value,
                    _ => return Err(SessionConsensusPeerError::Protocol),
                }
            } else {
                false
            };
            if can_resume {
                prior.restart = false;
            } else {
                *current = None;
            }
        }
        if current.is_none() {
            if statuses.values().filter(|s| s.active).count() > statuses.len() / 2
                && !statuses.values().any(|s| s.recovering)
                && statuses.values().all(|s| {
                    statuses
                        .values()
                        .next()
                        .is_some_and(|first| s.era == first.era && s.promise == first.promise)
                })
            {
                return Err(SessionConsensusPeerError::Rejected);
            }
            let era = statuses
                .values()
                .map(|s| s.era)
                .max()
                .and_then(|era| era.checked_add(1))
                .ok_or(SessionConsensusPeerError::Rejected)?;
            let round = Round {
                identity: self.inner.storage_identity,
                voters: fenced_transition_voter_set_digest(
                    self.inner.storage_identity,
                    &self.inner.bootstrap_members,
                ),
                era,
                nonce: SessionConsensusRequestId::new(),
                participants: statuses,
            };
            reservation(&round).inspect_err(|_| {
                self.inner.persistence_protocol.recovery_restriction(
                    crate::SessionAsyncRecoveryState::AuthorityRangeExhausted,
                );
            })?;
            *current = Some(Coordinator {
                round,
                selection: None,
                boundary: None,
                ready: BTreeMap::new(),
                restart: false,
                resume_owned_commit: false,
            });
        }
        let current = current
            .as_mut()
            .ok_or(SessionConsensusPeerError::Rejected)?;
        if current.selection.is_none() {
            let results = futures_util::future::join_all(
                self.inner.bootstrap_members.iter().copied().map(|node| {
                    self.recovery_call(node, Action::Prepare(current.round.clone()), deadline)
                }),
            )
            .await;
            let mut prepared = BTreeMap::new();
            for result in results {
                let Reply::Prepared(value) = result? else {
                    return Err(SessionConsensusPeerError::Protocol);
                };
                if prepared.insert(value.participant.node, *value).is_some() {
                    return Err(SessionConsensusPeerError::Rejected);
                }
            }
            let leader = prepared
                .iter()
                .max_by(|(a, left), (b, right)| {
                    left.retained
                        .last
                        .cmp(&right.retained.last)
                        .then_with(|| b.cmp(a))
                })
                .map(|(node, _)| *node)
                .ok_or(SessionConsensusPeerError::Rejected)?;
            let selection = Selection {
                round: current.round.clone(),
                prepared,
                leader,
            };
            validate_selection(&selection)?;
            current.selection = Some(selection);
        }
        let selection = current
            .selection
            .as_ref()
            .ok_or(SessionConsensusPeerError::Rejected)?;
        if current.boundary.is_none() {
            let results =
                futures_util::future::join_all(self.inner.bootstrap_members.iter().copied().map(
                    |node| self.recovery_call(node, Action::Select(selection.clone()), deadline),
                ))
                .await;
            for result in results {
                if !matches!(result?, Reply::Selected) {
                    return Err(SessionConsensusPeerError::Protocol);
                }
            }
            let reply = self
                .recovery_call(
                    selection.leader,
                    Action::Commit(selection.clone()),
                    deadline,
                )
                .await;
            let boundary = match reply {
                Ok(Reply::Committed(boundary)) => boundary,
                other => {
                    // A triggered election makes one real vote attempt. It
                    // cannot safely reuse its term after a lost response, and
                    // an accepted proposal may still finish. The next drive
                    // must either verify that the exact protected election
                    // still owns resumable work, or prepare a strictly newer
                    // range. That preparation drains and supersedes old effects.
                    current.restart = true;
                    let error = other.err().unwrap_or(SessionConsensusPeerError::Protocol);
                    current.resume_owned_commit = matches!(
                        error,
                        SessionConsensusPeerError::Timeout | SessionConsensusPeerError::Unavailable
                    );
                    return Err(error);
                }
            };
            current.boundary = Some(boundary);
        }
        let boundary = current
            .boundary
            .ok_or(SessionConsensusPeerError::Rejected)?;
        if current.ready.len() != self.inner.bootstrap_members.len() {
            let results = futures_util::future::join_all(
                self.inner.bootstrap_members.iter().copied().map(|node| {
                    self.recovery_call(
                        node,
                        Action::Ready {
                            selection: selection.clone(),
                            boundary,
                        },
                        deadline,
                    )
                }),
            )
            .await;
            for result in results {
                let Reply::Ready(value) = result? else {
                    return Err(SessionConsensusPeerError::Protocol);
                };
                current.ready.insert(value.node, value);
            }
        }
        let results = futures_util::future::join_all(
            self.inner.bootstrap_members.iter().copied().map(|node| {
                self.recovery_call(
                    node,
                    Action::Activate {
                        selection: selection.clone(),
                        ready: current.ready.clone(),
                    },
                    deadline,
                )
            }),
        )
        .await;
        for result in results {
            if !matches!(result?, Reply::Active) {
                return Err(SessionConsensusPeerError::Protocol);
            }
        }
        Ok(Reply::Active)
    }
}
