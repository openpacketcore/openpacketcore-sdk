//! Volatile class admission at the durable proposal and outbound boundaries.
//! Class metadata is authenticated forwarding context, never command bytes.
use super::*;
#[cfg(test)]
use crate::scope_scheduler::ScopeSchedulerBudgets;
use crate::scope_scheduler::{
    ScopeScheduler, ScopeSchedulerError, ScopeSchedulerKey, ScopeSchedulerOwner,
    ScopeSchedulerSnapshot, ScopeWorkClass, ScopeWorkPermit, ScopeWorkReservation,
};

/// Explicit field: missing metadata must fail decoding, never silently select
/// an old shared pool. Only admitted own-scope batches may declare a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum ForwardWorkClass {
    Inferred,
    Declared(ScopeWorkClass),
}

impl ForwardMutationRequest {
    pub(super) fn scheduling(&self) -> Result<(ScopeSchedulerKey, ScopeWorkClass), StoreError> {
        let class = match (self.work_class, &self.intent) {
            (ForwardWorkClass::Declared(ScopeWorkClass::SafetyControl), _)
            | (ForwardWorkClass::Declared(_), SessionMutationIntent::Authorized { .. }) => {
                return Err(StoreError::TopologyAuthorityRevoked);
            }
            (
                ForwardWorkClass::Declared(class),
                SessionMutationIntent::ScopeBatch(_) | SessionMutationIntent::ScopeBatchCancel(_),
            ) => class,
            (ForwardWorkClass::Declared(_), _) => return Err(StoreError::TopologyAuthorityRevoked),
            (ForwardWorkClass::Inferred, intent) => inferred_class(intent),
        };
        let lane = match &self.intent {
            SessionMutationIntent::ScopeBatch(command) => Some(command.request.lane()),
            SessionMutationIntent::ScopeBatchCancel(command) => Some(command.attempt.lane()),
            _ => None,
        };
        if let Some(lane) = lane {
            crate::scope_batch::require_data_lane_class(lane, class)
                .map_err(|_| StoreError::TopologyAuthorityRevoked)?;
        }
        let key = match &self.intent {
            SessionMutationIntent::ScopeAuthority(command) => scope_key(command.request.scope()),
            SessionMutationIntent::ScopeBatch(command) => scope_key(command.request.scope()),
            SessionMutationIntent::ScopeBatchCancel(command) => {
                scope_key(command.attempt.stamp().scope())
            }
            // Non-scope legacy traffic is an aggregate, not one tenant. It
            // shares the full class budget without a per-scope reduction.
            // Only the authenticated scope API can declare emergency classes.
            _ => ScopeSchedulerKey::INTERNAL,
        };
        Ok((key, class))
    }
}

fn inferred_class(intent: &SessionMutationIntent) -> ScopeWorkClass {
    match intent {
        SessionMutationIntent::ScopeAuthority(_)
        | SessionMutationIntent::VoterSlotControl(_)
        | SessionMutationIntent::PreflightScopeProfile
        | SessionMutationIntent::ActivateScopeProfile(_)
        | SessionMutationIntent::CertifyScopeProfileContinuation(_)
        | SessionMutationIntent::PrepareTopologyTransition { .. }
        | SessionMutationIntent::MarkTopologyLearnersReady { .. }
        | SessionMutationIntent::FenceTopologyAuthority { .. }
        | SessionMutationIntent::AbortTopologyTransition { .. }
        | SessionMutationIntent::FinalizeTopologyTransition { .. }
        | SessionMutationIntent::FinalizeOperatorRecovery { .. }
        | SessionMutationIntent::FinalizeOperatorRecoveryV2(_)
        | SessionMutationIntent::AsyncRecoveryBoundary { .. }
        | SessionMutationIntent::PreflightFencedTransitionCapability
        | SessionMutationIntent::ActivateFencedTransitionCapability { .. }
        | SessionMutationIntent::PreflightProtectedRosterProfile
        | SessionMutationIntent::PreflightProtectedRosterProfileV2
        | SessionMutationIntent::ActivateProtectedRosterProfileV2 { .. } => {
            ScopeWorkClass::SafetyControl
        }
        SessionMutationIntent::MaintainFencedTransitionV2History { .. } => {
            ScopeWorkClass::Maintenance
        }
        // Unclassified read APIs, including both logical-read supervisors,
        // use Normal. Explicit record-expiry floors acquire Maintenance at
        // their typed entry points; sharing this intent does not make a read
        // housekeeping work.
        SessionMutationIntent::AdvanceLogicalTime
        | SessionMutationIntent::CompareAndSet(_)
        | SessionMutationIntent::DeleteFenced(_)
        | SessionMutationIntent::RefreshTtl { .. }
        | SessionMutationIntent::AcquireLease { .. }
        | SessionMutationIntent::RenewLease { .. }
        | SessionMutationIntent::ReleaseLease(_)
        | SessionMutationIntent::BindConsumerRequest { .. }
        | SessionMutationIntent::ReadConsumerRecord { .. }
        | SessionMutationIntent::Authorized { .. }
        | SessionMutationIntent::FencedTransition(_)
        | SessionMutationIntent::ActivateFencedTransition { .. }
        | SessionMutationIntent::FencedTransitionV2(_)
        | SessionMutationIntent::ActivateFencedTransitionV2 { .. }
        | SessionMutationIntent::FencedTransitionV2Batch(_)
        | SessionMutationIntent::RosterAdmission(_)
        | SessionMutationIntent::RosterTerminal(_)
        | SessionMutationIntent::RosterAdmissionV2(_)
        | SessionMutationIntent::RosterTerminalV2(_)
        | SessionMutationIntent::VoidFencedTransitionV2(_)
        | SessionMutationIntent::ActivateVoidFencedTransitionV2 { .. }
        | SessionMutationIntent::ScopeBatch(_)
        | SessionMutationIntent::ScopeBatchCancel(_) => ScopeWorkClass::Normal,
    }
}

pub(super) fn scope_key(scope: &crate::scope_authority::ScopeId) -> ScopeSchedulerKey {
    let mut hash = Sha256::new();
    hash.update(b"openpacketcore/scope-scheduling-key/v1\0");
    hash.update(scope.store().as_bytes());
    for field in [
        scope.tenant().as_str().as_bytes(),
        scope.nf_kind().as_str().as_bytes(),
    ] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field);
    }
    hash.update(scope.slot());
    ScopeSchedulerKey::from_bytes(hash.finalize().into())
}

pub(super) struct StoreWorkAdmission {
    _owner: ScopeSchedulerOwner,
    scheduler: ScopeScheduler,
    #[cfg(test)]
    next_test_key: AtomicU64,
}

pub(super) enum ProposalAdmission {
    Running(ScopeWorkPermit),
    ActivationRead(ScopeWorkReservation),
}

impl StoreWorkAdmission {
    pub(super) fn new() -> Self {
        let owner = ScopeSchedulerOwner::default();
        let scheduler = owner.scheduler();
        Self {
            _owner: owner,
            scheduler,
            #[cfg(test)]
            next_test_key: AtomicU64::new(1),
        }
    }

    pub(super) async fn acquire_for(
        &self,
        key: ScopeSchedulerKey,
        class: ScopeWorkClass,
    ) -> Result<ScopeWorkPermit, ScopeSchedulerError> {
        // This helper creates a fresh local attempt, not an unresolved retry.
        self.scheduler
            .reserve(key, class)
            .await?
            .start()
            .await
            .map_err(|failure| failure.error())
    }

    pub(super) async fn reserve_for(
        &self,
        key: ScopeSchedulerKey,
        class: ScopeWorkClass,
    ) -> Result<ScopeWorkReservation, ScopeSchedulerError> {
        self.scheduler.reserve(key, class).await
    }

    pub(super) fn snapshot(&self) -> ScopeSchedulerSnapshot {
        self.scheduler.snapshot()
    }

    // Preserve existing exact permit-lifetime/cutover tests while changing the
    // production pool. These helpers can hold all five pools; production has
    // no unclassified acquire or multi-pool reservation.
    #[cfg(test)]
    fn test_key(&self) -> ScopeSchedulerKey {
        let mut key = [0xFE; 32];
        key[..8].copy_from_slice(
            &self
                .next_test_key
                .fetch_add(1, Ordering::Relaxed)
                .to_be_bytes(),
        );
        ScopeSchedulerKey::from_bytes(key)
    }

    #[cfg(test)]
    pub(super) async fn acquire_owned(
        self: Arc<Self>,
    ) -> Result<ScopeWorkPermit, ScopeSchedulerError> {
        self.acquire_for(self.test_key(), ScopeWorkClass::Normal)
            .await
    }

    #[cfg(all(test, target_os = "linux"))]
    pub(super) fn available_in_class_for_test(&self, class: ScopeWorkClass) -> usize {
        self.scheduler.available_running(class)
    }

    #[cfg(test)]
    pub(super) fn available_permits(&self) -> usize {
        ScopeWorkClass::ALL
            .into_iter()
            .map(|class| self.scheduler.available_running(class))
            .sum()
    }

    #[cfg(test)]
    pub(super) async fn acquire_many_owned(
        self: Arc<Self>,
        count: u32,
    ) -> Result<Vec<ScopeWorkPermit>, ScopeSchedulerError> {
        let count = count as usize;
        assert!(count <= SCOPE_PROPOSAL_ADMISSION_TOTAL_SLOTS);
        let budgets = ScopeSchedulerBudgets::default();
        let mut permits = Vec::new();
        let mut taken = [0; 5];
        // Take presently free credits first, so holding all other credits does
        // not wait on the one deliberately accepted proposal under test.
        for (index, class) in ScopeWorkClass::ALL.into_iter().enumerate() {
            for _ in 0..self
                .scheduler
                .available_running(class)
                .min(count - permits.len())
            {
                permits.push(self.acquire_for(self.test_key(), class).await?);
                taken[index] += 1;
            }
        }
        // A full-pool join then waits for outstanding supervisors to finish.
        for (index, class) in ScopeWorkClass::ALL.into_iter().enumerate() {
            for _ in taken[index]..budgets.class(class).running {
                if permits.len() == count {
                    return Ok(permits);
                }
                permits.push(self.acquire_for(self.test_key(), class).await?);
            }
        }
        Ok(permits)
    }
}

impl ConsensusSessionStore {
    pub(super) async fn start_proposal_before(
        &self,
        reservation: ScopeWorkReservation,
        deadline: tokio::time::Instant,
    ) -> Result<ScopeWorkPermit, ForwardMutationReply> {
        match tokio::time::timeout_at(deadline, reservation.start()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) | Err(_) => {
                self.inner
                    .diagnostics
                    .proposal_permit_deadline
                    .fetch_add(1, Ordering::Relaxed);
                Err(ForwardMutationReply::Unavailable)
            }
        }
    }

    pub(super) async fn known_binding_before_proposal(
        &self,
        request: &ForwardMutationRequest,
        deadline: tokio::time::Instant,
        allow_operator_recovery: bool,
    ) -> Option<ForwardMutationReply> {
        let SessionMutationIntent::BindConsumerRequest { request_commitment } = &request.intent
        else {
            return None;
        };
        let gate = self.inner.topology_coordinator.operation_gate();
        let _guard = match tokio::time::timeout_at(deadline, gate.read_owned()).await {
            Ok(guard) => guard,
            Err(_) => return Some(ForwardMutationReply::Unavailable),
        };
        let authority = if allow_operator_recovery {
            self.require_durable_fixed_quorum_admission_before(deadline)
                .await
        } else {
            self.require_application_traffic_intermediate_authority_before(deadline)
                .await
        };
        if authority.is_err() {
            return Some(ForwardMutationReply::Unavailable);
        }
        let (authority_identity, _) = match self.current_scope() {
            Ok(scope) => scope,
            Err(_) => return Some(ForwardMutationReply::Unavailable),
        };
        if request
            .required_consumer_scope
            .consumer_scope()
            .is_some_and(|required| *required != authority_identity)
        {
            return Some(ForwardMutationReply::Applied(Box::new(
                SessionConsensusResponse::rejected(StoreError::TopologyAuthorityRevoked),
            )));
        }
        match self
            .inner
            .backend
            .consensus_consumer_request_binding_lookup(
                self.inner.storage_identity,
                authority_identity,
                request.request_id,
                *request_commitment,
            )
            .await
        {
            Ok(crate::sqlite::consensus::ConsumerRequestBindingLookup::Matched(response)) => {
                Some(ForwardMutationReply::Applied(response))
            }
            Ok(crate::sqlite::consensus::ConsumerRequestBindingLookup::Conflict) => {
                Some(ForwardMutationReply::Applied(Box::new(
                    SessionConsensusResponse::rejected(StoreError::CasIdempotencyConflict),
                )))
            }
            Ok(crate::sqlite::consensus::ConsumerRequestBindingLookup::Missing) => None,
            Err(_) => Some(ForwardMutationReply::Unavailable),
        }
    }

    /// Observational proposal counts by class. Accepted proposals retain their
    /// running credits until Openraft resolves, even after caller cancellation.
    pub fn scope_proposal_scheduling_snapshot(&self) -> ScopeSchedulerSnapshot {
        self.inner.proposal_admission.snapshot()
    }

    /// Observational outbound mutation counts by class, independent from local
    /// proposal admission. The transport must also preserve class isolation.
    pub fn scope_forward_scheduling_snapshot(&self) -> ScopeSchedulerSnapshot {
        self.inner.forward_admission.snapshot()
    }

    pub(super) async fn forward_mutation_before(
        &self,
        leader: SessionConsensusNodeId,
        request: &ForwardMutationRequest,
        deadline: tokio::time::Instant,
    ) -> Result<ForwardMutationReply, ConsensusPeerCallFailure> {
        let (key, class) = request
            .scheduling()
            .map_err(|_| ConsensusPeerCallFailure::BeforeTransmission)?;
        let _permit = tokio::time::timeout_at(
            deadline,
            self.inner.forward_admission.acquire_for(key, class),
        )
        .await
        .map_err(|_| ConsensusPeerCallFailure::BeforeTransmission)?
        .map_err(|_| ConsensusPeerCallFailure::BeforeTransmission)?;
        // Admission can wait. Revalidate at the transmission boundary, using
        // the same typed authority route as local submission. A permit is not
        // a saved authorization token.
        let authority = if scope_profile::is_scope_command(&request.intent) {
            self.require_scope_traffic_authority_before(deadline).await
        } else if self.fixed_raw_v2_consumer_warm_route_for_intent(
            &request.intent,
            request.required_consumer_scope.consumer_scope(),
        ) {
            Ok(())
        } else {
            self.require_application_traffic_authority_before(deadline)
                .await
        };
        authority.map_err(|_| ConsensusPeerCallFailure::BeforeTransmission)?;
        if is_roster_mutation_intent(&request.intent) {
            self.call_roster_mutation_peer(leader, request, deadline)
                .await
        } else {
            self.call_peer::<_, ForwardMutationReply>(
                leader,
                SessionConsensusRpcFamily::ForwardMutation,
                &BorrowedForwardRequest::Mutation(request),
                deadline,
            )
            .await
        }
    }

    pub(super) async fn submit_classified_scope_batch(
        &self,
        request_id: SessionConsensusRequestId,
        intent: SessionMutationIntent,
        required_scope: SessionConsensusIdentity,
        class: ScopeWorkClass,
    ) -> Result<SessionConsensusResponse, StoreError> {
        let deadline = tokio::time::Instant::now()
            .checked_add(self.inner.operation_timeout)
            .ok_or_else(consensus_unavailable)?;
        let unavailable = consensus_outcome_unavailable(&intent);
        match self
            .submit_request_effect_classified_before(
                request_id,
                intent,
                Some(required_scope),
                deadline,
                ForwardWorkClass::Declared(class),
            )
            .await
        {
            ConsensusSubmissionEffect::NotTransmitted(error) => Err(error),
            ConsensusSubmissionEffect::OutcomeUnknown => Err(unavailable),
            ConsensusSubmissionEffect::Committed(response) => Ok(response),
            ConsensusSubmissionEffect::Rejected(response) => {
                response.result?;
                Err(unavailable)
            }
        }
    }
}
