//! Current-epoch admission around stable-cluster scope checkpoints.

use super::*;
use crate::scope_lease::service::ScopeLeaseBackend;
use crate::scope_lease::{ScopeLeaseCommand, ScopeLeaseError, ScopeLeaseId, ScopeState};

fn unavailable(_: impl std::fmt::Debug) -> ScopeLeaseError {
    ScopeLeaseError::Unavailable
}

impl ConsensusSessionStore {
    /// Immutable handle binding only; live authority is checked by each
    /// operation below, with its original asynchronous deadline.
    pub(crate) fn scope_lease_cluster_id(&self) -> crate::SessionConsensusClusterId {
        self.inner.storage_identity.cluster_id()
    }
}

#[async_trait]
impl ScopeLeaseBackend for ConsensusSessionStore {
    async fn current(&self, scope: &ScopeLeaseId) -> Result<ScopeState, ScopeLeaseError> {
        // The synchronous consumer_scope accessor deliberately refuses a
        // busy native owner. Resolve the identity here, then let asynchronous
        // admission wait for and validate its durable authority below.
        let (identity, _) = self.current_scope().map_err(unavailable)?;
        let current = SessionConsumerScope::new(identity);
        if current.consensus_identity().cluster_id() != scope.store() {
            return Err(ScopeLeaseError::Unauthorized);
        }
        let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
        let admission = self
            .admit_scope_read_before(current, deadline)
            .await
            .map_err(unavailable)?;
        drop(admission);
        // Authority has no record TTL: a ReadIndex barrier suffices. Never
        // propose AdvanceLogicalTime for a scope read or replay.
        self.scope_read_barrier_before(deadline)
            .await
            .map_err(unavailable)?;
        let _admission = self
            .admit_scope_read_before(current, deadline)
            .await
            .map_err(unavailable)?;
        let (legacy, checkpoint) = self
            .inner
            .backend
            .consensus_scope_lease_checkpoint(self.inner.storage_identity, scope.clone())
            .await
            .map_err(unavailable)?;
        self.require_scope_read_authority_before(current, deadline)
            .await
            .map_err(unavailable)?;
        if legacy {
            return Err(ScopeLeaseError::FormatMismatch);
        }
        crate::scope_lease::checkpoint_state(scope, checkpoint)
    }

    async fn commit(&self, operation: ScopeLeaseCommand) -> Result<ScopeState, ScopeLeaseError> {
        let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
        self.ensure_scope_profile_before(deadline)
            .await
            .map_err(|error| match error {
                StoreError::CapabilityNotSupported(_) => ScopeLeaseError::ProfileNotActivated,
                _ => ScopeLeaseError::Unavailable,
            })?;
        let (current, _) = self.current_scope().map_err(unavailable)?;
        if current.cluster_id() != operation.request.scope().store() {
            return Err(ScopeLeaseError::Unauthorized);
        }
        let response = self
            .submit_request_with_consumer_scope(
                SessionConsensusRequestId::from_bytes(*operation.request.request_id()),
                SessionMutationIntent::ScopeLease(Box::new(operation)),
                Some(current),
            )
            .await
            .map_err(|_| ScopeLeaseError::OutcomeUnknown)?;
        match response.result {
            Ok(SessionMutationOutcome::ScopeLease(Ok(checkpoint))) => checkpoint.state(),
            Ok(SessionMutationOutcome::ScopeLease(Err(error))) => Err(error),
            _ => Err(ScopeLeaseError::OutcomeUnknown),
        }
    }
}
