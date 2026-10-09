//! Current-epoch admission around stable-cluster scope checkpoints.

use super::*;
use crate::scope_authority::service::ScopeAuthorityBackend;
use crate::scope_authority::{ScopeAuthorityCommand, ScopeAuthorityError, ScopeId, ScopeState};

fn unavailable(_: impl std::fmt::Debug) -> ScopeAuthorityError {
    ScopeAuthorityError::Unavailable
}

impl ConsensusSessionStore {
    /// Immutable handle binding only; live authority is checked by each
    /// operation below, with its original asynchronous deadline.
    pub(crate) fn scope_authority_cluster_id(&self) -> crate::SessionConsensusClusterId {
        self.inner.storage_identity.cluster_id()
    }
}

#[async_trait]
impl ScopeAuthorityBackend for ConsensusSessionStore {
    async fn current(&self, scope: &ScopeId) -> Result<ScopeState, ScopeAuthorityError> {
        // The synchronous consumer_scope accessor deliberately refuses a
        // busy native owner. Resolve the identity here, then let asynchronous
        // admission wait for and validate its durable authority below.
        let (identity, _) = self.current_scope().map_err(unavailable)?;
        let current = SessionConsumerScope::new(identity);
        if current.consensus_identity().cluster_id() != scope.store() {
            return Err(ScopeAuthorityError::Unauthorized);
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
            .consensus_scope_authority_checkpoint(self.inner.storage_identity, scope.clone())
            .await
            .map_err(unavailable)?;
        self.require_scope_read_authority_before(current, deadline)
            .await
            .map_err(unavailable)?;
        if legacy {
            return Err(ScopeAuthorityError::FormatMismatch);
        }
        crate::scope_authority::checkpoint_state(scope, checkpoint)
    }

    async fn commit(
        &self,
        operation: ScopeAuthorityCommand,
    ) -> Result<ScopeState, ScopeAuthorityError> {
        let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
        self.ensure_scope_profile_before(deadline)
            .await
            .map_err(|error| match error {
                StoreError::CapabilityNotSupported(_) => ScopeAuthorityError::ProfileNotActivated,
                _ => ScopeAuthorityError::Unavailable,
            })?;
        let (current, _) = self.current_scope().map_err(unavailable)?;
        if current.cluster_id() != operation.request.scope().store() {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        let response = self
            .submit_request_with_consumer_scope(
                SessionConsensusRequestId::from_bytes(*operation.request.request_id()),
                SessionMutationIntent::ScopeAuthority(Box::new(operation)),
                Some(current),
            )
            .await
            .map_err(|_| ScopeAuthorityError::OutcomeUnknown)?;
        match response.result {
            Ok(SessionMutationOutcome::ScopeAuthority(Ok(checkpoint))) => checkpoint.state(),
            Ok(SessionMutationOutcome::ScopeAuthority(Err(error))) => Err(error),
            _ => Err(ScopeAuthorityError::OutcomeUnknown),
        }
    }
}
