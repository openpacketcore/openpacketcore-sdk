//! Current-configuration point reads and one-command atomic batch submissions.

use super::*;
use crate::scope_batch::{
    ScopeBatchCheckpoint, ScopeBatchCommand, ScopeBatchError, ScopeBatchOutcome, ScopeChildKey,
    ScopeChildRecord,
};
use crate::scope_lease::{ScopeLeaseError, ScopeLeaseId};
use crate::scope_storage::{self, ScopeRow};

fn unavailable(_: impl fmt::Debug) -> ScopeBatchError {
    ScopeBatchError::Unavailable
}

impl ConsensusSessionStore {
    async fn scope_row(
        &self,
        scope: &ScopeLeaseId,
        key: SessionKey,
    ) -> Result<Option<ScopeRow>, ScopeBatchError> {
        let (identity, _) = self.current_scope().map_err(unavailable)?;
        if identity.cluster_id() != scope.store() {
            return Err(ScopeLeaseError::Unauthorized.into());
        }
        let current = SessionConsumerScope::new(identity);
        let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
        drop(
            self.admit_scope_read_before(current, deadline)
                .await
                .map_err(unavailable)?,
        );
        self.scope_read_barrier_before(deadline)
            .await
            .map_err(unavailable)?;
        let _admission = self
            .admit_scope_read_before(current, deadline)
            .await
            .map_err(unavailable)?;
        let row = self
            .inner
            .backend
            .consensus_scope_record(self.inner.storage_identity, key)
            .await
            .map_err(unavailable)?;
        self.require_scope_read_authority_before(current, deadline)
            .await
            .map_err(unavailable)?;
        if row.as_ref().is_some_and(|row| row.scope() != Some(scope)) {
            return Err(ScopeBatchError::FormatMismatch);
        }
        Ok(row)
    }

    pub(crate) async fn scope_batch_checkpoint(
        &self,
        scope: &ScopeLeaseId,
    ) -> Result<ScopeBatchCheckpoint, ScopeBatchError> {
        match self
            .scope_row(scope, scope_storage::batch_key(scope)?)
            .await?
        {
            Some(ScopeRow::Batch(row)) => Ok(*row),
            None => Ok(ScopeBatchCheckpoint::empty(scope.clone())),
            _ => Err(ScopeBatchError::FormatMismatch),
        }
    }

    pub(crate) async fn scope_batch_child(
        &self,
        scope: &ScopeLeaseId,
        key: ScopeChildKey,
    ) -> Result<Option<ScopeChildRecord>, ScopeBatchError> {
        match self
            .scope_row(scope, scope_storage::child_key(scope, key)?)
            .await?
        {
            Some(ScopeRow::Child(row)) => Ok(row.value.is_some().then_some(row)),
            None => Ok(None),
            _ => Err(ScopeBatchError::FormatMismatch),
        }
    }

    pub(crate) async fn commit_scope_batch(
        &self,
        operation: ScopeBatchCommand,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchOutcome, ScopeBatchError> {
        let deadline = tokio::time::Instant::now() + self.inner.operation_timeout;
        self.ensure_scope_profile_before(deadline)
            .await
            .map_err(|error| match error {
                StoreError::CapabilityNotSupported(_) => {
                    ScopeBatchError::Scope(ScopeLeaseError::ProfileNotActivated)
                }
                _ => ScopeBatchError::Unavailable,
            })?;
        let (current, _) = self.current_scope().map_err(unavailable)?;
        if current.cluster_id() != operation.request.scope().store() {
            return Err(ScopeLeaseError::Unauthorized.into());
        }
        let response = self
            .submit_classified_scope_batch(
                SessionConsensusRequestId::from_bytes(*operation.request.request_id()),
                SessionMutationIntent::ScopeBatch(Box::new(operation)),
                current,
                class,
            )
            .await
            .map_err(|_| ScopeBatchError::OutcomeUnknown)?;
        match response.result {
            Ok(SessionMutationOutcome::ScopeBatch(result)) => result,
            _ => Err(ScopeBatchError::OutcomeUnknown),
        }
    }
}
