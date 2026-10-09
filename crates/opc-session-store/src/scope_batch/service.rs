//! Authenticated durable batch service.

use super::*;
use crate::scope_lease::{ScopeLeaseAction, ScopeLeaseAdmission, ScopeLeaseClock};
use crate::scope_scheduler::ScopeWorkClass;
use crate::{
    ConsensusSessionStore, SessionConsumerIdentity, SessionPersistenceMode,
    DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
};
use std::sync::Arc;

/// Strictly durable child records under an admitted scope grant. Construction
/// binds immutable configuration; each request independently validates current
/// authority, authenticated execution, and exact voter-profile activation.
#[derive(Clone)]
pub struct ScopeBatchStore {
    store: Arc<ConsensusSessionStore>,
    scope: ScopeLeaseId,
    clock: Arc<dyn ScopeLeaseClock>,
    admission: Arc<dyn ScopeLeaseAdmission>,
}
impl fmt::Debug for ScopeBatchStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeBatchStore(<redacted>)")
    }
}

impl ScopeBatchStore {
    /// Bind a configuration-derived stable scope to strictly durable consensus.
    /// The same platform admission policy used for the scope lease also binds
    /// each child mutation to its authenticated execution.
    pub fn new(
        store: Arc<ConsensusSessionStore>,
        scope: ScopeLeaseId,
        clock: Arc<dyn ScopeLeaseClock>,
        admission: Arc<dyn ScopeLeaseAdmission>,
    ) -> Result<Self, ScopeBatchError> {
        if store.persistence_mode() != SessionPersistenceMode::Durable {
            return Err(ScopeLeaseError::DurableConsensusRequired.into());
        }
        if store.scope_lease_cluster_id() != scope.store() {
            return Err(ScopeLeaseError::Unauthorized.into());
        }
        Ok(Self {
            store,
            scope,
            clock,
            admission,
        })
    }

    /// Read the next batch revision and counters without advancing time or
    /// appending a consensus command. Missing state has revision/counters zero.
    pub async fn current(
        &self,
        authenticated: &SessionConsumerIdentity,
    ) -> Result<ScopeBatchView, ScopeBatchError> {
        tokio::time::timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT, async {
            self.admission
                .authorize(authenticated, &self.scope, None, ScopeLeaseAction::Read)
                .await?;
            let state = self.store.scope_batch_checkpoint(&self.scope).await?;
            Ok(ScopeBatchView {
                revision: state.revision,
                counters: state.counters,
            })
        })
        .await
        .map_err(|_| ScopeBatchError::Unavailable)?
    }

    /// Read one live child through a linearizable barrier. Deleted rows read
    /// absent; their retained birth fence remains available to replicated apply.
    pub async fn read(
        &self,
        authenticated: &SessionConsumerIdentity,
        key: ScopeChildKey,
    ) -> Result<Option<ScopeChildRecord>, ScopeBatchError> {
        if key.as_bytes() == &[0; 32] {
            return Err(ScopeBatchError::InvalidRequest);
        }
        tokio::time::timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT, async {
            self.admission
                .authorize(authenticated, &self.scope, None, ScopeLeaseAction::Read)
                .await?;
            self.store.scope_batch_child(&self.scope, key).await
        })
        .await
        .map_err(|_| ScopeBatchError::Unavailable)?
    }

    /// Commit every child, claim and counter change in one application command,
    /// or return a no-effect conflict. Initial profile activation is a separate
    /// cluster prerequisite. On `OutcomeUnknown`, including configuration
    /// cutover, retry these exact bytes before starting the successor request.
    /// `Scope(ProfileNotActivated)` is also retryable, with no effect: the
    /// service attempts current-configuration activation on the exact retry.
    pub async fn execute(
        &self,
        authenticated: &SessionConsumerIdentity,
        request: &ScopeBatchRequest,
    ) -> Result<ScopeBatchOutcome, ScopeBatchError> {
        self.execute_classified(authenticated, request, ScopeWorkClass::Normal)
            .await
    }

    /// Submit an authenticated own-scope worker declaration outside the request
    /// digest. Every emergency-session procedure uses `Emergency`; unknown or
    /// unverified work uses `EmergencyClassification`. The voter cannot inspect
    /// sealed values. SafetyControl is reserved for typed authority operations
    /// and cannot be declared on a child batch. Admission and apply fencing are
    /// identical to [`Self::execute`]. Transport adapters must authenticate the
    /// header/class and provide per-class ingress/proof capacity before reading
    /// the body. Queue congestion is retried through normal backpressure;
    /// network/store deadlines still bound each dispatched attempt.
    pub async fn execute_classified(
        &self,
        authenticated: &SessionConsumerIdentity,
        request: &ScopeBatchRequest,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchOutcome, ScopeBatchError> {
        if class == ScopeWorkClass::SafetyControl {
            return Err(ScopeLeaseError::Unauthorized.into());
        }
        tokio::time::timeout(
            DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
            self.execute_inner(authenticated, request, class),
        )
        .await
        .map_err(|_| ScopeBatchError::OutcomeUnknown)?
    }

    async fn authorize(
        &self,
        authenticated: &SessionConsumerIdentity,
        request: &ScopeBatchRequest,
    ) -> Result<(), ScopeBatchError> {
        request.validate()?;
        if request.scope() != &self.scope || request.permit.execution().identity() != authenticated
        {
            return Err(ScopeLeaseError::Unauthorized.into());
        }
        self.admission
            .authorize(
                authenticated,
                &self.scope,
                Some(request.permit.execution()),
                ScopeLeaseAction::Mutate,
            )
            .await
            .map_err(Into::into)
    }

    async fn execute_inner(
        &self,
        authenticated: &SessionConsumerIdentity,
        request: &ScopeBatchRequest,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchOutcome, ScopeBatchError> {
        self.authorize(authenticated, request).await?;
        let current = self.store.scope_batch_checkpoint(&self.scope).await?;
        if current.replay(request)? {
            return current
                .outcome(request.lane())
                .cloned()
                .ok_or(ScopeBatchError::FormatMismatch);
        }
        self.authorize(authenticated, request).await?;
        let command = ScopeBatchCommand {
            request: request.clone(),
            bounds: self.clock.bounds()?,
        };
        match self.store.commit_scope_batch(command, class).await {
            Ok(outcome) => Ok(outcome),
            Err(
                ScopeBatchError::OutcomeUnknown
                | ScopeBatchError::Unavailable
                | ScopeBatchError::Scope(
                    ScopeLeaseError::Unavailable | ScopeLeaseError::OutcomeUnknown,
                ),
            ) => {
                if let Ok(current) = self.store.scope_batch_checkpoint(&self.scope).await {
                    if current.replay(request) == Ok(true) {
                        return current
                            .outcome(request.lane())
                            .cloned()
                            .ok_or(ScopeBatchError::FormatMismatch);
                    }
                }
                Err(ScopeBatchError::OutcomeUnknown)
            }
            Err(error) => Err(error),
        }
    }
}
