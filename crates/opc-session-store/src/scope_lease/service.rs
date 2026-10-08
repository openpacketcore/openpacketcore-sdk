//! Quorum-side admission and single-command scope commits.

use super::*;
use crate::{
    ConsensusSessionStore, SessionPersistenceMode, DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
};
use async_trait::async_trait;
use std::sync::Arc;

/// Separate admission decisions for controllers, execution mutations and reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeLeaseAction {
    /// Validate a successor's platform identity, incarnation and monotonic
    /// admission generation before staging it.
    Select,
    /// Acquire, renew, resume or release the authenticated execution itself.
    Mutate,
    /// Inspect current authority; a read by itself does not issue a new grant.
    Read,
}

/// Trusted platform admission boundary installed by the quorum composition.
///
/// The transport authenticates `authenticated` independently of the request.
/// For Select, implementations must independently verify the proposed
/// admission generation and every execution field against the platform's
/// current selection for this stable slot. An authorized controller or the
/// selected candidate may present that proof; merely possessing a shared
/// workload identity is insufficient. For Mutate, the policy must bind the
/// authenticated connection to the exact admitted execution, using retained
/// trusted admission evidence when credentials are shared across executions.
/// The service additionally checks the identity and exact execution against
/// the committed selection/permit. Renewal and resume need no fresh platform
/// API lookup, but copied permit claims or a shared identity alone must never
/// satisfy this binding. A transport may install a connection-bound policy;
/// no allow-all production policy is supplied. Platform protocol and
/// credentials stay outside replicated apply.
#[async_trait]
pub trait ScopeLeaseAdmission: Send + Sync {
    /// Validate the exact scope, role and optional execution against current
    /// trusted admission facts. May be called again before committing.
    async fn authorize(
        &self,
        authenticated: &SessionConsumerIdentity,
        scope: &ScopeLeaseId,
        execution: Option<&ScopeExecution>,
        action: ScopeLeaseAction,
    ) -> Result<(), ScopeLeaseError>;
}

#[async_trait]
pub(crate) trait ScopeLeaseBackend: Send + Sync {
    async fn current(&self, scope: &ScopeLeaseId) -> Result<ScopeState, ScopeLeaseError>;
    async fn commit(&self, command: ScopeLeaseCommand) -> Result<ScopeState, ScopeLeaseError>;
}

/// Strict quorum-side authority over one bounded native scope checkpoint.
///
/// The constructor requires durable consensus. The checkpoint contains public
/// authority claims, never credentials or child payloads. Retain each request
/// until its outcome is known; after uncertainty retry that exact request.
#[derive(Clone)]
pub struct ScopeLeaseStore {
    pub(super) backend: Arc<dyn ScopeLeaseBackend>,
    pub(super) scope: ScopeLeaseId,
    pub(super) clock: Arc<dyn ScopeLeaseClock>,
    pub(super) admission: Arc<dyn ScopeLeaseAdmission>,
}

impl fmt::Debug for ScopeLeaseStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeLeaseStore(<redacted>)")
    }
}

impl ScopeLeaseStore {
    /// Bind one stable cluster scope to durable consensus, authenticated
    /// admission and bounded time. Existing services survive reconfiguration;
    /// each request is admitted under the store's current configuration.
    /// Construction checks immutable configuration, not live readiness or
    /// authority. It does not wait for a reader or grant a permit. Reads and
    /// mutations independently validate admission within their deadlines.
    pub fn new(
        store: Arc<ConsensusSessionStore>,
        scope: ScopeLeaseId,
        clock: Arc<dyn ScopeLeaseClock>,
        admission: Arc<dyn ScopeLeaseAdmission>,
    ) -> Result<Self, ScopeLeaseError> {
        if store.persistence_mode() != SessionPersistenceMode::Durable {
            return Err(ScopeLeaseError::DurableConsensusRequired);
        }
        if store.scope_lease_cluster_id() != scope.store {
            return Err(ScopeLeaseError::Unauthorized);
        }
        Ok(Self {
            backend: store,
            scope,
            clock,
            admission,
        })
    }

    /// Execute Acquire, Renew or Resume and return opaque committed evidence
    /// for a gate adapter. Read, selection and release cannot mint this token.
    /// An exact replay keeps the original absolute deadlines and revision.
    pub async fn grant(
        &self,
        authenticated: &SessionConsumerIdentity,
        request: &ScopeLeaseRequest,
    ) -> Result<CommittedScopePermit, ScopeLeaseError> {
        if !matches!(
            &request.operation,
            ScopeLeaseOperation::Acquire { .. }
                | ScopeLeaseOperation::Renew { .. }
                | ScopeLeaseOperation::ResumeSameExecution { .. }
        ) {
            return Err(ScopeLeaseError::InvalidRequest);
        }
        let result = self.execute(authenticated, request).await?;
        let permit = result.permit.ok_or(ScopeLeaseError::Unavailable)?;
        Ok(CommittedScopePermit {
            permit,
            revision: result.revision,
        })
    }

    /// Read current scope state through the existing linearizable boundary.
    /// An absent scope has revision and selection zero. This never renews time.
    pub async fn current(
        &self,
        authenticated: &SessionConsumerIdentity,
    ) -> Result<ScopeLeaseView, ScopeLeaseError> {
        tokio::time::timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT, async {
            self.admission
                .authorize(authenticated, &self.scope, None, ScopeLeaseAction::Read)
                .await?;
            Ok(self.backend.current(&self.scope).await?.view)
        })
        .await
        .map_err(|_| ScopeLeaseError::Unavailable)?
    }

    /// Apply one exact request, or replay its retained immutable outcome.
    /// A configuration switch can return `OutcomeUnknown`; retry the exact request.
    /// `ProfileNotActivated` has no effect and is retryable; the service attempts
    /// activation under the current configuration when the exact request is retried.
    ///
    /// A successful return follows one durable consensus command. If another operation
    /// has superseded the retained result, the old expected revision conflicts;
    /// retry never reissues a permit. Resume requires the same retained process
    /// state; restarting with a new nonce requires selection and acquisition.
    pub async fn execute(
        &self,
        authenticated: &SessionConsumerIdentity,
        request: &ScopeLeaseRequest,
    ) -> Result<ScopeLeaseView, ScopeLeaseError> {
        tokio::time::timeout(
            DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
            self.execute_inner(authenticated, request),
        )
        .await
        .map_err(|_| ScopeLeaseError::OutcomeUnknown)?
    }

    async fn authorize(
        &self,
        authenticated: &SessionConsumerIdentity,
        request: &ScopeLeaseRequest,
    ) -> Result<(), ScopeLeaseError> {
        request.validate()?;
        if request.scope != self.scope {
            return Err(ScopeLeaseError::Unauthorized);
        }
        let action = if matches!(&request.operation, ScopeLeaseOperation::Select { .. }) {
            ScopeLeaseAction::Select
        } else {
            if authenticated != request.operation.execution().identity() {
                return Err(ScopeLeaseError::Unauthorized);
            }
            ScopeLeaseAction::Mutate
        };
        self.admission
            .authorize(
                authenticated,
                &self.scope,
                Some(request.operation.execution()),
                action,
            )
            .await
    }

    async fn execute_inner(
        &self,
        authenticated: &SessionConsumerIdentity,
        request: &ScopeLeaseRequest,
    ) -> Result<ScopeLeaseView, ScopeLeaseError> {
        self.authorize(authenticated, request).await?;
        let current = self.backend.current(&self.scope).await?;
        if current.replay(request)? {
            return Ok(current.view);
        }
        self.authorize(authenticated, request).await?;
        let command = ScopeLeaseCommand {
            request: request.clone(),
            bounds: self.clock.bounds()?,
        };
        current.transition(request, command.bounds)?;
        match self.backend.commit(command).await {
            Ok(state) => Ok(state.view),
            Err(ScopeLeaseError::OutcomeUnknown | ScopeLeaseError::Unavailable) => {
                if let Ok(state) = self.backend.current(&self.scope).await {
                    if state.replay(request) == Ok(true) {
                        return Ok(state.view);
                    }
                }
                Err(ScopeLeaseError::OutcomeUnknown)
            }
            Err(error) => Err(error),
        }
    }
}

pub(crate) fn is_scope_lease_key(key: &SessionKey) -> bool {
    matches!(&key.key_type, SessionKeyType::Other(name) if name.as_str() == RECORD_TYPE)
}
