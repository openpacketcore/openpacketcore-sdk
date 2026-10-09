//! Quorum-side authenticated admission and exact, untimed authority commits.

use super::*;
use crate::{
    ConsensusSessionStore, SessionPersistenceMode, DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
};
use async_trait::async_trait;
use std::sync::Arc;

/// Role established by the trusted transport policy, never by request claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeAuthorityRole {
    /// One authenticated process with proof of its exact boot key.
    Worker,
    /// Scope-authorized observations, without mutation or effect authority.
    Observer,
    /// Scope succession authority; does not inherit worker or voter rights.
    ScopeController,
}

/// Independent policy decisions at the authority and batch service boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeAuthorityAction {
    /// Independently verify a boot before first admission.
    AdmitInitial,
    /// Independently verify a successor boot and its monotonic generation.
    SucceedClosed,
    /// Verify the current process is closing its mutation and control paths.
    Close,
    /// Bind a child mutation to the exact authenticated boot.
    Mutate,
    /// Scope-authorized observation, never an effect capability.
    Read,
    /// Recover an exact committed request using retained boot verification.
    Recover,
}

/// Trusted admission and closure-verification boundary installed by the host.
///
/// Authenticate the channel independently of all serialized claims. Worker
/// decisions must verify possession of the exact process key, scope and boot
/// tuple; shared credentials are insufficient. New admissions independently
/// verify the generation and boot against the authoritative issuer. Read,
/// Mutate and Recover use retained boot verification: credential expiry never
/// expires an already admitted execution. No allow-all policy is supplied.
#[async_trait]
pub trait ScopeAuthorityAdmission: Send + Sync {
    /// Authorize a scope, execution and action. `request_digest` binds authority
    /// admission to the immutable request; voter configuration is excluded.
    async fn authorize(
        &self,
        authenticated: &SessionConsumerIdentity,
        scope: &ScopeId,
        execution: Option<&ScopeExecution>,
        action: ScopeAuthorityAction,
        request_digest: Option<[u8; 32]>,
    ) -> Result<ScopeAuthorityRole, ScopeAuthorityError>;

    /// Independently verify closure of this exact predecessor and evidence.
    /// Closure means it can no longer submit store mutations or peer-control
    /// effects. Installed forwarding is excluded. LocalQuiescence is valid
    /// only for the current worker's Close; FinalTermination requires trusted
    /// final termination evidence, never absence, elapsed time or client claims.
    /// The service creates an opaque token only after this hook succeeds and
    /// binds its evidence digest to the request before proposing a command.
    async fn verify_closure(
        &self,
        _authenticated: &SessionConsumerIdentity,
        _predecessor: &ScopeAuthorityStamp,
        _evidence: &ScopeClosureEvidence,
        _request_digest: [u8; 32],
    ) -> Result<(), ScopeAuthorityError> {
        Err(ScopeAuthorityError::ClosureRequired)
    }
}

#[async_trait]
pub(crate) trait ScopeAuthorityBackend: Send + Sync {
    async fn current(&self, scope: &ScopeId) -> Result<ScopeState, ScopeAuthorityError>;
    async fn commit(
        &self,
        command: ScopeAuthorityCommand,
    ) -> Result<ScopeState, ScopeAuthorityError>;
}

/// Strictly durable, untimed authority over one stable scope.
#[derive(Clone)]
pub struct ScopeAuthorityStore {
    pub(super) backend: Arc<dyn ScopeAuthorityBackend>,
    pub(super) scope: ScopeId,
    pub(super) admission: Arc<dyn ScopeAuthorityAdmission>,
}
impl fmt::Debug for ScopeAuthorityStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeAuthorityStore(<redacted>)")
    }
}
impl ScopeAuthorityStore {
    /// Bind immutable installation identity and trusted admission to durable
    /// consensus. Live readiness is checked on each operation, not construction.
    pub fn new(
        store: Arc<ConsensusSessionStore>,
        scope: ScopeId,
        admission: Arc<dyn ScopeAuthorityAdmission>,
    ) -> Result<Self, ScopeAuthorityError> {
        if store.persistence_mode() != SessionPersistenceMode::Durable {
            return Err(ScopeAuthorityError::DurableConsensusRequired);
        }
        if store.scope_authority_cluster_id() != scope.store {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        Ok(Self {
            backend: store,
            scope,
            admission,
        })
    }

    /// Authenticate the admitted boot and return opaque committed authority.
    /// A controller submits succession with `execute`; the successor retrieves
    /// its capability by retrying those exact bytes through this method. Only
    /// a still-current Active result can issue the capability.
    pub async fn admit(
        &self,
        authenticated: &SessionConsumerIdentity,
        request: &ScopeAuthorityRequest,
    ) -> Result<CommittedScopeAuthority, ScopeAuthorityError> {
        if !matches!(
            request.operation,
            ScopeAuthorityOperation::AdmitInitial { .. }
                | ScopeAuthorityOperation::SucceedClosed { .. }
        ) {
            return Err(ScopeAuthorityError::InvalidRequest);
        }
        tokio::time::timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT, async {
            request.validate()?;
            if request.scope != self.scope
                || authenticated != request.operation.execution().identity()
            {
                return Err(ScopeAuthorityError::Unauthorized);
            }
            let role = self
                .admission
                .authorize(
                    authenticated,
                    &self.scope,
                    None,
                    ScopeAuthorityAction::Read,
                    None,
                )
                .await?;
            if role != ScopeAuthorityRole::Worker {
                return Err(ScopeAuthorityError::Unauthorized);
            }
            let result = self.execute_inner(authenticated, request).await?;
            let stamp = result.stamp.ok_or(ScopeAuthorityError::Unavailable)?;
            let current = self.backend.current(&self.scope).await?;
            current.check_stamp(&stamp)?;
            let closed_predecessor = match &request.operation {
                ScopeAuthorityOperation::SucceedClosed { predecessor, .. } => {
                    Some(predecessor.clone())
                }
                _ => None,
            };
            Ok(CommittedScopeAuthority {
                stamp,
                closed_predecessor,
            })
        })
        .await
        .map_err(|_| ScopeAuthorityError::OutcomeUnknown)?
    }

    /// Observe current authority through a full-round linearizable read.
    /// This neither advances a clock nor issues an effect capability.
    pub async fn current(
        &self,
        authenticated: &SessionConsumerIdentity,
    ) -> Result<ScopeAuthorityView, ScopeAuthorityError> {
        tokio::time::timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT, async {
            self.admission
                .authorize(
                    authenticated,
                    &self.scope,
                    None,
                    ScopeAuthorityAction::Read,
                    None,
                )
                .await?;
            Ok(self.backend.current(&self.scope).await?.view)
        })
        .await
        .map_err(|_| ScopeAuthorityError::Unavailable)?
    }

    /// Commit or recover one exact request. Refusals change no authority row
    /// field. Configuration cutover and lost replies can be OutcomeUnknown;
    /// retry identical bytes. The configuration stamp is transport metadata.
    pub async fn execute(
        &self,
        authenticated: &SessionConsumerIdentity,
        request: &ScopeAuthorityRequest,
    ) -> Result<ScopeAuthorityView, ScopeAuthorityError> {
        tokio::time::timeout(
            DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
            self.execute_inner(authenticated, request),
        )
        .await
        .map_err(|_| ScopeAuthorityError::OutcomeUnknown)?
    }

    async fn authorize_request(
        &self,
        authenticated: &SessionConsumerIdentity,
        request: &ScopeAuthorityRequest,
        replay: bool,
    ) -> Result<(), ScopeAuthorityError> {
        let action = if replay {
            ScopeAuthorityAction::Recover
        } else {
            match request.operation {
                ScopeAuthorityOperation::AdmitInitial { .. } => ScopeAuthorityAction::AdmitInitial,
                ScopeAuthorityOperation::SucceedClosed { .. } => {
                    ScopeAuthorityAction::SucceedClosed
                }
                ScopeAuthorityOperation::Close { .. } => ScopeAuthorityAction::Close,
            }
        };
        let role = self
            .admission
            .authorize(
                authenticated,
                &self.scope,
                Some(request.operation.execution()),
                action,
                Some(request.digest()?),
            )
            .await?;
        let allowed = match role {
            ScopeAuthorityRole::Worker => authenticated == request.operation.execution().identity(),
            ScopeAuthorityRole::ScopeController => matches!(
                request.operation,
                ScopeAuthorityOperation::SucceedClosed { .. }
            ),
            ScopeAuthorityRole::Observer => false,
        };
        allowed
            .then_some(())
            .ok_or(ScopeAuthorityError::Unauthorized)
    }

    async fn execute_inner(
        &self,
        authenticated: &SessionConsumerIdentity,
        request: &ScopeAuthorityRequest,
    ) -> Result<ScopeAuthorityView, ScopeAuthorityError> {
        request.validate()?;
        if request.scope != self.scope {
            return Err(ScopeAuthorityError::Unauthorized);
        }
        self.admission
            .authorize(
                authenticated,
                &self.scope,
                None,
                ScopeAuthorityAction::Read,
                None,
            )
            .await?;
        let current = self.backend.current(&self.scope).await?;
        let replay = current.replay(request)?;
        self.authorize_request(authenticated, request, replay)
            .await?;
        if replay {
            return Ok(current.view);
        }
        current.transition(request)?;
        let proof = if let Some((predecessor, evidence)) = request.operation.closure() {
            if evidence.kind == ScopeClosureKind::CommittedClose {
                // transition already checked the exact closed predecessor and
                // the committed Close digest against the durable checkpoint.
                if current.view.closed_evidence().as_ref() != Some(evidence) {
                    return Err(ScopeAuthorityError::ClosureRequired);
                }
            } else {
                self.admission
                    .verify_closure(authenticated, predecessor, evidence, request.digest()?)
                    .await?;
            }
            Some(VerifiedScopeClosure {
                predecessor: predecessor.clone(),
                evidence: evidence.clone(),
            })
        } else {
            None
        };
        self.authorize_request(authenticated, request, false)
            .await?;
        let command = ScopeAuthorityCommand::verified(request.clone(), proof)?;
        match self.backend.commit(command).await {
            Ok(state) => Ok(state.view),
            Err(ScopeAuthorityError::OutcomeUnknown | ScopeAuthorityError::Unavailable) => {
                if let Ok(state) = self.backend.current(&self.scope).await {
                    if state.replay(request) == Ok(true) {
                        self.authorize_request(authenticated, request, true).await?;
                        return Ok(state.view);
                    }
                }
                Err(ScopeAuthorityError::OutcomeUnknown)
            }
            Err(error) => Err(error),
        }
    }
}

pub(crate) fn is_scope_authority_key(key: &SessionKey) -> bool {
    matches!(&key.key_type, SessionKeyType::Other(name) if name.as_str() == RECORD_TYPE)
}
