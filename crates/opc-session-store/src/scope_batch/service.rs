//! Authenticated durable batch service.

use super::*;
use crate::scope_authority::{ScopeAuthorityAction, ScopeAuthorityAdmission, ScopeAuthorityRole};
use crate::scope_scheduler::ScopeWorkClass;
use crate::{
    ConsensusSessionStore, SessionConsumerIdentity, SessionPersistenceMode,
    DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
};
use std::sync::Arc;

pub(crate) fn require_data_lane_class(
    lane: u8,
    class: ScopeWorkClass,
) -> Result<(), ScopeBatchError> {
    if class == ScopeWorkClass::SafetyControl || (lane == 7 && class != ScopeWorkClass::Emergency) {
        return Err(ScopeAuthorityError::Unauthorized.into());
    }
    Ok(())
}

/// Strictly durable child records under an admitted scope incarnation. Construction
/// binds immutable configuration; each request independently validates current
/// authority, authenticated execution, and exact voter-profile activation.
#[derive(Clone)]
pub struct ScopeBatchStore {
    store: Arc<ConsensusSessionStore>,
    namespace: ScopeNamespace,
    admission: Arc<dyn ScopeAuthorityAdmission>,
}
impl fmt::Debug for ScopeBatchStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeBatchStore(<redacted>)")
    }
}

impl ScopeBatchStore {
    /// Exact namespace bound to this authenticated service handle.
    pub const fn namespace(&self) -> &ScopeNamespace {
        &self.namespace
    }

    pub(super) async fn resolution_cut(
        &self,
        authenticated: &SessionConsumerIdentity,
    ) -> Result<ScopeBatchReadCut, ScopeBatchError> {
        tokio::time::timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT, async {
            self.authorize_read(authenticated).await?;
            self.store.scope_batch_cut(self.namespace.scope()).await
        })
        .await
        .map_err(|_| ScopeBatchError::Unavailable)?
    }

    /// Bind a configuration-derived stable scope to strictly durable consensus.
    /// The same platform admission policy used for the scope authority also binds
    /// each child mutation to its authenticated execution.
    pub fn new(
        store: Arc<ConsensusSessionStore>,
        namespace: ScopeNamespace,
        admission: Arc<dyn ScopeAuthorityAdmission>,
    ) -> Result<Self, ScopeBatchError> {
        if store.persistence_mode() != SessionPersistenceMode::Durable {
            return Err(ScopeAuthorityError::DurableConsensusRequired.into());
        }
        if store.scope_authority_cluster_id() != namespace.scope().store() {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        Ok(Self {
            store,
            namespace,
            admission,
        })
    }

    /// Read the next batch revision and counters without appending a command.
    /// AdmitInitial creates a zero-valued checkpoint; a missing ledger is a
    /// format fault, never evidence that retained floors may restart at zero.
    pub async fn current(
        &self,
        authenticated: &SessionConsumerIdentity,
    ) -> Result<ScopeBatchView, ScopeBatchError> {
        tokio::time::timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT, async {
            self.admission
                .authorize(
                    authenticated,
                    self.namespace.scope(),
                    None,
                    ScopeAuthorityAction::Read,
                    None,
                )
                .await?;
            let state = self
                .store
                .scope_batch_checkpoint(self.namespace.scope())
                .await?;
            Ok(ScopeBatchView {
                revision: state.revision,
                counters: state.counters,
            })
        })
        .await
        .map_err(|_| ScopeBatchError::Unavailable)?
    }

    /// Read exact historical status from one authority/ledger cut after a full
    /// current-configuration barrier. Absence while eligible is NotRecorded.
    pub async fn lookup(
        &self,
        authenticated: &SessionConsumerIdentity,
        attempt: &ScopeBatchAttempt,
    ) -> Result<ScopeBatchLookup, ScopeBatchError> {
        attempt.validate()?;
        if attempt.stamp().scope() != self.namespace.scope() {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        tokio::time::timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT, async {
            self.authorize_read(authenticated).await?;
            self.store
                .scope_batch_cut(self.namespace.scope())
                .await?
                .lookup(attempt)
        })
        .await
        .map_err(|_| ScopeBatchError::Unavailable)?
    }

    /// Reconstruct volatile lane coordination from one committed observation.
    /// Returned authority claims and receipts never issue an effect capability.
    pub async fn reopen(
        &self,
        authenticated: &SessionConsumerIdentity,
    ) -> Result<ScopeBatchReopen, ScopeBatchError> {
        Ok(self.resolution_cut(authenticated).await?.reopen())
    }

    async fn authorize_read(
        &self,
        authenticated: &SessionConsumerIdentity,
    ) -> Result<(), ScopeBatchError> {
        self.admission
            .authorize(
                authenticated,
                self.namespace.scope(),
                None,
                ScopeAuthorityAction::Read,
                None,
            )
            .await?;
        Ok(())
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
                .authorize(
                    authenticated,
                    self.namespace.scope(),
                    None,
                    ScopeAuthorityAction::Read,
                    None,
                )
                .await?;
            self.store.scope_batch_child(&self.namespace, key).await
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
        require_data_lane_class(request.lane(), class)?;
        tokio::time::timeout(
            DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT,
            self.execute_inner(authenticated, request, class),
        )
        .await
        .map_err(|_| ScopeBatchError::OutcomeUnknown)?
    }

    /// Race cancellation against apply for this exact immutable attempt. A
    /// retained apply winner is returned unchanged; cancellation never erases it.
    pub async fn cancel(
        &self,
        authenticated: &SessionConsumerIdentity,
        attempt: &ScopeBatchAttempt,
    ) -> Result<ScopeBatchReceipt, ScopeBatchError> {
        self.cancel_classified(authenticated, attempt, ScopeWorkClass::Normal)
            .await
    }

    /// Cancel under the trusted own-scope data classification. SafetyControl
    /// remains independent of data lanes and cannot be declared by this API.
    pub async fn cancel_classified(
        &self,
        authenticated: &SessionConsumerIdentity,
        attempt: &ScopeBatchAttempt,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchReceipt, ScopeBatchError> {
        require_data_lane_class(attempt.lane(), class)?;
        tokio::time::timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT, async {
            attempt.validate()?;
            if attempt.stamp().namespace() != &self.namespace
                || attempt.stamp().execution().identity() != authenticated
            {
                return Err(ScopeAuthorityError::Unauthorized.into());
            }
            let role = self
                .admission
                .authorize(
                    authenticated,
                    self.namespace.scope(),
                    Some(attempt.stamp().execution()),
                    ScopeAuthorityAction::Mutate,
                    Some(attempt.cancellation_digest()?),
                )
                .await?;
            if role != ScopeAuthorityRole::Worker {
                return Err(ScopeAuthorityError::Unauthorized.into());
            }
            self.store
                .commit_scope_batch_cancel(
                    ScopeBatchCancelCommand {
                        attempt: attempt.clone(),
                    },
                    class,
                )
                .await
        })
        .await
        .map_err(|_| ScopeBatchError::OutcomeUnknown)?
    }

    /// Resolve an old boot's uncertain write after a committed succession.
    /// Authorize the scope read and check current authority before consulting
    /// the stable receipt floor. Workers, observers and scope controllers may
    /// resolve outcomes. Never resubmit the predecessor's bytes with a
    /// new stamp. An Unknown result requires higher-level reconciliation; it is
    /// not permission to repeat a potentially applied external effect.
    pub async fn predecessor_outcome(
        &self,
        authenticated: &SessionConsumerIdentity,
        current: &ScopeAuthorityStamp,
        predecessor_request: &ScopeBatchRequest,
    ) -> Result<ScopeBatchResolution, ScopeBatchError> {
        tokio::time::timeout(DEFAULT_SESSION_CONSENSUS_OPERATION_TIMEOUT, async {
            if current.namespace() != &self.namespace
                || predecessor_request.scope() != self.namespace.scope()
            {
                return Err(ScopeAuthorityError::Unauthorized.into());
            }
            self.admission
                .authorize(
                    authenticated,
                    self.namespace.scope(),
                    None,
                    ScopeAuthorityAction::Read,
                    None,
                )
                .await?;
            let cut = self.store.scope_batch_cut(self.namespace.scope()).await?;
            let ScopeBatchReadCut::Initialized {
                authority,
                checkpoint,
            } = cut
            else {
                return Err(ScopeBatchError::FormatMismatch);
            };
            authority.check_stamp(current)?;
            if predecessor_request.stamp.revision() >= current.revision()
                || predecessor_request.stamp.incarnation() > current.incarnation()
            {
                return Err(ScopeBatchError::InvalidRequest);
            }
            checkpoint.resolve(predecessor_request)
        })
        .await
        .map_err(|_| ScopeBatchError::Unavailable)?
    }

    async fn authorize(
        &self,
        authenticated: &SessionConsumerIdentity,
        request: &ScopeBatchRequest,
    ) -> Result<(), ScopeBatchError> {
        request.validate()?;
        if request.namespace() != &self.namespace
            || request.stamp.execution().identity() != authenticated
        {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        let role = self
            .admission
            .authorize(
                authenticated,
                self.namespace.scope(),
                Some(request.stamp.execution()),
                ScopeAuthorityAction::Mutate,
                Some(request.digest()?),
            )
            .await?;
        if role != ScopeAuthorityRole::Worker {
            return Err(ScopeAuthorityError::Unauthorized.into());
        }
        Ok(())
    }

    async fn execute_inner(
        &self,
        authenticated: &SessionConsumerIdentity,
        request: &ScopeBatchRequest,
        class: ScopeWorkClass,
    ) -> Result<ScopeBatchOutcome, ScopeBatchError> {
        self.authorize(authenticated, request).await?;
        let current = self
            .store
            .scope_batch_checkpoint(self.namespace.scope())
            .await?;
        if current.replay(request)? {
            return current
                .outcome(request.lane())
                .cloned()
                .ok_or(ScopeBatchError::FormatMismatch);
        }
        self.authorize(authenticated, request).await?;
        let command = ScopeBatchCommand {
            request: request.clone(),
        };
        match self.store.commit_scope_batch(command, class).await {
            Ok(outcome) => Ok(outcome),
            Err(
                ScopeBatchError::OutcomeUnknown
                | ScopeBatchError::Unavailable
                | ScopeBatchError::Scope(
                    ScopeAuthorityError::Unavailable | ScopeAuthorityError::OutcomeUnknown,
                ),
            ) => {
                if let Ok(current) = self
                    .store
                    .scope_batch_checkpoint(self.namespace.scope())
                    .await
                {
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
