//! Protocol-to-effect handoff. No protocol Intent is acknowledged separately.
use std::{fmt, panic::AssertUnwindSafe, sync::Arc};

use futures_util::FutureExt;
use opc_config_model::{
    CommitError, CommitErrorCode, CommitMode, CommitRequest, CommitResult, ConfigOperation,
    OpcConfig,
};
use opc_mgmt_audit::{AuditEvent, AuditOperation, AuditOutcome, AuditReasonCode, AuditSink};

use crate::{ConfigBus, StoreError};

/// Required mutation-audit submission through one exact config-bus worker.
///
/// Obtain this from [`ConfigBus::required_config_audit`]. It carries no caller
/// authority and acknowledges no Intent. Submission still authorizes and
/// validates the request, then requires the datastore to admit one audit intent
/// bound to the complete encrypted effect before applying that effect.
///
/// The bus worker owns admitted submissions independently of caller cancellation.
/// After persistence starts, the datastore's retained operation, fixed expiry,
/// and terminal recovery are the only audit outcome authority. Generic sink
/// observations must never be substituted for a configuration result.
#[derive(Clone)]
pub struct RequiredConfigAudit<C: OpcConfig> {
    bus: ConfigBus<C>,
    observations: Arc<dyn AuditSink>,
}

impl<C: OpcConfig> RequiredConfigAudit<C> {
    /// Whether this capability belongs to this exact worker, including clones.
    /// Another bus over the same datastore is deliberately not equivalent.
    pub fn belongs_to(&self, bus: &ConfigBus<C>) -> bool {
        self.bus.tx.same_channel(&bus.tx)
    }

    /// The same datastore's read/denial observation port. It refuses standalone
    /// mutation Intents; only [`Self::submit`] can hand those to a config effect.
    pub fn observation_sink(&self) -> Arc<dyn AuditSink> {
        Arc::clone(&self.observations)
    }

    /// Transfer a protocol intent and its original immutable request together.
    /// The candidate, base version, mode and any confirmed target are bound by
    /// the authenticated encrypted commit produced by the worker, not by paths.
    pub async fn submit(
        &self,
        request: CommitRequest<C>,
        intent: AuditEvent,
    ) -> Result<CommitResult, CommitError> {
        if matches!(request.mode, CommitMode::ValidateOnly)
            || intent.outcome != AuditOutcome::Intent
            || intent.tx_id.is_some()
            || intent.request_id != request.request_id
            || intent.tenant != request.principal.tenant.as_str()
            || intent.principal != opc_mgmt_audit::principal_descriptor(&request.principal)
            || intent.transport != request.transport
            || intent.operation != audit_operation(request.operation)
        {
            return Err(CommitError::new(
                CommitErrorCode::AdmissionRejected,
                "configuration audit request binding mismatch",
            ));
        }
        self.bus
            .submit_with_audit(
                request,
                Some(RequiredAuditSubmission {
                    intent,
                    observations: Arc::clone(&self.observations),
                    effect_started: false,
                }),
            )
            .await
    }
}

impl<C: OpcConfig> fmt::Debug for RequiredConfigAudit<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequiredConfigAudit(<redacted>)")
    }
}

impl<C: OpcConfig> ConfigBus<C> {
    /// Bind the datastore's required audit port to this exact worker.
    /// Legacy and unaudited stores fail closed. Advertising an observation
    /// port alone cannot enable writes: the worker always uses the separate
    /// required-audit append method, whose default also refuses the effect.
    pub fn required_config_audit(&self) -> Result<RequiredConfigAudit<C>, StoreError> {
        let observations = self.store.required_audit_observations().ok_or_else(|| {
            StoreError::unavailable("required configuration audit is unsupported")
        })?;
        Ok(RequiredConfigAudit {
            bus: self.clone(),
            observations,
        })
    }
}

pub(crate) fn audit_operation(operation: ConfigOperation) -> AuditOperation {
    match operation {
        ConfigOperation::Replace => AuditOperation::Replace,
        ConfigOperation::Patch => AuditOperation::Update,
        ConfigOperation::Delete => AuditOperation::Delete,
        ConfigOperation::Rollback => AuditOperation::Rollback,
    }
}

pub(crate) struct RequiredAuditSubmission {
    pub(crate) intent: AuditEvent,
    observations: Arc<dyn AuditSink>,
    pub(crate) effect_started: bool,
}

impl RequiredAuditSubmission {
    pub(crate) async fn record_refusal(&self, error: &CommitError) {
        if self.effect_started {
            return;
        }
        let mut observation = self.intent.clone();
        observation.outcome = if error.code == CommitErrorCode::AuthorizationDenied {
            AuditOutcome::denied_code(AuditReasonCode::ACCESS_DENIED)
        } else {
            AuditOutcome::failed_code(AuditReasonCode::OPERATION_FAILED)
        };
        // The rejection cannot become a mutation success if observation fails.
        // Contain both future construction and poll panics without their payload.
        let result = AssertUnwindSafe(async { self.observations.record_async(&observation).await })
            .catch_unwind()
            .await;
        if !matches!(result, Ok(Ok(()))) {
            tracing::error!("configuration refusal audit observation unavailable");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommitWrite, ManagedDatastore, MockManagedDatastore, StoredConfig};
    use opc_config_model::{
        IdempotencyKey, RequestId, RequestSource, RollbackTarget, TransportType, TrustedPrincipal,
        WorkloadIdentity,
    };
    use opc_types::{TenantId, TxId};
    use std::time::{Duration, Instant};

    struct RefusingObservations;
    impl AuditSink for RefusingObservations {
        fn record(&self, _: &AuditEvent) -> Result<(), opc_mgmt_audit::AuditError> {
            Err(opc_mgmt_audit::AuditError::unavailable(
                "no mutation authority",
            ))
        }
    }

    struct AdvertisedOnly(Arc<MockManagedDatastore<()>>);
    #[async_trait::async_trait]
    impl ManagedDatastore<()> for AdvertisedOnly {
        fn required_audit_observations(&self) -> Option<Arc<dyn AuditSink>> {
            Some(Arc::new(RefusingObservations))
        }
        async fn load_latest(&self) -> Result<Option<StoredConfig<()>>, StoreError> {
            self.0.load_latest().await
        }
        async fn load_rollback(
            &self,
            target: RollbackTarget,
        ) -> Result<StoredConfig<()>, StoreError> {
            self.0.load_rollback(target).await
        }
        async fn load_by_idempotency_key(
            &self,
            key: &IdempotencyKey,
        ) -> Result<Option<StoredConfig<()>>, StoreError> {
            self.0.load_by_idempotency_key(key).await
        }
        async fn load_by_request_id(
            &self,
            id: RequestId,
        ) -> Result<Option<StoredConfig<()>>, StoreError> {
            self.0.load_by_request_id(id).await
        }
        async fn append_commit_write(&self, write: CommitWrite<()>) -> Result<(), StoreError> {
            self.0.append_commit_write(write).await
        }
        async fn clear_recovery_required(&self, tx_id: TxId) -> Result<(), StoreError> {
            self.0.clear_recovery_required(tx_id).await
        }
    }

    #[tokio::test]
    async fn observation_advertisement_cannot_enable_an_unaudited_append() {
        let store = Arc::new(MockManagedDatastore::new());
        let bus = ConfigBus::new_dev_only((), AdvertisedOnly(store.clone()))
            .await
            .unwrap();
        let audit = bus.required_config_audit().unwrap();
        let principal = TrustedPrincipal::new(
            WorkloadIdentity::User("synthetic".into()),
            TenantId::from_static("test"),
        );
        let request = CommitRequest::commit(
            RequestId::new(),
            principal,
            TransportType::Gnmi,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            (),
            Vec::new(),
            Instant::now() + Duration::from_secs(5),
        );
        let event = AuditEvent::new(
            request.request_id,
            &request.principal,
            request.transport,
            AuditOperation::Replace,
            AuditOutcome::Intent,
        );
        let error = audit.submit(request, event).await.unwrap_err();
        assert_eq!(error.code, CommitErrorCode::PersistFailed);
        assert!(store.load_latest().await.unwrap().is_none());
        assert_eq!(format!("{audit:?}"), "RequiredConfigAudit(<redacted>)");
    }
}
