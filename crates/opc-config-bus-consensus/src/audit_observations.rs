//! Privacy-projected observations on the exact configuration consensus owner.
use std::{future::Future, pin::Pin, sync::Arc};

use opc_config_bus::StoreError;
use opc_config_model::TransportType;
use opc_mgmt_audit::{
    AuditError, AuditEvent, AuditOperation, AuditOutcome, AuditSink, AuditTimeSource,
};
use opc_persist::audit_authority::{AuditAdmission, AuditCaller, AuditOperationState};
use opc_persist::{
    ConsensusConfigStore, ManagementAuditEventRecord, ManagementAuditInstant,
    ManagementAuditOperationCode, ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode,
    ManagementAuditTransportCode,
};

use crate::ConfigAuditPolicy;

impl ConfigAuditPolicy {
    pub(super) fn observation_sink(&self, store: Arc<ConsensusConfigStore>) -> Arc<dyn AuditSink> {
        Arc::new(ConsensusObservations {
            store,
            policy: self.clone(),
            admission: Arc::new(tokio::sync::Semaphore::new(32)),
        })
    }
}

struct ConsensusObservations {
    store: Arc<ConsensusConfigStore>,
    policy: ConfigAuditPolicy,
    admission: Arc<tokio::sync::Semaphore>,
}

impl AuditSink for ConsensusObservations {
    fn record(&self, _event: &AuditEvent) -> Result<(), AuditError> {
        Err(AuditError::unavailable(
            "consensus audit requires asynchronous recording",
        ))
    }

    fn record_async<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuditError>> + Send + 'a>> {
        Box::pin(async move {
            let runtime = tokio::runtime::Handle::try_current().map_err(|_| unavailable())?;
            let permit = Arc::clone(&self.admission)
                .try_acquire_owned()
                .map_err(|_| unavailable())?;
            let event = convert_event(event).map_err(|_| unavailable())?;
            let caller = AuditCaller::project(
                self.policy.privacy.as_ref(),
                event.tenant(),
                event.principal(),
            )
            .map_err(|_| unavailable())?;
            // This rejects Intent. Project before the queue/task boundary so
            // the immutable retained work contains no raw caller or request.
            let handle = self
                .store
                .prepare_audit_observation(
                    self.policy.privacy.as_ref(),
                    &event,
                    self.policy.lifetime,
                )
                .map_err(|_| unavailable())?;
            let expected = event.outcome();
            let store = Arc::clone(&self.store);
            // No await precedes ownership transfer. Once this future first
            // returns Pending, dropping it cannot retract the admitted work.
            runtime
                .spawn(async move {
                    let _permit = permit;
                    match store.admit_audit_operation(&handle, caller).await {
                        AuditAdmission::Applied(receipt)
                            if receipt.state()
                                == (AuditOperationState::Observed { outcome: expected }) =>
                        {
                            store
                                .complete_required_audit_outcome(&receipt, caller)
                                .await
                                .map_err(|_| unavailable())
                        }
                        _ => Err(unavailable()),
                    }
                })
                .await
                .map_err(|_| unavailable())?
        })
    }
}

fn unavailable() -> AuditError {
    AuditError::unavailable("consensus audit observation unavailable")
}

pub(super) fn convert_event(event: &AuditEvent) -> Result<ManagementAuditEventRecord, StoreError> {
    let time_source = match event.occurred_at.source() {
        AuditTimeSource::NodeClock => ManagementAuditTimeSourceCode::NodeClock,
        AuditTimeSource::SynchronisedNodeClock => {
            ManagementAuditTimeSourceCode::SynchronisedNodeClock
        }
    };
    let occurred_at = ManagementAuditInstant::try_new(
        event.occurred_at.utc_seconds(),
        event.occurred_at.nanosecond(),
        event.occurred_at.monotonic_sequence(),
        time_source,
    )
    .map_err(|_| StoreError::internal("invalid audit observation timestamp"))?;
    let transport = match event.transport {
        TransportType::Gnmi => ManagementAuditTransportCode::Gnmi,
        TransportType::NetconfSsh => ManagementAuditTransportCode::NetconfSsh,
        TransportType::NetconfTls => ManagementAuditTransportCode::NetconfTls,
        TransportType::RestconfHttps => ManagementAuditTransportCode::RestconfHttps,
        TransportType::Internal => ManagementAuditTransportCode::Internal,
    };
    let operation = match event.operation {
        AuditOperation::Capabilities => ManagementAuditOperationCode::Capabilities,
        AuditOperation::Read => ManagementAuditOperationCode::Read,
        AuditOperation::Subscribe => ManagementAuditOperationCode::Subscribe,
        AuditOperation::Create => ManagementAuditOperationCode::Create,
        AuditOperation::Update => ManagementAuditOperationCode::Update,
        AuditOperation::Replace => ManagementAuditOperationCode::Replace,
        AuditOperation::Delete => ManagementAuditOperationCode::Delete,
        AuditOperation::Commit => ManagementAuditOperationCode::Commit,
        AuditOperation::Rollback => ManagementAuditOperationCode::Rollback,
        AuditOperation::Validate => ManagementAuditOperationCode::Validate,
        AuditOperation::Exec => ManagementAuditOperationCode::Exec,
    };
    let outcome = match event.outcome {
        AuditOutcome::Intent => ManagementAuditOutcomeCode::Intent,
        AuditOutcome::Success => ManagementAuditOutcomeCode::Success,
        AuditOutcome::Denied(_) => ManagementAuditOutcomeCode::Denied,
        AuditOutcome::Failed(_) => ManagementAuditOutcomeCode::Failed,
    };
    ManagementAuditEventRecord::try_new(
        *event.request_id.as_uuid().as_bytes(),
        occurred_at,
        event.tenant.as_str(),
        event.principal.as_str(),
        transport,
        operation,
        outcome,
        event.outcome.code(),
        event.schema_paths.iter().map(|path| path.as_str()),
        event.tx_id.as_ref().map(|id| id.as_str()),
    )
    .map_err(|_| StoreError::internal("invalid audit observation"))
}
