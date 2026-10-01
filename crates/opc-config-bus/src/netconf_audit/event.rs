//! Exact event conversion shared in semantics with the existing consensus observation adapter.
use crate::StoreError;
use opc_config_model::TransportType;
use opc_mgmt_audit::{AuditEvent, AuditOperation, AuditOutcome, AuditTimeSource};
use opc_persist::{
    ManagementAuditEventRecord, ManagementAuditInstant, ManagementAuditOperationCode,
    ManagementAuditOutcomeCode, ManagementAuditTimeSourceCode, ManagementAuditTransportCode,
};

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
