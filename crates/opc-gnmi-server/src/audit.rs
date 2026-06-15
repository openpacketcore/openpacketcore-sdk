//! gNMI audit helpers over the shared management-plane audit contract.

use opc_config_model::{RequestId, TransportType, TrustedPrincipal, YangPath};
use opc_mgmt_audit::{AuditOperation, AuditOutcome, AuditReasonCode, AuditSink, SchemaNodePath};
use opc_mgmt_schema::SchemaRegistry;

use crate::GnmiError;

/// Records one gNMI audit event, mapping sink failures to a generic server
/// error. Callers must preserve the original client-facing error when audit
/// succeeds.
pub(crate) fn record_audit(
    audit: &dyn AuditSink,
    request_id: RequestId,
    principal: &TrustedPrincipal,
    operation: AuditOperation,
    outcome: AuditOutcome,
    paths: Vec<SchemaNodePath>,
) -> Result<(), GnmiError> {
    audit
        .record(
            &opc_mgmt_audit::AuditEvent::new(
                request_id,
                principal,
                TransportType::Gnmi,
                operation,
                outcome,
            )
            .with_paths(paths),
        )
        .map_err(|_| GnmiError::schema("gNMI audit sink failed"))
}

/// Maps a gNMI error class to a stable audit outcome.
pub(crate) fn outcome_for_error(err: &GnmiError) -> AuditOutcome {
    match err {
        GnmiError::PermissionDenied | GnmiError::Unauthenticated => {
            AuditOutcome::denied_code(AuditReasonCode::ACCESS_DENIED)
        }
        GnmiError::Unimplemented { .. } => {
            AuditOutcome::failed_code(AuditReasonCode::OPERATION_NOT_SUPPORTED)
        }
        GnmiError::Unavailable { .. } => {
            AuditOutcome::failed_code(AuditReasonCode::RESOURCE_DENIED)
        }
        GnmiError::InvalidArgument { detail } if detail.contains("management-plane limit") => {
            AuditOutcome::failed_code(AuditReasonCode::TOO_BIG)
        }
        GnmiError::InvalidArgument { .. } | GnmiError::NotFound { .. } => {
            AuditOutcome::failed_code(AuditReasonCode::INVALID_VALUE)
        }
        GnmiError::DeadlineExceeded
        | GnmiError::FailedPrecondition { .. }
        | GnmiError::Internal { .. } => {
            AuditOutcome::failed_code(AuditReasonCode::OPERATION_FAILED)
        }
    }
}

/// Converts canonical SDK instance paths to predicate-free audit schema paths.
pub(crate) fn schema_paths_for_yang(
    registry: &'static dyn SchemaRegistry,
    paths: impl IntoIterator<Item = YangPath>,
) -> Result<Vec<SchemaNodePath>, GnmiError> {
    let mut schema_paths = paths
        .into_iter()
        .map(|path| {
            let node = registry
                .node(path.as_str())
                .ok_or_else(|| GnmiError::schema("gNMI audit path is outside schema"))?;
            SchemaNodePath::new(node.path)
                .map_err(|_| GnmiError::schema("gNMI audit schema path is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    schema_paths.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    schema_paths.dedup_by(|a, b| a.as_str() == b.as_str());
    Ok(schema_paths)
}

/// Converts registry schema paths to audit schema paths.
pub(crate) fn schema_paths_for_schema(
    paths: impl IntoIterator<Item = &'static str>,
) -> Result<Vec<SchemaNodePath>, GnmiError> {
    let mut schema_paths = paths
        .into_iter()
        .map(|path| {
            SchemaNodePath::new(path)
                .map_err(|_| GnmiError::schema("gNMI audit schema path is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    schema_paths.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    schema_paths.dedup_by(|a, b| a.as_str() == b.as_str());
    Ok(schema_paths)
}
