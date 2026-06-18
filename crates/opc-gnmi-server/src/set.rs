//! Protocol-neutral gNMI Set model.

#![allow(deprecated)]

use std::time::{Duration, Instant};

use opc_config_model::{
    CommitError, CommitMode, CommitRequest, ConfigOperation, OpcConfig, RequestId, RequestSource,
    TransportType, TrustedPrincipal, YangPath,
};
use opc_mgmt_audit::{AuditOperation, AuditOutcome};
use opc_mgmt_errors::{commit_error_to_status, MgmtStatus};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_schema::SchemaRegistry;

use crate::audit::{outcome_for_error, record_audit, schema_paths_for_yang};
use crate::confirmed_commit::{parse_set_commit_extension, SetCommitExtension};
use crate::get::{now_nanos, yang_path_to_proto};
use crate::metrics::{record_set_commit_latency, SetCommitMetric};
use crate::proto::gnmi;
use crate::proto_adapter::{path_from_proto, typed_value_from_proto};
use crate::{
    normalize_typed_value, GnmiConfigBinding, GnmiError, GnmiPath, GnmiServer, NormalizedValue,
    ResolvedGnmiPath,
};

/// gNMI Set operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetOperation {
    /// `delete`.
    Delete,
    /// `replace`.
    Replace,
    /// `update`.
    Update,
    /// `union_replace`.
    UnionReplace,
}

impl SetOperation {
    /// Stable operation label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delete => "delete",
            Self::Replace => "replace",
            Self::Update => "update",
            Self::UnionReplace => "union_replace",
        }
    }
}

/// Schema-resolved, value-normalized gNMI Set request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NormalizedSet {
    /// Delete paths.
    pub deletes: Vec<YangPath>,
    /// Replace paths and normalized JSON values.
    pub replaces: Vec<(YangPath, NormalizedValue)>,
    /// Update paths and normalized JSON values.
    pub updates: Vec<(YangPath, NormalizedValue)>,
    /// Union-replace paths and normalized JSON values.
    pub union_replaces: Vec<(YangPath, NormalizedValue)>,
}

impl NormalizedSet {
    /// Builds an empty normalized Set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total addressed operation count.
    pub fn len(&self) -> usize {
        self.deletes.len() + self.replaces.len() + self.updates.len() + self.union_replaces.len()
    }

    /// Whether the set contains no operations.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Validates operation count and non-empty semantics.
    pub fn validate(&self, limits: &MgmtLimits) -> Result<(), GnmiError> {
        if self.is_empty() {
            return Err(GnmiError::invalid("gNMI Set request is empty"));
        }
        limits
            .check_paths(self.len())
            .map_err(GnmiError::from_limits)
    }

    /// Stable changed-path hint for config-bus request metadata.
    pub fn changed_paths_hint(&self) -> Vec<YangPath> {
        let mut paths = Vec::with_capacity(self.len());
        paths.extend(self.deletes.iter().cloned());
        paths.extend(self.replaces.iter().map(|(path, _)| path.clone()));
        paths.extend(self.updates.iter().map(|(path, _)| path.clone()));
        paths.extend(self.union_replaces.iter().map(|(path, _)| path.clone()));
        paths
    }

    /// Selects the coarse config-bus operation shape.
    ///
    /// The config bus derives authoritative changed paths from the candidate
    /// diff. This helper only selects the stable high-level operation code.
    pub fn config_operation(&self) -> Result<ConfigOperation, GnmiError> {
        if self.is_empty() {
            return Err(GnmiError::invalid("gNMI Set request is empty"));
        }
        if !self.deletes.is_empty()
            && self.replaces.is_empty()
            && self.updates.is_empty()
            && self.union_replaces.is_empty()
        {
            Ok(ConfigOperation::Delete)
        } else if self.deletes.is_empty()
            && self.updates.is_empty()
            && (!self.replaces.is_empty() || !self.union_replaces.is_empty())
        {
            Ok(ConfigOperation::Replace)
        } else {
            Ok(ConfigOperation::Patch)
        }
    }
}

/// Executes an authenticated gNMI Set request as one atomic config-bus commit.
pub(crate) async fn handle_set<C, B>(
    server: &GnmiServer<C, B>,
    principal: &TrustedPrincipal,
    request: &gnmi::SetRequest,
) -> Result<gnmi::SetResponse, GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    let request_id = RequestId::new();
    if let Err(err) = server
        .arbitration()
        .authorize_set(principal, &request.extension)
    {
        audit_set_result(
            server,
            request_id,
            principal,
            AuditOperation::Update,
            outcome_for_error(&err),
            Vec::new(),
        )?;
        return Err(err);
    }
    let commit_extension = match parse_set_commit_extension(&request.extension) {
        Ok(commit_extension) => commit_extension,
        Err(err) => {
            audit_set_result(
                server,
                request_id,
                principal,
                AuditOperation::Update,
                outcome_for_error(&err),
                Vec::new(),
            )?;
            return Err(err);
        }
    };
    if commit_extension.requires_arbitration() {
        if let Err(err) = server
            .arbitration()
            .ensure_commit_confirmed_fenced(&request.extension)
        {
            audit_set_result(
                server,
                request_id,
                principal,
                AuditOperation::Update,
                outcome_for_error(&err),
                Vec::new(),
            )?;
            return Err(err);
        }
    }
    if let Some(response) = handle_set_commit_extension_control(
        server,
        principal,
        request_id,
        request,
        commit_extension,
    )
    .await?
    {
        return Ok(response);
    }

    let normalized =
        match normalize_set_request(server.binding().schema(), server.limits(), request) {
            Ok(normalized) => normalized,
            Err(err) => {
                audit_set_result(
                    server,
                    request_id,
                    principal,
                    AuditOperation::Update,
                    outcome_for_error(&err),
                    Vec::new(),
                )?;
                return Err(err);
            }
        };
    let operation = normalized.config_operation()?;
    let commit_metric = set_commit_metric(operation);
    let audit_operation = set_audit_operation(operation);
    let audit_paths =
        schema_paths_for_yang(server.binding().schema(), normalized.changed_paths_hint())?;

    let bus = server.binding().config_bus();
    let snapshot = bus.current_snapshot();
    let candidate = match server
        .binding()
        .patcher()
        .apply_set(snapshot.config.as_ref(), &normalized)
    {
        Ok(candidate) => candidate,
        Err(err) => {
            audit_set_result(
                server,
                request_id,
                principal,
                audit_operation,
                outcome_for_error(&err),
                audit_paths,
            )?;
            return Err(err);
        }
    };

    let mode = match commit_extension {
        SetCommitExtension::Normal => CommitMode::Commit,
        SetCommitExtension::Begin { timeout } => CommitMode::CommitConfirmed { timeout },
        SetCommitExtension::Confirm | SetCommitExtension::Cancel => {
            unreachable!("control actions returned before normalization")
        }
    };
    let commit = CommitRequest::new(
        request_id,
        principal.clone(),
        TransportType::Gnmi,
        RequestSource::Northbound,
        operation,
        mode,
        Instant::now() + Duration::from_secs(30),
        Some(candidate),
        normalized.changed_paths_hint(),
    )
    .with_base_version(snapshot.version);

    let start = Instant::now();
    match bus.submit(commit).await {
        Ok(_) => {
            record_set_commit_latency(commit_metric, start.elapsed());
            audit_set_result(
                server,
                request_id,
                principal,
                audit_operation,
                AuditOutcome::Success,
                audit_paths,
            )?;
        }
        Err(err) => {
            let err = commit_error_to_gnmi(err);
            audit_set_result(
                server,
                request_id,
                principal,
                audit_operation,
                outcome_for_error(&err),
                audit_paths,
            )?;
            return Err(err);
        }
    }

    Ok(gnmi::SetResponse {
        prefix: None,
        response: update_results(&normalized)?,
        message: None,
        timestamp: now_nanos(),
        extension: Vec::new(),
    })
}

async fn handle_set_commit_extension_control<C, B>(
    server: &GnmiServer<C, B>,
    principal: &TrustedPrincipal,
    request_id: RequestId,
    request: &gnmi::SetRequest,
    commit_extension: SetCommitExtension,
) -> Result<Option<gnmi::SetResponse>, GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    match commit_extension {
        SetCommitExtension::Normal | SetCommitExtension::Begin { .. } => {
            if commit_extension == SetCommitExtension::Normal || set_operation_count(request) > 0 {
                Ok(None)
            } else {
                let err = GnmiError::invalid(
                    "OpenPacketCore commit-confirmed begin requires Set operations",
                );
                audit_set_result(
                    server,
                    request_id,
                    principal,
                    AuditOperation::Update,
                    outcome_for_error(&err),
                    Vec::new(),
                )?;
                Err(err)
            }
        }
        SetCommitExtension::Confirm | SetCommitExtension::Cancel => {
            if set_operation_count(request) != 0 {
                let err = GnmiError::invalid(
                    "OpenPacketCore commit-confirmed control action cannot include Set operations",
                );
                audit_set_result(
                    server,
                    request_id,
                    principal,
                    AuditOperation::Update,
                    outcome_for_error(&err),
                    Vec::new(),
                )?;
                return Err(err);
            }
            submit_commit_confirmed_control(server, principal, request_id, commit_extension)
                .await
                .map(Some)
        }
    }
}

async fn submit_commit_confirmed_control<C, B>(
    server: &GnmiServer<C, B>,
    principal: &TrustedPrincipal,
    request_id: RequestId,
    commit_extension: SetCommitExtension,
) -> Result<gnmi::SetResponse, GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    let bus = server.binding().config_bus();
    let snapshot = bus.current_snapshot();
    let deadline = Instant::now() + Duration::from_secs(30);
    let commit = match commit_extension {
        SetCommitExtension::Confirm => CommitRequest::new(
            request_id,
            principal.clone(),
            TransportType::Gnmi,
            RequestSource::Northbound,
            ConfigOperation::Patch,
            CommitMode::Commit,
            deadline,
            None,
            Vec::new(),
        ),
        SetCommitExtension::Cancel => CommitRequest::cancel_confirmed(
            request_id,
            principal.clone(),
            TransportType::Gnmi,
            RequestSource::Northbound,
            Vec::new(),
            deadline,
        ),
        SetCommitExtension::Normal | SetCommitExtension::Begin { .. } => {
            unreachable!("only control actions reach this helper")
        }
    }
    .with_base_version(snapshot.version);

    let start = Instant::now();
    match bus.submit(commit).await {
        Ok(_) => {
            record_set_commit_latency(SetCommitMetric::Patch, start.elapsed());
            audit_set_result(
                server,
                request_id,
                principal,
                AuditOperation::Update,
                AuditOutcome::Success,
                Vec::new(),
            )?;
        }
        Err(err) => {
            let err = commit_error_to_gnmi(err);
            audit_set_result(
                server,
                request_id,
                principal,
                AuditOperation::Update,
                outcome_for_error(&err),
                Vec::new(),
            )?;
            return Err(err);
        }
    }

    Ok(gnmi::SetResponse {
        prefix: None,
        response: Vec::new(),
        message: None,
        timestamp: now_nanos(),
        extension: Vec::new(),
    })
}

fn set_operation_count(request: &gnmi::SetRequest) -> usize {
    request.delete.len()
        + request.replace.len()
        + request.update.len()
        + request.union_replace.len()
}

fn audit_set_result<C, B>(
    server: &GnmiServer<C, B>,
    request_id: RequestId,
    principal: &TrustedPrincipal,
    operation: AuditOperation,
    outcome: AuditOutcome,
    paths: Vec<opc_mgmt_audit::SchemaNodePath>,
) -> Result<(), GnmiError>
where
    C: OpcConfig,
    B: GnmiConfigBinding<C>,
{
    record_audit(
        server.audit(),
        request_id,
        principal,
        operation,
        outcome,
        paths,
    )
}

fn normalize_set_request(
    registry: &'static dyn SchemaRegistry,
    limits: &MgmtLimits,
    request: &gnmi::SetRequest,
) -> Result<NormalizedSet, GnmiError> {
    let prefix = request.prefix.as_ref().map(path_from_proto).transpose()?;
    let mut normalized = NormalizedSet::new();

    for path in &request.delete {
        let path = path_from_proto(path)?;
        normalized
            .deletes
            .push(resolve_writable_path(registry, prefix.as_ref(), &path)?.canonical);
    }
    for update in &request.replace {
        normalized
            .replaces
            .push(resolve_update(registry, limits, prefix.as_ref(), update)?);
    }
    for update in &request.update {
        normalized
            .updates
            .push(resolve_update(registry, limits, prefix.as_ref(), update)?);
    }
    for update in &request.union_replace {
        normalized
            .union_replaces
            .push(resolve_update(registry, limits, prefix.as_ref(), update)?);
    }

    normalized.validate(limits)?;
    Ok(normalized)
}

fn resolve_update(
    registry: &'static dyn SchemaRegistry,
    limits: &MgmtLimits,
    prefix: Option<&GnmiPath>,
    update: &gnmi::Update,
) -> Result<(YangPath, NormalizedValue), GnmiError> {
    let path = update
        .path
        .as_ref()
        .map(path_from_proto)
        .transpose()?
        .unwrap_or_default();
    let resolved = resolve_writable_path(registry, prefix, &path)?;
    let value = update
        .val
        .as_ref()
        .ok_or_else(|| GnmiError::invalid("gNMI Set update is missing TypedValue"))?;
    let typed = typed_value_from_proto(value)?;
    let value = normalize_typed_value(&typed, limits)?;
    Ok((resolved.canonical, value))
}

fn resolve_writable_path(
    registry: &'static dyn SchemaRegistry,
    prefix: Option<&GnmiPath>,
    path: &GnmiPath,
) -> Result<ResolvedGnmiPath, GnmiError> {
    let resolved = crate::resolve_path(registry, prefix, path)?;
    if !resolved.node.config {
        return Err(GnmiError::invalid("gNMI Set path is not writable"));
    }
    Ok(resolved)
}

fn update_results(normalized: &NormalizedSet) -> Result<Vec<gnmi::UpdateResult>, GnmiError> {
    let mut results = Vec::with_capacity(normalized.len());
    for path in &normalized.deletes {
        results.push(update_result(path, SetOperation::Delete)?);
    }
    for (path, _) in &normalized.replaces {
        results.push(update_result(path, SetOperation::Replace)?);
    }
    for (path, _) in &normalized.updates {
        results.push(update_result(path, SetOperation::Update)?);
    }
    for (path, _) in &normalized.union_replaces {
        results.push(update_result(path, SetOperation::UnionReplace)?);
    }
    Ok(results)
}

fn update_result(
    path: &YangPath,
    operation: SetOperation,
) -> Result<gnmi::UpdateResult, GnmiError> {
    Ok(gnmi::UpdateResult {
        timestamp: 0,
        path: Some(yang_path_to_proto(path)?),
        message: None,
        op: set_operation_to_proto(operation),
    })
}

fn set_operation_to_proto(operation: SetOperation) -> i32 {
    match operation {
        SetOperation::Delete => gnmi::update_result::Operation::Delete as i32,
        SetOperation::Replace => gnmi::update_result::Operation::Replace as i32,
        SetOperation::Update => gnmi::update_result::Operation::Update as i32,
        SetOperation::UnionReplace => gnmi::update_result::Operation::UnionReplace as i32,
    }
}

fn set_commit_metric(operation: ConfigOperation) -> SetCommitMetric {
    match operation {
        ConfigOperation::Delete => SetCommitMetric::Delete,
        ConfigOperation::Replace => SetCommitMetric::Replace,
        ConfigOperation::Patch | ConfigOperation::Rollback => SetCommitMetric::Patch,
    }
}

fn set_audit_operation(operation: ConfigOperation) -> AuditOperation {
    match operation {
        ConfigOperation::Delete => AuditOperation::Delete,
        ConfigOperation::Replace => AuditOperation::Replace,
        ConfigOperation::Patch | ConfigOperation::Rollback => AuditOperation::Update,
    }
}

fn commit_error_to_gnmi(error: CommitError) -> GnmiError {
    match commit_error_to_status(error.code) {
        MgmtStatus::InvalidArgument => GnmiError::invalid("gNMI Set commit failed"),
        MgmtStatus::NotFound => GnmiError::not_found("gNMI Set commit failed"),
        MgmtStatus::PermissionDenied => GnmiError::PermissionDenied,
        MgmtStatus::Unauthenticated => GnmiError::Unauthenticated,
        MgmtStatus::Unimplemented => GnmiError::unimplemented("gNMI Set commit failed"),
        MgmtStatus::Unavailable => GnmiError::unavailable("gNMI Set commit failed"),
        MgmtStatus::DeadlineExceeded => GnmiError::DeadlineExceeded,
        MgmtStatus::FailedPrecondition => GnmiError::failed_precondition("gNMI Set commit failed"),
        MgmtStatus::Internal | MgmtStatus::Ok => GnmiError::schema("gNMI Set commit failed"),
        _ => GnmiError::schema("gNMI Set commit failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Encoding, NormalizedValue};

    fn path(value: &str) -> YangPath {
        YangPath::new(value).expect("path")
    }

    fn json(value: &str) -> NormalizedValue {
        NormalizedValue::new(Encoding::JsonIetf, value, &MgmtLimits::default()).expect("json")
    }

    #[test]
    fn validates_non_empty_and_limits() {
        let limits = MgmtLimits {
            max_paths_per_request: 1,
            ..MgmtLimits::default()
        };
        let empty = NormalizedSet::new();
        assert!(empty.validate(&limits).is_err());

        let set = NormalizedSet {
            deletes: vec![path("/a:b")],
            replaces: vec![(path("/a:c"), json("1"))],
            updates: Vec::new(),
            union_replaces: Vec::new(),
        };
        assert!(set.validate(&limits).is_err());
    }

    #[test]
    fn config_operation_is_conservative() {
        assert_eq!(
            NormalizedSet {
                deletes: vec![path("/a:b")],
                ..NormalizedSet::default()
            }
            .config_operation()
            .expect("op"),
            ConfigOperation::Delete
        );
        assert_eq!(
            NormalizedSet {
                replaces: vec![(path("/a:b"), json("1"))],
                union_replaces: vec![(path("/a:c"), json("2"))],
                ..NormalizedSet::default()
            }
            .config_operation()
            .expect("op"),
            ConfigOperation::Replace
        );
        assert_eq!(
            NormalizedSet {
                replaces: vec![(path("/a:b"), json("1"))],
                updates: vec![(path("/a:c"), json("2"))],
                ..NormalizedSet::default()
            }
            .config_operation()
            .expect("op"),
            ConfigOperation::Patch
        );
    }
}
