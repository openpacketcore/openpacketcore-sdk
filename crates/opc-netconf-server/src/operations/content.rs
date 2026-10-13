//! One pre-access authorization and capture path for content-filtered reads.

use std::collections::BTreeSet;
use std::sync::Arc;

use opc_config_model::OpcConfig;
use opc_mgmt_audit::{AuditEvent, AuditOperation, AuditOutcome, AuditSink, SchemaNodePath};
use opc_mgmt_authz::{PolicySource, ReadAction, ReadAuthorizer};
use opc_mgmt_schema::subtree::{AuthorizedSubtreePlan, SubtreeError};
use opc_mgmt_schema::{DefaultReport, NetconfXmlRenderContext, SchemaRegistry};

use crate::binding::{NetconfConfigBinding, ReadSelection};
use crate::capabilities::{NETCONF_BASE_NS, NETCONF_NMDA_NS};
use crate::error::{rpc_error_reply_with_attrs, rpc_ok_reply_with_attrs_and_data_ns, RpcError};
use crate::filter::{
    compile_content, netconf_monitoring_registry, yang_library_registry, ContentScope,
};
use crate::metrics::{
    record_nacm_denials, record_rpc_error, record_rpc_success, NetconfNacmAction, NetconfOperation,
};
use crate::xml::{
    Datastore, Filter, GetConfigRequest, GetDataRequest, GetRequest, NmdaDatastore, RpcOperation,
    SubtreeFilter, WithDefaultsMode,
};

use super::get::GetContext;
use super::{record_audit, AuditMode};

mod state;

#[derive(Clone, Copy)]
pub(crate) enum ContentRequest<'a> {
    Get(&'a GetRequest),
    Config(&'a GetConfigRequest),
    Data(&'a GetDataRequest),
}

#[derive(Clone, Copy)]
pub(crate) enum ContentSource {
    Running,
    Candidate,
    Startup,
}

/// A request capture can share an owned snapshot or borrow one supplied by a
/// public handler's caller. Neither variant clones the configuration model.
pub(crate) enum ContentConfig<'a, C> {
    Shared(Arc<C>),
    Borrowed(&'a C),
}

impl<C> std::ops::Deref for ContentConfig<'_, C> {
    type Target = C;

    fn deref(&self) -> &C {
        match self {
            Self::Shared(config) => config,
            Self::Borrowed(config) => config,
        }
    }
}

impl<'a> ContentRequest<'a> {
    pub(crate) fn from_operation(operation: &'a RpcOperation) -> Option<Self> {
        let request = match operation {
            RpcOperation::Get(request) => Self::Get(request),
            RpcOperation::GetConfig(request) => Self::Config(request),
            RpcOperation::GetData(request) => Self::Data(request),
            _ => return None,
        };
        request.filter().map(|_| request)
    }

    /// Full content support takes precedence over the existing key-only read
    /// profile. Bindings without it still use that schema-validated profile for
    /// Get and operational GetData; other constrained reads must refuse before
    /// loading configuration. Neither route falls back to opaque XML matching.
    pub(crate) fn use_content_handler<C: OpcConfig, B: NetconfConfigBinding<C>>(
        self,
        binding: &B,
    ) -> bool {
        let key_read = matches!(self, Self::Get(_))
            || matches!(self, Self::Data(request) if request.datastore == NmdaDatastore::Operational);
        self.filter().is_some() && (binding.supports_subtree_content() || !key_read)
    }

    pub(crate) fn filter(self) -> Option<&'a SubtreeFilter> {
        let filter = match self {
            Self::Get(request) => &request.filter,
            Self::Config(request) => &request.filter,
            Self::Data(request) => &request.filter,
        };
        match filter {
            Some(Filter::Subtree(filter)) if filter.has_content_matches() => Some(filter),
            _ => None,
        }
    }

    fn operation(self) -> NetconfOperation {
        match self {
            Self::Get(_) => NetconfOperation::Get,
            Self::Config(_) => NetconfOperation::GetConfig,
            Self::Data(_) => NetconfOperation::GetData,
        }
    }

    fn data_namespace(self) -> &'static str {
        if matches!(self, Self::Data(_)) {
            NETCONF_NMDA_NS
        } else {
            NETCONF_BASE_NS
        }
    }

    fn parameters<C: OpcConfig, B: NetconfConfigBinding<C>>(
        self,
        binding: &B,
    ) -> Result<(ContentScope, ContentSource, DefaultReport, bool), RpcError> {
        let (scope, source, defaults, empty_scope) = match self {
            Self::Get(request) => (
                ContentScope::All,
                ContentSource::Running,
                request.with_defaults,
                false,
            ),
            Self::Config(request) => {
                let source = match request.source {
                    Datastore::Running => ContentSource::Running,
                    Datastore::Candidate if binding.candidate_datastore_capability() => {
                        ContentSource::Candidate
                    }
                    Datastore::Startup if binding.startup_datastore_capability() => {
                        ContentSource::Startup
                    }
                    _ => return Err(RpcError::operation_not_supported()),
                };
                (ContentScope::Config, source, request.with_defaults, false)
            }
            Self::Data(request) => {
                if !binding.nmda_get_data_supported()
                    || request.max_depth_limited
                    || request.origin_filter_present
                    || (request.datastore == NmdaDatastore::Operational
                        && request.with_defaults.is_some())
                {
                    return Err(RpcError::operation_not_supported());
                }
                if request.with_origin {
                    return Err(if request.datastore == NmdaDatastore::Operational {
                        RpcError::operation_not_supported()
                    } else {
                        RpcError::invalid_value()
                    });
                }
                let source = match request.datastore {
                    NmdaDatastore::Running | NmdaDatastore::Operational => ContentSource::Running,
                    NmdaDatastore::Intended if binding.nmda_intended_equals_running() => {
                        ContentSource::Running
                    }
                    NmdaDatastore::Candidate if binding.candidate_datastore_capability() => {
                        ContentSource::Candidate
                    }
                    NmdaDatastore::Startup if binding.startup_datastore_capability() => {
                        ContentSource::Startup
                    }
                    _ => return Err(RpcError::invalid_value()),
                };
                let scope = if request.datastore == NmdaDatastore::Operational {
                    match request.config_filter {
                        Some(true) => ContentScope::Config,
                        Some(false) => ContentScope::State,
                        None => ContentScope::All,
                    }
                } else {
                    ContentScope::Config
                };
                (
                    scope,
                    source,
                    request.with_defaults,
                    request.datastore != NmdaDatastore::Operational
                        && request.config_filter == Some(false),
                )
            }
        };
        let capability = binding.with_defaults_capability();
        if defaults.is_some_and(|mode| !capability.as_ref().is_some_and(|cap| cap.supports(mode))) {
            return Err(RpcError::operation_not_supported());
        }
        let report = match defaults {
            None => binding.subtree_default_report(),
            Some(WithDefaultsMode::ReportAll) => DefaultReport::ReportAll,
            Some(WithDefaultsMode::ReportAllTagged) => DefaultReport::ReportAllTagged,
            Some(WithDefaultsMode::Trim) => DefaultReport::Trim,
            Some(WithDefaultsMode::Explicit) => DefaultReport::Explicit,
            Some(WithDefaultsMode::Unrecognized) => return Err(RpcError::operation_not_supported()),
        };
        Ok((scope, source, report, empty_scope))
    }
}

pub(crate) async fn handle<'a, C, B, P, A>(
    binding: &B,
    ctx: GetContext<'_, P, A>,
    request: ContentRequest<'_>,
    load: impl FnOnce(ContentSource) -> Result<ContentConfig<'a, C>, RpcError>,
    audit_mode: AuditMode,
) -> String
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
{
    handle_with_gate(binding, ctx, request, load, audit_mode, || {
        std::future::ready(None)
    })
    .await
}

/// Runs the authority gate only after schema and read authorization permit data
/// access. A gate rejection has already supplied its audit and complete reply.
pub(crate) async fn handle_with_gate<'a, C, B, P, A, F>(
    binding: &B,
    ctx: GetContext<'_, P, A>,
    request: ContentRequest<'_>,
    load: impl FnOnce(ContentSource) -> Result<ContentConfig<'a, C>, RpcError>,
    audit_mode: AuditMode,
    gate: impl FnOnce() -> F,
) -> String
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
    F: std::future::Future<Output = Option<String>>,
{
    let mut audit_paths = Vec::new();
    let result = match read(binding, &ctx, request, load, &mut audit_paths, gate).await {
        Ok(ReadResult::Reply(reply)) => return reply,
        Ok(ReadResult::Data(data)) => Ok(data),
        Err(error) => Err(error),
    };
    let outcome = match &result {
        Ok(_) => AuditOutcome::Success,
        Err(error) => match AuditOutcome::failed(error.classification.tag.as_str()) {
            Ok(outcome) => outcome,
            Err(_) => {
                return rpc_error_reply_with_attrs(
                    Some(ctx.message_id),
                    ctx.reply_attrs,
                    RpcError::operation_failed(),
                );
            }
        },
    };
    let event = AuditEvent::new(
        ctx.request_id,
        ctx.principal,
        ctx.transport,
        AuditOperation::Read,
        outcome,
    )
    .with_paths(audit_paths);
    let result = if record_audit(audit_mode, ctx.audit, &event).await.is_err() {
        Err(RpcError::operation_failed())
    } else {
        result
    };
    match result {
        Ok(xml) => {
            record_rpc_success(request.operation(), ctx.started.elapsed());
            rpc_ok_reply_with_attrs_and_data_ns(
                ctx.message_id,
                ctx.reply_attrs,
                request.data_namespace(),
                &xml,
            )
        }
        Err(error) => {
            record_rpc_error(
                request.operation(),
                error.classification.tag,
                ctx.started.elapsed(),
            );
            rpc_error_reply_with_attrs(Some(ctx.message_id), ctx.reply_attrs, error)
        }
    }
}

enum ReadResult {
    Data(String),
    Reply(String),
}

async fn read<'a, C, B, P, A, F>(
    binding: &B,
    ctx: &GetContext<'_, P, A>,
    request: ContentRequest<'_>,
    load: impl FnOnce(ContentSource) -> Result<ContentConfig<'a, C>, RpcError>,
    audit_paths: &mut Vec<SchemaNodePath>,
    gate: impl FnOnce() -> F,
) -> Result<ReadResult, RpcError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
    F: std::future::Future<Output = Option<String>>,
{
    let (scope, source, report, empty_scope) = request.parameters(binding)?;
    let filter = request
        .filter()
        .ok_or_else(RpcError::operation_not_supported)?;
    let registry = binding.schema_registry();
    let mut registries = vec![registry];
    if !matches!(scope, ContentScope::Config) {
        if binding.yang_library_capability().is_some() {
            registries.push(yang_library_registry());
        }
        if binding.netconf_monitoring_capability().is_some() {
            registries.push(netconf_monitoring_registry());
        }
    }
    let plan = compile_content(&registries, filter, scope, ctx.limits)
        .map_err(|error| error.rpc_error())?;
    ctx.limits
        .check_paths(plan.authorization_paths().len())
        .map_err(|_| RpcError::too_big())?;
    if empty_scope {
        return Ok(ReadResult::Data(String::new()));
    }
    if !binding.supports_subtree_content() {
        return Err(RpcError::operation_not_supported());
    }
    for path in plan.authorization_paths() {
        plan.budget()
            .charge(path.len().checked_add(1).ok_or_else(RpcError::too_big)?)
            .map_err(rpc_error)?;
        audit_paths.push(SchemaNodePath::new(*path).map_err(|_| RpcError::operation_failed())?);
    }
    let resolved = ctx
        .authz
        .policy_source()
        .active_policy_context_for_principal(ctx.principal)
        .map_err(|_| RpcError::resource_denied())?;
    let mut allowed = BTreeSet::new();
    for selected_registry in &registries {
        let mut paths = Vec::new();
        for path in plan.authorization_paths() {
            match plan.budget().node(*selected_registry, path) {
                Ok(_) => {
                    // The decision retains one schema path; never a predicate value.
                    plan.budget()
                        .charge(path.len().checked_add(1).ok_or_else(RpcError::too_big)?)
                        .map_err(rpc_error)?;
                    paths.push(*path);
                }
                Err(SubtreeError::Unsupported) => {}
                Err(error) => return Err(rpc_error(error)),
            }
        }
        if paths.is_empty() {
            continue;
        }
        let decisions = if std::ptr::eq(*selected_registry, ctx.authz.registry()) {
            ctx.authz
                .authorize_resolved(&resolved, ReadAction::Read, &paths)
        } else {
            ReadAuthorizer::new(*selected_registry, ctx.authz.policy_source())
                .map_err(|_| RpcError::operation_failed())?
                .authorize_resolved(&resolved, ReadAction::Read, &paths)
        };
        let denied = decisions
            .iter()
            .filter(|decision| !decision.allowed)
            .count();
        record_nacm_denials(NetconfNacmAction::Read, denied);
        for (path, decision) in paths.into_iter().zip(decisions) {
            plan.budget().charge(1).map_err(rpc_error)?;
            if decision.allowed {
                plan.budget().charge(1).map_err(rpc_error)?;
                allowed.insert(path);
            }
        }
    }
    let plan = plan
        .authorize(
            |path| allowed.contains(path),
            ctx.limits.max_subtree_filter_nodes,
        )
        .map_err(rpc_error)?;
    if plan.is_empty() {
        return Ok(ReadResult::Data(String::new()));
    }
    if let Some(reply) = gate().await {
        return Ok(ReadResult::Reply(reply));
    }
    let config = if needs_config(&plan, registry, scope).map_err(rpc_error)? {
        plan.budget().charge(1).map_err(rpc_error)?;
        Some(load(source)?)
    } else {
        None
    };
    // Complete provider validation precedes matching and buffered projection.
    let mut input = state::read(binding, &plan, registry, ctx.limits).map_err(rpc_error)?;
    if let Some(config) = config {
        let mut configuration = binding
            .project_subtree_content(&config, ReadSelection::with_subtree_plan(&plan), report)
            .map_err(rpc_error)?;
        opc_mgmt_schema::subtree::merge_bounded(registry, &mut configuration, input, plan.budget())
            .map_err(rpc_error)?;
        input = configuration;
    }
    let selected = plan.evaluate(registry, &input).map_err(rpc_error)?;
    let mut xml = NetconfXmlRenderContext::new(registry, plan.paths(), report)
        .render_nodes(&selected)
        .map_err(|_| RpcError::operation_failed())?;
    for discovery_registry in registries.into_iter().skip(1) {
        if !has_registry_paths(&plan, discovery_registry).map_err(rpc_error)? {
            continue;
        }
        let selection = ReadSelection::with_subtree_plan(&plan);
        let input = if std::ptr::eq(discovery_registry, yang_library_registry()) {
            binding.project_yang_library_content(selection)
        } else {
            binding.project_netconf_monitoring_content(selection)
        }
        .map_err(rpc_error)?;
        let selected = plan
            .evaluate(discovery_registry, &input)
            .map_err(rpc_error)?;
        let fragment = NetconfXmlRenderContext::new(discovery_registry, plan.paths(), report)
            .render_nodes(&selected)
            .map_err(|_| RpcError::operation_failed())?;
        plan.budget().charge(fragment.len()).map_err(rpc_error)?;
        xml.push_str(&fragment);
    }
    Ok(ReadResult::Data(xml))
}

fn has_registry_paths(
    plan: &AuthorizedSubtreePlan,
    registry: &dyn SchemaRegistry,
) -> Result<bool, SubtreeError> {
    for path in plan.paths() {
        match plan.budget().node(registry, path) {
            Ok(_) => return Ok(true),
            Err(SubtreeError::Unsupported) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}

fn needs_config(
    plan: &AuthorizedSubtreePlan,
    registry: &dyn SchemaRegistry,
    scope: ContentScope,
) -> Result<bool, SubtreeError> {
    if matches!(scope, ContentScope::State) {
        return Ok(false);
    }
    if matches!(scope, ContentScope::Config) {
        return Ok(true);
    }
    plan.needs_configuration(registry)
}

pub(super) fn rpc_error(error: SubtreeError) -> RpcError {
    match error {
        SubtreeError::TooBig => RpcError::too_big(),
        SubtreeError::Unsupported => RpcError::operation_not_supported(),
        SubtreeError::Invalid | SubtreeError::Projection => RpcError::operation_failed(),
    }
}
