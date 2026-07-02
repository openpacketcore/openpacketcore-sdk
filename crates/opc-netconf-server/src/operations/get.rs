//! `<get>` operation handling.

use opc_config_model::{OpcConfig, RequestId, TransportType, TrustedPrincipal, YangPath};
use opc_mgmt_audit::{
    AuditError, AuditEvent, AuditOperation, AuditOutcome, AuditSink, SchemaNodePath,
};
use opc_mgmt_authz::{PolicySource, ReadAction, ReadAuthorizer};
use opc_mgmt_errors::NetconfErrorTag;
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_opstate::{OperationalRequest, OperationalResponse};
use opc_mgmt_schema::{NodeKind, SchemaRegistry};

use crate::binding::{NetconfConfigBinding, ReadSelection};
use crate::error::{
    rpc_error_reply_with_attrs, rpc_ok_reply_with_attrs, RpcError, RpcReplyAttributes,
};
use crate::filter::{get_paths_with_discovery, netconf_monitoring_registry, yang_library_registry};
use crate::metrics::{
    record_nacm_denials, record_rpc_error, record_rpc_success, NetconfNacmAction, NetconfOperation,
};
use crate::xml::{GetRequest, WithDefaultsMode};

/// Shared context for handling one `<get>` request.
pub struct GetContext<'a, P, A>
where
    P: PolicySource,
    A: AuditSink,
{
    /// Read authorizer built from the generated schema registry.
    pub authz: &'a ReadAuthorizer<'static, P>,
    /// Audit sink.
    pub audit: &'a A,
    /// Northbound transport.
    pub transport: TransportType,
    /// Request correlation id.
    pub request_id: RequestId,
    /// Authenticated and mapped caller.
    pub principal: &'a TrustedPrincipal,
    /// NETCONF message id.
    pub message_id: &'a str,
    /// Extra request `<rpc>` attributes to copy onto `<rpc-reply>`.
    pub reply_attrs: &'a RpcReplyAttributes,
    /// RPC receive timestamp for latency metrics.
    pub started: std::time::Instant,
    /// Shared management-plane input and fanout limits.
    pub limits: &'a MgmtLimits,
}

/// Handles a parsed `<get>` request.
pub fn handle_get<C, B, P, A>(
    binding: &B,
    ctx: GetContext<'_, P, A>,
    request: &GetRequest,
) -> String
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
{
    let registry = binding.schema_registry();
    let yang_library_capability = binding.yang_library_capability();
    let monitoring_capability = binding.netconf_monitoring_capability();
    let with_defaults_mode = match request.with_defaults {
        Some(mode)
            if binding
                .with_defaults_capability()
                .is_some_and(|cap| cap.supports(mode)) =>
        {
            Some(mode)
        }
        Some(_) => {
            if audit_failure(
                ctx.audit,
                ctx.request_id,
                ctx.principal,
                ctx.transport,
                "operation-not-supported",
                Vec::new(),
            )
            .is_err()
            {
                record_rpc_error(
                    NetconfOperation::Get,
                    NetconfErrorTag::OperationFailed,
                    ctx.started.elapsed(),
                );
                return error_reply(&ctx, RpcError::operation_failed());
            }
            record_rpc_error(
                NetconfOperation::Get,
                NetconfErrorTag::OperationNotSupported,
                ctx.started.elapsed(),
            );
            tracing::debug!(
                operation = "get",
                error_tag = NetconfErrorTag::OperationNotSupported.as_str(),
                "NETCONF get rejected unsupported with-defaults parameter"
            );
            return error_reply(&ctx, RpcError::operation_not_supported());
        }
        None => None,
    };
    let selected_paths = match get_paths_with_discovery(
        registry,
        request.filter.as_ref(),
        yang_library_capability.is_some(),
        monitoring_capability.is_some(),
        ctx.limits,
    ) {
        Ok(paths) => paths,
        Err(err) => {
            let rpc_error = err.rpc_error();
            let error_tag = rpc_error.classification.tag;
            if audit_failure(
                ctx.audit,
                ctx.request_id,
                ctx.principal,
                ctx.transport,
                err.audit_reason(),
                Vec::new(),
            )
            .is_err()
            {
                record_rpc_error(
                    NetconfOperation::Get,
                    NetconfErrorTag::OperationFailed,
                    ctx.started.elapsed(),
                );
                return error_reply(&ctx, RpcError::operation_failed());
            }
            record_rpc_error(NetconfOperation::Get, error_tag, ctx.started.elapsed());
            tracing::debug!(
                operation = "get",
                error_tag = error_tag.as_str(),
                "NETCONF get rejected unsupported or invalid filter"
            );
            return error_reply(&ctx, rpc_error);
        }
    };
    let selected_path_count = selected_paths
        .data_paths
        .len()
        .saturating_add(selected_paths.yang_library_paths.len())
        .saturating_add(selected_paths.netconf_monitoring_paths.len());
    if ctx.limits.check_paths(selected_path_count).is_err() {
        if audit_failure(
            ctx.audit,
            ctx.request_id,
            ctx.principal,
            ctx.transport,
            "too-big",
            Vec::new(),
        )
        .is_err()
        {
            record_rpc_error(
                NetconfOperation::Get,
                NetconfErrorTag::OperationFailed,
                ctx.started.elapsed(),
            );
            return error_reply(&ctx, RpcError::operation_failed());
        }
        record_rpc_error(
            NetconfOperation::Get,
            NetconfErrorTag::TooBig,
            ctx.started.elapsed(),
        );
        tracing::debug!(
            operation = "get",
            error_tag = NetconfErrorTag::TooBig.as_str(),
            "NETCONF get rejected expanded path selection over limit"
        );
        return error_reply(&ctx, RpcError::too_big());
    }

    if selected_paths.data_paths.is_empty()
        && selected_paths.yang_library_paths.is_empty()
        && selected_paths.netconf_monitoring_paths.is_empty()
    {
        if audit_success(
            ctx.audit,
            ctx.request_id,
            ctx.principal,
            ctx.transport,
            Vec::new(),
        )
        .is_err()
        {
            record_rpc_error(
                NetconfOperation::Get,
                NetconfErrorTag::OperationFailed,
                ctx.started.elapsed(),
            );
            return error_reply(&ctx, RpcError::operation_failed());
        }
        record_rpc_success(NetconfOperation::Get, ctx.started.elapsed());
        tracing::debug!(operation = "get", "NETCONF get returned empty selection");
        return ok_reply(&ctx, "");
    }

    let decisions =
        match ctx
            .authz
            .authorize(ctx.principal, ReadAction::Read, &selected_paths.data_paths)
        {
            Ok(decisions) => decisions,
            Err(_) => {
                if audit_failure(
                    ctx.audit,
                    ctx.request_id,
                    ctx.principal,
                    ctx.transport,
                    "resource-denied",
                    schema_paths(&selected_paths.data_paths),
                )
                .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::Get,
                        NetconfErrorTag::OperationFailed,
                        ctx.started.elapsed(),
                    );
                    return error_reply(&ctx, RpcError::operation_failed());
                }
                record_rpc_error(
                    NetconfOperation::Get,
                    NetconfErrorTag::ResourceDenied,
                    ctx.started.elapsed(),
                );
                tracing::debug!(
                    operation = "get",
                    error_tag = NetconfErrorTag::ResourceDenied.as_str(),
                    "NETCONF get failed closed on policy source error"
                );
                return error_reply(&ctx, RpcError::resource_denied());
            }
        };

    let denied_count = decisions
        .iter()
        .filter(|decision| !decision.allowed)
        .count();

    let allowed_paths = decisions
        .iter()
        .zip(selected_paths.data_paths.iter().copied())
        .filter_map(|(decision, path)| decision.allowed.then_some(path))
        .collect::<Vec<_>>();

    let yang_library_authz = match authorize_yang_library(
        ctx.authz.policy_source(),
        ctx.principal,
        &selected_paths.yang_library_paths,
    ) {
        Ok(decisions) => decisions,
        Err(()) => {
            if audit_failure(
                ctx.audit,
                ctx.request_id,
                ctx.principal,
                ctx.transport,
                "resource-denied",
                schema_paths(&selected_paths.yang_library_paths),
            )
            .is_err()
            {
                record_rpc_error(
                    NetconfOperation::Get,
                    NetconfErrorTag::OperationFailed,
                    ctx.started.elapsed(),
                );
                return error_reply(&ctx, RpcError::operation_failed());
            }
            record_rpc_error(
                NetconfOperation::Get,
                NetconfErrorTag::ResourceDenied,
                ctx.started.elapsed(),
            );
            tracing::debug!(
                operation = "get",
                error_tag = NetconfErrorTag::ResourceDenied.as_str(),
                "NETCONF get failed closed on YANG Library authz setup"
            );
            return error_reply(&ctx, RpcError::resource_denied());
        }
    };

    let yang_library_denied = yang_library_authz
        .iter()
        .filter(|decision| !decision.allowed)
        .count();

    let netconf_monitoring_authz = match authorize_netconf_monitoring(
        ctx.authz.policy_source(),
        ctx.principal,
        &selected_paths.netconf_monitoring_paths,
    ) {
        Ok(decisions) => decisions,
        Err(()) => {
            if audit_failure(
                ctx.audit,
                ctx.request_id,
                ctx.principal,
                ctx.transport,
                "resource-denied",
                schema_paths(&selected_paths.netconf_monitoring_paths),
            )
            .is_err()
            {
                record_rpc_error(
                    NetconfOperation::Get,
                    NetconfErrorTag::OperationFailed,
                    ctx.started.elapsed(),
                );
                return error_reply(&ctx, RpcError::operation_failed());
            }
            record_rpc_error(
                NetconfOperation::Get,
                NetconfErrorTag::ResourceDenied,
                ctx.started.elapsed(),
            );
            tracing::debug!(
                operation = "get",
                error_tag = NetconfErrorTag::ResourceDenied.as_str(),
                "NETCONF get failed closed on monitoring authz setup"
            );
            return error_reply(&ctx, RpcError::resource_denied());
        }
    };

    let netconf_monitoring_denied = netconf_monitoring_authz
        .iter()
        .filter(|decision| !decision.allowed)
        .count();
    record_nacm_denials(
        NetconfNacmAction::Read,
        denied_count
            .saturating_add(yang_library_denied)
            .saturating_add(netconf_monitoring_denied),
    );

    let allowed_yang_library_paths = yang_library_authz
        .iter()
        .zip(selected_paths.yang_library_paths.iter().copied())
        .filter_map(|(decision, path)| decision.allowed.then_some(path))
        .collect::<Vec<_>>();

    let allowed_netconf_monitoring_paths = netconf_monitoring_authz
        .iter()
        .zip(selected_paths.netconf_monitoring_paths.iter().copied())
        .filter_map(|(decision, path)| decision.allowed.then_some(path))
        .collect::<Vec<_>>();

    let config_paths = allowed_paths
        .iter()
        .copied()
        .filter(|path| registry.node(path).is_some_and(|node| node.config))
        .collect::<Vec<_>>();
    let state_paths = allowed_paths
        .iter()
        .copied()
        .filter(|path| registry.node(path).is_some_and(|node| !node.config))
        .collect::<Vec<_>>();

    let operational = match read_operational(binding, &state_paths) {
        Ok(response) => response,
        Err(()) => {
            if audit_failure(
                ctx.audit,
                ctx.request_id,
                ctx.principal,
                ctx.transport,
                "operation-failed",
                schema_paths(&allowed_paths),
            )
            .is_err()
            {
                record_rpc_error(
                    NetconfOperation::Get,
                    NetconfErrorTag::OperationFailed,
                    ctx.started.elapsed(),
                );
                return error_reply(&ctx, RpcError::operation_failed());
            }
            record_rpc_error(
                NetconfOperation::Get,
                NetconfErrorTag::OperationFailed,
                ctx.started.elapsed(),
            );
            tracing::debug!(
                operation = "get",
                error_tag = NetconfErrorTag::OperationFailed.as_str(),
                "NETCONF get operational provider failed or returned unexpected paths"
            );
            return error_reply(&ctx, RpcError::operation_failed());
        }
    };

    let render_state_paths = state_paths_with_values(&state_paths, &operational);
    let render_config_paths = config_paths_for_render(registry, &config_paths, &render_state_paths);

    let rendered_data = if render_config_paths.is_empty() && render_state_paths.is_empty() {
        Ok(String::new())
    } else {
        let snapshot = binding.config_bus().current_snapshot();
        let config_selection = ReadSelection::new(&render_config_paths);
        let state_selection = ReadSelection::new(&render_state_paths);
        match with_defaults_mode {
            Some(mode) => binding.render_get_data_with_defaults(
                snapshot.config.as_ref(),
                config_selection,
                &operational,
                state_selection,
                mode,
            ),
            None => binding.render_get_data(
                snapshot.config.as_ref(),
                config_selection,
                &operational,
                state_selection,
            ),
        }
    };

    match rendered_data.and_then(|data_xml| {
        render_yang_library_if_selected(binding, &allowed_yang_library_paths, with_defaults_mode)
            .and_then(|yang_library_xml| {
                render_netconf_monitoring_if_selected(
                    binding,
                    &allowed_netconf_monitoring_paths,
                    with_defaults_mode,
                )
                .map(|monitoring_xml| {
                    let mut out = data_xml;
                    out.push_str(&yang_library_xml);
                    out.push_str(&monitoring_xml);
                    out
                })
            })
    }) {
        Ok(data_xml) => {
            if audit_success(
                ctx.audit,
                ctx.request_id,
                ctx.principal,
                ctx.transport,
                audit_paths(
                    &allowed_paths,
                    &allowed_yang_library_paths,
                    &allowed_netconf_monitoring_paths,
                ),
            )
            .is_err()
            {
                record_rpc_error(
                    NetconfOperation::Get,
                    NetconfErrorTag::OperationFailed,
                    ctx.started.elapsed(),
                );
                return error_reply(&ctx, RpcError::operation_failed());
            }
            record_rpc_success(NetconfOperation::Get, ctx.started.elapsed());
            tracing::debug!(operation = "get", "NETCONF get succeeded");
            ok_reply(&ctx, &data_xml)
        }
        Err(_) => {
            if audit_failure(
                ctx.audit,
                ctx.request_id,
                ctx.principal,
                ctx.transport,
                "operation-failed",
                audit_paths(
                    &allowed_paths,
                    &allowed_yang_library_paths,
                    &allowed_netconf_monitoring_paths,
                ),
            )
            .is_err()
            {
                record_rpc_error(
                    NetconfOperation::Get,
                    NetconfErrorTag::OperationFailed,
                    ctx.started.elapsed(),
                );
                return error_reply(&ctx, RpcError::operation_failed());
            }
            record_rpc_error(
                NetconfOperation::Get,
                NetconfErrorTag::OperationFailed,
                ctx.started.elapsed(),
            );
            tracing::debug!(
                operation = "get",
                error_tag = NetconfErrorTag::OperationFailed.as_str(),
                "NETCONF get XML projection failed"
            );
            error_reply(&ctx, RpcError::operation_failed())
        }
    }
}

fn error_reply<P, A>(ctx: &GetContext<'_, P, A>, error: RpcError) -> String
where
    P: PolicySource,
    A: AuditSink,
{
    rpc_error_reply_with_attrs(Some(ctx.message_id), ctx.reply_attrs, error)
}

fn ok_reply<P, A>(ctx: &GetContext<'_, P, A>, data_xml: &str) -> String
where
    P: PolicySource,
    A: AuditSink,
{
    rpc_ok_reply_with_attrs(ctx.message_id, ctx.reply_attrs, data_xml)
}

fn authorize_yang_library<P: PolicySource>(
    policy_source: &P,
    principal: &TrustedPrincipal,
    paths: &[&'static str],
) -> Result<Vec<opc_mgmt_authz::PathDecision>, ()> {
    authorize_builtin_registry(policy_source, principal, yang_library_registry(), paths)
}

fn authorize_netconf_monitoring<P: PolicySource>(
    policy_source: &P,
    principal: &TrustedPrincipal,
    paths: &[&'static str],
) -> Result<Vec<opc_mgmt_authz::PathDecision>, ()> {
    authorize_builtin_registry(
        policy_source,
        principal,
        netconf_monitoring_registry(),
        paths,
    )
}

fn authorize_builtin_registry<P: PolicySource>(
    policy_source: &P,
    principal: &TrustedPrincipal,
    registry: &'static dyn opc_mgmt_schema::SchemaRegistry,
    paths: &[&'static str],
) -> Result<Vec<opc_mgmt_authz::PathDecision>, ()> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let authz = ReadAuthorizer::new(registry, policy_source).map_err(|_| ())?;
    authz
        .authorize(principal, ReadAction::Read, paths)
        .map_err(|_| ())
}

fn render_yang_library_if_selected<C, B>(
    binding: &B,
    paths: &[&'static str],
    with_defaults_mode: Option<WithDefaultsMode>,
) -> Result<String, crate::binding::BindingError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
{
    if paths.is_empty() {
        return Ok(String::new());
    }
    let selection = ReadSelection::new(paths);
    match with_defaults_mode {
        Some(mode) => binding.render_yang_library_with_defaults(selection, mode),
        None => binding.render_yang_library(selection),
    }
}

fn render_netconf_monitoring_if_selected<C, B>(
    binding: &B,
    paths: &[&'static str],
    with_defaults_mode: Option<WithDefaultsMode>,
) -> Result<String, crate::binding::BindingError>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
{
    if paths.is_empty() {
        return Ok(String::new());
    }
    let selection = ReadSelection::new(paths);
    match with_defaults_mode {
        Some(mode) => binding.render_netconf_monitoring_with_defaults(selection, mode),
        None => binding.render_netconf_monitoring(selection),
    }
}

fn read_operational<C, B>(
    binding: &B,
    state_paths: &[&'static str],
) -> Result<OperationalResponse, ()>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
{
    if state_paths.is_empty() {
        return Ok(OperationalResponse::default());
    }

    let requested = state_paths
        .iter()
        .map(|path| YangPath::new(*path).map_err(|_| ()))
        .collect::<Result<Vec<_>, _>>()?;
    let request = OperationalRequest::new(requested);
    let response = binding.get_operational_state(&request).map_err(|_| ())?;
    response.validate_for_request(&request).map_err(|_| ())?;
    Ok(response)
}

fn state_paths_with_values(
    state_paths: &[&'static str],
    operational: &OperationalResponse,
) -> Vec<&'static str> {
    state_paths
        .iter()
        .copied()
        .filter(|path| {
            YangPath::new(*path)
                .ok()
                .is_some_and(|path| operational.value_for(&path).is_some())
        })
        .collect()
}

fn config_paths_for_render(
    registry: &'static dyn SchemaRegistry,
    config_paths: &[&'static str],
    render_state_paths: &[&'static str],
) -> Vec<&'static str> {
    if !render_state_paths.is_empty() || has_data_bearing_config_path(registry, config_paths) {
        config_paths.to_vec()
    } else {
        Vec::new()
    }
}

fn has_data_bearing_config_path(
    registry: &'static dyn SchemaRegistry,
    config_paths: &[&'static str],
) -> bool {
    config_paths.iter().any(|path| {
        registry.node(path).is_some_and(|node| {
            node.config
                && (node.presence || matches!(node.kind, NodeKind::Leaf | NodeKind::LeafList))
        })
    })
}

fn audit_success<A: AuditSink>(
    audit: &A,
    request_id: RequestId,
    principal: &TrustedPrincipal,
    transport: TransportType,
    paths: Vec<SchemaNodePath>,
) -> Result<(), AuditError> {
    audit.record(
        &AuditEvent::new(
            request_id,
            principal,
            transport,
            AuditOperation::Read,
            AuditOutcome::Success,
        )
        .with_paths(paths),
    )
}

#[expect(
    clippy::expect_used,
    reason = "static NETCONF audit reason codes are valid by construction"
)]
fn audit_failure<A: AuditSink>(
    audit: &A,
    request_id: RequestId,
    principal: &TrustedPrincipal,
    transport: TransportType,
    reason: &'static str,
    paths: Vec<SchemaNodePath>,
) -> Result<(), AuditError> {
    audit.record(
        &AuditEvent::new(
            request_id,
            principal,
            transport,
            AuditOperation::Read,
            AuditOutcome::failed(reason).expect("static NETCONF audit reason code"),
        )
        .with_paths(paths),
    )
}

#[expect(
    clippy::expect_used,
    reason = "static schema paths are valid by construction"
)]
fn schema_paths(paths: &[&'static str]) -> Vec<SchemaNodePath> {
    paths
        .iter()
        .map(|path| {
            SchemaNodePath::new(*path)
                .expect("registry schema paths must be valid audit schema-node paths")
        })
        .collect()
}

fn audit_paths(
    data_paths: &[&'static str],
    yang_library_paths: &[&'static str],
    netconf_monitoring_paths: &[&'static str],
) -> Vec<SchemaNodePath> {
    let mut paths = schema_paths(data_paths);
    paths.extend(schema_paths(yang_library_paths));
    paths.extend(schema_paths(netconf_monitoring_paths));
    paths
}
