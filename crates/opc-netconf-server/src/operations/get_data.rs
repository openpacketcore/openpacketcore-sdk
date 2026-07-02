//! RFC 8526 `<get-data>` operation handling.

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
use crate::capabilities::NETCONF_NMDA_NS;
use crate::error::{
    rpc_error_reply_with_attrs, rpc_ok_reply_with_attrs_and_data_ns, RpcError, RpcReplyAttributes,
};
use crate::filter::{
    get_config_paths_with_limits, get_paths_with_discovery, netconf_monitoring_registry,
    yang_library_registry,
};
use crate::metrics::{
    record_nacm_denials, record_rpc_error, record_rpc_success, NetconfNacmAction, NetconfOperation,
};
use crate::xml::{GetDataRequest, NmdaDatastore, WithDefaultsMode};

/// Shared context for handling one `<get-data>` request.
pub struct GetDataContext<'a, C, P, A>
where
    C: OpcConfig,
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
    /// Snapshot of the server-owned candidate datastore for candidate reads.
    pub candidate_config: Option<&'a C>,
    /// Whether the binding explicitly advertised RFC 6241 `:candidate`.
    pub candidate_supported: bool,
    /// Snapshot loaded from the binding-owned startup datastore.
    pub startup_config: Option<&'a C>,
    /// Whether the binding explicitly advertised RFC 6241 `:startup`.
    pub startup_supported: bool,
}

/// Handles a parsed RFC 8526 `<get-data>` request.
pub fn handle_get_data<C, B, P, A>(
    binding: &B,
    ctx: GetDataContext<'_, C, P, A>,
    request: &GetDataRequest,
) -> String
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
{
    if !binding.nmda_get_data_supported() {
        return fail(
            &ctx,
            RpcError::operation_not_supported(),
            "operation-not-supported",
            Vec::new(),
        );
    }

    if request.max_depth_limited || request.origin_filter_present {
        return fail(
            &ctx,
            RpcError::operation_not_supported(),
            "operation-not-supported",
            Vec::new(),
        );
    }

    if request.with_origin && request.datastore != NmdaDatastore::Operational {
        return fail(&ctx, RpcError::invalid_value(), "invalid-value", Vec::new());
    }

    if request.with_origin {
        return fail(
            &ctx,
            RpcError::operation_not_supported(),
            "operation-not-supported",
            Vec::new(),
        );
    }

    if request.with_defaults.is_some_and(|mode| {
        mode == WithDefaultsMode::Unrecognized
            || !binding
                .with_defaults_capability()
                .is_some_and(|cap| cap.supports(mode))
    }) {
        return fail(
            &ctx,
            RpcError::operation_not_supported(),
            "operation-not-supported",
            Vec::new(),
        );
    }

    match request.datastore {
        NmdaDatastore::Running => {
            handle_config_datastore(binding, ctx, request, ConfigSource::Running)
        }
        NmdaDatastore::Candidate => {
            if !ctx.candidate_supported {
                return fail(&ctx, RpcError::invalid_value(), "invalid-value", Vec::new());
            }
            if ctx.candidate_config.is_none() {
                return fail(
                    &ctx,
                    RpcError::operation_failed(),
                    "operation-failed",
                    Vec::new(),
                );
            }
            handle_config_datastore(binding, ctx, request, ConfigSource::Candidate)
        }
        NmdaDatastore::Startup => {
            if !ctx.startup_supported {
                return fail(&ctx, RpcError::invalid_value(), "invalid-value", Vec::new());
            }
            if ctx.startup_config.is_none() {
                return fail(&ctx, RpcError::data_missing(), "data-missing", Vec::new());
            }
            handle_config_datastore(binding, ctx, request, ConfigSource::Startup)
        }
        NmdaDatastore::Intended => {
            if !binding.nmda_intended_equals_running() {
                return fail(&ctx, RpcError::invalid_value(), "invalid-value", Vec::new());
            }
            handle_config_datastore(binding, ctx, request, ConfigSource::Running)
        }
        NmdaDatastore::Operational => handle_operational_datastore(binding, ctx, request),
    }
}

#[derive(Debug, Clone, Copy)]
enum ConfigSource {
    Running,
    Candidate,
    Startup,
}

#[expect(
    clippy::expect_used,
    reason = "presence established by the datastore-support check in the same function"
)]
fn handle_config_datastore<C, B, P, A>(
    binding: &B,
    ctx: GetDataContext<'_, C, P, A>,
    request: &GetDataRequest,
    source: ConfigSource,
) -> String
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
{
    if request.config_filter == Some(false) {
        return success(&ctx, Vec::new(), "");
    }

    let registry = binding.schema_registry();
    let config_paths =
        match get_config_paths_with_limits(registry, request.filter.as_ref(), ctx.limits) {
            Ok(paths) => paths,
            Err(err) => return fail(&ctx, err.rpc_error(), err.audit_reason(), Vec::new()),
        };
    if ctx.limits.check_paths(config_paths.len()).is_err() {
        return fail(&ctx, RpcError::too_big(), "too-big", Vec::new());
    }
    if config_paths.is_empty() {
        return success(&ctx, Vec::new(), "");
    }

    let decisions = match ctx
        .authz
        .authorize(ctx.principal, ReadAction::Read, &config_paths)
    {
        Ok(decisions) => decisions,
        Err(_) => {
            return fail(
                &ctx,
                RpcError::resource_denied(),
                "resource-denied",
                schema_paths(&config_paths),
            )
        }
    };
    let denied_count = decisions
        .iter()
        .filter(|decision| !decision.allowed)
        .count();
    record_nacm_denials(NetconfNacmAction::Read, denied_count);
    let allowed_paths = decisions
        .iter()
        .zip(config_paths.iter().copied())
        .filter_map(|(decision, path)| decision.allowed.then_some(path))
        .collect::<Vec<_>>();
    if allowed_paths.is_empty() {
        return success(&ctx, Vec::new(), "");
    }

    let snapshot =
        matches!(source, ConfigSource::Running).then(|| binding.config_bus().current_snapshot());
    let config = match source {
        ConfigSource::Running => snapshot
            .as_ref()
            .expect("running snapshot is present")
            .config
            .as_ref(),
        ConfigSource::Candidate => ctx
            .candidate_config
            .expect("candidate support checked before rendering"),
        ConfigSource::Startup => ctx
            .startup_config
            .expect("startup support checked before rendering"),
    };
    let selection = ReadSelection::new(&allowed_paths);
    let rendered = match request.with_defaults {
        Some(mode) => binding.render_running_config_with_defaults(config, selection, mode),
        None => binding.render_running_config(config, selection),
    };

    match rendered {
        Ok(data_xml) => success(&ctx, schema_paths(&allowed_paths), &data_xml),
        Err(_) => fail(
            &ctx,
            RpcError::operation_failed(),
            "operation-failed",
            schema_paths(&allowed_paths),
        ),
    }
}

fn handle_operational_datastore<C, B, P, A>(
    binding: &B,
    ctx: GetDataContext<'_, C, P, A>,
    request: &GetDataRequest,
) -> String
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
{
    if request.with_defaults.is_some() {
        return fail(
            &ctx,
            RpcError::operation_not_supported(),
            "operation-not-supported",
            Vec::new(),
        );
    }

    let registry = binding.schema_registry();
    let selected_paths = match get_paths_with_discovery(
        registry,
        request.filter.as_ref(),
        binding.yang_library_capability().is_some(),
        binding.netconf_monitoring_capability().is_some(),
        ctx.limits,
    ) {
        Ok(paths) => paths,
        Err(err) => return fail(&ctx, err.rpc_error(), err.audit_reason(), Vec::new()),
    };
    let decisions =
        match ctx
            .authz
            .authorize(ctx.principal, ReadAction::Read, &selected_paths.data_paths)
        {
            Ok(decisions) => decisions,
            Err(_) => {
                return fail(
                    &ctx,
                    RpcError::resource_denied(),
                    "resource-denied",
                    schema_paths(&selected_paths.data_paths),
                )
            }
        };
    let allowed_paths = decisions
        .iter()
        .zip(selected_paths.data_paths.iter().copied())
        .filter_map(|(decision, path)| decision.allowed.then_some(path))
        .collect::<Vec<_>>();

    let allow_builtin_state = request.config_filter != Some(true);
    let yang_library_authz = if allow_builtin_state {
        match authorize_yang_library(
            ctx.authz.policy_source(),
            ctx.principal,
            &selected_paths.yang_library_paths,
        ) {
            Ok(decisions) => decisions,
            Err(()) => {
                return fail(
                    &ctx,
                    RpcError::resource_denied(),
                    "resource-denied",
                    schema_paths(&selected_paths.yang_library_paths),
                )
            }
        }
    } else {
        Vec::new()
    };
    let netconf_monitoring_authz = if allow_builtin_state {
        match authorize_netconf_monitoring(
            ctx.authz.policy_source(),
            ctx.principal,
            &selected_paths.netconf_monitoring_paths,
        ) {
            Ok(decisions) => decisions,
            Err(()) => {
                return fail(
                    &ctx,
                    RpcError::resource_denied(),
                    "resource-denied",
                    schema_paths(&selected_paths.netconf_monitoring_paths),
                )
            }
        }
    } else {
        Vec::new()
    };

    let denied_count = decisions
        .iter()
        .filter(|decision| !decision.allowed)
        .count()
        + yang_library_authz
            .iter()
            .filter(|decision| !decision.allowed)
            .count()
        + netconf_monitoring_authz
            .iter()
            .filter(|decision| !decision.allowed)
            .count();
    record_nacm_denials(NetconfNacmAction::Read, denied_count);

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

    let mut config_paths = allowed_paths
        .iter()
        .copied()
        .filter(|path| registry.node(path).is_some_and(|node| node.config))
        .collect::<Vec<_>>();
    let mut state_paths = allowed_paths
        .iter()
        .copied()
        .filter(|path| registry.node(path).is_some_and(|node| !node.config))
        .collect::<Vec<_>>();
    match request.config_filter {
        Some(true) => state_paths.clear(),
        Some(false) => config_paths.clear(),
        None => {}
    }

    let selected_path_count = config_paths
        .len()
        .saturating_add(state_paths.len())
        .saturating_add(allowed_yang_library_paths.len())
        .saturating_add(allowed_netconf_monitoring_paths.len());
    if ctx.limits.check_paths(selected_path_count).is_err() {
        return fail(&ctx, RpcError::too_big(), "too-big", Vec::new());
    }

    let operational = match read_operational(binding, &state_paths) {
        Ok(response) => response,
        Err(()) => {
            return fail(
                &ctx,
                RpcError::operation_failed(),
                "operation-failed",
                schema_paths(&allowed_paths),
            )
        }
    };
    let render_state_paths = state_paths_with_values(&state_paths, &operational);
    let render_config_paths = config_paths_for_render(registry, &config_paths, &render_state_paths);

    let rendered_data = if render_config_paths.is_empty() && render_state_paths.is_empty() {
        Ok(String::new())
    } else {
        let snapshot = binding.config_bus().current_snapshot();
        binding.render_get_data(
            snapshot.config.as_ref(),
            ReadSelection::new(&render_config_paths),
            &operational,
            ReadSelection::new(&render_state_paths),
        )
    };

    match rendered_data.and_then(|mut data_xml| {
        if !allowed_yang_library_paths.is_empty() {
            data_xml.push_str(
                &binding.render_yang_library(ReadSelection::new(&allowed_yang_library_paths))?,
            );
        }
        if !allowed_netconf_monitoring_paths.is_empty() {
            data_xml.push_str(&binding.render_netconf_monitoring(ReadSelection::new(
                &allowed_netconf_monitoring_paths,
            ))?);
        }
        Ok(data_xml)
    }) {
        Ok(data_xml) => success(
            &ctx,
            audit_paths(
                &allowed_paths,
                &allowed_yang_library_paths,
                &allowed_netconf_monitoring_paths,
            ),
            &data_xml,
        ),
        Err(_) => fail(
            &ctx,
            RpcError::operation_failed(),
            "operation-failed",
            audit_paths(
                &allowed_paths,
                &allowed_yang_library_paths,
                &allowed_netconf_monitoring_paths,
            ),
        ),
    }
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

fn success<C, P, A>(
    ctx: &GetDataContext<'_, C, P, A>,
    paths: Vec<SchemaNodePath>,
    data_xml: &str,
) -> String
where
    C: OpcConfig,
    P: PolicySource,
    A: AuditSink,
{
    if audit_success(
        ctx.audit,
        ctx.request_id,
        ctx.principal,
        ctx.transport,
        paths,
    )
    .is_err()
    {
        record_rpc_error(
            NetconfOperation::GetData,
            NetconfErrorTag::OperationFailed,
            ctx.started.elapsed(),
        );
        return error_reply(ctx, RpcError::operation_failed());
    }
    record_rpc_success(NetconfOperation::GetData, ctx.started.elapsed());
    rpc_ok_reply_with_attrs_and_data_ns(ctx.message_id, ctx.reply_attrs, NETCONF_NMDA_NS, data_xml)
}

fn fail<C, P, A>(
    ctx: &GetDataContext<'_, C, P, A>,
    error: RpcError,
    reason: &'static str,
    paths: Vec<SchemaNodePath>,
) -> String
where
    C: OpcConfig,
    P: PolicySource,
    A: AuditSink,
{
    if audit_failure(
        ctx.audit,
        ctx.request_id,
        ctx.principal,
        ctx.transport,
        reason,
        paths,
    )
    .is_err()
    {
        record_rpc_error(
            NetconfOperation::GetData,
            NetconfErrorTag::OperationFailed,
            ctx.started.elapsed(),
        );
        return error_reply(ctx, RpcError::operation_failed());
    }
    record_rpc_error(
        NetconfOperation::GetData,
        error.classification.tag,
        ctx.started.elapsed(),
    );
    error_reply(ctx, error)
}

fn error_reply<C, P, A>(ctx: &GetDataContext<'_, C, P, A>, error: RpcError) -> String
where
    C: OpcConfig,
    P: PolicySource,
    A: AuditSink,
{
    rpc_error_reply_with_attrs(Some(ctx.message_id), ctx.reply_attrs, error)
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
