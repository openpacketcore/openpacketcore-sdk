//! `<get-config>` operation handling.

use opc_config_model::{OpcConfig, RequestId, TransportType, TrustedPrincipal};
use opc_mgmt_audit::{
    AuditError, AuditEvent, AuditOperation, AuditOutcome, AuditSink, SchemaNodePath,
};
use opc_mgmt_authz::{PolicySource, ReadAction, ReadAuthorizer};
use opc_mgmt_errors::NetconfErrorTag;
use opc_mgmt_limits::MgmtLimits;

use crate::binding::{NetconfConfigBinding, ReadSelection};
use crate::error::{
    rpc_error_reply_with_attrs, rpc_ok_reply_with_attrs, RpcError, RpcReplyAttributes,
};
use crate::filter::get_config_paths_with_limits;
use crate::metrics::{
    record_nacm_denials, record_rpc_error, record_rpc_success, NetconfNacmAction, NetconfOperation,
};
use crate::xml::{Datastore, GetConfigRequest, WithDefaultsMode};

/// Shared context for handling one `<get-config>` request.
pub struct GetConfigContext<'a, C, P, A>
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
    /// Whether this binding explicitly advertised RFC 6241 `:candidate`.
    pub candidate_supported: bool,
    /// Snapshot loaded from the binding-owned startup datastore.
    pub startup_config: Option<&'a C>,
    /// Whether this binding explicitly advertised RFC 6241 `:startup`.
    pub startup_supported: bool,
}

/// Handles a parsed `<get-config>` request.
pub fn handle_get_config<C, B, P, A>(
    binding: &B,
    ctx: GetConfigContext<'_, C, P, A>,
    request: &GetConfigRequest,
) -> String
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
{
    if request.source == Datastore::Candidate
        && ctx.candidate_supported
        && ctx.candidate_config.is_none()
    {
        if audit_failure(
            ctx.audit,
            ctx.request_id,
            ctx.principal,
            ctx.transport,
            "operation-failed",
            Vec::new(),
        )
        .is_err()
        {
            record_rpc_error(
                NetconfOperation::GetConfig,
                NetconfErrorTag::OperationFailed,
                ctx.started.elapsed(),
            );
            return error_reply(&ctx, RpcError::operation_failed());
        }
        record_rpc_error(
            NetconfOperation::GetConfig,
            NetconfErrorTag::OperationFailed,
            ctx.started.elapsed(),
        );
        return error_reply(&ctx, RpcError::operation_failed());
    }

    if request.source == Datastore::Startup && ctx.startup_supported && ctx.startup_config.is_none()
    {
        if audit_failure(
            ctx.audit,
            ctx.request_id,
            ctx.principal,
            ctx.transport,
            "data-missing",
            Vec::new(),
        )
        .is_err()
        {
            record_rpc_error(
                NetconfOperation::GetConfig,
                NetconfErrorTag::OperationFailed,
                ctx.started.elapsed(),
            );
            return error_reply(&ctx, RpcError::operation_failed());
        }
        record_rpc_error(
            NetconfOperation::GetConfig,
            NetconfErrorTag::DataMissing,
            ctx.started.elapsed(),
        );
        return error_reply(&ctx, RpcError::data_missing());
    }

    if request.source != Datastore::Running
        && !(request.source == Datastore::Candidate && ctx.candidate_supported)
        && !(request.source == Datastore::Startup && ctx.startup_supported)
    {
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
                NetconfOperation::GetConfig,
                NetconfErrorTag::OperationFailed,
                ctx.started.elapsed(),
            );
            return error_reply(&ctx, RpcError::operation_failed());
        }
        record_rpc_error(
            NetconfOperation::GetConfig,
            NetconfErrorTag::OperationNotSupported,
            ctx.started.elapsed(),
        );
        tracing::debug!(
            operation = "get-config",
            error_tag = NetconfErrorTag::OperationNotSupported.as_str(),
            "NETCONF get-config rejected unsupported source datastore"
        );
        return error_reply(&ctx, RpcError::operation_not_supported());
    }

    let with_defaults_mode: Option<WithDefaultsMode> = match request.with_defaults {
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
                    NetconfOperation::GetConfig,
                    NetconfErrorTag::OperationFailed,
                    ctx.started.elapsed(),
                );
                return error_reply(&ctx, RpcError::operation_failed());
            }
            record_rpc_error(
                NetconfOperation::GetConfig,
                NetconfErrorTag::OperationNotSupported,
                ctx.started.elapsed(),
            );
            tracing::debug!(
                operation = "get-config",
                error_tag = NetconfErrorTag::OperationNotSupported.as_str(),
                "NETCONF get-config rejected unsupported with-defaults parameter"
            );
            return error_reply(&ctx, RpcError::operation_not_supported());
        }
        None => None,
    };

    let registry = binding.schema_registry();
    let config_paths =
        match get_config_paths_with_limits(registry, request.filter.as_ref(), ctx.limits) {
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
                        NetconfOperation::GetConfig,
                        NetconfErrorTag::OperationFailed,
                        ctx.started.elapsed(),
                    );
                    return error_reply(&ctx, RpcError::operation_failed());
                }
                record_rpc_error(
                    NetconfOperation::GetConfig,
                    error_tag,
                    ctx.started.elapsed(),
                );
                tracing::debug!(
                    operation = "get-config",
                    error_tag = error_tag.as_str(),
                    "NETCONF get-config rejected unsupported or invalid filter"
                );
                return error_reply(&ctx, rpc_error);
            }
        };
    if ctx.limits.check_paths(config_paths.len()).is_err() {
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
                NetconfOperation::GetConfig,
                NetconfErrorTag::OperationFailed,
                ctx.started.elapsed(),
            );
            return error_reply(&ctx, RpcError::operation_failed());
        }
        record_rpc_error(
            NetconfOperation::GetConfig,
            NetconfErrorTag::TooBig,
            ctx.started.elapsed(),
        );
        tracing::debug!(
            operation = "get-config",
            error_tag = NetconfErrorTag::TooBig.as_str(),
            "NETCONF get-config rejected expanded path selection over limit"
        );
        return error_reply(&ctx, RpcError::too_big());
    }

    if config_paths.is_empty() {
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
                NetconfOperation::GetConfig,
                NetconfErrorTag::OperationFailed,
                ctx.started.elapsed(),
            );
            return error_reply(&ctx, RpcError::operation_failed());
        }
        record_rpc_success(NetconfOperation::GetConfig, ctx.started.elapsed());
        tracing::debug!(
            operation = "get-config",
            "NETCONF get-config returned empty selection"
        );
        return ok_reply(&ctx, "");
    }

    let decisions = match ctx
        .authz
        .authorize(ctx.principal, ReadAction::Read, &config_paths)
    {
        Ok(decisions) => decisions,
        Err(_) => {
            if audit_failure(
                ctx.audit,
                ctx.request_id,
                ctx.principal,
                ctx.transport,
                "resource-denied",
                schema_paths(&config_paths),
            )
            .is_err()
            {
                record_rpc_error(
                    NetconfOperation::GetConfig,
                    NetconfErrorTag::OperationFailed,
                    ctx.started.elapsed(),
                );
                return error_reply(&ctx, RpcError::operation_failed());
            }
            record_rpc_error(
                NetconfOperation::GetConfig,
                NetconfErrorTag::ResourceDenied,
                ctx.started.elapsed(),
            );
            tracing::debug!(
                operation = "get-config",
                error_tag = NetconfErrorTag::ResourceDenied.as_str(),
                "NETCONF get-config failed closed on policy source error"
            );
            return error_reply(&ctx, RpcError::resource_denied());
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
                NetconfOperation::GetConfig,
                NetconfErrorTag::OperationFailed,
                ctx.started.elapsed(),
            );
            return error_reply(&ctx, RpcError::operation_failed());
        }
        record_rpc_success(NetconfOperation::GetConfig, ctx.started.elapsed());
        tracing::debug!(
            operation = "get-config",
            "NETCONF get-config returned empty NACM-authorized selection"
        );
        return ok_reply(&ctx, "");
    }

    let snapshot =
        (request.source == Datastore::Running).then(|| binding.config_bus().current_snapshot());
    let config = match request.source {
        Datastore::Running => snapshot
            .as_ref()
            .expect("running get-config snapshot is present")
            .config
            .as_ref(),
        Datastore::Candidate => ctx
            .candidate_config
            .expect("candidate support checked before rendering"),
        Datastore::Startup => ctx
            .startup_config
            .expect("startup support checked before rendering"),
    };
    let selection = ReadSelection::new(&allowed_paths);
    let rendered = match with_defaults_mode {
        Some(mode) => binding.render_running_config_with_defaults(config, selection, mode),
        None => binding.render_running_config(config, selection),
    };

    match rendered {
        Ok(data_xml) => {
            if audit_success(
                ctx.audit,
                ctx.request_id,
                ctx.principal,
                ctx.transport,
                schema_paths(&allowed_paths),
            )
            .is_err()
            {
                record_rpc_error(
                    NetconfOperation::GetConfig,
                    NetconfErrorTag::OperationFailed,
                    ctx.started.elapsed(),
                );
                return error_reply(&ctx, RpcError::operation_failed());
            }
            record_rpc_success(NetconfOperation::GetConfig, ctx.started.elapsed());
            tracing::debug!(operation = "get-config", "NETCONF get-config succeeded");
            ok_reply(&ctx, &data_xml)
        }
        Err(_) => {
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
                    NetconfOperation::GetConfig,
                    NetconfErrorTag::OperationFailed,
                    ctx.started.elapsed(),
                );
                return error_reply(&ctx, RpcError::operation_failed());
            }
            record_rpc_error(
                NetconfOperation::GetConfig,
                NetconfErrorTag::OperationFailed,
                ctx.started.elapsed(),
            );
            tracing::debug!(
                operation = "get-config",
                error_tag = NetconfErrorTag::OperationFailed.as_str(),
                "NETCONF get-config XML projection failed"
            );
            error_reply(&ctx, RpcError::operation_failed())
        }
    }
}

fn error_reply<C, P, A>(ctx: &GetConfigContext<'_, C, P, A>, error: RpcError) -> String
where
    C: OpcConfig,
    P: PolicySource,
    A: AuditSink,
{
    rpc_error_reply_with_attrs(Some(ctx.message_id), ctx.reply_attrs, error)
}

fn ok_reply<C, P, A>(ctx: &GetConfigContext<'_, C, P, A>, data_xml: &str) -> String
where
    C: OpcConfig,
    P: PolicySource,
    A: AuditSink,
{
    rpc_ok_reply_with_attrs(ctx.message_id, ctx.reply_attrs, data_xml)
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

fn schema_paths(paths: &[&'static str]) -> Vec<SchemaNodePath> {
    paths
        .iter()
        .map(|path| {
            SchemaNodePath::new(*path)
                .expect("registry schema paths must be valid audit schema-node paths")
        })
        .collect()
}
