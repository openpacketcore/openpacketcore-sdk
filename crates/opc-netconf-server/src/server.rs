//! Read-only NETCONF server core.

use std::marker::PhantomData;
use std::time::Instant;

use opc_config_model::{OpcConfig, RequestId, TransportType, TrustedPrincipal};
use opc_mgmt_audit::{
    AuditError, AuditEvent, AuditOperation, AuditOutcome, AuditSink, SchemaNodePath,
};
use opc_mgmt_authz::{AuthzError, ExecAuthorizer, PolicySource, ReadAuthorizer};
use opc_mgmt_errors::{NetconfErrorTag, NetconfErrorType};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_schema::ModelData;
use thiserror::Error;

use crate::binding::{
    GetSchemaError, GetSchemaRequest as BindingGetSchemaRequest, NetconfConfigBinding,
};
use crate::capabilities::render_server_hello;
use crate::error::{
    rpc_error_reply_with_attrs, rpc_get_schema_reply_with_attrs, rpc_ok_empty_reply_with_attrs,
    RpcError, RpcReplyAttributes,
};
use crate::metrics::{record_rpc_error, record_rpc_success, NetconfOperation};
use crate::operations::get::{handle_get, GetContext};
use crate::operations::get_config::{handle_get_config, GetConfigContext};
use crate::xml::{
    parse_rpc_with_context, GetSchemaRequest as XmlGetSchemaRequest, RpcOperation,
    UnsupportedOperation, XmlError,
};

const NETCONF_BASE_MODEL: &[ModelData] = &[ModelData {
    name: "ietf-netconf",
    revision: "2011-06-01",
    namespace: "urn:ietf:params:xml:ns:netconf:base:1.0",
    prefix: "nc",
}];

const NETCONF_CLOSE_SESSION_PATH: &str = "/nc:close-session";

/// Server construction error.
#[derive(Debug, Error)]
pub enum ServerInitError {
    /// Schema registry self-check failed.
    #[error("schema registry failed self-check")]
    Registry,
    /// Read authorizer could not be constructed.
    #[error("read authorizer initialization failed: {0}")]
    Authz(#[from] AuthzError),
}

/// Result of handling one NETCONF RPC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RpcHandlingResult {
    /// XML `<rpc-reply>` to send to the client.
    pub reply_xml: String,
    /// Whether the session must close after the reply is written.
    pub close_session: bool,
}

impl RpcHandlingResult {
    fn keep_open(reply_xml: String) -> Self {
        Self {
            reply_xml,
            close_session: false,
        }
    }

    fn close(reply_xml: String) -> Self {
        Self {
            reply_xml,
            close_session: true,
        }
    }
}

/// Read-only NETCONF server core.
///
/// This type handles parsed XML RPC documents. It does not bind sockets or
/// perform the NETCONF `<hello>` handshake; transport/session code composes
/// those pieces around this core.
pub struct ReadOnlyNetconfServer<C, B, P, A>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
{
    binding: B,
    authz: ReadAuthorizer<'static, P>,
    audit: A,
    transport: TransportType,
    _config: PhantomData<C>,
}

impl<C, B, P, A> ReadOnlyNetconfServer<C, B, P, A>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
{
    /// Builds a read-only server core.
    pub fn new(
        binding: B,
        policy_source: P,
        audit: A,
        transport: TransportType,
    ) -> Result<Self, ServerInitError> {
        let registry = binding.schema_registry();
        registry
            .self_check()
            .map_err(|_| ServerInitError::Registry)?;
        let authz = ReadAuthorizer::new(registry, policy_source)?;
        Ok(Self {
            binding,
            authz,
            audit,
            transport,
            _config: PhantomData,
        })
    }

    /// Handles one complete XML RPC document and returns an XML `<rpc-reply>`.
    pub fn handle_rpc_xml(
        &self,
        request_id: RequestId,
        principal: &TrustedPrincipal,
        xml: &str,
        limits: &MgmtLimits,
    ) -> String {
        self.handle_rpc(request_id, principal, xml, limits)
            .reply_xml
    }

    /// Renders this server instance's `<hello>` capabilities.
    pub fn server_hello(&self, session_id: Option<u64>) -> String {
        let yang_library = self.binding.yang_library_capability();
        let monitoring = self.binding.netconf_monitoring_capability();
        let with_defaults = self.binding.with_defaults_capability();
        render_server_hello(
            session_id,
            yang_library.as_ref(),
            monitoring.as_ref(),
            with_defaults.as_ref(),
        )
    }

    /// Handles one complete XML RPC document and returns the reply plus any
    /// session-control action.
    pub fn handle_rpc(
        &self,
        request_id: RequestId,
        principal: &TrustedPrincipal,
        xml: &str,
        limits: &MgmtLimits,
    ) -> RpcHandlingResult {
        let started = Instant::now();
        let parsed = match parse_rpc_with_context(xml, limits) {
            Ok(parsed) => parsed,
            Err(err) => {
                let message_id = err.message_id.as_deref();
                if self
                    .audit_parse_failure(request_id, principal, &err.error)
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::Unknown,
                        NetconfErrorTag::OperationFailed,
                        started.elapsed(),
                    );
                    tracing::debug!(
                        operation = "unknown",
                        error_tag = NetconfErrorTag::OperationFailed.as_str(),
                        "NETCONF RPC rejected after audit failure"
                    );
                    return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                        message_id,
                        &err.reply_attrs,
                        RpcError::operation_failed(),
                    ));
                }
                let classification = err.error.classification();
                record_rpc_error(
                    NetconfOperation::Unknown,
                    classification.tag,
                    started.elapsed(),
                );
                tracing::debug!(
                    operation = "unknown",
                    error_type = classification.error_type.as_str(),
                    error_tag = classification.tag.as_str(),
                    "NETCONF RPC rejected during parse"
                );
                let rpc_error = RpcError::new(classification, err.error.client_message());
                return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    message_id,
                    &err.reply_attrs,
                    rpc_error,
                ));
            }
        };

        match &parsed.operation {
            RpcOperation::Get(request) => RpcHandlingResult::keep_open(handle_get::<C, B, P, A>(
                &self.binding,
                GetContext {
                    authz: &self.authz,
                    audit: &self.audit,
                    transport: self.transport,
                    request_id,
                    principal,
                    message_id: &parsed.message_id,
                    reply_attrs: &parsed.reply_attrs,
                    started,
                    limits,
                },
                request,
            )),
            RpcOperation::GetConfig(request) => {
                RpcHandlingResult::keep_open(handle_get_config::<C, B, P, A>(
                    &self.binding,
                    GetConfigContext {
                        authz: &self.authz,
                        audit: &self.audit,
                        transport: self.transport,
                        request_id,
                        principal,
                        message_id: &parsed.message_id,
                        reply_attrs: &parsed.reply_attrs,
                        started,
                        limits,
                    },
                    request,
                ))
            }
            RpcOperation::CloseSession => self.handle_close_session(
                request_id,
                principal,
                &parsed.message_id,
                &parsed.reply_attrs,
                started,
            ),
            RpcOperation::GetSchema(request) => self.handle_get_schema(
                request,
                request_id,
                principal,
                &parsed.message_id,
                &parsed.reply_attrs,
                started,
            ),
            RpcOperation::Unsupported(operation) => self.handle_unsupported_operation(
                *operation,
                request_id,
                principal,
                &parsed.message_id,
                &parsed.reply_attrs,
                started,
            ),
        }
    }

    fn handle_unsupported_operation(
        &self,
        operation: UnsupportedOperation,
        request_id: RequestId,
        principal: &TrustedPrincipal,
        message_id: &str,
        reply_attrs: &RpcReplyAttributes,
        started: Instant,
    ) -> RpcHandlingResult {
        let metric_operation = NetconfOperation::Unsupported(operation.as_str());
        if self
            .audit
            .record(&AuditEvent::new(
                request_id,
                principal,
                self.transport,
                audit_operation_for_unsupported(operation),
                audit_failed("operation-not-supported"),
            ))
            .is_err()
        {
            record_rpc_error(
                metric_operation,
                NetconfErrorTag::OperationFailed,
                started.elapsed(),
            );
            tracing::debug!(
                operation = operation.as_str(),
                error_tag = NetconfErrorTag::OperationFailed.as_str(),
                "NETCONF unsupported operation rejected after audit failure"
            );
            return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                Some(message_id),
                reply_attrs,
                RpcError::operation_failed(),
            ));
        }

        record_rpc_error(
            metric_operation,
            NetconfErrorTag::OperationNotSupported,
            started.elapsed(),
        );
        tracing::debug!(
            operation = operation.as_str(),
            error_tag = NetconfErrorTag::OperationNotSupported.as_str(),
            "NETCONF operation is recognized but not implemented in this slice"
        );
        RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
            Some(message_id),
            reply_attrs,
            RpcError::operation_not_supported(),
        ))
    }

    fn handle_close_session(
        &self,
        request_id: RequestId,
        principal: &TrustedPrincipal,
        message_id: &str,
        reply_attrs: &RpcReplyAttributes,
        started: Instant,
    ) -> RpcHandlingResult {
        let close_path = schema_node_path(NETCONF_CLOSE_SESSION_PATH);
        match self.authorize_exec(principal, NETCONF_CLOSE_SESSION_PATH) {
            Ok(true) => {}
            Ok(false) => {
                if self
                    .audit
                    .record(
                        &AuditEvent::new(
                            request_id,
                            principal,
                            self.transport,
                            AuditOperation::Exec,
                            audit_denied("access-denied"),
                        )
                        .with_paths([close_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::CloseSession,
                        NetconfErrorTag::OperationFailed,
                        started.elapsed(),
                    );
                    return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                        Some(message_id),
                        reply_attrs,
                        RpcError::operation_failed(),
                    ));
                }
                record_rpc_error(
                    NetconfOperation::CloseSession,
                    NetconfErrorTag::AccessDenied,
                    started.elapsed(),
                );
                tracing::debug!(
                    operation = "close-session",
                    error_tag = NetconfErrorTag::AccessDenied.as_str(),
                    "NETCONF close-session denied by exec NACM"
                );
                return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    Some(message_id),
                    reply_attrs,
                    RpcError::access_denied(),
                ));
            }
            Err(()) => {
                if self
                    .audit
                    .record(
                        &AuditEvent::new(
                            request_id,
                            principal,
                            self.transport,
                            AuditOperation::Exec,
                            audit_failed("resource-denied"),
                        )
                        .with_paths([close_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::CloseSession,
                        NetconfErrorTag::OperationFailed,
                        started.elapsed(),
                    );
                    return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                        Some(message_id),
                        reply_attrs,
                        RpcError::operation_failed(),
                    ));
                }
                record_rpc_error(
                    NetconfOperation::CloseSession,
                    NetconfErrorTag::ResourceDenied,
                    started.elapsed(),
                );
                tracing::debug!(
                    operation = "close-session",
                    error_tag = NetconfErrorTag::ResourceDenied.as_str(),
                    "NETCONF close-session failed closed on exec policy source error"
                );
                return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    Some(message_id),
                    reply_attrs,
                    RpcError::resource_denied(),
                ));
            }
        }

        if self
            .audit
            .record(
                &AuditEvent::new(
                    request_id,
                    principal,
                    self.transport,
                    AuditOperation::Exec,
                    AuditOutcome::Success,
                )
                .with_paths([close_path]),
            )
            .is_err()
        {
            record_rpc_error(
                NetconfOperation::CloseSession,
                NetconfErrorTag::OperationFailed,
                started.elapsed(),
            );
            tracing::debug!(
                operation = "close-session",
                error_tag = NetconfErrorTag::OperationFailed.as_str(),
                "NETCONF close-session rejected after audit failure"
            );
            return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                Some(message_id),
                reply_attrs,
                RpcError::operation_failed(),
            ));
        }

        record_rpc_success(NetconfOperation::CloseSession, started.elapsed());
        tracing::debug!(
            operation = "close-session",
            "NETCONF close-session succeeded"
        );
        RpcHandlingResult::close(rpc_ok_empty_reply_with_attrs(message_id, reply_attrs))
    }

    fn handle_get_schema(
        &self,
        request: &XmlGetSchemaRequest,
        request_id: RequestId,
        principal: &TrustedPrincipal,
        message_id: &str,
        reply_attrs: &RpcReplyAttributes,
        started: Instant,
    ) -> RpcHandlingResult {
        let schema_path = schema_node_path("/ncm:netconf-state/ncm:schemas/ncm:schema");
        if self.binding.netconf_monitoring_capability().is_none() {
            if self
                .audit
                .record(
                    &AuditEvent::new(
                        request_id,
                        principal,
                        self.transport,
                        AuditOperation::Read,
                        audit_failed("operation-not-supported"),
                    )
                    .with_paths([schema_path]),
                )
                .is_err()
            {
                record_rpc_error(
                    NetconfOperation::GetSchema,
                    NetconfErrorTag::OperationFailed,
                    started.elapsed(),
                );
                return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    Some(message_id),
                    reply_attrs,
                    RpcError::operation_failed(),
                ));
            }
            record_rpc_error(
                NetconfOperation::GetSchema,
                NetconfErrorTag::OperationNotSupported,
                started.elapsed(),
            );
            return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                Some(message_id),
                reply_attrs,
                RpcError::operation_not_supported(),
            ));
        }

        match self.authorize_get_schema(principal) {
            Ok(true) => {}
            Ok(false) => {
                if self
                    .audit
                    .record(
                        &AuditEvent::new(
                            request_id,
                            principal,
                            self.transport,
                            AuditOperation::Read,
                            audit_denied("access-denied"),
                        )
                        .with_paths([schema_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::GetSchema,
                        NetconfErrorTag::OperationFailed,
                        started.elapsed(),
                    );
                    return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                        Some(message_id),
                        reply_attrs,
                        RpcError::operation_failed(),
                    ));
                }
                record_rpc_error(
                    NetconfOperation::GetSchema,
                    NetconfErrorTag::AccessDenied,
                    started.elapsed(),
                );
                return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    Some(message_id),
                    reply_attrs,
                    RpcError::access_denied(),
                ));
            }
            Err(()) => {
                if self
                    .audit
                    .record(
                        &AuditEvent::new(
                            request_id,
                            principal,
                            self.transport,
                            AuditOperation::Read,
                            audit_failed("resource-denied"),
                        )
                        .with_paths([schema_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::GetSchema,
                        NetconfErrorTag::OperationFailed,
                        started.elapsed(),
                    );
                    return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                        Some(message_id),
                        reply_attrs,
                        RpcError::operation_failed(),
                    ));
                }
                record_rpc_error(
                    NetconfOperation::GetSchema,
                    NetconfErrorTag::ResourceDenied,
                    started.elapsed(),
                );
                return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    Some(message_id),
                    reply_attrs,
                    RpcError::resource_denied(),
                ));
            }
        }

        let binding_request = BindingGetSchemaRequest {
            identifier: request.identifier.clone(),
            version: request.version.clone(),
            format: request.format.clone(),
        };

        match self.binding.get_schema(&binding_request) {
            Ok(data_xml) => {
                if self
                    .audit
                    .record(
                        &AuditEvent::new(
                            request_id,
                            principal,
                            self.transport,
                            AuditOperation::Read,
                            AuditOutcome::Success,
                        )
                        .with_paths([schema_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::GetSchema,
                        NetconfErrorTag::OperationFailed,
                        started.elapsed(),
                    );
                    return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                        Some(message_id),
                        reply_attrs,
                        RpcError::operation_failed(),
                    ));
                }
                record_rpc_success(NetconfOperation::GetSchema, started.elapsed());
                RpcHandlingResult::keep_open(rpc_get_schema_reply_with_attrs(
                    message_id,
                    reply_attrs,
                    &data_xml,
                ))
            }
            Err(error) => {
                let (rpc_error, tag, reason) = match error {
                    GetSchemaError::NotFound => (
                        RpcError::invalid_value(),
                        NetconfErrorTag::InvalidValue,
                        "invalid-value",
                    ),
                    GetSchemaError::NotUnique => (
                        RpcError::operation_failed().with_app_tag("data-not-unique"),
                        NetconfErrorTag::OperationFailed,
                        "data-not-unique",
                    ),
                    GetSchemaError::Failed { .. } => (
                        RpcError::operation_failed(),
                        NetconfErrorTag::OperationFailed,
                        "operation-failed",
                    ),
                };
                if self
                    .audit
                    .record(
                        &AuditEvent::new(
                            request_id,
                            principal,
                            self.transport,
                            AuditOperation::Read,
                            audit_failed(reason),
                        )
                        .with_paths([schema_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::GetSchema,
                        NetconfErrorTag::OperationFailed,
                        started.elapsed(),
                    );
                    return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                        Some(message_id),
                        reply_attrs,
                        RpcError::operation_failed(),
                    ));
                }
                record_rpc_error(NetconfOperation::GetSchema, tag, started.elapsed());
                RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    Some(message_id),
                    reply_attrs,
                    rpc_error,
                ))
            }
        }
    }

    fn authorize_get_schema(&self, principal: &TrustedPrincipal) -> Result<bool, ()> {
        let authz = ReadAuthorizer::new(
            crate::filter::netconf_monitoring_registry(),
            self.authz.policy_source(),
        )
        .map_err(|_| ())?;
        authz
            .may(
                principal,
                opc_mgmt_authz::ReadAction::Read,
                "/ncm:netconf-state/ncm:schemas/ncm:schema",
            )
            .map_err(|_| ())
    }

    fn authorize_exec(&self, principal: &TrustedPrincipal, path: &str) -> Result<bool, ()> {
        let authz =
            ExecAuthorizer::new(NETCONF_BASE_MODEL, self.authz.policy_source()).map_err(|_| ())?;
        authz.may_exec(principal, path).map_err(|_| ())
    }

    fn audit_parse_failure(
        &self,
        request_id: RequestId,
        principal: &TrustedPrincipal,
        err: &XmlError,
    ) -> Result<(), AuditError> {
        let reason = match (err.classification().error_type, err.classification().tag) {
            (NetconfErrorType::Rpc, NetconfErrorTag::MalformedMessage) => "malformed-message",
            (_, NetconfErrorTag::UnknownNamespace) => "unknown-namespace",
            (_, NetconfErrorTag::MissingAttribute) => "missing-attribute",
            (_, NetconfErrorTag::MissingElement) => "missing-element",
            (_, NetconfErrorTag::TooBig) => "too-big",
            (_, NetconfErrorTag::OperationNotSupported) => "operation-not-supported",
            _ => "operation-failed",
        };
        self.audit.record(&AuditEvent::new(
            request_id,
            principal,
            self.transport,
            AuditOperation::Read,
            audit_failed(reason),
        ))
    }
}

fn audit_operation_for_unsupported(operation: UnsupportedOperation) -> AuditOperation {
    match operation {
        UnsupportedOperation::EditConfig => AuditOperation::Update,
        UnsupportedOperation::CopyConfig => AuditOperation::Replace,
        UnsupportedOperation::DeleteConfig => AuditOperation::Delete,
        UnsupportedOperation::Validate => AuditOperation::Validate,
        UnsupportedOperation::Lock
        | UnsupportedOperation::Unlock
        | UnsupportedOperation::KillSession
        | UnsupportedOperation::Commit
        | UnsupportedOperation::DiscardChanges => AuditOperation::Exec,
    }
}

fn schema_node_path(path: &'static str) -> SchemaNodePath {
    SchemaNodePath::new(path).expect("static NETCONF schema path")
}

fn audit_denied(reason: &'static str) -> AuditOutcome {
    AuditOutcome::denied(reason).expect("static NETCONF audit reason code")
}

fn audit_failed(reason: &'static str) -> AuditOutcome {
    AuditOutcome::failed(reason).expect("static NETCONF audit reason code")
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use opc_config_bus::{ConfigBus, MockManagedDatastore};
    use opc_config_model::{
        AuthStrength, ConfigError, OpcConfig, TransportType, TrustedPrincipal, ValidationContext,
        ValidationError, WorkloadIdentity, YangPath,
    };
    use opc_identity::{
        parse_certs_pem, parse_key_pem, IdentityState, SvidDocument, TrustBundle, TrustBundleSet,
        TrustDomain, WorkloadIdentity as IdentityWorkloadIdentity,
    };
    use opc_mgmt_audit::{AuditError, AuditEvent, AuditOperation, AuditOutcome, AuditSink};
    use opc_mgmt_authz::{AuthzError, PolicySource};
    use opc_mgmt_opstate::{
        OperationalError, OperationalRequest, OperationalResponse, OperationalValue,
    };
    use opc_mgmt_schema::{
        DataClass, LeafType, ModelData, NodeKind, NodeMeta, OriginEntry, SchemaRegistry,
    };
    use opc_mgmt_transport::TlsBootstrap;
    use opc_nacm::{
        ModuleRegistry, NacmAction, NacmPolicy, NacmRule, PolicyVersion, YangPathPattern,
    };
    use opc_redaction::metrics::METRICS;
    use opc_runtime::{
        Criticality, RestartPolicy, RuntimeMode, RuntimeProfile, ShutdownPolicy, ShutdownToken,
        Supervisor, TaskName,
    };
    use opc_tls::{PeerPolicy, TlsConfigBuilder};
    use opc_types::{SchemaDigest, TenantId, Timestamp};
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::watch;
    use tokio_rustls::rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    use super::*;
    use crate::binding::{
        BindingError, NetconfMonitoringCapability, ReadSelection, WithDefaultsCapability,
        YangLibraryCapability,
    };
    use crate::capabilities::{
        NETCONF_BASE_1_0, NETCONF_BASE_1_1, NETCONF_BASE_NS, NETCONF_MONITORING_NS,
        WITH_DEFAULTS_NS,
    };
    use crate::framing::base10;
    use crate::listener::{run_read_only_tls_listener, TlsListenerConfig};
    use crate::session::SessionConfig;
    use crate::supervision::{spawn_read_only_tls_listener, SupervisedTlsListenerConfig};
    use crate::xml::WithDefaultsMode;

    #[derive(Clone)]
    struct DemoConfig {
        hostname: String,
        secret: String,
    }

    impl OpcConfig for DemoConfig {
        type Delta = ();

        fn schema_digest(&self) -> SchemaDigest {
            SchemaDigest::from_bytes([1u8; 32])
        }

        fn diff(&self, _previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
            Ok(Vec::new())
        }

        fn changed_paths(
            &self,
            _previous: &Self,
            _deltas: &[Self::Delta],
        ) -> Result<Vec<YangPath>, ConfigError> {
            Ok(Vec::new())
        }

        fn apply_delta(&mut self, _delta: Self::Delta) -> Result<(), ConfigError> {
            Ok(())
        }

        fn validate_syntax(&self) -> Result<(), ValidationError> {
            Ok(())
        }

        fn validate_semantics(
            &self,
            _ctx: &ValidationContext<Self>,
        ) -> Result<(), ValidationError> {
            Ok(())
        }
    }

    struct TestRegistry;

    static MODELS: &[ModelData] = &[ModelData {
        name: "demo-system",
        revision: "2026-06-13",
        namespace: "urn:opc:demo",
        prefix: "sys",
    }];

    static ORIGINS: &[OriginEntry] = &[OriginEntry {
        origin: "",
        modules: &["demo-system"],
    }];

    static NODES: &[NodeMeta] = &[
        NodeMeta {
            path: "/sys:system",
            module: "demo-system",
            kind: NodeKind::Container,
            config: true,
            leaf_type: None,
            key_leaves: &[],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[
                "/sys:system/sys:hostname",
                "/sys:system/sys:secret",
                "/sys:system/sys:uptime",
            ],
        },
        NodeMeta {
            path: "/sys:system/sys:hostname",
            module: "demo-system",
            kind: NodeKind::Leaf,
            config: true,
            leaf_type: Some(LeafType::String),
            key_leaves: &[],
            data_class: DataClass::Public,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[],
        },
        NodeMeta {
            path: "/sys:system/sys:secret",
            module: "demo-system",
            kind: NodeKind::Leaf,
            config: true,
            leaf_type: Some(LeafType::String),
            key_leaves: &[],
            data_class: DataClass::SecuritySecret,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[],
        },
        NodeMeta {
            path: "/sys:system/sys:uptime",
            module: "demo-system",
            kind: NodeKind::Leaf,
            config: false,
            leaf_type: Some(LeafType::Int64),
            key_leaves: &[],
            data_class: DataClass::Operational,
            default: None,
            has_default: false,
            presence: false,
            child_paths: &[],
        },
    ];

    impl SchemaRegistry for TestRegistry {
        fn schema_digest(&self) -> &'static str {
            "fnv1a64:test"
        }

        fn served_models(&self) -> &'static [ModelData] {
            MODELS
        }

        fn nodes(&self) -> &'static [NodeMeta] {
            NODES
        }

        fn origins(&self) -> &'static [OriginEntry] {
            ORIGINS
        }
    }

    static REGISTRY: TestRegistry = TestRegistry;

    struct TestBinding {
        bus: Arc<ConfigBus<DemoConfig>>,
        observed_paths: Arc<Mutex<Vec<Vec<&'static str>>>>,
        observed_yang_library_paths: Arc<Mutex<Vec<Vec<&'static str>>>>,
        observed_monitoring_paths: Arc<Mutex<Vec<Vec<&'static str>>>>,
        observed_with_defaults: Arc<Mutex<Vec<WithDefaultsMode>>>,
        operational_mode: OperationalMode,
        yang_library: bool,
        monitoring: bool,
        with_defaults: bool,
        get_schema_mode: GetSchemaMode,
    }

    impl TestBinding {
        fn observed_paths(&self) -> Arc<Mutex<Vec<Vec<&'static str>>>> {
            Arc::clone(&self.observed_paths)
        }

        fn observed_yang_library_paths(&self) -> Arc<Mutex<Vec<Vec<&'static str>>>> {
            Arc::clone(&self.observed_yang_library_paths)
        }

        fn observed_monitoring_paths(&self) -> Arc<Mutex<Vec<Vec<&'static str>>>> {
            Arc::clone(&self.observed_monitoring_paths)
        }

        fn observed_with_defaults(&self) -> Arc<Mutex<Vec<WithDefaultsMode>>> {
            Arc::clone(&self.observed_with_defaults)
        }
    }

    #[derive(Clone, Copy)]
    enum OperationalMode {
        Normal,
        NoValues,
        Error,
        UnexpectedPath,
        DuplicatePath,
        UnexpectedOrigin,
    }

    #[derive(Clone, Copy)]
    enum GetSchemaMode {
        Ok,
        NotFound,
        NotUnique,
        Failed,
    }

    impl NetconfConfigBinding<DemoConfig> for TestBinding {
        fn config_bus(&self) -> Arc<ConfigBus<DemoConfig>> {
            Arc::clone(&self.bus)
        }

        fn schema_registry(&self) -> &'static dyn SchemaRegistry {
            &REGISTRY
        }

        fn render_running_config(
            &self,
            config: &DemoConfig,
            selection: ReadSelection<'_>,
        ) -> Result<String, BindingError> {
            self.observed_paths
                .lock()
                .expect("observed paths mutex")
                .push(selection.schema_paths().to_vec());

            let mut out = String::from(r#"<sys:system xmlns:sys="urn:opc:demo">"#);
            if selection.contains("/sys:system/sys:hostname") {
                out.push_str("<sys:hostname>");
                out.push_str(&crate::xml_escape(&config.hostname));
                out.push_str("</sys:hostname>");
            }
            if selection.contains("/sys:system/sys:secret") {
                out.push_str("<sys:secret>");
                out.push_str(&crate::xml_escape(&config.secret));
                out.push_str("</sys:secret>");
            }
            out.push_str("</sys:system>");
            Ok(out)
        }

        fn with_defaults_capability(&self) -> Option<WithDefaultsCapability> {
            self.with_defaults.then(|| {
                WithDefaultsCapability::new(
                    WithDefaultsMode::ReportAll,
                    [
                        WithDefaultsMode::Trim,
                        WithDefaultsMode::Explicit,
                        WithDefaultsMode::ReportAllTagged,
                    ],
                )
                .expect("with-defaults capability")
            })
        }

        fn render_running_config_with_defaults(
            &self,
            config: &DemoConfig,
            selection: ReadSelection<'_>,
            mode: WithDefaultsMode,
        ) -> Result<String, BindingError> {
            self.observed_with_defaults
                .lock()
                .expect("with-defaults observed mutex")
                .push(mode);
            let data = self.render_running_config(config, selection)?;
            Ok(data.replace("amf-1", &format!("amf-1-{}", mode.as_str())))
        }

        fn get_operational_state(
            &self,
            request: &OperationalRequest,
        ) -> Result<OperationalResponse, OperationalError> {
            match self.operational_mode {
                OperationalMode::Normal => {}
                OperationalMode::NoValues => return Ok(OperationalResponse::default()),
                OperationalMode::Error => {
                    return Err(OperationalError::internal(
                        "backend leaked /sys:system/sys:secret",
                    ));
                }
                OperationalMode::UnexpectedPath => {
                    return Ok(OperationalResponse::new([OperationalValue::new(
                        YangPath::new("/sys:system/sys:unexpected").expect("unexpected path"),
                        "\"do-not-leak\"",
                    )
                    .expect("valid operational json")]));
                }
                OperationalMode::DuplicatePath => {
                    let uptime = YangPath::new("/sys:system/sys:uptime").expect("uptime path");
                    return Ok(OperationalResponse::new([
                        OperationalValue::new(uptime.clone(), "12345")
                            .expect("valid operational json"),
                        OperationalValue::new(uptime, "67890").expect("valid operational json"),
                    ]));
                }
                OperationalMode::UnexpectedOrigin => {
                    let uptime = YangPath::new("/sys:system/sys:uptime").expect("uptime path");
                    return Ok(OperationalResponse::new([OperationalValue::new(
                        uptime, "12345",
                    )
                    .expect("valid operational json")
                    .with_origin(Some(opc_mgmt_opstate::Origin::System))]));
                }
            }

            let mut values = Vec::new();
            for path in request.paths() {
                if path.as_str() == "/sys:system/sys:uptime" {
                    values.push(
                        OperationalValue::new(path.clone(), "12345")
                            .expect("valid operational json"),
                    );
                }
            }
            Ok(OperationalResponse::new(values))
        }

        fn render_get_data(
            &self,
            config: &DemoConfig,
            config_selection: ReadSelection<'_>,
            operational: &OperationalResponse,
            operational_selection: ReadSelection<'_>,
        ) -> Result<String, BindingError> {
            self.observed_paths
                .lock()
                .expect("observed paths mutex")
                .push(config_selection.schema_paths().to_vec());

            let mut out = String::from(r#"<sys:system xmlns:sys="urn:opc:demo">"#);
            if config_selection.contains("/sys:system/sys:hostname") {
                out.push_str("<sys:hostname>");
                out.push_str(&crate::xml_escape(&config.hostname));
                out.push_str("</sys:hostname>");
            }
            if config_selection.contains("/sys:system/sys:secret") {
                out.push_str("<sys:secret>");
                out.push_str(&crate::xml_escape(&config.secret));
                out.push_str("</sys:secret>");
            }
            if operational_selection.contains("/sys:system/sys:uptime") {
                let uptime_path = YangPath::new("/sys:system/sys:uptime").expect("uptime path");
                if let Some(value) = operational.value_for(&uptime_path) {
                    out.push_str("<sys:uptime>");
                    out.push_str(&crate::xml_escape(value.value_json()));
                    out.push_str("</sys:uptime>");
                }
            }
            out.push_str("</sys:system>");
            Ok(out)
        }

        fn render_get_data_with_defaults(
            &self,
            config: &DemoConfig,
            config_selection: ReadSelection<'_>,
            operational: &OperationalResponse,
            operational_selection: ReadSelection<'_>,
            mode: WithDefaultsMode,
        ) -> Result<String, BindingError> {
            self.observed_with_defaults
                .lock()
                .expect("with-defaults observed mutex")
                .push(mode);
            let data =
                self.render_get_data(config, config_selection, operational, operational_selection)?;
            Ok(data.replace("amf-1", &format!("amf-1-{}", mode.as_str())))
        }

        fn yang_library_capability(&self) -> Option<YangLibraryCapability> {
            self.yang_library
                .then(|| YangLibraryCapability::new("fnv1a64:test-schema").expect("content id"))
        }

        fn render_yang_library(
            &self,
            selection: ReadSelection<'_>,
        ) -> Result<String, BindingError> {
            self.observed_yang_library_paths
                .lock()
                .expect("yang-library observed paths mutex")
                .push(selection.schema_paths().to_vec());

            let mut out = String::from(
                r#"<yanglib:yang-library xmlns:yanglib="urn:ietf:params:xml:ns:yang:ietf-yang-library">"#,
            );
            if selection.contains("/yanglib:yang-library/yanglib:content-id") {
                out.push_str("<yanglib:content-id>fnv1a64:test-schema</yanglib:content-id>");
            }
            if selection.contains("/yanglib:yang-library/yanglib:module-set") {
                out.push_str("<yanglib:module-set><yanglib:name>running</yanglib:name>");
                if selection.contains("/yanglib:yang-library/yanglib:module-set/yanglib:module") {
                    out.push_str("<yanglib:module><yanglib:name>demo-system</yanglib:name><yanglib:revision>2026-06-13</yanglib:revision><yanglib:namespace>urn:opc:demo</yanglib:namespace></yanglib:module>");
                }
                out.push_str("</yanglib:module-set>");
            }
            out.push_str("</yanglib:yang-library>");
            Ok(out)
        }

        fn render_yang_library_with_defaults(
            &self,
            selection: ReadSelection<'_>,
            mode: WithDefaultsMode,
        ) -> Result<String, BindingError> {
            self.observed_with_defaults
                .lock()
                .expect("with-defaults observed mutex")
                .push(mode);
            self.render_yang_library(selection)
        }

        fn netconf_monitoring_capability(&self) -> Option<NetconfMonitoringCapability> {
            self.monitoring.then_some(NetconfMonitoringCapability)
        }

        fn render_netconf_monitoring(
            &self,
            selection: ReadSelection<'_>,
        ) -> Result<String, BindingError> {
            self.observed_monitoring_paths
                .lock()
                .expect("monitoring observed paths mutex")
                .push(selection.schema_paths().to_vec());

            let mut out = String::from(
                r#"<ncm:netconf-state xmlns:ncm="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">"#,
            );
            if selection.contains("/ncm:netconf-state/ncm:schemas") {
                out.push_str("<ncm:schemas>");
                if selection.contains("/ncm:netconf-state/ncm:schemas/ncm:schema") {
                    out.push_str("<ncm:schema>");
                    if selection
                        .contains("/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:identifier")
                    {
                        out.push_str("<ncm:identifier>demo-system</ncm:identifier>");
                    }
                    if selection.contains("/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:version") {
                        out.push_str("<ncm:version>2026-06-13</ncm:version>");
                    }
                    if selection.contains("/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:format") {
                        out.push_str("<ncm:format>yang</ncm:format>");
                    }
                    if selection.contains("/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:namespace")
                    {
                        out.push_str("<ncm:namespace>urn:opc:demo</ncm:namespace>");
                    }
                    if selection.contains("/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:location")
                    {
                        out.push_str("<ncm:location>NETCONF</ncm:location>");
                    }
                    out.push_str("</ncm:schema>");
                }
                out.push_str("</ncm:schemas>");
            }
            out.push_str("</ncm:netconf-state>");
            Ok(out)
        }

        fn render_netconf_monitoring_with_defaults(
            &self,
            selection: ReadSelection<'_>,
            mode: WithDefaultsMode,
        ) -> Result<String, BindingError> {
            self.observed_with_defaults
                .lock()
                .expect("with-defaults observed mutex")
                .push(mode);
            self.render_netconf_monitoring(selection)
        }

        fn get_schema(&self, request: &BindingGetSchemaRequest) -> Result<String, GetSchemaError> {
            match self.get_schema_mode {
                GetSchemaMode::Ok => {
                    if request.identifier == "demo-system"
                        && request.version.as_deref() == Some("2026-06-13")
                        && request.format == "yang"
                    {
                        Ok(crate::xml_escape(
                            r#"module demo-system { namespace "urn:opc:demo"; prefix sys; }"#,
                        ))
                    } else {
                        Err(GetSchemaError::NotFound)
                    }
                }
                GetSchemaMode::NotFound => Err(GetSchemaError::NotFound),
                GetSchemaMode::NotUnique => Err(GetSchemaError::NotUnique),
                GetSchemaMode::Failed => Err(GetSchemaError::failed(
                    "schema backend leaked /sys:system/sys:secret",
                )),
            }
        }
    }

    struct AdvertisesDefaultsWithoutProjection {
        bus: Arc<ConfigBus<DemoConfig>>,
        observed_paths: Arc<Mutex<Vec<Vec<&'static str>>>>,
    }

    impl AdvertisesDefaultsWithoutProjection {
        fn observed_paths(&self) -> Arc<Mutex<Vec<Vec<&'static str>>>> {
            Arc::clone(&self.observed_paths)
        }
    }

    impl NetconfConfigBinding<DemoConfig> for AdvertisesDefaultsWithoutProjection {
        fn config_bus(&self) -> Arc<ConfigBus<DemoConfig>> {
            Arc::clone(&self.bus)
        }

        fn schema_registry(&self) -> &'static dyn SchemaRegistry {
            &REGISTRY
        }

        fn render_running_config(
            &self,
            config: &DemoConfig,
            selection: ReadSelection<'_>,
        ) -> Result<String, BindingError> {
            self.observed_paths
                .lock()
                .expect("observed paths mutex")
                .push(selection.schema_paths().to_vec());

            let mut out = String::from(r#"<sys:system xmlns:sys="urn:opc:demo">"#);
            if selection.contains("/sys:system/sys:hostname") {
                out.push_str("<sys:hostname>ordinary-renderer-");
                out.push_str(&crate::xml_escape(&config.hostname));
                out.push_str("</sys:hostname>");
            }
            out.push_str("</sys:system>");
            Ok(out)
        }

        fn with_defaults_capability(&self) -> Option<WithDefaultsCapability> {
            Some(
                WithDefaultsCapability::new(WithDefaultsMode::Trim, [])
                    .expect("with-defaults capability"),
            )
        }
    }

    #[derive(Clone, Copy)]
    enum AdvertisedDiscovery {
        YangLibrary,
        Monitoring,
    }

    struct AdvertisesDiscoveryWithoutProjection {
        bus: Arc<ConfigBus<DemoConfig>>,
        observed_paths: Arc<Mutex<Vec<Vec<&'static str>>>>,
        discovery: AdvertisedDiscovery,
    }

    impl AdvertisesDiscoveryWithoutProjection {
        fn observed_paths(&self) -> Arc<Mutex<Vec<Vec<&'static str>>>> {
            Arc::clone(&self.observed_paths)
        }
    }

    impl NetconfConfigBinding<DemoConfig> for AdvertisesDiscoveryWithoutProjection {
        fn config_bus(&self) -> Arc<ConfigBus<DemoConfig>> {
            Arc::clone(&self.bus)
        }

        fn schema_registry(&self) -> &'static dyn SchemaRegistry {
            &REGISTRY
        }

        fn render_running_config(
            &self,
            config: &DemoConfig,
            selection: ReadSelection<'_>,
        ) -> Result<String, BindingError> {
            self.observed_paths
                .lock()
                .expect("observed paths mutex")
                .push(selection.schema_paths().to_vec());

            let mut out = String::from(r#"<sys:system xmlns:sys="urn:opc:demo">"#);
            if selection.contains("/sys:system/sys:hostname") {
                out.push_str("<sys:hostname>ordinary-renderer-");
                out.push_str(&crate::xml_escape(&config.hostname));
                out.push_str("</sys:hostname>");
            }
            out.push_str("</sys:system>");
            Ok(out)
        }

        fn yang_library_capability(&self) -> Option<YangLibraryCapability> {
            matches!(self.discovery, AdvertisedDiscovery::YangLibrary)
                .then(|| YangLibraryCapability::new("fnv1a64:test-schema").expect("content id"))
        }

        fn netconf_monitoring_capability(&self) -> Option<NetconfMonitoringCapability> {
            matches!(self.discovery, AdvertisedDiscovery::Monitoring)
                .then_some(NetconfMonitoringCapability)
        }
    }

    #[derive(Clone, Default)]
    struct CapturingAudit {
        events: Arc<Mutex<Vec<AuditEvent>>>,
    }

    impl AuditSink for CapturingAudit {
        fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
            self.events.lock().expect("audit mutex").push(event.clone());
            Ok(())
        }
    }

    #[derive(Clone, Copy)]
    struct FailingAudit;

    impl AuditSink for FailingAudit {
        fn record(&self, _event: &AuditEvent) -> Result<(), AuditError> {
            Err(AuditError::failed(
                "disk full while writing /sys:system/sys:user[sys:name='secret-admin']",
            ))
        }
    }

    struct FixedPolicy(NacmPolicy);

    impl PolicySource for FixedPolicy {
        fn active_policy(&self, _tenant: &str) -> Result<NacmPolicy, AuthzError> {
            Ok(self.0.clone())
        }
    }

    struct BrokenPolicySource;

    impl PolicySource for BrokenPolicySource {
        fn active_policy(&self, _tenant: &str) -> Result<NacmPolicy, AuthzError> {
            Err(AuthzError::PolicyUnavailable)
        }
    }

    fn principal() -> TrustedPrincipal {
        TrustedPrincipal::new(
            WorkloadIdentity::User("operator".to_string()),
            TenantId::new("tenant-a").expect("tenant"),
        )
        .with_auth_strength(AuthStrength::MutualTls)
    }

    fn peer_policy() -> PeerPolicy {
        PeerPolicy {
            allowed_trust_domains: Some(HashSet::from([
                TrustDomain::new("test-domain").expect("trust domain")
            ])),
            ..Default::default()
        }
    }

    fn identity_state(spiffe_id: &str) -> IdentityState {
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        let ca_key = KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");

        let mut leaf_params = CertificateParams::default();
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "NETCONF Workload");
        leaf_params.subject_alt_names.push(SanType::URI(
            rcgen::Ia5String::try_from(spiffe_id).expect("spiffe san"),
        ));
        let now = ::time::OffsetDateTime::now_utc();
        leaf_params.not_before = now - ::time::Duration::days(1);
        leaf_params.not_after = now + ::time::Duration::days(1);

        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_cert, &ca_key)
            .expect("leaf cert");

        let ca_certs = parse_certs_pem(&ca_cert.pem()).expect("ca pem");
        let cert_chain = parse_certs_pem(&(leaf_cert.pem() + &ca_cert.pem())).expect("leaf chain");

        let trust_domain = TrustDomain::new("test-domain").expect("trust domain");
        let mut trust_bundles = TrustBundleSet::new();
        trust_bundles.insert(TrustBundle {
            trust_domain,
            certificates: ca_certs,
        });

        let identity =
            IdentityWorkloadIdentity::from_cert_der(cert_chain[0].as_ref(), &trust_bundles)
                .expect("identity");
        let private_key = parse_key_pem(&leaf_key.serialize_pem()).expect("leaf key pem");
        let svid = SvidDocument {
            spiffe_id: identity.spiffe_id.clone(),
            cert_chain,
            private_key,
            expires_at: Timestamp::now_utc(),
        };

        IdentityState {
            identity,
            svid,
            trust_bundles,
        }
    }

    async fn read_base10_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Vec<u8> {
        let mut frame = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            reader.read_exact(&mut byte).await.expect("read frame byte");
            frame.push(byte[0]);
            if frame.ends_with(base10::END_MARKER) {
                return base10::decode_message(&frame, &MgmtLimits::default()).expect("decode");
            }
        }
    }

    fn register_netconf_module(modules: &mut ModuleRegistry) {
        modules
            .register_module("ietf-netconf", "nc")
            .expect("NETCONF module");
    }

    fn allow_close_session_rule(modules: &ModuleRegistry) -> NacmRule {
        NacmRule::allow(
            NacmAction::Exec,
            YangPathPattern::parse(NETCONF_CLOSE_SESSION_PATH, modules)
                .expect("allow close-session path"),
        )
    }

    fn policy_allow_system_but_deny_secret() -> NacmPolicy {
        let mut modules = ModuleRegistry::new();
        modules
            .register_module("demo-system", "sys")
            .expect("module");
        register_netconf_module(&mut modules);
        NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(NacmRule::deny(
                NacmAction::Read,
                YangPathPattern::parse("/sys:system/sys:secret", &modules).expect("deny path"),
            ))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/sys:system/**", &modules).expect("allow path"),
            ))
            .add_rule(allow_close_session_rule(&modules))
            .build()
    }

    fn policy_allow_system_and_yang_library_but_deny_secret() -> NacmPolicy {
        let mut modules = ModuleRegistry::new();
        modules
            .register_module("demo-system", "sys")
            .expect("demo module");
        register_netconf_module(&mut modules);
        modules
            .register_module(
                crate::filter::YANG_LIBRARY_MODULE,
                crate::filter::YANG_LIBRARY_PREFIX,
            )
            .expect("yang-library module");
        modules
            .register_module(
                crate::filter::NETCONF_MONITORING_MODULE,
                crate::filter::NETCONF_MONITORING_PREFIX,
            )
            .expect("monitoring module");
        NacmPolicy::builder(PolicyVersion::new(1))
            .add_rule(NacmRule::deny(
                NacmAction::Read,
                YangPathPattern::parse("/sys:system/sys:secret", &modules).expect("deny path"),
            ))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/sys:system/**", &modules).expect("allow system path"),
            ))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/yanglib:yang-library/**", &modules)
                    .expect("allow yang-library path"),
            ))
            .add_rule(NacmRule::allow(
                NacmAction::Read,
                YangPathPattern::parse("/ncm:netconf-state/**", &modules)
                    .expect("allow monitoring path"),
            ))
            .add_rule(allow_close_session_rule(&modules))
            .build()
    }

    async fn server_fixture() -> (
        ReadOnlyNetconfServer<DemoConfig, TestBinding, FixedPolicy, CapturingAudit>,
        Arc<Mutex<Vec<Vec<&'static str>>>>,
        CapturingAudit,
    ) {
        server_fixture_with_operational_mode(OperationalMode::Normal).await
    }

    async fn server_fixture_with_operational_mode(
        operational_mode: OperationalMode,
    ) -> (
        ReadOnlyNetconfServer<DemoConfig, TestBinding, FixedPolicy, CapturingAudit>,
        Arc<Mutex<Vec<Vec<&'static str>>>>,
        CapturingAudit,
    ) {
        let bus = Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "amf-1".to_string(),
                    secret: "do-not-leak".to_string(),
                },
                MockManagedDatastore::new(),
            )
            .await
            .expect("bus"),
        );
        let binding = TestBinding {
            bus,
            observed_paths: Arc::new(Mutex::new(Vec::new())),
            observed_yang_library_paths: Arc::new(Mutex::new(Vec::new())),
            observed_monitoring_paths: Arc::new(Mutex::new(Vec::new())),
            observed_with_defaults: Arc::new(Mutex::new(Vec::new())),
            operational_mode,
            yang_library: false,
            monitoring: false,
            with_defaults: false,
            get_schema_mode: GetSchemaMode::Ok,
        };
        let observed = binding.observed_paths();
        let audit = CapturingAudit::default();
        let server = ReadOnlyNetconfServer::new(
            binding,
            FixedPolicy(policy_allow_system_but_deny_secret()),
            audit.clone(),
            TransportType::NetconfTls,
        )
        .expect("server");
        (server, observed, audit)
    }

    async fn server_fixture_with_yang_library() -> (
        ReadOnlyNetconfServer<DemoConfig, TestBinding, FixedPolicy, CapturingAudit>,
        Arc<Mutex<Vec<Vec<&'static str>>>>,
        Arc<Mutex<Vec<Vec<&'static str>>>>,
        CapturingAudit,
    ) {
        let bus = Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "amf-1".to_string(),
                    secret: "do-not-leak".to_string(),
                },
                MockManagedDatastore::new(),
            )
            .await
            .expect("bus"),
        );
        let binding = TestBinding {
            bus,
            observed_paths: Arc::new(Mutex::new(Vec::new())),
            observed_yang_library_paths: Arc::new(Mutex::new(Vec::new())),
            observed_monitoring_paths: Arc::new(Mutex::new(Vec::new())),
            observed_with_defaults: Arc::new(Mutex::new(Vec::new())),
            operational_mode: OperationalMode::Normal,
            yang_library: true,
            monitoring: false,
            with_defaults: false,
            get_schema_mode: GetSchemaMode::Ok,
        };
        let observed = binding.observed_paths();
        let observed_yang_library = binding.observed_yang_library_paths();
        let audit = CapturingAudit::default();
        let server = ReadOnlyNetconfServer::new(
            binding,
            FixedPolicy(policy_allow_system_and_yang_library_but_deny_secret()),
            audit.clone(),
            TransportType::NetconfTls,
        )
        .expect("server");
        (server, observed, observed_yang_library, audit)
    }

    async fn server_fixture_with_monitoring(
        policy: NacmPolicy,
        get_schema_mode: GetSchemaMode,
    ) -> (
        ReadOnlyNetconfServer<DemoConfig, TestBinding, FixedPolicy, CapturingAudit>,
        Arc<Mutex<Vec<Vec<&'static str>>>>,
        Arc<Mutex<Vec<Vec<&'static str>>>>,
        CapturingAudit,
    ) {
        let bus = Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "amf-1".to_string(),
                    secret: "do-not-leak".to_string(),
                },
                MockManagedDatastore::new(),
            )
            .await
            .expect("bus"),
        );
        let binding = TestBinding {
            bus,
            observed_paths: Arc::new(Mutex::new(Vec::new())),
            observed_yang_library_paths: Arc::new(Mutex::new(Vec::new())),
            observed_monitoring_paths: Arc::new(Mutex::new(Vec::new())),
            observed_with_defaults: Arc::new(Mutex::new(Vec::new())),
            operational_mode: OperationalMode::Normal,
            yang_library: false,
            monitoring: true,
            with_defaults: false,
            get_schema_mode,
        };
        let observed = binding.observed_paths();
        let observed_monitoring = binding.observed_monitoring_paths();
        let audit = CapturingAudit::default();
        let server = ReadOnlyNetconfServer::new(
            binding,
            FixedPolicy(policy),
            audit.clone(),
            TransportType::NetconfTls,
        )
        .expect("server");
        (server, observed, observed_monitoring, audit)
    }

    async fn server_fixture_with_defaults() -> (
        ReadOnlyNetconfServer<DemoConfig, TestBinding, FixedPolicy, CapturingAudit>,
        Arc<Mutex<Vec<Vec<&'static str>>>>,
        Arc<Mutex<Vec<WithDefaultsMode>>>,
        CapturingAudit,
    ) {
        let bus = Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "amf-1".to_string(),
                    secret: "do-not-leak".to_string(),
                },
                MockManagedDatastore::new(),
            )
            .await
            .expect("bus"),
        );
        let binding = TestBinding {
            bus,
            observed_paths: Arc::new(Mutex::new(Vec::new())),
            observed_yang_library_paths: Arc::new(Mutex::new(Vec::new())),
            observed_monitoring_paths: Arc::new(Mutex::new(Vec::new())),
            observed_with_defaults: Arc::new(Mutex::new(Vec::new())),
            operational_mode: OperationalMode::Normal,
            yang_library: false,
            monitoring: false,
            with_defaults: true,
            get_schema_mode: GetSchemaMode::Ok,
        };
        let observed = binding.observed_paths();
        let observed_with_defaults = binding.observed_with_defaults();
        let audit = CapturingAudit::default();
        let server = ReadOnlyNetconfServer::new(
            binding,
            FixedPolicy(policy_allow_system_but_deny_secret()),
            audit.clone(),
            TransportType::NetconfTls,
        )
        .expect("server");
        (server, observed, observed_with_defaults, audit)
    }

    async fn server_fixture_with_advertised_defaults_but_no_projection() -> (
        ReadOnlyNetconfServer<
            DemoConfig,
            AdvertisesDefaultsWithoutProjection,
            FixedPolicy,
            CapturingAudit,
        >,
        Arc<Mutex<Vec<Vec<&'static str>>>>,
        CapturingAudit,
    ) {
        let bus = Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "amf-1".to_string(),
                    secret: "do-not-leak".to_string(),
                },
                MockManagedDatastore::new(),
            )
            .await
            .expect("bus"),
        );
        let binding = AdvertisesDefaultsWithoutProjection {
            bus,
            observed_paths: Arc::new(Mutex::new(Vec::new())),
        };
        let observed = binding.observed_paths();
        let audit = CapturingAudit::default();
        let server = ReadOnlyNetconfServer::new(
            binding,
            FixedPolicy(policy_allow_system_but_deny_secret()),
            audit.clone(),
            TransportType::NetconfTls,
        )
        .expect("server");
        (server, observed, audit)
    }

    async fn server_fixture_with_advertised_discovery_but_no_projection(
        discovery: AdvertisedDiscovery,
    ) -> (
        ReadOnlyNetconfServer<
            DemoConfig,
            AdvertisesDiscoveryWithoutProjection,
            FixedPolicy,
            CapturingAudit,
        >,
        Arc<Mutex<Vec<Vec<&'static str>>>>,
        CapturingAudit,
    ) {
        let bus = Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "amf-1".to_string(),
                    secret: "do-not-leak".to_string(),
                },
                MockManagedDatastore::new(),
            )
            .await
            .expect("bus"),
        );
        let binding = AdvertisesDiscoveryWithoutProjection {
            bus,
            observed_paths: Arc::new(Mutex::new(Vec::new())),
            discovery,
        };
        let observed = binding.observed_paths();
        let audit = CapturingAudit::default();
        let server = ReadOnlyNetconfServer::new(
            binding,
            FixedPolicy(policy_allow_system_and_yang_library_but_deny_secret()),
            audit.clone(),
            TransportType::NetconfTls,
        )
        .expect("server");
        (server, observed, audit)
    }

    fn get_config_rpc(source: &str) -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="101"><get-config><source><{source}/></source></get-config></rpc>"#
        )
    }

    fn get_rpc() -> String {
        format!(r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="201"><get/></rpc>"#)
    }

    fn get_config_with_defaults_rpc(mode: &str) -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="111"><get-config><source><running/></source><with-defaults xmlns="{WITH_DEFAULTS_NS}">{}</with-defaults></get-config></rpc>"#,
            crate::xml_escape(mode)
        )
    }

    fn get_with_defaults_rpc(mode: &str) -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="211"><get><with-defaults xmlns="{WITH_DEFAULTS_NS}">{}</with-defaults></get></rpc>"#,
            crate::xml_escape(mode)
        )
    }

    fn get_schema_rpc(identifier: &str, version: Option<&str>) -> String {
        let mut rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="501"><get-schema xmlns="{NETCONF_MONITORING_NS}"><identifier>{}</identifier>"#,
            crate::xml_escape(identifier)
        );
        if let Some(version) = version {
            rpc.push_str("<version>");
            rpc.push_str(&crate::xml_escape(version));
            rpc.push_str("</version>");
        }
        rpc.push_str("<format>yang</format></get-schema></rpc>");
        rpc
    }

    fn close_session_rpc() -> String {
        format!(r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="301"><close-session/></rpc>"#)
    }

    fn unsupported_edit_config_rpc() -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="401"><edit-config><target><running/></target><config><sys:secret xmlns:sys="urn:opc:demo">do-not-leak</sys:secret></config></edit-config></rpc>"#
        )
    }

    fn unsupported_edit_config_cdata_rpc() -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="402"><edit-config><config><![CDATA[do-not-leak]]></config></edit-config></rpc>"#
        )
    }

    #[tokio::test]
    async fn get_config_running_reads_bus_authorizes_and_audits() {
        let (server, observed, audit) = server_fixture().await;
        let success_before = netconf_rpc_requests("get-config", "success");
        let nacm_before = netconf_nacm_denials("read");
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_config_rpc("running"),
            &MgmtLimits::default(),
        );

        assert!(reply.contains(r#"message-id="101""#));
        assert!(reply.contains("<sys:hostname>amf-1</sys:hostname>"));
        assert!(!reply.contains("do-not-leak"));
        assert!(!reply.contains("<sys:secret>"));

        let paths = observed.lock().expect("observed paths mutex");
        assert_eq!(
            paths.as_slice(),
            &[vec!["/sys:system", "/sys:system/sys:hostname"]]
        );

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert_eq!(events[0].transport, TransportType::NetconfTls);
        assert!(netconf_rpc_requests("get-config", "success") > success_before);
        assert!(netconf_nacm_denials("read") > nacm_before);
    }

    #[tokio::test]
    async fn rpc_reply_copies_extra_rpc_attributes_on_success_and_parse_error() {
        let (server, observed, _audit) = server_fixture().await;
        let success_rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" xmlns:trace="urn:trace" trace:id="req&amp;1" client-tag="cli" message-id="109"><get-config><source><running/></source></get-config></rpc>"#
        );
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &success_rpc,
            &MgmtLimits::default(),
        );
        assert!(reply.contains(r#"message-id="109""#));
        assert!(reply.contains(r#"xmlns:trace="urn:trace""#));
        assert!(reply.contains(r#"trace:id="req&amp;1""#));
        assert!(reply.contains(r#"client-tag="cli""#));
        assert!(reply.contains("<sys:hostname>amf-1</sys:hostname>"));
        assert!(!reply.contains("do-not-leak"));

        observed.lock().expect("observed paths mutex").clear();
        let error_rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" xmlns:trace="urn:trace" trace:id="err&amp;1" message-id="110"><get>do-not-leak</get></rpc>"#
        );
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &error_rpc,
            &MgmtLimits::default(),
        );
        assert!(reply.contains(r#"message-id="110""#));
        assert!(reply.contains(r#"xmlns:trace="urn:trace""#));
        assert!(reply.contains(r#"trace:id="err&amp;1""#));
        assert!(reply.contains("<error-tag>malformed-message</error-tag>"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());
    }

    #[tokio::test]
    async fn rpc_reply_with_copied_default_namespace_uses_prefixed_netconf_elements() {
        let (server, _observed, _audit) = server_fixture().await;
        let rpc = format!(
            r#"<nc:rpc xmlns:nc="{NETCONF_BASE_NS}" xmlns="urn:client:default" message-id="112"><nc:get-config><nc:source><nc:running/></nc:source></nc:get-config></nc:rpc>"#
        );

        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());

        assert!(reply.starts_with(&format!(
            r#"<nc1:rpc-reply xmlns:nc1="{NETCONF_BASE_NS}" message-id="112""#
        )));
        assert!(reply.contains(r#" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0""#));
        assert!(reply.contains(r#" xmlns="urn:client:default""#));
        assert!(reply.contains("<nc1:data>"));
        assert!(reply.contains("</nc1:data></nc1:rpc-reply>"));
        assert!(reply.contains("<sys:hostname>amf-1</sys:hostname>"));
        assert!(!reply.contains(r#"<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="112" xmlns="urn:client:default""#));
    }

    #[tokio::test]
    async fn get_config_expanded_selection_over_path_limit_is_too_big_without_projection() {
        let (server, observed, audit) = server_fixture().await;
        let limits = MgmtLimits {
            max_paths_per_request: 2,
            ..MgmtLimits::default()
        };

        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_config_rpc("running"),
            &limits,
        );

        assert!(reply.contains(r#"message-id="101""#));
        assert!(reply.contains("<error-tag>too-big</error-tag>"));
        assert!(!reply.contains("<sys:hostname>"));
        assert!(!reply.contains("<sys:secret>"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, audit_failed("too-big"));
        assert!(events[0].schema_paths.is_empty());
    }

    #[tokio::test]
    async fn get_config_all_denied_returns_empty_without_projection() {
        let bus = Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "amf-1".to_string(),
                    secret: "do-not-leak".to_string(),
                },
                MockManagedDatastore::new(),
            )
            .await
            .expect("bus"),
        );
        let binding = TestBinding {
            bus,
            observed_paths: Arc::new(Mutex::new(Vec::new())),
            observed_yang_library_paths: Arc::new(Mutex::new(Vec::new())),
            observed_monitoring_paths: Arc::new(Mutex::new(Vec::new())),
            observed_with_defaults: Arc::new(Mutex::new(Vec::new())),
            operational_mode: OperationalMode::Normal,
            yang_library: false,
            monitoring: false,
            with_defaults: false,
            get_schema_mode: GetSchemaMode::Ok,
        };
        let observed = binding.observed_paths();
        let audit = CapturingAudit::default();
        let server = ReadOnlyNetconfServer::new(
            binding,
            FixedPolicy(NacmPolicy::empty(PolicyVersion::new(99))),
            audit.clone(),
            TransportType::NetconfTls,
        )
        .expect("server");

        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_config_rpc("running"),
            &MgmtLimits::default(),
        );

        assert!(reply.contains(r#"message-id="101""#));
        assert!(reply.contains("<data/>"));
        assert!(!reply.contains("<sys:hostname>"));
        assert!(!reply.contains("<sys:secret>"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert!(events[0].schema_paths.is_empty());
    }

    #[tokio::test]
    async fn get_reads_running_config_and_operational_state() {
        let (server, observed, audit) = server_fixture().await;
        let success_before = netconf_rpc_requests("get", "success");
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_rpc(),
            &MgmtLimits::default(),
        );

        assert!(reply.contains(r#"message-id="201""#));
        assert!(reply.contains("<sys:hostname>amf-1</sys:hostname>"));
        assert!(reply.contains("<sys:uptime>12345</sys:uptime>"));
        assert!(!reply.contains("do-not-leak"));
        assert!(!reply.contains("<sys:secret>"));

        let paths = observed.lock().expect("observed paths mutex");
        assert_eq!(
            paths.as_slice(),
            &[vec!["/sys:system", "/sys:system/sys:hostname"]]
        );

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert!(netconf_rpc_requests("get", "success") > success_before);
    }

    #[tokio::test]
    async fn get_expanded_selection_over_path_limit_is_too_big_without_projection() {
        let (server, observed, audit) = server_fixture().await;
        let limits = MgmtLimits {
            max_paths_per_request: 3,
            ..MgmtLimits::default()
        };

        let reply = server.handle_rpc_xml(RequestId::new(), &principal(), &get_rpc(), &limits);

        assert!(reply.contains(r#"message-id="201""#));
        assert!(reply.contains("<error-tag>too-big</error-tag>"));
        assert!(!reply.contains("<sys:hostname>"));
        assert!(!reply.contains("<sys:secret>"));
        assert!(!reply.contains("<sys:uptime>"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, audit_failed("too-big"));
        assert!(events[0].schema_paths.is_empty());
    }

    #[tokio::test]
    async fn get_all_denied_returns_empty_without_projection_or_operational_provider() {
        let bus = Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "amf-1".to_string(),
                    secret: "do-not-leak".to_string(),
                },
                MockManagedDatastore::new(),
            )
            .await
            .expect("bus"),
        );
        let binding = TestBinding {
            bus,
            observed_paths: Arc::new(Mutex::new(Vec::new())),
            observed_yang_library_paths: Arc::new(Mutex::new(Vec::new())),
            observed_monitoring_paths: Arc::new(Mutex::new(Vec::new())),
            observed_with_defaults: Arc::new(Mutex::new(Vec::new())),
            operational_mode: OperationalMode::Error,
            yang_library: false,
            monitoring: false,
            with_defaults: false,
            get_schema_mode: GetSchemaMode::Ok,
        };
        let observed = binding.observed_paths();
        let audit = CapturingAudit::default();
        let server = ReadOnlyNetconfServer::new(
            binding,
            FixedPolicy(NacmPolicy::empty(PolicyVersion::new(100))),
            audit.clone(),
            TransportType::NetconfTls,
        )
        .expect("server");

        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_rpc(),
            &MgmtLimits::default(),
        );

        assert!(reply.contains(r#"message-id="201""#));
        assert!(reply.contains("<data/>"));
        assert!(!reply.contains("<sys:hostname>"));
        assert!(!reply.contains("<sys:secret>"));
        assert!(!reply.contains("<sys:uptime>"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert!(events[0].schema_paths.is_empty());
    }

    #[tokio::test]
    async fn default_server_does_not_advertise_yang_library() {
        let (server, _observed, _audit) = server_fixture().await;
        let hello = server.server_hello(Some(77));

        assert!(hello.contains(NETCONF_BASE_1_0));
        assert!(hello.contains(NETCONF_BASE_1_1));
        assert!(!hello.contains("yang-library"));
        assert!(!hello.contains("ietf-netconf-monitoring"));
    }

    #[tokio::test]
    async fn get_schema_is_operation_not_supported_until_monitoring_is_bound() {
        let (server, observed, audit) = server_fixture().await;
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_schema_rpc("demo-system", Some("2026-06-13")),
            &MgmtLimits::default(),
        );

        assert!(reply.contains(r#"message-id="501""#));
        assert!(reply.contains("<error-tag>operation-not-supported</error-tag>"));
        assert!(!reply.contains("demo-system {"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert!(events[0]
            .schema_paths
            .iter()
            .any(|path| path.as_str() == "/ncm:netconf-state/ncm:schemas/ncm:schema"));
    }

    #[tokio::test]
    async fn yang_library_binding_advertises_and_serves_registry_discovery() {
        let (server, observed, observed_yang_library, audit) =
            server_fixture_with_yang_library().await;
        let hello = server.server_hello(Some(88));

        assert!(hello.contains(
            "urn:ietf:params:netconf:capability:yang-library:1.1?revision=2019-01-04&amp;content-id=fnv1a64%3Atest-schema"
        ));

        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_rpc(),
            &MgmtLimits::default(),
        );

        assert!(reply.contains("<sys:hostname>amf-1</sys:hostname>"));
        assert!(reply.contains("<sys:uptime>12345</sys:uptime>"));
        assert!(reply.contains("<yanglib:yang-library"));
        assert!(reply.contains("<yanglib:content-id>fnv1a64:test-schema</yanglib:content-id>"));
        assert!(reply.contains("<yanglib:name>demo-system</yanglib:name>"));
        assert!(!reply.contains("do-not-leak"));

        let config_paths = observed.lock().expect("observed paths mutex");
        assert_eq!(
            config_paths.as_slice(),
            &[vec!["/sys:system", "/sys:system/sys:hostname"]]
        );
        let yang_paths = observed_yang_library
            .lock()
            .expect("yang-library observed paths mutex");
        assert!(yang_paths[0].contains(&"/yanglib:yang-library/yanglib:content-id"));
        assert!(yang_paths[0].contains(&"/yanglib:yang-library/yanglib:module-set"));

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert!(events[0]
            .schema_paths
            .iter()
            .any(|path| path.as_str() == "/yanglib:yang-library/yanglib:content-id"));
    }

    #[tokio::test]
    async fn yang_library_subtree_filter_selects_only_requested_discovery_nodes() {
        let (server, observed, observed_yang_library, _audit) =
            server_fixture_with_yang_library().await;
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="203"><get><filter><yanglib:yang-library xmlns:yanglib="urn:ietf:params:xml:ns:yang:ietf-yang-library"><yanglib:content-id/></yanglib:yang-library></filter></get></rpc>"#
        );

        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());

        assert!(reply.contains(r#"message-id="203""#));
        assert!(reply.contains("<yanglib:content-id>fnv1a64:test-schema</yanglib:content-id>"));
        assert!(!reply.contains("<yanglib:module-set>"));
        assert!(!reply.contains("<sys:hostname>"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());
        assert_eq!(
            observed_yang_library
                .lock()
                .expect("yang-library observed paths mutex")
                .as_slice(),
            &[vec![
                "/yanglib:yang-library",
                "/yanglib:yang-library/yanglib:content-id"
            ]]
        );
    }

    #[tokio::test]
    async fn yang_library_filter_fails_closed_when_not_advertised() {
        let (server, observed, _audit) = server_fixture().await;
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="204"><get><filter><yanglib:yang-library xmlns:yanglib="urn:ietf:params:xml:ns:yang:ietf-yang-library"/></filter></get></rpc>"#
        );

        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());

        assert!(reply.contains(r#"message-id="204""#));
        assert!(reply.contains("<error-tag>unknown-namespace</error-tag>"));
        assert!(!reply.contains("fnv1a64:test-schema"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());
    }

    #[tokio::test]
    async fn monitoring_binding_advertises_and_serves_schema_inventory() {
        let (server, observed, observed_monitoring, audit) = server_fixture_with_monitoring(
            policy_allow_system_and_yang_library_but_deny_secret(),
            GetSchemaMode::Ok,
        )
        .await;
        let hello = server.server_hello(Some(89));

        assert!(hello.contains(
            "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?module=ietf-netconf-monitoring&amp;revision=2010-10-04"
        ));

        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="205"><get><filter><ncm:netconf-state xmlns:ncm="{NETCONF_MONITORING_NS}"><ncm:schemas/></ncm:netconf-state></filter></get></rpc>"#
        );
        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());

        assert!(reply.contains(r#"message-id="205""#));
        assert!(reply.contains("<ncm:identifier>demo-system</ncm:identifier>"));
        assert!(reply.contains("<ncm:version>2026-06-13</ncm:version>"));
        assert!(reply.contains("<ncm:format>yang</ncm:format>"));
        assert!(reply.contains("<ncm:location>NETCONF</ncm:location>"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let monitoring_paths = observed_monitoring
            .lock()
            .expect("monitoring observed paths mutex");
        assert_eq!(
            monitoring_paths.as_slice(),
            &[vec![
                "/ncm:netconf-state",
                "/ncm:netconf-state/ncm:schemas",
                "/ncm:netconf-state/ncm:schemas/ncm:schema",
                "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:format",
                "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:identifier",
                "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:location",
                "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:namespace",
                "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:version",
            ]]
        );

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert!(events[0].schema_paths.iter().any(|path| {
            path.as_str() == "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:identifier"
        }));
    }

    #[tokio::test]
    async fn monitoring_filter_fails_closed_when_not_advertised() {
        let (server, observed, _audit) = server_fixture().await;
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="206"><get><filter><ncm:netconf-state xmlns:ncm="{NETCONF_MONITORING_NS}"/></filter></get></rpc>"#
        );

        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());

        assert!(reply.contains(r#"message-id="206""#));
        assert!(reply.contains("<error-tag>unknown-namespace</error-tag>"));
        assert!(!reply.contains("demo-system"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());
    }

    #[tokio::test]
    async fn get_schema_returns_schema_content_when_monitoring_and_nacm_allow() {
        let (server, observed, _observed_monitoring, audit) = server_fixture_with_monitoring(
            policy_allow_system_and_yang_library_but_deny_secret(),
            GetSchemaMode::Ok,
        )
        .await;
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_schema_rpc("demo-system", Some("2026-06-13")),
            &MgmtLimits::default(),
        );

        assert!(reply.contains(r#"message-id="501""#));
        assert!(reply.contains(&format!(r#"<data xmlns="{NETCONF_MONITORING_NS}">"#)));
        assert!(reply.contains("module demo-system"));
        assert!(reply.contains("&quot;urn:opc:demo&quot;"));
        assert!(!reply.contains("<rpc-error>"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert!(events[0]
            .schema_paths
            .iter()
            .any(|path| path.as_str() == "/ncm:netconf-state/ncm:schemas/ncm:schema"));
    }

    #[tokio::test]
    async fn get_schema_is_nacm_denied_without_monitoring_read_grant() {
        let (server, observed, _observed_monitoring, audit) = server_fixture_with_monitoring(
            policy_allow_system_but_deny_secret(),
            GetSchemaMode::Ok,
        )
        .await;
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_schema_rpc("demo-system", Some("2026-06-13")),
            &MgmtLimits::default(),
        );

        assert!(reply.contains("<error-tag>access-denied</error-tag>"));
        assert!(!reply.contains("module demo-system"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].outcome, audit_denied("access-denied"));
    }

    #[tokio::test]
    async fn get_schema_maps_missing_schema_to_invalid_value_without_identifier_leak() {
        let (server, _observed, _observed_monitoring, audit) = server_fixture_with_monitoring(
            policy_allow_system_and_yang_library_but_deny_secret(),
            GetSchemaMode::NotFound,
        )
        .await;
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_schema_rpc("secret-schema", Some("2026-06-13")),
            &MgmtLimits::default(),
        );

        assert!(reply.contains("<error-tag>invalid-value</error-tag>"));
        assert!(!reply.contains("secret-schema"));
        assert!(!reply.contains("do-not-leak"));

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].outcome, audit_failed("invalid-value"));
    }

    #[tokio::test]
    async fn get_schema_maps_ambiguous_schema_to_data_not_unique_app_tag() {
        let (server, _observed, _observed_monitoring, audit) = server_fixture_with_monitoring(
            policy_allow_system_and_yang_library_but_deny_secret(),
            GetSchemaMode::NotUnique,
        )
        .await;
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_schema_rpc("demo-system", None),
            &MgmtLimits::default(),
        );

        assert!(reply.contains("<error-tag>operation-failed</error-tag>"));
        assert!(reply.contains("<error-app-tag>data-not-unique</error-app-tag>"));
        assert!(!reply.contains("demo-system {"));

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].outcome, audit_failed("data-not-unique"));
    }

    #[tokio::test]
    async fn get_schema_backend_failure_does_not_leak_detail() {
        let (server, _observed, _observed_monitoring, audit) = server_fixture_with_monitoring(
            policy_allow_system_and_yang_library_but_deny_secret(),
            GetSchemaMode::Failed,
        )
        .await;
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_schema_rpc("demo-system", Some("2026-06-13")),
            &MgmtLimits::default(),
        );

        assert!(reply.contains("<error-tag>operation-failed</error-tag>"));
        assert!(!reply.contains("schema backend leaked"));
        assert!(!reply.contains("sys:secret"));

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].outcome, audit_failed("operation-failed"));
    }

    #[tokio::test]
    async fn get_subtree_filter_can_select_state_without_config_leaf() {
        let (server, observed, _audit) = server_fixture().await;
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="202"><get><filter><sys:system xmlns:sys="urn:opc:demo"><sys:uptime/></sys:system></filter></get></rpc>"#
        );
        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());

        assert!(reply.contains("<sys:uptime>12345</sys:uptime>"));
        assert!(!reply.contains("<sys:hostname>"));
        assert!(!reply.contains("<sys:secret>"));
        assert!(!reply.contains("do-not-leak"));

        let paths = observed.lock().expect("observed paths mutex");
        assert_eq!(paths.as_slice(), &[vec!["/sys:system"]]);
    }

    #[tokio::test]
    async fn get_state_only_absent_value_returns_empty_without_projection() {
        let (server, observed, audit) =
            server_fixture_with_operational_mode(OperationalMode::NoValues).await;
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="202"><get><filter><sys:system xmlns:sys="urn:opc:demo"><sys:uptime/></sys:system></filter></get></rpc>"#
        );

        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());

        assert!(reply.contains(r#"message-id="202""#));
        assert!(reply.contains("<data/>"));
        assert!(!reply.contains("<sys:hostname>"));
        assert!(!reply.contains("<sys:secret>"));
        assert!(!reply.contains("<sys:uptime>"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
    }

    #[tokio::test]
    async fn get_absent_state_does_not_suppress_allowed_config() {
        let (server, observed, _audit) =
            server_fixture_with_operational_mode(OperationalMode::NoValues).await;

        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_rpc(),
            &MgmtLimits::default(),
        );

        assert!(reply.contains(r#"message-id="201""#));
        assert!(reply.contains("<sys:hostname>amf-1</sys:hostname>"));
        assert!(!reply.contains("<sys:uptime>"));
        assert!(!reply.contains("<sys:secret>"));
        assert!(!reply.contains("do-not-leak"));

        let paths = observed.lock().expect("observed paths mutex");
        assert_eq!(
            paths.as_slice(),
            &[vec!["/sys:system", "/sys:system/sys:hostname"]]
        );
    }

    #[tokio::test]
    async fn get_provider_error_fails_closed_without_detail_leak() {
        let (server, observed, audit) =
            server_fixture_with_operational_mode(OperationalMode::Error).await;
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_rpc(),
            &MgmtLimits::default(),
        );

        assert!(reply.contains("<error-tag>operation-failed</error-tag>"));
        assert!(!reply.contains("backend leaked"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].outcome, audit_failed("operation-failed"));
    }

    #[tokio::test]
    async fn get_unexpected_operational_path_fails_closed_without_value_leak() {
        let (server, observed, _audit) =
            server_fixture_with_operational_mode(OperationalMode::UnexpectedPath).await;
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_rpc(),
            &MgmtLimits::default(),
        );

        assert!(reply.contains("<error-tag>operation-failed</error-tag>"));
        assert!(!reply.contains("sys:unexpected"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());
    }

    #[tokio::test]
    async fn get_duplicate_operational_path_fails_closed_without_projection() {
        let (server, observed, audit) =
            server_fixture_with_operational_mode(OperationalMode::DuplicatePath).await;
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_rpc(),
            &MgmtLimits::default(),
        );

        assert!(reply.contains("<error-tag>operation-failed</error-tag>"));
        assert!(!reply.contains("12345"));
        assert!(!reply.contains("67890"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].outcome, audit_failed("operation-failed"));
    }

    #[tokio::test]
    async fn get_unrequested_operational_origin_fails_closed() {
        let (server, observed, audit) =
            server_fixture_with_operational_mode(OperationalMode::UnexpectedOrigin).await;
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_rpc(),
            &MgmtLimits::default(),
        );

        assert!(reply.contains("<error-tag>operation-failed</error-tag>"));
        assert!(!reply.contains("or:system"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].outcome, audit_failed("operation-failed"));
    }

    #[tokio::test]
    async fn tls_listener_serves_hello_and_get_config_over_real_mtls() {
        let (server, _observed, audit) = server_fixture().await;
        let state = identity_state(
            "spiffe://test-domain/tenant/test/ns/default/sa/netconf/nf/amf/instance/0",
        );
        let (_identity_tx, identity_rx) = watch::channel(Some(state));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let shutdown = ShutdownToken::new();
        let limits = MgmtLimits::default();
        let listener_config = TlsListenerConfig {
            session: SessionConfig {
                limits,
                frame_timeout: Duration::from_secs(5),
            },
            drain_timeout: Duration::from_secs(5),
            ..TlsListenerConfig::default()
        };

        let listener_task = tokio::spawn(run_read_only_tls_listener(
            Arc::new(server),
            listener,
            TlsBootstrap::new(RuntimeMode::Production, peer_policy()),
            identity_rx.clone(),
            shutdown.clone(),
            listener_config,
        ));

        let client_config = Arc::new(
            TlsConfigBuilder::new(identity_rx)
                .with_policy(peer_policy())
                .build_client_config()
                .expect("client tls config"),
        );
        let connector = TlsConnector::from(client_config);
        let tcp = TcpStream::connect(addr).await.expect("connect");
        let server_name = ServerName::try_from("localhost")
            .expect("server name")
            .to_owned();
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("client tls");

        let server_hello =
            String::from_utf8(read_base10_frame(&mut tls).await).expect("hello utf8");
        assert!(server_hello.contains(NETCONF_BASE_1_0));

        let client_hello = format!(
            r#"<hello xmlns="{NETCONF_BASE_NS}"><capabilities><capability>{NETCONF_BASE_1_0}</capability></capabilities></hello>"#
        );
        tls.write_all(
            &base10::encode_message(client_hello.as_bytes(), &limits).expect("hello frame"),
        )
        .await
        .expect("write client hello");

        tls.write_all(
            &base10::encode_message(get_config_rpc("running").as_bytes(), &limits)
                .expect("rpc frame"),
        )
        .await
        .expect("write rpc");
        let reply = String::from_utf8(read_base10_frame(&mut tls).await).expect("reply utf8");
        assert!(reply.contains("<sys:hostname>amf-1</sys:hostname>"));
        assert!(!reply.contains("do-not-leak"));

        tls.write_all(&base10::encode_message(get_rpc().as_bytes(), &limits).expect("get frame"))
            .await
            .expect("write get rpc");
        let reply = String::from_utf8(read_base10_frame(&mut tls).await).expect("get reply utf8");
        assert!(reply.contains("<sys:hostname>amf-1</sys:hostname>"));
        assert!(reply.contains("<sys:uptime>12345</sys:uptime>"));
        assert!(!reply.contains("do-not-leak"));
        tls.shutdown().await.expect("client tls shutdown");
        drop(tls);

        shutdown.request_shutdown();
        let result = tokio::time::timeout(Duration::from_secs(5), listener_task)
            .await
            .expect("listener timeout")
            .expect("listener join")
            .expect("listener result");

        assert_eq!(result.accepted_sessions, 1);
        assert_eq!(result.completed_sessions, 1);
        assert_eq!(result.failed_sessions, 0);
        assert_eq!(result.rejected_sessions, 0);

        let events = audit.events.lock().expect("audit mutex");
        assert!(events
            .iter()
            .any(|event| event.outcome == AuditOutcome::Success
                && event.transport == TransportType::NetconfTls));
    }

    #[tokio::test]
    async fn tls_listener_rejects_connections_over_max_sessions() {
        let (server, _observed, _audit) = server_fixture().await;
        let state = identity_state(
            "spiffe://test-domain/tenant/test/ns/default/sa/netconf/nf/amf/instance/0",
        );
        let (_identity_tx, identity_rx) = watch::channel(Some(state));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let shutdown = ShutdownToken::new();
        let limits = MgmtLimits {
            max_sessions: 1,
            ..MgmtLimits::default()
        };
        let listener_config = TlsListenerConfig {
            session: SessionConfig {
                limits,
                frame_timeout: Duration::from_secs(5),
            },
            drain_timeout: Duration::from_secs(5),
            ..TlsListenerConfig::default()
        };

        let listener_task = tokio::spawn(run_read_only_tls_listener(
            Arc::new(server),
            listener,
            TlsBootstrap::new(RuntimeMode::Production, peer_policy()),
            identity_rx.clone(),
            shutdown.clone(),
            listener_config,
        ));

        let client_config = Arc::new(
            TlsConfigBuilder::new(identity_rx)
                .with_policy(peer_policy())
                .build_client_config()
                .expect("client tls config"),
        );
        let connector = TlsConnector::from(client_config);
        let tcp = TcpStream::connect(addr).await.expect("first connect");
        let server_name = ServerName::try_from("localhost")
            .expect("server name")
            .to_owned();
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .expect("first tls");
        let server_hello =
            String::from_utf8(read_base10_frame(&mut tls).await).expect("hello utf8");
        assert!(server_hello.contains(NETCONF_BASE_1_0));

        let mut over_limit = TcpStream::connect(addr).await.expect("second connect");
        let mut one = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), over_limit.read(&mut one))
            .await
            .expect("over-limit close")
            .expect("over-limit read");
        assert_eq!(read, 0);

        tls.shutdown().await.expect("first tls shutdown");
        drop(tls);
        shutdown.request_shutdown();
        let result = tokio::time::timeout(Duration::from_secs(5), listener_task)
            .await
            .expect("listener timeout")
            .expect("listener join")
            .expect("listener result");

        assert_eq!(result.accepted_sessions, 1);
        assert_eq!(result.completed_sessions, 0);
        assert_eq!(result.failed_sessions, 1);
        assert_eq!(result.rejected_sessions, 1);
    }

    #[tokio::test]
    async fn supervised_tls_listener_registers_as_runtime_listener_and_drains() {
        let (server, _observed, _audit) = server_fixture().await;
        let (_identity_tx, identity_rx) = watch::channel(None);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let shutdown = ShutdownToken::new();
        let supervisor = Supervisor::new(RuntimeProfile::dev("amf"), shutdown.clone());
        let task_name = TaskName::new("netconf-tls-supervised-test");

        let handle = spawn_read_only_tls_listener(
            &supervisor,
            Arc::new(server),
            listener,
            TlsBootstrap::new(RuntimeMode::Dev, PeerPolicy::default()),
            identity_rx,
            shutdown,
            SupervisedTlsListenerConfig {
                task_name: task_name.clone(),
                criticality: Criticality::Degrade,
                restart: RestartPolicy::no_restart(),
                listener: TlsListenerConfig {
                    drain_timeout: Duration::from_secs(1),
                    ..TlsListenerConfig::default()
                },
            },
        )
        .await
        .expect("spawn supervised listener");

        assert_eq!(handle.name, task_name);
        tokio::task::yield_now().await;

        let health = supervisor.health().await;
        let state = health
            .task_states
            .get("netconf-tls-supervised-test")
            .expect("task state");
        assert_eq!(state.kind, "listener");
        assert_eq!(state.criticality, "degrade");
        assert!(state.running);

        supervisor
            .shutdown_all(ShutdownPolicy::DrainWithTimeout(Duration::from_secs(2)))
            .await;

        let health = supervisor.health().await;
        let state = health
            .task_states
            .get("netconf-tls-supervised-test")
            .expect("task state after shutdown");
        assert!(!state.running);
        assert!(!health.degraded);
        assert!(!health.fatal_failure);
    }

    #[tokio::test]
    async fn audit_failure_prevents_successful_get_config_reply() {
        let bus = Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "amf-1".to_string(),
                    secret: "do-not-leak".to_string(),
                },
                MockManagedDatastore::new(),
            )
            .await
            .expect("bus"),
        );
        let binding = TestBinding {
            bus,
            observed_paths: Arc::new(Mutex::new(Vec::new())),
            observed_yang_library_paths: Arc::new(Mutex::new(Vec::new())),
            observed_monitoring_paths: Arc::new(Mutex::new(Vec::new())),
            observed_with_defaults: Arc::new(Mutex::new(Vec::new())),
            operational_mode: OperationalMode::Normal,
            yang_library: false,
            monitoring: false,
            with_defaults: false,
            get_schema_mode: GetSchemaMode::Ok,
        };
        let server = ReadOnlyNetconfServer::new(
            binding,
            FixedPolicy(policy_allow_system_but_deny_secret()),
            FailingAudit,
            TransportType::NetconfTls,
        )
        .expect("server");

        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_config_rpc("running"),
            &MgmtLimits::default(),
        );

        assert!(reply.contains("<error-tag>operation-failed</error-tag>"));
        assert!(!reply.contains("<sys:hostname>amf-1</sys:hostname>"));
        assert!(!reply.contains("secret-admin"));
        assert!(!reply.contains("do-not-leak"));
    }

    #[tokio::test]
    async fn close_session_returns_ok_audits_exec_and_requests_session_close() {
        let (server, _observed, audit) = server_fixture().await;
        let success_before = netconf_rpc_requests("close-session", "success");

        let result = server.handle_rpc(
            RequestId::new(),
            &principal(),
            &close_session_rpc(),
            &MgmtLimits::default(),
        );

        assert!(result.close_session);
        assert!(result.reply_xml.contains(r#"message-id="301""#));
        assert!(result.reply_xml.contains("<ok/>"));
        assert!(!result.reply_xml.contains("<data"));
        assert!(!result.reply_xml.contains("do-not-leak"));

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Exec);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert!(events[0]
            .schema_paths
            .iter()
            .any(|path| path.as_str() == NETCONF_CLOSE_SESSION_PATH));
        assert!(netconf_rpc_requests("close-session", "success") > success_before);
    }

    #[tokio::test]
    async fn close_session_without_exec_grant_is_access_denied_and_keeps_session_open() {
        let bus = Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "amf-1".to_string(),
                    secret: "do-not-leak".to_string(),
                },
                MockManagedDatastore::new(),
            )
            .await
            .expect("bus"),
        );
        let binding = TestBinding {
            bus,
            observed_paths: Arc::new(Mutex::new(Vec::new())),
            observed_yang_library_paths: Arc::new(Mutex::new(Vec::new())),
            observed_monitoring_paths: Arc::new(Mutex::new(Vec::new())),
            observed_with_defaults: Arc::new(Mutex::new(Vec::new())),
            operational_mode: OperationalMode::Normal,
            yang_library: false,
            monitoring: false,
            with_defaults: false,
            get_schema_mode: GetSchemaMode::Ok,
        };
        let audit = CapturingAudit::default();
        let server = ReadOnlyNetconfServer::new(
            binding,
            FixedPolicy(NacmPolicy::empty(PolicyVersion::new(404))),
            audit.clone(),
            TransportType::NetconfTls,
        )
        .expect("server");

        let result = server.handle_rpc(
            RequestId::new(),
            &principal(),
            &close_session_rpc(),
            &MgmtLimits::default(),
        );

        assert!(!result.close_session);
        assert!(result.reply_xml.contains(r#"message-id="301""#));
        assert!(result
            .reply_xml
            .contains("<error-tag>access-denied</error-tag>"));
        assert!(!result.reply_xml.contains("<ok/>"));
        assert!(!result.reply_xml.contains("do-not-leak"));

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Exec);
        assert_eq!(events[0].outcome, audit_denied("access-denied"));
        assert!(events[0]
            .schema_paths
            .iter()
            .any(|path| path.as_str() == NETCONF_CLOSE_SESSION_PATH));
    }

    #[tokio::test]
    async fn close_session_policy_error_is_resource_denied_and_keeps_session_open() {
        let bus = Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "amf-1".to_string(),
                    secret: "do-not-leak".to_string(),
                },
                MockManagedDatastore::new(),
            )
            .await
            .expect("bus"),
        );
        let binding = TestBinding {
            bus,
            observed_paths: Arc::new(Mutex::new(Vec::new())),
            observed_yang_library_paths: Arc::new(Mutex::new(Vec::new())),
            observed_monitoring_paths: Arc::new(Mutex::new(Vec::new())),
            observed_with_defaults: Arc::new(Mutex::new(Vec::new())),
            operational_mode: OperationalMode::Normal,
            yang_library: false,
            monitoring: false,
            with_defaults: false,
            get_schema_mode: GetSchemaMode::Ok,
        };
        let audit = CapturingAudit::default();
        let server = ReadOnlyNetconfServer::new(
            binding,
            BrokenPolicySource,
            audit.clone(),
            TransportType::NetconfTls,
        )
        .expect("server");

        let result = server.handle_rpc(
            RequestId::new(),
            &principal(),
            &close_session_rpc(),
            &MgmtLimits::default(),
        );

        assert!(!result.close_session);
        assert!(result.reply_xml.contains(r#"message-id="301""#));
        assert!(result
            .reply_xml
            .contains("<error-tag>resource-denied</error-tag>"));
        assert!(!result.reply_xml.contains("<ok/>"));
        assert!(!result.reply_xml.contains("policy"));
        assert!(!result.reply_xml.contains("do-not-leak"));

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Exec);
        assert_eq!(events[0].outcome, audit_failed("resource-denied"));
        assert!(events[0]
            .schema_paths
            .iter()
            .any(|path| path.as_str() == NETCONF_CLOSE_SESSION_PATH));
    }

    #[tokio::test]
    async fn audit_failure_prevents_close_session_success_and_keeps_session_open() {
        let bus = Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "amf-1".to_string(),
                    secret: "do-not-leak".to_string(),
                },
                MockManagedDatastore::new(),
            )
            .await
            .expect("bus"),
        );
        let binding = TestBinding {
            bus,
            observed_paths: Arc::new(Mutex::new(Vec::new())),
            observed_yang_library_paths: Arc::new(Mutex::new(Vec::new())),
            observed_monitoring_paths: Arc::new(Mutex::new(Vec::new())),
            observed_with_defaults: Arc::new(Mutex::new(Vec::new())),
            operational_mode: OperationalMode::Normal,
            yang_library: false,
            monitoring: false,
            with_defaults: false,
            get_schema_mode: GetSchemaMode::Ok,
        };
        let server = ReadOnlyNetconfServer::new(
            binding,
            FixedPolicy(policy_allow_system_but_deny_secret()),
            FailingAudit,
            TransportType::NetconfTls,
        )
        .expect("server");

        let result = server.handle_rpc(
            RequestId::new(),
            &principal(),
            &close_session_rpc(),
            &MgmtLimits::default(),
        );

        assert!(!result.close_session);
        assert!(result
            .reply_xml
            .contains("<error-tag>operation-failed</error-tag>"));
        assert!(!result.reply_xml.contains("secret-admin"));
        assert!(!result.reply_xml.contains("do-not-leak"));
    }

    #[tokio::test]
    async fn unsupported_base_operation_preserves_message_id_audits_and_leaks_no_payload() {
        let (server, observed, audit) = server_fixture().await;
        let failures_before = netconf_rpc_requests("edit-config", "failure");
        let errors_before = netconf_rpc_errors("edit-config", "operation-not-supported");

        let result = server.handle_rpc(
            RequestId::new(),
            &principal(),
            &unsupported_edit_config_rpc(),
            &MgmtLimits::default(),
        );

        assert!(!result.close_session);
        assert!(result.reply_xml.contains(r#"message-id="401""#));
        assert!(result
            .reply_xml
            .contains("<error-tag>operation-not-supported</error-tag>"));
        assert!(!result.reply_xml.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Update);
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert!(events[0].schema_paths.is_empty());
        assert!(netconf_rpc_requests("edit-config", "failure") > failures_before);
        assert!(netconf_rpc_errors("edit-config", "operation-not-supported") > errors_before);
    }

    #[tokio::test]
    async fn unsupported_base_operation_cdata_payload_is_bounded_ignored_and_not_echoed() {
        let (server, observed, audit) = server_fixture().await;
        let failures_before = netconf_rpc_requests("edit-config", "failure");
        let errors_before = netconf_rpc_errors("edit-config", "operation-not-supported");

        let result = server.handle_rpc(
            RequestId::new(),
            &principal(),
            &unsupported_edit_config_cdata_rpc(),
            &MgmtLimits::default(),
        );

        assert!(!result.close_session);
        assert!(result.reply_xml.contains(r#"message-id="402""#));
        assert!(result
            .reply_xml
            .contains("<error-tag>operation-not-supported</error-tag>"));
        assert!(!result.reply_xml.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Update);
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert!(events[0].schema_paths.is_empty());
        assert!(netconf_rpc_requests("edit-config", "failure") > failures_before);
        assert!(netconf_rpc_errors("edit-config", "operation-not-supported") > errors_before);
    }

    #[tokio::test]
    async fn audit_failure_on_unsupported_operation_returns_generic_error_without_payload() {
        let bus = Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "amf-1".to_string(),
                    secret: "do-not-leak".to_string(),
                },
                MockManagedDatastore::new(),
            )
            .await
            .expect("bus"),
        );
        let binding = TestBinding {
            bus,
            observed_paths: Arc::new(Mutex::new(Vec::new())),
            observed_yang_library_paths: Arc::new(Mutex::new(Vec::new())),
            observed_monitoring_paths: Arc::new(Mutex::new(Vec::new())),
            observed_with_defaults: Arc::new(Mutex::new(Vec::new())),
            operational_mode: OperationalMode::Normal,
            yang_library: false,
            monitoring: false,
            with_defaults: false,
            get_schema_mode: GetSchemaMode::Ok,
        };
        let server = ReadOnlyNetconfServer::new(
            binding,
            FixedPolicy(policy_allow_system_but_deny_secret()),
            FailingAudit,
            TransportType::NetconfTls,
        )
        .expect("server");

        let result = server.handle_rpc(
            RequestId::new(),
            &principal(),
            &unsupported_edit_config_rpc(),
            &MgmtLimits::default(),
        );

        assert!(!result.close_session);
        assert!(result.reply_xml.contains(r#"message-id="401""#));
        assert!(result
            .reply_xml
            .contains("<error-tag>operation-failed</error-tag>"));
        assert!(!result.reply_xml.contains("secret-admin"));
        assert!(!result.reply_xml.contains("do-not-leak"));
    }

    #[tokio::test]
    async fn candidate_is_recognized_but_not_supported_or_advertised() {
        let (server, observed, audit) = server_fixture().await;
        let failures_before = netconf_rpc_requests("get-config", "failure");
        let errors_before = netconf_rpc_errors("get-config", "operation-not-supported");
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_config_rpc("candidate"),
            &MgmtLimits::default(),
        );

        assert!(reply.contains("<error-tag>operation-not-supported</error-tag>"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert!(netconf_rpc_requests("get-config", "failure") > failures_before);
        assert!(netconf_rpc_errors("get-config", "operation-not-supported") > errors_before);
    }

    #[tokio::test]
    async fn get_config_with_defaults_is_recognized_but_not_supported_or_advertised() {
        let (server, observed, audit) = server_fixture().await;
        let failures_before = netconf_rpc_requests("get-config", "failure");
        let errors_before = netconf_rpc_errors("get-config", "operation-not-supported");

        let hello = server.server_hello(Some(78));
        assert!(!hello.contains("with-defaults"));

        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_config_with_defaults_rpc("trim"),
            &MgmtLimits::default(),
        );

        assert!(reply.contains(r#"message-id="111""#));
        assert!(reply.contains("<error-tag>operation-not-supported</error-tag>"));
        assert!(!reply.contains("trim"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert!(events[0].schema_paths.is_empty());
        assert!(netconf_rpc_requests("get-config", "failure") > failures_before);
        assert!(netconf_rpc_errors("get-config", "operation-not-supported") > errors_before);
    }

    #[tokio::test]
    async fn get_with_defaults_is_recognized_but_not_supported_or_advertised() {
        let (server, observed, audit) = server_fixture().await;
        let failures_before = netconf_rpc_requests("get", "failure");
        let errors_before = netconf_rpc_errors("get", "operation-not-supported");

        let hello = server.server_hello(Some(79));
        assert!(!hello.contains("with-defaults"));

        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_with_defaults_rpc("report-all-tagged"),
            &MgmtLimits::default(),
        );

        assert!(reply.contains(r#"message-id="211""#));
        assert!(reply.contains("<error-tag>operation-not-supported</error-tag>"));
        assert!(!reply.contains("report-all-tagged"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert!(events[0].schema_paths.is_empty());
        assert!(netconf_rpc_requests("get", "failure") > failures_before);
        assert!(netconf_rpc_errors("get", "operation-not-supported") > errors_before);
    }

    #[tokio::test]
    async fn get_config_with_defaults_is_advertised_and_binding_projected_when_bound() {
        let (server, observed, observed_defaults, audit) = server_fixture_with_defaults().await;
        let success_before = netconf_rpc_requests("get-config", "success");

        let hello = server.server_hello(Some(80));
        assert!(hello.contains(
            "urn:ietf:params:netconf:capability:with-defaults:1.0?basic-mode=report-all&amp;also-supported=trim,explicit,report-all-tagged"
        ));

        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_config_with_defaults_rpc("trim"),
            &MgmtLimits::default(),
        );

        assert!(reply.contains(r#"message-id="111""#));
        assert!(reply.contains("<sys:hostname>amf-1-trim</sys:hostname>"));
        assert!(!reply.contains("<rpc-error>"));
        assert!(!reply.contains("do-not-leak"));

        assert_eq!(
            observed.lock().expect("observed paths mutex").as_slice(),
            &[vec!["/sys:system", "/sys:system/sys:hostname"]]
        );
        assert_eq!(
            observed_defaults
                .lock()
                .expect("with-defaults observed mutex")
                .as_slice(),
            &[WithDefaultsMode::Trim]
        );

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert!(events[0]
            .schema_paths
            .iter()
            .any(|path| path.as_str() == "/sys:system/sys:hostname"));
        assert!(netconf_rpc_requests("get-config", "success") > success_before);
    }

    #[tokio::test]
    async fn get_with_defaults_is_advertised_and_binding_projected_when_bound() {
        let (server, observed, observed_defaults, audit) = server_fixture_with_defaults().await;
        let success_before = netconf_rpc_requests("get", "success");

        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_with_defaults_rpc("report-all-tagged"),
            &MgmtLimits::default(),
        );

        assert!(reply.contains(r#"message-id="211""#));
        assert!(reply.contains("<sys:hostname>amf-1-report-all-tagged</sys:hostname>"));
        assert!(reply.contains("<sys:uptime>12345</sys:uptime>"));
        assert!(!reply.contains("<rpc-error>"));
        assert!(!reply.contains("do-not-leak"));

        assert_eq!(
            observed.lock().expect("observed paths mutex").as_slice(),
            &[vec!["/sys:system", "/sys:system/sys:hostname"]]
        );
        assert_eq!(
            observed_defaults
                .lock()
                .expect("with-defaults observed mutex")
                .as_slice(),
            &[WithDefaultsMode::ReportAllTagged]
        );

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert!(netconf_rpc_requests("get", "success") > success_before);
    }

    #[tokio::test]
    async fn bound_with_defaults_rejects_unrecognized_mode_without_projection_or_leak() {
        let (server, observed, observed_defaults, audit) = server_fixture_with_defaults().await;

        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_config_with_defaults_rpc("secret-mode"),
            &MgmtLimits::default(),
        );

        assert!(reply.contains(r#"message-id="111""#));
        assert!(reply.contains("<error-tag>operation-not-supported</error-tag>"));
        assert!(!reply.contains("secret-mode"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());
        assert!(observed_defaults
            .lock()
            .expect("with-defaults observed mutex")
            .is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert!(events[0].schema_paths.is_empty());
    }

    #[tokio::test]
    async fn advertised_with_defaults_without_projection_fails_closed_without_fallback() {
        let (server, observed, audit) =
            server_fixture_with_advertised_defaults_but_no_projection().await;
        let failures_before = netconf_rpc_requests("get-config", "failure");

        let hello = server.server_hello(Some(81));
        assert!(
            hello.contains("urn:ietf:params:netconf:capability:with-defaults:1.0?basic-mode=trim")
        );

        let get_config_reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_config_with_defaults_rpc("trim"),
            &MgmtLimits::default(),
        );
        let get_reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_with_defaults_rpc("trim"),
            &MgmtLimits::default(),
        );

        for reply in [&get_config_reply, &get_reply] {
            assert!(reply.contains("<error-tag>operation-failed</error-tag>"));
            assert!(!reply.contains("ordinary-renderer"));
            assert!(!reply.contains("amf-1"));
            assert!(!reply.contains("do-not-leak"));
        }
        assert!(observed.lock().expect("observed paths mutex").is_empty());
        assert!(netconf_rpc_requests("get-config", "failure") > failures_before);

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 2);
        assert!(events
            .iter()
            .all(|event| event.outcome == audit_failed("operation-failed")));
        assert!(events.iter().all(|event| event
            .schema_paths
            .iter()
            .any(|path| path.as_str() == "/sys:system/sys:hostname")));
    }

    #[tokio::test]
    async fn advertised_yang_library_without_projection_fails_closed_without_fallback() {
        let (server, observed, audit) = server_fixture_with_advertised_discovery_but_no_projection(
            AdvertisedDiscovery::YangLibrary,
        )
        .await;

        let hello = server.server_hello(Some(82));
        assert!(hello.contains(
            "urn:ietf:params:netconf:capability:yang-library:1.1?revision=2019-01-04&amp;content-id=fnv1a64%3Atest-schema"
        ));

        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="207"><get><filter><yanglib:yang-library xmlns:yanglib="urn:ietf:params:xml:ns:yang:ietf-yang-library"><yanglib:content-id/></yanglib:yang-library></filter></get></rpc>"#
        );
        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());

        assert!(reply.contains(r#"message-id="207""#));
        assert!(reply.contains("<error-tag>operation-failed</error-tag>"));
        assert!(!reply.contains("fnv1a64:test-schema"));
        assert!(!reply.contains("ordinary-renderer"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, audit_failed("operation-failed"));
        assert!(events[0]
            .schema_paths
            .iter()
            .any(|path| path.as_str() == "/yanglib:yang-library/yanglib:content-id"));
    }

    #[tokio::test]
    async fn advertised_monitoring_without_projection_fails_closed_without_fallback() {
        let (server, observed, audit) = server_fixture_with_advertised_discovery_but_no_projection(
            AdvertisedDiscovery::Monitoring,
        )
        .await;

        let hello = server.server_hello(Some(83));
        assert!(hello.contains(
            "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?module=ietf-netconf-monitoring&amp;revision=2010-10-04"
        ));

        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="208"><get><filter><ncm:netconf-state xmlns:ncm="{NETCONF_MONITORING_NS}"><ncm:schemas/></ncm:netconf-state></filter></get></rpc>"#
        );
        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());

        assert!(reply.contains(r#"message-id="208""#));
        assert!(reply.contains("<error-tag>operation-failed</error-tag>"));
        assert!(!reply.contains("demo-system"));
        assert!(!reply.contains("ordinary-renderer"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, audit_failed("operation-failed"));
        assert!(events[0].schema_paths.iter().any(|path| {
            path.as_str() == "/ncm:netconf-state/ncm:schemas/ncm:schema/ncm:identifier"
        }));
    }

    #[tokio::test]
    async fn advertised_monitoring_without_get_schema_hook_fails_closed_without_identifier_leak() {
        let (server, observed, audit) = server_fixture_with_advertised_discovery_but_no_projection(
            AdvertisedDiscovery::Monitoring,
        )
        .await;

        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_schema_rpc("secret-schema", Some("2026-06-13")),
            &MgmtLimits::default(),
        );

        assert!(reply.contains(r#"message-id="501""#));
        assert!(reply.contains("<error-tag>operation-failed</error-tag>"));
        assert!(!reply.contains("secret-schema"));
        assert!(!reply.contains("get-schema retrieval"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, audit_failed("operation-failed"));
        assert!(events[0]
            .schema_paths
            .iter()
            .any(|path| path.as_str() == "/ncm:netconf-state/ncm:schemas/ncm:schema"));
    }

    #[tokio::test]
    async fn subtree_filter_selects_structural_schema_paths_before_nacm() {
        let (server, observed, audit) = server_fixture().await;
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="102"><get-config><source><running/></source><filter type="subtree"><sys:system xmlns:sys="urn:opc:demo"><sys:hostname/></sys:system></filter></get-config></rpc>"#
        );
        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());
        assert!(reply.contains("<sys:hostname>amf-1</sys:hostname>"));
        assert!(!reply.contains("<sys:secret>"));
        assert!(!reply.contains("do-not-leak"));

        let paths = observed.lock().expect("observed paths mutex");
        assert_eq!(
            paths.as_slice(),
            &[vec!["/sys:system", "/sys:system/sys:hostname"]]
        );

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
    }

    #[tokio::test]
    async fn subtree_filter_namespace_wildcard_selects_structural_schema_paths() {
        let (server, observed, audit) = server_fixture().await;
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="102"><get-config><source><running/></source><filter type="subtree"><system xmlns=""><hostname/></system></filter></get-config></rpc>"#
        );
        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());
        assert!(reply.contains("<sys:hostname>amf-1</sys:hostname>"));
        assert!(!reply.contains("<sys:secret>"));
        assert!(!reply.contains("do-not-leak"));

        let paths = observed.lock().expect("observed paths mutex");
        assert_eq!(
            paths.as_slice(),
            &[vec!["/sys:system", "/sys:system/sys:hostname"]]
        );

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
    }

    #[tokio::test]
    async fn subtree_filter_terminal_container_expands_then_nacm_filters_denied_children() {
        let (server, observed, _audit) = server_fixture().await;
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="103"><get-config><source><running/></source><filter><sys:system xmlns:sys="urn:opc:demo"/></filter></get-config></rpc>"#
        );
        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());
        assert!(reply.contains("<sys:hostname>amf-1</sys:hostname>"));
        assert!(!reply.contains("<sys:secret>"));
        assert!(!reply.contains("do-not-leak"));

        let paths = observed.lock().expect("observed paths mutex");
        assert_eq!(
            paths.as_slice(),
            &[vec!["/sys:system", "/sys:system/sys:hostname"]]
        );
    }

    #[tokio::test]
    async fn xpath_filter_remains_rejected_until_bounded_evaluator_exists() {
        let (server, observed, audit) = server_fixture().await;
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="104"><get-config><source><running/></source><filter type="xpath" select="/sys:system/sys:hostname"/></get-config></rpc>"#
        );
        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());
        assert!(reply.contains("<error-tag>operation-not-supported</error-tag>"));
        assert!(!reply.contains("sys:hostname"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
    }

    #[tokio::test]
    async fn subtree_filter_unknown_namespace_fails_closed_without_payload() {
        let (server, observed, _audit) = server_fixture().await;
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="105"><get-config><source><running/></source><filter><bad:system xmlns:bad="urn:secret:tenant"/></filter></get-config></rpc>"#
        );
        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());
        assert!(reply.contains("<error-tag>unknown-namespace</error-tag>"));
        assert!(!reply.contains("urn:secret:tenant"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());
    }

    #[tokio::test]
    async fn subtree_filter_content_match_fails_closed_until_supported() {
        let (server, observed, _audit) = server_fixture().await;
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="106"><get-config><source><running/></source><filter><sys:system xmlns:sys="urn:opc:demo"><sys:hostname>do-not-leak</sys:hostname></sys:system></filter></get-config></rpc>"#
        );
        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());
        assert!(reply.contains(r#"message-id="106""#));
        assert!(reply.contains("<error-tag>bad-element</error-tag>"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());
    }

    #[tokio::test]
    async fn unexpected_protocol_text_fails_closed_without_payload() {
        let (server, observed, _audit) = server_fixture().await;
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="107"><get>do-not-leak</get></rpc>"#
        );
        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());
        assert!(reply.contains(r#"message-id="107""#));
        assert!(reply.contains("<error-tag>malformed-message</error-tag>"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="108"><get><![CDATA[do-not-leak]]></get></rpc>"#
        );
        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());
        assert!(reply.contains(r#"message-id="108""#));
        assert!(reply.contains("<error-tag>malformed-message</error-tag>"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());
    }

    #[tokio::test]
    async fn malformed_xml_returns_generic_rpc_error_without_payload() {
        let (server, _observed, _audit) = server_fixture().await;
        let failures_before = netconf_rpc_requests("unknown", "failure");
        let errors_before = netconf_rpc_errors("unknown", "malformed-message");
        let rpc = format!(
            r#"<!DOCTYPE rpc [ <!ENTITY secret "do-not-leak"> ]><rpc xmlns="{NETCONF_BASE_NS}" message-id="1"><get-config><source><running/></source></get-config></rpc>"#
        );
        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());
        assert!(reply.contains("<error-tag>malformed-message</error-tag>"));
        assert!(!reply.contains("message-id="));
        assert!(!reply.contains("do-not-leak"));
        assert!(netconf_rpc_requests("unknown", "failure") > failures_before);
        assert!(netconf_rpc_errors("unknown", "malformed-message") > errors_before);
    }

    fn netconf_rpc_requests(operation: &str, outcome: &str) -> u64 {
        METRICS
            .netconf_rpc_requests_total
            .lock()
            .ok()
            .and_then(|map| {
                map.get(&(operation.to_string(), outcome.to_string()))
                    .copied()
            })
            .unwrap_or(0)
    }

    fn netconf_rpc_errors(operation: &str, error_tag: &str) -> u64 {
        METRICS
            .netconf_rpc_errors_total
            .lock()
            .ok()
            .and_then(|map| {
                map.get(&(operation.to_string(), error_tag.to_string()))
                    .copied()
            })
            .unwrap_or(0)
    }

    fn netconf_nacm_denials(action: &str) -> u64 {
        METRICS
            .netconf_nacm_denials_total
            .lock()
            .ok()
            .and_then(|map| map.get(action).copied())
            .unwrap_or(0)
    }
}
