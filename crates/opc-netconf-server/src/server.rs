//! NETCONF server core.

use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::panic::{self, AssertUnwindSafe};
use std::sync::Arc;
use std::time::{Duration, Instant};

use opc_config_model::{
    CommitMode, CommitRequest, ConfigOperation, OpcConfig, RequestId, RequestSource, TransportType,
    TrustedPrincipal, ValidationContext,
};
use opc_mgmt_audit::{
    AuditError, AuditEvent, AuditOperation, AuditOutcome, AuditSink, SchemaNodePath,
};
use opc_mgmt_authz::{AuthzError, ExecAuthorizer, PolicySource, ReadAuthorizer};
use opc_mgmt_errors::{commit_error_to_netconf, NetconfError, NetconfErrorTag, NetconfErrorType};
use opc_mgmt_limits::MgmtLimits;
use opc_mgmt_schema::ModelData;
use thiserror::Error;

use crate::binding::{
    EditConfigError, GetSchemaError, GetSchemaRequest as BindingGetSchemaRequest,
    NetconfConfigBinding,
};
use crate::capabilities::render_server_hello;
use crate::error::{
    rpc_error_reply_with_attrs, rpc_get_schema_reply_with_attrs, rpc_ok_empty_reply_with_attrs,
    RpcError, RpcReplyAttributes,
};
use crate::metrics::{record_rpc_error, record_rpc_success, NetconfOperation};
use crate::operations::get::{handle_get, GetContext};
use crate::operations::get_config::{handle_get_config, GetConfigContext};
use crate::session_registry::{KillSessionResult, RunningWriteResult, SessionRegistry};
use crate::session_registry::{LockRunningResult, UnlockRunningResult};
use crate::xml::{
    parse_rpc_with_context, Datastore as XmlDatastore, EditConfigRequest as XmlEditConfigRequest,
    EditErrorOption, EditTestOption, GetSchemaRequest as XmlGetSchemaRequest,
    KillSessionRequest as XmlKillSessionRequest, LockRequest as XmlLockRequest, RpcOperation,
    RpcOperationHint, RpcParseError, UnlockRequest as XmlUnlockRequest, UnsupportedOperation,
    ValidateRequest as XmlValidateRequest,
};

const NETCONF_BASE_MODEL: &[ModelData] = &[ModelData {
    name: "ietf-netconf",
    revision: "2011-06-01",
    namespace: "urn:ietf:params:xml:ns:netconf:base:1.0",
    prefix: "nc",
}];

const NETCONF_CLOSE_SESSION_PATH: &str = "/nc:close-session";
const NETCONF_EDIT_CONFIG_PATH: &str = "/nc:edit-config";
const NETCONF_LOCK_PATH: &str = "/nc:lock";
const NETCONF_UNLOCK_PATH: &str = "/nc:unlock";
const NETCONF_KILL_SESSION_PATH: &str = "/nc:kill-session";
const NETCONF_VALIDATE_PATH: &str = "/nc:validate";

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

struct RpcExecContext<'a> {
    request_id: RequestId,
    principal: &'a TrustedPrincipal,
    message_id: &'a str,
    reply_attrs: &'a RpcReplyAttributes,
    started: Instant,
}

/// NETCONF server core.
///
/// This type handles parsed XML RPC documents. It does not bind sockets or
/// perform the NETCONF `<hello>` handshake; transport/session code composes
/// those pieces around this core.
///
/// The public [`Self::handle_rpc`] and [`Self::handle_rpc_xml`] helpers are
/// registry-free, low-level dispatch helpers. They preserve parser, NACM,
/// audit, metrics, and reply behavior for one RPC, but they are not a complete
/// advertised NETCONF base session: `<kill-session>`, `<lock>`, and
/// `<unlock>` return `operation-not-supported` without a live
/// [`SessionRegistry`], and [`Self::handle_rpc_xml`] also discards the
/// `<close-session>` close signal. `<edit-config>` also returns
/// `operation-not-supported` from these registry-free helpers; running writes
/// require the registry-aware async session path.
/// Use [`crate::session::run_read_only_session_with_registry`] or
/// [`crate::transport::run_read_only_tls_session_with_registry`] when custom
/// transports need full base-session behavior backed by the audited shared
/// session registry.
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
    ///
    /// This is a low-level helper for request/response harnesses. It does not
    /// enact session-control side effects: `<kill-session>`, `<lock>`, and
    /// `<unlock>` have no shared registry context, and `<close-session>`'s
    /// close signal is discarded.
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
    ///
    /// The base capabilities are intended to be paired with the session runners
    /// in [`crate::session`] or [`crate::transport`]. Direct callers that pair a
    /// rendered `<hello>` with [`Self::handle_rpc`] do not get cross-session
    /// `<kill-session>` or running datastore lock semantics.
    pub fn server_hello(&self, session_id: Option<NonZeroU32>) -> String {
        let yang_library = self.binding.yang_library_capability();
        let monitoring = self.binding.netconf_monitoring_capability();
        let with_defaults = self.binding.with_defaults_capability();
        let writable_running = self.binding.writable_running_capability();
        render_server_hello(
            session_id,
            yang_library.as_ref(),
            monitoring.as_ref(),
            with_defaults.as_ref(),
            writable_running,
        )
    }

    /// Handles one complete XML RPC document and returns the reply plus any
    /// registry-free session-control action.
    ///
    /// This helper can report `<close-session>` via
    /// [`RpcHandlingResult::close_session`], but it cannot address other live
    /// sessions or hold running datastore lock ownership. `<kill-session>`,
    /// `<lock>`, and `<unlock>` therefore return `operation-not-supported`.
    /// Use the registry-aware session runners for complete base session-control
    /// behavior.
    pub fn handle_rpc(
        &self,
        request_id: RequestId,
        principal: &TrustedPrincipal,
        xml: &str,
        limits: &MgmtLimits,
    ) -> RpcHandlingResult {
        self.handle_rpc_inner(request_id, principal, xml, limits, None)
    }

    /// Handles one XML RPC with access to live NETCONF session controls.
    #[allow(dead_code)]
    pub(crate) fn handle_rpc_for_session(
        &self,
        request_id: RequestId,
        principal: &TrustedPrincipal,
        xml: &str,
        limits: &MgmtLimits,
        current_session_id: u64,
        sessions: &SessionRegistry,
    ) -> RpcHandlingResult {
        self.handle_rpc_inner(
            request_id,
            principal,
            xml,
            limits,
            Some((current_session_id, sessions)),
        )
    }

    /// Handles one XML RPC with access to live NETCONF session controls and
    /// async config-bus writes.
    pub(crate) async fn handle_rpc_for_session_async(
        &self,
        request_id: RequestId,
        principal: &TrustedPrincipal,
        xml: &str,
        limits: &MgmtLimits,
        current_session_id: u64,
        sessions: &SessionRegistry,
    ) -> RpcHandlingResult {
        self.handle_rpc_inner_async(
            request_id,
            principal,
            xml,
            limits,
            Some((current_session_id, sessions)),
        )
        .await
    }

    fn handle_rpc_inner(
        &self,
        request_id: RequestId,
        principal: &TrustedPrincipal,
        xml: &str,
        limits: &MgmtLimits,
        session_context: Option<(u64, &SessionRegistry)>,
    ) -> RpcHandlingResult {
        let started = Instant::now();
        let parsed = match parse_rpc_with_context(xml, limits) {
            Ok(parsed) => parsed,
            Err(err) => {
                let message_id = err.message_id.as_deref();
                let operation = netconf_operation_for_parse_failure(&err);
                let operation_label = operation.as_str();
                if self
                    .audit_parse_failure(request_id, principal, &err)
                    .is_err()
                {
                    record_rpc_error(
                        operation,
                        NetconfErrorTag::OperationFailed,
                        started.elapsed(),
                    );
                    tracing::debug!(
                        operation = operation_label,
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
                record_rpc_error(operation, classification.tag, started.elapsed());
                tracing::debug!(
                    operation = operation_label,
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
            RpcOperation::EditConfig(_) => self.handle_unsupported_operation(
                UnsupportedOperation::EditConfig,
                request_id,
                principal,
                &parsed.message_id,
                &parsed.reply_attrs,
                started,
            ),
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
            RpcOperation::Lock(request) => self.handle_lock(
                request,
                RpcExecContext {
                    request_id,
                    principal,
                    message_id: &parsed.message_id,
                    reply_attrs: &parsed.reply_attrs,
                    started,
                },
                session_context,
            ),
            RpcOperation::Unlock(request) => self.handle_unlock(
                request,
                RpcExecContext {
                    request_id,
                    principal,
                    message_id: &parsed.message_id,
                    reply_attrs: &parsed.reply_attrs,
                    started,
                },
                session_context,
            ),
            RpcOperation::Validate(request) => self.handle_validate(
                request,
                RpcExecContext {
                    request_id,
                    principal,
                    message_id: &parsed.message_id,
                    reply_attrs: &parsed.reply_attrs,
                    started,
                },
            ),
            RpcOperation::KillSession(request) => self.handle_kill_session(
                request,
                RpcExecContext {
                    request_id,
                    principal,
                    message_id: &parsed.message_id,
                    reply_attrs: &parsed.reply_attrs,
                    started,
                },
                session_context,
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

    async fn handle_rpc_inner_async(
        &self,
        request_id: RequestId,
        principal: &TrustedPrincipal,
        xml: &str,
        limits: &MgmtLimits,
        session_context: Option<(u64, &SessionRegistry)>,
    ) -> RpcHandlingResult {
        let started = Instant::now();
        let parsed = match parse_rpc_with_context(xml, limits) {
            Ok(parsed) => parsed,
            Err(err) => {
                let message_id = err.message_id.as_deref();
                let operation = netconf_operation_for_parse_failure(&err);
                let operation_label = operation.as_str();
                if self
                    .audit_parse_failure(request_id, principal, &err)
                    .is_err()
                {
                    record_rpc_error(
                        operation,
                        NetconfErrorTag::OperationFailed,
                        started.elapsed(),
                    );
                    tracing::debug!(
                        operation = operation_label,
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
                record_rpc_error(operation, classification.tag, started.elapsed());
                tracing::debug!(
                    operation = operation_label,
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
            RpcOperation::EditConfig(request) => {
                self.handle_edit_config(
                    request,
                    RpcExecContext {
                        request_id,
                        principal,
                        message_id: &parsed.message_id,
                        reply_attrs: &parsed.reply_attrs,
                        started,
                    },
                    session_context,
                )
                .await
            }
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
            RpcOperation::Lock(request) => self.handle_lock(
                request,
                RpcExecContext {
                    request_id,
                    principal,
                    message_id: &parsed.message_id,
                    reply_attrs: &parsed.reply_attrs,
                    started,
                },
                session_context,
            ),
            RpcOperation::Unlock(request) => self.handle_unlock(
                request,
                RpcExecContext {
                    request_id,
                    principal,
                    message_id: &parsed.message_id,
                    reply_attrs: &parsed.reply_attrs,
                    started,
                },
                session_context,
            ),
            RpcOperation::Validate(request) => self.handle_validate(
                request,
                RpcExecContext {
                    request_id,
                    principal,
                    message_id: &parsed.message_id,
                    reply_attrs: &parsed.reply_attrs,
                    started,
                },
            ),
            RpcOperation::KillSession(request) => self.handle_kill_session(
                request,
                RpcExecContext {
                    request_id,
                    principal,
                    message_id: &parsed.message_id,
                    reply_attrs: &parsed.reply_attrs,
                    started,
                },
                session_context,
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

    fn handle_kill_session(
        &self,
        request: &XmlKillSessionRequest,
        context: RpcExecContext<'_>,
        session_context: Option<(u64, &SessionRegistry)>,
    ) -> RpcHandlingResult {
        let RpcExecContext {
            request_id,
            principal,
            message_id,
            reply_attrs,
            started,
        } = context;
        let kill_path = schema_node_path(NETCONF_KILL_SESSION_PATH);
        match self.authorize_exec(principal, NETCONF_KILL_SESSION_PATH) {
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
                        .with_paths([kill_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::KillSession,
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
                    NetconfOperation::KillSession,
                    NetconfErrorTag::AccessDenied,
                    started.elapsed(),
                );
                tracing::debug!(
                    operation = "kill-session",
                    error_tag = NetconfErrorTag::AccessDenied.as_str(),
                    "NETCONF kill-session denied by exec NACM"
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
                        .with_paths([kill_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::KillSession,
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
                    NetconfOperation::KillSession,
                    NetconfErrorTag::ResourceDenied,
                    started.elapsed(),
                );
                tracing::debug!(
                    operation = "kill-session",
                    error_tag = NetconfErrorTag::ResourceDenied.as_str(),
                    "NETCONF kill-session failed closed on exec policy source error"
                );
                return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    Some(message_id),
                    reply_attrs,
                    RpcError::resource_denied(),
                ));
            }
        }

        let Some((current_session_id, sessions)) = session_context else {
            if self
                .audit
                .record(
                    &AuditEvent::new(
                        request_id,
                        principal,
                        self.transport,
                        AuditOperation::Exec,
                        audit_failed("operation-not-supported"),
                    )
                    .with_paths([kill_path]),
                )
                .is_err()
            {
                record_rpc_error(
                    NetconfOperation::KillSession,
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
                NetconfOperation::KillSession,
                NetconfErrorTag::OperationNotSupported,
                started.elapsed(),
            );
            return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                Some(message_id),
                reply_attrs,
                RpcError::operation_not_supported(),
            ));
        };

        if request.session_id == current_session_id {
            if self
                .audit
                .record(
                    &AuditEvent::new(
                        request_id,
                        principal,
                        self.transport,
                        AuditOperation::Exec,
                        audit_failed("invalid-value"),
                    )
                    .with_paths([kill_path]),
                )
                .is_err()
            {
                record_rpc_error(
                    NetconfOperation::KillSession,
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
                NetconfOperation::KillSession,
                NetconfErrorTag::InvalidValue,
                started.elapsed(),
            );
            tracing::debug!(
                operation = "kill-session",
                error_tag = NetconfErrorTag::InvalidValue.as_str(),
                "NETCONF kill-session rejected self-kill"
            );
            return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                Some(message_id),
                reply_attrs,
                RpcError::invalid_value(),
            ));
        }

        match sessions.terminate_after(request.session_id, || {
            self.audit
                .record(
                    &AuditEvent::new(
                        request_id,
                        principal,
                        self.transport,
                        AuditOperation::Exec,
                        AuditOutcome::Success,
                    )
                    .with_paths([kill_path.clone()]),
                )
                .map_err(|_| ())
        }) {
            Err(()) => {
                record_rpc_error(
                    NetconfOperation::KillSession,
                    NetconfErrorTag::OperationFailed,
                    started.elapsed(),
                );
                RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    Some(message_id),
                    reply_attrs,
                    RpcError::operation_failed(),
                ))
            }
            Ok(KillSessionResult::Terminated) => {
                record_rpc_success(NetconfOperation::KillSession, started.elapsed());
                tracing::debug!(operation = "kill-session", "NETCONF kill-session succeeded");
                RpcHandlingResult::keep_open(rpc_ok_empty_reply_with_attrs(message_id, reply_attrs))
            }
            Ok(KillSessionResult::NotFound) => {
                if self
                    .audit
                    .record(
                        &AuditEvent::new(
                            request_id,
                            principal,
                            self.transport,
                            AuditOperation::Exec,
                            audit_failed("data-missing"),
                        )
                        .with_paths([kill_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::KillSession,
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
                    NetconfOperation::KillSession,
                    NetconfErrorTag::DataMissing,
                    started.elapsed(),
                );
                tracing::debug!(
                    operation = "kill-session",
                    error_tag = NetconfErrorTag::DataMissing.as_str(),
                    "NETCONF kill-session target not found"
                );
                RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    Some(message_id),
                    reply_attrs,
                    RpcError::data_missing(),
                ))
            }
        }
    }

    fn handle_lock(
        &self,
        request: &XmlLockRequest,
        context: RpcExecContext<'_>,
        session_context: Option<(u64, &SessionRegistry)>,
    ) -> RpcHandlingResult {
        let RpcExecContext {
            request_id,
            principal,
            message_id,
            reply_attrs,
            started,
        } = context;
        let lock_path = schema_node_path(NETCONF_LOCK_PATH);
        if request.target != crate::xml::Datastore::Running {
            if self
                .audit
                .record(
                    &AuditEvent::new(
                        request_id,
                        principal,
                        self.transport,
                        AuditOperation::Exec,
                        audit_failed("operation-not-supported"),
                    )
                    .with_paths([lock_path]),
                )
                .is_err()
            {
                record_rpc_error(
                    NetconfOperation::Lock,
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
                NetconfOperation::Lock,
                NetconfErrorTag::OperationNotSupported,
                started.elapsed(),
            );
            return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                Some(message_id),
                reply_attrs,
                RpcError::operation_not_supported(),
            ));
        }

        match self.authorize_exec(principal, NETCONF_LOCK_PATH) {
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
                        .with_paths([lock_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::Lock,
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
                    NetconfOperation::Lock,
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
                            AuditOperation::Exec,
                            audit_failed("resource-denied"),
                        )
                        .with_paths([lock_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::Lock,
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
                    NetconfOperation::Lock,
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

        let Some((current_session_id, sessions)) = session_context else {
            if self
                .audit
                .record(
                    &AuditEvent::new(
                        request_id,
                        principal,
                        self.transport,
                        AuditOperation::Exec,
                        audit_failed("operation-not-supported"),
                    )
                    .with_paths([lock_path]),
                )
                .is_err()
            {
                record_rpc_error(
                    NetconfOperation::Lock,
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
                NetconfOperation::Lock,
                NetconfErrorTag::OperationNotSupported,
                started.elapsed(),
            );
            return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                Some(message_id),
                reply_attrs,
                RpcError::operation_not_supported(),
            ));
        };

        match sessions.lock_running_after(current_session_id, || {
            self.audit
                .record(
                    &AuditEvent::new(
                        request_id,
                        principal,
                        self.transport,
                        AuditOperation::Exec,
                        AuditOutcome::Success,
                    )
                    .with_paths([lock_path.clone()]),
                )
                .map_err(|_| ())
        }) {
            Ok(LockRunningResult::Acquired) => {
                record_rpc_success(NetconfOperation::Lock, started.elapsed());
                RpcHandlingResult::keep_open(rpc_ok_empty_reply_with_attrs(message_id, reply_attrs))
            }
            Ok(LockRunningResult::Denied { owner_session_id }) => self.lock_denied_reply(
                &RpcExecContext {
                    request_id,
                    principal,
                    message_id,
                    reply_attrs,
                    started,
                },
                NETCONF_LOCK_PATH,
                owner_session_id,
                NetconfOperation::Lock,
            ),
            Ok(LockRunningResult::SessionNotRegistered) => {
                let _ = self.audit.record(
                    &AuditEvent::new(
                        request_id,
                        principal,
                        self.transport,
                        AuditOperation::Exec,
                        audit_failed("operation-failed"),
                    )
                    .with_paths([lock_path]),
                );
                record_rpc_error(
                    NetconfOperation::Lock,
                    NetconfErrorTag::OperationFailed,
                    started.elapsed(),
                );
                RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    Some(message_id),
                    reply_attrs,
                    RpcError::operation_failed(),
                ))
            }
            Err(()) => {
                record_rpc_error(
                    NetconfOperation::Lock,
                    NetconfErrorTag::OperationFailed,
                    started.elapsed(),
                );
                RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    Some(message_id),
                    reply_attrs,
                    RpcError::operation_failed(),
                ))
            }
        }
    }

    fn handle_unlock(
        &self,
        request: &XmlUnlockRequest,
        context: RpcExecContext<'_>,
        session_context: Option<(u64, &SessionRegistry)>,
    ) -> RpcHandlingResult {
        let RpcExecContext {
            request_id,
            principal,
            message_id,
            reply_attrs,
            started,
        } = context;
        let unlock_path = schema_node_path(NETCONF_UNLOCK_PATH);
        if request.target != crate::xml::Datastore::Running {
            if self
                .audit
                .record(
                    &AuditEvent::new(
                        request_id,
                        principal,
                        self.transport,
                        AuditOperation::Exec,
                        audit_failed("operation-not-supported"),
                    )
                    .with_paths([unlock_path]),
                )
                .is_err()
            {
                record_rpc_error(
                    NetconfOperation::Unlock,
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
                NetconfOperation::Unlock,
                NetconfErrorTag::OperationNotSupported,
                started.elapsed(),
            );
            return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                Some(message_id),
                reply_attrs,
                RpcError::operation_not_supported(),
            ));
        }

        match self.authorize_exec(principal, NETCONF_UNLOCK_PATH) {
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
                        .with_paths([unlock_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::Unlock,
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
                    NetconfOperation::Unlock,
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
                            AuditOperation::Exec,
                            audit_failed("resource-denied"),
                        )
                        .with_paths([unlock_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::Unlock,
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
                    NetconfOperation::Unlock,
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

        let Some((current_session_id, sessions)) = session_context else {
            if self
                .audit
                .record(
                    &AuditEvent::new(
                        request_id,
                        principal,
                        self.transport,
                        AuditOperation::Exec,
                        audit_failed("operation-not-supported"),
                    )
                    .with_paths([unlock_path]),
                )
                .is_err()
            {
                record_rpc_error(
                    NetconfOperation::Unlock,
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
                NetconfOperation::Unlock,
                NetconfErrorTag::OperationNotSupported,
                started.elapsed(),
            );
            return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                Some(message_id),
                reply_attrs,
                RpcError::operation_not_supported(),
            ));
        };

        match sessions.unlock_running_after(current_session_id, || {
            self.audit
                .record(
                    &AuditEvent::new(
                        request_id,
                        principal,
                        self.transport,
                        AuditOperation::Exec,
                        AuditOutcome::Success,
                    )
                    .with_paths([unlock_path.clone()]),
                )
                .map_err(|_| ())
        }) {
            Ok(UnlockRunningResult::Unlocked) => {
                record_rpc_success(NetconfOperation::Unlock, started.elapsed());
                RpcHandlingResult::keep_open(rpc_ok_empty_reply_with_attrs(message_id, reply_attrs))
            }
            Ok(UnlockRunningResult::NotOwner { owner_session_id }) => self.lock_denied_reply(
                &RpcExecContext {
                    request_id,
                    principal,
                    message_id,
                    reply_attrs,
                    started,
                },
                NETCONF_UNLOCK_PATH,
                owner_session_id,
                NetconfOperation::Unlock,
            ),
            Ok(UnlockRunningResult::NotLocked | UnlockRunningResult::SessionNotRegistered) => {
                if self
                    .audit
                    .record(
                        &AuditEvent::new(
                            request_id,
                            principal,
                            self.transport,
                            AuditOperation::Exec,
                            audit_failed("operation-failed"),
                        )
                        .with_paths([unlock_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::Unlock,
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
                    NetconfOperation::Unlock,
                    NetconfErrorTag::OperationFailed,
                    started.elapsed(),
                );
                RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    Some(message_id),
                    reply_attrs,
                    RpcError::operation_failed(),
                ))
            }
            Err(()) => {
                record_rpc_error(
                    NetconfOperation::Unlock,
                    NetconfErrorTag::OperationFailed,
                    started.elapsed(),
                );
                RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    Some(message_id),
                    reply_attrs,
                    RpcError::operation_failed(),
                ))
            }
        }
    }

    fn lock_denied_reply(
        &self,
        context: &RpcExecContext<'_>,
        path: &'static str,
        owner_session_id: u64,
        operation: NetconfOperation,
    ) -> RpcHandlingResult {
        if self
            .audit
            .record(
                &AuditEvent::new(
                    context.request_id,
                    context.principal,
                    self.transport,
                    AuditOperation::Exec,
                    audit_failed("lock-denied"),
                )
                .with_paths([schema_node_path(path)]),
            )
            .is_err()
        {
            record_rpc_error(
                operation,
                NetconfErrorTag::OperationFailed,
                context.started.elapsed(),
            );
            return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                Some(context.message_id),
                context.reply_attrs,
                RpcError::operation_failed(),
            ));
        }
        record_rpc_error(
            operation,
            NetconfErrorTag::LockDenied,
            context.started.elapsed(),
        );
        RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
            Some(context.message_id),
            context.reply_attrs,
            RpcError::lock_denied(owner_session_id),
        ))
    }

    async fn handle_edit_config(
        &self,
        request: &XmlEditConfigRequest,
        context: RpcExecContext<'_>,
        session_context: Option<(u64, &SessionRegistry)>,
    ) -> RpcHandlingResult {
        if !self.binding.writable_running_capability() {
            return self.edit_config_failure_reply(
                &context,
                audit_failed("operation-not-supported"),
                RpcError::operation_not_supported(),
            );
        }

        if request.target != XmlDatastore::Running
            || request.error_option != EditErrorOption::StopOnError
            || request.test_option_explicit
            || request.test_option == EditTestOption::TestOnly
        {
            return self.edit_config_failure_reply(
                &context,
                audit_failed("operation-not-supported"),
                RpcError::operation_not_supported(),
            );
        }

        match self.authorize_exec(context.principal, NETCONF_EDIT_CONFIG_PATH) {
            Ok(true) => {}
            Ok(false) => {
                return self.edit_config_failure_reply(
                    &context,
                    audit_denied("access-denied"),
                    RpcError::access_denied(),
                );
            }
            Err(()) => {
                return self.edit_config_failure_reply(
                    &context,
                    audit_failed("resource-denied"),
                    RpcError::resource_denied(),
                );
            }
        }

        let Some((current_session_id, sessions)) = session_context else {
            return self.edit_config_failure_reply(
                &context,
                audit_failed("operation-not-supported"),
                RpcError::operation_not_supported(),
            );
        };

        let _write_guard = match sessions.begin_running_write(current_session_id) {
            RunningWriteResult::Acquired(guard) => guard,
            RunningWriteResult::Denied { owner_session_id } => {
                return self.edit_config_lock_denied_reply(&context, owner_session_id);
            }
            RunningWriteResult::SessionNotRegistered => {
                return self.edit_config_failure_reply(
                    &context,
                    audit_failed("operation-failed"),
                    RpcError::operation_failed(),
                );
            }
        };

        let bus = self.binding.config_bus();
        let snapshot = bus.current_snapshot();
        let candidate = match self
            .binding
            .build_edit_config_candidate(snapshot.config.as_ref(), request)
        {
            Ok(candidate) => candidate,
            Err(EditConfigError::Unsupported) => {
                return self.edit_config_failure_reply(
                    &context,
                    audit_failed("operation-not-supported"),
                    RpcError::operation_not_supported(),
                );
            }
            Err(EditConfigError::InvalidValue) => {
                return self.edit_config_failure_reply(
                    &context,
                    audit_failed("invalid-value"),
                    RpcError::invalid_value(),
                );
            }
            Err(EditConfigError::Failed { .. }) => {
                return self.edit_config_failure_reply(
                    &context,
                    audit_failed("operation-failed"),
                    RpcError::operation_failed(),
                );
            }
        };

        let commit_request = CommitRequest::commit(
            context.request_id,
            context.principal.clone(),
            self.transport,
            RequestSource::Northbound,
            ConfigOperation::Patch,
            candidate.candidate,
            candidate.changed_paths,
            Instant::now() + Duration::from_secs(30),
        )
        .with_base_version(snapshot.version);

        match bus.submit(commit_request).await {
            Ok(result) => {
                let paths = self.schema_paths_for_changed_paths(&result.changed_paths);
                if self
                    .audit
                    .record(
                        &AuditEvent::new(
                            context.request_id,
                            context.principal,
                            self.transport,
                            AuditOperation::Update,
                            AuditOutcome::Success,
                        )
                        .with_paths(paths),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::EditConfig,
                        NetconfErrorTag::OperationFailed,
                        context.started.elapsed(),
                    );
                    return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                        Some(context.message_id),
                        context.reply_attrs,
                        RpcError::operation_failed(),
                    ));
                }
                record_rpc_success(NetconfOperation::EditConfig, context.started.elapsed());
                RpcHandlingResult::keep_open(rpc_ok_empty_reply_with_attrs(
                    context.message_id,
                    context.reply_attrs,
                ))
            }
            Err(error) => {
                let classification = commit_error_to_netconf(error.code);
                self.edit_config_failure_reply(
                    &context,
                    audit_failed(error.code.as_str()),
                    rpc_error_for_netconf(classification),
                )
            }
        }
    }

    fn edit_config_failure_reply(
        &self,
        context: &RpcExecContext<'_>,
        outcome: AuditOutcome,
        rpc_error: RpcError,
    ) -> RpcHandlingResult {
        if self
            .audit
            .record(
                &AuditEvent::new(
                    context.request_id,
                    context.principal,
                    self.transport,
                    AuditOperation::Update,
                    outcome,
                )
                .with_paths([schema_node_path(NETCONF_EDIT_CONFIG_PATH)]),
            )
            .is_err()
        {
            record_rpc_error(
                NetconfOperation::EditConfig,
                NetconfErrorTag::OperationFailed,
                context.started.elapsed(),
            );
            return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                Some(context.message_id),
                context.reply_attrs,
                RpcError::operation_failed(),
            ));
        }

        record_rpc_error(
            NetconfOperation::EditConfig,
            rpc_error.classification.tag,
            context.started.elapsed(),
        );
        RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
            Some(context.message_id),
            context.reply_attrs,
            rpc_error,
        ))
    }

    fn edit_config_lock_denied_reply(
        &self,
        context: &RpcExecContext<'_>,
        owner_session_id: u64,
    ) -> RpcHandlingResult {
        if self
            .audit
            .record(
                &AuditEvent::new(
                    context.request_id,
                    context.principal,
                    self.transport,
                    AuditOperation::Update,
                    audit_failed("lock-denied"),
                )
                .with_paths([schema_node_path(NETCONF_EDIT_CONFIG_PATH)]),
            )
            .is_err()
        {
            record_rpc_error(
                NetconfOperation::EditConfig,
                NetconfErrorTag::OperationFailed,
                context.started.elapsed(),
            );
            return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                Some(context.message_id),
                context.reply_attrs,
                RpcError::operation_failed(),
            ));
        }

        record_rpc_error(
            NetconfOperation::EditConfig,
            NetconfErrorTag::LockDenied,
            context.started.elapsed(),
        );
        RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
            Some(context.message_id),
            context.reply_attrs,
            RpcError::lock_denied(owner_session_id),
        ))
    }

    fn schema_paths_for_changed_paths(
        &self,
        changed_paths: &[opc_config_model::YangPath],
    ) -> Vec<SchemaNodePath> {
        let registry = self.binding.schema_registry();
        let mut paths = Vec::new();
        let mut saw_unknown = false;
        for path in changed_paths {
            let Some(node) = registry.node(path.as_str()) else {
                saw_unknown = true;
                continue;
            };
            let schema_path = schema_node_path(node.path);
            if !paths.contains(&schema_path) {
                paths.push(schema_path);
            }
        }
        if paths.is_empty() || saw_unknown {
            let edit_path = schema_node_path(NETCONF_EDIT_CONFIG_PATH);
            if !paths.contains(&edit_path) {
                paths.push(edit_path);
            }
        }
        paths
    }

    fn handle_validate(
        &self,
        request: &XmlValidateRequest,
        context: RpcExecContext<'_>,
    ) -> RpcHandlingResult {
        let validate_path = schema_node_path(NETCONF_VALIDATE_PATH);
        if request.source != crate::xml::Datastore::Running {
            if self
                .audit
                .record(
                    &AuditEvent::new(
                        context.request_id,
                        context.principal,
                        self.transport,
                        AuditOperation::Validate,
                        audit_failed("operation-not-supported"),
                    )
                    .with_paths([validate_path]),
                )
                .is_err()
            {
                record_rpc_error(
                    NetconfOperation::Validate,
                    NetconfErrorTag::OperationFailed,
                    context.started.elapsed(),
                );
                return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    Some(context.message_id),
                    context.reply_attrs,
                    RpcError::operation_failed(),
                ));
            }
            record_rpc_error(
                NetconfOperation::Validate,
                NetconfErrorTag::OperationNotSupported,
                context.started.elapsed(),
            );
            return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                Some(context.message_id),
                context.reply_attrs,
                RpcError::operation_not_supported(),
            ));
        }

        match self.authorize_exec(context.principal, NETCONF_VALIDATE_PATH) {
            Ok(true) => {}
            Ok(false) => {
                if self
                    .audit
                    .record(
                        &AuditEvent::new(
                            context.request_id,
                            context.principal,
                            self.transport,
                            AuditOperation::Validate,
                            audit_denied("access-denied"),
                        )
                        .with_paths([validate_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::Validate,
                        NetconfErrorTag::OperationFailed,
                        context.started.elapsed(),
                    );
                    return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                        Some(context.message_id),
                        context.reply_attrs,
                        RpcError::operation_failed(),
                    ));
                }
                record_rpc_error(
                    NetconfOperation::Validate,
                    NetconfErrorTag::AccessDenied,
                    context.started.elapsed(),
                );
                return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    Some(context.message_id),
                    context.reply_attrs,
                    RpcError::access_denied(),
                ));
            }
            Err(_) => {
                if self
                    .audit
                    .record(
                        &AuditEvent::new(
                            context.request_id,
                            context.principal,
                            self.transport,
                            AuditOperation::Validate,
                            audit_failed("resource-denied"),
                        )
                        .with_paths([validate_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::Validate,
                        NetconfErrorTag::OperationFailed,
                        context.started.elapsed(),
                    );
                    return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                        Some(context.message_id),
                        context.reply_attrs,
                        RpcError::operation_failed(),
                    ));
                }
                record_rpc_error(
                    NetconfOperation::Validate,
                    NetconfErrorTag::ResourceDenied,
                    context.started.elapsed(),
                );
                return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                    Some(context.message_id),
                    context.reply_attrs,
                    RpcError::resource_denied(),
                ));
            }
        }

        let snapshot = self.binding.config_bus().current_snapshot();
        let validation_context = ValidationContext {
            request_id: context.request_id,
            principal: context.principal.clone(),
            transport: self.transport,
            source: RequestSource::Northbound,
            operation: ConfigOperation::Replace,
            mode: CommitMode::ValidateOnly,
            base_version: snapshot.version,
            previous: Some(Arc::clone(&snapshot.config)),
        };
        let validation = panic::catch_unwind(AssertUnwindSafe(|| {
            snapshot
                .config
                .validate_syntax()
                .map_err(|_| "syntax-validation-failed")?;
            snapshot
                .config
                .validate_semantics(&validation_context)
                .map_err(|_| "semantic-validation-failed")?;
            Ok::<_, &'static str>(())
        }));

        match validation {
            Ok(Ok(())) => {
                if self
                    .audit
                    .record(
                        &AuditEvent::new(
                            context.request_id,
                            context.principal,
                            self.transport,
                            AuditOperation::Validate,
                            AuditOutcome::Success,
                        )
                        .with_paths([validate_path]),
                    )
                    .is_err()
                {
                    record_rpc_error(
                        NetconfOperation::Validate,
                        NetconfErrorTag::OperationFailed,
                        context.started.elapsed(),
                    );
                    return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                        Some(context.message_id),
                        context.reply_attrs,
                        RpcError::operation_failed(),
                    ));
                }
                record_rpc_success(NetconfOperation::Validate, context.started.elapsed());
                RpcHandlingResult::keep_open(rpc_ok_empty_reply_with_attrs(
                    context.message_id,
                    context.reply_attrs,
                ))
            }
            Ok(Err(reason)) => self.validate_failed_reply(context, validate_path, reason),
            Err(_) => self.validate_failed_reply(context, validate_path, "operation-failed"),
        }
    }

    fn validate_failed_reply(
        &self,
        context: RpcExecContext<'_>,
        validate_path: SchemaNodePath,
        reason: &'static str,
    ) -> RpcHandlingResult {
        if self
            .audit
            .record(
                &AuditEvent::new(
                    context.request_id,
                    context.principal,
                    self.transport,
                    AuditOperation::Validate,
                    audit_failed(reason),
                )
                .with_paths([validate_path]),
            )
            .is_err()
        {
            record_rpc_error(
                NetconfOperation::Validate,
                NetconfErrorTag::OperationFailed,
                context.started.elapsed(),
            );
            return RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
                Some(context.message_id),
                context.reply_attrs,
                RpcError::operation_failed(),
            ));
        }
        record_rpc_error(
            NetconfOperation::Validate,
            NetconfErrorTag::OperationFailed,
            context.started.elapsed(),
        );
        RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
            Some(context.message_id),
            context.reply_attrs,
            RpcError::operation_failed(),
        ))
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
        err: &RpcParseError,
    ) -> Result<(), AuditError> {
        let reason = match (
            err.error.classification().error_type,
            err.error.classification().tag,
        ) {
            (NetconfErrorType::Rpc, NetconfErrorTag::MalformedMessage) => "malformed-message",
            (_, NetconfErrorTag::UnknownNamespace) => "unknown-namespace",
            (_, NetconfErrorTag::MissingAttribute) => "missing-attribute",
            (_, NetconfErrorTag::MissingElement) => "missing-element",
            (_, NetconfErrorTag::InvalidValue) => "invalid-value",
            (_, NetconfErrorTag::TooBig) => "too-big",
            (_, NetconfErrorTag::BadElement) => "bad-element",
            (_, NetconfErrorTag::OperationNotSupported) => "operation-not-supported",
            _ => "operation-failed",
        };
        let event = AuditEvent::new(
            request_id,
            principal,
            self.transport,
            audit_operation_for_parse_failure(err),
            audit_failed(reason),
        );
        let event = match err.operation_hint {
            Some(RpcOperationHint::EditConfig) => {
                event.with_paths([schema_node_path(NETCONF_EDIT_CONFIG_PATH)])
            }
            Some(RpcOperationHint::Lock) => event.with_paths([schema_node_path(NETCONF_LOCK_PATH)]),
            Some(RpcOperationHint::Unlock) => {
                event.with_paths([schema_node_path(NETCONF_UNLOCK_PATH)])
            }
            Some(RpcOperationHint::KillSession) => {
                event.with_paths([schema_node_path(NETCONF_KILL_SESSION_PATH)])
            }
            Some(RpcOperationHint::Validate) => {
                event.with_paths([schema_node_path(NETCONF_VALIDATE_PATH)])
            }
            Some(RpcOperationHint::Get | RpcOperationHint::GetConfig) | None => event,
        };
        self.audit.record(&event)
    }
}

fn audit_operation_for_parse_failure(err: &RpcParseError) -> AuditOperation {
    match err.operation_hint {
        Some(RpcOperationHint::EditConfig) => AuditOperation::Update,
        Some(RpcOperationHint::Lock | RpcOperationHint::Unlock) => AuditOperation::Exec,
        Some(RpcOperationHint::KillSession) => AuditOperation::Exec,
        Some(RpcOperationHint::Validate) => AuditOperation::Validate,
        Some(RpcOperationHint::Get | RpcOperationHint::GetConfig) | None => AuditOperation::Read,
    }
}

fn netconf_operation_for_parse_failure(err: &RpcParseError) -> NetconfOperation {
    match err.operation_hint {
        Some(RpcOperationHint::EditConfig) => NetconfOperation::EditConfig,
        Some(RpcOperationHint::Get) => NetconfOperation::Get,
        Some(RpcOperationHint::GetConfig) => NetconfOperation::GetConfig,
        Some(RpcOperationHint::Lock) => NetconfOperation::Lock,
        Some(RpcOperationHint::Unlock) => NetconfOperation::Unlock,
        Some(RpcOperationHint::KillSession) => NetconfOperation::KillSession,
        Some(RpcOperationHint::Validate) => NetconfOperation::Validate,
        None => NetconfOperation::Unknown,
    }
}

fn rpc_error_for_netconf(classification: NetconfError) -> RpcError {
    RpcError::new(classification, netconf_error_message(classification.tag))
}

fn netconf_error_message(tag: NetconfErrorTag) -> &'static str {
    match tag {
        NetconfErrorTag::InUse => "in use",
        NetconfErrorTag::InvalidValue => "invalid value",
        NetconfErrorTag::TooBig => "request is too large",
        NetconfErrorTag::MissingAttribute => "missing attribute",
        NetconfErrorTag::BadAttribute => "bad attribute",
        NetconfErrorTag::UnknownAttribute => "unknown attribute",
        NetconfErrorTag::MissingElement => "missing element",
        NetconfErrorTag::BadElement => "bad element",
        NetconfErrorTag::UnknownElement => "unknown element",
        NetconfErrorTag::UnknownNamespace => "unknown namespace",
        NetconfErrorTag::AccessDenied => "access denied",
        NetconfErrorTag::LockDenied => "lock denied",
        NetconfErrorTag::ResourceDenied => "resource denied",
        NetconfErrorTag::DataExists => "data exists",
        NetconfErrorTag::DataMissing => "data missing",
        NetconfErrorTag::OperationNotSupported => "operation not supported",
        NetconfErrorTag::OperationFailed => "operation failed",
        NetconfErrorTag::MalformedMessage => "malformed message",
        _ => "operation failed",
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
    use std::num::NonZeroU32;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use opc_config_bus::{
        AuthorizationContext, AuthorizationError, ConfigAuthorizer, ConfigBus, MockManagedDatastore,
    };
    use opc_config_model::{
        AuthStrength, ConfigError, ConfigOperation, OpcConfig, RequestSource, TransportType,
        TrustedPrincipal, ValidationContext, ValidationError, WorkloadIdentity, YangPath,
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
        BindingError, EditConfigCandidate, EditConfigError, NetconfMonitoringCapability,
        ReadSelection, WithDefaultsCapability, YangLibraryCapability,
    };
    use crate::capabilities::{
        NETCONF_BASE_1_0, NETCONF_BASE_1_1, NETCONF_BASE_NS, NETCONF_MONITORING_NS,
        WITH_DEFAULTS_NS, WRITABLE_RUNNING_1_0,
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
            previous: &Self,
            _deltas: &[Self::Delta],
        ) -> Result<Vec<YangPath>, ConfigError> {
            let mut paths = Vec::new();
            if self.hostname != previous.hostname {
                paths.push(YangPath::new("/sys:system/sys:hostname").expect("hostname path"));
            }
            if self.secret != previous.secret {
                paths.push(YangPath::new("/sys:system/sys:secret").expect("secret path"));
            }
            Ok(paths)
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

    #[derive(Clone)]
    struct ValidationConfig {
        mode: Arc<AtomicU8>,
        saw_previous: Arc<AtomicBool>,
    }

    impl ValidationConfig {
        fn new() -> Self {
            Self {
                mode: Arc::new(AtomicU8::new(0)),
                saw_previous: Arc::new(AtomicBool::new(false)),
            }
        }

        fn set_syntax_failure(&self) {
            self.mode.store(1, Ordering::SeqCst);
        }

        fn set_semantic_failure(&self) {
            self.mode.store(2, Ordering::SeqCst);
        }

        fn saw_previous(&self) -> bool {
            self.saw_previous.load(Ordering::SeqCst)
        }
    }

    impl OpcConfig for ValidationConfig {
        type Delta = ();

        fn schema_digest(&self) -> SchemaDigest {
            SchemaDigest::from_bytes([2u8; 32])
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
            if self.mode.load(Ordering::SeqCst) == 1 {
                return Err(ValidationError::syntax(
                    "syntax failure contains /sys:system/sys:secret",
                ));
            }
            Ok(())
        }

        fn validate_semantics(&self, ctx: &ValidationContext<Self>) -> Result<(), ValidationError> {
            if ctx.previous.is_some() {
                self.saw_previous.store(true, Ordering::SeqCst);
            }
            if self.mode.load(Ordering::SeqCst) == 2 {
                return Err(ValidationError::semantics(
                    "semantic failure contains /sys:system/sys:secret",
                ));
            }
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

    struct ValidationBinding {
        bus: Arc<ConfigBus<ValidationConfig>>,
    }

    impl NetconfConfigBinding<ValidationConfig> for ValidationBinding {
        fn config_bus(&self) -> Arc<ConfigBus<ValidationConfig>> {
            Arc::clone(&self.bus)
        }

        fn schema_registry(&self) -> &'static dyn SchemaRegistry {
            &REGISTRY
        }

        fn render_running_config(
            &self,
            _config: &ValidationConfig,
            _selection: ReadSelection<'_>,
        ) -> Result<String, BindingError> {
            Ok(String::new())
        }
    }

    struct NonWritableEditBinding {
        bus: Arc<ConfigBus<DemoConfig>>,
        candidate_builder_called: Arc<AtomicBool>,
    }

    impl NetconfConfigBinding<DemoConfig> for NonWritableEditBinding {
        fn config_bus(&self) -> Arc<ConfigBus<DemoConfig>> {
            Arc::clone(&self.bus)
        }

        fn schema_registry(&self) -> &'static dyn SchemaRegistry {
            &REGISTRY
        }

        fn render_running_config(
            &self,
            _config: &DemoConfig,
            _selection: ReadSelection<'_>,
        ) -> Result<String, BindingError> {
            Ok(String::new())
        }

        fn build_edit_config_candidate(
            &self,
            running: &DemoConfig,
            _request: &crate::xml::EditConfigRequest,
        ) -> Result<EditConfigCandidate<DemoConfig>, EditConfigError> {
            self.candidate_builder_called.store(true, Ordering::SeqCst);
            let mut candidate = running.clone();
            candidate.hostname = "amf-2".to_string();
            Ok(EditConfigCandidate::new(
                candidate,
                [YangPath::new("/sys:system/sys:hostname").expect("hostname path")],
            ))
        }
    }

    struct WritableCountingEditBinding {
        bus: Arc<ConfigBus<DemoConfig>>,
        candidate_builder_called: Arc<AtomicBool>,
    }

    impl NetconfConfigBinding<DemoConfig> for WritableCountingEditBinding {
        fn config_bus(&self) -> Arc<ConfigBus<DemoConfig>> {
            Arc::clone(&self.bus)
        }

        fn schema_registry(&self) -> &'static dyn SchemaRegistry {
            &REGISTRY
        }

        fn render_running_config(
            &self,
            _config: &DemoConfig,
            _selection: ReadSelection<'_>,
        ) -> Result<String, BindingError> {
            Ok(String::new())
        }

        fn writable_running_capability(&self) -> bool {
            true
        }

        fn build_edit_config_candidate(
            &self,
            running: &DemoConfig,
            _request: &crate::xml::EditConfigRequest,
        ) -> Result<EditConfigCandidate<DemoConfig>, EditConfigError> {
            self.candidate_builder_called.store(true, Ordering::SeqCst);
            let mut candidate = running.clone();
            candidate.hostname = "amf-2".to_string();
            Ok(EditConfigCandidate::new(
                candidate,
                [YangPath::new("/sys:system/sys:hostname").expect("hostname path")],
            ))
        }
    }

    #[derive(Debug, Clone)]
    struct ObservedAuthorization {
        transport: TransportType,
        source: RequestSource,
        operation: ConfigOperation,
        changed_paths: Vec<YangPath>,
    }

    #[derive(Debug)]
    struct DenyingConfigAuthorizer {
        called: Arc<AtomicBool>,
        observed: Arc<Mutex<Option<ObservedAuthorization>>>,
    }

    #[async_trait::async_trait]
    impl ConfigAuthorizer for DenyingConfigAuthorizer {
        async fn authorize(&self, ctx: &AuthorizationContext) -> Result<(), AuthorizationError> {
            self.called.store(true, Ordering::SeqCst);
            *self.observed.lock().expect("authorizer observation mutex") =
                Some(ObservedAuthorization {
                    transport: ctx.transport,
                    source: ctx.source,
                    operation: ctx.operation,
                    changed_paths: ctx.changed_paths.clone(),
                });
            Err(AuthorizationError::new("do-not-leak-authorizer-detail"))
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

        fn writable_running_capability(&self) -> bool {
            true
        }

        fn build_edit_config_candidate(
            &self,
            running: &DemoConfig,
            request: &crate::xml::EditConfigRequest,
        ) -> Result<EditConfigCandidate<DemoConfig>, EditConfigError> {
            if request.config_xml.contains("invalid-edit-value") {
                return Err(EditConfigError::InvalidValue);
            }
            if request.config_xml.contains("failed-edit-value") {
                return Err(EditConfigError::failed("do-not-leak"));
            }
            if request.config_xml.contains("unsupported-edit-shape") {
                return Err(EditConfigError::Unsupported);
            }
            if !request
                .config_xml
                .contains("<sys:hostname>amf-2</sys:hostname>")
            {
                return Err(EditConfigError::Unsupported);
            }

            let mut candidate = running.clone();
            candidate.hostname = "amf-2".to_string();
            Ok(EditConfigCandidate::new(
                candidate,
                [YangPath::new("/sys:system/sys:hostname").expect("hostname path")],
            ))
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

    fn session_id(id: u32) -> NonZeroU32 {
        NonZeroU32::new(id).expect("nonzero test session id")
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

    fn allow_edit_config_rule(modules: &ModuleRegistry) -> NacmRule {
        NacmRule::allow(
            NacmAction::Exec,
            YangPathPattern::parse(NETCONF_EDIT_CONFIG_PATH, modules)
                .expect("allow edit-config path"),
        )
    }

    fn allow_kill_session_rule(modules: &ModuleRegistry) -> NacmRule {
        NacmRule::allow(
            NacmAction::Exec,
            YangPathPattern::parse(NETCONF_KILL_SESSION_PATH, modules)
                .expect("allow kill-session path"),
        )
    }

    fn allow_lock_rule(modules: &ModuleRegistry) -> NacmRule {
        NacmRule::allow(
            NacmAction::Exec,
            YangPathPattern::parse(NETCONF_LOCK_PATH, modules).expect("allow lock path"),
        )
    }

    fn allow_unlock_rule(modules: &ModuleRegistry) -> NacmRule {
        NacmRule::allow(
            NacmAction::Exec,
            YangPathPattern::parse(NETCONF_UNLOCK_PATH, modules).expect("allow unlock path"),
        )
    }

    fn allow_validate_rule(modules: &ModuleRegistry) -> NacmRule {
        NacmRule::allow(
            NacmAction::Exec,
            YangPathPattern::parse(NETCONF_VALIDATE_PATH, modules).expect("allow validate path"),
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
            .add_rule(allow_lock_rule(&modules))
            .add_rule(allow_unlock_rule(&modules))
            .add_rule(allow_validate_rule(&modules))
            .add_rule(allow_edit_config_rule(&modules))
            .add_rule(allow_kill_session_rule(&modules))
            .build()
    }

    fn policy_allow_system_but_deny_edit_config() -> NacmPolicy {
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
            .add_rule(allow_lock_rule(&modules))
            .add_rule(allow_unlock_rule(&modules))
            .add_rule(allow_validate_rule(&modules))
            .add_rule(allow_kill_session_rule(&modules))
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
            .add_rule(allow_kill_session_rule(&modules))
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

    async fn validation_server_fixture() -> (
        ReadOnlyNetconfServer<ValidationConfig, ValidationBinding, FixedPolicy, CapturingAudit>,
        ValidationConfig,
        CapturingAudit,
    ) {
        let config = ValidationConfig::new();
        let bus = Arc::new(
            ConfigBus::new_dev_only(config.clone(), MockManagedDatastore::new())
                .await
                .expect("bus"),
        );
        let binding = ValidationBinding { bus };
        let audit = CapturingAudit::default();
        let server = ReadOnlyNetconfServer::new(
            binding,
            FixedPolicy(policy_allow_system_but_deny_secret()),
            audit.clone(),
            TransportType::NetconfTls,
        )
        .expect("server");
        (server, config, audit)
    }

    async fn server_fixture_with_policy_source_and_audit<P, A>(
        policy_source: P,
        audit: A,
    ) -> ReadOnlyNetconfServer<DemoConfig, TestBinding, P, A>
    where
        P: PolicySource,
        A: AuditSink,
    {
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
        ReadOnlyNetconfServer::new(binding, policy_source, audit, TransportType::NetconfTls)
            .expect("server")
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

    fn lock_rpc(target: &str) -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="303"><lock><target><{target}/></target></lock></rpc>"#
        )
    }

    fn unlock_rpc(target: &str) -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="304"><unlock><target><{target}/></target></unlock></rpc>"#
        )
    }

    fn validate_rpc(source: &str) -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="305"><validate><source><{source}/></source></validate></rpc>"#
        )
    }

    fn kill_session_rpc(session_id: u64) -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="302"><kill-session><session-id>{session_id}</session-id></kill-session></rpc>"#
        )
    }

    fn unsupported_edit_config_rpc() -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="401"><edit-config><target><running/></target><config><sys:secret xmlns:sys="urn:opc:demo">do-not-leak</sys:secret></config></edit-config></rpc>"#
        )
    }

    fn edit_config_hostname_rpc(message_id: &str) -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="{message_id}"><edit-config><target><running/></target><config><sys:system xmlns:sys="urn:opc:demo"><sys:hostname>amf-2</sys:hostname></sys:system></config></edit-config></rpc>"#
        )
    }

    fn edit_config_continue_on_error_rpc() -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="411"><edit-config><target><running/></target><error-option>continue-on-error</error-option><config><sys:system xmlns:sys="urn:opc:demo"><sys:hostname>amf-2</sys:hostname></sys:system></config></edit-config></rpc>"#
        )
    }

    fn edit_config_test_option_set_rpc() -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="414"><edit-config><target><running/></target><test-option>set</test-option><config><sys:system xmlns:sys="urn:opc:demo"><sys:hostname>amf-2</sys:hostname></sys:system></config></edit-config></rpc>"#
        )
    }

    fn edit_config_invalid_value_rpc() -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="412"><edit-config><target><running/></target><config><sys:system xmlns:sys="urn:opc:demo"><sys:hostname>invalid-edit-value</sys:hostname></sys:system></config></edit-config></rpc>"#
        )
    }

    fn edit_config_failed_rpc() -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="418"><edit-config><target><running/></target><config><sys:system xmlns:sys="urn:opc:demo"><sys:hostname>failed-edit-value</sys:hostname></sys:system></config></edit-config></rpc>"#
        )
    }

    fn unsupported_edit_config_cdata_rpc() -> String {
        format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="402"><edit-config><target><running/></target><config><![CDATA[do-not-leak]]></config></edit-config></rpc>"#
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
        let hello = server.server_hello(Some(session_id(77)));

        assert!(hello.contains(NETCONF_BASE_1_0));
        assert!(hello.contains(NETCONF_BASE_1_1));
        assert!(hello.contains(WRITABLE_RUNNING_1_0));
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
        let hello = server.server_hello(Some(session_id(88)));

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
        let hello = server.server_hello(Some(session_id(89)));

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
    async fn validate_running_returns_ok_and_audits_validate() {
        let (server, _observed, audit) = server_fixture().await;
        let success_before = netconf_rpc_requests("validate", "success");

        let result = server.handle_rpc(
            RequestId::new(),
            &principal(),
            &validate_rpc("running"),
            &MgmtLimits::default(),
        );

        assert!(!result.close_session);
        assert!(result.reply_xml.contains(r#"message-id="305""#));
        assert!(result.reply_xml.contains("<ok/>"));
        assert!(!result.reply_xml.contains("do-not-leak"));

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Validate);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_VALIDATE_PATH)]
        );
        assert!(netconf_rpc_requests("validate", "success") > success_before);
    }

    #[tokio::test]
    async fn validate_running_requires_exec_grant() {
        let audit = CapturingAudit::default();
        let server = server_fixture_with_policy_source_and_audit(
            FixedPolicy(NacmPolicy::empty(PolicyVersion::new(505))),
            audit.clone(),
        )
        .await;
        let errors_before = netconf_rpc_errors("validate", "access-denied");

        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &validate_rpc("running"),
            &MgmtLimits::default(),
        );

        assert!(reply.contains("<error-tag>access-denied</error-tag>"));
        assert!(!reply.contains("do-not-leak"));
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Validate);
        assert_eq!(events[0].outcome, audit_denied("access-denied"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_VALIDATE_PATH)]
        );
        assert!(netconf_rpc_errors("validate", "access-denied") > errors_before);
    }

    #[tokio::test]
    async fn validate_candidate_is_not_supported_or_advertised() {
        let (server, _observed, audit) = server_fixture().await;
        let errors_before = netconf_rpc_errors("validate", "operation-not-supported");

        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &validate_rpc("candidate"),
            &MgmtLimits::default(),
        );

        assert!(reply.contains("<error-tag>operation-not-supported</error-tag>"));
        assert!(!reply.contains("candidate config"));
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Validate);
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_VALIDATE_PATH)]
        );
        assert!(netconf_rpc_errors("validate", "operation-not-supported") > errors_before);

        let hello = server.server_hello(NonZeroU32::new(42));
        assert!(!hello.contains(":validate"));
    }

    #[tokio::test]
    async fn validate_running_failure_is_payload_free() {
        let (server, config, audit) = validation_server_fixture().await;
        config.set_syntax_failure();
        let errors_before = netconf_rpc_errors("validate", "operation-failed");

        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &validate_rpc("running"),
            &MgmtLimits::default(),
        );

        assert!(reply.contains("<error-tag>operation-failed</error-tag>"));
        assert!(!reply.contains("/sys:system/sys:secret"));
        assert!(!reply.contains("syntax failure"));
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Validate);
        assert_eq!(events[0].outcome, audit_failed("syntax-validation-failed"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_VALIDATE_PATH)]
        );
        assert!(netconf_rpc_errors("validate", "operation-failed") > errors_before);
    }

    #[tokio::test]
    async fn validate_running_semantic_failure_is_payload_free() {
        let (server, config, audit) = validation_server_fixture().await;
        config.set_semantic_failure();

        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &validate_rpc("running"),
            &MgmtLimits::default(),
        );

        assert!(reply.contains("<error-tag>operation-failed</error-tag>"));
        assert!(!reply.contains("/sys:system/sys:secret"));
        assert!(!reply.contains("semantic failure"));
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Validate);
        assert_eq!(
            events[0].outcome,
            audit_failed("semantic-validation-failed")
        );
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_VALIDATE_PATH)]
        );
        assert!(config.saw_previous());
    }

    #[tokio::test]
    async fn lock_without_registry_is_operation_not_supported() {
        let (server, _observed, audit) = server_fixture().await;
        let errors_before = netconf_rpc_errors("lock", "operation-not-supported");

        let result = server.handle_rpc(
            RequestId::new(),
            &principal(),
            &lock_rpc("running"),
            &MgmtLimits::default(),
        );

        assert!(!result.close_session);
        assert!(result
            .reply_xml
            .contains("<error-tag>operation-not-supported</error-tag>"));
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Exec);
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_LOCK_PATH)]
        );
        assert!(netconf_rpc_errors("lock", "operation-not-supported") > errors_before);
    }

    #[tokio::test]
    async fn lock_unlock_running_tracks_owner_and_lock_denied_info() {
        let (server, _observed, audit) = server_fixture().await;
        let sessions = SessionRegistry::new();
        let _owner = sessions.register(80).expect("owner");
        let _other = sessions.register(81).expect("other");
        let success_before = netconf_rpc_requests("lock", "success");
        let denied_before = netconf_rpc_errors("lock", "lock-denied");

        let locked = server.handle_rpc_for_session(
            RequestId::new(),
            &principal(),
            &lock_rpc("running"),
            &MgmtLimits::default(),
            80,
            &sessions,
        );
        assert!(locked.reply_xml.contains("<ok/>"));
        assert_eq!(sessions.running_lock_owner_for_test(), Some(80));
        assert!(netconf_rpc_requests("lock", "success") > success_before);

        let denied = server.handle_rpc_for_session(
            RequestId::new(),
            &principal(),
            &lock_rpc("running"),
            &MgmtLimits::default(),
            81,
            &sessions,
        );
        assert!(denied
            .reply_xml
            .contains("<error-tag>lock-denied</error-tag>"));
        assert!(denied.reply_xml.contains("<session-id>80</session-id>"));
        assert_eq!(sessions.running_lock_owner_for_test(), Some(80));
        assert!(netconf_rpc_errors("lock", "lock-denied") > denied_before);

        let not_owner = server.handle_rpc_for_session(
            RequestId::new(),
            &principal(),
            &unlock_rpc("running"),
            &MgmtLimits::default(),
            81,
            &sessions,
        );
        assert!(not_owner
            .reply_xml
            .contains("<error-tag>lock-denied</error-tag>"));
        assert!(not_owner.reply_xml.contains("<session-id>80</session-id>"));
        assert_eq!(sessions.running_lock_owner_for_test(), Some(80));

        let unlocked = server.handle_rpc_for_session(
            RequestId::new(),
            &principal(),
            &unlock_rpc("running"),
            &MgmtLimits::default(),
            80,
            &sessions,
        );
        assert!(unlocked.reply_xml.contains("<ok/>"));
        assert_eq!(sessions.running_lock_owner_for_test(), None);

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 4);
        assert_eq!(events[0].operation, AuditOperation::Exec);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_LOCK_PATH)]
        );
        assert_eq!(events[1].outcome, audit_failed("lock-denied"));
        assert_eq!(
            events[1].schema_paths,
            vec![schema_node_path(NETCONF_LOCK_PATH)]
        );
        assert_eq!(events[2].outcome, audit_failed("lock-denied"));
        assert_eq!(
            events[2].schema_paths,
            vec![schema_node_path(NETCONF_UNLOCK_PATH)]
        );
        assert_eq!(events[3].outcome, AuditOutcome::Success);
        assert_eq!(
            events[3].schema_paths,
            vec![schema_node_path(NETCONF_UNLOCK_PATH)]
        );
    }

    #[tokio::test]
    async fn lock_running_without_exec_grant_is_access_denied_and_does_not_lock() {
        let audit = CapturingAudit::default();
        let server = server_fixture_with_policy_source_and_audit(
            FixedPolicy(NacmPolicy::empty(PolicyVersion::new(405))),
            audit.clone(),
        )
        .await;
        let sessions = SessionRegistry::new();
        let _current = sessions.register(80).expect("current session");

        let result = server.handle_rpc_for_session(
            RequestId::new(),
            &principal(),
            &lock_rpc("running"),
            &MgmtLimits::default(),
            80,
            &sessions,
        );

        assert!(result
            .reply_xml
            .contains("<error-tag>access-denied</error-tag>"));
        assert_eq!(sessions.running_lock_owner_for_test(), None);
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, audit_denied("access-denied"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_LOCK_PATH)]
        );
    }

    #[tokio::test]
    async fn lock_audit_failure_prevents_lock_state_change() {
        let server = server_fixture_with_policy_source_and_audit(
            FixedPolicy(policy_allow_system_but_deny_secret()),
            FailingAudit,
        )
        .await;
        let sessions = SessionRegistry::new();
        let _current = sessions.register(80).expect("current session");

        let result = server.handle_rpc_for_session(
            RequestId::new(),
            &principal(),
            &lock_rpc("running"),
            &MgmtLimits::default(),
            80,
            &sessions,
        );

        assert!(result
            .reply_xml
            .contains("<error-tag>operation-failed</error-tag>"));
        assert!(!result.reply_xml.contains("secret-admin"));
        assert_eq!(sessions.running_lock_owner_for_test(), None);
    }

    #[tokio::test]
    async fn lock_candidate_and_unlock_without_lock_fail_closed() {
        let (server, _observed, audit) = server_fixture().await;
        let sessions = SessionRegistry::new();
        let _current = sessions.register(80).expect("current session");

        let candidate = server.handle_rpc_for_session(
            RequestId::new(),
            &principal(),
            &lock_rpc("candidate"),
            &MgmtLimits::default(),
            80,
            &sessions,
        );
        assert!(candidate
            .reply_xml
            .contains("<error-tag>operation-not-supported</error-tag>"));
        assert_eq!(sessions.running_lock_owner_for_test(), None);

        let unlocked = server.handle_rpc_for_session(
            RequestId::new(),
            &principal(),
            &unlock_rpc("running"),
            &MgmtLimits::default(),
            80,
            &sessions,
        );
        assert!(unlocked
            .reply_xml
            .contains("<error-tag>operation-failed</error-tag>"));
        assert!(!unlocked.reply_xml.contains("<session-id>"));

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert_eq!(events[1].outcome, audit_failed("operation-failed"));
    }

    #[tokio::test]
    async fn malformed_lock_unlock_parse_failures_are_exec_audited() {
        let (server, observed, audit) = server_fixture().await;
        let lock_errors_before = netconf_rpc_errors("lock", "missing-element");
        let unlock_errors_before = netconf_rpc_errors("unlock", "bad-element");
        let validate_errors_before = netconf_rpc_errors("validate", "bad-element");

        let lock =
            format!(r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="lock-missing"><lock/></rpc>"#);
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &lock,
            &MgmtLimits::default(),
        );
        assert!(reply.contains(r#"message-id="lock-missing""#));
        assert!(reply.contains("<error-tag>missing-element</error-tag>"));

        let unlock = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="unlock-bad"><unlock><target><running/><candidate/></target></unlock></rpc>"#
        );
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &unlock,
            &MgmtLimits::default(),
        );
        assert!(reply.contains(r#"message-id="unlock-bad""#));
        assert!(reply.contains("<error-tag>bad-element</error-tag>"));

        let validate = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="validate-bad"><validate><source><running/><candidate/></source></validate></rpc>"#
        );
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &validate,
            &MgmtLimits::default(),
        );
        assert!(reply.contains(r#"message-id="validate-bad""#));
        assert!(reply.contains("<error-tag>bad-element</error-tag>"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].operation, AuditOperation::Exec);
        assert_eq!(events[0].outcome, audit_failed("missing-element"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_LOCK_PATH)]
        );
        assert_eq!(events[1].operation, AuditOperation::Exec);
        assert_eq!(events[1].outcome, audit_failed("bad-element"));
        assert_eq!(
            events[1].schema_paths,
            vec![schema_node_path(NETCONF_UNLOCK_PATH)]
        );
        assert_eq!(events[2].operation, AuditOperation::Validate);
        assert_eq!(events[2].outcome, audit_failed("bad-element"));
        assert_eq!(
            events[2].schema_paths,
            vec![schema_node_path(NETCONF_VALIDATE_PATH)]
        );
        assert!(netconf_rpc_errors("lock", "missing-element") > lock_errors_before);
        assert!(netconf_rpc_errors("unlock", "bad-element") > unlock_errors_before);
        assert!(netconf_rpc_errors("validate", "bad-element") > validate_errors_before);
    }

    #[tokio::test]
    async fn kill_session_without_registry_is_operation_not_supported() {
        let (server, _observed, audit) = server_fixture().await;
        let errors_before = netconf_rpc_errors("kill-session", "operation-not-supported");

        let result = server.handle_rpc(
            RequestId::new(),
            &principal(),
            &kill_session_rpc(99),
            &MgmtLimits::default(),
        );

        assert!(!result.close_session);
        assert!(result
            .reply_xml
            .contains("<error-tag>operation-not-supported</error-tag>"));
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].operation, AuditOperation::Exec);
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_KILL_SESSION_PATH)]
        );
        assert!(netconf_rpc_errors("kill-session", "operation-not-supported") > errors_before);
    }

    #[tokio::test]
    async fn kill_session_rejects_self_kill_with_invalid_value() {
        let (server, _observed, audit) = server_fixture().await;
        let sessions = SessionRegistry::new();
        let _current = sessions.register(80).expect("current session");
        let errors_before = netconf_rpc_errors("kill-session", "invalid-value");

        let result = server.handle_rpc_for_session(
            RequestId::new(),
            &principal(),
            &kill_session_rpc(80),
            &MgmtLimits::default(),
            80,
            &sessions,
        );

        assert!(!result.close_session);
        assert!(result
            .reply_xml
            .contains("<error-tag>invalid-value</error-tag>"));
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].operation, AuditOperation::Exec);
        assert_eq!(events[0].outcome, audit_failed("invalid-value"));
        assert!(netconf_rpc_errors("kill-session", "invalid-value") > errors_before);
    }

    #[tokio::test]
    async fn kill_session_missing_target_returns_data_missing_without_value_leak() {
        let (server, _observed, audit) = server_fixture().await;
        let sessions = SessionRegistry::new();
        let _current = sessions.register(80).expect("current session");
        let errors_before = netconf_rpc_errors("kill-session", "data-missing");

        let result = server.handle_rpc_for_session(
            RequestId::new(),
            &principal(),
            &kill_session_rpc(99),
            &MgmtLimits::default(),
            80,
            &sessions,
        );

        assert!(!result.close_session);
        assert!(result
            .reply_xml
            .contains("<error-tag>data-missing</error-tag>"));
        assert!(!result.reply_xml.contains("99"));
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].operation, AuditOperation::Exec);
        assert_eq!(events[0].outcome, audit_failed("data-missing"));
        assert!(netconf_rpc_errors("kill-session", "data-missing") > errors_before);
    }

    #[tokio::test]
    async fn kill_session_terminates_registered_target_and_audits_success() {
        let (server, _observed, audit) = server_fixture().await;
        let sessions = SessionRegistry::new();
        let _current = sessions.register(80).expect("current session");
        let mut target = sessions.register(81).expect("target session");
        let success_before = netconf_rpc_requests("kill-session", "success");

        let result = server.handle_rpc_for_session(
            RequestId::new(),
            &principal(),
            &kill_session_rpc(81),
            &MgmtLimits::default(),
            80,
            &sessions,
        );

        assert!(!result.close_session);
        assert!(result.reply_xml.contains("<ok/>"));
        target.terminated().await;
        assert!(target.is_terminated());
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].operation, AuditOperation::Exec);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_KILL_SESSION_PATH)]
        );
        assert!(netconf_rpc_requests("kill-session", "success") > success_before);
    }

    #[tokio::test]
    async fn kill_session_without_exec_grant_is_access_denied_and_does_not_kill() {
        let audit = CapturingAudit::default();
        let server = server_fixture_with_policy_source_and_audit(
            FixedPolicy(NacmPolicy::empty(PolicyVersion::new(404))),
            audit.clone(),
        )
        .await;
        let sessions = SessionRegistry::new();
        let _current = sessions.register(80).expect("current session");
        let target = sessions.register(81).expect("target session");

        let result = server.handle_rpc_for_session(
            RequestId::new(),
            &principal(),
            &kill_session_rpc(81),
            &MgmtLimits::default(),
            80,
            &sessions,
        );

        assert!(!result.close_session);
        assert!(result
            .reply_xml
            .contains("<error-tag>access-denied</error-tag>"));
        assert!(!result.reply_xml.contains("<ok/>"));
        assert!(!result.reply_xml.contains("81"));
        assert!(!target.is_terminated());
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Exec);
        assert_eq!(events[0].outcome, audit_denied("access-denied"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_KILL_SESSION_PATH)]
        );
    }

    #[tokio::test]
    async fn kill_session_policy_error_is_resource_denied_and_does_not_kill() {
        let audit = CapturingAudit::default();
        let server =
            server_fixture_with_policy_source_and_audit(BrokenPolicySource, audit.clone()).await;
        let sessions = SessionRegistry::new();
        let _current = sessions.register(80).expect("current session");
        let target = sessions.register(81).expect("target session");

        let result = server.handle_rpc_for_session(
            RequestId::new(),
            &principal(),
            &kill_session_rpc(81),
            &MgmtLimits::default(),
            80,
            &sessions,
        );

        assert!(!result.close_session);
        assert!(result
            .reply_xml
            .contains("<error-tag>resource-denied</error-tag>"));
        assert!(!result.reply_xml.contains("<ok/>"));
        assert!(!result.reply_xml.contains("policy"));
        assert!(!result.reply_xml.contains("81"));
        assert!(!target.is_terminated());
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Exec);
        assert_eq!(events[0].outcome, audit_failed("resource-denied"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_KILL_SESSION_PATH)]
        );
    }

    #[tokio::test]
    async fn kill_session_audit_failure_prevents_target_termination() {
        let server = server_fixture_with_policy_source_and_audit(
            FixedPolicy(policy_allow_system_but_deny_secret()),
            FailingAudit,
        )
        .await;
        let sessions = SessionRegistry::new();
        let _current = sessions.register(80).expect("current session");
        let target = sessions.register(81).expect("target session");

        let result = server.handle_rpc_for_session(
            RequestId::new(),
            &principal(),
            &kill_session_rpc(81),
            &MgmtLimits::default(),
            80,
            &sessions,
        );

        assert!(!result.close_session);
        assert!(result
            .reply_xml
            .contains("<error-tag>operation-failed</error-tag>"));
        assert!(!result.reply_xml.contains("<ok/>"));
        assert!(!result.reply_xml.contains("secret-admin"));
        assert!(!result.reply_xml.contains("81"));
        assert!(!target.is_terminated());
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
    async fn edit_config_requires_writable_running_opt_in_before_binding_or_commit() {
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
        let candidate_builder_called = Arc::new(AtomicBool::new(false));
        let binding = NonWritableEditBinding {
            bus: Arc::clone(&bus),
            candidate_builder_called: Arc::clone(&candidate_builder_called),
        };
        let audit = CapturingAudit::default();
        let server = ReadOnlyNetconfServer::new(
            binding,
            FixedPolicy(policy_allow_system_but_deny_secret()),
            audit.clone(),
            TransportType::NetconfTls,
        )
        .expect("server");
        let sessions = SessionRegistry::new();
        let _registration = sessions.register(89).expect("register session");

        let hello = server.server_hello(NonZeroU32::new(89));
        assert!(!hello.contains(WRITABLE_RUNNING_1_0));

        let result = server
            .handle_rpc_for_session_async(
                RequestId::new(),
                &principal(),
                &edit_config_hostname_rpc("409"),
                &MgmtLimits::default(),
                89,
                &sessions,
            )
            .await;

        assert!(result
            .reply_xml
            .contains("<error-tag>operation-not-supported</error-tag>"));
        assert!(!candidate_builder_called.load(Ordering::SeqCst));
        let snapshot = bus.current_snapshot();
        assert_eq!(snapshot.config.hostname, "amf-1");

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Update);
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_EDIT_CONFIG_PATH)]
        );
    }

    #[tokio::test]
    async fn edit_config_requires_exec_nacm_before_candidate_builder_or_commit() {
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
        let candidate_builder_called = Arc::new(AtomicBool::new(false));
        let binding = WritableCountingEditBinding {
            bus: Arc::clone(&bus),
            candidate_builder_called: Arc::clone(&candidate_builder_called),
        };
        let audit = CapturingAudit::default();
        let server = ReadOnlyNetconfServer::new(
            binding,
            FixedPolicy(policy_allow_system_but_deny_edit_config()),
            audit.clone(),
            TransportType::NetconfTls,
        )
        .expect("server");
        let sessions = SessionRegistry::new();
        let _registration = sessions.register(97).expect("register session");

        let result = server
            .handle_rpc_for_session_async(
                RequestId::new(),
                &principal(),
                &edit_config_hostname_rpc("416"),
                &MgmtLimits::default(),
                97,
                &sessions,
            )
            .await;

        assert!(result.reply_xml.contains(r#"message-id="416""#));
        assert!(result
            .reply_xml
            .contains("<error-tag>access-denied</error-tag>"));
        assert!(!candidate_builder_called.load(Ordering::SeqCst));
        assert!(!result.reply_xml.contains("amf-2"));
        assert!(!result.reply_xml.contains("do-not-leak"));

        let snapshot = bus.current_snapshot();
        assert_eq!(snapshot.config.hostname, "amf-1");
        assert_eq!(sessions.running_write_owner_for_test(), None);

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Update);
        assert_eq!(events[0].outcome, audit_denied("access-denied"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_EDIT_CONFIG_PATH)]
        );
    }

    #[tokio::test]
    async fn edit_config_running_commits_candidate_and_audits_schema_path() {
        let (server, _observed, audit) = server_fixture().await;
        let sessions = SessionRegistry::new();
        let _registration = sessions.register(90).expect("register session");
        let successes_before = netconf_rpc_requests("edit-config", "success");

        let result = server
            .handle_rpc_for_session_async(
                RequestId::new(),
                &principal(),
                &edit_config_hostname_rpc("410"),
                &MgmtLimits::default(),
                90,
                &sessions,
            )
            .await;

        assert!(!result.close_session);
        assert!(result.reply_xml.contains(r#"message-id="410""#));
        assert!(result.reply_xml.contains("<ok/>"));
        assert!(!result.reply_xml.contains("amf-2"));

        let snapshot = server.binding.config_bus().current_snapshot();
        assert_eq!(snapshot.config.hostname, "amf-2");
        assert_eq!(sessions.running_write_owner_for_test(), None);

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Update);
        assert_eq!(events[0].outcome, AuditOutcome::Success);
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path("/sys:system/sys:hostname")]
        );
        assert!(netconf_rpc_requests("edit-config", "success") > successes_before);
    }

    #[tokio::test]
    async fn edit_config_success_audit_failure_is_payload_free_after_durable_commit() {
        let store = Arc::new(MockManagedDatastore::new());
        let bus = Arc::new(
            ConfigBus::new_dev_only(
                DemoConfig {
                    hostname: "amf-1".to_string(),
                    secret: "do-not-leak".to_string(),
                },
                Arc::clone(&store),
            )
            .await
            .expect("bus"),
        );
        let binding = TestBinding {
            bus: Arc::clone(&bus),
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
        let sessions = SessionRegistry::new();
        let _registration = sessions.register(98).expect("register session");
        let request_id = RequestId::new();

        let result = server
            .handle_rpc_for_session_async(
                request_id,
                &principal(),
                &edit_config_hostname_rpc("417"),
                &MgmtLimits::default(),
                98,
                &sessions,
            )
            .await;

        assert!(result.reply_xml.contains(r#"message-id="417""#));
        assert!(result
            .reply_xml
            .contains("<error-tag>operation-failed</error-tag>"));
        assert!(!result.reply_xml.contains("amf-2"));
        assert!(!result.reply_xml.contains("do-not-leak"));
        assert!(!result.reply_xml.contains("secret-admin"));
        assert_eq!(sessions.running_write_owner_for_test(), None);

        let snapshot = bus.current_snapshot();
        assert_eq!(snapshot.config.hostname, "amf-2");

        let latest = store.latest().await.expect("durable commit record");
        assert_eq!(latest.config.hostname, "amf-2");
        assert_eq!(latest.source, RequestSource::Northbound);
        assert_eq!(latest.request_id, Some(request_id));
        let fingerprint = latest
            .request_fingerprint
            .expect("commit request fingerprint");
        assert_eq!(fingerprint.operation, ConfigOperation::Patch);
        assert_eq!(fingerprint.transport, TransportType::NetconfTls);
        assert_eq!(
            fingerprint.changed_paths,
            vec![YangPath::new("/sys:system/sys:hostname").expect("hostname path")]
        );
    }

    #[tokio::test]
    async fn edit_config_bus_authorizer_denial_is_payload_free_and_does_not_commit() {
        let authorizer_called = Arc::new(AtomicBool::new(false));
        let observed_authorization = Arc::new(Mutex::new(None));
        let authorizer: Arc<dyn ConfigAuthorizer> = Arc::new(DenyingConfigAuthorizer {
            called: Arc::clone(&authorizer_called),
            observed: Arc::clone(&observed_authorization),
        });
        let bus = Arc::new(
            ConfigBus::new(
                DemoConfig {
                    hostname: "amf-1".to_string(),
                    secret: "do-not-leak".to_string(),
                },
                MockManagedDatastore::new(),
                authorizer,
            )
            .await
            .expect("bus"),
        );
        let binding = TestBinding {
            bus: Arc::clone(&bus),
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
            FixedPolicy(policy_allow_system_but_deny_secret()),
            audit.clone(),
            TransportType::NetconfTls,
        )
        .expect("server");
        let sessions = SessionRegistry::new();
        let _registration = sessions.register(96).expect("register session");

        let result = server
            .handle_rpc_for_session_async(
                RequestId::new(),
                &principal(),
                &edit_config_hostname_rpc("415"),
                &MgmtLimits::default(),
                96,
                &sessions,
            )
            .await;

        assert!(result.reply_xml.contains(r#"message-id="415""#));
        assert!(result
            .reply_xml
            .contains("<error-tag>access-denied</error-tag>"));
        assert!(!result.reply_xml.contains("do-not-leak-authorizer-detail"));
        assert!(!result.reply_xml.contains("amf-2"));
        assert!(authorizer_called.load(Ordering::SeqCst));
        let observed = observed_authorization
            .lock()
            .expect("authorizer observation mutex")
            .clone()
            .expect("authorizer observed context");
        assert_eq!(observed.transport, TransportType::NetconfTls);
        assert_eq!(observed.source, RequestSource::Northbound);
        assert_eq!(observed.operation, ConfigOperation::Patch);
        assert_eq!(
            observed.changed_paths,
            vec![YangPath::new("/sys:system/sys:hostname").expect("hostname path")]
        );

        let snapshot = bus.current_snapshot();
        assert_eq!(snapshot.config.hostname, "amf-1");
        assert_eq!(sessions.running_write_owner_for_test(), None);

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Update);
        assert_eq!(events[0].outcome, audit_failed("authorization_denied"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_EDIT_CONFIG_PATH)]
        );
    }

    #[tokio::test]
    async fn edit_config_unsupported_error_option_does_not_call_binding_or_commit() {
        let (server, _observed, audit) = server_fixture().await;
        let sessions = SessionRegistry::new();
        let _registration = sessions.register(91).expect("register session");

        let result = server
            .handle_rpc_for_session_async(
                RequestId::new(),
                &principal(),
                &edit_config_continue_on_error_rpc(),
                &MgmtLimits::default(),
                91,
                &sessions,
            )
            .await;

        assert!(result
            .reply_xml
            .contains("<error-tag>operation-not-supported</error-tag>"));
        let snapshot = server.binding.config_bus().current_snapshot();
        assert_eq!(snapshot.config.hostname, "amf-1");

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Update);
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_EDIT_CONFIG_PATH)]
        );
    }

    #[tokio::test]
    async fn edit_config_explicit_test_option_requires_validate_capability() {
        let (server, _observed, audit) = server_fixture().await;
        let sessions = SessionRegistry::new();
        let _registration = sessions.register(95).expect("register session");

        let result = server
            .handle_rpc_for_session_async(
                RequestId::new(),
                &principal(),
                &edit_config_test_option_set_rpc(),
                &MgmtLimits::default(),
                95,
                &sessions,
            )
            .await;

        assert!(result
            .reply_xml
            .contains("<error-tag>operation-not-supported</error-tag>"));
        let snapshot = server.binding.config_bus().current_snapshot();
        assert_eq!(snapshot.config.hostname, "amf-1");

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Update);
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_EDIT_CONFIG_PATH)]
        );
    }

    #[tokio::test]
    async fn edit_config_binding_invalid_value_is_payload_free_and_does_not_commit() {
        let (server, _observed, audit) = server_fixture().await;
        let sessions = SessionRegistry::new();
        let _registration = sessions.register(92).expect("register session");

        let result = server
            .handle_rpc_for_session_async(
                RequestId::new(),
                &principal(),
                &edit_config_invalid_value_rpc(),
                &MgmtLimits::default(),
                92,
                &sessions,
            )
            .await;

        assert!(result
            .reply_xml
            .contains("<error-tag>invalid-value</error-tag>"));
        assert!(!result.reply_xml.contains("invalid-edit-value"));
        let snapshot = server.binding.config_bus().current_snapshot();
        assert_eq!(snapshot.config.hostname, "amf-1");

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Update);
        assert_eq!(events[0].outcome, audit_failed("invalid-value"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_EDIT_CONFIG_PATH)]
        );
    }

    #[tokio::test]
    async fn edit_config_binding_failed_is_payload_free_and_releases_write_guard() {
        let (server, _observed, audit) = server_fixture().await;
        let sessions = SessionRegistry::new();
        let _registration = sessions.register(99).expect("register session");

        let result = server
            .handle_rpc_for_session_async(
                RequestId::new(),
                &principal(),
                &edit_config_failed_rpc(),
                &MgmtLimits::default(),
                99,
                &sessions,
            )
            .await;

        assert!(result.reply_xml.contains(r#"message-id="418""#));
        assert!(result
            .reply_xml
            .contains("<error-tag>operation-failed</error-tag>"));
        assert!(!result.reply_xml.contains("do-not-leak"));
        assert!(!result.reply_xml.contains("failed-edit-value"));

        let snapshot = server.binding.config_bus().current_snapshot();
        assert_eq!(snapshot.config.hostname, "amf-1");
        assert_eq!(sessions.running_write_owner_for_test(), None);

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Update);
        assert_eq!(events[0].outcome, audit_failed("operation-failed"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_EDIT_CONFIG_PATH)]
        );
    }

    #[tokio::test]
    async fn edit_config_running_lock_denied_uses_update_audit_and_does_not_commit() {
        let (server, _observed, audit) = server_fixture().await;
        let sessions = SessionRegistry::new();
        let _owner = sessions.register(93).expect("register owner");
        let _writer = sessions.register(94).expect("register writer");
        assert_eq!(
            sessions.lock_running_after(93, || Ok::<(), ()>(())),
            Ok(LockRunningResult::Acquired)
        );

        let result = server
            .handle_rpc_for_session_async(
                RequestId::new(),
                &principal(),
                &edit_config_hostname_rpc("413"),
                &MgmtLimits::default(),
                94,
                &sessions,
            )
            .await;

        assert!(result
            .reply_xml
            .contains("<error-tag>lock-denied</error-tag>"));
        assert!(result.reply_xml.contains("<session-id>93</session-id>"));
        let snapshot = server.binding.config_bus().current_snapshot();
        assert_eq!(snapshot.config.hostname, "amf-1");

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].operation, AuditOperation::Update);
        assert_eq!(events[0].outcome, audit_failed("lock-denied"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_EDIT_CONFIG_PATH)]
        );
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

        let hello = server.server_hello(Some(session_id(78)));
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

        let hello = server.server_hello(Some(session_id(79)));
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

        let hello = server.server_hello(Some(session_id(80)));
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

        let hello = server.server_hello(Some(session_id(81)));
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

        let hello = server.server_hello(Some(session_id(82)));
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

        let hello = server.server_hello(Some(session_id(83)));
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
        let get_config = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="104"><get-config><source><running/></source><filter type="xpath" select="/sys:system/sys:hostname"/></get-config></rpc>"#
        );
        let get_config_reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_config,
            &MgmtLimits::default(),
        );
        assert!(get_config_reply.contains("<error-tag>operation-not-supported</error-tag>"));
        assert!(!get_config_reply.contains("sys:hostname"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let get = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="105"><get><filter type="xpath" select="/sys:system/sys:hostname"/></get></rpc>"#
        );
        let get_reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &get, &MgmtLimits::default());
        assert!(get_reply.contains("<error-tag>operation-not-supported</error-tag>"));
        assert!(!get_reply.contains("sys:hostname"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert_eq!(events[1].outcome, audit_failed("operation-not-supported"));
    }

    #[tokio::test]
    async fn malformed_xpath_filter_envelope_fails_before_projection_without_payload() {
        let (server, observed, audit) = server_fixture().await;
        let get_errors_before = netconf_rpc_errors("get", "bad-element");
        let get = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="115"><get><filter type="xpath" select="/sys:system/sys:hostname[.='do-not-leak']" mode="all"/></get></rpc>"#
        );
        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &get, &MgmtLimits::default());

        assert!(reply.contains(r#"message-id="115""#));
        assert!(reply.contains("<error-tag>bad-element</error-tag>"));
        assert!(!reply.contains("do-not-leak"));
        assert!(!reply.contains("sys:hostname"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());
        assert!(netconf_rpc_errors("get", "bad-element") > get_errors_before);

        let get_config_errors_before = netconf_rpc_errors("get-config", "missing-attribute");
        let get_config = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="116"><get-config><source><running/></source><filter type="xpath"/></get-config></rpc>"#
        );
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &get_config,
            &MgmtLimits::default(),
        );

        assert!(reply.contains(r#"message-id="116""#));
        assert!(reply.contains("<error-tag>missing-attribute</error-tag>"));
        assert!(!reply.contains("sys:hostname"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());
        assert!(netconf_rpc_errors("get-config", "missing-attribute") > get_config_errors_before);

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].operation, AuditOperation::Read);
        assert_eq!(events[0].outcome, audit_failed("bad-element"));
        assert!(events[0].schema_paths.is_empty());
        assert_eq!(events[1].operation, AuditOperation::Read);
        assert_eq!(events[1].outcome, audit_failed("missing-attribute"));
        assert!(events[1].schema_paths.is_empty());
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
        let (server, observed, audit) = server_fixture().await;
        let errors_before = netconf_rpc_errors("get-config", "operation-not-supported");
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="106"><get-config><source><running/></source><filter><sys:system xmlns:sys="urn:opc:demo"><sys:hostname>do-not-leak</sys:hostname></sys:system></filter></get-config></rpc>"#
        );
        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());
        assert!(reply.contains(r#"message-id="106""#));
        assert!(reply.contains("<error-tag>operation-not-supported</error-tag>"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert!(netconf_rpc_errors("get-config", "operation-not-supported") > errors_before);
    }

    #[tokio::test]
    async fn subtree_filter_attribute_match_fails_closed_until_supported() {
        let (server, observed, audit) = server_fixture().await;
        let errors_before = netconf_rpc_errors("get", "operation-not-supported");
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="106a"><get><filter><sys:system xmlns:sys="urn:opc:demo" name="do-not-leak"/></filter></get></rpc>"#
        );
        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());
        assert!(reply.contains(r#"message-id="106a""#));
        assert!(reply.contains("<error-tag>operation-not-supported</error-tag>"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, audit_failed("operation-not-supported"));
        assert!(netconf_rpc_errors("get", "operation-not-supported") > errors_before);
    }

    #[tokio::test]
    async fn subtree_filter_content_match_over_limit_is_too_big_without_leak() {
        let (server, observed, audit) = server_fixture().await;
        let limits = MgmtLimits {
            max_subtree_filter_content_match_nodes: 1,
            ..MgmtLimits::default()
        };
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="106b"><get-config><source><running/></source><filter><sys:system xmlns:sys="urn:opc:demo"><sys:hostname>first</sys:hostname><sys:uptime>second</sys:uptime></sys:system></filter></get-config></rpc>"#
        );
        let reply = server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &limits);
        assert!(reply.contains(r#"message-id="106b""#));
        assert!(reply.contains("<error-tag>too-big</error-tag>"));
        assert!(!reply.contains("first"));
        assert!(!reply.contains("second"));
        assert!(!reply.contains("do-not-leak"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, audit_failed("too-big"));
    }

    #[tokio::test]
    async fn subtree_filter_nested_attribute_match_over_limit_is_too_big_without_leak() {
        let (server, observed, audit) = server_fixture().await;
        let limits = MgmtLimits {
            max_subtree_filter_attribute_match_nodes: 1,
            ..MgmtLimits::default()
        };
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="106c"><get-config><source><running/></source><filter><sys:system xmlns:sys="urn:opc:demo"><sys:hostname>content<sys:alt first="do-not-leak"/><sys:alt second="also-secret"/></sys:hostname></sys:system></filter></get-config></rpc>"#
        );
        let reply = server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &limits);
        assert!(reply.contains(r#"message-id="106c""#));
        assert!(reply.contains("<error-tag>too-big</error-tag>"));
        assert!(!reply.contains("content"));
        assert!(!reply.contains("do-not-leak"));
        assert!(!reply.contains("also-secret"));
        assert!(observed.lock().expect("observed paths mutex").is_empty());

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, audit_failed("too-big"));
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

    #[tokio::test]
    async fn invalid_kill_session_value_audits_invalid_value_without_payload() {
        let (server, _observed, audit) = server_fixture().await;
        let errors_before = netconf_rpc_errors("kill-session", "invalid-value");
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" message-id="bad-kill"><kill-session><session-id>4294967296</session-id></kill-session></rpc>"#
        );

        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());

        assert!(reply.contains(r#"message-id="bad-kill""#));
        assert!(reply.contains("<error-type>application</error-type>"));
        assert!(reply.contains("<error-tag>invalid-value</error-tag>"));
        assert!(!reply.contains("4294967296"));
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].operation, AuditOperation::Exec);
        assert_eq!(events[0].outcome, audit_failed("invalid-value"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_KILL_SESSION_PATH)]
        );
        assert!(netconf_rpc_errors("kill-session", "invalid-value") > errors_before);
    }

    #[tokio::test]
    async fn wrong_namespace_kill_session_audits_as_exec_without_accepting_it() {
        let (server, _observed, audit) = server_fixture().await;
        let errors_before = netconf_rpc_errors("kill-session", "unknown-namespace");
        let rpc = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" xmlns:bad="urn:example:bad" message-id="bad-ns"><bad:kill-session><session-id>42</session-id></bad:kill-session></rpc>"#
        );

        let reply =
            server.handle_rpc_xml(RequestId::new(), &principal(), &rpc, &MgmtLimits::default());

        assert!(reply.contains(r#"message-id="bad-ns""#));
        assert!(reply.contains("<error-tag>unknown-namespace</error-tag>"));
        assert!(!reply.contains("42"));
        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events[0].operation, AuditOperation::Exec);
        assert_eq!(events[0].outcome, audit_failed("unknown-namespace"));
        assert_eq!(
            events[0].schema_paths,
            vec![schema_node_path(NETCONF_KILL_SESSION_PATH)]
        );
        assert!(netconf_rpc_errors("kill-session", "unknown-namespace") > errors_before);
    }

    #[tokio::test]
    async fn wrong_namespace_read_operations_stay_unknown_until_base_namespace_matches() {
        let (server, _observed, audit) = server_fixture().await;
        let unknown_errors_before = netconf_rpc_errors("unknown", "unknown-namespace");

        let bad_get = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" xmlns:bad="urn:example:bad" message-id="bad-get"><bad:get/></rpc>"#
        );
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &bad_get,
            &MgmtLimits::default(),
        );
        assert!(reply.contains(r#"message-id="bad-get""#));
        assert!(reply.contains("<error-tag>unknown-namespace</error-tag>"));

        let bad_get_config = format!(
            r#"<rpc xmlns="{NETCONF_BASE_NS}" xmlns:bad="urn:example:bad" message-id="bad-get-config"><bad:get-config/></rpc>"#
        );
        let reply = server.handle_rpc_xml(
            RequestId::new(),
            &principal(),
            &bad_get_config,
            &MgmtLimits::default(),
        );
        assert!(reply.contains(r#"message-id="bad-get-config""#));
        assert!(reply.contains("<error-tag>unknown-namespace</error-tag>"));

        let events = audit.events.lock().expect("audit mutex");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].operation, AuditOperation::Read);
        assert_eq!(events[0].outcome, audit_failed("unknown-namespace"));
        assert!(events[0].schema_paths.is_empty());
        assert_eq!(events[1].operation, AuditOperation::Read);
        assert_eq!(events[1].outcome, audit_failed("unknown-namespace"));
        assert!(events[1].schema_paths.is_empty());
        assert!(netconf_rpc_errors("unknown", "unknown-namespace") >= unknown_errors_before + 2);
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
