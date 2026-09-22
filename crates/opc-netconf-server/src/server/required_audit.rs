//! Required configuration effects and the matching observation authority.

use super::*;
use opc_config_bus::{ConfigBus, RequiredConfigAudit};
use opc_config_model::CommitError;

/// Internal routing preserves the public legacy sink type without retaining a
/// second observation authority after required audit has been attached.
pub(super) enum ServerAudit<A> {
    Legacy(A),
    Required(Arc<dyn AuditSink>),
}

impl<A: AuditSink> AuditSink for ServerAudit<A> {
    fn record(&self, event: &AuditEvent) -> Result<(), AuditError> {
        match self {
            Self::Legacy(audit) => audit.record(event),
            Self::Required(audit) => audit.record(event),
        }
    }

    fn record_async<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> Pin<Box<dyn Future<Output = Result<(), AuditError>> + Send + 'a>> {
        match self {
            Self::Legacy(audit) => audit.record_async(event),
            Self::Required(audit) => audit.record_async(event),
        }
    }
}

impl<A: AuditSink> ServerAudit<A> {
    /// Only called inside the existing bounded blocking registry worker, with
    /// its atomic permit and registry guard still held. Never used on an async
    /// executor thread or as a configuration Intent admission path.
    pub(super) fn record_atomic(&self, event: &AuditEvent) -> Result<(), AuditError> {
        match self {
            Self::Legacy(audit) => audit.record(event),
            Self::Required(audit) => tokio::runtime::Handle::try_current()
                .map_err(|_| AuditError::unavailable("NETCONF audit runtime unavailable"))?
                .block_on(audit.record_async(event)),
        }
    }
}

impl<C, B, P, A> ReadOnlyNetconfServer<C, B, P, A>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
{
    /// Bind required mutation audit to this exact running-config bus worker.
    ///
    /// The current profile supports writable-running and asynchronous base
    /// session operations. Candidate, confirmed-commit and startup bindings are
    /// rejected explicitly: their local effect owners do not yet implement the
    /// required encrypted-effect/recovery contract. Capabilities are not hidden.
    ///
    /// Reads and pre-submission denials use the same authority's observation
    /// port. No standalone Intent is acknowledged, and the original sink is
    /// replaced. Synchronous dispatch cannot drive this asynchronous authority
    /// and fails closed. The capability grants no caller or NACM authority.
    pub fn with_required_config_audit(
        mut self,
        audit: RequiredConfigAudit<C>,
    ) -> Result<Self, ServerInitError> {
        if !audit.belongs_to(self.binding.config_bus().as_ref()) {
            return Err(ServerInitError::RequiredAuditWorkerMismatch);
        }
        if !self.required_audit_profile_supported() {
            return Err(ServerInitError::RequiredAuditProfileUnsupported);
        }
        self.audit = Arc::new(ServerAudit::Required(audit.observation_sink()));
        self.required_config_audit = Some(audit);
        Ok(self)
    }

    pub(super) fn required_audit_profile_supported(&self) -> bool {
        !self.binding.candidate_datastore_capability()
            && !self.binding.confirmed_commit_capability()
            && !self.binding.startup_datastore_capability()
            && self.binding.startup_datastore().is_none()
    }

    pub(super) async fn submit_config_effect(
        &self,
        bus: &ConfigBus<C>,
        request: CommitRequest<C>,
        mut intent: AuditEvent,
    ) -> Result<CommitResult, CommitError> {
        let Some(audit) = self.required_config_audit.as_ref() else {
            return bus.submit(request).await;
        };
        // Bind to the bus selected for this request, not a second potentially
        // different result from the application binding's config_bus method.
        if !audit.belongs_to(bus) || !self.required_audit_profile_supported() {
            intent.outcome = audit_failed("operation-failed");
            let _ = commit_audit_failed(&self.audit, &intent).await;
            return Err(CommitError::new(
                CommitErrorCode::AdmissionRejected,
                "configuration audit authority mismatch",
            ));
        }
        intent.operation = match request.operation {
            ConfigOperation::Replace => AuditOperation::Replace,
            ConfigOperation::Patch => AuditOperation::Update,
            ConfigOperation::Delete => AuditOperation::Delete,
            ConfigOperation::Rollback => AuditOperation::Rollback,
        };
        // Qualification only: restore the separated protocol Intent path.
        if commit_audit_failed(&self.audit, &intent).await {
            return Err(CommitError::new(
                CommitErrorCode::AdmissionRejected,
                "required configuration audit intent unavailable",
            ));
        }
        bus.submit(request).await
    }

    /// Once the required submitter owns the request, only its exact retained
    /// operation may report the outcome. A protocol error response is not a new
    /// failed audit observation and must not relabel a possibly committed write.
    pub(super) fn required_effect_error_reply(
        &self,
        context: &RpcExecContext<'_>,
        metric: NetconfOperation,
        code: CommitErrorCode,
    ) -> RpcHandlingResult {
        let error = rpc_error_for_commit_error(code);
        record_rpc_error(metric, error.classification.tag, context.started.elapsed());
        RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
            Some(context.message_id),
            context.reply_attrs,
            error,
        ))
    }
}
