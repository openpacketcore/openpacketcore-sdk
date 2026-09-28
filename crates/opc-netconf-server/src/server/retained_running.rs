//! Ordinary Running edits through the actual retained transport owner.

use super::*;
use opc_config_bus::{ConfigBus, NetconfMutationResult, NetconfSession, RequiredNetconfAudit};

impl<C, B, P, A> ReadOnlyNetconfServer<C, B, P, A>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
{
    /// Attach experimental exact-session audit for ordinary Running edits.
    ///
    /// This explicit profile supports Running `edit-config` and, when enabled
    /// by the binding, `edit-data`. The parser's effective schema-root operation
    /// selects Replace/Replace or Patch/Update request/audit semantics; a partial
    /// edit supplies its computed complete model without becoming a replacement
    /// request. Copy, delete-config, candidate, startup and confirmed lifecycle
    /// support are not enabled. The existing read-only and legacy required-config
    /// attachments retain their separate contracts.
    ///
    /// This experimental subset preserves the binding's advertised
    /// `:writable-running`; it adds no capability URI. The supported edit options
    /// and schema applicator remain unchanged. This attachment does not establish
    /// full protocol qualification or complete lifecycle support.
    ///
    /// The actual transport runner supplies the SDK session. Numeric session
    /// IDs and direct dispatch helpers cannot substitute that authority. The
    /// original bounded worker retains effects and recovery after cancellation.
    /// An acknowledged protocol success requires the original committed bus
    /// publication; a known native result with debt remains recoverable through
    /// the same worker and is never relabeled by a failure observation.
    #[cfg(feature = "required-netconf-audit")]
    pub fn with_retained_running_audit(
        mut self,
        audit: RequiredNetconfAudit<C>,
    ) -> Result<Self, ServerInitError> {
        if !audit.belongs_to(self.binding.config_bus().as_ref()) {
            return Err(ServerInitError::RequiredAuditWorkerMismatch);
        }
        if !self.binding.writable_running_capability()
            || !self.required_audit_profile_supported()
            || self.required_config_audit.is_some()
        {
            return Err(ServerInitError::RequiredAuditProfileUnsupported);
        }
        self.audit = Arc::new(required_audit::ServerAudit::Required(
            audit.observation_sink(),
        ));
        self.retained_sessions = Some(audit);
        self.retained_running = true;
        Ok(self)
    }

    pub(super) async fn submit_retained_running(
        &self,
        context: &RpcExecContext<'_>,
        kind: EditRpcKind,
        bus: &ConfigBus<C>,
        session: Option<&NetconfSession>,
        request: CommitRequest<C>,
        mut intent: AuditEvent,
    ) -> RpcHandlingResult {
        // Preserve the operation already used for NACM authorization. Both
        // ordinary edits carry a complete computed model, but a Patch must keep
        // its Update Intent and encrypted Patch fingerprint through publication.
        let operation = match request.operation {
            ConfigOperation::Replace => AuditOperation::Replace,
            ConfigOperation::Patch => AuditOperation::Update,
            ConfigOperation::Delete | ConfigOperation::Rollback => {
                return self
                    .edit_config_failure_reply(
                        context,
                        kind,
                        audit_failed("operation-not-supported"),
                        RpcError::operation_not_supported(),
                    )
                    .await;
            }
        };
        let (Some(audit), Some(session)) = (&self.retained_sessions, session) else {
            return self.required_effect_error_reply(
                context,
                kind.metric(),
                CommitErrorCode::AdmissionRejected,
            );
        };
        if !audit.belongs_to(bus)
            || !self.retained_audit_profile_supported()
            || self.required_config_audit.is_some()
        {
            return self.required_effect_error_reply(
                context,
                kind.metric(),
                CommitErrorCode::AdmissionRejected,
            );
        }
        intent.operation = operation;
        // This is the only handoff. It retains the request's original base,
        // deadline and candidate, and lends the real transport session. It must
        // never be replaced by ordinary submit or standalone Intent observation.
        let result = audit
            .replace_running(session, context.principal, request, intent)
            .await;
        match result {
            Ok(NetconfMutationResult::Applied(receipt)) => {
                if let Some(committed) = receipt.published_commit() {
                    return self.committed_revision_success_reply(
                        context,
                        kind.metric(),
                        committed,
                    );
                }
                // A known native effect is not publication success. Its exact
                // authenticated receipt and completion/publication debt remain
                // with the original worker. No failed terminal, fresh request,
                // synthetic commit receipt or generic recovery read is issued.
                self.required_effect_error_reply(
                    context,
                    kind.metric(),
                    CommitErrorCode::RecoveryRequired,
                )
            }
            Ok(NetconfMutationResult::Refused(error)) | Err(error) => {
                self.required_effect_error_reply(context, kind.metric(), error.code)
            }
            Ok(NetconfMutationResult::Rejected(_) | NetconfMutationResult::Unknown(_)) => self
                .required_effect_error_reply(
                    context,
                    kind.metric(),
                    CommitErrorCode::RecoveryRequired,
                ),
        }
    }
}
