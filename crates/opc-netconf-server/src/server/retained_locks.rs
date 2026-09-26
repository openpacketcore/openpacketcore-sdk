//! Running lock authority belongs to the actual SDK session and bounded worker.

use super::*;
use opc_config_bus::{NetconfLockDatastore, NetconfMutationResult, NetconfSession};

impl<C, B, P, A> ReadOnlyNetconfServer<C, B, P, A>
where
    C: OpcConfig,
    B: NetconfConfigBinding<C>,
    P: PolicySource,
    A: AuditSink,
{
    pub(super) async fn handle_retained_lock(
        &self,
        target: XmlDatastore,
        context: RpcExecContext<'_>,
        session: Option<&NetconfSession>,
        release: bool,
    ) -> RpcHandlingResult {
        let (path, metric) = if release {
            (NETCONF_UNLOCK_PATH, NetconfOperation::Unlock)
        } else {
            (NETCONF_LOCK_PATH, NetconfOperation::Lock)
        };
        let intent = AuditEvent::new(
            context.request_id,
            context.principal,
            self.transport,
            AuditOperation::Exec,
            AuditOutcome::Intent,
        )
        .with_paths([schema_node_path(path)]);

        // NACM evaluates the independently authenticated caller before any
        // worker message or Intent. Denials use the attached observation port.
        let refusal = match self.authorize_exec(context.principal, path) {
            Ok(false) => Some((audit_denied("access-denied"), RpcError::access_denied())),
            Err(()) => Some((
                audit_failed("operation-failed"),
                RpcError::operation_failed(),
            )),
            Ok(true) if target != XmlDatastore::Running => Some((
                audit_failed("operation-not-supported"),
                RpcError::operation_not_supported(),
            )),
            Ok(true) => None,
        };
        if let Some((outcome, mut error)) = refusal {
            let mut event = intent;
            event.outcome = outcome;
            if self.audit.record_async(&event).await.is_err() {
                error = RpcError::operation_failed();
            }
            return Self::retained_lock_error(&context, metric, error);
        }

        let (Some(audit), Some(session)) = (&self.retained_sessions, session) else {
            return Self::retained_lock_error(&context, metric, RpcError::operation_failed());
        };
        if !audit.belongs_to(self.binding.config_bus().as_ref())
            || self.binding.writable_running_capability()
            || !self.required_audit_profile_supported()
        {
            return Self::retained_lock_error(&context, metric, RpcError::operation_failed());
        }

        let result = if release {
            audit
                .release_lock(
                    session,
                    context.principal,
                    intent,
                    NetconfLockDatastore::Running,
                )
                .await
        } else {
            audit
                .acquire_lock(
                    session,
                    context.principal,
                    intent,
                    NetconfLockDatastore::Running,
                )
                .await
        };
        if matches!(result, Ok(NetconfMutationResult::Applied(ref receipt))
            if !receipt.completion_pending() && receipt.lock_ready())
        {
            record_rpc_success(metric, context.started.elapsed());
            return RpcHandlingResult::keep_open(rpc_ok_empty_reply_with_attrs(
                context.message_id,
                context.reply_attrs,
            ));
        }
        // The original worker owns recovery and any owed audit completion.
        // A protocol error cannot relabel a possibly applied effect as failed.
        // The SDK exposes no authenticated numeric owner for lock-denied info.
        Self::retained_lock_error(&context, metric, RpcError::operation_failed())
    }

    pub(super) fn retained_lock_error(
        context: &RpcExecContext<'_>,
        metric: NetconfOperation,
        error: RpcError,
    ) -> RpcHandlingResult {
        record_rpc_error(metric, error.classification.tag, context.started.elapsed());
        RpcHandlingResult::keep_open(rpc_error_reply_with_attrs(
            Some(context.message_id),
            context.reply_attrs,
            error,
        ))
    }
}
