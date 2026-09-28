//! Closed Running preparation and publication state owned by the serial worker.

use std::panic::AssertUnwindSafe;

use futures_util::FutureExt;
use opc_config_model::{
    CommitError, CommitErrorCode, CommitResult, ConfigOperation, OpcConfig, RequestId,
    TrustedPrincipal,
};
use opc_mgmt_audit::{AuditEvent, AuditOperation};
use opc_persist::audit_authority::{AuditCaller, NetconfRunningEditRead, NetconfSessionOwner};
use opc_types::{ConfigVersion, TxId};

use super::{
    result::from_original, store::TargetAttempt, NetconfAuditStore, NetconfMutationResult,
    SessionReference, TargetWorker,
};
use crate::{StoreError, StoredConfig};

/// Derived from the complete model request, never from its audit event.
/// Both edits replace the stored model while preserving their original operation.
#[derive(Clone, Copy)]
pub(crate) enum RunningOperation {
    Replace,
    Patch,
}

impl RunningOperation {
    pub(crate) fn from_config(operation: ConfigOperation) -> Option<Self> {
        match operation {
            ConfigOperation::Replace => Some(Self::Replace),
            ConfigOperation::Patch => Some(Self::Patch),
            ConfigOperation::Delete | ConfigOperation::Rollback => None,
        }
    }

    pub(crate) fn audit_operation(self) -> AuditOperation {
        match self {
            Self::Replace => AuditOperation::Replace,
            Self::Patch => AuditOperation::Update,
        }
    }
}

pub(crate) struct RunningPreparation {
    owner: NetconfSessionOwner,
    frozen: NetconfRunningEditRead,
    reference: SessionReference,
    operation: RunningOperation,
}

impl RunningPreparation {
    pub(crate) fn verifies_base_record<C: OpcConfig>(&self, record: &StoredConfig<C>) -> bool {
        self.frozen.record().is_some_and(|exact| {
            exact.tx_id == record.tx_id
                && exact.version == record.version
                && exact.schema_digest == record.schema_digest
                && record
                    .plaintext_digest
                    .is_some_and(|digest| digest.as_slice() == exact.plaintext_digest.as_slice())
                && !record.recovery_required
                && record.confirmed_deadline.is_none()
        })
    }

    pub(crate) fn matches_base<C: OpcConfig>(
        &self,
        tx_id: Option<TxId>,
        version: ConfigVersion,
        config: &C,
    ) -> bool {
        // No provider access is needed to refuse a stale projection/base. The
        // snapshot's model remains associated with this exact published head.
        self.frozen.tx_id() == tx_id
            && self.frozen.running_base_version() == version.get()
            && self
                .frozen
                .record()
                .is_none_or(|record| record.schema_digest == config.schema_digest())
    }
}

impl TargetWorker {
    pub(crate) fn running_session_active(
        &self,
        preparation: &RunningPreparation,
        principal: &TrustedPrincipal,
    ) -> bool {
        self.sessions
            .session(&preparation.reference)
            .is_some_and(|session| session.principal() == principal)
    }

    pub(crate) async fn freeze_running(
        &self,
        reference: &SessionReference,
        principal: &TrustedPrincipal,
        operation: RunningOperation,
        event: &AuditEvent,
    ) -> Result<RunningPreparation, CommitError> {
        self.check_new(event.request_id, principal)
            .map_err(|refusal| match refusal.into_result() {
                NetconfMutationResult::Refused(error) => error,
                _ => refused(),
            })?;
        if self.has_unsettled() {
            return Err(CommitError::recovery_required(
                "NETCONF original recovery required",
            ));
        }
        let session = self.sessions.session(reference).ok_or_else(refused)?;
        // The supplied authentication is independent of request/event data.
        if session.principal() != principal {
            return Err(refused());
        }
        self.port()
            .bind_intent(
                event.request_id,
                principal,
                event.transport,
                operation.audit_operation(),
                event,
            )
            .map_err(|_| refused())?;
        let owner = session.lifetime().owner().clone();
        let frozen = self
            .port()
            .freeze_running(&owner, principal)
            .await
            .map_err(|_| refused())?;
        if self.sessions.session(reference).is_none() {
            return Err(refused());
        }
        Ok(RunningPreparation {
            owner,
            frozen,
            reference: reference.clone(),
            operation,
        })
    }

    pub(crate) async fn execute_running(
        &mut self,
        preparation: RunningPreparation,
        attested: opc_persist::AttestedConfigCommit,
        principal: &TrustedPrincipal,
        event: &AuditEvent,
        deadline: std::time::Instant,
    ) -> NetconfMutationResult {
        // Preparation has no mutation authority. The SDK checks the frozen base,
        // attestation, exact session/lock incarnation and original event again.
        let mut original = match self
            .port()
            .prepare_running(
                &preparation.owner,
                &preparation.frozen,
                attested,
                preparation.operation,
                principal,
                event,
            )
            .await
        {
            Ok(original) => original,
            Err(_) => return NetconfMutationResult::Refused(refused()),
        };
        if self.sessions.session(&preparation.reference).is_none() {
            return NetconfMutationResult::Refused(refused());
        }
        if std::time::Instant::now() >= deadline {
            return NetconfMutationResult::Refused(CommitError::deadline_exceeded(
                "commit deadline exceeded",
            ));
        }
        original.bind_running_session(preparation.reference, deadline);
        // execute retains the complete original before polling SDK admission.
        // The SDK rechecks this original deadline and live session after
        // native waits, immediately before polling new Intent admission.
        match self.execute(event.request_id, principal, original).await {
            Ok(reply) => from_original(reply),
            Err(refusal) => refusal.into_result(),
        }
    }
}

fn refused() -> CommitError {
    CommitError::new(
        CommitErrorCode::AdmissionRejected,
        "NETCONF Running binding refused",
    )
}

/// Authenticated values from the original SDK result, never a caller outcome.
/// This is crate-private publication input, not a mutation/attestation adapter.
pub(crate) struct RunningPublication {
    pub(crate) tx_id: TxId,
    pub(crate) version: ConfigVersion,
    digest: [u8; 32],
    caller: AuditCaller,
    request: Option<RequestId>,
}

impl RunningPublication {
    pub(super) fn new(
        tx_id: TxId,
        version: u64,
        digest: [u8; 32],
        caller: AuditCaller,
        request: Option<RequestId>,
    ) -> Self {
        Self {
            tx_id,
            version: ConfigVersion::new(version),
            digest,
            caller,
            request,
        }
    }

    pub(crate) fn verifies<C: OpcConfig>(
        &self,
        port: &NetconfAuditStore,
        record: &StoredConfig<C>,
    ) -> bool {
        record.tx_id == self.tx_id
            && record.version == self.version
            && record.plaintext_digest == Some(self.digest)
            && port
                .caller(&record.principal)
                .is_ok_and(|caller| caller == self.caller)
            && self
                .request
                .is_none_or(|request| record.request_id == Some(request))
    }
}

#[async_trait::async_trait]
pub(crate) trait RunningPublicationPort: Send + Sync {
    async fn publish(&self, original: RunningPublication) -> Result<CommitResult, StoreError>;
}

pub(super) async fn publish_original(
    port: Option<&dyn RunningPublicationPort>,
    original: &mut TargetAttempt,
) {
    if !original.completion_settled() || !original.requires_running_publication() {
        return;
    }
    let (Some(port), Some(publication)) = (port, original.running_publication()) else {
        return;
    };
    // Keep the authenticated receipt and all publication debt outside the
    // unwind boundary. No decryption/marker failure may erase a known effect.
    if let Ok(Ok(result)) = AssertUnwindSafe(port.publish(publication))
        .catch_unwind()
        .await
    {
        original.mark_running_published(result);
    }
}
