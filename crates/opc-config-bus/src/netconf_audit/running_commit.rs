//! Ordinary Running's model pipeline and exact readback publication.
//! This module is a child of commit so it shares the existing authorization,
//! validation, fingerprint and fanout implementation without a second worker.

use super::*;
use crate::netconf_audit::running::{RunningPublication, RunningPublicationPort};
use crate::netconf_audit::{NetconfMutationResult, SessionReference, TargetWorker};
use opc_config_model::TransportType;
use opc_mgmt_audit::{AuditEvent, AuditOperation, AuditOutcome};

pub(crate) struct RunningMessage<C: OpcConfig> {
    pub(crate) session: SessionReference,
    pub(crate) principal: TrustedPrincipal,
    pub(crate) request: CommitRequest<C>,
    pub(crate) event: AuditEvent,
    pub(crate) reply: oneshot::Sender<NetconfMutationResult>,
}

pub(crate) async fn running_in_worker<C: OpcConfig>(
    worker: Option<&mut TargetWorker>,
    message: RunningMessage<C>,
    snapshot: &AtomicConfigSnapshot<C>,
    recovery: &RecoveryState,
    limits: &CommitAdmissionLimits,
    store: &dyn ManagedDatastore<C>,
    authorizer: &dyn ConfigAuthorizer,
    classifier: Arc<dyn ConfigImpactClassifier<C>>,
    authority: &Mutex<Option<Arc<dyn crate::ConfigAuthorityPort>>>,
    has_pending: bool,
    draining: bool,
) {
    let RunningMessage {
        session,
        principal,
        request,
        event,
        reply,
    } = message;
    let attempted = AssertUnwindSafe(async {
        let worker = worker.ok_or_else(refused)?;
        if draining || has_pending || recovery.reason().is_some() || worker.has_unsettled() {
            return Err(CommitError::recovery_required(
                "NETCONF Running recovery required",
            ));
        }
        prepare_running(
            worker, &session, &principal, request, &event, snapshot, limits, store, authorizer,
            classifier, authority,
        )
        .await
    })
    .catch_unwind()
    .await;
    let result = match attempted {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => NetconfMutationResult::Refused(error),
        Err(_) => {
            // An original may already be registered; do not invent a refusal or
            // fresh identity after a panic. Request recovery retains ownership.
            drop(reply);
            return;
        }
    };
    let _ = reply.send(result);
}

async fn prepare_running<C: OpcConfig>(
    worker: &mut TargetWorker,
    session: &SessionReference,
    principal: &TrustedPrincipal,
    mut request: CommitRequest<C>,
    event: &AuditEvent,
    snapshot: &AtomicConfigSnapshot<C>,
    limits: &CommitAdmissionLimits,
    store: &dyn ManagedDatastore<C>,
    authorizer: &dyn ConfigAuthorizer,
    classifier: Arc<dyn ConfigImpactClassifier<C>>,
    authority: &Mutex<Option<Arc<dyn crate::ConfigAuthorityPort>>>,
) -> Result<NetconfMutationResult, CommitError> {
    ensure_deadline(request.deadline)?;
    if request.principal != *principal
        || !matches!(request.mode, CommitMode::Commit)
        || request.operation != ConfigOperation::Replace
        || request.source != RequestSource::Northbound
        || !matches!(
            request.transport,
            TransportType::NetconfSsh | TransportType::NetconfTls
        )
        || event.request_id != request.request_id
        || event.principal != opc_mgmt_audit::principal_descriptor(principal)
        || event.tenant != principal.tenant.as_str()
        || event.transport != request.transport
        || event.operation != AuditOperation::Replace
        || event.outcome != AuditOutcome::Intent
        || event.tx_id.is_some()
    {
        return Err(refused());
    }
    enforce_candidate_payload_limit(request.candidate.as_ref(), limits)?;
    let current = snapshot.current_snapshot();
    // A new ordinary replacement always names its actual base, including zero.
    if request.base_version != current.version {
        return Err(refused());
    }
    let preparation = worker.freeze_running(session, principal, event).await?;
    if !preparation.matches_base(current.tx_id, current.version, current.config.as_ref()) {
        return Err(refused());
    }
    ensure_authority(
        authority,
        ConfigProjectionHead::new(current.tx_id, current.version),
    )
    .await?;
    let candidate = request
        .candidate
        .take()
        .ok_or_else(CommitError::missing_candidate)?;
    let context = ValidationContext {
        request_id: request.request_id,
        principal: principal.clone(),
        transport: request.transport,
        source: request.source,
        operation: request.operation,
        mode: request.mode.clone(),
        base_version: current.version,
        previous: Some(Arc::clone(&current.config)),
    };
    let (candidate, _, changed_paths) = compute_deltas_and_changed_paths(
        candidate,
        Arc::clone(&current.config),
        request.request_id,
    )
    .await?;
    authorize_request(&request, current.version, changed_paths.clone(), authorizer).await?;
    let candidate = validate_candidate(candidate, context.clone()).await?;
    let (candidate, plan) = classify_apply_plan(
        classifier,
        context,
        Arc::clone(&current.config),
        candidate,
        changed_paths.clone(),
        None,
    )
    .await?;
    // Match the actual decrypted model as well as its quorum-frozen identity.
    // This is a provider-backed read, after NACM/model validation and before
    // encryption; a wrong numeric/head/schema base was already refused above.
    if let Some(tx_id) = current.tx_id {
        let base = store
            .load_rollback(RollbackTarget::TxId(tx_id))
            .await
            .map_err(|_| refused())?;
        if !preparation.verifies_base_record(&base) {
            return Err(refused());
        }
        let (_, deltas, _) = compute_deltas_and_changed_paths(
            base.config,
            Arc::clone(&current.config),
            request.request_id,
        )
        .await?;
        if !deltas.is_empty() {
            return Err(refused());
        }
    }
    if !worker.running_session_active(&preparation, principal) {
        return Err(refused());
    }
    ensure_deadline(request.deadline)?;
    let version = current.version.next().ok_or_else(|| {
        CommitError::new(
            CommitErrorCode::VersionExhausted,
            "running config version counter is exhausted",
        )
    })?;
    let mut record = StoredConfig::new(
        TxId::new(),
        version,
        principal.clone(),
        request.source,
        candidate,
    );
    record.parent_tx_id = current.tx_id;
    record.request_id = Some(request.request_id);
    record.idempotency_key = request.idempotency_key.clone();
    record.request_fingerprint =
        persisted_request_fingerprint(&request, true, changed_paths, current.version);
    record.apply_plan = Some(plan);
    record.recovery_required = true;
    // This consumes the real adapter's encryption and SDK attestation once.
    // Neither ordinary append nor an observation sink can implement this step.
    let attested = store
        .prepare_netconf_running_commit(CommitWrite::new(record), principal, event)
        .await
        .map_err(|_| refused())?;
    ensure_deadline(request.deadline)?;
    Ok(worker
        .execute_running(preparation, attested, principal, event, request.deadline)
        .await)
}

fn refused() -> CommitError {
    CommitError::new(
        CommitErrorCode::AdmissionRejected,
        "ordinary NETCONF Running replacement refused",
    )
}

pub(crate) struct RunningPublisher<C: OpcConfig> {
    store: Arc<dyn ManagedDatastore<C>>,
    snapshot: Arc<AtomicConfigSnapshot<C>>,
    subscribers: Arc<Mutex<Vec<Arc<SubscriberState<C>>>>>,
    port: crate::netconf_audit::NetconfAuditStore,
}

impl<C: OpcConfig> RunningPublisher<C> {
    pub(crate) fn new(
        store: Arc<dyn ManagedDatastore<C>>,
        snapshot: Arc<AtomicConfigSnapshot<C>>,
        subscribers: Arc<Mutex<Vec<Arc<SubscriberState<C>>>>>,
        port: crate::netconf_audit::NetconfAuditStore,
    ) -> Self {
        Self {
            store,
            snapshot,
            subscribers,
            port,
        }
    }
}

#[async_trait::async_trait]
impl<C: OpcConfig> RunningPublicationPort for RunningPublisher<C> {
    async fn publish(&self, original: RunningPublication) -> Result<CommitResult, StoreError> {
        let unavailable =
            || StoreError::unavailable("original Running publication requires recovery");
        // Decrypt the exact retained transaction, never a caller candidate or
        // the current latest record substituted for an original outcome.
        let record = self
            .store
            .load_rollback(RollbackTarget::TxId(original.tx_id))
            .await?;
        if !original.verifies(&self.port, &record)
            || record.confirmed_deadline.is_some()
            || record.source != RequestSource::Northbound
        {
            return Err(unavailable());
        }
        let fingerprint = record
            .request_fingerprint
            .as_ref()
            .ok_or_else(unavailable)?;
        if !matches!(fingerprint.mode, StoredRequestMode::Commit)
            || fingerprint.operation != ConfigOperation::Replace
            || !matches!(
                fingerprint.transport,
                TransportType::NetconfSsh | TransportType::NetconfTls
            )
        {
            return Err(unavailable());
        }
        validate_stored_schema_digest(&record)?;
        let config =
            validate_startup_config(record.config.clone(), restore_validation_context(&record))
                .await?;
        let current = self.snapshot.current_snapshot();
        let already_published =
            current.tx_id == Some(record.tx_id) && current.version == record.version;
        if !already_published
            && (current.tx_id != record.parent_tx_id
                || current.version.next() != Some(record.version)
                || fingerprint.base_version != Some(current.version))
        {
            // A different incarnation cannot borrow cached publication success
            // or regress a later/unrelated snapshot to this old transaction.
            return Err(unavailable());
        }
        let result = replay_commit_result(&record).map_err(|_| unavailable())?;
        // Preserve snapshot -> durable marker-clear ordering. Even if the
        // latter fails, the worker keeps this exact known result and debt.
        self.snapshot
            .publish(Some(record.tx_id), record.version, Arc::new(config));
        self.store.clear_recovery_required(record.tx_id).await?;
        // Resync is safe after replay of a partial publication; it never invents
        // deltas against a model that may already contain the committed record.
        fanout_resync(&self.subscribers, record.version);
        Ok(result)
    }
}
