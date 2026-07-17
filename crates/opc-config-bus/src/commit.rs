//! Single-writer commit state machine (RFC 001 §5): bounded admission queue,
//! sequenced validate/authorize/persist/publish pipeline, commit-confirmed
//! expiry rollback, and the recovery fence that blocks writes after a partial
//! durable side effect or worker panic.

#![allow(clippy::too_many_arguments)]
use futures_util::FutureExt;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{mpsc, mpsc::error::TrySendError, oneshot};

use opc_alarm::{ProbableCause, Severity, SharedAlarmManager};
use opc_config_model::{
    ApplyPlan, CommitError, CommitErrorCode, CommitMode, CommitRequest, CommitResult, CommitStatus,
    CommittedConfigRevision, ConfigError, ConfigImpactClassifier, ConfigOperation, OpcConfig,
    RequestId, RequestSource, RollbackTarget, TrustedPrincipal, ValidationContext, ValidationError,
    YangPath,
};
use opc_types::{redact, ConfigVersion, Timestamp, TxId};

use crate::alarms::{
    apply_commit_alarm_outcome, raise_commit_error, raise_config_error_alarm,
    CONFIG_BUS_COMMIT_FAILURE_ALARM_TYPE,
};
use crate::authorizer::{ConfigAuthorizer, DenyAllAuthorizer};
use crate::datastore::ManagedDatastore;
use crate::restore::{
    restore_validation_context, startup_bootstrap_principal, validate_publishable_stored_config,
    validate_startup_config,
};
use crate::rollback::resolve_candidate;
use crate::subscribers::{ConfigReceiver, SubscriberLagPolicy, SubscriberState};
use crate::types::{
    AtomicConfigSnapshot, AuthorityMode, CommitWrite, ConfigChange, ConfigEvent, ConfigSnapshot,
    ConfirmedCommitResolution, DriftState, PublishedSnapshot, StoreError, StoreErrorCode,
    StoredConfig, StoredRequestFingerprint, StoredRequestMode,
};
use crate::ConfigProjectionHead;

pub(crate) const DEFAULT_COMMIT_QUEUE_CAPACITY: usize = 32;
const UNSUPPORTED_VALIDATE_ONLY_OPERATION_MESSAGE: &str =
    "validate-only only supports replace operations in this skeleton config bus";
const PERSIST_FAILED_MESSAGE: &str = "durable config persistence failed";
const IDEMPOTENCY_LOOKUP_FAILED_MESSAGE: &str = "idempotency key lookup failed";
const IDEMPOTENCY_KEY_COLLISION_MESSAGE: &str =
    "idempotency key is already bound to a different commit request";
const WORKER_PANIC_RECOVERY_REQUIRED_MESSAGE: &str =
    "config commit worker panicked; recovery is required before the next write";
const RECOVERY_RECONCILIATION_FAILED_MESSAGE: &str =
    "commit was published but the recovery marker could not be cleared durably";
const CONCURRENT_COMMIT_RECOVERY_REQUIRED_MESSAGE: &str =
    "durable config advanced concurrently; restore is required before the next write";
const EXPIRY_ROLLBACK_RECOVERY_REQUIRED_MESSAGE: &str =
    "commit-confirmed expiry rollback failed; recovery is required before the next write";
const OUTCOME_UNKNOWN_MESSAGE: &str =
    "durable config outcome is unknown; verify authoritative state before retrying";
const REQUEST_ID_COLLISION_MESSAGE: &str =
    "request id is already bound to a different commit request";
const PENDING_CONFIRMED_UPDATE_UNSUPPORTED_MESSAGE: &str =
    "commit-confirmed update while another confirmed commit is pending is not supported";
const STALE_BASE_VERSION_MESSAGE: &str =
    "commit base version does not match running config version";
const EMPTY_CHANGED_PATHS_FOR_NONEMPTY_DIFF_MESSAGE: &str =
    "changed path extraction returned no paths for a non-empty config diff";
const CANDIDATE_PAYLOAD_SIZE_UNAVAILABLE_MESSAGE: &str =
    "config candidate serialized payload size is unavailable";
const CANDIDATE_PAYLOAD_SIZE_FAILED_MESSAGE: &str =
    "config candidate serialized payload size could not be measured";
const SHADOW_MUTATION_REJECTED_MESSAGE: &str =
    "config mutations are disabled on a shadow committed-revision bus";

pub(crate) struct Submission<C: OpcConfig> {
    pub(crate) request: CommitRequest<C>,
    pub(crate) reply: oneshot::Sender<Result<CommitResult, CommitError>>,
}

enum PendingTimerUpdate {
    Unchanged,
    Set(Timestamp),
    Clear,
}

struct ProcessedCommit {
    result: CommitResult,
    pending_timer_update: PendingTimerUpdate,
}

impl ProcessedCommit {
    fn read_only(result: CommitResult) -> Self {
        Self {
            result,
            pending_timer_update: PendingTimerUpdate::Unchanged,
        }
    }
}

pub(crate) struct RecoveryState {
    pub(crate) fenced: AtomicBool,
    pub(crate) reason: Mutex<Option<String>>,
}

impl Default for RecoveryState {
    fn default() -> Self {
        Self {
            fenced: AtomicBool::new(false),
            reason: Mutex::new(None),
        }
    }
}

impl RecoveryState {
    pub(crate) fn reason(&self) -> Option<String> {
        if !self.fenced.load(Ordering::Acquire) {
            return None;
        }

        match self.reason.lock() {
            Ok(reason) => reason.clone(),
            Err(poisoned) => {
                tracing::error!("recovering poisoned config recovery-fence state");
                poisoned.into_inner().clone()
            }
        }
    }

    pub(crate) fn fence(&self, reason: impl Into<String>) {
        let mut slot = match self.reason.lock() {
            Ok(slot) => slot,
            Err(poisoned) => {
                tracing::error!("recovering poisoned config recovery-fence state");
                poisoned.into_inner()
            }
        };
        if slot.is_none() {
            *slot = Some(reason.into());
        }
        self.fenced.store(true, Ordering::Release);
        crate::metrics::record_recovery_fence_active(true);
    }
}

pub(crate) struct CommitAdmissionLimits {
    max_serialized_config_bytes: Mutex<Option<usize>>,
}

impl Default for CommitAdmissionLimits {
    fn default() -> Self {
        Self {
            max_serialized_config_bytes: Mutex::new(None),
        }
    }
}

impl CommitAdmissionLimits {
    fn max_serialized_config_bytes(&self) -> Option<usize> {
        *self
            .max_serialized_config_bytes
            .lock()
            .expect("admission limit mutex poisoned")
    }

    fn set_max_serialized_config_bytes(&self, max_bytes: Option<usize>) {
        *self
            .max_serialized_config_bytes
            .lock()
            .expect("admission limit mutex poisoned") = max_bytes;
    }
}

/// Sequenced config commit worker with atomic snapshot publication.
#[derive(Clone)]
pub struct ConfigBus<C: OpcConfig> {
    pub(crate) tx: mpsc::Sender<Submission<C>>,
    pub(crate) snapshot: Arc<AtomicConfigSnapshot<C>>,
    pub(crate) subscribers: Arc<Mutex<Vec<Arc<SubscriberState<C>>>>>,
    pub(crate) authority_mode: AuthorityMode,
    pub(crate) recovery: Arc<RecoveryState>,
    pub(crate) alarm_manager: SharedAlarmManager,
    pub(crate) authorizer: Arc<dyn ConfigAuthorizer>,
    pub(crate) admission_limits: Arc<CommitAdmissionLimits>,
    pub(crate) store: Arc<dyn ManagedDatastore<C>>,
}

impl<C: OpcConfig> ConfigBus<C> {
    pub(crate) fn spawn(
        initial: C,
        version: ConfigVersion,
        tx_id: Option<TxId>,
        store: Arc<dyn ManagedDatastore<C>>,
        queue_capacity: usize,
        authority_mode: AuthorityMode,
        alarm_manager: SharedAlarmManager,
        authorizer: Arc<dyn ConfigAuthorizer>,
        impact_classifier: Arc<dyn ConfigImpactClassifier<C>>,
        pending_deadline: Option<Timestamp>,
    ) -> Self {
        let queue_capacity = queue_capacity.max(1);
        let snapshot = Arc::new(AtomicConfigSnapshot::with_state(initial, version, tx_id));
        let subscribers = Arc::new(Mutex::new(Vec::new()));
        let recovery = Arc::new(RecoveryState::default());
        let admission_limits = Arc::new(CommitAdmissionLimits::default());
        let (tx, rx) = mpsc::channel(queue_capacity);

        tokio::spawn(worker_loop(
            rx,
            Arc::clone(&snapshot),
            Arc::clone(&subscribers),
            Arc::clone(&recovery),
            Arc::clone(&admission_limits),
            Arc::clone(&store),
            alarm_manager.clone(),
            authorizer.clone(),
            impact_classifier.clone(),
            pending_deadline,
        ));

        Self {
            tx,
            snapshot,
            subscribers,
            authority_mode,
            recovery,
            alarm_manager,
            authorizer,
            admission_limits,
            store,
        }
    }

    pub(crate) fn spawn_shadow(
        initial: C,
        version: ConfigVersion,
        tx_id: Option<TxId>,
        store: Arc<dyn ManagedDatastore<C>>,
        alarm_manager: SharedAlarmManager,
    ) -> Self {
        let snapshot = Arc::new(AtomicConfigSnapshot::with_state(initial, version, tx_id));
        let subscribers = Arc::new(Mutex::new(Vec::new()));
        let recovery = Arc::new(RecoveryState::default());
        let admission_limits = Arc::new(CommitAdmissionLimits::default());
        let (tx, rx) = mpsc::channel(1);
        drop(rx);

        Self {
            tx,
            snapshot,
            subscribers,
            authority_mode: AuthorityMode::Shadow,
            recovery,
            alarm_manager,
            authorizer: Arc::new(DenyAllAuthorizer),
            admission_limits,
            store,
        }
    }

    /// Enables a serialized candidate payload cap and returns this bus handle.
    ///
    /// The cap is checked before diffing, validation, persistence, or
    /// publication for requests that carry a candidate. The check uses
    /// [`OpcConfig::admission_payload_size_bytes`]; if a cap is configured and
    /// the config implementation cannot report a size, admission fails closed
    /// with `AdmissionRejected`.
    pub fn with_max_serialized_config_bytes(self, max_bytes: usize) -> Self {
        self.set_max_serialized_config_bytes(Some(max_bytes));
        self
    }

    /// Updates the serialized candidate payload cap for this bus and all cloned
    /// handles. `None` disables the cap.
    pub fn set_max_serialized_config_bytes(&self, max_bytes: Option<usize>) {
        self.admission_limits
            .set_max_serialized_config_bytes(max_bytes);
    }

    /// Submits a commit, validate-only, commit-confirmed, or rollback request
    /// and waits for the sequenced worker to finish it.
    ///
    /// Admission never blocks: if the bounded queue (default capacity 32) is
    /// full the request is rejected immediately with `AdmissionRejected` so
    /// callers can apply backpressure. While the recovery fence is raised,
    /// every new mutation fails with `RecoveryRequired`; an exact same-key
    /// retry may still replay an already persisted durable result without a
    /// side effect.
    /// A request is only reported successful after authorization, validation,
    /// durable append, and snapshot publication have all succeeded; failures
    /// before the durable append leave the running config untouched.
    pub async fn submit(&self, request: CommitRequest<C>) -> Result<CommitResult, CommitError> {
        if self.authority_mode == AuthorityMode::Shadow {
            return Err(CommitError::new(
                CommitErrorCode::AdmissionRejected,
                SHADOW_MUTATION_REJECTED_MESSAGE,
            ));
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        let sent = self.tx.try_send(Submission {
            request,
            reply: reply_tx,
        });

        let sub = match sent {
            Ok(_) => {
                crate::metrics::increment_pending_commits();
                true
            }
            Err(err) => {
                let commit_err = match err {
                    TrySendError::Full(_) => CommitError::new(
                        CommitErrorCode::AdmissionRejected,
                        "config commit queue is full",
                    ),
                    TrySendError::Closed(_) => {
                        CommitError::state_machine_fault("config commit worker is unavailable")
                    }
                };
                raise_commit_error(&self.alarm_manager, &commit_err);
                return Err(commit_err);
            }
        };

        let result =
            await_worker_reply(reply_rx, self.recovery.as_ref(), &self.alarm_manager).await;

        if sub {
            crate::metrics::decrement_pending_commits();
        }

        result
    }

    /// Resolve an ambiguous write by its original request identifier.
    ///
    /// This performs an authoritative datastore read and returns the exact
    /// persisted result metadata without exposing the config payload or
    /// principal. Encrypting stores retain a domain-separated request digest
    /// only when the original request had no idempotency key; callers that did
    /// supply one resolve ambiguity by retrying that key instead.
    pub async fn resolve_request_id(
        &self,
        request_id: opc_config_model::RequestId,
    ) -> Result<Option<CommitResult>, StoreError> {
        let Some(record) = self.store.load_by_request_id(request_id).await? else {
            return Ok(None);
        };
        replay_commit_result(&record)
            .map(Some)
            .map_err(|_| StoreError::internal("stored request replay metadata is invalid"))
    }

    /// Registers a change subscriber with its own bounded queue (capacity is
    /// floored at 1) and the given overflow policy.
    ///
    /// A slow subscriber only ever degrades itself — overflow drops events,
    /// disconnects it, or collapses its queue into a resync request according
    /// to `lag_policy` — and never delays publication or other subscribers.
    /// Dropping the returned receiver unregisters the subscription.
    pub fn subscribe(&self, lag_policy: SubscriberLagPolicy, capacity: usize) -> ConfigReceiver<C> {
        let subscriber = Arc::new(SubscriberState::new(lag_policy, capacity.max(1)));
        self.subscribers
            .lock()
            .expect("subscriber list mutex poisoned")
            .push(Arc::clone(&subscriber));
        ConfigReceiver { inner: subscriber }
    }

    /// Returns the published `(tx_id, version, config)` triple read in a
    /// single borrow, so the fields are mutually consistent even while a
    /// commit is publishing concurrently.
    pub fn current_snapshot(&self) -> PublishedSnapshot<C> {
        self.snapshot.current_snapshot()
    }

    /// Returns the exact transaction/version head represented by the local
    /// projection without exposing config bytes to an authority adapter.
    pub fn projection_head(&self) -> ConfigProjectionHead {
        let snapshot = self.snapshot.current_snapshot();
        ConfigProjectionHead::new(snapshot.tx_id, snapshot.version)
    }

    /// Returns a shared handle to the publication slot for data-plane
    /// readers. Reads through it never touch the commit queue, the store, or
    /// any lock held across await points, and the handle keeps working even
    /// if the bus itself is dropped or fenced.
    pub fn snapshot_handle(&self) -> Arc<AtomicConfigSnapshot<C>> {
        Arc::clone(&self.snapshot)
    }

    /// Reports whether this bus is the writer of record for the running
    /// config or a shadow mirror; fixed at construction (built-in
    /// constructors always create authoritative buses).
    pub fn authority_mode(&self) -> AuthorityMode {
        self.authority_mode
    }

    /// Reports whether every new successful mutation returns the exact
    /// persisted plaintext-envelope digest needed for committed-revision
    /// protocol responses.
    ///
    /// Legacy replay records may predate digests. Their replay result keeps
    /// `committed_revision` absent so protocol adapters can fail closed.
    pub fn committed_revision_supported(&self) -> bool {
        self.store.commit_receipts_include_plaintext_digest()
    }

    /// Reports whether the recovery fence is raised. `RecoveryRequired` means
    /// a durable side effect could not be reconciled (ambiguous append,
    /// recovery-marker failure, failed expiry rollback, or a worker panic):
    /// all new writes are rejected until the bus is rebuilt from the store,
    /// while reads keep serving the last published snapshot.
    pub fn drift_state(&self) -> DriftState {
        if self.recovery.reason().is_some() {
            DriftState::RecoveryRequired
        } else {
            DriftState::InSync
        }
    }

    /// Returns the shared alarm manager on which the bus raises and clears
    /// commit/startup failure alarms, so callers can attach the same manager
    /// to their own components or inspect active alarms.
    pub fn alarm_manager(&self) -> SharedAlarmManager {
        self.alarm_manager.clone()
    }

    /// Returns the authorizer consulted before every commit's durable side
    /// effects, so northbound layers can reuse the identical policy for
    /// read-path or pre-flight decisions.
    pub fn authorizer(&self) -> Arc<dyn ConfigAuthorizer> {
        self.authorizer.clone()
    }
}

impl<C: OpcConfig> ConfigSnapshot<C> for ConfigBus<C> {
    fn load(&self) -> Arc<C> {
        self.snapshot.load()
    }

    fn version(&self) -> ConfigVersion {
        self.snapshot.version()
    }
}

fn pending_deadline_fire_at(deadline: &Timestamp) -> tokio::time::Instant {
    let now = Timestamp::now_utc();
    let remaining: std::time::Duration = (*deadline.as_offset_datetime()
        - *now.as_offset_datetime())
    .try_into()
    .unwrap_or_default();
    tokio::time::Instant::now() + remaining
}

async fn worker_loop<C: OpcConfig>(
    mut rx: mpsc::Receiver<Submission<C>>,
    snapshot: Arc<AtomicConfigSnapshot<C>>,
    subscribers: Arc<Mutex<Vec<Arc<SubscriberState<C>>>>>,
    recovery: Arc<RecoveryState>,
    admission_limits: Arc<CommitAdmissionLimits>,
    store: Arc<dyn ManagedDatastore<C>>,
    alarm_manager: SharedAlarmManager,
    authorizer: Arc<dyn ConfigAuthorizer>,
    impact_classifier: Arc<dyn ConfigImpactClassifier<C>>,
    initial_pending_deadline: Option<Timestamp>,
) {
    let mut pending_fire_at = initial_pending_deadline
        .as_ref()
        .map(pending_deadline_fire_at);

    loop {
        let current_fire_at = pending_fire_at;

        tokio::select! {
            submission_opt = rx.recv() => {
                let Some(submission) = submission_opt else {
                    break;
                };

                let has_pending = pending_fire_at.is_some();

                let processed = AssertUnwindSafe(process_commit(
                    submission.request,
                    Arc::clone(&snapshot),
                    Arc::clone(&subscribers),
                    Arc::clone(&recovery),
                    Arc::clone(&admission_limits),
                    store.as_ref(),
                    authorizer.as_ref(),
                    impact_classifier.clone(),
                    has_pending,
                ))
                .catch_unwind()
                .await
                .unwrap_or_else(|_| {
                    tracing::error!("config commit worker caught panic while processing commit");
                    recovery.fence(WORKER_PANIC_RECOVERY_REQUIRED_MESSAGE);
                    Err(CommitError::state_machine_fault(
                        "config commit worker panicked",
                    ))
                });

                if let Ok(processed) = &processed {
                    match &processed.pending_timer_update {
                        PendingTimerUpdate::Unchanged => {}
                        PendingTimerUpdate::Set(deadline) => {
                            pending_fire_at = Some(pending_deadline_fire_at(deadline));
                        }
                        PendingTimerUpdate::Clear => {
                            pending_fire_at = None;
                        }
                    }
                }
                let result = processed.map(|processed| processed.result);

                if result.is_ok() {
                    if let Some(reason) = recovery.reason() {
                        raise_commit_error(
                            &alarm_manager,
                            &CommitError::recovery_required(reason),
                        );
                    } else {
                        apply_commit_alarm_outcome(&alarm_manager, &result);
                    }
                } else {
                    apply_commit_alarm_outcome(&alarm_manager, &result);
                }
                let _ = submission.reply.send(result);
            }
            _ = async {
                if let Some(fire_at) = current_fire_at {
                    tokio::time::sleep_until(fire_at).await;
                }
            }, if current_fire_at.is_some() => {
                tracing::warn!("commit-confirmed deadline expired; rolling back");
                crate::metrics::record_commit_confirmed_deadline_expiry();
                let current_snap = snapshot.current_snapshot();
                let rollback_tx_id = TxId::new();

                let rollback_res = async {
                    let latest_stored = store
                        .load_latest()
                        .await
                        .inspect_err(|err| {
                            log_automatic_store_error(
                                "failed to load latest config during expiry rollback",
                                err,
                            );
                        })?
                        .ok_or_else(|| {
                            StoreError::internal("no config stored during expiry rollback")
                        })?;
                    let parent_tx = latest_stored.parent_tx_id.ok_or_else(|| {
                        StoreError::internal("pending commit has no parent to roll back to")
                    })?;
                    let prev_stored = store
                        .load_rollback(RollbackTarget::TxId(parent_tx))
                        .await
                        .inspect_err(|err| {
                            log_automatic_store_error(
                                "failed to load previous confirmed config during expiry rollback",
                                err,
                            );
                        })?;
                    validate_publishable_stored_config(&prev_stored)?;
                    let validation_context = restore_validation_context(&prev_stored);
                    let rollback_config = validate_startup_config(
                        prev_stored.config,
                        validation_context,
                    )
                    .await?;

                    let rollback_version = current_snap.version.next().ok_or_else(|| {
                        StoreError::internal("version exhausted during expiry rollback")
                    })?;

                    let mut rollback_record = StoredConfig::new(
                        rollback_tx_id,
                        rollback_version,
                        startup_bootstrap_principal(),
                        RequestSource::Internal,
                        rollback_config.clone(),
                    );
                    rollback_record.parent_tx_id = current_snap.tx_id;
                    rollback_record.recovery_required = true;

                    let pending_tx_id = current_snap.tx_id.ok_or_else(|| {
                        StoreError::internal("pending snapshot has no transaction id")
                    })?;
                    if latest_stored.tx_id != pending_tx_id {
                        return Err(StoreError::unavailable(
                            "pending durable transaction changed before rollback",
                        ));
                    }
                    let rollback_write = CommitWrite::resolving(
                        rollback_record,
                        ConfirmedCommitResolution::Rollback { pending_tx_id },
                    )?;
                    store
                        .append_commit_write(rollback_write)
                        .await
                        .inspect_err(|err| {
                        log_automatic_store_error(
                            "failed to append expiry rollback commit",
                            err,
                        );
                    })?;

                    let previous = Arc::clone(&current_snap.config);
                    let (candidate, deltas, changed_paths) = compute_deltas_and_changed_paths(
                        rollback_config,
                        previous,
                        RequestId::new(),
                    ).await.map_err(|err| {
                        drop(err);
                        tracing::error!("failed to compute deltas for expiry rollback");
                        StoreError::internal("failed to compute deltas for expiry rollback")
                    })?;

                    let current_config = Arc::new(candidate);
                    let change = ConfigChange {
                        tx_id: rollback_tx_id,
                        version: rollback_version,
                        previous: Arc::clone(&current_snap.config),
                        current: Arc::clone(&current_config),
                        deltas: Arc::from(deltas),
                        changed_paths: Arc::from(changed_paths),
                    };
                    snapshot.publish(Some(rollback_tx_id), rollback_version, current_config);

                    fanout(&subscribers, change);

                    let marker_clear_error = store
                        .clear_recovery_required(rollback_tx_id)
                        .await
                        .err();
                    if let Some(err) = marker_clear_error.as_ref() {
                            log_automatic_store_error(
                                "failed to clear recovery required on expiry rollback commit",
                                err,
                            );
                    }

                    Ok::<Option<StoreError>, StoreError>(marker_clear_error)
                }.await;

                pending_fire_at = None;

                match rollback_res {
                    Err(err) => {
                        crate::metrics::record_rollback_failure();
                        log_automatic_store_error("expiry rollback failed", &err);
                        recovery.fence(EXPIRY_ROLLBACK_RECOVERY_REQUIRED_MESSAGE);

                        raise_config_error_alarm(
                            &alarm_manager,
                            CONFIG_BUS_COMMIT_FAILURE_ALARM_TYPE,
                            "rollback_failed",
                            "rollback_failed",
                            Severity::Major,
                            ProbableCause::StorageCorruption,
                        );
                    }
                    Ok(marker_clear_error) => {
                        crate::metrics::record_rollback_success();
                        if marker_clear_error.is_some() {
                            recovery.fence(RECOVERY_RECONCILIATION_FAILED_MESSAGE);
                            raise_commit_error(
                                &alarm_manager,
                                &CommitError::recovery_required(
                                    RECOVERY_RECONCILIATION_FAILED_MESSAGE,
                                ),
                            );
                        }
                    }
                }
            }
        }
    }
}

async fn process_commit<C: OpcConfig>(
    mut request: CommitRequest<C>,
    snapshot: Arc<AtomicConfigSnapshot<C>>,
    subscribers: Arc<Mutex<Vec<Arc<SubscriberState<C>>>>>,
    recovery: Arc<RecoveryState>,
    admission_limits: Arc<CommitAdmissionLimits>,
    store: &dyn ManagedDatastore<C>,
    authorizer: &dyn ConfigAuthorizer,
    impact_classifier: Arc<dyn ConfigImpactClassifier<C>>,
    has_pending: bool,
) -> Result<ProcessedCommit, CommitError> {
    if let Some(reason) = recovery.reason() {
        let can_attempt_durable_replay = request.idempotency_key.is_some()
            && matches!(
                request.mode,
                CommitMode::CommitConfirmed { .. }
                    | CommitMode::Commit
                    | CommitMode::CancelConfirmed
                    | CommitMode::Rollback { .. }
            );
        if !can_attempt_durable_replay {
            return Err(CommitError::recovery_required(reason));
        }
    }

    ensure_deadline(request.deadline)?;
    enforce_candidate_payload_limit(request.candidate.as_ref(), admission_limits.as_ref())?;

    let current = snapshot.current_snapshot();
    if matches!(request.mode, CommitMode::CommitConfirmed { .. }) && current.tx_id.is_none() {
        return Err(CommitError::rollback_unavailable(
            "commit-confirmed requires a durable rollback parent",
        ));
    }
    let tx_id = TxId::new();
    let validation_context = ValidationContext {
        request_id: request.request_id,
        principal: request.principal.clone(),
        transport: request.transport,
        source: request.source,
        operation: request.operation,
        mode: request.mode.clone(),
        base_version: current.version,
        previous: Some(Arc::clone(&current.config)),
    };

    match request.mode.clone() {
        CommitMode::ValidateOnly => {
            ensure_candidate_base_version(&request, current.version)?;
            ensure_supported_validate_only_operation(request.operation)?;
            let candidate = request
                .candidate
                .take()
                .ok_or_else(CommitError::missing_candidate)?;
            let previous = Arc::clone(&current.config);
            let (candidate, _deltas, changed_paths) = compute_deltas_and_changed_paths(
                candidate,
                Arc::clone(&previous),
                request.request_id,
            )
            .await?;
            authorize_request(&request, current.version, changed_paths.clone(), authorizer).await?;

            let validate_start = std::time::Instant::now();
            let candidate = validate_candidate(candidate, validation_context.clone()).await?;
            crate::metrics::observe_validate_latency(validate_start.elapsed().as_secs_f64());

            let (_candidate, apply_plan) = classify_apply_plan(
                impact_classifier,
                validation_context,
                previous,
                candidate,
                changed_paths.clone(),
                None,
            )
            .await?;

            ensure_deadline(request.deadline)?;
            Ok(ProcessedCommit::read_only(CommitResult {
                tx_id,
                base_version: current.version,
                new_version: None,
                status: CommitStatus::Validated,
                changed_paths,
                committed_revision: None,
                apply_plan: Some(apply_plan),
            }))
        }
        CommitMode::CommitConfirmed { .. }
        | CommitMode::Commit
        | CommitMode::CancelConfirmed
        | CommitMode::Rollback { .. } => {
            let preauthorized_rollback = matches!(
                request.mode,
                CommitMode::CancelConfirmed | CommitMode::Rollback { .. }
            );
            if preauthorized_rollback {
                authorize_request(
                    &request,
                    current.version,
                    request.changed_paths.clone(),
                    authorizer,
                )
                .await?;
            }

            if let Some(idempotency_key) = request.idempotency_key.as_ref() {
                if let Some(existing) = store
                    .load_by_idempotency_key(idempotency_key)
                    .await
                    .map_err(|err| {
                        log_store_error("load_by_idempotency_key failed", request.request_id, &err);
                        CommitError::state_machine_fault(IDEMPOTENCY_LOOKUP_FAILED_MESSAGE)
                    })?
                {
                    if request_matches_stored_fingerprint(&request, &existing)? {
                        let replay_paths = existing
                            .request_fingerprint
                            .as_ref()
                            .map(|fingerprint| fingerprint.changed_paths.clone())
                            .ok_or_else(|| {
                                CommitError::state_machine_fault(
                                    "idempotent replay requires a persisted request fingerprint",
                                )
                            })?;
                        authorize_request(&request, current.version, replay_paths, authorizer)
                            .await?;
                        return replay_commit_result(&existing).map(ProcessedCommit::read_only);
                    }

                    return Err(CommitError::new(
                        CommitErrorCode::AdmissionRejected,
                        IDEMPOTENCY_KEY_COLLISION_MESSAGE,
                    ));
                }
            }

            // A fenced bus may answer only an exact persisted replay above.
            // Missing and colliding keys must never pass into validation or a
            // new durable mutation, and a fence raised during lookup must be
            // observed before the new-write path.
            if let Some(reason) = recovery.reason() {
                return Err(CommitError::recovery_required(reason));
            }

            // A byte-for-byte retry of the request that created the pending
            // commit is resolved above before this new-write guard. Without
            // that ordering, a lost acknowledgement would make the original
            // commit-confirmed result permanently unrecoverable.
            if matches!(request.mode, CommitMode::CommitConfirmed { .. }) && has_pending {
                return Err(CommitError::new(
                    CommitErrorCode::AdmissionRejected,
                    PENDING_CONFIRMED_UPDATE_UNSUPPORTED_MESSAGE,
                ));
            }

            ensure_candidate_base_version(&request, current.version)?;
            let candidate_was_supplied = request.candidate.is_some();

            let apply_start = std::time::Instant::now();
            let previous = Arc::clone(&current.config);
            let candidate = resolve_candidate(
                request.request_id,
                request.mode.clone(),
                request.candidate.take(),
                store,
                Arc::clone(&previous),
                has_pending,
            )
            .await?;
            let (candidate, deltas, changed_paths) = compute_deltas_and_changed_paths(
                candidate,
                Arc::clone(&previous),
                request.request_id,
            )
            .await?;
            crate::metrics::observe_apply_latency(apply_start.elapsed().as_secs_f64());

            authorize_request(&request, current.version, changed_paths.clone(), authorizer).await?;

            let validate_start = std::time::Instant::now();
            let candidate = validate_candidate(candidate, validation_context.clone()).await?;
            crate::metrics::observe_validate_latency(validate_start.elapsed().as_secs_f64());

            let (candidate, apply_plan) = match &request.mode {
                CommitMode::Commit | CommitMode::CommitConfirmed { .. } => {
                    let (candidate, plan) = classify_apply_plan(
                        impact_classifier,
                        validation_context,
                        Arc::clone(&previous),
                        candidate,
                        changed_paths.clone(),
                        None,
                    )
                    .await?;
                    (candidate, Some(plan))
                }
                CommitMode::Rollback { target } => (
                    candidate,
                    Some(
                        ApplyPlan::default_hot(changed_paths.clone(), Some(target.clone()))
                            .normalize(),
                    ),
                ),
                CommitMode::CancelConfirmed => (candidate, None),
                CommitMode::ValidateOnly => {
                    unreachable!("handled above")
                }
            };

            ensure_deadline(request.deadline)?;

            let new_version = current.version.next().ok_or_else(|| {
                CommitError::new(
                    CommitErrorCode::VersionExhausted,
                    "running config version counter is exhausted",
                )
            })?;
            let request_fingerprint = persisted_request_fingerprint(
                &request,
                candidate_was_supplied,
                changed_paths.clone(),
                current.version,
            );
            let reconciliation_candidate = candidate_was_supplied.then(|| candidate.clone());
            let confirmed_deadline = match &request.mode {
                CommitMode::CommitConfirmed { timeout } => Some(Timestamp::from_offset_datetime(
                    time::OffsetDateTime::now_utc() + *timeout,
                )),
                _ => None,
            };

            let mut record = StoredConfig::new(
                tx_id,
                new_version,
                request.principal.clone(),
                request.source,
                candidate.clone(),
            );
            record.parent_tx_id = current.tx_id;
            record.request_fingerprint = request_fingerprint;
            record.request_id = Some(request.request_id);
            record.idempotency_key = request.idempotency_key.clone();
            record.apply_plan = apply_plan.clone();
            record.recovery_required = true;
            record.confirmed_deadline = confirmed_deadline;

            let resolution = if has_pending {
                let pending_tx_id = current.tx_id.ok_or_else(|| {
                    CommitError::state_machine_fault(
                        "pending commit-confirmed snapshot has no transaction id",
                    )
                })?;
                match &request.mode {
                    CommitMode::Commit => {
                        Some(ConfirmedCommitResolution::Confirm { pending_tx_id })
                    }
                    CommitMode::CancelConfirmed | CommitMode::Rollback { .. } => {
                        Some(ConfirmedCommitResolution::Rollback { pending_tx_id })
                    }
                    CommitMode::ValidateOnly | CommitMode::CommitConfirmed { .. } => None,
                }
            } else {
                None
            };
            let write = match resolution {
                Some(resolution) => CommitWrite::resolving(record, resolution).map_err(|_| {
                    CommitError::state_machine_fault("invalid durable commit write")
                })?,
                None => CommitWrite::new(record),
            };

            let persist_start = std::time::Instant::now();
            let receipt = match AssertUnwindSafe(store.append_commit_write_with_receipt(write))
                .catch_unwind()
                .await
            {
                Err(panic_payload) => {
                    drop(panic_payload);
                    tracing::error!(
                        request_id = %request.request_id,
                        "managed datastore panicked during append; durable outcome is unknown"
                    );
                    recovery.fence(OUTCOME_UNKNOWN_MESSAGE);
                    return Err(CommitError::outcome_unknown(OUTCOME_UNKNOWN_MESSAGE));
                }
                Ok(Err(err)) => {
                    log_store_error("append_commit failed", request.request_id, &err);
                    if err.code == StoreErrorCode::OutcomeUnknown {
                        recovery.fence(OUTCOME_UNKNOWN_MESSAGE);
                        return Err(CommitError::outcome_unknown(OUTCOME_UNKNOWN_MESSAGE));
                    }

                    // A leadership handoff can let two workers both miss the
                    // replay index before one wins the compare-and-append.
                    // Re-read the authoritative index after a definite
                    // rejection so the loser reports the committed logical
                    // request, rather than a false PersistFailed result.
                    request.candidate = reconciliation_candidate;
                    match load_reconciliation_record(store, &request).await {
                        Ok(Some(existing)) => {
                            if request_matches_stored_fingerprint(&request, &existing)? {
                                recovery.fence(CONCURRENT_COMMIT_RECOVERY_REQUIRED_MESSAGE);
                                return replay_commit_result(&existing)
                                    .map(ProcessedCommit::read_only);
                            }
                            return Err(CommitError::new(
                                CommitErrorCode::AdmissionRejected,
                                replay_collision_message(&request),
                            ));
                        }
                        Ok(None) => {}
                        Err(lookup_error) => {
                            log_store_error(
                                "post-append reconciliation lookup failed",
                                request.request_id,
                                &lookup_error,
                            );
                            recovery.fence(OUTCOME_UNKNOWN_MESSAGE);
                            return Err(CommitError::outcome_unknown(OUTCOME_UNKNOWN_MESSAGE));
                        }
                    }
                    return Err(CommitError::persist_failed(PERSIST_FAILED_MESSAGE));
                }
                Ok(Ok(receipt)) => receipt,
            };

            let current_config = Arc::new(candidate);
            let change = ConfigChange {
                tx_id,
                version: new_version,
                previous,
                current: Arc::clone(&current_config),
                deltas: Arc::from(deltas),
                changed_paths: Arc::from(changed_paths.clone()),
            };

            snapshot.publish(Some(tx_id), new_version, Arc::clone(&current_config));

            match AssertUnwindSafe(store.clear_recovery_required(tx_id))
                .catch_unwind()
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    log_store_error("clear_recovery_required failed", request.request_id, &err);
                    recovery.fence(RECOVERY_RECONCILIATION_FAILED_MESSAGE);
                }
                Err(panic_payload) => {
                    drop(panic_payload);
                    tracing::error!(
                        request_id = %request.request_id,
                        "managed datastore panicked while clearing the recovery marker"
                    );
                    recovery.fence(RECOVERY_RECONCILIATION_FAILED_MESSAGE);
                }
            }
            crate::metrics::observe_persist_latency(persist_start.elapsed().as_secs_f64());

            let notify_start = std::time::Instant::now();
            fanout(&subscribers, change);
            crate::metrics::observe_notify_latency(notify_start.elapsed().as_secs_f64());

            let status = match &request.mode {
                CommitMode::Commit => CommitStatus::Committed,
                CommitMode::CommitConfirmed { .. } => CommitStatus::CommitConfirmedPending,
                CommitMode::CancelConfirmed | CommitMode::Rollback { .. } => {
                    CommitStatus::RollbackApplied
                }
                CommitMode::ValidateOnly => {
                    unreachable!("handled above")
                }
            };

            Ok(ProcessedCommit {
                result: CommitResult {
                    tx_id,
                    base_version: current.version,
                    new_version: Some(new_version),
                    status,
                    changed_paths,
                    committed_revision: receipt
                        .plaintext_digest()
                        .map(|digest| CommittedConfigRevision::new(new_version, digest)),
                    apply_plan,
                },
                pending_timer_update: match confirmed_deadline {
                    Some(deadline) => PendingTimerUpdate::Set(deadline),
                    None => PendingTimerUpdate::Clear,
                },
            })
        }
    }
}

fn ensure_candidate_base_version<C: OpcConfig>(
    request: &CommitRequest<C>,
    running_version: ConfigVersion,
) -> Result<(), CommitError> {
    let candidate_bearing_mode = matches!(
        request.mode,
        CommitMode::ValidateOnly | CommitMode::Commit | CommitMode::CommitConfirmed { .. }
    );
    if candidate_bearing_mode
        && request.candidate.is_some()
        && request.base_version != running_version
    {
        return Err(CommitError::new(
            CommitErrorCode::AdmissionRejected,
            STALE_BASE_VERSION_MESSAGE,
        ));
    }
    Ok(())
}

fn enforce_candidate_payload_limit<C: OpcConfig>(
    candidate: Option<&C>,
    admission_limits: &CommitAdmissionLimits,
) -> Result<(), CommitError> {
    let Some(max_bytes) = admission_limits.max_serialized_config_bytes() else {
        return Ok(());
    };
    let Some(candidate) = candidate else {
        return Ok(());
    };

    let payload_size = candidate
        .admission_payload_size_bytes()
        .map_err(|_err| {
            CommitError::new(
                CommitErrorCode::AdmissionRejected,
                CANDIDATE_PAYLOAD_SIZE_FAILED_MESSAGE,
            )
        })?
        .ok_or_else(|| {
            CommitError::new(
                CommitErrorCode::AdmissionRejected,
                CANDIDATE_PAYLOAD_SIZE_UNAVAILABLE_MESSAGE,
            )
        })?;

    if payload_size > max_bytes {
        return Err(CommitError::new(
            CommitErrorCode::AdmissionRejected,
            format!(
                "config candidate serialized payload is {payload_size} bytes, exceeding limit of {max_bytes} bytes"
            ),
        ));
    }

    Ok(())
}

async fn authorize_request<C: OpcConfig>(
    request: &CommitRequest<C>,
    running_version: ConfigVersion,
    changed_paths: Vec<YangPath>,
    authorizer: &dyn ConfigAuthorizer,
) -> Result<(), CommitError> {
    let auth_ctx = crate::authorizer::AuthorizationContext {
        principal: request.principal.clone(),
        transport: request.transport,
        source: request.source,
        operation: request.operation,
        mode: request.mode.clone(),
        changed_paths,
        running_version,
        request_id: request.request_id,
        idempotency_key: request.idempotency_key.clone(),
    };

    authorizer
        .authorize(&auth_ctx)
        .await
        .map_err(|_auth_err| CommitError::authorization_denied("authorization denied"))
}

async fn load_reconciliation_record<C: OpcConfig>(
    store: &dyn ManagedDatastore<C>,
    request: &CommitRequest<C>,
) -> Result<Option<StoredConfig<C>>, StoreError> {
    match request.idempotency_key.as_ref() {
        Some(idempotency_key) => store.load_by_idempotency_key(idempotency_key).await,
        None => store.load_by_request_id(request.request_id).await,
    }
}

fn replay_collision_message<C: OpcConfig>(request: &CommitRequest<C>) -> &'static str {
    if request.idempotency_key.is_some() {
        IDEMPOTENCY_KEY_COLLISION_MESSAGE
    } else {
        REQUEST_ID_COLLISION_MESSAGE
    }
}

fn replay_commit_result<C: OpcConfig>(
    stored: &StoredConfig<C>,
) -> Result<CommitResult, CommitError> {
    let fingerprint = stored.request_fingerprint.as_ref().ok_or_else(|| {
        CommitError::state_machine_fault(
            "request reconciliation requires a persisted request fingerprint",
        )
    })?;
    let status = match &fingerprint.mode {
        StoredRequestMode::Commit | StoredRequestMode::ConfirmPending => CommitStatus::Committed,
        StoredRequestMode::CommitConfirmed { .. } => CommitStatus::CommitConfirmedPending,
        StoredRequestMode::CancelConfirmed | StoredRequestMode::Rollback { .. } => {
            CommitStatus::RollbackApplied
        }
    };

    let base_version = fingerprint
        .base_version
        .unwrap_or_else(|| ConfigVersion::new(stored.version.get().saturating_sub(1)));

    Ok(CommitResult {
        tx_id: stored.tx_id,
        base_version,
        new_version: Some(stored.version),
        status,
        changed_paths: fingerprint.changed_paths.clone(),
        committed_revision: stored
            .plaintext_digest
            .map(|digest| CommittedConfigRevision::new(stored.version, digest)),
        apply_plan: stored.apply_plan.clone(),
    })
}

fn persisted_request_fingerprint<C: OpcConfig>(
    request: &CommitRequest<C>,
    candidate_was_supplied: bool,
    changed_paths: Vec<YangPath>,
    base_version: ConfigVersion,
) -> Option<StoredRequestFingerprint> {
    let mode = match &request.mode {
        CommitMode::Commit if !candidate_was_supplied => StoredRequestMode::ConfirmPending,
        CommitMode::Commit => StoredRequestMode::Commit,
        CommitMode::CommitConfirmed { timeout } => {
            StoredRequestMode::CommitConfirmed { timeout: *timeout }
        }
        CommitMode::CancelConfirmed => StoredRequestMode::CancelConfirmed,
        CommitMode::Rollback { target } => StoredRequestMode::Rollback {
            target: target.clone(),
        },
        CommitMode::ValidateOnly => return None,
    };

    Some(StoredRequestFingerprint {
        operation: request.operation,
        mode,
        transport: request.transport,
        changed_paths,
        base_version: Some(base_version),
    })
}

fn request_matches_stored_fingerprint<C: OpcConfig>(
    request: &CommitRequest<C>,
    stored: &StoredConfig<C>,
) -> Result<bool, CommitError> {
    let Some(fingerprint) = stored.request_fingerprint.as_ref() else {
        return Ok(false);
    };

    if !principal_matches_idempotent_context(&request.principal, &stored.principal)
        || request.source != stored.source
        || request.transport != fingerprint.transport
    {
        return Ok(false);
    }

    if request.operation != fingerprint.operation {
        return Ok(false);
    }

    match (&request.mode, &fingerprint.mode) {
        (CommitMode::Commit, StoredRequestMode::Commit) => {
            let Some(candidate) = request.candidate.as_ref() else {
                return Ok(false);
            };
            if request.base_version != stored_request_base_version(stored, fingerprint) {
                return Ok(false);
            }
            candidate_matches_stored(candidate, &stored.config)
        }
        (
            CommitMode::CommitConfirmed { timeout },
            StoredRequestMode::CommitConfirmed {
                timeout: stored_timeout,
            },
        ) => {
            if timeout != stored_timeout {
                return Ok(false);
            }
            let Some(candidate) = request.candidate.as_ref() else {
                return Ok(false);
            };
            if request.base_version != stored_request_base_version(stored, fingerprint) {
                return Ok(false);
            }
            candidate_matches_stored(candidate, &stored.config)
        }
        (CommitMode::CancelConfirmed, StoredRequestMode::CancelConfirmed) => {
            Ok(request.candidate.is_none())
        }
        (CommitMode::Commit, StoredRequestMode::ConfirmPending) => Ok(request.candidate.is_none()),
        (
            CommitMode::Rollback { target },
            StoredRequestMode::Rollback {
                target: stored_target,
            },
        ) => Ok(target == stored_target),
        _ => Ok(false),
    }
}

fn stored_request_base_version<C: OpcConfig>(
    stored: &StoredConfig<C>,
    fingerprint: &StoredRequestFingerprint,
) -> ConfigVersion {
    fingerprint
        .base_version
        .unwrap_or_else(|| ConfigVersion::new(stored.version.get().saturating_sub(1)))
}

fn principal_matches_idempotent_context(
    request: &TrustedPrincipal,
    stored: &TrustedPrincipal,
) -> bool {
    request.identity == stored.identity
        && request.tenant == stored.tenant
        && request.auth_strength == stored.auth_strength
        && claims_match_order_insensitively(&request.roles, &stored.roles)
        && claims_match_order_insensitively(&request.groups, &stored.groups)
}

fn claims_match_order_insensitively(request: &[String], stored: &[String]) -> bool {
    let mut a: Vec<_> = request.iter().collect();
    let mut b: Vec<_> = stored.iter().collect();
    a.sort();
    b.sort();
    a == b
}

async fn compute_deltas_and_changed_paths<C: OpcConfig>(
    candidate: C,
    previous: Arc<C>,
    request_id: RequestId,
) -> Result<(C, Vec<C::Delta>, Vec<YangPath>), CommitError> {
    tokio::task::spawn_blocking(move || {
        let deltas = candidate.diff(previous.as_ref()).map_err(|err| {
            log_diff_failure(request_id, &err);
            CommitError::diff_failed(err)
        })?;
        let changed_paths = candidate
            .changed_paths(previous.as_ref(), &deltas)
            .map_err(|err| {
                log_diff_failure(request_id, &err);
                CommitError::diff_failed(err)
            })?;
        if !deltas.is_empty() && changed_paths.is_empty() {
            let err = ConfigError::new(
                "changed-path",
                EMPTY_CHANGED_PATHS_FOR_NONEMPTY_DIFF_MESSAGE,
            );
            log_diff_failure(request_id, &err);
            return Err(CommitError::diff_failed(err));
        }
        Ok::<_, CommitError>((candidate, deltas, changed_paths))
    })
    .await
    .map_err(|_| CommitError::state_machine_fault("diff task panicked"))?
}

fn candidate_matches_stored<C: OpcConfig>(candidate: &C, stored: &C) -> Result<bool, CommitError> {
    if candidate.schema_digest() != stored.schema_digest() {
        return Ok(false);
    }

    let forward = candidate.diff(stored).map_err(CommitError::diff_failed)?;
    if !forward.is_empty() {
        return Ok(false);
    }

    let reverse = stored.diff(candidate).map_err(CommitError::diff_failed)?;
    Ok(reverse.is_empty())
}

async fn validate_candidate<C: OpcConfig>(
    candidate: C,
    ctx: ValidationContext<C>,
) -> Result<C, CommitError> {
    let request_id = ctx.request_id;
    tokio::task::spawn_blocking(move || {
        candidate.validate_syntax().map_err(|err| {
            log_commit_validation_failure(request_id, &err);
            CommitError::syntax_validation(err)
        })?;
        candidate.validate_semantics(&ctx).map_err(|err| {
            log_commit_validation_failure(request_id, &err);
            CommitError::semantic_validation(err)
        })?;
        Ok::<_, CommitError>(candidate)
    })
    .await
    .map_err(|_| CommitError::state_machine_fault("validation task panicked"))?
}

async fn classify_apply_plan<C: OpcConfig>(
    impact_classifier: Arc<dyn ConfigImpactClassifier<C>>,
    ctx: ValidationContext<C>,
    previous: Arc<C>,
    candidate: C,
    changed_paths: Vec<YangPath>,
    rollback_target: Option<RollbackTarget>,
) -> Result<(C, ApplyPlan), CommitError> {
    let request_id = ctx.request_id;
    tokio::task::spawn_blocking(move || {
        let mut plan = impact_classifier
            .classify(&ctx, Some(previous.as_ref()), &candidate, &changed_paths)
            .map_err(|err| {
                log_apply_plan_classifier_failure(request_id, &err);
                CommitError::new(
                    CommitErrorCode::ApplyPlanRejected,
                    "config apply plan classification failed",
                )
            })?;
        if plan.rollback_target.is_none() {
            plan.rollback_target = rollback_target;
        }
        let plan = plan.normalize();
        if !plan.commit_allowed() {
            return Err(CommitError::apply_plan_rejected(plan));
        }
        Ok::<_, CommitError>((candidate, plan))
    })
    .await
    .map_err(|_| CommitError::state_machine_fault("apply-plan classification task panicked"))?
}

fn ensure_supported_validate_only_operation(operation: ConfigOperation) -> Result<(), CommitError> {
    if matches!(operation, ConfigOperation::Replace) {
        Ok(())
    } else {
        Err(CommitError::new(
            CommitErrorCode::AdmissionRejected,
            UNSUPPORTED_VALIDATE_ONLY_OPERATION_MESSAGE,
        ))
    }
}

fn log_commit_validation_failure(request_id: RequestId, error: &ValidationError) {
    tracing::warn!(
        request_id = %request_id,
        validation_stage = %error.stage,
        validation_error = %redact(&error.message),
        "candidate config validation failed"
    );
}

fn log_diff_failure(request_id: RequestId, error: &ConfigError) {
    tracing::warn!(
        request_id = %request_id,
        diff_error_kind = %error.kind(),
        diff_error = %redact(error.message()),
        "candidate config diff generation failed"
    );
}

fn log_apply_plan_classifier_failure(request_id: RequestId, error: &ConfigError) {
    tracing::warn!(
        request_id = %request_id,
        apply_plan_error_kind = %error.kind(),
        apply_plan_error = %redact(error.message()),
        "candidate config apply-plan classification failed"
    );
}

fn fanout<C: OpcConfig>(
    subscribers: &Arc<Mutex<Vec<Arc<SubscriberState<C>>>>>,
    change: ConfigChange<C>,
) {
    let snapshot = {
        let mut guard = match subscribers.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                tracing::error!("recovering poisoned config subscriber-list state");
                poisoned.into_inner()
            }
        };
        guard.retain(|subscriber| !subscriber.closed.load(Ordering::Acquire));
        guard.clone()
    };

    for subscriber in snapshot {
        subscriber.enqueue(ConfigEvent::Change(change.clone()));
    }
}

fn log_store_error(operation: &str, request_id: RequestId, error: &StoreError) {
    tracing::error!(
        request_id = %request_id,
        store_error_code = %error.code,
        store_error = %redact(&error.message),
        "{operation}"
    );
}

fn log_automatic_store_error(operation: &str, error: &StoreError) {
    tracing::error!(
        store_error_code = %error.code,
        store_error = %redact(&error.message),
        "{operation}"
    );
}

fn ensure_deadline(deadline: Instant) -> Result<(), CommitError> {
    if Instant::now() > deadline {
        Err(CommitError::deadline_exceeded(
            "request deadline expired before publication",
        ))
    } else {
        Ok(())
    }
}

fn dropped_worker_reply_error() -> CommitError {
    // The worker owns the durable boundary. Losing its response cannot prove
    // whether it stopped before or after append, so this is never an ordinary
    // state-machine failure.
    CommitError::outcome_unknown(OUTCOME_UNKNOWN_MESSAGE)
}

async fn await_worker_reply(
    reply_rx: oneshot::Receiver<Result<CommitResult, CommitError>>,
    recovery: &RecoveryState,
    alarm_manager: &SharedAlarmManager,
) -> Result<CommitResult, CommitError> {
    match reply_rx.await {
        Ok(result) => result,
        Err(_) => {
            recovery.fence(OUTCOME_UNKNOWN_MESSAGE);
            let error = dropped_worker_reply_error();
            raise_commit_error(alarm_manager, &error);
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fmt, sync::MutexGuard};
    use tracing::{
        field::{Field, Visit},
        span::{Attributes, Id, Record},
        Event, Metadata, Subscriber,
    };

    #[derive(Default)]
    struct EventVisitor {
        entries: Vec<String>,
    }

    impl Visit for EventVisitor {
        fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
            self.entries.push(format!("{}={value:?}", field.name()));
        }
    }

    struct CaptureSubscriber {
        events: Arc<Mutex<Vec<String>>>,
    }

    impl CaptureSubscriber {
        fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
            Self { events }
        }

        fn lock_events(&self) -> MutexGuard<'_, Vec<String>> {
            self.events.lock().expect("capture mutex poisoned")
        }
    }

    impl Subscriber for CaptureSubscriber {
        fn enabled(&self, _: &Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }

        fn record(&self, _: &Id, _: &Record<'_>) {}

        fn record_follows_from(&self, _: &Id, _: &Id) {}

        fn event(&self, event: &Event<'_>) {
            let mut visitor = EventVisitor::default();
            event.record(&mut visitor);
            self.lock_events().push(visitor.entries.join(" "));
        }

        fn enter(&self, _: &Id) {}

        fn exit(&self, _: &Id) {}
    }

    #[test]
    fn store_error_logs_are_redacted() {
        let secret = "dsn=postgres://user:secret@db/internal";
        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = CaptureSubscriber::new(Arc::clone(&captured));

        tracing::subscriber::with_default(subscriber, || {
            log_store_error(
                "append_commit failed",
                RequestId::new(),
                &StoreError::internal(secret),
            );
        });

        let rendered = captured.lock().expect("capture mutex poisoned").join("\n");

        assert!(!rendered.contains(secret));
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("internal"));
    }

    #[test]
    fn automatic_expiry_store_error_logs_are_redacted() {
        let secret = "token=expiry-rollback-secret";
        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = CaptureSubscriber::new(Arc::clone(&captured));

        tracing::subscriber::with_default(subscriber, || {
            log_automatic_store_error("expiry rollback failed", &StoreError::internal(secret));
        });

        let rendered = captured.lock().expect("capture mutex poisoned").join("\n");
        assert!(!rendered.contains(secret));
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("internal"));
    }

    #[tokio::test]
    async fn dropped_worker_reply_is_an_ambiguous_fenced_outcome() {
        let (reply_tx, reply_rx) = oneshot::channel();
        drop(reply_tx);
        let recovery = RecoveryState::default();
        let alarms = SharedAlarmManager::default();

        let error = await_worker_reply(reply_rx, &recovery, &alarms)
            .await
            .expect_err("a lost worker reply cannot prove the durable outcome");

        assert_eq!(error.code, CommitErrorCode::OutcomeUnknown);
        assert_eq!(error.message, OUTCOME_UNKNOWN_MESSAGE);
        assert_eq!(recovery.reason().as_deref(), Some(OUTCOME_UNKNOWN_MESSAGE));
        let active = alarms.active_alarms();
        assert_eq!(active.len(), 1);
        assert_eq!(
            active[0].alarm_type.as_str(),
            CONFIG_BUS_COMMIT_FAILURE_ALARM_TYPE
        );
    }
}
