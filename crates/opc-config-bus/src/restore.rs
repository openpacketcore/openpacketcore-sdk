//! `ConfigBus` constructors and startup recovery (RFC 001 §12): restore the
//! highest stored config, fail closed on schema mismatch or unreconciled
//! recovery markers, validate before publication, and automatically roll back
//! expired commit-confirmed records on restart.

use opc_alarm::SharedAlarmManager;
use opc_config_model::{
    CommitMode, ConfigImpactClassifier, ConfigOperation, HotConfigImpactClassifier, OpcConfig,
    RequestId, RequestSource, RollbackTarget, TransportType, TrustedPrincipal, ValidationContext,
    ValidationError, WorkloadIdentity,
};
use opc_types::{redact, ConfigVersion, TenantId, Timestamp, TxId};
use std::sync::{Arc, LazyLock};

use crate::alarms::{clear_config_alarm_type, preserve_startup_error};
use crate::authorizer::{AllowAllAuthorizer, ConfigAuthorizer};
use crate::commit::{ConfigBus, DEFAULT_COMMIT_QUEUE_CAPACITY};
use crate::datastore::ManagedDatastore;
use crate::types::{
    AuthorityMode, CommitWrite, ConfirmedCommitResolution, StoreError, StoredConfig,
    StoredRequestMode,
};

pub(crate) const RESTORE_SCHEMA_MISMATCH_MESSAGE: &str =
    "stored running config schema digest mismatch";
pub(crate) const RESTORE_RECOVERY_REQUIRED_MESSAGE: &str =
    "stored running config requires recovery reconciliation";
pub(crate) const RESTORE_CONFIRMED_DEADLINE_MESSAGE: &str =
    "stored running config requires commit-confirmed recovery";
const STARTUP_SYNTAX_VALIDATION_FAILED_MESSAGE: &str = "startup config failed syntax validation";
const STARTUP_SEMANTIC_VALIDATION_FAILED_MESSAGE: &str =
    "startup config failed semantic validation";
const STARTUP_VALIDATION_TASK_FAILED_MESSAGE: &str = "startup config validation task panicked";

static STARTUP_BOOTSTRAP_PRINCIPAL: LazyLock<TrustedPrincipal> = LazyLock::new(|| {
    TrustedPrincipal::new(
        WorkloadIdentity::Internal("startup".into()),
        TenantId::new("system").expect("static bootstrap tenant id must be valid"),
    )
});

pub(crate) fn startup_bootstrap_principal() -> TrustedPrincipal {
    STARTUP_BOOTSTRAP_PRINCIPAL.clone()
}

fn default_impact_classifier<C: OpcConfig>() -> Arc<dyn ConfigImpactClassifier<C>> {
    Arc::new(HotConfigImpactClassifier)
}

pub(crate) fn startup_validation_context<C: OpcConfig>(
    principal: TrustedPrincipal,
    base_version: ConfigVersion,
) -> ValidationContext<C> {
    ValidationContext {
        request_id: RequestId::new(),
        principal,
        transport: TransportType::Internal,
        source: RequestSource::StartupRecovery,
        operation: ConfigOperation::Replace,
        mode: CommitMode::Commit,
        base_version,
        previous: None,
    }
}

pub(crate) fn restore_validation_context<C: OpcConfig>(
    stored: &StoredConfig<C>,
) -> ValidationContext<C> {
    let request_id = stored.request_id.unwrap_or_default();
    let base_version = stored
        .request_fingerprint
        .as_ref()
        .and_then(|fp| fp.base_version)
        .unwrap_or_else(|| ConfigVersion::new(stored.version.get().saturating_sub(1)));

    let Some(fingerprint) = stored.request_fingerprint.as_ref() else {
        let mut ctx = startup_validation_context(stored.principal.clone(), base_version);
        ctx.request_id = request_id;
        return ctx;
    };

    ValidationContext {
        request_id,
        principal: stored.principal.clone(),
        transport: fingerprint.transport,
        source: stored.source,
        operation: fingerprint.operation,
        mode: restore_commit_mode(&fingerprint.mode),
        base_version,
        previous: None,
    }
}

fn restore_commit_mode(mode: &StoredRequestMode) -> CommitMode {
    match mode {
        StoredRequestMode::Commit => CommitMode::Commit,
        StoredRequestMode::CommitConfirmed { timeout } => {
            CommitMode::CommitConfirmed { timeout: *timeout }
        }
        StoredRequestMode::CancelConfirmed => CommitMode::CancelConfirmed,
        StoredRequestMode::ConfirmPending => CommitMode::Commit,
        StoredRequestMode::Rollback { target } => CommitMode::Rollback {
            target: target.clone(),
        },
    }
}

pub(crate) async fn validate_startup_config<C: OpcConfig>(
    config: C,
    ctx: ValidationContext<C>,
) -> Result<C, StoreError> {
    let request_id = ctx.request_id;
    tokio::task::spawn_blocking(move || {
        config.validate_syntax().map_err(|err| {
            log_startup_validation_failure(request_id, &err);
            StoreError::startup_syntax_validation_failed(STARTUP_SYNTAX_VALIDATION_FAILED_MESSAGE)
        })?;
        config.validate_semantics(&ctx).map_err(|err| {
            log_startup_validation_failure(request_id, &err);
            StoreError::startup_semantic_validation_failed(
                STARTUP_SEMANTIC_VALIDATION_FAILED_MESSAGE,
            )
        })?;
        Ok::<_, StoreError>(config)
    })
    .await
    .map_err(|_| {
        tracing::error!(
            request_id = %request_id,
            "startup config validation task panicked"
        );
        StoreError::startup_validation_task_failed(STARTUP_VALIDATION_TASK_FAILED_MESSAGE)
    })?
}

fn log_startup_validation_failure(request_id: RequestId, error: &ValidationError) {
    tracing::error!(
        request_id = %request_id,
        validation_stage = %error.stage,
        validation_error = %redact(&error.message),
        "startup config validation failed"
    );
}

pub(crate) fn validate_publishable_stored_config<C: OpcConfig>(
    stored: &StoredConfig<C>,
) -> Result<(), StoreError> {
    validate_stored_schema_digest(stored)?;
    validate_restored_recovery_marker(stored)?;
    validate_restored_confirmed_deadline(stored)
}

pub(crate) fn validate_stored_schema_digest<C: OpcConfig>(
    stored: &StoredConfig<C>,
) -> Result<(), StoreError> {
    let actual = stored.config.schema_digest();
    if stored.schema_digest != actual {
        tracing::error!(
            tx_id = %stored.tx_id,
            version = %stored.version,
            stored_schema_digest = %stored.schema_digest,
            computed_schema_digest = %actual,
            "stored running config schema digest mismatch"
        );
        Err(StoreError::restore_schema_mismatch(
            RESTORE_SCHEMA_MISMATCH_MESSAGE,
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_restored_recovery_marker<C: OpcConfig>(
    stored: &StoredConfig<C>,
) -> Result<(), StoreError> {
    if stored.recovery_required {
        tracing::error!(
            tx_id = %stored.tx_id,
            version = %stored.version,
            "stored running config requires recovery reconciliation before publication"
        );
        Err(StoreError::restore_recovery_required(
            RESTORE_RECOVERY_REQUIRED_MESSAGE,
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn validate_restored_confirmed_deadline<C: OpcConfig>(
    stored: &StoredConfig<C>,
) -> Result<(), StoreError> {
    if let Some(confirmed_deadline) = stored.confirmed_deadline {
        tracing::error!(
            tx_id = %stored.tx_id,
            version = %stored.version,
            confirmed_deadline = %confirmed_deadline,
            "stored running config requires commit-confirmed recovery before publication"
        );
        Err(StoreError::restore_confirmed_deadline(
            RESTORE_CONFIRMED_DEADLINE_MESSAGE,
        ))
    } else {
        Ok(())
    }
}

impl<C: OpcConfig> ConfigBus<C> {
    /// Builds a config bus with an internal alarm manager.
    pub async fn new<S>(
        initial: C,
        store: S,
        authorizer: Arc<dyn ConfigAuthorizer>,
    ) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        Self::with_queue_capacity(initial, store, DEFAULT_COMMIT_QUEUE_CAPACITY, authorizer).await
    }

    /// Dev/Test convenience constructor that implicitly installs `AllowAllAuthorizer`.
    pub async fn new_dev_only<S>(initial: C, store: S) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        Self::new(initial, store, Arc::new(AllowAllAuthorizer)).await
    }

    /// Compatibility alias for callers that already used the explicit authorizer constructor.
    pub async fn new_with_authorizer<S>(
        initial: C,
        store: S,
        authorizer: Arc<dyn ConfigAuthorizer>,
    ) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        Self::new(initial, store, authorizer).await
    }

    /// Builds a config bus with an internal alarm manager and queue capacity.
    pub async fn with_queue_capacity<S>(
        initial: C,
        store: S,
        queue_capacity: usize,
        authorizer: Arc<dyn ConfigAuthorizer>,
    ) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        Self::with_queue_capacity_and_alarm_manager(
            initial,
            store,
            queue_capacity,
            authorizer,
            SharedAlarmManager::default(),
        )
        .await
    }

    /// Dev/Test variant of `with_queue_capacity` that implicitly installs
    /// `AllowAllAuthorizer`; never use in production, where authorization
    /// must be default-deny.
    pub async fn with_queue_capacity_dev_only<S>(
        initial: C,
        store: S,
        queue_capacity: usize,
    ) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        Self::with_queue_capacity(initial, store, queue_capacity, Arc::new(AllowAllAuthorizer))
            .await
    }

    /// Builds a fresh (non-restoring) bus that raises startup and commit
    /// failure alarms on the supplied shared alarm manager instead of a
    /// private one, using the default commit queue capacity of 32.
    pub async fn new_with_alarm_manager<S>(
        initial: C,
        store: S,
        authorizer: Arc<dyn ConfigAuthorizer>,
        alarm_manager: SharedAlarmManager,
    ) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        Self::with_queue_capacity_and_alarm_manager(
            initial,
            store,
            DEFAULT_COMMIT_QUEUE_CAPACITY,
            authorizer,
            alarm_manager,
        )
        .await
    }

    /// Dev/Test variant of `new_with_alarm_manager` that implicitly installs
    /// `AllowAllAuthorizer`; never use in production.
    pub async fn new_with_alarm_manager_dev_only<S>(
        initial: C,
        store: S,
        alarm_manager: SharedAlarmManager,
    ) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        Self::new_with_alarm_manager(initial, store, Arc::new(AllowAllAuthorizer), alarm_manager)
            .await
    }

    /// Compatibility alias for callers that already supplied an authorizer and alarm manager explicitly.
    pub async fn new_with_authorizer_and_alarm_manager<S>(
        initial: C,
        store: S,
        authorizer: Arc<dyn ConfigAuthorizer>,
        alarm_manager: SharedAlarmManager,
    ) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        Self::new_with_alarm_manager(initial, store, authorizer, alarm_manager).await
    }

    /// Fully explicit fresh-start constructor: validates `initial` (syntax
    /// then semantics, off the async workers) and fails closed without
    /// spawning a worker if validation fails, then publishes it at
    /// `ConfigVersion::INITIAL` and starts the single sequenced commit worker
    /// behind a bounded queue of `queue_capacity` (floored at 1; submissions
    /// beyond it are rejected with `AdmissionRejected`). Ignores any existing
    /// store contents — use the `restore_or_new` family to recover them.
    pub async fn with_queue_capacity_and_alarm_manager<S>(
        initial: C,
        store: S,
        queue_capacity: usize,
        authorizer: Arc<dyn ConfigAuthorizer>,
        alarm_manager: SharedAlarmManager,
    ) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        Self::with_queue_capacity_and_alarm_manager_and_impact_classifier(
            initial,
            store,
            queue_capacity,
            authorizer,
            alarm_manager,
            default_impact_classifier(),
        )
        .await
    }

    /// Fully explicit fresh-start constructor with a product-supplied config
    /// impact classifier.
    pub async fn with_queue_capacity_and_alarm_manager_and_impact_classifier<S>(
        initial: C,
        store: S,
        queue_capacity: usize,
        authorizer: Arc<dyn ConfigAuthorizer>,
        alarm_manager: SharedAlarmManager,
        impact_classifier: Arc<dyn ConfigImpactClassifier<C>>,
    ) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        let store: Arc<dyn ManagedDatastore<C>> = Arc::new(store);
        let initial = validate_startup_config(
            initial,
            startup_validation_context(startup_bootstrap_principal(), ConfigVersion::INITIAL),
        )
        .await
        .map_err(|err| preserve_startup_error(&alarm_manager, err))?;
        clear_config_alarm_type(
            &alarm_manager,
            crate::alarms::CONFIG_BUS_STARTUP_FAILURE_ALARM_TYPE,
        );

        Ok(Self::spawn(
            initial,
            ConfigVersion::INITIAL,
            None,
            store,
            queue_capacity,
            AuthorityMode::Authoritative,
            alarm_manager,
            authorizer,
            impact_classifier,
            None,
        ))
    }

    /// Dev/Test variant of `with_queue_capacity_and_alarm_manager` that
    /// implicitly installs `AllowAllAuthorizer`; never use in production.
    pub async fn with_queue_capacity_and_alarm_manager_dev_only<S>(
        initial: C,
        store: S,
        queue_capacity: usize,
        alarm_manager: SharedAlarmManager,
    ) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        Self::with_queue_capacity_and_alarm_manager(
            initial,
            store,
            queue_capacity,
            Arc::new(AllowAllAuthorizer),
            alarm_manager,
        )
        .await
    }

    /// Restores or builds a config bus with an internal alarm manager.
    pub async fn restore_or_new<S>(
        initial: C,
        store: S,
        authorizer: Arc<dyn ConfigAuthorizer>,
    ) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        Self::restore_or_new_with_alarm_manager(
            initial,
            store,
            authorizer,
            SharedAlarmManager::default(),
        )
        .await
    }

    /// Dev/Test variant of `restore_or_new` that implicitly installs
    /// `AllowAllAuthorizer`; never use in production.
    pub async fn restore_or_new_dev_only<S>(initial: C, store: S) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        Self::restore_or_new(initial, store, Arc::new(AllowAllAuthorizer)).await
    }

    /// Compatibility alias for callers that already used the explicit authorizer restore constructor.
    pub async fn restore_or_new_with_authorizer<S>(
        initial: C,
        store: S,
        authorizer: Arc<dyn ConfigAuthorizer>,
    ) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        Self::restore_or_new(initial, store, authorizer).await
    }

    /// Full restore path (RFC 001 §12) reporting failures on the supplied
    /// alarm manager. Loads the latest stored record and, before publishing
    /// it, fails closed on schema-digest mismatch, an unreconciled
    /// `recovery_required` marker, or failed startup validation. A pending
    /// commit-confirmed record is honored if its deadline is still in the
    /// future (the rollback timer is re-armed) and otherwise automatically
    /// rolled back to its parent as a new durable commit. An empty store
    /// falls back to validating and publishing `initial` at
    /// `ConfigVersion::INITIAL`. Write admission only starts after the
    /// restored snapshot is published.
    pub async fn restore_or_new_with_alarm_manager<S>(
        initial: C,
        store: S,
        authorizer: Arc<dyn ConfigAuthorizer>,
        alarm_manager: SharedAlarmManager,
    ) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        Self::restore_or_new_with_alarm_manager_and_impact_classifier(
            initial,
            store,
            authorizer,
            alarm_manager,
            default_impact_classifier(),
        )
        .await
    }

    /// Full restore path with a product-supplied config impact classifier.
    pub async fn restore_or_new_with_alarm_manager_and_impact_classifier<S>(
        initial: C,
        store: S,
        authorizer: Arc<dyn ConfigAuthorizer>,
        alarm_manager: SharedAlarmManager,
        impact_classifier: Arc<dyn ConfigImpactClassifier<C>>,
    ) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        let store: Arc<dyn ManagedDatastore<C>> = Arc::new(store);
        let seed = store
            .load_latest()
            .await
            .map_err(|err| preserve_startup_error(&alarm_manager, err))?;
        let (initial, version, tx_id, pending_deadline) = match seed {
            Some(stored) => {
                let version = stored.version;
                let tx_id = Some(stored.tx_id);
                if let Some(deadline) = stored.confirmed_deadline {
                    let now = Timestamp::now_utc();
                    if deadline <= now {
                        tracing::warn!(
                            tx_id = %stored.tx_id,
                            version = %stored.version,
                            deadline = %deadline,
                            "restored pending commit is expired; performing automatic rollback"
                        );
                        let parent_tx = stored.parent_tx_id.ok_or_else(|| {
                            preserve_startup_error(
                                &alarm_manager,
                                StoreError::restore_confirmed_deadline(
                                    "stored running config requires commit-confirmed recovery",
                                ),
                            )
                        })?;
                        let prev_stored = store
                            .load_rollback(RollbackTarget::TxId(parent_tx))
                            .await
                            .map_err(|err| {
                                log_startup_store_error(
                                    "failed to load previous confirmed config during startup rollback",
                                    &err,
                                );
                                preserve_startup_error(&alarm_manager, StoreError::restore_confirmed_deadline("stored running config requires commit-confirmed recovery"))
                            })?;
                        validate_publishable_stored_config(&prev_stored)
                            .map_err(|err| preserve_startup_error(&alarm_manager, err))?;
                        let context = restore_validation_context(&prev_stored);
                        let rollback_config = validate_startup_config(prev_stored.config, context)
                            .await
                            .map_err(|err| preserve_startup_error(&alarm_manager, err))?;

                        // Create a rollback commit record
                        let rollback_tx_id = TxId::new();
                        let rollback_version = stored.version.next().ok_or_else(|| {
                            preserve_startup_error(
                                &alarm_manager,
                                StoreError::internal("version exhausted during startup rollback"),
                            )
                        })?;

                        // Construct StoredConfig for the rollback commit
                        let mut rollback_record = StoredConfig::new(
                            rollback_tx_id,
                            rollback_version,
                            startup_bootstrap_principal(),
                            RequestSource::StartupRecovery,
                            rollback_config.clone(),
                        );
                        rollback_record.parent_tx_id = Some(stored.tx_id);
                        rollback_record.recovery_required = true;

                        // Append the rollback and decide the pending commit in
                        // one applied-state compare-and-swap.
                        let rollback_write = CommitWrite::resolving(
                            rollback_record,
                            ConfirmedCommitResolution::Rollback {
                                pending_tx_id: stored.tx_id,
                            },
                        )
                        .map_err(|err| preserve_startup_error(&alarm_manager, err))?;
                        store
                            .append_commit_write(rollback_write)
                            .await
                            .map_err(|err| {
                                log_startup_store_error(
                                    "failed to append startup rollback commit",
                                    &err,
                                );
                                preserve_startup_error(
                                    &alarm_manager,
                                    StoreError::restore_recovery_required(
                                        RESTORE_RECOVERY_REQUIRED_MESSAGE,
                                    ),
                                )
                            })?;

                        // Clear recovery required on the rollback commit
                        store
                            .clear_recovery_required(rollback_tx_id)
                            .await
                            .map_err(|err| {
                                log_startup_store_error(
                                    "failed to clear recovery required on startup rollback commit",
                                    &err,
                                );
                                preserve_startup_error(
                                    &alarm_manager,
                                    StoreError::restore_recovery_required(
                                        RESTORE_RECOVERY_REQUIRED_MESSAGE,
                                    ),
                                )
                            })?;

                        (
                            rollback_config,
                            rollback_version,
                            Some(rollback_tx_id),
                            None,
                        )
                    } else {
                        validate_stored_schema_digest(&stored)
                            .map_err(|err| preserve_startup_error(&alarm_manager, err))?;
                        validate_restored_recovery_marker(&stored)
                            .map_err(|err| preserve_startup_error(&alarm_manager, err))?;
                        let context = restore_validation_context(&stored);
                        let config = validate_startup_config(stored.config, context)
                            .await
                            .map_err(|err| preserve_startup_error(&alarm_manager, err))?;
                        (config, version, tx_id, Some(deadline))
                    }
                } else {
                    validate_publishable_stored_config(&stored)
                        .map_err(|err| preserve_startup_error(&alarm_manager, err))?;
                    let context = restore_validation_context(&stored);
                    let config = validate_startup_config(stored.config, context)
                        .await
                        .map_err(|err| preserve_startup_error(&alarm_manager, err))?;
                    (config, version, tx_id, None)
                }
            }
            None => {
                let version = ConfigVersion::INITIAL;
                let config = validate_startup_config(
                    initial,
                    startup_validation_context(startup_bootstrap_principal(), version),
                )
                .await
                .map_err(|err| preserve_startup_error(&alarm_manager, err))?;
                let tx_id = TxId::new();
                store
                    .append_commit_write(CommitWrite::new(StoredConfig::new(
                        tx_id,
                        version,
                        startup_bootstrap_principal(),
                        RequestSource::StartupRecovery,
                        config.clone(),
                    )))
                    .await
                    .map_err(|err| preserve_startup_error(&alarm_manager, err))?;
                (config, version, Some(tx_id), None)
            }
        };
        clear_config_alarm_type(
            &alarm_manager,
            crate::alarms::CONFIG_BUS_STARTUP_FAILURE_ALARM_TYPE,
        );

        Ok(Self::spawn(
            initial,
            version,
            tx_id,
            store,
            DEFAULT_COMMIT_QUEUE_CAPACITY,
            AuthorityMode::Authoritative,
            alarm_manager,
            authorizer,
            impact_classifier,
            pending_deadline,
        ))
    }

    /// Dev/Test variant of `restore_or_new_with_alarm_manager` that
    /// implicitly installs `AllowAllAuthorizer`; never use in production.
    pub async fn restore_or_new_with_alarm_manager_dev_only<S>(
        initial: C,
        store: S,
        alarm_manager: SharedAlarmManager,
    ) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        Self::restore_or_new_with_alarm_manager(
            initial,
            store,
            Arc::new(AllowAllAuthorizer),
            alarm_manager,
        )
        .await
    }

    /// Compatibility alias for callers that already supplied an authorizer and alarm manager explicitly on restore.
    pub async fn restore_or_new_with_authorizer_and_alarm_manager<S>(
        initial: C,
        store: S,
        authorizer: Arc<dyn ConfigAuthorizer>,
        alarm_manager: SharedAlarmManager,
    ) -> Result<Self, StoreError>
    where
        S: ManagedDatastore<C> + 'static,
    {
        Self::restore_or_new_with_alarm_manager(initial, store, authorizer, alarm_manager).await
    }
}

fn log_startup_store_error(operation: &str, error: &StoreError) {
    tracing::error!(
        store_error_code = %error.code,
        store_error = %redact(&error.message),
        "{operation}"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fmt, sync::Arc, sync::Mutex, sync::MutexGuard};
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
    fn startup_validation_logs_are_redacted() {
        let secret = "password=super-secret";
        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = CaptureSubscriber::new(Arc::clone(&captured));

        tracing::subscriber::with_default(subscriber, || {
            log_startup_validation_failure(RequestId::new(), &ValidationError::syntax(secret));
        });

        let rendered = captured.lock().expect("capture mutex poisoned").join("\n");

        assert!(!rendered.contains(secret));
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("syntax"));
    }

    #[test]
    fn startup_store_error_logs_are_redacted() {
        let secret = "credential=startup-store-secret";
        let captured = Arc::new(Mutex::new(Vec::new()));
        let subscriber = CaptureSubscriber::new(Arc::clone(&captured));

        tracing::subscriber::with_default(subscriber, || {
            log_startup_store_error(
                "startup store operation failed",
                &StoreError::internal(secret),
            );
        });

        let rendered = captured.lock().expect("capture mutex poisoned").join("\n");
        assert!(!rendered.contains(secret));
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("internal"));
    }
}
