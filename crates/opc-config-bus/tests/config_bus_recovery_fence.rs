#![allow(unused_imports)]
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Notify;

use opc_alarm::{ProbableCause, Severity, SharedAlarmManager};
use opc_config_bus::{ConfigBus, DriftState};
use opc_config_model::{CommitErrorCode, CommitStatus, IdempotencyKey, RequestSource};
use opc_types::ConfigVersion;

mod config_bus_common;
use config_bus_common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_submit_still_raises_worker_commit_alarm() {
    let store = Arc::new(BlockingAppendFailureStore::new());
    let alarms = SharedAlarmManager::default();
    let bus = ConfigBus::new_with_alarm_manager_dev_only(
        TestConfig::new("initial"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    let submit = {
        let bus = bus.clone();
        tokio::spawn(async move {
            bus.submit(commit_request(
                "next",
                Instant::now() + Duration::from_secs(5),
            ))
            .await
        })
    };

    store.wait_until_append_started().await;
    submit.abort();
    assert!(submit
        .await
        .expect_err("submit task should be aborted")
        .is_cancelled());
    store.release();

    let alarm = wait_for_single_active_alarm(&alarms, "config-bus.commit.failure").await;
    assert_eq!(alarm.severity, Severity::Major);
    assert_eq!(alarm.probable_cause, ProbableCause::StorageCorruption);
    assert_alarm_details_code(&alarm, "persist_failed");
    assert!(!serde_json::to_string(&alarms.all_alarms())
        .expect("alarm history serializes")
        .contains("secret"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceled_submit_append_panic_still_raises_outcome_unknown_alarm() {
    let store = Arc::new(BlockingAppendPanicStore::new());
    let alarms = SharedAlarmManager::default();
    let bus = ConfigBus::new_with_alarm_manager_dev_only(
        TestConfig::new("initial"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    let submit = {
        let bus = bus.clone();
        tokio::spawn(async move {
            bus.submit(commit_request(
                "next",
                Instant::now() + Duration::from_secs(5),
            ))
            .await
        })
    };

    store.wait_until_append_started().await;
    submit.abort();
    assert!(submit
        .await
        .expect_err("submit task should be aborted")
        .is_cancelled());
    store.release();

    let alarm = wait_for_single_active_alarm(&alarms, "config-bus.commit.failure").await;
    assert_eq!(alarm.severity, Severity::Major);
    assert_eq!(alarm.probable_cause, ProbableCause::StorageCorruption);
    assert_alarm_details_code(&alarm, "outcome_unknown");
    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datastore_append_panic_is_outcome_unknown_and_fences_recovery() {
    let alarms = SharedAlarmManager::default();
    let bus = ConfigBus::new_with_alarm_manager_dev_only(
        TestConfig::new("initial"),
        PanicStore,
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    let first = bus
        .submit(commit_request(
            "first",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("append panic should surface as outcome unknown");
    assert_eq!(first.code, CommitErrorCode::OutcomeUnknown);
    assert_eq!(
        first.message,
        "durable config outcome is unknown; verify authoritative state before retrying"
    );
    let first_alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(first_alarm.severity, Severity::Major);
    assert_eq!(first_alarm.probable_cause, ProbableCause::StorageCorruption);
    assert_alarm_details_code(&first_alarm, "outcome_unknown");
    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);

    let second = bus
        .submit(commit_request(
            "second",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("fenced worker should reject later submissions");
    assert_eq!(second.code, CommitErrorCode::RecoveryRequired);
    assert_eq!(
        second.message,
        "durable config outcome is unknown; verify authoritative state before retrying"
    );

    let alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(alarm.severity, Severity::Major);
    assert_eq!(alarm.probable_cause, ProbableCause::StorageCorruption);
    assert_alarm_details_code(&alarm, "recovery_required");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn post_append_panic_reports_outcome_unknown_and_fences_until_reconciled() {
    let store = Arc::new(PostAppendPanicStore::new());
    let alarms = SharedAlarmManager::default();
    let bus = ConfigBus::new_with_alarm_manager_dev_only(
        TestConfig::new("initial"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    let err = bus
        .submit(commit_request(
            "persisted-before-panic",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("post-append panic should surface as outcome unknown");

    assert_eq!(err.code, CommitErrorCode::OutcomeUnknown);
    assert_eq!(
        err.message,
        "durable config outcome is unknown; verify authoritative state before retrying"
    );
    let history = store.history().await;
    assert_eq!(history.len(), 1);
    assert!(history[0].recovery_required);
    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);
    let alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(alarm.severity, Severity::Major);
    assert_eq!(alarm.probable_cause, ProbableCause::StorageCorruption);
    assert_alarm_details_code(&alarm, "outcome_unknown");

    let follow_up = bus
        .submit(commit_request(
            "must-fail-closed",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("recovery fence should reject later writes");

    assert_eq!(follow_up.code, CommitErrorCode::RecoveryRequired);
    assert_eq!(
        follow_up.message,
        "durable config outcome is unknown; verify authoritative state before retrying"
    );
    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_successful_append_reports_committed_after_deadline() {
    let store = Arc::new(SlowAppendStore::new(Duration::from_millis(60)));
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");

    let result = bus
        .submit(commit_request(
            "persisted-too-late",
            Instant::now() + Duration::from_millis(20),
        ))
        .await
        .expect("a successful durable append is authoritative after its deadline");

    assert_eq!(result.status, CommitStatus::Committed);
    assert_eq!(result.new_version, Some(ConfigVersion::new(1)));
    assert_eq!(bus.version(), ConfigVersion::new(1));
    assert_eq!(bus.load().name, "persisted-too-late");
    assert_eq!(bus.drift_state(), DriftState::InSync);
    let history = store.history().await;
    assert_eq!(history.len(), 1);
    assert!(!history[0].recovery_required);

    let restored =
        ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
            .await
            .expect("the committed record remains restorable");
    assert_eq!(restored.version(), ConfigVersion::new(1));
    assert_eq!(restored.load().name, "persisted-too-late");

    let follow_up = bus
        .submit(
            commit_request(
                "should-be-rejected",
                Instant::now() + Duration::from_secs(1),
            )
            .with_base_version(bus.version()),
        )
        .await
        .expect("the bus must remain writable after a known commit");

    assert_eq!(follow_up.status, CommitStatus::Committed);
    assert_eq!(follow_up.new_version, Some(ConfigVersion::new(2)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clear_recovery_failure_reports_known_commit_and_fences_future_writes() {
    let bus = ConfigBus::new_dev_only(
        TestConfig::new("initial"),
        Arc::new(ErrorStore::clear_recovery_fails("backend update failed")),
    )
    .await
    .expect("startup succeeds");

    let result = bus
        .submit(commit_request(
            "next",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect("the known durable commit must still be reported as committed");

    assert_eq!(result.status, CommitStatus::Committed);
    assert_eq!(result.new_version, Some(ConfigVersion::new(1)));
    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);
    assert_eq!(bus.version(), ConfigVersion::new(1));
    assert_eq!(bus.load().name, "next");

    let follow_up = bus
        .submit(commit_request(
            "later",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("fenced bus should reject later writes");

    assert_eq!(follow_up.code, CommitErrorCode::RecoveryRequired);
    assert_eq!(
        follow_up.message,
        "commit was published but the recovery marker could not be cleared durably"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outcome_unknown_is_read_resolvable_and_idempotent_after_recovery() {
    let store = Arc::new(OutcomeUnknownAfterAppendStore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let key = IdempotencyKey::new("unknown-outcome-retry").expect("idempotency key");

    let err = bus
        .submit(
            commit_request(
                "committed-with-lost-ack",
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key.clone()),
        )
        .await
        .expect_err("lost acknowledgement must not be reported as a clean failure");

    assert_eq!(err.code, CommitErrorCode::OutcomeUnknown);
    assert_eq!(bus.version(), ConfigVersion::INITIAL);
    assert_eq!(bus.load().name, "initial");
    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);
    assert_eq!(
        store
            .append_attempts
            .load(std::sync::atomic::Ordering::Acquire),
        1
    );

    let authoritative = store
        .load_by_idempotency_key(&key)
        .await
        .expect("authoritative lookup succeeds")
        .expect("the write was durably applied");
    assert_eq!(authoritative.config.name, "committed-with-lost-ack");
    assert_eq!(authoritative.version, ConfigVersion::new(1));
    assert!(authoritative.recovery_required);
    assert!(authoritative
        .request_fingerprint
        .as_ref()
        .is_some_and(|fingerprint| matches!(
            fingerprint.mode,
            opc_config_bus::StoredRequestMode::Commit
        )));

    let fenced_replay = bus
        .submit(
            commit_request(
                "committed-with-lost-ack",
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key.clone()),
        )
        .await
        .expect("the fenced bus may replay the exact persisted request");
    assert_eq!(fenced_replay.tx_id, authoritative.tx_id);
    assert_eq!(fenced_replay.new_version, Some(ConfigVersion::new(1)));
    assert_eq!(bus.load().name, "initial");
    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);
    assert_eq!(
        store
            .append_attempts
            .load(std::sync::atomic::Ordering::Acquire),
        1
    );

    let collision = bus
        .submit(
            commit_request("different-payload", Instant::now() + Duration::from_secs(1))
                .with_idempotency_key(key.clone()),
        )
        .await
        .expect_err("a fenced same-key collision must not mutate state");
    assert_eq!(collision.code, CommitErrorCode::AdmissionRejected);

    let changed_base = bus
        .submit(
            commit_request(
                "committed-with-lost-ack",
                Instant::now() + Duration::from_secs(1),
            )
            .with_base_version(ConfigVersion::new(1))
            .with_idempotency_key(key.clone()),
        )
        .await
        .expect_err("a changed caller CAS precondition must not alias the persisted request");
    assert_eq!(changed_base.code, CommitErrorCode::AdmissionRejected);
    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);
    assert_eq!(
        store
            .append_attempts
            .load(std::sync::atomic::Ordering::Acquire),
        1
    );

    let missing = bus
        .submit(
            commit_request("new-fenced-write", Instant::now() + Duration::from_secs(1))
                .with_idempotency_key(
                    IdempotencyKey::new("unknown-outcome-new-key").expect("idempotency key"),
                ),
        )
        .await
        .expect_err("a new keyed write must remain fenced");
    assert_eq!(missing.code, CommitErrorCode::RecoveryRequired);
    assert_eq!(
        store
            .append_attempts
            .load(std::sync::atomic::Ordering::Acquire),
        1
    );

    store
        .clear_recovery_required(authoritative.tx_id)
        .await
        .expect("recovery authority confirms the durable outcome");
    let recovered =
        ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
            .await
            .expect("replacement authority restores the committed outcome");
    let replay = recovered
        .submit(
            commit_request(
                "committed-with-lost-ack",
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key),
        )
        .await
        .expect("same-key retry replays the committed result");

    assert_eq!(replay.tx_id, authoritative.tx_id);
    assert_eq!(replay.new_version, Some(ConfigVersion::new(1)));
    assert_eq!(recovered.load().name, "committed-with-lost-ack");
    assert_eq!(store.history().await.len(), 1);
    assert_eq!(
        store
            .append_attempts
            .load(std::sync::atomic::Ordering::Acquire),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unreadable_concurrent_winner_is_outcome_unknown_not_persist_failed() {
    let store = Arc::new(UnreadableConcurrentWinnerStore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let key = IdempotencyKey::new("unreadable-concurrent-winner").expect("key");

    let error = bus
        .submit(
            commit_request("winner", Instant::now() + Duration::from_secs(1))
                .with_idempotency_key(key),
        )
        .await
        .expect_err("failed authoritative readback leaves the logical outcome ambiguous");

    assert_eq!(error.code, CommitErrorCode::OutcomeUnknown);
    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);
    assert_eq!(bus.version(), ConfigVersion::INITIAL);
    let history = store.history().await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].config.name, "winner");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outcome_unknown_without_a_retry_key_resolves_by_request_id() {
    let store = Arc::new(OutcomeUnknownAfterAppendStore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let request_id = RequestId::new();

    let error = bus
        .submit(CommitRequest::commit(
            request_id,
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            TestConfig::new("committed-with-lost-ack"),
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("lost acknowledgement is ambiguous");
    assert_eq!(error.code, CommitErrorCode::OutcomeUnknown);

    let resolved = bus
        .resolve_request_id(request_id)
        .await
        .expect("authoritative request lookup")
        .expect("durable request result");
    assert_eq!(resolved.status, CommitStatus::Committed);
    assert_eq!(resolved.base_version, ConfigVersion::INITIAL);
    assert_eq!(resolved.new_version, Some(ConfigVersion::new(1)));
    assert_eq!(resolved.changed_paths, vec![changed_path()]);
    assert_eq!(store.history().await.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_confirmed_outcome_unknown_resolves_by_request_id() {
    let store = Arc::new(OutcomeUnknownAfterAppendStore::new());
    store
        .inner
        .seed(StoredConfig::new(
            opc_types::TxId::new(),
            ConfigVersion::new(1),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("initial"),
        ))
        .await;
    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let request_id = RequestId::new();
    let error = bus
        .submit(
            CommitRequest::new(
                request_id,
                principal(),
                TransportType::Internal,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                CommitMode::CommitConfirmed {
                    timeout: Duration::from_secs(60),
                },
                Instant::now() + Duration::from_secs(1),
                Some(TestConfig::new("tentative")),
                vec![changed_path()],
            )
            .with_base_version(ConfigVersion::new(1)),
        )
        .await
        .expect_err("lost acknowledgement is ambiguous");
    assert_eq!(error.code, CommitErrorCode::OutcomeUnknown);

    let resolved = bus
        .resolve_request_id(request_id)
        .await
        .expect("authoritative request lookup")
        .expect("durable pending result");
    assert_eq!(resolved.status, CommitStatus::CommitConfirmedPending);
    assert_eq!(resolved.base_version, ConfigVersion::new(1));
    assert_eq!(resolved.new_version, Some(ConfigVersion::new(2)));
    assert_eq!(resolved.changed_paths, vec![changed_path()]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_confirmed_outcome_unknown_resolves_and_replays_exactly() {
    let store = Arc::new(OutcomeUnknownAfterAppendStore::new());
    store
        .inner
        .seed(StoredConfig::new(
            opc_types::TxId::new(),
            ConfigVersion::new(1),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("initial"),
        ))
        .await;
    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let request_id = RequestId::new();
    let key = IdempotencyKey::new("commit-confirmed-lost-ack").expect("idempotency key");
    let timeout = Duration::from_secs(60);
    let request = || {
        CommitRequest::new(
            request_id,
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            CommitMode::CommitConfirmed { timeout },
            Instant::now() + Duration::from_secs(1),
            Some(TestConfig::new("tentative")),
            vec![changed_path()],
        )
        .with_base_version(ConfigVersion::new(1))
        .with_idempotency_key(key.clone())
    };

    let error = bus
        .submit(request())
        .await
        .expect_err("lost acknowledgement is ambiguous");
    assert_eq!(error.code, CommitErrorCode::OutcomeUnknown);
    let durable = store
        .load_by_idempotency_key(&key)
        .await
        .expect("authoritative keyed lookup")
        .expect("durable pending commit");
    assert!(durable.recovery_required);
    store
        .clear_recovery_required(durable.tx_id)
        .await
        .expect("reconcile durable write");

    let recovered =
        ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
            .await
            .expect("restore pending commit");
    let replayed = recovered
        .submit(request())
        .await
        .expect("same request replays before pending-write rejection");
    assert_eq!(replayed.tx_id, durable.tx_id);
    assert_eq!(replayed.status, CommitStatus::CommitConfirmedPending);
    assert_eq!(replayed.new_version, Some(ConfigVersion::new(2)));
    assert_eq!(store.history().await.len(), 2);
    assert_eq!(
        store
            .append_attempts
            .load(std::sync::atomic::Ordering::Acquire),
        1
    );

    let collision = recovered
        .submit(
            CommitRequest::new(
                request_id,
                principal(),
                TransportType::Internal,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                CommitMode::CommitConfirmed {
                    timeout: Duration::from_secs(30),
                },
                Instant::now() + Duration::from_secs(1),
                Some(TestConfig::new("tentative")),
                vec![changed_path()],
            )
            .with_base_version(ConfigVersion::new(1))
            .with_idempotency_key(key),
        )
        .await
        .expect_err("changed timeout is an idempotency collision");
    assert_eq!(collision.code, CommitErrorCode::AdmissionRejected);

    let candidate_collision = recovered
        .submit(
            CommitRequest::new(
                request_id,
                principal(),
                TransportType::Internal,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                CommitMode::CommitConfirmed { timeout },
                Instant::now() + Duration::from_secs(1),
                Some(TestConfig::new("different-tentative")),
                vec![changed_path()],
            )
            .with_base_version(ConfigVersion::new(1))
            .with_idempotency_key(
                IdempotencyKey::new("commit-confirmed-lost-ack").expect("idempotency key"),
            ),
        )
        .await
        .expect_err("changed candidate is an idempotency collision");
    assert_eq!(candidate_collision.code, CommitErrorCode::AdmissionRejected);
}

async fn store_with_pending_commit() -> Arc<OutcomeUnknownAfterAppendStore<TestConfig>> {
    let store = Arc::new(OutcomeUnknownAfterAppendStore::new());
    let initial_tx_id = opc_types::TxId::new();
    store
        .inner
        .seed(StoredConfig::new(
            initial_tx_id,
            ConfigVersion::new(1),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("initial"),
        ))
        .await;
    let mut pending = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(2),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("tentative"),
    );
    pending.parent_tx_id = Some(initial_tx_id);
    pending.confirmed_deadline = Some(Timestamp::from_offset_datetime(
        time::OffsetDateTime::now_utc() + time::Duration::minutes(1),
    ));
    store.inner.seed(pending).await;
    store
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_confirmed_outcome_unknown_resolves_by_request_id() {
    let store = store_with_pending_commit().await;
    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
        .await
        .expect("restore pending commit");
    let request_id = RequestId::new();
    let error = bus
        .submit(CommitRequest::cancel_confirmed(
            request_id,
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("lost cancellation acknowledgement is ambiguous");
    assert_eq!(error.code, CommitErrorCode::OutcomeUnknown);

    let resolved = bus
        .resolve_request_id(request_id)
        .await
        .expect("authoritative request lookup")
        .expect("durable cancellation result");
    assert_eq!(resolved.status, CommitStatus::RollbackApplied);
    assert_eq!(resolved.base_version, ConfigVersion::new(2));
    assert_eq!(resolved.new_version, Some(ConfigVersion::new(3)));
    assert_eq!(store.history().await.len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancel_confirmed_outcome_unknown_replays_by_key_without_a_second_append() {
    let store = store_with_pending_commit().await;
    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
        .await
        .expect("restore pending commit");
    let request_id = RequestId::new();
    let key = IdempotencyKey::new("cancel-confirmed-lost-ack").expect("idempotency key");
    let request = || {
        CommitRequest::cancel_confirmed(
            request_id,
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        )
        .with_idempotency_key(key.clone())
    };
    let error = bus
        .submit(request())
        .await
        .expect_err("lost cancellation acknowledgement is ambiguous");
    assert_eq!(error.code, CommitErrorCode::OutcomeUnknown);
    let durable = store
        .load_by_idempotency_key(&key)
        .await
        .expect("authoritative keyed lookup")
        .expect("durable cancellation");
    store
        .clear_recovery_required(durable.tx_id)
        .await
        .expect("reconcile durable write");

    let recovered =
        ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
            .await
            .expect("restore cancellation result");
    let replayed = recovered.submit(request()).await.expect("same-key replay");
    assert_eq!(replayed.tx_id, durable.tx_id);
    assert_eq!(replayed.status, CommitStatus::RollbackApplied);
    assert_eq!(store.history().await.len(), 3);
    assert_eq!(
        store
            .append_attempts
            .load(std::sync::atomic::Ordering::Acquire),
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_confirm_outcome_unknown_resolves_by_request_id() {
    let store = store_with_pending_commit().await;
    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
        .await
        .expect("restore pending commit");
    let request_id = RequestId::new();
    let error = bus
        .submit(CommitRequest::new(
            request_id,
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            CommitMode::Commit,
            Instant::now() + Duration::from_secs(1),
            None,
            vec![changed_path()],
        ))
        .await
        .expect_err("lost confirmation acknowledgement is ambiguous");
    assert_eq!(error.code, CommitErrorCode::OutcomeUnknown);

    let resolved = bus
        .resolve_request_id(request_id)
        .await
        .expect("authoritative request lookup")
        .expect("durable confirmation result");
    assert_eq!(resolved.status, CommitStatus::Committed);
    assert_eq!(resolved.base_version, ConfigVersion::new(2));
    assert_eq!(resolved.new_version, Some(ConfigVersion::new(3)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_confirm_outcome_unknown_replays_by_key_without_semantic_aliasing() {
    let store = store_with_pending_commit().await;
    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
        .await
        .expect("restore pending commit");
    let request_id = RequestId::new();
    let key = IdempotencyKey::new("explicit-confirm-lost-ack").expect("idempotency key");
    let request = || {
        CommitRequest::new(
            request_id,
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            CommitMode::Commit,
            Instant::now() + Duration::from_secs(1),
            None,
            vec![changed_path()],
        )
        .with_idempotency_key(key.clone())
    };
    let error = bus
        .submit(request())
        .await
        .expect_err("lost confirmation acknowledgement is ambiguous");
    assert_eq!(error.code, CommitErrorCode::OutcomeUnknown);
    let durable = store
        .load_by_idempotency_key(&key)
        .await
        .expect("authoritative keyed lookup")
        .expect("durable confirmation");
    store
        .clear_recovery_required(durable.tx_id)
        .await
        .expect("reconcile durable confirmation");

    let recovered =
        ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
            .await
            .expect("restore confirmed successor");
    let replayed = recovered.submit(request()).await.expect("same-key replay");
    assert_eq!(replayed.tx_id, durable.tx_id);
    assert_eq!(replayed.status, CommitStatus::Committed);
    assert_eq!(store.history().await.len(), 3);
    assert_eq!(
        store
            .append_attempts
            .load(std::sync::atomic::Ordering::Acquire),
        1
    );

    let collision = recovered
        .submit(
            CommitRequest::commit(
                request_id,
                principal(),
                TransportType::Internal,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                TestConfig::new("semantically-different-commit"),
                vec![changed_path()],
                Instant::now() + Duration::from_secs(1),
            )
            .with_idempotency_key(key),
        )
        .await
        .expect_err("candidate-bearing request must not alias explicit confirm");
    assert_eq!(collision.code, CommitErrorCode::AdmissionRejected);
}
