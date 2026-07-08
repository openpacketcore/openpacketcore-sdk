#![allow(unused_imports)]
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use time::OffsetDateTime;
use tokio::{sync::Notify, time::timeout};

use opc_alarm::{Alarm, AlarmState, ProbableCause, Severity, SharedAlarmManager};
use opc_config_bus::{
    AllowAllAuthorizer, ConfigBus, ConfigEvent, ConfigSnapshot, DriftState, ManagedDatastore,
    MockManagedDatastore, StoreError, StoreErrorCode, StoredConfig, SubscriberLagPolicy,
};
use opc_config_model::{
    ApplyPlan, ApplyPlanChange, ChangeImpact, ChangeImpactClass, CommitErrorCode, CommitMode,
    CommitRequest, ConfigError, ConfigImpactClassifier, ConfigOperation, IdempotencyKey, OpcConfig,
    RequestId, RequestSource, RollbackTarget, TransportType, TrustedPrincipal, ValidationContext,
    ValidationError, WorkloadIdentity, YangPath,
};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp};

mod config_bus_common;
use config_bus_common::*;

struct StaticImpactClassifier {
    plan: ApplyPlan,
}

impl StaticImpactClassifier {
    fn new(plan: ApplyPlan) -> Self {
        Self { plan }
    }
}

impl ConfigImpactClassifier<TestConfig> for StaticImpactClassifier {
    fn classify(
        &self,
        _ctx: &ValidationContext<TestConfig>,
        _previous: Option<&TestConfig>,
        _candidate: &TestConfig,
        _changed_paths: &[YangPath],
    ) -> Result<ApplyPlan, ConfigError> {
        Ok(self.plan.clone())
    }
}

struct FailingImpactClassifier;

impl ConfigImpactClassifier<TestConfig> for FailingImpactClassifier {
    fn classify(
        &self,
        _ctx: &ValidationContext<TestConfig>,
        _previous: Option<&TestConfig>,
        _candidate: &TestConfig,
        _changed_paths: &[YangPath],
    ) -> Result<ApplyPlan, ConfigError> {
        Err(ConfigError::new("apply-plan", "raw-secret=value"))
    }
}

fn single_change_plan(class: ChangeImpactClass, reason_code: &str) -> ApplyPlan {
    ApplyPlan {
        class,
        changes: vec![ApplyPlanChange {
            path: changed_path(),
            class,
            reason_code: reason_code.into(),
            affected_sessions_estimate: Some(3),
        }],
        impact: ChangeImpact {
            class: ChangeImpactClass::Hot,
            affected_sessions_estimate: None,
            requires_external_workflow: false,
        },
        rollback_target: None,
        hard_errors: Vec::new(),
        warnings: Vec::new(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshot_load_does_not_wait_on_a_commit() {
    let store = Arc::new(BlockingStore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");

    let submit = {
        let bus = bus.clone();
        tokio::spawn(async move {
            bus.submit(commit_request(
                "next",
                Instant::now() + Duration::from_secs(1),
            ))
            .await
        })
    };

    store.wait_until_append_started().await;

    let loaded = bus.load();
    assert_eq!(loaded.name, "initial");
    assert_eq!(bus.version(), ConfigVersion::INITIAL);

    store.release();

    let result = submit
        .await
        .expect("submit task completed")
        .expect("commit succeeds");
    assert_eq!(result.new_version, Some(ConfigVersion::new(1)));
    assert_eq!(bus.load().name, "next");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validate_only_does_not_publish_or_notify() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let subscriber = bus.subscribe(SubscriberLagPolicy::DropOldest, 1);

    let result = bus
        .submit(CommitRequest::validate_only(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            TestConfig::new("validated-only"),
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect("validate-only succeeds");

    assert_eq!(result.status, opc_config_model::CommitStatus::Validated);
    let apply_plan = result.apply_plan.expect("validate-only returns apply plan");
    assert_eq!(apply_plan.class, ChangeImpactClass::Hot);
    assert_eq!(
        apply_plan.changes,
        vec![ApplyPlanChange {
            path: changed_path(),
            class: ChangeImpactClass::Hot,
            reason_code: "config_changed".into(),
            affected_sessions_estimate: None,
        }]
    );
    assert_eq!(bus.version(), ConfigVersion::INITIAL);
    assert_eq!(bus.load().name, "initial");
    assert_eq!(store.history().await.len(), 0);
    assert!(timeout(Duration::from_millis(25), subscriber.recv())
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validate_only_surfaces_diff_failures_without_publish() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");

    let err = bus
        .submit(CommitRequest::validate_only(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            TestConfig::with_diff_error("validated-only", "delta generation failed"),
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("validate-only should surface diff errors");

    assert_eq!(err.code, CommitErrorCode::DiffFailed);
    assert_eq!(bus.version(), ConfigVersion::INITIAL);
    assert_eq!(bus.load().name, "initial");
    assert_eq!(store.history().await.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_candidate_is_rejected_before_publish_or_persist() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds")
        .with_max_serialized_config_bytes(32);

    let err = bus
        .submit(CommitRequest::commit(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            TestConfig::new("oversized-candidate-payload-that-exceeds-the-cap"),
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("oversized candidate should be rejected");

    assert_eq!(err.code, CommitErrorCode::AdmissionRejected);
    assert!(
        err.message.contains("serialized payload"),
        "got: {}",
        err.message
    );
    assert_eq!(bus.version(), ConfigVersion::INITIAL);
    assert_eq!(bus.load().name, "initial");
    assert_eq!(store.history().await.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_returns_admitted_apply_plan_and_replays_it() {
    let store = Arc::new(MockManagedDatastore::new());
    let admitted_plan =
        single_change_plan(ChangeImpactClass::DrainRequired, "hostname_drain_required");
    let bus = ConfigBus::with_queue_capacity_and_alarm_manager_and_impact_classifier(
        TestConfig::new("initial"),
        Arc::clone(&store),
        32,
        Arc::new(AllowAllAuthorizer),
        SharedAlarmManager::default(),
        Arc::new(StaticImpactClassifier::new(admitted_plan.clone())),
    )
    .await
    .expect("startup succeeds");
    let key = IdempotencyKey::new("apply-plan-replay").expect("key");

    let result = bus
        .submit(
            commit_request("next", Instant::now() + Duration::from_secs(1))
                .with_idempotency_key(key.clone()),
        )
        .await
        .expect("commit succeeds");

    let result_plan = result.apply_plan.expect("commit returns apply plan");
    assert_eq!(result_plan.class, ChangeImpactClass::DrainRequired);
    assert!(result_plan.blocks_traffic_until_workflow());
    assert_eq!(
        store.latest().await.expect("record").apply_plan,
        Some(result_plan.clone())
    );

    let replay = bus
        .submit(
            commit_request("next", Instant::now() + Duration::from_secs(1))
                .with_idempotency_key(key),
        )
        .await
        .expect("idempotent replay succeeds");

    assert_eq!(replay.apply_plan, Some(result_plan));
    assert_eq!(store.history().await.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forbidden_live_apply_plan_rejects_before_append_or_publish() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::with_queue_capacity_and_alarm_manager_and_impact_classifier(
        TestConfig::new("initial"),
        Arc::clone(&store),
        32,
        Arc::new(AllowAllAuthorizer),
        SharedAlarmManager::default(),
        Arc::new(StaticImpactClassifier::new(single_change_plan(
            ChangeImpactClass::ForbiddenLive,
            "session_store_backend_changed",
        ))),
    )
    .await
    .expect("startup succeeds");

    let err = bus
        .submit(commit_request(
            "next",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("forbidden-live plan rejects");

    assert_eq!(err.code, CommitErrorCode::ApplyPlanRejected);
    let rejected_plan = err.apply_plan.expect("rejected plan is attached");
    assert_eq!(rejected_plan.class, ChangeImpactClass::ForbiddenLive);
    assert!(!rejected_plan.hard_errors.is_empty());
    assert_eq!(bus.load().name, "initial");
    assert_eq!(bus.version(), ConfigVersion::INITIAL);
    assert_eq!(store.history().await.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn classifier_failure_surfaces_stable_error_without_raw_detail() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::with_queue_capacity_and_alarm_manager_and_impact_classifier(
        TestConfig::new("initial"),
        Arc::clone(&store),
        32,
        Arc::new(AllowAllAuthorizer),
        SharedAlarmManager::default(),
        Arc::new(FailingImpactClassifier),
    )
    .await
    .expect("startup succeeds");

    let err = bus
        .submit(commit_request(
            "next",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("classifier failure rejects");

    assert_eq!(err.code, CommitErrorCode::ApplyPlanRejected);
    assert_eq!(err.apply_plan, None);
    assert!(!err.message.contains("raw-secret"));
    assert_eq!(bus.load().name, "initial");
    assert_eq!(store.history().await.len(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validation_failure_raises_warning_commit_alarm_and_success_clears_it() {
    let store = Arc::new(MockManagedDatastore::new());
    let alarms = SharedAlarmManager::default();
    let bus = ConfigBus::new_with_alarm_manager_dev_only(
        TestConfig::new("initial"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    let err = bus
        .submit(CommitRequest::validate_only(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            TestConfig::new(""),
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("invalid candidate should fail validation");

    assert_eq!(err.code, CommitErrorCode::SyntaxValidationFailed);
    let alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(alarm.severity, Severity::Warning);
    assert_eq!(alarm.probable_cause, ProbableCause::ConfigApplyFailed);
    assert_eq!(
        alarm.text.as_str(),
        "Config bus commit failure: syntax_validation_failed"
    );
    assert_alarm_details_code(&alarm, "syntax_validation_failed");

    bus.submit(commit_request(
        "next",
        Instant::now() + Duration::from_secs(1),
    ))
    .await
    .expect("subsequent valid commit succeeds");

    assert_eq!(alarms.active_count(), 0);
    assert_eq!(
        alarms
            .all_alarms()
            .iter()
            .map(|alarm| alarm.state)
            .collect::<Vec<_>>(),
        vec![AlarmState::Raised, AlarmState::Cleared]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_candidate_base_version_is_rejected_without_publish() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");

    let stale_base = bus.version();
    bus.submit(
        commit_request("first", Instant::now() + Duration::from_secs(1))
            .with_base_version(stale_base),
    )
    .await
    .expect("first commit succeeds");

    let err = bus
        .submit(
            commit_request("stale", Instant::now() + Duration::from_secs(1))
                .with_base_version(stale_base),
        )
        .await
        .expect_err("stale candidate should be rejected");

    assert_eq!(err.code, CommitErrorCode::AdmissionRejected);
    assert_eq!(bus.version(), ConfigVersion::new(1));
    assert_eq!(bus.load().name, "first");
    assert_eq!(store.history().await.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validate_only_success_clears_config_apply_commit_alarm() {
    let store = Arc::new(MockManagedDatastore::new());
    let alarms = SharedAlarmManager::default();
    let bus = ConfigBus::new_with_alarm_manager_dev_only(
        TestConfig::new("initial"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    let err = bus
        .submit(CommitRequest::validate_only(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            TestConfig::new(""),
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("invalid validate-only request should fail validation");

    assert_eq!(err.code, CommitErrorCode::SyntaxValidationFailed);
    let alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(alarm.severity, Severity::Warning);
    assert_eq!(alarm.probable_cause, ProbableCause::ConfigApplyFailed);
    assert_alarm_details_code(&alarm, "syntax_validation_failed");

    let result = bus
        .submit(CommitRequest::validate_only(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            TestConfig::new("validated-only"),
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect("successful validate-only retry should clear validation alarm");

    assert_eq!(result.status, opc_config_model::CommitStatus::Validated);
    assert_eq!(alarms.active_count(), 0);
    assert_eq!(
        alarms
            .all_alarms()
            .iter()
            .map(|alarm| alarm.state)
            .collect::<Vec<_>>(),
        vec![AlarmState::Raised, AlarmState::Cleared]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persistence_failure_raises_major_storage_commit_alarm() {
    let alarms = SharedAlarmManager::default();
    let bus = ConfigBus::new_with_alarm_manager_dev_only(
        TestConfig::new("initial"),
        ErrorStore::append_fails("dsn=postgres://user:secret@db/internal"),
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    let err = bus
        .submit(commit_request(
            "next",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("append failure should fail commit");

    assert_eq!(err.code, CommitErrorCode::PersistFailed);
    let alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(alarm.severity, Severity::Major);
    assert_eq!(alarm.probable_cause, ProbableCause::StorageCorruption);
    assert_eq!(
        alarm.text.as_str(),
        "Config bus commit failure: persist_failed"
    );
    assert!(!serde_json::to_string(&alarms.all_alarms())
        .expect("alarm history serializes")
        .contains("secret"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validate_only_success_does_not_clear_active_commit_path_alarm() {
    let alarms = SharedAlarmManager::default();
    let bus = ConfigBus::new_with_alarm_manager_dev_only(
        TestConfig::new("initial"),
        ErrorStore::append_fails("storage remains unavailable"),
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    bus.submit(commit_request(
        "commit-fails",
        Instant::now() + Duration::from_secs(1),
    ))
    .await
    .expect_err("append failure should raise a commit-path alarm");
    let original_alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(
        original_alarm.text.as_str(),
        "Config bus commit failure: persist_failed"
    );

    let validated = bus
        .submit(CommitRequest::validate_only(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            TestConfig::new("validated-only"),
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect("validate-only should not exercise persistence");

    assert_eq!(validated.status, opc_config_model::CommitStatus::Validated);
    let still_active = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(still_active.alarm_id, original_alarm.alarm_id);
    assert_eq!(still_active.text.as_str(), original_alarm.text.as_str());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queue_full_rejection_raises_warning_commit_alarm() {
    let store = Arc::new(BlockingStore::new());
    let alarms = SharedAlarmManager::default();
    let bus = ConfigBus::with_queue_capacity_and_alarm_manager_dev_only(
        TestConfig::new("initial"),
        Arc::clone(&store),
        1,
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    let first = {
        let bus = bus.clone();
        tokio::spawn(async move {
            bus.submit(commit_request(
                "first",
                Instant::now() + Duration::from_secs(5),
            ))
            .await
        })
    };
    store.wait_until_append_started().await;

    let mut second = {
        let bus = bus.clone();
        tokio::spawn(async move {
            bus.submit(commit_request(
                "second",
                Instant::now() + Duration::from_secs(5),
            ))
            .await
        })
    };
    let mut third = {
        let bus = bus.clone();
        tokio::spawn(async move {
            bus.submit(commit_request(
                "third",
                Instant::now() + Duration::from_secs(5),
            ))
            .await
        })
    };

    let second_rejected;
    let err = tokio::select! {
        result = &mut second => {
            second_rejected = true;
            result
                .expect("second submit task completed")
                .expect_err("one queued request should be rejected")
        }
        result = &mut third => {
            second_rejected = false;
            result
                .expect("third submit task completed")
                .expect_err("one queued request should be rejected")
        }
        _ = tokio::time::sleep(Duration::from_millis(100)) => {
            panic!("full commit queue did not reject a concurrent submission");
        }
    };

    assert_eq!(err.code, CommitErrorCode::AdmissionRejected);
    let alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(alarm.severity, Severity::Warning);
    assert_eq!(alarm.probable_cause, ProbableCause::ConfigApplyFailed);
    assert_alarm_details_code(&alarm, "admission_rejected");

    store.release();

    let first_result = first
        .await
        .expect("first submit task completed")
        .expect("first commit succeeds");
    assert_eq!(first_result.new_version, Some(ConfigVersion::new(1)));

    let queued_err = if second_rejected {
        third
            .await
            .expect("third submit task completed")
            .expect_err("queued stale commit should be rejected")
    } else {
        second
            .await
            .expect("second submit task completed")
            .expect_err("queued stale commit should be rejected")
    };
    assert_eq!(queued_err.code, CommitErrorCode::AdmissionRejected);
    assert_eq!(bus.version(), ConfigVersion::new(1));
    let stale_alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(stale_alarm.severity, Severity::Warning);
    assert_eq!(stale_alarm.probable_cause, ProbableCause::ConfigApplyFailed);
    assert_alarm_details_code(&stale_alarm, "admission_rejected");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validate_only_rejects_unsupported_operations() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");

    let err = bus
        .submit(CommitRequest::validate_only(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Delete,
            TestConfig::new("validated-only"),
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("unsupported validate-only operation should be rejected");

    assert_eq!(err.code, CommitErrorCode::AdmissionRejected);
    assert_eq!(
        err.message,
        "validate-only only supports replace operations in this skeleton config bus"
    );
    assert_eq!(store.history().await.len(), 0);
}
