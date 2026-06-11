use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::time::timeout;

use opc_alarm::{ProbableCause, Severity, SharedAlarmManager};
use opc_config_bus::{ConfigBus, ConfigEvent, StoredConfig};
use opc_config_model::{CommitErrorCode, CommitRequest, RollbackTarget};
use opc_types::{ConfigVersion, SchemaDigest};

mod config_bus_common;
use config_bus_common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rollback_failures_are_redacted_for_clients() {
    let secret = "dsn=postgres://user:secret@db/internal";
    let bus = ConfigBus::new_dev_only(
        TestConfig::new("initial"),
        Arc::new(ErrorStore::rollback_fails(secret)),
    )
    .await
    .expect("startup succeeds");

    let err = bus
        .submit(CommitRequest::rollback(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            RollbackTarget::Label("checkpoint-a".into()),
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("rollback load failure should surface to caller");

    assert_eq!(err.code, CommitErrorCode::RollbackUnavailable);
    assert_eq!(err.message, "rollback target could not be loaded");
    assert!(!err.message.contains(secret));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_rollback_target_raises_warning_config_apply_alarm() {
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
        .submit(CommitRequest::rollback(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            RollbackTarget::Label("missing-checkpoint".into()),
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("missing rollback target should fail");

    assert_eq!(err.code, CommitErrorCode::RollbackNotFound);
    assert_eq!(err.message, "rollback target was not found");
    let alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(alarm.severity, Severity::Warning);
    assert_eq!(alarm.probable_cause, ProbableCause::ConfigApplyFailed);
    assert_alarm_details_code(&alarm, "rollback_not_found");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn validate_only_success_does_not_clear_unrelated_config_apply_alarm() {
    let store = Arc::new(MockManagedDatastore::new());
    let alarms = SharedAlarmManager::default();
    let bus = ConfigBus::new_with_alarm_manager_dev_only(
        TestConfig::new("initial"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    bus.submit(CommitRequest::rollback(
        RequestId::new(),
        principal(),
        TransportType::Internal,
        RequestSource::Northbound,
        RollbackTarget::Label("missing-checkpoint".into()),
        vec![changed_path()],
        Instant::now() + Duration::from_secs(1),
    ))
    .await
    .expect_err("missing rollback target should fail");
    let original_alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_alarm_details_code(&original_alarm, "rollback_not_found");

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
    let still_active = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(still_active.alarm_id, original_alarm.alarm_id);
    assert_alarm_details_code(&still_active, "rollback_not_found");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rollback_rejects_schema_digest_mismatch_targets() {
    let store = Arc::new(MockManagedDatastore::new());
    let mut checkpoint = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(1),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("checkpoint-a"),
    );
    checkpoint.rollback_label = Some("checkpoint-a".into());
    checkpoint.schema_digest =
        SchemaDigest::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .expect("digest");
    store.seed(checkpoint).await;
    store
        .seed(StoredConfig::new(
            opc_types::TxId::new(),
            ConfigVersion::new(2),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("current"),
        ))
        .await;

    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
        .await
        .expect("startup restore succeeds");
    let subscriber = bus.subscribe(SubscriberLagPolicy::DropOldest, 1);

    let err = bus
        .submit(CommitRequest::rollback(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            RollbackTarget::Label("checkpoint-a".into()),
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("schema-mismatched rollback target should fail closed");

    assert_eq!(err.code, CommitErrorCode::RollbackUnavailable);
    assert_eq!(err.message, "rollback target could not be loaded");
    assert_eq!(bus.version(), ConfigVersion::new(2));
    assert_eq!(bus.load().name, "current");
    assert!(timeout(Duration::from_millis(25), subscriber.recv())
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rollback_rejects_recovery_required_targets() {
    let store = Arc::new(MockManagedDatastore::new());
    let mut checkpoint = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(1),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("checkpoint-a"),
    );
    checkpoint.rollback_label = Some("checkpoint-a".into());
    checkpoint.recovery_required = true;
    store.seed(checkpoint).await;
    store
        .seed(StoredConfig::new(
            opc_types::TxId::new(),
            ConfigVersion::new(2),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("current"),
        ))
        .await;

    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
        .await
        .expect("startup restore succeeds");
    let subscriber = bus.subscribe(SubscriberLagPolicy::DropOldest, 1);

    let err = bus
        .submit(CommitRequest::rollback(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            RollbackTarget::Label("checkpoint-a".into()),
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("recovery-required rollback target should fail closed");

    assert_eq!(err.code, CommitErrorCode::RollbackUnavailable);
    assert_eq!(err.message, "rollback target could not be loaded");
    assert_eq!(bus.version(), ConfigVersion::new(2));
    assert_eq!(bus.load().name, "current");
    assert!(timeout(Duration::from_millis(25), subscriber.recv())
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rollback_rejects_confirmed_deadline_targets() {
    let store = Arc::new(MockManagedDatastore::new());
    let mut checkpoint = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(1),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("checkpoint-a"),
    );
    checkpoint.rollback_label = Some("checkpoint-a".into());
    checkpoint.confirmed_deadline = Some(Timestamp::from(time::OffsetDateTime::UNIX_EPOCH));
    store.seed(checkpoint).await;
    store
        .seed(StoredConfig::new(
            opc_types::TxId::new(),
            ConfigVersion::new(2),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("current"),
        ))
        .await;

    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
        .await
        .expect("startup restore succeeds");
    let subscriber = bus.subscribe(SubscriberLagPolicy::DropOldest, 1);

    let err = bus
        .submit(CommitRequest::rollback(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            RollbackTarget::Label("checkpoint-a".into()),
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("commit-confirmed rollback target should fail closed");

    assert_eq!(err.code, CommitErrorCode::RollbackUnavailable);
    assert_eq!(err.message, "rollback target could not be loaded");
    assert_eq!(bus.version(), ConfigVersion::new(2));
    assert_eq!(bus.load().name, "current");
    assert!(timeout(Duration::from_millis(25), subscriber.recv())
        .await
        .is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rollback_reports_changed_paths_to_callers_and_subscribers() {
    let store = Arc::new(MockManagedDatastore::new());

    let mut checkpoint = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(1),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("checkpoint-a"),
    );
    checkpoint.rollback_label = Some("checkpoint-a".into());
    store.seed(checkpoint).await;
    store
        .seed(StoredConfig::new(
            opc_types::TxId::new(),
            ConfigVersion::new(2),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("current"),
        ))
        .await;

    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
        .await
        .expect("startup restore succeeds");
    let subscriber = bus.subscribe(SubscriberLagPolicy::DropOldest, 1);
    let rollback_path = changed_path();

    let result = bus
        .submit(CommitRequest::rollback(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            RollbackTarget::Label("checkpoint-a".into()),
            vec![rollback_path.clone()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect("rollback succeeds");

    assert_eq!(
        result.status,
        opc_config_model::CommitStatus::RollbackApplied
    );
    assert_eq!(result.new_version, Some(ConfigVersion::new(3)));
    assert_eq!(result.changed_paths, vec![rollback_path.clone()]);
    assert_eq!(bus.load().name, "checkpoint-a");

    match subscriber.recv().await.expect("rollback event published") {
        ConfigEvent::Change(change) => {
            assert_eq!(change.version, ConfigVersion::new(3));
            assert_eq!(change.current.name, "checkpoint-a");
            assert_eq!(change.changed_paths.as_ref(), &[rollback_path]);
        }
        ConfigEvent::ResyncRequired { .. } => panic!("expected direct rollback change"),
    }
}
