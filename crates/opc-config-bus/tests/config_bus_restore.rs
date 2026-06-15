use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use time::OffsetDateTime;

use opc_alarm::{ProbableCause, Severity, SharedAlarmManager};
use opc_config_bus::{ConfigBus, StoredConfig};
use opc_config_model::{ConfigOperation, RequestSource, TransportType};
use opc_types::{ConfigVersion, SchemaDigest, Timestamp};

mod config_bus_common;
use config_bus_common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_or_new_rejects_invalid_stored_config() {
    let store = Arc::new(MockManagedDatastore::new());
    store
        .seed(StoredConfig::new(
            opc_types::TxId::new(),
            ConfigVersion::new(3),
            principal(),
            RequestSource::StartupRecovery,
            TestConfig::new(""),
        ))
        .await;

    let err =
        match ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
            .await
        {
            Ok(_) => panic!("invalid stored config should fail startup restore"),
            Err(err) => err,
        };

    assert_eq!(err.code, StoreErrorCode::StartupSyntaxValidationFailed);
    assert_eq!(err.message, "startup config failed syntax validation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_or_new_rejects_schema_digest_mismatch() {
    let store = Arc::new(MockManagedDatastore::new());
    let mut stored = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(3),
        principal(),
        RequestSource::StartupRecovery,
        TestConfig::new("persisted"),
    );
    stored.schema_digest =
        SchemaDigest::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .expect("digest");
    store.seed(stored).await;

    let err =
        match ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
            .await
        {
            Ok(_) => panic!("schema mismatch should fail startup restore"),
            Err(err) => err,
        };

    assert_eq!(err.code, StoreErrorCode::RestoreSchemaMismatch);
    assert_eq!(err.message, "stored running config schema digest mismatch");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_or_new_rejects_invalid_initial_config_when_store_is_empty() {
    let store = Arc::new(MockManagedDatastore::new());

    let err =
        match ConfigBus::restore_or_new_dev_only(TestConfig::new(""), Arc::clone(&store)).await {
            Ok(_) => panic!("invalid initial config should fail startup restore"),
            Err(err) => err,
        };

    assert_eq!(err.code, StoreErrorCode::StartupSyntaxValidationFailed);
    assert_eq!(err.message, "startup config failed syntax validation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_or_new_rejects_semantically_invalid_initial_config_when_store_is_empty() {
    let store = Arc::new(MockManagedDatastore::new());

    let err = match ConfigBus::restore_or_new_dev_only(
        TestConfig::with_semantic_error("initial", "semantic startup failure"),
        Arc::clone(&store),
    )
    .await
    {
        Ok(_) => panic!("semantic startup validation should fail"),
        Err(err) => err,
    };

    assert_eq!(err.code, StoreErrorCode::StartupSemanticValidationFailed);
    assert_eq!(err.message, "startup config failed semantic validation");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_or_new_empty_store_persists_bootstrap_rollback_parent() {
    let store = Arc::new(MockManagedDatastore::new());

    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("restore with empty store should seed bootstrap");

    let snapshot = bus.current_snapshot();
    assert_eq!(snapshot.version, ConfigVersion::INITIAL);
    assert!(snapshot.tx_id.is_some());
    assert_eq!(snapshot.config.name, "initial");

    let history = store.history().await;
    assert_eq!(history.len(), 1);
    assert_eq!(Some(history[0].tx_id), snapshot.tx_id);
    assert_eq!(history[0].version, ConfigVersion::INITIAL);
    assert_eq!(history[0].config.name, "initial");
    assert!(history[0].parent_tx_id.is_none());
    assert!(history[0].confirmed_deadline.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_surfaces_startup_validation_task_panics() {
    let store = Arc::new(MockManagedDatastore::new());

    let err =
        match ConfigBus::new_dev_only(TestConfig::panic_on_validate("initial"), Arc::clone(&store))
            .await
        {
            Ok(_) => panic!("startup validation panic should fail"),
            Err(err) => err,
        };

    assert_eq!(err.code, StoreErrorCode::StartupValidationTaskFailed);
    assert_eq!(err.message, "startup config validation task panicked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_rejects_invalid_initial_config_before_publish() {
    let store = Arc::new(MockManagedDatastore::new());

    let err = match ConfigBus::new_dev_only(TestConfig::new(""), Arc::clone(&store)).await {
        Ok(_) => panic!("invalid initial config should fail startup validation"),
        Err(err) => err,
    };

    assert_eq!(err.code, StoreErrorCode::StartupSyntaxValidationFailed);
    assert_eq!(err.message, "startup config failed syntax validation");
    assert!(store.latest().await.is_none());
    assert!(store.history().await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_new_constructor_preserves_alarm_manager_on_error() {
    let err = match ConfigBus::new_dev_only(TestConfig::new(""), MockManagedDatastore::new()).await
    {
        Ok(_) => panic!("invalid initial config should fail startup validation"),
        Err(err) => err,
    };

    assert_eq!(err.code, StoreErrorCode::StartupSyntaxValidationFailed);
    let alarms = err
        .alarm_manager()
        .expect("default new constructor should preserve alarm manager on error");
    let alarm = single_active_alarm(&alarms, "config-bus.startup.failure");
    assert_eq!(alarm.severity, Severity::Major);
    assert_eq!(alarm.probable_cause, ProbableCause::ConfigApplyFailed);
    assert_alarm_details_code(&alarm, "startup_syntax_validation_failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_queue_capacity_constructor_preserves_alarm_manager_on_error() {
    let err = match ConfigBus::with_queue_capacity_dev_only(
        TestConfig::new(""),
        MockManagedDatastore::new(),
        1,
    )
    .await
    {
        Ok(_) => panic!("invalid initial config should fail startup validation"),
        Err(err) => err,
    };

    assert_eq!(err.code, StoreErrorCode::StartupSyntaxValidationFailed);
    let alarms = err
        .alarm_manager()
        .expect("default startup constructor should preserve alarm manager on error");
    let alarm = single_active_alarm(&alarms, "config-bus.startup.failure");
    assert_eq!(alarm.severity, Severity::Major);
    assert_eq!(alarm.probable_cause, ProbableCause::ConfigApplyFailed);
    assert_alarm_details_code(&alarm, "startup_syntax_validation_failed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_restore_constructor_preserves_alarm_manager_on_error() {
    let store = Arc::new(MockManagedDatastore::new());
    let mut stored = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(3),
        principal(),
        RequestSource::StartupRecovery,
        TestConfig::new("persisted"),
    );
    stored.schema_digest =
        SchemaDigest::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .expect("digest");
    store.seed(stored).await;

    let err =
        match ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
            .await
        {
            Ok(_) => panic!("schema mismatch should fail startup restore"),
            Err(err) => err,
        };

    assert_eq!(err.code, StoreErrorCode::RestoreSchemaMismatch);
    let alarms = err
        .alarm_manager()
        .expect("default restore constructor should preserve alarm manager on error");
    let alarm = single_active_alarm(&alarms, "config-bus.startup.failure");
    assert_eq!(alarm.severity, Severity::Critical);
    assert_eq!(alarm.probable_cause, ProbableCause::StorageCorruption);
    assert_alarm_details_code(&alarm, "restore_schema_mismatch");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_or_new_rejects_persisted_confirmed_deadline() {
    let store = Arc::new(MockManagedDatastore::new());
    let mut stored = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(3),
        principal(),
        RequestSource::StartupRecovery,
        TestConfig::new("persisted"),
    );
    stored.confirmed_deadline = Some(Timestamp::from(OffsetDateTime::UNIX_EPOCH));
    store.seed(stored).await;

    let err =
        match ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
            .await
        {
            Ok(_) => panic!("persisted commit-confirmed state should fail startup restore"),
            Err(err) => err,
        };

    assert_eq!(err.code, StoreErrorCode::RestoreConfirmedDeadline);
    assert_eq!(
        err.message,
        "stored running config requires commit-confirmed recovery"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_schema_mismatch_raises_critical_startup_alarm() {
    let store = Arc::new(MockManagedDatastore::new());
    let alarms = SharedAlarmManager::default();
    let mut stored = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(3),
        principal(),
        RequestSource::StartupRecovery,
        TestConfig::new("persisted"),
    );
    stored.schema_digest =
        SchemaDigest::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            .expect("digest");
    store.seed(stored).await;

    let err = match ConfigBus::restore_or_new_with_alarm_manager_dev_only(
        TestConfig::new("fallback"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    {
        Ok(_) => panic!("schema mismatch should fail startup restore"),
        Err(err) => err,
    };

    assert_eq!(err.code, StoreErrorCode::RestoreSchemaMismatch);
    let alarm = single_active_alarm(&alarms, "config-bus.startup.failure");
    assert_eq!(alarm.severity, Severity::Critical);
    assert_eq!(alarm.probable_cause, ProbableCause::StorageCorruption);
    assert_eq!(
        alarm.text.as_str(),
        "Config bus startup failure: restore_schema_mismatch"
    );
    assert_alarm_details_code(&alarm, "restore_schema_mismatch");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_recovery_required_raises_critical_startup_alarm() {
    let store = Arc::new(MockManagedDatastore::new());
    let alarms = SharedAlarmManager::default();
    let mut stored = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(3),
        principal(),
        RequestSource::StartupRecovery,
        TestConfig::new("persisted"),
    );
    stored.recovery_required = true;
    store.seed(stored).await;

    let err = match ConfigBus::restore_or_new_with_alarm_manager_dev_only(
        TestConfig::new("fallback"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    {
        Ok(_) => panic!("recovery marker should fail startup restore"),
        Err(err) => err,
    };

    assert_eq!(err.code, StoreErrorCode::RestoreRecoveryRequired);
    let alarm = single_active_alarm(&alarms, "config-bus.startup.failure");
    assert_eq!(alarm.severity, Severity::Critical);
    assert_eq!(alarm.probable_cause, ProbableCause::StorageCorruption);
    assert_alarm_details_code(&alarm, "restore_recovery_required");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_confirmed_deadline_raises_critical_startup_alarm() {
    let store = Arc::new(MockManagedDatastore::new());
    let alarms = SharedAlarmManager::default();
    let mut stored = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(3),
        principal(),
        RequestSource::StartupRecovery,
        TestConfig::new("persisted"),
    );
    stored.confirmed_deadline = Some(Timestamp::from(OffsetDateTime::UNIX_EPOCH));
    store.seed(stored).await;

    let err = match ConfigBus::restore_or_new_with_alarm_manager_dev_only(
        TestConfig::new("fallback"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    {
        Ok(_) => panic!("commit-confirmed restore state should fail startup restore"),
        Err(err) => err,
    };

    assert_eq!(err.code, StoreErrorCode::RestoreConfirmedDeadline);
    let alarm = single_active_alarm(&alarms, "config-bus.startup.failure");
    assert_eq!(alarm.severity, Severity::Critical);
    assert_eq!(alarm.probable_cause, ProbableCause::StorageCorruption);
    assert_alarm_details_code(&alarm, "restore_confirmed_deadline");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_or_new_reuses_persisted_request_context_for_revalidation() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(ContextBoundConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let candidate = ContextBoundConfig::new("persisted").with_authz(
        "config-admin",
        TransportType::RestconfHttps,
        RequestSource::Northbound,
    );

    bus.submit(CommitRequest::commit(
        RequestId::new(),
        principal_with_roles(["config-admin"]),
        TransportType::RestconfHttps,
        RequestSource::Northbound,
        ConfigOperation::Replace,
        candidate,
        vec![changed_path()],
        Instant::now() + Duration::from_secs(1),
    ))
    .await
    .expect("context-bound commit succeeds");

    let restored =
        ConfigBus::restore_or_new_dev_only(ContextBoundConfig::new("fallback"), Arc::clone(&store))
            .await
            .expect("restart should honor the persisted request context");

    assert_eq!(restored.version(), ConfigVersion::new(1));
    assert_eq!(restored.load().name, "persisted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_or_new_preserves_request_id_in_validation_context() {
    let store = Arc::new(MockManagedDatastore::new());
    let known_request_id =
        RequestId::from_str("123e4567-e89b-12d3-a456-426614174000").expect("uuid");
    let config = RequestIdAssertingConfig::new("persisted").expect_request_id(known_request_id);
    let mut stored = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(3),
        principal(),
        RequestSource::Northbound,
        config,
    );
    stored.request_fingerprint = Some(opc_config_bus::StoredRequestFingerprint {
        operation: ConfigOperation::Replace,
        mode: opc_config_bus::StoredRequestMode::Commit,
        transport: TransportType::Internal,
        changed_paths: vec![changed_path()],
        base_version: None,
    });
    stored.request_id = Some(known_request_id);
    store.seed(stored).await;

    let restored = ConfigBus::restore_or_new_dev_only(
        RequestIdAssertingConfig::new("fallback"),
        Arc::clone(&store),
    )
    .await
    .expect("restart should preserve the original request_id in validation context");

    assert_eq!(restored.version(), ConfigVersion::new(3));
    assert_eq!(restored.load().name, "persisted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_or_new_legacy_no_fingerprint_record_uses_version_minus_one_base() {
    let store = Arc::new(MockManagedDatastore::new());
    let stored_version = ConfigVersion::new(5);
    let expected_base = ConfigVersion::new(4);
    let config = BaseVersionAssertingConfig::new("persisted").expect_base_version(expected_base);
    let mut stored = StoredConfig::new(
        opc_types::TxId::new(),
        stored_version,
        principal(),
        RequestSource::Northbound,
        config,
    );
    stored.request_fingerprint = None;
    store.seed(stored).await;

    let restored = ConfigBus::restore_or_new_dev_only(
        BaseVersionAssertingConfig::new("fallback"),
        Arc::clone(&store),
    )
    .await
    .expect("restart should reconstruct base_version as version-1 for legacy records");

    assert_eq!(restored.version(), stored_version);
    assert_eq!(restored.load().name, "persisted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_or_new_legacy_fingerprint_no_base_version_uses_version_minus_one_base() {
    let store = Arc::new(MockManagedDatastore::new());
    let stored_version = ConfigVersion::new(5);
    let expected_base = ConfigVersion::new(4);
    let config = BaseVersionAssertingConfig::new("persisted").expect_base_version(expected_base);
    let mut stored = StoredConfig::new(
        opc_types::TxId::new(),
        stored_version,
        principal(),
        RequestSource::Northbound,
        config,
    );
    stored.request_fingerprint = Some(opc_config_bus::StoredRequestFingerprint {
        operation: ConfigOperation::Replace,
        mode: opc_config_bus::StoredRequestMode::Commit,
        transport: TransportType::Internal,
        changed_paths: vec![changed_path()],
        base_version: None,
    });
    store.seed(stored).await;

    let restored = ConfigBus::restore_or_new_dev_only(
        BaseVersionAssertingConfig::new("fallback"),
        Arc::clone(&store),
    )
    .await
    .expect("restart should reconstruct base_version as version-1 for legacy fingerprint records");

    assert_eq!(restored.version(), stored_version);
    assert_eq!(restored.load().name, "persisted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restore_or_new_non_contiguous_version_uses_persisted_base_version() {
    let store = Arc::new(MockManagedDatastore::new());
    let stored_version = ConfigVersion::new(5);
    let expected_base = ConfigVersion::new(2);
    let config = BaseVersionAssertingConfig::new("persisted").expect_base_version(expected_base);
    let mut stored = StoredConfig::new(
        opc_types::TxId::new(),
        stored_version,
        principal(),
        RequestSource::Northbound,
        config,
    );
    stored.request_fingerprint = Some(opc_config_bus::StoredRequestFingerprint {
        operation: ConfigOperation::Replace,
        mode: opc_config_bus::StoredRequestMode::Commit,
        transport: TransportType::Internal,
        changed_paths: vec![changed_path()],
        base_version: Some(expected_base),
    });
    store.seed(stored).await;

    let restored = ConfigBus::restore_or_new_dev_only(
        BaseVersionAssertingConfig::new("fallback"),
        Arc::clone(&store),
    )
    .await
    .expect("restart should use exact persisted base_version for non-contiguous versions");

    assert_eq!(restored.version(), stored_version);
    assert_eq!(restored.load().name, "persisted");
}
