use std::sync::Arc;
use std::time::{Duration, Instant};

use opc_config_bus::{ConfigBus, ConfigEvent, InMemoryManagedDatastore, ManagedDatastore};
use opc_config_model::{CommitMode, CommitRequest, IdempotencyKey, RollbackTarget};
use opc_types::ConfigVersion;

mod config_bus_common;
use config_bus_common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_memory_datastore_works_with_new_dev_only_and_persists_appends() {
    let store = Arc::new(InMemoryManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");

    let result = bus
        .submit(commit_request(
            "next",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect("commit succeeds");

    assert_eq!(result.new_version, Some(ConfigVersion::new(1)));
    assert_eq!(bus.load().name, "next");

    let history = store.history().await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].tx_id, result.tx_id);
    assert_eq!(history[0].config.name, "next");
    assert!(!history[0].recovery_required);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_memory_datastore_works_with_restore_or_new() {
    let store = Arc::new(InMemoryManagedDatastore::new());

    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("empty store restore should bootstrap");
    bus.submit(commit_request(
        "persisted",
        Instant::now() + Duration::from_secs(1),
    ))
    .await
    .expect("commit succeeds");

    let restored =
        ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
            .await
            .expect("restart should restore latest in-process record");

    assert_eq!(restored.version(), ConfigVersion::new(1));
    assert_eq!(restored.load().name, "persisted");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_memory_datastore_supports_rollback() {
    let store = Arc::new(InMemoryManagedDatastore::new());
    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");

    bus.submit(commit_request(
        "next",
        Instant::now() + Duration::from_secs(1),
    ))
    .await
    .expect("commit succeeds");

    let rollback = bus
        .submit(CommitRequest::rollback(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            RollbackTarget::Previous,
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect("rollback succeeds");

    assert_eq!(
        rollback.status,
        opc_config_model::CommitStatus::RollbackApplied
    );
    assert_eq!(bus.version(), ConfigVersion::new(2));
    assert_eq!(bus.load().name, "initial");
    assert_eq!(store.history().await.len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_memory_datastore_supports_commit_confirmed_flows() {
    let confirm_store = Arc::new(InMemoryManagedDatastore::new());
    let confirm_bus =
        ConfigBus::restore_or_new_dev_only(TestConfig::new("initial"), Arc::clone(&confirm_store))
            .await
            .expect("startup succeeds");
    begin_confirmed(
        &confirm_bus,
        "tentative-confirm",
        Duration::from_millis(100),
    )
    .await;

    confirm_bus
        .submit(CommitRequest::new(
            RequestId::new(),
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
        .expect("explicit confirm succeeds");
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert_eq!(confirm_bus.load().name, "tentative-confirm");
    assert!(confirm_store
        .history()
        .await
        .iter()
        .all(|record| record.confirmed_deadline.is_none()));

    let cancel_store = Arc::new(InMemoryManagedDatastore::new());
    let cancel_bus =
        ConfigBus::restore_or_new_dev_only(TestConfig::new("initial"), Arc::clone(&cancel_store))
            .await
            .expect("startup succeeds");
    begin_confirmed(&cancel_bus, "tentative-cancel", Duration::from_secs(60)).await;
    cancel_bus
        .submit(CommitRequest::cancel_confirmed(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect("cancel succeeds");
    assert_eq!(cancel_bus.load().name, "initial");

    let timeout_store = Arc::new(InMemoryManagedDatastore::new());
    let timeout_bus =
        ConfigBus::restore_or_new_dev_only(TestConfig::new("initial"), Arc::clone(&timeout_store))
            .await
            .expect("startup succeeds");
    let subscriber = timeout_bus.subscribe(SubscriberLagPolicy::DropOldest, 5);
    begin_confirmed(&timeout_bus, "tentative-timeout", Duration::from_millis(50)).await;
    let _ = subscriber.recv().await.expect("tentative event");

    tokio::time::sleep(Duration::from_millis(150)).await;

    assert_eq!(timeout_bus.load().name, "initial");
    match subscriber.recv().await.expect("timeout rollback event") {
        ConfigEvent::Change(change) => assert_eq!(change.current.name, "initial"),
        ConfigEvent::ResyncRequired { .. } => panic!("expected rollback change event"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_memory_datastore_preserves_idempotency_behavior() {
    let store = Arc::new(InMemoryManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");
    let key = IdempotencyKey::new("in-memory-replay").expect("key");

    let first = bus
        .submit(
            commit_request("next", Instant::now() + Duration::from_secs(1))
                .with_idempotency_key(key.clone()),
        )
        .await
        .expect("first commit succeeds");
    let second = bus
        .submit(
            commit_request("next", Instant::now() + Duration::from_secs(1))
                .with_idempotency_key(key),
        )
        .await
        .expect("idempotent replay succeeds");

    assert_eq!(second, first);
    assert_eq!(store.history().await.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_memory_datastore_preserves_recovery_marker_behavior() {
    let store = Arc::new(InMemoryManagedDatastore::new());
    let mut record = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(1),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("needs-recovery"),
    );
    record.recovery_required = true;
    store
        .append_commit(record)
        .await
        .expect("direct append succeeds");

    let err =
        match ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), Arc::clone(&store))
            .await
        {
            Ok(_) => panic!("recovery marker should fail closed on restore"),
            Err(err) => err,
        };

    assert_eq!(err.code, StoreErrorCode::RestoreRecoveryRequired);
}

async fn begin_confirmed(
    bus: &ConfigBus<TestConfig>,
    name: &str,
    timeout: Duration,
) -> opc_config_model::CommitResult {
    bus.submit(
        CommitRequest::new(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            CommitMode::CommitConfirmed { timeout },
            Instant::now() + Duration::from_secs(1),
            Some(TestConfig::new(name)),
            vec![changed_path()],
        )
        .with_base_version(bus.version()),
    )
    .await
    .expect("commit-confirmed succeeds")
}
