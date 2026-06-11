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
    ConfigBus, ConfigEvent, ConfigSnapshot, DriftState, ManagedDatastore, MockManagedDatastore,
    StoreError, StoreErrorCode, StoredConfig, SubscriberLagPolicy,
};
use opc_config_model::{
    CommitErrorCode, CommitMode, CommitRequest, ConfigError, ConfigOperation, IdempotencyKey,
    OpcConfig, RequestId, RequestSource, RollbackTarget, TransportType, TrustedPrincipal,
    ValidationContext, ValidationError, WorkloadIdentity, YangPath,
};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp};

mod config_bus_common;
use config_bus_common::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn successful_commit_clears_recovery_marker_without_duplicate_history() {
    let store = Arc::new(MockManagedDatastore::new());
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
    let history = store.history().await;
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].tx_id, result.tx_id);
    assert!(!history[0].recovery_required);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mock_store_rejects_duplicate_history_keys() {
    let store = MockManagedDatastore::new();
    let record = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(1),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("persisted"),
    );

    store
        .append_commit(record.clone())
        .await
        .expect("first insert succeeds");

    let duplicate_tx = store
        .append_commit(record.clone())
        .await
        .expect_err("duplicate tx id should be rejected");
    assert_eq!(duplicate_tx.code, StoreErrorCode::Internal);

    let duplicate_version = store
        .append_commit(StoredConfig::new(
            opc_types::TxId::new(),
            ConfigVersion::new(1),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("persisted-v2"),
        ))
        .await
        .expect_err("duplicate version should be rejected");
    assert_eq!(duplicate_version.code, StoreErrorCode::Internal);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_diff_expires_before_persist_and_does_not_publish() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");

    let err = bus
        .submit(CommitRequest::commit(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            TestConfig::with_diff_delay("slow-next", Duration::from_millis(80)),
            vec![changed_path()],
            Instant::now() + Duration::from_millis(20),
        ))
        .await
        .expect_err("slow diff should miss the deadline");

    assert_eq!(err.code, CommitErrorCode::DeadlineExceeded);
    assert_eq!(bus.version(), ConfigVersion::INITIAL);
    assert_eq!(bus.load().name, "initial");
    assert_eq!(store.history().await.len(), 0);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persist_failures_are_redacted_for_clients() {
    let secret = "dsn=postgres://user:secret@db/internal";
    let bus = ConfigBus::new_dev_only(
        TestConfig::new("initial"),
        Arc::new(ErrorStore::append_fails(secret)),
    )
    .await
    .expect("startup succeeds");

    let err = bus
        .submit(commit_request(
            "next",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("append failure should surface to caller");

    assert_eq!(err.code, CommitErrorCode::PersistFailed);
    assert_eq!(err.message, "durable config persistence failed");
    assert!(!err.message.contains(secret));
}
