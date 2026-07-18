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
async fn commit_confirmed_stores_deadline_and_publishes() {
    let store = Arc::new(MockManagedDatastore::new());
    store
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
    let subscriber = bus.subscribe(SubscriberLagPolicy::DropOldest, 1);

    let result = bus
        .submit(
            CommitRequest::new(
                RequestId::new(),
                principal(),
                TransportType::Internal,
                RequestSource::Northbound,
                ConfigOperation::Replace,
                CommitMode::CommitConfirmed {
                    timeout: Duration::from_millis(200),
                },
                Instant::now() + Duration::from_secs(1),
                Some(TestConfig::new("tentative")),
                vec![changed_path()],
            )
            .with_base_version(bus.version()),
        )
        .await
        .expect("commit-confirmed submission should succeed");

    assert_eq!(
        result.status,
        opc_config_model::CommitStatus::CommitConfirmedPending
    );
    assert_eq!(bus.version(), ConfigVersion::new(2));
    assert_eq!(bus.load().name, "tentative");

    match subscriber.recv().await.expect("event published") {
        ConfigEvent::Change(change) => {
            assert_eq!(change.version, ConfigVersion::new(2));
            assert_eq!(change.current.name, "tentative");
        }
        _ => panic!("expected change event"),
    }

    let history = store.history().await;
    assert_eq!(history.len(), 2);
    assert!(history[1].confirmed_deadline.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_append_arms_rollback_from_the_persisted_absolute_deadline() {
    let store = Arc::new(BlockingStore::new());
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

    let submit = {
        let bus = bus.clone();
        tokio::spawn(async move {
            bus.submit(
                CommitRequest::new(
                    RequestId::new(),
                    principal(),
                    TransportType::Internal,
                    RequestSource::Northbound,
                    ConfigOperation::Replace,
                    CommitMode::CommitConfirmed {
                        timeout: Duration::from_secs(1),
                    },
                    Instant::now() + Duration::from_secs(3),
                    Some(TestConfig::new("tentative")),
                    vec![changed_path()],
                )
                .with_base_version(ConfigVersion::new(1)),
            )
            .await
        })
    };

    store.wait_until_append_started().await;
    tokio::time::sleep(Duration::from_millis(700)).await;
    store.release();
    submit
        .await
        .expect("submit task completes")
        .expect("slow durable append remains a successful pending commit");

    tokio::time::timeout(Duration::from_millis(600), async {
        loop {
            if store.inner.history().await.len() == 3 && bus.load().name == "initial" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("rollback persists and publishes from the pre-append persisted deadline");
    assert_eq!(bus.load().name, "initial");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_confirmed_requires_durable_rollback_parent() {
    let store = Arc::new(MockManagedDatastore::new());
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");

    let error = bus
        .submit(CommitRequest::new(
            RequestId::new(),
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
        ))
        .await
        .expect_err("commit-confirmed without rollback parent must fail closed");

    assert_eq!(error.code, CommitErrorCode::RollbackUnavailable);
    assert_eq!(bus.load().name, "initial");
    assert!(store.history().await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_confirmed_update_while_pending_fails_closed() {
    let store = Arc::new(MockManagedDatastore::new());
    store
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

    bus.submit(
        CommitRequest::new(
            RequestId::new(),
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
        .with_base_version(bus.version()),
    )
    .await
    .expect("first commit-confirmed succeeds");

    let error = bus
        .submit(CommitRequest::new(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            CommitMode::CommitConfirmed {
                timeout: Duration::from_secs(60),
            },
            Instant::now() + Duration::from_secs(1),
            Some(TestConfig::new("stacked")),
            vec![changed_path()],
        ))
        .await
        .expect_err("second commit-confirmed must fail closed while pending");

    assert_eq!(error.code, CommitErrorCode::AdmissionRejected);
    assert_eq!(bus.load().name, "tentative");
    assert_eq!(store.history().await.len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_confirmed_explicit_confirm_prevents_rollback() {
    let store = Arc::new(MockManagedDatastore::new());
    store
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
    let subscriber = bus.subscribe(SubscriberLagPolicy::DropOldest, 1);

    bus.submit(
        CommitRequest::new(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            CommitMode::CommitConfirmed {
                timeout: Duration::from_millis(100),
            },
            Instant::now() + Duration::from_secs(1),
            Some(TestConfig::new("tentative")),
            vec![changed_path()],
        )
        .with_base_version(bus.version()),
    )
    .await
    .expect("commit-confirmed succeeds");

    let _ = subscriber.recv().await;

    let confirm_res = bus
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

    assert_eq!(
        confirm_res.status,
        opc_config_model::CommitStatus::Committed
    );
    assert_eq!(bus.version(), ConfigVersion::new(3));

    tokio::time::sleep(Duration::from_millis(150)).await;

    assert_eq!(bus.load().name, "tentative");
    assert_eq!(bus.version(), ConfigVersion::new(3));

    let history = store.history().await;
    assert!(history.iter().all(|r| r.confirmed_deadline.is_none()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_confirmed_cancel_rolls_back_immediately() {
    let store = Arc::new(MockManagedDatastore::new());
    store
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
    let subscriber = bus.subscribe(SubscriberLagPolicy::DropOldest, 5);

    bus.submit(
        CommitRequest::new(
            RequestId::new(),
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
        .with_base_version(bus.version()),
    )
    .await
    .expect("commit-confirmed succeeds");
    let _ = subscriber.recv().await.expect("tentative event");
    assert_eq!(bus.load().name, "tentative");

    let cancel = bus
        .submit(CommitRequest::cancel_confirmed(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            vec![changed_path()],
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect("cancel-confirmed succeeds");

    assert_eq!(
        cancel.status,
        opc_config_model::CommitStatus::RollbackApplied
    );
    assert_eq!(bus.load().name, "initial");
    assert_eq!(bus.version(), ConfigVersion::new(3));

    match subscriber.recv().await.expect("rollback event published") {
        ConfigEvent::Change(change) => {
            assert_eq!(change.version, ConfigVersion::new(3));
            assert_eq!(change.current.name, "initial");
        }
        _ => panic!("expected change event"),
    }

    let history = store.history().await;
    assert!(history
        .last()
        .is_some_and(|record| record.confirmed_deadline.is_none()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_confirmed_expiry_rollback_restores_previous() {
    let store = Arc::new(MockManagedDatastore::new());
    store
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
    let subscriber = bus.subscribe(SubscriberLagPolicy::DropOldest, 5);

    bus.submit(
        CommitRequest::new(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            CommitMode::CommitConfirmed {
                timeout: Duration::from_millis(50),
            },
            Instant::now() + Duration::from_secs(1),
            Some(TestConfig::new("tentative")),
            vec![changed_path()],
        )
        .with_base_version(bus.version()),
    )
    .await
    .expect("commit-confirmed succeeds");

    match subscriber.recv().await.expect("event published") {
        ConfigEvent::Change(change) => {
            assert_eq!(change.version, ConfigVersion::new(2));
            assert_eq!(change.current.name, "tentative");
        }
        _ => panic!("expected change event"),
    }

    tokio::time::sleep(Duration::from_millis(150)).await;

    assert_eq!(bus.load().name, "initial");
    assert_eq!(bus.version(), ConfigVersion::new(3));

    match subscriber.recv().await.expect("rollback event published") {
        ConfigEvent::Change(change) => {
            assert_eq!(change.version, ConfigVersion::new(3));
            assert_eq!(change.current.name, "initial");
        }
        _ => panic!("expected change event"),
    }

    assert!(
        tokio::time::timeout(Duration::from_millis(25), subscriber.recv())
            .await
            .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn expiry_rollback_fires_on_virtual_clock() {
    let store = Arc::new(MockManagedDatastore::new());
    store
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
    let subscriber = bus.subscribe(SubscriberLagPolicy::DropOldest, 5);

    bus.submit(
        CommitRequest::new(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            CommitMode::CommitConfirmed {
                timeout: Duration::from_secs(5),
            },
            Instant::now() + Duration::from_secs(1),
            Some(TestConfig::new("tentative")),
            vec![changed_path()],
        )
        .with_base_version(bus.version()),
    )
    .await
    .expect("commit-confirmed succeeds");

    match subscriber.recv().await.expect("event published") {
        ConfigEvent::Change(change) => {
            assert_eq!(change.version, ConfigVersion::new(2));
            assert_eq!(change.current.name, "tentative");
        }
        _ => panic!("expected change event"),
    }

    match subscriber.recv().await.expect("rollback event published") {
        ConfigEvent::Change(change) => {
            assert_eq!(change.version, ConfigVersion::new(3));
            assert_eq!(change.current.name, "initial");
        }
        _ => panic!("expected change event"),
    }

    assert_eq!(bus.load().name, "initial");
    assert_eq!(bus.version(), ConfigVersion::new(3));
}

#[tokio::test(start_paused = true)]
async fn replaying_pending_commit_confirmed_does_not_extend_its_durable_deadline() {
    let store = Arc::new(MockManagedDatastore::new());
    store
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
    let subscriber = bus.subscribe(SubscriberLagPolicy::DropOldest, 4);
    let key = IdempotencyKey::new("pending-replay-deadline").expect("key");
    let request = || {
        CommitRequest::new(
            RequestId::new(),
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
        .with_base_version(ConfigVersion::new(1))
        .with_idempotency_key(key.clone())
    };

    let timer_started = tokio::time::Instant::now();
    let first = bus
        .submit(request())
        .await
        .expect("commit-confirmed succeeds");
    subscriber.recv().await.expect("pending change published");
    tokio::time::advance(Duration::from_secs(30)).await;
    let replayed = bus.submit(request()).await.expect("exact replay succeeds");
    assert_eq!(replayed, first);

    tokio::time::advance(Duration::from_secs(31)).await;
    subscriber.recv().await.expect("rollback change published");
    assert!(
        tokio::time::Instant::now() <= timer_started + Duration::from_secs(62),
        "read-only replay must not push rollback into a new timeout window"
    );
    let history = store.history().await;
    assert_eq!(history.len(), 3, "rollback must use the original deadline");
    assert_eq!(bus.load().name, "initial");
}

#[tokio::test(start_paused = true)]
async fn replaying_an_older_commit_does_not_clear_a_newer_pending_deadline() {
    let store = Arc::new(MockManagedDatastore::new());
    store
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
    let subscriber = bus.subscribe(SubscriberLagPolicy::DropOldest, 6);
    let old_key = IdempotencyKey::new("older-stable-commit").expect("key");
    let old_request = || {
        commit_request("stable", Instant::now() + Duration::from_secs(1))
            .with_base_version(ConfigVersion::new(1))
            .with_idempotency_key(old_key.clone())
    };
    let old_result = bus
        .submit(old_request())
        .await
        .expect("stable commit succeeds");
    subscriber.recv().await.expect("stable change published");

    let pending_timer_started = tokio::time::Instant::now();
    bus.submit(
        CommitRequest::new(
            RequestId::new(),
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
        .with_base_version(ConfigVersion::new(2))
        .with_idempotency_key(IdempotencyKey::new("newer-pending").expect("key")),
    )
    .await
    .expect("commit-confirmed succeeds");
    subscriber.recv().await.expect("pending change published");

    tokio::time::advance(Duration::from_secs(30)).await;
    let replayed = bus
        .submit(old_request())
        .await
        .expect("older replay succeeds");
    assert_eq!(replayed, old_result);

    tokio::time::advance(Duration::from_secs(31)).await;
    subscriber.recv().await.expect("rollback change published");
    assert!(
        tokio::time::Instant::now() <= pending_timer_started + Duration::from_secs(62),
        "older replay must not disarm the newer rollback timer"
    );
    let history = store.history().await;
    assert_eq!(history.len(), 4, "older replay must not disarm rollback");
    assert_eq!(bus.load().name, "stable");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_confirmed_expiry_rollback_failure_fences_and_alarms() {
    let alarms = SharedAlarmManager::default();

    struct RollbackFailureStore {
        inner: MockManagedDatastore<TestConfig>,
        rollback_append_attempts: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ManagedDatastore<TestConfig> for RollbackFailureStore {
        async fn load_latest(&self) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
            self.inner.load_latest().await
        }
        async fn load_rollback(
            &self,
            target: RollbackTarget,
        ) -> Result<StoredConfig<TestConfig>, StoreError> {
            self.inner.load_rollback(target).await
        }
        async fn load_by_idempotency_key(
            &self,
            k: &IdempotencyKey,
        ) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
            self.inner.load_by_idempotency_key(k).await
        }
        async fn load_by_request_id(
            &self,
            request_id: RequestId,
        ) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
            self.inner.load_by_request_id(request_id).await
        }
        async fn append_commit_write(
            &self,
            commit: CommitWrite<TestConfig>,
        ) -> Result<(), StoreError> {
            if commit.record().source == RequestSource::Internal {
                self.rollback_append_attempts.fetch_add(1, Ordering::SeqCst);
                return Err(StoreError::internal("disk full or similar write error"));
            }
            self.inner.append_commit_write(commit).await
        }
        async fn clear_recovery_required(&self, tx_id: opc_types::TxId) -> Result<(), StoreError> {
            self.inner.clear_recovery_required(tx_id).await
        }
    }

    let inner_store = MockManagedDatastore::new();
    inner_store
        .seed(StoredConfig::new(
            opc_types::TxId::new(),
            ConfigVersion::new(1),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("initial"),
        ))
        .await;

    let rollback_append_attempts = Arc::new(AtomicUsize::new(0));
    let store = Arc::new(RollbackFailureStore {
        inner: inner_store,
        rollback_append_attempts: Arc::clone(&rollback_append_attempts),
    });
    let bus = ConfigBus::restore_or_new_with_alarm_manager_dev_only(
        TestConfig::new("initial"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    bus.submit(
        CommitRequest::new(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            CommitMode::CommitConfirmed {
                timeout: Duration::from_millis(50),
            },
            Instant::now() + Duration::from_secs(1),
            Some(TestConfig::new("tentative")),
            vec![changed_path()],
        )
        .with_base_version(bus.version()),
    )
    .await
    .expect("commit-confirmed succeeds");

    tokio::time::sleep(Duration::from_millis(150)).await;

    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);

    let alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(alarm.severity, Severity::Major);

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        rollback_append_attempts.load(Ordering::SeqCst),
        1,
        "expiry rollback failure must fence once instead of retrying in a tight loop"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn expiry_rollback_marker_clear_failure_reports_applied_decision_and_fences() {
    struct RollbackMarkerFailureStore {
        inner: MockManagedDatastore<TestConfig>,
        clear_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ManagedDatastore<TestConfig> for RollbackMarkerFailureStore {
        async fn load_latest(&self) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
            self.inner.load_latest().await
        }
        async fn load_rollback(
            &self,
            target: RollbackTarget,
        ) -> Result<StoredConfig<TestConfig>, StoreError> {
            self.inner.load_rollback(target).await
        }
        async fn load_by_idempotency_key(
            &self,
            key: &IdempotencyKey,
        ) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
            self.inner.load_by_idempotency_key(key).await
        }
        async fn load_by_request_id(
            &self,
            request_id: RequestId,
        ) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
            self.inner.load_by_request_id(request_id).await
        }
        async fn append_commit_write(
            &self,
            commit: CommitWrite<TestConfig>,
        ) -> Result<(), StoreError> {
            self.inner.append_commit_write(commit).await
        }
        async fn clear_recovery_required(&self, tx_id: opc_types::TxId) -> Result<(), StoreError> {
            if self.clear_calls.fetch_add(1, Ordering::AcqRel) == 0 {
                self.inner.clear_recovery_required(tx_id).await
            } else {
                Err(StoreError::internal(
                    "rollback recovery marker clear failed",
                ))
            }
        }
    }

    let inner = MockManagedDatastore::new();
    inner
        .seed(StoredConfig::new(
            opc_types::TxId::new(),
            ConfigVersion::new(1),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("initial"),
        ))
        .await;
    let store = Arc::new(RollbackMarkerFailureStore {
        inner,
        clear_calls: AtomicUsize::new(0),
    });
    let alarms = SharedAlarmManager::default();
    let bus = ConfigBus::restore_or_new_with_alarm_manager_dev_only(
        TestConfig::new("fallback"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    bus.submit(
        CommitRequest::new(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            CommitMode::CommitConfirmed {
                timeout: Duration::from_millis(50),
            },
            Instant::now() + Duration::from_secs(1),
            Some(TestConfig::new("tentative")),
            vec![changed_path()],
        )
        .with_base_version(ConfigVersion::new(1)),
    )
    .await
    .expect("commit-confirmed succeeds");

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if bus.version() == ConfigVersion::new(3) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("expiry rollback publishes despite marker-clear failure");

    assert_eq!(bus.load().name, "initial");
    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);
    let history = store.inner.history().await;
    assert_eq!(history.len(), 3);
    assert!(history[2].recovery_required);
    let alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_alarm_details_code(&alarm, "recovery_required");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_confirmed_expiry_validates_rollback_parent_before_publish() {
    struct InvalidRollbackParentStore {
        inner: MockManagedDatastore<TestConfig>,
    }

    #[async_trait::async_trait]
    impl ManagedDatastore<TestConfig> for InvalidRollbackParentStore {
        async fn load_latest(&self) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
            self.inner.load_latest().await
        }
        async fn load_rollback(
            &self,
            target: RollbackTarget,
        ) -> Result<StoredConfig<TestConfig>, StoreError> {
            let mut stored = self.inner.load_rollback(target).await?;
            stored.config =
                TestConfig::with_semantic_error(stored.config.name, "semantic rollback failure");
            Ok(stored)
        }
        async fn load_by_idempotency_key(
            &self,
            k: &IdempotencyKey,
        ) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
            self.inner.load_by_idempotency_key(k).await
        }
        async fn append_commit_write(
            &self,
            commit: CommitWrite<TestConfig>,
        ) -> Result<(), StoreError> {
            self.inner.append_commit_write(commit).await
        }
        async fn clear_recovery_required(&self, tx_id: opc_types::TxId) -> Result<(), StoreError> {
            self.inner.clear_recovery_required(tx_id).await
        }
    }

    let inner = MockManagedDatastore::new();
    inner
        .seed(StoredConfig::new(
            opc_types::TxId::new(),
            ConfigVersion::new(1),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("initial"),
        ))
        .await;
    let store = Arc::new(InvalidRollbackParentStore { inner });
    let alarms = SharedAlarmManager::default();
    let bus = ConfigBus::restore_or_new_with_alarm_manager_dev_only(
        TestConfig::new("fallback"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    .expect("startup succeeds");

    bus.submit(
        CommitRequest::new(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            CommitMode::CommitConfirmed {
                timeout: Duration::from_millis(50),
            },
            Instant::now() + Duration::from_secs(1),
            Some(TestConfig::new("tentative")),
            vec![changed_path()],
        )
        .with_base_version(bus.version()),
    )
    .await
    .expect("commit-confirmed succeeds");

    tokio::time::sleep(Duration::from_millis(150)).await;

    assert_eq!(bus.load().name, "tentative");
    assert_eq!(bus.version(), ConfigVersion::new(2));
    assert_eq!(bus.drift_state(), DriftState::RecoveryRequired);

    let alarm = single_active_alarm(&alarms, "config-bus.commit.failure");
    assert_eq!(alarm.severity, Severity::Major);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_confirmed_atomic_decision_failure_does_not_append_or_fence() {
    struct MarkConfirmFailureStore {
        inner: MockManagedDatastore<TestConfig>,
    }

    #[async_trait::async_trait]
    impl ManagedDatastore<TestConfig> for MarkConfirmFailureStore {
        async fn load_latest(&self) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
            self.inner.load_latest().await
        }
        async fn load_rollback(
            &self,
            target: RollbackTarget,
        ) -> Result<StoredConfig<TestConfig>, StoreError> {
            self.inner.load_rollback(target).await
        }
        async fn load_by_idempotency_key(
            &self,
            k: &IdempotencyKey,
        ) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
            self.inner.load_by_idempotency_key(k).await
        }
        async fn load_by_request_id(
            &self,
            request_id: RequestId,
        ) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
            self.inner.load_by_request_id(request_id).await
        }
        async fn append_commit_write(
            &self,
            commit: CommitWrite<TestConfig>,
        ) -> Result<(), StoreError> {
            if commit.confirmed_resolution().is_some() {
                return Err(StoreError::internal("confirmation decision write failed"));
            }
            self.inner.append_commit_write(commit).await
        }
        async fn clear_recovery_required(&self, tx_id: opc_types::TxId) -> Result<(), StoreError> {
            self.inner.clear_recovery_required(tx_id).await
        }
    }

    let inner_store = MockManagedDatastore::new();
    inner_store
        .seed(StoredConfig::new(
            opc_types::TxId::new(),
            ConfigVersion::new(1),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("initial"),
        ))
        .await;

    let store = Arc::new(MarkConfirmFailureStore { inner: inner_store });
    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("initial"), Arc::clone(&store))
        .await
        .expect("startup succeeds");

    bus.submit(
        CommitRequest::new(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            CommitMode::CommitConfirmed {
                timeout: Duration::from_secs(5),
            },
            Instant::now() + Duration::from_secs(1),
            Some(TestConfig::new("tentative")),
            vec![changed_path()],
        )
        .with_base_version(bus.version()),
    )
    .await
    .expect("commit-confirmed succeeds");

    let err = bus
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
        .expect_err("failed atomic confirmation must be a clean persistence failure");

    assert_eq!(err.code, CommitErrorCode::PersistFailed);
    assert_eq!(bus.drift_state(), DriftState::InSync);
    assert_eq!(bus.version(), ConfigVersion::new(2));
    assert_eq!(bus.load().name, "tentative");
    let history = store.inner.history().await;
    assert_eq!(history.len(), 2);
    assert!(history[1].confirmed_deadline.is_some());

    let follow_up = bus
        .submit(commit_request(
            "should-be-fenced",
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect_err("a pending commit still rejects an unrelated update");
    assert_eq!(follow_up.code, CommitErrorCode::AdmissionRejected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_confirmed_restart_expired_rolls_back() {
    let store = Arc::new(MockManagedDatastore::new());
    let alarms = SharedAlarmManager::default();

    let previous = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(1),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("initial"),
    );
    store.seed(previous).await;

    let mut pending = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(2),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("tentative"),
    );
    pending.parent_tx_id = Some(store.history().await[0].tx_id);
    pending.confirmed_deadline = Some(Timestamp::from(OffsetDateTime::UNIX_EPOCH));
    store.seed(pending).await;

    let bus = ConfigBus::restore_or_new_with_alarm_manager_dev_only(
        TestConfig::new("fallback"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    .expect("startup rollback succeeds");

    assert_eq!(bus.load().name, "initial");
    assert_eq!(bus.version(), ConfigVersion::new(3));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_confirmed_restart_expired_validates_rollback_target() {
    let store = Arc::new(MockManagedDatastore::new());
    let alarms = SharedAlarmManager::default();

    let previous = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(1),
        principal(),
        RequestSource::Northbound,
        TestConfig::with_semantic_error("invalid-previous", "semantic rollback failure"),
    );
    store.seed(previous).await;

    let mut pending = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(2),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("tentative"),
    );
    pending.parent_tx_id = Some(store.history().await[0].tx_id);
    pending.confirmed_deadline = Some(Timestamp::from(OffsetDateTime::UNIX_EPOCH));
    store.seed(pending).await;

    let err = match ConfigBus::restore_or_new_with_alarm_manager_dev_only(
        TestConfig::new("fallback"),
        Arc::clone(&store),
        alarms,
    )
    .await
    {
        Ok(_) => {
            panic!("expired pending rollback target must be validated before startup succeeds")
        }
        Err(err) => err,
    };

    assert_eq!(err.code, StoreErrorCode::StartupSemanticValidationFailed);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_confirmed_restart_unexpired_resumes_timer() {
    let store = Arc::new(MockManagedDatastore::new());
    let alarms = SharedAlarmManager::default();

    let previous = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(1),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("initial"),
    );
    store.seed(previous).await;

    let mut pending = StoredConfig::new(
        opc_types::TxId::new(),
        ConfigVersion::new(2),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("tentative"),
    );
    let deadline = OffsetDateTime::now_utc() + Duration::from_secs(10);
    pending.parent_tx_id = Some(store.history().await[0].tx_id);
    pending.confirmed_deadline = Some(Timestamp::from_offset_datetime(deadline));
    store.seed(pending).await;

    let bus = ConfigBus::restore_or_new_with_alarm_manager_dev_only(
        TestConfig::new("fallback"),
        Arc::clone(&store),
        alarms.clone(),
    )
    .await
    .expect("startup succeeds, timer resumes");

    assert_eq!(bus.load().name, "tentative");
    assert_eq!(bus.version(), ConfigVersion::new(2));

    bus.submit(CommitRequest::new(
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

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(bus.load().name, "tentative");
    assert_eq!(bus.version(), ConfigVersion::new(3));
}
