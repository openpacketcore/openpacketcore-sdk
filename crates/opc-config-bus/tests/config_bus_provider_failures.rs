use async_trait::async_trait;
use opc_alarm::{ProbableCause, Severity};
use opc_types::TxId;
use std::sync::Arc;
use std::time::{Duration, Instant};
mod config_bus_common;
use config_bus_common::*;

struct FaultStore {
    inner: MockManagedDatastore<TestConfig>,
    stage: &'static str,
    code: StoreErrorCode,
}
impl FaultStore {
    fn fail(&self, stage: &str) -> Result<(), StoreError> {
        if self.stage == stage {
            Err(StoreError::new(self.code, "storage operation failed"))
        } else {
            Ok(())
        }
    }
}
#[async_trait]
impl ManagedDatastore<TestConfig> for FaultStore {
    async fn load_latest(&self) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
        self.fail("latest")?;
        if self.stage == "pending-latest" && self.inner.history().await.len() >= 2 {
            return Err(StoreError::new(self.code, "storage operation failed"));
        }
        self.inner.load_latest().await
    }
    async fn load_committed_latest(&self) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
        self.fail("committed")?;
        self.inner.load_committed_latest().await
    }
    async fn load_rollback(
        &self,
        target: RollbackTarget,
    ) -> Result<StoredConfig<TestConfig>, StoreError> {
        self.fail("rollback")?;
        self.inner.load_rollback(target).await
    }
    async fn load_by_idempotency_key(
        &self,
        key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
        self.fail("idempotency")?;
        self.inner.load_by_idempotency_key(key).await
    }
    async fn load_by_request_id(
        &self,
        id: RequestId,
    ) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
        self.fail("reconcile")?;
        self.inner.load_by_request_id(id).await
    }
    async fn retained_history_floor(&self) -> Result<Option<ConfigVersion>, StoreError> {
        self.fail("floor")?;
        Ok(None)
    }
    async fn append_commit_write(&self, write: CommitWrite<TestConfig>) -> Result<(), StoreError> {
        if self.stage == "reconcile" {
            return Err(StoreError::internal("append rejected"));
        }
        self.fail("append")?;
        if self.stage == "pending-append" && self.inner.history().await.len() == 2 {
            return Err(StoreError::new(self.code, "storage operation failed"));
        }
        self.inner.append_commit_write(write).await
    }
    async fn clear_recovery_required(&self, tx: TxId) -> Result<(), StoreError> {
        if self.stage == "expiry-clear" && self.inner.history().await.len() == 3 {
            return Err(StoreError::new(
                self.code,
                "stored recovery marker rejected",
            ));
        }
        self.fail("clear")?;
        self.inner.clear_recovery_required(tx).await
    }
}
async fn commit_read_failure_code(stage: &'static str, code: StoreErrorCode) {
    let store = Arc::new(FaultStore {
        inner: MockManagedDatastore::new(),
        stage,
        code,
    });
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), store.clone())
        .await
        .unwrap();
    let request = commit_request("next", Instant::now() + Duration::from_secs(2))
        .with_idempotency_key(IdempotencyKey::new("retry").unwrap());
    let error = bus.submit(request).await.unwrap_err();
    assert_eq!(
        error.code,
        if code == StoreErrorCode::Unavailable {
            CommitErrorCode::PersistFailed
        } else {
            CommitErrorCode::StateMachineFault
        }
    );
    let alarms = bus.alarm_manager().active_alarms();
    assert_eq!(alarms.len(), 1);
    assert_eq!(
        alarms[0].probable_cause,
        if code == StoreErrorCode::Crypto {
            ProbableCause::StorageCorruption
        } else {
            ProbableCause::ConfigApplyFailed
        }
    );
    assert!(store.inner.history().await.is_empty());
    assert_eq!(bus.load().name, "initial");
}
#[tokio::test]
async fn unavailable_idempotency_lookup_keeps_provider_alarm() {
    commit_read_failure("idempotency").await;
}
#[tokio::test]
async fn unavailable_history_floor_keeps_provider_alarm() {
    commit_read_failure("floor").await;
}
async fn startup_rollback_failure_code(stage: &'static str, code: StoreErrorCode) {
    let store = Arc::new(FaultStore {
        inner: MockManagedDatastore::new(),
        stage,
        code,
    });
    let parent = StoredConfig::new(
        TxId::new(),
        ConfigVersion::new(1),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("confirmed"),
    );
    let mut pending = StoredConfig::new(
        TxId::new(),
        ConfigVersion::new(2),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("pending"),
    );
    pending.parent_tx_id = Some(parent.tx_id);
    pending.confirmed_deadline = Some(Timestamp::from(time::OffsetDateTime::UNIX_EPOCH));
    store.inner.seed(parent).await;
    store.inner.seed(pending).await;
    let error = match ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), store.clone())
        .await
    {
        Ok(_) => panic!("unavailable recovery must fence startup"),
        Err(error) => error,
    };
    assert_eq!(error.code, code);
    let alarms = error.alarm_manager().unwrap().active_alarms();
    assert_eq!(alarms.len(), 1);
    assert_eq!(
        alarms[0].probable_cause,
        if code == StoreErrorCode::Crypto {
            ProbableCause::StorageCorruption
        } else {
            ProbableCause::ConfigApplyFailed
        }
    );
    let history = store.inner.history().await;
    assert_eq!(history.len(), if stage == "clear" { 3 } else { 2 });
    if stage == "clear" {
        assert!(history.last().unwrap().recovery_required);
    }
}
#[tokio::test]
async fn unavailable_startup_rollback_read_keeps_provider_alarm() {
    startup_rollback_failure("rollback").await;
}
#[tokio::test]
async fn unavailable_startup_rollback_append_keeps_provider_alarm() {
    startup_rollback_failure("append").await;
}
#[tokio::test]
async fn unavailable_startup_rollback_clear_keeps_provider_alarm() {
    startup_rollback_failure("clear").await;
}

async fn commit_read_failure(stage: &'static str) {
    commit_read_failure_code(stage, StoreErrorCode::Unavailable).await;
}
async fn startup_rollback_failure(stage: &'static str) {
    startup_rollback_failure_code(stage, StoreErrorCode::Unavailable).await;
}
#[tokio::test]
async fn corrupt_idempotency_lookup_keeps_storage_alarm() {
    commit_read_failure_code("idempotency", StoreErrorCode::Crypto).await;
}
#[tokio::test]
async fn corrupt_history_floor_keeps_storage_alarm() {
    commit_read_failure_code("floor", StoreErrorCode::Crypto).await;
}
#[tokio::test]
async fn corrupt_startup_rollback_read_keeps_storage_alarm() {
    startup_rollback_failure_code("rollback", StoreErrorCode::Crypto).await;
}
#[tokio::test]
async fn corrupt_startup_rollback_append_keeps_storage_alarm() {
    startup_rollback_failure_code("append", StoreErrorCode::Crypto).await;
}
#[tokio::test]
async fn corrupt_startup_rollback_clear_keeps_storage_alarm() {
    startup_rollback_failure_code("clear", StoreErrorCode::Crypto).await;
}

async fn runtime_failure(stage: &'static str, code: StoreErrorCode) {
    let store = Arc::new(FaultStore {
        inner: MockManagedDatastore::new(),
        stage,
        code,
    });
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), store.clone())
        .await
        .unwrap();
    let result = bus
        .submit(commit_request(
            "next",
            Instant::now() + Duration::from_secs(2),
        ))
        .await;
    let alarms = bus.alarm_manager().active_alarms();
    if stage == "clear" {
        assert!(result.is_ok());
        assert_eq!(bus.load().name, "next");
        assert!(
            store
                .inner
                .history()
                .await
                .last()
                .unwrap()
                .recovery_required
        );
        let fenced = bus
            .submit(commit_request(
                "later",
                Instant::now() + Duration::from_secs(2),
            ))
            .await
            .unwrap_err();
        assert_eq!(fenced.code, CommitErrorCode::RecoveryRequired);
    } else {
        assert_eq!(
            result.unwrap_err().code,
            if stage == "reconcile" {
                CommitErrorCode::OutcomeUnknown
            } else {
                CommitErrorCode::PersistFailed
            }
        );
        assert_eq!(bus.load().name, "initial");
        assert!(store.inner.history().await.is_empty());
    }
    assert_eq!(alarms.len(), 1);
    assert_eq!(
        alarms[0].probable_cause,
        if code == StoreErrorCode::Crypto {
            ProbableCause::StorageCorruption
        } else {
            ProbableCause::ConfigApplyFailed
        }
    );
}
#[tokio::test]
async fn runtime_append_preserves_storage_failure_alarm() {
    for code in [StoreErrorCode::Unavailable, StoreErrorCode::Crypto] {
        runtime_failure("append", code).await;
    }
}
#[tokio::test]
async fn runtime_reconciliation_preserves_storage_failure_alarm() {
    for code in [StoreErrorCode::Unavailable, StoreErrorCode::Crypto] {
        runtime_failure("reconcile", code).await;
    }
}
#[tokio::test]
async fn runtime_marker_clear_preserves_storage_failure_alarm() {
    for code in [StoreErrorCode::Unavailable, StoreErrorCode::Crypto] {
        runtime_failure("clear", code).await;
    }
}
#[tokio::test]
async fn missing_startup_rollback_parent_keeps_critical_fence() {
    let store = Arc::new(MockManagedDatastore::new());
    let mut pending = StoredConfig::new(
        TxId::new(),
        ConfigVersion::new(2),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("pending"),
    );
    pending.parent_tx_id = Some(TxId::new());
    pending.confirmed_deadline = Some(Timestamp::from(time::OffsetDateTime::UNIX_EPOCH));
    store.seed(pending).await;
    let error = match ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), store.clone())
        .await
    {
        Ok(_) => panic!("missing rollback parent must fence startup"),
        Err(error) => error,
    };
    assert_eq!(error.code, StoreErrorCode::RestoreConfirmedDeadline);
    let alarms = error.alarm_manager().unwrap().active_alarms();
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0].severity, Severity::Critical);
    assert_eq!(alarms[0].probable_cause, ProbableCause::ConfigApplyFailed);
    assert_eq!(store.history().await.len(), 1);
}

#[tokio::test]
async fn expiry_marker_clear_preserves_storage_failure_alarm() {
    for code in [StoreErrorCode::Unavailable, StoreErrorCode::Crypto] {
        let store = Arc::new(FaultStore {
            inner: MockManagedDatastore::new(),
            stage: "expiry-clear",
            code,
        });
        store
            .inner
            .seed(StoredConfig::new(
                TxId::new(),
                ConfigVersion::new(1),
                principal(),
                RequestSource::Northbound,
                TestConfig::new("initial"),
            ))
            .await;
        let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), store.clone())
            .await
            .unwrap();
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
                Instant::now() + Duration::from_secs(2),
                Some(TestConfig::new("tentative")),
                vec![changed_path()],
            )
            .with_base_version(bus.version()),
        )
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while bus.alarm_manager().active_alarms().is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(bus.version(), ConfigVersion::new(3));
        assert_eq!(bus.load().name, "initial");
        assert!(
            store
                .inner
                .history()
                .await
                .last()
                .unwrap()
                .recovery_required
        );
        let alarms = bus.alarm_manager().active_alarms();
        assert_eq!(alarms.len(), 1);
        assert_eq!(
            alarms[0].probable_cause,
            if code == StoreErrorCode::Crypto {
                ProbableCause::StorageCorruption
            } else {
                ProbableCause::ConfigApplyFailed
            }
        );
        let fenced = bus
            .submit(
                commit_request("later", Instant::now() + Duration::from_secs(2))
                    .with_base_version(bus.version()),
            )
            .await
            .unwrap_err();
        assert_eq!(fenced.code, CommitErrorCode::RecoveryRequired);
    }
}

impl opc_config_bus::CommittedRevisionSource<TestConfig> for FaultStore {}

#[tokio::test]
async fn startup_latest_and_shadow_reads_preserve_failure_alarm() {
    for stage in ["latest", "committed"] {
        for code in [StoreErrorCode::Unavailable, StoreErrorCode::Crypto] {
            let store = Arc::new(FaultStore {
                inner: MockManagedDatastore::new(),
                stage,
                code,
            });
            let result = if stage == "latest" {
                ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), store.clone()).await
            } else {
                ConfigBus::restore_shadow(store.clone()).await
            };
            let error = match result {
                Ok(_) => panic!("failed reads must fence startup"),
                Err(error) => error,
            };
            assert_eq!(error.code, code);
            let alarms = error.alarm_manager().unwrap().active_alarms();
            assert_eq!(alarms.len(), 1);
            assert_eq!(alarms[0].severity, Severity::Critical);
            assert_eq!(
                alarms[0].probable_cause,
                if code == StoreErrorCode::Crypto {
                    ProbableCause::StorageCorruption
                } else {
                    ProbableCause::ConfigApplyFailed
                }
            );
            assert!(store.inner.history().await.is_empty());
        }
    }
}

async fn pending_fault_bus(
    stage: &'static str,
    code: StoreErrorCode,
    expiry: bool,
) -> (ConfigBus<TestConfig>, Arc<FaultStore>) {
    let store = Arc::new(FaultStore {
        inner: MockManagedDatastore::new(),
        stage,
        code,
    });
    store
        .inner
        .seed(StoredConfig::new(
            TxId::new(),
            ConfigVersion::new(1),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("initial"),
        ))
        .await;
    let bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), store.clone())
        .await
        .unwrap();
    bus.submit(
        CommitRequest::new(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            CommitMode::CommitConfirmed {
                timeout: if expiry {
                    Duration::from_millis(50)
                } else {
                    Duration::from_secs(60)
                },
            },
            Instant::now() + Duration::from_secs(2),
            Some(TestConfig::new("tentative")),
            vec![changed_path()],
        )
        .with_base_version(bus.version()),
    )
    .await
    .unwrap();
    (bus, store)
}

#[tokio::test]
async fn cancel_confirmed_reads_and_append_preserve_failure_alarm() {
    for stage in ["pending-latest", "rollback", "pending-append"] {
        for code in [StoreErrorCode::Unavailable, StoreErrorCode::Crypto] {
            let (bus, store) = pending_fault_bus(stage, code, false).await;
            let error = bus
                .submit(
                    CommitRequest::new(
                        RequestId::new(),
                        principal(),
                        TransportType::Internal,
                        RequestSource::Northbound,
                        ConfigOperation::Replace,
                        CommitMode::CancelConfirmed,
                        Instant::now() + Duration::from_secs(2),
                        None,
                        vec![changed_path()],
                    )
                    .with_base_version(bus.version()),
                )
                .await
                .unwrap_err();
            assert!(matches!(
                error.code,
                CommitErrorCode::RollbackUnavailable
                    | CommitErrorCode::PersistFailed
                    | CommitErrorCode::StateMachineFault
            ));
            assert_eq!(bus.load().name, "tentative");
            assert_eq!(store.inner.history().await.len(), 2);
            let alarms = bus.alarm_manager().active_alarms();
            assert_eq!(alarms.len(), 1);
            assert_eq!(alarms[0].severity, Severity::Major);
            assert_eq!(
                alarms[0].probable_cause,
                if code == StoreErrorCode::Crypto {
                    ProbableCause::StorageCorruption
                } else {
                    ProbableCause::ConfigApplyFailed
                }
            );
        }
    }
}

#[tokio::test]
async fn expiry_latest_parent_and_append_preserve_failure_alarm() {
    for stage in ["pending-latest", "rollback", "pending-append"] {
        for code in [StoreErrorCode::Unavailable, StoreErrorCode::Crypto] {
            let (bus, store) = pending_fault_bus(stage, code, true).await;
            tokio::time::timeout(Duration::from_secs(2), async {
                while bus.alarm_manager().active_alarms().is_empty() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(bus.load().name, "tentative");
            assert_eq!(store.inner.history().await.len(), 2);
            let alarms = bus.alarm_manager().active_alarms();
            assert_eq!(alarms.len(), 1);
            assert_eq!(alarms[0].severity, Severity::Major);
            assert_eq!(
                alarms[0].probable_cause,
                if code == StoreErrorCode::Crypto {
                    ProbableCause::StorageCorruption
                } else {
                    ProbableCause::ConfigApplyFailed
                }
            );
            assert_eq!(
                bus.submit(
                    commit_request("later", Instant::now() + Duration::from_secs(2))
                        .with_base_version(bus.version())
                )
                .await
                .unwrap_err()
                .code,
                CommitErrorCode::RecoveryRequired
            );
        }
    }
}
