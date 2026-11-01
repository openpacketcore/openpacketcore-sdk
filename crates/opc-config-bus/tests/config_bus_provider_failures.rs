use async_trait::async_trait;
use opc_alarm::ProbableCause;
use opc_types::TxId;
use std::sync::Arc;
use std::time::{Duration, Instant};
mod config_bus_common;
use config_bus_common::*;

struct FaultStore {
    inner: MockManagedDatastore<TestConfig>,
    stage: &'static str,
}
impl FaultStore {
    fn fail(&self, stage: &str) -> Result<(), StoreError> {
        if self.stage == stage {
            Err(StoreError::unavailable("provider unavailable"))
        } else {
            Ok(())
        }
    }
}
#[async_trait]
impl ManagedDatastore<TestConfig> for FaultStore {
    async fn load_latest(&self) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
        self.inner.load_latest().await
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
        self.inner.load_by_request_id(id).await
    }
    async fn retained_history_floor(&self) -> Result<Option<ConfigVersion>, StoreError> {
        self.fail("floor")?;
        Ok(None)
    }
    async fn append_commit_write(&self, write: CommitWrite<TestConfig>) -> Result<(), StoreError> {
        self.fail("append")?;
        self.inner.append_commit_write(write).await
    }
    async fn clear_recovery_required(&self, tx: TxId) -> Result<(), StoreError> {
        self.fail("clear")?;
        self.inner.clear_recovery_required(tx).await
    }
}
async fn commit_read_failure(stage: &'static str) {
    let store = Arc::new(FaultStore {
        inner: MockManagedDatastore::new(),
        stage,
    });
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), store.clone())
        .await
        .unwrap();
    let request = commit_request("next", Instant::now() + Duration::from_secs(2))
        .with_idempotency_key(IdempotencyKey::new("retry").unwrap());
    let error = bus.submit(request).await.unwrap_err();
    assert_eq!(error.code, CommitErrorCode::PersistFailed);
    let alarms = bus.alarm_manager().active_alarms();
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0].probable_cause, ProbableCause::ConfigApplyFailed);
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
async fn startup_rollback_failure(stage: &'static str) {
    let store = Arc::new(FaultStore {
        inner: MockManagedDatastore::new(),
        stage,
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
    assert_eq!(error.code, StoreErrorCode::Unavailable);
    let alarms = error.alarm_manager().unwrap().active_alarms();
    assert_eq!(alarms.len(), 1);
    assert_eq!(alarms[0].probable_cause, ProbableCause::ConfigApplyFailed);
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
