#![allow(dead_code, unused_imports)]

use async_trait::async_trait;
use opc_alarm::{Alarm, AlarmState, ProbableCause, Severity, SharedAlarmManager};
pub use opc_config_bus::{
    ConfigBus, ConfigEvent, ConfigSnapshot, DriftState, ManagedDatastore, MockManagedDatastore,
    StoreError, StoreErrorCode, StoredConfig, SubscriberLagPolicy,
};
pub use opc_config_model::{
    CommitErrorCode, CommitMode, CommitRequest, ConfigError, ConfigOperation, IdempotencyKey,
    OpcConfig, RequestId, RequestSource, RollbackTarget, TransportType, TrustedPrincipal,
    ValidationContext, ValidationError, WorkloadIdentity, YangPath,
};
pub use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp};
pub use std::str::FromStr;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use time::OffsetDateTime;
use tokio::{sync::Notify, time::timeout};

#[derive(Clone)]
pub struct TestConfig {
    pub name: String,
    pub diff_delay: Option<Duration>,
    pub diff_error: Option<&'static str>,
    pub semantic_error: Option<&'static str>,
    pub panic_on_validate: bool,
}

impl TestConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            diff_delay: None,
            diff_error: None,
            semantic_error: None,
            panic_on_validate: false,
        }
    }

    pub fn with_diff_delay(name: impl Into<String>, diff_delay: Duration) -> Self {
        Self {
            name: name.into(),
            diff_delay: Some(diff_delay),
            diff_error: None,
            semantic_error: None,
            panic_on_validate: false,
        }
    }

    pub fn with_diff_error(name: impl Into<String>, diff_error: &'static str) -> Self {
        Self {
            name: name.into(),
            diff_delay: None,
            diff_error: Some(diff_error),
            semantic_error: None,
            panic_on_validate: false,
        }
    }

    pub fn with_semantic_error(name: impl Into<String>, semantic_error: &'static str) -> Self {
        Self {
            name: name.into(),
            diff_delay: None,
            diff_error: None,
            semantic_error: Some(semantic_error),
            panic_on_validate: false,
        }
    }

    pub fn panic_on_validate(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            diff_delay: None,
            diff_error: None,
            semantic_error: None,
            panic_on_validate: true,
        }
    }
}

pub fn changed_paths_from_string_deltas(deltas: &[String]) -> Result<Vec<YangPath>, ConfigError> {
    deltas
        .iter()
        .map(|delta| {
            let encoded_path = delta
                .strip_prefix("replace:")
                .ok_or_else(|| ConfigError::new("changed-path", "unsupported delta operation"))?;
            let path = encoded_path
                .split_once('=')
                .map(|(path, _)| path)
                .unwrap_or(encoded_path);
            YangPath::new(path).map_err(|err| ConfigError::new("changed-path", err.message()))
        })
        .collect()
}

impl OpcConfig for TestConfig {
    type Delta = String;

    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_str("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .expect("digest")
    }

    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        if let Some(delay) = self.diff_delay {
            std::thread::sleep(delay);
        }

        if let Some(diff_error) = self.diff_error {
            return Err(ConfigError::new("diff", diff_error));
        }

        if self.name == previous.name {
            Ok(Vec::new())
        } else {
            Ok(vec![format!("replace:/system/hostname={}", self.name)])
        }
    }

    fn changed_paths(
        &self,
        _previous: &Self,
        deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        changed_paths_from_string_deltas(deltas)
    }

    fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
        self.name = delta;
        Ok(())
    }

    fn validate_syntax(&self) -> Result<(), ValidationError> {
        if self.name.trim().is_empty() {
            Err(ValidationError::syntax("hostname must not be empty"))
        } else {
            Ok(())
        }
    }

    fn validate_semantics(
        &self,
        _ctx: &ValidationContext<TestConfig>,
    ) -> Result<(), ValidationError> {
        if self.panic_on_validate {
            panic!("semantic validator panicked");
        }

        if let Some(semantic_error) = self.semantic_error {
            return Err(ValidationError::semantics(semantic_error));
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct ContextBoundConfig {
    pub name: String,
    pub required_role: Option<&'static str>,
    pub required_transport: Option<TransportType>,
    pub required_source: Option<RequestSource>,
}

impl ContextBoundConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            required_role: None,
            required_transport: None,
            required_source: None,
        }
    }

    pub fn with_authz(
        mut self,
        required_role: &'static str,
        required_transport: TransportType,
        required_source: RequestSource,
    ) -> Self {
        self.required_role = Some(required_role);
        self.required_transport = Some(required_transport);
        self.required_source = Some(required_source);
        self
    }
}

impl OpcConfig for ContextBoundConfig {
    type Delta = String;

    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_str("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .expect("digest")
    }

    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        if self.name == previous.name
            && self.required_role == previous.required_role
            && self.required_transport == previous.required_transport
            && self.required_source == previous.required_source
        {
            Ok(Vec::new())
        } else {
            Ok(vec![format!("replace:/system/hostname={}", self.name)])
        }
    }

    fn changed_paths(
        &self,
        _previous: &Self,
        deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        changed_paths_from_string_deltas(deltas)
    }

    fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
        self.name = delta;
        Ok(())
    }

    fn validate_syntax(&self) -> Result<(), ValidationError> {
        if self.name.trim().is_empty() {
            Err(ValidationError::syntax("hostname must not be empty"))
        } else {
            Ok(())
        }
    }

    fn validate_semantics(
        &self,
        ctx: &ValidationContext<ContextBoundConfig>,
    ) -> Result<(), ValidationError> {
        if let Some(required_role) = self.required_role {
            if !ctx.principal.roles.iter().any(|role| role == required_role) {
                return Err(ValidationError::semantics(
                    "principal lacks required config role",
                ));
            }
        }

        if let Some(required_transport) = self.required_transport {
            if ctx.transport != required_transport {
                return Err(ValidationError::semantics(
                    "transport is not authorized for this config",
                ));
            }
        }

        if let Some(required_source) = self.required_source {
            if ctx.source != required_source {
                return Err(ValidationError::semantics(
                    "source is not authorized for this config",
                ));
            }
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct RequestIdAssertingConfig {
    pub name: String,
    pub expected_request_id: Option<RequestId>,
}

impl RequestIdAssertingConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            expected_request_id: None,
        }
    }

    pub fn expect_request_id(mut self, id: RequestId) -> Self {
        self.expected_request_id = Some(id);
        self
    }
}

impl OpcConfig for RequestIdAssertingConfig {
    type Delta = String;

    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_str("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .expect("digest")
    }

    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        if self.name == previous.name {
            Ok(Vec::new())
        } else {
            Ok(vec![format!("replace:/system/hostname={}", self.name)])
        }
    }

    fn changed_paths(
        &self,
        _previous: &Self,
        deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        changed_paths_from_string_deltas(deltas)
    }

    fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
        self.name = delta;
        Ok(())
    }

    fn validate_syntax(&self) -> Result<(), ValidationError> {
        if self.name.trim().is_empty() {
            Err(ValidationError::syntax("hostname must not be empty"))
        } else {
            Ok(())
        }
    }

    fn validate_semantics(
        &self,
        ctx: &ValidationContext<RequestIdAssertingConfig>,
    ) -> Result<(), ValidationError> {
        if let Some(expected) = self.expected_request_id {
            if ctx.request_id != expected {
                return Err(ValidationError::semantics(
                    "request_id mismatch in restored validation context",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct BaseVersionAssertingConfig {
    pub name: String,
    pub expected_base_version: Option<ConfigVersion>,
}

impl BaseVersionAssertingConfig {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            expected_base_version: None,
        }
    }

    pub fn expect_base_version(mut self, version: ConfigVersion) -> Self {
        self.expected_base_version = Some(version);
        self
    }
}

impl OpcConfig for BaseVersionAssertingConfig {
    type Delta = String;

    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_str("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .expect("digest")
    }

    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        if self.name == previous.name {
            Ok(Vec::new())
        } else {
            Ok(vec![format!("replace:/system/hostname={}", self.name)])
        }
    }

    fn changed_paths(
        &self,
        _previous: &Self,
        deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        changed_paths_from_string_deltas(deltas)
    }

    fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
        self.name = delta;
        Ok(())
    }

    fn validate_syntax(&self) -> Result<(), ValidationError> {
        if self.name.trim().is_empty() {
            Err(ValidationError::syntax("hostname must not be empty"))
        } else {
            Ok(())
        }
    }

    fn validate_semantics(
        &self,
        ctx: &ValidationContext<BaseVersionAssertingConfig>,
    ) -> Result<(), ValidationError> {
        if let Some(expected) = self.expected_base_version {
            if ctx.base_version != expected {
                return Err(ValidationError::semantics(
                    "base_version mismatch in restored validation context",
                ));
            }
        }
        Ok(())
    }
}

pub fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::Internal("system".into()),
        TenantId::new("tenant-a").expect("tenant"),
    )
}

pub fn principal_with_roles(roles: impl IntoIterator<Item = &'static str>) -> TrustedPrincipal {
    principal().with_roles(roles)
}

pub fn principal_with_roles_and_groups(
    roles: impl IntoIterator<Item = &'static str>,
    groups: impl IntoIterator<Item = &'static str>,
) -> TrustedPrincipal {
    principal().with_roles(roles).with_groups(groups)
}

pub fn changed_path() -> YangPath {
    YangPath::new("/system/hostname").expect("path")
}

pub fn domain_path() -> YangPath {
    YangPath::new("/system/domain-name").expect("path")
}

pub fn commit_request(name: &str, deadline: Instant) -> CommitRequest<TestConfig> {
    CommitRequest::commit(
        RequestId::new(),
        principal(),
        TransportType::Internal,
        RequestSource::Northbound,
        ConfigOperation::Replace,
        TestConfig::new(name),
        vec![changed_path()],
        deadline,
    )
}

pub fn single_active_alarm(alarms: &SharedAlarmManager, alarm_type: &str) -> Alarm {
    let active = alarms.active_alarms();
    assert_eq!(active.len(), 1, "expected one active alarm: {active:?}");
    assert_eq!(active[0].alarm_type.as_str(), alarm_type);
    active[0].clone()
}

pub async fn wait_for_single_active_alarm(alarms: &SharedAlarmManager, alarm_type: &str) -> Alarm {
    for _ in 0..50 {
        let active = alarms.active_alarms();
        if active.len() == 1 && active[0].alarm_type.as_str() == alarm_type {
            return active[0].clone();
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    single_active_alarm(alarms, alarm_type)
}

pub fn assert_alarm_details_code(alarm: &Alarm, expected_code: &str) {
    let details = alarm
        .details
        .as_value()
        .expect("config-bus alarm details should be structured");
    assert_eq!(details["component"], "config-bus");
    assert_eq!(details["error_code"], expected_code);
    assert_eq!(details["boundary"], "management-plane");
}

pub struct BlockingStore<C: OpcConfig> {
    pub inner: MockManagedDatastore<C>,
    pub append_count: AtomicUsize,
    pub started: Notify,
    pub release: Notify,
}

impl<C: OpcConfig> BlockingStore<C> {
    pub fn new() -> Self {
        Self {
            inner: MockManagedDatastore::new(),
            append_count: AtomicUsize::new(0),
            started: Notify::new(),
            release: Notify::new(),
        }
    }

    pub async fn wait_until_append_started(&self) {
        self.started.notified().await;
    }

    pub fn release(&self) {
        self.release.notify_one();
    }
}

#[async_trait]
impl<C: OpcConfig> ManagedDatastore<C> for BlockingStore<C> {
    async fn load_latest(&self) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.inner.load_latest().await
    }

    async fn load_rollback(
        &self,
        target: opc_config_model::RollbackTarget,
    ) -> Result<StoredConfig<C>, StoreError> {
        self.inner.load_rollback(target).await
    }

    async fn load_by_idempotency_key(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.inner.load_by_idempotency_key(idempotency_key).await
    }

    async fn append_commit(&self, commit: StoredConfig<C>) -> Result<(), StoreError> {
        if self.append_count.fetch_add(1, Ordering::AcqRel) == 0 {
            self.started.notify_one();
            self.release.notified().await;
        }
        self.inner.append_commit(commit).await
    }

    async fn clear_recovery_required(&self, tx_id: opc_types::TxId) -> Result<(), StoreError> {
        self.inner.clear_recovery_required(tx_id).await
    }

    async fn mark_confirmed(&self, tx_id: opc_types::TxId) -> Result<(), StoreError> {
        self.inner.mark_confirmed(tx_id).await
    }
}

pub struct BlockingAppendFailureStore<C: OpcConfig> {
    pub inner: MockManagedDatastore<C>,
    pub started: Notify,
    pub release: Notify,
}

impl<C: OpcConfig> BlockingAppendFailureStore<C> {
    pub fn new() -> Self {
        Self {
            inner: MockManagedDatastore::new(),
            started: Notify::new(),
            release: Notify::new(),
        }
    }

    pub async fn wait_until_append_started(&self) {
        self.started.notified().await;
    }

    pub fn release(&self) {
        self.release.notify_one();
    }
}

#[async_trait]
impl<C: OpcConfig> ManagedDatastore<C> for BlockingAppendFailureStore<C> {
    async fn load_latest(&self) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.inner.load_latest().await
    }

    async fn load_rollback(
        &self,
        target: opc_config_model::RollbackTarget,
    ) -> Result<StoredConfig<C>, StoreError> {
        self.inner.load_rollback(target).await
    }

    async fn load_by_idempotency_key(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.inner.load_by_idempotency_key(idempotency_key).await
    }

    async fn append_commit(&self, _commit: StoredConfig<C>) -> Result<(), StoreError> {
        self.started.notify_one();
        self.release.notified().await;
        Err(StoreError::internal(
            "dsn=postgres://user:secret@db/internal",
        ))
    }

    async fn clear_recovery_required(&self, tx_id: opc_types::TxId) -> Result<(), StoreError> {
        self.inner.clear_recovery_required(tx_id).await
    }

    async fn mark_confirmed(&self, tx_id: opc_types::TxId) -> Result<(), StoreError> {
        self.inner.mark_confirmed(tx_id).await
    }
}

pub struct BlockingAppendPanicStore<C: OpcConfig> {
    pub inner: MockManagedDatastore<C>,
    pub started: Notify,
    pub release: Notify,
}

impl<C: OpcConfig> BlockingAppendPanicStore<C> {
    pub fn new() -> Self {
        Self {
            inner: MockManagedDatastore::new(),
            started: Notify::new(),
            release: Notify::new(),
        }
    }

    pub async fn wait_until_append_started(&self) {
        self.started.notified().await;
    }

    pub fn release(&self) {
        self.release.notify_one();
    }
}

#[async_trait]
impl<C: OpcConfig> ManagedDatastore<C> for BlockingAppendPanicStore<C> {
    async fn load_latest(&self) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.inner.load_latest().await
    }

    async fn load_rollback(
        &self,
        target: opc_config_model::RollbackTarget,
    ) -> Result<StoredConfig<C>, StoreError> {
        self.inner.load_rollback(target).await
    }

    async fn load_by_idempotency_key(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.inner.load_by_idempotency_key(idempotency_key).await
    }

    async fn append_commit(&self, _commit: StoredConfig<C>) -> Result<(), StoreError> {
        self.started.notify_one();
        self.release.notified().await;
        panic!("panic store append crashed after caller cancellation");
    }

    async fn clear_recovery_required(&self, tx_id: opc_types::TxId) -> Result<(), StoreError> {
        self.inner.clear_recovery_required(tx_id).await
    }

    async fn mark_confirmed(&self, tx_id: opc_types::TxId) -> Result<(), StoreError> {
        self.inner.mark_confirmed(tx_id).await
    }
}

pub struct PostAppendPanicStore<C: OpcConfig> {
    pub inner: MockManagedDatastore<C>,
}

impl<C: OpcConfig> PostAppendPanicStore<C> {
    pub fn new() -> Self {
        Self {
            inner: MockManagedDatastore::new(),
        }
    }

    pub async fn history(&self) -> Vec<StoredConfig<C>> {
        self.inner.history().await
    }
}

#[async_trait]
impl<C: OpcConfig> ManagedDatastore<C> for PostAppendPanicStore<C> {
    async fn load_latest(&self) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.inner.load_latest().await
    }

    async fn load_rollback(
        &self,
        target: opc_config_model::RollbackTarget,
    ) -> Result<StoredConfig<C>, StoreError> {
        self.inner.load_rollback(target).await
    }

    async fn load_by_idempotency_key(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.inner.load_by_idempotency_key(idempotency_key).await
    }

    async fn append_commit(&self, commit: StoredConfig<C>) -> Result<(), StoreError> {
        self.inner.append_commit(commit).await?;
        panic!("panic store append crashed after durable write");
    }

    async fn clear_recovery_required(&self, tx_id: opc_types::TxId) -> Result<(), StoreError> {
        self.inner.clear_recovery_required(tx_id).await
    }

    async fn mark_confirmed(&self, tx_id: opc_types::TxId) -> Result<(), StoreError> {
        self.inner.mark_confirmed(tx_id).await
    }
}

pub struct SlowAppendStore<C: OpcConfig> {
    pub inner: MockManagedDatastore<C>,
    pub delay: Duration,
}

impl<C: OpcConfig> SlowAppendStore<C> {
    pub fn new(delay: Duration) -> Self {
        Self {
            inner: MockManagedDatastore::new(),
            delay,
        }
    }

    pub async fn history(&self) -> Vec<StoredConfig<C>> {
        self.inner.history().await
    }
}

#[async_trait]
impl<C: OpcConfig> ManagedDatastore<C> for SlowAppendStore<C> {
    async fn load_latest(&self) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.inner.load_latest().await
    }

    async fn load_rollback(
        &self,
        target: opc_config_model::RollbackTarget,
    ) -> Result<StoredConfig<C>, StoreError> {
        self.inner.load_rollback(target).await
    }

    async fn load_by_idempotency_key(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<C>>, StoreError> {
        self.inner.load_by_idempotency_key(idempotency_key).await
    }

    async fn append_commit(&self, commit: StoredConfig<C>) -> Result<(), StoreError> {
        tokio::time::sleep(self.delay).await;
        self.inner.append_commit(commit).await
    }

    async fn clear_recovery_required(&self, tx_id: opc_types::TxId) -> Result<(), StoreError> {
        self.inner.clear_recovery_required(tx_id).await
    }

    async fn mark_confirmed(&self, tx_id: opc_types::TxId) -> Result<(), StoreError> {
        self.inner.mark_confirmed(tx_id).await
    }
}

pub struct ErrorStore {
    pub append_error: Option<&'static str>,
    pub clear_recovery_error: Option<&'static str>,
    pub idempotency_lookup_error: Option<&'static str>,
    pub rollback_error: Option<&'static str>,
}

impl ErrorStore {
    pub fn append_fails(message: &'static str) -> Self {
        Self {
            append_error: Some(message),
            clear_recovery_error: None,
            idempotency_lookup_error: None,
            rollback_error: None,
        }
    }

    pub fn clear_recovery_fails(message: &'static str) -> Self {
        Self {
            append_error: None,
            clear_recovery_error: Some(message),
            idempotency_lookup_error: None,
            rollback_error: None,
        }
    }

    pub fn idempotency_lookup_fails(message: &'static str) -> Self {
        Self {
            append_error: None,
            clear_recovery_error: None,
            idempotency_lookup_error: Some(message),
            rollback_error: None,
        }
    }

    pub fn rollback_fails(message: &'static str) -> Self {
        Self {
            append_error: None,
            clear_recovery_error: None,
            idempotency_lookup_error: None,
            rollback_error: Some(message),
        }
    }
}

#[async_trait]
impl ManagedDatastore<TestConfig> for ErrorStore {
    async fn load_latest(&self) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
        Ok(None)
    }

    async fn load_rollback(
        &self,
        _target: opc_config_model::RollbackTarget,
    ) -> Result<StoredConfig<TestConfig>, StoreError> {
        Err(StoreError::internal(
            self.rollback_error.expect("rollback error configured"),
        ))
    }

    async fn load_by_idempotency_key(
        &self,
        _idempotency_key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
        match self.idempotency_lookup_error {
            Some(message) => Err(StoreError::internal(message)),
            None => Ok(None),
        }
    }

    async fn append_commit(&self, _commit: StoredConfig<TestConfig>) -> Result<(), StoreError> {
        match self.append_error {
            Some(message) => Err(StoreError::internal(message)),
            None => Ok(()),
        }
    }

    async fn clear_recovery_required(&self, _tx_id: opc_types::TxId) -> Result<(), StoreError> {
        match self.clear_recovery_error {
            Some(message) => Err(StoreError::internal(message)),
            None => Ok(()),
        }
    }

    async fn mark_confirmed(&self, _tx_id: opc_types::TxId) -> Result<(), StoreError> {
        Ok(())
    }
}

pub struct PanicStore;

#[async_trait]
impl ManagedDatastore<TestConfig> for PanicStore {
    async fn load_latest(&self) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
        Ok(None)
    }

    async fn load_rollback(
        &self,
        _target: opc_config_model::RollbackTarget,
    ) -> Result<StoredConfig<TestConfig>, StoreError> {
        Err(StoreError::not_found("rollback not configured"))
    }

    async fn load_by_idempotency_key(
        &self,
        _idempotency_key: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<TestConfig>>, StoreError> {
        Ok(None)
    }

    async fn append_commit(&self, _commit: StoredConfig<TestConfig>) -> Result<(), StoreError> {
        panic!("panic store append crashed");
    }

    async fn clear_recovery_required(&self, _tx_id: opc_types::TxId) -> Result<(), StoreError> {
        Ok(())
    }

    async fn mark_confirmed(&self, _tx_id: opc_types::TxId) -> Result<(), StoreError> {
        Ok(())
    }
}
