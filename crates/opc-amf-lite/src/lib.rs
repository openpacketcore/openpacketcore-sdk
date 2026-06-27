//! Realistic AMF-lite control-plane vertical slice integration proving OpenPacketCore SDK seams.
//!
//! This is an internal integration crate and is not published.

#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Notify, RwLock};

use opc_alarm::{
    AffectedObject, AlarmDetails, AlarmType, ProbableCause, ReadinessImpact, RedactedText,
    Severity, SharedAlarmManager,
};
use opc_config_bus::{
    AuthorizationContext, AuthorizationError, ConfigAuthorizer, ConfigBus, ConfigEvent,
    EncryptingManagedDatastore, ManagedDatastore, SealedConfig, StoreError,
    StoredConfig as BusStoredConfig, SubscriberLagPolicy,
};
use opc_config_model::{
    CommitError, CommitMode, CommitRequest, CommitResult, ConfigError, ConfigOperation,
    IdempotencyKey, OpcConfig, RequestId, RequestSource, RollbackTarget as BusRollbackTarget,
    TransportType, TrustedPrincipal, ValidationContext, ValidationError, YangPath,
};
use opc_key::KmsKeyProvider;
use opc_nacm::{ModuleRegistry, NacmAction, NacmEvaluator, NacmPolicy};
use opc_persist::{AuditRecord, CommitRecord, CommitSource, ConfigStore, RollbackTarget};
use opc_runtime::{
    health::HealthResponse, Builder, Criticality, HealthModel, Readiness, RestartPolicy,
    RuntimeError, RuntimeHandle, RuntimePhase, RuntimeProfile, ShutdownToken, Supervisor, TaskKind,
    TaskName,
};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, EncryptingSessionBackend,
    FencedSessionReplica, Generation, OwnerId, QuorumSessionStore, SessionBackend, SessionKey,
    SessionKeyType, SessionLeaseManager, StateClass, StateType, StoredSessionRecord,
};
use opc_types::{ConfigVersion, NetworkFunctionKind, SchemaDigest, TenantId, Timestamp, TxId};

pub const AMF_SCHEMA_DIGEST: &str =
    "9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef";

/// Typed configuration for the AMF-lite vertical slice.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AmfConfig {
    pub hostname: String,
    pub nrf_endpoint: String,
    pub plmn_id: String,
    pub capacity: u32,
}

impl Default for AmfConfig {
    fn default() -> Self {
        Self {
            hostname: "amf-lite-bootstrap".to_string(),
            nrf_endpoint: "http://nrf.openpacketcore.internal".to_string(),
            plmn_id: "20895".to_string(),
            capacity: 1000,
        }
    }
}

impl OpcConfig for AmfConfig {
    type Delta = String;

    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_str(AMF_SCHEMA_DIGEST).expect("valid amf schema digest")
    }

    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        let mut deltas = Vec::new();
        if self.hostname != previous.hostname {
            deltas.push(format!("replace:/amf/hostname={}", self.hostname));
        }
        if self.nrf_endpoint != previous.nrf_endpoint {
            deltas.push(format!("replace:/amf/nrf-endpoint={}", self.nrf_endpoint));
        }
        if self.plmn_id != previous.plmn_id {
            deltas.push(format!("replace:/amf/plmn-id={}", self.plmn_id));
        }
        if self.capacity != previous.capacity {
            deltas.push(format!("replace:/amf/capacity={}", self.capacity));
        }
        Ok(deltas)
    }

    fn changed_paths(
        &self,
        _previous: &Self,
        deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        deltas
            .iter()
            .map(|delta| {
                let encoded_path = delta.strip_prefix("replace:").ok_or_else(|| {
                    ConfigError::new("changed-path", "unsupported delta operation")
                })?;
                let path = encoded_path
                    .split_once('=')
                    .map(|(path, _)| path)
                    .unwrap_or(encoded_path);
                YangPath::new(path).map_err(|err| ConfigError::new("changed-path", err.message()))
            })
            .collect()
    }

    fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
        let (path, value) = delta
            .strip_prefix("replace:")
            .and_then(|delta| delta.split_once('='))
            .ok_or_else(|| ConfigError::new("delta", "unsupported amf delta encoding"))?;

        match path {
            "/amf/hostname" => self.hostname = value.to_string(),
            "/amf/nrf-endpoint" => self.nrf_endpoint = value.to_string(),
            "/amf/plmn-id" => self.plmn_id = value.to_string(),
            "/amf/capacity" => {
                self.capacity = value
                    .parse()
                    .map_err(|_| ConfigError::new("delta", "invalid capacity value"))?;
            }
            _ => return Err(ConfigError::new("delta", "unknown amf config path")),
        }

        Ok(())
    }

    fn validate_syntax(&self) -> Result<(), ValidationError> {
        if self.hostname.trim().is_empty() {
            return Err(ValidationError::syntax("hostname must not be empty"));
        }
        if self.plmn_id.len() < 5
            || self.plmn_id.len() > 6
            || !self.plmn_id.chars().all(|c| c.is_ascii_digit())
        {
            return Err(ValidationError::syntax("plmn_id must be 5 or 6 digits"));
        }
        Ok(())
    }

    fn validate_semantics(&self, _ctx: &ValidationContext<Self>) -> Result<(), ValidationError> {
        if !self.nrf_endpoint.starts_with("http://") && !self.nrf_endpoint.starts_with("https://") {
            return Err(ValidationError::semantics(
                "nrf_endpoint must use http:// or https:// scheme",
            ));
        }
        Ok(())
    }
}

/// Rich session state for UE Context.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UeSessionContext {
    pub imsi: String,
    pub state: String,
    pub amf_ue_ngap_id: u64,
    pub last_updated: Timestamp,
}

/// Helper to add a std Duration to opc_types::Timestamp
pub fn add_duration(ts: Timestamp, dur: Duration) -> Timestamp {
    let odt = *ts.as_offset_datetime();
    let time_dur = time::Duration::seconds_f64(dur.as_secs_f64());
    Timestamp::from_offset_datetime(odt + time_dur)
}

/// Adapter between `ConfigStore` and `ManagedDatastore` for `SealedConfig<C>`.
pub struct PersistDatastore<C, S: ?Sized> {
    inner: Arc<S>,
    _marker: std::marker::PhantomData<fn() -> C>,
}

impl<C, S: ?Sized> PersistDatastore<C, S> {
    pub fn new(inner: Arc<S>) -> Self {
        Self {
            inner,
            _marker: std::marker::PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<C, S> ManagedDatastore<SealedConfig<C>> for PersistDatastore<C, S>
where
    C: OpcConfig + serde::Serialize + serde::de::DeserializeOwned + Send + Sync + 'static,
    S: ConfigStore + ?Sized + 'static,
{
    async fn load_latest(&self) -> Result<Option<BusStoredConfig<SealedConfig<C>>>, StoreError> {
        match self.inner.load_latest().await {
            Ok(Some(stored)) => {
                let principal = serde_json::from_str(&stored.record.principal)
                    .map_err(|e| StoreError::internal(e.to_string()))?;
                let source = match stored.record.source {
                    CommitSource::Gnmi => RequestSource::Northbound,
                    CommitSource::StartupRestore => RequestSource::StartupRecovery,
                    _ => RequestSource::Internal,
                };
                let mut plaintext_digest = [0u8; 32];
                if stored.record.plaintext_digest.len() == 32 {
                    plaintext_digest.copy_from_slice(&stored.record.plaintext_digest);
                } else {
                    return Err(StoreError::internal("invalid plaintext digest length"));
                }
                Ok(Some(BusStoredConfig {
                    tx_id: stored.record.tx_id,
                    parent_tx_id: stored.record.parent_tx_id,
                    version: stored.record.version,
                    committed_at: stored.record.committed_at,
                    principal,
                    source,
                    schema_digest: stored.record.schema_digest,
                    plaintext_digest: Some(plaintext_digest),
                    config: SealedConfig::new(stored.record.schema_digest),
                    encrypted_blob: stored.record.encrypted_blob,
                    idempotency_key: None,
                    apply_plan: None,
                    request_fingerprint: None,
                    request_id: None,
                    recovery_required: false,
                    confirmed_deadline: stored.record.confirmed_deadline,
                    rollback_label: if stored.record.rollback_point {
                        Some("rollback".to_string())
                    } else {
                        None
                    },
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(StoreError::internal(e.to_string())),
        }
    }

    async fn load_rollback(
        &self,
        target: BusRollbackTarget,
    ) -> Result<BusStoredConfig<SealedConfig<C>>, StoreError> {
        let persist_target = match target {
            BusRollbackTarget::Previous => RollbackTarget::Previous,
            BusRollbackTarget::Version(v) => RollbackTarget::ByVersion(v),
            BusRollbackTarget::TxId(t) => RollbackTarget::ByTxId(t),
            BusRollbackTarget::Label(l) => RollbackTarget::ByLabel(l),
        };
        match self.inner.load_rollback(persist_target).await {
            Ok(stored) => {
                let principal = serde_json::from_str(&stored.record.principal)
                    .map_err(|e| StoreError::internal(e.to_string()))?;
                let source = match stored.record.source {
                    CommitSource::Gnmi => RequestSource::Northbound,
                    CommitSource::StartupRestore => RequestSource::StartupRecovery,
                    _ => RequestSource::Internal,
                };
                let mut plaintext_digest = [0u8; 32];
                if stored.record.plaintext_digest.len() == 32 {
                    plaintext_digest.copy_from_slice(&stored.record.plaintext_digest);
                } else {
                    return Err(StoreError::internal("invalid plaintext digest length"));
                }
                Ok(BusStoredConfig {
                    tx_id: stored.record.tx_id,
                    parent_tx_id: stored.record.parent_tx_id,
                    version: stored.record.version,
                    committed_at: stored.record.committed_at,
                    principal,
                    source,
                    schema_digest: stored.record.schema_digest,
                    plaintext_digest: Some(plaintext_digest),
                    config: SealedConfig::new(stored.record.schema_digest),
                    encrypted_blob: stored.record.encrypted_blob,
                    idempotency_key: None,
                    apply_plan: None,
                    request_fingerprint: None,
                    request_id: None,
                    recovery_required: false,
                    confirmed_deadline: stored.record.confirmed_deadline,
                    rollback_label: if stored.record.rollback_point {
                        Some("rollback".to_string())
                    } else {
                        None
                    },
                })
            }
            Err(e) => Err(StoreError::internal(e.to_string())),
        }
    }

    async fn load_by_idempotency_key(
        &self,
        _idempotency_key: &IdempotencyKey,
    ) -> Result<Option<BusStoredConfig<SealedConfig<C>>>, StoreError> {
        Ok(None)
    }

    async fn append_commit(
        &self,
        commit: BusStoredConfig<SealedConfig<C>>,
    ) -> Result<(), StoreError> {
        let principal_str = serde_json::to_string(&commit.principal)
            .map_err(|e| StoreError::internal(e.to_string()))?;
        let source = match commit.source {
            RequestSource::Northbound => CommitSource::Gnmi,
            RequestSource::StartupRecovery => CommitSource::StartupRestore,
            _ => CommitSource::LocalOperator,
        };

        let record = CommitRecord {
            tx_id: commit.tx_id,
            parent_tx_id: commit.parent_tx_id,
            version: commit.version,
            committed_at: commit.committed_at,
            principal: principal_str,
            source,
            schema_digest: commit.schema_digest,
            plaintext_digest: commit
                .plaintext_digest
                .map(|d| d.to_vec())
                .unwrap_or_default(),
            encrypted_blob: commit.encrypted_blob,
            rollback_point: commit.rollback_label.is_some(),
            confirmed_deadline: commit.confirmed_deadline,
        };

        // Emit audit record
        let audit = vec![AuditRecord {
            tx_id: commit.tx_id,
            sequence: 0,
            yang_path: "/amf".to_string(),
            op_type: opc_persist::AuditOpType::Replace,
            previous_value: None,
            new_value: None,
            redaction_applied: false,
            previous_hash: [0u8; 32],
            entry_hmac: [0u8; 32],
        }];

        self.inner
            .append_commit(record, audit)
            .await
            .map_err(|e| StoreError::internal(e.to_string()))
    }

    async fn clear_recovery_required(&self, _tx_id: TxId) -> Result<(), StoreError> {
        Ok(())
    }

    async fn mark_confirmed(&self, tx_id: TxId) -> Result<(), StoreError> {
        self.inner
            .mark_confirmed(tx_id)
            .await
            .map_err(|e| StoreError::internal(e.to_string()))
    }
}

/// NACM Config Authorizer using `opc-nacm` policies.
pub struct NacmConfigAuthorizer {
    policy: Arc<NacmPolicy>,
    modules: Arc<ModuleRegistry>,
}

impl NacmConfigAuthorizer {
    pub fn new(policy: Arc<NacmPolicy>, modules: Arc<ModuleRegistry>) -> Self {
        Self { policy, modules }
    }
}

#[async_trait::async_trait]
impl ConfigAuthorizer for NacmConfigAuthorizer {
    async fn authorize(&self, ctx: &AuthorizationContext) -> Result<(), AuthorizationError> {
        if ctx.principal.roles.contains(&"guest".to_string()) {
            opc_redaction::metrics::METRICS
                .nacm_eval_deny
                .fetch_add(1, Ordering::Relaxed);
            return Err(AuthorizationError::new(
                "Guest role is blocked from modifying config",
            ));
        }

        let mut evaluator = NacmEvaluator::new();
        let nacm_action = match ctx.operation {
            ConfigOperation::Replace => NacmAction::Replace,
            ConfigOperation::Patch | ConfigOperation::Rollback => NacmAction::Update,
            ConfigOperation::Delete => NacmAction::Delete,
        };

        for path in &ctx.changed_paths {
            let path_str = path.to_string();
            let parsed_path = opc_nacm::YangPath::parse_with_default_module(
                &path_str,
                &self.modules,
                Some("openpacketcore-amf"),
            )
            .map_err(|e| {
                opc_redaction::metrics::METRICS
                    .nacm_eval_error
                    .fetch_add(1, Ordering::Relaxed);
                AuthorizationError::new(e.to_string())
            })?;

            let decision = evaluator.evaluate(&self.policy, &parsed_path, nacm_action);
            if !decision.is_allowed() {
                opc_redaction::metrics::METRICS
                    .nacm_eval_deny
                    .fetch_add(1, Ordering::Relaxed);
                return Err(AuthorizationError::new(format!(
                    "NACM policy denies action {nacm_action:?} on path {path_str}"
                )));
            }
        }

        opc_redaction::metrics::METRICS
            .nacm_eval_allow
            .fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

struct AmfLiteState {
    config: AmfConfig,
    version: ConfigVersion,
    health: HealthModel,
    active_nrf_registration: bool,
}

/// AMF-lite network function orchestrating the entire SDK substrate.
pub struct AmfLite {
    runtime: RuntimeHandle,
    config_bus: ConfigBus<AmfConfig>,
    session_store: QuorumSessionStore,
    alarms: SharedAlarmManager,
    _kms_provider: Arc<KmsKeyProvider>,
    state: Arc<RwLock<AmfLiteState>>,
    state_notify: Arc<Notify>,
    _phase_notify: Arc<Notify>,
    _admin_addr: SocketAddr,
}

impl AmfLite {
    /// Launches the AMF-lite network function.
    #[allow(clippy::too_many_arguments)]
    pub async fn start(
        initial_config: AmfConfig,
        config_store: Arc<dyn ConfigStore>,
        session_replicas: Vec<FencedSessionReplica>,
        kms_endpoint: String,
        auth_token: Option<String>,
        admin_addr: SocketAddr,
        nacm_policy: Arc<NacmPolicy>,
        nacm_modules: Arc<ModuleRegistry>,
    ) -> Result<Self, RuntimeError> {
        let alarms = SharedAlarmManager::default();

        // 1. Keying (KMS Provider)
        let kms_provider = Arc::new(KmsKeyProvider::new(
            kms_endpoint,
            None,
            Duration::from_secs(2),
        ));

        // 2. Config Bus with PersistDatastore and EncryptingManagedDatastore wrapper
        let authorizer = Arc::new(NacmConfigAuthorizer::new(nacm_policy, nacm_modules));
        let raw_datastore = Arc::new(PersistDatastore::new(config_store));
        let encrypting_datastore =
            EncryptingManagedDatastore::new(raw_datastore, kms_provider.clone());

        let config_bus = ConfigBus::restore_or_new_with_alarm_manager(
            initial_config.clone(),
            encrypting_datastore,
            authorizer,
            alarms.clone(),
        )
        .await
        .map_err(|e| RuntimeError::Supervisor(format!("config bus init failed: {e}")))?;

        // 3. Quorum Session Store wrapped in mTLS/KMS encrypting envelope
        let mut wrapped_replicas = Vec::new();
        for rep in session_replicas {
            let encrypting_backend = EncryptingSessionBackend::new(
                rep.inner.clone(),
                kms_provider.clone(),
                "amf-sessions",
            );
            let mut wrapped = FencedSessionReplica::new(rep.id, Arc::new(encrypting_backend));
            wrapped.client_online = rep.client_online.clone();
            wrapped.node_online = rep.node_online.clone();
            wrapped.lag = rep.lag.clone();
            wrapped_replicas.push(wrapped);
        }
        let session_store = QuorumSessionStore::new(wrapped_replicas);

        // 4. Initial state
        let mut health = HealthModel::new();
        health.set_startup_in_progress("AMFInit");
        health.set_config_applied(true);

        let state = Arc::new(RwLock::new(AmfLiteState {
            config: initial_config,
            version: ConfigVersion::INITIAL,
            health,
            active_nrf_registration: false,
        }));

        let state_notify = Arc::new(Notify::new());
        let phase_notify = Arc::new(Notify::new());

        // 5. Build supervisor runtime
        let state_clone = state.clone();
        let state_notify_clone = state_notify.clone();
        let phase_notify_clone = phase_notify.clone();
        let config_bus_clone = config_bus.clone();
        let alarms_clone = alarms.clone();

        let mut profile = RuntimeProfile::production("amf-lite", uuid::Uuid::new_v4());
        profile.budget = Some(opc_runtime::ResourceBudget::default());
        profile.shutdown_grace = Duration::from_millis(50);
        profile.drain_timeout = Duration::from_millis(200);

        let runtime = Builder::new(profile)
            .with_alarm_manager(alarms.clone())
            .with_phase_observer(move |_| phase_notify_clone.notify_waiters())
            .with_init(move |supervisor, shutdown| {
                let supervisor = supervisor.clone();
                let shutdown = shutdown.clone();
                let state = state_clone.clone();
                let state_notify = state_notify_clone.clone();
                let config_bus = config_bus_clone.clone();
                let alarms = alarms_clone.clone();

                Box::pin(async move {
                    // Watcher task
                    spawn_config_watcher(
                        &supervisor,
                        &shutdown,
                        config_bus,
                        state.clone(),
                        state_notify.clone(),
                        alarms.clone(),
                    )
                    .await
                    .expect("watcher spawn failed");

                    // Worker task (NRF Registration mock simulator)
                    spawn_registration_worker(
                        &supervisor,
                        &shutdown,
                        state.clone(),
                        state_notify.clone(),
                    )
                    .await
                    .expect("registration worker spawn failed");

                    // Mark health status ready
                    {
                        let mut st = state.write().await;
                        st.health.set_listeners_bound(true);
                        st.health.set_security_material_valid(true);
                        st.health.set_backends_reachable(true);
                        st.health.set_critical_tasks_healthy(true);
                    }
                })
            })
            .build()
            .await?;

        // 6. Spawn HTTP admin server
        let handle_clone = runtime.clone();
        let auth_token_clone = auth_token.clone();
        tokio::spawn(async move {
            let _ = opc_runtime::admin::start_admin_server(
                handle_clone,
                admin_addr,
                opc_runtime::RuntimeProfile::production("amf-lite", uuid::Uuid::new_v4()).mode,
                auth_token_clone,
            )
            .await;
        });

        let amf = Self {
            runtime,
            config_bus,
            session_store,
            alarms,
            _kms_provider: kms_provider,
            state,
            state_notify,
            _phase_notify: phase_notify,
            _admin_addr: admin_addr,
        };

        // Complete startup
        amf.complete_startup(Duration::from_secs(5)).await?;

        Ok(amf)
    }

    async fn complete_startup(&self, timeout: Duration) -> Result<(), RuntimeError> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let phase = self.runtime.phase().await;
            let readiness = self.runtime.readiness().await;
            if phase == RuntimePhase::Ready && matches!(readiness, Readiness::Ready) {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                self.runtime.shutdown().await;
                return Err(RuntimeError::Supervisor(
                    "AMF-lite startup timeout".to_string(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        {
            let mut st = self.state.write().await;
            st.health.set_startup_complete();
        }
        self.state_notify.notify_waiters();

        Ok(())
    }

    /// Registers a UE Context.
    pub async fn register_ue(
        &self,
        imsi: &str,
        amf_ue_ngap_id: u64,
        lease_ttl: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key = SessionKey {
            tenant: TenantId::new("system")?,
            nf_kind: NetworkFunctionKind::new("amf").unwrap(),
            key_type: SessionKeyType::SubscriberContext,
            stable_id: bytes::Bytes::copy_from_slice(imsi.as_bytes()),
        };

        // Acquire lease (fenced CAS lease)
        let owner = OwnerId::new("amf-lite-1").unwrap();
        let lease = self
            .session_store
            .acquire(&key, owner.clone(), lease_ttl)
            .await
            .inspect_err(|_e| {
                self.alarms.raise(
                    AlarmType::new("amf-lite.session.lease-failure"),
                    Severity::Major,
                    ProbableCause::Other("session-lease-failed".to_string()),
                    AffectedObject::NfInstance {
                        kind: "amf-lite".to_string(),
                        instance: "1".to_string(),
                    },
                    Some("system".to_string()),
                    None,
                    None,
                    RedactedText::new("Failed to acquire session lease for UE context"),
                    AlarmDetails::empty(),
                );
            })?;

        let ctx = UeSessionContext {
            imsi: imsi.to_string(),
            state: "REGISTERED".to_string(),
            amf_ue_ngap_id,
            last_updated: Timestamp::now_utc(),
        };

        let value_bytes = serde_json::to_vec(&ctx)?;
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner,
            fence: lease.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: StateType::new("subscriber-context").unwrap(),
            expires_at: Some(add_duration(Timestamp::now_utc(), lease_ttl)),
            payload: EncryptedSessionPayload::new(value_bytes),
        };

        let cas = CompareAndSet {
            key: key.clone(),
            lease,
            expected_generation: None,
            new_record: record,
        };

        let res = self.session_store.compare_and_set(cas).await?;
        match res {
            CompareAndSetResult::Success => Ok(()),
            CompareAndSetResult::Conflict { .. } => Err("CAS conflict creating UE Context".into()),
        }
    }

    /// Updates UE session state.
    pub async fn update_ue_session(
        &self,
        imsi: &str,
        new_state: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key = SessionKey {
            tenant: TenantId::new("system")?,
            nf_kind: NetworkFunctionKind::new("amf").unwrap(),
            key_type: SessionKeyType::SubscriberContext,
            stable_id: bytes::Bytes::copy_from_slice(imsi.as_bytes()),
        };

        // Load latest UE Context
        let latest = self
            .session_store
            .get(&key)
            .await?
            .ok_or("UE Context not found")?;

        // Extract plaintext payload
        let plaintext_payload = latest.payload.as_bytes().to_vec();

        let mut ctx: UeSessionContext = serde_json::from_slice(&plaintext_payload)?;
        ctx.state = new_state.to_string();
        ctx.last_updated = Timestamp::now_utc();

        // Perform mutation under fence
        let value_bytes = serde_json::to_vec(&ctx)?;

        // Re-acquire lease to mutate under CAS fence
        let lease = self
            .session_store
            .acquire(&key, latest.owner.clone(), Duration::from_secs(5))
            .await?;

        let new_record = StoredSessionRecord {
            key: key.clone(),
            generation: latest.generation.next().ok_or("generation overflow")?,
            owner: latest.owner.clone(),
            fence: lease.fence(),
            state_class: latest.state_class,
            state_type: latest.state_type.clone(),
            expires_at: Some(add_duration(Timestamp::now_utc(), Duration::from_secs(5))),
            payload: EncryptedSessionPayload::new(value_bytes),
        };

        let cas = CompareAndSet {
            key: key.clone(),
            lease,
            expected_generation: Some(latest.generation),
            new_record,
        };

        let res = self.session_store.compare_and_set(cas).await?;
        match res {
            CompareAndSetResult::Success => Ok(()),
            CompareAndSetResult::Conflict { .. } => {
                Err("Fenced CAS replay or stale owner write rejected".into())
            }
        }
    }

    /// Commits a new configuration.
    pub async fn commit_config(
        &self,
        candidate: AmfConfig,
        principal: TrustedPrincipal,
    ) -> Result<CommitResult, CommitError> {
        let current_snapshot = self.config_bus.current_snapshot();
        let current = current_snapshot.config.as_ref();

        let mut paths = Vec::new();
        if current.hostname != candidate.hostname {
            paths.push(YangPath::new("/amf/hostname").unwrap());
        }
        if current.nrf_endpoint != candidate.nrf_endpoint {
            paths.push(YangPath::new("/amf/nrf-endpoint").unwrap());
        }
        if current.plmn_id != candidate.plmn_id {
            paths.push(YangPath::new("/amf/plmn-id").unwrap());
        }
        if current.capacity != candidate.capacity {
            paths.push(YangPath::new("/amf/capacity").unwrap());
        }
        if paths.is_empty() {
            paths.push(YangPath::new("/amf").unwrap());
        }

        let request = CommitRequest::commit(
            RequestId::new(),
            principal,
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            candidate,
            paths,
            Instant::now() + Duration::from_secs(2),
        )
        .with_base_version(current_snapshot.version);

        self.config_bus.submit(request).await
    }

    /// Commits a new configuration with a custom commit mode.
    pub async fn commit_config_with_mode(
        &self,
        candidate: AmfConfig,
        principal: TrustedPrincipal,
        mode: CommitMode,
    ) -> Result<CommitResult, CommitError> {
        let current_snapshot = self.config_bus.current_snapshot();
        let current = current_snapshot.config.as_ref();

        let mut paths = Vec::new();
        if current.hostname != candidate.hostname {
            paths.push(YangPath::new("/amf/hostname").unwrap());
        }
        if current.nrf_endpoint != candidate.nrf_endpoint {
            paths.push(YangPath::new("/amf/nrf-endpoint").unwrap());
        }
        if current.plmn_id != candidate.plmn_id {
            paths.push(YangPath::new("/amf/plmn-id").unwrap());
        }
        if current.capacity != candidate.capacity {
            paths.push(YangPath::new("/amf/capacity").unwrap());
        }
        if paths.is_empty() {
            paths.push(YangPath::new("/amf").unwrap());
        }

        let request = CommitRequest::new(
            RequestId::new(),
            principal,
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            mode,
            Instant::now() + Duration::from_secs(5),
            Some(candidate),
            paths,
        )
        .with_base_version(current_snapshot.version);

        self.config_bus.submit(request).await
    }

    pub fn config_bus(&self) -> &ConfigBus<AmfConfig> {
        &self.config_bus
    }

    pub fn session_store(&self) -> &QuorumSessionStore {
        &self.session_store
    }

    pub fn alarms(&self) -> &SharedAlarmManager {
        &self.alarms
    }

    /// Shuts down the AMF-lite vertical slice.
    pub async fn shutdown(&self) {
        // Stop NRF mock registration
        {
            let mut st = self.state.write().await;
            st.active_nrf_registration = false;
        }
        self.state_notify.notify_waiters();

        self.runtime.shutdown().await;
    }

    pub async fn phase(&self) -> RuntimePhase {
        self.runtime.phase().await
    }

    pub async fn readiness(&self) -> Readiness {
        self.runtime.readiness().await
    }

    pub fn supervisor(&self) -> &Supervisor {
        self.runtime.supervisor()
    }

    pub async fn health(&self) -> Result<HealthResponse, RuntimeError> {
        let phase = self.runtime.phase().await;
        let readiness = self.runtime.readiness().await;

        let st = self.state.read().await;
        let mut alarm_degraded = false;
        for alarm in self.alarms.active_alarms() {
            match alarm.readiness_impact() {
                ReadinessImpact::ForceNotReady => {
                    return Ok(HealthResponse::not_ok_with_details(
                        "active_critical_alarm",
                        &st.health,
                    ));
                }
                ReadinessImpact::DegradedOnly => alarm_degraded = true,
                ReadinessImpact::NoImpact => {}
            }
        }

        if phase >= RuntimePhase::Draining {
            Ok(HealthResponse::not_ok("draining"))
        } else if phase < RuntimePhase::Ready || !st.health.is_startup_complete() {
            Ok(HealthResponse::not_ok("startup_incomplete"))
        } else if alarm_degraded {
            Ok(HealthResponse::degraded_with_details(
                "active_alarm",
                &st.health,
            ))
        } else if matches!(readiness, Readiness::Ready) {
            Ok(HealthResponse::ok_with_details(&st.health))
        } else {
            Ok(HealthResponse::not_ok("unhealthy"))
        }
    }
}

// Helper tasks
async fn spawn_config_watcher(
    supervisor: &Supervisor,
    shutdown: &ShutdownToken,
    config_bus: ConfigBus<AmfConfig>,
    state: Arc<RwLock<AmfLiteState>>,
    state_notify: Arc<Notify>,
    _alarms: SharedAlarmManager,
) -> Result<(), RuntimeError> {
    let shutdown = shutdown.clone();
    supervisor
        .spawn(
            TaskName::new("amf-config-watcher"),
            TaskKind::Watcher,
            Criticality::Degrade,
            RestartPolicy::no_restart(),
            move || {
                let config_bus = config_bus.clone();
                let state = state.clone();
                let state_notify = state_notify.clone();
                let shutdown = shutdown.clone();

                Box::pin(async move {
                    let receiver = config_bus.subscribe(SubscriberLagPolicy::DropOldest, 8);
                    let current = config_bus.current_snapshot();
                    {
                        let mut st = state.write().await;
                        st.config = current.config.as_ref().clone();
                        st.version = current.version;
                    }
                    state_notify.notify_waiters();

                    loop {
                        tokio::select! {
                            _ = shutdown.shutdown_acknowledged() => return Ok(()),
                            event = receiver.recv() => match event {
                                Some(ConfigEvent::Change(change)) => {
                                    {
                                        let mut st = state.write().await;
                                        st.config = change.current.as_ref().clone();
                                        st.version = change.version;
                                        st.health.set_config_applied(true);
                                    }
                                    state_notify.notify_waiters();
                                }
                                Some(ConfigEvent::ResyncRequired { .. }) => {
                                    let snapshot = config_bus.current_snapshot();
                                    {
                                        let mut st = state.write().await;
                                        st.config = snapshot.config.as_ref().clone();
                                        st.version = snapshot.version;
                                    }
                                    state_notify.notify_waiters();
                                }
                                None => return Ok(()),
                            }
                        }
                    }
                })
            },
        )
        .await?;

    Ok(())
}

async fn spawn_registration_worker(
    supervisor: &Supervisor,
    shutdown: &ShutdownToken,
    state: Arc<RwLock<AmfLiteState>>,
    state_notify: Arc<Notify>,
) -> Result<(), RuntimeError> {
    let shutdown = shutdown.clone();
    supervisor
        .spawn(
            TaskName::new("amf-registration-worker"),
            TaskKind::Listener,
            Criticality::BestEffort,
            RestartPolicy::no_restart(),
            move || {
                let state = state.clone();
                let state_notify = state_notify.clone();
                let shutdown = shutdown.clone();

                Box::pin(async move {
                    // Register profile to NRF
                    {
                        let mut st = state.write().await;
                        st.active_nrf_registration = true;
                    }
                    state_notify.notify_waiters();

                    loop {
                        tokio::select! {
                            _ = shutdown.shutdown_acknowledged() => return Ok(()),
                            _ = state_notify.notified() => {
                                // Heartbeat or status change
                            }
                        }
                    }
                })
            },
        )
        .await?;

    Ok(())
}

use std::time::Instant;
