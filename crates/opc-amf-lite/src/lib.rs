//! Realistic AMF-lite control-plane vertical slice integration proving OpenPacketCore SDK seams.
//!
//! This is an internal integration crate and is not published.

#![forbid(unsafe_code)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::error::Error;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
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
use opc_data_governance::IdentifierType;
use opc_key::{KeyProvider, KeyPurpose, KmsKeyProvider};
use opc_nacm::{ModuleRegistry, NacmAction, NacmEvaluator, NacmPolicy};
use opc_persist::{
    AttestedConfigCommit, AuditRecord, CommitRecord, CommitSource, ConfigStore, RollbackTarget,
};
use opc_redaction::{DigestKey, RedactionLevel, TelcoIdentifier};
use opc_runtime::{
    health::HealthResponse, known_gates, Builder, Criticality, GateImpact, GateStatus, HealthGate,
    HealthModel, Readiness, RestartPolicy, RuntimeError, RuntimeHandle, RuntimePhase,
    RuntimeProfile, ShutdownToken, Supervisor, TaskKind, TaskName,
};
use opc_session_store::{
    CompareAndSet, CompareAndSetResult, EncryptedSessionPayload, EncryptingSessionBackend,
    Generation, OwnerId, QuorumSessionStore, SessionBackend, SessionKey, SessionKeyType,
    SessionLeaseManager, StateClass, StateType, StoredSessionRecord,
};
use opc_testbed::Clock as TestClock;
use opc_types::{ConfigVersion, NetworkFunctionKind, SchemaDigest, TenantId, Timestamp, TxId};

pub const AMF_SCHEMA_DIGEST: &str =
    "9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef";

const AMF_SCHEMA_DIGEST_BYTES: [u8; 32] = [
    0x98, 0x76, 0x54, 0x32, 0x10, 0xab, 0xcd, 0xef, 0x98, 0x76, 0x54, 0x32, 0x10, 0xab, 0xcd, 0xef,
    0x98, 0x76, 0x54, 0x32, 0x10, 0xab, 0xcd, 0xef, 0x98, 0x76, 0x54, 0x32, 0x10, 0xab, 0xcd, 0xef,
];
const AMF_NF_KIND: &str = "amf";
const AMF_OWNER_ID: &str = "amf-lite-1";
const SUBSCRIBER_CONTEXT_STATE_TYPE: &str = "subscriber-context";
const SYSTEM_TENANT: &str = "system";
const SUBSCRIBER_PRIVACY_KEY_DOMAIN: &[u8] = b"opc-amf-lite/subscriber-privacy-key/v1";
const SESSION_STORE_READINESS_TASK: &str = "amf-session-store-readiness";
const SESSION_STORE_READINESS_PROBE_INTERVAL: Duration = Duration::from_secs(1);

type BoxError = Box<dyn Error + Send + Sync>;

fn static_value_error(kind: &'static str, err: impl std::fmt::Display) -> BoxError {
    Box::new(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("invalid static AMF {kind}: {err}"),
    ))
}

fn amf_nf_kind() -> Result<NetworkFunctionKind, BoxError> {
    NetworkFunctionKind::new(AMF_NF_KIND).map_err(|err| static_value_error("NF kind", err))
}

fn amf_owner_id() -> Result<OwnerId, BoxError> {
    OwnerId::new(AMF_OWNER_ID).map_err(|err| static_value_error("owner id", err))
}

fn subscriber_context_state_type() -> Result<StateType, BoxError> {
    StateType::new(SUBSCRIBER_CONTEXT_STATE_TYPE)
        .map_err(|err| static_value_error("session state type", err))
}

fn session_key_from_pseudonym(pseudonym: &str) -> Result<SessionKey, BoxError> {
    Ok(SessionKey {
        tenant: TenantId::new(SYSTEM_TENANT)?,
        nf_kind: amf_nf_kind()?,
        key_type: SessionKeyType::SubscriberContext,
        stable_id: bytes::Bytes::copy_from_slice(pseudonym.as_bytes()),
    })
}

fn amf_yang_path(path: &'static str) -> Result<YangPath, CommitError> {
    YangPath::new(path).map_err(|err| {
        CommitError::state_machine_fault(format!(
            "invalid static AMF YANG path {path}: {}",
            err.message()
        ))
    })
}

fn amf_changed_paths(
    current: &AmfConfig,
    candidate: &AmfConfig,
) -> Result<Vec<YangPath>, CommitError> {
    let mut paths = Vec::new();
    if current.hostname != candidate.hostname {
        paths.push(amf_yang_path("/amf/hostname")?);
    }
    if current.nrf_endpoint != candidate.nrf_endpoint {
        paths.push(amf_yang_path("/amf/nrf-endpoint")?);
    }
    if current.plmn_id != candidate.plmn_id {
        paths.push(amf_yang_path("/amf/plmn-id")?);
    }
    if current.capacity != candidate.capacity {
        paths.push(amf_yang_path("/amf/capacity")?);
    }
    if paths.is_empty() {
        paths.push(amf_yang_path("/amf")?);
    }

    Ok(paths)
}

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
        SchemaDigest::from_bytes(AMF_SCHEMA_DIGEST_BYTES)
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
    pub subscriber_pseudonym: String,
    pub subscriber_identity: String,
    pub state: String,
    pub amf_ue_ngap_id: u64,
    pub last_updated: Timestamp,
}

struct SubscriberPrivacyAlias {
    pseudonym: String,
    redacted_identity: String,
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

        let claim = commit.config.claim_fresh_envelope()?;
        let commit = AttestedConfigCommit::try_new(record, audit, claim)
            .map_err(|error| StoreError::internal(error.to_string()))?;
        self.inner
            .append_attested_commit(commit)
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

struct SystemAmfClock;

impl TestClock for SystemAmfClock {
    fn now(&self) -> Timestamp {
        Timestamp::now_utc()
    }

    fn monotonic(&self) -> Instant {
        Instant::now()
    }
}

/// AMF-lite network function orchestrating the entire SDK substrate.
/// AMF-facing encryption wrapper placed above the Openraft quorum store.
pub type AmfSessionStore = EncryptingSessionBackend<QuorumSessionStore, KmsKeyProvider>;

pub struct AmfLite {
    runtime: RuntimeHandle,
    config_bus: ConfigBus<AmfConfig>,
    session_store: AmfSessionStore,
    alarms: SharedAlarmManager,
    kms_provider: Arc<KmsKeyProvider>,
    clock: Arc<dyn TestClock>,
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
        session_store: QuorumSessionStore,
        kms_endpoint: String,
        auth_token: Option<String>,
        admin_addr: SocketAddr,
        nacm_policy: Arc<NacmPolicy>,
        nacm_modules: Arc<ModuleRegistry>,
    ) -> Result<Self, RuntimeError> {
        Self::start_with_clock(
            initial_config,
            config_store,
            session_store,
            kms_endpoint,
            auth_token,
            admin_addr,
            nacm_policy,
            nacm_modules,
            Arc::new(SystemAmfClock),
        )
        .await
    }

    /// Launches the AMF-lite network function with an injected clock.
    #[allow(clippy::too_many_arguments)]
    pub async fn start_with_clock(
        initial_config: AmfConfig,
        config_store: Arc<dyn ConfigStore>,
        session_store: QuorumSessionStore,
        kms_endpoint: String,
        auth_token: Option<String>,
        admin_addr: SocketAddr,
        nacm_policy: Arc<NacmPolicy>,
        nacm_modules: Arc<ModuleRegistry>,
        clock: Arc<dyn TestClock>,
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

        // 3. Encryption remains above the single Openraft-backed quorum
        // authority. Consensus replication and recovery see envelopes only.
        let readiness_store = session_store.clone();
        let session_store = EncryptingSessionBackend::new(
            Arc::new(session_store),
            kms_provider.clone(),
            "amf-sessions",
        );

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
        let readiness_store_clone = readiness_store.clone();

        let mut profile = RuntimeProfile::production("amf-lite", uuid::Uuid::new_v4());
        profile.budget = Some(opc_runtime::ResourceBudget::default());
        profile.shutdown_grace = Duration::from_millis(50);
        profile.drain_timeout = Duration::from_millis(200);

        let runtime = Builder::new(profile)
            .with_alarm_manager(alarms.clone())
            .with_phase_observer(move |_| phase_notify_clone.notify_waiters())
            .try_with_init(move |supervisor, shutdown| {
                let state = state_clone.clone();
                let state_notify = state_notify_clone.clone();
                let config_bus = config_bus_clone.clone();
                let alarms = alarms_clone.clone();
                let session_store = readiness_store_clone.clone();

                Box::pin(async move {
                    initialize_amf_runtime(
                        supervisor,
                        shutdown,
                        config_bus,
                        session_store,
                        state,
                        state_notify,
                        alarms,
                    )
                    .await
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
            kms_provider,
            clock,
            state,
            state_notify,
            _phase_notify: phase_notify,
            _admin_addr: admin_addr,
        };

        // Complete startup
        amf.complete_startup(Duration::from_secs(5)).await?;

        Ok(amf)
    }

    fn now(&self) -> Timestamp {
        self.clock.now()
    }

    async fn subscriber_privacy_alias(
        &self,
        imsi: &str,
    ) -> Result<SubscriberPrivacyAlias, BoxError> {
        let tenant = TenantId::new(SYSTEM_TENANT)?;
        let key_handle = self
            .kms_provider
            .get_active_key(KeyPurpose::Session, &tenant)
            .await?;
        let digest_key = DigestKey::new(
            key_handle.keyed_digest(SUBSCRIBER_PRIVACY_KEY_DOMAIN, b"subscriber-supi"),
        );
        let digest = opc_privacy::hash_identifier(&digest_key, IdentifierType::Supi, imsi);
        let redacted_identity = TelcoIdentifier::new(IdentifierType::Imsi, imsi)
            .redact(RedactionLevel::Class, None)
            .to_string();

        Ok(SubscriberPrivacyAlias {
            pseudonym: format!("supi-digest:{digest}"),
            redacted_identity,
        })
    }

    /// Derives the backend-visible session key for a subscriber without
    /// exposing the permanent identifier in store keys.
    pub async fn session_key_for_subscriber(&self, imsi: &str) -> Result<SessionKey, BoxError> {
        let alias = self.subscriber_privacy_alias(imsi).await?;
        session_key_from_pseudonym(&alias.pseudonym)
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
    ) -> Result<(), BoxError> {
        let alias = self.subscriber_privacy_alias(imsi).await?;
        let key = session_key_from_pseudonym(&alias.pseudonym)?;

        // Acquire lease (fenced CAS lease)
        let owner = amf_owner_id()?;
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

        let now = self.now();
        let ctx = UeSessionContext {
            subscriber_pseudonym: alias.pseudonym,
            subscriber_identity: alias.redacted_identity,
            state: "REGISTERED".to_string(),
            amf_ue_ngap_id,
            last_updated: now,
        };

        let value_bytes = serde_json::to_vec(&ctx)?;
        let record = StoredSessionRecord {
            key: key.clone(),
            generation: Generation::new(1),
            owner,
            fence: lease.fence(),
            state_class: StateClass::AuthoritativeSession,
            state_type: subscriber_context_state_type()?,
            expires_at: Some(add_duration(now, lease_ttl)),
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
    pub async fn update_ue_session(&self, imsi: &str, new_state: &str) -> Result<(), BoxError> {
        let key = self.session_key_for_subscriber(imsi).await?;

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
        let now = self.now();
        ctx.last_updated = now;

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
            expires_at: Some(add_duration(now, Duration::from_secs(5))),
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
        let paths = amf_changed_paths(current, &candidate)?;

        let request = CommitRequest::commit(
            RequestId::new(),
            principal,
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            candidate,
            paths,
            self.clock.monotonic() + Duration::from_secs(2),
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
        let paths = amf_changed_paths(current, &candidate)?;

        let request = CommitRequest::new(
            RequestId::new(),
            principal,
            TransportType::Internal,
            RequestSource::Northbound,
            ConfigOperation::Replace,
            mode,
            self.clock.monotonic() + Duration::from_secs(5),
            Some(candidate),
            paths,
        )
        .with_base_version(current_snapshot.version);

        self.config_bus.submit(request).await
    }

    pub fn config_bus(&self) -> &ConfigBus<AmfConfig> {
        &self.config_bus
    }

    pub fn session_store(&self) -> &AmfSessionStore {
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
async fn initialize_amf_runtime(
    supervisor: Supervisor,
    shutdown: ShutdownToken,
    config_bus: ConfigBus<AmfConfig>,
    session_store: QuorumSessionStore,
    state: Arc<RwLock<AmfLiteState>>,
    state_notify: Arc<Notify>,
    alarms: SharedAlarmManager,
) -> Result<(), RuntimeError> {
    // Watcher task
    spawn_config_watcher(
        &supervisor,
        &shutdown,
        config_bus,
        state.clone(),
        state_notify.clone(),
        alarms,
    )
    .await?;

    spawn_session_store_readiness(
        &supervisor,
        &shutdown,
        session_store,
        state.clone(),
        state_notify.clone(),
    )
    .await?;

    // Worker task (NRF Registration mock simulator)
    spawn_registration_worker(&supervisor, &shutdown, state.clone(), state_notify.clone()).await?;

    // Mark health status ready
    {
        let mut st = state.write().await;
        st.health.set_listeners_bound(true);
        st.health.set_security_material_valid(true);
        st.health.set_critical_tasks_healthy(true);
    }

    Ok(())
}

async fn spawn_session_store_readiness(
    supervisor: &Supervisor,
    shutdown: &ShutdownToken,
    session_store: QuorumSessionStore,
    state: Arc<RwLock<AmfLiteState>>,
    state_notify: Arc<Notify>,
) -> Result<(), RuntimeError> {
    let task_name = TaskName::new(SESSION_STORE_READINESS_TASK);
    supervisor
        .register(
            task_name.clone(),
            TaskKind::BackgroundSync,
            Criticality::Fatal,
            RestartPolicy::no_restart(),
        )
        .await?;
    supervisor.set_readiness_gated(&task_name, true).await;

    {
        let mut st = state.write().await;
        st.health.set_backends_reachable(false);
        st.health.set_gate(
            HealthGate::new(known_gates::SESSION_STORE, GateImpact::BlocksReadiness)
                .with_status(GateStatus::Unknown)
                .with_message("durable readiness has not been probed"),
        );
    }
    state_notify.notify_waiters();

    let supervisor_for_task = supervisor.clone();
    let shutdown = shutdown.clone();
    supervisor
        .spawn(
            task_name.clone(),
            TaskKind::BackgroundSync,
            Criticality::Fatal,
            RestartPolicy::no_restart(),
            move || {
                let session_store = session_store.clone();
                let state = state.clone();
                let state_notify = state_notify.clone();
                let supervisor = supervisor_for_task.clone();
                let task_name = task_name.clone();
                let shutdown = shutdown.clone();

                Box::pin(async move {
                    loop {
                        let report = tokio::select! {
                            _ = shutdown.shutdown_acknowledged() => return Ok(()),
                            report = session_store.probe_durable_readiness() => report,
                        };
                        let is_ready = report.is_ready();
                        let reason_code = report.reason_code();

                        {
                            let mut st = state.write().await;
                            st.health.set_backends_reachable(is_ready);
                            st.health.set_gate(
                                HealthGate::new(
                                    known_gates::SESSION_STORE,
                                    GateImpact::BlocksReadiness,
                                )
                                .with_status(if is_ready {
                                    GateStatus::Passing
                                } else {
                                    GateStatus::Failing
                                })
                                .with_message(reason_code),
                            );
                        }
                        state_notify.notify_waiters();
                        supervisor.set_task_ready(&task_name, is_ready).await;

                        tokio::select! {
                            _ = shutdown.shutdown_acknowledged() => return Ok(()),
                            _ = tokio::time::sleep(SESSION_STORE_READINESS_PROBE_INTERVAL) => {}
                        }
                    }
                })
            },
        )
        .await?;

    Ok(())
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use opc_config_bus::InMemoryManagedDatastore;
    use opc_session_testkit::ConsensusTestCluster;

    #[test]
    fn schema_digest_bytes_match_public_hex() {
        assert_eq!(
            SchemaDigest::from_bytes(AMF_SCHEMA_DIGEST_BYTES).to_hex(),
            AMF_SCHEMA_DIGEST
        );
    }

    #[tokio::test]
    async fn init_spawn_failure_returns_runtime_error() {
        let alarms = SharedAlarmManager::default();
        let config_bus = ConfigBus::restore_or_new_with_alarm_manager_dev_only(
            AmfConfig::default(),
            Arc::new(InMemoryManagedDatastore::new()),
            alarms.clone(),
        )
        .await
        .expect("config bus initializes");

        let mut health = HealthModel::new();
        health.set_startup_in_progress("AMFInit");
        health.set_config_applied(true);
        let state = Arc::new(RwLock::new(AmfLiteState {
            config: AmfConfig::default(),
            version: ConfigVersion::INITIAL,
            health,
            active_nrf_registration: false,
        }));
        let state_notify = Arc::new(Notify::new());
        let session_cluster = ConsensusTestCluster::start(1).await;
        let session_store = session_cluster.store(0);

        let mut profile = RuntimeProfile::production("amf-lite", uuid::Uuid::new_v4());
        profile.budget = Some(opc_runtime::ResourceBudget {
            max_tasks: 1,
            ..Default::default()
        });
        profile.shutdown_grace = Duration::from_millis(50);
        profile.drain_timeout = Duration::from_millis(200);

        let result = Builder::new(profile)
            .with_alarm_manager(alarms.clone())
            .try_with_init(move |supervisor, shutdown| {
                Box::pin(async move {
                    initialize_amf_runtime(
                        supervisor,
                        shutdown,
                        config_bus,
                        session_store,
                        state,
                        state_notify,
                        alarms,
                    )
                    .await
                })
            })
            .build()
            .await;

        match result {
            Err(RuntimeError::Supervisor(message)) => {
                assert!(
                    message.contains("max tasks limit reached"),
                    "unexpected supervisor error: {message}"
                );
            }
            Err(err) => panic!("expected supervisor budget error, got {err:?}"),
            Ok(handle) => {
                handle.shutdown().await;
                panic!("expected startup to fail when spawn budget is exhausted");
            }
        }
    }

    #[tokio::test]
    async fn durable_session_readiness_tracks_real_openraft_quorum() {
        let alarms = SharedAlarmManager::default();
        let config_bus = ConfigBus::restore_or_new_with_alarm_manager_dev_only(
            AmfConfig::default(),
            Arc::new(InMemoryManagedDatastore::new()),
            alarms.clone(),
        )
        .await
        .expect("config bus initializes");

        let mut health = HealthModel::new();
        health.set_startup_in_progress("AMFInit");
        health.set_config_applied(true);
        let state = Arc::new(RwLock::new(AmfLiteState {
            config: AmfConfig::default(),
            version: ConfigVersion::INITIAL,
            health,
            active_nrf_registration: false,
        }));
        let state_notify = Arc::new(Notify::new());

        let session_cluster = ConsensusTestCluster::start(3).await;
        session_cluster.set_node_online(1, false);
        session_cluster.set_node_online(2, false);
        let session_store = session_cluster.store(0);

        let mut profile = RuntimeProfile::production("amf-lite", uuid::Uuid::new_v4());
        profile.budget = Some(opc_runtime::ResourceBudget::default());
        profile.shutdown_grace = Duration::from_millis(50);
        profile.drain_timeout = Duration::from_millis(200);

        let state_for_init = state.clone();
        let handle = Builder::new(profile)
            .with_alarm_manager(alarms.clone())
            .try_with_init(move |supervisor, shutdown| {
                Box::pin(async move {
                    initialize_amf_runtime(
                        supervisor,
                        shutdown,
                        config_bus,
                        session_store,
                        state_for_init,
                        state_notify,
                        alarms,
                    )
                    .await
                })
            })
            .build()
            .await
            .expect("runtime initializes while durable readiness is pending");

        wait_for_session_gate(&state, GateStatus::Failing).await;
        assert_eq!(handle.phase().await, RuntimePhase::PeerWarmup);
        assert_eq!(handle.readiness().await, Readiness::NotReady);
        {
            let st = state.read().await;
            assert!(!st.health.backends_reachable);
            assert_eq!(st.health.gates.readiness(), Readiness::NotReady);
            let gate_name = opc_runtime::GateName::new(known_gates::SESSION_STORE);
            assert_eq!(
                st.health.gates.get(&gate_name).map(|gate| gate.impact),
                Some(GateImpact::BlocksReadiness)
            );
        }

        let supervisor_health = handle.supervisor().health().await;
        let readiness_task = supervisor_health
            .task_states
            .get(SESSION_STORE_READINESS_TASK)
            .expect("readiness task is supervised");
        assert_eq!(readiness_task.kind, "background-sync");
        assert_eq!(readiness_task.criticality, "fatal");

        session_cluster.set_node_online(1, true);
        session_cluster.set_node_online(2, true);
        wait_for_readiness(&handle, Readiness::Ready).await;
        wait_for_phase(&handle, RuntimePhase::Ready).await;
        wait_for_session_gate(&state, GateStatus::Passing).await;
        assert!(state.read().await.health.backends_reachable);

        session_cluster.set_node_online(1, false);
        session_cluster.set_node_online(2, false);
        wait_for_readiness(&handle, Readiness::NotReady).await;
        wait_for_session_gate(&state, GateStatus::Failing).await;
        assert!(!state.read().await.health.backends_reachable);

        session_cluster.set_node_online(1, true);
        session_cluster.set_node_online(2, true);
        wait_for_readiness(&handle, Readiness::Ready).await;
        wait_for_session_gate(&state, GateStatus::Passing).await;
        assert!(state.read().await.health.backends_reachable);

        handle.shutdown().await;
    }

    async fn wait_for_readiness(handle: &RuntimeHandle, expected: Readiness) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            if handle.readiness().await == expected {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for runtime readiness {expected:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn wait_for_phase(handle: &RuntimeHandle, expected: RuntimePhase) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            if handle.phase().await == expected {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for runtime phase {expected:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn wait_for_session_gate(state: &Arc<RwLock<AmfLiteState>>, expected: GateStatus) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        let gate_name = opc_runtime::GateName::new(known_gates::SESSION_STORE);
        loop {
            let status = state
                .read()
                .await
                .health
                .gates
                .get(&gate_name)
                .map(|gate| gate.status);
            if status == Some(expected) {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for session-store gate {expected:?}; observed {status:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}
