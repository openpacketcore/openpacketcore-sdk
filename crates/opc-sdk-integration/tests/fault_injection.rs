use bytes::Bytes;
use opc_alarm::{ProbableCause, ReadinessImpact, Severity};
use opc_crypto::{decrypt_envelope, encrypt_envelope_with_nonce, CryptoEnvelopeV1, CryptoError};
use opc_evidence::{compute_digest, EvidenceError, Manifest, ManifestEntry};
use opc_key::{ConfigAad, EnvelopeAad, KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_nacm::{
    ModuleRegistry, NacmAction, NacmEffect, NacmEvaluator, NacmPolicy, NacmRule, PolicyVersion,
    YangPath, YangPathPattern,
};
use opc_sdk_integration::ToyNetworkFunction;
use opc_session_store::{
    CompareAndSet, EncryptedSessionPayload, FakeSessionBackend, Generation, SessionBackend,
    SessionKey, SessionKeyType, StateClass, StateType, StoreError as SessionStoreError,
    StoredSessionRecord,
};
use opc_types::{NetworkFunctionKind, SchemaDigest, TenantId, Timestamp, TxId};
use std::{collections::HashMap, str::FromStr, time::Duration};

fn tenant() -> TenantId {
    TenantId::new("tenant-a").expect("tenant id")
}

fn config_aad() -> EnvelopeAad {
    EnvelopeAad::config(
        tenant(),
        9,
        ConfigAad::new(
            TxId::from_str("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa").expect("tx id"),
            Some(TxId::from_str("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb").expect("tx id")),
            Timestamp::from_str("2026-05-28T08:30:00Z").expect("timestamp"),
            "spiffe://core.example/tenant/tenant-a/ns/core/sa/config-writer/nf/amf/instance/amf-01",
            SchemaDigest::from_str(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .expect("schema digest"),
            "running",
        )
        .expect("config aad"),
    )
}

fn provider_with_active_key() -> MemoryKeyProvider {
    let provider = MemoryKeyProvider::new();
    provider
        .insert_active_key(
            KeyId::new("config-key-2026-01").expect("key id"),
            KeyPurpose::Config,
            tenant(),
            Zeroizing::new([0x11; 32]),
        )
        .expect("insert active key");
    provider
}

fn module_registry() -> ModuleRegistry {
    let mut registry = ModuleRegistry::new();
    registry
        .register_module("ietf-interfaces", "if")
        .expect("register interfaces module");
    registry
        .register_module("ietf-system", "sys")
        .expect("register system module");
    registry
}

fn session_key(stable_id: &'static [u8]) -> SessionKey {
    SessionKey {
        tenant: tenant(),
        nf_kind: NetworkFunctionKind::new("amf").expect("nf kind"),
        key_type: SessionKeyType::SubscriberContext,
        stable_id: Bytes::from_static(stable_id),
    }
}

fn session_record(
    key: SessionKey,
    generation: u64,
    owner: &str,
    fence: u64,
) -> StoredSessionRecord {
    StoredSessionRecord {
        key,
        generation: Generation::new(generation),
        owner: owner.parse().expect("owner id"),
        fence: opc_session_store::FenceToken::new(fence),
        state_class: StateClass::AuthoritativeSession,
        state_type: StateType::new("amf-registration-context").expect("state type"),
        expires_at: None,
        payload: EncryptedSessionPayload::new(Bytes::from_static(b"ciphertext")),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn fault_injection_missing_key_fails_closed_without_secret_leak() {
    let provider = provider_with_active_key();
    let aad = config_aad();
    let raw_secret = "subscriber-msisdn-5551234";
    let envelope =
        encrypt_envelope_with_nonce(&provider, &aad, raw_secret.as_bytes(), *b"0123456789ab")
            .await
            .expect("encrypt test payload");

    let mut decoded = CryptoEnvelopeV1::decode(&envelope).expect("decode envelope");
    decoded.key_id = KeyId::new("config-key-2026-missing").expect("missing key id");

    let err = decrypt_envelope(
        &provider,
        &aad,
        &decoded.encode().expect("re-encode envelope"),
    )
    .await
    .expect_err("missing key must fail closed");

    assert_eq!(err, CryptoError::DecryptionFailed);
    assert_eq!(err.to_string(), "envelope decryption failed");
    assert!(!err.to_string().contains(raw_secret));
}

#[test]
fn fault_injection_bad_nacm_rule_returns_typed_error() {
    let registry = module_registry();

    let err = YangPathPattern::parse("/if:interfaces/**/config", &registry)
        .expect_err("invalid NACM rule must be rejected");

    assert_eq!(err.kind(), "yang path");
    assert!(err.message().contains("wildcards are not valid"));
    assert!(!err.to_string().contains("subscriber"));
}

#[test]
fn fault_injection_nacm_denial_is_final_for_matching_rule() {
    let registry = module_registry();
    let path = YangPath::parse("/if:interfaces/interface/config/name", &registry)
        .expect("normalize request path");
    let deny_rule = YangPathPattern::parse("/if:interfaces/interface/config/name", &registry)
        .expect("normalize deny rule");
    let policy = NacmPolicy::builder(PolicyVersion::new(12))
        .add_rule(NacmRule::deny(NacmAction::Read, deny_rule))
        .build();
    let mut evaluator = NacmEvaluator::new();

    let decision = evaluator.evaluate(&policy, &path, NacmAction::Read);

    assert_eq!(decision.effect(), NacmEffect::Deny);
    assert!(!decision.is_allowed());
    assert_eq!(decision.matched_rule_index(), Some(0));
    assert_eq!(decision.policy_version(), PolicyVersion::new(12));
}

#[tokio::test(flavor = "current_thread")]
async fn fault_injection_stale_session_fence_rejects_replay_without_subscriber_leak() {
    let backend = FakeSessionBackend::new();
    let key = session_key(b"imsi-001010123456789");
    let key_debug = format!("{key:?}");

    let lease_a = opc_session_store::SessionLeaseManager::acquire(
        &backend,
        &key,
        "owner-a".parse().expect("owner a"),
        Duration::from_secs(30),
    )
    .await
    .expect("acquire owner a");

    backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: lease_a.clone(),
            expected_generation: None,
            new_record: session_record(
                key.clone(),
                1,
                lease_a.owner().as_str(),
                lease_a.fence().get(),
            ),
        })
        .await
        .expect("initial compare-and-set succeeds");

    let stale_lease = lease_a.clone();
    opc_session_store::SessionLeaseManager::release(&backend, lease_a)
        .await
        .expect("release owner a");
    let _lease_b = opc_session_store::SessionLeaseManager::acquire(
        &backend,
        &key,
        "owner-b".parse().expect("owner b"),
        Duration::from_secs(30),
    )
    .await
    .expect("acquire owner b");

    let err = backend
        .compare_and_set(CompareAndSet {
            key: key.clone(),
            lease: stale_lease.clone(),
            expected_generation: Some(Generation::new(1)),
            new_record: session_record(
                key,
                2,
                stale_lease.owner().as_str(),
                stale_lease.fence().get(),
            ),
        })
        .await
        .expect_err("stale lease must be fenced off");

    assert_eq!(err, SessionStoreError::StaleFence);
    assert_eq!(err.to_string(), "stale fence: current fence is higher");
    assert!(!err.to_string().contains("imsi-001010123456789"));
    assert!(key_debug.contains("[20 bytes]"));
    assert!(!key_debug.contains("imsi-001010123456789"));
}

#[tokio::test(flavor = "current_thread")]
async fn fault_injection_runtime_task_failure_raises_redacted_alarm() {
    let raw_subscriber = "imsi-001010123456789";
    let toy = ToyNetworkFunction::start(Default::default())
        .await
        .expect("toy runtime starts");
    let alarm = toy
        .inject_runtime_task_failure(Duration::from_secs(1))
        .await
        .expect("fatal runtime task failure should raise an alarm through toy nf wiring");

    assert_eq!(alarm.readiness_impact(), ReadinessImpact::ForceNotReady);
    assert_eq!(alarm.severity, Severity::Critical);
    assert_eq!(
        alarm.probable_cause,
        ProbableCause::Other("opc-runtime.task-failure".to_string())
    );
    assert_eq!(
        alarm.alarm_type.as_str(),
        "toy-nf.runtime.task.failure.toy-fault-injected-runtime-task"
    );
    assert_eq!(
        alarm.text.as_str(),
        "Fatal runtime task failure in supervised task toy-fault-injected-runtime-task"
    );
    assert!(!alarm.text.as_str().contains(raw_subscriber));
    let details = alarm
        .details
        .as_value()
        .expect("runtime alarm details are structured");
    assert_eq!(details["runtime_task"], "toy-fault-injected-runtime-task");
    assert_eq!(details["boundary"], "control-plane");

    let history = toy.alarm_history();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].alarm_id, alarm.alarm_id);
    assert!(!serde_json::to_string(&history)
        .expect("serialize alarm history")
        .contains(raw_subscriber));

    let health = toy
        .health()
        .await
        .expect("health snapshot after runtime fault");
    assert_eq!(health.active_alarm_count, 1);
    assert_eq!(health.runtime_readiness, "NotReady");
    assert_eq!(health.response.status, "not_ok");
    assert_eq!(health.response.reason, Some("active_alarm"));
    let details = health
        .response
        .details
        .as_ref()
        .expect("critical runtime-failure alarm should include health details");
    assert_eq!(details.readiness, "NotReady");
    assert!(!details.critical_tasks_healthy);
    assert!(!serde_json::to_string(&health)
        .expect("serialize health snapshot")
        .contains(raw_subscriber));

    toy.shutdown().await;
}

#[test]
fn fault_injection_evidence_tamper_fails_manifest_verification() {
    let manifest = Manifest {
        schema_version: "1.0.0".to_string(),
        sdk_version: "0.1.0".to_string(),
        git_commit: "deadbeef".to_string(),
        artifact_digests: vec![],
        file_digests: vec![ManifestEntry {
            path: "evidence/report.json".to_string(),
            digest: compute_digest(b"original evidence"),
        }],
        signing_identity: "spiffe://core.example/ns/release/sa/evidence-signer".to_string(),
        generation_tool: "opc-evidence".to_string(),
        generation_tool_version: "0.1.0".to_string(),
        generation_timestamp: "2026-05-29T00:00:00Z".to_string(),
        known_incomplete_sections: vec![],
        metadata: HashMap::new(),
    };

    let err = manifest
        .verify_file_digests(&HashMap::from([(
            "evidence/report.json".to_string(),
            compute_digest(b"tampered evidence"),
        )]))
        .expect_err("tampered evidence must fail closed");

    assert_eq!(err, EvidenceError::ManifestTampered);
    assert_eq!(err.to_string(), "manifest tampered: digest mismatch");
    assert!(!err.to_string().contains("subscriber"));
}

// ─────────────────────────────────────────────────────────────────────────────
// GAP-001-005 Storage Fault-Injection Harness and Tests
// ─────────────────────────────────────────────────────────────────────────────

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use opc_alarm::SharedAlarmManager;
use opc_config_bus::{
    ConfigBus, ConfigSnapshot, DriftState, ManagedDatastore, SealedConfig, StoreError, StoredConfig,
};
use opc_config_model::{CommitRequest, RequestId, RequestSource, TransportType, TrustedPrincipal};
use opc_persist::{CommitRecord, ConfigStore, FaultInjectingStore, FaultType, SqliteBackend};
use opc_redaction::metrics::METRICS;

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedMetadata {
    principal: TrustedPrincipal,
    idempotency_key: Option<opc_config_model::IdempotencyKey>,
    request_id: Option<RequestId>,
    request_fingerprint: Option<opc_config_bus::StoredRequestFingerprint>,
    recovery_required: bool,
}

pub struct ConfigStoreAdapter<S> {
    store: S,
    db_path: Option<PathBuf>,
    mock_recovery_required: Arc<std::sync::Mutex<std::collections::HashMap<TxId, bool>>>,
}

impl<S> ConfigStoreAdapter<S> {
    pub fn new(store: S, db_path: Option<PathBuf>) -> Self {
        Self {
            store,
            db_path,
            mock_recovery_required: Arc::new(std::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
        }
    }
}

#[async_trait::async_trait]
impl<S> ManagedDatastore<SealedConfig<opc_sdk_integration::ToyConfig>> for ConfigStoreAdapter<S>
where
    S: ConfigStore,
{
    async fn load_latest(
        &self,
    ) -> Result<Option<StoredConfig<SealedConfig<opc_sdk_integration::ToyConfig>>>, StoreError>
    {
        let loaded = self
            .store
            .load_latest()
            .await
            .map_err(|e| StoreError::internal(e.to_string()))?;
        let Some(stored) = loaded else {
            return Ok(None);
        };
        let meta: PersistedMetadata =
            serde_json::from_str(&stored.record.principal).map_err(|e| {
                StoreError::internal(format!("failed to deserialize principal metadata: {e}"))
            })?;

        let mut recovery_required = meta.recovery_required;
        if let Some(&val) = self
            .mock_recovery_required
            .lock()
            .unwrap()
            .get(&stored.record.tx_id)
        {
            recovery_required = val;
        }

        Ok(Some(StoredConfig {
            tx_id: stored.record.tx_id,
            parent_tx_id: stored.record.parent_tx_id,
            version: stored.record.version,
            committed_at: stored.record.committed_at,
            principal: meta.principal,
            source: match stored.record.source {
                opc_persist::CommitSource::Gnmi => opc_config_model::RequestSource::Northbound,
                opc_persist::CommitSource::Netconf => opc_config_model::RequestSource::Northbound,
                opc_persist::CommitSource::LocalOperator => {
                    opc_config_model::RequestSource::Internal
                }
                opc_persist::CommitSource::StartupRestore => {
                    opc_config_model::RequestSource::StartupRecovery
                }
                opc_persist::CommitSource::Rollback => opc_config_model::RequestSource::Internal,
                opc_persist::CommitSource::CommitConfirmedRestore => {
                    opc_config_model::RequestSource::StartupRecovery
                }
            },
            schema_digest: stored.record.schema_digest,
            plaintext_digest: if stored.record.plaintext_digest.is_empty() {
                None
            } else {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&stored.record.plaintext_digest);
                Some(arr)
            },
            config: SealedConfig::new(stored.record.schema_digest),
            encrypted_blob: stored.record.encrypted_blob,
            idempotency_key: meta.idempotency_key,
            request_fingerprint: meta.request_fingerprint,
            request_id: meta.request_id,
            recovery_required,
            confirmed_deadline: stored.record.confirmed_deadline,
            rollback_label: None,
        }))
    }

    async fn load_rollback(
        &self,
        target: opc_config_model::RollbackTarget,
    ) -> Result<StoredConfig<SealedConfig<opc_sdk_integration::ToyConfig>>, StoreError> {
        let p_target = match target {
            opc_config_model::RollbackTarget::Previous => opc_persist::RollbackTarget::Previous,
            opc_config_model::RollbackTarget::TxId(tx_id) => {
                opc_persist::RollbackTarget::ByTxId(tx_id)
            }
            opc_config_model::RollbackTarget::Version(v) => {
                opc_persist::RollbackTarget::ByVersion(v)
            }
            opc_config_model::RollbackTarget::Label(lbl) => {
                opc_persist::RollbackTarget::ByLabel(lbl)
            }
        };
        let stored = self
            .store
            .load_rollback(p_target)
            .await
            .map_err(|e| StoreError::internal(e.to_string()))?;
        let meta: PersistedMetadata =
            serde_json::from_str(&stored.record.principal).map_err(|e| {
                StoreError::internal(format!("failed to deserialize principal metadata: {e}"))
            })?;

        let mut recovery_required = meta.recovery_required;
        if let Some(&val) = self
            .mock_recovery_required
            .lock()
            .unwrap()
            .get(&stored.record.tx_id)
        {
            recovery_required = val;
        }

        Ok(StoredConfig {
            tx_id: stored.record.tx_id,
            parent_tx_id: stored.record.parent_tx_id,
            version: stored.record.version,
            committed_at: stored.record.committed_at,
            principal: meta.principal,
            source: match stored.record.source {
                opc_persist::CommitSource::Gnmi => opc_config_model::RequestSource::Northbound,
                opc_persist::CommitSource::Netconf => opc_config_model::RequestSource::Northbound,
                opc_persist::CommitSource::LocalOperator => {
                    opc_config_model::RequestSource::Internal
                }
                opc_persist::CommitSource::StartupRestore => {
                    opc_config_model::RequestSource::StartupRecovery
                }
                opc_persist::CommitSource::Rollback => opc_config_model::RequestSource::Internal,
                opc_persist::CommitSource::CommitConfirmedRestore => {
                    opc_config_model::RequestSource::StartupRecovery
                }
            },
            schema_digest: stored.record.schema_digest,
            plaintext_digest: if stored.record.plaintext_digest.is_empty() {
                None
            } else {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&stored.record.plaintext_digest);
                Some(arr)
            },
            config: SealedConfig::new(stored.record.schema_digest),
            encrypted_blob: stored.record.encrypted_blob,
            idempotency_key: meta.idempotency_key,
            request_fingerprint: meta.request_fingerprint,
            request_id: meta.request_id,
            recovery_required,
            confirmed_deadline: stored.record.confirmed_deadline,
            rollback_label: None,
        })
    }

    async fn load_by_idempotency_key(
        &self,
        idempotency_key: &opc_config_model::IdempotencyKey,
    ) -> Result<Option<StoredConfig<SealedConfig<opc_sdk_integration::ToyConfig>>>, StoreError>
    {
        let mut current = self.load_latest().await?;
        while let Some(stored) = current {
            if stored.idempotency_key.as_ref() == Some(idempotency_key) {
                return Ok(Some(stored));
            }
            if let Some(parent_tx) = stored.parent_tx_id {
                current = self
                    .load_rollback(opc_config_model::RollbackTarget::TxId(parent_tx))
                    .await
                    .ok();
            } else {
                break;
            }
        }
        Ok(None)
    }

    async fn append_commit(
        &self,
        commit: StoredConfig<SealedConfig<opc_sdk_integration::ToyConfig>>,
    ) -> Result<(), StoreError> {
        let principal_str = serde_json::to_string(&PersistedMetadata {
            principal: commit.principal,
            idempotency_key: commit.idempotency_key,
            request_id: commit.request_id,
            request_fingerprint: commit.request_fingerprint,
            recovery_required: commit.recovery_required,
        })
        .map_err(|e| StoreError::internal(e.to_string()))?;

        let record = CommitRecord {
            tx_id: commit.tx_id,
            parent_tx_id: commit.parent_tx_id,
            version: commit.version,
            committed_at: commit.committed_at,
            principal: principal_str,
            source: match commit.source {
                opc_config_model::RequestSource::Northbound => opc_persist::CommitSource::Gnmi,
                opc_config_model::RequestSource::StartupRecovery => {
                    opc_persist::CommitSource::StartupRestore
                }
                opc_config_model::RequestSource::Replication => {
                    opc_persist::CommitSource::StartupRestore
                }
                opc_config_model::RequestSource::Internal => {
                    opc_persist::CommitSource::LocalOperator
                }
            },
            schema_digest: commit.schema_digest,
            plaintext_digest: commit
                .plaintext_digest
                .map(|d| d.to_vec())
                .unwrap_or_default(),
            encrypted_blob: commit.encrypted_blob,
            rollback_point: commit.recovery_required,
            confirmed_deadline: commit.confirmed_deadline,
        };

        let audit = vec![];

        self.store
            .append_commit(record, audit)
            .await
            .map_err(|e| StoreError::internal(e.to_string()))
    }

    async fn clear_recovery_required(&self, tx_id: TxId) -> Result<(), StoreError> {
        self.mock_recovery_required
            .lock()
            .unwrap()
            .insert(tx_id, false);
        if let Some(ref path) = self.db_path {
            let conn = rusqlite::Connection::open(path)
                .map_err(|e| StoreError::internal(e.to_string()))?;
            let tx_id_bytes = tx_id.as_uuid().as_bytes().to_vec();
            let principal_str: String = conn
                .query_row(
                    "SELECT principal FROM config_history WHERE tx_id = ?1",
                    [&tx_id_bytes],
                    |row| row.get(0),
                )
                .map_err(|e| StoreError::internal(e.to_string()))?;

            let mut meta: PersistedMetadata = serde_json::from_str(&principal_str)
                .map_err(|e| StoreError::internal(e.to_string()))?;
            meta.recovery_required = false;

            let new_principal_str =
                serde_json::to_string(&meta).map_err(|e| StoreError::internal(e.to_string()))?;

            conn.execute(
                "UPDATE config_history SET principal = ?1 WHERE tx_id = ?2",
                rusqlite::params![new_principal_str, &tx_id_bytes],
            )
            .map_err(|e| StoreError::internal(e.to_string()))?;
        }
        Ok(())
    }

    async fn mark_confirmed(&self, tx_id: TxId) -> Result<(), StoreError> {
        self.store
            .mark_confirmed(tx_id)
            .await
            .map_err(|e| StoreError::internal(e.to_string()))
    }
}

fn test_principal() -> TrustedPrincipal {
    TrustedPrincipal {
        identity: opc_config_model::WorkloadIdentity::User("test-user".to_string()),
        tenant: tenant(),
        roles: vec!["admin".to_string()],
        groups: vec!["admin-group".to_string()],
        auth_strength: opc_config_model::AuthStrength::LocalProcess,
    }
}

fn test_commit_request(
    name: &str,
    deadline: std::time::Instant,
) -> CommitRequest<opc_sdk_integration::ToyConfig> {
    let config = opc_sdk_integration::ToyConfig {
        hostname: name.to_string(),
        ..Default::default()
    };
    CommitRequest::commit(
        RequestId::new(),
        test_principal(),
        TransportType::Internal,
        RequestSource::Northbound,
        opc_config_model::ConfigOperation::Replace,
        config,
        vec![opc_config_model::YangPath::new("/name").unwrap()],
        deadline,
    )
}

fn test_commit_confirmed_request(
    name: &str,
    deadline: std::time::Instant,
    timeout: std::time::Duration,
) -> CommitRequest<opc_sdk_integration::ToyConfig> {
    let config = opc_sdk_integration::ToyConfig {
        hostname: name.to_string(),
        ..Default::default()
    };
    CommitRequest::new(
        RequestId::new(),
        test_principal(),
        TransportType::Internal,
        RequestSource::Northbound,
        opc_config_model::ConfigOperation::Replace,
        opc_config_model::CommitMode::CommitConfirmed { timeout },
        deadline,
        Some(config),
        vec![opc_config_model::YangPath::new("/name").unwrap()],
    )
}

async fn setup_fault_injecting_bus(
    db_path: PathBuf,
    injector: FaultInjectingStore<SqliteBackend>,
    alarms: SharedAlarmManager,
) -> ConfigBus<opc_sdk_integration::ToyConfig> {
    let adapter = ConfigStoreAdapter::new(injector, Some(db_path));
    let provider = Arc::new(provider_with_active_key());
    let encrypting_store =
        opc_config_bus::EncryptingManagedDatastore::new(Arc::new(adapter), provider);
    ConfigBus::new_with_alarm_manager_dev_only(
        opc_sdk_integration::ToyConfig::default(),
        encrypting_store,
        alarms,
    )
    .await
    .expect("startup succeeds")
}

#[tokio::test(flavor = "current_thread")]
async fn test_fault_injection_disk_full_fails_closed() {
    let persist_errors_before = METRICS.persist_error.load(Ordering::Relaxed);

    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("disk_full.db");
    let sqlite = SqliteBackend::open(&db_path, true, 0).await.unwrap();
    let fault_store = FaultInjectingStore::new(sqlite);
    fault_store.enable_fault(FaultType::DiskFull);

    let alarms = SharedAlarmManager::default();
    let bus = setup_fault_injecting_bus(db_path.clone(), fault_store.clone(), alarms.clone()).await;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let req = test_commit_request("disk-full-test", deadline);

    let err = bus.submit(req).await.unwrap_err();

    // Fail closed: no publish, no notify, client gets a redacted error.
    assert!(bus.load().hostname != "disk-full-test");
    assert_eq!(bus.drift_state(), DriftState::InSync);

    // Redacted error check: no secret/sql details
    let err_str = err.to_string();
    assert!(!err_str.contains("secret"));
    assert!(!err_str.contains(".db"));

    // Metric check: use a delta to stay safe under parallel test execution.
    assert!(
        METRICS.persist_error.load(Ordering::Relaxed) > persist_errors_before,
        "persist_error metric did not increment"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_fault_injection_fsync_failure_fails_closed() {
    let persist_errors_before = METRICS.persist_error.load(Ordering::Relaxed);

    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("fsync_fail.db");
    let sqlite = SqliteBackend::open(&db_path, true, 0).await.unwrap();
    let fault_store = FaultInjectingStore::new(sqlite);
    fault_store.enable_fault(FaultType::FsyncFailure);

    let alarms = SharedAlarmManager::default();
    let bus = setup_fault_injecting_bus(db_path.clone(), fault_store.clone(), alarms).await;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let req = test_commit_request("fsync-test", deadline);

    let err = bus.submit(req).await.unwrap_err();

    assert!(bus.load().hostname != "fsync-test");
    let err_str = err.to_string();
    assert!(!err_str.contains("secret"));
    assert!(!err_str.contains(".db"));
    assert!(
        METRICS.persist_error.load(Ordering::Relaxed) > persist_errors_before,
        "persist_error metric did not increment"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_fault_injection_corrupt_database_on_startup() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("corrupt_db.db");
    let sqlite = SqliteBackend::open(&db_path, true, 0).await.unwrap();
    let fault_store = FaultInjectingStore::new(sqlite);
    fault_store.enable_fault(FaultType::CorruptDatabase);

    let adapter = ConfigStoreAdapter::new(fault_store.clone(), Some(db_path.clone()));
    let provider = Arc::new(provider_with_active_key());
    let encrypting_store =
        opc_config_bus::EncryptingManagedDatastore::new(Arc::new(adapter), provider);
    let alarms = SharedAlarmManager::default();

    let err = match ConfigBus::restore_or_new_with_alarm_manager_dev_only(
        opc_sdk_integration::ToyConfig::default(),
        encrypting_store,
        alarms.clone(),
    )
    .await
    {
        Err(e) => e,
        Ok(_) => panic!("expected database corruption startup failure, got Ok"),
    };

    // Assert redacted client-visible error
    let err_str = err.to_string();
    assert!(!err_str.contains("secret"));
    assert!(!err_str.contains("tenant-a-secret"));
    assert!(!err_str.contains(".db"));

    // Assert alarm raised
    let active = alarms.active_alarms();
    assert!(active
        .iter()
        .any(|alarm| alarm.alarm_type.as_str() == "config-bus.startup.failure"));
}

#[tokio::test(flavor = "current_thread")]
async fn test_fault_injection_corrupt_wal_on_startup() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("corrupt_wal.db");
    let sqlite = SqliteBackend::open(&db_path, true, 0).await.unwrap();
    let fault_store = FaultInjectingStore::new(sqlite);
    fault_store.enable_fault(FaultType::CorruptWal);

    let adapter = ConfigStoreAdapter::new(fault_store.clone(), Some(db_path.clone()));
    let provider = Arc::new(provider_with_active_key());
    let encrypting_store =
        opc_config_bus::EncryptingManagedDatastore::new(Arc::new(adapter), provider);
    let alarms = SharedAlarmManager::default();

    let err = match ConfigBus::restore_or_new_with_alarm_manager_dev_only(
        opc_sdk_integration::ToyConfig::default(),
        encrypting_store,
        alarms.clone(),
    )
    .await
    {
        Err(e) => e,
        Ok(_) => panic!("expected WAL corruption startup failure, got Ok"),
    };

    let err_str = err.to_string();
    assert!(!err_str.contains("secret"));
    assert!(!err_str.contains(".db"));

    let active = alarms.active_alarms();
    assert!(active
        .iter()
        .any(|alarm| alarm.alarm_type.as_str() == "config-bus.startup.failure"));
}

#[tokio::test(flavor = "current_thread")]
async fn test_fault_injection_rollback_audit_chain_corruption() {
    let audit_failures_before = METRICS
        .persist_audit_chain_verification_failure
        .load(Ordering::Relaxed);

    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("rollback_audit_corrupt.db");
    let sqlite = SqliteBackend::open(&db_path, true, 0).await.unwrap();
    let fault_store = FaultInjectingStore::new(sqlite);

    let alarms = SharedAlarmManager::default();
    let bus = setup_fault_injecting_bus(db_path.clone(), fault_store.clone(), alarms).await;

    // Commit 1 (confirmed)
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let _commit1 = bus
        .submit(test_commit_request("commit-1", deadline))
        .await
        .unwrap();

    // Commit 2 (pending)
    let req2 = test_commit_request("commit-2", deadline);
    bus.submit(req2).await.unwrap();

    // Enable audit chain corruption fault
    fault_store.enable_fault(FaultType::AuditChainCorruption);

    // Rollback to commit 1
    let err = bus
        .submit(CommitRequest::rollback(
            RequestId::new(),
            test_principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            opc_config_model::RollbackTarget::Previous,
            vec![opc_config_model::YangPath::new("/name").unwrap()],
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        ))
        .await
        .unwrap_err();

    assert!(bus.load().hostname != "commit-1");
    let err_str = err.to_string();
    assert!(!err_str.contains("secret"));

    // Check verification failure metric increments
    assert!(
        METRICS
            .persist_audit_chain_verification_failure
            .load(Ordering::Relaxed)
            > audit_failures_before,
        "persist_audit_chain_verification_failure metric did not increment"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_fault_injection_failed_rollback_load() {
    let rollback_failures_before = METRICS.config_bus_rollback_failure.load(Ordering::Relaxed);

    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("failed_rollback_load.db");
    let sqlite = SqliteBackend::open(&db_path, true, 0).await.unwrap();
    let fault_store = FaultInjectingStore::new(sqlite);

    let alarms = SharedAlarmManager::default();
    let bus = setup_fault_injecting_bus(db_path.clone(), fault_store.clone(), alarms).await;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let _commit1 = bus
        .submit(test_commit_request("commit-1", deadline))
        .await
        .unwrap();

    let req2 = test_commit_request("commit-2", deadline);
    bus.submit(req2).await.unwrap();

    fault_store.enable_fault(FaultType::FailedRollbackLoad);

    let err = bus
        .submit(CommitRequest::rollback(
            RequestId::new(),
            test_principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            opc_config_model::RollbackTarget::Previous,
            vec![opc_config_model::YangPath::new("/name").unwrap()],
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        ))
        .await
        .unwrap_err();

    let err_str = err.to_string();
    assert!(!err_str.contains("secret"));
    assert!(!err_str.contains(".db"));

    assert!(
        METRICS.config_bus_rollback_failure.load(Ordering::Relaxed) > rollback_failures_before,
        "config_bus_rollback_failure metric did not increment"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_fault_injection_mark_confirmed_failure() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("mark_confirmed.db");
    let sqlite = SqliteBackend::open(&db_path, true, 0).await.unwrap();
    let fault_store = FaultInjectingStore::new(sqlite);

    let alarms = SharedAlarmManager::default();
    let bus = setup_fault_injecting_bus(db_path.clone(), fault_store.clone(), alarms).await;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let _commit = bus
        .submit(test_commit_confirmed_request(
            "commit-1",
            deadline,
            std::time::Duration::from_secs(30),
        ))
        .await
        .unwrap();

    fault_store.enable_fault(FaultType::MarkConfirmedFailure);

    let confirm_req = CommitRequest::new(
        RequestId::new(),
        test_principal(),
        TransportType::Internal,
        RequestSource::Northbound,
        opc_config_model::ConfigOperation::Replace,
        opc_config_model::CommitMode::Commit,
        std::time::Instant::now() + std::time::Duration::from_secs(5),
        None,
        vec![opc_config_model::YangPath::new("/name").unwrap()],
    );
    let err = bus.submit(confirm_req).await.unwrap_err();

    let err_str = err.to_string();
    assert!(!err_str.contains("secret"));

    // Failure fences the bus/future writes
    let req2 = test_commit_request("commit-2", deadline);
    let err2 = bus.submit(req2).await.unwrap_err();
    assert_eq!(
        err2.code,
        opc_config_model::CommitErrorCode::RecoveryRequired
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_fault_injection_create_rollback_point_failure() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("create_rollback.db");
    let sqlite = SqliteBackend::open(&db_path, true, 0).await.unwrap();
    let fault_store = FaultInjectingStore::new(sqlite);

    // Direct test on SqliteBackend / FaultInjectingStore for rollback point creation
    let tx_id = TxId::new();
    fault_store.enable_fault(FaultType::CreateRollbackPointFailure);

    let err = fault_store
        .create_rollback_point(tx_id, Some("my-label".to_string()))
        .await
        .unwrap_err();
    let err_str = err.to_string();
    assert!(!err_str.contains("secret"));
}

#[tokio::test(flavor = "current_thread")]
async fn test_fault_injection_recovery_restart_remains_fenced() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("recovery_fence.db");
    let sqlite = SqliteBackend::open(&db_path, true, 0).await.unwrap();
    let fault_store = FaultInjectingStore::new(sqlite);

    let alarms = SharedAlarmManager::default();
    let bus = setup_fault_injecting_bus(db_path.clone(), fault_store.clone(), alarms).await;

    // Commit 1 (confirmed)
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let _commit = bus
        .submit(test_commit_request("commit-1", deadline))
        .await
        .unwrap();

    // Commit 2 (commit-confirmed pending)
    let _commit2 = bus
        .submit(test_commit_confirmed_request(
            "commit-2",
            deadline,
            std::time::Duration::from_secs(30),
        ))
        .await
        .unwrap();

    // Inject MarkConfirmedFailure, then try to confirm, which fails and forces recovery_required = true
    fault_store.enable_fault(FaultType::MarkConfirmedFailure);
    let confirm_req = CommitRequest::new(
        RequestId::new(),
        test_principal(),
        TransportType::Internal,
        RequestSource::Northbound,
        opc_config_model::ConfigOperation::Replace,
        opc_config_model::CommitMode::Commit,
        std::time::Instant::now() + std::time::Duration::from_secs(5),
        None,
        vec![opc_config_model::YangPath::new("/name").unwrap()],
    );
    let _ = bus.submit(confirm_req).await.unwrap_err();

    // Shutdown/drop the bus, then restart it.
    drop(bus);

    fault_store.disable_fault(FaultType::MarkConfirmedFailure);

    let adapter = Arc::new(ConfigStoreAdapter::new(
        fault_store.clone(),
        Some(db_path.clone()),
    ));
    let provider = Arc::new(provider_with_active_key());
    let encrypting_store = Arc::new(opc_config_bus::EncryptingManagedDatastore::new(
        adapter.clone(),
        provider,
    ));
    let alarms2 = SharedAlarmManager::default();
    let err = match ConfigBus::restore_or_new_with_alarm_manager_dev_only(
        opc_sdk_integration::ToyConfig::default(),
        encrypting_store.clone(),
        alarms2.clone(),
    )
    .await
    {
        Ok(_) => panic!("startup must fail when recovery is required"),
        Err(e) => e,
    };

    assert_eq!(
        err.code,
        opc_config_bus::StoreErrorCode::RestoreRecoveryRequired
    );

    // Operator recovery: clear recovery required
    let latest = adapter.load_latest().await.unwrap().unwrap();
    adapter.clear_recovery_required(latest.tx_id).await.unwrap();

    // Now startup must succeed!
    let bus2 = ConfigBus::restore_or_new_with_alarm_manager_dev_only(
        opc_sdk_integration::ToyConfig::default(),
        encrypting_store,
        alarms2.clone(),
    )
    .await
    .expect("startup succeeds after recovery is cleared");

    // The restarted bus must be in-sync
    assert_eq!(bus2.drift_state(), DriftState::InSync);

    // Submitting a write succeeds now
    let _commit3 = bus2
        .submit(test_commit_request("commit-3", deadline))
        .await
        .unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn test_fault_injection_session_store_sqlite_corruption() {
    let temp_dir = tempfile::tempdir().unwrap();
    let db_path = temp_dir.path().join("session_corrupt.db");

    // Write garbage to corrupt the database
    std::fs::write(
        &db_path,
        b"garbage sqlite file header containing secret=sensitive",
    )
    .unwrap();

    // Opening a corrupt db file must fail closed
    let res = opc_session_store::SqliteSessionBackend::open(&db_path);
    assert!(res.is_err());

    let err = match res {
        Err(e) => e,
        Ok(_) => panic!("expected error, got Ok"),
    };
    let err_str = err.to_string();
    // Verify no secret leak
    assert!(!err_str.contains("secret"));
    assert!(!err_str.contains("sensitive"));
    assert!(!err_str.contains(".db"));
}

// ─────────────────────────────────────────────────────────────────────────────
// GAP-008-004 Hung-Task and Memory-Budget Fault Injection Tests
// ─────────────────────────────────────────────────────────────────────────────

use opc_runtime::{
    Builder, Criticality, FakeClock, Readiness, ResourceBudget, RestartPolicy, RuntimeMode,
    RuntimeProfile, TaskKind, TaskName,
};

#[tokio::test(flavor = "current_thread")]
async fn test_fault_injection_task_never_completes_shutdown() {
    let clock = Arc::new(FakeClock::synchronized());
    let alarms = SharedAlarmManager::default();

    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "fault-inj-cnf".to_string(),
        shutdown_grace: Duration::from_secs(2),
        drain_timeout: Duration::from_secs(5),
        budget: Some(ResourceBudget::default()),
        ..Default::default()
    };

    let handle = Builder::new(profile)
        .with_clock(clock.clone())
        .with_alarm_manager(alarms.clone())
        .with_init(|supervisor, _shutdown| {
            Box::pin(async move {
                supervisor
                    .spawn(
                        TaskName::new("hanging-shutdown-task"),
                        TaskKind::ProtocolWorker,
                        Criticality::Fatal,
                        RestartPolicy::no_restart(),
                        || {
                            Box::pin(async {
                                // Ignore cancellation and loop forever
                                loop {
                                    tokio::time::sleep(Duration::from_secs(3600)).await;
                                }
                            })
                        },
                    )
                    .await
                    .unwrap();
            })
        })
        .build()
        .await
        .unwrap();

    let handle_clone = handle.clone();
    let shutdown_future = tokio::spawn(async move {
        handle_clone.shutdown().await;
    });

    // Let the task run and start shutting down.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Advance clock past the drain timeout
    clock.advance(Duration::from_secs(6));

    // Wait for the shutdown to complete (must not hang test execution)
    tokio::time::timeout(Duration::from_secs(5), shutdown_future)
        .await
        .expect("Shutdown did not complete within safety timeout")
        .unwrap();

    // Assert the drain incomplete alarm was raised
    let active_alarms = alarms.active_alarms();
    assert!(
        active_alarms
            .iter()
            .any(|alarm| { alarm.alarm_type.as_str() == "fault-inj-cnf.runtime.drain.incomplete" }),
        "Expected drain incomplete alarm to be raised, active alarms: {active_alarms:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn test_fault_injection_task_stops_making_progress() {
    let clock = Arc::new(FakeClock::synchronized());
    let alarms = SharedAlarmManager::default();

    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "fault-inj-cnf".to_string(),
        shutdown_grace: Duration::from_millis(20),
        drain_timeout: Duration::from_millis(50),
        budget: Some(ResourceBudget::default()),
        ..Default::default()
    };

    let handle = Builder::new(profile)
        .with_clock(clock.clone())
        .with_alarm_manager(alarms.clone())
        .build()
        .await
        .unwrap();

    let supervisor = handle.supervisor();

    // Register & spawn a task with 1-second heartbeat timeout
    let spec = opc_runtime::task::TaskSpec::new(
        "hung-task",
        TaskKind::ProtocolWorker,
        Criticality::Fatal,
        async {
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        },
    )
    .with_restart(RestartPolicy::no_restart());

    let mut spec = spec;
    spec.heartbeat_timeout = Some(Duration::from_secs(1));

    supervisor.spawn_spec(spec).await.unwrap();

    // Yield to allow the background task to start running
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Record initial heartbeat
    supervisor
        .record_heartbeat(&TaskName::new("hung-task"))
        .await;

    // Initially the supervisor health and readiness is fine (Ready)
    assert_eq!(supervisor.readiness().await, Readiness::Ready);

    // Advance fake clock past the 1-second timeout
    clock.advance(Duration::from_millis(1500));

    // Checking readiness triggers heartbeat timeout verification
    let readiness = supervisor.readiness().await;
    assert_eq!(readiness, Readiness::NotReady);

    // Assert task alarm raised (Critical severity, opc-runtime.task-failure cause)
    let active_alarms = alarms.active_alarms();
    assert!(
        active_alarms.iter().any(|alarm| {
            alarm.alarm_type.as_str() == "fault-inj-cnf.runtime.task.failure.hung-task"
                && alarm.severity == Severity::Critical
                && alarm.probable_cause
                    == ProbableCause::Other("opc-runtime.task-failure".to_string())
        }),
        "Expected hung task critical alarm to be raised, active: {active_alarms:?}"
    );

    // Verify task is marked failed in health (it is aborted/not running)
    // Yield to allow the background thread to run task cancellation
    tokio::time::sleep(Duration::from_millis(50)).await;
    let health = supervisor.health().await;
    let task_state = health.task_states.get("hung-task").expect("task state");
    assert!(!task_state.running, "Hung task must be aborted");

    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_fault_injection_restart_loop_exceeds_policy() {
    let clock = Arc::new(FakeClock::synchronized());
    let alarms = SharedAlarmManager::default();

    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "fault-inj-cnf".to_string(),
        shutdown_grace: Duration::from_millis(20),
        drain_timeout: Duration::from_millis(50),
        budget: Some(ResourceBudget::default()),
        ..Default::default()
    };

    let handle = Builder::new(profile)
        .with_clock(clock.clone())
        .with_alarm_manager(alarms.clone())
        .build()
        .await
        .unwrap();

    let supervisor = handle.supervisor();

    // Register & spawn a task that fails immediately on every startup,
    // with max_restarts = 2
    let restart_policy = RestartPolicy {
        max_restarts: 2,
        window_secs: 10,
        base_backoff_ms: 1,
        max_backoff_ms: 5,
        jitter: 0.0,
    };

    supervisor
        .spawn(
            TaskName::new("crash-loop-task"),
            TaskKind::ProtocolWorker,
            Criticality::Degrade,
            restart_policy,
            || {
                Box::pin(async {
                    Err(opc_runtime::task::TaskError::Aborted(
                        "intentional crash".to_string(),
                    ))
                })
            },
        )
        .await
        .unwrap();

    // Let the task run, fail, backoff, retry, and eventually exceed policy
    for _ in 0..15 {
        clock.advance(Duration::from_millis(10));
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Verify task exhausts restart limit and supervisor cancels/shuts down
    let health = supervisor.health().await;
    let task_state = health
        .task_states
        .get("crash-loop-task")
        .expect("task state");
    assert!(!task_state.running);
    assert_eq!(task_state.restart_count, 3);
    assert_eq!(health.degrade_count, 1);

    handle.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn test_fault_injection_memory_budget_pressure() {
    let budget_exhausted_before = METRICS.runtime_budget_exhausted.load(Ordering::Relaxed);

    let alarms = SharedAlarmManager::default();
    let budget = ResourceBudget {
        max_heap_bytes: Some(1024 * 1024), // 1 MiB max
        ..Default::default()
    };

    let profile = RuntimeProfile {
        mode: RuntimeMode::Conformance,
        nf_kind: "fault-inj-cnf".to_string(),
        shutdown_grace: Duration::from_millis(20),
        drain_timeout: Duration::from_millis(50),
        budget: Some(budget),
        ..Default::default()
    };

    let handle = Builder::new(profile)
        .with_alarm_manager(alarms.clone())
        .build()
        .await
        .unwrap();

    let supervisor = handle.supervisor();

    // Spawn a dummy task so the supervisor is not empty
    supervisor
        .spawn(
            TaskName::new("dummy-task"),
            TaskKind::ProtocolWorker,
            Criticality::BestEffort,
            RestartPolicy::no_restart(),
            || {
                Box::pin(async {
                    loop {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                    }
                })
            },
        )
        .await
        .unwrap();

    // Yield to let the dummy task start running
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Initially everything is healthy and ready
    assert_eq!(supervisor.readiness().await, Readiness::Ready);

    // Simulate memory pressure: set usage above max_heap_bytes (e.g. 2 MiB)
    supervisor.memory_limiter().set_usage(2 * 1024 * 1024);

    // Assert aggregate readiness drops to NotReady
    assert_eq!(supervisor.readiness().await, Readiness::NotReady);

    // Assert alarm is raised: Critical severity, Cause: opc-runtime.memory-budget-exceeded
    let active_alarms = alarms.active_alarms();
    assert!(
        active_alarms.iter().any(|alarm| {
            alarm.alarm_type.as_str() == "fault-inj-cnf.runtime.budget.exhausted"
                && alarm.severity == Severity::Critical
                && alarm.probable_cause
                    == ProbableCause::Other("opc-runtime.memory-budget-exceeded".to_string())
        }),
        "Expected memory budget exhausted alarm to be raised, active: {active_alarms:?}"
    );

    // Assert that spawning a new task fails closed due to budget pressure
    let spawn_res = supervisor
        .spawn(
            TaskName::new("new-task-under-pressure"),
            TaskKind::ProtocolWorker,
            Criticality::BestEffort,
            RestartPolicy::no_restart(),
            || Box::pin(async { Ok(()) }),
        )
        .await;

    assert!(
        spawn_res.is_err(),
        "Spawning task under memory pressure must fail"
    );
    let err_str = spawn_res.unwrap_err().to_string();
    assert!(
        err_str.contains("Resource budget limit exceeded: memory pressure"),
        "Wrong error: {err_str}"
    );
    assert_eq!(
        METRICS.runtime_budget_exhausted.load(Ordering::Relaxed),
        budget_exhausted_before + 1,
        "runtime_budget_exhausted metric did not increment exactly once"
    );

    // Verify error is redacted and client-safe (no raw paths/secrets/database details)
    assert!(!err_str.contains("secret"));
    assert!(!err_str.contains("/"));

    handle.shutdown().await;
}
