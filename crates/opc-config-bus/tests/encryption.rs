use opc_config_bus::{
    ConfigBus, ConfigSnapshot, EncryptingManagedDatastore, ManagedDatastore, MockManagedDatastore,
    SealedConfig, StoreErrorCode, StoredConfig,
};
use opc_config_model::{
    CommitRequest, CommitStatus, ConfigError, ConfigOperation, IdempotencyKey, OpcConfig,
    RequestId, RequestSource, RollbackTarget, TransportType, TrustedPrincipal, ValidationContext,
    ValidationError, WorkloadIdentity, YangPath,
};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, TxId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Serialize, Deserialize)]
struct TestConfig {
    name: String,
}

impl TestConfig {
    fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

fn changed_paths_from_string_deltas(deltas: &[String]) -> Result<Vec<YangPath>, ConfigError> {
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
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct MismatchedSchemaConfig {
    name: String,
}

impl OpcConfig for MismatchedSchemaConfig {
    type Delta = String;

    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
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
        Ok(())
    }

    fn validate_semantics(
        &self,
        _ctx: &ValidationContext<MismatchedSchemaConfig>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }
}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").expect("tenant")
}

fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(WorkloadIdentity::Internal("config-writer".into()), tenant())
}

fn test_provider() -> Arc<MemoryKeyProvider> {
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("config-active-2026-01").expect("key id"),
            KeyPurpose::Config,
            tenant(),
            Zeroizing::new([0x11; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("insert key");
    provider
}

async fn submit_commit(bus: &ConfigBus<TestConfig>, name: &str) -> opc_config_model::CommitResult {
    bus.submit(CommitRequest::commit(
        RequestId::new(),
        principal(),
        TransportType::Internal,
        RequestSource::Northbound,
        ConfigOperation::Replace,
        TestConfig::new(name),
        vec![YangPath::new("/system/hostname").expect("path")],
        Instant::now() + Duration::from_secs(1),
    ))
    .await
    .expect("commit")
}

#[tokio::test]
async fn encrypting_store_binds_parent_tx_id_and_rolls_back_via_decrypted_checkpoint() {
    let inner = Arc::new(MockManagedDatastore::new());
    let provider = test_provider();
    let store = EncryptingManagedDatastore::new(Arc::clone(&inner), Arc::clone(&provider));
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), store)
        .await
        .expect("bus");

    let first = submit_commit(&bus, "first").await;
    let second = submit_commit(&bus, "second").await;

    let history = inner.history().await;
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].parent_tx_id, None);
    assert_eq!(history[1].parent_tx_id, Some(first.tx_id));
    assert!(!history[0].encrypted_blob.is_empty());
    assert!(!history[1].encrypted_blob.is_empty());
    let sealed: &SealedConfig<TestConfig> = &history[0].config;
    assert_eq!(
        sealed.schema_digest(),
        TestConfig::new("first").schema_digest()
    );
    assert_ne!(
        history[0].encrypted_blob,
        serde_json::to_vec(&TestConfig::new("first")).expect("plaintext json")
    );

    let rollback = bus
        .submit(CommitRequest::rollback(
            RequestId::new(),
            principal(),
            TransportType::Internal,
            RequestSource::Northbound,
            RollbackTarget::TxId(first.tx_id),
            Vec::new(),
            Instant::now() + Duration::from_secs(1),
        ))
        .await
        .expect("rollback");

    assert_eq!(rollback.status, CommitStatus::RollbackApplied);
    assert_eq!(bus.load().name, "first");

    let history = inner.history().await;
    let latest = history.last().expect("rollback record");
    assert_eq!(latest.parent_tx_id, Some(second.tx_id));
    assert!(!latest.encrypted_blob.is_empty());
}

#[tokio::test]
async fn encrypted_latest_restores_and_preserves_parent_tx_id_on_next_commit() {
    let inner = Arc::new(MockManagedDatastore::new());
    let provider = test_provider();
    let store = EncryptingManagedDatastore::new(Arc::clone(&inner), Arc::clone(&provider));
    let bus = ConfigBus::new_dev_only(TestConfig::new("initial"), store)
        .await
        .expect("bus");

    let first = submit_commit(&bus, "first").await;
    drop(bus);

    let restored_store = EncryptingManagedDatastore::new(Arc::clone(&inner), Arc::clone(&provider));
    let restored = ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), restored_store)
        .await
        .expect("restored bus");

    assert_eq!(restored.load().name, "first");
    assert_eq!(restored.current_snapshot().tx_id, Some(first.tx_id));

    let second = submit_commit(&restored, "second").await;
    let history = inner.history().await;
    let latest = history.last().expect("second record");
    assert_eq!(latest.tx_id, second.tx_id);
    assert_eq!(latest.parent_tx_id, Some(first.tx_id));
    assert!(!latest.encrypted_blob.is_empty());
}

#[tokio::test]
async fn encrypted_idempotency_lookup_returns_decrypted_record() {
    let inner = Arc::new(MockManagedDatastore::new());
    let provider = test_provider();
    let store = EncryptingManagedDatastore::new(Arc::clone(&inner), Arc::clone(&provider));
    let idempotency_key = IdempotencyKey::new("commit-idempotency-key").expect("idempotency key");

    let mut record = StoredConfig::new(
        TxId::new(),
        ConfigVersion::new(1),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("idempotent"),
    );
    record.idempotency_key = Some(idempotency_key.clone());
    store.append_commit(record).await.expect("encrypted append");

    let stored = inner
        .history()
        .await
        .into_iter()
        .next()
        .expect("stored record");
    let sealed: &SealedConfig<TestConfig> = &stored.config;
    assert_eq!(
        sealed.schema_digest(),
        TestConfig::new("idempotent").schema_digest()
    );
    assert_ne!(
        stored.encrypted_blob,
        serde_json::to_vec(&TestConfig::new("idempotent")).expect("plaintext json")
    );

    let loaded = store
        .load_by_idempotency_key(&idempotency_key)
        .await
        .expect("load by idempotency key")
        .expect("record");
    assert_eq!(loaded.config.name, "idempotent");
    assert_eq!(loaded.idempotency_key, Some(idempotency_key));

    let stored_digest = stored.plaintext_digest.expect("plaintext digest");
    let expected_digest: [u8; 32] =
        Sha256::digest(serde_json::to_vec(&TestConfig::new("idempotent")).expect("json")).into();
    assert_eq!(stored_digest, expected_digest);
}

#[tokio::test]
async fn encrypting_store_append_commit_reports_missing_key() {
    let inner = Arc::new(MockManagedDatastore::new());
    let provider = Arc::new(MemoryKeyProvider::new());
    let store = EncryptingManagedDatastore::new(inner, provider);

    let err = store
        .append_commit(StoredConfig::new(
            TxId::new(),
            ConfigVersion::new(1),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("missing-key"),
        ))
        .await
        .expect_err("append must fail without a config key");

    assert_eq!(err.code, StoreErrorCode::Crypto);
    assert_eq!(err.message, "config envelope encryption failed");
}

#[tokio::test]
async fn legacy_plaintext_config_records_restore_and_reseal_on_next_commit() {
    let inner = Arc::new(MockManagedDatastore::new());
    let provider = test_provider();
    let legacy_tx_id = TxId::new();
    let idempotency_key = IdempotencyKey::new("legacy-config-key").expect("idempotency key");
    let mut legacy = StoredConfig::new(
        legacy_tx_id,
        ConfigVersion::new(1),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("legacy"),
    );
    legacy.idempotency_key = Some(idempotency_key.clone());
    legacy.rollback_label = Some("legacy-label".into());
    inner
        .seed(legacy.with_config(SealedConfig::legacy_plaintext(TestConfig::new("legacy"))))
        .await;

    let store = EncryptingManagedDatastore::new(Arc::clone(&inner), Arc::clone(&provider));
    let latest = store
        .load_latest()
        .await
        .expect("legacy latest")
        .expect("latest record");
    assert_eq!(latest.config.name, "legacy");

    let rollback = store
        .load_rollback(RollbackTarget::Label("legacy-label".into()))
        .await
        .expect("legacy rollback");
    assert_eq!(rollback.config.name, "legacy");

    let idempotent = store
        .load_by_idempotency_key(&idempotency_key)
        .await
        .expect("legacy idempotency")
        .expect("idempotent record");
    assert_eq!(idempotent.config.name, "legacy");

    let restored = ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), store)
        .await
        .expect("restored bus");
    assert_eq!(restored.load().name, "legacy");
    assert_eq!(restored.current_snapshot().tx_id, Some(legacy_tx_id));

    let next = submit_commit(&restored, "post-upgrade").await;
    let history = inner.history().await;
    let latest = history.last().expect("post-upgrade record");
    assert_eq!(latest.tx_id, next.tx_id);
    assert_eq!(latest.parent_tx_id, Some(legacy_tx_id));
    assert!(!latest.encrypted_blob.is_empty());
    assert!(latest.config.legacy_plaintext_config().is_none());
}

#[tokio::test]
async fn encrypted_schema_mismatch_uses_restore_error_code() {
    let inner = Arc::new(MockManagedDatastore::new());
    let provider = test_provider();
    let writer = EncryptingManagedDatastore::<TestConfig, _, _>::new(
        Arc::clone(&inner),
        Arc::clone(&provider),
    );

    writer
        .append_commit(StoredConfig::new(
            TxId::new(),
            ConfigVersion::new(1),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("schema-bound"),
        ))
        .await
        .expect("encrypted append");

    let stored = inner
        .history()
        .await
        .into_iter()
        .next()
        .expect("stored record");
    let schema_digest = stored.schema_digest;
    let mismatched_record =
        stored.with_config(SealedConfig::<MismatchedSchemaConfig>::new(schema_digest));
    let mismatched_inner = Arc::new(MockManagedDatastore::new());
    mismatched_inner.seed(mismatched_record).await;
    let reader =
        EncryptingManagedDatastore::<MismatchedSchemaConfig, _, _>::new(mismatched_inner, provider);

    let err = match reader.load_latest().await {
        Ok(_) => panic!("schema mismatch must fail"),
        Err(err) => err,
    };
    assert_eq!(err.code, StoreErrorCode::RestoreSchemaMismatch);
    assert_eq!(err.message, "stored running config schema digest mismatch");
}

#[tokio::test]
async fn encrypted_plaintext_digest_mismatch_fails_closed() {
    let inner = Arc::new(MockManagedDatastore::new());
    let provider = test_provider();
    let store = EncryptingManagedDatastore::new(Arc::clone(&inner), Arc::clone(&provider));

    store
        .append_commit(StoredConfig::new(
            TxId::new(),
            ConfigVersion::new(1),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("digest-bound"),
        ))
        .await
        .expect("encrypted append");

    let mut corrupted = inner
        .history()
        .await
        .into_iter()
        .next()
        .expect("stored record");
    corrupted.plaintext_digest = Some([0xff; 32]);

    let corrupt_inner = Arc::new(MockManagedDatastore::new());
    corrupt_inner.seed(corrupted).await;
    let corrupt_store = EncryptingManagedDatastore::new(corrupt_inner, provider);

    let err = match corrupt_store.load_latest().await {
        Ok(_) => panic!("mismatched plaintext digest must fail"),
        Err(err) => err,
    };
    assert_eq!(err.code, StoreErrorCode::Crypto);
    assert_eq!(err.message, "config envelope plaintext digest mismatch");
}

#[tokio::test]
async fn encrypted_pre_digest_record_restores_during_rolling_upgrade() {
    let inner = Arc::new(MockManagedDatastore::new());
    let provider = test_provider();
    let store = EncryptingManagedDatastore::new(Arc::clone(&inner), Arc::clone(&provider));

    store
        .append_commit(StoredConfig::new(
            TxId::new(),
            ConfigVersion::new(1),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("pre-digest"),
        ))
        .await
        .expect("encrypted append");

    let mut legacy_ciphertext = inner
        .history()
        .await
        .into_iter()
        .next()
        .expect("stored record");
    legacy_ciphertext.plaintext_digest = None;

    let legacy_inner = Arc::new(MockManagedDatastore::new());
    legacy_inner.seed(legacy_ciphertext).await;
    let legacy_store = EncryptingManagedDatastore::new(legacy_inner, provider);

    let restored = legacy_store
        .load_latest()
        .await
        .expect("restore pre-digest ciphertext")
        .expect("record");
    assert_eq!(restored.config.name, "pre-digest");
}

#[tokio::test]
async fn custom_config_store_kind_is_bound_into_envelope_aad() {
    let inner = Arc::new(MockManagedDatastore::new());
    let provider = test_provider();
    let writer = EncryptingManagedDatastore::<TestConfig, _, _>::with_store_kind(
        Arc::clone(&inner),
        Arc::clone(&provider),
        "startup",
    );

    writer
        .append_commit(StoredConfig::new(
            TxId::new(),
            ConfigVersion::new(1),
            principal(),
            RequestSource::Northbound,
            TestConfig::new("startup-checkpoint"),
        ))
        .await
        .expect("encrypted append");

    let loaded = writer
        .load_latest()
        .await
        .expect("load with matching store kind")
        .expect("record");
    assert_eq!(loaded.config.name, "startup-checkpoint");
    assert_eq!(writer.store_kind(), "startup");

    let default_reader = EncryptingManagedDatastore::<TestConfig, _, _>::new(inner, provider);
    let err = match default_reader.load_latest().await {
        Ok(_) => panic!("store kind mismatch must fail authentication"),
        Err(err) => err,
    };
    assert_eq!(err.code, StoreErrorCode::Crypto);
    assert_eq!(err.message, "config envelope decryption failed");
}

#[tokio::test]
async fn encrypting_store_rejects_corrupt_encrypted_rollback_target() {
    let inner = Arc::new(MockManagedDatastore::new());
    let provider = test_provider();
    let store = EncryptingManagedDatastore::new(Arc::clone(&inner), Arc::clone(&provider));

    let record = StoredConfig::new(
        TxId::new(),
        ConfigVersion::new(1),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("checkpoint"),
    );
    let rollback_tx_id = record.tx_id;
    store.append_commit(record).await.expect("encrypted append");

    let mut corrupted = inner
        .history()
        .await
        .into_iter()
        .next()
        .expect("stored record");
    corrupted.encrypted_blob[0] ^= 0xff;

    let corrupt_inner = Arc::new(MockManagedDatastore::new());
    corrupt_inner.seed(corrupted).await;
    let corrupt_store = EncryptingManagedDatastore::new(corrupt_inner, provider);

    let err = match corrupt_store
        .load_rollback(RollbackTarget::TxId(rollback_tx_id))
        .await
    {
        Ok(_) => panic!("corrupt envelope must fail"),
        Err(err) => err,
    };
    assert_eq!(err.code, StoreErrorCode::Crypto);
    assert_eq!(err.message, "config envelope decryption failed");
}

#[tokio::test]
async fn test_refactored_config_zeroizing_decrypt_hygiene() {
    let inner = Arc::new(MockManagedDatastore::new());
    let provider = test_provider();
    let store = EncryptingManagedDatastore::new(Arc::clone(&inner), Arc::clone(&provider));

    let initial_config = TestConfig::new("hygiene-config-secret-payload");
    let record = StoredConfig::new(
        TxId::new(),
        ConfigVersion::new(1),
        principal(),
        RequestSource::Northbound,
        initial_config.clone(),
    );

    // 1. Decrypt round-trip verification
    store.append_commit(record).await.expect("encrypted append");
    let restored = store
        .load_latest()
        .await
        .expect("load success")
        .expect("stored");
    assert_eq!(restored.config.name, initial_config.name);

    // 2. Corrupt envelope fail-closed verification
    let mut corrupted = inner
        .history()
        .await
        .into_iter()
        .next()
        .expect("stored record");
    corrupted.encrypted_blob[0] ^= 0x55;

    let corrupt_inner = Arc::new(MockManagedDatastore::new());
    corrupt_inner.seed(corrupted).await;
    let corrupt_store = EncryptingManagedDatastore::new(corrupt_inner, provider);

    let err = match corrupt_store.load_latest().await {
        Ok(_) => panic!("should fail closed"),
        Err(err) => err,
    };
    assert_eq!(err.code, StoreErrorCode::Crypto);

    // 3. Missing key fail-closed verification
    let empty_provider = Arc::new(MemoryKeyProvider::new());
    let bad_store = EncryptingManagedDatastore::new(Arc::clone(&inner), empty_provider);
    let err_missing = match bad_store.load_latest().await {
        Ok(_) => panic!("should fail closed"),
        Err(err) => err,
    };
    assert_eq!(err_missing.code, StoreErrorCode::Crypto);
}

#[tokio::test]
async fn test_config_classification_seam_regression() {
    let inner = Arc::new(MockManagedDatastore::new());
    let provider = test_provider();
    let store = EncryptingManagedDatastore::new(Arc::clone(&inner), Arc::clone(&provider));

    // 1. Envelope-shaped legacy plaintext (the config name starts with b"OPCE" magic)
    // and is stored as a legacy plaintext record (encrypted_blob is empty).
    let legacy_tx_id = TxId::new();
    let legacy = StoredConfig::new(
        legacy_tx_id,
        ConfigVersion::new(1),
        principal(),
        RequestSource::Northbound,
        TestConfig::new("OPCE_fake_envelope_data_123456"),
    );
    // Seed it explicitly as legacy plaintext
    inner
        .seed(
            legacy
                .clone()
                .with_config(SealedConfig::legacy_plaintext(TestConfig::new(
                    "OPCE_fake_envelope_data_123456",
                ))),
        )
        .await;

    // Loading it must NOT attempt to decrypt it, even though the config content resembles an envelope,
    // because it is recognized as legacy plaintext structurally (encrypted_blob is empty).
    let restored = store
        .load_latest()
        .await
        .expect("load success")
        .expect("stored record");
    assert_eq!(restored.config.name, "OPCE_fake_envelope_data_123456");

    // 2. Malformed envelope bytes fail closed
    let mut malformed = legacy.clone();
    malformed.encrypted_blob = b"OPCE_fake_malformed_envelope_data_123456".to_vec();

    let malformed_inner = Arc::new(MockManagedDatastore::<SealedConfig<TestConfig>>::new());
    malformed_inner
        .seed(malformed.with_config(SealedConfig::new(legacy.schema_digest)))
        .await;
    let malformed_store = EncryptingManagedDatastore::new(malformed_inner, Arc::clone(&provider));
    let err = match malformed_store.load_latest().await {
        Ok(_) => panic!("should fail closed"),
        Err(err) => err,
    };
    assert_eq!(err.code, StoreErrorCode::Crypto);

    // 3. Post-migration re-encryption
    // Create a ConfigBus with the restored legacy config
    let restored_bus = ConfigBus::restore_or_new_dev_only(TestConfig::new("fallback"), store)
        .await
        .expect("restore bus");
    assert_eq!(restored_bus.load().name, "OPCE_fake_envelope_data_123456");

    // Commit a new config
    submit_commit(&restored_bus, "new-config-payload").await;

    // Verify the latest history record has an encrypted_blob and no legacy plaintext
    let history = inner.history().await;
    let latest = history.last().expect("latest history");
    assert!(!latest.encrypted_blob.is_empty());
    assert!(latest.config.legacy_plaintext_config().is_none());
}
