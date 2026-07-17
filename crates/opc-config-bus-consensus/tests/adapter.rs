use std::str::FromStr;
use std::sync::Arc;

use opc_config_bus::{
    CommitWrite, CommittedRevisionSource, EncryptingManagedDatastore, ManagedDatastore,
    SealedConfig, StoreErrorCode, StoredConfig,
};
use opc_config_bus_consensus::{PersistManagedDatastore, RaftManagedDatastore};
use opc_config_model::{
    ConfigError, OpcConfig, RequestSource, RollbackTarget, TrustedPrincipal, ValidationContext,
    ValidationError, WorkloadIdentity, YangPath,
};
use opc_key::{KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_persist::{ConfigStore, MockConfigStore, RollbackTarget as PersistRollbackTarget};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct TestConfig {
    name: String,
}

impl OpcConfig for TestConfig {
    type Delta = String;

    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_bytes([0x25; 32])
    }

    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        if self == previous {
            Ok(Vec::new())
        } else {
            Ok(vec![self.name.clone()])
        }
    }

    fn changed_paths(
        &self,
        _previous: &Self,
        deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        if deltas.is_empty() {
            Ok(Vec::new())
        } else {
            YangPath::new("/system/name")
                .map(|path| vec![path])
                .map_err(|error| ConfigError::new("changed-path", error.message()))
        }
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
        _context: &ValidationContext<Self>,
    ) -> Result<(), ValidationError> {
        Ok(())
    }
}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").expect("test tenant")
}

fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::Internal("config-writer".to_owned()),
        tenant(),
    )
}

fn record(tx_id: TxId, label: &str) -> StoredConfig<TestConfig> {
    StoredConfig {
        tx_id,
        parent_tx_id: None,
        version: ConfigVersion::new(1),
        committed_at: Timestamp::from_str("2026-07-16T00:00:00Z").expect("fixed timestamp"),
        principal: principal(),
        source: RequestSource::Internal,
        schema_digest: SchemaDigest::from_bytes([0x25; 32]),
        plaintext_digest: None,
        config: TestConfig {
            name: "ciphertext-only-config".to_owned(),
        },
        encrypted_blob: Vec::new(),
        idempotency_key: None,
        apply_plan: None,
        request_fingerprint: None,
        request_id: None,
        recovery_required: false,
        confirmed_deadline: None,
        rollback_label: Some(label.to_owned()),
    }
}

fn provider() -> Arc<MemoryKeyProvider> {
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("config-key").expect("test key ID"),
            KeyPurpose::Config,
            tenant(),
            Zeroizing::new([0xA5; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("insert test key");
    provider
}

#[tokio::test]
async fn named_rollback_label_and_root_audit_are_persisted_atomically() {
    let persistence = Arc::new(MockConfigStore::new());
    let sealed = Arc::new(PersistManagedDatastore::<TestConfig, _>::new(Arc::clone(
        &persistence,
    )));
    let encrypted = EncryptingManagedDatastore::new(sealed, provider());
    let tx_id = TxId::new();

    encrypted
        .append_commit_write(CommitWrite::new(record(tx_id, "release-candidate")))
        .await
        .expect("append encrypted named rollback point");

    let persisted = persistence
        .load_rollback(PersistRollbackTarget::ByLabel(
            "release-candidate".to_owned(),
        ))
        .await
        .expect("load persisted named rollback point");
    assert_eq!(tx_id, persisted.record.tx_id);
    assert!(persisted.record.rollback_point);
    assert_eq!(1, persisted.audit.len());
    assert_eq!("/", persisted.audit[0].yang_path);
    assert!(persisted.audit[0].redaction_applied);
    let encoded = serde_json::to_string(&persisted).expect("persisted fixture JSON");
    assert!(!encoded.contains("ciphertext-only-config"));

    let restored = encrypted
        .load_rollback(RollbackTarget::Label("release-candidate".to_owned()))
        .await
        .expect("restore named rollback point");
    assert_eq!(
        Some("release-candidate"),
        restored.rollback_label.as_deref()
    );
    assert_eq!("ciphertext-only-config", restored.config.name);
}

#[test]
fn raft_adapter_port_is_statically_ciphertext_only() {
    fn assert_sealed_port<T: ManagedDatastore<SealedConfig<TestConfig>>>() {}
    fn assert_committed_source<T: CommittedRevisionSource<SealedConfig<TestConfig>>>() {}
    assert_sealed_port::<RaftManagedDatastore<TestConfig>>();
    assert_committed_source::<RaftManagedDatastore<TestConfig>>();
}

#[tokio::test]
async fn unavailable_persistence_maps_to_retryable_store_error() {
    #[derive(Debug)]
    struct UnavailableStore;

    #[async_trait::async_trait]
    impl ConfigStore for UnavailableStore {
        async fn load_latest(
            &self,
        ) -> Result<Option<opc_persist::StoredConfig>, opc_persist::PersistError> {
            Err(opc_persist::PersistError::unavailable())
        }

        async fn load_rollback(
            &self,
            _target: PersistRollbackTarget,
        ) -> Result<opc_persist::StoredConfig, opc_persist::PersistError> {
            Err(opc_persist::PersistError::unavailable())
        }

        async fn append_commit(
            &self,
            _record: opc_persist::CommitRecord,
            _audit: Vec<opc_persist::AuditRecord>,
        ) -> Result<(), opc_persist::PersistError> {
            Err(opc_persist::PersistError::unavailable())
        }

        async fn mark_confirmed(&self, _tx_id: TxId) -> Result<(), opc_persist::PersistError> {
            Err(opc_persist::PersistError::unavailable())
        }

        async fn create_rollback_point(
            &self,
            _tx_id: TxId,
            _label: Option<String>,
        ) -> Result<(), opc_persist::PersistError> {
            Err(opc_persist::PersistError::unavailable())
        }

        async fn preflight(
            &self,
        ) -> Result<opc_persist::PersistCapabilities, opc_persist::PersistError> {
            Err(opc_persist::PersistError::unavailable())
        }
    }

    let adapter = PersistManagedDatastore::<TestConfig, _>::new(Arc::new(UnavailableStore));
    let error = match adapter.load_latest().await {
        Ok(_) => panic!("unavailable backend must fail closed"),
        Err(error) => error,
    };
    assert_eq!(StoreErrorCode::Unavailable, error.code);
}
