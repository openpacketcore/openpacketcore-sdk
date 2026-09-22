//! Serialization/encryption boundary controls. The recording sink below is
//! deliberately not consensus, retained-storage or production capacity proof.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use opc_config_bus::datastore::ConfigCapacityProfile;
use opc_config_bus::{
    CommitWrite, EncryptingManagedDatastore, ManagedDatastore, SealedConfig, StoreError,
    StoredConfig,
};
use opc_config_model::{
    ConfigError, IdempotencyKey, OpcConfig, RequestSource, RollbackTarget, TrustedPrincipal,
    ValidationContext, ValidationError, WorkloadIdentity, YangPath,
};
use opc_key::{KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose, Zeroizing};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize};

const LOGICAL_BYTES: usize = 1_572_864;
const PLAINTEXT_BYTES: usize = 1_638_400;

#[derive(Clone, Deserialize)]
struct ProbeConfig {
    payload: String,
    #[serde(skip)]
    serializations: Arc<AtomicUsize>,
}

impl std::fmt::Debug for ProbeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProbeConfig(<synthetic>)")
    }
}

impl Serialize for ProbeConfig {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if self.serializations.fetch_add(1, Ordering::SeqCst) != 0 {
            return Err(serde::ser::Error::custom(
                "configuration serialized more than once",
            ));
        }
        let mut state = serializer.serialize_struct("ProbeConfig", 1)?;
        state.serialize_field("payload", &self.payload)?;
        state.end()
    }
}

impl OpcConfig for ProbeConfig {
    type Delta = String;

    fn schema_digest(&self) -> SchemaDigest {
        SchemaDigest::from_bytes([0xC1; 32])
    }

    fn diff(&self, previous: &Self) -> Result<Vec<Self::Delta>, ConfigError> {
        Ok(if self.payload == previous.payload {
            Vec::new()
        } else {
            vec![self.payload.clone()]
        })
    }

    fn changed_paths(
        &self,
        _: &Self,
        deltas: &[Self::Delta],
    ) -> Result<Vec<YangPath>, ConfigError> {
        if deltas.is_empty() {
            Ok(Vec::new())
        } else {
            YangPath::new("/synthetic/payload")
                .map(|path| vec![path])
                .map_err(|_| ConfigError::new("changed-path", "invalid synthetic path"))
        }
    }

    fn apply_delta(&mut self, delta: Self::Delta) -> Result<(), ConfigError> {
        self.payload = delta;
        Ok(())
    }

    fn validate_syntax(&self) -> Result<(), ValidationError> {
        Ok(())
    }

    fn validate_semantics(&self, _: &ValidationContext<Self>) -> Result<(), ValidationError> {
        Ok(())
    }
}

struct Provider {
    key: KeyHandle,
    active_calls: AtomicUsize,
}

#[async_trait]
impl KeyProvider for Provider {
    async fn get_active_key(&self, _: KeyPurpose, _: &TenantId) -> Result<KeyHandle, KeyError> {
        self.active_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.key.clone())
    }

    async fn get_key_by_id(&self, id: &KeyId) -> Result<KeyHandle, KeyError> {
        if id == self.key.key_id() {
            Ok(self.key.clone())
        } else {
            Err(KeyError::Unavailable)
        }
    }

    async fn rotate_key(&self, _: KeyPurpose, _: &TenantId) -> Result<KeyId, KeyError> {
        Err(KeyError::Unavailable)
    }
}

struct RecordingSink {
    profile: ConfigCapacityProfile,
    appends: AtomicUsize,
    record: tokio::sync::Mutex<Option<StoredConfig<SealedConfig<ProbeConfig>>>>,
}

#[async_trait]
impl ManagedDatastore<SealedConfig<ProbeConfig>> for RecordingSink {
    fn config_capacity_profile(&self) -> ConfigCapacityProfile {
        self.profile
    }

    async fn load_latest(
        &self,
    ) -> Result<Option<StoredConfig<SealedConfig<ProbeConfig>>>, StoreError> {
        Ok(self.record.lock().await.clone())
    }

    async fn load_rollback(
        &self,
        _: RollbackTarget,
    ) -> Result<StoredConfig<SealedConfig<ProbeConfig>>, StoreError> {
        Err(StoreError::not_found("synthetic sink has no rollback"))
    }

    async fn load_by_idempotency_key(
        &self,
        _: &IdempotencyKey,
    ) -> Result<Option<StoredConfig<SealedConfig<ProbeConfig>>>, StoreError> {
        Ok(None)
    }

    async fn append_commit_write(
        &self,
        commit: CommitWrite<SealedConfig<ProbeConfig>>,
    ) -> Result<(), StoreError> {
        let (record, resolution) = commit.into_parts();
        assert!(resolution.is_none());
        self.appends.fetch_add(1, Ordering::SeqCst);
        *self.record.lock().await = Some(record);
        Ok(())
    }

    async fn clear_recovery_required(&self, _: TxId) -> Result<(), StoreError> {
        Ok(())
    }
}

fn record(logical_bytes: usize, serializations: Arc<AtomicUsize>) -> StoredConfig<ProbeConfig> {
    let config = ProbeConfig {
        payload: "q".repeat(logical_bytes - b"{\"payload\":\"\"}".len()),
        serializations,
    };
    let schema_digest = config.schema_digest();
    StoredConfig {
        tx_id: TxId::new(),
        parent_tx_id: None,
        version: ConfigVersion::new(1),
        committed_at: Timestamp::from_offset_datetime(
            time::OffsetDateTime::from_unix_timestamp(1_900_000_000).expect("fixed time"),
        ),
        principal: TrustedPrincipal::new(
            WorkloadIdentity::Internal("synthetic-writer".into()),
            TenantId::from_static("test"),
        ),
        source: RequestSource::Internal,
        schema_digest,
        plaintext_digest: None,
        config,
        encrypted_blob: Vec::new(),
        idempotency_key: None,
        apply_plan: None,
        request_fingerprint: None,
        request_id: None,
        recovery_required: false,
        confirmed_deadline: None,
        rollback_label: None,
    }
}

async fn exercise(profile: ConfigCapacityProfile, logical_bytes: usize, accepted: bool) {
    let provider = Arc::new(Provider {
        key: KeyHandle::new(
            KeyId::new("synthetic-key").expect("key ID"),
            KeyPurpose::Config,
            TenantId::from_static("test"),
            Zeroizing::new([0xC2; 32]),
        ),
        active_calls: AtomicUsize::new(0),
    });
    let sink = Arc::new(RecordingSink {
        profile,
        appends: AtomicUsize::new(0),
        record: tokio::sync::Mutex::new(None),
    });
    // Exercise the trait's Arc forwarding implementation as well as the
    // encrypting wrapper's policy forwarding, with no second serialization.
    let wrapped =
        EncryptingManagedDatastore::new(Arc::new(Arc::clone(&sink)), Arc::clone(&provider));
    assert_eq!(wrapped.config_capacity_profile(), profile);
    let serializations = Arc::new(AtomicUsize::new(0));
    let input = record(logical_bytes, Arc::clone(&serializations));
    let expected_payload = input.config.payload.clone();
    let result = wrapped.append_commit(input).await;
    assert_eq!(serializations.load(Ordering::SeqCst), 1);
    if accepted {
        result.expect("admitted encryption boundary");
        assert_eq!(provider.active_calls.load(Ordering::SeqCst), 1);
        assert_eq!(sink.appends.load(Ordering::SeqCst), 1);
        let expected_digest = {
            let sealed = sink.record.lock().await;
            let sealed = sealed.as_ref().expect("sealed recording");
            assert!(!sealed.encrypted_blob.is_empty());
            sealed.plaintext_digest
        };
        let readback = wrapped
            .load_latest()
            .await
            .expect("decrypt")
            .expect("record");
        assert!(
            readback.config.payload == expected_payload,
            "exact logical plaintext readback"
        );
        assert_eq!(readback.plaintext_digest, expected_digest);
    } else {
        assert!(result.is_err(), "oversized input must reject");
        assert_eq!(
            provider.active_calls.load(Ordering::SeqCst),
            0,
            "reject before provider effects"
        );
        assert_eq!(
            sink.appends.load(Ordering::SeqCst),
            0,
            "reject before sealed-store effects"
        );
        assert!(sink.record.lock().await.is_none());
    }
}

#[tokio::test]
async fn config_capacity_957_adapter_serializes_at_limit_once() {
    exercise(ConfigCapacityProfile::BoundedV1, LOGICAL_BYTES, true).await;
}

#[tokio::test]
async fn config_capacity_957_adapter_rejects_one_over_before_provider_and_store() {
    exercise(ConfigCapacityProfile::BoundedV1, LOGICAL_BYTES + 1, false).await;
}

#[tokio::test]
async fn config_capacity_957_adapter_stops_the_complete_plaintext_writer() {
    exercise(ConfigCapacityProfile::BoundedV1, PLAINTEXT_BYTES + 1, false).await;
}

#[tokio::test]
async fn config_capacity_957_legacy_adapter_keeps_its_encryption_behavior() {
    exercise(ConfigCapacityProfile::Legacy, LOGICAL_BYTES + 1, true).await;
}
