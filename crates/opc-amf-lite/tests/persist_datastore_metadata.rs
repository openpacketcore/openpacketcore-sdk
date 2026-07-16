use std::sync::Arc;
use std::time::{Duration, Instant};

use opc_amf_lite::{AmfConfig, AMF_SCHEMA_DIGEST};
use opc_config_bus::{
    CommitWrite, ConfigBus, EncryptingManagedDatastore, ManagedDatastore, SealedConfig,
    StoreErrorCode, StoredConfig as BusStoredConfig,
};
use opc_config_bus_consensus::PersistManagedDatastore as PersistDatastore;
use opc_config_model::{
    CommitRequest, ConfigOperation, IdempotencyKey, RequestId, RequestSource, TransportType,
    TrustedPrincipal, WorkloadIdentity, YangPath,
};
use opc_persist::{
    CommitRecord, CommitSource, ConfigStore, ConfirmedCommitResolution, MockConfigStore,
};
use opc_types::{ConfigVersion, SchemaDigest, TenantId, Timestamp, TxId};
use sha2::{Digest, Sha256};

fn principal() -> TrustedPrincipal {
    TrustedPrincipal::new(
        WorkloadIdentity::Internal("legacy-config-writer".to_owned()),
        TenantId::new("tenant-a").expect("tenant"),
    )
}

fn persisted_principal(
    principal: &TrustedPrincipal,
    replay_lookup_digest: Option<&IdempotencyKey>,
) -> String {
    serde_json::to_string(&serde_json::json!({
        "principal": serde_json::to_string(principal).expect("principal JSON"),
        "replay_lookup_digest": replay_lookup_digest,
        "recovery_required": false,
    }))
    .expect("persisted metadata JSON")
}

fn commit_record(
    tx_id: TxId,
    parent_tx_id: Option<TxId>,
    version: u64,
    principal: String,
    confirmed_deadline: Option<Timestamp>,
) -> CommitRecord {
    CommitRecord {
        tx_id,
        parent_tx_id,
        version: ConfigVersion::new(version),
        committed_at: Timestamp::now_utc(),
        principal,
        source: CommitSource::Gnmi,
        schema_digest: AMF_SCHEMA_DIGEST.parse().expect("schema digest"),
        plaintext_digest: vec![0x11; 32],
        encrypted_blob: vec![0x22; 64],
        rollback_point: false,
        confirmed_deadline,
    }
}

#[tokio::test]
async fn persist_datastore_restores_legacy_trusted_principal_encoding() {
    let inner = Arc::new(MockConfigStore::new());
    let expected_principal = principal();
    let tx_id = TxId::new();
    inner
        .append_commit(
            CommitRecord {
                tx_id,
                parent_tx_id: None,
                version: ConfigVersion::new(1),
                committed_at: Timestamp::now_utc(),
                principal: serde_json::to_string(&expected_principal).expect("principal JSON"),
                source: CommitSource::Gnmi,
                schema_digest: AMF_SCHEMA_DIGEST.parse().expect("schema digest"),
                plaintext_digest: vec![0x11; 32],
                encrypted_blob: vec![0x22; 64],
                rollback_point: false,
                confirmed_deadline: None,
            },
            Vec::new(),
        )
        .await
        .expect("seed legacy record");

    let adapter = PersistDatastore::<AmfConfig, _>::new(inner);
    let restored = adapter
        .load_latest()
        .await
        .expect("load legacy metadata")
        .expect("legacy record");
    assert_eq!(tx_id, restored.tx_id);
    assert_eq!(expected_principal, restored.principal);
    assert_eq!(None, restored.idempotency_key);
    assert_eq!(None, restored.apply_plan);
    assert_eq!(None, restored.request_fingerprint);
    assert_eq!(None, restored.request_id);
    assert!(!restored.recovery_required);
}

#[tokio::test]
async fn persist_datastore_absent_legacy_request_lookup_is_definitive() {
    let adapter = PersistDatastore::<AmfConfig, _>::new(Arc::new(MockConfigStore::new()));
    assert!(adapter
        .load_by_request_id(opc_config_model::RequestId::new())
        .await
        .expect("absence is authoritative")
        .is_none());
}

#[tokio::test]
async fn persisted_exact_principal_bytes_remain_bound_to_envelope_aad() {
    let inner = Arc::new(MockConfigStore::new());
    let expected_principal = principal();
    let identity = serde_json::to_string(&expected_principal.identity).expect("identity JSON");
    let tenant = serde_json::to_string(&expected_principal.tenant).expect("tenant JSON");
    let auth_strength =
        serde_json::to_string(&expected_principal.auth_strength).expect("auth strength JSON");
    let aad_principal = format!(
        "{{\"auth_strength\":{auth_strength},\"groups\":[],\"roles\":[],\"tenant\":{tenant},\"identity\":{identity}}}"
    );
    assert_ne!(
        aad_principal,
        serde_json::to_string(&expected_principal).expect("canonical principal JSON")
    );

    let config = AmfConfig::default();
    let plaintext = serde_json::to_vec(&config).expect("config JSON");
    let tx_id = TxId::new();
    let version = ConfigVersion::new(1);
    let committed_at = Timestamp::now_utc();
    let schema_digest: SchemaDigest = AMF_SCHEMA_DIGEST.parse().expect("schema digest");
    let provider = Arc::new(opc_key::MemoryKeyProvider::new());
    provider
        .insert_active_key(
            opc_key::KeyId::new("principal-order-key").expect("key ID"),
            opc_key::KeyPurpose::Config,
            expected_principal.tenant.clone(),
            opc_key::Zeroizing::new([0x5A; opc_key::AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("config key");
    let aad = opc_key::EnvelopeAad::config(
        expected_principal.tenant.clone(),
        version.get(),
        opc_key::ConfigAad::new(
            tx_id,
            None,
            committed_at,
            &aad_principal,
            schema_digest,
            "running",
        )
        .expect("config AAD"),
    );
    let envelope = opc_crypto::encrypt_attested_envelope(provider.as_ref(), &aad, &plaintext)
        .await
        .expect("encrypt config");
    let persisted_metadata = serde_json::json!({
        "principal": aad_principal,
        "recovery_required": false,
    })
    .to_string();
    inner
        .append_commit(
            CommitRecord {
                tx_id,
                parent_tx_id: None,
                version,
                committed_at,
                principal: persisted_metadata,
                source: CommitSource::Gnmi,
                schema_digest,
                plaintext_digest: Sha256::digest(&plaintext).to_vec(),
                encrypted_blob: envelope.encoded().to_vec(),
                rollback_point: false,
                confirmed_deadline: None,
            },
            Vec::new(),
        )
        .await
        .expect("persist exact-AAD fixture");

    let raw = Arc::new(PersistDatastore::<AmfConfig, _>::new(inner));
    let encrypted = EncryptingManagedDatastore::new(raw, provider);
    let restored = encrypted
        .load_latest()
        .await
        .expect("decrypt using exact persisted principal bytes")
        .expect("stored config");
    assert_eq!(restored.principal, expected_principal);
    assert_eq!(restored.config.hostname, config.hostname);
}

#[tokio::test]
async fn replication_source_survives_persist_adapter_and_exact_keyed_replay() {
    let inner = Arc::new(MockConfigStore::new());
    let expected_principal = principal();
    let provider = Arc::new(opc_key::MemoryKeyProvider::new());
    provider
        .insert_active_key(
            opc_key::KeyId::new("replication-source-key").expect("key ID"),
            opc_key::KeyPurpose::Config,
            expected_principal.tenant.clone(),
            opc_key::Zeroizing::new([0x6B; opc_key::AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("config key");
    let raw = Arc::new(PersistDatastore::<AmfConfig, _>::new(Arc::clone(&inner)));
    let encrypted = EncryptingManagedDatastore::new(raw, provider);
    let bus = ConfigBus::new_dev_only(AmfConfig::default(), encrypted)
        .await
        .expect("config bus");

    let request_id = RequestId::new();
    let replay_key = IdempotencyKey::new("replication-source-replay").expect("replay key");
    let changed_path = YangPath::new("/amf/hostname").expect("YANG path");
    let candidate = AmfConfig {
        hostname: "replicated-amf".to_owned(),
        ..AmfConfig::default()
    };
    let request = || {
        CommitRequest::commit(
            request_id,
            expected_principal.clone(),
            TransportType::Internal,
            RequestSource::Replication,
            ConfigOperation::Replace,
            candidate.clone(),
            vec![changed_path.clone()],
            Instant::now() + Duration::from_secs(1),
        )
        .with_idempotency_key(replay_key.clone())
    };

    let committed = bus.submit(request()).await.expect("replicated commit");
    assert_eq!(
        CommitSource::LocalOperator,
        inner
            .load_latest()
            .await
            .expect("persisted read")
            .expect("persisted commit")
            .record
            .source,
        "the persistence wire remains unchanged"
    );
    let replayed = bus.submit(request()).await.expect("exact keyed replay");
    assert_eq!(committed.tx_id, replayed.tx_id);
    assert_eq!(committed.new_version, replayed.new_version);
    assert_eq!(committed.status, replayed.status);
}

#[tokio::test]
async fn persist_datastore_rejects_a_raw_replay_key_before_persistence() {
    let inner = Arc::new(MockConfigStore::new());
    let adapter = PersistDatastore::<AmfConfig, _>::new(Arc::clone(&inner));
    let schema_digest: SchemaDigest = AMF_SCHEMA_DIGEST.parse().expect("schema digest");
    let mut record = BusStoredConfig::new(
        TxId::new(),
        ConfigVersion::new(1),
        principal(),
        RequestSource::Northbound,
        SealedConfig::<AmfConfig>::new(schema_digest),
    );
    record.idempotency_key =
        Some(IdempotencyKey::new("raw-caller-idempotency-key").expect("raw idempotency key"));

    let error = adapter
        .append_commit_write(CommitWrite::new(record))
        .await
        .expect_err("raw replay metadata must fail closed");
    assert_eq!(StoreErrorCode::Internal, error.code);
    assert!(inner.load_latest().await.expect("inner lookup").is_none());
}

#[tokio::test]
async fn replay_lookup_traverses_a_rolled_back_pending_ancestor() {
    let inner = Arc::new(MockConfigStore::new());
    let expected_principal = principal();
    let replay_key = IdempotencyKey::new("a".repeat(64)).expect("lookup digest");
    let original_tx = TxId::new();
    let pending_tx = TxId::new();
    let rollback_tx = TxId::new();

    inner
        .append_commit(
            commit_record(
                original_tx,
                None,
                1,
                persisted_principal(&expected_principal, Some(&replay_key)),
                None,
            ),
            Vec::new(),
        )
        .await
        .expect("append original");
    inner
        .append_commit(
            commit_record(
                pending_tx,
                Some(original_tx),
                2,
                persisted_principal(&expected_principal, None),
                Some(Timestamp::now_utc()),
            ),
            Vec::new(),
        )
        .await
        .expect("append pending");
    inner
        .append_commit_resolving(
            commit_record(
                rollback_tx,
                Some(pending_tx),
                3,
                persisted_principal(&expected_principal, None),
                None,
            ),
            Vec::new(),
            ConfirmedCommitResolution::Rollback {
                pending_tx_id: pending_tx,
            },
        )
        .await
        .expect("atomically roll back pending commit");

    assert!(inner
        .load_rollback(opc_persist::RollbackTarget::ByTxId(pending_tx))
        .await
        .is_err());
    let adapter = PersistDatastore::<AmfConfig, _>::new(inner);
    let replayed = adapter
        .load_by_idempotency_key(&replay_key)
        .await
        .expect("authoritative replay scan")
        .expect("original replay record");
    assert_eq!(original_tx, replayed.tx_id);
    assert_eq!(Some(replay_key), replayed.idempotency_key);
}
