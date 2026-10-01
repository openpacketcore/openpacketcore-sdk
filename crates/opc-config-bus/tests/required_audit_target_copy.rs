//! Characterizes the real running encryption boundary for retained target copy.
//! This does not exercise target admission, promotion, or NETCONF wire dispatch.
use std::sync::Arc;

use opc_config_bus::{
    CommitWrite, EncryptingManagedDatastore, ManagedDatastore, MockManagedDatastore, SealedConfig,
    StoredConfig,
};
use opc_config_model::{
    IdempotencyKey, RequestId, RequestSource, TrustedPrincipal, WorkloadIdentity,
};
use opc_crypto::decrypt_envelope;
use opc_key::{ConfigAad, EnvelopeAad, KeyId, KeyPurpose, MemoryKeyProvider, Zeroizing};
use opc_types::{ConfigVersion, TenantId, TxId};
use sha2::{Digest, Sha256};

#[tokio::test]
async fn target_copy_fixture_preserves_replay_metadata_while_configuration_is_unchanged() {
    characterize_copy_replay(true).await;
    characterize_copy_replay(false).await;
}

async fn characterize_copy_replay(keyed: bool) {
    let tenant = TenantId::from_static("synthetic-target-copy");
    let principal = TrustedPrincipal::new(
        WorkloadIdentity::Internal("synthetic-copy".into()),
        tenant.clone(),
    );
    let provider = Arc::new(MemoryKeyProvider::new());
    provider
        .insert_active_key(
            KeyId::new("synthetic-copy-key").unwrap(),
            KeyPurpose::Config,
            tenant.clone(),
            Zeroizing::new([0x65; 32]),
        )
        .unwrap();
    let inner = Arc::new(MockManagedDatastore::<SealedConfig<()>>::new());
    let store = EncryptingManagedDatastore::new(inner.clone(), provider.clone());
    let mut first = StoredConfig::new(
        TxId::new(),
        ConfigVersion::new(1),
        principal.clone(),
        RequestSource::Northbound,
        (),
    );
    first.request_id = Some(RequestId::new());
    first.idempotency_key = keyed.then(|| IdempotencyKey::new("synthetic-original").unwrap());
    let mut second = StoredConfig::new(
        TxId::new(),
        ConfigVersion::new(2),
        principal,
        RequestSource::Northbound,
        (),
    );
    second.parent_tx_id = Some(first.tx_id);
    second.request_id = Some(RequestId::new());
    second.idempotency_key = keyed.then(|| IdempotencyKey::new("synthetic-copy").unwrap());
    let originals = [first, second];
    for original in &originals {
        store
            .append_commit_write(CommitWrite::new(original.clone()))
            .await
            .unwrap();
    }
    let history = inner.history().await;
    assert_eq!(history.len(), 2);
    let mut decoded = Vec::new();
    for (sealed, original) in history.iter().zip(&originals) {
        assert!(sealed.request_id.is_none());
        assert!(sealed.idempotency_key != original.idempotency_key);
        let aad = EnvelopeAad::config(
            tenant.clone(),
            original.version.get(),
            ConfigAad::new(
                original.tx_id,
                original.parent_tx_id,
                original.committed_at,
                serde_json::to_string(&original.principal).unwrap(),
                original.schema_digest,
                "running",
            )
            .unwrap(),
        );
        let plaintext = decrypt_envelope(provider.as_ref(), &aad, &sealed.encrypted_blob)
            .await
            .unwrap();
        let digest: [u8; 32] = Sha256::digest(plaintext.as_slice()).into();
        assert!(sealed.plaintext_digest == Some(digest));
        let value: serde_json::Value =
            serde_json::from_slice(plaintext.strip_prefix(b"\x89OPCCFG\x02\r\n\x1a\n").unwrap())
                .unwrap();
        assert_eq!(value["config"], serde_json::Value::Null);
        let replay = match &original.idempotency_key {
            Some(key) => store.load_by_idempotency_key(key).await.unwrap().unwrap(),
            None => store
                .load_by_request_id(original.request_id.unwrap())
                .await
                .unwrap()
                .unwrap(),
        };
        assert!(replay.request_id == original.request_id);
        assert!(replay.idempotency_key == original.idempotency_key);
        assert_eq!(replay.version, original.version);
        decoded.push(value);
    }
    assert_eq!(decoded[0]["config"], decoded[1]["config"]);
    assert!(decoded[0]["request_id"] != decoded[1]["request_id"]);
    if keyed {
        assert!(decoded[0]["idempotency_key"] != decoded[1]["idempotency_key"]);
    } else {
        assert!(decoded[0]["idempotency_key"].is_null());
        assert!(decoded[1]["idempotency_key"].is_null());
    }
    assert!(
        history[0].plaintext_digest != history[1].plaintext_digest,
        "a new request changes the authenticated replay wrapper even for identical configuration"
    );
}
