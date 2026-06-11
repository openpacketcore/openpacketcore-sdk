use super::*;
use crate::scope::serialize_bound_aad;
use opc_types::{SchemaDigest, TenantId, Timestamp, TxId};
use std::str::FromStr;

fn tenant() -> TenantId {
    TenantId::new("tenant-a").expect("tenant")
}

fn config_aad() -> EnvelopeAad {
    EnvelopeAad::config(
        tenant(),
        7,
        ConfigAad::new(
            TxId::from_str("11111111-1111-4111-8111-111111111111").expect("tx id"),
            Some(TxId::from_str("22222222-2222-4222-8222-222222222222").expect("tx id")),
            Timestamp::from_str("2026-05-28T08:20:00Z").expect("timestamp"),
            "spiffe://core.example/tenant/tenant-a/ns/core/sa/config-writer/nf/amf/instance/amf-01",
            SchemaDigest::from_str(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            )
            .expect("schema digest"),
            "running",
        )
        .expect("valid config aad"),
    )
}

fn session_aad() -> EnvelopeAad {
    EnvelopeAad::session(
        tenant(),
        5,
        SessionAad::new(
            "amf",
            "sub-a1f5f3d9",
            "amf-registration-context",
            42,
            7,
            "regional-cache-a",
        )
        .expect("valid session aad"),
    )
}

#[test]
fn config_aad_serialization_is_stable() {
    let aad = config_aad();
    let key_id = KeyId::new("config-active-2026-01").expect("key id");
    let serialized = serialize_bound_aad(&aad, &key_id).expect("serialize aad");

    assert_eq!(
        String::from_utf8(serialized).expect("utf8"),
        "{\"tenant\":\"tenant-a\",\"purpose\":\"config\",\"version\":7,\"key_id\":\"config-active-2026-01\",\"metadata\":{\"kind\":\"config\",\"tx_id\":\"11111111-1111-4111-8111-111111111111\",\"parent_tx_id\":\"22222222-2222-4222-8222-222222222222\",\"committed_at\":\"2026-05-28T08:20:00Z\",\"principal\":\"spiffe://core.example/tenant/tenant-a/ns/core/sa/config-writer/nf/amf/instance/amf-01\",\"schema_digest\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"store_kind\":\"running\"}}"
    );
}

#[test]
fn session_aad_serialization_is_stable() {
    let aad = session_aad();
    let key_id = KeyId::new("session-active-2026-01").expect("key id");
    let serialized = serialize_bound_aad(&aad, &key_id).expect("serialize aad");

    assert_eq!(
        String::from_utf8(serialized).expect("utf8"),
        "{\"tenant\":\"tenant-a\",\"purpose\":\"session\",\"version\":5,\"key_id\":\"session-active-2026-01\",\"metadata\":{\"kind\":\"session\",\"nf_kind\":\"amf\",\"session_key_digest\":\"sub-a1f5f3d9\",\"state_type\":\"amf-registration-context\",\"generation\":42,\"fence\":7,\"backend_namespace\":\"regional-cache-a\"}}"
    );
}

#[test]
fn encrypt_and_decrypt_bound_payload_round_trip() {
    let handle = KeyHandle::new(
        KeyId::new("config-active-2026-01").expect("key id"),
        KeyPurpose::Config,
        tenant(),
        Zeroizing::new([0x42; AES_256_GCM_SIV_KEY_LEN]),
    );
    let aad = config_aad();
    let nonce = *b"0123456789ab";
    let plaintext = br#"{"hostname":"amf-01"}"#;

    let encrypted = handle
        .encrypt_payload(&aad, plaintext, nonce)
        .expect("encrypt");
    let decrypted = handle
        .decrypt_payload(&aad, &encrypted.aad, &encrypted.ciphertext_and_tag, nonce)
        .expect("decrypt");

    assert_eq!(decrypted, plaintext);
    assert_eq!(
        handle
            .encrypt_payload(&aad, plaintext, nonce)
            .expect("encrypt again"),
        encrypted
    );
}

#[test]
fn decrypt_rejects_modified_aad_with_redacted_error() {
    let handle = KeyHandle::new(
        KeyId::new("config-active-2026-01").expect("key id"),
        KeyPurpose::Config,
        tenant(),
        Zeroizing::new([0x24; AES_256_GCM_SIV_KEY_LEN]),
    );
    let aad = config_aad();
    let nonce = *b"0123456789ab";
    let plaintext = b"secret payload";

    let encrypted = handle
        .encrypt_payload(&aad, plaintext, nonce)
        .expect("encrypt");
    let wrong = EnvelopeAad::config(
        tenant(),
        7,
        ConfigAad::new(
            TxId::from_str("11111111-1111-4111-8111-111111111111").expect("tx id"),
            Some(TxId::from_str("22222222-2222-4222-8222-222222222222").expect("tx id")),
            Timestamp::from_str("2026-05-28T08:20:00Z").expect("timestamp"),
            "spiffe://core.example/tenant/tenant-a/ns/core/sa/config-writer/nf/amf/instance/amf-01",
            SchemaDigest::from_str(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            )
            .expect("schema digest"),
            "running",
        )
        .expect("valid config aad"),
    );

    let err = handle
        .decrypt_payload(&wrong, &encrypted.aad, &encrypted.ciphertext_and_tag, nonce)
        .expect_err("wrong aad should fail");
    assert_eq!(err, CryptoOperationError::DecryptionFailed);
    assert_eq!(err.to_string(), "payload decryption failed");
}

#[tokio::test]
async fn memory_provider_rotation_preserves_historical_lookup() {
    let provider = MemoryKeyProvider::new();
    let initial_key_id = KeyId::new("session-active-2026-01").expect("key id");
    provider
        .insert_active_key(
            initial_key_id.clone(),
            KeyPurpose::Session,
            tenant(),
            Zeroizing::new([0x55; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("insert active key");

    let initial = provider
        .get_active_key(KeyPurpose::Session, &tenant())
        .await
        .expect("initial active");
    let rotated_id = provider
        .rotate_key(KeyPurpose::Session, &tenant())
        .await
        .expect("rotate");
    let rotated = provider
        .get_active_key(KeyPurpose::Session, &tenant())
        .await
        .expect("rotated active");
    let historical = provider
        .get_key_by_id(&initial_key_id)
        .await
        .expect("historical lookup");

    assert_eq!(initial.key_id(), historical.key_id());
    assert_ne!(initial.key_id(), rotated.key_id());
    assert_eq!(rotated.key_id(), &rotated_id);
    assert_eq!(rotated_id.as_str(), "session-active-2026-01-r1");
}

#[tokio::test]
async fn memory_provider_rotation_keeps_a_stable_base_key_id() {
    let provider = MemoryKeyProvider::new();
    let initial_key_id = KeyId::new("session-active-2026-01").expect("key id");
    provider
        .insert_active_key(
            initial_key_id,
            KeyPurpose::Session,
            tenant(),
            Zeroizing::new([0x55; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("insert active key");

    let rotated_once = provider
        .rotate_key(KeyPurpose::Session, &tenant())
        .await
        .expect("rotate once");
    let rotated_twice = provider
        .rotate_key(KeyPurpose::Session, &tenant())
        .await
        .expect("rotate twice");

    assert_eq!(rotated_once.as_str(), "session-active-2026-01-r1");
    assert_eq!(rotated_twice.as_str(), "session-active-2026-01-r2");
}

#[test]
fn session_aad_rejects_nul_bytes() {
    let err = SessionAad::new(
        "amf\0",
        "sub-a1f5f3d9",
        "amf-registration-context",
        42,
        7,
        "regional-cache-a",
    )
    .expect_err("nul bytes must be rejected");

    assert_eq!(
        err,
        KeyError::InvalidMetadata {
            field: "nf_kind",
            message: "must not contain NUL bytes".into(),
        }
    );
}

#[test]
fn session_aad_deserialization_rejects_nul_bytes() {
    let err = serde_json::from_str::<SessionAad>(
        r#"{
            "nf_kind":"amf\u0000",
            "session_key_digest":"sub-a1f5f3d9",
            "state_type":"amf-registration-context",
            "generation":42,
            "fence":7,
            "backend_namespace":"regional-cache-a"
        }"#,
    )
    .expect_err("nul bytes must be rejected during deserialization");

    assert!(err.to_string().contains("must not contain NUL bytes"));
}

#[test]
fn config_aad_new_rejects_blank_principal_and_store_kind() {
    let schema_digest =
        SchemaDigest::from_str("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
            .expect("schema digest");
    let tx_id = TxId::from_str("11111111-1111-4111-8111-111111111111").expect("tx id");
    let committed_at = Timestamp::from_str("2026-05-28T08:20:00Z").expect("timestamp");

    let principal_err = ConfigAad::new(tx_id, None, committed_at, "   ", schema_digest, "running")
        .expect_err("blank principals must be rejected");
    assert_eq!(
        principal_err,
        KeyError::InvalidMetadata {
            field: "principal",
            message: "must not be empty or whitespace-only".into(),
        }
    );

    let store_kind_err = ConfigAad::new(
        TxId::from_str("33333333-3333-4333-8333-333333333333").expect("tx id"),
        None,
        Timestamp::from_str("2026-05-28T08:20:00Z").expect("timestamp"),
        "spiffe://core.example/tenant/tenant-a/ns/core/sa/config-writer/nf/amf/instance/amf-01",
        schema_digest,
        "",
    )
    .expect_err("blank store kinds must be rejected");
    assert_eq!(
        store_kind_err,
        KeyError::InvalidMetadata {
            field: "store_kind",
            message: "must not be empty or whitespace-only".into(),
        }
    );
}

#[test]
fn config_aad_deserialization_rejects_blank_store_kind() {
    let err = serde_json::from_str::<ConfigAad>(
        r#"{
            "tx_id":"11111111-1111-4111-8111-111111111111",
            "parent_tx_id":"22222222-2222-4222-8222-222222222222",
            "committed_at":"2026-05-28T08:20:00Z",
            "principal":"spiffe://core.example/tenant/tenant-a/ns/core/sa/config-writer/nf/amf/instance/amf-01",
            "schema_digest":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "store_kind":"   "
        }"#,
    )
    .expect_err("blank store kinds must be rejected during deserialization");

    assert!(err
        .to_string()
        .contains("must not be empty or whitespace-only"));
}

#[test]
fn key_id_deserialization_rejects_invalid_input() {
    let err = serde_json::from_str::<KeyId>("\" bad key id \"")
        .expect_err("invalid key ids must be rejected during deserialization");

    assert!(err
        .to_string()
        .contains("must not contain leading or trailing whitespace"));
}

#[test]
fn envelope_aad_deserialization_rejects_mismatched_purpose_and_metadata() {
    let err = serde_json::from_str::<EnvelopeAad>(
        r#"{
            "tenant":"tenant-a",
            "purpose":"config",
            "version":5,
            "metadata":{
                "kind":"session",
                "nf_kind":"amf",
                "session_key_digest":"sub-a1f5f3d9",
                "state_type":"amf-registration-context",
                "generation":42,
                "fence":7,
                "backend_namespace":"regional-cache-a"
            }
        }"#,
    )
    .expect_err("mismatched purpose and metadata must be rejected");

    assert!(err.to_string().contains("must align with session metadata"));
}

#[test]
fn encrypt_rejects_mismatched_purpose_and_metadata() {
    let handle = KeyHandle::new(
        KeyId::new("config-active-2026-01").expect("key id"),
        KeyPurpose::Config,
        tenant(),
        Zeroizing::new([0x42; AES_256_GCM_SIV_KEY_LEN]),
    );
    let invalid = EnvelopeAad {
        tenant: tenant(),
        purpose: KeyPurpose::Config,
        version: 5,
        metadata: EnvelopeMetadata::Session(
            SessionAad::new(
                "amf",
                "sub-a1f5f3d9",
                "amf-registration-context",
                42,
                7,
                "regional-cache-a",
            )
            .expect("valid session aad"),
        ),
    };

    let err = handle
        .encrypt_payload(&invalid, b"payload", *b"0123456789ab")
        .expect_err("mismatched aad must fail before encryption");
    assert_eq!(err, CryptoOperationError::EncryptionFailed);
}

#[test]
fn decrypt_rejects_truncated_ciphertext_and_tag() {
    let handle = KeyHandle::new(
        KeyId::new("config-active-2026-01").expect("key id"),
        KeyPurpose::Config,
        tenant(),
        Zeroizing::new([0x42; AES_256_GCM_SIV_KEY_LEN]),
    );
    let aad = config_aad();
    let nonce = *b"0123456789ab";
    let plaintext = br#"{"hostname":"amf-01"}"#;

    let encrypted = handle
        .encrypt_payload(&aad, plaintext, nonce)
        .expect("encrypt");
    let truncated = &encrypted.ciphertext_and_tag[..AEAD_TAG_LEN - 1];

    let err = handle
        .decrypt_payload(&aad, &encrypted.aad, truncated, nonce)
        .expect_err("truncated ciphertext must fail");
    assert_eq!(err, CryptoOperationError::DecryptionFailed);
    assert_eq!(err.to_string(), "payload decryption failed");
}

#[tokio::test]
async fn memory_provider_rejects_duplicate_key_ids_across_tenants() {
    let provider = MemoryKeyProvider::new();
    let key_id = KeyId::new("config-key-2026-01").expect("key id");
    provider
        .insert_active_key(
            key_id.clone(),
            KeyPurpose::Config,
            tenant(),
            Zeroizing::new([0x11; 32]),
        )
        .expect("first insert");

    let err = provider
        .insert_active_key(
            key_id.clone(),
            KeyPurpose::Config,
            TenantId::new("tenant-b").expect("tenant"),
            Zeroizing::new([0x22; 32]),
        )
        .expect_err("duplicate key id must be rejected");

    assert_eq!(err, KeyError::DuplicateKeyId { key_id });
}

#[tokio::test]
async fn memory_provider_rotation_resumes_from_restored_suffix_and_history() {
    let provider = MemoryKeyProvider::new();
    provider
        .insert_historical_key(KeyHandle::new(
            KeyId::new("session-active-2026-01").expect("key id"),
            KeyPurpose::Session,
            tenant(),
            Zeroizing::new([0x11; AES_256_GCM_SIV_KEY_LEN]),
        ))
        .expect("insert historical base key");
    provider
        .insert_historical_key(KeyHandle::new(
            KeyId::new("session-active-2026-01-r8").expect("key id"),
            KeyPurpose::Session,
            tenant(),
            Zeroizing::new([0x22; AES_256_GCM_SIV_KEY_LEN]),
        ))
        .expect("insert historical rotated key");
    provider
        .insert_active_key(
            KeyId::new("session-active-2026-01-r7").expect("key id"),
            KeyPurpose::Session,
            tenant(),
            Zeroizing::new([0x55; AES_256_GCM_SIV_KEY_LEN]),
        )
        .expect("insert restored active key");

    let rotated = provider
        .rotate_key(KeyPurpose::Session, &tenant())
        .await
        .expect("rotate after restore");

    assert_eq!(rotated.as_str(), "session-active-2026-01-r9");
}
