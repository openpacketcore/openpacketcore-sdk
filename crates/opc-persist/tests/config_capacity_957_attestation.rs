//! Exact-plaintext capacity attestation; no consensus-capacity qualification.

use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use opc_crypto::{
    decrypt_envelope_with_handle, encrypt_attested_envelope_with_handle_and_nonce,
    encrypt_bounded_config_envelope, ConfigCapacityError, ConfigCapacityProfile, CryptoEnvelopeRef,
    CONFIG_CAPACITY_V1_AAD_BYTES, CONFIG_CAPACITY_V1_ENVELOPE_BYTES,
    CONFIG_CAPACITY_V1_LOGICAL_BYTES, CONFIG_CAPACITY_V1_PLAINTEXT_BYTES,
    CONFIG_CAPACITY_V1_REPLAY_BYTES,
};
use opc_key::{
    ConfigAad, EnvelopeAad, KeyError, KeyHandle, KeyId, KeyProvider, KeyPurpose, Zeroizing,
};
use opc_types::{SchemaDigest, TenantId, Timestamp, TxId};
use sha2::{Digest, Sha256};

const MAGIC: &[u8] = b"\x89OPCCFG\x02\r\n\x1a\n";

struct CountingProvider {
    calls: AtomicUsize,
    handle: KeyHandle,
}

impl CountingProvider {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            handle: KeyHandle::new(
                KeyId::new("k".repeat(512)).expect("maximum synthetic key ID"),
                KeyPurpose::Config,
                TenantId::from_static("synthetic"),
                Zeroizing::new([0xC1; 32]),
            ),
        }
    }
}

#[async_trait]
impl KeyProvider for CountingProvider {
    async fn get_active_key(&self, _: KeyPurpose, _: &TenantId) -> Result<KeyHandle, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.handle.clone())
    }

    async fn get_key_by_id(&self, _: &KeyId) -> Result<KeyHandle, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(KeyError::Unavailable)
    }

    async fn rotate_key(&self, _: KeyPurpose, _: &TenantId) -> Result<KeyId, KeyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(KeyError::Unavailable)
    }
}

fn aad() -> EnvelopeAad {
    aad_with_principal(
        "spiffe://test.example/tenant/synthetic/ns/test/sa/config/nf/test/instance/a",
    )
}

fn aad_with_principal(principal: &str) -> EnvelopeAad {
    EnvelopeAad::config(
        TenantId::from_static("synthetic"),
        1,
        ConfigAad::new(
            TxId::new(),
            None,
            Timestamp::from_offset_datetime(
                time::OffsetDateTime::from_unix_timestamp_nanos(1_800_000_000_123_456_789)
                    .expect("fixed timestamp"),
            ),
            principal,
            SchemaDigest::from_bytes([0xC2; 32]),
            "running",
        )
        .expect("synthetic metadata"),
    )
}

fn sized_bound_aad(key_id: &KeyId, bytes: usize) -> EnvelopeAad {
    // Start with escaped and multibyte metadata. Only ASCII padding is varied,
    // so exact serialized size grows by exactly one byte per padding byte.
    let mut principal = String::from("synthetic/\"\\\n\u{1}/\u{1f642}/");
    let base = opc_key::serialize_bound_aad(&aad_with_principal(&principal), key_id)
        .expect("valid bound AAD")
        .len();
    principal.extend(std::iter::repeat_n(
        'p',
        bytes.checked_sub(base).expect("AAD fixture size"),
    ));
    let metadata = aad_with_principal(&principal);
    assert_eq!(
        opc_key::serialize_bound_aad(&metadata, key_id)
            .expect("exact bound AAD")
            .len(),
        bytes
    );
    metadata
}

fn logical_json(bytes: usize) -> Vec<u8> {
    let mut value = vec![b'q'; bytes];
    value[0] = b'"';
    value[bytes - 1] = b'"';
    value
}

fn framed(logical: &[u8], replay_bytes: usize) -> Vec<u8> {
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(b"{\"config\":");
    bytes.extend_from_slice(logical);
    bytes.extend_from_slice(b",\"source\":null,\"idempotency_key\":\"");
    let padding = replay_bytes
        .checked_sub(bytes.len() - logical.len() + 2)
        .expect("replay fixture budget");
    bytes.resize(bytes.len() + padding, b'r');
    bytes.extend_from_slice(b"\"}");
    assert_eq!(bytes.len() - logical.len(), replay_bytes);
    bytes
}

async fn rejects_before_provider(plaintext: &[u8], expected: ConfigCapacityError) {
    let provider = CountingProvider::new();
    let result = encrypt_bounded_config_envelope(&provider, &aad(), plaintext).await;
    assert_eq!(result.expect_err("bounded input must reject"), expected);
    assert_eq!(
        provider.calls.load(Ordering::SeqCst),
        0,
        "no key-provider effects"
    );
}

#[tokio::test]
async fn config_capacity_957_direct_logical_limit_is_exact() {
    let provider = CountingProvider::new();
    let metadata = aad();
    let plaintext = logical_json(CONFIG_CAPACITY_V1_LOGICAL_BYTES);
    let envelope = encrypt_bounded_config_envelope(&provider, &metadata, &plaintext)
        .await
        .expect("at-limit logical encryption");
    let claim = envelope.claim().expect("fresh one-shot claim");
    let evidence = claim.capacity_evidence().expect("bounded evidence");
    assert_eq!(evidence.profile(), ConfigCapacityProfile::BoundedV1);
    assert_eq!(evidence.logical_bytes(), plaintext.len());
    assert_eq!(evidence.replay_bytes(), 0);
    assert!(claim.matches(envelope.encoded()));
    assert!(claim.matches_plaintext_digest(&Sha256::digest(&plaintext)));
    assert!(!claim.matches_plaintext_digest(&[0; 32]));
    assert!(
        envelope.clone().claim().is_err(),
        "clones cannot claim twice"
    );
    assert!(
        decrypt_envelope_with_handle(&provider.handle, &metadata, envelope.encoded())
            .expect("decrypt exact input")
            .as_slice()
            == plaintext,
        "exact logical readback"
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 1);
    rejects_before_provider(
        &logical_json(CONFIG_CAPACITY_V1_LOGICAL_BYTES + 1),
        ConfigCapacityError::LogicalBytes,
    )
    .await;
}

#[tokio::test]
async fn config_capacity_957_logical_and_replay_limits_are_independent() {
    let provider = CountingProvider::new();
    let metadata = aad();
    let logical = logical_json(CONFIG_CAPACITY_V1_LOGICAL_BYTES);
    let plaintext = framed(&logical, CONFIG_CAPACITY_V1_REPLAY_BYTES);
    assert_eq!(plaintext.len(), CONFIG_CAPACITY_V1_PLAINTEXT_BYTES);
    let envelope = encrypt_bounded_config_envelope(&provider, &metadata, &plaintext)
        .await
        .expect("joint at-limit plaintext");
    let evidence = envelope
        .claim()
        .expect("claim")
        .capacity_evidence()
        .expect("evidence");
    assert_eq!(evidence.logical_bytes(), logical.len());
    assert_eq!(evidence.replay_bytes(), CONFIG_CAPACITY_V1_REPLAY_BYTES);
    assert!(
        decrypt_envelope_with_handle(&provider.handle, &metadata, envelope.encoded())
            .expect("decrypt framed input")
            .as_slice()
            == plaintext,
        "exact framed readback"
    );
    rejects_before_provider(
        &framed(&logical_json(CONFIG_CAPACITY_V1_LOGICAL_BYTES + 1), 128),
        ConfigCapacityError::LogicalBytes,
    )
    .await;
    rejects_before_provider(
        &framed(b"{}", CONFIG_CAPACITY_V1_REPLAY_BYTES + 1),
        ConfigCapacityError::ReplayBytes,
    )
    .await;
    rejects_before_provider(
        &framed(&logical, CONFIG_CAPACITY_V1_REPLAY_BYTES + 1),
        ConfigCapacityError::PlaintextBytes,
    )
    .await;
}

#[tokio::test]
async fn config_capacity_957_raw_whitespace_cannot_borrow_replay_headroom() {
    for leading in [false, true] {
        // Only one extra byte: ignoring adjacent whitespace would incorrectly
        // admit this logical L+1 as L with a still-valid 129-byte replay span.
        let mut one_over = logical_json(CONFIG_CAPACITY_V1_LOGICAL_BYTES);
        if leading {
            one_over.insert(0, b' ');
        } else {
            one_over.push(b' ');
        }
        rejects_before_provider(&framed(&one_over, 128), ConfigCapacityError::LogicalBytes).await;
        let mut logical = vec![b' '; CONFIG_CAPACITY_V1_LOGICAL_BYTES + 1];
        let offset = if leading { logical.len() - 2 } else { 0 };
        logical[offset..offset + 2].copy_from_slice(b"{}");
        rejects_before_provider(&framed(&logical, 128), ConfigCapacityError::LogicalBytes).await;
    }
}

#[tokio::test]
async fn config_capacity_957_ambiguous_or_invalid_framing_has_no_provider_effects() {
    for invalid in [
        br#"{"config":{},"config":{}}"#.as_slice(),
        br#"{"config":{},"confi\u0067":{}}"#,
        br#"{"source":null}"#,
        br#"{"config":{},"unexpected":null}"#,
        br#"{"config":{},"source":null,"source":null}"#,
        br#"{"config":{}"#,
    ] {
        let mut plaintext = MAGIC.to_vec();
        plaintext.extend_from_slice(invalid);
        rejects_before_provider(&plaintext, ConfigCapacityError::InvalidPlaintext).await;
    }
    rejects_before_provider(b"{} {}", ConfigCapacityError::InvalidPlaintext).await;
    rejects_before_provider(b"\xff", ConfigCapacityError::InvalidPlaintext).await;
}

#[test]
fn config_capacity_957_legacy_encryption_cannot_issue_capacity_evidence() {
    let provider = CountingProvider::new();
    let envelope = encrypt_attested_envelope_with_handle_and_nonce(
        &provider.handle,
        &aad(),
        b"{}",
        [0xC3; 12],
    )
    .expect("legacy encryption");
    assert!(envelope
        .claim()
        .expect("legacy claim")
        .capacity_evidence()
        .is_none());
}

#[tokio::test]
async fn config_capacity_957_joint_crypto_maximum_and_aad_one_over() {
    let provider = CountingProvider::new();
    let metadata = sized_bound_aad(provider.handle.key_id(), CONFIG_CAPACITY_V1_AAD_BYTES);
    let plaintext = framed(
        &logical_json(CONFIG_CAPACITY_V1_LOGICAL_BYTES),
        CONFIG_CAPACITY_V1_REPLAY_BYTES,
    );
    let envelope = encrypt_bounded_config_envelope(&provider, &metadata, &plaintext)
        .await
        .expect("joint reachable plaintext/AAD/key-id maximum");
    let decoded = CryptoEnvelopeRef::decode(envelope.encoded()).expect("bounded envelope");
    assert_eq!(decoded.key_id.as_str().len(), 512);
    assert_eq!(decoded.nonce.len(), 12);
    assert_eq!(decoded.aad.len(), CONFIG_CAPACITY_V1_AAD_BYTES);
    assert_eq!(decoded.ciphertext_and_tag.len(), plaintext.len() + 16);
    assert_eq!(envelope.encoded().len(), CONFIG_CAPACITY_V1_ENVELOPE_BYTES);
    assert!(
        decrypt_envelope_with_handle(&provider.handle, &metadata, envelope.encoded())
            .expect("decrypt joint maximum")
            .as_slice()
            == plaintext
    );
    let over = sized_bound_aad(provider.handle.key_id(), CONFIG_CAPACITY_V1_AAD_BYTES + 1);
    let result = encrypt_bounded_config_envelope(&provider, &over, &plaintext).await;
    assert_eq!(
        result.expect_err("bound AAD one-over must reject"),
        ConfigCapacityError::AadBytes
    );
    // Bound AAD depends on the provider-selected key identifier. Reading that
    // identifier is required; no encrypted envelope or claim may be returned.
    assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    let provider = CountingProvider::new();
    let oversized_base = aad_with_principal(&"p".repeat(CONFIG_CAPACITY_V1_AAD_BYTES));
    let result = encrypt_bounded_config_envelope(&provider, &oversized_base, b"{}").await;
    assert_eq!(
        result.expect_err("base AAD rejects before selection"),
        ConfigCapacityError::AadBytes
    );
    assert_eq!(provider.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn config_capacity_957_evidence_counts_exact_utf8_and_escape_bytes() {
    let provider = CountingProvider::new();
    let logical = "{\"text\":\"\u{1f642}\\u0061\\\\\\\"\"}".as_bytes();
    let plaintext = framed(logical, 128);
    let envelope = encrypt_bounded_config_envelope(&provider, &aad(), &plaintext)
        .await
        .expect("escaped and UTF-8 logical input");
    let evidence = envelope
        .claim()
        .expect("claim")
        .capacity_evidence()
        .expect("evidence");
    assert_eq!(evidence.logical_bytes(), logical.len());
    assert_eq!(evidence.replay_bytes(), 128);
    let parsed: serde_json::Value = serde_json::from_slice(logical).expect("fixture JSON");
    let recoded = serde_json::to_vec(&parsed).expect("second serialization");
    assert_ne!(
        recoded.len(),
        logical.len(),
        "test must distinguish the actual input from a second serialization"
    );
}
