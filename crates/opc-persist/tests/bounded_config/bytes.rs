use super::support::*;
use opc_crypto::{
    decrypt_envelope_with_handle, encrypt_attested_envelope_with_handle_and_nonce,
    encrypt_bounded_config_envelope, encrypt_bounded_config_envelope_with_handle_and_nonce,
    ConfigCapacityError, ConfigCapacityProfile, CryptoEnvelopeRef,
    CONFIG_CAPACITY_V1_AAD_BYTES as AAD, CONFIG_CAPACITY_V1_ENVELOPE_BYTES as ENVELOPE,
    CONFIG_CAPACITY_V1_LOGICAL_BYTES as LOGICAL, CONFIG_CAPACITY_V1_PLAINTEXT_BYTES as PLAINTEXT,
    CONFIG_CAPACITY_V1_REPLAY_BYTES as REPLAY,
};
use opc_key::{EnvelopeAad, KeyHandle, KeyId, KeyPurpose, SessionAad, Zeroizing};
use opc_types::TenantId;
use sha2::{Digest, Sha256};
use std::str::FromStr;

#[test]
fn public_byte_limits_are_stable() {
    assert_eq!(
        [LOGICAL, REPLAY, PLAINTEXT, AAD, ENVELOPE],
        [1_572_864, 65_536, 1_638_400, 65_536, 1_704_492],
    );
}

async fn rejects_before_provider(bytes: &[u8], error: ConfigCapacityError) {
    let provider = Provider::new(Mode::Ready);
    assert_eq!(
        encrypt_bounded_config_envelope(&provider, &aad("writer"), bytes)
            .await
            .unwrap_err(),
        error
    );
    assert_eq!(
        provider.calls(),
        0,
        "rejection must precede provider access"
    );
}

#[tokio::test]
async fn logical_limit_is_exact_and_legacy_remains_unbounded() {
    let provider = Provider::new(Mode::Ready);
    let metadata = aad("writer");
    let bytes = logical(LOGICAL);
    let envelope = encrypt_bounded_config_envelope(&provider, &metadata, &bytes)
        .await
        .unwrap();
    let claim = envelope.claim().unwrap();
    let evidence = claim.capacity_evidence().unwrap();
    assert_eq!(evidence.logical_bytes(), LOGICAL);
    assert_eq!(evidence.replay_bytes(), 0);
    assert_eq!(evidence.profile(), ConfigCapacityProfile::BoundedV1);
    assert_eq!(evidence.profile().revision(), 1);
    assert_eq!(
        ConfigCapacityProfile::default(),
        ConfigCapacityProfile::Legacy
    );
    assert_eq!(ConfigCapacityProfile::Legacy.revision(), 0);
    assert!(claim.matches(envelope.encoded()));
    assert!(claim.matches_plaintext_digest(&Sha256::digest(&bytes)));
    assert_eq!(
        decrypt_envelope_with_handle(&provider.handle, &metadata, envelope.encoded())
            .unwrap()
            .as_slice(),
        bytes
    );
    assert_eq!(provider.calls(), 1);
    let oversized = logical(LOGICAL + 1);
    rejects_before_provider(&oversized, ConfigCapacityError::LogicalBytes).await;
    let legacy = encrypt_attested_envelope_with_handle_and_nonce(
        &provider.handle,
        &metadata,
        &oversized,
        [1; 12],
    )
    .unwrap();
    let (evidence, reservation) = legacy.claim().unwrap().into_capacity_parts();
    assert!(evidence.is_none() && reservation.is_none());
    assert_eq!(
        decrypt_envelope_with_handle(&provider.handle, &metadata, legacy.encoded())
            .unwrap()
            .as_slice(),
        oversized
    );
}

#[tokio::test]
async fn replay_and_total_plaintext_bounds_are_independent() {
    let provider = Provider::new(Mode::Ready);
    let value = logical(LOGICAL);
    let bytes = framed(&value, REPLAY);
    assert_eq!(bytes.len(), PLAINTEXT);
    let metadata = aad("writer");
    let envelope = encrypt_bounded_config_envelope(&provider, &metadata, &bytes)
        .await
        .unwrap();
    let evidence = envelope.claim().unwrap().capacity_evidence().unwrap();
    assert_eq!(evidence.logical_bytes(), LOGICAL);
    assert_eq!(evidence.replay_bytes(), REPLAY);
    assert_eq!(
        decrypt_envelope_with_handle(&provider.handle, &metadata, envelope.encoded())
            .unwrap()
            .as_slice(),
        bytes
    );
    rejects_before_provider(
        &framed(&logical(LOGICAL + 1), 128),
        ConfigCapacityError::LogicalBytes,
    )
    .await;
    rejects_before_provider(&framed(b"{}", REPLAY + 1), ConfigCapacityError::ReplayBytes).await;
    rejects_before_provider(
        &framed(&value, REPLAY + 1),
        ConfigCapacityError::PlaintextBytes,
    )
    .await;
}

#[tokio::test]
async fn joint_maximum_is_reachable_and_bound_aad_rejects_one_over() {
    let provider = Provider::new(Mode::Ready);
    let bytes = framed(&logical(LOGICAL), REPLAY);
    let metadata = sized_aad(provider.handle.key_id(), AAD);
    let envelope = encrypt_bounded_config_envelope(&provider, &metadata, &bytes)
        .await
        .unwrap();
    let view = CryptoEnvelopeRef::decode(envelope.encoded()).unwrap();
    assert_eq!(view.key_id.as_str().len(), 512);
    assert_eq!(view.aad.len(), AAD);
    assert_eq!(view.nonce.len(), 12);
    assert_eq!(view.ciphertext_and_tag.len(), PLAINTEXT + 16);
    assert_eq!(envelope.encoded().len(), ENVELOPE);
    assert_eq!(
        decrypt_envelope_with_handle(&provider.handle, &metadata, envelope.encoded())
            .unwrap()
            .as_slice(),
        bytes
    );
    let over = sized_aad(provider.handle.key_id(), AAD + 1);
    // Small plaintext keeps the envelope limit from masking the AAD check.
    assert_eq!(
        encrypt_bounded_config_envelope(&provider, &over, b"{}")
            .await
            .unwrap_err(),
        ConfigCapacityError::AadBytes
    );
    assert_eq!(
        provider.calls(),
        2,
        "bound AAD requires the selected key ID"
    );
    assert_eq!(
        encrypt_bounded_config_envelope(&provider, &aad(&"p".repeat(AAD)), b"{}")
            .await
            .unwrap_err(),
        ConfigCapacityError::AadBytes
    );
    assert_eq!(
        provider.calls(),
        2,
        "oversized base AAD must precede key selection"
    );
    assert!(KeyId::new("k".repeat(513)).is_err());
}

#[tokio::test]
async fn raw_whitespace_counts_as_logical_bytes_on_both_sides() {
    for leading in [true, false] {
        let mut at = logical(LOGICAL - 1);
        if leading {
            at.insert(0, b' ');
        } else {
            at.push(b'\n');
        }
        let provider = Provider::new(Mode::Ready);
        let envelope =
            encrypt_bounded_config_envelope(&provider, &aad("writer"), &framed(&at, 128))
                .await
                .unwrap();
        let evidence = envelope.claim().unwrap().capacity_evidence().unwrap();
        assert_eq!(
            (evidence.logical_bytes(), evidence.replay_bytes()),
            (LOGICAL, 128)
        );
        at.push(b'\t');
        rejects_before_provider(&framed(&at, 128), ConfigCapacityError::LogicalBytes).await;
        rejects_before_provider(&at, ConfigCapacityError::LogicalBytes).await;
    }
}

#[tokio::test]
async fn framing_rejects_unknown_duplicate_missing_and_invalid_values() {
    let mut invalid = vec![
        br#"{"config":{},"config":{}}"#.to_vec(),
        br#"{"config":{},"confi\u0067":{}}"#.to_vec(),
        br#"{"source":null}"#.to_vec(),
        br#"{"config":{},"unknown":null}"#.to_vec(),
        br#"{"config":{}"#.to_vec(),
    ];
    for field in [
        "source",
        "idempotency_key",
        "apply_plan",
        "request_fingerprint",
        "request_id",
    ] {
        invalid.push(format!("{{\"config\":null,\"{field}\":null,\"{field}\":null}}").into_bytes());
    }
    for bytes in invalid {
        rejects_before_provider(
            &[MAGIC, &bytes].concat(),
            ConfigCapacityError::InvalidPlaintext,
        )
        .await;
    }
    for bytes in [
        b"{} {}".as_slice(),
        b"\xff",
        b"",
        b"{",
        b"\x89OPCCFG\x03\r\n\x1a\n{}",
    ] {
        rejects_before_provider(bytes, ConfigCapacityError::InvalidPlaintext).await;
    }
}

#[tokio::test]
async fn evidence_uses_exact_utf8_escapes_and_all_replay_fields() {
    let provider = Provider::new(Mode::Ready);
    let value = " \n{\"text\":\"🙂\\u0061\\\\\\\"\"}\t ".as_bytes();
    let bytes = framed(value, 128);
    let envelope = encrypt_bounded_config_envelope(&provider, &aad("writer"), &bytes)
        .await
        .unwrap();
    let evidence = envelope.claim().unwrap().capacity_evidence().unwrap();
    assert_eq!(
        (evidence.logical_bytes(), evidence.replay_bytes()),
        (value.len(), 128)
    );
    let recoded =
        serde_json::to_vec(&serde_json::from_slice::<serde_json::Value>(value).unwrap()).unwrap();
    assert_ne!(recoded.len(), value.len());
    let wrapper = br#"{"source":null,"idempotency_key":"key","apply_plan":[],"request_fingerprint":{},"request_id":17,"config":null}"#;
    let envelope =
        encrypt_bounded_config_envelope(&provider, &aad("writer"), &[MAGIC, wrapper].concat())
            .await
            .unwrap();
    let evidence = envelope.claim().unwrap().capacity_evidence().unwrap();
    assert_eq!(evidence.logical_bytes(), 4);
    assert_eq!(evidence.replay_bytes(), MAGIC.len() + wrapper.len() - 4);
}

#[tokio::test]
async fn object_and_positional_wrappers_preserve_exact_value_spans() {
    let provider = Provider::new(Mode::Ready);
    for (wrapper, logical) in [
        (br#"[{}]"#.as_slice(), 2),
        (b"[ \n42\t ,null,[],{},false,0]", 6),
        (
            br#"{"source":{"nested":[1,{"config":0}]},"confi\u0067": null }"#,
            6,
        ),
        (
            br#"{"config":{"$serde_json::private::RawValue":"null"}}"#,
            41,
        ),
        (br#"{"source":1e999,"config":1e999}"#, 5),
    ] {
        let plaintext = [MAGIC, wrapper].concat();
        let envelope = encrypt_bounded_config_envelope(&provider, &aad("writer"), &plaintext)
            .await
            .unwrap();
        let evidence = envelope.claim().unwrap().capacity_evidence().unwrap();
        assert_eq!(evidence.logical_bytes(), logical, "{wrapper:?}");
        assert_eq!(evidence.replay_bytes(), plaintext.len() - logical);
    }
    for wrapper in [
        b"[]".as_slice(),
        b"[{},0,0,0,0,0,0]",
        b"[{},]",
        b"{\"config\":{} \"source\":0}",
        b"{\"config\" {}}",
        b"{\"config\":{}} null",
        b"{\"config\":\"\xff\"}",
    ] {
        rejects_before_provider(
            &[MAGIC, wrapper].concat(),
            ConfigCapacityError::InvalidPlaintext,
        )
        .await;
    }
}

#[tokio::test]
async fn wrong_purpose_rejects_before_provider_and_wrong_key_context_cannot_attest() {
    let provider = Provider::new(Mode::Ready);
    let session = EnvelopeAad::session(
        TenantId::from_static("synthetic"),
        1,
        SessionAad::new("test", "session", "state", 1, 1, "namespace").unwrap(),
    );
    assert_eq!(
        encrypt_bounded_config_envelope(&provider, &session, b"{}")
            .await
            .unwrap_err(),
        ConfigCapacityError::InvalidPlaintext
    );
    assert_eq!(provider.calls(), 0);
    for (purpose, tenant) in [
        (KeyPurpose::Config, "foreign"),
        (KeyPurpose::Session, "synthetic"),
    ] {
        let handle = KeyHandle::new(
            KeyId::new("other").unwrap(),
            purpose,
            TenantId::from_static(tenant),
            Zeroizing::new([0x31; 32]),
        );
        assert_eq!(
            encrypt_bounded_config_envelope_with_handle_and_nonce(
                &handle,
                &aad("writer"),
                b"{}",
                [2; 12]
            )
            .unwrap_err(),
            ConfigCapacityError::EncryptionFailed
        );
    }
}

#[tokio::test]
async fn unrepresentable_aad_timestamp_is_an_encryption_error() {
    let provider = Provider::new(Mode::Ready);
    let metadata = EnvelopeAad::config(
        TenantId::from_static("synthetic"),
        1,
        opc_key::ConfigAad::new(
            opc_types::TxId::new(),
            None,
            opc_types::Timestamp::from_str("0000-01-01T00:00:00+01:00").unwrap(),
            "writer",
            opc_types::SchemaDigest::from_bytes([0; 32]),
            "running",
        )
        .unwrap(),
    );
    assert_eq!(
        encrypt_attested_envelope_with_handle_and_nonce(
            &provider.handle,
            &metadata,
            b"{}",
            [8; 12]
        )
        .unwrap_err(),
        opc_crypto::CryptoError::EncryptionFailed
    );
    assert_eq!(
        encrypt_bounded_config_envelope(&provider, &metadata, b"{}")
            .await
            .unwrap_err(),
        ConfigCapacityError::EncryptionFailed
    );
    assert_eq!(provider.calls(), 0);
    assert_eq!(
        encrypt_bounded_config_envelope_with_handle_and_nonce(
            &provider.handle,
            &metadata,
            b"{}",
            [8; 12]
        )
        .unwrap_err(),
        ConfigCapacityError::EncryptionFailed
    );
}

#[test]
fn bounded_encryption_preserves_legacy_encoding_for_identical_inputs() {
    let provider = Provider::new(Mode::Ready);
    let metadata = aad("writer");
    for plaintext in [b"null".as_slice(), b" [1,2] ", b"{\"a\":1}"] {
        let legacy = encrypt_attested_envelope_with_handle_and_nonce(
            &provider.handle,
            &metadata,
            plaintext,
            [3; 12],
        )
        .unwrap();
        let bounded = encrypt_bounded_config_envelope_with_handle_and_nonce(
            &provider.handle,
            &metadata,
            plaintext,
            [3; 12],
        )
        .unwrap();
        assert_eq!(bounded.encoded(), legacy.encoded());
        let legacy_claim = legacy.claim().unwrap();
        assert!(legacy_claim.capacity_evidence().is_none());
        assert!(legacy_claim.matches(bounded.encoded()));
        assert!(legacy_claim.matches_plaintext_digest(&Sha256::digest(plaintext)));
        assert_eq!(
            legacy.clone().claim().unwrap_err(),
            opc_crypto::CryptoError::EncryptionFailed
        );
        assert!(bounded.claim().unwrap().capacity_evidence().is_some());
        for digest in [vec![], vec![0; 31], vec![0; 32], vec![0; 33]] {
            assert!(!legacy_claim.matches_plaintext_digest(&digest));
        }
    }
    // Legacy accepts arbitrary non-JSON bytes; the opt-in contract rejects them.
    assert!(encrypt_attested_envelope_with_handle_and_nonce(
        &provider.handle,
        &metadata,
        b"\xff",
        [4; 12]
    )
    .is_ok());
    assert_eq!(
        encrypt_bounded_config_envelope_with_handle_and_nonce(
            &provider.handle,
            &metadata,
            b"\xff",
            [4; 12]
        )
        .unwrap_err(),
        ConfigCapacityError::InvalidPlaintext
    );
}
