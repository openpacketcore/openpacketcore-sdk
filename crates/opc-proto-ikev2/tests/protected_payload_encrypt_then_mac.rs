use aes::{cipher::block_padding::NoPadding, Aes256};
use cbc::cipher::{BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, Mac};
use opc_proto_ikev2::{
    ikev2_aes_cbc_protected_body_len, ikev2_aes_cbc_protected_payload_len,
    ikev2_aes_gcm_protected_body_len, open_protected_payloads,
    seal_ikev2_sa_init_aes_cbc_protected_payload,
    seal_ikev2_sa_init_aes_cbc_protected_payload_with_iv_for_test_vector,
    seal_ikev2_sa_init_protected_payload, Ikev2DhGroup, Ikev2EncryptionAlgorithm,
    Ikev2IntegrityAlgorithm, Ikev2PrfAlgorithm, Ikev2ProtectedPayloadDirection,
    Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial, Ikev2SaInitProtectedPayloadProvider, Message,
    ProtectedPayloadKind, ProtectedPayloadOpenError, ProtectedPayloadSealContext,
};
use opc_protocol::{BorrowDecode, DecodeContext};
use sha2::Sha512;

const INITIATOR_SPI: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
const RESPONDER_SPI: [u8; 8] = [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];
const CBC_IV: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
];
const GCM_IV: [u8; 8] = [0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7];
const INNER_PAYLOAD: [u8; 8] = [0, 0, 0, 8, 1, 2, 3, 4];

fn cbc_profile(
    encryption: Ikev2EncryptionAlgorithm,
    integrity: Ikev2IntegrityAlgorithm,
) -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
        Ikev2PrfAlgorithm::HmacSha2_512,
        Ikev2DhGroup::Modp2048,
        encryption,
        integrity,
    )
    .expect("valid test CBC/HMAC profile")
}

fn gcm_192_profile() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_512,
        Ikev2DhGroup::Modp2048,
        Ikev2EncryptionAlgorithm::AesGcm16_192,
    )
    .expect("valid test AES-GCM-192 profile")
}

fn sequence(start: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|offset| start.wrapping_add(offset as u8))
        .collect()
}

fn established_material(profile: Ikev2SaInitCryptoProfile) -> Ikev2SaInitKeyMaterial {
    let prf_len = profile.prf().output_len();
    let integrity_len = profile.integrity_key_len();
    let encryption_len = profile.encryption().key_material_len();
    Ikev2SaInitKeyMaterial::from_established_keys(
        profile,
        false,
        &sequence(0xc0, prf_len),
        &sequence(0x00, integrity_len),
        &sequence(0x80, integrity_len),
        &sequence(0x40, encryption_len),
        &sequence(0xa0, encryption_len),
        &sequence(0x20, prf_len),
        &sequence(0x60, prf_len),
    )
    .expect("valid test established key material")
}

fn protected_prefix(
    kind: ProtectedPayloadKind,
    direction: Ikev2ProtectedPayloadDirection,
    crypto_body_len: usize,
    fragment_prefix: Option<[u8; 4]>,
    message_id: u32,
) -> Vec<u8> {
    let fixed_prefix = fragment_prefix.as_ref().map_or(&[][..], |value| &value[..]);
    assert_eq!(
        fixed_prefix.len(),
        match kind {
            ProtectedPayloadKind::Encrypted => 0,
            ProtectedPayloadKind::EncryptedFragment => 4,
        }
    );
    let payload_len = 4 + fixed_prefix.len() + crypto_body_len;
    let message_len = 28 + payload_len;
    let payload_len = u16::try_from(payload_len).expect("test payload length fits u16");
    let message_len = u32::try_from(message_len).expect("test message length fits u32");

    let mut prefix = Vec::with_capacity(32 + fixed_prefix.len());
    prefix.extend_from_slice(&INITIATOR_SPI);
    prefix.extend_from_slice(&RESPONDER_SPI);
    prefix.push(match kind {
        ProtectedPayloadKind::Encrypted => 46,
        ProtectedPayloadKind::EncryptedFragment => 53,
    });
    prefix.push(0x20);
    prefix.push(35);
    prefix.push(match direction {
        Ikev2ProtectedPayloadDirection::InitiatorToResponder => 0x08,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator => 0x20,
    });
    prefix.extend_from_slice(&message_id.to_be_bytes());
    prefix.extend_from_slice(&message_len.to_be_bytes());
    prefix.push(
        if fixed_prefix.first().copied() == Some(0) && fixed_prefix.get(1).copied().unwrap_or(1) > 1
        {
            0
        } else {
            35
        },
    );
    prefix.push(0);
    prefix.extend_from_slice(&payload_len.to_be_bytes());
    prefix.extend_from_slice(fixed_prefix);
    prefix
}

fn message(prefix: &[u8], crypto_body: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(prefix.len() + crypto_body.len());
    encoded.extend_from_slice(prefix);
    encoded.extend_from_slice(crypto_body);
    encoded
}

fn open(
    encoded: &[u8],
    profile: Ikev2SaInitCryptoProfile,
    material: &Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
) -> Result<Vec<opc_proto_ikev2::OpenedProtectedPayload>, ProtectedPayloadOpenError> {
    let (tail, decoded) = Message::decode(encoded, DecodeContext::default())
        .expect("synthetic protected message decodes");
    assert!(tail.is_empty());
    let provider = Ikev2SaInitProtectedPayloadProvider::new(profile, material, direction);
    open_protected_payloads(&decoded, encoded, DecodeContext::default(), &provider)
}

fn provider_error(error: &ProtectedPayloadOpenError) -> &str {
    match error {
        ProtectedPayloadOpenError::ProviderRejected(failure) => &failure.provider_error,
        other => panic!("expected provider rejection, got {other:?}"),
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
        .collect()
}

fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid synthetic hex fixture"),
    }
}

#[test]
fn cbc_sha512_opens_and_seals_independent_complete_message_vector() {
    // Independently generated with OpenSSL AES-256-CBC and HMAC-SHA512. The
    // literal final message makes incorrect IKE/SK Length fields or MAC coverage
    // fail rather than comparing two paths in this implementation.
    let expected = decode_hex(concat!(
        "010203040506070811121314151617182e202308000000010000006023000044",
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        "20c0fc6c0a479a0c6c084eae4dc1b303",
        "f247045d7dbfa00fea352a456097fd6db341db4b46adda5e55e2f1963953462b"
    ));
    let profile = cbc_profile(
        Ikev2EncryptionAlgorithm::AesCbc256,
        Ikev2IntegrityAlgorithm::HmacSha2_512_256,
    );
    let material = established_material(profile);

    let opened = open(
        &expected,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    )
    .expect("independent CBC/HMAC vector opens");
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].cleartext.as_ref(), INNER_PAYLOAD);

    assert_eq!(ikev2_aes_cbc_protected_body_len(profile, 8), Some(64));
    assert_eq!(ikev2_aes_cbc_protected_payload_len(profile, 8, 0), Some(68));
    let sealed = seal_ikev2_sa_init_aes_cbc_protected_payload_with_iv_for_test_vector(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        ProtectedPayloadSealContext {
            kind: ProtectedPayloadKind::Encrypted,
            message_prefix: &expected[..32],
        },
        &INNER_PAYLOAD,
        CBC_IV,
    )
    .expect("independent CBC/HMAC vector seals");
    assert_eq!(sealed.as_ref(), &expected[32..]);
}

#[test]
fn every_declared_cbc_key_size_and_sha2_integrity_roundtrips_both_directions() {
    let encryptions = [
        Ikev2EncryptionAlgorithm::AesCbc128,
        Ikev2EncryptionAlgorithm::AesCbc192,
        Ikev2EncryptionAlgorithm::AesCbc256,
    ];
    let integrities = [
        Ikev2IntegrityAlgorithm::HmacSha2_256_128,
        Ikev2IntegrityAlgorithm::HmacSha2_384_192,
        Ikev2IntegrityAlgorithm::HmacSha2_512_256,
    ];
    let directions = [
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
    ];

    for encryption in encryptions {
        for integrity in integrities {
            let profile = cbc_profile(encryption, integrity);
            let material = established_material(profile);
            let body_len = ikev2_aes_cbc_protected_body_len(profile, INNER_PAYLOAD.len())
                .expect("CBC body length");
            for direction in directions {
                let prefix = protected_prefix(
                    ProtectedPayloadKind::Encrypted,
                    direction,
                    body_len,
                    None,
                    u32::from(encryption.key_bits()) + u32::from(integrity.transform_id()),
                );
                let body = seal_ikev2_sa_init_aes_cbc_protected_payload_with_iv_for_test_vector(
                    profile,
                    &material,
                    direction,
                    ProtectedPayloadSealContext {
                        kind: ProtectedPayloadKind::Encrypted,
                        message_prefix: &prefix,
                    },
                    &INNER_PAYLOAD,
                    CBC_IV,
                )
                .expect("CBC/HMAC combination seals");
                let encoded = message(&prefix, &body);
                let opened = open(&encoded, profile, &material, direction)
                    .expect("CBC/HMAC combination opens");
                assert_eq!(opened[0].cleartext.as_ref(), INNER_PAYLOAD);
            }
        }
    }
}

#[test]
fn aes_gcm_192_is_executable_and_skf_uses_fragment_prefix_as_aad() {
    let profile = gcm_192_profile();
    let material = established_material(profile);
    let padding_len = 3;
    let body_len = ikev2_aes_gcm_protected_body_len(INNER_PAYLOAD.len(), padding_len)
        .expect("GCM body length");
    let fragment_prefix = [0, 1, 0, 2];
    let prefix = protected_prefix(
        ProtectedPayloadKind::EncryptedFragment,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        body_len,
        Some(fragment_prefix),
        9,
    );
    let body = seal_ikev2_sa_init_protected_payload(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        ProtectedPayloadSealContext {
            kind: ProtectedPayloadKind::EncryptedFragment,
            message_prefix: &prefix,
        },
        &INNER_PAYLOAD,
        padding_len,
        GCM_IV,
    )
    .expect("AES-GCM-192 SKF seals");
    let encoded = message(&prefix, &body);
    let opened = open(
        &encoded,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    )
    .expect("AES-GCM-192 SKF opens");
    assert_eq!(opened[0].kind, ProtectedPayloadKind::EncryptedFragment);
    assert_eq!(opened[0].cleartext.as_ref(), INNER_PAYLOAD);

    let mut tampered_fragment_total = encoded;
    tampered_fragment_total[35] = 3;
    let error = open(
        &tampered_fragment_total,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    )
    .expect_err("authenticated SKF fragment metadata tamper must fail");
    assert_eq!(
        provider_error(&error),
        "IKEv2 protected payload authentication failed"
    );
}

#[test]
fn cbc_skf_roundtrips_and_authenticates_fragment_metadata() {
    let profile = cbc_profile(
        Ikev2EncryptionAlgorithm::AesCbc256,
        Ikev2IntegrityAlgorithm::HmacSha2_512_256,
    );
    let material = established_material(profile);
    let body_len =
        ikev2_aes_cbc_protected_body_len(profile, INNER_PAYLOAD.len()).expect("CBC body length");
    let prefix = protected_prefix(
        ProtectedPayloadKind::EncryptedFragment,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        body_len,
        Some([0, 1, 0, 2]),
        10,
    );
    let body = seal_ikev2_sa_init_aes_cbc_protected_payload_with_iv_for_test_vector(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        ProtectedPayloadSealContext {
            kind: ProtectedPayloadKind::EncryptedFragment,
            message_prefix: &prefix,
        },
        &INNER_PAYLOAD,
        CBC_IV,
    )
    .expect("CBC/HMAC SKF seals");
    let encoded = message(&prefix, &body);
    let opened = open(
        &encoded,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
    )
    .expect("CBC/HMAC SKF opens");
    assert_eq!(opened[0].kind, ProtectedPayloadKind::EncryptedFragment);
    assert_eq!(opened[0].cleartext.as_ref(), INNER_PAYLOAD);

    let mut tampered = encoded;
    tampered[35] = 3;
    let error = open(
        &tampered,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
    )
    .expect_err("CBC SKF metadata tamper must fail");
    assert_eq!(
        provider_error(&error),
        "IKEv2 protected payload authentication failed"
    );
}

#[test]
fn cbc_authenticates_before_decrypt_and_rejects_wrong_direction_and_lengths() {
    let expected = decode_hex(concat!(
        "010203040506070811121314151617182e202308000000010000006023000044",
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
        "20c0fc6c0a479a0c6c084eae4dc1b303",
        "f247045d7dbfa00fea352a456097fd6db341db4b46adda5e55e2f1963953462b"
    ));
    let profile = cbc_profile(
        Ikev2EncryptionAlgorithm::AesCbc256,
        Ikev2IntegrityAlgorithm::HmacSha2_512_256,
    );
    let material = established_material(profile);

    for offset in [0, 32, 48, expected.len() - 1] {
        let mut corrupted = expected.clone();
        corrupted[offset] ^= 1;
        let error = open(
            &corrupted,
            profile,
            &material,
            Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        )
        .expect_err("CBC protected field corruption must fail");
        assert_eq!(
            provider_error(&error),
            "IKEv2 protected payload authentication failed"
        );
    }

    let wrong_direction = open(
        &expected,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
    )
    .expect_err("wrong directional keys must fail");
    assert_eq!(
        provider_error(&wrong_direction),
        "IKEv2 protected payload authentication failed"
    );

    let prefix = protected_prefix(
        ProtectedPayloadKind::Encrypted,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        65,
        None,
        11,
    );
    let mut malformed_body = Vec::new();
    malformed_body.extend_from_slice(&expected[32..48]);
    malformed_body.extend_from_slice(&expected[48..64]);
    malformed_body.push(0);
    malformed_body.extend_from_slice(&expected[64..]);
    let malformed = message(&prefix, &malformed_body);
    let error = open(
        &malformed,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    )
    .expect_err("non-block-aligned CBC ciphertext must fail");
    assert!(provider_error(&error).starts_with("invalid IKEv2 protected payload ciphertext length"));

    let truncated_iv_prefix = protected_prefix(
        ProtectedPayloadKind::Encrypted,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        8,
        None,
        14,
    );
    let truncated_iv = message(&truncated_iv_prefix, &[0_u8; 8]);
    let error = open(
        &truncated_iv,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    )
    .expect_err("truncated CBC IV must fail");
    assert_eq!(
        provider_error(&error),
        "invalid IKEv2 protected payload IV length: expected 16, actual 8"
    );
}

#[test]
fn authenticated_invalid_cbc_padding_is_rejected_without_an_oracle() {
    let profile = cbc_profile(
        Ikev2EncryptionAlgorithm::AesCbc256,
        Ikev2IntegrityAlgorithm::HmacSha2_512_256,
    );
    let material = established_material(profile);
    let prefix = protected_prefix(
        ProtectedPayloadKind::Encrypted,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        64,
        None,
        12,
    );
    let mut invalid_plaintext = [0_u8; 16];
    invalid_plaintext[15] = 0xff;
    cbc::Encryptor::<Aes256>::new_from_slices(material.sk_ei(), &CBC_IV)
        .expect("test AES-CBC key and IV")
        .encrypt_padded::<NoPadding>(&mut invalid_plaintext, 16)
        .expect("test invalid-padding plaintext encrypts");
    let mut body = Vec::new();
    body.extend_from_slice(&CBC_IV);
    body.extend_from_slice(&invalid_plaintext);
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(material.sk_ai()).expect("test HMAC key");
    mac.update(&prefix);
    mac.update(&body);
    body.extend_from_slice(&mac.finalize().into_bytes()[..32]);
    let encoded = message(&prefix, &body);

    let error = open(
        &encoded,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    )
    .expect_err("authenticated invalid IKE padding must fail");
    assert!(provider_error(&error).starts_with("invalid IKEv2 protected payload padding"));
}

#[test]
fn production_cbc_sealing_uses_fresh_ivs_and_cached_replay_is_byte_identical() {
    let profile = cbc_profile(
        Ikev2EncryptionAlgorithm::AesCbc256,
        Ikev2IntegrityAlgorithm::HmacSha2_512_256,
    );
    let material = established_material(profile);
    let body_len =
        ikev2_aes_cbc_protected_body_len(profile, INNER_PAYLOAD.len()).expect("CBC body length");
    let prefix = protected_prefix(
        ProtectedPayloadKind::Encrypted,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        body_len,
        None,
        13,
    );
    let first = seal_ikev2_sa_init_aes_cbc_protected_payload(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        ProtectedPayloadSealContext {
            kind: ProtectedPayloadKind::Encrypted,
            message_prefix: &prefix,
        },
        &INNER_PAYLOAD,
    )
    .expect("first production CBC seal");
    let cached_retransmission = first.clone();
    let second = seal_ikev2_sa_init_aes_cbc_protected_payload(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        ProtectedPayloadSealContext {
            kind: ProtectedPayloadKind::Encrypted,
            message_prefix: &prefix,
        },
        &INNER_PAYLOAD,
    )
    .expect("second production CBC seal");

    assert_ne!(&first[..16], &second[..16]);
    assert_eq!(cached_retransmission, first);
    for body in [&first, &second] {
        let encoded = message(&prefix, body);
        let opened = open(
            &encoded,
            profile,
            &material,
            Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        )
        .expect("production CBC body opens");
        assert_eq!(opened[0].cleartext.as_ref(), INNER_PAYLOAD);
    }
}
