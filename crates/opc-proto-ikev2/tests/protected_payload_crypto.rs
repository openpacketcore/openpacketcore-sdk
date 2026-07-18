use aes_gcm::{
    aead::{Aead, Key, KeyInit, Nonce, Payload},
    Aes128Gcm, Aes256Gcm,
};
use bytes::BytesMut;
use opc_proto_ikev2::{
    build_delete_payload_body, build_ike_auth_cleartext_payload_chain,
    decode_ike_auth_cleartext_payloads, decrypt_ikev2_sa_init_protected_payload,
    derive_ike_sa_init_key_material, ikev2_aes_gcm_protected_body_len,
    ikev2_aes_gcm_protected_payload_len, open_protected_payloads,
    seal_ikev2_sa_init_protected_payload, seal_ikev2_sa_init_protected_payload_with_iv_counter,
    Header, HeaderFlags, Ikev2AesGcmExplicitIvCounter, Ikev2DhGroup, Ikev2EncryptionAlgorithm,
    Ikev2IkeAuthPayloadBuild, Ikev2PrfAlgorithm, Ikev2ProtectedPayloadCryptoError,
    Ikev2ProtectedPayloadCryptoErrorCode, Ikev2ProtectedPayloadDirection,
    Ikev2ProtectedPayloadOpenError, Ikev2SaInitCryptoProfile, Ikev2SaInitProtectedPayloadProvider,
    Message, PayloadChain, PayloadType, ProtectedPayloadContext, ProtectedPayloadKind,
    ProtectedPayloadOpenError, ProtectedPayloadSealContext, EXCHANGE_TYPE_IKE_AUTH,
    EXCHANGE_TYPE_INFORMATIONAL, GENERIC_PAYLOAD_HEADER_LEN, HEADER_LEN, IKEV2_IPSEC_SPI_SIZE,
    IKEV2_SECURITY_PROTOCOL_ID_ESP,
};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext};

const INITIATOR_SPI: u64 = 0x0102_0304_0506_0708;
const RESPONDER_SPI: u64 = 0x1112_1314_1516_1718;
const MESSAGE_ID: u32 = 7;
const AES_GCM_SALT_LEN: usize = 4;
const AES_GCM_EXPLICIT_IV_LEN: usize = 8;
const AES_GCM_ICV_LEN: usize = 16;
const INNER_PAYLOAD: &[u8] = b"cleartext-inner-auth-payload";
const EXPLICIT_IV_I2R: [u8; AES_GCM_EXPLICIT_IV_LEN] =
    [0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87];
const EXPLICIT_IV_R2I: [u8; AES_GCM_EXPLICIT_IV_LEN] =
    [0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97];
const OUTER_NOTIFY_PAYLOAD_LEN: usize = GENERIC_PAYLOAD_HEADER_LEN + 4;

#[derive(Clone, Copy)]
struct ProtectedMessageShape {
    exchange_type: u8,
    first_inner_payload: PayloadType,
}

fn profile_128() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
    .expect("valid AES-GCM-128 IKE profile")
}

fn profile_256() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_384,
        Ikev2DhGroup::Ecp384,
        Ikev2EncryptionAlgorithm::AesGcm16_256,
    )
    .expect("valid AES-GCM-256 IKE profile")
}

fn key_material(profile: Ikev2SaInitCryptoProfile) -> opc_proto_ikev2::Ikev2SaInitKeyMaterial {
    match derive_ike_sa_init_key_material(
        profile,
        INITIATOR_SPI.to_be_bytes(),
        RESPONDER_SPI.to_be_bytes(),
        &[0x11; 32],
        &[0x22; 32],
        &[0x33; 48],
        None,
    ) {
        Ok(material) => material,
        Err(error) => panic!("test SA_INIT key material derivation failed: {error}"),
    }
}

fn encrypted_message(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &opc_proto_ikev2::Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
    inner_payload: &[u8],
    padding: &[u8],
    explicit_iv: [u8; AES_GCM_EXPLICIT_IV_LEN],
) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(inner_payload.len() + padding.len() + 1);
    plaintext.extend_from_slice(inner_payload);
    plaintext.extend_from_slice(padding);
    let pad_len = match u8::try_from(padding.len()) {
        Ok(value) => value,
        Err(error) => panic!("test padding length invalid: {error}"),
    };
    plaintext.push(pad_len);
    encrypted_message_with_plaintext(profile, key_material, direction, &plaintext, explicit_iv)
}

fn encrypted_message_with_plaintext(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &opc_proto_ikev2::Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
    plaintext: &[u8],
    explicit_iv: [u8; AES_GCM_EXPLICIT_IV_LEN],
) -> Vec<u8> {
    let protected_body_len = AES_GCM_EXPLICIT_IV_LEN + plaintext.len() + AES_GCM_ICV_LEN;
    let mut encoded =
        placeholder_message(protected_body_len, PayloadType::ExtensibleAuthentication);
    let protected_body_offset = HEADER_LEN + GENERIC_PAYLOAD_HEADER_LEN;
    let aad = &encoded[..protected_body_offset];
    let ciphertext_and_tag = encrypt_ciphertext_and_tag(
        profile,
        key_material,
        direction,
        aad,
        plaintext,
        explicit_iv,
    );

    let body_end = protected_body_offset + protected_body_len;
    let protected_body = match encoded.get_mut(protected_body_offset..body_end) {
        Some(body) => body,
        None => panic!("test protected body range missing"),
    };
    protected_body[..AES_GCM_EXPLICIT_IV_LEN].copy_from_slice(&explicit_iv);
    protected_body[AES_GCM_EXPLICIT_IV_LEN..].copy_from_slice(&ciphertext_and_tag);
    encoded
}

fn sealed_message(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &opc_proto_ikev2::Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
    inner_payload: &[u8],
    padding_len: u8,
    explicit_iv: [u8; AES_GCM_EXPLICIT_IV_LEN],
) -> Vec<u8> {
    sealed_message_for_exchange(
        profile,
        key_material,
        direction,
        ProtectedMessageShape {
            exchange_type: EXCHANGE_TYPE_IKE_AUTH,
            first_inner_payload: PayloadType::ExtensibleAuthentication,
        },
        inner_payload,
        padding_len,
        explicit_iv,
    )
}

fn sealed_message_for_exchange(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &opc_proto_ikev2::Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
    shape: ProtectedMessageShape,
    inner_payload: &[u8],
    padding_len: u8,
    explicit_iv: [u8; AES_GCM_EXPLICIT_IV_LEN],
) -> Vec<u8> {
    let protected_body_len = AES_GCM_EXPLICIT_IV_LEN
        + inner_payload.len()
        + usize::from(padding_len)
        + 1
        + AES_GCM_ICV_LEN;
    let mut encoded = placeholder_message_for_exchange(
        protected_body_len,
        shape.first_inner_payload,
        shape.exchange_type,
    );
    let protected_body_offset = HEADER_LEN + GENERIC_PAYLOAD_HEADER_LEN;
    let prefix = &encoded[..protected_body_offset];
    let protected_body = match seal_ikev2_sa_init_protected_payload(
        profile,
        key_material,
        direction,
        ProtectedPayloadSealContext {
            kind: ProtectedPayloadKind::Encrypted,
            message_prefix: prefix,
        },
        inner_payload,
        padding_len,
        explicit_iv,
    ) {
        Ok(body) => body,
        Err(error) => panic!("test protected payload seal failed: {error:?}"),
    };
    assert_eq!(protected_body.len(), protected_body_len);

    let body_end = protected_body_offset + protected_body_len;
    let target = match encoded.get_mut(protected_body_offset..body_end) {
        Some(body) => body,
        None => panic!("test protected body range missing"),
    };
    target.copy_from_slice(&protected_body);
    encoded
}

#[test]
fn protected_length_helpers_match_sealed_body_for_supported_profiles() {
    for (profile, direction, explicit_iv) in [
        (
            profile_128(),
            Ikev2ProtectedPayloadDirection::InitiatorToResponder,
            EXPLICIT_IV_I2R,
        ),
        (
            profile_256(),
            Ikev2ProtectedPayloadDirection::ResponderToInitiator,
            EXPLICIT_IV_R2I,
        ),
    ] {
        let material = key_material(profile);
        for padding_len in [0_u8, 7] {
            let expected_body_len =
                ikev2_aes_gcm_protected_body_len(INNER_PAYLOAD.len(), padding_len)
                    .expect("body length");
            let expected_payload_len =
                ikev2_aes_gcm_protected_payload_len(INNER_PAYLOAD.len(), padding_len)
                    .expect("payload length");
            let encoded =
                placeholder_message(expected_body_len, PayloadType::ExtensibleAuthentication);
            let prefix = &encoded[..HEADER_LEN + GENERIC_PAYLOAD_HEADER_LEN];
            let protected_body = seal_ikev2_sa_init_protected_payload(
                profile,
                &material,
                direction,
                ProtectedPayloadSealContext {
                    kind: ProtectedPayloadKind::Encrypted,
                    message_prefix: prefix,
                },
                INNER_PAYLOAD,
                padding_len,
                explicit_iv,
            )
            .expect("seal protected body");

            assert_eq!(protected_body.len(), expected_body_len);
            assert_eq!(
                expected_payload_len,
                GENERIC_PAYLOAD_HEADER_LEN + protected_body.len()
            );
        }
    }
}

#[test]
fn same_aes_gcm_key_and_explicit_iv_produces_identical_sealed_body() {
    let profile = profile_128();
    let material = key_material(profile);
    let encoded = placeholder_message(
        ikev2_aes_gcm_protected_body_len(INNER_PAYLOAD.len(), 0).unwrap(),
        PayloadType::ExtensibleAuthentication,
    );
    let prefix = &encoded[..HEADER_LEN + GENERIC_PAYLOAD_HEADER_LEN];
    let context = ProtectedPayloadSealContext {
        kind: ProtectedPayloadKind::Encrypted,
        message_prefix: prefix,
    };

    let first = seal_ikev2_sa_init_protected_payload(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        context,
        INNER_PAYLOAD,
        0,
        EXPLICIT_IV_I2R,
    )
    .expect("first seal succeeds");
    let second = seal_ikev2_sa_init_protected_payload(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        context,
        INNER_PAYLOAD,
        0,
        EXPLICIT_IV_I2R,
    )
    .expect("second seal succeeds");

    assert_eq!(first, second);
}

#[test]
fn explicit_iv_counter_restores_next_send_value_without_reuse() {
    let mut counter = Ikev2AesGcmExplicitIvCounter::new(0x0102_0304_0506_0708);

    assert_eq!(counter.next_value(), 0x0102_0304_0506_0708);
    assert_eq!(
        counter.next_explicit_iv().expect("first IV"),
        0x0102_0304_0506_0708_u64.to_be_bytes()
    );

    let persisted_next_value = counter.next_value();
    let mut restored = Ikev2AesGcmExplicitIvCounter::new(persisted_next_value);

    assert_eq!(
        restored.next_explicit_iv().expect("restored IV"),
        0x0102_0304_0506_0709_u64.to_be_bytes()
    );
    assert_eq!(restored.next_value(), 0x0102_0304_0506_070a);
}

#[test]
fn seal_with_iv_counter_persists_next_value_for_restore() {
    let profile = profile_128();
    let material = key_material(profile);
    let encoded = placeholder_message(
        ikev2_aes_gcm_protected_body_len(INNER_PAYLOAD.len(), 0).unwrap(),
        PayloadType::ExtensibleAuthentication,
    );
    let prefix = &encoded[..HEADER_LEN + GENERIC_PAYLOAD_HEADER_LEN];
    let context = ProtectedPayloadSealContext {
        kind: ProtectedPayloadKind::Encrypted,
        message_prefix: prefix,
    };
    let mut counter = Ikev2AesGcmExplicitIvCounter::new(0x0000_0000_0000_1000);

    let first = seal_ikev2_sa_init_protected_payload_with_iv_counter(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        context,
        INNER_PAYLOAD,
        0,
        &mut counter,
    )
    .expect("first seal succeeds");
    assert_eq!(&first[..AES_GCM_EXPLICIT_IV_LEN], &0x1000_u64.to_be_bytes());

    let persisted_next_value = counter.next_value();
    let mut restored = Ikev2AesGcmExplicitIvCounter::new(persisted_next_value);
    let second = seal_ikev2_sa_init_protected_payload_with_iv_counter(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        context,
        INNER_PAYLOAD,
        0,
        &mut restored,
    )
    .expect("restored seal succeeds");

    assert_eq!(
        &second[..AES_GCM_EXPLICIT_IV_LEN],
        &0x1001_u64.to_be_bytes()
    );
    assert_ne!(
        &first[..AES_GCM_EXPLICIT_IV_LEN],
        &second[..AES_GCM_EXPLICIT_IV_LEN]
    );
    assert_eq!(restored.next_value(), 0x0000_0000_0000_1002);
}

#[test]
fn explicit_iv_counter_fails_closed_before_wraparound() {
    let mut counter = Ikev2AesGcmExplicitIvCounter::new(u64::MAX);
    let err = counter
        .next_explicit_iv()
        .expect_err("counter must not wrap");

    assert_eq!(
        err.as_str(),
        "ike_protected_payload_crypto_explicit_iv_exhausted"
    );
    assert_eq!(counter.next_value(), u64::MAX);
}

fn encrypted_message_after_notify(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &opc_proto_ikev2::Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
    inner_payload: &[u8],
    explicit_iv: [u8; AES_GCM_EXPLICIT_IV_LEN],
) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(inner_payload.len() + 1);
    plaintext.extend_from_slice(inner_payload);
    plaintext.push(0);

    let protected_body_len = AES_GCM_EXPLICIT_IV_LEN + plaintext.len() + AES_GCM_ICV_LEN;
    let mut encoded = placeholder_message_after_notify(protected_body_len);
    let protected_body_offset = HEADER_LEN + OUTER_NOTIFY_PAYLOAD_LEN + GENERIC_PAYLOAD_HEADER_LEN;
    let aad = &encoded[..protected_body_offset];
    let ciphertext_and_tag = encrypt_ciphertext_and_tag(
        profile,
        key_material,
        direction,
        aad,
        &plaintext,
        explicit_iv,
    );

    let body_end = protected_body_offset + protected_body_len;
    let protected_body = match encoded.get_mut(protected_body_offset..body_end) {
        Some(body) => body,
        None => panic!("test protected body range missing"),
    };
    protected_body[..AES_GCM_EXPLICIT_IV_LEN].copy_from_slice(&explicit_iv);
    protected_body[AES_GCM_EXPLICIT_IV_LEN..].copy_from_slice(&ciphertext_and_tag);
    encoded
}

fn placeholder_message(protected_body_len: usize, first_inner_payload: PayloadType) -> Vec<u8> {
    placeholder_message_for_exchange(
        protected_body_len,
        first_inner_payload,
        EXCHANGE_TYPE_IKE_AUTH,
    )
}

fn placeholder_message_for_exchange(
    protected_body_len: usize,
    first_inner_payload: PayloadType,
    exchange_type: u8,
) -> Vec<u8> {
    let payload_len = match GENERIC_PAYLOAD_HEADER_LEN.checked_add(protected_body_len) {
        Some(value) => value,
        None => panic!("test payload length overflow"),
    };
    let payload_len_u16 = match u16::try_from(payload_len) {
        Ok(value) => value,
        Err(error) => panic!("test payload length invalid: {error}"),
    };

    let mut payload = Vec::with_capacity(payload_len);
    payload.push(first_inner_payload.as_u8());
    payload.push(0);
    payload.extend_from_slice(&payload_len_u16.to_be_bytes());
    payload.resize(payload_len, 0);

    let header = Header::new(
        INITIATOR_SPI,
        RESPONDER_SPI,
        PayloadType::Encrypted,
        exchange_type,
        HeaderFlags::from_bits(true, false, false),
        MESSAGE_ID,
    );
    let message = Message {
        header,
        payloads: PayloadChain::new(PayloadType::Encrypted, &payload),
        tail: &[],
    };

    let mut encoded = BytesMut::new();
    match message.encode(&mut encoded, EncodeContext::default()) {
        Ok(()) => encoded.to_vec(),
        Err(error) => panic!("test protected message encode failed: {error}"),
    }
}

fn placeholder_message_after_notify(protected_body_len: usize) -> Vec<u8> {
    let protected_payload_len = match GENERIC_PAYLOAD_HEADER_LEN.checked_add(protected_body_len) {
        Some(value) => value,
        None => panic!("test protected payload length overflow"),
    };
    let protected_payload_len_u16 = match u16::try_from(protected_payload_len) {
        Ok(value) => value,
        Err(error) => panic!("test protected payload length invalid: {error}"),
    };
    let total_payload_len = match OUTER_NOTIFY_PAYLOAD_LEN.checked_add(protected_payload_len) {
        Some(value) => value,
        None => panic!("test total payload length overflow"),
    };

    let mut payload = Vec::with_capacity(total_payload_len);
    payload.push(PayloadType::Encrypted.as_u8());
    payload.push(0);
    payload.extend_from_slice(&(OUTER_NOTIFY_PAYLOAD_LEN as u16).to_be_bytes());
    payload.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    payload.push(PayloadType::ExtensibleAuthentication.as_u8());
    payload.push(0);
    payload.extend_from_slice(&protected_payload_len_u16.to_be_bytes());
    payload.resize(total_payload_len, 0);

    let header = Header::new(
        INITIATOR_SPI,
        RESPONDER_SPI,
        PayloadType::Notify,
        EXCHANGE_TYPE_IKE_AUTH,
        HeaderFlags::from_bits(true, false, false),
        MESSAGE_ID,
    );
    let message = Message {
        header,
        payloads: PayloadChain::new(PayloadType::Notify, &payload),
        tail: &[],
    };

    let mut encoded = BytesMut::new();
    match message.encode(&mut encoded, EncodeContext::default()) {
        Ok(()) => encoded.to_vec(),
        Err(error) => panic!("test protected message encode failed: {error}"),
    }
}

fn encrypt_ciphertext_and_tag(
    profile: Ikev2SaInitCryptoProfile,
    key_material: &opc_proto_ikev2::Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
    aad: &[u8],
    plaintext: &[u8],
    explicit_iv: [u8; AES_GCM_EXPLICIT_IV_LEN],
) -> Vec<u8> {
    let sk_e = match direction {
        Ikev2ProtectedPayloadDirection::InitiatorToResponder => key_material.sk_ei(),
        Ikev2ProtectedPayloadDirection::ResponderToInitiator => key_material.sk_er(),
    };
    let encryption_key_len = match profile
        .encryption()
        .key_material_len()
        .checked_sub(AES_GCM_SALT_LEN)
    {
        Some(value) => value,
        None => panic!("test profile key material length underflow"),
    };
    let (encryption_key, salt) = sk_e.split_at(encryption_key_len);
    let mut nonce = [0_u8; AES_GCM_SALT_LEN + AES_GCM_EXPLICIT_IV_LEN];
    nonce[..AES_GCM_SALT_LEN].copy_from_slice(salt);
    nonce[AES_GCM_SALT_LEN..].copy_from_slice(&explicit_iv);
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    match profile.encryption() {
        Ikev2EncryptionAlgorithm::AesGcm16_128 => {
            let key = match <&Key<Aes128Gcm>>::try_from(encryption_key) {
                Ok(key) => key,
                Err(error) => panic!("test AES-GCM-128 key length failed: {error:?}"),
            };
            let nonce = match <&Nonce<Aes128Gcm>>::try_from(nonce.as_slice()) {
                Ok(nonce) => nonce,
                Err(error) => panic!("test AES-GCM-128 nonce length failed: {error:?}"),
            };
            let cipher = Aes128Gcm::new(key);
            match cipher.encrypt(nonce, payload) {
                Ok(bytes) => bytes,
                Err(error) => panic!("test AES-GCM-128 encryption failed: {error}"),
            }
        }
        Ikev2EncryptionAlgorithm::AesGcm16_256 => {
            let key = match <&Key<Aes256Gcm>>::try_from(encryption_key) {
                Ok(key) => key,
                Err(error) => panic!("test AES-GCM-256 key length failed: {error:?}"),
            };
            let nonce = match <&Nonce<Aes256Gcm>>::try_from(nonce.as_slice()) {
                Ok(nonce) => nonce,
                Err(error) => panic!("test AES-GCM-256 nonce length failed: {error:?}"),
            };
            let cipher = Aes256Gcm::new(key);
            match cipher.encrypt(nonce, payload) {
                Ok(bytes) => bytes,
                Err(error) => panic!("test AES-GCM-256 encryption failed: {error}"),
            }
        }
        unsupported => panic!("unsupported test encryption profile: {unsupported:?}"),
    }
}

fn decode_message(encoded: &[u8]) -> Message<'_> {
    let (tail, message) = match Message::decode(encoded, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("test protected message decode failed: {error:?}"),
    };
    assert!(tail.is_empty());
    message
}

fn open_with_provider(
    encoded: &[u8],
    profile: Ikev2SaInitCryptoProfile,
    key_material: &opc_proto_ikev2::Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
) -> Result<Vec<opc_proto_ikev2::OpenedProtectedPayload>, Ikev2ProtectedPayloadOpenError> {
    let message = decode_message(encoded);
    let provider = Ikev2SaInitProtectedPayloadProvider::new(profile, key_material, direction);
    open_protected_payloads(&message, encoded, DecodeContext::default(), &provider)
}

fn provider_rejection_code(
    error: &Ikev2ProtectedPayloadOpenError,
) -> Option<Ikev2ProtectedPayloadCryptoErrorCode> {
    match error {
        ProtectedPayloadOpenError::ProviderRejected(failure) => Some(failure.provider_error.code()),
        _ => None,
    }
}

#[test]
fn opens_initiator_to_responder_aes_gcm_128_payload() {
    let profile = profile_128();
    let material = key_material(profile);
    let encoded = encrypted_message(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        INNER_PAYLOAD,
        &[0xa0, 0xa1, 0xa2],
        EXPLICIT_IV_I2R,
    );

    let opened = match open_with_provider(
        &encoded,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    ) {
        Ok(opened) => opened,
        Err(error) => panic!("protected payload open failed: {error:?}"),
    };

    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].kind, ProtectedPayloadKind::Encrypted);
    assert_eq!(
        opened[0].first_inner_payload,
        PayloadType::ExtensibleAuthentication
    );
    assert_eq!(opened[0].cleartext.as_ref(), INNER_PAYLOAD);
}

#[test]
fn opens_responder_to_initiator_aes_gcm_256_payload() {
    let profile = profile_256();
    let material = key_material(profile);
    let encoded = encrypted_message(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        INNER_PAYLOAD,
        &[],
        EXPLICIT_IV_R2I,
    );

    let opened = match open_with_provider(
        &encoded,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
    ) {
        Ok(opened) => opened,
        Err(error) => panic!("protected payload open failed: {error:?}"),
    };

    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].cleartext.as_ref(), INNER_PAYLOAD);
}

#[test]
fn seals_responder_to_initiator_payload_that_public_opener_accepts() {
    let profile = profile_256();
    let material = key_material(profile);
    let encoded = sealed_message(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        INNER_PAYLOAD,
        2,
        EXPLICIT_IV_R2I,
    );

    let opened = match open_with_provider(
        &encoded,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
    ) {
        Ok(opened) => opened,
        Err(error) => panic!("sealed protected payload open failed: {error:?}"),
    };

    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].cleartext.as_ref(), INNER_PAYLOAD);
}

#[test]
fn seals_and_opens_empty_informational_request() {
    let profile = profile_128();
    let material = key_material(profile);
    let encoded = sealed_message_for_exchange(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        ProtectedMessageShape {
            exchange_type: EXCHANGE_TYPE_INFORMATIONAL,
            first_inner_payload: PayloadType::NoNext,
        },
        &[],
        0,
        EXPLICIT_IV_I2R,
    );
    let message = decode_message(&encoded);
    assert_eq!(message.header.exchange_type, EXCHANGE_TYPE_INFORMATIONAL);

    let opened = match open_with_provider(
        &encoded,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    ) {
        Ok(opened) => opened,
        Err(error) => panic!("empty INFORMATIONAL open failed: {error:?}"),
    };
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].first_inner_payload, PayloadType::NoNext);
    assert!(opened[0].cleartext.is_empty());
}

#[test]
fn seals_and_opens_informational_delete_payload() {
    let profile = profile_128();
    let material = key_material(profile);
    let child_spi = [0xde, 0xad, 0xbe, 0xef];
    let delete_body = build_delete_payload_body(
        IKEV2_SECURITY_PROTOCOL_ID_ESP,
        IKEV2_IPSEC_SPI_SIZE,
        &[&child_spi],
    )
    .expect("Delete body");
    let (first_inner_payload, cleartext) =
        build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Delete,
            body: delete_body,
        }])
        .expect("Delete cleartext chain");
    let encoded = sealed_message_for_exchange(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        ProtectedMessageShape {
            exchange_type: EXCHANGE_TYPE_INFORMATIONAL,
            first_inner_payload,
        },
        &cleartext,
        0,
        EXPLICIT_IV_I2R,
    );

    let opened = match open_with_provider(
        &encoded,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    ) {
        Ok(opened) => opened,
        Err(error) => panic!("Delete INFORMATIONAL open failed: {error:?}"),
    };
    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].first_inner_payload, PayloadType::Delete);

    let decoded = decode_ike_auth_cleartext_payloads(
        opened[0].first_inner_payload,
        opened[0].cleartext.as_ref(),
    )
    .expect("decode opened Delete");
    assert_eq!(decoded.deletes.len(), 1);
    assert_eq!(
        decoded.deletes[0].protocol_id,
        IKEV2_SECURITY_PROTOCOL_ID_ESP
    );
    assert_eq!(decoded.deletes[0].spis, vec![child_spi.as_slice()]);
}

#[test]
fn sealing_rejects_invalid_sk_and_skf_prefixes() {
    let profile = profile_128();
    let material = key_material(profile);
    let short_prefix = [0u8; HEADER_LEN + GENERIC_PAYLOAD_HEADER_LEN - 1];

    let invalid_aad = match seal_ikev2_sa_init_protected_payload(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        ProtectedPayloadSealContext {
            kind: ProtectedPayloadKind::Encrypted,
            message_prefix: &short_prefix,
        },
        INNER_PAYLOAD,
        0,
        EXPLICIT_IV_R2I,
    ) {
        Ok(_) => panic!("short AAD prefix must fail"),
        Err(error) => error,
    };
    assert_eq!(
        invalid_aad.as_str(),
        "ike_protected_payload_crypto_invalid_aad"
    );

    let invalid_skf = match seal_ikev2_sa_init_protected_payload(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        ProtectedPayloadSealContext {
            kind: ProtectedPayloadKind::EncryptedFragment,
            message_prefix: &[0u8; HEADER_LEN + GENERIC_PAYLOAD_HEADER_LEN],
        },
        INNER_PAYLOAD,
        0,
        EXPLICIT_IV_R2I,
    ) {
        Ok(_) => panic!("SKF sealing with a missing fragment prefix must fail"),
        Err(error) => error,
    };
    assert_eq!(
        invalid_skf.as_str(),
        "ike_protected_payload_crypto_invalid_aad"
    );
}

#[test]
fn opens_protected_payload_after_unencrypted_prefix_using_payload_offset() {
    let profile = profile_128();
    let material = key_material(profile);
    let encoded = encrypted_message_after_notify(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        INNER_PAYLOAD,
        EXPLICIT_IV_I2R,
    );

    let opened = match open_with_provider(
        &encoded,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    ) {
        Ok(opened) => opened,
        Err(error) => panic!("protected payload open failed: {error:?}"),
    };

    assert_eq!(opened.len(), 1);
    assert_eq!(opened[0].offset, OUTER_NOTIFY_PAYLOAD_LEN);
    assert_eq!(opened[0].cleartext.as_ref(), INNER_PAYLOAD);
}

#[test]
fn rejects_wrong_direction_wrong_aad_and_tampered_body_or_tag() {
    let profile = profile_128();
    let material = key_material(profile);
    let encoded = encrypted_message(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        INNER_PAYLOAD,
        &[],
        EXPLICIT_IV_I2R,
    );

    let wrong_direction = match open_with_provider(
        &encoded,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
    ) {
        Ok(opened) => panic!("wrong direction unexpectedly opened: {opened:?}"),
        Err(error) => error,
    };
    assert_eq!(
        provider_rejection_code(&wrong_direction),
        Some(Ikev2ProtectedPayloadCryptoErrorCode::AuthenticationFailed)
    );

    let decoded = decode_message(&encoded);
    let provider = Ikev2SaInitProtectedPayloadProvider::new(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    );
    let mut wrong_aad = encoded.clone();
    wrong_aad[23] ^= 0x01;
    let wrong_aad_error =
        match open_protected_payloads(&decoded, &wrong_aad, DecodeContext::default(), &provider) {
            Ok(opened) => panic!("wrong AAD unexpectedly opened: {opened:?}"),
            Err(error) => error,
        };
    assert_eq!(
        provider_rejection_code(&wrong_aad_error),
        Some(Ikev2ProtectedPayloadCryptoErrorCode::AuthenticationFailed)
    );

    let mut tampered_ciphertext = encoded.clone();
    tampered_ciphertext[HEADER_LEN + GENERIC_PAYLOAD_HEADER_LEN + AES_GCM_EXPLICIT_IV_LEN] ^= 0x01;
    let tampered_ciphertext_error = match open_with_provider(
        &tampered_ciphertext,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    ) {
        Ok(opened) => panic!("tampered ciphertext unexpectedly opened: {opened:?}"),
        Err(error) => error,
    };
    assert_eq!(
        provider_rejection_code(&tampered_ciphertext_error),
        Some(Ikev2ProtectedPayloadCryptoErrorCode::AuthenticationFailed)
    );

    let mut tampered_tag = encoded.clone();
    let last = match tampered_tag.last_mut() {
        Some(byte) => byte,
        None => panic!("test message unexpectedly empty"),
    };
    *last ^= 0x01;
    let tampered_tag_error = match open_with_provider(
        &tampered_tag,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    ) {
        Ok(opened) => panic!("tampered tag unexpectedly opened: {opened:?}"),
        Err(error) => error,
    };
    assert_eq!(
        provider_rejection_code(&tampered_tag_error),
        Some(Ikev2ProtectedPayloadCryptoErrorCode::AuthenticationFailed)
    );
}

#[test]
fn rejects_invalid_padding_after_authenticated_decryption() {
    let profile = profile_128();
    let material = key_material(profile);
    let encoded = encrypted_message_with_plaintext(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        &[0xa0, 0x03],
        EXPLICIT_IV_I2R,
    );

    let error = match open_with_provider(
        &encoded,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    ) {
        Ok(opened) => panic!("invalid padding unexpectedly opened: {opened:?}"),
        Err(error) => error,
    };

    assert_eq!(
        provider_rejection_code(&error),
        Some(Ikev2ProtectedPayloadCryptoErrorCode::InvalidPadding)
    );
    let debug = format!("{error:?}");
    assert!(!debug.contains("cleartext-inner-auth-payload"));
}

#[test]
fn rejects_short_body_malformed_skf_and_profile_key_mismatch_with_stable_codes() {
    let profile = profile_128();
    let material = key_material(profile);
    let short = placeholder_message(4, PayloadType::ExtensibleAuthentication);
    let short_error = match open_with_provider(
        &short,
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    ) {
        Ok(opened) => panic!("short body unexpectedly opened: {opened:?}"),
        Err(error) => error,
    };
    match short_error {
        ProtectedPayloadOpenError::ProviderRejected(failure) => {
            assert_eq!(
                failure.provider_error,
                Ikev2ProtectedPayloadCryptoError::ProtectedPayloadTooShort {
                    min_len: 24,
                    actual: 4,
                }
            );
        }
        other => panic!("unexpected short-body error: {other:?}"),
    }

    let header = Header::new(
        INITIATOR_SPI,
        RESPONDER_SPI,
        PayloadType::EncryptedFragment,
        EXCHANGE_TYPE_IKE_AUTH,
        HeaderFlags::from_bits(false, true, false),
        MESSAGE_ID,
    );
    let context = ProtectedPayloadContext {
        header: &header,
        kind: ProtectedPayloadKind::EncryptedFragment,
        first_inner_payload: PayloadType::ExtensibleAuthentication,
        payload_offset: 0,
        message_bytes: &[],
    };
    let malformed_skf = match decrypt_ikev2_sa_init_protected_payload(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        context,
        &[],
    ) {
        Ok(opened) => panic!("malformed SKF unexpectedly opened: {opened:?}"),
        Err(error) => error,
    };
    assert_eq!(
        malformed_skf.as_str(),
        "ike_protected_payload_crypto_invalid_aad"
    );

    let mismatch_profile = profile_256();
    let context = valid_context(&short, &header);
    let mismatch = match decrypt_ikev2_sa_init_protected_payload(
        mismatch_profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        context,
        &short[HEADER_LEN + GENERIC_PAYLOAD_HEADER_LEN..],
    ) {
        Ok(opened) => panic!("profile/key mismatch unexpectedly opened: {opened:?}"),
        Err(error) => error,
    };
    assert_eq!(
        mismatch.as_str(),
        "ike_protected_payload_crypto_invalid_key_length"
    );
}

fn valid_context<'a>(message_bytes: &'a [u8], header: &'a Header) -> ProtectedPayloadContext<'a> {
    ProtectedPayloadContext {
        header,
        kind: ProtectedPayloadKind::Encrypted,
        first_inner_payload: PayloadType::ExtensibleAuthentication,
        payload_offset: 0,
        message_bytes,
    }
}

#[test]
fn error_debug_display_and_provider_debug_are_redaction_safe() {
    let profile = profile_128();
    let material = key_material(profile);
    let encoded = encrypted_message(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        b"super-secret-cleartext-AUTH-bytes",
        &[],
        EXPLICIT_IV_I2R,
    );
    let header = Header::new(
        INITIATOR_SPI,
        RESPONDER_SPI,
        PayloadType::Encrypted,
        EXCHANGE_TYPE_IKE_AUTH,
        HeaderFlags::from_bits(true, false, false),
        MESSAGE_ID,
    );
    let context = valid_context(&encoded, &header);
    let error = match decrypt_ikev2_sa_init_protected_payload(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        context,
        b"ciphertext-secret-AUTH-bytes",
    ) {
        Ok(opened) => panic!("mismatched body unexpectedly opened: {opened:?}"),
        Err(error) => error,
    };
    assert_eq!(error.as_str(), "ike_protected_payload_crypto_invalid_aad");

    let provider = Ikev2SaInitProtectedPayloadProvider::new(
        profile,
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    );
    let combined = format!("{error:?} {error} {provider:?}");
    assert!(!combined.contains("super-secret-cleartext"));
    assert!(!combined.contains("ciphertext-secret"));
    assert!(!combined.contains("AUTH-bytes"));
    assert!(!combined.contains("01020304"));
}

#[test]
fn direct_error_codes_match_variants() {
    let errors = [
        Ikev2ProtectedPayloadCryptoError::ProtectedPayloadTooShort {
            min_len: 24,
            actual: 1,
        },
        Ikev2ProtectedPayloadCryptoError::AuthenticationFailed,
        Ikev2ProtectedPayloadCryptoError::InvalidAssociatedData,
        Ikev2ProtectedPayloadCryptoError::InvalidPadding {
            plaintext_len: 1,
            pad_len: 2,
        },
        Ikev2ProtectedPayloadCryptoError::ExplicitIvExhausted,
    ];

    let codes: Vec<&'static str> = errors.iter().map(|error| error.as_str()).collect();
    assert_eq!(
        codes,
        vec![
            "ike_protected_payload_crypto_body_too_short",
            "ike_protected_payload_crypto_authentication_failed",
            "ike_protected_payload_crypto_invalid_aad",
            "ike_protected_payload_crypto_invalid_padding",
            "ike_protected_payload_crypto_explicit_iv_exhausted",
        ]
    );
}
