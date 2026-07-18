use aes::{cipher::block_padding::NoPadding, Aes256};
use bytes::BytesMut;
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use hmac::{Hmac, Mac};
use opc_proto_ikev2::{
    build_ike_auth_cleartext_payload_chain, build_ike_sa_init_response,
    decode_ike_sa_init_request_payloads, derive_ike_sa_init_key_material,
    ikev2_aes_cbc_padding_len, ikev2_aes_cbc_protected_body_len, negotiate_ike_sa_init,
    open_protected_payloads, seal_ikev2_sa_init_aes_cbc_protected_payload, Ikev2DhGroup,
    Ikev2EncryptionAlgorithm, Ikev2EphemeralDhKey, Ikev2IkeAuthPayloadBuild,
    Ikev2IntegrityAlgorithm, Ikev2KeyExchangePayload, Ikev2KeyExchangePayloadBuild,
    Ikev2NoncePayload, Ikev2NoncePayloadBuild, Ikev2PrfAlgorithm, Ikev2ProtectedPayloadCryptoError,
    Ikev2ProtectedPayloadCryptoErrorCode, Ikev2ProtectedPayloadDirection,
    Ikev2ProtectedPayloadOpenError, Ikev2SaInitCryptoProfile, Ikev2SaInitNegotiationError,
    Ikev2SaInitNegotiationPolicy, Ikev2SaInitPayloads, Ikev2SaInitProtectedPayloadProvider,
    Ikev2SaInitResponsePayloads, Ikev2SaPayload, Ikev2SaProposal, Ikev2SaTransform,
    Ikev2TransformAttribute, Ikev2TransformAttributeValue, Message, PayloadType,
    ProtectedPayloadKind, ProtectedPayloadOpenError, ProtectedPayloadSealContext,
    EXCHANGE_TYPE_IKE_AUTH,
};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext};
use rand::{rngs::SysRng, TryRng};
use sha2::Sha512;

const INITIATOR_SPI: u64 = 0x0102_0304_0506_0708;
const RESPONDER_SPI: u64 = 0x1112_1314_1516_1718;
const TRANSFORM_TYPE_ENCR: u8 = 1;
const TRANSFORM_TYPE_PRF: u8 = 2;
const TRANSFORM_TYPE_INTEG: u8 = 3;
const TRANSFORM_TYPE_DH: u8 = 4;

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

/// Literal, synthetic capture-shaped IKE_SA_INIT request.
///
/// This is deliberately not emitted by the SDK SA builder. Its manual wire
/// shape is ENCR12(keylen 256), INTEG14, PRF7, DH14, followed by a 256-byte
/// group-14 public value, a 32-byte nonce, NAT detection, fragmentation,
/// signature-hash, redirect, and unknown non-critical private-use notifications.
fn synthetic_capture() -> Vec<u8> {
    decode_hex(concat!(
        "010203040506070800000000000000002120220800000000000001d7",
        "220000300000002c010100040300000c0100000c800e0100",
        "030000080300000e0300000802000007000000080400000e",
        "28000108000e0000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000002",
        "290000242122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40",
        "2900001c000040041111111111111111111111111111111111111111",
        "2900001c000040052222222222222222222222222222222222222222",
        "290000080000402e",
        "2900000c0000402f00020003",
        "2900000800004016",
        "0000000b0000fde8a1b2c3"
    ))
}

fn observed_profile() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
        Ikev2PrfAlgorithm::HmacSha2_512,
        Ikev2DhGroup::Modp2048,
        Ikev2EncryptionAlgorithm::AesCbc256,
        Ikev2IntegrityAlgorithm::HmacSha2_512_256,
    )
    .expect("observed synthetic profile is executable")
}

fn observed_policy() -> Ikev2SaInitNegotiationPolicy {
    Ikev2SaInitNegotiationPolicy::new(vec![observed_profile()])
        .expect("observed synthetic policy is valid")
}

fn decode_request(bytes: &[u8]) -> (Message<'_>, Ikev2SaInitPayloads<'_>) {
    let (tail, message) = Message::decode(bytes, DecodeContext::default())
        .expect("literal synthetic IKE_SA_INIT message decodes");
    assert!(tail.is_empty());
    let payloads = decode_ike_sa_init_request_payloads(&message, DecodeContext::default())
        .expect("literal synthetic IKE_SA_INIT payloads decode");
    (message, payloads)
}

fn encode_owned(message: &opc_proto_ikev2::OwnedMessage) -> Vec<u8> {
    let mut out = BytesMut::new();
    message
        .encode(&mut out, EncodeContext::default())
        .expect("synthetic message encodes");
    out.to_vec()
}

fn protected_prefix(
    direction: Ikev2ProtectedPayloadDirection,
    first_inner_payload: PayloadType,
    protected_body_len: usize,
) -> Vec<u8> {
    let payload_len = 4_usize
        .checked_add(protected_body_len)
        .expect("synthetic protected payload length");
    let message_len = 28_usize
        .checked_add(payload_len)
        .expect("synthetic protected message length");
    let payload_len = u16::try_from(payload_len).expect("synthetic payload length fits");
    let message_len = u32::try_from(message_len).expect("synthetic message length fits");

    let mut prefix = Vec::with_capacity(32);
    prefix.extend_from_slice(&INITIATOR_SPI.to_be_bytes());
    prefix.extend_from_slice(&RESPONDER_SPI.to_be_bytes());
    prefix.push(PayloadType::Encrypted.as_u8());
    prefix.push(0x20);
    prefix.push(EXCHANGE_TYPE_IKE_AUTH);
    prefix.push(match direction {
        Ikev2ProtectedPayloadDirection::InitiatorToResponder => 0x08,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator => 0x20,
    });
    prefix.extend_from_slice(&1_u32.to_be_bytes());
    prefix.extend_from_slice(&message_len.to_be_bytes());
    prefix.push(first_inner_payload.as_u8());
    prefix.push(0);
    prefix.extend_from_slice(&payload_len.to_be_bytes());
    prefix
}

fn seal_protected_message(
    profile: Ikev2SaInitCryptoProfile,
    material: &opc_proto_ikev2::Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
    first_inner_payload: PayloadType,
    cleartext: &[u8],
) -> Vec<u8> {
    let body_len = ikev2_aes_cbc_protected_body_len(profile, cleartext.len())
        .expect("CBC/HMAC protected body length");
    let prefix = protected_prefix(direction, first_inner_payload, body_len);
    let body = seal_ikev2_sa_init_aes_cbc_protected_payload(
        profile,
        material,
        direction,
        ProtectedPayloadSealContext {
            kind: ProtectedPayloadKind::Encrypted,
            message_prefix: &prefix,
        },
        cleartext,
    )
    .expect("production CSPRNG-bound CBC/HMAC sealing succeeds");
    let mut message = prefix;
    message.extend_from_slice(&body);
    message
}

fn open_protected_message(
    bytes: &[u8],
    profile: Ikev2SaInitCryptoProfile,
    material: &opc_proto_ikev2::Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
) -> Result<Vec<opc_proto_ikev2::OpenedProtectedPayload>, Ikev2ProtectedPayloadOpenError> {
    let (tail, message) = Message::decode(bytes, DecodeContext::default())
        .expect("synthetic outer protected message decodes");
    assert!(tail.is_empty());
    let provider = Ikev2SaInitProtectedPayloadProvider::new(profile, material, direction);
    open_protected_payloads(&message, bytes, DecodeContext::default(), &provider)
}

fn provider_error(error: &Ikev2ProtectedPayloadOpenError) -> &Ikev2ProtectedPayloadCryptoError {
    match error {
        ProtectedPayloadOpenError::ProviderRejected(failure) => &failure.provider_error,
        other => panic!("expected protected-payload provider rejection, got {other:?}"),
    }
}

fn independently_verify_and_open_cbc_sha512(
    message: &[u8],
    material: &opc_proto_ikev2::Ikev2SaInitKeyMaterial,
    direction: Ikev2ProtectedPayloadDirection,
) -> Vec<u8> {
    let (encryption_key, integrity_key) = match direction {
        Ikev2ProtectedPayloadDirection::InitiatorToResponder => {
            (material.sk_ei(), material.sk_ai())
        }
        Ikev2ProtectedPayloadDirection::ResponderToInitiator => {
            (material.sk_er(), material.sk_ar())
        }
    };
    assert_eq!(encryption_key.len(), 32);
    assert_eq!(integrity_key.len(), 64);
    assert_eq!(message[16], PayloadType::Encrypted.as_u8());
    assert!(message.len() >= 32 + 16 + 16 + 32);

    let icv_start = message.len() - 32;
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(integrity_key)
        .expect("independent HMAC-SHA2-512 key");
    mac.update(&message[..icv_start]);
    let expected_icv = mac.finalize().into_bytes();
    assert_eq!(&expected_icv[..32], &message[icv_start..]);

    let iv = &message[32..48];
    let mut plaintext = message[48..icv_start].to_vec();
    cbc::Decryptor::<Aes256>::new_from_slices(encryption_key, iv)
        .expect("independent AES-CBC-256 key and IV")
        .decrypt_padded::<NoPadding>(&mut plaintext)
        .expect("independent AES-CBC ciphertext alignment");
    let pad_len = usize::from(*plaintext.last().expect("independent IKE pad-length octet"));
    let cleartext_len = plaintext
        .len()
        .checked_sub(pad_len + 1)
        .expect("independent IKE padding fits plaintext");
    plaintext.truncate(cleartext_len);
    plaintext
}

fn cached_or_build_response<F>(cache: &mut Option<Vec<u8>>, build: F) -> Vec<u8>
where
    F: FnOnce() -> Vec<u8>,
{
    if let Some(response) = cache {
        return response.clone();
    }
    let response = build();
    *cache = Some(response.clone());
    response
}

#[test]
fn literal_capture_offsets_and_lengths_are_independently_self_consistent() {
    let fixture = synthetic_capture();
    assert_eq!(fixture.len(), 471);
    assert_eq!(u32::from_be_bytes(fixture[24..28].try_into().unwrap()), 471);
    assert_eq!(&fixture[..8], &INITIATOR_SPI.to_be_bytes());
    assert_eq!(&fixture[8..16], &[0; 8]);
    assert_eq!(&fixture[16..20], &[33, 0x20, 34, 0x08]);

    assert_eq!(u16::from_be_bytes(fixture[30..32].try_into().unwrap()), 48);
    assert_eq!(u16::from_be_bytes(fixture[34..36].try_into().unwrap()), 44);
    assert_eq!(&fixture[36..40], &[1, 1, 0, 4]);
    assert_eq!(
        (fixture[44], u16::from_be_bytes([fixture[46], fixture[47]])),
        (1, 12)
    );
    assert_eq!(
        (fixture[56], u16::from_be_bytes([fixture[58], fixture[59]])),
        (3, 14)
    );
    assert_eq!(
        (fixture[64], u16::from_be_bytes([fixture[66], fixture[67]])),
        (2, 7)
    );
    assert_eq!(
        (fixture[72], u16::from_be_bytes([fixture[74], fixture[75]])),
        (4, 14)
    );

    assert_eq!(u16::from_be_bytes(fixture[78..80].try_into().unwrap()), 264);
    assert_eq!(&fixture[80..84], &[0, 14, 0, 0]);
    assert_eq!(fixture[84..340].len(), 256);
    assert!(fixture[84..339].iter().all(|byte| *byte == 0));
    assert_eq!(fixture[339], 2);
    assert_eq!(
        u16::from_be_bytes(fixture[342..344].try_into().unwrap()),
        36
    );
    assert_eq!(fixture[344..376].len(), 32);

    for (offset, length, notify_type) in [
        (376, 28, 16_388),
        (404, 28, 16_389),
        (432, 8, 16_430),
        (440, 12, 16_431),
        (452, 8, 16_406),
        (460, 11, 65_000),
    ] {
        assert_eq!(
            usize::from(u16::from_be_bytes([
                fixture[offset + 2],
                fixture[offset + 3]
            ])),
            length
        );
        assert_eq!(
            u16::from_be_bytes([fixture[offset + 6], fixture[offset + 7]]),
            notify_type
        );
        assert_eq!(
            fixture[offset + 1] & 0x80,
            0,
            "fixture payload is non-critical"
        );
    }
    assert_eq!(
        fixture[460], 0,
        "unknown private-use notification ends the chain"
    );
}

#[test]
fn capture_shaped_responder_proof_reaches_bidirectional_protected_ike_auth() {
    let request_bytes = synthetic_capture();
    let (request, payloads) = decode_request(&request_bytes);
    assert_eq!(payloads.key_exchange.dh_group, 14);
    assert_eq!(payloads.key_exchange.key_exchange_data.len(), 256);
    assert_eq!(payloads.nonce.nonce.len(), 32);
    assert_eq!(
        payloads
            .notifies
            .iter()
            .map(|notify| notify.notify_message_type)
            .collect::<Vec<_>>(),
        [16_388, 16_389, 16_430, 16_431, 16_406, 65_000]
    );

    let selection =
        negotiate_ike_sa_init(&payloads, &observed_policy()).expect("capture-shaped suite selects");
    assert_eq!(selection.profile(), observed_profile());
    assert_eq!(
        selection
            .selected_proposal()
            .transforms
            .iter()
            .map(|transform| transform.transform_type)
            .collect::<Vec<_>>(),
        [
            TRANSFORM_TYPE_ENCR,
            TRANSFORM_TYPE_INTEG,
            TRANSFORM_TYPE_PRF,
            TRANSFORM_TYPE_DH
        ]
    );

    let responder_dh = Ikev2EphemeralDhKey::generate(selection.profile().dh_group())
        .expect("responder ephemeral DH material generates");
    let shared_secret = responder_dh
        .agree(payloads.key_exchange.key_exchange_data)
        .expect("responder accepts the synthetic group-14 public value");
    let mut responder_nonce = [0_u8; 32];
    SysRng
        .try_fill_bytes(&mut responder_nonce)
        .expect("responder nonce CSPRNG succeeds");
    let material = derive_ike_sa_init_key_material(
        selection.profile(),
        INITIATOR_SPI.to_be_bytes(),
        RESPONDER_SPI.to_be_bytes(),
        payloads.nonce.nonce,
        &responder_nonce,
        &shared_secret,
        None,
    )
    .expect("complete responder IKE-SA keys derive");
    assert_eq!(material.sk_d().len(), 64);
    assert_eq!(material.sk_ai().len(), 64);
    assert_eq!(material.sk_ar().len(), 64);
    assert_eq!(material.sk_ei().len(), 32);
    assert_eq!(material.sk_er().len(), 32);
    assert_eq!(material.sk_pi().len(), 64);
    assert_eq!(material.sk_pr().len(), 64);

    let response = build_ike_sa_init_response(
        &request.header,
        RESPONDER_SPI,
        &Ikev2SaInitResponsePayloads {
            security_association: selection.response_security_association(),
            key_exchange: Ikev2KeyExchangePayloadBuild {
                dh_group: selection.profile().dh_group().transform_id(),
                key_exchange_data: responder_dh.public_value().to_vec(),
            },
            nonce: Ikev2NoncePayloadBuild {
                nonce: responder_nonce.to_vec(),
            },
            notifies: Vec::new(),
        },
    )
    .expect("IKE_SA_INIT response builds");
    let response_bytes = encode_owned(&response);
    let (tail, decoded_response) = Message::decode(&response_bytes, DecodeContext::default())
        .expect("independent response decode succeeds");
    assert!(tail.is_empty());
    let mut response_payloads = decoded_response.payloads();
    let response_sa = Ikev2SaPayload::decode(
        response_payloads
            .next()
            .unwrap()
            .expect("response SA raw payload"),
    )
    .expect("response SA typed decode");
    let response_ke = Ikev2KeyExchangePayload::decode(
        response_payloads
            .next()
            .unwrap()
            .expect("response KE raw payload"),
    )
    .expect("response KE typed decode");
    let response_nonce = Ikev2NoncePayload::decode(
        response_payloads
            .next()
            .unwrap()
            .expect("response Nonce raw payload"),
    )
    .expect("response Nonce typed decode");
    assert!(response_payloads.next().is_none());
    assert_eq!(
        Ikev2SaInitCryptoProfile::from_proposal(&response_sa.proposals[0])
            .expect("selected response proposal is executable"),
        selection.profile()
    );
    assert_eq!(response_ke.dh_group, 14);
    assert_eq!(response_ke.key_exchange_data, responder_dh.public_value());
    assert_eq!(response_nonce.nonce, responder_nonce);

    let (request_first, request_cleartext) =
        build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::IdentificationInitiator,
            body: b"\x01\0\0\0synthetic-initiator".to_vec(),
        }])
        .expect("synthetic IKE_AUTH request cleartext builds");
    let protected_request = seal_protected_message(
        selection.profile(),
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        request_first,
        &request_cleartext,
    );
    assert_eq!(
        independently_verify_and_open_cbc_sha512(
            &protected_request,
            &material,
            Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        ),
        request_cleartext.as_ref()
    );
    let opened_request = open_protected_message(
        &protected_request,
        selection.profile(),
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    )
    .expect("responder authenticates and opens initiator IKE_AUTH");
    assert_eq!(
        opened_request[0].cleartext.as_ref(),
        request_cleartext.as_ref()
    );

    let (response_first, response_cleartext) =
        build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::IdentificationResponder,
            body: b"\x01\0\0\0synthetic-responder".to_vec(),
        }])
        .expect("synthetic IKE_AUTH response cleartext builds");
    let mut protected_response_cache = None;
    let mut protected_response_seals = 0_u8;
    let protected_response = cached_or_build_response(&mut protected_response_cache, || {
        protected_response_seals += 1;
        seal_protected_message(
            selection.profile(),
            &material,
            Ikev2ProtectedPayloadDirection::ResponderToInitiator,
            response_first,
            &response_cleartext,
        )
    });
    assert_eq!(
        independently_verify_and_open_cbc_sha512(
            &protected_response,
            &material,
            Ikev2ProtectedPayloadDirection::ResponderToInitiator,
        ),
        response_cleartext.as_ref()
    );
    let opened_response = open_protected_message(
        &protected_response,
        selection.profile(),
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
    )
    .expect("initiator authenticates and opens responder IKE_AUTH");
    assert_eq!(
        opened_response[0].cleartext.as_ref(),
        response_cleartext.as_ref()
    );

    for offset in [0, 32, 48, protected_request.len() - 1] {
        let mut corrupted = protected_request.clone();
        corrupted[offset] ^= 1;
        let error = open_protected_message(
            &corrupted,
            selection.profile(),
            &material,
            Ikev2ProtectedPayloadDirection::InitiatorToResponder,
        )
        .expect_err("header, IV, ciphertext, and ICV corruption must fail");
        assert_eq!(
            provider_error(&error),
            &Ikev2ProtectedPayloadCryptoError::AuthenticationFailed
        );
    }
    let wrong_direction = open_protected_message(
        &protected_request,
        selection.profile(),
        &material,
        Ikev2ProtectedPayloadDirection::ResponderToInitiator,
    )
    .expect_err("wrong-direction keys must fail");
    assert_eq!(
        provider_error(&wrong_direction),
        &Ikev2ProtectedPayloadCryptoError::AuthenticationFailed
    );

    let mut malformed_length = protected_request.clone();
    let icv_start = malformed_length.len() - selection.profile().integrity_icv_len();
    malformed_length.remove(icv_start - 1);
    let malformed_message_len = u32::try_from(malformed_length.len()).unwrap();
    malformed_length[24..28].copy_from_slice(&malformed_message_len.to_be_bytes());
    let malformed_payload_len = u16::try_from(malformed_length.len() - 28).unwrap();
    malformed_length[30..32].copy_from_slice(&malformed_payload_len.to_be_bytes());
    let error = open_protected_message(
        &malformed_length,
        selection.profile(),
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    )
    .expect_err("non-block-aligned ciphertext must fail safely");
    assert_eq!(
        provider_error(&error).code(),
        Ikev2ProtectedPayloadCryptoErrorCode::InvalidCiphertextLength
    );

    let mut invalid_padding = protected_request.clone();
    let icv_len = selection.profile().integrity_icv_len();
    let ciphertext_len = invalid_padding.len() - 32 - 16 - icv_len;
    let preceding_last_byte = if ciphertext_len == 16 {
        32 + 15
    } else {
        48 + ciphertext_len - 32 + 15
    };
    let valid_pad_len = ikev2_aes_cbc_padding_len(request_cleartext.len()).unwrap();
    invalid_padding[preceding_last_byte] ^= valid_pad_len ^ 0xff;
    let new_icv_start = invalid_padding.len() - icv_len;
    let mut mac =
        <Hmac<Sha512> as Mac>::new_from_slice(material.sk_ai()).expect("test HMAC key length");
    mac.update(&invalid_padding[..new_icv_start]);
    let icv = mac.finalize().into_bytes();
    invalid_padding[new_icv_start..].copy_from_slice(&icv[..icv_len]);
    let error = open_protected_message(
        &invalid_padding,
        selection.profile(),
        &material,
        Ikev2ProtectedPayloadDirection::InitiatorToResponder,
    )
    .expect_err("authenticated invalid padding must fail safely");
    assert_eq!(
        provider_error(&error).code(),
        Ikev2ProtectedPayloadCryptoErrorCode::InvalidPadding
    );

    let mut sa_init_response_cache = Some(response_bytes.clone());
    let mut responder_material_allocations = 1_u8;
    let replayed_sa_init_response = cached_or_build_response(&mut sa_init_response_cache, || {
        responder_material_allocations += 1;
        Vec::new()
    });
    assert_eq!(responder_material_allocations, 1);
    assert_eq!(replayed_sa_init_response, response_bytes);

    let replayed_ike_auth_response =
        cached_or_build_response(&mut protected_response_cache, || {
            protected_response_seals += 1;
            Vec::new()
        });
    assert_eq!(protected_response_seals, 1);
    assert_eq!(replayed_ike_auth_response, protected_response);
}

fn transform(
    transform_type: u8,
    transform_id: u16,
    attributes: Vec<Ikev2TransformAttribute<'static>>,
) -> Ikev2SaTransform<'static> {
    Ikev2SaTransform {
        transform_type,
        transform_id,
        attributes,
    }
}

fn payloads_with_transforms(
    transforms: Vec<Ikev2SaTransform<'static>>,
    ke_group: u16,
) -> Ikev2SaInitPayloads<'static> {
    static KE: [u8; 256] = {
        let mut value = [0_u8; 256];
        value[255] = 2;
        value
    };
    static NONCE: [u8; 32] = [0x44; 32];
    Ikev2SaInitPayloads {
        security_association: Ikev2SaPayload {
            proposals: vec![Ikev2SaProposal {
                proposal_number: 1,
                protocol_id: 1,
                spi_size: 0,
                spi: &[],
                transforms,
            }],
        },
        key_exchange: Ikev2KeyExchangePayload {
            dh_group: ke_group,
            key_exchange_data: &KE,
        },
        nonce: Ikev2NoncePayload { nonce: &NONCE },
        notifies: Vec::new(),
        vendor_ids: Vec::new(),
        other_payload_count: 0,
    }
}

fn observed_transforms() -> Vec<Ikev2SaTransform<'static>> {
    vec![
        transform(
            TRANSFORM_TYPE_ENCR,
            12,
            vec![Ikev2TransformAttribute {
                attribute_type: 14,
                value: Ikev2TransformAttributeValue::Tv(256),
            }],
        ),
        transform(TRANSFORM_TYPE_INTEG, 14, Vec::new()),
        transform(TRANSFORM_TYPE_PRF, 7, Vec::new()),
        transform(TRANSFORM_TYPE_DH, 14, Vec::new()),
    ]
}

#[test]
fn transform_order_and_well_formed_alternatives_do_not_change_selection() {
    let first = payloads_with_transforms(observed_transforms(), 14);
    let mut alternate_order = observed_transforms();
    alternate_order.swap(1, 2);
    alternate_order.insert(
        0,
        transform(
            TRANSFORM_TYPE_ENCR,
            12,
            vec![Ikev2TransformAttribute {
                attribute_type: 14,
                value: Ikev2TransformAttributeValue::Tv(128),
            }],
        ),
    );
    alternate_order.insert(
        1,
        transform(
            TRANSFORM_TYPE_PRF,
            7,
            vec![Ikev2TransformAttribute {
                attribute_type: 30_000,
                value: Ikev2TransformAttributeValue::Tlv(b"synthetic-unknown-attribute"),
            }],
        ),
    );
    let second = payloads_with_transforms(alternate_order, 14);

    let selected_first = negotiate_ike_sa_init(&first, &observed_policy()).unwrap();
    let selected_second = negotiate_ike_sa_init(&second, &observed_policy()).unwrap();
    assert_eq!(selected_first.profile(), selected_second.profile());
    assert_eq!(selected_second.selected_proposal().transforms.len(), 4);
    assert!(selected_second
        .selected_proposal()
        .transforms
        .iter()
        .any(|transform| transform.transform_type == TRANSFORM_TYPE_ENCR
            && transform.attributes[0].value
                == opc_proto_ikev2::Ikev2TransformAttributeBuildValue::Tv(256)));
}

#[test]
fn capability_policy_and_ke_length_fail_before_crypto_allocation() {
    assert_eq!(
        Ikev2SaInitNegotiationPolicy::new(Vec::new()).unwrap_err(),
        Ikev2SaInitNegotiationError::NoConfiguredProfiles
    );
    assert_eq!(
        Ikev2SaInitNegotiationPolicy::new(vec![observed_profile(), observed_profile()])
            .unwrap_err(),
        Ikev2SaInitNegotiationError::DuplicateConfiguredProfile
    );

    static SHORT_KE: [u8; 255] = [2; 255];
    let mut short = payloads_with_transforms(observed_transforms(), 14);
    short.key_exchange.key_exchange_data = &SHORT_KE;
    let error = negotiate_ike_sa_init(&short, &observed_policy()).unwrap_err();
    assert_eq!(
        error,
        Ikev2SaInitNegotiationError::InvalidKeyExchangeLength {
            dh_group: 14,
            expected: 256,
            actual: 255,
        }
    );

    let mut unknown_type = observed_transforms();
    unknown_type.push(transform(250, 1, Vec::new()));
    assert_eq!(
        negotiate_ike_sa_init(
            &payloads_with_transforms(unknown_type, 14),
            &observed_policy(),
        )
        .unwrap_err(),
        Ikev2SaInitNegotiationError::NoAcceptableProposal
    );

    let mut missing_integrity = observed_transforms();
    missing_integrity.retain(|transform| transform.transform_type != TRANSFORM_TYPE_INTEG);
    assert_eq!(
        negotiate_ike_sa_init(
            &payloads_with_transforms(missing_integrity, 14),
            &observed_policy(),
        )
        .unwrap_err(),
        Ikev2SaInitNegotiationError::NoAcceptableProposal
    );

    let mut invalid_number = payloads_with_transforms(observed_transforms(), 14);
    invalid_number.security_association.proposals[0].proposal_number = 0;
    assert_eq!(
        negotiate_ike_sa_init(&invalid_number, &observed_policy()).unwrap_err(),
        Ikev2SaInitNegotiationError::InvalidProposalNumber {
            actual: 0,
            expected: 1,
        }
    );

    static PROPOSAL_SPI: [u8; 4] = [1, 2, 3, 4];
    let mut unexpected_spi = payloads_with_transforms(observed_transforms(), 14);
    unexpected_spi.security_association.proposals[0].spi_size = 4;
    unexpected_spi.security_association.proposals[0].spi = &PROPOSAL_SPI;
    assert_eq!(
        negotiate_ike_sa_init(&unexpected_spi, &observed_policy()).unwrap_err(),
        Ikev2SaInitNegotiationError::UnexpectedIkeProposalSpi {
            proposal_number: 1,
            spi_len: 4,
        }
    );
}

#[test]
fn duplicate_or_contradictory_transforms_fail_closed() {
    let mut duplicate = observed_transforms();
    duplicate.push(transform(TRANSFORM_TYPE_PRF, 7, Vec::new()));
    let error = negotiate_ike_sa_init(&payloads_with_transforms(duplicate, 14), &observed_policy())
        .unwrap_err();
    assert!(matches!(
        error,
        Ikev2SaInitNegotiationError::DuplicateTransform { .. }
    ));
    assert_eq!(
        error.as_str(),
        "ike_sa_init_negotiation_duplicate_transform"
    );

    let mut duplicate_attribute = observed_transforms();
    duplicate_attribute[0]
        .attributes
        .push(Ikev2TransformAttribute {
            attribute_type: 14,
            value: Ikev2TransformAttributeValue::Tv(128),
        });
    let error = negotiate_ike_sa_init(
        &payloads_with_transforms(duplicate_attribute, 14),
        &observed_policy(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        Ikev2SaInitNegotiationError::DuplicateTransformAttribute { .. }
    ));
}

#[test]
fn unsupported_dh1_is_typed_no_acceptable_proposal_and_ke_mismatch_is_distinct() {
    let mut dh1 = observed_transforms();
    dh1[3].transform_id = 1;
    let no_proposal =
        negotiate_ike_sa_init(&payloads_with_transforms(dh1, 1), &observed_policy()).unwrap_err();
    assert_eq!(
        no_proposal,
        Ikev2SaInitNegotiationError::NoAcceptableProposal
    );
    assert!(no_proposal.is_no_acceptable_proposal());

    let mismatch = negotiate_ike_sa_init(
        &payloads_with_transforms(observed_transforms(), 19),
        &observed_policy(),
    )
    .unwrap_err();
    assert_eq!(
        mismatch,
        Ikev2SaInitNegotiationError::KeyExchangeDhGroupMismatch {
            received: 19,
            preferred: 14,
        }
    );
    assert!(!mismatch.is_no_acceptable_proposal());
}
