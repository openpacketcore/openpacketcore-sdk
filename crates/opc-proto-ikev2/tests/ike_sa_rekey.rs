use opc_proto_ikev2::{
    build_ike_auth_cleartext_payload_chain, build_ike_auth_notify_payload,
    build_ike_auth_sa_payload, build_ike_sa_rekey_request, build_ike_sa_rekey_response,
    decode_ike_sa_rekey_request, decode_ike_sa_rekey_request_with_context,
    decode_ike_sa_rekey_response, decode_ike_sa_rekey_response_with_context,
    decode_ikev2_dedicated_bearer_create_child_sa_request, derive_ike_sa_rekey_key_material,
    negotiate_ike_sa_rekey, Header, HeaderFlags, Ikev2DhGroup, Ikev2EncryptionAlgorithm,
    Ikev2IkeAuthPayloadBuild, Ikev2IkeSaRekeyBuildError, Ikev2IkeSaRekeyPayloadRole,
    Ikev2IkeSaRekeyRequestBuild, Ikev2IkeSaRekeyRequestBuildError, Ikev2IkeSaRekeyRequestError,
    Ikev2IkeSaRekeyResponseBuild, Ikev2IkeSaRekeyResponseError, Ikev2IkeSaRekeySentRequest,
    Ikev2IntegrityAlgorithm, Ikev2KeyExchangePayloadBuild, Ikev2NoncePayloadBuild,
    Ikev2NoncePayloadError, Ikev2NotifyPayloadBuild, Ikev2PrfAlgorithm, Ikev2SaInitBuildError,
    Ikev2SaInitCryptoError, Ikev2SaInitCryptoProfile, Ikev2SaInitNegotiationError,
    Ikev2SaInitNegotiationPolicy, Ikev2SaPayload, Ikev2SaPayloadBuild, Ikev2SaProposalBuild,
    Ikev2SaTransformBuild, Ikev2TransformAttributeBuild, Ikev2TransformAttributeBuildValue,
    PayloadChain, PayloadType, EXCHANGE_TYPE_CREATE_CHILD_SA, EXCHANGE_TYPE_IKE_AUTH,
    IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, IKEV2_NOTIFY_PROTOCOL_ID_NONE, IKEV2_NOTIFY_REKEY_SA,
    IKEV2_NOTIFY_TEMPORARY_FAILURE, IKEV2_SECURITY_PROTOCOL_ID_AH, IKEV2_SECURITY_PROTOCOL_ID_ESP,
    IKEV2_SECURITY_PROTOCOL_ID_IKE,
};
use opc_protocol::{DecodeContext, UnknownIePolicy};

mod support;

const CURRENT_INITIATOR_SPI: u64 = 0x0102_0304_0506_0708;
const CURRENT_RESPONDER_SPI: u64 = 0x1112_1314_1516_1718;
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

fn request_header() -> Header {
    Header::new(
        CURRENT_INITIATOR_SPI,
        CURRENT_RESPONDER_SPI,
        PayloadType::Encrypted,
        EXCHANGE_TYPE_CREATE_CHILD_SA,
        HeaderFlags::from_bits(true, false, false),
        7,
    )
}

/// Specification-authored AEAD opened request bytes.
///
/// SA: IKE SPI 01..08, ENCR_AES_GCM_16/128, PRF-SHA2-256, DH19.
/// Ni: 32 literal octets. KEi: fixed-width 64-octet ECP coordinate pair.
fn aead_request_vector() -> Vec<u8> {
    let mut bytes = decode_hex(concat!(
        // SA generic header and one 44-octet Proposal.
        "28000030",
        "0000002c01010803",
        "0102030405060708",
        "0300000c01000014800e0080",
        "0300000802000005",
        "0000000804000013",
        // Ni generic header and 32-octet nonce.
        "22000024",
        "1112131415161718191a1b1c1d1e1f20",
        "2122232425262728292a2b2c2d2e2f30",
        // KEi generic header, DH19, and sender-zero reserved field.
        "00000048",
        "00130000",
    ));
    bytes.extend_from_slice(&[0x41; 64]);
    assert_eq!(bytes.len(), 156);
    bytes
}

/// Specification-authored AES-CBC/HMAC opened request bytes.
///
/// SA: IKE SPI 11..18, AES-CBC-256, HMAC-SHA2-512-256, PRF-SHA2-512,
/// DH14. Ni is 32 octets and KEi is a 256-octet MODP public value.
fn encrypt_then_mac_request_vector() -> Vec<u8> {
    let mut bytes = decode_hex(concat!(
        "28000038",
        "0000003401010804",
        "1112131415161718",
        "0300000c0100000c800e0100",
        "030000080300000e",
        "0300000802000007",
        "000000080400000e",
        "22000024",
        "3132333435363738393a3b3c3d3e3f40",
        "4142434445464748494a4b4c4d4e4f50",
        "00000108",
        "000e0000",
    ));
    bytes.extend_from_slice(&[0x61; 256]);
    assert_eq!(bytes.len(), 356);
    bytes
}

fn aead_profile() -> Ikev2SaInitCryptoProfile {
    support::ensure_ike_crypto();
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
    .expect("synthetic AEAD profile is executable")
}

fn encrypt_then_mac_profile() -> Ikev2SaInitCryptoProfile {
    support::ensure_ike_crypto();
    Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
        Ikev2PrfAlgorithm::HmacSha2_512,
        Ikev2DhGroup::Modp2048,
        Ikev2EncryptionAlgorithm::AesCbc256,
        Ikev2IntegrityAlgorithm::HmacSha2_512_256,
    )
    .expect("synthetic encrypt-then-MAC profile is executable")
}

fn policy(profile: Ikev2SaInitCryptoProfile) -> Ikev2SaInitNegotiationPolicy {
    Ikev2SaInitNegotiationPolicy::new(vec![profile]).expect("synthetic policy is valid")
}

fn aead_response_vector() -> Vec<u8> {
    let mut bytes = decode_hex(concat!(
        "28000030",
        "0000002c01010803",
        "a1a2a3a4a5a6a7a8",
        "0300000c01000014800e0080",
        "0300000802000005",
        "0000000804000013",
        "22000024",
        "b1b2b3b4b5b6b7b8b9babbbcbdbebfc0",
        "c1c2c3c4c5c6c7c8c9cacbcccdcecfd0",
        "00000048",
        "00130000",
    ));
    bytes.extend_from_slice(&[0x71; 64]);
    assert_eq!(bytes.len(), 156);
    bytes
}

fn encrypt_then_mac_response_vector() -> Vec<u8> {
    let mut bytes = decode_hex(concat!(
        "28000038",
        "0000003401010804",
        "b1b2b3b4b5b6b7b8",
        "0300000c0100000c800e0100",
        "030000080300000e",
        "0300000802000007",
        "000000080400000e",
        "22000024",
        "7172737475767778797a7b7c7d7e7f80",
        "8182838485868788898a8b8c8d8e8f90",
        "00000108",
        "000e0000",
    ));
    bytes.extend_from_slice(&[0x81; 256]);
    assert_eq!(bytes.len(), 356);
    bytes
}

#[test]
fn independent_aead_vector_decodes_selects_kdf_profile_and_builds_exact_response() {
    let request_bytes = aead_request_vector();
    let header = request_header();
    let request =
        decode_ike_sa_rekey_request(&header, PayloadType::SecurityAssociation, &request_bytes)
            .expect("literal AEAD IKE-SA rekey request decodes");

    assert_eq!(request.security_association().proposals.len(), 1);
    let proposal = &request.security_association().proposals[0];
    assert_eq!(proposal.protocol_id, IKEV2_SECURITY_PROTOCOL_ID_IKE);
    assert_eq!(proposal.spi.len(), 8);
    assert_eq!(request.nonce().nonce.len(), 32);
    assert_eq!(request.key_exchange().dh_group, 19);
    assert_eq!(request.key_exchange().key_exchange_data.len(), 64);

    let profile = aead_profile();
    let negotiation = negotiate_ike_sa_rekey(&request, &policy(profile))
        .expect("AEAD rekey proposal is selected");
    assert_eq!(negotiation.profile(), profile);
    assert_eq!(negotiation.new_initiator_spi(), [1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(negotiation.selected_proposal().spi.len(), 8);

    let response_nonce = decode_hex(concat!(
        "b1b2b3b4b5b6b7b8b9babbbcbdbebfc0",
        "c1c2c3c4c5c6c7c8c9cacbcccdcecfd0",
    ));
    let responder_public = vec![0x71; 64];
    let new_responder_spi = [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8];

    let key_material = derive_ike_sa_rekey_key_material(
        Ikev2PrfAlgorithm::HmacSha2_256,
        &[0x91; 32],
        negotiation.profile(),
        negotiation.new_initiator_spi(),
        new_responder_spi,
        request.nonce().nonce,
        &response_nonce,
        &[0x92; 32],
    )
    .expect("selected profile passes directly to the existing rekey KDF");
    assert_eq!(key_material.sk_d().len(), 32);

    let build = Ikev2IkeSaRekeyResponseBuild {
        negotiation,
        new_responder_spi,
        nonce: Ikev2NoncePayloadBuild {
            nonce: response_nonce,
        },
        key_exchange: Ikev2KeyExchangePayloadBuild {
            dh_group: 19,
            key_exchange_data: responder_public,
        },
    };
    let response = build_ike_sa_rekey_response(&build).expect("AEAD response builds");
    assert_eq!(response.first_payload(), PayloadType::SecurityAssociation);
    assert_eq!(response.bytes().as_ref(), aead_response_vector());
    assert_eq!(
        payload_types(response.first_payload(), response.bytes()),
        vec![
            PayloadType::SecurityAssociation,
            PayloadType::Nonce,
            PayloadType::KeyExchange,
        ]
    );

    let debug = format!("{request:?} {build:?} {response:?}");
    assert!(!debug.contains("0102030405060708"));
    assert!(!debug.contains("b1b2b3b4"));
    assert!(!debug.contains("71717171"));
    assert!(!debug.contains("[1, 2, 3, 4, 5, 6, 7, 8]"));
    assert!(!debug.contains("[161, 162, 163, 164"));
    assert!(!debug.contains("[177, 178, 179, 180"));
    assert!(!debug.contains("[113, 113, 113, 113"));
    assert!(debug.contains("nonce_len"));
    assert!(debug.contains("key_exchange_data_len"));
}

#[test]
fn independent_encrypt_then_mac_vector_decodes_selects_and_builds_exact_response() {
    let request_bytes = encrypt_then_mac_request_vector();
    let header = request_header();
    let request =
        decode_ike_sa_rekey_request(&header, PayloadType::SecurityAssociation, &request_bytes)
            .expect("literal encrypt-then-MAC IKE-SA rekey request decodes");
    let profile = encrypt_then_mac_profile();
    let negotiation = negotiate_ike_sa_rekey(&request, &policy(profile))
        .expect("encrypt-then-MAC rekey proposal is selected");

    assert_eq!(negotiation.profile(), profile);
    assert_eq!(
        negotiation.new_initiator_spi(),
        [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
    );
    assert_eq!(negotiation.selected_proposal().transforms.len(), 4);

    let response_nonce = decode_hex(concat!(
        "7172737475767778797a7b7c7d7e7f80",
        "8182838485868788898a8b8c8d8e8f90",
    ));
    let new_responder_spi = [0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8];
    let shared_secret = vec![0x94; Ikev2DhGroup::Modp2048.shared_secret_len()];
    let key_material = derive_ike_sa_rekey_key_material(
        Ikev2PrfAlgorithm::HmacSha2_256,
        &[0x93; 32],
        negotiation.profile(),
        negotiation.new_initiator_spi(),
        new_responder_spi,
        request.nonce().nonce,
        &response_nonce,
        &shared_secret,
    )
    .expect("mixed old/new PRF KDF accepts the selected profile");
    assert_eq!(key_material.sk_d().len(), 64);

    let response = build_ike_sa_rekey_response(&Ikev2IkeSaRekeyResponseBuild {
        negotiation,
        new_responder_spi,
        nonce: Ikev2NoncePayloadBuild {
            nonce: response_nonce,
        },
        key_exchange: Ikev2KeyExchangePayloadBuild {
            dh_group: 14,
            key_exchange_data: vec![0x81; 256],
        },
    })
    .expect("encrypt-then-MAC response builds");
    assert_eq!(
        response.bytes().as_ref(),
        encrypt_then_mac_response_vector()
    );
    assert_eq!(
        payload_types(response.first_payload(), response.bytes()),
        vec![
            PayloadType::SecurityAssociation,
            PayloadType::Nonce,
            PayloadType::KeyExchange,
        ]
    );

    assert!(decode_ikev2_dedicated_bearer_create_child_sa_request(
        &header,
        PayloadType::SecurityAssociation,
        &request_bytes,
    )
    .is_err());
}

#[test]
fn rekey_kdf_requires_each_group_fixed_width_shared_secret() {
    support::ensure_ike_crypto();
    let nonce = [0x11; 16];
    for (group, expected_len) in [
        (Ikev2DhGroup::Modp2048, 256),
        (Ikev2DhGroup::Ecp256, 32),
        (Ikev2DhGroup::Ecp384, 48),
        (Ikev2DhGroup::Ecp521, 66),
    ] {
        assert_eq!(group.shared_secret_len(), expected_len);
        let profile = Ikev2SaInitCryptoProfile::new_aead(
            Ikev2PrfAlgorithm::HmacSha2_256,
            group,
            Ikev2EncryptionAlgorithm::AesGcm16_128,
        )
        .expect("supported group produces an executable test profile");

        let exact_secret = vec![0x55; expected_len];
        derive_ike_sa_rekey_key_material(
            Ikev2PrfAlgorithm::HmacSha2_256,
            &[0x22; 32],
            profile,
            [0x33; 8],
            [0x44; 8],
            &nonce,
            &nonce,
            &exact_secret,
        )
        .expect("the negotiated group's fixed-width shared secret is accepted");

        for actual_len in [0, expected_len - 1, expected_len + 1] {
            let invalid_secret = vec![0x55; actual_len];
            let error = derive_ike_sa_rekey_key_material(
                Ikev2PrfAlgorithm::HmacSha2_256,
                &[0x22; 32],
                profile,
                [0x33; 8],
                [0x44; 8],
                &nonce,
                &nonce,
                &invalid_secret,
            )
            .expect_err("non-fixed-width shared secret is rejected");
            assert_eq!(
                error,
                Ikev2SaInitCryptoError::InvalidKeyLength {
                    name: "new DH shared secret",
                    len: actual_len,
                }
            );
            assert_eq!(error.as_str(), "ike_sa_init_crypto_invalid_key_length");
            assert!(!format!("{error:?} {error}").contains("[85, 85"));
        }
    }
}

fn payload_types(first: PayloadType, bytes: &[u8]) -> Vec<PayloadType> {
    PayloadChain::new(first, bytes)
        .iter()
        .map(|payload| {
            payload
                .expect("synthetic payload chain decodes")
                .payload_type
        })
        .collect()
}

fn transform(
    transform_type: u8,
    transform_id: u16,
    attributes: Vec<Ikev2TransformAttributeBuild>,
) -> Ikev2SaTransformBuild {
    Ikev2SaTransformBuild {
        transform_type,
        transform_id,
        attributes,
    }
}

fn request_entries(
    protocol_id: u8,
    spi: Vec<u8>,
    dh_transform_id: u16,
    ke_group: u16,
    ke_data_len: usize,
) -> Vec<Ikev2IkeAuthPayloadBuild> {
    let sa_body = build_ike_auth_sa_payload(&Ikev2SaPayloadBuild {
        proposals: vec![Ikev2SaProposalBuild {
            proposal_number: 1,
            protocol_id,
            spi,
            transforms: vec![
                transform(
                    TRANSFORM_TYPE_ENCR,
                    20,
                    vec![Ikev2TransformAttributeBuild {
                        attribute_type: 14,
                        value: Ikev2TransformAttributeBuildValue::Tv(128),
                    }],
                ),
                transform(TRANSFORM_TYPE_PRF, 5, Vec::new()),
                transform(TRANSFORM_TYPE_DH, dh_transform_id, Vec::new()),
            ],
        }],
    })
    .expect("synthetic SA body builds");
    let mut key_exchange = Vec::with_capacity(4 + ke_data_len);
    key_exchange.extend_from_slice(&ke_group.to_be_bytes());
    key_exchange.extend_from_slice(&[0, 0]);
    key_exchange.extend(std::iter::repeat_n(0x51, ke_data_len));
    vec![
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::SecurityAssociation,
            body: sa_body,
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Nonce,
            body: vec![0x52; 32],
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::KeyExchange,
            body: key_exchange,
        },
    ]
}

fn decode_entries_error(
    header: &Header,
    entries: &[Ikev2IkeAuthPayloadBuild],
) -> Ikev2IkeSaRekeyRequestError {
    let (first_payload, bytes) =
        build_ike_auth_cleartext_payload_chain(entries).expect("synthetic chain builds");
    decode_ike_sa_rekey_request(header, first_payload, &bytes)
        .expect_err("synthetic invalid request is rejected")
}

fn forward_compatible_request_vector() -> (PayloadType, Vec<u8>) {
    let mut entries = request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, vec![1; 8], 19, 19, 64);
    entries.insert(
        1,
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::VendorId,
            body: vec![0xde, 0xad, 0xbe, 0xef],
        },
    );
    for (notify_message_type, notification_data, role) in [
        (16_000, vec![0xee, 0x01], "error"),
        (65_000, vec![0xba, 0xad], "status"),
    ] {
        entries.push(Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Notify,
            body: build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild {
                protocol_id: IKEV2_NOTIFY_PROTOCOL_ID_NONE,
                spi: Vec::new(),
                notify_message_type,
                notification_data,
            })
            .unwrap_or_else(|error| panic!("synthetic unrecognized {role} Notify builds: {error}")),
        });
    }
    let (first, bytes) =
        build_ike_auth_cleartext_payload_chain(&entries).expect("extension chain builds");
    (
        first,
        append_unknown_payload(first, bytes.to_vec(), 250, false, &[0xca, 0xfe]),
    )
}

fn append_unknown_payload(
    first: PayloadType,
    mut bytes: Vec<u8>,
    payload_type: u8,
    critical: bool,
    body: &[u8],
) -> Vec<u8> {
    let last_offset = PayloadChain::new(first, &bytes)
        .iter()
        .last()
        .expect("synthetic chain has a final payload")
        .expect("synthetic chain decodes")
        .offset;
    bytes[last_offset] = payload_type;
    let payload_len = u16::try_from(4 + body.len()).expect("synthetic unknown payload fits u16");
    bytes.extend_from_slice(&[PayloadType::NoNext.as_u8(), if critical { 0x80 } else { 0 }]);
    bytes.extend_from_slice(&payload_len.to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn request_cardinality_fails_closed() {
    let header = request_header();
    let base = request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, vec![1; 8], 19, 19, 64);
    for (index, role) in [
        Ikev2IkeSaRekeyPayloadRole::SecurityAssociation,
        Ikev2IkeSaRekeyPayloadRole::Nonce,
        Ikev2IkeSaRekeyPayloadRole::KeyExchange,
    ]
    .into_iter()
    .enumerate()
    {
        let mut missing = base.clone();
        missing.remove(index);
        assert_eq!(
            decode_entries_error(&header, &missing),
            Ikev2IkeSaRekeyRequestError::MissingPayload { role }
        );

        let mut duplicate = base.clone();
        duplicate.insert(index, base[index].clone());
        assert_eq!(
            decode_entries_error(&header, &duplicate),
            Ikev2IkeSaRekeyRequestError::DuplicatePayload { role }
        );
    }
}

#[test]
fn request_accepts_reordered_payloads_and_honors_explicit_decode_bounds() {
    let header = request_header();
    let entries = request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, vec![1; 8], 19, 19, 64);
    let reordered = [entries[2].clone(), entries[0].clone(), entries[1].clone()];
    let (first, bytes) =
        build_ike_auth_cleartext_payload_chain(&reordered).expect("reordered chain builds");

    let request = decode_ike_sa_rekey_request(&header, first, &bytes)
        .expect("required payloads decode independently of ordering");
    assert_eq!(request.security_association().proposals.len(), 1);
    assert_eq!(request.key_exchange().dh_group, 19);
    assert_eq!(request.nonce().nonce.len(), 32);

    let message_limited = DecodeContext {
        max_message_len: bytes.len() - 1,
        ..DecodeContext::conservative()
    };
    assert_eq!(
        decode_ike_sa_rekey_request_with_context(&header, first, &bytes, message_limited)
            .expect_err("caller message bound remains authoritative"),
        Ikev2IkeSaRekeyRequestError::MessageTooLarge {
            actual: bytes.len(),
            maximum: bytes.len() - 1,
        }
    );

    let payload_limited = DecodeContext {
        max_ies: 2,
        ..DecodeContext::conservative()
    };
    assert_eq!(
        decode_ike_sa_rekey_request_with_context(&header, first, &bytes, payload_limited)
            .expect_err("caller payload-count bound remains authoritative"),
        Ikev2IkeSaRekeyRequestError::PayloadChain
    );
}

#[test]
fn request_rejects_child_protocol_bad_spi_dh_none_and_ke_mismatch() {
    let header = request_header();
    for protocol_id in [
        IKEV2_SECURITY_PROTOCOL_ID_ESP,
        IKEV2_SECURITY_PROTOCOL_ID_AH,
    ] {
        let entries = request_entries(protocol_id, vec![1; 8], 19, 19, 64);
        assert_eq!(
            decode_entries_error(&header, &entries),
            Ikev2IkeSaRekeyRequestError::ProposalProtocolNotIke {
                proposal_number: 1,
                actual: protocol_id,
            }
        );
    }

    let wrong_spi = request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, vec![1; 4], 19, 19, 64);
    assert_eq!(
        decode_entries_error(&header, &wrong_spi),
        Ikev2IkeSaRekeyRequestError::ProposalSpiLengthInvalid {
            proposal_number: 1,
            actual: 4,
        }
    );

    let zero_spi = request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, vec![0; 8], 19, 19, 64);
    assert_eq!(
        decode_entries_error(&header, &zero_spi),
        Ikev2IkeSaRekeyRequestError::ProposalSpiZero { proposal_number: 1 }
    );

    let dh_none = request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, vec![1; 8], 0, 19, 64);
    assert_eq!(
        decode_entries_error(&header, &dh_none),
        Ikev2IkeSaRekeyRequestError::DhNoneProhibited { proposal_number: 1 }
    );

    let mismatch = request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, vec![1; 8], 19, 20, 97);
    assert_eq!(
        decode_entries_error(&header, &mismatch),
        Ikev2IkeSaRekeyRequestError::KeyExchangeDhGroupMismatch { received: 20 }
    );
}

#[test]
fn request_rejects_rekey_notify_traffic_selectors_and_other_known_payloads() {
    let header = request_header();
    let base = request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, vec![1; 8], 19, 19, 64);
    let rekey_notify = build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild {
        protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
        spi: vec![1, 2, 3, 4],
        notify_message_type: IKEV2_NOTIFY_REKEY_SA,
        notification_data: Vec::new(),
    })
    .expect("synthetic REKEY_SA Notify builds");
    let mut with_notify = base.clone();
    with_notify.push(Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Notify,
        body: rekey_notify,
    });
    assert_eq!(
        decode_entries_error(&header, &with_notify),
        Ikev2IkeSaRekeyRequestError::RekeySaNotifyProhibited
    );

    for payload_type in [
        PayloadType::TrafficSelectorInitiator,
        PayloadType::TrafficSelectorResponder,
        PayloadType::Configuration,
    ] {
        let mut entries = base.clone();
        entries.push(Ikev2IkeAuthPayloadBuild {
            payload_type,
            body: Vec::new(),
        });
        let expected = Ikev2IkeSaRekeyRequestError::UnexpectedPayloadType {
            payload_type: payload_type.as_u8(),
        };
        assert_eq!(decode_entries_error(&header, &entries), expected);
    }
}

#[test]
fn default_request_preserves_rfc_forward_compatible_extensions() {
    let (first, bytes) = forward_compatible_request_vector();
    let request = decode_ike_sa_rekey_request(&request_header(), first, &bytes)
        .expect("RFC forward-compatible extensions are accepted by default");

    assert_eq!(request.vendor_ids().len(), 1);
    assert_eq!(request.vendor_ids()[0].vendor_id, &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(request.unrecognized_notifies().len(), 2);
    assert_eq!(
        request.unrecognized_notifies()[0].notify_message_type,
        16_000
    );
    assert_eq!(
        request.unrecognized_notifies()[0].notification_data,
        &[0xee, 0x01]
    );
    assert_eq!(
        request.unrecognized_notifies()[1].notify_message_type,
        65_000
    );
    assert_eq!(
        request.unrecognized_notifies()[1].notification_data,
        &[0xba, 0xad]
    );
    assert_eq!(request.unknown_noncritical_payloads().len(), 1);
    assert_eq!(request.unknown_noncritical_payloads()[0].payload_type, 250);
    assert_eq!(
        request.unknown_noncritical_payloads()[0].body,
        &[0xca, 0xfe]
    );

    let debug = format!("{request:?}");
    assert!(debug.contains("vendor_id_count: 1"));
    assert!(debug.contains("unrecognized_notify_count: 2"));
    assert!(debug.contains("unknown_noncritical_payload_count: 1"));
    assert!(!debug.contains("222, 173, 190, 239"));
    assert!(!debug.contains("238, 1"));
    assert!(!debug.contains("186, 173"));
    assert!(!debug.contains("202, 254"));
}

#[test]
fn explicit_unknown_policy_drops_or_preserves_mandatory_ignored_extensions() {
    let header = request_header();
    let (first, bytes) = forward_compatible_request_vector();
    let drop_context = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Drop,
        ..DecodeContext::conservative()
    };
    let dropped = decode_ike_sa_rekey_request_with_context(&header, first, &bytes, drop_context)
        .expect("explicit drop policy accepts the core request");
    assert_eq!(dropped.vendor_ids().len(), 1);
    assert!(dropped.unrecognized_notifies().is_empty());
    assert!(dropped.unknown_noncritical_payloads().is_empty());

    let reject_context = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Reject,
        ..DecodeContext::conservative()
    };
    let preserved =
        decode_ike_sa_rekey_request_with_context(&header, first, &bytes, reject_context)
            .expect("RFC-mandated ignored extensions cannot reject the core request");
    assert_eq!(preserved.vendor_ids().len(), 1);
    assert_eq!(
        preserved
            .unrecognized_notifies()
            .iter()
            .map(|notify| notify.notify_message_type)
            .collect::<Vec<_>>(),
        vec![16_000, 65_000]
    );
    assert_eq!(preserved.unknown_noncritical_payloads().len(), 1);
    assert_eq!(
        preserved.unknown_noncritical_payloads()[0].payload_type,
        250
    );
    assert_eq!(
        preserved.unknown_noncritical_payloads()[0].body,
        &[0xca, 0xfe]
    );
}

#[test]
fn unknown_critical_payload_still_fails_closed() {
    let base = request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, vec![1; 8], 19, 19, 64);
    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&base).expect("base chain builds");
    let critical = append_unknown_payload(first, bytes.to_vec(), 250, true, &[1, 2]);
    assert_eq!(
        decode_ike_sa_rekey_request(&request_header(), first, &critical)
            .expect_err("unknown critical payload remains fatal"),
        Ikev2IkeSaRekeyRequestError::PayloadChain
    );
}

#[test]
fn header_shape_fails_closed_before_opened_payload_decode() {
    let bytes = aead_request_vector();
    let mut header = request_header();
    header.exchange_type = EXCHANGE_TYPE_IKE_AUTH;
    assert_eq!(
        decode_ike_sa_rekey_request(&header, PayloadType::SecurityAssociation, &bytes)
            .expect_err("wrong exchange rejected"),
        Ikev2IkeSaRekeyRequestError::WrongExchangeType {
            actual: EXCHANGE_TYPE_IKE_AUTH,
        }
    );

    let mut header = request_header();
    header.flags = HeaderFlags::from_bits(true, true, false);
    assert_eq!(
        decode_ike_sa_rekey_request(&header, PayloadType::SecurityAssociation, &bytes)
            .expect_err("response flag rejected"),
        Ikev2IkeSaRekeyRequestError::ResponseFlagUnexpected
    );

    let mut header = request_header();
    header.next_payload = PayloadType::SecurityAssociation.as_u8();
    assert_eq!(
        decode_ike_sa_rekey_request(&header, PayloadType::SecurityAssociation, &bytes)
            .expect_err("unprotected outer shape rejected"),
        Ikev2IkeSaRekeyRequestError::OuterPayloadNotEncrypted {
            actual: PayloadType::SecurityAssociation.as_u8(),
        }
    );

    let mut header = request_header();
    header.responder_spi = 0;
    assert_eq!(
        decode_ike_sa_rekey_request(&header, PayloadType::SecurityAssociation, &bytes)
            .expect_err("zero established IKE SPI rejected"),
        Ikev2IkeSaRekeyRequestError::IkeSpiZero
    );
}

#[test]
fn selection_preserves_the_selected_alternative_spi() {
    let header = request_header();
    let mut entries = request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, vec![0x11; 8], 19, 19, 64);
    let aead_transforms = || {
        vec![
            transform(
                TRANSFORM_TYPE_ENCR,
                20,
                vec![Ikev2TransformAttributeBuild {
                    attribute_type: 14,
                    value: Ikev2TransformAttributeBuildValue::Tv(128),
                }],
            ),
            transform(TRANSFORM_TYPE_PRF, 5, Vec::new()),
            transform(TRANSFORM_TYPE_DH, 19, Vec::new()),
        ]
    };
    let mut first_transforms = aead_transforms();
    first_transforms[0].transform_id = 65_000;
    let mut sa = Ikev2SaPayloadBuild {
        proposals: vec![
            Ikev2SaProposalBuild {
                proposal_number: 1,
                protocol_id: IKEV2_SECURITY_PROTOCOL_ID_IKE,
                spi: vec![0x11; 8],
                transforms: first_transforms,
            },
            Ikev2SaProposalBuild {
                proposal_number: 2,
                protocol_id: IKEV2_SECURITY_PROTOCOL_ID_IKE,
                spi: vec![0x22; 8],
                transforms: aead_transforms(),
            },
        ],
    };
    entries[0].body = build_ike_auth_sa_payload(&sa).expect("two-proposal SA builds");
    let (first, bytes) =
        build_ike_auth_cleartext_payload_chain(&entries).expect("two-proposal chain builds");
    let request = decode_ike_sa_rekey_request(&header, first, &bytes)
        .expect("two valid IKE rekey offers decode");
    let selected = negotiate_ike_sa_rekey(&request, &policy(aead_profile()))
        .expect("second executable offer selects");
    assert_eq!(selected.selected_proposal().proposal_number, 2);
    assert_eq!(selected.new_initiator_spi(), [0x22; 8]);

    let response = build_ike_sa_rekey_response(&Ikev2IkeSaRekeyResponseBuild {
        negotiation: selected,
        new_responder_spi: [0x33; 8],
        nonce: Ikev2NoncePayloadBuild { nonce: vec![2; 32] },
        key_exchange: Ikev2KeyExchangePayloadBuild {
            dh_group: 19,
            key_exchange_data: vec![3; 64],
        },
    })
    .expect("response for second selected proposal builds");
    let selected_sa = PayloadChain::new(response.first_payload(), response.bytes())
        .iter()
        .next()
        .expect("response contains SA")
        .expect("response SA framing decodes");
    let selected_sa = Ikev2SaPayload::decode(selected_sa).expect("response SA body decodes");
    assert_eq!(selected_sa.proposals[0].proposal_number, 2);
    assert_eq!(selected_sa.proposals[0].spi, &[0x33; 8]);

    sa.proposals[1].proposal_number = 3;
    entries[0].body = build_ike_auth_sa_payload(&sa).expect("bad-number fixture encodes");
    assert_eq!(
        decode_entries_error(&header, &entries),
        Ikev2IkeSaRekeyRequestError::InvalidProposalNumber {
            actual: 3,
            expected: 2,
        }
    );
}

#[test]
fn selection_rejects_duplicate_transforms_and_invalid_ke_length() {
    let header = request_header();
    let mut duplicate = request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, vec![1; 8], 19, 19, 64);
    let mut sa = Ikev2SaPayloadBuild {
        proposals: vec![Ikev2SaProposalBuild {
            proposal_number: 1,
            protocol_id: IKEV2_SECURITY_PROTOCOL_ID_IKE,
            spi: vec![1; 8],
            transforms: vec![
                transform(
                    TRANSFORM_TYPE_ENCR,
                    20,
                    vec![Ikev2TransformAttributeBuild {
                        attribute_type: 14,
                        value: Ikev2TransformAttributeBuildValue::Tv(128),
                    }],
                ),
                transform(
                    TRANSFORM_TYPE_ENCR,
                    20,
                    vec![Ikev2TransformAttributeBuild {
                        attribute_type: 14,
                        value: Ikev2TransformAttributeBuildValue::Tv(128),
                    }],
                ),
                transform(TRANSFORM_TYPE_PRF, 5, Vec::new()),
                transform(TRANSFORM_TYPE_DH, 19, Vec::new()),
            ],
        }],
    };
    duplicate[0].body = build_ike_auth_sa_payload(&sa).expect("duplicate SA fixture builds");
    let (first, bytes) =
        build_ike_auth_cleartext_payload_chain(&duplicate).expect("duplicate chain builds");
    let request = decode_ike_sa_rekey_request(&header, first, &bytes)
        .expect("duplicate transforms are structurally decoded");
    assert_eq!(
        negotiate_ike_sa_rekey(&request, &policy(aead_profile()))
            .expect_err("duplicate transform rejected by selection"),
        Ikev2SaInitNegotiationError::DuplicateTransform {
            proposal_number: 1,
            transform_type: TRANSFORM_TYPE_ENCR,
            transform_id: 20,
        }
    );

    sa.proposals[0].transforms.remove(1);
    let mut short_ke = request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, vec![1; 8], 19, 19, 63);
    short_ke[0].body = build_ike_auth_sa_payload(&sa).expect("valid SA fixture builds");
    let (first, bytes) =
        build_ike_auth_cleartext_payload_chain(&short_ke).expect("short KE chain builds");
    let request = decode_ike_sa_rekey_request(&header, first, &bytes)
        .expect("short KE is structurally decoded");
    assert_eq!(
        negotiate_ike_sa_rekey(&request, &policy(aead_profile()))
            .expect_err("selected KE length rejected"),
        Ikev2SaInitNegotiationError::InvalidKeyExchangeLength {
            dh_group: 19,
            expected: 64,
            actual: 63,
        }
    );
}

#[test]
fn response_builder_rejects_zero_spi_ke_mismatch_length_and_bad_nonce() {
    let bytes = aead_request_vector();
    let request =
        decode_ike_sa_rekey_request(&request_header(), PayloadType::SecurityAssociation, &bytes)
            .expect("AEAD request decodes");
    let negotiation =
        negotiate_ike_sa_rekey(&request, &policy(aead_profile())).expect("AEAD offer selects");
    let mut build = Ikev2IkeSaRekeyResponseBuild {
        negotiation,
        new_responder_spi: [0; 8],
        nonce: Ikev2NoncePayloadBuild { nonce: vec![2; 32] },
        key_exchange: Ikev2KeyExchangePayloadBuild {
            dh_group: 19,
            key_exchange_data: vec![3; 64],
        },
    };
    assert_eq!(
        build_ike_sa_rekey_response(&build).expect_err("zero responder SPI rejected"),
        Ikev2IkeSaRekeyBuildError::ResponderSpiZero
    );

    build.new_responder_spi = [4; 8];
    build.key_exchange.dh_group = 20;
    assert_eq!(
        build_ike_sa_rekey_response(&build).expect_err("wrong KEr group rejected"),
        Ikev2IkeSaRekeyBuildError::KeyExchangeDhGroupMismatch {
            expected: 19,
            actual: 20,
        }
    );

    build.key_exchange.dh_group = 19;
    build.key_exchange.key_exchange_data.pop();
    assert_eq!(
        build_ike_sa_rekey_response(&build).expect_err("short KEr rejected"),
        Ikev2IkeSaRekeyBuildError::InvalidKeyExchangeLength {
            dh_group: 19,
            expected: 64,
            actual: 63,
        }
    );

    build.key_exchange.key_exchange_data.push(3);
    build.nonce.nonce.truncate(15);
    assert_eq!(
        build_ike_sa_rekey_response(&build).expect_err("short Nr rejected"),
        Ikev2IkeSaRekeyBuildError::Nonce(Ikev2SaInitBuildError::NonceTooShort)
    );
}

fn response_header() -> Header {
    Header::new(
        CURRENT_INITIATOR_SPI,
        CURRENT_RESPONDER_SPI,
        PayloadType::Encrypted,
        EXCHANGE_TYPE_CREATE_CHILD_SA,
        HeaderFlags::from_bits(false, true, false),
        7,
    )
}

fn aead_sent_request() -> Ikev2IkeSaRekeySentRequest {
    Ikev2IkeSaRekeySentRequest {
        old_initiator_spi: CURRENT_INITIATOR_SPI,
        old_responder_spi: CURRENT_RESPONDER_SPI,
        profile: aead_profile(),
    }
}

fn aead_request_build() -> Ikev2IkeSaRekeyRequestBuild {
    Ikev2IkeSaRekeyRequestBuild {
        profile: aead_profile(),
        new_initiator_spi: [1, 2, 3, 4, 5, 6, 7, 8],
        nonce: Ikev2NoncePayloadBuild {
            nonce: decode_hex(concat!(
                "1112131415161718191a1b1c1d1e1f20",
                "2122232425262728292a2b2c2d2e2f30",
            )),
        },
        key_exchange: Ikev2KeyExchangePayloadBuild {
            dh_group: 19,
            key_exchange_data: vec![0x41; 64],
        },
    }
}

fn response_entries(spi: Vec<u8>) -> Vec<Ikev2IkeAuthPayloadBuild> {
    request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, spi, 19, 19, 64)
}

fn decode_response_entries_error(
    entries: &[Ikev2IkeAuthPayloadBuild],
) -> Ikev2IkeSaRekeyResponseError {
    let (first_payload, bytes) =
        build_ike_auth_cleartext_payload_chain(entries).expect("synthetic response chain builds");
    decode_ike_sa_rekey_response(
        &response_header(),
        &aead_sent_request(),
        first_payload,
        &bytes,
    )
    .expect_err("synthetic invalid response is rejected")
}

#[test]
fn initiator_aead_vector_builds_exact_request_decodes_response_and_feeds_kdf() {
    let build = aead_request_build();
    let request = build_ike_sa_rekey_request(&build).expect("literal AEAD rekey request builds");
    assert_eq!(request.first_payload(), PayloadType::SecurityAssociation);
    assert_eq!(request.bytes().as_ref(), aead_request_vector());
    assert_eq!(
        payload_types(request.first_payload(), request.bytes()),
        vec![
            PayloadType::SecurityAssociation,
            PayloadType::Nonce,
            PayloadType::KeyExchange,
        ]
    );

    let decoded =
        decode_ike_sa_rekey_request(&request_header(), request.first_payload(), request.bytes())
            .expect("responder boundary accepts the built initiator request");
    let negotiation = negotiate_ike_sa_rekey(&decoded, &policy(aead_profile()))
        .expect("responder selects the single offered proposal");
    assert_eq!(negotiation.profile(), aead_profile());
    assert_eq!(negotiation.new_initiator_spi(), build.new_initiator_spi);

    let sent = aead_sent_request();
    let response_bytes = aead_response_vector();
    let response = decode_ike_sa_rekey_response(
        &response_header(),
        &sent,
        PayloadType::SecurityAssociation,
        &response_bytes,
    )
    .expect("literal AEAD rekey response decodes");
    assert_eq!(response.profile(), aead_profile());
    assert_eq!(response.dh_group(), Ikev2DhGroup::Ecp256);
    assert_eq!(
        response.new_responder_spi(),
        [0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8]
    );
    assert_eq!(
        response.nonce().nonce,
        decode_hex(concat!(
            "b1b2b3b4b5b6b7b8b9babbbcbdbebfc0",
            "c1c2c3c4c5c6c7c8c9cacbcccdcecfd0",
        ))
        .as_slice()
    );
    assert_eq!(response.key_exchange().dh_group, 19);
    assert_eq!(
        response.key_exchange().key_exchange_data,
        [0x71; 64].as_slice()
    );
    assert!(response.vendor_ids().is_empty());
    assert!(response.unrecognized_notifies().is_empty());
    assert!(response.unknown_noncritical_payloads().is_empty());

    let key_material = derive_ike_sa_rekey_key_material(
        Ikev2PrfAlgorithm::HmacSha2_256,
        &[0x91; 32],
        response.profile(),
        build.new_initiator_spi,
        response.new_responder_spi(),
        &build.nonce.nonce,
        response.nonce().nonce,
        &[0x92; 32],
    )
    .expect("decoded response feeds directly into the existing rekey KDF");
    assert_eq!(key_material.sk_d().len(), 32);

    let debug = format!("{build:?} {request:?} {sent:?} {response:?}");
    assert!(!debug.contains("0102030405060708"));
    assert!(!debug.contains("[1, 2, 3, 4"));
    assert!(!debug.contains("[17, 18, 19, 20"));
    assert!(!debug.contains("[65, 65, 65"));
    assert!(!debug.contains("[161, 162, 163, 164"));
    assert!(!debug.contains("[177, 178, 179, 180"));
    assert!(!debug.contains("[113, 113, 113"));
    assert!(!debug.contains(&CURRENT_INITIATOR_SPI.to_string()));
    assert!(!debug.contains(&CURRENT_RESPONDER_SPI.to_string()));
    assert!(debug.contains("nonce_len"));
    assert!(debug.contains("key_exchange_data_len"));
}

#[test]
fn initiator_encrypt_then_mac_vector_builds_exact_request_and_decodes_response() {
    let build = Ikev2IkeSaRekeyRequestBuild {
        profile: encrypt_then_mac_profile(),
        new_initiator_spi: [0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18],
        nonce: Ikev2NoncePayloadBuild {
            nonce: decode_hex(concat!(
                "3132333435363738393a3b3c3d3e3f40",
                "4142434445464748494a4b4c4d4e4f50",
            )),
        },
        key_exchange: Ikev2KeyExchangePayloadBuild {
            dh_group: 14,
            key_exchange_data: vec![0x61; 256],
        },
    };
    let request =
        build_ike_sa_rekey_request(&build).expect("literal encrypt-then-MAC rekey request builds");
    assert_eq!(request.bytes().as_ref(), encrypt_then_mac_request_vector());
    let (first_payload, bytes) = request.into_parts();
    assert_eq!(
        payload_types(first_payload, &bytes),
        vec![
            PayloadType::SecurityAssociation,
            PayloadType::Nonce,
            PayloadType::KeyExchange,
        ]
    );

    let sent = Ikev2IkeSaRekeySentRequest {
        old_initiator_spi: CURRENT_INITIATOR_SPI,
        old_responder_spi: CURRENT_RESPONDER_SPI,
        profile: encrypt_then_mac_profile(),
    };
    let response_bytes = encrypt_then_mac_response_vector();
    let response = decode_ike_sa_rekey_response(
        &response_header(),
        &sent,
        PayloadType::SecurityAssociation,
        &response_bytes,
    )
    .expect("literal encrypt-then-MAC rekey response decodes");
    assert_eq!(response.profile(), encrypt_then_mac_profile());
    assert_eq!(response.dh_group(), Ikev2DhGroup::Modp2048);
    assert_eq!(
        response.new_responder_spi(),
        [0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8]
    );
    assert_eq!(
        response.nonce().nonce,
        decode_hex(concat!(
            "7172737475767778797a7b7c7d7e7f80",
            "8182838485868788898a8b8c8d8e8f90",
        ))
        .as_slice()
    );
    assert_eq!(response.key_exchange().dh_group, 14);
    assert_eq!(
        response.key_exchange().key_exchange_data,
        [0x81; 256].as_slice()
    );

    let shared_secret = vec![0x94; Ikev2DhGroup::Modp2048.shared_secret_len()];
    let key_material = derive_ike_sa_rekey_key_material(
        Ikev2PrfAlgorithm::HmacSha2_256,
        &[0x93; 32],
        response.profile(),
        build.new_initiator_spi,
        response.new_responder_spi(),
        &build.nonce.nonce,
        response.nonce().nonce,
        &shared_secret,
    )
    .expect("mixed old/new PRF KDF accepts the decoded response");
    assert_eq!(key_material.sk_d().len(), 64);
}

#[test]
fn request_builder_rejects_zero_spi_ke_mismatch_length_and_bad_nonce() {
    let mut build = aead_request_build();
    build.new_initiator_spi = [0; 8];
    let error = build_ike_sa_rekey_request(&build).expect_err("zero new initiator SPI rejected");
    assert_eq!(error, Ikev2IkeSaRekeyRequestBuildError::InitiatorSpiZero);
    assert_eq!(
        error.as_str(),
        "ike_sa_rekey_request_build_initiator_spi_zero"
    );
    assert_eq!(error.to_string(), error.as_str());

    let mut build = aead_request_build();
    build.key_exchange.dh_group = 20;
    let error = build_ike_sa_rekey_request(&build).expect_err("wrong KEi group rejected");
    assert_eq!(
        error,
        Ikev2IkeSaRekeyRequestBuildError::KeyExchangeDhGroupMismatch {
            expected: 19,
            actual: 20,
        }
    );
    assert_eq!(
        error.as_str(),
        "ike_sa_rekey_request_build_ke_group_mismatch"
    );

    let mut build = aead_request_build();
    build.key_exchange.key_exchange_data.pop();
    let error = build_ike_sa_rekey_request(&build).expect_err("short KEi rejected");
    assert_eq!(
        error,
        Ikev2IkeSaRekeyRequestBuildError::InvalidKeyExchangeLength {
            dh_group: 19,
            expected: 64,
            actual: 63,
        }
    );
    assert_eq!(
        error.as_str(),
        "ike_sa_rekey_request_build_ke_length_invalid"
    );

    let mut build = aead_request_build();
    build.nonce.nonce.truncate(15);
    let error = build_ike_sa_rekey_request(&build).expect_err("short Ni rejected");
    assert_eq!(
        error,
        Ikev2IkeSaRekeyRequestBuildError::Nonce(Ikev2SaInitBuildError::NonceTooShort)
    );
    assert_eq!(error.as_str(), "ike_sa_rekey_request_build_nonce_invalid");
}

#[test]
fn response_header_shape_fails_closed_before_opened_payload_decode() {
    let bytes = aead_response_vector();
    let sent = aead_sent_request();

    let mut header = response_header();
    header.exchange_type = EXCHANGE_TYPE_IKE_AUTH;
    assert_eq!(
        decode_ike_sa_rekey_response(&header, &sent, PayloadType::SecurityAssociation, &bytes)
            .expect_err("wrong exchange rejected"),
        Ikev2IkeSaRekeyResponseError::WrongExchangeType {
            actual: EXCHANGE_TYPE_IKE_AUTH,
        }
    );

    let mut header = response_header();
    header.flags = HeaderFlags::from_bits(true, false, false);
    let error =
        decode_ike_sa_rekey_response(&header, &sent, PayloadType::SecurityAssociation, &bytes)
            .expect_err("missing response flag rejected");
    assert_eq!(error, Ikev2IkeSaRekeyResponseError::ResponseFlagMissing);
    assert_eq!(error.as_str(), "ike_sa_rekey_response_flag_missing");

    let mut header = response_header();
    header.next_payload = PayloadType::SecurityAssociation.as_u8();
    assert_eq!(
        decode_ike_sa_rekey_response(&header, &sent, PayloadType::SecurityAssociation, &bytes)
            .expect_err("unprotected outer shape rejected"),
        Ikev2IkeSaRekeyResponseError::OuterPayloadNotEncrypted {
            actual: PayloadType::SecurityAssociation.as_u8(),
        }
    );

    let mut header = response_header();
    header.responder_spi = CURRENT_RESPONDER_SPI ^ 1;
    let error =
        decode_ike_sa_rekey_response(&header, &sent, PayloadType::SecurityAssociation, &bytes)
            .expect_err("foreign established SPI pair rejected");
    assert_eq!(error, Ikev2IkeSaRekeyResponseError::IkeSpiMismatch);
    assert_eq!(error.as_str(), "ike_sa_rekey_response_ike_spi_mismatch");
    assert!(!format!("{error:?} {error}").contains(&CURRENT_RESPONDER_SPI.to_string()));

    let mut header = response_header();
    header.initiator_spi = CURRENT_INITIATOR_SPI ^ 1;
    assert_eq!(
        decode_ike_sa_rekey_response(&header, &sent, PayloadType::SecurityAssociation, &bytes)
            .expect_err("foreign initiator SPI rejected"),
        Ikev2IkeSaRekeyResponseError::IkeSpiMismatch
    );

    let mut zero_sent = sent;
    zero_sent.old_responder_spi = 0;
    let mut header = response_header();
    header.responder_spi = 0;
    assert_eq!(
        decode_ike_sa_rekey_response(
            &header,
            &zero_sent,
            PayloadType::SecurityAssociation,
            &bytes
        )
        .expect_err("zero established IKE SPI rejected"),
        Ikev2IkeSaRekeyResponseError::IkeSpiZero
    );
}

#[test]
fn response_cardinality_fails_closed() {
    let base = response_entries(vec![0xa1; 8]);
    for (index, role) in [
        Ikev2IkeSaRekeyPayloadRole::SecurityAssociation,
        Ikev2IkeSaRekeyPayloadRole::Nonce,
        Ikev2IkeSaRekeyPayloadRole::KeyExchange,
    ]
    .into_iter()
    .enumerate()
    {
        let mut missing = base.clone();
        missing.remove(index);
        let error = decode_response_entries_error(&missing);
        assert_eq!(error, Ikev2IkeSaRekeyResponseError::MissingPayload { role });
        assert_eq!(error.as_str(), "ike_sa_rekey_response_payload_missing");

        let mut duplicate = base.clone();
        duplicate.insert(index, base[index].clone());
        let error = decode_response_entries_error(&duplicate);
        assert_eq!(
            error,
            Ikev2IkeSaRekeyResponseError::DuplicatePayload { role }
        );
        assert_eq!(error.as_str(), "ike_sa_rekey_response_payload_duplicate");
    }
}

#[test]
fn response_rejects_rekey_notify_traffic_selectors_and_unknown_critical() {
    let base = response_entries(vec![0xa1; 8]);
    let rekey_notify = build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild {
        protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
        spi: vec![1, 2, 3, 4],
        notify_message_type: IKEV2_NOTIFY_REKEY_SA,
        notification_data: Vec::new(),
    })
    .expect("synthetic REKEY_SA Notify builds");
    let mut with_notify = base.clone();
    with_notify.push(Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Notify,
        body: rekey_notify,
    });
    let error = decode_response_entries_error(&with_notify);
    assert_eq!(error, Ikev2IkeSaRekeyResponseError::RekeySaNotifyProhibited);
    assert_eq!(
        error.as_str(),
        "ike_sa_rekey_response_rekey_sa_notify_prohibited"
    );

    for payload_type in [
        PayloadType::TrafficSelectorInitiator,
        PayloadType::TrafficSelectorResponder,
        PayloadType::Configuration,
    ] {
        let mut entries = base.clone();
        entries.push(Ikev2IkeAuthPayloadBuild {
            payload_type,
            body: Vec::new(),
        });
        let error = decode_response_entries_error(&entries);
        assert_eq!(
            error,
            Ikev2IkeSaRekeyResponseError::UnexpectedPayloadType {
                payload_type: payload_type.as_u8(),
            }
        );
        assert_eq!(error.as_str(), "ike_sa_rekey_response_payload_unexpected");
    }

    let (first, bytes) =
        build_ike_auth_cleartext_payload_chain(&base).expect("base response chain builds");
    let critical = append_unknown_payload(first, bytes.to_vec(), 250, true, &[1, 2]);
    let error =
        decode_ike_sa_rekey_response(&response_header(), &aead_sent_request(), first, &critical)
            .expect_err("unknown critical payload remains fatal");
    assert_eq!(error, Ikev2IkeSaRekeyResponseError::UnknownCriticalPayload);
    assert_eq!(
        error.as_str(),
        "ike_sa_rekey_response_unknown_critical_payload"
    );

    let truncated_len = bytes.len() - 1;
    let error = decode_ike_sa_rekey_response(
        &response_header(),
        &aead_sent_request(),
        first,
        &bytes[..truncated_len],
    )
    .expect_err("truncated chain remains fatal");
    assert_eq!(error, Ikev2IkeSaRekeyResponseError::PayloadChain);
    assert_eq!(
        error.as_str(),
        "ike_sa_rekey_response_payload_chain_invalid"
    );
}

#[test]
fn response_proposal_and_ke_mismatches_fail_closed_before_derivation() {
    for protocol_id in [
        IKEV2_SECURITY_PROTOCOL_ID_ESP,
        IKEV2_SECURITY_PROTOCOL_ID_AH,
    ] {
        let entries = request_entries(protocol_id, vec![0xa1; 8], 19, 19, 64);
        assert_eq!(
            decode_response_entries_error(&entries),
            Ikev2IkeSaRekeyResponseError::ProposalProtocolNotIke {
                actual: protocol_id,
            }
        );
    }

    assert_eq!(
        decode_response_entries_error(&response_entries(vec![0xa1; 4])),
        Ikev2IkeSaRekeyResponseError::ProposalSpiLengthInvalid { actual: 4 }
    );
    assert_eq!(
        decode_response_entries_error(&response_entries(vec![0; 8])),
        Ikev2IkeSaRekeyResponseError::ProposalSpiZero
    );

    let aead_transforms = || {
        vec![
            transform(
                TRANSFORM_TYPE_ENCR,
                20,
                vec![Ikev2TransformAttributeBuild {
                    attribute_type: 14,
                    value: Ikev2TransformAttributeBuildValue::Tv(128),
                }],
            ),
            transform(TRANSFORM_TYPE_PRF, 5, Vec::new()),
            transform(TRANSFORM_TYPE_DH, 19, Vec::new()),
        ]
    };
    let selected_proposal =
        |proposal_number: u8, transforms: Vec<Ikev2SaTransformBuild>| Ikev2SaProposalBuild {
            proposal_number,
            protocol_id: IKEV2_SECURITY_PROTOCOL_ID_IKE,
            spi: vec![0xa1; 8],
            transforms,
        };
    let sa_error = |proposals: Vec<Ikev2SaProposalBuild>| {
        let mut entries = response_entries(vec![0xa1; 8]);
        entries[0].body = build_ike_auth_sa_payload(&Ikev2SaPayloadBuild { proposals })
            .expect("synthetic response SA builds");
        decode_response_entries_error(&entries)
    };

    let error = sa_error(vec![
        selected_proposal(1, aead_transforms()),
        selected_proposal(2, aead_transforms()),
    ]);
    assert_eq!(
        error,
        Ikev2IkeSaRekeyResponseError::ProposalCountInvalid { actual: 2 }
    );
    assert_eq!(
        error.as_str(),
        "ike_sa_rekey_response_proposal_count_invalid"
    );

    let error = sa_error(vec![selected_proposal(2, aead_transforms())]);
    assert_eq!(
        error,
        Ikev2IkeSaRekeyResponseError::InvalidProposalNumber {
            actual: 2,
            expected: 1,
        }
    );
    assert_eq!(
        error.as_str(),
        "ike_sa_rekey_response_proposal_number_invalid"
    );

    let mut wrong_encryption = aead_transforms();
    wrong_encryption[0].transform_id = 12;
    let error = sa_error(vec![selected_proposal(1, wrong_encryption)]);
    assert_eq!(
        error,
        Ikev2IkeSaRekeyResponseError::ProposalTransformMismatch {
            transform_type: TRANSFORM_TYPE_ENCR,
        }
    );
    assert_eq!(
        error.as_str(),
        "ike_sa_rekey_response_proposal_transform_mismatch"
    );

    let mut wrong_key_length = aead_transforms();
    wrong_key_length[0].attributes[0].value = Ikev2TransformAttributeBuildValue::Tv(256);
    assert_eq!(
        sa_error(vec![selected_proposal(1, wrong_key_length)]),
        Ikev2IkeSaRekeyResponseError::ProposalTransformMismatch {
            transform_type: TRANSFORM_TYPE_ENCR,
        }
    );

    let mut unexpected_integrity = aead_transforms();
    unexpected_integrity.insert(1, transform(TRANSFORM_TYPE_INTEG, 12, Vec::new()));
    assert_eq!(
        sa_error(vec![selected_proposal(1, unexpected_integrity)]),
        Ikev2IkeSaRekeyResponseError::ProposalTransformMismatch {
            transform_type: TRANSFORM_TYPE_INTEG,
        }
    );

    let mut wrong_group = aead_transforms();
    wrong_group[2].transform_id = 20;
    assert_eq!(
        sa_error(vec![selected_proposal(1, wrong_group)]),
        Ikev2IkeSaRekeyResponseError::ProposalTransformMismatch {
            transform_type: TRANSFORM_TYPE_DH,
        }
    );

    let mut missing_prf = aead_transforms();
    missing_prf.remove(1);
    assert_eq!(
        sa_error(vec![selected_proposal(1, missing_prf)]),
        Ikev2IkeSaRekeyResponseError::ProposalTransformMismatch {
            transform_type: TRANSFORM_TYPE_PRF,
        }
    );

    let mut duplicate_group = aead_transforms();
    duplicate_group.push(transform(TRANSFORM_TYPE_DH, 19, Vec::new()));
    assert_eq!(
        sa_error(vec![selected_proposal(1, duplicate_group)]),
        Ikev2IkeSaRekeyResponseError::ProposalTransformMismatch {
            transform_type: TRANSFORM_TYPE_DH,
        }
    );

    let mut unknown_transform_type = aead_transforms();
    unknown_transform_type.push(transform(5, 1, Vec::new()));
    assert_eq!(
        sa_error(vec![selected_proposal(1, unknown_transform_type)]),
        Ikev2IkeSaRekeyResponseError::ProposalTransformMismatch { transform_type: 5 }
    );

    let mut missing_integrity =
        request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, vec![0xb1; 8], 14, 14, 256);
    missing_integrity[0].body = build_ike_auth_sa_payload(&Ikev2SaPayloadBuild {
        proposals: vec![Ikev2SaProposalBuild {
            proposal_number: 1,
            protocol_id: IKEV2_SECURITY_PROTOCOL_ID_IKE,
            spi: vec![0xb1; 8],
            transforms: vec![
                transform(
                    TRANSFORM_TYPE_ENCR,
                    12,
                    vec![Ikev2TransformAttributeBuild {
                        attribute_type: 14,
                        value: Ikev2TransformAttributeBuildValue::Tv(256),
                    }],
                ),
                transform(TRANSFORM_TYPE_PRF, 7, Vec::new()),
                transform(TRANSFORM_TYPE_DH, 14, Vec::new()),
            ],
        }],
    })
    .expect("integrity-free encrypt-then-MAC SA builds");
    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&missing_integrity)
        .expect("integrity-free chain builds");
    let etm_sent = Ikev2IkeSaRekeySentRequest {
        old_initiator_spi: CURRENT_INITIATOR_SPI,
        old_responder_spi: CURRENT_RESPONDER_SPI,
        profile: encrypt_then_mac_profile(),
    };
    assert_eq!(
        decode_ike_sa_rekey_response(&response_header(), &etm_sent, first, &bytes)
            .expect_err("missing required integrity transform rejected"),
        Ikev2IkeSaRekeyResponseError::ProposalTransformMismatch {
            transform_type: TRANSFORM_TYPE_INTEG,
        }
    );

    let ke_mismatch = request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, vec![0xa1; 8], 19, 20, 96);
    let error = decode_response_entries_error(&ke_mismatch);
    assert_eq!(
        error,
        Ikev2IkeSaRekeyResponseError::KeyExchangeDhGroupMismatch {
            expected: 19,
            actual: 20,
        }
    );
    assert_eq!(error.as_str(), "ike_sa_rekey_response_ke_group_mismatch");

    let short_ke = request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, vec![0xa1; 8], 19, 19, 63);
    let error = decode_response_entries_error(&short_ke);
    assert_eq!(
        error,
        Ikev2IkeSaRekeyResponseError::InvalidKeyExchangeLength {
            dh_group: 19,
            expected: 64,
            actual: 63,
        }
    );
    assert_eq!(error.as_str(), "ike_sa_rekey_response_ke_length_invalid");

    let mut short_nonce = response_entries(vec![0xa1; 8]);
    short_nonce[1].body = vec![0x52; 15];
    let error = decode_response_entries_error(&short_nonce);
    assert_eq!(
        error,
        Ikev2IkeSaRekeyResponseError::Nonce(Ikev2NoncePayloadError::NonceTooShort)
    );
    assert_eq!(error.as_str(), "ike_sa_rekey_response_nonce_invalid");
}

fn forward_compatible_response_vector() -> (PayloadType, Vec<u8>) {
    let mut entries = response_entries(vec![0xa1; 8]);
    entries.insert(
        1,
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::VendorId,
            body: vec![0xde, 0xad, 0xbe, 0xef],
        },
    );
    // Both Notify types sit in the RFC 7296 §3.10.1 status range (>= 16384),
    // which a response decoder must ignore; 16_384 pins the range boundary.
    // Error-range types are rejected and covered by dedicated tests.
    for (notify_message_type, notification_data, role) in [
        (16_384, vec![0xee, 0x01], "boundary status"),
        (65_000, vec![0xba, 0xad], "status"),
    ] {
        entries.push(Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Notify,
            body: build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild {
                protocol_id: IKEV2_NOTIFY_PROTOCOL_ID_NONE,
                spi: Vec::new(),
                notify_message_type,
                notification_data,
            })
            .unwrap_or_else(|error| panic!("synthetic unrecognized {role} Notify builds: {error}")),
        });
    }
    let (first, bytes) =
        build_ike_auth_cleartext_payload_chain(&entries).expect("extension response chain builds");
    (
        first,
        append_unknown_payload(first, bytes.to_vec(), 250, false, &[0xca, 0xfe]),
    )
}

#[test]
fn response_preserves_extensions_accepts_reordering_and_honors_bounds() {
    let sent = aead_sent_request();
    let (first, bytes) = forward_compatible_response_vector();
    let response = decode_ike_sa_rekey_response(&response_header(), &sent, first, &bytes)
        .expect("RFC forward-compatible response extensions are accepted by default");
    assert_eq!(response.vendor_ids().len(), 1);
    assert_eq!(
        response.vendor_ids()[0].vendor_id,
        &[0xde, 0xad, 0xbe, 0xef]
    );
    assert_eq!(
        response
            .unrecognized_notifies()
            .iter()
            .map(|notify| notify.notify_message_type)
            .collect::<Vec<_>>(),
        vec![16_384, 65_000]
    );
    assert_eq!(response.unknown_noncritical_payloads().len(), 1);
    assert_eq!(response.unknown_noncritical_payloads()[0].payload_type, 250);
    assert_eq!(
        response.unknown_noncritical_payloads()[0].body,
        &[0xca, 0xfe]
    );

    let debug = format!("{response:?}");
    assert!(debug.contains("vendor_id_count: 1"));
    assert!(debug.contains("unrecognized_notify_count: 2"));
    assert!(debug.contains("unknown_noncritical_payload_count: 1"));
    assert!(!debug.contains("222, 173, 190, 239"));
    assert!(!debug.contains("238, 1"));
    assert!(!debug.contains("186, 173"));
    assert!(!debug.contains("202, 254"));

    let drop_context = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Drop,
        ..DecodeContext::conservative()
    };
    let dropped = decode_ike_sa_rekey_response_with_context(
        &response_header(),
        &sent,
        first,
        &bytes,
        drop_context,
    )
    .expect("explicit drop policy accepts the core response");
    assert_eq!(dropped.vendor_ids().len(), 1);
    assert!(dropped.unrecognized_notifies().is_empty());
    assert!(dropped.unknown_noncritical_payloads().is_empty());

    let reject_context = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Reject,
        ..DecodeContext::conservative()
    };
    let preserved = decode_ike_sa_rekey_response_with_context(
        &response_header(),
        &sent,
        first,
        &bytes,
        reject_context,
    )
    .expect("RFC-mandated ignored extensions cannot reject the core response");
    assert_eq!(preserved.unrecognized_notifies().len(), 2);
    assert_eq!(preserved.unknown_noncritical_payloads().len(), 1);

    let entries = response_entries(vec![0xa1; 8]);
    let reordered = [entries[2].clone(), entries[0].clone(), entries[1].clone()];
    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&reordered)
        .expect("reordered response chain builds");
    let response = decode_ike_sa_rekey_response(&response_header(), &sent, first, &bytes)
        .expect("required payloads decode independently of ordering");
    assert_eq!(response.new_responder_spi(), [0xa1; 8]);

    let message_limited = DecodeContext {
        max_message_len: bytes.len() - 1,
        ..DecodeContext::conservative()
    };
    assert_eq!(
        decode_ike_sa_rekey_response_with_context(
            &response_header(),
            &sent,
            first,
            &bytes,
            message_limited,
        )
        .expect_err("caller message bound remains authoritative"),
        Ikev2IkeSaRekeyResponseError::MessageTooLarge {
            actual: bytes.len(),
            maximum: bytes.len() - 1,
        }
    );

    let payload_limited = DecodeContext {
        max_ies: 2,
        ..DecodeContext::conservative()
    };
    assert_eq!(
        decode_ike_sa_rekey_response_with_context(
            &response_header(),
            &sent,
            first,
            &bytes,
            payload_limited,
        )
        .expect_err("caller payload-count bound remains authoritative"),
        Ikev2IkeSaRekeyResponseError::PayloadChain
    );
}

fn notify_entry(
    protocol_id: u8,
    spi: Vec<u8>,
    notify_message_type: u16,
    notification_data: Vec<u8>,
) -> Ikev2IkeAuthPayloadBuild {
    Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Notify,
        body: build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild {
            protocol_id,
            spi,
            notify_message_type,
            notification_data,
        })
        .expect("synthetic Notify payload builds"),
    }
}

#[test]
fn response_unrecognized_error_range_notify_fails_exchange_despite_valid_core_chain() {
    for notify_message_type in [16_000, 16_383] {
        let mut entries = response_entries(vec![0xa1; 8]);
        entries.push(notify_entry(
            IKEV2_NOTIFY_PROTOCOL_ID_NONE,
            Vec::new(),
            notify_message_type,
            vec![0xee, 0x01],
        ));
        let error = decode_response_entries_error(&entries);
        assert_eq!(
            error,
            Ikev2IkeSaRekeyResponseError::PeerErrorNotify {
                notify_message_type,
                protocol_id: IKEV2_NOTIFY_PROTOCOL_ID_NONE,
            },
            "RFC 7296 section 3.10.1 fails the request for error type {notify_message_type}",
        );
        assert_eq!(error.as_str(), "ike_sa_rekey_response_peer_error_notify");
        assert_eq!(error.to_string(), error.as_str());
    }
}

#[test]
fn response_error_range_notify_rejection_cannot_be_suppressed_by_any_unknown_ie_policy() {
    let mut entries = response_entries(vec![0xa1; 8]);
    entries.push(notify_entry(
        IKEV2_NOTIFY_PROTOCOL_ID_NONE,
        Vec::new(),
        16_000,
        vec![0xee, 0x01],
    ));
    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&entries)
        .expect("synthetic error-notify response chain builds");
    for policy in [
        UnknownIePolicy::Preserve,
        UnknownIePolicy::Drop,
        UnknownIePolicy::Reject,
    ] {
        let context = DecodeContext {
            unknown_ie_policy: policy,
            ..DecodeContext::conservative()
        };
        let error = decode_ike_sa_rekey_response_with_context(
            &response_header(),
            &aead_sent_request(),
            first,
            &bytes,
            context,
        )
        .expect_err("error-range notify fails the exchange under every unknown-IE policy");
        assert_eq!(
            error,
            Ikev2IkeSaRekeyResponseError::PeerErrorNotify {
                notify_message_type: 16_000,
                protocol_id: IKEV2_NOTIFY_PROTOCOL_ID_NONE,
            },
            "policy {policy:?} must not suppress the RFC 7296 section 3.10.1 failure",
        );
    }
}

#[test]
fn error_only_response_yields_typed_peer_error_not_missing_payload() {
    for (notify_message_type, role) in [
        (IKEV2_NOTIFY_TEMPORARY_FAILURE, "TEMPORARY_FAILURE"),
        (IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, "NO_PROPOSAL_CHOSEN"),
    ] {
        let entries = vec![notify_entry(
            IKEV2_NOTIFY_PROTOCOL_ID_NONE,
            Vec::new(),
            notify_message_type,
            Vec::new(),
        )];
        let error = decode_response_entries_error(&entries);
        assert_eq!(
            error,
            Ikev2IkeSaRekeyResponseError::PeerErrorNotify {
                notify_message_type,
                protocol_id: IKEV2_NOTIFY_PROTOCOL_ID_NONE,
            },
            "a declining {role}-only response carries its typed notify identity",
        );
        assert_eq!(error.as_str(), "ike_sa_rekey_response_peer_error_notify");
    }
}

#[test]
fn request_decoder_still_ignores_error_range_notifies_including_temporary_failure() {
    let header = request_header();
    let mut entries = request_entries(IKEV2_SECURITY_PROTOCOL_ID_IKE, vec![1; 8], 19, 19, 64);
    entries.push(notify_entry(
        IKEV2_NOTIFY_PROTOCOL_ID_NONE,
        Vec::new(),
        IKEV2_NOTIFY_TEMPORARY_FAILURE,
        Vec::new(),
    ));
    entries.push(notify_entry(
        IKEV2_NOTIFY_PROTOCOL_ID_NONE,
        Vec::new(),
        16_000,
        vec![0xee, 0x01],
    ));
    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&entries)
        .expect("synthetic error-notify request chain builds");
    let request = decode_ike_sa_rekey_request(&header, first, &bytes)
        .expect("request-side error-range notifies remain ignored per RFC 7296 section 3.10.1");
    assert_eq!(
        request
            .unrecognized_notifies()
            .iter()
            .map(|notify| notify.notify_message_type)
            .collect::<Vec<_>>(),
        vec![IKEV2_NOTIFY_TEMPORARY_FAILURE, 16_000]
    );
}

#[test]
fn response_peer_error_notify_output_leaks_no_spi_nonce_or_ke_bytes() {
    let mut entries = response_entries(vec![0xa1; 8]);
    entries.push(notify_entry(
        IKEV2_SECURITY_PROTOCOL_ID_ESP,
        vec![0xab, 0xac, 0xad, 0xae],
        16_000,
        vec![0xee, 0x01],
    ));
    let error = decode_response_entries_error(&entries);
    assert_eq!(
        error,
        Ikev2IkeSaRekeyResponseError::PeerErrorNotify {
            notify_message_type: 16_000,
            protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
        }
    );

    let rendered = format!("{error:?} {error}");
    // Hex renderings of notify SPI, notification data, and proposal SPI.
    assert!(!rendered.contains("abacadae"));
    assert!(!rendered.contains("ee01"));
    assert!(!rendered.contains("a1a2a3a4"));
    // Decimal-array renderings of notify SPI, notification data, proposal
    // SPI, nonce (0x52), and KE public value (0x51).
    assert!(!rendered.contains("[171, 172, 173, 174]"));
    assert!(!rendered.contains("238, 1"));
    assert!(!rendered.contains("[161, 162, 163, 164"));
    assert!(!rendered.contains("[82, 82"));
    assert!(!rendered.contains("[81, 81"));
    // Decimal-integer renderings of the notify SPI and established SPI pair.
    assert!(!rendered.contains(&u32::from_be_bytes([0xab, 0xac, 0xad, 0xae]).to_string()));
    assert!(!rendered.contains(&CURRENT_INITIATOR_SPI.to_string()));
    assert!(!rendered.contains(&CURRENT_RESPONDER_SPI.to_string()));
}
