//! RFC 7296/IANA specification-authored ENCR_NULL Child-SA fixtures.

use opc_proto_ikev2::{
    build_child_sa_response_payloads, decode_ikev2_dedicated_bearer_create_child_sa_request,
    negotiate_child_sa, Header, HeaderFlags, Ikev2ChildSaCryptoProfile,
    Ikev2ChildSaNegotiationPolicy, Ikev2ChildSaTransformRequirement, Ikev2EncryptionAlgorithm,
    Ikev2IntegrityAlgorithm, Ikev2PrfAlgorithm, Ikev2SaInitCryptoError, Ikev2SaPayload,
    Ikev2TrafficSelectorPayload, PayloadType, EXCHANGE_TYPE_CREATE_CHILD_SA,
    IKEV2_SECURITY_PROTOCOL_ID_ESP,
};

const TRANSFORM_TYPE_ENCR: u8 = 1;
const TRANSFORM_TYPE_INTEG: u8 = 3;
const ENCR_NULL: u16 = 11;
const AUTH_HMAC_SHA2_256_128: u16 = 12;

fn fixture_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("non-hex fixture octet"),
    }
}

fn decode_hex_fixture(value: &str) -> Vec<u8> {
    let mut chunks = value.as_bytes().chunks_exact(2);
    let bytes = chunks
        .by_ref()
        .map(|pair| (fixture_nibble(pair[0]) << 4) | fixture_nibble(pair[1]))
        .collect::<Vec<_>>();
    assert!(chunks.remainder().is_empty(), "odd fixture hex length");
    bytes
}

// RFC 7296 sections 3.3.1/3.3.2, with IANA Transform Type 1 ID 11:
// Proposal(last, len=28, #1, ESP, SPI=4, transforms=2), SPI 0x11223344,
// ENCR_NULL without attributes, then AUTH_HMAC_SHA2_256_128.
const ENCR_NULL_AUTH_SHA256_SA: &[u8] = &[
    0x00, 0x00, 0x00, 0x1c, 0x01, 0x03, 0x04, 0x02, 0x11, 0x22, 0x33, 0x44, 0x03, 0x00, 0x00, 0x08,
    0x01, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x08, 0x03, 0x00, 0x00, 0x0c,
];

// One IPv4 address-range selector for 10.0.0.1, all protocols and ports.
const TSI: &[u8] = &[
    0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x10, 0x00, 0x00, 0xff, 0xff, 0x0a, 0x00, 0x00, 0x01,
    0x0a, 0x00, 0x00, 0x01,
];

// One route-all IPv4 address-range selector.
const TSR: &[u8] = &[
    0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x10, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0xff, 0xff,
];

fn policy(require_integrity: bool) -> Ikev2ChildSaNegotiationPolicy {
    let mut required_transforms = vec![Ikev2ChildSaTransformRequirement {
        transform_type: TRANSFORM_TYPE_ENCR,
        accepted_transform_ids: vec![ENCR_NULL],
    }];
    if require_integrity {
        required_transforms.push(Ikev2ChildSaTransformRequirement {
            transform_type: TRANSFORM_TYPE_INTEG,
            accepted_transform_ids: vec![AUTH_HMAC_SHA2_256_128],
        });
    }
    Ikev2ChildSaNegotiationPolicy {
        accepted_protocol_ids: vec![IKEV2_SECURITY_PROTOCOL_ID_ESP],
        required_transforms,
        accepted_initiator_traffic_selectors: Vec::new(),
        accepted_responder_traffic_selectors: Vec::new(),
    }
}

#[test]
fn published_encr_null_fixture_negotiates_and_reencodes_exact_transform() {
    let sa = Ikev2SaPayload::decode_body(ENCR_NULL_AUTH_SHA256_SA)
        .unwrap_or_else(|error| panic!("ENCR_NULL SA fixture failed to decode: {error:?}"));
    let tsi = Ikev2TrafficSelectorPayload::decode_body(TSI)
        .unwrap_or_else(|error| panic!("TSi fixture failed to decode: {error:?}"));
    let tsr = Ikev2TrafficSelectorPayload::decode_body(TSR)
        .unwrap_or_else(|error| panic!("TSr fixture failed to decode: {error:?}"));
    let negotiation = negotiate_child_sa(&sa, &tsi, &tsr, &policy(true))
        .unwrap_or_else(|error| panic!("ENCR_NULL fixture failed negotiation: {error:?}"));
    let profile = Ikev2ChildSaCryptoProfile::from_child_sa_negotiation(
        Ikev2PrfAlgorithm::HmacSha2_256,
        &negotiation,
    )
    .unwrap_or_else(|error| panic!("ENCR_NULL profile failed: {error:?}"));

    assert_eq!(profile.encryption(), Ikev2EncryptionAlgorithm::Null);
    assert_eq!(profile.encryption().key_length_attribute_bits(), None);
    assert_eq!(profile.encryption().key_material_len(), 0);
    assert_eq!(profile.encryption().salt_len(), 0);
    assert_eq!(
        profile.integrity(),
        Some(Ikev2IntegrityAlgorithm::HmacSha2_256_128)
    );
    assert_eq!(profile.validate_executable(), Ok(()));

    let response = build_child_sa_response_payloads(&negotiation, vec![0x55, 0x66, 0x77, 0x88])
        .unwrap_or_else(|error| panic!("ENCR_NULL response build failed: {error:?}"));
    let response_sa = Ikev2SaPayload::decode_body(&response.security_association.body)
        .unwrap_or_else(|error| panic!("ENCR_NULL response failed to decode: {error:?}"));
    let proposal = &response_sa.proposals[0];
    assert_eq!(proposal.protocol_id, IKEV2_SECURITY_PROTOCOL_ID_ESP);
    assert_eq!(proposal.transforms[0].transform_id, ENCR_NULL);
    assert!(proposal.transforms[0].attributes.is_empty());
    assert_eq!(proposal.transforms[1].transform_id, AUTH_HMAC_SHA2_256_128);
}

#[test]
fn dedicated_bearer_fuzz_seed_is_a_valid_encr_null_create_child_request() {
    let seed =
        include_str!("../fuzz/corpus/dedicated_bearer/create-child-request-encr-null").trim();
    let hex = match seed.strip_prefix("hex:") {
        Some(hex) => hex,
        None => panic!("dedicated-bearer seed omitted hex prefix"),
    };
    let bytes = decode_hex_fixture(hex);
    assert_eq!(bytes[0], 0, "seed must select request fuzz mode");
    let first_payload = PayloadType::from_u8(bytes[1]);
    let header = Header::new(
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        PayloadType::Encrypted,
        EXCHANGE_TYPE_CREATE_CHILD_SA,
        HeaderFlags::from_bits(false, false, false),
        7,
    );
    let request =
        decode_ikev2_dedicated_bearer_create_child_sa_request(&header, first_payload, &bytes[2..])
            .unwrap_or_else(|error| panic!("ENCR_NULL dedicated-bearer seed failed: {error:?}"));

    let proposal = &request.security_association.proposals[0];
    assert_eq!(proposal.transforms[0].transform_id, ENCR_NULL);
    assert!(proposal.transforms[0].attributes.is_empty());
    assert_eq!(proposal.transforms[1].transform_id, AUTH_HMAC_SHA2_256_128);
    let restored = Ikev2ChildSaCryptoProfile::from_transform_ids(
        Ikev2PrfAlgorithm::HmacSha2_256.transform_id(),
        proposal.transforms[0].transform_id,
        None,
        Some(proposal.transforms[1].transform_id),
    )
    .unwrap_or_else(|error| panic!("ENCR_NULL seed profile restore failed: {error:?}"));
    assert_eq!(restored.encryption(), Ikev2EncryptionAlgorithm::Null);
    assert_eq!(restored.directional_encryption_len(), 0);
}

#[test]
fn encr_null_without_integrity_fails_closed() {
    // Proposal(last, len=20, ESP, one ENCR_NULL transform, no INTEG).
    let body = [
        0x00, 0x00, 0x00, 0x14, 0x01, 0x03, 0x04, 0x01, 0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00,
        0x08, 0x01, 0x00, 0x00, 0x0b,
    ];
    let sa = Ikev2SaPayload::decode_body(&body)
        .unwrap_or_else(|error| panic!("NULL-only SA fixture failed to decode: {error:?}"));
    let tsi = Ikev2TrafficSelectorPayload::decode_body(TSI)
        .unwrap_or_else(|error| panic!("TSi fixture failed to decode: {error:?}"));
    let tsr = Ikev2TrafficSelectorPayload::decode_body(TSR)
        .unwrap_or_else(|error| panic!("TSr fixture failed to decode: {error:?}"));
    let negotiation = negotiate_child_sa(&sa, &tsi, &tsr, &policy(false))
        .unwrap_or_else(|error| panic!("NULL-only fixture selection failed: {error:?}"));

    assert_eq!(
        Ikev2ChildSaCryptoProfile::from_child_sa_negotiation(
            Ikev2PrfAlgorithm::HmacSha2_256,
            &negotiation,
        ),
        Err(Ikev2SaInitCryptoError::InconsistentTransformSet)
    );
}

#[test]
fn encr_null_key_length_attribute_is_rejected() {
    // The ENCR_NULL transform is 12 octets because it illegally carries a TV
    // Key Length attribute (type 14, value 128). IANA marks Key Length as not
    // allowed for transform 11.
    let body = [
        0x00, 0x00, 0x00, 0x20, 0x01, 0x03, 0x04, 0x02, 0x11, 0x22, 0x33, 0x44, 0x03, 0x00, 0x00,
        0x0c, 0x01, 0x00, 0x00, 0x0b, 0x80, 0x0e, 0x00, 0x80, 0x00, 0x00, 0x00, 0x08, 0x03, 0x00,
        0x00, 0x0c,
    ];
    let sa = Ikev2SaPayload::decode_body(&body)
        .unwrap_or_else(|error| panic!("attributed NULL fixture failed to decode: {error:?}"));
    let tsi = Ikev2TrafficSelectorPayload::decode_body(TSI)
        .unwrap_or_else(|error| panic!("TSi fixture failed to decode: {error:?}"));
    let tsr = Ikev2TrafficSelectorPayload::decode_body(TSR)
        .unwrap_or_else(|error| panic!("TSr fixture failed to decode: {error:?}"));
    let negotiation = negotiate_child_sa(&sa, &tsi, &tsr, &policy(true))
        .unwrap_or_else(|error| panic!("attributed NULL fixture selection failed: {error:?}"));

    assert_eq!(
        Ikev2ChildSaCryptoProfile::from_child_sa_negotiation(
            Ikev2PrfAlgorithm::HmacSha2_256,
            &negotiation,
        ),
        Err(Ikev2SaInitCryptoError::UnsupportedEncryptionKeyLength {
            transform_id: ENCR_NULL,
            key_bits: Some(128),
        })
    );
}
