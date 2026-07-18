use opc_proto_ikev2::{
    build_ike_auth_authentication_payload, build_ike_auth_cleartext_payload_chain,
    build_ike_auth_configuration_payload, build_ike_auth_identification_payload,
    build_ike_auth_traffic_selector_payload, compute_ike_auth_shared_key_mic,
    decode_ike_auth_cleartext_payloads, derive_ike_sa_init_key_material,
    verify_ike_auth_shared_key_mic, Ikev2AuthenticationPayload, Ikev2AuthenticationPayloadBuild,
    Ikev2ConfigurationAttributeBuild, Ikev2ConfigurationPayload, Ikev2ConfigurationPayloadBuild,
    Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2IdentificationPayload,
    Ikev2IdentificationPayloadBuild, Ikev2IkeAuthBuildError, Ikev2IkeAuthPayloadBuild,
    Ikev2IkeAuthPayloadError, Ikev2IkeAuthPeer, Ikev2IkeAuthSignedOctets,
    Ikev2IkeAuthVerificationError, Ikev2KeyExchangePayload, Ikev2KeyExchangePayloadError,
    Ikev2PrfAlgorithm, Ikev2SaInitCryptoProfile, Ikev2SaPayload, Ikev2SaPayloadError,
    Ikev2TrafficSelectorBuild, Ikev2TrafficSelectorPayload, Ikev2TrafficSelectorPayloadBuild,
    Ikev2ValidationProfile, Message, PayloadChain, PayloadType, EXCHANGE_TYPE_IKE_AUTH, HEADER_LEN,
    IKEV2_AUTH_METHOD_SHARED_KEY_MIC, IKEV2_TS_IPV4_ADDR_RANGE,
};
use opc_protocol::{BorrowDecode, DecodeContext, DecodeErrorCode};

fn network_context() -> DecodeContext {
    DecodeContext::conservative()
}

fn append_payload(out: &mut Vec<u8>, next: PayloadType, critical_reserved: u8, body: &[u8]) {
    let length = u16::try_from(4 + body.len()).expect("synthetic payload length fits u16");
    out.push(next.as_u8());
    out.push(critical_reserved);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(body);
}

fn traffic_selector_body(reserved: [u8; 3]) -> Vec<u8> {
    vec![
        1,
        reserved[0],
        reserved[1],
        reserved[2],
        IKEV2_TS_IPV4_ADDR_RANGE,
        0,
        0,
        16,
        0,
        0,
        0xff,
        0xff,
        10,
        0,
        0,
        1,
        10,
        0,
        0,
        254,
    ]
}

fn combined_receive_fixture() -> Vec<u8> {
    let mut payloads = Vec::new();
    append_payload(
        &mut payloads,
        PayloadType::Authentication,
        0x81,
        &[2, 0x11, 0x12, 0x13, b'i'],
    );
    append_payload(
        &mut payloads,
        PayloadType::Configuration,
        0x02,
        &[IKEV2_AUTH_METHOD_SHARED_KEY_MIC, 0x21, 0x22, 0x23, 0xaa],
    );
    append_payload(
        &mut payloads,
        PayloadType::TrafficSelectorInitiator,
        0x04,
        &[1, 0x31, 0x32, 0x33],
    );
    append_payload(
        &mut payloads,
        PayloadType::NoNext,
        0x08,
        &traffic_selector_body([0x41, 0x42, 0x43]),
    );

    let message_len = u32::try_from(HEADER_LEN + payloads.len()).expect("fixture length fits u32");
    let mut message = Vec::with_capacity(message_len as usize);
    message.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
    message.extend_from_slice(&0x1112_1314_1516_1718u64.to_be_bytes());
    message.push(PayloadType::IdentificationInitiator.as_u8());
    message.push(0x2f);
    message.push(EXCHANGE_TYPE_IKE_AUTH);
    message.push(0x09);
    message.extend_from_slice(&0u32.to_be_bytes());
    message.extend_from_slice(&message_len.to_be_bytes());
    message.extend_from_slice(&payloads);
    message
}

fn crypto_profile() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
    .expect("valid test profile")
}

#[test]
fn network_receive_accepts_combined_ignored_fields_and_known_critical_payload() {
    let bytes = combined_receive_fixture();
    let (tail, message) = Message::decode(&bytes, network_context()).expect("network receive");
    assert!(tail.is_empty());
    assert_eq!(message.header.minor_version, 15);
    assert_eq!(message.header.flags.reserved_bits(), 1);

    let first = message
        .payloads_with_context(network_context())
        .next()
        .expect("ID payload")
        .expect("known critical payload accepted");
    assert!(first.critical);
    assert_eq!(first.reserved, 1);

    let decoded = decode_ike_auth_cleartext_payloads(
        message.payloads.first_payload(),
        message.payloads.bytes(),
    )
    .expect("typed receive decode");
    assert_eq!(decoded.identification_initiators.len(), 1);
    assert_eq!(decoded.authentications.len(), 1);
    assert_eq!(decoded.configurations.len(), 1);
    assert_eq!(decoded.traffic_selectors_initiator.len(), 1);
    assert_eq!(
        decoded.identification_initiators[0].reserved,
        [0x11, 0x12, 0x13]
    );
    assert_eq!(
        decoded.identification_initiators[0].to_payload_body(),
        [2, 0x11, 0x12, 0x13, b'i']
    );
}

#[test]
fn each_typed_ignored_field_has_an_opt_in_sender_canonical_diagnostic() {
    let canonical = Ikev2ValidationProfile::SenderCanonical;

    let id = [2, 1, 2, 3, b'i'];
    assert_eq!(
        Ikev2IdentificationPayload::decode_body(&id)
            .expect("network ID")
            .reserved,
        [1, 2, 3]
    );
    assert_eq!(
        Ikev2IdentificationPayload::decode_body_with_profile(&id, canonical),
        Err(Ikev2IkeAuthPayloadError::ReservedNonZero)
    );

    let authentication = [IKEV2_AUTH_METHOD_SHARED_KEY_MIC, 1, 2, 3, 0xaa];
    assert!(Ikev2AuthenticationPayload::decode_body(&authentication).is_ok());
    assert_eq!(
        Ikev2AuthenticationPayload::decode_body_with_profile(&authentication, canonical),
        Err(Ikev2IkeAuthPayloadError::ReservedNonZero)
    );

    let key_exchange = [0, 19, 1, 2, 0xaa];
    assert!(Ikev2KeyExchangePayload::decode_body(&key_exchange).is_ok());
    assert_eq!(
        Ikev2KeyExchangePayload::decode_body_with_profile(&key_exchange, canonical),
        Err(Ikev2KeyExchangePayloadError::ReservedNonZero)
    );

    let configuration = [1, 1, 2, 3];
    assert!(Ikev2ConfigurationPayload::decode_body(&configuration).is_ok());
    assert_eq!(
        Ikev2ConfigurationPayload::decode_body_with_profile(&configuration, canonical),
        Err(Ikev2IkeAuthPayloadError::ReservedNonZero)
    );

    let selectors = traffic_selector_body([1, 2, 3]);
    assert!(Ikev2TrafficSelectorPayload::decode_body(&selectors).is_ok());
    assert_eq!(
        Ikev2TrafficSelectorPayload::decode_body_with_profile(&selectors, canonical),
        Err(Ikev2IkeAuthPayloadError::ReservedNonZero)
    );

    let sa = [0, 0, 0, 16, 1, 1, 0, 1, 0, 0, 0, 8, 1, 0, 0, 12];
    assert!(Ikev2SaPayload::decode_body(&sa).is_ok());
    for reserved_index in [1, 9, 13] {
        let mut noncanonical = sa;
        noncanonical[reserved_index] = 1;
        assert!(Ikev2SaPayload::decode_body(&noncanonical).is_ok());
        assert_eq!(
            Ikev2SaPayload::decode_body_with_profile(&noncanonical, canonical),
            Err(Ikev2SaPayloadError::ReservedNonZero)
        );
    }

    let configuration_attribute = [1, 0, 0, 0, 0x80, 1, 0, 0];
    let decoded = Ikev2ConfigurationPayload::decode_body(&configuration_attribute)
        .expect("network CP attribute");
    assert_eq!(decoded.attributes[0].attribute_type, 1);
    assert_eq!(
        Ikev2ConfigurationPayload::decode_body_with_profile(&configuration_attribute, canonical,),
        Err(Ikev2IkeAuthPayloadError::ReservedNonZero)
    );
}

#[test]
fn auth_uses_exact_received_id_body_and_every_transcript_mutation_fails() {
    let profile = crypto_profile();
    let key_material = derive_ike_sa_init_key_material(
        profile,
        [0x11; 8],
        [0x22; 8],
        &[0x33; 32],
        &[0x44; 32],
        &[0x55; 32],
        None,
    )
    .expect("test key material");
    let identity = [2, 0xa1, 0xa2, 0xa3, b'u', b's', b'e', b'r'];
    let decoded_identity = Ikev2IdentificationPayload::decode_body(&identity).expect("received ID");
    let exact_identity = decoded_identity.to_payload_body();
    assert_eq!(exact_identity, identity);

    let message = b"synthetic-first-ike-sa-init-message";
    let nonce = [0x77; 32];
    let auth_keying_material = [0x99; 64];
    let signed = Ikev2IkeAuthSignedOctets {
        peer: Ikev2IkeAuthPeer::Initiator,
        ike_sa_init_message: message,
        peer_nonce: &nonce,
        identity_payload_body: &exact_identity,
    };
    let auth_data =
        compute_ike_auth_shared_key_mic(profile, &key_material, signed, &auth_keying_material)
            .expect("AUTH MIC");
    let authentication = Ikev2AuthenticationPayload {
        auth_method: IKEV2_AUTH_METHOD_SHARED_KEY_MIC,
        auth_data: &auth_data,
    };
    verify_ike_auth_shared_key_mic(
        profile,
        &key_material,
        signed,
        &auth_keying_material,
        &authentication,
    )
    .expect("exact received ID verifies");

    for index in 0..message.len() {
        let mut changed = message.to_vec();
        changed[index] ^= 1;
        let changed_signed = Ikev2IkeAuthSignedOctets {
            ike_sa_init_message: &changed,
            ..signed
        };
        assert_eq!(
            verify_ike_auth_shared_key_mic(
                profile,
                &key_material,
                changed_signed,
                &auth_keying_material,
                &authentication,
            ),
            Err(Ikev2IkeAuthVerificationError::AuthenticationFailed)
        );
    }

    for index in 0..nonce.len() {
        let mut changed = nonce;
        changed[index] ^= 1;
        let changed_signed = Ikev2IkeAuthSignedOctets {
            peer_nonce: &changed,
            ..signed
        };
        assert_eq!(
            verify_ike_auth_shared_key_mic(
                profile,
                &key_material,
                changed_signed,
                &auth_keying_material,
                &authentication,
            ),
            Err(Ikev2IkeAuthVerificationError::AuthenticationFailed)
        );
    }

    for index in 0..exact_identity.len() {
        let mut changed = exact_identity.clone();
        changed[index] ^= 1;
        let changed_signed = Ikev2IkeAuthSignedOctets {
            identity_payload_body: &changed,
            ..signed
        };
        assert_eq!(
            verify_ike_auth_shared_key_mic(
                profile,
                &key_material,
                changed_signed,
                &auth_keying_material,
                &authentication,
            ),
            Err(Ikev2IkeAuthVerificationError::AuthenticationFailed)
        );
    }
}

#[test]
fn downstream_identification_struct_literal_sets_reserved_transcript_octets_explicitly() {
    let identity = Ikev2IdentificationPayload {
        id_type: 2,
        reserved: [0xa1, 0xa2, 0xa3],
        id_data: b"synthetic-id",
    };

    assert_eq!(
        identity.to_payload_body().as_slice(),
        b"\x02\xa1\xa2\xa3synthetic-id"
    );
}

#[test]
fn receiver_profile_does_not_weaken_major_length_chain_or_unknown_critical_checks() {
    let mut invalid_major = combined_receive_fixture();
    invalid_major[17] = 0x1f;
    assert!(matches!(
        Message::decode(&invalid_major, network_context()),
        Err(error) if matches!(
            error.code(),
            DecodeErrorCode::InvalidEnumValue { field: "major_version", value: 1 }
        )
    ));

    let malformed_length = [0, 0, 0, 3];
    assert!(matches!(
        PayloadChain::new(PayloadType::Nonce, &malformed_length).validate(network_context()),
        Err(error) if matches!(error.code(), DecodeErrorCode::InvalidLength { .. })
    ));

    let trailing_after_no_next = [0, 0, 0, 4, 0];
    assert!(matches!(
        PayloadChain::new(PayloadType::Nonce, &trailing_after_no_next)
            .validate(network_context()),
        Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
    ));

    let unknown_critical = [0, 0x80, 0, 4];
    assert!(matches!(
        PayloadChain::new(PayloadType::Unknown(250), &unknown_critical)
            .validate(network_context()),
        Err(error) if matches!(error.code(), DecodeErrorCode::UnknownCriticalIe)
    ));
    assert!(matches!(
        PayloadChain::new(PayloadType::Unknown(250), &unknown_critical).validate_with_profile(
            network_context(),
            Ikev2ValidationProfile::SenderCanonical,
        ),
        Err(error) if matches!(error.code(), DecodeErrorCode::UnknownCriticalIe)
    ));

    let known_critical = [0, 0x80, 0, 4];
    PayloadChain::new(PayloadType::Nonce, &known_critical)
        .validate(network_context())
        .expect("known critical bit ignored on receive");
    assert!(matches!(
        PayloadChain::new(PayloadType::Nonce, &known_critical).validate_with_profile(
            network_context(),
            Ikev2ValidationProfile::SenderCanonical,
        ),
        Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
    ));
}

#[test]
fn typed_outbound_builders_and_generic_chain_are_sender_canonical() {
    let id = build_ike_auth_identification_payload(&Ikev2IdentificationPayloadBuild {
        id_type: 2,
        id_data: b"synthetic-id".to_vec(),
    })
    .expect("ID build");
    let authentication = build_ike_auth_authentication_payload(&Ikev2AuthenticationPayloadBuild {
        auth_method: IKEV2_AUTH_METHOD_SHARED_KEY_MIC,
        auth_data: vec![0xaa; 32],
    })
    .expect("AUTH build");
    let configuration = build_ike_auth_configuration_payload(&Ikev2ConfigurationPayloadBuild {
        config_type: 1,
        attributes: vec![Ikev2ConfigurationAttributeBuild {
            attribute_type: 1,
            value: Vec::new(),
        }],
    })
    .expect("CP build");
    let selectors = build_ike_auth_traffic_selector_payload(&Ikev2TrafficSelectorPayloadBuild {
        selectors: vec![Ikev2TrafficSelectorBuild {
            ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
            ip_protocol_id: 0,
            start_port: 0,
            end_port: u16::MAX,
            start_address: vec![10, 0, 0, 1],
            end_address: vec![10, 0, 0, 254],
        }],
    })
    .expect("TS build");

    assert_eq!(&id[1..4], &[0, 0, 0]);
    assert_eq!(&authentication[1..4], &[0, 0, 0]);
    assert_eq!(&configuration[1..4], &[0, 0, 0]);
    assert_eq!(&selectors[1..4], &[0, 0, 0]);

    let (first, chain) = build_ike_auth_cleartext_payload_chain(&[
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::IdentificationInitiator,
            body: id,
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Authentication,
            body: authentication,
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Configuration,
            body: configuration,
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::TrafficSelectorInitiator,
            body: selectors,
        },
    ])
    .expect("cleartext chain build");
    PayloadChain::new(first, &chain)
        .validate_with_profile(network_context(), Ikev2ValidationProfile::SenderCanonical)
        .expect("builder output is sender canonical");

    assert_eq!(
        build_ike_auth_configuration_payload(&Ikev2ConfigurationPayloadBuild {
            config_type: 1,
            attributes: vec![Ikev2ConfigurationAttributeBuild {
                attribute_type: 0x8001,
                value: Vec::new(),
            }],
        }),
        Err(Ikev2IkeAuthBuildError::ConfigurationAttributeTypeTooLarge)
    );
}
