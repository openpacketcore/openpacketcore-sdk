use opc_proto_ikev2::{
    build_child_sa_response_payloads, build_create_child_sa_rekey_request_payloads,
    build_create_child_sa_rekey_response_payloads, build_delete_payload_body,
    build_ike_auth_authentication_payload, build_ike_auth_cleartext_payload_chain,
    build_ike_auth_configuration_payload, build_ike_auth_delete_payload,
    build_ike_auth_identification_payload, build_ike_auth_sa_payload,
    build_ike_auth_traffic_selector_payload, compute_ike_auth_shared_key_mic,
    decode_ike_auth_cleartext_payloads, derive_ike_sa_init_key_material,
    encode_nonce_payload_build, ike_auth_shared_key_authentication_payload_body_len,
    negotiate_child_sa, verify_ike_auth_shared_key_mic, Ikev2AuthenticationPayloadBuild,
    Ikev2ChildSaNegotiationError, Ikev2ChildSaNegotiationPolicy, Ikev2ChildSaTransformRequirement,
    Ikev2ConfigurationAttributeBuild, Ikev2ConfigurationPayloadBuild,
    Ikev2CreateChildSaRekeyRequestBuild, Ikev2CreateChildSaRekeyResponseBuild, Ikev2DeletePayload,
    Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2IdentificationPayloadBuild,
    Ikev2IkeAuthBuildError, Ikev2IkeAuthPayloadBuild, Ikev2IkeAuthPayloadError, Ikev2IkeAuthPeer,
    Ikev2IkeAuthSignedOctets, Ikev2IkeAuthVerificationError, Ikev2IntegrityAlgorithm,
    Ikev2KeyExchangePayloadBuild, Ikev2NoncePayloadBuild, Ikev2PrfAlgorithm,
    Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial, Ikev2SaPayload, Ikev2SaPayloadBuild,
    Ikev2SaProposal, Ikev2SaProposalBuild, Ikev2SaTransformBuild, Ikev2TrafficSelectorBuild,
    Ikev2TrafficSelectorPayloadBuild, PayloadChain, PayloadType, IKEV2_AUTH_METHOD_SHARED_KEY_MIC,
    IKEV2_IPSEC_SPI_SIZE, IKEV2_NOTIFY_REKEY_SA, IKEV2_SECURITY_PROTOCOL_ID_ESP,
    IKEV2_SECURITY_PROTOCOL_ID_IKE, IKEV2_TS_IPV4_ADDR_RANGE, IKEV2_TS_IPV6_ADDR_RANGE,
};

mod support;

fn sa_body() -> Vec<u8> {
    build_ike_auth_sa_payload(&child_sa_payload_build()).expect("SA build")
}

fn child_sa_payload_build() -> Ikev2SaPayloadBuild {
    Ikev2SaPayloadBuild {
        proposals: vec![Ikev2SaProposalBuild {
            proposal_number: 1,
            protocol_id: 3,
            spi: vec![0xaa, 0xbb, 0xcc, 0xdd],
            transforms: vec![
                Ikev2SaTransformBuild {
                    transform_type: 1,
                    transform_id: 21,
                    attributes: Vec::new(),
                },
                Ikev2SaTransformBuild {
                    transform_type: 1,
                    transform_id: 20,
                    attributes: Vec::new(),
                },
            ],
        }],
    }
}

fn child_sa_pfs_payload_build(dh_group: u16) -> Ikev2SaPayloadBuild {
    let mut payload = child_sa_payload_build();
    payload.proposals[0].transforms.push(Ikev2SaTransformBuild {
        transform_type: 4,
        transform_id: dh_group,
        attributes: Vec::new(),
    });
    payload
}

fn ts_payload() -> Ikev2TrafficSelectorPayloadBuild {
    Ikev2TrafficSelectorPayloadBuild {
        selectors: vec![Ikev2TrafficSelectorBuild {
            ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
            ip_protocol_id: 0,
            start_port: 0,
            end_port: u16::MAX,
            start_address: vec![10, 0, 0, 1],
            end_address: vec![10, 0, 0, 255],
        }],
    }
}

fn ts_payload_body(
    ts_type: u8,
    ip_protocol_id: u8,
    start_port: u16,
    end_port: u16,
    start_address: &[u8],
    end_address: &[u8],
) -> Vec<u8> {
    let selector_len = 8 + start_address.len() + end_address.len();
    let selector_len = u16::try_from(selector_len).expect("traffic selector length fits u16");
    let mut body = vec![1, 0, 0, 0, ts_type, ip_protocol_id];
    body.extend_from_slice(&selector_len.to_be_bytes());
    body.extend_from_slice(&start_port.to_be_bytes());
    body.extend_from_slice(&end_port.to_be_bytes());
    body.extend_from_slice(start_address);
    body.extend_from_slice(end_address);
    body
}

fn decode_ts_error(body: Vec<u8>) -> Ikev2IkeAuthPayloadError {
    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::TrafficSelectorInitiator,
        body,
    }])
    .expect("malformed TS chain can still be encoded");
    decode_ike_auth_cleartext_payloads(first, &bytes).expect_err("malformed TS")
}

fn profile() -> Ikev2SaInitCryptoProfile {
    Ikev2SaInitCryptoProfile::new_aead(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
    .expect("valid AES-GCM IKE profile")
}

fn key_material() -> Ikev2SaInitKeyMaterial {
    support::ensure_ike_crypto();
    derive_ike_sa_init_key_material(
        opc_proto_ikev2::Ikev2NonceLocalRole::Responder,
        profile(),
        [0x11; 8],
        [0x22; 8],
        &[0x33; 32],
        &[0x44; 32],
        &[0x55; 32],
        None,
    )
    .expect("key material")
}

#[test]
fn shared_key_auth_payload_length_helper_matches_builder() {
    for profile in [
        profile(),
        Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
            Ikev2PrfAlgorithm::HmacSha1,
            Ikev2DhGroup::Modp768,
            Ikev2EncryptionAlgorithm::AesCbc128,
            Ikev2IntegrityAlgorithm::HmacSha1_96,
        )
        .expect("valid explicit SHA1 compatibility profile"),
        Ikev2SaInitCryptoProfile::new_aead(
            Ikev2PrfAlgorithm::HmacSha2_384,
            Ikev2DhGroup::Ecp384,
            Ikev2EncryptionAlgorithm::AesGcm16_256,
        )
        .expect("valid AES-GCM IKE profile"),
    ] {
        let auth_body = build_ike_auth_authentication_payload(&Ikev2AuthenticationPayloadBuild {
            auth_method: IKEV2_AUTH_METHOD_SHARED_KEY_MIC,
            auth_data: vec![0u8; profile.prf().output_len()],
        })
        .expect("AUTH build");
        assert_eq!(
            ike_auth_shared_key_authentication_payload_body_len(profile),
            auth_body.len()
        );
    }
}

#[test]
fn public_nonce_payload_builder_validates_and_encodes_nonce() {
    let nonce = Ikev2NoncePayloadBuild {
        nonce: vec![0x5a; 32],
    };
    assert_eq!(
        encode_nonce_payload_build(&nonce).expect("valid nonce"),
        nonce.nonce
    );

    let error = encode_nonce_payload_build(&Ikev2NoncePayloadBuild { nonce: vec![0; 15] })
        .expect_err("short nonce must fail closed");
    assert_eq!(error.as_str(), "ike_sa_init_build_nonce_too_short");
}

#[test]
fn decodes_and_builds_ike_auth_cleartext_payloads() {
    let idi = build_ike_auth_identification_payload(&Ikev2IdentificationPayloadBuild {
        id_type: 2,
        id_data: b"user@example.net".to_vec(),
    })
    .expect("IDi build");
    let idr = build_ike_auth_identification_payload(&Ikev2IdentificationPayloadBuild {
        id_type: 2,
        id_data: b"epdg.example.net".to_vec(),
    })
    .expect("IDr build");
    let auth = build_ike_auth_authentication_payload(&Ikev2AuthenticationPayloadBuild {
        auth_method: 2,
        auth_data: vec![0x44; 16],
    })
    .expect("AUTH build");
    let cp = build_ike_auth_configuration_payload(&Ikev2ConfigurationPayloadBuild {
        config_type: 2,
        attributes: vec![Ikev2ConfigurationAttributeBuild {
            attribute_type: 1,
            value: vec![192, 0, 2, 10],
        }],
    })
    .expect("CP build");
    let tsi = build_ike_auth_traffic_selector_payload(&ts_payload()).expect("TSi build");
    let tsr = build_ike_auth_traffic_selector_payload(&ts_payload()).expect("TSr build");
    let delete_spi = [1, 2, 3, 4];
    let delete = build_delete_payload_body(
        IKEV2_SECURITY_PROTOCOL_ID_ESP,
        IKEV2_IPSEC_SPI_SIZE,
        &[&delete_spi],
    )
    .expect("Delete build");

    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&[
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::IdentificationInitiator,
            body: idi,
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::IdentificationResponder,
            body: idr,
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Authentication,
            body: auth,
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::ExtensibleAuthentication,
            body: vec![1, 7, 0, 5, 1],
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Configuration,
            body: cp,
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::SecurityAssociation,
            body: sa_body(),
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::TrafficSelectorInitiator,
            body: tsi,
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::TrafficSelectorResponder,
            body: tsr,
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Delete,
            body: delete,
        },
    ])
    .expect("cleartext chain build");

    let decoded = decode_ike_auth_cleartext_payloads(first, &bytes).expect("decode IKE_AUTH");

    assert_eq!(decoded.identification_initiators.len(), 1);
    assert_eq!(decoded.identification_responders.len(), 1);
    assert_eq!(decoded.authentications.len(), 1);
    assert_eq!(decoded.eap.len(), 1);
    assert_eq!(decoded.configurations[0].attributes.len(), 1);
    assert_eq!(decoded.security_associations[0].proposals[0].protocol_id, 3);
    assert_eq!(decoded.traffic_selectors_initiator[0].selectors.len(), 1);
    assert_eq!(decoded.traffic_selectors_responder[0].selectors.len(), 1);
    assert_eq!(decoded.deletes[0].spis.len(), 1);

    let debug = format!("{decoded:?}");
    assert!(!debug.contains("user@example.net"));
    assert!(!debug.contains("epdg.example.net"));
    assert!(!debug.contains("44"));
}

#[test]
fn delete_payload_builder_round_trips_ike_and_esp_spis() {
    let ike_body = build_delete_payload_body(IKEV2_SECURITY_PROTOCOL_ID_IKE, 0, &[])
        .expect("IKE Delete build");
    assert_eq!(ike_body, vec![1, 0, 0, 0]);
    let ike = Ikev2DeletePayload::decode_body(&ike_body).expect("IKE Delete decode");
    assert_eq!(ike.protocol_id, IKEV2_SECURITY_PROTOCOL_ID_IKE);
    assert!(ike.spis.is_empty());
    assert_eq!(ike.encode_body().expect("IKE Delete encode"), ike_body);

    let esp_spi = [0xde, 0xad, 0xbe, 0xef];
    let esp_body = build_delete_payload_body(
        IKEV2_SECURITY_PROTOCOL_ID_ESP,
        IKEV2_IPSEC_SPI_SIZE,
        &[&esp_spi],
    )
    .expect("ESP Delete build");
    assert_eq!(esp_body, vec![3, 4, 0, 1, 0xde, 0xad, 0xbe, 0xef]);
    let esp = Ikev2DeletePayload::decode_body(&esp_body).expect("ESP Delete decode");
    assert_eq!(esp.protocol_id, IKEV2_SECURITY_PROTOCOL_ID_ESP);
    assert_eq!(esp.spis, vec![esp_spi.as_slice()]);
    assert_eq!(
        build_ike_auth_delete_payload(&esp).expect("Delete view build"),
        esp_body
    );

    let second_spi = [0x10, 0x20, 0x30, 0x40];
    let many_body = build_delete_payload_body(
        IKEV2_SECURITY_PROTOCOL_ID_ESP,
        IKEV2_IPSEC_SPI_SIZE,
        &[&esp_spi, &second_spi],
    )
    .expect("many ESP Delete build");
    assert_eq!(
        many_body,
        vec![3, 4, 0, 2, 0xde, 0xad, 0xbe, 0xef, 0x10, 0x20, 0x30, 0x40]
    );
    let many = Ikev2DeletePayload::decode_body(&many_body).expect("many ESP Delete decode");
    assert_eq!(many.spis, vec![esp_spi.as_slice(), second_spi.as_slice()]);
}

#[test]
fn delete_payload_builder_rejects_invalid_spi_shapes() {
    let short_spi = [0xde, 0xad, 0xbe];
    let mismatch = build_delete_payload_body(
        IKEV2_SECURITY_PROTOCOL_ID_ESP,
        IKEV2_IPSEC_SPI_SIZE,
        &[&short_spi],
    )
    .expect_err("short ESP SPI rejected");
    assert_eq!(mismatch, Ikev2IkeAuthBuildError::DeleteSpiSizeMismatch);

    let spi = [0xde, 0xad, 0xbe, 0xef];
    let ike_with_spi = build_delete_payload_body(IKEV2_SECURITY_PROTOCOL_ID_IKE, 4, &[&spi])
        .expect_err("IKE Delete with SPI rejected");
    assert_eq!(ike_with_spi, Ikev2IkeAuthBuildError::DeleteIkeSaSpiInvalid);

    let esp_without_spi = build_delete_payload_body(IKEV2_SECURITY_PROTOCOL_ID_ESP, 4, &[])
        .expect_err("ESP Delete without SPI rejected");
    assert_eq!(esp_without_spi, Ikev2IkeAuthBuildError::DeleteSpiMissing);
}

#[test]
fn computes_and_verifies_shared_key_auth_mic_without_leaking_inputs() {
    let material = key_material();
    let id_body = build_ike_auth_identification_payload(&Ikev2IdentificationPayloadBuild {
        id_type: 2,
        id_data: b"private-user@example.net".to_vec(),
    })
    .expect("ID build");
    let signed = Ikev2IkeAuthSignedOctets {
        peer: Ikev2IkeAuthPeer::Initiator,
        ike_sa_init_message: b"first-ike-sa-init-request-wire-bytes",
        peer_nonce: &[0x77; 32],
        identity_payload_body: &id_body,
    };
    let aaa_keying_material = [0x99; 64];
    let auth_data =
        compute_ike_auth_shared_key_mic(profile(), &material, signed, &aaa_keying_material)
            .expect("AUTH MIC");
    let auth_body = build_ike_auth_authentication_payload(&Ikev2AuthenticationPayloadBuild {
        auth_method: IKEV2_AUTH_METHOD_SHARED_KEY_MIC,
        auth_data: auth_data.clone(),
    })
    .expect("AUTH build");
    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Authentication,
        body: auth_body,
    }])
    .expect("AUTH chain");
    let decoded = decode_ike_auth_cleartext_payloads(first, &bytes).expect("decode AUTH");

    verify_ike_auth_shared_key_mic(
        profile(),
        &material,
        signed,
        &aaa_keying_material,
        &decoded.authentications[0],
    )
    .expect("AUTH verify");

    let wrong_key = [0xaa; 64];
    let err = verify_ike_auth_shared_key_mic(
        profile(),
        &material,
        signed,
        &wrong_key,
        &decoded.authentications[0],
    )
    .expect_err("wrong key must fail");
    assert_eq!(err, Ikev2IkeAuthVerificationError::AuthenticationFailed);

    let rendered = format!(
        "{:?} {:?} {:?}",
        signed,
        Ikev2AuthenticationPayloadBuild {
            auth_method: IKEV2_AUTH_METHOD_SHARED_KEY_MIC,
            auth_data
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::IdentificationInitiator,
            body: id_body.clone()
        }
    );
    assert!(!rendered.contains("private-user@example.net"));
    assert!(!rendered.contains("153"));
    assert!(!rendered.contains("first-ike-sa-init-request-wire-bytes"));
}

#[test]
fn sha1_compatibility_profile_computes_and_verifies_ike_auth_mic() {
    support::ensure_ike_crypto();
    let profile = Ikev2SaInitCryptoProfile::new_encrypt_then_mac(
        Ikev2PrfAlgorithm::HmacSha1,
        Ikev2DhGroup::Modp768,
        Ikev2EncryptionAlgorithm::AesCbc128,
        Ikev2IntegrityAlgorithm::HmacSha1_96,
    )
    .expect("explicit SHA1 compatibility profile is executable");
    let material = derive_ike_sa_init_key_material(
        opc_proto_ikev2::Ikev2NonceLocalRole::Responder,
        profile,
        [0x11; 8],
        [0x22; 8],
        &[0x33; 32],
        &[0x44; 32],
        &[0x55; 96],
        None,
    )
    .expect("SHA1 compatibility key material derives");
    let signed = Ikev2IkeAuthSignedOctets {
        peer: Ikev2IkeAuthPeer::Initiator,
        ike_sa_init_message: b"synthetic-sha1-compatibility-transcript",
        peer_nonce: &[0x66; 32],
        identity_payload_body: &[2, 0, 0, 0, b'i', b'd'],
    };
    let auth_keying_material = [0x77; 64];
    let mic = compute_ike_auth_shared_key_mic(profile, &material, signed, &auth_keying_material)
        .expect("SHA1 compatibility AUTH MIC computes");
    assert_eq!(mic.len(), 20);

    let authentication = opc_proto_ikev2::Ikev2AuthenticationPayload {
        auth_method: IKEV2_AUTH_METHOD_SHARED_KEY_MIC,
        auth_data: &mic,
    };
    verify_ike_auth_shared_key_mic(
        profile,
        &material,
        signed,
        &auth_keying_material,
        &authentication,
    )
    .expect("SHA1 compatibility AUTH MIC verifies");

    let mut corrupted = mic;
    corrupted[0] ^= 0x80;
    let corrupted_authentication = opc_proto_ikev2::Ikev2AuthenticationPayload {
        auth_method: IKEV2_AUTH_METHOD_SHARED_KEY_MIC,
        auth_data: &corrupted,
    };
    assert_eq!(
        verify_ike_auth_shared_key_mic(
            profile,
            &material,
            signed,
            &auth_keying_material,
            &corrupted_authentication,
        ),
        Err(Ikev2IkeAuthVerificationError::AuthenticationFailed)
    );
}

#[test]
fn rejects_unsupported_auth_method_and_malformed_signed_octets() {
    let material = key_material();
    let auth = opc_proto_ikev2::Ikev2AuthenticationPayload {
        auth_method: 1,
        auth_data: &[0x11; 32],
    };
    let signed = Ikev2IkeAuthSignedOctets {
        peer: Ikev2IkeAuthPeer::Responder,
        ike_sa_init_message: b"first-ike-sa-init-response-wire-bytes",
        peer_nonce: &[0x88; 32],
        identity_payload_body: &[2, 0, 0, 0, b'r'],
    };

    let method_err =
        verify_ike_auth_shared_key_mic(profile(), &material, signed, &[0x55; 64], &auth)
            .expect_err("method 1 unsupported");
    assert_eq!(
        method_err,
        Ikev2IkeAuthVerificationError::UnsupportedAuthenticationMethod { method: 1 }
    );

    let bad_nonce = Ikev2IkeAuthSignedOctets {
        peer: Ikev2IkeAuthPeer::Responder,
        ike_sa_init_message: b"first-ike-sa-init-response-wire-bytes",
        peer_nonce: &[0x88; 8],
        identity_payload_body: &[2, 0, 0, 0, b'r'],
    };
    let nonce_err = compute_ike_auth_shared_key_mic(profile(), &material, bad_nonce, &[0x55; 64])
        .expect_err("short nonce rejected");
    assert_eq!(nonce_err.as_str(), "ike_auth_verify_nonce_length_invalid");
}

#[test]
fn negotiates_child_sa_intent_and_builds_response_payloads() {
    let tsi = build_ike_auth_traffic_selector_payload(&ts_payload()).expect("TSi build");
    let tsr = build_ike_auth_traffic_selector_payload(&ts_payload()).expect("TSr build");
    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&[
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::SecurityAssociation,
            body: sa_body(),
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::TrafficSelectorInitiator,
            body: tsi,
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::TrafficSelectorResponder,
            body: tsr,
        },
    ])
    .expect("cleartext chain build");
    let decoded = decode_ike_auth_cleartext_payloads(first, &bytes).expect("decode IKE_AUTH");

    let selected = negotiate_child_sa(
        None,
        &decoded.security_associations[0],
        &decoded.traffic_selectors_initiator[0],
        &decoded.traffic_selectors_responder[0],
        &Ikev2ChildSaNegotiationPolicy {
            accepted_protocol_ids: vec![3],
            required_transforms: vec![Ikev2ChildSaTransformRequirement {
                transform_type: 1,
                accepted_transform_ids: vec![20],
            }],
            accepted_initiator_traffic_selectors: ts_payload().selectors,
            accepted_responder_traffic_selectors: ts_payload().selectors,
        },
    )
    .expect("child SA negotiation");

    assert_eq!(selected.proposal_number, 1);
    assert_eq!(selected.protocol_id, 3);
    assert_eq!(selected.initiator_spi.len(), 4);
    assert_eq!(selected.transforms.len(), 1);
    assert_eq!(selected.transforms[0].transform_id, 20);

    let response = build_child_sa_response_payloads(&selected, vec![0x10, 0x20, 0x30, 0x40])
        .expect("response");
    let (response_first, response_bytes) = build_ike_auth_cleartext_payload_chain(&[
        response.security_association,
        response.traffic_selectors_initiator,
        response.traffic_selectors_responder,
    ])
    .expect("response chain");
    let response_decoded = decode_ike_auth_cleartext_payloads(response_first, &response_bytes)
        .expect("decode response");

    assert_eq!(
        response_decoded.security_associations[0].proposals[0].spi,
        &[0x10, 0x20, 0x30, 0x40]
    );
    assert_eq!(
        response_decoded.traffic_selectors_initiator[0].selectors[0].start_address,
        &[10, 0, 0, 1]
    );

    let debug = format!("{selected:?}");
    assert!(!debug.contains("170"));
    assert!(!debug.contains("10, 0, 0, 1"));
}

#[test]
fn child_sa_negotiation_never_silently_drops_pfs_transform_type() {
    let sa = build_ike_auth_sa_payload(&child_sa_pfs_payload_build(19)).expect("PFS SA build");
    let tsi = build_ike_auth_traffic_selector_payload(&ts_payload()).expect("TSi build");
    let tsr = build_ike_auth_traffic_selector_payload(&ts_payload()).expect("TSr build");
    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&[
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::SecurityAssociation,
            body: sa,
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::TrafficSelectorInitiator,
            body: tsi,
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::TrafficSelectorResponder,
            body: tsr,
        },
    ])
    .expect("cleartext chain build");
    let decoded = decode_ike_auth_cleartext_payloads(first, &bytes).expect("decode PFS offer");

    let unconstrained = negotiate_child_sa(
        None,
        &decoded.security_associations[0],
        &decoded.traffic_selectors_initiator[0],
        &decoded.traffic_selectors_responder[0],
        &Ikev2ChildSaNegotiationPolicy {
            accepted_protocol_ids: vec![IKEV2_SECURITY_PROTOCOL_ID_ESP],
            required_transforms: vec![Ikev2ChildSaTransformRequirement {
                transform_type: 1,
                accepted_transform_ids: vec![20],
            }],
            accepted_initiator_traffic_selectors: Vec::new(),
            accepted_responder_traffic_selectors: Vec::new(),
        },
    )
    .expect_err("unconstrained D-H transform must not be omitted");
    assert_eq!(
        unconstrained,
        Ikev2ChildSaNegotiationError::UnconstrainedTransformType
    );

    let selected = negotiate_child_sa(
        Some(&opc_proto_ikev2::Ikev2KeyExchangePayload {
            dh_group: 19,
            key_exchange_data: &[2; 64],
        }),
        &decoded.security_associations[0],
        &decoded.traffic_selectors_initiator[0],
        &decoded.traffic_selectors_responder[0],
        &Ikev2ChildSaNegotiationPolicy {
            accepted_protocol_ids: vec![IKEV2_SECURITY_PROTOCOL_ID_ESP],
            required_transforms: vec![
                Ikev2ChildSaTransformRequirement {
                    transform_type: 1,
                    accepted_transform_ids: vec![20],
                },
                Ikev2ChildSaTransformRequirement {
                    transform_type: 4,
                    accepted_transform_ids: vec![19],
                },
            ],
            accepted_initiator_traffic_selectors: Vec::new(),
            accepted_responder_traffic_selectors: Vec::new(),
        },
    )
    .expect("PFS policy selects every offered transform type");
    assert_eq!(selected.transforms.len(), 2);
    assert!(selected
        .transforms
        .iter()
        .any(|transform| transform.transform_type == 4 && transform.transform_id == 19));

    let response = build_child_sa_response_payloads(&selected, vec![0x10, 0x20, 0x30, 0x40])
        .expect("response");
    let (response_first, response_bytes) =
        build_ike_auth_cleartext_payload_chain(&[response.security_association])
            .expect("response chain");
    let response_decoded =
        decode_ike_auth_cleartext_payloads(response_first, &response_bytes).expect("response SA");
    let echoed = &response_decoded.security_associations[0].proposals[0].transforms;
    assert_eq!(echoed.len(), 2);
    assert!(echoed
        .iter()
        .any(|transform| transform.transform_type == 4 && transform.transform_id == 19));
}

#[test]
fn builds_create_child_sa_rekey_request_and_response_payloads() {
    let old_spi = [0xca, 0xfe, 0xba, 0xbe];
    let request =
        build_create_child_sa_rekey_request_payloads(&Ikev2CreateChildSaRekeyRequestBuild {
            rekeyed_protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
            rekeyed_spi: old_spi.to_vec(),
            security_association: child_sa_pfs_payload_build(19),
            nonce: Ikev2NoncePayloadBuild {
                nonce: vec![0x11; 32],
            },
            key_exchange: Some(Ikev2KeyExchangePayloadBuild {
                dh_group: 19,
                key_exchange_data: vec![0x22; 64],
            }),
            traffic_selectors_initiator: ts_payload(),
            traffic_selectors_responder: ts_payload(),
        })
        .expect("rekey request build");
    let request_entries = request.into_payloads();
    let request_types: Vec<PayloadType> = request_entries
        .iter()
        .map(|entry| entry.payload_type)
        .collect();
    assert_eq!(
        request_types,
        vec![
            PayloadType::Notify,
            PayloadType::SecurityAssociation,
            PayloadType::Nonce,
            PayloadType::KeyExchange,
            PayloadType::TrafficSelectorInitiator,
            PayloadType::TrafficSelectorResponder,
        ]
    );

    let (first, bytes) =
        build_ike_auth_cleartext_payload_chain(&request_entries).expect("request chain");
    let decoded = decode_ike_auth_cleartext_payloads(first, &bytes).expect("decode request");
    assert_eq!(decoded.notifies.len(), 1);
    assert_eq!(
        decoded.notifies[0].notify_message_type,
        IKEV2_NOTIFY_REKEY_SA
    );
    assert_eq!(
        decoded.notifies[0].protocol_id,
        IKEV2_SECURITY_PROTOCOL_ID_ESP
    );
    assert_eq!(decoded.notifies[0].spi, old_spi.as_slice());
    assert!(decoded.notifies[0].notification_data.is_empty());
    assert_eq!(decoded.security_associations.len(), 1);
    assert_eq!(decoded.traffic_selectors_initiator.len(), 1);
    assert_eq!(decoded.traffic_selectors_responder.len(), 1);

    let raw_types: Vec<PayloadType> = PayloadChain::new(first, &bytes)
        .iter()
        .map(|payload| payload.expect("payload decode").payload_type)
        .collect();
    assert_eq!(raw_types, request_types);

    let response =
        build_create_child_sa_rekey_response_payloads(&Ikev2CreateChildSaRekeyResponseBuild {
            security_association: child_sa_payload_build(),
            nonce: Ikev2NoncePayloadBuild {
                nonce: vec![0x33; 32],
            },
            key_exchange: None,
            traffic_selectors_initiator: ts_payload(),
            traffic_selectors_responder: ts_payload(),
        })
        .expect("rekey response build");
    let response_entries = response.into_payloads();
    let response_types: Vec<PayloadType> = response_entries
        .iter()
        .map(|entry| entry.payload_type)
        .collect();
    assert_eq!(
        response_types,
        vec![
            PayloadType::SecurityAssociation,
            PayloadType::Nonce,
            PayloadType::TrafficSelectorInitiator,
            PayloadType::TrafficSelectorResponder,
        ]
    );
}

#[test]
fn rekey_request_builder_rejects_invalid_rekey_notify_shape() {
    let mut request = Ikev2CreateChildSaRekeyRequestBuild {
        rekeyed_protocol_id: IKEV2_SECURITY_PROTOCOL_ID_IKE,
        rekeyed_spi: vec![0xca, 0xfe, 0xba, 0xbe],
        security_association: child_sa_payload_build(),
        nonce: Ikev2NoncePayloadBuild {
            nonce: vec![0x11; 32],
        },
        key_exchange: None,
        traffic_selectors_initiator: ts_payload(),
        traffic_selectors_responder: ts_payload(),
    };
    let invalid_protocol = build_create_child_sa_rekey_request_payloads(&request)
        .expect_err("IKE protocol cannot identify Child-SA rekey");
    assert_eq!(
        invalid_protocol,
        Ikev2IkeAuthBuildError::InvalidRekeyProtocolId
    );

    request.rekeyed_protocol_id = IKEV2_SECURITY_PROTOCOL_ID_ESP;
    request.rekeyed_spi = vec![0xca, 0xfe, 0xba];
    let invalid_spi = build_create_child_sa_rekey_request_payloads(&request)
        .expect_err("short rekey SPI rejected");
    assert_eq!(invalid_spi, Ikev2IkeAuthBuildError::RekeySpiLengthInvalid);
}

#[test]
fn rekey_builder_enforces_dh_and_key_exchange_consistency() {
    let mut request = Ikev2CreateChildSaRekeyRequestBuild {
        rekeyed_protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
        rekeyed_spi: vec![0xca, 0xfe, 0xba, 0xbe],
        security_association: child_sa_pfs_payload_build(19),
        nonce: Ikev2NoncePayloadBuild {
            nonce: vec![0x11; 32],
        },
        key_exchange: None,
        traffic_selectors_initiator: ts_payload(),
        traffic_selectors_responder: ts_payload(),
    };

    let missing = build_create_child_sa_rekey_request_payloads(&request)
        .expect_err("D-H transform requires KE");
    assert_eq!(missing, Ikev2IkeAuthBuildError::KeyExchangeRequired);

    request.key_exchange = Some(Ikev2KeyExchangePayloadBuild {
        dh_group: 20,
        key_exchange_data: vec![0x22; 65],
    });
    let mismatch = build_create_child_sa_rekey_request_payloads(&request)
        .expect_err("KE group must match an offered D-H transform");
    assert_eq!(mismatch, Ikev2IkeAuthBuildError::KeyExchangeDhGroupMismatch);

    request.security_association = child_sa_payload_build();
    let unexpected = build_create_child_sa_rekey_request_payloads(&request)
        .expect_err("KE without a D-H transform must fail closed");
    assert_eq!(unexpected, Ikev2IkeAuthBuildError::UnexpectedKeyExchange);
}

#[test]
fn rejects_child_sa_selector_mismatch_and_missing_responder_spi() {
    let tsi = build_ike_auth_traffic_selector_payload(&ts_payload()).expect("TSi build");
    let tsr = build_ike_auth_traffic_selector_payload(&ts_payload()).expect("TSr build");
    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&[
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::SecurityAssociation,
            body: sa_body(),
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::TrafficSelectorInitiator,
            body: tsi,
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::TrafficSelectorResponder,
            body: tsr,
        },
    ])
    .expect("cleartext chain build");
    let decoded = decode_ike_auth_cleartext_payloads(first, &bytes).expect("decode IKE_AUTH");

    let selector_mismatch = negotiate_child_sa(
        None,
        &decoded.security_associations[0],
        &decoded.traffic_selectors_initiator[0],
        &decoded.traffic_selectors_responder[0],
        &Ikev2ChildSaNegotiationPolicy {
            accepted_protocol_ids: vec![3],
            required_transforms: vec![Ikev2ChildSaTransformRequirement {
                transform_type: 1,
                accepted_transform_ids: vec![20],
            }],
            accepted_initiator_traffic_selectors: vec![Ikev2TrafficSelectorBuild {
                ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
                ip_protocol_id: 0,
                start_port: 0,
                end_port: u16::MAX,
                start_address: vec![192, 0, 2, 1],
                end_address: vec![192, 0, 2, 255],
            }],
            accepted_responder_traffic_selectors: ts_payload().selectors,
        },
    )
    .expect_err("selector mismatch");
    assert_eq!(
        selector_mismatch,
        Ikev2ChildSaNegotiationError::TrafficSelectorMismatch
    );

    let selected = negotiate_child_sa(
        None,
        &decoded.security_associations[0],
        &decoded.traffic_selectors_initiator[0],
        &decoded.traffic_selectors_responder[0],
        &Ikev2ChildSaNegotiationPolicy {
            accepted_protocol_ids: vec![3],
            required_transforms: vec![Ikev2ChildSaTransformRequirement {
                transform_type: 1,
                accepted_transform_ids: vec![20],
            }],
            accepted_initiator_traffic_selectors: Vec::new(),
            accepted_responder_traffic_selectors: Vec::new(),
        },
    )
    .expect("child SA negotiation");
    let spi_err = build_child_sa_response_payloads(&selected, Vec::new()).expect_err("missing SPI");
    assert_eq!(spi_err, Ikev2IkeAuthBuildError::ChildSaResponderSpiMissing);

    let missing_transform_policy = negotiate_child_sa(
        None,
        &decoded.security_associations[0],
        &decoded.traffic_selectors_initiator[0],
        &decoded.traffic_selectors_responder[0],
        &Ikev2ChildSaNegotiationPolicy {
            accepted_protocol_ids: vec![3],
            required_transforms: Vec::new(),
            accepted_initiator_traffic_selectors: Vec::new(),
            accepted_responder_traffic_selectors: Vec::new(),
        },
    )
    .expect_err("empty transform policy");
    assert_eq!(
        missing_transform_policy,
        Ikev2ChildSaNegotiationError::NoTransformRequirements
    );

    let duplicate_transform_policy = negotiate_child_sa(
        None,
        &decoded.security_associations[0],
        &decoded.traffic_selectors_initiator[0],
        &decoded.traffic_selectors_responder[0],
        &Ikev2ChildSaNegotiationPolicy {
            accepted_protocol_ids: vec![3],
            required_transforms: vec![
                Ikev2ChildSaTransformRequirement {
                    transform_type: 1,
                    accepted_transform_ids: vec![20],
                },
                Ikev2ChildSaTransformRequirement {
                    transform_type: 1,
                    accepted_transform_ids: vec![21],
                },
            ],
            accepted_initiator_traffic_selectors: Vec::new(),
            accepted_responder_traffic_selectors: Vec::new(),
        },
    )
    .expect_err("duplicate transform policy");
    assert_eq!(
        duplicate_transform_policy,
        Ikev2ChildSaNegotiationError::DuplicateTransformRequirement
    );

    let unsupported_protocol = negotiate_child_sa(
        None,
        &decoded.security_associations[0],
        &decoded.traffic_selectors_initiator[0],
        &decoded.traffic_selectors_responder[0],
        &Ikev2ChildSaNegotiationPolicy {
            accepted_protocol_ids: vec![4],
            required_transforms: vec![Ikev2ChildSaTransformRequirement {
                transform_type: 1,
                accepted_transform_ids: vec![20],
            }],
            accepted_initiator_traffic_selectors: Vec::new(),
            accepted_responder_traffic_selectors: Vec::new(),
        },
    )
    .expect_err("unsupported protocol");
    assert_eq!(
        unsupported_protocol,
        Ikev2ChildSaNegotiationError::NoSupportedProposal
    );

    let spi = [0xaa, 0xbb, 0xcc, 0xdd];
    let empty_transform_sa = Ikev2SaPayload {
        proposals: vec![Ikev2SaProposal {
            proposal_number: 1,
            protocol_id: 3,
            spi_size: 4,
            spi: &spi,
            transforms: Vec::new(),
        }],
    };
    let empty_transforms = negotiate_child_sa(
        None,
        &empty_transform_sa,
        &decoded.traffic_selectors_initiator[0],
        &decoded.traffic_selectors_responder[0],
        &Ikev2ChildSaNegotiationPolicy {
            accepted_protocol_ids: vec![3],
            required_transforms: vec![Ikev2ChildSaTransformRequirement {
                transform_type: 1,
                accepted_transform_ids: vec![20],
            }],
            accepted_initiator_traffic_selectors: Vec::new(),
            accepted_responder_traffic_selectors: Vec::new(),
        },
    )
    .expect_err("empty transforms");
    assert_eq!(empty_transforms, Ikev2ChildSaNegotiationError::NoTransforms);
}

#[test]
fn rejects_malformed_traffic_selectors_and_invalid_builders() {
    let auth_error = build_ike_auth_authentication_payload(&Ikev2AuthenticationPayloadBuild {
        auth_method: 0,
        auth_data: vec![1, 2, 3],
    })
    .expect_err("invalid AUTH method");
    assert_eq!(
        auth_error,
        Ikev2IkeAuthBuildError::InvalidAuthenticationMethod
    );

    let invalid_ts = vec![1, 0, 0, 0, 7, 0, 0, 7, 0, 0, 0xff, 0xff, 10];
    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::TrafficSelectorInitiator,
        body: invalid_ts,
    }])
    .expect("malformed TS chain can still be encoded");
    let error = decode_ike_auth_cleartext_payloads(first, &bytes).expect_err("malformed TS");

    assert_eq!(
        error.as_str(),
        Ikev2IkeAuthPayloadError::TrafficSelectorLengthTooShort.as_str()
    );

    assert_eq!(
        decode_ts_error(ts_payload_body(42, 6, 0, 1, &[10, 0, 0, 1], &[10, 0, 0, 2],)),
        Ikev2IkeAuthPayloadError::TrafficSelectorTypeUnsupported
    );
    assert_eq!(
        decode_ts_error(ts_payload_body(
            IKEV2_TS_IPV6_ADDR_RANGE,
            6,
            0,
            1,
            &[10, 0, 0, 1],
            &[10, 0, 0, 2],
        )),
        Ikev2IkeAuthPayloadError::TrafficSelectorAddressLengthInvalid
    );
    assert_eq!(
        decode_ts_error(ts_payload_body(
            IKEV2_TS_IPV4_ADDR_RANGE,
            6,
            2,
            1,
            &[10, 0, 0, 1],
            &[10, 0, 0, 2],
        )),
        Ikev2IkeAuthPayloadError::TrafficSelectorPortRangeInvalid
    );
    assert_eq!(
        decode_ts_error(ts_payload_body(
            IKEV2_TS_IPV4_ADDR_RANGE,
            6,
            0,
            1,
            &[10, 0, 0, 2],
            &[10, 0, 0, 1],
        )),
        Ikev2IkeAuthPayloadError::TrafficSelectorAddressRangeInvalid
    );

    let unsupported_ts_type =
        build_ike_auth_traffic_selector_payload(&Ikev2TrafficSelectorPayloadBuild {
            selectors: vec![Ikev2TrafficSelectorBuild {
                ts_type: 42,
                ip_protocol_id: 0,
                start_port: 0,
                end_port: 1,
                start_address: vec![10, 0, 0, 1],
                end_address: vec![10, 0, 0, 2],
            }],
        })
        .expect_err("unsupported TS type");
    assert_eq!(
        unsupported_ts_type,
        Ikev2IkeAuthBuildError::TrafficSelectorTypeUnsupported
    );

    let family_mismatch =
        build_ike_auth_traffic_selector_payload(&Ikev2TrafficSelectorPayloadBuild {
            selectors: vec![Ikev2TrafficSelectorBuild {
                ts_type: IKEV2_TS_IPV6_ADDR_RANGE,
                ip_protocol_id: 0,
                start_port: 0,
                end_port: 1,
                start_address: vec![10, 0, 0, 1],
                end_address: vec![10, 0, 0, 2],
            }],
        })
        .expect_err("IPv6 TS type needs IPv6 addresses");
    assert_eq!(
        family_mismatch,
        Ikev2IkeAuthBuildError::TrafficSelectorAddressLengthInvalid
    );

    let reversed_ports =
        build_ike_auth_traffic_selector_payload(&Ikev2TrafficSelectorPayloadBuild {
            selectors: vec![Ikev2TrafficSelectorBuild {
                ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
                ip_protocol_id: 0,
                start_port: 2,
                end_port: 1,
                start_address: vec![10, 0, 0, 1],
                end_address: vec![10, 0, 0, 2],
            }],
        })
        .expect_err("reversed ports rejected");
    assert_eq!(
        reversed_ports,
        Ikev2IkeAuthBuildError::TrafficSelectorPortRangeInvalid
    );

    let reversed_addresses =
        build_ike_auth_traffic_selector_payload(&Ikev2TrafficSelectorPayloadBuild {
            selectors: vec![Ikev2TrafficSelectorBuild {
                ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
                ip_protocol_id: 0,
                start_port: 0,
                end_port: u16::MAX,
                start_address: vec![10, 0, 0, 2],
                end_address: vec![10, 0, 0, 1],
            }],
        })
        .expect_err("reversed addresses rejected");
    assert_eq!(
        reversed_addresses,
        Ikev2IkeAuthBuildError::TrafficSelectorAddressRangeInvalid
    );
}

#[test]
fn traffic_selector_wildcard_and_opaque_port_semantics_are_canonical() {
    let start_address = [192, 0, 2, 10];
    let end_address = [192, 0, 2, 20];
    let wildcard_narrow =
        build_ike_auth_traffic_selector_payload(&Ikev2TrafficSelectorPayloadBuild {
            selectors: vec![Ikev2TrafficSelectorBuild {
                ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
                ip_protocol_id: 0,
                start_port: 4_500,
                end_port: 4_500,
                start_address: start_address.to_vec(),
                end_address: end_address.to_vec(),
            }],
        })
        .expect_err("protocol zero requires the canonical ANY port range");
    assert_eq!(
        wildcard_narrow,
        Ikev2IkeAuthBuildError::TrafficSelectorPortRangeInvalid
    );
    assert_eq!(
        decode_ts_error(ts_payload_body(
            IKEV2_TS_IPV4_ADDR_RANGE,
            0,
            4_500,
            4_500,
            &start_address,
            &end_address,
        )),
        Ikev2IkeAuthPayloadError::TrafficSelectorPortRangeInvalid
    );

    let protocol_zero_opaque =
        build_ike_auth_traffic_selector_payload(&Ikev2TrafficSelectorPayloadBuild {
            selectors: vec![Ikev2TrafficSelectorBuild {
                ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
                ip_protocol_id: 0,
                start_port: u16::MAX,
                end_port: 0,
                start_address: start_address.to_vec(),
                end_address: end_address.to_vec(),
            }],
        })
        .expect_err("OPAQUE is not the canonical protocol-zero ANY representation");
    assert_eq!(
        protocol_zero_opaque,
        Ikev2IkeAuthBuildError::TrafficSelectorPortRangeInvalid
    );
    assert_eq!(
        decode_ts_error(ts_payload_body(
            IKEV2_TS_IPV4_ADDR_RANGE,
            0,
            u16::MAX,
            0,
            &start_address,
            &end_address,
        )),
        Ikev2IkeAuthPayloadError::TrafficSelectorPortRangeInvalid
    );

    let opaque = Ikev2TrafficSelectorPayloadBuild {
        selectors: vec![Ikev2TrafficSelectorBuild {
            ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
            ip_protocol_id: 6,
            start_port: u16::MAX,
            end_port: 0,
            start_address: start_address.to_vec(),
            end_address: end_address.to_vec(),
        }],
    };
    let opaque_body =
        build_ike_auth_traffic_selector_payload(&opaque).expect("RFC OPAQUE selector builds");
    assert_eq!(
        opaque_body,
        ts_payload_body(
            IKEV2_TS_IPV4_ADDR_RANGE,
            6,
            u16::MAX,
            0,
            &start_address,
            &end_address,
        )
    );
    let (first, bytes) = build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::TrafficSelectorInitiator,
        body: opaque_body,
    }])
    .expect("OPAQUE TS chain");
    let decoded =
        decode_ike_auth_cleartext_payloads(first, &bytes).expect("RFC OPAQUE selector decodes");
    let decoded = &decoded.traffic_selectors_initiator[0].selectors[0];
    assert_eq!(decoded.ip_protocol_id, 6);
    assert_eq!(decoded.start_port, u16::MAX);
    assert_eq!(decoded.end_port, 0);
}
fn ke_width_request(group: u16, width: usize) -> Ikev2CreateChildSaRekeyRequestBuild {
    Ikev2CreateChildSaRekeyRequestBuild {
        rekeyed_protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
        rekeyed_spi: vec![1, 2, 3, 4],
        security_association: child_sa_pfs_payload_build(group),
        nonce: Ikev2NoncePayloadBuild {
            nonce: vec![0x11; 32],
        },
        key_exchange: Some(Ikev2KeyExchangePayloadBuild {
            dh_group: group,
            key_exchange_data: vec![0x22; width],
        }),
        traffic_selectors_initiator: ts_payload(),
        traffic_selectors_responder: ts_payload(),
    }
}

#[test]
fn generic_ke_request_build_enforces_group_width() {
    // RFC 7296 section 3.4: fixed group widths, including 96 octets for group 1.
    for (group, width) in [(1, 96), (2, 128), (14, 256), (19, 64), (20, 96), (21, 132)] {
        assert!(
            build_create_child_sa_rekey_request_payloads(&ke_width_request(group, width)).is_ok()
        );
        for actual in [1, width - 1, width + 1] {
            assert!(
                matches!(
                    build_create_child_sa_rekey_request_payloads(&ke_width_request(group, actual)),
                    Err(error) if error.as_str() == "ike_auth_build_ke_value_invalid"
                ),
                "group {group}, width {actual}"
            );
        }
    }
}

#[test]
fn generic_ke_response_build_enforces_group_width() {
    for (group, width) in [(1, 96), (2, 128), (14, 256), (19, 64), (20, 96), (21, 132)] {
        let request = ke_width_request(group, width);
        let mut response = Ikev2CreateChildSaRekeyResponseBuild {
            security_association: request.security_association,
            nonce: request.nonce,
            key_exchange: request.key_exchange,
            traffic_selectors_initiator: request.traffic_selectors_initiator,
            traffic_selectors_responder: request.traffic_selectors_responder,
        };
        assert!(build_create_child_sa_rekey_response_payloads(&response).is_ok());
        for actual in [1, width - 1, width + 1] {
            response.key_exchange = Some(Ikev2KeyExchangePayloadBuild {
                dh_group: group,
                key_exchange_data: vec![0x22; actual],
            });
            assert!(
                matches!(
                    build_create_child_sa_rekey_response_payloads(&response),
                    Err(error) if error.as_str() == "ike_auth_build_ke_value_invalid"
                ),
                "group {group}, width {actual}"
            );
        }
    }
}

fn outgoing_child_request() -> Ikev2CreateChildSaRekeyRequestBuild {
    Ikev2CreateChildSaRekeyRequestBuild {
        rekeyed_protocol_id: 3,
        rekeyed_spi: vec![1, 2, 3, 4],
        security_association: child_sa_payload_build(),
        nonce: Ikev2NoncePayloadBuild { nonce: vec![3; 32] },
        key_exchange: None,
        traffic_selectors_initiator: ts_payload(),
        traffic_selectors_responder: ts_payload(),
    }
}
#[test]
fn outgoing_child_request_rejects_a_short_local_nonce() {
    for len in [16, 24, 31, 32] {
        let mut input = outgoing_child_request();
        input.nonce.nonce.resize(len, 3);
        let result = build_create_child_sa_rekey_request_payloads(&input);
        if len < 32 {
            assert_eq!(
                result,
                Err(Ikev2IkeAuthBuildError::Nonce(
                    opc_proto_ikev2::Ikev2SaInitBuildError::NonceTooShort
                ))
            );
        } else {
            assert!(result.is_ok());
        }
    }
}
#[test]
fn outgoing_child_response_rejects_a_short_local_nonce() {
    for len in [16, 24, 31, 32] {
        let input = Ikev2CreateChildSaRekeyResponseBuild {
            security_association: child_sa_payload_build(),
            nonce: Ikev2NoncePayloadBuild {
                nonce: vec![3; len],
            },
            key_exchange: None,
            traffic_selectors_initiator: ts_payload(),
            traffic_selectors_responder: ts_payload(),
        };
        let result = build_create_child_sa_rekey_response_payloads(&input);
        if len < 32 {
            assert_eq!(
                result,
                Err(Ikev2IkeAuthBuildError::Nonce(
                    opc_proto_ikev2::Ikev2SaInitBuildError::NonceTooShort
                ))
            );
        } else {
            assert!(result.is_ok());
        }
    }
}
fn child_group_offer(separate: bool) -> Ikev2SaPayloadBuild {
    let mut sa = child_sa_pfs_payload_build(1);
    if separate {
        let mut p = child_sa_pfs_payload_build(14).proposals.remove(0);
        p.proposal_number = 2;
        sa.proposals.push(p);
    } else {
        sa.proposals[0].transforms.push(Ikev2SaTransformBuild {
            transform_type: 4,
            transform_id: 14,
            attributes: vec![],
        });
    }
    sa
}

fn assert_child_pfs_ke_guess_retry(guessed_group: u16, guessed_width: usize) {
    let mut offer = child_sa_pfs_payload_build(guessed_group);
    offer.proposals[0].transforms.push(Ikev2SaTransformBuild {
        transform_type: 4,
        transform_id: 14,
        attributes: vec![],
    });
    let sa_wire = build_ike_auth_sa_payload(&offer).expect("peer SA offer");
    let sa = Ikev2SaPayload::decode_body(&sa_wire).expect("received SA");
    let ts_wire = build_ike_auth_traffic_selector_payload(&ts_payload()).expect("TS");
    let ts =
        opc_proto_ikev2::Ikev2TrafficSelectorPayload::decode_body(&ts_wire).expect("received TS");
    let policy = Ikev2ChildSaNegotiationPolicy {
        accepted_protocol_ids: vec![IKEV2_SECURITY_PROTOCOL_ID_ESP],
        required_transforms: vec![
            Ikev2ChildSaTransformRequirement {
                transform_type: 1,
                accepted_transform_ids: vec![20],
            },
            Ikev2ChildSaTransformRequirement {
                transform_type: 4,
                accepted_transform_ids: vec![14],
            },
        ],
        accepted_initiator_traffic_selectors: vec![],
        accepted_responder_traffic_selectors: vec![],
    };
    // Use received wire rather than the local builder, which requires an
    // implemented group. Group 31's 32-octet X25519 value is RFC 8031 section 3.1.
    let mut ke_wire = guessed_group.to_be_bytes().to_vec();
    ke_wire.extend_from_slice(&[0, 0]);
    ke_wire.resize(4 + guessed_width, 0);
    ke_wire[4] = 9;
    let ke = opc_proto_ikev2::Ikev2KeyExchangePayload::decode_body(&ke_wire)
        .expect("structurally valid received KE");
    // RFC 7296 sections 1.3 and 3.4 require the selected-group retry before
    // interpreting a KE for a different group, including an unimplemented one.
    let retry = negotiate_child_sa(Some(&ke), &sa, &ts, &ts, &policy)
        .expect_err("different KE group requests a retry");
    assert_eq!(
        retry,
        Ikev2ChildSaNegotiationError::KeyExchangeDhGroupMismatch {
            received: guessed_group,
            preferred: 14,
        }
    );
    let notify = retry.invalid_ke_notify().expect("selected-group retry");
    assert_eq!(notify.protocol_id, 0);
    assert!(notify.spi.is_empty());
    assert_eq!(notify.notify_message_type, 17);
    assert_eq!(notify.notification_data, [0, 14]);
    assert_eq!(
        opc_proto_ikev2::build_ike_auth_notify_payload(&notify).expect("retry wire"),
        [0, 0, 0, 17, 0, 14]
    );

    let mut retry_wire = vec![0, 14, 0, 0];
    retry_wire.extend_from_slice(&[2; 256]);
    let ke = opc_proto_ikev2::Ikev2KeyExchangePayload::decode_body(&retry_wire)
        .expect("received group-14 retry");
    let selected = negotiate_child_sa(Some(&ke), &sa, &ts, &ts, &policy)
        .expect("selected group's correctly sized retry succeeds");
    assert_eq!(
        selected
            .transforms
            .iter()
            .find(|transform| transform.transform_type == 4)
            .expect("selected DH transform")
            .transform_id,
        14
    );
    for width in [1, 255, 257] {
        retry_wire.resize(4 + width, 2);
        let ke = opc_proto_ikev2::Ikev2KeyExchangePayload::decode_body(&retry_wire)
            .expect("structurally valid matching-group KE");
        let error = negotiate_child_sa(Some(&ke), &sa, &ts, &ts, &policy)
            .expect_err("matching-group malformed width is rejected");
        assert_eq!(error, Ikev2ChildSaNegotiationError::InvalidKeyExchange);
        assert!(error.invalid_ke_notify().is_none());
    }
}

#[test]
fn child_pfs_retries_an_unsupported_ke_guess_with_the_selected_group() {
    assert_child_pfs_ke_guess_retry(31, 32);
}

#[test]
fn child_pfs_retries_a_legacy_unsupported_ke_guess_with_the_selected_group() {
    assert_child_pfs_ke_guess_retry(5, 192);
}

#[test]
fn child_pfs_retries_a_different_supported_ke_guess_before_width_validation() {
    for width in [64, 63, 65] {
        assert_child_pfs_ke_guess_retry(19, width);
    }
}

#[test]
fn child_pfs_prefers_stronger_common_groups_over_group_one() {
    for separate in [false, true] {
        let wire = build_ike_auth_sa_payload(&child_group_offer(separate)).expect("SA");
        let sa = Ikev2SaPayload::decode_body(&wire).expect("SA view");
        let ts = build_ike_auth_traffic_selector_payload(&ts_payload()).expect("TS");
        let ts = opc_proto_ikev2::Ikev2TrafficSelectorPayload::decode_body(&ts).expect("TS view");
        let policy = Ikev2ChildSaNegotiationPolicy {
            accepted_protocol_ids: vec![3],
            required_transforms: vec![
                Ikev2ChildSaTransformRequirement {
                    transform_type: 1,
                    accepted_transform_ids: vec![20],
                },
                Ikev2ChildSaTransformRequirement {
                    transform_type: 4,
                    accepted_transform_ids: vec![1, 14],
                },
            ],
            accepted_initiator_traffic_selectors: vec![],
            accepted_responder_traffic_selectors: vec![],
        };
        let retry = negotiate_child_sa(
            Some(&opc_proto_ikev2::Ikev2KeyExchangePayload {
                dh_group: 1,
                key_exchange_data: &[2; 96],
            }),
            &sa,
            &ts,
            &ts,
            &policy,
        )
        .expect_err("strong common group requests KE retry");
        assert_eq!(
            retry,
            Ikev2ChildSaNegotiationError::KeyExchangeDhGroupMismatch {
                received: 1,
                preferred: 14
            }
        );
        let notify = retry.invalid_ke_notify().expect("retry notify");
        assert_eq!(notify.notify_message_type, 17);
        assert_eq!(notify.protocol_id, 0);
        assert!(notify.spi.is_empty());
        assert_eq!(notify.notification_data, [0, 14]);
        assert_eq!(
            opc_proto_ikev2::build_ike_auth_notify_payload(&notify).expect("encoded KE retry"),
            [0, 0, 0, 17, 0, 14]
        );
        for width in [1, 255, 257] {
            assert_eq!(
                negotiate_child_sa(
                    Some(&opc_proto_ikev2::Ikev2KeyExchangePayload {
                        dh_group: 14,
                        key_exchange_data: &vec![2; width],
                    }),
                    &sa,
                    &ts,
                    &ts,
                    &policy,
                ),
                Err(Ikev2ChildSaNegotiationError::InvalidKeyExchange)
            );
        }
        let selected = negotiate_child_sa(
            Some(&opc_proto_ikev2::Ikev2KeyExchangePayload {
                dh_group: 14,
                key_exchange_data: &[2; 256],
            }),
            &sa,
            &ts,
            &ts,
            &policy,
        )
        .expect("common stronger PFS suite");
        assert_eq!(
            selected
                .transforms
                .iter()
                .find(|t| t.transform_type == 4)
                .expect("DH")
                .transform_id,
            14
        );
        let legacy_wire =
            build_ike_auth_sa_payload(&child_sa_pfs_payload_build(1)).expect("legacy SA");
        let legacy = Ikev2SaPayload::decode_body(&legacy_wire).expect("legacy SA view");
        let selected_legacy = negotiate_child_sa(
            Some(&opc_proto_ikev2::Ikev2KeyExchangePayload {
                dh_group: 1,
                key_exchange_data: &[2; 96],
            }),
            &legacy,
            &ts,
            &ts,
            &policy,
        )
        .expect("legacy-only common group");
        assert_eq!(
            selected_legacy
                .transforms
                .iter()
                .find(|t| t.transform_type == 4)
                .expect("DH")
                .transform_id,
            1
        );
        assert_eq!(
            negotiate_child_sa(None, &sa, &ts, &ts, &policy),
            Err(Ikev2ChildSaNegotiationError::KeyExchangeRequired)
        );
    }
}
#[test]
fn outgoing_child_offer_puts_group_one_last() {
    for separate in [false, true] {
        let mut input = outgoing_child_request();
        input.security_association = child_group_offer(separate);
        input.key_exchange = Some(Ikev2KeyExchangePayloadBuild {
            dh_group: 1,
            key_exchange_data: vec![2; 96],
        });
        let built = build_create_child_sa_rekey_request_payloads(&input).expect("offer");
        let sa = Ikev2SaPayload::decode_body(&built.security_association.body).expect("SA view");
        let groups: Vec<_> = sa
            .proposals
            .iter()
            .flat_map(|p| &p.transforms)
            .filter(|t| t.transform_type == 4)
            .map(|t| t.transform_id)
            .collect();
        assert_eq!(groups, [14, 1]);
    }
}

#[test]
fn outgoing_child_offer_preserves_nonlegacy_and_no_pfs_proposal_order() {
    for groups in [[0, 14, 1], [19, 14, 1]] {
        let mut input = outgoing_child_request();
        input.security_association.proposals.clear();
        for (index, group) in groups.into_iter().enumerate() {
            let mut proposal = child_sa_pfs_payload_build(group).proposals.remove(0);
            proposal.proposal_number = (index + 1) as u8;
            if group == 0 {
                proposal.transforms.retain(|t| t.transform_type != 4);
            }
            input.security_association.proposals.push(proposal);
        }
        input.key_exchange = Some(Ikev2KeyExchangePayloadBuild {
            dh_group: 14,
            key_exchange_data: vec![2; 256],
        });
        let built = build_create_child_sa_rekey_request_payloads(&input).expect("ordered offer");
        let sa = Ikev2SaPayload::decode_body(&built.security_association.body).expect("SA view");
        let ordered_groups: Vec<_> = sa
            .proposals
            .iter()
            .map(|p| {
                p.transforms
                    .iter()
                    .find(|t| t.transform_type == 4)
                    .map_or(0, |t| t.transform_id)
            })
            .collect();
        assert_eq!(ordered_groups, groups);
    }
}

#[test]
fn outgoing_offer_rejects_invalid_proposal_numbers_before_normalization() {
    let mut input = Ikev2CreateChildSaRekeyRequestBuild {
        rekeyed_protocol_id: 3,
        rekeyed_spi: vec![1, 2, 3, 4],
        security_association: child_sa_payload_build(),
        nonce: Ikev2NoncePayloadBuild { nonce: vec![3; 32] },
        key_exchange: None,
        traffic_selectors_initiator: ts_payload(),
        traffic_selectors_responder: ts_payload(),
    };
    input.security_association.proposals[0].proposal_number = 0;
    assert_eq!(
        build_create_child_sa_rekey_request_payloads(&input),
        Err(Ikev2IkeAuthBuildError::SecurityAssociation(
            opc_proto_ikev2::Ikev2SaInitBuildError::InvalidProposalNumber
        ))
    );
}

#[test]
fn single_group_child_offer_preserves_other_transform_positions() {
    for (group, width) in [(1, 96), (14, 256)] {
        let mut security_association = child_sa_pfs_payload_build(group);
        security_association.proposals[0]
            .transforms
            .push(Ikev2SaTransformBuild {
                transform_type: 5,
                transform_id: 0,
                attributes: vec![],
            });
        let original_body = build_ike_auth_sa_payload(&security_association).expect("original SA");
        let input = Ikev2CreateChildSaRekeyRequestBuild {
            rekeyed_protocol_id: 3,
            rekeyed_spi: vec![1, 2, 3, 4],
            security_association,
            nonce: Ikev2NoncePayloadBuild { nonce: vec![3; 32] },
            key_exchange: Some(Ikev2KeyExchangePayloadBuild {
                dh_group: group,
                key_exchange_data: vec![2; width],
            }),
            traffic_selectors_initiator: ts_payload(),
            traffic_selectors_responder: ts_payload(),
        };
        let built =
            build_create_child_sa_rekey_request_payloads(&input).expect("single-group offer");
        assert_eq!(
            built.security_association.body, original_body,
            "group {group}"
        );
    }
}

fn generic_child_offer_for_groups(groups: &[u16], separate: bool) -> Ikev2SaPayloadBuild {
    let mut offer = child_sa_pfs_payload_build(groups[0]);
    for group in &groups[1..] {
        if separate {
            let mut proposal = child_sa_pfs_payload_build(*group).proposals.remove(0);
            proposal.proposal_number = u8::try_from(offer.proposals.len() + 1).unwrap();
            offer.proposals.push(proposal);
        } else {
            offer.proposals[0].transforms.push(Ikev2SaTransformBuild {
                transform_type: 4,
                transform_id: *group,
                attributes: vec![],
            });
        }
    }
    offer
}

fn generic_child_any_dh_policy(accepted: Vec<u16>) -> Ikev2ChildSaNegotiationPolicy {
    Ikev2ChildSaNegotiationPolicy {
        accepted_protocol_ids: vec![3],
        required_transforms: vec![
            Ikev2ChildSaTransformRequirement {
                transform_type: 1,
                accepted_transform_ids: vec![20],
            },
            Ikev2ChildSaTransformRequirement {
                transform_type: 4,
                accepted_transform_ids: accepted,
            },
        ],
        accepted_initiator_traffic_selectors: vec![],
        accepted_responder_traffic_selectors: vec![],
    }
}

#[test]
fn received_ke_selection_order_keeps_legacy_group_one_over_unimplemented_groups() {
    // RFC 7296 section 3.3.6: an unimplemented DH transform is unacceptable,
    // rather than a stronger executable alternative to the legacy group.
    let ts_wire = build_ike_auth_traffic_selector_payload(&ts_payload()).unwrap();
    let ts = opc_proto_ikev2::Ikev2TrafficSelectorPayload::decode_body(&ts_wire).unwrap();
    let mut ke_wire = vec![0, 1, 0, 0];
    ke_wire.extend_from_slice(&[2; 96]);
    let ke = opc_proto_ikev2::Ikev2KeyExchangePayload::decode_body(&ke_wire).unwrap();
    for separate in [false, true] {
        for unsupported in [5, 22, 31] {
            for groups in [vec![1, unsupported], vec![unsupported, 1]] {
                let wire =
                    build_ike_auth_sa_payload(&generic_child_offer_for_groups(&groups, separate))
                        .unwrap();
                let sa = Ikev2SaPayload::decode_body(&wire).unwrap();
                for accepted in [vec![], groups.clone()] {
                    let selected = negotiate_child_sa(
                        Some(&ke),
                        &sa,
                        &ts,
                        &ts,
                        &generic_child_any_dh_policy(accepted),
                    )
                    .expect("group 1 is the only implemented common DH group");
                    assert_eq!(
                        selected
                            .transforms
                            .iter()
                            .find(|t| t.transform_type == 4)
                            .unwrap()
                            .transform_id,
                        1
                    );
                }
            }
        }
    }
}

#[test]
fn received_ke_selection_order_retries_only_an_implemented_stronger_group() {
    let ts_wire = build_ike_auth_traffic_selector_payload(&ts_payload()).unwrap();
    let ts = opc_proto_ikev2::Ikev2TrafficSelectorPayload::decode_body(&ts_wire).unwrap();
    let mut ke_wire = vec![0, 1, 0, 0];
    ke_wire.extend_from_slice(&[2; 96]);
    let ke = opc_proto_ikev2::Ikev2KeyExchangePayload::decode_body(&ke_wire).unwrap();
    for separate in [false, true] {
        let groups = [1, 31, 5, 14];
        let wire =
            build_ike_auth_sa_payload(&generic_child_offer_for_groups(&groups, separate)).unwrap();
        let sa = Ikev2SaPayload::decode_body(&wire).unwrap();
        for accepted in [vec![], groups.to_vec()] {
            let retry = negotiate_child_sa(
                Some(&ke),
                &sa,
                &ts,
                &ts,
                &generic_child_any_dh_policy(accepted),
            )
            .unwrap_err();
            assert_eq!(
                retry,
                Ikev2ChildSaNegotiationError::KeyExchangeDhGroupMismatch {
                    received: 1,
                    preferred: 14
                }
            );
            assert_eq!(
                opc_proto_ikev2::build_ike_auth_notify_payload(&retry.invalid_ke_notify().unwrap())
                    .unwrap(),
                [0, 0, 0, 17, 0, 14]
            );
        }
    }
}
