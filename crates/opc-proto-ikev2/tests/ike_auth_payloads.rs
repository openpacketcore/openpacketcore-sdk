use opc_proto_ikev2::{
    build_child_sa_response_payloads, build_create_child_sa_rekey_request_payloads,
    build_create_child_sa_rekey_response_payloads, build_delete_payload_body,
    build_ike_auth_authentication_payload, build_ike_auth_cleartext_payload_chain,
    build_ike_auth_configuration_payload, build_ike_auth_delete_payload,
    build_ike_auth_identification_payload, build_ike_auth_sa_payload,
    build_ike_auth_traffic_selector_payload, compute_ike_auth_shared_key_mic,
    decode_ike_auth_cleartext_payloads, derive_ike_sa_init_key_material,
    ike_auth_shared_key_authentication_payload_body_len, negotiate_child_sa,
    verify_ike_auth_shared_key_mic, Ikev2AuthenticationPayloadBuild, Ikev2ChildSaNegotiationError,
    Ikev2ChildSaNegotiationPolicy, Ikev2ChildSaTransformRequirement,
    Ikev2ConfigurationAttributeBuild, Ikev2ConfigurationPayloadBuild,
    Ikev2CreateChildSaRekeyRequestBuild, Ikev2CreateChildSaRekeyResponseBuild, Ikev2DeletePayload,
    Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2IdentificationPayloadBuild,
    Ikev2IkeAuthBuildError, Ikev2IkeAuthPayloadBuild, Ikev2IkeAuthPayloadError, Ikev2IkeAuthPeer,
    Ikev2IkeAuthSignedOctets, Ikev2IkeAuthVerificationError, Ikev2KeyExchangePayloadBuild,
    Ikev2NoncePayloadBuild, Ikev2PrfAlgorithm, Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial,
    Ikev2SaPayload, Ikev2SaPayloadBuild, Ikev2SaProposal, Ikev2SaProposalBuild,
    Ikev2SaTransformBuild, Ikev2TrafficSelectorBuild, Ikev2TrafficSelectorPayloadBuild,
    PayloadChain, PayloadType, IKEV2_AUTH_METHOD_SHARED_KEY_MIC, IKEV2_IPSEC_SPI_SIZE,
    IKEV2_NOTIFY_REKEY_SA, IKEV2_SECURITY_PROTOCOL_ID_ESP, IKEV2_SECURITY_PROTOCOL_ID_IKE,
    IKEV2_TS_IPV4_ADDR_RANGE, IKEV2_TS_IPV6_ADDR_RANGE,
};

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
    start_port: u16,
    end_port: u16,
    start_address: &[u8],
    end_address: &[u8],
) -> Vec<u8> {
    let selector_len = 8 + start_address.len() + end_address.len();
    let selector_len = u16::try_from(selector_len).expect("traffic selector length fits u16");
    let mut body = vec![1, 0, 0, 0, ts_type, 0];
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
    Ikev2SaInitCryptoProfile::new(
        Ikev2PrfAlgorithm::HmacSha2_256,
        Ikev2DhGroup::Ecp256,
        Ikev2EncryptionAlgorithm::AesGcm16_128,
    )
}

fn key_material() -> Ikev2SaInitKeyMaterial {
    derive_ike_sa_init_key_material(
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
        Ikev2SaInitCryptoProfile::new(
            Ikev2PrfAlgorithm::HmacSha2_384,
            Ikev2DhGroup::Ecp384,
            Ikev2EncryptionAlgorithm::AesGcm16_256,
        ),
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
fn builds_create_child_sa_rekey_request_and_response_payloads() {
    let old_spi = [0xca, 0xfe, 0xba, 0xbe];
    let request =
        build_create_child_sa_rekey_request_payloads(&Ikev2CreateChildSaRekeyRequestBuild {
            rekeyed_protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
            rekeyed_spi: old_spi.to_vec(),
            security_association: child_sa_payload_build(),
            nonce: Ikev2NoncePayloadBuild {
                nonce: vec![0x11; 32],
            },
            key_exchange: Some(Ikev2KeyExchangePayloadBuild {
                dh_group: 19,
                key_exchange_data: vec![0x22; 65],
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
        decode_ts_error(ts_payload_body(42, 0, 1, &[10, 0, 0, 1], &[10, 0, 0, 2])),
        Ikev2IkeAuthPayloadError::TrafficSelectorTypeUnsupported
    );
    assert_eq!(
        decode_ts_error(ts_payload_body(
            IKEV2_TS_IPV6_ADDR_RANGE,
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
                end_port: 1,
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
