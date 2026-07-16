use bytes::BytesMut;
use opc_proto_ikev2::{
    build_create_child_sa_rekey_response_payloads, build_delete_payload_body,
    build_ike_auth_cleartext_payload_chain, build_ike_auth_notify_payload,
    dedicated_bearer::{
        build_ikev2_dedicated_bearer_create_child_sa_error_response,
        build_ikev2_dedicated_bearer_create_child_sa_request,
        build_ikev2_dedicated_bearer_create_child_sa_response,
        build_ikev2_dedicated_bearer_delete_request,
        build_ikev2_dedicated_bearer_informational_error_response,
        build_ikev2_dedicated_bearer_informational_success_response,
        build_ikev2_dedicated_bearer_modification_request, build_ikev2_dedicated_bearer_notify,
        decode_ikev2_dedicated_bearer_create_child_sa_request,
        decode_ikev2_dedicated_bearer_create_child_sa_response,
        decode_ikev2_dedicated_bearer_delete_request,
        decode_ikev2_dedicated_bearer_informational_response,
        decode_ikev2_dedicated_bearer_modification_request, decode_ikev2_dedicated_bearer_notify,
        validate_ikev2_dedicated_bearer_create_child_sa_response_correlation,
        validate_ikev2_dedicated_bearer_delete_response_correlation, Ikev2ApnAmbr,
        Ikev2ApnAmbrRateCodes, Ikev2DedicatedBearerCreateChildSaRequestBuild,
        Ikev2DedicatedBearerCreateChildSaResponse, Ikev2DedicatedBearerCreateChildSaResponseBuild,
        Ikev2DedicatedBearerError, Ikev2DedicatedBearerEspSpi, Ikev2DedicatedBearerExchangeError,
        Ikev2DedicatedBearerInformationalResponse, Ikev2DedicatedBearerModificationRequestBuild,
        Ikev2DedicatedBearerNotify, Ikev2DedicatedBearerProtocolError,
        Ikev2DedicatedBearerResponseError, Ikev2EpsQos, Ikev2EpsQosRateCodes, Ikev2ExtendedApnAmbr,
        Ikev2ExtendedBitRateUnit, Ikev2ExtendedEpsQos, IKEV2_NOTIFY_APN_AMBR, IKEV2_NOTIFY_EPS_QOS,
        IKEV2_NOTIFY_EXTENDED_APN_AMBR, IKEV2_NOTIFY_EXTENDED_EPS_QOS,
        IKEV2_NOTIFY_MODIFIED_BEARER, IKEV2_NOTIFY_MULTIPLE_BEARER_PDN_CONNECTIVITY,
        IKEV2_NOTIFY_SEMANTIC_ERRORS_IN_PACKET_FILTERS,
        IKEV2_NOTIFY_SEMANTIC_ERROR_IN_THE_TFT_OPERATION,
        IKEV2_NOTIFY_SYNTACTICAL_ERRORS_IN_PACKET_FILTERS,
        IKEV2_NOTIFY_SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION, IKEV2_NOTIFY_TFT,
    },
    derive_child_sa_key_material, Header, HeaderFlags, Ikev2ChildSaCryptoProfile,
    Ikev2CreateChildSaRekeyResponseBuild, Ikev2EncryptionAlgorithm, Ikev2IkeAuthPayloadBuild,
    Ikev2KeyExchangePayloadBuild, Ikev2NoncePayloadBuild, Ikev2NotifyPayload,
    Ikev2NotifyPayloadBuild, Ikev2PrfAlgorithm, Ikev2SaPayloadBuild, Ikev2SaProposalBuild,
    Ikev2SaTransformBuild, Ikev2TrafficSelectorBuild, Ikev2TrafficSelectorPayloadBuild,
    PayloadChain, PayloadType, EXCHANGE_TYPE_CREATE_CHILD_SA, EXCHANGE_TYPE_INFORMATIONAL,
    IKEV2_NOTIFY_REKEY_SA, IKEV2_SECURITY_PROTOCOL_ID_ESP, IKEV2_TS_IPV4_ADDR_RANGE,
};
use opc_proto_tft::{
    PacketFilter, PacketFilterComponent, PacketFilterDirection, PacketFilterIdentifier,
    TftOperation, TrafficFlowTemplate,
};
use quickcheck::quickcheck;

const TRANSFORM_TYPE_ENCR: u8 = 1;
const TRANSFORM_TYPE_INTEG: u8 = 3;
const TRANSFORM_TYPE_DH: u8 = 4;
const TRANSFORM_TYPE_ESN: u8 = 5;
const TRANSFORM_ID_NONE: u16 = 0;

fn must_ok<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

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

fn request_header(exchange_type: u8, message_id: u32) -> Header {
    Header::new(
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        PayloadType::Encrypted,
        exchange_type,
        HeaderFlags::from_bits(false, false, false),
        message_id,
    )
}

fn response_header(exchange_type: u8, message_id: u32) -> Header {
    Header::new(
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        PayloadType::Encrypted,
        exchange_type,
        HeaderFlags::from_bits(true, true, false),
        message_id,
    )
}

fn eps_qos() -> Ikev2EpsQos {
    must_ok(Ikev2EpsQos::new(1, None, None, None))
}

fn full_eps_qos() -> Ikev2EpsQos {
    must_ok(Ikev2EpsQos::new(
        1,
        Some(Ikev2EpsQosRateCodes {
            maximum_uplink: 0xfe,
            maximum_downlink: 0xfd,
            guaranteed_uplink: 0x80,
            guaranteed_downlink: 0x7f,
        }),
        Some(Ikev2EpsQosRateCodes {
            maximum_uplink: 0xfa,
            maximum_downlink: 0xb9,
            guaranteed_uplink: 0x4a,
            guaranteed_downlink: 1,
        }),
        Some(Ikev2EpsQosRateCodes {
            maximum_uplink: 0xf6,
            maximum_downlink: 0xa2,
            guaranteed_uplink: 0x3e,
            guaranteed_downlink: 1,
        }),
    ))
}

fn extended_eps_qos() -> Ikev2ExtendedEpsQos {
    Ikev2ExtendedEpsQos {
        maximum_unit: Ikev2ExtendedBitRateUnit::new(7),
        maximum_uplink: 11,
        maximum_downlink: 12,
        guaranteed_unit: Ikev2ExtendedBitRateUnit::new(8),
        guaranteed_uplink: 13,
        guaranteed_downlink: 14,
    }
}

fn apn_ambr() -> Ikev2ApnAmbr {
    must_ok(Ikev2ApnAmbr::new(
        Ikev2ApnAmbrRateCodes {
            downlink: 0xfe,
            uplink: 0xfd,
        },
        Some(Ikev2ApnAmbrRateCodes {
            downlink: 0xfa,
            uplink: 0xb9,
        }),
        Some(Ikev2ApnAmbrRateCodes {
            downlink: 0xfe,
            uplink: 1,
        }),
    ))
}

fn extended_apn_ambr() -> Ikev2ExtendedApnAmbr {
    Ikev2ExtendedApnAmbr {
        downlink_unit: Ikev2ExtendedBitRateUnit::new(7),
        downlink: 100,
        uplink_unit: Ikev2ExtendedBitRateUnit::new(8),
        uplink: 200,
    }
}

fn create_tft() -> TrafficFlowTemplate {
    let filter = must_ok(PacketFilter::new(
        must_ok(PacketFilterIdentifier::new(3)),
        PacketFilterDirection::Bidirectional,
        10,
        vec![
            PacketFilterComponent::ProtocolIdentifierNextHeader(17),
            PacketFilterComponent::SingleRemotePort(4_500),
        ],
    ));
    must_ok(TrafficFlowTemplate::create_new(vec![filter], vec![]))
}

fn replacement_tft() -> TrafficFlowTemplate {
    let filter = must_ok(PacketFilter::new(
        must_ok(PacketFilterIdentifier::new(3)),
        PacketFilterDirection::Bidirectional,
        10,
        vec![PacketFilterComponent::SingleRemotePort(5_000)],
    ));
    must_ok(TrafficFlowTemplate::replace_packet_filters(
        vec![filter],
        vec![],
    ))
}

fn transforms() -> Vec<Ikev2SaTransformBuild> {
    vec![
        Ikev2SaTransformBuild {
            transform_type: TRANSFORM_TYPE_ENCR,
            transform_id: 20,
            attributes: vec![],
        },
        Ikev2SaTransformBuild {
            transform_type: TRANSFORM_TYPE_ESN,
            transform_id: TRANSFORM_ID_NONE,
            attributes: vec![],
        },
    ]
}

fn sa(spi: [u8; 4]) -> Ikev2SaPayloadBuild {
    Ikev2SaPayloadBuild {
        proposals: vec![Ikev2SaProposalBuild {
            proposal_number: 1,
            protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
            spi: spi.to_vec(),
            transforms: transforms(),
        }],
    }
}

fn ts(
    start: [u8; 4],
    end: [u8; 4],
    start_port: u16,
    end_port: u16,
) -> Ikev2TrafficSelectorPayloadBuild {
    Ikev2TrafficSelectorPayloadBuild {
        selectors: vec![Ikev2TrafficSelectorBuild {
            ts_type: IKEV2_TS_IPV4_ADDR_RANGE,
            ip_protocol_id: 0,
            start_port,
            end_port,
            start_address: start.to_vec(),
            end_address: end.to_vec(),
        }],
    }
}

fn broad_ts() -> Ikev2TrafficSelectorPayloadBuild {
    ts([0, 0, 0, 0], [255, 255, 255, 255], 0, u16::MAX)
}

fn narrow_ts() -> Ikev2TrafficSelectorPayloadBuild {
    ts([10, 0, 0, 1], [10, 0, 0, 10], 4_500, 4_500)
}

fn create_request_build() -> Ikev2DedicatedBearerCreateChildSaRequestBuild {
    Ikev2DedicatedBearerCreateChildSaRequestBuild {
        security_association: sa([1, 2, 3, 4]),
        nonce: Ikev2NoncePayloadBuild {
            nonce: vec![0x11; 32],
        },
        key_exchange: None,
        traffic_selectors_initiator: broad_ts(),
        traffic_selectors_responder: broad_ts(),
        eps_qos: eps_qos(),
        extended_eps_qos: Some(extended_eps_qos()),
        tft: create_tft(),
        apn_ambr: None,
        extended_apn_ambr: None,
    }
}

fn create_response_build() -> Ikev2DedicatedBearerCreateChildSaResponseBuild {
    Ikev2DedicatedBearerCreateChildSaResponseBuild {
        security_association: sa([5, 6, 7, 8]),
        nonce: Ikev2NoncePayloadBuild {
            nonce: vec![0x22; 32],
        },
        key_exchange: None,
        traffic_selectors_initiator: narrow_ts(),
        traffic_selectors_responder: narrow_ts(),
    }
}

fn create_request_entries_with_sa(
    security_association: Ikev2SaPayloadBuild,
) -> Vec<Ikev2IkeAuthPayloadBuild> {
    let common = must_ok(build_create_child_sa_rekey_response_payloads(
        &Ikev2CreateChildSaRekeyResponseBuild {
            security_association,
            nonce: Ikev2NoncePayloadBuild {
                nonce: vec![0x11; 32],
            },
            key_exchange: None,
            traffic_selectors_initiator: broad_ts(),
            traffic_selectors_responder: broad_ts(),
        },
    ));
    let mut entries = common.into_payloads();
    entries.push(must_ok(build_ikev2_dedicated_bearer_notify(
        &Ikev2DedicatedBearerNotify::EpsQos(eps_qos()),
    )));
    entries.push(must_ok(build_ikev2_dedicated_bearer_notify(
        &Ikev2DedicatedBearerNotify::Tft(create_tft()),
    )));
    entries
}

fn create_request_entries() -> Vec<Ikev2IkeAuthPayloadBuild> {
    create_request_entries_with_sa(sa([1, 2, 3, 4]))
}

fn decode_notify_body(body: &[u8]) -> Ikev2DedicatedBearerNotify {
    let raw = must_ok(Ikev2NotifyPayload::decode_body(body));
    match must_ok(decode_ikev2_dedicated_bearer_notify(raw)) {
        Some(value) => value,
        None => panic!("known notify decoded as unknown"),
    }
}

#[test]
fn normative_notify_numbers_and_fixed_shapes_are_exact() {
    assert_eq!(IKEV2_NOTIFY_MULTIPLE_BEARER_PDN_CONNECTIVITY, 42_011);
    assert_eq!(IKEV2_NOTIFY_EPS_QOS, 42_014);
    assert_eq!(IKEV2_NOTIFY_EXTENDED_EPS_QOS, 42_015);
    assert_eq!(IKEV2_NOTIFY_TFT, 42_017);
    assert_eq!(IKEV2_NOTIFY_MODIFIED_BEARER, 42_020);
    assert_eq!(IKEV2_NOTIFY_APN_AMBR, 42_094);
    assert_eq!(IKEV2_NOTIFY_EXTENDED_APN_AMBR, 42_095);
    assert_eq!(IKEV2_NOTIFY_SEMANTIC_ERROR_IN_THE_TFT_OPERATION, 8_241);
    assert_eq!(IKEV2_NOTIFY_SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION, 8_242);
    assert_eq!(IKEV2_NOTIFY_SEMANTIC_ERRORS_IN_PACKET_FILTERS, 8_244);
    assert_eq!(IKEV2_NOTIFY_SYNTACTICAL_ERRORS_IN_PACKET_FILTERS, 8_245);

    let capability = must_ok(build_ikev2_dedicated_bearer_notify(
        &Ikev2DedicatedBearerNotify::MultipleBearerPdnConnectivity,
    ));
    assert_eq!(capability.body, [0x00, 0x00, 0xa4, 0x1b]);
    let error = must_ok(build_ikev2_dedicated_bearer_notify(
        &Ikev2DedicatedBearerNotify::ProtocolError(
            Ikev2DedicatedBearerProtocolError::SemanticErrorInTftOperation,
        ),
    ));
    assert_eq!(error.body, [0x00, 0x00, 0x20, 0x31]);
    let modified = must_ok(build_ikev2_dedicated_bearer_notify(
        &Ikev2DedicatedBearerNotify::ModifiedBearer(must_ok(Ikev2DedicatedBearerEspSpi::new(
            0x0102_0304,
        ))),
    ));
    assert_eq!(modified.body, [0x03, 0x04, 0xa4, 0x24, 1, 2, 3, 4]);
}

#[test]
fn all_typed_notifies_roundtrip_with_inner_lengths() {
    let values = vec![
        Ikev2DedicatedBearerNotify::MultipleBearerPdnConnectivity,
        Ikev2DedicatedBearerNotify::EpsQos(full_eps_qos()),
        Ikev2DedicatedBearerNotify::ExtendedEpsQos(extended_eps_qos()),
        Ikev2DedicatedBearerNotify::Tft(create_tft()),
        Ikev2DedicatedBearerNotify::ModifiedBearer(must_ok(Ikev2DedicatedBearerEspSpi::new(
            0x1020_3040,
        ))),
        Ikev2DedicatedBearerNotify::ApnAmbr(apn_ambr()),
        Ikev2DedicatedBearerNotify::ExtendedApnAmbr(extended_apn_ambr()),
        Ikev2DedicatedBearerNotify::ProtocolError(
            Ikev2DedicatedBearerProtocolError::SemanticErrorInTftOperation,
        ),
        Ikev2DedicatedBearerNotify::ProtocolError(
            Ikev2DedicatedBearerProtocolError::SyntacticalErrorInTftOperation,
        ),
        Ikev2DedicatedBearerNotify::ProtocolError(
            Ikev2DedicatedBearerProtocolError::SemanticErrorsInPacketFilters,
        ),
        Ikev2DedicatedBearerNotify::ProtocolError(
            Ikev2DedicatedBearerProtocolError::SyntacticalErrorsInPacketFilters,
        ),
    ];
    for value in values {
        let body = must_ok(build_ikev2_dedicated_bearer_notify(&value)).body;
        assert_eq!(decode_notify_body(&body), value);
    }
}

#[test]
fn tft_notify_embeds_identical_canonical_value_bytes() {
    let tft = create_tft();
    let mut expected = BytesMut::new();
    must_ok(tft.encode_value(&mut expected));
    let body = must_ok(build_ikev2_dedicated_bearer_notify(
        &Ikev2DedicatedBearerNotify::Tft(tft),
    ))
    .body;
    assert_eq!(usize::from(body[4]), expected.len());
    assert_eq!(&body[5..], expected.as_ref());
}

#[test]
fn typed_notify_rejects_wrong_shape_length_qci_and_zero_spi() {
    let wrong_protocol = [3, 0, 0xa4, 0x1e, 1, 9];
    assert!(matches!(
        decode_ikev2_dedicated_bearer_notify(must_ok(Ikev2NotifyPayload::decode_body(
            &wrong_protocol
        ))),
        Err(Ikev2DedicatedBearerError::InvalidNotifyProtocolId { .. })
    ));
    let wrong_inner_length = [0, 0, 0xa4, 0x1e, 2, 9];
    assert!(matches!(
        decode_ikev2_dedicated_bearer_notify(must_ok(Ikev2NotifyPayload::decode_body(
            &wrong_inner_length
        ))),
        Err(Ikev2DedicatedBearerError::InnerLengthMismatch { .. })
    ));
    let reserved_qci = [0, 0, 0xa4, 0x1e, 1, 0];
    assert!(matches!(
        decode_ikev2_dedicated_bearer_notify(must_ok(Ikev2NotifyPayload::decode_body(
            &reserved_qci
        ))),
        Err(Ikev2DedicatedBearerError::InvalidQci { value: 0 })
    ));
    let zero_spi = [3, 4, 0xa4, 0x24, 0, 0, 0, 0];
    assert!(matches!(
        decode_ikev2_dedicated_bearer_notify(must_ok(Ikev2NotifyPayload::decode_body(&zero_spi))),
        Err(Ikev2DedicatedBearerError::ZeroEspSpi)
    ));
}

#[test]
fn new_child_sa_build_decode_and_response_correlation_succeed() {
    let request_wire = must_ok(build_ikev2_dedicated_bearer_create_child_sa_request(
        &create_request_build(),
    ));
    let request_header = request_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7);
    let request = must_ok(decode_ikev2_dedicated_bearer_create_child_sa_request(
        &request_header,
        request_wire.first_payload(),
        request_wire.bytes(),
    ));
    assert_eq!(request.tft.operation(), TftOperation::CreateNew);
    assert!(request.extended_eps_qos.is_some());

    for raw in PayloadChain::new(request_wire.first_payload(), request_wire.bytes()).iter() {
        let raw = must_ok(raw);
        if raw.payload_type == PayloadType::Notify {
            let notify = must_ok(Ikev2NotifyPayload::decode(raw));
            assert_ne!(notify.notify_message_type, IKEV2_NOTIFY_REKEY_SA);
        }
    }

    let response_wire = must_ok(build_ikev2_dedicated_bearer_create_child_sa_response(
        &create_response_build(),
    ));
    let response_header_value = response_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7);
    let response = must_ok(decode_ikev2_dedicated_bearer_create_child_sa_response(
        &response_header_value,
        response_wire.first_payload(),
        response_wire.bytes(),
    ));
    must_ok(
        validate_ikev2_dedicated_bearer_create_child_sa_response_correlation(
            &request_header,
            &response_header_value,
            &request,
            &response,
        ),
    );
    let response_nonce = match &response {
        Ikev2DedicatedBearerCreateChildSaResponse::Success { nonce, .. } => nonce.nonce,
        Ikev2DedicatedBearerCreateChildSaResponse::Error(_) => {
            panic!("successful fixture decoded as error")
        }
    };
    let key_material = must_ok(derive_child_sa_key_material(
        Ikev2ChildSaCryptoProfile::new_aead(
            Ikev2PrfAlgorithm::HmacSha2_256,
            Ikev2EncryptionAlgorithm::AesGcm16_256,
        ),
        &[0x33; 32],
        request.nonce.nonce,
        response_nonce,
        None,
    ));
    assert_eq!(key_material.initiator_to_responder_encryption().len(), 36);
    assert_eq!(key_material.responder_to_initiator_encryption().len(), 36);
    assert_eq!(request_wire.clone().into_parts(), request_wire.into_parts());
}

#[test]
fn new_child_sa_with_pfs_build_decode_and_response_correlation_succeed() {
    const DH_GROUP: u16 = 19;

    let mut request_build = create_request_build();
    request_build.security_association.proposals[0]
        .transforms
        .push(Ikev2SaTransformBuild {
            transform_type: TRANSFORM_TYPE_DH,
            transform_id: DH_GROUP,
            attributes: vec![],
        });
    request_build.key_exchange = Some(Ikev2KeyExchangePayloadBuild {
        dh_group: DH_GROUP,
        key_exchange_data: vec![0x31; 64],
    });
    let request_wire = must_ok(build_ikev2_dedicated_bearer_create_child_sa_request(
        &request_build,
    ));
    let request_header = request_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 9);
    let request = must_ok(decode_ikev2_dedicated_bearer_create_child_sa_request(
        &request_header,
        request_wire.first_payload(),
        request_wire.bytes(),
    ));
    let request_key_exchange = match request.key_exchange {
        Some(value) => value,
        None => panic!("PFS request decoded without KE"),
    };
    assert_eq!(request_key_exchange.dh_group, DH_GROUP);
    assert_eq!(request_key_exchange.key_exchange_data, [0x31; 64]);

    let mut response_build = create_response_build();
    response_build.security_association.proposals[0]
        .transforms
        .push(Ikev2SaTransformBuild {
            transform_type: TRANSFORM_TYPE_DH,
            transform_id: DH_GROUP,
            attributes: vec![],
        });
    response_build.key_exchange = Some(Ikev2KeyExchangePayloadBuild {
        dh_group: DH_GROUP,
        key_exchange_data: vec![0x42; 64],
    });
    let response_wire = must_ok(build_ikev2_dedicated_bearer_create_child_sa_response(
        &response_build,
    ));
    let response_header = response_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 9);
    let response = must_ok(decode_ikev2_dedicated_bearer_create_child_sa_response(
        &response_header,
        response_wire.first_payload(),
        response_wire.bytes(),
    ));
    let response_key_exchange = match &response {
        Ikev2DedicatedBearerCreateChildSaResponse::Success {
            key_exchange: Some(value),
            ..
        } => value,
        Ikev2DedicatedBearerCreateChildSaResponse::Success {
            key_exchange: None, ..
        } => panic!("PFS response decoded without KE"),
        Ikev2DedicatedBearerCreateChildSaResponse::Error(_) => {
            panic!("PFS success fixture decoded as error")
        }
    };
    assert_eq!(response_key_exchange.dh_group, DH_GROUP);
    assert_eq!(response_key_exchange.key_exchange_data, [0x42; 64]);
    must_ok(
        validate_ikev2_dedicated_bearer_create_child_sa_response_correlation(
            &request_header,
            &response_header,
            &request,
            &response,
        ),
    );
}

#[test]
fn esp_proposals_missing_mandatory_transform_types_fail_closed() {
    let mut missing_encryption = create_request_build();
    missing_encryption.security_association.proposals[0]
        .transforms
        .retain(|transform| transform.transform_type != TRANSFORM_TYPE_ENCR);
    let missing_encryption_error =
        Ikev2DedicatedBearerExchangeError::MissingMandatoryEspTransform {
            transform_type: TRANSFORM_TYPE_ENCR,
        };
    assert_eq!(
        build_ikev2_dedicated_bearer_create_child_sa_request(&missing_encryption),
        Err(missing_encryption_error.clone())
    );
    let raw_request =
        create_request_entries_with_sa(missing_encryption.security_association.clone());
    let (first_payload, bytes) = must_ok(build_ike_auth_cleartext_payload_chain(&raw_request));
    assert_eq!(
        decode_ikev2_dedicated_bearer_create_child_sa_request(
            &request_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 10),
            first_payload,
            &bytes,
        ),
        Err(missing_encryption_error)
    );

    let mut missing_esn = create_response_build();
    missing_esn.security_association.proposals[0]
        .transforms
        .retain(|transform| transform.transform_type != TRANSFORM_TYPE_ESN);
    let missing_esn_error = Ikev2DedicatedBearerExchangeError::MissingMandatoryEspTransform {
        transform_type: TRANSFORM_TYPE_ESN,
    };
    assert_eq!(
        build_ikev2_dedicated_bearer_create_child_sa_response(&missing_esn),
        Err(missing_esn_error.clone())
    );
    let raw_response = must_ok(build_create_child_sa_rekey_response_payloads(
        &Ikev2CreateChildSaRekeyResponseBuild {
            security_association: missing_esn.security_association,
            nonce: missing_esn.nonce,
            key_exchange: missing_esn.key_exchange,
            traffic_selectors_initiator: missing_esn.traffic_selectors_initiator,
            traffic_selectors_responder: missing_esn.traffic_selectors_responder,
        },
    ))
    .into_payloads();
    let (first_payload, bytes) = must_ok(build_ike_auth_cleartext_payload_chain(&raw_response));
    assert_eq!(
        decode_ikev2_dedicated_bearer_create_child_sa_response(
            &response_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 10),
            first_payload,
            &bytes,
        ),
        Err(missing_esn_error)
    );
}

#[test]
fn response_selects_exactly_one_transform_from_every_offered_type() {
    let integrity = Ikev2SaTransformBuild {
        transform_type: TRANSFORM_TYPE_INTEG,
        transform_id: 2,
        attributes: vec![],
    };
    let mut request_build = create_request_build();
    request_build.security_association.proposals[0].transforms[0].transform_id = 3;
    request_build.security_association.proposals[0]
        .transforms
        .insert(1, integrity.clone());
    let request_wire = must_ok(build_ikev2_dedicated_bearer_create_child_sa_request(
        &request_build,
    ));
    let request_header = request_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 11);
    let request = must_ok(decode_ikev2_dedicated_bearer_create_child_sa_request(
        &request_header,
        request_wire.first_payload(),
        request_wire.bytes(),
    ));
    let response_header = response_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 11);

    let mut omitted = create_response_build();
    omitted.security_association.proposals[0].transforms[0].transform_id = 3;
    let omitted_wire = must_ok(build_ikev2_dedicated_bearer_create_child_sa_response(
        &omitted,
    ));
    let omitted = must_ok(decode_ikev2_dedicated_bearer_create_child_sa_response(
        &response_header,
        omitted_wire.first_payload(),
        omitted_wire.bytes(),
    ));
    assert_eq!(
        validate_ikev2_dedicated_bearer_create_child_sa_response_correlation(
            &request_header,
            &response_header,
            &request,
            &omitted,
        ),
        Err(
            Ikev2DedicatedBearerExchangeError::ResponseTransformTypeOmitted {
                transform_type: TRANSFORM_TYPE_INTEG,
            }
        )
    );

    let mut complete = create_response_build();
    complete.security_association.proposals[0].transforms[0].transform_id = 3;
    complete.security_association.proposals[0]
        .transforms
        .insert(1, integrity);
    let complete_wire = must_ok(build_ikev2_dedicated_bearer_create_child_sa_response(
        &complete,
    ));
    let complete = must_ok(decode_ikev2_dedicated_bearer_create_child_sa_response(
        &response_header,
        complete_wire.first_payload(),
        complete_wire.bytes(),
    ));
    must_ok(
        validate_ikev2_dedicated_bearer_create_child_sa_response_correlation(
            &request_header,
            &response_header,
            &request,
            &complete,
        ),
    );
}

#[test]
fn response_can_select_offered_dh_none_without_key_exchange() {
    const DH_GROUP: u16 = 19;

    let mut request_build = create_request_build();
    request_build.security_association.proposals[0]
        .transforms
        .extend([
            Ikev2SaTransformBuild {
                transform_type: TRANSFORM_TYPE_DH,
                transform_id: DH_GROUP,
                attributes: vec![],
            },
            Ikev2SaTransformBuild {
                transform_type: TRANSFORM_TYPE_DH,
                transform_id: TRANSFORM_ID_NONE,
                attributes: vec![],
            },
        ]);
    request_build.key_exchange = Some(Ikev2KeyExchangePayloadBuild {
        dh_group: DH_GROUP,
        key_exchange_data: vec![0x51; 64],
    });
    let request_wire = must_ok(build_ikev2_dedicated_bearer_create_child_sa_request(
        &request_build,
    ));
    let request_header = request_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 12);
    let request = must_ok(decode_ikev2_dedicated_bearer_create_child_sa_request(
        &request_header,
        request_wire.first_payload(),
        request_wire.bytes(),
    ));

    let mut response_build = create_response_build();
    response_build.security_association.proposals[0]
        .transforms
        .push(Ikev2SaTransformBuild {
            transform_type: TRANSFORM_TYPE_DH,
            transform_id: TRANSFORM_ID_NONE,
            attributes: vec![],
        });
    let response_wire = must_ok(build_ikev2_dedicated_bearer_create_child_sa_response(
        &response_build,
    ));
    let response_header = response_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 12);
    let response = must_ok(decode_ikev2_dedicated_bearer_create_child_sa_response(
        &response_header,
        response_wire.first_payload(),
        response_wire.bytes(),
    ));
    assert!(matches!(
        response,
        Ikev2DedicatedBearerCreateChildSaResponse::Success {
            key_exchange: None,
            ..
        }
    ));
    must_ok(
        validate_ikev2_dedicated_bearer_create_child_sa_response_correlation(
            &request_header,
            &response_header,
            &request,
            &response,
        ),
    );
}

#[test]
fn create_child_rejects_rekey_and_non_create_tft() {
    let common = must_ok(build_create_child_sa_rekey_response_payloads(
        &Ikev2CreateChildSaRekeyResponseBuild {
            security_association: sa([1, 2, 3, 4]),
            nonce: Ikev2NoncePayloadBuild {
                nonce: vec![0x11; 32],
            },
            key_exchange: None,
            traffic_selectors_initiator: broad_ts(),
            traffic_selectors_responder: broad_ts(),
        },
    ));
    let mut entries = common.into_payloads();
    entries.insert(
        0,
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Notify,
            body: must_ok(build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild {
                protocol_id: IKEV2_SECURITY_PROTOCOL_ID_ESP,
                spi: vec![1, 2, 3, 4],
                notify_message_type: IKEV2_NOTIFY_REKEY_SA,
                notification_data: vec![],
            })),
        },
    );
    entries.push(must_ok(build_ikev2_dedicated_bearer_notify(
        &Ikev2DedicatedBearerNotify::EpsQos(eps_qos()),
    )));
    entries.push(must_ok(build_ikev2_dedicated_bearer_notify(
        &Ikev2DedicatedBearerNotify::Tft(create_tft()),
    )));
    let (first, bytes) = must_ok(build_ike_auth_cleartext_payload_chain(&entries));
    assert_eq!(
        decode_ikev2_dedicated_bearer_create_child_sa_request(
            &request_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7),
            first,
            &bytes,
        ),
        Err(Ikev2DedicatedBearerExchangeError::RekeyNotifyProhibited)
    );

    let mut invalid = create_request_build();
    invalid.tft = replacement_tft();
    assert_eq!(
        build_ikev2_dedicated_bearer_create_child_sa_request(&invalid),
        Err(Ikev2DedicatedBearerExchangeError::CreateTftOperationRequired)
    );
}

#[test]
fn create_child_error_response_is_typed_and_cannot_mix_success() {
    let wire = must_ok(build_ikev2_dedicated_bearer_create_child_sa_error_response(
        Ikev2DedicatedBearerProtocolError::SyntacticalErrorsInPacketFilters,
    ));
    let response = must_ok(decode_ikev2_dedicated_bearer_create_child_sa_response(
        &response_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7),
        wire.first_payload(),
        wire.bytes(),
    ));
    assert!(matches!(
        response,
        Ikev2DedicatedBearerCreateChildSaResponse::Error(
            Ikev2DedicatedBearerResponseError::DedicatedBearer(
                Ikev2DedicatedBearerProtocolError::SyntacticalErrorsInPacketFilters
            )
        )
    ));

    let mut mixed_payloads = must_ok(build_create_child_sa_rekey_response_payloads(
        &Ikev2CreateChildSaRekeyResponseBuild {
            security_association: sa([5, 6, 7, 8]),
            nonce: Ikev2NoncePayloadBuild {
                nonce: vec![0x22; 32],
            },
            key_exchange: None,
            traffic_selectors_initiator: narrow_ts(),
            traffic_selectors_responder: narrow_ts(),
        },
    ))
    .into_payloads();
    mixed_payloads.push(must_ok(build_ikev2_dedicated_bearer_notify(
        &Ikev2DedicatedBearerNotify::ProtocolError(
            Ikev2DedicatedBearerProtocolError::SyntacticalErrorsInPacketFilters,
        ),
    )));
    let (first_payload, mixed_wire) =
        must_ok(build_ike_auth_cleartext_payload_chain(&mixed_payloads));
    assert_eq!(
        decode_ikev2_dedicated_bearer_create_child_sa_response(
            &response_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7),
            first_payload,
            &mixed_wire,
        ),
        Err(Ikev2DedicatedBearerExchangeError::ErrorResponseMixedWithPayloads)
    );
}

#[test]
fn response_correlation_rejects_expanded_selectors_and_wrong_message_id() {
    let mut request_build = create_request_build();
    request_build.traffic_selectors_initiator = narrow_ts();
    request_build.traffic_selectors_responder = narrow_ts();
    let request_wire = must_ok(build_ikev2_dedicated_bearer_create_child_sa_request(
        &request_build,
    ));
    let request_header = request_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7);
    let request = must_ok(decode_ikev2_dedicated_bearer_create_child_sa_request(
        &request_header,
        request_wire.first_payload(),
        request_wire.bytes(),
    ));

    let mut expanded = create_response_build();
    expanded.traffic_selectors_initiator = ts([0, 0, 0, 0], [255, 255, 255, 255], 0, u16::MAX);
    let response_wire = must_ok(build_ikev2_dedicated_bearer_create_child_sa_response(
        &expanded,
    ));
    let response_header_value = response_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7);
    let response = must_ok(decode_ikev2_dedicated_bearer_create_child_sa_response(
        &response_header_value,
        response_wire.first_payload(),
        response_wire.bytes(),
    ));
    assert_eq!(
        validate_ikev2_dedicated_bearer_create_child_sa_response_correlation(
            &request_header,
            &response_header_value,
            &request,
            &response,
        ),
        Err(Ikev2DedicatedBearerExchangeError::ResponseTrafficSelectorsExpanded)
    );

    let wrong_id = response_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 8);
    assert_eq!(
        validate_ikev2_dedicated_bearer_create_child_sa_response_correlation(
            &request_header,
            &wrong_id,
            &request,
            &response,
        ),
        Err(Ikev2DedicatedBearerExchangeError::ResponseCorrelationMismatch)
    );

    let mut same_sender = response_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7);
    same_sender.flags = HeaderFlags::from_bits(false, true, false);
    assert_eq!(
        validate_ikev2_dedicated_bearer_create_child_sa_response_correlation(
            &request_header,
            &same_sender,
            &request,
            &response,
        ),
        Err(Ikev2DedicatedBearerExchangeError::ResponseCorrelationMismatch)
    );
}

#[test]
fn request_cardinality_unknown_preservation_and_ke_rules_are_strict() {
    let mut duplicated = create_request_entries();
    duplicated.push(must_ok(build_ikev2_dedicated_bearer_notify(
        &Ikev2DedicatedBearerNotify::EpsQos(eps_qos()),
    )));
    let (first, bytes) = must_ok(build_ike_auth_cleartext_payload_chain(&duplicated));
    assert_eq!(
        decode_ikev2_dedicated_bearer_create_child_sa_request(
            &request_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7),
            first,
            &bytes,
        ),
        Err(Ikev2DedicatedBearerExchangeError::DuplicatePayload {
            role: opc_proto_ikev2::dedicated_bearer::Ikev2DedicatedBearerPayloadRole::EpsQos,
        })
    );

    let with_unknown = create_request_entries();
    let (first, encoded) = must_ok(build_ike_auth_cleartext_payload_chain(&with_unknown));
    let mut last_offset = None;
    for raw in PayloadChain::new(first, &encoded).iter() {
        last_offset = Some(must_ok(raw).offset);
    }
    let last_offset = match last_offset {
        Some(value) => value,
        None => panic!("request payload chain unexpectedly empty"),
    };
    let mut bytes = encoded.to_vec();
    bytes[last_offset] = 250;
    bytes.extend_from_slice(&[0, 0, 0, 8, 0xde, 0xad, 0xbe, 0xef]);
    let decoded = must_ok(decode_ikev2_dedicated_bearer_create_child_sa_request(
        &request_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7),
        first,
        &bytes,
    ));
    assert_eq!(decoded.unknown_noncritical_payloads.len(), 1);
    assert_eq!(decoded.unknown_noncritical_payloads[0].payload_type, 250);
    assert_eq!(
        decoded.unknown_noncritical_payloads[0].body,
        [0xde, 0xad, 0xbe, 0xef]
    );

    let mut missing_ke = create_request_build();
    missing_ke.security_association.proposals[0]
        .transforms
        .push(Ikev2SaTransformBuild {
            transform_type: TRANSFORM_TYPE_DH,
            transform_id: 19,
            attributes: vec![],
        });
    assert!(matches!(
        build_ikev2_dedicated_bearer_create_child_sa_request(&missing_ke),
        Err(Ikev2DedicatedBearerExchangeError::Build(_))
    ));
}

#[test]
fn response_correlation_rejects_unoffered_proposal_and_transform() {
    let request_wire = must_ok(build_ikev2_dedicated_bearer_create_child_sa_request(
        &create_request_build(),
    ));
    let request_header = request_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7);
    let request = must_ok(decode_ikev2_dedicated_bearer_create_child_sa_request(
        &request_header,
        request_wire.first_payload(),
        request_wire.bytes(),
    ));
    let response_header = response_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7);

    let mut wrong_proposal = create_response_build();
    wrong_proposal.security_association.proposals[0].proposal_number = 2;
    let wire = must_ok(build_ikev2_dedicated_bearer_create_child_sa_response(
        &wrong_proposal,
    ));
    let decoded = must_ok(decode_ikev2_dedicated_bearer_create_child_sa_response(
        &response_header,
        wire.first_payload(),
        wire.bytes(),
    ));
    assert_eq!(
        validate_ikev2_dedicated_bearer_create_child_sa_response_correlation(
            &request_header,
            &response_header,
            &request,
            &decoded,
        ),
        Err(Ikev2DedicatedBearerExchangeError::ResponseProposalNotOffered)
    );

    let mut wrong_transform = create_response_build();
    wrong_transform.security_association.proposals[0].transforms[0].transform_id = 21;
    let wire = must_ok(build_ikev2_dedicated_bearer_create_child_sa_response(
        &wrong_transform,
    ));
    let decoded = must_ok(decode_ikev2_dedicated_bearer_create_child_sa_response(
        &response_header,
        wire.first_payload(),
        wire.bytes(),
    ));
    assert_eq!(
        validate_ikev2_dedicated_bearer_create_child_sa_response_correlation(
            &request_header,
            &response_header,
            &request,
            &decoded,
        ),
        Err(Ikev2DedicatedBearerExchangeError::ResponseTransformNotOffered)
    );
}

#[test]
fn modification_roundtrip_and_dependencies_are_strict() {
    let input = Ikev2DedicatedBearerModificationRequestBuild {
        modified_bearer: must_ok(Ikev2DedicatedBearerEspSpi::new(0x1020_3040)),
        eps_qos: Some(eps_qos()),
        extended_eps_qos: Some(extended_eps_qos()),
        tft: Some(replacement_tft()),
        apn_ambr: Some(apn_ambr()),
        extended_apn_ambr: Some(extended_apn_ambr()),
    };
    let wire = must_ok(build_ikev2_dedicated_bearer_modification_request(&input));
    let decoded = must_ok(decode_ikev2_dedicated_bearer_modification_request(
        &request_header(EXCHANGE_TYPE_INFORMATIONAL, 8),
        wire.first_payload(),
        wire.bytes(),
    ));
    assert_eq!(decoded.modified_bearer.get(), 0x1020_3040);
    assert_eq!(
        decoded.tft.as_ref().map(TrafficFlowTemplate::operation),
        Some(TftOperation::ReplacePacketFilters)
    );

    let no_updates = Ikev2DedicatedBearerModificationRequestBuild {
        modified_bearer: input.modified_bearer,
        eps_qos: None,
        extended_eps_qos: None,
        tft: None,
        apn_ambr: None,
        extended_apn_ambr: None,
    };
    assert_eq!(
        build_ikev2_dedicated_bearer_modification_request(&no_updates),
        Err(Ikev2DedicatedBearerExchangeError::ModificationHasNoUpdates)
    );
    let orphan_extended = Ikev2DedicatedBearerModificationRequestBuild {
        extended_eps_qos: Some(extended_eps_qos()),
        tft: Some(replacement_tft()),
        ..no_updates
    };
    assert_eq!(
        build_ikev2_dedicated_bearer_modification_request(&orphan_extended),
        Err(Ikev2DedicatedBearerExchangeError::ExtendedEpsQosWithoutEpsQos)
    );
}

#[test]
fn deletion_and_informational_responses_are_correlated_and_typed() {
    let spi = must_ok(Ikev2DedicatedBearerEspSpi::new(0x1020_3040));
    let wire = must_ok(build_ikev2_dedicated_bearer_delete_request(spi));
    let request_header = request_header(EXCHANGE_TYPE_INFORMATIONAL, 9);
    let decoded = must_ok(decode_ikev2_dedicated_bearer_delete_request(
        &request_header,
        wire.first_payload(),
        wire.bytes(),
    ));
    assert_eq!(decoded.esp_spi, spi);

    let success = build_ikev2_dedicated_bearer_informational_success_response();
    let response_header = response_header(EXCHANGE_TYPE_INFORMATIONAL, 9);
    assert!(matches!(
        must_ok(decode_ikev2_dedicated_bearer_informational_response(
            &response_header,
            success.first_payload(),
            success.bytes(),
        )),
        Ikev2DedicatedBearerInformationalResponse::Success { .. }
    ));
    must_ok(validate_ikev2_dedicated_bearer_delete_response_correlation(
        &request_header,
        &response_header,
    ));

    let error = must_ok(build_ikev2_dedicated_bearer_informational_error_response(
        Ikev2DedicatedBearerProtocolError::SemanticErrorsInPacketFilters,
    ));
    assert!(matches!(
        must_ok(decode_ikev2_dedicated_bearer_informational_response(
            &response_header,
            error.first_payload(),
            error.bytes(),
        )),
        Ikev2DedicatedBearerInformationalResponse::Error(
            Ikev2DedicatedBearerResponseError::DedicatedBearer(
                Ikev2DedicatedBearerProtocolError::SemanticErrorsInPacketFilters
            )
        )
    ));
}

#[test]
fn deletion_rejects_multiple_spis_and_duplicate_delete_payloads() {
    let first_spi = [1, 2, 3, 4];
    let second_spi = [5, 6, 7, 8];
    let body = must_ok(build_delete_payload_body(
        IKEV2_SECURITY_PROTOCOL_ID_ESP,
        4,
        &[&first_spi, &second_spi],
    ));
    let entry = Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Delete,
        body,
    };
    let (first, bytes) = must_ok(build_ike_auth_cleartext_payload_chain(
        std::slice::from_ref(&entry),
    ));
    assert_eq!(
        decode_ikev2_dedicated_bearer_delete_request(
            &request_header(EXCHANGE_TYPE_INFORMATIONAL, 9),
            first,
            &bytes,
        ),
        Err(Ikev2DedicatedBearerExchangeError::DeleteSpiCount { actual: 2 })
    );
    let (first, bytes) = must_ok(build_ike_auth_cleartext_payload_chain(&[
        entry.clone(),
        entry,
    ]));
    assert_eq!(
        decode_ikev2_dedicated_bearer_delete_request(
            &request_header(EXCHANGE_TYPE_INFORMATIONAL, 9),
            first,
            &bytes,
        ),
        Err(Ikev2DedicatedBearerExchangeError::DuplicatePayload {
            role: opc_proto_ikev2::dedicated_bearer::Ikev2DedicatedBearerPayloadRole::Delete,
        })
    );
}

#[test]
fn redaction_safe_debug_omits_spi_and_unknown_bytes() {
    let spi = must_ok(Ikev2DedicatedBearerEspSpi::new(0xdead_beef));
    let debug = format!("{spi:?}");
    assert!(!debug.contains("dead"));
    assert!(!debug.contains("3735928559"));
    assert!(debug.contains("redacted"));
}

quickcheck! {
    fn eps_qos_value_roundtrips(
        qci_selector: u8,
        a: u8,
        b: u8,
        c: u8,
        d: u8
    ) -> bool {
        let qcis = [1u8, 5, 9, 65, 69, 79, 82, 128, 200, 254];
        let qci = qcis[usize::from(qci_selector) % qcis.len()];
        let value = match Ikev2EpsQos::new(
            qci,
            Some(Ikev2EpsQosRateCodes {
                maximum_uplink: a,
                maximum_downlink: b,
                guaranteed_uplink: c,
                guaranteed_downlink: d,
            }),
            None,
            None,
        ) {
            Ok(value) => value,
            Err(_) => return false,
        };
        Ikev2EpsQos::decode_value(&value.encode_value()) == Ok(value)
    }
}

#[test]
fn specification_authored_opened_payload_fixtures_are_byte_exact() {
    // RFC 7296 generic payload framing combined with TS 24.302 R17 7.2.7,
    // 7.4.6.3 and 8.2.9.10-8.2.9.12. The first octet is the SK Next Payload;
    // the remaining octets are the already-authenticated cleartext chain.
    const CREATE_REQUEST: &str = "21280000200000001c0103040201020304030000080100001400000008050000002c00002411111111111111111111111111111111111111111111111111111111111111112d00001801000000070000100000ffff00000000ffffffff2900001801000000070000100000ffff00000000ffffffff2900000a0000a41e0101290000130000a41f0a07000b000c08000d000e000000120000a4210921330a053011501194";
    const CREATE_RESPONSE: &str = "21280000200000001c0103040205060708030000080100001400000008050000002c00002422222222222222222222222222222222222222222222222222222222222222222d0000180100000007000010119411940a0000010a00000a000000180100000007000010119411940a0000010a00000a";
    const CREATE_ERROR: &str = "290000000800002035";
    const MODIFICATION: &str =
        "292900000c0304a424102030402900000a0000a41e0101000000100000a4210781330a03501388";
    const DELETION: &str = "2a0000000c0304000110203040";

    let create_request = decode_hex_fixture(CREATE_REQUEST);
    let encoded_request = must_ok(build_ikev2_dedicated_bearer_create_child_sa_request(
        &create_request_build(),
    ));
    assert_eq!(encoded_request.first_payload().as_u8(), create_request[0]);
    assert_eq!(encoded_request.bytes().as_ref(), &create_request[1..]);
    must_ok(decode_ikev2_dedicated_bearer_create_child_sa_request(
        &request_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7),
        PayloadType::from_u8(create_request[0]),
        &create_request[1..],
    ));

    let create_response = decode_hex_fixture(CREATE_RESPONSE);
    let encoded_response = must_ok(build_ikev2_dedicated_bearer_create_child_sa_response(
        &create_response_build(),
    ));
    assert_eq!(encoded_response.first_payload().as_u8(), create_response[0]);
    assert_eq!(encoded_response.bytes().as_ref(), &create_response[1..]);
    must_ok(decode_ikev2_dedicated_bearer_create_child_sa_response(
        &response_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 7),
        PayloadType::from_u8(create_response[0]),
        &create_response[1..],
    ));

    let create_error = decode_hex_fixture(CREATE_ERROR);
    let encoded_error = must_ok(build_ikev2_dedicated_bearer_create_child_sa_error_response(
        Ikev2DedicatedBearerProtocolError::SyntacticalErrorsInPacketFilters,
    ));
    assert_eq!(encoded_error.first_payload().as_u8(), create_error[0]);
    assert_eq!(encoded_error.bytes().as_ref(), &create_error[1..]);

    let modification = decode_hex_fixture(MODIFICATION);
    let encoded_modification = must_ok(build_ikev2_dedicated_bearer_modification_request(
        &Ikev2DedicatedBearerModificationRequestBuild {
            modified_bearer: must_ok(Ikev2DedicatedBearerEspSpi::new(0x1020_3040)),
            eps_qos: Some(eps_qos()),
            extended_eps_qos: None,
            tft: Some(replacement_tft()),
            apn_ambr: None,
            extended_apn_ambr: None,
        },
    ));
    assert_eq!(
        encoded_modification.first_payload().as_u8(),
        modification[0]
    );
    assert_eq!(encoded_modification.bytes().as_ref(), &modification[1..]);
    must_ok(decode_ikev2_dedicated_bearer_modification_request(
        &request_header(EXCHANGE_TYPE_INFORMATIONAL, 8),
        PayloadType::from_u8(modification[0]),
        &modification[1..],
    ));

    let deletion = decode_hex_fixture(DELETION);
    let encoded_deletion = must_ok(build_ikev2_dedicated_bearer_delete_request(must_ok(
        Ikev2DedicatedBearerEspSpi::new(0x1020_3040),
    )));
    assert_eq!(encoded_deletion.first_payload().as_u8(), deletion[0]);
    assert_eq!(encoded_deletion.bytes().as_ref(), &deletion[1..]);
    must_ok(decode_ikev2_dedicated_bearer_delete_request(
        &request_header(EXCHANGE_TYPE_INFORMATIONAL, 9),
        PayloadType::from_u8(deletion[0]),
        &deletion[1..],
    ));
}
