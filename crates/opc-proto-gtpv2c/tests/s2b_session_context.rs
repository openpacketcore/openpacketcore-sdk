use bytes::{Bytes, BytesMut};
use opc_proto_gtpv2c::{
    encode_typed_ie_sequence, s2b_create_session_request, s2b_delete_session_request,
    AccessPointName, AdditionalProtocolConfigurationOptions, BearerContext,
    ChargingCharacteristics, EpsBearerId, FullyQualifiedTeid, Ikev2ErrorNotifyTypeError,
    Indication, IpAddress, MessageType, OwnedMessage, PdnAddressAllocation, PlmnId, PortNumber,
    ProtocolConfigurationOptions, RanNasCause, RatType, RatTypeValue, RawIe, Recovery,
    S2bAaaProvidedMsisdn, S2bCreateSessionContext, S2bCreateSessionIdentity,
    S2bCreateSessionRequest, S2bDeleteSessionContext, S2bDeleteSessionRequest, S2bMessage,
    S2bSessionContextProjectionError, S2bUeEndpoint, S2bUeNatTraversal, SelectionMode,
    SelectionModeValue, ServingNetwork, SessionTraceDepth, TbcdDigits, TraceInformation,
    TwanIdentifier, TwanIdentifierTimestamp, TypedIe, TypedIeValue, IE_TYPE_APCO, IE_TYPE_APN,
    IE_TYPE_BEARER_CONTEXT, IE_TYPE_CHARGING_CHARACTERISTICS, IE_TYPE_EBI, IE_TYPE_F_TEID,
    IE_TYPE_IMSI, IE_TYPE_INDICATION, IE_TYPE_IP_ADDRESS, IE_TYPE_MEI, IE_TYPE_MSISDN, IE_TYPE_PAA,
    IE_TYPE_PCO, IE_TYPE_PDN_TYPE, IE_TYPE_PORT_NUMBER, IE_TYPE_RAN_NAS_CAUSE, IE_TYPE_RAT_TYPE,
    IE_TYPE_RECOVERY, IE_TYPE_SELECTION_MODE, IE_TYPE_SERVING_NETWORK, IE_TYPE_TRACE_INFORMATION,
    IE_TYPE_TWAN_IDENTIFIER, IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP, INTERFACE_TYPE_S2B_EPDG_GTP_C,
    MAX_IKEV2_ERROR_NOTIFY_TYPE,
};
use opc_protocol::{DecodeContext, DecodeErrorCode, Encode, EncodeContext, ValidationLevel};

fn procedure_context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    }
}

fn bearer_context() -> BearerContext<'static> {
    BearerContext {
        members: vec![TypedIe {
            instance: 0,
            value: TypedIeValue::EpsBearerId(EpsBearerId { value: 5 }),
        }],
    }
}

fn trace_information() -> TraceInformation {
    TraceInformation {
        plmn: PlmnId::new("001", "01"),
        trace_id: [0xa1, 0xa2, 0xa3],
        triggering_events: [0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9],
        network_element_types: [0xc1, 0xc2],
        session_trace_depth: SessionTraceDepth::Maximum,
        interfaces: [
            0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec,
        ],
        collection_entity: IpAddress::Ipv4([192, 0, 2, 200]),
    }
}

fn base_create_request(
    identity: S2bCreateSessionIdentity,
    paa: PdnAddressAllocation,
    context: S2bCreateSessionContext,
) -> S2bCreateSessionRequest<'static> {
    S2bCreateSessionRequest {
        sequence_number: 0x010203,
        identity,
        rat_type: RatType {
            value: RatTypeValue::Wlan,
        },
        serving_network: ServingNetwork {
            plmn: PlmnId::new("001", "01"),
        },
        sender_f_teid: FullyQualifiedTeid {
            interface_type: INTERFACE_TYPE_S2B_EPDG_GTP_C,
            teid: 0x1020_3040,
            ipv4: Some([192, 0, 2, 1]),
            ipv6: None,
        },
        apn: AccessPointName::new(vec!["ims".to_string()]),
        selection_mode: SelectionMode {
            value: SelectionModeValue::MsOrNetworkProvidedSubscriptionVerified,
        },
        paa,
        bearer_context: bearer_context(),
        context,
        additional_ies: Vec::new(),
    }
}

fn complete_create_context_request() -> S2bCreateSessionRequest<'static> {
    base_create_request(
        S2bCreateSessionIdentity::Subscriber {
            imsi: TbcdDigits::new("001010123456789"),
            mei: Some(TbcdDigits::new("356789012345670")),
            indication: Some(Indication {
                flags: vec![0x01, 0x00],
            }),
        },
        PdnAddressAllocation::static_ipv4([10, 0, 0, 9]).expect("valid static PAA"),
        S2bCreateSessionContext {
            msisdn: Some(S2bAaaProvidedMsisdn::new(TbcdDigits::new("15551234567"))),
            pco: Some(ProtocolConfigurationOptions { value: vec![0x80] }),
            apco: Some(AdditionalProtocolConfigurationOptions {
                value: vec![0x80, 0x00],
            }),
            recovery: Some(Recovery { restart_counter: 7 }),
            charging_characteristics: Some(ChargingCharacteristics::from_octets([0x11, 0x22])),
            trace_information: Some(trace_information()),
            wlan_location: Some(
                TwanIdentifier::new(b"test-wlan".to_vec()).expect("valid test SSID"),
            ),
            wlan_location_timestamp: Some(TwanIdentifierTimestamp::from_ntp_seconds(0x1020_3040)),
            ue_endpoint: Some(S2bUeEndpoint {
                local_ip: IpAddress::Ipv4([198, 51, 100, 20]),
                nat: S2bUeNatTraversal::Detected {
                    udp_port: Some(PortNumber::new(4500)),
                    tcp_port: Some(PortNumber::new(4501)),
                },
            }),
            epdg_ikev2_endpoint: Some(IpAddress::Ipv6([
                0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ])),
        },
    )
}

fn complete_delete_context_request() -> S2bDeleteSessionRequest<'static> {
    S2bDeleteSessionRequest {
        sequence_number: 0x010204,
        teid: 0x5566_7788,
        linked_ebi: EpsBearerId { value: 5 },
        context: S2bDeleteSessionContext {
            release_cause: Some(RanNasCause::diameter(1)),
            indication: Some(Indication {
                flags: vec![0x01, 0x00],
            }),
            pco: Some(ProtocolConfigurationOptions { value: vec![0x80] }),
            wlan_location: Some(
                TwanIdentifier::new(b"delete-wlan".to_vec()).expect("valid test SSID"),
            ),
            wlan_location_timestamp: Some(TwanIdentifierTimestamp::from_ntp_seconds(0x1020_3040)),
            ue_endpoint: S2bUeEndpoint {
                local_ip: IpAddress::Ipv4([198, 51, 100, 30]),
                nat: S2bUeNatTraversal::Detected {
                    udp_port: Some(PortNumber::new(4500)),
                    tcp_port: Some(PortNumber::new(4501)),
                },
            },
        },
        additional_ies: Vec::new(),
    }
}

fn decode_types(message: &OwnedMessage) -> Vec<(u8, u8)> {
    let mut wire = BytesMut::new();
    message
        .encode(&mut wire, EncodeContext::default())
        .expect("test profile message encodes");
    let (tail, decoded) =
        S2bMessage::decode(&wire, procedure_context()).expect("test profile message decodes");
    assert!(tail.is_empty());
    decoded
        .as_view()
        .expect("test message has a typed S2b view")
        .ies
        .iter()
        .map(|ie| (ie.ie_type(), ie.instance))
        .collect()
}

fn encode_owned(message: &OwnedMessage) -> Vec<u8> {
    let mut wire = BytesMut::new();
    message
        .encode(&mut wire, EncodeContext::default())
        .expect("test profile message encodes");
    wire.to_vec()
}

fn append_raw_tlivs(message: &OwnedMessage, keys: &[(u8, u8)]) -> Vec<u8> {
    let mut raw_ies = BytesMut::from(message.raw_ies.as_ref());
    for (ie_type, instance) in keys {
        raw_ies.extend_from_slice(&[*ie_type, 0, 0, *instance & 0x0f]);
    }
    encode_owned(&OwnedMessage {
        header: message.header.clone(),
        raw_ies: raw_ies.freeze(),
    })
}

fn decode_hex_seed(seed: &str) -> Vec<u8> {
    let hex = seed
        .trim()
        .strip_prefix("hex:")
        .expect("test fuzz seed has hex prefix");
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("test fuzz seed is ASCII");
            u8::from_str_radix(text, 16).expect("test fuzz seed is hexadecimal")
        })
        .collect()
}

#[test]
fn textual_fuzz_seeds_decode_through_context_projections() {
    for (seed, message_type) in [
        (
            include_str!("../fuzz/corpus/decode_s2b/spec__create_session_context.hexseed"),
            MessageType::CreateSessionRequest,
        ),
        (
            include_str!("../fuzz/corpus/decode_s2b/spec__delete_session_context.hexseed"),
            MessageType::DeleteSessionRequest,
        ),
    ] {
        let bytes = decode_hex_seed(seed);
        let (tail, decoded) = S2bMessage::decode(&bytes, procedure_context())
            .expect("session-context fuzz seed decodes ProcedureAware");
        assert!(tail.is_empty());
        let view = decoded.as_view().expect("session-context seed is typed");
        assert_eq!(view.message_type(), message_type);
        match message_type {
            MessageType::CreateSessionRequest => {
                view.create_session_context()
                    .expect("Create context seed projects");
            }
            MessageType::DeleteSessionRequest => {
                view.delete_session_context()
                    .expect("Delete context seed projects");
            }
            _ => unreachable!("test matrix contains only session-context requests"),
        }
    }
}

#[test]
fn session_context_ie_codecs_match_release_18_octets() {
    let charging = TypedIe {
        instance: 0,
        value: TypedIeValue::ChargingCharacteristics(ChargingCharacteristics::from_octets([
            0x12, 0x34,
        ])),
    };
    let trace = TypedIe {
        instance: 0,
        value: TypedIeValue::TraceInformation(trace_information()),
    };
    let diameter = TypedIe {
        instance: 0,
        value: TypedIeValue::RanNasCause(RanNasCause::diameter(1)),
    };
    let ikev2_cause = RanNasCause::ikev2(24).expect("test IKEv2 error type is valid");
    let ikev2 = TypedIe {
        instance: 0,
        value: TypedIeValue::RanNasCause(ikev2_cause),
    };

    let mut encoded = BytesMut::new();
    encode_typed_ie_sequence(
        &[charging, trace, diameter, ikev2],
        &mut encoded,
        EncodeContext::default(),
    )
    .expect("typed session-context IEs encode");

    assert_eq!(&encoded[..6], &[95, 0, 2, 0, 0x12, 0x34]);
    let diameter_offset = 6 + 4 + 34;
    assert_eq!(
        &encoded[6..diameter_offset],
        &[
            96, 0, 34, 0, 0x00, 0xf1, 0x10, 0xa1, 0xa2, 0xa3, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
            0xb7, 0xb8, 0xb9, 0xc1, 0xc2, 0x02, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8,
            0xe9, 0xea, 0xeb, 0xec, 192, 0, 2, 200,
        ]
    );
    assert_eq!(
        &encoded[diameter_offset..diameter_offset + 7],
        &[172, 0, 3, 0, 0x40, 0, 1]
    );
    assert_eq!(
        &encoded[diameter_offset + 7..diameter_offset + 14],
        &[172, 0, 3, 0, 0x50, 0, 24]
    );

    let decoded = TypedIe::decode_sequence(&encoded, DecodeContext::default())
        .expect("normative session-context IE octets decode");
    // The generic sequence decoder applies its configured singleton duplicate
    // policy, so the later same-key IKEv2 fixture replaces Diameter here.
    assert_eq!(decoded.len(), 3);
    assert_eq!(decoded[2].value, TypedIeValue::RanNasCause(ikev2_cause));
    let diameter_decoded = TypedIe::decode_sequence(
        &encoded[diameter_offset..diameter_offset + 7],
        DecodeContext::default(),
    )
    .expect("Diameter release cause decodes independently");
    assert!(matches!(
        diameter_decoded[0].value,
        TypedIeValue::RanNasCause(RanNasCause::Diameter(1))
    ));

    let mut ipv6_trace = trace_information();
    ipv6_trace.collection_entity =
        IpAddress::Ipv6([0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
    let mut ipv6_encoded = BytesMut::new();
    TypedIe {
        instance: 0,
        value: TypedIeValue::TraceInformation(ipv6_trace),
    }
    .encode(&mut ipv6_encoded, EncodeContext::default())
    .expect("IPv6 Trace Information encodes");
    assert_eq!(ipv6_encoded.len(), 4 + 46);
    TypedIe::decode_sequence(&ipv6_encoded, DecodeContext::default())
        .expect("IPv6 Trace Information decodes");
}

#[test]
fn ikev2_release_cause_accepts_only_notify_error_types() {
    let largest_error = RanNasCause::ikev2(MAX_IKEV2_ERROR_NOTIFY_TYPE)
        .expect("16383 is the largest IKEv2 Notify error type");
    assert_eq!(largest_error.value(), MAX_IKEV2_ERROR_NOTIFY_TYPE);
    assert_eq!(
        RanNasCause::ikev2(MAX_IKEV2_ERROR_NOTIFY_TYPE + 1),
        Err(Ikev2ErrorNotifyTypeError::NotErrorType)
    );
    assert_eq!(
        RanNasCause::ikev2(u16::MAX),
        Err(Ikev2ErrorNotifyTypeError::NotErrorType)
    );

    let decoded =
        TypedIe::decode_sequence(&[172, 0, 3, 0, 0x50, 0x3f, 0xff], DecodeContext::default())
            .expect("largest IKEv2 Notify error type decodes");
    assert_eq!(decoded[0].value, TypedIeValue::RanNasCause(largest_error));

    let error =
        TypedIe::decode_sequence(&[172, 0, 3, 0, 0x50, 0x40, 0x00], DecodeContext::default())
            .expect_err("IKEv2 Notify status type must fail closed");
    assert!(matches!(error.code(), DecodeErrorCode::Structural { .. }));
    let error_debug = format!("{error:?}");
    assert!(!error_debug.contains("16384"));
}

#[test]
fn extendable_session_context_ies_accept_suffixes_and_canonicalize_known_prefixes() {
    let charging_extension = [95, 0, 4, 0, 0x12, 0x34, 0xaa, 0xbb];
    let decoded = TypedIe::decode_sequence(&charging_extension, DecodeContext::default())
        .expect("Charging Characteristics extension suffix is receiver-ignored");
    assert!(matches!(
        decoded[0].value,
        TypedIeValue::ChargingCharacteristics(value) if value.octets() == [0x12, 0x34]
    ));
    let mut canonical = BytesMut::new();
    decoded[0]
        .encode(&mut canonical, EncodeContext::default())
        .expect("known Charging Characteristics prefix canonicalizes");
    assert_eq!(&canonical[..], &[95, 0, 2, 0, 0x12, 0x34]);

    // Cause Type (the low nibble) and later-release suffix octets are ignored
    // for Diameter/IKEv2 causes by TS 29.274 clause 8.103.
    let diameter_extension = [172, 0, 5, 0, 0x4f, 0x12, 0x34, 0xcc, 0xdd];
    let decoded = TypedIe::decode_sequence(&diameter_extension, DecodeContext::default())
        .expect("Diameter RAN/NAS Cause extension suffix is receiver-ignored");
    assert!(matches!(
        decoded[0].value,
        TypedIeValue::RanNasCause(RanNasCause::Diameter(0x1234))
    ));
    canonical.clear();
    decoded[0]
        .encode(&mut canonical, EncodeContext::default())
        .expect("known Diameter cause prefix canonicalizes");
    assert_eq!(&canonical[..], &[172, 0, 3, 0, 0x40, 0x12, 0x34]);
}

#[test]
fn session_context_ie_codecs_reject_bad_lengths_and_non_s2b_cause_family() {
    for (malformed, expected_code) in [
        (&[95, 0, 1, 0, 0x12][..], DecodeErrorCode::Truncated),
        (&[172, 0, 2, 0, 0x40, 0][..], DecodeErrorCode::Truncated),
        (
            &[172, 0, 3, 0, 0x10, 0, 1][..],
            DecodeErrorCode::InvalidEnumValue {
                field: "s2b_ran_nas_cause_protocol_type",
                value: 1,
            },
        ),
    ] {
        let error = TypedIe::decode_sequence(malformed, DecodeContext::default())
            .expect_err("malformed session-context IE must be rejected");
        assert_eq!(error.code(), &expected_code);
    }

    for invalid_len in [33usize, 35, 45, 47] {
        let mut malformed_trace = vec![96, 0, invalid_len as u8, 0];
        malformed_trace.extend(vec![0u8; invalid_len]);
        let error = TypedIe::decode_sequence(&malformed_trace, DecodeContext::default())
            .expect_err("Trace Information must contain exactly an IPv4 or IPv6 endpoint");
        assert!(matches!(
            error.code(),
            DecodeErrorCode::InvalidLength { .. }
        ));
    }

    let mut invalid_depth = vec![96, 0, 34, 0];
    let mut invalid_depth_value = [0u8; 34];
    invalid_depth_value[0..3].copy_from_slice(&[0x00, 0xf1, 0x10]);
    invalid_depth_value[17] = 6;
    invalid_depth.extend(invalid_depth_value);
    assert!(TypedIe::decode_sequence(&invalid_depth, DecodeContext::default()).is_err());
}

#[test]
fn create_context_encodes_exact_s2b_instances_order_and_projects() {
    let message = s2b_create_session_request(complete_create_context_request())
        .expect("complete Create Session context builds");

    assert_eq!(
        decode_types(&message),
        vec![
            (IE_TYPE_IMSI, 0),
            (IE_TYPE_MSISDN, 0),
            (IE_TYPE_MEI, 0),
            (IE_TYPE_SERVING_NETWORK, 0),
            (IE_TYPE_RAT_TYPE, 0),
            (IE_TYPE_INDICATION, 0),
            (IE_TYPE_F_TEID, 0),
            (IE_TYPE_APN, 0),
            (IE_TYPE_SELECTION_MODE, 0),
            (IE_TYPE_PAA, 0),
            (IE_TYPE_PCO, 0),
            (IE_TYPE_BEARER_CONTEXT, 0),
            (IE_TYPE_TRACE_INFORMATION, 0),
            (IE_TYPE_RECOVERY, 0),
            (IE_TYPE_CHARGING_CHARACTERISTICS, 0),
            (IE_TYPE_IP_ADDRESS, 0),
            (IE_TYPE_PORT_NUMBER, 0),
            (IE_TYPE_IP_ADDRESS, 3),
            (IE_TYPE_TWAN_IDENTIFIER, 1),
            (IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP, 0),
            (IE_TYPE_APCO, 0),
            (IE_TYPE_PORT_NUMBER, 2),
        ]
    );

    let mut wire = BytesMut::new();
    message
        .encode(&mut wire, EncodeContext::default())
        .expect("complete Create Session encodes");
    let (_, decoded) =
        S2bMessage::decode(&wire, procedure_context()).expect("complete Create Session decodes");
    let summary = decoded
        .as_view()
        .expect("typed Create Session view")
        .create_session_context()
        .expect("typed Create Session context projects");
    assert!(summary.msisdn.is_some());
    assert!(summary.trace_information.is_some());
    assert!(summary.wlan_location.is_some());
    assert!(summary.epdg_ikev2_endpoint.is_some());
    assert!(matches!(
        summary.ue_endpoint.expect("UE endpoint present").nat,
        S2bUeNatTraversal::Detected {
            udp_port: Some(_),
            tcp_port: Some(_)
        }
    ));
}

#[test]
fn create_context_covers_dynamic_static_roaming_nat_and_emergency_forms() {
    let rows = vec![
        (
            "normal dynamic with AAA context",
            S2bCreateSessionIdentity::Subscriber {
                imsi: TbcdDigits::new("001010123456789"),
                mei: Some(TbcdDigits::new("356789012345670")),
                indication: Some(Indication {
                    flags: vec![0x01, 0x00],
                }),
            },
            PdnAddressAllocation::dynamic_ipv4(),
            S2bCreateSessionContext {
                msisdn: Some(S2bAaaProvidedMsisdn::new(TbcdDigits::new("15551234567"))),
                pco: Some(ProtocolConfigurationOptions { value: vec![0x80] }),
                apco: Some(AdditionalProtocolConfigurationOptions {
                    value: vec![0x80, 0x00],
                }),
                recovery: Some(Recovery { restart_counter: 7 }),
                charging_characteristics: Some(ChargingCharacteristics::from_octets([0x11, 0x22])),
                trace_information: Some(trace_information()),
                wlan_location: Some(
                    TwanIdentifier::new(b"normal-wlan".to_vec()).expect("valid test SSID"),
                ),
                wlan_location_timestamp: Some(TwanIdentifierTimestamp::from_ntp_seconds(
                    0x1020_3040,
                )),
                ue_endpoint: Some(S2bUeEndpoint::without_nat(IpAddress::Ipv4([
                    198, 51, 100, 20,
                ]))),
                epdg_ikev2_endpoint: Some(IpAddress::Ipv4([192, 0, 2, 10])),
            },
            vec![
                (IE_TYPE_IMSI, 0),
                (IE_TYPE_MSISDN, 0),
                (IE_TYPE_MEI, 0),
                (IE_TYPE_SERVING_NETWORK, 0),
                (IE_TYPE_RAT_TYPE, 0),
                (IE_TYPE_INDICATION, 0),
                (IE_TYPE_F_TEID, 0),
                (IE_TYPE_APN, 0),
                (IE_TYPE_SELECTION_MODE, 0),
                (IE_TYPE_PAA, 0),
                (IE_TYPE_PCO, 0),
                (IE_TYPE_BEARER_CONTEXT, 0),
                (IE_TYPE_TRACE_INFORMATION, 0),
                (IE_TYPE_RECOVERY, 0),
                (IE_TYPE_CHARGING_CHARACTERISTICS, 0),
                (IE_TYPE_IP_ADDRESS, 0),
                (IE_TYPE_IP_ADDRESS, 3),
                (IE_TYPE_TWAN_IDENTIFIER, 1),
                (IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP, 0),
                (IE_TYPE_APCO, 0),
            ],
        ),
        (
            "roaming static with UDP NAT",
            S2bCreateSessionIdentity::subscriber(TbcdDigits::new("001010987654321")),
            PdnAddressAllocation::static_ipv6(
                64,
                [0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7],
            )
            .expect("valid static IPv6 PAA"),
            S2bCreateSessionContext {
                ue_endpoint: Some(S2bUeEndpoint::with_udp_nat(
                    IpAddress::Ipv4([198, 51, 100, 21]),
                    PortNumber::new(4500),
                )),
                ..S2bCreateSessionContext::default()
            },
            vec![
                (IE_TYPE_IMSI, 0),
                (IE_TYPE_SERVING_NETWORK, 0),
                (IE_TYPE_RAT_TYPE, 0),
                (IE_TYPE_F_TEID, 0),
                (IE_TYPE_APN, 0),
                (IE_TYPE_SELECTION_MODE, 0),
                (IE_TYPE_PAA, 0),
                (IE_TYPE_BEARER_CONTEXT, 0),
                (IE_TYPE_IP_ADDRESS, 0),
                (IE_TYPE_PORT_NUMBER, 0),
            ],
        ),
        (
            "UICC-less emergency NAT TCP",
            S2bCreateSessionIdentity::UiccLessEmergency {
                mei: TbcdDigits::new("356789012345670"),
                indication: Indication {
                    flags: vec![0, 0x40],
                },
            },
            PdnAddressAllocation::dynamic_ipv4(),
            S2bCreateSessionContext {
                ue_endpoint: Some(S2bUeEndpoint::with_tcp_nat(
                    IpAddress::Ipv4([198, 51, 100, 22]),
                    PortNumber::new(4501),
                )),
                ..S2bCreateSessionContext::default()
            },
            vec![
                (IE_TYPE_MEI, 0),
                (IE_TYPE_SERVING_NETWORK, 0),
                (IE_TYPE_RAT_TYPE, 0),
                (IE_TYPE_INDICATION, 0),
                (IE_TYPE_F_TEID, 0),
                (IE_TYPE_APN, 0),
                (IE_TYPE_SELECTION_MODE, 0),
                (IE_TYPE_PAA, 0),
                (IE_TYPE_BEARER_CONTEXT, 0),
                (IE_TYPE_IP_ADDRESS, 0),
                (IE_TYPE_PORT_NUMBER, 2),
            ],
        ),
    ];

    for (name, identity, paa, context, expected_keys) in rows {
        let mut request = base_create_request(identity, paa, context);
        if name.starts_with("roaming") {
            request.serving_network = ServingNetwork {
                plmn: PlmnId::new("302", "720"),
            };
        }
        let message = s2b_create_session_request(request)
            .unwrap_or_else(|error| panic!("{name} must build: {error}"));
        assert_eq!(decode_types(&message), expected_keys, "{name}");

        let wire = encode_owned(&message);
        let (tail, decoded) = S2bMessage::decode(&wire, procedure_context())
            .unwrap_or_else(|error| panic!("{name} must decode: {error}"));
        assert!(tail.is_empty(), "{name}");
        let summary = decoded
            .as_view()
            .expect("typed Create Session view")
            .create_session_context()
            .unwrap_or_else(|error| panic!("{name} must project: {error}"));
        if name == "normal dynamic with AAA context" {
            assert!(summary.msisdn.is_some());
            assert!(summary.trace_information.is_some());
            assert!(summary.wlan_location.is_some());
            assert!(summary.epdg_ikev2_endpoint.is_some());
            assert!(matches!(
                summary.ue_endpoint.expect("normal endpoint present").nat,
                S2bUeNatTraversal::NotDetected
            ));
        }
        if name == "roaming static with UDP NAT" {
            assert!(summary.msisdn.is_none());
            assert!(summary.wlan_location.is_none());
            assert!(matches!(
                summary.ue_endpoint.expect("roaming endpoint present").nat,
                S2bUeNatTraversal::Detected {
                    udp_port: Some(_),
                    tcp_port: None
                }
            ));
        }
        if name == "UICC-less emergency NAT TCP" {
            assert!(summary.msisdn.is_none());
            assert!(matches!(
                summary.ue_endpoint.expect("emergency endpoint present").nat,
                S2bUeNatTraversal::Detected {
                    udp_port: None,
                    tcp_port: Some(_)
                }
            ));
        }
    }

    let missing_ip = base_create_request(
        S2bCreateSessionIdentity::UiccLessEmergency {
            mei: TbcdDigits::new("356789012345670"),
            indication: Indication {
                flags: vec![0, 0x40],
            },
        },
        PdnAddressAllocation::dynamic_ipv4(),
        S2bCreateSessionContext::default(),
    );
    assert!(s2b_create_session_request(missing_ip).is_err());

    let missing_uimsi = base_create_request(
        S2bCreateSessionIdentity::UiccLessEmergency {
            mei: TbcdDigits::new("356789012345670"),
            indication: Indication { flags: vec![0, 0] },
        },
        PdnAddressAllocation::dynamic_ipv4(),
        S2bCreateSessionContext {
            ue_endpoint: Some(S2bUeEndpoint::without_nat(IpAddress::Ipv4([
                198, 51, 100, 24,
            ]))),
            ..S2bCreateSessionContext::default()
        },
    );
    assert!(s2b_create_session_request(missing_uimsi).is_err());
}

#[test]
fn delete_context_encodes_diameter_ikev2_nat_and_location_instances() {
    let location = TwanIdentifier::new(b"delete-wlan".to_vec()).expect("valid test SSID");
    // The trigger classification is a product-owned fact. It is deliberately
    // named in this matrix but does not create an extra wire field.
    let rows = vec![
        (
            "UE/ePDG detach",
            S2bDeleteSessionContext {
                release_cause: Some(
                    RanNasCause::ikev2(24).expect("test IKEv2 error type is valid"),
                ),
                indication: Some(Indication {
                    flags: vec![0x01, 0x00],
                }),
                pco: Some(ProtocolConfigurationOptions { value: vec![0x80] }),
                wlan_location: Some(location.clone()),
                wlan_location_timestamp: Some(TwanIdentifierTimestamp::from_ntp_seconds(
                    0x1020_3040,
                )),
                ue_endpoint: S2bUeEndpoint::with_udp_nat(
                    IpAddress::Ipv4([198, 51, 100, 30]),
                    PortNumber::new(4500),
                ),
            },
            vec![
                (IE_TYPE_EBI, 0),
                (IE_TYPE_INDICATION, 0),
                (IE_TYPE_PCO, 0),
                (IE_TYPE_RAN_NAS_CAUSE, 0),
                (IE_TYPE_TWAN_IDENTIFIER, 1),
                (IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP, 1),
                (IE_TYPE_IP_ADDRESS, 0),
                (IE_TYPE_PORT_NUMBER, 0),
            ],
        ),
        (
            "HSS/AAA detach",
            S2bDeleteSessionContext {
                release_cause: Some(RanNasCause::diameter(1)),
                indication: None,
                pco: None,
                wlan_location: None,
                wlan_location_timestamp: None,
                ue_endpoint: S2bUeEndpoint::with_tcp_nat(
                    IpAddress::Ipv4([198, 51, 100, 31]),
                    PortNumber::new(4501),
                ),
            },
            vec![
                (IE_TYPE_EBI, 0),
                (IE_TYPE_RAN_NAS_CAUSE, 0),
                (IE_TYPE_IP_ADDRESS, 0),
                (IE_TYPE_PORT_NUMBER, 1),
            ],
        ),
        (
            "PDN disconnection",
            S2bDeleteSessionContext {
                release_cause: None,
                indication: None,
                pco: None,
                wlan_location: None,
                wlan_location_timestamp: None,
                ue_endpoint: S2bUeEndpoint::without_nat(IpAddress::Ipv6([
                    0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                ])),
            },
            vec![(IE_TYPE_EBI, 0), (IE_TYPE_IP_ADDRESS, 0)],
        ),
    ];

    for (trigger, context, expected_keys) in rows {
        let expected_cause = context.release_cause;
        let message = s2b_delete_session_request(S2bDeleteSessionRequest {
            sequence_number: 0x010204,
            teid: 0x5566_7788,
            linked_ebi: EpsBearerId { value: 5 },
            context,
            additional_ies: Vec::new(),
        })
        .expect("Delete Session context builds");
        assert_eq!(decode_types(&message), expected_keys, "{trigger}");

        let wire = encode_owned(&message);
        let (tail, decoded) = S2bMessage::decode(&wire, procedure_context())
            .unwrap_or_else(|error| panic!("{trigger} must decode: {error}"));
        assert!(tail.is_empty(), "{trigger}");
        let summary = decoded
            .as_view()
            .expect("typed Delete Session view")
            .delete_session_context()
            .expect("Delete Session context projects");
        assert_eq!(summary.release_cause, expected_cause, "{trigger}");
    }
}

#[test]
fn builders_reject_profile_owned_escape_hatches_and_invalid_nat_state() {
    for (ie_type, instance) in [
        (IE_TYPE_IMSI, 9),
        (IE_TYPE_MSISDN, 0),
        (IE_TYPE_MEI, 0),
        (IE_TYPE_INDICATION, 0),
        (IE_TYPE_PCO, 0),
        (IE_TYPE_APCO, 0),
        (IE_TYPE_RECOVERY, 0),
        (IE_TYPE_IP_ADDRESS, 3),
        (IE_TYPE_PORT_NUMBER, 2),
        (IE_TYPE_CHARGING_CHARACTERISTICS, 0),
        (IE_TYPE_CHARGING_CHARACTERISTICS, 1),
        (IE_TYPE_TRACE_INFORMATION, 0),
        (IE_TYPE_TRACE_INFORMATION, 1),
        (IE_TYPE_TWAN_IDENTIFIER, 1),
        (IE_TYPE_TWAN_IDENTIFIER, 0),
        (IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP, 0),
        (IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP, 1),
        (IE_TYPE_IP_ADDRESS, 1),
        (IE_TYPE_PORT_NUMBER, 1),
        (IE_TYPE_PDN_TYPE, 0),
        (IE_TYPE_RAN_NAS_CAUSE, 0),
    ] {
        let mut create = base_create_request(
            S2bCreateSessionIdentity::subscriber(TbcdDigits::new("001010123456789")),
            PdnAddressAllocation::dynamic_ipv4(),
            S2bCreateSessionContext::default(),
        );
        create.additional_ies.push(TypedIe {
            instance,
            value: TypedIeValue::Raw(RawIe {
                ie_type,
                instance,
                spare: 0,
                value: &[],
            }),
        });
        assert!(
            s2b_create_session_request(create).is_err(),
            "Create inapplicable/profile-owned IE {ie_type}/{instance} bypassed validation"
        );
    }

    let mut emergency_with_injected_imsi = base_create_request(
        S2bCreateSessionIdentity::UiccLessEmergency {
            mei: TbcdDigits::new("356789012345670"),
            indication: Indication {
                flags: vec![0, 0x40],
            },
        },
        PdnAddressAllocation::dynamic_ipv4(),
        S2bCreateSessionContext {
            ue_endpoint: Some(S2bUeEndpoint::without_nat(IpAddress::Ipv4([
                198, 51, 100, 38,
            ]))),
            ..S2bCreateSessionContext::default()
        },
    );
    emergency_with_injected_imsi.additional_ies.push(TypedIe {
        instance: 0,
        value: TypedIeValue::Imsi(TbcdDigits::new("001010123456789")),
    });
    assert!(
        s2b_create_session_request(emergency_with_injected_imsi).is_err(),
        "UICC-less emergency identity must not be bypassed by additional IMSI"
    );

    let create_invalid_nat = base_create_request(
        S2bCreateSessionIdentity::subscriber(TbcdDigits::new("001010123456789")),
        PdnAddressAllocation::dynamic_ipv4(),
        S2bCreateSessionContext {
            ue_endpoint: Some(S2bUeEndpoint {
                local_ip: IpAddress::Ipv4([198, 51, 100, 39]),
                nat: S2bUeNatTraversal::Detected {
                    udp_port: None,
                    tcp_port: None,
                },
            }),
            ..S2bCreateSessionContext::default()
        },
    );
    assert!(s2b_create_session_request(create_invalid_nat).is_err());

    for (ie_type, instance) in [
        (IE_TYPE_EBI, 0),
        (IE_TYPE_INDICATION, 0),
        (IE_TYPE_PCO, 0),
        (IE_TYPE_RAN_NAS_CAUSE, 0),
        (IE_TYPE_RAN_NAS_CAUSE, 1),
        (IE_TYPE_IP_ADDRESS, 0),
        (IE_TYPE_IP_ADDRESS, 3),
        (IE_TYPE_PORT_NUMBER, 1),
        (IE_TYPE_PORT_NUMBER, 2),
        (IE_TYPE_TWAN_IDENTIFIER, 1),
        (IE_TYPE_TWAN_IDENTIFIER, 0),
        (IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP, 1),
        (IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP, 0),
        (IE_TYPE_MSISDN, 0),
        (IE_TYPE_CHARGING_CHARACTERISTICS, 0),
        (IE_TYPE_TRACE_INFORMATION, 0),
    ] {
        let mut delete = S2bDeleteSessionRequest {
            sequence_number: 0x010204,
            teid: 0x5566_7788,
            linked_ebi: EpsBearerId { value: 5 },
            context: S2bDeleteSessionContext {
                release_cause: None,
                indication: None,
                pco: None,
                wlan_location: None,
                wlan_location_timestamp: None,
                ue_endpoint: S2bUeEndpoint::without_nat(IpAddress::Ipv4([198, 51, 100, 40])),
            },
            additional_ies: Vec::new(),
        };
        delete.additional_ies.push(TypedIe {
            instance,
            value: TypedIeValue::Raw(RawIe {
                ie_type,
                instance,
                spare: 0,
                value: &[],
            }),
        });
        assert!(
            s2b_delete_session_request(delete).is_err(),
            "Delete inapplicable/profile-owned IE {ie_type}/{instance} bypassed validation"
        );
    }

    let delete = S2bDeleteSessionRequest {
        sequence_number: 0x010204,
        teid: 0x5566_7788,
        linked_ebi: EpsBearerId { value: 5 },
        context: S2bDeleteSessionContext {
            release_cause: None,
            indication: None,
            pco: None,
            wlan_location: None,
            wlan_location_timestamp: None,
            ue_endpoint: S2bUeEndpoint {
                local_ip: IpAddress::Ipv4([198, 51, 100, 40]),
                nat: S2bUeNatTraversal::Detected {
                    udp_port: None,
                    tcp_port: None,
                },
            },
        },
        additional_ies: Vec::new(),
    };
    assert!(s2b_delete_session_request(delete).is_err());
}

#[test]
fn procedure_receive_discards_wrong_context_instances_and_preserves_unknown_optionals() {
    let mut request = base_create_request(
        S2bCreateSessionIdentity::subscriber(TbcdDigits::new("001010123456789")),
        PdnAddressAllocation::dynamic_ipv4(),
        S2bCreateSessionContext::default(),
    );
    request.additional_ies.push(TypedIe {
        instance: 9,
        value: TypedIeValue::Raw(opc_proto_gtpv2c::RawIe {
            ie_type: 250,
            instance: 9,
            spare: 0,
            value: &[0xde, 0xad],
        }),
    });
    let built = s2b_create_session_request(request).expect("unknown optional IE builds");
    let create_wrong_keys = [
        (IE_TYPE_MSISDN, 1),
        (IE_TYPE_CHARGING_CHARACTERISTICS, 1),
        (IE_TYPE_TRACE_INFORMATION, 1),
        (IE_TYPE_IP_ADDRESS, 1),
        (IE_TYPE_PORT_NUMBER, 1),
        (IE_TYPE_TWAN_IDENTIFIER, 0),
        (IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP, 1),
        (IE_TYPE_RAN_NAS_CAUSE, 0),
        (IE_TYPE_PDN_TYPE, 0),
    ];
    // Zero-length values prove the known wrong-instance TLIV is discarded
    // before value decoding under TS 29.274 clause 7.7.9.
    let wire = append_raw_tlivs(&built, &create_wrong_keys);
    let (tail, decoded) = S2bMessage::decode(&wire, procedure_context())
        .expect("wrong-instance known IE is discarded");
    assert!(tail.is_empty());
    let view = decoded.as_view().expect("typed Create Session view");
    for key in create_wrong_keys {
        assert!(
            !view.ies.iter().any(|ie| (ie.ie_type(), ie.instance) == key),
            "Create wrong-instance IE {key:?} was retained"
        );
    }
    assert!(view
        .ies
        .iter()
        .any(|ie| ie.ie_type() == 250 && ie.instance == 9));

    let mut delete = S2bDeleteSessionRequest {
        sequence_number: 0x010204,
        teid: 0x5566_7788,
        linked_ebi: EpsBearerId { value: 5 },
        context: S2bDeleteSessionContext {
            release_cause: None,
            indication: None,
            pco: None,
            wlan_location: None,
            wlan_location_timestamp: None,
            ue_endpoint: S2bUeEndpoint::without_nat(IpAddress::Ipv4([198, 51, 100, 40])),
        },
        additional_ies: Vec::new(),
    };
    delete.additional_ies.push(TypedIe {
        instance: 8,
        value: TypedIeValue::Raw(RawIe {
            ie_type: 251,
            instance: 8,
            spare: 0,
            value: &[0xbe, 0xef],
        }),
    });
    let built = s2b_delete_session_request(delete).expect("unknown Delete optional IE builds");
    let delete_wrong_keys = [
        (IE_TYPE_MSISDN, 0),
        (IE_TYPE_CHARGING_CHARACTERISTICS, 0),
        (IE_TYPE_TRACE_INFORMATION, 0),
        (IE_TYPE_RAN_NAS_CAUSE, 1),
        (IE_TYPE_IP_ADDRESS, 3),
        (IE_TYPE_PORT_NUMBER, 2),
        (IE_TYPE_TWAN_IDENTIFIER, 0),
        (IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP, 0),
        (IE_TYPE_PDN_TYPE, 0),
    ];
    let wire = append_raw_tlivs(&built, &delete_wrong_keys);
    let (tail, decoded) = S2bMessage::decode(&wire, procedure_context())
        .expect("Delete wrong-instance known IEs are discarded");
    assert!(tail.is_empty());
    let view = decoded.as_view().expect("typed Delete Session view");
    for key in delete_wrong_keys {
        assert!(
            !view.ies.iter().any(|ie| (ie.ie_type(), ie.instance) == key),
            "Delete wrong-instance IE {key:?} was retained"
        );
    }
    assert!(view
        .ies
        .iter()
        .any(|ie| ie.ie_type() == IE_TYPE_IP_ADDRESS && ie.instance == 0));
    assert!(view
        .ies
        .iter()
        .any(|ie| ie.ie_type() == 251 && ie.instance == 8));
}

#[test]
fn procedure_receive_enforces_create_port_dependency_after_instance_filtering() {
    let built = s2b_create_session_request(base_create_request(
        S2bCreateSessionIdentity::subscriber(TbcdDigits::new("001010123456789")),
        PdnAddressAllocation::dynamic_ipv4(),
        S2bCreateSessionContext::default(),
    ))
    .expect("Create Session without optional endpoint builds");
    let mut raw_ies = BytesMut::from(built.raw_ies.as_ref());
    TypedIe {
        instance: 0,
        value: TypedIeValue::PortNumber(PortNumber::new(4500)),
    }
    .encode(&mut raw_ies, EncodeContext::default())
    .expect("valid orphan UDP Port encodes for receive test");
    let wire = encode_owned(&OwnedMessage {
        header: built.header,
        raw_ies: raw_ies.freeze(),
    });

    assert!(
        S2bMessage::decode(&wire, procedure_context()).is_err(),
        "ProcedureAware receive must reject a retained port without UE Local IP"
    );

    let (tail, strict) = S2bMessage::decode(
        &wire,
        DecodeContext {
            validation_level: ValidationLevel::Strict,
            ..DecodeContext::default()
        },
    )
    .expect("strict decode leaves the cross-field projection to the caller");
    assert!(tail.is_empty());
    assert_eq!(
        strict
            .as_view()
            .expect("typed strict Create Session view")
            .create_session_context(),
        Err(S2bSessionContextProjectionError::CreatePortWithoutLocalIp)
    );
}

#[test]
fn receive_cardinality_is_per_type_and_instance_for_every_session_context_singleton() {
    let create = s2b_create_session_request(complete_create_context_request())
        .expect("complete Create Session context builds");
    let delete = s2b_delete_session_request(complete_delete_context_request())
        .expect("complete Delete Session context builds");
    let rows = [
        (
            "Create",
            create,
            vec![
                (IE_TYPE_IMSI, 0),
                (IE_TYPE_MSISDN, 0),
                (IE_TYPE_MEI, 0),
                (IE_TYPE_INDICATION, 0),
                (IE_TYPE_PCO, 0),
                (IE_TYPE_APCO, 0),
                (IE_TYPE_RECOVERY, 0),
                (IE_TYPE_CHARGING_CHARACTERISTICS, 0),
                (IE_TYPE_TRACE_INFORMATION, 0),
                (IE_TYPE_IP_ADDRESS, 0),
                (IE_TYPE_IP_ADDRESS, 3),
                (IE_TYPE_PORT_NUMBER, 0),
                (IE_TYPE_PORT_NUMBER, 2),
                (IE_TYPE_TWAN_IDENTIFIER, 1),
                (IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP, 0),
            ],
        ),
        (
            "Delete",
            delete,
            vec![
                (IE_TYPE_EBI, 0),
                (IE_TYPE_INDICATION, 0),
                (IE_TYPE_PCO, 0),
                (IE_TYPE_RAN_NAS_CAUSE, 0),
                (IE_TYPE_TWAN_IDENTIFIER, 1),
                (IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP, 1),
                (IE_TYPE_IP_ADDRESS, 0),
                (IE_TYPE_PORT_NUMBER, 0),
                (IE_TYPE_PORT_NUMBER, 1),
            ],
        ),
    ];

    for (procedure, message, keys) in rows {
        let wire = encode_owned(&message);
        let (_, decoded) = S2bMessage::decode(&wire, procedure_context())
            .unwrap_or_else(|error| panic!("complete {procedure} fixture must decode: {error}"));
        let view = decoded.as_view().expect("typed session request view");
        for key in keys {
            let duplicate = view
                .ies
                .iter()
                .find(|ie| (ie.ie_type(), ie.instance) == key)
                .unwrap_or_else(|| panic!("complete {procedure} fixture is missing {key:?}"))
                .clone();
            assert_eq!(
                view.ies
                    .iter()
                    .filter(|ie| (ie.ie_type(), ie.instance) == key)
                    .count(),
                1,
                "{procedure} fixture must have one initial {key:?}"
            );

            let mut raw_ies = BytesMut::from(view.raw_ies);
            duplicate
                .encode(&mut raw_ies, EncodeContext::default())
                .expect("same-value singleton duplicate encodes");
            let duplicate_wire = encode_owned(&OwnedMessage {
                header: view.header.clone(),
                raw_ies: raw_ies.freeze(),
            });
            let (tail, decoded) =
                S2bMessage::decode_with_diagnostics(&duplicate_wire, procedure_context())
                    .unwrap_or_else(|error| {
                        panic!("{procedure} duplicate {key:?} must be first-wins: {error}")
                    });
            assert!(tail.is_empty());
            let retained = decoded
                .message()
                .as_view()
                .expect("typed duplicate session request view")
                .ies
                .iter()
                .filter(|ie| (ie.ie_type(), ie.instance) == key)
                .count();
            assert_eq!(retained, 1, "{procedure} must retain one {key:?}");
            let evidence = decoded
                .diagnostics()
                .duplicate_ies()
                .iter()
                .find(|entry| entry.ie_type() == key.0 && entry.instance() == key.1)
                .unwrap_or_else(|| panic!("{procedure} duplicate {key:?} needs evidence"));
            assert_eq!(evidence.depth(), 0);
            assert_eq!(evidence.duplicate_count(), 1);
            assert_eq!(decoded.diagnostics().omitted_duplicate_count(), 0);
        }
    }
}

#[test]
fn receive_rejects_delete_without_mandatory_local_ip() {
    let raw_ies = Bytes::from_static(&[IE_TYPE_EBI, 0, 1, 0, 5]);
    let received = OwnedMessage {
        header: opc_proto_gtpv2c::Header::with_teid(36, 0x0102_0304, 0x010205),
        raw_ies,
    };
    let mut wire = BytesMut::new();
    received
        .encode(&mut wire, EncodeContext::default())
        .expect("malformed Delete Session fixture encodes");
    assert!(S2bMessage::decode(&wire, procedure_context()).is_err());

    let (_, strict) = S2bMessage::decode(
        &wire,
        DecodeContext {
            validation_level: ValidationLevel::Strict,
            ..DecodeContext::default()
        },
    )
    .expect("strict context leaves procedure projection to caller");
    assert_eq!(
        strict
            .as_view()
            .expect("typed strict Delete Session view")
            .delete_session_context(),
        Err(S2bSessionContextProjectionError::DeleteMissingLocalIp)
    );
}

#[test]
fn session_context_debug_redacts_subscriber_endpoint_location_trace_and_release_values() {
    let sensitive_imsi = "001019876543210";
    let sensitive_msisdn = "15559876543";
    let sensitive_mei = "356789012345671";
    let sensitive_ssid = "private-location-ssid";
    let identity = S2bCreateSessionIdentity::Subscriber {
        imsi: TbcdDigits::new(sensitive_imsi),
        mei: Some(TbcdDigits::new(sensitive_mei)),
        indication: Some(Indication {
            flags: vec![0x01, 0x00],
        }),
    };
    let aaa_msisdn = S2bAaaProvidedMsisdn::new(TbcdDigits::new(sensitive_msisdn));
    let endpoint = S2bUeEndpoint {
        local_ip: IpAddress::Ipv4([203, 0, 113, 199]),
        nat: S2bUeNatTraversal::Detected {
            udp_port: Some(PortNumber::new(49999)),
            tcp_port: Some(PortNumber::new(50000)),
        },
    };
    let context = S2bCreateSessionContext {
        msisdn: Some(aaa_msisdn.clone()),
        charging_characteristics: Some(ChargingCharacteristics::from_octets([0x11, 0x22])),
        trace_information: Some(trace_information()),
        wlan_location: Some(
            TwanIdentifier::new(sensitive_ssid.as_bytes().to_vec()).expect("valid test SSID"),
        ),
        wlan_location_timestamp: Some(TwanIdentifierTimestamp::from_ntp_seconds(0x1020_3040)),
        ue_endpoint: Some(endpoint),
        epdg_ikev2_endpoint: Some(IpAddress::Ipv4([203, 0, 113, 200])),
        ..S2bCreateSessionContext::default()
    };
    let create_request = base_create_request(
        identity.clone(),
        PdnAddressAllocation::static_ipv4([10, 20, 30, 40]).expect("valid static PAA"),
        context.clone(),
    );
    let mut debug = format!(
        "{identity:?} {aaa_msisdn:?} {endpoint:?} {:?} {:?} {:?} {context:?} {create_request:?}",
        endpoint.nat,
        trace_information(),
        ChargingCharacteristics::from_octets([0x11, 0x22]),
    );

    let create =
        s2b_create_session_request(create_request).expect("redaction Create Session builds");
    let create_wire = encode_owned(&create);
    let (_, create_decoded) = S2bMessage::decode(&create_wire, procedure_context())
        .expect("redaction Create Session decodes");
    let create_summary = create_decoded
        .as_view()
        .expect("typed redaction Create view")
        .create_session_context()
        .expect("redaction Create context projects");
    debug.push_str(&format!(" {create_decoded:?} {create_summary:?}"));

    let delete_context = S2bDeleteSessionContext {
        release_cause: Some(RanNasCause::ikev2(16001).expect("test IKEv2 error type is valid")),
        indication: Some(Indication {
            flags: vec![0x01, 0x00],
        }),
        pco: Some(ProtocolConfigurationOptions { value: vec![0x80] }),
        wlan_location: Some(
            TwanIdentifier::new(sensitive_ssid.as_bytes().to_vec()).expect("valid test SSID"),
        ),
        wlan_location_timestamp: Some(TwanIdentifierTimestamp::from_ntp_seconds(0x1020_3040)),
        ue_endpoint: endpoint,
    };
    let delete_request = S2bDeleteSessionRequest {
        sequence_number: 0x010204,
        teid: 0xdead_beef,
        linked_ebi: EpsBearerId { value: 5 },
        context: delete_context.clone(),
        additional_ies: Vec::new(),
    };
    debug.push_str(&format!(" {delete_context:?} {delete_request:?}"));
    let delete =
        s2b_delete_session_request(delete_request).expect("redaction Delete Session builds");
    let delete_wire = encode_owned(&delete);
    let (_, delete_decoded) = S2bMessage::decode(&delete_wire, procedure_context())
        .expect("redaction Delete Session decodes");
    let delete_summary = delete_decoded
        .as_view()
        .expect("typed redaction Delete view")
        .delete_session_context()
        .expect("redaction Delete context projects");
    debug.push_str(&format!(" {delete_decoded:?} {delete_summary:?}"));

    for secret in [
        sensitive_imsi,
        sensitive_msisdn,
        sensitive_mei,
        sensitive_ssid,
        "203.0.113.199",
        "203.0.113.200",
        "203, 0, 113, 199",
        "203, 0, 113, 200",
        "49999",
        "50000",
        "161, 162, 163",
        "192, 0, 2, 200",
        "17, 34",
        "270544960",
        "16001",
    ] {
        assert!(!debug.contains(secret), "Debug leaked {secret}");
    }

    let release_debug = format!(
        "{:?}",
        RanNasCause::ikev2(16001).expect("test IKEv2 error type is valid")
    );
    assert!(!release_debug.contains("16001"));
    let charging_debug = format!("{:?}", ChargingCharacteristics::from_octets([0x12, 0x34]));
    assert!(!charging_debug.contains("18"));
    assert!(!charging_debug.contains("52"));
}
