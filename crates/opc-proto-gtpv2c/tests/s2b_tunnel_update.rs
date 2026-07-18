//! TS 29.274 R18 S2b UE-initiated IPsec tunnel-update fixtures.
//!
//! The wire constants below were authored directly from clauses 8.9, 8.56,
//! 8.100, 8.110, and Table 7.2.7-1 rather than emitted by the SDK encoder.

use bytes::BytesMut;
use opc_proto_gtpv2c::{
    decode_typed_ie_sequence, s2b_modify_bearer_response, s2b_ue_ipsec_tunnel_update_request,
    BearerContext, CauseValue, Gtpv2cClientResponseEvidence, Gtpv2cClientTransaction,
    Gtpv2cClientTransactionDecision, Gtpv2cClientTransactionPlan, Gtpv2cClientTransactionPolicy,
    Gtpv2cPeerToken, IpAddress, PlmnId, PortNumber, RawIe, S2bMessage, S2bModifyBearerResponse,
    S2bUeIpsecTunnelUpdateEndpoint, S2bUeIpsecTunnelUpdateRequest, TwanIdentifier,
    TwanIdentifierError, TwanIdentifierTimestamp, TwanLogicalAccessId, TwanRelayIdentity, TypedIe,
    TypedIeValue, IE_TYPE_BEARER_CONTEXT, IE_TYPE_IP_ADDRESS, IE_TYPE_OVERLOAD_CONTROL_INFORMATION,
    IE_TYPE_PORT_NUMBER, IE_TYPE_TWAN_IDENTIFIER, IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP,
    MODIFY_BEARER_REQUEST,
};
#[allow(deprecated)]
use opc_proto_gtpv2c::{s2b_modify_bearer_request, S2bModifyBearerRequest};
use opc_protocol::{DecodeContext, DecodeErrorCode, Encode, EncodeContext, ValidationLevel};

const GENERAL_LOCATION_AND_TIMESTAMP: &[u8] = &[
    0x48, 0x22, 0x00, 0x23, 0x11, 0x22, 0x33, 0x44, 0x01, 0x02, 0x03, 0x00,
    // TWAN Identifier, instance 0: BSSID + PLMN, SSID "lab1".
    0xa9, 0x00, 0x0f, 0x00, 0x05, 0x04, 0x6c, 0x61, 0x62, 0x31, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0xf1, 0x10, // TWAN Identifier Timestamp, instance 0.
    0xb3, 0x00, 0x04, 0x00, 0xe9, 0x3c, 0x7f, 0x00,
];

const GENERAL_NO_OPTIONAL_FIELDS: &[u8] = &[
    0x48, 0x22, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44, 0x01, 0x02, 0x04, 0x00,
];

const GENERAL_LOCATION_ONLY: &[u8] = &[
    0x48, 0x22, 0x00, 0x1b, 0x11, 0x22, 0x33, 0x44, 0x01, 0x02, 0x05, 0x00, 0xa9, 0x00, 0x0f, 0x00,
    0x05, 0x04, 0x6c, 0x61, 0x62, 0x31, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0xf1, 0x10,
];

const GENERAL_TIMESTAMP_ONLY: &[u8] = &[
    0x48, 0x22, 0x00, 0x10, 0x11, 0x22, 0x33, 0x44, 0x01, 0x02, 0x06, 0x00, 0xb3, 0x00, 0x04, 0x00,
    0xe9, 0x3c, 0x7f, 0x00,
];

const FIXED_BROADBAND_LOCAL_IP: &[u8] = &[
    0x48, 0x22, 0x00, 0x10, 0x11, 0x22, 0x33, 0x44, 0x01, 0x02, 0x07, 0x00, 0x4a, 0x00, 0x04, 0x01,
    0xc6, 0x33, 0x64, 0x07,
];

const FIXED_BROADBAND_LOCAL_IP_AND_UDP: &[u8] = &[
    0x48, 0x22, 0x00, 0x16, 0x11, 0x22, 0x33, 0x44, 0x01, 0x02, 0x08, 0x00, 0x4a, 0x00, 0x04, 0x01,
    0xc6, 0x33, 0x64, 0x07, 0x7e, 0x00, 0x02, 0x01, 0xaf, 0xc8,
];

// TS 29.274 Table 7.2.7-4 mandatory grouped members: overload sequence,
// reduction metric, and period-of-validity timer.
const EPDG_OVERLOAD_CONTROL_VALUE: &[u8] = &[
    0xb7, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x01, 0xb6, 0x00, 0x01, 0x00, 0x0a, 0x9c, 0x00, 0x01,
    0x00, 0x01,
];

fn procedure_context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    }
}

fn encode_message(message: &impl Encode) -> Vec<u8> {
    let mut bytes = BytesMut::new();
    message
        .encode(&mut bytes, EncodeContext::default())
        .expect("test message must encode");
    bytes.to_vec()
}

fn encode_typed_ie(ie: &TypedIe<'_>) -> Vec<u8> {
    let mut bytes = BytesMut::new();
    ie.encode(&mut bytes, EncodeContext::default())
        .expect("test IE must encode");
    bytes.to_vec()
}

fn raw_typed_ie<'a>(ie_type: u8, instance: u8, value: &'a [u8]) -> TypedIe<'a> {
    TypedIe {
        instance,
        value: TypedIeValue::Raw(RawIe {
            ie_type,
            instance,
            spare: 0,
            value,
        }),
    }
}

fn label_encoded_fqdn(final_label_len: usize) -> Vec<u8> {
    let mut value = Vec::with_capacity(193 + final_label_len);
    for label_octet in *b"abc" {
        value.push(63);
        value.extend(std::iter::repeat_n(label_octet, 63));
    }
    value.push(u8::try_from(final_label_len).expect("test label length must fit in one octet"));
    value.extend(std::iter::repeat_n(b'd', final_label_len));
    value
}

fn decode_request(bytes: &[u8]) -> opc_proto_gtpv2c::S2bProcedureMessage<'_> {
    let (tail, message) = S2bMessage::decode(bytes, procedure_context())
        .expect("independent S2b tunnel-update bytes must decode");
    assert!(tail.is_empty());
    match message {
        S2bMessage::ModifySessionRequest(view) => view,
        other => panic!("expected Modify Bearer Request, got {other:?}"),
    }
}

fn location() -> TwanIdentifier {
    TwanIdentifier {
        ssid: b"lab1".to_vec(),
        bssid: Some([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
        civic_address: None,
        plmn: Some(PlmnId::new("001", "01")),
        operator_name: None,
        logical_access_id: None,
    }
}

#[test]
fn independent_general_update_fixtures_cover_optional_field_combinations() {
    let cases = [
        (GENERAL_NO_OPTIONAL_FIELDS, false, false, 0x010204),
        (GENERAL_LOCATION_ONLY, true, false, 0x010205),
        (GENERAL_TIMESTAMP_ONLY, false, true, 0x010206),
        (GENERAL_LOCATION_AND_TIMESTAMP, true, true, 0x010203),
    ];

    for (bytes, location_present, timestamp_present, sequence_number) in cases {
        let summary = decode_request(bytes)
            .ue_ipsec_tunnel_update_request_summary()
            .expect("valid request must project");
        assert_eq!(summary.sequence_number, sequence_number);
        assert_eq!(summary.teid, 0x1122_3344);
        assert_eq!(summary.wlan_location.is_some(), location_present);
        assert_eq!(summary.wlan_location_timestamp.is_some(), timestamp_present);
        assert_eq!(summary.endpoint, S2bUeIpsecTunnelUpdateEndpoint::General);
    }
}

#[test]
fn builder_matches_independent_general_fixture_exactly() {
    let built = s2b_ue_ipsec_tunnel_update_request(S2bUeIpsecTunnelUpdateRequest {
        sequence_number: 0x010203,
        teid: 0x1122_3344,
        wlan_location: Some(location()),
        wlan_location_timestamp: Some(TwanIdentifierTimestamp::from_ntp_seconds(0xe93c_7f00)),
        endpoint: S2bUeIpsecTunnelUpdateEndpoint::General,
        additional_ies: Vec::new(),
    })
    .expect("typed general update must build");
    assert_eq!(encode_message(&built), GENERAL_LOCATION_AND_TIMESTAMP);
}

#[test]
fn fixed_broadband_fixtures_enforce_instance_one_and_udp_dependency() {
    let without_nat = decode_request(FIXED_BROADBAND_LOCAL_IP)
        .ue_ipsec_tunnel_update_request_summary()
        .expect("local-IP-only update must project");
    assert_eq!(
        without_nat.endpoint,
        S2bUeIpsecTunnelUpdateEndpoint::FixedBroadband {
            ue_local_ip: IpAddress::Ipv4([198, 51, 100, 7]),
            ue_udp_port: None,
        }
    );

    let with_nat = decode_request(FIXED_BROADBAND_LOCAL_IP_AND_UDP)
        .ue_ipsec_tunnel_update_request_summary()
        .expect("local IP plus UDP update must project");
    assert_eq!(
        with_nat.endpoint,
        S2bUeIpsecTunnelUpdateEndpoint::FixedBroadband {
            ue_local_ip: IpAddress::Ipv4([198, 51, 100, 7]),
            ue_udp_port: Some(PortNumber::new(45_000)),
        }
    );

    let built = s2b_ue_ipsec_tunnel_update_request(S2bUeIpsecTunnelUpdateRequest {
        sequence_number: 0x010208,
        teid: 0x1122_3344,
        wlan_location: None,
        wlan_location_timestamp: None,
        endpoint: S2bUeIpsecTunnelUpdateEndpoint::FixedBroadband {
            ue_local_ip: IpAddress::Ipv4([198, 51, 100, 7]),
            ue_udp_port: Some(PortNumber::new(45_000)),
        },
        additional_ies: Vec::new(),
    })
    .expect("typed Fixed Broadband update must build");
    assert_eq!(encode_message(&built), FIXED_BROADBAND_LOCAL_IP_AND_UDP);

    let port_without_ip = [
        0x48, 0x22, 0x00, 0x0e, 0x11, 0x22, 0x33, 0x44, 0x01, 0x02, 0x09, 0x00, 0x7e, 0x00, 0x02,
        0x01, 0xaf, 0xc8,
    ];
    let error = S2bMessage::decode(&port_without_ip, procedure_context())
        .expect_err("UDP port without local IP must fail closed");
    assert!(matches!(
        error.code(),
        DecodeErrorCode::Structural {
            reason: "S2b UE UDP Port at instance 1 requires UE Local IP Address at instance 1"
        }
    ));
}

#[test]
fn complete_twan_identifier_codec_is_bounded_typed_and_redacted() {
    let full = TwanIdentifier {
        ssid: b"lab".to_vec(),
        bssid: Some([2, 0, 0, 0, 0, 1]),
        civic_address: Some(vec![0xaa, 0xbb]),
        plmn: None,
        operator_name: Some(b"op1".to_vec()),
        logical_access_id: Some(TwanLogicalAccessId {
            relay_identity: TwanRelayIdentity::Fqdn(vec![3, b'r', b'e', b'l', 3, b'l', b'a', b'b']),
            circuit_id: vec![1, 2],
        }),
    };
    assert_eq!(full.validate(), Ok(()));
    let ie = TypedIe {
        instance: 0,
        value: TypedIeValue::TwanIdentifier(full.clone()),
    };
    let mut encoded = BytesMut::new();
    ie.encode(&mut encoded, EncodeContext::default())
        .expect("complete TWAN Identifier must encode");
    assert_eq!(
        encoded.as_ref(),
        &[
            0xa9, 0x00, 0x1f, 0x00, 0x1b, 0x03, b'l', b'a', b'b', 2, 0, 0, 0, 0, 1, 2, 0xaa, 0xbb,
            3, b'o', b'p', b'1', 1, 8, 3, b'r', b'e', b'l', 3, b'l', b'a', b'b', 2, 1, 2,
        ]
    );
    let decoded = decode_typed_ie_sequence(encoded.as_ref(), procedure_context(), 0)
        .expect("complete TWAN Identifier must decode");
    assert_eq!(decoded, vec![ie]);

    let debug = format!("{full:?}");
    assert!(!debug.contains("lab"));
    assert!(!debug.contains("op1"));
    assert!(!debug.contains("001"));
    assert!(debug.contains("<redacted>"));

    let mut too_long = full;
    too_long.ssid = vec![0; 33];
    assert_eq!(too_long.validate(), Err(TwanIdentifierError::SsidTooLong));

    let conflicting = TwanIdentifier {
        ssid: b"lab".to_vec(),
        bssid: None,
        civic_address: None,
        plmn: Some(PlmnId::new("001", "01")),
        operator_name: Some(b"operator.example".to_vec()),
        logical_access_id: None,
    };
    assert_eq!(
        conflicting.validate(),
        Err(TwanIdentifierError::ConflictingOperatorIdentifiers)
    );
}

#[test]
fn relay_fqdn_enforces_rfc_1035_complete_name_bound() {
    let valid = TwanIdentifier {
        ssid: b"lab".to_vec(),
        bssid: None,
        civic_address: None,
        plmn: None,
        operator_name: None,
        logical_access_id: Some(TwanLogicalAccessId {
            relay_identity: TwanRelayIdentity::Fqdn(label_encoded_fqdn(61)),
            circuit_id: vec![1],
        }),
    };
    let valid_fqdn_len = match &valid
        .logical_access_id
        .as_ref()
        .expect("test Logical Access ID must exist")
        .relay_identity
    {
        TwanRelayIdentity::Fqdn(value) => value.len(),
        TwanRelayIdentity::IpAddress(_) => panic!("test relay must be an FQDN"),
    };
    assert_eq!(valid_fqdn_len, 254);
    assert_eq!(valid.validate(), Ok(()));

    let ie = TypedIe {
        instance: 0,
        value: TypedIeValue::TwanIdentifier(valid.clone()),
    };
    let encoded = encode_typed_ie(&ie);
    assert_eq!(
        decode_typed_ie_sequence(&encoded, procedure_context(), 0)
            .expect("254-octet rootless relay FQDN must decode"),
        vec![ie]
    );

    let mut invalid = valid;
    invalid
        .logical_access_id
        .as_mut()
        .expect("test Logical Access ID must exist")
        .relay_identity = TwanRelayIdentity::Fqdn(label_encoded_fqdn(62));
    assert_eq!(
        invalid.validate(),
        Err(TwanIdentifierError::InvalidRelayFqdn)
    );
    let error = TypedIe {
        instance: 0,
        value: TypedIeValue::TwanIdentifier(invalid),
    }
    .encode(&mut BytesMut::new(), EncodeContext::default())
    .expect_err("255-octet rootless relay FQDN must not encode");
    assert!(matches!(
        error.code(),
        opc_protocol::EncodeErrorCode::Structural { .. }
    ));
}

#[test]
fn fixed_and_extendable_ie_lengths_follow_their_release_contracts() {
    for (ie_type, value, expected_truncated) in [
        (IE_TYPE_IP_ADDRESS, vec![0; 5], false),
        (IE_TYPE_PORT_NUMBER, vec![0; 1], true),
        (IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP, vec![0; 3], true),
    ] {
        let raw = RawIe {
            ie_type,
            instance: 0,
            spare: 0,
            value: &value,
        };
        let error = TypedIe::decode_from_raw(raw, procedure_context(), 0, 0)
            .expect_err("invalid fixed-size IE must fail");
        if expected_truncated {
            assert_eq!(error.code(), &DecodeErrorCode::Truncated);
        } else {
            assert!(matches!(
                error.code(),
                DecodeErrorCode::InvalidLength { .. }
            ));
        }
    }

    let port = TypedIe::decode_from_raw(
        RawIe {
            ie_type: IE_TYPE_PORT_NUMBER,
            instance: 1,
            spare: 0,
            value: &[0xaf, 0xc8, 0xaa],
        },
        procedure_context(),
        0,
        0,
    )
    .expect("Port Number receiver must ignore an extension suffix");
    assert!(matches!(
        port.value,
        TypedIeValue::PortNumber(value) if value == PortNumber::new(45_000)
    ));
    assert_eq!(encode_typed_ie(&port), [0x7e, 0x00, 0x02, 0x01, 0xaf, 0xc8]);

    let timestamp = TypedIe::decode_from_raw(
        RawIe {
            ie_type: IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP,
            instance: 0,
            spare: 0,
            value: &[0xe9, 0x3c, 0x7f, 0x00, 0xbb],
        },
        procedure_context(),
        0,
        0,
    )
    .expect("TWAN timestamp receiver must ignore an extension suffix");
    assert!(matches!(
        timestamp.value,
        TypedIeValue::TwanIdentifierTimestamp(value)
            if value == TwanIdentifierTimestamp::from_ntp_seconds(0xe93c_7f00)
    ));
    assert_eq!(
        encode_typed_ie(&timestamp),
        [0xb3, 0x00, 0x04, 0x00, 0xe9, 0x3c, 0x7f, 0x00]
    );
}

#[test]
fn twan_flag_directed_fields_reject_truncation() {
    for value in [
        vec![0x01, 0x00, 0, 0, 0, 0, 0],
        vec![0x02, 0x00],
        vec![0x04, 0x00, 0, 0],
        vec![0x08, 0x00],
        vec![0x10, 0x00],
    ] {
        let error = TypedIe::decode_from_raw(
            RawIe {
                ie_type: IE_TYPE_TWAN_IDENTIFIER,
                instance: 0,
                spare: 0,
                value: &value,
            },
            procedure_context(),
            0,
            0,
        )
        .expect_err("truncated flag-directed TWAN field must fail");
        assert!(matches!(error.code(), DecodeErrorCode::Truncated));
    }
}

#[test]
fn twan_receive_ignores_extensions_and_spare_flags_but_canonicalizes_them() {
    let mut extended = GENERAL_LOCATION_AND_TIMESTAMP.to_vec();
    extended[2..4].copy_from_slice(&0x0024_u16.to_be_bytes());
    extended[13..15].copy_from_slice(&0x0010_u16.to_be_bytes());
    extended.insert(31, 0xaa);

    let (_, decoded) = S2bMessage::decode(&extended, procedure_context())
        .expect("TWAN extension suffix must be ignored by the Release 18 view");
    let mut raw_preserved = BytesMut::new();
    decoded
        .encode(
            &mut raw_preserved,
            EncodeContext {
                raw_preserving: true,
                ..EncodeContext::default()
            },
        )
        .expect("raw-preserving S2b encode must retain extension suffix");
    assert_eq!(raw_preserved.as_ref(), extended);
    assert_eq!(encode_message(&decoded), GENERAL_LOCATION_AND_TIMESTAMP);

    let mut spare_flags = GENERAL_LOCATION_AND_TIMESTAMP.to_vec();
    spare_flags[16] |= 0xe0;
    S2bMessage::decode(
        &spare_flags,
        DecodeContext {
            validation_level: ValidationLevel::Strict,
            ..DecodeContext::default()
        },
    )
    .expect("strict receive must also ignore TWAN value spare flag bits");
    let (_, decoded) = S2bMessage::decode(&spare_flags, procedure_context())
        .expect("TWAN spare flag bits must be ignored on receive");
    let mut raw_preserved = BytesMut::new();
    decoded
        .encode(
            &mut raw_preserved,
            EncodeContext {
                raw_preserving: true,
                ..EncodeContext::default()
            },
        )
        .expect("raw-preserving S2b encode must retain spare flag bits");
    assert_eq!(raw_preserved.as_ref(), spare_flags);
    assert_eq!(encode_message(&decoded), GENERAL_LOCATION_AND_TIMESTAMP);
}

#[test]
fn port_and_timestamp_extensions_are_raw_preserved_and_canonicalized() {
    let mut extended_port = FIXED_BROADBAND_LOCAL_IP_AND_UDP.to_vec();
    extended_port[2..4].copy_from_slice(&0x0017_u16.to_be_bytes());
    extended_port[21..23].copy_from_slice(&0x0003_u16.to_be_bytes());
    extended_port.push(0xaa);
    let (_, decoded) = S2bMessage::decode(&extended_port, procedure_context())
        .expect("Port Number extension suffix must be ignored");
    let mut raw_preserved = BytesMut::new();
    decoded
        .encode(
            &mut raw_preserved,
            EncodeContext {
                raw_preserving: true,
                ..EncodeContext::default()
            },
        )
        .expect("raw-preserving S2b encode must retain Port Number extension");
    assert_eq!(raw_preserved.as_ref(), extended_port);
    assert_eq!(encode_message(&decoded), FIXED_BROADBAND_LOCAL_IP_AND_UDP);

    let mut extended_timestamp = GENERAL_TIMESTAMP_ONLY.to_vec();
    extended_timestamp[2..4].copy_from_slice(&0x0011_u16.to_be_bytes());
    extended_timestamp[13..15].copy_from_slice(&0x0005_u16.to_be_bytes());
    extended_timestamp.push(0xbb);
    let (_, decoded) = S2bMessage::decode(&extended_timestamp, procedure_context())
        .expect("TWAN timestamp extension suffix must be ignored");
    let mut raw_preserved = BytesMut::new();
    decoded
        .encode(
            &mut raw_preserved,
            EncodeContext {
                raw_preserving: true,
                ..EncodeContext::default()
            },
        )
        .expect("raw-preserving S2b encode must retain timestamp extension");
    assert_eq!(raw_preserved.as_ref(), extended_timestamp);
    assert_eq!(encode_message(&decoded), GENERAL_TIMESTAMP_ONLY);
}

#[test]
fn ipv6_ip_address_and_relay_identity_are_typed_and_redacted() {
    let endpoint = IpAddress::Ipv6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7]);
    let ip_ie = TypedIe {
        instance: 1,
        value: TypedIeValue::IpAddress(endpoint),
    };
    let mut ip_wire = BytesMut::new();
    ip_ie
        .encode(&mut ip_wire, EncodeContext::default())
        .expect("IPv6 IP Address IE must encode");
    let decoded = decode_typed_ie_sequence(ip_wire.as_ref(), procedure_context(), 0)
        .expect("IPv6 IP Address IE must decode");
    assert_eq!(decoded, vec![ip_ie]);

    let twan = TwanIdentifier {
        ssid: b"lab".to_vec(),
        bssid: None,
        civic_address: None,
        plmn: None,
        operator_name: None,
        logical_access_id: Some(TwanLogicalAccessId {
            relay_identity: TwanRelayIdentity::IpAddress(endpoint),
            circuit_id: vec![1, 2, 3],
        }),
    };
    let twan_ie = TypedIe {
        instance: 0,
        value: TypedIeValue::TwanIdentifier(twan),
    };
    let mut twan_wire = BytesMut::new();
    twan_ie
        .encode(&mut twan_wire, EncodeContext::default())
        .expect("IPv6 relay TWAN Identifier must encode");
    let decoded = decode_typed_ie_sequence(twan_wire.as_ref(), procedure_context(), 0)
        .expect("IPv6 relay TWAN Identifier must decode");
    assert_eq!(decoded, vec![twan_ie]);

    let debug = format!("{endpoint:?}");
    assert!(!debug.contains("2001"));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn constructor_rejects_wrong_instances_known_ies_and_legacy_bearer_shape() {
    let known_wrong_instance = TypedIe {
        instance: 0,
        value: TypedIeValue::IpAddress(IpAddress::Ipv4([198, 51, 100, 8])),
    };
    let error = s2b_ue_ipsec_tunnel_update_request(S2bUeIpsecTunnelUpdateRequest {
        sequence_number: 9,
        teid: 0x1122_3344,
        wlan_location: None,
        wlan_location_timestamp: None,
        endpoint: S2bUeIpsecTunnelUpdateEndpoint::General,
        additional_ies: vec![known_wrong_instance],
    })
    .expect_err("known fields must not bypass typed instances");
    assert!(matches!(
        error,
        opc_proto_gtpv2c::S2bProfileBuildError::Encode(_)
    ));

    let zero_teid = s2b_ue_ipsec_tunnel_update_request(S2bUeIpsecTunnelUpdateRequest {
        sequence_number: 9,
        teid: 0,
        wlan_location: None,
        wlan_location_timestamp: None,
        endpoint: S2bUeIpsecTunnelUpdateEndpoint::General,
        additional_ies: Vec::new(),
    });
    assert!(zero_teid.is_err());

    #[allow(deprecated)]
    let legacy = s2b_modify_bearer_request(S2bModifyBearerRequest {
        sequence_number: 9,
        teid: 0x1122_3344,
        bearer_context: BearerContext {
            members: Vec::new(),
        },
        additional_ies: Vec::new(),
    });
    assert!(legacy.is_err());
}

#[test]
fn epdg_overload_control_instance_two_is_the_only_known_additional_request_ie() {
    let built = s2b_ue_ipsec_tunnel_update_request(S2bUeIpsecTunnelUpdateRequest {
        sequence_number: 0x01020b,
        teid: 0x1122_3344,
        wlan_location: None,
        wlan_location_timestamp: None,
        endpoint: S2bUeIpsecTunnelUpdateEndpoint::General,
        additional_ies: vec![raw_typed_ie(
            IE_TYPE_OVERLOAD_CONTROL_INFORMATION,
            2,
            EPDG_OVERLOAD_CONTROL_VALUE,
        )],
    })
    .expect("S2b ePDG overload-control instance 2 must build");
    let bytes = encode_message(&built);
    let view = decode_request(&bytes);
    assert!(view
        .ies
        .iter()
        .any(|ie| { ie.ie_type() == IE_TYPE_OVERLOAD_CONTROL_INFORMATION && ie.instance == 2 }));

    for wrong_instance in [0, 1, 3] {
        let error = s2b_ue_ipsec_tunnel_update_request(S2bUeIpsecTunnelUpdateRequest {
            sequence_number: 0x01020b,
            teid: 0x1122_3344,
            wlan_location: None,
            wlan_location_timestamp: None,
            endpoint: S2bUeIpsecTunnelUpdateEndpoint::General,
            additional_ies: vec![raw_typed_ie(
                IE_TYPE_OVERLOAD_CONTROL_INFORMATION,
                wrong_instance,
                EPDG_OVERLOAD_CONTROL_VALUE,
            )],
        })
        .expect_err("non-S2b overload-control instance must not build");
        assert!(matches!(
            error,
            opc_proto_gtpv2c::S2bProfileBuildError::Encode(_)
        ));
    }

    let mismatched_raw_instance = TypedIe {
        instance: 2,
        value: TypedIeValue::Raw(RawIe {
            ie_type: IE_TYPE_OVERLOAD_CONTROL_INFORMATION,
            instance: 1,
            spare: 0,
            value: EPDG_OVERLOAD_CONTROL_VALUE,
        }),
    };
    let error = s2b_ue_ipsec_tunnel_update_request(S2bUeIpsecTunnelUpdateRequest {
        sequence_number: 0x01020b,
        teid: 0x1122_3344,
        wlan_location: None,
        wlan_location_timestamp: None,
        endpoint: S2bUeIpsecTunnelUpdateEndpoint::General,
        additional_ies: vec![mismatched_raw_instance],
    })
    .expect_err("raw wire instance must not bypass the S2b overload assignment");
    assert!(matches!(
        error,
        opc_proto_gtpv2c::S2bProfileBuildError::Encode(_)
    ));

    let mut wrong_receive_instance = bytes;
    wrong_receive_instance[15] = 1;
    let view = decode_request(&wrong_receive_instance);
    assert!(!view.has_ie(IE_TYPE_OVERLOAD_CONTROL_INFORMATION));
}

#[test]
fn receive_discards_unexpected_bearer_context_and_wrong_instances() {
    let mut with_bearer = GENERAL_LOCATION_AND_TIMESTAMP.to_vec();
    // Increase GTP message length by the nine-octet grouped IE below.
    with_bearer[2..4].copy_from_slice(&0x002c_u16.to_be_bytes());
    with_bearer.extend_from_slice(&[
        IE_TYPE_BEARER_CONTEXT,
        0x00,
        0x05,
        0x00,
        0x49,
        0x00,
        0x01,
        0x00,
        0x05,
    ]);
    let view = decode_request(&with_bearer);
    assert!(!view.has_ie(IE_TYPE_BEARER_CONTEXT));
    let summary = view
        .ue_ipsec_tunnel_update_request_summary()
        .expect("unexpected Bearer Context must not block S2b processing");
    assert!(summary.wlan_location.is_some());
    assert!(summary.wlan_location_timestamp.is_some());

    let wrong_ip_instance = [
        0x48, 0x22, 0x00, 0x10, 0x11, 0x22, 0x33, 0x44, 0x01, 0x02, 0x0a, 0x00, 0x4a, 0x00, 0x04,
        0x00, 0xc6, 0x33, 0x64, 0x07,
    ];
    let wrong = decode_request(&wrong_ip_instance)
        .ue_ipsec_tunnel_update_request_summary()
        .expect("known unexpected instance must be discarded");
    assert_eq!(wrong.endpoint, S2bUeIpsecTunnelUpdateEndpoint::General);
}

#[test]
fn procedure_receive_retains_first_singleton_occurrence() {
    let mut duplicate = FIXED_BROADBAND_LOCAL_IP.to_vec();
    duplicate[2..4].copy_from_slice(&0x0018_u16.to_be_bytes());
    duplicate.extend_from_slice(&[IE_TYPE_IP_ADDRESS, 0x00, 0x04, 0x01, 203, 0, 113, 9]);
    let (tail, decoded) = S2bMessage::decode_with_diagnostics(&duplicate, procedure_context())
        .expect("duplicate receive must retain the first value");
    assert!(tail.is_empty());
    assert_eq!(decoded.diagnostics().duplicate_ies().len(), 1);
    let view = decoded
        .message()
        .as_view()
        .expect("Modify Bearer Request must expose a typed view");
    let summary = view
        .ue_ipsec_tunnel_update_request_summary()
        .expect("first retained endpoint must project");
    assert_eq!(
        summary.endpoint,
        S2bUeIpsecTunnelUpdateEndpoint::FixedBroadband {
            ue_local_ip: IpAddress::Ipv4([198, 51, 100, 7]),
            ue_udp_port: None,
        }
    );
}

#[test]
fn response_projection_and_client_transaction_cover_success_rejection_retry_and_duplicate() {
    let request = s2b_ue_ipsec_tunnel_update_request(S2bUeIpsecTunnelUpdateRequest {
        sequence_number: 0x010203,
        teid: 0x1122_3344,
        wlan_location: Some(location()),
        wlan_location_timestamp: None,
        endpoint: S2bUeIpsecTunnelUpdateEndpoint::General,
        additional_ies: Vec::new(),
    })
    .expect("request must build");
    let request_bytes = encode_message(&request);
    let peer = Gtpv2cPeerToken::new(7);
    let plan = Gtpv2cClientTransactionPlan::from_encoded_request(
        &request_bytes,
        peer,
        Some(0x5566_7788),
        procedure_context(),
    )
    .expect("S2b tunnel update must be a supported client transaction");
    let mut transaction = Gtpv2cClientTransaction::with_policy(
        plan.clone(),
        Gtpv2cClientTransactionPolicy::default().with_max_response_timeouts(2),
    );
    assert_eq!(
        transaction.sent_waiting_response().decision,
        Gtpv2cClientTransactionDecision::SentWaitingResponse
    );
    assert_eq!(
        transaction.response_timeout().decision,
        Gtpv2cClientTransactionDecision::SafeRetransmitSamePeer
    );
    assert_eq!(
        transaction.sent_waiting_response().decision,
        Gtpv2cClientTransactionDecision::SentWaitingResponse
    );

    let accepted = s2b_modify_bearer_response(S2bModifyBearerResponse {
        sequence_number: 0x010203,
        teid: 0x5566_7788,
        cause: CauseValue::RequestAccepted,
        additional_ies: Vec::new(),
    })
    .expect("accepted response must build");
    let accepted_bytes = encode_message(&accepted);
    let (_, accepted_message) = S2bMessage::decode(&accepted_bytes, procedure_context())
        .expect("accepted response must decode");
    let accepted_view = accepted_message
        .as_view()
        .expect("accepted response must have a typed view");
    let accepted_summary = accepted_view
        .ue_ipsec_tunnel_update_response_summary()
        .expect("accepted Cause and correlation fields must project");
    assert_eq!(accepted_summary.sequence_number, 0x010203);
    assert_eq!(accepted_summary.teid, 0x5566_7788);
    assert_eq!(accepted_summary.cause, CauseValue::RequestAccepted);
    let accepted_evidence = Gtpv2cClientResponseEvidence::from_view(accepted_view, peer);
    assert_eq!(
        transaction.observe_response(accepted_evidence).decision,
        Gtpv2cClientTransactionDecision::ResponseMatched
    );
    assert_eq!(
        transaction.observe_response(accepted_evidence).decision,
        Gtpv2cClientTransactionDecision::DuplicateResponse
    );

    let rejected = s2b_modify_bearer_response(S2bModifyBearerResponse {
        sequence_number: 0x010203,
        teid: 0x5566_7788,
        cause: CauseValue::RequestRejected,
        additional_ies: Vec::new(),
    })
    .expect("rejected response must build");
    let rejected_bytes = encode_message(&rejected);
    let (_, rejected_message) = S2bMessage::decode(&rejected_bytes, procedure_context())
        .expect("rejected response must decode");
    let rejected_view = rejected_message
        .as_view()
        .expect("rejected response must have a typed view");
    let rejected_summary = rejected_view
        .ue_ipsec_tunnel_update_response_summary()
        .expect("rejection Cause and correlation fields must project");
    assert_eq!(rejected_summary.cause, CauseValue::RequestRejected);
    let mut rejected_transaction = Gtpv2cClientTransaction::new(plan);
    let _ = rejected_transaction.sent_waiting_response();
    assert_eq!(
        rejected_transaction
            .observe_response(Gtpv2cClientResponseEvidence::from_view(rejected_view, peer))
            .decision,
        Gtpv2cClientTransactionDecision::ResponseMatched
    );
}

#[test]
fn endpoint_and_location_debug_do_not_disclose_values() {
    let endpoint = S2bUeIpsecTunnelUpdateEndpoint::FixedBroadband {
        ue_local_ip: IpAddress::Ipv4([198, 51, 100, 7]),
        ue_udp_port: Some(PortNumber::new(45_000)),
    };
    let debug = format!("{endpoint:?}");
    assert!(!debug.contains("198"));
    assert!(!debug.contains("45000"));
    assert!(debug.contains("<redacted>"));
}

#[test]
fn fixture_message_type_is_modify_bearer_request() {
    assert_eq!(GENERAL_LOCATION_AND_TIMESTAMP[1], MODIFY_BEARER_REQUEST);
    assert_eq!(GENERAL_LOCATION_AND_TIMESTAMP[12], IE_TYPE_TWAN_IDENTIFIER);
}
