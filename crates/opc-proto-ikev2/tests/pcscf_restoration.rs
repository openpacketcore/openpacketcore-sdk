use std::net::{Ipv4Addr, Ipv6Addr};

use opc_proto_ikev2::{
    build_ike_auth_cleartext_payload_chain, build_ike_auth_configuration_payload,
    build_ikev2_pcscf_restoration_request, decode_ikev2_pcscf_restoration_response,
    decode_ikev2_pcscf_restoration_response_with_context,
    validate_ikev2_pcscf_restoration_response_correlation, Header, HeaderFlags,
    Ikev2ConfigurationAttributeBuild, Ikev2ConfigurationPayloadBuild, Ikev2IkeAuthPayloadBuild,
    Ikev2IkeAuthPayloadError, Ikev2NotifyPayloadError, Ikev2PcscfRestorationAddress,
    Ikev2PcscfRestorationAddressFamilies, Ikev2PcscfRestorationError, Ikev2ValidationProfile,
    PayloadChain, PayloadType, EXCHANGE_TYPE_CREATE_CHILD_SA, EXCHANGE_TYPE_INFORMATIONAL,
    IKEV2_PCSCF_RESTORATION_MAX_ADDRESSES,
};
use opc_protocol::{DecodeContext, UnknownIePolicy};

const CONFIGURATION_TYPE_REPLY: u8 = 2;
const P_CSCF_IP4_ADDRESS: u16 = 20;
const P_CSCF_IP6_ADDRESS: u16 = 21;
const UNSUPPORTED_CONFIGURATION_ATTRIBUTE: u16 = 32_000;
const UNRECOGNIZED_STATUS_NOTIFY: u16 = 40_000;
const ERROR_NOTIFY: u16 = 43;

fn must_ok<T, E: core::fmt::Debug>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("unexpected error: {error:?}"),
    }
}

fn request_header(message_id: u32) -> Header {
    Header::new(
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        PayloadType::Encrypted,
        EXCHANGE_TYPE_INFORMATIONAL,
        HeaderFlags::from_bits(false, false, false),
        message_id,
    )
}

fn response_header(message_id: u32) -> Header {
    Header::new(
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        PayloadType::Encrypted,
        EXCHANGE_TYPE_INFORMATIONAL,
        HeaderFlags::from_bits(true, true, false),
        message_id,
    )
}

fn configuration_body(config_type: u8, attributes: &[(u16, &[u8])]) -> Vec<u8> {
    must_ok(build_ike_auth_configuration_payload(
        &Ikev2ConfigurationPayloadBuild {
            config_type,
            attributes: attributes
                .iter()
                .map(|(attribute_type, value)| Ikev2ConfigurationAttributeBuild {
                    attribute_type: *attribute_type,
                    value: value.to_vec(),
                })
                .collect(),
        },
    ))
}

fn configuration_chain(
    config_type: u8,
    attributes: &[(u16, &[u8])],
) -> (PayloadType, bytes::Bytes) {
    let body = configuration_body(config_type, attributes);
    must_ok(build_ike_auth_cleartext_payload_chain(&[
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Configuration,
            body,
        },
    ]))
}

fn raw_payload_chain(entries: &[(PayloadType, bool, &[u8])]) -> (PayloadType, Vec<u8>) {
    let first_payload = match entries.first() {
        Some((payload_type, _, _)) => *payload_type,
        None => panic!("test fixture requires at least one payload"),
    };
    let mut bytes = Vec::new();
    for (index, (_, critical, body)) in entries.iter().enumerate() {
        let next_payload = entries
            .get(index + 1)
            .map_or(PayloadType::NoNext, |(payload_type, _, _)| *payload_type);
        let payload_len = match u16::try_from(4 + body.len()) {
            Ok(value) => value,
            Err(_) => panic!("test fixture payload exceeds u16"),
        };
        bytes.push(next_payload.as_u8());
        bytes.push(if *critical { 0x80 } else { 0 });
        bytes.extend_from_slice(&payload_len.to_be_bytes());
        bytes.extend_from_slice(body);
    }
    (first_payload, bytes)
}

fn notify_body(notify_message_type: u16, data: &[u8]) -> Vec<u8> {
    let mut body = vec![0, 0];
    body.extend_from_slice(&notify_message_type.to_be_bytes());
    body.extend_from_slice(data);
    body
}

fn assert_reply_decodes_and_correlates(
    addresses: &[Ikev2PcscfRestorationAddress],
    families: Ikev2PcscfRestorationAddressFamilies,
    attributes: &[(u16, &[u8])],
) {
    let request = must_ok(build_ikev2_pcscf_restoration_request(addresses));
    let (first_payload, bytes) = configuration_chain(CONFIGURATION_TYPE_REPLY, attributes);
    let response = must_ok(decode_ikev2_pcscf_restoration_response(
        &response_header(7),
        first_payload,
        &bytes,
    ));
    assert_eq!(response.address_families(), families);
    must_ok(validate_ikev2_pcscf_restoration_response_correlation(
        &request_header(7),
        &response_header(7),
        &request,
        &response,
    ));
}

#[test]
fn valued_requests_are_deterministic_sender_canonical_fixtures() {
    let fixtures = [
        (
            vec![
                Ikev2PcscfRestorationAddress::Ipv4(Ipv4Addr::new(192, 0, 2, 10)),
                Ikev2PcscfRestorationAddress::Ipv4(Ipv4Addr::new(198, 51, 100, 7)),
            ],
            Ikev2PcscfRestorationAddressFamilies::Ipv4,
            vec![
                0x00, 0x00, 0x00, 0x18, // generic CP header
                0x01, 0x00, 0x00, 0x00, // CFG_REQUEST and reserved bytes
                0x00, 0x14, 0x00, 0x04, // P_CSCF_IP4_ADDRESS
                0xc0, 0x00, 0x02, 0x0a, 0x00, 0x14, 0x00, 0x04, // second IPv4 attribute
                0xc6, 0x33, 0x64, 0x07,
            ],
        ),
        (
            vec![
                Ikev2PcscfRestorationAddress::Ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
                Ikev2PcscfRestorationAddress::Ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)),
            ],
            Ikev2PcscfRestorationAddressFamilies::Ipv6,
            vec![
                0x00, 0x00, 0x00, 0x30, // generic CP header
                0x01, 0x00, 0x00, 0x00, // CFG_REQUEST and reserved bytes
                0x00, 0x15, 0x00, 0x10, // P_CSCF_IP6_ADDRESS
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01, 0x00, 0x15, 0x00, 0x10, // second IPv6 attribute
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02,
            ],
        ),
        (
            vec![
                Ikev2PcscfRestorationAddress::Ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2)),
                Ikev2PcscfRestorationAddress::Ipv4(Ipv4Addr::new(198, 51, 100, 7)),
            ],
            Ikev2PcscfRestorationAddressFamilies::DualStack,
            vec![
                0x00, 0x00, 0x00, 0x24, // generic CP header
                0x01, 0x00, 0x00, 0x00, // CFG_REQUEST and reserved bytes
                0x00, 0x15, 0x00, 0x10, // P_CSCF_IP6_ADDRESS (input order)
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x02, 0x00, 0x14, 0x00, 0x04, // P_CSCF_IP4_ADDRESS
                0xc6, 0x33, 0x64, 0x07,
            ],
        ),
    ];

    for (addresses, families, expected) in fixtures {
        let request = must_ok(build_ikev2_pcscf_restoration_request(&addresses));
        assert_eq!(request.address_families(), families);
        assert_eq!(request.address_count(), addresses.len());
        assert_eq!(request.first_payload(), PayloadType::Configuration);
        assert_eq!(request.bytes().as_ref(), expected);
        assert!(PayloadChain::new(request.first_payload(), request.bytes())
            .validate_with_profile(
                DecodeContext::conservative(),
                Ikev2ValidationProfile::SenderCanonical,
            )
            .is_ok());
        let (retained, address_count, first_payload, bytes) = request.into_parts();
        assert_eq!(retained, families);
        assert_eq!(address_count, addresses.len());
        assert_eq!(first_payload, PayloadType::Configuration);
        assert_eq!(bytes.as_ref(), expected);
    }
}

#[test]
fn same_family_order_and_exact_repetitions_are_preserved() {
    let ipv4_a = Ikev2PcscfRestorationAddress::Ipv4(Ipv4Addr::new(192, 0, 2, 10));
    let ipv4_b = Ikev2PcscfRestorationAddress::Ipv4(Ipv4Addr::new(198, 51, 100, 7));
    let ipv6_a =
        Ikev2PcscfRestorationAddress::Ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
    let ipv6_b =
        Ikev2PcscfRestorationAddress::Ipv6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2));

    let forward_ipv4 = must_ok(build_ikev2_pcscf_restoration_request(&[ipv4_a, ipv4_b]));
    let reversed_ipv4 = must_ok(build_ikev2_pcscf_restoration_request(&[ipv4_b, ipv4_a]));
    assert_ne!(forward_ipv4.bytes(), reversed_ipv4.bytes());
    assert_eq!(
        reversed_ipv4.bytes().as_ref(),
        &[
            0x00, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x04, 0xc6, 0x33,
            0x64, 0x07, 0x00, 0x14, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x0a,
        ]
    );
    let forward_ipv6 = must_ok(build_ikev2_pcscf_restoration_request(&[ipv6_a, ipv6_b]));
    let reversed_ipv6 = must_ok(build_ikev2_pcscf_restoration_request(&[ipv6_b, ipv6_a]));
    assert_ne!(forward_ipv6.bytes(), reversed_ipv6.bytes());
    assert_eq!(
        reversed_ipv6.bytes().as_ref(),
        &[
            0x00, 0x00, 0x00, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x10, 0x20, 0x01,
            0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0x00, 0x15, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]
    );

    let repeated_ipv4 = must_ok(build_ikev2_pcscf_restoration_request(&[ipv4_a, ipv4_a]));
    assert_eq!(repeated_ipv4.address_count(), 2);
    assert_eq!(
        repeated_ipv4.bytes().as_ref(),
        &[
            0x00, 0x00, 0x00, 0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x04, 0xc0, 0x00,
            0x02, 0x0a, 0x00, 0x14, 0x00, 0x04, 0xc0, 0x00, 0x02, 0x0a,
        ]
    );
    let repeated_ipv6 = must_ok(build_ikev2_pcscf_restoration_request(&[ipv6_a, ipv6_a]));
    assert_eq!(repeated_ipv6.address_count(), 2);
    assert_eq!(
        repeated_ipv6.bytes().as_ref(),
        &[
            0x00, 0x00, 0x00, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x10, 0x20, 0x01,
            0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x15, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ]
    );
}

#[test]
fn ipv4_ipv6_and_dual_stack_replies_decode_and_correlate() {
    assert_reply_decodes_and_correlates(
        &[
            Ikev2PcscfRestorationAddress::Ipv4(Ipv4Addr::new(192, 0, 2, 10)),
            Ikev2PcscfRestorationAddress::Ipv4(Ipv4Addr::new(192, 0, 2, 10)),
        ],
        Ikev2PcscfRestorationAddressFamilies::Ipv4,
        &[(P_CSCF_IP4_ADDRESS, &[])],
    );
    assert_reply_decodes_and_correlates(
        &[Ikev2PcscfRestorationAddress::Ipv6(Ipv6Addr::LOCALHOST)],
        Ikev2PcscfRestorationAddressFamilies::Ipv6,
        &[(P_CSCF_IP6_ADDRESS, &[])],
    );
    assert_reply_decodes_and_correlates(
        &[
            Ikev2PcscfRestorationAddress::Ipv4(Ipv4Addr::new(198, 51, 100, 7)),
            Ikev2PcscfRestorationAddress::Ipv6(Ipv6Addr::LOCALHOST),
        ],
        Ikev2PcscfRestorationAddressFamilies::DualStack,
        &[(P_CSCF_IP6_ADDRESS, &[]), (P_CSCF_IP4_ADDRESS, &[])],
    );
}

#[test]
fn request_list_bounds_and_debug_are_safe() {
    assert_eq!(
        build_ikev2_pcscf_restoration_request(&[]),
        Err(Ikev2PcscfRestorationError::AddressListEmpty)
    );

    let excessive = (0..=IKEV2_PCSCF_RESTORATION_MAX_ADDRESSES)
        .map(|index| Ikev2PcscfRestorationAddress::Ipv6(Ipv6Addr::from(index as u128)))
        .collect::<Vec<_>>();
    let maximum = must_ok(build_ikev2_pcscf_restoration_request(
        &excessive[..IKEV2_PCSCF_RESTORATION_MAX_ADDRESSES],
    ));
    assert_eq!(
        maximum.address_count(),
        IKEV2_PCSCF_RESTORATION_MAX_ADDRESSES
    );
    assert_eq!(
        build_ikev2_pcscf_restoration_request(&excessive),
        Err(Ikev2PcscfRestorationError::AddressListTooLong {
            actual: IKEV2_PCSCF_RESTORATION_MAX_ADDRESSES + 1,
            maximum: IKEV2_PCSCF_RESTORATION_MAX_ADDRESSES,
        })
    );

    let first = Ikev2PcscfRestorationAddress::Ipv4(Ipv4Addr::new(192, 0, 2, 10));
    let second = Ikev2PcscfRestorationAddress::Ipv4(Ipv4Addr::new(198, 51, 100, 7));
    let request = must_ok(build_ikev2_pcscf_restoration_request(&[first, second]));
    assert_eq!(request.address_count(), 2);
    let address_debug = format!("{first:?}");
    let request_debug = format!("{request:?}");
    for forbidden in ["192.0.2.10", "198.51.100.7", "c000020a", "c6336407"] {
        assert!(!address_debug.contains(forbidden));
        assert!(!request_debug.contains(forbidden));
    }
    assert!(address_debug.contains("[REDACTED]"));
}

#[test]
fn network_receiver_ignores_rfc_reserved_fields() {
    let (first_payload, bytes) =
        configuration_chain(CONFIGURATION_TYPE_REPLY, &[(P_CSCF_IP4_ADDRESS, &[])]);
    let mut bytes = bytes.to_vec();
    bytes[1] = 0x7f;
    bytes[5..8].copy_from_slice(&[0xaa, 0xbb, 0xcc]);
    bytes[8] |= 0x80;

    let response = must_ok(decode_ikev2_pcscf_restoration_response(
        &response_header(7),
        first_payload,
        &bytes,
    ));
    assert_eq!(
        response.address_families(),
        Ikev2PcscfRestorationAddressFamilies::Ipv4
    );
    assert!(PayloadChain::new(first_payload, &bytes)
        .validate_with_profile(
            DecodeContext::conservative(),
            Ikev2ValidationProfile::SenderCanonical,
        )
        .is_err());
}

#[test]
fn interleaved_noncritical_extensions_are_retained_and_do_not_block_correlation() {
    let unsupported_a = [0xde, 0xad];
    let unsupported_b = [0xbe, 0xef, 0x01];
    let configuration = configuration_body(
        CONFIGURATION_TYPE_REPLY,
        &[
            (UNSUPPORTED_CONFIGURATION_ATTRIBUTE, &unsupported_a),
            (P_CSCF_IP4_ADDRESS, &[]),
            (UNSUPPORTED_CONFIGURATION_ATTRIBUTE + 1, &unsupported_b),
        ],
    );
    let status = notify_body(UNRECOGNIZED_STATUS_NOTIFY, &[0xa5, 0x5a]);
    let vendor_id = [0x11, 0x22, 0x33];
    let unknown_body = [0x44, 0x55, 0x66, 0x77];
    let (first_payload, bytes) = raw_payload_chain(&[
        (PayloadType::VendorId, false, &vendor_id),
        (PayloadType::Configuration, false, &configuration),
        (PayloadType::Unknown(250), false, &unknown_body),
        (PayloadType::Notify, false, &status),
    ]);

    let response = must_ok(decode_ikev2_pcscf_restoration_response(
        &response_header(7),
        first_payload,
        &bytes,
    ));
    assert_eq!(
        response.address_families(),
        Ikev2PcscfRestorationAddressFamilies::Ipv4
    );
    assert_eq!(response.unsupported_configuration_attributes().len(), 2);
    assert_eq!(
        response.unsupported_configuration_attributes()[0].attribute_type,
        UNSUPPORTED_CONFIGURATION_ATTRIBUTE
    );
    assert_eq!(
        response.unsupported_configuration_attributes()[0].value,
        unsupported_a
    );
    assert_eq!(
        response.unsupported_configuration_attributes()[1].attribute_type,
        UNSUPPORTED_CONFIGURATION_ATTRIBUTE + 1
    );
    assert_eq!(
        response.unsupported_configuration_attributes()[1].value,
        unsupported_b
    );
    assert_eq!(response.vendor_ids().len(), 1);
    assert_eq!(response.vendor_ids()[0].vendor_id, vendor_id);
    assert_eq!(response.unrecognized_notifies().len(), 1);
    assert_eq!(
        response.unrecognized_notifies()[0].notify_message_type,
        UNRECOGNIZED_STATUS_NOTIFY
    );
    assert_eq!(
        response.unrecognized_notifies()[0].notification_data,
        [0xa5, 0x5a]
    );
    assert_eq!(response.unknown_noncritical_payloads().len(), 1);
    assert_eq!(response.unknown_noncritical_payloads()[0].payload_type, 250);
    assert_eq!(
        response.unknown_noncritical_payloads()[0].body,
        unknown_body
    );

    let request = must_ok(build_ikev2_pcscf_restoration_request(&[
        Ikev2PcscfRestorationAddress::Ipv4(Ipv4Addr::new(192, 0, 2, 10)),
    ]));
    must_ok(validate_ikev2_pcscf_restoration_response_correlation(
        &request_header(7),
        &response_header(7),
        &request,
        &response,
    ));

    let debug = format!("{response:?}");
    for forbidden in ["dead", "beef", "a55a", "112233", "44556677"] {
        assert!(!debug.contains(forbidden));
    }
    assert!(debug.contains("unsupported_configuration_attribute_count: 2"));
    assert!(debug.contains("unknown_noncritical_payload_count: 1"));

    let dropped = must_ok(decode_ikev2_pcscf_restoration_response_with_context(
        &response_header(7),
        first_payload,
        &bytes,
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..DecodeContext::conservative()
        },
    ));
    assert!(dropped.unsupported_configuration_attributes().is_empty());
    assert!(dropped.unrecognized_notifies().is_empty());
    assert!(dropped.unknown_noncritical_payloads().is_empty());
    assert_eq!(dropped.vendor_ids().len(), 1);

    let reject_is_preserve = must_ok(decode_ikev2_pcscf_restoration_response_with_context(
        &response_header(7),
        first_payload,
        &bytes,
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..DecodeContext::conservative()
        },
    ));
    assert_eq!(
        reject_is_preserve
            .unsupported_configuration_attributes()
            .len(),
        2
    );
    assert_eq!(reject_is_preserve.unrecognized_notifies().len(), 1);
    assert_eq!(reject_is_preserve.unknown_noncritical_payloads().len(), 1);
    assert_eq!(reject_is_preserve.vendor_ids().len(), 1);
}

#[test]
fn unknown_critical_and_error_range_notify_payloads_fail_closed() {
    let configuration = configuration_body(CONFIGURATION_TYPE_REPLY, &[(P_CSCF_IP4_ADDRESS, &[])]);
    let critical_body = [0x44, 0x55];
    let (first_payload, bytes) = raw_payload_chain(&[
        (PayloadType::Configuration, false, &configuration),
        (PayloadType::Unknown(250), true, &critical_body),
    ]);
    assert_eq!(
        decode_ikev2_pcscf_restoration_response(&response_header(7), first_payload, &bytes,),
        Err(Ikev2PcscfRestorationError::UnknownCriticalPayload)
    );

    let error_notify = notify_body(ERROR_NOTIFY, &[]);
    let (first_payload, bytes) = raw_payload_chain(&[
        (PayloadType::Configuration, false, &configuration),
        (PayloadType::Notify, false, &error_notify),
    ]);
    assert_eq!(
        decode_ikev2_pcscf_restoration_response(&response_header(7), first_payload, &bytes,),
        Err(Ikev2PcscfRestorationError::PeerErrorNotify {
            notify_message_type: ERROR_NOTIFY,
            protocol_id: 0,
        })
    );
}

#[test]
fn known_pcscf_attributes_fail_closed_and_unsupported_attributes_are_preserved() {
    let header = response_header(7);
    let (first_payload, bytes) = configuration_chain(CONFIGURATION_TYPE_REPLY, &[]);
    assert_eq!(
        decode_ikev2_pcscf_restoration_response(&header, first_payload, &bytes),
        Err(Ikev2PcscfRestorationError::AddressFamilyMissing)
    );

    let (first_payload, bytes) = configuration_chain(
        CONFIGURATION_TYPE_REPLY,
        &[(P_CSCF_IP4_ADDRESS, &[192, 0, 2, 1])],
    );
    assert_eq!(
        decode_ikev2_pcscf_restoration_response(&header, first_payload, &bytes),
        Err(Ikev2PcscfRestorationError::AddressValueNotEmpty {
            family: Ikev2PcscfRestorationAddressFamilies::Ipv4,
            actual_len: 4,
        })
    );

    let (first_payload, bytes) = configuration_chain(
        CONFIGURATION_TYPE_REPLY,
        &[(P_CSCF_IP6_ADDRESS, &[0x20; 16])],
    );
    assert_eq!(
        decode_ikev2_pcscf_restoration_response(&header, first_payload, &bytes),
        Err(Ikev2PcscfRestorationError::AddressValueNotEmpty {
            family: Ikev2PcscfRestorationAddressFamilies::Ipv6,
            actual_len: 16,
        })
    );

    let (first_payload, bytes) = configuration_chain(
        CONFIGURATION_TYPE_REPLY,
        &[(P_CSCF_IP6_ADDRESS, &[]), (P_CSCF_IP6_ADDRESS, &[])],
    );
    assert_eq!(
        decode_ikev2_pcscf_restoration_response(&header, first_payload, &bytes),
        Err(Ikev2PcscfRestorationError::AddressFamilyDuplicate {
            family: Ikev2PcscfRestorationAddressFamilies::Ipv6,
        })
    );

    let unsupported_value = [0xde, 0xad, 0xbe, 0xef];
    let (first_payload, bytes) = configuration_chain(
        CONFIGURATION_TYPE_REPLY,
        &[
            (UNSUPPORTED_CONFIGURATION_ATTRIBUTE, &unsupported_value),
            (P_CSCF_IP4_ADDRESS, &[]),
        ],
    );
    let response = must_ok(decode_ikev2_pcscf_restoration_response(
        &header,
        first_payload,
        &bytes,
    ));
    assert_eq!(
        response.address_families(),
        Ikev2PcscfRestorationAddressFamilies::Ipv4
    );
    assert_eq!(response.unsupported_configuration_attributes().len(), 1);
    assert_eq!(
        response.unsupported_configuration_attributes()[0].attribute_type,
        UNSUPPORTED_CONFIGURATION_ATTRIBUTE
    );
    assert_eq!(
        response.unsupported_configuration_attributes()[0].value,
        unsupported_value
    );
    assert!(!format!("{response:?}").contains("deadbeef"));
}

#[test]
fn wrong_configuration_and_payload_cardinality_fail_closed() {
    let header = response_header(7);
    let (first_payload, bytes) = configuration_chain(1, &[(P_CSCF_IP4_ADDRESS, &[])]);
    assert_eq!(
        decode_ikev2_pcscf_restoration_response(&header, first_payload, &bytes),
        Err(Ikev2PcscfRestorationError::WrongConfigurationType {
            expected: CONFIGURATION_TYPE_REPLY,
            actual: 1,
        })
    );

    assert_eq!(
        decode_ikev2_pcscf_restoration_response(&header, PayloadType::NoNext, &[],),
        Err(Ikev2PcscfRestorationError::ConfigurationPayloadMissing)
    );

    let body = must_ok(build_ike_auth_configuration_payload(
        &Ikev2ConfigurationPayloadBuild {
            config_type: CONFIGURATION_TYPE_REPLY,
            attributes: vec![Ikev2ConfigurationAttributeBuild {
                attribute_type: P_CSCF_IP4_ADDRESS,
                value: Vec::new(),
            }],
        },
    ));
    let (first_payload, bytes) = must_ok(build_ike_auth_cleartext_payload_chain(&[
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Configuration,
            body: body.clone(),
        },
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Configuration,
            body,
        },
    ]));
    assert_eq!(
        decode_ikev2_pcscf_restoration_response(&header, first_payload, &bytes),
        Err(Ikev2PcscfRestorationError::ConfigurationPayloadDuplicate)
    );

    let (first_payload, bytes) = must_ok(build_ike_auth_cleartext_payload_chain(&[
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Notify,
            body: Vec::new(),
        },
    ]));
    assert_eq!(
        decode_ikev2_pcscf_restoration_response(&header, first_payload, &bytes),
        Err(Ikev2PcscfRestorationError::Notify(
            Ikev2NotifyPayloadError::BodyTooShort
        ))
    );

    let (first_payload, bytes) = must_ok(build_ike_auth_cleartext_payload_chain(&[
        Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Delete,
            body: Vec::new(),
        },
    ]));
    assert_eq!(
        decode_ikev2_pcscf_restoration_response(&header, first_payload, &bytes),
        Err(Ikev2PcscfRestorationError::UnexpectedPayloadType {
            actual: PayloadType::Delete,
        })
    );
}

#[test]
fn malformed_and_truncated_payloads_fail_closed() {
    let header = response_header(7);
    let cases: &[(PayloadType, &[u8])] = &[
        (PayloadType::Configuration, &[0x00, 0x00, 0x00]),
        (
            PayloadType::Configuration,
            &[0x00, 0x00, 0x00, 0x0c, 0x02, 0x00, 0x00, 0x00],
        ),
        (PayloadType::NoNext, &[0x00]),
    ];
    for (first_payload, bytes) in cases {
        assert_eq!(
            decode_ikev2_pcscf_restoration_response(&header, *first_payload, bytes),
            Err(Ikev2PcscfRestorationError::PayloadChain)
        );
    }

    let malformed_configuration_bodies: &[(&[u8], Ikev2IkeAuthPayloadError)] = &[
        (
            &[0x02, 0x00, 0x00],
            Ikev2IkeAuthPayloadError::ConfigurationTooShort,
        ),
        (
            &[0x02, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00],
            Ikev2IkeAuthPayloadError::ConfigurationAttributeTooShort,
        ),
        (
            &[
                0x02, 0x00, 0x00, 0x00, // CFG_REPLY
                0x00, 0x14, 0x00, 0x01, // claims a one-octet value
            ],
            Ikev2IkeAuthPayloadError::ConfigurationAttributeLengthExceedsBody,
        ),
    ];
    for (body, expected) in malformed_configuration_bodies {
        let (first_payload, bytes) = must_ok(build_ike_auth_cleartext_payload_chain(&[
            Ikev2IkeAuthPayloadBuild {
                payload_type: PayloadType::Configuration,
                body: body.to_vec(),
            },
        ]));
        assert_eq!(
            decode_ikev2_pcscf_restoration_response(&header, first_payload, &bytes),
            Err(Ikev2PcscfRestorationError::Payload(expected.clone()))
        );
    }

    let oversized = vec![0u8; DecodeContext::conservative().max_message_len + 1];
    assert_eq!(
        decode_ikev2_pcscf_restoration_response(&header, PayloadType::Configuration, &oversized,),
        Err(Ikev2PcscfRestorationError::MessageTooLarge {
            actual: oversized.len(),
            maximum: DecodeContext::conservative().max_message_len,
        })
    );
}

#[test]
fn family_and_header_correlation_mismatches_fail_closed() {
    let request = must_ok(build_ikev2_pcscf_restoration_request(&[
        Ikev2PcscfRestorationAddress::Ipv4(Ipv4Addr::new(192, 0, 2, 10)),
        Ikev2PcscfRestorationAddress::Ipv6(Ipv6Addr::LOCALHOST),
    ]));
    let (first_payload, bytes) =
        configuration_chain(CONFIGURATION_TYPE_REPLY, &[(P_CSCF_IP4_ADDRESS, &[])]);
    let response = must_ok(decode_ikev2_pcscf_restoration_response(
        &response_header(7),
        first_payload,
        &bytes,
    ));
    assert_eq!(
        validate_ikev2_pcscf_restoration_response_correlation(
            &request_header(7),
            &response_header(7),
            &request,
            &response,
        ),
        Err(Ikev2PcscfRestorationError::AddressFamiliesMismatch {
            expected: Ikev2PcscfRestorationAddressFamilies::DualStack,
            actual: Ikev2PcscfRestorationAddressFamilies::Ipv4,
        })
    );

    let mut mismatches = Vec::new();
    let mut wrong_message_id = response_header(8);
    mismatches.push(wrong_message_id.clone());
    wrong_message_id.message_id = 7;
    wrong_message_id.initiator_spi = 9;
    mismatches.push(wrong_message_id.clone());
    wrong_message_id.initiator_spi = request_header(7).initiator_spi;
    wrong_message_id.flags = HeaderFlags::from_bits(false, true, false);
    mismatches.push(wrong_message_id);

    let ipv4_request = must_ok(build_ikev2_pcscf_restoration_request(&[
        Ikev2PcscfRestorationAddress::Ipv4(Ipv4Addr::new(192, 0, 2, 10)),
    ]));
    for mismatched_header in mismatches {
        assert_eq!(
            validate_ikev2_pcscf_restoration_response_correlation(
                &request_header(7),
                &mismatched_header,
                &ipv4_request,
                &response,
            ),
            Err(Ikev2PcscfRestorationError::ResponseCorrelationMismatch)
        );
    }
}

#[test]
fn response_header_validation_is_strict_and_errors_are_stable() {
    let (first_payload, bytes) =
        configuration_chain(CONFIGURATION_TYPE_REPLY, &[(P_CSCF_IP4_ADDRESS, &[])]);
    let mut missing_response_flag = response_header(7);
    missing_response_flag.flags = HeaderFlags::from_bits(true, false, false);
    assert_eq!(
        decode_ikev2_pcscf_restoration_response(&missing_response_flag, first_payload, &bytes,),
        Err(Ikev2PcscfRestorationError::ResponseFlagMissing)
    );

    let mut wrong_exchange = response_header(7);
    wrong_exchange.exchange_type = EXCHANGE_TYPE_CREATE_CHILD_SA;
    assert_eq!(
        decode_ikev2_pcscf_restoration_response(&wrong_exchange, first_payload, &bytes),
        Err(Ikev2PcscfRestorationError::WrongExchangeType {
            actual: EXCHANGE_TYPE_CREATE_CHILD_SA,
        })
    );

    let mut zero_spi = response_header(7);
    zero_spi.responder_spi = 0;
    assert_eq!(
        decode_ikev2_pcscf_restoration_response(&zero_spi, first_payload, &bytes),
        Err(Ikev2PcscfRestorationError::IkeSpiZero)
    );

    let error = Ikev2PcscfRestorationError::AddressValueNotEmpty {
        family: Ikev2PcscfRestorationAddressFamilies::Ipv6,
        actual_len: 16,
    };
    assert_eq!(
        error.as_str(),
        "ikev2_pcscf_restoration_address_value_not_empty"
    );
    assert_eq!(format!("{error}"), error.as_str());
}
