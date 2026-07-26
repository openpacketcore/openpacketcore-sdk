use bytes::BytesMut;
use opc_proto_gtpv2c::{
    decode_typed_ie_sequence, encode_typed_ie_sequence, AdditionalProtocolConfigurationOptions,
    IpcpDnsRequest, PcoAddressConfiguration, PcoDecodeError, PcoRequest, PcscfAddressRequest,
    PcscfRequest, ProtocolConfigurationOptions, TypedIe, TypedIeValue, PCO_CONTAINER_IPV4_LINK_MTU,
    PCO_CONTAINER_P_CSCF_IPV4, PCO_CONTAINER_P_CSCF_IPV6, PCO_CONTAINER_P_CSCF_RESELECTION_SUPPORT,
    PCO_MAX_CONTAINERS, PCO_PROTOCOL_IPCP,
};
use opc_protocol::{DecodeContext, EncodeContext};

/// Every P-CSCF request the type can express, and the address containers each
/// one is required to carry.
const EVERY_PCSCF_REQUEST: [(PcscfAddressRequest, &[u16]); 3] = [
    (PcscfAddressRequest::Ipv4, &[PCO_CONTAINER_P_CSCF_IPV4]),
    (PcscfAddressRequest::Ipv6, &[PCO_CONTAINER_P_CSCF_IPV6]),
    (
        PcscfAddressRequest::Ipv4AndIpv6,
        &[PCO_CONTAINER_P_CSCF_IPV6, PCO_CONTAINER_P_CSCF_IPV4],
    ),
];

/// Collect the identifier of every length-delimited unit in an encoded
/// MS-to-network request, past the leading configuration-protocol octet.
fn container_identifiers(encoded: &[u8]) -> Vec<u16> {
    let mut identifiers = Vec::new();
    let mut remaining = &encoded[1..];
    while remaining.len() >= 3 {
        let identifier = u16::from_be_bytes([remaining[0], remaining[1]]);
        let end = 3 + usize::from(remaining[2]);
        identifiers.push(identifier);
        remaining = &remaining[end..];
    }
    assert!(remaining.is_empty(), "trailing octets in {encoded:02x?}");
    identifiers
}

#[test]
fn request_encoder_emits_zero_length_address_containers_in_registry_order() {
    assert!(PcoRequest::none().encode_request_contents().is_empty());

    let encoded = PcoRequest {
        p_cscf: Some(PcscfRequest::addresses(PcscfAddressRequest::Ipv4AndIpv6)),
        dns_server_ipv6: true,
        dns_server_ipv4: true,
        ipv4_link_mtu: false,
        ipcp_dns: IpcpDnsRequest::none(),
    }
    .encode_request_contents();
    assert_eq!(
        encoded,
        vec![0x80, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x0d, 0x00,]
    );
}

#[test]
fn pcscf_reselection_support_accompanies_each_address_request_family() {
    assert_eq!(PCO_CONTAINER_P_CSCF_RESELECTION_SUPPORT, 0x0012);

    // TS 24.008 10.5.6.3: "This PCO parameter may be present only if a
    // container with P-CSCF IPv4 Address Request or P-CSCF IPv6 Address
    // Request is present." Each accompanying form is legal, and 0x0012 is
    // still never implied by an address request on its own.
    let cases: [(PcscfAddressRequest, Vec<u8>, Vec<u8>); 3] = [
        (
            PcscfAddressRequest::Ipv4,
            vec![0x80, 0x00, 0x0c, 0x00],
            vec![0x80, 0x00, 0x0c, 0x00, 0x00, 0x12, 0x00],
        ),
        (
            PcscfAddressRequest::Ipv6,
            vec![0x80, 0x00, 0x01, 0x00],
            vec![0x80, 0x00, 0x01, 0x00, 0x00, 0x12, 0x00],
        ),
        (
            PcscfAddressRequest::Ipv4AndIpv6,
            vec![0x80, 0x00, 0x01, 0x00, 0x00, 0x0c, 0x00],
            vec![0x80, 0x00, 0x01, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x12, 0x00],
        ),
    ];

    for (addresses, without_support, with_support) in cases {
        let addresses_only = PcoRequest {
            p_cscf: Some(PcscfRequest::addresses(addresses)),
            ..PcoRequest::none()
        };
        assert!(addresses_only.is_requested());
        assert_eq!(
            addresses_only.encode_request_contents(),
            without_support,
            "{addresses:?} must not imply reselection support"
        );

        let supported = PcoRequest {
            p_cscf: Some(PcscfRequest::with_reselection_support(addresses)),
            ..PcoRequest::none()
        };
        assert!(supported.is_requested());
        assert_eq!(
            supported.encode_request_contents(),
            with_support,
            "{addresses:?} with reselection support"
        );
    }
}

#[test]
fn reselection_support_is_unrepresentable_without_a_p_cscf_address_request() {
    // The conditional-presence rule is enforced by the type, so the negative
    // case is a compile error rather than a runtime rejection: there is no
    // `PcscfAddressRequest` variant selecting neither family, and
    // `reselection_support` exists only inside `PcscfRequest`. This walks the
    // whole representable domain and proves the encoder never emits 0x0012
    // unaccompanied -- including alongside every other selectable parameter,
    // so no combination reintroduces the standalone container.
    for (addresses, expected_p_cscf) in EVERY_PCSCF_REQUEST {
        for reselection_support in [false, true] {
            for dns_server_ipv6 in [false, true] {
                for dns_server_ipv4 in [false, true] {
                    for ipv4_link_mtu in [false, true] {
                        let request = PcoRequest {
                            p_cscf: Some(PcscfRequest {
                                addresses,
                                reselection_support,
                            }),
                            dns_server_ipv6,
                            dns_server_ipv4,
                            ipv4_link_mtu,
                            ipcp_dns: IpcpDnsRequest::none(),
                        };
                        let identifiers = container_identifiers(&request.encode_request_contents());
                        let carries_support =
                            identifiers.contains(&PCO_CONTAINER_P_CSCF_RESELECTION_SUPPORT);
                        assert_eq!(carries_support, reselection_support, "{request:?}");
                        for identifier in expected_p_cscf {
                            assert!(
                                identifiers.contains(identifier),
                                "{identifier:#06x} missing from {request:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    // And with no P-CSCF request at all, 0x0012 cannot appear.
    for dns_server_ipv6 in [false, true] {
        for dns_server_ipv4 in [false, true] {
            for ipv4_link_mtu in [false, true] {
                let request = PcoRequest {
                    p_cscf: None,
                    dns_server_ipv6,
                    dns_server_ipv4,
                    ipv4_link_mtu,
                    ipcp_dns: IpcpDnsRequest::none(),
                };
                let encoded = request.encode_request_contents();
                if encoded.is_empty() {
                    continue;
                }
                let identifiers = container_identifiers(&encoded);
                assert!(
                    !identifiers.contains(&PCO_CONTAINER_P_CSCF_RESELECTION_SUPPORT),
                    "{request:?} emitted an unaccompanied 0x0012"
                );
            }
        }
    }
}

#[test]
fn reselection_support_orders_after_all_legacy_address_requests() {
    let encoded = PcoRequest {
        p_cscf: Some(PcscfRequest::with_reselection_support(
            PcscfAddressRequest::Ipv4AndIpv6,
        )),
        dns_server_ipv6: true,
        dns_server_ipv4: true,
        ipv4_link_mtu: false,
        ipcp_dns: IpcpDnsRequest::none(),
    }
    .encode_request_contents();
    assert_eq!(
        encoded,
        vec![
            0x80, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x0d, 0x00, 0x00,
            0x12, 0x00,
        ]
    );
}

#[test]
fn network_decoder_projects_ipv4_ipv6_and_repeated_addresses() {
    let p_cscf_v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dns_v6 = [
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
    ];
    let mut contents = vec![
        0x80, // extension bit + configuration protocol 000
        // Well-formed unit for a protocol this crate does not model (IPv6CP),
        // which TS 24.008 10.5.6.3 requires the receiver to ignore. This was
        // `0x8021` until IPCP became a supported identifier.
        0x80, 0x57, 0x02, 0xaa, 0xbb, 0x00, 0x01, 0x10,
    ];
    contents.extend_from_slice(&p_cscf_v6);
    contents.extend_from_slice(&[0x00, 0x03, 0x10]);
    contents.extend_from_slice(&dns_v6);
    contents.extend_from_slice(&[
        0x00, 0x0d, 0x04, 8, 8, 8, 8, // DNS IPv4
        0x00, 0x0c, 0x04, 198, 51, 100, 1, // P-CSCF IPv4
        0x00, 0x0c, 0x04, 198, 51, 100, 2, // repeated P-CSCF IPv4
    ]);

    let decoded =
        PcoAddressConfiguration::decode_network_contents(&contents).expect("well-formed PCO");
    assert_eq!(decoded.p_cscf_ipv6, vec![p_cscf_v6]);
    assert_eq!(decoded.dns_server_ipv6, vec![dns_v6]);
    assert_eq!(decoded.dns_server_ipv4, vec![[8, 8, 8, 8]]);
    assert_eq!(
        decoded.p_cscf_ipv4,
        vec![[198, 51, 100, 1], [198, 51, 100, 2]]
    );
    assert!(!decoded.is_empty());

    let debug = format!("{decoded:?}");
    assert!(debug.contains("p_cscf_ipv4_count: 2"));
    assert!(!debug.contains("198"));
    assert!(!debug.contains("2001"));
}

#[test]
fn network_decoder_fails_closed_on_malformed_boundaries() {
    let cases: &[(&[u8], PcoDecodeError)] = &[
        (&[], PcoDecodeError::Empty),
        (&[0x00], PcoDecodeError::UnsupportedHeader),
        (&[0x81], PcoDecodeError::UnsupportedHeader),
        (
            &[0x80, 0x00, 0x0d],
            PcoDecodeError::ContainerHeaderTruncated,
        ),
        (
            &[0x80, 0x00, 0x0d, 0x05, 8, 8, 8, 8],
            PcoDecodeError::ContainerLengthOverrun,
        ),
        (
            &[0x80, 0x00, 0x0d, 0x03, 8, 8, 8],
            PcoDecodeError::InvalidIpv4AddressLength,
        ),
        (
            &[
                0x80, 0x00, 0x01, 0x0f, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            PcoDecodeError::InvalidIpv6AddressLength,
        ),
    ];

    for (contents, expected) in cases {
        assert_eq!(
            PcoAddressConfiguration::decode_network_contents(contents),
            Err(*expected),
            "contents {contents:02x?}"
        );
        assert!(!expected.as_str().is_empty());
    }
}

#[test]
fn network_decoder_enforces_container_count_bound() {
    let mut contents = vec![0x80];
    for _ in 0..=PCO_MAX_CONTAINERS {
        // Unknown zero-length container: counted, but never interpreted, so
        // the bound is what rejects this rather than any per-unit rule.
        contents.extend_from_slice(&[0x00, 0xff, 0x00]);
    }

    assert_eq!(
        PcoAddressConfiguration::decode_network_contents(&contents),
        Err(PcoDecodeError::TooManyContainers)
    );
}

#[test]
fn pco_request_round_trips_through_opaque_gtpv2c_ie_transport() {
    let value = PcoRequest {
        p_cscf: Some(PcscfRequest::with_reselection_support(
            PcscfAddressRequest::Ipv4,
        )),
        dns_server_ipv6: false,
        dns_server_ipv4: true,
        ipv4_link_mtu: false,
        ipcp_dns: IpcpDnsRequest::none(),
    }
    .encode_request_contents();
    let pco = ProtocolConfigurationOptions {
        value: value.clone(),
    };
    let apco = AdditionalProtocolConfigurationOptions {
        value: value.clone(),
    };
    let ies = [
        TypedIe {
            instance: 0,
            value: TypedIeValue::ProtocolConfigurationOptions(pco.clone()),
        },
        TypedIe {
            instance: 0,
            value: TypedIeValue::AdditionalProtocolConfigurationOptions(apco.clone()),
        },
    ];
    let mut wire = BytesMut::new();
    encode_typed_ie_sequence(&ies, &mut wire, EncodeContext::default()).expect("encode PCO IE");
    let decoded =
        decode_typed_ie_sequence(&wire, DecodeContext::default(), 0).expect("decode PCO IE");

    assert_eq!(decoded.len(), 2);
    assert_eq!(
        decoded[0].value,
        TypedIeValue::ProtocolConfigurationOptions(pco)
    );
    assert_eq!(
        decoded[1].value,
        TypedIeValue::AdditionalProtocolConfigurationOptions(apco)
    );
    assert_eq!(
        value,
        vec![0x80, 0x00, 0x0c, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x12, 0x00]
    );
}

#[test]
fn ipcp_configure_request_precedes_containers_and_matches_the_observed_wire() {
    let encoded = PcoRequest {
        p_cscf: Some(PcscfRequest::addresses(PcscfAddressRequest::Ipv4AndIpv6)),
        dns_server_ipv6: true,
        dns_server_ipv4: true,
        ipv4_link_mtu: false,
        ipcp_dns: IpcpDnsRequest {
            primary_dns: true,
            secondary_dns: true,
            identifier: 0x2a,
        },
    }
    .encode_request_contents();

    // Derived from TS 24.008 10.5.6.3, RFC 1332/1661 and RFC 1877 rather than
    // from this encoder: the configuration protocol options list occupies
    // octets 4..w and the additional parameters list w+1..z, so the IPCP unit
    // is positionally ahead of every container.
    assert_eq!(
        encoded,
        vec![
            0x80, // extension bit + configuration protocol 000
            0x80, 0x21, // protocol identifier: IPCP
            0x10, // length of the protocol identifier contents: 16
            0x01, // Code: Configure-Request
            0x2a, // Identifier
            0x00, 0x10, // Length: RFC 1661 counts this header plus both options
            0x81, 0x06, 0x00, 0x00, 0x00, 0x00, // 129 Primary DNS, address requested
            0x83, 0x06, 0x00, 0x00, 0x00, 0x00, // 131 Secondary DNS, address requested
            0x00, 0x01, 0x00, // P-CSCF IPv6 request container
            0x00, 0x03, 0x00, // DNS Server IPv6 request container
            0x00, 0x0c, 0x00, // P-CSCF IPv4 request container
            0x00, 0x0d, 0x00, // DNS Server IPv4 request container
        ]
    );

    // Issue #558 observed an interoperating gateway sending exactly this: an
    // IPCP unit of length 16 alongside four container requests.
    assert_eq!(encoded[3], 16);
    assert_eq!(PCO_PROTOCOL_IPCP, 0x8021);
}

#[test]
fn each_ipcp_dns_option_is_independently_selectable() {
    let primary_only = PcoRequest {
        ipcp_dns: IpcpDnsRequest {
            primary_dns: true,
            ..IpcpDnsRequest::none()
        },
        ..PcoRequest::none()
    };
    assert!(primary_only.is_requested());
    assert_eq!(
        primary_only.encode_request_contents(),
        vec![0x80, 0x80, 0x21, 0x0a, 0x01, 0x00, 0x00, 0x0a, 0x81, 0x06, 0, 0, 0, 0]
    );

    let secondary_only = PcoRequest {
        ipcp_dns: IpcpDnsRequest {
            secondary_dns: true,
            identifier: 0xff,
            ..IpcpDnsRequest::none()
        },
        ..PcoRequest::none()
    };
    assert_eq!(
        secondary_only.encode_request_contents(),
        vec![0x80, 0x80, 0x21, 0x0a, 0x01, 0xff, 0x00, 0x0a, 0x83, 0x06, 0, 0, 0, 0]
    );
}

#[test]
fn an_identifier_alone_never_emits_an_ipcp_unit() {
    let identifier_only = PcoRequest {
        ipcp_dns: IpcpDnsRequest {
            identifier: 0x7f,
            ..IpcpDnsRequest::none()
        },
        ..PcoRequest::none()
    };
    assert!(!identifier_only.ipcp_dns.is_requested());
    assert!(!identifier_only.is_requested());
    assert!(identifier_only.encode_request_contents().is_empty());
}

#[test]
fn configure_nak_supplies_the_dns_addresses_the_request_asked_for() {
    let contents = vec![
        0x80, //
        0x80, 0x21, 0x10, // IPCP unit, contents length 16
        0x03, // Code: Configure-Nak
        0x2a, // Identifier echoed from the request
        0x00, 0x10, //
        0x81, 0x06, 8, 8, 8, 8, // 129 Primary DNS
        0x83, 0x06, 1, 1, 1, 1, // 131 Secondary DNS
    ];

    let decoded =
        PcoAddressConfiguration::decode_network_contents(&contents).expect("well-formed IPCP Nak");
    assert_eq!(decoded.ipcp_primary_dns, Some([8, 8, 8, 8]));
    assert_eq!(decoded.ipcp_secondary_dns, Some([1, 1, 1, 1]));
    assert!(decoded.dns_server_ipv4.is_empty());
    assert!(!decoded.is_empty());
    assert_eq!(
        decoded.dns_server_ipv4_all(),
        vec![[8, 8, 8, 8], [1, 1, 1, 1]]
    );
}

#[test]
fn only_a_configure_nak_is_read_for_addresses() {
    // RFC 1661 5.3: a Configure-Ack echoes the request's options verbatim, and
    // this crate always requests with the RFC 1877 all-zero address, so an Ack
    // conveys no server. A Reject conveys that the peer will not answer.
    for code in [0x01, 0x02, 0x04] {
        let contents = vec![
            0x80, 0x80, 0x21, 0x0a, code, 0x2a, 0x00, 0x0a, 0x81, 0x06, 8, 8, 8, 8,
        ];
        let decoded = PcoAddressConfiguration::decode_network_contents(&contents)
            .expect("non-Nak IPCP codes are accepted and ignored");
        assert_eq!(decoded.ipcp_primary_dns, None, "code {code:#04x}");
        assert!(decoded.is_empty(), "code {code:#04x}");
    }
}

#[test]
fn an_echoed_all_zero_address_is_not_treated_as_a_dns_server() {
    let contents = vec![
        0x80, 0x80, 0x21, 0x10, 0x03, 0x2a, 0x00, 0x10, //
        0x81, 0x06, 0, 0, 0, 0, // peer echoed the request encoding
        0x83, 0x06, 9, 9, 9, 9,
    ];

    let decoded = PcoAddressConfiguration::decode_network_contents(&contents).expect("well-formed");
    assert_eq!(decoded.ipcp_primary_dns, None);
    assert_eq!(decoded.ipcp_secondary_dns, Some([9, 9, 9, 9]));
    assert_eq!(decoded.dns_server_ipv4_all(), vec![[9, 9, 9, 9]]);
}

#[test]
fn a_repeated_ipcp_dns_option_keeps_the_first_address() {
    let contents = vec![
        0x80, 0x80, 0x21, 0x10, 0x03, 0x2a, 0x00, 0x10, //
        0x81, 0x06, 8, 8, 8, 8, //
        0x81, 0x06, 4, 4, 4, 4, // duplicate: ignored
    ];

    let decoded = PcoAddressConfiguration::decode_network_contents(&contents).expect("well-formed");
    assert_eq!(decoded.ipcp_primary_dns, Some([8, 8, 8, 8]));
}

#[test]
fn unknown_ipcp_options_are_skipped_without_failing_the_value() {
    let contents = vec![
        // Contents is 4 header + 6 + 6 + 2 = 18 octets.
        0x80, 0x80, 0x21, 0x12, 0x03, 0x2a, 0x00, 0x12, //
        0x03, 0x06, 0xc0, 0x00, 0x02, 0x01, // 3 IP-Address: not modelled
        0x81, 0x06, 8, 8, 8, 8, //
        0x02, 0x02, // 2 IP-Compression-Protocol, minimum length
    ];

    let decoded = PcoAddressConfiguration::decode_network_contents(&contents).expect("well-formed");
    assert_eq!(decoded.ipcp_primary_dns, Some([8, 8, 8, 8]));
}

#[test]
fn ipcp_addresses_merge_with_container_addresses_without_duplication() {
    let contents = vec![
        0x80, //
        0x80, 0x21, 0x10, 0x03, 0x2a, 0x00, 0x10, //
        0x81, 0x06, 8, 8, 8, 8, // also supplied as a container below
        0x83, 0x06, 1, 1, 1, 1, //
        0x00, 0x0d, 0x04, 8, 8, 8, 8, // DNS Server IPv4 container
        0x00, 0x0d, 0x04, 9, 9, 9, 9,
    ];

    let decoded = PcoAddressConfiguration::decode_network_contents(&contents).expect("well-formed");
    assert_eq!(decoded.dns_server_ipv4, vec![[8, 8, 8, 8], [9, 9, 9, 9]]);
    assert_eq!(decoded.ipcp_primary_dns, Some([8, 8, 8, 8]));
    // Containers keep wire order and lead; the IPCP addresses follow, and the
    // address supplied by both mechanisms appears once.
    assert_eq!(
        decoded.dns_server_ipv4_all(),
        vec![[8, 8, 8, 8], [9, 9, 9, 9], [1, 1, 1, 1]]
    );
}

#[test]
fn ipcp_addresses_stay_out_of_debug_output() {
    let contents = vec![
        0x80, 0x80, 0x21, 0x10, 0x03, 0x2a, 0x00, 0x10, //
        0x81, 0x06, 203, 0, 113, 53, //
        0x83, 0x06, 198, 51, 100, 53,
    ];

    let decoded = PcoAddressConfiguration::decode_network_contents(&contents).expect("well-formed");
    let debug = format!("{decoded:?}");
    assert!(debug.contains("ipcp_primary_dns_present: true"));
    assert!(debug.contains("ipcp_secondary_dns_present: true"));
    for octet in ["203", "113", "198", "51", "100"] {
        assert!(!debug.contains(octet), "{octet} leaked into {debug}");
    }
}

#[test]
fn malformed_ipcp_units_fail_closed() {
    let cases: &[(&[u8], PcoDecodeError)] = &[
        // Unit contents shorter than the RFC 1661 four-octet header.
        (
            &[0x80, 0x80, 0x21, 0x02, 0xaa, 0xbb],
            PcoDecodeError::IpcpHeaderTruncated,
        ),
        // Length below the header size.
        (
            &[0x80, 0x80, 0x21, 0x04, 0x03, 0x2a, 0x00, 0x03],
            PcoDecodeError::IpcpLengthInvalid,
        ),
        // Length beyond the unit contents.
        (
            &[0x80, 0x80, 0x21, 0x04, 0x03, 0x2a, 0x00, 0x40],
            PcoDecodeError::IpcpLengthInvalid,
        ),
        // Option header cut short by the declared IPCP length.
        (
            &[0x80, 0x80, 0x21, 0x05, 0x03, 0x2a, 0x00, 0x05, 0x81],
            PcoDecodeError::IpcpOptionTruncated,
        ),
        // Option length below the two-octet minimum.
        (
            &[0x80, 0x80, 0x21, 0x06, 0x03, 0x2a, 0x00, 0x06, 0x81, 0x01],
            PcoDecodeError::IpcpOptionLengthInvalid,
        ),
        // Option length beyond the remaining options.
        (
            &[0x80, 0x80, 0x21, 0x06, 0x03, 0x2a, 0x00, 0x06, 0x81, 0x06],
            PcoDecodeError::IpcpOptionLengthInvalid,
        ),
        // A DNS option that is well-formed but not four address octets.
        (
            &[
                0x80, 0x80, 0x21, 0x09, 0x03, 0x2a, 0x00, 0x09, 0x81, 0x05, 8, 8, 8,
            ],
            PcoDecodeError::IpcpDnsOptionLengthInvalid,
        ),
    ];

    for (contents, expected) in cases {
        assert_eq!(
            PcoAddressConfiguration::decode_network_contents(contents),
            Err(*expected),
            "contents {contents:02x?}"
        );
        assert!(expected.as_str().starts_with("pco_ipcp_"));
    }
}

#[test]
fn a_request_and_its_configure_nak_answer_complete_the_dns_exchange() {
    let request = PcoRequest {
        dns_server_ipv4: true,
        ipcp_dns: IpcpDnsRequest {
            primary_dns: true,
            secondary_dns: true,
            identifier: 0x11,
        },
        ..PcoRequest::none()
    }
    .encode_request_contents();

    // The peer answers the IPCP unit and ignores the container request, which
    // is the interoperability case this exists for.
    let identifier = request[5];
    let answer = vec![
        0x80, 0x80, 0x21, 0x10, 0x03, identifier, 0x00, 0x10, //
        0x81, 0x06, 8, 8, 4, 4, //
        0x83, 0x06, 8, 8, 8, 8,
    ];

    let decoded = PcoAddressConfiguration::decode_network_contents(&answer).expect("well-formed");
    assert!(decoded.dns_server_ipv4.is_empty());
    assert_eq!(
        decoded.dns_server_ipv4_all(),
        vec![[8, 8, 4, 4], [8, 8, 8, 8]],
        "a caller reading only dns_server_ipv4 would have no DNS at all"
    );
}

#[test]
fn an_ipcp_request_survives_the_apco_transport_used_on_s2b() {
    // TS 29.274 8.104 carries this structure as the APCO IE, which is the
    // interface issue #558 names. The transport stays opaque, so the IPCP unit
    // has to arrive byte-identical.
    let value = PcoRequest {
        dns_server_ipv4: true,
        ipcp_dns: IpcpDnsRequest {
            primary_dns: true,
            secondary_dns: true,
            identifier: 0x5a,
        },
        ..PcoRequest::none()
    }
    .encode_request_contents();
    let apco = AdditionalProtocolConfigurationOptions {
        value: value.clone(),
    };
    let ies = [TypedIe {
        instance: 0,
        value: TypedIeValue::AdditionalProtocolConfigurationOptions(apco),
    }];

    let mut wire = BytesMut::new();
    encode_typed_ie_sequence(&ies, &mut wire, EncodeContext::default()).expect("encode APCO IE");
    let decoded =
        decode_typed_ie_sequence(&wire, DecodeContext::default(), 0).expect("decode APCO IE");
    let TypedIeValue::AdditionalProtocolConfigurationOptions(round_tripped) = &decoded[0].value
    else {
        panic!("expected an APCO IE");
    };
    assert_eq!(round_tripped.value, value);
    assert_eq!(&value[1..4], &[0x80, 0x21, 0x10]);
}

#[test]
fn link_mtu_request_is_an_empty_container_ordered_by_identifier() {
    assert_eq!(PCO_CONTAINER_IPV4_LINK_MTU, 0x0010);

    let mtu_only = PcoRequest {
        ipv4_link_mtu: true,
        ..PcoRequest::none()
    };
    assert!(mtu_only.is_requested());
    // TS 24.008 10.5.6.3: MS to network the container is zero-length.
    assert_eq!(
        mtu_only.encode_request_contents(),
        vec![0x80, 0x00, 0x10, 0x00]
    );

    // 0x0010 sorts after the DNS/P-CSCF containers and before 0x0012. The
    // P-CSCF address request is what makes 0x0012 legal here at all, per TS
    // 24.008 10.5.6.3, and it extends the ordering assertion by one identifier.
    let with_neighbours = PcoRequest {
        p_cscf: Some(PcscfRequest::with_reselection_support(
            PcscfAddressRequest::Ipv4,
        )),
        dns_server_ipv4: true,
        ipv4_link_mtu: true,
        ..PcoRequest::none()
    };
    assert_eq!(
        with_neighbours.encode_request_contents(),
        vec![0x80, 0x00, 0x0c, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x10, 0x00, 0x00, 0x12, 0x00]
    );
}

#[test]
fn network_supplied_link_mtu_decodes_as_two_octets() {
    // 1358 = 0x054e, the value TS 24.008 NOTE 1 recommends as a maximum for
    // the sibling non-IP container.
    let decoded =
        PcoAddressConfiguration::decode_network_contents(&[0x80, 0x00, 0x10, 0x02, 0x05, 0x4e])
            .expect("well-formed link MTU");
    assert_eq!(decoded.ipv4_link_mtu, Some(1358));
    // is_empty() asks about addresses; an MTU-only value is still empty, so a
    // caller's configured-DNS fallback still fires.
    assert!(decoded.is_empty());
    assert!(format!("{decoded:?}").contains("ipv4_link_mtu: Some(1358)"));

    let boundary =
        PcoAddressConfiguration::decode_network_contents(&[0x80, 0x00, 0x10, 0x02, 0xff, 0xff])
            .expect("well-formed");
    assert_eq!(boundary.ipv4_link_mtu, Some(u16::MAX));
}

#[test]
fn a_link_mtu_container_of_the_wrong_length_is_ignored_not_rejected() {
    // TS 24.008 10.5.6.3: "If the length of container identifier contents is
    // different from two octets, then it shall be ignored by the receiver."
    // This is deliberately unlike the address containers, which fail closed.
    for contents in [
        &[0x80, 0x00, 0x10, 0x00][..],
        &[0x80, 0x00, 0x10, 0x01, 0x05][..],
        &[0x80, 0x00, 0x10, 0x03, 0x05, 0x4e, 0x00][..],
    ] {
        let decoded = PcoAddressConfiguration::decode_network_contents(contents)
            .expect("a wrong-length link MTU is ignored, not an error");
        assert_eq!(decoded.ipv4_link_mtu, None, "contents {contents:02x?}");
        assert!(decoded.is_empty());
    }

    // A wrong-length instance must not discard a later well-formed one, and
    // must not stop the rest of the value being parsed.
    let decoded = PcoAddressConfiguration::decode_network_contents(&[
        0x80, 0x00, 0x10, 0x01, 0x05, // ignored
        0x00, 0x10, 0x02, 0x05, 0xdc, // 1500
        0x00, 0x0d, 0x04, 8, 8, 8, 8,
    ])
    .expect("well-formed");
    assert_eq!(decoded.ipv4_link_mtu, Some(1500));
    assert_eq!(decoded.dns_server_ipv4, vec![[8, 8, 8, 8]]);
}

#[test]
fn a_repeated_link_mtu_container_keeps_the_first() {
    let decoded = PcoAddressConfiguration::decode_network_contents(&[
        0x80, 0x00, 0x10, 0x02, 0x05, 0xdc, // 1500
        0x00, 0x10, 0x02, 0x02, 0x00, // 512, ignored
    ])
    .expect("well-formed");
    assert_eq!(decoded.ipv4_link_mtu, Some(1500));
}

#[test]
fn a_received_unaccompanied_reselection_support_container_is_ignored() {
    // TS 24.008 10.5.6.3 lists 0012H as Reserved in the network-to-MS
    // direction this decoder models, and states: "If the additional parameters
    // list contains a container identifier that is not supported by the
    // receiving entity the corresponding unit shall be ignored." The
    // conditional-presence rule constrains the sender and assigns the receiver
    // no behaviour, so a peer that breaks it must not cost the caller the
    // addresses carried in the same value.
    let decoded = PcoAddressConfiguration::decode_network_contents(&[
        0x80, 0x00, 0x12, 0x00, // no 0x0001 or 0x000c anywhere in the value
        0x00, 0x0d, 0x04, 8, 8, 8, 8,
    ])
    .expect("an unsupported container is ignored, not an error");
    assert_eq!(decoded.dns_server_ipv4, vec![[8, 8, 8, 8]]);
    assert!(!decoded.is_empty());

    // Accompanied, and with the non-empty contents 10.5.6.3 also says to
    // ignore: still projects nothing of its own, still not an error.
    let decoded = PcoAddressConfiguration::decode_network_contents(&[
        0x80, 0x00, 0x0c, 0x04, 198, 51, 100, 1, //
        0x00, 0x12, 0x01, 0xff,
    ])
    .expect("well-formed framing");
    assert_eq!(decoded.p_cscf_ipv4, vec![[198, 51, 100, 1]]);
}

#[test]
fn a_wrong_length_address_container_still_fails_closed() {
    // The ignore rule is specific to the link MTU: TS 24.008 states no such
    // rule for the address containers, so those keep rejecting the value.
    assert_eq!(
        PcoAddressConfiguration::decode_network_contents(&[0x80, 0x00, 0x0d, 0x03, 8, 8, 8]),
        Err(PcoDecodeError::InvalidIpv4AddressLength)
    );
}

#[test]
fn an_unusable_link_mtu_is_not_surfaced() {
    // RFC 791 requires every internet module to forward a 68-octet datagram,
    // so nothing below that is a link MTU. Surfacing one lets a caller that
    // applies it blackhole the user plane.
    for (mtu, octets) in [
        (0u16, [0x00, 0x00]),
        (1, [0x00, 0x01]),
        (28, [0x00, 0x1c]),
        (67, [0x00, 0x43]),
    ] {
        let decoded = PcoAddressConfiguration::decode_network_contents(&[
            0x80, 0x00, 0x10, 0x02, octets[0], octets[1],
        ])
        .expect("a wrong value is ignored, not an error");
        assert_eq!(
            decoded.ipv4_link_mtu, None,
            "mtu {mtu} must not be surfaced"
        );
        assert!(decoded.is_empty());
    }

    // The RFC 791 minimum itself is usable and must survive.
    let decoded =
        PcoAddressConfiguration::decode_network_contents(&[0x80, 0x00, 0x10, 0x02, 0x00, 0x44])
            .expect("well-formed");
    assert_eq!(decoded.ipv4_link_mtu, Some(68));

    // An unusable first instance must not shadow a usable later one.
    let decoded = PcoAddressConfiguration::decode_network_contents(&[
        0x80, 0x00, 0x10, 0x02, 0x00, 0x00, 0x00, 0x10, 0x02, 0x05, 0xdc,
    ])
    .expect("well-formed");
    assert_eq!(decoded.ipv4_link_mtu, Some(1500));
}

#[test]
fn an_mtu_only_value_still_reports_empty_for_the_dns_fallback() {
    // Regression for the predicate contract: `if cfg.is_empty() { use
    // configured DNS }` must still fire when the peer sent only an MTU.
    let decoded =
        PcoAddressConfiguration::decode_network_contents(&[0x80, 0x00, 0x10, 0x02, 0x05, 0xdc])
            .expect("well-formed");
    assert_eq!(decoded.ipv4_link_mtu, Some(1500));
    assert!(decoded.is_empty());
    assert!(decoded.dns_server_ipv4_all().is_empty());
}
