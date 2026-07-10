use bytes::BytesMut;
use opc_proto_gtpv2c::{
    decode_typed_ie_sequence, encode_typed_ie_sequence, PcoAddressConfiguration, PcoDecodeError,
    PcoRequest, ProtocolConfigurationOptions, TypedIe, TypedIeValue, PCO_MAX_CONTAINERS,
};
use opc_protocol::{DecodeContext, EncodeContext};

#[test]
fn request_encoder_emits_zero_length_address_containers_in_registry_order() {
    assert!(PcoRequest::none().encode_request_contents().is_empty());

    let encoded = PcoRequest {
        p_cscf_ipv6: true,
        dns_server_ipv6: true,
        p_cscf_ipv4: true,
        dns_server_ipv4: true,
    }
    .encode_request_contents();
    assert_eq!(
        encoded,
        vec![0x80, 0x00, 0x01, 0x00, 0x00, 0x03, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x0d, 0x00,]
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
        0x80, 0x21, 0x02, 0xaa, 0xbb, // well-formed unknown IPCP: skipped
        0x00, 0x01, 0x10,
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
        contents.extend_from_slice(&[0x80, 0x21, 0x00]);
    }

    assert_eq!(
        PcoAddressConfiguration::decode_network_contents(&contents),
        Err(PcoDecodeError::TooManyContainers)
    );
}

#[test]
fn pco_request_round_trips_through_opaque_gtpv2c_ie_transport() {
    let value = PcoRequest {
        p_cscf_ipv6: false,
        dns_server_ipv6: false,
        p_cscf_ipv4: true,
        dns_server_ipv4: true,
    }
    .encode_request_contents();
    let pco = ProtocolConfigurationOptions {
        value: value.clone(),
    };
    let ies = [TypedIe {
        instance: 0,
        value: TypedIeValue::ProtocolConfigurationOptions(pco.clone()),
    }];
    let mut wire = BytesMut::new();
    encode_typed_ie_sequence(&ies, &mut wire, EncodeContext::default()).expect("encode PCO IE");
    let decoded =
        decode_typed_ie_sequence(&wire, DecodeContext::default(), 0).expect("decode PCO IE");

    assert_eq!(decoded.len(), 1);
    assert_eq!(
        decoded[0].value,
        TypedIeValue::ProtocolConfigurationOptions(pco)
    );
    assert_eq!(value, vec![0x80, 0x00, 0x0c, 0x00, 0x00, 0x0d, 0x00]);
}
