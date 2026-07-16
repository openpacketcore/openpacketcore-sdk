use std::{collections::BTreeSet, net::Ipv4Addr};

use bytes::{Bytes, BytesMut};
use opc_proto_tft::{
    AuthorizationToken, FlowIdentifier, PacketFilter, PacketFilterComponent, PacketFilterDirection,
    PacketFilterIdentifier, PacketFilterIdentifierList, PacketFilterList, TftErrorKind,
    TftOperation, TftParameter, TrafficFlowTemplate, UnknownTftParameter,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, Encode, EncodeContext, EncodeErrorCode, OwnedDecode,
};

// TS 24.008 V18.8.0 table 10.5.162 and figure 10.5.144b:
// 0x21 = Create New, E=0, one filter; 0x31 = bidirectional/id 1;
// precedence 0x20; content length 2; component 0x30 with value 0x11.
const CREATE_PROTOCOL_FILTER: &[u8] = &[0x21, 0x31, 0x20, 0x02, 0x30, 0x11];

// TS 24.008 table 10.5.162 valid operation/list forms. The full-filter
// entries reuse the independently authored component bytes above.
const IGNORE: &[u8] = &[0x00];
const DELETE_EXISTING: &[u8] = &[0x40];
const DELETE_EXISTING_WITH_PARAMETERS: &[u8] = &[0x50, 0xfe, 0x01, 0xaa];
const ADD_PROTOCOL_FILTER: &[u8] = &[0x61, 0x31, 0x20, 0x02, 0x30, 0x11];
const REPLACE_PROTOCOL_FILTER: &[u8] = &[0x81, 0x31, 0x20, 0x02, 0x30, 0x11];
const DELETE_FILTERS: &[u8] = &[0xa2, 0x01, 0x02];
// 0xd0 = No TFT operation, E=1, count=0; unsupported parameter 0xfe is
// preserved under the clause 10.5.6.12 unsupported-parameter rule.
const NO_OPERATION: &[u8] = &[0xd0, 0xfe, 0x01, 0xaa];

// TS 24.008 figures 10.5.144b/c: Create/E/one filter followed by an
// Authorization Token, two Flow Identifiers, Packet Filter Identifiers, and
// an unsupported parameter. Token/unknown bytes are fixture-only test data.
const CREATE_WITH_PARAMETERS: &[u8] = &[
    0x31, // Create New, E=1, one packet filter
    0x31, 0x20, 0x02, 0x30, 0x11, // bidirectional id1, precedence, protocol 17
    0x01, 0x02, 0xaa, 0xbb, // Authorization Token
    0x02, 0x04, 0x00, 0x01, 0x00, 0x02, // Flow Identifier (1, 2)
    0x02, 0x04, 0x00, 0x01, 0x00, 0x03, // Flow Identifier (1, 3)
    0x03, 0x02, 0x01, 0x02, // Packet Filter Identifiers 1 and 2
    0xfe, 0x03, 0xde, 0xad, 0xbe, // permitted unsupported parameter
];

// TS 24.008 table 10.5.162 component IDs and fixed widths. This is TS 23.060
// table-12 combination I plus Ethernet classifiers and IPv4 EtherType.
const IPV4_AND_ETHERNET_COMPONENTS: &[u8] = &[
    0x21, 0x31, 0x10, 0x38, // Create, id1/bidir, precedence, 56 content octets
    0x10, 0xc0, 0x00, 0x02, 0x01, 0xff, 0xff, 0xff, 0x00, // IPv4 remote/mask
    0x11, 0xc6, 0x33, 0x64, 0x0a, 0xff, 0xff, 0xff, 0xff, // IPv4 local/mask
    0x30, 0x11, // UDP protocol identifier
    0x40, 0x13, 0x88, // single local port 5000
    0x50, 0x01, 0xbb, // single remote port 443
    0x70, 0x2e, 0xfc, // ToS value/mask
    0x81, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // destination MAC
    0x82, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // source MAC
    0x83, 0x01, 0x23, // C-TAG VID
    0x84, 0x04, 0x56, // S-TAG VID
    0x85, 0x0b, // C-TAG PCP 5, DEI 1
    0x86, 0x06, // S-TAG PCP 3, DEI 0
    0x87, 0x08, 0x00, // IPv4 EtherType
];

// Alternate TS 23.060 table-12 combination-I port-range encodings.
const PORT_RANGE_COMPONENTS: &[u8] = &[
    0x21, 0x32, 0x11, 0x0f, // Create, id2/bidir, precedence, 15 content octets
    0x41, 0x03, 0xe8, 0x07, 0xd0, // local range 1000..2000
    0x51, 0x13, 0x88, 0x17, 0x70, // remote range 5000..6000
    0x30, 0x06, // TCP protocol identifier
    0x70, 0x00, 0xff, // traffic class value/mask
];

// TS 23.060 table-12 combination II: IPv6 address attributes, next header,
// IPsec SPI and traffic class. EtherType is IPv6.
const IPV6_MASK_PREFIX_AND_SPI_COMPONENTS: &[u8] = &[
    0x21, 0x33, 0x12, 0x40, // Create, id3/bidir, precedence, 64 content octets
    0x20, // IPv6 remote address and mask
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x23, // IPv6 local address/prefix
    0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x40, // /64
    0x30, 0x32, // ESP next header
    0x60, 0x12, 0x34, 0x56, 0x78, // IPsec SPI
    0x70, 0x20, 0xf0, // traffic class value/mask
    0x87, 0x86, 0xdd, // IPv6 EtherType
];

// TS 23.060 table-12 combination III: IPv6 remote prefix, traffic class and
// flow label. The 20-bit flow label's high spare nibble is zero.
const IPV6_PREFIX_AND_FLOW_LABEL_COMPONENTS: &[u8] = &[
    0x21, 0x34, 0x13, 0x1c, // Create, id4/bidir, precedence, 28 content octets
    0x21, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x30, // IPv6 remote /48
    0x80, 0x0a, 0xbc, 0xde, // flow label 0xabcde
    0x70, 0x30, 0xf0, // traffic class value/mask
    0x87, 0x86, 0xdd, // IPv6 EtherType
];

fn assert_fixture_roundtrip(bytes: &[u8]) -> TrafficFlowTemplate {
    let decoded = TrafficFlowTemplate::decode_value(bytes).expect("spec fixture must decode");
    let mut encoded = BytesMut::new();
    decoded
        .encode_value(&mut encoded)
        .expect("decoded fixture must encode");
    assert_eq!(encoded.as_ref(), bytes);
    assert_eq!(decoded.encoded_value_len().expect("length"), bytes.len());
    decoded
}

fn identifier(value: u8) -> PacketFilterIdentifier {
    PacketFilterIdentifier::new(value).expect("test identifier is valid")
}

fn simple_filter(identifier_value: u8, precedence: u8) -> PacketFilter {
    PacketFilter::new(
        identifier(identifier_value),
        PacketFilterDirection::Bidirectional,
        precedence,
        vec![PacketFilterComponent::ProtocolIdentifierNextHeader(17)],
    )
    .expect("test filter is valid")
}

#[test]
fn every_tft_operation_has_a_spec_authored_roundtrip_fixture() {
    let cases = [
        (IGNORE, TftOperation::Ignore),
        (CREATE_PROTOCOL_FILTER, TftOperation::CreateNew),
        (DELETE_EXISTING, TftOperation::DeleteExisting),
        (ADD_PROTOCOL_FILTER, TftOperation::AddPacketFilters),
        (REPLACE_PROTOCOL_FILTER, TftOperation::ReplacePacketFilters),
        (DELETE_FILTERS, TftOperation::DeletePacketFilters),
        (NO_OPERATION, TftOperation::NoOperation),
    ];
    for (fixture, expected_operation) in cases {
        let value = assert_fixture_roundtrip(fixture);
        assert_eq!(value.operation(), expected_operation);
    }
}

#[test]
fn all_release_18_component_types_decode_and_roundtrip() {
    let fixtures = [
        IPV4_AND_ETHERNET_COMPONENTS,
        PORT_RANGE_COMPONENTS,
        IPV6_MASK_PREFIX_AND_SPI_COMPONENTS,
        IPV6_PREFIX_AND_FLOW_LABEL_COMPONENTS,
    ];
    let mut observed = BTreeSet::new();
    for fixture in fixtures {
        let value = assert_fixture_roundtrip(fixture);
        let filters = value
            .packet_filters()
            .filters()
            .expect("component fixture carries full filters");
        for filter in filters {
            observed.extend(
                filter
                    .components()
                    .iter()
                    .map(|component| component.kind().type_code()),
            );
        }
    }
    assert_eq!(
        observed,
        BTreeSet::from([
            0x10, 0x11, 0x20, 0x21, 0x23, 0x30, 0x40, 0x41, 0x50, 0x51, 0x60, 0x70, 0x80, 0x81,
            0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        ])
    );
}

#[test]
fn every_direction_encoding_and_the_maximum_filter_count_roundtrip() {
    let directions = [
        PacketFilterDirection::PreRelease7,
        PacketFilterDirection::DownlinkOnly,
        PacketFilterDirection::UplinkOnly,
        PacketFilterDirection::Bidirectional,
    ];
    for (identifier_value, direction) in directions.into_iter().enumerate() {
        let identifier_value = u8::try_from(identifier_value).expect("four directions fit in u8");
        let filter = PacketFilter::new(
            identifier(identifier_value),
            direction,
            identifier_value,
            vec![PacketFilterComponent::ProtocolIdentifierNextHeader(17)],
        )
        .expect("direction fixture");
        let value = TrafficFlowTemplate::create_new(vec![filter], Vec::new())
            .expect("single direction filter");
        let mut encoded = BytesMut::new();
        value.encode_value(&mut encoded).expect("encode direction");
        assert_eq!(
            TrafficFlowTemplate::decode_value(&encoded),
            Ok(value),
            "direction {direction:?}"
        );
    }

    let filters = (0..15)
        .map(|value| simple_filter(value, value))
        .collect::<Vec<_>>();
    let value = TrafficFlowTemplate::create_new(filters, Vec::new()).expect("15 filters fit");
    let mut encoded = BytesMut::new();
    value.encode_value(&mut encoded).expect("encode 15 filters");
    assert_eq!(TrafficFlowTemplate::decode_value(&encoded), Ok(value));
}

#[test]
fn e_bit_parameter_list_is_typed_ordered_and_unknown_preserving() {
    let value = assert_fixture_roundtrip(CREATE_WITH_PARAMETERS);
    assert_eq!(value.parameters().len(), 5);
    assert!(matches!(
        value.parameters().first(),
        Some(TftParameter::AuthorizationToken(_))
    ));
    assert!(matches!(
        value.parameters().last(),
        Some(TftParameter::Unknown(_))
    ));
}

#[test]
fn ignore_operation_preserves_specifically_ignored_contents() {
    let fixture = [0x00, 0xde, 0xad, 0xbe, 0xef];
    let value = assert_fixture_roundtrip(&fixture);
    assert_eq!(value.ignored_contents(), &[0xde, 0xad, 0xbe, 0xef]);
}

#[test]
fn framework_traits_use_the_same_strict_codec() {
    let context = DecodeContext::conservative();
    let (tail, borrowed) =
        <TrafficFlowTemplate as BorrowDecode>::decode(CREATE_PROTOCOL_FILTER, context)
            .expect("borrow trait decode");
    assert!(tail.is_empty());
    let owned =
        TrafficFlowTemplate::decode_owned(Bytes::copy_from_slice(CREATE_PROTOCOL_FILTER), context)
            .expect("owned trait decode");
    assert_eq!(borrowed, owned);

    let mut encoded = BytesMut::new();
    Encode::encode(&owned, &mut encoded, EncodeContext::default()).expect("trait encode");
    assert_eq!(encoded.as_ref(), CREATE_PROTOCOL_FILTER);
}

#[test]
fn framework_limits_fail_before_output_mutation() {
    let value = assert_fixture_roundtrip(CREATE_PROTOCOL_FILTER);
    let context = EncodeContext {
        max_message_len: CREATE_PROTOCOL_FILTER.len() - 1,
        ..EncodeContext::default()
    };
    let mut destination = BytesMut::from(&b"prefix"[..]);
    let before = destination.clone();
    let error = Encode::encode(&value, &mut destination, context).expect_err("capacity fails");
    assert!(matches!(
        error.code(),
        EncodeErrorCode::CapacityExceeded { .. }
    ));
    assert_eq!(destination, before);

    let mut decode_context = DecodeContext::conservative();
    decode_context.max_ies = 1;
    let error =
        TrafficFlowTemplate::decode_value_with_context(CREATE_PROTOCOL_FILTER, decode_context)
            .expect_err("filter plus component exceed one element");
    assert!(matches!(
        error.kind(),
        TftErrorKind::ElementLimitExceeded { limit: 1 }
    ));
}

#[test]
fn constructors_cover_every_operation_without_ambiguous_lists() {
    let filter = simple_filter(1, 10);
    assert_eq!(
        TrafficFlowTemplate::create_new(vec![filter.clone()], Vec::new())
            .expect("create")
            .operation(),
        TftOperation::CreateNew
    );
    assert_eq!(
        TrafficFlowTemplate::add_packet_filters(vec![filter.clone()], Vec::new())
            .expect("add")
            .operation(),
        TftOperation::AddPacketFilters
    );
    assert_eq!(
        TrafficFlowTemplate::replace_packet_filters(vec![filter], Vec::new())
            .expect("replace")
            .operation(),
        TftOperation::ReplacePacketFilters
    );
    assert_eq!(
        TrafficFlowTemplate::delete_packet_filters(vec![identifier(1)], Vec::new())
            .expect("delete filters")
            .operation(),
        TftOperation::DeletePacketFilters
    );
    assert_eq!(
        TrafficFlowTemplate::delete_existing().operation(),
        TftOperation::DeleteExisting
    );
    let parameter =
        TftParameter::Unknown(UnknownTftParameter::new(0xfe, [1]).expect("unknown parameter"));
    assert_eq!(
        TrafficFlowTemplate::no_operation(vec![parameter])
            .expect("no operation")
            .operation(),
        TftOperation::NoOperation
    );

    let parameter =
        TftParameter::Unknown(UnknownTftParameter::new(0xfe, [1]).expect("unknown parameter"));
    let delete = TrafficFlowTemplate::delete_existing_with_parameters(vec![parameter])
        .expect("delete-existing can independently carry parameters");
    assert_eq!(delete.operation(), TftOperation::DeleteExisting);
    assert_eq!(delete.parameters().len(), 1);
}

#[test]
fn e_bit_is_independent_for_delete_existing() {
    let value = assert_fixture_roundtrip(DELETE_EXISTING_WITH_PARAMETERS);
    assert_eq!(value.operation(), TftOperation::DeleteExisting);
    assert_eq!(value.packet_filters(), &PacketFilterList::None);
    assert_eq!(value.parameters().len(), 1);
}

#[test]
fn malformed_operation_and_list_forms_fail_closed() {
    let cases: &[&[u8]] = &[
        &[],                       // missing operation octet
        &[0xe0],                   // reserved operation 7
        &[0x20],                   // create with zero filters
        &[0x41, 0x01],             // delete-existing with non-zero count
        &[0xc0],                   // no-operation without E/parameters
        &[0xd0],                   // E set but parameter list empty
        &[0x40, 0x00],             // trailing byte with E clear
        &[0x21, 0xf1],             // full-filter spare bits non-zero
        &[0xa1, 0x11],             // delete identifier spare bits non-zero
        &[0x21, 0x31, 0, 0],       // empty full-filter contents
        &[0x21, 0x31, 0, 2, 0x30], // declared content truncation
    ];
    for bytes in cases {
        assert!(
            TrafficFlowTemplate::decode_value(bytes).is_err(),
            "accepted malformed bytes {bytes:02x?}"
        );
    }
}

#[test]
fn malformed_and_reserved_components_fail_closed() {
    let cases: &[&[u8]] = &[
        &[0x21, 0x31, 0, 1, 0x12],             // reserved component
        &[0x21, 0x31, 0, 5, 0x10, 1, 2, 3, 4], // short IPv4 component
        &[0x21, 0x31, 0, 4, 0x80, 0xf0, 0, 1], // flow-label spare bits
        &[0x21, 0x31, 0, 3, 0x83, 0xf0, 1],    // VLAN-ID spare bits
        &[0x21, 0x31, 0, 2, 0x85, 0xf1],       // PCP/DEI spare bits
        &[
            0x21, 0x31, 0, 18, 0x21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129,
        ], // IPv6 prefix >128
        &[0x21, 0x31, 0, 5, 0x41, 0, 2, 0, 1], // descending range
        &[0x21, 0x31, 0, 4, 0x30, 17, 0x30, 6], // duplicate type
        &[
            0x21, 0x31, 0, 27, 0x10, 1, 2, 3, 4, 255, 255, 255, 0, 0x21, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 64,
        ], // mixed IPv4/IPv6 families
        &[0x21, 0x31, 0, 8, 0x40, 0, 1, 0x41, 0, 1, 0, 2], // single+range
        &[0x21, 0x31, 0, 8, 0x40, 0, 1, 0x60, 0, 0, 0, 1], // port+SPI
        &[0x21, 0x31, 0, 6, 0x30, 17, 0x80, 0, 0, 1], // protocol+flow
        &[
            0x21, 0x31, 0, 12, 0x87, 0x08, 0x06, 0x10, 1, 2, 3, 4, 255, 255, 255, 0,
        ], // ARP EtherType plus IP component
    ];
    for bytes in cases {
        assert!(
            TrafficFlowTemplate::decode_value(bytes).is_err(),
            "accepted malformed component bytes {bytes:02x?}"
        );
    }
}

#[test]
fn duplicate_filter_identifiers_and_precedence_are_rejected() {
    let duplicate_identifier = [0x22, 0x31, 1, 2, 0x30, 17, 0x31, 2, 2, 0x30, 6];
    let duplicate_precedence = [0x22, 0x31, 1, 2, 0x30, 17, 0x32, 1, 2, 0x30, 6];
    let duplicate_delete_identifier = [0xa2, 0x01, 0x01];
    for bytes in [
        duplicate_identifier.as_slice(),
        duplicate_precedence.as_slice(),
        duplicate_delete_identifier.as_slice(),
    ] {
        assert!(TrafficFlowTemplate::decode_value(bytes).is_err());
    }

    let filters = vec![simple_filter(1, 1), simple_filter(1, 2)];
    assert!(matches!(
        TrafficFlowTemplate::create_new(filters, Vec::new())
            .expect_err("duplicate identifiers")
            .kind(),
        TftErrorKind::DuplicatePacketFilterIdentifier { identifier: 1 }
    ));
    let filters = vec![simple_filter(1, 1), simple_filter(2, 1)];
    assert!(matches!(
        TrafficFlowTemplate::create_new(filters, Vec::new())
            .expect_err("duplicate precedence")
            .kind(),
        TftErrorKind::DuplicateEvaluationPrecedence { precedence: 1 }
    ));
}

#[test]
fn malformed_parameters_and_authorization_order_are_rejected() {
    let cases: &[&[u8]] = &[
        &[0xd0, 0x02, 0x03, 0, 1, 2], // Flow Identifier must be four octets
        &[0xd0, 0x03, 0x01, 0xf1],    // filter identifier spare bits
        &[0xd0, 0x03, 0x02, 1, 1],    // duplicate filter identifier
        &[0xd0, 0x01, 0x01, 0xaa],    // authorization token not followed by flow
        &[0xd0, 0x01, 1, 0xaa, 0x01, 1, 0xbb], // consecutive tokens
        &[0xd0, 0xfe],                // truncated parameter length
        &[0xd0, 0xfe, 2, 1],          // truncated parameter contents
    ];
    for bytes in cases {
        assert!(TrafficFlowTemplate::decode_value(bytes).is_err());
    }

    assert!(UnknownTftParameter::new(1, [0xaa]).is_err());
    assert!(AuthorizationToken::new(Vec::<u8>::new()).is_err());
    assert!(PacketFilterIdentifierList::new(vec![identifier(1), identifier(1)]).is_err());

    let token =
        TftParameter::AuthorizationToken(AuthorizationToken::new([0xaa]).expect("nonempty token"));
    let unknown =
        TftParameter::Unknown(UnknownTftParameter::new(0xfe, [0xbb]).expect("unknown parameter"));
    assert!(TrafficFlowTemplate::no_operation(vec![token, unknown]).is_err());

    let token =
        TftParameter::AuthorizationToken(AuthorizationToken::new([0xaa]).expect("nonempty token"));
    let flow = TftParameter::FlowIdentifier(FlowIdentifier::new(1, 2));
    assert!(TrafficFlowTemplate::no_operation(vec![token, flow]).is_ok());
}

#[test]
fn constructors_reject_range_and_size_constraints() {
    assert!(PacketFilterIdentifier::new(16).is_err());
    assert!(opc_proto_tft::PortRange::new(2, 1).is_err());
    assert!(opc_proto_tft::Ipv6FlowLabel::new(0x10_0000).is_err());
    assert!(opc_proto_tft::VlanIdentifier::new(0x1000).is_err());
    assert!(opc_proto_tft::VlanPriority::new(8, false).is_err());

    let too_many = (0..16)
        .map(|value| simple_filter(value, value))
        .collect::<Vec<_>>();
    assert!(TrafficFlowTemplate::create_new(too_many, Vec::new()).is_err());
    assert!(TrafficFlowTemplate::create_new(Vec::new(), Vec::new()).is_err());
    assert!(TrafficFlowTemplate::delete_packet_filters(Vec::new(), Vec::new()).is_err());

    let huge_unknown =
        UnknownTftParameter::new(0xfe, vec![0; 255]).expect("one parameter content length fits u8");
    assert!(TrafficFlowTemplate::no_operation(vec![TftParameter::Unknown(huge_unknown)]).is_err());

    let maximum = TrafficFlowTemplate::ignore_with_contents(vec![0; 254])
        .expect("operation octet plus 254 ignored octets is the maximum value");
    assert_eq!(maximum.encoded_value_len().expect("maximum length"), 255);
    assert!(TrafficFlowTemplate::ignore_with_contents(vec![0; 255]).is_err());
    assert!(TrafficFlowTemplate::decode_value(&[0; 255]).is_ok());
    assert!(TrafficFlowTemplate::decode_value(&[0; 256]).is_err());
}

#[test]
fn structural_truncations_are_rejected() {
    let fixtures = [
        CREATE_PROTOCOL_FILTER,
        ADD_PROTOCOL_FILTER,
        REPLACE_PROTOCOL_FILTER,
        DELETE_FILTERS,
        NO_OPERATION,
        IPV4_AND_ETHERNET_COMPONENTS,
        PORT_RANGE_COMPONENTS,
        IPV6_MASK_PREFIX_AND_SPI_COMPONENTS,
        IPV6_PREFIX_AND_FLOW_LABEL_COMPONENTS,
    ];
    for fixture in fixtures {
        for cut in 0..fixture.len() {
            assert!(
                TrafficFlowTemplate::decode_value(&fixture[..cut]).is_err(),
                "fixture accepted truncation at {cut}: {fixture:02x?}"
            );
        }
    }
}

#[test]
fn complete_parameter_boundaries_are_valid_shorter_values() {
    // Once the mandatory filter and the Authorization Token's first following
    // Flow Identifier are complete, each subsequent parameter boundary is a
    // valid shorter TFT rather than a malformed truncation.
    let valid_proper_prefixes = [16usize, 22, 26];
    for cut in 0..CREATE_WITH_PARAMETERS.len() {
        let result = TrafficFlowTemplate::decode_value(&CREATE_WITH_PARAMETERS[..cut]);
        assert_eq!(
            result.is_ok(),
            valid_proper_prefixes.contains(&cut),
            "unexpected prefix result at {cut}"
        );
    }
}

#[test]
fn debug_and_errors_do_not_expose_filter_or_parameter_contents() {
    let filter = PacketFilter::new(
        identifier(1),
        PacketFilterDirection::Bidirectional,
        1,
        vec![PacketFilterComponent::Ipv4RemoteAddress {
            address: Ipv4Addr::new(192, 0, 2, 77),
            mask: Ipv4Addr::new(255, 255, 255, 0),
        }],
    )
    .expect("filter");
    let token = TftParameter::AuthorizationToken(
        AuthorizationToken::new([0xde, 0xad, 0xbe, 0xef]).expect("token"),
    );
    let flow = TftParameter::FlowIdentifier(FlowIdentifier::new(1, 2));
    let tft = TrafficFlowTemplate::create_new(vec![filter], vec![token, flow]).expect("TFT");
    let debug = format!("{tft:?}");
    assert!(!debug.contains("192.0.2.77"));
    assert!(!debug.contains("deadbeef"));
    assert!(!debug.contains("[222, 173, 190, 239]"));

    let malformed = [0x21, 0x31, 0, 1, 0x12];
    let error = TrafficFlowTemplate::decode_value(&malformed).expect_err("reserved component");
    let diagnostic = format!("{error:?} {error}");
    assert!(!diagnostic.contains("31, 0, 1"));
    assert!(error.offset().is_some());

    let redacted_values = format!(
        "{:?} {:?} {:?} {:?} {:?}",
        opc_proto_tft::PortRange::new(443, 4500).expect("range"),
        opc_proto_tft::Ipv6FlowLabel::new(0xabcde).expect("flow label"),
        opc_proto_tft::VlanIdentifier::new(123).expect("VLAN"),
        opc_proto_tft::VlanPriority::new(5, true).expect("priority"),
        FlowIdentifier::new(1234, 5678),
    );
    for secret in ["443", "4500", "703710", "123", "5", "1234", "5678"] {
        assert!(
            !redacted_values.contains(secret),
            "Debug exposed classifier value {secret}"
        );
    }
}

#[test]
fn generic_new_rejects_operation_list_mismatches() {
    let filter = simple_filter(1, 1);
    let mismatches = [
        TrafficFlowTemplate::new(
            TftOperation::CreateNew,
            PacketFilterList::Identifiers(vec![identifier(1)]),
            Vec::new(),
        ),
        TrafficFlowTemplate::new(
            TftOperation::DeletePacketFilters,
            PacketFilterList::Filters(vec![filter]),
            Vec::new(),
        ),
        TrafficFlowTemplate::new(
            TftOperation::DeleteExisting,
            PacketFilterList::Identifiers(vec![identifier(1)]),
            Vec::new(),
        ),
    ];
    assert!(mismatches.into_iter().all(|result| result.is_err()));
}
