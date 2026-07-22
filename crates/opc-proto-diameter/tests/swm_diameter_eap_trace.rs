#![cfg(feature = "app-swm")]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU64,
};

use bytes::{Bytes, BytesMut};
use opc_proto_diameter::apps::swm;
use opc_proto_diameter::dictionary::{
    AvpCardinality, AvpDataType, AvpKey, CommandKind, FlagRequirement,
};
use opc_proto_diameter::{
    base, AvpCode, AvpFlags, CommandFlags, Header, Message, OwnedMessage, RawAvp, VendorId,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DuplicateIePolicy, Encode, EncodeContext,
    UnknownIePolicy,
};

const HOP_BY_HOP: u32 = 0x1020_3040;
const END_TO_END: u32 = 0x5060_7080;
const SESSION_ID: &[u8] = b"session;synthetic;trace";
const AAA_HOST: &[u8] = b"aaa.synthetic.invalid";
const AAA_REALM: &[u8] = b"home.synthetic.invalid";
const EPDG_HOST: &[u8] = b"epdg.synthetic.invalid";
const EPDG_REALM: &[u8] = b"visited.synthetic.invalid";
const TRACE_REFERENCE: [u8; 6] = [0x21, 0xf3, 0x54, 0xaa, 0xbb, 0xcc];
const TRACE_URI: &[u8] = b"https://trace.synthetic.invalid/TraceMnS/v1/records/stream";
const CONNECTION: swm::SwmDiameterConnectionToken =
    swm::SwmDiameterConnectionToken::new(NonZeroU64::MIN);
const OTHER_CONNECTION: swm::SwmDiameterConnectionToken = swm::SwmDiameterConnectionToken::new(
    NonZeroU64::new(2).expect("synthetic connection token is nonzero"),
);
const UNKNOWN_CHILD: AvpCode = AvpCode::new(900_352);
const FOREIGN_VENDOR: VendorId = VendorId::new(42_424);
const WIRE_VENDOR_3GPP: VendorId = VendorId::new(10_415);
const WIRE_AVP_TRACE_COLLECTION_ENTITY: AvpCode = AvpCode::new(1_452);
const WIRE_AVP_TRACE_DATA: AvpCode = AvpCode::new(1_458);
const WIRE_AVP_TRACE_REFERENCE: AvpCode = AvpCode::new(1_459);
const WIRE_AVP_TRACE_DEPTH: AvpCode = AvpCode::new(1_462);
const WIRE_AVP_TRACE_NE_TYPE_LIST: AvpCode = AvpCode::new(1_463);
const WIRE_AVP_TRACE_INTERFACE_LIST: AvpCode = AvpCode::new(1_464);
const WIRE_AVP_TRACE_EVENT_LIST: AvpCode = AvpCode::new(1_465);
const WIRE_AVP_TRACE_INFO: AvpCode = AvpCode::new(1_505);
const WIRE_AVP_TRACE_REPORTING_CONSUMER_URI: AvpCode = AvpCode::new(1_727);

#[derive(Debug, Clone, PartialEq, Eq)]
struct AvpSnapshot {
    code: AvpCode,
    vendor_id: Option<VendorId>,
    flags: u8,
    value: Vec<u8>,
}

fn put_u24(dst: &mut Vec<u8>, value: usize) {
    let value = u32::try_from(value).expect("synthetic fixture length fits u32");
    dst.extend_from_slice(&value.to_be_bytes()[1..]);
}

fn raw_avp(code: AvpCode, flags: u8, vendor_id: Option<VendorId>, value: &[u8]) -> Vec<u8> {
    assert_eq!(flags & AvpFlags::VENDOR != 0, vendor_id.is_some());
    let header_len = if vendor_id.is_some() { 12 } else { 8 };
    let length = header_len + value.len();
    let mut wire = Vec::with_capacity((length + 3) & !3);
    wire.extend_from_slice(&code.get().to_be_bytes());
    wire.push(flags);
    put_u24(&mut wire, length);
    if let Some(vendor_id) = vendor_id {
        wire.extend_from_slice(&vendor_id.get().to_be_bytes());
    }
    wire.extend_from_slice(value);
    wire.resize((length + 3) & !3, 0);
    wire
}

fn vendor_child(code: AvpCode, value: &[u8]) -> Vec<u8> {
    raw_avp(
        code,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(WIRE_VENDOR_3GPP),
        value,
    )
}

fn address_value(address: IpAddr) -> Vec<u8> {
    let mut value = Vec::new();
    match address {
        IpAddr::V4(address) => {
            value.extend_from_slice(&1_u16.to_be_bytes());
            value.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            value.extend_from_slice(&2_u16.to_be_bytes());
            value.extend_from_slice(&address.octets());
        }
    }
    value
}

fn event_bitmap(bits: u8) -> Vec<u8> {
    // TS 32.422 V18.5 §5.1: PGW occupies bits 5..7 of octet 9, while
    // SGW occupies the low nibble of that same octet.
    let mut value = vec![0_u8; 17];
    value[8] = bits;
    value
}

fn interface_bitmap(bits: u8) -> Vec<u8> {
    let mut value = vec![0_u8; 23];
    value[10] = bits;
    value
}

fn activation_children(
    depth: u32,
    events: u8,
    interfaces: Option<u8>,
    address: IpAddr,
    uri: Option<&[u8]>,
    unknown_children: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    let mut children = vec![
        vendor_child(WIRE_AVP_TRACE_REFERENCE, &TRACE_REFERENCE),
        vendor_child(WIRE_AVP_TRACE_DEPTH, &depth.to_be_bytes()),
        vendor_child(WIRE_AVP_TRACE_NE_TYPE_LIST, &[0x00, 0x01, 0x00]),
    ];
    if let Some(bits) = interfaces {
        children.push(vendor_child(
            WIRE_AVP_TRACE_INTERFACE_LIST,
            &interface_bitmap(bits),
        ));
    }
    children.push(vendor_child(
        WIRE_AVP_TRACE_EVENT_LIST,
        &event_bitmap(events),
    ));
    children.push(vendor_child(
        WIRE_AVP_TRACE_COLLECTION_ENTITY,
        &address_value(address),
    ));
    if let Some(uri) = uri {
        children.push(raw_avp(
            WIRE_AVP_TRACE_REPORTING_CONSUMER_URI,
            AvpFlags::VENDOR,
            Some(WIRE_VENDOR_3GPP),
            uri,
        ));
    }
    children.extend_from_slice(unknown_children);
    children
}

fn grouped_value(children: &[Vec<u8>]) -> Vec<u8> {
    let mut value = Vec::new();
    for child in children {
        value.extend_from_slice(child);
    }
    value
}

fn trace_info_activation(children: &[Vec<u8>]) -> Vec<u8> {
    let trace_data = vendor_child(WIRE_AVP_TRACE_DATA, &grouped_value(children));
    trace_info_with_children(&[trace_data])
}

fn trace_info_with_children(children: &[Vec<u8>]) -> Vec<u8> {
    raw_avp(
        WIRE_AVP_TRACE_INFO,
        AvpFlags::VENDOR,
        Some(WIRE_VENDOR_3GPP),
        &grouped_value(children),
    )
}

fn trace_info_deactivation() -> Vec<u8> {
    raw_avp(
        WIRE_AVP_TRACE_INFO,
        AvpFlags::VENDOR,
        Some(WIRE_VENDOR_3GPP),
        &vendor_child(WIRE_AVP_TRACE_REFERENCE, &TRACE_REFERENCE),
    )
}

fn answer_wire_with(
    extras: &[Vec<u8>],
    hop_by_hop: u32,
    end_to_end: u32,
    origin_host: &[u8],
) -> Vec<u8> {
    answer_wire_with_result(
        extras,
        hop_by_hop,
        end_to_end,
        origin_host,
        base::RESULT_CODE_DIAMETER_SUCCESS,
    )
}

fn answer_wire_with_result(
    extras: &[Vec<u8>],
    hop_by_hop: u32,
    end_to_end: u32,
    origin_host: &[u8],
    result_code: u32,
) -> Vec<u8> {
    let mut raw_avps = Vec::new();
    for avp in [
        raw_avp(base::AVP_SESSION_ID, AvpFlags::MANDATORY, None, SESSION_ID),
        raw_avp(
            base::AVP_AUTH_APPLICATION_ID,
            AvpFlags::MANDATORY,
            None,
            &swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        raw_avp(
            swm::AVP_AUTH_REQUEST_TYPE,
            AvpFlags::MANDATORY,
            None,
            &swm::AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE.to_be_bytes(),
        ),
        raw_avp(
            base::AVP_RESULT_CODE,
            AvpFlags::MANDATORY,
            None,
            &result_code.to_be_bytes(),
        ),
        raw_avp(
            base::AVP_ORIGIN_HOST,
            AvpFlags::MANDATORY,
            None,
            origin_host,
        ),
        raw_avp(base::AVP_ORIGIN_REALM, AvpFlags::MANDATORY, None, AAA_REALM),
    ] {
        raw_avps.extend_from_slice(&avp);
    }
    for extra in extras {
        raw_avps.extend_from_slice(extra);
    }
    raw_avps.extend_from_slice(&raw_avp(
        swm::AVP_EAP_PAYLOAD,
        AvpFlags::MANDATORY,
        None,
        &[3, 9, 0, 4],
    ));
    encode(&OwnedMessage {
        header: Header::new(
            CommandFlags::answer(true, false),
            swm::COMMAND_DIAMETER_EAP,
            swm::APPLICATION_ID,
            hop_by_hop,
            end_to_end,
        ),
        raw_avps: Bytes::from(raw_avps),
    })
}

fn answer_wire(extras: &[Vec<u8>]) -> Vec<u8> {
    answer_wire_with(extras, HOP_BY_HOP, END_TO_END, AAA_HOST)
}

fn request_wire(extra: Option<Vec<u8>>) -> Vec<u8> {
    let mut raw_avps = Vec::new();
    for avp in [
        raw_avp(base::AVP_SESSION_ID, AvpFlags::MANDATORY, None, SESSION_ID),
        raw_avp(
            base::AVP_AUTH_APPLICATION_ID,
            AvpFlags::MANDATORY,
            None,
            &swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        raw_avp(base::AVP_ORIGIN_HOST, AvpFlags::MANDATORY, None, EPDG_HOST),
        raw_avp(
            base::AVP_ORIGIN_REALM,
            AvpFlags::MANDATORY,
            None,
            EPDG_REALM,
        ),
        raw_avp(
            base::AVP_DESTINATION_REALM,
            AvpFlags::MANDATORY,
            None,
            AAA_REALM,
        ),
        raw_avp(
            swm::AVP_AUTH_REQUEST_TYPE,
            AvpFlags::MANDATORY,
            None,
            &swm::AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE.to_be_bytes(),
        ),
        raw_avp(
            swm::AVP_EAP_PAYLOAD,
            AvpFlags::MANDATORY,
            None,
            &[2, 9, 0, 4],
        ),
    ] {
        raw_avps.extend_from_slice(&avp);
    }
    if let Some(extra) = extra {
        raw_avps.extend_from_slice(&extra);
    }
    encode(&OwnedMessage {
        header: Header::new(
            CommandFlags::request(true),
            swm::COMMAND_DIAMETER_EAP,
            swm::APPLICATION_ID,
            HOP_BY_HOP,
            END_TO_END,
        ),
        raw_avps: Bytes::from(raw_avps),
    })
}

fn framing_context() -> DecodeContext {
    DecodeContext {
        max_ies: 512,
        max_message_len: 256 * 1024,
        duplicate_ie_policy: DuplicateIePolicy::First,
        unknown_ie_policy: UnknownIePolicy::Preserve,
        ..DecodeContext::default()
    }
}

fn typed_context(policy: UnknownIePolicy) -> DecodeContext {
    DecodeContext {
        max_ies: 512,
        max_message_len: 256 * 1024,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        unknown_ie_policy: policy,
        ..DecodeContext::conservative()
    }
}

fn decode(wire: &[u8]) -> Message<'_> {
    let (tail, message) =
        Message::decode(wire, framing_context()).expect("synthetic Diameter framing");
    assert!(tail.is_empty());
    message
}

fn parse_with_context(
    wire: &[u8],
    context: DecodeContext,
) -> Result<swm::SwmDiameterEapAnswer, DecodeError> {
    swm::parse_swm_diameter_eap_answer(&decode(wire), context)
}

fn parse(wire: &[u8]) -> Result<swm::SwmDiameterEapAnswer, DecodeError> {
    parse_with_context(wire, typed_context(UnknownIePolicy::Preserve))
}

fn parse_envelope(wire: &[u8]) -> Result<swm::SwmDiameterEapAnswerEnvelope, DecodeError> {
    swm::parse_swm_diameter_eap_answer_envelope(
        &decode(wire),
        typed_context(UnknownIePolicy::Preserve),
    )
}

fn response_envelope(
    wire: &[u8],
    connection: swm::SwmDiameterConnectionToken,
) -> swm::SwmDiameterEapResponseEnvelope {
    swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(wire),
        connection,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("synthetic authenticated response parses")
}

fn bound_request() -> swm::SwmDiameterEapRequestEnvelope {
    let wire = request_wire(None);
    swm::parse_swm_diameter_eap_request_envelope(
        &decode(&wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("synthetic DER parses")
    .with_expected_answer_peer(swm::SwmExpectedAnswerPeer::direct(
        CONNECTION,
        String::from_utf8(AAA_HOST.to_vec()).expect("ASCII host"),
        String::from_utf8(AAA_REALM.to_vec()).expect("ASCII realm"),
    ))
}

fn correlated(wire: &[u8]) -> swm::SwmCorrelatedDiameterEapResponse {
    bound_request()
        .correlate_response(response_envelope(wire, CONNECTION))
        .expect("synthetic authenticated response correlates")
}

fn encode(message: &OwnedMessage) -> Vec<u8> {
    let mut wire = BytesMut::new();
    message
        .encode(&mut wire, EncodeContext::default())
        .expect("synthetic Diameter message encodes");
    wire.to_vec()
}

fn snapshots(mut wire: &[u8]) -> Vec<AvpSnapshot> {
    let mut values = Vec::new();
    while !wire.is_empty() {
        let (remaining, avp) =
            RawAvp::decode(wire, DecodeContext::default()).expect("synthetic AVP decodes");
        values.push(AvpSnapshot {
            code: avp.header.code,
            vendor_id: avp.header.vendor_id,
            flags: avp.header.flags.bits(),
            value: avp.value.to_vec(),
        });
        wire = remaining;
    }
    values
}

fn trace_data_snapshots(wire: &[u8]) -> Vec<AvpSnapshot> {
    let message = decode(wire);
    let outer = snapshots(message.raw_avps);
    let trace_info = outer
        .iter()
        .find(|avp| avp.code == WIRE_AVP_TRACE_INFO && avp.vendor_id == Some(WIRE_VENDOR_3GPP))
        .expect("Trace-Info exists");
    let trace_info_children = snapshots(&trace_info.value);
    let trace_data = trace_info_children
        .iter()
        .find(|avp| avp.code == WIRE_AVP_TRACE_DATA && avp.vendor_id == Some(WIRE_VENDOR_3GPP))
        .expect("Trace-Data exists");
    snapshots(&trace_data.value)
}

fn activation_fixture(address: IpAddr) -> Vec<u8> {
    trace_info_activation(&activation_children(
        2,
        0x70,
        Some(0xff),
        address,
        Some(TRACE_URI),
        &[],
    ))
}

fn successful_answer() -> swm::SwmDiameterEapAnswer {
    swm::SwmDiameterEapAnswer {
        session_id: "session;synthetic;trace".into(),
        auth_application_id: swm::APPLICATION_ID.get(),
        auth_request_type: swm::AuthRequestType::AuthorizeAuthenticate,
        result: swm::SwmDiameterResult::Base(base::RESULT_CODE_DIAMETER_SUCCESS),
        origin_host: "aaa.synthetic.invalid".into(),
        origin_realm: "home.synthetic.invalid".into(),
        user_name: None,
        subscriber_authorization: Default::default(),
        mip6_feature_vector: None,
        supported_features: Vec::new(),
        oc_supported_features: None,
        oc_olr: None,
        load_reports: Vec::new(),
        service_selection: None,
        default_context_identifier: None,
        apn_configurations: Vec::new(),
        mobile_node_identifier: None,
        session_timeout: None,
        multi_round_timeout: None,
        authorization_lifetime: None,
        auth_grace_period: None,
        re_auth_request_type: None,
        eap_payload: Some(vec![3, 9, 0, 4].into()),
        eap_reissued_payload: None,
        error_message: None,
        state_avps: Vec::new(),
        eap_master_session_key: None,
        extensions: Default::default(),
    }
}

#[test]
fn literal_trace_activation_fixture_round_trips_and_matches_typed_encoding() {
    let trace_avp = activation_fixture(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
    let wire = answer_wire(std::slice::from_ref(&trace_avp));
    let envelope = parse_envelope(&wire).expect("literal-code activation fixture parses");
    assert!(envelope.answer().has_trace_info());

    let correlated = correlated(&wire);
    let trace = correlated
        .trace_info()
        .expect("typed trace data is exposed only after correlation");
    let data = trace.data();
    assert_eq!(data.trace_reference().octets(), TRACE_REFERENCE);
    assert_eq!(data.depth(), swm::SwmTraceDepth::Maximum);
    assert!(data.events().traces_pdn_connection_creation());
    assert!(data.events().traces_pdn_connection_termination());
    assert!(data.events().traces_bearer_lifecycle());
    assert!(data.has_explicit_pdn_gateway_target());
    let interfaces = data.interfaces().expect("interface bitmap is present");
    assert!(interfaces.includes_s2a());
    assert!(interfaces.includes_s2b());
    assert!(interfaces.includes_s2c());
    assert!(interfaces.includes_s5());
    assert!(interfaces.includes_s6b());
    assert!(interfaces.includes_gx());
    assert!(interfaces.includes_s8b());
    assert!(interfaces.includes_sgi());
    assert_eq!(
        data.collection_entity(),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))
    );
    assert_eq!(
        data.reporting_consumer_uri().map(|uri| uri.as_str()),
        Some(std::str::from_utf8(TRACE_URI).expect("synthetic URI is UTF-8"))
    );

    let rebuilt = swm::build_swm_diameter_eap_answer_envelope(&envelope, EncodeContext::default())
        .expect("immutable parsed activation replays");
    assert_eq!(encode(&rebuilt), wire);

    let reference = swm::SwmTraceReference::new(TRACE_REFERENCE).expect("valid PLMN trace id");
    let uri = swm::SwmTraceReportingConsumerUri::new(
        std::str::from_utf8(TRACE_URI).expect("synthetic URI is UTF-8"),
    )
    .expect("synthetic trace endpoint is valid");
    let data = swm::SwmTraceData::new(
        reference,
        swm::SwmTraceDepth::Maximum,
        swm::SwmPgwTraceEvents::new(true, true, true),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
    )
    .expect("originated trace data is valid")
    .with_explicit_pdn_gateway_target()
    .with_interfaces(swm::SwmPgwTraceInterfaces::new(
        true, true, true, true, true, true, true, true,
    ))
    .with_reporting_consumer_uri(uri)
    .expect("originated URI has valid provenance");
    let trace = swm::SwmTraceInfo::activation(data).expect("originated activation is valid");
    let mut answer = successful_answer();
    answer
        .set_trace_info(trace)
        .expect("originated trace is accepted");
    let built = swm::build_swm_diameter_eap_answer(
        &answer,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .expect("typed activation answer builds");
    assert_eq!(encode(&built), wire);
}

#[test]
fn direct_trace_reference_deactivation_is_rejected_in_command_268_dea() {
    let trace_avp = trace_info_deactivation();
    let wire = answer_wire(std::slice::from_ref(&trace_avp));
    let error = parse_envelope(&wire).expect_err("direct deactivation belongs to command 265");
    assert!(matches!(
        error.code(),
        opc_protocol::DecodeErrorCode::Structural { .. }
    ));
}

#[test]
fn current_release_depth_event_interface_and_address_shapes_decode_exactly() {
    let depths = [
        swm::SwmTraceDepth::Minimum,
        swm::SwmTraceDepth::Medium,
        swm::SwmTraceDepth::Maximum,
        swm::SwmTraceDepth::MinimumWithoutVendorSpecificExtension,
        swm::SwmTraceDepth::MediumWithoutVendorSpecificExtension,
        swm::SwmTraceDepth::MaximumWithoutVendorSpecificExtension,
    ];
    for (wire_depth, expected) in depths.into_iter().enumerate() {
        let trace = trace_info_activation(&activation_children(
            u32::try_from(wire_depth).expect("depth index fits u32"),
            0,
            Some(0),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            None,
            &[],
        ));
        let response = answer_wire(&[trace]);
        let correlated_response = correlated(&response);
        let data = correlated_response
            .trace_info()
            .expect("trace exists")
            .data();
        assert_eq!(data.depth(), expected);
        assert_eq!(
            data.events(),
            swm::SwmPgwTraceEvents::new(false, false, false)
        );
        assert_eq!(
            data.interfaces(),
            Some(swm::SwmPgwTraceInterfaces::new(
                false, false, false, false, false, false, false, false,
            ))
        );
    }

    for (event_bit, expected) in [
        (0x10, (true, false, false)),
        (0x20, (false, true, false)),
        (0x40, (false, false, true)),
    ] {
        let trace = trace_info_activation(&activation_children(
            0,
            event_bit,
            None,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10)),
            None,
            &[],
        ));
        let response = answer_wire(&[trace]);
        let correlated_response = correlated(&response);
        let data = correlated_response
            .trace_info()
            .expect("trace exists")
            .data();
        assert_eq!(
            (
                data.events().traces_pdn_connection_creation(),
                data.events().traces_pdn_connection_termination(),
                data.events().traces_bearer_lifecycle(),
            ),
            expected
        );
        assert_eq!(
            data.collection_entity(),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10))
        );
    }

    for (interface_bit, expected) in [
        (
            0x01_u8,
            [true, false, false, false, false, false, false, false],
        ),
        (
            0x02,
            [false, true, false, false, false, false, false, false],
        ),
        (
            0x04,
            [false, false, true, false, false, false, false, false],
        ),
        (
            0x08,
            [false, false, false, true, false, false, false, false],
        ),
        (
            0x10,
            [false, false, false, false, true, false, false, false],
        ),
        (
            0x20,
            [false, false, false, false, false, true, false, false],
        ),
        (
            0x40,
            [false, false, false, false, false, false, true, false],
        ),
        (
            0x80,
            [false, false, false, false, false, false, false, true],
        ),
    ] {
        let trace = trace_info_activation(&activation_children(
            0,
            0,
            Some(interface_bit),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            None,
            &[],
        ));
        let response = answer_wire(&[trace]);
        let correlated_response = correlated(&response);
        let data = correlated_response
            .trace_info()
            .expect("trace exists")
            .data();
        let interfaces = data.interfaces().expect("interface selection exists");
        assert_eq!(
            [
                interfaces.includes_s2a(),
                interfaces.includes_s2b(),
                interfaces.includes_s2c(),
                interfaces.includes_s5(),
                interfaces.includes_s6b(),
                interfaces.includes_gx(),
                interfaces.includes_s8b(),
                interfaces.includes_sgi(),
            ],
            expected
        );

        let originated_data = swm::SwmTraceData::new(
            swm::SwmTraceReference::new(TRACE_REFERENCE).expect("originated trace reference"),
            swm::SwmTraceDepth::Minimum,
            swm::SwmPgwTraceEvents::default(),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        )
        .expect("originated trace data")
        .with_interfaces(swm::SwmPgwTraceInterfaces::new(
            expected[0],
            expected[1],
            expected[2],
            expected[3],
            expected[4],
            expected[5],
            expected[6],
            expected[7],
        ));
        let mut answer = successful_answer();
        answer
            .set_trace_info(
                swm::SwmTraceInfo::activation(originated_data)
                    .expect("originated trace activation"),
            )
            .expect("originated trace attaches");
        let built = swm::build_swm_diameter_eap_answer(
            &answer,
            HOP_BY_HOP,
            END_TO_END,
            EncodeContext::default(),
        )
        .expect("trace answer builds");
        let built_wire = encode(&built);
        let interface = trace_data_snapshots(&built_wire)
            .into_iter()
            .find(|avp| avp.code == WIRE_AVP_TRACE_INTERFACE_LIST)
            .expect("Trace-Interface-List exists");
        assert_eq!(interface.value, interface_bitmap(interface_bit));
    }
}

#[test]
fn reporting_consumer_uri_uses_the_documented_strict_ts32158_profile() {
    for accepted in [
        "https://collector.example/TraceReportingMnS/v1800/traceRecords",
        "http://192.0.2.10:8080/3gpp/TraceReportingMnS/v1800/traceRecords/stream",
        "https://[2001:db8::10]/TraceReportingMnS/v1800/traceRecords",
        "HTTPS://collector.example/TraceReportingMnS/v1800/trace%20records",
    ] {
        let uri = swm::SwmTraceReportingConsumerUri::new(accepted)
            .expect("valid TS 32.158 literal is accepted");
        let expected = if let Some(remainder) = accepted.strip_prefix("HTTPS://") {
            format!("https://{remainder}")
        } else {
            accepted.to_owned()
        };
        assert_eq!(uri.as_str(), expected);
    }

    for rejected in [
        "ftp://collector.example/TraceReportingMnS/v1800/traceRecords",
        "https://user@collector.example/TraceReportingMnS/v1800/traceRecords",
        "https://collector.example/TraceReportingMnS/v1800",
        "https://collector.example/TraceReportingMnS//traceRecords",
        "https://collector.example//TraceReportingMnS/v1800/traceRecords",
        "https://collector.example/TraceReportingMnS/v1800/../traceRecords",
        "https://collector.example/TraceReportingMnS/v1800/%2e%2e",
        "https://collector.example/TraceReportingMnS/v1800/.%2e/traceRecords",
        "https://collector.example/TraceReportingMnS/v1800/%2e./traceRecords",
        "https://collector.example/TraceReportingMnS/v1800/trace%2frecords",
        "https://collector.example/TraceReportingMnS/v1800/trace%5Crecords",
        "https://collector.example/TraceReportingMnS/v1800/trace%3Frecords",
        "https://collector.example/TraceReportingMnS/v1800/trace%23records",
        "https://collector.example/TraceReportingMnS/v1800/trace%00records",
        "https://collector.example/TraceReportingMnS/v1800/trace%1frecords",
        "https://collector.example/TraceReportingMnS/v1800/trace%7frecords",
        "https://collector.example/TraceReportingMnS/v1800/trace%25records",
        "https://collector.example/TraceReportingMnS/v1800/%252e%252e/traceRecords",
        "https://collector.example/TraceReportingMnS/v1800/trace%ZZ",
        "https://collector.example/TraceReportingMnS/v1800/traceRecords?tenant=x",
        "https://collector.example/TraceReportingMnS/v1800/traceRecords#part",
        "https://2001:db8::10/TraceReportingMnS/v1800/traceRecords",
        "https://127.1/TraceReportingMnS/v1800/traceRecords",
        "https://2130706433/TraceReportingMnS/v1800/traceRecords",
        "https://0177.0.0.1/TraceReportingMnS/v1800/traceRecords",
        "https://0x7f000001/TraceReportingMnS/v1800/traceRecords",
        "https://collector.example:0/TraceReportingMnS/v1800/traceRecords",
        "https://collector.example:65536/TraceReportingMnS/v1800/traceRecords",
        "https://collector.example/TraceReportingMnS/v1800/trace records",
        "https://collector.example/TraceReportingMnS/v1800/tracé",
    ] {
        assert!(
            swm::SwmTraceReportingConsumerUri::new(rejected).is_err(),
            "invalid URI literal unexpectedly accepted"
        );
    }

    let prefix = "https://a.invalid/MnS/v1/";
    let exact = format!("{prefix}{}", "r".repeat(2_048 - prefix.len()));
    assert_eq!(exact.len(), 2_048);
    assert!(swm::SwmTraceReportingConsumerUri::new(&exact).is_ok());
    let excessive = format!("{exact}x");
    assert!(swm::SwmTraceReportingConsumerUri::new(excessive).is_err());
}

#[test]
fn received_reporting_consumer_uri_rejects_ambiguous_wire_forms() {
    for rejected in [
        "https://collector.example/MnS/v1/trace%2frecords",
        "https://collector.example/MnS/v1/trace%5Crecords",
        "https://collector.example/MnS/v1/trace%3frecords",
        "https://collector.example/MnS/v1/trace%23records",
        "https://collector.example/MnS/v1/trace%00records",
        "https://collector.example/MnS/v1/trace%1frecords",
        "https://collector.example/MnS/v1/.%2e/records",
        "https://collector.example/MnS/v1/%252e%252e/records",
        "https://127.1/MnS/v1/records",
        "https://2130706433/MnS/v1/records",
        "https://0177.0.0.1/MnS/v1/records",
        "https://0x7f000001/MnS/v1/records",
    ] {
        let children = activation_children(
            0,
            0x10,
            None,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            Some(rejected.as_bytes()),
            &[],
        );
        assert!(
            parse(&answer_wire(&[trace_info_activation(&children)])).is_err(),
            "ambiguous received URI unexpectedly parsed"
        );
    }
}

#[test]
fn trace_wire_identity_flags_lengths_and_bitmaps_fail_closed() {
    let canonical = activation_children(
        2,
        0x70,
        Some(0xff),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        Some(TRACE_URI),
        &[],
    );
    let canonical_data = vendor_child(WIRE_AVP_TRACE_DATA, &grouped_value(&canonical));

    let mut invalid_trace_infos = vec![
        raw_avp(
            WIRE_AVP_TRACE_INFO,
            AvpFlags::VENDOR | AvpFlags::PROTECTED,
            Some(WIRE_VENDOR_3GPP),
            &canonical_data,
        ),
        raw_avp(
            WIRE_AVP_TRACE_INFO,
            AvpFlags::VENDOR,
            Some(FOREIGN_VENDOR),
            &canonical_data,
        ),
    ];

    let replacements = [
        vendor_child(WIRE_AVP_TRACE_REFERENCE, &[0x21, 0xf3, 0x54, 0xaa, 0xbb]),
        vendor_child(
            WIRE_AVP_TRACE_REFERENCE,
            &[0xfa, 0xf3, 0x54, 0xaa, 0xbb, 0xcc],
        ),
        vendor_child(WIRE_AVP_TRACE_DEPTH, &[0, 0, 2]),
        vendor_child(WIRE_AVP_TRACE_DEPTH, &6_u32.to_be_bytes()),
        vendor_child(WIRE_AVP_TRACE_NE_TYPE_LIST, &[0, 2, 0]),
        vendor_child(WIRE_AVP_TRACE_EVENT_LIST, &[0_u8; 16]),
        {
            let mut bitmap = event_bitmap(0x70);
            bitmap[7] = 1;
            vendor_child(WIRE_AVP_TRACE_EVENT_LIST, &bitmap)
        },
        {
            let mut bitmap = event_bitmap(0x70);
            bitmap[8] |= 0x01;
            vendor_child(WIRE_AVP_TRACE_EVENT_LIST, &bitmap)
        },
        vendor_child(WIRE_AVP_TRACE_INTERFACE_LIST, &[0_u8; 22]),
        {
            let mut bitmap = interface_bitmap(0xff);
            bitmap[8] = 1;
            vendor_child(WIRE_AVP_TRACE_INTERFACE_LIST, &bitmap)
        },
        vendor_child(WIRE_AVP_TRACE_COLLECTION_ENTITY, &[0, 1, 192, 0, 2]),
        raw_avp(
            WIRE_AVP_TRACE_REPORTING_CONSUMER_URI,
            AvpFlags::VENDOR,
            Some(WIRE_VENDOR_3GPP),
            b"https://collector.example/MnS/v1",
        ),
        raw_avp(
            WIRE_AVP_TRACE_REFERENCE,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(FOREIGN_VENDOR),
            &TRACE_REFERENCE,
        ),
    ];
    for replacement in replacements {
        let code = snapshots(&replacement)
            .first()
            .expect("replacement AVP exists")
            .code;
        let index = canonical
            .iter()
            .position(|child| {
                snapshots(child)
                    .first()
                    .is_some_and(|snapshot| snapshot.code == code)
            })
            .expect("canonical child exists");
        let mut children = canonical.clone();
        children[index] = replacement;
        invalid_trace_infos.push(trace_info_activation(&children));
    }

    invalid_trace_infos.push(raw_avp(WIRE_AVP_TRACE_INFO, 0, None, &canonical_data));

    for trace_info in invalid_trace_infos {
        let error = parse(&answer_wire(&[trace_info]))
            .expect_err("malformed trace identity/shape must fail closed");
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("198.51.100.9"));
        assert!(!diagnostic.contains("trace.synthetic.invalid"));
    }
}

#[test]
fn every_known_trace_data_child_enforces_vendor_and_flags() {
    let canonical = activation_children(
        2,
        0x70,
        Some(0xff),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        Some(TRACE_URI),
        &[],
    );
    for (index, child) in canonical.iter().enumerate() {
        let snapshot = snapshots(child)
            .into_iter()
            .next()
            .expect("canonical child exists");

        let foreign_vendor = raw_avp(
            snapshot.code,
            snapshot.flags,
            Some(FOREIGN_VENDOR),
            &snapshot.value,
        );
        let mut foreign_children = canonical.clone();
        foreign_children[index] = foreign_vendor;
        assert!(
            parse(&answer_wire(&[trace_info_activation(&foreign_children)])).is_err(),
            "known trace child accepted a foreign vendor identity"
        );

        let invalid_flags = snapshot.flags | AvpFlags::PROTECTED;
        let invalid_flag_child = raw_avp(
            snapshot.code,
            invalid_flags,
            Some(WIRE_VENDOR_3GPP),
            &snapshot.value,
        );
        let mut invalid_flag_children = canonical.clone();
        invalid_flag_children[index] = invalid_flag_child;
        assert!(
            parse(&answer_wire(&[trace_info_activation(
                &invalid_flag_children
            )]))
            .is_err(),
            "known trace child accepted invalid flags"
        );

        let missing_vendor_flag = raw_avp(
            snapshot.code,
            snapshot.flags & !AvpFlags::VENDOR,
            None,
            &snapshot.value,
        );
        let mut missing_vendor_flag_children = canonical.clone();
        missing_vendor_flag_children[index] = missing_vendor_flag;
        assert!(
            parse(&answer_wire(&[trace_info_activation(
                &missing_vendor_flag_children
            )]))
            .is_err(),
            "known trace child accepted a missing V flag"
        );
    }
}

#[test]
fn understood_trace_m_bit_mismatches_parse_and_reencode_canonically() {
    let canonical = activation_children(
        2,
        0x70,
        Some(0xff),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
        Some(TRACE_URI),
        &[],
    );

    for (index, child) in canonical.iter().enumerate() {
        let snapshot = snapshots(child)
            .into_iter()
            .next()
            .expect("canonical child exists");
        let mismatched = raw_avp(
            snapshot.code,
            snapshot.flags ^ AvpFlags::MANDATORY,
            snapshot.vendor_id,
            &snapshot.value,
        );
        let mut children = canonical.clone();
        children[index] = mismatched;
        let wire = answer_wire(&[trace_info_activation(&children)]);
        let envelope = parse_envelope(&wire).expect("known child M mismatch is ignored");
        let rebuilt =
            swm::build_swm_diameter_eap_answer_envelope(&envelope, EncodeContext::default())
                .expect("known child mismatch reencodes");
        let rebuilt_wire = encode(&rebuilt);
        let rebuilt_child = trace_data_snapshots(&rebuilt_wire)
            .into_iter()
            .find(|candidate| candidate.code == snapshot.code)
            .expect("rebuilt child exists");
        assert_eq!(rebuilt_child.flags, snapshot.flags);
    }

    let canonical_data = vendor_child(WIRE_AVP_TRACE_DATA, &grouped_value(&canonical));
    let data_snapshot = snapshots(&canonical_data)
        .into_iter()
        .next()
        .expect("canonical Trace-Data exists");
    let mismatched_data = raw_avp(
        WIRE_AVP_TRACE_DATA,
        data_snapshot.flags ^ AvpFlags::MANDATORY,
        data_snapshot.vendor_id,
        &data_snapshot.value,
    );
    let data_wire = answer_wire(&[trace_info_with_children(&[mismatched_data])]);
    let data_envelope = parse_envelope(&data_wire).expect("Trace-Data M mismatch is ignored");
    let rebuilt_data =
        swm::build_swm_diameter_eap_answer_envelope(&data_envelope, EncodeContext::default())
            .expect("Trace-Data mismatch reencodes");
    let rebuilt_data_wire = encode(&rebuilt_data);
    let rebuilt_outer = snapshots(decode(&rebuilt_data_wire).raw_avps);
    let rebuilt_trace_info = rebuilt_outer
        .iter()
        .find(|avp| avp.code == WIRE_AVP_TRACE_INFO)
        .expect("rebuilt Trace-Info exists");
    let rebuilt_trace_data = snapshots(&rebuilt_trace_info.value)
        .into_iter()
        .find(|avp| avp.code == WIRE_AVP_TRACE_DATA)
        .expect("rebuilt Trace-Data exists");
    assert_eq!(rebuilt_trace_data.flags, data_snapshot.flags);

    let mismatched_info = raw_avp(
        WIRE_AVP_TRACE_INFO,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(WIRE_VENDOR_3GPP),
        &canonical_data,
    );
    let info_wire = answer_wire(&[mismatched_info]);
    let info_envelope = parse_envelope(&info_wire).expect("Trace-Info M mismatch is ignored");
    let rebuilt_info =
        swm::build_swm_diameter_eap_answer_envelope(&info_envelope, EncodeContext::default())
            .expect("Trace-Info mismatch reencodes");
    let rebuilt_info_wire = encode(&rebuilt_info);
    let rebuilt_info_snapshot = snapshots(decode(&rebuilt_info_wire).raw_avps)
        .into_iter()
        .find(|avp| avp.code == WIRE_AVP_TRACE_INFO)
        .expect("rebuilt Trace-Info exists");
    assert_eq!(rebuilt_info_snapshot.flags, AvpFlags::VENDOR);
}

#[test]
fn trace_cardinality_command_shape_misnesting_and_der_role_are_strict() {
    let children = activation_children(
        0,
        0x10,
        None,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        None,
        &[],
    );
    let activation = trace_info_activation(&children);
    assert!(parse(&answer_wire(&[activation.clone(), activation.clone()])).is_err());

    let mut duplicate_reference = children.clone();
    duplicate_reference.push(vendor_child(WIRE_AVP_TRACE_REFERENCE, &TRACE_REFERENCE));
    assert!(parse(&answer_wire(&[trace_info_activation(&duplicate_reference)])).is_err());

    let trace_data = vendor_child(WIRE_AVP_TRACE_DATA, &grouped_value(&children));
    let duplicate_data = trace_info_with_children(&[trace_data.clone(), trace_data.clone()]);
    assert!(parse(&answer_wire(&[duplicate_data])).is_err());

    let both = raw_avp(
        WIRE_AVP_TRACE_INFO,
        AvpFlags::VENDOR,
        Some(WIRE_VENDOR_3GPP),
        &grouped_value(&[
            trace_data,
            vendor_child(WIRE_AVP_TRACE_REFERENCE, &TRACE_REFERENCE),
        ]),
    );
    assert!(parse(&answer_wire(&[both])).is_err());

    let neither = raw_avp(
        WIRE_AVP_TRACE_INFO,
        AvpFlags::VENDOR,
        Some(WIRE_VENDOR_3GPP),
        &[],
    );
    assert!(parse(&answer_wire(&[neither])).is_err());

    assert!(parse(&answer_wire(&[vendor_child(
        WIRE_AVP_TRACE_DEPTH,
        &0_u32.to_be_bytes(),
    )]))
    .is_err());

    let mut nested_trace_info = children.clone();
    nested_trace_info.push(trace_info_deactivation());
    assert!(parse(&answer_wire(&[trace_info_activation(&nested_trace_info)])).is_err());

    let der = request_wire(Some(activation));
    assert!(swm::parse_swm_diameter_eap_request(
        &decode(&der),
        typed_context(UnknownIePolicy::Preserve),
    )
    .is_err());
}

#[test]
fn trace_data_requires_each_mandatory_child_and_valid_group_flags() {
    let canonical = activation_children(
        0,
        0x10,
        None,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        None,
        &[],
    );
    for missing in [
        WIRE_AVP_TRACE_REFERENCE,
        WIRE_AVP_TRACE_DEPTH,
        WIRE_AVP_TRACE_EVENT_LIST,
        WIRE_AVP_TRACE_COLLECTION_ENTITY,
    ] {
        let children = canonical
            .iter()
            .filter(|child| {
                snapshots(child)
                    .first()
                    .is_some_and(|snapshot| snapshot.code != missing)
            })
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            parse(&answer_wire(&[trace_info_activation(&children)])).is_err(),
            "missing mandatory child unexpectedly accepted"
        );
    }

    let trace_data_value = grouped_value(&canonical);
    for flags in [
        AvpFlags::VENDOR | AvpFlags::MANDATORY | AvpFlags::PROTECTED,
        AvpFlags::MANDATORY,
    ] {
        let vendor = (flags & AvpFlags::VENDOR != 0).then_some(WIRE_VENDOR_3GPP);
        let malformed_data = raw_avp(WIRE_AVP_TRACE_DATA, flags, vendor, &trace_data_value);
        let trace_info = trace_info_with_children(&[malformed_data]);
        assert!(parse(&answer_wire(&[trace_info])).is_err());
    }

    for duplicated in [
        WIRE_AVP_TRACE_REFERENCE,
        WIRE_AVP_TRACE_DEPTH,
        WIRE_AVP_TRACE_NE_TYPE_LIST,
        WIRE_AVP_TRACE_EVENT_LIST,
        WIRE_AVP_TRACE_COLLECTION_ENTITY,
    ] {
        let duplicate = canonical
            .iter()
            .find(|child| {
                snapshots(child)
                    .first()
                    .is_some_and(|snapshot| snapshot.code == duplicated)
            })
            .expect("canonical child exists")
            .clone();
        let mut children = canonical.clone();
        children.push(duplicate);
        assert!(parse(&answer_wire(&[trace_info_activation(&children)])).is_err());
    }

    let canonical_with_optional = activation_children(
        0,
        0x10,
        Some(0x40),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        Some(TRACE_URI),
        &[],
    );
    for duplicated in [
        WIRE_AVP_TRACE_INTERFACE_LIST,
        WIRE_AVP_TRACE_REPORTING_CONSUMER_URI,
    ] {
        let duplicate = canonical_with_optional
            .iter()
            .find(|child| {
                snapshots(child)
                    .first()
                    .is_some_and(|snapshot| snapshot.code == duplicated)
            })
            .expect("optional child exists")
            .clone();
        let mut children = canonical_with_optional.clone();
        children.push(duplicate);
        assert!(parse(&answer_wire(&[trace_info_activation(&children)])).is_err());
    }
}

#[test]
fn omitted_trace_ne_and_interface_lists_keep_their_standard_meanings() {
    let mut children = activation_children(
        0,
        0x10,
        None,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        None,
        &[],
    );
    children.retain(|child| {
        snapshots(child)
            .first()
            .is_some_and(|snapshot| snapshot.code != WIRE_AVP_TRACE_NE_TYPE_LIST)
    });
    let wire = answer_wire(&[trace_info_activation(&children)]);
    let correlated_response = correlated(&wire);
    let data = correlated_response
        .trace_info()
        .expect("trace exists")
        .data();
    assert!(!data.has_explicit_pdn_gateway_target());
    assert_eq!(data.interfaces(), None);

    let rebuilt = parse_envelope(&wire).expect("omitted optionals parse");
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_answer_envelope(&rebuilt, EncodeContext::default(),)
                .expect("omitted optionals replay")
        ),
        wire
    );
}

#[test]
fn nested_zero_vendor_ids_fail_before_known_or_unknown_dispatch() {
    let canonical = activation_children(
        0,
        0x10,
        None,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        None,
        &[],
    );
    let zero_vendor_unknown = raw_avp(
        UNKNOWN_CHILD,
        AvpFlags::VENDOR,
        Some(VendorId::new(0)),
        &[1],
    );

    let trace_data = vendor_child(WIRE_AVP_TRACE_DATA, &grouped_value(&canonical));
    let outer_wire = answer_wire(&[trace_info_with_children(&[
        trace_data,
        zero_vendor_unknown.clone(),
    ])]);
    let mut inner = canonical;
    inner.push(zero_vendor_unknown);
    let inner_wire = answer_wire(&[trace_info_activation(&inner)]);

    for policy in [
        UnknownIePolicy::Drop,
        UnknownIePolicy::Preserve,
        UnknownIePolicy::Reject,
    ] {
        for wire in [&outer_wire, &inner_wire] {
            let error = parse_with_context(wire, typed_context(policy))
                .expect_err("zero nested Vendor-Id must fail under every unknown policy");
            assert!(matches!(
                error.code(),
                opc_protocol::DecodeErrorCode::Structural { .. }
            ));
            assert_eq!(
                error.spec_ref().map(opc_protocol::SpecRef::section),
                Some("4.1.1")
            );
        }
    }
}

#[test]
fn unknown_duplicate_policy_is_per_scope_vendor_aware_and_drop_safe() {
    let duplicate_a = raw_avp(UNKNOWN_CHILD, 0, None, &[1]);
    let duplicate_b = raw_avp(UNKNOWN_CHILD, 0, None, &[2]);
    let foreign_same_code = raw_avp(UNKNOWN_CHILD, AvpFlags::VENDOR, Some(FOREIGN_VENDOR), &[3]);
    let canonical = activation_children(
        0,
        0x10,
        None,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        None,
        &[duplicate_a.clone(), duplicate_b.clone()],
    );
    let inner_duplicate_wire = answer_wire(&[trace_info_activation(&canonical)]);
    let trace_data = vendor_child(
        WIRE_AVP_TRACE_DATA,
        &grouped_value(&activation_children(
            0,
            0x10,
            None,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            None,
            &[],
        )),
    );
    let outer_duplicate_wire = answer_wire(&[trace_info_with_children(&[
        trace_data.clone(),
        duplicate_a.clone(),
        duplicate_b.clone(),
    ])]);

    for policy in [UnknownIePolicy::Drop, UnknownIePolicy::Preserve] {
        for wire in [&inner_duplicate_wire, &outer_duplicate_wire] {
            let error = parse_with_context(wire, typed_context(policy))
                .expect_err("duplicate unknown key must be rejected");
            assert!(matches!(
                error.code(),
                opc_protocol::DecodeErrorCode::DuplicateIe
            ));
        }
    }

    let vendor_aware_outer_wire = answer_wire(&[trace_info_with_children(&[
        trace_data,
        duplicate_a.clone(),
        foreign_same_code.clone(),
    ])]);
    let vendor_aware_inner_wire = answer_wire(&[trace_info_activation(&activation_children(
        0,
        0x10,
        None,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        None,
        &[duplicate_a, foreign_same_code],
    ))]);
    for wire in [&vendor_aware_outer_wire, &vendor_aware_inner_wire] {
        let parsed = parse_with_context(wire, typed_context(UnknownIePolicy::Preserve))
            .expect("same code under different vendor identities is not a duplicate key");
        assert!(parsed.has_trace_info());
    }

    for duplicate_policy in [DuplicateIePolicy::First, DuplicateIePolicy::Last] {
        for wire in [&outer_duplicate_wire, &inner_duplicate_wire] {
            let mut context = typed_context(UnknownIePolicy::Preserve);
            context.duplicate_ie_policy = duplicate_policy;
            let envelope = swm::parse_swm_diameter_eap_answer_envelope(&decode(wire), context)
                .expect("non-rejecting duplicate policy preserves unknown wire order");
            assert_eq!(
                encode(
                    &swm::build_swm_diameter_eap_answer_envelope(
                        &envelope,
                        EncodeContext::default(),
                    )
                    .expect("preserved order replays")
                ),
                *wire
            );
        }
    }
}

#[test]
fn nested_unknown_policy_and_allocation_limits_are_enforced() {
    let optional_unknown = raw_avp(UNKNOWN_CHILD, 0, None, &[0x10, 0x20, 0x30]);
    let children = activation_children(
        0,
        0x10,
        None,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        None,
        std::slice::from_ref(&optional_unknown),
    );
    let wire = answer_wire(&[trace_info_activation(&children)]);

    let preserved = parse_envelope(&wire).expect("optional unknown child is retained");
    let correlated_response = correlated(&wire);
    let data = correlated_response
        .trace_info()
        .expect("trace exists")
        .data();
    assert_eq!(data.additional_avp_count(), 1);
    let replay = swm::build_swm_diameter_eap_answer_envelope(&preserved, EncodeContext::default())
        .expect("preserved unknown child replays through sealed envelope");
    assert_eq!(encode(&replay), wire);

    let ignored = parse_with_context(&wire, typed_context(UnknownIePolicy::Drop))
        .expect("optional unknown child can be ignored");
    assert!(ignored.has_trace_info());
    assert!(parse_with_context(&wire, typed_context(UnknownIePolicy::Reject)).is_err());

    let outer_trace_data = vendor_child(
        WIRE_AVP_TRACE_DATA,
        &grouped_value(&activation_children(
            0,
            0x10,
            None,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            None,
            &[],
        )),
    );
    let outer_wire = answer_wire(&[trace_info_with_children(&[
        outer_trace_data.clone(),
        optional_unknown.clone(),
    ])]);
    let outer_envelope = parse_envelope(&outer_wire).expect("outer optional child is retained");
    assert_eq!(
        correlated(&outer_wire)
            .trace_info()
            .expect("trace exists")
            .additional_avp_count(),
        1
    );
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_answer_envelope(
                &outer_envelope,
                EncodeContext::default(),
            )
            .expect("outer optional child replays")
        ),
        outer_wire
    );
    assert!(
        parse_with_context(&outer_wire, typed_context(UnknownIePolicy::Drop))
            .expect("outer optional child can be dropped")
            .has_trace_info()
    );
    assert!(parse_with_context(&outer_wire, typed_context(UnknownIePolicy::Reject)).is_err());

    let mandatory_unknown = raw_avp(UNKNOWN_CHILD, AvpFlags::MANDATORY, None, &[1]);
    let mandatory_wire = answer_wire(&[trace_info_activation(&activation_children(
        0,
        0x10,
        None,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        None,
        &[mandatory_unknown],
    ))]);
    assert!(parse_with_context(&mandatory_wire, typed_context(UnknownIePolicy::Preserve)).is_err());
    assert!(parse_with_context(&mandatory_wire, typed_context(UnknownIePolicy::Drop)).is_err());

    let outer_mandatory_wire = answer_wire(&[trace_info_with_children(&[
        raw_avp(UNKNOWN_CHILD, AvpFlags::MANDATORY, None, &[1]),
        outer_trace_data,
    ])]);
    assert!(parse_with_context(
        &outer_mandatory_wire,
        typed_context(UnknownIePolicy::Preserve),
    )
    .is_err());
    assert!(
        parse_with_context(&outer_mandatory_wire, typed_context(UnknownIePolicy::Drop),).is_err()
    );

    let mut depth_context = typed_context(UnknownIePolicy::Preserve);
    depth_context.max_depth = 1;
    assert!(parse_with_context(&wire, depth_context).is_err());

    let two_unknown = [
        raw_avp(UNKNOWN_CHILD, 0, None, &[1]),
        raw_avp(AvpCode::new(900_353), 0, None, &[2]),
    ];
    let ie_wire = answer_wire(&[trace_info_activation(&activation_children(
        0,
        0x10,
        Some(0x40),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        Some(TRACE_URI),
        &two_unknown,
    ))]);
    let mut ie_context = typed_context(UnknownIePolicy::Preserve);
    ie_context.max_ies = 8;
    assert!(parse_with_context(&ie_wire, ie_context).is_err());

    let many_unknown = (0_u32..129)
        .map(|index| raw_avp(AvpCode::new(901_000 + index), 0, None, &[1]))
        .collect::<Vec<_>>();
    let retained_wire = answer_wire(&[trace_info_activation(&activation_children(
        0,
        0x10,
        None,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        None,
        &many_unknown,
    ))]);
    assert!(parse(&retained_wire).is_err());
}

#[test]
fn trace_values_cross_only_authenticated_correlation_and_cannot_be_transplanted() {
    let activation = activation_fixture(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
    let wire = answer_wire(std::slice::from_ref(&activation));
    let raw = response_envelope(&wire, CONNECTION);
    let swm::SwmDiameterEapResponse::Application(raw_answer) = raw.response() else {
        panic!("ordinary DEA parsed as generic error");
    };
    assert!(raw_answer.has_trace_info());
    let raw_diagnostic = format!("{raw_answer:?}");

    let directly_parsed = parse(&wire).expect("ordinary typed answer parses");
    let direct_rebuild_error = swm::build_swm_diameter_eap_answer(
        &directly_parsed.clone(),
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .expect_err("a parsed answer clone is not an origination authority");
    assert!(matches!(
        direct_rebuild_error.code(),
        opc_protocol::EncodeErrorCode::Structural { .. }
    ));
    let parsed_envelope = parse_envelope(&wire).expect("parsed envelope retains replay authority");
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_answer_envelope(
                &parsed_envelope,
                EncodeContext::default(),
            )
            .expect("sealed parsed envelope replays")
        ),
        wire
    );

    let correlated_response = bound_request()
        .correlate_response(raw)
        .expect("complete authenticated evidence matches");
    let received = correlated_response
        .trace_info()
        .expect("correlated typed trace data is available")
        .clone();

    let mut originated_answer = successful_answer();
    let error = originated_answer
        .set_trace_info(received.clone())
        .expect_err("received trace cannot be re-originated");
    assert_eq!(error, swm::SwmTraceValueError::InvalidReplayProvenance);

    let received_data = received.data();
    assert_eq!(
        swm::SwmTraceInfo::activation(received_data.clone())
            .expect_err("received data provenance survives clone"),
        swm::SwmTraceValueError::InvalidReplayProvenance
    );
    assert_eq!(
        swm::SwmTraceData::new(
            received_data.trace_reference().clone(),
            swm::SwmTraceDepth::Minimum,
            swm::SwmPgwTraceEvents::new(false, false, false),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        )
        .expect_err("received reference provenance survives clone"),
        swm::SwmTraceValueError::InvalidReplayProvenance
    );
    let fresh_data = swm::SwmTraceData::new(
        swm::SwmTraceReference::new(TRACE_REFERENCE).expect("originated reference"),
        swm::SwmTraceDepth::Minimum,
        swm::SwmPgwTraceEvents::new(false, false, false),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
    )
    .expect("originated trace data");
    assert_eq!(
        fresh_data
            .with_reporting_consumer_uri(
                received_data
                    .reporting_consumer_uri()
                    .expect("received URI exists")
                    .clone(),
            )
            .expect_err("received URI provenance survives clone"),
        swm::SwmTraceValueError::InvalidReplayProvenance
    );

    let reconstructed_reference =
        swm::SwmTraceReference::new(received_data.trace_reference().octets())
            .expect("caller explicitly revalidates received trace identity");
    let reconstructed_uri = swm::SwmTraceReportingConsumerUri::new(
        received_data
            .reporting_consumer_uri()
            .expect("received URI exists")
            .as_str(),
    )
    .expect("caller explicitly revalidates received endpoint");
    let reconstructed_data = swm::SwmTraceData::new(
        reconstructed_reference,
        received_data.depth(),
        received_data.events(),
        received_data.collection_entity(),
    )
    .expect("explicit reconstruction creates an originated value")
    .with_explicit_pdn_gateway_target()
    .with_interfaces(
        received_data
            .interfaces()
            .expect("received interfaces exist"),
    )
    .with_reporting_consumer_uri(reconstructed_uri)
    .expect("explicitly reconstructed URI is originated");
    let mut explicitly_authorized_answer = successful_answer();
    explicitly_authorized_answer
        .set_trace_info(
            swm::SwmTraceInfo::activation(reconstructed_data)
                .expect("explicitly reconstructed activation"),
        )
        .expect("caller-authorized fresh trace may be originated");

    assert_eq!(
        bound_request()
            .correlate_response(response_envelope(&wire, OTHER_CONNECTION))
            .expect_err("connection generation mismatch fails closed"),
        swm::SwmDiameterEapCorrelationError::PeerConnectionMismatch
    );
    let wrong_transaction = answer_wire_with(
        std::slice::from_ref(&activation),
        HOP_BY_HOP ^ 1,
        END_TO_END,
        AAA_HOST,
    );
    assert_eq!(
        bound_request()
            .correlate_response(response_envelope(&wrong_transaction, CONNECTION))
            .expect_err("transaction mismatch fails closed"),
        swm::SwmDiameterEapCorrelationError::TransactionMismatch
    );
    let wrong_origin = answer_wire_with(
        std::slice::from_ref(&activation),
        HOP_BY_HOP,
        END_TO_END,
        b"other-aaa.synthetic.invalid",
    );
    assert_eq!(
        bound_request()
            .correlate_response(response_envelope(&wrong_origin, CONNECTION))
            .expect_err("logical origin mismatch fails closed"),
        swm::SwmDiameterEapCorrelationError::PeerIdentityMismatch
    );

    let diagnostics =
        format!("{raw_diagnostic} {correlated_response:?} {received:?} {error:?} {error}");
    for sensitive in ["198.51.100.9", "trace.synthetic.invalid", "aabbcc"] {
        assert!(!diagnostics.contains(sensitive));
    }
    for action_state in ["Activate", "Deactivate", "SwmTraceAction"] {
        assert!(!diagnostics.contains(action_state));
    }
}

#[test]
fn correlated_trace_presence_does_not_replace_diameter_result_policy() {
    let activation = activation_fixture(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));
    let wire = answer_wire_with_result(
        std::slice::from_ref(&activation),
        HOP_BY_HOP,
        END_TO_END,
        AAA_HOST,
        base::RESULT_CODE_DIAMETER_AUTHORIZATION_REJECTED,
    );
    let correlated = correlated(&wire);
    assert!(correlated.trace_info().is_some());
    let swm::SwmDiameterEapResponse::Application(answer) = correlated.response() else {
        panic!("ordinary application answer expected");
    };
    assert!(answer.result.is_diameter_authorization_rejected());
}

#[test]
fn trace_dictionary_definitions_and_command_roles_match_the_typed_boundary() {
    assert_eq!(opc_proto_diameter::apps::VENDOR_ID_3GPP, WIRE_VENDOR_3GPP);
    assert_eq!(swm::AVP_TRACE_INFO, WIRE_AVP_TRACE_INFO);
    assert_eq!(swm::AVP_TRACE_DATA, WIRE_AVP_TRACE_DATA);
    assert_eq!(swm::AVP_TRACE_REFERENCE, WIRE_AVP_TRACE_REFERENCE);
    assert_eq!(swm::AVP_TRACE_DEPTH, WIRE_AVP_TRACE_DEPTH);
    assert_eq!(swm::AVP_TRACE_NE_TYPE_LIST, WIRE_AVP_TRACE_NE_TYPE_LIST);
    assert_eq!(swm::AVP_TRACE_INTERFACE_LIST, WIRE_AVP_TRACE_INTERFACE_LIST);
    assert_eq!(swm::AVP_TRACE_EVENT_LIST, WIRE_AVP_TRACE_EVENT_LIST);
    assert_eq!(
        swm::AVP_TRACE_COLLECTION_ENTITY,
        WIRE_AVP_TRACE_COLLECTION_ENTITY
    );
    assert_eq!(
        swm::AVP_TRACE_REPORTING_CONSUMER_URI,
        WIRE_AVP_TRACE_REPORTING_CONSUMER_URI
    );

    let dictionary = swm::dictionary();
    let trace_key = AvpKey::vendor(swm::AVP_TRACE_INFO, WIRE_VENDOR_3GPP);
    let trace = dictionary
        .find_avp(trace_key)
        .expect("Trace-Info is registered");
    assert_eq!(trace.data_type(), AvpDataType::Grouped);
    assert_eq!(trace.flags().vendor(), FlagRequirement::MustBeSet);
    assert_eq!(trace.flags().mandatory(), FlagRequirement::MustBeUnset);
    assert_eq!(trace.flags().protected(), FlagRequirement::MustBeUnset);
    assert_eq!(trace.grouped_avp_rules().len(), 1);

    let data = dictionary
        .find_avp(AvpKey::vendor(swm::AVP_TRACE_DATA, WIRE_VENDOR_3GPP))
        .expect("Trace-Data is registered");
    assert_eq!(data.data_type(), AvpDataType::Grouped);
    assert_eq!(data.grouped_avp_rules().len(), 7);
    let uri = dictionary
        .find_avp(AvpKey::vendor(
            swm::AVP_TRACE_REPORTING_CONSUMER_URI,
            WIRE_VENDOR_3GPP,
        ))
        .expect("Trace-Reporting-Consumer-Uri is registered");
    assert_eq!(uri.data_type(), AvpDataType::DiameterUri);
    assert_eq!(uri.flags().mandatory(), FlagRequirement::MustBeUnset);

    let der = dictionary
        .find_command(
            swm::APPLICATION_ID,
            swm::COMMAND_DIAMETER_EAP,
            CommandKind::Request,
        )
        .expect("DER command is registered");
    assert_eq!(
        der.find_avp_rule(trace_key)
            .expect("DER trace rule exists")
            .cardinality(),
        AvpCardinality::Forbidden
    );
    let dea = dictionary
        .find_command(
            swm::APPLICATION_ID,
            swm::COMMAND_DIAMETER_EAP,
            CommandKind::Answer,
        )
        .expect("DEA command is registered");
    assert_eq!(
        dea.find_avp_rule(trace_key)
            .expect("DEA trace rule exists")
            .cardinality(),
        AvpCardinality::ZeroOrOne
    );
    let projected = swm::projected_profile_dictionary()
        .find_command(
            swm::APPLICATION_ID,
            swm::COMMAND_DIAMETER_EAP,
            CommandKind::Answer,
        )
        .expect("projected DEA command is registered");
    assert_eq!(
        projected
            .find_avp_rule(trace_key)
            .expect("projected DEA trace rule exists")
            .cardinality(),
        AvpCardinality::ZeroOrOne
    );
}
