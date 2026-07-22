#![cfg(feature = "app-swm")]

use std::num::NonZeroU64;

use bytes::{Bytes, BytesMut};
use opc_proto_diameter::apps::{
    swm::{
        self, AuthRequestType, SwmAccessNetworkInfo, SwmAccessNetworkLocatorEvidence,
        SwmAccessNetworkLocatorStatus, SwmAccessNetworkOperatorName,
        SwmAccessNetworkOperatorNamespace, SwmBasicServiceSetIdentifier, SwmCivicAddress,
        SwmCivicAddressElement, SwmCivicLocationData, SwmCivicLocationInformation,
        SwmCorrelatedDiameterEapResponse, SwmDiameterConnectionToken, SwmDiameterEapAnswer,
        SwmDiameterEapAnswerEnvelope, SwmDiameterEapCorrelationError,
        SwmDiameterEapRequestEnvelope, SwmDiameterEapResponse, SwmDiameterEapResponseEnvelope,
        SwmDiameterResult, SwmExpectedAnswerPeer, SwmLocationContextErrorCode, SwmLocationEntity,
        SwmLocationMethod, SwmLogicalAccessId, SwmNtpTimestamp64, SwmUserLocationInfoTime,
        SwmUserLocationInfoTimeOmission, SwmWlanSsid,
    },
    VENDOR_ID_3GPP,
};
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

const HOP_BY_HOP: u32 = 0x0102_0304;
const END_TO_END: u32 = 0x1122_3344;
const SESSION_ID: &[u8] = b"session;synthetic;dea-location";
const AAA_HOST: &[u8] = b"aaa.synthetic.invalid";
const AAA_REALM: &[u8] = b"home.synthetic.invalid";
const EPDG_HOST: &[u8] = b"epdg.synthetic.invalid";
const EPDG_REALM: &[u8] = b"visited.synthetic.invalid";
const CONNECTION: SwmDiameterConnectionToken = SwmDiameterConnectionToken::new(NonZeroU64::MIN);
const OTHER_CONNECTION: SwmDiameterConnectionToken = SwmDiameterConnectionToken::new(
    NonZeroU64::new(2).expect("synthetic connection token is nonzero"),
);
const LOCATION_INDEX: u16 = 0x1020;
const UNKNOWN_CHILD: AvpCode = AvpCode::new(900_120);
const FOREIGN_VENDOR: VendorId = VendorId::new(42_424);

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

fn location_information(index: u16, code: u8, method: &[u8]) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend_from_slice(&index.to_be_bytes());
    value.push(code);
    value.push(1);
    value.extend_from_slice(&0x0102_0304_0506_0708_u64.to_be_bytes());
    value.extend_from_slice(&0x1112_1314_1516_1718_u64.to_be_bytes());
    value.extend_from_slice(method);
    value
}

fn location_data(index: u16) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend_from_slice(&index.to_be_bytes());
    value.extend_from_slice(b"CA");
    value.extend_from_slice(&[3, 9]);
    value.extend_from_slice(b"Testville");
    value.extend_from_slice(&[19, 8]);
    value.extend_from_slice(b"Main St.");
    value
}

fn location_data_with_element(index: u16, civic_address_type: u8, element: &[u8]) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend_from_slice(&index.to_be_bytes());
    value.extend_from_slice(b"CA");
    value.push(civic_address_type);
    value.push(u8::try_from(element.len()).expect("synthetic civic element fits one octet"));
    value.extend_from_slice(element);
    value
}

fn access_children(
    include_information: bool,
    include_data: bool,
    unknown_flags: Option<u8>,
) -> Vec<Vec<u8>> {
    let mut children = vec![
        raw_avp(
            swm::AVP_SSID,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            b"synthetic-wlan",
        ),
        raw_avp(
            swm::AVP_BSSID,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            b"02-AB-CD-EF-00-01",
        ),
    ];
    if include_information {
        children.push(raw_avp(
            swm::AVP_LOCATION_INFORMATION,
            0,
            None,
            &location_information(LOCATION_INDEX, 0, b"802.11"),
        ));
    }
    if include_data {
        children.push(raw_avp(
            swm::AVP_LOCATION_DATA,
            0,
            None,
            &location_data(LOCATION_INDEX),
        ));
    }
    children.extend([
        raw_avp(swm::AVP_OPERATOR_NAME, 0, None, b"1synthetic.invalid"),
        raw_avp(
            swm::AVP_LOGICAL_ACCESS_ID,
            AvpFlags::VENDOR,
            Some(swm::VENDOR_ID_ETSI),
            b"circuit-synthetic-1",
        ),
    ]);
    if let Some(flags) = unknown_flags {
        children.push(raw_avp(UNKNOWN_CHILD, flags, None, &[0x10, 0x20, 0x30]));
    }
    children
}

fn access_avp_with(children: &[Vec<u8>], flags: u8, vendor_id: Option<VendorId>) -> Vec<u8> {
    let mut value = Vec::new();
    for child in children {
        value.extend_from_slice(child);
    }
    raw_avp(swm::AVP_ACCESS_NETWORK_INFO, flags, vendor_id, &value)
}

fn canonical_access_avp(unknown_flags: Option<u8>) -> Vec<u8> {
    access_avp_with(
        &access_children(true, true, unknown_flags),
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
    )
}

fn answer_avps_with(extras: &[Vec<u8>], session_id: &[u8], origin_host: &[u8]) -> Vec<u8> {
    let mut raw = Vec::new();
    for avp in [
        raw_avp(base::AVP_SESSION_ID, AvpFlags::MANDATORY, None, session_id),
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
            &3_u32.to_be_bytes(),
        ),
        raw_avp(
            base::AVP_RESULT_CODE,
            AvpFlags::MANDATORY,
            None,
            &base::RESULT_CODE_DIAMETER_SUCCESS.to_be_bytes(),
        ),
        raw_avp(
            base::AVP_ORIGIN_HOST,
            AvpFlags::MANDATORY,
            None,
            origin_host,
        ),
        raw_avp(base::AVP_ORIGIN_REALM, AvpFlags::MANDATORY, None, AAA_REALM),
    ] {
        raw.extend_from_slice(&avp);
    }
    for extra in extras {
        raw.extend_from_slice(extra);
    }
    raw.extend_from_slice(&raw_avp(
        swm::AVP_EAP_PAYLOAD,
        AvpFlags::MANDATORY,
        None,
        &[3, 9, 0, 4],
    ));
    raw
}

fn answer_wire(extras: &[Vec<u8>]) -> Vec<u8> {
    answer_wire_with(extras, HOP_BY_HOP, END_TO_END, SESSION_ID, AAA_HOST, true)
}

fn answer_wire_with(
    extras: &[Vec<u8>],
    hop_by_hop: u32,
    end_to_end: u32,
    session_id: &[u8],
    origin_host: &[u8],
    proxiable: bool,
) -> Vec<u8> {
    let message = OwnedMessage {
        header: Header::new(
            CommandFlags::answer(proxiable, false),
            swm::COMMAND_DIAMETER_EAP,
            swm::APPLICATION_ID,
            hop_by_hop,
            end_to_end,
        ),
        raw_avps: Bytes::from(answer_avps_with(extras, session_id, origin_host)),
    };
    encode(&message)
}

fn request_wire() -> Vec<u8> {
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

fn typed_context(unknown_ie_policy: UnknownIePolicy) -> DecodeContext {
    DecodeContext {
        max_ies: 512,
        max_message_len: 256 * 1024,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        unknown_ie_policy,
        ..DecodeContext::conservative()
    }
}

fn decode(wire: &[u8]) -> Message<'_> {
    let (tail, message) =
        Message::decode(wire, framing_context()).expect("synthetic Diameter framing");
    assert!(tail.is_empty());
    message
}

fn parse_with_policy(
    wire: &[u8],
    unknown_ie_policy: UnknownIePolicy,
) -> Result<SwmDiameterEapAnswer, DecodeError> {
    swm::parse_swm_diameter_eap_answer(&decode(wire), typed_context(unknown_ie_policy))
}

fn parse(wire: &[u8]) -> Result<SwmDiameterEapAnswer, DecodeError> {
    parse_with_policy(wire, UnknownIePolicy::Preserve)
}

fn parse_envelope(wire: &[u8]) -> Result<SwmDiameterEapAnswerEnvelope, DecodeError> {
    swm::parse_swm_diameter_eap_answer_envelope(
        &decode(wire),
        typed_context(UnknownIePolicy::Preserve),
    )
}

fn bound_request() -> SwmDiameterEapRequestEnvelope {
    let wire = request_wire();
    let message = decode(&wire);
    swm::parse_swm_diameter_eap_request_envelope(&message, typed_context(UnknownIePolicy::Preserve))
        .expect("synthetic DER parses")
        .with_expected_answer_peer(SwmExpectedAnswerPeer::direct(
            CONNECTION,
            String::from_utf8(AAA_HOST.to_vec()).expect("ASCII host"),
            String::from_utf8(AAA_REALM.to_vec()).expect("ASCII realm"),
        ))
}

fn correlated_with_policy(
    wire: &[u8],
    unknown_ie_policy: UnknownIePolicy,
) -> Result<SwmCorrelatedDiameterEapResponse, DecodeError> {
    let response = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(wire),
        CONNECTION,
        typed_context(unknown_ie_policy),
    )?;
    Ok(bound_request()
        .correlate_response(response)
        .expect("synthetic authenticated response correlates"))
}

fn response_envelope(
    wire: &[u8],
    connection: SwmDiameterConnectionToken,
) -> SwmDiameterEapResponseEnvelope {
    swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(wire),
        connection,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("synthetic authenticated response parses")
}

fn correlated(wire: &[u8]) -> SwmCorrelatedDiameterEapResponse {
    correlated_with_policy(wire, UnknownIePolicy::Preserve)
        .expect("synthetic authenticated response parses")
}

fn assert_spec_ref(error: &DecodeError, body: &str, document: &str, section: &str) {
    let spec = error.spec_ref().expect("decode error carries SpecRef");
    assert_eq!(spec.body(), body);
    assert_eq!(spec.doc(), document);
    assert_eq!(spec.section(), section);
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

fn typed_access() -> SwmAccessNetworkInfo {
    let address = SwmCivicAddress::try_new(
        *b"CA",
        vec![
            SwmCivicAddressElement::try_new(3, "Testville").expect("synthetic city is valid"),
            SwmCivicAddressElement::try_new(19, "Main St.").expect("synthetic street is valid"),
        ],
    )
    .expect("synthetic civic address is valid");
    let information = SwmCivicLocationInformation::new(
        LOCATION_INDEX,
        SwmLocationEntity::AccessNetwork,
        SwmNtpTimestamp64::from_bits(0x0102_0304_0506_0708),
        SwmNtpTimestamp64::from_bits(0x1112_1314_1516_1718),
        SwmLocationMethod::try_new("802.11").expect("registered method shape is valid"),
    );
    let data = SwmCivicLocationData::new(LOCATION_INDEX, address);
    let bssid = SwmBasicServiceSetIdentifier::try_from_octets([0x02, 0xab, 0xcd, 0xef, 0, 1])
        .expect("synthetic BSSID is valid");
    SwmAccessNetworkInfo::try_new(
        SwmWlanSsid::try_new("synthetic-wlan").expect("synthetic SSID is valid"),
        SwmAccessNetworkLocatorEvidence::Bssid(bssid),
    )
    .expect("initial BSSID evidence is valid")
    .with_civic_location(information, data)
    .expect("matching civic association is valid")
    .with_operator_name(
        SwmAccessNetworkOperatorName::try_realm("synthetic.invalid")
            .expect("synthetic realm is valid"),
    )
    .with_logical_access_id(
        SwmLogicalAccessId::try_new(b"circuit-synthetic-1".to_vec())
            .expect("synthetic logical access id is valid"),
    )
}

fn successful_answer() -> SwmDiameterEapAnswer {
    let mut answer = SwmDiameterEapAnswer {
        session_id: "session;synthetic;dea-location".into(),
        auth_application_id: swm::APPLICATION_ID.get(),
        auth_request_type: AuthRequestType::AuthorizeAuthenticate,
        result: SwmDiameterResult::Base(base::RESULT_CODE_DIAMETER_SUCCESS),
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
        authorization_lifetime: None,
        auth_grace_period: None,
        re_auth_request_type: None,
        eap_payload: Some(vec![3, 9, 0, 4].into()),
        eap_reissued_payload: None,
        error_message: None,
        state_avps: Vec::new(),
        eap_master_session_key: None,
        extensions: Default::default(),
    };
    answer
        .set_wlan_location_with_time(
            typed_access(),
            SwmUserLocationInfoTime::from_ntp_seconds(0x2021_2223),
        )
        .expect("synthetic originated WLAN location is valid");
    answer
}

#[test]
fn independent_dea_fixture_round_trips_all_location_children_and_time() {
    let access = canonical_access_avp(Some(0));
    let timestamp = raw_avp(
        swm::AVP_USER_LOCATION_INFO_TIME,
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
        &0x2021_2223_u32.to_be_bytes(),
    );
    let wire = answer_wire(&[access, timestamp]);

    let envelope = parse_envelope(&wire).expect("standards-authored DEA location fixture parses");
    let answer = envelope.answer();
    assert!(answer.has_wlan_location());
    assert!(answer.has_wlan_location_time());
    let correlated = correlated(&wire);
    let location = correlated
        .wlan_location()
        .expect("correlated WLAN location is present");
    let parsed = location.access_network_info();
    assert_eq!(parsed.ssid().as_str(), "synthetic-wlan");
    assert_eq!(
        parsed.bssid().map(SwmBasicServiceSetIdentifier::octets),
        Some([0x02, 0xab, 0xcd, 0xef, 0, 1])
    );
    assert_eq!(
        parsed
            .location_information()
            .map(SwmCivicLocationInformation::index),
        Some(LOCATION_INDEX)
    );
    assert_eq!(
        parsed.location_data().map(SwmCivicLocationData::index),
        Some(LOCATION_INDEX)
    );
    assert_eq!(
        parsed.operator_name().map(|value| value.value()),
        Some("synthetic.invalid")
    );
    assert_eq!(
        parsed.logical_access_id().map(SwmLogicalAccessId::as_bytes),
        Some(b"circuit-synthetic-1".as_slice())
    );
    assert_eq!(parsed.extensions().len(), 1);
    let metadata = parsed
        .extensions()
        .metadata()
        .next()
        .expect("unknown optional child retained");
    assert_eq!(metadata.code(), UNKNOWN_CHILD);
    assert_eq!(metadata.value_len(), 3);
    assert_eq!(
        location
            .user_location_info_time()
            .map(SwmUserLocationInfoTime::ntp_seconds),
        Some(0x2021_2223)
    );

    let rebuilt = swm::build_swm_diameter_eap_answer_envelope(&envelope, EncodeContext::default())
        .expect("sealed parsed location answer rebuilds");
    assert_eq!(encode(&rebuilt), wire);
}

#[test]
fn location_values_cross_only_the_fully_correlated_response_boundary() {
    let extras = [
        canonical_access_avp(None),
        raw_avp(
            swm::AVP_USER_LOCATION_INFO_TIME,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            &0x2021_2223_u32.to_be_bytes(),
        ),
    ];
    let wire = answer_wire(&extras);
    let raw = response_envelope(&wire, CONNECTION);
    let SwmDiameterEapResponse::Application(raw_answer) = raw.response() else {
        panic!("synthetic ordinary DEA parsed as a generic error");
    };
    assert!(raw_answer.has_wlan_location());
    assert!(raw_answer.has_wlan_location_time());

    let correlated = bound_request()
        .correlate_response(raw)
        .expect("all authenticated correlation evidence matches");
    let location = correlated
        .wlan_location()
        .expect("location is disclosed after correlation");
    assert_eq!(
        location.access_network_info().ssid().as_str(),
        "synthetic-wlan"
    );
    assert_eq!(
        location
            .user_location_info_time()
            .map(SwmUserLocationInfoTime::ntp_seconds),
        Some(0x2021_2223),
    );

    assert_eq!(
        bound_request()
            .correlate_response(response_envelope(&wire, OTHER_CONNECTION))
            .expect_err("connection generation mismatch fails closed"),
        SwmDiameterEapCorrelationError::PeerConnectionMismatch,
    );

    let wrong_transaction = answer_wire_with(
        &extras,
        HOP_BY_HOP ^ 1,
        END_TO_END,
        SESSION_ID,
        AAA_HOST,
        true,
    );
    assert_eq!(
        bound_request()
            .correlate_response(response_envelope(&wrong_transaction, CONNECTION))
            .expect_err("transaction mismatch fails closed"),
        SwmDiameterEapCorrelationError::TransactionMismatch,
    );

    let wrong_origin = answer_wire_with(
        &extras,
        HOP_BY_HOP,
        END_TO_END,
        SESSION_ID,
        b"other-aaa.synthetic.invalid",
        true,
    );
    assert_eq!(
        bound_request()
            .correlate_response(response_envelope(&wrong_origin, CONNECTION))
            .expect_err("logical Origin mismatch fails closed"),
        SwmDiameterEapCorrelationError::PeerIdentityMismatch,
    );

    let wrong_session = answer_wire_with(
        &extras,
        HOP_BY_HOP,
        END_TO_END,
        b"session;synthetic;wrong",
        AAA_HOST,
        true,
    );
    assert_eq!(
        bound_request()
            .correlate_response(response_envelope(&wrong_session, CONNECTION))
            .expect_err("Session-Id mismatch fails closed"),
        SwmDiameterEapCorrelationError::SessionMismatch,
    );

    let wrong_proxiable =
        answer_wire_with(&extras, HOP_BY_HOP, END_TO_END, SESSION_ID, AAA_HOST, false);
    let error = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wrong_proxiable),
        CONNECTION,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("ordinary DEA P-bit mismatch fails before correlation");
    assert_eq!(error.offset(), 4);
    assert_spec_ref(&error, "3gpp", "TS29273", "DEA");
}

#[test]
fn typed_builder_emits_canonical_codes_vendors_flags_order_and_bytes() {
    let built = swm::build_swm_diameter_eap_answer(
        &successful_answer(),
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .expect("typed answer builds");
    let top_level = snapshots(&built.raw_avps);
    let access = top_level
        .iter()
        .find(|avp| avp.code == swm::AVP_ACCESS_NETWORK_INFO)
        .expect("Access-Network-Info emitted");
    assert_eq!(access.vendor_id, Some(VENDOR_ID_3GPP));
    assert_eq!(access.flags, AvpFlags::VENDOR);
    let children = snapshots(&access.value);
    assert_eq!(
        children
            .iter()
            .map(|avp| (avp.code, avp.vendor_id, avp.flags))
            .collect::<Vec<_>>(),
        vec![
            (swm::AVP_SSID, Some(VENDOR_ID_3GPP), AvpFlags::VENDOR,),
            (
                swm::AVP_BSSID,
                Some(VENDOR_ID_3GPP),
                AvpFlags::VENDOR | AvpFlags::MANDATORY,
            ),
            (swm::AVP_LOCATION_INFORMATION, None, 0),
            (swm::AVP_LOCATION_DATA, None, 0),
            (swm::AVP_OPERATOR_NAME, None, 0),
            (
                swm::AVP_LOGICAL_ACCESS_ID,
                Some(swm::VENDOR_ID_ETSI),
                AvpFlags::VENDOR,
            ),
        ]
    );
    assert_eq!(children[0].value, b"synthetic-wlan");
    assert_eq!(children[1].value, b"02-AB-CD-EF-00-01");
    assert_eq!(
        children[2].value,
        location_information(LOCATION_INDEX, 0, b"802.11")
    );
    assert_eq!(children[3].value, location_data(LOCATION_INDEX));
    assert_eq!(children[4].value, b"1synthetic.invalid");
    assert_eq!(children[5].value, b"circuit-synthetic-1");

    let timestamp = top_level
        .iter()
        .find(|avp| avp.code == swm::AVP_USER_LOCATION_INFO_TIME)
        .expect("User-Location-Info-Time emitted");
    assert_eq!(timestamp.vendor_id, Some(VENDOR_ID_3GPP));
    assert_eq!(timestamp.flags, AvpFlags::VENDOR);
    assert_eq!(timestamp.value, 0x2021_2223_u32.to_be_bytes());
}

#[test]
fn e212_operator_namespace_round_trips_as_the_exact_five_digit_value() {
    let mut children = access_children(false, false, None);
    children[2] = raw_avp(swm::AVP_OPERATOR_NAME, 0, None, b"200101");
    let access = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
    let wire = answer_wire(&[access]);
    let envelope = parse_envelope(&wire).expect("E.212 operator fixture parses");
    assert!(envelope.answer().has_wlan_location());
    let correlated = correlated(&wire);
    let operator = correlated
        .wlan_location()
        .expect("correlated location is present")
        .access_network_info()
        .operator_name()
        .expect("operator is present");
    assert_eq!(
        operator.namespace(),
        SwmAccessNetworkOperatorNamespace::E212
    );
    assert_eq!(operator.value(), "00101");

    let rebuilt = swm::build_swm_diameter_eap_answer_envelope(&envelope, EncodeContext::default())
        .expect("sealed E.212 operator fixture rebuilds");
    assert_eq!(encode(&rebuilt), wire);
}

#[test]
fn timestamp_requires_location_and_originated_omission_is_explicit() {
    let mut answer = successful_answer();
    answer
        .set_wlan_location_without_time(
            typed_access(),
            SwmUserLocationInfoTimeOmission::unavailable(),
        )
        .expect("explicit omission evidence is accepted");
    let wire = encode(
        &swm::build_swm_diameter_eap_answer(
            &answer,
            HOP_BY_HOP,
            END_TO_END,
            EncodeContext::default(),
        )
        .expect("explicitly unavailable timestamp remains valid"),
    );
    let envelope =
        parse_envelope(&wire).expect("location without timestamp remains valid on receive");
    assert!(envelope.answer().has_wlan_location());
    assert!(!envelope.answer().has_wlan_location_time());
    let correlated = correlated(&wire);
    let received_omission = correlated
        .wlan_location()
        .expect("correlated location is present")
        .user_location_info_time_omission()
        .expect("correlated omission evidence is present");
    assert!(received_omission.was_absent_on_receive());
    assert_eq!(
        answer
            .set_wlan_location_without_time(typed_access(), received_omission)
            .expect_err("receive-derived omission cannot be transplanted")
            .code(),
        SwmLocationContextErrorCode::InvalidReplayProvenance,
    );
    assert!(swm::build_swm_diameter_eap_answer(
        envelope.answer(),
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .is_err());
    let rebuilt = swm::build_swm_diameter_eap_answer_envelope(&envelope, EncodeContext::default())
        .expect("sealed received omission replays without a synthetic AVP");
    assert_eq!(encode(&rebuilt), wire);

    let timestamp = raw_avp(
        swm::AVP_USER_LOCATION_INFO_TIME,
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
        &1_u32.to_be_bytes(),
    );
    assert!(parse(&answer_wire(&[timestamp])).is_err());
}

#[test]
fn known_m_bit_mismatches_are_tolerated_but_canonicalized() {
    let mut children = access_children(true, true, None);
    children[0] = raw_avp(
        swm::AVP_SSID,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(VENDOR_ID_3GPP),
        b"synthetic-wlan",
    );
    children[1] = raw_avp(
        swm::AVP_BSSID,
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
        b"02-AB-CD-EF-00-01",
    );
    let outer = access_avp_with(
        &children,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(VENDOR_ID_3GPP),
    );
    let timestamp = raw_avp(
        swm::AVP_USER_LOCATION_INFO_TIME,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(VENDOR_ID_3GPP),
        &1_u32.to_be_bytes(),
    );
    let envelope = parse_envelope(&answer_wire(&[outer, timestamp]))
        .expect("TS 29.273 known-AVP M mismatch is tolerated");
    let rebuilt = swm::build_swm_diameter_eap_answer_envelope(&envelope, EncodeContext::default())
        .expect("sealed parsed values canonicalize");
    let top_level = snapshots(&rebuilt.raw_avps);
    assert_eq!(
        top_level
            .iter()
            .find(|avp| avp.code == swm::AVP_ACCESS_NETWORK_INFO)
            .map(|avp| avp.flags),
        Some(AvpFlags::VENDOR)
    );
    assert_eq!(
        top_level
            .iter()
            .find(|avp| avp.code == swm::AVP_USER_LOCATION_INFO_TIME)
            .map(|avp| avp.flags),
        Some(AvpFlags::VENDOR)
    );
}

#[test]
fn defining_protected_bit_allowances_are_accepted_on_reused_children_and_time() {
    let mut children = access_children(true, true, None);
    children[1] = raw_avp(
        swm::AVP_BSSID,
        AvpFlags::VENDOR | AvpFlags::MANDATORY | AvpFlags::PROTECTED,
        Some(VENDOR_ID_3GPP),
        b"02-AB-CD-EF-00-01",
    );
    children[2] = raw_avp(
        swm::AVP_LOCATION_INFORMATION,
        AvpFlags::PROTECTED,
        None,
        &location_information(LOCATION_INDEX, 0, b"802.11"),
    );
    children[3] = raw_avp(
        swm::AVP_LOCATION_DATA,
        AvpFlags::PROTECTED,
        None,
        &location_data(LOCATION_INDEX),
    );
    children[4] = raw_avp(
        swm::AVP_OPERATOR_NAME,
        AvpFlags::PROTECTED,
        None,
        b"1synthetic.invalid",
    );
    children[5] = raw_avp(
        swm::AVP_LOGICAL_ACCESS_ID,
        AvpFlags::VENDOR | AvpFlags::PROTECTED,
        Some(swm::VENDOR_ID_ETSI),
        b"circuit-synthetic-1",
    );
    let access = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
    let timestamp = raw_avp(
        swm::AVP_USER_LOCATION_INFO_TIME,
        AvpFlags::VENDOR | AvpFlags::PROTECTED,
        Some(VENDOR_ID_3GPP),
        &1_u32.to_be_bytes(),
    );
    let envelope = parse_envelope(&answer_wire(&[access, timestamp]))
        .expect("reused child specifications permit the received P bits");
    let rebuilt = swm::build_swm_diameter_eap_answer_envelope(&envelope, EncodeContext::default())
        .expect("sealed parsed protected-bit fixture canonicalizes");
    let top_level = snapshots(&rebuilt.raw_avps);
    let access = top_level
        .iter()
        .find(|avp| avp.code == swm::AVP_ACCESS_NETWORK_INFO)
        .expect("Access-Network-Info emitted");
    assert_eq!(access.flags, AvpFlags::VENDOR);
    let ssid = snapshots(&access.value)
        .into_iter()
        .find(|avp| avp.code == swm::AVP_SSID)
        .expect("SSID emitted");
    assert_eq!(ssid.flags, AvpFlags::VENDOR);
}

#[test]
fn access_network_info_and_ssid_protected_bits_fail_closed() {
    let protected_outer = access_avp_with(
        &access_children(true, true, None),
        AvpFlags::VENDOR | AvpFlags::PROTECTED,
        Some(VENDOR_ID_3GPP),
    );
    let error = parse(&answer_wire(&[protected_outer]))
        .expect_err("TS 29.273 requires Access-Network-Info P clear");
    assert_spec_ref(&error, "3gpp", "TS29273", "5.2.3.24");

    let mut children = access_children(true, true, None);
    children[0] = raw_avp(
        swm::AVP_SSID,
        AvpFlags::VENDOR | AvpFlags::PROTECTED,
        Some(VENDOR_ID_3GPP),
        b"synthetic-wlan",
    );
    let protected_ssid = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
    let error =
        parse(&answer_wire(&[protected_ssid])).expect_err("TS 29.273 requires SSID P clear");
    assert_spec_ref(&error, "3gpp", "TS29273", "5.2.3.22");
}

#[test]
fn civic_information_and_data_must_be_a_complete_matching_pair() {
    for (include_information, include_data) in [(true, false), (false, true)] {
        let access = access_avp_with(
            &access_children(include_information, include_data, None),
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
        );
        assert!(
            parse(&answer_wire(&[access])).is_err(),
            "one-sided civic pair was accepted"
        );
    }

    let mut children = access_children(true, true, None);
    children[3] = raw_avp(
        swm::AVP_LOCATION_DATA,
        0,
        None,
        &location_data(LOCATION_INDEX + 1),
    );
    let mismatched = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
    assert!(parse(&answer_wire(&[mismatched])).is_err());

    let information = SwmCivicLocationInformation::new(
        1,
        SwmLocationEntity::UserDevice,
        SwmNtpTimestamp64::from_bits(0),
        SwmNtpTimestamp64::from_bits(0),
        SwmLocationMethod::try_new("Manual").expect("registered method shape"),
    );
    let address = SwmCivicAddress::try_new(*b"CA", Vec::new()).expect("country-only civic data");
    let error = SwmAccessNetworkInfo::try_new(
        SwmWlanSsid::try_new("synthetic").expect("synthetic SSID"),
        SwmAccessNetworkLocatorEvidence::Civic {
            information,
            data: SwmCivicLocationData::new(2, address),
        },
    )
    .expect_err("builder rejects mismatched association indexes");
    assert_eq!(
        error.code(),
        SwmLocationContextErrorCode::LocationIndexMismatch
    );

    let user_information = SwmCivicLocationInformation::new(
        2,
        SwmLocationEntity::UserDevice,
        SwmNtpTimestamp64::from_bits(0),
        SwmNtpTimestamp64::from_bits(0),
        SwmLocationMethod::try_new("Manual").expect("registered method"),
    );
    let address = SwmCivicAddress::try_new(*b"CA", Vec::new()).expect("civic address");
    let error = SwmAccessNetworkInfo::try_new(
        SwmWlanSsid::try_new("synthetic").expect("synthetic SSID"),
        SwmAccessNetworkLocatorEvidence::Civic {
            information: user_information,
            data: SwmCivicLocationData::new(2, address),
        },
    )
    .expect_err("builder rejects a UE entity inside Access-Network-Info");
    assert_eq!(
        error.code(),
        SwmLocationContextErrorCode::InvalidLocationEntity
    );

    let mut children = access_children(true, true, None);
    let mut user_location = location_information(LOCATION_INDEX, 0, b"802.11");
    user_location[3] = 0;
    children[2] = raw_avp(swm::AVP_LOCATION_INFORMATION, 0, None, &user_location);
    let access = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
    assert!(parse(&answer_wire(&[access])).is_err());
}

#[test]
fn unregistered_location_method_fails_closed_on_receive() {
    let mut children = access_children(true, true, None);
    children[2] = raw_avp(
        swm::AVP_LOCATION_INFORMATION,
        0,
        None,
        &location_information(LOCATION_INDEX, 0, b"future-synthetic-method"),
    );
    let access = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
    assert_eq!(
        *parse(&answer_wire(&[access]))
            .expect_err("unregistered received method is rejected")
            .code(),
        opc_protocol::DecodeErrorCode::Structural {
            reason: "SWm Location-Information contains an invalid method token"
        }
    );
    assert_eq!(
        SwmLocationMethod::try_new("future-synthetic-method")
            .expect_err("unregistered originated method is rejected")
            .code(),
        SwmLocationContextErrorCode::InvalidLocationMethod
    );
}

#[test]
fn malformed_known_location_shapes_fail_closed() {
    let missing_ssid = access_avp_with(
        &access_children(false, false, None)[1..],
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
    );
    assert!(parse(&answer_wire(&[missing_ssid])).is_err());

    let duplicated = canonical_access_avp(None);
    assert!(parse(&answer_wire(&[duplicated.clone(), duplicated])).is_err());

    let timestamp = raw_avp(
        swm::AVP_USER_LOCATION_INFO_TIME,
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
        &1_u32.to_be_bytes(),
    );
    assert!(parse(&answer_wire(&[timestamp.clone(), timestamp])).is_err());

    let malformed_time = raw_avp(
        swm::AVP_USER_LOCATION_INFO_TIME,
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
        &[0, 1, 2],
    );
    assert!(parse(&answer_wire(&[malformed_time])).is_err());
}

#[test]
fn bssid_and_location_time_failures_cite_the_defining_specifications() {
    let mut children = access_children(true, true, None);
    children[1] = raw_avp(
        swm::AVP_BSSID,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(VENDOR_ID_3GPP),
        b"01-00-00-00-00-01",
    );
    let access = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
    let error = parse(&answer_wire(&[access])).expect_err("group BSSID rejected");
    assert_spec_ref(&error, "3gpp", "TS32299", "7.2.30A");

    let malformed_time = raw_avp(
        swm::AVP_USER_LOCATION_INFO_TIME,
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
        &[0, 1, 2],
    );
    let error = parse(&answer_wire(&[malformed_time])).expect_err("short time rejected");
    assert_spec_ref(&error, "3gpp", "TS29212", "5.3.101");
}

#[test]
fn malformed_child_vendor_flags_cardinality_and_values_fail_closed() {
    let replacement_cases = [
        raw_avp(swm::AVP_SSID, 0, None, b"synthetic-wlan"),
        raw_avp(swm::AVP_SSID, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP), b""),
        raw_avp(
            swm::AVP_BSSID,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            b"01-00-00-00-00-01",
        ),
        raw_avp(
            swm::AVP_BSSID,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            b"00-00-00-00-00-00",
        ),
        raw_avp(
            swm::AVP_BSSID,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            b"FF-FF-FF-FF-FF-FF",
        ),
    ];
    for replacement in replacement_cases {
        let mut children = access_children(true, true, None);
        let index = usize::from(replacement[0..4] == swm::AVP_BSSID.get().to_be_bytes());
        children[index] = replacement;
        let access = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
        assert!(parse(&answer_wire(&[access])).is_err());
    }

    let mut duplicate_ssid = access_children(true, true, None);
    duplicate_ssid.insert(1, duplicate_ssid[0].clone());
    let access = access_avp_with(&duplicate_ssid, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
    assert!(parse(&answer_wire(&[access])).is_err());

    let mut zero_vendor_extension = access_children(true, true, None);
    zero_vendor_extension.push(raw_avp(
        UNKNOWN_CHILD,
        AvpFlags::VENDOR,
        Some(VendorId::new(0)),
        &[0x01],
    ));
    let access = access_avp_with(
        &zero_vendor_extension,
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
    );
    assert!(parse(&answer_wire(&[access])).is_err());
}

#[test]
fn top_level_location_code_collisions_follow_unknown_policy_by_full_identity() {
    let optional_collisions = vec![
        raw_avp(
            swm::AVP_ACCESS_NETWORK_INFO,
            AvpFlags::VENDOR,
            Some(FOREIGN_VENDOR),
            b"foreign-access",
        ),
        raw_avp(
            swm::AVP_USER_LOCATION_INFO_TIME,
            AvpFlags::VENDOR,
            Some(FOREIGN_VENDOR),
            b"foreign-time",
        ),
        raw_avp(swm::AVP_ACCESS_NETWORK_INFO, 0, None, b"ietf-access"),
        raw_avp(swm::AVP_USER_LOCATION_INFO_TIME, 0, None, b"ietf-time"),
    ];
    let wire = answer_wire(&optional_collisions);
    let preserved = parse_envelope(&wire).expect("optional full-key collisions are preserved");
    assert!(!preserved.answer().has_wlan_location());
    assert!(!preserved.answer().has_wlan_location_time());
    assert_eq!(
        preserved
            .answer()
            .extensions
            .metadata()
            .map(|metadata| (metadata.code(), metadata.vendor_id()))
            .collect::<Vec<_>>(),
        vec![
            (swm::AVP_ACCESS_NETWORK_INFO, Some(FOREIGN_VENDOR)),
            (swm::AVP_USER_LOCATION_INFO_TIME, Some(FOREIGN_VENDOR)),
            (swm::AVP_ACCESS_NETWORK_INFO, None),
            (swm::AVP_USER_LOCATION_INFO_TIME, None),
        ]
    );

    let rebuilt = swm::build_swm_diameter_eap_answer_envelope(&preserved, EncodeContext::default())
        .expect("sealed collision extensions replay canonically");
    let replayed = snapshots(&rebuilt.raw_avps)
        .into_iter()
        .filter(|avp| {
            matches!(
                (avp.code, avp.vendor_id),
                (code, Some(vendor))
                    if vendor == FOREIGN_VENDOR
                        && matches!(
                            code,
                            swm::AVP_ACCESS_NETWORK_INFO | swm::AVP_USER_LOCATION_INFO_TIME
                        )
            ) || matches!(
                (avp.code, avp.vendor_id),
                (
                    swm::AVP_ACCESS_NETWORK_INFO | swm::AVP_USER_LOCATION_INFO_TIME,
                    None
                )
            )
        })
        .map(|avp| (avp.code, avp.vendor_id, avp.flags, avp.value))
        .collect::<Vec<_>>();
    assert_eq!(
        replayed,
        vec![
            (
                swm::AVP_ACCESS_NETWORK_INFO,
                Some(FOREIGN_VENDOR),
                AvpFlags::VENDOR,
                b"foreign-access".to_vec(),
            ),
            (
                swm::AVP_USER_LOCATION_INFO_TIME,
                Some(FOREIGN_VENDOR),
                AvpFlags::VENDOR,
                b"foreign-time".to_vec(),
            ),
            (
                swm::AVP_ACCESS_NETWORK_INFO,
                None,
                0,
                b"ietf-access".to_vec(),
            ),
            (
                swm::AVP_USER_LOCATION_INFO_TIME,
                None,
                0,
                b"ietf-time".to_vec(),
            ),
        ]
    );

    let dropped = parse_with_policy(&wire, UnknownIePolicy::Drop)
        .expect("Drop discards optional full-key collisions");
    assert!(dropped.extensions.is_empty());
    assert!(parse_with_policy(&wire, UnknownIePolicy::Reject).is_err());

    let mandatory_collision = raw_avp(
        swm::AVP_ACCESS_NETWORK_INFO,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(FOREIGN_VENDOR),
        b"foreign-mandatory",
    );
    assert!(parse(&answer_wire(&[mandatory_collision])).is_err());
    let zero_vendor_collision = raw_avp(
        swm::AVP_USER_LOCATION_INFO_TIME,
        AvpFlags::VENDOR,
        Some(VendorId::new(0)),
        b"zero-vendor",
    );
    assert!(parse(&answer_wire(&[zero_vendor_collision])).is_err());
}

#[test]
fn nested_location_code_collisions_follow_unknown_policy_by_full_identity() {
    let collision_values = vec![
        (
            swm::AVP_SSID,
            Some(FOREIGN_VENDOR),
            AvpFlags::VENDOR,
            b"foreign-ssid".to_vec(),
        ),
        (swm::AVP_BSSID, None, 0, b"ietf-bssid".to_vec()),
        (
            swm::AVP_LOCATION_INFORMATION,
            Some(FOREIGN_VENDOR),
            AvpFlags::VENDOR,
            b"foreign-information".to_vec(),
        ),
        (
            swm::AVP_LOCATION_DATA,
            Some(FOREIGN_VENDOR),
            AvpFlags::VENDOR,
            b"foreign-data".to_vec(),
        ),
        (
            swm::AVP_OPERATOR_NAME,
            Some(FOREIGN_VENDOR),
            AvpFlags::VENDOR,
            b"foreign-operator".to_vec(),
        ),
        (
            swm::AVP_LOGICAL_ACCESS_ID,
            Some(VENDOR_ID_3GPP),
            AvpFlags::VENDOR,
            b"foreign-logical".to_vec(),
        ),
    ];
    let mut children = access_children(true, true, None);
    children.extend(
        collision_values
            .iter()
            .map(|(code, vendor_id, flags, value)| raw_avp(*code, *flags, *vendor_id, value)),
    );
    let access = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
    let wire = answer_wire(&[access]);
    let preserved = parse_envelope(&wire).expect("nested full-key collisions are preserved");
    let correlated = correlated(&wire);
    let parsed_access = correlated
        .wlan_location()
        .expect("exact correlated Access-Network-Info remains typed")
        .access_network_info();
    assert_eq!(
        parsed_access
            .extensions()
            .metadata()
            .map(|metadata| (metadata.code(), metadata.vendor_id()))
            .collect::<Vec<_>>(),
        collision_values
            .iter()
            .map(|(code, vendor_id, _, _)| (*code, *vendor_id))
            .collect::<Vec<_>>()
    );

    let rebuilt = swm::build_swm_diameter_eap_answer_envelope(&preserved, EncodeContext::default())
        .expect("sealed nested collision extensions replay canonically");
    let rebuilt_access = snapshots(&rebuilt.raw_avps)
        .into_iter()
        .find(|avp| {
            avp.code == swm::AVP_ACCESS_NETWORK_INFO && avp.vendor_id == Some(VENDOR_ID_3GPP)
        })
        .expect("exact Access-Network-Info is rebuilt");
    let replayed_children = snapshots(&rebuilt_access.value)
        .into_iter()
        .filter(|avp| {
            collision_values
                .iter()
                .any(|(code, vendor_id, _, _)| avp.code == *code && avp.vendor_id == *vendor_id)
        })
        .map(|avp| (avp.code, avp.vendor_id, avp.flags, avp.value))
        .collect::<Vec<_>>();
    assert_eq!(replayed_children, collision_values);

    let dropped = correlated_with_policy(&wire, UnknownIePolicy::Drop)
        .expect("Drop discards optional nested collisions");
    assert_eq!(
        dropped
            .wlan_location()
            .map(|location| location.access_network_info())
            .map(|value| value.extensions().len()),
        Some(0)
    );
    assert!(parse_with_policy(&wire, UnknownIePolicy::Reject).is_err());

    let mut mandatory_children = access_children(true, true, None);
    mandatory_children.push(raw_avp(
        swm::AVP_BSSID,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(FOREIGN_VENDOR),
        b"foreign-mandatory",
    ));
    let access = access_avp_with(&mandatory_children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
    assert!(parse(&answer_wire(&[access])).is_err());
}

#[test]
fn common_bssid_spellings_are_accepted_and_canonicalized() {
    for spelling in [b"02:ab:cd:ef:00:01".as_slice(), b"02-ab-cd-ef-00-01"] {
        let mut children = access_children(true, true, None);
        children[1] = raw_avp(
            swm::AVP_BSSID,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            spelling,
        );
        let access = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
        let envelope =
            parse_envelope(&answer_wire(&[access])).expect("common BSSID spelling parses");
        let rebuilt =
            swm::build_swm_diameter_eap_answer_envelope(&envelope, EncodeContext::default())
                .expect("sealed parsed BSSID rebuilds");
        let outer = snapshots(&rebuilt.raw_avps)
            .into_iter()
            .find(|avp| avp.code == swm::AVP_ACCESS_NETWORK_INFO)
            .expect("access context emitted");
        let bssid = snapshots(&outer.value)
            .into_iter()
            .find(|avp| avp.code == swm::AVP_BSSID)
            .expect("BSSID emitted");
        assert_eq!(bssid.value, b"02-AB-CD-EF-00-01");
    }
}

#[test]
fn received_ssid_only_value_retains_absent_locator_provenance() {
    let access = access_avp_with(
        &[raw_avp(
            swm::AVP_SSID,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            b"synthetic-wlan",
        )],
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
    );
    let wire = answer_wire(&[access]);
    let envelope = parse_envelope(&wire).expect("received SSID-only value is tolerated");
    assert!(envelope.answer().has_wlan_location());
    let correlated = correlated(&wire);
    let typed = correlated
        .wlan_location()
        .expect("correlated access context present")
        .access_network_info();
    assert_eq!(
        typed.locator_status(),
        SwmAccessNetworkLocatorStatus::AbsentOnReceive
    );
    assert!(swm::build_swm_diameter_eap_answer(
        envelope.answer(),
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .is_err());
    let rebuilt = swm::build_swm_diameter_eap_answer_envelope(&envelope, EncodeContext::default())
        .expect("only the sealed parsed envelope may replay received absence");
    assert_eq!(encode(&rebuilt), wire);
}

#[test]
fn received_location_provenance_cannot_be_mutated_copied_or_transplanted() {
    let received_present_wire = answer_wire(&[
        access_avp_with(
            &access_children(false, false, None),
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
        ),
        raw_avp(
            swm::AVP_USER_LOCATION_INFO_TIME,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            &1_u32.to_be_bytes(),
        ),
    ]);
    let received_present = parse_envelope(&received_present_wire)
        .expect("received access context with locators parses");
    assert!(received_present.answer().has_wlan_location());

    let correlated_present = correlated(&received_present_wire);
    let received_access = correlated_present
        .wlan_location()
        .expect("correlated received access context is present")
        .access_network_info()
        .clone();
    let operator = SwmAccessNetworkOperatorName::try_realm("mutated.synthetic.invalid")
        .expect("synthetic realm is valid");
    let originated_bssid = SwmBasicServiceSetIdentifier::try_from_octets([0x02, 0, 0, 0, 0, 2])
        .expect("synthetic originated BSSID is valid");
    let logical_access_id = SwmLogicalAccessId::try_new(b"new-circuit-synthetic".to_vec())
        .expect("synthetic logical access id is valid");
    let civic_address =
        SwmCivicAddress::try_new(*b"CA", Vec::new()).expect("country-only civic data is valid");
    let civic_information = SwmCivicLocationInformation::new(
        LOCATION_INDEX + 1,
        SwmLocationEntity::AccessNetwork,
        SwmNtpTimestamp64::from_bits(1),
        SwmNtpTimestamp64::from_bits(2),
        SwmLocationMethod::try_new("Manual").expect("registered location method"),
    );
    let civic_data = SwmCivicLocationData::new(LOCATION_INDEX + 1, civic_address);
    let civic_mutation = received_access
        .clone()
        .with_civic_location(civic_information.clone(), civic_data.clone())
        .expect("replacement civic pair is internally valid");
    let all_mutations = received_access
        .clone()
        .with_operator_name(operator.clone())
        .with_bssid(originated_bssid)
        .with_civic_location(civic_information, civic_data)
        .expect("replacement civic pair is internally valid")
        .with_logical_access_id(logical_access_id.clone());
    for received_or_mutated in [
        received_access.clone(),
        received_access.clone().with_bssid(originated_bssid),
        civic_mutation,
        received_access.clone().with_operator_name(operator.clone()),
        received_access
            .clone()
            .with_logical_access_id(logical_access_id),
        all_mutations,
    ] {
        let mut candidate = successful_answer();
        assert!(candidate
            .set_wlan_location_with_time(
                received_or_mutated,
                SwmUserLocationInfoTime::from_ntp_seconds(1),
            )
            .is_err());
    }

    let mut freshly_originated = successful_answer();
    freshly_originated
        .set_wlan_location_with_time(
            SwmAccessNetworkInfo::try_new(
                SwmWlanSsid::try_new("fresh-synthetic-wlan").expect("synthetic SSID is valid"),
                SwmAccessNetworkLocatorEvidence::Bssid(originated_bssid),
            )
            .expect("a newly originated complete value is valid")
            .with_operator_name(operator),
            SwmUserLocationInfoTime::from_ntp_seconds(1),
        )
        .expect("fresh originated location is accepted");
    assert!(swm::build_swm_diameter_eap_answer(
        &freshly_originated,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .is_ok());

    let ssid_only = access_avp_with(
        &[raw_avp(
            swm::AVP_SSID,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            b"synthetic-wlan",
        )],
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
    );
    let received_absent_wire = answer_wire(&[ssid_only]);
    let received_absent = parse_envelope(&received_absent_wire)
        .expect("received SSID-only value remains interoperable");
    assert!(received_absent.answer().has_wlan_location());
    let correlated_absent = correlated(&received_absent_wire);
    let received_omission = correlated_absent
        .wlan_location()
        .expect("correlated received location is present")
        .user_location_info_time_omission()
        .expect("received location without time carries sealed provenance");
    let mut copied_omission = successful_answer();
    assert!(copied_omission
        .set_wlan_location_without_time(typed_access(), received_omission)
        .is_err());
    copied_omission
        .set_wlan_location_without_time(
            typed_access(),
            SwmUserLocationInfoTimeOmission::unavailable(),
        )
        .expect("locally originated omission remains valid");
    assert!(swm::build_swm_diameter_eap_answer(
        &copied_omission,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .is_ok());

    let retained_wire = answer_wire(&[
        canonical_access_avp(Some(0)),
        raw_avp(
            swm::AVP_USER_LOCATION_INFO_TIME,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            &1_u32.to_be_bytes(),
        ),
    ]);
    let retained = parse_envelope(&retained_wire).expect("retained extension fixture parses");
    let correlated_retained = correlated(&retained_wire);
    let retained_access = correlated_retained
        .wlan_location()
        .expect("correlated retained location is present")
        .access_network_info()
        .clone();
    let mut retained_mutation = retained.answer().clone();
    let operator = SwmAccessNetworkOperatorName::try_realm("changed.synthetic.invalid")
        .expect("synthetic realm is valid");
    let originated_bssid = SwmBasicServiceSetIdentifier::try_from_octets([0x02, 0, 0, 0, 0, 3])
        .expect("synthetic originated BSSID is valid");
    assert!(retained_mutation
        .set_wlan_location_with_time(
            retained_access
                .with_operator_name(operator)
                .with_bssid(originated_bssid),
            SwmUserLocationInfoTime::from_ntp_seconds(1),
        )
        .is_err());
    let replayed = swm::build_swm_diameter_eap_answer_envelope(&retained, EncodeContext::default())
        .expect("unmodified sealed retained extensions replay");
    assert_eq!(encode(&replayed), retained_wire);
}

#[test]
fn malformed_rfc5580_payloads_fail_closed() {
    let malformed_information = [
        vec![0; 20],
        location_information(LOCATION_INDEX, 1, b"802.11"),
        location_information(LOCATION_INDEX, 0, b"bad method!"),
    ];
    for value in malformed_information {
        let mut children = access_children(true, true, None);
        children[2] = raw_avp(swm::AVP_LOCATION_INFORMATION, 0, None, &value);
        let access = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
        assert!(parse(&answer_wire(&[access])).is_err());
    }

    let mut truncated_extension = Vec::new();
    truncated_extension.extend_from_slice(&LOCATION_INDEX.to_be_bytes());
    truncated_extension.extend_from_slice(b"CA");
    truncated_extension.extend_from_slice(&[40, 32]);
    truncated_extension.extend_from_slice(b"urn:private");
    let malformed_data = [
        vec![0, 1, b'C'],
        vec![0, 1, b'c', b'a'],
        vec![0, 1, b'C', b'A', 3],
        vec![0, 1, b'C', b'A', 3, 5, b'o', b'n', b'e'],
        vec![0, 1, b'C', b'A', 3, 1, 0xff],
        location_data_with_element(LOCATION_INDEX, 7, b"reserved"),
        location_data_with_element(LOCATION_INDEX, 128, b"LATN"),
        location_data_with_element(LOCATION_INDEX, 40, b"relative PN pole-7"),
        truncated_extension,
    ];
    for value in malformed_data {
        let mut children = access_children(true, true, None);
        children[3] = raw_avp(swm::AVP_LOCATION_DATA, 0, None, &value);
        let access = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
        assert!(parse(&answer_wire(&[access])).is_err());
    }

    for operator in [
        b"0forbidden".as_slice(),
        b"1bad realm".as_slice(),
        b"2123".as_slice(),
    ] {
        let mut children = access_children(true, true, None);
        children[4] = raw_avp(swm::AVP_OPERATOR_NAME, 0, None, operator);
        let access = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
        assert!(parse(&answer_wire(&[access])).is_err());
    }
}

#[test]
fn arbitrary_structural_catype_40_extension_round_trips() {
    let extension = "urn:private:synthetic Future_Name pole-7 with spaces";
    let mut children = access_children(true, true, None);
    children[3] = raw_avp(
        swm::AVP_LOCATION_DATA,
        0,
        None,
        &location_data_with_element(LOCATION_INDEX, 40, extension.as_bytes()),
    );
    let access = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
    let wire = answer_wire(&[access]);
    let envelope = parse_envelope(&wire).expect("private CAtype-40 extension parses");
    let correlated = correlated(&wire);
    let value = correlated
        .wlan_location()
        .map(|location| location.access_network_info())
        .and_then(SwmAccessNetworkInfo::location_data)
        .and_then(|data| data.address().elements().first())
        .map(SwmCivicAddressElement::value);
    assert_eq!(value, Some(extension));
    let rebuilt = swm::build_swm_diameter_eap_answer_envelope(&envelope, EncodeContext::default())
        .expect("private CAtype-40 extension rebuilds");
    assert_eq!(encode(&rebuilt), wire);
}

#[test]
fn unknown_children_obey_bounded_extension_policy() {
    let optional = canonical_access_avp(Some(0));
    let preserve_wire = answer_wire(std::slice::from_ref(&optional));
    let preserved = correlated_with_policy(&preserve_wire, UnknownIePolicy::Preserve)
        .expect("optional child is preserved");
    assert_eq!(
        preserved
            .wlan_location()
            .map(|location| location.access_network_info())
            .map(|access| access.extensions().len()),
        Some(1)
    );

    let drop_wire = answer_wire(&[optional]);
    let dropped = correlated_with_policy(&drop_wire, UnknownIePolicy::Drop)
        .expect("optional child is droppable");
    assert_eq!(
        dropped
            .wlan_location()
            .map(|location| location.access_network_info())
            .map(|access| access.extensions().len()),
        Some(0)
    );

    let rejected = canonical_access_avp(Some(0));
    assert!(parse_with_policy(&answer_wire(&[rejected]), UnknownIePolicy::Reject).is_err());

    let mandatory = canonical_access_avp(Some(AvpFlags::MANDATORY));
    assert!(parse_with_policy(&answer_wire(&[mandatory]), UnknownIePolicy::Preserve).is_err());
}

#[test]
fn retained_unknown_child_count_is_bounded_before_copying_the_129th() {
    let mut children = access_children(true, true, None);
    for index in 0..129_u32 {
        children.push(raw_avp(
            AvpCode::new(910_000 + index),
            0,
            None,
            &[u8::try_from(index & 0xff).expect("masked value fits")],
        ));
    }
    let access = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
    assert!(parse(&answer_wire(&[access])).is_err());
}

#[test]
fn nested_and_top_level_extensions_share_one_answer_retention_budget() {
    let mut children = access_children(true, true, None);
    for index in 0..128_u32 {
        children.push(raw_avp(
            AvpCode::new(920_000 + index),
            0,
            None,
            &[u8::try_from(index & 0xff).expect("masked value fits")],
        ));
    }
    let access = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
    let top_level_extension = raw_avp(AvpCode::new(930_000), 0, None, &[0x01]);
    assert!(parse(&answer_wire(&[access, top_level_extension.clone()])).is_err());

    let access = access_avp_with(&children, AvpFlags::VENDOR, Some(VENDOR_ID_3GPP));
    let nested_wire = answer_wire(&[access]);
    let nested = correlated(&nested_wire);
    let top_level = parse(&answer_wire(std::slice::from_ref(&top_level_extension)))
        .expect("one top-level extension fits the budget");
    let mut recombined = successful_answer();
    assert!(recombined
        .set_wlan_location_with_time(
            nested
                .wlan_location()
                .expect("correlated nested location")
                .access_network_info()
                .clone(),
            SwmUserLocationInfoTime::from_ntp_seconds(1),
        )
        .is_err());
    recombined.extensions = top_level.extensions;
    assert!(swm::build_swm_diameter_eap_answer(
        &recombined,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .is_ok());
}

#[test]
fn public_constructors_enforce_bounds_without_value_bearing_errors() {
    assert_eq!(
        SwmWlanSsid::try_new("")
            .expect_err("empty SSID rejected")
            .code(),
        SwmLocationContextErrorCode::InvalidSsid
    );
    assert_eq!(
        SwmWlanSsid::try_new("x".repeat(33))
            .expect_err("overlong SSID rejected")
            .code(),
        SwmLocationContextErrorCode::InvalidSsid
    );
    assert_eq!(
        SwmLocationMethod::try_new("bad method!")
            .expect_err("invalid method rejected")
            .code(),
        SwmLocationContextErrorCode::InvalidLocationMethod
    );
    assert_eq!(
        SwmLocationMethod::try_new("future-synthetic-method")
            .expect_err("unregistered outbound method rejected")
            .code(),
        SwmLocationContextErrorCode::InvalidLocationMethod
    );
    for invalid in [[0, 0, 0, 0, 0, 0], [1, 0, 0, 0, 0, 1], [u8::MAX; 6]] {
        assert_eq!(
            SwmBasicServiceSetIdentifier::try_from_octets(invalid)
                .expect_err("non-individual BSSID rejected")
                .code(),
            SwmLocationContextErrorCode::InvalidBssid
        );
    }
    assert_eq!(
        SwmCivicAddress::try_new(*b"ca", Vec::new())
            .expect_err("lowercase country rejected")
            .code(),
        SwmLocationContextErrorCode::InvalidCountryCode
    );
    assert_eq!(
        SwmAccessNetworkOperatorName::try_e212("1234")
            .expect_err("short E212 rejected")
            .code(),
        SwmLocationContextErrorCode::InvalidOperatorE212
    );
    assert_eq!(
        SwmAccessNetworkOperatorName::try_realm("bad realm")
            .expect_err("invalid realm rejected")
            .code(),
        SwmLocationContextErrorCode::InvalidOperatorRealm
    );
    assert_eq!(
        SwmLogicalAccessId::try_new(Vec::new())
            .expect_err("empty logical access id rejected")
            .code(),
        SwmLocationContextErrorCode::InvalidLogicalAccessId
    );

    assert!(SwmCivicAddressElement::try_new(128, "Latn").is_ok());
    assert_eq!(
        SwmCivicAddressElement::try_new(128, "LATN")
            .expect_err("noncanonical script rejected")
            .code(),
        SwmLocationContextErrorCode::InvalidCivicAddressValue
    );
    assert_eq!(
        SwmCivicAddressElement::try_new(7, "reserved")
            .expect_err("unregistered CAtype rejected")
            .code(),
        SwmLocationContextErrorCode::InvalidCivicAddressType
    );
    assert!(SwmCivicAddressElement::try_new(
        40,
        "urn:ietf:params:xml:ns:pidf:geopriv10:civicAddr:ext PN pole-7",
    )
    .is_ok());
    assert!(SwmCivicAddressElement::try_new(40, "urn:private:unknown PN pole-7",).is_ok());
    assert!(SwmCivicAddressElement::try_new(
        40,
        "https://synthetic.invalid/civic Future-Name value with spaces",
    )
    .is_ok());
    assert!(
        SwmCivicAddressElement::try_new(40, "urn:private:unknown N\u{00E4}me unicode-value",)
            .is_ok()
    );
    for invalid_extension in [
        "relative PN value",
        "urn:private:%GG PN value",
        "urn:private:unknown  value",
        "urn:private:unknown 1PN value",
        "urn:private:unknown ns:PN value",
        "urn:private:unknown PN",
        "urn:private:unknown PN ",
        "urn:private:unknown PN  value",
        "urn:private:unknown PN value\0",
    ] {
        assert_eq!(
            SwmCivicAddressElement::try_new(40, invalid_extension)
                .expect_err("malformed CAtype-40 structure is rejected")
                .code(),
            SwmLocationContextErrorCode::InvalidCivicAddressValue
        );
    }
    let maximum_prefix = "urn:private:synthetic N ";
    let maximum_extension = format!(
        "{maximum_prefix}{}",
        "x".repeat(usize::from(u8::MAX) - maximum_prefix.len())
    );
    assert_eq!(maximum_extension.len(), usize::from(u8::MAX));
    assert!(SwmCivicAddressElement::try_new(40, &maximum_extension).is_ok());
    let overlong_extension = format!("{maximum_extension}x");
    assert_eq!(
        SwmCivicAddressElement::try_new(40, overlong_extension)
            .expect_err("CAtype-40 remains bounded by its one-octet length")
            .code(),
        SwmLocationContextErrorCode::InvalidCivicElement
    );
    assert!(SwmCivicAddressElement::try_new(29, "office").is_ok());
    assert_eq!(
        SwmCivicAddressElement::try_new(29, "private-place")
            .expect_err("unregistered location type rejected")
            .code(),
        SwmLocationContextErrorCode::InvalidCivicAddressValue
    );

    let maximum_empty_elements = (0..124)
        .map(|_| {
            SwmCivicAddressElement::try_new(16, "")
                .expect("empty civic element value is representable")
        })
        .collect();
    assert!(SwmCivicAddress::try_new(*b"CA", maximum_empty_elements).is_ok());
    let one_too_many_empty_elements = (0..125)
        .map(|_| {
            SwmCivicAddressElement::try_new(16, "")
                .expect("empty civic element value is representable")
        })
        .collect();
    assert_eq!(
        SwmCivicAddress::try_new(*b"CA", one_too_many_empty_elements)
            .expect_err("the first unrepresentable element count is rejected")
            .code(),
        SwmLocationContextErrorCode::CivicAddressTooLong
    );

    let ssid_only = SwmAccessNetworkInfo::try_new(
        SwmWlanSsid::try_new("synthetic-policy-ssid").expect("SSID valid"),
        SwmAccessNetworkLocatorEvidence::OmittedByOperatorPolicy,
    )
    .expect("explicit operator-policy omission is valid");
    assert_eq!(
        ssid_only.locator_status(),
        SwmAccessNetworkLocatorStatus::OmittedByOperatorPolicy
    );
}

#[test]
fn diagnostics_are_redaction_safe() {
    let answer = successful_answer();
    let access = typed_access();
    let wire = answer_wire(&[
        canonical_access_avp(None),
        raw_avp(
            swm::AVP_USER_LOCATION_INFO_TIME,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            &0x2021_2223_u32.to_be_bytes(),
        ),
    ]);
    let raw_response = response_envelope(&wire, CONNECTION);
    let correlated = bound_request()
        .correlate_response(raw_response.clone())
        .expect("synthetic response correlates");
    let correlated_location = correlated
        .wlan_location()
        .expect("synthetic correlated location is present");
    let diagnostics = format!(
        "{answer:?} {access:?} {:?} {:?} {:?} {:?} {raw_response:?} {correlated:?} {correlated_location:?}",
        access.ssid(),
        access.bssid(),
        access.operator_name(),
        access.logical_access_id(),
    );
    for secret in [
        "synthetic-wlan",
        "02-AB-CD-EF-00-01",
        "synthetic.invalid",
        "circuit-synthetic-1",
        "Testville",
        "Main St.",
    ] {
        assert!(!diagnostics.contains(secret));
    }
    assert!(diagnostics.contains("redacted"));

    let invalid = "private operator value with spaces";
    let error = SwmAccessNetworkOperatorName::try_realm(invalid)
        .expect_err("synthetic invalid realm is rejected");
    assert!(!format!("{error:?} {error}").contains(invalid));
}

#[test]
fn dictionary_declares_dea_only_command_applicability_and_grouped_types() {
    let dictionary = swm::dictionary();
    let answer = dictionary
        .find_command(
            swm::APPLICATION_ID,
            swm::COMMAND_DIAMETER_EAP,
            CommandKind::Answer,
        )
        .expect("SWm DEA command definition");
    let request = dictionary
        .find_command(
            swm::APPLICATION_ID,
            swm::COMMAND_DIAMETER_EAP,
            CommandKind::Request,
        )
        .expect("SWm DER command definition");
    let access_key = AvpKey::vendor(swm::AVP_ACCESS_NETWORK_INFO, VENDOR_ID_3GPP);
    let time_key = AvpKey::vendor(swm::AVP_USER_LOCATION_INFO_TIME, VENDOR_ID_3GPP);
    assert!(answer
        .avp_rules()
        .iter()
        .any(|rule| rule.key() == access_key && rule.cardinality() == AvpCardinality::ZeroOrOne));
    assert!(answer
        .avp_rules()
        .iter()
        .any(|rule| rule.key() == time_key && rule.cardinality() == AvpCardinality::ZeroOrOne));
    assert!(!request
        .avp_rules()
        .iter()
        .any(|rule| matches!(rule.key(), key if key == access_key || key == time_key)));

    let access_definition = dictionary
        .find_avp(access_key)
        .expect("Access-Network-Info dictionary definition");
    assert_eq!(access_definition.data_type(), AvpDataType::Grouped);
    assert_eq!(
        access_definition.flags().vendor(),
        FlagRequirement::MustBeSet
    );
    assert_eq!(
        access_definition.flags().protected(),
        FlagRequirement::MustBeUnset
    );
    assert_eq!(access_definition.grouped_avp_rules().len(), 6);

    let ssid_definition = dictionary
        .find_avp(AvpKey::vendor(swm::AVP_SSID, VENDOR_ID_3GPP))
        .expect("SSID dictionary definition");
    assert_eq!(
        ssid_definition.flags().protected(),
        FlagRequirement::MustBeUnset
    );

    let time_definition = dictionary
        .find_avp(time_key)
        .expect("User-Location-Info-Time dictionary definition");
    assert_eq!(time_definition.data_type(), AvpDataType::Time);
    assert_eq!(time_definition.spec_ref().body(), "3gpp");
    assert_eq!(time_definition.spec_ref().doc(), "TS29212");
    assert_eq!(time_definition.spec_ref().section(), "5.3.101");

    let bssid_definition = dictionary
        .find_avp(AvpKey::vendor(swm::AVP_BSSID, VENDOR_ID_3GPP))
        .expect("BSSID dictionary definition");
    assert_eq!(bssid_definition.spec_ref().body(), "3gpp");
    assert_eq!(bssid_definition.spec_ref().doc(), "TS32299");
    assert_eq!(bssid_definition.spec_ref().section(), "7.2.30A");
}
