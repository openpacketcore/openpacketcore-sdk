#![cfg(feature = "app-swm")]

use bytes::{Bytes, BytesMut};
use opc_proto_diameter::apps::swm::{self, AuthRequestType};
use opc_proto_diameter::apps::SWM_PROJECTED_PROFILE_DICTIONARIES;
use opc_proto_diameter::apps::VENDOR_ID_3GPP;
use opc_proto_diameter::base;
use opc_proto_diameter::dictionary::{AvpDataType, AvpKey, FlagRequirement};
use opc_proto_diameter::{
    AvpCode, AvpFlags, CommandFlags, Header, Message, OwnedMessage, RawAvp, VendorId,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DuplicateIePolicy, Encode,
    EncodeContext, UnknownIePolicy,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU64;

const HOP_BY_HOP: u32 = 0x0352_a001;
const END_TO_END: u32 = 0x0352_a002;
const SESSION_ID: &str = "session;synthetic;apn-352";
const EPDG_HOST: &str = "epdg.apn.synthetic.invalid";
const EPDG_REALM: &str = "visited.apn.synthetic.invalid";
const AAA_HOST: &str = "aaa.apn.synthetic.invalid";
const AAA_REALM: &str = "home.apn.synthetic.invalid";
const APN: &str = "ims.synthetic.invalid";
const APN_OI: &str = "epc.mnc001.mcc001.gprs";
const VISITED_MCC: &str = "001";
const VISITED_MNC: &str = "01";
const CONNECTION: swm::SwmDiameterConnectionToken =
    swm::SwmDiameterConnectionToken::new(NonZeroU64::MIN);

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

fn address_value(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(address) => {
            let mut value = vec![0, 1];
            value.extend_from_slice(&address.octets());
            value
        }
        IpAddr::V6(address) => {
            let mut value = vec![0, 2];
            value.extend_from_slice(&address.octets());
            value
        }
    }
}

fn vendor_u32(code: AvpCode, mandatory: bool, value: u32) -> Vec<u8> {
    raw_avp(
        code,
        AvpFlags::VENDOR | if mandatory { AvpFlags::MANDATORY } else { 0 },
        Some(VENDOR_ID_3GPP),
        &value.to_be_bytes(),
    )
}

fn agent_info(address: IpAddr) -> Vec<u8> {
    agent_info_with_m_bit(address, true)
}

fn agent_info_with_m_bit(address: IpAddr, mandatory: bool) -> Vec<u8> {
    let child = raw_avp(
        swm::AVP_MIP_HOME_AGENT_ADDRESS,
        AvpFlags::MANDATORY,
        None,
        &address_value(address),
    );
    raw_avp(
        swm::AVP_MIP6_AGENT_INFO,
        if mandatory { AvpFlags::MANDATORY } else { 0 },
        None,
        &child,
    )
}

fn apn_configuration(children: &[Vec<u8>]) -> Vec<u8> {
    let value: Vec<u8> = children.iter().flatten().copied().collect();
    raw_avp(
        swm::AVP_APN_CONFIGURATION,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(VENDOR_ID_3GPP),
        &value,
    )
}

fn grouped_3gpp(code: AvpCode, mandatory: bool, children: &[Vec<u8>]) -> Vec<u8> {
    let value: Vec<u8> = children.iter().flatten().copied().collect();
    raw_avp(
        code,
        AvpFlags::VENDOR | if mandatory { AvpFlags::MANDATORY } else { 0 },
        Some(VENDOR_ID_3GPP),
        &value,
    )
}

fn specific_apn_info_group(mandatory: bool, children: &[Vec<u8>]) -> Vec<u8> {
    grouped_3gpp(swm::AVP_SPECIFIC_APN_INFO, mandatory, children)
}

fn specific_apn_info(
    service_selection: &str,
    gateway: IpAddr,
    visited_network: Option<&[u8]>,
    mandatory: bool,
    extensions: &[Vec<u8>],
) -> Vec<u8> {
    let mut children = vec![
        raw_avp(
            swm::AVP_SERVICE_SELECTION,
            AvpFlags::MANDATORY,
            None,
            service_selection.as_bytes(),
        ),
        agent_info(gateway),
    ];
    if let Some(visited_network) = visited_network {
        children.push(raw_avp(
            swm::AVP_VISITED_NETWORK_IDENTIFIER,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            visited_network,
        ));
    }
    children.extend_from_slice(extensions);
    specific_apn_info_group(mandatory, &children)
}

fn arp_children(priority: u32) -> Vec<Vec<u8>> {
    vec![
        vendor_u32(swm::AVP_PRIORITY_LEVEL, true, priority),
        vendor_u32(swm::AVP_PRE_EMPTION_CAPABILITY, true, 1),
        vendor_u32(swm::AVP_PRE_EMPTION_VULNERABILITY, true, 0),
    ]
}

fn qos_profile(qci: u32, priority: u32) -> Vec<u8> {
    grouped_3gpp(
        swm::AVP_EPS_SUBSCRIBED_QOS_PROFILE,
        true,
        &[
            vendor_u32(swm::AVP_QOS_CLASS_IDENTIFIER, true, qci),
            grouped_3gpp(
                swm::AVP_ALLOCATION_RETENTION_PRIORITY,
                true,
                &arp_children(priority),
            ),
        ],
    )
}

fn ambr(base_ul: u32, base_dl: u32, extended_ul: Option<u32>, extended_dl: Option<u32>) -> Vec<u8> {
    let mut children = vec![
        vendor_u32(swm::AVP_MAX_REQUESTED_BANDWIDTH_UL, true, base_ul),
        vendor_u32(swm::AVP_MAX_REQUESTED_BANDWIDTH_DL, true, base_dl),
    ];
    if let Some(value) = extended_ul {
        children.push(vendor_u32(
            swm::AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_UL,
            true,
            value,
        ));
    }
    if let Some(value) = extended_dl {
        children.push(vendor_u32(
            swm::AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_DL,
            true,
            value,
        ));
    }
    grouped_3gpp(swm::AVP_AMBR, true, &children)
}

fn complete_apn_children(extension: Option<Vec<u8>>) -> Vec<Vec<u8>> {
    let ipv4 = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    let ipv6 = IpAddr::V6(
        "2001:db8:352:1::"
            .parse::<Ipv6Addr>()
            .expect("synthetic canonical IPv6 prefix"),
    );
    let mut children = vec![
        vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
        raw_avp(
            swm::AVP_SERVED_PARTY_IP_ADDRESS,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            &address_value(ipv4),
        ),
        raw_avp(
            swm::AVP_SERVED_PARTY_IP_ADDRESS,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            &address_value(ipv6),
        ),
        vendor_u32(swm::AVP_PDN_TYPE, true, 2),
        raw_avp(
            swm::AVP_SERVICE_SELECTION,
            AvpFlags::MANDATORY,
            None,
            APN.as_bytes(),
        ),
        vendor_u32(swm::AVP_VPLMN_DYNAMIC_ADDRESS_ALLOWED, true, 1),
        agent_info(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        raw_avp(
            swm::AVP_VISITED_NETWORK_IDENTIFIER,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            b"mnc001.mcc001.3gppnetwork.org",
        ),
        vendor_u32(swm::AVP_PDN_GW_ALLOCATION_TYPE, true, 1),
        raw_avp(
            swm::AVP_3GPP_CHARGING_CHARACTERISTICS,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            b"A53C",
        ),
        raw_avp(
            swm::AVP_APN_OI_REPLACEMENT,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            APN_OI.as_bytes(),
        ),
        vendor_u32(swm::AVP_INTERWORKING_5GS_INDICATOR, false, 1),
    ];
    if let Some(extension) = extension {
        children.push(extension);
    }
    children
}

fn answer_wire(result_code: u32, extras: &[Vec<u8>]) -> Vec<u8> {
    let mut raw = Vec::new();
    for avp in [
        raw_avp(
            base::AVP_SESSION_ID,
            AvpFlags::MANDATORY,
            None,
            SESSION_ID.as_bytes(),
        ),
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
            &result_code.to_be_bytes(),
        ),
        raw_avp(
            base::AVP_ORIGIN_HOST,
            AvpFlags::MANDATORY,
            None,
            AAA_HOST.as_bytes(),
        ),
        raw_avp(
            base::AVP_ORIGIN_REALM,
            AvpFlags::MANDATORY,
            None,
            AAA_REALM.as_bytes(),
        ),
    ] {
        raw.extend_from_slice(&avp);
    }
    for extra in extras {
        raw.extend_from_slice(extra);
    }
    if result_code == base::RESULT_CODE_DIAMETER_SUCCESS {
        raw.extend_from_slice(&raw_avp(
            swm::AVP_EAP_PAYLOAD,
            AvpFlags::MANDATORY,
            None,
            &[3, 0x35, 0, 4],
        ));
    }
    encode(&OwnedMessage {
        header: Header::new(
            CommandFlags::answer(true, false),
            swm::COMMAND_DIAMETER_EAP,
            swm::APPLICATION_ID,
            HOP_BY_HOP,
            END_TO_END,
        ),
        raw_avps: Bytes::from(raw),
    })
}

fn request_wire(service_selection: &[u8]) -> Vec<u8> {
    let mut raw = Vec::new();
    for avp in [
        raw_avp(
            base::AVP_SESSION_ID,
            AvpFlags::MANDATORY,
            None,
            SESSION_ID.as_bytes(),
        ),
        raw_avp(
            base::AVP_AUTH_APPLICATION_ID,
            AvpFlags::MANDATORY,
            None,
            &swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        raw_avp(
            base::AVP_ORIGIN_HOST,
            AvpFlags::MANDATORY,
            None,
            EPDG_HOST.as_bytes(),
        ),
        raw_avp(
            base::AVP_ORIGIN_REALM,
            AvpFlags::MANDATORY,
            None,
            EPDG_REALM.as_bytes(),
        ),
        raw_avp(
            base::AVP_DESTINATION_REALM,
            AvpFlags::MANDATORY,
            None,
            AAA_REALM.as_bytes(),
        ),
        raw_avp(
            swm::AVP_SERVICE_SELECTION,
            AvpFlags::MANDATORY,
            None,
            service_selection,
        ),
        raw_avp(
            swm::AVP_AUTH_REQUEST_TYPE,
            AvpFlags::MANDATORY,
            None,
            &3_u32.to_be_bytes(),
        ),
        raw_avp(
            swm::AVP_EAP_PAYLOAD,
            AvpFlags::MANDATORY,
            None,
            &[2, 0x35, 0, 5, 1],
        ),
    ] {
        raw.extend_from_slice(&avp);
    }
    encode(&OwnedMessage {
        header: Header::new(
            CommandFlags::request(true),
            swm::COMMAND_DIAMETER_EAP,
            swm::APPLICATION_ID,
            HOP_BY_HOP,
            END_TO_END,
        ),
        raw_avps: Bytes::from(raw),
    })
}

fn framing_context() -> DecodeContext {
    DecodeContext {
        max_ies: 1_024,
        max_message_len: 256 * 1024,
        duplicate_ie_policy: DuplicateIePolicy::First,
        unknown_ie_policy: UnknownIePolicy::Preserve,
        ..DecodeContext::default()
    }
}

fn typed_context() -> DecodeContext {
    DecodeContext {
        max_ies: 1_024,
        max_message_len: 256 * 1024,
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        unknown_ie_policy: UnknownIePolicy::Preserve,
        ..DecodeContext::conservative()
    }
}

fn decode(wire: &[u8]) -> Message<'_> {
    let (tail, message) =
        Message::decode(wire, framing_context()).expect("synthetic Diameter framing");
    assert!(tail.is_empty());
    message
}

fn parse(wire: &[u8]) -> Result<swm::SwmDiameterEapAnswer, DecodeError> {
    swm::parse_swm_diameter_eap_answer(&decode(wire), typed_context())
}

fn encode(message: &OwnedMessage) -> Vec<u8> {
    let mut wire = BytesMut::new();
    message
        .encode(&mut wire, EncodeContext::default())
        .expect("synthetic Diameter message encodes");
    wire.to_vec()
}

fn raw_avps(mut wire: &[u8]) -> Vec<RawAvp<'_>> {
    let mut avps = Vec::new();
    while !wire.is_empty() {
        let (tail, avp) = RawAvp::decode(wire, framing_context()).expect("synthetic AVP decodes");
        avps.push(avp);
        wire = tail;
    }
    avps
}

fn sample_request(emergency: bool) -> swm::SwmDiameterEapRequest {
    swm::SwmDiameterEapRequest {
        session_id: SESSION_ID.to_owned().into(),
        auth_application_id: swm::APPLICATION_ID.get(),
        origin_host: EPDG_HOST.to_owned().into(),
        origin_realm: EPDG_REALM.to_owned().into(),
        destination_realm: AAA_REALM.to_owned().into(),
        destination_host: Some(AAA_HOST.to_owned().into()),
        user_name: Some("subscriber@synthetic.invalid".to_owned().into()),
        rat_type: None,
        service_selection: Some(APN.to_owned().into()),
        mip6_feature_vector: Some(swm::SwmMip6FeatureVector::gtpv2_only()),
        qos_capability: None,
        visited_network_identifier: None,
        aaa_failure_indication: None,
        supported_features: Vec::new(),
        ue_local_ip_address: None,
        oc_supported_features: None,
        auth_request_type: AuthRequestType::AuthorizeAuthenticate,
        eap_payload: vec![2, 0x35, 0, 5, 1].into(),
        emergency_services: emergency.then_some(swm::SwmEmergencyServices::emergency_indication()),
        terminal_information: None,
        high_priority_access_info: None,
        state_avps: Vec::new(),
        route_records: Vec::new(),
        extensions: Default::default(),
    }
}

fn sample_answer() -> swm::SwmDiameterEapAnswer {
    swm::SwmDiameterEapAnswer {
        session_id: SESSION_ID.to_owned().into(),
        auth_application_id: swm::APPLICATION_ID.get(),
        auth_request_type: AuthRequestType::AuthorizeAuthenticate,
        result: swm::SwmDiameterResult::Base(base::RESULT_CODE_DIAMETER_SUCCESS),
        origin_host: AAA_HOST.to_owned().into(),
        origin_realm: AAA_REALM.to_owned().into(),
        user_name: None,
        mip6_feature_vector: Some(swm::SwmMip6FeatureVector::gtpv2_only()),
        supported_features: Vec::new(),
        oc_supported_features: None,
        oc_olr: None,
        load_reports: Vec::new(),
        service_selection: None,
        default_context_identifier: Some(7),
        apn_configurations: Vec::new(),
        subscriber_authorization: Default::default(),
        mobile_node_identifier: None,
        session_timeout: None,
        authorization_lifetime: None,
        auth_grace_period: None,
        re_auth_request_type: None,
        eap_payload: Some(vec![3, 0x35, 0, 4].into()),
        eap_reissued_payload: None,
        error_message: None,
        state_avps: Vec::new(),
        eap_master_session_key: None,
        extensions: Default::default(),
    }
}

fn sample_core(pdn_type: swm::PdnType, service_selection: &str) -> swm::ApnConfiguration {
    swm::ApnConfiguration {
        context_identifier: 7,
        service_selection: service_selection.to_owned().into(),
        pdn_type,
        eps_subscribed_qos_profile: None,
        ambr: None,
    }
}

fn sample_gateway() -> swm::SwmMip6AgentInfo {
    swm::SwmMip6AgentInfo::new(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))], None, None)
        .expect("synthetic gateway")
}

fn correlate_wire(
    wire: &[u8],
    ctx: DecodeContext,
    requested_apn: Option<&str>,
) -> swm::SwmCorrelatedDiameterEapResponse {
    let response = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(wire),
        CONNECTION,
        ctx,
    )
    .expect("authenticated response envelope");
    let mut request = sample_request(false);
    request.service_selection = requested_apn.map(|value| value.to_owned().into());
    request.mip6_feature_vector = match response.response() {
        swm::SwmDiameterEapResponse::Application(answer) => answer.mip6_feature_vector,
        swm::SwmDiameterEapResponse::GenericError(_) => None,
    };
    let outbound = swm::SwmDiameterEapRequestEnvelope::for_outbound_on(
        request,
        swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END),
        swm::SwmExpectedAnswerPeer::direct(CONNECTION, AAA_HOST.to_owned(), AAA_REALM.to_owned()),
    )
    .with_locally_configured_mobility_mode(swm::SwmLocallyConfiguredMobilityMode::NetworkBased);
    outbound
        .correlate_response(response)
        .expect("authenticated peer and complete DER/DEA correlation")
}

#[test]
fn independent_complete_fixture_round_trips_and_exposes_typed_views() {
    let unknown = raw_avp(
        AvpCode::new(61_352),
        AvpFlags::PROTECTED,
        None,
        b"sealed-extension",
    );
    let apn = apn_configuration(&complete_apn_children(Some(unknown.clone())));
    let wire = answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &[apn]);
    let parsed = parse(&wire).expect("complete standards-authored APN fixture");
    let correlated = correlate_wire(&wire, typed_context(), Some(APN));
    let mut views = correlated
        .apn_configuration_views()
        .expect("strictly correlated supplements are available");
    let view = views.next().expect("one APN view");
    assert!(views.next().is_none());
    assert_eq!(view.core().context_identifier, 7);
    assert_eq!(view.core().pdn_type, swm::PdnType::Ipv4v6);
    assert_eq!(view.served_party_ip_addresses().len(), 2);
    assert!(matches!(
        view.served_party_ip_addresses(),
        [IpAddr::V4(_), IpAddr::V6(_)]
    ));
    assert_eq!(
        view.vplmn_dynamic_address_allowed(),
        Some(swm::SwmVplmnDynamicAddressAllowed::Allowed)
    );
    assert_eq!(
        view.effective_vplmn_dynamic_address_allowed(),
        swm::SwmVplmnDynamicAddressAllowed::Allowed
    );
    assert_eq!(
        view.pdn_gw_allocation_type(),
        Some(swm::SwmPdnGwAllocationType::Dynamic)
    );
    assert_eq!(
        view.effective_pdn_gw_allocation_type(),
        Some(swm::SwmPdnGwAllocationType::Dynamic)
    );
    assert_eq!(
        view.interworking_5gs_indicator(),
        Some(swm::SwmInterworking5gsIndicator::Subscribed)
    );
    assert_eq!(
        view.charging_characteristics(),
        Some(swm::SwmChargingCharacteristics::from_octets([0xa5, 0x3c]))
    );
    assert_eq!(
        view.apn_oi_replacement()
            .map(swm::SwmApnOiReplacement::as_str),
        Some(APN_OI)
    );
    assert_eq!(
        view.effective_interworking_5gs_indicator(),
        swm::SwmInterworking5gsIndicator::Subscribed
    );
    assert_eq!(
        view.visited_network_identifier()
            .map(swm::SwmVisitedNetworkIdentifier::as_str),
        Some("mnc001.mcc001.3gppnetwork.org")
    );
    assert!(view.mip6_agent_info().is_some());
    let metadata: Vec<_> = view.extension_metadata().collect();
    assert_eq!(metadata.len(), 1);
    assert_eq!(metadata[0].code(), AvpCode::new(61_352));

    let debug = format!("{parsed:?} {view:?}");
    for private in [
        APN,
        "198.51.100.10",
        "2001:db8:352",
        "mnc001.mcc001",
        APN_OI,
        "A53C",
        "sealed-extension",
    ] {
        assert!(!debug.contains(private));
    }

    let rebuilt = encode(
        &swm::build_swm_diameter_eap_answer(
            &parsed,
            HOP_BY_HOP,
            END_TO_END,
            EncodeContext::default(),
        )
        .expect("parsed complete APN rebuilds"),
    );
    assert_eq!(rebuilt, wire);
}

#[test]
fn supplemental_apn_views_require_authenticated_connection_and_origin_correlation() {
    let wire = answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&complete_apn_children(None))],
    );
    let response = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wire),
        CONNECTION,
        typed_context(),
    )
    .expect("authenticated response envelope");
    let request_for = |connection, host: &str| {
        let mut request = sample_request(false);
        request.mip6_feature_vector = None;
        swm::SwmDiameterEapRequestEnvelope::for_outbound_on(
            request,
            swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END),
            swm::SwmExpectedAnswerPeer::direct(connection, host.to_owned(), AAA_REALM.to_owned()),
        )
        .with_locally_configured_mobility_mode(swm::SwmLocallyConfiguredMobilityMode::NetworkBased)
    };
    let other_connection =
        swm::SwmDiameterConnectionToken::new(NonZeroU64::new(2).expect("nonzero token"));
    assert_eq!(
        request_for(other_connection, AAA_HOST)
            .correlate_response(response.clone())
            .expect_err("connection generation mismatch must fail"),
        swm::SwmDiameterEapCorrelationError::PeerConnectionMismatch
    );
    assert_eq!(
        request_for(CONNECTION, "other-aaa.synthetic.invalid")
            .correlate_response(response.clone())
            .expect_err("authenticated Origin-Host mismatch must fail"),
        swm::SwmDiameterEapCorrelationError::PeerIdentityMismatch
    );
    let correlated = request_for(CONNECTION, AAA_HOST)
        .correlate_response(response)
        .expect("strict correlation succeeds");
    assert_eq!(
        correlated
            .authorized_apn_configurations()
            .expect("policy APN view is unlocked only now")
            .len(),
        1
    );
}

#[test]
fn understood_outer_apn_accepts_both_m_shapes_and_rebuilds_canonically() {
    let children: Vec<u8> = complete_apn_children(None).into_iter().flatten().collect();
    for mandatory in [false, true] {
        let outer = raw_avp(
            swm::AVP_APN_CONFIGURATION,
            AvpFlags::VENDOR | if mandatory { AvpFlags::MANDATORY } else { 0 },
            Some(VENDOR_ID_3GPP),
            &children,
        );
        let wire = answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &[outer]);
        let (tail, message) = Message::decode_with_dictionary(
            &wire,
            typed_context(),
            SWM_PROJECTED_PROFILE_DICTIONARIES,
        )
        .expect("global dictionary accepts understood APN M mismatch");
        assert!(tail.is_empty());
        let parsed = swm::parse_swm_diameter_eap_answer(&message, typed_context())
            .expect("typed parser accepts understood APN M mismatch");
        let rebuilt = swm::build_swm_diameter_eap_answer(
            &parsed,
            HOP_BY_HOP,
            END_TO_END,
            EncodeContext::default(),
        )
        .expect("understood APN rebuilds canonically");
        let rebuilt_wire = encode(&rebuilt);
        let rebuilt_message = decode(&rebuilt_wire);
        let rebuilt_outer = raw_avps(rebuilt_message.raw_avps)
            .into_iter()
            .find(|avp| avp.header.code == swm::AVP_APN_CONFIGURATION)
            .expect("canonical APN outer");
        assert!(rebuilt_outer.header.flags.is_mandatory());
        assert!(!rebuilt_outer.header.flags.is_protected());
    }
}

#[test]
fn checked_request_bound_mutator_is_atomic_and_emits_canonical_flags() {
    let transaction = swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END);
    let request =
        swm::SwmDiameterEapRequestEnvelope::for_outbound(sample_request(false), transaction);
    let visited = swm::SwmVisitedNetworkIdentifier::new(VISITED_MCC, VISITED_MNC)
        .expect("synthetic visited PLMN");
    let builder =
        swm::SwmAuthorizedApnConfiguration::builder(sample_core(swm::PdnType::Ipv4v6, APN))
            .add_served_party_ip_address(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)))
            .expect("first family");
    let authorized = builder
        .add_served_party_ip_address(IpAddr::V6(
            "2001:db8:352:1::"
                .parse()
                .expect("canonical synthetic IPv6 prefix"),
        ))
        .expect("second family")
        .with_vplmn_dynamic_address_allowed(swm::SwmVplmnDynamicAddressAllowed::Allowed)
        .with_mip6_agent_info(sample_gateway())
        .with_pdn_gw_allocation_type(swm::SwmPdnGwAllocationType::Dynamic)
        .with_visited_network_identifier(visited)
        .with_charging_characteristics(swm::SwmChargingCharacteristics::from_octets([0xa5, 0x3c]))
        .with_apn_oi_replacement(swm::SwmApnOiReplacement::new(APN_OI).expect("synthetic APN-OI"))
        .with_interworking_5gs_indicator(swm::SwmInterworking5gsIndicator::Subscribed)
        .build()
        .expect("complete APN relationships");
    let mut answer = sample_answer();
    answer
        .set_authorized_apn_configurations_for(&request, vec![authorized])
        .expect("request-bound APN mutation");
    let wire = encode(
        &swm::build_swm_diameter_eap_answer_for(&request, &answer, EncodeContext::default())
            .expect("request-bound answer"),
    );
    let message = decode(&wire);
    let outer = raw_avps(message.raw_avps)
        .into_iter()
        .find(|avp| avp.header.code == swm::AVP_APN_CONFIGURATION)
        .expect("APN-Configuration emitted");
    assert_eq!(outer.header.vendor_id, Some(VENDOR_ID_3GPP));
    assert!(outer.header.flags.is_mandatory());
    let children = raw_avps(outer.value);
    let child_codes: Vec<_> = children.iter().map(|child| child.header.code).collect();
    assert_eq!(
        child_codes,
        [
            swm::AVP_CONTEXT_IDENTIFIER,
            swm::AVP_SERVED_PARTY_IP_ADDRESS,
            swm::AVP_SERVED_PARTY_IP_ADDRESS,
            swm::AVP_PDN_TYPE,
            swm::AVP_SERVICE_SELECTION,
            swm::AVP_VPLMN_DYNAMIC_ADDRESS_ALLOWED,
            swm::AVP_MIP6_AGENT_INFO,
            swm::AVP_VISITED_NETWORK_IDENTIFIER,
            swm::AVP_PDN_GW_ALLOCATION_TYPE,
            swm::AVP_3GPP_CHARGING_CHARACTERISTICS,
            swm::AVP_APN_OI_REPLACEMENT,
            swm::AVP_INTERWORKING_5GS_INDICATOR,
        ]
    );
    let served: Vec<_> = children
        .iter()
        .filter(|child| child.header.code == swm::AVP_SERVED_PARTY_IP_ADDRESS)
        .collect();
    assert_eq!(served.len(), 2);
    assert!(served.iter().all(|child| {
        child.header.vendor_id == Some(VENDOR_ID_3GPP)
            && child.header.flags.is_mandatory()
            && !child.header.flags.is_protected()
    }));
    let interworking = children
        .iter()
        .find(|child| child.header.code == swm::AVP_INTERWORKING_5GS_INDICATOR)
        .expect("Interworking-5GS-Indicator");
    assert!(interworking.header.flags.is_vendor_specific());
    assert!(!interworking.header.flags.is_mandatory());
    assert!(!interworking.header.flags.is_protected());
    let charging = children
        .iter()
        .find(|child| child.header.code == swm::AVP_3GPP_CHARGING_CHARACTERISTICS)
        .expect("3GPP-Charging-Characteristics");
    assert_eq!(charging.header.vendor_id, Some(VENDOR_ID_3GPP));
    assert!(!charging.header.flags.is_mandatory());
    assert!(!charging.header.flags.is_protected());
    assert_eq!(charging.value, b"A53C");
    let apn_oi = children
        .iter()
        .find(|child| child.header.code == swm::AVP_APN_OI_REPLACEMENT)
        .expect("APN-OI-Replacement");
    assert_eq!(apn_oi.header.vendor_id, Some(VENDOR_ID_3GPP));
    assert!(apn_oi.header.flags.is_mandatory());
    assert!(!apn_oi.header.flags.is_protected());
    assert_eq!(apn_oi.value, APN_OI.as_bytes());
    let correlated = correlate_wire(&wire, typed_context(), Some(APN));
    assert_eq!(
        correlated
            .default_apn_configuration_view()
            .expect("strictly correlated supplements are available")
            .expect("default APN")
            .core()
            .context_identifier,
        7
    );

    let replacement = || {
        let mut core = sample_core(swm::PdnType::Ipv4, APN);
        core.context_identifier = 8;
        swm::SwmAuthorizedApnConfiguration::builder(core)
            .add_served_party_ip_address(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11)))
            .expect("replacement static IPv4")
            .with_mip6_agent_info(sample_gateway())
            .build()
            .expect("replacement APN")
    };
    assert_eq!(
        answer
            .set_authorized_apn_profile_for(&request, Some(9), vec![replacement()])
            .expect_err("proposed default must resolve before mutation")
            .code(),
        swm::SwmApnConfigurationErrorCode::DefaultContextIdentifierMissing
    );
    assert_eq!(answer.default_context_identifier, Some(7));
    assert_eq!(
        answer
            .default_apn_configuration()
            .expect("prior default remains present")
            .context_identifier,
        7
    );
    answer
        .set_authorized_apn_profile_for(&request, Some(8), vec![replacement()])
        .expect("valid default and APN replace atomically");
    assert_eq!(answer.default_context_identifier, Some(8));
}

#[test]
fn checked_mutator_rejects_request_result_mobility_and_correlation_contradictions() {
    let transaction = swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END);
    let normal =
        swm::SwmDiameterEapRequestEnvelope::for_outbound(sample_request(false), transaction);
    let emergency =
        swm::SwmDiameterEapRequestEnvelope::for_outbound(sample_request(true), transaction);
    let complete = || {
        swm::SwmAuthorizedApnConfiguration::builder(sample_core(swm::PdnType::Ipv4, APN))
            .add_served_party_ip_address(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)))
            .expect("static IPv4")
            .with_mip6_agent_info(sample_gateway())
            .build()
            .expect("complete APN")
    };

    let mut answer = sample_answer();
    assert_eq!(
        answer
            .set_authorized_apn_configurations_for(&emergency, vec![complete()])
            .expect_err("emergency APN is forbidden")
            .code(),
        swm::SwmApnConfigurationErrorCode::EmergencyRequest
    );
    assert!(answer.apn_configurations.is_empty(), "mutation is atomic");

    answer.result = swm::SwmDiameterResult::Base(base::RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY);
    assert_eq!(
        answer
            .set_authorized_apn_configurations_for(&normal, vec![complete()])
            .expect_err("non-success APN is forbidden")
            .code(),
        swm::SwmApnConfigurationErrorCode::ResultNotExactSuccess
    );

    let mut answer = sample_answer();
    answer.mip6_feature_vector = None;
    assert_eq!(
        answer
            .set_authorized_apn_configurations_for(&normal, vec![complete()])
            .expect_err("network fields require selected NBM")
            .code(),
        swm::SwmApnConfigurationErrorCode::RequestMismatch
    );

    let wrong = swm::SwmAuthorizedApnConfiguration::new(sample_core(
        swm::PdnType::Ipv4,
        "other.synthetic.invalid",
    ))
    .expect("standalone core");
    let mut answer = sample_answer();
    assert_eq!(
        answer
            .set_authorized_apn_configurations_for(&normal, vec![wrong])
            .expect_err("requested APN must be returned")
            .code(),
        swm::SwmApnConfigurationErrorCode::RequestedApnMissing
    );

    let mut answer = sample_answer();
    answer
        .set_authorized_apn_configurations_for(&normal, vec![complete()])
        .expect("initial correlated APN");
    answer.apn_configurations[0].context_identifier = 8;
    assert!(
        swm::build_swm_diameter_eap_answer_for(&normal, &answer, EncodeContext::default()).is_err(),
        "mutated public core must not misassociate or re-encode"
    );

    let mut answer = sample_answer();
    answer
        .set_authorized_apn_configurations_for(&normal, vec![complete()])
        .expect("initial correlated APN");
    answer.apn_configurations[0].pdn_type = swm::PdnType::Ipv6;
    assert!(
        swm::build_swm_diameter_eap_answer_for(&normal, &answer, EncodeContext::default()).is_err(),
        "semantically changed public core must not re-encode"
    );

    let mut second_core = sample_core(swm::PdnType::Ipv4, "second.synthetic.invalid");
    second_core.context_identifier = 8;
    let second = swm::SwmAuthorizedApnConfiguration::builder(second_core)
        .add_served_party_ip_address(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11)))
        .expect("second static IPv4")
        .with_mip6_agent_info(sample_gateway())
        .build()
        .expect("second complete APN");
    let mut answer = sample_answer();
    answer
        .set_authorized_apn_configurations_for(&normal, vec![complete(), second])
        .expect("two correlated APNs");
    answer.apn_configurations.swap(0, 1);
    assert!(
        swm::build_swm_diameter_eap_answer_for(&normal, &answer, EncodeContext::default()).is_err(),
        "reordered public cores must not misassociate or re-encode"
    );
}

#[test]
fn local_assignment_rejects_every_network_based_only_apn_field() {
    let transaction = swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END);
    let mut request_facts = sample_request(false);
    request_facts.mip6_feature_vector = None;
    let request = swm::SwmDiameterEapRequestEnvelope::for_outbound(request_facts, transaction)
        .with_locally_configured_mobility_mode(
            swm::SwmLocallyConfiguredMobilityMode::LocalIpAddressAssignment,
        );
    let base_core = sample_core(swm::PdnType::Ipv4, APN);

    let mut qos_core = base_core.clone();
    qos_core.eps_subscribed_qos_profile = Some(swm::EpsSubscribedQosProfile {
        qos_class_identifier: swm::SwmQosClassIdentifier::new(9).expect("standard QCI"),
        allocation_retention_priority: swm::AllocationRetentionPriority {
            priority_level: swm::SwmPriorityLevel::new(15).expect("valid priority"),
            pre_emption_capability: Some(swm::SwmPreemptionCapability::Disabled),
            pre_emption_vulnerability: Some(swm::SwmPreemptionVulnerability::Enabled),
        },
    });
    let mut ambr_core = base_core.clone();
    ambr_core.ambr = Some(swm::Ambr::new(50_000_000, 150_000_000).expect("valid AMBR"));

    let configurations = [
        swm::SwmAuthorizedApnConfiguration::builder(qos_core)
            .with_mip6_agent_info(sample_gateway())
            .build()
            .expect("QoS APN is structurally valid"),
        swm::SwmAuthorizedApnConfiguration::builder(ambr_core)
            .with_mip6_agent_info(sample_gateway())
            .build()
            .expect("AMBR APN is structurally valid"),
        swm::SwmAuthorizedApnConfiguration::builder(base_core.clone())
            .with_mip6_agent_info(sample_gateway())
            .with_pdn_gw_allocation_type(swm::SwmPdnGwAllocationType::Static)
            .build()
            .expect("gateway allocation APN is structurally valid"),
        swm::SwmAuthorizedApnConfiguration::builder(base_core.clone())
            .with_mip6_agent_info(sample_gateway())
            .with_charging_characteristics(swm::SwmChargingCharacteristics::from_octets([
                0xa5, 0x3c,
            ]))
            .build()
            .expect("charging APN is structurally valid"),
        swm::SwmAuthorizedApnConfiguration::builder(base_core.clone())
            .with_mip6_agent_info(sample_gateway())
            .with_apn_oi_replacement(
                swm::SwmApnOiReplacement::new(APN_OI).expect("synthetic APN-OI"),
            )
            .build()
            .expect("APN-OI APN is structurally valid"),
    ];

    for configuration in configurations {
        let mut answer = sample_answer();
        answer.mip6_feature_vector = None;
        assert_eq!(
            answer
                .set_authorized_apn_configurations_for(&request, vec![configuration])
                .expect_err("NBM-only field must fail under local assignment")
                .code(),
            swm::SwmApnConfigurationErrorCode::MobilityModeMismatch
        );
        assert!(answer.apn_configurations.is_empty(), "mutation is atomic");
    }

    let minimal = swm::SwmAuthorizedApnConfiguration::builder(base_core)
        .with_mip6_agent_info(sample_gateway())
        .build()
        .expect("minimal local-assignment APN");
    let mut answer = sample_answer();
    answer.mip6_feature_vector = None;
    answer
        .set_authorized_apn_configurations_for(&request, vec![minimal])
        .expect("local assignment permits only HA-APN plus gateway identity");
    let wire = encode(
        &swm::build_swm_diameter_eap_answer_for(&request, &answer, EncodeContext::default())
            .expect("local-assignment answer encodes"),
    );
    let correlated = correlate_wire(&wire, typed_context(), Some(APN));
    let local = correlated
        .default_apn_configuration_view()
        .expect("strict local supplement view")
        .expect("local default APN");
    assert_eq!(
        local.effective_pdn_gw_allocation_type(),
        Some(swm::SwmPdnGwAllocationType::Static)
    );
    assert_eq!(
        local.effective_vplmn_dynamic_address_allowed(),
        swm::SwmVplmnDynamicAddressAllowed::NotAllowed
    );
    assert_eq!(
        local.effective_interworking_5gs_indicator(),
        swm::SwmInterworking5gsIndicator::NotSubscribed
    );
}

#[test]
fn explicit_local_mobility_requires_integrated_ha_discovery_for_apn_data() {
    let transaction = swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END);
    let mut request_facts = sample_request(false);
    request_facts.mip6_feature_vector = Some(swm::SwmMip6FeatureVector::from_bits_retain(
        swm::SwmMip6FeatureVector::MIP6_INTEGRATED,
    ));
    let request = swm::SwmDiameterEapRequestEnvelope::for_outbound(request_facts, transaction);
    let minimal = || {
        swm::SwmAuthorizedApnConfiguration::builder(sample_core(swm::PdnType::Ipv4, APN))
            .with_mip6_agent_info(sample_gateway())
            .build()
            .expect("minimal HA-discovery APN")
    };

    let mut answer = sample_answer();
    answer.mip6_feature_vector = Some(swm::SwmMip6FeatureVector::from_bits_retain(
        swm::SwmMip6FeatureVector::ASSIGN_LOCAL_IP,
    ));
    assert_eq!(
        answer
            .set_authorized_apn_configurations_for(&request, vec![minimal()])
            .expect_err("explicit local selection without HA discovery is contradictory")
            .code(),
        swm::SwmApnConfigurationErrorCode::MobilityModeMismatch
    );
    assert!(answer.apn_configurations.is_empty());

    answer.mip6_feature_vector = Some(swm::SwmMip6FeatureVector::from_bits_retain(
        swm::SwmMip6FeatureVector::ASSIGN_LOCAL_IP | swm::SwmMip6FeatureVector::MIP6_INTEGRATED,
    ));
    answer
        .set_authorized_apn_configurations_for(&request, vec![minimal()])
        .expect("explicit local assignment plus HA discovery permits minimal APN data");
}

#[test]
fn local_mobility_provenance_is_required_and_explicit_aaa_selection_wins() {
    let transaction = swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END);
    let network_configuration = || {
        swm::SwmAuthorizedApnConfiguration::builder(sample_core(swm::PdnType::Ipv4, APN))
            .add_served_party_ip_address(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)))
            .expect("synthetic static address")
            .build()
            .expect("network-based APN")
    };

    let mut no_offer = sample_request(false);
    no_offer.mip6_feature_vector = None;
    let no_provenance =
        swm::SwmDiameterEapRequestEnvelope::for_outbound(no_offer.clone(), transaction);
    let mut answer = sample_answer();
    answer.mip6_feature_vector = None;
    assert_eq!(
        answer
            .set_authorized_apn_configurations_for(&no_provenance, vec![network_configuration()],)
            .expect_err("APN authorization needs AAA or trusted local mobility provenance")
            .code(),
        swm::SwmApnConfigurationErrorCode::MobilityModeMismatch
    );

    let parsed_profile = parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&complete_apn_children(None))],
    ))
    .expect("standalone DEA retains wire facts before request conditioning");
    assert!(swm::build_swm_diameter_eap_answer_for(
        &no_provenance,
        &parsed_profile,
        EncodeContext::default(),
    )
    .is_err());

    let local_network = swm::SwmDiameterEapRequestEnvelope::for_outbound(no_offer, transaction)
        .with_locally_configured_mobility_mode(swm::SwmLocallyConfiguredMobilityMode::NetworkBased);
    answer
        .set_authorized_apn_configurations_for(&local_network, vec![network_configuration()])
        .expect("trusted local network-based mode applies when DEA omits its vector");
    swm::build_swm_diameter_eap_answer_for(
        &local_network,
        &parsed_profile,
        EncodeContext::default(),
    )
    .expect("trusted local network-based provenance validates parsed APN facts");

    let local_input =
        swm::SwmDiameterEapRequestEnvelope::for_outbound(sample_request(false), transaction)
            .with_locally_configured_mobility_mode(
                swm::SwmLocallyConfiguredMobilityMode::LocalIpAddressAssignment,
            );
    let mut explicit_network = sample_answer();
    explicit_network
        .set_authorized_apn_configurations_for(&local_input, vec![network_configuration()])
        .expect("explicit AAA network-based selection overrides local fallback");

    let mut local_offer = sample_request(false);
    local_offer.mip6_feature_vector = Some(swm::SwmMip6FeatureVector::from_bits_retain(
        swm::SwmMip6FeatureVector::ASSIGN_LOCAL_IP | swm::SwmMip6FeatureVector::MIP6_INTEGRATED,
    ));
    let local_network_fallback =
        swm::SwmDiameterEapRequestEnvelope::for_outbound(local_offer, transaction)
            .with_locally_configured_mobility_mode(
                swm::SwmLocallyConfiguredMobilityMode::NetworkBased,
            );
    let mut explicit_local = sample_answer();
    explicit_local.mip6_feature_vector = Some(swm::SwmMip6FeatureVector::from_bits_retain(
        swm::SwmMip6FeatureVector::ASSIGN_LOCAL_IP | swm::SwmMip6FeatureVector::MIP6_INTEGRATED,
    ));
    assert_eq!(
        explicit_local
            .set_authorized_apn_configurations_for(
                &local_network_fallback,
                vec![network_configuration()],
            )
            .expect_err("explicit AAA local selection overrides local network fallback")
            .code(),
        swm::SwmApnConfigurationErrorCode::MobilityModeMismatch
    );
}

#[test]
fn per_apn_charging_and_apn_oi_codec_is_strict_canonical_and_redacted() {
    let core = || {
        vec![
            vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
            vendor_u32(swm::AVP_PDN_TYPE, true, 0),
            raw_avp(
                swm::AVP_SERVICE_SELECTION,
                AvpFlags::MANDATORY,
                None,
                APN.as_bytes(),
            ),
        ]
    };
    let mut positive = core();
    positive.push(raw_avp(
        swm::AVP_3GPP_CHARGING_CHARACTERISTICS,
        AvpFlags::VENDOR | AvpFlags::PROTECTED,
        Some(VENDOR_ID_3GPP),
        b"a53c",
    ));
    positive.push(raw_avp(
        swm::AVP_APN_OI_REPLACEMENT,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(VENDOR_ID_3GPP),
        APN_OI.as_bytes(),
    ));
    let wire = answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&positive)],
    );
    let parsed = parse(&wire).expect("valid protected charging and canonical APN-OI");
    let correlated = correlate_wire(&wire, typed_context(), Some(APN));
    let view = correlated
        .apn_configuration_views()
        .expect("strict supplement correlation")
        .next()
        .expect("one APN");
    assert_eq!(
        view.charging_characteristics(),
        Some(swm::SwmChargingCharacteristics::from_octets([0xa5, 0x3c]))
    );
    assert_eq!(
        view.apn_oi_replacement()
            .map(swm::SwmApnOiReplacement::as_str),
        Some(APN_OI)
    );
    let debug = format!("{parsed:?} {view:?}");
    assert!(!debug.contains(APN_OI));
    assert!(!debug.contains("a53c"));
    assert!(!debug.contains("A53C"));

    let rebuilt = swm::build_swm_diameter_eap_answer(
        &parsed,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .expect("known values rebuild canonically");
    let rebuilt_wire = encode(&rebuilt);
    let rebuilt_message = decode(&rebuilt_wire);
    let rebuilt_apn = raw_avps(rebuilt_message.raw_avps)
        .into_iter()
        .find(|avp| avp.header.code == swm::AVP_APN_CONFIGURATION)
        .expect("rebuilt APN");
    let rebuilt_charging = raw_avps(rebuilt_apn.value)
        .into_iter()
        .find(|avp| avp.header.code == swm::AVP_3GPP_CHARGING_CHARACTERISTICS)
        .expect("rebuilt charging");
    assert_eq!(rebuilt_charging.value, b"A53C");
    assert!(!rebuilt_charging.header.flags.is_mandatory());
    assert!(!rebuilt_charging.header.flags.is_protected());

    let invalid_children = [
        raw_avp(
            swm::AVP_3GPP_CHARGING_CHARACTERISTICS,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            b"A53",
        ),
        raw_avp(
            swm::AVP_3GPP_CHARGING_CHARACTERISTICS,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            b"ZZZZ",
        ),
        raw_avp(
            swm::AVP_APN_OI_REPLACEMENT,
            AvpFlags::VENDOR | AvpFlags::MANDATORY | AvpFlags::PROTECTED,
            Some(VENDOR_ID_3GPP),
            APN_OI.as_bytes(),
        ),
        raw_avp(
            swm::AVP_APN_OI_REPLACEMENT,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            b"not-a-3gpp-operator-id.invalid",
        ),
        raw_avp(
            swm::AVP_APN_OI_REPLACEMENT,
            AvpFlags::MANDATORY,
            None,
            APN_OI.as_bytes(),
        ),
    ];
    for invalid in invalid_children {
        let mut children = core();
        children.push(invalid);
        assert!(parse(&answer_wire(
            base::RESULT_CODE_DIAMETER_SUCCESS,
            &[apn_configuration(&children)],
        ))
        .is_err());
    }

    for duplicate in [
        raw_avp(
            swm::AVP_3GPP_CHARGING_CHARACTERISTICS,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            b"A53C",
        ),
        raw_avp(
            swm::AVP_APN_OI_REPLACEMENT,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            APN_OI.as_bytes(),
        ),
    ] {
        let mut children = core();
        children.push(duplicate.clone());
        children.push(duplicate);
        assert!(parse(&answer_wire(
            base::RESULT_CODE_DIAMETER_SUCCESS,
            &[apn_configuration(&children)],
        ))
        .is_err());
    }
}

#[test]
fn public_builder_rejects_address_and_gateway_relationship_errors() {
    let duplicate_family =
        swm::SwmAuthorizedApnConfiguration::builder(sample_core(swm::PdnType::Ipv4v6, APN))
            .add_served_party_ip_address("198.51.100.10".parse().expect("IPv4"))
            .expect("first IPv4")
            .add_served_party_ip_address("198.51.100.11".parse().expect("IPv4"))
            .expect_err("one address per family");
    assert_eq!(
        duplicate_family.code(),
        swm::SwmApnConfigurationErrorCode::DuplicateServedPartyAddressFamily
    );

    let bad_prefix =
        swm::SwmAuthorizedApnConfiguration::builder(sample_core(swm::PdnType::Ipv6, APN))
            .add_served_party_ip_address("2001:db8::1".parse().expect("IPv6"))
            .expect_err("lower 64 bits must be zero");
    assert_eq!(
        bad_prefix.code(),
        swm::SwmApnConfigurationErrorCode::NoncanonicalIpv6Prefix
    );

    for address in [
        "0.0.0.0",
        "127.0.0.1",
        "169.254.1.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "fe80::",
        "ff00::",
    ] {
        assert_eq!(
            swm::SwmAuthorizedApnConfiguration::builder(sample_core(swm::PdnType::Ipv4v6, APN,))
                .add_served_party_ip_address(address.parse().expect("synthetic invalid IP class"))
                .expect_err("non-assignable static address must fail")
                .code(),
            swm::SwmApnConfigurationErrorCode::InvalidServedPartyAddress
        );
    }

    let mismatch =
        swm::SwmAuthorizedApnConfiguration::builder(sample_core(swm::PdnType::Ipv4, APN))
            .add_served_party_ip_address("2001:db8:352::".parse().expect("IPv6"))
            .expect("canonical prefix")
            .build()
            .expect_err("PDN-Type and address family must agree");
    assert_eq!(
        mismatch.code(),
        swm::SwmApnConfigurationErrorCode::PdnTypeAddressMismatch
    );

    let allocation_without_gateway =
        swm::SwmAuthorizedApnConfiguration::builder(sample_core(swm::PdnType::Ipv4, APN))
            .with_pdn_gw_allocation_type(swm::SwmPdnGwAllocationType::Static)
            .build()
            .expect_err("allocation applies only to MIP6-Agent-Info");
    assert_eq!(
        allocation_without_gateway.code(),
        swm::SwmApnConfigurationErrorCode::AllocationWithoutGateway
    );

    let visited = swm::SwmVisitedNetworkIdentifier::new(VISITED_MCC, VISITED_MNC)
        .expect("synthetic visited PLMN");
    let visited_without_dynamic =
        swm::SwmAuthorizedApnConfiguration::builder(sample_core(swm::PdnType::Ipv4, APN))
            .with_mip6_agent_info(sample_gateway())
            .with_pdn_gw_allocation_type(swm::SwmPdnGwAllocationType::Static)
            .with_visited_network_identifier(visited)
            .build()
            .expect_err("visited PLMN describes dynamic allocation");
    assert_eq!(
        visited_without_dynamic.code(),
        swm::SwmApnConfigurationErrorCode::VisitedNetworkWithoutDynamicGateway
    );
}

#[test]
fn wire_parser_rejects_flags_width_cardinality_semantics_and_truncation() {
    let core = || {
        vec![
            vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
            vendor_u32(swm::AVP_PDN_TYPE, true, 0),
            raw_avp(
                swm::AVP_SERVICE_SELECTION,
                AvpFlags::MANDATORY,
                None,
                APN.as_bytes(),
            ),
        ]
    };
    let mut cases = Vec::new();

    let mut wrong_vendor = core();
    wrong_vendor.push(raw_avp(
        swm::AVP_VPLMN_DYNAMIC_ADDRESS_ALLOWED,
        AvpFlags::MANDATORY,
        None,
        &1_u32.to_be_bytes(),
    ));
    cases.push(wrong_vendor);

    let mut protected = core();
    protected.push(raw_avp(
        swm::AVP_VPLMN_DYNAMIC_ADDRESS_ALLOWED,
        AvpFlags::VENDOR | AvpFlags::MANDATORY | AvpFlags::PROTECTED,
        Some(VENDOR_ID_3GPP),
        &1_u32.to_be_bytes(),
    ));
    cases.push(protected);

    let mut wrong_width = core();
    wrong_width.push(raw_avp(
        swm::AVP_PDN_GW_ALLOCATION_TYPE,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(VENDOR_ID_3GPP),
        &[1],
    ));
    cases.push(wrong_width);

    let mut bad_enum = core();
    bad_enum.push(vendor_u32(swm::AVP_INTERWORKING_5GS_INDICATOR, false, 2));
    cases.push(bad_enum);

    let mut duplicate = core();
    duplicate.push(vendor_u32(swm::AVP_VPLMN_DYNAMIC_ADDRESS_ALLOWED, true, 0));
    duplicate.push(vendor_u32(swm::AVP_VPLMN_DYNAMIC_ADDRESS_ALLOWED, true, 1));
    cases.push(duplicate);

    let mut third_address = core();
    for address in ["198.51.100.10", "2001:db8:352::", "203.0.113.10"] {
        third_address.push(raw_avp(
            swm::AVP_SERVED_PARTY_IP_ADDRESS,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            &address_value(address.parse().expect("synthetic IP")),
        ));
    }
    cases.push(third_address);

    let mut non_assignable_address = core();
    non_assignable_address.push(raw_avp(
        swm::AVP_SERVED_PARTY_IP_ADDRESS,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(VENDOR_ID_3GPP),
        &address_value(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
    ));
    cases.push(non_assignable_address);

    let mut inapplicable = core();
    inapplicable.push(vendor_u32(AvpCode::new(1618), false, 1));
    cases.push(inapplicable);

    let mut truncated_child = core();
    truncated_child.push(vec![0, 0, 0, 1]);
    cases.push(truncated_child);

    for children in cases {
        let wire = answer_wire(
            base::RESULT_CODE_DIAMETER_SUCCESS,
            &[apn_configuration(&children)],
        );
        assert!(parse(&wire).is_err());
    }

    let children: Vec<u8> = core().into_iter().flatten().collect();
    let protected_outer = raw_avp(
        swm::AVP_APN_CONFIGURATION,
        AvpFlags::VENDOR | AvpFlags::MANDATORY | AvpFlags::PROTECTED,
        Some(VENDOR_ID_3GPP),
        &children,
    );
    assert!(parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[protected_outer]
    ))
    .is_err());
}

#[test]
fn nested_and_top_level_unknowns_share_one_retention_budget() {
    let mut children = vec![
        vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
        vendor_u32(swm::AVP_PDN_TYPE, true, 0),
        raw_avp(
            swm::AVP_SERVICE_SELECTION,
            AvpFlags::MANDATORY,
            None,
            APN.as_bytes(),
        ),
    ];
    children.extend((0..65).map(|index| raw_avp(AvpCode::new(62_000 + index), 0, None, b"x")));
    let extras: Vec<Vec<u8>> = std::iter::once(apn_configuration(&children))
        .chain((0..64).map(|index| raw_avp(AvpCode::new(63_000 + index), 0, None, b"x")))
        .collect();
    assert!(parse(&answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &extras)).is_err());
}

#[test]
fn apn_configuration_collection_is_bounded_during_parse() {
    let extras: Vec<Vec<u8>> = (1..=128)
        .map(|context_identifier| {
            apn_configuration(&[
                vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, context_identifier),
                vendor_u32(swm::AVP_PDN_TYPE, true, 0),
                raw_avp(
                    swm::AVP_SERVICE_SELECTION,
                    AvpFlags::MANDATORY,
                    None,
                    format!("apn-{context_identifier}.synthetic.invalid").as_bytes(),
                ),
            ])
        })
        .collect();
    parse(&answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &extras))
        .expect("exact typed APN collection bound");

    let mut excessive = extras;
    excessive.push(apn_configuration(&[
        vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 129),
        vendor_u32(swm::AVP_PDN_TYPE, true, 0),
        raw_avp(
            swm::AVP_SERVICE_SELECTION,
            AvpFlags::MANDATORY,
            None,
            b"apn-129.synthetic.invalid",
        ),
    ]));
    let error = parse(&answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &excessive))
        .expect_err("the 129th APN must fail before an unbounded typed allocation");
    assert_eq!(error.code(), &DecodeErrorCode::IeCountExceeded);
}

#[test]
fn dictionary_exposes_exact_new_apn_child_types_and_flags() {
    let dictionary = swm::dictionary();
    for (code, data_type) in [
        (swm::AVP_SERVED_PARTY_IP_ADDRESS, AvpDataType::Address),
        (
            swm::AVP_VPLMN_DYNAMIC_ADDRESS_ALLOWED,
            AvpDataType::Enumerated,
        ),
        (swm::AVP_PDN_GW_ALLOCATION_TYPE, AvpDataType::Enumerated),
        (swm::AVP_INTERWORKING_5GS_INDICATOR, AvpDataType::Enumerated),
        (swm::AVP_SPECIFIC_APN_INFO, AvpDataType::Grouped),
    ] {
        let definition = dictionary
            .find_avp(AvpKey::vendor(code, VENDOR_ID_3GPP))
            .expect("typed APN child definition");
        assert_eq!(definition.data_type(), data_type);
        assert_eq!(definition.flags().vendor(), FlagRequirement::MustBeSet);
        assert_eq!(definition.flags().mandatory(), FlagRequirement::MayBeSet);
        assert_eq!(definition.flags().protected(), FlagRequirement::MustBeUnset);
    }
}

#[test]
fn extension_equality_is_reflexive_symmetric_and_transitive() {
    let wire = answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&[
            vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
            vendor_u32(swm::AVP_PDN_TYPE, true, 0),
            raw_avp(
                swm::AVP_SERVICE_SELECTION,
                AvpFlags::MANDATORY,
                None,
                APN.as_bytes(),
            ),
        ])],
    );
    let a = parse(&wire).expect("first representation");
    let b = parse(&wire).expect("second representation");
    let c = parse(&wire).expect("third representation");
    assert_eq!(a, a.clone(), "reflexivity");
    assert_eq!(a, b);
    assert_eq!(b, a, "symmetry");
    assert_eq!(b, c);
    assert_eq!(a, c, "transitivity");
}

#[test]
fn full_core_binding_rejects_every_public_core_mutation() {
    let transaction = swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END);
    let request =
        swm::SwmDiameterEapRequestEnvelope::for_outbound(sample_request(false), transaction);
    let mut core = sample_core(swm::PdnType::Ipv4, APN);
    core.eps_subscribed_qos_profile = Some(swm::EpsSubscribedQosProfile {
        qos_class_identifier: swm::SwmQosClassIdentifier::new(9).expect("QCI"),
        allocation_retention_priority: swm::AllocationRetentionPriority {
            priority_level: swm::SwmPriorityLevel::new(15).expect("priority"),
            pre_emption_capability: Some(swm::SwmPreemptionCapability::Disabled),
            pre_emption_vulnerability: Some(swm::SwmPreemptionVulnerability::Enabled),
        },
    });
    core.ambr = Some(swm::Ambr::new(50_000_000, 150_000_000).expect("AMBR"));
    let authorized = swm::SwmAuthorizedApnConfiguration::builder(core)
        .add_served_party_ip_address(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)))
        .expect("static address")
        .with_mip6_agent_info(sample_gateway())
        .build()
        .expect("complete authorization");
    let mut baseline = sample_answer();
    baseline
        .set_authorized_apn_profile_for(&request, Some(7), vec![authorized])
        .expect("bound profile");

    type CoreMutation = Box<dyn Fn(&mut swm::ApnConfiguration)>;
    let mut mutations: Vec<CoreMutation> = vec![
        Box::new(|core| core.context_identifier = 8),
        Box::new(|core| core.service_selection = "changed.synthetic.invalid".into()),
        Box::new(|core| core.pdn_type = swm::PdnType::Ipv6),
        Box::new(|core| core.eps_subscribed_qos_profile = None),
        Box::new(|core| core.ambr = None),
    ];
    for mutate in mutations.drain(..) {
        let mut answer = baseline.clone();
        mutate(&mut answer.apn_configurations[0]);
        assert!(swm::build_swm_diameter_eap_answer_for(
            &request,
            &answer,
            EncodeContext::default()
        )
        .is_err());
    }
}

#[test]
fn apn_identifier_and_wildcard_request_correlation_are_fail_closed() {
    let maximum_encoded_length = "a".repeat(62);
    let overlong_encoded_length = "a".repeat(63);
    let oversized_invalid_core = swm::ApnConfiguration {
        context_identifier: 7,
        service_selection: "a".repeat(1024 * 1024).into(),
        pdn_type: swm::PdnType::Ipv4,
        eps_subscribed_qos_profile: None,
        ambr: None,
    };
    assert_eq!(
        swm::SwmAuthorizedApnConfiguration::new(oversized_invalid_core)
            .expect_err("oversized public core is rejected before supplement binding")
            .code(),
        swm::SwmApnConfigurationErrorCode::InvalidServiceSelection
    );
    for invalid in [
        "",
        "*",
        "bad..label",
        "bad label",
        "-leading.example",
        "trailing-.example",
        "rac-service",
        "LAC.example",
        "sgsn-edge",
        "RNC.example",
        "internet.gprs",
        "internet.GPRS",
        overlong_encoded_length.as_str(),
    ] {
        assert!(swm::SwmApnNetworkIdentifier::new(invalid).is_err());
    }
    assert!(swm::SwmApnNetworkIdentifier::new(maximum_encoded_length).is_ok());
    assert_eq!(
        swm::SwmApnNetworkIdentifier::new(APN)
            .expect("valid APN")
            .as_str(),
        APN
    );
    assert_eq!(
        swm::SwmApnNetworkIdentifier::new("IMS.SYNTHETIC.INVALID")
            .expect("APN comparison is case-insensitive")
            .as_str(),
        APN
    );
    assert!(swm::SwmRequestedApn::new("*")
        .expect("wildcard")
        .is_wildcard());

    let mut uppercase_request_facts = sample_request(false);
    uppercase_request_facts.service_selection = Some("IMS.SYNTHETIC.INVALID".into());
    let uppercase_request = swm::SwmDiameterEapRequestEnvelope::for_outbound(
        uppercase_request_facts,
        swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END),
    );
    let lowercase_configuration =
        swm::SwmAuthorizedApnConfiguration::new(sample_core(swm::PdnType::Ipv4, APN))
            .expect("authorized APN");
    let mut case_insensitive_answer = sample_answer();
    case_insensitive_answer
        .set_authorized_apn_profile_for(
            &uppercase_request,
            Some(7),
            vec![lowercase_configuration.clone()],
        )
        .expect("named request correlation is case-insensitive");

    let mut uppercase_duplicate = sample_core(swm::PdnType::Ipv6, "IMS.SYNTHETIC.INVALID");
    uppercase_duplicate.context_identifier = 8;
    let uppercase_duplicate = swm::SwmAuthorizedApnConfiguration::new(uppercase_duplicate)
        .expect("uppercase APN is valid");
    assert_eq!(
        case_insensitive_answer
            .set_authorized_apn_profile_for(
                &uppercase_request,
                Some(7),
                vec![lowercase_configuration, uppercase_duplicate],
            )
            .expect_err("case-only duplicate APNs fail closed")
            .code(),
        swm::SwmApnConfigurationErrorCode::DuplicateServiceSelection
    );

    let mut request_facts = sample_request(false);
    request_facts.service_selection = Some("*".into());
    let request = swm::SwmDiameterEapRequestEnvelope::for_outbound(
        request_facts,
        swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END),
    );
    let configuration =
        swm::SwmAuthorizedApnConfiguration::new(sample_core(swm::PdnType::Ipv4, APN))
            .expect("authorized APN");
    let mut answer = sample_answer();
    assert_eq!(
        answer
            .set_authorized_apn_profile_for(&request, None, vec![configuration.clone()])
            .expect_err("wildcard requires a default pointer")
            .code(),
        swm::SwmApnConfigurationErrorCode::DefaultContextIdentifierMissing
    );
    answer
        .set_authorized_apn_profile_for(&request, Some(7), vec![configuration])
        .expect("wildcard resolves through the default pointer");

    for invalid in [
        "bad..label",
        "bad label",
        "rac-service",
        "internet.gprs",
        overlong_encoded_length.as_str(),
    ] {
        let mut invalid_request = sample_request(false);
        invalid_request.service_selection = Some(invalid.to_owned().into());
        assert!(swm::build_swm_diameter_eap_request(
            &invalid_request,
            HOP_BY_HOP,
            END_TO_END,
            EncodeContext::default(),
        )
        .is_err());
        let wire = answer_wire(
            base::RESULT_CODE_DIAMETER_SUCCESS,
            &[apn_configuration(&[
                vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
                vendor_u32(swm::AVP_PDN_TYPE, true, 0),
                raw_avp(
                    swm::AVP_SERVICE_SELECTION,
                    AvpFlags::MANDATORY,
                    None,
                    invalid.as_bytes(),
                ),
            ])],
        );
        assert!(parse(&wire).is_err());
    }

    let wildcard_wire = answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&[
            vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
            vendor_u32(swm::AVP_PDN_TYPE, true, 0),
            raw_avp(swm::AVP_SERVICE_SELECTION, AvpFlags::MANDATORY, None, b"*"),
            specific_apn_info(
                APN,
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                Some(b"mnc001.mcc001.3gppnetwork.org"),
                true,
                &[],
            ),
        ])],
    );
    let mut wildcard_answer = parse(&wildcard_wire).expect("raw wildcard profile is valid");
    assert_eq!(
        wildcard_answer.apn_configurations[0]
            .service_selection
            .as_ref(),
        "*"
    );
    let correlated = correlate_wire(&wildcard_wire, typed_context(), Some(APN));
    let view = correlated
        .apn_configuration_views()
        .expect("strict correlation exposes typed wildcard facts")
        .next()
        .expect("one wildcard configuration");
    let specific = view.specific_apn_infos();
    assert_eq!(specific.len(), 1);
    assert_eq!(specific[0].service_selection().as_str(), APN);
    assert_eq!(
        specific[0]
            .visited_network_identifier()
            .map(swm::SwmVisitedNetworkIdentifier::as_str),
        Some("mnc001.mcc001.3gppnetwork.org")
    );
    assert!(specific[0].mip6_agent_info().selection().is_some());
    let wildcard_error = match correlated.authorized_apn_configurations() {
        Ok(_) => panic!("wildcard parent must not become broad authorization"),
        Err(error) => error,
    };
    assert_eq!(
        wildcard_error.code(),
        swm::SwmApnConfigurationErrorCode::WildcardAuthorizationUnsupported
    );
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_answer(
                &wildcard_answer,
                HOP_BY_HOP,
                END_TO_END,
                EncodeContext::default(),
            )
            .expect("raw wildcard profile rebuilds")
        ),
        wildcard_wire
    );
    wildcard_answer.default_context_identifier = Some(7);
    wildcard_answer.mip6_feature_vector = Some(swm::SwmMip6FeatureVector::gtpv2_only());
    let named_request = swm::SwmDiameterEapRequestEnvelope::for_outbound(
        sample_request(false),
        swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END),
    );
    swm::build_swm_diameter_eap_answer_for(
        &named_request,
        &wildcard_answer,
        EncodeContext::default(),
    )
    .expect("named request matches an exact typed nested APN");
    let mut nonmatching_request_facts = sample_request(false);
    nonmatching_request_facts.service_selection = Some("other.synthetic.invalid".into());
    let nonmatching_request = swm::SwmDiameterEapRequestEnvelope::for_outbound(
        nonmatching_request_facts,
        swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END),
    );
    assert!(swm::build_swm_diameter_eap_answer_for(
        &nonmatching_request,
        &wildcard_answer,
        EncodeContext::default()
    )
    .is_err());
    swm::build_swm_diameter_eap_answer_for(&request, &wildcard_answer, EncodeContext::default())
        .expect("wildcard request resolves only through its default pointer");
}

#[test]
fn der_service_selection_validates_wire_bytes_before_owned_policy_state() {
    let maximum = "a".repeat(62);
    let parsed = swm::parse_swm_diameter_eap_request(
        &decode(&request_wire(maximum.as_bytes())),
        typed_context(),
    )
    .expect("62-octet encoded APN boundary is valid");
    match parsed.requested_apn().expect("typed requested APN") {
        Some(swm::SwmRequestedApn::NetworkIdentifier(identifier)) => {
            assert_eq!(identifier.as_str(), maximum)
        }
        _ => panic!("expected a named requested APN"),
    }

    for invalid in [
        "a".repeat(63).into_bytes(),
        b"bad..label".to_vec(),
        vec![0xff; 32],
    ] {
        assert!(swm::parse_swm_diameter_eap_request(
            &decode(&request_wire(&invalid)),
            typed_context(),
        )
        .is_err());
    }
}

#[test]
fn foreign_vendor_collisions_and_inapplicable_children_follow_exact_identity_policy() {
    let core = || {
        vec![
            vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
            vendor_u32(swm::AVP_PDN_TYPE, true, 0),
            raw_avp(
                swm::AVP_SERVICE_SELECTION,
                AvpFlags::MANDATORY,
                None,
                APN.as_bytes(),
            ),
        ]
    };
    let foreign = raw_avp(
        swm::AVP_CONTEXT_IDENTIFIER,
        AvpFlags::VENDOR,
        Some(VendorId::new(65_352)),
        b"foreign",
    );
    let mut children = core();
    children.push(foreign);
    let wire = answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&children)],
    );
    parse(&wire).expect("foreign optional identity is preserved");
    let preserved = correlate_wire(&wire, typed_context(), Some(APN));
    assert_eq!(
        preserved
            .apn_configuration_views()
            .expect("checked view")
            .next()
            .expect("APN")
            .extension_metadata()
            .count(),
        1
    );
    let drop_context = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Drop,
        ..typed_context()
    };
    let dropped = correlate_wire(&wire, drop_context, Some(APN));
    assert_eq!(
        dropped
            .apn_configuration_views()
            .expect("checked view")
            .next()
            .expect("APN")
            .extension_metadata()
            .count(),
        0
    );
    assert!(swm::parse_swm_diameter_eap_answer(
        &decode(&wire),
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..typed_context()
        },
    )
    .is_err());

    let collision_codes = [
        swm::AVP_SERVICE_SELECTION,
        swm::AVP_SPECIFIC_APN_INFO,
        swm::AVP_SERVICE_SELECTION,
        swm::AVP_MIP6_AGENT_INFO,
        swm::AVP_VISITED_NETWORK_IDENTIFIER,
    ];
    let foreign_vendor = VendorId::new(65_352);
    let collision_wire = |mandatory_collision: Option<usize>| {
        let collision = |index: usize| {
            let mut flags = AvpFlags::VENDOR;
            if mandatory_collision == Some(index) {
                flags |= AvpFlags::MANDATORY;
            }
            raw_avp(
                collision_codes[index],
                flags,
                Some(foreign_vendor),
                b"foreign-numeric-collision",
            )
        };
        let nested_extensions = [collision(2), collision(3), collision(4)];
        answer_wire(
            base::RESULT_CODE_DIAMETER_SUCCESS,
            &[apn_configuration(&[
                vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
                vendor_u32(swm::AVP_PDN_TYPE, true, 0),
                raw_avp(swm::AVP_SERVICE_SELECTION, AvpFlags::MANDATORY, None, b"*"),
                specific_apn_info(
                    APN,
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                    None,
                    true,
                    &nested_extensions,
                ),
                collision(0),
                collision(1),
            ])],
        )
    };

    let collision_wire_optional = collision_wire(None);
    let preserved = correlate_wire(&collision_wire_optional, typed_context(), Some(APN));
    let preserved_view = preserved
        .apn_configuration_views()
        .expect("foreign collisions remain correlated wire facts")
        .next()
        .expect("wildcard APN");
    let parent_metadata: Vec<_> = preserved_view.extension_metadata().collect();
    assert_eq!(
        parent_metadata
            .iter()
            .map(|metadata| (metadata.code(), metadata.vendor_id()))
            .collect::<Vec<_>>(),
        [
            (swm::AVP_SERVICE_SELECTION, Some(foreign_vendor)),
            (swm::AVP_SPECIFIC_APN_INFO, Some(foreign_vendor)),
        ]
    );
    let nested_metadata: Vec<_> = preserved_view.specific_apn_infos()[0]
        .extension_metadata()
        .collect();
    assert_eq!(
        nested_metadata
            .iter()
            .map(|metadata| (metadata.code(), metadata.vendor_id()))
            .collect::<Vec<_>>(),
        [
            (swm::AVP_SERVICE_SELECTION, Some(foreign_vendor)),
            (swm::AVP_MIP6_AGENT_INFO, Some(foreign_vendor)),
            (swm::AVP_VISITED_NETWORK_IDENTIFIER, Some(foreign_vendor),),
        ]
    );

    let dropped = correlate_wire(
        &collision_wire_optional,
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..typed_context()
        },
        Some(APN),
    );
    let dropped_view = dropped
        .apn_configuration_views()
        .expect("drop policy preserves typed APN facts")
        .next()
        .expect("wildcard APN");
    assert_eq!(dropped_view.extension_metadata().count(), 0);
    assert_eq!(
        dropped_view.specific_apn_infos()[0]
            .extension_metadata()
            .count(),
        0
    );

    let rejected = swm::parse_swm_diameter_eap_answer(
        &decode(&collision_wire_optional),
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..typed_context()
        },
    )
    .expect_err("reject policy fails every foreign numeric collision closed");
    assert_eq!(rejected.code(), &DecodeErrorCode::UnknownCriticalIe);

    for mandatory_collision in 0..collision_codes.len() {
        let wire = collision_wire(Some(mandatory_collision));
        let error = parse(&wire).expect_err("foreign M-set numeric collision must fail closed");
        assert_eq!(error.code(), &DecodeErrorCode::UnknownCriticalIe);
    }

    let mut mandatory_collision = core();
    mandatory_collision.push(raw_avp(
        swm::AVP_CONTEXT_IDENTIFIER,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(VendorId::new(65_352)),
        b"foreign",
    ));
    assert!(parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&mandatory_collision)]
    ))
    .is_err());

    for allowed in [1613, 1690, 1697, 1707] {
        let mut values = core();
        values.push(vendor_u32(AvpCode::new(allowed), false, 1));
        assert!(parse(&answer_wire(
            base::RESULT_CODE_DIAMETER_SUCCESS,
            &[apn_configuration(&values)]
        ))
        .is_ok());
    }
    for prohibited in [1618, 1663, 1665, 1667, 1681, 1682, 1684, 1686, 3125] {
        let mut values = core();
        values.push(vendor_u32(AvpCode::new(prohibited), false, 1));
        assert!(parse(&answer_wire(
            base::RESULT_CODE_DIAMETER_SUCCESS,
            &[apn_configuration(&values)]
        ))
        .is_err());
    }
}

#[test]
fn specific_apn_info_is_typed_ordered_repeatable_and_originates_canonically() {
    let private_extension = raw_avp(
        AvpCode::new(65_352),
        AvpFlags::PROTECTED,
        None,
        b"private-specific-extension",
    );
    let first = specific_apn_info(
        APN,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        Some(b"mnc001.mcc001.3gppnetwork.org"),
        true,
        std::slice::from_ref(&private_extension),
    );
    let second = specific_apn_info(
        APN,
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
        None,
        true,
        &[],
    );
    let wire = answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&[
            vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
            vendor_u32(swm::AVP_PDN_TYPE, true, 0),
            raw_avp(swm::AVP_SERVICE_SELECTION, AvpFlags::MANDATORY, None, b"*"),
            first,
            second,
        ])],
    );

    let (tail, dictionary_message) =
        Message::decode_with_dictionary(&wire, typed_context(), SWM_PROJECTED_PROFILE_DICTIONARIES)
            .expect("dictionary recognizes typed repeatable Specific-APN-Info");
    assert!(tail.is_empty());
    let parsed = swm::parse_swm_diameter_eap_answer(&dictionary_message, typed_context())
        .expect("typed repeated Specific-APN-Info");
    let correlated = correlate_wire(&wire, typed_context(), Some(APN));
    let view = correlated
        .apn_configuration_views()
        .expect("strict structural view")
        .next()
        .expect("wildcard APN");
    let specific = view.specific_apn_infos();
    assert_eq!(specific.len(), 2);
    assert_eq!(specific[0].service_selection().as_str(), APN);
    assert_eq!(specific[1].service_selection().as_str(), APN);
    assert_eq!(
        specific[0].mip6_agent_info().home_agent_addresses(),
        [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]
    );
    assert_eq!(specific[0].extension_metadata().count(), 1);
    assert_eq!(specific[1].extension_metadata().count(), 0);
    let debug = format!("{correlated:?} {view:?} {:?}", specific[0]);
    for private in [
        APN,
        "192.0.2.10",
        "mnc001.mcc001",
        "private-specific-extension",
    ] {
        assert!(!debug.contains(private));
    }
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_answer(
                &parsed,
                HOP_BY_HOP,
                END_TO_END,
                EncodeContext::default(),
            )
            .expect("canonical typed values rebuild")
        ),
        wire
    );

    let visited = swm::SwmVisitedNetworkIdentifier::new(VISITED_MCC, VISITED_MNC)
        .expect("canonical visited network");
    let typed = swm::SwmSpecificApnInfo::new(
        swm::SwmApnNetworkIdentifier::new(APN).expect("named APN"),
        sample_gateway(),
        Some(visited),
    );
    let wildcard =
        swm::SwmAuthorizedApnConfiguration::builder(sample_core(swm::PdnType::Ipv4, "*"))
            .add_specific_apn_info(typed.clone())
            .expect("Specific-APN-Info belongs to wildcard parent")
            .add_specific_apn_info(typed)
            .expect("the same named APN may retain another ordered gateway pair")
            .build()
            .expect("wire-valid wildcard profile");
    assert!(wildcard.network_identifier().is_err());
    assert_eq!(
        swm::SwmAuthorizedApnConfiguration::builder(sample_core(swm::PdnType::Ipv4, APN))
            .add_specific_apn_info(swm::SwmSpecificApnInfo::new(
                swm::SwmApnNetworkIdentifier::new(APN).expect("named APN"),
                sample_gateway(),
                None,
            ))
            .expect_err("a concrete parent cannot contain Specific-APN-Info")
            .code(),
        swm::SwmApnConfigurationErrorCode::SpecificApnInfoRequiresWildcard
    );

    let request = swm::SwmDiameterEapRequestEnvelope::for_outbound(
        sample_request(false),
        swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END),
    );
    let mut answer = sample_answer();
    answer
        .set_authorized_apn_profile_for(&request, Some(7), vec![wildcard])
        .expect("typed nested APN satisfies the named DER without selecting a gateway");
    let originated_wire = encode(
        &swm::build_swm_diameter_eap_answer_for(&request, &answer, EncodeContext::default())
            .expect("typed wildcard profile originates"),
    );
    let originated_correlated = correlate_wire(&originated_wire, typed_context(), Some(APN));
    assert_eq!(
        originated_correlated
            .apn_configuration_views()
            .expect("originated supplement requires strict response correlation")
            .next()
            .expect("wildcard APN")
            .specific_apn_infos()
            .len(),
        2
    );
    let outer = raw_avps(decode(&originated_wire).raw_avps)
        .into_iter()
        .find(|avp| avp.header.code == swm::AVP_APN_CONFIGURATION)
        .expect("APN-Configuration");
    let specific_groups: Vec<_> = raw_avps(outer.value)
        .into_iter()
        .filter(|avp| avp.header.code == swm::AVP_SPECIFIC_APN_INFO)
        .collect();
    assert_eq!(specific_groups.len(), 2);
    assert!(specific_groups.iter().all(|group| {
        group.header.vendor_id == Some(VENDOR_ID_3GPP)
            && group.header.flags.is_mandatory()
            && !group.header.flags.is_protected()
    }));
    let children = raw_avps(specific_groups[0].value);
    assert_eq!(
        children
            .iter()
            .map(|child| child.header.code)
            .collect::<Vec<_>>(),
        [
            swm::AVP_SERVICE_SELECTION,
            swm::AVP_MIP6_AGENT_INFO,
            swm::AVP_VISITED_NETWORK_IDENTIFIER,
        ]
    );
    assert!(children
        .iter()
        .all(|child| child.header.flags.is_mandatory()));
}

#[test]
fn specific_apn_info_cardinality_identity_lengths_depth_and_bounds_fail_closed() {
    let gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let service = raw_avp(
        swm::AVP_SERVICE_SELECTION,
        AvpFlags::MANDATORY,
        None,
        APN.as_bytes(),
    );
    let agent = agent_info(gateway);
    let visited = raw_avp(
        swm::AVP_VISITED_NETWORK_IDENTIFIER,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(VENDOR_ID_3GPP),
        b"mnc001.mcc001.3gppnetwork.org",
    );
    let wildcard_wire = |specific: Vec<u8>| {
        answer_wire(
            base::RESULT_CODE_DIAMETER_SUCCESS,
            &[apn_configuration(&[
                vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
                vendor_u32(swm::AVP_PDN_TYPE, true, 0),
                raw_avp(swm::AVP_SERVICE_SELECTION, AvpFlags::MANDATORY, None, b"*"),
                specific,
            ])],
        )
    };

    let invalid_groups = vec![
        specific_apn_info_group(true, std::slice::from_ref(&agent)),
        specific_apn_info_group(true, std::slice::from_ref(&service)),
        specific_apn_info_group(true, &[service.clone(), service.clone(), agent.clone()]),
        specific_apn_info_group(true, &[service.clone(), agent.clone(), agent.clone()]),
        specific_apn_info_group(
            true,
            &[
                service.clone(),
                agent.clone(),
                visited.clone(),
                visited.clone(),
            ],
        ),
        specific_apn_info_group(
            true,
            &[
                raw_avp(swm::AVP_SERVICE_SELECTION, AvpFlags::MANDATORY, None, b"*"),
                agent.clone(),
            ],
        ),
        specific_apn_info_group(
            true,
            &[
                raw_avp(
                    swm::AVP_SERVICE_SELECTION,
                    AvpFlags::MANDATORY,
                    None,
                    "a".repeat(63).as_bytes(),
                ),
                agent.clone(),
            ],
        ),
        specific_apn_info_group(
            true,
            &[
                service.clone(),
                raw_avp(swm::AVP_MIP6_AGENT_INFO, AvpFlags::MANDATORY, None, &[]),
            ],
        ),
        specific_apn_info_group(
            true,
            &[
                service.clone(),
                agent.clone(),
                raw_avp(
                    swm::AVP_VISITED_NETWORK_IDENTIFIER,
                    AvpFlags::VENDOR | AvpFlags::MANDATORY,
                    Some(VENDOR_ID_3GPP),
                    b"not-a-plmn-domain",
                ),
            ],
        ),
        specific_apn_info_group(
            true,
            &[
                raw_avp(
                    swm::AVP_SERVICE_SELECTION,
                    AvpFlags::VENDOR | AvpFlags::MANDATORY,
                    Some(VENDOR_ID_3GPP),
                    APN.as_bytes(),
                ),
                agent.clone(),
            ],
        ),
        specific_apn_info_group(
            true,
            &[
                service.clone(),
                agent.clone(),
                raw_avp(
                    AvpCode::new(65_353),
                    AvpFlags::MANDATORY,
                    None,
                    b"must-understand",
                ),
            ],
        ),
        raw_avp(
            swm::AVP_SPECIFIC_APN_INFO,
            AvpFlags::VENDOR | AvpFlags::MANDATORY | AvpFlags::PROTECTED,
            Some(VENDOR_ID_3GPP),
            &[service.clone(), agent.clone()].concat(),
        ),
        raw_avp(
            swm::AVP_SPECIFIC_APN_INFO,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VendorId::new(65_352)),
            &[service.clone(), agent.clone()].concat(),
        ),
        raw_avp(
            swm::AVP_SPECIFIC_APN_INFO,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            &[0; 36],
        ),
    ];
    for invalid in invalid_groups {
        assert!(parse(&wildcard_wire(invalid)).is_err());
    }

    let concrete_parent = answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&[
            vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
            vendor_u32(swm::AVP_PDN_TYPE, true, 0),
            service.clone(),
            specific_apn_info(APN, gateway, None, true, &[]),
        ])],
    );
    assert!(parse(&concrete_parent).is_err());

    let mut too_many_groups = vec![
        vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
        vendor_u32(swm::AVP_PDN_TYPE, true, 0),
        raw_avp(swm::AVP_SERVICE_SELECTION, AvpFlags::MANDATORY, None, b"*"),
    ];
    for index in 0..129 {
        let named = format!("apn{index}.synthetic.invalid");
        too_many_groups.push(specific_apn_info(&named, gateway, None, true, &[]));
    }
    assert!(parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&too_many_groups)]
    ))
    .is_err());

    let valid = wildcard_wire(specific_apn_info(APN, gateway, None, true, &[]));
    assert!(swm::parse_swm_diameter_eap_answer(
        &decode(&valid),
        DecodeContext {
            max_depth: 2,
            ..typed_context()
        }
    )
    .is_err());
}

#[test]
fn specific_apn_info_extension_policy_budget_and_m_variance_are_strict() {
    let optional = raw_avp(
        AvpCode::new(65_354),
        AvpFlags::PROTECTED,
        None,
        b"specific-optional",
    );
    let gateway = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let wire = answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&[
            vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
            vendor_u32(swm::AVP_PDN_TYPE, true, 0),
            raw_avp(swm::AVP_SERVICE_SELECTION, AvpFlags::MANDATORY, None, b"*"),
            specific_apn_info(APN, gateway, None, true, std::slice::from_ref(&optional)),
        ])],
    );
    let preserved = correlate_wire(&wire, typed_context(), Some(APN));
    assert_eq!(
        preserved
            .apn_configuration_views()
            .expect("preserved strict view")
            .next()
            .expect("APN")
            .specific_apn_infos()[0]
            .extension_metadata()
            .count(),
        1
    );
    let dropped = correlate_wire(
        &wire,
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..typed_context()
        },
        Some(APN),
    );
    assert_eq!(
        dropped
            .apn_configuration_views()
            .expect("dropped strict view")
            .next()
            .expect("APN")
            .specific_apn_infos()[0]
            .extension_metadata()
            .count(),
        0
    );
    assert!(swm::parse_swm_diameter_eap_answer(
        &decode(&wire),
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..typed_context()
        }
    )
    .is_err());

    let mut retained_extensions = Vec::new();
    for index in 0..126_u32 {
        retained_extensions.push(raw_avp(
            AvpCode::new(66_000 + index),
            0,
            None,
            &[u8::try_from(index).expect("bounded index")],
        ));
    }
    let mut parent_children = vec![
        vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
        vendor_u32(swm::AVP_PDN_TYPE, true, 0),
        raw_avp(swm::AVP_SERVICE_SELECTION, AvpFlags::MANDATORY, None, b"*"),
        specific_apn_info(APN, gateway, None, true, &retained_extensions),
    ];
    for index in 0..3_u32 {
        parent_children.push(raw_avp(
            AvpCode::new(67_000 + index),
            0,
            None,
            b"parent-extension",
        ));
    }
    assert!(parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&parent_children)]
    ))
    .is_err());

    let m_clear_group = specific_apn_info_group(
        false,
        &[
            raw_avp(swm::AVP_SERVICE_SELECTION, 0, None, APN.as_bytes()),
            agent_info_with_m_bit(gateway, false),
            raw_avp(
                swm::AVP_VISITED_NETWORK_IDENTIFIER,
                AvpFlags::VENDOR,
                Some(VENDOR_ID_3GPP),
                b"mnc001.mcc001.3gppnetwork.org",
            ),
        ],
    );
    let m_clear_wire = answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&[
            vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
            vendor_u32(swm::AVP_PDN_TYPE, true, 0),
            raw_avp(swm::AVP_SERVICE_SELECTION, AvpFlags::MANDATORY, None, b"*"),
            m_clear_group,
        ])],
    );
    let parsed = parse(&m_clear_wire).expect("understood Specific-APN-Info ignores M variance");
    let rebuilt = encode(
        &swm::build_swm_diameter_eap_answer(
            &parsed,
            HOP_BY_HOP,
            END_TO_END,
            EncodeContext::default(),
        )
        .expect("M-variant input rebuilds canonically"),
    );
    let outer = raw_avps(decode(&rebuilt).raw_avps)
        .into_iter()
        .find(|avp| avp.header.code == swm::AVP_APN_CONFIGURATION)
        .expect("APN-Configuration");
    let specific = raw_avps(outer.value)
        .into_iter()
        .find(|avp| avp.header.code == swm::AVP_SPECIFIC_APN_INFO)
        .expect("Specific-APN-Info");
    assert!(specific.header.flags.is_mandatory());
    assert!(raw_avps(specific.value)
        .iter()
        .all(|child| child.header.flags.is_mandatory()));
}

#[test]
fn known_apn_children_accept_m_variance_and_canonicalize() {
    let base_children = || {
        let agent_address = raw_avp(
            swm::AVP_MIP_HOME_AGENT_ADDRESS,
            AvpFlags::MANDATORY,
            None,
            &address_value(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        );
        vec![
            vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, false, 7),
            raw_avp(
                swm::AVP_SERVED_PARTY_IP_ADDRESS,
                AvpFlags::VENDOR,
                Some(VENDOR_ID_3GPP),
                &address_value(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10))),
            ),
            vendor_u32(swm::AVP_PDN_TYPE, false, 0),
            raw_avp(swm::AVP_SERVICE_SELECTION, 0, None, APN.as_bytes()),
            vendor_u32(swm::AVP_VPLMN_DYNAMIC_ADDRESS_ALLOWED, false, 0),
            raw_avp(swm::AVP_MIP6_AGENT_INFO, 0, None, &agent_address),
            raw_avp(
                swm::AVP_VISITED_NETWORK_IDENTIFIER,
                AvpFlags::VENDOR,
                Some(VENDOR_ID_3GPP),
                b"mnc001.mcc001.3gppnetwork.org",
            ),
            vendor_u32(swm::AVP_PDN_GW_ALLOCATION_TYPE, false, 1),
            vendor_u32(swm::AVP_INTERWORKING_5GS_INDICATOR, true, 1),
            raw_avp(
                swm::AVP_3GPP_CHARGING_CHARACTERISTICS,
                AvpFlags::VENDOR | AvpFlags::MANDATORY,
                Some(VENDOR_ID_3GPP),
                b"A53C",
            ),
            raw_avp(
                swm::AVP_APN_OI_REPLACEMENT,
                AvpFlags::VENDOR,
                Some(VENDOR_ID_3GPP),
                APN_OI.as_bytes(),
            ),
        ]
    };
    let inbound = answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&base_children())],
    );
    let (tail, dictionary_message) = Message::decode_with_dictionary(
        &inbound,
        typed_context(),
        SWM_PROJECTED_PROFILE_DICTIONARIES,
    )
    .expect("dictionary tolerates known child M variance");
    assert!(tail.is_empty());
    let parsed = swm::parse_swm_diameter_eap_answer(&dictionary_message, typed_context())
        .expect("known children tolerate received M variance");
    let rebuilt = swm::build_swm_diameter_eap_answer(
        &parsed,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .expect("canonical rebuild");
    let encoded = encode(&rebuilt);
    let message = decode(&encoded);
    let outer = raw_avps(message.raw_avps)
        .into_iter()
        .find(|avp| avp.header.code == swm::AVP_APN_CONFIGURATION)
        .expect("APN");
    let children = raw_avps(outer.value);
    for mandatory_code in [
        swm::AVP_CONTEXT_IDENTIFIER,
        swm::AVP_SERVED_PARTY_IP_ADDRESS,
        swm::AVP_PDN_TYPE,
        swm::AVP_SERVICE_SELECTION,
        swm::AVP_VPLMN_DYNAMIC_ADDRESS_ALLOWED,
        swm::AVP_VISITED_NETWORK_IDENTIFIER,
        swm::AVP_PDN_GW_ALLOCATION_TYPE,
        swm::AVP_APN_OI_REPLACEMENT,
    ] {
        assert!(children
            .iter()
            .find(|child| child.header.code == mandatory_code)
            .expect("canonical child")
            .header
            .flags
            .is_mandatory());
    }
    assert!(children
        .iter()
        .find(|child| child.header.code == swm::AVP_MIP6_AGENT_INFO)
        .expect("canonical MIP6-Agent-Info child")
        .header
        .flags
        .is_mandatory());
    assert!(!children
        .iter()
        .find(|child| child.header.code == swm::AVP_INTERWORKING_5GS_INDICATOR)
        .expect("interworking child")
        .header
        .flags
        .is_mandatory());
    assert!(!children
        .iter()
        .find(|child| child.header.code == swm::AVP_3GPP_CHARGING_CHARACTERISTICS)
        .expect("charging child")
        .header
        .flags
        .is_mandatory());
}

#[test]
fn qos_and_extended_ambr_are_typed_validated_and_round_trip() {
    let children = vec![
        vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
        vendor_u32(swm::AVP_PDN_TYPE, true, 0),
        raw_avp(
            swm::AVP_SERVICE_SELECTION,
            AvpFlags::MANDATORY,
            None,
            APN.as_bytes(),
        ),
        qos_profile(9, 15),
        ambr(50_000_000, u32::MAX, None, Some(5_000_000)),
    ];
    let wire = answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&children)],
    );
    let parsed = parse(&wire).expect("typed QoS and extended AMBR");
    let correlated = correlate_wire(&wire, typed_context(), Some(APN));
    let core = correlated
        .apn_configuration_views()
        .expect("strict correlated view")
        .next()
        .expect("APN")
        .core();
    let qos = core.eps_subscribed_qos_profile.expect("QoS");
    assert_eq!(qos.qos_class_identifier.value(), 9);
    assert_eq!(qos.allocation_retention_priority.priority_level.value(), 15);
    let typed_ambr = core.ambr.expect("AMBR");
    assert_eq!(
        typed_ambr.max_requested_bandwidth_ul.bits_per_second(),
        50_000_000
    );
    assert_eq!(
        typed_ambr.max_requested_bandwidth_dl.bits_per_second(),
        5_000_000_000
    );
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_answer(
                &parsed,
                HOP_BY_HOP,
                END_TO_END,
                EncodeContext::default(),
            )
            .expect("rebuild")
        ),
        wire
    );

    for assigned in [1, 9, 65, 67, 69, 71, 76, 79, 80, 82, 85, 128, 254] {
        assert!(swm::SwmQosClassIdentifier::new(assigned).is_ok());
    }
    for reserved in [0, 10, 64, 68, 77, 78, 81, 86, 127, 255] {
        assert!(swm::SwmQosClassIdentifier::new(reserved).is_err());
    }
    assert!(swm::SwmPriorityLevel::new(0).is_err());
    assert!(swm::SwmPriorityLevel::new(16).is_err());
    assert!(swm::SwmBandwidth::new(0).is_err());
    assert!(swm::SwmBandwidth::new(u32::MAX as u64 + 1).is_err());

    let m_clear_qos = grouped_3gpp(
        swm::AVP_EPS_SUBSCRIBED_QOS_PROFILE,
        false,
        &[
            vendor_u32(swm::AVP_QOS_CLASS_IDENTIFIER, false, 9),
            grouped_3gpp(
                swm::AVP_ALLOCATION_RETENTION_PRIORITY,
                false,
                &[
                    vendor_u32(swm::AVP_PRIORITY_LEVEL, false, 15),
                    vendor_u32(swm::AVP_PRE_EMPTION_CAPABILITY, false, 1),
                    vendor_u32(swm::AVP_PRE_EMPTION_VULNERABILITY, false, 0),
                ],
            ),
        ],
    );
    let m_clear_ambr = grouped_3gpp(
        swm::AVP_AMBR,
        false,
        &[
            vendor_u32(swm::AVP_MAX_REQUESTED_BANDWIDTH_UL, false, u32::MAX),
            vendor_u32(swm::AVP_MAX_REQUESTED_BANDWIDTH_DL, false, 1),
            vendor_u32(
                swm::AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_UL,
                false,
                5_000_000,
            ),
        ],
    );
    let mut m_clear_children = vec![
        vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
        vendor_u32(swm::AVP_PDN_TYPE, true, 0),
        raw_avp(
            swm::AVP_SERVICE_SELECTION,
            AvpFlags::MANDATORY,
            None,
            APN.as_bytes(),
        ),
    ];
    m_clear_children.extend([m_clear_qos, m_clear_ambr]);
    let m_clear = parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&m_clear_children)],
    ))
    .expect("nested known QoS and AMBR children tolerate M variance");
    let canonical = encode(
        &swm::build_swm_diameter_eap_answer(
            &m_clear,
            HOP_BY_HOP,
            END_TO_END,
            EncodeContext::default(),
        )
        .expect("canonical QoS rebuild"),
    );
    let canonical_message = decode(&canonical);
    let canonical_apn = raw_avps(canonical_message.raw_avps)
        .into_iter()
        .find(|avp| avp.header.code == swm::AVP_APN_CONFIGURATION)
        .expect("canonical APN");
    let canonical_children = raw_avps(canonical_apn.value);
    let canonical_qos = canonical_children
        .iter()
        .find(|avp| avp.header.code == swm::AVP_EPS_SUBSCRIBED_QOS_PROFILE)
        .expect("canonical QoS group");
    assert!(canonical_qos.header.flags.is_mandatory());
    let canonical_qos_children = raw_avps(canonical_qos.value);
    assert!(canonical_qos_children
        .iter()
        .all(|avp| avp.header.flags.is_mandatory()));
    let canonical_arp = canonical_qos_children
        .iter()
        .find(|avp| avp.header.code == swm::AVP_ALLOCATION_RETENTION_PRIORITY)
        .expect("canonical ARP group");
    assert!(raw_avps(canonical_arp.value)
        .iter()
        .all(|avp| avp.header.flags.is_mandatory()));
    let canonical_ambr = canonical_children
        .iter()
        .find(|avp| avp.header.code == swm::AVP_AMBR)
        .expect("canonical AMBR group");
    assert!(canonical_ambr.header.flags.is_mandatory());
    assert!(raw_avps(canonical_ambr.value)
        .iter()
        .all(|avp| avp.header.flags.is_mandatory()));

    let core = || {
        vec![
            vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
            vendor_u32(swm::AVP_PDN_TYPE, true, 0),
            raw_avp(
                swm::AVP_SERVICE_SELECTION,
                AvpFlags::MANDATORY,
                None,
                APN.as_bytes(),
            ),
        ]
    };
    let invalid_qos = [
        qos_profile(0, 15),
        qos_profile(10, 15),
        qos_profile(9, 0),
        qos_profile(9, 16),
        grouped_3gpp(
            swm::AVP_EPS_SUBSCRIBED_QOS_PROFILE,
            true,
            &[vendor_u32(swm::AVP_QOS_CLASS_IDENTIFIER, true, 9)],
        ),
        grouped_3gpp(
            swm::AVP_EPS_SUBSCRIBED_QOS_PROFILE,
            true,
            &[
                vendor_u32(swm::AVP_QOS_CLASS_IDENTIFIER, true, 9),
                vendor_u32(swm::AVP_QOS_CLASS_IDENTIFIER, true, 9),
                grouped_3gpp(
                    swm::AVP_ALLOCATION_RETENTION_PRIORITY,
                    true,
                    &arp_children(15),
                ),
            ],
        ),
        grouped_3gpp(
            swm::AVP_EPS_SUBSCRIBED_QOS_PROFILE,
            true,
            &[
                raw_avp(
                    swm::AVP_QOS_CLASS_IDENTIFIER,
                    AvpFlags::VENDOR | AvpFlags::MANDATORY | AvpFlags::PROTECTED,
                    Some(VENDOR_ID_3GPP),
                    &9_u32.to_be_bytes(),
                ),
                grouped_3gpp(
                    swm::AVP_ALLOCATION_RETENTION_PRIORITY,
                    true,
                    &arp_children(15),
                ),
            ],
        ),
        grouped_3gpp(
            swm::AVP_EPS_SUBSCRIBED_QOS_PROFILE,
            true,
            &[
                vendor_u32(swm::AVP_QOS_CLASS_IDENTIFIER, true, 9),
                grouped_3gpp(
                    swm::AVP_ALLOCATION_RETENTION_PRIORITY,
                    true,
                    &[
                        vendor_u32(swm::AVP_PRIORITY_LEVEL, true, 15),
                        vendor_u32(swm::AVP_PRE_EMPTION_CAPABILITY, true, 2),
                    ],
                ),
            ],
        ),
    ];
    for qos in invalid_qos {
        let mut children = core();
        children.push(qos);
        assert!(parse(&answer_wire(
            base::RESULT_CODE_DIAMETER_SUCCESS,
            &[apn_configuration(&children)]
        ))
        .is_err());
    }
    for invalid_ambr in [
        ambr(0, 1, None, None),
        ambr(1, 1, Some(4_294_968), None),
        ambr(u32::MAX, 1, Some(4_294_967), None),
        grouped_3gpp(
            swm::AVP_AMBR,
            true,
            &[
                vendor_u32(swm::AVP_MAX_REQUESTED_BANDWIDTH_UL, true, u32::MAX),
                vendor_u32(swm::AVP_MAX_REQUESTED_BANDWIDTH_DL, true, 1),
                vendor_u32(
                    swm::AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_UL,
                    true,
                    5_000_000,
                ),
                vendor_u32(
                    swm::AVP_EXTENDED_MAX_REQUESTED_BANDWIDTH_UL,
                    true,
                    5_000_001,
                ),
            ],
        ),
        grouped_3gpp(
            swm::AVP_AMBR,
            true,
            &[
                raw_avp(
                    swm::AVP_MAX_REQUESTED_BANDWIDTH_UL,
                    AvpFlags::VENDOR | AvpFlags::MANDATORY | AvpFlags::PROTECTED,
                    Some(VENDOR_ID_3GPP),
                    &1_u32.to_be_bytes(),
                ),
                vendor_u32(swm::AVP_MAX_REQUESTED_BANDWIDTH_DL, true, 1),
            ],
        ),
    ] {
        let mut children = core();
        children.push(invalid_ambr);
        assert!(parse(&answer_wire(
            base::RESULT_CODE_DIAMETER_SUCCESS,
            &[apn_configuration(&children)]
        ))
        .is_err());
    }
}

#[test]
fn unsupported_pdn_type_is_preserved_raw_but_rejected_for_authorization() {
    let wire = answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[apn_configuration(&[
            vendor_u32(swm::AVP_CONTEXT_IDENTIFIER, true, 7),
            vendor_u32(swm::AVP_PDN_TYPE, true, 99),
            raw_avp(
                swm::AVP_SERVICE_SELECTION,
                AvpFlags::MANDATORY,
                None,
                APN.as_bytes(),
            ),
        ])],
    );
    let parsed = parse(&wire).expect("unknown PDN type remains a raw wire fact");
    assert_eq!(
        parsed.apn_configurations[0].pdn_type,
        swm::PdnType::Other(99)
    );
    let correlated = correlate_wire(&wire, typed_context(), Some(APN));
    assert_eq!(
        correlated
            .apn_configuration_views()
            .expect("future PDN type remains a correlated wire fact")
            .next()
            .expect("one APN")
            .core()
            .pdn_type,
        swm::PdnType::Other(99)
    );
    let error = match correlated.authorized_apn_configurations() {
        Ok(_) => panic!("unknown PDN type must not become authorization"),
        Err(error) => error,
    };
    assert_eq!(
        error.code(),
        swm::SwmApnConfigurationErrorCode::UnsupportedPdnType
    );
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_answer(
                &parsed,
                HOP_BY_HOP,
                END_TO_END,
                EncodeContext::default(),
            )
            .expect("raw unknown PDN type rebuilds")
        ),
        wire
    );
}
