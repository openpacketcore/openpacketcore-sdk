#![cfg(feature = "app-swm")]

use bytes::{Bytes, BytesMut};
use opc_proto_diameter::apps::swm::{self, AuthRequestType};
use opc_proto_diameter::apps::VENDOR_ID_3GPP;
use opc_proto_diameter::base;
use opc_proto_diameter::dictionary::{AvpCardinality, AvpDataType, AvpKey, FlagRequirement};
use opc_proto_diameter::{
    AvpCode, AvpFlags, CommandFlags, Header, Message, OwnedMessage, RawAvp, VendorId,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DuplicateIePolicy, Encode, EncodeContext,
    UnknownIePolicy,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU64;

const HOP_BY_HOP: u32 = 0x0352_0001;
const END_TO_END: u32 = 0x0352_0002;
const SESSION_ID: &str = "session;synthetic;mobility-352";
const EPDG_HOST: &str = "epdg.mobility.synthetic.invalid";
const EPDG_REALM: &str = "visited.mobility.synthetic.invalid";
const AAA_HOST: &str = "aaa.mobility.synthetic.invalid";
const AAA_REALM: &str = "home.mobility.synthetic.invalid";
const PRIVATE_HA_HOST: &str = "ha.mobility.private.invalid";
const PRIVATE_HA_REALM: &str = "mobility.private.invalid";
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

fn agent_info(flags: u8, children: &[Vec<u8>]) -> Vec<u8> {
    let value: Vec<u8> = children.iter().flatten().copied().collect();
    raw_avp(swm::AVP_MIP6_AGENT_INFO, flags, None, &value)
}

fn emergency_info(flags: u8, children: &[Vec<u8>]) -> Vec<u8> {
    let value: Vec<u8> = children.iter().flatten().copied().collect();
    raw_avp(swm::AVP_EMERGENCY_INFO, flags, Some(VENDOR_ID_3GPP), &value)
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
        service_selection: None,
        mip6_feature_vector: None,
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
        mip6_feature_vector: None,
        supported_features: Vec::new(),
        oc_supported_features: None,
        oc_olr: None,
        load_reports: Vec::new(),
        service_selection: None,
        default_context_identifier: None,
        apn_configurations: Vec::new(),
        mobile_node_identifier: None,
        subscriber_authorization: Default::default(),
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

fn sample_gateway() -> swm::SwmMip6AgentInfo {
    swm::SwmMip6AgentInfo::new(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))], None, None)
        .expect("synthetic gateway is valid")
}

#[test]
fn canonical_model_is_total_ordered_and_redaction_safe() {
    let host = swm::SwmMipHomeAgentHost::new(PRIVATE_HA_REALM, PRIVATE_HA_HOST)
        .expect("synthetic host identity");
    let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    let prefix = swm::SwmMip6HomeLinkPrefix::new(
        "2001:db8:352::"
            .parse::<Ipv6Addr>()
            .expect("synthetic IPv6"),
        64,
    )
    .expect("canonical prefix");
    let info = swm::SwmMip6AgentInfo::new(vec![first, second], Some(host), Some(prefix))
        .expect("RFC 5447 permits two same-family addresses");

    assert_eq!(info.home_agent_addresses(), &[first, second]);
    assert!(matches!(
        info.selection(),
        Some(swm::SwmMip6AgentSelection::Addresses(addresses)) if addresses == [first, second]
    ));
    assert_eq!(
        info.home_agent_host().map(|host| host.destination_host()),
        Some(PRIVATE_HA_HOST)
    );
    let debug = format!("{info:?} {:?} {:?}", info.selection(), prefix);
    for private in [
        PRIVATE_HA_HOST,
        PRIVATE_HA_REALM,
        "192.0.2.10",
        "192.0.2.11",
        "2001:db8:352",
    ] {
        assert!(!debug.contains(private));
    }
}

#[test]
fn canonical_model_rejects_missing_identity_excess_addresses_and_bad_prefix() {
    assert_eq!(
        swm::SwmMip6AgentInfo::new(Vec::new(), None, None)
            .expect_err("identity is mandatory")
            .code(),
        swm::SwmGatewayContextErrorCode::MissingGatewayIdentity
    );
    assert_eq!(
        swm::SwmMip6AgentInfo::new(
            vec![
                "192.0.2.1".parse().expect("IPv4"),
                "192.0.2.2".parse().expect("IPv4"),
                "2001:db8::1".parse().expect("IPv6"),
            ],
            None,
            None,
        )
        .expect_err("RFC 5447 caps the address list at two")
        .code(),
        swm::SwmGatewayContextErrorCode::TooManyGatewayAddresses
    );
    assert_eq!(
        swm::SwmMip6HomeLinkPrefix::new("2001:db8::1".parse().expect("IPv6"), 64,)
            .expect_err("host bits must be zero")
            .code(),
        swm::SwmGatewayContextErrorCode::NonzeroHomeLinkPrefixTrailingBits
    );
    assert!(swm::SwmMipHomeAgentHost::new("", PRIVATE_HA_HOST).is_err());
    assert!(swm::SwmMipHomeAgentHost::new(PRIVATE_HA_REALM, "hé").is_err());
}

#[test]
fn independent_top_level_fixture_accepts_m_set_or_clear_and_preserves_order() {
    let first = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let second = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11));
    let children = [
        raw_avp(
            swm::AVP_MIP_HOME_AGENT_ADDRESS,
            AvpFlags::MANDATORY,
            None,
            &address_value(first),
        ),
        raw_avp(
            swm::AVP_MIP_HOME_AGENT_ADDRESS,
            AvpFlags::MANDATORY,
            None,
            &address_value(second),
        ),
    ];
    for flags in [AvpFlags::MANDATORY, 0] {
        let parsed = parse(&answer_wire(
            base::RESULT_CODE_DIAMETER_SUCCESS,
            &[agent_info(flags, &children)],
        ))
        .expect("TS 29.273 note 2 ignores a known top-level M mismatch");
        assert_eq!(
            parsed
                .gateway_context()
                .chained_s2b_s8_serving_gateway()
                .expect("serving gateway")
                .home_agent_addresses(),
            &[first, second]
        );
    }
}

#[test]
fn host_and_home_link_prefix_have_exact_typed_wire_shapes() {
    let host_children = [
        raw_avp(
            base::AVP_DESTINATION_REALM,
            AvpFlags::MANDATORY,
            None,
            PRIVATE_HA_REALM.as_bytes(),
        ),
        raw_avp(
            base::AVP_DESTINATION_HOST,
            AvpFlags::MANDATORY,
            None,
            PRIVATE_HA_HOST.as_bytes(),
        ),
    ];
    let host = raw_avp(
        swm::AVP_MIP_HOME_AGENT_HOST,
        AvpFlags::MANDATORY,
        None,
        &host_children.iter().flatten().copied().collect::<Vec<_>>(),
    );
    let mut prefix_value = vec![64];
    prefix_value.extend_from_slice(
        &"2001:db8:352::"
            .parse::<Ipv6Addr>()
            .expect("synthetic IPv6")
            .octets(),
    );
    let prefix = raw_avp(
        swm::AVP_MIP6_HOME_LINK_PREFIX,
        AvpFlags::MANDATORY,
        None,
        &prefix_value,
    );
    let parsed = parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[agent_info(AvpFlags::MANDATORY, &[host, prefix])],
    ))
    .expect("host/prefix fixture");
    let gateway = parsed
        .gateway_context()
        .chained_s2b_s8_serving_gateway()
        .expect("serving gateway");
    assert_eq!(
        gateway
            .home_agent_host()
            .map(|host| (host.destination_realm(), host.destination_host())),
        Some((PRIVATE_HA_REALM, PRIVATE_HA_HOST))
    );
    assert_eq!(
        gateway.home_link_prefix().map(|prefix| prefix.prefix_len()),
        Some(64)
    );
    assert!(matches!(
        gateway.selection(),
        Some(swm::SwmMip6AgentSelection::Host(_))
    ));
}

#[test]
fn emergency_outer_and_recognized_nested_agent_accept_m_set_or_clear() {
    let address = raw_avp(
        swm::AVP_MIP_HOME_AGENT_ADDRESS,
        AvpFlags::MANDATORY,
        None,
        &address_value("2001:db8::10".parse().expect("IPv6")),
    );
    for outer_flags in [AvpFlags::VENDOR, AvpFlags::VENDOR | AvpFlags::MANDATORY] {
        for nested_flags in [0, AvpFlags::MANDATORY] {
            let parsed = parse(&answer_wire(
                base::RESULT_CODE_DIAMETER_SUCCESS,
                &[emergency_info(
                    outer_flags,
                    &[agent_info(nested_flags, std::slice::from_ref(&address))],
                )],
            ))
            .expect("understood Emergency-Info and MIP6-Agent-Info ignore an M mismatch");
            assert!(parsed.gateway_context().emergency_info().is_some());
        }
    }

    assert!(parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[emergency_info(
            AvpFlags::VENDOR,
            &[agent_info(AvpFlags::PROTECTED, &[address])]
        )],
    ))
    .is_err());
}

#[test]
fn malformed_grouped_shapes_and_wrong_vendor_fail_closed() {
    let address = raw_avp(
        swm::AVP_MIP_HOME_AGENT_ADDRESS,
        AvpFlags::MANDATORY,
        None,
        &address_value("192.0.2.10".parse().expect("IPv4")),
    );
    let empty_agent = agent_info(AvpFlags::MANDATORY, &[]);
    let protected_agent = agent_info(
        AvpFlags::MANDATORY | AvpFlags::PROTECTED,
        std::slice::from_ref(&address),
    );
    let wrong_vendor_agent = raw_avp(
        swm::AVP_MIP6_AGENT_INFO,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(VendorId::new(55_555)),
        &address,
    );
    let bad_prefix = raw_avp(
        swm::AVP_MIP6_HOME_LINK_PREFIX,
        AvpFlags::MANDATORY,
        None,
        &[129; 17],
    );
    let missing_host_child = raw_avp(
        swm::AVP_MIP_HOME_AGENT_HOST,
        AvpFlags::MANDATORY,
        None,
        &raw_avp(
            base::AVP_DESTINATION_REALM,
            AvpFlags::MANDATORY,
            None,
            PRIVATE_HA_REALM.as_bytes(),
        ),
    );
    let empty_host_identity = raw_avp(
        swm::AVP_MIP_HOME_AGENT_HOST,
        AvpFlags::MANDATORY,
        None,
        &[
            raw_avp(base::AVP_DESTINATION_REALM, AvpFlags::MANDATORY, None, b""),
            raw_avp(
                base::AVP_DESTINATION_HOST,
                AvpFlags::MANDATORY,
                None,
                PRIVATE_HA_HOST.as_bytes(),
            ),
        ]
        .iter()
        .flatten()
        .copied()
        .collect::<Vec<_>>(),
    );
    let host = raw_avp(
        swm::AVP_MIP_HOME_AGENT_HOST,
        AvpFlags::MANDATORY,
        None,
        &[
            raw_avp(
                base::AVP_DESTINATION_REALM,
                AvpFlags::MANDATORY,
                None,
                PRIVATE_HA_REALM.as_bytes(),
            ),
            raw_avp(
                base::AVP_DESTINATION_HOST,
                AvpFlags::MANDATORY,
                None,
                PRIVATE_HA_HOST.as_bytes(),
            ),
        ]
        .iter()
        .flatten()
        .copied()
        .collect::<Vec<_>>(),
    );
    let duplicate_host = [host.clone(), host];
    let third_address = raw_avp(
        swm::AVP_MIP_HOME_AGENT_ADDRESS,
        AvpFlags::MANDATORY,
        None,
        &address_value("192.0.2.11".parse().expect("IPv4")),
    );
    let fourth_address = raw_avp(
        swm::AVP_MIP_HOME_AGENT_ADDRESS,
        AvpFlags::MANDATORY,
        None,
        &address_value("192.0.2.12".parse().expect("IPv4")),
    );
    for extra in [
        empty_agent,
        protected_agent,
        wrong_vendor_agent,
        agent_info(AvpFlags::MANDATORY, &[address.clone(), bad_prefix]),
        agent_info(AvpFlags::MANDATORY, &[missing_host_child]),
        agent_info(AvpFlags::MANDATORY, &[empty_host_identity]),
        agent_info(AvpFlags::MANDATORY, &duplicate_host),
        agent_info(
            AvpFlags::MANDATORY,
            &[address.clone(), third_address, fourth_address],
        ),
        agent_info(
            AvpFlags::MANDATORY,
            &[raw_avp(
                swm::AVP_MIP_HOME_AGENT_ADDRESS,
                AvpFlags::MANDATORY,
                None,
                &[0, 3, 192, 0, 2, 10],
            )],
        ),
        agent_info(
            AvpFlags::MANDATORY,
            &[raw_avp(
                swm::AVP_MIP_HOME_AGENT_ADDRESS,
                0,
                None,
                &address_value("192.0.2.10".parse().expect("IPv4")),
            )],
        ),
    ] {
        assert!(parse(&answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &[extra])).is_err());
    }
}

#[test]
fn unknown_optional_children_round_trip_but_unknown_mandatory_and_shared_budget_fail() {
    let address = raw_avp(
        swm::AVP_MIP_HOME_AGENT_ADDRESS,
        AvpFlags::MANDATORY,
        None,
        &address_value("192.0.2.10".parse().expect("IPv4")),
    );
    let optional = raw_avp(AvpCode::new(61_000), 0, None, b"opaque-extension");
    let wire = answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[agent_info(
            AvpFlags::MANDATORY,
            &[address.clone(), optional.clone()],
        )],
    );
    let parsed = parse(&wire).expect("unknown optional grouped child is retained");
    assert_eq!(
        parsed
            .gateway_context()
            .chained_s2b_s8_serving_gateway()
            .expect("serving gateway")
            .extension_count(),
        1
    );
    let retained_gateway = parsed
        .gateway_context()
        .chained_s2b_s8_serving_gateway()
        .expect("serving gateway")
        .clone();
    let transaction = swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END);
    let outbound =
        swm::SwmDiameterEapRequestEnvelope::for_outbound(sample_request(false), transaction);
    let bound = swm::SwmRequestBoundDeaGatewayContext::chained_s2b_s8(&outbound, retained_gateway);
    let rebuilt = encode(
        &swm::build_swm_diameter_eap_answer_for_with_gateway_context(
            &outbound,
            &sample_answer(),
            &bound,
            EncodeContext::default(),
        )
        .expect("retained mobility extension rebuilds"),
    );
    let rebuilt_message = decode(&rebuilt);
    let rebuilt_agent = raw_avps(rebuilt_message.raw_avps)
        .into_iter()
        .find(|avp| avp.header.code == swm::AVP_MIP6_AGENT_INFO)
        .expect("rebuilt MIP6-Agent-Info");
    assert!(
        rebuilt_agent
            .value
            .windows(optional.len())
            .any(|candidate| candidate == optional),
        "the exact retained optional child must be re-emitted"
    );
    assert!(parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[agent_info(
            AvpFlags::MANDATORY,
            &[
                address.clone(),
                raw_avp(AvpCode::new(61_001), AvpFlags::MANDATORY, None, b"x"),
            ],
        )],
    ))
    .is_err());

    let nested: Vec<Vec<u8>> = std::iter::once(address)
        .chain((0..65).map(|index| raw_avp(AvpCode::new(62_000 + index), 0, None, b"x")))
        .collect();
    let top_level: Vec<Vec<u8>> = std::iter::once(agent_info(AvpFlags::MANDATORY, &nested))
        .chain((0..64).map(|index| raw_avp(AvpCode::new(63_000 + index), 0, None, b"x")))
        .collect();
    assert!(parse(&answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &top_level)).is_err());
}

#[test]
fn request_bound_chained_gateway_builds_correlates_and_authorizes() {
    let transaction = swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END);
    let outbound =
        swm::SwmDiameterEapRequestEnvelope::for_outbound(sample_request(false), transaction);
    let bound = swm::SwmRequestBoundDeaGatewayContext::chained_s2b_s8(&outbound, sample_gateway());
    let wire = encode(
        &swm::build_swm_diameter_eap_answer_for_with_gateway_context(
            &outbound,
            &sample_answer(),
            &bound,
            EncodeContext::default(),
        )
        .expect("request-bound serving gateway answer"),
    );
    let message = decode(&wire);
    let outer = raw_avps(message.raw_avps)
        .into_iter()
        .find(|avp| avp.header.code == swm::AVP_MIP6_AGENT_INFO)
        .expect("MIP6-Agent-Info emitted");
    assert_eq!(outer.header.vendor_id, None);
    assert!(outer.header.flags.is_mandatory());
    assert!(!outer.header.flags.is_protected());
    let received = swm::parse_swm_diameter_eap_answer_envelope(&message, typed_context())
        .expect("typed mobility DEA");
    let correlated = outbound
        .correlate_answer(received)
        .expect("exact DER/DEA correlation");
    let authorized = correlated
        .authorize_chained_s2b_s8_gateway(
            swm::SwmChainedS2bS8Authorization::from_trusted_routing_context(),
        )
        .expect("caller-authorized chained gateway")
        .expect("gateway present");
    assert_eq!(
        authorized.gateway().home_agent_addresses(),
        sample_gateway().home_agent_addresses()
    );
}

#[test]
fn emergency_gateway_requires_emergency_request_exact_success_and_exact_binding() {
    let transaction = swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END);
    let emergency =
        swm::SwmDiameterEapRequestEnvelope::for_outbound(sample_request(true), transaction);
    assert!(
        swm::SwmRequestBoundDeaGatewayContext::authenticated_non_roaming_emergency_from_hss(
            &swm::SwmDiameterEapRequestEnvelope::for_outbound(sample_request(false), transaction),
            sample_gateway(),
        )
        .is_err()
    );
    let bound =
        swm::SwmRequestBoundDeaGatewayContext::authenticated_non_roaming_emergency_from_hss(
            &emergency,
            sample_gateway(),
        )
        .expect("emergency DER permits HSS-derived context");
    let different = swm::SwmDiameterEapRequestEnvelope::for_outbound(
        sample_request(true),
        swm::SwmDiameterTransaction::new(HOP_BY_HOP + 1, END_TO_END),
    );
    assert!(swm::build_swm_diameter_eap_answer_for_with_gateway_context(
        &different,
        &sample_answer(),
        &bound,
        EncodeContext::default(),
    )
    .is_err());
    let mut different_facts = sample_request(true);
    different_facts.user_name = Some("different@synthetic.invalid".to_owned().into());
    let different_facts =
        swm::SwmDiameterEapRequestEnvelope::for_outbound(different_facts, transaction);
    assert!(swm::build_swm_diameter_eap_answer_for_with_gateway_context(
        &different_facts,
        &sample_answer(),
        &bound,
        EncodeContext::default(),
    )
    .is_err());
    let mut failure = sample_answer();
    failure.result = swm::SwmDiameterResult::Base(base::RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY);
    failure.eap_payload = None;
    assert!(swm::build_swm_diameter_eap_answer_for_with_gateway_context(
        &emergency,
        &failure,
        &bound,
        EncodeContext::default(),
    )
    .is_err());

    let wire = encode(
        &swm::build_swm_diameter_eap_answer_for_with_gateway_context(
            &emergency,
            &sample_answer(),
            &bound,
            EncodeContext::default(),
        )
        .expect("request-bound emergency answer"),
    );
    let message = decode(&wire);
    let emergency_outer = raw_avps(message.raw_avps)
        .into_iter()
        .find(|avp| avp.header.code == swm::AVP_EMERGENCY_INFO)
        .expect("Emergency-Info emitted");
    assert_eq!(emergency_outer.header.vendor_id, Some(VENDOR_ID_3GPP));
    assert!(emergency_outer.header.flags.is_vendor_specific());
    assert!(!emergency_outer.header.flags.is_mandatory());
    assert!(!emergency_outer.header.flags.is_protected());
    let nested_agent = raw_avps(emergency_outer.value)
        .into_iter()
        .find(|avp| avp.header.code == swm::AVP_MIP6_AGENT_INFO)
        .expect("nested MIP6-Agent-Info emitted");
    assert_eq!(nested_agent.header.vendor_id, None);
    assert!(nested_agent.header.flags.is_mandatory());
    assert!(!nested_agent.header.flags.is_protected());
    let received = swm::parse_swm_diameter_eap_answer_envelope(&message, typed_context())
        .expect("typed emergency DEA");
    let rebuilt = encode(
        &swm::build_swm_diameter_eap_answer_for_with_gateway_context(
            &emergency,
            received.answer(),
            &bound,
            EncodeContext::default(),
        )
        .expect("parsed request-bound context rebuilds canonically"),
    );
    assert_eq!(rebuilt, wire);
    let correlated = emergency
        .correlate_answer(received)
        .expect("exact emergency correlation");
    assert!(correlated
        .answer()
        .gateway_context()
        .emergency_info()
        .is_some());
    assert!(correlated
        .authorize_authenticated_non_roaming_emergency_gateway(
            swm::SwmAuthenticatedNonRoamingEmergencyAuthorization::from_trusted_hss_context(),
        )
        .is_ok());
}

#[test]
fn authenticated_response_correlation_unlocks_emergency_gateway_authorization() {
    let transaction = swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END);
    let outbound = swm::SwmDiameterEapRequestEnvelope::for_outbound_on(
        sample_request(true),
        transaction,
        swm::SwmExpectedAnswerPeer::direct(CONNECTION, AAA_HOST.to_owned(), AAA_REALM.to_owned()),
    );
    let bound =
        swm::SwmRequestBoundDeaGatewayContext::authenticated_non_roaming_emergency_from_hss(
            &outbound,
            sample_gateway(),
        )
        .expect("emergency DER permits HSS-derived context");
    let wire = encode(
        &swm::build_swm_diameter_eap_answer_for_with_gateway_context(
            &outbound,
            &sample_answer(),
            &bound,
            EncodeContext::default(),
        )
        .expect("request-bound emergency answer"),
    );
    let received = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wire),
        CONNECTION,
        typed_context(),
    )
    .expect("authenticated response envelope");
    let correlated = outbound
        .correlate_response(received)
        .expect("connection and application correlation");
    let authorized = correlated
        .authorize_authenticated_non_roaming_emergency_gateway(
            swm::SwmAuthenticatedNonRoamingEmergencyAuthorization::from_trusted_hss_context(),
        )
        .expect("caller-authorized emergency gateway");
    assert_eq!(
        authorized.gateway().home_agent_addresses(),
        sample_gateway().home_agent_addresses()
    );
}

#[test]
fn emergency_group_cardinality_vendor_and_flags_fail_closed() {
    let address = raw_avp(
        swm::AVP_MIP_HOME_AGENT_ADDRESS,
        AvpFlags::MANDATORY,
        None,
        &address_value("192.0.2.10".parse().expect("IPv4")),
    );
    let nested = agent_info(AvpFlags::MANDATORY, &[address]);
    let wrong_vendor = raw_avp(
        swm::AVP_EMERGENCY_INFO,
        AvpFlags::VENDOR,
        Some(VendorId::new(55_555)),
        &nested,
    );
    for extra in [
        emergency_info(AvpFlags::VENDOR, &[]),
        emergency_info(AvpFlags::VENDOR, &[nested.clone(), nested.clone()]),
        emergency_info(
            AvpFlags::VENDOR | AvpFlags::PROTECTED,
            std::slice::from_ref(&nested),
        ),
        wrong_vendor,
        raw_avp(swm::AVP_EMERGENCY_INFO, 0, None, &nested),
    ] {
        assert!(parse(&answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &[extra])).is_err());
    }
}

#[test]
fn duplicate_vendor_collision_and_truncated_mobility_shapes_fail_closed() {
    let address_value = address_value("192.0.2.10".parse().expect("IPv4"));
    let address = raw_avp(
        swm::AVP_MIP_HOME_AGENT_ADDRESS,
        AvpFlags::MANDATORY,
        None,
        &address_value,
    );
    let agent = agent_info(AvpFlags::MANDATORY, std::slice::from_ref(&address));
    assert!(parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[agent.clone(), agent],
    ))
    .is_err());

    let vendor_collision = raw_avp(
        swm::AVP_MIP_HOME_AGENT_ADDRESS,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(VENDOR_ID_3GPP),
        &address_value,
    );
    assert!(parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[agent_info(AvpFlags::MANDATORY, &[vendor_collision],)],
    ))
    .is_err());

    let truncated_prefix = raw_avp(
        swm::AVP_MIP6_HOME_LINK_PREFIX,
        AvpFlags::MANDATORY,
        None,
        &[0; 16],
    );
    assert!(parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[agent_info(
            AvpFlags::MANDATORY,
            &[address.clone(), truncated_prefix],
        )],
    ))
    .is_err());

    let mut truncated_child = Vec::new();
    truncated_child.extend_from_slice(&swm::AVP_MIP_HOME_AGENT_ADDRESS.get().to_be_bytes());
    truncated_child.push(AvpFlags::MANDATORY);
    put_u24(&mut truncated_child, 14);
    truncated_child.extend_from_slice(&[0, 1]);
    assert!(parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[agent_info(AvpFlags::MANDATORY, &[truncated_child])],
    ))
    .is_err());
}

#[test]
fn dictionary_pins_mobility_types_cardinality_and_contextual_flags() {
    let dictionary = swm::dictionary();
    let agent = dictionary
        .find_avp(AvpKey::ietf(swm::AVP_MIP6_AGENT_INFO))
        .expect("MIP6-Agent-Info definition");
    assert_eq!(agent.data_type(), AvpDataType::Grouped);
    assert_eq!(agent.flags().vendor(), FlagRequirement::MustBeUnset);
    assert_eq!(agent.flags().mandatory(), FlagRequirement::MayBeSet);
    assert_eq!(agent.flags().protected(), FlagRequirement::MustBeUnset);
    assert_eq!(
        agent
            .find_grouped_avp_rule(AvpKey::ietf(swm::AVP_MIP_HOME_AGENT_ADDRESS))
            .map(|rule| rule.cardinality()),
        Some(AvpCardinality::ZeroOrMore)
    );

    let emergency = dictionary
        .find_avp(AvpKey::vendor(swm::AVP_EMERGENCY_INFO, VENDOR_ID_3GPP))
        .expect("Emergency-Info definition");
    assert_eq!(emergency.data_type(), AvpDataType::Grouped);
    assert_eq!(emergency.flags().vendor(), FlagRequirement::MustBeSet);
    assert_eq!(emergency.flags().mandatory(), FlagRequirement::MayBeSet);
    assert_eq!(emergency.flags().protected(), FlagRequirement::MustBeUnset);
}

#[test]
fn non_success_and_missing_emergency_context_fail_closed_on_parse_or_authorization() {
    let address = raw_avp(
        swm::AVP_MIP_HOME_AGENT_ADDRESS,
        AvpFlags::MANDATORY,
        None,
        &address_value("192.0.2.10".parse().expect("IPv4")),
    );
    assert!(parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_UNABLE_TO_COMPLY,
        &[agent_info(AvpFlags::MANDATORY, &[address])],
    ))
    .is_err());

    let transaction = swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END);
    let outbound =
        swm::SwmDiameterEapRequestEnvelope::for_outbound(sample_request(true), transaction);
    let answer = swm::SwmDiameterEapAnswerEnvelope::for_outbound(sample_answer(), transaction);
    let correlated = outbound
        .correlate_answer(answer)
        .expect("plain success still correlates");
    assert_eq!(
        correlated
            .authorize_authenticated_non_roaming_emergency_gateway(
                swm::SwmAuthenticatedNonRoamingEmergencyAuthorization::from_trusted_hss_context(),
            )
            .expect_err("emergency gateway is absent")
            .code(),
        swm::SwmGatewayContextErrorCode::EmergencyGatewayMissing
    );
}

#[test]
fn parsed_emergency_context_cannot_authorize_a_non_emergency_request() {
    let address = raw_avp(
        swm::AVP_MIP_HOME_AGENT_ADDRESS,
        AvpFlags::MANDATORY,
        None,
        &address_value("192.0.2.10".parse().expect("IPv4")),
    );
    let emergency = emergency_info(
        AvpFlags::VENDOR,
        &[agent_info(AvpFlags::MANDATORY, &[address])],
    );
    let outbound = swm::SwmDiameterEapRequestEnvelope::for_outbound_on(
        sample_request(false),
        swm::SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END),
        swm::SwmExpectedAnswerPeer::direct(CONNECTION, AAA_HOST.to_owned(), AAA_REALM.to_owned()),
    );
    let received = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&answer_wire(
            base::RESULT_CODE_DIAMETER_SUCCESS,
            &[emergency],
        )),
        CONNECTION,
        typed_context(),
    )
    .expect("hostile emergency context is syntactically valid");
    let correlated = outbound
        .correlate_response(received)
        .expect("message correlation is independent of emergency semantics");
    assert_eq!(
        correlated
            .authorize_authenticated_non_roaming_emergency_gateway(
                swm::SwmAuthenticatedNonRoamingEmergencyAuthorization::from_trusted_hss_context(),
            )
            .expect_err("a non-emergency DER must not authorize received emergency context")
            .code(),
        swm::SwmGatewayContextErrorCode::RequestNotEmergency
    );
}
