#![cfg(feature = "app-swm")]

use bytes::{Bytes, BytesMut};
use opc_proto_diameter::apps::swm::{
    self, AuthRequestType, SwmApnOiReplacement, SwmChargingCharacteristics,
    SwmConditionalValueSource, SwmCoreNetworkRestrictions, SwmDeaSubscriberAuthorization,
    SwmDiameterConnectionToken, SwmDiameterEapAnswer, SwmDiameterEapAnswerEnvelope,
    SwmDiameterResult, SwmE164Number, SwmExpectedAnswerPeer, SwmLocallyConfiguredMobilityMode,
    SwmMip6FeatureVector, SwmMpsPriority, SwmSubscriptionId, SwmUeUsageType,
};
use opc_proto_diameter::apps::VENDOR_ID_3GPP;
use opc_proto_diameter::{
    base, AvpCode, AvpFlags, CommandFlags, Header, Message, OwnedMessage, RawAvp, VendorId,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DuplicateIePolicy, Encode, EncodeContext,
    UnknownIePolicy,
};
use std::num::NonZeroU64;
use zeroize::ZeroizeOnDrop;

const HOP_BY_HOP: u32 = 0x0123_4567;
const END_TO_END: u32 = 0x89ab_cdef;
const SESSION_ID: &[u8] = b"session;synthetic;subscriber-auth";
const EPDG_HOST: &[u8] = b"epdg.synthetic.invalid";
const AAA_HOST: &[u8] = b"aaa.synthetic.invalid";
const REALM: &[u8] = b"home.synthetic.invalid";
const E164: &str = "15551234567";
const APN_OI: &str = "mnc001.mcc001.gprs";
const UNKNOWN_CHILD: AvpCode = AvpCode::new(998_001);
const RETRY_CONNECTION: SwmDiameterConnectionToken =
    SwmDiameterConnectionToken::new(NonZeroU64::MIN);

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

fn subscription_id_value(
    subscription_type: u32,
    data: &[u8],
    type_flags: u8,
    data_flags: u8,
    additional: &[Vec<u8>],
) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend_from_slice(&raw_avp(
        swm::AVP_SUBSCRIPTION_ID_TYPE,
        type_flags,
        None,
        &subscription_type.to_be_bytes(),
    ));
    value.extend_from_slice(&raw_avp(
        swm::AVP_SUBSCRIPTION_ID_DATA,
        data_flags,
        None,
        data,
    ));
    for child in additional {
        value.extend_from_slice(child);
    }
    value
}

fn answer_wire(result_code: u32, extras: &[Vec<u8>]) -> Vec<u8> {
    let mut raw = Vec::new();
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
            &3_u32.to_be_bytes(),
        ),
        raw_avp(
            base::AVP_RESULT_CODE,
            AvpFlags::MANDATORY,
            None,
            &result_code.to_be_bytes(),
        ),
        raw_avp(base::AVP_ORIGIN_HOST, AvpFlags::MANDATORY, None, AAA_HOST),
        raw_avp(base::AVP_ORIGIN_REALM, AvpFlags::MANDATORY, None, REALM),
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
            &[3, 9, 0, 4],
        ));
    }
    encode_message(&OwnedMessage {
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

fn request_wire(emergency: bool, mobility: Option<u64>) -> Vec<u8> {
    let mut raw = Vec::new();
    for avp in [
        raw_avp(base::AVP_SESSION_ID, AvpFlags::MANDATORY, None, SESSION_ID),
        raw_avp(base::AVP_ORIGIN_HOST, AvpFlags::MANDATORY, None, EPDG_HOST),
        raw_avp(base::AVP_ORIGIN_REALM, AvpFlags::MANDATORY, None, REALM),
        raw_avp(
            base::AVP_DESTINATION_REALM,
            AvpFlags::MANDATORY,
            None,
            REALM,
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
            swm::AVP_EAP_PAYLOAD,
            AvpFlags::MANDATORY,
            None,
            &[2, 9, 0, 5, 1],
        ),
    ] {
        raw.extend_from_slice(&avp);
    }
    if emergency {
        raw.extend_from_slice(&raw_avp(
            swm::AVP_EMERGENCY_SERVICES,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            &1_u32.to_be_bytes(),
        ));
    }
    if let Some(mobility) = mobility {
        raw.extend_from_slice(&raw_avp(
            swm::AVP_MIP6_FEATURE_VECTOR,
            AvpFlags::MANDATORY,
            None,
            &mobility.to_be_bytes(),
        ));
    }
    encode_message(&OwnedMessage {
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
    let (tail, message) = Message::decode(wire, framing_context()).expect("synthetic framing");
    assert!(tail.is_empty());
    message
}

fn parse(wire: &[u8]) -> Result<SwmDiameterEapAnswer, DecodeError> {
    swm::parse_swm_diameter_eap_answer(&decode(wire), typed_context(UnknownIePolicy::Preserve))
}

fn parse_with_policy(
    wire: &[u8],
    unknown_ie_policy: UnknownIePolicy,
) -> Result<SwmDiameterEapAnswer, DecodeError> {
    swm::parse_swm_diameter_eap_answer(&decode(wire), typed_context(unknown_ie_policy))
}

fn encode_message(message: &OwnedMessage) -> Vec<u8> {
    let mut wire = BytesMut::new();
    message
        .encode(&mut wire, EncodeContext::default())
        .expect("synthetic message encodes");
    wire.to_vec()
}

fn full_authorization_extras(charging_flags: u8) -> Vec<Vec<u8>> {
    let unknown = raw_avp(UNKNOWN_CHILD, 0, None, b"retained-child");
    vec![
        raw_avp(
            swm::AVP_APN_OI_REPLACEMENT,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            APN_OI.as_bytes(),
        ),
        raw_avp(
            swm::AVP_SUBSCRIPTION_ID,
            AvpFlags::MANDATORY | AvpFlags::PROTECTED,
            None,
            &subscription_id_value(
                0,
                E164.as_bytes(),
                AvpFlags::MANDATORY | AvpFlags::PROTECTED,
                AvpFlags::MANDATORY | AvpFlags::PROTECTED,
                &[unknown],
            ),
        ),
        raw_avp(
            swm::AVP_3GPP_CHARGING_CHARACTERISTICS,
            charging_flags,
            Some(VENDOR_ID_3GPP),
            b"a1B2",
        ),
        raw_avp(
            swm::AVP_UE_USAGE_TYPE,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            &255_u32.to_be_bytes(),
        ),
        raw_avp(
            swm::AVP_CORE_NETWORK_RESTRICTIONS,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            &0x8000_0003_u32.to_be_bytes(),
        ),
        raw_avp(
            swm::AVP_MPS_PRIORITY,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            &0x8000_0007_u32.to_be_bytes(),
        ),
    ]
}

fn successful_answer(authorization: SwmDeaSubscriberAuthorization) -> SwmDiameterEapAnswer {
    SwmDiameterEapAnswer {
        session_id: String::from_utf8(SESSION_ID.to_vec())
            .expect("synthetic Session-Id is UTF-8")
            .into(),
        auth_application_id: swm::APPLICATION_ID.get(),
        auth_request_type: AuthRequestType::AuthorizeAuthenticate,
        result: SwmDiameterResult::Base(base::RESULT_CODE_DIAMETER_SUCCESS),
        origin_host: String::from_utf8(AAA_HOST.to_vec())
            .expect("synthetic Origin-Host is UTF-8")
            .into(),
        origin_realm: String::from_utf8(REALM.to_vec())
            .expect("synthetic Origin-Realm is UTF-8")
            .into(),
        user_name: None,
        subscriber_authorization: authorization,
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
    }
}

fn find_avp<'a>(message: &'a Message<'a>, code: AvpCode) -> RawAvp<'a> {
    find_nested_avp(message.raw_avps, code)
}

fn find_nested_avp(mut input: &[u8], code: AvpCode) -> RawAvp<'_> {
    while !input.is_empty() {
        let (tail, avp) = RawAvp::decode(input, framing_context()).expect("encoded AVP");
        if avp.header.code == code {
            return avp;
        }
        input = tail;
    }
    panic!("synthetic output omitted requested AVP")
}

#[test]
fn independent_fixture_parses_all_subscriber_values_and_discards_unassigned_bits() {
    let extras = full_authorization_extras(AvpFlags::VENDOR | AvpFlags::PROTECTED);
    let parsed = parse(&answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &extras))
        .expect("complete subscriber authorization fixture");
    let authorization = &parsed.subscriber_authorization;

    assert_eq!(
        authorization
            .apn_oi_replacement()
            .expect("APN-OI-Replacement")
            .as_str(),
        APN_OI
    );
    assert_eq!(
        authorization
            .subscription_id()
            .expect("Subscription-Id")
            .value()
            .as_str(),
        E164
    );
    assert_eq!(
        authorization
            .subscription_id()
            .expect("Subscription-Id")
            .additional_avp_count(),
        1
    );
    assert_eq!(
        authorization
            .charging_characteristics()
            .expect("charging characteristics")
            .octets(),
        [0xa1, 0xb2]
    );
    assert_eq!(
        authorization.ue_usage_type().map(SwmUeUsageType::value),
        Some(255)
    );
    assert!(authorization
        .core_network_restrictions()
        .expect("core restrictions")
        .disallows_five_gc());
    let mps = authorization.mps_priority().expect("MPS priority");
    assert!(mps.has_cs_priority());
    assert!(mps.has_eps_priority());
    assert!(mps.has_messaging_priority());
}

#[test]
fn absent_authorization_bundle_preserves_existing_dea_bytes() {
    let wire = answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &[]);
    let parsed = parse(&wire).expect("legacy DEA without subscriber facts");
    assert!(parsed.subscriber_authorization.is_empty());
    assert_eq!(
        encode_message(
            &swm::build_swm_diameter_eap_answer(
                &parsed,
                HOP_BY_HOP,
                END_TO_END,
                EncodeContext::default(),
            )
            .expect("legacy DEA remains encodable"),
        ),
        wire
    );
}

#[test]
fn correlated_builder_canonicalizes_values_and_preserves_subscription_extensions() {
    let mut parsed = parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &full_authorization_extras(AvpFlags::VENDOR | AvpFlags::PROTECTED),
    ))
    .expect("complete fixture");
    parsed.mip6_feature_vector = Some(SwmMip6FeatureVector::from_bits_retain(
        SwmMip6FeatureVector::GTPV2_SUPPORTED,
    ));
    let request_wire = request_wire(false, Some(SwmMip6FeatureVector::GTPV2_SUPPORTED));
    let request = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&request_wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("synthetic DER envelope");
    let rebuilt =
        swm::build_swm_diameter_eap_answer_for(&request, &parsed, EncodeContext::default())
            .expect("request-conditioned subscriber authorization encodes");
    let wire = encode_message(&rebuilt);
    let message = decode(&wire);

    let charging = find_avp(&message, swm::AVP_3GPP_CHARGING_CHARACTERISTICS);
    assert_eq!(charging.header.flags.bits(), AvpFlags::VENDOR);
    assert_eq!(charging.value, b"A1B2");
    assert_eq!(
        find_avp(&message, swm::AVP_APN_OI_REPLACEMENT)
            .header
            .flags
            .bits(),
        AvpFlags::VENDOR | AvpFlags::MANDATORY
    );
    assert_eq!(
        find_avp(&message, swm::AVP_CORE_NETWORK_RESTRICTIONS).value,
        2_u32.to_be_bytes()
    );
    assert_eq!(
        find_avp(&message, swm::AVP_MPS_PRIORITY).value,
        7_u32.to_be_bytes()
    );
    let subscription = find_avp(&message, swm::AVP_SUBSCRIPTION_ID);
    assert_eq!(subscription.header.flags.bits(), AvpFlags::MANDATORY);
    assert_eq!(
        find_nested_avp(subscription.value, swm::AVP_SUBSCRIPTION_ID_TYPE)
            .header
            .flags
            .bits(),
        AvpFlags::MANDATORY
    );
    assert_eq!(
        find_nested_avp(subscription.value, swm::AVP_SUBSCRIPTION_ID_DATA)
            .header
            .flags
            .bits(),
        AvpFlags::MANDATORY
    );
    assert!(subscription
        .value
        .windows(b"retained-child".len())
        .any(|window| window == b"retained-child"));
    assert_eq!(
        parse(&wire)
            .expect("canonical answer reparses")
            .subscriber_authorization,
        parsed.subscriber_authorization
    );
}

#[test]
fn e164_and_apn_constructors_reject_non_wire_presentations() {
    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    assert_zeroize_on_drop::<SwmE164Number>();

    for invalid in [
        "",
        "0",
        "000000",
        "0123",
        "+15551234567",
        "1555-123-4567",
        "1234567890123456",
    ] {
        assert!(SwmE164Number::new(invalid).is_err());
    }
    for invalid in [
        "",
        "mnc01.mcc001.gprs",
        "mnc001.mcc01.gprs",
        "mnc001.mcc001.example",
        "mnc0001.mcc001.gprs",
        "mnc001.mcc0001.gprs",
        ".mnc001.mcc001.gprs",
        "bad_label.mnc001.mcc001.gprs",
        "-bad.mnc001.mcc001.gprs",
        "mnc001.mcc001.gprs.example",
    ] {
        assert!(SwmApnOiReplacement::new(invalid).is_err());
    }
    assert!(SwmE164Number::new(E164).is_ok());
    for valid in [
        APN_OI,
        "internet.mnc001.mcc001.gprs",
        "ims.service.MNC123.MCC456.GPRS",
    ] {
        assert!(SwmApnOiReplacement::new(valid).is_ok());
    }
}

#[test]
fn subscription_id_rejects_wrong_type_invalid_e164_and_child_flags() {
    let cases = [
        subscription_id_value(
            1,
            E164.as_bytes(),
            AvpFlags::MANDATORY,
            AvpFlags::MANDATORY,
            &[],
        ),
        subscription_id_value(
            0,
            b"+15551234567",
            AvpFlags::MANDATORY,
            AvpFlags::MANDATORY,
            &[],
        ),
        subscription_id_value(
            0,
            b"1234567890123456",
            AvpFlags::MANDATORY,
            AvpFlags::MANDATORY,
            &[],
        ),
        subscription_id_value(0, b"0", AvpFlags::MANDATORY, AvpFlags::MANDATORY, &[]),
        subscription_id_value(0, b"0123", AvpFlags::MANDATORY, AvpFlags::MANDATORY, &[]),
        subscription_id_value(0, E164.as_bytes(), 0, AvpFlags::MANDATORY, &[]),
        subscription_id_value(0, E164.as_bytes(), AvpFlags::MANDATORY, 0, &[]),
    ];
    for value in cases {
        let extra = raw_avp(swm::AVP_SUBSCRIPTION_ID, AvpFlags::MANDATORY, None, &value);
        assert!(parse(&answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &[extra])).is_err());
    }
}

#[test]
fn subscription_id_rejects_missing_duplicate_and_unknown_mandatory_children() {
    let only_type = raw_avp(
        swm::AVP_SUBSCRIPTION_ID_TYPE,
        AvpFlags::MANDATORY,
        None,
        &0_u32.to_be_bytes(),
    );
    let only_data = raw_avp(
        swm::AVP_SUBSCRIPTION_ID_DATA,
        AvpFlags::MANDATORY,
        None,
        E164.as_bytes(),
    );
    let duplicate_type = subscription_id_value(
        0,
        E164.as_bytes(),
        AvpFlags::MANDATORY,
        AvpFlags::MANDATORY,
        std::slice::from_ref(&only_type),
    );
    let unknown_mandatory = subscription_id_value(
        0,
        E164.as_bytes(),
        AvpFlags::MANDATORY,
        AvpFlags::MANDATORY,
        &[raw_avp(
            UNKNOWN_CHILD,
            AvpFlags::MANDATORY,
            None,
            b"unknown",
        )],
    );

    for (flags, value) in [
        (AvpFlags::MANDATORY, only_type),
        (AvpFlags::MANDATORY, only_data),
        (AvpFlags::MANDATORY, duplicate_type),
        (AvpFlags::MANDATORY, unknown_mandatory),
    ] {
        let outer = raw_avp(swm::AVP_SUBSCRIPTION_ID, flags, None, &value);
        assert!(parse(&answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &[outer])).is_err());
    }
}

#[test]
fn subscription_id_rejects_vendor_smuggling_of_core_child_codes() {
    for vendor_id in [VendorId::new(0), VendorId::new(42_424)] {
        for (code, value) in [
            (swm::AVP_SUBSCRIPTION_ID_TYPE, 0_u32.to_be_bytes().to_vec()),
            (swm::AVP_SUBSCRIPTION_ID_DATA, E164.as_bytes().to_vec()),
        ] {
            let collision = raw_avp(code, AvpFlags::VENDOR, Some(vendor_id), &value);
            let grouped = subscription_id_value(
                0,
                E164.as_bytes(),
                AvpFlags::MANDATORY,
                AvpFlags::MANDATORY,
                &[collision],
            );
            let outer = raw_avp(
                swm::AVP_SUBSCRIPTION_ID,
                AvpFlags::MANDATORY,
                None,
                &grouped,
            );
            for policy in [UnknownIePolicy::Preserve, UnknownIePolicy::Drop] {
                assert!(parse_with_policy(
                    &answer_wire(
                        base::RESULT_CODE_DIAMETER_SUCCESS,
                        std::slice::from_ref(&outer),
                    ),
                    policy,
                )
                .is_err());
            }
        }
    }
}

#[test]
fn subscription_id_rejects_vendor_zero_optional_extension_before_policy() {
    let vendor_zero_extension = raw_avp(
        UNKNOWN_CHILD,
        AvpFlags::VENDOR,
        Some(VendorId::new(0)),
        b"must-not-be-retained",
    );
    let grouped = subscription_id_value(
        0,
        E164.as_bytes(),
        AvpFlags::MANDATORY,
        AvpFlags::MANDATORY,
        &[vendor_zero_extension],
    );
    let outer = raw_avp(
        swm::AVP_SUBSCRIPTION_ID,
        AvpFlags::MANDATORY,
        None,
        &grouped,
    );

    for policy in [UnknownIePolicy::Preserve, UnknownIePolicy::Drop] {
        parse_with_policy(
            &answer_wire(
                base::RESULT_CODE_DIAMETER_SUCCESS,
                std::slice::from_ref(&outer),
            ),
            policy,
        )
        .expect_err("SWm must reject nested Vendor-Id zero before unknown-AVP handling");
    }
}

#[test]
fn subscription_optional_child_policy_is_bounded_and_duplicate_safe() {
    let unknown = raw_avp(UNKNOWN_CHILD, 0, None, b"sealed-extension");
    let value = subscription_id_value(
        0,
        E164.as_bytes(),
        AvpFlags::MANDATORY,
        AvpFlags::MANDATORY,
        std::slice::from_ref(&unknown),
    );
    let outer = raw_avp(swm::AVP_SUBSCRIPTION_ID, AvpFlags::MANDATORY, None, &value);
    let dropped = parse_with_policy(
        &answer_wire(
            base::RESULT_CODE_DIAMETER_SUCCESS,
            std::slice::from_ref(&outer),
        ),
        UnknownIePolicy::Drop,
    )
    .expect("Drop discards an optional grouped extension");
    assert_eq!(
        dropped
            .subscriber_authorization
            .subscription_id()
            .expect("typed Subscription-Id")
            .additional_avp_count(),
        0
    );
    assert!(parse_with_policy(
        &answer_wire(
            base::RESULT_CODE_DIAMETER_SUCCESS,
            std::slice::from_ref(&outer)
        ),
        UnknownIePolicy::Reject,
    )
    .is_err());

    let duplicated_value = subscription_id_value(
        0,
        E164.as_bytes(),
        AvpFlags::MANDATORY,
        AvpFlags::MANDATORY,
        &[unknown.clone(), unknown],
    );
    let duplicated = raw_avp(
        swm::AVP_SUBSCRIPTION_ID,
        AvpFlags::MANDATORY,
        None,
        &duplicated_value,
    );
    assert!(parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[duplicated],
    ))
    .is_err());
}

#[test]
fn ue_usage_and_core_restrictions_accept_known_m_mismatch_and_encode_canonically() {
    let extras = [
        raw_avp(
            swm::AVP_UE_USAGE_TYPE,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            &127_u32.to_be_bytes(),
        ),
        raw_avp(
            swm::AVP_CORE_NETWORK_RESTRICTIONS,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VENDOR_ID_3GPP),
            &2_u32.to_be_bytes(),
        ),
    ];
    let parsed = parse(&answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &extras))
        .expect("SWm receiver ignores recognized M mismatch");
    let rebuilt = swm::build_swm_diameter_eap_answer(
        &parsed,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .expect("canonical subscriber facts encode");
    let wire = encode_message(&rebuilt);
    let message = decode(&wire);
    assert_eq!(
        find_avp(&message, swm::AVP_UE_USAGE_TYPE)
            .header
            .flags
            .bits(),
        AvpFlags::VENDOR
    );
    assert_eq!(
        find_avp(&message, swm::AVP_CORE_NETWORK_RESTRICTIONS)
            .header
            .flags
            .bits(),
        AvpFlags::VENDOR
    );
}

#[test]
fn understood_outer_subscriber_m_mismatches_encode_canonically() {
    for mandatory in [false, true] {
        let m = if mandatory { AvpFlags::MANDATORY } else { 0 };
        let subscription = subscription_id_value(
            0,
            E164.as_bytes(),
            AvpFlags::MANDATORY,
            AvpFlags::MANDATORY,
            &[],
        );
        let extras = [
            raw_avp(
                swm::AVP_APN_OI_REPLACEMENT,
                AvpFlags::VENDOR | m,
                Some(VENDOR_ID_3GPP),
                APN_OI.as_bytes(),
            ),
            raw_avp(swm::AVP_SUBSCRIPTION_ID, m, None, &subscription),
            raw_avp(
                swm::AVP_3GPP_CHARGING_CHARACTERISTICS,
                AvpFlags::VENDOR | m,
                Some(VENDOR_ID_3GPP),
                b"A1B2",
            ),
            raw_avp(
                swm::AVP_MPS_PRIORITY,
                AvpFlags::VENDOR | m,
                Some(VENDOR_ID_3GPP),
                &2_u32.to_be_bytes(),
            ),
        ];
        let mut parsed = parse(&answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &extras))
            .expect("understood outer subscriber M mismatch is tolerated");
        parsed.mip6_feature_vector = Some(SwmMip6FeatureVector::gtpv2_only());
        let request_wire = request_wire(false, Some(SwmMip6FeatureVector::GTPV2_SUPPORTED));
        let request = swm::parse_swm_diameter_eap_request_envelope(
            &decode(&request_wire),
            typed_context(UnknownIePolicy::Preserve),
        )
        .expect("GTPv2 request envelope");
        let rebuilt =
            swm::build_swm_diameter_eap_answer_for(&request, &parsed, EncodeContext::default())
                .expect("canonical subscriber answer");
        let wire = encode_message(&rebuilt);
        let message = decode(&wire);
        assert_eq!(
            find_avp(&message, swm::AVP_APN_OI_REPLACEMENT)
                .header
                .flags
                .bits(),
            AvpFlags::VENDOR | AvpFlags::MANDATORY
        );
        assert_eq!(
            find_avp(&message, swm::AVP_SUBSCRIPTION_ID)
                .header
                .flags
                .bits(),
            AvpFlags::MANDATORY
        );
        assert_eq!(
            find_avp(&message, swm::AVP_3GPP_CHARGING_CHARACTERISTICS)
                .header
                .flags
                .bits(),
            AvpFlags::VENDOR
        );
        assert_eq!(
            find_avp(&message, swm::AVP_MPS_PRIORITY)
                .header
                .flags
                .bits(),
            AvpFlags::VENDOR
        );
    }
}

#[test]
fn top_level_subscriber_codes_reject_wrong_vendor_under_every_unknown_policy() {
    let vendor_specific = [
        (
            swm::AVP_APN_OI_REPLACEMENT,
            AvpFlags::MANDATORY,
            APN_OI.as_bytes().to_vec(),
        ),
        (swm::AVP_3GPP_CHARGING_CHARACTERISTICS, 0, b"A1B2".to_vec()),
        (swm::AVP_UE_USAGE_TYPE, 0, 1_u32.to_be_bytes().to_vec()),
        (
            swm::AVP_CORE_NETWORK_RESTRICTIONS,
            0,
            2_u32.to_be_bytes().to_vec(),
        ),
        (swm::AVP_MPS_PRIORITY, 0, 2_u32.to_be_bytes().to_vec()),
    ];
    for (code, non_vendor_flags, value) in vendor_specific {
        for extra in [
            raw_avp(code, non_vendor_flags, None, &value),
            raw_avp(
                code,
                AvpFlags::VENDOR | non_vendor_flags,
                Some(VendorId::new(0)),
                &value,
            ),
            raw_avp(
                code,
                AvpFlags::VENDOR | non_vendor_flags,
                Some(VendorId::new(42_424)),
                &value,
            ),
        ] {
            for policy in [
                UnknownIePolicy::Preserve,
                UnknownIePolicy::Drop,
                UnknownIePolicy::Reject,
            ] {
                assert!(parse_with_policy(
                    &answer_wire(
                        base::RESULT_CODE_DIAMETER_SUCCESS,
                        std::slice::from_ref(&extra),
                    ),
                    policy,
                )
                .is_err());
            }
        }
    }

    let subscription = subscription_id_value(
        0,
        E164.as_bytes(),
        AvpFlags::MANDATORY,
        AvpFlags::MANDATORY,
        &[],
    );
    for vendor_id in [VendorId::new(0), VendorId::new(42_424)] {
        let extra = raw_avp(
            swm::AVP_SUBSCRIPTION_ID,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(vendor_id),
            &subscription,
        );
        for policy in [
            UnknownIePolicy::Preserve,
            UnknownIePolicy::Drop,
            UnknownIePolicy::Reject,
        ] {
            assert!(parse_with_policy(
                &answer_wire(
                    base::RESULT_CODE_DIAMETER_SUCCESS,
                    std::slice::from_ref(&extra),
                ),
                policy,
            )
            .is_err());
        }
    }
}

#[test]
fn scalar_width_range_cardinality_and_flags_fail_closed() {
    let invalid = [
        raw_avp(
            swm::AVP_UE_USAGE_TYPE,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            &256_u32.to_be_bytes(),
        ),
        raw_avp(
            swm::AVP_UE_USAGE_TYPE,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            &[0, 1, 2],
        ),
        raw_avp(
            swm::AVP_APN_OI_REPLACEMENT,
            AvpFlags::VENDOR | AvpFlags::MANDATORY | AvpFlags::PROTECTED,
            Some(VENDOR_ID_3GPP),
            APN_OI.as_bytes(),
        ),
        raw_avp(
            swm::AVP_3GPP_CHARGING_CHARACTERISTICS,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            b"xyz!",
        ),
        raw_avp(
            swm::AVP_UE_USAGE_TYPE,
            AvpFlags::VENDOR | AvpFlags::PROTECTED,
            Some(VENDOR_ID_3GPP),
            &1_u32.to_be_bytes(),
        ),
        raw_avp(
            swm::AVP_CORE_NETWORK_RESTRICTIONS,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            &[0, 1, 2],
        ),
        raw_avp(
            swm::AVP_CORE_NETWORK_RESTRICTIONS,
            AvpFlags::VENDOR | AvpFlags::PROTECTED,
            Some(VENDOR_ID_3GPP),
            &2_u32.to_be_bytes(),
        ),
        raw_avp(
            swm::AVP_MPS_PRIORITY,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            &[0, 1, 2],
        ),
        raw_avp(
            swm::AVP_MPS_PRIORITY,
            AvpFlags::VENDOR | AvpFlags::PROTECTED,
            Some(VENDOR_ID_3GPP),
            &2_u32.to_be_bytes(),
        ),
        raw_avp(
            swm::AVP_3GPP_CHARGING_CHARACTERISTICS,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            b"001",
        ),
    ];
    for extra in invalid {
        assert!(parse(&answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &[extra])).is_err());
    }

    let duplicate = raw_avp(
        swm::AVP_MPS_PRIORITY,
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
        &2_u32.to_be_bytes(),
    );
    assert!(parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &[duplicate.clone(), duplicate],
    ))
    .is_err());
}

#[test]
fn mps_priority_presence_requires_the_eps_subscription_bit() {
    for bits in [0_u32, 1, 4, 5, 0x8000_0000] {
        let extra = raw_avp(
            swm::AVP_MPS_PRIORITY,
            AvpFlags::VENDOR,
            Some(VENDOR_ID_3GPP),
            &bits.to_be_bytes(),
        );
        assert!(parse(&answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &[extra])).is_err());
    }

    for priority in [
        SwmMpsPriority::none(),
        SwmMpsPriority::none().with_cs_priority(true),
        SwmMpsPriority::none().with_messaging_priority(true),
    ] {
        let answer =
            successful_answer(SwmDeaSubscriberAuthorization::new().with_mps_priority(priority));
        assert!(swm::build_swm_diameter_eap_answer(
            &answer,
            HOP_BY_HOP,
            END_TO_END,
            EncodeContext::default(),
        )
        .is_err());
    }

    let extra = raw_avp(
        swm::AVP_MPS_PRIORITY,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(VENDOR_ID_3GPP),
        &0x8000_0002_u32.to_be_bytes(),
    );
    let parsed = parse(&answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &[extra]))
        .expect("MPS-EPS-Priority authorizes a present MPS value");
    assert!(parsed
        .subscriber_authorization
        .mps_priority()
        .expect("MPS priority")
        .has_eps_priority());
    let rebuilt = swm::build_swm_diameter_eap_answer(
        &parsed,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .expect("valid MPS subscription fact re-encodes");
    let rebuilt_wire = encode_message(&rebuilt);
    let rebuilt_message = decode(&rebuilt_wire);
    assert_eq!(
        find_avp(&rebuilt_message, swm::AVP_MPS_PRIORITY).value,
        2_u32.to_be_bytes()
    );
}

#[test]
fn non_success_dea_can_carry_non_result_conditioned_subscriber_facts() {
    let extra = raw_avp(
        swm::AVP_MPS_PRIORITY,
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
        &2_u32.to_be_bytes(),
    );
    let parsed = parse(&answer_wire(5003, &[extra]))
        .expect("standalone parser retains syntactically valid subscriber facts");
    let rebuilt = swm::build_swm_diameter_eap_answer(
        &parsed,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .expect("MPS-Priority is not success-conditioned by TS 29.273");
    let reparsed = parse(&encode_message(&rebuilt)).expect("rebuilt non-success DEA reparses");
    assert!(reparsed
        .subscriber_authorization
        .mps_priority()
        .expect("retained MPS priority")
        .has_eps_priority());
}

#[test]
fn apn_oi_requires_correlated_non_emergency_network_mobility() {
    let apn_wire = raw_avp(
        swm::AVP_APN_OI_REPLACEMENT,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(VENDOR_ID_3GPP),
        APN_OI.as_bytes(),
    );
    assert!(parse(&answer_wire(5003, &[apn_wire])).is_err());

    let authorization = SwmDeaSubscriberAuthorization::new()
        .with_apn_oi_replacement(SwmApnOiReplacement::new(APN_OI).expect("valid synthetic APN-OI"));
    let mut answer = successful_answer(authorization);
    assert!(swm::build_swm_diameter_eap_answer(
        &answer,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .is_err());

    let normal_wire = request_wire(false, None);
    let normal = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&normal_wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("ordinary DER envelope");
    answer.result = SwmDiameterResult::Base(5003);
    answer.eap_payload = None;
    assert!(
        swm::build_swm_diameter_eap_answer_for(&normal, &answer, EncodeContext::default(),)
            .is_err()
    );
    answer.result = SwmDiameterResult::Base(base::RESULT_CODE_DIAMETER_SUCCESS);
    answer.eap_payload = Some(vec![3, 9, 0, 4].into());
    assert!(
        swm::build_swm_diameter_eap_answer_for(&normal, &answer, EncodeContext::default(),)
            .is_err()
    );

    let emergency_wire = request_wire(true, None);
    let emergency = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&emergency_wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("emergency DER envelope");
    assert!(
        swm::build_swm_diameter_eap_answer_for(&emergency, &answer, EncodeContext::default(),)
            .is_err()
    );

    let mobility_wire = request_wire(false, Some(SwmMip6FeatureVector::GTPV2_SUPPORTED));
    let mobility = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&mobility_wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("mobility DER envelope");
    answer.mip6_feature_vector = Some(SwmMip6FeatureVector::from_bits_retain(
        SwmMip6FeatureVector::ASSIGN_LOCAL_IP,
    ));
    assert!(
        swm::build_swm_diameter_eap_answer_for(&mobility, &answer, EncodeContext::default(),)
            .is_err()
    );
    answer.mip6_feature_vector = Some(SwmMip6FeatureVector::from_bits_retain(
        SwmMip6FeatureVector::GTPV2_SUPPORTED,
    ));
    assert!(
        swm::build_swm_diameter_eap_answer_for(&mobility, &answer, EncodeContext::default(),)
            .is_ok()
    );

    let pmip_wire = request_wire(false, Some(SwmMip6FeatureVector::PMIP6_SUPPORTED));
    let pmip = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&pmip_wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("PMIPv6 DER envelope");
    assert!(
        swm::build_swm_diameter_eap_answer_for(&pmip, &answer, EncodeContext::default(),).is_ok()
    );
}

#[test]
fn local_mobility_provenance_is_explicit_replay_safe_and_aaa_precedent() {
    let normal_wire = request_wire(false, None);
    let normal = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&normal_wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("ordinary DER envelope");
    assert_eq!(normal.locally_configured_mobility_mode(), None);
    let default_outbound = swm::SwmDiameterEapRequestEnvelope::for_outbound(
        normal.request().clone(),
        normal.transaction(),
    );
    assert_eq!(default_outbound.locally_configured_mobility_mode(), None);
    let absent_exchange = normal
        .clone()
        .correlate_answer(SwmDiameterEapAnswerEnvelope::for_outbound(
            successful_answer(SwmDeaSubscriberAuthorization::new()),
            normal.transaction(),
        ))
        .expect("ordinary exchange without mobility provenance correlates");
    assert_eq!(absent_exchange.effective_mobility_mode(), None);
    assert_eq!(absent_exchange.mobility_mode_source(), None);

    let local_nbm = normal
        .clone()
        .with_locally_configured_mobility_mode(SwmLocallyConfiguredMobilityMode::NetworkBased);
    assert!(!normal.same_replay_payload(&local_nbm));
    let local_ip = normal.clone().with_locally_configured_mobility_mode(
        SwmLocallyConfiguredMobilityMode::LocalIpAddressAssignment,
    );
    assert!(!local_nbm.same_replay_payload(&local_ip));

    let mut retry = local_nbm.clone();
    retry.mark_for_failover_retransmission(
        HOP_BY_HOP ^ 0x0101_0101,
        SwmExpectedAnswerPeer::routed(RETRY_CONNECTION),
    );
    assert_eq!(
        retry.locally_configured_mobility_mode(),
        Some(SwmLocallyConfiguredMobilityMode::NetworkBased)
    );
    assert!(local_nbm.same_replay_payload(&retry));

    let authorization = SwmDeaSubscriberAuthorization::new()
        .with_apn_oi_replacement(SwmApnOiReplacement::new(APN_OI).expect("valid synthetic APN-OI"));
    let local_answer = successful_answer(authorization.clone());
    assert!(swm::build_swm_diameter_eap_answer_for(
        &normal,
        &local_answer,
        EncodeContext::default(),
    )
    .is_err());
    assert!(swm::build_swm_diameter_eap_answer_for(
        &local_ip,
        &local_answer,
        EncodeContext::default(),
    )
    .is_err());
    assert!(swm::build_swm_diameter_eap_answer_for(
        &local_nbm,
        &local_answer,
        EncodeContext::default(),
    )
    .is_ok());
    let local_exchange = local_nbm
        .clone()
        .correlate_answer(SwmDiameterEapAnswerEnvelope::for_outbound(
            local_answer,
            local_nbm.transaction(),
        ))
        .expect("trusted local NBM proves the APN condition when DEA omits mobility");
    assert_eq!(
        local_exchange.mobility_mode_source(),
        Some(SwmConditionalValueSource::LocallyConfigured)
    );
    assert_eq!(
        local_exchange.effective_mobility_mode(),
        Some(SwmLocallyConfiguredMobilityMode::NetworkBased)
    );
    assert_eq!(
        local_exchange.local_mobility_mode_input(),
        Some(SwmLocallyConfiguredMobilityMode::NetworkBased)
    );

    let offered_wire = request_wire(false, Some(SwmMip6FeatureVector::GTPV2_SUPPORTED));
    let offered = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&offered_wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("NBM DER envelope")
    .with_locally_configured_mobility_mode(SwmLocallyConfiguredMobilityMode::NetworkBased);
    let mut aaa_answer = successful_answer(authorization.clone());
    aaa_answer.mip6_feature_vector = Some(SwmMip6FeatureVector::from_bits_retain(
        SwmMip6FeatureVector::PMIP6_SUPPORTED,
    ));
    let aaa_exchange = offered
        .clone()
        .correlate_answer(SwmDiameterEapAnswerEnvelope::for_outbound(
            aaa_answer,
            offered.transaction(),
        ))
        .expect("explicit collective NBM selection takes precedence");
    assert_eq!(
        aaa_exchange.mobility_mode_source(),
        Some(SwmConditionalValueSource::AaaDerived)
    );
    assert_eq!(
        aaa_exchange.effective_mobility_mode(),
        Some(SwmLocallyConfiguredMobilityMode::NetworkBased)
    );
    assert_eq!(
        aaa_exchange.local_mobility_mode_input(),
        Some(SwmLocallyConfiguredMobilityMode::NetworkBased)
    );
    assert!(aaa_exchange
        .answer()
        .mip6_feature_vector
        .is_some_and(|value| value.contains(SwmMip6FeatureVector::PMIP6_SUPPORTED)));

    let mut local_assignment = successful_answer(SwmDeaSubscriberAuthorization::new());
    local_assignment.mip6_feature_vector = Some(SwmMip6FeatureVector::from_bits_retain(
        SwmMip6FeatureVector::ASSIGN_LOCAL_IP,
    ));
    let local_assignment_exchange = offered
        .clone()
        .correlate_answer(SwmDiameterEapAnswerEnvelope::for_outbound(
            local_assignment.clone(),
            offered.transaction(),
        ))
        .expect("explicit AAA local-address selection correlates");
    assert_eq!(
        local_assignment_exchange.mobility_mode_source(),
        Some(SwmConditionalValueSource::AaaDerived)
    );
    assert_eq!(
        local_assignment_exchange.effective_mobility_mode(),
        Some(SwmLocallyConfiguredMobilityMode::LocalIpAddressAssignment)
    );
    local_assignment.subscriber_authorization = authorization;
    assert!(swm::build_swm_diameter_eap_answer_for(
        &offered,
        &local_assignment,
        EncodeContext::default(),
    )
    .is_err());

    let other_offer_wire = request_wire(
        false,
        Some(SwmMip6FeatureVector::MIP6_INTEGRATED | SwmMip6FeatureVector::GTPV2_SUPPORTED),
    );
    let other_offer = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&other_offer_wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("other-feature DER envelope")
    .with_locally_configured_mobility_mode(SwmLocallyConfiguredMobilityMode::NetworkBased);
    let mut other_answer = successful_answer(SwmDeaSubscriberAuthorization::new());
    other_answer.mip6_feature_vector = Some(SwmMip6FeatureVector::from_bits_retain(
        SwmMip6FeatureVector::MIP6_INTEGRATED,
    ));
    let other_exchange = other_offer
        .clone()
        .correlate_answer(SwmDiameterEapAnswerEnvelope::for_outbound(
            other_answer,
            other_offer.transaction(),
        ))
        .expect("explicit non-mode feature selection correlates without local fallback");
    assert_eq!(other_exchange.effective_mobility_mode(), None);
    assert_eq!(other_exchange.mobility_mode_source(), None);
    assert_eq!(
        other_exchange.local_mobility_mode_input(),
        Some(SwmLocallyConfiguredMobilityMode::NetworkBased)
    );
}

#[test]
fn answer_only_subscriber_values_are_rejected_in_der() {
    let mut wire = request_wire(false, None);
    let extra = raw_avp(
        swm::AVP_MPS_PRIORITY,
        AvpFlags::VENDOR,
        Some(VENDOR_ID_3GPP),
        &2_u32.to_be_bytes(),
    );
    let message_len = wire.len() + extra.len();
    wire.extend_from_slice(&extra);
    wire[1..4].copy_from_slice(&u32::try_from(message_len).expect("length").to_be_bytes()[1..]);
    assert!(swm::parse_swm_diameter_eap_request(
        &decode(&wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .is_err());
}

#[test]
fn diagnostics_redact_every_subscriber_classification() {
    let apn =
        SwmApnOiReplacement::new("sentinel.private.mnc001.mcc001.gprs").expect("valid APN-OI");
    let e164 = SwmE164Number::new("15559876543").expect("valid E.164");
    let subscription = SwmSubscriptionId::e164(e164.clone());
    let charging = SwmChargingCharacteristics::from_octets([0xde, 0xad]);
    let usage = SwmUeUsageType::new(231);
    let restrictions = SwmCoreNetworkRestrictions::five_gc_not_allowed();
    let mps = SwmMpsPriority::none().with_eps_priority(true);
    let bundle = SwmDeaSubscriberAuthorization::new()
        .with_apn_oi_replacement(apn.clone())
        .with_subscription_id(subscription.clone())
        .with_charging_characteristics(charging)
        .with_ue_usage_type(usage)
        .with_core_network_restrictions(restrictions)
        .with_mps_priority(mps);
    assert_eq!(
        format!("{charging:?}"),
        "SwmChargingCharacteristics(<redacted>)"
    );
    assert_eq!(format!("{usage:?}"), "SwmUeUsageType(<redacted>)");
    assert_eq!(
        format!("{restrictions:?}"),
        "SwmCoreNetworkRestrictions(<redacted>)"
    );
    assert_eq!(format!("{mps:?}"), "SwmMpsPriority(<redacted>)");

    for rendered in [
        format!("{apn:?}"),
        format!("{e164:?}"),
        format!("{subscription:?}"),
        format!("{charging:?}"),
        format!("{usage:?}"),
        format!("{restrictions:?}"),
        format!("{mps:?}"),
        format!("{bundle:?}"),
    ] {
        assert!(!rendered.contains("sentinel"));
        assert!(!rendered.contains("15559876543"));
        assert!(!rendered.contains("231"));
        assert!(!rendered.to_ascii_lowercase().contains("dead"));
        assert!(!rendered.contains("222"));
        assert!(!rendered.contains("173"));
    }
}

#[test]
fn dictionary_declares_command_roles_and_grouped_children() {
    let dictionary = swm::dictionary();
    let subscription = dictionary
        .find_avp(opc_proto_diameter::dictionary::AvpKey::ietf(
            swm::AVP_SUBSCRIPTION_ID,
        ))
        .expect("Subscription-Id definition");
    assert_eq!(subscription.grouped_avp_rules().len(), 2);
    assert_eq!(
        subscription.flags().mandatory(),
        opc_proto_diameter::dictionary::FlagRequirement::MayBeSet
    );
    assert_eq!(
        subscription.flags().protected(),
        opc_proto_diameter::dictionary::FlagRequirement::MayBeSet
    );
    for code in [
        swm::AVP_APN_OI_REPLACEMENT,
        swm::AVP_3GPP_CHARGING_CHARACTERISTICS,
        swm::AVP_UE_USAGE_TYPE,
        swm::AVP_CORE_NETWORK_RESTRICTIONS,
        swm::AVP_MPS_PRIORITY,
    ] {
        let definition = dictionary
            .find_avp(opc_proto_diameter::dictionary::AvpKey::vendor(
                code,
                VENDOR_ID_3GPP,
            ))
            .expect("subscriber scalar definition");
        assert_eq!(
            definition.flags().mandatory(),
            opc_proto_diameter::dictionary::FlagRequirement::MayBeSet
        );
    }
    let answer = dictionary
        .find_command(
            swm::APPLICATION_ID,
            swm::COMMAND_DIAMETER_EAP,
            opc_proto_diameter::dictionary::CommandKind::Answer,
        )
        .expect("DEA command definition");
    assert!(answer
        .find_avp_rule(opc_proto_diameter::dictionary::AvpKey::vendor(
            swm::AVP_MPS_PRIORITY,
            VENDOR_ID_3GPP,
        ))
        .is_some());
    let request = dictionary
        .find_command(
            swm::APPLICATION_ID,
            swm::COMMAND_DIAMETER_EAP,
            opc_proto_diameter::dictionary::CommandKind::Request,
        )
        .expect("DER command definition");
    assert!(request
        .find_avp_rule(opc_proto_diameter::dictionary::AvpKey::vendor(
            swm::AVP_MPS_PRIORITY,
            VENDOR_ID_3GPP,
        ))
        .is_some_and(|rule| {
            rule.cardinality() == opc_proto_diameter::dictionary::AvpCardinality::Forbidden
        }));
}
