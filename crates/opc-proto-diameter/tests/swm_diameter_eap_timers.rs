#![cfg(feature = "app-swm")]

use bytes::{Bytes, BytesMut};
use opc_proto_diameter::apps::swm::{
    self, AuthRequestType, SwmDiameterEapAnswer, SwmDiameterResult, SwmReAuthRequestType,
    SwmSessionTimeout,
};
use opc_proto_diameter::dictionary::{AvpCardinality, AvpKey};
use opc_proto_diameter::{
    base, AvpCode, AvpFlags, CommandFlags, DictionarySet, Header, Message, OwnedMessage, VendorId,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DuplicateIePolicy, Encode, EncodeContext,
    UnknownIePolicy,
};

const HOP_BY_HOP: u32 = 0x0102_0304;
const END_TO_END: u32 = 0x1122_3344;
const SESSION_ID: &[u8] = b"session;synthetic;dea-timers";
const AAA_HOST: &[u8] = b"aaa.synthetic.invalid";
const AAA_REALM: &[u8] = b"home.synthetic.invalid";

static SWM_DICTIONARIES: DictionarySet<'static> =
    DictionarySet::new(&[base::dictionary(), swm::dictionary()]);
static SWM_PROJECTED_DICTIONARIES: DictionarySet<'static> =
    DictionarySet::new(&[base::dictionary(), swm::projected_profile_dictionary()]);

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

fn answer_avps(result_code: u32, extras: &[Vec<u8>]) -> Vec<u8> {
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
        raw_avp(base::AVP_ORIGIN_REALM, AvpFlags::MANDATORY, None, AAA_REALM),
    ] {
        raw.extend_from_slice(&avp);
    }
    for extra in extras {
        raw.extend_from_slice(extra);
    }
    if result_code / 1_000 == 2 {
        raw.extend_from_slice(&raw_avp(
            swm::AVP_EAP_PAYLOAD,
            AvpFlags::MANDATORY,
            None,
            &[3, 9, 0, 4],
        ));
    }
    raw
}

fn answer_wire(result_code: u32, extras: &[Vec<u8>]) -> Vec<u8> {
    let message = OwnedMessage {
        header: Header::new(
            CommandFlags::answer(true, result_code / 1_000 == 3),
            swm::COMMAND_DIAMETER_EAP,
            swm::APPLICATION_ID,
            HOP_BY_HOP,
            END_TO_END,
        ),
        raw_avps: Bytes::from(answer_avps(result_code, extras)),
    };
    encode(&message)
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

fn encode(message: &OwnedMessage) -> Vec<u8> {
    let mut wire = BytesMut::new();
    message
        .encode(&mut wire, EncodeContext::default())
        .expect("synthetic Diameter message encodes");
    wire.to_vec()
}

fn timer_avp(code: AvpCode, value: u32) -> Vec<u8> {
    raw_avp(code, AvpFlags::MANDATORY, None, &value.to_be_bytes())
}

fn successful_answer() -> SwmDiameterEapAnswer {
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
        origin_realm: String::from_utf8(AAA_REALM.to_vec())
            .expect("synthetic Origin-Realm is UTF-8")
            .into(),
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
fn absent_timer_fields_preserve_existing_success_bytes() {
    let wire = answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &[]);
    let parsed = parse(&wire).expect("legacy DEA without timer context");
    assert_eq!(parsed.session_timeout, None);
    assert_eq!(parsed.authorization_lifetime, None);
    assert_eq!(parsed.auth_grace_period, None);
    assert_eq!(parsed.re_auth_request_type, None);
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_answer(
                &parsed,
                HOP_BY_HOP,
                END_TO_END,
                EncodeContext::default(),
            )
            .expect("legacy answer remains encodable"),
        ),
        wire,
    );
}

#[test]
fn independent_wire_fixture_round_trips_complete_timer_context() {
    let extras = [
        timer_avp(base::AVP_SESSION_TIMEOUT, 900),
        timer_avp(base::AVP_RE_AUTH_REQUEST_TYPE, 0),
        timer_avp(base::AVP_AUTHORIZATION_LIFETIME, 600),
        timer_avp(base::AVP_AUTH_GRACE_PERIOD, 30),
    ];
    let wire = answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &extras);
    let parsed = parse(&wire).expect("standards-authored timer fixture");

    assert_eq!(
        parsed.session_timeout.map(SwmSessionTimeout::seconds),
        Some(900)
    );
    assert_eq!(parsed.authorization_lifetime, Some(600));
    assert_eq!(parsed.auth_grace_period, Some(30));
    assert_eq!(
        parsed.re_auth_request_type,
        Some(SwmReAuthRequestType::AuthorizeOnly)
    );
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_answer(
                &parsed,
                HOP_BY_HOP,
                END_TO_END,
                EncodeContext::default(),
            )
            .expect("timer answer rebuilds"),
        ),
        wire,
    );
}

#[test]
fn explicit_zero_timeout_is_unlimited_and_not_smaller_than_lifetime() {
    let extras = [
        timer_avp(base::AVP_SESSION_TIMEOUT, 0),
        timer_avp(base::AVP_RE_AUTH_REQUEST_TYPE, 1),
        timer_avp(base::AVP_AUTHORIZATION_LIFETIME, u32::MAX),
    ];
    let wire = answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &extras);
    let parsed = parse(&wire).expect("zero timeout means unlimited");
    assert!(parsed
        .session_timeout
        .expect("typed timeout")
        .is_unlimited());
    assert_eq!(
        parsed.re_auth_request_type,
        Some(SwmReAuthRequestType::AuthorizeAuthenticate)
    );
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_answer(
                &parsed,
                HOP_BY_HOP,
                END_TO_END,
                EncodeContext::default(),
            )
            .expect("explicit zero and re-auth value one rebuild"),
        ),
        wire,
    );

    let zero_lifetime = [timer_avp(base::AVP_AUTHORIZATION_LIFETIME, 0)];
    let parsed = parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &zero_lifetime,
    ))
    .expect("zero authorization lifetime does not require re-auth type");
    assert_eq!(parsed.authorization_lifetime, Some(0));
}

#[test]
fn timer_unsigned32_boundaries_round_trip_exactly() {
    for extra in [
        timer_avp(base::AVP_SESSION_TIMEOUT, u32::MAX),
        timer_avp(base::AVP_AUTH_GRACE_PERIOD, 0),
        timer_avp(base::AVP_AUTH_GRACE_PERIOD, u32::MAX),
    ] {
        let wire = answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &[extra]);
        let parsed = parse(&wire).expect("Unsigned32 timer boundary parses");
        assert_eq!(
            encode(
                &swm::build_swm_diameter_eap_answer(
                    &parsed,
                    HOP_BY_HOP,
                    END_TO_END,
                    EncodeContext::default(),
                )
                .expect("Unsigned32 timer boundary rebuilds"),
            ),
            wire,
        );
    }
}

#[test]
fn timer_cross_field_constraints_fail_closed_for_parse_and_build() {
    let positive_without_reauth = [
        timer_avp(base::AVP_SESSION_TIMEOUT, 900),
        timer_avp(base::AVP_AUTHORIZATION_LIFETIME, 600),
    ];
    assert!(parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &positive_without_reauth,
    ))
    .is_err());

    let timeout_too_short = [
        timer_avp(base::AVP_SESSION_TIMEOUT, 599),
        timer_avp(base::AVP_RE_AUTH_REQUEST_TYPE, 0),
        timer_avp(base::AVP_AUTHORIZATION_LIFETIME, 600),
    ];
    assert!(parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &timeout_too_short,
    ))
    .is_err());

    let mut answer = successful_answer();
    answer.session_timeout = Some(SwmSessionTimeout::from_seconds(599));
    answer.authorization_lifetime = Some(600);
    answer.re_auth_request_type = Some(SwmReAuthRequestType::AuthorizeOnly);
    assert!(swm::build_swm_diameter_eap_answer(
        &answer,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .is_err());

    answer.session_timeout = Some(SwmSessionTimeout::from_seconds(900));
    answer.re_auth_request_type = None;
    assert!(swm::build_swm_diameter_eap_answer(
        &answer,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .is_err());
}

#[test]
fn session_timeout_is_restricted_to_exact_base_diameter_success() {
    let timeout = [timer_avp(base::AVP_SESSION_TIMEOUT, 60)];
    for result_code in [1_001, 2_002, 3_001, 4_001, 5_001] {
        assert!(
            parse(&answer_wire(result_code, &timeout)).is_err(),
            "Session-Timeout was accepted for result code {result_code}",
        );
    }

    let mut answer = successful_answer();
    answer.session_timeout = Some(SwmSessionTimeout::from_seconds(60));
    for result in [
        SwmDiameterResult::Base(1_001),
        SwmDiameterResult::Base(2_002),
        SwmDiameterResult::Base(3_001),
        SwmDiameterResult::Base(4_001),
        SwmDiameterResult::Base(5_001),
        SwmDiameterResult::Experimental {
            vendor_id: VendorId::new(10_415),
            code: base::RESULT_CODE_DIAMETER_SUCCESS,
        },
    ] {
        answer.result = result;
        assert!(
            swm::build_swm_diameter_eap_answer(
                &answer,
                HOP_BY_HOP,
                END_TO_END,
                EncodeContext::default(),
            )
            .is_err(),
            "Session-Timeout build accepted a non-success result",
        );
    }
}

#[test]
fn timer_avps_reject_wrong_flags_vendor_width_and_duplicates() {
    for code in [
        base::AVP_SESSION_TIMEOUT,
        base::AVP_AUTHORIZATION_LIFETIME,
        base::AVP_AUTH_GRACE_PERIOD,
        base::AVP_RE_AUTH_REQUEST_TYPE,
    ] {
        for malformed in [
            raw_avp(code, 0, None, &0_u32.to_be_bytes()),
            raw_avp(
                code,
                AvpFlags::MANDATORY | AvpFlags::PROTECTED,
                None,
                &0_u32.to_be_bytes(),
            ),
            raw_avp(
                code,
                AvpFlags::VENDOR | AvpFlags::MANDATORY,
                Some(VendorId::new(10_415)),
                &0_u32.to_be_bytes(),
            ),
            raw_avp(code, AvpFlags::MANDATORY, None, &[0, 0, 0]),
        ] {
            assert!(
                parse(&answer_wire(
                    base::RESULT_CODE_DIAMETER_SUCCESS,
                    &[malformed]
                ))
                .is_err(),
                "malformed timer code {} was accepted",
                code.get(),
            );
        }

        let duplicated = [timer_avp(code, 0), timer_avp(code, 0)];
        assert!(
            parse(&answer_wire(
                base::RESULT_CODE_DIAMETER_SUCCESS,
                &duplicated
            ))
            .is_err(),
            "duplicate timer code {} was accepted",
            code.get(),
        );
    }
}

#[test]
fn invalid_re_auth_value_and_auth_session_state_fail_closed() {
    let invalid_reauth = [timer_avp(base::AVP_RE_AUTH_REQUEST_TYPE, 2)];
    assert!(parse(&answer_wire(
        base::RESULT_CODE_DIAMETER_SUCCESS,
        &invalid_reauth,
    ))
    .is_err());

    for policy in [
        UnknownIePolicy::Preserve,
        UnknownIePolicy::Drop,
        UnknownIePolicy::Reject,
    ] {
        for flags in [0, AvpFlags::MANDATORY] {
            let forbidden = [raw_avp(
                base::AVP_AUTH_SESSION_STATE,
                flags,
                None,
                &1_u32.to_be_bytes(),
            )];
            assert!(
                parse_with_policy(
                    &answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &forbidden),
                    policy,
                )
                .is_err(),
                "exact IETF Auth-Session-State survived policy {policy:?} and flags {flags:#x}",
            );
        }
    }
}

#[test]
fn timer_code_collisions_remain_distinct_vendor_avps() {
    let vendor_id = VendorId::new(10_415);
    for code in [base::AVP_AUTH_SESSION_STATE, base::AVP_SESSION_TIMEOUT] {
        let retained = raw_avp(code, AvpFlags::VENDOR, Some(vendor_id), &[1, 2, 3, 4]);
        let wire = answer_wire(
            base::RESULT_CODE_DIAMETER_SUCCESS,
            std::slice::from_ref(&retained),
        );

        let preserved = parse_with_policy(&wire, UnknownIePolicy::Preserve)
            .expect("non-mandatory vendor collision is preservable");
        assert_eq!(preserved.extensions.len(), 1);
        let metadata = preserved
            .extensions
            .metadata()
            .next()
            .expect("one retained vendor AVP");
        assert_eq!(metadata.code(), code);
        assert_eq!(metadata.vendor_id(), Some(vendor_id));
        assert_eq!(metadata.flags().bits(), AvpFlags::VENDOR);
        assert_eq!(metadata.value_len(), 4);
        let rebuilt = encode(
            &swm::build_swm_diameter_eap_answer(
                &preserved,
                HOP_BY_HOP,
                END_TO_END,
                EncodeContext::default(),
            )
            .expect("preserved vendor collision rebuilds"),
        );
        assert!(rebuilt.ends_with(&retained));

        let dropped = parse_with_policy(&wire, UnknownIePolicy::Drop)
            .expect("non-mandatory vendor collision is droppable");
        assert!(dropped.extensions.is_empty());
        assert!(parse_with_policy(&wire, UnknownIePolicy::Reject).is_err());

        let mandatory = raw_avp(
            code,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(vendor_id),
            &[1, 2, 3, 4],
        );
        assert!(parse_with_policy(
            &answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &[mandatory]),
            UnknownIePolicy::Preserve,
        )
        .is_err());

        let zero_vendor = raw_avp(
            code,
            AvpFlags::VENDOR,
            Some(VendorId::new(0)),
            &[1, 2, 3, 4],
        );
        assert!(parse_with_policy(
            &answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &[zero_vendor]),
            UnknownIePolicy::Preserve,
        )
        .is_err());
    }
}

#[test]
fn timer_dictionary_rules_match_typed_cardinality_and_swm_omission() {
    for command in [
        &swm::COMMAND_DIAMETER_EAP_ANSWER,
        &swm::COMMAND_DIAMETER_EAP_ANSWER_PROJECTED_PROFILE,
    ] {
        for code in [
            base::AVP_SESSION_TIMEOUT,
            base::AVP_AUTHORIZATION_LIFETIME,
            base::AVP_AUTH_GRACE_PERIOD,
            base::AVP_RE_AUTH_REQUEST_TYPE,
        ] {
            assert_eq!(
                command
                    .find_avp_rule(AvpKey::ietf(code))
                    .expect("timer rule")
                    .cardinality(),
                AvpCardinality::ZeroOrOne,
            );
        }
        assert_eq!(
            command
                .find_avp_rule(AvpKey::ietf(base::AVP_AUTH_SESSION_STATE))
                .expect("Auth-Session-State omission rule")
                .cardinality(),
            AvpCardinality::Forbidden,
        );
    }

    for dictionaries in [SWM_DICTIONARIES, SWM_PROJECTED_DICTIONARIES] {
        for flags in [0, AvpFlags::MANDATORY] {
            let forbidden = raw_avp(
                base::AVP_AUTH_SESSION_STATE,
                flags,
                None,
                &1_u32.to_be_bytes(),
            );
            let wire = answer_wire(base::RESULT_CODE_DIAMETER_SUCCESS, &[forbidden]);
            assert!(
                Message::decode_with_dictionary(
                    &wire,
                    typed_context(UnknownIePolicy::Preserve),
                    dictionaries,
                )
                .is_err(),
                "dictionary pre-scan accepted forbidden Auth-Session-State flags {flags:#x}",
            );
        }
    }
}

#[test]
fn timer_diagnostics_are_redaction_safe() {
    let timeout = SwmSessionTimeout::from_seconds(4_294_967_294);
    assert_eq!(format!("{timeout:?}"), "SwmSessionTimeout(<redacted>)");

    let mut answer = successful_answer();
    answer.session_timeout = Some(timeout);
    answer.authorization_lifetime = Some(4_294_967_293);
    answer.auth_grace_period = Some(4_294_967_292);
    answer.re_auth_request_type = Some(SwmReAuthRequestType::AuthorizeOnly);
    let diagnostic = format!("{answer:?}");
    assert!(!diagnostic.contains("429496729"));
    assert!(diagnostic.contains("authorization_lifetime_present: true"));
    assert!(diagnostic.contains("auth_grace_period_present: true"));
    assert!(diagnostic.contains("re_auth_request_type_present: true"));
}
