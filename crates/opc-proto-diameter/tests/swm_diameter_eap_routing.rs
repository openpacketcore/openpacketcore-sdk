#![cfg(feature = "app-swm")]

use std::num::NonZeroU64;

use bytes::{Bytes, BytesMut};
use opc_proto_diameter::apps::swm::{
    self, SwmDiameterEapCorrelationError, SwmDiameterEapRequestEnvelope, SwmDiameterEapResponse,
    SwmDiameterRedirect, SwmDiameterRedirectError, SwmDiameterTransaction, SwmExpectedAnswerPeer,
    SwmRedirectHostUsage,
};
use opc_proto_diameter::avp::dictionary::Redacted;
use opc_proto_diameter::dictionary::{AvpCardinality, AvpKey};
use opc_proto_diameter::{
    base, AvpCode, AvpFlags, CommandFlags, CommandKind, DictionarySet, Header, Message,
    OwnedMessage, VendorId,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DuplicateIePolicy, Encode, EncodeContext, UnknownIePolicy,
};

const HOP_BY_HOP: u32 = 0x1020_3040;
const END_TO_END: u32 = 0x5060_7080;
const SESSION_ID: &[u8] = b"session;synthetic;swm-routing";
const EPDG_HOST: &[u8] = b"epdg.synthetic.invalid";
const EPDG_REALM: &[u8] = b"visited.synthetic.invalid";
const AAA_HOST: &[u8] = b"aaa.synthetic.invalid";
const AAA_REALM: &[u8] = b"home.synthetic.invalid";
const AGENT_HOST: &[u8] = b"agent.synthetic.invalid";
const PROXY_HOST: &[u8] = b"proxy.synthetic.invalid";
const PROXY_STATE: &[u8] = b"opaque-proxy-state-sentinel";
const ROUTE_RECORD: &[u8] = b"route.synthetic.invalid";
const REDIRECT_ONE: &str = "aaa://redirect-one.synthetic.invalid";
const REDIRECT_TWO: &str = "aaa://redirect-two.synthetic.invalid;transport=sctp";
const CONNECTION: swm::SwmDiameterConnectionToken =
    swm::SwmDiameterConnectionToken::new(NonZeroU64::MIN);
const OTHER_CONNECTION: swm::SwmDiameterConnectionToken =
    swm::SwmDiameterConnectionToken::new(NonZeroU64::new(2).expect("nonzero constant"));

static BASELINE_DICTIONARIES: DictionarySet<'static> =
    DictionarySet::new(&[base::dictionary(), swm::dictionary()]);
static PROJECTED_DICTIONARIES: DictionarySet<'static> =
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

fn encode(message: &OwnedMessage) -> Vec<u8> {
    let mut wire = BytesMut::new();
    message
        .encode(&mut wire, EncodeContext::default())
        .expect("synthetic Diameter message encodes");
    wire.to_vec()
}

fn message_wire(
    flags: CommandFlags,
    hop_by_hop: u32,
    end_to_end: u32,
    avps: Vec<Vec<u8>>,
) -> Vec<u8> {
    let raw_avps = avps.into_iter().flatten().collect::<Vec<_>>();
    encode(&OwnedMessage {
        header: Header::new(
            flags,
            swm::COMMAND_DIAMETER_EAP,
            swm::APPLICATION_ID,
            hop_by_hop,
            end_to_end,
        ),
        raw_avps: Bytes::from(raw_avps),
    })
}

fn framing_context() -> DecodeContext {
    DecodeContext {
        max_ies: 512,
        max_message_len: 256 * 1024,
        duplicate_ie_policy: DuplicateIePolicy::Last,
        unknown_ie_policy: UnknownIePolicy::Preserve,
        ..DecodeContext::default()
    }
}

fn typed_context(unknown_ie_policy: UnknownIePolicy) -> DecodeContext {
    DecodeContext {
        max_ies: 512,
        max_message_len: 256 * 1024,
        duplicate_ie_policy: DuplicateIePolicy::Last,
        unknown_ie_policy,
        ..DecodeContext::conservative()
    }
}

fn decode(wire: &[u8]) -> Message<'_> {
    let (tail, message) = Message::decode(wire, framing_context()).expect("Diameter framing");
    assert!(tail.is_empty());
    message
}

fn mandatory_avp(code: AvpCode, value: &[u8]) -> Vec<u8> {
    raw_avp(code, AvpFlags::MANDATORY, None, value)
}

fn proxy_info_with(host: &[u8], state: &[u8], extras: &[Vec<u8>]) -> Vec<u8> {
    let mut value = Vec::new();
    value.extend_from_slice(&mandatory_avp(base::AVP_PROXY_HOST, host));
    value.extend_from_slice(&mandatory_avp(base::AVP_PROXY_STATE, state));
    for extra in extras {
        value.extend_from_slice(extra);
    }
    mandatory_avp(base::AVP_PROXY_INFO, &value)
}

fn proxy_info() -> Vec<u8> {
    proxy_info_with(PROXY_HOST, PROXY_STATE, &[])
}

fn redirect_host(value: &str) -> Vec<u8> {
    mandatory_avp(base::AVP_REDIRECT_HOST, value.as_bytes())
}

fn failed_avp(value: &[u8]) -> Vec<u8> {
    mandatory_avp(base::AVP_FAILED_AVP, value)
}

fn experimental_result(vendor_id: u32, result_code: u32) -> Vec<u8> {
    let mut value = mandatory_avp(base::AVP_VENDOR_ID, &vendor_id.to_be_bytes());
    value.extend_from_slice(&mandatory_avp(
        base::AVP_EXPERIMENTAL_RESULT_CODE,
        &result_code.to_be_bytes(),
    ));
    mandatory_avp(base::AVP_EXPERIMENTAL_RESULT, &value)
}

fn generic_avps(
    result_code: Option<u32>,
    session_id: Option<&[u8]>,
    extras: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    let mut avps = Vec::new();
    if let Some(session_id) = session_id {
        avps.push(mandatory_avp(base::AVP_SESSION_ID, session_id));
    }
    avps.push(mandatory_avp(base::AVP_ORIGIN_HOST, AGENT_HOST));
    avps.push(mandatory_avp(base::AVP_ORIGIN_REALM, AAA_REALM));
    if let Some(result_code) = result_code {
        avps.push(mandatory_avp(
            base::AVP_RESULT_CODE,
            &result_code.to_be_bytes(),
        ));
    }
    avps.extend_from_slice(extras);
    avps
}

fn generic_wire(
    result_code: Option<u32>,
    session_id: Option<&[u8]>,
    extras: &[Vec<u8>],
) -> Vec<u8> {
    message_wire(
        CommandFlags::answer(true, true),
        HOP_BY_HOP,
        END_TO_END,
        generic_avps(result_code, session_id, extras),
    )
}

fn request_avps(extras: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut avps = vec![
        mandatory_avp(base::AVP_SESSION_ID, SESSION_ID),
        mandatory_avp(
            base::AVP_AUTH_APPLICATION_ID,
            &swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        mandatory_avp(base::AVP_ORIGIN_HOST, EPDG_HOST),
        mandatory_avp(base::AVP_ORIGIN_REALM, EPDG_REALM),
        mandatory_avp(base::AVP_DESTINATION_REALM, AAA_REALM),
        mandatory_avp(
            swm::AVP_AUTH_REQUEST_TYPE,
            &swm::AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE.to_be_bytes(),
        ),
        mandatory_avp(
            swm::AVP_EAP_PAYLOAD,
            &[0x02, 0x17, 0x00, 0x08, 0x32, 0x01, 0x02, 0x03],
        ),
    ];
    avps.extend_from_slice(extras);
    avps
}

fn request_wire_with_flags(flags: CommandFlags, extras: &[Vec<u8>]) -> Vec<u8> {
    message_wire(flags, HOP_BY_HOP, END_TO_END, request_avps(extras))
}

fn request_wire(extras: &[Vec<u8>]) -> Vec<u8> {
    request_wire_with_flags(CommandFlags::request(true), extras)
}

fn ordinary_answer_avps(
    result: Vec<u8>,
    session_id: &[u8],
    origin_host: &[u8],
    extras: &[Vec<u8>],
) -> Vec<Vec<u8>> {
    let mut avps = vec![
        mandatory_avp(base::AVP_SESSION_ID, session_id),
        mandatory_avp(
            base::AVP_AUTH_APPLICATION_ID,
            &swm::APPLICATION_ID.get().to_be_bytes(),
        ),
        mandatory_avp(
            swm::AVP_AUTH_REQUEST_TYPE,
            &swm::AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE.to_be_bytes(),
        ),
        result,
        mandatory_avp(base::AVP_ORIGIN_HOST, origin_host),
        mandatory_avp(base::AVP_ORIGIN_REALM, AAA_REALM),
    ];
    avps.extend_from_slice(extras);
    avps
}

fn ordinary_answer_wire(
    result_code: u32,
    session_id: &[u8],
    origin_host: &[u8],
    extras: &[Vec<u8>],
) -> Vec<u8> {
    message_wire(
        CommandFlags::answer(true, false),
        HOP_BY_HOP,
        END_TO_END,
        ordinary_answer_avps(
            mandatory_avp(base::AVP_RESULT_CODE, &result_code.to_be_bytes()),
            session_id,
            origin_host,
            extras,
        ),
    )
}

fn bound_request(extras: &[Vec<u8>]) -> SwmDiameterEapRequestEnvelope {
    let wire = request_wire(extras);
    swm::parse_swm_diameter_eap_request_envelope(
        &decode(&wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("synthetic DER")
    .with_expected_answer_peer(SwmExpectedAnswerPeer::direct(
        CONNECTION,
        String::from_utf8(AAA_HOST.to_vec()).expect("ASCII host"),
        String::from_utf8(AAA_REALM.to_vec()).expect("ASCII realm"),
    ))
}

fn avp_keys(wire: &[u8]) -> Vec<AvpKey> {
    decode(wire)
        .avps(framing_context())
        .map(|avp| avp.expect("framed AVP").header.key())
        .collect()
}

#[test]
fn generic_error_grammar_accepts_only_valid_e_bit_result_families() {
    for result_code in [3_001, 5_005, 6_001, 9_999] {
        let response = swm::parse_swm_diameter_eap_response(
            &decode(&generic_wire(Some(result_code), None, &[])),
            typed_context(UnknownIePolicy::Preserve),
        )
        .expect("valid generic E-bit result family");
        let SwmDiameterEapResponse::GenericError(answer) = response else {
            panic!("E-bit response must use generic grammar");
        };
        assert_eq!(answer.result_code, result_code);
        assert_eq!(answer.session_id, None);
    }

    for result_code in [0, 999, 1_001, 2_001, 4_001] {
        swm::parse_swm_diameter_eap_response(
            &decode(&generic_wire(Some(result_code), None, &[])),
            typed_context(UnknownIePolicy::Preserve),
        )
        .expect_err("invalid E-bit result family must fail closed");
    }

    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(
            None,
            None,
            &[experimental_result(10_415, 3_006)],
        )),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("Experimental-Result cannot replace mandatory base Result-Code");

    let response = swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(
            Some(5_005),
            None,
            &[experimental_result(10_415, 3_006)],
        )),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("experimental numeric 3006 must not claim redirect semantics");
    let SwmDiameterEapResponse::GenericError(answer) = response else {
        panic!("E-bit response must use generic grammar");
    };
    assert!(!answer.has_redirect());
}

#[test]
fn generic_avp_specific_errors_require_failed_avp_evidence() {
    let required = [
        base::RESULT_CODE_DIAMETER_AVP_UNSUPPORTED,
        base::RESULT_CODE_DIAMETER_INVALID_AVP_VALUE,
        base::RESULT_CODE_DIAMETER_CONTRADICTING_AVPS,
        base::RESULT_CODE_DIAMETER_AVP_NOT_ALLOWED,
        base::RESULT_CODE_DIAMETER_AVP_OCCURS_TOO_MANY_TIMES,
        base::RESULT_CODE_DIAMETER_INVALID_AVP_LENGTH,
        base::RESULT_CODE_DIAMETER_INVALID_AVP_BIT_COMBO,
    ];
    for result_code in required {
        swm::parse_swm_diameter_eap_response(
            &decode(&generic_wire(Some(result_code), None, &[])),
            typed_context(UnknownIePolicy::Preserve),
        )
        .expect_err("RFC-required Failed-AVP evidence must not be omitted");
        swm::parse_swm_diameter_eap_response(
            &decode(&generic_wire(
                Some(result_code),
                None,
                &[failed_avp(&[0xff])],
            )),
            typed_context(UnknownIePolicy::Preserve),
        )
        .expect("opaque Failed-AVP satisfies the required outer evidence");
    }

    for result_code in [
        base::RESULT_CODE_DIAMETER_INVALID_AVP_BITS,
        base::RESULT_CODE_DIAMETER_MISSING_AVP,
    ] {
        swm::parse_swm_diameter_eap_response(
            &decode(&generic_wire(Some(result_code), None, &[])),
            typed_context(UnknownIePolicy::Preserve),
        )
        .expect("RFC does not make Failed-AVP a hard parse requirement for this result");
    }
}

#[test]
fn outbound_generic_surface_can_originate_only_redirect_indication() {
    let redirect =
        SwmDiameterRedirect::new(vec![Redacted::from(REDIRECT_ONE.to_owned())], None, None)
            .expect("redirect plan");
    let base_answer = swm::SwmDiameterEapGenericErrorAnswer::new_redirect(
        Redacted::from(String::from_utf8(SESSION_ID.to_vec()).expect("ASCII Session-Id")),
        "agent.synthetic.invalid",
        "home.synthetic.invalid",
        redirect,
    )
    .expect("redirect answer");
    for result_code in [3_009, 5_001, 5_004, 5_005] {
        let mut answer = base_answer.clone();
        answer.result_code = result_code;
        swm::build_swm_diameter_eap_response_for(
            &bound_request(&[]),
            &SwmDiameterEapResponse::GenericError(Box::new(answer)),
            EncodeContext::default(),
        )
        .expect_err("other errors must use the request-bound error-answer builder");
    }
}

#[test]
fn redirect_usage_preserves_wire_presence_and_enforces_cache_requirements() {
    let one_host = || vec![Redacted::from(REDIRECT_ONE.to_owned())];
    let absent_usage = SwmDiameterRedirect::new(one_host(), None, Some(60))
        .expect("RFC permits max-cache-time with absent usage");
    assert_eq!(absent_usage.usage(), None);
    assert_eq!(
        absent_usage.effective_usage(),
        SwmRedirectHostUsage::DontCache
    );
    assert_eq!(absent_usage.max_cache_time(), Some(60));

    let explicit_zero =
        SwmDiameterRedirect::new(one_host(), Some(SwmRedirectHostUsage::DontCache), Some(60))
            .expect("RFC permits max-cache-time with explicit DONT_CACHE");
    assert_eq!(explicit_zero.usage(), Some(SwmRedirectHostUsage::DontCache));
    assert_eq!(explicit_zero.max_cache_time(), Some(60));

    assert_eq!(
        SwmDiameterRedirect::new(one_host(), Some(SwmRedirectHostUsage::AllSession), None,)
            .expect_err("cacheable usage requires a lifetime"),
        SwmDiameterRedirectError::MissingMaxCacheTime,
    );
    SwmDiameterRedirect::new(one_host(), Some(SwmRedirectHostUsage::AllSession), Some(60))
        .expect("complete cacheable redirect");

    let one = Redacted::from(REDIRECT_ONE.to_owned());
    SwmDiameterRedirect::new(vec![one.clone(); 128], None, None)
        .expect("128 host-only redirect AVPs fit the shared cap");
    assert_eq!(
        SwmDiameterRedirect::new(
            vec![one.clone(); 127],
            Some(SwmRedirectHostUsage::AllSession),
            Some(60),
        )
        .expect_err("host plus cache AVPs must fit the shared cap"),
        SwmDiameterRedirectError::TooManyAvps,
    );
    SwmDiameterRedirect::new(
        vec![one.clone(); 126],
        Some(SwmRedirectHostUsage::AllSession),
        Some(60),
    )
    .expect("126 hosts plus usage and max fit");
    assert_eq!(
        SwmDiameterRedirect::new(vec![one; 129], None, None).expect_err("host count is bounded"),
        SwmDiameterRedirectError::TooManyHosts,
    );

    let precedence = [
        SwmRedirectHostUsage::AllSession,
        SwmRedirectHostUsage::AllUser,
        SwmRedirectHostUsage::RealmAndApplication,
        SwmRedirectHostUsage::AllRealm,
        SwmRedirectHostUsage::AllApplication,
        SwmRedirectHostUsage::AllHost,
    ];
    assert_eq!(
        precedence.map(SwmRedirectHostUsage::routing_precedence_rank),
        [Some(1), Some(2), Some(3), Some(4), Some(5), Some(6)]
    );
}

fn correlated_redirect(
    usage: Option<SwmRedirectHostUsage>,
    max_cache_time: Option<u32>,
) -> SwmDiameterRedirect {
    let mut extras = vec![redirect_host(REDIRECT_ONE)];
    if let Some(usage) = usage {
        extras.push(mandatory_avp(
            base::AVP_REDIRECT_HOST_USAGE,
            &usage.value().to_be_bytes(),
        ));
    }
    if let Some(max_cache_time) = max_cache_time {
        extras.push(mandatory_avp(
            base::AVP_REDIRECT_MAX_CACHE_TIME,
            &max_cache_time.to_be_bytes(),
        ));
    }
    let wire = generic_wire(
        Some(swm::DIAMETER_REDIRECT_INDICATION),
        Some(SESSION_ID),
        &extras,
    );
    let envelope = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wire),
        CONNECTION,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("generic redirect response");
    bound_request(&[])
        .correlate_response(envelope)
        .expect("strictly correlated redirect")
        .redirect()
        .expect("redirect present")
        .clone()
}

#[test]
fn raw_redirect_cache_forms_follow_rfc_6733() {
    let absent = correlated_redirect(None, Some(30));
    assert_eq!(absent.usage(), None);
    assert_eq!(absent.effective_usage(), SwmRedirectHostUsage::DontCache);
    assert_eq!(absent.max_cache_time(), Some(30));

    let explicit_zero = correlated_redirect(Some(SwmRedirectHostUsage::DontCache), Some(30));
    assert_eq!(explicit_zero.usage(), Some(SwmRedirectHostUsage::DontCache));
    assert_eq!(explicit_zero.max_cache_time(), Some(30));

    let cached = correlated_redirect(Some(SwmRedirectHostUsage::AllSession), Some(30));
    assert_eq!(cached.usage(), Some(SwmRedirectHostUsage::AllSession));

    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(
            Some(swm::DIAMETER_REDIRECT_INDICATION),
            Some(SESSION_ID),
            &[
                redirect_host(REDIRECT_ONE),
                mandatory_avp(
                    base::AVP_REDIRECT_HOST_USAGE,
                    &SwmRedirectHostUsage::AllSession.value().to_be_bytes(),
                ),
            ],
        )),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("cacheable usage without max-cache-time must fail");
}

#[test]
fn redirect_is_actionable_only_after_strict_connection_and_request_correlation() {
    let proxy = proxy_info();
    let extras = [
        redirect_host(REDIRECT_ONE),
        redirect_host(REDIRECT_TWO),
        proxy.clone(),
    ];
    let wire = generic_wire(
        Some(swm::DIAMETER_REDIRECT_INDICATION),
        Some(SESSION_ID),
        &extras,
    );

    let parsed = swm::parse_swm_diameter_eap_response(
        &decode(&wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("uncorrelated generic response can be inspected safely");
    let SwmDiameterEapResponse::GenericError(answer) = &parsed else {
        panic!("generic response expected");
    };
    assert!(answer.has_redirect());
    assert!(swm::build_swm_diameter_eap_response_for(
        &bound_request(std::slice::from_ref(&proxy)),
        &parsed,
        EncodeContext::default(),
    )
    .is_err());

    let response = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wire),
        CONNECTION,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("connection-bound generic response");
    let correlated = bound_request(std::slice::from_ref(&proxy))
        .correlate_response(response)
        .expect("matching connection, IDs, session, and Proxy-Info");
    let redirect = correlated.redirect().expect("actionable redirect");
    assert_eq!(redirect.hosts().len(), 2);
    assert_eq!(redirect.hosts()[0].as_ref(), REDIRECT_ONE);
    assert_eq!(redirect.hosts()[1].as_ref(), REDIRECT_TWO);

    let absent_session_wire = generic_wire(
        Some(swm::DIAMETER_REDIRECT_INDICATION),
        None,
        &[redirect_host(REDIRECT_ONE), proxy.clone()],
    );
    let absent_session = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&absent_session_wire),
        CONNECTION,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("generic response may omit Session-Id");
    bound_request(std::slice::from_ref(&proxy))
        .correlate_response(absent_session)
        .expect("transaction and connection still bind an absent Session-Id response");

    let wrong_connection = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wire),
        OTHER_CONNECTION,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("well-formed response on another connection");
    assert_eq!(
        bound_request(std::slice::from_ref(&proxy))
            .correlate_response(wrong_connection)
            .expect_err("connection generation is binding"),
        SwmDiameterEapCorrelationError::PeerConnectionMismatch,
    );

    let wrong_transaction_wire = message_wire(
        CommandFlags::answer(true, true),
        HOP_BY_HOP ^ 1,
        END_TO_END,
        generic_avps(
            Some(swm::DIAMETER_REDIRECT_INDICATION),
            Some(SESSION_ID),
            &extras,
        ),
    );
    let wrong_transaction = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wrong_transaction_wire),
        CONNECTION,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("well-formed response with another transaction");
    assert_eq!(
        bound_request(std::slice::from_ref(&proxy))
            .correlate_response(wrong_transaction)
            .expect_err("both transaction identifiers are binding"),
        SwmDiameterEapCorrelationError::TransactionMismatch,
    );

    let wrong_end_to_end_wire = message_wire(
        CommandFlags::answer(true, true),
        HOP_BY_HOP,
        END_TO_END ^ 1,
        generic_avps(
            Some(swm::DIAMETER_REDIRECT_INDICATION),
            Some(SESSION_ID),
            &extras,
        ),
    );
    let wrong_end_to_end = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wrong_end_to_end_wire),
        CONNECTION,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("well-formed response with another end-to-end identifier");
    assert_eq!(
        bound_request(std::slice::from_ref(&proxy))
            .correlate_response(wrong_end_to_end)
            .expect_err("End-to-End identifier is independently binding"),
        SwmDiameterEapCorrelationError::TransactionMismatch,
    );

    let other_proxy = proxy_info_with(b"other-proxy.synthetic.invalid", PROXY_STATE, &[]);
    let wrong_proxy_wire = generic_wire(
        Some(swm::DIAMETER_REDIRECT_INDICATION),
        Some(SESSION_ID),
        &[redirect_host(REDIRECT_ONE), other_proxy],
    );
    let wrong_proxy = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wrong_proxy_wire),
        CONNECTION,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("well-formed response with another proxy chain");
    assert_eq!(
        bound_request(std::slice::from_ref(&proxy))
            .correlate_response(wrong_proxy)
            .expect_err("ordered Proxy-Info bytes are binding"),
        SwmDiameterEapCorrelationError::ProxyInfoMismatch,
    );

    let wrong_session_wire = generic_wire(
        Some(swm::DIAMETER_REDIRECT_INDICATION),
        Some(b"another;synthetic;session"),
        &[redirect_host(REDIRECT_ONE), proxy],
    );
    let wrong_session = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&wrong_session_wire),
        CONNECTION,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("well-formed response with another session");
    assert_eq!(
        bound_request(&[proxy_info()])
            .correlate_response(wrong_session)
            .expect_err("present Session-Id is binding"),
        SwmDiameterEapCorrelationError::SessionMismatch,
    );

    let debug = format!("{correlated:?}");
    assert!(!debug.contains(REDIRECT_ONE));
    assert!(!debug.contains(REDIRECT_TWO));
    assert!(!debug.contains(std::str::from_utf8(PROXY_STATE).expect("ASCII sentinel")));
}

#[test]
fn generic_agents_skip_logical_origin_policy_but_ordinary_answers_do_not() {
    let generic = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&generic_wire(Some(5_005), Some(SESSION_ID), &[])),
        CONNECTION,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("agent-originated generic response");
    bound_request(&[])
        .correlate_response(generic)
        .expect("generic error can originate at a trusted intermediary");

    let ordinary_wire = ordinary_answer_wire(5_005, SESSION_ID, AGENT_HOST, &[]);
    let ordinary = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&ordinary_wire),
        CONNECTION,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("ordinary application answer");
    assert_eq!(
        bound_request(&[])
            .correlate_response(ordinary)
            .expect_err("ordinary final Origin must satisfy direct-peer policy"),
        SwmDiameterEapCorrelationError::PeerIdentityMismatch,
    );
}

#[test]
fn request_and_generic_builders_preserve_rfc_routing_order_and_failover_facts() {
    let proxy = proxy_info();
    let route = mandatory_avp(base::AVP_ROUTE_RECORD, ROUTE_RECORD);
    let extension = raw_avp(AvpCode::new(900_001), 0, None, b"opaque-extension");
    let raw_request = request_wire(&[proxy.clone(), route, extension]);
    let mut envelope = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&raw_request),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("routed DER")
    .with_expected_answer_peer(SwmExpectedAnswerPeer::routed(CONNECTION));
    assert_eq!(envelope.request().route_records.len(), 1);
    assert_eq!(envelope.proxy_info_count(), 1);

    let before_failover = envelope.clone();
    envelope.mark_for_failover_retransmission(
        HOP_BY_HOP ^ 0x00ff_0000,
        SwmExpectedAnswerPeer::routed(OTHER_CONNECTION),
    );
    assert!(before_failover.same_replay_payload(&envelope));
    let rebuilt = swm::build_swm_diameter_eap_request_envelope(&envelope, EncodeContext::default())
        .expect("failover DER rebuild");
    assert!(rebuilt.header.flags.is_request());
    assert!(rebuilt.header.flags.is_proxiable());
    assert!(!rebuilt.header.flags.is_error());
    assert!(rebuilt.header.flags.is_potentially_retransmitted());
    assert_eq!(rebuilt.header.end_to_end_identifier, END_TO_END);
    assert_ne!(rebuilt.header.hop_by_hop_identifier, HOP_BY_HOP);
    let rebuilt_wire = encode(&rebuilt);
    let keys = avp_keys(&rebuilt_wire);
    let eap = keys
        .iter()
        .position(|key| *key == AvpKey::ietf(swm::AVP_EAP_PAYLOAD))
        .expect("EAP-Payload");
    let proxy_position = keys
        .iter()
        .position(|key| *key == AvpKey::ietf(base::AVP_PROXY_INFO))
        .expect("Proxy-Info");
    let route_position = keys
        .iter()
        .position(|key| *key == AvpKey::ietf(base::AVP_ROUTE_RECORD))
        .expect("Route-Record");
    let extension_position = keys
        .iter()
        .position(|key| *key == AvpKey::ietf(AvpCode::new(900_001)))
        .expect("extension");
    assert!(eap < proxy_position);
    assert!(proxy_position < route_position);
    assert!(route_position < extension_position);

    let redirect = SwmDiameterRedirect::new(
        vec![Redacted::from(REDIRECT_ONE.to_owned())],
        Some(SwmRedirectHostUsage::AllSession),
        Some(60),
    )
    .expect("outbound redirect plan");
    let answer = swm::SwmDiameterEapGenericErrorAnswer::new_redirect(
        Redacted::from(String::from_utf8(SESSION_ID.to_vec()).expect("ASCII Session-Id")),
        "agent.synthetic.invalid",
        "home.synthetic.invalid",
        redirect,
    )
    .expect("outbound generic redirect");
    let response = SwmDiameterEapResponse::GenericError(Box::new(answer));
    let built_response = swm::build_swm_diameter_eap_response_for(
        &before_failover,
        &response,
        EncodeContext::default(),
    )
    .expect("request-bound generic response");
    assert!(built_response.header.flags.is_error());
    assert!(!built_response.header.flags.is_potentially_retransmitted());
    let response_wire = encode(&built_response);
    let response_keys = avp_keys(&response_wire);
    let response_proxy = response_keys
        .iter()
        .position(|key| *key == AvpKey::ietf(base::AVP_PROXY_INFO))
        .expect("echoed Proxy-Info");
    let response_redirect = response_keys
        .iter()
        .position(|key| *key == AvpKey::ietf(base::AVP_REDIRECT_HOST))
        .expect("Redirect-Host");
    assert!(response_proxy < response_redirect);
    assert!(!response_keys.contains(&AvpKey::ietf(base::AVP_ROUTE_RECORD)));

    let debug = format!("{:?}", envelope.request());
    assert!(!debug.contains(std::str::from_utf8(ROUTE_RECORD).expect("ASCII sentinel")));
}

#[test]
fn ordinary_e_clear_answers_retain_but_cannot_rebind_opaque_failed_avps() {
    let wire = ordinary_answer_wire(
        5_005,
        SESSION_ID,
        AAA_HOST,
        &[failed_avp(&[0xff]), failed_avp(&[0x00, 0x01])],
    );
    let answer = swm::parse_swm_diameter_eap_answer(
        &decode(&wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("RFC 4072 ordinary DEA may repeat Failed-AVP");
    assert_eq!(answer.extensions.len(), 2);
    assert!(answer
        .extensions
        .metadata()
        .all(|metadata| metadata.code() == base::AVP_FAILED_AVP));
    swm::build_swm_diameter_eap_answer(&answer, HOP_BY_HOP, END_TO_END, EncodeContext::default())
        .expect_err("Failed-AVP evidence must not be rebound through a mutable typed answer");
}

#[test]
fn generic_wildcard_is_vendor_aware_and_enforces_answer_semantics() {
    let correct_auth_application = mandatory_avp(
        base::AVP_AUTH_APPLICATION_ID,
        &swm::APPLICATION_ID.get().to_be_bytes(),
    );
    let known_application_avp = mandatory_avp(
        swm::AVP_AUTH_REQUEST_TYPE,
        &swm::AUTH_REQUEST_TYPE_AUTHORIZE_AUTHENTICATE.to_be_bytes(),
    );
    let response = swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(
            Some(5_005),
            None,
            &[correct_auth_application.clone(), known_application_avp],
        )),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("known valid M-set application AVPs fit the generic wildcard");
    let SwmDiameterEapResponse::GenericError(answer) = response else {
        panic!("generic response expected");
    };
    assert_eq!(answer.additional_avp_count(), 2);

    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(
            Some(5_005),
            None,
            &[mandatory_avp(
                base::AVP_AUTH_APPLICATION_ID,
                &1_u32.to_be_bytes(),
            )],
        )),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("Auth-Application-Id must match the SWm header");
    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(
            Some(5_005),
            None,
            &[correct_auth_application.clone(), correct_auth_application],
        )),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("generic singleton duplicates fail under typed guards");

    for prohibited in [base::AVP_DESTINATION_HOST, base::AVP_DESTINATION_REALM] {
        swm::parse_swm_diameter_eap_response(
            &decode(&generic_wire(
                Some(5_005),
                None,
                &[mandatory_avp(prohibited, b"forbidden.synthetic.invalid")],
            )),
            typed_context(UnknownIePolicy::Preserve),
        )
        .expect_err("Diameter answers prohibit Destination AVPs");

        let ordinary = ordinary_answer_wire(
            5_005,
            SESSION_ID,
            AAA_HOST,
            &[raw_avp(prohibited, 0, None, b"forbidden.synthetic.invalid")],
        );
        swm::parse_swm_diameter_eap_answer(
            &decode(&ordinary),
            typed_context(UnknownIePolicy::Preserve),
        )
        .expect_err("ordinary answers prohibit M-clear Destination AVPs");
        for dictionaries in [BASELINE_DICTIONARIES, PROJECTED_DICTIONARIES] {
            Message::decode_with_dictionary(&ordinary, DecodeContext::conservative(), dictionaries)
                .expect_err("answer dictionary must forbid M-clear Destination AVPs");
        }
    }

    let vendor_collision = raw_avp(
        base::AVP_REDIRECT_HOST,
        AvpFlags::VENDOR,
        Some(VendorId::new(10_415)),
        b"not-an-ietf-redirect",
    );
    let response = swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(
            Some(5_005),
            None,
            std::slice::from_ref(&vendor_collision),
        )),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("nonzero vendor collision follows unknown optional preservation");
    let SwmDiameterEapResponse::GenericError(answer) = response else {
        panic!("generic response expected");
    };
    assert!(!answer.has_redirect());
    assert_eq!(answer.additional_avp_count(), 1);

    let response = swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(
            Some(5_005),
            None,
            std::slice::from_ref(&vendor_collision),
        )),
        typed_context(UnknownIePolicy::Drop),
    )
    .expect("unknown optional collision can be dropped");
    let SwmDiameterEapResponse::GenericError(answer) = response else {
        panic!("generic response expected");
    };
    assert_eq!(answer.additional_avp_count(), 0);
    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(Some(5_005), None, &[vendor_collision])),
        typed_context(UnknownIePolicy::Reject),
    )
    .expect_err("unknown optional collision follows Reject policy");

    let unknown_mandatory = mandatory_avp(AvpCode::new(900_002), b"opaque");
    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(Some(5_005), None, &[unknown_mandatory])),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("genuinely unknown M-set AVP must fail closed");

    let malformed_failed = swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(Some(5_005), None, &[failed_avp(&[0xff])])),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("Failed-AVP inner representation is intentionally opaque");
    let SwmDiameterEapResponse::GenericError(answer) = malformed_failed else {
        panic!("generic response expected");
    };
    assert_eq!(answer.failed_avp_count(), 1);
}

#[test]
fn vendor_zero_and_invalid_experimental_vendor_fail_closed() {
    let vendor_zero = raw_avp(
        AvpCode::new(900_003),
        AvpFlags::VENDOR,
        Some(VendorId::new(0)),
        b"opaque",
    );
    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(
            Some(5_005),
            None,
            std::slice::from_ref(&vendor_zero),
        )),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("RFC 6733 reserves Vendor-Id zero when V is set");
    swm::parse_swm_diameter_eap_request(
        &decode(&request_wire(&[vendor_zero])),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("DER must also reject unknown optional AVPs with Vendor-Id zero");

    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(
            Some(5_005),
            None,
            &[experimental_result(0, 5_001)],
        )),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("Experimental-Result Vendor-Id must be nonzero");
}

#[test]
fn proxy_info_validation_is_exact_bounded_and_policy_aware() {
    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(Some(5_005), None, &[proxy_info()])),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("exact Proxy-Host plus Proxy-State");

    let missing_state = mandatory_avp(
        base::AVP_PROXY_INFO,
        &mandatory_avp(base::AVP_PROXY_HOST, PROXY_HOST),
    );
    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(Some(5_005), None, &[missing_state])),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("Proxy-State is mandatory");

    let duplicate_host = proxy_info_with(
        PROXY_HOST,
        PROXY_STATE,
        &[mandatory_avp(base::AVP_PROXY_HOST, PROXY_HOST)],
    );
    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(Some(5_005), None, &[duplicate_host])),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("Proxy-Host is exact-once even under Last policy");

    let empty_host = proxy_info_with(b"", PROXY_STATE, &[]);
    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(Some(5_005), None, &[empty_host])),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("Proxy-Host must be nonempty");

    let wrong_host_flags = raw_avp(base::AVP_PROXY_HOST, 0, None, PROXY_HOST);
    let mut wrong_value = wrong_host_flags;
    wrong_value.extend_from_slice(&mandatory_avp(base::AVP_PROXY_STATE, PROXY_STATE));
    let wrong_flags = mandatory_avp(base::AVP_PROXY_INFO, &wrong_value);
    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(Some(5_005), None, &[wrong_flags])),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("Proxy-Host flags are exact");

    let unknown_optional = raw_avp(AvpCode::new(900_004), 0, None, b"opaque");
    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(
            Some(5_005),
            None,
            &[proxy_info_with(
                PROXY_HOST,
                PROXY_STATE,
                std::slice::from_ref(&unknown_optional),
            )],
        )),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("unknown optional Proxy-Info child follows Preserve policy");

    let nested_vendor_zero = raw_avp(
        AvpCode::new(900_006),
        AvpFlags::VENDOR,
        Some(VendorId::new(0)),
        b"opaque",
    );
    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(
            Some(5_005),
            None,
            &[proxy_info_with(
                PROXY_HOST,
                PROXY_STATE,
                &[nested_vendor_zero],
            )],
        )),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("unknown optional Proxy-Info child must reject Vendor-Id zero");

    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(
            Some(5_005),
            None,
            &[proxy_info_with(
                PROXY_HOST,
                PROXY_STATE,
                &[mandatory_avp(AvpCode::new(900_005), b"opaque")],
            )],
        )),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("unknown mandatory Proxy-Info child fails closed");

    let many_children = (0..127)
        .map(|index| raw_avp(AvpCode::new(910_000 + index), 0, None, &[]))
        .collect::<Vec<_>>();
    let oversized = proxy_info_with(PROXY_HOST, PROXY_STATE, &many_children);
    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(Some(5_005), None, &[oversized])),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("Proxy-Info child count has an explicit 128-AVP bound");
}

#[test]
fn header_route_and_dictionary_rules_fail_closed() {
    let no_p = message_wire(
        CommandFlags::answer(false, true),
        HOP_BY_HOP,
        END_TO_END,
        generic_avps(Some(5_005), None, &[]),
    );
    swm::parse_swm_diameter_eap_response(&decode(&no_p), typed_context(UnknownIePolicy::Preserve))
        .expect_err("DEA must preserve P");

    let with_t = message_wire(
        CommandFlags::from_bits(
            CommandFlags::PROXIABLE | CommandFlags::ERROR | CommandFlags::POTENTIALLY_RETRANSMITTED,
        ),
        HOP_BY_HOP,
        END_TO_END,
        generic_avps(Some(5_005), None, &[]),
    );
    swm::parse_swm_diameter_eap_response(
        &decode(&with_t),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("DEA must clear T");

    let request_with_e = request_wire_with_flags(
        CommandFlags::from_bits(
            CommandFlags::REQUEST | CommandFlags::PROXIABLE | CommandFlags::ERROR,
        ),
        &[],
    );
    swm::parse_swm_diameter_eap_request(
        &decode(&request_with_e),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("DER must clear E");

    let m_clear_redirect = request_wire(&[raw_avp(
        base::AVP_REDIRECT_HOST,
        0,
        None,
        b"aaa://forbidden.synthetic.invalid",
    )]);
    swm::parse_swm_diameter_eap_request(
        &decode(&m_clear_redirect),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("DER must reject M-clear answer-only Redirect-Host");

    let m_clear_failed = request_wire(&[raw_avp(base::AVP_FAILED_AVP, 0, None, &[0xff])]);
    swm::parse_swm_diameter_eap_request(
        &decode(&m_clear_failed),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("DER must reject M-clear answer-only Failed-AVP");

    let m_clear_result = request_wire(&[raw_avp(
        base::AVP_RESULT_CODE,
        0,
        None,
        &5_005_u32.to_be_bytes(),
    )]);
    swm::parse_swm_diameter_eap_request(
        &decode(&m_clear_result),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("DER must reject M-clear answer-only Result-Code");

    let mut experimental_value = mandatory_avp(base::AVP_VENDOR_ID, &10_415_u32.to_be_bytes());
    experimental_value.extend_from_slice(&mandatory_avp(
        base::AVP_EXPERIMENTAL_RESULT_CODE,
        &5_001_u32.to_be_bytes(),
    ));
    let m_clear_experimental = request_wire(&[raw_avp(
        base::AVP_EXPERIMENTAL_RESULT,
        0,
        None,
        &experimental_value,
    )]);
    swm::parse_swm_diameter_eap_request(
        &decode(&m_clear_experimental),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("DER must reject M-clear answer-only Experimental-Result");

    for dictionaries in [BASELINE_DICTIONARIES, PROJECTED_DICTIONARIES] {
        Message::decode_with_dictionary(
            &m_clear_redirect,
            DecodeContext::conservative(),
            dictionaries,
        )
        .expect_err("DER dictionary must forbid M-clear Redirect-Host");
        Message::decode_with_dictionary(
            &m_clear_failed,
            DecodeContext::conservative(),
            dictionaries,
        )
        .expect_err("DER dictionary must forbid M-clear Failed-AVP");
        Message::decode_with_dictionary(
            &m_clear_result,
            DecodeContext::conservative(),
            dictionaries,
        )
        .expect_err("DER dictionary must forbid M-clear Result-Code");
        Message::decode_with_dictionary(
            &m_clear_experimental,
            DecodeContext::conservative(),
            dictionaries,
        )
        .expect_err("DER dictionary must forbid M-clear Experimental-Result");
    }

    let route_answer = generic_wire(
        Some(5_005),
        None,
        &[mandatory_avp(base::AVP_ROUTE_RECORD, ROUTE_RECORD)],
    );
    swm::parse_swm_diameter_eap_response(
        &decode(&route_answer),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("answers prohibit Route-Record");

    for dictionary in [swm::dictionary(), swm::projected_profile_dictionary()] {
        let der = dictionary
            .find_command(
                swm::APPLICATION_ID,
                swm::COMMAND_DIAMETER_EAP,
                CommandKind::Request,
            )
            .expect("DER dictionary");
        assert_eq!(
            der.find_avp_rule(AvpKey::ietf(base::AVP_ROUTE_RECORD))
                .map(|rule| rule.cardinality()),
            Some(AvpCardinality::ZeroOrMore),
        );
        assert!(der.allows_multiple(AvpKey::ietf(base::AVP_PROXY_INFO)));
        for forbidden in [
            base::AVP_REDIRECT_HOST,
            base::AVP_REDIRECT_HOST_USAGE,
            base::AVP_REDIRECT_MAX_CACHE_TIME,
            base::AVP_FAILED_AVP,
            base::AVP_RESULT_CODE,
            base::AVP_EXPERIMENTAL_RESULT,
        ] {
            assert_eq!(
                der.find_avp_rule(AvpKey::ietf(forbidden))
                    .map(|rule| rule.cardinality()),
                Some(AvpCardinality::Forbidden),
            );
        }

        let dea = dictionary
            .find_command(
                swm::APPLICATION_ID,
                swm::COMMAND_DIAMETER_EAP,
                CommandKind::Answer,
            )
            .expect("DEA dictionary");
        assert_eq!(
            dea.find_avp_rule(AvpKey::ietf(base::AVP_ROUTE_RECORD))
                .map(|rule| rule.cardinality()),
            Some(AvpCardinality::Forbidden),
        );
        assert!(dea.allows_multiple(AvpKey::ietf(base::AVP_PROXY_INFO)));
        assert!(dea.allows_multiple(AvpKey::ietf(base::AVP_REDIRECT_HOST)));
        assert!(dea.allows_multiple(AvpKey::ietf(base::AVP_FAILED_AVP)));
        for forbidden in [base::AVP_DESTINATION_HOST, base::AVP_DESTINATION_REALM] {
            assert_eq!(
                dea.find_avp_rule(AvpKey::ietf(forbidden))
                    .map(|rule| rule.cardinality()),
                Some(AvpCardinality::Forbidden),
            );
        }
    }

    let first_failed_value = mandatory_avp(base::AVP_ORIGIN_HOST, b"first.synthetic.invalid");
    let second_failed_value = mandatory_avp(base::AVP_ORIGIN_HOST, b"second.synthetic.invalid");
    let repeated = generic_wire(
        Some(swm::DIAMETER_REDIRECT_INDICATION),
        None,
        &[
            proxy_info(),
            proxy_info_with(b"proxy-two.synthetic.invalid", b"other-state", &[]),
            redirect_host(REDIRECT_ONE),
            redirect_host(REDIRECT_TWO),
            failed_avp(&first_failed_value),
            failed_avp(&second_failed_value),
        ],
    );
    for dictionaries in [BASELINE_DICTIONARIES, PROJECTED_DICTIONARIES] {
        let (tail, _) =
            Message::decode_with_dictionary(&repeated, DecodeContext::conservative(), dictionaries)
                .expect("repeatable routing and error AVPs are dictionary-visible");
        assert!(tail.is_empty());
    }

    for dictionaries in [BASELINE_DICTIONARIES, PROJECTED_DICTIONARIES] {
        Message::decode_with_dictionary(&route_answer, DecodeContext::conservative(), dictionaries)
            .expect_err("Route-Record is forbidden in every DEA profile");
    }
}

#[test]
fn experimental_numeric_redirect_stays_ordinary_and_e_clear() {
    let wire = message_wire(
        CommandFlags::answer(true, false),
        HOP_BY_HOP,
        END_TO_END,
        ordinary_answer_avps(
            experimental_result(10_415, swm::DIAMETER_REDIRECT_INDICATION),
            SESSION_ID,
            AAA_HOST,
            &[],
        ),
    );
    let answer = swm::parse_swm_diameter_eap_answer(
        &decode(&wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("experimental numeric 3006 remains ordinary application grammar");
    let rebuilt = swm::build_swm_diameter_eap_answer(
        &answer,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .expect("ordinary experimental result re-encodes");
    assert!(!rebuilt.header.flags.is_error());
    assert_eq!(encode(&rebuilt), wire);
}

#[test]
fn diagnostics_redact_error_routing_and_identity_values() {
    let error_message = b"private-error-message-sentinel";
    let wire = generic_wire(
        Some(swm::DIAMETER_REDIRECT_INDICATION),
        Some(SESSION_ID),
        &[
            raw_avp(base::AVP_ERROR_MESSAGE, 0, None, error_message),
            redirect_host(REDIRECT_ONE),
            proxy_info(),
        ],
    );
    let response = swm::parse_swm_diameter_eap_response(
        &decode(&wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("redaction fixture");
    let debug = format!("{response:?}");
    for sentinel in [
        std::str::from_utf8(SESSION_ID).expect("ASCII"),
        std::str::from_utf8(AGENT_HOST).expect("ASCII"),
        std::str::from_utf8(AAA_REALM).expect("ASCII"),
        std::str::from_utf8(error_message).expect("ASCII"),
        REDIRECT_ONE,
        std::str::from_utf8(PROXY_STATE).expect("ASCII"),
    ] {
        assert!(!debug.contains(sentinel));
    }
}

#[test]
fn redirect_context_is_exactly_tied_to_base_3006() {
    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(
            Some(swm::DIAMETER_REDIRECT_INDICATION),
            None,
            &[],
        )),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("base 3006 requires Redirect-Host");
    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(
            Some(5_005),
            None,
            &[redirect_host(REDIRECT_ONE)],
        )),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("other base results must not carry redirect context");
    swm::parse_swm_diameter_eap_response(
        &decode(&generic_wire(
            Some(swm::DIAMETER_REDIRECT_INDICATION),
            None,
            &[redirect_host("not-a-diameter-uri")],
        )),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("Redirect-Host must be a DiameterURI");

    let ordinary_protocol_error = ordinary_answer_wire(3_001, SESSION_ID, AAA_HOST, &[]);
    swm::parse_swm_diameter_eap_answer(
        &decode(&ordinary_protocol_error),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect_err("base 3xxx requires generic E-bit grammar");
}

#[test]
fn response_without_peer_binding_cannot_be_correlated() {
    let request = request_wire(&[]);
    let request = swm::parse_swm_diameter_eap_request_envelope(
        &decode(&request),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("DER without transport binding");
    let response = swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(&generic_wire(Some(5_005), Some(SESSION_ID), &[])),
        CONNECTION,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("generic response");
    assert_eq!(
        request
            .correlate_response(response)
            .expect_err("transport binding is mandatory"),
        SwmDiameterEapCorrelationError::PeerBindingMissing,
    );
}

#[test]
fn transaction_type_is_preserved_by_envelope_rebuild() {
    let request = bound_request(&[]);
    assert_eq!(
        request.transaction(),
        SwmDiameterTransaction::new(HOP_BY_HOP, END_TO_END)
    );
}
