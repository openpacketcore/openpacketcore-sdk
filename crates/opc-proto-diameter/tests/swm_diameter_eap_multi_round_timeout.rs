#![cfg(feature = "app-swm")]

use std::num::NonZeroU64;

use bytes::{Bytes, BytesMut};
use opc_proto_diameter::apps::swm::{
    self, SwmCorrelatedDiameterEapResponse, SwmDiameterConnectionToken, SwmDiameterEapAnswer,
    SwmDiameterEapRequestEnvelope, SwmDiameterEapResponseEnvelope, SwmExpectedAnswerPeer,
    SwmMultiRoundTimeout,
};
use opc_proto_diameter::dictionary::{AvpCardinality, AvpDataType, AvpKey, FlagRequirement};
use opc_proto_diameter::{
    base, AvpCode, AvpFlags, CommandFlags, DictionarySet, Header, Message, OwnedMessage, RawAvp,
    VendorId,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DuplicateIePolicy, Encode, EncodeContext,
    UnknownIePolicy,
};

const HOP_BY_HOP: u32 = 0x0102_0304;
const END_TO_END: u32 = 0x1122_3344;
const SESSION_ID: &[u8] = b"epdg-a.example;multi-round;1";
const AAA_HOST: &[u8] = b"aaa-a.example";
const AAA_REALM: &[u8] = b"example";
const EPDG_HOST: &[u8] = b"epdg-a.example";
const CONNECTION: SwmDiameterConnectionToken = SwmDiameterConnectionToken::new(NonZeroU64::MIN);
const FOREIGN_VENDOR: VendorId = VendorId::new(42_424);
const DIAMETER_MULTI_ROUND_AUTH: u32 = 1_001;
const WIRE_MULTI_ROUND_TIME_OUT: AvpCode = AvpCode::new(272);

static SWM_DICTIONARIES: DictionarySet<'static> =
    DictionarySet::new(&[base::dictionary(), swm::dictionary()]);
static SWM_PROJECTED_DICTIONARIES: DictionarySet<'static> =
    DictionarySet::new(&[base::dictionary(), swm::projected_profile_dictionary()]);

#[derive(Clone, Copy)]
enum ResultWire {
    Base(u32),
    Experimental { vendor_id: VendorId, code: u32 },
}

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

fn result_avp(result: ResultWire) -> Vec<u8> {
    match result {
        ResultWire::Base(code) => raw_avp(
            base::AVP_RESULT_CODE,
            AvpFlags::MANDATORY,
            None,
            &code.to_be_bytes(),
        ),
        ResultWire::Experimental { vendor_id, code } => {
            let mut children = raw_avp(
                base::AVP_VENDOR_ID,
                AvpFlags::MANDATORY,
                None,
                &vendor_id.get().to_be_bytes(),
            );
            children.extend_from_slice(&raw_avp(
                base::AVP_EXPERIMENTAL_RESULT_CODE,
                AvpFlags::MANDATORY,
                None,
                &code.to_be_bytes(),
            ));
            raw_avp(
                base::AVP_EXPERIMENTAL_RESULT,
                AvpFlags::MANDATORY,
                None,
                &children,
            )
        }
    }
}

fn answer_wire(
    result: ResultWire,
    eap_payload: Option<&[u8]>,
    eap_reissued_payload: Option<&[u8]>,
    extras: &[Vec<u8>],
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
        result_avp(result),
        raw_avp(base::AVP_ORIGIN_HOST, AvpFlags::MANDATORY, None, AAA_HOST),
        raw_avp(base::AVP_ORIGIN_REALM, AvpFlags::MANDATORY, None, AAA_REALM),
    ] {
        raw_avps.extend_from_slice(&avp);
    }
    for extra in extras {
        raw_avps.extend_from_slice(extra);
    }
    if let Some(payload) = eap_payload {
        raw_avps.extend_from_slice(&raw_avp(
            swm::AVP_EAP_PAYLOAD,
            AvpFlags::MANDATORY,
            None,
            payload,
        ));
    }
    if let Some(payload) = eap_reissued_payload {
        raw_avps.extend_from_slice(&raw_avp(
            swm::AVP_EAP_REISSUED_PAYLOAD,
            AvpFlags::MANDATORY,
            None,
            payload,
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
        raw_avps: Bytes::from(raw_avps),
    })
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
        raw_avp(base::AVP_ORIGIN_REALM, AvpFlags::MANDATORY, None, AAA_REALM),
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
            &[2, 7, 0, 5, 1],
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

fn timeout_avp(value: u32) -> Vec<u8> {
    raw_avp(
        WIRE_MULTI_ROUND_TIME_OUT,
        AvpFlags::MANDATORY,
        None,
        &value.to_be_bytes(),
    )
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

fn bound_request() -> SwmDiameterEapRequestEnvelope {
    let wire = request_wire(None);
    swm::parse_swm_diameter_eap_request_envelope(
        &decode(&wire),
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("synthetic DER parses")
    .with_expected_answer_peer(SwmExpectedAnswerPeer::direct(
        CONNECTION,
        "aaa-a.example",
        "example",
    ))
}

fn response_envelope(wire: &[u8]) -> SwmDiameterEapResponseEnvelope {
    swm::parse_swm_diameter_eap_response_envelope_from_connection(
        &decode(wire),
        CONNECTION,
        typed_context(UnknownIePolicy::Preserve),
    )
    .expect("synthetic response parses")
}

fn correlated(wire: &[u8]) -> SwmCorrelatedDiameterEapResponse {
    bound_request()
        .correlate_response(response_envelope(wire))
        .expect("authenticated synthetic response correlates")
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

#[test]
fn base_dictionary_and_swm_command_profiles_are_normative() {
    assert_eq!(base::AVP_MULTI_ROUND_TIME_OUT.get(), 272);
    let definition = base::dictionary()
        .find_avp(AvpKey::ietf(base::AVP_MULTI_ROUND_TIME_OUT))
        .expect("Multi-Round-Time-Out base definition");
    assert_eq!(definition.name(), "Multi-Round-Time-Out");
    assert_eq!(definition.data_type(), AvpDataType::Unsigned32);
    assert_eq!(definition.flags().vendor(), FlagRequirement::MustBeUnset);
    assert_eq!(definition.flags().mandatory(), FlagRequirement::MustBeSet);
    assert_eq!(definition.flags().protected(), FlagRequirement::MustBeUnset);
    assert_eq!(definition.spec_ref().doc(), "RFC6733");
    assert_eq!(definition.spec_ref().section(), "8.19");

    assert_eq!(
        swm::COMMAND_DIAMETER_EAP_REQUEST
            .find_avp_rule(AvpKey::ietf(base::AVP_MULTI_ROUND_TIME_OUT))
            .expect("DER omission rule")
            .cardinality(),
        AvpCardinality::Forbidden,
    );
    for command in [
        &swm::COMMAND_DIAMETER_EAP_ANSWER,
        &swm::COMMAND_DIAMETER_EAP_ANSWER_PROJECTED_PROFILE,
    ] {
        assert_eq!(
            command
                .find_avp_rule(AvpKey::ietf(base::AVP_MULTI_ROUND_TIME_OUT))
                .expect("DEA singleton rule")
                .cardinality(),
            AvpCardinality::ZeroOrOne,
        );
    }
}

#[test]
fn independent_example_fixture_preserves_exact_wire_identity_and_value() {
    let timeout = timeout_avp(0x0102_0304);
    let wire = answer_wire(
        ResultWire::Base(DIAMETER_MULTI_ROUND_AUTH),
        Some(&[1, 7, 0, 5, 1]),
        None,
        std::slice::from_ref(&timeout),
    );
    let message = decode(&wire);
    let parsed = parse(&wire).expect("RFC 4072 fixture parses");
    assert_eq!(
        parsed
            .multi_round_timeout
            .map(SwmMultiRoundTimeout::seconds),
        Some(0x0102_0304),
    );
    let avp = snapshots(message.raw_avps)
        .into_iter()
        .find(|avp| avp.code == WIRE_MULTI_ROUND_TIME_OUT)
        .expect("fixture contains Multi-Round-Time-Out");
    assert_eq!(avp.vendor_id, None);
    assert_eq!(avp.flags, AvpFlags::MANDATORY);
    assert_eq!(avp.value, 0x0102_0304_u32.to_be_bytes());

    let rebuilt = swm::build_swm_diameter_eap_answer(
        &parsed,
        HOP_BY_HOP,
        END_TO_END,
        EncodeContext::default(),
    )
    .expect("typed answer rebuilds");
    assert_eq!(encode(&rebuilt), wire);
}

#[test]
fn absent_and_full_unsigned32_domain_do_not_manufacture_policy() {
    let absent_wire = answer_wire(
        ResultWire::Base(DIAMETER_MULTI_ROUND_AUTH),
        Some(&[1, 7, 0, 5, 1]),
        None,
        &[],
    );
    let absent = parse(&absent_wire).expect("absent timer parses");
    assert_eq!(absent.multi_round_timeout, None);
    assert_eq!(
        encode(
            &swm::build_swm_diameter_eap_answer(
                &absent,
                HOP_BY_HOP,
                END_TO_END,
                EncodeContext::default(),
            )
            .expect("absent timer rebuilds"),
        ),
        absent_wire,
    );

    for value in [0, 1, u32::MAX] {
        let wire = answer_wire(
            ResultWire::Base(DIAMETER_MULTI_ROUND_AUTH),
            Some(&[1, 7, 0, 5, 1]),
            None,
            &[timeout_avp(value)],
        );
        let parsed = parse(&wire).expect("Unsigned32 timeout parses");
        assert_eq!(
            parsed
                .multi_round_timeout
                .map(SwmMultiRoundTimeout::seconds),
            Some(value),
        );
        assert_eq!(
            encode(
                &swm::build_swm_diameter_eap_answer(
                    &parsed,
                    HOP_BY_HOP,
                    END_TO_END,
                    EncodeContext::default(),
                )
                .expect("Unsigned32 timeout rebuilds"),
            ),
            wire,
        );
    }
}

#[test]
fn consecutive_answers_retain_only_their_own_request_timeout() {
    let first = parse(&answer_wire(
        ResultWire::Base(DIAMETER_MULTI_ROUND_AUTH),
        Some(&[1, 7, 0, 5, 1]),
        None,
        &[timeout_avp(3)],
    ))
    .expect("first answer parses");
    let second = parse(&answer_wire(
        ResultWire::Base(DIAMETER_MULTI_ROUND_AUTH),
        Some(&[1, 8, 0, 5, 1]),
        None,
        &[timeout_avp(17)],
    ))
    .expect("second answer parses");
    assert_eq!(
        first.multi_round_timeout.map(SwmMultiRoundTimeout::seconds),
        Some(3),
    );
    assert_eq!(
        second
            .multi_round_timeout
            .map(SwmMultiRoundTimeout::seconds),
        Some(17),
    );
}

#[test]
fn actionable_timeout_requires_correlation_base_1001_and_actual_eap_payload_request() {
    let actionable = answer_wire(
        ResultWire::Base(DIAMETER_MULTI_ROUND_AUTH),
        Some(&[1, 7, 0, 5, 1]),
        None,
        &[timeout_avp(31)],
    );
    assert_eq!(
        correlated(&actionable)
            .current_eap_request_timeout()
            .map(SwmMultiRoundTimeout::seconds),
        Some(31),
    );

    let cases = [
        answer_wire(
            ResultWire::Experimental {
                vendor_id: VendorId::new(10_415),
                code: DIAMETER_MULTI_ROUND_AUTH,
            },
            Some(&[1, 7, 0, 5, 1]),
            None,
            &[timeout_avp(31)],
        ),
        answer_wire(
            ResultWire::Base(base::RESULT_CODE_DIAMETER_SUCCESS),
            Some(&[3, 7, 0, 4]),
            None,
            &[timeout_avp(31)],
        ),
        answer_wire(
            ResultWire::Base(4_001),
            Some(&[4, 7, 0, 4]),
            None,
            &[timeout_avp(31)],
        ),
        answer_wire(
            ResultWire::Base(2_002),
            Some(&[1, 7, 0, 5, 1]),
            None,
            &[timeout_avp(31)],
        ),
        answer_wire(
            ResultWire::Base(DIAMETER_MULTI_ROUND_AUTH),
            Some(&[1, 7, 0, 6, 1]),
            None,
            &[timeout_avp(31)],
        ),
        answer_wire(
            ResultWire::Base(DIAMETER_MULTI_ROUND_AUTH),
            None,
            Some(&[1, 7, 0, 5, 1]),
            &[timeout_avp(31)],
        ),
    ];
    for wire in cases {
        let raw = parse(&wire).expect("grammar-valid non-actionable fact parses");
        assert_eq!(
            raw.multi_round_timeout.map(SwmMultiRoundTimeout::seconds),
            Some(31),
        );
        assert_eq!(correlated(&wire).current_eap_request_timeout(), None);
    }
}

#[test]
fn malformed_identity_flags_width_and_duplicate_fail_closed() {
    for malformed in [
        raw_avp(WIRE_MULTI_ROUND_TIME_OUT, 0, None, &7_u32.to_be_bytes()),
        raw_avp(
            WIRE_MULTI_ROUND_TIME_OUT,
            AvpFlags::MANDATORY | AvpFlags::PROTECTED,
            None,
            &7_u32.to_be_bytes(),
        ),
        raw_avp(
            WIRE_MULTI_ROUND_TIME_OUT,
            AvpFlags::VENDOR | AvpFlags::MANDATORY,
            Some(VendorId::new(10_415)),
            &7_u32.to_be_bytes(),
        ),
        raw_avp(
            WIRE_MULTI_ROUND_TIME_OUT,
            AvpFlags::MANDATORY,
            None,
            &[0, 0, 7],
        ),
        raw_avp(
            WIRE_MULTI_ROUND_TIME_OUT,
            AvpFlags::MANDATORY,
            None,
            &[0, 0, 0, 0, 7],
        ),
    ] {
        assert!(parse(&answer_wire(
            ResultWire::Base(DIAMETER_MULTI_ROUND_AUTH),
            Some(&[1, 7, 0, 5, 1]),
            None,
            &[malformed],
        ))
        .is_err());
    }

    assert!(parse(&answer_wire(
        ResultWire::Base(DIAMETER_MULTI_ROUND_AUTH),
        Some(&[1, 7, 0, 5, 1]),
        None,
        &[timeout_avp(1), timeout_avp(2)],
    ))
    .is_err());
}

#[test]
fn foreign_code_collision_obeys_unknown_policy_without_shadowing_ietf_field() {
    let collision = raw_avp(
        WIRE_MULTI_ROUND_TIME_OUT,
        AvpFlags::VENDOR,
        Some(FOREIGN_VENDOR),
        &77_u32.to_be_bytes(),
    );
    let wire = answer_wire(
        ResultWire::Base(DIAMETER_MULTI_ROUND_AUTH),
        Some(&[1, 7, 0, 5, 1]),
        None,
        &[timeout_avp(9), collision.clone()],
    );
    let preserved = parse_with_policy(&wire, UnknownIePolicy::Preserve)
        .expect("optional foreign collision is retained");
    assert_eq!(
        preserved
            .multi_round_timeout
            .map(SwmMultiRoundTimeout::seconds),
        Some(9),
    );
    assert_eq!(preserved.extensions.len(), 1);
    let metadata = preserved
        .extensions
        .metadata()
        .next()
        .expect("one retained collision");
    assert_eq!(metadata.code(), WIRE_MULTI_ROUND_TIME_OUT);
    assert_eq!(metadata.vendor_id(), Some(FOREIGN_VENDOR));

    let dropped = parse_with_policy(&wire, UnknownIePolicy::Drop)
        .expect("optional foreign collision is droppable");
    assert_eq!(
        dropped
            .multi_round_timeout
            .map(SwmMultiRoundTimeout::seconds),
        Some(9),
    );
    assert!(dropped.extensions.is_empty());
    assert!(parse_with_policy(&wire, UnknownIePolicy::Reject).is_err());

    let mandatory = raw_avp(
        WIRE_MULTI_ROUND_TIME_OUT,
        AvpFlags::VENDOR | AvpFlags::MANDATORY,
        Some(FOREIGN_VENDOR),
        &77_u32.to_be_bytes(),
    );
    assert!(parse_with_policy(
        &answer_wire(
            ResultWire::Base(DIAMETER_MULTI_ROUND_AUTH),
            Some(&[1, 7, 0, 5, 1]),
            None,
            &[mandatory],
        ),
        UnknownIePolicy::Preserve,
    )
    .is_err());
}

#[test]
fn exact_ietf_timeout_is_forbidden_in_der_by_dictionary_and_typed_parser() {
    for flags in [0, AvpFlags::MANDATORY] {
        let wire = request_wire(Some(raw_avp(
            WIRE_MULTI_ROUND_TIME_OUT,
            flags,
            None,
            &5_u32.to_be_bytes(),
        )));
        assert!(swm::parse_swm_diameter_eap_request(
            &decode(&wire),
            typed_context(UnknownIePolicy::Preserve),
        )
        .is_err());
        for dictionaries in [SWM_DICTIONARIES, SWM_PROJECTED_DICTIONARIES] {
            assert!(Message::decode_with_dictionary(
                &wire,
                typed_context(UnknownIePolicy::Preserve),
                dictionaries,
            )
            .is_err());
        }
    }
}

#[test]
fn timeout_diagnostics_disclose_presence_only() {
    let timeout = SwmMultiRoundTimeout::from_seconds(2_147_483_646);
    assert_eq!(format!("{timeout:?}"), "SwmMultiRoundTimeout(<redacted>)");
    let wire = answer_wire(
        ResultWire::Base(DIAMETER_MULTI_ROUND_AUTH),
        Some(&[1, 7, 0, 5, 1]),
        None,
        &[timeout_avp(timeout.seconds())],
    );
    let raw_diagnostic = format!("{:?}", parse(&wire).expect("answer parses"));
    let correlated_diagnostic = format!("{:?}", correlated(&wire));
    for diagnostic in [&raw_diagnostic, &correlated_diagnostic] {
        for private in [
            "2147483646",
            "aaa-a.example",
            "epdg-a.example",
            "multi-round;1",
            "[1, 7, 0, 5, 1]",
        ] {
            assert!(!diagnostic.contains(private), "diagnostic leaked {private}");
        }
    }
    assert!(raw_diagnostic.contains("multi_round_timeout_present: true"));
    assert!(correlated_diagnostic.contains("current_eap_request_timeout_present: true"));

    let malformed = raw_avp(
        WIRE_MULTI_ROUND_TIME_OUT,
        AvpFlags::MANDATORY,
        None,
        &[0x7f, 0xfe, 0xfd],
    );
    let error = parse(&answer_wire(
        ResultWire::Base(DIAMETER_MULTI_ROUND_AUTH),
        Some(&[1, 7, 0, 5, 1]),
        None,
        &[malformed],
    ))
    .expect_err("wrong-width timeout fails closed");
    for diagnostic in [format!("{error}"), format!("{error:?}")] {
        for private in ["8388351", "7ffefd", "aaa-a.example", "epdg-a.example"] {
            assert!(!diagnostic.contains(private), "error leaked {private}");
        }
    }
}
