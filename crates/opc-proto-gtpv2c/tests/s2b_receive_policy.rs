//! TS 29.274 clauses 7.7.9 and 7.7.10 receive-policy evidence.

use bytes::{Bytes, BytesMut};
use opc_proto_gtpv2c::{
    encode_typed_ie_sequence, CauseValue, ChargingId, EpsBearerId, Header, Message, OwnedMessage,
    RawIe, Recovery, S2bMessage, TypedIe, TypedIeValue, IE_TYPE_AMBR, IE_TYPE_APCO, IE_TYPE_APN,
    IE_TYPE_APN_RESTRICTION, IE_TYPE_BEARER_CONTEXT, IE_TYPE_BEARER_QOS, IE_TYPE_CAUSE,
    IE_TYPE_CHARGING_ID, IE_TYPE_EBI, IE_TYPE_F_TEID, IE_TYPE_LOAD_CONTROL_INFORMATION,
    IE_TYPE_OVERLOAD_CONTROL_INFORMATION, IE_TYPE_PCO, IE_TYPE_PDN_TYPE, IE_TYPE_PGW_CHANGE_INFO,
    IE_TYPE_RECOVERY, IE_TYPE_SERVING_NETWORK, MAX_PGW_APN_LOAD_CONTROL_INFORMATION_IES,
    MAX_PGW_OVERLOAD_CONTROL_INFORMATION_IES,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, DuplicateIePolicy, Encode, EncodeContext,
    ValidationLevel,
};

const ECHO_REQUEST_FIXTURE: &[u8] = include_bytes!("fixtures/spec/echo_request_recovery.bin");
const CREATE_SESSION_REQUEST_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/create_session_request_s2b_subset.bin");
const CREATE_SESSION_RESPONSE_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/create_session_response_s2b_subset.bin");
const MODIFY_BEARER_REQUEST_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/modify_bearer_request_bearer_context.bin");
const MODIFY_BEARER_RESPONSE_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/modify_bearer_response_cause.bin");
const DELETE_SESSION_RESPONSE_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/delete_session_response_cause.bin");
const CREATE_BEARER_REQUEST_FIXTURE: &[u8] =
    include_bytes!("fixtures/spec/create_bearer_request_s2b.bin");

fn procedure_context() -> DecodeContext {
    DecodeContext {
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    }
}

fn structural_context() -> DecodeContext {
    DecodeContext {
        duplicate_ie_policy: DuplicateIePolicy::First,
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    }
}

fn raw_ie_boundaries(raw_ies: &[u8]) -> Vec<usize> {
    let mut boundaries = vec![0];
    let mut offset = 0usize;
    while offset < raw_ies.len() {
        assert!(raw_ies.len().saturating_sub(offset) >= 4);
        let value_len = usize::from(u16::from_be_bytes([
            raw_ies[offset + 1],
            raw_ies[offset + 2],
        ]));
        offset = offset.saturating_add(4).saturating_add(value_len);
        assert!(offset <= raw_ies.len());
        boundaries.push(offset);
    }
    boundaries
}

fn encode_raw_message(header: Header, raw_ies: Vec<u8>) -> Vec<u8> {
    let message = OwnedMessage {
        header,
        raw_ies: Bytes::from(raw_ies),
    };
    let mut encoded = BytesMut::new();
    message
        .encode(&mut encoded, EncodeContext::default())
        .expect("test message must encode");
    encoded.to_vec()
}

fn append_raw_ies(fixture: &'static [u8], appended: &[u8]) -> Vec<u8> {
    let (_, message) = Message::decode(fixture, structural_context()).expect("fixture decodes");
    let mut raw_ies = message.raw_ies.to_vec();
    raw_ies.extend_from_slice(appended);
    encode_raw_message(message.header, raw_ies)
}

fn raw_ie(ie_type: u8, instance: u8, value: &[u8]) -> Vec<u8> {
    let value_len = u16::try_from(value.len()).expect("test IE value fits u16");
    let mut encoded = Vec::with_capacity(value.len().saturating_add(4));
    encoded.push(ie_type);
    encoded.extend_from_slice(&value_len.to_be_bytes());
    encoded.push(instance & 0x0f);
    encoded.extend_from_slice(value);
    encoded
}

fn bearer_context(instance: u8, members: &[u8]) -> Vec<u8> {
    raw_ie(IE_TYPE_BEARER_CONTEXT, instance, members)
}

fn duplicate_singleton_at(
    fixture: &'static [u8],
    ie_type: u8,
    instance: u8,
    placement: usize,
    change_value: bool,
) -> Vec<u8> {
    let (_, message) = Message::decode(fixture, structural_context()).expect("fixture decodes");
    let boundaries = raw_ie_boundaries(message.raw_ies);
    let mut target = None;
    for window in boundaries.windows(2) {
        let start = window[0];
        if message.raw_ies[start] == ie_type && message.raw_ies[start + 3] & 0x0f == instance {
            target = Some((start, window[1]));
            break;
        }
    }
    let (target_start, target_end) = target.expect("target singleton exists");
    let mut duplicate = message.raw_ies[target_start..target_end].to_vec();
    if change_value {
        let last = duplicate.last_mut().expect("typed singleton has a value");
        *last ^= 1;
    }

    let eligible: Vec<usize> = boundaries
        .into_iter()
        .filter(|boundary| *boundary >= target_end)
        .collect();
    let insertion = match placement {
        0 => eligible[0],
        1 => eligible[eligible.len() / 2],
        _ => *eligible.last().expect("at least one insertion boundary"),
    };
    let mut raw_ies = message.raw_ies.to_vec();
    raw_ies.splice(insertion..insertion, duplicate);
    encode_raw_message(message.header, raw_ies)
}

fn first_u8_value(message: &S2bMessage<'_>, ie_type: u8) -> u8 {
    let ie = message
        .as_view()
        .expect("typed S2b view")
        .ies
        .iter()
        .find(|ie| ie.ie_type() == ie_type && ie.instance == 0)
        .expect("retained singleton");
    match &ie.value {
        TypedIeValue::Recovery(value) => value.restart_counter,
        TypedIeValue::Cause(value) => u8::from(value.value),
        TypedIeValue::EpsBearerId(value) => value.value,
        TypedIeValue::Imsi(value) => value
            .digits
            .as_bytes()
            .last()
            .copied()
            .expect("fixture IMSI is non-empty"),
        value => panic!("unexpected singleton value: {value:?}"),
    }
}

#[test]
fn procedure_receive_is_first_wins_at_beginning_middle_and_end() {
    let fixtures = [
        (ECHO_REQUEST_FIXTURE, IE_TYPE_RECOVERY, 42),
        (CREATE_SESSION_REQUEST_FIXTURE, 1, b'9'),
        (MODIFY_BEARER_RESPONSE_FIXTURE, IE_TYPE_CAUSE, 16),
        (DELETE_SESSION_RESPONSE_FIXTURE, IE_TYPE_CAUSE, 16),
        (CREATE_BEARER_REQUEST_FIXTURE, IE_TYPE_EBI, 5),
    ];

    for (fixture, ie_type, expected) in fixtures {
        for placement in 0..3 {
            let bytes = duplicate_singleton_at(fixture, ie_type, 0, placement, true);
            let (tail, decoded) = S2bMessage::decode_with_diagnostics(&bytes, procedure_context())
                .expect("procedure receive must ignore a later singleton");
            assert!(tail.is_empty());
            assert_eq!(first_u8_value(decoded.message(), ie_type), expected);
            let evidence = decoded.diagnostics().duplicate_ies();
            assert_eq!(evidence.len(), 1);
            assert_eq!(evidence[0].ie_type(), ie_type);
            assert_eq!(evidence[0].instance(), 0);
            assert_eq!(evidence[0].depth(), 0);
            assert_eq!(evidence[0].duplicate_count(), 1);
        }
    }
}

#[test]
fn every_top_level_singleton_in_representative_fixtures_accepts_same_value_repetition() {
    let fixtures = [
        ECHO_REQUEST_FIXTURE,
        CREATE_SESSION_REQUEST_FIXTURE,
        MODIFY_BEARER_RESPONSE_FIXTURE,
        DELETE_SESSION_RESPONSE_FIXTURE,
        CREATE_BEARER_REQUEST_FIXTURE,
    ];
    for fixture in fixtures {
        let (_, message) = Message::decode(fixture, structural_context()).expect("fixture decodes");
        let boundaries = raw_ie_boundaries(message.raw_ies);
        let keys: Vec<(u8, u8)> = boundaries
            .windows(2)
            .filter_map(|window| {
                let offset = window[0];
                let key = (message.raw_ies[offset], message.raw_ies[offset + 3] & 0x0f);
                (!matches!(key, (93, 0) | (IE_TYPE_EBI, 1))).then_some(key)
            })
            .collect();
        for (ie_type, instance) in keys {
            for placement in 0..3 {
                let bytes = duplicate_singleton_at(fixture, ie_type, instance, placement, false);
                let (_, decoded) = S2bMessage::decode_with_diagnostics(&bytes, procedure_context())
                    .expect("same-value singleton repetition must be ignored");
                assert!(decoded
                    .diagnostics()
                    .duplicate_ies()
                    .iter()
                    .any(|entry| { entry.ie_type() == ie_type && entry.instance() == instance }));
            }
        }
    }
}

#[test]
fn unknown_optional_interleaving_does_not_change_first_wins_projection() {
    let duplicate = duplicate_singleton_at(ECHO_REQUEST_FIXTURE, IE_TYPE_RECOVERY, 0, 2, true);
    let (_, message) = Message::decode(&duplicate, structural_context()).expect("message decodes");
    let unknown = [245, 0, 2, 7, 0xde, 0xad];
    let mut raw_ies = message.raw_ies.to_vec();
    raw_ies.splice(5..5, unknown);
    let bytes = encode_raw_message(message.header, raw_ies);

    let (_, decoded) = S2bMessage::decode_with_diagnostics(&bytes, procedure_context())
        .expect("unknown optional IE must remain compatible with first-wins");
    assert_eq!(first_u8_value(decoded.message(), IE_TYPE_RECOVERY), 42);
    assert_eq!(decoded.diagnostics().duplicate_ies().len(), 1);
    assert!(decoded
        .message()
        .as_view()
        .expect("Echo view")
        .ies
        .iter()
        .any(|ie| ie.ie_type() == 245 && ie.instance == 7));
}

#[test]
fn nested_and_top_level_duplicate_scopes_are_independent() {
    let (_, decoded) = S2bMessage::decode(CREATE_BEARER_REQUEST_FIXTURE, structural_context())
        .expect("fixture decodes structurally");
    let view = decoded.as_view().expect("typed Create Bearer view");
    let mut ies = view.ies.clone();

    let top_ebi = ies
        .iter()
        .find(|ie| ie.ie_type() == IE_TYPE_EBI && ie.instance == 0)
        .expect("linked EBI")
        .clone();
    ies.insert(
        1,
        TypedIe {
            instance: 0,
            value: TypedIeValue::EpsBearerId(EpsBearerId { value: 6 }),
        },
    );
    let context = ies
        .iter_mut()
        .find_map(|ie| match &mut ie.value {
            TypedIeValue::BearerContext(context) => Some(context),
            _ => None,
        })
        .expect("bearer context");
    let nested_ebi = context
        .members
        .iter()
        .find(|ie| ie.ie_type() == IE_TYPE_EBI && ie.instance == 0)
        .expect("nested EBI")
        .clone();
    context.members.push(nested_ebi);

    let mut raw_ies = BytesMut::new();
    encode_typed_ie_sequence(&ies, &mut raw_ies, EncodeContext::default())
        .expect("mutated IE sequence encodes");
    let bytes = encode_raw_message(view.header.clone(), raw_ies.to_vec());
    let (_, decoded) = S2bMessage::decode_with_diagnostics(&bytes, procedure_context())
        .expect("independent scopes decode first-wins");
    assert_eq!(
        decoded
            .message()
            .as_view()
            .expect("typed view")
            .create_bearer_request()
            .expect("Create Bearer projection")
            .linked_ebi,
        match top_ebi.value {
            TypedIeValue::EpsBearerId(ebi) => ebi,
            _ => panic!("fixture linked EBI changed type"),
        }
    );
    let evidence = decoded.diagnostics().duplicate_ies();
    assert_eq!(evidence.len(), 2);
    assert!(evidence.iter().any(|entry| entry.depth() == 0));
    assert!(evidence.iter().any(|entry| entry.depth() == 1));
    assert_ne!(evidence[0].scope_offset(), evidence[1].scope_offset());
}

#[test]
fn repeatable_excess_is_ignored_at_the_table_bound() {
    let (_, decoded) = S2bMessage::decode(CREATE_BEARER_REQUEST_FIXTURE, structural_context())
        .expect("fixture decodes structurally");
    let view = decoded.as_view().expect("typed Create Bearer view");
    let mut ies = view.ies.clone();
    for _ in 0..=MAX_PGW_APN_LOAD_CONTROL_INFORMATION_IES {
        ies.push(TypedIe {
            instance: 1,
            value: TypedIeValue::Raw(RawIe {
                ie_type: IE_TYPE_LOAD_CONTROL_INFORMATION,
                instance: 1,
                spare: 0,
                value: &[1],
            }),
        });
    }
    let mut raw_ies = BytesMut::new();
    encode_typed_ie_sequence(&ies, &mut raw_ies, EncodeContext::default())
        .expect("repeatable fixture encodes");
    let bytes = encode_raw_message(view.header.clone(), raw_ies.to_vec());

    let (_, decoded) = S2bMessage::decode_with_diagnostics(&bytes, procedure_context())
        .expect("excess repeatable occurrence is ignored");
    let projected = decoded
        .message()
        .as_view()
        .expect("typed view")
        .create_bearer_request()
        .expect("Create Bearer projection");
    assert_eq!(
        projected
            .additional_ies
            .iter()
            .filter(|ie| { ie.ie_type() == IE_TYPE_LOAD_CONTROL_INFORMATION && ie.instance == 1 })
            .count(),
        MAX_PGW_APN_LOAD_CONTROL_INFORMATION_IES
    );
    assert!(decoded
        .diagnostics()
        .duplicate_ies()
        .iter()
        .any(|entry| entry.ie_type() == IE_TYPE_LOAD_CONTROL_INFORMATION));
}

#[test]
fn malformed_first_occurrence_is_not_repaired_by_a_later_valid_value() {
    let raw_ies = vec![
        IE_TYPE_RECOVERY,
        0,
        0,
        0, // malformed first Recovery: empty value
        IE_TYPE_RECOVERY,
        0,
        1,
        0,
        7,
    ];
    let (_, fixture) =
        Message::decode(ECHO_REQUEST_FIXTURE, structural_context()).expect("Echo fixture decodes");
    let bytes = encode_raw_message(fixture.header, raw_ies);
    let error = S2bMessage::decode(&bytes, procedure_context())
        .expect_err("later valid Recovery must not repair malformed first Recovery");
    assert!(matches!(
        error.code(),
        DecodeErrorCode::InvalidLength { .. }
    ));
}

#[test]
fn unexpected_known_instance_is_discarded_and_cannot_satisfy_required_ie() {
    let (_, fixture) =
        Message::decode(ECHO_REQUEST_FIXTURE, structural_context()).expect("Echo fixture decodes");
    let wrong = vec![IE_TYPE_RECOVERY, 0, 1, 1, 9];
    let only_wrong = encode_raw_message(fixture.header.clone(), wrong.clone());
    assert!(S2bMessage::decode(&only_wrong, procedure_context()).is_err());

    let mut with_expected = wrong;
    with_expected.extend_from_slice(&[IE_TYPE_RECOVERY, 0, 1, 0, 7]);
    let bytes = encode_raw_message(fixture.header, with_expected);
    let (_, decoded) = S2bMessage::decode(&bytes, procedure_context())
        .expect("unexpected instance is discarded when expected key exists");
    let view = decoded.as_view().expect("Echo view");
    assert_eq!(view.ies.len(), 1);
    assert_eq!(first_u8_value(&decoded, IE_TYPE_RECOVERY), 7);
}

#[test]
fn echo_discards_known_unexpected_type_but_preserves_unknown_optional_ie() {
    let (_, fixture) =
        Message::decode(ECHO_REQUEST_FIXTURE, structural_context()).expect("Echo fixture decodes");
    let mut raw_ies = vec![IE_TYPE_RECOVERY, 0, 1, 0, 42];
    raw_ies.extend_from_slice(&[
        IE_TYPE_APN,
        0,
        9,
        0,
        8,
        b'i',
        b'n',
        b't',
        b'e',
        b'r',
        b'n',
        b'e',
        b't',
    ]);
    raw_ies.extend_from_slice(&[245, 0, 2, 7, 0xde, 0xad]);
    let bytes = encode_raw_message(fixture.header, raw_ies);

    let (_, decoded) = S2bMessage::decode(&bytes, procedure_context())
        .expect("Echo must discard APN and continue");
    let ies = &decoded.as_view().expect("Echo view").ies;
    assert!(!ies.iter().any(|ie| ie.ie_type() == IE_TYPE_APN));
    assert!(ies.iter().any(|ie| ie.ie_type() == 245 && ie.instance == 7));
}

#[test]
fn procedure_families_discard_known_unexpected_types_and_preserve_unknown_optional_ies() {
    const UNKNOWN: &[u8] = &[245, 0, 2, 7, 0xde, 0xad];
    let cases: &[(&[u8], u8, &[u8])] = &[
        (
            ECHO_REQUEST_FIXTURE,
            IE_TYPE_APN,
            &[IE_TYPE_APN, 0, 2, 0, 1, b'x'],
        ),
        (
            CREATE_SESSION_REQUEST_FIXTURE,
            IE_TYPE_CAUSE,
            &[IE_TYPE_CAUSE, 0, 2, 0, 16, 0],
        ),
        (
            MODIFY_BEARER_RESPONSE_FIXTURE,
            IE_TYPE_APN,
            &[IE_TYPE_APN, 0, 2, 0, 1, b'x'],
        ),
        (
            DELETE_SESSION_RESPONSE_FIXTURE,
            IE_TYPE_APN,
            &[IE_TYPE_APN, 0, 2, 0, 1, b'x'],
        ),
        (
            CREATE_BEARER_REQUEST_FIXTURE,
            IE_TYPE_RECOVERY,
            &[IE_TYPE_RECOVERY, 0, 1, 0, 9],
        ),
    ];

    for (fixture, unexpected_type, unexpected) in cases {
        let mut appended = unexpected.to_vec();
        appended.extend_from_slice(UNKNOWN);
        let bytes = append_raw_ies(fixture, &appended);
        let (_, decoded) = S2bMessage::decode(&bytes, procedure_context())
            .expect("known unexpected IE must be discarded while processing continues");
        let ies = &decoded.as_view().expect("typed S2b view").ies;
        assert!(!ies.iter().any(|ie| ie.ie_type() == *unexpected_type));
        assert!(ies.iter().any(|ie| ie.ie_type() == 245 && ie.instance == 7));
    }
}

#[test]
fn known_unexpected_value_is_discarded_before_typed_value_decode() {
    let bytes = append_raw_ies(
        ECHO_REQUEST_FIXTURE,
        &[IE_TYPE_APN, 0, 0, 0], // APN value would fail typed decoding if interpreted.
    );
    let (_, decoded) = S2bMessage::decode(&bytes, procedure_context())
        .expect("known unexpected APN must be discarded at the TLIV boundary");
    assert_eq!(first_u8_value(&decoded, IE_TYPE_RECOVERY), 42);
    assert!(!decoded
        .as_view()
        .expect("Echo view")
        .ies
        .iter()
        .any(|ie| ie.ie_type() == IE_TYPE_APN));
}

#[test]
fn assigned_create_session_response_optionals_are_preserved() {
    let appended = [
        IE_TYPE_APN_RESTRICTION,
        0,
        1,
        0,
        0,
        IE_TYPE_AMBR,
        0,
        8,
        0,
        0,
        0,
        0,
        1,
        0,
        0,
        0,
        2,
        IE_TYPE_PCO,
        0,
        1,
        0,
        0x80,
        IE_TYPE_APCO,
        0,
        1,
        0,
        0x80,
        IE_TYPE_RECOVERY,
        0,
        1,
        0,
        9,
        IE_TYPE_CHARGING_ID,
        0,
        4,
        0,
        0x12,
        0x34,
        0x56,
        0x78,
    ];
    let bytes = append_raw_ies(CREATE_SESSION_RESPONSE_FIXTURE, &appended);
    let (_, decoded) = S2bMessage::decode(&bytes, procedure_context())
        .expect("assigned Create Session Response optionals must decode");
    let ies = &decoded.as_view().expect("typed response view").ies;
    for ie_type in [
        IE_TYPE_APN_RESTRICTION,
        IE_TYPE_AMBR,
        IE_TYPE_PCO,
        IE_TYPE_APCO,
        IE_TYPE_RECOVERY,
        IE_TYPE_CHARGING_ID,
    ] {
        assert!(ies
            .iter()
            .any(|ie| ie.ie_type() == ie_type && ie.instance == 0));
    }
}

#[test]
fn create_session_discards_unexpected_pdn_type_and_continues_processing() {
    let bytes = append_raw_ies(
        CREATE_SESSION_REQUEST_FIXTURE,
        &[IE_TYPE_PDN_TYPE, 0, 1, 0, 1],
    );
    let (_, decoded) = S2bMessage::decode(&bytes, procedure_context())
        .expect("unexpected PDN Type is discarded under clause 7.7.9");
    let view = decoded.as_view().expect("typed request view");
    assert!(view.has_ie(opc_proto_gtpv2c::IE_TYPE_PAA));
    assert!(!view.has_ie(IE_TYPE_PDN_TYPE));
}

#[test]
fn assigned_nested_create_session_response_charging_id_is_preserved() {
    let (_, decoded) = S2bMessage::decode(CREATE_SESSION_RESPONSE_FIXTURE, structural_context())
        .expect("fixture decodes structurally");
    let view = decoded.as_view().expect("typed response view");
    let mut ies = view.ies.clone();
    let context = ies
        .iter_mut()
        .find_map(|ie| match &mut ie.value {
            TypedIeValue::BearerContext(context) => Some(context),
            _ => None,
        })
        .expect("bearer context");
    context.members.push(TypedIe {
        instance: 0,
        value: TypedIeValue::ChargingId(ChargingId { value: 0x1234_5678 }),
    });

    let mut raw_ies = BytesMut::new();
    encode_typed_ie_sequence(&ies, &mut raw_ies, EncodeContext::default())
        .expect("mutated IE sequence encodes");
    let bytes = encode_raw_message(view.header.clone(), raw_ies.to_vec());
    let (_, decoded) = S2bMessage::decode(&bytes, procedure_context())
        .expect("assigned nested Charging ID must decode");
    let context = decoded
        .as_view()
        .expect("typed response view")
        .ies
        .iter()
        .find_map(|ie| match &ie.value {
            TypedIeValue::BearerContext(context) => Some(context),
            _ => None,
        })
        .expect("bearer context");
    assert!(context
        .members
        .iter()
        .any(|ie| ie.ie_type() == IE_TYPE_CHARGING_ID && ie.instance == 0));
}

#[test]
fn grouped_scope_discards_known_unexpected_type_and_preserves_unknown_optional_ie() {
    let (_, decoded) = S2bMessage::decode(CREATE_BEARER_REQUEST_FIXTURE, structural_context())
        .expect("fixture decodes structurally");
    let view = decoded.as_view().expect("typed Create Bearer view");
    let mut ies = view.ies.clone();
    let context = ies
        .iter_mut()
        .find_map(|ie| match &mut ie.value {
            TypedIeValue::BearerContext(context) => Some(context),
            _ => None,
        })
        .expect("bearer context");
    context.members.push(TypedIe {
        instance: 0,
        value: TypedIeValue::Recovery(Recovery { restart_counter: 9 }),
    });
    context.members.push(TypedIe {
        instance: 6,
        value: TypedIeValue::Raw(RawIe {
            ie_type: 244,
            instance: 6,
            spare: 0,
            value: &[0xca, 0xfe],
        }),
    });

    let mut raw_ies = BytesMut::new();
    encode_typed_ie_sequence(&ies, &mut raw_ies, EncodeContext::default())
        .expect("mutated IE sequence encodes");
    let bytes = encode_raw_message(view.header.clone(), raw_ies.to_vec());
    let (_, decoded) = S2bMessage::decode(&bytes, procedure_context())
        .expect("grouped known unexpected IE must be discarded");
    let context = decoded
        .as_view()
        .expect("typed view")
        .ies
        .iter()
        .find_map(|ie| match &ie.value {
            TypedIeValue::BearerContext(context) => Some(context),
            _ => None,
        })
        .expect("bearer context");
    assert!(!context
        .members
        .iter()
        .any(|ie| ie.ie_type() == IE_TYPE_RECOVERY));
    assert!(context
        .members
        .iter()
        .any(|ie| ie.ie_type() == 244 && ie.instance == 6));
}

fn assert_instance_one_discards_malformed_member(
    fixture: &'static [u8],
    required_members: &[u8],
    unexpected_type: u8,
) {
    let mut members = required_members.to_vec();
    members.extend_from_slice(&raw_ie(unexpected_type, 0, &[]));
    let bytes = append_raw_ies(fixture, &bearer_context(1, &members));
    let (_, decoded) = S2bMessage::decode(&bytes, procedure_context())
        .expect("instance-1 known-unexpected member must be discarded before value decoding");
    let context = decoded
        .as_view()
        .expect("typed view")
        .ies
        .iter()
        .find_map(|ie| match &ie.value {
            TypedIeValue::BearerContext(context) if ie.instance == 1 => Some(context),
            _ => None,
        })
        .expect("instance-1 bearer context");
    assert!(!context
        .members
        .iter()
        .any(|member| member.ie_type() == unexpected_type));
}

#[test]
fn every_instance_one_bearer_context_uses_its_own_member_table() {
    const EBI: &[u8] = &[IE_TYPE_EBI, 0, 1, 0, 6];
    const EBI_AND_CAUSE: &[u8] = &[IE_TYPE_EBI, 0, 1, 0, 6, IE_TYPE_CAUSE, 0, 2, 0, 16, 0];

    assert_instance_one_discards_malformed_member(
        CREATE_SESSION_REQUEST_FIXTURE,
        EBI,
        IE_TYPE_BEARER_QOS,
    );
    assert_instance_one_discards_malformed_member(
        CREATE_SESSION_RESPONSE_FIXTURE,
        EBI_AND_CAUSE,
        IE_TYPE_CHARGING_ID,
    );
    assert_instance_one_discards_malformed_member(
        MODIFY_BEARER_REQUEST_FIXTURE,
        EBI,
        IE_TYPE_F_TEID,
    );
    assert_instance_one_discards_malformed_member(
        MODIFY_BEARER_RESPONSE_FIXTURE,
        EBI_AND_CAUSE,
        IE_TYPE_CHARGING_ID,
    );
}

#[test]
fn instance_one_bearer_context_lists_preserve_multiple_entries() {
    const REQUEST_MEMBER_ONE: &[u8] = &[IE_TYPE_EBI, 0, 1, 0, 6];
    const REQUEST_MEMBER_TWO: &[u8] = &[IE_TYPE_EBI, 0, 1, 0, 7];
    const RESPONSE_MEMBER_ONE: &[u8] = &[IE_TYPE_EBI, 0, 1, 0, 6, IE_TYPE_CAUSE, 0, 2, 0, 16, 0];
    const RESPONSE_MEMBER_TWO: &[u8] = &[IE_TYPE_EBI, 0, 1, 0, 7, IE_TYPE_CAUSE, 0, 2, 0, 16, 0];
    let cases = [
        (
            CREATE_SESSION_REQUEST_FIXTURE,
            REQUEST_MEMBER_ONE,
            REQUEST_MEMBER_TWO,
        ),
        (
            CREATE_SESSION_RESPONSE_FIXTURE,
            RESPONSE_MEMBER_ONE,
            RESPONSE_MEMBER_TWO,
        ),
        (
            MODIFY_BEARER_REQUEST_FIXTURE,
            REQUEST_MEMBER_ONE,
            REQUEST_MEMBER_TWO,
        ),
        (
            MODIFY_BEARER_RESPONSE_FIXTURE,
            RESPONSE_MEMBER_ONE,
            RESPONSE_MEMBER_TWO,
        ),
    ];

    for (fixture, first, second) in cases {
        let mut appended = bearer_context(1, first);
        appended.extend_from_slice(&bearer_context(1, second));
        let bytes = append_raw_ies(fixture, &appended);
        let (_, decoded) = S2bMessage::decode_with_diagnostics(&bytes, procedure_context())
            .expect("table-declared instance-1 bearer-context list must be retained");
        assert_eq!(
            decoded
                .message()
                .as_view()
                .expect("typed view")
                .ies
                .iter()
                .filter(|ie| ie.ie_type() == IE_TYPE_BEARER_CONTEXT && ie.instance == 1)
                .count(),
            2
        );
        assert!(!decoded
            .diagnostics()
            .duplicate_ies()
            .iter()
            .any(|entry| { entry.ie_type() == IE_TYPE_BEARER_CONTEXT && entry.instance() == 1 }));
    }
}

#[test]
fn session_response_control_lists_preserve_first_n_and_report_excess() {
    let response_fixtures = [
        CREATE_SESSION_RESPONSE_FIXTURE,
        MODIFY_BEARER_RESPONSE_FIXTURE,
        DELETE_SESSION_RESPONSE_FIXTURE,
    ];
    let lists = [
        (
            IE_TYPE_LOAD_CONTROL_INFORMATION,
            1,
            MAX_PGW_APN_LOAD_CONTROL_INFORMATION_IES,
        ),
        (
            IE_TYPE_OVERLOAD_CONTROL_INFORMATION,
            0,
            MAX_PGW_OVERLOAD_CONTROL_INFORMATION_IES,
        ),
    ];

    for fixture in response_fixtures {
        for (ie_type, instance, limit) in lists {
            let mut appended = Vec::new();
            for value in 0..=limit {
                appended.extend_from_slice(&raw_ie(ie_type, instance, &[value as u8]));
            }
            let bytes = append_raw_ies(fixture, &appended);
            let (_, decoded) = S2bMessage::decode_with_diagnostics(&bytes, procedure_context())
                .expect("response list excess must be ignored");
            assert_eq!(
                decoded
                    .message()
                    .as_view()
                    .expect("typed view")
                    .ies
                    .iter()
                    .filter(|ie| ie.ie_type() == ie_type && ie.instance == instance)
                    .count(),
                limit
            );
            let evidence = decoded
                .diagnostics()
                .duplicate_ies()
                .iter()
                .find(|entry| entry.ie_type() == ie_type && entry.instance() == instance)
                .expect("bounded excess evidence");
            assert_eq!(evidence.duplicate_count(), 1);
        }
    }
}

#[test]
fn response_pgw_change_info_is_singleton_and_keeps_first_grouped_value() {
    let response_fixtures = [
        CREATE_SESSION_RESPONSE_FIXTURE,
        MODIFY_BEARER_RESPONSE_FIXTURE,
    ];
    for fixture in response_fixtures {
        let first_grouped_value = [74, 0, 4, 0, 192, 0, 2, 1];
        let mut appended = raw_ie(IE_TYPE_PGW_CHANGE_INFO, 0, &first_grouped_value);
        appended.extend_from_slice(&raw_ie(
            IE_TYPE_PGW_CHANGE_INFO,
            0,
            &[74, 0, 4, 0, 192, 0, 2, 2],
        ));
        appended.extend_from_slice(&raw_ie(
            IE_TYPE_PGW_CHANGE_INFO,
            0,
            // The nested child claims four value octets but supplies one. The
            // later duplicate must be discarded before grouped interpretation.
            &[74, 0, 4, 0, 192],
        ));
        let bytes = append_raw_ies(fixture, &appended);
        let (_, decoded) = S2bMessage::decode_with_diagnostics(&bytes, procedure_context())
            .expect("later PGW Change Info duplicates must not replace the first");
        let retained: Vec<_> = decoded
            .message()
            .as_view()
            .expect("typed view")
            .ies
            .iter()
            .filter(|ie| ie.ie_type() == IE_TYPE_PGW_CHANGE_INFO && ie.instance == 0)
            .collect();
        assert_eq!(retained.len(), 1);
        let TypedIeValue::Raw(raw) = &retained[0].value else {
            panic!("PGW Change Info is preserved as an inspectable grouped raw value");
        };
        assert_eq!(raw.value, first_grouped_value);
        let evidence = decoded
            .diagnostics()
            .duplicate_ies()
            .iter()
            .find(|entry| entry.ie_type() == IE_TYPE_PGW_CHANGE_INFO && entry.instance() == 0)
            .expect("singleton duplicate evidence");
        assert_eq!(evidence.duplicate_count(), 2);
    }
}

#[test]
fn modify_bearer_preserves_serving_network_and_top_and_nested_charging_ids() {
    let request = append_raw_ies(
        MODIFY_BEARER_REQUEST_FIXTURE,
        &raw_ie(IE_TYPE_SERVING_NETWORK, 0, &[0x00, 0xf1, 0x10]),
    );
    let (_, decoded) = S2bMessage::decode(&request, procedure_context())
        .expect("Modify Bearer Serving Network is assigned by Table 7.2.7-1");
    assert!(decoded
        .as_view()
        .expect("typed request")
        .ies
        .iter()
        .any(|ie| {
            ie.ie_type() == IE_TYPE_SERVING_NETWORK
                && matches!(ie.value, TypedIeValue::ServingNetwork(_))
        }));

    let mut response_members = raw_ie(IE_TYPE_EBI, 0, &[6]);
    response_members.extend_from_slice(&raw_ie(IE_TYPE_CAUSE, 0, &[16, 0]));
    response_members.extend_from_slice(&raw_ie(IE_TYPE_CHARGING_ID, 0, &[0x11, 0x22, 0x33, 0x44]));
    let mut response_append = raw_ie(IE_TYPE_CHARGING_ID, 0, &[0x55, 0x66, 0x77, 0x88]);
    response_append.extend_from_slice(&bearer_context(0, &response_members));
    let response = append_raw_ies(MODIFY_BEARER_RESPONSE_FIXTURE, &response_append);
    let (_, decoded) = S2bMessage::decode(&response, procedure_context())
        .expect("Modify Bearer top-level and nested Charging ID roles are assigned");
    let view = decoded.as_view().expect("typed response");
    assert!(view
        .ies
        .iter()
        .any(|ie| ie.ie_type() == IE_TYPE_CHARGING_ID && ie.instance == 0));
    let context = view
        .ies
        .iter()
        .find_map(|ie| match &ie.value {
            TypedIeValue::BearerContext(context) if ie.instance == 0 => Some(context),
            _ => None,
        })
        .expect("modified bearer context");
    assert!(context
        .members
        .iter()
        .any(|ie| ie.ie_type() == IE_TYPE_CHARGING_ID && ie.instance == 0));
}

#[test]
fn duplicate_diagnostics_are_bounded_and_redaction_safe() {
    let (_, fixture) =
        Message::decode(ECHO_REQUEST_FIXTURE, structural_context()).expect("Echo fixture decodes");
    let mut raw_ies = vec![IE_TYPE_RECOVERY, 0, 1, 0, 7];
    for index in 0..65u8 {
        let ie_type = 220u8.saturating_add(index / 16);
        let instance = index % 16;
        for secret in [0xa5, 0x5a] {
            raw_ies.extend_from_slice(&[ie_type, 0, 1, instance, secret]);
        }
    }
    let bytes = encode_raw_message(fixture.header, raw_ies);
    let (_, decoded) = S2bMessage::decode_with_diagnostics(&bytes, procedure_context())
        .expect("bounded duplicate fixture decodes");
    assert_eq!(decoded.diagnostics().duplicate_ies().len(), 64);
    assert_eq!(decoded.diagnostics().omitted_duplicate_count(), 1);
    let debug = format!("{:?}", decoded.diagnostics());
    assert!(!debug.contains("a5"));
    assert!(!debug.contains("5a"));
}

#[test]
fn normal_cause_projection_keeps_the_first_value() {
    let bytes = duplicate_singleton_at(MODIFY_BEARER_RESPONSE_FIXTURE, IE_TYPE_CAUSE, 0, 2, true);
    let (_, decoded) =
        S2bMessage::decode(&bytes, procedure_context()).expect("Modify Bearer response decodes");
    assert_eq!(
        CauseValue::from(first_u8_value(&decoded, IE_TYPE_CAUSE)),
        CauseValue::RequestAccepted
    );
}

#[test]
fn echo_projection_keeps_first_recovery_value() {
    let bytes = duplicate_singleton_at(ECHO_REQUEST_FIXTURE, IE_TYPE_RECOVERY, 0, 2, true);
    let (_, decoded) =
        S2bMessage::decode(&bytes, procedure_context()).expect("Echo request decodes");
    assert_eq!(
        first_u8_value(&decoded, IE_TYPE_RECOVERY),
        Recovery {
            restart_counter: 42
        }
        .restart_counter
    );
}
