use bytes::BytesMut;
use opc_proto_gtpv2c::{
    decode_typed_ie_sequence, encode_typed_ie_sequence, TypedIeValue, IE_TYPE_BEARER_CONTEXT,
    IE_TYPE_RECOVERY,
};
use opc_protocol::{
    DecodeContext, DecodeErrorCode, DuplicateIePolicy, EncodeContext, UnknownIePolicy,
};

const UNKNOWN_A: u8 = 0xfa;
const UNKNOWN_B: u8 = 0xfb;

fn raw_ie(ie_type: u8, instance: u8, value: &[u8]) -> Vec<u8> {
    let length = u16::try_from(value.len()).expect("test IE value length fits u16");
    let mut encoded = Vec::with_capacity(value.len() + 4);
    encoded.push(ie_type);
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.push(instance & 0x0f);
    encoded.extend_from_slice(value);
    encoded
}

fn policy_context(unknown_ie_policy: UnknownIePolicy) -> DecodeContext {
    DecodeContext {
        unknown_ie_policy,
        ..DecodeContext::default()
    }
}

fn encode_typed(ies: &[opc_proto_gtpv2c::TypedIe<'_>]) -> Vec<u8> {
    let mut encoded = BytesMut::new();
    encode_typed_ie_sequence(ies, &mut encoded, EncodeContext::default())
        .expect("decoded test IEs re-encode");
    encoded.to_vec()
}

#[test]
fn top_level_unknown_policy_is_drop_preserve_or_reject() {
    let unknown_a = raw_ie(UNKNOWN_A, 1, &[0xaa, 0x01]);
    let recovery = raw_ie(IE_TYPE_RECOVERY, 0, &[7]);
    let unknown_b = raw_ie(UNKNOWN_B, 2, &[0xbb, 0x02]);
    let wire = [
        unknown_a.as_slice(),
        recovery.as_slice(),
        unknown_b.as_slice(),
    ]
    .concat();

    let dropped = decode_typed_ie_sequence(&wire, policy_context(UnknownIePolicy::Drop), 0)
        .expect("Drop omits unsupported IEs");
    assert_eq!(dropped.len(), 1);
    assert!(matches!(
        &dropped[0].value,
        TypedIeValue::Recovery(value) if value.restart_counter == 7
    ));
    assert_eq!(encode_typed(&dropped), recovery);

    let preserved = decode_typed_ie_sequence(&wire, policy_context(UnknownIePolicy::Preserve), 0)
        .expect("Preserve retains unsupported IEs");
    assert_eq!(
        preserved
            .iter()
            .map(|ie| (ie.ie_type(), ie.instance))
            .collect::<Vec<_>>(),
        vec![(UNKNOWN_A, 1), (IE_TYPE_RECOVERY, 0), (UNKNOWN_B, 2)]
    );
    assert!(matches!(&preserved[0].value, TypedIeValue::Raw(_)));
    assert!(matches!(&preserved[2].value, TypedIeValue::Raw(_)));
    assert_eq!(encode_typed(&preserved), wire);

    let error = decode_typed_ie_sequence(&wire, policy_context(UnknownIePolicy::Reject), 0)
        .expect_err("Reject fails on the first unsupported IE");
    assert_eq!(error.code(), &DecodeErrorCode::UnknownCriticalIe);
    assert_eq!(error.offset(), 0);
}

#[test]
fn nested_bearer_context_applies_the_same_unknown_policy() {
    let unknown_a = raw_ie(UNKNOWN_A, 1, &[0xaa]);
    let recovery = raw_ie(IE_TYPE_RECOVERY, 0, &[9]);
    let unknown_b = raw_ie(UNKNOWN_B, 2, &[0xbb]);
    let members = [
        unknown_a.as_slice(),
        recovery.as_slice(),
        unknown_b.as_slice(),
    ]
    .concat();
    let wire = raw_ie(IE_TYPE_BEARER_CONTEXT, 0, &members);

    let dropped = decode_typed_ie_sequence(&wire, policy_context(UnknownIePolicy::Drop), 0)
        .expect("nested Drop succeeds");
    let TypedIeValue::BearerContext(context) = &dropped[0].value else {
        panic!("expected Bearer Context");
    };
    assert_eq!(context.members.len(), 1);
    assert!(matches!(
        &context.members[0].value,
        TypedIeValue::Recovery(value) if value.restart_counter == 9
    ));

    let preserved = decode_typed_ie_sequence(&wire, policy_context(UnknownIePolicy::Preserve), 0)
        .expect("nested Preserve succeeds");
    let TypedIeValue::BearerContext(context) = &preserved[0].value else {
        panic!("expected Bearer Context");
    };
    assert_eq!(
        context
            .members
            .iter()
            .map(|ie| (ie.ie_type(), ie.instance))
            .collect::<Vec<_>>(),
        vec![(UNKNOWN_A, 1), (IE_TYPE_RECOVERY, 0), (UNKNOWN_B, 2)]
    );
    assert_eq!(encode_typed(&preserved), wire);

    let error = decode_typed_ie_sequence(&wire, policy_context(UnknownIePolicy::Reject), 0)
        .expect_err("nested Reject fails on the first unsupported member");
    assert_eq!(error.code(), &DecodeErrorCode::UnknownCriticalIe);
    assert_eq!(error.offset(), 4);
}

#[test]
fn dropped_unknown_duplicates_do_not_affect_retained_duplicate_policy() {
    let first_unknown = raw_ie(UNKNOWN_A, 3, &[0x11]);
    let recovery = raw_ie(IE_TYPE_RECOVERY, 0, &[4]);
    let last_unknown = raw_ie(UNKNOWN_A, 3, &[0x22]);
    let wire = [
        first_unknown.as_slice(),
        recovery.as_slice(),
        last_unknown.as_slice(),
    ]
    .concat();

    let dropped = decode_typed_ie_sequence(
        &wire,
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            duplicate_ie_policy: DuplicateIePolicy::Reject,
            ..DecodeContext::default()
        },
        0,
    )
    .expect("dropped duplicate unknown keys cannot trigger rejection");
    assert_eq!(encode_typed(&dropped), recovery);

    let first = decode_typed_ie_sequence(
        &wire,
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Preserve,
            duplicate_ie_policy: DuplicateIePolicy::First,
            ..DecodeContext::default()
        },
        0,
    )
    .expect("First keeps the first unknown duplicate deterministically");
    assert_eq!(
        first
            .iter()
            .map(|ie| (ie.ie_type(), ie.instance))
            .collect::<Vec<_>>(),
        vec![(UNKNOWN_A, 3), (IE_TYPE_RECOVERY, 0)]
    );
    assert_eq!(
        match &first[0].value {
            TypedIeValue::Raw(raw) => raw.value,
            other => panic!("expected raw unknown, got {other:?}"),
        },
        &[0x11]
    );

    let last = decode_typed_ie_sequence(
        &wire,
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Preserve,
            duplicate_ie_policy: DuplicateIePolicy::Last,
            ..DecodeContext::default()
        },
        0,
    )
    .expect("Last keeps the last unknown duplicate deterministically");
    assert_eq!(
        last.iter()
            .map(|ie| (ie.ie_type(), ie.instance))
            .collect::<Vec<_>>(),
        vec![(IE_TYPE_RECOVERY, 0), (UNKNOWN_A, 3)]
    );
    assert_eq!(
        match &last[1].value {
            TypedIeValue::Raw(raw) => raw.value,
            other => panic!("expected raw unknown, got {other:?}"),
        },
        &[0x22]
    );

    let error = decode_typed_ie_sequence(
        &wire,
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Preserve,
            duplicate_ie_policy: DuplicateIePolicy::Reject,
            ..DecodeContext::default()
        },
        0,
    )
    .expect_err("preserved duplicate unknown keys obey Reject");
    assert_eq!(error.code(), &DecodeErrorCode::DuplicateIe);
}

#[test]
fn drop_still_enforces_wire_bounds_and_counts_every_input_ie() {
    let unknown = raw_ie(UNKNOWN_A, 0, &[0x11]);
    let three_unknown = [unknown.as_slice(), unknown.as_slice(), unknown.as_slice()].concat();
    let count_error = decode_typed_ie_sequence(
        &three_unknown,
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            duplicate_ie_policy: DuplicateIePolicy::First,
            max_ies: 2,
            ..DecodeContext::default()
        },
        0,
    )
    .expect_err("dropped IEs still count toward max_ies");
    assert_eq!(count_error.code(), &DecodeErrorCode::IeCountExceeded);

    let truncated = [UNKNOWN_A, 0, 4, 0, 0xaa];
    let truncation_error =
        decode_typed_ie_sequence(&truncated, policy_context(UnknownIePolicy::Drop), 0)
            .expect_err("Drop cannot bypass an invalid unknown IE boundary");
    assert_eq!(truncation_error.code(), &DecodeErrorCode::Truncated);
}
