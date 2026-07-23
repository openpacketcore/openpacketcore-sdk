use bytes::{Bytes, BytesMut};
use opc_proto_pfcp::{
    heartbeat_request_with_recovery,
    ie::{decode_typed_ie_sequence, RecoveryTimeStamp, TypedIe},
    profile::ProfileValidationError,
    InformationElement,
};
use opc_protocol::{DecodeContext, DecodeErrorCode, EncodeContext, UnknownIePolicy};

const CREATE_PDR: u16 = 1;
const PDR_ID: u16 = 56;
const RECOVERY_TIME_STAMP: u16 = 96;
const UNKNOWN_A: u16 = 500;
const UNKNOWN_B: u16 = 501;

fn raw_ie(ie_type: u16, value: &[u8]) -> Vec<u8> {
    let length = u16::try_from(value.len()).expect("test IE value length fits u16");
    let mut encoded = Vec::with_capacity(value.len() + 4);
    encoded.extend_from_slice(&ie_type.to_be_bytes());
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(value);
    encoded
}

fn policy_context(unknown_ie_policy: UnknownIePolicy) -> DecodeContext {
    DecodeContext {
        unknown_ie_policy,
        ..DecodeContext::default()
    }
}

fn encode_typed(ies: &[TypedIe]) -> Vec<u8> {
    let mut encoded = BytesMut::new();
    for ie in ies {
        ie.encode(&mut encoded, EncodeContext::default())
            .expect("decoded test IE re-encodes");
    }
    encoded.to_vec()
}

#[test]
fn top_level_sequence_applies_drop_preserve_and_reject() {
    let unknown_a = raw_ie(UNKNOWN_A, &[0xaa, 0x01]);
    let recovery = raw_ie(RECOVERY_TIME_STAMP, &[0, 0, 0, 7]);
    let unknown_b = raw_ie(UNKNOWN_B, &[0xbb, 0x02]);
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
        &dropped[0],
        TypedIe::RecoveryTimeStamp(value) if value.seconds == 7
    ));
    assert_eq!(encode_typed(&dropped), recovery);

    let preserved = decode_typed_ie_sequence(&wire, policy_context(UnknownIePolicy::Preserve), 0)
        .expect("Preserve retains unsupported IEs");
    assert_eq!(
        preserved.iter().map(TypedIe::ie_type).collect::<Vec<_>>(),
        vec![UNKNOWN_A, RECOVERY_TIME_STAMP, UNKNOWN_B]
    );
    assert!(matches!(&preserved[0], TypedIe::Raw(_)));
    assert!(matches!(&preserved[2], TypedIe::Raw(_)));
    assert_eq!(encode_typed(&preserved), wire);

    let error = decode_typed_ie_sequence(&wire, policy_context(UnknownIePolicy::Reject), 0)
        .expect_err("Reject fails on the first unsupported IE");
    assert_eq!(error.code(), &DecodeErrorCode::UnknownCriticalIe);
}

#[test]
fn grouped_sequence_applies_the_same_unknown_policy() {
    let unknown_a = raw_ie(UNKNOWN_A, &[0xaa]);
    let pdr_id = raw_ie(PDR_ID, &[0, 7]);
    let unknown_b = raw_ie(UNKNOWN_B, &[0xbb]);
    let members = [
        unknown_a.as_slice(),
        pdr_id.as_slice(),
        unknown_b.as_slice(),
    ]
    .concat();
    let wire = raw_ie(CREATE_PDR, &members);

    let dropped = decode_typed_ie_sequence(&wire, policy_context(UnknownIePolicy::Drop), 0)
        .expect("nested Drop succeeds");
    let TypedIe::CreatePdr(create_pdr) = &dropped[0] else {
        panic!("expected Create PDR");
    };
    assert_eq!(create_pdr.members.len(), 1);
    assert!(matches!(
        &create_pdr.members[0],
        TypedIe::PdrId(value) if value.value == 7
    ));

    let preserved = decode_typed_ie_sequence(&wire, policy_context(UnknownIePolicy::Preserve), 0)
        .expect("nested Preserve succeeds");
    let TypedIe::CreatePdr(create_pdr) = &preserved[0] else {
        panic!("expected Create PDR");
    };
    assert_eq!(
        create_pdr
            .members
            .iter()
            .map(TypedIe::ie_type)
            .collect::<Vec<_>>(),
        vec![UNKNOWN_A, PDR_ID, UNKNOWN_B]
    );
    assert_eq!(encode_typed(&preserved), wire);

    let error = decode_typed_ie_sequence(&wire, policy_context(UnknownIePolicy::Reject), 0)
        .expect_err("nested Reject fails on the first unsupported member");
    assert_eq!(error.code(), &DecodeErrorCode::UnknownCriticalIe);
}

#[test]
fn unknown_duplicates_keep_wire_order_or_drop_without_bypassing_limits() {
    let first_unknown = raw_ie(UNKNOWN_A, &[0x11]);
    let recovery = raw_ie(RECOVERY_TIME_STAMP, &[0, 0, 0, 9]);
    let last_unknown = raw_ie(UNKNOWN_A, &[0x22]);
    let wire = [
        first_unknown.as_slice(),
        recovery.as_slice(),
        last_unknown.as_slice(),
    ]
    .concat();

    let dropped = decode_typed_ie_sequence(&wire, policy_context(UnknownIePolicy::Drop), 0)
        .expect("Drop omits both unknown occurrences");
    assert_eq!(encode_typed(&dropped), recovery);

    let preserved = decode_typed_ie_sequence(&wire, policy_context(UnknownIePolicy::Preserve), 0)
        .expect("Preserve keeps duplicate unknown entries in wire order");
    assert_eq!(
        preserved.iter().map(TypedIe::ie_type).collect::<Vec<_>>(),
        vec![UNKNOWN_A, RECOVERY_TIME_STAMP, UNKNOWN_A]
    );
    assert_eq!(
        match &preserved[0] {
            TypedIe::Raw(raw) => raw.value.as_ref(),
            other => panic!("expected raw unknown, got {other:?}"),
        },
        &[0x11]
    );
    assert_eq!(
        match &preserved[2] {
            TypedIe::Raw(raw) => raw.value.as_ref(),
            other => panic!("expected raw unknown, got {other:?}"),
        },
        &[0x22]
    );
    assert_eq!(encode_typed(&preserved), wire);

    let error = decode_typed_ie_sequence(
        &wire,
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            max_ies: 2,
            ..DecodeContext::default()
        },
        0,
    )
    .expect_err("dropped IEs still count toward max_ies");
    assert_eq!(error.code(), &DecodeErrorCode::IeCountExceeded);

    let truncated = [0x01, 0xf4, 0x00, 0x04, 0xaa];
    let truncation_error =
        decode_typed_ie_sequence(&truncated, policy_context(UnknownIePolicy::Drop), 0)
            .expect_err("Drop cannot bypass an invalid unknown IE boundary");
    assert_eq!(truncation_error.code(), &DecodeErrorCode::Truncated);
}

#[test]
fn single_ie_api_explicitly_preserves_when_drop_cannot_be_represented() {
    let unknown = raw_ie(UNKNOWN_A, &[0xde, 0xad]);
    let (remaining, decoded) = TypedIe::decode(&unknown, policy_context(UnknownIePolicy::Drop), 0)
        .expect("single-IE compatibility API remains total");

    assert!(remaining.is_empty());
    assert!(matches!(decoded, TypedIe::Raw(_)));
}

#[test]
fn production_profile_uses_the_policy_enforcing_sequence_boundary() {
    let mut message = heartbeat_request_with_recovery(7, RecoveryTimeStamp { seconds: 9 })
        .expect("profile fixture builds");
    message.ies.insert(
        0,
        InformationElement {
            ie_type: UNKNOWN_A,
            enterprise_id: 0,
            value: Bytes::from_static(&[0xa5, 0x5a]),
        },
    );

    message
        .validate_production_v1(policy_context(UnknownIePolicy::Drop))
        .expect("Drop omits the unknown top-level typed entry");
    message
        .validate_production_v1(policy_context(UnknownIePolicy::Preserve))
        .expect("Preserve retains an ignored raw optional entry");

    let error = message
        .validate_production_v1(policy_context(UnknownIePolicy::Reject))
        .expect_err("Reject must fail the profile boundary");
    let ProfileValidationError::TypedDecode { source, .. } = error else {
        panic!("expected typed decode error");
    };
    assert_eq!(source.code(), &DecodeErrorCode::UnknownCriticalIe);

    message.ies.insert(
        0,
        InformationElement {
            ie_type: UNKNOWN_B,
            enterprise_id: 0,
            value: Bytes::from_static(&[0x11]),
        },
    );
    let count_error = message
        .validate_production_v1(DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            max_ies: 2,
            ..DecodeContext::default()
        })
        .expect_err("profile Drop cannot bypass the top-level IE-count bound");
    let ProfileValidationError::TypedDecode { source, .. } = count_error else {
        panic!("expected typed decode error");
    };
    assert_eq!(source.code(), &DecodeErrorCode::IeCountExceeded);
}
