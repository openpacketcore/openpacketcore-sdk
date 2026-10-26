use opc_proto_gtpu::{GtpuControlCodecErrorCode, GtpuControlMessage};
use opc_protocol::{DecodeContext, EncodeContext, UnknownIePolicy, ValidationLevel};

fn wire(kind: u8, ies: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0x32, kind, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0];
    bytes.extend_from_slice(ies);
    bytes[2..4].copy_from_slice(&((ies.len() + 4) as u16).to_be_bytes());
    bytes
}

#[test]
fn unexpected_defined_elements_are_skipped_but_truncation_still_fails() {
    for level in [
        ValidationLevel::Structural,
        ValidationLevel::Strict,
        ValidationLevel::ProcedureAware,
    ] {
        let ctx = DecodeContext {
            validation_level: level,
            ..DecodeContext::default()
        };
        for ies in [
            &[14, 5][..],
            &[16, 0, 0, 0, 1],
            &[133, 0, 4, 192, 0, 2, 1],
            &[230, 0, 1, 1],
        ] {
            let bytes = wire(1, ies);
            let msg = GtpuControlMessage::decode_datagram(&bytes, ctx).unwrap();
            assert_eq!(
                msg.to_bytes(EncodeContext::default()).unwrap().as_ref(),
                wire(1, &[])
            );
            let short = wire(1, &ies[..ies.len() - 1]);
            assert_eq!(
                GtpuControlMessage::decode_datagram(&short, ctx)
                    .unwrap_err()
                    .code(),
                &GtpuControlCodecErrorCode::TruncatedIe
            );
        }
        let msg = GtpuControlMessage::decode_datagram(
            &wire(26, &[14, 5, 16, 0, 0, 0, 7, 133, 0, 4, 192, 0, 2, 1]),
            ctx,
        )
        .unwrap();
        let GtpuControlMessage::ErrorIndication(value) = msg else {
            panic!()
        };
        assert_eq!(value.teid_data_i().value(), 7);
    }
}

#[test]
fn repeated_elements_use_first_value_and_private_extensions_can_repeat() {
    for duplicate_ie_policy in [
        opc_protocol::DuplicateIePolicy::First,
        opc_protocol::DuplicateIePolicy::Last,
        opc_protocol::DuplicateIePolicy::Reject,
    ] {
        let ctx = DecodeContext {
            duplicate_ie_policy,
            ..DecodeContext::default()
        };
        for (kind, repeated, first) in [
            (2, vec![14, 0, 14, 5], vec![14, 0]),
            (
                26,
                vec![16, 0, 0, 0, 7, 16, 0, 0, 0, 9, 133, 0, 4, 192, 0, 2, 1],
                vec![16, 0, 0, 0, 7, 133, 0, 4, 192, 0, 2, 1],
            ),
            (31, vec![141, 1, 0x40, 141, 1, 0x85], vec![141, 1, 0x40]),
            (
                1,
                vec![231, 0, 4, 0, 0, 0, 1, 231, 0, 4, 0, 0, 0, 2],
                vec![231, 0, 4, 0, 0, 0, 1],
            ),
        ] {
            let msg = GtpuControlMessage::decode_datagram(&wire(kind, &repeated), ctx).unwrap();
            let canonical = GtpuControlMessage::decode_datagram(&wire(kind, &first), ctx).unwrap();
            assert_eq!(msg, canonical);
        }
    }
    let ies = [255, 0, 2, 0, 1, 255, 0, 2, 0, 2];
    let msg =
        GtpuControlMessage::decode_datagram(&wire(1, &ies), DecodeContext::default()).unwrap();
    assert_eq!(
        msg.to_bytes(EncodeContext::default()).unwrap().as_ref(),
        wire(1, &ies)
    );
}

#[test]
fn unknown_tlv_reject_policy_obeys_the_receiver_skip_rule() {
    let ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Reject,
        ..DecodeContext::default()
    };
    let msg = GtpuControlMessage::decode_datagram(&wire(1, &[200, 0, 1, 9]), ctx).unwrap();
    assert_eq!(
        msg.to_bytes(EncodeContext::default()).unwrap().as_ref(),
        wire(1, &[])
    );
}

#[test]
fn defined_tv_lengths_allow_skip_without_losing_following_ies() {
    // Independently transcribed from TS 29.060 V19.0.0 Table 37.
    for (kind, len) in [
        (1, 1),
        (2, 8),
        (3, 6),
        (4, 4),
        (5, 4),
        (8, 1),
        (9, 28),
        (11, 1),
        (12, 3),
        (13, 1),
        (14, 1),
        (15, 1),
        (16, 4),
        (17, 4),
        (18, 5),
        (19, 1),
        (20, 1),
        (21, 1),
        (22, 9),
        (23, 1),
        (24, 1),
        (25, 2),
        (26, 2),
        (27, 2),
        (28, 2),
        (29, 1),
        (127, 4),
    ] {
        let mut ies = vec![kind];
        ies.resize(len + 1, 0);
        let short = wire(1, &ies[..len]);
        assert_eq!(
            GtpuControlMessage::decode_datagram(&short, DecodeContext::default())
                .unwrap_err()
                .code(),
            &GtpuControlCodecErrorCode::TruncatedIe
        );
        ies.extend_from_slice(&[231, 0, 4, 0, 0, 0, 7]);
        let actual =
            GtpuControlMessage::decode_datagram(&wire(1, &ies), DecodeContext::default()).unwrap();
        let expected = GtpuControlMessage::decode_datagram(
            &wire(1, &[231, 0, 4, 0, 0, 0, 7]),
            DecodeContext::default(),
        )
        .unwrap();
        assert_eq!(actual, expected, "TV type {kind}");
    }
}

#[test]
fn ignored_elements_still_consume_bounds_and_require_complete_framing() {
    for ies in [&[14, 0, 14][..], &[231, 0, 4, 0, 0, 0, 1, 231, 0, 4, 0]] {
        assert_eq!(
            GtpuControlMessage::decode_datagram(&wire(2, ies), DecodeContext::default())
                .unwrap_err()
                .code(),
            &GtpuControlCodecErrorCode::TruncatedIe
        );
    }
    let ctx = DecodeContext {
        max_ies: 1,
        ..DecodeContext::default()
    };
    assert_eq!(
        GtpuControlMessage::decode_datagram(&wire(1, &[14, 0, 14, 0]), ctx)
            .unwrap_err()
            .code(),
        &GtpuControlCodecErrorCode::IeCountExceeded
    );
    // An ignored repeat need not have a semantically valid value, only framing.
    let msg = GtpuControlMessage::decode_datagram(
        &wire(1, &[231, 0, 4, 0, 0, 0, 1, 231, 0, 0]),
        DecodeContext::default(),
    )
    .unwrap();
    let expected = GtpuControlMessage::decode_datagram(
        &wire(1, &[231, 0, 4, 0, 0, 0, 1]),
        DecodeContext::default(),
    )
    .unwrap();
    assert_eq!(msg, expected);
}
