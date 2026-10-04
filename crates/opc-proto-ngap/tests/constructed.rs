//! Construct from independent IE bytes, never from a decoded SDK message.

use bytes::{Bytes, BytesMut};
use opc_proto_ngap::{decode, encode, Criticality, Message, MessageType, Pdu, PduKind, ProtocolIe};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, DuplicateIePolicy, Encode, EncodeContext,
    EncodeErrorCode, OwnedDecode, UnknownIePolicy, ValidationLevel,
};
use sha2::{Digest, Sha256};

#[test]
fn constructed_ng_setup_has_no_received_bytes_and_matches_release18() {
    // TS 38.413 V18.10.0 9.2.6.1, independently encoded by the published
    // Pycrate oracle: GlobalN3IWF-ID, SupportedTAList and DefaultPagingDRX.
    let ies = [
        ProtocolIe::new(
            27,
            Criticality::reject,
            &[0x80, 0x00, 0xf1, 0x10, 0, 0, 0x80],
        ),
        ProtocolIe::new(
            102,
            Criticality::reject,
            &[0, 0, 0, 0, 1, 0, 0, 0xf1, 0x10, 0, 0, 0, 8],
        ),
        ProtocolIe::new(21, Criticality::ignore, &[0x40]),
    ];
    let pdu = Pdu::from_protocol_ies(MessageType::NgSetupRequest, &ies, DecodeContext::default())
        .expect("construct independent fields");
    assert!(pdu.raw.is_empty());
    let expected = [
        0x00, 0x15, 0x00, 0x24, 0x00, 0x00, 0x03, 0x00, 0x1b, 0x00, 0x07, 0x80, 0x00, 0xf1, 0x10,
        0x00, 0x00, 0x80, 0x00, 0x66, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0xf1,
        0x10, 0x00, 0x00, 0x00, 0x08, 0x00, 0x15, 0x40, 0x01, 0x40,
    ];
    assert!(encode(&pdu, EncodeContext::default()).expect("encode") == expected);
    assert_eq!(
        pdu.wire_len(EncodeContext::default()).expect("length"),
        expected.len()
    );
}

#[test]
fn independent_per_length_and_fragmentation_oracle_matches_all_outcomes() {
    let oracle: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/constructed-framing.json")).expect("oracle");
    let cases = oracle["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 54);
    for case in cases {
        let kind = match case["message"].as_str().expect("message") {
            "NGSetupRequest" => MessageType::NgSetupRequest,
            "NGSetupResponse" => MessageType::NgSetupResponse,
            "NGSetupFailure" => MessageType::NgSetupFailure,
            _ => panic!("oracle message"),
        };
        let size = case["value_len"].as_u64().expect("size") as usize;
        let value: Vec<_> = (0..size)
            .map(|index| ((index * 17 + 3) % 256) as u8)
            .collect();
        let pdu = Pdu::from_protocol_ies(
            kind,
            &[ProtocolIe::new(65535, Criticality::ignore, &value)],
            DecodeContext {
                max_message_len: 200_000,
                ..DecodeContext::default()
            },
        )
        .expect("construct");
        let ctx = EncodeContext {
            max_message_len: 200_000,
            ..EncodeContext::default()
        };
        let wire = encode(&pdu, ctx).expect("canonical");
        assert_eq!(
            wire.len(),
            case["wire_len"].as_u64().expect("length") as usize
        );
        assert_eq!(
            Sha256::digest(&wire)
                .iter()
                .map(|octet| format!("{octet:02x}"))
                .collect::<String>(),
            case["wire_sha256"].as_str().expect("digest")
        );
        assert_eq!(pdu.wire_len(ctx).expect("wire length"), wire.len());
        let received = Pdu::decode_owned(
            Bytes::from(wire.clone()),
            DecodeContext {
                max_message_len: 200_000,
                ..DecodeContext::default()
            },
        )
        .expect("receive");
        assert!(received.kind == pdu.kind);
        assert!(encode(&received, ctx).expect("receive canonical") == wire);
        // The exact limit succeeds; one byte too small fails before appending.
        let limited = EncodeContext {
            max_message_len: wire.len() - 1,
            ..ctx
        };
        let mut dst = BytesMut::from(&b"retained-prefix"[..]);
        assert!(matches!(
            pdu.encode(&mut dst, limited).unwrap_err().code(),
            EncodeErrorCode::CapacityExceeded { .. }
        ));
        assert!(&dst[..] == b"retained-prefix");
        assert!(pdu.wire_len(limited).is_err());
        assert!(encode(
            &pdu,
            EncodeContext {
                max_message_len: wire.len(),
                ..ctx
            }
        )
        .is_ok());
    }
}

fn paging_drx() -> ProtocolIe<'static> {
    ProtocolIe::new(21, Criticality::ignore, &[0x40])
}

fn constructed(ies: &[ProtocolIe<'_>], ctx: DecodeContext) -> Pdu {
    Pdu::from_protocol_ies(MessageType::NgSetupRequest, ies, ctx).expect("structural container")
}

fn message_mut(pdu: &mut Pdu) -> &mut Message {
    match &mut pdu.kind {
        PduKind::Initiating { message, .. }
        | PduKind::Successful { message, .. }
        | PduKind::Unsuccessful { message, .. } => message,
    }
}

#[test]
fn construction_applies_existing_count_depth_unknown_and_duplicate_policies() {
    let ies = [
        paging_drx(),
        ProtocolIe::new(21, Criticality::ignore, &[0x20]),
    ];
    let make = |ctx| Pdu::from_protocol_ies(MessageType::NgSetupRequest, &ies, ctx);
    assert_eq!(
        make(DecodeContext {
            duplicate_ie_policy: DuplicateIePolicy::Reject,
            ..DecodeContext::default()
        })
        .unwrap_err()
        .code(),
        &DecodeErrorCode::DuplicateIe
    );
    assert_eq!(
        make(DecodeContext {
            max_ies: 1,
            ..DecodeContext::default()
        })
        .unwrap_err()
        .code(),
        &DecodeErrorCode::IeCountExceeded
    );
    assert_eq!(
        make(DecodeContext {
            max_depth: 4,
            ..DecodeContext::default()
        })
        .unwrap_err()
        .code(),
        &DecodeErrorCode::DepthExceeded
    );
    for (duplicate_ie_policy, retained) in [
        (DuplicateIePolicy::First, 0x40),
        (DuplicateIePolicy::Last, 0x20),
    ] {
        let pdu = make(DecodeContext {
            duplicate_ie_policy,
            max_depth: 5,
            ..DecodeContext::default()
        })
        .expect("policy");
        let wire = encode(&pdu, EncodeContext::default()).expect("canonical filtered view");
        assert!(wire == [0, 21, 0, 8, 0, 0, 1, 0, 21, 0x40, 1, retained]);
    }
    let huge_count = vec![paging_drx(); 65536];
    assert_eq!(
        Pdu::from_protocol_ies(
            MessageType::NgSetupRequest,
            &huge_count,
            DecodeContext {
                max_ies: usize::MAX,
                max_message_len: usize::MAX,
                ..DecodeContext::default()
            }
        )
        .unwrap_err()
        .code(),
        &DecodeErrorCode::IeCountExceeded
    );

    for criticality in [
        Criticality::reject,
        Criticality::ignore,
        Criticality::notify,
    ] {
        let unknown = [ProtocolIe::new(65535, criticality, b"synthetic-private")];
        let make = |ctx| Pdu::from_protocol_ies(MessageType::NgSetupRequest, &unknown, ctx);
        assert!(make(DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..DecodeContext::default()
        })
        .is_err());
        if criticality == Criticality::reject {
            assert_eq!(
                make(DecodeContext {
                    validation_level: ValidationLevel::Strict,
                    ..DecodeContext::default()
                })
                .unwrap_err()
                .code(),
                &DecodeErrorCode::UnknownCriticalIe
            );
            let pdu = make(DecodeContext {
                validation_level: ValidationLevel::Structural,
                ..DecodeContext::default()
            })
            .expect("explicit permissive receive");
            assert!(encode(&pdu, EncodeContext::default()).is_err());
        } else {
            let preserved = make(DecodeContext::default()).expect("preserve");
            assert!(encode(&preserved, EncodeContext::default()).is_ok());
            let dropped = make(DecodeContext {
                unknown_ie_policy: UnknownIePolicy::Drop,
                ..DecodeContext::default()
            })
            .expect("drop");
            assert!(
                encode(&dropped, EncodeContext::default()).expect("empty container")
                    == [0, 21, 0, 3, 0, 0, 0]
            );
        }
    }
}

#[test]
fn raw_preserving_and_canonical_filtered_output_are_distinct() {
    // X.691/TS 38.413 root container: two singleton occurrences, an unknown
    // ignore IE, and no nested semantic claim. First/Last are caller policy.
    let wire = [
        0, 21, 0, 19, 0, 0, 3, 0, 21, 0x40, 1, 0x40, 0, 21, 0x40, 1, 0x20, 0xff, 0xff, 0x40, 2,
        0xab, 0xcd,
    ];
    let pdu = decode(
        &wire,
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            duplicate_ie_policy: DuplicateIePolicy::Last,
            ..DecodeContext::default()
        },
    )
    .expect("policy");
    assert!(
        encode(
            &pdu,
            EncodeContext {
                raw_preserving: true,
                ..EncodeContext::default()
            }
        )
        .expect("raw")
            == wire
    );
    assert!(
        encode(&pdu, EncodeContext::default()).expect("canonical")
            == [0, 21, 0, 8, 0, 0, 1, 0, 21, 0x40, 1, 0x20]
    );
    let fresh = constructed(&[paging_drx()], DecodeContext::default());
    assert!(encode(
        &fresh,
        EncodeContext {
            raw_preserving: true,
            ..EncodeContext::default()
        }
    )
    .is_err());
}

#[test]
fn canonical_encoding_revalidates_mutable_message_and_wrapper() {
    let pdu = constructed(&[paging_drx()], DecodeContext::default());
    let mut adversaries = Vec::new();
    let mut changed = pdu.clone();
    if let PduKind::Initiating { procedure_code, .. } = &mut changed.kind {
        *procedure_code = 14;
    }
    adversaries.push(changed);
    let mut changed = pdu.clone();
    if let PduKind::Initiating { criticality, .. } = &mut changed.kind {
        *criticality = Criticality::ignore;
    }
    adversaries.push(changed);
    let mut changed = pdu.clone();
    if let PduKind::Initiating {
        procedure_code,
        criticality,
        message,
    } = changed.kind
    {
        changed.kind = PduKind::Successful {
            procedure_code,
            criticality,
            message,
        };
    }
    adversaries.push(changed);
    let mut changed = pdu.clone();
    if let Message::NgSetupRequest(req) = message_mut(&mut changed) {
        req.protocol_ies.0.push(req.protocol_ies.0[0].clone());
    }
    adversaries.push(changed);
    let mut changed = pdu.clone();
    if let Message::NgSetupRequest(req) = message_mut(&mut changed) {
        req.protocol_ies.0[0].criticality = rasn::aper::decode(&[0]).expect("reject enum");
    }
    adversaries.push(changed);
    let mut changed = pdu.clone();
    if let Message::NgSetupRequest(req) = message_mut(&mut changed) {
        req.protocol_ies
            .0
            .resize(65536, req.protocol_ies.0[0].clone());
    }
    adversaries.push(changed);
    let mut changed = pdu.clone();
    *message_mut(&mut changed) = Message::Unknown(Bytes::from_static(b"synthetic-private"));
    adversaries.push(changed);
    for mut bad in adversaries {
        // Saved bytes cannot rescue an invalid typed view in canonical mode.
        bad.raw = Bytes::from_static(&[0, 21, 0, 3, 0, 0, 0]);
        let mut dst = BytesMut::from(&b"retained-prefix"[..]);
        assert!(bad.encode(&mut dst, EncodeContext::default()).is_err());
        assert!(&dst[..] == b"retained-prefix");
        assert!(bad.wire_len(EncodeContext::default()).is_err());
        assert!(
            encode(
                &bad,
                EncodeContext {
                    raw_preserving: true,
                    ..EncodeContext::default()
                }
            )
            .expect("raw path remains available")
                == bad.raw
        );
    }
}

#[test]
fn construction_bounds_include_outer_framing_and_diagnostics_are_redacted() {
    let marker = b"synthetic-private";
    let ie = ProtocolIe::new(65535, Criticality::ignore, marker);
    let pdu = constructed(&[ie], DecodeContext::default());
    let total = pdu.wire_len(EncodeContext::default()).expect("length");
    let make = |max_message_len| {
        Pdu::from_protocol_ies(
            MessageType::NgSetupRequest,
            &[ie],
            DecodeContext {
                max_message_len,
                ..DecodeContext::default()
            },
        )
    };
    assert!(make(total).is_ok());
    let error = make(total - 1).unwrap_err();
    assert_eq!(error.code(), &DecodeErrorCode::MessageLengthExceeded);
    let diagnostic = format!("{ie:?} {pdu:?} {error:?} {error}");
    assert!(!diagnostic.contains("synthetic-private"));
    assert!(!diagnostic.contains("115, 121, 110"));
    assert!(!diagnostic.contains("73796e"));
    assert!(diagnostic.contains("value_len"));
}

#[test]
fn fragmented_outer_boundary_consumes_terminator_and_no_following_message() {
    // X.691 11.9: a 16K fragment MUST have a following determinant, here 0.
    // The IE contains 16376 octets; the root prefix + IE framing adds 8.
    // Construct the literal directly, independently of the SDK writer.
    let mut wire = vec![0, 21, 0, 0xc1, 0, 0, 1, 0xff, 0xff, 0x40, 0xbf, 0xf8];
    wire.extend_from_slice(&vec![7; 16376]);
    wire.push(0);
    let pdu = Pdu::decode_owned(Bytes::from(wire.clone()), DecodeContext::default())
        .expect("fragmented PDU");
    assert!(pdu.raw == wire);
    assert!(encode(&pdu, EncodeContext::default()).expect("canonical") == wire);
    let mut joined = wire.clone();
    joined.extend_from_slice(&[0, 21, 0, 3, 0, 0, 0]);
    let (remainder, first) =
        <Pdu as BorrowDecode>::decode(&joined, DecodeContext::default()).expect("borrow first");
    assert!(remainder == [0, 21, 0, 3, 0, 0, 0]);
    assert!(first.raw == wire);
    assert!(Pdu::decode_owned(Bytes::from(joined), DecodeContext::default()).is_err());
    assert!(Pdu::decode_owned(
        Bytes::copy_from_slice(&wire[..wire.len() - 1]),
        DecodeContext::default()
    )
    .is_err());
    for invalid in [0xc0, 0xc2, 0xc3, 0xc4, 0xc5, 0xff] {
        let mut broken = wire.clone();
        broken[3] = invalid;
        assert!(Pdu::decode_owned(Bytes::from(broken), DecodeContext::default()).is_err());
    }
    for length in [0, 1, 2, 3, 4, 100, 16383, 16384] {
        assert!(Pdu::decode_owned(
            Bytes::copy_from_slice(&wire[..length]),
            DecodeContext::default()
        )
        .is_err());
    }
}

#[test]
fn fragmented_inner_ie_does_not_consume_the_next_ie() {
    // Two IEs: unknown ignore (16K) then PagingDRX. Both levels fragment.
    // The root body is 16397 octets: one C1 fragment and a 13-octet tail.
    let mut body = vec![0, 0, 2, 0xff, 0xfe, 0x40, 0xc1];
    body.extend_from_slice(&vec![7; 16384]);
    body.extend_from_slice(&[0, 0, 21, 0x40, 1, 0x40]);
    assert_eq!(body.len(), 16397);
    let mut wire = vec![0, 21, 0, 0xc1];
    wire.extend_from_slice(&body[..16384]);
    wire.push(13);
    wire.extend_from_slice(&body[16384..]);
    let pdu =
        Pdu::decode_owned(Bytes::from(wire.clone()), DecodeContext::default()).expect("both IEs");
    let PduKind::Initiating {
        message: Message::NgSetupRequest(req),
        ..
    } = &pdu.kind
    else {
        panic!("message");
    };
    assert_eq!(req.protocol_ies.0.len(), 2);
    assert_eq!(req.protocol_ies.0[0].value.as_bytes().len(), 16384);
    assert_eq!(req.protocol_ies.0[1].id, 21);
    assert!(req.protocol_ies.0[1].value.as_bytes() == [0x40]);
    assert!(encode(&pdu, EncodeContext::default()).expect("canonical") == wire);
}
