//! Spec-authored TS 24.501 §8.2.1–8.2.5 authentication fixtures.
use opc_proto_nas::decode_mm_message_body;
use opc_protocol::DecodeContext;

#[test]
fn strict_authentication_dispatch_rejects_missing_and_malformed_fields() {
    for (kind, body) in [
        (0x56, &[][..]),                    // Request needs ngKSI, ABBA, and a challenge.
        (0x56, &[0, 1, 0][..]),             // ABBA has at least two value octets.
        (0x57, &[][..]),                    // Response needs RES* or EAP.
        (0x57, &[0x2d, 1, 0][..]),          // RES* is exactly 16 octets.
        (0x59, &[][..]),                    // Failure needs a cause.
        (0x59, &[21][..]),                  // Synchronization failure needs AUTS.
        (0x5a, &[0, 0, 4, 3, 1, 0, 4][..]), // EAP-Success needs ABBA.
    ] {
        assert!(
            decode_mm_message_body(kind, body, strict_context()).is_err(),
            "kind={kind:02x} body={body:02x?}"
        );
    }
}

use bytes::{Bytes, BytesMut};
use opc_proto_nas::{
    Abba, AuthenticationFailure, AuthenticationReject, AuthenticationRequest,
    AuthenticationResponse, AuthenticationResult, EapMessage, MmCause, MmMessageBody, NgKsi,
};
use opc_protocol::{
    BorrowDecode, DecodeErrorCode, DuplicateIePolicy, Encode, EncodeContext, OwnedDecode,
    UnknownIePolicy, ValidationLevel,
};

fn strict_context() -> DecodeContext {
    DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    }
}

fn aka_request() -> Vec<u8> {
    let mut wire = vec![0x0a, 2, 0, 0, 0x21]; // mapped KSI 2, ABBA 0000, RAND TV
    wire.extend_from_slice(&[0x11; 16]);
    wire.extend_from_slice(&[0x20, 16]); // AUTN TLV
    wire.extend_from_slice(&[0x22; 16]);
    wire
}
fn res_response() -> Vec<u8> {
    let mut wire = vec![0x2d, 16];
    wire.extend_from_slice(&[0x33; 16]);
    wire
}
fn sync_failure() -> Vec<u8> {
    let mut wire = vec![21, 0x30, 14];
    wire.extend_from_slice(&[0x44; 14]);
    wire
}
fn encoded(value: &impl Encode) -> Vec<u8> {
    let mut out = BytesMut::new();
    value.encode(&mut out, EncodeContext::default()).unwrap();
    assert_eq!(out.len(), value.wire_len(EncodeContext::default()).unwrap());
    out.to_vec()
}

#[test]
fn spec_authentication_examples_decode_fields_and_encode_exactly() {
    let request =
        AuthenticationRequest::decode_owned(aka_request().into(), DecodeContext::default())
            .unwrap();
    assert_eq!(request.ng_ksi.identifier(), 2);
    assert!(request.ng_ksi.is_mapped());
    assert!(!request.ng_ksi.no_key_available());
    assert_eq!(request.abba.as_bytes(), &[0, 0]);
    assert_eq!(request.rand, Some([0x11; 16]));
    assert_eq!(request.autn, Some([0x22; 16]));
    assert!(request.eap_message.is_none());
    assert_eq!(encoded(&request), aka_request());

    let response = AuthenticationResponse::decode(&res_response(), DecodeContext::default())
        .unwrap()
        .1;
    assert_eq!(response.res_star, Some([0x33; 16]));
    assert_eq!(encoded(&response), res_response());
    let failure = AuthenticationFailure::decode(&sync_failure(), DecodeContext::default())
        .unwrap()
        .1;
    assert_eq!(failure.cause, MmCause::SYNCH_FAILURE);
    assert_eq!(failure.auts, Some([0x44; 14]));
    assert_eq!(encoded(&failure), sync_failure());

    // EAP-Success (code 3), mandatory LV-E, optional ABBA TLV.
    let result = [1, 0, 4, 3, 7, 0, 4, 0x38, 2, 0, 0];
    let decoded = AuthenticationResult::decode(&result, DecodeContext::default())
        .unwrap()
        .1;
    assert_eq!(decoded.eap_message.as_bytes(), &[3, 7, 0, 4]);
    assert_eq!(decoded.abba.unwrap().as_bytes(), &[0, 0]);
    // EAP-Failure (code 4), optional TLV-E.
    let reject = [0x78, 0, 4, 4, 7, 0, 4];
    let decoded = AuthenticationReject::decode(&reject, DecodeContext::default())
        .unwrap()
        .1;
    assert_eq!(encoded(&decoded), reject);

    for (kind, wire) in [
        (0x56, aka_request()),
        (0x57, res_response()),
        (0x59, sync_failure()),
        (0x5a, result.to_vec()),
        (0x58, reject.to_vec()),
        (0x58, vec![]),
    ] {
        let body = decode_mm_message_body(kind, &wire, DecodeContext::default()).unwrap();
        assert_eq!(encoded(&body), wire);
    }
}

#[test]
fn eap_alternatives_and_unknown_cause_round_trip() {
    let request = [0, 2, 0, 0, 0x78, 0, 5, 1, 8, 0, 5, 23];
    let response = [0x78, 0, 5, 2, 8, 0, 5, 23];
    for (kind, wire) in [
        (0x56, &request[..]),
        (0x57, &response[..]),
        (0x59, &[0xfe][..]),
    ] {
        let body = decode_mm_message_body(kind, wire, DecodeContext::default()).unwrap();
        assert_eq!(encoded(&body), wire);
    }
    assert_eq!(MmCause::new(0xfe).as_u8(), 0xfe);
}

#[test]
fn ie_bounds_and_ngksi_meaning_are_checked() {
    for n in [0, 1, 256] {
        assert!(Abba::new(vec![0; n].into()).is_err());
    }
    for n in [2, 255] {
        assert_eq!(Abba::new(vec![0; n].into()).unwrap().as_bytes().len(), n);
    }
    for n in [0, 1, 2, 3, 1501] {
        assert!(EapMessage::new(vec![0; n].into()).is_err());
    }
    let mut max_eap = vec![0; 1500];
    max_eap[..4].copy_from_slice(&[1, 1, 5, 220]);
    assert!(EapMessage::new(max_eap.into()).is_ok());
    assert!(EapMessage::new(Bytes::from_static(&[3, 0, 0, 5])).is_err());
    for id in 0..8 {
        for mapped in [false, true] {
            let ksi = NgKsi::new(id, mapped).unwrap();
            assert_eq!(ksi.identifier(), id);
            assert_eq!(ksi.is_mapped(), mapped);
            assert_eq!(ksi.no_key_available(), id == 7);
        }
    }
    assert!(NgKsi::new(8, false).is_err());
    // Value 7 is reserved in network-to-UE authentication messages.
    let mut reserved = aka_request();
    reserved[0] = 7;
    assert!(AuthenticationRequest::decode(&reserved, DecodeContext::default()).is_err());
}

#[test]
fn presence_constraints_apply_to_encode_and_strict_decode() {
    let mut request = AuthenticationRequest::decode(&aka_request(), strict_context())
        .unwrap()
        .1;
    request.autn = None;
    assert!(request.wire_len(EncodeContext::default()).is_err());
    request.autn = Some([0x22; 16]);
    request.eap_message = Some(EapMessage::new(Bytes::from_static(&[1, 1, 0, 5, 23])).unwrap());
    let mut out = BytesMut::from(&b"prefix"[..]);
    assert!(request.encode(&mut out, EncodeContext::default()).is_err());
    assert_eq!(&out[..], b"prefix");
    let mut both = aka_request();
    both.extend_from_slice(&[0x78, 0, 5, 1, 1, 0, 5, 23]);
    assert!(AuthenticationRequest::decode(&both, strict_context()).is_err());
    let mut both = res_response();
    both.extend_from_slice(&[0x78, 0, 5, 2, 1, 0, 5, 23]);
    assert!(AuthenticationResponse::decode(&both, strict_context()).is_err());
    let mut failure = AuthenticationFailure::decode(&sync_failure(), strict_context())
        .unwrap()
        .1;
    failure.cause = MmCause::MAC_FAILURE;
    assert!(failure.wire_len(EncodeContext::default()).is_err());
    assert!(AuthenticationFailure::decode(
        &[20, 0x30, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        strict_context()
    )
    .is_err());
    assert!(AuthenticationReject::decode(&[0x78, 0, 4, 3, 1, 0, 4], strict_context()).is_err());
}

#[test]
fn unknown_ie_forms_preserve_drop_or_reject_but_critical_always_fails() {
    let extension = [0x80, 0x60, 2, 0xaa, 0xbb, 0x7b, 0, 2, 0xcc, 0xdd];
    let mut wire = res_response();
    wire.extend_from_slice(&extension);
    for level in [ValidationLevel::Structural, ValidationLevel::Strict] {
        let ctx = DecodeContext {
            validation_level: level,
            ..DecodeContext::default()
        };
        let msg = AuthenticationResponse::decode(&wire, ctx).unwrap().1;
        assert_eq!(msg.optional_ies.len(), 3);
        assert_eq!(encoded(&msg), wire);
    }
    let ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Drop,
        ..DecodeContext::default()
    };
    assert_eq!(
        encoded(&AuthenticationResponse::decode(&wire, ctx).unwrap().1),
        res_response()
    );
    let ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Reject,
        ..DecodeContext::default()
    };
    assert!(AuthenticationResponse::decode(&wire, ctx).is_err());
    for iei in (0..=0x0f).chain([0x7e, 0x7f]) {
        let mut critical = res_response();
        critical.extend_from_slice(&[iei, 0]);
        for policy in [
            UnknownIePolicy::Preserve,
            UnknownIePolicy::Drop,
            UnknownIePolicy::Reject,
        ] {
            let ctx = DecodeContext {
                unknown_ie_policy: policy,
                ..DecodeContext::default()
            };
            assert_eq!(
                AuthenticationResponse::decode(&critical, ctx)
                    .unwrap_err()
                    .code(),
                &DecodeErrorCode::UnknownCriticalIe
            );
        }
    }
}

#[test]
fn repeated_ies_use_first_occurrence_per_section_7_6_3() {
    let mut wire = res_response();
    wire.extend_from_slice(&[0x2d, 16]);
    wire.extend_from_slice(&[0x55; 16]);
    let msg = AuthenticationResponse::decode(&wire, DecodeContext::default())
        .unwrap()
        .1;
    assert_eq!(msg.res_star, Some([0x33; 16]));
    assert_eq!(encoded(&msg), res_response());
    let ctx = DecodeContext {
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        ..DecodeContext::default()
    };
    assert_eq!(
        AuthenticationResponse::decode(&wire, ctx)
            .unwrap_err()
            .code(),
        &DecodeErrorCode::DuplicateIe
    );
}

#[test]
fn lengths_truncations_and_decode_limits_are_enforced() {
    for (kind, wire) in [
        (0x56, aka_request()),
        (0x57, res_response()),
        (0x59, sync_failure()),
    ] {
        for end in 0..wire.len() {
            assert!(
                decode_mm_message_body(kind, &wire[..end], strict_context()).is_err(),
                "{kind:x} end={end}"
            );
        }
        let ctx = DecodeContext {
            max_message_len: wire.len() - 1,
            ..strict_context()
        };
        assert_eq!(
            decode_mm_message_body(kind, &wire, ctx).unwrap_err().code(),
            &DecodeErrorCode::MessageLengthExceeded
        );
        let ctx = DecodeContext {
            max_ies: 0,
            ..strict_context()
        };
        assert_eq!(
            decode_mm_message_body(kind, &wire, ctx).unwrap_err().code(),
            &DecodeErrorCode::IeCountExceeded
        );
    }
    for n in [0, 1, 15, 17, 255] {
        let mut response = vec![0x2d, n];
        response.extend(vec![0; n as usize]);
        assert!(AuthenticationResponse::decode(&response, strict_context()).is_err());
        let mut request = aka_request();
        request[22] = n;
        request.truncate(23);
        request.extend(vec![0; n as usize]);
        assert!(AuthenticationRequest::decode(&request, strict_context()).is_err());
    }
}

#[test]
fn typed_values_drive_encoding_and_debug_redacts_authentication_material() {
    let mut request = AuthenticationRequest::decode(&aka_request(), DecodeContext::default())
        .unwrap()
        .1;
    request.rand = Some([0x66; 16]);
    let wire = encoded(&request);
    assert_eq!(&wire[5..21], &[0x66; 16]);
    let body = MmMessageBody::AuthenticationRequest(request);
    let debug = format!("{body:?}");
    assert!(debug.contains("redacted"));
    assert!(!debug.contains("102, 102"));
    let response = decode_mm_message_body(0x57, &res_response(), DecodeContext::default()).unwrap();
    assert!(!format!("{response:?}").contains("51, 51"));
}

#[test]
fn arbitrary_authentication_bodies_never_panic_and_sender_valid_values_reencode() {
    fn property(data: Vec<u8>) -> bool {
        for kind in 0x56..=0x5a {
            for ctx in [
                DecodeContext::default(),
                DecodeContext::conservative(),
                DecodeContext {
                    max_message_len: 32,
                    max_ies: 2,
                    ..DecodeContext::default()
                },
            ] {
                if let Ok(value) = decode_mm_message_body(kind, &data, ctx) {
                    let mut wire = BytesMut::new();
                    if value.encode(&mut wire, EncodeContext::default()).is_ok() {
                        let again = decode_mm_message_body(kind, &wire, ctx).unwrap();
                        assert_eq!(value, again);
                    } else {
                        // A receiver may accept optional-presence combinations a
                        // conforming sender must not emit. Refusal stays atomic.
                        assert!(!matches!(
                            ctx.validation_level,
                            ValidationLevel::Strict | ValidationLevel::ProcedureAware
                        ));
                        assert!(wire.is_empty());
                    }
                }
            }
        }
        true
    }
    quickcheck::QuickCheck::new()
        .tests(2000)
        .quickcheck(property as fn(Vec<u8>) -> bool);
}

#[test]
fn eap_common_packet_shapes_are_validated() {
    for wire in [
        &[1, 1, 0, 4][..],
        &[2, 1, 0, 4][..],
        &[3, 1, 0, 5, 0][..],
        &[4, 1, 0, 5, 0][..],
    ] {
        assert!(EapMessage::new(Bytes::copy_from_slice(wire)).is_err());
    }
}

#[test]
fn raw_extensions_cannot_override_typed_fields_or_smuggle_trailing_ies() {
    use opc_proto_nas::OptionalIe;
    for ie in [
        OptionalIe {
            iei: 0x2d,
            value: Bytes::from(vec![0x55; 16]),
            raw: Bytes::from(res_response()),
        },
        OptionalIe {
            iei: 0x60,
            value: Bytes::from_static(&[1]),
            raw: Bytes::from_static(&[0x60, 1, 1, 0x80]),
        },
        OptionalIe {
            iei: 0x60,
            value: Bytes::from_static(&[2]),
            raw: Bytes::from_static(&[0x60, 1, 1]),
        },
        OptionalIe {
            iei: 0x60,
            value: Bytes::new(),
            raw: Bytes::from_static(&[0, 0]),
        },
    ] {
        let mut response =
            AuthenticationResponse::decode(&res_response(), DecodeContext::default())
                .unwrap()
                .1;
        response.optional_ies.push(ie);
        let mut out = BytesMut::from(&b"prefix"[..]);
        assert!(response.encode(&mut out, EncodeContext::default()).is_err());
        assert_eq!(&out[..], b"prefix");
    }
}

#[test]
fn oversized_eap_is_rejected_before_copying_its_value() {
    let mut wire = vec![0x78, 0x06, 0x40]; // 1600 value octets exceeds the 1500 limit.
    wire.extend_from_slice(&[1, 1, 0x06, 0x40]);
    wire.resize(1603, 0);
    for ctx in [DecodeContext::default(), strict_context()] {
        let mut result = None;
        let allocations = allocation_counter::measure(|| {
            result = Some(AuthenticationResponse::decode(&wire, ctx));
        });
        match result.unwrap() {
            Ok((_, response)) => {
                assert_eq!(ctx.validation_level, ValidationLevel::Structural);
                assert!(response.eap_message.is_none());
            }
            Err(_) => assert_eq!(ctx.validation_level, ValidationLevel::Strict),
        }
        assert_eq!(allocations.count_total, 0);
    }
}

#[test]
fn eap_messages_and_result_reject_all_incomplete_ie_prefixes() {
    for (kind, wire) in [
        (0x56, &[0, 2, 0, 0, 0x78, 0, 5, 1, 8, 0, 5, 23][..]),
        (0x57, &[0x78, 0, 5, 2, 8, 0, 5, 23][..]),
        (0x5a, &[1, 0, 4, 3, 7, 0, 4, 0x38, 2, 0, 0][..]),
        (0x58, &[0x78, 0, 4, 4, 7, 0, 4][..]),
    ] {
        for end in usize::from(kind == 0x58)..wire.len() {
            assert!(
                decode_mm_message_body(kind, &wire[..end], strict_context()).is_err(),
                "{kind:x} prefix {end}"
            );
        }
    }
}

#[test]
fn review_default_decode_does_not_enforce_sender_optional_presence() {
    let mut stray_auts = sync_failure();
    stray_auts[0] = 20;
    let mut both_request = aka_request();
    both_request.extend_from_slice(&[0x78, 0, 5, 1, 1, 0, 5, 23]);
    let mut both_response = res_response();
    both_response.extend_from_slice(&[0x78, 0, 5, 2, 1, 0, 5, 23]);
    for (kind, wire) in [
        (0x56, vec![0, 2, 0, 0]),
        (0x57, vec![]),
        (0x59, stray_auts.clone()),
        (0x59, vec![21]),
        (0x5a, vec![1, 0, 4, 3, 1, 0, 4]),
        (0x58, vec![0x78, 0, 4, 3, 1, 0, 4]),
        (0x56, both_request),
        (0x57, both_response),
    ] {
        for level in [ValidationLevel::HeaderOnly, ValidationLevel::Structural] {
            let ctx = DecodeContext {
                validation_level: level,
                ..DecodeContext::default()
            };
            assert!(
                decode_mm_message_body(kind, &wire, ctx).is_ok(),
                "{kind:x}: {wire:x?}"
            );
        }
        for level in [ValidationLevel::Strict, ValidationLevel::ProcedureAware] {
            let ctx = DecodeContext {
                validation_level: level,
                ..DecodeContext::default()
            };
            assert!(decode_mm_message_body(kind, &wire, ctx).is_err());
        }
    }
    let failure = AuthenticationFailure::decode(&stray_auts, DecodeContext::default())
        .unwrap()
        .1;
    assert!(
        failure.auts.is_none(),
        "unnecessary AUTS is ignored (TS 24.007 11.4.1)"
    );
}

#[test]
fn review_default_decode_trims_extended_values_and_eap_padding() {
    let mut request = aka_request();
    request[22] = 17;
    request.push(0xff);
    let mut response = res_response();
    response[1] = 17;
    response.push(0xff);
    let mut failure = sync_failure();
    failure[2] = 15;
    failure.push(0xff);
    for (kind, padded, canonical) in [
        (0x56, request, aka_request()),
        (0x57, response, res_response()),
        (0x59, failure, sync_failure()),
        (
            0x58,
            vec![0x78, 0, 5, 4, 5, 0, 4, 0],
            vec![0x78, 0, 4, 4, 5, 0, 4],
        ),
        (
            0x5a,
            vec![1, 0, 5, 4, 5, 0, 4, 0],
            vec![1, 0, 4, 4, 5, 0, 4],
        ),
    ] {
        let value = decode_mm_message_body(kind, &padded, DecodeContext::default()).unwrap();
        assert_eq!(encoded(&value), canonical);
        for level in [ValidationLevel::Strict, ValidationLevel::ProcedureAware] {
            let ctx = DecodeContext {
                validation_level: level,
                ..DecodeContext::default()
            };
            assert!(decode_mm_message_body(kind, &padded, ctx).is_err());
        }
    }
}

#[test]
fn review_default_decode_drops_malformed_optional_ies() {
    for wire in [
        &[0x78, 0, 4, 4, 5, 0, 9][..], // Invalid EAP Length.
        &[0x78, 0, 4, 4, 5, 0, 3][..], // EAP Length below common header.
        &[0x78, 0, 4, 1, 5, 0, 4][..], // Missing EAP Request Type.
        &[0x78][..],
        &[0x78, 0][..],
        &[0x78, 0, 4, 4][..], // Truncated optional framing.
    ] {
        let value = AuthenticationReject::decode(wire, DecodeContext::default())
            .unwrap()
            .1;
        assert!(value.eap_message.is_none());
        let ctx = DecodeContext {
            validation_level: ValidationLevel::Strict,
            ..DecodeContext::default()
        };
        assert!(AuthenticationReject::decode(wire, ctx).is_err());
    }
    let wire = [1, 0, 4, 4, 5, 0, 4, 0x38, 1, 0, 0x60, 1, 9];
    let value = AuthenticationResult::decode(&wire, DecodeContext::default())
        .unwrap()
        .1;
    assert!(value.abba.is_none());
    assert_eq!(
        value.optional_ies.len(),
        1,
        "continue after a bounded malformed value"
    );
    assert_eq!(value.optional_ies[0].value.as_ref(), &[9]);
    // Invalid mandatory EAP must still fail at every level.
    assert!(
        AuthenticationResult::decode(&[1, 0, 4, 4, 5, 0, 9], DecodeContext::default()).is_err()
    );
}

#[test]
fn review_out_of_order_known_ies_are_ignored() {
    let mut wire = vec![0, 2, 0, 0, 0x20, 16];
    wire.extend_from_slice(&[0x22; 16]);
    wire.push(0x21);
    wire.extend_from_slice(&[0x11; 16]);
    let value = AuthenticationRequest::decode(&wire, DecodeContext::default())
        .unwrap()
        .1;
    assert_eq!(value.autn, Some([0x22; 16]));
    assert!(
        value.rand.is_none(),
        "late RAND is out of table order (7.6.2)"
    );
}

#[test]
fn strict_request_rejects_eap_before_rand_and_autn() {
    let mut wire = vec![0, 2, 0, 0, 0x78, 0, 5, 1, 1, 0, 5, 23];
    wire.extend_from_slice(&aka_request()[4..]);
    for level in [ValidationLevel::HeaderOnly, ValidationLevel::Structural] {
        let ctx = DecodeContext {
            validation_level: level,
            ..DecodeContext::default()
        };
        let value = AuthenticationRequest::decode(&wire, ctx).unwrap().1;
        assert!(value.eap_message.is_some());
        assert!(value.rand.is_none());
        assert!(value.autn.is_none());
    }
    for level in [ValidationLevel::Strict, ValidationLevel::ProcedureAware] {
        let ctx = DecodeContext {
            validation_level: level,
            ..DecodeContext::default()
        };
        assert!(AuthenticationRequest::decode(&wire[..12], ctx).is_ok());
        assert!(
            AuthenticationRequest::decode(&wire, ctx).is_err(),
            "late RAND/AUTN must not bypass strict validation at {level:?}"
        );
    }
}

#[test]
fn strict_response_rejects_eap_before_res_star() {
    let mut wire = vec![0x78, 0, 5, 2, 1, 0, 5, 23];
    wire.extend_from_slice(&res_response());
    for level in [ValidationLevel::HeaderOnly, ValidationLevel::Structural] {
        let ctx = DecodeContext {
            validation_level: level,
            ..DecodeContext::default()
        };
        let value = AuthenticationResponse::decode(&wire, ctx).unwrap().1;
        assert!(value.eap_message.is_some());
        assert!(value.res_star.is_none());
    }
    for level in [ValidationLevel::Strict, ValidationLevel::ProcedureAware] {
        let ctx = DecodeContext {
            validation_level: level,
            ..DecodeContext::default()
        };
        assert!(AuthenticationResponse::decode(&wire[..8], ctx).is_ok());
        assert!(
            AuthenticationResponse::decode(&wire, ctx).is_err(),
            "late RES* must not bypass strict validation at {level:?}"
        );
    }
}

#[test]
fn sm_debug_redacts_raw_authentication_values() {
    use opc_proto_nas::{NasMessage, Sm};
    let sm = Sm {
        pdu_session_id: 1,
        pti: 2,
        message_type: 0xc5,
        body: Bytes::from_static(b"synthetic-secret-auth-value"),
    };
    let envelope = NasMessage::Sm(sm.clone());
    for debug in [
        format!("{sm:?}"),
        format!("{sm:#?}"),
        format!("{envelope:?}"),
        format!("{envelope:#?}"),
    ] {
        assert!(!debug.contains("synthetic-secret"));
        assert!(debug.contains("redacted"));
        assert!(debug.contains("pdu_session_id"));
        assert!(debug.contains("pti"));
        assert!(debug.contains("message_type"));
    }
}

#[test]
fn raw_body_debug_redacts_authentication_values() {
    use opc_proto_nas::{RawMessageBody, SmMessageBody};
    let raw = RawMessageBody::new(b"synthetic-secret-auth-value");
    let sm_body = SmMessageBody::PduSessionAuthenticationCommand(raw.clone());
    let mm_body = MmMessageBody::Unknown(raw.clone());
    for debug in [
        format!("{raw:?}"),
        format!("{raw:#?}"),
        format!("{sm_body:?}"),
        format!("{sm_body:#?}"),
        format!("{mm_body:?}"),
        format!("{mm_body:#?}"),
    ] {
        assert!(!debug.contains("synthetic-secret"));
        assert!(debug.contains("redacted"));
    }
}

#[test]
fn review_envelope_debug_redacts_raw_authentication_values() {
    use opc_proto_nas::{
        NasCount, NasMessage, PlainMm, SecurityHeaderType, SecurityProtected, VerifiedNasPayload,
    };
    let secret = Bytes::from_static(b"synthetic-secret-auth-value");
    let plain = PlainMm {
        spare: 0,
        message_type: 0x57,
        body: secret.clone(),
    };
    let verified = VerifiedNasPayload {
        count: NasCount::new(0, 1),
        payload: secret.clone(),
    };
    let protected = SecurityProtected {
        security_header_type: SecurityHeaderType::IntegrityProtected,
        spare: 0,
        mac: [0; 4],
        sequence_number: 0,
        payload: secret,
    };
    for debug in [
        format!("{plain:?}"),
        format!("{protected:?}"),
        format!("{verified:?}"),
        format!("{:?}", NasMessage::PlainMm(plain)),
    ] {
        assert!(!debug.contains("synthetic-secret"));
        assert!(debug.contains("redacted"));
    }
}
