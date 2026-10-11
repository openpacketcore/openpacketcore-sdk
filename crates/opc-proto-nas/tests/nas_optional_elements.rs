//! Message-specific TS 24.501 V18.11.1 optional-IE framing contracts.

#[path = "fixtures/optional_elements.rs"]
mod fixtures;

use bytes::{Bytes, BytesMut};
use fixtures::{Ie, Message};
use opc_proto_nas::{
    decode_mm_message_body, ConfigurationUpdateCommand, ConfigurationUpdateComplete, MmMessageBody,
    NasMessage, OptionalIe, RegistrationAccept, RegistrationRequest, SecurityModeCommand,
    SecurityModeComplete,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DuplicateIePolicy, Encode,
    EncodeContext, EncodeErrorCode, OwnedDecode, SpecRef, UnknownIePolicy, ValidationLevel,
};

fn body_with(message: &Message, optional: &[u8]) -> Vec<u8> {
    let mut body = message.mandatory.to_vec();
    body.extend_from_slice(optional);
    body
}

fn all_elements(message: &Message) -> Vec<u8> {
    let mut body = message.mandatory.to_vec();
    for ie in message.ies {
        body.extend_from_slice(ie.wire);
    }
    body
}

fn optional_ies(body: &MmMessageBody) -> &[OptionalIe] {
    match body {
        MmMessageBody::RegistrationRequest(body) => &body.optional_ies,
        MmMessageBody::RegistrationAccept(body) => &body.optional_ies,
        MmMessageBody::SecurityModeCommand(body) => &body.optional_ies,
        MmMessageBody::SecurityModeComplete(body) => &body.optional_ies,
        MmMessageBody::ConfigurationUpdateCommand(body) => &body.optional_ies,
        MmMessageBody::ConfigurationUpdateComplete(body) => &body.optional_ies,
        other => panic!("expected a typed optional-IE body, got {other:?}"),
    }
}

fn expected_error(code: DecodeErrorCode, offset: usize, section: &'static str) -> DecodeError {
    DecodeError::new(code, offset).with_spec_ref(SpecRef::new("3gpp", "TS24501", section))
}

fn invalid_length(offset: usize, section: &'static str) -> DecodeError {
    expected_error(
        DecodeErrorCode::InvalidLength {
            reason: "optional IE length outside message bounds",
        },
        offset,
        section,
    )
}

fn unknown_ie(offset: usize, section: &'static str) -> DecodeError {
    expected_error(
        DecodeErrorCode::Structural {
            reason: "unknown optional IE",
        },
        offset,
        section,
    )
}

fn assert_direct_round_trip<T>(wire: &[u8])
where
    T: for<'a> BorrowDecode<'a> + OwnedDecode + Encode + PartialEq + std::fmt::Debug,
{
    let (rest, borrowed) = T::decode(wire, DecodeContext::conservative()).unwrap();
    assert!(rest.is_empty());
    let owned =
        T::decode_owned(Bytes::copy_from_slice(wire), DecodeContext::conservative()).unwrap();
    assert_eq!(borrowed, owned);
    for raw_preserving in [false, true] {
        let ctx = EncodeContext {
            raw_preserving,
            ..EncodeContext::default()
        };
        let mut encoded = BytesMut::new();
        owned.encode(&mut encoded, ctx).unwrap();
        assert_eq!(owned.wire_len(ctx).unwrap(), wire.len());
        assert_eq!(&encoded[..], wire);
    }
}

fn assert_message_round_trip(message: &Message, count: usize) {
    let body = all_elements(message);
    let decoded =
        decode_mm_message_body(message.kind, &body, DecodeContext::conservative()).unwrap();
    let ies = optional_ies(&decoded);
    assert_eq!(ies.len(), count);
    assert_eq!(message.ies.len(), count);
    for (actual, expected) in ies.iter().zip(message.ies) {
        assert_eq!(actual.iei, expected.wire[0]);
        assert_eq!(&actual.raw[..], expected.wire);
        assert_eq!(&actual.value[..], &expected.wire[expected.header_len..]);
    }
    let mut encoded = BytesMut::new();
    decoded
        .encode(&mut encoded, EncodeContext::default())
        .unwrap();
    assert_eq!(
        decoded.wire_len(EncodeContext::default()).unwrap(),
        body.len()
    );
    assert_eq!(&encoded[..], &body);

    // The same independently authored body goes through the full NAS dispatcher.
    let mut frame = vec![0x7e, 0, message.kind];
    frame.extend_from_slice(&body);
    let (rest, nas) = NasMessage::decode(&frame, DecodeContext::conservative()).unwrap();
    assert!(rest.is_empty());
    let NasMessage::PlainMm(plain) = &nas else {
        panic!("expected plain 5GMM")
    };
    assert_eq!(
        plain.decode_body(DecodeContext::conservative()).unwrap(),
        decoded
    );
    let mut encoded_frame = BytesMut::new();
    nas.encode(&mut encoded_frame, EncodeContext::default())
        .unwrap();
    assert_eq!(&encoded_frame[..], &frame);
}

#[test]
fn registration_request_all_42_optional_elements_strict_round_trip() {
    assert_message_round_trip(&fixtures::REQUEST, 42);
    assert_direct_round_trip::<RegistrationRequest>(&all_elements(&fixtures::REQUEST));
}

#[test]
fn registration_accept_all_60_optional_elements_strict_round_trip() {
    assert_message_round_trip(&fixtures::ACCEPT, 60);
    assert_direct_round_trip::<RegistrationAccept>(&all_elements(&fixtures::ACCEPT));
}

#[test]
fn security_mode_command_all_7_optional_elements_strict_round_trip() {
    assert_message_round_trip(&fixtures::SECURITY_COMMAND, 7);
    assert_direct_round_trip::<SecurityModeCommand>(&all_elements(&fixtures::SECURITY_COMMAND));
}

#[test]
fn security_mode_complete_all_3_optional_elements_strict_round_trip() {
    assert_message_round_trip(&fixtures::SECURITY_COMPLETE, 3);
    assert_direct_round_trip::<SecurityModeComplete>(&all_elements(&fixtures::SECURITY_COMPLETE));
}

#[test]
fn configuration_update_command_all_44_optional_elements_strict_round_trip() {
    assert_message_round_trip(&fixtures::CONFIGURATION_COMMAND, 44);
    assert_direct_round_trip::<ConfigurationUpdateCommand>(&all_elements(
        &fixtures::CONFIGURATION_COMMAND,
    ));
}

#[test]
fn configuration_update_complete_empty_table_strict_round_trip() {
    assert_message_round_trip(&fixtures::CONFIGURATION_COMPLETE, 0);
    assert_direct_round_trip::<ConfigurationUpdateComplete>(&[]);
}

// The fixture declares its header size independently of production framing.
// Change only the declared length and opaque value, retaining the identifier.
fn length_variant(ie: &Ie, total: usize) -> Vec<u8> {
    let value_len = total - ie.header_len;
    let mut wire = vec![ie.wire[0]];
    match ie.header_len {
        2 => wire.push(u8::try_from(value_len).unwrap()),
        3 => wire.extend_from_slice(&u16::try_from(value_len).unwrap().to_be_bytes()),
        _ => panic!("only variable-length IEs have a length field"),
    }
    wire.resize(total, 0x5a);
    wire
}

#[test]
fn every_table_length_bound_is_enforced_under_strict_and_procedure_aware() {
    for message in fixtures::MESSAGES {
        for ie in message.ies.iter().filter(|ie| ie.header_len > 1) {
            for level in [ValidationLevel::Strict, ValidationLevel::ProcedureAware] {
                let ctx = DecodeContext {
                    validation_level: level,
                    max_message_len: 70_000,
                    ..DecodeContext::conservative()
                };
                // The wire's physical u8/u16 limit also bounds an open-ended row.
                for len in [ie.wire.len(), ie.max_len] {
                    let wire = length_variant(ie, len);
                    let decoded =
                        decode_mm_message_body(message.kind, &body_with(message, &wire), ctx)
                            .unwrap_or_else(|err| {
                                panic!(
                                    "kind={:02x} ie={:02x} len={len}: {err}",
                                    message.kind, ie.wire[0]
                                )
                            });
                    assert_eq!(optional_ies(&decoded).len(), 1);
                    assert_eq!(&optional_ies(&decoded)[0].raw[..], &wire);
                }
                if ie.wire.len() > ie.header_len {
                    let wire = length_variant(ie, ie.wire.len() - 1);
                    assert_eq!(
                        decode_mm_message_body(message.kind, &body_with(message, &wire), ctx)
                            .unwrap_err(),
                        invalid_length(0, ie.section),
                        "kind={:02x} ie={:02x} below minimum",
                        message.kind,
                        ie.wire[0],
                    );
                }
                let physical_max = if ie.header_len == 2 { 257 } else { 65538 };
                if ie.max_len < physical_max {
                    let wire = length_variant(ie, ie.max_len + 1);
                    assert_eq!(
                        decode_mm_message_body(message.kind, &body_with(message, &wire), ctx)
                            .unwrap_err(),
                        invalid_length(0, ie.section),
                        "kind={:02x} ie={:02x} above maximum",
                        message.kind,
                        ie.wire[0],
                    );
                }
            }
        }
    }
}

#[test]
fn structural_and_header_only_levels_preserve_framed_lengths_outside_table_bounds() {
    for message in fixtures::MESSAGES {
        for ie in message.ies.iter().filter(|ie| ie.header_len > 1) {
            let mut lengths = Vec::new();
            if ie.wire.len() > ie.header_len {
                lengths.push(ie.wire.len() - 1);
            }
            let physical_max = if ie.header_len == 2 { 257 } else { 65538 };
            if ie.max_len < physical_max {
                lengths.push(ie.max_len + 1);
            }
            for len in lengths {
                let wire = length_variant(ie, len);
                let body = body_with(message, &wire);
                for level in [ValidationLevel::Structural, ValidationLevel::HeaderOnly] {
                    let ctx = DecodeContext {
                        validation_level: level,
                        max_message_len: 70_000,
                        ..DecodeContext::conservative()
                    };
                    let decoded = decode_mm_message_body(message.kind, &body, ctx).unwrap();
                    assert_eq!(optional_ies(&decoded).len(), 1);
                    assert_eq!(&optional_ies(&decoded)[0].raw[..], &wire);
                    let mut encoded = BytesMut::new();
                    decoded
                        .encode(&mut encoded, EncodeContext::default())
                        .unwrap();
                    assert_eq!(&encoded[..], &body);
                }
            }
        }
    }
}

#[test]
fn each_known_optional_element_reports_exact_truncation() {
    for message in fixtures::MESSAGES {
        for ie in message.ies {
            // An absent optional IE is valid; a one-octet IE cannot be partial.
            for end in 1..ie.wire.len() {
                assert_eq!(
                    decode_mm_message_body(
                        message.kind,
                        &body_with(message, &ie.wire[..end]),
                        DecodeContext::conservative(),
                    )
                    .unwrap_err(),
                    expected_error(DecodeErrorCode::Truncated, 0, ie.section),
                    "kind={:02x} ie={:02x} prefix={end}",
                    message.kind,
                    ie.wire[0],
                );
            }
        }
    }
}

#[test]
fn every_registered_ie_rejects_duplicates_including_different_half_octet_values() {
    for message in fixtures::MESSAGES {
        for ie in message.ies {
            let mut duplicated = ie.wire.to_vec();
            let mut second = ie.wire.to_vec();
            if second[0] >= 0x80 {
                second[0] ^= 0x0f;
            }
            duplicated.extend_from_slice(&second);
            assert_eq!(
                decode_mm_message_body(
                    message.kind,
                    &body_with(message, &duplicated),
                    DecodeContext::conservative()
                )
                .unwrap_err(),
                expected_error(DecodeErrorCode::DuplicateIe, ie.wire.len(), message.section),
                "kind={:02x} ie={:02x}",
                message.kind,
                ie.wire[0],
            );
        }
    }
}

#[test]
fn half_octet_duplicate_first_and_last_policies_preserve_the_selected_wire_value() {
    for message in fixtures::MESSAGES {
        for ie in message.ies.iter().filter(|ie| ie.wire[0] >= 0x80) {
            let first = ie.wire[0];
            let last = first ^ 0x0f;
            for (policy, wanted) in [
                (DuplicateIePolicy::First, first),
                (DuplicateIePolicy::Last, last),
            ] {
                let ctx = DecodeContext {
                    duplicate_ie_policy: policy,
                    ..DecodeContext::conservative()
                };
                let decoded =
                    decode_mm_message_body(message.kind, &body_with(message, &[first, last]), ctx)
                        .unwrap();
                let ies = optional_ies(&decoded);
                assert_eq!(ies.len(), 1);
                assert_eq!(ies[0].iei, wanted);
                assert_eq!(&ies[0].raw[..], &[wanted]);
                assert!(ies[0].value.is_empty());
                let mut encoded = BytesMut::new();
                decoded
                    .encode(&mut encoded, EncodeContext::default())
                    .unwrap();
                assert_eq!(&encoded[..], &body_with(message, &[wanted]));
            }
        }
    }
}

fn fixture_contains(message: &Message, octet: u8) -> bool {
    message.ies.iter().any(|ie| {
        if octet >= 0x80 {
            ie.wire[0] & 0xf0 == octet & 0xf0
        } else {
            ie.wire[0] == octet
        }
    })
}

#[test]
fn foreign_message_elements_are_rejected_under_all_rejecting_contexts() {
    let rejecting = [
        DecodeContext::conservative(),
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Preserve,
            ..DecodeContext::conservative()
        },
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..DecodeContext::conservative()
        },
        DecodeContext {
            validation_level: ValidationLevel::ProcedureAware,
            ..DecodeContext::default()
        },
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..DecodeContext::default()
        },
    ];
    for message in fixtures::MESSAGES {
        for other in fixtures::MESSAGES {
            for ie in other
                .ies
                .iter()
                .filter(|ie| !fixture_contains(message, ie.wire[0]))
            {
                for ctx in rejecting {
                    assert_eq!(
                        decode_mm_message_body(message.kind, &body_with(message, ie.wire), ctx)
                            .unwrap_err(),
                        unknown_ie(0, message.section),
                        "kind={:02x} foreign kind={:02x} ie={:02x}",
                        message.kind,
                        other.kind,
                        ie.wire[0],
                    );
                }
            }
        }
    }
}

#[test]
fn every_bit_8_identifier_is_one_octet_even_when_unknown_to_the_message() {
    for message in fixtures::MESSAGES {
        for octet in 0x80..=0xff {
            let body = body_with(message, &[octet]);
            let decoded =
                decode_mm_message_body(message.kind, &body, DecodeContext::default()).unwrap();
            let ies = optional_ies(&decoded);
            assert_eq!(ies.len(), 1);
            assert_eq!(ies[0].iei, octet);
            assert_eq!(&ies[0].raw[..], &[octet]);
            assert!(ies[0].value.is_empty());

            let known = fixture_contains(message, octet);
            let drop = DecodeContext {
                unknown_ie_policy: UnknownIePolicy::Drop,
                ..DecodeContext::default()
            };
            let decoded = decode_mm_message_body(message.kind, &body, drop).unwrap();
            assert_eq!(optional_ies(&decoded).len(), usize::from(known));
            let strict = decode_mm_message_body(message.kind, &body, DecodeContext::conservative());
            if known {
                assert_eq!(&optional_ies(&strict.unwrap())[0].raw[..], &[octet]);
            } else {
                assert_eq!(strict.unwrap_err(), unknown_ie(0, message.section));
            }
        }
    }
}

#[test]
fn unknown_half_octet_duplicates_use_the_high_nibble_in_permissive_contexts() {
    // The Complete table is empty: all three one-octet elements are unknown.
    let wire = [0x80, 0x91, 0x8f];
    for (policy, expected) in [
        (DuplicateIePolicy::First, [0x80, 0x91]),
        (DuplicateIePolicy::Last, [0x91, 0x8f]),
    ] {
        let ctx = DecodeContext {
            duplicate_ie_policy: policy,
            ..DecodeContext::default()
        };
        let (_, decoded) = ConfigurationUpdateComplete::decode(&wire, ctx).unwrap();
        assert_eq!(decoded.optional_ies.len(), 2);
        assert_eq!(decoded.optional_ies[0].iei, expected[0]);
        assert_eq!(decoded.optional_ies[1].iei, expected[1]);
        let mut encoded = BytesMut::new();
        decoded
            .encode(&mut encoded, EncodeContext::default())
            .unwrap();
        assert_eq!(&encoded[..], &expected);
    }
    let ctx = DecodeContext {
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        ..DecodeContext::default()
    };
    assert_eq!(
        ConfigurationUpdateComplete::decode(&wire, ctx).unwrap_err(),
        expected_error(DecodeErrorCode::DuplicateIe, 2, "8.2.20"),
    );
}

#[test]
fn unknown_full_octet_elements_retain_permissive_framing_and_policy() {
    // Non-critical identifiers retain permissive framing where unassigned.
    for wire in [&[0x4d, 2, 0xab, 0xcd][..], &[0x7d, 0, 2, 0xab, 0xcd][..]] {
        for message in fixtures::MESSAGES {
            if fixture_contains(message, wire[0]) {
                continue;
            }
            let body = body_with(message, wire);
            let decoded =
                decode_mm_message_body(message.kind, &body, DecodeContext::default()).unwrap();
            let ies = optional_ies(&decoded);
            assert_eq!(ies.len(), 1);
            assert_eq!(&ies[0].value[..], &[0xab, 0xcd]);
            assert_eq!(&ies[0].raw[..], wire);
            let mut encoded = BytesMut::new();
            decoded
                .encode(&mut encoded, EncodeContext::default())
                .unwrap();
            assert_eq!(&encoded[..], &body);

            let drop = DecodeContext {
                unknown_ie_policy: UnknownIePolicy::Drop,
                ..DecodeContext::default()
            };
            assert!(
                optional_ies(&decode_mm_message_body(message.kind, &body, drop).unwrap())
                    .is_empty()
            );
            assert_eq!(
                decode_mm_message_body(message.kind, &body, DecodeContext::conservative())
                    .unwrap_err(),
                unknown_ie(0, message.section),
            );
            let short = body_with(message, &wire[..wire.len() - 1]);
            assert_eq!(
                decode_mm_message_body(message.kind, &short, DecodeContext::default()).unwrap_err(),
                expected_error(DecodeErrorCode::Truncated, 0, message.section),
            );
        }
    }
}

#[test]
fn every_full_octet_identifier_outside_the_table_is_rejected_by_rejecting_contexts() {
    let rejecting = [
        DecodeContext::conservative(),
        DecodeContext {
            validation_level: ValidationLevel::ProcedureAware,
            ..DecodeContext::default()
        },
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..DecodeContext::default()
        },
    ];
    for message in fixtures::MESSAGES {
        for octet in 0x00..=0x7f_u8 {
            if fixture_contains(message, octet) {
                continue;
            }
            let expected = if octet <= 0x0f || matches!(octet, 0x7e | 0x7f) {
                expected_error(DecodeErrorCode::UnknownCriticalIe, 0, "7.5")
            } else {
                unknown_ie(0, message.section)
            };
            for ctx in rejecting {
                assert_eq!(
                    decode_mm_message_body(message.kind, &body_with(message, &[octet, 0, 0]), ctx)
                        .unwrap_err(),
                    expected,
                    "kind={:02x} ie={octet:02x}",
                    message.kind,
                );
            }
        }
    }
}

#[test]
fn unknown_comprehension_required_identifiers_fail_closed_in_all_six_bodies() {
    let contexts = [
        DecodeContext::default(),
        DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..DecodeContext::default()
        },
        DecodeContext::conservative(),
    ];
    for message in fixtures::MESSAGES {
        for octet in (0x00..=0x0f).chain([0x7e, 0x7f]) {
            assert!(!fixture_contains(message, octet));
            for ctx in contexts {
                assert_eq!(
                    decode_mm_message_body(message.kind, &body_with(message, &[octet, 0, 0]), ctx)
                        .unwrap_err(),
                    expected_error(DecodeErrorCode::UnknownCriticalIe, 0, "7.5"),
                    "kind={:02x} ie={octet:02x} ctx={ctx:?}",
                    message.kind,
                );
            }
        }
    }
}

#[test]
fn same_identifier_uses_the_selected_messages_length_bounds() {
    // LADN information permits an empty value in Configuration update command,
    // but Registration accept requires at least ten value octets.
    let empty_ladn = [0x79, 0, 0];
    let decoded = decode_mm_message_body(0x54, &empty_ladn, DecodeContext::conservative()).unwrap();
    assert_eq!(optional_ies(&decoded).len(), 1);
    assert_eq!(
        decode_mm_message_body(0x42, &[1, 1, 0x79, 0, 0], DecodeContext::conservative())
            .unwrap_err(),
        invalid_length(0, "9.11.3.30"),
    );
    // IEI 0x16 is a three-value-octet PLMN in Request and a one-value-octet
    // T3502 timer in Accept. Both formats are TLV but their bounds differ.
    let timer = [0x16, 1, 1];
    assert_eq!(
        decode_mm_message_body(
            0x41,
            &body_with(&fixtures::REQUEST, &timer),
            DecodeContext::conservative()
        )
        .unwrap_err(),
        invalid_length(0, "9.11.3.85"),
    );
    assert_eq!(
        optional_ies(
            &decode_mm_message_body(0x42, &[1, 1, 0x16, 1, 1], DecodeContext::conservative())
                .unwrap()
        )
        .len(),
        1
    );
    // IEI 0x78 is EAP in Security mode command and an opaque non-IMEISV PEI
    // in Security mode complete; the latter is not subject to EAP's bound.
    let mut long_pei = vec![0x78, 0x05, 0xdd]; // 1501 value octets
    long_pei.resize(1504, 0);
    assert_eq!(
        optional_ies(
            &decode_mm_message_body(0x5e, &long_pei, DecodeContext::conservative()).unwrap()
        )
        .len(),
        1
    );
    assert_eq!(
        decode_mm_message_body(
            0x5d,
            &body_with(&fixtures::SECURITY_COMMAND, &long_pei),
            DecodeContext::conservative()
        )
        .unwrap_err(),
        invalid_length(0, "9.11.2.2"),
    );
}

#[test]
fn later_optional_errors_report_the_optional_list_offset_and_exact_clause() {
    let message = &fixtures::SECURITY_COMMAND;
    for (wire, expected) in [
        (&[0xe1, 0x36, 0][..], invalid_length(1, "9.11.3.12")),
        (
            &[0xe1, 0x57][..],
            expected_error(DecodeErrorCode::Truncated, 1, "9.11.3.25"),
        ),
        (&[0xe1, 0x4d, 0][..], unknown_ie(1, "8.2.25")),
        (
            &[0xe1, 0x36, 1, 0, 0x36, 1, 0][..],
            expected_error(DecodeErrorCode::DuplicateIe, 4, "8.2.25"),
        ),
    ] {
        assert_eq!(
            decode_mm_message_body(
                message.kind,
                &body_with(message, wire),
                DecodeContext::conservative()
            )
            .unwrap_err(),
            expected,
        );
    }
}

#[test]
fn security_mode_mandatory_errors_cite_the_correct_message_clauses() {
    assert_eq!(
        SecurityModeCommand::decode(&[], DecodeContext::conservative()).unwrap_err(),
        expected_error(DecodeErrorCode::Truncated, 0, "8.2.25"),
    );
    let ctx = DecodeContext {
        max_message_len: 0,
        ..DecodeContext::conservative()
    };
    assert_eq!(
        SecurityModeCommand::decode(&[0x22], ctx).unwrap_err(),
        expected_error(DecodeErrorCode::MessageLengthExceeded, 0, "8.2.25"),
    );
    assert_eq!(
        SecurityModeComplete::decode(&[0x77], ctx).unwrap_err(),
        expected_error(DecodeErrorCode::MessageLengthExceeded, 0, "8.2.26"),
    );
}

#[test]
fn configuration_update_empty_table_still_enforces_resource_limits() {
    for kind in [0x54, 0x55] {
        let section = if kind == 0x54 { "8.2.19" } else { "8.2.20" };
        let ctx = DecodeContext {
            max_ies: 1,
            unknown_ie_policy: UnknownIePolicy::Drop,
            ..DecodeContext::default()
        };
        assert_eq!(
            decode_mm_message_body(kind, &[0x4d, 0, 0x4e, 0], ctx).unwrap_err(),
            expected_error(DecodeErrorCode::IeCountExceeded, 2, section),
        );
    }
    let ctx = DecodeContext {
        max_message_len: 1,
        ..DecodeContext::default()
    };
    assert_eq!(
        ConfigurationUpdateCommand::decode(&[0xd1, 0x91], ctx).unwrap_err(),
        expected_error(DecodeErrorCode::MessageLengthExceeded, 0, "8.2.19"),
    );
    assert_eq!(
        ConfigurationUpdateComplete::decode(&[0x4d, 0], ctx).unwrap_err(),
        expected_error(DecodeErrorCode::MessageLengthExceeded, 0, "8.2.20"),
    );
}

#[test]
fn configuration_update_bodies_redact_values_and_refuse_encoding_before_writing() {
    let mut wire = vec![0x4d, 16];
    wire.extend_from_slice(b"sensitive-value!");
    for kind in [0x54, 0x55] {
        let decoded = decode_mm_message_body(kind, &wire, DecodeContext::default()).unwrap();
        let debug = format!("{decoded:?}");
        assert!(debug.contains("optional_ies_len"));
        assert!(!debug.contains("sensitive-value"));
        assert!(!debug.contains("OptionalIe {"));
        let mut out = BytesMut::from(&b"unchanged"[..]);
        let ctx = EncodeContext {
            max_message_len: wire.len() - 1,
            ..EncodeContext::default()
        };
        assert_eq!(
            decoded.encode(&mut out, ctx).unwrap_err().code(),
            &EncodeErrorCode::CapacityExceeded {
                required: wire.len(),
                available: wire.len() - 1
            },
        );
        assert_eq!(&out[..], b"unchanged");
    }
}

#[test]
fn messages_without_typed_tables_keep_their_raw_bodies_under_strict_validation() {
    for kind in [0x43, 0x44, 0x4c, 0x64, 0x67, 0x68, 0xfe] {
        let wire = [0x99, 0x47, 0x80, 0xff];
        let decoded = decode_mm_message_body(kind, &wire, DecodeContext::conservative()).unwrap();
        let mut encoded = BytesMut::new();
        decoded
            .encode(&mut encoded, EncodeContext::default())
            .unwrap();
        assert_eq!(&encoded[..], &wire);
    }
}
