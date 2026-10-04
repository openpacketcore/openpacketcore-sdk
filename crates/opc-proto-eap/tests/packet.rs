use opc_proto_eap::eap5g::{self, Limits, Message};
use opc_proto_eap::{
    EapAkaError, EapAkaPacket, EapAkaPacketKind, EapCode, EapFailure, EapMethodPacket, EapPacket,
    EapPacketError, EapSuccess,
};

fn method_packet(packet: EapPacket<'_>, code: u8) -> EapMethodPacket<'_> {
    match (code, packet) {
        (1, EapPacket::Request(packet)) | (2, EapPacket::Response(packet)) => packet,
        _ => panic!("incorrect header classification"),
    }
}

#[test]
fn success_round_trips_exact_four_octets_at_identifier_boundaries() {
    for identifier in [0u8, 255] {
        let success = EapSuccess::new(identifier);
        let wire = success.encode();
        assert_eq!(wire, [3, identifier, 0, 4]);
        let packet = EapPacket::parse(&wire).expect("valid Success");
        assert_eq!(packet.identifier(), identifier);
        let EapPacket::Success(parsed) = packet else {
            panic!("Success expected");
        };
        assert_eq!(parsed, success);
        assert_eq!(parsed.identifier(), identifier);
        assert_eq!(parsed.encode(), wire);
        assert!(parsed.matches_response_identifier(identifier));
        assert!(!parsed.matches_response_identifier(identifier.wrapping_add(1)));
    }
}

#[test]
fn failure_round_trips_exact_four_octets_at_identifier_boundaries() {
    for identifier in [0u8, 255] {
        let failure = EapFailure::new(identifier);
        let wire = failure.encode();
        assert_eq!(wire, [4, identifier, 0, 4]);
        let packet = EapPacket::parse(&wire).expect("valid Failure");
        assert_eq!(packet.identifier(), identifier);
        let EapPacket::Failure(parsed) = packet else {
            panic!("Failure expected");
        };
        assert_eq!(parsed, failure);
        assert_eq!(parsed.identifier(), identifier);
        assert_eq!(parsed.encode(), wire);
        assert!(parsed.matches_response_identifier(identifier));
        assert!(!parsed.matches_response_identifier(identifier.wrapping_add(1)));
    }
}

#[test]
fn terminal_receive_padding_is_ignored_and_never_encoded() {
    for code in [3, 4] {
        for identifier in [0, 255] {
            let mut wire = vec![code, identifier, 0, 4];
            // Outside Length: RFC 3748 section 4 lower-layer padding, not Data.
            wire.extend_from_slice(b"private-padding-sentinel");
            let packet = EapPacket::parse(&wire).expect("receive padding is allowed");
            assert_eq!(packet.identifier(), identifier);
            let encoded = match packet {
                EapPacket::Success(success) => success.encode(),
                EapPacket::Failure(failure) => failure.encode(),
                _ => panic!("terminal expected"),
            };
            assert_eq!(encoded, [code, identifier, 0, 4]);
        }
    }
}

#[test]
fn rejects_truncated_common_headers_and_unsupported_codes() {
    for code in [1, 2, 3, 4] {
        let header = [code, 255, 0, 4];
        for length in 0..4 {
            assert_eq!(
                EapPacket::parse(&header[..length]).expect_err("incomplete header"),
                EapPacketError::TruncatedHeader,
            );
        }
    }
    for code in [0, 5, 255] {
        assert_eq!(
            EapPacket::parse(&[code, 255, 0, 4]).expect_err("unsupported code"),
            EapPacketError::UnsupportedCode,
        );
    }
}

#[test]
fn rejects_invalid_and_inconsistent_declared_lengths() {
    for code in [1, 2, 3, 4] {
        for length in 0..4 {
            assert_eq!(
                EapPacket::parse(&[code, 255, 0, length]).expect_err("invalid Length"),
                EapPacketError::InvalidLength,
            );
        }
        for length in [5u16, 256, u16::MAX] {
            let [high, low] = length.to_be_bytes();
            assert_eq!(
                EapPacket::parse(&[code, 255, high, low]).expect_err("truncated packet"),
                EapPacketError::LengthMismatch,
            );
        }
    }
}

#[test]
fn terminals_reject_declared_data_including_zero_and_method_headers() {
    for code in [3, 4] {
        for data in [b"\0".as_slice(), b"private-data-sentinel", &[23, 5, 0, 0]] {
            let length = u16::try_from(4 + data.len()).expect("synthetic Length");
            let [high, low] = length.to_be_bytes();
            let mut wire = vec![code, 255, high, low];
            wire.extend_from_slice(data);
            assert_eq!(
                EapPacket::parse(&wire).expect_err("terminals have no Data"),
                EapPacketError::InvalidTerminalLength,
            );
            wire.extend_from_slice(b"more-padding");
            assert_eq!(
                EapPacket::parse(&wire).expect_err("padding cannot repair declared Data"),
                EapPacketError::InvalidTerminalLength,
            );
        }
    }
}

#[test]
fn requests_and_responses_require_a_type_octet_within_length() {
    for code in [1, 2] {
        for wire in [vec![code, 255, 0, 4], vec![code, 255, 0, 4, 23]] {
            assert_eq!(
                EapPacket::parse(&wire).expect_err("Type is missing"),
                EapPacketError::InvalidLength,
            );
        }
        // Admission validates only common framing, regardless of Type value.
        for method in [0, 1, 23, 50, 254, 255] {
            let wire = [code, 255, 0, 5, method];
            let packet = EapPacket::parse(&wire).expect("complete common framing");
            assert_eq!(packet.identifier(), 255);
            let packet = method_packet(packet, code);
            assert_eq!(
                packet.parse_aka().expect_err("AKA header is incomplete"),
                EapAkaError::PacketTooShort {
                    actual: 5,
                    minimum: 8,
                },
            );
            assert_eq!(
                packet
                    .parse_eap5g(Limits::default())
                    .expect_err("EAP-5G header is incomplete"),
                eap5g::Error::Truncated,
            );
        }
    }
}

#[test]
fn dispatches_both_aka_methods_and_directions_after_removing_padding() {
    for method in [23, 50] {
        for code in [1, 2] {
            // RFC 4187 Identity Request / Authentication-Reject Response.
            let mut wire = if code == 1 {
                vec![1, 255, 0, 12, method, 5, 0, 0, 13, 1, 0, 0]
            } else {
                vec![2, 255, 0, 8, method, 2, 0, 0]
            };
            let declared = wire.len();
            wire.extend_from_slice(b"private-padding-sentinel");
            let admitted = EapPacket::parse(&wire).expect("common framing");
            let packet = method_packet(admitted, code)
                .parse_aka()
                .expect("valid AKA");
            assert_eq!(packet.identifier(), 255);
            assert_eq!(packet.code().as_u8(), code);
            assert_eq!(packet.method().as_u8(), method);
            assert!(matches!(
                (code, packet.kind()),
                (1, EapAkaPacketKind::IdentityRequest { .. })
                    | (2, EapAkaPacketKind::AuthenticationReject)
            ));
            // Calling the existing method parser directly remains exact-framed.
            assert_eq!(
                EapAkaPacket::parse(&wire).expect_err("direct method parser is strict"),
                EapAkaError::LengthMismatch {
                    declared,
                    actual: wire.len(),
                },
            );
        }
    }
}

#[test]
fn dispatches_eap5g_request_and_response_with_original_limits() {
    for (code, message_id) in [(1, 1), (2, 4)] {
        // TS 24.502 Start / Stop. Stop is a Response, not EAP Failure.
        let canonical = [
            code, 255, 0, 14, 254, 0, 0x28, 0xaf, 0, 0, 0, 3, message_id, 0,
        ];
        let mut wire = canonical.to_vec();
        wire.extend_from_slice(b"private-padding-sentinel");
        let admitted = EapPacket::parse(&wire).expect("common framing");
        let method = method_packet(admitted, code);
        let limits = Limits {
            max_packet_len: 14,
            ..Limits::default()
        };
        let packet = method.parse_eap5g(limits).expect("valid EAP-5G");
        assert_eq!(packet.identifier(), 255);
        assert_eq!(packet.code().as_u8(), code);
        assert!(matches!(
            (code, packet.message()),
            (1, Message::Start) | (2, Message::Stop)
        ));
        assert!(packet.encode(limits).expect("canonical encoding") == canonical);
        assert_eq!(
            method
                .parse_eap5g(Limits {
                    max_packet_len: 13,
                    ..limits
                })
                .expect_err("caller bounds still apply"),
            eap5g::Error::LimitExceeded,
        );
        assert_eq!(
            eap5g::Packet::parse(&wire, Limits::default())
                .expect_err("direct method parser is strict"),
            eap5g::Error::LengthMismatch,
        );
    }
}

#[test]
fn method_validation_is_deferred_and_preserves_existing_errors() {
    for code in [1, 2] {
        let unknown_method = [code, 0, 0, 14, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let admitted = EapPacket::parse(&unknown_method).expect("header admission");
        let method = method_packet(admitted, code);
        assert_eq!(
            method.parse_aka().expect_err("unknown method"),
            EapAkaError::UnsupportedMethod { actual: 99 },
        );
        assert_eq!(
            method
                .parse_eap5g(Limits::default())
                .expect_err("unknown method"),
            eap5g::Error::UnsupportedMethod,
        );

        let invalid_aka = [code, 0, 0, 8, 23, 255, 0, 0];
        let admitted = EapPacket::parse(&invalid_aka).expect("header admission");
        assert_eq!(
            method_packet(admitted, code)
                .parse_aka()
                .expect_err("unsupported subtype"),
            EapAkaPacket::parse(&invalid_aka).expect_err("original error"),
        );
        let invalid_eap5g = [code, 0, 0, 14, 254, 0, 0x28, 0xaf, 0, 0, 0, 3, 255, 0];
        let admitted = EapPacket::parse(&invalid_eap5g).expect("header admission");
        assert_eq!(
            method_packet(admitted, code)
                .parse_eap5g(Limits::default())
                .expect_err("unsupported message"),
            eap5g::Packet::parse(&invalid_eap5g, Limits::default()).expect_err("original error"),
        );
    }
}

#[test]
fn method_projections_keep_the_input_lifetime_and_borrow_only_declared_data() {
    // RFC 4187 Identity Response, eight synthetic identity octets.
    let mut aka = vec![2, 9, 0, 20, 23, 5, 0, 0, 14, 3, 0, 8];
    aka.extend_from_slice(b"test-ue!");
    aka.extend_from_slice(b"private-padding-sentinel");
    let identity = {
        let admitted = EapPacket::parse(&aka).expect("common framing");
        let projection = method_packet(admitted, 2).parse_aka().expect("valid AKA");
        projection.asserted_identity().expect("asserted identity")
    };
    assert!(std::ptr::eq(identity, &aka[12..20]));

    // TS 24.502 NAS Response, empty AN and four synthetic NAS octets.
    let mut eap5g = vec![
        2, 9, 0, 22, 254, 0, 0x28, 0xaf, 0, 0, 0, 3, 2, 0, 0, 0, 0, 4,
    ];
    eap5g.extend_from_slice(&[0x7e, 0, 0x41, 0]);
    eap5g.extend_from_slice(b"private-padding-sentinel");
    let nas = {
        let admitted = EapPacket::parse(&eap5g).expect("common framing");
        let projection = method_packet(admitted, 2)
            .parse_eap5g(Limits::default())
            .expect("valid EAP-5G");
        let Message::NasResponse { nas, .. } = projection.message() else {
            panic!("NAS Response expected");
        };
        nas.as_bytes()
    };
    assert!(std::ptr::eq(nas, &eap5g[18..22]));
}

#[test]
fn new_debug_surfaces_omit_identifiers_payloads_and_padding() {
    for identifier in [0, 255] {
        assert_eq!(
            format!("{:?}", EapSuccess::new(identifier)),
            "EapSuccess { .. }"
        );
        assert_eq!(
            format!("{:?}", EapFailure::new(identifier)),
            "EapFailure { .. }"
        );
        for (code, expected) in [
            (1, "Request(EapMethodPacket { .. })"),
            (2, "Response(EapMethodPacket { .. })"),
            (3, "Success(EapSuccess { .. })"),
            (4, "Failure(EapFailure { .. })"),
        ] {
            let mut wire = vec![code, identifier, 0, 4];
            if code <= 2 {
                wire.push(1); // Identity, with a synthetic private Type-Data value.
                wire.extend_from_slice(b"private-method-sentinel");
                let length = u16::try_from(wire.len()).expect("synthetic Length");
                wire[2..4].copy_from_slice(&length.to_be_bytes());
            }
            wire.extend_from_slice(b"private-padding-sentinel");
            let packet = EapPacket::parse(&wire).expect("common framing");
            assert_eq!(format!("{packet:?}"), expected);
            if code <= 2 {
                assert_eq!(
                    format!("{:?}", method_packet(packet, code)),
                    "EapMethodPacket { .. }"
                );
            }
        }
    }
}

#[test]
fn admission_errors_are_stable_and_value_free() {
    for (wire, debug, display) in [
        (vec![3, 255, 0], "TruncatedHeader", "eap_truncated_header"),
        (
            vec![255, 255, 0, 4],
            "UnsupportedCode",
            "eap_unsupported_code",
        ),
        (vec![3, 255, 0, 3], "InvalidLength", "eap_invalid_length"),
        (vec![4, 255, 0, 5], "LengthMismatch", "eap_length_mismatch"),
        (
            vec![3, 255, 0, 5, 0xa5],
            "InvalidTerminalLength",
            "eap_invalid_terminal_length",
        ),
    ] {
        let error = EapPacket::parse(&wire).expect_err("invalid packet");
        assert_eq!(format!("{error:?}"), debug);
        assert_eq!(error.to_string(), display);
    }
}

#[test]
fn existing_direction_enum_remains_exhaustive() {
    // Compile-time regression for the public two-variant method direction API.
    let direction = |code| match code {
        EapCode::Request => 1,
        EapCode::Response => 2,
    };
    assert_eq!(direction(EapCode::Request), 1);
    assert_eq!(direction(EapCode::Response), 2);
}
