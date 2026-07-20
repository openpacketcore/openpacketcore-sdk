//! TS 29.281 Release 18 control-message fixtures and negative cases.

use std::{net::IpAddr, num::NonZeroU32};

use bytes::Bytes;
use opc_proto_gtpu::{
    GtpuControlCodecErrorCode, GtpuControlMessage, GtpuEchoRequest, GtpuEchoResponse,
    GtpuEndMarker, GtpuErrorIndication, GtpuExtensionChainError, GtpuExtensionHeaderComprehension,
    GtpuExtensionHeaderRecipient, GtpuExtensionHeaderType, GtpuExtensionHeaderTypeList, GtpuHeader,
    GtpuMessage, GtpuPrivateExtension, GtpuRecoveryTimeStamp,
    GtpuSupportedExtensionHeadersNotification, GtpuTunnelEndpointId, PduSessionContainer,
    PduSessionContainerError,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, EncodeContext, UnknownIePolicy, ValidationLevel,
};

// Synthetic, specification-authored fixtures derived directly from TS 29.281
// figures 5.1-1, 5.2.1-1 and 8.2-1 through 8.6-1. They contain no live
// addresses, tunnel identifiers, or vendor data.
const ECHO_REQUEST: &[u8] = &[0x32, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0x12, 0x34, 0, 0];
const ECHO_RESPONSE: &[u8] = &[
    0x32, 0x02, 0x00, 0x06, 0, 0, 0, 0, 0x12, 0x34, 0, 0, 0x0e, 0,
];
const ERROR_INDICATION_IPV4_WITH_UDP_PORT: &[u8] = &[
    0x36, 0x1a, 0x00, 0x14, 0, 0, 0, 0, 0, 0, 0, 0x40, 0x01, 0x08, 0x68, 0, 0x10, 0x11, 0x22, 0x33,
    0x44, 0x85, 0, 4, 192, 0, 2, 10,
];
const ERROR_INDICATION_IPV6: &[u8] = &[
    0x32, 0x1a, 0x00, 0x1c, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x11, 0x22, 0x33, 0x44, 0x85, 0, 0x10,
    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
];
const SUPPORTED_EXTENSION_HEADERS: &[u8] = &[
    0x32, 0x1f, 0x00, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0x8d, 0, 2, 0x40, 0x85,
];
const END_MARKER: &[u8] = &[0x30, 0xfe, 0, 0, 0x11, 0x22, 0x33, 0x44];
const END_MARKER_WITH_PDU_SESSION_CONTAINER: &[u8] = &[
    0x34, 0xfe, 0, 8, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0x85, 1, 0, 9, 0,
];
const ECHO_REQUEST_TIMESTAMP_AND_PRIVATE: &[u8] = &[
    0x32, 0x01, 0x00, 0x13, 0, 0, 0, 0, 0, 7, 0, 0, 0xe7, 0, 6, 1, 2, 3, 4, 0xaa, 0xbb, 0xff, 0, 3,
    0x7e, 0xd9, 0x10,
];
const ECHO_REQUEST_UNUSED_NEXT_EXTENSION: &[u8] =
    &[0x32, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0x12, 0x34, 0, 0x84];

fn decode(bytes: &[u8]) -> GtpuControlMessage {
    match GtpuControlMessage::decode(bytes, DecodeContext::default()) {
        Ok((tail, message)) => {
            assert!(tail.is_empty());
            message
        }
        Err(error) => panic!("fixture failed to decode: {error:?}"),
    }
}

fn encode(message: &GtpuControlMessage) -> Bytes {
    match message.to_bytes(EncodeContext::default()) {
        Ok(bytes) => bytes,
        Err(error) => panic!("fixture failed to encode: {error:?}"),
    }
}

#[test]
fn echo_request_and_response_match_spec_authored_fixtures() {
    let request = match decode(ECHO_REQUEST) {
        GtpuControlMessage::EchoRequest(value) => value,
        other => panic!("unexpected message: {other:?}"),
    };
    assert_eq!(request.sequence_number(), 0x1234);
    assert!(request.private_extensions().is_empty());
    assert_eq!(
        encode(&GtpuControlMessage::EchoRequest(request.clone())),
        ECHO_REQUEST
    );

    let response = match decode(ECHO_RESPONSE) {
        GtpuControlMessage::EchoResponse(value) => value,
        other => panic!("unexpected message: {other:?}"),
    };
    assert_eq!(response.sequence_number(), request.sequence_number());
    assert_eq!(response, GtpuEchoResponse::for_request(&request));
    assert_eq!(
        encode(&GtpuControlMessage::EchoResponse(response)),
        ECHO_RESPONSE
    );
}

#[test]
fn received_recovery_counter_is_ignored_and_canonicalized_to_zero() {
    let mut received = ECHO_RESPONSE.to_vec();
    received[13] = 0xa5;

    let decoded = decode(&received);
    assert_eq!(encode(&decoded), ECHO_RESPONSE);
}

#[test]
fn receiver_ignored_npdu_and_raw_optional_fields_are_not_promoted() {
    let mut received = ECHO_REQUEST.to_vec();
    received[0] = 0x33; // S=1 and PN=1.
    received[10] = 0xa5;

    let decoded = decode(&received);
    assert_eq!(encode(&decoded), ECHO_REQUEST);
}

#[test]
fn receiver_ignored_next_extension_type_is_not_evaluated() {
    let decoded = decode(ECHO_REQUEST_UNUSED_NEXT_EXTENSION);
    let request = match &decoded {
        GtpuControlMessage::EchoRequest(value) => value,
        other => panic!("unexpected message: {other:?}"),
    };
    assert_eq!(request.sequence_number(), 0x1234);
    assert!(!request.extension_chain().has_headers());
    assert_eq!(encode(&decoded), ECHO_REQUEST);
}

#[test]
fn typed_network_receive_ignores_spare_bit_and_canonicalizes_it_to_zero() {
    let fixtures = [
        (ECHO_REQUEST, ECHO_REQUEST),
        (ECHO_RESPONSE, ECHO_RESPONSE),
        (
            ERROR_INDICATION_IPV4_WITH_UDP_PORT,
            ERROR_INDICATION_IPV4_WITH_UDP_PORT,
        ),
        (ERROR_INDICATION_IPV6, ERROR_INDICATION_IPV6),
        (SUPPORTED_EXTENSION_HEADERS, SUPPORTED_EXTENSION_HEADERS),
        (END_MARKER, END_MARKER),
        (
            END_MARKER_WITH_PDU_SESSION_CONTAINER,
            END_MARKER_WITH_PDU_SESSION_CONTAINER,
        ),
        (
            ECHO_REQUEST_TIMESTAMP_AND_PRIVATE,
            ECHO_REQUEST_TIMESTAMP_AND_PRIVATE,
        ),
        (ECHO_REQUEST_UNUSED_NEXT_EXTENSION, ECHO_REQUEST),
    ];
    let contexts = [
        DecodeContext::conservative(),
        DecodeContext {
            validation_level: ValidationLevel::Strict,
            ..DecodeContext::default()
        },
        DecodeContext {
            validation_level: ValidationLevel::ProcedureAware,
            ..DecodeContext::default()
        },
    ];

    for (fixture, canonical) in fixtures {
        let mut received = fixture.to_vec();
        received[0] |= 0x08;
        for ctx in contexts {
            let decoded = GtpuControlMessage::decode_datagram(&received, ctx)
                .expect("typed network receive must ignore the spare bit");
            assert_eq!(encode(&decoded).as_ref(), canonical);
        }
    }
}

#[test]
fn active_zero_next_extension_type_fails_closed() {
    let wire = [0x36, 0x01, 0, 4, 0, 0, 0, 0, 0x12, 0x34, 0, 0];
    let error = GtpuControlMessage::decode(&wire, DecodeContext::default())
        .expect_err("E=1 requires a non-zero next extension type");
    assert_eq!(error.code(), &GtpuControlCodecErrorCode::InvalidHeaderFlags);
    assert_eq!(error.offset(), 11);

    let manually_built = GtpuMessage {
        header: GtpuHeader {
            version: 1,
            protocol_type: true,
            reserved: 0,
            ext_hdr_flag: true,
            seq_num_flag: true,
            npdu_num_flag: false,
            message_type: 1,
            length: 4,
            teid: 0,
            sequence_number: Some(0x1234),
            npdu_number: None,
            next_ext_type: Some(0),
            raw_sequence_number: Some(0x1234),
            raw_npdu_number: Some(0),
            raw_next_ext_type: Some(0),
        },
        raw_extension_headers: &[],
        payload: &[],
    };
    let error = GtpuControlMessage::from_message(&manually_built, DecodeContext::default())
        .expect_err("manual E=1/next=0 frame must fail identically");
    assert_eq!(error.code(), &GtpuControlCodecErrorCode::InvalidHeaderFlags);
    assert_eq!(error.offset(), 11);
}

#[test]
fn from_message_reapplies_strict_frame_invariants_after_loose_decode() {
    let wire = [0x36, 0x01, 0, 4, 0, 0, 0, 0, 0x12, 0x34, 0, 0];
    let (_, loosely_decoded) = GtpuMessage::decode(
        &wire,
        DecodeContext {
            validation_level: ValidationLevel::Structural,
            ..DecodeContext::default()
        },
    )
    .expect("structural generic decode permits active next-extension type zero");
    let error = GtpuControlMessage::from_message(
        &loosely_decoded,
        DecodeContext {
            validation_level: ValidationLevel::Strict,
            ..DecodeContext::default()
        },
    )
    .expect_err("typed conversion must reapply its active-extension contract");
    assert_eq!(error.code(), &GtpuControlCodecErrorCode::InvalidHeaderFlags);
    assert_eq!(error.offset(), 11);
}

#[test]
fn from_message_reapplies_generic_header_length_and_message_limits() {
    let (_, decoded) = GtpuMessage::decode(
        ECHO_REQUEST,
        DecodeContext {
            validation_level: ValidationLevel::Structural,
            ..DecodeContext::default()
        },
    )
    .expect("fixture must decode generically");

    let mut version_zero = decoded.clone();
    version_zero.header.version = 0;
    let error = GtpuControlMessage::from_message(&version_zero, DecodeContext::default())
        .expect_err("version zero must fail at the typed conversion boundary");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::Framing {
            code: DecodeErrorCode::InvalidEnumValue {
                field: "version",
                value: 0,
            }
        }
    );
    assert_eq!(error.offset(), 0);

    let mut protocol_type_clear = decoded.clone();
    protocol_type_clear.header.protocol_type = false;
    let error = GtpuControlMessage::from_message(&protocol_type_clear, DecodeContext::default())
        .expect_err("PT=0 must fail at the typed conversion boundary");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::Framing {
            code: DecodeErrorCode::InvalidEnumValue {
                field: "protocol_type",
                value: 0,
            }
        }
    );
    assert_eq!(error.offset(), 0);

    let mut mismatched_length = decoded.clone();
    mismatched_length.header.length = mismatched_length.header.length.saturating_add(1);
    let error = GtpuControlMessage::from_message(&mismatched_length, DecodeContext::default())
        .expect_err("declared length must match retained frame fields");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::Framing {
            code: DecodeErrorCode::InvalidLength {
                reason: "declared length does not match decoded frame",
            }
        }
    );
    assert_eq!(error.offset(), 2);

    let error = GtpuControlMessage::from_message(
        &decoded,
        DecodeContext {
            max_message_len: ECHO_REQUEST.len() - 1,
            ..DecodeContext::default()
        },
    )
    .expect_err("message-size limit must be reapplied by from_message");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::Framing {
            code: DecodeErrorCode::MessageLengthExceeded
        }
    );
    assert_eq!(error.offset(), 0);
}

#[test]
fn from_message_reapplies_extension_depth_count_and_header_contract() {
    let two_extensions = [
        0x34, 0xfe, 0, 12, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0x07, 1, 0xaa, 0xbb, 0x08, 1, 0xcc,
        0xdd, 0,
    ];
    let (_, decoded) = GtpuMessage::decode(
        &two_extensions,
        DecodeContext {
            validation_level: ValidationLevel::Structural,
            ..DecodeContext::default()
        },
    )
    .expect("two-extension fixture must decode generically");

    let depth_error = GtpuControlMessage::from_message(
        &decoded,
        DecodeContext {
            max_depth: 1,
            ..DecodeContext::default()
        },
    )
    .expect_err("second extension must exceed max_depth=1");
    assert_eq!(
        depth_error.code(),
        &GtpuControlCodecErrorCode::Framing {
            code: DecodeErrorCode::DepthExceeded
        }
    );
    assert_eq!(depth_error.offset(), 16);

    let count_error = GtpuControlMessage::from_message(
        &decoded,
        DecodeContext {
            max_ies: 1,
            ..DecodeContext::default()
        },
    )
    .expect_err("second extension must exceed max_ies=1");
    assert_eq!(
        count_error.code(),
        &GtpuControlCodecErrorCode::Framing {
            code: DecodeErrorCode::IeCountExceeded
        }
    );
    assert_eq!(count_error.offset(), 16);

    let mut extension_bytes_without_flag = decoded.clone();
    extension_bytes_without_flag.header.ext_hdr_flag = false;
    extension_bytes_without_flag.header.next_ext_type = None;
    extension_bytes_without_flag.header.raw_sequence_number = None;
    extension_bytes_without_flag.header.raw_npdu_number = None;
    extension_bytes_without_flag.header.raw_next_ext_type = None;
    let contract_error =
        GtpuControlMessage::from_message(&extension_bytes_without_flag, DecodeContext::default())
            .expect_err("raw extension bytes require E=1");
    assert_eq!(
        contract_error.code(),
        &GtpuControlCodecErrorCode::Framing {
            code: DecodeErrorCode::Structural {
                reason: "extension bytes present while extension header flag is clear",
            }
        }
    );
    assert_eq!(contract_error.offset(), 12);
}

#[test]
fn independent_ipv6_timestamp_and_private_extension_fixtures_are_exact() {
    let error = match decode(ERROR_INDICATION_IPV6) {
        GtpuControlMessage::ErrorIndication(value) => value,
        other => panic!("unexpected message: {other:?}"),
    };
    let expected_address = match "2001:db8::10".parse::<IpAddr>() {
        Ok(value) => value,
        Err(parse_error) => panic!("test address failed: {parse_error}"),
    };
    assert_eq!(error.peer_address().address(), expected_address);
    assert_eq!(
        encode(&GtpuControlMessage::ErrorIndication(error)),
        ERROR_INDICATION_IPV6
    );

    let request = match decode(ECHO_REQUEST_TIMESTAMP_AND_PRIVATE) {
        GtpuControlMessage::EchoRequest(value) => value,
        other => panic!("unexpected message: {other:?}"),
    };
    let timestamp = request
        .recovery_time_stamp()
        .expect("fixture contains Recovery Time Stamp");
    assert_eq!(timestamp.seconds_since_1900(), 0x0102_0304);
    assert_eq!(timestamp.additional_data(), &[0xaa, 0xbb]);
    assert_eq!(request.private_extensions().len(), 1);
    assert_eq!(
        request.private_extensions()[0].extension_identifier(),
        32_473
    );
    assert_eq!(request.private_extensions()[0].value(), &[0x10]);
    assert_eq!(
        encode(&GtpuControlMessage::EchoRequest(request)),
        ECHO_REQUEST_TIMESTAMP_AND_PRIVATE
    );
}

#[test]
fn echo_optional_timestamp_and_repeatable_private_extensions_are_canonical() {
    let timestamp = GtpuRecoveryTimeStamp::new(0x0102_0304);
    assert!(timestamp.additional_data().is_empty());
    let mut request = GtpuEchoRequest::new(7).with_recovery_time_stamp(timestamp);
    request.push_private_extension(GtpuPrivateExtension::new(
        32_473,
        Bytes::from_static(&[0x10]),
    ));
    request.push_private_extension(GtpuPrivateExtension::new(
        32_474,
        Bytes::from_static(&[0x20, 0x21]),
    ));
    let model = GtpuControlMessage::EchoRequest(request);

    let wire = encode(&model);
    let reparsed = decode(&wire);
    assert_eq!(reparsed, model);
    let debug = format!("{reparsed:?}");
    assert!(!debug.contains("170, 187"));
}

#[test]
fn error_indication_ipv4_and_udp_port_match_spec_authored_fixture() {
    let error = match decode(ERROR_INDICATION_IPV4_WITH_UDP_PORT) {
        GtpuControlMessage::ErrorIndication(value) => value,
        other => panic!("unexpected message: {other:?}"),
    };
    assert_eq!(error.teid_data_i().value(), 0x1122_3344);
    let expected_address = match "192.0.2.10".parse::<IpAddr>() {
        Ok(value) => value,
        Err(parse_error) => panic!("test address failed: {parse_error}"),
    };
    assert_eq!(error.peer_address().address(), expected_address);
    assert_eq!(error.triggering_udp_source_port(), Some(2152));
    assert_eq!(
        encode(&GtpuControlMessage::ErrorIndication(error.clone())),
        ERROR_INDICATION_IPV4_WITH_UDP_PORT
    );

    let debug = format!("{error:?}");
    assert!(!debug.contains("11223344"));
    assert!(!debug.contains("192.0.2.10"));
    assert!(!debug.contains("2152"));
}

#[test]
fn error_indication_ipv6_round_trips_and_requires_nonzero_teid() {
    let teid = match NonZeroU32::new(9) {
        Some(value) => value,
        None => panic!("test TEID must be non-zero"),
    };
    let address = match "2001:db8::10".parse::<IpAddr>() {
        Ok(value) => value,
        Err(error) => panic!("test address failed: {error}"),
    };
    let model = GtpuControlMessage::ErrorIndication(GtpuErrorIndication::new(teid, address));
    let wire = encode(&model);
    assert_eq!(decode(&wire), model);

    let mut zero_teid = wire.to_vec();
    // IE type 16 begins at offset 12 for a sequence-bearing message.
    zero_teid[13..17].fill(0);
    let error = GtpuControlMessage::decode(&zero_teid, DecodeContext::default())
        .expect_err("zero Error Indication TEID must fail");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::InvalidIeValue { ie_type: 16 }
    );
}

#[test]
fn supported_extension_headers_and_end_marker_match_spec_fixtures() {
    let supported = decode(SUPPORTED_EXTENSION_HEADERS);
    let list = match &supported {
        GtpuControlMessage::SupportedExtensionHeadersNotification(value) => {
            value.supported_types().as_slice()
        }
        other => panic!("unexpected message: {other:?}"),
    };
    assert_eq!(
        list,
        &[
            GtpuExtensionHeaderType::new(0x40),
            GtpuExtensionHeaderType::new(0x85)
        ]
    );
    assert_eq!(encode(&supported), SUPPORTED_EXTENSION_HEADERS);

    let marker = decode(END_MARKER);
    match &marker {
        GtpuControlMessage::EndMarker(value) => {
            assert_eq!(value.teid().value(), 0x1122_3344);
        }
        other => panic!("unexpected message: {other:?}"),
    }
    assert_eq!(encode(&marker), END_MARKER);
    assert!(!format!("{marker:?}").contains("11223344"));
}

#[test]
fn end_marker_accepts_and_reencodes_pdu_session_container() {
    let marker = match decode(END_MARKER_WITH_PDU_SESSION_CONTAINER) {
        GtpuControlMessage::EndMarker(value) => value,
        other => panic!("unexpected message: {other:?}"),
    };
    let container = marker
        .extension_chain()
        .pdu_session_container
        .as_ref()
        .expect("fixture contains PDU Session Container");
    assert_eq!(container.pdu_type, 0);
    assert_eq!(container.qfi, 9);
    assert_eq!(
        encode(&GtpuControlMessage::EndMarker(marker)),
        END_MARKER_WITH_PDU_SESSION_CONTAINER
    );
}

#[test]
fn end_marker_builder_emits_pdu_session_container_fixture() {
    let container = PduSessionContainer::new_downlink(9, None, false)
        .expect("valid PDU Session Container must construct");
    let marker = GtpuEndMarker::new(GtpuTunnelEndpointId::new(0x1122_3344))
        .with_pdu_session_container(container)
        .expect("valid PDU Session Container must build");
    let message = GtpuControlMessage::EndMarker(marker);

    assert_eq!(encode(&message), END_MARKER_WITH_PDU_SESSION_CONTAINER);
    assert_eq!(decode(END_MARKER_WITH_PDU_SESSION_CONTAINER), message);

    let invalid = PduSessionContainer {
        pdu_type: 2,
        qfi: 9,
        ppi: None,
        rqi: false,
    };
    let error = GtpuEndMarker::new(GtpuTunnelEndpointId::new(1))
        .with_pdu_session_container(invalid)
        .expect_err("End Marker builder must use the fallible PDU boundary");
    assert_eq!(
        error,
        GtpuExtensionChainError::InvalidPduSessionContainer {
            reason: PduSessionContainerError::ReservedPduType,
        }
    );
}

#[test]
fn end_marker_reports_precise_pdu_session_container_reasons_and_offsets() {
    let cases = [
        ([0x20, 0x09], PduSessionContainerError::ReservedPduType),
        (
            [0x08, 0x09],
            PduSessionContainerError::UnsupportedDownlinkConditionalFields,
        ),
        (
            [0x04, 0x09],
            PduSessionContainerError::UnsupportedDownlinkConditionalFields,
        ),
        (
            [0x02, 0x09],
            PduSessionContainerError::UnsupportedDownlinkConditionalFields,
        ),
        (
            [0x18, 0x09],
            PduSessionContainerError::UnsupportedUplinkConditionalFields,
        ),
        (
            [0x11, 0x09],
            PduSessionContainerError::UnsupportedUplinkConditionalFields,
        ),
        (
            [0x10, 0x49],
            PduSessionContainerError::UnsupportedUplinkConditionalFields,
        ),
    ];
    for (content, reason) in cases {
        let wire = [
            0x34, 0xfe, 0, 8, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0x85, 1, content[0], content[1], 0,
        ];
        for validation_level in [ValidationLevel::Structural, ValidationLevel::ProcedureAware] {
            let error = GtpuControlMessage::decode(
                &wire,
                DecodeContext {
                    validation_level,
                    ..DecodeContext::default()
                },
            )
            .expect_err("unsupported PDU Session Container must fail closed");
            assert_eq!(
                error.code(),
                &GtpuControlCodecErrorCode::MalformedPduSessionContainer { reason }
            );
            assert_eq!(error.offset(), 12);
        }
    }

    let reserved_after_unknown_optional = [
        0x34, 0xfe, 0, 12, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0x07, 1, 0xaa, 0xbb, 0x85, 1, 0x20,
        0x09, 0,
    ];
    let error =
        GtpuControlMessage::decode(&reserved_after_unknown_optional, DecodeContext::default())
            .expect_err("reserved second extension must retain its own offset");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::MalformedPduSessionContainer {
            reason: PduSessionContainerError::ReservedPduType,
        }
    );
    assert_eq!(error.offset(), 16);

    let duplicate = [
        0x34, 0xfe, 0, 12, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0x85, 1, 0, 9, 0x85, 1, 0, 10, 0,
    ];
    let error = GtpuControlMessage::decode(&duplicate, DecodeContext::default())
        .expect_err("second PDU Session Container must fail as a duplicate");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::DuplicatePduSessionContainer
    );
    assert_eq!(error.offset(), 16);
}

#[test]
fn control_mutators_retain_unknown_optional_extension_headers() {
    let error_with_unknown_optional = [
        0x36, 0x1a, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0x07, 1, 0xaa, 0xbb, 0x40, 1, 0x04, 0xd2, 0, 16,
        0x11, 0x22, 0x33, 0x44, 133, 0, 4, 192, 0, 2, 1,
    ];
    let error = match decode(&error_with_unknown_optional) {
        GtpuControlMessage::ErrorIndication(value) => value,
        other => panic!("unexpected message: {other:?}"),
    };
    let mutated = error
        .with_triggering_udp_source_port(2152)
        .expect("valid preserved chain must accept UDP Port mutation");
    assert_eq!(mutated.extension_chain().header_count, 2);
    assert_eq!(mutated.extension_chain().first_extension_type, Some(0x07));
    assert_eq!(
        mutated.extension_chain().raw_headers.as_ref(),
        &[1, 0xaa, 0xbb, 0x40, 1, 0x08, 0x68, 0]
    );
    let model = GtpuControlMessage::ErrorIndication(mutated);
    let wire = encode(&model);
    assert_eq!(decode(&wire), model);

    let marker_with_unknown_optional = [
        0x34, 0xfe, 0, 12, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0x07, 1, 0xcc, 0xdd, 0x85, 1, 0, 8, 0,
    ];
    let marker = match decode(&marker_with_unknown_optional) {
        GtpuControlMessage::EndMarker(value) => value,
        other => panic!("unexpected message: {other:?}"),
    };
    let container = PduSessionContainer::new_downlink(9, None, false)
        .expect("valid PDU Session Container must construct");
    let mutated = marker
        .with_pdu_session_container(container)
        .expect("valid preserved chain must accept PDU mutation");
    assert_eq!(mutated.extension_chain().header_count, 2);
    assert_eq!(mutated.extension_chain().first_extension_type, Some(0x07));
    assert_eq!(
        mutated.extension_chain().raw_headers.as_ref(),
        &[1, 0xcc, 0xdd, 0x85, 1, 0, 9, 0]
    );
    let model = GtpuControlMessage::EndMarker(mutated);
    let wire = encode(&model);
    assert_eq!(decode(&wire), model);
}

#[test]
fn pdu_session_container_is_rejected_outside_end_marker() {
    let echo_request_with_pdu_session_container = [
        0x36, 0x01, 0, 8, 0, 0, 0, 0, 0x12, 0x34, 0, 0x85, 1, 0, 9, 0,
    ];
    let error = GtpuControlMessage::decode(
        &echo_request_with_pdu_session_container,
        DecodeContext::default(),
    )
    .expect_err("PDU Session Container is not valid on Echo Request");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::UnexpectedExtension {
            extension_type: 0x85
        }
    );
    assert_eq!(error.offset(), 12);
}

#[test]
fn standardized_gpdu_extensions_are_unexpected_on_typed_control_messages() {
    // TS 29.281 R18.4.0 figure 5.2.1-3 assigns both 0x04 (current) and
    // 0x86 (legacy) to the PDU Set Information Container. That container is
    // G-PDU-only, so its optional-comprehension bits do not turn it into an
    // unknown forward-compatible Echo extension.
    for extension_type in [
        0x01, 0x02, 0x03, 0x04, 0x20, 0x40, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0xc0, 0xc1, 0xc2,
    ] {
        let wire = [
            0x36,
            0x01,
            0,
            8,
            0,
            0,
            0,
            0,
            0,
            1,
            0,
            extension_type,
            1,
            0xaa,
            0xbb,
            0,
        ];
        let error = GtpuControlMessage::decode(&wire, DecodeContext::default())
            .expect_err("standardized G-PDU extension must be procedure-inapplicable on Echo");
        assert_eq!(
            error.code(),
            &GtpuControlCodecErrorCode::UnexpectedExtension { extension_type },
            "extension type {extension_type:#04x}"
        );
        assert_eq!(error.offset(), 12);
    }
}

#[test]
fn builders_round_trip_supported_notification_and_end_marker_private_data() {
    let types = match GtpuExtensionHeaderTypeList::new([
        GtpuExtensionHeaderType::new(0x40),
        GtpuExtensionHeaderType::new(0x85),
    ]) {
        Ok(value) => value,
        Err(error) => panic!("valid type list failed: {error:?}"),
    };
    let mut notification = GtpuSupportedExtensionHeadersNotification::new(types);
    notification.push_private_extension(GtpuPrivateExtension::new(
        1,
        Bytes::from_static(&[0xde, 0xad]),
    ));
    let notification = GtpuControlMessage::SupportedExtensionHeadersNotification(notification);
    assert_eq!(decode(&encode(&notification)), notification);

    let mut marker = GtpuEndMarker::new(GtpuTunnelEndpointId::new(0));
    marker.push_private_extension(GtpuPrivateExtension::new(
        2,
        Bytes::from_static(&[0xbe, 0xef]),
    ));
    let marker = GtpuControlMessage::EndMarker(marker);
    assert_eq!(decode(&encode(&marker)), marker);
}

#[test]
fn unknown_tlv_policy_preserves_drops_or_rejects_without_exposing_value() {
    let wire = [0x32, 0x01, 0, 8, 0, 0, 0, 0, 0, 1, 0, 0, 200, 0, 1, 0xab];
    let preserved = decode(&wire);
    let request = match &preserved {
        GtpuControlMessage::EchoRequest(value) => value,
        other => panic!("unexpected message: {other:?}"),
    };
    assert_eq!(request.unknown_ies().len(), 1);
    assert_eq!(request.unknown_ies()[0].ie_type(), 200);
    assert_eq!(request.unknown_ies()[0].value(), &[0xab]);
    assert!(!format!("{:?}", request.unknown_ies()[0]).contains("171"));
    assert_eq!(encode(&preserved).as_ref(), wire);

    let drop_ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Drop,
        ..DecodeContext::default()
    };
    let dropped = match GtpuControlMessage::decode(&wire, drop_ctx) {
        Ok((_, value)) => value,
        Err(error) => panic!("drop policy failed: {error:?}"),
    };
    assert_eq!(
        encode(&dropped).as_ref(),
        &[0x32, 0x01, 0, 4, 0, 0, 0, 0, 0, 1, 0, 0]
    );

    let reject_ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Reject,
        ..DecodeContext::default()
    };
    let error = GtpuControlMessage::decode(&wire, reject_ctx)
        .expect_err("reject policy must reject an unknown TLV");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::UnknownIe { ie_type: 200 }
    );
}

#[test]
fn unknown_tv_fails_closed_because_its_boundary_is_not_known() {
    let wire = [0x32, 0x01, 0, 6, 0, 0, 0, 0, 0, 1, 0, 0, 42, 0];
    let error = GtpuControlMessage::decode(&wire, DecodeContext::default())
        .expect_err("unknown TV must fail closed");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::UnknownTvIe { ie_type: 42 }
    );
}

#[test]
fn comprehension_bits_drive_unknown_extension_handling() {
    let classes = [
        (
            0x04,
            GtpuExtensionHeaderComprehension::NotRequiredForward,
            false,
            false,
        ),
        (
            0x44,
            GtpuExtensionHeaderComprehension::NotRequiredDiscardByIntermediate,
            false,
            false,
        ),
        (
            0x84,
            GtpuExtensionHeaderComprehension::RequiredByEndpoint,
            true,
            false,
        ),
        (
            0xc4,
            GtpuExtensionHeaderComprehension::RequiredByRecipient,
            true,
            true,
        ),
    ];
    for (value, class, endpoint_required, intermediate_required) in classes {
        let header_type = GtpuExtensionHeaderType::new(value);
        assert_eq!(header_type.comprehension(), class);
        assert_eq!(
            class.is_required_by(GtpuExtensionHeaderRecipient::Endpoint),
            endpoint_required
        );
        assert_eq!(
            class.is_required_by(GtpuExtensionHeaderRecipient::Intermediate),
            intermediate_required
        );
    }

    let pdcp = GtpuExtensionHeaderType::new(0xc0);
    assert!(pdcp.unsupported_requires_comprehension_by(GtpuExtensionHeaderRecipient::Intermediate));
    assert!(!pdcp.unsupported_requires_comprehension_by(
        GtpuExtensionHeaderRecipient::ServingGatewayReceivingGpdu
    ));
}

#[test]
fn generic_decoder_rejects_only_unknown_comprehension_required_extensions() {
    for (extension_type, should_reject) in
        [(0x04, false), (0x44, false), (0x84, true), (0xc4, true)]
    {
        let wire = [
            0x34,
            0xff,
            0,
            8,
            0x11,
            0x22,
            0x33,
            0x44,
            0,
            0,
            0,
            extension_type,
            1,
            0xaa,
            0xbb,
            0,
        ];
        let ctx = DecodeContext {
            unknown_ie_policy: UnknownIePolicy::Reject,
            ..DecodeContext::default()
        };
        let preserved = match GtpuMessage::decode(&wire, DecodeContext::default()) {
            Ok((_, value)) => value,
            Err(error) => panic!("preserve decode failed: {error:?}"),
        };
        let required = match preserved
            .first_unsupported_required_extension(GtpuExtensionHeaderRecipient::Endpoint)
        {
            Ok(value) => value,
            Err(error) => panic!("extension analysis failed: {error:?}"),
        };
        assert_eq!(required.is_some(), should_reject);

        let result = GtpuMessage::decode(&wire, ctx);
        if should_reject {
            let error = result.expect_err("required extension must be rejected");
            assert_eq!(error.code(), &DecodeErrorCode::UnknownCriticalIe);
        } else {
            assert!(result.is_ok(), "optional extension must be skipped");
        }
    }
}

#[test]
fn unsupported_extension_scan_rejects_bytes_after_terminal_header() {
    let wire = [
        0x34, 0xff, 0, 8, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0x87, 1, 0xaa, 0xbb, 0,
    ];
    let (_, mut message) = GtpuMessage::decode(&wire, DecodeContext::default())
        .expect("generic preserve decode must accept the required extension");
    let terminal_then_trailing = [1, 0xaa, 0xbb, 0, 1, 0xcc, 0xdd, 0];
    message.header.length = 12;
    message.raw_extension_headers = &terminal_then_trailing;

    let error = message
        .first_unsupported_required_extension(GtpuExtensionHeaderRecipient::Endpoint)
        .expect_err("trailing raw bytes must take precedence over notification planning");
    assert_eq!(
        error.code(),
        &DecodeErrorCode::Structural {
            reason: "bytes remain after terminal extension header",
        }
    );
    assert_eq!(error.offset(), 4);
}

#[test]
fn typed_control_reports_required_extension_for_notification_planning() {
    let wire = [
        0x36, 0x01, 0, 8, 0, 0, 0, 0, 0, 1, 0, 0x87, 1, 0xaa, 0xbb, 0,
    ];
    let error = GtpuControlMessage::decode(&wire, DecodeContext::default())
        .expect_err("unsupported required extension must fail");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::UnsupportedRequiredExtension {
            extension_type: 0x87
        }
    );

    let mut optional = wire;
    optional[11] = 0x07;
    let decoded = decode(&optional);
    assert_eq!(encode(&decoded).as_ref(), optional);
}

#[test]
fn mandatory_cardinality_order_flags_and_teid_fail_closed() {
    let missing_recovery = [0x32, 0x02, 0, 4, 0, 0, 0, 0, 0, 1, 0, 0];
    assert_eq!(
        GtpuControlMessage::decode(&missing_recovery, DecodeContext::default())
            .expect_err("missing Recovery must fail")
            .code(),
        &GtpuControlCodecErrorCode::MissingMandatoryIe { ie_type: 14 }
    );

    let duplicate_recovery = [0x32, 0x02, 0, 8, 0, 0, 0, 0, 0, 1, 0, 0, 14, 0, 14, 0];
    assert_eq!(
        GtpuControlMessage::decode(&duplicate_recovery, DecodeContext::default())
            .expect_err("duplicate Recovery must fail")
            .code(),
        &GtpuControlCodecErrorCode::DuplicateIe { ie_type: 14 }
    );

    let out_of_order = [
        0x32, 0x02, 0, 12, 0, 0, 0, 0, 0, 1, 0, 0, 0xff, 0, 2, 0, 1, 14, 0, 0,
    ];
    assert_eq!(
        GtpuControlMessage::decode(&out_of_order, DecodeContext::default())
            .expect_err("out-of-order IEs must fail")
            .code(),
        &GtpuControlCodecErrorCode::IesOutOfOrder
    );

    let mut wrong_teid = ECHO_REQUEST.to_vec();
    wrong_teid[7] = 1;
    assert_eq!(
        GtpuControlMessage::decode(&wrong_teid, DecodeContext::default())
            .expect_err("Echo TEID must be zero")
            .code(),
        &GtpuControlCodecErrorCode::InvalidHeaderTeid
    );

    let mut wrong_s = ECHO_REQUEST.to_vec();
    wrong_s[0] = 0x30;
    wrong_s[2..4].copy_from_slice(&0u16.to_be_bytes());
    wrong_s.truncate(8);
    assert_eq!(
        GtpuControlMessage::decode(&wrong_s, DecodeContext::default())
            .expect_err("Echo S flag must be one")
            .code(),
        &GtpuControlCodecErrorCode::InvalidHeaderFlags
    );

    let mut marker_with_s = END_MARKER.to_vec();
    marker_with_s[0] = 0x32;
    marker_with_s[2..4].copy_from_slice(&4u16.to_be_bytes());
    marker_with_s.extend_from_slice(&[0, 1, 0, 0]);
    assert_eq!(
        GtpuControlMessage::decode(&marker_with_s, DecodeContext::default())
            .expect_err("End Marker S flag must be zero")
            .code(),
        &GtpuControlCodecErrorCode::InvalidHeaderFlags
    );
}

#[test]
fn extension_type_list_accepts_empty_and_rejects_zero_or_duplicate_values() {
    let empty = GtpuExtensionHeaderTypeList::new(std::iter::empty());
    let empty = empty.expect("TS 29.281 permits a list of zero supported types");
    assert!(empty.as_slice().is_empty());

    for values in [vec![0], vec![0x40, 0x40]] {
        let result =
            GtpuExtensionHeaderTypeList::new(values.into_iter().map(GtpuExtensionHeaderType::new));
        assert!(result.is_err());
    }

    let wire = [0x32, 0x1f, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 141, 0, 0];
    let message = decode(&wire);
    let notification = match &message {
        GtpuControlMessage::SupportedExtensionHeadersNotification(value) => value,
        other => panic!("unexpected message: {other:?}"),
    };
    assert!(notification.supported_types().as_slice().is_empty());
    assert_eq!(encode(&message).as_ref(), wire);
}

#[test]
fn error_indication_mandatory_ie_cardinality_and_offsets_are_exact() {
    let missing_teid = [
        0x32, 0x1a, 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 133, 0, 4, 192, 0, 2, 1,
    ];
    let error = GtpuControlMessage::decode(&missing_teid, DecodeContext::default())
        .expect_err("missing TEID Data I must fail");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::MissingMandatoryIe { ie_type: 16 }
    );
    assert_eq!(error.offset(), 19);

    let missing_peer = [
        0x32, 0x1a, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0x11, 0x22, 0x33, 0x44,
    ];
    let error = GtpuControlMessage::decode(&missing_peer, DecodeContext::default())
        .expect_err("missing GTP-U Peer Address must fail");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::MissingMandatoryIe { ie_type: 133 }
    );
    assert_eq!(error.offset(), 17);

    let duplicate_teid = [
        0x32, 0x1a, 0, 21, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0x11, 0x22, 0x33, 0x44, 16, 0x55, 0x66,
        0x77, 0x88, 133, 0, 4, 192, 0, 2, 1,
    ];
    let error = GtpuControlMessage::decode(&duplicate_teid, DecodeContext::default())
        .expect_err("duplicate TEID Data I must fail");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::DuplicateIe { ie_type: 16 }
    );
    assert_eq!(error.offset(), 17);

    let duplicate_peer = [
        0x32, 0x1a, 0, 23, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0x11, 0x22, 0x33, 0x44, 133, 0, 4, 192, 0,
        2, 1, 133, 0, 4, 198, 51, 100, 1,
    ];
    let error = GtpuControlMessage::decode(&duplicate_peer, DecodeContext::default())
        .expect_err("duplicate GTP-U Peer Address must fail");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::DuplicateIe { ie_type: 133 }
    );
    assert_eq!(error.offset(), 24);
}

#[test]
fn duplicate_timestamp_and_supported_type_list_fail_at_datagram_offsets() {
    let duplicate_timestamp = [
        0x32, 0x01, 0, 18, 0, 0, 0, 0, 0, 1, 0, 0, 231, 0, 4, 1, 2, 3, 4, 231, 0, 4, 5, 6, 7, 8,
    ];
    let error = GtpuControlMessage::decode(&duplicate_timestamp, DecodeContext::default())
        .expect_err("duplicate Recovery Time Stamp must fail");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::DuplicateIe { ie_type: 231 }
    );
    assert_eq!(error.offset(), 19);

    let duplicate_type_list = [
        0x32, 0x1f, 0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 141, 0, 1, 0x40, 141, 0, 1, 0x85,
    ];
    let error = GtpuControlMessage::decode(&duplicate_type_list, DecodeContext::default())
        .expect_err("duplicate Extension Header Type List must fail");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::DuplicateIe { ie_type: 141 }
    );
    assert_eq!(error.offset(), 16);
}

#[test]
fn error_and_supported_notification_require_sequence_and_zero_header_teid() {
    let valid_error_without_optional_header = [
        0x30, 0x1a, 0, 12, 0, 0, 0, 0, 16, 0x11, 0x22, 0x33, 0x44, 133, 0, 4, 192, 0, 2, 1,
    ];
    let error = GtpuControlMessage::decode(
        &valid_error_without_optional_header,
        DecodeContext::default(),
    )
    .expect_err("Error Indication requires S=1");
    assert_eq!(error.code(), &GtpuControlCodecErrorCode::InvalidHeaderFlags);
    assert_eq!(error.offset(), 0);

    let mut error_with_teid = ERROR_INDICATION_IPV6.to_vec();
    error_with_teid[7] = 1;
    let error = GtpuControlMessage::decode(&error_with_teid, DecodeContext::default())
        .expect_err("Error Indication header TEID must be zero");
    assert_eq!(error.code(), &GtpuControlCodecErrorCode::InvalidHeaderTeid);
    assert_eq!(error.offset(), 4);

    let supported_without_optional_header = [0x30, 0x1f, 0, 4, 0, 0, 0, 0, 141, 0, 1, 0x40];
    let error =
        GtpuControlMessage::decode(&supported_without_optional_header, DecodeContext::default())
            .expect_err("Supported Extension Headers Notification requires S=1");
    assert_eq!(error.code(), &GtpuControlCodecErrorCode::InvalidHeaderFlags);
    assert_eq!(error.offset(), 0);

    let mut supported_with_teid = SUPPORTED_EXTENSION_HEADERS.to_vec();
    supported_with_teid[7] = 1;
    let error = GtpuControlMessage::decode(&supported_with_teid, DecodeContext::default())
        .expect_err("Supported Extension Headers Notification TEID must be zero");
    assert_eq!(error.code(), &GtpuControlCodecErrorCode::InvalidHeaderTeid);
    assert_eq!(error.offset(), 4);
}

#[test]
fn unexpected_ie_offset_is_datagram_relative() {
    let recovery_on_echo_request = [0x32, 0x01, 0, 6, 0, 0, 0, 0, 0, 1, 0, 0, 14, 0];
    let error = GtpuControlMessage::decode(&recovery_on_echo_request, DecodeContext::default())
        .expect_err("Recovery is not valid on Echo Request");
    assert_eq!(
        error.code(),
        &GtpuControlCodecErrorCode::UnexpectedIe { ie_type: 14 }
    );
    assert_eq!(error.offset(), 12);
}

#[test]
fn known_ie_and_udp_extension_lengths_fail_closed() {
    let invalid_peer_address = [
        0x32, 0x1a, 0, 17, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 1, 133, 0, 5, 192, 0, 2, 1, 0,
    ];
    assert_eq!(
        GtpuControlMessage::decode(&invalid_peer_address, DecodeContext::default())
            .expect_err("five-octet peer address must fail")
            .code(),
        &GtpuControlCodecErrorCode::InvalidIeLength { ie_type: 133 }
    );

    let short_timestamp = [
        0x32, 0x01, 0, 10, 0, 0, 0, 0, 0, 1, 0, 0, 231, 0, 3, 1, 2, 3,
    ];
    assert_eq!(
        GtpuControlMessage::decode(&short_timestamp, DecodeContext::default())
            .expect_err("short timestamp must fail")
            .code(),
        &GtpuControlCodecErrorCode::InvalidIeLength { ie_type: 231 }
    );

    let short_private = [0x32, 0x01, 0, 8, 0, 0, 0, 0, 0, 1, 0, 0, 255, 0, 1, 0];
    assert_eq!(
        GtpuControlMessage::decode(&short_private, DecodeContext::default())
            .expect_err("short Private Extension must fail")
            .code(),
        &GtpuControlCodecErrorCode::InvalidIeLength { ie_type: 255 }
    );

    let invalid_udp_extension = [
        0x36, 0x1a, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0x40, 2, 0x08, 0x68, 0, 0, 0, 0, 0, 16, 0, 0, 0, 1,
        133, 0, 4, 192, 0, 2, 1,
    ];
    assert_eq!(
        GtpuControlMessage::decode(&invalid_udp_extension, DecodeContext::default())
            .expect_err("oversized UDP Port extension must fail")
            .code(),
        &GtpuControlCodecErrorCode::InvalidExtensionLength
    );
}

#[test]
fn duplicate_udp_extension_and_wrong_procedure_ie_fail_closed() {
    let duplicate_udp_extension = [
        0x36, 0x1a, 0, 24, 0, 0, 0, 0, 0, 0, 0, 0x40, 1, 0x08, 0x68, 0x40, 1, 0x08, 0x68, 0, 16, 0,
        0, 0, 1, 133, 0, 4, 192, 0, 2, 1,
    ];
    assert_eq!(
        GtpuControlMessage::decode(&duplicate_udp_extension, DecodeContext::default())
            .expect_err("duplicate UDP Port extension must fail")
            .code(),
        &GtpuControlCodecErrorCode::UnexpectedExtension {
            extension_type: 0x40
        }
    );

    let tunnel_status_on_echo = [0x32, 0x01, 0, 8, 0, 0, 0, 0, 0, 1, 0, 0, 230, 0, 1, 0];
    assert_eq!(
        GtpuControlMessage::decode(&tunnel_status_on_echo, DecodeContext::default())
            .expect_err("Tunnel Status IE is not valid on Echo")
            .code(),
        &GtpuControlCodecErrorCode::UnexpectedIe { ie_type: 230 }
    );

    let gpdu = [0x30, 0xff, 0, 2, 0, 0, 0, 1, 42, 0];
    assert_eq!(
        GtpuControlMessage::decode(&gpdu, DecodeContext::default())
            .expect_err("malformed G-PDU payload must not be parsed as control IEs")
            .code(),
        &GtpuControlCodecErrorCode::UnsupportedMessageType
    );
}

#[test]
fn malformed_lengths_limits_and_capacity_are_bounded() {
    assert_eq!(
        GtpuControlMessage::decode(&[0x30], DecodeContext::default())
            .expect_err("short frame must fail")
            .code(),
        &GtpuControlCodecErrorCode::Framing {
            code: DecodeErrorCode::Truncated
        }
    );

    for fixture in [
        ECHO_REQUEST,
        ECHO_RESPONSE,
        ERROR_INDICATION_IPV4_WITH_UDP_PORT,
        ERROR_INDICATION_IPV6,
        SUPPORTED_EXTENSION_HEADERS,
        END_MARKER,
        END_MARKER_WITH_PDU_SESSION_CONTAINER,
        ECHO_REQUEST_TIMESTAMP_AND_PRIVATE,
        ECHO_REQUEST_UNUSED_NEXT_EXTENSION,
    ] {
        for length in 0..fixture.len() {
            assert!(
                GtpuControlMessage::decode(&fixture[..length], DecodeContext::default()).is_err()
            );
        }
    }

    let limited = DecodeContext {
        max_ies: 0,
        ..DecodeContext::default()
    };
    assert_eq!(
        GtpuControlMessage::decode(ECHO_RESPONSE, limited)
            .expect_err("IE limit must be enforced")
            .code(),
        &GtpuControlCodecErrorCode::IeCountExceeded
    );

    let model = GtpuControlMessage::EchoRequest(GtpuEchoRequest::new(1));
    let encode_ctx = EncodeContext {
        max_message_len: 11,
        ..EncodeContext::default()
    };
    assert_eq!(
        model
            .to_bytes(encode_ctx)
            .expect_err("capacity must be enforced")
            .code(),
        &GtpuControlCodecErrorCode::CapacityExceeded
    );

    let mut oversized_payload = GtpuEchoRequest::new(1);
    oversized_payload
        .push_private_extension(GtpuPrivateExtension::new(1, Bytes::from(vec![0xa5; 4096])));
    let oversized_payload = GtpuControlMessage::EchoRequest(oversized_payload);
    assert_eq!(
        oversized_payload
            .to_bytes(EncodeContext {
                max_message_len: 12,
                ..EncodeContext::default()
            })
            .expect_err("exact wire-size preflight must reject before serialization")
            .code(),
        &GtpuControlCodecErrorCode::CapacityExceeded
    );

    let mut too_many_ies = GtpuEchoRequest::new(1);
    for identifier in 0..=256u16 {
        too_many_ies.push_private_extension(GtpuPrivateExtension::new(identifier, Bytes::new()));
    }
    assert_eq!(
        GtpuControlMessage::EchoRequest(too_many_ies)
            .to_bytes(EncodeContext::default())
            .expect_err("builder IE count must be bounded before reference allocation")
            .code(),
        &GtpuControlCodecErrorCode::IeCountExceeded
    );

    let mut overlong = ECHO_REQUEST.to_vec();
    overlong.push(0xff);
    assert_eq!(
        GtpuControlMessage::decode_datagram(&overlong, DecodeContext::default())
            .expect_err("datagram decode must reject trailing bytes")
            .code(),
        &GtpuControlCodecErrorCode::TrailingBytes
    );
}
