use bytes::BytesMut;
use opc_proto_ikev2::{
    classify_ike_nat_traversal_datagram, inspect_ike_nat_traversal_datagram, Ikev2MessageRejection,
    Ikev2PayloadChainRejection, Ikev2SaInitNotifyBuildError,
    Ikev2SaInitUnknownCriticalPayloadRequestError, Ikev2UnknownCriticalPayloadMessage, Message,
    NatTraversalClassification, NatTraversalIkeTransport, NatTraversalRejection, PayloadChain,
    PayloadType, EXCHANGE_TYPE_IKE_SA_INIT, HEADER_LEN, IKEV2_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD,
    IKE_NAT_TRAVERSAL_UDP_PORT, IKE_UDP_PORT,
};
use opc_protocol::{BorrowDecode, DecodeContext, DecodeErrorCode, Encode, EncodeContext};

const TEST_INITIATOR_SPI: u64 = 0x0102_0304_0506_0708;
const UNKNOWN_CRITICAL_TYPE: u8 = 200;
const WIRE_EXCHANGE_TYPE_IKE_SA_INIT: u8 = 34;
const WIRE_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD: u16 = 1;

// RFC 7296 section 3.2, independently authored generic-payload bytes. The
// outer IKE header names type 200; its complete four-octet generic header sets
// Critical, declares no body, and terminates the chain.
const FIRST_UNKNOWN_CRITICAL: [u8; 4] = [0x00, 0x80, 0x00, 0x04];

// A known Vendor ID payload precedes type 200. The offending payload is in the
// middle and names a final known Nonce payload. Every declared length is exact.
const MIDDLE_UNKNOWN_CRITICAL: [u8; 13] = [
    0xc8, 0x00, 0x00, 0x05, 0xaa, // V -> unknown 200, one-octet body.
    0x28, 0x80, 0x00, 0x04, // unknown 200 -> Nonce, Critical, empty body.
    0x00, 0x00, 0x00, 0x04, // Nonce -> NONE, empty generic body.
];

// A known Vendor ID and a skippable unknown noncritical type 201 precede the
// final offending type 200. This is also the exact three-payload count fixture.
const FINAL_UNKNOWN_CRITICAL: [u8; 15] = [
    0xc9, 0x00, 0x00, 0x05, 0xbb, // V -> unknown 201, one-octet body.
    0xc8, 0x00, 0x00, 0x06, 0xcc, 0xdd, // unknown 201 -> unknown 200.
    0x00, 0x80, 0x00, 0x04, // unknown 200 -> NONE, Critical.
];

fn synthetic_ike_message(
    first_payload: u8,
    exchange_type: u8,
    flags: u8,
    payloads: &[u8],
) -> Vec<u8> {
    let total_len = match HEADER_LEN.checked_add(payloads.len()) {
        Some(value) => value,
        None => panic!("synthetic IKE fixture length overflow"),
    };
    let total_len = match u32::try_from(total_len) {
        Ok(value) => value,
        Err(error) => panic!("synthetic IKE fixture length invalid: {error}"),
    };

    // RFC 7296 section 3.1 fixed header, authored independently of the SDK
    // encoder. Only the test SPI is non-zero; the responder SPI and Message ID
    // are zero for an initial request.
    let mut message = Vec::with_capacity(total_len as usize);
    message.extend_from_slice(&TEST_INITIATOR_SPI.to_be_bytes());
    message.extend_from_slice(&0u64.to_be_bytes());
    message.push(first_payload);
    message.push(0x20);
    message.push(exchange_type);
    message.push(flags);
    message.extend_from_slice(&0u32.to_be_bytes());
    message.extend_from_slice(&total_len.to_be_bytes());
    message.extend_from_slice(payloads);
    message
}

fn unknown_message(bytes: &[u8]) -> Ikev2UnknownCriticalPayloadMessage {
    match Message::decode_with_rejection(bytes, DecodeContext::default()) {
        Err(Ikev2MessageRejection::UnknownCriticalPayload(rejection)) => rejection,
        other => panic!("unexpected detailed message result: {other:?}"),
    }
}

#[test]
fn generic_iterator_preserves_exact_type_and_offset_without_accepting_body() {
    let chain = PayloadChain::new(
        PayloadType::Unknown(UNKNOWN_CRITICAL_TYPE),
        &FIRST_UNKNOWN_CRITICAL,
    );
    let mut iterator = chain.iter_with_context(DecodeContext::default());

    let error = match iterator.next() {
        Some(Err(error)) => error,
        other => panic!("unexpected raw iterator result: {other:?}"),
    };
    assert!(matches!(error.code(), DecodeErrorCode::UnknownCriticalIe));
    let rejection = match iterator.unknown_critical_rejection() {
        Some(value) => value,
        None => panic!("missing typed unknown-critical rejection"),
    };
    assert_eq!(rejection.code(), "ike_unknown_critical_payload");
    assert_eq!(rejection.payload_type(), UNKNOWN_CRITICAL_TYPE);
    assert_eq!(rejection.payload_offset(), 0);
    assert!(iterator.next().is_none());

    assert!(matches!(
        chain.validate_with_rejection(DecodeContext::default()),
        Err(Ikev2PayloadChainRejection::UnknownCriticalPayload(value))
            if value == rejection
    ));

    let message = synthetic_ike_message(
        UNKNOWN_CRITICAL_TYPE,
        EXCHANGE_TYPE_IKE_SA_INIT,
        0x08,
        &FIRST_UNKNOWN_CRITICAL,
    );
    assert!(matches!(
        Message::decode(&message, DecodeContext::default()),
        Err(error) if matches!(error.code(), DecodeErrorCode::UnknownCriticalIe)
    ));
}

#[test]
fn first_middle_and_final_positions_retain_exact_offsets() {
    let fixtures = [
        (
            PayloadType::Unknown(UNKNOWN_CRITICAL_TYPE).as_u8(),
            FIRST_UNKNOWN_CRITICAL.as_slice(),
            0,
        ),
        (
            PayloadType::VendorId.as_u8(),
            MIDDLE_UNKNOWN_CRITICAL.as_slice(),
            5,
        ),
        (
            PayloadType::VendorId.as_u8(),
            FINAL_UNKNOWN_CRITICAL.as_slice(),
            11,
        ),
    ];

    for (first_payload, payloads, expected_offset) in fixtures {
        let request =
            synthetic_ike_message(first_payload, EXCHANGE_TYPE_IKE_SA_INIT, 0x08, payloads);
        let rejection = unknown_message(&request).rejection();
        assert_eq!(rejection.payload_type(), UNKNOWN_CRITICAL_TYPE);
        assert_eq!(rejection.payload_offset(), expected_offset);
    }
}

#[test]
fn maximum_payload_count_accepts_offender_at_limit_but_not_beyond_it() {
    let request = synthetic_ike_message(
        PayloadType::VendorId.as_u8(),
        EXCHANGE_TYPE_IKE_SA_INIT,
        0x08,
        &FINAL_UNKNOWN_CRITICAL,
    );
    let at_limit = DecodeContext {
        max_ies: 3,
        ..DecodeContext::default()
    };
    let rejection = match Message::decode_with_rejection(&request, at_limit) {
        Err(Ikev2MessageRejection::UnknownCriticalPayload(rejection)) => rejection,
        other => panic!("unexpected at-limit result: {other:?}"),
    };
    assert_eq!(rejection.rejection().payload_offset(), 11);

    let before_offender = DecodeContext {
        max_ies: 2,
        ..DecodeContext::default()
    };
    assert!(matches!(
        Message::decode_with_rejection(&request, before_offender),
        Err(Ikev2MessageRejection::Malformed(error))
            if matches!(error.code(), DecodeErrorCode::IeCountExceeded)
    ));
}

#[test]
fn message_length_bound_wins_before_unknown_critical_projection() {
    let request = synthetic_ike_message(
        UNKNOWN_CRITICAL_TYPE,
        EXCHANGE_TYPE_IKE_SA_INIT,
        0x08,
        &FIRST_UNKNOWN_CRITICAL,
    );
    let bounded = DecodeContext {
        max_message_len: request.len() - 1,
        ..DecodeContext::default()
    };
    assert!(matches!(
        Message::decode_with_rejection(&request, bounded),
        Err(Ikev2MessageRejection::Malformed(error))
            if matches!(error.code(), DecodeErrorCode::MessageLengthExceeded)
    ));

    let chain = PayloadChain::new(
        PayloadType::Unknown(UNKNOWN_CRITICAL_TYPE),
        &FIRST_UNKNOWN_CRITICAL,
    );
    let chain_bound = DecodeContext {
        max_message_len: FIRST_UNKNOWN_CRITICAL.len() - 1,
        ..DecodeContext::default()
    };
    assert!(matches!(
        chain.validate_with_rejection(chain_bound),
        Err(Ikev2PayloadChainRejection::Malformed(error))
            if matches!(error.code(), DecodeErrorCode::MessageLengthExceeded)
    ));

    let mut iterator = chain.iter_with_context(chain_bound);
    assert!(matches!(
        iterator.next(),
        Some(Err(error)) if matches!(error.code(), DecodeErrorCode::MessageLengthExceeded)
    ));
    assert!(iterator.next().is_none());
    assert_eq!(iterator.unknown_critical_rejection(), None);
}

#[test]
fn initial_request_composes_into_exact_notify_type_one_response() {
    let request = synthetic_ike_message(
        UNKNOWN_CRITICAL_TYPE,
        WIRE_EXCHANGE_TYPE_IKE_SA_INIT,
        0x08,
        &FIRST_UNKNOWN_CRITICAL,
    );
    let reply_request = match unknown_message(&request).try_into_ike_sa_init_request() {
        Ok(value) => value,
        Err(error) => panic!("request did not gain expected reply authority: {error}"),
    };
    assert_eq!(
        reply_request.offending_payload_type(),
        UNKNOWN_CRITICAL_TYPE
    );
    assert_eq!(reply_request.payload_offset(), 0);

    let response = match reply_request.build_response() {
        Ok(value) => value,
        Err(error) => panic!("response build failed: {error}"),
    };
    assert_eq!(response.header.initiator_spi, TEST_INITIATOR_SPI);
    assert_eq!(response.header.responder_spi, 0);
    assert!(response.header.flags.response());
    assert!(!response.header.flags.initiator());
    assert_eq!(response.header.message_id, 0);
    assert_eq!(
        response.header.exchange_type,
        WIRE_EXCHANGE_TYPE_IKE_SA_INIT
    );
    assert_eq!(response.header.next_payload, PayloadType::Notify.as_u8());
    assert_eq!(EXCHANGE_TYPE_IKE_SA_INIT, WIRE_EXCHANGE_TYPE_IKE_SA_INIT);
    assert_eq!(
        IKEV2_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD,
        WIRE_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD
    );
    assert_eq!(
        response.raw_payloads.as_ref(),
        [
            0x00,
            0x00,
            0x00,
            0x09, // Generic Notify header: NONE, flags zero, length 9.
            0x00,
            0x00,
            0x00,
            0x01,
            UNKNOWN_CRITICAL_TYPE,
        ]
    );

    let mut encoded = BytesMut::new();
    if let Err(error) = response.encode(&mut encoded, EncodeContext::default()) {
        panic!("response encode failed: {error}");
    }
    assert_eq!(encoded.len(), HEADER_LEN + 9);
}

#[test]
fn udp_500_and_udp_4500_preserve_transport_and_identical_rejection() {
    let ike = synthetic_ike_message(
        PayloadType::VendorId.as_u8(),
        EXCHANGE_TYPE_IKE_SA_INIT,
        0x08,
        &MIDDLE_UNKNOWN_CRITICAL,
    );
    let mut natt = vec![0, 0, 0, 0];
    natt.extend_from_slice(&ike);

    for (port, datagram, expected_transport) in [
        (
            IKE_UDP_PORT,
            ike.as_slice(),
            NatTraversalIkeTransport::Udp500,
        ),
        (
            IKE_NAT_TRAVERSAL_UDP_PORT,
            natt.as_slice(),
            NatTraversalIkeTransport::Udp4500NonEspMarker,
        ),
    ] {
        let inspection = inspect_ike_nat_traversal_datagram(port, datagram);
        assert_eq!(inspection.code(), "ike_unknown_critical_payload");
        assert!(matches!(
            inspection.classification(),
            NatTraversalClassification::Rejected(NatTraversalRejection::MalformedIke {
                transport,
                decode_code: opc_proto_ikev2::NatTraversalIkeDecodeErrorCode::UnknownCriticalPayload,
            }) if *transport == expected_transport
        ));
        let rejection = match inspection.unknown_critical_payload() {
            Some(value) => value,
            None => panic!("missing typed NAT traversal rejection"),
        };
        assert_eq!(rejection.transport(), expected_transport);
        assert_eq!(
            rejection.rejection().rejection().payload_type(),
            UNKNOWN_CRITICAL_TYPE
        );
        assert_eq!(rejection.rejection().rejection().payload_offset(), 5);
        assert!(rejection.rejection().try_into_ike_sa_init_request().is_ok());

        assert!(matches!(
            classify_ike_nat_traversal_datagram(port, datagram),
            NatTraversalClassification::Rejected(NatTraversalRejection::MalformedIke {
                transport,
                decode_code: opc_proto_ikev2::NatTraversalIkeDecodeErrorCode::UnknownCriticalPayload,
            }) if transport == expected_transport
        ));
    }
}

#[test]
fn unknown_noncritical_and_known_critical_payloads_remain_accepted() {
    let unknown_noncritical = synthetic_ike_message(
        201,
        EXCHANGE_TYPE_IKE_SA_INIT,
        0x08,
        &[0x00, 0x00, 0x00, 0x04],
    );
    let (_, message) =
        match Message::decode_with_rejection(&unknown_noncritical, DecodeContext::default()) {
            Ok(value) => value,
            Err(error) => panic!("unknown noncritical payload was rejected: {error:?}"),
        };
    let payload = match message.payloads().next() {
        Some(Ok(value)) => value,
        other => panic!("unexpected unknown noncritical payload: {other:?}"),
    };
    assert_eq!(payload.payload_type, PayloadType::Unknown(201));
    assert!(!payload.critical);

    let known_critical = synthetic_ike_message(
        PayloadType::VendorId.as_u8(),
        EXCHANGE_TYPE_IKE_SA_INIT,
        0x08,
        &[0x00, 0x80, 0x00, 0x04],
    );
    let (_, message) =
        match Message::decode_with_rejection(&known_critical, DecodeContext::default()) {
            Ok(value) => value,
            Err(error) => panic!("known critical payload was rejected: {error:?}"),
        };
    let payload = match message.payloads().next() {
        Some(Ok(value)) => value,
        other => panic!("unexpected known critical payload: {other:?}"),
    };
    assert_eq!(payload.payload_type, PayloadType::VendorId);
    assert!(payload.critical);
}

#[test]
fn malformed_unknown_critical_framing_never_becomes_typed_or_reply_capable() {
    let cases = [
        // Complete generic header, but declared length is below four.
        vec![0x00, 0x80, 0x00, 0x03],
        // Declares one body octet that is not present.
        vec![0x00, 0x80, 0x00, 0x05],
        // Generic header itself is truncated.
        vec![0x00, 0x80, 0x00],
    ];

    for payloads in cases {
        let request = synthetic_ike_message(
            UNKNOWN_CRITICAL_TYPE,
            EXCHANGE_TYPE_IKE_SA_INIT,
            0x08,
            &payloads,
        );
        assert!(matches!(
            Message::decode_with_rejection(&request, DecodeContext::default()),
            Err(Ikev2MessageRejection::Malformed(_))
        ));

        let chain = PayloadChain::new(PayloadType::Unknown(UNKNOWN_CRITICAL_TYPE), &payloads);
        let mut iterator = chain.iter_with_context(DecodeContext::default());
        assert!(matches!(iterator.next(), Some(Err(_))));
        assert_eq!(iterator.unknown_critical_rejection(), None);
    }
}

#[test]
fn fixed_header_and_preceding_chain_failures_remain_malformed() {
    // Truncated fixed header: no complete request projection exists.
    let truncated_header = [0u8; HEADER_LEN - 1];
    assert!(matches!(
        Message::decode_with_rejection(&truncated_header, DecodeContext::default()),
        Err(Ikev2MessageRejection::Malformed(error))
            if matches!(error.code(), DecodeErrorCode::Truncated)
    ));

    // Complete fixed header declares one more byte than the supplied message.
    let mut declared_too_long = synthetic_ike_message(
        UNKNOWN_CRITICAL_TYPE,
        EXCHANGE_TYPE_IKE_SA_INIT,
        0x08,
        &FIRST_UNKNOWN_CRITICAL,
    );
    let longer_len = match u32::try_from(declared_too_long.len() + 1) {
        Ok(value) => value,
        Err(error) => panic!("synthetic declared length invalid: {error}"),
    };
    declared_too_long[24..28].copy_from_slice(&longer_len.to_be_bytes());
    assert!(matches!(
        Message::decode_with_rejection(&declared_too_long, DecodeContext::default()),
        Err(Ikev2MessageRejection::Malformed(error))
            if matches!(error.code(), DecodeErrorCode::Truncated)
    ));

    // A known Vendor ID claims an illegal three-octet length before its Next
    // Payload link could establish the following type 200 offender.
    let malformed_predecessor = [
        UNKNOWN_CRITICAL_TYPE,
        0x00,
        0x00,
        0x03,
        0x00,
        0x80,
        0x00,
        0x04,
    ];
    let request = synthetic_ike_message(
        PayloadType::VendorId.as_u8(),
        EXCHANGE_TYPE_IKE_SA_INIT,
        0x08,
        &malformed_predecessor,
    );
    assert!(matches!(
        Message::decode_with_rejection(&request, DecodeContext::default()),
        Err(Ikev2MessageRejection::Malformed(error))
            if matches!(error.code(), DecodeErrorCode::InvalidLength { .. })
    ));
    let inspection = inspect_ike_nat_traversal_datagram(IKE_UDP_PORT, &request);
    assert!(inspection.unknown_critical_payload().is_none());
    assert!(matches!(
        inspection.classification(),
        NatTraversalClassification::Rejected(NatTraversalRejection::MalformedIke {
            decode_code: opc_proto_ikev2::NatTraversalIkeDecodeErrorCode::InvalidLength,
            ..
        })
    ));
}

#[test]
fn responses_and_trailing_messages_never_gain_reply_authority() {
    let response = synthetic_ike_message(
        UNKNOWN_CRITICAL_TYPE,
        EXCHANGE_TYPE_IKE_SA_INIT,
        0x20,
        &FIRST_UNKNOWN_CRITICAL,
    );
    let response_rejection = unknown_message(&response);
    assert!(!response_rejection.is_request());
    assert!(matches!(
        response_rejection.try_into_ike_sa_init_request(),
        Err(
            Ikev2SaInitUnknownCriticalPayloadRequestError::InvalidRequest(
                Ikev2SaInitNotifyBuildError::ResponseHeader
            )
        )
    ));

    let mut trailing_request = synthetic_ike_message(
        UNKNOWN_CRITICAL_TYPE,
        EXCHANGE_TYPE_IKE_SA_INIT,
        0x08,
        &FIRST_UNKNOWN_CRITICAL,
    );
    trailing_request.extend_from_slice(&[0xde, 0xad]);
    assert!(matches!(
        unknown_message(&trailing_request).try_into_ike_sa_init_request(),
        Err(Ikev2SaInitUnknownCriticalPayloadRequestError::TrailingBytes)
    ));
    assert!(matches!(
        classify_ike_nat_traversal_datagram(IKE_UDP_PORT, &trailing_request),
        NatTraversalClassification::Rejected(NatTraversalRejection::TrailingIkeBytes {
            transport: NatTraversalIkeTransport::Udp500,
            declared_len,
            actual_len,
        }) if declared_len == HEADER_LEN + FIRST_UNKNOWN_CRITICAL.len()
            && actual_len == trailing_request.len()
    ));
}

#[test]
fn non_initial_request_shapes_do_not_gain_reply_authority() {
    let no_initiator_flag = synthetic_ike_message(
        UNKNOWN_CRITICAL_TYPE,
        EXCHANGE_TYPE_IKE_SA_INIT,
        0x00,
        &FIRST_UNKNOWN_CRITICAL,
    );
    assert!(matches!(
        unknown_message(&no_initiator_flag).try_into_ike_sa_init_request(),
        Err(
            Ikev2SaInitUnknownCriticalPayloadRequestError::InvalidRequest(
                Ikev2SaInitNotifyBuildError::InitiatorFlagNotSet
            )
        )
    ));

    let other_exchange = synthetic_ike_message(
        UNKNOWN_CRITICAL_TYPE,
        EXCHANGE_TYPE_IKE_SA_INIT + 1,
        0x08,
        &FIRST_UNKNOWN_CRITICAL,
    );
    assert!(matches!(
        unknown_message(&other_exchange).try_into_ike_sa_init_request(),
        Err(
            Ikev2SaInitUnknownCriticalPayloadRequestError::InvalidRequest(
                Ikev2SaInitNotifyBuildError::NotIkeSaInit
            )
        )
    ));
}

#[test]
fn typed_rejection_diagnostics_are_redaction_safe() {
    let request = synthetic_ike_message(
        PayloadType::VendorId.as_u8(),
        EXCHANGE_TYPE_IKE_SA_INIT,
        0x08,
        &MIDDLE_UNKNOWN_CRITICAL,
    );
    let detailed = match Message::decode_with_rejection(&request, DecodeContext::default()) {
        Err(error @ Ikev2MessageRejection::UnknownCriticalPayload(_)) => error,
        other => panic!("unexpected detailed result: {other:?}"),
    };
    let message_rejection = match &detailed {
        Ikev2MessageRejection::UnknownCriticalPayload(value) => *value,
        Ikev2MessageRejection::Malformed(_) => panic!("unexpected malformed rejection"),
    };
    let reply_request = match message_rejection.try_into_ike_sa_init_request() {
        Ok(value) => value,
        Err(error) => panic!("request projection failed: {error}"),
    };
    let inspection = inspect_ike_nat_traversal_datagram(IKE_UDP_PORT, &request);

    for debug in [
        format!("{detailed:?}"),
        format!("{message_rejection:?}"),
        format!("{reply_request:?}"),
        format!("{inspection:?}"),
    ] {
        assert!(debug.contains("ike_unknown_critical_payload"));
        assert!(debug.contains("payload_type"));
        assert!(debug.contains("payload_offset"));
        assert!(!debug.contains("initiator_spi"));
        assert!(!debug.contains("responder_spi"));
        assert!(!debug.contains("72623859790382856"));
        assert!(!debug.contains("[200, 0, 0, 5"));
        assert!(!debug.contains("[222, 173"));
    }
}
