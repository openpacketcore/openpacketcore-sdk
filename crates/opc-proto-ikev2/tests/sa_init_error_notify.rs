use bytes::BytesMut;
use opc_proto_ikev2::{
    build_ike_sa_init_invalid_ke_response, build_ike_sa_init_notify_response, Header, HeaderFlags,
    Ikev2NotifyPayload, Ikev2NotifyPayloadBuild, Ikev2SaInitNotifyBuildError, Message, PayloadType,
    EXCHANGE_TYPE_CREATE_CHILD_SA, EXCHANGE_TYPE_IKE_SA_INIT, IKEV2_NOTIFY_INVALID_KE_PAYLOAD,
    IKEV2_NOTIFY_INVALID_SYNTAX, IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, IKEV2_NOTIFY_PROTOCOL_ID_NONE,
};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext};

const INITIATOR_SPI: u64 = 0x0102_0304_0506_0708;

fn request_header() -> Header {
    Header::new(
        INITIATOR_SPI,
        0,
        PayloadType::SecurityAssociation,
        EXCHANGE_TYPE_IKE_SA_INIT,
        HeaderFlags::from_bits(true, false, false),
        0,
    )
}

fn notify(notify_message_type: u16, notification_data: Vec<u8>) -> Ikev2NotifyPayloadBuild {
    Ikev2NotifyPayloadBuild {
        protocol_id: IKEV2_NOTIFY_PROTOCOL_ID_NONE,
        spi: Vec::new(),
        notify_message_type,
        notification_data,
    }
}

fn encode_response(response: &opc_proto_ikev2::OwnedMessage) -> BytesMut {
    let mut encoded = BytesMut::new();
    match response.encode(&mut encoded, EncodeContext::default()) {
        Ok(()) => encoded,
        Err(error) => panic!("IKE_SA_INIT error response encode failed: {error:?}"),
    }
}

#[test]
fn invalid_ke_response_is_byte_exact_and_decodes_roundtrip() {
    let request = request_header();
    let response = match build_ike_sa_init_invalid_ke_response(&request, 19) {
        Ok(value) => value,
        Err(error) => panic!("INVALID_KE_PAYLOAD response build failed: {error:?}"),
    };

    let encoded = encode_response(&response);
    assert_eq!(
        encoded.as_ref(),
        &[
            // IKE header: initiator SPI A, responder SPI zero.
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // First payload Notify, IKEv2, IKE_SA_INIT, R=1/I=0.
            0x29, 0x20, 0x22, 0x20, // Message ID zero; complete message length 38.
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26,
            // Final generic payload, length 10.
            0x00, 0x00, 0x00, 0x0a,
            // Protocol ID zero, SPI size zero, INVALID_KE_PAYLOAD (17).
            0x00, 0x00, 0x00, 0x11,
            // Accepted ECP-256 group (19), exactly two octets, big endian.
            0x00, 0x13,
        ]
    );

    let (tail, decoded) = match Message::decode(&encoded, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("INVALID_KE_PAYLOAD response decode failed: {error:?}"),
    };
    assert!(tail.is_empty());
    assert_eq!(decoded.header.initiator_spi, INITIATOR_SPI);
    assert_eq!(decoded.header.responder_spi, 0);
    assert_eq!(decoded.header.exchange_type, EXCHANGE_TYPE_IKE_SA_INIT);
    assert_eq!(decoded.header.message_id, 0);
    assert!(!decoded.header.flags.initiator());
    assert!(decoded.header.flags.response());
    assert_eq!(decoded.header.flags.canonical_raw(), 0x20);

    let mut payloads = decoded.payloads();
    let raw = match payloads.next() {
        Some(Ok(value)) => value,
        other => panic!("unexpected INVALID_KE_PAYLOAD response payload: {other:?}"),
    };
    assert_eq!(raw.payload_type, PayloadType::Notify);
    assert_eq!(raw.next_payload, PayloadType::NoNext);
    assert!(payloads.next().is_none());
    let decoded_notify = match Ikev2NotifyPayload::decode(raw) {
        Ok(value) => value,
        Err(error) => panic!("INVALID_KE_PAYLOAD Notify decode failed: {error:?}"),
    };
    assert_eq!(decoded_notify.protocol_id, IKEV2_NOTIFY_PROTOCOL_ID_NONE);
    assert_eq!(decoded_notify.spi_size, 0);
    assert!(decoded_notify.spi.is_empty());
    assert_eq!(
        decoded_notify.notify_message_type,
        IKEV2_NOTIFY_INVALID_KE_PAYLOAD
    );
    assert_eq!(decoded_notify.notification_data, [0x00, 0x13]);
}

#[test]
fn generic_builder_emits_bounded_no_proposal_chosen_response() {
    let request = request_header();
    let error_notify = notify(IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, Vec::new());
    let response = match build_ike_sa_init_notify_response(&request, &[error_notify]) {
        Ok(value) => value,
        Err(error) => panic!("NO_PROPOSAL_CHOSEN response build failed: {error:?}"),
    };
    let encoded = encode_response(&response);

    assert_eq!(
        encoded.as_ref(),
        &[
            // IKE header: initiator SPI A, responder SPI zero.
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, // First payload Notify, IKEv2, IKE_SA_INIT, R=1/I=0.
            0x29, 0x20, 0x22, 0x20, // Message ID zero; complete message length 36.
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24,
            // Final generic payload, length 8.
            0x00, 0x00, 0x00, 0x08,
            // Protocol ID zero, SPI size zero, NO_PROPOSAL_CHOSEN (14).
            0x00, 0x00, 0x00, 0x0e,
        ]
    );
    assert_eq!(response.header.initiator_spi, INITIATOR_SPI);
    assert_eq!(response.header.responder_spi, 0);
    assert_eq!(response.header.message_id, 0);
    assert!(!response.header.flags.initiator());
    assert!(response.header.flags.response());

    let (tail, decoded) = match Message::decode(&encoded, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("NO_PROPOSAL_CHOSEN response decode failed: {error:?}"),
    };
    assert!(tail.is_empty());
    assert_eq!(decoded.header.initiator_spi, INITIATOR_SPI);
    assert_eq!(decoded.header.responder_spi, 0);
    assert_eq!(decoded.header.exchange_type, EXCHANGE_TYPE_IKE_SA_INIT);
    assert_eq!(decoded.header.message_id, 0);
    assert!(!decoded.header.flags.initiator());
    assert!(decoded.header.flags.response());
    assert_eq!(decoded.header.flags.canonical_raw(), 0x20);

    let mut payloads = decoded.payloads();
    let raw = match payloads.next() {
        Some(Ok(value)) => value,
        other => panic!("unexpected NO_PROPOSAL_CHOSEN response payload: {other:?}"),
    };
    assert_eq!(raw.payload_type, PayloadType::Notify);
    assert_eq!(raw.next_payload, PayloadType::NoNext);
    assert!(payloads.next().is_none());
    let decoded_notify = match Ikev2NotifyPayload::decode(raw) {
        Ok(value) => value,
        Err(error) => panic!("NO_PROPOSAL_CHOSEN Notify decode failed: {error:?}"),
    };
    assert_eq!(decoded_notify.protocol_id, IKEV2_NOTIFY_PROTOCOL_ID_NONE);
    assert_eq!(decoded_notify.spi_size, 0);
    assert!(decoded_notify.spi.is_empty());
    assert_eq!(
        decoded_notify.notify_message_type,
        IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN
    );
    assert!(decoded_notify.notification_data.is_empty());
}

#[test]
fn notify_response_builder_rejects_invalid_request_headers() {
    let mut response_header = request_header();
    response_header.flags = HeaderFlags::from_bits(true, true, false);

    let mut wrong_exchange = request_header();
    wrong_exchange.exchange_type = EXCHANGE_TYPE_CREATE_CHILD_SA;

    let mut missing_initiator_flag = request_header();
    missing_initiator_flag.flags = HeaderFlags::from_bits(false, false, false);

    let mut zero_initiator_spi = request_header();
    zero_initiator_spi.initiator_spi = 0;

    let mut nonzero_message_id = request_header();
    nonzero_message_id.message_id = 1;

    let mut nonzero_responder_spi = request_header();
    nonzero_responder_spi.responder_spi = 0x1112_1314_1516_1718;

    let error_notify = notify(IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, Vec::new());
    for (header, expected) in [
        (wrong_exchange, Ikev2SaInitNotifyBuildError::NotIkeSaInit),
        (response_header, Ikev2SaInitNotifyBuildError::ResponseHeader),
        (
            missing_initiator_flag,
            Ikev2SaInitNotifyBuildError::InitiatorFlagNotSet,
        ),
        (
            zero_initiator_spi,
            Ikev2SaInitNotifyBuildError::InitiatorSpiZero,
        ),
        (
            nonzero_message_id,
            Ikev2SaInitNotifyBuildError::MessageIdNonZero,
        ),
        (
            nonzero_responder_spi,
            Ikev2SaInitNotifyBuildError::ResponderSpiNonZero,
        ),
    ] {
        let error =
            match build_ike_sa_init_notify_response(&header, std::slice::from_ref(&error_notify)) {
                Ok(value) => {
                    panic!("invalid request header unexpectedly built response: {value:?}")
                }
                Err(error) => error,
            };
        assert_eq!(error, expected);
        assert!(error.as_str().starts_with("ike_sa_init_notify_"));
    }
}

#[test]
fn notify_response_builder_rejects_unbounded_or_ambiguous_sets() {
    let request = request_header();
    let no_proposal = notify(IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, Vec::new());
    let invalid_ke = notify(IKEV2_NOTIFY_INVALID_KE_PAYLOAD, vec![0, 19]);

    let missing = match build_ike_sa_init_notify_response(&request, &[]) {
        Ok(value) => panic!("empty Notify set unexpectedly built response: {value:?}"),
        Err(error) => error,
    };
    assert_eq!(missing, Ikev2SaInitNotifyBuildError::MissingNotify);

    let multiple = match build_ike_sa_init_notify_response(&request, &[no_proposal, invalid_ke]) {
        Ok(value) => panic!("multiple error Notifies unexpectedly built response: {value:?}"),
        Err(error) => error,
    };
    assert_eq!(multiple, Ikev2SaInitNotifyBuildError::MultipleNotifies);
}

#[test]
fn notify_response_builder_enforces_ike_sa_notify_shapes_and_lengths() {
    let request = request_header();
    let mut cases = Vec::new();

    let mut wrong_protocol = notify(IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, Vec::new());
    wrong_protocol.protocol_id = 1;
    cases.push((
        wrong_protocol,
        Ikev2SaInitNotifyBuildError::ProtocolIdNotZero,
    ));

    let mut with_spi = notify(IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, Vec::new());
    with_spi.spi = vec![0xaa];
    cases.push((with_spi, Ikev2SaInitNotifyBuildError::SpiNotEmpty));

    cases.push((
        notify(IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, vec![0]),
        Ikev2SaInitNotifyBuildError::UnexpectedNotificationData,
    ));
    cases.push((
        notify(IKEV2_NOTIFY_INVALID_KE_PAYLOAD, vec![19]),
        Ikev2SaInitNotifyBuildError::InvalidKePayloadDataLength,
    ));
    cases.push((
        notify(IKEV2_NOTIFY_INVALID_KE_PAYLOAD, vec![0, 19, 0]),
        Ikev2SaInitNotifyBuildError::InvalidKePayloadDataLength,
    ));
    cases.push((
        notify(
            IKEV2_NOTIFY_INVALID_KE_PAYLOAD,
            vec![0; usize::from(u16::MAX) + 1],
        ),
        Ikev2SaInitNotifyBuildError::InvalidKePayloadDataLength,
    ));
    cases.push((
        notify(IKEV2_NOTIFY_INVALID_KE_PAYLOAD, vec![0, 0]),
        Ikev2SaInitNotifyBuildError::InvalidDhGroup,
    ));

    for (error_notify, expected) in cases {
        let error = match build_ike_sa_init_notify_response(&request, &[error_notify]) {
            Ok(value) => panic!("invalid Notify shape unexpectedly built response: {value:?}"),
            Err(error) => error,
        };
        assert_eq!(error, expected);
    }
}

#[test]
fn notify_response_builder_rejects_unprotected_invalid_syntax() {
    let request = request_header();
    let invalid_syntax = notify(IKEV2_NOTIFY_INVALID_SYNTAX, Vec::new());
    let error = match build_ike_sa_init_notify_response(&request, &[invalid_syntax]) {
        Ok(value) => panic!("unprotected INVALID_SYNTAX unexpectedly built response: {value:?}"),
        Err(error) => error,
    };

    assert_eq!(error, Ikev2SaInitNotifyBuildError::UnsupportedNotifyType);
    assert_eq!(error.as_str(), "ike_sa_init_notify_unsupported_notify_type");
}

#[test]
fn invalid_ke_convenience_builder_rejects_reserved_group_zero() {
    let error = match build_ike_sa_init_invalid_ke_response(&request_header(), 0) {
        Ok(value) => panic!("zero accepted group unexpectedly built response: {value:?}"),
        Err(error) => error,
    };
    assert_eq!(error, Ikev2SaInitNotifyBuildError::InvalidDhGroup);
}
