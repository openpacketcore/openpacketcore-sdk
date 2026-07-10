use bytes::{Bytes, BytesMut};
use opc_proto_ikev2::{
    build_ike_sa_init_cookie_response, extract_ike_sa_init_cookie_notify, Header, HeaderFlags,
    Ikev2CookieNotifyBuildError, Ikev2CookieNotifyExtractError, Ikev2NotifyPayload,
    Ikev2NotifyPayloadError, Message, OwnedMessage, PayloadChain, PayloadType, RawPayload,
    EXCHANGE_TYPE_CREATE_CHILD_SA, EXCHANGE_TYPE_IKE_SA_INIT, GENERIC_PAYLOAD_HEADER_LEN,
    HEADER_LEN, IKEV2_NOTIFY_AUTHENTICATION_FAILED, IKEV2_NOTIFY_CHILD_SA_NOT_FOUND,
    IKEV2_NOTIFY_COOKIE, IKEV2_NOTIFY_COOKIE2, IKEV2_NOTIFY_FAILED_CP_REQUIRED,
    IKEV2_NOTIFY_INTERNAL_ADDRESS_FAILURE, IKEV2_NOTIFY_INVALID_IKE_SPI,
    IKEV2_NOTIFY_INVALID_KE_PAYLOAD, IKEV2_NOTIFY_INVALID_MAJOR_VERSION,
    IKEV2_NOTIFY_INVALID_MESSAGE_ID, IKEV2_NOTIFY_INVALID_SELECTORS, IKEV2_NOTIFY_INVALID_SPI,
    IKEV2_NOTIFY_INVALID_SYNTAX, IKEV2_NOTIFY_NO_ADDITIONAL_SAS, IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN,
    IKEV2_NOTIFY_PROTOCOL_ID_NONE, IKEV2_NOTIFY_SINGLE_PAIR_REQUIRED,
    IKEV2_NOTIFY_TEMPORARY_FAILURE, IKEV2_NOTIFY_TS_UNACCEPTABLE,
    IKEV2_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD,
};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext};

fn request_header(exchange_type: u8, responder_spi: u64, message_id: u32) -> Header {
    Header::new(
        0x0102_0304_0506_0708,
        responder_spi,
        PayloadType::Notify,
        exchange_type,
        HeaderFlags::from_bits(true, false, false),
        message_id,
    )
}

fn response_header() -> Header {
    Header::new(
        0x0102_0304_0506_0708,
        0,
        PayloadType::Notify,
        EXCHANGE_TYPE_IKE_SA_INIT,
        HeaderFlags::from_bits(true, true, false),
        0,
    )
}

fn notify_body(protocol_id: u8, spi: &[u8], notify_type: u16, data: &[u8]) -> Vec<u8> {
    let spi_size = match u8::try_from(spi.len()) {
        Ok(value) => value,
        Err(error) => panic!("test SPI length invalid: {error}"),
    };
    let mut body = Vec::with_capacity(4 + spi.len() + data.len());
    body.push(protocol_id);
    body.push(spi_size);
    body.extend_from_slice(&notify_type.to_be_bytes());
    body.extend_from_slice(spi);
    body.extend_from_slice(data);
    body
}

fn generic_payload(next_payload: PayloadType, body: &[u8]) -> Vec<u8> {
    let payload_len = match GENERIC_PAYLOAD_HEADER_LEN.checked_add(body.len()) {
        Some(value) => value,
        None => panic!("test generic payload length overflow"),
    };
    let payload_len_u16 = match u16::try_from(payload_len) {
        Ok(value) => value,
        Err(error) => panic!("test generic payload length invalid: {error}"),
    };
    let mut payload = Vec::with_capacity(payload_len);
    payload.push(next_payload.as_u8());
    payload.push(0);
    payload.extend_from_slice(&payload_len_u16.to_be_bytes());
    payload.extend_from_slice(body);
    payload
}

fn request_message(first_payload: PayloadType, raw_payloads: Vec<u8>) -> OwnedMessage {
    let mut header = request_header(EXCHANGE_TYPE_IKE_SA_INIT, 0, 0);
    header.next_payload = first_payload.as_u8();
    let total_len = match HEADER_LEN.checked_add(raw_payloads.len()) {
        Some(value) => value,
        None => panic!("test request message length overflow"),
    };
    header.length = match u32::try_from(total_len) {
        Ok(value) => value,
        Err(error) => panic!("test request message length invalid: {error}"),
    };
    OwnedMessage {
        header,
        raw_payloads: Bytes::from(raw_payloads),
    }
}

fn first_raw_notify<'a>(raw_payloads: &'a [u8]) -> RawPayload<'a> {
    let chain = PayloadChain::new(PayloadType::Notify, raw_payloads);
    let mut iter = chain.iter();
    match iter.next() {
        Some(Ok(payload)) => payload,
        Some(Err(error)) => panic!("test Notify payload decode failed: {error:?}"),
        None => panic!("test Notify payload missing"),
    }
}

#[test]
fn notify_payload_view_parses_and_redacts_spi_and_data() {
    let body = notify_body(
        1,
        &[0xaa, 0xbb, 0xcc, 0xdd],
        IKEV2_NOTIFY_COOKIE,
        b"secret-cookie",
    );
    let payload = generic_payload(PayloadType::NoNext, &body);
    let raw = first_raw_notify(&payload);

    let notify = match Ikev2NotifyPayload::decode(raw) {
        Ok(value) => value,
        Err(error) => panic!("Notify decode failed: {error:?}"),
    };

    assert_eq!(notify.protocol_id, 1);
    assert_eq!(notify.spi_size, 4);
    assert_eq!(notify.notify_message_type, IKEV2_NOTIFY_COOKIE);
    assert_eq!(notify.spi, [0xaa, 0xbb, 0xcc, 0xdd]);
    assert_eq!(notify.notification_data, b"secret-cookie");
    assert!(notify.is_cookie());
    assert!(!notify.is_cookie2());

    let debug = format!("{notify:?}");
    assert!(!debug.contains("secret-cookie"));
    assert!(!debug.contains("aa"));

    let error = match Ikev2NotifyPayload::decode_body(&[0, 0, 0]) {
        Ok(value) => panic!("short Notify body unexpectedly decoded: {value:?}"),
        Err(error) => error,
    };
    assert_eq!(error, Ikev2NotifyPayloadError::BodyTooShort);
    assert_eq!(error.as_str(), "ike_notify_body_too_short");
}

#[test]
fn notify_error_registry_matches_rfc_7296() {
    assert_eq!(IKEV2_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD, 1);
    assert_eq!(IKEV2_NOTIFY_INVALID_IKE_SPI, 4);
    assert_eq!(IKEV2_NOTIFY_INVALID_MAJOR_VERSION, 5);
    assert_eq!(IKEV2_NOTIFY_INVALID_SYNTAX, 7);
    assert_eq!(IKEV2_NOTIFY_INVALID_MESSAGE_ID, 9);
    assert_eq!(IKEV2_NOTIFY_INVALID_SPI, 11);
    assert_eq!(IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, 14);
    assert_eq!(IKEV2_NOTIFY_INVALID_KE_PAYLOAD, 17);
    assert_eq!(IKEV2_NOTIFY_AUTHENTICATION_FAILED, 24);
    assert_eq!(IKEV2_NOTIFY_SINGLE_PAIR_REQUIRED, 34);
    assert_eq!(IKEV2_NOTIFY_NO_ADDITIONAL_SAS, 35);
    assert_eq!(IKEV2_NOTIFY_INTERNAL_ADDRESS_FAILURE, 36);
    assert_eq!(IKEV2_NOTIFY_FAILED_CP_REQUIRED, 37);
    assert_eq!(IKEV2_NOTIFY_TS_UNACCEPTABLE, 38);
    assert_eq!(IKEV2_NOTIFY_INVALID_SELECTORS, 39);
    assert_eq!(IKEV2_NOTIFY_TEMPORARY_FAILURE, 43);
    assert_eq!(IKEV2_NOTIFY_CHILD_SA_NOT_FOUND, 44);
}

#[test]
fn cookie_response_builder_encodes_canonical_notify_response() {
    let request = request_header(EXCHANGE_TYPE_IKE_SA_INIT, 0, 0);
    let response = match build_ike_sa_init_cookie_response(&request, b"secret-cookie") {
        Ok(value) => value,
        Err(error) => panic!("COOKIE response build failed: {error:?}"),
    };

    assert_eq!(response.header.initiator_spi, request.initiator_spi);
    assert_eq!(response.header.responder_spi, 0);
    assert_eq!(response.header.exchange_type, EXCHANGE_TYPE_IKE_SA_INIT);
    assert!(
        !response.header.flags.initiator(),
        "responder must clear the Initiator flag (RFC 7296 §3.1)"
    );
    assert!(
        response.header.flags.response(),
        "responder must set the Response flag"
    );
    assert_eq!(
        response.header.flags.canonical_raw(),
        0x20,
        "cookie response flags octet must be R=1, I=0"
    );
    assert_eq!(response.header.message_id, 0);

    let mut encoded = BytesMut::new();
    match response.encode(&mut encoded, EncodeContext::default()) {
        Ok(()) => {}
        Err(error) => panic!("COOKIE response encode failed: {error:?}"),
    }
    let (_tail, decoded) = match Message::decode(&encoded, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("COOKIE response decode failed: {error:?}"),
    };
    let mut payloads = decoded.payloads();
    let raw = match payloads.next() {
        Some(Ok(value)) => value,
        other => panic!("unexpected COOKIE response payload: {other:?}"),
    };
    assert_eq!(raw.payload_type, PayloadType::Notify);
    assert_eq!(raw.next_payload, PayloadType::NoNext);
    assert!(payloads.next().is_none());
    let notify = match Ikev2NotifyPayload::decode(raw) {
        Ok(value) => value,
        Err(error) => panic!("COOKIE response Notify decode failed: {error:?}"),
    };
    assert_eq!(notify.protocol_id, IKEV2_NOTIFY_PROTOCOL_ID_NONE);
    assert_eq!(notify.spi_size, 0);
    assert_eq!(notify.notify_message_type, IKEV2_NOTIFY_COOKIE);
    assert_eq!(notify.notification_data, b"secret-cookie");
}

#[test]
fn cookie_extractor_returns_single_cookie_and_rejects_duplicates() {
    let cookie_body = notify_body(
        IKEV2_NOTIFY_PROTOCOL_ID_NONE,
        &[],
        IKEV2_NOTIFY_COOKIE,
        b"secret-cookie",
    );
    let request = request_message(
        PayloadType::Notify,
        generic_payload(PayloadType::NoNext, &cookie_body),
    );
    let borrowed = request.as_borrowed();

    let cookie = match extract_ike_sa_init_cookie_notify(&borrowed, DecodeContext::default()) {
        Ok(Some(value)) => value,
        Ok(None) => panic!("COOKIE Notify was not extracted"),
        Err(error) => panic!("COOKIE extraction failed: {error:?}"),
    };

    assert_eq!(cookie.offset, 0);
    assert_eq!(cookie.cookie(), b"secret-cookie");
    let debug = format!("{cookie:?}");
    assert!(!debug.contains("secret-cookie"));
    assert!(debug.contains("cookie_len"));

    let mut duplicate_payloads = generic_payload(PayloadType::Notify, &cookie_body);
    duplicate_payloads.extend_from_slice(&generic_payload(PayloadType::NoNext, &cookie_body));
    let duplicate_request = request_message(PayloadType::Notify, duplicate_payloads);
    let duplicate_borrowed = duplicate_request.as_borrowed();
    let error =
        match extract_ike_sa_init_cookie_notify(&duplicate_borrowed, DecodeContext::default()) {
            Ok(value) => panic!("duplicate COOKIE Notify unexpectedly extracted: {value:?}"),
            Err(error) => error,
        };
    assert_eq!(error.as_str(), "ike_cookie_extract_duplicate_cookie_notify");
    assert_eq!(error, Ikev2CookieNotifyExtractError::DuplicateCookieNotify);
}

#[test]
fn cookie_extractor_ignores_cookie2_and_rejects_bad_cookie_shape() {
    let cookie2_body = notify_body(
        IKEV2_NOTIFY_PROTOCOL_ID_NONE,
        &[],
        IKEV2_NOTIFY_COOKIE2,
        b"cookie2-data",
    );
    let request = request_message(
        PayloadType::Notify,
        generic_payload(PayloadType::NoNext, &cookie2_body),
    );
    let borrowed = request.as_borrowed();
    let extracted = match extract_ike_sa_init_cookie_notify(&borrowed, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("COOKIE2-only request should not fail: {error:?}"),
    };
    assert!(extracted.is_none());

    let bad_cookie_body = notify_body(1, &[0xaa], IKEV2_NOTIFY_COOKIE, b"secret-cookie");
    let bad_request = request_message(
        PayloadType::Notify,
        generic_payload(PayloadType::NoNext, &bad_cookie_body),
    );
    let bad_borrowed = bad_request.as_borrowed();
    let error = match extract_ike_sa_init_cookie_notify(&bad_borrowed, DecodeContext::default()) {
        Ok(value) => panic!("bad COOKIE Notify shape unexpectedly extracted: {value:?}"),
        Err(error) => error,
    };
    assert_eq!(error.as_str(), "ike_cookie_extract_invalid_cookie_shape");
    assert_eq!(error, Ikev2CookieNotifyExtractError::InvalidCookieShape);
}

#[test]
fn cookie_response_builder_and_extractor_validate_ike_sa_init_request_boundary() {
    let response = response_header();
    let response_error = match build_ike_sa_init_cookie_response(&response, b"secret-cookie") {
        Ok(value) => panic!("response header unexpectedly built COOKIE response: {value:?}"),
        Err(error) => error,
    };
    assert_eq!(response_error, Ikev2CookieNotifyBuildError::ResponseHeader);
    assert_eq!(
        response_error.as_str(),
        "ike_cookie_response_from_response_header"
    );

    let non_init = request_header(EXCHANGE_TYPE_CREATE_CHILD_SA, 0, 0);
    let non_init_error = match build_ike_sa_init_cookie_response(&non_init, b"secret-cookie") {
        Ok(value) => panic!("non-SA_INIT header unexpectedly built COOKIE response: {value:?}"),
        Err(error) => error,
    };
    assert_eq!(non_init_error, Ikev2CookieNotifyBuildError::NotIkeSaInit);

    let bad_message = request_message(PayloadType::NoNext, Vec::new());
    let mut bad_header = bad_message.as_borrowed();
    bad_header.header.message_id = 1;
    let error = match extract_ike_sa_init_cookie_notify(&bad_header, DecodeContext::default()) {
        Ok(value) => panic!("bad Message ID unexpectedly extracted COOKIE: {value:?}"),
        Err(error) => error,
    };
    assert_eq!(error, Ikev2CookieNotifyExtractError::MessageIdNonZero);
}
