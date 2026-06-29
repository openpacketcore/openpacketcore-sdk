use opc_proto_ikev2::{
    build_ike_sa_init_response, decode_ike_sa_init_request_payloads, Header, HeaderFlags,
    Ikev2KeyExchangePayloadBuild, Ikev2NoncePayloadBuild, Ikev2NotifyPayloadBuild,
    Ikev2SaInitBuildError, Ikev2SaInitPayloadError, Ikev2SaInitResponsePayloads,
    Ikev2SaPayloadBuild, Ikev2SaPayloadError, Ikev2SaProposalBuild, Ikev2SaTransformBuild,
    Ikev2TransformAttributeBuild, Ikev2TransformAttributeBuildValue, Message, PayloadChain,
    PayloadType, EXCHANGE_TYPE_IKE_SA_INIT, GENERIC_PAYLOAD_HEADER_LEN, HEADER_LEN,
};
use opc_protocol::DecodeContext;

fn payload(next: PayloadType, body: &[u8]) -> Vec<u8> {
    let len = match GENERIC_PAYLOAD_HEADER_LEN.checked_add(body.len()) {
        Some(value) => value,
        None => panic!("test payload length overflow"),
    };
    let len_u16 = match u16::try_from(len) {
        Ok(value) => value,
        Err(error) => panic!("test payload length invalid: {error}"),
    };
    let mut out = Vec::with_capacity(len);
    out.push(next.as_u8());
    out.push(0);
    out.extend_from_slice(&len_u16.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn sa_body() -> Vec<u8> {
    vec![
        0, 0, 0, 16, // Proposal: last, reserved, length.
        1, 1, 0, 1, // Proposal number, IKE protocol, no SPI, one transform.
        0, 0, 0, 8, // Transform: last, reserved, length.
        1, 0, 0, 12, // Transform type ENCR, reserved, transform ID.
    ]
}

fn ke_body() -> Vec<u8> {
    let mut out = vec![0, 19, 0, 0];
    out.extend_from_slice(&[0xaa; 32]);
    out
}

fn nonce_body() -> Vec<u8> {
    vec![0xbb; 16]
}

fn notify_body() -> Vec<u8> {
    vec![0, 0, 0x40, 0x0e]
}

fn request_message<'a>(raw_payloads: &'a [u8]) -> Message<'a> {
    let mut header = Header::new(
        0x0102_0304_0506_0708,
        0,
        PayloadType::SecurityAssociation,
        EXCHANGE_TYPE_IKE_SA_INIT,
        HeaderFlags::from_bits(true, false, false),
        0,
    );
    let length = match HEADER_LEN.checked_add(raw_payloads.len()) {
        Some(value) => value,
        None => panic!("test message length overflow"),
    };
    header.length = match u32::try_from(length) {
        Ok(value) => value,
        Err(error) => panic!("test message length invalid: {error}"),
    };
    Message {
        header,
        payloads: PayloadChain::new(PayloadType::SecurityAssociation, raw_payloads),
        tail: &[],
    }
}

fn valid_payload_chain() -> Vec<u8> {
    let mut raw = Vec::new();
    raw.extend_from_slice(&payload(PayloadType::KeyExchange, &sa_body()));
    raw.extend_from_slice(&payload(PayloadType::Nonce, &ke_body()));
    raw.extend_from_slice(&payload(PayloadType::Notify, &nonce_body()));
    raw.extend_from_slice(&payload(PayloadType::VendorId, &notify_body()));
    raw.extend_from_slice(&payload(PayloadType::NoNext, b"vendor-secret"));
    raw
}

#[test]
fn decodes_sa_init_required_and_optional_payloads() {
    let raw = valid_payload_chain();
    let message = request_message(&raw);

    let decoded = match decode_ike_sa_init_request_payloads(&message, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("SA_INIT payload decode failed: {error:?}"),
    };

    assert_eq!(decoded.security_association.proposals.len(), 1);
    assert_eq!(
        decoded.security_association.proposals[0].transforms[0].transform_type,
        1
    );
    assert_eq!(
        decoded.security_association.proposals[0].transforms[0].transform_id,
        12
    );
    assert_eq!(decoded.key_exchange.dh_group, 19);
    assert_eq!(decoded.key_exchange.key_exchange_data.len(), 32);
    assert_eq!(decoded.nonce.nonce.len(), 16);
    assert_eq!(decoded.notifies.len(), 1);
    assert_eq!(decoded.vendor_ids.len(), 1);

    let debug = format!("{decoded:?}");
    assert!(!debug.contains("aa"));
    assert!(!debug.contains("bb"));
    assert!(!debug.contains("vendor-secret"));
}

#[test]
fn rejects_duplicate_required_payloads() {
    let mut raw = Vec::new();
    raw.extend_from_slice(&payload(PayloadType::KeyExchange, &sa_body()));
    raw.extend_from_slice(&payload(PayloadType::Nonce, &ke_body()));
    raw.extend_from_slice(&payload(PayloadType::Nonce, &nonce_body()));
    raw.extend_from_slice(&payload(PayloadType::NoNext, &nonce_body()));
    let message = request_message(&raw);

    let error = match decode_ike_sa_init_request_payloads(&message, DecodeContext::default()) {
        Ok(value) => panic!("duplicate nonce unexpectedly decoded: {value:?}"),
        Err(error) => error,
    };

    assert_eq!(error.as_str(), "ike_sa_init_payloads_duplicate_nonce");
}

#[test]
fn rejects_malformed_sa_payload_with_stable_code() {
    let bad_sa = vec![0, 0, 0, 8, 1, 1, 0, 0];
    let mut raw = Vec::new();
    raw.extend_from_slice(&payload(PayloadType::KeyExchange, &bad_sa));
    raw.extend_from_slice(&payload(PayloadType::Nonce, &ke_body()));
    raw.extend_from_slice(&payload(PayloadType::NoNext, &nonce_body()));
    let message = request_message(&raw);

    let error = match decode_ike_sa_init_request_payloads(&message, DecodeContext::default()) {
        Ok(value) => panic!("malformed SA unexpectedly decoded: {value:?}"),
        Err(error) => error,
    };

    assert_eq!(error.as_str(), "ike_sa_init_payloads_sa_decode_error");
    assert!(matches!(
        error,
        Ikev2SaInitPayloadError::SecurityAssociation(Ikev2SaPayloadError::MissingTransform)
    ));
}

#[test]
fn builds_canonical_sa_init_response_chain() {
    let raw = valid_payload_chain();
    let request = request_message(&raw);
    let response = match build_ike_sa_init_response(
        &request.header,
        0x1112_1314_1516_1718,
        &Ikev2SaInitResponsePayloads {
            security_association: Ikev2SaPayloadBuild {
                proposals: vec![Ikev2SaProposalBuild {
                    proposal_number: 1,
                    protocol_id: 1,
                    spi: Vec::new(),
                    transforms: vec![Ikev2SaTransformBuild {
                        transform_type: 1,
                        transform_id: 12,
                        attributes: vec![Ikev2TransformAttributeBuild {
                            attribute_type: 14,
                            value: Ikev2TransformAttributeBuildValue::Tv(256),
                        }],
                    }],
                }],
            },
            key_exchange: Ikev2KeyExchangePayloadBuild {
                dh_group: 19,
                key_exchange_data: vec![0xcc; 32],
            },
            nonce: Ikev2NoncePayloadBuild {
                nonce: vec![0xdd; 16],
            },
            notifies: vec![Ikev2NotifyPayloadBuild {
                protocol_id: 0,
                spi: Vec::new(),
                notify_message_type: 16_390,
                notification_data: vec![0xee; 8],
            }],
        },
    ) {
        Ok(value) => value,
        Err(error) => panic!("SA_INIT response build failed: {error:?}"),
    };

    assert!(response.header.flags.response());
    assert_eq!(response.header.responder_spi, 0x1112_1314_1516_1718);
    assert_eq!(
        response.header.next_payload,
        PayloadType::SecurityAssociation.as_u8()
    );

    let borrowed = response.as_borrowed();
    let mut iter = borrowed.payloads();
    let first = match iter.next() {
        Some(Ok(value)) => value,
        other => panic!("unexpected first payload: {other:?}"),
    };
    assert_eq!(first.payload_type, PayloadType::SecurityAssociation);
    assert_eq!(first.next_payload, PayloadType::KeyExchange);

    let second = match iter.next() {
        Some(Ok(value)) => value,
        other => panic!("unexpected second payload: {other:?}"),
    };
    assert_eq!(second.payload_type, PayloadType::KeyExchange);
    assert_eq!(second.next_payload, PayloadType::Nonce);

    let third = match iter.next() {
        Some(Ok(value)) => value,
        other => panic!("unexpected third payload: {other:?}"),
    };
    assert_eq!(third.payload_type, PayloadType::Nonce);
    assert_eq!(third.next_payload, PayloadType::Notify);

    let fourth = match iter.next() {
        Some(Ok(value)) => value,
        other => panic!("unexpected fourth payload: {other:?}"),
    };
    assert_eq!(fourth.payload_type, PayloadType::Notify);
    assert_eq!(fourth.next_payload, PayloadType::NoNext);
    assert!(iter.next().is_none());
}

#[test]
fn builder_rejects_missing_responder_spi_without_leaking_material() {
    let raw = valid_payload_chain();
    let request = request_message(&raw);
    let error = match build_ike_sa_init_response(
        &request.header,
        0,
        &Ikev2SaInitResponsePayloads {
            security_association: Ikev2SaPayloadBuild {
                proposals: vec![Ikev2SaProposalBuild {
                    proposal_number: 1,
                    protocol_id: 1,
                    spi: Vec::new(),
                    transforms: vec![Ikev2SaTransformBuild {
                        transform_type: 1,
                        transform_id: 12,
                        attributes: Vec::new(),
                    }],
                }],
            },
            key_exchange: Ikev2KeyExchangePayloadBuild {
                dh_group: 19,
                key_exchange_data: vec![0xaa; 32],
            },
            nonce: Ikev2NoncePayloadBuild {
                nonce: vec![0xbb; 16],
            },
            notifies: Vec::new(),
        },
    ) {
        Ok(value) => panic!("missing responder SPI unexpectedly built: {value:?}"),
        Err(error) => error,
    };

    assert_eq!(error, Ikev2SaInitBuildError::MissingResponderSpi);
    let debug = format!("{error:?}");
    assert!(!debug.contains("aa"));
    assert!(!debug.contains("bb"));
}
