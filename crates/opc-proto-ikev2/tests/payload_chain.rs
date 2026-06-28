use bytes::{Bytes, BytesMut};
use opc_proto_ikev2::{
    CryptoProvider, Header, HeaderFlags, Message, PayloadChain, PayloadType,
    ProtectedPayloadContext, ProtectedPayloadKind, RawPayload, EXCHANGE_TYPE_IKE_SA_INIT,
    HEADER_LEN,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, Encode, EncodeContext, OwnedDecode, ToOwnedPdu,
    UnknownIePolicy, ValidationLevel,
};

fn sa_nonce_message() -> [u8; HEADER_LEN + 16] {
    let mut bytes = [0u8; HEADER_LEN + 16];
    bytes[0..8].copy_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
    bytes[8..16].copy_from_slice(&0u64.to_be_bytes());
    bytes[16] = PayloadType::SecurityAssociation.as_u8();
    bytes[17] = 0x20;
    bytes[18] = EXCHANGE_TYPE_IKE_SA_INIT;
    bytes[19] = 0x08;
    bytes[20..24].copy_from_slice(&0u32.to_be_bytes());
    bytes[24..28].copy_from_slice(&((HEADER_LEN + 16) as u32).to_be_bytes());
    bytes[28..36].copy_from_slice(&[
        PayloadType::Nonce.as_u8(),
        0x00,
        0x00,
        0x08,
        0xde,
        0xad,
        0xbe,
        0xef,
    ]);
    bytes[36..44].copy_from_slice(&[0x00, 0x00, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44]);
    bytes
}

#[test]
fn decodes_unencrypted_payload_chain_and_roundtrips_raw_bytes() {
    let bytes = sa_nonce_message();
    let (tail, message) = match Message::decode(&bytes, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("message decode failed: {error:?}"),
    };
    assert!(tail.is_empty());
    assert!(message.tail.is_empty());
    assert_eq!(
        message.payloads.first_payload(),
        PayloadType::SecurityAssociation
    );

    let mut payloads = message.payloads();
    let first = match payloads.next() {
        Some(Ok(payload)) => payload,
        other => panic!("unexpected first payload: {other:?}"),
    };
    assert_eq!(first.payload_type, PayloadType::SecurityAssociation);
    assert_eq!(first.next_payload, PayloadType::Nonce);
    assert_eq!(first.body, [0xde, 0xad, 0xbe, 0xef]);
    assert!(!first.critical);

    let second = match payloads.next() {
        Some(Ok(payload)) => payload,
        other => panic!("unexpected second payload: {other:?}"),
    };
    assert_eq!(second.payload_type, PayloadType::Nonce);
    assert_eq!(second.next_payload, PayloadType::NoNext);
    assert_eq!(second.body, [0x11, 0x22, 0x33, 0x44]);
    assert!(payloads.next().is_none());

    let mut encoded = BytesMut::new();
    let result = message.encode(
        &mut encoded,
        EncodeContext {
            raw_preserving: true,
            ..EncodeContext::default()
        },
    );
    assert!(result.is_ok());
    assert_eq!(encoded.as_ref(), bytes.as_slice());

    let owned = message.to_owned_pdu();
    assert_eq!(owned.raw_payloads.as_ref(), &bytes[HEADER_LEN..]);
}

#[test]
fn owned_decode_slices_declared_message_without_tail() {
    let mut packet = sa_nonce_message().to_vec();
    packet.extend_from_slice(&[0xaa, 0xbb]);
    let owned = match opc_proto_ikev2::OwnedMessage::decode_owned(
        Bytes::copy_from_slice(&packet),
        DecodeContext::default(),
    ) {
        Ok(value) => value,
        Err(error) => panic!("owned decode failed: {error:?}"),
    };
    assert_eq!(owned.raw_payloads.len(), 16);
    assert_eq!(
        owned.raw_payloads.as_ref(),
        &packet[HEADER_LEN..HEADER_LEN + 16]
    );
}

#[test]
fn unknown_noncritical_payload_is_preserved() {
    let payload = [0x00, 0x00, 0x00, 0x04];
    let chain = PayloadChain::new(PayloadType::Unknown(200), &payload);
    let mut iter = chain.iter_with_context(DecodeContext::default());
    let payload = match iter.next() {
        Some(Ok(value)) => value,
        other => panic!("unexpected unknown payload result: {other:?}"),
    };
    assert_eq!(payload.payload_type, PayloadType::Unknown(200));
    assert_eq!(payload.body, []);
    assert!(iter.next().is_none());
}

#[test]
fn unknown_critical_payload_can_fail_closed() {
    let payload = [0x00, 0x80, 0x00, 0x04];
    let chain = PayloadChain::new(PayloadType::Unknown(200), &payload);
    let ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Reject,
        ..DecodeContext::default()
    };
    let mut iter = chain.iter_with_context(ctx);
    let result = match iter.next() {
        Some(value) => value,
        None => panic!("iterator ended before unknown critical payload"),
    };
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::UnknownCriticalIe)
    ));
}

#[test]
fn protected_payload_boundary_does_not_parse_ciphertext() {
    let payload_bytes = [
        PayloadType::SecurityAssociation.as_u8(),
        0x00,
        0x00,
        0x08,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
    ];
    let chain = PayloadChain::new(PayloadType::Encrypted, &payload_bytes);
    let mut iter = chain.iter_with_context(DecodeContext::default());
    let protected = match iter.next() {
        Some(Ok(value)) => value,
        other => panic!("unexpected protected payload: {other:?}"),
    };
    assert_eq!(protected.payload_type, PayloadType::Encrypted);
    assert_eq!(
        protected.protected_kind(),
        Some(ProtectedPayloadKind::Encrypted)
    );
    assert_eq!(protected.next_payload, PayloadType::SecurityAssociation);
    assert_eq!(protected.body, [0xaa, 0xbb, 0xcc, 0xdd]);
    assert!(iter.next().is_none());
}

struct EchoProvider;

impl CryptoProvider for EchoProvider {
    type Error = ();

    fn open_payload(
        &self,
        context: ProtectedPayloadContext<'_>,
        protected_body: &[u8],
    ) -> Result<Bytes, Self::Error> {
        assert_eq!(context.kind, ProtectedPayloadKind::Encrypted);
        assert_eq!(
            context.first_inner_payload,
            PayloadType::SecurityAssociation
        );
        Ok(Bytes::copy_from_slice(protected_body))
    }
}

#[test]
fn crypto_provider_boundary_is_caller_supplied() {
    let header = Header::new(
        0x0102_0304_0506_0708,
        0,
        PayloadType::Encrypted.as_u8(),
        EXCHANGE_TYPE_IKE_SA_INIT,
        HeaderFlags::from_bits(true, false, false),
        0,
    );
    let provider = EchoProvider;
    let context = ProtectedPayloadContext {
        header: &header,
        kind: ProtectedPayloadKind::Encrypted,
        first_inner_payload: PayloadType::SecurityAssociation,
        message_bytes: &[],
    };
    let opened = provider.open_payload(context, &[0xaa, 0xbb]);
    assert!(matches!(opened, Ok(bytes) if bytes.as_ref() == [0xaa, 0xbb]));
}

#[test]
fn malformed_payload_chain_rejects_length_truncation_limits_and_reserved_bits() {
    let too_short = [0x00, 0x00, 0x00, 0x03];
    let mut iter = PayloadChain::new(PayloadType::Nonce, &too_short).iter();
    let result = match iter.next() {
        Some(value) => value,
        None => panic!("iterator ended before invalid short length"),
    };
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::InvalidLength { .. })
    ));

    let truncated = [0x00, 0x00, 0x00, 0x08, 0xaa];
    let mut iter = PayloadChain::new(PayloadType::Nonce, &truncated).iter();
    let result = match iter.next() {
        Some(value) => value,
        None => panic!("iterator ended before truncated payload"),
    };
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::Truncated)
    ));

    let ctx = DecodeContext {
        max_ies: 0,
        ..DecodeContext::default()
    };
    let mut iter =
        PayloadChain::new(PayloadType::Nonce, &[0x00, 0x00, 0x00, 0x04]).iter_with_context(ctx);
    let result = match iter.next() {
        Some(value) => value,
        None => panic!("iterator ended before count limit"),
    };
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::IeCountExceeded)
    ));

    let ctx = DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..DecodeContext::default()
    };
    let mut iter =
        PayloadChain::new(PayloadType::Nonce, &[0x00, 0x01, 0x00, 0x04]).iter_with_context(ctx);
    let result = match iter.next() {
        Some(value) => value,
        None => panic!("iterator ended before reserved-bit rejection"),
    };
    assert!(matches!(
        result,
        Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
    ));
}

#[test]
fn message_decode_rejects_payload_bytes_when_header_says_no_next_payload() {
    let mut bytes = [0u8; HEADER_LEN + 4];
    bytes[17] = 0x20;
    bytes[18] = EXCHANGE_TYPE_IKE_SA_INIT;
    bytes[24..28].copy_from_slice(&((HEADER_LEN + 4) as u32).to_be_bytes());
    bytes[28..32].copy_from_slice(&[0x00, 0x00, 0x00, 0x04]);
    let decoded = Message::decode(&bytes, DecodeContext::default());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Structural { .. })
    ));
}

#[test]
fn encode_rejects_empty_payload_region_with_payload_type() {
    let header = Header::new(
        0x0102_0304_0506_0708,
        0,
        PayloadType::Nonce.as_u8(),
        EXCHANGE_TYPE_IKE_SA_INIT,
        HeaderFlags::from_bits(true, false, false),
        0,
    );
    let message = Message {
        header,
        payloads: PayloadChain::new(PayloadType::Nonce, &[]),
        tail: &[],
    };
    let mut encoded = BytesMut::new();
    let result = message.encode(&mut encoded, EncodeContext::default());
    assert!(result.is_err());
    assert!(encoded.is_empty());
}

#[test]
fn raw_payload_type_alias_compiles_for_public_api() {
    fn body_len(payload: RawPayload<'_>) -> usize {
        payload.body.len()
    }
    let chain = PayloadChain::new(PayloadType::Nonce, &[0x00, 0x00, 0x00, 0x04]);
    let mut iter = chain.iter();
    let payload = match iter.next() {
        Some(Ok(value)) => value,
        other => panic!("unexpected payload for API compile test: {other:?}"),
    };
    assert_eq!(body_len(payload), 0);
}
