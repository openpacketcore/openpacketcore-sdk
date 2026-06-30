use bytes::{Bytes, BytesMut};
use opc_proto_ikev2::{
    open_protected_payloads, CryptoProvider, Header, HeaderFlags, Message, OpenedProtectedPayload,
    PayloadChain, PayloadType, ProtectedPayloadContext, ProtectedPayloadKind,
    ProtectedPayloadOpenError, RawPayload, EXCHANGE_TYPE_IKE_SA_INIT, GENERIC_PAYLOAD_HEADER_LEN,
    HEADER_LEN,
};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, Encode, EncodeContext, OwnedDecode, ToOwnedPdu,
    ValidationLevel,
};
use std::{cell::Cell, fmt};

fn sa_nonce_message() -> [u8; HEADER_LEN + 16] {
    [
        0x01,                      // RFC 7296 §3.1 octet 0: Initiator SPI byte 0.
        0x02,                      // RFC 7296 §3.1 octet 1: Initiator SPI byte 1.
        0x03,                      // RFC 7296 §3.1 octet 2: Initiator SPI byte 2.
        0x04,                      // RFC 7296 §3.1 octet 3: Initiator SPI byte 3.
        0x05,                      // RFC 7296 §3.1 octet 4: Initiator SPI byte 4.
        0x06,                      // RFC 7296 §3.1 octet 5: Initiator SPI byte 5.
        0x07,                      // RFC 7296 §3.1 octet 6: Initiator SPI byte 6.
        0x08,                      // RFC 7296 §3.1 octet 7: Initiator SPI byte 7.
        0x00,                      // RFC 7296 §3.1 octet 8: Responder SPI byte 0.
        0x00,                      // RFC 7296 §3.1 octet 9: Responder SPI byte 1.
        0x00,                      // RFC 7296 §3.1 octet 10: Responder SPI byte 2.
        0x00,                      // RFC 7296 §3.1 octet 11: Responder SPI byte 3.
        0x00,                      // RFC 7296 §3.1 octet 12: Responder SPI byte 4.
        0x00,                      // RFC 7296 §3.1 octet 13: Responder SPI byte 5.
        0x00,                      // RFC 7296 §3.1 octet 14: Responder SPI byte 6.
        0x00,                      // RFC 7296 §3.1 octet 15: Responder SPI byte 7.
        0x21,                      // RFC 7296 §3.1 octet 16: first payload SA (IANA value 33).
        0x20,                      // RFC 7296 §3.1 octet 17: version 2.0.
        EXCHANGE_TYPE_IKE_SA_INIT, // RFC 7296 §3.1 octet 18: IKE_SA_INIT (34).
        0x08,                      // RFC 7296 §3.1 octet 19: Initiator flag set, V bit clear.
        0x00,                      // RFC 7296 §3.1 octet 20: Message ID byte 0.
        0x00,                      // RFC 7296 §3.1 octet 21: Message ID byte 1.
        0x00,                      // RFC 7296 §3.1 octet 22: Message ID byte 2.
        0x00,                      // RFC 7296 §3.1 octet 23: Message ID byte 3.
        0x00,                      // RFC 7296 §3.1 octet 24: Length byte 0.
        0x00,                      // RFC 7296 §3.1 octet 25: Length byte 1.
        0x00,                      // RFC 7296 §3.1 octet 26: Length byte 2.
        0x2c,                      // RFC 7296 §3.1 octet 27: Length byte 3 (44 octets).
        0x28,                      // RFC 7296 §3.2 octet 28: SA next payload Nonce (IANA value 40).
        0x00, // RFC 7296 §3.2 octet 29: SA critical bit clear, reserved bits zero.
        0x00, // RFC 7296 §3.2 octet 30: SA payload length byte 0.
        0x08, // RFC 7296 §3.2 octet 31: SA payload length byte 1 (8 octets).
        0xde, // RFC 7296 §3.2 octet 32: Hand-authored SA body byte 0.
        0xad, // RFC 7296 §3.2 octet 33: Hand-authored SA body byte 1.
        0xbe, // RFC 7296 §3.2 octet 34: Hand-authored SA body byte 2.
        0xef, // RFC 7296 §3.2 octet 35: Hand-authored SA body byte 3.
        0x00, // RFC 7296 §3.2 octet 36: Nonce next payload No Next (IANA value 0).
        0x00, // RFC 7296 §3.2 octet 37: Nonce critical bit clear, reserved bits zero.
        0x00, // RFC 7296 §3.2 octet 38: Nonce payload length byte 0.
        0x08, // RFC 7296 §3.2 octet 39: Nonce payload length byte 1 (8 octets).
        0x11, // RFC 7296 §3.2 octet 40: Hand-authored Nonce body byte 0.
        0x22, // RFC 7296 §3.2 octet 41: Hand-authored Nonce body byte 1.
        0x33, // RFC 7296 §3.2 octet 42: Hand-authored Nonce body byte 2.
        0x44, // RFC 7296 §3.2 octet 43: Hand-authored Nonce body byte 3.
    ]
}

fn protected_message_bytes(first_inner_payload: PayloadType, protected_body: &[u8]) -> Vec<u8> {
    let payload_len = match GENERIC_PAYLOAD_HEADER_LEN.checked_add(protected_body.len()) {
        Some(value) => value,
        None => panic!("test protected payload length overflow"),
    };
    let payload_len_u16 = match u16::try_from(payload_len) {
        Ok(value) => value,
        Err(error) => panic!("test protected payload length invalid: {error}"),
    };
    let mut payload = Vec::with_capacity(payload_len);
    payload.push(first_inner_payload.as_u8());
    payload.push(0);
    payload.extend_from_slice(&payload_len_u16.to_be_bytes());
    payload.extend_from_slice(protected_body);

    let header = Header::new(
        0x0102_0304_0506_0708,
        0x1112_1314_1516_1718,
        PayloadType::Encrypted,
        EXCHANGE_TYPE_IKE_SA_INIT,
        HeaderFlags::from_bits(true, false, false),
        3,
    );
    let message = Message {
        header,
        payloads: PayloadChain::new(PayloadType::Encrypted, &payload),
        tail: &[],
    };
    let mut encoded = BytesMut::new();
    match message.encode(&mut encoded, EncodeContext::default()) {
        Ok(()) => encoded.to_vec(),
        Err(error) => panic!("test protected message encode failed: {error}"),
    }
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
fn canonical_message_encode_rewrites_header_and_preserves_payload_bytes() {
    let mut bytes = sa_nonce_message();
    bytes[17] = 0x21; // RFC 7296 §3.1 version field decoded as major 2, minor 1.
    bytes[19] = 0x9f; // RFC 7296 §3.1 I and V bits plus reserved bits on input.

    let (_tail, message) = match Message::decode(&bytes, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("message decode failed: {error:?}"),
    };

    let mut encoded = BytesMut::new();
    let result = message.encode(&mut encoded, EncodeContext::default());
    assert!(result.is_ok());

    let mut expected = sa_nonce_message();
    expected[17] = 0x20; // RFC 7296 §3.1 canonical IKEv2 version 2.0.
    expected[19] = 0x08; // RFC 7296 §3.1 canonical send flags keep only I/R bits.
    assert_eq!(encoded.as_ref(), expected.as_slice());
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
fn unknown_critical_payload_rejects_by_default() {
    let payload = [0x00, 0x80, 0x00, 0x04];
    let chain = PayloadChain::new(PayloadType::Unknown(200), &payload);
    let mut iter = chain.iter_with_context(DecodeContext::default());
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
    for (payload_type, protected_kind) in [
        (PayloadType::Encrypted, ProtectedPayloadKind::Encrypted),
        (
            PayloadType::EncryptedFragment,
            ProtectedPayloadKind::EncryptedFragment,
        ),
    ] {
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
        let chain = PayloadChain::new(payload_type, &payload_bytes);
        let mut iter = chain.iter_with_context(DecodeContext::default());
        let protected = match iter.next() {
            Some(Ok(value)) => value,
            other => panic!("unexpected protected payload: {other:?}"),
        };
        assert_eq!(protected.payload_type, payload_type);
        assert_eq!(protected.protected_kind(), Some(protected_kind));
        assert_eq!(protected.next_payload, PayloadType::SecurityAssociation);
        assert_eq!(protected.body, [0xaa, 0xbb, 0xcc, 0xdd]);
        assert!(iter.next().is_none());
    }
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

#[derive(Debug)]
struct FakeCryptoError(&'static str);

impl fmt::Display for FakeCryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

struct RecordingProvider<'a> {
    calls: Cell<usize>,
    expected_message: &'a [u8],
}

impl<'a> RecordingProvider<'a> {
    fn new(expected_message: &'a [u8]) -> Self {
        Self {
            calls: Cell::new(0),
            expected_message,
        }
    }
}

impl CryptoProvider for RecordingProvider<'_> {
    type Error = FakeCryptoError;

    fn open_payload(
        &self,
        context: ProtectedPayloadContext<'_>,
        protected_body: &[u8],
    ) -> Result<Bytes, Self::Error> {
        self.calls.set(self.calls.get() + 1);
        assert_eq!(context.kind, ProtectedPayloadKind::Encrypted);
        assert_eq!(
            context.first_inner_payload,
            PayloadType::ExtensibleAuthentication
        );
        assert_eq!(context.header.message_id, 3);
        assert_eq!(context.message_bytes, self.expected_message);
        assert_eq!(protected_body, b"protected-secret");
        Ok(Bytes::from_static(b"opened-cleartext-secret"))
    }
}

struct FailingProvider;

impl CryptoProvider for FailingProvider {
    type Error = FakeCryptoError;

    fn open_payload(
        &self,
        _context: ProtectedPayloadContext<'_>,
        _protected_body: &[u8],
    ) -> Result<Bytes, Self::Error> {
        Err(FakeCryptoError("redacted-open-failed"))
    }
}

#[test]
fn crypto_provider_boundary_is_caller_supplied() {
    let header = Header::new(
        0x0102_0304_0506_0708,
        0,
        PayloadType::Encrypted,
        EXCHANGE_TYPE_IKE_SA_INIT,
        HeaderFlags::from_bits(true, false, false),
        0,
    );
    let provider = EchoProvider;
    let context = ProtectedPayloadContext {
        header: &header,
        kind: ProtectedPayloadKind::Encrypted,
        first_inner_payload: PayloadType::SecurityAssociation,
        payload_offset: 0,
        message_bytes: &[],
    };
    let opened = provider.open_payload(context, &[0xaa, 0xbb]);
    assert!(matches!(opened, Ok(bytes) if bytes.as_ref() == [0xaa, 0xbb]));
}

#[test]
fn open_protected_payloads_delegates_with_exact_outer_message_bytes() {
    let encoded =
        protected_message_bytes(PayloadType::ExtensibleAuthentication, b"protected-secret");
    let (_tail, message) = match Message::decode(&encoded, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("message decode failed: {error:?}"),
    };
    let provider = RecordingProvider::new(&encoded);

    let opened =
        match open_protected_payloads(&message, &encoded, DecodeContext::default(), &provider) {
            Ok(value) => value,
            Err(error) => panic!("protected payload open failed: {error:?}"),
        };

    assert_eq!(provider.calls.get(), 1);
    assert_eq!(
        opened,
        vec![OpenedProtectedPayload {
            kind: ProtectedPayloadKind::Encrypted,
            offset: 0,
            protected_body_len: b"protected-secret".len(),
            first_inner_payload: PayloadType::ExtensibleAuthentication,
            cleartext: Bytes::from_static(b"opened-cleartext-secret"),
        }]
    );
    let debug = format!("{opened:?}");
    assert!(!debug.contains("protected-secret"));
    assert!(!debug.contains("opened-cleartext-secret"));
    assert!(debug.contains("cleartext_len"));
}

#[test]
fn open_protected_payloads_projects_provider_failure_without_body_leakage() {
    let encoded =
        protected_message_bytes(PayloadType::ExtensibleAuthentication, b"protected-secret");
    let (_tail, message) = match Message::decode(&encoded, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("message decode failed: {error:?}"),
    };

    let error = match open_protected_payloads(
        &message,
        &encoded,
        DecodeContext::default(),
        &FailingProvider,
    ) {
        Ok(value) => panic!("provider failure unexpectedly opened payloads: {value:?}"),
        Err(error) => error,
    };

    assert_eq!(error.as_str(), "ike_protected_payload_provider_rejected");
    match &error {
        ProtectedPayloadOpenError::ProviderRejected(failure) => {
            assert_eq!(failure.kind, ProtectedPayloadKind::Encrypted);
            assert_eq!(failure.offset, 0);
            assert_eq!(failure.protected_body_len, b"protected-secret".len());
            assert_eq!(
                failure.first_inner_payload,
                PayloadType::ExtensibleAuthentication
            );
            assert_eq!(failure.provider_error, "redacted-open-failed");
        }
        other => panic!("unexpected protected payload open error: {other:?}"),
    }
    let debug = format!("{error:?}");
    assert!(!debug.contains("protected-secret"));
}

#[test]
fn open_protected_payloads_rejects_non_matching_outer_message_bytes() {
    let encoded =
        protected_message_bytes(PayloadType::ExtensibleAuthentication, b"protected-secret");
    let (_tail, message) = match Message::decode(&encoded, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("message decode failed: {error:?}"),
    };
    let provider = RecordingProvider::new(&encoded);
    let short = &encoded[..encoded.len() - 1];

    let error = match open_protected_payloads(&message, short, DecodeContext::default(), &provider)
    {
        Ok(value) => panic!("short message bytes unexpectedly opened payloads: {value:?}"),
        Err(error) => error,
    };
    assert_eq!(
        error.as_str(),
        "ike_protected_payload_message_bytes_length_mismatch"
    );
    assert_eq!(provider.calls.get(), 0);

    let mut mismatched = encoded.clone();
    match mismatched.get_mut(HEADER_LEN + GENERIC_PAYLOAD_HEADER_LEN) {
        Some(byte) => *byte ^= 0xff,
        None => panic!("test protected payload body byte missing"),
    }
    let error =
        match open_protected_payloads(&message, &mismatched, DecodeContext::default(), &provider) {
            Ok(value) => panic!("mismatched message bytes unexpectedly opened payloads: {value:?}"),
            Err(error) => error,
        };
    assert_eq!(
        error.as_str(),
        "ike_protected_payload_message_payload_mismatch"
    );
    assert_eq!(provider.calls.get(), 0);
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
        PayloadType::Nonce,
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
