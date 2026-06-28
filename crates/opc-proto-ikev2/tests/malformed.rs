use bytes::{Bytes, BytesMut};
use opc_proto_ikev2::{Message, OwnedMessage, PayloadChain, PayloadType};
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeErrorCode, Encode, EncodeContext, OwnedDecode,
};

fn assert_decode_does_not_panic(input: &[u8]) {
    let message = std::panic::catch_unwind(|| {
        let _ = Message::decode(input, DecodeContext::default());
    });
    assert!(message.is_ok(), "message decode panicked for {input:?}");

    let owned = std::panic::catch_unwind(|| {
        let _ = OwnedMessage::decode_owned(Bytes::copy_from_slice(input), DecodeContext::default());
    });
    assert!(owned.is_ok(), "owned decode panicked for {input:?}");

    let payloads = std::panic::catch_unwind(|| {
        for item in PayloadChain::new(PayloadType::Nonce, input).iter() {
            if item.is_err() {
                break;
            }
        }
    });
    assert!(payloads.is_ok(), "payload iteration panicked for {input:?}");
}

#[test]
fn malformed_prefixes_and_structural_inputs_do_not_panic() {
    let valid = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 40, 0x20, 34, 0x08,
        0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0, 8, 0x11, 0x22, 0x33, 0x44,
    ];
    for len in 0..valid.len() {
        assert_decode_does_not_panic(&valid[..len]);
    }

    let malformed_cases: &[&[u8]] = &[
        &[0xff, 0xff, 0xff, 0xff],
        &[0; 28],
        &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 0x20, 34, 0x08, 0, 0, 0, 0, 0xff,
            0xff, 0xff, 0xff,
        ],
        &[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 40, 0x20, 34, 0x08, 0, 0, 0, 0, 0, 0,
            0, 32, 0, 0,
        ],
    ];
    for input in malformed_cases {
        assert_decode_does_not_panic(input);
    }
}

#[test]
fn message_rejects_declared_boundary_and_capacity_errors() {
    let too_long = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 34, 0x08,
        0, 0, 0, 0, 0, 0, 0, 28,
    ];
    let ctx = DecodeContext {
        max_message_len: 27,
        ..DecodeContext::default()
    };
    let decoded = Message::decode(&too_long, ctx);
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::MessageLengthExceeded)
    ));

    let mut incomplete = too_long;
    incomplete[16] = PayloadType::Nonce.as_u8();
    incomplete[27] = 36;
    let decoded = Message::decode(&incomplete, DecodeContext::default());
    assert!(matches!(
        decoded,
        Err(error) if matches!(error.code(), DecodeErrorCode::Truncated)
    ));
}

#[test]
fn encode_capacity_failure_happens_before_writing() {
    let packet = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 40, 0x20, 34, 0x08,
        0, 0, 0, 0, 0, 0, 0, 36, 0, 0, 0, 8, 0x11, 0x22, 0x33, 0x44,
    ];
    let (_, message) = match Message::decode(&packet, DecodeContext::default()) {
        Ok(value) => value,
        Err(error) => panic!("decode for capacity test failed: {error:?}"),
    };
    let mut encoded = BytesMut::new();
    let ctx = EncodeContext {
        max_message_len: 35,
        ..EncodeContext::default()
    };
    let result = message.encode(&mut encoded, ctx);
    assert!(result.is_err());
    assert!(encoded.is_empty());
}
