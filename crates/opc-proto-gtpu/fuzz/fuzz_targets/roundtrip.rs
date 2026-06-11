#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use opc_proto_gtpu::GtpuMessage;
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext, ValidationLevel};

fuzz_target!(|data: &[u8]| {
    // 1. Raw-preserving roundtrip check:
    // Any successfully decoded GTP-U message must encode back to the exact same bytes in raw-preserving mode.
    let ctx = DecodeContext {
        validation_level: ValidationLevel::Structural,
        ..DecodeContext::default()
    };

    if let Ok((tail, msg)) = GtpuMessage::decode(data, ctx) {
        let parsed_len = data.len() - tail.len();
        let original_parsed_bytes = &data[..parsed_len];

        let mut buf = BytesMut::new();
        let mut raw_ctx = EncodeContext::default();
        raw_ctx.raw_preserving = true;

        if msg.encode(&mut buf, raw_ctx).is_ok() {
            assert_eq!(
                buf.as_ref(),
                original_parsed_bytes,
                "Raw-preserving roundtrip failed: encode(decode(input)) != input"
            );
        }

        // 2. Canonical roundtrip check:
        // Any canonically encoded message must decode to a model that, when encoded again, produces identical bytes.
        let mut canonical_buf = BytesMut::new();
        let canonical_ctx = EncodeContext::default();

        if msg.encode(&mut canonical_buf, canonical_ctx).is_ok() {
            let decode_ctx = DecodeContext::default();
            if let Ok((tail_can, msg_can)) = GtpuMessage::decode(&canonical_buf, decode_ctx) {
                assert!(
                    tail_can.is_empty(),
                    "Canonical encoding left unconsumed tail bytes after decoding"
                );

                let mut canonical_buf_2 = BytesMut::new();
                msg_can
                    .encode(&mut canonical_buf_2, canonical_ctx)
                    .expect("Failed to encode canonical message a second time");

                assert_eq!(
                    canonical_buf.as_ref(),
                    canonical_buf_2.as_ref(),
                    "Canonical roundtrip failed: encode(decode(encode(model))) != encode(model)"
                );
            }
        }
    }
});
