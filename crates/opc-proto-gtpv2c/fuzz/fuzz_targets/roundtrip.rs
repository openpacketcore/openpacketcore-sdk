#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use opc_proto_gtpv2c::{Message, S2bMessage};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext};

fuzz_target!(|data: &[u8]| {
    if let Ok((tail, message)) = Message::decode(data, DecodeContext::default()) {
        let parsed_len = data.len() - tail.len();
        let parsed = &data[..parsed_len];

        let mut raw = BytesMut::new();
        if message
            .encode(
                &mut raw,
                EncodeContext {
                    raw_preserving: true,
                    ..EncodeContext::default()
                },
            )
            .is_ok()
        {
            assert_eq!(raw.as_ref(), parsed);
        }

        let mut canonical = BytesMut::new();
        if message
            .encode(&mut canonical, EncodeContext::default())
            .is_ok()
        {
            if let Ok((canonical_tail, canonical_message)) =
                Message::decode(canonical.as_ref(), DecodeContext::default())
            {
                assert!(canonical_tail.is_empty());
                let mut canonical_again = BytesMut::new();
                if canonical_message
                    .encode(&mut canonical_again, EncodeContext::default())
                    .is_ok()
                {
                    assert_eq!(canonical_again.as_ref(), canonical.as_ref());
                }
            }
        }
    }

    if let Ok((tail, message)) = S2bMessage::decode(data, DecodeContext::default()) {
        let parsed_len = data.len() - tail.len();
        let parsed = &data[..parsed_len];
        let mut raw = BytesMut::new();
        if message
            .encode(
                &mut raw,
                EncodeContext {
                    raw_preserving: true,
                    ..EncodeContext::default()
                },
            )
            .is_ok()
        {
            assert_eq!(raw.as_ref(), parsed);
        }
    }
});
