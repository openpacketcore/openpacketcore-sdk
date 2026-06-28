#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use opc_proto_ikev2::Message;
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext};

fuzz_target!(|data: &[u8]| {
    if let Ok((_tail, message)) = Message::decode(data, DecodeContext::default()) {
        let mut encoded = BytesMut::new();
        let _ = message.encode(
            &mut encoded,
            EncodeContext {
                raw_preserving: true,
                ..EncodeContext::default()
            },
        );
    }
});
