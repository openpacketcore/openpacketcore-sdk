#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_proto_pfcp::{ie::TypedIe, Message, OwnedMessage};
use opc_protocol::{BorrowDecode, DecodeContext, OwnedDecode, ValidationLevel};

fuzz_target!(|data: &[u8]| {
    // Borrowed decode at the default (Structural) level.
    let ctx = DecodeContext::default();
    let _ = Message::decode(data, ctx);

    // Strict decode (spare bits / FO flag enforcement).
    let mut ctx_strict = DecodeContext::default();
    ctx_strict.validation_level = ValidationLevel::Strict;
    let _ = Message::decode(data, ctx_strict);

    // Owned decode path.
    let _ = OwnedMessage::decode_owned(
        bytes::Bytes::copy_from_slice(data),
        DecodeContext::default(),
    );

    // Typed IE decode path (depth-limited).
    let mut offset = 0usize;
    while offset < data.len() {
        match TypedIe::decode(&data[offset..], DecodeContext::default(), 0) {
            Ok((remaining, _ie)) => {
                offset = data.len() - remaining.len();
            }
            Err(_e) => break,
        }
    }

    // Typed IE decode with aggressive depth limit.
    let mut ctx_shallow = DecodeContext::default();
    ctx_shallow.max_depth = 2;
    let _ = TypedIe::decode(data, ctx_shallow, 0);
});
