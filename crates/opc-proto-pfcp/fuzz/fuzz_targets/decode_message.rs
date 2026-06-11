#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_proto_pfcp::{Message, OwnedMessage};
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
});
