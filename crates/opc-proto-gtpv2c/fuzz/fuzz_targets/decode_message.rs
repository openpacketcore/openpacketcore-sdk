#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use opc_proto_gtpv2c::{validate_ie_region, Message, OwnedMessage};
use opc_protocol::{BorrowDecode, DecodeContext, OwnedDecode, ValidationLevel};

fuzz_target!(|data: &[u8]| {
    let _ = Message::decode(data, DecodeContext::default());

    let mut strict = DecodeContext::default();
    strict.validation_level = ValidationLevel::Strict;
    let _ = Message::decode(data, strict);

    let _ = OwnedMessage::decode_owned(Bytes::copy_from_slice(data), DecodeContext::default());

    let mut shallow = DecodeContext::default();
    shallow.max_ies = 4;
    let _ = validate_ie_region(data, shallow);
});
