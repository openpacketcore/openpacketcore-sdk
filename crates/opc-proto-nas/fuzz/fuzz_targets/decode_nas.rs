#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_proto_nas::{MobileIdentity, NasMessage};
use opc_protocol::{BorrowDecode, DecodeContext, OwnedDecode, ValidationLevel};

fuzz_target!(|data: &[u8]| {
    // Borrowed decode at the default (Structural) level.
    let _ = NasMessage::decode(data, DecodeContext::default());

    // Strict decode (spare-nibble enforcement).
    let mut ctx_strict = DecodeContext::default();
    ctx_strict.validation_level = ValidationLevel::Strict;
    let _ = NasMessage::decode(data, ctx_strict);

    // Owned decode path.
    let _ = NasMessage::decode_owned(
        bytes::Bytes::copy_from_slice(data),
        DecodeContext::default(),
    );

    // Mobile identity decoding on arbitrary content bytes.
    let _ = MobileIdentity::decode(data);
});
