#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_proto_diameter::apps::APP_DICTIONARIES;
use opc_proto_diameter::{Message, OwnedMessage};
use opc_protocol::{BorrowDecode, DecodeContext, OwnedDecode, ValidationLevel};

fuzz_target!(|data: &[u8]| {
    // Borrowed decode at the default (Structural) level.
    let ctx = DecodeContext::default();
    let _ = Message::decode(data, ctx);

    // Strict decode (reserved flag-bit / zero-padding enforcement).
    let ctx_strict = DecodeContext {
        validation_level: ValidationLevel::Strict,
        ..Default::default()
    };
    let _ = Message::decode(data, ctx_strict);

    // Header-only decode (exercises framing without AVP validation).
    let ctx_header = DecodeContext {
        validation_level: ValidationLevel::HeaderOnly,
        ..Default::default()
    };
    let _ = Message::decode(data, ctx_header);

    // Owned decode path.
    let _ = OwnedMessage::decode_owned(
        bytes::Bytes::copy_from_slice(data),
        DecodeContext::default(),
    );

    // Dictionary-aware validation (grouped AVP recursion, depth-limited).
    if let Ok((_, message)) = Message::decode(data, DecodeContext::default()) {
        let _ = message.validate_avps_with_dictionary(
            DecodeContext::default(),
            APP_DICTIONARIES,
        );
        let ctx_shallow = DecodeContext {
            max_depth: 2,
            ..Default::default()
        };
        let _ = message.validate_avps_with_dictionary(ctx_shallow, APP_DICTIONARIES);
    }
});
