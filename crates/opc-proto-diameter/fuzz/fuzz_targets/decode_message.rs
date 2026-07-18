#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_proto_diameter::apps::{APP_DICTIONARIES, SWM_PROJECTED_PROFILE_DICTIONARIES};
use opc_proto_diameter::error_answer::{inspect_diameter_request, DiameterRequestInspection};
use opc_proto_diameter::{Message, OwnedMessage};
use opc_protocol::{BorrowDecode, DecodeContext, OwnedDecode, ValidationLevel};

fuzz_target!(|data: &[u8]| {
    // Bounded request inspection and error-context capture.
    if let DiameterRequestInspection::Request(envelope) =
        inspect_diameter_request(data, DecodeContext::conservative())
    {
        let _ = envelope.classify(data, APP_DICTIONARIES);
    }
    let _ = inspect_diameter_request(
        data,
        DecodeContext {
            max_depth: 0,
            ..DecodeContext::conservative()
        },
    );
    let _ = inspect_diameter_request(
        data,
        DecodeContext {
            max_ies: 1,
            ..DecodeContext::conservative()
        },
    );

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

    // Application-aware command resolution and cardinality validation.
    let _ = Message::decode_with_dictionary(
        data,
        DecodeContext::conservative(),
        APP_DICTIONARIES,
    );
    let _ = OwnedMessage::decode_owned_with_dictionary(
        bytes::Bytes::copy_from_slice(data),
        DecodeContext::conservative(),
        APP_DICTIONARIES,
    );
    let _ = Message::decode_with_dictionary(
        data,
        DecodeContext::conservative(),
        SWM_PROJECTED_PROFILE_DICTIONARIES,
    );
    let _ = OwnedMessage::decode_owned_with_dictionary(
        bytes::Bytes::copy_from_slice(data),
        DecodeContext::conservative(),
        SWM_PROJECTED_PROFILE_DICTIONARIES,
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
