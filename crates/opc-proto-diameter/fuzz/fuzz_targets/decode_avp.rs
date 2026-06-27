#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_proto_diameter::apps::APP_DICTIONARIES;
use opc_proto_diameter::{validate_avp_region_with_dictionary, RawAvp};
use opc_protocol::{BorrowDecode, DecodeContext, ValidationLevel};

fuzz_target!(|data: &[u8]| {
    // Raw AVP region validation at the default level.
    let ctx = DecodeContext::default();
    let _ = validate_avp_region_with_dictionary(data, ctx, APP_DICTIONARIES);

    // Strict validation (reserved bits, zero padding).
    let mut ctx_strict = DecodeContext::default();
    ctx_strict.validation_level = ValidationLevel::Strict;
    let _ = validate_avp_region_with_dictionary(data, ctx_strict, APP_DICTIONARIES);

    // Iterate raw AVPs one-by-one to exercise the iterator error path.
    let mut remaining = data;
    while !remaining.is_empty() {
        match RawAvp::decode(remaining, DecodeContext::default()) {
            Ok((next, avp)) => {
                // Grouped-value validation path for each successfully decoded AVP.
                let _ = avp.validate_grouped_value_with_dictionary(
                    DecodeContext::default(),
                    APP_DICTIONARIES,
                );
                let consumed = remaining.len() - next.len();
                if consumed == 0 {
                    break;
                }
                remaining = next;
            }
            Err(_) => break,
        }
    }
});
