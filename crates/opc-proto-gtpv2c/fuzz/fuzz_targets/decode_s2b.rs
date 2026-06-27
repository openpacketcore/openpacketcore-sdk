#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_proto_gtpv2c::{decode_typed_ie_sequence, S2bMessage};
use opc_protocol::{DecodeContext, ValidationLevel};

fuzz_target!(|data: &[u8]| {
    let _ = S2bMessage::decode(data, DecodeContext::default());

    let procedure = DecodeContext {
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    };
    let _ = S2bMessage::decode(data, procedure);

    let shallow = DecodeContext {
        max_depth: 2,
        max_ies: 4,
        ..DecodeContext::default()
    };
    let _ = decode_typed_ie_sequence(data, shallow, 0);
});
