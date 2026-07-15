#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_proto_tft::TrafficFlowTemplate;
use opc_protocol::DecodeContext;

fuzz_target!(|data: &[u8]| {
    let _ = TrafficFlowTemplate::decode_value(data);

    let constrained = DecodeContext {
        max_message_len: 64,
        max_ies: 8,
        ..DecodeContext::conservative()
    };
    let _ = TrafficFlowTemplate::decode_value_with_context(data, constrained);
});
