#![no_main]

use bytes::BytesMut;
use libfuzzer_sys::fuzz_target;
use opc_proto_tft::TrafficFlowTemplate;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = TrafficFlowTemplate::decode_value(data) {
        let mut encoded = BytesMut::new();
        if value.encode_value(&mut encoded).is_ok() {
            assert_eq!(encoded.as_ref(), data);
            assert_eq!(TrafficFlowTemplate::decode_value(&encoded), Ok(value));
        }
    }
});
