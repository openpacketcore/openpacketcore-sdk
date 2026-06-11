#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_protocol::EncodeContext;

// Fuzz target template for round-trip properties.
//
// Protocol crates copy this template and test both canonical and
// raw-preserving modes:
//
// 1. Canonical: `decode(encode(model)) == model`
// 2. Raw-preserving: `encode_raw_preserving(decode_raw_preserving(input)) == input`
// 3. Reject stability: rejected inputs never panic, hang, or over-allocate.
fuzz_target!(|data: &[u8]| {
    let _canonical = EncodeContext::default();
    let _raw = EncodeContext {
        raw_preserving: true,
        ..EncodeContext::default()
    };
    let _ = data.len();
    // Template: replace with actual protocol round-trip call.
    // let model = generate_model(data);
    // let encoded = model.encode(&mut buf, canonical)?;
    // let decoded = MyPdu::decode(&buf, ctx)?;
    // assert_eq!(decoded, model);
});
