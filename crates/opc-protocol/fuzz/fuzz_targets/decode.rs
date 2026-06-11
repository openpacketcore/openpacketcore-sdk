#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_protocol::DecodeContext;

// Fuzz target template for full decode.
//
// Protocol crates copy this template and plug their own `BorrowDecode`
// implementation into the `fuzz_target!` body. This exercises:
// - full structural decode,
// - header-only decode (when `ValidationLevel::HeaderOnly` is used),
// - length and bounds checks,
// - rejection stability (no panic, no unbounded allocation).
fuzz_target!(|data: &[u8]| {
    let _ctx = DecodeContext::default();
    let _ = data.len();
    // Template: replace with actual protocol decode call.
    // let _ = MyPdu::decode(data, ctx);
});
