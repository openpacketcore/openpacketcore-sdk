#![no_main]

mod support;

use libfuzzer_sys::fuzz_target;
use opc_proto_gtpu::{GtpuControlMessage, GtpuMessage};
use opc_protocol::{BorrowDecode, DecodeContext, ValidationLevel};

fuzz_target!(|data: &[u8]| {
    let decoded_seed = support::decode_hex_seed(data);
    let data = decoded_seed.as_deref().unwrap_or(data);

    // Fuzz standard default decode
    let ctx = DecodeContext::default();
    let _ = GtpuMessage::decode(data, ctx);

    // Fuzz with HeaderOnly decode
    let mut ctx_hdr = DecodeContext::default();
    ctx_hdr.validation_level = ValidationLevel::HeaderOnly;
    let _ = GtpuMessage::decode(data, ctx_hdr);

    // Fuzz with Strict decode
    let mut ctx_strict = DecodeContext::default();
    ctx_strict.validation_level = ValidationLevel::Strict;
    let _ = GtpuMessage::decode(data, ctx_strict);

    // Fuzz with ProcedureAware decode
    let mut ctx_proc = DecodeContext::default();
    ctx_proc.validation_level = ValidationLevel::ProcedureAware;
    let _ = GtpuMessage::decode(data, ctx_proc);

    // Exercise the typed path/tunnel-management boundary and all of its
    // bounded IE/cardinality/comprehension checks.
    let _ = GtpuControlMessage::decode(data, DecodeContext::default());
    let _ = GtpuControlMessage::decode_datagram(data, DecodeContext::default());
});
