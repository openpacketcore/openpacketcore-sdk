#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use opc_proto_ngap::Pdu;
use opc_protocol::{DecodeContext, OwnedDecode};

fuzz_target!(|data: &[u8]| {
    let _ = Pdu::decode_owned(Bytes::copy_from_slice(data), DecodeContext::default());
});
