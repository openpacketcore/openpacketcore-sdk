#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use opc_proto_ikev2::{Message, OwnedMessage, PayloadChain, PayloadType};
use opc_protocol::{BorrowDecode, DecodeContext, OwnedDecode};

fuzz_target!(|data: &[u8]| {
    let _ = Message::decode(data, DecodeContext::default());
    let _ = OwnedMessage::decode_owned(Bytes::copy_from_slice(data), DecodeContext::default());
    for item in PayloadChain::new(PayloadType::Nonce, data).iter() {
        if item.is_err() {
            break;
        }
    }
});
