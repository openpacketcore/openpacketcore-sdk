#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use opc_proto_ikev2::{
    build_ikev2_n1_mode_notify, decode_ikev2_n1_mode_notify,
    decode_ikev2_signature_hash_algorithms_notify, Ikev2N1ModeNotifications, Ikev2NotifyPayload,
    Message, OwnedMessage, PayloadChain, PayloadType,
};
use opc_protocol::{BorrowDecode, DecodeContext, OwnedDecode};

fuzz_target!(|data: &[u8]| {
    let _ = Message::decode(data, DecodeContext::default());
    let _ = OwnedMessage::decode_owned(Bytes::copy_from_slice(data), DecodeContext::default());
    for item in PayloadChain::new(PayloadType::Nonce, data).iter() {
        if item.is_err() {
            break;
        }
    }
    if let Ok(notify) = Ikev2NotifyPayload::decode_body(data) {
        let _ = decode_ikev2_signature_hash_algorithms_notify(notify);
        if let Ok(Some(value)) = decode_ikev2_n1_mode_notify(notify) {
            let wire = build_ikev2_n1_mode_notify(value).unwrap();
            let generic = Ikev2NotifyPayload::decode_body(&wire).unwrap();
            assert_eq!(decode_ikev2_n1_mode_notify(generic), Ok(Some(value)));
            assert!(Ikev2N1ModeNotifications::decode(&[notify, notify]).is_err());
        }
    }
});
