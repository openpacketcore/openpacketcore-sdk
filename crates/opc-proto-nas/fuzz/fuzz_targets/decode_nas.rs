#![no_main]

use libfuzzer_sys::fuzz_target;
use opc_proto_nas::{
    decode_mm_message_body, decode_sm_message_body, MobileIdentity, NasMessage,
    RegistrationAccept, RegistrationRequest, SecurityModeCommand, SecurityModeComplete,
};
use opc_protocol::{BorrowDecode, DecodeContext, OwnedDecode, ValidationLevel};

fuzz_target!(|data: &[u8]| {
    // Borrowed decode at the default (Structural) level.
    let _ = NasMessage::decode(data, DecodeContext::default());

    // Strict decode (spare-nibble enforcement).
    let mut ctx_strict = DecodeContext::default();
    ctx_strict.validation_level = ValidationLevel::Strict;
    let _ = NasMessage::decode(data, ctx_strict);

    // Owned decode path.
    let _ = NasMessage::decode_owned(
        bytes::Bytes::copy_from_slice(data),
        DecodeContext::default(),
    );

    // Mobile identity decoding on arbitrary content bytes.
    let _ = MobileIdentity::decode(data);

    // v2 message body parsing.
    let _ = RegistrationRequest::decode_body(data, DecodeContext::default());
    let _ = RegistrationAccept::decode_body(data, DecodeContext::default());
    let _ = SecurityModeCommand::decode_body(data, DecodeContext::default());
    let _ = SecurityModeComplete::decode_body(data, DecodeContext::default());
    if let Some((&message_type, body)) = data.split_first() {
        let _ = decode_mm_message_body(message_type, body, DecodeContext::default());
        let _ = decode_sm_message_body(message_type, body, DecodeContext::default());
    }

    // BCD helpers on fixed-size prefixes.
    if data.len() >= 3 {
        let _ = opc_proto_nas::unpack_plmn([data[0], data[1], data[2]]);
    }
    if data.len() >= 2 {
        let _ = opc_proto_nas::unpack_routing_indicator([data[0], data[1]]);
    }
    let _ = opc_proto_nas::unpack_imei(data);
});
