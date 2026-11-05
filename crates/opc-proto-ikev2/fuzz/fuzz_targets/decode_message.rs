#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use opc_proto_ikev2::{
    build_ikev2_n1_mode_notify, build_ikev2_redirect_notify, decode_ikev2_n1_mode_notify,
    decode_ikev2_redirect_notify, decode_ikev2_redirect_notify_with_profile,
    decode_ikev2_redirect_support, decode_ikev2_signature_hash_algorithms_notify,
    Ikev2N1ModeNotifications, Ikev2NotifyPayload, Ikev2RedirectContext, Ikev2ValidationProfile,
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
        let _ = decode_ikev2_redirect_support(&[notify]);
        for context in [
            Ikev2RedirectContext::SaInitRequest,
            Ikev2RedirectContext::SaInitResponse,
            Ikev2RedirectContext::IkeAuthResponse,
            Ikev2RedirectContext::InformationalRequest,
        ] {
            for profile in [
                Ikev2ValidationProfile::NetworkReceive,
                Ikev2ValidationProfile::SenderCanonical,
            ] {
                let received = decode_ikev2_redirect_notify_with_profile(notify, context, profile);
                if profile == Ikev2ValidationProfile::NetworkReceive {
                    assert_eq!(received, decode_ikev2_redirect_notify(notify, context));
                }
                if let Ok(Some(value)) = received {
                    let wire = build_ikev2_redirect_notify(value, context).unwrap();
                    let canonical = Ikev2NotifyPayload::decode_body(&wire).unwrap();
                    assert_eq!(
                        decode_ikev2_redirect_notify_with_profile(canonical, context, profile),
                        Ok(Some(value))
                    );
                    if context == Ikev2RedirectContext::SaInitRequest {
                        assert!(decode_ikev2_redirect_support(&[notify, notify]).is_err());
                    }
                }
            }
        }

        if let Ok(Some(value)) = decode_ikev2_n1_mode_notify(notify) {
            let wire = build_ikev2_n1_mode_notify(value).unwrap();
            let generic = Ikev2NotifyPayload::decode_body(&wire).unwrap();
            assert_eq!(decode_ikev2_n1_mode_notify(generic), Ok(Some(value)));
            assert!(Ikev2N1ModeNotifications::decode(&[notify, notify]).is_err());
        }
    }
});
