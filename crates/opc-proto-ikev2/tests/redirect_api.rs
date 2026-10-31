//! Public IP-only original-gateway and support-metadata contracts.

use std::net::{IpAddr, Ipv4Addr};

use opc_proto_ikev2::{
    build_ikev2_redirect_notify, decode_ikev2_redirect_support, Ikev2NotifyPayload,
    Ikev2RedirectContext, Ikev2RedirectGatewayIdentity, Ikev2RedirectNotify,
    Ikev2RedirectNotifyError,
};

#[test]
fn original_gateway_is_an_ip_value_and_collection_retains_it() {
    let original: IpAddr = Ipv4Addr::new(192, 0, 2, 9).into();
    let typed = Ikev2RedirectNotify::RedirectedFrom(original);
    let body = build_ikev2_redirect_notify(typed, Ikev2RedirectContext::SaInitRequest).unwrap();
    let summary =
        decode_ikev2_redirect_support(&[Ikev2NotifyPayload::decode_body(&body).unwrap()]).unwrap();
    assert!(summary.is_supported());
    assert_eq!(summary.redirected_from(), Some(original));
    assert!(!summary.supported_notify_present());
    let empty = decode_ikev2_redirect_support(&[]).unwrap();
    assert!(!empty.is_supported());
    assert_eq!(empty.redirected_from(), None);
    assert!(!format!("{summary:?}").contains("192.0.2.9"));
}

#[test]
fn checked_original_gateway_draft_rejects_every_fqdn_before_text_validation() {
    for name in ["", "vpn.example", "a..b", "\u{00fc}"] {
        assert_eq!(
            Ikev2RedirectNotify::redirected_from(Ikev2RedirectGatewayIdentity::Fqdn(name)),
            Err(Ikev2RedirectNotifyError::RedirectedFromRequiresIp),
        );
    }
}
