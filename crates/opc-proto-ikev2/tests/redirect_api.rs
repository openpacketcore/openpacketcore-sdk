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

#[test]
fn collection_distinguishes_explicit_support_and_original_ip_in_both_orders() {
    let supported = build_ikev2_redirect_notify(
        Ikev2RedirectNotify::Supported,
        Ikev2RedirectContext::SaInitRequest,
    )
    .unwrap();
    let original: IpAddr = "2001:db8::9".parse().unwrap();
    let from = build_ikev2_redirect_notify(
        Ikev2RedirectNotify::RedirectedFrom(original),
        Ikev2RedirectContext::SaInitRequest,
    )
    .unwrap();
    let supported = Ikev2NotifyPayload::decode_body(&supported).unwrap();
    let from = Ikev2NotifyPayload::decode_body(&from).unwrap();
    let explicit = decode_ikev2_redirect_support(&[supported]).unwrap();
    assert!(explicit.is_supported());
    assert!(explicit.supported_notify_present());
    assert_eq!(explicit.redirected_from(), None);
    for notifies in [[supported, from], [from, supported]] {
        let summary = decode_ikev2_redirect_support(&notifies).unwrap();
        assert!(summary.is_supported());
        assert!(summary.supported_notify_present());
        assert_eq!(summary.redirected_from(), Some(original));
        assert!(!format!("{summary:?}").contains("2001:db8"));
    }
    for notifies in [[from, supported, from], [supported, from, supported]] {
        assert!(matches!(
            decode_ikev2_redirect_support(&notifies),
            Err(Ikev2RedirectNotifyError::DuplicateSupported
                | Ikev2RedirectNotifyError::DuplicateRedirectedFrom)
        ));
    }
}

#[test]
fn unassigned_and_private_gateway_types_and_del_text_are_rejected() {
    for kind in [0, 4, 240, 241, 254, 255] {
        let data = [kind, 1, b'a'];
        let notify = Ikev2NotifyPayload {
            protocol_id: 0,
            spi_size: 0,
            spi: &[],
            notify_message_type: 16407,
            notification_data: &data,
        };
        assert_eq!(
            opc_proto_ikev2::decode_ikev2_redirect_notify(
                notify,
                Ikev2RedirectContext::IkeAuthResponse
            ),
            Err(Ikev2RedirectNotifyError::GatewayIdentityTypeUnsupported)
        );
    }
    assert_eq!(
        build_ikev2_redirect_notify(
            Ikev2RedirectNotify::Redirect {
                gateway: Ikev2RedirectGatewayIdentity::Fqdn("a\u{7f}.example"),
                nonce: None
            },
            Ikev2RedirectContext::IkeAuthResponse
        ),
        Err(Ikev2RedirectNotifyError::FqdnInvalidCharacter)
    );
}
