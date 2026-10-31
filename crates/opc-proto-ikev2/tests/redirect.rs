//! Independent RFC 5685 section 9 Notify body vectors and malformed inputs.

use std::net::{Ipv4Addr, Ipv6Addr};

use opc_proto_ikev2::redirect::{
    build_ikev2_redirect_notify, decode_ikev2_redirect_notify,
    decode_ikev2_redirect_notify_with_profile, decode_ikev2_redirect_support,
    Ikev2RedirectContext as Context, Ikev2RedirectGatewayIdentity as Gateway,
    Ikev2RedirectNotify as Redirect, Ikev2RedirectNotifyError as Error, IKEV2_NOTIFY_REDIRECT,
    IKEV2_NOTIFY_REDIRECTED_FROM, IKEV2_NOTIFY_REDIRECT_SUPPORTED, IKEV2_REDIRECT_MAX_NOTIFIES,
};
use opc_proto_ikev2::{
    build_ike_auth_cleartext_payload_chain, decode_ike_auth_cleartext_payloads,
    Ikev2IkeAuthPayloadBuild, Ikev2NotifyPayload, Ikev2ValidationProfile, PayloadType,
};

// Includes the generic Notify body, but not its generic payload header.
const SUPPORTED: &[u8] = &[0, 0, 0x40, 0x16];
const IPV4: &[u8] = &[0, 0, 0x40, 0x17, 1, 4, 192, 0, 2, 1];
const IPV6: &[u8] = &[
    0, 0, 0x40, 0x17, 2, 16, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];
const FQDN: &[u8] = b"\0\0\x40\x17\x03\x0bvpn.example";
const FROM: &[u8] = &[0, 0, 0x40, 0x18, 1, 4, 192, 0, 2, 9];

fn generic(body: &[u8]) -> Ikev2NotifyPayload<'_> {
    Ikev2NotifyPayload::decode_body(body).unwrap()
}

fn redirect(gateway: Gateway<'_>) -> Redirect<'_> {
    Redirect::Redirect {
        gateway,
        nonce: None,
    }
}

#[test]
fn constants_and_three_identity_types_match_literal_notify_bodies() {
    assert_eq!(IKEV2_NOTIFY_REDIRECT_SUPPORTED, 16406);
    assert_eq!(IKEV2_NOTIFY_REDIRECT, 16407);
    assert_eq!(IKEV2_NOTIFY_REDIRECTED_FROM, 16408);
    for (gateway, wire) in [
        (Gateway::Ipv4(Ipv4Addr::new(192, 0, 2, 1)), IPV4),
        (
            Gateway::Ipv6("2001:db8::1".parse::<Ipv6Addr>().unwrap()),
            IPV6,
        ),
        (Gateway::Fqdn("vpn.example"), FQDN),
    ] {
        for context in [Context::IkeAuthResponse, Context::InformationalRequest] {
            let typed = redirect(gateway);
            assert_eq!(build_ikev2_redirect_notify(typed, context).unwrap(), wire);
            assert_eq!(
                decode_ikev2_redirect_notify(generic(wire), context),
                Ok(Some(typed))
            );
            let build = typed.to_notify_build(context).unwrap();
            assert_eq!(build.protocol_id, 0);
            assert!(build.spi.is_empty());
            assert_eq!(build.notification_data, wire[4..]);
        }
    }
}

#[test]
fn support_and_redirected_from_match_literal_bodies_and_imply_support() {
    let from = Redirect::RedirectedFrom(Gateway::Ipv4(Ipv4Addr::new(192, 0, 2, 9)));
    for (typed, wire) in [(Redirect::Supported, SUPPORTED), (from, FROM)] {
        assert_eq!(
            build_ikev2_redirect_notify(typed, Context::SaInitRequest).unwrap(),
            wire
        );
        assert_eq!(
            decode_ikev2_redirect_notify(generic(wire), Context::SaInitRequest),
            Ok(Some(typed))
        );
        assert_eq!(decode_ikev2_redirect_support(&[generic(wire)]), Ok(true));
    }
    assert_eq!(
        decode_ikev2_redirect_support(&[generic(SUPPORTED), generic(FROM)]),
        Ok(true)
    );
    assert_eq!(decode_ikev2_redirect_support(&[]), Ok(false));
    let mut from_v6 = IPV6.to_vec();
    from_v6[3] = 0x18;
    let typed = Redirect::RedirectedFrom(Gateway::Ipv6("2001:db8::1".parse().unwrap()));
    assert_eq!(
        build_ikev2_redirect_notify(typed, Context::SaInitRequest).unwrap(),
        from_v6
    );
    assert_eq!(
        decode_ikev2_redirect_notify(generic(&from_v6), Context::SaInitRequest),
        Ok(Some(typed))
    );
}

#[test]
fn sa_init_echoes_peer_nonce_at_both_rfc_bounds() {
    for size in [16, 32, 256] {
        let nonce = vec![0xa5; size];
        for base in [IPV4, IPV6, FQDN] {
            let mut wire = base.to_vec();
            wire.extend_from_slice(&nonce);
            let typed = decode_ikev2_redirect_notify(generic(&wire), Context::SaInitResponse)
                .unwrap()
                .unwrap();
            let Redirect::Redirect {
                nonce: received, ..
            } = typed
            else {
                panic!("redirect expected")
            };
            assert_eq!(received, Some(nonce.as_slice()));
            assert_eq!(
                build_ikev2_redirect_notify(typed, Context::SaInitResponse).unwrap(),
                wire
            );
        }
    }
}

#[test]
fn nonce_is_required_only_in_sa_init_responses() {
    assert_eq!(
        decode_ikev2_redirect_notify(generic(IPV4), Context::SaInitResponse),
        Err(Error::NonceRequired)
    );
    let gateway = Gateway::Ipv4(Ipv4Addr::new(192, 0, 2, 1));
    assert_eq!(
        build_ikev2_redirect_notify(redirect(gateway), Context::SaInitResponse),
        Err(Error::NonceRequired)
    );
    for size in [0, 1, 15, 257] {
        let nonce = vec![0x77; size];
        let typed = Redirect::Redirect {
            gateway,
            nonce: Some(&nonce),
        };
        assert_eq!(
            build_ikev2_redirect_notify(typed, Context::SaInitResponse),
            Err(Error::NonceLengthInvalid)
        );
        if size != 0 {
            let mut wire = IPV4.to_vec();
            wire.extend_from_slice(&nonce);
            assert_eq!(
                decode_ikev2_redirect_notify(generic(&wire), Context::SaInitResponse),
                Err(Error::NonceLengthInvalid)
            );
        }
        for context in [Context::IkeAuthResponse, Context::InformationalRequest] {
            assert_eq!(
                build_ikev2_redirect_notify(typed, context),
                Err(Error::NonceProhibited)
            );
        }
    }
    let mut extra = IPV4.to_vec();
    extra.push(0);
    for context in [Context::IkeAuthResponse, Context::InformationalRequest] {
        assert_eq!(
            decode_ikev2_redirect_notify(generic(&extra), context),
            Err(Error::NonceProhibited)
        );
    }
}

#[test]
fn recognized_notifies_require_their_exchange_direction() {
    for context in [
        Context::SaInitResponse,
        Context::IkeAuthResponse,
        Context::InformationalRequest,
    ] {
        for wire in [SUPPORTED, FROM] {
            assert_eq!(
                decode_ikev2_redirect_notify(generic(wire), context),
                Err(Error::WrongContext)
            );
        }
        assert_eq!(
            build_ikev2_redirect_notify(Redirect::Supported, context),
            Err(Error::WrongContext)
        );
    }
    assert_eq!(
        decode_ikev2_redirect_notify(generic(IPV4), Context::SaInitRequest),
        Err(Error::WrongContext)
    );
    assert_eq!(
        build_ikev2_redirect_notify(
            redirect(Gateway::Ipv4(Ipv4Addr::LOCALHOST)),
            Context::SaInitRequest
        ),
        Err(Error::WrongContext)
    );
}

#[test]
fn malformed_gateway_headers_lengths_and_types_are_named() {
    let cases: Vec<(Vec<u8>, Error)> = vec![
        (vec![], Error::GatewayHeaderTruncated),
        (vec![1], Error::GatewayHeaderTruncated),
        (
            vec![0, 4, 192, 0, 2, 1],
            Error::GatewayIdentityTypeUnsupported,
        ),
        (
            vec![4, 4, 192, 0, 2, 1],
            Error::GatewayIdentityTypeUnsupported,
        ),
        (vec![1, 0], Error::GatewayIdentityEmpty),
        (vec![1, 4, 192, 0, 2], Error::GatewayIdentityTruncated),
        (vec![1, 3, 192, 0, 2], Error::Ipv4LengthInvalid),
        (vec![1, 5, 192, 0, 2, 1, 0], Error::Ipv4LengthInvalid),
        (
            vec![2, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            Error::Ipv6LengthInvalid,
        ),
    ];
    for (data, expected) in cases {
        let view = Ikev2NotifyPayload {
            notification_data: &data,
            ..generic(IPV4)
        };
        assert_eq!(
            decode_ikev2_redirect_notify(view, Context::IkeAuthResponse),
            Err(expected)
        );
    }
}

#[test]
fn fqdn_encoding_rejects_non_ascii_terminators_empty_labels_and_oversize() {
    for (name, expected) in [
        ("", Error::GatewayIdentityEmpty),
        ("v\u{00fc}pn.example", Error::FqdnNonAscii),
        ("vpn.example\0", Error::FqdnInvalidCharacter),
        ("vpn.example\r", Error::FqdnInvalidCharacter),
        ("vpn.example\n", Error::FqdnInvalidCharacter),
        ("vpn example", Error::FqdnInvalidCharacter),
        ("a..example", Error::FqdnEmptyLabel),
        (".", Error::FqdnEmptyLabel),
    ] {
        assert_eq!(
            build_ikev2_redirect_notify(redirect(Gateway::Fqdn(name)), Context::IkeAuthResponse),
            Err(expected)
        );
        let mut body = vec![0, 0, 0x40, 0x17, 3, u8::try_from(name.len()).unwrap()];
        body.extend_from_slice(name.as_bytes());
        assert_eq!(
            decode_ikev2_redirect_notify(generic(&body), Context::IkeAuthResponse),
            Err(expected)
        );
    }
    let long_label = "a".repeat(64);
    assert_eq!(
        build_ikev2_redirect_notify(
            redirect(Gateway::Fqdn(&long_label)),
            Context::IkeAuthResponse
        ),
        Err(Error::FqdnLabelTooLong)
    );
    let too_long = "a".repeat(256);
    assert_eq!(
        build_ikev2_redirect_notify(redirect(Gateway::Fqdn(&too_long)), Context::IkeAuthResponse),
        Err(Error::GatewayIdentityTooLong)
    );
    let wire_long_name = vec!["a".repeat(63); 4].join(".");
    assert_eq!(
        build_ikev2_redirect_notify(
            redirect(Gateway::Fqdn(&wire_long_name)),
            Context::IkeAuthResponse
        ),
        Err(Error::FqdnNameTooLong)
    );
}

#[test]
fn fqdn_text_is_preserved_with_maximum_labels_and_optional_root_dot() {
    let maximum = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61),
    ]
    .join(".");
    for name in [
        "VPN.Example",
        "xn--tmonesimerkki-bfbb.example.net",
        maximum.as_str(),
        &(maximum.clone() + "."),
    ] {
        let typed = redirect(Gateway::Fqdn(name));
        let wire = build_ikev2_redirect_notify(typed, Context::IkeAuthResponse).unwrap();
        assert_eq!(&wire[6..], name.as_bytes());
        assert_eq!(
            decode_ikev2_redirect_notify(generic(&wire), Context::IkeAuthResponse),
            Ok(Some(typed))
        );
    }
}

#[test]
fn redirected_from_prohibits_fqdn_and_trailing_data() {
    let mut fqdn = FQDN.to_vec();
    fqdn[3] = 0x18;
    assert_eq!(
        decode_ikev2_redirect_notify(generic(&fqdn), Context::SaInitRequest),
        Err(Error::RedirectedFromRequiresIp)
    );
    assert_eq!(
        build_ikev2_redirect_notify(
            Redirect::RedirectedFrom(Gateway::Fqdn("vpn.example")),
            Context::SaInitRequest
        ),
        Err(Error::RedirectedFromRequiresIp)
    );
    let mut trailing = FROM.to_vec();
    trailing.push(0x55);
    assert_eq!(
        decode_ikev2_redirect_notify(generic(&trailing), Context::SaInitRequest),
        Err(Error::UnexpectedTrailingData)
    );
    assert_eq!(
        decode_ikev2_redirect_notify(generic(&[0, 0, 0x40, 0x16, 0]), Context::SaInitRequest),
        Err(Error::SupportedDataNonempty)
    );
}

#[test]
fn spi_views_are_strict_but_network_receivers_ignore_empty_spi_protocol_id() {
    for (wire, context) in [
        (SUPPORTED, Context::SaInitRequest),
        (FROM, Context::SaInitRequest),
        (IPV4, Context::IkeAuthResponse),
    ] {
        let normal = decode_ikev2_redirect_notify(generic(wire), context);
        for protocol_id in 0..=255 {
            let view = Ikev2NotifyPayload {
                protocol_id,
                ..generic(wire)
            };
            assert_eq!(decode_ikev2_redirect_notify(view, context), normal);
            let canonical = decode_ikev2_redirect_notify_with_profile(
                view,
                context,
                Ikev2ValidationProfile::SenderCanonical,
            );
            assert_eq!(
                canonical,
                if protocol_id == 0 {
                    normal
                } else {
                    Err(Error::ProtocolIdNonzero)
                }
            );
        }
        assert_eq!(
            decode_ikev2_redirect_notify(
                Ikev2NotifyPayload {
                    spi_size: 1,
                    ..generic(wire)
                },
                context
            ),
            Err(Error::SpiSizeNonzero)
        );
        assert_eq!(
            decode_ikev2_redirect_notify(
                Ikev2NotifyPayload {
                    spi: &[0x55],
                    ..generic(wire)
                },
                context
            ),
            Err(Error::SpiNonempty)
        );
    }
}

#[test]
fn support_collection_is_bounded_atomic_and_rejects_duplicate_recognized_types() {
    assert_eq!(
        decode_ikev2_redirect_support(&[generic(SUPPORTED), generic(SUPPORTED)]),
        Err(Error::DuplicateSupported)
    );
    assert_eq!(
        decode_ikev2_redirect_support(&[generic(FROM), generic(FROM)]),
        Err(Error::DuplicateRedirectedFrom)
    );
    assert_eq!(
        decode_ikev2_redirect_support(&[generic(SUPPORTED), generic(&[0, 0, 0x40, 0x18])]),
        Err(Error::GatewayHeaderTruncated)
    );
    let unrelated = Ikev2NotifyPayload {
        protocol_id: 255,
        spi_size: 7,
        notify_message_type: 16384,
        spi: &[],
        notification_data: &[],
    };
    assert_eq!(
        decode_ikev2_redirect_notify(unrelated, Context::SaInitRequest),
        Ok(None)
    );
    assert_eq!(
        decode_ikev2_redirect_support(&vec![unrelated; IKEV2_REDIRECT_MAX_NOTIFIES]),
        Ok(false)
    );
    assert_eq!(
        decode_ikev2_redirect_support(&vec![unrelated; IKEV2_REDIRECT_MAX_NOTIFIES + 1]),
        Err(Error::TooManyNotifies)
    );
}

#[test]
fn generic_ike_auth_chain_has_exact_rfc_notify_payload_framing() {
    let typed = redirect(Gateway::Ipv4(Ipv4Addr::new(192, 0, 2, 1)));
    let body = build_ikev2_redirect_notify(typed, Context::IkeAuthResponse).unwrap();
    let (first, chain) = build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
        payload_type: PayloadType::Notify,
        body,
    }])
    .unwrap();
    assert_eq!(first, PayloadType::Notify);
    assert_eq!(
        chain.as_ref(),
        [0, 0, 0, 14, 0, 0, 0x40, 0x17, 1, 4, 192, 0, 2, 1]
    );
    let decoded = decode_ike_auth_cleartext_payloads(first, &chain).unwrap();
    assert_eq!(decoded.notifies.len(), 1);
    assert_eq!(
        decode_ikev2_redirect_notify(decoded.notifies[0], Context::IkeAuthResponse),
        Ok(Some(typed))
    );
}

#[test]
fn every_fixed_body_prefix_is_rejected_without_panicking() {
    for wire in [IPV4, IPV6, FQDN] {
        for end in 0..wire.len() {
            if let Ok(view) = Ikev2NotifyPayload::decode_body(&wire[..end]) {
                assert!(decode_ikev2_redirect_notify(view, Context::IkeAuthResponse).is_err());
            }
        }
    }
}

#[test]
fn debug_and_errors_do_not_reveal_gateways_or_nonces() {
    for gateway in [
        Gateway::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
        Gateway::Ipv6("2001:db8::1".parse().unwrap()),
        Gateway::Fqdn("vpn.example"),
    ] {
        let typed = Redirect::Redirect {
            gateway,
            nonce: Some(&[0xab; 16]),
        };
        let debug = format!("{typed:?} {gateway:?}");
        for forbidden in ["192.0.2.1", "2001:db8", "vpn.example", "171", "abab"] {
            assert!(!debug.contains(forbidden));
        }
    }
    for error in [
        Error::GatewayIdentityTruncated,
        Error::NonceProhibited,
        Error::FqdnInvalidCharacter,
    ] {
        assert!(!error.as_str().is_empty());
        assert!(!format!("{error:?}: {error}").contains("vpn.example"));
    }
}

#[test]
fn every_ip_identity_length_has_only_its_exact_width_accepted() {
    for (kind, width, invalid) in [
        (1, 4, Error::Ipv4LengthInvalid),
        (2, 16, Error::Ipv6LengthInvalid),
    ] {
        for length in 0..=255_u8 {
            let mut body = vec![0, 0, 0x40, 0x17, kind, length];
            body.extend(vec![0x55; usize::from(length)]);
            let result = decode_ikev2_redirect_notify(generic(&body), Context::IkeAuthResponse);
            if length == width {
                assert!(matches!(
                    result,
                    Ok(Some(Redirect::Redirect { nonce: None, .. }))
                ));
            } else {
                assert_eq!(
                    result,
                    Err(if length == 0 {
                        Error::GatewayIdentityEmpty
                    } else {
                        invalid
                    })
                );
            }
        }
    }
}

#[test]
fn fqdn_wire_decoder_rejects_invalid_utf8_and_dns_length_overflows() {
    let long_labels = vec!["a".repeat(63); 4].join(".");
    for (identity, expected) in [
        (vec![0xff], Error::FqdnNonAscii),
        (vec![b'a'; 64], Error::FqdnLabelTooLong),
        (long_labels.into_bytes(), Error::FqdnNameTooLong),
    ] {
        let mut body = vec![0, 0, 0x40, 0x17, 3, u8::try_from(identity.len()).unwrap()];
        body.extend_from_slice(&identity);
        assert_eq!(
            decode_ikev2_redirect_notify(generic(&body), Context::IkeAuthResponse),
            Err(expected)
        );
    }
}

#[test]
fn malformed_or_misplaced_recognized_notify_never_becomes_support() {
    for malformed in [IPV4, &[0, 0, 0x40, 0x16, 0]] {
        assert!(decode_ikev2_redirect_support(&[generic(SUPPORTED), generic(malformed)]).is_err());
        assert!(decode_ikev2_redirect_support(&[generic(malformed), generic(SUPPORTED)]).is_err());
    }
    let mut full = vec![generic(&[0, 0, 0x40, 0x00]); IKEV2_REDIRECT_MAX_NOTIFIES];
    full[IKEV2_REDIRECT_MAX_NOTIFIES - 1] = generic(FROM);
    assert_eq!(decode_ikev2_redirect_support(&full), Ok(true));
}
