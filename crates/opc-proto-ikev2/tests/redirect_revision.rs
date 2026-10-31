//! Redirect boundary and initial-exchange regressions.

use std::net::Ipv4Addr;

use bytes::Bytes;
use opc_proto_ikev2::{
    admit_ike_sa_init_response, build_ike_sa_init_notify_response, build_ike_sa_init_request,
    build_ikev2_redirect_notify, decode_ikev2_redirect_notify, Header, HeaderFlags, Ikev2DhGroup,
    Ikev2EphemeralDhKey, Ikev2NotifyPayload, Ikev2NotifyPayloadBuild,
    Ikev2RedirectContext as Context, Ikev2RedirectGatewayIdentity as Gateway,
    Ikev2RedirectNotify as Redirect, Ikev2RedirectNotifyError as Error,
    Ikev2SaInitInitiatorError as AdmissionError, Ikev2SaInitNotifyBuildError, Ikev2SaInitRequest,
    Ikev2SaInitResponse, Ikev2SaPayloadBuild, Ikev2SaProposalBuild, Ikev2SaTransformBuild,
    Ikev2TransformAttributeBuild, Ikev2TransformAttributeBuildValue, OwnedMessage, PayloadType,
    EXCHANGE_TYPE_IKE_SA_INIT,
};
use opc_protocol::DecodeContext;

mod support;

fn request(support: bool) -> Ikev2SaInitRequest {
    let notifies = if support {
        vec![Redirect::Supported
            .to_notify_build(Context::SaInitRequest)
            .unwrap()]
    } else {
        vec![]
    };
    request_with_notifies(&notifies)
}

fn request_with_notifies(notifies: &[Ikev2NotifyPayloadBuild]) -> Ikev2SaInitRequest {
    support::ensure_ike_crypto();
    let key = Ikev2EphemeralDhKey::generate(Ikev2DhGroup::Ecp256).unwrap();
    let offer = Ikev2SaPayloadBuild {
        proposals: vec![Ikev2SaProposalBuild {
            proposal_number: 1,
            protocol_id: 1,
            spi: vec![],
            transforms: vec![
                Ikev2SaTransformBuild {
                    transform_type: 1,
                    transform_id: 20,
                    attributes: vec![Ikev2TransformAttributeBuild {
                        attribute_type: 14,
                        value: Ikev2TransformAttributeBuildValue::Tv(128),
                    }],
                },
                Ikev2SaTransformBuild {
                    transform_type: 2,
                    transform_id: 5,
                    attributes: vec![],
                },
                Ikev2SaTransformBuild {
                    transform_type: 4,
                    transform_id: 19,
                    attributes: vec![],
                },
            ],
        }],
    };
    build_ike_sa_init_request(0x0102_0304_0506_0708, &offer, &key, &[0x61; 32], notifies).unwrap()
}

fn redirect_notify() -> Ikev2NotifyPayloadBuild {
    Redirect::Redirect {
        gateway: Gateway::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
        nonce: Some(&[0x61; 32]),
    }
    .to_notify_build(Context::SaInitResponse)
    .unwrap()
}

fn raw_response(request: &Ikev2SaInitRequest) -> OwnedMessage {
    // Independent literal generic payload framing, not the response builder
    // under test: four header octets, six Notify/gateway octets, address, Ni.
    let mut raw = vec![0, 0, 0, 46, 0, 0, 0x40, 0x17, 1, 4, 192, 0, 2, 1];
    raw.extend_from_slice(&[0x61; 32]);
    let mut header = Header::new(
        request.message().header.initiator_spi,
        0,
        PayloadType::Notify,
        EXCHANGE_TYPE_IKE_SA_INIT,
        HeaderFlags::from_bits(false, true, false),
        0,
    );
    header.length = 28 + u32::try_from(raw.len()).unwrap();
    OwnedMessage {
        header,
        raw_payloads: Bytes::from(raw),
    }
}

#[test]
fn redirected_from_type_three_precedes_all_identity_shape_errors() {
    for data in [
        &[3][..],
        &[3, 0],
        &[3, 4, b'a'],
        &[3, 1, 0xff],
        &[3, 4, b'a', b'.', b'.', b'b'],
    ] {
        let notify = Ikev2NotifyPayload {
            protocol_id: 0,
            spi_size: 0,
            notify_message_type: 16408,
            spi: &[],
            notification_data: data,
        };
        assert_eq!(
            decode_ikev2_redirect_notify(notify, Context::SaInitRequest),
            Err(Error::RedirectedFromRequiresIp)
        );
    }
}

#[test]
fn fqdn_backslash_is_rejected_on_build_and_receive() {
    for name in [r"a\.b", r"\000.example", r"evil\.example.com"] {
        assert_eq!(
            build_ikev2_redirect_notify(
                Redirect::Redirect {
                    gateway: Gateway::Fqdn(name),
                    nonce: None
                },
                Context::IkeAuthResponse
            ),
            Err(Error::FqdnInvalidCharacter)
        );
        let mut body = vec![0, 0, 0x40, 0x17, 3, u8::try_from(name.len()).unwrap()];
        body.extend_from_slice(name.as_bytes());
        assert_eq!(
            decode_ikev2_redirect_notify(
                Ikev2NotifyPayload::decode_body(&body).unwrap(),
                Context::IkeAuthResponse
            ),
            Err(Error::FqdnInvalidCharacter)
        );
    }
}

#[test]
fn exact_256_octet_dns_wire_name_is_rejected_in_both_text_forms() {
    let name = [
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(62),
    ]
    .join(".");
    assert_eq!(name.len(), 254);
    for text in [name.clone(), name + "."] {
        assert_eq!(
            build_ikev2_redirect_notify(
                Redirect::Redirect {
                    gateway: Gateway::Fqdn(&text),
                    nonce: None
                },
                Context::IkeAuthResponse
            ),
            Err(Error::FqdnNameTooLong)
        );
        let mut body = vec![0, 0, 0x40, 0x17, 3, u8::try_from(text.len()).unwrap()];
        body.extend_from_slice(text.as_bytes());
        assert_eq!(
            decode_ikev2_redirect_notify(
                Ikev2NotifyPayload::decode_body(&body).unwrap(),
                Context::IkeAuthResponse
            ),
            Err(Error::FqdnNameTooLong)
        );
    }
}

#[test]
fn notify_only_builder_accepts_a_valid_nonce_echoing_redirect() {
    let request = request(true);
    let response =
        build_ike_sa_init_notify_response(&request.message().header, &[redirect_notify()]);
    assert!(
        response.is_ok(),
        "a valid redirect has a zero-SPI responder path: {response:?}"
    );
    let response = response.unwrap();
    assert_eq!(response.header.responder_spi, 0);
    assert_eq!(response.raw_payloads, raw_response(&request).raw_payloads);
}

#[test]
fn initiator_admits_supported_matching_redirect_without_establishing_an_sa() {
    let request = request(true);
    let response = raw_response(&request);
    let result =
        admit_ike_sa_init_response(&request, &response.as_borrowed(), DecodeContext::default());
    assert!(
        result.is_ok(),
        "supported matching redirect must survive initial response admission: {result:?}"
    );
    let result = result.unwrap();
    assert!(!matches!(result, Ikev2SaInitResponse::Accepted(_)));
    assert!(matches!(result, Ikev2SaInitResponse::Redirect {
        gateway: Gateway::Ipv4(address)
    } if address == Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(format!("{result:?}"), "Redirect(<redacted>)");
}

#[test]
fn initial_redirect_checks_nonce_and_support_across_both_spi_forms() {
    let request = request(true);
    for responder_spi in [0, 1] {
        let mut valid = raw_response(&request);
        valid.header.responder_spi = responder_spi;
        let outcome =
            admit_ike_sa_init_response(&request, &valid.as_borrowed(), DecodeContext::default())
                .unwrap();
        assert!(matches!(outcome, Ikev2SaInitResponse::Redirect {
            gateway: Gateway::Ipv4(address)
        } if address == Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!matches!(outcome, Ikev2SaInitResponse::Accepted(_)));
        let mut mismatch = valid;
        let mut raw = mismatch.raw_payloads.to_vec();
        *raw.last_mut().unwrap() ^= 1;
        mismatch.raw_payloads = Bytes::from(raw);
        assert_admission_error(&request, &mismatch, AdmissionError::InvalidRedirect);
        let unsupported = self::request(false);
        let mut unsupported_response = raw_response(&unsupported);
        unsupported_response.header.responder_spi = responder_spi;
        assert_admission_error(
            &unsupported,
            &unsupported_response,
            AdmissionError::InvalidRedirect,
        );
    }
}

fn assert_admission_error(
    request: &Ikev2SaInitRequest,
    response: &OwnedMessage,
    expected: AdmissionError,
) {
    assert_eq!(
        admit_ike_sa_init_response(request, &response.as_borrowed(), DecodeContext::default())
            .unwrap_err(),
        expected
    );
}

#[test]
fn initial_redirect_accepts_both_support_forms_and_preserves_cookie_retry_support() {
    let supported = Redirect::Supported
        .to_notify_build(Context::SaInitRequest)
        .unwrap();
    let from = Redirect::RedirectedFrom("2001:db8::9".parse().unwrap())
        .to_notify_build(Context::SaInitRequest)
        .unwrap();
    for notifies in [vec![from.clone()], vec![supported, from]] {
        let request = request_with_notifies(&notifies)
            .with_cookie(&[0x73; 16])
            .unwrap();
        for gateway in [
            Gateway::Ipv6("2001:db8::1".parse().unwrap()),
            Gateway::Fqdn("Vpn.Example."),
        ] {
            let notify = Redirect::Redirect {
                gateway,
                nonce: Some(&[0x61; 32]),
            }
            .to_notify_build(Context::SaInitResponse)
            .unwrap();
            let response =
                build_ike_sa_init_notify_response(&request.message().header, &[notify]).unwrap();
            let result = admit_ike_sa_init_response(
                &request,
                &response.as_borrowed(),
                DecodeContext::default(),
            )
            .unwrap();
            assert!(
                matches!(result, Ikev2SaInitResponse::Redirect { gateway: actual } if actual == gateway)
            );
        }
    }
}

#[test]
fn initial_redirect_rejects_malformed_or_duplicate_sent_support() {
    let supported = Redirect::Supported
        .to_notify_build(Context::SaInitRequest)
        .unwrap();
    let mut malformed = supported.clone();
    malformed.notification_data.push(0);
    for notifies in [vec![supported.clone(), supported], vec![malformed]] {
        let request = request_with_notifies(&notifies);
        assert_admission_error(
            &request,
            &raw_response(&request),
            AdmissionError::InvalidRedirect,
        );
    }
}

#[test]
fn initial_redirect_rejects_duplicate_and_competing_retry_or_success_payloads() {
    let request = request(true);
    // Duplicate REDIRECT, NO_PROPOSAL_CHOSEN, COOKIE, or a standalone Nr.
    for (kind, second) in [
        (
            PayloadType::Notify,
            raw_response(&request).raw_payloads.to_vec(),
        ),
        (PayloadType::Notify, vec![0, 0, 0, 8, 0, 0, 0, 14]),
        (PayloadType::Notify, vec![0, 0, 0, 9, 0, 0, 0x40, 6, 1]),
        (
            PayloadType::Nonce,
            [vec![0, 0, 0, 36], vec![0x62; 32]].concat(),
        ),
    ] {
        for reversed in [false, true] {
            let mut response = raw_response(&request);
            let mut redirect = response.raw_payloads.to_vec();
            let mut other = second.clone();
            let raw = if reversed {
                other[0] = PayloadType::Notify.as_u8();
                response.header.next_payload = kind.as_u8();
                [other, redirect].concat()
            } else {
                redirect[0] = kind.as_u8();
                [redirect, other].concat()
            };
            response.header.length = 28 + u32::try_from(raw.len()).unwrap();
            response.raw_payloads = raw.into();
            assert_admission_error(&request, &response, AdmissionError::InvalidRetry);
        }
    }
}

#[test]
fn initial_redirect_receive_ignores_protocol_id_but_builder_is_canonical() {
    let request = request(true);
    for protocol_id in 0..=255 {
        let mut response = raw_response(&request);
        let mut raw = response.raw_payloads.to_vec();
        raw[4] = protocol_id;
        response.raw_payloads = raw.into();
        assert!(matches!(
            admit_ike_sa_init_response(&request, &response.as_borrowed(), DecodeContext::default()),
            Ok(Ikev2SaInitResponse::Redirect { .. })
        ));
        let mut notify = redirect_notify();
        notify.protocol_id = protocol_id;
        let built = build_ike_sa_init_notify_response(&request.message().header, &[notify]);
        if protocol_id == 0 {
            assert!(built.is_ok());
        } else {
            assert_eq!(
                built.unwrap_err(),
                Ikev2SaInitNotifyBuildError::ProtocolIdNotZero
            );
        }
    }
}

#[test]
fn initial_redirect_reports_exact_failures_for_nonce_spi_and_malformed_identity() {
    let request = request(true);
    let mut response = raw_response(&request);
    response.header.responder_spi = 1;
    let outcome =
        admit_ike_sa_init_response(&request, &response.as_borrowed(), DecodeContext::default())
            .unwrap();
    assert!(matches!(outcome, Ikev2SaInitResponse::Redirect {
        gateway: Gateway::Ipv4(address)
    } if address == Ipv4Addr::new(192, 0, 2, 1)));
    assert!(!matches!(outcome, Ikev2SaInitResponse::Accepted(_)));
    let unsupported = self::request(false);
    assert_admission_error(
        &unsupported,
        &raw_response(&unsupported),
        AdmissionError::InvalidRedirect,
    );
    for data in [
        vec![],
        vec![1, 0],
        vec![1, 4, 192, 0, 2],
        [vec![1, 4, 192, 0, 2, 1], vec![0x61; 15]].concat(),
        [vec![1, 4, 192, 0, 2, 1], vec![0x61; 257]].concat(),
        [vec![1, 4, 192, 0, 2, 1], vec![0x62; 32]].concat(),
    ] {
        let mut notify = redirect_notify();
        notify.notification_data = data.clone();
        if data.last() != Some(&0x62) {
            assert_eq!(
                build_ike_sa_init_notify_response(&request.message().header, &[notify])
                    .unwrap_err(),
                Ikev2SaInitNotifyBuildError::InvalidRedirect
            );
        }
        let mut response = raw_response(&request);
        let length = u16::try_from(8 + data.len()).unwrap().to_be_bytes();
        response.raw_payloads = [vec![0, 0, length[0], length[1], 0, 0, 0x40, 0x17], data]
            .concat()
            .into();
        response.header.length = 28 + u32::try_from(response.raw_payloads.len()).unwrap();
        assert_admission_error(&request, &response, AdmissionError::InvalidRedirect);
    }
    let mut with_spi = redirect_notify();
    with_spi.spi.push(1);
    assert_eq!(
        build_ike_sa_init_notify_response(&request.message().header, &[with_spi]).unwrap_err(),
        Ikev2SaInitNotifyBuildError::SpiNotEmpty
    );
    let mut response = raw_response(&request);
    let mut raw = response.raw_payloads.to_vec();
    raw[5] = 1;
    response.raw_payloads = raw.into();
    assert_admission_error(&request, &response, AdmissionError::InvalidRedirect);
}

#[test]
fn initial_redirect_outcome_ignores_the_responder_spi() {
    let request = request(true);
    for responder_spi in [0, 1, 0x0102_0304_0506_0708, u64::MAX] {
        let mut response = raw_response(&request);
        response.header.responder_spi = responder_spi;
        let result =
            admit_ike_sa_init_response(&request, &response.as_borrowed(), DecodeContext::default());
        assert!(
            result.is_ok(),
            "a correlated no-SA redirect tolerates either SPI form: {result:?}"
        );
        let result = result.unwrap();
        assert!(matches!(result, Ikev2SaInitResponse::Redirect {
            gateway: Gateway::Ipv4(address)
        } if address == Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!matches!(result, Ikev2SaInitResponse::Accepted(_)));
        assert_eq!(format!("{result:?}"), "Redirect(<redacted>)");
    }
}

#[test]
fn zero_spi_redirect_preserves_canonical_wire_and_non_sa_outcome() {
    let request = request(true);
    let expected = raw_response(&request);
    let built =
        build_ike_sa_init_notify_response(&request.message().header, &[redirect_notify()]).unwrap();
    assert_eq!(built.header.responder_spi, 0);
    assert_eq!(built.header, expected.header);
    assert_eq!(built.raw_payloads, expected.raw_payloads);
    let result =
        admit_ike_sa_init_response(&request, &built.as_borrowed(), DecodeContext::default())
            .unwrap();
    assert!(matches!(result, Ikev2SaInitResponse::Redirect {
        gateway: Gateway::Ipv4(address)
    } if address == Ipv4Addr::new(192, 0, 2, 1)));
    assert!(!matches!(result, Ikev2SaInitResponse::Accepted(_)));
}
