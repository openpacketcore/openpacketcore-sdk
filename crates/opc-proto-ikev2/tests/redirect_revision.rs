//! Redirect boundary regressions using the original public codec surface.

use std::net::Ipv4Addr;

use bytes::Bytes;
use opc_proto_ikev2::{
    admit_ike_sa_init_response, build_ike_sa_init_notify_response, build_ike_sa_init_request,
    build_ikev2_redirect_notify, decode_ikev2_redirect_notify, Header, HeaderFlags, Ikev2DhGroup,
    Ikev2EphemeralDhKey, Ikev2NotifyPayload, Ikev2NotifyPayloadBuild,
    Ikev2RedirectContext as Context, Ikev2RedirectGatewayIdentity as Gateway,
    Ikev2RedirectNotify as Redirect, Ikev2RedirectNotifyError as Error, Ikev2SaInitRequest,
    Ikev2SaPayloadBuild, Ikev2SaProposalBuild, Ikev2SaTransformBuild, Ikev2TransformAttributeBuild,
    Ikev2TransformAttributeBuildValue, OwnedMessage, PayloadType, EXCHANGE_TYPE_IKE_SA_INIT,
};
use opc_protocol::DecodeContext;

mod support;

fn request(support: bool) -> Ikev2SaInitRequest {
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
    let notifies = if support {
        vec![Redirect::Supported
            .to_notify_build(Context::SaInitRequest)
            .unwrap()]
    } else {
        vec![]
    };
    build_ike_sa_init_request(0x0102_0304_0506_0708, &offer, &key, &[0x61; 32], &notifies).unwrap()
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
    assert!(!matches!(
        result.unwrap(),
        opc_proto_ikev2::Ikev2SaInitResponse::Accepted(_)
    ));
}

#[test]
fn initial_redirect_rejects_nonce_mismatch_nonzero_spi_and_absent_support() {
    let request = request(true);
    let mut mismatch = raw_response(&request);
    let mut raw = mismatch.raw_payloads.to_vec();
    *raw.last_mut().unwrap() ^= 1;
    mismatch.raw_payloads = Bytes::from(raw);
    assert!(admit_ike_sa_init_response(
        &request,
        &mismatch.as_borrowed(),
        DecodeContext::default()
    )
    .is_err());
    let mut wrong_spi = raw_response(&request);
    wrong_spi.header.responder_spi = 1;
    assert!(admit_ike_sa_init_response(
        &request,
        &wrong_spi.as_borrowed(),
        DecodeContext::default()
    )
    .is_err());
    let unsupported = self::request(false);
    assert!(admit_ike_sa_init_response(
        &unsupported,
        &raw_response(&unsupported).as_borrowed(),
        DecodeContext::default()
    )
    .is_err());
}
