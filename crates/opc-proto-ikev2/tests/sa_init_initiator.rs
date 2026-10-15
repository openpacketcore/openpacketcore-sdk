//! Initiator offer/admission contract, including unauthenticated retry outcomes.
//! @spec IETF RFC7296 1.2, 2.6, 2.7, 2.10, 3.1, 3.3.6, 3.4, 3.9, 3.10.1
//! @req REQ-IETF-RFC7296-SA-INIT-INITIATOR-001

use bytes::Bytes;
use opc_proto_ikev2::{
    admit_ike_sa_init_response, build_ike_sa_init_cookie_response,
    build_ike_sa_init_notify_response, build_ike_sa_init_request, build_ike_sa_init_response,
    decode_ike_sa_init_request_payloads, HeaderFlags, Ikev2DhGroup, Ikev2EphemeralDhKey,
    Ikev2KeyExchangePayloadBuild, Ikev2NoncePayloadBuild, Ikev2NotifyPayloadBuild,
    Ikev2SaInitInitiatorError, Ikev2SaInitRequest, Ikev2SaInitResponse,
    Ikev2SaInitResponsePayloads, Ikev2SaPayloadBuild, Ikev2SaProposalBuild, Ikev2SaTransformBuild,
    Ikev2TransformAttributeBuild, Ikev2TransformAttributeBuildValue, OwnedMessage, PayloadType,
    IKEV2_NOTIFY_COOKIE, IKEV2_NOTIFY_INVALID_KE_PAYLOAD, IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN,
};
use opc_protocol::DecodeContext;

mod support;

const SPI_I: u64 = 0x0102_0304_0506_0708;
const SPI_R: u64 = 0x1112_1314_1516_1718;

fn transform(kind: u8, id: u16) -> Ikev2SaTransformBuild {
    Ikev2SaTransformBuild {
        transform_type: kind,
        transform_id: id,
        attributes: vec![],
    }
}

fn offer() -> Ikev2SaPayloadBuild {
    let mut encr = transform(1, 20); // AES-GCM-16, 128-bit key.
    encr.attributes.push(Ikev2TransformAttributeBuild {
        attribute_type: 14,
        value: Ikev2TransformAttributeBuildValue::Tv(128),
    });
    Ikev2SaPayloadBuild {
        proposals: vec![Ikev2SaProposalBuild {
            proposal_number: 1,
            protocol_id: 1,
            spi: vec![],
            transforms: vec![encr, transform(2, 5), transform(4, 19)],
        }],
    }
}

fn key() -> Ikev2EphemeralDhKey {
    support::ensure_ike_crypto();
    Ikev2EphemeralDhKey::generate(Ikev2DhGroup::Ecp256).unwrap()
}

fn request(offer: &Ikev2SaPayloadBuild) -> Ikev2SaInitRequest {
    build_ike_sa_init_request(SPI_I, offer, &key(), &[0x61; 32], &[]).unwrap()
}

fn response_payloads() -> Ikev2SaInitResponsePayloads {
    Ikev2SaInitResponsePayloads {
        security_association: offer(),
        key_exchange: Ikev2KeyExchangePayloadBuild {
            dh_group: 19,
            key_exchange_data: key().public_value().to_vec(),
        },
        nonce: Ikev2NoncePayloadBuild {
            nonce: vec![0x72; 32],
        },
        notifies: vec![],
    }
}

fn response(request: &Ikev2SaInitRequest, payloads: &Ikev2SaInitResponsePayloads) -> OwnedMessage {
    build_ike_sa_init_response(&request.message().header, SPI_R, payloads).unwrap()
}

fn assert_rejected(request: &Ikev2SaInitRequest, response: &OwnedMessage) {
    assert!(
        admit_ike_sa_init_response(request, &response.as_borrowed(), DecodeContext::default())
            .is_err()
    );
}

#[test]
fn request_preserves_caller_preference_and_public_key_custody() {
    let key = key();
    let mut offered = offer();
    offered.proposals[0].transforms.push(transform(2, 7));
    let mut second = offered.proposals[0].clone();
    second.proposal_number = 2;
    second.transforms[0].attributes[0].value = Ikev2TransformAttributeBuildValue::Tv(256);
    offered.proposals.push(second);
    let notify = Ikev2NotifyPayloadBuild {
        protocol_id: 0,
        spi: vec![],
        notify_message_type: 65000,
        notification_data: b"synthetic-notify".to_vec(),
    };
    let request = build_ike_sa_init_request(SPI_I, &offered, &key, &[0x61; 32], &[notify]).unwrap();
    let message = request.message().as_borrowed();
    let decoded = decode_ike_sa_init_request_payloads(&message, DecodeContext::default()).unwrap();
    assert_eq!(message.header.initiator_spi, SPI_I);
    assert_eq!(message.header.responder_spi, 0);
    assert_eq!(message.header.message_id, 0);
    assert!(message.header.flags.initiator());
    assert!(!message.header.flags.response());
    assert_eq!(decoded.security_association.proposals.len(), 2);
    assert_eq!(decoded.security_association.proposals[1].proposal_number, 2);
    assert_eq!(
        decoded.security_association.proposals[0].transforms[3].transform_id,
        7
    );
    assert_eq!(decoded.key_exchange.key_exchange_data, key.public_value());
    assert_eq!(decoded.nonce.nonce, &[0x61; 32]);
    assert_eq!(decoded.notifies[0].notification_data, b"synthetic-notify");
    // Building never consumes or exports the caller's private-key handle.
    assert!(key.agree(key.public_value()).is_ok());
}

#[test]
fn request_rejects_invalid_offer_and_uses_strongest_prf_nonce_minimum() {
    let key = key();
    let mut offered = offer();
    for len in [0, 15, 257] {
        assert!(build_ike_sa_init_request(SPI_I, &offered, &key, &vec![0x61; len], &[]).is_err());
    }
    for len in [16, 256] {
        assert!(build_ike_sa_init_request(SPI_I, &offered, &key, &vec![0x61; len], &[]).is_ok());
    }
    offered.proposals[0].transforms.push(transform(2, 7));
    assert!(build_ike_sa_init_request(SPI_I, &offered, &key, &[0x61; 31], &[]).is_err());
    assert!(build_ike_sa_init_request(SPI_I, &offered, &key, &[0x61; 32], &[]).is_ok());
    assert!(build_ike_sa_init_request(0, &offered, &key, &[0x61; 32], &[]).is_err());
    offered.proposals[0].transforms[2].transform_id = 20;
    assert_eq!(
        build_ike_sa_init_request(SPI_I, &offered, &key, &[0x61; 32], &[]).unwrap_err(),
        Ikev2SaInitInitiatorError::KeyExchangeNotOffered
    );
    for mutation in 0..6 {
        let mut offered = offer();
        match mutation {
            0 => offered.proposals.clear(),
            1 => offered.proposals[0].proposal_number = 2,
            2 => offered.proposals[0].protocol_id = 3,
            3 => offered.proposals[0].spi.push(1),
            4 => {
                offered.proposals[0].transforms.remove(1);
            }
            _ => offered.proposals[0].transforms.push(transform(4, 19)),
        }
        assert!(
            build_ike_sa_init_request(SPI_I, &offered, &key, &[0x61; 32], &[]).is_err(),
            "mutation {mutation}"
        );
    }
}

#[test]
fn admission_accepts_one_exact_offered_subset_in_any_transform_order() {
    let mut offered = offer();
    offered.proposals[0].transforms.push(transform(2, 7));
    let mut second = offer().proposals.remove(0);
    second.proposal_number = 2;
    offered.proposals.push(second);
    let request = request(&offered);
    let mut payloads = response_payloads();
    payloads.security_association.proposals[0].proposal_number = 2;
    payloads.security_association.proposals[0]
        .transforms
        .reverse();
    let response = response(&request, &payloads);
    let Ikev2SaInitResponse::Accepted(accepted) =
        admit_ike_sa_init_response(&request, &response.as_borrowed(), DecodeContext::default())
            .unwrap()
    else {
        panic!("expected acceptance")
    };
    assert_eq!(accepted.profile().dh_group(), Ikev2DhGroup::Ecp256);
    assert_eq!(accepted.responder_spi(), SPI_R);
    assert_eq!(
        accepted.key_exchange(),
        payloads.key_exchange.key_exchange_data
    );
    assert_eq!(accepted.nonce(), payloads.nonce.nonce);
}

#[test]
fn admission_rejects_header_confusion_and_zero_responder_spi() {
    let request = request(&offer());
    let response = response(&request, &response_payloads());
    for mutation in 0..7 {
        let mut response = response.clone();
        match mutation {
            0 => response.header.initiator_spi ^= 1,
            1 => response.header.responder_spi = 0,
            2 => response.header.message_id = 1,
            3 => response.header.flags = HeaderFlags::from_bits(false, false, false),
            4 => response.header.flags = HeaderFlags::from_bits(true, true, false),
            5 => response.header.exchange_type = 35,
            _ => response.header.major_version = 1,
        }
        assert_rejected(&request, &response);
    }
    // RFC receiver rules ignore reserved flag bits, V and higher minor versions.
    let mut response = response;
    response.header.flags = HeaderFlags::new(0xf7);
    response.header.minor_version = 1;
    assert!(admit_ike_sa_init_response(
        &request,
        &response.as_borrowed(),
        DecodeContext::default()
    )
    .is_ok());
}

#[test]
fn admission_rejects_unoffered_incomplete_and_extra_transforms_or_proposals() {
    let request = request(&offer());
    for mutation in 0..10 {
        let mut payloads = response_payloads();
        let proposal = &mut payloads.security_association.proposals[0];
        match mutation {
            0 => proposal.proposal_number = 2,
            1 => {
                let mut extra = proposal.clone();
                extra.proposal_number = 2;
                payloads.security_association.proposals.push(extra);
            }
            2 => proposal.transforms[1].transform_id = 7,
            3 => proposal.transforms.push(transform(2, 5)),
            4 => proposal.transforms.push(transform(5, 0)),
            5 => {
                proposal.transforms.remove(1);
            }
            6 => {
                proposal.transforms[0].attributes[0].value =
                    Ikev2TransformAttributeBuildValue::Tv(256)
            }
            7 => proposal.transforms[0].attributes.clear(),
            8 => proposal.protocol_id = 3,
            _ => proposal.spi = vec![1, 2, 3, 4],
        }
        assert_rejected(&request, &response(&request, &payloads));
    }
}

#[test]
fn admission_rejects_ke_group_and_public_value_and_nonce_mismatches() {
    let mut offered = offer();
    offered.proposals[0].transforms.push(transform(4, 20));
    let request = request(&offered);
    for mutation in 0..5 {
        let mut payloads = response_payloads();
        match mutation {
            0 => payloads.key_exchange.dh_group = 20,
            1 => payloads.security_association.proposals[0].transforms[2].transform_id = 20,
            2 => payloads
                .key_exchange
                .key_exchange_data
                .pop()
                .map(|_| ())
                .unwrap(),
            3 => payloads.key_exchange.key_exchange_data.fill(0),
            _ => payloads.nonce.nonce = vec![0x72; 16],
        }
        if mutation == 4 {
            // SHA-512 selection requires 32 octets even though §3.9 allows 16.
            let mut offered = offer();
            offered.proposals[0].transforms[1].transform_id = 7;
            let request = self::request(&offered);
            payloads.security_association = offered;
            assert_rejected(&request, &response(&request, &payloads));
        } else {
            assert_rejected(&request, &response(&request, &payloads));
        }
    }
    let mut response = response(&request, &response_payloads());
    // Deliberately malformed 15-byte Nr cannot be emitted by the typed responder.
    let mut raw = response.raw_payloads.to_vec();
    let nonce_start = raw.len() - 36;
    raw.truncate(nonce_start + 19);
    raw[nonce_start + 2..nonce_start + 4].copy_from_slice(&19_u16.to_be_bytes());
    response.raw_payloads = Bytes::from(raw);
    response.header.length = 28 + u32::try_from(response.raw_payloads.len()).unwrap();
    assert_rejected(&request, &response);
}

#[test]
fn typed_retries_accept_both_spi_forms_and_cookie_retry_preserves_payloads() {
    let request = request(&offer());
    let cookie = b"synthetic-cookie";
    for responder_spi in [0, SPI_R] {
        let mut challenge =
            build_ike_sa_init_cookie_response(&request.message().header, cookie).unwrap();
        challenge.header.responder_spi = responder_spi;
        let Ikev2SaInitResponse::Cookie(cookie_notify) = admit_ike_sa_init_response(
            &request,
            &challenge.as_borrowed(),
            DecodeContext::default(),
        )
        .unwrap() else {
            panic!("expected COOKIE")
        };
        assert_eq!(cookie_notify.cookie(), cookie);
        let retry = request.with_cookie(cookie_notify.cookie()).unwrap();
        let payloads = retry
            .message()
            .payloads()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(payloads[0].payload_type, PayloadType::Notify);
        assert_eq!(
            &retry.message().raw_payloads[payloads[0].body.len() + 4..],
            &request.message().raw_payloads[..]
        );
        assert_eq!(retry.message().header.responder_spi, 0);
        assert_eq!(retry.message().header.message_id, 0);
        let retry_again = retry.with_cookie(b"replacement").unwrap();
        assert_eq!(
            retry_again.message().payloads().count(),
            retry.message().payloads().count()
        );
        for (kind, data) in [
            (IKEV2_NOTIFY_INVALID_KE_PAYLOAD, vec![0, 20]),
            (IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, vec![]),
        ] {
            let notify = Ikev2NotifyPayloadBuild {
                protocol_id: 0,
                spi: vec![],
                notify_message_type: kind,
                notification_data: data,
            };
            let mut reply =
                build_ike_sa_init_notify_response(&request.message().header, &[notify]).unwrap();
            reply.header.responder_spi = responder_spi;
            let outcome = admit_ike_sa_init_response(
                &request,
                &reply.as_borrowed(),
                DecodeContext::default(),
            )
            .unwrap();
            match kind {
                IKEV2_NOTIFY_INVALID_KE_PAYLOAD => assert!(matches!(
                    outcome,
                    Ikev2SaInitResponse::InvalidKePayload {
                        requested_group: 20
                    }
                )),
                _ => assert!(matches!(outcome, Ikev2SaInitResponse::NoProposalChosen)),
            }
        }
    }
}

#[test]
fn retries_reject_malformed_duplicate_and_conflicting_notifications() {
    let request = request(&offer());
    for cookie in [vec![], vec![1; 65]] {
        let challenge =
            build_ike_sa_init_cookie_response(&request.message().header, &cookie).unwrap();
        assert_rejected(&request, &challenge);
        assert!(request.with_cookie(&cookie).is_err());
    }
    let mut challenge =
        build_ike_sa_init_cookie_response(&request.message().header, b"cookie").unwrap();
    let mut raw = challenge.raw_payloads.to_vec();
    raw[4] = 1; // COOKIE cannot carry a protocol ID.
    challenge.raw_payloads = Bytes::from(raw);
    assert_rejected(&request, &challenge);
    for kind in [IKEV2_NOTIFY_COOKIE, IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN] {
        let mut payloads = response_payloads();
        payloads.notifies.push(Ikev2NotifyPayloadBuild {
            protocol_id: 0,
            spi: vec![],
            notify_message_type: kind,
            notification_data: b"cookie".to_vec(),
        });
        assert_rejected(&request, &response(&request, &payloads));
    }
    let mut challenge =
        build_ike_sa_init_cookie_response(&request.message().header, b"cookie").unwrap();
    let original = challenge.raw_payloads.clone();
    let mut raw = original.to_vec();
    raw[0] = PayloadType::Notify.as_u8();
    raw.extend_from_slice(&original);
    challenge.raw_payloads = Bytes::from(raw);
    challenge.header.length = 28 + u32::try_from(challenge.raw_payloads.len()).unwrap();
    assert_rejected(&request, &challenge);
}

#[test]
fn diagnostics_never_render_nonce_ke_or_cookie_bytes() {
    let request = request(&offer());
    let payloads = response_payloads();
    let response = response(&request, &payloads);
    let accepted =
        admit_ike_sa_init_response(&request, &response.as_borrowed(), DecodeContext::default())
            .unwrap();
    let challenge =
        build_ike_sa_init_cookie_response(&request.message().header, b"private-cookie-marker")
            .unwrap();
    let cookie =
        admit_ike_sa_init_response(&request, &challenge.as_borrowed(), DecodeContext::default())
            .unwrap();
    let rendered = format!("{request:?} {accepted:?} {cookie:?}");
    for bytes in [
        &[0x61; 32][..],
        &payloads.nonce.nonce[..],
        &payloads.key_exchange.key_exchange_data[..],
        b"private-cookie-marker",
    ] {
        assert!(!rendered.contains(&format!("{bytes:?}")));
        assert!(!rendered.contains(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()));
        if let Ok(text) = std::str::from_utf8(bytes) {
            assert!(!rendered.contains(text));
        }
    }
    let error =
        build_ike_sa_init_request(SPI_I, &offer(), &key(), b"secret-short", &[]).unwrap_err();
    assert!(!format!("{error:?} {error}").contains("secret-short"));
}
