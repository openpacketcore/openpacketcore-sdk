//! Hand-authored vectors from the RFC 6311 §6.1/§6.3 layouts.
//! No peer-interoperability claim.

use opc_proto_ikev2::{
    build_ike_auth_cleartext_payload_chain, build_ike_auth_notify_payload,
    decode_ike_auth_cleartext_payloads, decode_ikev2_message_id_sync_notify,
    decode_ikev2_message_id_sync_supported_notify, Ikev2IkeAuthPayloadBuild, Ikev2MessageIdSync,
    Ikev2MessageIdSyncError, Ikev2NotifyPayload, Ikev2NotifyPayloadBuild, PayloadType,
    IKEV2_NOTIFY_MESSAGE_ID_SYNC, IKEV2_NOTIFY_MESSAGE_ID_SYNC_SUPPORTED,
};

// Complete generic Notify payloads: next=0, flags=0, length=8/20,
// Protocol ID=0, SPI Size=0, type=16420/16422. Sync data is nonce[4],
// sender's expected next outbound request ID[4],
// sender's expected next inbound request ID[4].
const SUPPORT: [u8; 8] = [0, 0, 0, 8, 0, 0, 0x40, 0x24];
const REQUEST: [u8; 20] = [
    0, 0, 0, 20, 0, 0, 0x40, 0x26, 0, 1, 0xfe, 0xff, 1, 2, 3, 4, 5, 6, 7, 8,
];
// A response echoes the nonce, but its counter order is P2 then M2,
// whereas the request carries M1 then P1 (RFC 6311 section 5.1).
const RESPONSE: [u8; 20] = [
    0, 0, 0, 20, 0, 0, 0x40, 0x26, 0, 1, 0xfe, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
];

fn chain(bodies: &[&[u8]]) -> (PayloadType, bytes::Bytes) {
    build_ike_auth_cleartext_payload_chain(
        &bodies
            .iter()
            .map(|body| Ikev2IkeAuthPayloadBuild {
                payload_type: PayloadType::Notify,
                body: body.to_vec(),
            })
            .collect::<Vec<_>>(),
    )
    .expect("synthetic Notify payload chain")
}

#[test]
fn support_builder_and_extractor_match_literal_rfc6311_vector() {
    assert_eq!(IKEV2_NOTIFY_MESSAGE_ID_SYNC_SUPPORTED, 16420);
    assert_eq!(IKEV2_NOTIFY_MESSAGE_ID_SYNC, 16422);
    let body = build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild::message_id_sync_supported())
        .expect("support builder");
    let (first, bytes) = chain(&[&body]);
    assert_eq!(bytes.as_ref(), SUPPORT);
    let opened = decode_ike_auth_cleartext_payloads(first, &bytes).expect("opened IKE_AUTH");
    assert!(opened.message_id_sync_supported().unwrap().is_some());
    assert_eq!(opened.notifies[0].protocol_id, 0);
    assert!(opened.notifies[0].spi.is_empty());
}

#[test]
fn sync_codec_preserves_sender_relative_nonce_and_counter_vectors() {
    for (wire, send, receive) in [
        (&REQUEST, 0x0102_0304, 0x0506_0708),
        (&RESPONSE, 0x1122_3344, 0x5566_7788),
    ] {
        let notify = Ikev2NotifyPayload::decode_body(&wire[4..]).unwrap();
        let value = decode_ikev2_message_id_sync_notify(notify)
            .unwrap()
            .unwrap();
        assert_eq!(value.nonce(), [0, 1, 0xfe, 0xff]);
        assert_eq!(value.expected_send_req_message_id(), send);
        assert_eq!(value.expected_recv_req_message_id(), receive);
        let body = build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild::message_id_sync(value))
            .unwrap();
        assert_eq!(chain(&[&body]).1.as_ref(), wire);
    }
}

#[test]
fn codec_preserves_all_counter_bits_without_claiming_counter_admission() {
    for send in [0, 1, 0x8000_0000, u32::MAX] {
        for receive in [0, 1, 0x8000_0000, u32::MAX] {
            let value = Ikev2MessageIdSync::new([0xff; 4], send, receive);
            let body =
                build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild::message_id_sync(value))
                    .unwrap();
            assert_eq!(body.len(), 16);
            assert_eq!(&body[4..8], &[0xff; 4]);
            assert_eq!(&body[8..12], &send.to_be_bytes());
            assert_eq!(&body[12..16], &receive.to_be_bytes());
            assert_eq!(
                decode_ikev2_message_id_sync_notify(
                    Ikev2NotifyPayload::decode_body(&body).unwrap()
                ),
                Ok(Some(value))
            );
        }
    }
}

#[test]
fn every_truncated_or_extended_sync_body_is_rejected() {
    let body = &REQUEST[4..];
    for length in 0..body.len() {
        match Ikev2NotifyPayload::decode_body(&body[..length]) {
            Err(_) => assert!(length < 4),
            Ok(notify) => assert_eq!(
                decode_ikev2_message_id_sync_notify(notify),
                Err(Ikev2MessageIdSyncError::InvalidDataLength)
            ),
        }
    }
    for extra in 1..=4 {
        let mut extended = body.to_vec();
        extended.extend(vec![0; extra]);
        assert_eq!(
            decode_ikev2_message_id_sync_notify(
                Ikev2NotifyPayload::decode_body(&extended).unwrap()
            ),
            Err(Ikev2MessageIdSyncError::InvalidDataLength)
        );
    }
}

#[test]
fn support_data_is_forbidden_and_empty_spis_ignore_protocol_id_on_receive() {
    for protocol in 0..=u8::MAX {
        let mut support = SUPPORT[4..].to_vec();
        support[0] = protocol;
        assert!(decode_ikev2_message_id_sync_supported_notify(
            Ikev2NotifyPayload::decode_body(&support).unwrap()
        )
        .unwrap()
        .is_some());
        support.push(0);
        assert_eq!(
            decode_ikev2_message_id_sync_supported_notify(
                Ikev2NotifyPayload::decode_body(&support).unwrap()
            ),
            Err(Ikev2MessageIdSyncError::InvalidDataLength)
        );
        let mut sync = REQUEST[4..].to_vec();
        sync[0] = protocol;
        assert!(decode_ikev2_message_id_sync_notify(
            Ikev2NotifyPayload::decode_body(&sync).unwrap()
        )
        .unwrap()
        .is_some());
    }
}

#[test]
fn nonempty_and_inconsistent_spis_fail_closed_for_both_types() {
    for body in [&SUPPORT[4..], &REQUEST[4..]] {
        let original = Ikev2NotifyPayload::decode_body(body).unwrap();
        for (size, spi, error) in [
            (1, &[0xaa][..], Ikev2MessageIdSyncError::SpiSizeNonzero),
            (1, &[][..], Ikev2MessageIdSyncError::SpiSizeNonzero),
            (0, &[0xaa][..], Ikev2MessageIdSyncError::SpiNonempty),
        ] {
            let notify = Ikev2NotifyPayload {
                spi_size: size,
                spi,
                ..original
            };
            let result = if body.len() == 4 {
                decode_ikev2_message_id_sync_supported_notify(notify).map(|value| value.is_some())
            } else {
                decode_ikev2_message_id_sync_notify(notify).map(|value| value.is_some())
            };
            assert_eq!(result, Err(error));
        }
    }
}

#[test]
fn unrelated_notifies_including_esp_sync_do_not_assert_message_id_support() {
    for notify_type in [0, 16421, 16423, 65535] {
        let notify = Ikev2NotifyPayload {
            protocol_id: 3,
            spi_size: 1,
            notify_message_type: notify_type,
            spi: &[1],
            notification_data: &[2],
        };
        assert_eq!(
            decode_ikev2_message_id_sync_supported_notify(notify),
            Ok(None)
        );
        assert_eq!(decode_ikev2_message_id_sync_notify(notify), Ok(None));
    }
    let (first, bytes) = chain(&[&[0, 0, 0x40, 0x25]]);
    let opened = decode_ike_auth_cleartext_payloads(first, &bytes).unwrap();
    assert_eq!(opened.message_id_sync_supported(), Ok(None));
    let empty = decode_ike_auth_cleartext_payloads(PayloadType::NoNext, &[]).unwrap();
    assert_eq!(empty.message_id_sync_supported(), Ok(None));
}

#[test]
fn each_decoder_classifies_only_its_own_type_across_the_u16_registry() {
    let support = Ikev2NotifyPayload::decode_body(&SUPPORT[4..]).unwrap();
    let sync = Ikev2NotifyPayload::decode_body(&REQUEST[4..]).unwrap();
    for notify_type in u16::MIN..=u16::MAX {
        assert_eq!(
            decode_ikev2_message_id_sync_supported_notify(Ikev2NotifyPayload {
                notify_message_type: notify_type,
                ..support
            })
            .map(|value| value.is_some()),
            Ok(notify_type == 16420),
            "support classification of Notify type {notify_type}"
        );
        assert_eq!(
            decode_ikev2_message_id_sync_notify(Ikev2NotifyPayload {
                notify_message_type: notify_type,
                ..sync
            })
            .map(|value| value.is_some()),
            Ok(notify_type == 16422),
            "sync classification of Notify type {notify_type}"
        );
    }
}

#[test]
fn valid_sibling_notifies_do_not_cross_classification_or_ike_auth_support() {
    assert_eq!(
        decode_ikev2_message_id_sync_supported_notify(
            Ikev2NotifyPayload::decode_body(&REQUEST[4..]).unwrap()
        ),
        Ok(None)
    );
    assert_eq!(
        decode_ikev2_message_id_sync_notify(
            Ikev2NotifyPayload::decode_body(&SUPPORT[4..]).unwrap()
        ),
        Ok(None)
    );
    let (first, bytes) = chain(&[&REQUEST[4..]]);
    let opened = decode_ike_auth_cleartext_payloads(first, &bytes).unwrap();
    assert_eq!(opened.message_id_sync_supported(), Ok(None));
}

#[test]
fn aggregate_rejects_malformed_and_every_duplicate_order() {
    let good = &SUPPORT[4..];
    let malformed = &[0, 0, 0x40, 0x24, 0x5a][..];
    let unrelated = &[0, 0, 0x40, 0x25][..];
    for bodies in [
        vec![good, malformed],
        vec![malformed, good],
        vec![good, good],
        vec![malformed, malformed],
    ] {
        let (first, bytes) = chain(&bodies);
        let opened = decode_ike_auth_cleartext_payloads(first, &bytes).unwrap();
        assert_eq!(
            opened.message_id_sync_supported(),
            Err(Ikev2MessageIdSyncError::DuplicateSupport)
        );
    }
    let (first, bytes) = chain(&[unrelated, malformed]);
    let opened = decode_ike_auth_cleartext_payloads(first, &bytes).unwrap();
    assert_eq!(
        opened.message_id_sync_supported(),
        Err(Ikev2MessageIdSyncError::InvalidDataLength)
    );
    let (first, bytes) = chain(&[unrelated, good, unrelated]);
    let opened = decode_ike_auth_cleartext_payloads(first, &bytes).unwrap();
    assert!(opened.message_id_sync_supported().unwrap().is_some());
}

#[test]
fn diagnostics_do_not_expose_nonce_or_counter_values() {
    let value = Ikev2MessageIdSync::new([0x41, 0x42, 0x43, 0x44], 123456789, 987654321);
    assert_eq!(format!("{value:?}"), "Ikev2MessageIdSync { .. }");
    let error = Ikev2MessageIdSyncError::InvalidDataLength;
    assert_eq!(error.to_string(), "ike_message_id_sync_invalid_data_length");
    assert_eq!(error.as_str(), "ike_message_id_sync_invalid_data_length");
}
