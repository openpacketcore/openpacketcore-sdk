use opc_proto_ikev2::{
    build_ike_auth_cleartext_payload_chain, build_ike_auth_notify_payload,
    decode_ike_auth_cleartext_payloads, decode_ikev2_pcscf_reselection_support_notify,
    Ikev2IkeAuthPayloadBuild, Ikev2NotifyPayload, Ikev2NotifyPayloadBuild,
    Ikev2PcscfReselectionSupportNotifyError, PayloadType, IKEV2_NOTIFY_P_CSCF_RESELECTION_SUPPORT,
};

const NOTIFY_TYPE_BYTES: [u8; 2] = IKEV2_NOTIFY_P_CSCF_RESELECTION_SUPPORT.to_be_bytes();
const CANONICAL: [u8; 4] = [0, 0, NOTIFY_TYPE_BYTES[0], NOTIFY_TYPE_BYTES[1]];
const NONZERO_PROTOCOL: [u8; 4] = [3, 0, NOTIFY_TYPE_BYTES[0], NOTIFY_TYPE_BYTES[1]];
const NONEMPTY_SPI: [u8; 5] = [0, 1, NOTIFY_TYPE_BYTES[0], NOTIFY_TYPE_BYTES[1], 0xa5];
const NONEMPTY_DATA: [u8; 5] = [0, 0, NOTIFY_TYPE_BYTES[0], NOTIFY_TYPE_BYTES[1], 0x5a];
const UNRELATED: [u8; 4] = [0, 0, 0x40, 0x04];

#[test]
fn exact_type_and_builder_match_ts24302_four_octet_shape() {
    assert_eq!(IKEV2_NOTIFY_P_CSCF_RESELECTION_SUPPORT, 41_304);
    assert_eq!(NOTIFY_TYPE_BYTES, [0xa1, 0x58]);

    let body =
        build_ike_auth_notify_payload(&Ikev2NotifyPayloadBuild::p_cscf_reselection_support())
            .expect("canonical P-CSCF reselection-support Notify");
    assert_eq!(body, CANONICAL);

    let notify = Ikev2NotifyPayload::decode_body(&body).expect("generic Notify decode");
    let marker =
        decode_ikev2_pcscf_reselection_support_notify(notify).expect("strict typed decode");
    assert!(marker.is_some());
    assert_eq!(format!("{marker:?}"), "Some(Ikev2PcscfReselectionSupport)");
}

#[test]
fn canonical_notify_decodes_from_an_opened_ike_auth_payload_chain() {
    let (first_payload, cleartext) =
        build_ike_auth_cleartext_payload_chain(&[Ikev2IkeAuthPayloadBuild {
            payload_type: PayloadType::Notify,
            body: CANONICAL.to_vec(),
        }])
        .expect("synthetic IKE_AUTH chain");
    let payloads = decode_ike_auth_cleartext_payloads(first_payload, &cleartext)
        .expect("opened IKE_AUTH decode");

    assert_eq!(payloads.notifies.len(), 1);
    assert!(
        decode_ikev2_pcscf_reselection_support_notify(payloads.notifies[0])
            .expect("strict typed decode")
            .is_some()
    );
}

#[test]
fn unrelated_notify_remains_distinct_from_malformed_type_41304() {
    let notify = Ikev2NotifyPayload::decode_body(&UNRELATED).expect("unrelated Notify");
    assert_eq!(
        decode_ikev2_pcscf_reselection_support_notify(notify),
        Ok(None)
    );
}

#[test]
fn wrong_protocol_id_fails_closed_without_losing_the_raw_view() {
    let notify = Ikev2NotifyPayload::decode_body(&NONZERO_PROTOCOL).expect("generic Notify decode");
    assert_eq!(notify.protocol_id, 3);
    assert_eq!(
        decode_ikev2_pcscf_reselection_support_notify(notify),
        Err(Ikev2PcscfReselectionSupportNotifyError::ProtocolIdNonzero)
    );
}

#[test]
fn nonzero_spi_size_and_nonempty_spi_fail_closed() {
    let notify = Ikev2NotifyPayload::decode_body(&NONEMPTY_SPI).expect("generic Notify decode");
    assert_eq!(notify.spi, &[0xa5]);
    assert_eq!(
        decode_ikev2_pcscf_reselection_support_notify(notify),
        Err(Ikev2PcscfReselectionSupportNotifyError::SpiSizeNonzero)
    );

    let inconsistent_public_view = Ikev2NotifyPayload {
        protocol_id: 0,
        spi_size: 0,
        notify_message_type: IKEV2_NOTIFY_P_CSCF_RESELECTION_SUPPORT,
        spi: &[0xa5],
        notification_data: &[],
    };
    assert_eq!(
        decode_ikev2_pcscf_reselection_support_notify(inconsistent_public_view),
        Err(Ikev2PcscfReselectionSupportNotifyError::SpiNonempty)
    );
}

#[test]
fn notification_data_fails_closed_without_losing_the_raw_view() {
    let notify = Ikev2NotifyPayload::decode_body(&NONEMPTY_DATA).expect("generic Notify decode");
    assert_eq!(notify.notification_data, &[0x5a]);
    assert_eq!(
        decode_ikev2_pcscf_reselection_support_notify(notify),
        Err(Ikev2PcscfReselectionSupportNotifyError::NotificationDataNonempty)
    );
}

#[test]
fn errors_and_debug_are_stable_and_payload_free() {
    let cases = [
        (
            Ikev2PcscfReselectionSupportNotifyError::ProtocolIdNonzero,
            "ike_pcscf_reselection_support_protocol_id_nonzero",
        ),
        (
            Ikev2PcscfReselectionSupportNotifyError::SpiSizeNonzero,
            "ike_pcscf_reselection_support_spi_size_nonzero",
        ),
        (
            Ikev2PcscfReselectionSupportNotifyError::SpiNonempty,
            "ike_pcscf_reselection_support_spi_nonempty",
        ),
        (
            Ikev2PcscfReselectionSupportNotifyError::NotificationDataNonempty,
            "ike_pcscf_reselection_support_notification_data_nonempty",
        ),
    ];
    for (error, code) in cases {
        assert_eq!(error.as_str(), code);
        assert_eq!(error.to_string(), code);
        assert!(!format!("{error:?}").contains("a55a"));
    }

    let raw = Ikev2NotifyPayload {
        protocol_id: 0,
        spi_size: 2,
        notify_message_type: IKEV2_NOTIFY_P_CSCF_RESELECTION_SUPPORT,
        spi: &[0xa5, 0x5a],
        notification_data: &[0xde, 0xad],
    };
    let debug = format!("{raw:?}");
    assert!(debug.contains("spi_len: 2"));
    assert!(debug.contains("notification_data_len: 2"));
    assert!(!debug.contains("a5"));
    assert!(!debug.contains("de"));
    assert!(!debug.contains("subscriber"));
    assert!(!debug.contains("endpoint"));
}
