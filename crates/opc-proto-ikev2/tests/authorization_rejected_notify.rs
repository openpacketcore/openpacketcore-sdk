use opc_proto_ikev2::{
    build_ike_auth_notify_payload, Ikev2NotifyPayload, Ikev2NotifyPayloadBuild,
    IKEV2_NOTIFY_AUTHORIZATION_REJECTED,
};

#[test]
fn authorization_rejected_constructor_matches_ts24302_wire_value() {
    let value = Ikev2NotifyPayloadBuild::authorization_rejected();
    assert_eq!(value.protocol_id, 0);
    assert!(value.spi.is_empty());
    assert_eq!(value.notify_message_type, 9_003);
    assert_eq!(
        value.notify_message_type,
        IKEV2_NOTIFY_AUTHORIZATION_REJECTED
    );
    assert!(value.notification_data.is_empty());

    // TS 24.302 R17 table 8.1.2.2-1 assigns 9003; RFC 7296 section 3.10
    // supplies the Protocol ID, SPI Size, and Notify Message Type framing.
    let body = build_ike_auth_notify_payload(&value).expect("fixed Notify body encodes");
    assert_eq!(body, [0x00, 0x00, 0x23, 0x2b]);

    let decoded = Ikev2NotifyPayload::decode_body(&body).expect("fixed Notify body decodes");
    assert!(decoded.is_authorization_rejected());
}

#[test]
fn authorization_rejected_receive_tolerates_protocol_id_and_rejects_invalid_shape() {
    let canonical = Ikev2NotifyPayload {
        protocol_id: 0,
        spi_size: 0,
        notify_message_type: IKEV2_NOTIFY_AUTHORIZATION_REJECTED,
        spi: &[],
        notification_data: &[],
    };
    assert!(canonical.is_authorization_rejected());

    assert!(!Ikev2NotifyPayload {
        notify_message_type: IKEV2_NOTIFY_AUTHORIZATION_REJECTED - 1,
        ..canonical
    }
    .is_authorization_rejected());
    // RFC 7296 section 3.10 requires Protocol ID to be ignored when SPI Size
    // is zero. This independently authored body is noncanonical for a sender
    // but valid on receipt.
    let ignored_protocol =
        Ikev2NotifyPayload::decode_body(&[0x03, 0x00, 0x23, 0x2b]).expect("valid Notify body");
    assert!(ignored_protocol.is_authorization_rejected());

    let spi = [0xde, 0xad, 0xbe, 0xef];
    assert!(!Ikev2NotifyPayload {
        spi_size: 4,
        spi: &spi,
        ..canonical
    }
    .is_authorization_rejected());

    let private_data = b"subscriber-private-data";
    let with_data = Ikev2NotifyPayload {
        notification_data: private_data,
        ..canonical
    };
    assert!(!with_data.is_authorization_rejected());
    let diagnostic = format!("{with_data:?}");
    assert!(!diagnostic.contains("subscriber-private-data"));
}
