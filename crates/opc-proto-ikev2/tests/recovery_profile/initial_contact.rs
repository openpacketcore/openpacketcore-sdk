//! Codec-only assertions. Identity-bound cleanup requires the lifecycle driver.

use opc_proto_ikev2::{
    decode_ikev2_initial_contact_notify as decode, Ikev2InitialContactNotifyError as Error,
    Ikev2NotifyPayload as Notify, IKEV2_NOTIFY_INITIAL_CONTACT,
};

#[test]
fn initial_contact_is_a_strict_empty_signal_and_unrelated_types_are_lossless() {
    assert_eq!(IKEV2_NOTIFY_INITIAL_CONTACT, 16_384);
    let notify = Notify::decode_body(&[0, 0, 0x40, 0]).unwrap();
    let signal = decode(notify).unwrap().unwrap();
    assert_eq!(format!("{signal:?}"), "Ikev2InitialContact");
    let unrelated = Notify {
        protocol_id: 99,
        spi_size: 8,
        notify_message_type: 16_385,
        spi: b"private!",
        notification_data: b"private data",
    };
    let before = unrelated;
    assert_eq!(decode(unrelated), Ok(None));
    assert_eq!(unrelated, before);
}

#[test]
fn initial_contact_ignores_protocol_id_when_spi_is_empty() {
    for protocol_id in 0..=u8::MAX {
        let body = [protocol_id, 0, 0x40, 0];
        let notify = Notify::decode_body(&body).unwrap();
        assert!(decode(notify).unwrap().is_some());
        assert_eq!(notify.protocol_id, protocol_id);
    }
}

#[test]
fn initial_contact_refuses_each_invalid_field_with_content_free_errors() {
    let valid = Notify::decode_body(&[0, 0, 0x40, 0]).unwrap();
    for (invalid, error) in [
        (
            Notify {
                spi_size: 1,
                ..valid
            },
            Error::SpiSizeNonzero,
        ),
        (
            Notify {
                spi: b"private spi",
                ..valid
            },
            Error::SpiNonempty,
        ),
        (
            Notify {
                notification_data: b"private payload",
                ..valid
            },
            Error::NotificationDataNonempty,
        ),
    ] {
        assert_eq!(decode(invalid), Err(error));
        assert_eq!(error.to_string(), error.as_str());
        for diagnostic in [format!("{error:?}"), error.to_string()] {
            assert!(!diagnostic.contains("private"));
        }
    }
    let mut all = Notify {
        protocol_id: 1,
        spi_size: 1,
        spi: b"x",
        notification_data: b"y",
        ..valid
    };
    assert_eq!(decode(all), Err(Error::SpiSizeNonzero));
    all.spi_size = 0;
    assert_eq!(decode(all), Err(Error::SpiNonempty));
    all.spi = &[];
    assert_eq!(decode(all), Err(Error::NotificationDataNonempty));
}
