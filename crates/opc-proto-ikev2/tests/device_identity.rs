use opc_proto_ikev2::{
    build_ikev2_device_identity_request, build_ikev2_device_identity_response,
    decode_ikev2_device_identity_notify, Ikev2DeviceIdentity, Ikev2DeviceIdentityNotify,
    Ikev2DeviceIdentityNotifyError, Ikev2DeviceIdentityType, Ikev2NotifyPayload,
    IKEV2_NOTIFY_DEVICE_IDENTITY,
};
use opc_types::{Imei15, Imeisv};

const IMEI: &str = "490154203237518";
const IMEISV: &str = "4901542032375116";

fn decode_body(body: &[u8]) -> Ikev2DeviceIdentityNotify {
    let notify = Ikev2NotifyPayload::decode_body(body).expect("generic Notify body");
    decode_ikev2_device_identity_notify(notify).expect("typed DEVICE_IDENTITY")
}

fn decode_error(body: &[u8]) -> Ikev2DeviceIdentityNotifyError {
    let notify = Ikev2NotifyPayload::decode_body(body).expect("generic Notify body");
    decode_ikev2_device_identity_notify(notify).expect_err("malformed DEVICE_IDENTITY")
}

#[test]
fn imei_request_and_response_match_fixed_ts24302_vectors() {
    let request =
        build_ikev2_device_identity_request(Ikev2DeviceIdentityType::Imei).expect("request build");
    assert_eq!(request, [0x00, 0x00, 0xa0, 0x8d, 0x00, 0x01, 0x01]);
    assert_eq!(
        decode_body(&request),
        Ikev2DeviceIdentityNotify::Request(Ikev2DeviceIdentityType::Imei)
    );

    let response_identity = Ikev2DeviceIdentity::Imei(Imei15::new(IMEI).expect("valid IMEI"));
    let response =
        build_ikev2_device_identity_response(&response_identity).expect("response build");
    assert_eq!(
        response,
        [
            0x00, 0x00, 0xa0, 0x8d, 0x00, 0x09, 0x01, 0x94, 0x10, 0x45, 0x02, 0x23, 0x73, 0x15,
            0xf8,
        ]
    );

    let decoded = decode_body(&response);
    assert!(!decoded.is_request());
    assert_eq!(decoded.as_str(), "device_identity_response_imei");
    assert_eq!(
        decoded
            .response()
            .and_then(Ikev2DeviceIdentity::imei)
            .map(Imei15::as_str),
        Some(IMEI)
    );
    assert!(!format!("{decoded:?}").contains(IMEI));
}

#[test]
fn imei_response_preserves_spare_zero_and_non_luhn_digits() {
    let spare_zero = Ikev2DeviceIdentity::Imei(
        Imei15::new("490154203237510").expect("valid transmitted spare-zero IMEI"),
    );
    let response =
        build_ikev2_device_identity_response(&spare_zero).expect("spare-zero response build");
    assert_eq!(response.last(), Some(&0xf0));
    assert_eq!(
        decode_body(&response),
        Ikev2DeviceIdentityNotify::Response(spare_zero)
    );

    let non_luhn = Ikev2DeviceIdentity::Imei(
        Imei15::new("490154203237519").expect("opaque fifteenth digit is valid on wire"),
    );
    let response = build_ikev2_device_identity_response(&non_luhn).expect("non-Luhn response");
    assert_eq!(response.last(), Some(&0xf9));
    assert_eq!(
        decode_body(&response),
        Ikev2DeviceIdentityNotify::Response(non_luhn)
    );
}

#[test]
fn imeisv_request_and_response_match_fixed_ts24302_vectors() {
    let request = build_ikev2_device_identity_request(Ikev2DeviceIdentityType::Imeisv)
        .expect("request build");
    assert_eq!(request, [0x00, 0x00, 0xa0, 0x8d, 0x00, 0x01, 0x02]);
    assert_eq!(
        decode_body(&request).identity_type(),
        Ikev2DeviceIdentityType::Imeisv
    );

    let response_identity = Ikev2DeviceIdentity::Imeisv(Imeisv::new(IMEISV).expect("valid IMEISV"));
    let response =
        build_ikev2_device_identity_response(&response_identity).expect("response build");
    assert_eq!(
        response,
        [
            0x00, 0x00, 0xa0, 0x8d, 0x00, 0x09, 0x02, 0x94, 0x10, 0x45, 0x02, 0x23, 0x73, 0x15,
            0x61,
        ]
    );

    let decoded = decode_body(&response);
    assert_eq!(decoded.as_str(), "device_identity_response_imeisv");
    assert_eq!(
        decoded
            .response()
            .and_then(Ikev2DeviceIdentity::imeisv)
            .map(Imeisv::as_str),
        Some(IMEISV)
    );
    assert!(!format!("{decoded:?}").contains(IMEISV));
}

#[test]
fn decoder_rejects_wrong_notify_type_protocol_and_spi() {
    let data = [0x00, 0x01, 0x01];
    let wrong_type = Ikev2NotifyPayload {
        protocol_id: 0,
        spi_size: 0,
        notify_message_type: IKEV2_NOTIFY_DEVICE_IDENTITY - 1,
        spi: &[],
        notification_data: &data,
    };
    assert_eq!(
        decode_ikev2_device_identity_notify(wrong_type),
        Err(Ikev2DeviceIdentityNotifyError::WrongNotifyType)
    );

    let wrong_protocol = Ikev2NotifyPayload {
        protocol_id: 3,
        notify_message_type: IKEV2_NOTIFY_DEVICE_IDENTITY,
        ..wrong_type
    };
    assert_eq!(
        decode_ikev2_device_identity_notify(wrong_protocol),
        Err(Ikev2DeviceIdentityNotifyError::ProtocolIdNotZero)
    );

    let spi = [0xaa];
    let with_spi = Ikev2NotifyPayload {
        protocol_id: 0,
        spi_size: 1,
        notify_message_type: IKEV2_NOTIFY_DEVICE_IDENTITY,
        spi: &spi,
        notification_data: &data,
    };
    assert_eq!(
        decode_ikev2_device_identity_notify(with_spi),
        Err(Ikev2DeviceIdentityNotifyError::SpiNotEmpty)
    );
}

#[test]
fn decoder_rejects_truncation_length_mismatch_and_reserved_type() {
    assert_eq!(
        decode_error(&[0x00, 0x00, 0xa0, 0x8d, 0x00, 0x01]),
        Ikev2DeviceIdentityNotifyError::NotificationDataTooShort
    );
    assert_eq!(
        decode_error(&[0x00, 0x00, 0xa0, 0x8d, 0x00, 0x09, 0x01]),
        Ikev2DeviceIdentityNotifyError::DeclaredLengthMismatch
    );
    assert_eq!(
        decode_error(&[0x00, 0x00, 0xa0, 0x8d, 0x00, 0x01, 0x00]),
        Ikev2DeviceIdentityNotifyError::ReservedIdentityType
    );

    let short_identity = [
        0x00, 0x00, 0xa0, 0x8d, 0x00, 0x08, 0x01, 0x94, 0x10, 0x45, 0x02, 0x23, 0x73, 0x15,
    ];
    assert_eq!(
        decode_error(&short_identity),
        Ikev2DeviceIdentityNotifyError::IdentityValueLength
    );
}

#[test]
fn decoder_rejects_non_decimal_tbcd_internal_padding_and_bad_imei_filler() {
    let invalid_low_nibble = [
        0x00, 0x00, 0xa0, 0x8d, 0x00, 0x09, 0x02, 0x9a, 0x10, 0x45, 0x02, 0x23, 0x73, 0x15, 0x61,
    ];
    assert_eq!(
        decode_error(&invalid_low_nibble),
        Ikev2DeviceIdentityNotifyError::InvalidTbcdDigit
    );

    let internal_padding = [
        0x00, 0x00, 0xa0, 0x8d, 0x00, 0x09, 0x01, 0xf4, 0x10, 0x45, 0x02, 0x23, 0x73, 0x15, 0xf8,
    ];
    assert_eq!(
        decode_error(&internal_padding),
        Ikev2DeviceIdentityNotifyError::InvalidTbcdDigit
    );

    let bad_filler = [
        0x00, 0x00, 0xa0, 0x8d, 0x00, 0x09, 0x01, 0x94, 0x10, 0x45, 0x02, 0x23, 0x73, 0x15, 0xe8,
    ];
    assert_eq!(
        decode_error(&bad_filler),
        Ikev2DeviceIdentityNotifyError::InvalidImeiEndMark
    );

    let opaque_fifteenth_digit = [
        0x00, 0x00, 0xa0, 0x8d, 0x00, 0x09, 0x01, 0x94, 0x10, 0x45, 0x02, 0x23, 0x73, 0x15, 0xf9,
    ];
    assert_eq!(
        decode_body(&opaque_fifteenth_digit)
            .response()
            .and_then(Ikev2DeviceIdentity::imei)
            .map(Imei15::as_str),
        Some("490154203237519")
    );
}

#[test]
fn error_labels_and_debug_output_are_redaction_safe() {
    for error in [
        Ikev2DeviceIdentityNotifyError::WrongNotifyType,
        Ikev2DeviceIdentityNotifyError::DeclaredLengthMismatch,
        Ikev2DeviceIdentityNotifyError::InvalidTbcdDigit,
        Ikev2DeviceIdentityNotifyError::InvalidImei,
    ] {
        assert!(error.as_str().starts_with("ike_device_identity_"));
        assert!(!format!("{error:?}").contains(IMEI));
        assert!(!error.to_string().contains(IMEI));
    }
}
