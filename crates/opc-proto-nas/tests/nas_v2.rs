//! v2 integration tests: first-CNF body dispatch and NAS security helpers.

use bytes::BytesMut;
use opc_key::{KeyHandle, KeyId, KeyPurpose, Zeroizing, AES_256_GCM_SIV_KEY_LEN};
use opc_proto_nas::{
    MmMessageBody, NasCipheringAlgorithm, NasCount, NasIntegrityAlgorithm, NasMessage,
    NasSecurityContext, NasSecurityDirection, NullNasSecurityAlgorithms, SecurityHeaderType,
    SmMessageBody,
};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext};
use opc_types::TenantId;

fn plain_mm(message_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x7E, 0x00, message_type];
    out.extend_from_slice(body);
    out
}

fn sm(message_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x2E, 0x01, 0x05, message_type];
    out.extend_from_slice(body);
    out
}

fn tenant() -> TenantId {
    TenantId::from_static("tenant-a")
}

fn session_key(id: &str, fill: u8) -> KeyHandle {
    KeyHandle::new(
        KeyId::new(id).unwrap(),
        KeyPurpose::Session,
        tenant(),
        Zeroizing::new([fill; AES_256_GCM_SIV_KEY_LEN]),
    )
}

fn security_context() -> NasSecurityContext {
    NasSecurityContext::new(
        NasIntegrityAlgorithm::Nia0,
        NasCipheringAlgorithm::Nea0,
        session_key("nas-int", 0x11),
        session_key("nas-ciph", 0x22),
        0,
        1,
    )
    .unwrap()
}

#[test]
fn plain_mm_decode_body_security_mode_command_round_trip() {
    let body = &[0x21, 0x00, 0x02, 0x80, 0x00, 0xE0];
    let bytes = plain_mm(0x5D, body);
    let nas = NasMessage::decode(&bytes, DecodeContext::default())
        .unwrap()
        .1;
    let plain = match &nas {
        NasMessage::PlainMm(plain) => plain,
        other => panic!("expected plain MM, got {other:?}"),
    };

    let decoded_body = plain.decode_body(DecodeContext::default()).unwrap();
    let command = match &decoded_body {
        MmMessageBody::SecurityModeCommand(command) => command,
        other => panic!("expected Security Mode Command, got {other:?}"),
    };
    assert_eq!(
        command.selected_algorithms.ciphering,
        NasCipheringAlgorithm::Nea2
    );
    assert_eq!(
        command.selected_algorithms.integrity,
        NasIntegrityAlgorithm::Nia1
    );

    let mut encoded_body = BytesMut::new();
    decoded_body
        .encode(&mut encoded_body, EncodeContext::default())
        .unwrap();
    assert_eq!(&encoded_body[..], body);
}

#[test]
fn sm_decode_body_preserves_first_cnf_raw_body() {
    let body = &[0x01, 0x02, 0x03];
    let bytes = sm(0xD4, body);
    let nas = NasMessage::decode(&bytes, DecodeContext::default())
        .unwrap()
        .1;
    let sm = match &nas {
        NasMessage::Sm(sm) => sm,
        other => panic!("expected SM, got {other:?}"),
    };

    let decoded_body = sm.decode_body(DecodeContext::default()).unwrap();
    assert!(matches!(
        decoded_body,
        SmMessageBody::PduSessionReleaseComplete(_)
    ));
    let mut encoded_body = BytesMut::new();
    decoded_body
        .encode(&mut encoded_body, EncodeContext::default())
        .unwrap();
    assert_eq!(&encoded_body[..], body);
}

#[test]
fn security_protected_nia0_nea0_payload_verifies_and_decodes() {
    let context = security_context();
    let algorithms = NullNasSecurityAlgorithms;
    let payload = plain_mm(0x43, &[0xAA, 0xBB]);
    let envelope = context
        .protect_payload(
            &algorithms,
            NasSecurityDirection::Downlink,
            SecurityHeaderType::IntegrityProtectedAndCiphered,
            NasCount::new(1, 0x44),
            &payload,
        )
        .unwrap();
    let protected = NasMessage::SecurityProtected(envelope);

    let mut encoded = BytesMut::new();
    protected
        .encode(&mut encoded, EncodeContext::default())
        .unwrap();
    let decoded = NasMessage::decode(&encoded, DecodeContext::default())
        .unwrap()
        .1;
    let envelope = match &decoded {
        NasMessage::SecurityProtected(envelope) => envelope,
        other => panic!("expected security-protected NAS, got {other:?}"),
    };

    let verified = context
        .verify_and_decipher(&algorithms, NasSecurityDirection::Downlink, envelope)
        .unwrap();
    assert_eq!(verified.count, NasCount::new(1, 0x44));
    let inner = NasMessage::decode(&verified.payload, DecodeContext::default())
        .unwrap()
        .1;
    let plain = match inner {
        NasMessage::PlainMm(plain) => plain,
        other => panic!("expected inner plain MM, got {other:?}"),
    };
    assert!(matches!(
        plain.decode_body(DecodeContext::default()).unwrap(),
        MmMessageBody::RegistrationComplete(_)
    ));
}

#[test]
fn security_protected_wrong_mac_fails_closed() {
    let context = security_context();
    let algorithms = NullNasSecurityAlgorithms;
    let mut envelope = context
        .protect_payload(
            &algorithms,
            NasSecurityDirection::Uplink,
            SecurityHeaderType::IntegrityProtected,
            NasCount::new(0, 0x01),
            &[0x7E, 0x00, 0x43],
        )
        .unwrap();
    envelope.mac[0] = 1;

    assert!(context
        .verify_integrity(&algorithms, NasSecurityDirection::Uplink, &envelope)
        .is_err());
}
