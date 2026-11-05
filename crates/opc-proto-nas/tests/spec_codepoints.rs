//! Independent codepoints from TS 24.501 V19.8.0 Tables 9.7.1/2, 9.11.3.7.1
//! and 9.11.3.34.1. Naming a codepoint does not implement its procedure.

use bytes::BytesMut;
use opc_proto_nas::{
    messages::{
        decode_mm_message_body, decode_sm_message_body, RegistrationRequest, RegistrationType,
        SecurityModeCommand, SelectedNasSecurityAlgorithms,
    },
    MmMessageType, SmMessageType,
};
use opc_protocol::{DecodeContext, Encode, EncodeContext, ValidationLevel};

#[test]
fn all_registration_values_follow_receiver_rules_and_preserve_raw_octet() {
    for validation_level in [
        ValidationLevel::HeaderOnly,
        ValidationLevel::Structural,
        ValidationLevel::Strict,
        ValidationLevel::ProcedureAware,
    ] {
        for value in 0..=7 {
            let mut body = vec![0xb8 | value, 0, 11];
            body.extend_from_slice(&[0xf2, 0x00, 0xf1, 0x10, 1, 0, 0x41, 0, 0, 0, 1]);
            let ctx = DecodeContext {
                validation_level,
                ..DecodeContext::default()
            };
            let (_, request) = RegistrationRequest::decode_body(&body, ctx).unwrap();
            assert_eq!(request.registration_type as u8, value.max(1));
            assert!(request.follow_on_request);
            assert_eq!(request.ng_ksi.value, 3);
            assert!(request.ng_ksi.no_key_available);
            assert_eq!(request.raw_first_octet, body[0]);
            let mut encoded = BytesMut::new();
            request
                .encode(
                    &mut encoded,
                    EncodeContext {
                        raw_preserving: true,
                        ..EncodeContext::default()
                    },
                )
                .unwrap();
            assert_eq!(encoded.as_ref(), body);
            // Table 9.11.3.7.1 gives typed InitialRegistration sender value 1.
            encoded.clear();
            request
                .encode(&mut encoded, EncodeContext::default())
                .unwrap();
            body[0] = 0xb8 | value.max(1);
            assert_eq!(encoded.as_ref(), body);
        }
    }
    assert_eq!(RegistrationType::InitialRegistration as u8, 1);
}

#[test]
fn security_algorithm_registry_accepts_defined_codes_and_rejects_reserved_codes() {
    for raw in 0..=255 {
        let decoded = SelectedNasSecurityAlgorithms::from_octet(raw);
        if raw >> 4 > 7 || raw & 15 > 7 {
            assert!(decoded.is_err(), "reserved algorithm {raw:#x}");
            continue;
        }
        let algorithms = decoded.unwrap();
        assert_eq!(algorithms.ciphering as u8, raw >> 4);
        assert_eq!(algorithms.integrity as u8, raw & 15);
        let body = [raw, 0, 2, 0xff, 0xff];
        let (_, command) =
            SecurityModeCommand::decode_body(&body, DecodeContext::default()).unwrap();
        let mut encoded = BytesMut::new();
        command
            .encode(&mut encoded, EncodeContext::default())
            .unwrap();
        assert_eq!(encoded.as_ref(), body);
    }
}

#[test]
fn named_message_types_keep_their_raw_body_dispatch() {
    let body = [0x01, 0x23, 0x45];
    for code in [0x50, 0x51, 0x52, 0x69, 0x6a, 0x6b, 0x6c, 0x6d] {
        assert_eq!(MmMessageType::from_u8(code).map(|t| t as u8), Some(code));
        let decoded = decode_mm_message_body(code, &body, DecodeContext::default()).unwrap();
        let mut encoded = BytesMut::new();
        decoded
            .encode(&mut encoded, EncodeContext::default())
            .unwrap();
        assert_eq!(encoded.as_ref(), body);
    }
    for code in [0xd8, 0xd9, 0xda, 0xdb] {
        assert_eq!(SmMessageType::from_u8(code).map(|t| t as u8), Some(code));
        let decoded = decode_sm_message_body(code, &body, DecodeContext::default()).unwrap();
        let mut encoded = BytesMut::new();
        decoded
            .encode(&mut encoded, EncodeContext::default())
            .unwrap();
        assert_eq!(encoded.as_ref(), body);
    }
}
