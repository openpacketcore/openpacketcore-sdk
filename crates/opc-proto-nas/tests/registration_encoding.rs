//! TS 24.501 V19.8.0 §§9.11.3.6/7: typed sender values and raw forwarding.

use bytes::BytesMut;
use opc_proto_nas::messages::{
    RegistrationAccept, RegistrationRequest, RegistrationResult, RegistrationType,
};
use opc_protocol::{DecodeContext, Encode, EncodeContext};

fn request(first: u8) -> (Vec<u8>, RegistrationRequest) {
    let mut wire = vec![first, 0, 11, 0xf2, 0x00, 0xf1, 0x10, 1, 0, 0x41, 0, 0, 0, 1];
    wire.extend_from_slice(&[0x10, 1, 0x55]); // 5GMM capability TLV
    let (_, request) = RegistrationRequest::decode_body(&wire, DecodeContext::default()).unwrap();
    (wire, request)
}

fn encoded(value: &impl Encode, raw_preserving: bool) -> BytesMut {
    let ctx = EncodeContext {
        raw_preserving,
        ..EncodeContext::default()
    };
    let mut out = BytesMut::new();
    value.encode(&mut out, ctx).unwrap();
    assert_eq!(value.wire_len(ctx).unwrap(), out.len());
    out
}

#[test]
fn unused_received_registration_type_is_canonicalized_only_for_typed_sending() {
    let (mut wire, request) = request(0xb8);
    assert_eq!(
        request.registration_type,
        RegistrationType::InitialRegistration
    );
    assert_eq!(encoded(&request, true).as_ref(), wire);
    wire[0] = 0xb9;
    assert_eq!(encoded(&request, false).as_ref(), wire);
}

#[test]
fn typed_registration_edits_control_the_canonical_first_octet() {
    let (wire, mut request) = request(0xb9);
    request.registration_type = RegistrationType::PeriodicRegistrationUpdating;
    request.follow_on_request = false;
    request.ng_ksi.value = 5;
    request.ng_ksi.no_key_available = false;
    assert_eq!(encoded(&request, true).as_ref(), wire);
    let mut expected = wire;
    expected[0] = 0x53;
    assert_eq!(encoded(&request, false).as_ref(), expected);
}

#[test]
fn canonical_registration_rejects_out_of_range_key_identifiers_atomically() {
    let (wire, mut request) = request(0xb9);
    for value in [8, 15, 255] {
        request.ng_ksi.value = value;
        assert!(request.wire_len(EncodeContext::default()).is_err());
        let mut out = BytesMut::from(&b"prefix"[..]);
        assert!(request.encode(&mut out, EncodeContext::default()).is_err());
        assert_eq!(out.as_ref(), b"prefix");
        assert_eq!(encoded(&request, true).as_ref(), wire);
    }
}

#[test]
fn typed_registration_accept_edits_preserve_defined_flags_and_clear_the_spare() {
    // Figure/Table 9.11.3.6.1: bits 4-7 are defined; only bit 8 is spare.
    let wire = [1, 0xf9, 0x10, 1, 0x55];
    let (_, mut accept) = RegistrationAccept::decode_body(&wire, DecodeContext::default()).unwrap();
    accept.registration_result = RegistrationResult::AccessNon3gpp;
    accept.registration_result_flags.sms_allowed = false;
    accept.registration_result_flags.nssaa_to_be_performed = false;
    assert!(accept.registration_result_flags.emergency_registered);
    assert_eq!(encoded(&accept, true).as_ref(), wire);
    assert_eq!(encoded(&accept, false).as_ref(), &[1, 0x62, 0x10, 1, 0x55]);
}
