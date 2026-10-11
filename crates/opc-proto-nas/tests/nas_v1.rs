//! v1 integration tests: Registration Request/Accept body parsing, optional-IE
//! iteration, and BCD digit unpacking (PLMN, routing indicator, IMEI/IMEISV).

use bytes::BytesMut;
use opc_proto_nas::{
    unpack_imei, unpack_plmn, unpack_routing_indicator, IdentityType, MobileIdentity, NasMessage,
    RegistrationAccept, RegistrationRequest, RegistrationResult, RegistrationType,
};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext, OwnedDecode};

/// Build a full plain 5GMM NAS byte vector from the 3-octet header and body.
fn plain_mm(message_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![0x7E, 0x00, message_type];
    out.extend_from_slice(body);
    out
}

#[test]
fn registration_request_full_round_trip() {
    // Body: initial registration, ngKSI=0, SUCI, UE security capability.
    let body: &[u8] = &[
        0x01, // initial registration, ngKSI=0
        0x00, 0x0A, // LV-E mobile-identity length
        0x01, 0x02, 0xF8, 0x39, 0x21, 0xF3, 0x00, 0x00, 0x13, 0x57, // SUCI
        0x2E, 0x02, 0x80, 0x00, // UE security capability (known TLV IE)
    ];
    let bytes = plain_mm(0x41, body);

    let nas = NasMessage::decode_owned(
        BytesMut::from(bytes.as_slice()).freeze(),
        DecodeContext::default(),
    )
    .unwrap();
    let plain = match &nas {
        NasMessage::PlainMm(m) => m,
        other => panic!("expected plain MM, got {other:?}"),
    };

    let (_, req) = RegistrationRequest::decode_body(&plain.body, DecodeContext::default()).unwrap();
    assert_eq!(req.registration_type, RegistrationType::InitialRegistration);
    assert!(!req.follow_on_request);
    assert_eq!(req.ng_ksi.value, 0);
    assert_eq!(req.mobile_identity.identity_type, IdentityType::Suci);
    assert_eq!(req.optional_ies.len(), 1);
    assert_eq!(req.optional_ies[0].iei, 0x2E);

    // Body round-trip.
    let mut encoded_body = BytesMut::new();
    req.encode(&mut encoded_body, EncodeContext::default())
        .unwrap();
    assert_eq!(&encoded_body[..], body);

    // Full NAS round-trip.
    let mut encoded_nas = BytesMut::new();
    nas.encode(&mut encoded_nas, EncodeContext::default())
        .unwrap();
    assert_eq!(&encoded_nas[..], bytes);
}

#[test]
fn registration_request_bcd_views() {
    let body: &[u8] = &[
        0x01, 0x00, 0x0A, 0x01, 0x02, 0xF8, 0x39, 0x21, 0xF3, 0x00, 0x00, 0x13, 0x57,
    ];
    let (_, req) = RegistrationRequest::decode_body(body, DecodeContext::default()).unwrap();

    let suci = match &req.mobile_identity.view {
        opc_proto_nas::IdentityView::Suci(opc_proto_nas::SuciView::Imsi {
            plmn,
            routing_indicator,
            ..
        }) => (plmn, routing_indicator),
        other => panic!("expected IMSI-format SUCI, got {other:?}"),
    };

    let plmn = unpack_plmn(*suci.0).unwrap();
    assert_eq!(plmn.mcc, "208");
    assert_eq!(plmn.mnc, "93");

    let ri = unpack_routing_indicator(*suci.1).unwrap();
    assert_eq!(ri, "123");
}

#[test]
fn registration_request_preserves_unknown_optional_ie() {
    // TS 24.501 V18.11.1 Table 8.2.6.1.1 does not assign IEI 0x4D.
    // Unlike 0x99 (Network slicing indication, one octet), it can exercise
    // the decoder's unknown full-octet TLV preservation policy.
    let mut body = vec![
        0x01, 0x00, 0x0A, 0x01, 0x02, 0xF8, 0x39, 0x21, 0xF3, 0x00, 0x00, 0x13, 0x57,
    ];
    body.extend_from_slice(&[0x4D, 0x02, 0xAB, 0xCD]);

    let (_, req) = RegistrationRequest::decode_body(&body, DecodeContext::default()).unwrap();
    let unknown = req
        .optional_ies
        .iter()
        .find(|ie| ie.iei == 0x4D)
        .expect("unknown IE preserved");
    assert_eq!(&unknown.value[..], &[0xAB, 0xCD]);

    let mut encoded = BytesMut::new();
    req.encode(&mut encoded, EncodeContext::default()).unwrap();
    assert_eq!(&encoded[..], body);
}

#[test]
fn registration_request_network_slicing_indication_is_one_octet() {
    // TS 24.501 V18.11.1 Table 8.2.6.1.1 assigns 9-; the low nibble is
    // the value, not a length. A following UE security capability must
    // start a separate IE (TS 24.007 section 11.2.4).
    let body = [
        0x01, 0x00, 0x0A, 0x01, 0x02, 0xF8, 0x39, 0x21, 0xF3, 0x00, 0x00, 0x13, 0x57, 0x99, 0x2E,
        0x02, 0x80, 0x00,
    ];
    let (_, req) = RegistrationRequest::decode_body(&body, DecodeContext::conservative()).unwrap();
    assert_eq!(req.optional_ies.len(), 2);
    assert_eq!(req.optional_ies[0].iei, 0x99);
    assert!(req.optional_ies[0].value.is_empty());
    assert_eq!(&req.optional_ies[0].raw[..], &[0x99]);
    assert_eq!(req.optional_ies[1].iei, 0x2E);
    assert_eq!(&req.optional_ies[1].value[..], &[0x80, 0x00]);
    let mut encoded = BytesMut::new();
    req.encode(&mut encoded, EncodeContext::default()).unwrap();
    assert_eq!(&encoded[..], &body);
}

#[test]
fn registration_request_truncated_mobile_identity_rejected() {
    let body: &[u8] = &[0x01, 0x00, 0x10, 0x01];
    assert!(RegistrationRequest::decode_body(body, DecodeContext::default()).is_err());
}

#[test]
fn registration_accept_full_round_trip() {
    let body: &[u8] = &[
        0x01, 0x01, // LV length=1, value=1 (3GPP access)
        0x77, 0x00, 0x0B, // 5G-GUTI TLV-E, length 11
        0xF2, 0x02, 0xF8, 0x39, 0x11, 0x01, 0x41, 0xDE, 0xAD, 0xBE, 0xEF,
    ];
    let bytes = plain_mm(0x42, body);

    let nas = NasMessage::decode(&bytes, DecodeContext::default())
        .unwrap()
        .1;
    let plain = match &nas {
        NasMessage::PlainMm(m) => m,
        other => panic!("expected plain MM, got {other:?}"),
    };

    let (_, acc) = RegistrationAccept::decode_body(&plain.body, DecodeContext::default()).unwrap();
    assert_eq!(acc.registration_result, RegistrationResult::Access3gpp);
    assert_eq!(acc.optional_ies.len(), 1);
    assert_eq!(acc.optional_ies[0].iei, 0x77);

    let mut encoded_body = BytesMut::new();
    acc.encode(&mut encoded_body, EncodeContext::default())
        .unwrap();
    assert_eq!(&encoded_body[..], body);

    let mut encoded_nas = BytesMut::new();
    nas.encode(&mut encoded_nas, EncodeContext::default())
        .unwrap();
    assert_eq!(&encoded_nas[..], bytes);
}

#[test]
fn imei_identity_bcd_round_trip() {
    // IMEI = 356412111238480 (15 digits).
    let content = &[0x3B, 0x65, 0x14, 0x12, 0x11, 0x32, 0x48, 0x08];
    let id = MobileIdentity::decode(content).unwrap();
    assert_eq!(id.identity_type, IdentityType::Imei);
    assert_eq!(unpack_imei(content).unwrap(), "356412111238480");

    let mut buf = BytesMut::new();
    id.encode(&mut buf).unwrap();
    assert_eq!(&buf[..], content);
}

#[test]
fn imeisv_identity_bcd_round_trip() {
    // IMEISV = 1234567890123456 (16 digits).
    let content = &[0x15, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54, 0xF6];
    let id = MobileIdentity::decode(content).unwrap();
    assert_eq!(id.identity_type, IdentityType::Imeisv);
    assert_eq!(unpack_imei(content).unwrap(), "1234567890123456");

    let mut buf = BytesMut::new();
    id.encode(&mut buf).unwrap();
    assert_eq!(&buf[..], content);
}
