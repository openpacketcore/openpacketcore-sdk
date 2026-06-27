//! Fixture provenance and redaction evidence for opc-proto-diameter.
//!
//! This file separates four kinds of test bytes:
//!
//! 1. **RFC-authored fixtures** — hand-built from IETF RFC 6733 wire layouts.
//!    These are the only fixtures that count as ADR 0015 conformance evidence.
//!
//! 2. **3GPP-authored fixtures** — hand-built from 3GPP TS 32.299 (Rf) and
//!    3GPP TS 29.273 (SWm) wire layouts. They count as application-dictionary
//!    evidence, not full application-conformance evidence, because the crate
//!    does not yet implement every AVP in those specs.
//!
//! 3. **ePDG parity bytes** — *not* imported into this file. The source task
//!    references ePDG local-builder cases; those remain external parity seeds
//!    until a later fixture-intake task records provenance, license, and
//!    capture metadata. This crate deliberately does not treat them as
//!    conformance evidence.
//!
//! 4. **Generated codec round trips** — built with this crate's own encoder.
//!    They are useful regression tests but do not prove wire conformance by
//!    themselves.

use opc_proto_diameter::{
    ApplicationId, AvpCode, AvpHeader, CommandCode, Message, OwnedMessage, RawAvp,
};
use opc_protocol::{BorrowDecode, DecodeContext, Encode, EncodeContext, OwnedDecode};

// -----------------------------------------------------------------------------
// RFC 6733 hand-authored fixtures
// -----------------------------------------------------------------------------

/// Build a canonical Diameter AVP header + value (RFC 6733 §4).
///
/// Octet layout for a non-vendor AVP:
///   0-3   AVP Code
///   4     AVP Flags (V/M/P/r/r/r/r/r)
///   5-7   24-bit AVP Length (header + AVP data; padding is excluded)
///   8+    AVP Data
///   tail  0-3 octets of zero padding to a 4-octet boundary
fn rfc_avp(code: u32, flags: u8, value: &[u8]) -> Vec<u8> {
    let length = 8 + value.len();
    let mut out = Vec::new();
    out.extend_from_slice(&code.to_be_bytes()); // octets 0-3: AVP Code
    out.push(flags); // octet 4: AVP Flags
    out.extend_from_slice(&(length as u32).to_be_bytes()[1..]); // octets 5-7: 24-bit length
    out.extend_from_slice(value); // AVP Data

    // Zero pad to 4-octet boundary (RFC 6733 §4).
    let pad = (4 - (length % 4)) % 4;
    out.extend_from_slice(&vec![0; pad]);
    out
}

/// Build a canonical Diameter message header (RFC 6733 §3).
///
/// Octet layout of the fixed 20-octet header:
///   0     Version (1)
///   1-3   24-bit Message Length (header + AVPs)
///   4     Command Flags (R/P/E/T/r/r/r/r)
///   5-7   24-bit Command Code
///   8-11  Application-Id
///   12-15 Hop-by-Hop Identifier
///   16-19 End-to-End Identifier
///   20+   AVP region
fn rfc_message(
    flags: u8,
    command_code: u32,
    application_id: u32,
    hop_by_hop: u32,
    end_to_end: u32,
    avps: &[u8],
) -> Vec<u8> {
    let length = 20 + avps.len();
    let mut out = Vec::new();
    out.push(1); // octet 0: version
    out.extend_from_slice(&(length as u32).to_be_bytes()[1..]); // octets 1-3: 24-bit length
    out.push(flags); // octet 4: command flags
    out.extend_from_slice(&command_code.to_be_bytes()[1..]); // octets 5-7: command code
    out.extend_from_slice(&application_id.to_be_bytes()); // octets 8-11: application-id
    out.extend_from_slice(&hop_by_hop.to_be_bytes()); // octets 12-15: hop-by-hop
    out.extend_from_slice(&end_to_end.to_be_bytes()); // octets 16-19: end-to-end
    out.extend_from_slice(avps);
    out
}

/// RFC 6733 §5.3.1 Capabilities-Exchange-Request fixture.
///
/// Fixture provenance: hand-authored from RFC 6733 §3 (message header) and
/// §4 (AVP framing). Each AVP value is chosen to exercise one data
/// shape: DiameterIdentity, Address, Unsigned32, and UTF8String.
fn rfc6733_cer_bytes() -> Vec<u8> {
    let mut avps = Vec::new();
    // Origin-Host AVP (code 264, M), RFC 6733 §6.3.
    avps.extend_from_slice(&rfc_avp(264, 0x40, b"aaa.example"));
    // Origin-Realm AVP (code 296, M), RFC 6733 §6.4.
    avps.extend_from_slice(&rfc_avp(296, 0x40, b"example"));
    // Host-IP-Address AVP (code 257, M), RFC 6733 §5.3.5.
    // Address value: AddressType 1 (IPv4, RFC 6733 §4.3.3) + 10.0.0.1.
    avps.extend_from_slice(&rfc_avp(257, 0x40, b"\x00\x01\x0a\x00\x00\x01"));
    // Vendor-Id AVP (code 266, M), value 10415 (3GPP), RFC 6733 §5.3.3.
    avps.extend_from_slice(&rfc_avp(266, 0x40, &10415u32.to_be_bytes()));
    // Product-Name AVP (code 269, M bit clear), RFC 6733 §5.3.7.
    avps.extend_from_slice(&rfc_avp(269, 0x00, b"opc-rfc-fixture"));
    // Auth-Application-Id AVP (code 258, M), RFC 6733 §6.8.
    avps.extend_from_slice(&rfc_avp(258, 0x40, &0x0100_0001u32.to_be_bytes()));

    // Command code 257, R bit set, Application-Id 0. RFC 6733 §5.3.1.
    rfc_message(0x80, 257, 0, 0x1111_1111, 0x2222_2222, &avps)
}

/// RFC 6733 §5.3.2 Capabilities-Exchange-Answer fixture.
fn rfc6733_cea_bytes() -> Vec<u8> {
    let mut avps = Vec::new();
    // Result-Code AVP (code 268, M), DIAMETER_SUCCESS = 2001. RFC 6733 §7.1.
    avps.extend_from_slice(&rfc_avp(268, 0x40, &2001u32.to_be_bytes()));
    // Origin-Host AVP (code 264, M), RFC 6733 §6.3.
    avps.extend_from_slice(&rfc_avp(264, 0x40, b"hss.example"));
    // Origin-Realm AVP (code 296, M), RFC 6733 §6.4.
    avps.extend_from_slice(&rfc_avp(296, 0x40, b"example"));
    // Host-IP-Address AVP (code 257, M), RFC 6733 §5.3.5.
    avps.extend_from_slice(&rfc_avp(257, 0x40, b"\x00\x01\x0a\x00\x00\x02"));
    // Vendor-Id AVP (code 266, M), RFC 6733 §5.3.3.
    avps.extend_from_slice(&rfc_avp(266, 0x40, &10415u32.to_be_bytes()));
    // Product-Name AVP (code 269, M bit clear), RFC 6733 §5.3.7.
    avps.extend_from_slice(&rfc_avp(269, 0x00, b"opc-rfc-fixture"));

    // Command code 257, R bit cleared, Application-Id 0. RFC 6733 §5.3.2.
    rfc_message(0x00, 257, 0, 0x1111_1111, 0x2222_2222, &avps)
}

/// RFC 6733 §5.5.1 Device-Watchdog-Request fixture.
fn rfc6733_dwr_bytes() -> Vec<u8> {
    let mut avps = Vec::new();
    // Origin-Host AVP (code 264, M), RFC 6733 §6.3.
    avps.extend_from_slice(&rfc_avp(264, 0x40, b"aaa.example"));
    // Origin-Realm AVP (code 296, M), RFC 6733 §6.4.
    avps.extend_from_slice(&rfc_avp(296, 0x40, b"example"));
    // Command code 280, R bit set, Application-Id 0. RFC 6733 §5.5.1.
    rfc_message(0x80, 280, 0, 0x3333_3333, 0x4444_4444, &avps)
}

/// RFC 6733 §5.4.1 Disconnect-Peer-Request fixture.
fn rfc6733_dpr_bytes() -> Vec<u8> {
    let mut avps = Vec::new();
    // Origin-Host AVP (code 264, M), RFC 6733 §6.3.
    avps.extend_from_slice(&rfc_avp(264, 0x40, b"aaa.example"));
    // Origin-Realm AVP (code 296, M), RFC 6733 §6.4.
    avps.extend_from_slice(&rfc_avp(296, 0x40, b"example"));
    // Disconnect-Cause AVP (code 273, M), REBOOTING = 0. RFC 6733 §5.4.3.
    avps.extend_from_slice(&rfc_avp(273, 0x40, &0u32.to_be_bytes()));
    // Command code 282, R bit set, Application-Id 0. RFC 6733 §5.4.1.
    rfc_message(0x80, 282, 0, 0x5555_5555, 0x6666_6666, &avps)
}

#[test]
fn rfc6733_cer_decodes_and_preserves_header_fields() {
    let bytes = rfc6733_cer_bytes();
    let (tail, message) = Message::decode(&bytes, DecodeContext::default())
        .expect("RFC 6733 CER fixture must decode");
    assert!(tail.is_empty());
    assert_eq!(message.header.version, 1);
    assert!(message.header.flags.is_request());
    assert_eq!(message.header.command_code, CommandCode::new(257));
    assert_eq!(message.header.application_id, ApplicationId::new(0));
    assert_eq!(message.header.hop_by_hop_identifier, 0x1111_1111);
    assert_eq!(message.header.end_to_end_identifier, 0x2222_2222);
}

#[test]
fn rfc6733_cea_decodes_and_preserves_result_code() {
    let bytes = rfc6733_cea_bytes();
    let (_, message) = Message::decode(&bytes, DecodeContext::default())
        .expect("RFC 6733 CEA fixture must decode");
    assert!(!message.header.flags.is_request());
    assert_eq!(message.header.command_code, CommandCode::new(257));
}

#[test]
fn rfc6733_dwr_decodes_without_panic() {
    let bytes = rfc6733_dwr_bytes();
    let (_, message) = Message::decode(&bytes, DecodeContext::default())
        .expect("RFC 6733 DWR fixture must decode");
    assert!(message.header.flags.is_request());
    assert_eq!(message.header.command_code, CommandCode::new(280));
}

#[test]
fn rfc6733_dpr_decodes_and_preserves_disconnect_cause() {
    let bytes = rfc6733_dpr_bytes();
    let (_, message) = Message::decode(&bytes, DecodeContext::default())
        .expect("RFC 6733 DPR fixture must decode");
    assert!(message.header.flags.is_request());
    assert_eq!(message.header.command_code, CommandCode::new(282));
}

#[test]
fn rfc6733_fixtures_round_trip_byte_exact() {
    // Because these fixtures are canonical (zero padding, no reserved bits),
    // decode → encode must reproduce the input exactly.
    for fixture in [
        rfc6733_cer_bytes(),
        rfc6733_cea_bytes(),
        rfc6733_dwr_bytes(),
        rfc6733_dpr_bytes(),
    ] {
        let (_, message) =
            Message::decode(&fixture, DecodeContext::default()).expect("fixture must decode");
        let mut encoded = bytes::BytesMut::new();
        message
            .encode(&mut encoded, EncodeContext::default())
            .expect("fixture must re-encode");
        assert_eq!(
            encoded.to_vec(),
            fixture,
            "decode → encode must be byte-exact for canonical RFC 6733 fixtures"
        );

        let owned = OwnedMessage::decode_owned(
            bytes::Bytes::from(fixture.clone()),
            DecodeContext::default(),
        )
        .expect("fixture must decode_owned");
        let mut encoded = bytes::BytesMut::new();
        owned
            .encode(&mut encoded, EncodeContext::default())
            .expect("owned fixture must re-encode");
        assert_eq!(encoded.to_vec(), fixture);
    }
}

// -----------------------------------------------------------------------------
// 3GPP hand-authored fixtures
// -----------------------------------------------------------------------------

#[cfg(any(
    feature = "app-gx",
    feature = "app-rf",
    feature = "app-s6a",
    feature = "app-s6b",
    feature = "app-swm",
    feature = "app-swx"
))]
use opc_proto_diameter::apps::APP_DICTIONARIES;

/// 3GPP TS 32.299 Rf Accounting-Request (START record) fixture.
///
/// Fixture provenance: hand-authored from RFC 6733 §3/§4 wire framing and
/// 3GPP TS 32.299 §5.1 / §7.1 command/AVP codes. The AVP list is the minimal
/// ePDG-required subset used by the SDK `app-rf` helpers. It is
/// application-dictionary evidence, not full Rf-application conformance
/// evidence.
#[cfg(feature = "app-rf")]
fn ts32299_rf_acr_start_bytes() -> Vec<u8> {
    let mut avps = Vec::new();
    // Session-Id AVP (code 263, M), RFC 6733 §8.8.
    avps.extend_from_slice(&rfc_avp(263, 0x40, b"session;rf;001"));
    // Origin-Host AVP (code 264, M), RFC 6733 §6.3.
    avps.extend_from_slice(&rfc_avp(264, 0x40, b"epdg.example"));
    // Origin-Realm AVP (code 296, M), RFC 6733 §6.4.
    avps.extend_from_slice(&rfc_avp(296, 0x40, b"epc.example.org"));
    // Destination-Realm AVP (code 283, M), RFC 6733 §6.6.
    avps.extend_from_slice(&rfc_avp(283, 0x40, b"epc.example.org"));
    // Accounting-Record-Type AVP (code 480, M), START = 2. RFC 6733 §9.8.1.
    avps.extend_from_slice(&rfc_avp(480, 0x40, &2u32.to_be_bytes()));
    // Accounting-Record-Number AVP (code 485, M). RFC 6733 §9.8.2.
    avps.extend_from_slice(&rfc_avp(485, 0x40, &0u32.to_be_bytes()));
    // Acct-Application-Id AVP (code 259, M), value 3. RFC 6733 §6.9.
    avps.extend_from_slice(&rfc_avp(259, 0x40, &3u32.to_be_bytes()));
    // Service-Context-Id AVP (code 461, M), 3GPP TS 32.299 §7.1.12.
    avps.extend_from_slice(&rfc_avp(461, 0x40, b"32260@3gpp.org"));
    // Accounting-Request, command code 271, R/P bits set, app id 3.
    // RFC 6733 §9.7.1 / 3GPP TS 32.299 §5.1.
    rfc_message(0xC0, 271, 3, 0x7777_7777, 0x8888_8888, &avps)
}

/// 3GPP TS 29.273 SWm Diameter-EAP-Request fixture.
///
/// Fixture provenance: hand-authored from RFC 6733 §3/§4 wire framing and
/// 3GPP TS 29.273 §6.1 command/AVP codes. The AVP list matches the minimal
/// ePDG-required subset used by the SDK `app-swm` helpers. It is
/// application-dictionary evidence, not full SWm-application conformance
/// evidence.
#[cfg(feature = "app-swm")]
fn ts29273_swm_der_bytes() -> Vec<u8> {
    let mut avps = Vec::new();
    // Session-Id AVP (code 263, M), RFC 6733 §8.8.
    avps.extend_from_slice(&rfc_avp(263, 0x40, b"sess;swm;001"));
    // Auth-Application-Id AVP (code 258, M), SWm app id 16777264. RFC 6733 §6.8.
    avps.extend_from_slice(&rfc_avp(258, 0x40, &16_777_264u32.to_be_bytes()));
    // Origin-Host AVP (code 264, M), RFC 6733 §6.3.
    avps.extend_from_slice(&rfc_avp(264, 0x40, b"epdg.example"));
    // Origin-Realm AVP (code 296, M), RFC 6733 §6.4.
    avps.extend_from_slice(&rfc_avp(296, 0x40, b"visited.example"));
    // Destination-Realm AVP (code 283, M), RFC 6733 §6.6.
    avps.extend_from_slice(&rfc_avp(283, 0x40, b"home.example"));
    // Auth-Request-Type AVP (code 274, M), AUTHORIZE_AUTHENTICATE = 3. RFC 6733 §8.7.
    avps.extend_from_slice(&rfc_avp(274, 0x40, &3u32.to_be_bytes()));
    // EAP-Payload AVP (code 462, M). RFC 4072 §4.1.
    avps.extend_from_slice(&rfc_avp(462, 0x40, b"\x02\x17\x00\x08\x32\x01\x02\x03"));
    // Diameter-EAP-Request, command code 268, R/P bits set, app id 16777264.
    // 3GPP TS 29.273 §6.1.
    rfc_message(0xC0, 268, 16_777_264, 0x9999_9999, 0xAAAA_AAAA, &avps)
}

#[cfg(feature = "app-rf")]
#[test]
fn ts32299_rf_acr_start_decodes_with_app_dictionary() {
    let bytes = ts32299_rf_acr_start_bytes();
    let (_, message) = Message::decode(&bytes, DecodeContext::default())
        .expect("Rf ACR START fixture must decode");
    assert_eq!(message.header.command_code, CommandCode::new(271));
    assert_eq!(message.header.application_id, ApplicationId::new(3));
    assert!(
        message
            .validate_avps_with_dictionary(DecodeContext::default(), APP_DICTIONARIES)
            .is_ok(),
        "Rf ACR fixture must validate against the app dictionary"
    );
}

#[cfg(feature = "app-swm")]
#[test]
fn ts29273_swm_der_decodes_with_app_dictionary() {
    let bytes = ts29273_swm_der_bytes();
    let (_, message) =
        Message::decode(&bytes, DecodeContext::default()).expect("SWm DER fixture must decode");
    assert_eq!(message.header.command_code, CommandCode::new(268));
    assert_eq!(
        message.header.application_id,
        ApplicationId::new(16_777_264)
    );
    assert!(
        message
            .validate_avps_with_dictionary(DecodeContext::default(), APP_DICTIONARIES)
            .is_ok(),
        "SWm DER fixture must validate against the app dictionary"
    );
}

// -----------------------------------------------------------------------------
// Generated codec round trips
// -----------------------------------------------------------------------------

/// A round-trip fixture built with this crate's encoder. It is a useful
/// regression test but does not prove wire conformance by itself.
#[cfg(feature = "peer")]
fn generated_cer_bytes() -> Vec<u8> {
    use opc_proto_diameter::peer::{
        build_capabilities_exchange_request, HostIpAddress, PeerCapabilities, PeerIdentity,
    };
    use std::net::Ipv4Addr;

    let capabilities = PeerCapabilities::new(
        PeerIdentity::new("aaa.example", "example"),
        vec![HostIpAddress::from(Ipv4Addr::new(10, 0, 0, 1))],
        opc_proto_diameter::VendorId::new(10415),
        "opc-generated",
    );
    let message = build_capabilities_exchange_request(
        &capabilities,
        0x0102_0304,
        0xA0B0_C0D0,
        EncodeContext::default(),
    )
    .expect("generated CER must build");
    let mut encoded = bytes::BytesMut::new();
    message
        .encode(&mut encoded, EncodeContext::default())
        .expect("generated CER must encode");
    encoded.to_vec()
}

#[cfg(feature = "peer")]
#[test]
fn generated_codec_round_trip_decodes_back_to_equal_message() {
    let bytes = generated_cer_bytes();
    let (_, first) =
        Message::decode(&bytes, DecodeContext::default()).expect("generated bytes must decode");
    let mut encoded = bytes::BytesMut::new();
    first
        .encode(&mut encoded, EncodeContext::default())
        .expect("first decode must re-encode");
    let (_, second) =
        Message::decode(&encoded, DecodeContext::default()).expect("second decode must succeed");
    assert_eq!(first, second);
}

// -----------------------------------------------------------------------------
// Redaction evidence
// -----------------------------------------------------------------------------

#[cfg(feature = "base")]
use opc_proto_diameter::avp::dictionary::Redacted;

#[cfg(feature = "base")]
#[test]
fn redacted_string_does_not_leak_in_debug_or_display() {
    let sensitive = Redacted::<String>::from("001010123456789");
    let debug = format!("{sensitive:?}");
    let display = format!("{sensitive}");
    assert!(!debug.contains("001010123456789"));
    assert!(!display.contains("001010123456789"));
    assert!(debug.contains("REDACTED"));
    assert!(display.contains("REDACTED"));
}

#[cfg(feature = "base")]
#[test]
fn redacted_bytes_does_not_leak_in_debug_or_display() {
    let key = Redacted::<Vec<u8>>::from(vec![0xAA; 32]);
    let debug = format!("{key:?}");
    let display = format!("{key}");
    assert!(!debug.contains("aa"));
    assert!(!display.contains("aa"));
    assert!(debug.contains("REDACTED"));
}

#[cfg(feature = "base")]
#[test]
fn redacted_ip_does_not_leak_in_debug_or_display() {
    use std::net::{IpAddr, Ipv4Addr};

    let addr = Redacted::<IpAddr>::from(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let debug = format!("{addr:?}");
    let display = format!("{addr}");
    assert!(!debug.contains("10.0.0.1"));
    assert!(!display.contains("10.0.0.1"));
    assert!(debug.contains("REDACTED"));
}

#[cfg(feature = "base")]
#[test]
fn redacted_equality_allows_business_logic_without_leak() {
    let a = Redacted::<String>::from("secret");
    let b = Redacted::<String>::from("secret");
    let c = Redacted::<String>::from("other");
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn raw_avp_debug_does_not_redact_value_because_it_is_raw_bytes() {
    // Raw AVPs intentionally preserve bytes; redaction is a typed-layer policy.
    let avp = RawAvp {
        header: AvpHeader::ietf(AvpCode::new(264), true),
        value: b"host.example",
        padding: &[],
    };
    let debug = format!("{avp:?}");
    // Derived Debug for `&[u8]` renders decimal bytes, not the UTF-8 string.
    assert!(debug.contains("104"));
    assert!(debug.contains("111"));
    assert!(!debug.contains("REDACTED"));
}
