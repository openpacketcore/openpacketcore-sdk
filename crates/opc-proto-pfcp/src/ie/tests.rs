#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used)]

//! Conformance tests for typed PFCP IEs.
//!
//! Fixtures are hand-authored from 3GPP TS 29.244 R18 with octet-level
//! comments citing section numbers. Every test asserts byte-exact
//! decode → encode round-trip, including unknown IEs.

use bytes::{BufMut, Bytes, BytesMut};
use opc_protocol::{DecodeContext, DecodeErrorCode, EncodeContext, UnknownIePolicy};

use crate::ie::{CauseValue, NodeIdType, TypedIe};

/// Helper: encode a typed IE to raw bytes.
fn encode_typed(ie: &TypedIe) -> Bytes {
    let mut buf = BytesMut::new();
    ie.encode(&mut buf, EncodeContext::default()).unwrap();
    buf.freeze()
}

/// Helper: decode a typed IE from raw bytes.
fn decode_typed(bytes: &[u8]) -> TypedIe {
    let (rest, ie) = TypedIe::decode(bytes, DecodeContext::default(), 0).unwrap();
    assert!(rest.is_empty(), "unexpected trailing bytes after IE decode");
    ie
}

/// Assert byte-exact round-trip for a typed IE.
fn assert_typed_roundtrip(bytes: &[u8]) {
    let decoded = decode_typed(bytes);
    let encoded = encode_typed(&decoded);
    assert_eq!(
        &encoded[..],
        bytes,
        "typed IE round-trip not byte-exact for {decoded:?}"
    );
}

// ---------------------------------------------------------------------------
// Cause (§8.2.1)
// ---------------------------------------------------------------------------

/// Cause IE, value = Request accepted (1) per TS 29.244 §8.2.1.
/// Octets: type=0x0013, length=0x0001, value=0x01.
#[test]
fn test_cause_request_accepted_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x13, // IE type 19 (Cause)
        0x00, 0x01, // length 1
        0x01, // Cause value: Request accepted (§8.2.1 Table 8.2.1-1)
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::Cause(c) => assert_eq!(c.value, CauseValue::RequestAccepted),
        other => panic!("expected Cause, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Cause IE with unknown value (0xFF) must round-trip byte-exact.
#[test]
fn test_cause_unknown_value_roundtrip() {
    let bytes: &[u8] = &[
        0x00, 0x13, // IE type 19
        0x00, 0x01, // length 1
        0xFF, // unknown cause value
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::Cause(c) => assert_eq!(c.value, CauseValue::Unknown(0xFF)),
        other => panic!("expected Cause, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

#[test]
fn test_cause_truncated_rejected() {
    let bytes: &[u8] = &[
        0x00, 0x13, // IE type 19
        0x00, 0x01, // length 1
              // value missing
    ];
    let result = TypedIe::decode(bytes, DecodeContext::default(), 0);
    assert!(result.is_err(), "truncated Cause must be rejected");
}

// ---------------------------------------------------------------------------
// Node ID (§8.2.38)
// ---------------------------------------------------------------------------

/// Node ID IE, IPv4 type (0) with address 192.0.2.1 per §8.2.38.
/// Octets: type=0x003C, length=0x0005, flags=0x00, addr=4 octets.
#[test]
fn test_node_id_ipv4_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x3C, // IE type 60 (Node ID)
        0x00, 0x05, // length 5 (1 flag + 4 addr)
        0x00, // Node ID type = IPv4 (§8.2.38)
        0xC0, 0x00, 0x02, 0x01, // 192.0.2.1
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::NodeId(n) => {
            assert_eq!(n.node_id_type, NodeIdType::Ipv4);
            assert_eq!(n.value, &[0xC0, 0x00, 0x02, 0x01]);
        }
        other => panic!("expected NodeId, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Node ID IE, IPv6 type (1) with loopback per §8.2.38.
#[test]
fn test_node_id_ipv6_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x3C, // IE type 60
        0x00, 0x11, // length 17 (1 flag + 16 addr)
        0x01, // Node ID type = IPv6
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // ::1
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::NodeId(n) => {
            assert_eq!(n.node_id_type, NodeIdType::Ipv6);
            assert_eq!(n.value.len(), 16);
        }
        other => panic!("expected NodeId, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

#[test]
fn test_node_id_ipv4_wrong_length_rejected() {
    let bytes: &[u8] = &[
        0x00, 0x3C, // IE type 60
        0x00, 0x04, // length 4 (should be 5 for IPv4)
        0x00, // IPv4 type
        0xC0, 0x00, 0x02, // only 3 octets
    ];
    let result = TypedIe::decode(bytes, DecodeContext::default(), 0);
    assert!(
        result.is_err(),
        "IPv4 Node ID with wrong length must be rejected"
    );
}

// ---------------------------------------------------------------------------
// F-SEID (§8.2.40)
// ---------------------------------------------------------------------------

/// F-SEID IE with V4=1, SEID=0x123456789ABCDEF0, IPv4=192.0.2.1 per §8.2.40.
/// Octet 5: flags = 0x02 (V4=1, V6=0).
/// Octets 6-13: SEID (8 octets).
/// Octets 14-17: IPv4 address.
#[test]
fn test_fseid_v4_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x39, // IE type 57 (F-SEID)
        0x00, 0x0D, // length 13 (1 + 8 + 4)
        0x02, // flags: V4=1, V6=0, spare bits 0 (§8.2.40)
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, // SEID
        0xC0, 0x00, 0x02, 0x01, // IPv4
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::FSeid(f) => {
            assert!(f.v4);
            assert!(!f.v6);
            assert_eq!(f.seid, 0x1234_5678_9ABC_DEF0);
            assert_eq!(f.ipv4, Some([0xC0, 0x00, 0x02, 0x01]));
            assert_eq!(f.ipv6, None);
        }
        other => panic!("expected FSeid, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// F-SEID IE with V4=1, V6=1, SEID, IPv4, IPv6 per §8.2.40.
/// IPv4 precedes IPv6 when both are present.
#[test]
fn test_fseid_v4v6_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x39, // IE type 57
        0x00, 0x1D, // length 29 (1 + 8 + 4 + 16)
        0x03, // flags: V4=1, V6=1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // SEID = 1
        0xC0, 0x00, 0x02, 0x01, // IPv4
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // IPv6 ::1
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::FSeid(f) => {
            assert!(f.v4);
            assert!(f.v6);
            assert_eq!(f.ipv4, Some([0xC0, 0x00, 0x02, 0x01]));
            assert_eq!(
                f.ipv6,
                Some([0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
            );
        }
        other => panic!("expected FSeid, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

#[test]
fn test_fseid_truncated_rejected() {
    let bytes: &[u8] = &[
        0x00, 0x39, // IE type 57
        0x00, 0x08, // length 8 (too short for even flags+SEID)
        0x02, // V4=1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // only 7 SEID octets
    ];
    let result = TypedIe::decode(bytes, DecodeContext::default(), 0);
    assert!(result.is_err(), "truncated F-SEID must be rejected");
}

// ---------------------------------------------------------------------------
// F-TEID (§8.2.5)
// ---------------------------------------------------------------------------

/// F-TEID IE with V4=1, TEID=0x12345678, IPv4=192.0.2.1 per §8.2.5.
/// Octet 5: flags = 0x01 (V4=1).
/// Octets 6-9: TEID.
/// Octets 10-13: IPv4.
#[test]
fn test_fteid_v4_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x15, // IE type 21 (F-TEID)
        0x00, 0x09, // length 9 (1 + 4 + 4)
        0x01, // flags: V4=1 (§8.2.5)
        0x12, 0x34, 0x56, 0x78, // TEID
        0xC0, 0x00, 0x02, 0x01, // IPv4
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::FTeid(f) => {
            assert!(f.v4);
            assert!(!f.v6);
            assert!(!f.ch);
            assert_eq!(f.teid, Some(0x1234_5678));
            assert_eq!(f.ipv4, Some([0xC0, 0x00, 0x02, 0x01]));
        }
        other => panic!("expected FTeid, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// F-TEID IE with CH=1, CHID=1, Choose ID=5 per §8.2.5.
/// When CH=1 and CHID=1, only flags and CHID are present.
#[test]
fn test_fteid_ch_chid_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x15, // IE type 21
        0x00, 0x02, // length 2
        0x0C, // flags: CH=1, CHID=1 (bits 3 and 4)
        0x05, // Choose ID
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::FTeid(f) => {
            assert!(f.ch);
            assert!(f.chid);
            assert_eq!(f.teid, None);
            assert_eq!(f.choose_id, Some(5));
        }
        other => panic!("expected FTeid, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

#[test]
fn test_fteid_truncated_teid_rejected() {
    let bytes: &[u8] = &[
        0x00, 0x15, // IE type 21
        0x00, 0x04, // length 4 (1 flag + 3 partial TEID)
        0x01, // V4=1, CH=0
        0x12, 0x34, 0x56, // partial TEID
    ];
    let result = TypedIe::decode(bytes, DecodeContext::default(), 0);
    assert!(result.is_err(), "truncated F-TEID TEID must be rejected");
}

// ---------------------------------------------------------------------------
// PDR ID (§8.2.36)
// ---------------------------------------------------------------------------

/// PDR ID IE, value = 0x1234 per §8.2.36 (2 octets).
#[test]
fn test_pdr_id_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x38, // IE type 56 (PDR ID)
        0x00, 0x02, // length 2
        0x12, 0x34, // PDR ID
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::PdrId(p) => assert_eq!(p.value, 0x1234),
        other => panic!("expected PdrId, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

// ---------------------------------------------------------------------------
// FAR ID (§8.2.50)
// ---------------------------------------------------------------------------

/// FAR ID IE, value = 0x12345678 per §8.2.50 (4 octets).
#[test]
fn test_far_id_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x6C, // IE type 108 (FAR ID)
        0x00, 0x04, // length 4
        0x12, 0x34, 0x56, 0x78, // FAR ID
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::FarId(f) => assert_eq!(f.value, 0x1234_5678),
        other => panic!("expected FarId, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

// ---------------------------------------------------------------------------
// QER ID (§8.2.37)
// ---------------------------------------------------------------------------

/// QER ID IE, value = 0x00000001 per §8.2.37 (4 octets).
#[test]
fn test_qer_id_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x6D, // IE type 109 (QER ID)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x01, // QER ID
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::QerId(q) => assert_eq!(q.value, 1),
        other => panic!("expected QerId, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

// ---------------------------------------------------------------------------
// URR ID (§8.2.71)
// ---------------------------------------------------------------------------

/// URR ID IE, value = 0x00000002 per §8.2.71 (4 octets).
#[test]
fn test_urr_id_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x51, // IE type 81 (URR ID)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x02, // URR ID
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::UrrId(u) => assert_eq!(u.value, 2),
        other => panic!("expected UrrId, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

// ---------------------------------------------------------------------------
// Precedence (§8.2.20)
// ---------------------------------------------------------------------------

/// Precedence IE, value = 0x0000000A per §8.2.20 (4 octets).
#[test]
fn test_precedence_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x1D, // IE type 29 (Precedence)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x0A, // precedence 10
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::Precedence(p) => assert_eq!(p.value, 10),
        other => panic!("expected Precedence, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

// ---------------------------------------------------------------------------
// Apply Action (§8.2.26)
// ---------------------------------------------------------------------------

/// Apply Action IE with DROP=1, FORW=1 per §8.2.26 (2 octets).
/// Octet 5: 0x03 (DROP | FORW).
/// Octet 6: 0x00 (spare).
#[test]
fn test_apply_action_drop_forw_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x2C, // IE type 44 (Apply Action)
        0x00, 0x02, // length 2
        0x03, // DROP=1, FORW=1 (§8.2.26)
        0x00, // spare
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::ApplyAction(a) => {
            assert!(a.drop);
            assert!(a.forward);
            assert!(!a.buffer);
            assert_eq!(a.spare, 0);
        }
        other => panic!("expected ApplyAction, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

// ---------------------------------------------------------------------------
// Source Interface (§8.2.2)
// ---------------------------------------------------------------------------

/// Source Interface IE, value = Access (0) per §8.2.2.
/// High nibble is spare (0).
#[test]
fn test_source_interface_access_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x14, // IE type 20 (Source Interface)
        0x00, 0x01, // length 1
        0x00, // Access (0), spare nibble 0 (§8.2.2)
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::SourceInterface(s) => {
            assert_eq!(s.value, 0);
            assert_eq!(s.spare, 0);
        }
        other => panic!("expected SourceInterface, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

// ---------------------------------------------------------------------------
// Destination Interface (§8.2.3)
// ---------------------------------------------------------------------------

/// Destination Interface IE, value = Core (1) per §8.2.3.
#[test]
fn test_destination_interface_core_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x2A, // IE type 42 (Destination Interface)
        0x00, 0x01, // length 1
        0x01, // Core (1), spare nibble 0 (§8.2.3)
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::DestinationInterface(d) => {
            assert_eq!(d.value, 1);
            assert_eq!(d.spare, 0);
        }
        other => panic!("expected DestinationInterface, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

// ---------------------------------------------------------------------------
// Network Instance (§8.2.4)
// ---------------------------------------------------------------------------

/// Network Instance IE with DNN "internet" per §8.2.4.
#[test]
fn test_network_instance_spec_bytes() {
    let dnn = b"internet";
    let mut bytes = BytesMut::from(&[0x00, 0x16][..]); // IE type 22
    bytes.put_u16(dnn.len() as u16); // length
    bytes.put_slice(dnn);
    let ie = decode_typed(&bytes);
    match ie {
        TypedIe::NetworkInstance(n) => assert_eq!(n.value, dnn.as_slice()),
        other => panic!("expected NetworkInstance, got {other:?}"),
    }
    assert_typed_roundtrip(&bytes);
}

// ---------------------------------------------------------------------------
// UE IP Address (§8.2.62)
// ---------------------------------------------------------------------------

/// UE IP Address IE with V4=1, IPv4=192.0.2.1 per §8.2.62.
/// Octet 5: flags = 0x01 (V4=1).
/// Octets 6-9: IPv4 address.
#[test]
fn test_ue_ip_address_v4_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x5D, // IE type 93 (UE IP Address)
        0x00, 0x05, // length 5
        0x01, // V4=1 (§8.2.62)
        0xC0, 0x00, 0x02, 0x01, // IPv4
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::UeIpAddress(u) => {
            assert!(u.v4);
            assert!(!u.v6);
            assert_eq!(u.ipv4, Some([0xC0, 0x00, 0x02, 0x01]));
        }
        other => panic!("expected UeIpAddress, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// UE IP Address IE with V4=1, IPv4D=1, prefix length 24 per §8.2.62.
#[test]
fn test_ue_ip_address_v4_prefix_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x5D, // IE type 93
        0x00, 0x06, // length 6
        0x09, // V4=1, IPv4D=1
        0xC0, 0x00, 0x02, 0x00, // IPv4
        0x18, // prefix length 24
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::UeIpAddress(u) => {
            assert!(u.v4);
            assert!(u.ipv4d);
            assert_eq!(u.ipv4_prefix_length, Some(24));
        }
        other => panic!("expected UeIpAddress, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

// ---------------------------------------------------------------------------
// Outer Header Removal (§8.2.57)
// ---------------------------------------------------------------------------

/// Outer Header Removal IE, description = GTP-U/UDP/IPv4 (0) per §8.2.57.
#[test]
fn test_outer_header_removal_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x5F, // IE type 95 (Outer Header Removal)
        0x00, 0x01, // length 1
        0x00, // description 0 (§8.2.57)
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::OuterHeaderRemoval(o) => assert_eq!(o.description, 0),
        other => panic!("expected OuterHeaderRemoval, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

// ---------------------------------------------------------------------------
// Recovery Time Stamp (§8.2.69)
// ---------------------------------------------------------------------------

/// Recovery Time Stamp IE, value = 0x66555A00 per §8.2.69 (4 octets).
#[test]
fn test_recovery_time_stamp_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x60, // IE type 96 (Recovery Time Stamp)
        0x00, 0x04, // length 4
        0x66, 0x55, 0x5A, 0x00, // seconds since epoch (§8.2.69)
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::RecoveryTimeStamp(r) => assert_eq!(r.seconds, 0x6655_5A00),
        other => panic!("expected RecoveryTimeStamp, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

// ---------------------------------------------------------------------------
// Outer Header Creation (§8.2.12)
// ---------------------------------------------------------------------------

/// Outer Header Creation IE, GTP-U/UDP/IPv4 per §8.2.56: octet 5 bit 1 set,
/// i.e. wire octets `01 00` (octet 5 is the high byte of the description).
/// TEID and IPv4 address follow; no UDP port for GTP-U encapsulations.
#[test]
fn test_outer_header_creation_gtpu_ipv4_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x54, // IE type 84 (Outer Header Creation)
        0x00, 0x0A, // length 10 (2 + 4 + 4)
        0x01, 0x00, // description: GTP-U/UDP/IPv4 (octet 5 bit 1, §8.2.56)
        0x12, 0x34, 0x56, 0x78, // TEID
        0xC0, 0x00, 0x02, 0x01, // IPv4 192.0.2.1
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::OuterHeaderCreation(o) => {
            assert_eq!(o.description, 0x0100);
            assert_eq!(o.teid, Some(0x1234_5678));
            assert_eq!(o.ipv4, Some([0xC0, 0x00, 0x02, 0x01]));
            assert_eq!(o.port, None, "GTP-U encapsulation carries no UDP port");
        }
        other => panic!("expected OuterHeaderCreation, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Outer Header Creation IE, UDP/IPv4 per §8.2.56: octet 5 bit 3 set
/// (wire octets `04 00`). A non-GTP UDP encapsulation carries an IPv4
/// address and a UDP port but NO TEID.
#[test]
fn test_outer_header_creation_udp_ipv4_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x54, // IE type 84 (Outer Header Creation)
        0x00, 0x08, // length 8 (2 + 4 + 2)
        0x04, 0x00, // description: UDP/IPv4 (octet 5 bit 3, §8.2.56)
        0xC0, 0x00, 0x02, 0x02, // IPv4 192.0.2.2
        0x08, 0x68, // UDP port 2152
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::OuterHeaderCreation(o) => {
            assert_eq!(o.description, 0x0400);
            assert_eq!(o.teid, None, "UDP/IPv4 encapsulation carries no TEID");
            assert_eq!(o.ipv4, Some([0xC0, 0x00, 0x02, 0x02]));
            assert_eq!(o.port, Some(2152));
        }
        other => panic!("expected OuterHeaderCreation, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Outer Header Creation IE with only octet 6 bit 1 set (N19 Indication,
/// wire octets `00 01`): no conditional fields are present at all.
#[test]
fn test_outer_header_creation_n19_indication_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x54, // IE type 84 (Outer Header Creation)
        0x00, 0x02, // length 2 (description only)
        0x00, 0x01, // description: N19 Indication (octet 6 bit 1, §8.2.56)
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::OuterHeaderCreation(o) => {
            assert_eq!(o.description, 0x0001);
            assert_eq!(o.teid, None);
            assert_eq!(o.ipv4, None);
            assert_eq!(o.port, None);
        }
        other => panic!("expected OuterHeaderCreation, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

// ---------------------------------------------------------------------------
// Unknown IE preservation
// ---------------------------------------------------------------------------

/// An unknown IE type (0xFFFF) must be preserved as `TypedIe::Raw` and
/// round-trip byte-exact.
#[test]
fn test_unknown_ie_raw_preservation() {
    let bytes: &[u8] = &[
        0xFF, 0xFF, // unknown IE type 65535
        0x00, 0x04, // length 4
        0xDE, 0xAD, 0xBE, 0xEF, // value
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::Raw(raw) => {
            assert_eq!(raw.ie_type, 0xFFFF);
            // Vendor IE: enterprise_id is extracted from first 2 octets of value area
            assert_eq!(raw.enterprise_id, 0xDEAD);
            assert_eq!(&raw.value[..], &[0xBE, 0xEF]);
        }
        other => panic!("expected Raw, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

#[test]
fn test_unknown_ie_reject_policy_fails_closed() {
    let bytes: &[u8] = &[
        0xFF, 0xFF, // unknown IE type 65535
        0x00, 0x04, // length 4
        0xDE, 0xAD, 0xBE, 0xEF, // value
    ];
    let ctx = DecodeContext {
        unknown_ie_policy: UnknownIePolicy::Reject,
        ..DecodeContext::default()
    };

    let err = TypedIe::decode(bytes, ctx, 0).unwrap_err();

    assert_eq!(err.code(), &DecodeErrorCode::UnknownCriticalIe);
}

/// A vendor-specific IE must be preserved as `TypedIe::Raw` with enterprise
/// ID intact.
#[test]
fn test_vendor_ie_raw_preservation() {
    let bytes: &[u8] = &[
        0x80, 0x01, // vendor IE type 0x8001
        0x00, 0x05, // length 5 = enterprise id (2) + value (3)
        0x00, 0x42, // enterprise id 0x42
        0x61, 0x62, 0x63, // value "abc"
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::Raw(raw) => {
            assert_eq!(raw.ie_type, 0x8001);
            assert_eq!(raw.enterprise_id, 0x42);
            assert_eq!(&raw.value[..], b"abc");
        }
        other => panic!("expected Raw, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

// ---------------------------------------------------------------------------
// Grouped IE depth limits
// ---------------------------------------------------------------------------

/// Create PDR containing a PDI containing a Source Interface — depth 2.
/// Must succeed with default max_depth (16).
#[test]
fn test_grouped_ie_nested_success() {
    // Build: Create PDR (grouped) -> PDI (grouped) -> Source Interface (simple)
    let source_interface: &[u8] = &[
        0x00, 0x14, // IE type 20 (Source Interface)
        0x00, 0x01, // length 1
        0x00, // Access
    ];
    let _pdi: &[u8] = &[
        0x00,
        0x02, // IE type 2 (PDI)
        0x00,
        (source_interface.len() as u8), // length = size of Source Interface IE
    ];
    // Actually build it properly with BytesMut
    let mut pdi_value = BytesMut::new();
    pdi_value.put_slice(source_interface);
    let mut pdi_ie = BytesMut::new();
    pdi_ie.put_u16(2); // PDI type
    pdi_ie.put_u16(pdi_value.len() as u16);
    pdi_ie.put_slice(&pdi_value);

    let mut create_pdr_value = BytesMut::new();
    create_pdr_value.put_slice(&pdi_ie);
    let mut create_pdr_ie = BytesMut::new();
    create_pdr_ie.put_u16(1); // Create PDR type
    create_pdr_ie.put_u16(create_pdr_value.len() as u16);
    create_pdr_ie.put_slice(&create_pdr_value);

    let bytes = create_pdr_ie.freeze();
    let ie = decode_typed(&bytes);
    match ie {
        TypedIe::CreatePdr(g) => {
            assert_eq!(g.members.len(), 1);
        }
        other => panic!("expected CreatePdr, got {other:?}"),
    }
    assert_typed_roundtrip(&bytes);
}

/// Grouped IE recursion must be rejected when max_depth is exceeded.
#[test]
fn test_grouped_ie_depth_exceeded() {
    // Build a deeply nested structure: Create PDR -> Create PDR -> ... -> Source Interface
    let source_interface: &[u8] = &[
        0x00, 0x14, // IE type 20 (Source Interface)
        0x00, 0x01, // length 1
        0x00, // Access
    ];

    let mut inner = BytesMut::from(source_interface);
    // Nest 10 levels deep
    for _ in 0..10 {
        let mut outer = BytesMut::new();
        outer.put_u16(1); // Create PDR type
        outer.put_u16(inner.len() as u16);
        outer.put_slice(&inner);
        inner = outer;
    }

    let ctx = DecodeContext {
        max_depth: 4,
        ..DecodeContext::default()
    };
    let result = TypedIe::decode(&inner, ctx, 0);
    assert!(
        result.is_err(),
        "deeply nested grouped IE must exceed max_depth"
    );
}

#[test]
fn test_grouped_ie_member_count_exceeded() {
    let source_interface: &[u8] = &[
        0x00, 0x14, // IE type 20 (Source Interface)
        0x00, 0x01, // length 1
        0x00, // Access
    ];

    let mut grouped_value = BytesMut::new();
    grouped_value.extend_from_slice(source_interface);
    grouped_value.extend_from_slice(source_interface);

    let mut grouped = BytesMut::new();
    grouped.put_u16(1); // Create PDR grouped IE
    grouped.put_u16(grouped_value.len() as u16);
    grouped.extend_from_slice(&grouped_value);

    let ctx = DecodeContext {
        max_ies: 1,
        ..DecodeContext::default()
    };
    let err = match TypedIe::decode(&grouped, ctx, 0) {
        Ok(_) => panic!("member count must exceed max_ies"),
        Err(err) => err,
    };
    assert_eq!(err.code(), &DecodeErrorCode::IeCountExceeded);
}

// ---------------------------------------------------------------------------
// Negative tests: truncation, overflow
// ---------------------------------------------------------------------------

#[test]
fn test_far_id_truncated_rejected() {
    let bytes: &[u8] = &[
        0x00, 0x6C, // IE type 108 (FAR ID)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, // only 3 octets
    ];
    let result = TypedIe::decode(bytes, DecodeContext::default(), 0);
    assert!(result.is_err(), "truncated FAR ID must be rejected");
}

#[test]
fn test_precedence_truncated_rejected() {
    let bytes: &[u8] = &[
        0x00, 0x1D, // IE type 29 (Precedence)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, // only 3 octets
    ];
    let result = TypedIe::decode(bytes, DecodeContext::default(), 0);
    assert!(result.is_err(), "truncated Precedence must be rejected");
}

#[test]
fn test_recovery_timestamp_truncated_rejected() {
    let bytes: &[u8] = &[
        0x00, 0x60, // IE type 96 (Recovery Time Stamp)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, // only 3 octets
    ];
    let result = TypedIe::decode(bytes, DecodeContext::default(), 0);
    assert!(
        result.is_err(),
        "truncated Recovery Time Stamp must be rejected"
    );
}

#[test]
fn test_outer_header_creation_truncated_teid_rejected() {
    let bytes: &[u8] = &[
        0x00, 0x54, // IE type 84 (Outer Header Creation)
        0x00, 0x05, // length 5 (2 desc + 3 partial TEID)
        0x01, 0x00, // description GTP-U/UDP/IPv4 (octet 5 bit 1)
        0x12, 0x34, 0x56, // partial TEID
    ];
    let result = TypedIe::decode(bytes, DecodeContext::default(), 0);
    assert!(
        result.is_err(),
        "truncated Outer Header Creation TEID must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Grouped IE encode/decode round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_created_pdr_roundtrip() {
    // Created PDR containing PDR ID and F-TEID
    let pdr_id: &[u8] = &[
        0x00, 0x38, // IE type 56 (PDR ID)
        0x00, 0x02, // length 2
        0x00, 0x01, // PDR ID = 1
    ];
    let fteid: &[u8] = &[
        0x00, 0x15, // IE type 21 (F-TEID)
        0x00, 0x09, // length 9
        0x01, // V4=1
        0x00, 0x00, 0x00, 0x01, // TEID = 1
        0xC0, 0x00, 0x02, 0x01, // IPv4
    ];
    let mut value = BytesMut::new();
    value.put_slice(pdr_id);
    value.put_slice(fteid);

    let mut raw = BytesMut::new();
    raw.put_u16(8); // Created PDR type
    raw.put_u16(value.len() as u16);
    raw.put_slice(&value);

    let bytes = raw.freeze();
    let ie = decode_typed(&bytes);
    match ie {
        TypedIe::CreatedPdr(g) => assert_eq!(g.members.len(), 2),
        other => panic!("expected CreatedPdr, got {other:?}"),
    }
    assert_typed_roundtrip(&bytes);
}

#[test]
fn test_create_far_roundtrip() {
    // Create FAR containing FAR ID and Apply Action
    let far_id: &[u8] = &[
        0x00, 0x6C, // IE type 108 (FAR ID)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x01, // FAR ID = 1
    ];
    let apply_action: &[u8] = &[
        0x00, 0x2C, // IE type 44 (Apply Action)
        0x00, 0x02, // length 2
        0x02, // FORW=1
        0x00, // spare
    ];
    let mut value = BytesMut::new();
    value.put_slice(far_id);
    value.put_slice(apply_action);

    let mut raw = BytesMut::new();
    raw.put_u16(3); // Create FAR type
    raw.put_u16(value.len() as u16);
    raw.put_slice(&value);

    let bytes = raw.freeze();
    let ie = decode_typed(&bytes);
    match ie {
        TypedIe::CreateFar(g) => assert_eq!(g.members.len(), 2),
        other => panic!("expected CreateFar, got {other:?}"),
    }
    assert_typed_roundtrip(&bytes);
}

#[test]
fn test_forwarding_parameters_roundtrip() {
    // Forwarding Parameters containing Destination Interface and Outer Header Creation
    let dst_intf: &[u8] = &[
        0x00, 0x2A, // IE type 42 (Destination Interface)
        0x00, 0x01, // length 1
        0x01, // Core
    ];
    let ohc: &[u8] = &[
        0x00, 0x54, // IE type 84 (Outer Header Creation)
        0x00, 0x0A, // length 10
        0x01, 0x00, // GTP-U/UDP/IPv4 (octet 5 bit 1, §8.2.56)
        0x00, 0x00, 0x00, 0x01, // TEID
        0xC0, 0x00, 0x02, 0x01, // IPv4
    ];
    let mut value = BytesMut::new();
    value.put_slice(dst_intf);
    value.put_slice(ohc);

    let mut raw = BytesMut::new();
    raw.put_u16(4); // Forwarding Parameters type
    raw.put_u16(value.len() as u16);
    raw.put_slice(&value);

    let bytes = raw.freeze();
    let ie = decode_typed(&bytes);
    match ie {
        TypedIe::ForwardingParameters(g) => assert_eq!(g.members.len(), 2),
        other => panic!("expected ForwardingParameters, got {other:?}"),
    }
    assert_typed_roundtrip(&bytes);
}

#[test]
fn test_create_qer_roundtrip() {
    // Create QER containing QER ID
    let qer_id: &[u8] = &[
        0x00, 0x6D, // IE type 109 (QER ID)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x01, // QER ID = 1
    ];
    let mut value = BytesMut::new();
    value.put_slice(qer_id);

    let mut raw = BytesMut::new();
    raw.put_u16(7); // Create QER type
    raw.put_u16(value.len() as u16);
    raw.put_slice(&value);

    let bytes = raw.freeze();
    let ie = decode_typed(&bytes);
    match ie {
        TypedIe::CreateQer(g) => assert_eq!(g.members.len(), 1),
        other => panic!("expected CreateQer, got {other:?}"),
    }
    assert_typed_roundtrip(&bytes);
}

#[test]
fn test_create_urr_roundtrip() {
    // Create URR containing URR ID
    let urr_id: &[u8] = &[
        0x00, 0x51, // IE type 81 (URR ID)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x02, // URR ID = 2
    ];
    let mut value = BytesMut::new();
    value.put_slice(urr_id);

    let mut raw = BytesMut::new();
    raw.put_u16(6); // Create URR type
    raw.put_u16(value.len() as u16);
    raw.put_slice(&value);

    let bytes = raw.freeze();
    let ie = decode_typed(&bytes);
    match ie {
        TypedIe::CreateUrr(g) => assert_eq!(g.members.len(), 1),
        other => panic!("expected CreateUrr, got {other:?}"),
    }
    assert_typed_roundtrip(&bytes);
}

// ---------------------------------------------------------------------------
// QoS IEs (§8.2.89, §8.2.7, §8.2.8, §8.2.9)
// ---------------------------------------------------------------------------

/// QoS Flow Identifier IE, value = 5 per §8.2.89.
/// Octets: type=0x007C, length=0x0001, value=0x05 (spare bits 0).
#[test]
fn test_qfi_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x7C, // IE type 124 (QFI)
        0x00, 0x01, // length 1
        0x05, // QFI = 5, spare bits 0 (§8.2.89)
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::Qfi(q) => assert_eq!(q.value, 5),
        other => panic!("expected Qfi, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Gate Status IE with both gates open per §8.2.7.
/// Octets: type=0x0019, length=0x0001, value=0x00.
#[test]
fn test_gate_status_open_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x19, // IE type 25 (Gate Status)
        0x00, 0x01, // length 1
        0x00, // UL gate open (0), DL gate open (0) (§8.2.7)
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::GateStatus(g) => {
            assert_eq!(g.ul, crate::ie::Gate::Open);
            assert_eq!(g.dl, crate::ie::Gate::Open);
        }
        other => panic!("expected GateStatus, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Gate Status IE with both gates closed per §8.2.7.
/// UL gate = 1 (closed), DL gate = 1 (closed) => value 0x05.
#[test]
fn test_gate_status_closed_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x19, // IE type 25 (Gate Status)
        0x00, 0x01, // length 1
        0x05, // UL closed (1), DL closed (1)
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::GateStatus(g) => {
            assert_eq!(g.ul, crate::ie::Gate::Closed);
            assert_eq!(g.dl, crate::ie::Gate::Closed);
        }
        other => panic!("expected GateStatus, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Maximum Bit Rate IE per §8.2.8.
/// UL MBR = 0x0000000001 (1 kbps), DL MBR = 0x0000000002 (2 kbps).
#[test]
fn test_mbr_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x1A, // IE type 26 (MBR)
        0x00, 0x0A, // length 10
        // UL MBR (5 octets)
        0x00, 0x00, 0x00, 0x00, 0x01, // DL MBR (5 octets)
        0x00, 0x00, 0x00, 0x00, 0x02,
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::Mbr(m) => {
            assert_eq!(m.ul_kbps, 1);
            assert_eq!(m.dl_kbps, 2);
        }
        other => panic!("expected Mbr, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Guaranteed Bit Rate IE per §8.2.9.
/// UL GBR = 0x00000003E8 (1000 kbps), DL GBR = 0x00000007D0 (2000 kbps).
#[test]
fn test_gbr_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x1B, // IE type 27 (GBR)
        0x00, 0x0A, // length 10
        // UL GBR (5 octets)
        0x00, 0x00, 0x00, 0x03, 0xE8, // DL GBR (5 octets)
        0x00, 0x00, 0x00, 0x07, 0xD0,
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::Gbr(g) => {
            assert_eq!(g.ul_kbps, 1000);
            assert_eq!(g.dl_kbps, 2000);
        }
        other => panic!("expected Gbr, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

#[test]
fn test_mbr_truncated_rejected() {
    let bytes: &[u8] = &[
        0x00, 0x1A, // IE type 26 (MBR)
        0x00, 0x0A, // length 10
        // only 9 octets
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    ];
    let result = TypedIe::decode(bytes, DecodeContext::default(), 0);
    assert!(result.is_err(), "truncated MBR must be rejected");
}

#[test]
fn test_gbr_truncated_rejected() {
    let bytes: &[u8] = &[
        0x00, 0x1B, // IE type 27 (GBR)
        0x00, 0x0A, // length 10
        // only 9 octets
        0x00, 0x00, 0x00, 0x03, 0xE8, 0x00, 0x00, 0x00, 0x07,
    ];
    let result = TypedIe::decode(bytes, DecodeContext::default(), 0);
    assert!(result.is_err(), "truncated GBR must be rejected");
}

/// Create QER containing QER ID, Gate Status, MBR, GBR and QFI per §7.5.2.5.
#[test]
fn test_create_qer_with_qos_members_roundtrip() {
    let qer_id: &[u8] = &[
        0x00, 0x6D, // IE type 109 (QER ID)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x01, // QER ID = 1
    ];
    let gate_status: &[u8] = &[
        0x00, 0x19, // IE type 25 (Gate Status)
        0x00, 0x01, // length 1
        0x00, // both gates open
    ];
    let mbr: &[u8] = &[
        0x00, 0x1A, // IE type 26 (MBR)
        0x00, 0x0A, // length 10
        0x00, 0x00, 0x00, 0x00, 0x01, // UL 1 kbps
        0x00, 0x00, 0x00, 0x00, 0x02, // DL 2 kbps
    ];
    let gbr: &[u8] = &[
        0x00, 0x1B, // IE type 27 (GBR)
        0x00, 0x0A, // length 10
        0x00, 0x00, 0x00, 0x00, 0x01, // UL 1 kbps
        0x00, 0x00, 0x00, 0x00, 0x02, // DL 2 kbps
    ];
    let qfi: &[u8] = &[
        0x00, 0x7C, // IE type 124 (QFI)
        0x00, 0x01, // length 1
        0x05, // QFI = 5
    ];

    let mut value = BytesMut::new();
    value.put_slice(qer_id);
    value.put_slice(gate_status);
    value.put_slice(mbr);
    value.put_slice(gbr);
    value.put_slice(qfi);

    let mut raw = BytesMut::new();
    raw.put_u16(7); // Create QER type
    raw.put_u16(value.len() as u16);
    raw.put_slice(&value);

    let bytes = raw.freeze();
    let ie = decode_typed(&bytes);
    match ie {
        TypedIe::CreateQer(g) => {
            assert_eq!(g.members.len(), 5);
        }
        other => panic!("expected CreateQer, got {other:?}"),
    }
    assert_typed_roundtrip(&bytes);
}

/// Update QER containing QER ID and a modified MBR per §7.5.4.5.
#[test]
fn test_update_qer_roundtrip() {
    let qer_id: &[u8] = &[
        0x00, 0x6D, // IE type 109 (QER ID)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x01, // QER ID = 1
    ];
    let mbr: &[u8] = &[
        0x00, 0x1A, // IE type 26 (MBR)
        0x00, 0x0A, // length 10
        0x00, 0x00, 0x00, 0x00, 0x0A, // UL 10 kbps
        0x00, 0x00, 0x00, 0x00, 0x14, // DL 20 kbps
    ];

    let mut value = BytesMut::new();
    value.put_slice(qer_id);
    value.put_slice(mbr);

    let mut raw = BytesMut::new();
    raw.put_u16(14); // Update QER type
    raw.put_u16(value.len() as u16);
    raw.put_slice(&value);

    let bytes = raw.freeze();
    let ie = decode_typed(&bytes);
    match ie {
        TypedIe::UpdateQer(g) => {
            assert_eq!(g.members.len(), 2);
        }
        other => panic!("expected UpdateQer, got {other:?}"),
    }
    assert_typed_roundtrip(&bytes);
}

// ---------------------------------------------------------------------------
// Session Modification lifecycle IEs (§7.5.4)
// ---------------------------------------------------------------------------

/// Update PDR grouped IE (type 9) containing a PDR ID per TS 29.244 §7.5.4.2.
#[test]
fn test_update_pdr_spec_bytes() {
    let pdr_id: &[u8] = &[
        0x00, 0x38, // IE type 56 (PDR ID)
        0x00, 0x02, // length 2
        0x00, 0x01, // PDR ID = 1
    ];
    let mut value = BytesMut::new();
    value.put_slice(pdr_id);

    let mut raw = BytesMut::new();
    raw.put_u16(9); // Update PDR type (TS 29.244 Table 8.1.2-1)
    raw.put_u16(value.len() as u16);
    raw.put_slice(&value);

    let bytes = raw.freeze();
    let ie = decode_typed(&bytes);
    match ie {
        TypedIe::UpdatePdr(g) => {
            assert_eq!(g.members.len(), 1);
        }
        other => panic!("expected UpdatePdr, got {other:?}"),
    }
    assert_typed_roundtrip(&bytes);
}

/// Update FAR grouped IE (type 10) containing FAR ID and Update Forwarding
/// Parameters per TS 29.244 §7.5.4.3.
#[test]
fn test_update_far_spec_bytes() {
    let far_id: &[u8] = &[
        0x00, 0x6C, // IE type 108 (FAR ID)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x01, // FAR ID = 1
    ];
    let dst_intf: &[u8] = &[
        0x00, 0x2A, // IE type 42 (Destination Interface)
        0x00, 0x01, // length 1
        0x01, // Core (1)
    ];
    let mut update_fp_value = BytesMut::new();
    update_fp_value.put_slice(dst_intf);
    let update_fp: &[u8] = &[
        0x00,
        0x0B, // IE type 11 (Update Forwarding Parameters)
        0x00,
        (update_fp_value.len() as u8), // length
    ];
    let mut update_fp_ie = BytesMut::new();
    update_fp_ie.put_slice(update_fp);
    update_fp_ie.put_slice(&update_fp_value);

    let mut value = BytesMut::new();
    value.put_slice(far_id);
    value.put_slice(&update_fp_ie);

    let mut raw = BytesMut::new();
    raw.put_u16(10); // Update FAR type (TS 29.244 Table 8.1.2-1)
    raw.put_u16(value.len() as u16);
    raw.put_slice(&value);

    let bytes = raw.freeze();
    let ie = decode_typed(&bytes);
    match ie {
        TypedIe::UpdateFar(g) => {
            assert_eq!(g.members.len(), 2);
        }
        other => panic!("expected UpdateFar, got {other:?}"),
    }
    assert_typed_roundtrip(&bytes);
}

/// Update URR grouped IE (type 13) containing a URR ID per TS 29.244 §7.5.4.4.
#[test]
fn test_update_urr_spec_bytes() {
    let urr_id: &[u8] = &[
        0x00, 0x51, // IE type 81 (URR ID)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x02, // URR ID = 2
    ];
    let mut value = BytesMut::new();
    value.put_slice(urr_id);

    let mut raw = BytesMut::new();
    raw.put_u16(13); // Update URR type (TS 29.244 Table 8.1.2-1)
    raw.put_u16(value.len() as u16);
    raw.put_slice(&value);

    let bytes = raw.freeze();
    let ie = decode_typed(&bytes);
    match ie {
        TypedIe::UpdateUrr(g) => {
            assert_eq!(g.members.len(), 1);
        }
        other => panic!("expected UpdateUrr, got {other:?}"),
    }
    assert_typed_roundtrip(&bytes);
}

/// Remove PDR IE (type 15) carrying PDR ID 0x1234 per TS 29.244 §7.5.4.6.
#[test]
fn test_remove_pdr_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x0F, // IE type 15 (Remove PDR)
        0x00, 0x02, // length 2
        0x12, 0x34, // PDR ID
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::RemovePdr(r) => assert_eq!(r.pdr_id.value, 0x1234),
        other => panic!("expected RemovePdr, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Remove FAR IE (type 16) carrying FAR ID 0x12345678 per TS 29.244 §7.5.4.7.
#[test]
fn test_remove_far_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x10, // IE type 16 (Remove FAR)
        0x00, 0x04, // length 4
        0x12, 0x34, 0x56, 0x78, // FAR ID
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::RemoveFar(r) => assert_eq!(r.far_id.value, 0x1234_5678),
        other => panic!("expected RemoveFar, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Remove URR IE (type 17) carrying URR ID 2 per TS 29.244 §7.5.4.8.
#[test]
fn test_remove_urr_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x11, // IE type 17 (Remove URR)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x02, // URR ID
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::RemoveUrr(r) => assert_eq!(r.urr_id.value, 2),
        other => panic!("expected RemoveUrr, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Remove QER IE (type 18) carrying QER ID 1 per TS 29.244 §7.5.4.9.
#[test]
fn test_remove_qer_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x12, // IE type 18 (Remove QER)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x01, // QER ID
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::RemoveQer(r) => assert_eq!(r.qer_id.value, 1),
        other => panic!("expected RemoveQer, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

#[test]
fn test_remove_pdr_truncated_rejected() {
    let bytes: &[u8] = &[
        0x00, 0x0F, // IE type 15 (Remove PDR)
        0x00, 0x02, // length 2
        0x00, // only 1 octet
    ];
    let result = TypedIe::decode(bytes, DecodeContext::default(), 0);
    assert!(result.is_err(), "truncated Remove PDR must be rejected");
}

// ---------------------------------------------------------------------------
// Usage reporting / Session Report IEs
// ---------------------------------------------------------------------------

/// Report Type IE (type 39) with Usage Report flag set per TS 29.244 §8.2.21.
#[test]
fn test_report_type_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x27, // IE type 39 (Report Type)
        0x00, 0x01, // length 1
        0x02, // Usage Report bit (bit 2)
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::ReportType(r) => {
            assert!(r.usage_report);
            assert!(!r.downlink_data_report);
        }
        other => panic!("expected ReportType, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Measurement Method IE (type 62) with Duration + Volume per TS 29.244 §8.2.40.
#[test]
fn test_measurement_method_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x3E, // IE type 62 (Measurement Method)
        0x00, 0x01, // length 1
        0x03, // DURAT (bit 1) + VOLUM (bit 2)
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::MeasurementMethod(m) => {
            assert!(m.duration);
            assert!(m.volume);
            assert!(!m.event);
        }
        other => panic!("expected MeasurementMethod, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Reporting Triggers IE (type 37) with Volume + Time Threshold per TS 29.244 §8.2.19.
#[test]
fn test_reporting_triggers_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x25, // IE type 37 (Reporting Triggers)
        0x00, 0x03, // length 3
        0x06, // VOLTH (bit 2) + TIMTH (bit 3)
        0x00, // no octet 6 flags
        0x00, // no octet 7 flags, spare bits zero
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::ReportingTriggers(r) => {
            assert!(r.volume_threshold);
            assert!(r.time_threshold);
            assert!(!r.periodic_reporting);
        }
        other => panic!("expected ReportingTriggers, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Volume Threshold IE (type 31) with Total Volume present per TS 29.244 §8.2.13.
#[test]
fn test_volume_threshold_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x1F, // IE type 31 (Volume Threshold)
        0x00, 0x09, // length 9 (1 flag octet + 8 octets total volume)
        0x01, // TOVOL flag (bit 1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, // total volume 10
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::VolumeThreshold(v) => {
            assert_eq!(v.total_volume, Some(10));
            assert_eq!(v.uplink_volume, None);
            assert_eq!(v.downlink_volume, None);
        }
        other => panic!("expected VolumeThreshold, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Time Threshold IE (type 32) with 60 seconds per TS 29.244 §8.2.14.
#[test]
fn test_time_threshold_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x20, // IE type 32 (Time Threshold)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x3C, // 60 seconds
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::TimeThreshold(t) => assert_eq!(t.seconds, 60),
        other => panic!("expected TimeThreshold, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Volume Quota IE (type 73) with Total Volume present per TS 29.244 §8.2.50.
#[test]
fn test_volume_quota_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x49, // IE type 73 (Volume Quota)
        0x00, 0x09, // length 9
        0x01, // TOVOL flag (bit 1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, // total volume 100
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::VolumeQuota(v) => {
            assert_eq!(v.total_volume, Some(100));
            assert_eq!(v.uplink_volume, None);
            assert_eq!(v.downlink_volume, None);
        }
        other => panic!("expected VolumeQuota, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Time Quota IE (type 74) with 300 seconds per TS 29.244 §8.2.51.
#[test]
fn test_time_quota_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x4A, // IE type 74 (Time Quota)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x01, 0x2C, // 300 seconds
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::TimeQuota(t) => assert_eq!(t.seconds, 300),
        other => panic!("expected TimeQuota, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Monitoring Time IE (type 33) per TS 29.244 §8.2.15.
#[test]
fn test_monitoring_time_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x21, // IE type 33 (Monitoring Time)
        0x00, 0x04, // length 4
        0x66, 0x55, 0x5A, 0x00, // NTP short-format seconds
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::MonitoringTime(m) => assert_eq!(m.seconds, 0x6655_5A00),
        other => panic!("expected MonitoringTime, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Offending IE (type 40) reporting IE type 56 per TS 29.244 §8.2.22.
#[test]
fn test_offending_ie_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x28, // IE type 40 (Offending IE)
        0x00, 0x02, // length 2
        0x00, 0x38, // offending IE type 56 (PDR ID)
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::OffendingIe(o) => assert_eq!(o.ie_type, 56),
        other => panic!("expected OffendingIe, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Usage Report Trigger IE (type 63) for Volume Threshold per TS 29.244 §8.2.41.
#[test]
fn test_usage_report_trigger_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x3F, // IE type 63 (Usage Report Trigger)
        0x00, 0x03, // length 3
        0x02, // VOLTH (bit 2)
        0x00, 0x00,
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::UsageReportTrigger(u) => {
            assert!(u.volume_threshold);
            assert!(!u.periodic_reporting);
        }
        other => panic!("expected UsageReportTrigger, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Volume Measurement IE (type 66) with Total Volume per TS 29.244 §8.2.44.
#[test]
fn test_volume_measurement_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x42, // IE type 66 (Volume Measurement)
        0x00, 0x09, // length 9
        0x01, // TOVOL flag (bit 1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, // total volume 32 octets
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::VolumeMeasurement(v) => {
            assert_eq!(v.total_volume, Some(32));
            assert_eq!(v.total_packets, None);
        }
        other => panic!("expected VolumeMeasurement, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Duration Measurement IE (type 67) with 120 seconds per TS 29.244 §8.2.45.
#[test]
fn test_duration_measurement_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x43, // IE type 67 (Duration Measurement)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x78, // 120 seconds
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::DurationMeasurement(d) => assert_eq!(d.seconds, 120),
        other => panic!("expected DurationMeasurement, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// UR-SEQN IE (type 104) with sequence 7 per TS 29.244 §8.2.71.
#[test]
fn test_ur_seqn_spec_bytes() {
    let bytes: &[u8] = &[
        0x00, 0x68, // IE type 104 (UR-SEQN)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x07, // UR-SEQN = 7
    ];
    let ie = decode_typed(bytes);
    match ie {
        TypedIe::UrSeqn(u) => assert_eq!(u.value, 7),
        other => panic!("expected UrSeqn, got {other:?}"),
    }
    assert_typed_roundtrip(bytes);
}

/// Usage Report grouped IE (type 80) within Session Report Request per TS 29.244 §7.5.8.3.
#[test]
fn test_usage_report_spec_bytes() {
    let urr_id: &[u8] = &[
        0x00, 0x51, // IE type 81 (URR ID)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x02, // URR ID = 2
    ];
    let ur_seqn: &[u8] = &[
        0x00, 0x68, // IE type 104 (UR-SEQN)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x01, // UR-SEQN = 1
    ];
    let trigger: &[u8] = &[
        0x00, 0x3F, // IE type 63 (Usage Report Trigger)
        0x00, 0x03, // length 3
        0x02, 0x00, 0x00, // Volume Threshold trigger
    ];
    let volume: &[u8] = &[
        0x00, 0x42, // IE type 66 (Volume Measurement)
        0x00, 0x09, // length 9
        0x01, // TOVOL
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, // total volume 128
    ];
    let duration: &[u8] = &[
        0x00, 0x43, // IE type 67 (Duration Measurement)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, 0x3C, // 60 seconds
    ];

    let mut value = BytesMut::new();
    value.put_slice(urr_id);
    value.put_slice(ur_seqn);
    value.put_slice(trigger);
    value.put_slice(volume);
    value.put_slice(duration);

    let mut raw = BytesMut::new();
    raw.put_u16(80); // Usage Report (Session Report Request)
    raw.put_u16(value.len() as u16);
    raw.put_slice(&value);

    let bytes = raw.freeze();
    let ie = decode_typed(&bytes);
    match ie {
        TypedIe::UsageReport(g) => {
            assert_eq!(g.members.len(), 5);
        }
        other => panic!("expected UsageReport, got {other:?}"),
    }
    assert_typed_roundtrip(&bytes);
}

#[test]
fn test_volume_threshold_truncated_rejected() {
    let bytes: &[u8] = &[
        0x00, 0x1F, // IE type 31 (Volume Threshold)
        0x00, 0x09, // length 9
        0x01, // TOVOL flag set
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // only 7 octets of total volume
    ];
    let result = TypedIe::decode(bytes, DecodeContext::default(), 0);
    assert!(
        result.is_err(),
        "truncated Volume Threshold must be rejected"
    );
}

#[test]
fn test_duration_measurement_truncated_rejected() {
    let bytes: &[u8] = &[
        0x00, 0x43, // IE type 67 (Duration Measurement)
        0x00, 0x04, // length 4
        0x00, 0x00, 0x00, // only 3 octets
    ];
    let result = TypedIe::decode(bytes, DecodeContext::default(), 0);
    assert!(
        result.is_err(),
        "truncated Duration Measurement must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Typed-to-raw helpers: encode_value and InformationElement::from_typed
// ---------------------------------------------------------------------------

#[cfg(test)]
mod from_typed_tests {
    use bytes::{Bytes, BytesMut};
    use opc_protocol::EncodeContext;

    use crate::ie::{
        ApplyAction, Cause, CauseValue, CreateFar, CreatePdr, CreateQer, CreateUrr, CreatedPdr,
        DestinationInterface, DurationMeasurement, FSeid, FTeid, FarId, Gate, GateStatus, Gbr, Mbr,
        MeasurementMethod, MonitoringTime, NetworkInstance, NodeId, NodeIdType, OffendingIe,
        OuterHeaderCreation, OuterHeaderRemoval, Pdi, PdrId, Precedence, QerId, Qfi,
        RecoveryTimeStamp, RemoveFar, RemovePdr, RemoveQer, RemoveUrr, ReportType,
        ReportingTriggers, SourceInterface, TimeQuota, TimeThreshold, TypedIe, UeIpAddress,
        UpdateFar, UpdateForwardingParameters, UpdatePdr, UpdateQer, UpdateUrr, UrSeqn, UrrId,
        UsageReport, UsageReportTrigger, VolumeMeasurement, VolumeQuota, VolumeThreshold,
    };
    use crate::InformationElement;

    fn all_typed_ie_variants() -> Vec<TypedIe> {
        vec![
            TypedIe::CreatePdr(CreatePdr {
                members: vec![
                    TypedIe::PdrId(PdrId { value: 1 }),
                    TypedIe::Precedence(Precedence { value: 1 }),
                ],
            }),
            TypedIe::Pdi(Pdi {
                members: vec![
                    TypedIe::SourceInterface(SourceInterface { value: 0, spare: 0 }),
                    TypedIe::NetworkInstance(NetworkInstance {
                        value: b"internet".to_vec(),
                    }),
                ],
            }),
            TypedIe::CreateFar(CreateFar {
                members: vec![
                    TypedIe::FarId(FarId { value: 1 }),
                    TypedIe::ApplyAction(ApplyAction {
                        drop: false,
                        forward: true,
                        buffer: false,
                        notify_cp: false,
                        duplicate: false,
                        ip_masquerade: false,
                        ip_masquerade_decap: false,
                        dfrt: false,
                        edrt: false,
                        bdpn: false,
                        ddpn: false,
                        spare: 0,
                    }),
                ],
            }),
            TypedIe::ForwardingParameters(crate::ie::ForwardingParameters {
                members: vec![TypedIe::DestinationInterface(DestinationInterface {
                    value: 0,
                    spare: 0,
                })],
            }),
            TypedIe::CreateUrr(CreateUrr {
                members: vec![TypedIe::UrrId(UrrId { value: 1 })],
            }),
            TypedIe::CreateQer(CreateQer {
                members: vec![
                    TypedIe::QerId(QerId { value: 1 }),
                    TypedIe::GateStatus(GateStatus {
                        ul: Gate::Open,
                        dl: Gate::Open,
                    }),
                    TypedIe::Mbr(Mbr {
                        ul_kbps: 1,
                        dl_kbps: 1,
                    }),
                    TypedIe::Gbr(Gbr {
                        ul_kbps: 1,
                        dl_kbps: 1,
                    }),
                    TypedIe::Qfi(Qfi { value: 1 }),
                ],
            }),
            TypedIe::UpdateQer(UpdateQer {
                members: vec![TypedIe::QerId(QerId { value: 1 })],
            }),
            TypedIe::UpdatePdr(UpdatePdr {
                members: vec![TypedIe::PdrId(PdrId { value: 1 })],
            }),
            TypedIe::UpdateFar(UpdateFar {
                members: vec![TypedIe::FarId(FarId { value: 1 })],
            }),
            TypedIe::UpdateForwardingParameters(UpdateForwardingParameters {
                members: vec![TypedIe::DestinationInterface(DestinationInterface {
                    value: 0,
                    spare: 0,
                })],
            }),
            TypedIe::UpdateUrr(UpdateUrr {
                members: vec![TypedIe::UrrId(UrrId { value: 1 })],
            }),
            TypedIe::CreatedPdr(CreatedPdr {
                members: vec![
                    TypedIe::PdrId(PdrId { value: 1 }),
                    TypedIe::FTeid(FTeid {
                        v4: true,
                        v6: false,
                        ch: false,
                        chid: false,
                        choose_id: None,
                        teid: Some(1),
                        ipv4: Some([1, 2, 3, 4]),
                        ipv6: None,
                    }),
                ],
            }),
            TypedIe::UsageReport(UsageReport {
                members: vec![
                    TypedIe::UrrId(UrrId { value: 1 }),
                    TypedIe::UrSeqn(UrSeqn { value: 1 }),
                    TypedIe::UsageReportTrigger(UsageReportTrigger {
                        periodic_reporting: true,
                        volume_threshold: false,
                        time_threshold: false,
                        quota_holding_time: false,
                        start_of_traffic: false,
                        stop_of_traffic: false,
                        dropped_dl_traffic_threshold: false,
                        immediate_report: false,
                        volume_quota: false,
                        time_quota: false,
                        linked_usage_reporting: false,
                        termination_report: false,
                        monitoring_time: false,
                        envelope_closure: false,
                        mac_addresses_reporting: false,
                        event_threshold: false,
                        event_quota: false,
                        termination_by_up_report: false,
                        ip_multicast_join_leave: false,
                        quota_validity_time: false,
                        end_marker_reception_report: false,
                        user_plane_inactivity_timer: false,
                    }),
                ],
            }),
            TypedIe::Cause(Cause {
                value: CauseValue::RequestAccepted,
            }),
            TypedIe::SourceInterface(SourceInterface { value: 0, spare: 0 }),
            TypedIe::FTeid(FTeid {
                v4: true,
                v6: false,
                ch: false,
                chid: false,
                choose_id: None,
                teid: Some(1),
                ipv4: Some([1, 2, 3, 4]),
                ipv6: None,
            }),
            TypedIe::NetworkInstance(NetworkInstance {
                value: b"internet".to_vec(),
            }),
            TypedIe::GateStatus(GateStatus {
                ul: Gate::Open,
                dl: Gate::Open,
            }),
            TypedIe::Mbr(Mbr {
                ul_kbps: 1,
                dl_kbps: 1,
            }),
            TypedIe::Gbr(Gbr {
                ul_kbps: 1,
                dl_kbps: 1,
            }),
            TypedIe::Precedence(Precedence { value: 1 }),
            TypedIe::ApplyAction(ApplyAction {
                drop: false,
                forward: true,
                buffer: false,
                notify_cp: false,
                duplicate: false,
                ip_masquerade: false,
                ip_masquerade_decap: false,
                dfrt: false,
                edrt: false,
                bdpn: false,
                ddpn: false,
                spare: 0,
            }),
            TypedIe::DestinationInterface(DestinationInterface { value: 0, spare: 0 }),
            TypedIe::PdrId(PdrId { value: 1 }),
            TypedIe::FSeid(FSeid {
                v4: true,
                v6: false,
                seid: 1,
                ipv4: Some([127, 0, 0, 1]),
                ipv6: None,
            }),
            TypedIe::NodeId(NodeId {
                node_id_type: NodeIdType::Fqdn,
                value: b"ref".to_vec(),
            }),
            TypedIe::UrrId(UrrId { value: 1 }),
            TypedIe::UeIpAddress(UeIpAddress {
                v4: true,
                v6: false,
                sd: false,
                ipv4d: false,
                ipv6d: false,
                chv4: false,
                chv6: false,
                ch: false,
                ipv4: Some([1, 2, 3, 4]),
                ipv6: None,
                ipv4_prefix_length: None,
                ipv6_prefix_length: None,
            }),
            TypedIe::OuterHeaderRemoval(OuterHeaderRemoval { description: 0 }),
            TypedIe::RecoveryTimeStamp(RecoveryTimeStamp { seconds: 0 }),
            TypedIe::OuterHeaderCreation(OuterHeaderCreation {
                description: 0,
                teid: None,
                ipv4: None,
                ipv6: None,
                port: None,
                c_tag: None,
                s_tag: None,
            }),
            TypedIe::FarId(FarId { value: 1 }),
            TypedIe::QerId(QerId { value: 1 }),
            TypedIe::Qfi(Qfi { value: 1 }),
            TypedIe::RemovePdr(RemovePdr {
                pdr_id: PdrId { value: 1 },
            }),
            TypedIe::RemoveFar(RemoveFar {
                far_id: FarId { value: 1 },
            }),
            TypedIe::RemoveUrr(RemoveUrr {
                urr_id: UrrId { value: 1 },
            }),
            TypedIe::RemoveQer(RemoveQer {
                qer_id: QerId { value: 1 },
            }),
            TypedIe::ReportType(ReportType {
                downlink_data_report: false,
                usage_report: true,
                error_indication_report: false,
                user_plane_inactivity_report: false,
                tsc_management_info_report: false,
                session_report: false,
                up_initiated_session_request: false,
            }),
            TypedIe::MeasurementMethod(MeasurementMethod {
                duration: true,
                volume: true,
                event: false,
            }),
            TypedIe::ReportingTriggers(ReportingTriggers {
                periodic_reporting: false,
                volume_threshold: true,
                time_threshold: true,
                quota_holding_time: false,
                start_of_traffic: false,
                stop_of_traffic: false,
                dropped_dl_traffic_threshold: false,
                linked_usage_reporting: false,
                volume_quota: false,
                time_quota: false,
                envelope_closure: false,
                mac_addresses_reporting: false,
                event_threshold: false,
                event_quota: false,
                ip_multicast_join_leave: false,
                quota_validity_time: false,
                report_end_marker_reception: false,
                user_plane_inactivity_timer: false,
            }),
            TypedIe::VolumeThreshold(VolumeThreshold {
                total_volume: Some(1),
                uplink_volume: None,
                downlink_volume: None,
            }),
            TypedIe::TimeThreshold(TimeThreshold { seconds: 1 }),
            TypedIe::VolumeQuota(VolumeQuota {
                total_volume: Some(1),
                uplink_volume: None,
                downlink_volume: None,
            }),
            TypedIe::TimeQuota(TimeQuota { seconds: 1 }),
            TypedIe::MonitoringTime(MonitoringTime { seconds: 1 }),
            TypedIe::OffendingIe(OffendingIe { ie_type: 56 }),
            TypedIe::UsageReportTrigger(UsageReportTrigger {
                periodic_reporting: true,
                volume_threshold: false,
                time_threshold: false,
                quota_holding_time: false,
                start_of_traffic: false,
                stop_of_traffic: false,
                dropped_dl_traffic_threshold: false,
                immediate_report: false,
                volume_quota: false,
                time_quota: false,
                linked_usage_reporting: false,
                termination_report: false,
                monitoring_time: false,
                envelope_closure: false,
                mac_addresses_reporting: false,
                event_threshold: false,
                event_quota: false,
                termination_by_up_report: false,
                ip_multicast_join_leave: false,
                quota_validity_time: false,
                end_marker_reception_report: false,
                user_plane_inactivity_timer: false,
            }),
            TypedIe::VolumeMeasurement(VolumeMeasurement {
                total_volume: Some(1),
                uplink_volume: None,
                downlink_volume: None,
                total_packets: None,
                uplink_packets: None,
                downlink_packets: None,
            }),
            TypedIe::DurationMeasurement(DurationMeasurement { seconds: 1 }),
            TypedIe::UrSeqn(UrSeqn { value: 1 }),
            TypedIe::Raw(InformationElement {
                ie_type: 0x8001,
                enterprise_id: 1,
                value: Bytes::from_static(b"vendor"),
            }),
        ]
    }

    #[test]
    fn information_element_from_typed_matches_typed_encode_for_every_variant(
    ) -> Result<(), crate::EncodeError> {
        for typed in all_typed_ie_variants() {
            let mut direct = BytesMut::new();
            typed.encode(&mut direct, EncodeContext::default())?;

            let raw = InformationElement::from_typed(&typed)?;
            let mut via_raw = BytesMut::new();
            raw.encode(&mut via_raw)?;

            assert_eq!(
                direct.freeze().as_ref(),
                via_raw.freeze().as_ref(),
                "from_typed did not match typed encode for {typed:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn raw_variant_encode_value_returns_raw_value() -> Result<(), crate::EncodeError> {
        let raw = InformationElement {
            ie_type: 0x8001,
            enterprise_id: 1,
            value: Bytes::from_static(b"vendor"),
        };
        let typed = TypedIe::Raw(raw.clone());
        assert_eq!(typed.encode_value()?, raw.value);
        Ok(())
    }

    #[test]
    fn from_typed_propagates_encode_errors() {
        // A vendor-specific raw IE whose value is too large to encode triggers
        // length_overflow when the grouped IE tries to encode its member.
        let oversized = InformationElement {
            ie_type: 0x8001,
            enterprise_id: 1,
            value: Bytes::from(vec![0u8; (u16::MAX as usize) + 1]),
        };
        let grouped = TypedIe::CreatePdr(CreatePdr {
            members: vec![TypedIe::Raw(oversized)],
        });
        assert!(grouped.encode_value().is_err());
        assert!(InformationElement::from_typed(&grouped).is_err());
    }
}
