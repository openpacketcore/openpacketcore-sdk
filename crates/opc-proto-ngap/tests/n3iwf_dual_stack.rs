//! TS 38.413 9.3.2.4 and TS 38.414 5.3: a 160-bit transport address
//! contains IPv4 in its first 32 bits, followed by the 128-bit IPv6 address.
//! These synthetic APER literals do not use the SDK encoder as their oracle.

use opc_proto_ngap::n3iwf::{
    modify_fields::UplinkModifications,
    modify_results::ModifyResponseTransfer,
    resource_fields::{DownlinkTransport, UplinkTransport, UplinkTransportList},
    resource_results::SetupResponseTransfer,
};
use opc_protocol::{DecodeContext, EncodeContext};

const ADDRESS: [u8; 20] = [
    192, 0, 2, 1, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

fn endpoint(prefix: &[u8], teid: u32) -> Vec<u8> {
    let mut wire = prefix.to_vec();
    wire.extend_from_slice(&ADDRESS);
    wire.extend_from_slice(&teid.to_be_bytes());
    wire
}

#[test]
fn dual_stack_uplink_preserves_the_complete_address() {
    // Four root flags, eight-bit (160 - 1) length, then aligned octets.
    let wire = endpoint(&[0x09, 0xf0], 0x01020304);
    let value = UplinkTransport::decode(&wire, DecodeContext::default()).unwrap();
    assert_eq!(value.teid(), 0x01020304);
    assert_eq!(
        value.encode(EncodeContext::default()).unwrap().as_bytes(),
        wire
    );
}

#[test]
fn dual_stack_downlink_preserves_the_complete_address() {
    let wire = endpoint(&[0x09, 0xf0], 0x04030201);
    let value = DownlinkTransport::decode(&wire, DecodeContext::default()).unwrap();
    assert_eq!(value.teid(), 0x04030201);
    assert_eq!(
        value.encode(EncodeContext::default()).unwrap().as_bytes(),
        wire
    );
}

#[test]
fn dual_stack_additional_uplink_keeps_parent_alignment() {
    // Two count bits and two item flags precede the transport information.
    let wire = endpoint(&[0x00, 0x9f], 0x01020304);
    let value = UplinkTransportList::decode(&wire, DecodeContext::default()).unwrap();
    assert_eq!(value.values().len(), 1);
    assert_eq!(value.values()[0].teid(), 0x01020304);
    assert_eq!(
        value.encode(EncodeContext::default()).unwrap().as_bytes(),
        wire
    );
}

#[test]
fn dual_stack_modify_pairs_keep_both_directions() {
    let mut wire = endpoint(&[0x00, 0x9f], 0x01020304);
    wire.extend_from_slice(&endpoint(&[0x09, 0xf0], 0x04030201));
    let value = UplinkModifications::decode(&wire, DecodeContext::default()).unwrap();
    assert_eq!(value.values().len(), 1);
    assert_eq!(value.values()[0].uplink.teid(), 0x01020304);
    assert_eq!(value.values()[0].downlink.teid(), 0x04030201);
    assert_eq!(
        value.encode(EncodeContext::default()).unwrap().as_bytes(),
        wire
    );
}

#[test]
fn dual_stack_setup_result_keeps_flow_associations() {
    // Five transfer flags, two tunnel flags, four transport flags, length.
    let mut wire = endpoint(&[0x00, 0x13, 0xe0], 0x01020304);
    wire.extend_from_slice(&[0x00, 0x07]); // One flow: no optionals, QFI 7.
    let value = SetupResponseTransfer::decode(&wire, DecodeContext::default()).unwrap();
    assert_eq!(value.downlink().teid(), 0x01020304);
    assert_eq!(value.accepted().len(), 1);
    assert_eq!(value.accepted()[0].value(), 7);
    assert_eq!(
        value.encode(EncodeContext::default()).unwrap().as_bytes(),
        wire
    );
}

#[test]
fn dual_stack_modify_result_preserves_optional_endpoints() {
    // Seven transfer flags with downlink and uplink present, then transport.
    let mut wire = endpoint(&[0x60, 0x13, 0xe0], 0x01020304);
    wire.extend_from_slice(&endpoint(&[0x09, 0xf0], 0x04030201));
    let value = ModifyResponseTransfer::decode(&wire, DecodeContext::default()).unwrap();
    assert_eq!(value.downlink.unwrap().teid(), 0x01020304);
    assert_eq!(value.uplink.unwrap().teid(), 0x04030201);
    assert_eq!(
        value.encode(EncodeContext::default()).unwrap().as_bytes(),
        wire
    );
}
