//! TS 38.413 9.3.2.4 and TS 38.414 5.3: a 160-bit transport address
//! contains IPv4 in its first 32 bits, followed by the 128-bit IPv6 address.
//! These synthetic APER literals do not use the SDK encoder as their oracle.

use opc_proto_ngap::n3iwf::{
    modify_fields::UplinkModifications,
    modify_results::ModifyResponseTransfer,
    resource_fields::{
        DownlinkTransport, TransportLayerAddress, UplinkTransport, UplinkTransportList,
    },
    resource_results::SetupResponseTransfer,
};
use opc_protocol::{DecodeContext, EncodeContext};

const ADDRESS: [u8; 20] = [
    192, 0, 2, 1, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

fn combined() -> TransportLayerAddress {
    TransportLayerAddress::Ipv4v6 {
        ipv4: std::net::Ipv4Addr::new(192, 0, 2, 1),
        ipv6: std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
    }
}

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
    assert_eq!(value.address(), combined());
    assert_eq!(value, UplinkTransport::with_address(combined(), 0x01020304));
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
    assert_eq!(value.address(), combined());
    assert_eq!(
        value,
        DownlinkTransport::with_address(combined(), 0x04030201)
    );
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
    assert_eq!(value.values()[0].address(), combined());
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
    assert_eq!(value.values()[0].uplink.address(), combined());
    assert_eq!(value.values()[0].downlink.address(), combined());
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
    assert_eq!(value.downlink().address(), combined());
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
    assert_eq!(value.downlink.unwrap().address(), combined());
    assert_eq!(value.uplink.unwrap().address(), combined());
    assert_eq!(value.downlink.unwrap().teid(), 0x01020304);
    assert_eq!(value.uplink.unwrap().teid(), 0x04030201);
    assert_eq!(
        value.encode(EncodeContext::default()).unwrap().as_bytes(),
        wire
    );
}

#[test]
fn dual_stack_framing_and_resource_limits_remain_exact() {
    macro_rules! check {
        ($ty:ty, $wire:expr, $depth:expr, $ies:expr) => {{
            let wire = $wire;
            let ctx = DecodeContext {
                max_message_len: wire.len(),
                max_depth: $depth,
                max_ies: $ies,
                ..DecodeContext::default()
            };
            let value = <$ty>::decode(&wire, ctx).unwrap();
            assert_eq!(
                value
                    .encode(EncodeContext {
                        max_message_len: wire.len(),
                        ..EncodeContext::default()
                    })
                    .unwrap()
                    .as_bytes(),
                wire
            );
            assert!(value
                .encode(EncodeContext {
                    max_message_len: wire.len() - 1,
                    ..EncodeContext::default()
                })
                .is_err());
            assert!(<$ty>::decode(
                &wire,
                DecodeContext {
                    max_message_len: wire.len() - 1,
                    ..ctx
                }
            )
            .is_err());
            assert!(<$ty>::decode(
                &wire,
                DecodeContext {
                    max_depth: $depth - 1,
                    ..ctx
                }
            )
            .is_err());
            for end in 0..wire.len() {
                assert!(
                    <$ty>::decode(&wire[..end], ctx).is_err(),
                    "truncated at {end}"
                );
            }
            let mut trailing = wire;
            trailing.push(0);
            assert!(<$ty>::decode(&trailing, DecodeContext::default()).is_err());
            assert!(format!("{value:?}").contains("REDACTED"));
        }};
    }
    check!(UplinkTransport, endpoint(&[0x09, 0xf0], 1), 3, 0);
    check!(DownlinkTransport, endpoint(&[0x09, 0xf0], 1), 3, 0);
    let list = endpoint(&[0x00, 0x9f], 1);
    check!(UplinkTransportList, list.clone(), 5, 1);
    assert!(UplinkTransportList::decode(
        &list,
        DecodeContext {
            max_ies: 0,
            ..DecodeContext::default()
        }
    )
    .is_err());
    let mut pair = list;
    pair.extend_from_slice(&endpoint(&[0x09, 0xf0], 2));
    check!(UplinkModifications, pair.clone(), 5, 1);
    assert!(UplinkModifications::decode(
        &pair,
        DecodeContext {
            max_ies: 0,
            ..DecodeContext::default()
        }
    )
    .is_err());
    let mut setup = endpoint(&[0, 0x13, 0xe0], 1);
    setup.extend_from_slice(&[0, 7]);
    check!(SetupResponseTransfer, setup.clone(), 6, 1);
    assert!(SetupResponseTransfer::decode(
        &setup,
        DecodeContext {
            max_ies: 0,
            ..DecodeContext::default()
        }
    )
    .is_err());
    let mut modify = endpoint(&[0x60, 0x13, 0xe0], 1);
    modify.extend_from_slice(&endpoint(&[0x09, 0xf0], 2));
    check!(ModifyResponseTransfer, modify, 4, 0);
}

#[test]
fn dual_stack_support_does_not_admit_other_widths_extensions_or_padding() {
    for bits in 1u16..=256 {
        if matches!(bits, 32 | 128 | 160) {
            continue;
        }
        let mut wire = ((bits - 1) << 4).to_be_bytes().to_vec();
        wire.resize(2 + usize::from(bits).div_ceil(8) + 4, 0);
        assert!(UplinkTransport::decode(&wire, DecodeContext::default()).is_err());
        assert!(DownlinkTransport::decode(&wire, DecodeContext::default()).is_err());
        let mut pair = vec![0, (bits - 1) as u8];
        pair.resize(2 + usize::from(bits).div_ceil(8) + 4, 0);
        pair.extend_from_slice(&endpoint(&[0x09, 0xf0], 2));
        assert!(UplinkModifications::decode(&pair, DecodeContext::default()).is_err());
    }
    for (octet, mask) in [(0, 0x80), (0, 0x40), (0, 0x20), (0, 0x10), (1, 1)] {
        let mut wire = endpoint(&[0x09, 0xf0], 1);
        wire[octet] |= mask;
        assert!(UplinkTransport::decode(&wire, DecodeContext::default()).is_err());
        assert!(DownlinkTransport::decode(&wire, DecodeContext::default()).is_err());
    }
    let mut setup = endpoint(&[0, 0x13, 0xe0], 1);
    setup.extend_from_slice(&[0, 7]);
    setup[2] |= 1; // Nonzero alignment padding at the nested parent offset.
    assert!(SetupResponseTransfer::decode(&setup, DecodeContext::default()).is_err());
}

#[test]
fn mixed_address_families_preserve_each_endpoint_and_flow_mapping() {
    use opc_proto_ngap::n3iwf::{
        modify_fields::UplinkModification,
        resource_fields::QosFlowId,
        resource_results::{AssociatedQosFlow, DownlinkQosTunnel, QosFlowMapping},
    };
    let addresses = [
        TransportLayerAddress::Ipv4(std::net::Ipv4Addr::new(198, 51, 100, 2)),
        TransportLayerAddress::Ipv6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        combined(),
    ];
    for uplink in addresses {
        for downlink in addresses {
            let pair = UplinkModifications::new(vec![UplinkModification {
                uplink: UplinkTransport::with_address(uplink, 0),
                downlink: DownlinkTransport::with_address(downlink, u32::MAX),
            }])
            .unwrap();
            let wire = pair.encode(EncodeContext::default()).unwrap();
            assert_eq!(
                UplinkModifications::decode(wire.as_bytes(), DecodeContext::default()).unwrap(),
                pair
            );
        }
    }
    let uplinks = UplinkTransportList::new(
        addresses
            .map(|address| UplinkTransport::with_address(address, 7))
            .to_vec(),
    )
    .unwrap();
    let wire = uplinks.encode(EncodeContext::default()).unwrap();
    assert_eq!(
        UplinkTransportList::decode(wire.as_bytes(), DecodeContext::default()).unwrap(),
        uplinks
    );
    let tunnel = |address| {
        DownlinkQosTunnel::new(
            DownlinkTransport::with_address(address, 7),
            vec![AssociatedQosFlow {
                qfi: QosFlowId::new(7).unwrap(),
                mapping: Some(QosFlowMapping::Downlink),
            }],
        )
        .unwrap()
    };
    let setup = SetupResponseTransfer::with_tunnels(
        tunnel(combined()),
        addresses.map(tunnel).to_vec(),
        vec![],
    )
    .unwrap();
    let wire = setup.encode(EncodeContext::default()).unwrap();
    assert_eq!(
        SetupResponseTransfer::decode(wire.as_bytes(), DecodeContext::default()).unwrap(),
        setup
    );
    let modify = ModifyResponseTransfer {
        downlink: Some(DownlinkTransport::with_address(combined(), 0)),
        uplink: Some(UplinkTransport::with_address(addresses[0], u32::MAX)),
        additional: addresses.map(tunnel).to_vec(),
        ..ModifyResponseTransfer::default()
    };
    let wire = modify.encode(EncodeContext::default()).unwrap();
    assert_eq!(
        ModifyResponseTransfer::decode(wire.as_bytes(), DecodeContext::default()).unwrap(),
        modify
    );
}
