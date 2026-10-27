//! Sender/receiver boundaries from TS 29.244 V19.6.0, independently encoded.

use bytes::{Bytes, BytesMut};
use opc_proto_pfcp::{
    ie::{Cause, CauseValue, TypedIe, UeIpAddress},
    InformationElement, OwnedMessage,
};
use opc_protocol::{DecodeContext, EncodeContext, OwnedDecode, ValidationLevel};

fn tlv(kind: u16, value: &[u8]) -> Vec<u8> {
    let mut wire = kind.to_be_bytes().to_vec();
    wire.extend_from_slice(&(value.len() as u16).to_be_bytes());
    wire.extend_from_slice(value);
    wire
}

fn modification(ies: &[Vec<u8>]) -> OwnedMessage {
    let mut wire = vec![0x21, 52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0];
    for ie in ies {
        wire.extend_from_slice(ie);
    }
    let len = (wire.len() - 4) as u16;
    wire[2..4].copy_from_slice(&len.to_be_bytes());
    OwnedMessage::decode_owned(Bytes::from(wire), DecodeContext::default()).unwrap()
}

fn far(kind: u16, action: &[u8], parameters: Option<&[u8]>) -> OwnedMessage {
    let mut members = tlv(108, &[0, 0, 0, 7]);
    members.extend(tlv(44, action));
    if let Some(parameters) = parameters {
        members.extend(tlv(if kind == 3 { 4 } else { 11 }, parameters));
    }
    modification(&[tlv(kind, &members)])
}

#[test]
fn release_15_apply_action_decodes_and_canonically_emits_two_octets() {
    // Table 8.1.2-1: Apply Action has one original fixed octet; §8.2.26
    // defines subsequent flags. Unknown extensions do not change known flags.
    for value in [&[2][..], &[2, 0][..], &[2, 0, 0xaa][..]] {
        let (_, TypedIe::ApplyAction(action)) =
            TypedIe::decode(&tlv(44, value), DecodeContext::default(), 0).unwrap()
        else {
            panic!("expected Apply Action")
        };
        assert!(action.forward);
        assert!(!action.edrt && !action.bdpn && !action.ddpn && !action.fssm && !action.mbsu);
        let mut encoded = BytesMut::new();
        TypedIe::ApplyAction(action)
            .encode(&mut encoded, EncodeContext::default())
            .unwrap();
        assert_eq!(encoded.as_ref(), &[0, 44, 0, 2, 2, 0]);
    }
    assert!(TypedIe::decode(&tlv(44, &[]), DecodeContext::default(), 0).is_err());
}

#[test]
fn release_15_apply_action_is_accepted_in_create_and_update_far() {
    for kind in [3, 10] {
        assert!(far(kind, &[2], Some(&tlv(42, &[0])))
            .validate_production_v1(DecodeContext::default())
            .is_ok());
    }
}

#[test]
fn update_far_can_change_only_the_action() {
    // §5.6.3 and Table 7.5.4.3-1: unchanged forwarding parameters are omitted.
    assert!(far(10, &[2, 0], None)
        .validate_production_v1(DecodeContext::default())
        .is_ok());
    assert!(far(3, &[2, 0], None)
        .validate_production_v1(DecodeContext::default())
        .is_err());
    assert!(far(10, &[3, 0], None)
        .validate_production_v1(DecodeContext::default())
        .is_err());
}

#[test]
fn update_far_can_change_outer_header_without_repeating_destination() {
    // Table 7.5.4.3-2: Destination Interface is supplied only if changed.
    // §8.2.56: GTP-U/UDP/IPv4, TEID 7, address 192.0.2.1.
    let outer = tlv(84, &[1, 0, 0, 0, 0, 7, 192, 0, 2, 1]);
    assert!(far(10, &[2, 0], Some(&outer))
        .validate_production_v1(DecodeContext::default())
        .is_ok());
    assert!(far(3, &[2, 0], Some(&outer))
        .validate_production_v1(DecodeContext::default())
        .is_err());
    let short = tlv(84, &[1]);
    assert!(far(10, &[2, 0], Some(&short))
        .validate_production_v1(DecodeContext::default())
        .is_err());
}

#[test]
fn ue_address_requires_an_address_or_allocation_request_on_decode() {
    // §8.2.62: the value identifies an address or requests its assignment.
    for validation_level in [
        ValidationLevel::HeaderOnly,
        ValidationLevel::Structural,
        ValidationLevel::Strict,
        ValidationLevel::ProcedureAware,
    ] {
        let ctx = DecodeContext {
            validation_level,
            ..DecodeContext::default()
        };
        for flags in [0, 4] {
            assert!(
                TypedIe::decode(&tlv(93, &[flags]), ctx, 0).is_err(),
                "flags={flags}"
            );
        }
        for flags in [0x10, 0x20, 0x30] {
            assert!(
                TypedIe::decode(&tlv(93, &[flags]), ctx, 0).is_ok(),
                "flags={flags}"
            );
        }
    }
}

#[test]
fn ue_address_requires_an_address_or_allocation_request_on_encode() {
    for sd in [false, true] {
        let address = UeIpAddress {
            v4: false,
            v6: false,
            sd,
            ipv6d: false,
            ip6pl: false,
            chv4: false,
            chv6: false,
            ipv4: None,
            ipv6: None,
            ipv6_prefix_delegation_bits: None,
            ipv6_prefix_length: None,
        };
        let mut encoded = BytesMut::from(&b"prefix"[..]);
        assert!(TypedIe::UeIpAddress(address)
            .encode(&mut encoded, EncodeContext::default())
            .is_err());
        assert_eq!(encoded.as_ref(), b"prefix");
    }
}

#[test]
fn typed_ie_senders_clear_spares_while_raw_ie_values_remain_available() {
    // §8.1.2: receive without evaluating spare bits; transmit them as zero.
    for (kind, received, canonical) in [
        (20, &[0xf1][..], &[1][..]),
        (42, &[0xf2][..], &[2][..]),
        (44, &[0x12, 0xe0][..], &[0x12, 0][..]),
    ] {
        let wire = tlv(kind, received);
        let (_, raw) = InformationElement::decode(&wire).unwrap();
        assert_eq!(raw.value.as_ref(), received);
        let (_, typed) = TypedIe::decode(&wire, DecodeContext::default(), 0).unwrap();
        for raw_preserving in [false, true] {
            let mut encoded = BytesMut::new();
            typed
                .encode(
                    &mut encoded,
                    EncodeContext {
                        raw_preserving,
                        ..EncodeContext::default()
                    },
                )
                .unwrap();
            assert_eq!(encoded.as_ref(), tlv(kind, canonical));
        }
    }
}

#[test]
fn dfrt_requires_forwarding_in_both_far_profiles() {
    // §8.2.26: DFRT is permitted only together with FORW.
    for kind in [3, 10] {
        assert!(far(kind, &[0x81, 0], Some(&tlv(42, &[0])))
            .validate_production_v1(DecodeContext::default())
            .is_err());
        assert!(far(kind, &[0x82, 0], Some(&tlv(42, &[0])))
            .validate_production_v1(DecodeContext::default())
            .is_ok());
    }
}

#[test]
fn node_ip_addresses_ignore_extensions_but_reject_short_values() {
    // §8.1.2 and §8.2.38: Node ID is extendable; known address widths remain fixed.
    for canonical in [
        vec![0, 192, 0, 2, 1],
        vec![1, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
    ] {
        let mut extended = canonical.clone();
        extended.extend_from_slice(&[0xaa, 0xbb]);
        let (_, typed) = TypedIe::decode(&tlv(60, &extended), DecodeContext::default(), 0).unwrap();
        let mut encoded = BytesMut::new();
        typed
            .encode(&mut encoded, EncodeContext::default())
            .unwrap();
        assert_eq!(encoded.as_ref(), tlv(60, &canonical));
        assert!(TypedIe::decode(
            &tlv(60, &canonical[..canonical.len() - 1]),
            DecodeContext::default(),
            0
        )
        .is_err());
    }
}

#[test]
fn reserved_cause_cannot_be_sent_through_either_typed_representation() {
    // Table 8.2.1-1: zero shall not be sent, including an Unknown(0) alias.
    for value in [CauseValue::Reserved, CauseValue::Unknown(0)] {
        let mut encoded = BytesMut::from(&b"prefix"[..]);
        assert!(TypedIe::Cause(Cause { value })
            .encode(&mut encoded, EncodeContext::default())
            .is_err());
        assert_eq!(encoded.as_ref(), b"prefix");
    }
    for value in [1, 63, 64, 255] {
        let mut encoded = BytesMut::new();
        TypedIe::Cause(Cause {
            value: CauseValue::from(value),
        })
        .encode(&mut encoded, EncodeContext::default())
        .unwrap();
        assert_eq!(encoded.as_ref(), &[0, 19, 0, 1, value]);
    }
}
