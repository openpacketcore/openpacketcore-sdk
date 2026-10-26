//! TS 29.274 clause 8.15 and TS 29.212 clauses 5.3.45-5.3.47 ARP contracts.
//!
//! Priority-Level is the literal value 1..=15, with 1 the highest priority.
//! Capability and vulnerability use the Diameter convention: zero enables
//! pre-emption and one disables it. The public booleans express permission,
//! independently of the raw PCI/PVI bits. Bits 8 and 2 remain spare.

use opc_proto_gtpv2c::{AllocationRetentionPriority, BearerQos, BearerQosValidationError};

fn arp(level: u8, pci: bool, pvi: bool) -> AllocationRetentionPriority {
    AllocationRetentionPriority::new(level, pci, pvi).expect("test ARP level is 1..=15")
}

#[test]
fn level_one_is_the_highest_priority_and_encodes_as_0x04() {
    let highest = arp(1, true, true);
    assert_eq!(highest.priority_level(), 1);
    assert_eq!(highest.to_octet(), 0x04);

    let lowest = arp(15, true, true);
    assert_eq!(lowest.priority_level(), 15);
    assert_eq!(lowest.to_octet(), 0x3c);

    // The encoded level field must increase with the numerical level: level 1
    // (highest importance) has the smallest octet, level 15 (lowest) the largest.
    assert!(highest.to_octet() < lowest.to_octet());

    assert_eq!(
        AllocationRetentionPriority::from_octet(0x04),
        Ok(highest),
        "level 1 must decode from octet 0x04"
    );
    assert_eq!(
        AllocationRetentionPriority::from_octet(0x3c),
        Ok(lowest),
        "level 15 must decode from octet 0x3c"
    );
}

#[test]
fn octet_level_field_is_an_identity_mapping_for_every_level() {
    for level in 1..=15u8 {
        for (pci, pvi) in [(false, false), (true, false), (false, true), (true, true)] {
            let value = arp(level, pci, pvi);
            let expected = ((!pci as u8) << 6) | (level << 2) | (!pvi as u8);
            assert_eq!(
                value.to_octet(),
                expected,
                "level {level} pci={pci} pvi={pvi} must use the identity octet map"
            );
            assert_eq!(
                AllocationRetentionPriority::from_octet(expected),
                Ok(value),
                "octet 0x{expected:02x} must round-trip level {level}"
            );
            // The inverse polarity mistake would produce 16 - level here; the
            // two mappings coincide only at the midpoint (level 8).
            if level != 8 {
                assert_ne!(
                    expected,
                    ((!pci as u8) << 6) | ((16 - level) << 2) | (!pvi as u8),
                    "level {level} must not be encoded as 16 - level"
                );
            }
        }
    }
}

#[test]
fn spare_bits_and_out_of_range_levels_stay_rejected() {
    // Spare bit 8 (0x80) and spare bit 2 (0x02) are not part of the typed map.
    assert_eq!(
        AllocationRetentionPriority::from_octet(0x82),
        Err(BearerQosValidationError::InvalidArpSpareBits)
    );
    assert_eq!(
        AllocationRetentionPriority::from_octet(0x80),
        Err(BearerQosValidationError::InvalidArpSpareBits)
    );
    assert_eq!(
        AllocationRetentionPriority::from_octet(0x02),
        Err(BearerQosValidationError::InvalidArpSpareBits)
    );
    // Level field zero is outside TS 29.274's 1..=15.
    for octet in [0x00u8, 0x01, 0x40, 0x41] {
        assert_eq!(
            AllocationRetentionPriority::from_octet(octet),
            Err(BearerQosValidationError::InvalidPriorityLevel),
            "octet 0x{octet:02x} carries level 0 and must be rejected"
        );
    }
    assert_eq!(
        AllocationRetentionPriority::new(0, false, false),
        Err(BearerQosValidationError::InvalidPriorityLevel)
    );
    assert_eq!(
        AllocationRetentionPriority::new(16, false, false),
        Err(BearerQosValidationError::InvalidPriorityLevel)
    );
}

#[test]
fn bearer_qos_octet_keeps_the_same_polarity() {
    // The Bearer QoS IE carries the same packed octet; reading it back through
    // the typed accessor must not invert the level either.
    let level_one =
        BearerQos::new(arp(1, false, false), 1, 128, 128, 64, 64).expect("valid GBR voice QoS");
    assert_eq!(
        level_one
            .allocation_retention_priority()
            .expect("valid ARP")
            .priority_level(),
        1
    );

    let level_fifteen =
        BearerQos::new(arp(15, false, false), 1, 128, 128, 64, 64).expect("valid GBR voice QoS");
    assert_eq!(
        level_fifteen
            .allocation_retention_priority()
            .expect("valid ARP")
            .priority_level(),
        15
    );
}

#[test]
fn preemption_flags_decode_zero_as_enabled() {
    // The literal ARP octet in the Update Bearer issue payload has PCI=0,
    // PL=4 and PVI=1: it may pre-empt, but must not be pre-empted.
    let decoded = AllocationRetentionPriority::from_octet(0x11).expect("valid ARP");
    assert_eq!(decoded.priority_level(), 4);
    assert!(decoded.preemption_capability());
    assert!(!decoded.preemption_vulnerability());
    let disabled = AllocationRetentionPriority::from_octet(0x4d).expect("valid ARP");
    assert!(!disabled.preemption_capability());
    assert!(!disabled.preemption_vulnerability());
}

#[test]
fn preemption_flags_encode_zero_as_enabled() {
    assert_eq!(arp(2, true, false).to_octet(), 0x09);
    assert_eq!(arp(2, false, true).to_octet(), 0x48);
    assert_eq!(arp(2, true, true).to_octet(), 0x08);
    assert_eq!(arp(2, false, false).to_octet(), 0x49);
}

#[test]
fn preemption_permissions_use_the_enabled_zero_wire_convention() {
    for level in 1..=15 {
        for capability in [false, true] {
            for vulnerability in [false, true] {
                let wire = (level << 2)
                    | if capability { 0 } else { 0x40 }
                    | if vulnerability { 0 } else { 1 };
                let decoded = AllocationRetentionPriority::from_octet(wire).unwrap();
                assert_eq!(decoded.priority_level(), level);
                assert_eq!(decoded.preemption_capability(), capability);
                assert_eq!(decoded.preemption_vulnerability(), vulnerability);
                assert_eq!(
                    AllocationRetentionPriority::new(level, capability, vulnerability)
                        .unwrap()
                        .to_octet(),
                    wire
                );
            }
        }
    }
}
