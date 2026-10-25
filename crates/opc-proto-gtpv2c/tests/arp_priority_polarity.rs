//! Pins the TS 29.274 Allocation and Retention Priority polarity (issue #1354).
//!
//! The reported symptom was an allegedly inverted priority level: a higher
//! numerical level being treated as more important. The GTPv2-C ARP octet packs
//! Priority-Level (bits 6-3), Pre-emption-Capability (bit 7) and
//! Pre-emption-Vulnerability (bit 1); bits 8 and 2 are spare. Level 1 is the
//! highest priority and level 15 the lowest, and the octet's level field is an
//! identity mapping of that value (`level << 2`), not `16 - level`.
//!
//! The sibling ARP carriers audited for the same symptom are direct integer
//! mappings with no octet packing: `opc-proto-ngap`'s
//! `AllocationRetentionPriority` stores the 1..=15 priority verbatim
//! (`crates/opc-proto-ngap/src/n3iwf/qos_fields.rs`), and
//! `opc-proto-diameter`'s SWm `SwmPriorityLevel` maps the Diameter Unsigned32
//! 1..=15 verbatim (`crates/opc-proto-diameter/src/apps/swm.rs`). Only the
//! GTPv2-C octet packing could invert the polarity, so this regression pins it
//! and the audit records why no sibling change is needed.

use opc_proto_gtpv2c::{AllocationRetentionPriority, BearerQos, BearerQosValidationError};

fn arp(level: u8, pci: bool, pvi: bool) -> AllocationRetentionPriority {
    AllocationRetentionPriority::new(level, pci, pvi).expect("test ARP level is 1..=15")
}

#[test]
fn level_one_is_the_highest_priority_and_encodes_as_0x04() {
    let highest = arp(1, false, false);
    assert_eq!(highest.priority_level(), 1);
    assert_eq!(highest.to_octet(), 0x04);

    let lowest = arp(15, false, false);
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
            let expected = ((pci as u8) << 6) | (level << 2) | (pvi as u8);
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
                    ((pci as u8) << 6) | ((16 - level) << 2) | (pvi as u8),
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
