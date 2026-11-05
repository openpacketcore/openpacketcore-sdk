//! TS 29.274 clause 8.15 and TS 29.212 clause 5.3.45 QoS contracts.

use opc_proto_gtpv2c::AllocationRetentionPriority;
use std::cmp::Ordering;

#[test]
fn arp_wire_priority_levels_are_not_inverted() {
    for (octet, level) in [(0x04, 1), (0x20, 8), (0x3c, 15)] {
        let arp = AllocationRetentionPriority::from_octet(octet).expect("valid ARP");
        assert_eq!(arp.priority_level(), level);
        assert_eq!(arp.to_octet(), octet);
    }
}

#[test]
fn arp_domain_comparison_ranks_level_one_highest_and_fifteen_lowest() {
    let highest = AllocationRetentionPriority::from_octet(0x04).expect("level one");
    let lowest = AllocationRetentionPriority::from_octet(0x3c).expect("level fifteen");
    assert_eq!(highest.cmp_priority(&lowest), Ordering::Greater);
    assert_eq!(lowest.cmp_priority(&highest), Ordering::Less);

    let mut priorities: Vec<_> = [8, 15, 3, 10, 1, 14, 2, 12, 4, 13, 5, 11, 6, 9, 7]
        .into_iter()
        .map(|level| AllocationRetentionPriority::new(level, false, false).expect("valid level"))
        .collect();
    priorities.sort_by(|left, right| right.cmp_priority(left));
    assert_eq!(
        priorities
            .iter()
            .map(|arp| arp.priority_level())
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
}

#[test]
fn arp_priority_comparison_is_independent_of_preemption_flags() {
    for level in 1..=15 {
        let reference = AllocationRetentionPriority::new(level, false, false).expect("valid level");
        for flags in [0x00, 0x01, 0x40, 0x41] {
            let arp =
                AllocationRetentionPriority::from_octet((level << 2) | flags).expect("valid ARP");
            assert_eq!(arp.cmp_priority(&reference), Ordering::Equal);
            assert_eq!(reference.cmp_priority(&arp), Ordering::Equal);
        }
    }
}
