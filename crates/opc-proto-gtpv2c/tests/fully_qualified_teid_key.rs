use std::cmp::Ordering;
use std::collections::{hash_map::DefaultHasher, BTreeSet, HashSet};
use std::hash::{Hash, Hasher};

use opc_proto_gtpv2c::FullyQualifiedTeid;

const INTERFACE_TYPE: u8 = 30;
const TEID: u32 = 0x1122_3344;
const IPV4_A: [u8; 4] = [192, 0, 2, 1];
const IPV4_B: [u8; 4] = [192, 0, 2, 2];
const IPV6_A: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const IPV6_B: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];

fn f_teid(
    interface_type: u8,
    teid: u32,
    ipv4: Option<[u8; 4]>,
    ipv6: Option<[u8; 16]>,
) -> FullyQualifiedTeid {
    FullyQualifiedTeid {
        interface_type,
        teid,
        ipv4,
        ipv6,
    }
}

fn hash(value: &FullyQualifiedTeid) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[test]
fn identical_f_teids_are_equal_hash_and_order_keys() {
    let key = f_teid(INTERFACE_TYPE, TEID, Some(IPV4_A), Some(IPV6_A));
    let identical = key.clone();

    assert_eq!(key, identical);
    assert_eq!(hash(&key), hash(&identical));
    assert_eq!(key.cmp(&identical), Ordering::Equal);
    assert_eq!(key.partial_cmp(&identical), Some(Ordering::Equal));

    let hashed = HashSet::from([key.clone(), identical.clone()]);
    assert_eq!(hashed.len(), 1);

    let ordered = BTreeSet::from([key, identical]);
    assert_eq!(ordered.len(), 1);
}

#[test]
fn f_teid_collection_identity_retains_every_protocol_component() {
    let cases = [
        (
            "dual stack",
            f_teid(INTERFACE_TYPE, TEID, Some(IPV4_A), Some(IPV6_A)),
        ),
        (
            "interface type",
            f_teid(INTERFACE_TYPE + 1, TEID, Some(IPV4_A), Some(IPV6_A)),
        ),
        (
            "TEID",
            f_teid(INTERFACE_TYPE, TEID + 1, Some(IPV4_A), Some(IPV6_A)),
        ),
        (
            "IPv4 endpoint",
            f_teid(INTERFACE_TYPE, TEID, Some(IPV4_B), Some(IPV6_A)),
        ),
        (
            "IPv6 endpoint",
            f_teid(INTERFACE_TYPE, TEID, Some(IPV4_A), Some(IPV6_B)),
        ),
        (
            "IPv4-only family presence",
            f_teid(INTERFACE_TYPE, TEID, Some(IPV4_A), None),
        ),
        (
            "IPv6-only family presence",
            f_teid(INTERFACE_TYPE, TEID, None, Some(IPV6_A)),
        ),
    ];

    for (left_index, (left_label, left)) in cases.iter().enumerate() {
        for (right_label, right) in cases.iter().skip(left_index + 1) {
            assert_ne!(left, right, "{left_label} collided with {right_label}");
            assert_ne!(
                left.cmp(right),
                Ordering::Equal,
                "{left_label} ordered equal to {right_label}"
            );
        }
    }

    let hashed: HashSet<_> = cases.iter().map(|(_, value)| value.clone()).collect();
    assert_eq!(hashed.len(), cases.len());

    let ordered: BTreeSet<_> = cases.iter().map(|(_, value)| value.clone()).collect();
    assert_eq!(ordered.len(), cases.len());
}

#[test]
fn f_teid_equality_and_total_order_obey_the_same_laws() {
    let keys = [
        f_teid(INTERFACE_TYPE - 1, TEID, Some(IPV4_A), Some(IPV6_A)),
        f_teid(INTERFACE_TYPE, TEID - 1, Some(IPV4_A), Some(IPV6_A)),
        f_teid(INTERFACE_TYPE, TEID, None, Some(IPV6_A)),
        f_teid(INTERFACE_TYPE, TEID, Some(IPV4_A), None),
        f_teid(INTERFACE_TYPE, TEID, Some(IPV4_A), Some(IPV6_A)),
        f_teid(INTERFACE_TYPE, TEID, Some(IPV4_A), Some(IPV6_B)),
        f_teid(INTERFACE_TYPE, TEID, Some(IPV4_B), Some(IPV6_A)),
    ];

    for left in &keys {
        for right in &keys {
            let ordering = left.cmp(right);
            assert_eq!(left == right, ordering == Ordering::Equal);
            assert_eq!(left.partial_cmp(right), Some(ordering));
            assert_eq!(ordering.reverse(), right.cmp(left));

            if left == right {
                assert_eq!(hash(left), hash(right));
            }
        }
    }
}
