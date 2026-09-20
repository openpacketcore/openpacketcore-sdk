//! Synthetic ABI detector; native tests separately qualify forwarding.
use opc_gtpu_ebpf_common::{GtpuSessionEntry, GTPU_SESSION_ENTRY_LEN};

fn fixture() -> [u8; GTPU_SESSION_ENTRY_LEN] {
    let mut b = [0; GTPU_SESSION_ENTRY_LEN];
    b[..4].copy_from_slice(&[2, 4, 4, 0]);
    b[4..8].copy_from_slice(&[10, 45, 0, 2]);
    b[20..24].copy_from_slice(&[192, 0, 2, 10]);
    b[36..40].copy_from_slice(&[192, 0, 2, 1]);
    b[52..56].copy_from_slice(&0x11223344_u32.to_be_bytes());
    b[56..60].copy_from_slice(&0x55667788_u32.to_be_bytes());
    b[64] = 0xff;
    b[70..72].copy_from_slice(&2152_u16.to_be_bytes());
    b
}

#[test]
fn independent_n3_entry_version_two_is_canonical() {
    for qfi in 0..64 {
        let mut bytes = fixture();
        bytes[72] = qfi;
        let entry = GtpuSessionEntry::decode(&bytes).expect("valid fixed-flow N3 entry");
        assert_eq!(entry.n3_qfi(), Some(qfi));
        assert_eq!(entry.encode(), bytes);
    }
}

#[test]
fn n3_outer_endpoints_match_the_directional_unicast_contract() {
    for slot in [20, 36] {
        for address in [[224, 0, 0, 1], [239, 255, 255, 255], [255; 4], [0; 4]] {
            let mut bytes = fixture();
            bytes[slot..slot + 4].copy_from_slice(&address);
            assert!(GtpuSessionEntry::decode(&bytes).is_none());
        }
        let mut bytes = fixture();
        bytes[2] = 6;
        bytes[20..36].copy_from_slice(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        bytes[36..52].copy_from_slice(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        assert!(GtpuSessionEntry::decode(&bytes).is_some());
        bytes[slot] = 0xff;
        assert!(GtpuSessionEntry::decode(&bytes).is_none());
    }
}

#[test]
fn n3_version_and_reserved_bytes_cannot_alias_legacy() {
    for version in 0..=255 {
        let mut bytes = fixture();
        bytes[0] = version;
        assert_eq!(
            GtpuSessionEntry::decode(&bytes).is_some(),
            matches!(version, 1 | 2)
        );
    }
    for qfi in 64..=255 {
        let mut bytes = fixture();
        bytes[72] = qfi;
        assert!(GtpuSessionEntry::decode(&bytes).is_none());
    }
    for index in 73..80 {
        let mut bytes = fixture();
        bytes[index] = 1;
        assert!(GtpuSessionEntry::decode(&bytes).is_none());
    }
    let mut legacy = fixture();
    legacy[0] = 1;
    legacy[72] = 1;
    assert!(GtpuSessionEntry::decode(&legacy).is_none());
}
