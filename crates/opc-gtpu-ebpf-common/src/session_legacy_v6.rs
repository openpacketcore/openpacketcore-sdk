// Frozen v6 entry validator from SDK revision 850662d3f, before the IPv6
// Packet Too Big format. Keep its format constants and validation unchanged:
// this is an independent older reader for the downgrade contract.
use super::{GtpuSessionIpFamily, GtpuUplinkSourcePortPolicy};
const GTPU_SESSION_ENTRY_LEN: usize = 80;
const ENTRY_FORMAT_VERSION: u8 = 1;
const N3_ENTRY_FORMAT_VERSION: u8 = 2;

#[inline(always)]
fn entry_profile_is_canonical(value: &[u8; GTPU_SESSION_ENTRY_LEN]) -> bool {
    match value[0] {
        ENTRY_FORMAT_VERSION if value[72] == 0 => {}
        N3_ENTRY_FORMAT_VERSION if value[72] <= 63 => {}
        _ => return false,
    }
    value[73] == 0
        && value[74] == 0
        && value[75] == 0
        && value[76] == 0
        && value[77] == 0
        && value[78] == 0
        && value[79] == 0
}

// The ordinary entry already excludes unspecified addresses. N3 additionally
// excludes multicast and the IPv4 limited broadcast address, matching its
// public directional TNL model. Keep this usable by both decode paths.
#[inline(always)]
const fn n3_outer_is_unicast(family: u8, value: &[u8; 16]) -> bool {
    match family {
        4 => {
            !(value[0] >= 224 && value[0] <= 239
                || value[0] == 255 && value[1] == 255 && value[2] == 255 && value[3] == 255)
        }
        6 => value[0] != 0xff,
        _ => false,
    }
}

#[inline(always)]
fn native_word_4(value: &[u8; 16], offset: usize) -> u32 {
    u32::from_ne_bytes([
        value[offset],
        value[offset + 1],
        value[offset + 2],
        value[offset + 3],
    ])
}

#[inline(always)]
fn native_word_8(value: &[u8; 16], offset: usize) -> u64 {
    u64::from_ne_bytes([
        value[offset],
        value[offset + 1],
        value[offset + 2],
        value[offset + 3],
        value[offset + 4],
        value[offset + 5],
        value[offset + 6],
        value[offset + 7],
    ])
}

#[inline(always)]
fn bytes_16_are_zero(value: &[u8; 16]) -> bool {
    native_word_8(value, 0) | native_word_8(value, 8) == 0
}

// Validate one address per call: keeping the independent address-byte loads
// in separate frames avoids register spills that exceed the Linux 5.14/6.8
// combined stack limit in the grouped downlink authority chain.
#[inline(never)]
fn wire_address_is_canonical(family: u8, value: &[u8; 16]) -> bool {
    match GtpuSessionIpFamily::from_wire(family) {
        Some(GtpuSessionIpFamily::Ipv4) => {
            native_word_4(value, 0) != 0
                && native_word_4(value, 4) == 0
                && native_word_8(value, 8) == 0
        }
        Some(GtpuSessionIpFamily::Ipv6) => !bytes_16_are_zero(value),
        None => false,
    }
}

#[inline(never)]
fn wire_paa_is_canonical(family: u8, value: &[u8; 16]) -> bool {
    match GtpuSessionIpFamily::from_wire(family) {
        Some(GtpuSessionIpFamily::Ipv4) => {
            native_word_4(value, 0) != 0
                && native_word_4(value, 4) == 0
                && native_word_8(value, 8) == 0
        }
        Some(GtpuSessionIpFamily::Ipv6) => {
            native_word_8(value, 0) != 0 && native_word_8(value, 8) == 0
        }
        None => false,
    }
}

#[inline(never)]
pub(super) fn entry_wire_is_canonical(
    value: &[u8; GTPU_SESSION_ENTRY_LEN],
    expected_family: GtpuSessionIpFamily,
) -> bool {
    let inner_paa: &[u8; 16] = match (&value[4..20]).try_into() {
        Ok(value) => value,
        Err(_) => return false,
    };
    let peer_outer: &[u8; 16] = match (&value[20..36]).try_into() {
        Ok(value) => value,
        Err(_) => return false,
    };
    let local_outer: &[u8; 16] = match (&value[36..52]).try_into() {
        Ok(value) => value,
        Err(_) => return false,
    };
    if !entry_profile_is_canonical(value)
        || value[1] != expected_family as u8
        || value[3] != 0
        || !wire_paa_is_canonical(value[1], inner_paa)
        || !wire_address_is_canonical(value[2], peer_outer)
        || !wire_address_is_canonical(value[2], local_outer)
        || (value[0] == N3_ENTRY_FORMAT_VERSION
            && (!n3_outer_is_unicast(value[2], peer_outer)
                || !n3_outer_is_unicast(value[2], local_outer)))
        || u32::from_ne_bytes([value[52], value[53], value[54], value[55]]) == 0
        || u32::from_ne_bytes([value[56], value[57], value[58], value[59]]) == 0
        || !matches!(value[64], 0..=63 | 0xff)
    {
        return false;
    }
    let aliases_inner = match (expected_family, GtpuSessionIpFamily::from_wire(value[2])) {
        (GtpuSessionIpFamily::Ipv4, Some(GtpuSessionIpFamily::Ipv4)) => {
            native_word_4(inner_paa, 0) == native_word_4(local_outer, 0)
        }
        (GtpuSessionIpFamily::Ipv6, Some(GtpuSessionIpFamily::Ipv6)) => {
            native_word_8(inner_paa, 0) == native_word_8(local_outer, 0)
        }
        _ => false,
    };
    if aliases_inner {
        return false;
    }
    let first = u16::from_be_bytes([value[66], value[67]]);
    let last = u16::from_be_bytes([value[68], value[69]]);
    let downlink_policy_is_canonical = match value[65] {
        0 => first == 0 && last == 0,
        1 => first == last,
        2 => first < last,
        _ => false,
    };
    downlink_policy_is_canonical
        && GtpuUplinkSourcePortPolicy::from_map_value([value[70], value[71]]).is_some()
}
