//! Shared eBPF map ABI for the SWu IPsec load-balancing datapath.
//!
//! This crate is the single source of truth for byte layouts exchanged between
//! the host-XDP steering backend and the XDP program. It is `no_std`,
//! dependency-free, and deliberately key-material-free: values contain only
//! packet-header routing keys and redirect metadata.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

/// Ethernet header length at XDP ingress.
pub const ETH_HDR_LEN: usize = 14;
/// EtherType for IPv4.
pub const ETH_P_IPV4: u16 = 0x0800;
/// EtherType for IPv6.
pub const ETH_P_IPV6: u16 = 0x86DD;
/// Minimum option-free IPv4 header length.
pub const IPV4_MIN_HDR_LEN: usize = 20;
/// UDP header length.
pub const UDP_HDR_LEN: usize = 8;
/// IKEv2 fixed header length.
pub const IKEV2_HDR_LEN: usize = 28;
/// ESP-in-UDP header prefix length: SPI + sequence number.
pub const ESP_HEADER_PREFIX_LEN: usize = 8;
/// UDP port for IKE.
pub const UDP_PORT_IKE: u16 = 500;
/// UDP port for IKE/ESP NAT traversal.
pub const UDP_PORT_IKE_NATT: u16 = 4500;
/// RFC 3948 non-ESP marker preceding IKE on UDP/4500.
pub const NON_ESP_MARKER: [u8; 4] = [0, 0, 0, 0];
/// RFC 3948 NAT-T keepalive byte.
pub const NAT_T_KEEPALIVE: u8 = 0xff;
/// IKEv2 major version.
pub const IKEV2_MAJOR_VERSION: u8 = 2;
/// IKE_SA_INIT exchange type.
pub const IKEV2_EXCHANGE_IKE_SA_INIT: u8 = 34;

/// BPF map name: installed steering rules.
pub const MAP_SWU_RULES: &str = "IPSEC_LB_RULES";
/// BPF map name: precomputed routing-tag targets.
pub const MAP_TAG_TARGETS: &str = "IPSEC_LB_TAG_TARGETS";
/// BPF map name: single-slot datapath configuration.
pub const MAP_CONFIG: &str = "IPSEC_LB_CONFIG";
/// BPF map name: per-CPU datapath counters.
pub const MAP_COUNTERS: &str = "IPSEC_LB_COUNTERS";
/// XDP program name.
pub const PROG_SWU_XDP: &str = "opc_ipsec_lb_xdp";

/// Map key byte length.
pub const RULE_KEY_LEN: usize = 17;
/// Map value byte length.
pub const RULE_VALUE_LEN: usize = 8;
/// Tag-target map key byte length.
pub const TAG_TARGET_KEY_LEN: usize = 2;
/// Datapath config value byte length.
pub const CONFIG_VALUE_LEN: usize = 4;

/// Rule key kind for IKE packets keyed by responder SPI.
pub const RULE_KIND_IKE_RESPONDER_SPI: u8 = 1;
/// Rule key kind for ESP-in-UDP packets keyed by ESP SPI.
pub const RULE_KIND_ESP_SPI: u8 = 2;
/// Rule key kind for initial IKE_SA_INIT bootstrap packets.
pub const RULE_KIND_IKE_INIT: u8 = 3;

/// Rule flag: redirect to another interface instead of passing locally.
pub const RULE_FLAG_REDIRECT_IFINDEX: u16 = 1;
/// Rule flag: pass to local stack because this node owns the target.
pub const RULE_FLAG_LOCAL_OWNER: u16 = 2;

/// Counter index: packets passed through because they were not SWu traffic.
pub const COUNTER_PASS_NON_SWU: u32 = 0;
/// Counter index: packets redirected by a rule.
pub const COUNTER_REDIRECT: u32 = 1;
/// Counter index: packets passed to the local stack by a local-owner rule.
pub const COUNTER_LOCAL_OWNER: u32 = 2;
/// Counter index: SWu packets dropped as malformed or unsupported.
pub const COUNTER_DROP_MALFORMED: u32 = 3;
/// Counter index: UDP/4500 NAT-T keepalives consumed.
pub const COUNTER_NATT_KEEPALIVE: u32 = 4;
/// Counter index: SWu packets with no installed owner rule.
pub const COUNTER_MISS: u32 = 5;
/// Number of counter slots.
pub const COUNTER_SLOTS: u32 = 6;

/// Fixed steering map key.
///
/// Layout (17 bytes):
///
/// | offset | field    | meaning                                      |
/// |--------|----------|----------------------------------------------|
/// | 0      | kind     | one of `RULE_KIND_*`                         |
/// | 1..17  | material | kind-specific network-order match material   |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpRuleKey {
    /// Key kind.
    pub kind: u8,
    /// Kind-specific match material.
    pub material: [u8; 16],
}

impl XdpRuleKey {
    /// Build a key for an IKE responder SPI.
    #[must_use]
    pub fn ike_responder_spi(spi: u64) -> Self {
        let mut material = [0_u8; 16];
        material[..8].copy_from_slice(&spi.to_be_bytes());
        Self {
            kind: RULE_KIND_IKE_RESPONDER_SPI,
            material,
        }
    }

    /// Build a key for an ESP SPI.
    #[must_use]
    pub fn esp_spi(spi: u32) -> Self {
        let mut material = [0_u8; 16];
        material[..4].copy_from_slice(&spi.to_be_bytes());
        Self {
            kind: RULE_KIND_ESP_SPI,
            material,
        }
    }

    /// Build a key for IPv4 IKE_SA_INIT bootstrap.
    #[must_use]
    pub fn ike_init_ipv4(initiator_spi: u64, source_ip: [u8; 4]) -> Self {
        let mut material = [0_u8; 16];
        material[..8].copy_from_slice(&initiator_spi.to_be_bytes());
        material[8..12].copy_from_slice(&source_ip);
        Self {
            kind: RULE_KIND_IKE_INIT,
            material,
        }
    }

    /// Encode into the fixed map-key byte layout.
    #[must_use]
    pub const fn encode(&self) -> [u8; RULE_KEY_LEN] {
        [
            self.kind,
            self.material[0],
            self.material[1],
            self.material[2],
            self.material[3],
            self.material[4],
            self.material[5],
            self.material[6],
            self.material[7],
            self.material[8],
            self.material[9],
            self.material[10],
            self.material[11],
            self.material[12],
            self.material[13],
            self.material[14],
            self.material[15],
        ]
    }

    /// Decode from the fixed map-key byte layout.
    #[must_use]
    pub const fn decode(value: &[u8; RULE_KEY_LEN]) -> Self {
        Self {
            kind: value[0],
            material: [
                value[1], value[2], value[3], value[4], value[5], value[6], value[7], value[8],
                value[9], value[10], value[11], value[12], value[13], value[14], value[15],
                value[16],
            ],
        }
    }
}

/// Fixed steering map value.
///
/// Layout (8 bytes):
///
/// | offset | field            | meaning                                  |
/// |--------|------------------|------------------------------------------|
/// | 0..2   | owner_shard      | owner shard, big-endian                  |
/// | 2..6   | redirect_ifindex | target ifindex, big-endian; 0 = local    |
/// | 6..8   | flags            | `RULE_FLAG_*`, big-endian                |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpRuleValue {
    /// Owner shard.
    pub owner_shard: u16,
    /// Redirect target ifindex. Zero means local owner/pass-to-stack.
    pub redirect_ifindex: u32,
    /// Rule flags.
    pub flags: u16,
}

impl XdpRuleValue {
    /// Encode into the fixed map-value byte layout.
    #[must_use]
    pub const fn encode(&self) -> [u8; RULE_VALUE_LEN] {
        let shard = self.owner_shard.to_be_bytes();
        let ifindex = self.redirect_ifindex.to_be_bytes();
        let flags = self.flags.to_be_bytes();
        [
            shard[0], shard[1], ifindex[0], ifindex[1], ifindex[2], ifindex[3], flags[0], flags[1],
        ]
    }

    /// Decode from the fixed map-value byte layout.
    #[must_use]
    pub const fn decode(value: &[u8; RULE_VALUE_LEN]) -> Self {
        Self {
            owner_shard: u16::from_be_bytes([value[0], value[1]]),
            redirect_ifindex: u32::from_be_bytes([value[2], value[3], value[4], value[5]]),
            flags: u16::from_be_bytes([value[6], value[7]]),
        }
    }
}

/// Fixed tag-target map key.
///
/// The key is the routing tag extracted from the high bits of a responder IKE
/// SPI or inbound ESP SPI. Tags are precomputed by userspace and do not scale
/// with active SAs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpTagKey {
    /// Routing tag.
    pub tag: u16,
}

impl XdpTagKey {
    /// Encode into the fixed map-key byte layout.
    #[must_use]
    pub const fn encode(&self) -> [u8; TAG_TARGET_KEY_LEN] {
        self.tag.to_be_bytes()
    }

    /// Decode from the fixed map-key byte layout.
    #[must_use]
    pub const fn decode(value: &[u8; TAG_TARGET_KEY_LEN]) -> Self {
        Self {
            tag: u16::from_be_bytes([value[0], value[1]]),
        }
    }
}

/// Single-slot datapath configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpConfig {
    /// Number of high bits used as routing tag for IKE responder SPIs.
    pub ike_tag_bits: u8,
    /// Number of high bits used as routing tag for ESP SPIs.
    pub esp_tag_bits: u8,
    /// Reserved for future flags; must be zero for now.
    pub flags: u16,
}

impl XdpConfig {
    /// Encode into the fixed config byte layout.
    #[must_use]
    pub const fn encode(&self) -> [u8; CONFIG_VALUE_LEN] {
        let flags = self.flags.to_be_bytes();
        [self.ike_tag_bits, self.esp_tag_bits, flags[0], flags[1]]
    }

    /// Decode from the fixed config byte layout.
    #[must_use]
    pub const fn decode(value: &[u8; CONFIG_VALUE_LEN]) -> Self {
        Self {
            ike_tag_bits: value[0],
            esp_tag_bits: value[1],
            flags: u16::from_be_bytes([value[2], value[3]]),
        }
    }

    /// Extract the configured routing tag from a 64-bit IKE responder SPI.
    #[must_use]
    pub const fn ike_tag(&self, spi: u64) -> Option<u16> {
        extract_high_tag_u64(spi, self.ike_tag_bits)
    }

    /// Extract the configured routing tag from a 32-bit ESP SPI.
    #[must_use]
    pub const fn esp_tag(&self, spi: u32) -> Option<u16> {
        extract_high_tag_u32(spi, self.esp_tag_bits)
    }
}

const fn extract_high_tag_u64(value: u64, bits: u8) -> Option<u16> {
    if bits == 0 || bits > 16 || bits >= 64 {
        return None;
    }
    Some(((value >> (64 - bits)) & ((1_u64 << bits) - 1)) as u16)
}

const fn extract_high_tag_u32(value: u32, bits: u8) -> Option<u16> {
    if bits == 0 || bits > 16 || bits >= 32 {
        return None;
    }
    Some(((value >> (32 - bits)) & ((1_u32 << bits) - 1)) as u16)
}

/// FNV-1a offset basis for the stateless IKE_SA_INIT bootstrap tag.
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a prime for the stateless IKE_SA_INIT bootstrap tag.
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Compute the stateless bootstrap routing tag for an initial IKE_SA_INIT.
///
/// An initial IKE_SA_INIT has a zero responder SPI, so there is no allocated
/// tagged SPI to route on yet. This is the single source of truth shared by the
/// XDP datapath and the userspace classifier so both steer such a packet to the
/// same shard: FNV-1a over the big-endian initiator SPI followed by the source-IP
/// octets (4 for IPv4, 16 for IPv6), masked to `tag_bits` high-order tag slots.
/// Returns `None` for an out-of-range tag width.
#[must_use]
pub fn bootstrap_tag(initiator_spi: u64, source_ip_octets: &[u8], tag_bits: u8) -> Option<u16> {
    if tag_bits == 0 || tag_bits > 16 {
        return None;
    }
    let mut hash = FNV_OFFSET_BASIS;
    for byte in initiator_spi.to_be_bytes() {
        hash = fnv1a(hash, byte);
    }
    for &byte in source_ip_octets {
        hash = fnv1a(hash, byte);
    }
    Some((hash & ((1_u64 << tag_bits) - 1)) as u16)
}

const fn fnv1a(hash: u64, byte: u8) -> u64 {
    (hash ^ (byte as u64)).wrapping_mul(FNV_PRIME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steering_key_encoding_is_stable() {
        assert_eq!(
            XdpRuleKey::ike_responder_spi(0x0102_0304_0506_0708).encode(),
            [1, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            XdpRuleKey::esp_spi(0x99aa_bbcc).encode(),
            [2, 0x99, 0xaa, 0xbb, 0xcc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            XdpRuleKey::ike_init_ipv4(0x0102_0304_0506_0708, [198, 51, 100, 7]).encode(),
            [1 + 2, 1, 2, 3, 4, 5, 6, 7, 8, 198, 51, 100, 7, 0, 0, 0, 0]
        );
    }

    #[test]
    fn steering_value_encoding_is_stable() {
        let value = XdpRuleValue {
            owner_shard: 7,
            redirect_ifindex: 42,
            flags: RULE_FLAG_REDIRECT_IFINDEX,
        };
        let encoded = value.encode();
        assert_eq!(encoded, [0, 7, 0, 0, 0, 42, 0, 1]);
        assert_eq!(XdpRuleValue::decode(&encoded), value);
    }

    #[test]
    fn config_and_tag_target_encoding_are_stable() {
        let config = XdpConfig {
            ike_tag_bits: 8,
            esp_tag_bits: 6,
            flags: 0,
        };
        assert_eq!(config.encode(), [8, 6, 0, 0]);
        assert_eq!(XdpConfig::decode(&config.encode()), config);

        let key = XdpTagKey { tag: 0x03ff };
        assert_eq!(key.encode(), [0x03, 0xff]);
        assert_eq!(XdpTagKey::decode(&key.encode()), key);
    }

    #[test]
    fn bootstrap_tag_is_deterministic_masked_and_width_checked() {
        let a = bootstrap_tag(0x0102_0304_0506_0708, &[198, 51, 100, 7], 8);
        assert_eq!(
            a,
            bootstrap_tag(0x0102_0304_0506_0708, &[198, 51, 100, 7], 8)
        );
        assert!(a.unwrap() < 256);
        assert!(bootstrap_tag(0xdead_beef, &[203, 0, 113, 9], 4).unwrap() < 16);
        // IPv6 octets (16 bytes) are accepted too.
        assert!(bootstrap_tag(7, &[0x20; 16], 10).unwrap() < 1024);
        assert_eq!(bootstrap_tag(1, &[], 0), None);
        assert_eq!(bootstrap_tag(1, &[], 17), None);
    }

    #[test]
    fn tag_extraction_uses_high_order_bits() {
        let config = XdpConfig {
            ike_tag_bits: 8,
            esp_tag_bits: 4,
            flags: 0,
        };
        assert_eq!(config.ike_tag(0xab00_0000_0000_0001), Some(0xab));
        assert_eq!(config.esp_tag(0xc000_0001), Some(0x0c));
        assert_eq!(
            XdpConfig {
                ike_tag_bits: 17,
                esp_tag_bits: 4,
                flags: 0,
            }
            .ike_tag(1),
            None
        );
    }
}
