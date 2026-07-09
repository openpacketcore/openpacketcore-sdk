//! XDP datapath for SWu IKE/IPsec steering.
//!
//! The program is steer-only: it parses enough Ethernet/IP/UDP/IKE/ESP header
//! bytes to select a local pass or cross-node redirect target. It never
//! decrypts ESP and has no map that can carry IPsec key material.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action::{XDP_DROP, XDP_PASS},
    helpers::bpf_redirect,
    macros::{map, xdp},
    maps::{Array, HashMap, PerCpuArray},
    programs::XdpContext,
};
use opc_ipsec_lb_ebpf_common::{
    bootstrap_tag, XdpConfig, XdpRuleKey, XdpRuleValue, XdpTagKey, CONFIG_VALUE_LEN,
    COUNTER_DROP_MALFORMED,
    COUNTER_LOCAL_OWNER, COUNTER_MISS, COUNTER_NATT_KEEPALIVE, COUNTER_PASS_NON_SWU,
    COUNTER_REDIRECT, COUNTER_SLOTS, ESP_HEADER_PREFIX_LEN, ETH_HDR_LEN, ETH_P_IPV4, ETH_P_IPV6,
    IKEV2_EXCHANGE_IKE_SA_INIT, IKEV2_HDR_LEN, IKEV2_MAJOR_VERSION, NAT_T_KEEPALIVE,
    NON_ESP_MARKER, RULE_FLAG_LOCAL_OWNER, RULE_FLAG_REDIRECT_IFINDEX, RULE_KEY_LEN,
    RULE_VALUE_LEN, TAG_TARGET_KEY_LEN, UDP_HDR_LEN, UDP_PORT_IKE, UDP_PORT_IKE_NATT,
};

/// Per-SPI override rules for post-failover exceptions.
#[map(name = "IPSEC_LB_RULES")]
static IPSEC_LB_RULES: HashMap<[u8; RULE_KEY_LEN], [u8; RULE_VALUE_LEN]> =
    HashMap::pinned(65536, 0);

/// Precomputed routing-tag target table. This is O(tags), not O(flows).
#[map(name = "IPSEC_LB_TAG_TARGETS")]
static IPSEC_LB_TAG_TARGETS: HashMap<[u8; TAG_TARGET_KEY_LEN], [u8; RULE_VALUE_LEN]> =
    HashMap::pinned(65536, 0);

/// Single-slot datapath config.
#[map(name = "IPSEC_LB_CONFIG")]
static IPSEC_LB_CONFIG: Array<[u8; CONFIG_VALUE_LEN]> = Array::pinned(1, 0);

/// Per-CPU counters.
#[map(name = "IPSEC_LB_COUNTERS")]
static IPSEC_LB_COUNTERS: PerCpuArray<u64> = PerCpuArray::pinned(COUNTER_SLOTS, 0);

const IPV4_PROTO_UDP: u8 = 17;
const IPV6_NEXT_HEADER_FRAGMENT: u8 = 44;
const IPV6_NEXT_HEADER_HOP: u8 = 0;
const IPV6_NEXT_HEADER_ROUTING: u8 = 43;
const IPV6_NEXT_HEADER_DEST: u8 = 60;
const IPV4_FRAG_MASK: u16 = 0x3fff;

#[xdp]
pub fn opc_ipsec_lb_xdp(ctx: XdpContext) -> u32 {
    match try_xdp(&ctx) {
        Ok(action) => action,
        Err(()) => {
            count(COUNTER_DROP_MALFORMED);
            XDP_DROP
        }
    }
}

fn try_xdp(ctx: &XdpContext) -> Result<u32, ()> {
    let eth_proto = u16::from_be(load(ctx, 12)?);
    match eth_proto {
        ETH_P_IPV4 => steer_ipv4(ctx),
        ETH_P_IPV6 => steer_ipv6(ctx),
        _ => {
            count(COUNTER_PASS_NON_SWU);
            Ok(XDP_PASS)
        }
    }
}

fn steer_ipv4(ctx: &XdpContext) -> Result<u32, ()> {
    let version_ihl: u8 = load(ctx, ETH_HDR_LEN)?;
    if version_ihl >> 4 != 4 {
        count(COUNTER_PASS_NON_SWU);
        return Ok(XDP_PASS);
    }
    let ip_header_len = usize::from(version_ihl & 0x0f) * 4;
    if ip_header_len < 20 {
        return Err(());
    }
    let protocol: u8 = load(ctx, ETH_HDR_LEN + 9)?;
    if protocol != IPV4_PROTO_UDP {
        count(COUNTER_PASS_NON_SWU);
        return Ok(XDP_PASS);
    }
    let frag = u16::from_be(load(ctx, ETH_HDR_LEN + 6)?);
    if frag & IPV4_FRAG_MASK != 0 {
        return Err(());
    }
    let source_ip: [u8; 4] = load(ctx, ETH_HDR_LEN + 12)?;
    steer_udp(ctx, ETH_HDR_LEN + ip_header_len, IpSource::V4(source_ip))
}

fn steer_ipv6(ctx: &XdpContext) -> Result<u32, ()> {
    let version: u8 = load(ctx, ETH_HDR_LEN)?;
    if version >> 4 != 6 {
        count(COUNTER_PASS_NON_SWU);
        return Ok(XDP_PASS);
    }
    let next_header: u8 = load(ctx, ETH_HDR_LEN + 6)?;
    match next_header {
        IPV4_PROTO_UDP => {
            let source_ip: [u8; 16] = load(ctx, ETH_HDR_LEN + 8)?;
            steer_udp(ctx, ETH_HDR_LEN + 40, IpSource::V6(source_ip))
        }
        IPV6_NEXT_HEADER_FRAGMENT
        | IPV6_NEXT_HEADER_HOP
        | IPV6_NEXT_HEADER_ROUTING
        | IPV6_NEXT_HEADER_DEST => Err(()),
        _ => {
            count(COUNTER_PASS_NON_SWU);
            Ok(XDP_PASS)
        }
    }
}

fn steer_udp(ctx: &XdpContext, udp_offset: usize, source_ip: IpSource) -> Result<u32, ()> {
    let dport = u16::from_be(load(ctx, udp_offset + 2)?);
    let payload_offset = udp_offset + UDP_HDR_LEN;
    match dport {
        UDP_PORT_IKE => steer_ike(ctx, payload_offset, source_ip),
        UDP_PORT_IKE_NATT => steer_udp_4500(ctx, payload_offset, source_ip),
        _ => {
            count(COUNTER_PASS_NON_SWU);
            Ok(XDP_PASS)
        }
    }
}

fn steer_udp_4500(ctx: &XdpContext, payload_offset: usize, source_ip: IpSource) -> Result<u32, ()> {
    let first: u8 = load(ctx, payload_offset)?;
    if first == NAT_T_KEEPALIVE && payload_offset + 1 == ctx.data_end() - ctx.data() {
        count(COUNTER_NATT_KEEPALIVE);
        return Ok(XDP_DROP);
    }
    let marker: [u8; 4] = load(ctx, payload_offset)?;
    if marker == NON_ESP_MARKER {
        return steer_ike(ctx, payload_offset + NON_ESP_MARKER.len(), source_ip);
    }
    let spi = u32::from_be(load(ctx, payload_offset)?);
    if spi == 0 {
        return Err(());
    }
    let _sequence: u32 = load(ctx, payload_offset + 4)?;
    let _ = ESP_HEADER_PREFIX_LEN;
    let config = read_config()?;
    let key = XdpRuleKey::esp_spi(spi).encode();
    if let Some(action) = override_action(&key)? {
        return Ok(action);
    }
    let tag = config.esp_tag(spi).ok_or(())?;
    tag_action(tag)
}

fn steer_ike(ctx: &XdpContext, ike_offset: usize, source_ip: IpSource) -> Result<u32, ()> {
    let initiator_spi = u64::from_be(load(ctx, ike_offset)?);
    let responder_spi = u64::from_be(load(ctx, ike_offset + 8)?);
    let version: u8 = load(ctx, ike_offset + 17)?;
    if version >> 4 != IKEV2_MAJOR_VERSION {
        return Err(());
    }
    let exchange_type: u8 = load(ctx, ike_offset + 18)?;
    let declared_len = u32::from_be(load(ctx, ike_offset + 24)?) as usize;
    if declared_len < IKEV2_HDR_LEN || ike_offset + declared_len > ctx.data_end() - ctx.data() {
        return Err(());
    }

    let config = read_config()?;
    if responder_spi == 0 {
        if exchange_type != IKEV2_EXCHANGE_IKE_SA_INIT {
            return Err(());
        }
        // Shared with the userspace classifier via `ebpf_common::bootstrap_tag`
        // so both steer an initial IKE_SA_INIT to the same shard.
        let tag = match source_ip {
            IpSource::V4(octets) => bootstrap_tag(initiator_spi, &octets, config.ike_tag_bits),
            IpSource::V6(octets) => bootstrap_tag(initiator_spi, &octets, config.ike_tag_bits),
        }
        .ok_or(())?;
        return tag_action(tag);
    }

    let key = XdpRuleKey::ike_responder_spi(responder_spi).encode();
    if let Some(action) = override_action(&key)? {
        return Ok(action);
    }
    let tag = config.ike_tag(responder_spi).ok_or(())?;
    tag_action(tag)
}

fn read_config() -> Result<XdpConfig, ()> {
    let Some(config_ptr) = IPSEC_LB_CONFIG.get_ptr(0) else {
        return Err(());
    };
    // SAFETY: config map value lives for the duration of this program invocation.
    let config = XdpConfig::decode(unsafe { &*config_ptr });
    if config.flags != 0 {
        return Err(());
    }
    Ok(config)
}

fn override_action(key: &[u8; RULE_KEY_LEN]) -> Result<Option<u32>, ()> {
    let Some(value_ptr) = IPSEC_LB_RULES.get_ptr(key) else {
        return Ok(None);
    };
    // SAFETY: map value lives for the duration of this program invocation.
    Ok(Some(apply_value(XdpRuleValue::decode(unsafe {
        &*value_ptr
    }))))
}

fn tag_action(tag: u16) -> Result<u32, ()> {
    let key = XdpTagKey { tag }.encode();
    let Some(value_ptr) = IPSEC_LB_TAG_TARGETS.get_ptr(&key) else {
        count(COUNTER_MISS);
        return Ok(XDP_DROP);
    };
    // SAFETY: map value lives for the duration of this program invocation.
    Ok(apply_value(XdpRuleValue::decode(unsafe { &*value_ptr })))
}

fn apply_value(value: XdpRuleValue) -> u32 {
    if value.flags & RULE_FLAG_LOCAL_OWNER != 0 {
        count(COUNTER_LOCAL_OWNER);
        return XDP_PASS;
    }
    if value.flags & RULE_FLAG_REDIRECT_IFINDEX != 0 && value.redirect_ifindex != 0 {
        count(COUNTER_REDIRECT);
        // SAFETY: helper does not dereference pointers; ifindex and flags are scalars.
        return unsafe { bpf_redirect(value.redirect_ifindex, 0) as u32 };
    }
    count(COUNTER_DROP_MALFORMED);
    XDP_DROP
}

fn count(index: u32) {
    if let Some(counter) = IPSEC_LB_COUNTERS.get_ptr_mut(index) {
        // SAFETY: per-CPU slot; no concurrent access on the same CPU.
        unsafe { *counter += 1 };
    }
}

fn load<T: Copy>(ctx: &XdpContext, offset: usize) -> Result<T, ()> {
    let start = ctx.data().checked_add(offset).ok_or(())?;
    let end = start.checked_add(core::mem::size_of::<T>()).ok_or(())?;
    if end > ctx.data_end() {
        return Err(());
    }
    // SAFETY: bounds above prove the object is inside packet data; unaligned
    // reads are required for network headers.
    Ok(unsafe { core::ptr::read_unaligned(start as *const T) })
}

#[derive(Clone, Copy)]
enum IpSource {
    V4([u8; 4]),
    V6([u8; 16]),
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
