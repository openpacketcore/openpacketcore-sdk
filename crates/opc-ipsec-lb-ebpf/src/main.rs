//! XDP fast path for keyless SWu IKE/ESP classification and owner steering.
//!
//! The program executes the same branch-bounded decision procedure as the
//! userspace classifier (`classify_transport`, shared via
//! `opc-ipsec-lb-ebpf-common`): UDP/500 is IKE, UDP/4500 discriminates the
//! RFC 3948 non-ESP marker from ESP-in-UDP, IP protocol 50 is native ESP, and
//! everything else passes to the normal stack untouched.
//!
//! Classified packets are looked up in the pinned owner map keyed by the
//! canonical destination-scoped ownership key (destination address + routing
//! domain + encapsulation + SPI context). The verdict is fail-closed:
//!
//! - owner = self -> `XDP_PASS` (local counter);
//! - owner = remote -> `XDP_REDIRECT` into the dedicated userspace-redirector
//!   hand-off interface (redirect counter). In-kernel encapsulation of the
//!   authenticated steering transport is infeasible (AEAD crypto is a
//!   userspace concern), so the kernel/userspace split is this explicit,
//!   observable channel;
//! - map miss, stale ownership generation, unclassifiable packets, and
//!   internal errors -> `XDP_PASS` to the userspace slow path with a distinct
//!   counter each. The program never returns `XDP_DROP`.
//!
//! The program parses packet headers only: no map or program section can
//! carry IPsec key material.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action::XDP_PASS,
    helpers::bpf_redirect,
    macros::{map, xdp},
    maps::{Array, HashMap, PerCpuArray},
    programs::XdpContext,
};
use aya_ebpf_bindings::helpers::bpf_xdp_load_bytes;
use opc_ipsec_lb_ebpf_common::{
    classify_transport, decide_owner_verdict, ownership_map_key, verdict_counter,
    XdpDatapathConfig, XdpIpAddress, XdpTransportClass, XdpVerdict, CONFIG_VALUE_LEN,
    COUNTER_ERROR, COUNTER_NATT_KEEPALIVE, COUNTER_PASS_NON_SWU, COUNTER_SLOTS,
    COUNTER_UNCLASSIFIABLE, ESP_HEADER_PREFIX_LEN, ETH_HDR_LEN, ETH_P_IPV4, ETH_P_IPV6,
    IP_PROTOCOL_ESP, IP_PROTOCOL_UDP, MAX_INGRESS_IPV6_EXTENSION_HEADERS, OWNER_KEY_LEN,
    OWNER_VALUE_LEN, XDP_TRANSPORT_PROBE_LEN,
};

/// Pinned owner map keyed by the canonical destination-scoped ownership key.
#[map(name = "IPSEC_LB_OWNERS")]
static IPSEC_LB_OWNERS: HashMap<[u8; OWNER_KEY_LEN], [u8; OWNER_VALUE_LEN]> =
    HashMap::pinned(65536, 0);

/// Single-slot datapath config.
#[map(name = "IPSEC_LB_CONFIG")]
static IPSEC_LB_CONFIG: Array<[u8; CONFIG_VALUE_LEN]> = Array::pinned(1, 0);

/// Per-CPU per-verdict counters.
#[map(name = "IPSEC_LB_COUNTERS")]
static IPSEC_LB_COUNTERS: PerCpuArray<u64> = PerCpuArray::pinned(COUNTER_SLOTS, 0);

const IPV4_MIN_HDR_LEN: usize = 20;
const IPV6_HDR_LEN: usize = 40;
const IPV4_TOTAL_LEN_OFFSET: usize = 2;
const IPV4_FRAG_OFFSET: usize = 6;
const IPV4_PROTOCOL_OFFSET: usize = 9;
const IPV4_SOURCE_OFFSET: usize = 12;
const IPV4_DESTINATION_OFFSET: usize = 16;
const IPV6_NEXT_HEADER_OFFSET: usize = 6;
const IPV6_PAYLOAD_LEN_OFFSET: usize = 4;
const IPV6_SOURCE_OFFSET: usize = 8;
const IPV6_DESTINATION_OFFSET: usize = 24;
const IPV4_FRAG_OFFSET_MASK: u16 = 0x1fff;
const IPV4_MORE_FRAGMENTS_MASK: u16 = 0x2000;
const IPV6_NEXT_HEADER_HOP: u8 = 0;
const IPV6_NEXT_HEADER_ROUTING: u8 = 43;
const IPV6_NEXT_HEADER_FRAGMENT: u8 = 44;
const IPV6_NEXT_HEADER_AH: u8 = 51;
const IPV6_NEXT_HEADER_DEST: u8 = 60;
const IPV6_FRAGMENT_LEN: usize = 8;
const IPV6_FRAG_VALUE_MASK: u16 = 0xfff9;

#[xdp]
pub fn opc_ipsec_lb_xdp(ctx: XdpContext) -> u32 {
    steer(&ctx)
}

#[inline(always)]
fn steer(ctx: &XdpContext) -> u32 {
    let eth_proto = match load::<u16>(ctx, 12) {
        Some(value) => u16::from_be(value),
        None => return counted_pass(COUNTER_UNCLASSIFIABLE),
    };
    match eth_proto {
        ETH_P_IPV4 => steer_ipv4(ctx),
        ETH_P_IPV6 => steer_ipv6(ctx),
        _ => counted_pass(COUNTER_PASS_NON_SWU),
    }
}

#[inline(always)]
fn steer_ipv4(ctx: &XdpContext) -> u32 {
    // One up-front bounds proof covers every fixed-header read from the
    // copied window.
    let Some(header) = read_window::<{ ETH_HDR_LEN + IPV4_MIN_HDR_LEN }>(ctx) else {
        return counted_pass(COUNTER_UNCLASSIFIABLE);
    };
    let version_ihl = header[ETH_HDR_LEN];
    if version_ihl >> 4 != 4 {
        return counted_pass(COUNTER_UNCLASSIFIABLE);
    }
    let ip_header_len = usize::from(version_ihl & 0x0f) * 4;
    if ip_header_len < IPV4_MIN_HDR_LEN {
        return counted_pass(COUNTER_UNCLASSIFIABLE);
    }
    let total_len = usize::from(u16::from_be_bytes([
        header[ETH_HDR_LEN + IPV4_TOTAL_LEN_OFFSET],
        header[ETH_HDR_LEN + IPV4_TOTAL_LEN_OFFSET + 1],
    ]));
    if total_len < ip_header_len || ETH_HDR_LEN + total_len > packet_len(ctx) {
        return counted_pass(COUNTER_UNCLASSIFIABLE);
    }
    let fragment = u16::from_be_bytes([
        header[ETH_HDR_LEN + IPV4_FRAG_OFFSET],
        header[ETH_HDR_LEN + IPV4_FRAG_OFFSET + 1],
    ]);
    if fragment & (IPV4_FRAG_OFFSET_MASK | IPV4_MORE_FRAGMENTS_MASK) != 0 {
        // IP fragmentation is handed to the slow path fail-closed.
        return counted_pass(COUNTER_UNCLASSIFIABLE);
    }
    let protocol = header[ETH_HDR_LEN + IPV4_PROTOCOL_OFFSET];
    if protocol != IP_PROTOCOL_UDP && protocol != IP_PROTOCOL_ESP {
        return counted_pass(COUNTER_PASS_NON_SWU);
    }
    let source: [u8; 4] = header[ETH_HDR_LEN + IPV4_SOURCE_OFFSET..ETH_HDR_LEN + 20]
        .try_into()
        .unwrap_or([0; 4]);
    let destination: [u8; 4] = header[ETH_HDR_LEN + IPV4_DESTINATION_OFFSET..]
        .try_into()
        .unwrap_or([0; 4]);
    steer_transport(
        ctx,
        protocol,
        ETH_HDR_LEN + ip_header_len,
        total_len - ip_header_len,
        XdpIpAddress::V4(source),
        XdpIpAddress::V4(destination),
    )
}

#[inline(always)]
fn steer_ipv6(ctx: &XdpContext) -> u32 {
    // One up-front bounds proof covers every fixed-header read from the
    // copied window.
    let Some(header) = read_window::<{ ETH_HDR_LEN + IPV6_HDR_LEN }>(ctx) else {
        return counted_pass(COUNTER_UNCLASSIFIABLE);
    };
    if header[ETH_HDR_LEN] >> 4 != 6 {
        return counted_pass(COUNTER_UNCLASSIFIABLE);
    }
    let payload_len = usize::from(u16::from_be_bytes([
        header[ETH_HDR_LEN + IPV6_PAYLOAD_LEN_OFFSET],
        header[ETH_HDR_LEN + IPV6_PAYLOAD_LEN_OFFSET + 1],
    ]));
    if ETH_HDR_LEN + IPV6_HDR_LEN + payload_len > packet_len(ctx) {
        return counted_pass(COUNTER_UNCLASSIFIABLE);
    }
    let mut protocol = header[ETH_HDR_LEN + IPV6_NEXT_HEADER_OFFSET];
    let mut cursor = ETH_HDR_LEN + IPV6_HDR_LEN;
    let packet_end = ETH_HDR_LEN + IPV6_HDR_LEN + payload_len;
    let mut extension_count = 0usize;
    while is_ipv6_extension_header(protocol) {
        if extension_count == MAX_INGRESS_IPV6_EXTENSION_HEADERS {
            return counted_pass(COUNTER_UNCLASSIFIABLE);
        }
        if cursor + IPV6_FRAGMENT_LEN > packet_end {
            return counted_pass(COUNTER_UNCLASSIFIABLE);
        }
        let Some(extension) = read_bytes::<8>(ctx, cursor) else {
            return counted_pass(COUNTER_UNCLASSIFIABLE);
        };
        let Some(extension_len) = extension_header_len(protocol, &extension) else {
            return counted_pass(COUNTER_UNCLASSIFIABLE);
        };
        if cursor + extension_len > packet_end {
            return counted_pass(COUNTER_UNCLASSIFIABLE);
        }
        protocol = extension[0];
        cursor += extension_len;
        extension_count += 1;
    }
    if protocol != IP_PROTOCOL_UDP && protocol != IP_PROTOCOL_ESP {
        return counted_pass(COUNTER_PASS_NON_SWU);
    }
    let source: [u8; 16] = header[ETH_HDR_LEN + IPV6_SOURCE_OFFSET..ETH_HDR_LEN + 24]
        .try_into()
        .unwrap_or([0; 16]);
    let destination: [u8; 16] = header[ETH_HDR_LEN + IPV6_DESTINATION_OFFSET..]
        .try_into()
        .unwrap_or([0; 16]);
    steer_transport(
        ctx,
        protocol,
        cursor,
        packet_end - cursor,
        XdpIpAddress::V6(source),
        XdpIpAddress::V6(destination),
    )
}

/// Copy the first N packet bytes after proving they are all present.
#[inline(always)]
fn read_window<const N: usize>(ctx: &XdpContext) -> Option<[u8; N]> {
    let start = ctx.data();
    if start.checked_add(N)? > ctx.data_end() {
        return None;
    }
    let mut window = [0_u8; N];
    let mut index = 0usize;
    while index < N {
        // SAFETY: the check above proves all N bytes are inside the packet.
        window[index] = unsafe { *(start as *const u8).add(index) };
        index += 1;
    }
    Some(window)
}

/// Compute one IPv6 extension header's length from its copied 8-byte prefix,
/// rejecting fragments and malformed AH headers fail-closed.
#[inline(always)]
fn extension_header_len(next_header: u8, extension: &[u8; 8]) -> Option<usize> {
    if next_header == IPV6_NEXT_HEADER_FRAGMENT {
        let fragment = u16::from_be_bytes([extension[2], extension[3]]);
        if fragment & IPV6_FRAG_VALUE_MASK != 0 {
            // Non-initial fragments and incomplete chains go to the slow path.
            return None;
        }
        return Some(IPV6_FRAGMENT_LEN);
    }
    let len_octets = extension[1];
    if next_header == IPV6_NEXT_HEADER_AH {
        if len_octets < 1 {
            return None;
        }
        return Some((usize::from(len_octets) + 2) * 4);
    }
    Some((usize::from(len_octets) + 1) * 8)
}

/// Copy N packet bytes at `offset` through the `bpf_xdp_load_bytes` helper,
/// which performs its own bounds enforcement.
#[inline(always)]
fn read_bytes<const N: usize>(ctx: &XdpContext, offset: usize) -> Option<[u8; N]> {
    let mut buffer = [0_u8; N];
    // SAFETY: the helper validates the packet range and writes at most N
    // bytes into the stack buffer.
    let result = unsafe {
        bpf_xdp_load_bytes(
            ctx.ctx,
            offset as u32,
            buffer.as_mut_ptr().cast(),
            N as u32,
        )
    };
    if result != 0 {
        return None;
    }
    Some(buffer)
}

#[inline(always)]
fn is_ipv6_extension_header(next_header: u8) -> bool {
    matches!(
        next_header,
        IPV6_NEXT_HEADER_HOP
            | IPV6_NEXT_HEADER_ROUTING
            | IPV6_NEXT_HEADER_FRAGMENT
            | IPV6_NEXT_HEADER_AH
            | IPV6_NEXT_HEADER_DEST
    )
}

#[inline(always)]
fn steer_transport(
    ctx: &XdpContext,
    protocol: u8,
    transport_offset: usize,
    declared_transport_len: usize,
    source: XdpIpAddress,
    destination: XdpIpAddress,
) -> u32 {
    let available_len = packet_len(ctx).checked_sub(transport_offset);
    let Some(available_len) = available_len else {
        return counted_pass(COUNTER_UNCLASSIFIABLE);
    };
    if available_len < declared_transport_len {
        return counted_pass(COUNTER_UNCLASSIFIABLE);
    }
    let probe_len = if available_len < XDP_TRANSPORT_PROBE_LEN {
        available_len
    } else {
        XDP_TRANSPORT_PROBE_LEN
    };
    // A transport shorter than a UDP or ESP header prefix is unclassifiable
    // without invoking the helper (which rejects zero-sized reads).
    if probe_len < ESP_HEADER_PREFIX_LEN {
        return counted_pass(COUNTER_UNCLASSIFIABLE);
    }
    let mut probe = [0_u8; XDP_TRANSPORT_PROBE_LEN];
    // SAFETY: the helper validates the packet range and writes at most
    // probe_len bytes into the stack buffer.
    let result = unsafe {
        bpf_xdp_load_bytes(
            ctx.ctx,
            transport_offset as u32,
            probe.as_mut_ptr().cast(),
            probe_len as u32,
        )
    };
    if result != 0 {
        return counted_pass(COUNTER_UNCLASSIFIABLE);
    }

    let class = classify_transport(protocol, &probe, available_len, declared_transport_len);
    match class {
        XdpTransportClass::NonSwu => counted_pass(COUNTER_PASS_NON_SWU),
        XdpTransportClass::NatKeepalive => counted_pass(COUNTER_NATT_KEEPALIVE),
        XdpTransportClass::Unclassifiable => counted_pass(COUNTER_UNCLASSIFIABLE),
        identity => {
            let Some(config_ptr) = IPSEC_LB_CONFIG.get_ptr(0) else {
                return counted_pass(COUNTER_ERROR);
            };
            // SAFETY: config map value lives for the duration of this program invocation.
            let Some(config) = XdpDatapathConfig::decode(unsafe { &*config_ptr }) else {
                return counted_pass(COUNTER_ERROR);
            };
            let source_port = u16::from_be_bytes([probe[0], probe[1]]);
            let Some(key) = ownership_map_key(
                &identity,
                source,
                source_port,
                destination,
                config.routing_domain,
            ) else {
                return counted_pass(COUNTER_UNCLASSIFIABLE);
            };
            let entry = IPSEC_LB_OWNERS.get_ptr(&key).map(|ptr| {
                // SAFETY: map value lives for the duration of this program invocation.
                unsafe { *ptr }
            });
            let verdict = decide_owner_verdict(entry, &config);
            count(verdict_counter(verdict));
            match verdict {
                XdpVerdict::RedirectHandoff => {
                    // SAFETY: helper does not dereference pointers; the ifindex
                    // is a scalar from the validated config.
                    unsafe { bpf_redirect(config.handoff_ifindex, 0) as u32 }
                }
                XdpVerdict::Local
                | XdpVerdict::SlowPathMiss
                | XdpVerdict::SlowPathStale
                | XdpVerdict::SlowPathError => XDP_PASS,
            }
        }
    }
}

#[inline(always)]
fn packet_len(ctx: &XdpContext) -> usize {
    ctx.data_end() - ctx.data()
}

#[inline(always)]
fn counted_pass(index: u32) -> u32 {
    count(index);
    XDP_PASS
}

#[inline(always)]
fn count(index: u32) {
    if let Some(counter) = IPSEC_LB_COUNTERS.get_ptr_mut(index) {
        // SAFETY: per-CPU slot; no concurrent access on the same CPU.
        unsafe { *counter += 1 };
    }
}

#[inline(always)]
fn load<T: Copy>(ctx: &XdpContext, offset: usize) -> Option<T> {
    let start = ctx.data().checked_add(offset)?;
    let end = start.checked_add(core::mem::size_of::<T>())?;
    if end > ctx.data_end() {
        return None;
    }
    // SAFETY: bounds above prove the object is inside packet data; unaligned
    // reads are required for network headers.
    Some(unsafe { core::ptr::read_unaligned(start as *const T) })
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
