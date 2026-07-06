//! tc clsact GTP-U datapath for the ePDG S2b-U interface (TS 29.281).
//!
//! Two programs attach to the PGW-facing (S2b-U) interface:
//!
//! - `opc_gtpu_uplink` (tc egress): looks up the uplink FAR by the inner IPv4
//!   source (the UE PAA) and GTP-U-encapsulates the packet toward the PGW.
//!   FAR miss passes the packet through untouched.
//! - `opc_gtpu_downlink` (tc ingress): matches UDP/2152 GTPv1-U G-PDUs, looks
//!   up the downlink PDR by TEID, validates the inner packet, and strips the
//!   outer IPv4/UDP/GTP-U headers so the inner packet continues up the stack
//!   (and through the ePDG's XFRM output policy). Unknown-TEID G-PDUs are
//!   dropped and counted; non-G-PDU GTP-U (echo, error indication) passes
//!   through to the control plane.
//!
//! Byte layouts live in `opc-gtpu-ebpf-common` and are shared with the
//! userspace loader in `opc-gtpu-dataplane`.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{
        bpf_adj_room_mode::BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_ENCAP_L3_IPV4,
        BPF_F_ADJ_ROOM_ENCAP_L4_UDP, TC_ACT_OK, TC_ACT_SHOT,
    },
    helpers::bpf_redirect_neigh,
    macros::{classifier, map},
    maps::{Array, HashMap, PerCpuArray},
    programs::TcContext,
};
use opc_gtpu_ebpf_common::{
    build_uplink_encap, classify_gtpu, DownlinkPdr, GtpuClass, UplinkFar, COUNTER_DL_DECAP,
    COUNTER_DL_DST_MISMATCH, COUNTER_DL_MALFORMED, COUNTER_DL_UNKNOWN_TEID, COUNTER_SLOTS,
    COUNTER_UL_ENCAP, COUNTER_UL_FAR_MISS, DOWNLINK_PDR_VALUE_LEN, ETH_HDR_LEN, ETH_P_IPV4,
    GTPU_MANDATORY_HDR_LEN, GTPU_MAX_EXT_HEADERS, GTPU_OPT_LEN, GTPU_UDP_PORT,
    UPLINK_FAR_VALUE_LEN,
};

/// Uplink FAR: UE PAA (IPv4, network order) -> encap state.
#[map]
static GTPU_UPLINK_FAR: HashMap<[u8; 4], [u8; UPLINK_FAR_VALUE_LEN]> = HashMap::pinned(65536, 0);

/// Downlink PDR: local S2b-U TEID (network order) -> UE PAA.
#[map]
static GTPU_DOWNLINK_PDR: HashMap<[u8; 4], [u8; DOWNLINK_PDR_VALUE_LEN]> =
    HashMap::pinned(65536, 0);

/// Per-CPU datapath counters, indexed by the COUNTER_* constants.
#[map]
static GTPU_COUNTERS: PerCpuArray<u64> = PerCpuArray::pinned(COUNTER_SLOTS, 0);

/// Single-slot device configuration: slot 0 holds the local S2b-U IPv4
/// (network order), used as the outer source when a FAR carries 0.0.0.0 and
/// read back by the loader on restore.
#[map]
static GTPU_CONFIG: Array<[u8; 4]> = Array::pinned(1, 0);

const IPV4_PROTO_UDP: u8 = 17;
const IPV4_FRAG_MASK: u16 = 0x3FFF; // MF bit + fragment offset

#[inline(always)]
fn count(index: u32) {
    if let Some(counter) = GTPU_COUNTERS.get_ptr_mut(index) {
        // SAFETY: per-CPU slot; no concurrent access on the same CPU.
        unsafe { *counter += 1 };
    }
}

#[classifier]
pub fn opc_gtpu_uplink(mut ctx: TcContext) -> i32 {
    try_uplink(&mut ctx).unwrap_or(TC_ACT_OK as i32)
}

#[classifier]
pub fn opc_gtpu_downlink(mut ctx: TcContext) -> i32 {
    try_downlink(&mut ctx).unwrap_or(TC_ACT_OK as i32)
}

/// Uplink: inner IPv4 packet routed to the S2b-U interface with
/// `src = UE PAA`. Prepend `[outer IPv4][UDP][GTPv1-U]` and re-resolve the
/// L2 next hop for the new outer destination.
fn try_uplink(ctx: &mut TcContext) -> Result<i32, ()> {
    let eth_proto = u16::from_be(ctx.load(12).map_err(|_| ())?);
    if eth_proto != ETH_P_IPV4 {
        return Ok(TC_ACT_OK as i32);
    }
    let version_ihl: u8 = ctx.load(ETH_HDR_LEN).map_err(|_| ())?;
    if version_ihl >> 4 != 4 {
        return Ok(TC_ACT_OK as i32);
    }

    let inner_src: [u8; 4] = ctx.load(ETH_HDR_LEN + 12).map_err(|_| ())?;
    let Some(far_ptr) = GTPU_UPLINK_FAR.get_ptr(&inner_src) else {
        count(COUNTER_UL_FAR_MISS);
        return Ok(TC_ACT_OK as i32);
    };
    // SAFETY: the map value outlives this program invocation and is only
    // read here.
    let mut far = UplinkFar::decode(unsafe { &*far_ptr });
    if far.local_ip == [0, 0, 0, 0] {
        if let Some(local_ip) = GTPU_CONFIG.get_ptr(0) {
            // SAFETY: single-slot array value written only by the loader.
            far.local_ip = unsafe { *local_ip };
        }
    }

    let inner_len = (ctx.len() as usize).saturating_sub(ETH_HDR_LEN);
    let inner_len = u16::try_from(inner_len).map_err(|_| ())?;
    let encap = build_uplink_encap(&far, inner_len).ok_or(())?;

    ctx.skb
        .adjust_room(
            encap.len() as i32,
            BPF_ADJ_ROOM_MAC,
            u64::from(BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP),
        )
        .map_err(|_| ())?;
    ctx.store(ETH_HDR_LEN, &encap, 0).map_err(|_| ())?;
    count(COUNTER_UL_ENCAP);

    // The frame's L2 destination was resolved for the inner route; the outer
    // destination is the PGW. Re-run FIB/neighbour resolution for the new
    // outer header. The re-emitted frame traverses this egress hook once
    // more, misses the FAR (outer src is not a UE PAA), and passes through.
    // SAFETY: helper takes no pointers when plen == 0.
    let ret = unsafe { bpf_redirect_neigh((*ctx.skb.skb).ifindex, core::ptr::null_mut(), 0, 0) };
    Ok(ret as i32)
}

/// Downlink: GTPv1-U G-PDU from the PGW on UDP/2152. Validate, look up the
/// PDR by TEID, strip the outer headers, and hand the inner packet to the
/// stack so routing and the XFRM output policy toward the UE apply.
fn try_downlink(ctx: &mut TcContext) -> Result<i32, ()> {
    let eth_proto = u16::from_be(ctx.load(12).map_err(|_| ())?);
    if eth_proto != ETH_P_IPV4 {
        return Ok(TC_ACT_OK as i32);
    }
    let version_ihl: u8 = ctx.load(ETH_HDR_LEN).map_err(|_| ())?;
    if version_ihl >> 4 != 4 {
        return Ok(TC_ACT_OK as i32);
    }
    let ip_header_len = usize::from(version_ihl & 0x0F) * 4;
    if ip_header_len < 20 {
        return Ok(TC_ACT_OK as i32);
    }
    let frag = u16::from_be(ctx.load(ETH_HDR_LEN + 6).map_err(|_| ())?);
    if frag & IPV4_FRAG_MASK != 0 {
        // Fragmented outer packets go to the stack for reassembly.
        return Ok(TC_ACT_OK as i32);
    }
    let protocol: u8 = ctx.load(ETH_HDR_LEN + 9).map_err(|_| ())?;
    if protocol != IPV4_PROTO_UDP {
        return Ok(TC_ACT_OK as i32);
    }

    let l4_offset = ETH_HDR_LEN + ip_header_len;
    let dport = u16::from_be(ctx.load(l4_offset + 2).map_err(|_| ())?);
    if dport != GTPU_UDP_PORT {
        return Ok(TC_ACT_OK as i32);
    }

    let gtp_offset = l4_offset + 8;
    let Ok(gtp_header) = ctx.load::<[u8; GTPU_MANDATORY_HDR_LEN]>(gtp_offset) else {
        count(COUNTER_DL_MALFORMED);
        return Ok(TC_ACT_SHOT as i32);
    };
    let (teid, gtp_length, has_opt, has_ext) = match classify_gtpu(&gtp_header) {
        GtpuClass::NotGtpV1 | GtpuClass::NotGpdu => return Ok(TC_ACT_OK as i32),
        GtpuClass::Gpdu {
            teid,
            length,
            has_opt,
            has_ext,
        } => (teid, length, has_opt, has_ext),
    };

    // Everything after the mandatory 8 bytes (optional block, extension
    // headers, T-PDU) must be covered by the GTP-U length field and present
    // in the packet.
    let gtp_end = gtp_offset + GTPU_MANDATORY_HDR_LEN + usize::from(gtp_length);
    if gtp_end > ctx.len() as usize {
        count(COUNTER_DL_MALFORMED);
        return Ok(TC_ACT_SHOT as i32);
    }

    let mut payload_offset = gtp_offset + GTPU_MANDATORY_HDR_LEN;
    if has_opt {
        let Ok(opt) = ctx.load::<[u8; GTPU_OPT_LEN]>(payload_offset) else {
            count(COUNTER_DL_MALFORMED);
            return Ok(TC_ACT_SHOT as i32);
        };
        payload_offset += GTPU_OPT_LEN;
        if has_ext {
            let mut next_ext = opt[3];
            let mut walked = 0;
            while next_ext != 0 {
                if walked == GTPU_MAX_EXT_HEADERS || payload_offset >= gtp_end {
                    count(COUNTER_DL_MALFORMED);
                    return Ok(TC_ACT_SHOT as i32);
                }
                let Ok(ext_len_units) = ctx.load::<u8>(payload_offset) else {
                    count(COUNTER_DL_MALFORMED);
                    return Ok(TC_ACT_SHOT as i32);
                };
                if ext_len_units == 0 {
                    count(COUNTER_DL_MALFORMED);
                    return Ok(TC_ACT_SHOT as i32);
                }
                let ext_len = usize::from(ext_len_units) * 4;
                let Ok(next) = ctx.load::<u8>(payload_offset + ext_len - 1) else {
                    count(COUNTER_DL_MALFORMED);
                    return Ok(TC_ACT_SHOT as i32);
                };
                payload_offset += ext_len;
                next_ext = next;
                walked += 1;
            }
        }
    }
    if payload_offset >= gtp_end {
        count(COUNTER_DL_MALFORMED);
        return Ok(TC_ACT_SHOT as i32);
    }

    let Some(pdr_ptr) = GTPU_DOWNLINK_PDR.get_ptr(&teid) else {
        count(COUNTER_DL_UNKNOWN_TEID);
        return Ok(TC_ACT_SHOT as i32);
    };
    // SAFETY: the map value outlives this program invocation and is only
    // read here.
    let pdr = DownlinkPdr::decode(unsafe { &*pdr_ptr });

    let Ok(inner_version_ihl) = ctx.load::<u8>(payload_offset) else {
        count(COUNTER_DL_MALFORMED);
        return Ok(TC_ACT_SHOT as i32);
    };
    if inner_version_ihl >> 4 != 4 {
        count(COUNTER_DL_MALFORMED);
        return Ok(TC_ACT_SHOT as i32);
    }
    let Ok(inner_dst) = ctx.load::<[u8; 4]>(payload_offset + 16) else {
        count(COUNTER_DL_MALFORMED);
        return Ok(TC_ACT_SHOT as i32);
    };
    if inner_dst != pdr.ue_ip {
        count(COUNTER_DL_DST_MISMATCH);
        return Ok(TC_ACT_SHOT as i32);
    }

    // Strip outer IPv4 + UDP + GTP-U (+ optional block and extension
    // headers), leaving `[Ethernet][inner IPv4 ...]`.
    let strip = payload_offset - ETH_HDR_LEN;
    if ctx
        .skb
        .adjust_room(-(strip as i32), BPF_ADJ_ROOM_MAC, 0)
        .is_err()
    {
        count(COUNTER_DL_MALFORMED);
        return Ok(TC_ACT_SHOT as i32);
    }
    count(COUNTER_DL_DECAP);
    Ok(TC_ACT_OK as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
