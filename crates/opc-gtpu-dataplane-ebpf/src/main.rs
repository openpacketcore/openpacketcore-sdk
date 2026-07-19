//! tc clsact GTP-U datapath for the ePDG S2b-U interface (TS 29.281).
//!
//! Two programs attach to the PGW-facing (S2b-U) interface:
//!
//! - `opc_gtpu_uplink` (tc egress): looks up the uplink FAR by the inner IPv4
//!   source (the UE PAA) and, for a dedicated bearer, the packet mark stamped
//!   by inbound XFRM. It then GTP-U-encapsulates the packet toward the PGW.
//!   A legacy mark-zero FAR miss passes through untouched; a nonzero-mark
//!   miss is dropped so explicitly classified subscriber traffic cannot leak
//!   without GTP-U encapsulation.
//! - `opc_gtpu_downlink` (tc ingress): matches UDP/2152 GTPv1-U G-PDUs and
//!   validates the exact IPv4/UDP/GTP-U boundaries and checksums before PDR
//!   lookup, validates the inner packet, and strips the proven outer envelope.
//!   It then stamps any dedicated-bearer packet mark and lets the inner packet
//!   continue through the ePDG's XFRM output policy. Unknown-TEID G-PDUs are
//!   dropped and counted; non-G-PDU GTP-U (echo, error indication) passes
//!   through to the control plane.
//!   Zero IPv4 UDP omission and software-verified nonzero checksums are
//!   accepted only after a reversible checksum-field probe excludes any
//!   pending `CHECKSUM_PARTIAL` operation and restores the exact original
//!   bytes.
//!
//! Byte layouts live in `opc-gtpu-ebpf-common` and are shared with the
//! userspace loader in `opc-gtpu-dataplane`.

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{
        __sk_buff, bpf_adj_room_mode::BPF_ADJ_ROOM_MAC, BPF_CSUM_LEVEL_QUERY,
        BPF_F_ADJ_ROOM_ENCAP_L3_IPV4, BPF_F_ADJ_ROOM_ENCAP_L4_UDP, TC_ACT_OK, TC_ACT_REDIRECT,
        TC_ACT_SHOT,
    },
    cty::c_void,
    helpers::{
        bpf_csum_diff, bpf_csum_level, bpf_loop, bpf_redirect_neigh, bpf_skb_change_tail,
        bpf_skb_load_bytes,
    },
    macros::{classifier, map},
    maps::{Array, HashMap, PerCpuArray},
    programs::TcContext,
};
use opc_gtpu_ebpf_common::{
    build_uplink_encap_with_dscp, classify_gtpu, classify_udp_checksum,
    internet_checksum_sum_is_valid, marked_owner_wire_authorizes_downlink,
    marked_owner_wire_authorizes_uplink, uplink_non_encapsulation_drops,
    validate_ipv4_downlink_binding_wire, DownlinkBindingMismatch, DownlinkPdr, GtpuClass,
    GtpuEnvelopeBounds, Ipv4EnvelopeBounds, MarkedDownlinkPdr, UdpChecksumDisposition,
    UdpChecksumEvidence, UdpEnvelopeBounds, UplinkFar, UplinkFarKey,
    COUNTER_DL_BINDING_FAMILY_MISMATCH, COUNTER_DL_BINDING_INGRESS_MISMATCH,
    COUNTER_DL_BINDING_INVALID, COUNTER_DL_BINDING_LOCAL_MISMATCH,
    COUNTER_DL_BINDING_PEER_MISMATCH, COUNTER_DL_BINDING_SOURCE_PORT_MISMATCH, COUNTER_DL_DECAP,
    COUNTER_DL_DST_MISMATCH, COUNTER_DL_MALFORMED, COUNTER_DL_UNKNOWN_TEID, COUNTER_SLOTS,
    COUNTER_UL_ENCAP, COUNTER_UL_FAR_MISS, DOWNLINK_BINDING_COUNTER_SLOTS,
    DOWNLINK_ENDPOINT_BINDING_VALUE_LEN, DOWNLINK_PDR_VALUE_LEN, ETH_HDR_LEN, ETH_P_IPV4,
    GTPU_MANDATORY_HDR_LEN, GTPU_MAX_EXT_HEADERS, GTPU_OPT_LEN, GTPU_UDP_PORT,
    MARKED_BEARER_OWNER_VALUE_LEN, MARKED_DOWNLINK_PDR_VALUE_LEN, UPLINK_DSCP_SCHEMA_MARKER_KEY,
    UPLINK_DSCP_VALUE_LEN, UPLINK_FAR_VALUE_LEN, UPLINK_MARK_KEY_LEN,
};

/// Uplink FAR: UE PAA (IPv4, network order) -> encap state.
#[map]
static GTPU_UPLINK_FAR: HashMap<[u8; 4], [u8; UPLINK_FAR_VALUE_LEN]> = HashMap::pinned(65536, 0);

/// Marked uplink FAR: `(UE PAA, skb mark)` -> encap state.
#[map]
static GTPU_ULM_FAR: HashMap<[u8; UPLINK_MARK_KEY_LEN], [u8; UPLINK_FAR_VALUE_LEN]> =
    HashMap::pinned(65536, 0);

/// Optional fixed outer DSCP: UE PAA -> one validated six-bit codepoint.
#[map]
static GTPU_UPLINK_DSCP: HashMap<[u8; 4], [u8; UPLINK_DSCP_VALUE_LEN]> = HashMap::pinned(65536, 0);

/// Optional fixed outer DSCP: `(UE PAA, skb mark)` -> codepoint.
#[map]
static GTPU_ULM_DSCP: HashMap<[u8; UPLINK_MARK_KEY_LEN], [u8; UPLINK_DSCP_VALUE_LEN]> =
    HashMap::pinned(65536, 0);

/// Legacy/default downlink PDR: local TEID -> UE PAA.
#[map]
static GTPU_DOWNLINK_PDR: HashMap<[u8; 4], [u8; DOWNLINK_PDR_VALUE_LEN]> =
    HashMap::pinned(65536, 0);

/// Dedicated-bearer downlink PDR: local TEID -> `(UE PAA, skb mark)`.
#[map]
static GTPU_DLM_PDR: HashMap<[u8; 4], [u8; MARKED_DOWNLINK_PDR_VALUE_LEN]> =
    HashMap::pinned(65536, 0);

/// Downlink outer endpoint/ingress identity: local TEID -> binding.
#[map]
static GTPU_DL_BIND: HashMap<[u8; 4], [u8; DOWNLINK_ENDPOINT_BINDING_VALUE_LEN]> =
    HashMap::pinned(65536, 0);

/// Marked-bearer owner journal and forwarding commit gate.
#[map]
static GTPU_M_OWNER: HashMap<[u8; UPLINK_MARK_KEY_LEN], [u8; MARKED_BEARER_OWNER_VALUE_LEN]> =
    HashMap::pinned(65536, 0);

/// Per-CPU datapath counters, indexed by the COUNTER_* constants.
#[map]
static GTPU_COUNTERS: PerCpuArray<u64> = PerCpuArray::pinned(COUNTER_SLOTS, 0);

/// Fixed-cardinality provenance mismatch counters.
#[map]
static GTPU_DL_DROP: PerCpuArray<u64> = PerCpuArray::pinned(DOWNLINK_BINDING_COUNTER_SLOTS, 0);

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

#[inline(always)]
fn count_binding_drop(index: u32) {
    if let Some(counter) = GTPU_DL_DROP.get_ptr_mut(index) {
        // SAFETY: per-CPU slot; no concurrent access on the same CPU.
        unsafe { *counter += 1 };
    }
}

#[inline(always)]
fn binding_drop(reason: DownlinkBindingMismatch) -> i32 {
    let index = match reason {
        DownlinkBindingMismatch::Invalid => COUNTER_DL_BINDING_INVALID,
        DownlinkBindingMismatch::AddressFamily => COUNTER_DL_BINDING_FAMILY_MISMATCH,
        DownlinkBindingMismatch::PeerAddress => COUNTER_DL_BINDING_PEER_MISMATCH,
        DownlinkBindingMismatch::LocalAddress => COUNTER_DL_BINDING_LOCAL_MISMATCH,
        DownlinkBindingMismatch::IngressAttachment => COUNTER_DL_BINDING_INGRESS_MISMATCH,
        DownlinkBindingMismatch::SourcePort => COUNTER_DL_BINDING_SOURCE_PORT_MISMATCH,
    };
    count_binding_drop(index);
    TC_ACT_SHOT as i32
}

/// Read the complete Linux packet mark presented to the tc hook.
///
/// Aya exposes a safe mark setter but no getter for `TcContext`. Keep the
/// direct context access isolated here so every lookup observes exactly the
/// post-XFRM mark supplied by the kernel.
#[inline(always)]
fn packet_mark(ctx: &TcContext) -> u32 {
    // SAFETY: the kernel supplies a verifier-checked, non-null `__sk_buff`
    // context for the lifetime of this classifier invocation. This helper
    // performs one aligned, read-only access to its fixed-width `mark` field.
    unsafe { (*ctx.skb.skb).mark }
}

/// Read the exact interface on which this tc classifier is executing.
#[inline(always)]
fn packet_ifindex(ctx: &TcContext) -> u32 {
    // SAFETY: the kernel supplies a verifier-checked, non-null `__sk_buff`
    // context for the lifetime of this classifier invocation. `ifindex` is a
    // fixed-width read-only field at this boundary.
    unsafe { (*ctx.skb.skb).ifindex }
}

#[classifier]
pub fn opc_gtpu_uplink(mut ctx: TcContext) -> i32 {
    let mark = packet_mark(&ctx);
    match try_uplink(&mut ctx, mark) {
        Ok(action) => action,
        Err(()) => non_encapsulation_action(mark),
    }
}

#[classifier]
pub fn opc_gtpu_downlink(mut ctx: TcContext) -> i32 {
    try_downlink(&mut ctx).unwrap_or(TC_ACT_OK as i32)
}

/// Uplink: inner IPv4 packet routed to the S2b-U interface with
/// `src = UE PAA`. Prepend `[outer IPv4][UDP][GTPv1-U]` and re-resolve the
/// L2 next hop for the new outer destination.
fn try_uplink(ctx: &mut TcContext, mark: u32) -> Result<i32, ()> {
    let eth_proto = u16::from_be(ctx.load(12).map_err(|_| ())?);
    if eth_proto != ETH_P_IPV4 {
        return Ok(non_encapsulation_action(mark));
    }
    let version_ihl: u8 = ctx.load(ETH_HDR_LEN).map_err(|_| ())?;
    if version_ihl >> 4 != 4 {
        return Ok(non_encapsulation_action(mark));
    }

    let inner_src: [u8; 4] = ctx.load(ETH_HDR_LEN + 12).map_err(|_| ())?;
    if inner_src == UPLINK_DSCP_SCHEMA_MARKER_KEY {
        // Reserved durable-schema evidence is never subscriber forwarding
        // state, even if a locally forged packet uses source 0.0.0.0.
        return Ok(non_encapsulation_action(mark));
    }
    let marked_key = UplinkFarKey {
        ue_ip: inner_src,
        bearer_mark: mark.to_be_bytes(),
    }
    .encode();
    let far_ptr = if mark == 0 {
        GTPU_UPLINK_FAR.get_ptr(&inner_src)
    } else {
        GTPU_ULM_FAR.get_ptr(&marked_key)
    };
    let Some(far_ptr) = far_ptr else {
        count(COUNTER_UL_FAR_MISS);
        return Ok(non_encapsulation_action(mark));
    };
    // SAFETY: the map value outlives this program invocation and is only
    // read here.
    let mut far = UplinkFar::decode(unsafe { &*far_ptr });
    if far.local_ip == [0, 0, 0, 0] {
        if mark != 0 {
            // Marked journals bind a concrete complete FAR. The zero-source
            // compatibility fallback is retained only for legacy/default
            // records migrated from the v1 object.
            return Ok(TC_ACT_SHOT as i32);
        }
        if let Some(local_ip) = GTPU_CONFIG.get_ptr(0) {
            // SAFETY: single-slot array value written only by the loader.
            far.local_ip = unsafe { *local_ip };
        }
    }

    let inner_len = (ctx.len() as usize).saturating_sub(ETH_HDR_LEN);
    let inner_len = u16::try_from(inner_len).map_err(|_| ())?;
    let dscp_ptr = if mark == 0 {
        GTPU_UPLINK_DSCP.get_ptr(&inner_src)
    } else {
        GTPU_ULM_DSCP.get_ptr(&marked_key)
    };
    let dscp_wire = if let Some(dscp_ptr) = dscp_ptr {
        // SAFETY: the map value outlives this invocation and is read only.
        let value = unsafe { (*dscp_ptr)[0] };
        if value > 63 {
            return Ok(TC_ACT_SHOT as i32);
        }
        value
    } else {
        0xff
    };
    if mark != 0 {
        let Some(owner_ptr) = GTPU_M_OWNER.get_ptr(&marked_key) else {
            count(COUNTER_UL_FAR_MISS);
            return Ok(TC_ACT_SHOT as i32);
        };
        // SAFETY: the hash value remains map-owned for this invocation and is
        // read only by the allocation-free wire validator.
        if !marked_owner_wire_authorizes_uplink(unsafe { &*owner_ptr }, &far, dscp_wire) {
            return Ok(TC_ACT_SHOT as i32);
        }
    }
    let dscp = if dscp_wire == 0xff {
        None
    } else {
        Some(dscp_wire)
    };
    let encap = build_uplink_encap_with_dscp(&far, inner_len, dscp).ok_or(())?;

    ctx.skb
        .adjust_room(
            encap.len() as i32,
            BPF_ADJ_ROOM_MAC,
            u64::from(BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP),
        )
        .map_err(|_| ())?;
    ctx.store(ETH_HDR_LEN, &encap, 0).map_err(|_| ())?;
    count(COUNTER_UL_ENCAP);

    if mark != 0 {
        // The complete bearer mark is consumed by the exact marked FAR.
        // Clear it before neighbour redirect so the re-emitted outer packet
        // traverses this hook as mark zero rather than self-dropping on a
        // marked FAR miss for the local S2b-U source.
        ctx.set_mark(0);
    }

    // The frame's L2 destination was resolved for the inner route; the outer
    // destination is the PGW. Re-run FIB/neighbour resolution for the new
    // outer header. The re-emitted frame traverses this egress hook once
    // more, misses the FAR (outer src is not a UE PAA), and passes through.
    // SAFETY: helper takes no pointers when plen == 0.
    let ret = unsafe { bpf_redirect_neigh((*ctx.skb.skb).ifindex, core::ptr::null_mut(), 0, 0) };
    if mark != 0 && ret != i64::from(TC_ACT_REDIRECT) {
        Ok(TC_ACT_SHOT as i32)
    } else {
        Ok(ret as i32)
    }
}

#[inline(always)]
fn non_encapsulation_action(mark: u32) -> i32 {
    if uplink_non_encapsulation_drops(mark) {
        TC_ACT_SHOT as i32
    } else {
        TC_ACT_OK as i32
    }
}

#[inline(always)]
fn malformed_downlink() -> i32 {
    count(COUNTER_DL_MALFORMED);
    TC_ACT_SHOT as i32
}

const CHECKSUM_CHUNK_LEN: usize = 256;

#[repr(C)]
struct ChecksumLoopContext {
    skb: *mut __sk_buff,
    offset: u32,
    seed: u32,
    failed: u32,
}

/// Add one fixed checksum chunk without verifier-unrolling the packet loop.
///
/// The kernel invokes this as a `bpf_loop` callback. Returning one stops the
/// loop after recording a fail-closed helper error in the caller-owned stack
/// context; zero advances to the next fixed chunk.
#[inline(never)]
unsafe extern "C" fn checksum_loop_chunk(_index: u64, context: *mut c_void) -> i64 {
    // SAFETY: `checksum_skb_region` passes a live, uniquely borrowed stack
    // context for the complete synchronous `bpf_loop` call.
    let context = unsafe { &mut *context.cast::<ChecksumLoopContext>() };
    if context.failed != 0 {
        return 1;
    }

    let mut chunk = core::mem::MaybeUninit::<[u8; CHECKSUM_CHUNK_LEN]>::uninit();
    // SAFETY: the kernel supplied the live tc skb pointer. A successful load
    // initializes the complete fixed stack buffer before the checksum helper
    // reads that same four-byte-multiple region.
    let result = unsafe {
        if bpf_skb_load_bytes(
            context.skb.cast(),
            context.offset,
            chunk.as_mut_ptr().cast(),
            CHECKSUM_CHUNK_LEN as u32,
        ) != 0
        {
            context.failed = 1;
            return 1;
        }
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            chunk.as_mut_ptr().cast(),
            CHECKSUM_CHUNK_LEN as u32,
            context.seed,
        )
    };
    if result < 0 {
        context.failed = 1;
        return 1;
    }
    context.seed = result as u32;
    context.offset = context.offset.wrapping_add(CHECKSUM_CHUNK_LEN as u32);
    0
}

#[inline(always)]
fn checksum_packet_chunk<const LENGTH: usize>(
    ctx: &TcContext,
    offset: usize,
    seed: u32,
) -> Result<(usize, u32), ()> {
    let next_offset = offset.checked_add(LENGTH).ok_or(())?;
    if LENGTH == 0 || !LENGTH.is_multiple_of(4) {
        return Err(());
    }
    let offset = u32::try_from(offset).map_err(|_| ())?;
    let mut chunk = core::mem::MaybeUninit::<[u8; LENGTH]>::uninit();
    // SAFETY: the kernel supplied this live tc skb. The successful first
    // helper initializes every byte in the one stack buffer before the second
    // helper reads exactly the same nonzero four-byte-multiple region.
    let result = unsafe {
        if bpf_skb_load_bytes(
            ctx.skb.skb.cast(),
            offset,
            chunk.as_mut_ptr().cast(),
            LENGTH as u32,
        ) != 0
        {
            return Err(());
        }
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            chunk.as_mut_ptr().cast(),
            LENGTH as u32,
            seed,
        )
    };
    if result < 0 {
        return Err(());
    }
    Ok((next_offset, result as u32))
}

/// Add an exact skb byte range to a ones-complement checksum accumulator.
///
/// Full fixed-size chunks run through the kernel's bounded `bpf_loop` helper,
/// so the verifier analyzes one callback state instead of unrolling every
/// checksum seed across the maximum IPv4 UDP length. Fixed remainder chunks
/// use `bpf_skb_load_bytes`, which also supports non-linear skb data. A final
/// one-to-three-byte suffix is copied into a zero-padded stack word.
#[inline(always)]
fn checksum_skb_region(
    ctx: &TcContext,
    offset: usize,
    length: usize,
    mut seed: u32,
) -> Result<u32, ()> {
    if length > usize::from(u16::MAX) {
        return Err(());
    }
    let range_end = offset.checked_add(length).ok_or(())?;
    let range_end = u32::try_from(range_end).map_err(|_| ())?;
    let full_chunks = u32::try_from(length / CHECKSUM_CHUNK_LEN).map_err(|_| ())?;
    let start = u32::try_from(offset).map_err(|_| ())?;
    let mut loop_context = ChecksumLoopContext {
        skb: ctx.skb.skb,
        offset: start,
        seed,
        failed: 0,
    };
    if full_chunks != 0 {
        // SAFETY: the callback is a static BPF subprogram with the signature
        // required by `bpf_loop`. The mutable context lives on this stack for
        // the synchronous helper call, and flags zero is the only supported
        // mode. The input length caps the loop at 255 fixed iterations.
        let performed = unsafe {
            bpf_loop(
                full_chunks,
                checksum_loop_chunk as *mut c_void,
                (&mut loop_context as *mut ChecksumLoopContext).cast(),
                0,
            )
        };
        if performed != i64::from(full_chunks) || loop_context.failed != 0 {
            return Err(());
        }
    }
    let expected_loop_end = start
        .checked_add(
            full_chunks
                .checked_mul(CHECKSUM_CHUNK_LEN as u32)
                .ok_or(())?,
        )
        .ok_or(())?;
    if loop_context.offset != expected_loop_end {
        return Err(());
    }
    seed = loop_context.seed;
    let mut cursor = usize::try_from(loop_context.offset).map_err(|_| ())?;
    let mut remaining = length % CHECKSUM_CHUNK_LEN;

    if remaining >= 128 {
        (cursor, seed) = checksum_packet_chunk::<128>(ctx, cursor, seed)?;
        remaining -= 128;
    }
    if remaining >= 64 {
        (cursor, seed) = checksum_packet_chunk::<64>(ctx, cursor, seed)?;
        remaining -= 64;
    }
    if remaining >= 32 {
        (cursor, seed) = checksum_packet_chunk::<32>(ctx, cursor, seed)?;
        remaining -= 32;
    }
    if remaining >= 16 {
        (cursor, seed) = checksum_packet_chunk::<16>(ctx, cursor, seed)?;
        remaining -= 16;
    }
    if remaining >= 8 {
        (cursor, seed) = checksum_packet_chunk::<8>(ctx, cursor, seed)?;
        remaining -= 8;
    }
    if remaining >= 4 {
        (cursor, seed) = checksum_packet_chunk::<4>(ctx, cursor, seed)?;
        remaining -= 4;
    }

    if remaining != 0 {
        let mut suffix = [0_u8; 4];
        suffix[0] = ctx.load(cursor).map_err(|_| ())?;
        if remaining > 1 {
            suffix[1] = ctx.load(cursor + 1).map_err(|_| ())?;
        }
        if remaining > 2 {
            suffix[2] = ctx.load(cursor + 2).map_err(|_| ())?;
        }
        // SAFETY: `suffix` is a four-byte initialized stack buffer and both
        // helper sizes obey the required four-byte alignment contract.
        let result = unsafe {
            bpf_csum_diff(
                core::ptr::null_mut(),
                0,
                suffix.as_mut_ptr().cast::<u32>(),
                4,
                seed,
            )
        };
        if result < 0 {
            return Err(());
        }
        seed = result as u32;
    }
    let consumed_end = cursor.checked_add(remaining).ok_or(())?;
    if u32::try_from(consumed_end).map_err(|_| ())? != range_end {
        return Err(());
    }
    Ok(seed)
}

#[inline(always)]
fn ipv4_header_checksum_is_valid(ctx: &TcContext, bounds: Ipv4EnvelopeBounds) -> bool {
    let words = bounds.ip_header_len() / 2;
    let mut sum = 0_u32;
    let mut index = 0_usize;
    while index < 30 {
        if index >= words {
            break;
        }
        let Some(offset) = index
            .checked_mul(2)
            .and_then(|value| ETH_HDR_LEN.checked_add(value))
        else {
            return false;
        };
        let Ok(word) = ctx.load::<u16>(offset) else {
            return false;
        };
        sum = sum.wrapping_add(u32::from(u16::from_be(word)));
        index += 1;
    }
    internet_checksum_sum_is_valid(sum)
}

#[inline(always)]
fn software_udp_checksum_is_valid(ctx: &TcContext, bounds: UdpEnvelopeBounds) -> bool {
    let udp_offset = bounds.ipv4().udp_offset();
    let Ok(source) = ctx.load::<[u8; 4]>(ETH_HDR_LEN + 12) else {
        return false;
    };
    let Ok(destination) = ctx.load::<[u8; 4]>(ETH_HDR_LEN + 16) else {
        return false;
    };
    let udp_length = bounds.udp_end() - udp_offset;
    let udp_length_u16 = match u16::try_from(udp_length) {
        Ok(length) => length,
        Err(_) => return false,
    };
    let mut pseudo_header = [0_u8; 12];
    pseudo_header[0..4].copy_from_slice(&source);
    pseudo_header[4..8].copy_from_slice(&destination);
    pseudo_header[9] = IPV4_PROTO_UDP;
    pseudo_header[10..12].copy_from_slice(&udp_length_u16.to_be_bytes());
    // SAFETY: `pseudo_header` is an initialized twelve-byte stack buffer, and
    // the checksum helper length is a multiple of four.
    let pseudo_sum = unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            pseudo_header.as_mut_ptr().cast::<u32>(),
            12,
            0,
        )
    };
    if pseudo_sum < 0 {
        return false;
    }
    checksum_skb_region(ctx, udp_offset, udp_length, pseudo_sum as u32)
        .is_ok_and(internet_checksum_sum_is_valid)
}

#[inline(always)]
fn zero_udp_checksum_is_omitted(ctx: &TcContext, checksum_offset: usize) -> bool {
    // TC exposes CHECKSUM_UNNECESSARY through `bpf_csum_level`, but not the
    // distinction between CHECKSUM_NONE and CHECKSUM_PARTIAL. Linux's
    // non-pseudoheader checksum replacement changes an ordinary checksum
    // field and deliberately leaves a CHECKSUM_PARTIAL field untouched. Use a
    // reversible probe to distinguish a legal IPv4 UDP omission from an
    // unfinished zero partial-checksum seed.
    let Ok(original) = ctx.load::<u16>(checksum_offset) else {
        return false;
    };
    if original != 0 {
        return false;
    }
    let probe_word = u64::from(u16::to_be(1));
    if ctx
        .l4_csum_replace(checksum_offset, 0, probe_word, 2)
        .is_err()
    {
        return false;
    }
    let changed = ctx
        .load::<u16>(checksum_offset)
        .is_ok_and(|value| value != 0);

    // Ones-complement arithmetic has two zero representations, so the reverse
    // operation alone may produce 0xffff. Always restore the exact original
    // bytes with zero helper flags, then verify them. Any helper or reload
    // failure fails closed before PDR lookup.
    let reversed = ctx
        .l4_csum_replace(checksum_offset, probe_word, 0, 2)
        .is_ok();
    let restored = ctx.store(checksum_offset, &original, 0).is_ok()
        && ctx
            .load::<u16>(checksum_offset)
            .is_ok_and(|value| value == 0);
    changed && reversed && restored
}

#[inline(always)]
fn nonzero_udp_checksum_has_no_pending_offload(ctx: &TcContext, checksum_offset: usize) -> bool {
    let Ok(original) = ctx.load::<u16>(checksum_offset) else {
        return false;
    };
    if original == 0 {
        return false;
    }

    // With non-pseudoheader flags Linux leaves a CHECKSUM_PARTIAL field
    // unchanged. An ordinary complete field must change under this fixed
    // delta. Comparing against the exact nonzero snapshot is essential: a
    // mere nonzero test would misclassify an unchanged partial seed.
    let probe_word = u64::from(u16::to_be(1));
    if ctx
        .l4_csum_replace(checksum_offset, 0, probe_word, 2)
        .is_err()
    {
        return false;
    }
    let changed = ctx
        .load::<u16>(checksum_offset)
        .is_ok_and(|value| value != original);
    let reversed = ctx
        .l4_csum_replace(checksum_offset, probe_word, 0, 2)
        .is_ok();
    let restored = ctx.store(checksum_offset, &original, 0).is_ok()
        && ctx
            .load::<u16>(checksum_offset)
            .is_ok_and(|value| value == original);
    changed && reversed && restored
}

#[inline(always)]
fn udp_checksum_is_valid(ctx: &TcContext, bounds: UdpEnvelopeBounds) -> bool {
    let udp_offset = bounds.ipv4().udp_offset();
    let Ok(checksum) = ctx.load::<u16>(udp_offset + 6) else {
        return false;
    };
    let checksum = u16::from_be(checksum);
    if checksum == 0 {
        let evidence = if zero_udp_checksum_is_omitted(ctx, udp_offset + 6) {
            UdpChecksumEvidence::NoPendingOffload
        } else {
            UdpChecksumEvidence::Unverified
        };
        return matches!(
            classify_udp_checksum(checksum, evidence),
            UdpChecksumDisposition::Omitted
        );
    }
    // `BPF_CSUM_LEVEL_QUERY` succeeds only for CHECKSUM_UNNECESSARY. A
    // negative result includes CHECKSUM_NONE, COMPLETE, PARTIAL, and helper
    // errors, so the reversible field probe must additionally exclude
    // CHECKSUM_PARTIAL before software verification. Zero still requires the
    // probe because IPv4 checksum omission is valid only when no completion
    // operation remains pending.
    // SAFETY: the kernel supplied this live tc `__sk_buff` context. The query
    // is read-only and carries no packet or userspace pointer.
    let kernel_verified =
        unsafe { bpf_csum_level(ctx.skb.skb, u64::from(BPF_CSUM_LEVEL_QUERY)) >= 0 };
    let evidence = if kernel_verified {
        UdpChecksumEvidence::KernelVerified
    } else if nonzero_udp_checksum_has_no_pending_offload(ctx, udp_offset + 6) {
        UdpChecksumEvidence::NoPendingOffload
    } else {
        UdpChecksumEvidence::Unverified
    };
    match classify_udp_checksum(checksum, evidence) {
        UdpChecksumDisposition::Omitted | UdpChecksumDisposition::KernelVerified => true,
        UdpChecksumDisposition::SoftwareRequired
            if evidence == UdpChecksumEvidence::NoPendingOffload =>
        {
            software_udp_checksum_is_valid(ctx, bounds)
        }
        UdpChecksumDisposition::SoftwareRequired => false,
    }
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
    let Some(ip_header_len) = usize::from(version_ihl & 0x0F).checked_mul(4) else {
        return Ok(TC_ACT_OK as i32);
    };
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

    let Some(l4_offset) = ETH_HDR_LEN.checked_add(ip_header_len) else {
        return Ok(TC_ACT_OK as i32);
    };
    let Some(dport_offset) = l4_offset.checked_add(2) else {
        return Ok(TC_ACT_OK as i32);
    };
    let dport = u16::from_be(ctx.load(dport_offset).map_err(|_| ())?);
    if dport != GTPU_UDP_PORT {
        return Ok(TC_ACT_OK as i32);
    }

    // From this point onward UDP/2152 identifies a GTP-U candidate. Every
    // malformed declaration or checksum fails closed before any PDR lookup.
    let Ok(total_length) = ctx.load::<u16>(ETH_HDR_LEN + 2) else {
        return Ok(malformed_downlink());
    };
    let Ok(ipv4_bounds) =
        Ipv4EnvelopeBounds::parse(ctx.len() as usize, version_ihl, u16::from_be(total_length))
    else {
        return Ok(malformed_downlink());
    };
    if ipv4_bounds.udp_offset() != l4_offset || !ipv4_header_checksum_is_valid(ctx, ipv4_bounds) {
        return Ok(malformed_downlink());
    }
    let Ok(udp_length) = ctx.load::<u16>(l4_offset + 4) else {
        return Ok(malformed_downlink());
    };
    let Ok(udp_bounds) = UdpEnvelopeBounds::parse(ipv4_bounds, u16::from_be(udp_length)) else {
        return Ok(malformed_downlink());
    };
    if !udp_checksum_is_valid(ctx, udp_bounds) {
        return Ok(malformed_downlink());
    }

    let gtp_offset = udp_bounds.gtp_offset();
    let Ok(gtp_header) = ctx.load::<[u8; GTPU_MANDATORY_HDR_LEN]>(gtp_offset) else {
        return Ok(malformed_downlink());
    };
    let declared_gtp_length = u16::from_be_bytes([gtp_header[2], gtp_header[3]]);
    let Ok(gtp_bounds) = GtpuEnvelopeBounds::parse(udp_bounds, declared_gtp_length) else {
        return Ok(malformed_downlink());
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

    if gtp_length != declared_gtp_length {
        return Ok(malformed_downlink());
    }
    let gtp_end = gtp_bounds.gtp_end();

    if ipv4_bounds.ip_end() < ctx.len() as usize {
        let Ok(ip_end) = u32::try_from(ipv4_bounds.ip_end()) else {
            return Ok(malformed_downlink());
        };
        // SAFETY: `ip_end` was checked against skb length and derives from
        // IPv4 Total Length. Trimming removes only layer-2 padding so it
        // cannot survive front decapsulation as unauthenticated inner bytes.
        if unsafe { bpf_skb_change_tail(ctx.skb.skb, ip_end, 0) } != 0 {
            return Ok(malformed_downlink());
        }
    }

    let Some(mut payload_offset) = gtp_offset.checked_add(GTPU_MANDATORY_HDR_LEN) else {
        return Ok(malformed_downlink());
    };
    if has_opt {
        let Some(optional_end) = payload_offset.checked_add(GTPU_OPT_LEN) else {
            return Ok(malformed_downlink());
        };
        if optional_end > gtp_end {
            return Ok(malformed_downlink());
        }
        let Ok(opt) = ctx.load::<[u8; GTPU_OPT_LEN]>(payload_offset) else {
            return Ok(malformed_downlink());
        };
        payload_offset = optional_end;
        if has_ext {
            let mut next_ext = opt[3];
            let mut walked = 0;
            while next_ext != 0 {
                if walked == GTPU_MAX_EXT_HEADERS || payload_offset >= gtp_end {
                    return Ok(malformed_downlink());
                }
                let Ok(ext_len_units) = ctx.load::<u8>(payload_offset) else {
                    return Ok(malformed_downlink());
                };
                if ext_len_units == 0 {
                    return Ok(malformed_downlink());
                }
                let Some(ext_len) = usize::from(ext_len_units).checked_mul(4) else {
                    return Ok(malformed_downlink());
                };
                let Some(ext_end) = payload_offset.checked_add(ext_len) else {
                    return Ok(malformed_downlink());
                };
                if ext_end > gtp_end {
                    return Ok(malformed_downlink());
                }
                let Ok(next) = ctx.load::<u8>(ext_end - 1) else {
                    return Ok(malformed_downlink());
                };
                payload_offset = ext_end;
                next_ext = next;
                walked += 1;
            }
        }
    }
    if payload_offset >= gtp_end {
        return Ok(malformed_downlink());
    }
    let Some(inner_minimum_end) = payload_offset.checked_add(20) else {
        return Ok(malformed_downlink());
    };
    if inner_minimum_end > gtp_end {
        return Ok(malformed_downlink());
    }

    authorize_and_decap_downlink(ctx, teid, l4_offset, payload_offset)
}

/// Authorize the complete downlink forwarding identity and perform decap.
///
/// Keep this phase in a verifier-visible BPF subprogram. The envelope and
/// software-checksum phase uses a bounded 256-byte `bpf_loop` callback stack;
/// separating the map-graph authorization phase ensures the callback and the
/// endpoint/owner checks do not share one oversized caller frame.
#[inline(never)]
fn authorize_and_decap_downlink(
    ctx: &mut TcContext,
    teid: [u8; 4],
    l4_offset: usize,
    payload_offset: usize,
) -> Result<i32, ()> {
    let legacy_pdr = GTPU_DOWNLINK_PDR.get_ptr(&teid);
    let marked_pdr = GTPU_DLM_PDR.get_ptr(&teid);
    let (pdr, output_mark, owner_selector) = match (legacy_pdr, marked_pdr) {
        (None, None) => {
            count(COUNTER_DL_UNKNOWN_TEID);
            return Ok(TC_ACT_SHOT as i32);
        }
        (Some(_), Some(_)) => {
            // A TEID must exist in exactly one schema. Treat externally
            // corrupted duplicate ownership as malformed rather than picking
            // a bearer nondeterministically.
            count(COUNTER_DL_MALFORMED);
            return Ok(TC_ACT_SHOT as i32);
        }
        (Some(pdr_ptr), None) => {
            // SAFETY: the map value outlives this program invocation and is
            // only read here.
            let legacy = DownlinkPdr::decode(unsafe { &*pdr_ptr });
            (
                MarkedDownlinkPdr {
                    ue_ip: legacy.ue_ip,
                    bearer_mark: [0; 4],
                },
                0,
                None,
            )
        }
        (None, Some(pdr_ptr)) => {
            // SAFETY: the map value outlives this program invocation and is
            // only read here.
            let pdr = MarkedDownlinkPdr::decode(unsafe { &*pdr_ptr });
            if pdr.bearer_mark == [0; 4] {
                // Mark zero belongs exclusively to the legacy/default map.
                count(COUNTER_DL_MALFORMED);
                return Ok(TC_ACT_SHOT as i32);
            }
            let selector = UplinkFarKey {
                ue_ip: pdr.ue_ip,
                bearer_mark: pdr.bearer_mark,
            }
            .encode();
            (pdr, u32::from_be_bytes(pdr.bearer_mark), Some(selector))
        }
    };

    let Some(binding_ptr) = GTPU_DL_BIND.get_ptr(&teid) else {
        count_binding_drop(COUNTER_DL_BINDING_INVALID);
        return Ok(TC_ACT_SHOT as i32);
    };
    // SAFETY: the hash value remains map-owned for this invocation and is
    // read only by the allocation-free wire validators below.
    let binding = unsafe { &*binding_ptr };
    let Ok(outer_peer) = ctx.load::<[u8; 4]>(ETH_HDR_LEN + 12) else {
        return Ok(binding_drop(DownlinkBindingMismatch::Invalid));
    };
    let Ok(outer_local) = ctx.load::<[u8; 4]>(ETH_HDR_LEN + 16) else {
        return Ok(binding_drop(DownlinkBindingMismatch::Invalid));
    };
    let Ok(source_port) = ctx.load::<u16>(l4_offset) else {
        return Ok(binding_drop(DownlinkBindingMismatch::Invalid));
    };
    if let Err(reason) = validate_ipv4_downlink_binding_wire(
        binding,
        outer_peer,
        outer_local,
        packet_ifindex(ctx),
        u16::from_be(source_port),
    ) {
        return Ok(binding_drop(reason));
    }
    if let Some(selector) = owner_selector {
        let Some(owner_ptr) = GTPU_M_OWNER.get_ptr(&selector) else {
            return Ok(binding_drop(DownlinkBindingMismatch::Invalid));
        };
        // SAFETY: both map values remain map-owned and read-only for this
        // exact comparison. Publishing Active last means an old owner cannot
        // authorize a newly replaced binding during peer relocation.
        if !marked_owner_wire_authorizes_downlink(unsafe { &*owner_ptr }, teid, binding) {
            return Ok(binding_drop(DownlinkBindingMismatch::Invalid));
        }
    }

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
    // This boundary owns the complete mark. Zero is the authoritative
    // default bearer; a nonzero value selects one exact dedicated Child SA.
    ctx.set_mark(output_mark);
    count(COUNTER_DL_DECAP);
    Ok(TC_ACT_OK as i32)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
