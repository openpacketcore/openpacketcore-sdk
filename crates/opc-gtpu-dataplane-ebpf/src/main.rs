//! tc clsact GTP-U datapath for the ePDG S2b-U interface (TS 29.281).
//!
//! Two programs attach to the PGW-facing (S2b-U) interface:
//!
//! - `opc_gtpu_uplink` (tc egress): resolves an IPv4 or IPv6 UE source and
//!   packet mark through the grouped-session authority, then encapsulates it
//!   over an independently selected IPv4 or IPv6 S2b-U transport. The frozen
//!   v5 IPv4 maps remain a compatibility fallback only when no grouped index
//!   owns the selector. A legacy mark-zero FAR miss passes through untouched;
//!   a nonzero-mark miss is dropped so explicitly classified subscriber
//!   traffic cannot leak without GTP-U encapsulation.
//! - `opc_gtpu_downlink` (tc ingress): matches UDP/2152 GTPv1-U G-PDUs and
//!   validates exact IPv4 or IPv6 UDP/GTP-U boundaries and checksums before
//!   grouped PDR lookup, validates the independent inner IP family, and strips
//!   the proven outer envelope. It then stamps any dedicated-bearer packet
//!   mark and lets the inner packet continue through the ePDG's XFRM output
//!   policy. Unknown-TEID G-PDUs are dropped and counted; non-G-PDU GTP-U
//!   (echo, error indication) passes through to the control plane. IPv6 UDP
//!   checksums are mandatory. Zero IPv4 UDP omission and software-verified
//!   nonzero checksums are accepted only after a reversible checksum-field
//!   probe excludes any pending `CHECKSUM_PARTIAL` operation and restores the
//!   exact original bytes.
//!
//! Byte layouts live in `opc-gtpu-ebpf-common` and are shared with the
//! userspace loader in `opc-gtpu-dataplane`.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

use aya_ebpf::{
    bindings::{
        __sk_buff, bpf_adj_room_mode::BPF_ADJ_ROOM_MAC, BPF_CSUM_LEVEL_QUERY,
        BPF_F_ADJ_ROOM_DECAP_L3_IPV4, BPF_F_ADJ_ROOM_DECAP_L3_IPV6, BPF_F_ADJ_ROOM_ENCAP_L3_IPV4,
        BPF_F_ADJ_ROOM_ENCAP_L3_IPV6, BPF_F_ADJ_ROOM_ENCAP_L4_UDP, TC_ACT_OK, TC_ACT_REDIRECT,
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
    apply_uplink_mtu_policy, build_uplink_encap_with_dscp_and_source_port, classify_gtpu,
    classify_udp_checksum, decide_uplink_pmtu, downlink_frame_end,
    downlink_parse_ipv4_total_length, downlink_parse_payload_offset, downlink_parse_teid,
    internet_checksum_sum_is_valid, marked_owner_wire_authorizes_downlink,
    marked_owner_wire_authorizes_uplink, pack_downlink_parse_result,
    pdp_commit_wire_authorized_source_port, pdp_commit_wire_authorizes_downlink,
    pdp_commit_wire_authorizes_graph, select_gtpu_session_entry_wire,
    uplink_non_encapsulation_drops, validate_ipv4_downlink_binding_wire, DownlinkBindingMismatch,
    DownlinkPdr, GtpuClass, GtpuEnvelopeBounds, GtpuOuterFragmentPolicy, GtpuPmtuProtocol,
    GtpuSessionEntryWireView, GtpuSessionIpFamily, GtpuUplinkMtuPolicy, Ipv4EnvelopeBounds,
    MarkedDownlinkPdr, UdpChecksumDisposition, UdpChecksumEvidence, UdpEnvelopeBounds, UplinkFar,
    UplinkFarKey, UplinkMtuMapState, UplinkPmtuDecision, COUNTER_DL_BINDING_FAMILY_MISMATCH,
    COUNTER_DL_BINDING_INGRESS_MISMATCH, COUNTER_DL_BINDING_INVALID,
    COUNTER_DL_BINDING_LOCAL_MISMATCH, COUNTER_DL_BINDING_PEER_MISMATCH,
    COUNTER_DL_BINDING_SOURCE_PORT_MISMATCH, COUNTER_DL_DECAP, COUNTER_DL_DST_MISMATCH,
    COUNTER_DL_MALFORMED, COUNTER_DL_UNKNOWN_TEID, COUNTER_SLOTS, COUNTER_UL_ENCAP,
    COUNTER_UL_FAR_MISS, COUNTER_UL_MTU_REJECT, COUNTER_UL_PMTU_CORRUPT,
    DOWNLINK_BINDING_COUNTER_SLOTS, DOWNLINK_ENDPOINT_BINDING_VALUE_LEN, DOWNLINK_PDR_VALUE_LEN,
    ETH_HDR_LEN, ETH_P_IPV4, ETH_P_IPV6, GTPU_FLAGS_V1_GPDU, GTPU_IPV6_ENCAP_LEN,
    GTPU_MANDATORY_HDR_LEN, GTPU_MAX_EXT_HEADERS, GTPU_MSG_TYPE_GPDU, GTPU_OPT_LEN,
    GTPU_SESSION_CONFIG_KEY, GTPU_SESSION_CONFIG_VALUE_LEN, GTPU_SESSION_DOWNLINK_KEY_LEN,
    GTPU_SESSION_GROUP_ID_LEN, GTPU_SESSION_GROUP_REF_LEN, GTPU_SESSION_GROUP_VALUE_LEN,
    GTPU_SESSION_SCHEMA_MARKER_LEN, GTPU_SESSION_TRANSACTION_VALUE_LEN,
    GTPU_SESSION_UPLINK_KEY_LEN, GTPU_UDP_PORT, IPV6_HDR_LEN, IPV6_MAX_EXT_HEADERS,
    IPV6_MAX_OPTIONS_PER_HEADER, IPV6_NH_DESTINATION_OPTIONS, IPV6_NH_FRAGMENT, IPV6_NH_HOP_BY_HOP,
    IPV6_NH_ROUTING, IPV6_NH_UDP, MARKED_BEARER_OWNER_VALUE_LEN, MARKED_DOWNLINK_PDR_VALUE_LEN,
    UPLINK_DSCP_SCHEMA_MARKER_KEY, UPLINK_DSCP_VALUE_LEN, UPLINK_FAR_VALUE_LEN,
    UPLINK_MARK_KEY_LEN, UPLINK_PMTU_COUNTER_SLOTS, UPLINK_PMTU_VALUE_LEN,
    UPLINK_SOURCE_PORT_VALUE_LEN,
};
#[cfg(test)]
use opc_gtpu_ebpf_common::{
    classify_ipv6_extension_step, internet_checksum, udp_ipv6_checksum, Ipv6ExtensionStep,
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

/// Complete default-bearer commit authority, including source-port policy.
#[map]
static GTPU_UL_SPORT: HashMap<[u8; 4], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]> =
    HashMap::pinned(65536, 0);

/// Complete marked-bearer commit authority, including source-port policy.
#[map]
static GTPU_ULM_SPORT: HashMap<[u8; UPLINK_MARK_KEY_LEN], [u8; UPLINK_SOURCE_PORT_VALUE_LEN]> =
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

/// Single-slot uplink MTU policy: effective link MTU, fragmentation flags,
/// reserved. An all-zero slot is the explicit unset (legacy) state.
#[map]
static GTPU_PMTU_CFG: Array<[u8; UPLINK_PMTU_VALUE_LEN]> = Array::pinned(1, 0);

/// Per-CPU counter of uplink packets rejected fail closed by the MTU policy.
#[map]
static GTPU_PMTU_DROP: PerCpuArray<u64> = PerCpuArray::pinned(UPLINK_PMTU_COUNTER_SLOTS, 0);

/// Atomic grouped-session authority keyed by stable group identity.
#[map]
static GTPU_SESSIONS: HashMap<[u8; GTPU_SESSION_GROUP_ID_LEN], [u8; GTPU_SESSION_GROUP_VALUE_LEN]> =
    HashMap::pinned(65536, 0);

/// Family-tagged grouped uplink selector index.
#[map]
static GTPU_UL_INDEX: HashMap<[u8; GTPU_SESSION_UPLINK_KEY_LEN], [u8; GTPU_SESSION_GROUP_REF_LEN]> =
    HashMap::pinned(65536, 0);

/// Family-tagged grouped downlink selector index.
#[map]
static GTPU_DL_INDEX: HashMap<
    [u8; GTPU_SESSION_DOWNLINK_KEY_LEN],
    [u8; GTPU_SESSION_GROUP_REF_LEN],
> = HashMap::pinned(65536, 0);

/// Durable userspace transaction journal; tc never reads this map.
#[map]
static GTPU_SESS_TXN: HashMap<
    [u8; GTPU_SESSION_GROUP_ID_LEN],
    [u8; GTPU_SESSION_TRANSACTION_VALUE_LEN],
> = HashMap::pinned(65536, 0);

/// Stable grouped-session device identity and local endpoint set.
#[map]
static GTPU_CONFIG6: Array<[u8; GTPU_SESSION_CONFIG_VALUE_LEN]> = Array::pinned(1, 0);

/// Independent grouped-session schema marker; tc never reads this map.
#[map]
static GTPU_SCHEMA6: Array<[u8; GTPU_SESSION_SCHEMA_MARKER_LEN]> = Array::pinned(1, 0);

const IPV4_PROTO_UDP: u8 = 17;
const IPV4_FRAG_MASK: u16 = 0x3FFF; // MF bit + fragment offset
const IPV6_FIXED_AND_UDP_GTP_LEN: usize = IPV6_HDR_LEN + 8 + GTPU_MANDATORY_HDR_LEN;
const IPV6_PARSE_PASS: i32 = 0;
const IPV6_PARSE_ACCEPT: i32 = 1;
const IPV6_PARSE_DROP: i32 = -1;
const GROUPED_LOOKUP_MISS: u8 = 0;
const GROUPED_LOOKUP_ERROR: u8 = 1;
const GROUPED_LOOKUP_AUTHORIZED: u8 = 2;

#[derive(Clone, Copy)]
struct ParsedIpv6Downlink {
    ip_end: u32,
    udp_offset: u32,
    payload_offset: u32,
    teid: [u8; 4],
}

impl ParsedIpv6Downlink {
    const EMPTY: Self = Self {
        ip_end: 0,
        udp_offset: 0,
        payload_offset: 0,
        teid: [0; 4],
    };
}

#[inline(always)]
const fn grouped_index_permits_v5_fallback(index_present: bool) -> bool {
    !index_present
}

#[inline(always)]
const fn ipv4_inner_length_is_exact(version_ihl: u8, total_len: u16, available: usize) -> bool {
    let header_len = ((version_ihl & 0x0f) as usize) * 4;
    version_ihl >> 4 == 4
        && header_len >= 20
        && (total_len as usize) >= header_len
        && total_len as usize == available
}

#[inline(always)]
const fn ipv6_inner_length_is_exact(version: u8, payload_len: u16, available: usize) -> bool {
    version >> 4 == 6
        && payload_len != 0
        && match IPV6_HDR_LEN.checked_add(payload_len as usize) {
            Some(total) => total == available,
            None => false,
        }
}

#[inline(always)]
const fn grouped_decap_flags(
    outer_family: GtpuSessionIpFamily,
    inner_family: GtpuSessionIpFamily,
) -> u64 {
    match (outer_family, inner_family) {
        (GtpuSessionIpFamily::Ipv4, GtpuSessionIpFamily::Ipv6) => {
            BPF_F_ADJ_ROOM_DECAP_L3_IPV6 as u64
        }
        (GtpuSessionIpFamily::Ipv6, GtpuSessionIpFamily::Ipv4) => {
            BPF_F_ADJ_ROOM_DECAP_L3_IPV4 as u64
        }
        _ => 0,
    }
}

#[inline(always)]
fn pack_grouped_downlink_offsets(l4_offset: usize, payload_offset: usize) -> Option<u64> {
    let l4_offset = u32::try_from(l4_offset).ok()?;
    let payload_offset = u32::try_from(payload_offset).ok()?;
    Some((u64::from(l4_offset) << 32) | u64::from(payload_offset))
}

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
fn count_pmtu_drop(index: u32) {
    if let Some(counter) = GTPU_PMTU_DROP.get_ptr_mut(index) {
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

/// Resolve one grouped uplink selector without ever re-reading its index.
///
/// `status == GROUPED_LOOKUP_MISS` is the only result that permits the frozen
/// v5 fallback. Once an index exists, every malformed reference, missing
/// authority/configuration, or failed exact-match check remains an error.
#[inline(never)]
fn grouped_uplink_authority<'a>(
    ctx: &'a TcContext,
    mark: u32,
    eth_proto: u16,
    status: &mut u8,
) -> Option<GtpuSessionEntryWireView<'a>> {
    *status = GROUPED_LOOKUP_MISS;
    let mut key_wire = [0_u8; GTPU_SESSION_UPLINK_KEY_LEN];
    let inner_family = match eth_proto {
        ETH_P_IPV4 => {
            let version_ihl = ctx.load::<u8>(ETH_HDR_LEN).ok()?;
            if version_ihl >> 4 != 4 {
                return None;
            }
            key_wire[0] = GtpuSessionIpFamily::Ipv4 as u8;
            key_wire[4..8].copy_from_slice(&ctx.load::<[u8; 4]>(ETH_HDR_LEN + 12).ok()?);
            GtpuSessionIpFamily::Ipv4
        }
        ETH_P_IPV6 => {
            let version = ctx.load::<u8>(ETH_HDR_LEN).ok()?;
            if version >> 4 != 6 {
                return None;
            }
            key_wire[0] = GtpuSessionIpFamily::Ipv6 as u8;
            let source = ctx.load::<[u8; 16]>(ETH_HDR_LEN + 8).ok()?;
            key_wire[4..12].copy_from_slice(&source[..8]);
            GtpuSessionIpFamily::Ipv6
        }
        _ => return None,
    };
    key_wire[20..24].copy_from_slice(&mark.to_be_bytes());
    let index_ptr = GTPU_UL_INDEX.get_ptr(key_wire);
    if grouped_index_permits_v5_fallback(index_ptr.is_some()) {
        return None;
    }
    let index_ptr = index_ptr?;
    *status = GROUPED_LOOKUP_ERROR;
    // SAFETY: one retained map value is borrowed only for this invocation.
    let reference = unsafe { &*index_ptr };
    let mut group_key = [0_u8; GTPU_SESSION_GROUP_ID_LEN];
    group_key.copy_from_slice(&reference[..GTPU_SESSION_GROUP_ID_LEN]);
    let authority_ptr = GTPU_SESSIONS.get_ptr(group_key)?;
    let config_ptr = GTPU_CONFIG6.get_ptr(GTPU_SESSION_CONFIG_KEY)?;
    // SAFETY: tie the retained map-value borrow to this classifier context;
    // no returned view can outlive the packet invocation.
    let authority: &'a [u8; GTPU_SESSION_GROUP_VALUE_LEN] = unsafe { &*authority_ptr };
    let entry = select_gtpu_session_entry_wire(
        authority,
        reference,
        // SAFETY: configuration is borrowed only for this selection call.
        unsafe { &*config_ptr },
        packet_ifindex(ctx),
        inner_family.slot(),
    )?;
    if !entry.authorizes_uplink_key(&key_wire) {
        return None;
    }
    *status = GROUPED_LOOKUP_AUTHORIZED;
    Some(entry)
}

/// Resolve one grouped downlink selector without ever re-reading its index.
///
/// The family-specific outer parser has already proven the GTP-U envelope.
/// The caller distinguishes a true index miss from retained-index failure by
/// checking `status`; only a true miss may enter the frozen v5 TEID maps.
#[inline(never)]
fn grouped_downlink_authority<'a>(
    ctx: &'a TcContext,
    teid: [u8; 4],
    packed_offsets: u64,
    status: &mut u8,
) -> Option<GtpuSessionEntryWireView<'a>> {
    *status = GROUPED_LOOKUP_MISS;
    let l4_offset = usize::try_from(packed_offsets >> 32).ok()?;
    let payload_offset = usize::try_from(packed_offsets as u32).ok()?;
    let outer_family = match u16::from_be(ctx.load::<u16>(12).ok()?) {
        ETH_P_IPV4 => GtpuSessionIpFamily::Ipv4,
        ETH_P_IPV6 => GtpuSessionIpFamily::Ipv6,
        _ => return None,
    };
    let version = ctx.load::<u8>(payload_offset).ok()? >> 4;
    let inner_family = match version {
        4 => GtpuSessionIpFamily::Ipv4,
        6 => GtpuSessionIpFamily::Ipv6,
        _ => {
            *status = GROUPED_LOOKUP_ERROR;
            return None;
        }
    };
    if teid == [0; 4] {
        *status = GROUPED_LOOKUP_ERROR;
        return None;
    }
    let mut key_wire = [0_u8; GTPU_SESSION_DOWNLINK_KEY_LEN];
    key_wire[0] = outer_family as u8;
    key_wire[1] = inner_family as u8;
    key_wire[4..8].copy_from_slice(&teid);
    let index_ptr = GTPU_DL_INDEX.get_ptr(key_wire);
    if grouped_index_permits_v5_fallback(index_ptr.is_some()) {
        return None;
    }
    let index_ptr = index_ptr?;
    *status = GROUPED_LOOKUP_ERROR;
    let mut inner_destination = [0_u8; 16];
    let inner_destination = match inner_family {
        GtpuSessionIpFamily::Ipv4 => {
            let address = ctx.load::<[u8; 4]>(payload_offset + 16).ok()?;
            inner_destination[..4].copy_from_slice(&address);
            inner_destination
        }
        GtpuSessionIpFamily::Ipv6 => ctx.load::<[u8; 16]>(payload_offset + 24).ok()?,
    };
    // SAFETY: retain one selector snapshot and never re-read the index.
    let reference = unsafe { &*index_ptr };
    let mut group_key = [0_u8; GTPU_SESSION_GROUP_ID_LEN];
    group_key.copy_from_slice(&reference[..GTPU_SESSION_GROUP_ID_LEN]);
    let authority_ptr = GTPU_SESSIONS.get_ptr(group_key)?;
    let config_ptr = GTPU_CONFIG6.get_ptr(GTPU_SESSION_CONFIG_KEY)?;
    // SAFETY: tie the retained map-value borrow to this classifier context;
    // no returned view can outlive the packet invocation.
    let authority: &'a [u8; GTPU_SESSION_GROUP_VALUE_LEN] = unsafe { &*authority_ptr };
    let entry = select_gtpu_session_entry_wire(
        authority,
        reference,
        // SAFETY: configuration is borrowed only for this selection call.
        unsafe { &*config_ptr },
        packet_ifindex(ctx),
        inner_family.slot(),
    )?;
    if !entry.authorizes_downlink_key(&key_wire) {
        return None;
    }
    let mut outer_peer = [0_u8; 16];
    let mut outer_local = [0_u8; 16];
    match outer_family {
        GtpuSessionIpFamily::Ipv4 => {
            outer_peer[..4].copy_from_slice(&ctx.load::<[u8; 4]>(ETH_HDR_LEN + 12).ok()?);
            outer_local[..4].copy_from_slice(&ctx.load::<[u8; 4]>(ETH_HDR_LEN + 16).ok()?);
        }
        GtpuSessionIpFamily::Ipv6 => {
            outer_peer = ctx.load::<[u8; 16]>(ETH_HDR_LEN + 8).ok()?;
            outer_local = ctx.load::<[u8; 16]>(ETH_HDR_LEN + 24).ok()?;
        }
    };
    let source_port = u16::from_be(ctx.load::<u16>(l4_offset).ok()?);
    if !entry.authorizes_downlink_packet(&outer_peer, &outer_local, source_port, &inner_destination)
    {
        return None;
    }
    *status = GROUPED_LOOKUP_AUTHORIZED;
    Some(entry)
}

#[inline(always)]
fn grouped_inner_length(ctx: &TcContext, family: GtpuSessionIpFamily) -> Option<u16> {
    let available = (ctx.len() as usize).checked_sub(ETH_HDR_LEN)?;
    match family {
        GtpuSessionIpFamily::Ipv4 => {
            let version_ihl = ctx.load::<u8>(ETH_HDR_LEN).ok()?;
            let total_len = u16::from_be(ctx.load::<u16>(ETH_HDR_LEN + 2).ok()?);
            if !ipv4_inner_length_is_exact(version_ihl, total_len, available) {
                return None;
            }
            Some(total_len)
        }
        GtpuSessionIpFamily::Ipv6 => {
            let version = ctx.load::<u8>(ETH_HDR_LEN).ok()?;
            let payload_len = u16::from_be(ctx.load::<u16>(ETH_HDR_LEN + 4).ok()?);
            if !ipv6_inner_length_is_exact(version, payload_len, available) {
                return None;
            }
            let total_len = IPV6_HDR_LEN.checked_add(usize::from(payload_len))?;
            u16::try_from(total_len).ok()
        }
    }
}

#[inline(always)]
fn packet_gso_size(ctx: &TcContext) -> u32 {
    // SAFETY: the kernel supplies a verifier-checked, non-null `__sk_buff`
    // context. `gso_size` is a fixed-width read-only field.
    unsafe { (*ctx.skb.skb).gso_size }
}

/// Prove that the skb carries fully materialized bytes before software builds
/// an outer IPv6 UDP checksum.
///
/// A non-pseudo checksum replacement changes an ordinary word but Linux
/// deliberately leaves it unchanged for `CHECKSUM_PARTIAL`. EtherType is a
/// safe, aligned two-byte probe shared by both inner families. Every path
/// restores and reloads the exact snapshot before returning.
#[inline(never)]
fn checksum_bytes_are_materialized(ctx: &TcContext) -> bool {
    if packet_gso_size(ctx) != 0 {
        return false;
    }
    let checksum_offset = 12;
    let Ok(original) = ctx.load::<u16>(checksum_offset) else {
        return false;
    };
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
fn ipv6_uplink_pmtu_allows(inner_len: u16, inner_family: GtpuSessionIpFamily) -> bool {
    let Some(policy_ptr) = GTPU_PMTU_CFG.get_ptr(0) else {
        return true;
    };
    // SAFETY: one aligned four-byte map value is read atomically.
    let policy_bytes = unsafe { (policy_ptr as *const u32).read_unaligned() }.to_ne_bytes();
    match GtpuUplinkMtuPolicy::decode_map_value(&policy_bytes) {
        UplinkMtuMapState::Unset => true,
        UplinkMtuMapState::Configured(policy)
            if policy.fragmentation() == GtpuOuterFragmentPolicy::SignalPacketTooBig =>
        {
            let inner_protocol = match inner_family {
                GtpuSessionIpFamily::Ipv4 => GtpuPmtuProtocol::Icmpv4,
                GtpuSessionIpFamily::Ipv6 => GtpuPmtuProtocol::Icmpv6,
            };
            match decide_uplink_pmtu(policy, GtpuSessionIpFamily::Ipv6, inner_len, inner_protocol) {
                UplinkPmtuDecision::Emit { .. } => true,
                UplinkPmtuDecision::RejectTooBig { .. } => {
                    count_pmtu_drop(COUNTER_UL_MTU_REJECT);
                    false
                }
                UplinkPmtuDecision::RequiresOuterFragmentation { .. } => {
                    count_pmtu_drop(COUNTER_UL_PMTU_CORRUPT);
                    false
                }
            }
        }
        UplinkMtuMapState::Configured(_) | UplinkMtuMapState::Corrupt => {
            count_pmtu_drop(COUNTER_UL_PMTU_CORRUPT);
            false
        }
    }
}

#[inline(always)]
fn finalize_internet_checksum(sum: u32) -> u16 {
    let first = (sum & 0xffff) + (sum >> 16);
    let second = (first & 0xffff) + (first >> 16);
    let checksum = !(second as u16);
    if checksum == 0 {
        u16::MAX
    } else {
        checksum
    }
}

#[inline(always)]
fn finalized_internet_checksum_bytes(sum: u32) -> [u8; 2] {
    finalize_internet_checksum(sum).to_ne_bytes()
}

#[inline(always)]
fn complete_grouped_uplink(ctx: &TcContext, mark: u32, ether_type: u16) -> i32 {
    if ctx.store(12, &ether_type.to_be_bytes(), 0).is_err() {
        return TC_ACT_SHOT;
    }
    if mark != 0 {
        ctx.set_mark(0);
    }
    count(COUNTER_UL_ENCAP);
    // SAFETY: no neighbour parameter pointer is supplied; the helper derives
    // the route and neighbour from the newly materialized outer IP header.
    let action = unsafe { bpf_redirect_neigh((*ctx.skb.skb).ifindex, core::ptr::null_mut(), 0, 0) };
    if action == i64::from(TC_ACT_REDIRECT) {
        action as i32
    } else {
        TC_ACT_SHOT
    }
}

#[inline(never)]
fn encapsulate_grouped_ipv6(
    ctx: &TcContext,
    mark: u32,
    entry: GtpuSessionEntryWireView<'_>,
    inner_len: u16,
) -> i32 {
    if entry.outer_family() != GtpuSessionIpFamily::Ipv6
        || !checksum_bytes_are_materialized(ctx)
        || !ipv6_uplink_pmtu_allows(inner_len, entry.inner_family())
    {
        return TC_ACT_SHOT;
    }
    let peer = entry.peer_outer_wire();
    let local = entry.local_outer_wire();
    let Some(udp_length) = inner_len.checked_add(16) else {
        return TC_ACT_SHOT;
    };
    let source_port = entry.uplink_source_port();
    if source_port == 0 {
        return TC_ACT_SHOT;
    }
    let traffic_class = entry.egress_dscp().unwrap_or(0) << 2;
    let mut encap = [0_u8; GTPU_IPV6_ENCAP_LEN];
    encap[0] = 0x60 | (traffic_class >> 4);
    encap[1] = traffic_class << 4;
    encap[4..6].copy_from_slice(&udp_length.to_be_bytes());
    encap[6] = IPV6_NH_UDP;
    encap[7] = 64;
    encap[8..24].copy_from_slice(&local);
    encap[24..40].copy_from_slice(&peer);
    encap[40..42].copy_from_slice(&source_port.to_be_bytes());
    encap[42..44].copy_from_slice(&GTPU_UDP_PORT.to_be_bytes());
    encap[44..46].copy_from_slice(&udp_length.to_be_bytes());
    encap[48] = GTPU_FLAGS_V1_GPDU;
    encap[49] = GTPU_MSG_TYPE_GPDU;
    encap[50..52].copy_from_slice(&inner_len.to_be_bytes());
    encap[52..56].copy_from_slice(&entry.peer_teid());

    let mut pseudo_header = [0_u8; 40];
    pseudo_header[..16].copy_from_slice(&local);
    pseudo_header[16..32].copy_from_slice(&peer);
    pseudo_header[32..36].copy_from_slice(&u32::from(udp_length).to_be_bytes());
    pseudo_header[39] = IPV6_NH_UDP;
    // SAFETY: both stack buffers are fully initialized and each helper length
    // is a nonzero multiple of four.
    let pseudo_sum = unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            pseudo_header.as_mut_ptr().cast::<u32>(),
            pseudo_header.len() as u32,
            0,
        )
    };
    if pseudo_sum < 0 {
        return TC_ACT_SHOT;
    }
    // SAFETY: bytes 40..56 are the initialized fixed UDP/GTP header and its
    // length is a nonzero multiple of four.
    let fixed_sum = unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            encap.as_mut_ptr().add(IPV6_HDR_LEN).cast::<u32>(),
            16,
            pseudo_sum as u32,
        )
    };
    if fixed_sum < 0 {
        return TC_ACT_SHOT;
    }
    let Ok(sum) = checksum_skb_region(ctx, ETH_HDR_LEN, usize::from(inner_len), fixed_sum as u32)
    else {
        return TC_ACT_SHOT;
    };
    encap[46..48].copy_from_slice(&finalized_internet_checksum_bytes(sum));
    if ctx
        .skb
        .adjust_room(
            encap.len() as i32,
            BPF_ADJ_ROOM_MAC,
            u64::from(BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP),
        )
        .is_err()
        || ctx.store(ETH_HDR_LEN, &encap, 0).is_err()
    {
        return TC_ACT_SHOT;
    }
    complete_grouped_uplink(ctx, mark, ETH_P_IPV6)
}

#[inline(never)]
fn encapsulate_grouped_ipv4(
    ctx: &TcContext,
    mark: u32,
    entry: GtpuSessionEntryWireView<'_>,
    inner_len: u16,
) -> i32 {
    if entry.outer_family() != GtpuSessionIpFamily::Ipv4 {
        return TC_ACT_SHOT;
    }
    let peer = entry.peer_outer_wire();
    let local = entry.local_outer_wire();
    let far = UplinkFar {
        peer_ip: [peer[0], peer[1], peer[2], peer[3]],
        local_ip: [local[0], local[1], local[2], local[3]],
        o_teid: entry.peer_teid(),
    };
    let Some(mut encap) = build_uplink_encap_with_dscp_and_source_port(
        &far,
        inner_len,
        entry.egress_dscp(),
        entry.uplink_source_port(),
    ) else {
        return TC_ACT_SHOT;
    };
    if let Some(policy_ptr) = GTPU_PMTU_CFG.get_ptr(0) {
        // SAFETY: one aligned four-byte map value is read atomically.
        let bytes = unsafe { (policy_ptr as *const u32).read_unaligned() }.to_ne_bytes();
        match GtpuUplinkMtuPolicy::decode_map_value(&bytes) {
            UplinkMtuMapState::Unset => {}
            UplinkMtuMapState::Configured(policy)
                if policy.fragmentation() == GtpuOuterFragmentPolicy::SignalPacketTooBig =>
            {
                if !apply_uplink_mtu_policy(&mut encap, policy) {
                    count_pmtu_drop(COUNTER_UL_MTU_REJECT);
                    return TC_ACT_SHOT;
                }
            }
            UplinkMtuMapState::Configured(_) | UplinkMtuMapState::Corrupt => {
                count_pmtu_drop(COUNTER_UL_PMTU_CORRUPT);
                return TC_ACT_SHOT;
            }
        }
    }
    if ctx
        .skb
        .adjust_room(
            encap.len() as i32,
            BPF_ADJ_ROOM_MAC,
            u64::from(BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP),
        )
        .is_err()
        || ctx.store(ETH_HDR_LEN, &encap, 0).is_err()
    {
        return TC_ACT_SHOT;
    }
    complete_grouped_uplink(ctx, mark, ETH_P_IPV4)
}

#[inline(always)]
fn encapsulate_grouped_uplink(
    ctx: &TcContext,
    mark: u32,
    entry: GtpuSessionEntryWireView<'_>,
) -> i32 {
    let Some(inner_len) = grouped_inner_length(ctx, entry.inner_family()) else {
        return TC_ACT_SHOT;
    };
    match entry.outer_family() {
        GtpuSessionIpFamily::Ipv4 => encapsulate_grouped_ipv4(ctx, mark, entry, inner_len),
        GtpuSessionIpFamily::Ipv6 => encapsulate_grouped_ipv6(ctx, mark, entry, inner_len),
    }
}

#[inline(always)]
fn grouped_inner_payload_is_exact(
    ctx: &TcContext,
    payload_offset: usize,
    family: GtpuSessionIpFamily,
) -> bool {
    let Some(available) = (ctx.len() as usize).checked_sub(payload_offset) else {
        return false;
    };
    match family {
        GtpuSessionIpFamily::Ipv4 => {
            let Ok(version_ihl) = ctx.load::<u8>(payload_offset) else {
                return false;
            };
            let Ok(total_len) = ctx.load::<u16>(payload_offset + 2) else {
                return false;
            };
            ipv4_inner_length_is_exact(version_ihl, u16::from_be(total_len), available)
        }
        GtpuSessionIpFamily::Ipv6 => {
            let Ok(version) = ctx.load::<u8>(payload_offset) else {
                return false;
            };
            let Ok(payload_len) = ctx.load::<u16>(payload_offset + 4) else {
                return false;
            };
            ipv6_inner_length_is_exact(version, u16::from_be(payload_len), available)
        }
    }
}

#[inline(never)]
fn decap_grouped_downlink(
    ctx: &TcContext,
    outer_family: GtpuSessionIpFamily,
    payload_offset: usize,
    entry: GtpuSessionEntryWireView<'_>,
) -> i32 {
    let inner_family = entry.inner_family();
    if !grouped_inner_payload_is_exact(ctx, payload_offset, inner_family) {
        count(COUNTER_DL_MALFORMED);
        return TC_ACT_SHOT;
    }
    let Some(strip) = payload_offset.checked_sub(ETH_HDR_LEN) else {
        count(COUNTER_DL_MALFORMED);
        return TC_ACT_SHOT;
    };
    let Ok(strip) = i32::try_from(strip) else {
        count(COUNTER_DL_MALFORMED);
        return TC_ACT_SHOT;
    };
    let decap_flags = grouped_decap_flags(outer_family, inner_family);
    if ctx
        .skb
        .adjust_room(-strip, BPF_ADJ_ROOM_MAC, decap_flags)
        .is_err()
    {
        count(COUNTER_DL_MALFORMED);
        return TC_ACT_SHOT;
    }
    let ether_type = match inner_family {
        GtpuSessionIpFamily::Ipv4 => ETH_P_IPV4,
        GtpuSessionIpFamily::Ipv6 => ETH_P_IPV6,
    };
    if ctx.store(12, &ether_type.to_be_bytes(), 0).is_err() {
        count(COUNTER_DL_MALFORMED);
        return TC_ACT_SHOT;
    }
    ctx.set_mark(u32::from_be_bytes(entry.bearer_mark()));
    count(COUNTER_DL_DECAP);
    TC_ACT_OK
}

#[repr(C)]
struct Ipv6ExtensionLoopContext {
    skb: *mut __sk_buff,
    ip_end: u32,
    cursor: u32,
    option_remaining: u32,
    walked: u32,
    options_walked: u32,
    next_header: u32,
    flags: u32,
    state: u32,
}

const IPV6_EXTENSION_STATE_WALK: u32 = 0;
const IPV6_EXTENSION_STATE_OPTIONS: u32 = 1;
const IPV6_EXTENSION_STATE_DONE: u32 = 2;
const IPV6_EXTENSION_STATE_FAILED: u32 = 3;

const IPV6_EXTENSION_FLAG_FRAGMENT: u32 = 1 << 0;
const IPV6_EXTENSION_FLAG_ROUTING: u32 = 1 << 1;
const IPV6_EXTENSION_FLAG_PRE_ROUTING_DESTINATION: u32 = 1 << 2;
const IPV6_EXTENSION_FLAG_FINAL_DESTINATION: u32 = 1 << 3;
const IPV6_EXTENSION_FLAGS_MASK: u32 = IPV6_EXTENSION_FLAG_FRAGMENT
    | IPV6_EXTENSION_FLAG_ROUTING
    | IPV6_EXTENSION_FLAG_PRE_ROUTING_DESTINATION
    | IPV6_EXTENSION_FLAG_FINAL_DESTINATION;
const IPV6_PACKET_MAX_END: u32 = (ETH_HDR_LEN + IPV6_HDR_LEN + u16::MAX as usize) as u32;
const IPV6_OPTIONS_MAX_BYTES: u32 = (u8::MAX as u32 + 1) * 8 - 2;

// One iteration discovers an extension header or consumes one option TLV.
// Eight headers carrying the maximum 32 options each therefore require at
// most 8 * (1 + 32) verifier-bounded steps.
const IPV6_EXTENSION_LOOP_STEPS: u32 =
    (IPV6_MAX_EXT_HEADERS * (IPV6_MAX_OPTIONS_PER_HEADER + 1)) as u32;

/// Advance one state in the complete IPv6 extension-chain walk.
///
/// A single `bpf_loop` owns both extension discovery and option-TLV parsing.
/// This avoids multiplying verifier states across nested loops while retaining
/// the exact header-count and per-options-header limits.
#[inline(never)]
unsafe extern "C" fn walk_ipv6_extension_step(_index: u64, context: *mut c_void) -> i64 {
    // SAFETY: `ipv6_udp_offset` passes a live, uniquely borrowed
    // stack context for the complete synchronous `bpf_loop` call.
    let context = unsafe { &mut *context.cast::<Ipv6ExtensionLoopContext>() };
    if context.state > IPV6_EXTENSION_STATE_OPTIONS {
        return 1;
    }
    // `bpf_loop` revisits this callback with caller-stack scalars. Reassert
    // every protocol bound so imprecise merged states cannot turn a bounded
    // packet cursor or state field into an unbounded branch.
    if context.ip_end < (ETH_HDR_LEN + IPV6_HDR_LEN) as u32
        || context.ip_end > IPV6_PACKET_MAX_END
        || context.cursor < (ETH_HDR_LEN + IPV6_HDR_LEN) as u32
        || context.cursor > context.ip_end
        || context.option_remaining > IPV6_OPTIONS_MAX_BYTES
        || context.walked > IPV6_MAX_EXT_HEADERS as u32
        || context.options_walked > IPV6_MAX_OPTIONS_PER_HEADER as u32
        || context.next_header > u32::from(u8::MAX)
        || context.flags & !IPV6_EXTENSION_FLAGS_MASK != 0
    {
        context.state = IPV6_EXTENSION_STATE_FAILED;
        return 1;
    }

    if context.state == IPV6_EXTENSION_STATE_OPTIONS {
        if context.option_remaining == 0
            || context.options_walked >= IPV6_MAX_OPTIONS_PER_HEADER as u32
            || context.cursor >= context.ip_end
        {
            context.state = IPV6_EXTENSION_STATE_FAILED;
            return 1;
        }

        let mut option_type = core::mem::MaybeUninit::<u8>::uninit();
        // SAFETY: the live skb and checked cursor are valid helper inputs. A
        // successful load initializes the one-byte stack destination.
        if unsafe {
            bpf_skb_load_bytes(
                context.skb.cast(),
                context.cursor,
                option_type.as_mut_ptr().cast(),
                1,
            )
        } != 0
        {
            context.state = IPV6_EXTENSION_STATE_FAILED;
            return 1;
        }
        // SAFETY: the preceding helper initialized this byte.
        let option_type = unsafe { option_type.assume_init() };
        let consumed = if option_type == 0 {
            1
        } else {
            if context.option_remaining < 2 {
                context.state = IPV6_EXTENSION_STATE_FAILED;
                return 1;
            }
            let length_offset = context.cursor + 1;
            let mut option_length = core::mem::MaybeUninit::<u8>::uninit();
            // SAFETY: two declared option bytes remain, so the length octet
            // is within the already bounded extension header.
            if unsafe {
                bpf_skb_load_bytes(
                    context.skb.cast(),
                    length_offset,
                    option_length.as_mut_ptr().cast(),
                    1,
                )
            } != 0
            {
                context.state = IPV6_EXTENSION_STATE_FAILED;
                return 1;
            }
            // SAFETY: the preceding helper initialized this byte.
            let option_length = unsafe { option_length.assume_init() };
            if option_type != 1 && option_type >> 6 != 0 {
                context.state = IPV6_EXTENSION_STATE_FAILED;
                return 1;
            }
            u32::from(option_length) + 2
        };
        if consumed > context.option_remaining {
            context.state = IPV6_EXTENSION_STATE_FAILED;
            return 1;
        }
        let cursor = context.cursor + consumed;
        if cursor > context.ip_end {
            context.state = IPV6_EXTENSION_STATE_FAILED;
            return 1;
        }
        context.cursor = cursor;
        context.option_remaining -= consumed;
        context.options_walked += 1;
        if context.option_remaining != 0 {
            return 0;
        }

        context.state = IPV6_EXTENSION_STATE_WALK;
        if context.next_header == u32::from(IPV6_NH_UDP) {
            context.state = IPV6_EXTENSION_STATE_DONE;
            return 1;
        }
        if context.walked >= IPV6_MAX_EXT_HEADERS as u32 {
            context.state = IPV6_EXTENSION_STATE_FAILED;
            return 1;
        }
        return 0;
    }

    if context.next_header == u32::from(IPV6_NH_UDP) {
        context.state = IPV6_EXTENSION_STATE_DONE;
        return 1;
    }
    if context.walked >= IPV6_MAX_EXT_HEADERS as u32 {
        context.state = IPV6_EXTENSION_STATE_FAILED;
        return 1;
    }

    let current_header = context.next_header as u8;
    let fragment_seen = context.flags & IPV6_EXTENSION_FLAG_FRAGMENT != 0;
    let routing_seen = context.flags & IPV6_EXTENSION_FLAG_ROUTING != 0;
    let pre_routing_destination_seen =
        context.flags & IPV6_EXTENSION_FLAG_PRE_ROUTING_DESTINATION != 0;
    let final_destination_seen = context.flags & IPV6_EXTENSION_FLAG_FINAL_DESTINATION != 0;
    if current_header == IPV6_NH_HOP_BY_HOP && context.walked != 0
        || current_header == IPV6_NH_ROUTING && routing_seen
        || current_header == IPV6_NH_FRAGMENT && fragment_seen
        || current_header == IPV6_NH_ROUTING && (fragment_seen || final_destination_seen)
        || current_header == IPV6_NH_FRAGMENT
            && (final_destination_seen || pre_routing_destination_seen && !routing_seen)
        || current_header == IPV6_NH_DESTINATION_OPTIONS && final_destination_seen
        || current_header == IPV6_NH_DESTINATION_OPTIONS
            && pre_routing_destination_seen
            && !routing_seen
    {
        context.state = IPV6_EXTENSION_STATE_FAILED;
        return 1;
    }

    let prefix_end = context.cursor + 8;
    if prefix_end > context.ip_end {
        context.state = IPV6_EXTENSION_STATE_FAILED;
        return 1;
    }
    let mut prefix = core::mem::MaybeUninit::<[u8; 8]>::uninit();
    // SAFETY: the explicit declared-packet bound proves the eight-byte prefix
    // is available. Successful load initializes the complete stack array.
    if unsafe {
        bpf_skb_load_bytes(
            context.skb.cast(),
            context.cursor,
            prefix.as_mut_ptr().cast(),
            8,
        )
    } != 0
    {
        context.state = IPV6_EXTENSION_STATE_FAILED;
        return 1;
    }
    // SAFETY: the preceding helper initialized the complete array.
    let prefix = unsafe { prefix.assume_init() };
    let available = context.ip_end - context.cursor;
    let header_len = match current_header {
        IPV6_NH_HOP_BY_HOP | IPV6_NH_ROUTING | IPV6_NH_DESTINATION_OPTIONS => {
            (u32::from(prefix[1]) + 1) * 8
        }
        IPV6_NH_FRAGMENT => {
            let fragment = u16::from_be_bytes([prefix[2], prefix[3]]);
            if fragment & 0xfff8 != 0 || fragment & 0x0001 != 0 {
                context.state = IPV6_EXTENSION_STATE_FAILED;
                return 1;
            }
            8
        }
        _ => {
            context.state = IPV6_EXTENSION_STATE_FAILED;
            return 1;
        }
    };
    if header_len > available {
        context.state = IPV6_EXTENSION_STATE_FAILED;
        return 1;
    }
    let header_end = context.cursor + header_len;
    if header_end > context.ip_end {
        context.state = IPV6_EXTENSION_STATE_FAILED;
        return 1;
    }
    if current_header == IPV6_NH_ROUTING && !validate_ipv6_routing_skb(prefix, header_len as usize)
    {
        context.state = IPV6_EXTENSION_STATE_FAILED;
        return 1;
    }

    match current_header {
        IPV6_NH_ROUTING => context.flags |= IPV6_EXTENSION_FLAG_ROUTING,
        IPV6_NH_FRAGMENT => context.flags |= IPV6_EXTENSION_FLAG_FRAGMENT,
        IPV6_NH_DESTINATION_OPTIONS if routing_seen || fragment_seen => {
            context.flags |= IPV6_EXTENSION_FLAG_FINAL_DESTINATION;
        }
        IPV6_NH_DESTINATION_OPTIONS => {
            context.flags |= IPV6_EXTENSION_FLAG_PRE_ROUTING_DESTINATION;
        }
        _ => {}
    }
    context.walked += 1;
    context.next_header = u32::from(prefix[0]);

    if current_header == IPV6_NH_HOP_BY_HOP || current_header == IPV6_NH_DESTINATION_OPTIONS {
        context.cursor += 2;
        context.option_remaining = header_len - 2;
        context.options_walked = 0;
        context.state = IPV6_EXTENSION_STATE_OPTIONS;
        return 0;
    }

    context.cursor = header_end;
    if context.next_header == u32::from(IPV6_NH_UDP) {
        context.state = IPV6_EXTENSION_STATE_DONE;
        return 1;
    }
    if context.walked >= IPV6_MAX_EXT_HEADERS as u32 {
        context.state = IPV6_EXTENSION_STATE_FAILED;
        return 1;
    }
    0
}

#[inline(always)]
fn validate_ipv6_routing_skb(prefix: [u8; 8], header_len: usize) -> bool {
    if prefix[3] != 0 {
        return false;
    }
    match prefix[2] {
        0 => false,
        2 => {
            header_len == 24 && prefix[4] == 0 && prefix[5] == 0 && prefix[6] == 0 && prefix[7] == 0
        }
        4 => usize::from(prefix[4])
            .checked_add(1)
            .and_then(|entries| entries.checked_mul(16))
            .and_then(|bytes| bytes.checked_add(8))
            .is_some_and(|minimum| minimum <= header_len),
        _ => true,
    }
}

/// Walk the declared IPv6 extension chain without materializing it.
///
/// `None` always means "let the IPv6 stack decide": the caller has not yet
/// proven a UDP/2152 candidate. Atomic fragments are accepted; packets that
/// require reassembly, AH/ESP, active routing, and discard-required options
/// remain untouched for the host stack.
#[inline(never)]
fn ipv6_udp_offset(ctx: &TcContext, ip_end: usize) -> Option<usize> {
    let next_header = ctx.load::<u8>(ETH_HDR_LEN + 6).ok()?;
    let cursor = ETH_HDR_LEN.checked_add(IPV6_HDR_LEN)?;
    if next_header == IPV6_NH_UDP {
        return Some(cursor);
    }
    let mut loop_context = Ipv6ExtensionLoopContext {
        skb: ctx.skb.skb,
        ip_end: u32::try_from(ip_end).ok()?,
        cursor: u32::try_from(cursor).ok()?,
        option_remaining: 0,
        walked: 0,
        options_walked: 0,
        next_header: u32::from(next_header),
        flags: 0,
        state: IPV6_EXTENSION_STATE_WALK,
    };
    // SAFETY: the callback has the ABI required by `bpf_loop`. The mutable
    // context remains live for the synchronous helper call, and flags zero is
    // the only supported mode.
    let performed = unsafe {
        bpf_loop(
            IPV6_EXTENSION_LOOP_STEPS,
            walk_ipv6_extension_step as *mut c_void,
            (&mut loop_context as *mut Ipv6ExtensionLoopContext).cast(),
            0,
        )
    };
    if performed < 0 || loop_context.state != IPV6_EXTENSION_STATE_DONE {
        return None;
    }
    usize::try_from(loop_context.cursor).ok()
}

#[inline(never)]
fn software_ipv6_udp_checksum_is_valid(
    ctx: &TcContext,
    udp_offset: usize,
    udp_length: usize,
) -> bool {
    let Ok(source) = ctx.load::<[u8; 16]>(ETH_HDR_LEN + 8) else {
        return false;
    };
    let Ok(destination) = ctx.load::<[u8; 16]>(ETH_HDR_LEN + 24) else {
        return false;
    };
    let Ok(udp_length) = u32::try_from(udp_length) else {
        return false;
    };
    let mut pseudo_header = [0_u8; 40];
    pseudo_header[..16].copy_from_slice(&source);
    pseudo_header[16..32].copy_from_slice(&destination);
    pseudo_header[32..36].copy_from_slice(&udp_length.to_be_bytes());
    pseudo_header[39] = IPV6_NH_UDP;
    // SAFETY: the pseudo-header is fully initialized and its length is a
    // nonzero multiple of four.
    let pseudo_sum = unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            pseudo_header.as_mut_ptr().cast::<u32>(),
            pseudo_header.len() as u32,
            0,
        )
    };
    if pseudo_sum < 0 {
        return false;
    }
    checksum_skb_region(ctx, udp_offset, udp_length as usize, pseudo_sum as u32)
        .is_ok_and(internet_checksum_sum_is_valid)
}

#[inline(always)]
fn ipv6_udp_checksum_is_valid(ctx: &TcContext, udp_offset: usize, udp_length: usize) -> bool {
    let checksum_offset = match udp_offset.checked_add(6) {
        Some(offset) => offset,
        None => return false,
    };
    let Ok(checksum) = ctx.load::<u16>(checksum_offset) else {
        return false;
    };
    if u16::from_be(checksum) == 0 {
        return false;
    }
    // SAFETY: read-only metadata query over the live tc skb.
    let kernel_verified =
        unsafe { bpf_csum_level(ctx.skb.skb, u64::from(BPF_CSUM_LEVEL_QUERY)) >= 0 };
    kernel_verified
        || nonzero_udp_checksum_has_no_pending_offload(ctx, checksum_offset)
            && software_ipv6_udp_checksum_is_valid(ctx, udp_offset, udp_length)
}

#[inline(never)]
fn parse_downlink_ipv6(ctx: &mut TcContext, parsed: &mut ParsedIpv6Downlink) -> i32 {
    let base_end = ETH_HDR_LEN + IPV6_HDR_LEN;
    if (ctx.len() as usize) < base_end {
        return IPV6_PARSE_PASS;
    }
    let Ok(version) = ctx.load::<u8>(ETH_HDR_LEN) else {
        return IPV6_PARSE_PASS;
    };
    if version >> 4 != 6 {
        return IPV6_PARSE_PASS;
    }
    let Ok(payload_length) = ctx.load::<u16>(ETH_HDR_LEN + 4) else {
        return IPV6_PARSE_PASS;
    };
    let payload_length = usize::from(u16::from_be(payload_length));
    if payload_length == 0 {
        return IPV6_PARSE_PASS;
    }
    let Some(ip_end) = base_end.checked_add(payload_length) else {
        return IPV6_PARSE_PASS;
    };
    if ip_end > ctx.len() as usize {
        return IPV6_PARSE_PASS;
    }
    let Some(udp_offset) = ipv6_udp_offset(ctx, ip_end) else {
        return IPV6_PARSE_PASS;
    };
    let Some(destination_end) = udp_offset.checked_add(4) else {
        return IPV6_PARSE_PASS;
    };
    if destination_end > ip_end {
        return IPV6_PARSE_PASS;
    }
    let Ok(destination_port) = ctx.load::<u16>(udp_offset + 2) else {
        return IPV6_PARSE_PASS;
    };
    if u16::from_be(destination_port) != GTPU_UDP_PORT {
        return IPV6_PARSE_PASS;
    }

    // UDP/2152 is now proven. Every malformed boundary, checksum, or G-PDU
    // declaration fails closed before the grouped selector lookup.
    if packet_gso_size(ctx) != 0 {
        return IPV6_PARSE_DROP;
    }
    let Some(udp_header_end) = udp_offset.checked_add(8) else {
        return IPV6_PARSE_DROP;
    };
    if udp_header_end > ip_end {
        return IPV6_PARSE_DROP;
    }
    let Ok(udp_length) = ctx.load::<u16>(udp_offset + 4) else {
        return IPV6_PARSE_DROP;
    };
    let udp_length = usize::from(u16::from_be(udp_length));
    let Some(udp_end) = udp_offset.checked_add(udp_length) else {
        return IPV6_PARSE_DROP;
    };
    if udp_length < IPV6_FIXED_AND_UDP_GTP_LEN - IPV6_HDR_LEN
        || udp_end != ip_end
        || !ipv6_udp_checksum_is_valid(ctx, udp_offset, udp_length)
    {
        return IPV6_PARSE_DROP;
    }
    let gtp_offset = udp_header_end;
    let Ok(gtp_header) = ctx.load::<[u8; GTPU_MANDATORY_HDR_LEN]>(gtp_offset) else {
        return IPV6_PARSE_DROP;
    };
    let declared_gtp_length = u16::from_be_bytes([gtp_header[2], gtp_header[3]]);
    let Some(gtp_end) = gtp_offset
        .checked_add(GTPU_MANDATORY_HDR_LEN)
        .and_then(|offset| offset.checked_add(usize::from(declared_gtp_length)))
    else {
        return IPV6_PARSE_DROP;
    };
    if gtp_end != udp_end {
        return IPV6_PARSE_DROP;
    }
    let (teid, gtp_length, has_opt, has_ext) = match classify_gtpu(&gtp_header) {
        GtpuClass::NotGtpV1 | GtpuClass::NotGpdu => return IPV6_PARSE_PASS,
        GtpuClass::Gpdu {
            teid,
            length,
            has_opt,
            has_ext,
        } => (teid, length, has_opt, has_ext),
    };
    if gtp_length != declared_gtp_length {
        return IPV6_PARSE_DROP;
    }
    let Some(mut payload_offset) = gtp_offset.checked_add(GTPU_MANDATORY_HDR_LEN) else {
        return IPV6_PARSE_DROP;
    };
    if has_opt {
        let Some(optional_end) = payload_offset.checked_add(GTPU_OPT_LEN) else {
            return IPV6_PARSE_DROP;
        };
        if optional_end > gtp_end {
            return IPV6_PARSE_DROP;
        }
        let Ok(optional) = ctx.load::<[u8; GTPU_OPT_LEN]>(payload_offset) else {
            return IPV6_PARSE_DROP;
        };
        payload_offset = optional_end;
        if has_ext {
            let mut next_extension = optional[3];
            let mut walked = 0_usize;
            while next_extension != 0 {
                if walked == GTPU_MAX_EXT_HEADERS || payload_offset >= gtp_end {
                    return IPV6_PARSE_DROP;
                }
                let Ok(length_units) = ctx.load::<u8>(payload_offset) else {
                    return IPV6_PARSE_DROP;
                };
                if length_units == 0 {
                    return IPV6_PARSE_DROP;
                }
                let Some(extension_end) = usize::from(length_units)
                    .checked_mul(4)
                    .and_then(|length| payload_offset.checked_add(length))
                else {
                    return IPV6_PARSE_DROP;
                };
                if extension_end > gtp_end {
                    return IPV6_PARSE_DROP;
                }
                let Ok(following) = ctx.load::<u8>(extension_end - 1) else {
                    return IPV6_PARSE_DROP;
                };
                payload_offset = extension_end;
                next_extension = following;
                walked += 1;
            }
        }
    }
    if payload_offset >= gtp_end
        || payload_offset
            .checked_add(20)
            .is_none_or(|minimum| minimum > gtp_end)
    {
        return IPV6_PARSE_DROP;
    }
    let (Ok(ip_end), Ok(udp_offset), Ok(payload_offset)) = (
        u32::try_from(ip_end),
        u32::try_from(udp_offset),
        u32::try_from(payload_offset),
    ) else {
        return IPV6_PARSE_DROP;
    };
    *parsed = ParsedIpv6Downlink {
        ip_end,
        udp_offset,
        payload_offset,
        teid,
    };
    IPV6_PARSE_ACCEPT
}

#[inline(never)]
fn handle_downlink_ipv6(ctx: &mut TcContext) -> i32 {
    let mut parsed = ParsedIpv6Downlink::EMPTY;
    match parse_downlink_ipv6(ctx, &mut parsed) {
        IPV6_PARSE_PASS => return TC_ACT_OK,
        IPV6_PARSE_DROP => return malformed_downlink(),
        IPV6_PARSE_ACCEPT => {}
        _ => return malformed_downlink(),
    }
    if parsed.ip_end < ctx.len() {
        // SAFETY: the parser proved this exact declared IPv6 packet end is
        // within the skb. Trimming only removes trailing L2 padding.
        if unsafe { bpf_skb_change_tail(ctx.skb.skb, parsed.ip_end, 0) } != 0 {
            return malformed_downlink();
        }
    }
    let (Ok(udp_offset), Ok(payload_offset)) = (
        usize::try_from(parsed.udp_offset),
        usize::try_from(parsed.payload_offset),
    ) else {
        return malformed_downlink();
    };
    let Some(packed_offsets) = pack_grouped_downlink_offsets(udp_offset, payload_offset) else {
        return malformed_downlink();
    };
    let mut status = GROUPED_LOOKUP_MISS;
    match grouped_downlink_authority(ctx, parsed.teid, packed_offsets, &mut status) {
        Some(entry) => {
            decap_grouped_downlink(ctx, GtpuSessionIpFamily::Ipv6, payload_offset, entry)
        }
        None if status == GROUPED_LOOKUP_ERROR => binding_drop(DownlinkBindingMismatch::Invalid),
        None => {
            // The frozen v5 schema has no outer-IPv6 selector. A valid G-PDU
            // with no grouped owner is therefore unknown, never pass-through.
            count(COUNTER_DL_UNKNOWN_TEID);
            TC_ACT_SHOT
        }
    }
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
    let Ok(ether_type) = ctx.load::<u16>(12) else {
        return TC_ACT_OK;
    };
    if u16::from_be(ether_type) == ETH_P_IPV6 {
        return handle_downlink_ipv6(&mut ctx);
    }
    let parsed = parse_downlink(&mut ctx);
    let ipv4_total_length = downlink_parse_ipv4_total_length(parsed);
    if ipv4_total_length == 0 {
        return parsed as i32;
    }
    let Some(ip_end) = downlink_frame_end(ipv4_total_length) else {
        return malformed_downlink();
    };
    if (ip_end as usize) < ctx.len() as usize {
        // SAFETY: the parser proved that this end derives from the canonical
        // IPv4 Total Length and does not exceed the skb. Keeping the trim in
        // this frame preserves the checksum metadata transition through the
        // subsequent front decapsulation helper.
        if unsafe { bpf_skb_change_tail(ctx.skb.skb, ip_end, 0) } != 0 {
            return malformed_downlink();
        }
    }
    let Ok(version_ihl) = ctx.load::<u8>(ETH_HDR_LEN) else {
        return malformed_downlink();
    };
    let Some(l4_offset) = usize::from(version_ihl & 0x0f)
        .checked_mul(4)
        .and_then(|length| ETH_HDR_LEN.checked_add(length))
    else {
        return malformed_downlink();
    };
    let payload_offset = usize::from(downlink_parse_payload_offset(parsed));
    let teid = downlink_parse_teid(parsed);
    let Some(packed_offsets) = pack_grouped_downlink_offsets(l4_offset, payload_offset) else {
        return malformed_downlink();
    };
    let mut grouped_status = GROUPED_LOOKUP_MISS;
    match grouped_downlink_authority(&ctx, teid, packed_offsets, &mut grouped_status) {
        Some(entry) => {
            return decap_grouped_downlink(&ctx, GtpuSessionIpFamily::Ipv4, payload_offset, entry);
        }
        None if grouped_status == GROUPED_LOOKUP_ERROR => {
            return binding_drop(DownlinkBindingMismatch::Invalid);
        }
        None => {}
    }
    authorize_and_decap_legacy_downlink(&mut ctx, teid, l4_offset, payload_offset)
}

/// Uplink: inner IPv4 packet routed to the S2b-U interface with
/// `src = UE PAA`. Prepend `[outer IPv4][UDP][GTPv1-U]` and re-resolve the
/// L2 next hop for the new outer destination.
fn try_uplink(ctx: &mut TcContext, mark: u32) -> Result<i32, ()> {
    let eth_proto = u16::from_be(ctx.load(12).map_err(|_| ())?);
    let mut grouped_status = GROUPED_LOOKUP_MISS;
    match grouped_uplink_authority(ctx, mark, eth_proto, &mut grouped_status) {
        Some(entry) => return Ok(encapsulate_grouped_uplink(ctx, mark, entry)),
        None if grouped_status == GROUPED_LOOKUP_ERROR => return Ok(TC_ACT_SHOT),
        None => {}
    }
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
    let owner_ptr = if mark != 0 {
        let Some(owner_ptr) = GTPU_M_OWNER.get_ptr(&marked_key) else {
            count(COUNTER_UL_FAR_MISS);
            return Ok(TC_ACT_SHOT as i32);
        };
        Some(owner_ptr)
    } else {
        None
    };
    let dscp = if dscp_wire == 0xff {
        None
    } else {
        Some(dscp_wire)
    };
    let sport_ptr = if mark == 0 {
        GTPU_UL_SPORT.get_ptr(&inner_src)
    } else {
        GTPU_ULM_SPORT.get_ptr(&marked_key)
    };
    let Some(sport_ptr) = sport_ptr else {
        // Every committed v4 bearer owns one explicit policy entry, including
        // legacy 2152. Absence is durable-state corruption, never an implicit
        // policy transition.
        return Ok(TC_ACT_SHOT as i32);
    };
    // SAFETY: the map value outlives this invocation and is read only.
    let commit = unsafe { &*sport_ptr };
    let local_teid = [commit[0], commit[1], commit[2], commit[3]];
    if mark == 0 {
        if GTPU_DLM_PDR.get_ptr(&local_teid).is_some() {
            return Ok(TC_ACT_SHOT as i32);
        }
        let Some(pdr_ptr) = GTPU_DOWNLINK_PDR.get_ptr(&local_teid) else {
            return Ok(TC_ACT_SHOT as i32);
        };
        // SAFETY: the map value remains map-owned and read-only for this
        // complete-graph comparison.
        if DownlinkPdr::decode(unsafe { &*pdr_ptr }).ue_ip != inner_src {
            return Ok(TC_ACT_SHOT as i32);
        }
    } else {
        if GTPU_DOWNLINK_PDR.get_ptr(&local_teid).is_some() {
            return Ok(TC_ACT_SHOT as i32);
        }
        let Some(pdr_ptr) = GTPU_DLM_PDR.get_ptr(&local_teid) else {
            return Ok(TC_ACT_SHOT as i32);
        };
        // SAFETY: the map value remains map-owned and read-only for this
        // complete-graph comparison.
        let pdr = MarkedDownlinkPdr::decode(unsafe { &*pdr_ptr });
        if pdr.ue_ip != inner_src || pdr.bearer_mark != mark.to_be_bytes() {
            return Ok(TC_ACT_SHOT as i32);
        }
    }
    let Some(binding_ptr) = GTPU_DL_BIND.get_ptr(&local_teid) else {
        return Ok(TC_ACT_SHOT as i32);
    };
    // SAFETY: the map value remains map-owned and read-only. An Active commit
    // authorizes uplink encapsulation only while every live component in both
    // directions still matches the same record.
    let binding = unsafe { &*binding_ptr };
    if !pdp_commit_wire_authorizes_graph(commit, local_teid, &far, dscp_wire, binding) {
        return Ok(TC_ACT_SHOT as i32);
    }
    if let Some(owner_ptr) = owner_ptr {
        // SAFETY: the owner remains map-owned and read-only. Both halves are
        // checked so an inconsistent owner/commit pair cannot authorize one
        // direction of a marked context.
        let owner = unsafe { &*owner_ptr };
        if !marked_owner_wire_authorizes_uplink(owner, &far, dscp_wire)
            || !marked_owner_wire_authorizes_downlink(owner, local_teid, binding)
        {
            return Ok(TC_ACT_SHOT as i32);
        }
    }
    let source_port = u16::from_be_bytes([commit[64], commit[65]]);
    let encap = build_uplink_encap_with_dscp_and_source_port(&far, inner_len, dscp, source_port)
        .ok_or(())?;
    let mut encap = encap;
    if let Some(pmtu_ptr) = GTPU_PMTU_CFG.get_ptr(0) {
        // SAFETY: single-slot array value written by the loader before the
        // device is managed, and later by `set_uplink_mtu_policy` via one
        // atomic four-byte map write. A single four-byte load (read_unaligned
        // lowers to one aligned ldw on the BPF target) cannot observe a torn
        // policy word.
        let policy_bytes = unsafe { (pmtu_ptr as *const u32).read_unaligned() }.to_ne_bytes();
        match GtpuUplinkMtuPolicy::decode_map_value(&policy_bytes) {
            UplinkMtuMapState::Unset => {}
            UplinkMtuMapState::Corrupt => {
                // Corrupt adopted policy state must drop rather than emit an
                // unchecked encapsulation. This counter is a canary for
                // external writers and never moves in normal operation.
                count_pmtu_drop(COUNTER_UL_PMTU_CORRUPT);
                return Ok(TC_ACT_SHOT as i32);
            }
            UplinkMtuMapState::Configured(policy)
                if policy.fragmentation() == GtpuOuterFragmentPolicy::SignalPacketTooBig =>
            {
                if !apply_uplink_mtu_policy(&mut encap, policy) {
                    // Fail closed: the over-MTU inner packet is never emitted
                    // unencapsulated and the encapsulation never silently
                    // exceeds the effective link MTU.
                    count_pmtu_drop(COUNTER_UL_MTU_REJECT);
                    return Ok(TC_ACT_SHOT as i32);
                }
            }
            UplinkMtuMapState::Configured(_) => {
                // Canonical for a host fragmenter, but not executable by tc.
                // Treat an out-of-band writer like corrupt state and drop all
                // packets until userspace restores an executable policy.
                count_pmtu_drop(COUNTER_UL_PMTU_CORRUPT);
                return Ok(TC_ACT_SHOT as i32);
            }
        }
    }

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

// Keep checksum callback overhead bounded without turning a maximum-length
// UDP datagram into thousands of helper invocations.
const CHECKSUM_CHUNK_LEN: usize = 128;

#[derive(Clone, Copy)]
struct ChecksumRemainderPlan {
    chunk_64: bool,
    chunk_32: bool,
    chunk_16: bool,
    chunk_8: bool,
    chunk_4: bool,
    suffix_len: usize,
}

/// Decompose every sub-128-byte tail into complete helper reads plus at most
/// one zero-padded one-to-three-byte suffix.
///
/// Keeping this plan explicit prevents a larger residual tail from being
/// mistaken for a suffix after the fixed helper calls have advanced `cursor`.
#[inline(always)]
const fn checksum_remainder_plan(mut length: usize) -> Option<ChecksumRemainderPlan> {
    if length >= CHECKSUM_CHUNK_LEN {
        return None;
    }
    let chunk_64 = length >= 64;
    if chunk_64 {
        length -= 64;
    }
    let chunk_32 = length >= 32;
    if chunk_32 {
        length -= 32;
    }
    let chunk_16 = length >= 16;
    if chunk_16 {
        length -= 16;
    }
    let chunk_8 = length >= 8;
    if chunk_8 {
        length -= 8;
    }
    let chunk_4 = length >= 4;
    if chunk_4 {
        length -= 4;
    }
    if length > 3 {
        return None;
    }
    Some(ChecksumRemainderPlan {
        chunk_64,
        chunk_32,
        chunk_16,
        chunk_8,
        chunk_4,
        suffix_len: length,
    })
}

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
        // mode. The input length caps the loop at 511 fixed iterations.
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
    let plan = checksum_remainder_plan(length % CHECKSUM_CHUNK_LEN).ok_or(())?;

    if plan.chunk_64 {
        (cursor, seed) = checksum_packet_chunk::<64>(ctx, cursor, seed)?;
    }
    if plan.chunk_32 {
        (cursor, seed) = checksum_packet_chunk::<32>(ctx, cursor, seed)?;
    }
    if plan.chunk_16 {
        (cursor, seed) = checksum_packet_chunk::<16>(ctx, cursor, seed)?;
    }
    if plan.chunk_8 {
        (cursor, seed) = checksum_packet_chunk::<8>(ctx, cursor, seed)?;
    }
    if plan.chunk_4 {
        (cursor, seed) = checksum_packet_chunk::<4>(ctx, cursor, seed)?;
    }

    let remaining = plan.suffix_len;
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
#[inline(never)]
fn parse_downlink(ctx: &mut TcContext) -> u64 {
    let Ok(eth_proto) = ctx.load::<u16>(12) else {
        return u64::from(TC_ACT_OK as u32);
    };
    let eth_proto = u16::from_be(eth_proto);
    if eth_proto != ETH_P_IPV4 {
        return u64::from(TC_ACT_OK as u32);
    }
    let Ok(version_ihl) = ctx.load::<u8>(ETH_HDR_LEN) else {
        return u64::from(TC_ACT_OK as u32);
    };
    if version_ihl >> 4 != 4 {
        return u64::from(TC_ACT_OK as u32);
    }
    let Some(ip_header_len) = usize::from(version_ihl & 0x0F).checked_mul(4) else {
        return u64::from(TC_ACT_OK as u32);
    };
    if ip_header_len < 20 {
        return u64::from(TC_ACT_OK as u32);
    }
    let Ok(frag) = ctx.load::<u16>(ETH_HDR_LEN + 6) else {
        return u64::from(TC_ACT_OK as u32);
    };
    let frag = u16::from_be(frag);
    if frag & IPV4_FRAG_MASK != 0 {
        // Fragmented outer packets go to the stack for reassembly.
        return u64::from(TC_ACT_OK as u32);
    }
    let Ok(protocol) = ctx.load::<u8>(ETH_HDR_LEN + 9) else {
        return u64::from(TC_ACT_OK as u32);
    };
    if protocol != IPV4_PROTO_UDP {
        return u64::from(TC_ACT_OK as u32);
    }

    let Some(l4_offset) = ETH_HDR_LEN.checked_add(ip_header_len) else {
        return u64::from(TC_ACT_OK as u32);
    };
    let Some(dport_offset) = l4_offset.checked_add(2) else {
        return u64::from(TC_ACT_OK as u32);
    };
    let Ok(dport) = ctx.load::<u16>(dport_offset) else {
        return u64::from(TC_ACT_OK as u32);
    };
    let dport = u16::from_be(dport);
    if dport != GTPU_UDP_PORT {
        return u64::from(TC_ACT_OK as u32);
    }

    // From this point onward UDP/2152 identifies a GTP-U candidate. Every
    // malformed declaration or checksum fails closed before any PDR lookup.
    let Ok(total_length) = ctx.load::<u16>(ETH_HDR_LEN + 2) else {
        return u64::from(malformed_downlink() as u32);
    };
    let Ok(ipv4_bounds) =
        Ipv4EnvelopeBounds::parse(ctx.len() as usize, version_ihl, u16::from_be(total_length))
    else {
        return u64::from(malformed_downlink() as u32);
    };
    if ipv4_bounds.udp_offset() != l4_offset || !ipv4_header_checksum_is_valid(ctx, ipv4_bounds) {
        return u64::from(malformed_downlink() as u32);
    }
    let Ok(udp_length) = ctx.load::<u16>(l4_offset + 4) else {
        return u64::from(malformed_downlink() as u32);
    };
    let Ok(udp_bounds) = UdpEnvelopeBounds::parse(ipv4_bounds, u16::from_be(udp_length)) else {
        return u64::from(malformed_downlink() as u32);
    };
    if !udp_checksum_is_valid(ctx, udp_bounds) {
        return u64::from(malformed_downlink() as u32);
    }

    let gtp_offset = udp_bounds.gtp_offset();
    let Ok(gtp_header) = ctx.load::<[u8; GTPU_MANDATORY_HDR_LEN]>(gtp_offset) else {
        return u64::from(malformed_downlink() as u32);
    };
    let declared_gtp_length = u16::from_be_bytes([gtp_header[2], gtp_header[3]]);
    let Ok(gtp_bounds) = GtpuEnvelopeBounds::parse(udp_bounds, declared_gtp_length) else {
        return u64::from(malformed_downlink() as u32);
    };
    let (teid, gtp_length, has_opt, has_ext) = match classify_gtpu(&gtp_header) {
        GtpuClass::NotGtpV1 | GtpuClass::NotGpdu => return u64::from(TC_ACT_OK as u32),
        GtpuClass::Gpdu {
            teid,
            length,
            has_opt,
            has_ext,
        } => (teid, length, has_opt, has_ext),
    };

    if gtp_length != declared_gtp_length {
        return u64::from(malformed_downlink() as u32);
    }
    let gtp_end = gtp_bounds.gtp_end();

    let Some(mut payload_offset) = gtp_offset.checked_add(GTPU_MANDATORY_HDR_LEN) else {
        return u64::from(malformed_downlink() as u32);
    };
    if has_opt {
        let Some(optional_end) = payload_offset.checked_add(GTPU_OPT_LEN) else {
            return u64::from(malformed_downlink() as u32);
        };
        if optional_end > gtp_end {
            return u64::from(malformed_downlink() as u32);
        }
        let Ok(opt) = ctx.load::<[u8; GTPU_OPT_LEN]>(payload_offset) else {
            return u64::from(malformed_downlink() as u32);
        };
        payload_offset = optional_end;
        if has_ext {
            let mut next_ext = opt[3];
            let mut walked = 0;
            while next_ext != 0 {
                if walked == GTPU_MAX_EXT_HEADERS || payload_offset >= gtp_end {
                    return u64::from(malformed_downlink() as u32);
                }
                let Ok(ext_len_units) = ctx.load::<u8>(payload_offset) else {
                    return u64::from(malformed_downlink() as u32);
                };
                if ext_len_units == 0 {
                    return u64::from(malformed_downlink() as u32);
                }
                let Some(ext_len) = usize::from(ext_len_units).checked_mul(4) else {
                    return u64::from(malformed_downlink() as u32);
                };
                let Some(ext_end) = payload_offset.checked_add(ext_len) else {
                    return u64::from(malformed_downlink() as u32);
                };
                if ext_end > gtp_end {
                    return u64::from(malformed_downlink() as u32);
                }
                let Ok(next) = ctx.load::<u8>(ext_end - 1) else {
                    return u64::from(malformed_downlink() as u32);
                };
                payload_offset = ext_end;
                next_ext = next;
                walked += 1;
            }
        }
    }
    if payload_offset >= gtp_end {
        return u64::from(malformed_downlink() as u32);
    }
    let Some(inner_minimum_end) = payload_offset.checked_add(20) else {
        return u64::from(malformed_downlink() as u32);
    };
    if inner_minimum_end > gtp_end {
        return u64::from(malformed_downlink() as u32);
    }

    let Ok(payload_offset) = u16::try_from(payload_offset) else {
        return u64::from(malformed_downlink() as u32);
    };
    pack_downlink_parse_result(u16::from_be(total_length), payload_offset, teid)
}

/// Authorize the complete downlink forwarding identity and perform decap.
///
/// Keep this phase in a verifier-visible BPF subprogram. The envelope and
/// software-checksum phase uses a bounded `bpf_loop` callback stack;
/// separating the map-graph authorization phase ensures the callback and the
/// endpoint/owner checks do not share one oversized caller frame.
#[inline(never)]
fn authorize_and_decap_legacy_downlink(
    ctx: &mut TcContext,
    teid: [u8; 4],
    l4_offset: usize,
    payload_offset: usize,
) -> i32 {
    let legacy_pdr = GTPU_DOWNLINK_PDR.get_ptr(&teid);
    let marked_pdr = GTPU_DLM_PDR.get_ptr(&teid);
    let (pdr, output_mark, owner_selector) = match (legacy_pdr, marked_pdr) {
        (None, None) => {
            count(COUNTER_DL_UNKNOWN_TEID);
            return TC_ACT_SHOT as i32;
        }
        (Some(_), Some(_)) => {
            // A TEID must exist in exactly one schema. Treat externally
            // corrupted duplicate ownership as malformed rather than picking
            // a bearer nondeterministically.
            count(COUNTER_DL_MALFORMED);
            return TC_ACT_SHOT as i32;
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
                return TC_ACT_SHOT as i32;
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
        return TC_ACT_SHOT as i32;
    };
    // SAFETY: the hash value remains map-owned for this invocation and is
    // read only by the allocation-free wire validators below.
    let binding = unsafe { &*binding_ptr };
    let Ok(outer_peer) = ctx.load::<[u8; 4]>(ETH_HDR_LEN + 12) else {
        return binding_drop(DownlinkBindingMismatch::Invalid);
    };
    let Ok(outer_local) = ctx.load::<[u8; 4]>(ETH_HDR_LEN + 16) else {
        return binding_drop(DownlinkBindingMismatch::Invalid);
    };
    let Ok(source_port) = ctx.load::<u16>(l4_offset) else {
        return binding_drop(DownlinkBindingMismatch::Invalid);
    };
    if let Err(reason) = validate_ipv4_downlink_binding_wire(
        binding,
        outer_peer,
        outer_local,
        packet_ifindex(ctx),
        u16::from_be(source_port),
    ) {
        return binding_drop(reason);
    }
    if let Some(selector) = owner_selector {
        let Some(owner_ptr) = GTPU_M_OWNER.get_ptr(&selector) else {
            return binding_drop(DownlinkBindingMismatch::Invalid);
        };
        // SAFETY: both map values remain map-owned and read-only for this
        // exact comparison. Publishing Active last means an old owner cannot
        // authorize a newly replaced binding during peer relocation.
        if !marked_owner_wire_authorizes_downlink(unsafe { &*owner_ptr }, teid, binding) {
            return binding_drop(DownlinkBindingMismatch::Invalid);
        }
    }
    let commit_ptr = if let Some(selector) = owner_selector {
        GTPU_ULM_SPORT.get_ptr(&selector)
    } else {
        GTPU_UL_SPORT.get_ptr(&pdr.ue_ip)
    };
    let Some(commit_ptr) = commit_ptr else {
        return binding_drop(DownlinkBindingMismatch::Invalid);
    };
    let far_ptr = if let Some(selector) = owner_selector {
        GTPU_ULM_FAR.get_ptr(&selector)
    } else {
        GTPU_UPLINK_FAR.get_ptr(&pdr.ue_ip)
    };
    let Some(far_ptr) = far_ptr else {
        return binding_drop(DownlinkBindingMismatch::Invalid);
    };
    // SAFETY: the map value remains map-owned and read-only for this exact
    // complete-graph comparison.
    let far = UplinkFar::decode(unsafe { &*far_ptr });
    let dscp_ptr = if let Some(selector) = owner_selector {
        GTPU_ULM_DSCP.get_ptr(&selector)
    } else {
        GTPU_UPLINK_DSCP.get_ptr(&pdr.ue_ip)
    };
    let dscp_wire = if let Some(dscp_ptr) = dscp_ptr {
        // SAFETY: the map value remains map-owned and is read only.
        let value = unsafe { (*dscp_ptr)[0] };
        if value > 63 {
            return binding_drop(DownlinkBindingMismatch::Invalid);
        }
        value
    } else {
        0xff
    };
    // SAFETY: the map value remains map-owned and read-only. The one Active
    // commit record is the cross-direction publication point for this graph.
    let commit = unsafe { &*commit_ptr };
    if pdp_commit_wire_authorized_source_port(commit, &far, dscp_wire).is_none()
        || !pdp_commit_wire_authorizes_downlink(commit, teid, binding)
    {
        return binding_drop(DownlinkBindingMismatch::Invalid);
    }

    let Ok(inner_version_ihl) = ctx.load::<u8>(payload_offset) else {
        count(COUNTER_DL_MALFORMED);
        return TC_ACT_SHOT as i32;
    };
    if inner_version_ihl >> 4 != 4 {
        count(COUNTER_DL_MALFORMED);
        return TC_ACT_SHOT as i32;
    }
    let Ok(inner_dst) = ctx.load::<[u8; 4]>(payload_offset + 16) else {
        count(COUNTER_DL_MALFORMED);
        return TC_ACT_SHOT as i32;
    };
    if inner_dst != pdr.ue_ip {
        count(COUNTER_DL_DST_MISMATCH);
        return TC_ACT_SHOT as i32;
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
        return TC_ACT_SHOT as i32;
    }
    // This boundary owns the complete mark. Zero is the authoritative
    // default bearer; a nonzero value selects one exact dedicated Child SA.
    ctx.set_mark(output_mark);
    count(COUNTER_DL_DECAP);
    TC_ACT_OK as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grouped_fallback_requires_a_true_index_miss() {
        assert!(grouped_index_permits_v5_fallback(false));
        assert!(!grouped_index_permits_v5_fallback(true));

        // Once the selector is retained, every later authority/configuration
        // failure remains owned by the grouped schema and cannot re-enable
        // the frozen v5 path.
        let index_was_retained = true;
        let authority_decoded = false;
        assert!(!authority_decoded);
        assert!(!grouped_index_permits_v5_fallback(index_was_retained));
    }

    #[test]
    fn grouped_ipv4_inner_length_requires_the_exact_declared_packet() {
        assert!(ipv4_inner_length_is_exact(0x45, 20, 20));
        assert!(ipv4_inner_length_is_exact(0x46, 24, 24));
        assert!(!ipv4_inner_length_is_exact(0x65, 20, 20));
        assert!(!ipv4_inner_length_is_exact(0x44, 20, 20));
        assert!(!ipv4_inner_length_is_exact(0x46, 20, 20));
        assert!(!ipv4_inner_length_is_exact(0x45, 20, 21));
    }

    #[test]
    fn grouped_ipv6_inner_length_rejects_jumbograms_and_trailing_bytes() {
        assert!(ipv6_inner_length_is_exact(0x60, 8, IPV6_HDR_LEN + 8));
        assert!(!ipv6_inner_length_is_exact(0x40, 8, IPV6_HDR_LEN + 8));
        assert!(!ipv6_inner_length_is_exact(0x60, 0, IPV6_HDR_LEN));
        assert!(!ipv6_inner_length_is_exact(0x60, 8, IPV6_HDR_LEN + 9));
    }

    #[test]
    fn crossed_family_decap_selects_only_the_required_kernel_flag() {
        assert_eq!(
            grouped_decap_flags(GtpuSessionIpFamily::Ipv4, GtpuSessionIpFamily::Ipv4),
            0
        );
        assert_eq!(
            grouped_decap_flags(GtpuSessionIpFamily::Ipv6, GtpuSessionIpFamily::Ipv6),
            0
        );
        assert_eq!(
            grouped_decap_flags(GtpuSessionIpFamily::Ipv4, GtpuSessionIpFamily::Ipv6),
            u64::from(BPF_F_ADJ_ROOM_DECAP_L3_IPV6)
        );
        assert_eq!(
            grouped_decap_flags(GtpuSessionIpFamily::Ipv6, GtpuSessionIpFamily::Ipv4),
            u64::from(BPF_F_ADJ_ROOM_DECAP_L3_IPV4)
        );
    }

    #[test]
    fn internet_checksum_finalization_folds_carry_and_never_emits_zero() {
        assert_eq!(finalize_internet_checksum(0), u16::MAX);
        assert_eq!(finalize_internet_checksum(0xffff), u16::MAX);
        assert_eq!(finalize_internet_checksum(0x1234), 0xedcb);
        assert_eq!(finalize_internet_checksum(0x1ffff), 0xfffe);
    }

    #[cfg(target_endian = "little")]
    #[test]
    fn bpfel_checksum_finalization_preserves_network_wire_order() {
        // On bpfel/x86, bpf_csum_diff returns the native __wsum 0xac68
        // for the RFC words 0x1234 + 0x5678. The complemented checksum is
        // 0x9753 on the wire; __sum16 values are therefore stored natively,
        // without an additional big-endian conversion.
        let helper_sum = 0xac68;
        assert_eq!(finalized_internet_checksum_bytes(helper_sum), [0x97, 0x53]);
    }

    #[test]
    fn checksum_remainder_plan_covers_every_byte_exactly() {
        for length in 0..CHECKSUM_CHUNK_LEN {
            let plan = checksum_remainder_plan(length).expect("bounded checksum remainder");
            let covered = usize::from(plan.chunk_64) * 64
                + usize::from(plan.chunk_32) * 32
                + usize::from(plan.chunk_16) * 16
                + usize::from(plan.chunk_8) * 8
                + usize::from(plan.chunk_4) * 4
                + plan.suffix_len;
            assert_eq!(covered, length);
            assert!(plan.suffix_len <= 3);
        }
        assert!(checksum_remainder_plan(CHECKSUM_CHUNK_LEN).is_none());
    }

    #[test]
    fn live_ipv6_gtpu_checksum_vector_covers_the_complete_73_byte_inner_packet() {
        let source = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let destination = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x10,
        ];
        let udp = [
            0x08, 0x68, 0x08, 0x68, 0x00, 0x59, 0x00, 0x00, 0x30, 0xff, 0x00, 0x49, 0x62, 0x00,
            0x00, 0x02, 0x60, 0x00, 0x00, 0x00, 0x00, 0x21, 0x11, 0x3f, 0x20, 0x01, 0x0d, 0xb8,
            0x00, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x20, 0x01,
            0x0d, 0xb8, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
            0x15, 0xe1, 0x00, 0x35, 0x00, 0x21, 0xb1, 0x5b, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x65,
            0x64, 0x2d, 0x76, 0x36, 0x2d, 0x69, 0x6e, 0x6e, 0x65, 0x72, 0x2d, 0x76, 0x36, 0x2d,
            0x6f, 0x75, 0x74, 0x65, 0x72,
        ];

        assert_eq!(udp.len(), 16 + 73);
        assert_eq!(udp_ipv6_checksum(source, destination, &udp), Some(0x8e6c));

        let mut pseudo_header = [0_u8; 40];
        pseudo_header[..16].copy_from_slice(&source);
        pseudo_header[16..32].copy_from_slice(&destination);
        pseudo_header[32..36].copy_from_slice(&(udp.len() as u32).to_be_bytes());
        pseudo_header[39] = IPV6_NH_UDP;
        let mut prior_bug_input = pseudo_header.to_vec();
        prior_bug_input.extend_from_slice(&udp[..16]);
        prior_bug_input.extend_from_slice(&udp[16..16 + 63]);
        assert_eq!(
            internet_checksum(&prior_bug_input),
            0x485d,
            "the prior 32+16+8+4+3 plan omitted the final ten bytes"
        );

        let plan = checksum_remainder_plan(73).expect("73-byte live inner packet");
        assert!(plan.chunk_64);
        assert!(plan.chunk_8);
        assert_eq!(plan.suffix_len, 1);
    }

    #[test]
    fn ipv6_fragment_step_accepts_only_atomic_fragments() {
        assert_eq!(
            classify_ipv6_extension_step(IPV6_NH_FRAGMENT, [IPV6_NH_UDP, 0, 0, 0, 0, 0, 0, 0], 8),
            Ok(Ipv6ExtensionStep::Skip {
                next_header: IPV6_NH_UDP,
                header_len: 8,
                atomic_fragment: true,
            })
        );
        assert!(classify_ipv6_extension_step(
            IPV6_NH_FRAGMENT,
            [IPV6_NH_UDP, 0, 0, 1, 0, 0, 0, 0],
            8
        )
        .is_err());
        assert!(classify_ipv6_extension_step(
            IPV6_NH_FRAGMENT,
            [IPV6_NH_UDP, 0, 0, 8, 0, 0, 0, 0],
            8
        )
        .is_err());
    }

    #[test]
    fn ipv6_routing_validation_rejects_active_or_deprecated_routes() {
        assert!(!validate_ipv6_routing_skb(
            [IPV6_NH_UDP, 0, 0, 0, 0, 0, 0, 0],
            8
        ));
        assert!(!validate_ipv6_routing_skb(
            [IPV6_NH_UDP, 2, 2, 1, 0, 0, 0, 0],
            24
        ));
        assert!(validate_ipv6_routing_skb(
            [IPV6_NH_UDP, 2, 2, 0, 0, 0, 0, 0],
            24
        ));
        assert!(!validate_ipv6_routing_skb(
            [IPV6_NH_UDP, 2, 2, 0, 1, 0, 0, 0],
            24
        ));
        assert!(validate_ipv6_routing_skb(
            [IPV6_NH_UDP, 2, 4, 0, 0, 0, 0, 0],
            24
        ));
        assert!(!validate_ipv6_routing_skb(
            [IPV6_NH_UDP, 1, 4, 0, 0, 0, 0, 0],
            16
        ));
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
