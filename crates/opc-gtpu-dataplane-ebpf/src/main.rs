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
//!   traffic cannot leak without GTP-U encapsulation. A successful
//!   `bpf_redirect_neigh` re-enters this same hook, so the program recognizes
//!   its own re-emitted outer frame and counts the redirect outcome.
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
        __sk_buff, bpf_adj_room_mode::BPF_ADJ_ROOM_MAC, bpf_spin_lock as BpfSpinLock,
        BPF_CSUM_LEVEL_QUERY, BPF_F_ADJ_ROOM_DECAP_L3_IPV4, BPF_F_ADJ_ROOM_DECAP_L3_IPV6,
        BPF_F_ADJ_ROOM_ENCAP_L3_IPV4, BPF_F_ADJ_ROOM_ENCAP_L3_IPV6, BPF_F_ADJ_ROOM_ENCAP_L4_UDP,
        TC_ACT_OK, TC_ACT_REDIRECT, TC_ACT_SHOT,
    },
    btf_maps::Array as BtfArray,
    cty::c_void,
    helpers::{
        bpf_csum_diff, bpf_csum_level, bpf_ktime_get_boot_ns, bpf_loop, bpf_redirect_neigh,
        bpf_skb_change_tail, bpf_skb_load_bytes, bpf_spin_lock, bpf_spin_unlock,
    },
    macros::{btf_map, classifier, map},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::TcContext,
};
use opc_gtpu_ebpf_common::classify_ipv6_extension_step;
use opc_gtpu_ebpf_common::trusted_traffic_observation_abi::{
    GtpuTrafficObservationRegistration, GtpuTrafficObservationRegistrationWireView,
};
use opc_gtpu_ebpf_common::{
    apply_uplink_mtu_policy, build_uplink_encap_with_dscp_and_source_port, classify_gtpu,
    classify_udp_checksum, decide_uplink_pmtu, downlink_frame_end,
    downlink_parse_ipv4_total_length, downlink_parse_payload_offset, downlink_parse_teid,
    gtpu_session_config_wire_owns_local_ipv4, gtpu_session_config_wire_owns_local_ipv6,
    internet_checksum_sum_is_valid, marked_owner_wire_authorizes_downlink,
    marked_owner_wire_authorizes_uplink, pack_downlink_parse_result,
    pdp_commit_wire_authorized_source_port, pdp_commit_wire_authorizes_downlink,
    pdp_commit_wire_authorizes_graph, select_gtpu_session_entry_wire,
    tft_classifier_filter_matches, tft_classifier_schema_is_current,
    uplink_non_encapsulation_drops, validate_ipv4_downlink_binding_wire, DownlinkBindingMismatch,
    DownlinkPdr, GtpuClass, GtpuEnvelopeBounds, GtpuOuterFragmentPolicy, GtpuPmtuProtocol,
    GtpuSessionAuthorityWireView, GtpuSessionEntryWireView, GtpuSessionGroupPhase,
    GtpuSessionIpFamily, GtpuTrafficObservationDirection, GtpuUplinkMtuPolicy, Ipv4EnvelopeBounds,
    Ipv6ExtensionStep, MarkedDownlinkPdr, TftClassifierFilter, TftClassifierFilterKey,
    TftClassifierIpv4Packet, TftClassifierKey, TftClassifierMeta, UdpChecksumDisposition,
    UdpChecksumEvidence, UdpEnvelopeBounds, UplinkFar, UplinkFarKey, UplinkMtuMapState,
    UplinkPmtuDecision, COUNTER_DL_BINDING_FAMILY_MISMATCH, COUNTER_DL_BINDING_INGRESS_MISMATCH,
    COUNTER_DL_BINDING_INVALID, COUNTER_DL_BINDING_LOCAL_MISMATCH,
    COUNTER_DL_BINDING_PEER_MISMATCH, COUNTER_DL_BINDING_SOURCE_PORT_MISMATCH, COUNTER_DL_DECAP,
    COUNTER_DL_DST_MISMATCH, COUNTER_DL_MALFORMED, COUNTER_DL_UNKNOWN_TEID, COUNTER_SLOTS,
    COUNTER_TFT_CLASSIFIER_INVALID_STATE, COUNTER_TFT_CLASSIFIER_MALFORMED,
    COUNTER_TFT_CLASSIFIER_NO_MATCH, COUNTER_UL_ENCAP, COUNTER_UL_FAR_MISS, COUNTER_UL_MTU_REJECT,
    COUNTER_UL_PMTU_CORRUPT, COUNTER_UL_REDIRECT_RESOLVED, DOWNLINK_BINDING_COUNTER_SLOTS,
    DOWNLINK_ENDPOINT_BINDING_VALUE_LEN, DOWNLINK_PDR_VALUE_LEN, ETH_HDR_LEN, ETH_P_IPV4,
    ETH_P_IPV6, GTPU_ENCAP_LEN, GTPU_FLAGS_V1_GPDU, GTPU_IPV6_ENCAP_LEN, GTPU_MANDATORY_HDR_LEN,
    GTPU_MAX_EXT_HEADERS, GTPU_MSG_TYPE_GPDU, GTPU_OPT_LEN, GTPU_SESSION_CONFIG_KEY,
    GTPU_SESSION_CONFIG_VALUE_LEN, GTPU_SESSION_DOWNLINK_KEY_LEN, GTPU_SESSION_GROUP_ID_LEN,
    GTPU_SESSION_GROUP_REF_LEN, GTPU_SESSION_GROUP_VALUE_LEN, GTPU_SESSION_SCHEMA_MARKER_LEN,
    GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN, GTPU_SESSION_TRANSACTION_VALUE_LEN,
    GTPU_SESSION_UPLINK_KEY_LEN,
    GTPU_TRAFFIC_OBSERVATION_EVENT_LEN, GTPU_TRAFFIC_OBSERVATION_GATE_INDEX,
    GTPU_TRAFFIC_OBSERVATION_GATE_MAX_ENTRIES,
    GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN,
    GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PROFILE, GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_MAGIC,
    GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_VERSION, GTPU_TRAFFIC_OBSERVATION_REDIRECT_NONCE_LEN,
    GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN, GTPU_TRAFFIC_OBSERVATION_REGISTRATION_MAX_ENTRIES,
    GTPU_TRAFFIC_OBSERVATION_RING_BYTES, GTPU_UDP_PORT, IPV4_MIN_HDR_LEN, IPV6_HDR_LEN,
    IPV6_MAX_EXT_HEADERS, IPV6_MAX_OPTIONS_PER_HEADER, IPV6_NH_DESTINATION_OPTIONS,
    IPV6_NH_FRAGMENT, IPV6_NH_HOP_BY_HOP, IPV6_NH_NONE, IPV6_NH_ROUTING, IPV6_NH_UDP,
    MARKED_BEARER_OWNER_VALUE_LEN, MARKED_DOWNLINK_PDR_VALUE_LEN, TFT_CLASSIFIER_COUNTER_SLOTS,
    TFT_CLASSIFIER_FILTER_MAP_MAX_ENTRIES, TFT_CLASSIFIER_MAX_FILTERS,
    TFT_CLASSIFIER_META_MAP_MAX_ENTRIES, TFT_CLASSIFIER_SCHEMA_VALUE_LEN, UDP_HDR_LEN,
    UPLINK_DSCP_SCHEMA_MARKER_KEY, UPLINK_DSCP_VALUE_LEN, UPLINK_FAR_VALUE_LEN,
    UPLINK_MARK_KEY_LEN, UPLINK_PMTU_COUNTER_SLOTS, UPLINK_PMTU_VALUE_LEN,
    UPLINK_SOURCE_PORT_VALUE_LEN,
};
#[cfg(test)]
use opc_gtpu_ebpf_common::{internet_checksum, udp_ipv6_checksum};

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

/// Exact-current observation registrations. Startup clears this pinned map
/// before minting a new source incarnation and epoch.
#[map]
static GTPU_OBS_REG: HashMap<
    [u8; GTPU_SESSION_GROUP_ID_LEN],
    [u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN],
> = HashMap::pinned(GTPU_TRAFFIC_OBSERVATION_REGISTRATION_MAX_ENTRIES, 0);

/// Exact per-attempt redirect authority. A nonce resolves only to the group
/// that published it; re-entry still requires that group's active exact
/// registration to carry the same nonce, so this map alone can never emit.
#[map]
static GTPU_OBS_REDIR: HashMap<
    [u8; GTPU_TRAFFIC_OBSERVATION_REDIRECT_NONCE_LEN],
    [u8; GTPU_SESSION_GROUP_ID_LEN],
> = HashMap::pinned(GTPU_TRAFFIC_OBSERVATION_REGISTRATION_MAX_ENTRIES, 0);

/// Bounded local-forwarding observations. This pinned ring buffer is not a
/// peer-delivery channel; a host evaluator must compose both directions and
/// bracket drains with `GTPU_OBS_LOSS`.
#[map]
static GTPU_OBS_EVT: RingBuf = RingBuf::pinned(GTPU_TRAFFIC_OBSERVATION_RING_BYTES, 0);

/// Per-CPU, saturating evidence that a local observation could not enter the
/// bounded ring buffer. Startup clears it with the pinned source state.
#[map]
static GTPU_OBS_LOSS: PerCpuArray<u64> = PerCpuArray::pinned(1, 0);

/// Global, source-scoped producer sequence. Unlike boot time, this remains
/// unique when different CPUs observe packets in the same clock tick. Startup
/// resets it together with registrations, the ring, and loss evidence.
#[map]
static GTPU_OBS_SEQ: Array<u64> = Array::pinned(1, 0);

/// Loader-owned source-publication state. Slot zero is the reset/quiescence
/// gate; slot one is the durable publication-identity high-water mark. Odd gate
/// values authorize producers and even values fence them. The publication
/// high-water mark is never reset within a retained map graph, so delayed
/// packets cannot bind a later proof attempt through an identity ABA. The
/// separate full-width redirect nonce closes that ABA across graph recreation.
#[map]
static GTPU_OBS_GATE: Array<u64> = Array::pinned(GTPU_TRAFFIC_OBSERVATION_GATE_MAX_ENTRIES, 0);

/// BTF-visible synchronization primitive for `GTPU_OBS_SEQ`.
#[repr(C)]
#[derive(Clone, Copy)]
struct ObservationSequenceLock {
    lock: BpfSpinLock,
}

/// Separate lock-only map. Every required map lookup happens before the lock
/// is acquired, and userspace never mutates this special BTF value.
#[btf_map]
static GTPU_OBS_LCK: BtfArray<ObservationSequenceLock, 1> = BtfArray::new();

/// Per-CPU publication-occupancy scratch. The producer marks this fixed-size
/// value while it is inside the source gate and clears it on every return.
/// It never retains packet material or contributes to event correlation.
#[map]
static GTPU_OBS_FLOW: PerCpuArray<[u8; 40]> = PerCpuArray::pinned(1, 0);

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

/// Durable selector-authority operation stamps; tc never reads this map.
///
/// Kept separate from `GTPU_SESS_TXN` so the transaction journal ABI stays
/// stable while userspace verifies authority coordinates before any effect or
/// terminal readback.
#[map]
static GTPU_SEL_STAMP: HashMap<
    [u8; GTPU_SESSION_GROUP_ID_LEN],
    [u8; GTPU_SESSION_SELECTOR_STAMP_VALUE_LEN],
> = HashMap::pinned(1024, 0);

/// Stable grouped-session device identity and local endpoint set.
#[map]
static GTPU_CONFIG6: Array<[u8; GTPU_SESSION_CONFIG_VALUE_LEN]> = Array::pinned(1, 0);

/// Independent grouped-session schema marker; tc never reads this map.
#[map]
static GTPU_SCHEMA6: Array<[u8; GTPU_SESSION_SCHEMA_MARKER_LEN]> = Array::pinned(1, 0);

/// Independent v1 schema marker for shared-SA IPv4 TFT classification.
///
/// Userspace writes the exact marker only after it has verified the additive
/// map graph and attached this program generation. tc consults it only once a
/// metadata entry owns a PAA; an absent classifier therefore keeps the frozen
/// v5 path byte-for-byte unchanged.
#[map]
static GTPU_TFT_SCHEMA: Array<[u8; TFT_CLASSIFIER_SCHEMA_VALUE_LEN]> = Array::pinned(1, 0);

/// Atomically replaced active-bank selector for one `(attachment, IPv4 PAA)`.
#[map]
static GTPU_TFT_META: HashMap<TftClassifierKey, TftClassifierMeta> =
    HashMap::pinned(TFT_CLASSIFIER_META_MAP_MAX_ENTRIES, 0);

/// Both immutable filter banks, keyed by classifier, bank, and bounded index.
#[map]
static GTPU_TFT_FILT: HashMap<TftClassifierFilterKey, TftClassifierFilter> =
    HashMap::pinned(TFT_CLASSIFIER_FILTER_MAP_MAX_ENTRIES, 0);

/// Bounded fail-closed drop reasons for owned shared-SA classifier packets.
#[map]
static GTPU_TFT_DROP: PerCpuArray<u64> = PerCpuArray::pinned(TFT_CLASSIFIER_COUNTER_SLOTS, 0);

const IPV4_PROTO_UDP: u8 = 17;
const IPV4_FRAG_MASK: u16 = 0x3FFF; // MF bit + fragment offset

// The owned TFT parser must reject every prohibited IPv4 fragment/control
// flag: reserved, MF, and every nonzero offset. DF remains valid because it
// does not make the packet a fragment.
const IPV4_OWNED_TFT_FRAG_REJECT_MASK: u16 = 0xBFFF;
const IPV6_FIXED_AND_UDP_GTP_LEN: usize = IPV6_HDR_LEN + 8 + GTPU_MANDATORY_HDR_LEN;
const IPV6_PARSE_PASS: i32 = 0;
const IPV6_PARSE_ACCEPT: i32 = 1;
const IPV6_PARSE_DROP: i32 = -1;
const GROUPED_LOOKUP_MISS: u8 = 0;
const GROUPED_LOOKUP_ERROR: u8 = 1;
const GROUPED_LOOKUP_AUTHORIZED: u8 = 2;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

#[inline(always)]
const fn ipv4_owned_tft_fragment_is_unfragmented(fragment: u16) -> bool {
    fragment & IPV4_OWNED_TFT_FRAG_REJECT_MASK == 0
}

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
const fn ipv6_inner_total_length(
    version: u8,
    payload_len: u16,
    next_header: u8,
    available: usize,
) -> Option<usize> {
    if version >> 4 != 6 || (payload_len == 0 && next_header != IPV6_NH_NONE) {
        return None;
    }
    match IPV6_HDR_LEN.checked_add(payload_len as usize) {
        Some(total) if total == available => Some(total),
        Some(_) | None => None,
    }
}

#[inline(always)]
const fn ipv6_inner_length_is_exact(
    version: u8,
    payload_len: u16,
    next_header: u8,
    available: usize,
) -> bool {
    ipv6_inner_total_length(version, payload_len, next_header, available).is_some()
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
fn count_tft_classifier_drop(index: u32) {
    if let Some(counter) = GTPU_TFT_DROP.get_ptr_mut(index) {
        // SAFETY: per-CPU slot; no concurrent access on the same CPU.
        unsafe { *counter += 1 };
    }
}

#[inline(always)]
fn count_observation_loss() {
    if let Some(counter) = GTPU_OBS_LOSS.get_ptr_mut(0) {
        // SAFETY: per-CPU slot; no concurrent access on the same CPU.
        unsafe { *counter = (*counter).saturating_add(1) };
    }
}

#[inline(always)]
fn clear_observation_flow_scratch() {
    if let Some(flow) = GTPU_OBS_FLOW.get_ptr_mut(0) {
        // SAFETY: this is the current CPU's private fixed-size scratch slot.
        unsafe { (&mut *flow).fill(0) };
    }
}

/// Return whether this retained graph is allowed to affect a packet at all.
///
/// The loader holds this gate at a distinct even incarnation while a terminal
/// successor is being proven.  The tc links must already exist at that point:
/// their exact program identity is part of the broker-authenticated successor
/// receipt.  Passing an skb unchanged here therefore keeps those linked
/// programs traffic-inert until the exact durable admission activation write.
/// Missing, zero, and even values all fail open only in the narrow tc sense
/// (`TC_ACT_OK`): they never classify, drop, redirect, mutate, or publish.
#[inline(always)]
fn traffic_gate_allows_packet_effects() -> bool {
    let Some(gate_ptr) = GTPU_OBS_GATE.get_ptr(GTPU_TRAFFIC_OBSERVATION_GATE_INDEX) else {
        return false;
    };
    // SAFETY: the gate is a live array value written only by the loader. A
    // volatile load prevents compiler reuse across the classifier boundary.
    let gate = unsafe { core::ptr::read_volatile(gate_ptr) };
    gate != 0 && gate & 1 == 1
}

/// Enter the observation publication critical section for one exact loader
/// gate incarnation. The per-CPU scratch remains nonzero until after the ring
/// record is submitted, allowing userspace to prove every old producer has
/// quiesced before it resets retained source state.
#[inline(always)]
fn begin_observation_publication() -> bool {
    let Some(gate_ptr) = GTPU_OBS_GATE.get_ptr(GTPU_TRAFFIC_OBSERVATION_GATE_INDEX) else {
        return false;
    };
    // SAFETY: the gate is a live array value written only by the loader. A
    // volatile load prevents compiler reuse across the scratch publication.
    let gate = unsafe { core::ptr::read_volatile(gate_ptr) };
    if gate == 0 || gate & 1 == 0 {
        return false;
    }
    let Some(flow_ptr) = GTPU_OBS_FLOW.get_ptr_mut(0) else {
        return false;
    };
    // SAFETY: this is the current CPU's private fixed-size scratch slot.
    let flow = unsafe { &mut *flow_ptr };
    flow.fill(0);
    flow[0] = u8::MAX;
    let Some(confirm_ptr) = GTPU_OBS_GATE.get_ptr(GTPU_TRAFFIC_OBSERVATION_GATE_INDEX) else {
        flow.fill(0);
        return false;
    };
    // SAFETY: same live read-only map value as above. A changed value means
    // reset began between entry and publication of the active marker.
    let confirmed = unsafe { core::ptr::read_volatile(confirm_ptr) };
    if confirmed != gate {
        flow.fill(0);
        return false;
    }
    true
}

#[inline(always)]
fn next_observation_sequence() -> Option<u64> {
    let counter = GTPU_OBS_SEQ.get_ptr_mut(0)?;
    let sequence_lock = GTPU_OBS_LCK.get_ptr_mut(0)?;
    // SAFETY: both pointers are live array-map values for this invocation.
    // The BTF spin lock serializes this plain u64 update across CPUs, all map
    // lookups occurred before locking, and unlock is unconditional even when
    // the sequence is exhausted.
    unsafe {
        bpf_spin_lock(&mut (*sequence_lock).lock);
        let next = (*counter).checked_add(1);
        if let Some(next) = next {
            *counter = next;
        }
        bpf_spin_unlock(&mut (*sequence_lock).lock);
        next
    }
}

// `__sk_buff.cb` is five `u32` words in Aya's generated bindings, matching
// Linux's 20-byte tc scratch area. Word zero is an exact ownership marker; the
// remaining four native-endian words preserve every byte of the CSPRNG-filled
// per-attempt redirect nonce. The SDK owns this tc hook's scratch contract.
// A fresh pinned graph may restart finite publication IDs, but cannot recreate
// this nonce, closing delayed-skb ABA across graph recreation.
const GROUPED_UPLINK_OBSERVATION_CB_MARKER: u32 = 0xa000_0000;

#[inline(always)]
fn grouped_observation_marker(stamp: u32) -> bool {
    stamp == GROUPED_UPLINK_OBSERVATION_CB_MARKER
}

#[inline(always)]
fn grouped_observation_cb_stamp(
    nonce: [u8; GTPU_TRAFFIC_OBSERVATION_REDIRECT_NONCE_LEN],
) -> [u32; 5] {
    [
        GROUPED_UPLINK_OBSERVATION_CB_MARKER,
        u32::from_ne_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_ne_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_ne_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
        u32::from_ne_bytes([nonce[12], nonce[13], nonce[14], nonce[15]]),
    ]
}

#[inline(always)]
fn nonce_from_grouped_observation_cb_stamp(
    cb: &[u32; 5],
) -> Option<[u8; GTPU_TRAFFIC_OBSERVATION_REDIRECT_NONCE_LEN]> {
    if !grouped_observation_marker(cb[0]) {
        return None;
    }
    let first = cb[1].to_ne_bytes();
    let second = cb[2].to_ne_bytes();
    let third = cb[3].to_ne_bytes();
    let fourth = cb[4].to_ne_bytes();
    Some([
        first[0], first[1], first[2], first[3], second[0], second[1], second[2], second[3],
        third[0], third[1], third[2], third[3], fourth[0], fourth[1], fourth[2], fourth[3],
    ])
}

/// Store the owned tc control-buffer words using only direct, constant-offset
/// scalar accesses. In particular, do not assign or borrow the complete `cb`
/// array: LLVM may materialize that as a store through a modified context
/// pointer, which the tc verifier rejects.
#[inline(always)]
fn store_grouped_uplink_observation_cb_stamp(ctx: &TcContext, stamp: [u32; 5]) {
    // SAFETY: the tc verifier supplies a live, writable `__sk_buff` context.
    // Each explicit scalar access preserves the verifier-recognized context
    // base while covering the complete marker-plus-16-byte nonce stamp.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*ctx.skb.skb).cb[0]), stamp[0]);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*ctx.skb.skb).cb[1]), stamp[1]);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*ctx.skb.skb).cb[2]), stamp[2]);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*ctx.skb.skb).cb[3]), stamp[3]);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*ctx.skb.skb).cb[4]), stamp[4]);
    }
}

/// Clear every word owned by a proven grouped redirect stamp using direct,
/// constant-offset scalar stores.
#[inline(always)]
fn clear_grouped_uplink_observation_cb_stamp(ctx: &TcContext) {
    // SAFETY: the caller established exact ownership from word zero. Each
    // volatile scalar access prevents LLVM from replacing the stores with a
    // verifier-invalid `memset` through a derived context pointer.
    unsafe {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*ctx.skb.skb).cb[0]), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*ctx.skb.skb).cb[1]), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*ctx.skb.skb).cb[2]), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*ctx.skb.skb).cb[3]), 0);
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*ctx.skb.skb).cb[4]), 0);
    }
}

/// Capture the current immutable registration identity at a forwarding
/// boundary. A map replacement after this lookup leaves the borrowed old value
/// valid for this invocation, while later publication requires exact identity
/// equality with the live registration.
#[inline(always)]
fn current_observation_redirect_identity(
    authority: Option<&[u8; GTPU_SESSION_GROUP_VALUE_LEN]>,
) -> Option<([u8; GTPU_TRAFFIC_OBSERVATION_REDIRECT_NONCE_LEN], u32)> {
    let authority = authority?;
    let authority = GtpuSessionAuthorityWireView::decode(authority)?;
    let raw_registration = GTPU_OBS_REG.get_ptr(authority.group_key())?;
    // SAFETY: Aya returned a live read-only map-value pointer for this program
    // invocation. No reference or identifying bytes escape the kernel.
    let raw_registration = unsafe { &*raw_registration };
    GtpuTrafficObservationRegistration::encoded_redirect_identity_if_current_authority(
        raw_registration,
        authority,
    )
}

/// Store opaque grouped authority only across this program's pending neighbour
/// redirect. The tc scratch area is not packet data and cannot be populated by
/// an unprivileged packet sender.
#[inline(always)]
fn stamp_grouped_uplink_observation(
    ctx: &TcContext,
    authority: Option<&[u8; GTPU_SESSION_GROUP_VALUE_LEN]>,
) {
    let Some((nonce, _)) = current_observation_redirect_identity(authority) else {
        return;
    };
    store_grouped_uplink_observation_cb_stamp(ctx, grouped_observation_cb_stamp(nonce));
}

/// Take and clear the one-shot grouped redirect stamp. A nonmatching marker is
/// ignored so unrelated tc scratch users retain their state.
#[inline(always)]
fn take_grouped_uplink_observation_stamp(
    ctx: &TcContext,
) -> Option<[u8; GTPU_TRAFFIC_OBSERVATION_REDIRECT_NONCE_LEN]> {
    // SAFETY: the tc verifier supplies a live, writable `__sk_buff` context.
    // The marker check prevents this program from clearing scratch state it did
    // not write; a matching stamp is consumed before any map lookup or event.
    // These direct, constant-offset loads avoid a whole-array context borrow.
    let stamp = unsafe {
        [
            core::ptr::read_volatile(core::ptr::addr_of!((*ctx.skb.skb).cb[0])),
            core::ptr::read_volatile(core::ptr::addr_of!((*ctx.skb.skb).cb[1])),
            core::ptr::read_volatile(core::ptr::addr_of!((*ctx.skb.skb).cb[2])),
            core::ptr::read_volatile(core::ptr::addr_of!((*ctx.skb.skb).cb[3])),
            core::ptr::read_volatile(core::ptr::addr_of!((*ctx.skb.skb).cb[4])),
        ]
    };
    let nonce = nonce_from_grouped_observation_cb_stamp(&stamp)?;
    clear_grouped_uplink_observation_cb_stamp(ctx);
    Some(nonce)
}

/// Clear only a matching internal stamp when this frame is not a proven
/// redirect re-entry. This prevents stale scratch state from surviving into a
/// later classifier while preserving unrelated tc scratch users' state.
#[inline(always)]
fn clear_unmatched_grouped_uplink_observation_stamp(ctx: &TcContext) {
    // SAFETY: the tc verifier supplies a live, writable `__sk_buff` context.
    // A marker mismatch is left untouched because this program does not own it.
    let marker = unsafe { core::ptr::read_volatile(core::ptr::addr_of!((*ctx.skb.skb).cb[0])) };
    if grouped_observation_marker(marker) {
        clear_grouped_uplink_observation_cb_stamp(ctx);
    }
}

/// Return the authenticated sample carried by one exact inner ICMP Echo
/// exchange. This is deliberately a side path: all parse failures suppress
/// evidence only and leave forwarding unchanged. Core-to-access accepts only
/// a public Echo request, then replaces its payload with the private response
/// domain before XFRM can forward it. Access-to-core accepts only that private
/// payload on an Echo reply. The declared inner IP extent must be the whole
/// live skb payload, and the ICMP extent must be exactly its fixed header plus
/// challenge so packets with ambiguous trailers cannot mint proof events.
// Keep this scalar-only orchestrator in its caller's frame. Giving it a
// separate eight-byte result frame pushes the otherwise bounded downlink
// observation chain above the 512-byte combined-stack limit on Linux 5.14
// and 6.8. The parser, authenticator, and rewrite remain non-inlined sibling
// calls, so their packet and authority scratch is never live together.
#[inline(always)]
fn observation_challenge_sample<const CORE_TO_ACCESS: bool>(
    ctx: &TcContext,
    inner_offset: usize,
    registration: GtpuTrafficObservationRegistrationWireView<'_>,
) -> Option<u32> {
    let packet = validated_observation_icmp_echo::<CORE_TO_ACCESS>(ctx, inner_offset);
    if packet == 0 {
        return None;
    }
    let sample_id =
        authenticate_observation_icmp_echo::<CORE_TO_ACCESS>(ctx, registration, packet)?;
    if CORE_TO_ACCESS
        && !rewrite_authenticated_observation_icmp_echo_request(
            ctx,
            inner_offset,
            registration,
            packet,
            sample_id,
        )
    {
        return None;
    }
    Some(sample_id)
}

/// Parse and checksum one fixed observation packet without retaining any
/// authentication bytes in the checksum call chain. The packed return keeps
/// the orchestration frame scalar-only: the high byte is the IP version and
/// the low 56 bits are the exact ICMP offset. A zero value is invalid.
#[inline(never)]
fn validated_observation_icmp_echo<const CORE_TO_ACCESS: bool>(
    ctx: &TcContext,
    inner_offset: usize,
) -> u64 {
    let Some(packet) = try_validated_observation_icmp_echo::<CORE_TO_ACCESS>(ctx, inner_offset)
    else {
        return 0;
    };
    packet
}

#[inline(always)]
fn try_validated_observation_icmp_echo<const CORE_TO_ACCESS: bool>(
    ctx: &TcContext,
    inner_offset: usize,
) -> Option<u64> {
    let version = ctx.load::<u8>(inner_offset).ok()? >> 4;
    let (protocol, l4_offset, ip_end) = match version {
        4 => {
            let version_ihl = ctx.load::<u8>(inner_offset).ok()?;
            let header_len = usize::from(version_ihl & 0x0f).checked_mul(4)?;
            let total_len = usize::from(u16::from_be(ctx.load::<u16>(inner_offset + 2).ok()?));
            let fragment = u16::from_be(ctx.load::<u16>(inner_offset + 6).ok()?);
            if version_ihl >> 4 != 4
                || header_len < IPV4_MIN_HDR_LEN
                || total_len < header_len
                || fragment & 0x3fff != 0
            {
                return None;
            }
            let ip_end = inner_offset.checked_add(total_len)?;
            if ip_end > ctx.len() as usize
                || !ipv4_header_checksum_is_valid_at(ctx, inner_offset, header_len)
            {
                return None;
            }
            let protocol = ctx.load::<u8>(inner_offset + 9).ok()?;
            (protocol, inner_offset.checked_add(header_len)?, ip_end)
        }
        6 => {
            let payload_len = usize::from(u16::from_be(ctx.load::<u16>(inner_offset + 4).ok()?));
            let base_end = inner_offset.checked_add(IPV6_HDR_LEN)?;
            let ip_end = base_end.checked_add(payload_len)?;
            // Observation is a non-forwarding side path, but it must still
            // prove both the declared IPv6 payload boundary and the live skb
            // boundary before reading its terminal eight-byte L4 selector.
            if payload_len < 8 || ip_end > ctx.len() as usize {
                return None;
            }
            let (protocol, l4_offset) = ipv6_l4_offset(
                ctx,
                ip_end,
                ipv6_l4_parse_config(inner_offset, IPV6_TERMINAL_OBSERVATION, true),
            )?;
            if l4_offset.checked_add(8)? > ip_end {
                return None;
            }
            (protocol, l4_offset, ip_end)
        }
        _ => return None,
    };
    if ip_end != ctx.len() as usize {
        return None;
    }
    let transport_len = ip_end.checked_sub(l4_offset)?;
    if transport_len != 8 + GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN {
        return None;
    }
    let icmp = ctx.load::<[u8; 2]>(l4_offset).ok()?;
    let expected_type = match (CORE_TO_ACCESS, version, protocol) {
        (true, 4, IPPROTO_ICMP) => 8,
        (true, 6, IPPROTO_ICMPV6) => 128,
        (false, 4, IPPROTO_ICMP) => 0,
        (false, 6, IPPROTO_ICMPV6) => 129,
        _ => return None,
    };
    if icmp != [expected_type, 0] {
        return None;
    }
    let checksum_is_valid = match version {
        4 => observation_icmp_checksum_40_is_valid(ctx, l4_offset, 0),
        6 => observation_icmpv6_checksum_is_valid(ctx, inner_offset, l4_offset),
        _ => false,
    };
    if !checksum_is_valid {
        return None;
    }
    const OBSERVATION_ICMP_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_ffff;
    let l4_offset = l4_offset as u64;
    if l4_offset == 0 || l4_offset > OBSERVATION_ICMP_OFFSET_MASK {
        return None;
    }
    Some((u64::from(version) << 56) | l4_offset)
}

/// Authenticate a packet only after the sibling parser has proved its exact
/// IP/ICMP extent, direction-specific type, and checksum. No packet mutation
/// can occur between these BPF-to-BPF calls, and every byte used for authority
/// is reloaded from the same skb before an event or response rewrite.
#[inline(never)]
fn authenticate_observation_icmp_echo<const CORE_TO_ACCESS: bool>(
    ctx: &TcContext,
    registration: GtpuTrafficObservationRegistrationWireView<'_>,
    packet: u64,
) -> Option<u32> {
    const OBSERVATION_ICMP_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_ffff;
    let version = (packet >> 56) as u8;
    let l4_offset = (packet & OBSERVATION_ICMP_OFFSET_MASK) as usize;
    let icmp = ctx.load::<[u8; 8]>(l4_offset).ok()?;
    let payload_offset = l4_offset.checked_add(8)?;
    let magic = u32::from_be(ctx.load::<u32>(payload_offset).ok()?);
    let profile = u32::from_be(ctx.load::<u32>(payload_offset.checked_add(4)?).ok()?);
    let packet_publication_id = u32::from_be(ctx.load::<u32>(payload_offset.checked_add(8)?).ok()?);
    let sample_id = u32::from_be(ctx.load::<u32>(payload_offset.checked_add(12)?).ok()?);
    if magic != u32::from_be_bytes(GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_MAGIC)
        || profile
            != u32::from_be_bytes([
                GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_VERSION,
                GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PROFILE,
                0,
                0,
            ])
        || packet_publication_id != registration.publication_id()
        || sample_id == 0
    {
        return None;
    }
    let tag_offset = payload_offset.checked_add(16)?;
    let tag = ctx.load::<[u8; 16]>(tag_offset).ok()?;
    let identifier = u16::from_be_bytes([icmp[4], icmp[5]]);
    let sequence = u16::from_be_bytes([icmp[6], icmp[7]]);
    if CORE_TO_ACCESS {
        match (version, icmp[0], icmp[1]) {
            (4, 8, 0) | (6, 128, 0) => registration
                .icmp_echo_request_tag_is_valid(identifier, sequence, sample_id, &tag)
                .then_some(sample_id),
            _ => None,
        }
    } else {
        match (version, icmp[0], icmp[1]) {
            (4, 0, 0) | (6, 129, 0) => registration
                .icmp_echo_reply_tag_is_valid(identifier, sequence, sample_id, &tag)
                .then_some(sample_id),
            _ => None,
        }
    }
}

/// Revalidate and replace one authenticated public request tag with its
/// private response tag, recomputing the fixed ICMP checksum before mutation.
/// Authentication and rewrite are sibling calls from the observation
/// orchestrator, so neither one's packet scratch remains live in the other's
/// verifier call chain. A failed mutation restores the exact request bytes and
/// suppresses evidence; it never widens forwarding acceptance.
#[inline(never)]
fn rewrite_authenticated_observation_icmp_echo_request(
    ctx: &TcContext,
    ip_offset: usize,
    registration: GtpuTrafficObservationRegistrationWireView<'_>,
    packet: u64,
    sample_id: u32,
) -> bool {
    const OBSERVATION_ICMP_OFFSET_MASK: u64 = 0x00ff_ffff_ffff_ffff;
    let version = (packet >> 56) as u8;
    let icmp_offset = (packet & OBSERVATION_ICMP_OFFSET_MASK) as usize;
    let Ok(icmp) = ctx.load::<[u8; 8]>(icmp_offset) else {
        return false;
    };
    if !matches!((version, icmp[0], icmp[1]), (4, 8, 0) | (6, 128, 0)) {
        return false;
    }
    let identifier = u16::from_be_bytes([icmp[4], icmp[5]]);
    let sequence = u16::from_be_bytes([icmp[6], icmp[7]]);
    let Some(tag_offset) = icmp_offset.checked_add(8 + 16) else {
        return false;
    };
    let Ok(request_tag) = ctx.load::<[u8; 16]>(tag_offset) else {
        return false;
    };
    if !registration.icmp_echo_request_tag_is_valid(identifier, sequence, sample_id, &request_tag) {
        return false;
    }
    let Some(response_tag) = registration.icmp_echo_response_tag(sample_id) else {
        return false;
    };
    let Some(checksum_offset) = icmp_offset.checked_add(2) else {
        return false;
    };
    let Ok(original_checksum) = ctx.load::<u16>(checksum_offset) else {
        return false;
    };
    let Ok(mut message) = ctx.load::<[u8; 40]>(icmp_offset) else {
        return false;
    };
    message[2] = 0;
    message[3] = 0;
    message[24..].copy_from_slice(&response_tag);
    let seed = match version {
        4 => 0,
        6 => match observation_icmpv6_pseudo_sum(ctx, ip_offset, 40) {
            Some(seed) => seed,
            None => return false,
        },
        _ => return false,
    };
    // SAFETY: the fully initialized fixed-size message is a nonzero multiple
    // of four, as required by `bpf_csum_diff`.
    let sum = unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            message.as_mut_ptr().cast::<u32>(),
            message.len() as u32,
            seed,
        )
    };
    if sum < 0 {
        return false;
    }
    let checksum_bytes = observation_icmp_checksum_bytes_from_helper_sum(sum as u32, version);
    if ctx.store(tag_offset, &response_tag, 0).is_err()
        || ctx.store(checksum_offset, &checksum_bytes, 0).is_err()
    {
        let _ = ctx.store(tag_offset, &request_tag, 0);
        let _ = ctx.store(checksum_offset, &original_checksum, 0);
        return false;
    }
    let checksum_is_valid = match version {
        4 => observation_icmp_checksum_40_is_valid(ctx, icmp_offset, 0),
        6 => observation_icmpv6_checksum_is_valid(ctx, ip_offset, icmp_offset),
        _ => false,
    };
    let response_was_stored = ctx
        .load::<[u8; 16]>(tag_offset)
        .is_ok_and(|stored| stored == response_tag);
    if checksum_is_valid && response_was_stored {
        return true;
    }
    let _ = ctx.store(tag_offset, &request_tag, 0);
    let _ = ctx.store(checksum_offset, &original_checksum, 0);
    false
}

/// Fold a native `__wsum` returned by `bpf_csum_diff` into wire bytes.
///
/// Kernel checksum helpers return native checksum scalars. `__sum16` must
/// therefore be stored in native byte order: on bpfel, an additional
/// big-endian conversion reverses the two bytes on the packet wire.
#[inline(always)]
fn observation_icmp_checksum_bytes_from_helper_sum(sum: u32, version: u8) -> [u8; 2] {
    let first = (sum & 0xffff).wrapping_add(sum >> 16);
    let second = (first & 0xffff).wrapping_add(first >> 16);
    let checksum = !(second as u16);
    // ICMPv6 has no checksum-omission representation.
    let checksum = if version == 6 && checksum == 0 {
        u16::MAX
    } else {
        checksum
    };
    checksum.to_ne_bytes()
}

/// Emit only an exact-current local forwarding-boundary observation. Every
/// observation failure is deliberately ignored by the forwarding path.
#[inline(never)]
fn emit_grouped_observation(
    ctx: &TcContext,
    authority: Option<&[u8; GTPU_SESSION_GROUP_VALUE_LEN]>,
    publication_id: u32,
    inner_offset: usize,
    direction: GtpuTrafficObservationDirection,
) {
    if !begin_observation_publication() {
        return;
    }
    try_emit_grouped_observation(ctx, authority, publication_id, inner_offset, direction);
    clear_observation_flow_scratch();
}

#[inline(always)]
fn try_emit_grouped_observation(
    ctx: &TcContext,
    authority: Option<&[u8; GTPU_SESSION_GROUP_VALUE_LEN]>,
    publication_id: u32,
    inner_offset: usize,
    direction: GtpuTrafficObservationDirection,
) {
    let Some(authority) = authority else {
        return;
    };
    let Some(authority_view) = GtpuSessionAuthorityWireView::decode(authority) else {
        return;
    };
    let group_key = authority_view.group_key();
    let Some(raw_registration) = GTPU_OBS_REG.get_ptr(group_key) else {
        return;
    };
    // SAFETY: Aya returned this pointer from the retained registration map;
    // this function only reads its fixed map-value extent before returning.
    let raw_registration = unsafe { &*raw_registration };
    let Some(registration) =
        GtpuTrafficObservationRegistrationWireView::decode_if_current_authority(
            raw_registration,
            authority_view,
            publication_id,
        )
    else {
        return;
    };
    let sample_id = match direction {
        GtpuTrafficObservationDirection::CoreToAccess => {
            observation_challenge_sample::<true>(ctx, inner_offset, registration)
        }
        GtpuTrafficObservationDirection::AccessToCore => {
            observation_challenge_sample::<false>(ctx, inner_offset, registration)
        }
    };
    let Some(sample_id) = sample_id else {
        return;
    };
    publish_grouped_observation_event(
        authority,
        raw_registration,
        publication_id,
        sample_id,
        direction,
    );
}

/// Publish one already authenticated sample. Keeping ring-record construction
/// out of the packet parser prevents its event frame from being live while the
/// verifier evaluates the bounded ICMP challenge and rewrite call chain.
#[inline(never)]
fn publish_grouped_observation_event(
    authority: &[u8; GTPU_SESSION_GROUP_VALUE_LEN],
    raw_registration: &[u8; GTPU_TRAFFIC_OBSERVATION_REGISTRATION_LEN],
    publication_id: u32,
    sample_id: u32,
    direction: GtpuTrafficObservationDirection,
) {
    // SAFETY: this helper returns the kernel's monotonic boot-time clock.
    let boot_time_ns = unsafe { bpf_ktime_get_boot_ns() };
    let Some(producer_sequence) = next_observation_sequence() else {
        count_observation_loss();
        return;
    };
    let Some(mut event) = GTPU_OBS_EVT.reserve_bytes(GTPU_TRAFFIC_OBSERVATION_EVENT_LEN, 0) else {
        count_observation_loss();
        return;
    };
    let Ok(event_bytes) = <&mut [u8; GTPU_TRAFFIC_OBSERVATION_EVENT_LEN]>::try_from(&mut event[..])
    else {
        event.discard(0);
        count_observation_loss();
        return;
    };
    event_bytes[72..80].copy_from_slice(&boot_time_ns.to_be_bytes());
    event_bytes[80..88].copy_from_slice(&producer_sequence.to_be_bytes());
    event_bytes[88] = direction as u8;
    if !GtpuTrafficObservationRegistration::write_current_event(
        raw_registration,
        authority,
        publication_id,
        sample_id,
        event_bytes,
    ) {
        event.discard(0);
        count_observation_loss();
        return;
    }
    event.submit(0);
}

/// Emit an uplink observation only after the strict redirect re-entry envelope
/// proof has succeeded. This re-fetches authority by the opaque group key so a
/// changed group generation or registration suppresses stale observations.
#[inline(never)]
fn emit_grouped_uplink_observation_on_reentry(ctx: &TcContext, eth_proto: u16) {
    let Some(nonce) = take_grouped_uplink_observation_stamp(ctx) else {
        return;
    };
    let Some(group_key_ptr) = GTPU_OBS_REDIR.get_ptr(nonce) else {
        return;
    };
    // SAFETY: this retained map value is read only for this classifier invocation.
    let group_key = unsafe { *group_key_ptr };
    let Some(authority_ptr) = GTPU_SESSIONS.get_ptr(group_key) else {
        return;
    };
    // SAFETY: this is one retained normal hash-map value borrowed for this tc
    // invocation only; no view escapes this function.
    let authority = unsafe { &*authority_ptr };
    let Some(authority_view) = GtpuSessionAuthorityWireView::decode(authority) else {
        return;
    };
    if !authority_view.matches_group_key(&group_key)
        || authority_view.phase() != Some(GtpuSessionGroupPhase::Active)
    {
        return;
    }
    let Some(raw_registration) = GTPU_OBS_REG.get_ptr(group_key) else {
        return;
    };
    // SAFETY: this retained fixed-size registration is borrowed for this invocation.
    let raw_registration = unsafe { &*raw_registration };
    let Some((registration_nonce, publication_id)) =
        GtpuTrafficObservationRegistration::encoded_redirect_identity_if_current_authority(
            raw_registration,
            authority_view,
        )
    else {
        return;
    };
    if registration_nonce != nonce {
        return;
    }
    let inner_offset = match eth_proto {
        ETH_P_IPV4 => ETH_HDR_LEN + GTPU_ENCAP_LEN,
        ETH_P_IPV6 => ETH_HDR_LEN + GTPU_IPV6_ENCAP_LEN,
        _ => return,
    };
    emit_grouped_observation(
        ctx,
        Some(authority),
        publication_id,
        inner_offset,
        GtpuTrafficObservationDirection::AccessToCore,
    );
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum TftClassifierUplinkResult {
    Absent,
    Selected(u32),
    Drop,
}

/// Strictly parse the inner IPv4 fields needed by the v1 TFT classifier.
///
/// This runs only after a metadata record owns the exact source PAA. It
/// rejects every fragment and malformed TCP, UDP, or ESP packet before a
/// default-bearer decision is possible. Packets for an unowned PAA never take
/// this parser, retaining the frozen v5 behavior exactly.
#[inline(never)]
fn parse_owned_tft_ipv4(
    ctx: &TcContext,
    local_address: [u8; 4],
) -> Option<TftClassifierIpv4Packet> {
    let available = (ctx.len() as usize).checked_sub(ETH_HDR_LEN)?;
    let version_ihl = ctx.load::<u8>(ETH_HDR_LEN).ok()?;
    let header_len = usize::from(version_ihl & 0x0f).checked_mul(4)?;
    let total_len = usize::from(u16::from_be(ctx.load::<u16>(ETH_HDR_LEN + 2).ok()?));
    let fragment = u16::from_be(ctx.load::<u16>(ETH_HDR_LEN + 6).ok()?);
    if version_ihl >> 4 != 4
        || header_len < IPV4_MIN_HDR_LEN
        || total_len < header_len
        || total_len != available
        || !ipv4_owned_tft_fragment_is_unfragmented(fragment)
    {
        return None;
    }
    let protocol = ctx.load::<u8>(ETH_HDR_LEN + 9).ok()?;
    let tos = ctx.load::<u8>(ETH_HDR_LEN + 1).ok()?;
    let remote_address = ctx.load::<[u8; 4]>(ETH_HDR_LEN + 16).ok()?;
    let transport_offset = ETH_HDR_LEN.checked_add(header_len)?;
    let payload_len = total_len.checked_sub(header_len)?;
    let (local_port, remote_port) = match protocol {
        6 => {
            if payload_len < 20 {
                return None;
            }
            let tcp_data_offset =
                usize::from(ctx.load::<u8>(transport_offset + 12).ok()? >> 4).checked_mul(4)?;
            if tcp_data_offset < 20 || tcp_data_offset > payload_len {
                return None;
            }
            let local_port = u16::from_be(ctx.load::<u16>(transport_offset).ok()?);
            let remote_port = u16::from_be(ctx.load::<u16>(transport_offset + 2).ok()?);
            (Some(local_port), Some(remote_port))
        }
        17 => {
            if payload_len < UDP_HDR_LEN
                || usize::from(u16::from_be(ctx.load::<u16>(transport_offset + 4).ok()?))
                    != payload_len
            {
                return None;
            }
            let local_port = u16::from_be(ctx.load::<u16>(transport_offset).ok()?);
            let remote_port = u16::from_be(ctx.load::<u16>(transport_offset + 2).ok()?);
            (Some(local_port), Some(remote_port))
        }
        _ => (None, None),
    };
    let esp_spi = if protocol == 50 {
        if payload_len < 8 {
            return None;
        }
        Some(u32::from_be(ctx.load::<u32>(transport_offset).ok()?))
    } else {
        None
    };
    Some(TftClassifierIpv4Packet::new(
        local_address,
        remote_address,
        protocol,
        tos,
        local_port,
        remote_port,
        esp_spi,
    ))
}

#[repr(C)]
struct TftClassifierLoopContext {
    key: TftClassifierKey,
    meta: TftClassifierMeta,
    packet: TftClassifierIpv4Packet,
    matched: u8,
    invalid: u8,
    selected_rank: u16,
    candidate_rank: u16,
}

/// Persist the current callback rank only after that filter matched.
///
/// `bpf_loop` callbacks on older enterprise kernels must not carry a selected
/// bearer mark across nested BPF-to-BPF calls. The callback records the dense
/// execution rank in its caller-owned context instead; the caller re-reads the
/// metadata-bound row after the loop and obtains its mark there.
#[inline(never)]
fn remember_tft_classifier_match(context: &mut TftClassifierLoopContext) {
    if context.matched == 0 {
        context.selected_rank = context.candidate_rank;
        context.matched = 1;
    }
}

/// Re-read the metadata-bound winning row after the bounded callback loop.
///
/// The callback has already established that this dense rank matched. Looking
/// the record up again makes the selected mark a post-loop value, so it never
/// crosses the callback's validation and match subprogram calls.
#[inline(never)]
fn selected_tft_classifier_mark(
    key: TftClassifierKey,
    meta: &TftClassifierMeta,
    dense_rank: u16,
) -> Option<u32> {
    let filter_key = TftClassifierFilterKey::from_validated_meta(key, meta, dense_rank)?;
    let filter_ptr = GTPU_TFT_FILT.get_ptr(filter_key)?;
    // SAFETY: the active metadata and metadata-bound key retain this map value
    // for the current invocation. This revalidates the executable row before
    // exposing its mark to the caller.
    let filter = unsafe { &*filter_ptr };
    filter
        .is_runtime_valid_at(dense_rank as u8)
        .then(|| filter.bearer_mark())
}

/// Match exactly one active-bank filter in a bounded `bpf_loop` callback.
///
/// Keeping the 72-byte filter record in this separate verifier frame avoids
/// unrolling the bounded classifier snapshot into the tc entry stack. The
/// callback repeats the index bound before constructing a key, so no hostile
/// metadata byte can drive an unbounded lookup sequence.
#[inline(never)]
unsafe extern "C" fn classify_tft_filter_step(index: u64, context: *mut c_void) -> i64 {
    // SAFETY: `classify_owned_tft_uplink` gives `bpf_loop` one live, uniquely
    // borrowed stack context for its synchronous invocation.
    let context = unsafe { &mut *context.cast::<TftClassifierLoopContext>() };
    if context.invalid != 0 {
        return 1;
    }
    if index >= TFT_CLASSIFIER_MAX_FILTERS as u64 {
        context.invalid = 1;
        return 1;
    }
    // Store the scalar before any nested BPF-to-BPF call. The selection helper
    // below reloads this context field after matching rather than preserving
    // `index` or a bearer mark through those calls.
    context.candidate_rank = index as u16;
    let Some(filter_key) =
        TftClassifierFilterKey::from_validated_meta(context.key, &context.meta, index as u16)
    else {
        context.invalid = 1;
        return 1;
    };
    let Some(filter_ptr) = GTPU_TFT_FILT.get_ptr(&filter_key) else {
        context.invalid = 1;
        return 1;
    };
    // SAFETY: the map value remains valid for the callback invocation. The
    // lookup key binds the executable row to metadata's owner, generations,
    // bank, and index. Userspace derives that dense index from strict TFT
    // precedence before publication and exactly verifies the redundant value
    // identity and original precedence during readback.
    let filter = unsafe { &*filter_ptr };
    if !filter.is_runtime_valid_at(index as u8) {
        context.invalid = 1;
        return 1;
    }
    if !tft_classifier_filter_matches(filter, &context.packet) {
        return 0;
    }
    remember_tft_classifier_match(context);
    0
}

/// Classify one previously unmarked IPv4 packet when a complete shared-SA
/// classifier owns its `(ifindex, PAA)` key.
///
/// Metadata is the only publication point. The publisher fills and reads back
/// the inactive bank first, then atomically replaces this hash-map value. A
/// reader observes either bank and constructs every lookup key from that
/// metadata's owner, generations, bank, and dense precedence rank. The old
/// bank remains intact until a later pre-publication staging pass, so readers
/// never race post-publication record cleanup.
#[inline(never)]
fn classify_owned_tft_uplink(ctx: &TcContext) -> TftClassifierUplinkResult {
    let Ok(local_address) = ctx.load::<[u8; 4]>(ETH_HDR_LEN + 12) else {
        return TftClassifierUplinkResult::Absent;
    };
    let Some(key) = TftClassifierKey::new(packet_ifindex(ctx), local_address) else {
        return TftClassifierUplinkResult::Absent;
    };
    let Some(meta_ptr) = GTPU_TFT_META.get_ptr(&key) else {
        return TftClassifierUplinkResult::Absent;
    };
    let Some(schema_ptr) = GTPU_TFT_SCHEMA.get_ptr(0) else {
        count_tft_classifier_drop(COUNTER_TFT_CLASSIFIER_INVALID_STATE);
        return TftClassifierUplinkResult::Drop;
    };
    // SAFETY: hash-map values are retained by the kernel for this invocation;
    // the all-byte ABI has alignment one and userspace publishes whole values.
    let meta = unsafe { *meta_ptr };
    // SAFETY: the single-slot marker is read-only for this invocation.
    if !tft_classifier_schema_is_current(unsafe { &*schema_ptr }) || !meta.is_valid() {
        count_tft_classifier_drop(COUNTER_TFT_CLASSIFIER_INVALID_STATE);
        return TftClassifierUplinkResult::Drop;
    }
    let Some(packet) = parse_owned_tft_ipv4(ctx, local_address) else {
        count_tft_classifier_drop(COUNTER_TFT_CLASSIFIER_MALFORMED);
        return TftClassifierUplinkResult::Drop;
    };
    let mut loop_context = TftClassifierLoopContext {
        key,
        meta,
        packet,
        matched: 0,
        invalid: 0,
        selected_rank: 0,
        candidate_rank: 0,
    };
    // SAFETY: the callback is a static BPF subprogram with the helper's exact
    // ABI. The context remains live and uniquely borrowed for this synchronous
    // call. Its fixed whole-classifier iteration bound matches the map ABI.
    let performed = unsafe {
        bpf_loop(
            u32::from(meta.filter_count()),
            classify_tft_filter_step as *mut c_void,
            (&mut loop_context as *mut TftClassifierLoopContext).cast(),
            0,
        )
    };
    if performed < 0 || loop_context.invalid != 0 {
        count_tft_classifier_drop(COUNTER_TFT_CLASSIFIER_INVALID_STATE);
        return TftClassifierUplinkResult::Drop;
    }
    match loop_context.matched {
        1 => match selected_tft_classifier_mark(key, &meta, loop_context.selected_rank) {
            Some(mark) => TftClassifierUplinkResult::Selected(mark),
            None => {
                count_tft_classifier_drop(COUNTER_TFT_CLASSIFIER_INVALID_STATE);
                TftClassifierUplinkResult::Drop
            }
        },
        0 if meta.has_default() => TftClassifierUplinkResult::Selected(0),
        0 => {
            count_tft_classifier_drop(COUNTER_TFT_CLASSIFIER_NO_MATCH);
            TftClassifierUplinkResult::Drop
        }
        _ => {
            count_tft_classifier_drop(COUNTER_TFT_CLASSIFIER_INVALID_STATE);
            TftClassifierUplinkResult::Drop
        }
    }
}

/// Return whether an outer UDP header at `l4_offset` addresses GTP-U and
/// carries a GTPv1 G-PDU, the exact envelope both uplink completion sites
/// stamp.
///
/// The message-type check is what keeps locally originated GTP-U control
/// traffic (echo request/response, error indication) out of the re-entry
/// counter: those share the port but never the G-PDU type.
#[inline(always)]
fn outer_envelope_is_uplink_gpdu(ctx: &TcContext, l4_offset: usize) -> bool {
    let Ok(destination_port) = ctx.load::<u16>(l4_offset + 2) else {
        return false;
    };
    if u16::from_be(destination_port) != GTPU_UDP_PORT {
        return false;
    }
    let Ok(header) = ctx.load::<[u8; 2]>(l4_offset + UDP_HDR_LEN) else {
        return false;
    };
    header == [GTPU_FLAGS_V1_GPDU, GTPU_MSG_TYPE_GPDU]
}

/// Return whether `address` is one of this attachment's local S2b-U IPv4
/// endpoints.
///
/// The frozen v5 attachment records it in the single-slot `GTPU_CONFIG`; a
/// grouped attachment records it in `GTPU_CONFIG6` and leaves `GTPU_CONFIG`
/// zero. Both are consulted so one program serves either schema.
#[inline(always)]
fn local_outer_endpoint_is_ipv4(ctx: &TcContext, address: &[u8; 4]) -> bool {
    if *address == [0, 0, 0, 0] {
        return false;
    }
    if let Some(config_ptr) = GTPU_CONFIG.get_ptr(0) {
        // SAFETY: single-slot array value written only by the loader at attach
        // and read here for the length of this invocation.
        if unsafe { *config_ptr } == *address {
            return true;
        }
    }
    let Some(config_ptr) = GTPU_CONFIG6.get_ptr(GTPU_SESSION_CONFIG_KEY) else {
        return false;
    };
    // SAFETY: single-slot array value written only by the loader; borrowed
    // read-only for this canonicality check.
    gtpu_session_config_wire_owns_local_ipv4(unsafe { &*config_ptr }, packet_ifindex(ctx), address)
}

/// Return whether this frame is one of this datapath's own re-emitted outer
/// GTP-U frames traversing the egress hook a second time.
///
/// A successful `bpf_redirect_neigh` re-enters this hook through
/// `skb_do_redirect` -> `__bpf_redirect_neigh_v4` -> `bpf_out_neigh_v4` ->
/// `neigh_output` -> `dev_queue_xmit` -> `sch_handle_egress`; a redirect that
/// finds no usable route is freed before it gets there, and one whose
/// neighbour never resolves is parked in the neighbour's `arp_queue` and
/// likewise never reaches this hook. Counting this second traversal is
/// therefore the redirect outcome, which the helper's constant return value
/// can never report.
///
/// The discriminator is what the frame *is*, never a stamp this program
/// writes: `skb->mark` is load-bearing production state here and is left
/// alone. It requires all of
///
/// - mark zero, which both completion sites establish before redirecting;
/// - an outer IPv4 or IPv6 UDP/2152 GTPv1 G-PDU envelope of exactly the shape
///   this program stamps;
/// - an outer source that is one of this attachment's own local S2b-U
///   endpoints: `GTPU_CONFIG` for the frozen v5 schema, `GTPU_CONFIG6` for
///   grouped attachments, the latter bound to the observed ifindex. Both maps
///   are reached through a per-interface pin directory, so either schema's
///   value is already scoped to this attachment.
///
/// It cannot false-positive on subscriber traffic, because no provisioned UE
/// PAA may alias the local outer endpoint: `GtpuSessionEntry::new` and
/// `entry_wire_is_canonical` reject a grouped entry whose inner PAA aliases
/// its local outer address, and the frozen v5 path rejects
/// `pdp.ms_address == device.bind_address` at install and again on read-back.
/// A first-pass subscriber packet therefore never carries this source, and for
/// the same reason no FAR or grouped selector could ever have matched it --
/// so the FAR-miss accounting this replaces was never reporting a real session
/// lookup failure either. What remains is a locally forged frame that copies
/// this attachment's own outer source, port and G-PDU header; it inflates an
/// observability counter and changes no forwarding decision.
#[inline(never)]
fn uplink_frame_is_redirect_reentry(ctx: &TcContext, mark: u32, eth_proto: u16) -> bool {
    if mark != 0 {
        return false;
    }
    match eth_proto {
        ETH_P_IPV4 => {
            let Ok(version_ihl) = ctx.load::<u8>(ETH_HDR_LEN) else {
                return false;
            };
            let Ok(protocol) = ctx.load::<u8>(ETH_HDR_LEN + 9) else {
                return false;
            };
            // Both sites emit an option-free header; the MTU policy only ever
            // stamps DF and never grows the IHL.
            if version_ihl != 0x45 || protocol != IPV4_PROTO_UDP {
                return false;
            }
            if !outer_envelope_is_uplink_gpdu(ctx, ETH_HDR_LEN + IPV4_MIN_HDR_LEN) {
                return false;
            }
            let Ok(source) = ctx.load::<[u8; 4]>(ETH_HDR_LEN + 12) else {
                return false;
            };
            local_outer_endpoint_is_ipv4(ctx, &source)
        }
        ETH_P_IPV6 => {
            let Ok(version) = ctx.load::<u8>(ETH_HDR_LEN) else {
                return false;
            };
            let Ok(next_header) = ctx.load::<u8>(ETH_HDR_LEN + 6) else {
                return false;
            };
            // The grouped outer-IPv6 encapsulation is the fixed 40-byte header
            // with UDP directly next; no extension-header walk is needed.
            if version >> 4 != 6 || next_header != IPV6_NH_UDP {
                return false;
            }
            if !outer_envelope_is_uplink_gpdu(ctx, ETH_HDR_LEN + IPV6_HDR_LEN) {
                return false;
            }
            let Ok(source) = ctx.load::<[u8; 16]>(ETH_HDR_LEN + 8) else {
                return false;
            };
            let Some(config_ptr) = GTPU_CONFIG6.get_ptr(GTPU_SESSION_CONFIG_KEY) else {
                return false;
            };
            // SAFETY: single-slot array value written only by the loader;
            // borrowed read-only for this canonicality check.
            gtpu_session_config_wire_owns_local_ipv6(
                unsafe { &*config_ptr },
                packet_ifindex(ctx),
                &source,
            )
        }
        _ => false,
    }
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
    observation_authority: &mut Option<&'a [u8; GTPU_SESSION_GROUP_VALUE_LEN]>,
) -> Option<GtpuSessionEntryWireView<'a>> {
    *status = GROUPED_LOOKUP_MISS;
    *observation_authority = None;
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
    *observation_authority = Some(authority);
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
    observation_authority: &mut Option<&'a [u8; GTPU_SESSION_GROUP_VALUE_LEN]>,
) -> Option<GtpuSessionEntryWireView<'a>> {
    *status = GROUPED_LOOKUP_MISS;
    *observation_authority = None;
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
    *observation_authority = Some(authority);
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
            let next_header = ctx.load::<u8>(ETH_HDR_LEN + 6).ok()?;
            let total_len = ipv6_inner_total_length(version, payload_len, next_header, available)?;
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
fn complete_grouped_uplink(
    ctx: &TcContext,
    mark: u32,
    ether_type: u16,
    authority: Option<&[u8; GTPU_SESSION_GROUP_VALUE_LEN]>,
) -> i32 {
    if ctx.store(12, &ether_type.to_be_bytes(), 0).is_err() {
        return TC_ACT_SHOT;
    }
    if mark != 0 {
        // Clear the bearer mark before redirecting: the re-emitted outer frame
        // must traverse this hook as mark zero so it is recognized as this
        // program's own re-entry instead of self-dropping on a marked FAR miss.
        ctx.set_mark(0);
    }
    count(COUNTER_UL_ENCAP);
    // SAFETY: no neighbour parameter pointer is supplied; the helper derives
    // the route and neighbour from the newly materialized outer IP header. A
    // redirect that resolves re-enters this egress hook, where
    // `uplink_frame_is_redirect_reentry` proves delivery to `dev_queue_xmit`.
    // The opaque authority stamp is deliberately written immediately before
    // submission, but no observation is emitted unless that later proof holds.
    stamp_grouped_uplink_observation(ctx, authority);
    let action = unsafe { bpf_redirect_neigh((*ctx.skb.skb).ifindex, core::ptr::null_mut(), 0, 0) };
    if action == i64::from(TC_ACT_REDIRECT) {
        action as i32
    } else {
        TC_ACT_SHOT
    }
}

/// Materialize the exact outer IPv6/UDP/GTP-U header and return the checksum
/// seed for its fixed UDP/GTP-U prefix.
///
/// This verifier boundary keeps the 40-byte IPv6 pseudo-header out of the
/// caller that walks the variable-length inner packet. The returned seed is
/// calculated from the same initialized header bytes that the caller later
/// writes, so reducing stack overlap cannot make checksum authority drift from
/// the emitted packet.
#[inline(never)]
fn prepare_grouped_ipv6_encapsulation(
    entry: GtpuSessionEntryWireView<'_>,
    inner_len: u16,
    encap: &mut [u8; GTPU_IPV6_ENCAP_LEN],
) -> Option<u32> {
    let peer = entry.peer_outer_wire();
    let local = entry.local_outer_wire();
    let udp_length = inner_len.checked_add(16)?;
    let source_port = entry.uplink_source_port();
    if source_port == 0 {
        return None;
    }
    let traffic_class = entry.egress_dscp().unwrap_or(0) << 2;
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
        return None;
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
        return None;
    }
    Some(fixed_sum as u32)
}

#[inline(never)]
fn encapsulate_grouped_ipv6(
    ctx: &TcContext,
    mark: u32,
    entry: GtpuSessionEntryWireView<'_>,
    inner_len: u16,
    authority: Option<&[u8; GTPU_SESSION_GROUP_VALUE_LEN]>,
) -> i32 {
    if entry.outer_family() != GtpuSessionIpFamily::Ipv6
        || !checksum_bytes_are_materialized(ctx)
        || !ipv6_uplink_pmtu_allows(inner_len, entry.inner_family())
    {
        return TC_ACT_SHOT;
    }
    let mut encap = [0_u8; GTPU_IPV6_ENCAP_LEN];
    let Some(fixed_sum) = prepare_grouped_ipv6_encapsulation(entry, inner_len, &mut encap) else {
        return TC_ACT_SHOT;
    };
    let Ok(sum) = checksum_skb_region(ctx, ETH_HDR_LEN, usize::from(inner_len), fixed_sum) else {
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
    complete_grouped_uplink(ctx, mark, ETH_P_IPV6, authority)
}

#[inline(never)]
fn encapsulate_grouped_ipv4(
    ctx: &TcContext,
    mark: u32,
    entry: GtpuSessionEntryWireView<'_>,
    inner_len: u16,
    authority: Option<&[u8; GTPU_SESSION_GROUP_VALUE_LEN]>,
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
    complete_grouped_uplink(ctx, mark, ETH_P_IPV4, authority)
}

#[inline(always)]
fn encapsulate_grouped_uplink(
    ctx: &TcContext,
    mark: u32,
    entry: GtpuSessionEntryWireView<'_>,
    authority: Option<&[u8; GTPU_SESSION_GROUP_VALUE_LEN]>,
) -> i32 {
    let Some(inner_len) = grouped_inner_length(ctx, entry.inner_family()) else {
        return TC_ACT_SHOT;
    };
    match entry.outer_family() {
        GtpuSessionIpFamily::Ipv4 => {
            encapsulate_grouped_ipv4(ctx, mark, entry, inner_len, authority)
        }
        GtpuSessionIpFamily::Ipv6 => {
            encapsulate_grouped_ipv6(ctx, mark, entry, inner_len, authority)
        }
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
            let Ok(next_header) = ctx.load::<u8>(payload_offset + 6) else {
                return false;
            };
            ipv6_inner_length_is_exact(version, u16::from_be(payload_len), next_header, available)
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
    ip_start: u32,
    ip_end: u32,
    cursor: u32,
    option_remaining: u32,
    walked: u32,
    options_walked: u32,
    next_header: u32,
    flags: u32,
    state: u32,
    terminal: u32,
    reject_fragments: u32,
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
// Observation begins after a proven outer GTP-U envelope, while the existing
// downlink parser starts at Ethernet. Bound both positions so bpf_loop state
// remains verifier-friendly without assuming a fixed inner IPv6 offset.
const IPV6_PACKET_MAX_END: u32 =
    (ETH_HDR_LEN + GTPU_IPV6_ENCAP_LEN + IPV6_HDR_LEN + u16::MAX as usize) as u32;
const IPV6_OPTIONS_MAX_BYTES: u32 = (u8::MAX as u32 + 1) * 8 - 2;
const IPV6_TERMINAL_UDP: u32 = 0;
const IPV6_TERMINAL_OBSERVATION: u32 = 1;

#[inline(always)]
const fn ipv6_l4_parse_config(ip_start: usize, terminal: u32, reject_fragments: bool) -> u64 {
    (ip_start as u64) | ((terminal as u64) << 32) | ((reject_fragments as u64) << 33)
}

// One iteration discovers an extension header or consumes one option TLV.
// Eight headers carrying the maximum 32 options each therefore require at
// most 8 * (1 + 32) verifier-bounded steps.
const IPV6_EXTENSION_LOOP_STEPS: u32 =
    (IPV6_MAX_EXT_HEADERS * (IPV6_MAX_OPTIONS_PER_HEADER + 1)) as u32;

#[inline(always)]
const fn ipv6_terminal_is_accepted(next_header: u32, terminal: u32) -> bool {
    match terminal {
        IPV6_TERMINAL_UDP => next_header == IPV6_NH_UDP as u32,
        IPV6_TERMINAL_OBSERVATION => {
            next_header == IPPROTO_TCP as u32
                || next_header == IPPROTO_UDP as u32
                || next_header == IPPROTO_ICMPV6 as u32
        }
        _ => false,
    }
}

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
    if context.ip_start < ETH_HDR_LEN as u32
        || context.ip_start > (ETH_HDR_LEN + GTPU_IPV6_ENCAP_LEN) as u32
    {
        context.state = IPV6_EXTENSION_STATE_FAILED;
        return 1;
    }
    let base_end = context.ip_start + IPV6_HDR_LEN as u32;
    if context.ip_end < base_end
        || context.ip_end > IPV6_PACKET_MAX_END
        || context.cursor < base_end
        || context.cursor > context.ip_end
        || context.option_remaining > IPV6_OPTIONS_MAX_BYTES
        || context.walked > IPV6_MAX_EXT_HEADERS as u32
        || context.options_walked > IPV6_MAX_OPTIONS_PER_HEADER as u32
        || context.next_header > u32::from(u8::MAX)
        || context.flags & !IPV6_EXTENSION_FLAGS_MASK != 0
        || context.terminal > IPV6_TERMINAL_OBSERVATION
        || context.reject_fragments > 1
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
        if ipv6_terminal_is_accepted(context.next_header, context.terminal) {
            context.state = IPV6_EXTENSION_STATE_DONE;
            return 1;
        }
        if context.walked >= IPV6_MAX_EXT_HEADERS as u32 {
            context.state = IPV6_EXTENSION_STATE_FAILED;
            return 1;
        }
        return 0;
    }

    if ipv6_terminal_is_accepted(context.next_header, context.terminal) {
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
    // Keep the observation and forwarding walkers aligned with the shared
    // host-model classifier. The callback owns only skb loading and bounded
    // option/routing validation that cannot use a borrowed packet slice.
    let Ok(Ipv6ExtensionStep::Skip {
        next_header,
        header_len,
        atomic_fragment,
    }) = classify_ipv6_extension_step(current_header, prefix, available as usize)
    else {
        context.state = IPV6_EXTENSION_STATE_FAILED;
        return 1;
    };
    if context.reject_fragments != 0 && atomic_fragment {
        context.state = IPV6_EXTENSION_STATE_FAILED;
        return 1;
    }
    let header_len = u32::from(header_len);
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
    context.next_header = u32::from(next_header);

    if current_header == IPV6_NH_HOP_BY_HOP || current_header == IPV6_NH_DESTINATION_OPTIONS {
        context.cursor += 2;
        context.option_remaining = header_len - 2;
        context.options_walked = 0;
        context.state = IPV6_EXTENSION_STATE_OPTIONS;
        return 0;
    }

    context.cursor = header_end;
    if ipv6_terminal_is_accepted(context.next_header, context.terminal) {
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

/// Walk one bounded IPv6 extension chain without materializing it.
///
/// The terminal selector retains the forwarding parser's UDP/atomic-fragment
/// contract while observation accepts only TCP, UDP, or ICMPv6 and rejects
/// every Fragment header. Failure is side-effect free for the caller.
#[inline(never)]
fn ipv6_l4_offset(ctx: &TcContext, ip_end: usize, parse_config: u64) -> Option<(u8, usize)> {
    let ip_start = usize::try_from(parse_config as u32).ok()?;
    let terminal = u32::try_from((parse_config >> 32) & 1).ok()?;
    let reject_fragments = (parse_config >> 33) & 1 != 0;
    if parse_config >> 34 != 0 {
        return None;
    }
    let cursor = ip_start.checked_add(IPV6_HDR_LEN)?;
    if ip_end > ctx.len() as usize || terminal > IPV6_TERMINAL_OBSERVATION {
        return None;
    }
    let next_header = ctx.load::<u8>(ip_start.checked_add(6)?).ok()?;
    let mut loop_context = Ipv6ExtensionLoopContext {
        skb: ctx.skb.skb,
        ip_start: u32::try_from(ip_start).ok()?,
        ip_end: u32::try_from(ip_end).ok()?,
        cursor: u32::try_from(cursor).ok()?,
        option_remaining: 0,
        walked: 0,
        options_walked: 0,
        next_header: u32::from(next_header),
        flags: 0,
        state: IPV6_EXTENSION_STATE_WALK,
        terminal,
        reject_fragments: u32::from(reject_fragments),
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
    Some((
        u8::try_from(loop_context.next_header).ok()?,
        usize::try_from(loop_context.cursor).ok()?,
    ))
}

/// Walk the declared IPv6 extension chain without materializing it.
///
/// `None` always means "let the IPv6 stack decide": the caller has not yet
/// proven a UDP/2152 candidate. Atomic fragments are accepted; packets that
/// require reassembly, AH/ESP, active routing, and discard-required options
/// remain untouched for the host stack.
#[inline(never)]
fn ipv6_udp_offset(ctx: &TcContext, ip_end: usize) -> Option<usize> {
    ipv6_l4_offset(
        ctx,
        ip_end,
        ipv6_l4_parse_config(ETH_HDR_LEN, IPV6_TERMINAL_UDP, false),
    )
    .map(|(_, offset)| offset)
}

#[inline(never)]
fn software_ipv6_udp_checksum_is_valid(
    ctx: &TcContext,
    udp_offset: usize,
    udp_length: usize,
) -> bool {
    let Some(pseudo_sum) = ipv6_udp_pseudo_sum(ctx, udp_length) else {
        return false;
    };
    checksum_skb_region(ctx, udp_offset, udp_length, pseudo_sum)
        .is_ok_and(internet_checksum_sum_is_valid)
}

/// Return the IPv6/UDP pseudo-header checksum seed without retaining its
/// 40-byte packet identity beside the variable-length skb checksum walker.
#[inline(never)]
fn ipv6_udp_pseudo_sum(ctx: &TcContext, udp_length: usize) -> Option<u32> {
    let Ok(source) = ctx.load::<[u8; 16]>(ETH_HDR_LEN + 8) else {
        return None;
    };
    let Ok(destination) = ctx.load::<[u8; 16]>(ETH_HDR_LEN + 24) else {
        return None;
    };
    let Ok(udp_length) = u32::try_from(udp_length) else {
        return None;
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
        return None;
    }
    Some(pseudo_sum as u32)
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

    // The IPv6 and UDP headers locate the mandatory GTP-U header. Non-G-PDU
    // traffic is pass-only and stays with the local typed control consumer,
    // whose kernel-owned checksum completion may still be pending at tc.
    // G-PDU is the only decapsulation candidate and therefore remains subject
    // to every strict envelope and checksum validation below.
    let Some(udp_header_end) = udp_offset.checked_add(8) else {
        return IPV6_PARSE_DROP;
    };
    let Some(gtp_header_end) = udp_header_end.checked_add(GTPU_MANDATORY_HDR_LEN) else {
        return IPV6_PARSE_DROP;
    };
    if gtp_header_end > ip_end {
        return IPV6_PARSE_DROP;
    }
    let Ok(gtp_header) = ctx.load::<[u8; GTPU_MANDATORY_HDR_LEN]>(udp_header_end) else {
        return IPV6_PARSE_DROP;
    };
    let (teid, gtp_length, has_opt, has_ext) = match classify_gtpu(&gtp_header) {
        GtpuClass::NotGtpV1 | GtpuClass::NotGpdu => return IPV6_PARSE_PASS,
        GtpuClass::Gpdu {
            teid,
            length,
            has_opt,
            has_ext,
        } => (teid, length, has_opt, has_ext),
    };

    // UDP/2152 G-PDUs are decapsulation candidates. Every malformed boundary,
    // checksum, or G-PDU declaration fails closed before the grouped selector
    // lookup.
    if packet_gso_size(ctx) != 0 {
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
    let mut observation_authority = None;
    match grouped_downlink_authority(
        ctx,
        parsed.teid,
        packed_offsets,
        &mut status,
        &mut observation_authority,
    ) {
        Some(entry) => {
            // Freeze the attempt identity before the forwarding mutation. A
            // delayed packet cannot be rebound to a registration installed
            // after this decision; the emitter also revalidates the exact
            // authority and publication after successful decapsulation.
            let observation_publication_id =
                current_observation_redirect_identity(observation_authority)
                    .map(|(_, publication_id)| publication_id);
            let action =
                decap_grouped_downlink(ctx, GtpuSessionIpFamily::Ipv6, payload_offset, entry);
            if action == TC_ACT_OK {
                if let Some(publication_id) = observation_publication_id {
                    emit_grouped_observation(
                        ctx,
                        observation_authority,
                        publication_id,
                        ETH_HDR_LEN,
                        GtpuTrafficObservationDirection::CoreToAccess,
                    );
                }
            }
            action
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

/// Attempt the grouped IPv4 path after the outer envelope parser has produced
/// exact offsets. The live observation authority is intentionally owned only
/// by this sibling phase: keeping it out of the classifier root means a
/// grouped miss cannot carry unrelated proof scratch into the legacy journal
/// authorization call chain.
///
/// `None` is the one proven grouped miss. Every malformed or conflicting
/// grouped state remains a handled fail-closed verdict.
#[inline(never)]
fn handle_grouped_downlink_ipv4(
    ctx: &TcContext,
    teid: [u8; 4],
    l4_offset: usize,
    payload_offset: usize,
) -> Option<i32> {
    let Some(packed_offsets) = pack_grouped_downlink_offsets(l4_offset, payload_offset) else {
        return Some(malformed_downlink());
    };
    let mut grouped_status = GROUPED_LOOKUP_MISS;
    let mut observation_authority = None;
    match grouped_downlink_authority(
        ctx,
        teid,
        packed_offsets,
        &mut grouped_status,
        &mut observation_authority,
    ) {
        Some(entry) => {
            // Capture before mutation, publish only after the exact grouped
            // decapsulation succeeds, and revalidate against current
            // authority inside the emitter.
            let observation_publication_id =
                current_observation_redirect_identity(observation_authority)
                    .map(|(_, publication_id)| publication_id);
            let action =
                decap_grouped_downlink(ctx, GtpuSessionIpFamily::Ipv4, payload_offset, entry);
            if action == TC_ACT_OK {
                if let Some(publication_id) = observation_publication_id {
                    emit_grouped_observation(
                        ctx,
                        observation_authority,
                        publication_id,
                        ETH_HDR_LEN,
                        GtpuTrafficObservationDirection::CoreToAccess,
                    );
                }
            }
            Some(action)
        }
        None if grouped_status == GROUPED_LOOKUP_ERROR => {
            Some(binding_drop(DownlinkBindingMismatch::Invalid))
        }
        None => None,
    }
}

#[classifier]
pub fn opc_gtpu_uplink(mut ctx: TcContext) -> i32 {
    if !traffic_gate_allows_packet_effects() {
        return TC_ACT_OK;
    }
    let mark = packet_mark(&ctx);
    let Ok(eth_proto) = ctx.load::<u16>(12) else {
        return non_encapsulation_action(mark);
    };
    let eth_proto = u16::from_be(eth_proto);
    if uplink_frame_is_redirect_reentry(&ctx, mark, eth_proto) {
        // Keep the delivery-proof path in the classifier's small root frame.
        // The ordinary encapsulation path owns substantially more stack; if it
        // is inlined here, Linux accounts that unrelated frame while checking
        // the nested observation parser and rejects the otherwise bounded
        // chain before a packet can run.
        count(COUNTER_UL_REDIRECT_RESOLVED);
        emit_grouped_uplink_observation_on_reentry(&ctx, eth_proto);
        return non_encapsulation_action(mark);
    }
    clear_unmatched_grouped_uplink_observation_stamp(&ctx);

    match try_uplink(&mut ctx, mark, eth_proto) {
        Ok(action) => action,
        Err(()) => non_encapsulation_action(mark),
    }
}

#[classifier]
pub fn opc_gtpu_downlink(mut ctx: TcContext) -> i32 {
    if !traffic_gate_allows_packet_effects() {
        return TC_ACT_OK;
    }
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
    if let Some(action) = handle_grouped_downlink_ipv4(&ctx, teid, l4_offset, payload_offset) {
        return action;
    }
    authorize_and_decap_legacy_downlink(&mut ctx, teid, l4_offset, payload_offset)
}

/// Uplink: inner IPv4 packet routed to the S2b-U interface with
/// `src = UE PAA`. Prepend `[outer IPv4][UDP][GTPv1-U]` and re-resolve the
/// L2 next hop for the new outer destination.
#[inline(never)]
fn try_uplink(ctx: &mut TcContext, mut mark: u32, eth_proto: u16) -> Result<i32, ()> {
    match eth_proto {
        ETH_P_IPV4 => {
            let version_ihl: u8 = ctx.load(ETH_HDR_LEN).map_err(|_| ())?;
            if version_ihl >> 4 != 4 {
                return Ok(non_encapsulation_action(mark));
            }

            // A shared-SA classifier owns an unmarked, valid IPv4 PAA before
            // any grouped/default selector can choose an entry for mark zero.
            // A selected nonzero mark is made visible to both later lookup
            // paths; absent metadata leaves the frozen behavior unchanged.
            if mark == 0 {
                match classify_owned_tft_uplink(ctx) {
                    TftClassifierUplinkResult::Absent => {}
                    TftClassifierUplinkResult::Selected(selected_mark) => {
                        mark = selected_mark;
                        if mark != 0 {
                            ctx.set_mark(mark);
                        }
                    }
                    TftClassifierUplinkResult::Drop => return Ok(TC_ACT_SHOT as i32),
                }
            }
        }
        // IPv6 has no TFT classifier and retains its grouped-only path.
        ETH_P_IPV6 => {}
        _ => return Ok(non_encapsulation_action(mark)),
    }

    // This is intentionally after the classifier. A grouped default entry
    // must not observe an originally unmarked shared-SA packet before TFT can
    // select its dedicated bearer mark.
    let mut grouped_status = GROUPED_LOOKUP_MISS;
    let mut observation_authority = None;
    match grouped_uplink_authority(
        ctx,
        mark,
        eth_proto,
        &mut grouped_status,
        &mut observation_authority,
    ) {
        Some(entry) => {
            return Ok(encapsulate_grouped_uplink(
                ctx,
                mark,
                entry,
                observation_authority,
            ));
        }
        None if grouped_status == GROUPED_LOOKUP_ERROR => return Ok(TC_ACT_SHOT),
        None => {}
    }

    try_legacy_uplink(ctx, mark, eth_proto)
}

/// Run only the frozen IPv4 compatibility path after grouped authority has
/// conclusively missed. Keeping its independent graph-validation frame out of
/// grouped IPv6 encapsulation bounds every verifier call chain without
/// changing selector precedence or forwarding behavior.
#[inline(never)]
fn try_legacy_uplink(ctx: &mut TcContext, mark: u32, eth_proto: u16) -> Result<i32, ()> {
    if eth_proto != ETH_P_IPV4 {
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
    if mark != 0 {
        // Re-fetch immediately before authorization instead of carrying a map
        // pointer across the intervening graph checks. The verifier must see
        // this exact lookup provenance at the subprogram boundary, and a
        // concurrent owner removal must fail closed in either case.
        let Some(owner_ptr) = GTPU_M_OWNER.get_ptr(&marked_key) else {
            count(COUNTER_UL_FAR_MISS);
            return Ok(TC_ACT_SHOT as i32);
        };
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
    // outer header. A redirect that resolves re-enters this egress hook once
    // more, where `uplink_frame_is_redirect_reentry` recognizes it and counts
    // COUNTER_UL_REDIRECT_RESOLVED before it passes through.
    // SAFETY: helper takes no pointers when plen == 0.
    let ret = unsafe { bpf_redirect_neigh((*ctx.skb.skb).ifindex, core::ptr::null_mut(), 0, 0) };
    // Fail closed on any non-redirect verdict, symmetrically with
    // `complete_grouped_uplink`, so no future call shape can return an
    // unhandled value that `sch_handle_egress` maps to `default: break` and
    // keeps transmitting with the inner route's L2 destination. Today the
    // `else` arm is unreachable: `bpf_redirect_neigh` returns TC_ACT_SHOT only
    // for `(plen && plen < sizeof(*params)) || flags`, and `plen == 0` with
    // `flags == 0` is exactly the shape that condition can never be true for.
    if ret == i64::from(TC_ACT_REDIRECT) {
        Ok(ret as i32)
    } else {
        Ok(TC_ACT_SHOT as i32)
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

/// Add one fixed remainder chunk without retaining its packet buffer in the
/// variable-length checksum walker's verifier frame.
#[inline(never)]
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
#[inline(never)]
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
    ipv4_header_checksum_is_valid_at(ctx, ETH_HDR_LEN, bounds.ip_header_len())
}

#[inline(always)]
fn ipv4_header_checksum_is_valid_at(
    ctx: &TcContext,
    ip_offset: usize,
    ip_header_len: usize,
) -> bool {
    if !(IPV4_MIN_HDR_LEN..=60).contains(&ip_header_len) || !ip_header_len.is_multiple_of(2) {
        return false;
    }
    let words = ip_header_len / 2;
    let mut sum = 0_u32;
    let mut index = 0_usize;
    while index < 30 {
        if index >= words {
            break;
        }
        let Some(offset) = index
            .checked_mul(2)
            .and_then(|value| ip_offset.checked_add(value))
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

/// Validate one exact fixed ICMP observation message without entering the
/// variable-length packet checksum frame. The packet parser proves this
/// message is precisely the eight-byte Echo header plus the 32-byte challenge
/// and reaches the declared IP/skb end before calling here.
///
/// `bpf_skb_load_bytes` retains support for non-linear skbs. The initialized
/// fixed buffer is passed whole to the checksum helper, so no packet byte is
/// skipped and no untrusted length controls stack use.
#[inline(never)]
fn observation_icmp_checksum_40_is_valid(ctx: &TcContext, icmp_offset: usize, seed: u32) -> bool {
    let Ok(icmp_offset) = u32::try_from(icmp_offset) else {
        return false;
    };
    let mut message = core::mem::MaybeUninit::<[u8; 40]>::uninit();
    // SAFETY: the kernel supplied this live tc skb. A successful load
    // initializes all 40 bytes before `bpf_csum_diff` reads that same nonzero
    // four-byte-multiple region.
    let sum = unsafe {
        if bpf_skb_load_bytes(
            ctx.skb.skb.cast(),
            icmp_offset,
            message.as_mut_ptr().cast(),
            40,
        ) != 0
        {
            return false;
        }
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            message.as_mut_ptr().cast::<u32>(),
            40,
            seed,
        )
    };
    sum >= 0 && internet_checksum_sum_is_valid(sum as u32)
}

#[inline(never)]
fn observation_icmpv6_checksum_is_valid(
    ctx: &TcContext,
    ip_offset: usize,
    icmp_offset: usize,
) -> bool {
    let Some(pseudo_sum) = observation_icmpv6_pseudo_sum(ctx, ip_offset, 40) else {
        return false;
    };
    observation_icmp_checksum_40_is_valid(ctx, icmp_offset, pseudo_sum)
}

/// Return the fixed IPv6 ICMP pseudo-header checksum seed. The complete
/// pseudo-header is initialized before the helper sees its aligned words.
#[inline(never)]
fn observation_icmpv6_pseudo_sum(
    ctx: &TcContext,
    ip_offset: usize,
    icmp_length: u32,
) -> Option<u32> {
    let Ok(source) = ctx.load::<[u64; 2]>(ip_offset + 8) else {
        return None;
    };
    let Ok(destination) = ctx.load::<[u64; 2]>(ip_offset + 24) else {
        return None;
    };
    let length = icmp_length.to_be_bytes();
    // Initialize every byte directly. A zero-filled array followed by copies
    // lowers to an extra `memset` BPF-to-BPF call, which would make the
    // downlink parser's already bounded checksum path exceed the kernel's
    // eight-frame call-depth limit.
    let mut pseudo_header = [
        source[0],
        source[1],
        destination[0],
        destination[1],
        u64::from_ne_bytes([
            length[0],
            length[1],
            length[2],
            length[3],
            0,
            0,
            0,
            IPPROTO_ICMPV6,
        ]),
    ];
    // SAFETY: the pseudo-header is fully initialized and its length is a
    // nonzero multiple of four, as required by `bpf_csum_diff`.
    let pseudo_sum = unsafe {
        bpf_csum_diff(
            core::ptr::null_mut(),
            0,
            pseudo_header.as_mut_ptr().cast::<u32>(),
            core::mem::size_of_val(&pseudo_header) as u32,
            0,
        )
    };
    if pseudo_sum < 0 {
        return None;
    }
    Some(pseudo_sum as u32)
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

    // The fixed headers locate the mandatory GTP-U header. Non-G-PDU traffic
    // is pass-only and remains for the local typed control consumer, whose
    // kernel-owned checksum completion may still be pending at tc. G-PDU is
    // the only decapsulation candidate and remains fail-closed below.
    let Some(gtp_offset) = l4_offset.checked_add(UDP_HDR_LEN) else {
        return u64::from(malformed_downlink() as u32);
    };
    let Some(gtp_header_end) = gtp_offset.checked_add(GTPU_MANDATORY_HDR_LEN) else {
        return u64::from(malformed_downlink() as u32);
    };
    if gtp_header_end > ctx.len() as usize {
        return u64::from(malformed_downlink() as u32);
    }
    let Ok(gtp_header) = ctx.load::<[u8; GTPU_MANDATORY_HDR_LEN]>(gtp_offset) else {
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

    // UDP/2152 G-PDUs are decapsulation candidates. Every malformed
    // declaration or checksum fails closed before any PDR lookup.
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

    let declared_gtp_length = u16::from_be_bytes([gtp_header[2], gtp_header[3]]);
    let Ok(gtp_bounds) = GtpuEnvelopeBounds::parse(udp_bounds, declared_gtp_length) else {
        return u64::from(malformed_downlink() as u32);
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

    // The pre-#655 generic tuple-correlation host model is deliberately kept
    // out of the test graph. It describes a producer contract that must never
    // again be able to mint traffic-proof events.
    #[cfg(any())]
    mod legacy_generic_flow_correlation_model {
        use super::*;

        /// Host model for the observation-only IPv6 key contract. The eBPF
        /// implementation uses the same `classify_ipv6_extension_step` primitive,
        /// but reads bounded skb ranges inside a verifier-safe `bpf_loop`.
        fn modeled_ipv6_observation_key(
            packet: &[u8],
            direction: GtpuTrafficObservationDirection,
        ) -> Option<[u8; 40]> {
            if packet.len() < IPV6_HDR_LEN || packet[0] >> 4 != 6 {
                return None;
            }
            let ip_end = IPV6_HDR_LEN
                .checked_add(usize::from(u16::from_be_bytes([packet[4], packet[5]])))?;
            if ip_end > packet.len() {
                return None;
            }
            let mut next_header = packet[6];
            let mut cursor = IPV6_HDR_LEN;
            let mut walked = 0_usize;
            let mut routing_seen = false;
            let mut pre_routing_destination_seen = false;
            let mut final_destination_seen = false;
            loop {
                if matches!(next_header, IPPROTO_TCP | IPPROTO_UDP | IPPROTO_ICMPV6) {
                    break;
                }
                if walked == IPV6_MAX_EXT_HEADERS
                    || next_header == IPV6_NH_HOP_BY_HOP && walked != 0
                    || next_header == IPV6_NH_ROUTING && routing_seen
                    || next_header == IPV6_NH_FRAGMENT
                    || next_header == IPV6_NH_ROUTING && final_destination_seen
                    || next_header == IPV6_NH_DESTINATION_OPTIONS && final_destination_seen
                    || next_header == IPV6_NH_DESTINATION_OPTIONS
                        && pre_routing_destination_seen
                        && !routing_seen
                {
                    return None;
                }
                let prefix: [u8; 8] = packet
                    .get(cursor..cursor.checked_add(8)?)?
                    .try_into()
                    .ok()?;
                let available = ip_end.checked_sub(cursor)?;
                let Ipv6ExtensionStep::Skip {
                    next_header: following,
                    header_len,
                    atomic_fragment,
                } = classify_ipv6_extension_step(next_header, prefix, available).ok()?
                else {
                    return None;
                };
                // Correlation deliberately rejects even an atomic Fragment header:
                // evidence must never depend on fragment interpretation.
                if atomic_fragment {
                    return None;
                }
                let header_end = cursor.checked_add(usize::from(header_len))?;
                let header = packet.get(cursor..header_end)?;
                match next_header {
                    IPV6_NH_HOP_BY_HOP | IPV6_NH_DESTINATION_OPTIONS => {
                        validate_ipv6_options_header(header).ok()?;
                    }
                    IPV6_NH_ROUTING => validate_ipv6_routing_header(header).ok()?,
                    _ => {}
                }
                match next_header {
                    IPV6_NH_ROUTING => routing_seen = true,
                    IPV6_NH_DESTINATION_OPTIONS if routing_seen => final_destination_seen = true,
                    IPV6_NH_DESTINATION_OPTIONS => pre_routing_destination_seen = true,
                    _ => {}
                }
                cursor = header_end;
                next_header = following;
                walked += 1;
            }
            let transport_len = ip_end.checked_sub(cursor)?;
            if transport_len < 8 {
                return None;
            }
            let mut l4_header = [0_u8; 20];
            let prefix_len = core::cmp::min(transport_len, l4_header.len());
            l4_header[..prefix_len].copy_from_slice(packet.get(cursor..cursor + prefix_len)?);
            if !observation_transport_is_valid(next_header, 6, l4_header, transport_len) {
                return None;
            }
            let l4: [u8; 8] = l4_header[..8].try_into().ok()?;
            let (access_l4, core_l4) = observation_l4_correlation(next_header, 6, direction, l4)?;
            let mut key = [0_u8; 40];
            key[0] = 1;
            key[1] = 6;
            key[2] = next_header;
            match direction {
                GtpuTrafficObservationDirection::AccessToCore => {
                    key[4..20].copy_from_slice(&packet[8..24]);
                    key[20..36].copy_from_slice(&packet[24..40]);
                }
                GtpuTrafficObservationDirection::CoreToAccess => {
                    key[4..20].copy_from_slice(&packet[24..40]);
                    key[20..36].copy_from_slice(&packet[8..24]);
                }
            }
            key[36..38].copy_from_slice(&access_l4);
            key[38..40].copy_from_slice(&core_l4);
            Some(key)
        }

        fn modeled_ipv6_packet(first_next_header: u8, extensions: &[u8], l4: [u8; 8]) -> Vec<u8> {
            // Keep a twenty-byte declared transport extent so the helper can model
            // both direct TCP and TCP reached through an extension chain. UDP and
            // ICMP simply treat the remaining bytes as payload.
            let transport_len = 20;
            let mut packet = vec![0_u8; IPV6_HDR_LEN + extensions.len() + transport_len];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(
                &u16::try_from(extensions.len() + transport_len)
                    .expect("synthetic payload fits")
                    .to_be_bytes(),
            );
            packet[6] = first_next_header;
            packet[8..24].copy_from_slice(&[0x20; 16]);
            packet[24..40].copy_from_slice(&[0x30; 16]);
            packet[IPV6_HDR_LEN..IPV6_HDR_LEN + extensions.len()].copy_from_slice(extensions);
            let transport_start = IPV6_HDR_LEN + extensions.len();
            packet[transport_start..transport_start + l4.len()].copy_from_slice(&l4);
            packet[transport_start + 12] = 0x50;
            if first_next_header == IPPROTO_UDP && l4[4] == 0 && l4[5] == 0 {
                packet[transport_start + 4..transport_start + 6]
                    .copy_from_slice(&u16::try_from(transport_len).expect("bounded").to_be_bytes());
            }
            packet
        }

        fn modeled_ipv4_observation_key(
            packet: &[u8],
            direction: GtpuTrafficObservationDirection,
        ) -> Option<[u8; 40]> {
            if packet.len() < IPV4_MIN_HDR_LEN || packet[0] >> 4 != 4 {
                return None;
            }
            let header_len = usize::from(packet[0] & 0x0f).checked_mul(4)?;
            let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            let fragment = u16::from_be_bytes([packet[6], packet[7]]);
            if header_len < IPV4_MIN_HDR_LEN || total_len < header_len || fragment & 0x3fff != 0 {
                return None;
            }
            let ip_end = total_len;
            if ip_end > packet.len() {
                return None;
            }
            let l4_offset = header_len;
            let transport_len = ip_end.checked_sub(l4_offset)?;
            if transport_len < 8 {
                return None;
            }
            let mut l4_header = [0_u8; 20];
            let prefix_len = core::cmp::min(transport_len, l4_header.len());
            l4_header[..prefix_len].copy_from_slice(packet.get(l4_offset..l4_offset + prefix_len)?);
            let protocol = packet[9];
            if !observation_transport_is_valid(protocol, 4, l4_header, transport_len) {
                return None;
            }
            let l4: [u8; 8] = l4_header[..8].try_into().ok()?;
            let (access_l4, core_l4) = observation_l4_correlation(protocol, 4, direction, l4)?;
            let mut key = [0_u8; 40];
            key[0] = 1;
            key[1] = 4;
            key[2] = protocol;
            match direction {
                GtpuTrafficObservationDirection::AccessToCore => {
                    key[4..8].copy_from_slice(&packet[12..16]);
                    key[20..24].copy_from_slice(&packet[16..20]);
                }
                GtpuTrafficObservationDirection::CoreToAccess => {
                    key[4..8].copy_from_slice(&packet[16..20]);
                    key[20..24].copy_from_slice(&packet[12..16]);
                }
            }
            key[36..38].copy_from_slice(&access_l4);
            key[38..40].copy_from_slice(&core_l4);
            Some(key)
        }

        fn modeled_ipv4_packet(protocol: u8, transport: &[u8]) -> Vec<u8> {
            let total_len = IPV4_MIN_HDR_LEN + transport.len();
            let mut packet = vec![0_u8; total_len];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&u16::try_from(total_len).expect("bounded").to_be_bytes());
            packet[9] = protocol;
            packet[12..16].copy_from_slice(&[0x0a, 0, 0, 1]);
            packet[16..20].copy_from_slice(&[0x0a, 0, 0, 2]);
            packet[IPV4_MIN_HDR_LEN..].copy_from_slice(transport);
            packet
        }

        #[test]
        fn observation_ipv6_model_accepts_direct_and_canonical_extension_l4() {
            for (protocol, l4) in [
                (IPPROTO_TCP, [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0]),
                (IPPROTO_UDP, [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0]),
                (IPPROTO_ICMPV6, [128, 0, 0, 0, 0xab, 0xcd, 0x12, 0x34]),
            ] {
                assert!(modeled_ipv6_observation_key(
                    &modeled_ipv6_packet(protocol, &[], l4),
                    GtpuTrafficObservationDirection::AccessToCore,
                )
                .is_some());
            }

            let canonical_chain = [
                IPV6_NH_DESTINATION_OPTIONS,
                0,
                0,
                0,
                0,
                0,
                0,
                0, // Hop-by-Hop.
                IPV6_NH_ROUTING,
                0,
                0,
                0,
                0,
                0,
                0,
                0, // pre-routing Destination.
                IPV6_NH_DESTINATION_OPTIONS,
                0,
                253,
                0,
                0,
                0,
                0,
                0, // inert Routing.
                IPPROTO_TCP,
                0,
                0,
                0,
                0,
                0,
                0,
                0, // final Destination.
            ];
            assert!(modeled_ipv6_observation_key(
                &modeled_ipv6_packet(
                    IPV6_NH_HOP_BY_HOP,
                    &canonical_chain,
                    [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0],
                ),
                GtpuTrafficObservationDirection::AccessToCore,
            )
            .is_some());

            // The forwarding extension contract itself rejects AH, so correlation
            // must not broaden it merely to produce an observation.
            assert!(modeled_ipv6_observation_key(
                &modeled_ipv6_packet(51, &[IPPROTO_TCP, 0, 0, 0, 0, 0, 0, 0], [1; 8]),
                GtpuTrafficObservationDirection::AccessToCore,
            )
            .is_none());
        }

        #[test]
        fn observation_ipv6_model_rejects_ambiguous_or_malformed_chains() {
            let l4 = [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0];
            for fragment in [
                [IPPROTO_TCP, 0, 0, 0, 0, 0, 0, 0], // atomic
                [IPPROTO_TCP, 0, 0, 8, 0, 0, 0, 0], // non-first
            ] {
                assert!(modeled_ipv6_observation_key(
                    &modeled_ipv6_packet(IPV6_NH_FRAGMENT, &fragment, l4),
                    GtpuTrafficObservationDirection::AccessToCore,
                )
                .is_none());
            }
            let mut too_many = Vec::new();
            for _ in 0..=IPV6_MAX_EXT_HEADERS {
                too_many.extend_from_slice(&[IPV6_NH_HOP_BY_HOP, 0, 0, 0, 0, 0, 0, 0]);
            }
            assert!(modeled_ipv6_observation_key(
                &modeled_ipv6_packet(IPV6_NH_HOP_BY_HOP, &too_many, l4),
                GtpuTrafficObservationDirection::AccessToCore,
            )
            .is_none());
            let malformed = modeled_ipv6_packet(
                IPV6_NH_DESTINATION_OPTIONS,
                &[IPPROTO_TCP, 1, 0, 0, 0, 0, 0, 0],
                l4,
            );
            assert!(modeled_ipv6_observation_key(
                &malformed,
                GtpuTrafficObservationDirection::AccessToCore,
            )
            .is_none());
            let mut truncated = modeled_ipv6_packet(IPPROTO_TCP, &[], l4);
            truncated[4..6]
                .copy_from_slice(&u16::try_from(l4.len() + 8).expect("bounded").to_be_bytes());
            assert!(modeled_ipv6_observation_key(
                &truncated,
                GtpuTrafficObservationDirection::AccessToCore,
            )
            .is_none());
        }

        #[test]
        fn observation_ipv6_model_normalizes_reverse_tcp_and_echo_flows() {
            let forward =
                modeled_ipv6_packet(IPPROTO_TCP, &[], [0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0]);
            let mut reverse =
                modeled_ipv6_packet(IPPROTO_TCP, &[], [0x56, 0x78, 0x12, 0x34, 0, 0, 0, 0]);
            reverse[8..24].copy_from_slice(&forward[24..40]);
            reverse[24..40].copy_from_slice(&forward[8..24]);
            assert_eq!(
                modeled_ipv6_observation_key(
                    &forward,
                    GtpuTrafficObservationDirection::AccessToCore
                ),
                modeled_ipv6_observation_key(
                    &reverse,
                    GtpuTrafficObservationDirection::CoreToAccess
                ),
            );

            let echo =
                modeled_ipv6_packet(IPPROTO_ICMPV6, &[], [128, 0, 0, 0, 0xab, 0xcd, 0x12, 0x34]);
            let mut reply =
                modeled_ipv6_packet(IPPROTO_ICMPV6, &[], [129, 0, 0, 0, 0xab, 0xcd, 0x12, 0x34]);
            reply[8..24].copy_from_slice(&echo[24..40]);
            reply[24..40].copy_from_slice(&echo[8..24]);
            assert_eq!(
                modeled_ipv6_observation_key(&echo, GtpuTrafficObservationDirection::AccessToCore),
                modeled_ipv6_observation_key(&reply, GtpuTrafficObservationDirection::CoreToAccess),
            );

            let mut later_echo = echo.clone();
            later_echo[46..48].copy_from_slice(&0x5678_u16.to_be_bytes());
            let mut later_reply = reply.clone();
            later_reply[46..48].copy_from_slice(&0x5678_u16.to_be_bytes());
            assert_eq!(
                modeled_ipv6_observation_key(&echo, GtpuTrafficObservationDirection::AccessToCore),
                modeled_ipv6_observation_key(
                    &later_echo,
                    GtpuTrafficObservationDirection::AccessToCore,
                ),
            );
            assert_eq!(
                modeled_ipv6_observation_key(
                    &later_echo,
                    GtpuTrafficObservationDirection::AccessToCore
                ),
                modeled_ipv6_observation_key(
                    &later_reply,
                    GtpuTrafficObservationDirection::CoreToAccess
                ),
            );
        }

        #[test]
        fn observation_echo_correlation_spans_successive_ipv4_and_ipv6_exchanges() {
            for (protocol, version, request_type, reply_type) in
                [(IPPROTO_ICMP, 4, 8, 0), (IPPROTO_ICMPV6, 6, 128, 129)]
            {
                let request_one = [request_type, 0, 0, 0, 0xab, 0xcd, 0, 1];
                let reply_one = [reply_type, 0, 0, 0, 0xab, 0xcd, 0, 1];
                let request_two = [request_type, 0, 0, 0, 0xab, 0xcd, 0, 2];
                let reply_two = [reply_type, 0, 0, 0, 0xab, 0xcd, 0, 2];
                let expected = observation_l4_correlation(
                    protocol,
                    version,
                    GtpuTrafficObservationDirection::AccessToCore,
                    request_one,
                );
                assert_eq!(
                    expected,
                    observation_l4_correlation(
                        protocol,
                        version,
                        GtpuTrafficObservationDirection::CoreToAccess,
                        reply_one,
                    )
                );
                assert_eq!(
                    expected,
                    observation_l4_correlation(
                        protocol,
                        version,
                        GtpuTrafficObservationDirection::AccessToCore,
                        request_two,
                    )
                );
                assert_eq!(
                    expected,
                    observation_l4_correlation(
                        protocol,
                        version,
                        GtpuTrafficObservationDirection::CoreToAccess,
                        reply_two,
                    )
                );
            }
        }

        #[test]
        fn observation_ipv4_transport_shape_rejects_malformed_and_accepts_valid() {
            let mut tcp = vec![0_u8; 20];
            tcp[0..4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
            tcp[12] = 0x50;
            assert!(modeled_ipv4_observation_key(
                &modeled_ipv4_packet(IPPROTO_TCP, &tcp),
                GtpuTrafficObservationDirection::AccessToCore,
            )
            .is_some());
            let mut bad_tcp_offset = modeled_ipv4_packet(IPPROTO_TCP, &tcp);
            bad_tcp_offset[20 + 12] = 0x40;
            assert!(modeled_ipv4_observation_key(
                &bad_tcp_offset,
                GtpuTrafficObservationDirection::AccessToCore,
            )
            .is_none());
            let truncated_tcp = modeled_ipv4_packet(IPPROTO_TCP, &tcp[..8]);
            assert!(modeled_ipv4_observation_key(
                &truncated_tcp,
                GtpuTrafficObservationDirection::AccessToCore,
            )
            .is_none());

            let mut udp = vec![0_u8; 8];
            udp[0..4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
            udp[4..6].copy_from_slice(&8_u16.to_be_bytes());
            assert!(modeled_ipv4_observation_key(
                &modeled_ipv4_packet(IPPROTO_UDP, &udp),
                GtpuTrafficObservationDirection::AccessToCore,
            )
            .is_some());
            let mut udp_zero = modeled_ipv4_packet(IPPROTO_UDP, &udp);
            udp_zero[20 + 4..20 + 6].copy_from_slice(&0_u16.to_be_bytes());
            assert!(modeled_ipv4_observation_key(
                &udp_zero,
                GtpuTrafficObservationDirection::AccessToCore,
            )
            .is_none());
            let mut udp_mismatch = modeled_ipv4_packet(IPPROTO_UDP, &udp);
            udp_mismatch[20 + 4..20 + 6].copy_from_slice(&9_u16.to_be_bytes());
            assert!(modeled_ipv4_observation_key(
                &udp_mismatch,
                GtpuTrafficObservationDirection::AccessToCore,
            )
            .is_none());

            let echo = [8, 0, 0, 0, 0xab, 0xcd, 0, 1];
            assert!(modeled_ipv4_observation_key(
                &modeled_ipv4_packet(IPPROTO_ICMP, &echo),
                GtpuTrafficObservationDirection::AccessToCore,
            )
            .is_some());
            let mut nonzero_code = modeled_ipv4_packet(IPPROTO_ICMP, &echo);
            nonzero_code[20 + 1] = 1;
            assert!(modeled_ipv4_observation_key(
                &nonzero_code,
                GtpuTrafficObservationDirection::AccessToCore,
            )
            .is_none());
            let truncated_echo = modeled_ipv4_packet(IPPROTO_ICMP, &echo[..7]);
            assert!(modeled_ipv4_observation_key(
                &truncated_echo,
                GtpuTrafficObservationDirection::AccessToCore,
            )
            .is_none());

            let mut ipv6_bad_code =
                modeled_ipv6_packet(IPPROTO_ICMPV6, &[], [128, 0, 0, 0, 0xab, 0xcd, 0, 1]);
            ipv6_bad_code[40 + 1] = 1;
            assert!(modeled_ipv6_observation_key(
                &ipv6_bad_code,
                GtpuTrafficObservationDirection::AccessToCore,
            )
            .is_none());
            let mut ipv6_truncated =
                modeled_ipv6_packet(IPPROTO_ICMPV6, &[], [128, 0, 0, 0, 0xab, 0xcd, 0, 1]);
            ipv6_truncated[4..6].copy_from_slice(&7_u16.to_be_bytes());
            assert!(modeled_ipv6_observation_key(
                &ipv6_truncated,
                GtpuTrafficObservationDirection::AccessToCore,
            )
            .is_none());
        }

        #[test]
        fn observation_ipv6_uses_bounded_shared_walker_and_rejects_fragments() {
            // Mutation guard: removing the configured fragment rejection or
            // returning to the fixed IPv6+40 L4 offset breaks this source test.
            let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
            let (_, observation) = source
                .split_once("fn observation_flow_key(")
                .expect("observation key is present");
            assert!(observation.contains("ipv6_l4_offset("));
            assert!(observation.contains("IPV6_TERMINAL_OBSERVATION, true"));
            let (_, walker) = source
                .split_once("fn ipv6_l4_offset(")
                .expect("shared IPv6 walker is present");
            assert!(walker.contains("classify_ipv6_extension_step"));
            assert!(walker.contains("context.reject_fragments != 0 && atomic_fragment"));
            assert!(walker.contains("context.walked >= IPV6_MAX_EXT_HEADERS as u32"));
        }
    }

    use opc_gtpu_ebpf_common::{
        GtpuSessionDeviceId, GtpuSessionGeneration, GtpuSessionGroupId,
        GtpuTrafficObservationBinding, GtpuTrafficObservationEvent,
    };

    fn challenge_registration(
        publication_id: u32,
        secret: [u8; 16],
    ) -> GtpuTrafficObservationRegistration {
        let binding = GtpuTrafficObservationBinding::new(
            GtpuSessionGroupId::new([0x11; 16]).expect("nonzero test group"),
            GtpuSessionDeviceId::new([0x22; 16]).expect("nonzero test device"),
            GtpuSessionGeneration::new(7).expect("nonzero test generation"),
        );
        GtpuTrafficObservationRegistration::new(binding, 9, 11, [0x33; 16], publication_id, secret)
            .expect("valid test registration")
    }

    fn modeled_challenge_sample(
        packet: &mut [u8],
        direction: GtpuTrafficObservationDirection,
        registration: GtpuTrafficObservationRegistration,
    ) -> Option<u32> {
        let (version, protocol, l4_offset) = match *packet.first()? >> 4 {
            4 => {
                let header_len = usize::from(packet.first()? & 0x0f).checked_mul(4)?;
                let total_len = usize::from(u16::from_be_bytes([*packet.get(2)?, *packet.get(3)?]));
                let fragment = u16::from_be_bytes([*packet.get(6)?, *packet.get(7)?]);
                if header_len < IPV4_MIN_HDR_LEN
                    || total_len != packet.len()
                    || fragment & IPV4_FRAG_MASK != 0
                {
                    return None;
                }
                (4, *packet.get(9)?, header_len)
            }
            6 => {
                let payload_len =
                    usize::from(u16::from_be_bytes([*packet.get(4)?, *packet.get(5)?]));
                if IPV6_HDR_LEN.checked_add(payload_len)? != packet.len() {
                    return None;
                }
                (6, *packet.get(6)?, IPV6_HDR_LEN)
            }
            _ => return None,
        };
        if packet.len().checked_sub(l4_offset)?
            != 8 + GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN
        {
            return None;
        }
        let icmp = packet.get(l4_offset..l4_offset.checked_add(8)?)?;
        if icmp[1] != 0 {
            return None;
        }
        let checksum_is_valid = match version {
            4 => {
                internet_checksum(packet.get(..l4_offset)?) == 0
                    && internet_checksum(packet.get(l4_offset..)?) == 0
            }
            6 => {
                let mut checksum_input = Vec::with_capacity(40 + packet.len() - l4_offset);
                checksum_input.extend_from_slice(packet.get(8..24)?);
                checksum_input.extend_from_slice(packet.get(24..40)?);
                checksum_input.extend_from_slice(
                    &u32::try_from(packet.len() - l4_offset).ok()?.to_be_bytes(),
                );
                checksum_input.extend_from_slice(&[0, 0, 0, IPPROTO_ICMPV6]);
                checksum_input.extend_from_slice(packet.get(l4_offset..)?);
                internet_checksum(&checksum_input) == 0
            }
            _ => false,
        };
        if !checksum_is_valid {
            return None;
        }
        let identifier = u16::from_be_bytes([icmp[4], icmp[5]]);
        let sequence = u16::from_be_bytes([icmp[6], icmp[7]]);
        let payload = packet.get(l4_offset.checked_add(8)?..)?.try_into().ok()?;
        let encoded = registration.encode();
        match (direction, version, protocol, icmp[0]) {
            (GtpuTrafficObservationDirection::CoreToAccess, 4, IPPROTO_ICMP, 8)
            | (GtpuTrafficObservationDirection::CoreToAccess, 6, IPPROTO_ICMPV6, 128) => {
                let sample =
                    GtpuTrafficObservationRegistration::encoded_icmp_echo_request_sample_if_valid(
                        &encoded, identifier, sequence, &payload,
                    )?;
                let response = GtpuTrafficObservationRegistration::encoded_icmp_echo_response_payload_if_request_valid(
                    &encoded,
                    identifier,
                    sequence,
                    &payload,
                )?;
                packet[l4_offset + 8..].copy_from_slice(&response);
                packet[l4_offset + 2..l4_offset + 4].fill(0);
                let checksum = modeled_icmp_checksum(packet, version, l4_offset)?;
                packet[l4_offset + 2..l4_offset + 4].copy_from_slice(&checksum.to_be_bytes());
                let rewritten = packet.get(l4_offset + 8..)?.try_into().ok()?;
                (modeled_icmp_checksum_is_valid(packet, version, l4_offset)
                    && GtpuTrafficObservationRegistration::encoded_icmp_echo_reply_sample_if_valid(
                        &encoded, identifier, sequence, &rewritten,
                    ) == Some(sample))
                .then_some(sample)
            }
            (GtpuTrafficObservationDirection::AccessToCore, 4, IPPROTO_ICMP, 0)
            | (GtpuTrafficObservationDirection::AccessToCore, 6, IPPROTO_ICMPV6, 129) => {
                GtpuTrafficObservationRegistration::encoded_icmp_echo_reply_sample_if_valid(
                    &encoded, identifier, sequence, &payload,
                )
            }
            _ => None,
        }
    }

    fn modeled_icmp_checksum(packet: &[u8], version: u8, l4_offset: usize) -> Option<u16> {
        let mut input = Vec::with_capacity(40 + packet.len() - l4_offset);
        if version == 6 {
            input.extend_from_slice(packet.get(8..24)?);
            input.extend_from_slice(packet.get(24..40)?);
            input.extend_from_slice(&u32::try_from(packet.len() - l4_offset).ok()?.to_be_bytes());
            input.extend_from_slice(&[0, 0, 0, IPPROTO_ICMPV6]);
        }
        input.extend_from_slice(packet.get(l4_offset..)?);
        let checksum = internet_checksum(&input);
        Some(if version == 6 && checksum == 0 {
            u16::MAX
        } else {
            checksum
        })
    }

    fn modeled_icmp_checksum_is_valid(packet: &[u8], version: u8, l4_offset: usize) -> bool {
        if version == 4 {
            internet_checksum(&packet[l4_offset..]) == 0
        } else if version == 6 {
            let mut input = Vec::with_capacity(40 + packet.len() - l4_offset);
            input.extend_from_slice(&packet[8..24]);
            input.extend_from_slice(&packet[24..40]);
            input.extend_from_slice(
                &u32::try_from(packet.len() - l4_offset)
                    .unwrap()
                    .to_be_bytes(),
            );
            input.extend_from_slice(&[0, 0, 0, IPPROTO_ICMPV6]);
            input.extend_from_slice(&packet[l4_offset..]);
            internet_checksum(&input) == 0
        } else {
            false
        }
    }

    fn refresh_modeled_icmp_checksum(packet: &mut [u8], version: u8, l4_offset: usize) {
        packet[l4_offset + 2..l4_offset + 4].fill(0);
        let checksum = modeled_icmp_checksum(packet, version, l4_offset).expect("fixed packet");
        packet[l4_offset + 2..l4_offset + 4].copy_from_slice(&checksum.to_be_bytes());
    }

    fn modeled_challenge_packet(version: u8, icmp_type: u8, payload: [u8; 32]) -> Vec<u8> {
        let (header_len, protocol) = match version {
            4 => (IPV4_MIN_HDR_LEN, IPPROTO_ICMP),
            6 => (IPV6_HDR_LEN, IPPROTO_ICMPV6),
            _ => unreachable!("test family is fixed"),
        };
        let mut packet = vec![0_u8; header_len + 8 + payload.len()];
        match version {
            4 => {
                let total_len = u16::try_from(packet.len()).expect("test packet fits");
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&total_len.to_be_bytes());
                packet[9] = protocol;
            }
            6 => {
                let payload_len =
                    u16::try_from(packet.len() - IPV6_HDR_LEN).expect("test packet fits");
                packet[0] = 0x60;
                packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
                packet[6] = protocol;
            }
            _ => unreachable!("test family is fixed"),
        }
        packet[header_len] = icmp_type;
        let sample_id = u32::from_be_bytes(payload[12..16].try_into().expect("sample ID"));
        packet[header_len + 4..header_len + 8].copy_from_slice(&[
            (sample_id >> 24) as u8,
            (sample_id >> 16) as u8,
            (sample_id >> 8) as u8,
            sample_id as u8,
        ]);
        packet[header_len + 8..].copy_from_slice(&payload);
        let transport_checksum = match version {
            4 => internet_checksum(&packet[header_len..]),
            6 => {
                let mut checksum_input = Vec::with_capacity(40 + packet.len() - header_len);
                checksum_input.extend_from_slice(&packet[8..24]);
                checksum_input.extend_from_slice(&packet[24..40]);
                checksum_input.extend_from_slice(
                    &u32::try_from(packet.len() - header_len)
                        .expect("test packet fits")
                        .to_be_bytes(),
                );
                checksum_input.extend_from_slice(&[0, 0, 0, IPPROTO_ICMPV6]);
                checksum_input.extend_from_slice(&packet[header_len..]);
                internet_checksum(&checksum_input)
            }
            _ => unreachable!("test family is fixed"),
        };
        packet[header_len + 2..header_len + 4].copy_from_slice(&transport_checksum.to_be_bytes());
        if version == 4 {
            let header_checksum = internet_checksum(&packet[..header_len]);
            packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
        }
        packet
    }

    #[test]
    fn authenticated_challenges_are_the_only_observation_inputs_for_both_families() {
        for (version, request_type, reply_type) in [(4, 8, 0), (6, 128, 129)] {
            let registration = challenge_registration(17, [0x44; 16]);
            let request = registration
                .icmp_echo_challenge_payload(23)
                .expect("nonzero sample");
            let mut downlink = modeled_challenge_packet(version, request_type, request);
            assert_eq!(
                modeled_challenge_sample(
                    &mut downlink,
                    GtpuTrafficObservationDirection::CoreToAccess,
                    registration,
                ),
                Some(23)
            );
            assert!(modeled_icmp_checksum_is_valid(
                &downlink,
                version,
                if version == 4 {
                    IPV4_MIN_HDR_LEN
                } else {
                    IPV6_HDR_LEN
                },
            ));
            let response: [u8; 32] = downlink[if version == 4 {
                IPV4_MIN_HDR_LEN
            } else {
                IPV6_HDR_LEN
            } + 8..]
                .try_into()
                .expect("exact response payload");
            assert_ne!(request, response);
            let mut reply = modeled_challenge_packet(version, reply_type, response);
            assert_eq!(
                modeled_challenge_sample(
                    &mut reply,
                    GtpuTrafficObservationDirection::AccessToCore,
                    registration,
                ),
                Some(23)
            );
        }
    }

    #[test]
    fn private_reply_domain_rejects_reflection_and_identifier_sequence_mutation() {
        for (version, request_type, reply_type) in [(4, 8, 0), (6, 128, 129)] {
            let registration = challenge_registration(17, [0x44; 16]);
            let request = registration
                .icmp_echo_challenge_payload(0x0123_4567)
                .expect("nonzero sample");
            let l4_offset = if version == 4 {
                IPV4_MIN_HDR_LEN
            } else {
                IPV6_HDR_LEN
            };
            let mut reflected = modeled_challenge_packet(version, reply_type, request);
            assert_eq!(
                modeled_challenge_sample(
                    &mut reflected,
                    GtpuTrafficObservationDirection::AccessToCore,
                    registration,
                ),
                None,
            );

            let response = GtpuTrafficObservationRegistration::encoded_icmp_echo_response_payload_if_request_valid(
                &registration.encode(),
                0x0123,
                0x4567,
                &request,
            )
            .expect("request validates");
            assert_ne!(request, response);
            let mut response_as_request = modeled_challenge_packet(version, request_type, response);
            assert_eq!(
                modeled_challenge_sample(
                    &mut response_as_request,
                    GtpuTrafficObservationDirection::CoreToAccess,
                    registration,
                ),
                None,
            );

            let mut wrong_identifier = modeled_challenge_packet(version, reply_type, response);
            wrong_identifier[l4_offset + 4] ^= 1;
            refresh_modeled_icmp_checksum(&mut wrong_identifier, version, l4_offset);
            assert_eq!(
                modeled_challenge_sample(
                    &mut wrong_identifier,
                    GtpuTrafficObservationDirection::AccessToCore,
                    registration,
                ),
                None,
            );

            let mut wrong_sequence = modeled_challenge_packet(version, reply_type, response);
            wrong_sequence[l4_offset + 7] ^= 1;
            refresh_modeled_icmp_checksum(&mut wrong_sequence, version, l4_offset);
            assert_eq!(
                modeled_challenge_sample(
                    &mut wrong_sequence,
                    GtpuTrafficObservationDirection::AccessToCore,
                    registration,
                ),
                None,
            );
        }
    }

    #[test]
    fn challenge_observations_require_valid_network_and_transport_checksums() {
        let registration = challenge_registration(17, [0x44; 16]);
        let payload = registration
            .icmp_echo_challenge_payload(23)
            .expect("nonzero sample");

        let mut bad_ipv4_header = modeled_challenge_packet(4, 8, payload);
        bad_ipv4_header[10] ^= 1;
        assert_eq!(
            modeled_challenge_sample(
                &mut bad_ipv4_header,
                GtpuTrafficObservationDirection::CoreToAccess,
                registration,
            ),
            None,
        );

        let mut bad_icmpv4 = modeled_challenge_packet(4, 8, payload);
        bad_icmpv4[IPV4_MIN_HDR_LEN + 2] ^= 1;
        assert_eq!(
            modeled_challenge_sample(
                &mut bad_icmpv4,
                GtpuTrafficObservationDirection::CoreToAccess,
                registration,
            ),
            None,
        );

        let mut bad_icmpv6 = modeled_challenge_packet(6, 128, payload);
        bad_icmpv6[IPV6_HDR_LEN + 2] ^= 1;
        assert_eq!(
            modeled_challenge_sample(
                &mut bad_icmpv6,
                GtpuTrafficObservationDirection::CoreToAccess,
                registration,
            ),
            None,
        );

        let mut wrong_ipv6_pseudo_header = modeled_challenge_packet(6, 128, payload);
        wrong_ipv6_pseudo_header[8] ^= 1;
        assert_eq!(
            modeled_challenge_sample(
                &mut wrong_ipv6_pseudo_header,
                GtpuTrafficObservationDirection::CoreToAccess,
                registration,
            ),
            None,
        );
    }

    #[test]
    fn malformed_or_unrelated_traffic_never_yields_a_challenge_sample() {
        let registration = challenge_registration(17, [0x44; 16]);
        let payload = registration
            .icmp_echo_challenge_payload(23)
            .expect("nonzero sample");
        for version in [4, 6] {
            let request_type = if version == 4 { 8 } else { 128 };
            let mut wrong_tag = modeled_challenge_packet(version, request_type, payload);
            *wrong_tag.last_mut().expect("payload exists") ^= 1;
            assert_eq!(
                modeled_challenge_sample(
                    &mut wrong_tag,
                    GtpuTrafficObservationDirection::AccessToCore,
                    registration
                ),
                None
            );

            let mut code = modeled_challenge_packet(version, request_type, payload);
            code[if version == 4 {
                IPV4_MIN_HDR_LEN
            } else {
                IPV6_HDR_LEN
            } + 1] = 1;
            assert_eq!(
                modeled_challenge_sample(
                    &mut code,
                    GtpuTrafficObservationDirection::AccessToCore,
                    registration
                ),
                None
            );

            let mut trailer = modeled_challenge_packet(version, request_type, payload);
            trailer.push(0);
            assert_eq!(
                modeled_challenge_sample(
                    &mut trailer,
                    GtpuTrafficObservationDirection::AccessToCore,
                    registration
                ),
                None
            );

            let mut duplicated_payload = modeled_challenge_packet(version, request_type, payload);
            duplicated_payload.extend_from_slice(&payload);
            if version == 4 {
                let total_len = u16::try_from(duplicated_payload.len()).expect("test packet fits");
                duplicated_payload[2..4].copy_from_slice(&total_len.to_be_bytes());
            } else {
                let payload_len = u16::try_from(duplicated_payload.len() - IPV6_HDR_LEN)
                    .expect("test packet fits");
                duplicated_payload[4..6].copy_from_slice(&payload_len.to_be_bytes());
            }
            assert_eq!(
                modeled_challenge_sample(
                    &mut duplicated_payload,
                    GtpuTrafficObservationDirection::AccessToCore,
                    registration
                ),
                None
            );

            let mut malformed = modeled_challenge_packet(version, request_type, payload);
            if version == 4 {
                malformed[2..4].copy_from_slice(&39_u16.to_be_bytes());
            } else {
                malformed[4..6].copy_from_slice(&39_u16.to_be_bytes());
            }
            assert_eq!(
                modeled_challenge_sample(
                    &mut malformed,
                    GtpuTrafficObservationDirection::AccessToCore,
                    registration
                ),
                None
            );

            let mut wrong_type = modeled_challenge_packet(version, request_type, payload);
            wrong_type[if version == 4 {
                IPV4_MIN_HDR_LEN
            } else {
                IPV6_HDR_LEN
            }] = 3;
            assert_eq!(
                modeled_challenge_sample(
                    &mut wrong_type,
                    GtpuTrafficObservationDirection::AccessToCore,
                    registration
                ),
                None
            );
        }

        let mut ipv4_fragment = modeled_challenge_packet(4, 8, payload);
        ipv4_fragment[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        assert_eq!(
            modeled_challenge_sample(
                &mut ipv4_fragment,
                GtpuTrafficObservationDirection::AccessToCore,
                registration
            ),
            None
        );

        let mut request = modeled_challenge_packet(4, 8, payload);
        let mut tuple_correlated = request.clone();
        tuple_correlated[9] = IPPROTO_TCP;
        assert_eq!(
            modeled_challenge_sample(
                &mut tuple_correlated,
                GtpuTrafficObservationDirection::AccessToCore,
                registration
            ),
            None
        );
        let stale_registration = challenge_registration(18, [0x44; 16]);
        assert_eq!(
            modeled_challenge_sample(
                &mut request,
                GtpuTrafficObservationDirection::AccessToCore,
                stale_registration
            ),
            None
        );
        assert_eq!(
            modeled_challenge_sample(
                &mut request,
                GtpuTrafficObservationDirection::AccessToCore,
                registration
            ),
            None
        );
    }

    #[test]
    fn challenge_events_keep_sample_ids_and_one_registration_stream_correlation() {
        let registration = challenge_registration(17, [0x44; 16]);
        let first = registration
            .icmp_echo_challenge_payload(23)
            .expect("nonzero sample");
        let second = registration
            .icmp_echo_challenge_payload(24)
            .expect("nonzero sample");
        let mut first_request = modeled_challenge_packet(4, 8, first);
        assert_eq!(
            modeled_challenge_sample(
                &mut first_request,
                GtpuTrafficObservationDirection::CoreToAccess,
                registration
            ),
            Some(23)
        );
        let mut second_request = modeled_challenge_packet(6, 128, second);
        assert_eq!(
            modeled_challenge_sample(
                &mut second_request,
                GtpuTrafficObservationDirection::CoreToAccess,
                registration
            ),
            Some(24)
        );
        let stream = registration.challenge_stream_correlation_id();
        let first_event = GtpuTrafficObservationEvent::new(
            registration,
            stream,
            23,
            GtpuTrafficObservationDirection::AccessToCore,
            1,
            1,
        )
        .expect("valid event");
        let second_event = GtpuTrafficObservationEvent::new(
            registration,
            stream,
            24,
            GtpuTrafficObservationDirection::CoreToAccess,
            2,
            2,
        )
        .expect("valid event");
        assert_eq!(first_event.sample_id(), 23);
        assert_eq!(second_event.sample_id(), 24);
        assert_eq!(first_event.correlation_id(), second_event.correlation_id());
    }

    #[test]
    fn challenge_producer_source_contract_excludes_generic_flow_emission() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
        assert!(source.contains(
            "#[inline(always)]\nfn observation_challenge_sample<const CORE_TO_ACCESS: bool>("
        ));
        let (_, producer) = source
            .split_once("fn observation_challenge_sample<const CORE_TO_ACCESS: bool>(")
            .expect("challenge orchestrator is present");
        let (producer, _) = producer
            .split_once("/// Parse and checksum one fixed observation packet")
            .expect("challenge orchestrator terminator is present");
        let parse = producer
            .find("validated_observation_icmp_echo::<CORE_TO_ACCESS>")
            .expect("exact packet parser runs first");
        let authenticate = producer
            .find("authenticate_observation_icmp_echo::<CORE_TO_ACCESS>")
            .expect("packet authentication follows parsing");
        let rewrite = producer
            .find("rewrite_authenticated_observation_icmp_echo_request(")
            .expect("authenticated downlink request is rewritten");
        assert!(parse < authenticate);
        assert!(authenticate < rewrite);
        assert!(producer.contains("if CORE_TO_ACCESS"));

        let (_, validator) = source
            .split_once("fn try_validated_observation_icmp_echo<const CORE_TO_ACCESS: bool>(")
            .expect("challenge validator is present");
        let (validator, _) = validator
            .split_once("/// Authenticate a packet")
            .expect("challenge validator terminator is present");
        assert!(validator.contains("ip_end != ctx.len() as usize"));
        assert!(validator.contains(
            "transport_len != 8 + GTPU_TRAFFIC_OBSERVATION_ICMP_ECHO_CHALLENGE_PAYLOAD_LEN"
        ));
        assert!(validator.contains("IPV6_TERMINAL_OBSERVATION, true"));
        assert!(validator.contains("observation_icmp_checksum_40_is_valid("));
        assert!(validator.contains("observation_icmpv6_checksum_is_valid("));
        let (_, fixed_ipv4_checksum) = source
            .split_once("fn observation_icmp_checksum_40_is_valid(")
            .expect("fixed observation checksum helper is present");
        let (fixed_ipv4_checksum, _) = fixed_ipv4_checksum
            .split_once("fn observation_icmpv6_checksum_is_valid(")
            .expect("fixed checksum helper terminator is present");
        assert!(fixed_ipv4_checksum.contains("MaybeUninit::<[u8; 40]>::uninit()"));
        assert!(fixed_ipv4_checksum.contains("bpf_skb_load_bytes("));
        assert!(fixed_ipv4_checksum.contains("bpf_csum_diff("));
        assert!(fixed_ipv4_checksum.contains("            seed,"));
        assert!(!fixed_ipv4_checksum.contains("checksum_skb_region("));
        let (_, ipv6_pseudo_checksum) = source
            .split_once("fn observation_icmpv6_pseudo_sum(")
            .expect("fixed ICMPv6 pseudo-header helper is present");
        let (ipv6_pseudo_checksum, _) = ipv6_pseudo_checksum
            .split_once("fn software_udp_checksum_is_valid(")
            .expect("fixed ICMPv6 pseudo-header helper terminator is present");
        assert!(ipv6_pseudo_checksum.contains("core::mem::size_of_val(&pseudo_header) as u32"));
        assert!(!ipv6_pseudo_checksum.contains("pseudo_header.len() as u32"));
        let (_, walker) = source
            .split_once("fn ipv6_l4_offset(")
            .expect("shared IPv6 walker is present");
        assert!(walker.contains("context.reject_fragments != 0 && atomic_fragment"));
        let active_source = source
            .split("    #[cfg(any())]")
            .next()
            .expect("source prefix");
        assert!(!active_source.contains("fn observation_flow_key("));
        assert!(!active_source.contains("encoded_correlation_half("));
        assert!(!active_source.contains("struct ObservationIcmpEchoRewrite"));
        assert!(!active_source.contains("fn rewrite_observation_icmp_echo_request("));
        assert!(!active_source.contains("fn observation_icmp_checksum_for_payload("));

        let (_, writer) = source
            .split_once("fn try_emit_grouped_observation(")
            .expect("event writer is present");
        let (writer, publisher) = writer
            .split_once("fn publish_grouped_observation_event(")
            .expect("sample parser and ring publisher are separate frames");
        assert!(writer.contains("observation_challenge_sample"));
        assert!(writer.contains("publish_grouped_observation_event("));
        let (publisher, _) = publisher
            .split_once("/// Emit an uplink observation")
            .expect("ring publisher terminator is present");
        assert!(publisher.contains("write_current_event"));
    }

    #[test]
    fn grouped_uplink_observation_stamp_preserves_nonce_bytes_and_rejects_mutation() {
        let nonce = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
            0xdc, 0xfe,
        ];
        let stamp = grouped_observation_cb_stamp(nonce);
        assert_eq!(nonce_from_grouped_observation_cb_stamp(&stamp), Some(nonce));
        assert_eq!(nonce_from_grouped_observation_cb_stamp(&[0; 5]), None);

        let mut wrong_ownership = stamp;
        wrong_ownership[0] |= 1;
        assert_eq!(
            nonce_from_grouped_observation_cb_stamp(&wrong_ownership),
            None
        );

        let mut forged_nonce = stamp;
        forged_nonce[3] ^= 1;
        assert_ne!(
            nonce_from_grouped_observation_cb_stamp(&forged_nonce),
            Some(nonce)
        );
    }

    #[test]
    fn grouped_uplink_observation_control_buffer_stores_and_clears_all_nonce_words() {
        let nonce = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba,
            0xdc, 0xfe,
        ];
        let stamp = grouped_observation_cb_stamp(nonce);
        // SAFETY: Aya's generated context is a C-compatible aggregate of
        // integer and pointer fields; all-zeroes is a valid host test fixture.
        let mut skb: __sk_buff = unsafe { core::mem::zeroed() };
        let ctx = TcContext::new(&mut skb);

        store_grouped_uplink_observation_cb_stamp(&ctx, stamp);
        assert_eq!(skb.cb, stamp);
        assert_eq!(take_grouped_uplink_observation_stamp(&ctx), Some(nonce));
        assert_eq!(skb.cb, [0; 5]);

        store_grouped_uplink_observation_cb_stamp(&ctx, stamp);
        clear_unmatched_grouped_uplink_observation_stamp(&ctx);
        assert_eq!(skb.cb, [0; 5]);

        let unrelated = [0xfeed_cafe, 1, 2, 3, 4];
        skb.cb = unrelated;
        clear_unmatched_grouped_uplink_observation_stamp(&ctx);
        assert_eq!(skb.cb, unrelated);
    }

    #[test]
    fn grouped_control_buffer_context_accesses_remain_verifier_safe() {
        // Fix-removal guard for the real verifier failure observed on Linux
        // 6.8: ordinary adjacent zero stores were coalesced into `memset`
        // through a modified context pointer. Every owned cb access must stay
        // an explicit volatile operation rooted at the original context.
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
        let (_, context_accesses) = source
            .split_once("fn store_grouped_uplink_observation_cb_stamp(")
            .expect("control-buffer store helper is present");
        let (context_accesses, _) = context_accesses
            .split_once("/// Return the authenticated sample carried")
            .expect("control-buffer helper region has a terminator");
        let cb_accesses = context_accesses
            .lines()
            .filter(|line| line.contains("(*ctx.skb.skb).cb["))
            .collect::<Vec<_>>();

        assert_eq!(cb_accesses.len(), 16);
        assert!(cb_accesses.iter().all(|line| {
            line.contains("core::ptr::write_volatile") || line.contains("core::ptr::read_volatile")
        }));
        assert_eq!(
            context_accesses
                .matches("core::ptr::write_volatile")
                .count(),
            10
        );
        assert_eq!(
            context_accesses.matches("core::ptr::read_volatile").count(),
            6
        );
    }

    #[test]
    fn grouped_uplink_observation_waits_for_proven_redirect_reentry() {
        // The helper verdict only submits a redirect. Keep the event writer
        // out of that branch and reachable only after the pre-existing strict
        // outer-envelope re-entry proof has succeeded.
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
        let (_, completion) = source
            .split_once("fn complete_grouped_uplink(")
            .expect("grouped completion is present");
        let (completion, _) = completion
            .split_once("fn encapsulate_grouped_ipv6(")
            .expect("grouped completion terminator is present");
        let stamp = completion
            .find("stamp_grouped_uplink_observation(ctx, authority);")
            .expect("grouped redirect stamps opaque authority");
        let redirect = completion
            .find("bpf_redirect_neigh")
            .expect("grouped redirect is present");
        assert!(stamp < redirect);
        assert!(!completion.contains("emit_grouped_observation("));

        let (_, uplink) = source
            .split_once("pub fn opc_gtpu_uplink(mut ctx: TcContext)")
            .expect("uplink classifier is present");
        let (uplink, ordinary) = uplink
            .split_once("fn try_uplink(")
            .expect("ordinary uplink path remains a separate frame");
        let (ordinary, _) = ordinary
            .split_once("/// Run only the frozen IPv4 compatibility path")
            .expect("ordinary uplink path terminator is present");
        let reentry = uplink
            .find("if uplink_frame_is_redirect_reentry(&ctx, mark, eth_proto)")
            .expect("redirect re-entry proof is present");
        let emit = uplink
            .find("emit_grouped_uplink_observation_on_reentry(&ctx, eth_proto);")
            .expect("uplink event emission is on re-entry");
        let clear = uplink
            .find("clear_unmatched_grouped_uplink_observation_stamp(&ctx);")
            .expect("non-re-entry paths clear only matching internal stamps");
        assert!(reentry < emit);
        assert!(emit < clear);
        assert!(ordinary.starts_with("ctx: &mut TcContext, mut mark: u32, eth_proto: u16)"));
        assert!(!ordinary.contains("emit_grouped_uplink_observation_on_reentry"));
    }

    #[test]
    fn unstamped_or_wrong_nonce_reentry_cannot_select_observation_authority() {
        // An unprivileged sender cannot set tc scratch state. This structural
        // guard makes both a missing stamp and a mutated group ID stop before
        // an event can be written: the stamp is consumed, resolved through
        // redirect authority, and back-validated against the live nonce.
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
        let (_, reentry) = source
            .split_once("fn emit_grouped_uplink_observation_on_reentry")
            .expect("uplink re-entry event helper is present");
        let (reentry, _) = reentry
            .split_once("/// Return whether this frame is one of this datapath's own")
            .expect("uplink re-entry event helper terminator is present");
        assert!(
            reentry.contains("let Some(nonce) = take_grouped_uplink_observation_stamp(ctx) else")
        );
        assert!(reentry.contains("GTPU_OBS_REDIR.get_ptr(nonce)"));
        assert!(reentry.contains("GTPU_SESSIONS.get_ptr(group_key)"));
        assert!(reentry.contains("GtpuSessionAuthorityWireView::decode(authority)"));
        assert!(reentry.contains("!authority_view.matches_group_key(&group_key)"));
        assert!(reentry.contains("authority_view.phase() != Some(GtpuSessionGroupPhase::Active)"));
        assert!(reentry.contains("registration_nonce, publication_id"));
        assert!(reentry.contains("registration_nonce != nonce"));
        assert!(reentry.contains("emit_grouped_observation("));
    }

    #[test]
    fn forwarding_boundary_identity_fences_registration_replacement() {
        // Fix-removal guard: both directions capture an immutable publication
        // identity before delayed forwarding work, and the final writer must
        // compare that exact identity with the live map registration.
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
        let (_, capture) = source
            .split_once("fn current_observation_redirect_identity(")
            .expect("publication capture helper is present");
        let (capture, _) = capture
            .split_once("/// Store opaque grouped authority")
            .expect("publication capture helper terminator is present");
        assert!(capture.contains(
            "GtpuTrafficObservationRegistration::encoded_redirect_identity_if_current_authority("
        ));
        assert!(capture.contains("raw_registration,"));
        assert!(capture.contains("\n        authority,\n"));

        let (_, writer) = source
            .split_once("fn try_emit_grouped_observation(")
            .expect("observation writer is present");
        let (writer, _) = writer
            .split_once("/// Emit an uplink observation")
            .expect("observation writer terminator is present");
        assert!(writer
            .contains("GtpuTrafficObservationRegistrationWireView::decode_if_current_authority("));
        assert!(writer.contains("raw_registration,"));
        assert!(writer.contains("\n            authority_view,\n"));
        assert!(writer.contains("publication_id,"));

        for (start, end, family) in [
            (
                "fn handle_downlink_ipv6(",
                "/// Attempt the grouped IPv4 path",
                "IPv6",
            ),
            (
                "fn handle_grouped_downlink_ipv4(",
                "#[classifier]\npub fn opc_gtpu_uplink",
                "IPv4",
            ),
        ] {
            let (_, downlink) = source
                .split_once(start)
                .unwrap_or_else(|| panic!("grouped {family} downlink handler is present"));
            let (downlink, _) = downlink
                .split_once(end)
                .unwrap_or_else(|| panic!("grouped {family} downlink terminator is present"));
            let capture = downlink
                .find("current_observation_redirect_identity(observation_authority)")
                .unwrap_or_else(|| panic!("grouped {family} captures publication identity"));
            let mutation = downlink
                .find("decap_grouped_downlink(")
                .unwrap_or_else(|| panic!("grouped {family} performs delayed packet mutation"));
            let emit = downlink
                .find("emit_grouped_observation(")
                .unwrap_or_else(|| panic!("grouped {family} emits after successful forwarding"));
            assert!(
                capture < mutation,
                "grouped {family} captures before mutation"
            );
            assert!(mutation < emit, "grouped {family} publishes after mutation");
        }
    }

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
    fn successor_traffic_gate_passes_packets_before_exact_activation() {
        // A host unit test cannot execute a loaded tc classifier, so prove the
        // actual classifier-root contract directly: every disabled successor
        // incarnation returns before its first packet read, authority lookup,
        // redirect, drop, or packet mutation. The loader can activate only an
        // odd incarnation after the broker has admitted the exact receipt.
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
        for (classifier, terminator, first_packet_read) in [
            (
                "pub fn opc_gtpu_uplink(mut ctx: TcContext)",
                "#[classifier]\npub fn opc_gtpu_downlink",
                "let mark = packet_mark(&ctx);",
            ),
            (
                "pub fn opc_gtpu_downlink(mut ctx: TcContext)",
                "/// Uplink: inner IPv4 packet",
                "let Ok(ether_type) = ctx.load::<u16>(12)",
            ),
        ] {
            let (_, root) = source
                .split_once(classifier)
                .expect("tc classifier root is present");
            let (root, _) = root
                .split_once(terminator)
                .expect("tc classifier root has a bounded body");
            let root = root
                .trim_start()
                .strip_prefix('{')
                .expect("classifier body begins after its signature")
                .trim_start();
            assert!(root.starts_with("if !traffic_gate_allows_packet_effects()"));
            let first_effect = root
                .find(first_packet_read)
                .expect("packet-processing body is present");
            let gate = &root[..first_effect];
            assert!(gate.contains("return TC_ACT_OK;"));
            assert!(!gate.contains("bpf_redirect"));
            assert!(!gate.contains("TC_ACT_SHOT"));
            assert!(!gate.contains("bpf_skb_"));
        }

        // Missing, zero, and every even retained incarnation are inert; the
        // one activation transition is a distinct odd value.
        let gate = |value: u64| value != 0 && value & 1 == 1;
        assert!(!gate(0));
        assert!(!gate(2));
        assert!(gate(3));
        assert!(!gate(4));
    }

    #[test]
    fn uplink_classifier_precedes_all_authority_lookups() {
        // This source-level guard keeps the order explicit where a host test
        // cannot instantiate `TcContext`: redirect re-entry is terminal;
        // classifier selection (or a fail-closed drop) happens before the
        // grouped default selector and the legacy FAR selector; and a chosen
        // mark is stored before either selector can observe it.
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
        let (_, classifier_root) = source
            .split_once("pub fn opc_gtpu_uplink(mut ctx: TcContext)")
            .expect("uplink classifier root is present");
        let (classifier_root, uplink) = classifier_root
            .split_once("fn try_uplink(")
            .expect("try_uplink source is present");
        let redirect = classifier_root
            .find("if uplink_frame_is_redirect_reentry(&ctx, mark, eth_proto)")
            .expect("redirect re-entry check is present");
        let ordinary = classifier_root
            .find("match try_uplink(&mut ctx, mark, eth_proto)")
            .expect("ordinary uplink path is called after re-entry handling");
        let classifier = uplink
            .find("match classify_owned_tft_uplink(ctx)")
            .expect("TFT classifier is present");
        let selected_mark = uplink
            .find("mark = selected_mark;")
            .expect("selected TFT mark feeds later lookups");
        let persisted_mark = uplink
            .find("ctx.set_mark(mark);")
            .expect("selected TFT mark is written");
        let grouped = uplink
            .find("match grouped_uplink_authority(")
            .expect("grouped authority lookup is present");
        let legacy = uplink
            .find("let far_ptr = if mark == 0")
            .expect("legacy FAR lookup is present");

        assert!(redirect < ordinary);
        assert!(classifier < selected_mark);
        assert!(selected_mark < persisted_mark);
        assert!(persisted_mark < grouped);
        assert!(grouped < legacy);
        assert!(uplink.contains("TftClassifierUplinkResult::Absent => {}"));
        assert!(uplink.contains("TftClassifierUplinkResult::Drop => return Ok(TC_ACT_SHOT as i32)"));
    }

    #[test]
    fn tft_callback_defers_bearer_mark_resolution_until_after_bpf_loop() {
        // The host test cannot invoke a tc `bpf_loop` callback, so retain the
        // generated control-flow contract in source: the callback may retain
        // only a dense rank, and the mark is resolved from a fresh
        // metadata-bound lookup after the loop returns.
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
        let (_, callback) = source
            .split_once("unsafe extern \"C\" fn classify_tft_filter_step")
            .expect("TFT callback is present");
        let (callback, _) = callback
            .split_once("/// Classify one previously unmarked IPv4 packet")
            .expect("TFT callback terminator is present");
        let candidate_rank = callback
            .find("context.candidate_rank = index as u16;")
            .expect("candidate rank is stored in caller-owned context");
        let filter_key = callback
            .find("TftClassifierFilterKey::from_validated_meta")
            .expect("metadata-bound filter-key validation is present");
        let runtime_validation = callback
            .find("filter.is_runtime_valid_at(index as u8)")
            .expect("runtime filter validation is present");
        let packet_match = callback
            .find("tft_classifier_filter_matches(filter, &context.packet)")
            .expect("packet-filter match is present");
        let remember_match = callback
            .find("remember_tft_classifier_match(context);")
            .expect("rank-only selection commit is present");
        assert!(candidate_rank < filter_key);
        assert!(candidate_rank < runtime_validation);
        assert!(candidate_rank < packet_match);
        assert!(packet_match < remember_match);
        assert!(!callback.contains("bearer_mark()"));
        assert!(!callback.contains("evaluation_precedence"));

        let (_, classifier) = source
            .split_once("fn classify_owned_tft_uplink(ctx: &TcContext)")
            .expect("owned TFT classifier is present");
        let loop_call = classifier
            .find("bpf_loop(")
            .expect("bounded TFT loop is present");
        let selected_mark = classifier
            .find("selected_tft_classifier_mark(key, &meta, loop_context.selected_rank)")
            .expect("post-loop selected mark lookup is present");
        assert!(loop_call < selected_mark);
        assert!(classifier.contains("u32::from(meta.filter_count())"));
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
    fn owned_tft_ipv4_fragment_validation_rejects_reserved_mf_and_offsets_but_allows_df() {
        assert!(ipv4_owned_tft_fragment_is_unfragmented(0));
        assert!(ipv4_owned_tft_fragment_is_unfragmented(0x4000));
        assert!(!ipv4_owned_tft_fragment_is_unfragmented(0x8000));
        assert!(!ipv4_owned_tft_fragment_is_unfragmented(0x2000));
        assert!(!ipv4_owned_tft_fragment_is_unfragmented(0x0001));
    }

    #[test]
    fn grouped_ipv6_uplink_length_accepts_an_empty_no_next_header_packet() {
        assert_eq!(
            ipv6_inner_total_length(0x60, 0, IPV6_NH_NONE, IPV6_HDR_LEN),
            Some(IPV6_HDR_LEN)
        );
        assert_eq!(
            ipv6_inner_total_length(0x60, 8, IPV6_NH_UDP, IPV6_HDR_LEN + 8),
            Some(IPV6_HDR_LEN + 8)
        );
    }

    #[test]
    fn grouped_ipv6_downlink_length_accepts_an_empty_no_next_header_packet() {
        assert!(ipv6_inner_length_is_exact(
            0x60,
            0,
            IPV6_NH_NONE,
            IPV6_HDR_LEN
        ));
        assert!(ipv6_inner_length_is_exact(
            0x60,
            8,
            IPV6_NH_UDP,
            IPV6_HDR_LEN + 8
        ));
    }

    #[test]
    fn grouped_ipv6_inner_length_rejects_jumbograms_truncation_and_trailing_bytes() {
        assert!(ipv6_inner_total_length(0x40, 8, IPV6_NH_UDP, IPV6_HDR_LEN + 8).is_none());
        assert!(ipv6_inner_total_length(0x60, 0, IPV6_NH_HOP_BY_HOP, IPV6_HDR_LEN + 8).is_none());
        assert!(ipv6_inner_total_length(0x60, 0, IPV6_NH_NONE, IPV6_HDR_LEN + 1).is_none());
        assert!(ipv6_inner_total_length(0x60, 0, IPV6_NH_UDP, IPV6_HDR_LEN).is_none());
        assert!(ipv6_inner_total_length(0x60, 8, IPV6_NH_UDP, IPV6_HDR_LEN + 7).is_none());
        assert!(ipv6_inner_total_length(0x60, 8, IPV6_NH_UDP, IPV6_HDR_LEN + 9).is_none());
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
        assert_eq!(
            observation_icmp_checksum_bytes_from_helper_sum(helper_sum, 4),
            [0x97, 0x53]
        );
        assert_eq!(
            observation_icmp_checksum_bytes_from_helper_sum(helper_sum, 6),
            [0x97, 0x53]
        );
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
    fn grouped_ipv6_checksum_walk_has_an_isolated_header_frame() {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/main.rs"));
        assert!(source.contains("#[inline(never)]\nfn prepare_grouped_ipv6_encapsulation("));
        assert!(source.contains("#[inline(never)]\nfn checksum_packet_chunk<const LENGTH: usize>("));
        assert!(source.contains("#[inline(never)]\nfn ipv6_udp_pseudo_sum("));
        let (_, checksum_validator) = source
            .split_once("fn software_ipv6_udp_checksum_is_valid(")
            .expect("software IPv6/UDP checksum validator is present");
        let (checksum_validator, _) = checksum_validator
            .split_once("fn ipv6_udp_pseudo_sum(")
            .expect("IPv6/UDP pseudo-header helper follows its caller");
        assert!(checksum_validator.contains("ipv6_udp_pseudo_sum(ctx, udp_length)"));
        assert!(checksum_validator.contains("checksum_skb_region(ctx, udp_offset, udp_length"));
        assert!(!checksum_validator.contains("pseudo_header"));
        let (_, preparation) = source
            .split_once("fn prepare_grouped_ipv6_encapsulation(")
            .expect("grouped IPv6 preparation boundary is present");
        let (preparation, caller) = preparation
            .split_once("fn encapsulate_grouped_ipv6(")
            .expect("grouped IPv6 checksum caller follows preparation");
        let (caller, _) = caller
            .split_once("fn encapsulate_grouped_ipv4(")
            .expect("grouped IPv6 checksum caller terminator is present");

        assert!(preparation.contains("let mut pseudo_header = [0_u8; 40];"));
        assert!(preparation.contains("encap[40..42].copy_from_slice"));
        assert!(preparation.contains("encap.as_mut_ptr().add(IPV6_HDR_LEN)"));
        assert!(preparation.contains("Some(fixed_sum as u32)"));
        assert!(!caller.contains("pseudo_header"));

        let prepare = caller
            .find("prepare_grouped_ipv6_encapsulation(entry, inner_len, &mut encap)")
            .expect("fixed header and checksum seed are materialized together");
        let checksum = caller
            .find("checksum_skb_region(ctx, ETH_HDR_LEN, usize::from(inner_len), fixed_sum)")
            .expect("the complete inner packet is checksummed from the fixed seed");
        let materialize = caller
            .find("encap[46..48].copy_from_slice")
            .expect("final checksum is materialized in the prepared header");
        let store = caller
            .find("ctx.store(ETH_HDR_LEN, &encap, 0)")
            .expect("the prepared header is emitted");
        assert!(prepare < checksum);
        assert!(checksum < materialize);
        assert!(materialize < store);
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
