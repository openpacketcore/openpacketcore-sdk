//! Versioned XDP owner-map ABI and shared classification/verdict logic.
//!
//! This module is the single source of truth for the SWu XDP fast path:
//!
//! - the pinned owner-map key/value layouts, keyed by the canonical
//!   destination-scoped ownership key (destination address + routing domain +
//!   encapsulation + SPI context) defined by `opc-ipsec-lb`'s ownership model;
//! - the single-slot datapath configuration (self shard, routing domain,
//!   userspace-redirector hand-off interface) and the separate single-slot
//!   ownership fence generation (an aligned `u64` in its own map so
//!   generation advances are never torn against a concurrent reader);
//! - the per-verdict counter indices exported to userspace;
//! - the branch-bounded transport classification decision procedure and the
//!   owner-verdict decision, shared verbatim by the eBPF program and the
//!   host-side tests so both execute exactly the same rules.
//!
//! Nothing here carries IPsec key material: keys are packet-header routing
//! identities and values are owner identities plus ownership generations.
//!
//! # Kernel feature floor
//!
//! - Load/attach: Linux >= 5.4 with kernel BTF (`/sys/kernel/btf/vmlinux`),
//!   XDP, pinned maps (bpffs), per-CPU arrays, `bpf_redirect`, and
//!   `bpf_xdp_load_bytes`.
//! - Atomic program replacement: Linux >= 5.7 (`XDP_FLAGS_REPLACE` with
//!   `IFLA_XDP_EXPECTED_FD`) or >= 5.9 (`bpf_link_create`/`bpf_link_update`
//!   for XDP). The userspace loader enforces both floors with a typed error.
//!
//! # Fail-closed contract
//!
//! The XDP program never drops a packet. Every verdict is either `XDP_PASS`
//! (local stack, userspace slow path, or untouched non-SWu traffic) or
//! `XDP_REDIRECT` into the dedicated userspace-redirector hand-off interface
//! (counted only when the helper itself confirms `XDP_REDIRECT`; a redirect
//! failure fails closed to the slow path with the error counter). Map miss,
//! stale ownership generation, unclassifiable packets, and internal errors
//! all fall back to the userspace slow path with a distinct counter.
//!
//! # Deliberate divergence from the userspace classifier
//!
//! The fast path executes the same branch-bounded decision procedure for
//! direct, complete, unfragmented packets. It deliberately narrows the
//! userspace classifier's acceptance set in ways that are always fail-closed
//! (the packet reaches the same slow path, never a verdict the userspace
//! path would contradict):
//!
//! - any IP fragmentation (including initial fragments with MF set, which
//!   the userspace classifier accepts) is unclassifiable here;
//! - IPv6 extension-header order, duplication, AH alignment, and
//!   fragment-header reserved-bit validation are not reproduced: the walk
//!   only skips well-formed extension headers to find the terminal protocol;
//! - ICMP/ICMPv6 error quotes are not classified (they are ordinary
//!   pass-through traffic here, exactly where the userspace slow path sees
//!   them anyway).
//!
//! Equally deliberate: 802.1Q VLAN-tagged ingress bypasses steering entirely
//! (`ETH_P_8021Q` is not `ETH_P_IPV4`/`ETH_P_IPV6`), so tagged traffic passes
//! untouched to the stack — consistent with the userspace classifier, which
//! starts at the network layer, and never a drop.

use crate::{
    ESP_HEADER_PREFIX_LEN, IKEV2_EXCHANGE_IKE_SA_INIT, IKEV2_HDR_LEN, IKEV2_MAJOR_VERSION,
    NAT_T_KEEPALIVE, NON_ESP_MARKER, UDP_HDR_LEN, UDP_PORT_IKE, UDP_PORT_IKE_NATT,
};

/// IPv4 protocol number for UDP.
pub const IP_PROTOCOL_UDP: u8 = 17;
/// IPv4/IPv6 protocol number for native ESP (RFC 4303).
pub const IP_PROTOCOL_ESP: u8 = 50;

/// Maximum number of IPv6 extension headers inspected by the keyless parser.
///
/// The fixed bound keeps attacker-controlled extension chains from turning
/// classification into an unbounded per-packet loop. A packet exceeding the
/// bound is unclassifiable rather than partially interpreted.
pub const MAX_INGRESS_IPV6_EXTENSION_HEADERS: usize = 8;

/// Number of transport-header bytes the XDP program copies for classification.
///
/// Covers a UDP header (8) plus the RFC 3948 non-ESP marker (4) plus the fixed
/// IKEv2 header (28), which is the deepest discriminator the decision
/// procedure reads.
pub const XDP_TRANSPORT_PROBE_LEN: usize = 40;

/// Minimum allocatable ESP SPI; RFC 4303 reserves 0 through 255.
pub const MIN_ALLOCATABLE_ESP_SPI: u32 = 256;

/// Minimum kernel release for loading and attaching the XDP datapath.
///
/// Linux 5.4 is the first release exposing kernel BTF at
/// `/sys/kernel/btf/vmlinux` together with the XDP, map-pinning, per-CPU
/// array, and `bpf_redirect` features the program relies on.
pub const XDP_MIN_KERNEL_RELEASE: (u16, u16) = (5, 4);

/// Minimum kernel release for graceful atomic program replacement.
///
/// Atomic compare-and-replace of an attached XDP program needs
/// `XDP_FLAGS_REPLACE` with `IFLA_XDP_EXPECTED_FD` (Linux 5.7) or the XDP
/// `bpf_link` update path (Linux 5.9).
pub const XDP_MIN_KERNEL_REPLACE_RELEASE: (u16, u16) = (5, 7);

/// BPF map name: destination-scoped owner records.
pub const MAP_OWNERS: &str = "IPSEC_LB_OWNERS";
/// BPF map name: single-slot datapath configuration.
pub const MAP_CONFIG: &str = "IPSEC_LB_CONFIG";
/// BPF map name: single-slot ownership fence generation.
pub const MAP_FENCE: &str = "IPSEC_LB_FENCE";
/// BPF map name: per-CPU per-verdict counters.
pub const MAP_COUNTERS: &str = "IPSEC_LB_COUNTERS";
/// XDP program name.
pub const PROG_SWU_XDP: &str = "opc_ipsec_lb_xdp";

/// Fixed owner-map key byte length.
///
/// The key wraps the canonical ownership-key encoding: byte 0 is the canonical
/// length (1..=[`OWNERSHIP_KEY_MAX_ENCODED_BYTES`]), bytes 1.. carry the
/// canonical key, and the remainder is zero. The fixed width keeps the map
/// key type stable while the versioned canonical encoding inside it evolves.
pub const OWNER_KEY_LEN: usize = 64;
/// Owner-map value byte length.
pub const OWNER_VALUE_LEN: usize = 16;
/// Datapath config value byte length.
pub const CONFIG_VALUE_LEN: usize = 32;
/// Fence-map value byte length (one aligned `u64`).
pub const FENCE_VALUE_LEN: usize = 8;
/// Current datapath config ABI version.
///
/// Version 2 moved the ownership fence generation out of the config value
/// into its own aligned `u64` map (see [`MAP_FENCE`]); v1 configs are
/// rejected so a stale pinned config fails closed instead of being
/// misread.
pub const XDP_CONFIG_ABI_VERSION: u8 = 2;

/// Counter index: packets passed through untouched because they were not SWu
/// IKE/ESP traffic.
pub const COUNTER_PASS_NON_SWU: u32 = 0;
/// Counter index: packets whose fresh owner is this shard (local pass).
pub const COUNTER_LOCAL: u32 = 1;
/// Counter index: packets handed to the userspace redirector because a remote
/// shard is the fresh owner.
pub const COUNTER_REDIRECT: u32 = 2;
/// Counter index: classified packets with no owner-map entry (slow-path
/// hand-off).
pub const COUNTER_MISS: u32 = 3;
/// Counter index: packets whose owner-map entry is older than the configured
/// ownership fence generation (slow-path hand-off).
pub const COUNTER_STALE: u32 = 4;
/// Counter index: SWu-candidate packets the bounded parser could not classify
/// (slow-path hand-off).
pub const COUNTER_UNCLASSIFIABLE: u32 = 5;
/// Counter index: internal errors and invalid config/value encodings
/// (fail-closed slow-path hand-off).
pub const COUNTER_ERROR: u32 = 6;
/// Counter index: RFC 3948 one-octet NAT-T keepalives passed to the stack.
pub const COUNTER_NATT_KEEPALIVE: u32 = 7;
/// Number of counter slots.
pub const COUNTER_SLOTS: u32 = 8;

/// Magic prefix of the canonical ownership-key encoding.
pub const OWNERSHIP_KEY_MAGIC: [u8; 4] = *b"OPCO";
/// Version of the stable canonical ownership-key byte encoding.
pub const OWNERSHIP_KEY_ENCODING_VERSION: u8 = 1;
/// Maximum number of bytes in one canonical ownership key.
pub const OWNERSHIP_KEY_MAX_ENCODED_BYTES: usize = 59;

/// Canonical ownership-key kind: initial IKE exchange.
pub const OWNERSHIP_KIND_INITIAL_IKE: u8 = 1;
/// Canonical ownership-key kind: established IKE SA.
pub const OWNERSHIP_KIND_ESTABLISHED_IKE: u8 = 2;
/// Canonical ownership-key kind: inbound ESP Child SA.
pub const OWNERSHIP_KIND_ESP: u8 = 3;
/// Canonical address family: IPv4.
pub const OWNERSHIP_ADDR_FAMILY_IPV4: u8 = 4;
/// Canonical address family: IPv6.
pub const OWNERSHIP_ADDR_FAMILY_IPV6: u8 = 6;
/// Canonical ESP encapsulation: native IP protocol 50.
pub const OWNERSHIP_ESP_NATIVE: u8 = 1;
/// Canonical ESP encapsulation: RFC 3948 UDP-encapsulated ESP.
pub const OWNERSHIP_ESP_UDP_ENCAPSULATED: u8 = 2;

/// An IP address observed or configured at the public ingress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XdpIpAddress {
    /// IPv4 address octets.
    V4([u8; 4]),
    /// IPv6 address octets.
    V6([u8; 16]),
}

impl XdpIpAddress {
    #[inline(always)]
    fn family(self) -> u8 {
        match self {
            Self::V4(_) => OWNERSHIP_ADDR_FAMILY_IPV4,
            Self::V6(_) => OWNERSHIP_ADDR_FAMILY_IPV6,
        }
    }

    #[inline(always)]
    fn octets(self) -> ([u8; 16], usize) {
        match self {
            Self::V4(octets) => {
                let mut wide = [0_u8; 16];
                wide[..4].copy_from_slice(&octets);
                (wide, 4)
            }
            Self::V6(octets) => (octets, 16),
        }
    }
}

/// Transport identity extracted by the branch-bounded keyless classifier.
///
/// This mirrors the direct-ingress outcomes of the userspace classifier in
/// `opc-ipsec-lb`: the same port/marker/protocol branches produce the same
/// identity, or fail closed to `Unclassifiable` without guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XdpTransportClass {
    /// IKEv2 with a non-zero responder SPI (established SA).
    IkeEstablished {
        /// IKE initiator SPI.
        initiator_spi: u64,
        /// IKE responder SPI.
        responder_spi: u64,
    },
    /// Initial IKE_SA_INIT with a zero responder SPI.
    IkeInitial {
        /// IKE initiator SPI.
        initiator_spi: u64,
        /// Wire IKE exchange type discriminator.
        exchange: u8,
    },
    /// ESP (native or UDP-encapsulated) with an allocatable SPI.
    Esp {
        /// `OWNERSHIP_ESP_NATIVE` or `OWNERSHIP_ESP_UDP_ENCAPSULATED`.
        encapsulation: u8,
        /// Inbound ESP SPI.
        spi: u32,
    },
    /// RFC 3948 one-octet NAT traversal keepalive.
    NatKeepalive,
    /// Not SWu IKE/ESP traffic; pass to the normal stack untouched.
    NonSwu,
    /// An SWu candidate the bounded parser could not classify safely.
    Unclassifiable,
}

/// Fast-path verdict for one classified packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XdpVerdict {
    /// The fresh owner is this shard; pass to the local stack.
    Local,
    /// The fresh owner is a remote shard; hand the packet to the userspace
    /// redirector through the configured hand-off interface.
    RedirectHandoff,
    /// No owner-map entry exists; hand off to the userspace slow path.
    SlowPathMiss,
    /// The entry's ownership generation is older than the configured fence;
    /// hand off to the userspace slow path.
    SlowPathStale,
    /// Invalid map value or missing redirect channel; fail closed to the
    /// userspace slow path.
    SlowPathError,
}

/// XDP action code for a successful redirect (`XDP_REDIRECT`).
pub const XDP_ACTION_REDIRECT: u32 = 4;

/// Outcome of evaluating a `bpf_redirect` helper result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum XdpRedirectOutcome {
    /// The helper confirmed the redirect; count it and return its action.
    Redirected,
    /// The helper rejected the redirect (for example `XDP_ABORTED`); count
    /// the error and fail closed to the slow path instead of miscounting a
    /// phantom redirect.
    SlowPathError,
}

/// Evaluate a `bpf_redirect` helper return value.
///
/// Shared verbatim by the eBPF program and host-side tests. Note that some
/// kernels defer transmit failures past the helper return: on those the
/// helper reports `XDP_REDIRECT` even when the frame is later dropped by the
/// target driver. Attach-time validation of the hand-off interface (exists,
/// up, and distinct from the attached interface) is the enforceable guard
/// against that blind spot; this check covers the kernels that do report
/// synchronously.
#[must_use]
#[inline(always)]
pub const fn redirect_outcome(helper_result: u32) -> XdpRedirectOutcome {
    if helper_result == XDP_ACTION_REDIRECT {
        XdpRedirectOutcome::Redirected
    } else {
        XdpRedirectOutcome::SlowPathError
    }
}

/// Per-verdict counter index for one classified identity's verdict.
#[must_use]
#[inline(always)]
pub const fn verdict_counter(verdict: XdpVerdict) -> u32 {
    match verdict {
        XdpVerdict::Local => COUNTER_LOCAL,
        XdpVerdict::RedirectHandoff => COUNTER_REDIRECT,
        XdpVerdict::SlowPathMiss => COUNTER_MISS,
        XdpVerdict::SlowPathStale => COUNTER_STALE,
        XdpVerdict::SlowPathError => COUNTER_ERROR,
    }
}

/// Classify the transport identity of one direct ingress packet.
///
/// `protocol` is the terminal IP protocol (after any IPv6 extension walk).
/// `probe` holds the first transport bytes (starting at the UDP or ESP
/// header); it may be shorter than the datagram but the classifier only reads
/// fixed header prefixes. `available_len` is the number of transport bytes
/// actually present in the packet and `declared_transport_len` is the
/// transport length declared by the IP header. IP-level fragmentation must
/// already have been rejected by the caller, so the two lengths agree for a
/// well-formed packet.
///
/// The decision procedure is branch-bounded and mirrors the userspace
/// classifier exactly for direct packets:
///
/// - UDP/500 -> IKE;
/// - UDP/4500 with a zero non-ESP marker -> IKE; a nonzero first word ->
///   ESP-in-UDP (SPI extracted); a lone `0xff` byte -> NAT-T keepalive;
/// - IP protocol 50 -> native ESP (SPI extracted);
/// - any other protocol or port -> not SWu traffic.
#[must_use]
#[inline(always)]
pub fn classify_transport(
    protocol: u8,
    probe: &[u8],
    available_len: usize,
    declared_transport_len: usize,
) -> XdpTransportClass {
    match protocol {
        IP_PROTOCOL_ESP => classify_native_esp(probe, available_len),
        IP_PROTOCOL_UDP => classify_udp(probe, available_len, declared_transport_len),
        _ => XdpTransportClass::NonSwu,
    }
}

#[inline(always)]
fn classify_native_esp(probe: &[u8], available_len: usize) -> XdpTransportClass {
    if available_len < ESP_HEADER_PREFIX_LEN || probe.len() < ESP_HEADER_PREFIX_LEN {
        return XdpTransportClass::Unclassifiable;
    }
    let spi = u32::from_be_bytes([probe[0], probe[1], probe[2], probe[3]]);
    if spi < MIN_ALLOCATABLE_ESP_SPI {
        return XdpTransportClass::Unclassifiable;
    }
    XdpTransportClass::Esp {
        encapsulation: OWNERSHIP_ESP_NATIVE,
        spi,
    }
}

#[inline(always)]
fn classify_udp(
    probe: &[u8],
    available_len: usize,
    declared_transport_len: usize,
) -> XdpTransportClass {
    if probe.len() < UDP_HDR_LEN {
        return XdpTransportClass::Unclassifiable;
    }
    let declared_udp_len = usize::from(u16::from_be_bytes([probe[4], probe[5]]));
    // The packet is complete and unfragmented, so the UDP length must match
    // the IP-declared transport length exactly and be fully present.
    if declared_udp_len < UDP_HDR_LEN
        || declared_udp_len != declared_transport_len
        || declared_udp_len > available_len
    {
        return XdpTransportClass::Unclassifiable;
    }
    let payload_len = declared_udp_len - UDP_HDR_LEN;
    let probed_payload_len = payload_len.min(probe.len() - UDP_HDR_LEN);
    let payload = &probe[UDP_HDR_LEN..UDP_HDR_LEN + probed_payload_len];
    let destination_port = u16::from_be_bytes([probe[2], probe[3]]);
    match destination_port {
        UDP_PORT_IKE => classify_ike(payload, payload_len),
        UDP_PORT_IKE_NATT => classify_udp_4500(payload, payload_len),
        _ => XdpTransportClass::NonSwu,
    }
}

#[inline(always)]
fn classify_udp_4500(payload: &[u8], payload_len: usize) -> XdpTransportClass {
    if payload_len == NAT_T_KEEPALIVE_LEN {
        return match payload {
            [NAT_T_KEEPALIVE] => XdpTransportClass::NatKeepalive,
            _ => XdpTransportClass::Unclassifiable,
        };
    }
    if payload_len < NON_ESP_MARKER.len() {
        return XdpTransportClass::Unclassifiable;
    }
    if payload.len() < NON_ESP_MARKER.len() {
        return XdpTransportClass::Unclassifiable;
    }
    if payload[..NON_ESP_MARKER.len()] == NON_ESP_MARKER {
        let declared_ike_len = payload_len - NON_ESP_MARKER.len();
        if declared_ike_len == 0 {
            return XdpTransportClass::Unclassifiable;
        }
        return classify_ike(&payload[NON_ESP_MARKER.len()..], declared_ike_len);
    }
    if payload_len < ESP_HEADER_PREFIX_LEN || payload.len() < ESP_HEADER_PREFIX_LEN {
        return XdpTransportClass::Unclassifiable;
    }
    let spi = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if spi < MIN_ALLOCATABLE_ESP_SPI {
        return XdpTransportClass::Unclassifiable;
    }
    XdpTransportClass::Esp {
        encapsulation: OWNERSHIP_ESP_UDP_ENCAPSULATED,
        spi,
    }
}

#[inline(always)]
fn classify_ike(payload: &[u8], declared_ike_len: usize) -> XdpTransportClass {
    if payload.len() < IKEV2_HDR_LEN {
        return XdpTransportClass::Unclassifiable;
    }
    if payload[17] >> 4 != IKEV2_MAJOR_VERSION {
        return XdpTransportClass::Unclassifiable;
    }
    let ike_len = u32::from_be_bytes([payload[24], payload[25], payload[26], payload[27]]) as usize;
    if ike_len < IKEV2_HDR_LEN || ike_len != declared_ike_len {
        return XdpTransportClass::Unclassifiable;
    }
    let initiator_spi = u64::from_be_bytes([
        payload[0], payload[1], payload[2], payload[3], payload[4], payload[5], payload[6],
        payload[7],
    ]);
    if initiator_spi == 0 {
        return XdpTransportClass::Unclassifiable;
    }
    let responder_spi = u64::from_be_bytes([
        payload[8],
        payload[9],
        payload[10],
        payload[11],
        payload[12],
        payload[13],
        payload[14],
        payload[15],
    ]);
    if responder_spi == 0 {
        if payload[18] != IKEV2_EXCHANGE_IKE_SA_INIT {
            return XdpTransportClass::Unclassifiable;
        }
        return XdpTransportClass::IkeInitial {
            initiator_spi,
            exchange: payload[18],
        };
    }
    XdpTransportClass::IkeEstablished {
        initiator_spi,
        responder_spi,
    }
}

/// Length of the RFC 3948 one-octet NAT traversal keepalive.
pub const NAT_T_KEEPALIVE_LEN: usize = 1;

/// Build the fixed owner-map key for one classified identity.
///
/// The embedded canonical bytes are exactly the canonical ownership-key
/// encoding shared with `opc-ipsec-lb`'s `SessionOwnershipKey`, so an entry
/// installed by userspace for a session key is the entry the XDP program looks
/// up for a packet of that session. `source_port` is only meaningful for UDP
/// observations (the initial-IKE key carries the outer source tuple); pass 0
/// for native ESP.
#[must_use]
#[inline(always)]
pub fn ownership_map_key(
    class: &XdpTransportClass,
    source: XdpIpAddress,
    source_port: u16,
    destination: XdpIpAddress,
    routing_domain: u64,
) -> Option<[u8; OWNER_KEY_LEN]> {
    let mut key = [0_u8; OWNER_KEY_LEN];
    let body = &mut key[1..];
    let canonical_len = match *class {
        XdpTransportClass::IkeEstablished {
            initiator_spi,
            responder_spi,
        } => write_canonical_established_ike(
            body,
            destination,
            routing_domain,
            initiator_spi,
            responder_spi,
        ),
        XdpTransportClass::IkeInitial {
            initiator_spi,
            exchange,
        } => write_canonical_initial_ike(
            body,
            destination,
            routing_domain,
            source,
            source_port,
            initiator_spi,
            exchange,
        ),
        XdpTransportClass::Esp { encapsulation, spi } => {
            write_canonical_esp(body, destination, routing_domain, encapsulation, spi)
        }
        XdpTransportClass::NatKeepalive
        | XdpTransportClass::NonSwu
        | XdpTransportClass::Unclassifiable => return None,
    };
    key[0] = canonical_len as u8;
    Some(key)
}

/// Encode the canonical initial-IKE ownership key.
///
/// Layout: `OPCO` magic, encoding version, kind, destination (routing domain +
/// address), outer source (address + port), initiator SPI, exchange
/// discriminator. Returns the buffer and the used prefix length.
#[must_use]
#[inline(always)]
pub fn canonical_initial_ike_key(
    destination: XdpIpAddress,
    routing_domain: u64,
    source: XdpIpAddress,
    source_port: u16,
    initiator_spi: u64,
    exchange: u8,
) -> ([u8; OWNERSHIP_KEY_MAX_ENCODED_BYTES], usize) {
    let mut encoded = [0_u8; OWNERSHIP_KEY_MAX_ENCODED_BYTES];
    let len = write_canonical_initial_ike(
        &mut encoded,
        destination,
        routing_domain,
        source,
        source_port,
        initiator_spi,
        exchange,
    );
    (encoded, len)
}

/// Encode the canonical established-IKE ownership key.
#[must_use]
#[inline(always)]
pub fn canonical_established_ike_key(
    destination: XdpIpAddress,
    routing_domain: u64,
    initiator_spi: u64,
    responder_spi: u64,
) -> ([u8; OWNERSHIP_KEY_MAX_ENCODED_BYTES], usize) {
    let mut encoded = [0_u8; OWNERSHIP_KEY_MAX_ENCODED_BYTES];
    let len = write_canonical_established_ike(
        &mut encoded,
        destination,
        routing_domain,
        initiator_spi,
        responder_spi,
    );
    (encoded, len)
}

/// Encode the canonical inbound-ESP ownership key.
#[must_use]
#[inline(always)]
pub fn canonical_esp_key(
    destination: XdpIpAddress,
    routing_domain: u64,
    encapsulation: u8,
    spi: u32,
) -> ([u8; OWNERSHIP_KEY_MAX_ENCODED_BYTES], usize) {
    let mut encoded = [0_u8; OWNERSHIP_KEY_MAX_ENCODED_BYTES];
    let len = write_canonical_esp(
        &mut encoded,
        destination,
        routing_domain,
        encapsulation,
        spi,
    );
    (encoded, len)
}

/// Write the canonical initial-IKE ownership key into `buf`, returning the
/// encoded length. `buf` must be at least the variant's fixed width; callers
/// pass an [`OWNERSHIP_KEY_MAX_ENCODED_BYTES`]-sized buffer (or the owner-map
/// key body, which is larger).
#[inline(always)]
pub fn write_canonical_initial_ike(
    buf: &mut [u8],
    destination: XdpIpAddress,
    routing_domain: u64,
    source: XdpIpAddress,
    source_port: u16,
    initiator_spi: u64,
    exchange: u8,
) -> usize {
    let mut cursor = encode_header(buf, OWNERSHIP_KIND_INITIAL_IKE);
    cursor = encode_destination(buf, cursor, destination, routing_domain);
    cursor = encode_address(buf, cursor, source);
    cursor = encode_bytes(buf, cursor, &source_port.to_be_bytes());
    cursor = encode_bytes(buf, cursor, &initiator_spi.to_be_bytes());
    encode_bytes(buf, cursor, &[exchange])
}

/// Write the canonical established-IKE ownership key into `buf`.
#[inline(always)]
pub fn write_canonical_established_ike(
    buf: &mut [u8],
    destination: XdpIpAddress,
    routing_domain: u64,
    initiator_spi: u64,
    responder_spi: u64,
) -> usize {
    let mut cursor = encode_header(buf, OWNERSHIP_KIND_ESTABLISHED_IKE);
    cursor = encode_destination(buf, cursor, destination, routing_domain);
    cursor = encode_bytes(buf, cursor, &initiator_spi.to_be_bytes());
    encode_bytes(buf, cursor, &responder_spi.to_be_bytes())
}

/// Write the canonical inbound-ESP ownership key into `buf`.
#[inline(always)]
pub fn write_canonical_esp(
    buf: &mut [u8],
    destination: XdpIpAddress,
    routing_domain: u64,
    encapsulation: u8,
    spi: u32,
) -> usize {
    let mut cursor = encode_header(buf, OWNERSHIP_KIND_ESP);
    cursor = encode_destination(buf, cursor, destination, routing_domain);
    cursor = encode_bytes(buf, cursor, &[encapsulation]);
    encode_bytes(buf, cursor, &spi.to_be_bytes())
}

#[inline(always)]
fn encode_header(encoded: &mut [u8], kind: u8) -> usize {
    let mut cursor = encode_bytes(encoded, 0, &OWNERSHIP_KEY_MAGIC);
    cursor = encode_bytes(encoded, cursor, &[OWNERSHIP_KEY_ENCODING_VERSION]);
    encode_bytes(encoded, cursor, &[kind])
}

#[inline(always)]
fn encode_destination(
    encoded: &mut [u8],
    cursor: usize,
    destination: XdpIpAddress,
    routing_domain: u64,
) -> usize {
    let cursor = encode_bytes(encoded, cursor, &routing_domain.to_be_bytes());
    encode_address(encoded, cursor, destination)
}

#[inline(always)]
fn encode_address(encoded: &mut [u8], cursor: usize, address: XdpIpAddress) -> usize {
    let cursor = encode_bytes(encoded, cursor, &[address.family()]);
    let (octets, len) = address.octets();
    encode_bytes(encoded, cursor, &octets[..len])
}

#[inline(always)]
fn encode_bytes(encoded: &mut [u8], cursor: usize, bytes: &[u8]) -> usize {
    encoded[cursor..cursor + bytes.len()].copy_from_slice(bytes);
    cursor + bytes.len()
}

/// Fixed owner-map value: owner identity plus ownership generation.
///
/// Layout (16 bytes, all big-endian):
///
/// | offset | width | field |
/// | ---: | ---: | --- |
/// | 0 | 2 | owner shard |
/// | 2 | 2 | flags (zero in v1) |
/// | 4 | 8 | ownership generation (non-zero) |
/// | 12 | 4 | reserved (zero) |
///
/// A userspace update writes the whole 16-byte value with one
/// `bpf_map_update_elem` call. On the kernels within the documented feature
/// floor that replacement is atomic in practice, but the guarantee is
/// architectural, not contractual: a lockless reader could theoretically
/// observe a torn value mid-update, and nothing in this ABI detects that.
/// In particular the dangerous mix — an old owner shard with a new
/// generation — decodes perfectly and is NOT caught by the strict decode
/// below; that decode only rejects structurally invalid values (non-zero
/// flags/reserved bytes, zero generation). The design therefore accepts
/// best-effort atomicity: the fence generation and the fenced ownership
/// authority's re-install discipline bound how long a stale or mixed value
/// can steer before the slow path re-validates it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpOwnerValue {
    /// Owner shard identity.
    pub owner_shard: u16,
    /// Fenced ownership generation for this record.
    pub generation: u64,
}

impl XdpOwnerValue {
    /// Encode into the fixed map-value byte layout.
    #[must_use]
    pub const fn encode(&self) -> [u8; OWNER_VALUE_LEN] {
        let owner = self.owner_shard.to_be_bytes();
        let generation = self.generation.to_be_bytes();
        [
            owner[0],
            owner[1],
            0,
            0,
            generation[0],
            generation[1],
            generation[2],
            generation[3],
            generation[4],
            generation[5],
            generation[6],
            generation[7],
            0,
            0,
            0,
            0,
        ]
    }

    /// Decode a map value, rejecting unknown flags, reserved bytes, and zero
    /// generations so ABI skew fails closed instead of steering wrong.
    #[must_use]
    #[inline(always)]
    pub const fn decode(value: &[u8; OWNER_VALUE_LEN]) -> Option<Self> {
        if value[2] != 0
            || value[3] != 0
            || value[12] != 0
            || value[13] != 0
            || value[14] != 0
            || value[15] != 0
        {
            return None;
        }
        let generation = u64::from_be_bytes([
            value[4], value[5], value[6], value[7], value[8], value[9], value[10], value[11],
        ]);
        if generation == 0 {
            return None;
        }
        Some(Self {
            owner_shard: u16::from_be_bytes([value[0], value[1]]),
            generation,
        })
    }
}

/// Single-slot datapath configuration.
///
/// Layout (32 bytes, all big-endian):
///
/// | offset | width | field |
/// | ---: | ---: | --- |
/// | 0 | 1 | ABI version ([`XDP_CONFIG_ABI_VERSION`]) |
/// | 1 | 1 | flags (zero in v2) |
/// | 2 | 2 | self shard |
/// | 4 | 8 | routing-domain tag |
/// | 12 | 8 | reserved (zero; the v1 fence field moved to [`MAP_FENCE`]) |
/// | 20 | 4 | userspace-redirector hand-off ifindex (0 = none) |
/// | 24 | 8 | reserved (zero) |
///
/// The ownership fence generation lives in its own single-slot aligned-`u64`
/// map (`IPSEC_LB_FENCE`) so an advance is a single tear-free aligned store;
/// it is deliberately not part of this wider value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XdpDatapathConfig {
    /// Shard identity of this node.
    pub self_shard: u16,
    /// Opaque routing-domain tag mixed into ownership keys.
    pub routing_domain: u64,
    /// Interface index of the dedicated userspace-redirector hand-off
    /// interface. Zero disables the redirect channel; a remote-owner verdict
    /// then fails closed to the slow path with the error counter.
    pub handoff_ifindex: u32,
}

impl XdpDatapathConfig {
    /// Encode into the fixed config byte layout.
    #[must_use]
    pub const fn encode(&self) -> [u8; CONFIG_VALUE_LEN] {
        let shard = self.self_shard.to_be_bytes();
        let domain = self.routing_domain.to_be_bytes();
        let ifindex = self.handoff_ifindex.to_be_bytes();
        [
            XDP_CONFIG_ABI_VERSION,
            0,
            shard[0],
            shard[1],
            domain[0],
            domain[1],
            domain[2],
            domain[3],
            domain[4],
            domain[5],
            domain[6],
            domain[7],
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            ifindex[0],
            ifindex[1],
            ifindex[2],
            ifindex[3],
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]
    }

    /// Decode the config, rejecting unknown ABI versions, flags, and reserved
    /// bytes so a schema mismatch fails closed with the error counter.
    #[must_use]
    #[inline(always)]
    pub const fn decode(value: &[u8; CONFIG_VALUE_LEN]) -> Option<Self> {
        if value[0] != XDP_CONFIG_ABI_VERSION || value[1] != 0 {
            return None;
        }
        let mut index = 12;
        while index < 20 {
            if value[index] != 0 {
                return None;
            }
            index += 1;
        }
        let mut index = 24;
        while index < CONFIG_VALUE_LEN {
            if value[index] != 0 {
                return None;
            }
            index += 1;
        }
        Some(Self {
            self_shard: u16::from_be_bytes([value[2], value[3]]),
            routing_domain: u64::from_be_bytes([
                value[4], value[5], value[6], value[7], value[8], value[9], value[10], value[11],
            ]),
            handoff_ifindex: u32::from_be_bytes([value[20], value[21], value[22], value[23]]),
        })
    }
}

/// Decide the fast-path verdict for one owner-map lookup.
///
/// Shared verbatim by the eBPF program and host-side tests:
///
/// - miss -> slow-path hand-off with the miss counter;
/// - invalid value encoding -> fail-closed slow-path hand-off (error counter);
/// - generation older than the fence -> slow-path hand-off (stale counter);
/// - owner = self -> local pass;
/// - owner = remote -> userspace-redirector hand-off, or fail-closed
///   slow-path hand-off when no hand-off interface is configured.
#[must_use]
#[inline(always)]
pub fn decide_owner_verdict(
    entry: Option<[u8; OWNER_VALUE_LEN]>,
    config: &XdpDatapathConfig,
    fence_generation: u64,
) -> XdpVerdict {
    let Some(raw) = entry else {
        return XdpVerdict::SlowPathMiss;
    };
    let Some(value) = XdpOwnerValue::decode(&raw) else {
        return XdpVerdict::SlowPathError;
    };
    if value.generation < fence_generation {
        return XdpVerdict::SlowPathStale;
    }
    if value.owner_shard == config.self_shard {
        return XdpVerdict::Local;
    }
    if config.handoff_ifindex == 0 {
        return XdpVerdict::SlowPathError;
    }
    XdpVerdict::RedirectHandoff
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec::Vec;

    use super::*;

    const CONFIG: XdpDatapathConfig = XdpDatapathConfig {
        self_shard: 1,
        routing_domain: 7,
        handoff_ifindex: 42,
    };

    const FENCE: u64 = 5;

    fn udp_probe(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut probe = Vec::new();
        probe.extend_from_slice(&source_port.to_be_bytes());
        probe.extend_from_slice(&destination_port.to_be_bytes());
        probe.extend_from_slice(&(payload.len() as u16 + 8).to_be_bytes());
        probe.extend_from_slice(&[0, 0]);
        probe.extend_from_slice(payload);
        probe
    }

    fn ike_header(initiator: u64, responder: u64, exchange: u8) -> Vec<u8> {
        let mut header = Vec::new();
        header.extend_from_slice(&initiator.to_be_bytes());
        header.extend_from_slice(&responder.to_be_bytes());
        header.push(0x20); // next payload
        header.push(0x20); // version 2.0
        header.push(exchange);
        header.push(0x08); // flags: initiator
        header.extend_from_slice(&[0; 4]); // message id
        header.extend_from_slice(&(IKEV2_HDR_LEN as u32).to_be_bytes());
        header
    }

    #[test]
    fn udp_500_established_ike_is_classified() {
        let probe = udp_probe(45000, UDP_PORT_IKE, &ike_header(0x1111, 0x2222, 35));
        let declared = probe.len();
        assert_eq!(
            classify_transport(IP_PROTOCOL_UDP, &probe, declared, declared),
            XdpTransportClass::IkeEstablished {
                initiator_spi: 0x1111,
                responder_spi: 0x2222,
            }
        );
    }

    #[test]
    fn udp_500_initial_ike_is_classified() {
        let probe = udp_probe(45000, UDP_PORT_IKE, &ike_header(0x1111, 0, 34));
        let declared = probe.len();
        assert_eq!(
            classify_transport(IP_PROTOCOL_UDP, &probe, declared, declared),
            XdpTransportClass::IkeInitial {
                initiator_spi: 0x1111,
                exchange: 34,
            }
        );
    }

    #[test]
    fn udp_4500_zero_marker_is_ike_and_nonzero_word_is_esp() {
        let mut payload = NON_ESP_MARKER.to_vec();
        payload.extend_from_slice(&ike_header(0xaaaa, 0xbbbb, 35));
        let probe = udp_probe(45000, UDP_PORT_IKE_NATT, &payload);
        let declared = probe.len();
        assert_eq!(
            classify_transport(IP_PROTOCOL_UDP, &probe, declared, declared),
            XdpTransportClass::IkeEstablished {
                initiator_spi: 0xaaaa,
                responder_spi: 0xbbbb,
            }
        );

        let mut esp = 0x00ca_fe00_u32.to_be_bytes().to_vec();
        esp.extend_from_slice(&[0, 0, 0, 1, 9, 9, 9, 9]);
        let probe = udp_probe(45000, UDP_PORT_IKE_NATT, &esp);
        let declared = probe.len();
        assert_eq!(
            classify_transport(IP_PROTOCOL_UDP, &probe, declared, declared),
            XdpTransportClass::Esp {
                encapsulation: OWNERSHIP_ESP_UDP_ENCAPSULATED,
                spi: 0x00ca_fe00,
            }
        );
    }

    #[test]
    fn udp_4500_keepalive_and_malformed_candidates() {
        let probe = udp_probe(45000, UDP_PORT_IKE_NATT, &[NAT_T_KEEPALIVE]);
        let declared = probe.len();
        assert_eq!(
            classify_transport(IP_PROTOCOL_UDP, &probe, declared, declared),
            XdpTransportClass::NatKeepalive
        );

        // Marker with no IKE header after it.
        let probe = udp_probe(45000, UDP_PORT_IKE_NATT, &NON_ESP_MARKER);
        let declared = probe.len();
        assert_eq!(
            classify_transport(IP_PROTOCOL_UDP, &probe, declared, declared),
            XdpTransportClass::Unclassifiable
        );

        // Reserved ESP SPI.
        let mut esp = 0x0000_00ff_u32.to_be_bytes().to_vec();
        esp.extend_from_slice(&[0, 0, 0, 1]);
        let probe = udp_probe(45000, UDP_PORT_IKE_NATT, &esp);
        let declared = probe.len();
        assert_eq!(
            classify_transport(IP_PROTOCOL_UDP, &probe, declared, declared),
            XdpTransportClass::Unclassifiable
        );

        // Truncated ESP prefix.
        let probe = udp_probe(45000, UDP_PORT_IKE_NATT, &[0xca, 0xfe, 0x02]);
        let declared = probe.len();
        assert_eq!(
            classify_transport(IP_PROTOCOL_UDP, &probe, declared, declared),
            XdpTransportClass::Unclassifiable
        );
    }

    #[test]
    fn native_esp_and_non_swu_are_discriminated() {
        let mut esp = 0x00ca_fe00_u32.to_be_bytes().to_vec();
        esp.extend_from_slice(&[0, 0, 0, 1, 1, 2, 3, 4]);
        assert_eq!(
            classify_transport(IP_PROTOCOL_ESP, &esp, esp.len(), esp.len()),
            XdpTransportClass::Esp {
                encapsulation: OWNERSHIP_ESP_NATIVE,
                spi: 0x00ca_fe00,
            }
        );

        assert_eq!(
            classify_transport(IP_PROTOCOL_ESP, &[0, 0, 1], 3, 3),
            XdpTransportClass::Unclassifiable
        );

        assert_eq!(
            classify_transport(1, &[0; 8], 8, 8),
            XdpTransportClass::NonSwu
        );

        let probe = udp_probe(53, 53, &[0; 12]);
        let declared = probe.len();
        assert_eq!(
            classify_transport(IP_PROTOCOL_UDP, &probe, declared, declared),
            XdpTransportClass::NonSwu
        );
    }

    #[test]
    fn udp_length_inconsistencies_fail_closed() {
        let probe = udp_probe(45000, UDP_PORT_IKE, &ike_header(0x1111, 0x2222, 35));
        let declared = probe.len();
        // IP declares less than the UDP length.
        assert_eq!(
            classify_transport(IP_PROTOCOL_UDP, &probe, declared, declared - 1),
            XdpTransportClass::Unclassifiable
        );
        // Packet is shorter than the UDP declaration.
        assert_eq!(
            classify_transport(IP_PROTOCOL_UDP, &probe, declared - 1, declared),
            XdpTransportClass::Unclassifiable
        );
        // Zero responder SPI outside IKE_SA_INIT.
        let probe = udp_probe(45000, UDP_PORT_IKE, &ike_header(0x1111, 0, 35));
        let declared = probe.len();
        assert_eq!(
            classify_transport(IP_PROTOCOL_UDP, &probe, declared, declared),
            XdpTransportClass::Unclassifiable
        );
        // Zero initiator SPI.
        let probe = udp_probe(45000, UDP_PORT_IKE, &ike_header(0, 0x2222, 35));
        let declared = probe.len();
        assert_eq!(
            classify_transport(IP_PROTOCOL_UDP, &probe, declared, declared),
            XdpTransportClass::Unclassifiable
        );
        // Wrong IKE major version.
        let mut ike = ike_header(0x1111, 0x2222, 35);
        ike[17] = 0x10;
        let probe = udp_probe(45000, UDP_PORT_IKE, &ike);
        let declared = probe.len();
        assert_eq!(
            classify_transport(IP_PROTOCOL_UDP, &probe, declared, declared),
            XdpTransportClass::Unclassifiable
        );
    }

    #[test]
    fn canonical_key_encodings_are_stable() {
        let (key, len) = canonical_established_ike_key(
            XdpIpAddress::V4([203, 0, 113, 7]),
            7,
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
        );
        let expected: &[u8] = b"OPCO\x01\x02\
            \x00\x00\x00\x00\x00\x00\x00\x07\x04\xcb\x00q\x07\
            \x01\x02\x03\x04\x05\x06\x07\x08\x11\x12\x13\x14\x15\x16\x17\x18";
        assert_eq!(&key[..len], expected);

        let (key, len) = canonical_esp_key(
            XdpIpAddress::V4([203, 0, 113, 7]),
            7,
            OWNERSHIP_ESP_NATIVE,
            0x00ca_fe00,
        );
        let expected: &[u8] = b"OPCO\x01\x03\
            \x00\x00\x00\x00\x00\x00\x00\x07\x04\xcb\x00q\x07\x01\x00\xca\xfe\x00";
        assert_eq!(&key[..len], expected);

        let (key, len) = canonical_initial_ike_key(
            XdpIpAddress::V4([203, 0, 113, 7]),
            7,
            XdpIpAddress::V4([198, 51, 100, 9]),
            45000,
            0x0102_0304_0506_0708,
            34,
        );
        let expected: &[u8] = b"OPCO\x01\x01\
            \x00\x00\x00\x00\x00\x00\x00\x07\x04\xcb\x00q\x07\
            \x04\xc6\x33\x64\x09\xaf\xc8\
            \x01\x02\x03\x04\x05\x06\x07\x08\x22";
        assert_eq!(&key[..len], expected);
    }

    #[test]
    fn canonical_initial_ike_ipv6_fills_the_max_encoding() {
        let (key, len) = canonical_initial_ike_key(
            XdpIpAddress::V6([0x20; 16]),
            7,
            XdpIpAddress::V6([0x30; 16]),
            4500,
            1,
            34,
        );
        assert_eq!(len, OWNERSHIP_KEY_MAX_ENCODED_BYTES);
        assert_eq!(&key[0..4], b"OPCO");
    }

    #[test]
    fn ownership_map_key_wraps_the_canonical_encoding() {
        let class = XdpTransportClass::Esp {
            encapsulation: OWNERSHIP_ESP_UDP_ENCAPSULATED,
            spi: 0x00ca_fe00,
        };
        let key = ownership_map_key(
            &class,
            XdpIpAddress::V4([198, 51, 100, 9]),
            4500,
            XdpIpAddress::V4([203, 0, 113, 7]),
            7,
        )
        .expect("ESP identity has a key");
        let (canonical, canonical_len) = canonical_esp_key(
            XdpIpAddress::V4([203, 0, 113, 7]),
            7,
            OWNERSHIP_ESP_UDP_ENCAPSULATED,
            0x00ca_fe00,
        );
        assert_eq!(usize::from(key[0]), canonical_len);
        assert_eq!(&key[1..1 + canonical_len], &canonical[..canonical_len]);
        assert!(key[1 + canonical_len..].iter().all(|byte| *byte == 0));

        assert_eq!(
            ownership_map_key(
                &XdpTransportClass::NonSwu,
                XdpIpAddress::V4([0; 4]),
                0,
                XdpIpAddress::V4([0; 4]),
                0,
            ),
            None
        );
    }

    #[test]
    fn owner_value_encoding_is_stable_and_strict() {
        let value = XdpOwnerValue {
            owner_shard: 7,
            generation: 0x0102_0304_0506_0708,
        };
        assert_eq!(
            value.encode(),
            [0, 7, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0]
        );
        assert_eq!(XdpOwnerValue::decode(&value.encode()), Some(value));

        let mut zero_generation = value.encode();
        zero_generation[4..12].copy_from_slice(&[0; 8]);
        assert_eq!(XdpOwnerValue::decode(&zero_generation), None);

        let mut flagged = value.encode();
        flagged[2] = 1;
        assert_eq!(XdpOwnerValue::decode(&flagged), None);

        let mut reserved = value.encode();
        reserved[15] = 1;
        assert_eq!(XdpOwnerValue::decode(&reserved), None);
    }

    #[test]
    fn config_encoding_is_stable_and_version_checked() {
        let encoded = CONFIG.encode();
        assert_eq!(encoded[0], XDP_CONFIG_ABI_VERSION);
        assert_eq!(&encoded[2..4], &1_u16.to_be_bytes());
        assert_eq!(&encoded[4..12], &7_u64.to_be_bytes());
        assert_eq!(&encoded[12..20], &[0; 8]);
        assert_eq!(&encoded[20..24], &42_u32.to_be_bytes());
        assert_eq!(XdpDatapathConfig::decode(&encoded), Some(CONFIG));

        let mut wrong_version = encoded;
        wrong_version[0] = 0;
        assert_eq!(XdpDatapathConfig::decode(&wrong_version), None);

        let mut v1_layout = encoded;
        v1_layout[0] = 1;
        v1_layout[12] = 5;
        assert_eq!(XdpDatapathConfig::decode(&v1_layout), None);

        let mut reserved = encoded;
        reserved[31] = 1;
        assert_eq!(XdpDatapathConfig::decode(&reserved), None);
    }

    #[test]
    fn redirect_outcome_only_counts_helper_confirmed_redirects() {
        assert_eq!(
            redirect_outcome(XDP_ACTION_REDIRECT),
            XdpRedirectOutcome::Redirected
        );
        // XDP_ABORTED (0), XDP_DROP (1), XDP_PASS (2), XDP_TX (3), and
        // arbitrary garbage fail closed.
        for result in [0_u32, 1, 2, 3, 5, u32::MAX] {
            assert_eq!(
                redirect_outcome(result),
                XdpRedirectOutcome::SlowPathError,
                "helper result {result} must fail closed"
            );
        }
    }

    #[test]
    fn verdict_decision_covers_every_branch() {
        let owner_self = XdpOwnerValue {
            owner_shard: 1,
            generation: 5,
        }
        .encode();
        let owner_remote = XdpOwnerValue {
            owner_shard: 2,
            generation: 6,
        }
        .encode();
        let owner_stale = XdpOwnerValue {
            owner_shard: 1,
            generation: 4,
        }
        .encode();

        assert_eq!(
            decide_owner_verdict(None, &CONFIG, FENCE),
            XdpVerdict::SlowPathMiss
        );
        assert_eq!(
            decide_owner_verdict(Some(owner_self), &CONFIG, FENCE),
            XdpVerdict::Local
        );
        assert_eq!(
            decide_owner_verdict(Some(owner_remote), &CONFIG, FENCE),
            XdpVerdict::RedirectHandoff
        );
        assert_eq!(
            decide_owner_verdict(Some(owner_stale), &CONFIG, FENCE),
            XdpVerdict::SlowPathStale
        );
        assert_eq!(
            decide_owner_verdict(Some([0; OWNER_VALUE_LEN]), &CONFIG, FENCE),
            XdpVerdict::SlowPathError
        );

        // A remote owner without a redirect channel fails closed.
        let no_channel = XdpDatapathConfig {
            handoff_ifindex: 0,
            ..CONFIG
        };
        assert_eq!(
            decide_owner_verdict(Some(owner_remote), &no_channel, FENCE),
            XdpVerdict::SlowPathError
        );

        // Verdict counters are distinct per verdict.
        let counters = [
            verdict_counter(XdpVerdict::Local),
            verdict_counter(XdpVerdict::RedirectHandoff),
            verdict_counter(XdpVerdict::SlowPathMiss),
            verdict_counter(XdpVerdict::SlowPathStale),
            verdict_counter(XdpVerdict::SlowPathError),
        ];
        for (index, counter) in counters.iter().enumerate() {
            assert!(counters[..index].iter().all(|other| other != counter));
        }
    }
}
