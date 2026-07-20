//! Post-reassembly downlink consumer for the kernel outer-fragment handoff.
//!
//! The tc downlink program passes outer IPv4 fragments to the kernel stack
//! unchanged (`TC_ACT_OK`); the kernel reassembles them under its bounded
//! `ipfrag` accounting and delivers exactly one complete UDP/2152 datagram to
//! the socket bound on the concrete local S2b-U address (never `0.0.0.0`).
//! This module is the SDK consumer for that re-entry point:
//! [`GtpuReassemblyConsumer::process`] mirrors the tc fast path's PDR
//! resolution, endpoint-binding validation, marked-bearer owner-journal
//! authorization, and inner destination checks, and returns the decapsulated
//! inner packet with its output bearer mark. Non-G-PDU GTP-U (echo, error
//! indication) is handed back for the control plane, matching the fast
//! path's pass-through.
//!
//! Deliberate, documented divergences from the tc fast path:
//!
//! - Checksum verification is the kernel's: socket delivery implies the
//!   kernel accepted the reassembled datagram, so the consumer performs no
//!   checksum probes of its own.
//! - Envelope padding strictness differs: tc requires the UDP end to equal
//!   the IPv4 end and drops padded envelopes, while the kernel strips layer-2
//!   padding before socket delivery, so a padded envelope that tc would drop
//!   unfragmented is accepted here after reassembly.
//! - The ingress ifindex cannot come from `IP_PKTINFO` on this path — the
//!   kernel reports ifindex 0 for reassembled datagrams — so it is the
//!   managed interface's ifindex supplied by the caller (see
//!   [`recv_reassembled_gtpu`]); delivery is scoped to the right interface
//!   by the concrete-address bind instead.
//!
//! The consumer's counters are userspace-side and deliberately *not* part of
//! the eBPF backend's identity-bound `datapath_snapshot` counters: the
//! snapshot aggregates the tc datapath's per-CPU maps, while these count the
//! post-reassembly socket path. Operators should monitor both.
//!
//! Socket lifecycle guidance for the embedding ePDG: size `SO_RCVBUF` for
//! the expected reassembled burst (kernel UDP buffer overruns drop silently
//! and are not visible in these counters), and shut down in reverse order —
//! detach the tc datapath first or close the consumer socket last — because
//! fragments arriving after the socket closes are answered with ICMP port
//! unreachable toward the PGW. Reassembly itself stays in the kernel, so
//! fragment memory and time are bounded by `net.ipv4.ipfrag_*` rather than
//! by any SDK state; the SDK never holds a userspace fragment cache.
//! Delivery of the decapsulated inner packet (route/XFRM injection) is the
//! embedding ePDG's choice and is deliberately out of scope here.

use std::fmt;
use std::net::Ipv4Addr;

use opc_gtpu_ebpf_common::{
    parse_gtpu_tpdu, DownlinkBindingMismatch, DownlinkEndpointBinding, GtpuReassemblyBounds,
    MarkedDownlinkPdr, UplinkFarKey, MAX_REASSEMBLED_GTPU_LEN, UPLINK_MARK_KEY_LEN,
};

use crate::model::GtpBearerMark;

/// Read the live per-netns IPv4 reassembly bounds for capability reporting.
///
/// Returns `None` when either sysctl is unreadable; the bounds are never
/// fabricated from defaults, so a capability report carrying `None` means
/// "kernel limits unknown", not "kernel defaults".
#[cfg(target_os = "linux")]
#[must_use]
pub fn linux_reassembly_bounds() -> Option<GtpuReassemblyBounds> {
    fn read_sysctl_u32(path: &str) -> Option<u32> {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|value| value.trim().parse().ok())
    }
    Some(GtpuReassemblyBounds {
        max_inflight_bytes: read_sysctl_u32("/proc/sys/net/ipv4/ipfrag_high_thresh")?,
        timeout_seconds: read_sysctl_u32("/proc/sys/net/ipv4/ipfrag_time")?,
    })
}

/// Exact outer provenance of one reassembled downlink GTP-U datagram.
///
/// The consumer receives these values from the delivery socket: peer address
/// and source port from the datagram source, the local destination from
/// `IP_PKTINFO`, and the managed interface's ifindex from the caller (see
/// [`recv_reassembled_gtpu`] for why `IP_PKTINFO` cannot supply it on this
/// path). They authorize the datagram against the same canonical
/// [`DownlinkEndpointBinding`] as the tc fast path.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DownlinkOuterProvenance {
    peer_address: Ipv4Addr,
    local_address: Ipv4Addr,
    ingress_ifindex: u32,
    source_port: u16,
}

impl DownlinkOuterProvenance {
    /// Construct one canonical provenance. Unspecified addresses and a zero
    /// ifindex cannot authorize anything and return `None`.
    #[must_use]
    pub fn new(
        peer_address: Ipv4Addr,
        local_address: Ipv4Addr,
        ingress_ifindex: u32,
        source_port: u16,
    ) -> Option<Self> {
        if peer_address.is_unspecified() || local_address.is_unspecified() || ingress_ifindex == 0 {
            return None;
        }
        Some(Self {
            peer_address,
            local_address,
            ingress_ifindex,
            source_port,
        })
    }

    /// Return the outer peer (PGW) address.
    #[must_use]
    pub const fn peer_address(&self) -> Ipv4Addr {
        self.peer_address
    }

    /// Return the local outer destination address.
    #[must_use]
    pub const fn local_address(&self) -> Ipv4Addr {
        self.local_address
    }

    /// Return the ingress interface index the datagram arrived on.
    #[must_use]
    pub const fn ingress_ifindex(&self) -> u32 {
        self.ingress_ifindex
    }

    /// Return the outer UDP source port.
    #[must_use]
    pub const fn source_port(&self) -> u16 {
        self.source_port
    }
}

impl fmt::Debug for DownlinkOuterProvenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DownlinkOuterProvenance")
            .field("peer_address", &"<redacted>")
            .field("local_address", &"<redacted>")
            .field("ingress_ifindex", &"<redacted>")
            .field("source_port", &"<redacted>")
            .finish()
    }
}

/// Receive one reassembled UDP/2152 datagram together with its authoritative
/// outer provenance via `IP_PKTINFO`.
///
/// The returned provenance carries the datagram's source (peer address and
/// source port) and the kernel-reported local destination address, so the
/// consumer never hardcodes them. `ingress_ifindex` must be the managed
/// S2b-U interface's ifindex: the kernel reports ifindex 0 in `IP_PKTINFO`
/// for reassembled datagrams (and on the loopback receive path), so
/// per-packet packet-info cannot supply it. What scopes delivery to the
/// right interface is the concrete-address bind — the socket must be bound
/// on the interface's own S2b-U address (never `0.0.0.0`), so datagrams
/// addressed to any other interface never arrive. When the kernel *does*
/// report a nonzero ifindex, it is cross-checked against `ingress_ifindex`
/// and a mismatch fails closed. `IP_PKTINFO` is enabled on the socket as a
/// side effect.
///
/// # Errors
///
/// Returns the underlying socket error, or `InvalidData` when the kernel
/// supplied no packet-info control message, a conflicting ifindex, or a
/// non-canonical provenance.
#[cfg(target_os = "linux")]
pub fn recv_reassembled_gtpu(
    socket: &std::net::UdpSocket,
    buffer: &mut [u8],
    ingress_ifindex: u32,
) -> std::io::Result<(usize, DownlinkOuterProvenance)> {
    use nix::sys::socket::{
        recvmsg, setsockopt, sockopt, ControlMessageOwned, MsgFlags, SockaddrIn,
    };
    use std::os::fd::AsRawFd;

    setsockopt(socket, sockopt::Ipv4PacketInfo, &true)?;
    let mut cmsg_space = nix::cmsg_space!(nix::libc::in_pktinfo);
    let mut iov = [std::io::IoSliceMut::new(buffer)];
    let message = recvmsg::<SockaddrIn>(
        socket.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_space),
        MsgFlags::empty(),
    )?;
    let from = std::net::SocketAddr::from(message.address.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "missing datagram source")
    })?);
    let std::net::IpAddr::V4(peer) = from.ip() else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "non-IPv4 datagram source",
        ));
    };
    let packet_info = message
        .cmsgs()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?
        .find_map(|control| match control {
            ControlMessageOwned::Ipv4PacketInfo(info) => Some(info),
            _ => None,
        })
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "missing IP_PKTINFO control message",
            )
        })?;
    let reported_ifindex = u32::try_from(packet_info.ipi_ifindex).unwrap_or(0);
    if reported_ifindex != 0 && reported_ifindex != ingress_ifindex {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "kernel ingress ifindex conflicts with the managed interface",
        ));
    }
    let local = Ipv4Addr::from(u32::from_be(packet_info.ipi_addr.s_addr));
    let provenance = DownlinkOuterProvenance::new(peer, local, ingress_ifindex, from.port())
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "non-canonical provenance")
        })?;
    Ok((message.bytes, provenance))
}

/// Typed resolution of the downlink PDR lookup for one G-PDU TEID.
///
/// The lookup closure must return [`GtpuReassemblyPdr::Corrupt`] for every
/// state the tc fast path drops as malformed: a TEID present in *both* the
/// legacy and marked PDR maps (externally corrupted duplicate ownership) and
/// a marked PDR carrying the reserved zero bearer mark. Returning
/// `Configured` for either would let the socket path deliver packets the tc
/// path drops fail closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuReassemblyPdr {
    /// One canonical PDR authorizes the TEID.
    Configured(MarkedDownlinkPdr),
    /// The persisted PDR state is corrupt; fail closed.
    Corrupt,
}

/// Stable, redaction-safe reason a reassembled datagram was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuReassemblyDrop {
    /// The reassembled message violates the GTP-U framing invariants, or the
    /// persisted PDR state is corrupt (dual-map TEID or reserved zero mark).
    Malformed,
    /// The datagram exceeds the bounded maximum reassembled length.
    Oversized,
    /// No PDR exists for the G-PDU TEID.
    UnknownTeid,
    /// The outer provenance failed the canonical endpoint binding, or the
    /// marked bearer's owner journal did not authorize the delivery.
    BindingMismatch(DownlinkBindingMismatch),
    /// The inner destination does not match the session's UE PAA.
    DestinationMismatch,
}

/// Bounded counters of the post-reassembly consumer, mirroring the
/// fixed-cardinality datapath counters of the tc fast path.
///
/// These are userspace counters for the socket re-entry path and are
/// intentionally separate from the eBPF backend's `datapath_snapshot`
/// per-CPU map aggregates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GtpuReassemblyCounters {
    /// Reassembled G-PDUs decapsulated and handed to the embedding ePDG.
    pub decapsulated: u64,
    /// Messages passed through for the control plane (non-G-PDU GTP-U).
    pub control_plane: u64,
    /// Reassembled messages dropped as malformed, including corrupt PDR
    /// state (dual-map TEID, reserved zero mark).
    pub malformed: u64,
    /// G-PDUs dropped for an unknown TEID.
    pub unknown_teid: u64,
    /// G-PDUs dropped by the outer-endpoint binding or the marked-bearer
    /// owner journal.
    pub binding_drops: u64,
    /// G-PDUs dropped because the inner destination is not the session's UE.
    pub destination_mismatches: u64,
    /// Datagrams rejected before parsing because they exceed the bounded
    /// maximum reassembled length.
    pub oversized: u64,
}

/// Outcome of processing one reassembled downlink datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GtpuReassemblyOutcome {
    /// The datagram was authorized and decapsulated exactly once.
    Decapsulated {
        /// The complete inner packet (bounded by the reassembled datagram).
        inner_packet: Vec<u8>,
        /// Output bearer mark for XFRM policy selection; `None` is the
        /// default bearer (mark zero), matching the fast path.
        bearer_mark: Option<GtpBearerMark>,
    },
    /// Not a G-PDU: hand the message to the GTP-U control plane.
    ControlPlane,
    /// Fail-closed drop with a bounded typed reason.
    Dropped(GtpuReassemblyDrop),
}

/// Post-reassembly downlink consumer: the SDK GTP-U consumer that kernel
/// reassembly re-enters, backed by the caller's authoritative PDR,
/// endpoint-binding, and owner-journal state.
///
/// The three closures are the integration seam:
///
/// - `lookup_pdr` resolves a TEID to a typed [`GtpuReassemblyPdr`]; it must
///   report `Corrupt` for dual-map TEIDs and reserved zero marks, exactly
///   the states the tc program drops as malformed.
/// - `lookup_binding` serves the canonical endpoint binding for the TEID.
/// - `authorize_marked_owner` decides whether the marked-bearer owner
///   journal authorizes `(teid, selector, binding)`; production callers back
///   it with `marked_owner_wire_authorizes_downlink` over the pinned
///   `GTPU_M_OWNER` map. It is consulted only for marked bearers, mirroring
///   the tc program's `Active`-journal requirement so install, relocation,
///   and removal windows cannot deliver through the socket path what the tc
///   path would drop.
///
/// Keeping the state source caller-supplied makes the consumer
/// backend-neutral and lets the embedding ePDG decide how read-back state is
/// refreshed.
pub struct GtpuReassemblyConsumer<P, B, O> {
    lookup_pdr: P,
    lookup_binding: B,
    authorize_marked_owner: O,
    counters: GtpuReassemblyCounters,
}

impl<P, B, O> fmt::Debug for GtpuReassemblyConsumer<P, B, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpuReassemblyConsumer")
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

impl<P, B, O> GtpuReassemblyConsumer<P, B, O>
where
    P: Fn([u8; 4]) -> Option<GtpuReassemblyPdr>,
    B: Fn([u8; 4]) -> Option<DownlinkEndpointBinding>,
    O: Fn([u8; 4], [u8; UPLINK_MARK_KEY_LEN], &DownlinkEndpointBinding) -> bool,
{
    /// Construct a consumer over the given PDR, binding, and owner lookups.
    pub fn new(lookup_pdr: P, lookup_binding: B, authorize_marked_owner: O) -> Self {
        Self {
            lookup_pdr,
            lookup_binding,
            authorize_marked_owner,
            counters: GtpuReassemblyCounters::default(),
        }
    }

    /// Return the bounded consumer counters.
    #[must_use]
    pub const fn counters(&self) -> GtpuReassemblyCounters {
        self.counters
    }

    /// Process one complete reassembled UDP/2152 datagram.
    ///
    /// `message` is the exact UDP payload delivered by the socket. It is
    /// bounded by [`MAX_REASSEMBLED_GTPU_LEN`]; larger inputs are dropped
    /// before parsing. Each call delivers at most one decapsulated packet:
    /// the kernel completes a fragment set into exactly one datagram, so
    /// duplicated, reordered, overlapping, or timed-out fragment sets can
    /// never produce a second delivery here.
    pub fn process(
        &mut self,
        message: &[u8],
        provenance: &DownlinkOuterProvenance,
    ) -> GtpuReassemblyOutcome {
        if message.len() > MAX_REASSEMBLED_GTPU_LEN {
            self.counters.oversized += 1;
            return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Oversized);
        }
        let tpdu = match parse_gtpu_tpdu(message) {
            Ok(Some(tpdu)) => tpdu,
            Ok(None) => {
                self.counters.control_plane += 1;
                return GtpuReassemblyOutcome::ControlPlane;
            }
            Err(_) => {
                self.counters.malformed += 1;
                return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Malformed);
            }
        };
        let pdr = match (self.lookup_pdr)(tpdu.teid) {
            None => {
                self.counters.unknown_teid += 1;
                return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::UnknownTeid);
            }
            Some(GtpuReassemblyPdr::Corrupt) => {
                // Dual-map TEID or reserved zero mark: the tc program drops
                // these as malformed, and so does this path.
                self.counters.malformed += 1;
                return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Malformed);
            }
            Some(GtpuReassemblyPdr::Configured(pdr)) => pdr,
        };
        let Some(binding) = (self.lookup_binding)(tpdu.teid) else {
            self.counters.binding_drops += 1;
            return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(
                DownlinkBindingMismatch::Invalid,
            ));
        };
        if let Err(reason) = binding.validate_ipv4_packet(
            provenance.peer_address.octets(),
            provenance.local_address.octets(),
            provenance.ingress_ifindex,
            provenance.source_port,
        ) {
            self.counters.binding_drops += 1;
            return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(reason));
        }
        let output_mark = u32::from_be_bytes(pdr.bearer_mark);
        if output_mark != 0 {
            // A marked bearer is delivered only when its owner journal
            // authorizes this exact TEID and binding, mirroring the tc
            // program's Active-journal gate.
            let selector = UplinkFarKey {
                ue_ip: pdr.ue_ip,
                bearer_mark: pdr.bearer_mark,
            }
            .encode();
            if !(self.authorize_marked_owner)(tpdu.teid, selector, &binding) {
                self.counters.binding_drops += 1;
                return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(
                    DownlinkBindingMismatch::Invalid,
                ));
            }
        }
        // Mirror the fast path: the T-PDU must be an inner IPv4 packet
        // addressed to the session's UE PAA. `parse_gtpu_tpdu` already
        // guarantees at least a minimum inner header.
        if tpdu.payload[0] >> 4 != 4 {
            self.counters.malformed += 1;
            return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Malformed);
        }
        if tpdu.payload[16..20] != pdr.ue_ip {
            self.counters.destination_mismatches += 1;
            return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::DestinationMismatch);
        }
        let bearer_mark = GtpBearerMark::new(output_mark);
        self.counters.decapsulated += 1;
        GtpuReassemblyOutcome::Decapsulated {
            inner_packet: tpdu.payload.to_vec(),
            bearer_mark,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_gtpu_ebpf_common::{GtpuEndpointAddress, GtpuSourcePortPolicy};

    const UE: Ipv4Addr = Ipv4Addr::new(10, 45, 0, 2);
    const PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 10);
    const LOCAL: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const TEID: [u8; 4] = [0x10, 0, 0, 1];

    fn provenance() -> DownlinkOuterProvenance {
        DownlinkOuterProvenance::new(PEER, LOCAL, 7, 2152).unwrap()
    }

    fn binding() -> DownlinkEndpointBinding {
        DownlinkEndpointBinding::new(
            GtpuEndpointAddress::Ipv4(PEER.octets()),
            GtpuEndpointAddress::Ipv4(LOCAL.octets()),
            7,
            GtpuSourcePortPolicy::Any,
        )
        .unwrap()
    }

    fn pdr(mark: [u8; 4]) -> MarkedDownlinkPdr {
        MarkedDownlinkPdr {
            ue_ip: UE.octets(),
            bearer_mark: mark,
        }
    }

    type PdrLookup = Box<dyn Fn([u8; 4]) -> Option<GtpuReassemblyPdr>>;
    type BindingLookup = Box<dyn Fn([u8; 4]) -> Option<DownlinkEndpointBinding>>;
    type OwnerAuthorizer =
        Box<dyn Fn([u8; 4], [u8; UPLINK_MARK_KEY_LEN], &DownlinkEndpointBinding) -> bool>;

    fn consumer(
        mark: [u8; 4],
    ) -> GtpuReassemblyConsumer<PdrLookup, BindingLookup, OwnerAuthorizer> {
        consumer_with_owner(mark, true)
    }

    fn consumer_with_owner(
        mark: [u8; 4],
        owner_authorized: bool,
    ) -> GtpuReassemblyConsumer<PdrLookup, BindingLookup, OwnerAuthorizer> {
        GtpuReassemblyConsumer::new(
            Box::new(move |teid| (teid == TEID).then(|| GtpuReassemblyPdr::Configured(pdr(mark)))),
            Box::new(move |teid| (teid == TEID).then(binding)),
            Box::new(move |_: [u8; 4], _: [u8; 8], _: &DownlinkEndpointBinding| owner_authorized),
        )
    }

    fn inner_packet(dst: Ipv4Addr) -> Vec<u8> {
        let mut inner = vec![
            0x45, 0, 0, 24, 0, 0, 0, 0, 64, 17, 0, 0, 10, 45, 0, 9, 0, 0, 0, 0,
        ];
        inner[16..20].copy_from_slice(&dst.octets());
        inner.extend_from_slice(b"data");
        inner
    }

    fn gpdu(teid: [u8; 4], inner: &[u8]) -> Vec<u8> {
        let mut message = vec![0x30, 0xFF, 0, 0, teid[0], teid[1], teid[2], teid[3]];
        let declared = u16::try_from(inner.len()).unwrap();
        message[2..4].copy_from_slice(&declared.to_be_bytes());
        message.extend_from_slice(inner);
        message
    }

    #[test]
    fn authorized_marked_datagram_decapsulates_with_output_mark() {
        let mut consumer = consumer(0x0102_0304_u32.to_be_bytes());
        let outcome = consumer.process(&gpdu(TEID, &inner_packet(UE)), &provenance());
        let GtpuReassemblyOutcome::Decapsulated {
            inner_packet: delivered,
            bearer_mark,
        } = outcome
        else {
            panic!("expected decapsulation, got {outcome:?}");
        };
        assert_eq!(delivered, inner_packet(UE));
        assert_eq!(bearer_mark, GtpBearerMark::new(0x0102_0304));
        assert_eq!(consumer.counters().decapsulated, 1);
    }

    #[test]
    fn default_bearer_decapsulates_without_mark_or_owner_check() {
        let mut consumer = consumer_with_owner([0; 4], false);
        let outcome = consumer.process(&gpdu(TEID, &inner_packet(UE)), &provenance());
        assert!(
            matches!(
                outcome,
                GtpuReassemblyOutcome::Decapsulated {
                    bearer_mark: None,
                    ..
                }
            ),
            "a default bearer must never consult the owner journal: {outcome:?}"
        );
    }

    #[test]
    fn marked_bearer_without_owner_authorization_fails_closed() {
        let mut consumer = consumer_with_owner(0x0102_0304_u32.to_be_bytes(), false);
        assert_eq!(
            consumer.process(&gpdu(TEID, &inner_packet(UE)), &provenance()),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(
                DownlinkBindingMismatch::Invalid
            ))
        );
        let counters = consumer.counters();
        assert_eq!(counters.binding_drops, 1);
        assert_eq!(counters.decapsulated, 0);
    }

    #[test]
    fn corrupt_pdr_state_fails_closed_like_the_tc_path() {
        // Dual-map TEID or marked PDR with a reserved zero mark must surface
        // as Corrupt from the lookup; the consumer drops as malformed.
        let mut consumer = GtpuReassemblyConsumer::new(
            Box::new(|_teid| Some(GtpuReassemblyPdr::Corrupt)) as PdrLookup,
            Box::new(move |teid| (teid == TEID).then(binding)) as BindingLookup,
            Box::new(|_: [u8; 4], _: [u8; 8], _: &DownlinkEndpointBinding| true) as OwnerAuthorizer,
        );
        assert_eq!(
            consumer.process(&gpdu(TEID, &inner_packet(UE)), &provenance()),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Malformed)
        );
        let counters = consumer.counters();
        assert_eq!(counters.malformed, 1);
        assert_eq!(counters.decapsulated, 0);
    }

    #[test]
    fn every_drop_reason_is_typed_and_counted() {
        let mut consumer = consumer([0; 4]);
        // Unknown TEID.
        assert_eq!(
            consumer.process(&gpdu([0x20, 0, 0, 9], &inner_packet(UE)), &provenance()),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::UnknownTeid)
        );
        // Wrong outer peer.
        let wrong_peer =
            DownlinkOuterProvenance::new(Ipv4Addr::new(192, 0, 2, 11), LOCAL, 7, 2152).unwrap();
        assert_eq!(
            consumer.process(&gpdu(TEID, &inner_packet(UE)), &wrong_peer),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(
                DownlinkBindingMismatch::PeerAddress
            ))
        );
        // Wrong ingress ifindex.
        let wrong_ifindex = DownlinkOuterProvenance::new(PEER, LOCAL, 8, 2152).unwrap();
        assert_eq!(
            consumer.process(&gpdu(TEID, &inner_packet(UE)), &wrong_ifindex),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(
                DownlinkBindingMismatch::IngressAttachment
            ))
        );
        // Inner destination mismatch.
        assert_eq!(
            consumer.process(
                &gpdu(TEID, &inner_packet(Ipv4Addr::new(10, 45, 0, 9))),
                &provenance()
            ),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::DestinationMismatch)
        );
        // Malformed framing.
        assert_eq!(
            consumer.process(&[0x30, 0xFF, 0, 1], &provenance()),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Malformed)
        );
        // Non-IPv4 inner.
        let mut v6_inner = vec![0x60; 40];
        v6_inner.extend_from_slice(&[0; 8]);
        assert_eq!(
            consumer.process(&gpdu(TEID, &v6_inner), &provenance()),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Malformed)
        );
        let counters = consumer.counters();
        assert_eq!(counters.unknown_teid, 1);
        assert_eq!(counters.binding_drops, 2);
        assert_eq!(counters.destination_mismatches, 1);
        assert_eq!(counters.malformed, 2);
        assert_eq!(counters.decapsulated, 0);
    }

    #[test]
    fn non_gpdu_messages_pass_to_the_control_plane() {
        let mut consumer = consumer([0; 4]);
        let mut echo = vec![0x30, 0x01, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0];
        echo[0] = 0x32;
        assert_eq!(
            consumer.process(&echo, &provenance()),
            GtpuReassemblyOutcome::ControlPlane
        );
        assert_eq!(consumer.counters().control_plane, 1);
    }

    #[test]
    fn oversized_datagrams_are_dropped_before_parsing() {
        let mut consumer = consumer([0; 4]);
        let oversized = vec![0x30; MAX_REASSEMBLED_GTPU_LEN + 1];
        assert_eq!(
            consumer.process(&oversized, &provenance()),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Oversized)
        );
        assert_eq!(consumer.counters().oversized, 1);
        // The exact bounded maximum is admitted to the parser.
        let mut maximum = vec![0x30, 0xFF, 0, 0, 0, 0, 0, 0];
        maximum.resize(MAX_REASSEMBLED_GTPU_LEN, 0);
        let _ = consumer.process(&maximum, &provenance());
        assert_eq!(consumer.counters().oversized, 1);
    }

    #[test]
    fn missing_binding_fails_closed() {
        let mut consumer = GtpuReassemblyConsumer::new(
            Box::new(move |teid| (teid == TEID).then(|| GtpuReassemblyPdr::Configured(pdr([0; 4]))))
                as PdrLookup,
            Box::new(|_teid| None) as BindingLookup,
            Box::new(|_: [u8; 4], _: [u8; 8], _: &DownlinkEndpointBinding| true) as OwnerAuthorizer,
        );
        assert_eq!(
            consumer.process(&gpdu(TEID, &inner_packet(UE)), &provenance()),
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::BindingMismatch(
                DownlinkBindingMismatch::Invalid
            ))
        );
    }

    #[test]
    fn provenance_rejects_noncanonical_identity_and_redacts_debug() {
        assert!(DownlinkOuterProvenance::new(Ipv4Addr::UNSPECIFIED, LOCAL, 7, 2152).is_none());
        assert!(DownlinkOuterProvenance::new(PEER, Ipv4Addr::UNSPECIFIED, 7, 2152).is_none());
        assert!(DownlinkOuterProvenance::new(PEER, LOCAL, 0, 2152).is_none());
        let debug = format!("{:?}", provenance());
        assert!(!debug.contains("192"));
        assert!(!debug.contains("2152"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recv_reassembled_gtpu_extracts_pktinfo_provenance() {
        use std::net::UdpSocket;

        let receiver = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let sender_port = sender.local_addr().unwrap().port();
        sender.send_to(b"gtpu-probe", receiver_addr).unwrap();

        receiver
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut buffer = [0_u8; 64];
        // Loopback reports ifindex 0 in IP_PKTINFO (skb_iif is unset on the
        // loopback receive path), so the managed-interface ifindex passed in
        // is used; on real interfaces the kernel value is cross-checked.
        let (len, provenance) = recv_reassembled_gtpu(&receiver, &mut buffer, 1).unwrap();
        assert_eq!(&buffer[..len], b"gtpu-probe");
        assert_eq!(provenance.peer_address(), Ipv4Addr::LOCALHOST);
        assert_eq!(provenance.local_address(), Ipv4Addr::LOCALHOST);
        assert_eq!(provenance.source_port(), sender_port);
        assert_eq!(provenance.ingress_ifindex(), 1);
    }
}
