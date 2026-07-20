//! Post-reassembly downlink consumer for the kernel outer-fragment handoff.
//!
//! The tc downlink program passes outer IPv4 fragments to the kernel stack
//! unchanged (`TC_ACT_OK`); the kernel reassembles them under its bounded
//! `ipfrag` accounting and delivers exactly one complete UDP/2152 datagram to
//! the socket bound on the local S2b-U endpoint. This module is the SDK
//! consumer for that re-entry point: [`GtpuReassemblyConsumer::process`]
//! applies the same PDR lookup, outer-endpoint binding validation, and inner
//! destination check as the tc fast path and returns the decapsulated inner
//! packet with its output bearer mark. Non-G-PDU GTP-U (echo, error
//! indication) is handed back for the control plane, matching the fast
//! path's pass-through.
//!
//! Reassembly itself stays in the kernel, so fragment memory and time are
//! bounded by `net.ipv4.ipfrag_*` rather than by any SDK state; the SDK never
//! holds a userspace fragment cache. Delivery of the decapsulated inner
//! packet (route/XFRM injection) is the embedding ePDG's choice and is
//! deliberately out of scope here.

use std::fmt;
use std::net::Ipv4Addr;

use opc_gtpu_ebpf_common::{
    parse_gtpu_tpdu, DownlinkBindingMismatch, DownlinkEndpointBinding, MarkedDownlinkPdr,
    MAX_REASSEMBLED_GTPU_LEN,
};

use crate::model::GtpBearerMark;

/// Exact outer provenance of one reassembled downlink GTP-U datagram.
///
/// The consumer receives these values from the delivery socket (peer address
/// and source port from the datagram source, local address and ingress
/// ifindex from the bound endpoint or `IP_PKTINFO`). They authorize the
/// datagram against the same canonical [`DownlinkEndpointBinding`] as the
/// tc fast path.
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

/// Stable, redaction-safe reason a reassembled datagram was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuReassemblyDrop {
    /// The reassembled message violates the GTP-U framing invariants.
    Malformed,
    /// No PDR exists for the G-PDU TEID.
    UnknownTeid,
    /// The outer provenance failed the canonical endpoint binding.
    BindingMismatch(DownlinkBindingMismatch),
    /// The inner destination does not match the session's UE PAA.
    DestinationMismatch,
}

/// Bounded counters of the post-reassembly consumer, mirroring the
/// fixed-cardinality datapath counters of the tc fast path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GtpuReassemblyCounters {
    /// Reassembled G-PDUs decapsulated and handed to the embedding ePDG.
    pub decapsulated: u64,
    /// Messages passed through for the control plane (non-G-PDU GTP-U).
    pub control_plane: u64,
    /// Reassembled messages dropped as malformed.
    pub malformed: u64,
    /// G-PDUs dropped for an unknown TEID.
    pub unknown_teid: u64,
    /// G-PDUs dropped by the outer-endpoint binding.
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
/// reassembly re-enters, backed by the caller's authoritative PDR and
/// endpoint-binding state.
///
/// The lookup closures are the integration seam: they must serve exactly the
/// state the tc fast path would consult (for the eBPF backend, the pinned
/// downlink PDR and endpoint-binding maps read back through the backend).
/// Keeping them caller-supplied makes the consumer backend-neutral and lets
/// the embedding ePDG decide how read-back state is refreshed.
pub struct GtpuReassemblyConsumer<P, B> {
    lookup_pdr: P,
    lookup_binding: B,
    counters: GtpuReassemblyCounters,
}

impl<P, B> fmt::Debug for GtpuReassemblyConsumer<P, B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GtpuReassemblyConsumer")
            .field("counters", &self.counters)
            .finish_non_exhaustive()
    }
}

impl<P, B> GtpuReassemblyConsumer<P, B>
where
    P: Fn([u8; 4]) -> Option<MarkedDownlinkPdr>,
    B: Fn([u8; 4]) -> Option<DownlinkEndpointBinding>,
{
    /// Construct a consumer over the given PDR and binding lookups.
    pub fn new(lookup_pdr: P, lookup_binding: B) -> Self {
        Self {
            lookup_pdr,
            lookup_binding,
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
            return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Malformed);
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
        let Some(pdr) = (self.lookup_pdr)(tpdu.teid) else {
            self.counters.unknown_teid += 1;
            return GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::UnknownTeid);
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
        let bearer_mark = u32::from_be_bytes(pdr.bearer_mark);
        let bearer_mark = GtpBearerMark::new(bearer_mark);
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

    type PdrLookup = Box<dyn Fn([u8; 4]) -> Option<MarkedDownlinkPdr>>;
    type BindingLookup = Box<dyn Fn([u8; 4]) -> Option<DownlinkEndpointBinding>>;

    fn pdr(mark: [u8; 4]) -> MarkedDownlinkPdr {
        MarkedDownlinkPdr {
            ue_ip: UE.octets(),
            bearer_mark: mark,
        }
    }

    fn consumer(mark: [u8; 4]) -> GtpuReassemblyConsumer<PdrLookup, BindingLookup> {
        GtpuReassemblyConsumer::new(
            Box::new(move |teid| (teid == TEID).then(|| pdr(mark))),
            Box::new(move |teid| (teid == TEID).then(binding)),
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
    fn authorized_datagram_decapsulates_exactly_once_with_output_mark() {
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
    fn default_bearer_decapsulates_without_mark() {
        let mut consumer = consumer([0; 4]);
        let outcome = consumer.process(&gpdu(TEID, &inner_packet(UE)), &provenance());
        assert!(matches!(
            outcome,
            GtpuReassemblyOutcome::Decapsulated {
                bearer_mark: None,
                ..
            }
        ));
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
            GtpuReassemblyOutcome::Dropped(GtpuReassemblyDrop::Malformed)
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
            move |teid| (teid == TEID).then(|| pdr([0; 4])),
            |_teid| None,
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
}
