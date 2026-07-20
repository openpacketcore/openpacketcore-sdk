//! Typed uplink PMTU/fragmentation decision and the downlink outer-fragment
//! contract.
//!
//! The uplink half turns the fixed [`GTPU_ENCAP_LEN`]-byte encapsulation into
//! a typed action: emit within the effective link MTU, emit oversized with DF
//! clear when the policy permits downstream outer fragmentation, or fail
//! closed with typed ICMP Packet-Too-Big guidance. It is pure `no_std` logic
//! shared between host-side callers and the tc uplink program so both enforce
//! the identical decision table.
//!
//! The downlink half states the backend-neutral outer-fragment contract: the
//! tc datapath hands outer fragments to the kernel stack unchanged and the
//! SDK's post-reassembly consumer feeds the reassembled GTP-U datagram back
//! into the SDK PDR/binding/decapsulation path. Reassembly resources stay in
//! the kernel's bounded `ipfrag` accounting; the SDK never holds an unbounded
//! userspace fragment cache.

use crate::{
    build_uplink_encap_with_dscp_and_source_port, ipv4_header_checksum, GTPU_ENCAP_LEN,
    IPV4_MIN_HDR_LEN,
};

/// Byte length of the single-slot uplink MTU policy map value.
///
/// Layout: effective link MTU (2 bytes, big endian), one flag byte, one
/// reserved zero byte. An all-zero value is the explicit unset state and
/// selects the legacy pre-policy behavior (only the IPv4 total-length `u16`
/// limit is enforced).
pub const UPLINK_PMTU_VALUE_LEN: usize = 4;

/// Policy flag: over-MTU encapsulations are emitted with DF clear, permitting
/// outer IPv4 fragmentation downstream (see
/// [`GtpuOuterFragmentPolicy::FragmentOuter`] for the exact semantics).
pub const UPLINK_PMTU_FLAG_FRAGMENT_PERMITTED: u8 = 1;

/// Minimum acceptable effective link MTU: the fixed encapsulation plus the
/// IPv4 minimum MTU of 68 (RFC 791 section 3.1), so at least one
/// minimum-size inner packet always fits.
pub const MIN_UPLINK_LINK_MTU: u16 = GTPU_ENCAP_LEN as u16 + 68;

/// Explicit uplink outer-fragmentation policy for one S2b-U link.
///
/// The default is fail closed: an over-MTU encapsulation is rejected with
/// typed PMTU guidance rather than silently emitted.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GtpuOuterFragmentPolicy {
    /// Reject over-MTU inner packets with typed Packet-Too-Big guidance. The
    /// DF bit is stamped on every emitted outer IPv4 header so downstream
    /// links report, rather than silently absorb, any residual MTU mismatch.
    ///
    /// On the eBPF tc backend this outcome is a silent, counted drop: the
    /// kernel datapath emits no ICMP itself, so the operator must size the
    /// inner MTU out of band (e.g. MSS clamping) or run a host component
    /// that consumes the typed signal (see `opc-gtpu-dataplane`'s PTB
    /// generation helper).
    #[default]
    SignalPacketTooBig,
    /// Emit over-MTU encapsulations with DF clear, relying on a downstream
    /// hop to fragment the outer IPv4 packet. The ePDG egress never
    /// fragments: the tc uplink program transmits via `bpf_redirect_neigh`,
    /// which bypasses the kernel's `ip_fragment` path, so the oversized
    /// frame leaves whole. This policy is safe only when the configured
    /// effective MTU is below the egress device's real MTU (so the emitted
    /// frame fits the device) *and* a downstream fragmenting hop exists;
    /// otherwise oversized frames risk silent drops by drivers or MRU-limited
    /// receivers. The inner packet is never fragmented by this datapath.
    FragmentOuter,
}

impl core::fmt::Debug for GtpuOuterFragmentPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SignalPacketTooBig => f.write_str("SignalPacketTooBig"),
            Self::FragmentOuter => f.write_str("FragmentOuter"),
        }
    }
}

/// Explicit uplink PMTU policy for one S2b-U link: the effective link MTU of
/// the GTP-U egress and the outer-fragmentation choice.
///
/// The effective link MTU is an input to this type (chosen by the operator or
/// read from the egress interface); choosing it is deliberately out of scope
/// for the dataplane. Construction bounds it to
/// [`MIN_UPLINK_LINK_MTU`]..=`u16::MAX` so the encapsulated minimum inner
/// packet always fits and the IPv4 total-length field cannot overflow.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct GtpuUplinkMtuPolicy {
    effective_link_mtu: u16,
    fragmentation: GtpuOuterFragmentPolicy,
}

impl core::fmt::Debug for GtpuUplinkMtuPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GtpuUplinkMtuPolicy")
            .field("effective_link_mtu", &self.effective_link_mtu)
            .field("fragmentation", &self.fragmentation)
            .finish()
    }
}

impl GtpuUplinkMtuPolicy {
    /// Construct one canonical policy. A link MTU below
    /// [`MIN_UPLINK_LINK_MTU`] cannot carry even the smallest inner packet
    /// and fails closed with `None`.
    #[must_use]
    pub const fn new(
        effective_link_mtu: u16,
        fragmentation: GtpuOuterFragmentPolicy,
    ) -> Option<Self> {
        if effective_link_mtu < MIN_UPLINK_LINK_MTU {
            None
        } else {
            Some(Self {
                effective_link_mtu,
                fragmentation,
            })
        }
    }

    /// Effective MTU of the GTP-U egress link, including every outer header.
    #[must_use]
    pub const fn effective_link_mtu(self) -> u16 {
        self.effective_link_mtu
    }

    /// Explicit outer-fragmentation choice.
    #[must_use]
    pub const fn fragmentation(self) -> GtpuOuterFragmentPolicy {
        self.fragmentation
    }

    /// Maximum inner packet length that encapsulates within the effective
    /// link MTU: the headroom accounting for the fixed [`GTPU_ENCAP_LEN`]
    /// overhead.
    #[must_use]
    pub const fn inner_mtu(self) -> u16 {
        self.effective_link_mtu - GTPU_ENCAP_LEN as u16
    }

    /// Encode into the fixed single-slot map value.
    #[must_use]
    pub const fn map_value(self) -> [u8; UPLINK_PMTU_VALUE_LEN] {
        let mtu = self.effective_link_mtu.to_be_bytes();
        let flags = match self.fragmentation {
            GtpuOuterFragmentPolicy::SignalPacketTooBig => 0,
            GtpuOuterFragmentPolicy::FragmentOuter => UPLINK_PMTU_FLAG_FRAGMENT_PERMITTED,
        };
        [mtu[0], mtu[1], flags, 0]
    }

    /// Decode a single-slot map value, retaining whether it was canonical.
    ///
    /// An all-zero value is the explicit unset state (legacy behavior), not
    /// corruption.
    #[must_use]
    pub const fn decode_map_value(value: &[u8; UPLINK_PMTU_VALUE_LEN]) -> UplinkMtuMapState {
        if value[0] == 0 && value[1] == 0 {
            if value[2] == 0 && value[3] == 0 {
                return UplinkMtuMapState::Unset;
            }
            return UplinkMtuMapState::Corrupt;
        }
        if value[3] != 0 || value[2] & !UPLINK_PMTU_FLAG_FRAGMENT_PERMITTED != 0 {
            return UplinkMtuMapState::Corrupt;
        }
        let fragmentation = if value[2] & UPLINK_PMTU_FLAG_FRAGMENT_PERMITTED == 0 {
            GtpuOuterFragmentPolicy::SignalPacketTooBig
        } else {
            GtpuOuterFragmentPolicy::FragmentOuter
        };
        match Self::new(u16::from_be_bytes([value[0], value[1]]), fragmentation) {
            Some(policy) => UplinkMtuMapState::Configured(policy),
            None => UplinkMtuMapState::Corrupt,
        }
    }
}

/// Decoded state of the single-slot uplink MTU policy map value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UplinkMtuMapState {
    /// All-zero value: no MTU policy is configured and the datapath enforces
    /// only the legacy IPv4 total-length limit.
    Unset,
    /// One canonical configured policy.
    Configured(GtpuUplinkMtuPolicy),
    /// Non-canonical persisted state; every consumer fails closed.
    Corrupt,
}

/// Protocol family of the ICMP Packet-Too-Big signal toward the inner source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GtpuPmtuProtocol {
    /// ICMPv4 Destination Unreachable, "fragmentation needed and DF set"
    /// (RFC 792 type 3 code 4) with the RFC 1191 next-hop MTU field.
    Icmpv4,
    /// ICMPv6 Packet Too Big (RFC 8200 section 5, RFC 8201 type 2).
    Icmpv6,
}

/// ICMPv4 type for Destination Unreachable.
pub const ICMPV4_TYPE_DESTINATION_UNREACHABLE: u8 = 3;
/// ICMPv4 code for "fragmentation needed and DF set" (RFC 792, RFC 1191).
///
/// This tunnel never fragments inner packets, so the signal is generated for
/// any over-MTU inner packet regardless of the inner packet's own DF bit —
/// the inner DF constraint is satisfied vacuously.
pub const ICMPV4_CODE_FRAGMENTATION_NEEDED_DF_SET: u8 = 4;
/// ICMPv6 type for Packet Too Big (RFC 8200 section 5).
pub const ICMPV6_TYPE_PACKET_TOO_BIG: u8 = 2;

/// Typed Packet-Too-Big guidance the ePDG generates toward the inner source
/// when uplink encapsulation is rejected for size.
///
/// The advertised MTU is always the inner-facing MTU (effective link MTU
/// minus the fixed encapsulation overhead), so the inner source learns the
/// largest inner packet the tunnel can carry. Values carry only bounded
/// lengths and protocol constants; no address or session state is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuPmtuSignal {
    /// ICMPv4 Destination Unreachable / fragmentation-needed (type
    /// [`ICMPV4_TYPE_DESTINATION_UNREACHABLE`], code
    /// [`ICMPV4_CODE_FRAGMENTATION_NEEDED_DF_SET`]) advertising this
    /// inner-facing next-hop MTU per RFC 1191.
    Icmpv4FragmentationNeeded {
        /// Inner-facing MTU advertised to the inner source.
        inner_mtu: u16,
    },
    /// ICMPv6 Packet Too Big (type [`ICMPV6_TYPE_PACKET_TOO_BIG`])
    /// advertising this inner-facing MTU per RFC 8200/RFC 8201.
    Icmpv6PacketTooBig {
        /// Inner-facing MTU advertised to the inner source.
        inner_mtu: u16,
    },
}

impl GtpuPmtuSignal {
    /// Build the signal for one inner packet family and inner-facing MTU.
    #[must_use]
    pub const fn new(protocol: GtpuPmtuProtocol, inner_mtu: u16) -> Self {
        match protocol {
            GtpuPmtuProtocol::Icmpv4 => Self::Icmpv4FragmentationNeeded { inner_mtu },
            GtpuPmtuProtocol::Icmpv6 => Self::Icmpv6PacketTooBig { inner_mtu },
        }
    }

    /// The inner-facing MTU advertised by this signal.
    #[must_use]
    pub const fn inner_mtu(self) -> u16 {
        match self {
            Self::Icmpv4FragmentationNeeded { inner_mtu } => inner_mtu,
            Self::Icmpv6PacketTooBig { inner_mtu } => inner_mtu,
        }
    }
}

/// Typed outcome of one uplink encapsulation attempt under an MTU policy.
///
/// The `encap` bytes in the emit variants contain the outer addresses and
/// TEID, so `Debug` redacts them exactly like the other wire-carrying types
/// in this crate; only bounded lengths and protocol constants are shown.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UplinkEncapOutcome {
    /// The encapsulated packet fits the effective link MTU; emit it.
    Emit {
        /// Exact encapsulation bytes to prepend (DF stamped under the
        /// [`GtpuOuterFragmentPolicy::SignalPacketTooBig`] policy).
        encap: [u8; GTPU_ENCAP_LEN],
        /// Remaining link-MTU headroom after encapsulation.
        headroom: u16,
    },
    /// The encapsulated packet exceeds the effective link MTU and the policy
    /// permits downstream outer fragmentation; emit it with DF clear. The
    /// ePDG egress never fragments itself (see
    /// [`GtpuOuterFragmentPolicy::FragmentOuter`]); the inner packet is
    /// delivered unfragmented inside one G-PDU.
    EmitOuterFragmented {
        /// Exact encapsulation bytes to prepend (DF clear).
        encap: [u8; GTPU_ENCAP_LEN],
        /// Bytes by which the encapsulated packet exceeds the effective MTU.
        excess: u16,
    },
    /// Fail-closed rejection: nothing is emitted and the inner packet is
    /// never leaked unencapsulated. On the eBPF tc backend this is a silent,
    /// counted drop; a host caller generates the typed Packet-Too-Big signal
    /// toward the inner source.
    RejectTooBig {
        /// ICMP guidance toward the inner source.
        signal: GtpuPmtuSignal,
        /// Fixed encapsulation overhead accounted against the link MTU.
        encap_overhead: u16,
        /// Encapsulated total length that exceeded the effective link MTU.
        attempted_total: u32,
    },
}

impl core::fmt::Debug for UplinkEncapOutcome {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Emit { headroom, .. } => f
                .debug_struct("Emit")
                .field("encap", &"<redacted>")
                .field("headroom", headroom)
                .finish(),
            Self::EmitOuterFragmented { excess, .. } => f
                .debug_struct("EmitOuterFragmented")
                .field("encap", &"<redacted>")
                .field("excess", excess)
                .finish(),
            Self::RejectTooBig {
                signal,
                encap_overhead,
                attempted_total,
            } => f
                .debug_struct("RejectTooBig")
                .field("signal", signal)
                .field("encap_overhead", encap_overhead)
                .field("attempted_total", attempted_total)
                .finish(),
        }
    }
}

/// Stamp the IPv4 DF bit on a built encapsulation and refresh the outer
/// header checksum.
///
/// The builder emits flags/fragment-offset zero, so only the DF bit can
/// change; the checksum is recomputed over the complete option-free header.
pub fn stamp_ipv4_dont_fragment(encap: &mut [u8; GTPU_ENCAP_LEN]) {
    encap[6] |= 0x40;
    encap[10] = 0;
    encap[11] = 0;
    let mut header = [0_u8; IPV4_MIN_HDR_LEN];
    header.copy_from_slice(&encap[..IPV4_MIN_HDR_LEN]);
    let checksum = ipv4_header_checksum(&header);
    encap[10] = checksum.to_be_bytes()[0];
    encap[11] = checksum.to_be_bytes()[1];
}

/// Apply a configured MTU policy to an already-built encapsulation, stamping
/// DF when the policy requires it.
///
/// Returns `false` when the encapsulated packet exceeds the effective link
/// MTU and the policy does not permit outer fragmentation: the caller must
/// drop fail closed (never emitting the inner packet unencapsulated) and
/// surface [`UplinkEncapOutcome::RejectTooBig`] guidance where it can.
/// This is the exact gate the tc uplink program executes; host callers
/// should prefer [`decide_uplink_encap`], which composes the builder and
/// this gate into the typed outcome.
#[must_use]
pub fn apply_uplink_mtu_policy(
    encap: &mut [u8; GTPU_ENCAP_LEN],
    policy: GtpuUplinkMtuPolicy,
) -> bool {
    let outer_total = u32::from(u16::from_be_bytes([encap[2], encap[3]]));
    if outer_total > u32::from(policy.effective_link_mtu) {
        return matches!(policy.fragmentation, GtpuOuterFragmentPolicy::FragmentOuter);
    }
    if matches!(
        policy.fragmentation,
        GtpuOuterFragmentPolicy::SignalPacketTooBig
    ) {
        stamp_ipv4_dont_fragment(encap);
    }
    true
}

/// Decide the typed uplink encapsulation action under an explicit MTU policy.
///
/// `inner_family` selects the ICMP protocol used in
/// [`UplinkEncapOutcome::RejectTooBig`] guidance; it must match the actual
/// inner packet family of the caller's datapath (the current tc datapath is
/// IPv4-inner only). Input validation (DSCP range, reserved source port zero,
/// IPv4 total-length `u16` limit) fails closed with `None`, exactly matching
/// [`build_uplink_encap_with_dscp_and_source_port`].
#[must_use]
pub fn decide_uplink_encap(
    far: &crate::UplinkFar,
    inner_len: u16,
    dscp: Option<u8>,
    source_port: u16,
    mtu_policy: GtpuUplinkMtuPolicy,
    inner_family: GtpuPmtuProtocol,
) -> Option<UplinkEncapOutcome> {
    let mut encap =
        build_uplink_encap_with_dscp_and_source_port(far, inner_len, dscp, source_port)?;
    let outer_total = u32::from(inner_len) + GTPU_ENCAP_LEN as u32;
    let link_mtu = u32::from(mtu_policy.effective_link_mtu);
    if outer_total <= link_mtu {
        if matches!(
            mtu_policy.fragmentation,
            GtpuOuterFragmentPolicy::SignalPacketTooBig
        ) {
            stamp_ipv4_dont_fragment(&mut encap);
        }
        Some(UplinkEncapOutcome::Emit {
            encap,
            headroom: (link_mtu - outer_total) as u16,
        })
    } else {
        match mtu_policy.fragmentation {
            GtpuOuterFragmentPolicy::FragmentOuter => {
                Some(UplinkEncapOutcome::EmitOuterFragmented {
                    encap,
                    excess: (outer_total - link_mtu) as u16,
                })
            }
            GtpuOuterFragmentPolicy::SignalPacketTooBig => Some(UplinkEncapOutcome::RejectTooBig {
                signal: GtpuPmtuSignal::new(inner_family, mtu_policy.inner_mtu()),
                encap_overhead: GTPU_ENCAP_LEN as u16,
                attempted_total: outer_total,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::format;

    use super::*;
    use crate::UplinkFar;

    fn far() -> UplinkFar {
        UplinkFar {
            peer_ip: [192, 0, 2, 10],
            local_ip: [192, 0, 2, 1],
            o_teid: [0x20, 0x00, 0x00, 0x01],
        }
    }

    fn strict_policy(link_mtu: u16) -> GtpuUplinkMtuPolicy {
        GtpuUplinkMtuPolicy::new(link_mtu, GtpuOuterFragmentPolicy::SignalPacketTooBig).unwrap()
    }

    #[test]
    fn policy_construction_bounds_and_headroom_accounting() {
        assert!(GtpuUplinkMtuPolicy::new(
            MIN_UPLINK_LINK_MTU - 1,
            GtpuOuterFragmentPolicy::FragmentOuter
        )
        .is_none());
        let policy =
            GtpuUplinkMtuPolicy::new(MIN_UPLINK_LINK_MTU, GtpuOuterFragmentPolicy::FragmentOuter)
                .unwrap();
        assert_eq!(policy.inner_mtu(), 68);
        assert_eq!(
            strict_policy(1500).inner_mtu(),
            1500 - GTPU_ENCAP_LEN as u16
        );
        assert!(
            GtpuUplinkMtuPolicy::new(u16::MAX, GtpuOuterFragmentPolicy::FragmentOuter).is_some()
        );
    }

    #[test]
    fn policy_map_value_round_trips_and_zero_is_unset_not_corrupt() {
        assert_eq!(
            GtpuUplinkMtuPolicy::decode_map_value(&[0; UPLINK_PMTU_VALUE_LEN]),
            UplinkMtuMapState::Unset
        );
        for fragmentation in [
            GtpuOuterFragmentPolicy::SignalPacketTooBig,
            GtpuOuterFragmentPolicy::FragmentOuter,
        ] {
            let policy = GtpuUplinkMtuPolicy::new(1500, fragmentation).unwrap();
            assert_eq!(
                GtpuUplinkMtuPolicy::decode_map_value(&policy.map_value()),
                UplinkMtuMapState::Configured(policy)
            );
        }
        let strict = strict_policy(1400).map_value();
        assert_eq!(strict, [0x05, 0x78, 0, 0]);
        let fragment = GtpuUplinkMtuPolicy::new(1400, GtpuOuterFragmentPolicy::FragmentOuter)
            .unwrap()
            .map_value();
        assert_eq!(fragment, [0x05, 0x78, 1, 0]);
    }

    #[test]
    fn policy_map_value_rejects_every_noncanonical_byte() {
        // MTU below the minimum.
        assert_eq!(
            GtpuUplinkMtuPolicy::decode_map_value(&[0, 60, 0, 0]),
            UplinkMtuMapState::Corrupt
        );
        // Unknown flag bits.
        assert_eq!(
            GtpuUplinkMtuPolicy::decode_map_value(&[0x05, 0x78, 2, 0]),
            UplinkMtuMapState::Corrupt
        );
        // Reserved byte.
        assert_eq!(
            GtpuUplinkMtuPolicy::decode_map_value(&[0x05, 0x78, 0, 1]),
            UplinkMtuMapState::Corrupt
        );
        // Zero MTU with nonzero flags or reserved bytes is corrupt, not unset.
        assert_eq!(
            GtpuUplinkMtuPolicy::decode_map_value(&[0, 0, 1, 0]),
            UplinkMtuMapState::Corrupt
        );
        assert_eq!(
            GtpuUplinkMtuPolicy::decode_map_value(&[0, 0, 0, 1]),
            UplinkMtuMapState::Corrupt
        );
    }

    #[test]
    fn emit_within_mtu_reports_headroom_and_stamps_df_for_strict_policy() {
        let outcome = decide_uplink_encap(
            &far(),
            1400,
            Some(46),
            40_000,
            strict_policy(1500),
            GtpuPmtuProtocol::Icmpv4,
        )
        .unwrap();
        let UplinkEncapOutcome::Emit { encap, headroom } = outcome else {
            panic!("expected Emit, got {outcome:?}");
        };
        assert_eq!(headroom, 1500 - 1400 - GTPU_ENCAP_LEN as u16);
        assert_eq!(encap[6] & 0x40, 0x40, "strict policy must stamp DF");
        let mut header = [0_u8; IPV4_MIN_HDR_LEN];
        header.copy_from_slice(&encap[..IPV4_MIN_HDR_LEN]);
        assert_eq!(
            u16::from_be_bytes([encap[10], encap[11]]),
            ipv4_header_checksum(&header),
            "DF stamping must refresh the outer checksum"
        );
        // DSCP and source-port stamping survive the policy gate.
        assert_eq!(encap[1], 46 << 2);
        assert_eq!(u16::from_be_bytes([encap[20], encap[21]]), 40_000);
    }

    #[test]
    fn emit_within_mtu_keeps_df_clear_under_fragment_policy() {
        let outcome = decide_uplink_encap(
            &far(),
            1400,
            None,
            crate::GTPU_UDP_PORT,
            GtpuUplinkMtuPolicy::new(1500, GtpuOuterFragmentPolicy::FragmentOuter).unwrap(),
            GtpuPmtuProtocol::Icmpv4,
        )
        .unwrap();
        let UplinkEncapOutcome::Emit { encap, .. } = outcome else {
            panic!("expected Emit, got {outcome:?}");
        };
        assert_eq!(encap[6] & 0x40, 0);
        // Byte-for-byte identical to the pre-policy builder when no DF stamp
        // applies.
        assert_eq!(
            encap,
            build_uplink_encap_with_dscp_and_source_port(&far(), 1400, None, crate::GTPU_UDP_PORT)
                .unwrap()
        );
    }

    #[test]
    fn boundary_packet_exactly_at_mtu_emits_with_zero_headroom() {
        let inner_len = 1500 - GTPU_ENCAP_LEN as u16;
        for fragmentation in [
            GtpuOuterFragmentPolicy::SignalPacketTooBig,
            GtpuOuterFragmentPolicy::FragmentOuter,
        ] {
            let policy = GtpuUplinkMtuPolicy::new(1500, fragmentation).unwrap();
            let outcome = decide_uplink_encap(
                &far(),
                inner_len,
                None,
                crate::GTPU_UDP_PORT,
                policy,
                GtpuPmtuProtocol::Icmpv4,
            )
            .unwrap();
            let UplinkEncapOutcome::Emit { headroom, .. } = outcome else {
                panic!("expected Emit at the exact boundary, got {outcome:?}");
            };
            assert_eq!(headroom, 0);
        }
    }

    #[test]
    fn over_mtu_rejects_fail_closed_with_typed_pmtu_guidance() {
        let outcome = decide_uplink_encap(
            &far(),
            1480,
            None,
            crate::GTPU_UDP_PORT,
            strict_policy(1500),
            GtpuPmtuProtocol::Icmpv4,
        )
        .unwrap();
        assert_eq!(
            outcome,
            UplinkEncapOutcome::RejectTooBig {
                signal: GtpuPmtuSignal::Icmpv4FragmentationNeeded { inner_mtu: 1464 },
                encap_overhead: GTPU_ENCAP_LEN as u16,
                attempted_total: 1516,
            }
        );
        let ipv6 = decide_uplink_encap(
            &far(),
            1480,
            None,
            crate::GTPU_UDP_PORT,
            strict_policy(1500),
            GtpuPmtuProtocol::Icmpv6,
        )
        .unwrap();
        assert_eq!(
            ipv6,
            UplinkEncapOutcome::RejectTooBig {
                signal: GtpuPmtuSignal::Icmpv6PacketTooBig { inner_mtu: 1464 },
                encap_overhead: GTPU_ENCAP_LEN as u16,
                attempted_total: 1516,
            }
        );
        assert_eq!(ICMPV4_TYPE_DESTINATION_UNREACHABLE, 3);
        assert_eq!(ICMPV4_CODE_FRAGMENTATION_NEEDED_DF_SET, 4);
        assert_eq!(ICMPV6_TYPE_PACKET_TOO_BIG, 2);
    }

    #[test]
    fn over_mtu_emits_outer_fragmented_only_when_permitted() {
        let outcome = decide_uplink_encap(
            &far(),
            1480,
            None,
            crate::GTPU_UDP_PORT,
            GtpuUplinkMtuPolicy::new(1500, GtpuOuterFragmentPolicy::FragmentOuter).unwrap(),
            GtpuPmtuProtocol::Icmpv4,
        )
        .unwrap();
        let UplinkEncapOutcome::EmitOuterFragmented { encap, excess } = outcome else {
            panic!("expected EmitOuterFragmented, got {outcome:?}");
        };
        assert_eq!(excess, 16);
        assert_eq!(encap[6] & 0x40, 0, "outer fragmentation requires DF clear");
        assert_eq!(u16::from_be_bytes([encap[2], encap[3]]), 1516);
    }

    #[test]
    fn invalid_inputs_fail_closed_like_the_legacy_builder() {
        assert!(decide_uplink_encap(
            &far(),
            60,
            Some(64),
            crate::GTPU_UDP_PORT,
            strict_policy(1500),
            GtpuPmtuProtocol::Icmpv4,
        )
        .is_none());
        assert!(decide_uplink_encap(
            &far(),
            60,
            None,
            0,
            strict_policy(1500),
            GtpuPmtuProtocol::Icmpv4,
        )
        .is_none());
        assert!(decide_uplink_encap(
            &far(),
            u16::MAX - 35,
            None,
            crate::GTPU_UDP_PORT,
            GtpuUplinkMtuPolicy::new(u16::MAX, GtpuOuterFragmentPolicy::FragmentOuter).unwrap(),
            GtpuPmtuProtocol::Icmpv4,
        )
        .is_none());
    }

    #[test]
    fn apply_gate_matches_decide_for_both_policies() {
        let mut encap =
            build_uplink_encap_with_dscp_and_source_port(&far(), 1480, None, crate::GTPU_UDP_PORT)
                .unwrap();
        assert!(!apply_uplink_mtu_policy(&mut encap, strict_policy(1500)));
        assert_eq!(
            encap[6] & 0x40,
            0,
            "a rejected encapsulation is never DF-stamped or emitted"
        );
        let fragment =
            GtpuUplinkMtuPolicy::new(1500, GtpuOuterFragmentPolicy::FragmentOuter).unwrap();
        assert!(apply_uplink_mtu_policy(&mut encap, fragment));
        let mut fitting =
            build_uplink_encap_with_dscp_and_source_port(&far(), 1400, None, crate::GTPU_UDP_PORT)
                .unwrap();
        assert!(apply_uplink_mtu_policy(&mut fitting, strict_policy(1500)));
        assert_eq!(fitting[6] & 0x40, 0x40);
    }

    #[test]
    fn outcome_debug_redacts_encap_bytes_in_every_variant() {
        let emit = decide_uplink_encap(
            &far(),
            1400,
            Some(46),
            40_000,
            strict_policy(1500),
            GtpuPmtuProtocol::Icmpv4,
        )
        .unwrap();
        let fragmented = decide_uplink_encap(
            &far(),
            1480,
            None,
            40_000,
            GtpuUplinkMtuPolicy::new(1500, GtpuOuterFragmentPolicy::FragmentOuter).unwrap(),
            GtpuPmtuProtocol::Icmpv4,
        )
        .unwrap();
        let rejected = decide_uplink_encap(
            &far(),
            1480,
            None,
            crate::GTPU_UDP_PORT,
            strict_policy(1500),
            GtpuPmtuProtocol::Icmpv4,
        )
        .unwrap();
        for outcome in [emit, fragmented, rejected] {
            let debug = format!("{outcome:?}");
            // The outer addresses, TEID, and selected port live in the encap
            // bytes and must never appear in diagnostics.
            for forbidden in ["192", "32, 0, 0, 1", "40000", "0x20"] {
                assert!(!debug.contains(forbidden), "leaked {forbidden} in {debug}");
            }
        }
        let emit_debug = format!("{emit:?}");
        assert!(emit_debug.contains("<redacted>"));
        assert!(emit_debug.contains("headroom"));
        let rejected_debug = format!("{rejected:?}");
        assert!(rejected_debug.contains("Icmpv4FragmentationNeeded"));
    }
}
