//! Backend-neutral downlink outer-fragment contract and the post-reassembly
//! GTP-U consumer parser.
//!
//! The tc downlink program hands outer IPv4 fragments to the kernel stack
//! unchanged (`TC_ACT_OK`). The kernel reassembles them under its bounded
//! `ipfrag` accounting and delivers exactly one complete UDP/2152 datagram to
//! the SDK consumer bound on the local S2b-U endpoint. That consumer feeds
//! the datagram back into the same PDR/binding/decapsulation semantics as the
//! tc fast path; [`parse_gtpu_tpdu`] is the shared wire parser for that
//! re-entry point. The SDK never holds a userspace fragment cache, so
//! reassembly memory and time stay bounded by the kernel's configured
//! limits and are reported through the backend capability surface.

use crate::{classify_gtpu, GtpuClass, GTPU_MANDATORY_HDR_LEN, GTPU_MAX_EXT_HEADERS, GTPU_OPT_LEN};

/// Explicit downlink outer-fragment handling contract of a GTP-U backend.
///
/// `KernelReassemblyHandoff` is the complete contract for fragmented outer
/// packets: the datapath passes every outer fragment to the kernel stack,
/// the kernel reassembles under bounded `net.ipv4.ipfrag_*` resources, and
/// exactly one reassembled GTP-U datagram re-enters the SDK consumer, which
/// applies the identical PDR/binding/decapsulation path as unfragmented
/// traffic. A backend that cannot demonstrate that re-entry must report
/// [`GtpuDownlinkFragmentContract::Unsupported`] rather than silently
/// dropping or ignoring fragments.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum GtpuDownlinkFragmentContract {
    /// The backend has no demonstrated post-reassembly GTP-U consumer.
    #[default]
    Unsupported,
    /// Fragments are handed to the kernel for bounded reassembly and the
    /// reassembled datagram demonstrably re-enters the SDK GTP-U consumer
    /// exactly once.
    KernelReassemblyHandoff {
        /// Bounded reassembly resource statement in force.
        bounds: GtpuReassemblyBounds,
    },
}

/// Bounded reassembly resource statement for the kernel-handoff contract.
///
/// Reassembly is performed by the kernel, so these bounds describe the
/// configured `ipfrag` limits the backend relies on: the maximum bytes held
/// across all in-flight reassembly contexts and the maximum time an
/// incomplete fragment set is retained before eviction. Every incomplete,
/// duplicated, overlapping, or timed-out fragment set is dropped by the
/// kernel inside these bounds and never reaches the SDK consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GtpuReassemblyBounds {
    /// Maximum total bytes held by in-flight fragment reassembly.
    pub max_inflight_bytes: u32,
    /// Maximum seconds an incomplete fragment set is retained.
    pub timeout_seconds: u32,
}

/// Linux default reassembly bounds (`net.ipv4.ipfrag_high_thresh` = 4 MiB,
/// `net.ipv4.ipfrag_time` = 30 s), used when the backend cannot read the
/// live sysctl values.
pub const LINUX_DEFAULT_REASSEMBLY_BOUNDS: GtpuReassemblyBounds = GtpuReassemblyBounds {
    max_inflight_bytes: 4 * 1024 * 1024,
    timeout_seconds: 30,
};

/// Maximum byte length of one reassembled GTP-U datagram admitted to the
/// post-reassembly consumer: the largest UDP payload over IPv4.
pub const MAX_REASSEMBLED_GTPU_LEN: usize = u16::MAX as usize - 20 - 8;

/// Stable, redaction-safe reason a reassembled GTP-U message was rejected by
/// the post-reassembly parser.
///
/// Variants intentionally contain no addresses, TEIDs, or payload bytes. The
/// consumer maps every variant to its bounded malformed-packet counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuTpduError {
    /// The message is shorter than the mandatory GTP-U header.
    TruncatedHeader,
    /// The GTP-U length field does not end exactly at the message end.
    InconsistentLength,
    /// The optional field block overruns the declared message end.
    MalformedOptionalBlock,
    /// The extension-header chain is unterminated, oversized, or exceeds the
    /// bounded walk depth.
    MalformedExtensionChain,
    /// The T-PDU is absent or shorter than a minimum inner IPv4 header.
    TruncatedPayload,
}

/// One validated G-PDU T-PDU view over a complete reassembled GTP-U message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GtpuTpdu<'a> {
    /// TEID exactly as on the wire, network order.
    pub teid: [u8; 4],
    /// The T-PDU (inner packet) bytes.
    pub payload: &'a [u8],
}

/// Parse one complete reassembled GTP-U message (the UDP payload delivered to
/// the consumer) with exactly the mandatory-header classification, optional
/// block, and bounded extension-header walk of the tc downlink fast path.
///
/// Returns `Ok(None)` for messages the fast path passes through untouched —
/// non-GTPv1 and non-G-PDU GTP-U (echo, error indication) — so the consumer
/// hands them to the control plane rather than dropping them. Malformed
/// declarations fail closed with a bounded typed reason.
///
/// # Errors
///
/// Returns a fieldless [`GtpuTpduError`] when the message violates the
/// TS 29.281 framing invariants the fast path enforces.
pub fn parse_gtpu_tpdu(message: &[u8]) -> Result<Option<GtpuTpdu<'_>>, GtpuTpduError> {
    if message.len() < GTPU_MANDATORY_HDR_LEN {
        return Err(GtpuTpduError::TruncatedHeader);
    }
    let header: [u8; GTPU_MANDATORY_HDR_LEN] = message[..GTPU_MANDATORY_HDR_LEN]
        .try_into()
        .map_err(|_| GtpuTpduError::TruncatedHeader)?;
    let (teid, declared_length, has_opt, has_ext) = match classify_gtpu(&header) {
        GtpuClass::NotGtpV1 | GtpuClass::NotGpdu => return Ok(None),
        GtpuClass::Gpdu {
            teid,
            length,
            has_opt,
            has_ext,
        } => (teid, length, has_opt, has_ext),
    };
    let gtp_end = GTPU_MANDATORY_HDR_LEN
        .checked_add(usize::from(declared_length))
        .ok_or(GtpuTpduError::InconsistentLength)?;
    if gtp_end != message.len() {
        return Err(GtpuTpduError::InconsistentLength);
    }

    let mut payload_offset = GTPU_MANDATORY_HDR_LEN;
    if has_opt {
        let optional_end = payload_offset
            .checked_add(GTPU_OPT_LEN)
            .ok_or(GtpuTpduError::MalformedOptionalBlock)?;
        if optional_end > gtp_end {
            return Err(GtpuTpduError::MalformedOptionalBlock);
        }
        let next_ext_at = payload_offset + GTPU_OPT_LEN - 1;
        payload_offset = optional_end;
        if has_ext {
            let mut next_ext = message[next_ext_at];
            let mut walked = 0;
            while next_ext != 0 {
                if walked == GTPU_MAX_EXT_HEADERS || payload_offset >= gtp_end {
                    return Err(GtpuTpduError::MalformedExtensionChain);
                }
                let ext_len_units = message[payload_offset];
                if ext_len_units == 0 {
                    return Err(GtpuTpduError::MalformedExtensionChain);
                }
                let ext_len = usize::from(ext_len_units)
                    .checked_mul(4)
                    .ok_or(GtpuTpduError::MalformedExtensionChain)?;
                let ext_end = payload_offset
                    .checked_add(ext_len)
                    .ok_or(GtpuTpduError::MalformedExtensionChain)?;
                if ext_end > gtp_end {
                    return Err(GtpuTpduError::MalformedExtensionChain);
                }
                payload_offset = ext_end;
                next_ext = message[ext_end - 1];
                walked += 1;
            }
        }
    }
    if payload_offset >= gtp_end || gtp_end - payload_offset < 20 {
        return Err(GtpuTpduError::TruncatedPayload);
    }
    Ok(Some(GtpuTpdu {
        teid,
        payload: &message[payload_offset..],
    }))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec;
    use std::vec::Vec;

    use super::*;

    fn gpdu(teid: [u8; 4], flags: u8, body: &[u8]) -> Vec<u8> {
        let mut message = vec![flags, 0xFF, 0, 0, teid[0], teid[1], teid[2], teid[3]];
        let declared = u16::try_from(message.len() - GTPU_MANDATORY_HDR_LEN + body.len()).unwrap();
        message[2..4].copy_from_slice(&declared.to_be_bytes());
        message.extend_from_slice(body);
        message
    }

    fn inner() -> Vec<u8> {
        // Minimum inner IPv4 header plus payload.
        let mut inner = vec![
            0x45, 0, 0, 24, 0, 0, 0, 0, 64, 17, 0, 0, 10, 45, 0, 2, 10, 45, 0, 2,
        ];
        inner.extend_from_slice(b"data");
        inner
    }

    #[test]
    fn complete_gpdu_yields_teid_and_exact_tpdu() {
        let message = gpdu([0x10, 0, 0, 1], 0x30, &inner());
        let tpdu = parse_gtpu_tpdu(&message).unwrap().unwrap();
        assert_eq!(tpdu.teid, [0x10, 0, 0, 1]);
        assert_eq!(tpdu.payload, &inner());
    }

    #[test]
    fn non_gpdu_and_non_v1_messages_pass_to_the_control_plane() {
        // Echo request (message type 1), S flag set.
        let mut echo = gpdu([0; 4], 0x32, &[0; 4]);
        echo[1] = 0x01;
        assert_eq!(parse_gtpu_tpdu(&echo), Ok(None));
        // GTPv2 flags.
        let mut v2 = gpdu([0; 4], 0x48, &inner());
        assert_eq!(parse_gtpu_tpdu(&v2), Ok(None));
        v2[0] = 0x20; // PT clear (GTP').
        assert_eq!(parse_gtpu_tpdu(&v2), Ok(None));
    }

    #[test]
    fn optional_block_and_bounded_extension_walk_match_the_fast_path() {
        let mut body = vec![0, 1, 0, 0x85]; // optional block, next ext type 0x85
                                            // One extension header: two 4-byte units, terminated by type 0.
        body.extend_from_slice(&[2, 0xaa, 0xbb, 0, 0xcc, 0xdd, 0xee, 0]);
        body.extend_from_slice(&inner());
        let message = gpdu([0x10, 0, 0, 2], 0x34, &body);
        let tpdu = parse_gtpu_tpdu(&message).unwrap().unwrap();
        assert_eq!(tpdu.payload, &inner());
    }

    #[test]
    fn malformed_messages_fail_closed_with_bounded_reasons() {
        assert_eq!(
            parse_gtpu_tpdu(&[0x30; 7]),
            Err(GtpuTpduError::TruncatedHeader)
        );

        // Declared length disagrees with the message end.
        let mut bad_length = gpdu([0x10, 0, 0, 1], 0x30, &inner());
        let declared = u16::from_be_bytes([bad_length[2], bad_length[3]]);
        bad_length[2..4].copy_from_slice(&(declared + 1).to_be_bytes());
        assert_eq!(
            parse_gtpu_tpdu(&bad_length),
            Err(GtpuTpduError::InconsistentLength)
        );

        // Optional block overruns the declared end.
        let short_opt = gpdu([0x10, 0, 0, 1], 0x32, &[0, 1, 0]);
        assert_eq!(
            parse_gtpu_tpdu(&short_opt),
            Err(GtpuTpduError::MalformedOptionalBlock)
        );

        // Zero-length extension unit.
        let mut body = vec![0, 1, 0, 0x85, 0, 0, 0, 0];
        body.extend_from_slice(&inner());
        assert_eq!(
            parse_gtpu_tpdu(&gpdu([0x10, 0, 0, 1], 0x34, &body)),
            Err(GtpuTpduError::MalformedExtensionChain)
        );

        // Extension chain runs past the declared end.
        let mut body = vec![0, 1, 0, 0x85, 1, 0, 0, 0x85];
        body.extend_from_slice(&inner());
        assert_eq!(
            parse_gtpu_tpdu(&gpdu([0x10, 0, 0, 1], 0x34, &body)),
            Err(GtpuTpduError::MalformedExtensionChain)
        );

        // A terminated chain that leaves no room for a minimum inner packet.
        let mut body = vec![0, 1, 0, 0x85, 1, 0, 0, 0];
        body.extend_from_slice(&[0x45; 19]);
        assert_eq!(
            parse_gtpu_tpdu(&gpdu([0x10, 0, 0, 1], 0x34, &body)),
            Err(GtpuTpduError::TruncatedPayload)
        );

        // Extension walk depth exceeds the bounded maximum.
        let mut body = vec![0, 1, 0, 0x85];
        for _ in 0..=GTPU_MAX_EXT_HEADERS {
            body.extend_from_slice(&[1, 0, 0, 0x85]);
        }
        body.extend_from_slice(&inner());
        assert_eq!(
            parse_gtpu_tpdu(&gpdu([0x10, 0, 0, 1], 0x34, &body)),
            Err(GtpuTpduError::MalformedExtensionChain)
        );

        // T-PDU shorter than a minimum inner IPv4 header.
        assert_eq!(
            parse_gtpu_tpdu(&gpdu([0x10, 0, 0, 1], 0x30, &[0x45; 19])),
            Err(GtpuTpduError::TruncatedPayload)
        );
        assert_eq!(
            parse_gtpu_tpdu(&gpdu([0x10, 0, 0, 1], 0x30, &[])),
            Err(GtpuTpduError::TruncatedPayload)
        );
    }

    #[test]
    fn reassembly_bounds_and_contract_are_bounded_and_copyable() {
        let contract = GtpuDownlinkFragmentContract::KernelReassemblyHandoff {
            bounds: LINUX_DEFAULT_REASSEMBLY_BOUNDS,
        };
        let GtpuDownlinkFragmentContract::KernelReassemblyHandoff { bounds } = contract else {
            panic!("expected handoff contract");
        };
        assert_eq!(bounds.max_inflight_bytes, 4 * 1024 * 1024);
        assert_eq!(bounds.timeout_seconds, 30);
        assert_eq!(MAX_REASSEMBLED_GTPU_LEN, 65507);
        assert_eq!(
            GtpuDownlinkFragmentContract::default(),
            GtpuDownlinkFragmentContract::Unsupported
        );
    }
}
