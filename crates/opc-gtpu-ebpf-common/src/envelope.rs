//! Verifier-friendly bounds and checksum primitives for downlink GTP-U.

use crate::{ETH_HDR_LEN, GTPU_MANDATORY_HDR_LEN, IPV4_MIN_HDR_LEN, UDP_HDR_LEN};

/// Maximum IPv4 header length, including options.
pub const IPV4_MAX_HDR_LEN: usize = 60;

/// Stable, redaction-safe reason an outer GTP-U envelope was rejected.
///
/// Variants intentionally contain no addresses, TEIDs, payload bytes, lengths,
/// or checksum values. The eBPF datapath maps every variant to its single
/// bounded malformed-packet counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GtpuEnvelopeError {
    /// The IPv4 version or IHL field is invalid.
    InvalidIpv4Header,
    /// IPv4 Total Length cannot contain its header, UDP, and mandatory GTP-U.
    InvalidIpv4TotalLength,
    /// IPv4 Total Length extends beyond the accessible packet.
    TruncatedIpv4Packet,
    /// The complete variable-IHL IPv4 header checksum is invalid.
    InvalidIpv4Checksum,
    /// UDP Length is smaller than the UDP header.
    InvalidUdpLength,
    /// UDP Length does not end exactly at IPv4 Total Length.
    InconsistentUdpBoundary,
    /// UDP checksum handling was neither proven omission, valid, nor verified.
    InvalidUdpChecksum,
    /// UDP Length cannot contain the mandatory GTP-U header.
    TruncatedGtpuHeader,
    /// GTP-U Length does not end exactly at the UDP payload boundary.
    InconsistentGtpuBoundary,
}

/// Checked bounds of a complete outer IPv4 packet carrying UDP and GTP-U.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4EnvelopeBounds {
    ip_header_len: usize,
    ip_end: usize,
    udp_offset: usize,
}

impl Ipv4EnvelopeBounds {
    /// Validate IPv4 version, IHL, Total Length, and accessible-packet bounds.
    ///
    /// `skb_len` includes the Ethernet header and any legal layer-2 padding.
    /// The returned `ip_end` is derived only from IPv4 Total Length, so padding
    /// is never admitted to a later UDP or GTP-U boundary.
    ///
    /// # Errors
    ///
    /// Returns a fieldless [`GtpuEnvelopeError`] when the IPv4 declaration is
    /// malformed, too small for UDP plus mandatory GTP-U, or truncated.
    pub fn parse(
        skb_len: usize,
        version_ihl: u8,
        total_length: u16,
    ) -> Result<Self, GtpuEnvelopeError> {
        let ihl_words = usize::from(version_ihl & 0x0f);
        if version_ihl >> 4 != 4 || ihl_words < 5 {
            return Err(GtpuEnvelopeError::InvalidIpv4Header);
        }
        let ip_header_len = ihl_words
            .checked_mul(4)
            .ok_or(GtpuEnvelopeError::InvalidIpv4Header)?;
        if !(IPV4_MIN_HDR_LEN..=IPV4_MAX_HDR_LEN).contains(&ip_header_len) {
            return Err(GtpuEnvelopeError::InvalidIpv4Header);
        }
        let minimum_total_length = ip_header_len
            .checked_add(UDP_HDR_LEN)
            .and_then(|length| length.checked_add(GTPU_MANDATORY_HDR_LEN))
            .ok_or(GtpuEnvelopeError::InvalidIpv4TotalLength)?;
        let total_length = usize::from(total_length);
        if total_length < minimum_total_length {
            return Err(GtpuEnvelopeError::InvalidIpv4TotalLength);
        }
        let ip_end = ETH_HDR_LEN
            .checked_add(total_length)
            .ok_or(GtpuEnvelopeError::InvalidIpv4TotalLength)?;
        if ip_end > skb_len {
            return Err(GtpuEnvelopeError::TruncatedIpv4Packet);
        }
        let udp_offset = ETH_HDR_LEN
            .checked_add(ip_header_len)
            .ok_or(GtpuEnvelopeError::InvalidIpv4Header)?;
        Ok(Self {
            ip_header_len,
            ip_end,
            udp_offset,
        })
    }

    /// Complete IPv4 header length, including options.
    #[must_use]
    pub const fn ip_header_len(self) -> usize {
        self.ip_header_len
    }

    /// Exclusive IPv4 packet end derived from Total Length.
    #[must_use]
    pub const fn ip_end(self) -> usize {
        self.ip_end
    }

    /// Offset of the UDP header from the Ethernet frame start.
    #[must_use]
    pub const fn udp_offset(self) -> usize {
        self.udp_offset
    }
}

/// Checked bounds of UDP nested exactly inside an outer IPv4 packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpEnvelopeBounds {
    ipv4: Ipv4EnvelopeBounds,
    udp_end: usize,
    gtp_offset: usize,
}

impl UdpEnvelopeBounds {
    /// Validate UDP Length and its exact relationship to IPv4 Total Length.
    ///
    /// # Errors
    ///
    /// Returns a fieldless [`GtpuEnvelopeError`] when UDP is shorter than its
    /// header, cannot contain mandatory GTP-U, overflows, or does not end at
    /// the declared IPv4 boundary.
    pub fn parse(ipv4: Ipv4EnvelopeBounds, udp_length: u16) -> Result<Self, GtpuEnvelopeError> {
        let udp_length = usize::from(udp_length);
        if udp_length < UDP_HDR_LEN {
            return Err(GtpuEnvelopeError::InvalidUdpLength);
        }
        let minimum_gtpu_length = UDP_HDR_LEN
            .checked_add(GTPU_MANDATORY_HDR_LEN)
            .ok_or(GtpuEnvelopeError::TruncatedGtpuHeader)?;
        if udp_length < minimum_gtpu_length {
            return Err(GtpuEnvelopeError::TruncatedGtpuHeader);
        }
        let udp_end = ipv4
            .udp_offset
            .checked_add(udp_length)
            .ok_or(GtpuEnvelopeError::InconsistentUdpBoundary)?;
        if udp_end != ipv4.ip_end {
            return Err(GtpuEnvelopeError::InconsistentUdpBoundary);
        }
        let gtp_offset = ipv4
            .udp_offset
            .checked_add(UDP_HDR_LEN)
            .ok_or(GtpuEnvelopeError::TruncatedGtpuHeader)?;
        Ok(Self {
            ipv4,
            udp_end,
            gtp_offset,
        })
    }

    /// Checked outer IPv4 bounds.
    #[must_use]
    pub const fn ipv4(self) -> Ipv4EnvelopeBounds {
        self.ipv4
    }

    /// Exclusive UDP end, equal to the declared IPv4 end.
    #[must_use]
    pub const fn udp_end(self) -> usize {
        self.udp_end
    }

    /// Offset of the mandatory GTP-U header.
    #[must_use]
    pub const fn gtp_offset(self) -> usize {
        self.gtp_offset
    }
}

/// Checked exact nesting of GTP-U inside UDP inside IPv4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GtpuEnvelopeBounds {
    udp: UdpEnvelopeBounds,
    gtp_end: usize,
}

impl GtpuEnvelopeBounds {
    /// Validate the TS 29.281 GTP-U Length field against the UDP payload end.
    ///
    /// # Errors
    ///
    /// Returns [`GtpuEnvelopeError::InconsistentGtpuBoundary`] unless the
    /// mandatory eight-byte header plus the declared post-header length ends
    /// exactly at the UDP and IPv4 boundary.
    pub fn parse(udp: UdpEnvelopeBounds, gtpu_length: u16) -> Result<Self, GtpuEnvelopeError> {
        let gtp_end = udp
            .gtp_offset
            .checked_add(GTPU_MANDATORY_HDR_LEN)
            .and_then(|end| end.checked_add(usize::from(gtpu_length)))
            .ok_or(GtpuEnvelopeError::InconsistentGtpuBoundary)?;
        if gtp_end != udp.udp_end {
            return Err(GtpuEnvelopeError::InconsistentGtpuBoundary);
        }
        Ok(Self { udp, gtp_end })
    }

    /// Checked UDP bounds.
    #[must_use]
    pub const fn udp(self) -> UdpEnvelopeBounds {
        self.udp
    }

    /// Exclusive GTP-U end, equal to both the UDP and IPv4 ends.
    #[must_use]
    pub const fn gtp_end(self) -> usize {
        self.gtp_end
    }
}

/// How a received IPv4 UDP checksum must be handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpChecksumDisposition {
    /// A zero IPv4 UDP checksum is legally omitted by RFC 768, and the caller
    /// has proved that no partial checksum operation remains pending.
    Omitted,
    /// The kernel positively reports `CHECKSUM_UNNECESSARY` for this skb.
    KernelVerified,
    /// Packet bytes must be validated in software before decapsulation.
    SoftwareRequired,
}

/// Evidence available for classifying one received UDP checksum field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpChecksumEvidence {
    /// The caller proved that no checksum offload operation remains pending.
    ///
    /// Byte-only parsers have this evidence inherently. A live skb caller must
    /// independently exclude `CHECKSUM_PARTIAL` before selecting this variant.
    NoPendingOffload,
    /// The kernel positively authenticated the current checksum layer.
    KernelVerified,
    /// The checksum bytes are not authenticated and offload state is unresolved.
    ///
    /// This includes helper errors and any live skb state that may still be
    /// `CHECKSUM_PARTIAL`.
    Unverified,
}

/// Classify an IPv4 UDP checksum from explicit checksum-state evidence.
///
/// A zero field is classified as legal omission only with
/// [`UdpChecksumEvidence::NoPendingOffload`]. In particular, callers must not
/// treat a failed `CHECKSUM_UNNECESSARY` query as proof of omission because it
/// does not distinguish `CHECKSUM_NONE` from `CHECKSUM_PARTIAL`.
#[must_use]
pub const fn classify_udp_checksum(
    checksum: u16,
    evidence: UdpChecksumEvidence,
) -> UdpChecksumDisposition {
    match evidence {
        UdpChecksumEvidence::KernelVerified => UdpChecksumDisposition::KernelVerified,
        UdpChecksumEvidence::NoPendingOffload if checksum == 0 => UdpChecksumDisposition::Omitted,
        UdpChecksumEvidence::NoPendingOffload | UdpChecksumEvidence::Unverified => {
            UdpChecksumDisposition::SoftwareRequired
        }
    }
}

/// Return whether a checksum-helper accumulator includes a valid checksum.
///
/// This folds the `u32` ones-complement sum returned by `bpf_csum_diff`.
#[must_use]
pub const fn internet_checksum_sum_is_valid(sum: u32) -> bool {
    let first = (sum & 0xffff) + (sum >> 16);
    let second = (first & 0xffff) + (first >> 16);
    second == 0xffff
}

fn add_checksum_word(sum: u32, word: u16) -> u32 {
    let expanded = sum + u32::from(word);
    (expanded & 0xffff) + (expanded >> 16)
}

fn add_checksum_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut offset = 0;
    while offset + 1 < bytes.len() {
        sum = add_checksum_word(sum, u16::from_be_bytes([bytes[offset], bytes[offset + 1]]));
        offset += 2;
    }
    if offset < bytes.len() {
        sum = add_checksum_word(sum, u16::from(bytes[offset]) << 8);
    }
    sum
}

fn checksum_from_sum(sum: u32) -> u16 {
    let folded = (sum & 0xffff) + (sum >> 16);
    !(folded as u16)
}

/// Compute an RFC 1071 Internet checksum over arbitrary bytes.
///
/// An odd final octet is padded on the right with zero. To verify a header,
/// call this function with its checksum field intact and require zero.
#[must_use]
pub fn internet_checksum(bytes: &[u8]) -> u16 {
    checksum_from_sum(add_checksum_bytes(0, bytes))
}

/// Compute the IPv4 UDP checksum for a UDP header and payload.
///
/// `udp` must contain exactly the UDP Length bytes and its checksum field must
/// be zero. The IPv4 pseudo-header is included. A computed zero is encoded as
/// `0xffff`, as required by RFC 768 to distinguish it from checksum omission.
/// Returns `None` when the slice cannot be represented by UDP Length.
#[must_use]
pub fn udp_ipv4_checksum(source: [u8; 4], destination: [u8; 4], udp: &[u8]) -> Option<u16> {
    let length = u16::try_from(udp.len()).ok()?;
    let mut sum = add_checksum_bytes(0, &source);
    sum = add_checksum_bytes(sum, &destination);
    sum = add_checksum_word(sum, u16::from(17_u8));
    sum = add_checksum_word(sum, length);
    sum = add_checksum_bytes(sum, udp);
    let checksum = checksum_from_sum(sum);
    Some(if checksum == 0 { 0xffff } else { checksum })
}

/// Verify a non-zero IPv4 UDP checksum over its exact declared bytes.
///
/// A zero checksum is not accepted here; callers must first classify it as
/// [`UdpChecksumDisposition::Omitted`]. Oversized slices fail closed.
#[must_use]
pub fn udp_ipv4_checksum_is_valid(source: [u8; 4], destination: [u8; 4], udp: &[u8]) -> bool {
    let Ok(length) = u16::try_from(udp.len()) else {
        return false;
    };
    if udp.len() < UDP_HDR_LEN || (udp[6] == 0 && udp[7] == 0) {
        return false;
    }
    let mut sum = add_checksum_bytes(0, &source);
    sum = add_checksum_bytes(sum, &destination);
    sum = add_checksum_word(sum, u16::from(17_u8));
    sum = add_checksum_word(sum, length);
    sum = add_checksum_bytes(sum, udp);
    internet_checksum_sum_is_valid(sum)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use std::vec;
    use std::vec::Vec;

    use super::*;

    const SOURCE: [u8; 4] = [192, 0, 2, 1];
    const DESTINATION: [u8; 4] = [198, 51, 100, 2];

    fn read_u16(frame: &[u8], offset: usize) -> Result<u16, GtpuEnvelopeError> {
        let bytes = frame
            .get(offset..offset + 2)
            .ok_or(GtpuEnvelopeError::TruncatedIpv4Packet)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn validate_frame(
        frame: &[u8],
        kernel_verified_udp: bool,
    ) -> Result<GtpuEnvelopeBounds, GtpuEnvelopeError> {
        let version_ihl = *frame
            .get(ETH_HDR_LEN)
            .ok_or(GtpuEnvelopeError::TruncatedIpv4Packet)?;
        let total_length = read_u16(frame, ETH_HDR_LEN + 2)?;
        let ipv4 = Ipv4EnvelopeBounds::parse(frame.len(), version_ihl, total_length)?;
        let header_end = ETH_HDR_LEN
            .checked_add(ipv4.ip_header_len())
            .ok_or(GtpuEnvelopeError::InvalidIpv4Header)?;
        let header = frame
            .get(ETH_HDR_LEN..header_end)
            .ok_or(GtpuEnvelopeError::TruncatedIpv4Packet)?;
        if internet_checksum(header) != 0 {
            return Err(GtpuEnvelopeError::InvalidIpv4Checksum);
        }
        let udp_length = read_u16(frame, ipv4.udp_offset() + 4)?;
        let udp = UdpEnvelopeBounds::parse(ipv4, udp_length)?;
        let udp_checksum = read_u16(frame, ipv4.udp_offset() + 6)?;
        let checksum_evidence = if kernel_verified_udp {
            UdpChecksumEvidence::KernelVerified
        } else {
            // This parser owns complete frame bytes rather than a live skb, so
            // no pending kernel checksum operation exists.
            UdpChecksumEvidence::NoPendingOffload
        };
        if matches!(
            classify_udp_checksum(udp_checksum, checksum_evidence),
            UdpChecksumDisposition::SoftwareRequired
        ) {
            let udp_bytes = frame
                .get(ipv4.udp_offset()..udp.udp_end())
                .ok_or(GtpuEnvelopeError::InconsistentUdpBoundary)?;
            let source = frame
                .get(ETH_HDR_LEN + 12..ETH_HDR_LEN + 16)
                .ok_or(GtpuEnvelopeError::TruncatedIpv4Packet)?;
            let destination = frame
                .get(ETH_HDR_LEN + 16..ETH_HDR_LEN + 20)
                .ok_or(GtpuEnvelopeError::TruncatedIpv4Packet)?;
            if !udp_ipv4_checksum_is_valid(
                [source[0], source[1], source[2], source[3]],
                [
                    destination[0],
                    destination[1],
                    destination[2],
                    destination[3],
                ],
                udp_bytes,
            ) {
                return Err(GtpuEnvelopeError::InvalidUdpChecksum);
            }
        }
        let gtpu_length = read_u16(frame, udp.gtp_offset() + 2)?;
        GtpuEnvelopeBounds::parse(udp, gtpu_length)
    }

    fn build_frame(
        ip_options: &[u8],
        gtpu_body: &[u8],
        checksum_udp: bool,
        padding_len: usize,
    ) -> Vec<u8> {
        assert_eq!(ip_options.len() % 4, 0);
        assert!(ip_options.len() <= IPV4_MAX_HDR_LEN - IPV4_MIN_HDR_LEN);
        let ip_header_len = IPV4_MIN_HDR_LEN + ip_options.len();
        let gtpu_length = GTPU_MANDATORY_HDR_LEN + gtpu_body.len();
        let udp_length = UDP_HDR_LEN + gtpu_length;
        let ip_total_length = ip_header_len + udp_length;
        let mut frame = vec![0_u8; ETH_HDR_LEN + ip_total_length + padding_len];
        frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        let ip = ETH_HDR_LEN;
        frame[ip] = 0x40 | u8::try_from(ip_header_len / 4).unwrap();
        frame[ip + 2..ip + 4]
            .copy_from_slice(&u16::try_from(ip_total_length).unwrap().to_be_bytes());
        frame[ip + 8] = 64;
        frame[ip + 9] = 17;
        frame[ip + 12..ip + 16].copy_from_slice(&SOURCE);
        frame[ip + 16..ip + 20].copy_from_slice(&DESTINATION);
        frame[ip + IPV4_MIN_HDR_LEN..ip + ip_header_len].copy_from_slice(ip_options);
        let udp = ip + ip_header_len;
        frame[udp..udp + 2].copy_from_slice(&2152_u16.to_be_bytes());
        frame[udp + 2..udp + 4].copy_from_slice(&2152_u16.to_be_bytes());
        frame[udp + 4..udp + 6].copy_from_slice(&u16::try_from(udp_length).unwrap().to_be_bytes());
        let gtpu = udp + UDP_HDR_LEN;
        frame[gtpu] = 0x30;
        frame[gtpu + 1] = 0xff;
        frame[gtpu + 2..gtpu + 4]
            .copy_from_slice(&u16::try_from(gtpu_body.len()).unwrap().to_be_bytes());
        frame[gtpu + 4..gtpu + 8].copy_from_slice(&0x1020_3040_u32.to_be_bytes());
        frame[gtpu + GTPU_MANDATORY_HDR_LEN..gtpu + gtpu_length].copy_from_slice(gtpu_body);

        let ip_checksum = internet_checksum(&frame[ip..udp]);
        frame[ip + 10..ip + 12].copy_from_slice(&ip_checksum.to_be_bytes());
        if checksum_udp {
            let checksum =
                udp_ipv4_checksum(SOURCE, DESTINATION, &frame[udp..udp + udp_length]).unwrap();
            frame[udp + 6..udp + 8].copy_from_slice(&checksum.to_be_bytes());
        }
        frame
    }

    fn refresh_ip_checksum(frame: &mut [u8]) {
        let ip = ETH_HDR_LEN;
        let header_len = usize::from(frame[ip] & 0x0f) * 4;
        frame[ip + 10..ip + 12].fill(0);
        let checksum = internet_checksum(&frame[ip..ip + header_len]);
        frame[ip + 10..ip + 12].copy_from_slice(&checksum.to_be_bytes());
    }

    fn refresh_udp_checksum(frame: &mut [u8]) {
        let ip = ETH_HDR_LEN;
        let header_len = usize::from(frame[ip] & 0x0f) * 4;
        let udp = ip + header_len;
        let udp_length = usize::from(u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]));
        frame[udp + 6..udp + 8].fill(0);
        let checksum =
            udp_ipv4_checksum(SOURCE, DESTINATION, &frame[udp..udp + udp_length]).unwrap();
        frame[udp + 6..udp + 8].copy_from_slice(&checksum.to_be_bytes());
    }

    #[test]
    fn minimum_and_option_bearing_frames_have_exact_nested_bounds() {
        for (options, body, checksum_udp, padding) in [
            (&[][..], &[0x45, 0, 0, 20][..], false, 0),
            (&[1, 1, 0, 0][..], &[0x45, 1, 2, 3, 4][..], true, 18),
            (
                &[1, 1, 1, 1, 1, 1, 0, 0][..],
                &[0x45, 1, 2, 3, 4, 5][..],
                true,
                0,
            ),
        ] {
            let frame = build_frame(options, body, checksum_udp, padding);
            let bounds = validate_frame(&frame, false).unwrap();
            assert_eq!(bounds.gtp_end(), bounds.udp().udp_end());
            assert_eq!(bounds.gtp_end(), bounds.udp().ipv4().ip_end());
            assert!(bounds.gtp_end() <= frame.len());
            assert_eq!(frame.len() - bounds.gtp_end(), padding);
        }
    }

    #[test]
    fn ipv4_bounds_reject_bad_ihl_total_length_and_truncation() {
        assert_eq!(
            Ipv4EnvelopeBounds::parse(128, 0x44, 64),
            Err(GtpuEnvelopeError::InvalidIpv4Header)
        );
        assert_eq!(
            Ipv4EnvelopeBounds::parse(128, 0x65, 64),
            Err(GtpuEnvelopeError::InvalidIpv4Header)
        );
        assert_eq!(
            Ipv4EnvelopeBounds::parse(128, 0x45, 35),
            Err(GtpuEnvelopeError::InvalidIpv4TotalLength)
        );
        assert_eq!(
            Ipv4EnvelopeBounds::parse(49, 0x45, 36),
            Err(GtpuEnvelopeError::TruncatedIpv4Packet)
        );
        let padded = Ipv4EnvelopeBounds::parse(usize::MAX, 0x4f, u16::MAX).unwrap();
        assert_eq!(padded.ip_header_len(), IPV4_MAX_HDR_LEN);
        assert!(padded.ip_end() < usize::MAX);
    }

    #[test]
    fn udp_and_gtpu_bounds_reject_every_non_exact_nesting() {
        let ipv4 = Ipv4EnvelopeBounds::parse(256, 0x45, 100).unwrap();
        assert_eq!(
            UdpEnvelopeBounds::parse(ipv4, 7),
            Err(GtpuEnvelopeError::InvalidUdpLength)
        );
        assert_eq!(
            UdpEnvelopeBounds::parse(ipv4, 8),
            Err(GtpuEnvelopeError::TruncatedGtpuHeader)
        );
        for length in [79_u16, 81] {
            assert_eq!(
                UdpEnvelopeBounds::parse(ipv4, length),
                Err(GtpuEnvelopeError::InconsistentUdpBoundary)
            );
        }
        let udp = UdpEnvelopeBounds::parse(ipv4, 80).unwrap();
        for length in [63_u16, 65] {
            assert_eq!(
                GtpuEnvelopeBounds::parse(udp, length),
                Err(GtpuEnvelopeError::InconsistentGtpuBoundary)
            );
        }
        let exact = GtpuEnvelopeBounds::parse(udp, 64).unwrap();
        assert_eq!(exact.gtp_end(), exact.udp().udp_end());
        assert_eq!(exact.gtp_end(), exact.udp().ipv4().ip_end());
    }

    #[test]
    fn variable_ihl_ipv4_checksum_covers_options() {
        let mut frame = build_frame(&[0x94, 4, 0, 0], &[0x45, 1, 2, 3], false, 0);
        validate_frame(&frame, false).unwrap();
        frame[ETH_HDR_LEN + IPV4_MIN_HDR_LEN] ^= 1;
        assert_eq!(
            validate_frame(&frame, false),
            Err(GtpuEnvelopeError::InvalidIpv4Checksum)
        );
    }

    #[test]
    fn rfc768_style_udp_vectors_cover_odd_and_even_lengths() {
        for (payload, expected) in [(&b"odd"[..], 0x2f6c_u16), (&b"even"[..], 0x37ea)] {
            let mut udp = vec![0_u8; UDP_HDR_LEN + payload.len()];
            udp[0..2].copy_from_slice(&2152_u16.to_be_bytes());
            udp[2..4].copy_from_slice(&2152_u16.to_be_bytes());
            let udp_length = u16::try_from(udp.len()).unwrap();
            udp[4..6].copy_from_slice(&udp_length.to_be_bytes());
            udp[UDP_HDR_LEN..].copy_from_slice(payload);
            assert_eq!(udp_ipv4_checksum(SOURCE, DESTINATION, &udp), Some(expected));
            udp[6..8].copy_from_slice(&expected.to_be_bytes());
            assert!(udp_ipv4_checksum_is_valid(SOURCE, DESTINATION, &udp));
            udp[UDP_HDR_LEN] ^= 1;
            assert!(!udp_ipv4_checksum_is_valid(SOURCE, DESTINATION, &udp));
        }
    }

    #[test]
    fn udp_checksum_disposition_requires_explicit_no_pending_offload_evidence() {
        assert_eq!(
            classify_udp_checksum(0, UdpChecksumEvidence::NoPendingOffload),
            UdpChecksumDisposition::Omitted
        );
        assert_eq!(
            classify_udp_checksum(0, UdpChecksumEvidence::Unverified),
            UdpChecksumDisposition::SoftwareRequired
        );
        assert_eq!(
            classify_udp_checksum(0x1234, UdpChecksumEvidence::KernelVerified),
            UdpChecksumDisposition::KernelVerified
        );
        assert_eq!(
            classify_udp_checksum(0x1234, UdpChecksumEvidence::Unverified),
            UdpChecksumDisposition::SoftwareRequired
        );
    }

    #[test]
    fn frame_fixtures_reject_ip_udp_and_gtpu_boundary_disagreement() {
        let base = build_frame(&[1, 1, 0, 0], &[0x45; 32], true, 8);
        let ip = ETH_HDR_LEN;
        let udp = ip + 24;
        let gtpu = udp + UDP_HDR_LEN;

        let mut invalid_ip_checksum = base.clone();
        invalid_ip_checksum[ip + 8] ^= 1;
        assert_eq!(
            validate_frame(&invalid_ip_checksum, false),
            Err(GtpuEnvelopeError::InvalidIpv4Checksum)
        );

        let mut truncated = base.clone();
        truncated.truncate(base.len() - 9);
        assert_eq!(
            validate_frame(&truncated, false),
            Err(GtpuEnvelopeError::TruncatedIpv4Packet)
        );

        for adjustment in [-1_i16, 1] {
            let mut inconsistent_ip = base.clone();
            let current = read_u16(&inconsistent_ip, ip + 2).unwrap();
            inconsistent_ip[ip + 2..ip + 4]
                .copy_from_slice(&current.wrapping_add_signed(adjustment).to_be_bytes());
            refresh_ip_checksum(&mut inconsistent_ip);
            assert_eq!(
                validate_frame(&inconsistent_ip, false),
                Err(GtpuEnvelopeError::InconsistentUdpBoundary)
            );

            let mut inconsistent_udp = base.clone();
            let current = read_u16(&inconsistent_udp, udp + 4).unwrap();
            inconsistent_udp[udp + 4..udp + 6]
                .copy_from_slice(&current.wrapping_add_signed(adjustment).to_be_bytes());
            assert_eq!(
                validate_frame(&inconsistent_udp, false),
                Err(GtpuEnvelopeError::InconsistentUdpBoundary)
            );

            let mut inconsistent_gtpu = base.clone();
            let current = read_u16(&inconsistent_gtpu, gtpu + 2).unwrap();
            inconsistent_gtpu[gtpu + 2..gtpu + 4]
                .copy_from_slice(&current.wrapping_add_signed(adjustment).to_be_bytes());
            refresh_udp_checksum(&mut inconsistent_gtpu);
            assert_eq!(
                validate_frame(&inconsistent_gtpu, false),
                Err(GtpuEnvelopeError::InconsistentGtpuBoundary)
            );
        }

        let mut invalid_udp_checksum = base;
        invalid_udp_checksum[gtpu + GTPU_MANDATORY_HDR_LEN] ^= 1;
        assert_eq!(
            validate_frame(&invalid_udp_checksum, false),
            Err(GtpuEnvelopeError::InvalidUdpChecksum)
        );
    }

    #[test]
    fn property_every_accepted_envelope_has_exact_bounded_ends() {
        let edge_skb_lengths = [0, 1, ETH_HDR_LEN, usize::MAX - 1, usize::MAX];
        for skb_len in edge_skb_lengths {
            for version_ihl in [0_u8, 0x44, 0x45, 0x4f, 0x55, 0xff] {
                for total_length in [0_u16, 35, 36, 60, u16::MAX] {
                    let _ = Ipv4EnvelopeBounds::parse(skb_len, version_ihl, total_length);
                }
            }
        }

        let mut state = 0x9e37_79b9_u32;
        for _ in 0..50_000 {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            let version_ihl = (state >> 24) as u8;
            let total_length = state as u16;
            let skb_len = usize::from((state >> 8) as u16);
            let Ok(ipv4) = Ipv4EnvelopeBounds::parse(skb_len, version_ihl, total_length) else {
                continue;
            };
            state = state.rotate_left(13).wrapping_add(0xa5a5_5a5a);
            let Ok(udp) = UdpEnvelopeBounds::parse(ipv4, state as u16) else {
                continue;
            };
            state = state.rotate_right(7).wrapping_mul(2_654_435_761);
            let Ok(gtpu) = GtpuEnvelopeBounds::parse(udp, state as u16) else {
                continue;
            };
            assert_eq!(gtpu.gtp_end(), gtpu.udp().udp_end());
            assert_eq!(gtpu.gtp_end(), gtpu.udp().ipv4().ip_end());
            assert!(gtpu.gtp_end() <= skb_len);
        }

        for body_length in 0_u16..=1_024 {
            let udp_length = u32::from(body_length) + 16;
            let total_length = udp_length + 20;
            let skb_length = usize::try_from(total_length + ETH_HDR_LEN as u32 + 32).unwrap();
            let ipv4 =
                Ipv4EnvelopeBounds::parse(skb_length, 0x45, u16::try_from(total_length).unwrap())
                    .unwrap();
            let udp = UdpEnvelopeBounds::parse(ipv4, u16::try_from(udp_length).unwrap()).unwrap();
            let gtpu = GtpuEnvelopeBounds::parse(udp, body_length).unwrap();
            assert_eq!(gtpu.gtp_end(), gtpu.udp().udp_end());
            assert_eq!(gtpu.gtp_end(), gtpu.udp().ipv4().ip_end());
            assert!(gtpu.gtp_end() <= skb_length);
        }
    }
}
