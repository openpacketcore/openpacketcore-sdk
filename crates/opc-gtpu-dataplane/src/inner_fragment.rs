//! RFC 791 fragmentation of one downlink inner IPv4 datagram before
//! encapsulation: the eBPF backend's default policy for an authorized inner
//! packet with Don't Fragment set that exceeds its session's downlink inner
//! MTU (RFC 4459 section 3.4; see
//! [`GtpuDownlinkOversizePolicy::FragmentInner`](crate::GtpuDownlinkOversizePolicy::FragmentInner)).
//!
//! The procedure is RFC 791 section 3.2 ("An Example Fragmentation
//! Procedure"), generalized to an n-way split as it permits. Every fragment
//! but the last carries the largest multiple of 8 data octets that fits the
//! MTU, so the count is minimal and the fragments are produced in order (RFC
//! 1812 section 4.2.2.7). The original header is copied; the total length,
//! More Fragments flag, fragment offset and header checksum are set per
//! fragment, and Don't Fragment is cleared. Clearing DF is the owner-approved
//! policy: RFC 791 section 2.3 and RFC 6864 section 4.3 forbid fragmenting a
//! DF datagram or clearing DF in transit, and RFC 1191 section 4 has a router
//! discard it and signal the originator instead.
//!
//! Before any work, the header is validated as RFC 1812 section 5.2.2
//! requires of a router: version, header length, header checksum, and a
//! total length that covers the header and is not truncated. Octets beyond
//! the total length are not part of the datagram and are ignored, as the
//! kernel's receive path trims them. A datagram with IPv4 options is refused:
//! this path implements neither the RFC 791 option copy rules nor a router's
//! Record Route and Timestamp processing.

use bytes::{Bytes, BytesMut};
use opc_gtpu_ebpf_common::internet_checksum;

const IPV4_HEADER_LEN: usize = 20;
/// RFC 791 section 3.1 flags: bit 0 reserved, bit 1 DF, bit 2 MF.
const FLAG_DONT_FRAGMENT: u16 = 0x4000;
const FLAG_MORE_FRAGMENTS: u16 = 0x2000;
const FRAGMENT_OFFSET_MASK: u16 = 0x1fff;
/// RFC 791 section 3.1: the Total Length field bounds a datagram.
const IPV4_MAX_DATAGRAM_LEN: usize = 65_535;

/// Why one over-MTU inner packet is not fragmented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) enum InnerFragmentRefusal {
    /// The header fails an RFC 1812 section 5.2.2 check, or the datagram's
    /// data would extend past the 65,535-octet RFC 791 limit.
    Malformed,
    /// The datagram carries IPv4 options.
    Options,
}

/// Validate an IPv4 header as RFC 1812 section 5.2.2 requires of a router,
/// and RFC 1122 section 3.2.1.2 of a host: version 4, a header length of at
/// least 20 octets, a correct header checksum, and a total length that covers
/// the header and is not truncated. Returns the header and total lengths, or
/// `None` for a packet to discard silently.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn valid_ipv4_header(packet: &[u8]) -> Option<(usize, usize)> {
    let first = *packet.first()?;
    let header_len = usize::from(first & 0x0f) * 4;
    if first >> 4 != 4 || header_len < IPV4_HEADER_LEN {
        return None;
    }
    let header = packet.get(..header_len)?;
    if internet_checksum(header) != 0 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
    (header_len..=packet.len())
        .contains(&total_len)
        .then_some((header_len, total_len))
}

/// One validated, option-free IPv4 datagram (possibly itself a fragment).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct Ipv4FragmentSource<'a> {
    header: [u8; IPV4_HEADER_LEN],
    data: &'a [u8],
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl<'a> Ipv4FragmentSource<'a> {
    /// Validate `packet`, whose first octet begins the IPv4 header.
    pub(crate) fn parse(packet: &'a [u8]) -> Result<Self, InnerFragmentRefusal> {
        use InnerFragmentRefusal::{Malformed, Options};
        let (header_len, total_len) = valid_ipv4_header(packet).ok_or(Malformed)?;
        if header_len != IPV4_HEADER_LEN {
            return Err(Options);
        }
        let mut header = [0_u8; IPV4_HEADER_LEN];
        header.copy_from_slice(&packet[..IPV4_HEADER_LEN]);
        let data = &packet[IPV4_HEADER_LEN..total_len];
        let source = Self { header, data };
        // A fragment's data must end within the largest datagram, which also
        // keeps every new fragment offset within its 13 bits.
        if source.offset_octets() + IPV4_HEADER_LEN + data.len() > IPV4_MAX_DATAGRAM_LEN {
            return Err(Malformed);
        }
        Ok(source)
    }

    fn flags_and_offset(&self) -> u16 {
        u16::from_be_bytes([self.header[6], self.header[7]])
    }

    fn offset_octets(&self) -> usize {
        usize::from(self.flags_and_offset() & FRAGMENT_OFFSET_MASK) * 8
    }

    /// The datagram's own Identification.
    pub(crate) fn identification(&self) -> u16 {
        u16::from_be_bytes([self.header[4], self.header[5]])
    }

    /// RFC 6864 section 4: an atomic datagram has DF set, MF clear and a
    /// zero fragment offset. Its Identification has no meaning.
    pub(crate) fn is_atomic(&self) -> bool {
        let flags = self.flags_and_offset();
        flags & FLAG_DONT_FRAGMENT != 0
            && flags & FLAG_MORE_FRAGMENTS == 0
            && flags & FRAGMENT_OFFSET_MASK == 0
    }

    /// Split into fragments of at most `mtu` octets that all carry
    /// `identification`. Returns `None` when `mtu` cannot carry the header
    /// and 8 data octets or when the datagram already fits.
    pub(crate) fn fragment(&self, mtu: u16, identification: u16) -> Option<Vec<Bytes>> {
        let payload_per_fragment = usize::from(mtu).checked_sub(IPV4_HEADER_LEN)? & !7;
        if payload_per_fragment == 0 || IPV4_HEADER_LEN + self.data.len() <= usize::from(mtu) {
            return None;
        }
        let original = self.flags_and_offset();
        let reserved =
            original & !(FLAG_DONT_FRAGMENT | FLAG_MORE_FRAGMENTS | FRAGMENT_OFFSET_MASK);
        let original_units = original & FRAGMENT_OFFSET_MASK;
        let count = self.data.len().div_ceil(payload_per_fragment);
        let mut buffer = BytesMut::with_capacity(self.data.len() + count * IPV4_HEADER_LEN);
        let mut lengths = Vec::with_capacity(count);
        for (index, chunk) in self.data.chunks(payload_per_fragment).enumerate() {
            let mut header = self.header;
            let total_len = u16::try_from(IPV4_HEADER_LEN + chunk.len()).ok()?;
            header[2..4].copy_from_slice(&total_len.to_be_bytes());
            header[4..6].copy_from_slice(&identification.to_be_bytes());
            // RFC 791 section 3.2 step (9): FO <- OFO + NFB; MF <- OMF for the
            // last piece, MF <- 1 before it. DF is cleared by policy.
            let units = u16::try_from(index * payload_per_fragment / 8)
                .ok()
                .and_then(|units| original_units.checked_add(units))
                .filter(|units| *units <= FRAGMENT_OFFSET_MASK)?;
            let more_fragments = if index + 1 == count {
                original & FLAG_MORE_FRAGMENTS
            } else {
                FLAG_MORE_FRAGMENTS
            };
            header[6..8].copy_from_slice(&(reserved | more_fragments | units).to_be_bytes());
            header[10..12].fill(0);
            let checksum = internet_checksum(&header);
            header[10..12].copy_from_slice(&checksum.to_be_bytes());
            buffer.extend_from_slice(&header);
            buffer.extend_from_slice(chunk);
            lengths.push(IPV4_HEADER_LEN + chunk.len());
        }
        let mut bytes = buffer.freeze();
        Some(
            lengths
                .into_iter()
                .map(|length| bytes.split_to(length))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Independently authored option-free IPv4/UDP datagram: TOS 0xb8, ID
    /// 0x1234, DF, TTL 57, 8.8.8.8 to 10.45.0.2, `payload_len` payload octets.
    fn datagram(payload_len: usize, flags_offset: u16) -> Vec<u8> {
        let total = u16::try_from(28 + payload_len).unwrap();
        let mut packet = vec![0x45, 0xb8];
        packet.extend_from_slice(&total.to_be_bytes());
        packet.extend_from_slice(&[0x12, 0x34]);
        packet.extend_from_slice(&flags_offset.to_be_bytes());
        packet.extend_from_slice(&[57, 17, 0, 0, 8, 8, 8, 8, 10, 45, 0, 2]);
        let checksum = internet_checksum(&packet);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet.extend_from_slice(&[0x13, 0xc4, 0x13, 0xc4]);
        packet.extend_from_slice(&u16::try_from(8 + payload_len).unwrap().to_be_bytes());
        packet.extend_from_slice(&[0xab, 0xcd]);
        packet.extend((0..payload_len).map(|index| (index % 251) as u8));
        packet
    }

    /// Reassemble RFC 791 fragments independently: order by offset, require
    /// contiguous coverage and exactly one final fragment.
    fn reassemble(fragments: &[Bytes]) -> (Vec<u8>, u16) {
        let mut pieces: Vec<(usize, &[u8], bool)> = fragments
            .iter()
            .map(|fragment| {
                let flags = u16::from_be_bytes([fragment[6], fragment[7]]);
                (
                    usize::from(flags & 0x1fff) * 8,
                    &fragment[20..],
                    flags & 0x2000 != 0,
                )
            })
            .collect();
        pieces.sort_by_key(|piece| piece.0);
        let mut data = Vec::new();
        for (offset, piece, _) in &pieces {
            assert_eq!(*offset, data.len(), "contiguous fragments");
            data.extend_from_slice(piece);
        }
        assert_eq!(
            pieces.iter().filter(|piece| !piece.2).count(),
            1,
            "exactly one last fragment"
        );
        (data, u16::from_be_bytes([fragments[0][4], fragments[0][5]]))
    }

    #[test]
    fn atomic_datagram_splits_into_exact_rfc_791_fragments() {
        // The CRC case: 1,450 octets with DF over a 1,300-octet inner MTU.
        let packet = datagram(1_422, 0x4000);
        let source = Ipv4FragmentSource::parse(&packet).unwrap();
        assert!(source.is_atomic());
        let fragments = source.fragment(1_300, 0xbeef).unwrap();
        assert_eq!(fragments.len(), 2);
        // Independent literal of both headers. First: 20 + 1,280 octets
        // (NFB = (1,300 - 20) / 8 = 160 blocks), ID 0xbeef, MF, offset 0.
        let mut first = vec![
            0x45, 0xb8, 0x05, 0x14, 0xbe, 0xef, 0x20, 0x00, 57, 17, 0, 0, 8, 8, 8, 8, 10, 45, 0, 2,
        ];
        let checksum = internet_checksum(&first);
        first[10..12].copy_from_slice(&checksum.to_be_bytes());
        // Second: 20 + 150 octets, MF clear (the original's), offset 160.
        let mut second = vec![
            0x45, 0xb8, 0x00, 0xaa, 0xbe, 0xef, 0x00, 0xa0, 57, 17, 0, 0, 8, 8, 8, 8, 10, 45, 0, 2,
        ];
        let checksum = internet_checksum(&second);
        second[10..12].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(&fragments[0][..20], &first[..]);
        assert_eq!(&fragments[1][..20], &second[..]);
        assert_eq!(fragments[0].len(), 1_300);
        assert_eq!(fragments[1].len(), 170);
        assert_eq!(&fragments[0][20..], &packet[20..1_300]);
        assert_eq!(&fragments[1][20..], &packet[1_300..]);
        for fragment in &fragments {
            assert_eq!(internet_checksum(&fragment[..20]), 0);
        }
        let (data, identification) = reassemble(&fragments);
        assert_eq!(identification, 0xbeef);
        assert_eq!(data, &packet[20..]);
    }

    #[test]
    fn every_mtu_and_length_reassembles_exactly() {
        for mtu in [576_u16, 577, 583, 584, 1_280, 1_300, 1_499, 9_000, 0x7fff] {
            for payload_len in [
                usize::from(mtu) - 27,
                usize::from(mtu),
                (2 * usize::from(mtu)).min(65_507),
                65_507,
            ] {
                let packet = datagram(payload_len, 0x4000);
                let source = Ipv4FragmentSource::parse(&packet).unwrap();
                let fragments = source.fragment(mtu, 7).unwrap();
                let per_fragment = (usize::from(mtu) - 20) / 8 * 8;
                assert_eq!(fragments.len(), (packet.len() - 20).div_ceil(per_fragment));
                for (index, fragment) in fragments.iter().enumerate() {
                    assert!(fragment.len() <= usize::from(mtu));
                    assert_eq!(
                        usize::from(u16::from_be_bytes([fragment[2], fragment[3]])),
                        fragment.len()
                    );
                    assert_eq!(fragment[6] & 0x40, 0, "DF cleared");
                    assert_eq!(fragment[6] & 0x80, 0, "reserved bit unchanged");
                    let last = index + 1 == fragments.len();
                    assert_eq!(fragment[6] & 0x20 != 0, !last);
                    if !last {
                        assert_eq!((fragment.len() - 20) % 8, 0);
                    }
                    assert_eq!(internet_checksum(&fragment[..20]), 0);
                    assert_eq!(&fragment[8..10], &packet[8..10], "TTL and protocol");
                    assert_eq!(fragment[1], packet[1], "TOS");
                    assert_eq!(&fragment[12..20], &packet[12..20], "addresses");
                }
                let (data, identification) = reassemble(&fragments);
                assert_eq!(identification, 7);
                assert_eq!(data, &packet[20..], "mtu {mtu} payload {payload_len}");
            }
        }
    }

    #[test]
    fn a_dont_fragment_fragment_is_refragmented_within_its_own_range() {
        // A middle fragment with DF: offset 185 blocks (1,480 octets), MF set.
        let mut packet = datagram(1_452, 0x6000 | 185);
        let middle = Ipv4FragmentSource::parse(&packet).unwrap();
        assert!(!middle.is_atomic(), "a fragment is never atomic");
        let fragments = middle.fragment(1_000, 0x1234).unwrap();
        assert_eq!(fragments.len(), 2);
        for (fragment, units) in fragments.iter().zip([185_u16, 185 + 122]) {
            let flags = u16::from_be_bytes([fragment[6], fragment[7]]);
            assert_eq!(
                flags,
                0x2000 | units,
                "MF kept on the original's last piece"
            );
        }
        // The final fragment of a datagram keeps MF clear on its last piece.
        packet = datagram(1_452, 0x4000 | 185);
        let last = Ipv4FragmentSource::parse(&packet).unwrap();
        assert!(!last.is_atomic());
        let fragments = last.fragment(1_000, 0x1234).unwrap();
        assert_eq!(
            u16::from_be_bytes([fragments[1][6], fragments[1][7]]),
            185 + 122
        );
    }

    #[test]
    fn reserved_flag_and_trailing_link_octets_follow_rfc_791() {
        let mut packet = datagram(1_422, 0xc000);
        packet[10..12].fill(0);
        let checksum = internet_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet.extend_from_slice(&[0xee; 5]);
        let source = Ipv4FragmentSource::parse(&packet).unwrap();
        let fragments = source.fragment(1_300, 9).unwrap();
        for fragment in &fragments {
            assert_eq!(fragment[6] & 0xc0, 0x80, "reserved bit copied, DF cleared");
        }
        let (data, _) = reassemble(&fragments);
        assert_eq!(
            data,
            &packet[20..packet.len() - 5],
            "trailing octets ignored"
        );
    }

    #[test]
    fn invalid_headers_and_options_are_refused_before_any_work() {
        let valid = datagram(1_422, 0x4000);
        let refused = |packet: &[u8]| Ipv4FragmentSource::parse(packet).err();
        assert_eq!(refused(&[]), Some(InnerFragmentRefusal::Malformed));
        assert_eq!(refused(&valid[..19]), Some(InnerFragmentRefusal::Malformed));
        let mut version = valid.clone();
        version[0] = 0x65;
        assert_eq!(refused(&version), Some(InnerFragmentRefusal::Malformed));
        let mut short_header = valid.clone();
        short_header[0] = 0x44;
        assert_eq!(
            refused(&short_header),
            Some(InnerFragmentRefusal::Malformed)
        );
        let mut checksum = valid.clone();
        checksum[10] ^= 1;
        assert_eq!(refused(&checksum), Some(InnerFragmentRefusal::Malformed));
        assert_eq!(
            refused(&valid[..valid.len() - 1]),
            Some(InnerFragmentRefusal::Malformed),
            "truncated"
        );
        let mut under = valid.clone();
        under[2..4].copy_from_slice(&19_u16.to_be_bytes());
        under[10..12].fill(0);
        let sum = internet_checksum(&under[..20]);
        under[10..12].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(refused(&under), Some(InnerFragmentRefusal::Malformed));
        // A fragment whose data would end past 65,535 octets.
        let mut beyond = datagram(1_422, 0x4000 | 8_100);
        assert_eq!(refused(&beyond), Some(InnerFragmentRefusal::Malformed));
        beyond = datagram(1_422, 0x4000 | 7_000);
        assert!(refused(&beyond).is_none());
        // Options: a valid 24-octet header with one NOP and End of Options.
        let mut options = valid[..20].to_vec();
        options[0] = 0x46;
        options.extend_from_slice(&[1, 0, 0, 0]);
        options.extend_from_slice(&valid[20..]);
        let total = u16::try_from(options.len()).unwrap();
        options[2..4].copy_from_slice(&total.to_be_bytes());
        options[10..12].fill(0);
        let sum = internet_checksum(&options[..24]);
        options[10..12].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(refused(&options), Some(InnerFragmentRefusal::Options));
        // A datagram that fits, or an MTU without room for 8 data octets,
        // yields no fragments.
        let source = Ipv4FragmentSource::parse(&valid).unwrap();
        assert!(source.fragment(1_450, 1).is_none());
        assert!(source.fragment(27, 1).is_none());
        assert!(source.fragment(19, 1).is_none());
    }
}
