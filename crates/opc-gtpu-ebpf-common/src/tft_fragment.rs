//! Bounded inner-uplink IPv4 fragment affinity shared by host and tc.
//!
//! A bucket is mutated only under the caller's exclusive lock. The tc map
//! places one BTF spin lock before each bucket; all methods used under that
//! lock inline and perform no helper calls or allocations. Expired slots are
//! reused in place, never deleted. No live slot is evicted, including poisoned
//! or completed datagrams. The fixed deadline is never refreshed.
//!
//! Bucket selection is owner-partitioned. The classifier identity in the first
//! key bytes (attachment interface index and the subscriber PAA) selects one of
//! [`TFT_FRAGMENT_OWNER_GROUPS`] owner groups; the remaining key bytes select a
//! bucket inside that group. One subscriber can therefore occupy at most
//! [`TFT_FRAGMENT_OWNER_MAX_DATAGRAMS`] concurrent fragmented datagrams and can
//! never deny a bucket that belongs to another group. Two subscriber addresses
//! that hash to the same group share that group's bound; the blast radius of a
//! collision is one group, not the whole table.

use crate::{TftClassifierIpv4Packet, TftClassifierKey, TftClassifierMeta};

/// Pinned BTF array containing a spin lock and four affinity slots per value.
pub const MAP_TFT_FRAGMENT_AFFINITY: &str = "GTPU_TFT_FRAG";
/// Number of independently locked affinity buckets.
pub const TFT_FRAGMENT_BUCKETS: u32 = 16_384;
/// Slots in each bucket. A full bucket refuses admission even if others are free.
pub const TFT_FRAGMENT_WAYS: usize = 4;
/// Buckets one owner group may select. The first key bytes (attachment plus
/// subscriber PAA) pick the group, so one subscriber is confined to these
/// buckets and cannot occupy another owner group's capacity.
pub const TFT_FRAGMENT_OWNER_BUCKETS: u32 = 64;
/// Number of independently selected owner groups across the affinity table.
pub const TFT_FRAGMENT_OWNER_GROUPS: u32 = TFT_FRAGMENT_BUCKETS / TFT_FRAGMENT_OWNER_BUCKETS;
/// Maximum concurrent fragmented datagrams one owner can occupy:
/// its buckets times the slots in each bucket. This is the stated
/// per-subscriber admission bound.
pub const TFT_FRAGMENT_OWNER_MAX_DATAGRAMS: u32 =
    TFT_FRAGMENT_OWNER_BUCKETS * TFT_FRAGMENT_WAYS as u32;
const _: () = assert!(TFT_FRAGMENT_BUCKETS.is_power_of_two());
const _: () = assert!(TFT_FRAGMENT_OWNER_BUCKETS.is_power_of_two());
const _: () = assert!(TFT_FRAGMENT_OWNER_BUCKETS < TFT_FRAGMENT_BUCKETS);
/// Maximum distinct fragments accepted for one datagram, including its first.
pub const TFT_FRAGMENT_MAX_RANGES: usize = 64;
const _: () = assert!(TFT_FRAGMENT_MAX_RANGES.is_power_of_two());
/// Fixed lifetime in boot-time nanoseconds (two seconds).
pub const TFT_FRAGMENT_LIFETIME_NS: u64 = 2_000_000_000;
/// Exact key width: ifindex, PAA, source, destination, ID, protocol, reserved.
pub const TFT_FRAGMENT_KEY_LEN: usize = 20;
/// Fixed-width slot. Identity and parsed packet words are little endian;
/// key, interval, mark and timestamp byte arrays use network order.
pub const TFT_FRAGMENT_ENTRY_LEN: usize = 392;
/// Bucket data width, excluding its kernel spin lock.
pub const TFT_FRAGMENT_BUCKET_DATA_LEN: usize = TFT_FRAGMENT_WAYS * TFT_FRAGMENT_ENTRY_LEN;
/// BTF map value width, including its four-byte kernel spin lock.
pub const TFT_FRAGMENT_BUCKET_VALUE_LEN: usize = 4 + TFT_FRAGMENT_BUCKET_DATA_LEN;

/// Whether a coherently read BTF bucket contains no unexpired entries.
///
/// `now_ns` is sampled from the boot clock before the map scan. Expired bytes
/// are inert even when retained in place; a nonzero slot without a deadline is
/// not accepted as empty. This is an occupancy proof, not schema validation.
#[must_use]
pub fn tft_fragment_bucket_is_empty_at(
    value: &[u8; TFT_FRAGMENT_BUCKET_VALUE_LEN],
    now_ns: u64,
) -> bool {
    const DEADLINE: usize = core::mem::offset_of!(TftFragmentEntry, expires_at);
    value[4..]
        .as_chunks::<TFT_FRAGMENT_ENTRY_LEN>()
        .0
        .iter()
        .all(|entry| {
            if entry.iter().all(|byte| *byte == 0) {
                return true;
            }
            let mut deadline = [0; 8];
            deadline.copy_from_slice(&entry[DEADLINE..DEADLINE + 8]);
            let deadline = u64::from_be_bytes(deadline);
            deadline != 0 && deadline <= now_ns
        })
}

/// Exact datagram identity. Debug output intentionally omits packet values.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct TftFragmentKey([u8; TFT_FRAGMENT_KEY_LEN]);

impl TftFragmentKey {
    /// Construct a key after the attachment and fixed IPv4 fields are available.
    ///
    /// This does not parse variable packet lengths: an invalid later fragment
    /// must still find a retained stale key before any absent-classifier fallback.
    #[must_use]
    #[inline(always)]
    pub fn new(
        classifier: TftClassifierKey,
        source: [u8; 4],
        destination: [u8; 4],
        protocol: u8,
        identification: u16,
    ) -> Self {
        let mut bytes = [0; TFT_FRAGMENT_KEY_LEN];
        bytes[..8].copy_from_slice(&classifier.encode());
        bytes[8..12].copy_from_slice(&source);
        bytes[12..16].copy_from_slice(&destination);
        bytes[16..18].copy_from_slice(&identification.to_be_bytes());
        bytes[18] = protocol;
        Self(bytes)
    }

    /// Deterministic owner-partitioned bucket selection.
    ///
    /// The first eight bytes are the classifier identity (attachment interface
    /// index and subscriber PAA); they select the owner group. The remaining
    /// key bytes continue the same hash and select a bucket inside that group.
    /// Work is one FNV pass over the 20 key bytes, as before: the group boundary
    /// adds only masks, not a second hash. Collisions never permit eviction.
    #[must_use]
    #[inline(always)]
    pub fn bucket(self) -> u32 {
        let mut hash = 2_166_136_261_u32;
        let mut index = 0;
        while index < 8 {
            hash = (hash ^ u32::from(self.0[index])).wrapping_mul(16_777_619);
            index += 1;
        }
        let owner = hash & (TFT_FRAGMENT_OWNER_GROUPS - 1);
        while index < TFT_FRAGMENT_KEY_LEN {
            hash = (hash ^ u32::from(self.0[index])).wrapping_mul(16_777_619);
            index += 1;
        }
        let within = hash & (TFT_FRAGMENT_OWNER_BUCKETS - 1);
        owner * TFT_FRAGMENT_OWNER_BUCKETS + within
    }

    /// Fixed network-order key bytes for map inspection by a trusted loader.
    #[must_use]
    pub const fn encode(self) -> [u8; TFT_FRAGMENT_KEY_LEN] {
        self.0
    }

    #[inline(always)]
    fn matches(&self, other: &Self) -> bool {
        let mut difference = 0;
        for index in 0..TFT_FRAGMENT_KEY_LEN {
            difference |= self.0[index] ^ other.0[index];
        }
        difference == 0
    }
}

impl core::fmt::Debug for TftFragmentKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("TftFragmentKey(<redacted>)")
    }
}

/// Validated fragment interval, in bytes of the original IPv4 payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct TftIpv4Fragment {
    start: u16,
    end: u16,
    header_len: u8,
    more: bool,
}

impl TftIpv4Fragment {
    /// Validate one exact fragmented IPv4 envelope without reading transport.
    /// Rejects reserved/DF flags, empty or unaligned non-final payloads, invalid
    /// IHL, trailing/truncated bytes, and intervals exceeding the IPv4 limit.
    #[must_use]
    #[inline(always)]
    pub const fn from_header(
        version_ihl: u8,
        total_len: u16,
        available: usize,
        fragment: u16,
    ) -> Option<Self> {
        let header_len = (version_ihl & 0x0f) * 4;
        if version_ihl >> 4 != 4
            || header_len < 20
            || total_len as usize != available
            || total_len <= header_len as u16
            || fragment & 0xc000 != 0
            || fragment & 0x3fff == 0
        {
            return None;
        }
        let payload_len = total_len - header_len as u16;
        let more = fragment & 0x2000 != 0;
        if more && !payload_len.is_multiple_of(8) {
            return None;
        }
        let start = (fragment & 0x1fff) * 8;
        let Some(end) = start.checked_add(payload_len) else {
            return None;
        };
        if end > u16::MAX - header_len as u16 {
            return None;
        }
        Some(Self {
            start,
            end,
            header_len,
            more,
        })
    }

    /// Parse the complete IPv4 envelope, without interpreting later payloads.
    #[must_use]
    pub fn parse(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 {
            return None;
        }
        Self::from_header(
            packet[0],
            u16::from_be_bytes([packet[2], packet[3]]),
            packet.len(),
            u16::from_be_bytes([packet[6], packet[7]]),
        )
    }

    /// Whether this is fragment zero, the only fragment allowed to classify.
    #[must_use]
    #[inline(always)]
    pub const fn is_first(self) -> bool {
        self.start == 0
    }
}

/// Result of the bounded state transition, before downstream bearer authority.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TftFragmentDisposition {
    /// No classifier and no retained live key: preserve ordinary lookup behavior.
    Absent,
    /// Use this mark in the existing exact bearer/F-TEID authority lookup.
    Selected(u32),
    /// Malformed fragment envelope or incomplete first-fragment transport header.
    Malformed,
    /// Orphan, stale authority, or ambiguous/overlapping fragments.
    Drop,
    /// The classifier owner's bounded bucket group is full of live or poisoned
    /// entries, so this subscriber's new fragmented datagram cannot be tracked.
    /// The packet is dropped fail closed; no other owner's entry is evicted.
    Capacity,
}

impl core::fmt::Debug for TftFragmentDisposition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Absent => f.write_str("Absent"),
            Self::Selected(_) => f.write_str("Selected(<redacted>)"),
            Self::Malformed => f.write_str("Malformed"),
            Self::Drop => f.write_str("Drop"),
            Self::Capacity => f.write_str("Capacity"),
        }
    }
}

#[derive(Clone, Copy)]
#[repr(C)]
struct TftFragmentEntry {
    key: TftFragmentKey,
    meta: [[u8; 8]; 9],
    first_packet: [[u8; 4]; 6],
    expires_at: [u8; 8],
    mark: [u8; 4],
    first_end: [u8; 2],
    final_end: [u8; 2],
    range_count: u8,
    poisoned: u8,
    first_header_len: u8,
    reserved: u8,
    ranges: [[[u8; 2]; 2]; TFT_FRAGMENT_MAX_RANGES],
}

impl TftFragmentEntry {
    const EMPTY: Self = Self {
        key: TftFragmentKey([0; TFT_FRAGMENT_KEY_LEN]),
        meta: [[0; 8]; 9],
        first_packet: [[0; 4]; 6],
        expires_at: [0; 8],
        mark: [0; 4],
        first_end: [0; 2],
        final_end: [0; 2],
        range_count: 0,
        poisoned: 0,
        first_header_len: 0,
        reserved: 0,
        ranges: [[[0; 2]; 2]; TFT_FRAGMENT_MAX_RANGES],
    };
}

/// Four fixed slots, mutated under exclusive access (a BTF spin lock in tc).
///
/// The public mutator is a low-level classifier model, not forwarding authority.
/// Its caller must supply the exact current validated classifier metadata and
/// the result of matching a fully parsed first fragment. The returned mark must
/// still pass the ordinary downstream bearer authority lookup.
#[derive(Clone)]
#[repr(C)]
pub struct TftFragmentBucket {
    entries: [TftFragmentEntry; TFT_FRAGMENT_WAYS],
}

impl Default for TftFragmentBucket {
    fn default() -> Self {
        Self::new()
    }
}

impl TftFragmentBucket {
    /// Empty bucket. In tc the kernel initializes array map data to zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: [TftFragmentEntry::EMPTY; TFT_FRAGMENT_WAYS],
        }
    }

    /// Apply one packet while the caller holds exclusive bucket access.
    ///
    /// `first` is present only for a complete, successfully classified fragment
    /// zero. `meta` is the current active, schema-validated selector; a default
    /// removal fence is represented by `None`. All four slots are inspected for
    /// an exact live key before an expired slot may be reused. Work is bounded
    /// by four key comparisons and 64 interval comparisons. No helper, BPF
    /// subprogram, allocation, or whole-entry copy is permitted under the lock.
    #[must_use]
    #[inline(always)]
    pub fn apply(
        &mut self,
        key: TftFragmentKey,
        fragment: Option<TftIpv4Fragment>,
        meta: Option<&TftClassifierMeta>,
        first: Option<(&TftClassifierIpv4Packet, u32)>,
        now_ns: u64,
    ) -> TftFragmentDisposition {
        let mut matched = TFT_FRAGMENT_WAYS;
        let mut available = TFT_FRAGMENT_WAYS;
        for index in 0..TFT_FRAGMENT_WAYS {
            let entry = &self.entries[index];
            if now_ns >= u64::from_be_bytes(entry.expires_at) {
                if available == TFT_FRAGMENT_WAYS {
                    available = index;
                }
            } else if entry.key.matches(&key) {
                matched = index;
            }
        }
        if matched == TFT_FRAGMENT_WAYS && meta.is_none() {
            return TftFragmentDisposition::Absent;
        }
        let Some(fragment) = fragment else {
            if matched < TFT_FRAGMENT_WAYS {
                self.entries[matched].poisoned = 1;
            }
            return TftFragmentDisposition::Malformed;
        };
        if matched == TFT_FRAGMENT_WAYS {
            if !fragment.is_first() {
                return TftFragmentDisposition::Drop;
            }
            if available == TFT_FRAGMENT_WAYS {
                // Every slot in this owner bucket is live or poisoned: the
                // per-owner bound refused this datagram without touching
                // another owner's buckets.
                return TftFragmentDisposition::Capacity;
            }
            let Some((packet, mark)) = first else {
                return TftFragmentDisposition::Malformed;
            };
            let Some(meta) = meta else {
                return TftFragmentDisposition::Drop;
            };
            if packet.udp_length().is_some_and(|end| {
                end <= fragment.end || end > u16::MAX - u16::from(fragment.header_len)
            }) {
                return TftFragmentDisposition::Malformed;
            }
            let Some(expires_at) = now_ns.checked_add(TFT_FRAGMENT_LIFETIME_NS) else {
                return TftFragmentDisposition::Drop;
            };
            // Write only the live fields and first range. Old unused ranges
            // remain inaccessible behind range_count, avoiding a large memset.
            let entry = &mut self.entries[available];
            entry.key = key;
            for index in 0..9 {
                entry.meta[index] = meta.fragment_identity_word(index).to_le_bytes();
            }
            for index in 0..6 {
                entry.first_packet[index] = packet.fragment_packet_word(index).to_le_bytes();
            }
            entry.expires_at = expires_at.to_be_bytes();
            entry.mark = mark.to_be_bytes();
            entry.first_end = fragment.end.to_be_bytes();
            entry.final_end = [0; 2];
            entry.range_count = 1;
            entry.poisoned = 0;
            entry.first_header_len = fragment.header_len;
            entry.reserved = 0;
            entry.ranges[0] = [[0; 2], fragment.end.to_be_bytes()];
            return TftFragmentDisposition::Selected(mark);
        }
        let entry = &mut self.entries[matched];
        // A packet descheduled before locking must not consume a slot that
        // another CPU has since expired and reused for the same IPv4 ID.
        if now_ns < u64::from_be_bytes(entry.expires_at).saturating_sub(TFT_FRAGMENT_LIFETIME_NS) {
            entry.poisoned = 1;
            return TftFragmentDisposition::Drop;
        }
        let Some(meta) = meta else {
            entry.poisoned = 1;
            return TftFragmentDisposition::Drop;
        };
        let mut identity_difference = 0;
        for index in 0..9 {
            identity_difference |=
                u64::from_le_bytes(entry.meta[index]) ^ meta.fragment_identity_word(index);
        }
        if entry.poisoned != 0 || identity_difference != 0 {
            entry.poisoned = 1;
            return TftFragmentDisposition::Drop;
        }
        let mark = u32::from_be_bytes(entry.mark);
        if fragment.is_first() {
            if let Some((packet, candidate)) = first {
                let mut packet_difference = 0;
                for index in 0..6 {
                    packet_difference |= u32::from_le_bytes(entry.first_packet[index])
                        ^ packet.fragment_packet_word(index);
                }
                if candidate == mark
                    && packet_difference == 0
                    && fragment.end == u16::from_be_bytes(entry.first_end)
                    && fragment.header_len == entry.first_header_len
                {
                    return TftFragmentDisposition::Selected(mark);
                }
            }
            entry.poisoned = 1;
            return TftFragmentDisposition::Drop;
        }
        let final_end = u16::from_be_bytes(entry.final_end);
        let transport = u32::from_le_bytes(entry.first_packet[4]);
        let udp_end = (transport >> 16) as u16;
        let is_udp = (transport >> 8) as u8 == 17;
        if entry.range_count as usize >= TFT_FRAGMENT_MAX_RANGES
            || fragment.end > u16::MAX - u16::from(entry.first_header_len)
            || (final_end != 0 && (fragment.end > final_end || !fragment.more))
            || (is_udp
                && (fragment.end > udp_end
                    || (fragment.more && fragment.end == udp_end)
                    || (!fragment.more && fragment.end != udp_end)))
        {
            entry.poisoned = 1;
            return TftFragmentDisposition::Drop;
        }
        for index in 0..TFT_FRAGMENT_MAX_RANGES as u32 {
            // Keep the address bound local to every access. The barrier stops
            // LLVM replacing this with a walking pointer; the mask survives
            // optimization even when an older verifier forgets scalar bounds
            // across a stack reload. It is an identity for this 0..64 loop.
            let index = core::hint::black_box(index) & (TFT_FRAGMENT_MAX_RANGES as u32 - 1);
            if index >= u32::from(entry.range_count) {
                // This is the first unused record. Reuse the same bounded
                // index for the append, rather than reloading an older count
                // whose bound an older verifier may have lost on the stack.
                entry.ranges[index as usize] =
                    [fragment.start.to_be_bytes(), fragment.end.to_be_bytes()];
                entry.range_count += 1;
                if !fragment.more {
                    entry.final_end = fragment.end.to_be_bytes();
                }
                return TftFragmentDisposition::Selected(mark);
            }
            let start = u16::from_be_bytes(entry.ranges[index as usize][0]);
            let end = u16::from_be_bytes(entry.ranges[index as usize][1]);
            if (fragment.start < end && start < fragment.end)
                || (!fragment.more && end > fragment.end)
            {
                entry.poisoned = 1;
                return TftFragmentDisposition::Drop;
            }
        }
        entry.poisoned = 1;
        TftFragmentDisposition::Drop
    }
}

const _: [(); TFT_FRAGMENT_ENTRY_LEN] = [(); core::mem::size_of::<TftFragmentEntry>()];
const _: [(); TFT_FRAGMENT_BUCKET_DATA_LEN] = [(); core::mem::size_of::<TftFragmentBucket>()];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TftClassifierOwnerId;

    #[test]
    fn retained_bucket_emptiness_uses_every_boot_clock_deadline() {
        let mut bytes = [0; TFT_FRAGMENT_BUCKET_VALUE_LEN];
        assert!(tft_fragment_bucket_is_empty_at(&bytes, 100));
        for slot in 0..TFT_FRAGMENT_WAYS {
            let start = 4 + slot * TFT_FRAGMENT_ENTRY_LEN;
            bytes[start] = 1;
            assert!(
                !tft_fragment_bucket_is_empty_at(&bytes, 100),
                "nonzero entry without a deadline is not proven empty"
            );
            // Literal wire coordinate independently checks the C layout.
            bytes[start + 116..start + 124].copy_from_slice(&101_u64.to_be_bytes());
            assert!(!tft_fragment_bucket_is_empty_at(&bytes, 100));
            assert!(tft_fragment_bucket_is_empty_at(&bytes, 101));
            bytes[start + 116..start + 124].copy_from_slice(&99_u64.to_be_bytes());
            assert!(tft_fragment_bucket_is_empty_at(&bytes, 100));
        }
    }

    fn key(id: u16) -> TftFragmentKey {
        TftFragmentKey::new(
            TftClassifierKey::new(7, [192, 0, 2, 1]).unwrap(),
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            50,
            id,
        )
    }

    fn meta(generation: u64) -> TftClassifierMeta {
        TftClassifierMeta::new(
            0,
            true,
            TftClassifierOwnerId::new([1; 16]).unwrap(),
            1,
            generation,
            1,
            [2; 32],
        )
        .unwrap()
    }

    fn first() -> TftIpv4Fragment {
        TftIpv4Fragment::from_header(0x45, 44, 44, 0x2000).unwrap()
    }

    fn last() -> TftIpv4Fragment {
        TftIpv4Fragment::from_header(0x45, 36, 36, 3).unwrap()
    }

    fn packet() -> TftClassifierIpv4Packet {
        TftClassifierIpv4Packet::new(
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            50,
            0,
            None,
            None,
            Some(12),
        )
    }

    #[test]
    fn pair_duplicates_and_fixed_completion_deadline() {
        let mut bucket = TftFragmentBucket::new();
        let meta = meta(1);
        assert_eq!(
            bucket.apply(
                key(1),
                Some(first()),
                Some(&meta),
                Some((&packet(), 11)),
                10
            ),
            TftFragmentDisposition::Selected(11)
        );
        let expires = bucket.entries[0].expires_at;
        assert_eq!(
            bucket.apply(
                key(1),
                Some(first()),
                Some(&meta),
                Some((&packet(), 11)),
                20
            ),
            TftFragmentDisposition::Selected(11)
        );
        assert_eq!(bucket.entries[0].expires_at, expires);
        assert_eq!(
            bucket.apply(key(1), Some(last()), Some(&meta), None, 30),
            TftFragmentDisposition::Selected(11)
        );
        assert_eq!(bucket.entries[0].expires_at, expires);
        assert_eq!(
            bucket.apply(key(1), Some(last()), Some(&meta), None, 40),
            TftFragmentDisposition::Drop
        );
        assert_eq!(
            bucket.apply(
                key(1),
                Some(first()),
                Some(&meta),
                Some((&packet(), 11)),
                50
            ),
            TftFragmentDisposition::Drop
        );
        assert_eq!(
            bucket.apply(
                key(1),
                Some(first()),
                Some(&meta),
                Some((&packet(), 12)),
                u64::from_be_bytes(expires)
            ),
            TftFragmentDisposition::Selected(12)
        );
    }

    #[test]
    fn authority_removal_and_replacement_preserve_stale_tombstones() {
        for replacement in [None, Some(meta(2))] {
            let mut bucket = TftFragmentBucket::new();
            assert_eq!(
                bucket.apply(
                    key(1),
                    Some(first()),
                    Some(&meta(1)),
                    Some((&packet(), 11)),
                    10
                ),
                TftFragmentDisposition::Selected(11)
            );
            assert_eq!(
                bucket.apply(key(1), Some(last()), replacement.as_ref(), None, 20),
                TftFragmentDisposition::Drop
            );
            assert_eq!(
                bucket.apply(key(1), Some(last()), Some(&meta(1)), None, 30),
                TftFragmentDisposition::Drop
            );
        }
    }

    #[test]
    fn full_bucket_never_evicts_live_entries() {
        let mut bucket = TftFragmentBucket::new();
        for id in 1..=4 {
            assert_eq!(
                bucket.apply(
                    key(id),
                    Some(first()),
                    Some(&meta(1)),
                    Some((&packet(), 11)),
                    10
                ),
                TftFragmentDisposition::Selected(11)
            );
        }
        assert_eq!(
            bucket.apply(
                key(5),
                Some(first()),
                Some(&meta(1)),
                Some((&packet(), 11)),
                20
            ),
            TftFragmentDisposition::Capacity
        );
        for id in 1..=4 {
            assert_eq!(
                bucket.apply(key(id), Some(last()), Some(&meta(1)), None, 30),
                TftFragmentDisposition::Selected(11)
            );
        }
    }

    #[test]
    fn final_retained_range_is_checked_in_every_bucket_slot() {
        let mut bucket = TftFragmentBucket::new();
        let metadata = meta(1);
        for id in 1..=TFT_FRAGMENT_WAYS as u16 {
            let now = u64::from(id) * 100;
            assert_eq!(
                bucket.apply(
                    key(id),
                    Some(first()),
                    Some(&metadata),
                    Some((&packet(), 11)),
                    now,
                ),
                TftFragmentDisposition::Selected(11)
            );
            // Leave one free record so rejection must come from the last
            // overlap comparison, rather than the capacity guard.
            for index in 1..TFT_FRAGMENT_MAX_RANGES - 1 {
                let flags = 0x2000 | (index * 3) as u16;
                let tail = TftIpv4Fragment::from_header(0x45, 44, 44, flags).unwrap();
                assert_eq!(
                    bucket.apply(key(id), Some(tail), Some(&metadata), None, now + 10),
                    TftFragmentDisposition::Selected(11)
                );
            }
            let flags = 0x2000 | ((TFT_FRAGMENT_MAX_RANGES - 2) * 3) as u16;
            let overlap = TftIpv4Fragment::from_header(0x45, 44, 44, flags).unwrap();
            assert_eq!(
                bucket.apply(key(id), Some(overlap), Some(&metadata), None, now + 20),
                TftFragmentDisposition::Drop
            );
            assert_eq!(
                bucket.apply(
                    key(id),
                    Some(first()),
                    Some(&metadata),
                    Some((&packet(), 11)),
                    now + 30,
                ),
                TftFragmentDisposition::Drop
            );
        }
    }

    #[test]
    fn malformed_retained_key_drops_even_without_metadata() {
        let mut bucket = TftFragmentBucket::new();
        assert_eq!(
            bucket.apply(
                key(1),
                Some(first()),
                Some(&meta(1)),
                Some((&packet(), 11)),
                10
            ),
            TftFragmentDisposition::Selected(11)
        );
        assert_eq!(
            bucket.apply(key(1), None, None, None, 20),
            TftFragmentDisposition::Malformed
        );
        assert_eq!(
            bucket.apply(key(2), None, None, None, 20),
            TftFragmentDisposition::Absent
        );
        assert_eq!(
            bucket.apply(key(2), Some(last()), Some(&meta(1)), None, 20),
            TftFragmentDisposition::Drop
        );
    }

    #[test]
    fn udp_declared_length_binds_every_tail_and_duplicate_first() {
        let mut bytes = [0; 44];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&44_u16.to_be_bytes());
        bytes[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
        bytes[9] = 17;
        bytes[24..26].copy_from_slice(&32_u16.to_be_bytes());
        let packet = TftClassifierIpv4Packet::parse_first_fragment(&bytes).unwrap();
        assert_eq!(packet.udp_length(), Some(32));
        let key = TftFragmentKey::new(
            TftClassifierKey::new(7, [192, 0, 2, 1]).unwrap(),
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            17,
            1,
        );
        let valid_last = TftIpv4Fragment::from_header(0x45, 28, 28, 3).unwrap();
        for tail in [
            valid_last,
            last(), // final payload end 40 exceeds UDP length 32
            TftIpv4Fragment::from_header(0x45, 24, 24, 3).unwrap(), // too short
            TftIpv4Fragment::from_header(0x45, 28, 28, 0x2003).unwrap(), // MF at end
        ] {
            let mut bucket = TftFragmentBucket::new();
            assert_eq!(
                bucket.apply(key, Some(first()), Some(&meta(1)), Some((&packet, 11)), 10),
                TftFragmentDisposition::Selected(11)
            );
            let expected = if tail == valid_last {
                TftFragmentDisposition::Selected(11)
            } else {
                TftFragmentDisposition::Drop
            };
            assert_eq!(
                bucket.apply(key, Some(tail), Some(&meta(1)), None, 20),
                expected
            );
            if tail != valid_last {
                assert_eq!(
                    bucket.apply(key, Some(valid_last), Some(&meta(1)), None, 30),
                    TftFragmentDisposition::Drop
                );
            }
        }
        let mut bucket = TftFragmentBucket::new();
        assert_eq!(
            bucket.apply(key, Some(first()), Some(&meta(1)), Some((&packet, 11)), 10),
            TftFragmentDisposition::Selected(11)
        );
        bytes[24..26].copy_from_slice(&40_u16.to_be_bytes());
        let changed = TftClassifierIpv4Packet::parse_first_fragment(&bytes).unwrap();
        assert_eq!(
            bucket.apply(key, Some(first()), Some(&meta(1)), Some((&changed, 11)), 20),
            TftFragmentDisposition::Drop
        );
        assert_eq!(
            bucket.apply(key, Some(valid_last), Some(&meta(1)), None, 30),
            TftFragmentDisposition::Drop
        );
    }

    fn owner_group(classifier: TftClassifierKey) -> u32 {
        TftFragmentKey::new(classifier, [192, 0, 2, 1], [198, 51, 100, 2], 50, 0).bucket()
            / TFT_FRAGMENT_OWNER_BUCKETS
    }

    fn classifier_for_paa(paa: [u8; 4]) -> TftClassifierKey {
        TftClassifierKey::new(7, paa).expect("canonical classifier key")
    }

    fn owner_buckets() -> [TftFragmentBucket; TFT_FRAGMENT_OWNER_BUCKETS as usize] {
        core::array::from_fn(|_| TftFragmentBucket::new())
    }

    /// Fill every bucket of `classifier`'s owner group with exactly four live
    /// first-fragment entries, skipping IDs whose bucket is already full.
    fn fill_owner_group(
        classifier: TftClassifierKey,
        metadata: &TftClassifierMeta,
    ) -> (
        [TftFragmentBucket; TFT_FRAGMENT_OWNER_BUCKETS as usize],
        u16,
    ) {
        let first = first();
        let packet = packet();
        let mut buckets = owner_buckets();
        let owner = owner_group(classifier);
        let mut counts = [0_u8; TFT_FRAGMENT_OWNER_BUCKETS as usize];
        let mut identification = 0_u16;
        let mut live = 0_u32;
        while live < TFT_FRAGMENT_OWNER_MAX_DATAGRAMS {
            identification = identification.wrapping_add(1);
            let key = TftFragmentKey::new(
                classifier,
                [192, 0, 2, 1],
                [198, 51, 100, 2],
                50,
                identification,
            );
            let slot = (key.bucket() - owner * TFT_FRAGMENT_OWNER_BUCKETS) as usize;
            if counts[slot] == TFT_FRAGMENT_WAYS as u8 {
                continue;
            }
            assert_eq!(
                buckets[slot].apply(key, Some(first), Some(metadata), Some((&packet, 11)), 10),
                TftFragmentDisposition::Selected(11)
            );
            counts[slot] += 1;
            live += 1;
        }
        (buckets, identification)
    }

    /// One subscriber's classifier confines every key it can create to one
    /// owner group of `TFT_FRAGMENT_OWNER_BUCKETS` buckets.
    #[test]
    fn owner_bucket_partition_is_exact_and_subscriber_scoped() {
        assert_eq!(
            TFT_FRAGMENT_OWNER_GROUPS * TFT_FRAGMENT_OWNER_BUCKETS,
            TFT_FRAGMENT_BUCKETS
        );
        assert_eq!(TFT_FRAGMENT_OWNER_MAX_DATAGRAMS, 256);
        let classifier = classifier_for_paa([192, 0, 2, 1]);
        let owner = owner_group(classifier);
        let mut seen = 0_u64;
        for identification in 0..4_096_u16 {
            let key = TftFragmentKey::new(
                classifier,
                [192, 0, 2, 1],
                [198, 51, 100, 2],
                50,
                identification,
            );
            let bucket = key.bucket();
            assert!(bucket < TFT_FRAGMENT_BUCKETS);
            assert_eq!(
                bucket / TFT_FRAGMENT_OWNER_BUCKETS,
                owner,
                "one subscriber must stay inside one owner group"
            );
            seen |= 1 << (bucket % TFT_FRAGMENT_OWNER_BUCKETS);
        }
        assert_eq!(
            seen.count_ones(),
            TFT_FRAGMENT_OWNER_BUCKETS,
            "one subscriber must be able to reach every bucket in its own group"
        );
    }

    /// A subscriber that fills every slot of its own group is refused fail
    /// closed; another owner group keeps admitting.
    #[test]
    fn a_saturating_owner_is_refused_without_touching_another_group() {
        let classifier = classifier_for_paa([192, 0, 2, 1]);
        let meta_a = meta(1);
        let (mut buckets, last_identification) = fill_owner_group(classifier, &meta_a);
        let owner = owner_group(classifier);
        // Every bucket in the group now has four live entries; a new datagram
        // for the same subscriber is refused with the distinct capacity outcome
        // without resetting any entry.
        let first = first();
        let packet = packet();
        let refused = TftFragmentKey::new(
            classifier,
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            50,
            last_identification.wrapping_add(1),
        );
        let slot = (refused.bucket() - owner * TFT_FRAGMENT_OWNER_BUCKETS) as usize;
        assert_eq!(
            buckets[slot].apply(refused, Some(first), Some(&meta_a), Some((&packet, 11)), 10),
            TftFragmentDisposition::Capacity
        );
        // A different owner group is unaffected.
        let other = (2_u8..=255)
            .map(|last| classifier_for_paa([10, 0, 0, last]))
            .find(|candidate| owner_group(*candidate) != owner)
            .expect("a different owner group exists");
        let key = TftFragmentKey::new(other, [192, 0, 2, 1], [198, 51, 100, 2], 50, 1);
        assert_eq!(
            TftFragmentBucket::new().apply(
                key,
                Some(first),
                Some(&meta(2)),
                Some((&packet, 11)),
                10
            ),
            TftFragmentDisposition::Selected(11)
        );
    }

    /// A hash collision only shares one group's bound; a third group is still
    /// admitted, and the colliding subscriber cannot evict the first one's
    /// entries (they are retained, not reset).
    #[test]
    fn colliding_owner_groups_share_only_their_group() {
        let first_classifier = classifier_for_paa([192, 0, 2, 1]);
        let mut colliding = None;
        let mut distinct = None;
        for last in 2_u8..=255 {
            let candidate = classifier_for_paa([10, 0, 0, last]);
            if owner_group(candidate) == owner_group(first_classifier) && colliding.is_none() {
                colliding = Some(candidate);
            }
            if owner_group(candidate) != owner_group(first_classifier) && distinct.is_none() {
                distinct = Some(candidate);
            }
        }
        let colliding = colliding.expect("a colliding owner group exists");
        let distinct = distinct.expect("a distinct owner group exists");
        let meta_a = meta(1);
        let (mut buckets, last_identification) = fill_owner_group(first_classifier, &meta_a);
        let owner = owner_group(first_classifier);
        let first = first();
        let packet = packet();
        let refused = TftFragmentKey::new(
            colliding,
            [192, 0, 2, 1],
            [198, 51, 100, 2],
            50,
            last_identification.wrapping_add(1),
        );
        let slot = (refused.bucket() - owner * TFT_FRAGMENT_OWNER_BUCKETS) as usize;
        assert_eq!(
            buckets[slot].apply(
                refused,
                Some(first),
                Some(&meta(2)),
                Some((&packet, 11)),
                10
            ),
            TftFragmentDisposition::Capacity,
            "a colliding owner shares the group bound"
        );
        let admitted = TftFragmentKey::new(distinct, [192, 0, 2, 1], [198, 51, 100, 2], 50, 1);
        assert_eq!(
            TftFragmentBucket::new().apply(
                admitted,
                Some(first),
                Some(&meta(3)),
                Some((&packet, 11)),
                10
            ),
            TftFragmentDisposition::Selected(11),
            "a non-colliding owner is unaffected"
        );
    }

    #[test]
    fn fragment_envelope_validation_is_strict() {
        for (ihl, total, actual, flags) in [
            (0x45, 44, 44, 0xa000),
            (0x45, 44, 44, 0x6000),
            (0x44, 44, 44, 0x2000),
            (0x4f, 44, 44, 0x2000),
            (0x45, 20, 20, 0x2000),
            (0x45, 43, 43, 0x2000),
            (0x45, 44, 45, 0x2000),
            (0x45, 28, 28, 0x1fff),
        ] {
            assert!(TftIpv4Fragment::from_header(ihl, total, actual, flags).is_none());
        }
    }
}
