//! Shared bounded RFC 2782 draw; callers canonicalize before drawing.

use crate::{DnsError, DnsName, SnaptrFilter, SnaptrOrdering};

pub(super) fn weighted_order<T, K: PartialEq>(
    records: Vec<T>,
    seed: u64,
    priority: impl Fn(&T) -> K,
    weight: impl Fn(&T) -> u16,
) -> Result<Vec<T>, DnsError> {
    let mut records = records;
    let mut random = SelectionRandom(seed);
    let mut ordered = Vec::with_capacity(records.len());
    while let Some(first) = records.first() {
        let end = records
            .iter()
            .take_while(|r| priority(r) == priority(first))
            .count();
        let mut group: Vec<_> = records.drain(..end).collect();
        for index in (1..group.len()).rev() {
            let other = random.below(index as u64 + 1)? as usize;
            group.swap(index, other);
        }
        group.sort_by_key(|record| weight(record) != 0);
        while !group.is_empty() {
            let sum: u64 = group.iter().map(|record| u64::from(weight(record))).sum();
            let draw = random.below(sum + 1)?;
            let mut running = 0;
            let index = group
                .iter()
                .position(|record| {
                    running += u64::from(weight(record));
                    running >= draw
                })
                .ok_or(DnsError::MalformedAnswer)?;
            ordered.push(group.remove(index));
        }
    }
    Ok(ordered)
}

// SplitMix64 is selection-only; DNS IDs and source ports use independent entropy.
struct SelectionRandom(u64);

impl SelectionRandom {
    fn below(&mut self, bound: u64) -> Result<u64, DnsError> {
        let threshold = bound.wrapping_neg() % bound;
        for _ in 0..32 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut value = self.0;
            value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            value ^= value >> 31;
            if value >= threshold {
                return Ok(value % bound);
            }
        }
        Err(DnsError::LimitExceeded)
    }
}

pub(super) fn snaptr_seed(seed: u64, kind: u16, owner: &DnsName, filter: &SnaptrFilter) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    let mut add = |bytes: &[u8]| {
        for byte in bytes {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100_0000_01b3);
        }
    };
    add(b"opc-snaptr-draw-v1\0");
    add(&seed.to_be_bytes());
    add(&kind.to_be_bytes());
    add(&[match filter.ordering() {
        SnaptrOrdering::Rfc3958 => 0,
        SnaptrOrdering::ThreeGpp => 1,
    }]);
    for value in [owner.as_str(), filter.service(), filter.protocol()] {
        // Public constructors bound these strings well below u16::MAX.
        add(&(value.len() as u16).to_be_bytes());
        add(value.as_bytes());
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snaptr_seed_matches_independently_framed_fnv_vectors() {
        // Independently calculated using Python struct.pack('>QHB') and
        // length-prefixed ASCII strings, not a production hashing helper.
        for (seed, kind, profile, owner, service, protocol, expected) in [
            (
                0,
                35,
                SnaptrOrdering::Rfc3958,
                "ims.apn.epc.mnc001.mcc001.3gppnetwork.org.",
                "x-3gpp-pgw",
                "x-s2b-gtp",
                0xd778_e9a9_9cc9_2954,
            ),
            (
                7,
                33,
                SnaptrOrdering::ThreeGpp,
                "service.example.invalid.",
                "x-3gpp-pgw",
                "x-s2b-gtp",
                0x2b89_df48_0143_ed45,
            ),
            (
                u64::MAX,
                35,
                SnaptrOrdering::Rfc3958,
                "nai.epc.mnc001.mcc001.3gppnetwork.org.",
                "aaa+ap16777264",
                "diameter.sctp",
                0x37f4_ad52_4d02_0774,
            ),
        ] {
            let filter = SnaptrFilter::new(service, protocol, profile).unwrap();
            assert_eq!(
                snaptr_seed(seed, kind, &DnsName::new(owner).unwrap(), &filter),
                expected
            );
            assert_ne!(
                snaptr_seed(seed, kind + 1, &DnsName::new(owner).unwrap(), &filter),
                expected
            );
            assert_ne!(
                snaptr_seed(
                    seed,
                    kind,
                    &DnsName::new("different.example.").unwrap(),
                    &filter
                ),
                expected
            );
        }
    }
}
