//! Minimal-disruption shard selection helpers.

use sha2::{Digest, Sha256};

use crate::error::IpsecLbError;
use crate::model::{IpAddress, ShardId};
use crate::ownership::{EligibleOwnershipMembers, OwnerSelection, SessionOwnershipKey};

/// A validated sorted set of unique shards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShardSet {
    shards: Vec<ShardId>,
}

impl ShardSet {
    /// Build a shard set from caller-supplied IDs.
    pub fn new(mut shards: Vec<ShardId>) -> Result<Self, IpsecLbError> {
        if shards.is_empty() {
            return Err(IpsecLbError::EmptyShardSet);
        }
        shards.sort_unstable();
        if shards.windows(2).any(|window| window[0] == window[1]) {
            return Err(IpsecLbError::DuplicateShard);
        }
        Ok(Self { shards })
    }

    /// Borrow the sorted shard list.
    #[must_use]
    pub fn shards(&self) -> &[ShardId] {
        &self.shards
    }

    /// Return true when the shard is present.
    #[must_use]
    pub fn contains(&self, shard: ShardId) -> bool {
        self.shards.binary_search(&shard).is_ok()
    }
}

/// Key material used only for deterministic selection, never IPsec crypto.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SelectionKey {
    /// Routing tag value.
    Tag(u64),
    /// Initial IKE_SA_INIT bootstrap key.
    IkeInit {
        /// Initiator SPI.
        initiator_spi: u64,
        /// Source IP.
        source_ip: IpAddress,
    },
    /// Raw bytes for tests or adapters.
    Bytes(Vec<u8>),
}

impl SelectionKey {
    fn feed_hasher(&self, hasher: &mut Sha256) {
        match self {
            Self::Tag(tag) => {
                hasher.update([0x01]);
                hasher.update(tag.to_be_bytes());
            }
            Self::IkeInit {
                initiator_spi,
                source_ip,
            } => {
                hasher.update([0x02]);
                hasher.update(initiator_spi.to_be_bytes());
                match source_ip {
                    IpAddress::V4(octets) => {
                        hasher.update([4]);
                        hasher.update(octets);
                    }
                    IpAddress::V6(octets) => {
                        hasher.update([6]);
                        hasher.update(octets);
                    }
                }
            }
            Self::Bytes(bytes) => {
                hasher.update([0x03]);
                hasher.update((bytes.len() as u64).to_be_bytes());
                hasher.update(bytes);
            }
        }
    }
}

/// Rendezvous/HRW selector.
#[derive(Debug, Clone, Copy, Default)]
pub struct RendezvousSelector;

impl RendezvousSelector {
    /// Select the highest-scoring shard for the key.
    pub fn select(&self, shards: &ShardSet, key: &SelectionKey) -> Result<ShardId, IpsecLbError> {
        let mut best: Option<(u128, ShardId)> = None;
        for shard in shards.shards() {
            let score = score_key(*shard, key);
            match best {
                Some((best_score, best_shard))
                    if score < best_score || (score == best_score && *shard >= best_shard) => {}
                _ => best = Some((score, *shard)),
            }
        }
        best.map(|(_, shard)| shard)
            .ok_or(IpsecLbError::EmptyShardSet)
    }

    /// Select the deterministic owner for one destination-scoped session key.
    ///
    /// The membership generation is intentionally not mixed into the HRW
    /// score: advancing an otherwise identical membership view therefore does
    /// not move every session. The returned [`OwnerSelection`] carries the
    /// generation so an effect point can reject a selection made from a stale
    /// view.
    pub fn select_owner(
        &self,
        membership: &EligibleOwnershipMembers,
        key: &SessionOwnershipKey,
    ) -> Result<OwnerSelection, crate::ownership::OwnershipSelectionError> {
        let mut best: Option<(u128, ShardId)> = None;
        let key_digest = key.canonical_digest();
        for member in membership.members() {
            let score = score_ownership_key(*member, &key_digest);
            match best {
                Some((best_score, best_member))
                    if score < best_score || (score == best_score && *member >= best_member) => {}
                _ => best = Some((score, *member)),
            }
        }

        // EligibleOwnershipMembers structurally contains at least one member.
        // Avoid unwrap/expect so this remains robust if the representation is
        // refactored later.
        let owner = best
            .map(|(_, owner)| owner)
            .ok_or(crate::ownership::OwnershipSelectionError::EmptyMembership)?;
        Ok(OwnerSelection::new(
            owner,
            membership.generation(),
            key_digest,
        ))
    }
}

fn score_key(shard: ShardId, key: &SelectionKey) -> u128 {
    let mut hasher = Sha256::new();
    hasher.update(b"opc-ipsec-lb/rendezvous/v1");
    hasher.update(shard.get().to_be_bytes());
    key.feed_hasher(&mut hasher);
    let digest = hasher.finalize();
    let mut score = [0u8; 16];
    score.copy_from_slice(&digest[..16]);
    u128::from_be_bytes(score)
}

fn score_ownership_key(member: ShardId, key_digest: &[u8; 32]) -> u128 {
    let mut hasher = Sha256::new();
    hasher.update(b"opc-ipsec-lb/ownership-rendezvous/v1");
    hasher.update(member.get().to_be_bytes());
    hasher.update(key_digest);
    let digest = hasher.finalize();
    let mut score = [0u8; 16];
    score.copy_from_slice(&digest[..16]);
    u128::from_be_bytes(score)
}

/// Measured movement when a shard set changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShardDisruption {
    /// Number of keys measured.
    pub total_keys: usize,
    /// Keys whose selected shard changed.
    pub moved_keys: usize,
}

impl ShardDisruption {
    /// Return movement in parts per million.
    #[must_use]
    pub fn moved_ppm(self) -> u64 {
        if self.total_keys == 0 {
            return 0;
        }
        ((self.moved_keys as u128 * 1_000_000) / self.total_keys as u128) as u64
    }
}

/// Measure how many keys move between two shard sets.
pub fn measure_disruption(
    before: &ShardSet,
    after: &ShardSet,
    keys: &[SelectionKey],
) -> Result<ShardDisruption, IpsecLbError> {
    let selector = RendezvousSelector;
    let mut moved = 0usize;
    for key in keys {
        if selector.select(before, key)? != selector.select(after, key)? {
            moved += 1;
        }
    }
    Ok(ShardDisruption {
        total_keys: keys.len(),
        moved_keys: moved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shards(count: u16) -> ShardSet {
        ShardSet::new((0..count).map(ShardId::new).collect()).unwrap()
    }

    #[test]
    fn shard_set_rejects_empty_and_duplicate_inputs() {
        assert!(matches!(
            ShardSet::new(Vec::new()).unwrap_err(),
            IpsecLbError::EmptyShardSet
        ));
        assert!(matches!(
            ShardSet::new(vec![ShardId::new(1), ShardId::new(1)]).unwrap_err(),
            IpsecLbError::DuplicateShard
        ));
    }

    #[test]
    fn rendezvous_is_stable_for_same_key_and_shards() {
        let set = shards(5);
        let selector = RendezvousSelector;
        let key = SelectionKey::Tag(42);
        assert_eq!(
            selector.select(&set, &key).unwrap(),
            selector.select(&set, &key).unwrap()
        );
    }

    #[test]
    fn adding_one_shard_does_not_shuffle_everything() {
        let before = shards(5);
        let after = shards(6);
        let keys: Vec<_> = (0..65_536).map(SelectionKey::Tag).collect();
        let disruption = measure_disruption(&before, &after, &keys).unwrap();
        let upper_bound = keys.len().div_ceil(5);
        assert!(
            disruption.moved_keys <= upper_bound,
            "moved={} upper_bound={} ppm={}",
            disruption.moved_keys,
            upper_bound,
            disruption.moved_ppm()
        );
    }
}
