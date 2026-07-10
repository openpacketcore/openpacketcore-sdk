//! Tagged SPI allocation and decoding.

use rand::{rngs::SysRng, TryRng};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use crate::error::IpsecLbError;
use crate::model::ShardId;
use crate::ports::SpiAllocator;
use crate::selector::{RendezvousSelector, SelectionKey, ShardSet};

const MAX_ALLOCATION_ATTEMPTS: usize = 256;
const MAX_TAG_BITS: u8 = 16;

/// SPI wire kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpiKind {
    /// 64-bit IKE responder SPI.
    Ikev2Responder,
    /// 32-bit ESP Child SA SPI.
    ChildEsp,
    /// Test or future extension with caller-supplied bit width.
    Custom {
        /// Total wire bits.
        total_bits: u8,
    },
}

impl SpiKind {
    /// Total bits available on the wire.
    #[must_use]
    pub const fn total_bits(self) -> u8 {
        match self {
            Self::Ikev2Responder => 64,
            Self::ChildEsp => 32,
            Self::Custom { total_bits } => total_bits,
        }
    }
}

/// Tagged SPI layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaggedSpiLayout {
    kind: SpiKind,
    tag_bits: u8,
    min_unpredictable_bits: u8,
}

impl TaggedSpiLayout {
    /// Build and validate a tagged SPI layout.
    pub fn new(
        kind: SpiKind,
        tag_bits: u8,
        min_unpredictable_bits: u8,
    ) -> Result<Self, IpsecLbError> {
        let total_bits = kind.total_bits();
        let random_bits = total_bits.saturating_sub(tag_bits);
        if tag_bits == 0
            || tag_bits >= total_bits
            || tag_bits > MAX_TAG_BITS
            || total_bits > 64
            || random_bits < min_unpredictable_bits
        {
            return Err(IpsecLbError::InvalidSpiLayout {
                total_bits,
                tag_bits,
                min_unpredictable_bits,
            });
        }
        Ok(Self {
            kind,
            tag_bits,
            min_unpredictable_bits,
        })
    }

    /// Total wire bits.
    #[must_use]
    pub const fn total_bits(self) -> u8 {
        self.kind.total_bits()
    }

    /// Routing tag bits.
    #[must_use]
    pub const fn tag_bits(self) -> u8 {
        self.tag_bits
    }

    /// Unpredictable non-tag bits.
    #[must_use]
    pub const fn unpredictable_bits(self) -> u8 {
        self.total_bits() - self.tag_bits
    }

    /// Minimum configured unpredictable bits.
    #[must_use]
    pub const fn min_unpredictable_bits(self) -> u8 {
        self.min_unpredictable_bits
    }

    /// SPI kind.
    #[must_use]
    pub const fn kind(self) -> SpiKind {
        self.kind
    }

    fn tag_mask(self) -> u64 {
        mask_for_bits(self.tag_bits)
    }

    fn random_mask(self) -> u64 {
        mask_for_bits(self.unpredictable_bits())
    }

    fn max_value(self) -> u64 {
        mask_for_bits(self.total_bits())
    }

    /// Smallest SPI value this kind may allocate. RFC 4303 §2.1 / IANA reserve
    /// ESP SPI values 1..=255 (and 0 for every kind), so a Child ESP SPI must be
    /// >= 256; a zero SPI is reserved for all kinds.
    fn min_value(self) -> u64 {
        match self.kind {
            SpiKind::ChildEsp => 256,
            _ => 1,
        }
    }

    fn encode(self, tag: u64, random: u64) -> Result<u64, IpsecLbError> {
        if tag > self.tag_mask() || random > self.random_mask() {
            return Err(IpsecLbError::SpiOutOfRange);
        }
        let value = (tag << self.unpredictable_bits()) | random;
        if value < self.min_value() || value > self.max_value() {
            return Err(IpsecLbError::SpiOutOfRange);
        }
        Ok(value)
    }

    fn decode_tag(self, value: u64) -> Result<u64, IpsecLbError> {
        if value < self.min_value() || value > self.max_value() {
            return Err(IpsecLbError::SpiOutOfRange);
        }
        Ok((value >> self.unpredictable_bits()) & self.tag_mask())
    }
}

fn mask_for_bits(bits: u8) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

/// Allocated tagged SPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TaggedSpi {
    /// SPI kind.
    pub kind: SpiKind,
    /// Raw SPI value in host byte order.
    pub value: u64,
    /// Routing tag embedded in the high bits.
    pub tag: u64,
    /// Shard selected by the tag.
    pub shard: ShardId,
}

impl TaggedSpi {
    /// Return the SPI as a 32-bit ESP value.
    pub fn as_u32(self) -> Result<u32, IpsecLbError> {
        u32::try_from(self.value).map_err(|_| IpsecLbError::SpiOutOfRange)
    }
}

/// Request for a fresh SPI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpiAllocationRequest {
    /// SPI wire kind.
    pub kind: SpiKind,
    /// Owner shard.
    pub shard: ShardId,
}

/// Request for a rekey SPI that must keep the old tag stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RekeyRequest {
    /// SPI being replaced.
    pub replaces: TaggedSpi,
}

/// Entropy source for deterministic tests and system-backed production use.
pub trait EntropySource: Send + Sync + std::fmt::Debug {
    /// Fill bytes with unpredictable material.
    fn fill_bytes(&self, dst: &mut [u8]) -> Result<(), IpsecLbError>;
}

/// System CSPRNG entropy source.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemEntropy;

impl EntropySource for SystemEntropy {
    fn fill_bytes(&self, dst: &mut [u8]) -> Result<(), IpsecLbError> {
        SysRng
            .try_fill_bytes(dst)
            .map_err(|_| IpsecLbError::EntropyUnavailable)
    }
}

/// Deterministic entropy source for tests.
#[derive(Debug, Clone)]
pub struct FixedEntropy {
    bytes: Vec<u8>,
    cursor: Arc<Mutex<usize>>,
}

impl FixedEntropy {
    /// Build a deterministic entropy source that repeats the provided bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            cursor: Arc::new(Mutex::new(0)),
        }
    }
}

impl EntropySource for FixedEntropy {
    fn fill_bytes(&self, dst: &mut [u8]) -> Result<(), IpsecLbError> {
        if self.bytes.is_empty() {
            return Err(IpsecLbError::EntropyUnavailable);
        }
        let mut cursor = self
            .cursor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for (idx, byte) in dst.iter_mut().enumerate() {
            *byte = self.bytes[(*cursor + idx) % self.bytes.len()];
        }
        *cursor = cursor.saturating_add(dst.len());
        Ok(())
    }
}

/// Tagged SPI allocator.
#[derive(Debug, Clone)]
pub struct TaggedSpiAllocator<E = SystemEntropy> {
    layout: TaggedSpiLayout,
    shards: ShardSet,
    selector: RendezvousSelector,
    /// Precomputed shard -> owned routing tags, built once at construction so
    /// allocation does not re-run the O(2^tag_bits * shards) rendezvous map on
    /// every attach.
    shard_tags: BTreeMap<ShardId, Vec<u64>>,
    entropy: E,
    /// Externally live SPIs, such as HA-restored SAs, that fresh and rekey
    /// allocation must redraw past. Clones share this set.
    reserved: Arc<Mutex<BTreeSet<u64>>>,
}

/// Precompute, for each shard, the routing tags it owns under the rendezvous
/// selector (the canonical tag->shard mapping, matching `decode`). Rendezvous
/// selection is infallible for a non-empty `ShardSet`, so any error just skips a
/// tag rather than panicking.
fn precompute_shard_tags(
    layout: TaggedSpiLayout,
    shards: &ShardSet,
) -> BTreeMap<ShardId, Vec<u64>> {
    let selector = RendezvousSelector;
    let mut map: BTreeMap<ShardId, Vec<u64>> = BTreeMap::new();
    // `tag_bits` is 1..=MAX_TAG_BITS (16) by construction, so the shift is bounded.
    let tag_count: u64 = 1 << layout.tag_bits();
    for tag in 0..tag_count {
        if let Ok(shard) = selector.select(shards, &SelectionKey::Tag(tag)) {
            map.entry(shard).or_default().push(tag);
        }
    }
    map
}

impl TaggedSpiAllocator<SystemEntropy> {
    /// Build an allocator using the system CSPRNG.
    pub fn system(layout: TaggedSpiLayout, shards: ShardSet) -> Self {
        Self::new(layout, shards, SystemEntropy)
    }
}

impl<E> TaggedSpiAllocator<E>
where
    E: EntropySource,
{
    /// Build an allocator from an explicit entropy source.
    #[must_use]
    pub fn new(layout: TaggedSpiLayout, shards: ShardSet, entropy: E) -> Self {
        let shard_tags = precompute_shard_tags(layout, &shards);
        Self {
            layout,
            shards,
            selector: RendezvousSelector,
            shard_tags,
            entropy,
            reserved: Arc::default(),
        }
    }

    /// Return the allocator layout.
    #[must_use]
    pub const fn layout(&self) -> TaggedSpiLayout {
        self.layout
    }

    fn random_low_bits(&self) -> Result<u64, IpsecLbError> {
        let mut bytes = [0u8; 8];
        self.entropy.fill_bytes(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes) & self.layout.random_mask())
    }

    fn tags_for_shard(&self, shard: ShardId) -> Result<&[u64], IpsecLbError> {
        if !self.shards.contains(shard) {
            return Err(IpsecLbError::UnknownShard);
        }
        match self.shard_tags.get(&shard) {
            Some(tags) if !tags.is_empty() => Ok(tags),
            _ => Err(IpsecLbError::TagSpaceExhausted),
        }
    }

    fn choose_tag(&self, shard: ShardId) -> Result<u64, IpsecLbError> {
        let tags = self.tags_for_shard(shard)?;
        let random = self.random_low_bits()?;
        let index = (random as usize) % tags.len();
        Ok(tags[index])
    }

    /// Reserve an externally live tagged SPI.
    ///
    /// The supplied kind, tag, and shard must be the canonical metadata that
    /// this allocator decodes from `value`. The operation is idempotent and
    /// shared by every clone of this allocator.
    ///
    /// # Errors
    ///
    /// Returns [`IpsecLbError`] when the SPI does not belong to this allocator's
    /// kind/layout/shard map or its metadata is inconsistent.
    pub fn reserve(&self, spi: TaggedSpi) -> Result<bool, IpsecLbError> {
        self.validate_tagged_spi(spi)?;
        Ok(self.lock_reserved().insert(spi.value))
    }

    /// Release a reservation after the corresponding SA is no longer live.
    ///
    /// Returns `true` when a reservation existed. Canonical metadata is still
    /// required so a stale or wrong-kind release cannot free another live SA's
    /// exclusion by raw value alone.
    ///
    /// # Errors
    ///
    /// Returns [`IpsecLbError`] when `spi` is not canonical for this allocator.
    pub fn release(&self, spi: TaggedSpi) -> Result<bool, IpsecLbError> {
        self.validate_tagged_spi(spi)?;
        Ok(self.lock_reserved().remove(&spi.value))
    }

    /// Return whether a canonical tagged SPI is currently reserved.
    ///
    /// # Errors
    ///
    /// Returns [`IpsecLbError`] when `spi` is not canonical for this allocator.
    pub fn is_reserved(&self, spi: TaggedSpi) -> Result<bool, IpsecLbError> {
        self.validate_tagged_spi(spi)?;
        Ok(self.is_value_reserved(spi.value))
    }

    fn validate_tagged_spi(&self, spi: TaggedSpi) -> Result<(), IpsecLbError> {
        let decoded = self.decode(spi.kind, spi.value)?;
        if decoded.tag != spi.tag || decoded.shard != spi.shard {
            return Err(IpsecLbError::invalid_config(
                "tagged_spi",
                "tag and shard metadata must match the encoded SPI value",
            ));
        }
        Ok(())
    }

    fn is_value_reserved(&self, value: u64) -> bool {
        self.lock_reserved().contains(&value)
    }

    fn lock_reserved(&self) -> std::sync::MutexGuard<'_, BTreeSet<u64>> {
        self.reserved
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl<E> SpiAllocator for TaggedSpiAllocator<E>
where
    E: EntropySource,
{
    fn allocate(&self, request: SpiAllocationRequest) -> Result<TaggedSpi, IpsecLbError> {
        if request.kind != self.layout.kind() {
            return Err(IpsecLbError::SpiOutOfRange);
        }
        let tag = self.choose_tag(request.shard)?;
        for _ in 0..MAX_ALLOCATION_ATTEMPTS {
            let random = self.random_low_bits()?;
            if let Ok(value) = self.layout.encode(tag, random) {
                if self.is_value_reserved(value) {
                    continue;
                }
                return Ok(TaggedSpi {
                    kind: request.kind,
                    value,
                    tag,
                    shard: request.shard,
                });
            }
        }
        Err(IpsecLbError::AllocationAttemptsExhausted)
    }

    fn allocate_rekey(&self, request: RekeyRequest) -> Result<TaggedSpi, IpsecLbError> {
        if request.replaces.kind != self.layout.kind() {
            return Err(IpsecLbError::SpiOutOfRange);
        }
        for _ in 0..MAX_ALLOCATION_ATTEMPTS {
            let random = self.random_low_bits()?;
            if let Ok(value) = self.layout.encode(request.replaces.tag, random) {
                if value == request.replaces.value || self.is_value_reserved(value) {
                    continue;
                }
                return Ok(TaggedSpi {
                    kind: request.replaces.kind,
                    value,
                    tag: request.replaces.tag,
                    shard: request.replaces.shard,
                });
            }
        }
        Err(IpsecLbError::AllocationAttemptsExhausted)
    }

    fn decode(&self, kind: SpiKind, value: u64) -> Result<TaggedSpi, IpsecLbError> {
        if kind != self.layout.kind() {
            return Err(IpsecLbError::SpiOutOfRange);
        }
        let tag = self.layout.decode_tag(value)?;
        let shard = self
            .selector
            .select(&self.shards, &SelectionKey::Tag(tag))?;
        Ok(TaggedSpi {
            kind,
            value,
            tag,
            shard,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shard_set() -> ShardSet {
        ShardSet::new(vec![ShardId::new(0), ShardId::new(1), ShardId::new(2)]).unwrap()
    }

    #[test]
    fn strict_entropy_floor_rejects_tagged_ike_and_esp_layouts() {
        assert!(matches!(
            TaggedSpiLayout::new(SpiKind::Ikev2Responder, 1, 64).unwrap_err(),
            IpsecLbError::InvalidSpiLayout { .. }
        ));
        assert!(matches!(
            TaggedSpiLayout::new(SpiKind::ChildEsp, 1, 64).unwrap_err(),
            IpsecLbError::InvalidSpiLayout { .. }
        ));
    }

    #[test]
    fn allocation_round_trips_decode_to_owner_shard() {
        let layout = TaggedSpiLayout::new(SpiKind::ChildEsp, 8, 24).unwrap();
        let allocator =
            TaggedSpiAllocator::new(layout, shard_set(), FixedEntropy::new(vec![0x5a, 0xc3]));
        let spi = allocator
            .allocate(SpiAllocationRequest {
                kind: SpiKind::ChildEsp,
                shard: ShardId::new(1),
            })
            .unwrap();
        let decoded = allocator.decode(SpiKind::ChildEsp, spi.value).unwrap();
        assert_eq!(decoded.shard, ShardId::new(1));
        assert_eq!(decoded.tag, spi.tag);
        assert_ne!(decoded.value, 0);
        assert!(decoded.as_u32().is_ok());
    }

    #[test]
    fn rekey_keeps_the_same_tag_and_shard() {
        let layout = TaggedSpiLayout::new(SpiKind::ChildEsp, 8, 24).unwrap();
        let allocator =
            TaggedSpiAllocator::new(layout, shard_set(), FixedEntropy::new((0..64).collect()));
        let old = allocator
            .allocate(SpiAllocationRequest {
                kind: SpiKind::ChildEsp,
                shard: ShardId::new(2),
            })
            .unwrap();
        let new = allocator
            .allocate_rekey(RekeyRequest { replaces: old })
            .unwrap();
        assert_eq!(new.tag, old.tag);
        assert_eq!(new.shard, old.shard);
        assert_ne!(new.value, old.value);
    }

    #[test]
    fn allocation_and_rekey_redraw_past_reserved_spis() {
        let layout = TaggedSpiLayout::new(SpiKind::ChildEsp, 8, 24).unwrap();
        let entropy: Vec<u8> = (0..64).collect();
        let probe =
            TaggedSpiAllocator::new(layout, shard_set(), FixedEntropy::new(entropy.clone()));
        let request = SpiAllocationRequest {
            kind: SpiKind::ChildEsp,
            shard: ShardId::new(1),
        };
        let blocked = probe.allocate(request).unwrap();

        let allocator = TaggedSpiAllocator::new(layout, shard_set(), FixedEntropy::new(entropy));
        assert!(allocator.reserve(blocked).unwrap());
        let redrawn = allocator.allocate(request).unwrap();
        assert_ne!(redrawn.value, blocked.value);

        let rekey_entropy: Vec<u8> = (64..128).collect();
        let rekey_probe = TaggedSpiAllocator::new(
            layout,
            shard_set(),
            FixedEntropy::new(rekey_entropy.clone()),
        );
        let blocked_rekey = rekey_probe
            .allocate_rekey(RekeyRequest { replaces: redrawn })
            .unwrap();
        let rekey_allocator =
            TaggedSpiAllocator::new(layout, shard_set(), FixedEntropy::new(rekey_entropy));
        assert!(rekey_allocator.reserve(blocked_rekey).unwrap());
        let replacement = rekey_allocator
            .allocate_rekey(RekeyRequest { replaces: redrawn })
            .unwrap();
        assert_ne!(replacement.value, blocked_rekey.value);
        assert_eq!(replacement.tag, redrawn.tag);
        assert_eq!(replacement.shard, redrawn.shard);
    }

    #[test]
    fn cloned_allocators_share_idempotent_reservations_and_release() {
        let layout = TaggedSpiLayout::new(SpiKind::ChildEsp, 8, 24).unwrap();
        let allocator =
            TaggedSpiAllocator::new(layout, shard_set(), FixedEntropy::new((0..64).collect()));
        let spi = allocator
            .allocate(SpiAllocationRequest {
                kind: SpiKind::ChildEsp,
                shard: ShardId::new(2),
            })
            .unwrap();
        let clone = allocator.clone();

        assert!(clone.reserve(spi).unwrap());
        assert!(!allocator.reserve(spi).unwrap());
        assert!(allocator.is_reserved(spi).unwrap());
        assert!(allocator.release(spi).unwrap());
        assert!(!clone.is_reserved(spi).unwrap());
        assert!(!clone.release(spi).unwrap());
    }

    #[test]
    fn reservation_rejects_wrong_kind_and_noncanonical_metadata() {
        let layout = TaggedSpiLayout::new(SpiKind::ChildEsp, 8, 24).unwrap();
        let allocator =
            TaggedSpiAllocator::new(layout, shard_set(), FixedEntropy::new((0..64).collect()));
        let spi = allocator
            .allocate(SpiAllocationRequest {
                kind: SpiKind::ChildEsp,
                shard: ShardId::new(1),
            })
            .unwrap();

        let wrong_kind = TaggedSpi {
            kind: SpiKind::Ikev2Responder,
            ..spi
        };
        assert!(matches!(
            allocator.reserve(wrong_kind),
            Err(IpsecLbError::SpiOutOfRange)
        ));

        let wrong_tag = TaggedSpi {
            tag: spi.tag ^ 1,
            ..spi
        };
        assert!(matches!(
            allocator.reserve(wrong_tag),
            Err(IpsecLbError::InvalidConfig {
                field: "tagged_spi",
                ..
            })
        ));

        let wrong_shard = TaggedSpi {
            shard: ShardId::new(u16::MAX),
            ..spi
        };
        assert!(matches!(
            allocator.reserve(wrong_shard),
            Err(IpsecLbError::InvalidConfig {
                field: "tagged_spi",
                ..
            })
        ));
    }

    #[test]
    fn reserved_collision_exhausts_within_bounded_attempts() {
        let layout = TaggedSpiLayout::new(SpiKind::ChildEsp, 8, 24).unwrap();
        let entropy = vec![0x5a, 0xc3];
        let probe =
            TaggedSpiAllocator::new(layout, shard_set(), FixedEntropy::new(entropy.clone()));
        let request = SpiAllocationRequest {
            kind: SpiKind::ChildEsp,
            shard: ShardId::new(1),
        };
        let blocked = probe.allocate(request).unwrap();
        let allocator = TaggedSpiAllocator::new(layout, shard_set(), FixedEntropy::new(entropy));
        allocator.reserve(blocked).unwrap();

        assert_eq!(
            allocator.allocate(request).unwrap_err(),
            IpsecLbError::AllocationAttemptsExhausted
        );
    }

    #[test]
    fn decode_rejects_zero_spi() {
        let layout = TaggedSpiLayout::new(SpiKind::ChildEsp, 8, 24).unwrap();
        let allocator = TaggedSpiAllocator::new(layout, shard_set(), FixedEntropy::new(vec![0x01]));
        assert!(matches!(
            allocator.decode(SpiKind::ChildEsp, 0).unwrap_err(),
            IpsecLbError::SpiOutOfRange
        ));
        assert!(matches!(
            allocator.decode(SpiKind::ChildEsp, 255).unwrap_err(),
            IpsecLbError::SpiOutOfRange
        ));
    }

    #[test]
    fn esp_layout_excludes_iana_reserved_low_spis() {
        // RFC 4303 §2.1 / IANA reserve ESP SPI values 1..=255; the allocator must
        // never emit them. IKE reserves only 0.
        let esp = TaggedSpiLayout::new(SpiKind::ChildEsp, 8, 24).unwrap();
        assert!(matches!(
            esp.encode(0, 5).unwrap_err(),
            IpsecLbError::SpiOutOfRange
        ));
        assert!(matches!(
            esp.encode(0, 255).unwrap_err(),
            IpsecLbError::SpiOutOfRange
        ));
        assert_eq!(esp.encode(0, 256).unwrap(), 256);

        let ike = TaggedSpiLayout::new(SpiKind::Ikev2Responder, 8, 24).unwrap();
        assert!(matches!(
            ike.encode(0, 0).unwrap_err(),
            IpsecLbError::SpiOutOfRange
        ));
        assert_eq!(ike.encode(0, 5).unwrap(), 5);
    }
}
