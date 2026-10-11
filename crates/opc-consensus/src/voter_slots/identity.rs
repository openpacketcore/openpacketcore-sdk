use serde::{Deserialize, Deserializer, Serialize};

use super::VoterSlotError;
use crate::ConsensusNodeId;

/// Largest incarnation admitting an injective, positive signed-63-bit Raft ID.
pub const MAX_VOTER_INCARNATION: u64 = 1 << 47;

/// Stable nonzero slot ordinal assigned by the immutable installation manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct SlotId(u16);

impl SlotId {
    /// Validate an ordinal; ordinals must never be recycled within an installation.
    pub const fn new(value: u16) -> Result<Self, VoterSlotError> {
        if value == 0 {
            return Err(VoterSlotError::InvalidSlot);
        }
        Ok(Self(value))
    }

    /// Fixed-width durable ordinal.
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for SlotId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(u16::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Positive incarnation within a stable slot, never reused after retirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct VoterIncarnation(u64);

impl VoterIncarnation {
    /// Validate the fixed profile's incarnation domain.
    pub const fn new(value: u64) -> Result<Self, VoterSlotError> {
        if value == 0 || value > MAX_VOTER_INCARNATION {
            return Err(VoterSlotError::InvalidIncarnation);
        }
        Ok(Self(value))
    }

    /// Durable numeric incarnation.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Allocate the next ordinal without wraparound or reuse.
    ///
    /// This arithmetic grants no authority to admit the resulting incarnation.
    pub const fn next(self) -> Result<Self, VoterSlotError> {
        if self.0 == MAX_VOTER_INCARNATION {
            return Err(VoterSlotError::IncarnationExhausted);
        }
        Ok(Self(self.0 + 1))
    }
}

impl<'de> Deserialize<'de> for VoterIncarnation {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(u64::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Incarnation-qualified identity, scoped by the enclosing installation ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct VoterSlotIdentity {
    slot: SlotId,
    incarnation: VoterIncarnation,
}

impl VoterSlotIdentity {
    /// Bind already validated coordinates.
    pub const fn new(slot: SlotId, incarnation: VoterIncarnation) -> Self {
        Self { slot, incarnation }
    }

    /// Stable logical slot.
    pub const fn slot(self) -> SlotId {
        self.slot
    }

    /// Current incarnation of that slot.
    pub const fn incarnation(self) -> VoterIncarnation {
        self.incarnation
    }

    /// Injective engine ID; unlike a hash it cannot collide within an installation.
    pub const fn node_id(self) -> ConsensusNodeId {
        ConsensusNodeId::from_voter_slot(self)
    }

    /// Reverse the fixed-profile mapping. This does not admit a peer or identify
    /// its installation; legacy dynamic IDs must not be interpreted this way.
    pub fn from_node_id(node: ConsensusNodeId) -> Result<Self, VoterSlotError> {
        Ok(Self::new(
            SlotId::new((node.get() & 0xffff) as u16)?,
            VoterIncarnation::new((node.get() >> 16) + 1)?,
        ))
    }
}
