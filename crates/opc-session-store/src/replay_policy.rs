//! Producer-selected replay semantics, independent of the mutation tree.

use crate::StoreError;

/// Maximum non-application rows accounted for by one source image.
pub const MAX_REPLICATION_INTERNAL_KEYS: u32 = 1_048_576;

/// Position within one bounded committed command's application entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum ReplicationCommandBoundary {
    /// This entry completes its command.
    Single,
    /// First entry, with the exact identity and number of following entries.
    Start {
        /// Identity shared by all entries of this command.
        id: [u8; 16],
        /// Number of entries still to apply, in 1..=255.
        following_entries: u16,
    },
    /// One explicitly identified continuation of a previously started command.
    Continue {
        /// Exact identity of the started command.
        id: [u8; 16],
        /// Number of entries remaining after this one, in 0..=254.
        remaining_entries: u16,
    },
}

/// Committed transition from one outward application cursor range to another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum ReplicationRecoveryBoundary {
    /// No recovery transition; the next cursor must be contiguous.
    None,
    /// Move from this exact predecessor to the committed recovery floor.
    Recover {
        /// Exact predecessor cursor before the new recovery floor takes effect.
        previous_sequence: u64,
    },
}

/// Complete replay policy selected by the producer of an application entry.
///
/// Mutations do not imply pruning, retirement, recovery or command boundaries.
/// Every field is present in the encoding; a missing policy is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ReplicationReplayPolicy {
    /// Prune globally expired records and expired/released leases before effects.
    pub prune_expired: bool,
    /// Finalize dead application keys after this entry's effects.
    pub retire_dead_keys: bool,
    /// Source recovery floor used by every rotation and fence observation.
    pub async_fence_floor: u64,
    /// Source capacity rotations, decided once at its command boundary.
    pub capacity_rotations: u8,
    /// Non-application source rows consuming the same resident-key capacity.
    pub internal_key_count: u32,
    /// Explicit framing of this entry within its committed source command.
    pub command: ReplicationCommandBoundary,
    /// Explicit committed recovery transition; ordinary gaps remain invalid.
    pub recovery: ReplicationRecoveryBoundary,
}

impl ReplicationReplayPolicy {
    /// Preserve unrelated records and exact retirement state.
    pub const fn preserve() -> Self {
        Self {
            prune_expired: false,
            retire_dead_keys: false,
            async_fence_floor: 0,
            capacity_rotations: 0,
            internal_key_count: 0,
            command: ReplicationCommandBoundary::Single,
            recovery: ReplicationRecoveryBoundary::None,
        }
    }

    /// Prune expiry without enabling an epoch-retirement policy.
    pub const fn prune_expired() -> Self {
        Self {
            prune_expired: true,
            ..Self::preserve()
        }
    }

    /// Prune expiry and finalize the source's bounded exact dead-key history.
    pub const fn prune_and_retire() -> Self {
        Self {
            prune_expired: true,
            retire_dead_keys: true,
            ..Self::preserve()
        }
    }

    pub(crate) fn validate(&self) -> Result<(), StoreError> {
        let invalid = || StoreError::Serialization("invalid replication replay policy".into());
        if self.async_fence_floor > i64::MAX as u64 - 2
            || self.capacity_rotations > 2
            || self.internal_key_count > MAX_REPLICATION_INTERNAL_KEYS
        {
            return Err(invalid());
        }
        match self.command {
            ReplicationCommandBoundary::Single => {}
            ReplicationCommandBoundary::Start {
                following_entries, ..
            } if (1..=255).contains(&following_entries) => {}
            ReplicationCommandBoundary::Continue {
                remaining_entries, ..
            } if remaining_entries <= 254
                && self.capacity_rotations == 0
                && self.recovery == ReplicationRecoveryBoundary::None => {}
            _ => return Err(invalid()),
        }
        if let ReplicationRecoveryBoundary::Recover { previous_sequence } = self.recovery {
            if self.async_fence_floor == 0
                || previous_sequence > self.async_fence_floor
                || self.command != ReplicationCommandBoundary::Single
                || self.prune_expired
                || self.retire_dead_keys
            {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

/// Bounded continuation metadata shared by application replay consumers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReplayCommandCursor {
    pub(crate) id: [u8; 16],
    pub(crate) remaining: u16,
    pub(crate) timestamp: opc_types::Timestamp,
    pub(crate) async_fence_floor: u64,
}

impl ReplayCommandCursor {
    pub(crate) fn after(entry: &crate::ReplicationEntry) -> Option<Self> {
        let (id, remaining) = match entry.replay_policy.command {
            ReplicationCommandBoundary::Start {
                id,
                following_entries,
            } => (id, following_entries),
            ReplicationCommandBoundary::Continue {
                id,
                remaining_entries,
            } if remaining_entries > 0 => (id, remaining_entries),
            _ => return None,
        };
        Some(Self {
            id,
            remaining,
            timestamp: entry.timestamp,
            async_fence_floor: entry.replay_policy.async_fence_floor,
        })
    }

    pub(crate) fn advance(
        pending: Option<Self>,
        entry: &crate::ReplicationEntry,
    ) -> Result<Option<Self>, StoreError> {
        match (pending, entry.replay_policy.command) {
            (
                None,
                ReplicationCommandBoundary::Single | ReplicationCommandBoundary::Start { .. },
            ) => {}
            (
                Some(pending),
                ReplicationCommandBoundary::Continue {
                    id,
                    remaining_entries,
                },
            ) if pending.id == id
                && pending.remaining == remaining_entries + 1
                && pending.timestamp == entry.timestamp
                && pending.async_fence_floor == entry.replay_policy.async_fence_floor => {}
            _ => {
                return Err(StoreError::Serialization(
                    "inconsistent replication command continuation".into(),
                ))
            }
        }
        let next = Self::after(entry);
        if let Some(cursor) = next {
            entry
                .sequence
                .checked_add(u64::from(cursor.remaining))
                .ok_or(StoreError::ReplicationOperationLimitExceeded)?;
        }
        Ok(next)
    }
}
