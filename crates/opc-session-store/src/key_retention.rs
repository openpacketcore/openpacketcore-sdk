//! Shared committed epoch vocabulary for bounded exact key history.

use serde::{Deserialize, Serialize};

/// Complete-key ordering shared by retirement finalizers, independent of map
/// iteration order and of the fake's existing restore ordering.
pub(crate) fn compare_key_parts(
    left: (&str, &str, &crate::SessionKeyType, &[u8]),
    right: (&str, &str, &crate::SessionKeyType, &[u8]),
) -> std::cmp::Ordering {
    fn kind(value: &crate::SessionKeyType) -> u8 {
        match value {
            crate::SessionKeyType::SubscriberContext => 0,
            crate::SessionKeyType::PduSession => 1,
            crate::SessionKeyType::TeidMapping => 2,
            crate::SessionKeyType::PfcpSeid => 3,
            crate::SessionKeyType::HandoverTransaction => 4,
            crate::SessionKeyType::Other(_) => 5,
        }
    }
    (left.0, left.1, left.2.as_str(), kind(left.2), left.3).cmp(&(
        right.0,
        right.1,
        right.2.as_str(),
        kind(right.2),
        right.3,
    ))
}

/// Frozen by the native generation vocabulary; replicas cannot tune it locally.
pub(crate) const RETIRED_KEYS_PER_EPOCH: u64 = 32_768;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RotationReason {
    Threshold,
    Capacity,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeyRetention {
    pub(crate) epoch: u64,
    pub(crate) floor_prev: u64,
    pub(crate) floor_cur: u64,
    pub(crate) retired_max: u64,
    pub(crate) retired_count: u64,
    pub(crate) last_rotation: Option<RotationReason>,
}

impl KeyRetention {
    /// Close one epoch atomically. The returned epoch is the oldest bucket
    /// that must be removed before publishing the new metadata.
    pub(crate) fn rotate(
        &mut self,
        next_fence: &mut u64,
        counter_limit: u64,
        async_floor: u64,
        reason: RotationReason,
    ) -> Result<Option<u64>, crate::StoreError> {
        let exhausted = || crate::StoreError::FencedTransitionStorageExhausted;
        let epoch = self.epoch.checked_add(1).ok_or_else(exhausted)?;
        // Advance the floor callers actually observe, including after Async
        // recovery. Otherwise two physical rotations below that recovery floor
        // would leave an old absent-key preparation valid.
        let floor_prev = self.floor_cur.max(async_floor);
        let floor_cur = floor_prev
            .checked_add(1)
            .ok_or_else(exhausted)?
            .max(self.retired_max.checked_add(1).ok_or_else(exhausted)?);
        let allocated = (*next_fence).max(floor_cur.checked_add(1).ok_or_else(exhausted)?);
        if allocated > counter_limit {
            return Err(exhausted());
        }
        *self = Self {
            epoch,
            floor_prev,
            floor_cur,
            retired_max: 0,
            retired_count: 0,
            last_rotation: Some(reason),
        };
        *next_fence = allocated;
        Ok(epoch.checked_sub(2))
    }

    pub(crate) fn observed_absent_fence(self, async_floor: u64) -> u64 {
        self.floor_cur.max(async_floor)
    }

    #[cfg(any(target_os = "linux", feature = "lab-memory", test))]
    pub(crate) fn accepts_absent_fence(self, expected: u64, async_floor: u64) -> bool {
        expected == self.floor_prev.max(async_floor) || expected == self.floor_cur.max(async_floor)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn retains_epoch(self, retired_epoch: u64) -> bool {
        retired_epoch == self.epoch || self.epoch.checked_sub(1) == Some(retired_epoch)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn valid_retired_fence(self, retired_epoch: u64, fence: u64) -> bool {
        self.retains_epoch(retired_epoch)
            && if retired_epoch == self.epoch {
                fence <= self.retired_max
            } else {
                fence < self.floor_cur
            }
    }

    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn valid(self, next_fence: u64) -> bool {
        self.floor_prev <= self.floor_cur
            && self.floor_cur < next_fence
            && self.retired_max < next_fence
            && self.retired_count < RETIRED_KEYS_PER_EPOCH
            && (self.retired_count != 0 || self.retired_max == 0)
            && (self.epoch != 0 || (self.floor_prev == 0 && self.floor_cur == 0))
            && ((self.epoch == 0) == self.last_rotation.is_none())
            && (self.epoch == 0 || self.floor_prev < self.floor_cur)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_rotations_advance_the_observed_async_floor() {
        let mut keys = KeyRetention::default();
        let mut next = 101;
        let async_floor = 100;
        let prepared = keys.observed_absent_fence(async_floor);
        assert_eq!(prepared, 100);
        assert!(keys.accepts_absent_fence(prepared, async_floor));
        assert!(!keys.accepts_absent_fence(prepared + 1, async_floor));
        assert_eq!(
            keys.rotate(&mut next, u64::MAX, async_floor, RotationReason::Capacity)
                .unwrap(),
            None
        );
        assert!(keys.valid(next));
        assert_eq!((keys.floor_prev, keys.floor_cur, next), (100, 101, 102));
        assert!(keys.accepts_absent_fence(prepared, async_floor));
        assert!(keys.accepts_absent_fence(101, async_floor));
        assert!(!keys.accepts_absent_fence(102, async_floor));
        assert_eq!(
            keys.rotate(&mut next, u64::MAX, async_floor, RotationReason::Capacity)
                .unwrap(),
            Some(0)
        );
        assert!(keys.valid(next));
        assert_eq!((keys.floor_prev, keys.floor_cur, next), (101, 102, 103));
        assert!(!keys.accepts_absent_fence(prepared, async_floor));
        assert!(keys.accepts_absent_fence(101, async_floor));
        assert!(keys.accepts_absent_fence(102, async_floor));
        assert!(!keys.accepts_absent_fence(103, async_floor));
    }

    #[test]
    fn epoch_rotation_exhaustion_preserves_every_committed_field() {
        let native_limit = i64::MAX as u64;
        let cases = [
            (
                KeyRetention {
                    epoch: u64::MAX,
                    floor_cur: 1,
                    last_rotation: Some(RotationReason::Threshold),
                    ..KeyRetention::default()
                },
                2,
                u64::MAX,
            ),
            (
                KeyRetention {
                    epoch: 1,
                    floor_cur: u64::MAX - 1,
                    last_rotation: Some(RotationReason::Capacity),
                    ..KeyRetention::default()
                },
                u64::MAX,
                u64::MAX,
            ),
            (
                KeyRetention {
                    retired_count: 1,
                    retired_max: u64::MAX - 1,
                    ..KeyRetention::default()
                },
                u64::MAX,
                u64::MAX,
            ),
            (
                KeyRetention {
                    epoch: 1,
                    floor_cur: native_limit - 1,
                    last_rotation: Some(RotationReason::Threshold),
                    ..KeyRetention::default()
                },
                native_limit,
                native_limit,
            ),
        ];
        for (original, allocation, limit) in cases {
            assert!(original.valid(allocation));
            let mut keys = original;
            let mut next = allocation;
            assert_eq!(
                keys.rotate(&mut next, limit, 0, RotationReason::Capacity),
                Err(crate::StoreError::FencedTransitionStorageExhausted)
            );
            assert_eq!(keys, original);
            assert_eq!(next, allocation);
        }
    }
}
