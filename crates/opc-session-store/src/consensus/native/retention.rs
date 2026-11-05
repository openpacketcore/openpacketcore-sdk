//! Committed replay floors. These are part of the application image, never
//! derived from a local reader, wall clock, checkpoint, or follower position.

use super::*;

/// Number of most recent committed notifications available for replay.
pub(crate) const NOTIFICATION_WINDOW: usize = 65_536;

/// The final dead row at physical removal. A capture's original predecessor
/// can still be live: several committed commands may retire and forget it
/// before the next cut. Preserve this bounded witness independently of those
/// exact capture endpoints.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct KeyRemoval {
    fence: u64,
    retired_epoch: u64,
}

impl KeyRemoval {
    pub(super) fn new(
        key: &SessionKey,
        row: &NativeKeyState,
        retention: Retention,
    ) -> io::Result<Self> {
        retention.validate_key_removal(key, Some(row))?;
        Ok(Self {
            fence: row.fence,
            retired_epoch: row
                .retired_epoch
                .ok_or_else(|| invalid("native key retirement witness lacks a tag"))?,
        })
    }

    pub(super) fn validate(
        self,
        before_fence: Option<u64>,
        earliest_retirement: u64,
        retention: Retention,
    ) -> io::Result<()> {
        if retention.keys.floor_prev == 0
            || self.fence >= retention.keys.floor_prev
            || before_fence.is_some_and(|fence| fence > self.fence)
            || self.retired_epoch < earliest_retirement
            || self.retired_epoch >= retention.keys.epoch.saturating_sub(1)
        {
            return Err(invalid(
                "native key retirement witness is outside its committed window",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Retention {
    pub(crate) watch_retired_through: u64,
    pub(crate) keys: crate::key_retention::KeyRetention,
}

impl Retention {
    pub(crate) fn validate(self, watch_sequence: u64, next_fence: u64) -> io::Result<()> {
        if self.watch_retired_through != watch_sequence.saturating_sub(NOTIFICATION_WINDOW as u64) {
            return Err(invalid("native notification retention frontier invalid"));
        }
        if !self.keys.valid(next_fence) {
            return Err(invalid("native key retirement frontiers invalid"));
        }
        Ok(())
    }

    pub(crate) fn transition(self, after: Self) -> io::Result<()> {
        if after.watch_retired_through < self.watch_retired_through {
            return Err(invalid("native notification retirement regressed"));
        }
        if after.keys.epoch < self.keys.epoch
            || after.keys.floor_prev < self.keys.floor_prev
            || after.keys.floor_cur < self.keys.floor_cur
            || (after.keys.epoch == self.keys.epoch
                && (after.keys.floor_prev != self.keys.floor_prev
                    || after.keys.floor_cur != self.keys.floor_cur
                    || after.keys.last_rotation != self.keys.last_rotation
                    || after.keys.retired_count < self.keys.retired_count
                    || after.keys.retired_max < self.keys.retired_max))
        {
            return Err(invalid("native key retirement frontiers regressed"));
        }
        let rotations = after.keys.epoch - self.keys.epoch;
        if rotations != 0
            && (after.keys.floor_cur - self.keys.floor_cur < rotations
                || after.keys.floor_prev < self.keys.floor_cur
                || after.keys.floor_prev - self.keys.floor_cur < rotations - 1)
        {
            return Err(invalid("native key rotation did not advance every floor"));
        }
        Ok(())
    }

    pub(crate) fn absent_fence(self, key: &SessionKey) -> u64 {
        if crate::scope_storage::is_scope_record_key(key) {
            0
        } else {
            self.keys.floor_cur
        }
    }

    pub(super) fn validate_key_removal(
        self,
        key: &SessionKey,
        before: Option<&NativeKeyState>,
    ) -> io::Result<()> {
        if crate::scope_storage::is_scope_record_key(key)
            || self.keys.floor_prev == 0
            || before.is_some_and(|row| {
                row.fence >= self.keys.floor_prev
                    || row.record.is_some()
                    || row.lease.is_some()
                    || row.reserved
                    || row
                        .retired_epoch
                        .is_none_or(|epoch| epoch >= self.keys.epoch.saturating_sub(1))
            })
        {
            return Err(invalid(
                "native key retirement lacks a higher absent-key fence",
            ));
        }
        Ok(())
    }
}

impl NativeFrontiers {
    pub(super) fn rotate_keys(
        &mut self,
        reason: crate::key_retention::RotationReason,
    ) -> Result<Option<u64>, StoreError> {
        let mut keys = self.retention.keys;
        let mut next_fence = self.next_fence;
        let through = keys.rotate(
            &mut next_fence,
            COUNTER_MAX,
            self.async_fence_floor(),
            reason,
        )?;
        self.retention.keys = keys;
        self.next_fence = next_fence;
        Ok(through)
    }

    pub(super) fn retire_notifications(&mut self) {
        self.retention.watch_retired_through = self.retention.watch_retired_through.max(
            self.watch_sequence
                .saturating_sub(NOTIFICATION_WINDOW as u64),
        );
    }

    pub(super) fn notification_position(&self, sequence: u64) -> Option<usize> {
        sequence
            .checked_sub(self.retention.watch_retired_through)
            .and_then(|distance| distance.checked_sub(1))
            .and_then(|position| usize::try_from(position).ok())
    }
}

fn key_capacity_limit() -> usize {
    #[cfg(test)]
    {
        TEST_KEY_CAPACITY_LIMIT.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        validation::MAX_ITEMS
    }
}

impl NativeDelta<'_> {
    fn resident_key_count(&self) -> io::Result<usize> {
        let removed = self
            .key_removals
            .keys()
            .filter(|key| self.base.keys.contains_key(*key))
            .count();
        let added = self
            .keys
            .keys()
            .filter(|key| !self.base.keys.contains_key(*key))
            .count();
        self.base
            .keys
            .len()
            .checked_sub(removed)
            .and_then(|count| count.checked_add(added))
            .ok_or_else(|| invalid("native key capacity accounting overflow"))
    }

    /// Reserve a journal position when internal resident capacity changes or
    /// needs a capacity decision. Rotation stays at command finalization.
    pub(super) fn requires_capacity_notification(&self, new_keys: usize) -> io::Result<bool> {
        self.resident_key_count()?
            .checked_add(new_keys)
            .map(|count| new_keys != 0 || count > key_capacity_limit())
            .ok_or_else(|| invalid("native key capacity accounting overflow"))
    }
    /// Capacity is settled once the complete command has succeeded. Retained
    /// history can require two early rotations; no intermediate reader or
    /// child operation observes those staged floors.
    pub(super) fn rotate_key_capacity(&mut self) -> io::Result<()> {
        self.rotate_key_capacity_at(key_capacity_limit())
    }

    // The production entry point always uses MAX_ITEMS. Keeping the bounded
    // policy separate lets unit tests exercise the same finalization at a
    // small resident limit without changing the committed epoch threshold.
    pub(super) fn rotate_key_capacity_at(&mut self, maximum: usize) -> io::Result<()> {
        if self.base.keys.len().saturating_add(self.keys.len()) <= maximum {
            return Ok(());
        }
        let mut count = self.resident_key_count()?;
        while count > maximum {
            if self
                .expiry
                .oldest_retired_through(self.frontiers.retention.keys.epoch)
                .is_none()
            {
                return Err(invalid("native live key capacity exhausted"));
            }
            let through = self
                .frontiers
                .rotate_keys(crate::key_retention::RotationReason::Capacity)
                .map_err(|_| invalid("native capacity rotation exhausted"))?;
            if let Some(through) = through {
                while let Some(key) = self.expiry.oldest_retired_through(through) {
                    let before = self.physical_key(&key);
                    self.frontiers
                        .retention
                        .validate_key_removal(&key, Some(&before))?;
                    self.expiry.replace(&key, Some(&before), None);
                    self.keys.remove(&key);
                    let witness = KeyRemoval::new(&key, &before, self.frontiers.retention)?;
                    self.key_removals.insert(key, witness);
                    count = count
                        .checked_sub(1)
                        .ok_or_else(|| invalid("native key capacity accounting underflow"))?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
thread_local! {
    static TEST_KEY_CAPACITY_LIMIT: std::cell::Cell<usize> = const {
        std::cell::Cell::new(validation::MAX_ITEMS)
    };
}

#[cfg(test)]
pub(super) fn with_key_capacity_limit_for_test<T>(maximum: usize, run: impl FnOnce() -> T) -> T {
    assert!(maximum > 0 && maximum <= validation::MAX_ITEMS);
    struct Reset(usize);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_KEY_CAPACITY_LIMIT.with(|limit| limit.set(self.0));
        }
    }
    let _reset = Reset(TEST_KEY_CAPACITY_LIMIT.with(|limit| limit.replace(maximum)));
    run()
}
