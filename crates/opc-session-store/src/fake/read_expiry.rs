//! Local visibility of expiry is separate from deterministic command time.

use super::*;
use std::collections::HashSet;

#[derive(Default)]
pub(super) struct ReadExpiry {
    records: HashSet<FakeMapKey>,
    #[cfg(feature = "lab-memory")]
    pub(super) receipts: HashSet<crate::FencedTransitionRequestId>,
}

impl FakeSessionBackend {
    pub(super) fn read_expiry(&self) -> std::sync::MutexGuard<'_, ReadExpiry> {
        self.read_expiry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(super) fn record_hidden(&self, key: &FakeMapKey) -> bool {
        self.read_expiry().records.contains(key)
    }

    pub(super) fn record_expired(&self, record: &StoredSessionRecord, now: Timestamp) -> bool {
        let key = Self::map_key(&record.key);
        let mut view = self.read_expiry();
        if record.is_expired_at(now) {
            view.records.insert(key);
            true
        } else {
            view.records.contains(&key)
        }
    }

    pub(super) fn get_for_read(
        &self,
        state: &FakeBackendState,
        key: &SessionKey,
        now: Timestamp,
    ) -> Option<StoredSessionRecord> {
        state
            .records
            .get(&Self::map_key(key))
            .filter(|record| !self.record_expired(record, now))
            .cloned()
    }

    pub(super) fn publish_staged_data(
        &self,
        state: &mut FakeBackendState,
        staged: FakeBackendState,
    ) {
        // Shared persistent-map nodes are skipped. Marks remain bounded by
        // canonical records and survive unrelated lease/record commits.
        let mut view = self.read_expiry();
        for change in state.records.diff(&staged.records) {
            let key = match change {
                imbl::ordmap::DiffItem::Add(key, _) | imbl::ordmap::DiffItem::Remove(key, _) => key,
                imbl::ordmap::DiffItem::Update { old: (key, _), .. } => key,
            };
            view.records.remove(key);
        }
        #[cfg(feature = "lab-memory")]
        if staged.lab_transitions.is_empty() {
            view.receipts.clear();
        }
        drop(view);
        state.commit_staged_data(staged);
    }
}
