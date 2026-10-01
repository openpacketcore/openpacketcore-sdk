//! Validation-local indexes over borrowed, not yet trusted operation handles.
//! Legacy Intent, TargetIntent and EmptyCommit entries share one ordinal space.
//!
//! Sorting does not authenticate an entry. The caller still authenticates the
//! original chain in order, derives every operation, and compares the complete
//! result with the retained operations. An ordinal can resolve an outcome only
//! after its Intent has joined that authenticated prefix.

use std::cmp::Ordering;
use std::mem::size_of;

use super::MAX_LEDGER_EVENTS;
use super::{AuditAuthorityError, AuditOperationHandle, AuditToken, EntryPayload, LedgerEntry};

const WORD_BITS: usize = u64::BITS as usize;
const BITMAP_WORDS: usize = MAX_LEDGER_EVENTS.div_ceil(WORD_BITS);

struct IndexedIntent<'a> {
    handle: &'a AuditOperationHandle,
    ordinal: usize,
}

pub(super) struct ValidationIndex<'a> {
    by_mac: Vec<IndexedIntent<'a>>,
    duplicate_requests: [u64; BITMAP_WORDS],
    #[cfg(test)]
    _observed: super::validation_probe::IndexOwner,
}

impl<'a> ValidationIndex<'a> {
    pub(super) fn new(entries: &'a [LedgerEntry]) -> Result<Self, AuditAuthorityError> {
        // LedgerState checks the admitted bound first. Keep the helper's own
        // fixed bitmap safe even if another caller is added later.
        if entries.len() > MAX_LEDGER_EVENTS {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let count = entries.iter().filter_map(operation_handle).count();
        let mut by_mac = Self::reserve(count)?;
        for handle in entries.iter().filter_map(operation_handle) {
            let ordinal = by_mac.len();
            by_mac.push(IndexedIntent { handle, ordinal });
        }
        // Both sorts are in place and allocate no auxiliary vector. The
        // ordinal tie break retains the first chronological occurrence even
        // when untrusted handles have identical complete request/MAC values.
        by_mac.sort_unstable_by(|left, right| {
            compare_request(
                &left.handle.body.binding.request,
                &right.handle.body.binding.request,
            )
            .then_with(|| left.ordinal.cmp(&right.ordinal))
        });
        let mut duplicate_requests = [0; BITMAP_WORDS];
        for pair in by_mac.windows(2) {
            if compare_request(
                &pair[0].handle.body.binding.request,
                &pair[1].handle.body.binding.request,
            ) == Ordering::Equal
            {
                let ordinal = pair[1].ordinal;
                let word = duplicate_requests
                    .get_mut(ordinal / WORD_BITS)
                    .ok_or(AuditAuthorityError::BindingMismatch)?;
                *word |= 1_u64 << (ordinal % WORD_BITS);
            }
        }
        by_mac.sort_unstable_by(|left, right| {
            compare_mac(&left.handle.mac, &right.handle.mac)
                .then_with(|| left.ordinal.cmp(&right.ordinal))
        });
        #[cfg(test)]
        let observed = super::validation_probe::IndexOwner::new(
            count,
            by_mac.capacity(),
            size_of::<IndexedIntent<'_>>(),
            size_of::<[u64; BITMAP_WORDS]>(),
        );
        Ok(Self {
            by_mac,
            duplicate_requests,
            #[cfg(test)]
            _observed: observed,
        })
    }

    fn reserve(count: usize) -> Result<Vec<IndexedIntent<'a>>, AuditAuthorityError> {
        count
            .checked_mul(size_of::<IndexedIntent<'_>>())
            .ok_or(AuditAuthorityError::Unavailable)?;
        let mut values = Vec::new();
        if count != 0 {
            #[cfg(test)]
            let count = super::validation_probe::requested(count);
            // One exact fallible allocation; pushes never grow this vector.
            values
                .try_reserve_exact(count)
                .map_err(|_| AuditAuthorityError::Unavailable)?;
        }
        Ok(values)
    }

    pub(super) fn duplicate_request(&self, ordinal: usize) -> Result<bool, AuditAuthorityError> {
        if ordinal >= self.by_mac.len() {
            return Err(AuditAuthorityError::BindingMismatch);
        }
        let word = self
            .duplicate_requests
            .get(ordinal / WORD_BITS)
            .ok_or(AuditAuthorityError::BindingMismatch)?;
        Ok(word & (1_u64 << (ordinal % WORD_BITS)) != 0)
    }

    pub(super) fn prior_operation(&self, mac: &[u8; 32], derived_len: usize) -> Option<usize> {
        let first = self
            .by_mac
            .partition_point(|entry| compare_mac(&entry.handle.mac, mac) == Ordering::Less);
        let entry = self.by_mac.get(first)?;
        (compare_mac(&entry.handle.mac, mac) == Ordering::Equal && entry.ordinal < derived_len)
            .then_some(entry.ordinal)
    }

    #[cfg(feature = "dangerous-test-hooks")]
    pub(super) fn allocation(&self) -> (usize, usize) {
        (
            self.by_mac.as_ptr() as usize,
            self.by_mac.capacity() * size_of::<IndexedIntent<'_>>(),
        )
    }

    #[cfg(test)]
    pub(super) fn observe_allocation(
        &self,
    ) -> crate::consensus::config_capacity_simultaneous_working_tests::ledger::OwnerGuard<'_> {
        crate::consensus::config_capacity_simultaneous_working_tests::ledger::validation_index(
            &self.by_mac,
        )
    }

    #[cfg(test)]
    pub(super) fn overflowing_reservation() -> Result<(), AuditAuthorityError> {
        Self::reserve(usize::MAX).map(|_| ())
    }
}

// Borrow only. Validation still authenticates each payload before deriving its
// operation; the index cannot grant authority to a retained recovery command.
fn operation_handle(entry: &LedgerEntry) -> Option<&AuditOperationHandle> {
    match &entry.payload {
        EntryPayload::Intent(handle) => Some(handle),
        EntryPayload::TargetIntent(retained) => Some(&retained.handle),
        EntryPayload::EmptyCommit(prepared) => Some(prepared.handle()),
        _ => None,
    }
}

fn compare_request(left: &AuditToken, right: &AuditToken) -> Ordering {
    #[cfg(test)]
    super::validation_probe::comparison();
    left.cmp(right)
}

fn compare_mac(left: &[u8; 32], right: &[u8; 32]) -> Ordering {
    #[cfg(test)]
    super::validation_probe::comparison();
    left.cmp(right)
}
