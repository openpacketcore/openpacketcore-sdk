//! Ordered native metadata feeds the original durable restore-page selector.
//! The caller holds an immutable admitted business capture and install permit;
//! no SQL connection, payload scan or index rebuild occurs on this read path.

use super::*;
use crate::consensus::verified_snapshot::VerificationMemory;
use crate::restore::{
    RestoreScanPage, RestoreScanRequest, RESTORE_SCAN_MAX_EXAMINED_METADATA_BYTES,
    RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES, RESTORE_SCAN_MAX_SQLITE_VM_STEPS,
};
use crate::sqlite::ops::{RestoreScanIncarnation, RestoreScanSource};

struct Rows<'a, I> {
    state: &'a NativeState,
    keys: I,
    snapshot_time: Timestamp,
    check: &'a dyn Fn() -> io::Result<()>,
    visited: usize,
}

impl<'state, I: Iterator<Item = &'state SessionKey>> RestoreScanSource for Rows<'state, I> {
    type Row<'a>
        = &'state StoredSessionRecord
    where
        Self: 'a;

    fn next_row(&mut self) -> Result<Option<Self::Row<'_>>, StoreError> {
        loop {
            (self.check)().map_err(|error| {
                if error.kind() == io::ErrorKind::TimedOut {
                    StoreError::RestoreScanWorkBudgetExceeded
                } else {
                    unavailable()
                }
            })?;
            let Some(key) = self.keys.next() else {
                return Ok(None);
            };
            // Expired rows do not enter the original examined/excluded
            // counts. They still consume finite work and deadline checks.
            self.visited += 1;
            if self.visited > RESTORE_SCAN_MAX_SQLITE_VM_STEPS {
                return Err(StoreError::RestoreScanWorkBudgetExceeded);
            }
            let record = self
                .state
                .keys
                .get(key)
                .and_then(|state| state.record.as_ref())
                .ok_or_else(unavailable)?;
            if &record.key != key {
                return Err(unavailable());
            }
            if record
                .expires_at
                .is_none_or(|until| until > self.snapshot_time)
            {
                return Ok(Some(record));
            }
        }
    }
}

impl NativeState {
    pub(crate) fn set_local_restore_incarnation(&mut self, incarnation: RestoreScanIncarnation) {
        self.local_restore = Some(Arc::new(incarnation));
    }

    pub(crate) fn scan_restore_records(
        &self,
        request: RestoreScanRequest,
        now: Timestamp,
        check: &dyn Fn() -> io::Result<()>,
    ) -> Result<RestoreScanPage, StoreError> {
        request.validate()?;
        check().map_err(|_| unavailable())?;
        let proof = self.require_business_proof().map_err(|_| unavailable())?;
        let incarnation = self
            .snapshot_origin
            .as_ref()
            .map(|origin| origin.incarnation())
            .or(self.local_restore.as_deref())
            .ok_or_else(unavailable)?;
        // Candidates, the final page, cursor scratch and one complete record
        // validator overlap. Reserve them before cursor decoding or copies.
        let _memory = VerificationMemory::reserve(
            2 * RESTORE_SCAN_MAX_EXAMINED_METADATA_BYTES
                + 2 * RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES
                + 4 * crate::sqlite::SQLITE_CONSENSUS_MAX_VALUE_BYTES
                + 64 * 1024,
        )
        .map_err(|_| unavailable())?;
        let position = incarnation.scan_position(&request, self.frontiers.restore_revision, now)?;
        let mut rows = Rows {
            state: self,
            keys: proof.expiry.ordered_records(position.seek_key.as_ref()),
            snapshot_time: position.snapshot_time,
            check,
            visited: 0,
        };
        let mut selection = crate::sqlite::ops::select_restore_scan_candidates(
            &request,
            crate::sqlite::RestoreScanValidationProfile::Consensus,
            &mut rows,
        )?;
        drop(rows);
        let mut records = Vec::new();
        records
            .try_reserve_exact(selection.candidates.len())
            .map_err(|_| unavailable())?;
        for candidate in std::mem::take(&mut selection.candidates) {
            check().map_err(|_| unavailable())?;
            let record = self
                .keys
                .get(&candidate.key)
                .and_then(|state| state.record.as_ref())
                .ok_or_else(unavailable)?;
            crate::sqlite::validate_consensus_record(record)?;
            records.push(owned::record(record).map_err(|_| unavailable())?);
        }
        check().map_err(|_| unavailable())?;
        selection.finish(
            records,
            &request.scope,
            incarnation,
            self.frontiers.restore_revision,
            position,
        )
    }
}
