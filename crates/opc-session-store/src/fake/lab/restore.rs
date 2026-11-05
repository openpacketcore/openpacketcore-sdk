//! Authenticated seek cursors over one volatile lab allocation.
//!
//! `DurableOpaqueV1` is the existing cursor wire/validation profile. Reusing
//! that format supplies no persistence: both its key and incarnation disappear
//! with the process. No snapshot, key, record, or cursor is written to a file.

use std::ops::Bound::{Excluded, Unbounded};

use super::*;
use crate::restore::{
    RESTORE_SCAN_MAX_EXAMINED_METADATA_BYTES, RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE,
    RESTORE_SCAN_MAX_SQLITE_VM_STEPS,
};

impl RestoreAuthority {
    pub(super) fn new() -> Self {
        let mut epoch: [u8; 16] = rand::random();
        epoch[0] |= 1;
        Self {
            epoch,
            key: opc_key::Zeroizing::new(rand::random()),
        }
    }
}

impl FakeSessionBackend {
    pub(in crate::fake) async fn lab_scan_restore_records(
        &self,
        request: RestoreScanRequest,
    ) -> Result<RestoreScanPage, StoreError> {
        request.validate()?;
        let authority = self
            .lab_restore_authority
            .as_ref()
            .ok_or(StoreError::RestoreScanCursorStale)?;
        let state = self.inner.lock().await;
        let now = self.clock.now_utc();
        let revision = state.lab_restore_revision;
        if revision == u64::MAX {
            return Err(StoreError::RestoreScanWorkBudgetExceeded);
        }
        let (seek, position, snapshot_time) = match request.cursor.as_ref() {
            Some(cursor) => {
                let (epoch, cursor_revision, time, key, position) =
                    cursor.authenticated_parts(&request.scope, &authority.key)?;
                if epoch != authority.epoch || cursor_revision != revision || time > now {
                    return Err(StoreError::RestoreScanCursorStale);
                }
                // Expiry invalidates the scan view without deleting canonical
                // rows that a delayed committed entry may still need.
                if state.records.values().any(|record| {
                    record
                        .expires_at
                        .is_some_and(|expires| time < expires && self.record_expired(record, now))
                }) {
                    return Err(StoreError::RestoreScanCursorStale);
                }
                (Excluded(Self::map_key(&key)), position, time)
            }
            None => (Unbounded, 0, now),
        };
        let mut candidates = state.records.range((seek, Unbounded));
        let mut records = Vec::with_capacity(request.limit.min(64));
        let mut payload_bytes = 0_usize;
        let mut retained_bytes = std::mem::size_of::<RestoreScanPage>();
        let mut metadata_bytes = 0_usize;
        let mut examined_count = 0_usize;
        let mut visited = 0_usize;
        let mut excluded_count = 0_usize;
        let mut last_key = None;
        let mut has_more = false;
        // Both selection and lookahead use the same bounded live-row source.
        let mut next_live = || -> Result<Option<&StoredSessionRecord>, StoreError> {
            for (_, record) in candidates.by_ref() {
                visited += 1;
                if visited > RESTORE_SCAN_MAX_SQLITE_VM_STEPS {
                    return Err(StoreError::RestoreScanWorkBudgetExceeded);
                }
                if !self.record_expired(record, snapshot_time) {
                    return Ok(Some(record));
                }
            }
            Ok(None)
        };
        while let Some(record) = next_live()? {
            let record_bytes = restore_record_retained_bytes(record)?;
            let next_metadata = metadata_bytes
                .checked_add(record_bytes.saturating_sub(record.payload.len()))
                .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
            let cursor_bytes =
                RestoreScanCursor::durable_retained_token_bytes_for_key(&record.key)?;
            let matches = request.scope.matches_record(record);
            // Continue through a bounded expired tail even after filling the
            // page. A following matching live row belongs to the next page.
            if matches && records.len() == request.limit {
                has_more = true;
                break;
            }
            let next_payload = payload_bytes
                .checked_add(if matches { record.payload.len() } else { 0 })
                .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
            let next_retained = retained_bytes
                .checked_add(if matches { record_bytes } else { 0 })
                .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
            if next_metadata > RESTORE_SCAN_MAX_EXAMINED_METADATA_BYTES
                || next_payload > RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES
                || next_retained
                    .checked_add(cursor_bytes)
                    .is_none_or(|bytes| bytes > RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES)
            {
                if examined_count == 0 {
                    return Err(StoreError::RestoreScanWorkBudgetExceeded);
                }
                has_more = true;
                break;
            }
            metadata_bytes = next_metadata;
            payload_bytes = next_payload;
            retained_bytes = next_retained;
            examined_count += 1;
            last_key = Some(&record.key);
            if matches {
                records.push(record.clone());
            } else {
                excluded_count += 1;
            }
            if examined_count == RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE {
                has_more = next_live()?.is_some();
                break;
            }
        }
        let next_cursor = if has_more {
            let live_examined = records.len() + excluded_count;
            if live_examined == 0 {
                // An incomplete page still requires live progress. Expired
                // rows were skipped by the separately bounded row source.
                return Err(StoreError::RestoreScanWorkBudgetExceeded);
            }
            let key = last_key.ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
            let position = position
                .checked_add(live_examined as u64)
                .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
            Some(RestoreScanCursor::durable(
                &authority.key,
                authority.epoch,
                revision,
                snapshot_time,
                &request.scope,
                key,
                position,
            )?)
        } else {
            None
        };
        records.sort_by(compare_restore_records);
        Ok(RestoreScanPage::new_durable(
            records,
            excluded_count,
            next_cursor,
        ))
    }
}
