//! Authenticated seek cursors over one volatile lab allocation.
//!
//! `DurableOpaqueV1` is the existing cursor wire/validation profile. Reusing
//! that format supplies no persistence: both its key and incarnation disappear
//! with the process. No snapshot, key, record, or cursor is written to a file.

use std::ops::Bound::{Excluded, Unbounded};

use super::*;
use crate::restore::{
    RESTORE_SCAN_MAX_EXAMINED_METADATA_BYTES, RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE,
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
        let mut state = self.inner.lock().await;
        let now = self.clock.now_utc();
        Self::prune_state(&mut state, now);
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
                (Excluded(Self::map_key(&key)), position, time)
            }
            None => (Unbounded, 0, now),
        };
        let mut candidates = state.records.range((seek, Unbounded)).peekable();
        let mut records = Vec::with_capacity(request.limit.min(64));
        let mut payload_bytes = 0_usize;
        let mut retained_bytes = std::mem::size_of::<RestoreScanPage>();
        let mut metadata_bytes = 0_usize;
        let mut examined_count = 0_usize;
        let mut excluded_count = 0_usize;
        let mut last_key = None;
        let mut has_more = false;
        while let Some((_, record)) = candidates.next() {
            let record_bytes = restore_record_retained_bytes(record)?;
            let next_metadata = metadata_bytes
                .checked_add(record_bytes.saturating_sub(record.payload.len()))
                .ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
            let cursor_bytes =
                RestoreScanCursor::durable_retained_token_bytes_for_key(&record.key)?;
            let matches =
                !record.is_expired_at(snapshot_time) && request.scope.matches_record(record);
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
            if records.len() == request.limit
                || examined_count == RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE
            {
                has_more = candidates.peek().is_some();
                break;
            }
        }
        let next_cursor = if has_more {
            let key = last_key.ok_or(StoreError::RestoreScanWorkBudgetExceeded)?;
            let position = position
                .checked_add(examined_count as u64)
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
