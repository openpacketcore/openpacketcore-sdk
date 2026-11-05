//! Relocate cold rows in the selected suffix after a background base build.
//! The map is issued only by exact authenticated frame rebasing. Each unit
//! visits at most 64 captured rows, including rows needing no replacement.

use super::*;
use crate::fenced_mutation_roster::RequestBindingKey;
use std::ops::Bound::{Excluded, Unbounded};

pub(super) struct ReplayStream {
    capture: capture::SnapshotCapture,
    source: Arc<VerifiedPrefix>,
    old: Arc<VerifiedPrefix>,
    cut: PrefixIdentity,
    mappings: Vec<FrameMapping>,
    table: u8,
    receipt: row_map::OwnedIter<FencedTransitionV2RequestId, SharedRow<NativeReceipt>>,
    notification: usize,
    log: Option<u64>,
    roster: imbl::hashmap::ConsumingIter<
        (RequestBindingKey, SharedRow<roster::Row>),
        imbl::shared_ptr::DefaultSharedPtr,
    >,
}

impl ReplayStream {
    pub(super) fn new(
        capture: capture::SnapshotCapture,
        source: Arc<VerifiedPrefix>,
        old: Arc<VerifiedPrefix>,
        cut: PrefixIdentity,
        mappings: Vec<FrameMapping>,
    ) -> io::Result<Self> {
        if cut.file_epoch != old.identity().file_epoch
            || cut.binding != old.identity().binding
            || cut.length > old.identity().length
            || source.identity().file_epoch != cut.file_epoch.checked_add(1).unwrap_or(0)
            || Version::capture(&capture.storage)?.context_digest()? != source.identity().frontiers
        {
            return Err(invalid("native replay relocation source differs"));
        }
        let mut end = cut.length;
        for mapping in &mappings {
            let shift = mapping.value;
            if shift.old_body < end
                || shift.length == 0
                || shift
                    .old_body
                    .checked_add(shift.length)
                    .is_none_or(|n| n > old.identity().length)
                || shift
                    .new_body
                    .checked_add(shift.length)
                    .is_none_or(|n| n > source.identity().length)
            {
                return Err(invalid("native replay relocation map invalid"));
            }
            end = shift.old_body + shift.length;
        }
        let receipt = capture.storage.business.receipts.owning_iter();
        let roster = capture.storage.business.roster.rows.clone().into_iter();
        Ok(Self {
            capture,
            source,
            old,
            cut,
            mappings,
            table: 0,
            receipt,
            notification: 0,
            log: None,
            roster,
        })
    }

    fn map(&self, old: &VerifiedPrefix, offset: u64, length: u32) -> io::Result<Option<u64>> {
        if !old.same_source(&self.old) || offset < self.cut.length {
            return Ok(None);
        }
        let index = self
            .mappings
            .partition_point(|m| m.value.old_body <= offset);
        let shift = index
            .checked_sub(1)
            .and_then(|n| self.mappings.get(n))
            .ok_or_else(|| invalid("native replay relocation range has no frame"))?
            .value;
        if offset
            .checked_add(u64::from(length))
            .is_none_or(|end| end > shift.old_body + shift.length)
        {
            return Err(invalid("native replay relocation range exceeds frame body"));
        }
        shift
            .new_body
            .checked_add(offset - shift.old_body)
            .map(Some)
            .ok_or_else(|| invalid("native replay relocation offset overflow"))
    }

    fn range(&self, range: Option<&resident::SelectedRange>) -> io::Result<Option<(u64, u32)>> {
        let Some(range) = range else { return Ok(None) };
        let (old, offset, length) = range.descriptor();
        Ok(self
            .map(old, offset, length)?
            .map(|offset| (offset, length)))
    }

    pub(super) fn next(
        &mut self,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<(Relocations, bool)> {
        let mut rows = RelocationBuilder::new(relocation::RELOCATION_STEP_ROWS)?;
        let mut visited = 0;
        while visited < relocation::RELOCATION_STEP_ROWS && self.table < 4 {
            check()?;
            match self.table {
                0 => {
                    let Some(captured) = self.receipt.next() else {
                        self.table += 1;
                        continue;
                    };
                    let id = captured.key();
                    let row = captured.value();
                    if let Some((source, range)) = row.cold_range() {
                        let length = u32::try_from(range.end() - range.offset())
                            .map_err(|_| invalid("native replay receipt length overflow"))?;
                        if let Some(offset) = self.map(&source, range.offset(), length)? {
                            rows.receipt(*id, row, offset, length)?;
                        }
                    }
                }
                1 => {
                    let Some(row) = self
                        .capture
                        .storage
                        .business
                        .notifications
                        .get(self.notification)
                    else {
                        self.table += 1;
                        continue;
                    };
                    self.notification += 1;
                    if let Some((offset, length)) = self.range(row.selected_range())? {
                        rows.notification(row, offset, length)?;
                    }
                }
                2 => {
                    let bounds = (self.log.map_or(Unbounded, Excluded), Unbounded);
                    let Some((index, row)) = self.capture.storage.log.entries.range(bounds).next()
                    else {
                        self.table += 1;
                        continue;
                    };
                    self.log = Some(*index);
                    if let Some((offset, length)) = self.range(row.selected_range())? {
                        rows.log(*index, row, offset, length)?;
                    }
                }
                3 => {
                    let Some((_binding, row)) = self.roster.next() else {
                        self.table += 1;
                        continue;
                    };
                    if let Some((offset, length)) = self.range(row.selected_range())? {
                        rows.roster(&row, offset, length)?;
                    }
                }
                _ => unreachable!(),
            }
            visited += 1;
        }
        let native = &self.capture.storage;
        let rows = rows.prepare(
            Arc::clone(&self.source),
            native.business.identity,
            native.business.applied(),
            &native.business.members,
            native.business.roster_root.clone(),
            check,
        )?;
        Ok((rows, self.table == 4))
    }
}
