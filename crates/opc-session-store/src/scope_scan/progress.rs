//! Bounded page work and transactional keyset progress at an immutable cut.
//! The caller accounts a candidate and all cross-row reads through `visit`,
//! then advances only after the whole item has a final integrity verdict.

use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub(crate) struct PageLimits {
    pub(crate) rows: usize,
    pub(crate) payload_bytes: usize,
    pub(crate) retained_bytes: usize,
    pub(crate) visits: usize,
    pub(crate) metadata_bytes: usize,
}

impl Default for PageLimits {
    fn default() -> Self {
        Self {
            rows: crate::RESTORE_SCAN_DEFAULT_PAGE_SIZE,
            payload_bytes: crate::RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES,
            retained_bytes: crate::RESTORE_SCAN_MAX_PAGE_RETAINED_BYTES,
            visits: crate::RESTORE_SCAN_MAX_EXAMINED_ROWS_PER_PAGE,
            metadata_bytes: crate::RESTORE_SCAN_MAX_EXAMINED_METADATA_BYTES,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct InventoryTotals {
    pub(crate) items: u64,
    pub(crate) failed_items: u64,
    pub(crate) failures: u64,
    pub(crate) claims_incomplete: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct ItemCost {
    pub(crate) emitted: bool,
    pub(crate) payload_bytes: usize,
    pub(crate) retained_bytes: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PageUsage {
    pub(crate) returned_rows: usize,
    pub(crate) payload_bytes: usize,
    pub(crate) retained_bytes: usize,
    pub(crate) visits: usize,
    pub(crate) metadata_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PageProgressError {
    InvalidLimits,
    WorkBudget,
    PageFull,
    PositionNotAdvancing,
    InvalidItem,
    CountOverflow,
}

#[derive(Clone, Copy)]
pub(crate) enum PageEnd {
    Exhausted,
    Interrupted,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PageBoundary<P> {
    Continue {
        after: P,
        totals: InventoryTotals,
    },
    Complete {
        after: Option<P>,
        totals: InventoryTotals,
    },
    NoProgress,
}

enum Position<P> {
    Initial(Option<P>),
    Advanced(P),
}

impl<P> Position<P> {
    fn as_ref(&self) -> Option<&P> {
        match self {
            Self::Initial(after) => after.as_ref(),
            Self::Advanced(after) => Some(after),
        }
    }
    fn into_option(self) -> Option<P> {
        match self {
            Self::Initial(after) => after,
            Self::Advanced(after) => Some(after),
        }
    }
}

pub(crate) struct PageProgress<P> {
    limits: PageLimits,
    after: Position<P>,
    totals: InventoryTotals,
    usage: PageUsage,
}

impl<P: Ord> PageProgress<P> {
    pub(crate) fn new(
        limits: PageLimits,
        after: Option<P>,
        totals: InventoryTotals,
        fixed_retained_bytes: usize,
    ) -> Result<Self, PageProgressError> {
        let maximum = PageLimits::default();
        if !(1..=1024).contains(&limits.rows)
            || !(1..=maximum.payload_bytes).contains(&limits.payload_bytes)
            || !(1..=maximum.retained_bytes).contains(&limits.retained_bytes)
            || !(1..=maximum.visits).contains(&limits.visits)
            || !(1..=maximum.metadata_bytes).contains(&limits.metadata_bytes)
            || fixed_retained_bytes >= limits.retained_bytes
        {
            return Err(PageProgressError::InvalidLimits);
        }
        Ok(Self {
            limits,
            after: Position::Initial(after),
            totals,
            usage: PageUsage {
                retained_bytes: fixed_retained_bytes,
                ..PageUsage::default()
            },
        })
    }
    pub(crate) fn visit(
        &mut self,
        metadata_bytes: usize,
        elapsed: Duration,
    ) -> Result<(), PageProgressError> {
        let visits = self
            .usage
            .visits
            .checked_add(1)
            .ok_or(PageProgressError::WorkBudget)?;
        let metadata = self
            .usage
            .metadata_bytes
            .checked_add(metadata_bytes)
            .ok_or(PageProgressError::WorkBudget)?;
        if elapsed >= Duration::from_secs(1)
            || visits > self.limits.visits
            || metadata > self.limits.metadata_bytes
        {
            return Err(PageProgressError::WorkBudget);
        }
        self.usage.visits = visits;
        self.usage.metadata_bytes = metadata;
        Ok(())
    }
    pub(crate) fn can_fit(&self, cost: ItemCost) -> Result<(), PageProgressError> {
        if cost.payload_bytes > cost.retained_bytes
            || (!cost.emitted && (cost.payload_bytes != 0 || cost.retained_bytes != 0))
        {
            return Err(PageProgressError::InvalidItem);
        }
        let rows = self
            .usage
            .returned_rows
            .checked_add(usize::from(cost.emitted))
            .ok_or(PageProgressError::PageFull)?;
        let payload = self
            .usage
            .payload_bytes
            .checked_add(cost.payload_bytes)
            .ok_or(PageProgressError::PageFull)?;
        let retained = self
            .usage
            .retained_bytes
            .checked_add(cost.retained_bytes)
            .ok_or(PageProgressError::PageFull)?;
        if rows > self.limits.rows
            || payload > self.limits.payload_bytes
            || retained > self.limits.retained_bytes
        {
            return Err(PageProgressError::PageFull);
        }
        Ok(())
    }
    pub(crate) fn complete_item(
        &mut self,
        position: P,
        cost: ItemCost,
        failures: u8,
        claims_incomplete: bool,
    ) -> Result<(), PageProgressError> {
        if self.after.as_ref().is_some_and(|after| position <= *after) {
            return Err(PageProgressError::PositionNotAdvancing);
        }
        if failures > 8 || (claims_incomplete && failures == 0) {
            return Err(PageProgressError::InvalidItem);
        }
        self.can_fit(cost)?;
        let totals = InventoryTotals {
            items: self
                .totals
                .items
                .checked_add(1)
                .ok_or(PageProgressError::CountOverflow)?,
            failed_items: self
                .totals
                .failed_items
                .checked_add(u64::from(failures > 0))
                .ok_or(PageProgressError::CountOverflow)?,
            failures: self
                .totals
                .failures
                .checked_add(u64::from(failures))
                .ok_or(PageProgressError::CountOverflow)?,
            claims_incomplete: self.totals.claims_incomplete || claims_incomplete,
        };
        // All fallible checks precede the commit: a rejected or unfinished item
        // is still strictly after this page's continuation and will be retried.
        self.usage.returned_rows += usize::from(cost.emitted);
        self.usage.payload_bytes += cost.payload_bytes;
        self.usage.retained_bytes += cost.retained_bytes;
        self.totals = totals;
        self.after = Position::Advanced(position);
        Ok(())
    }
    pub(crate) fn after(&self) -> Option<&P> {
        self.after.as_ref()
    }
    pub(crate) fn usage(&self) -> PageUsage {
        self.usage
    }
    pub(crate) fn finish(self, end: PageEnd) -> PageBoundary<P> {
        if matches!(end, PageEnd::Exhausted) {
            PageBoundary::Complete {
                after: self.after.into_option(),
                totals: self.totals,
            }
        } else {
            match self.after {
                Position::Advanced(after) => PageBoundary::Continue {
                    after,
                    totals: self.totals,
                },
                Position::Initial(_) => PageBoundary::NoProgress,
            }
        }
    }
}

#[cfg(test)]
#[path = "progress_tests.rs"]
mod tests;
