//! Bounded observation vocabulary shared by local and authenticated transports.

use super::engine::InspectedItem;
use super::integrity::{ClaimHolder, ItemDisposition, ItemFailure, ItemKind};
use super::progress::{InventoryTotals, PageLimits};
use super::protocol::{ReplyBody, ScopeScanReply};
use super::{ScopeCut, ScopeScanCursor, ScopeScanError};
use crate::scope_batch::{ScopeChildKey, ScopeChildRecord, ScopeClaimKey};
use std::fmt;

/// Immutable per-view page maxima. Smaller limits never limit the total inventory.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScopeScanPageLimits(pub(crate) PageLimits);
impl ScopeScanPageLimits {
    /// Choose row and stored-payload maxima. One maximum-size legal child must
    /// fit; memory and work limits remain the SDK's fixed hard ceilings.
    pub fn new(rows: usize, payload_bytes: usize) -> Result<Self, ScopeScanError> {
        if !(1..=crate::RESTORE_SCAN_MAX_PAGE_SIZE).contains(&rows)
            || !(crate::scope_storage::MAX_SCOPE_ROW_BYTES
                ..=crate::RESTORE_SCAN_MAX_LOCAL_PAGE_PAYLOAD_BYTES)
                .contains(&payload_bytes)
        {
            return Err(ScopeScanError::InvalidPageLimits);
        }
        Ok(Self(PageLimits {
            rows,
            payload_bytes,
            ..PageLimits::default()
        }))
    }
    /// Maximum returned rows before any authenticated work-budget reduction.
    pub const fn rows(&self) -> usize {
        self.0.rows
    }
    /// Maximum stored-payload bytes in one reply, including sealed envelopes.
    pub const fn payload_bytes(&self) -> usize {
        self.0.payload_bytes
    }
}
/// Progress and completion are explicit, including an empty healthy inventory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeScanPageStatus {
    /// At least one fully inspected position advanced; a manifest may emit no items.
    Progress,
    /// No complete item fit the work budget; the next cursor has a reduced row limit.
    WorkBudgetExceeded,
    /// Both ranges finished; the bounded summary describes failures separately.
    Complete,
}

impl ScopeScanReply {
    /// Whether this reply advances, requires a bounded retry, or completes.
    pub fn status(&self) -> ScopeScanPageStatus {
        match &self.body {
            ReplyBody::Data { .. } => ScopeScanPageStatus::Progress,
            ReplyBody::WorkBudget { .. } => ScopeScanPageStatus::WorkBudgetExceeded,
            ReplyBody::Complete { .. } => ScopeScanPageStatus::Complete,
        }
    }
    /// Continue only after accepting this reply. Sending the continuation
    /// acknowledges the previous cached reply; a lost reply retries its input cursor.
    pub fn continuation(&self) -> Option<&ScopeScanCursor> {
        match &self.body {
            ReplyBody::Data { next, .. } | ReplyBody::WorkBudget { next } => Some(next),
            ReplyBody::Complete { .. } => None,
        }
    }
    /// Final item observations in this bounded reply, in child-then-claim order.
    pub fn items(&self) -> impl ExactSizeIterator<Item = ScopeScanItem<'_>> {
        let items: &[InspectedItem] = match &self.body {
            ReplyBody::Data { items, .. } => items,
            _ => &[],
        };
        items.iter().map(ScopeScanItem)
    }
    /// A fixed-size terminal summary, with a cursor for its paged failure manifest.
    pub fn summary(&self) -> Option<ScopeScanSummary<'_>> {
        match &self.body {
            ReplyBody::Complete { totals, manifest } => Some(ScopeScanSummary {
                totals: *totals,
                manifest: manifest.as_ref(),
            }),
            _ => None,
        }
    }
}

/// Borrowed fixed-size completion facts; the full failure history stays in the cut.
#[derive(Clone, Copy, Debug)]
pub struct ScopeScanSummary<'a> {
    totals: InventoryTotals,
    manifest: Option<&'a ScopeScanCursor>,
}
impl ScopeScanSummary<'_> {
    /// Number of distinct child and claim rows examined, including damaged rows.
    pub const fn examined_items(&self) -> u64 {
        self.totals.items
    }
    /// Number of examined positions with one or more final failures.
    pub const fn failed_items(&self) -> u64 {
        self.totals.failed_items
    }
    /// Total final failures, including multiple bad references on one child.
    pub const fn failures(&self) -> u64 {
        self.totals.failures
    }
    /// Kinds whose unreadable keys require callers to restrict new allocation.
    pub fn incomplete_kinds(&self) -> &'static [ItemKind] {
        if self.totals.claims_incomplete {
            &[ItemKind::Claim]
        } else {
            &[]
        }
    }
    /// Start a bounded rescan of failures from this same retained cut.
    pub const fn failure_manifest(&self) -> Option<&ScopeScanCursor> {
        self.manifest
    }
}

/// One final inventory observation. Application payload authentication and
/// application-defined references remain the caller's responsibility.
#[derive(Clone, Copy)]
pub struct ScopeScanItem<'a>(&'a InspectedItem);
impl<'a> ScopeScanItem<'a> {
    /// Stored kind whose physical position was examined.
    pub fn kind(&self) -> ItemKind {
        if self.0.position.kind == 0 {
            ItemKind::Child
        } else {
            ItemKind::Claim
        }
    }
    /// Bounded opaque position, stable for deduplication within this cut.
    pub fn position(&self) -> &[u8] {
        &self.0.position.bytes
    }
    /// Decoded child metadata and sealed value, if the row could be decoded.
    /// Restore eligibility still requires the final disposition and caller checks.
    pub const fn child(&self) -> Option<&'a ScopeChildRecord> {
        self.0.child.as_ref()
    }
    /// Decoded claim metadata, if the row could be decoded.
    pub fn claim(&self) -> Option<ScopeScanClaim<'a>> {
        self.0.claim.as_ref().map(ScopeScanClaim)
    }
    /// Final SDK verdict at this cut. It grants no permission to write or allocate.
    pub const fn disposition(&self) -> ItemDisposition {
        self.0.inspection.disposition
    }
    /// All final failures for this position, bounded by the child claim limit.
    pub fn failures(&self) -> &[ItemFailure] {
        &self.0.inspection.failures
    }
    /// An unreadable claim identity restricts new allocations of that kind.
    pub const fn inventory_incomplete(&self) -> bool {
        self.0.inspection.inventory_incomplete
    }
}
impl fmt::Debug for ScopeScanItem<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeScanItem(<redacted>)")
    }
}

/// Decoded claim revision and owner from a retained cut.
#[derive(Clone, Copy)]
pub struct ScopeScanClaim<'a>(&'a crate::scope_storage::ClaimRow);
impl ScopeScanClaim<'_> {
    /// Opaque claim identity.
    pub const fn key(&self) -> ScopeClaimKey {
        self.0.key
    }
    /// Retained claim revision, including a released row's revision.
    pub const fn revision(&self) -> u64 {
        self.0.revision
    }
    /// Decoded owner metadata. The item's final verdict decides whether it is verified.
    pub fn owner(&self) -> Option<ClaimHolder> {
        self.0.owner.map(|owner| ClaimHolder {
            child: *owner.child.as_bytes(),
            birth: owner.birth,
        })
    }
}
impl fmt::Debug for ScopeScanClaim<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeScanClaim(<redacted>)")
    }
}

/// Exact point observation requested at the same cut as inventory pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeScanLookupKey {
    /// A sealed child or retained tombstone.
    Child(ScopeChildKey),
    /// A held or retained released claim.
    Claim(ScopeClaimKey),
}

/// One same-cut final point result, including explicit absence.
pub struct ScopeScanLookup {
    pub(crate) cut: ScopeCut,
    pub(crate) item: InspectedItem,
}
impl ScopeScanLookup {
    /// Whether this observation names the exact requested kind and key,
    /// including when its body is missing or cannot be decoded.
    pub fn matches_key(&self, key: ScopeScanLookupKey) -> bool {
        let (kind, key) = match key {
            ScopeScanLookupKey::Child(key) => {
                (0, crate::scope_storage::child_key(&self.cut.namespace, key))
            }
            ScopeScanLookupKey::Claim(key) => {
                (1, crate::scope_storage::claim_key(&self.cut.namespace, key))
            }
        };
        key.is_ok_and(|key| {
            self.item.position.kind == kind
                && self.item.position.locator == super::position::LocatorKind::Canonical
                && self.item.position.bytes == key.stable_id.as_ref()
        })
    }

    /// The same immutable cut as the view's inventory pages.
    pub fn cut(&self) -> &ScopeCut {
        &self.cut
    }
    /// Final item observation. Missing and corrupt results are never retried at this cut.
    pub fn item(&self) -> ScopeScanItem<'_> {
        ScopeScanItem(&self.item)
    }
}
impl fmt::Debug for ScopeScanLookup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopeScanLookup(<redacted>)")
    }
}
