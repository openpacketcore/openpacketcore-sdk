//! Bounded child-then-claim inventory at one retained cut.

use super::headers::RawScopeRecord;
use super::integrity::{
    self, ChildFacts, ClaimFacts, ClaimHolder, FinalItemInspection, IntegrityFault,
    InventoryFloors, InventoryLookup, ItemKind, ItemRead,
};
pub(crate) use super::position::InventoryPosition;
use super::position::LocatorKind;
use super::progress::{
    InventoryTotals, ItemCost, PageBoundary, PageEnd, PageLimits, PageProgress, PageProgressError,
};
use crate::scope_authority::ScopeNamespace;
use crate::scope_batch::ScopeChildRecord;
use crate::scope_storage::{self, ClaimRow, ScopeRow};
use crate::SessionKey;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InventoryError {
    Interrupted,
    WorkBudget,
    InvalidPosition,
    InvalidLimits,
    CountOverflow,
}

/// A final physical failure has an exact bounded locator and no readable key.
pub(crate) struct InventoryCandidate {
    pub(crate) position: InventoryPosition,
    pub(crate) key: Option<SessionKey>,
}

pub(crate) fn native_candidate(
    namespace: &ScopeNamespace,
    key: SessionKey,
) -> Result<InventoryCandidate, InventoryError> {
    let position = position(namespace, &key)?;
    let key = (position.locator == LocatorKind::Canonical).then_some(key);
    Ok(InventoryCandidate { position, key })
}

pub(crate) struct InspectedItem {
    pub(crate) position: InventoryPosition,
    pub(crate) child: Option<ScopeChildRecord>,
    pub(crate) claim: Option<ClaimRow>,
    pub(crate) inspection: FinalItemInspection,
    pub(crate) stored_bytes: usize,
}

pub(crate) struct InventoryPage {
    pub(crate) items: Vec<InspectedItem>,
    pub(crate) boundary: PageBoundary<InventoryPosition>,
}

/// Sources perform a namespace-bounded keyset step and bounded raw point read.
/// A source charges visits and metadata before allocating any owned row body.
/// Operational interruption is never converted into a corrupt or missing row.
pub(crate) trait InventorySource {
    fn next_candidate(
        &mut self,
        namespace: &ScopeNamespace,
        kind: ItemKind,
        after: Option<&InventoryPosition>,
        budget: &mut InventoryBudget,
    ) -> Result<Option<InventoryCandidate>, InventoryError>;
    fn read(
        &mut self,
        key: &SessionKey,
        budget: &mut InventoryBudget,
    ) -> Result<RawScopeRecord, InventoryError>;
}

pub(crate) struct InventoryBudget {
    pub(crate) progress: PageProgress<InventoryPosition>,
    started: Instant,
}
impl InventoryBudget {
    pub(crate) fn charge(&mut self, metadata: usize) -> Result<(), InventoryError> {
        self.progress
            .visit(metadata, self.started.elapsed())
            .map_err(progress_error)
    }
}

fn progress_error(error: PageProgressError) -> InventoryError {
    match error {
        PageProgressError::WorkBudget | PageProgressError::PageFull => InventoryError::WorkBudget,
        PageProgressError::PositionNotAdvancing => InventoryError::InvalidPosition,
        PageProgressError::CountOverflow => InventoryError::CountOverflow,
        PageProgressError::InvalidLimits | PageProgressError::InvalidItem => {
            InventoryError::InvalidLimits
        }
    }
}

pub(crate) fn page<S: InventorySource>(
    source: &mut S,
    namespace: &ScopeNamespace,
    floors: InventoryFloors,
    limits: PageLimits,
    after: Option<InventoryPosition>,
    totals: InventoryTotals,
    failures_only: bool,
) -> Result<InventoryPage, InventoryError> {
    if let Some(after) = &after {
        validate_position(namespace, after)?;
    }
    let mut kind = after.as_ref().map_or(0, |position| position.kind);
    let mut budget = InventoryBudget {
        progress: PageProgress::new(limits, after, totals, 4096).map_err(progress_error)?,
        started: Instant::now(),
    };
    let mut items = Vec::new();
    let end = loop {
        if budget.progress.usage().returned_rows >= limits.rows {
            break PageEnd::Interrupted;
        }
        let after = budget
            .progress
            .after()
            .filter(|position| position.kind == kind)
            .cloned();
        let next = source.next_candidate(namespace, item_kind(kind)?, after.as_ref(), &mut budget);
        let candidate = match next {
            Ok(Some(candidate)) => candidate,
            Ok(None) if kind == 0 => {
                kind = 1;
                continue;
            }
            Ok(None) => break PageEnd::Exhausted,
            Err(InventoryError::WorkBudget) => break PageEnd::Interrupted,
            Err(error) => return Err(error),
        };
        let position = candidate.position;
        validate_position(namespace, &position)?;
        if position.kind != kind
            || budget
                .progress
                .after()
                .is_some_and(|after| position <= *after)
        {
            return Err(InventoryError::InvalidPosition);
        }
        let mut item = if let Some(key) = candidate.key {
            match inspect(source, namespace, floors, &key, &mut budget) {
                Ok(item) if item.position == position => item,
                Ok(_) => return Err(InventoryError::InvalidPosition),
                Err(InventoryError::WorkBudget) => break PageEnd::Interrupted,
                Err(error) => return Err(error),
            }
        } else {
            if position.locator == LocatorKind::Canonical {
                return Err(InventoryError::InvalidPosition);
            }
            InspectedItem {
                position: position.clone(),
                child: None,
                claim: None,
                stored_bytes: 0,
                inspection: integrity::unreadable_key(item_kind(position.kind)?),
            }
        };
        let emitted = !failures_only || !item.inspection.failures.is_empty();
        if failures_only {
            // The terminal failure manifest re-examines this same retained cut.
            // It retains only failures, never sealed values or a whole history.
            item.child = None;
            item.claim = None;
            item.stored_bytes = 0;
        }
        let cost = if emitted {
            ItemCost {
                emitted: true,
                payload_bytes: item.stored_bytes,
                // Covers value ownership, encoding headroom, bounded claims,
                // failures, Vec capacities and per-item envelope bookkeeping.
                retained_bytes: item.stored_bytes.saturating_mul(2).saturating_add(4096),
            }
        } else {
            ItemCost {
                emitted: false,
                payload_bytes: 0,
                retained_bytes: 0,
            }
        };
        let failures = u8::try_from(item.inspection.failures.len())
            .map_err(|_| InventoryError::InvalidLimits)?;
        match budget.progress.complete_item(
            position,
            cost,
            failures,
            item.inspection.inventory_incomplete,
        ) {
            Ok(()) => {}
            Err(PageProgressError::PageFull) => break PageEnd::Interrupted,
            Err(error) => return Err(progress_error(error)),
        }
        if emitted {
            items.push(item);
        }
    };
    Ok(InventoryPage {
        items,
        boundary: budget.progress.finish(end),
    })
}

pub(crate) fn lookup<S: InventorySource>(
    source: &mut S,
    namespace: &ScopeNamespace,
    floors: InventoryFloors,
    key: &SessionKey,
) -> Result<InspectedItem, InventoryError> {
    position(namespace, key)?;
    let mut budget = InventoryBudget {
        progress: PageProgress::new(
            PageLimits::default(),
            None,
            InventoryTotals::default(),
            4096,
        )
        .map_err(progress_error)?,
        started: Instant::now(),
    };
    inspect(source, namespace, floors, key, &mut budget)
}

fn item_kind(kind: u8) -> Result<ItemKind, InventoryError> {
    match kind {
        0 => Ok(ItemKind::Child),
        1 => Ok(ItemKind::Claim),
        _ => Err(InventoryError::InvalidPosition),
    }
}

pub(crate) fn kind_name(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Child => "opc-scope-child",
        ItemKind::Claim => "opc-scope-claim",
    }
}

fn validate_position(
    namespace: &ScopeNamespace,
    position: &InventoryPosition,
) -> Result<(), InventoryError> {
    if !position.valid_namespace(namespace) {
        return Err(InventoryError::InvalidPosition);
    }
    Ok(())
}

fn position(
    namespace: &ScopeNamespace,
    key: &SessionKey,
) -> Result<InventoryPosition, InventoryError> {
    let kind = match key.key_type.as_str() {
        "opc-scope-child" => 0,
        "opc-scope-claim" => 1,
        _ => return Err(InventoryError::InvalidPosition),
    };
    if &key.tenant != namespace.scope().tenant() || &key.nf_kind != namespace.scope().nf_kind() {
        return Err(InventoryError::InvalidPosition);
    }
    let bytes = key.stable_id.as_ref();
    let locator = match bytes.len() {
        64 => LocatorKind::Canonical,
        32..64 => LocatorKind::NativeKnown,
        1..32 => LocatorKind::NativeUnknown,
        _ => return Err(InventoryError::InvalidPosition),
    };
    let position = InventoryPosition {
        kind,
        locator,
        bytes: bytes.to_vec(),
    };
    validate_position(namespace, &position)?;
    Ok(position)
}

enum Decoded {
    Child(ScopeChildRecord, usize),
    Claim(ClaimRow, usize),
    Missing,
    Corrupt(IntegrityFault),
}

fn decode<S: InventorySource>(
    source: &mut S,
    namespace: &ScopeNamespace,
    key: &SessionKey,
    budget: &mut InventoryBudget,
) -> Result<Decoded, InventoryError> {
    let raw = match source.read(key, budget)? {
        RawScopeRecord::Missing => return Ok(Decoded::Missing),
        RawScopeRecord::Corrupt => return Ok(Decoded::Corrupt(IntegrityFault::Encoding)),
        RawScopeRecord::Present(raw) => raw,
    };
    if raw.key != *key {
        return Ok(Decoded::Corrupt(IntegrityFault::Key));
    }
    if scope_storage::require_current_record_format(&raw).is_err() {
        return Ok(Decoded::Corrupt(IntegrityFault::Encoding));
    }
    let stored_bytes = raw.payload.len();
    if stored_bytes > maximum_record_bytes(key) {
        return Ok(Decoded::Corrupt(IntegrityFault::Encoding));
    }
    match ScopeRow::from_record(&raw) {
        Ok(ScopeRow::Child(child)) if child.namespace() == namespace => {
            Ok(Decoded::Child(child, stored_bytes))
        }
        Ok(ScopeRow::Claim(claim)) if &claim.namespace == namespace => {
            Ok(Decoded::Claim(claim, stored_bytes))
        }
        Ok(_) => Ok(Decoded::Corrupt(IntegrityFault::Key)),
        Err(_) => Ok(Decoded::Corrupt(IntegrityFault::Encoding)),
    }
}

pub(crate) fn maximum_record_bytes(key: &SessionKey) -> usize {
    if key.key_type.as_str() == kind_name(ItemKind::Child) {
        scope_storage::MAX_SCOPE_ROW_BYTES
    } else {
        scope_storage::MAX_METADATA_BYTES
    }
}

fn child_facts(child: &ScopeChildRecord) -> ChildFacts {
    ChildFacts {
        key: *child.key().as_bytes(),
        birth: child.revision().birth(),
        generation: child.revision().generation(),
        batch_revision: child.batch_revision,
        live: child.value().is_some(),
        claims: child
            .claims()
            .iter()
            .map(|claim| *claim.as_bytes())
            .collect(),
    }
}

fn claim_facts(claim: &ClaimRow) -> ClaimFacts {
    ClaimFacts {
        key: *claim.key.as_bytes(),
        revision: claim.revision,
        owner: claim.owner.map(|owner| ClaimHolder {
            child: *owner.child.as_bytes(),
            birth: owner.birth,
        }),
    }
}

struct Lookup<'a, S> {
    source: &'a mut S,
    namespace: &'a ScopeNamespace,
    budget: &'a mut InventoryBudget,
}
impl<S: InventorySource> InventoryLookup for Lookup<'_, S> {
    type Interrupted = InventoryError;
    fn child(&mut self, key: [u8; 32]) -> Result<ItemRead<ChildFacts>, InventoryError> {
        let key = scope_storage::namespace_key(self.namespace, kind_name(ItemKind::Child), &key)
            .map_err(|_| InventoryError::InvalidPosition)?;
        Ok(
            match decode(self.source, self.namespace, &key, self.budget)? {
                Decoded::Child(child, _) => ItemRead::Present(child_facts(&child)),
                Decoded::Missing => ItemRead::Missing,
                Decoded::Corrupt(reason) => ItemRead::Corrupt(reason),
                Decoded::Claim(_, _) => ItemRead::Corrupt(IntegrityFault::Key),
            },
        )
    }
    fn claim(&mut self, key: [u8; 32]) -> Result<ItemRead<ClaimFacts>, InventoryError> {
        let key = scope_storage::namespace_key(self.namespace, kind_name(ItemKind::Claim), &key)
            .map_err(|_| InventoryError::InvalidPosition)?;
        Ok(
            match decode(self.source, self.namespace, &key, self.budget)? {
                Decoded::Claim(claim, _) => ItemRead::Present(claim_facts(&claim)),
                Decoded::Missing => ItemRead::Missing,
                Decoded::Corrupt(reason) => ItemRead::Corrupt(reason),
                Decoded::Child(_, _) => ItemRead::Corrupt(IntegrityFault::Key),
            },
        )
    }
}

fn inspect<S: InventorySource>(
    source: &mut S,
    namespace: &ScopeNamespace,
    floors: InventoryFloors,
    key: &SessionKey,
    budget: &mut InventoryBudget,
) -> Result<InspectedItem, InventoryError> {
    let position = position(namespace, key)?;
    let logical: Option<[u8; 32]> = position.logical_key().and_then(|key| key.try_into().ok());
    let row = decode(source, namespace, key, budget)?;
    let mut lookup = Lookup {
        source,
        namespace,
        budget,
    };
    let mut child = None;
    let mut claim = None;
    let mut stored_bytes = 0;
    let inspection = match item_kind(position.kind)? {
        ItemKind::Child => {
            let facts = match row {
                Decoded::Child(row, bytes) => {
                    let facts = child_facts(&row);
                    stored_bytes = bytes;
                    child = Some(row);
                    ItemRead::Present(facts)
                }
                Decoded::Missing => ItemRead::Missing,
                Decoded::Corrupt(reason) => ItemRead::Corrupt(reason),
                Decoded::Claim(_, _) => ItemRead::Corrupt(IntegrityFault::Key),
            };
            integrity::inspect_child(logical, facts, floors, &mut lookup)?
        }
        ItemKind::Claim => {
            let facts = match row {
                Decoded::Claim(row, bytes) => {
                    let facts = claim_facts(&row);
                    stored_bytes = bytes;
                    claim = Some(row);
                    ItemRead::Present(facts)
                }
                Decoded::Missing => ItemRead::Missing,
                Decoded::Corrupt(reason) => ItemRead::Corrupt(reason),
                Decoded::Child(_, _) => ItemRead::Corrupt(IntegrityFault::Key),
            };
            integrity::inspect_claim(logical, facts, floors, &mut lookup)?
        }
    };
    Ok(InspectedItem {
        position,
        child,
        claim,
        inspection,
        stored_bytes,
    })
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
