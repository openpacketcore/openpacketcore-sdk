//! Final item inspection at a retained cut. Decoders validate canonical rows
//! and namespace membership before providing these bounded, non-secret facts.
//! Operational interruption never becomes durable corruption or a final item.

use std::fmt;

pub(crate) type Key = [u8; 32];

/// Kind of one inventory item or referenced row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemKind {
    /// A sealed child, including an application-defined index or tombstone.
    Child,
    /// A unique claim, including a retained released row.
    Claim,
}

/// Final SDK integrity failure, distinct from application payload validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrityFault {
    /// The row cannot be canonically decoded within the stored profile.
    Encoding,
    /// The physical and logical identity or namespace is inconsistent.
    Key,
    /// A retained revision or birth is inconsistent with the captured floors.
    Header,
    /// The same-cut child and claim ownership facts disagree.
    Ownership,
}

#[derive(Clone, Copy)]
pub(crate) struct InventoryFloors {
    pub(crate) batch_revision: u64,
    pub(crate) birth: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ChildFacts {
    pub(crate) key: Key,
    pub(crate) birth: u64,
    pub(crate) generation: u64,
    pub(crate) batch_revision: u64,
    pub(crate) live: bool,
    pub(crate) claims: Vec<Key>,
}

/// Exact child birth observed as a claim holder at one retained cut.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ClaimHolder {
    pub(crate) child: Key,
    pub(crate) birth: u64,
}

impl ClaimHolder {
    /// Opaque child identity observed in the claim.
    pub const fn child(&self) -> &[u8; 32] {
        &self.child
    }
    /// Exact non-recycled birth observed in the claim.
    pub const fn birth(&self) -> u64 {
        self.birth
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ClaimFacts {
    pub(crate) key: Key,
    pub(crate) revision: u64,
    pub(crate) owner: Option<ClaimHolder>,
}

#[derive(Clone)]
pub(crate) enum ItemRead<T> {
    Present(T),
    Missing,
    Corrupt(IntegrityFault),
}

pub(crate) trait InventoryLookup {
    type Interrupted;
    fn child(&mut self, key: Key) -> Result<ItemRead<ChildFacts>, Self::Interrupted>;
    fn claim(&mut self, key: Key) -> Result<ItemRead<ClaimFacts>, Self::Interrupted>;
}

/// A final, bounded failure associated with an examined inventory position.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ItemFailure {
    /// A referenced row is absent at this cut.
    Missing {
        /// Kind of the absent reference.
        kind: ItemKind,
        /// Opaque identity of the absent reference.
        key: Key,
    },
    /// One row cannot supply trustworthy inventory evidence.
    Corrupt {
        /// Kind of the damaged row or reference.
        kind: ItemKind,
        /// Opaque identity, absent if the logical key is unreadable.
        key: Option<Key>,
        /// SDK integrity check which failed.
        reason: IntegrityFault,
    },
}

/// Final SDK inventory verdict at one cut, never mutation or effect authority.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ItemDisposition {
    /// A live child whose SDK metadata and claim references agree.
    LiveChild,
    /// A retained child deletion with its birth and generation.
    ChildTombstone,
    /// A child with a final integrity fault; its claims remain restricted.
    UnrestorableChild,
    /// The claim agrees with this exact live child birth.
    ClaimHeld(ClaimHolder),
    /// The claim remains held because its body or owner is unverifiable.
    ClaimHeldUnknown,
    /// A retained released claim; this observation alone cannot authorize reuse.
    ClaimReleased,
    /// The requested child or claim is absent at this cut.
    MissingAtCut,
}

/// Every verdict is final at this cut, including missing and corrupt items.
/// A claim disposition is evidence only, never permission to allocate it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FinalItemInspection {
    pub(crate) disposition: ItemDisposition,
    pub(crate) failures: Vec<ItemFailure>,
    pub(crate) inventory_incomplete: bool,
}

macro_rules! redacted_debug {
    ($($ty:ty),+ $(,)?) => { $(impl fmt::Debug for $ty {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(concat!(stringify!($ty), "(<redacted>)"))
        }
    })+ };
}
redacted_debug!(
    ChildFacts,
    ClaimFacts,
    ClaimHolder,
    ItemFailure,
    ItemDisposition,
    FinalItemInspection
);

pub(crate) fn inspect_child<L: InventoryLookup>(
    key: Option<Key>,
    row: ItemRead<ChildFacts>,
    cut: InventoryFloors,
    lookup: &mut L,
) -> Result<FinalItemInspection, L::Interrupted> {
    let kind = ItemKind::Child;
    let Some(key) = key.filter(|key| *key != [0; 32]) else {
        return Ok(corrupt(kind, None, IntegrityFault::Key));
    };
    let row = match row {
        ItemRead::Present(row) => row,
        ItemRead::Missing => return Ok(missing(kind, key)),
        ItemRead::Corrupt(reason) => return Ok(corrupt(kind, Some(key), reason)),
    };
    if let Err(reason) = child_header(&row, key, cut) {
        return Ok(corrupt(kind, Some(key), reason));
    }
    let mut failures = Vec::new();
    for claim in &row.claims {
        let fault = match lookup.claim(*claim)? {
            ItemRead::Missing => Some(ItemFailure::Missing {
                kind: ItemKind::Claim,
                key: *claim,
            }),
            ItemRead::Corrupt(reason) => Some(ItemFailure::Corrupt {
                kind: ItemKind::Claim,
                key: Some(*claim),
                reason,
            }),
            ItemRead::Present(found) => {
                let reason = claim_header(&found, *claim, cut).err().or_else(|| {
                    (found.owner
                        != Some(ClaimHolder {
                            child: key,
                            birth: row.birth,
                        }))
                    .then_some(IntegrityFault::Ownership)
                });
                reason.map(|reason| ItemFailure::Corrupt {
                    kind: ItemKind::Claim,
                    key: Some(*claim),
                    reason,
                })
            }
        };
        if let Some(fault) = fault {
            failures.push(fault);
        }
    }
    let disposition = if !failures.is_empty() {
        ItemDisposition::UnrestorableChild
    } else if row.live {
        ItemDisposition::LiveChild
    } else {
        ItemDisposition::ChildTombstone
    };
    Ok(FinalItemInspection {
        disposition,
        failures,
        inventory_incomplete: false,
    })
}

pub(crate) fn inspect_claim<L: InventoryLookup>(
    key: Option<Key>,
    row: ItemRead<ClaimFacts>,
    cut: InventoryFloors,
    lookup: &mut L,
) -> Result<FinalItemInspection, L::Interrupted> {
    let kind = ItemKind::Claim;
    let Some(key) = key.filter(|key| *key != [0; 32]) else {
        return Ok(corrupt(kind, None, IntegrityFault::Key));
    };
    let row = match row {
        ItemRead::Present(row) => row,
        ItemRead::Missing => return Ok(missing(kind, key)),
        ItemRead::Corrupt(reason) => return Ok(corrupt(kind, Some(key), reason)),
    };
    if let Err(reason) = claim_header(&row, key, cut) {
        return Ok(corrupt(kind, Some(key), reason));
    }
    let Some(owner) = row.owner else {
        return Ok(FinalItemInspection {
            disposition: ItemDisposition::ClaimReleased,
            failures: Vec::new(),
            inventory_incomplete: false,
        });
    };
    let fault = match lookup.child(owner.child)? {
        ItemRead::Missing => Some(ItemFailure::Missing {
            kind: ItemKind::Child,
            key: owner.child,
        }),
        ItemRead::Corrupt(reason) => Some(ItemFailure::Corrupt {
            kind: ItemKind::Child,
            key: Some(owner.child),
            reason,
        }),
        ItemRead::Present(found) => {
            let reason = child_header(&found, owner.child, cut).err().or_else(|| {
                (!found.live || found.birth != owner.birth || !found.claims.contains(&key))
                    .then_some(IntegrityFault::Ownership)
            });
            reason.map(|reason| ItemFailure::Corrupt {
                kind: ItemKind::Child,
                key: Some(owner.child),
                reason,
            })
        }
    };
    Ok(FinalItemInspection {
        disposition: if fault.is_some() {
            ItemDisposition::ClaimHeldUnknown
        } else {
            ItemDisposition::ClaimHeld(owner)
        },
        failures: fault.into_iter().collect(),
        inventory_incomplete: false,
    })
}

fn child_header(row: &ChildFacts, key: Key, cut: InventoryFloors) -> Result<(), IntegrityFault> {
    if row.key != key {
        return Err(IntegrityFault::Key);
    }
    if !positive(row.birth)
        || row.birth > cut.birth
        || !positive(row.generation)
        || !positive(row.batch_revision)
        || row.batch_revision > cut.batch_revision
        || row.claims.len() > 8
        || (!row.live && !row.claims.is_empty())
        || row
            .claims
            .iter()
            .enumerate()
            .any(|(index, key)| *key == [0; 32] || row.claims[..index].contains(key))
    {
        return Err(IntegrityFault::Header);
    }
    Ok(())
}

fn claim_header(row: &ClaimFacts, key: Key, cut: InventoryFloors) -> Result<(), IntegrityFault> {
    if row.key != key {
        return Err(IntegrityFault::Key);
    }
    if !positive(row.revision)
        || row.revision > cut.batch_revision
        || row.owner.is_some_and(|owner| {
            owner.child == [0; 32] || !positive(owner.birth) || owner.birth > cut.birth
        })
    {
        return Err(IntegrityFault::Header);
    }
    Ok(())
}

fn positive(value: u64) -> bool {
    (1..=i64::MAX as u64).contains(&value)
}

fn missing(kind: ItemKind, key: Key) -> FinalItemInspection {
    FinalItemInspection {
        disposition: ItemDisposition::MissingAtCut,
        failures: vec![ItemFailure::Missing { kind, key }],
        inventory_incomplete: false,
    }
}

pub(crate) fn unreadable_key(kind: ItemKind) -> FinalItemInspection {
    corrupt(kind, None, IntegrityFault::Key)
}

fn corrupt(kind: ItemKind, key: Option<Key>, reason: IntegrityFault) -> FinalItemInspection {
    FinalItemInspection {
        disposition: match kind {
            ItemKind::Child => ItemDisposition::UnrestorableChild,
            ItemKind::Claim => ItemDisposition::ClaimHeldUnknown,
        },
        failures: vec![ItemFailure::Corrupt { kind, key, reason }],
        inventory_incomplete: kind == ItemKind::Claim && key.is_none(),
    }
}

#[cfg(test)]
#[path = "integrity_tests.rs"]
mod tests;
