//! Test-only live-owner accounting at the real retained-ledger validation calls.
//!
//! These are allocated payload extents, not allocator/RSS estimates. SQL engine
//! pages, serde scratch and Arc bookkeeping are outside this lower bound. An
//! inactive observer performs no inventory and imposes no ledger-shape limit.

use std::cell::Cell;
use std::marker::PhantomData;
use std::mem::size_of;

use crate::audit_authority::ledger::{EntryPayload, LedgerEntry, LedgerOperation, LedgerState};
use crate::audit_authority::AuditOperationHandle;
use crate::consensus::audit_mutation::AuditedConfigCommand;

const HELD: usize = 0;
const READ: usize = 1;
const DECODED: usize = 2;
const DERIVED: usize = 3;
const AUTH: usize = 4;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Sample {
    pub(crate) command: usize,
    pub(crate) apply_page: usize,
    pub(crate) encryption_alias: usize,
    pub(crate) recovery: usize,
    pub(crate) held_ledger: usize,
    pub(crate) row_json: usize,
    pub(crate) decoded_ledger: usize,
    pub(crate) derived: usize,
    pub(crate) authentication: usize,
    pub(crate) total: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Observation {
    base: Sample,
    owners: [usize; 5],
    pub(crate) reads: usize,
    pub(crate) nested_reads: usize,
    pub(crate) derived_len: usize,
    pub(crate) derived_capacity: usize,
    pub(crate) peak: Sample,
    pub(crate) nested_peak: Sample,
}

thread_local! {
    static OBSERVATION: Cell<Option<Observation>> = const { Cell::new(None) };
}

fn sample(observation: &mut Observation) {
    let mut current = Sample {
        // The decoded page is measured before its move into apply. Charge it
        // only while the actual nested call borrows that command and ledger;
        // this never extends the observation beyond the moved entry's drop.
        apply_page: if observation.owners[HELD] != 0 {
            observation.base.apply_page
        } else {
            0
        },
        held_ledger: observation.owners[HELD],
        row_json: observation.owners[READ],
        decoded_ledger: observation.owners[DECODED],
        derived: observation.owners[DERIVED],
        authentication: observation.owners[AUTH],
        ..observation.base
    };
    current.total = [
        current.command,
        current.apply_page,
        current.encryption_alias,
        current.recovery,
        current.held_ledger,
        current.row_json,
        current.decoded_ledger,
        current.derived,
        current.authentication,
    ]
    .into_iter()
    .try_fold(0_usize, usize::checked_add)
    .expect("finite concrete owner extents");
    if current.total > observation.peak.total {
        observation.peak = current;
    }
    if current.held_ledger != 0 && current.total > observation.nested_peak.total {
        observation.nested_peak = current;
    }
}

fn ledger_heap(ledger: &LedgerState) -> usize {
    assert!(
        ledger.continuity.is_none(),
        "fixture excludes continuity rows"
    );
    let boxes = ledger
        .entries
        .iter()
        .map(|entry| match &entry.payload {
            EntryPayload::Intent(_) => size_of::<AuditOperationHandle>(),
            EntryPayload::Outcome { .. } | EntryPayload::Terminal { .. } => 0,
            EntryPayload::Event(_) | EntryPayload::KeyTransition(_) => {
                panic!("fixture uses only real operation admission and terminal transitions")
            }
        })
        .sum::<usize>();
    ledger.entries.capacity() * size_of::<LedgerEntry>()
        + ledger.operations.capacity() * size_of::<LedgerOperation>()
        + boxes
}

// Guards borrow owners wherever they do not grow. Drop order is deliberate:
// the observation ends before those owners move, are replaced, or are freed.
pub(crate) struct OwnerGuard<'a> {
    category: usize,
    active: bool,
    owner: PhantomData<&'a ()>,
}

fn owner<'a>(category: usize, bytes: impl FnOnce() -> usize) -> OwnerGuard<'a> {
    let active = OBSERVATION.with(|slot| {
        let Some(mut observation) = slot.get() else {
            return false;
        };
        assert_eq!(observation.owners[category], 0, "one owner per category");
        observation.owners[category] = bytes();
        if category == READ {
            observation.reads += 1;
            observation.nested_reads += usize::from(observation.owners[HELD] != 0);
        }
        sample(&mut observation);
        slot.set(Some(observation));
        true
    });
    OwnerGuard {
        category,
        active,
        owner: PhantomData,
    }
}

impl Drop for OwnerGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            OBSERVATION.with(|slot| {
                if let Some(mut observation) = slot.get() {
                    observation.owners[self.category] = 0;
                    slot.set(Some(observation));
                }
            });
        }
    }
}

pub(crate) fn held<'a>(
    ledger: &'a LedgerState,
    _command: &'a AuditedConfigCommand,
) -> OwnerGuard<'a> {
    owner(HELD, || ledger_heap(ledger))
}

pub(crate) struct ReadGuard<'a> {
    _encoded: OwnerGuard<'a>,
    _ledger: OwnerGuard<'a>,
}

pub(crate) fn read<'a>(encoded: &'a Vec<u8>, ledger: Option<&'a LedgerState>) -> ReadGuard<'a> {
    ReadGuard {
        _encoded: owner(READ, || encoded.capacity()),
        _ledger: owner(DECODED, || ledger.map_or(0, ledger_heap)),
    }
}

pub(crate) fn authentication(encoded: &Vec<u8>) -> OwnerGuard<'_> {
    owner(AUTH, || encoded.capacity())
}

pub(crate) struct DerivedGuard(OwnerGuard<'static>);

pub(crate) fn derived() -> DerivedGuard {
    DerivedGuard(owner(DERIVED, || 0))
}

impl DerivedGuard {
    pub(crate) fn observe(&self, operations: &Vec<LedgerOperation>) {
        if self.0.active {
            OBSERVATION.with(|slot| {
                let Some(mut observation) = slot.get() else {
                    return;
                };
                observation.owners[DERIVED] = operations.capacity() * size_of::<LedgerOperation>();
                observation.derived_len = observation.derived_len.max(operations.len());
                observation.derived_capacity =
                    observation.derived_capacity.max(operations.capacity());
                sample(&mut observation);
                slot.set(Some(observation));
            });
        }
    }
}

pub(crate) struct ObservationGuard;

impl ObservationGuard {
    pub(crate) fn start(base: Sample) -> Self {
        OBSERVATION.with(|slot| {
            assert!(
                slot.get().is_none(),
                "one synchronous observation per thread"
            );
            let mut observation = Observation {
                base,
                ..Observation::default()
            };
            sample(&mut observation);
            slot.set(Some(observation));
        });
        Self
    }

    pub(crate) fn finish(self) -> Observation {
        OBSERVATION.with(|slot| {
            let observation = slot.take().expect("active observation");
            assert_eq!(observation.owners, [0; 5], "all observed scopes have ended");
            observation
        })
    }
}

impl Drop for ObservationGuard {
    fn drop(&mut self) {
        OBSERVATION.with(|slot| slot.set(None));
    }
}
