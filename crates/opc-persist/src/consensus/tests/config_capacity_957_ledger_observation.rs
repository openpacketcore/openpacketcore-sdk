//! Test-only live-owner accounting at the real retained-ledger validation calls.
//!
//! These are allocated payload extents, not allocator/RSS estimates. SQL engine
//! pages, serde scratch and Arc bookkeeping are outside this lower bound. An
//! inactive observer performs no inventory and imposes no ledger-shape limit.

use std::cell::Cell;
use std::marker::PhantomData;
use std::mem::size_of;
use std::ops::Deref;

use crate::audit_authority::continuity::chain::SignedAuditRow;

use crate::audit_authority::ledger::{EntryPayload, LedgerEntry, LedgerOperation, LedgerState};
use crate::audit_authority::AuditOperationHandle;
use crate::consensus::audit_mutation::AuditedConfigCommand;

const HELD: usize = 0;
const READ: usize = 1;
const DECODED: usize = 2;
const DERIVED: usize = 3;
const AUTH: usize = 4;
const APPLY: usize = 5;
const WRITE: usize = 6;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Sample {
    pub(crate) command: usize,
    pub(crate) apply_page: usize,
    pub(crate) encryption_alias: usize,
    pub(crate) recovery: usize,
    pub(crate) held_ledger: usize,
    pub(crate) caller_ledger: usize,
    pub(crate) row_json: usize,
    pub(crate) write_json: usize,
    pub(crate) decoded_ledger: usize,
    pub(crate) derived: usize,
    pub(crate) authentication: usize,
    pub(crate) total: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Observation {
    base: Sample,
    owners: [usize; 7],
    pub(crate) reads: usize,
    pub(crate) apply_reads: usize,
    pub(crate) writes: usize,
    pub(crate) nested_reads: usize,
    pub(crate) derived_len: usize,
    pub(crate) derived_capacity: usize,
    pub(crate) continuity_rows: usize,
    pub(crate) continuity_bytes: usize,
    pub(crate) validation_peak: Sample,
    pub(crate) peak: Sample,
    pub(crate) nested_peak: Sample,
}

thread_local! {
    static OBSERVATION: Cell<Option<Observation>> = const { Cell::new(None) };
}

fn sample(observation: &mut Observation) {
    #[cfg(target_os = "linux")]
    let caller_ledger =
        crate::consensus::store::config_capacity_caller_ledger_observation::current_bytes();
    #[cfg(not(target_os = "linux"))]
    let caller_ledger = 0;
    let mut current = Sample {
        caller_ledger,
        // The guard borrows the actual decoded command through its apply and
        // retained receipt read, ending before that moved entry is dropped.
        apply_page: observation.owners[APPLY],
        held_ledger: observation.owners[HELD],
        row_json: observation.owners[READ],
        write_json: observation.owners[WRITE],
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
        current.caller_ledger,
        current.row_json,
        current.write_json,
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
    if current.derived != 0 && current.total > observation.validation_peak.total {
        observation.validation_peak = current;
    }
    if current.held_ledger != 0 && current.total > observation.nested_peak.total {
        observation.nested_peak = current;
    }
}

pub(crate) fn ledger_heap(ledger: &LedgerState) -> usize {
    let continuity = ledger.continuity.as_ref().map_or(0, |chain| {
        chain.rows.capacity() * size_of::<SignedAuditRow>()
    });
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
        + continuity
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
            observation.apply_reads += usize::from(observation.owners[APPLY] != 0);
            observation.nested_reads += usize::from(observation.owners[HELD] != 0);
        }
        if category == WRITE {
            observation.writes += 1;
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

pub(crate) fn applying(_command: &AuditedConfigCommand) -> OwnerGuard<'_> {
    owner(APPLY, || {
        OBSERVATION.with(|slot| slot.get().expect("active observation").base.apply_page)
    })
}

pub(crate) struct ReadGuard<'a> {
    _encoded: OwnerGuard<'a>,
    _ledger: OwnerGuard<'a>,
}

// This wrapper contains the actual SQL result Vec. It never clones the row or
// lends an encoded-byte reference to the decoded-ledger guard. Field order
// clears the observation immediately before the actual Vec is dropped.
pub(crate) struct EncodedRead {
    _observed: OwnerGuard<'static>,
    encoded: Vec<u8>,
}

impl EncodedRead {
    pub(crate) fn observe(encoded: Vec<u8>) -> Self {
        Self {
            _observed: owner(READ, || encoded.capacity()),
            encoded,
        }
    }
}

impl Deref for EncodedRead {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.encoded
    }
}

fn observe_continuity(ledger: Option<&LedgerState>) {
    OBSERVATION.with(|slot| {
        let Some(mut observation) = slot.get() else {
            return;
        };
        if let Some(chain) = ledger.and_then(|ledger| ledger.continuity.as_ref()) {
            observation.continuity_rows = observation.continuity_rows.max(chain.rows.len());
            observation.continuity_bytes = observation
                .continuity_bytes
                .max(chain.rows.capacity() * size_of::<SignedAuditRow>());
        }
        slot.set(Some(observation));
    });
}

pub(crate) fn decoded(ledger: Option<&LedgerState>) -> OwnerGuard<'_> {
    observe_continuity(ledger);
    owner(DECODED, || ledger.map_or(0, ledger_heap))
}

pub(crate) fn write<'a>(encoded: &'a Vec<u8>, ledger: Option<&'a LedgerState>) -> ReadGuard<'a> {
    observe_continuity(ledger);
    ReadGuard {
        _encoded: owner(WRITE, || encoded.capacity()),
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
            assert_eq!(observation.owners, [0; 7], "all observed scopes have ended");
            observation
        })
    }
}

impl Drop for ObservationGuard {
    fn drop(&mut self) {
        OBSERVATION.with(|slot| slot.set(None));
    }
}
