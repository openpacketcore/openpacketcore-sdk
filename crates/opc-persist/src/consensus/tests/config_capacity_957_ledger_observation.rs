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

// Before/after capacities of the actual mutable ledger, not simultaneous byte
// charges and not estimates of parser storage or allocator-internal overlap.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct LedgerCollections {
    pub(crate) lengths: [usize; 3],
    pub(crate) capacities: [usize; 3],
}

fn ledger_collections(ledger: &LedgerState) -> LedgerCollections {
    let (row_len, row_capacity) = ledger
        .continuity
        .as_ref()
        .map_or((0, 0), |chain| (chain.rows.len(), chain.rows.capacity()));
    LedgerCollections {
        lengths: [ledger.entries.len(), ledger.operations.len(), row_len],
        capacities: [
            ledger.entries.capacity(),
            ledger.operations.capacity(),
            row_capacity,
        ],
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Observation {
    base: Sample,
    owners: [usize; 7],
    ledger_identities: [usize; 7],
    continuity_depth: usize,
    encoding_depth: usize,
    pub(crate) encoding_calls: usize,
    pub(crate) read_continuity_peak: Sample,
    pub(crate) mutation_continuity_peak: Sample,
    pub(crate) continuity_checks: usize,
    pub(crate) continuity_peak: Sample,
    pub(crate) mutation_peak: Sample,
    pub(crate) mutation_owners: usize,
    pub(crate) mutation_initial: Option<LedgerCollections>,
    pub(crate) mutation_final: Option<LedgerCollections>,
    pub(crate) encoding_peak: Sample,
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
    if observation.continuity_depth > 0 && current.total > observation.continuity_peak.total {
        observation.continuity_peak = current;
    }
    if current.held_ledger > 0
        && current.authentication > 0
        && current.total > observation.mutation_peak.total
    {
        observation.mutation_peak = current;
    }
    if observation.continuity_depth > 0 && current.authentication > 0 {
        if current.decoded_ledger > 0
            && current.held_ledger == 0
            && current.total > observation.read_continuity_peak.total
        {
            observation.read_continuity_peak = current;
        }
        if current.held_ledger > 0 && current.total > observation.mutation_continuity_peak.total {
            observation.mutation_continuity_peak = current;
        }
    }
    if observation.encoding_depth > 0 && current.total > observation.encoding_peak.total {
        observation.encoding_peak = current;
    }
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
            EntryPayload::Event(_) => size_of::<crate::audit_authority::ProjectedAuditEvent>(),
            EntryPayload::KeyTransition(_) => {
                size_of::<crate::audit_authority::continuity::AuditKeyTransition>()
            }
            EntryPayload::TargetIntent(_) | EntryPayload::EmptyCommit(_) => {
                panic!("capacity-only observer does not inventory retained target payloads")
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
                    observation.ledger_identities[self.category] = 0;
                    slot.set(Some(observation));
                }
            });
        }
    }
}

pub(crate) fn applying(_command: &AuditedConfigCommand) -> OwnerGuard<'_> {
    owner(APPLY, || {
        OBSERVATION.with(|slot| slot.get().expect("active observation").base.apply_page)
    })
}

// A borrowed SQLite blob has no SDK-owned row buffer. Keep read counters live
// without charging SQLite's separate storage to the mutation working buffer.
pub(crate) fn borrowed_read(_encoded: &[u8]) -> OwnerGuard<'_> {
    owner(READ, || 0)
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
    match ledger {
        Some(ledger) => ledger_owner(DECODED, ledger),
        None => owner(DECODED, || 0),
    }
}

pub(crate) fn write(encoded: &Vec<u8>) -> OwnerGuard<'_> {
    OBSERVATION.with(|slot| {
        if let Some(mut observation) = slot.get() {
            observation.writes += 1;
            slot.set(Some(observation));
        }
    });
    owner(WRITE, || encoded.capacity())
}

// The caller cannot grow this Vec: StateWriter rejects writes past the one
// reserved extent. A counter-only guard permits the real serializer's mutation.
pub(crate) struct EncodingGuard {
    _encoded: OwnerGuard<'static>,
    active: bool,
}

pub(crate) fn encoding(encoded: &Vec<u8>) -> EncodingGuard {
    let guard = owner(WRITE, || encoded.capacity());
    let active = OBSERVATION.with(|slot| {
        let Some(mut observation) = slot.get() else {
            return false;
        };
        observation.encoding_depth += 1;
        observation.encoding_calls += 1;
        sample(&mut observation);
        slot.set(Some(observation));
        true
    });
    EncodingGuard {
        _encoded: guard,
        active,
    }
}

impl Drop for EncodingGuard {
    fn drop(&mut self) {
        if self.active {
            OBSERVATION.with(|slot| {
                if let Some(mut observation) = slot.get() {
                    observation.encoding_depth -= 1;
                    slot.set(Some(observation));
                }
            });
        }
    }
}

fn ledger_owner<'a>(category: usize, ledger: &LedgerState) -> OwnerGuard<'a> {
    observe_continuity(Some(ledger));
    OBSERVATION.with(|slot| {
        if let Some(mut observation) = slot.get() {
            assert_eq!(observation.ledger_identities[category], 0);
            observation.ledger_identities[category] = std::ptr::from_ref(ledger) as usize;
            slot.set(Some(observation));
        }
    });
    owner(category, || ledger_heap(ledger))
}

// The actual caller keeps the same mutable ledger until the explicit handoff
// to write_sync. This guard stores counters only and cannot extend its lifetime.
pub(crate) fn mutating(ledger: &LedgerState) -> OwnerGuard<'static> {
    let guard = ledger_owner(HELD, ledger);
    OBSERVATION.with(|slot| {
        if let Some(mut observation) = slot.get() {
            observation.mutation_owners += 1;
            let current = ledger_collections(ledger);
            if observation.mutation_initial.is_none() {
                observation.mutation_initial = Some(current);
            }
            observation.mutation_final = Some(current);
            slot.set(Some(observation));
        }
    });
    guard
}

// Refresh only an already registered real owner, immediately after mutation.
// Test setup and unrelated ledgers neither allocate inventory nor affect totals.
pub(crate) fn changed(ledger: &LedgerState) {
    let identity = std::ptr::from_ref(ledger) as usize;
    OBSERVATION.with(|slot| {
        let Some(mut observation) = slot.get() else {
            return;
        };
        for category in [HELD, DECODED] {
            if observation.ledger_identities[category] == identity {
                observation.owners[category] = ledger_heap(ledger);
                if category == HELD {
                    observation.mutation_final = Some(ledger_collections(ledger));
                }
            }
        }
        sample(&mut observation);
        slot.set(Some(observation));
    });
    observe_continuity(Some(ledger));
}

// seal_continuity mutably borrows just its chain. Update the allocation delta
// after each push without borrowing that chain and the enclosing ledger twice.
pub(crate) fn changed_rows(identity: usize, previous_capacity: usize, rows: &Vec<SignedAuditRow>) {
    OBSERVATION.with(|slot| {
        let Some(mut observation) = slot.get() else {
            return;
        };
        for category in [HELD, DECODED] {
            if observation.ledger_identities[category] == identity {
                observation.owners[category] = observation.owners[category]
                    .checked_sub(previous_capacity * size_of::<SignedAuditRow>())
                    .and_then(|bytes| {
                        bytes.checked_add(rows.capacity() * size_of::<SignedAuditRow>())
                    })
                    .expect("actual continuity allocation delta");
                if category == HELD {
                    if let Some(current) = &mut observation.mutation_final {
                        current.lengths[2] = rows.len();
                        current.capacities[2] = rows.capacity();
                    }
                }
            }
        }
        observation.continuity_rows = observation.continuity_rows.max(rows.len());
        observation.continuity_bytes = observation
            .continuity_bytes
            .max(rows.capacity() * size_of::<SignedAuditRow>());
        sample(&mut observation);
        slot.set(Some(observation));
    });
}

pub(crate) struct ContinuityGuard<'a> {
    _ledger: Option<OwnerGuard<'a>>,
    active: bool,
}

pub(crate) fn continuity(ledger: &LedgerState) -> ContinuityGuard<'_> {
    let identity = std::ptr::from_ref(ledger) as usize;
    let registered = OBSERVATION.with(|slot| {
        slot.get().is_some_and(|observation| {
            [HELD, DECODED]
                .into_iter()
                .any(|category| observation.ledger_identities[category] == identity)
        })
    });
    let guard = (!registered).then(|| ledger_owner(DECODED, ledger));
    let active = OBSERVATION.with(|slot| {
        let Some(mut observation) = slot.get() else {
            return false;
        };
        observation.continuity_depth += 1;
        observation.continuity_checks += 1;
        sample(&mut observation);
        slot.set(Some(observation));
        true
    });
    ContinuityGuard {
        _ledger: guard,
        active,
    }
}

impl Drop for ContinuityGuard<'_> {
    fn drop(&mut self) {
        if self.active {
            OBSERVATION.with(|slot| {
                if let Some(mut observation) = slot.get() {
                    observation.continuity_depth -= 1;
                    slot.set(Some(observation));
                }
            });
        }
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
            assert_eq!(observation.ledger_identities, [0; 7]);
            assert_eq!(observation.continuity_depth, 0);
            assert_eq!(observation.encoding_depth, 0);
            observation
        })
    }
}

impl Drop for ObservationGuard {
    fn drop(&mut self) {
        OBSERVATION.with(|slot| slot.set(None));
    }
}
