//! Expected-readback row ranges. Only a successful complete append verifier
//! can turn these offsets and pinned logical revisions into replacements.
//! The WAL owner publishes them after durable CURRENT, with no file work or
//! codec under State. Superseded logical rows are left alone.

use super::*;
use crate::consensus::native::resident::RowFingerprint;
use std::mem::size_of;

enum Expected {
    RetireSlotProjection {
        index: u64,
        row: SharedRow<log::NativeLogEntry>,
    },
    Receipt {
        id: FencedTransitionV2RequestId,
        row: SharedRow<NativeReceipt>,
        offset: u64,
        length: u32,
    },
    Notification {
        row: NotificationRow,
        offset: u64,
        length: u32,
    },
    Log {
        index: u64,
        row: SharedRow<log::NativeLogEntry>,
        offset: u64,
        length: u32,
    },
    Roster {
        row: SharedRow<roster::Row>,
        offset: u64,
        length: u32,
    },
}

#[derive(Clone)]
enum Replacement {
    Receipt {
        id: FencedTransitionV2RequestId,
        row: SharedRow<NativeReceipt>,
    },
    Notification {
        row: NotificationRow,
    },
    Log {
        index: u64,
        row: SharedRow<log::NativeLogEntry>,
    },
    Roster {
        binding: crate::fenced_mutation_roster::RequestBindingKey,
        row: SharedRow<roster::Row>,
    },
}

pub(in crate::consensus::native) struct RelocationBuilder {
    rows: Vec<Expected>,
    maximum: usize,
    _memory: VerificationMemory,
}

pub(crate) struct Relocations {
    rows: Vec<Replacement>,
    base: Option<Box<super::rollover::RelocationStream>>,
    replay: Option<Box<super::replay::ReplayStream>>,
    identity: SessionConsensusIdentity,
    members: BTreeSet<SessionConsensusNodeId>,
    root: Option<Arc<crate::fenced_mutation_roster::RosterAttestationTrustRootV1>>,
    _memory: VerificationMemory,
}

#[cfg(test)]
impl Relocations {
    pub(super) fn reserved_bytes_for_test(&self) -> usize {
        self._memory.reserved_bytes_for_test()
    }
}

/// One owner work unit publishes at most 64 logical row revisions into their
/// live, deferred and journal roots. The writer releases State and services
/// its WAL queue between units.
pub(crate) const RELOCATION_STEP_ROWS: usize = 64;

/// Fixed stack storage keeps the old resident values until State is released.
/// Its borrow prevents refunding the preparation charge before this batch
/// drops, including the final batch. No row or output allocation occurs here.
pub(crate) struct RetiredRows<'a> {
    _rows: [Option<Replacement>; RELOCATION_STEP_ROWS],
    _captured_rows: [Option<Replacement>; RELOCATION_STEP_ROWS],
    _journal_rows: [Option<SharedRow<log::NativeLogEntry>>; RELOCATION_STEP_ROWS],
    _captured_journal_rows: [Option<SharedRow<log::NativeLogEntry>>; RELOCATION_STEP_ROWS],
    remaining: bool,
    _memory: std::marker::PhantomData<&'a VerificationMemory>,
}

impl RetiredRows<'_> {
    pub(crate) fn has_remaining(&self) -> bool {
        self.remaining
    }
}

impl RelocationBuilder {
    pub(super) fn new(maximum: usize) -> io::Result<Self> {
        // Both exact-capacity vectors coexist while ranges become compact
        // rows. Receipt and notification metadata is inline in these vectors.
        // Charge the largest remaining concrete value Arc and body; no
        // payload or prefix index is copied and logical revisions are retained.
        let allocation = NativeReceipt::relocation_allocation_bytes()
            .max(log::NativeLogEntry::relocation_allocation_bytes());
        // Roster::Row::selected reserves its independent copy before it
        // transfers into resident metadata. That prospective replacement has
        // the same whole-process RSS ownership as a catalog's selected rows.
        let bytes = maximum
            .checked_mul(size_of::<Expected>() + size_of::<Replacement>() + allocation)
            .and_then(|bytes| bytes.checked_add(64 * 1024))
            .ok_or_else(|| invalid("native relocation reservation overflow"))?;
        let memory = VerificationMemory::reserve(bytes)?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(maximum)
            .map_err(|_| invalid("native relocation range allocation failed"))?;
        Ok(Self {
            rows,
            maximum,
            _memory: memory,
        })
    }

    fn push(&mut self, row: Expected) -> io::Result<()> {
        if self.rows.len() == self.maximum {
            return Err(invalid("native relocation count exceeds its captured rows"));
        }
        self.rows.push(row);
        Ok(())
    }

    pub(in crate::consensus::native) fn receipt(
        &mut self,
        id: FencedTransitionV2RequestId,
        row: &SharedRow<NativeReceipt>,
        offset: u64,
        length: u32,
    ) -> io::Result<()> {
        self.push(Expected::Receipt {
            id,
            row: row.clone(),
            offset,
            length,
        })
    }
    pub(in crate::consensus::native) fn notification(
        &mut self,
        row: &NotificationRow,
        offset: u64,
        length: u32,
    ) -> io::Result<()> {
        self.push(Expected::Notification {
            row: row.clone(),
            offset,
            length,
        })
    }
    pub(in crate::consensus::native) fn log(
        &mut self,
        index: u64,
        row: &SharedRow<log::NativeLogEntry>,
        offset: u64,
        length: u32,
    ) -> io::Result<()> {
        self.push(Expected::Log {
            index,
            row: row.clone(),
            offset,
            length,
        })
    }

    pub(in crate::consensus::native) fn roster(
        &mut self,
        row: &SharedRow<roster::Row>,
        offset: u64,
        length: u32,
    ) -> io::Result<()> {
        self.push(Expected::Roster {
            row: row.clone(),
            offset,
            length,
        })
    }

    pub(super) fn retire_slot_projection(
        &mut self,
        index: u64,
        row: &SharedRow<log::NativeLogEntry>,
    ) -> io::Result<()> {
        self.push(Expected::RetireSlotProjection {
            index,
            row: row.clone(),
        })
    }

    pub(super) fn prepare(
        self,
        source: Arc<VerifiedPrefix>,
        identity: SessionConsensusIdentity,
        applied: Option<LogId<SessionConsensusNodeId>>,
        members: &BTreeSet<SessionConsensusNodeId>,
        root: Option<Arc<crate::fenced_mutation_roster::RosterAttestationTrustRootV1>>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Relocations> {
        let Self {
            rows,
            maximum: _,
            _memory,
        } = self;
        let mut replacements = Vec::new();
        replacements
            .try_reserve_exact(rows.len())
            .map_err(|_| invalid("native relocation output allocation failed"))?;
        for expected in rows {
            check()?;
            replacements.push(match expected {
                Expected::RetireSlotProjection { index, row } => {
                    if applied.is_none_or(|cut| index > cut.index) {
                        return Err(invalid("native projection retirement exceeds applied cut"));
                    }
                    Replacement::Log {
                        index,
                        row: row.relocated(row.without_slot_projection()?),
                    }
                }
                Expected::Receipt {
                    id,
                    row,
                    offset,
                    length,
                } => {
                    let facts = facts::Receipt::of(id, &row)?;
                    let cold = NativeReceipt::from_admitted_range(
                        id,
                        facts,
                        Arc::clone(&source),
                        offset,
                        length,
                    )?;
                    if cold.row_fingerprint(1, &id)? != row.row_fingerprint(1, &id)? {
                        return Err(invalid("native receipt relocation content differs"));
                    }
                    Replacement::Receipt {
                        id,
                        row: row.relocated(cold),
                    }
                }
                Expected::Notification {
                    row,
                    offset,
                    length,
                } => {
                    let sequence = row.sequence();
                    let facts = facts::Row {
                        content: row.row_fingerprint(3, &sequence)?,
                        facts: facts::Notification {
                            sequence,
                            timestamp: row.timestamp(),
                        },
                    };
                    let cold = NativeNotification::from_admitted_range(
                        facts,
                        Arc::clone(&source),
                        offset,
                        length,
                    )?;
                    if cold.row_fingerprint(3, &sequence)? != facts.content {
                        return Err(invalid("native notification relocation content differs"));
                    }
                    Replacement::Notification {
                        row: row.relocated(cold),
                    }
                }
                Expected::Log {
                    index,
                    row,
                    offset,
                    length,
                } => {
                    let facts = facts::Row {
                        content: row.content(index)?,
                        facts: facts::Log {
                            slot_control: row.is_slot_control(),
                            id: row.id(),
                            membership: row.membership()?,
                        },
                    };
                    let cold = log::NativeLogEntry::from_admitted_range_with_profile(
                        facts,
                        Arc::clone(&source),
                        offset,
                        length,
                        identity,
                        members,
                        row.slot_profile(),
                        applied,
                    )?;
                    if cold.content(index)? != facts.content {
                        return Err(invalid("native log relocation content differs"));
                    }
                    Replacement::Log {
                        index,
                        row: row.relocated(cold),
                    }
                }
                Expected::Roster {
                    row,
                    offset,
                    length,
                } => {
                    let root = root.as_deref().ok_or_else(|| {
                        invalid("native roster relocation configured root absent")
                    })?;
                    let cold = row.selected(
                        Arc::clone(&source),
                        offset,
                        length,
                        root,
                        &roster::fixed_scope(identity, members),
                        check,
                    )?;
                    Replacement::Roster {
                        binding: row.binding(),
                        row: row.relocated(cold),
                    }
                }
            });
        }
        check()?;
        Ok(Relocations {
            rows: replacements,
            base: None,
            replay: None,
            identity,
            members: members.clone(),
            root,
            _memory,
        })
    }
}

impl Relocations {
    pub(crate) fn empty(native: &NativeStorage, source: Arc<VerifiedPrefix>) -> io::Result<Self> {
        RelocationBuilder::new(0)?.prepare(
            source,
            native.business.identity,
            native.business.applied(),
            &native.business.members,
            native.business.roster_root.clone(),
            &|| Ok(()),
        )
    }

    pub(crate) fn from_base(
        capture: capture::SnapshotCapture,
        source: Arc<VerifiedPrefix>,
    ) -> io::Result<Self> {
        let mut result = RelocationBuilder::new(0)?.prepare(
            Arc::clone(&source),
            capture.storage.business.identity,
            capture.storage.business.applied(),
            &capture.storage.business.members,
            capture.storage.business.roster_root.clone(),
            &|| Ok(()),
        )?;
        result.base = Some(Box::new(super::rollover::RelocationStream::new(
            capture, source,
        )?));
        Ok(result)
    }

    pub(crate) fn from_replay(
        capture: capture::SnapshotCapture,
        source: Arc<VerifiedPrefix>,
        old: Arc<VerifiedPrefix>,
        cut: PrefixIdentity,
        mappings: Vec<super::FrameMapping>,
    ) -> io::Result<Self> {
        let mut result = RelocationBuilder::new(0)?.prepare(
            Arc::clone(&source),
            capture.storage.business.identity,
            capture.storage.business.applied(),
            &capture.storage.business.members,
            capture.storage.business.roster_root.clone(),
            &|| Ok(()),
        )?;
        result.replay = Some(Box::new(super::replay::ReplayStream::new(
            capture, source, old, cut, mappings,
        )?));
        Ok(result)
    }

    /// Complete at most one bounded base batch outside State. The immutable
    /// capture is shared; no second full index or all-row relocation vector is
    /// allocated, even when the compact file contains a full retained history.
    pub(crate) fn prepare_step(&mut self, check: &impl Fn() -> io::Result<()>) -> io::Result<()> {
        if self.rows.is_empty() {
            if let Some(base) = &mut self.base {
                let (next, finished) = base.next(check)?;
                self.rows = next.rows;
                self._memory = next._memory;
                if finished {
                    self.base = None;
                }
            }
        }
        if self.rows.is_empty() {
            if let Some(replay) = &mut self.replay {
                let (next, finished) = replay.next(check)?;
                self.rows = next.rows;
                self._memory = next._memory;
                if finished {
                    self.replay = None;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rows.is_empty() && self.base.is_none() && self.replay.is_none()
    }

    /// The integrating WAL owner has already made this exact generation's
    /// CURRENT durable and checked its live owner. All fallible validation is
    /// complete before changing a row. Proof counts, contents and logical
    /// revisions remain identical; concurrent replacements simply do not match.
    #[cfg(test)]
    pub(crate) fn publish_step(
        &mut self,
        storage: &mut NativeStorage,
    ) -> io::Result<RetiredRows<'_>> {
        self.publish_step_mirrored(storage, None)
    }

    /// The deferred selected cut is immutable logically, but its own row roots
    /// must shed retired source pins too. Publish the same at-most-64 distinct
    /// revisions into both roots; validation for both precedes any mutation.
    /// Both old batches survive State and fit the existing 64 KiB workspace.
    pub(crate) fn publish_step_mirrored(
        &mut self,
        storage: &mut NativeStorage,
        mut mirror: Option<&mut NativeStorage>,
    ) -> io::Result<RetiredRows<'_>> {
        self.require_authority(storage)?;
        if let Some(captured) = mirror.as_deref() {
            self.require_authority(captured)?;
        }
        let mut retired = RetiredRows {
            _rows: std::array::from_fn(|_| None),
            _captured_rows: std::array::from_fn(|_| None),
            _journal_rows: std::array::from_fn(|_| None),
            _captured_journal_rows: std::array::from_fn(|_| None),
            remaining: false,
            _memory: std::marker::PhantomData,
        };
        for (((slot, captured_slot), journal_slot), captured_journal_slot) in retired
            ._rows
            .iter_mut()
            .zip(&mut retired._captured_rows)
            .zip(&mut retired._journal_rows)
            .zip(&mut retired._captured_journal_rows)
        {
            let Some(mut replacement) = self.rows.pop() else {
                break;
            };
            if let Some(captured) = mirror.as_deref_mut() {
                let mut copy = replacement.clone();
                *captured_journal_slot = publish_replacement(captured, &mut copy);
                *captured_slot = Some(copy);
            }
            *journal_slot = publish_replacement(storage, &mut replacement);
            *slot = Some(replacement);
        }
        retired.remaining = !self.is_empty();
        Ok(retired)
    }

    fn require_authority(&self, storage: &NativeStorage) -> io::Result<()> {
        // Log admission includes the complete business proof admission under
        // this same exclusive storage borrow, before any row is relocated.
        storage.log.generation_version(&storage.business)?;
        if storage.business.identity != self.identity
            || storage.business.members != self.members
            || storage.business.roster_root != self.root
        {
            return Err(invalid("native relocation authority changed"));
        }
        Ok(())
    }
}

// Two row roots plus their journal predecessor aliases still fit the same
// fixed workspace. All four retired batches drop after the owner releases State.
const _: () = assert!(
    RELOCATION_STEP_ROWS
        * (2 * size_of::<Replacement>() + 2 * size_of::<Option<SharedRow<log::NativeLogEntry>>>())
        <= 64 * 1024
);

fn publish_replacement(
    storage: &mut NativeStorage,
    replacement: &mut Replacement,
) -> Option<SharedRow<log::NativeLogEntry>> {
    let mut journal = None;
    match replacement {
        Replacement::Receipt { id, row } => {
            if storage
                .business
                .receipts
                .get(id)
                .is_some_and(|current| current.ptr_eq(row))
            {
                if let Some(previous) = storage.business.receipts.insert(*id, row.clone()) {
                    *row = previous;
                }
            }
        }
        Replacement::Notification { row } => {
            if let Some(index) = storage
                .business
                .frontiers
                .notification_position(row.sequence())
            {
                if storage
                    .business
                    .notifications
                    .get(index)
                    .is_some_and(|current| current.ptr_eq(row))
                {
                    *row = storage.business.notifications.set(index, row.clone());
                }
            }
        }
        Replacement::Log { index, row } => {
            journal = storage.log.relocate_journal_predecessor(*index, row);
            if storage
                .log
                .entries
                .get(index)
                .is_some_and(|current| current.ptr_eq(row))
            {
                if row.has_slot_projection() {
                    storage.log.slot_projections.insert(*index, row.clone());
                } else {
                    storage.log.slot_projections.remove(index);
                }
                if let Some(previous) = storage.log.entries.insert(*index, row.clone()) {
                    *row = previous;
                }
            }
        }
        Replacement::Roster { binding, row } => {
            if storage
                .business
                .roster
                .rows
                .get(binding)
                .is_some_and(|current| current.ptr_eq(row))
            {
                if let Some(previous) = storage.business.roster.rows.insert(*binding, row.clone()) {
                    *row = previous;
                }
            }
        }
    }
    journal
}

pub(in crate::consensus::native) struct PositionedReader<'a> {
    reader: &'a mut dyn Read,
    position: u64,
}
impl<'a> PositionedReader<'a> {
    pub(super) fn new(reader: &'a mut dyn Read, position: u64) -> Self {
        Self { reader, position }
    }
    pub(in crate::consensus::native) fn position(&self) -> u64 {
        self.position
    }
}
impl Read for PositionedReader<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.reader.read(bytes)?;
        self.position = self
            .position
            .checked_add(count as u64)
            .ok_or_else(|| invalid("native relocation read position overflow"))?;
        Ok(count)
    }
}
