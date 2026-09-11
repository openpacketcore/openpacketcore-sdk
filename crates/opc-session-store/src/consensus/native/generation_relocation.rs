//! Expected-readback row ranges. Only a successful complete append verifier
//! can turn these offsets and pinned logical revisions into replacements.
//! The WAL owner publishes them after durable CURRENT, with no file work or
//! codec under State. Superseded logical rows are left alone.

use super::*;
use crate::consensus::native::resident::RowFingerprint;
use std::mem::size_of;

enum Expected {
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

enum Replacement {
    Receipt {
        id: FencedTransitionV2RequestId,
        row: SharedRow<NativeReceipt>,
    },
    Notification {
        index: usize,
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
    identity: SessionConsensusIdentity,
    members: BTreeSet<SessionConsensusNodeId>,
    root: Option<Arc<crate::fenced_mutation_roster::RosterAttestationTrustRootV1>>,
    _memory: VerificationMemory,
}

/// One owner work unit performs at most 64 persistent-container mutations.
/// The writer releases State and services its WAL queue between units.
pub(crate) const RELOCATION_STEP_ROWS: usize = 64;

/// Fixed stack storage keeps the old resident values until State is released.
/// Its borrow prevents refunding the preparation charge before this batch
/// drops, including the final batch. No row or output allocation occurs here.
pub(crate) struct RetiredRows<'a> {
    _rows: [Option<Replacement>; RELOCATION_STEP_ROWS],
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
        // rows. Notification metadata is inline in these vectors. Charge the
        // largest remaining concrete value Arc plus selected-body Box; no
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

    pub(super) fn prepare(
        self,
        source: Arc<VerifiedPrefix>,
        identity: SessionConsensusIdentity,
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
                    let index = usize::try_from(sequence.checked_sub(1).ok_or_else(|| {
                        invalid("native relocation notification sequence is zero")
                    })?)
                    .map_err(|_| invalid("native relocation notification index overflow"))?;
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
                        index,
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
                            id: row.id(),
                            membership: row.membership()?,
                        },
                    };
                    let cold = log::NativeLogEntry::from_admitted_range(
                        facts,
                        Arc::clone(&source),
                        offset,
                        length,
                        identity,
                        members,
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
            identity,
            members: members.clone(),
            root,
            _memory,
        })
    }
}

impl Relocations {
    pub(crate) fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// The integrating WAL owner has already made this exact generation's
    /// CURRENT durable and checked its live owner. All fallible validation is
    /// complete before changing a row. Proof counts, contents and logical
    /// revisions remain identical; concurrent replacements simply do not match.
    pub(crate) fn publish_step(
        &mut self,
        storage: &mut NativeStorage,
    ) -> io::Result<RetiredRows<'_>> {
        storage.business.require_business_proof()?;
        storage.log.generation_version(&storage.business)?;
        if storage.business.identity != self.identity
            || storage.business.members != self.members
            || storage.business.roster_root != self.root
        {
            return Err(invalid("native relocation authority changed"));
        }
        let mut retired = RetiredRows {
            _rows: std::array::from_fn(|_| None),
            remaining: false,
            _memory: std::marker::PhantomData,
        };
        for slot in &mut retired._rows {
            let Some(mut replacement) = self.rows.pop() else {
                break;
            };
            match &mut replacement {
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
                Replacement::Notification { index, row } => {
                    if storage
                        .business
                        .notifications
                        .get(*index)
                        .is_some_and(|current| current.ptr_eq(row))
                    {
                        *row = storage.business.notifications.set(*index, row.clone());
                    }
                }
                Replacement::Log { index, row } => {
                    if storage
                        .log
                        .entries
                        .get(index)
                        .is_some_and(|current| current.ptr_eq(row))
                    {
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
                        if let Some(previous) =
                            storage.business.roster.rows.insert(*binding, row.clone())
                        {
                            *row = previous;
                        }
                    }
                }
            }
            *slot = Some(replacement);
        }
        retired.remaining = !self.rows.is_empty();
        Ok(retired)
    }
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
