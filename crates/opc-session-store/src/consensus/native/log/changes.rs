//! Exact process-local log admission revisions and coalesced after-images.
//! A proof certifies the admission view only. The WAL owner's independently
//! durable committed watermark remains the authority for business application.

use super::*;
use crate::consensus::verified_snapshot::VerificationMemory;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::mem::size_of;
use std::sync::Arc;

#[path = "generation_frames.rs"]
mod frames;

#[derive(Clone)]
pub(in crate::consensus::native) struct GenerationLogVersion(Arc<LogProof>);

impl GenerationLogVersion {
    pub(in crate::consensus::native) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::consensus::native) struct LogFrontiers {
    pub(in crate::consensus::native) vote: Option<Vote<SessionConsensusNodeId>>,
    pub(in crate::consensus::native) committed: Option<LogId<SessionConsensusNodeId>>,
    pub(in crate::consensus::native) purged: Option<LogId<SessionConsensusNodeId>>,
}

impl LogFrontiers {
    pub(super) fn of(log: &NativeLog) -> Self {
        Self {
            vote: log.vote,
            committed: log.committed,
            purged: log.purged,
        }
    }
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct Summary {
    count: usize,
    content: [u8; 32],
    revisions: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    content: [u8; 32],
    revision: [u8; 32],
}

impl Summary {
    fn replace(&mut self, before: Option<Stamp>, after: Option<Stamp>) -> io::Result<()> {
        self.count = self
            .count
            .checked_sub(usize::from(before.is_some()))
            .and_then(|count| count.checked_add(usize::from(after.is_some())))
            .filter(|count| *count <= MAX_RETAINED_LOG_ENTRIES)
            .ok_or_else(|| invalid("native log change count exceeds bound"))?;
        for stamp in [before, after].into_iter().flatten() {
            for (slot, byte) in self.content.iter_mut().zip(stamp.content) {
                *slot ^= byte;
            }
            for (slot, byte) in self.revisions.iter_mut().zip(stamp.revision) {
                *slot ^= byte;
            }
        }
        Ok(())
    }
}

fn stamp(index: u64, row: &SharedRow<NativeLogEntry>) -> io::Result<Stamp> {
    let content = row.content(index)?;
    let mut revision = Sha256::new();
    revision.update(b"OPC-native-log-revision-v1\0");
    revision.update(content);
    revision.update(row.revision().to_le_bytes());
    Ok(Stamp {
        content,
        revision: revision.finalize().into(),
    })
}

pub(super) struct LogProof {
    identity: SessionConsensusIdentity,
    members: BTreeSet<SessionConsensusNodeId>,
    snapshot_origin: Option<Arc<NativeSnapshotAuthority>>,
    frontiers: LogFrontiers,
    summary: Summary,
    first: Option<LogId<SessionConsensusNodeId>>,
    last: Option<LogId<SessionConsensusNodeId>>,
    revision: u64,
    _memory: VerificationMemory,
}

impl LogProof {
    fn new(
        state: &NativeState,
        frontiers: LogFrontiers,
        summary: Summary,
        first: Option<LogId<SessionConsensusNodeId>>,
        last: Option<LogId<SessionConsensusNodeId>>,
        revision: u64,
    ) -> io::Result<Arc<Self>> {
        let memory =
            VerificationMemory::reserve(64 * 1024 + size_of::<Self>() + 2 * size_of::<usize>())?;
        Ok(Arc::new(Self {
            identity: state.identity,
            members: state.members.clone(),
            snapshot_origin: state.snapshot_origin.clone(),
            frontiers,
            summary,
            first,
            last,
            revision,
            _memory: memory,
        }))
    }
}

fn exact(
    id: LogId<SessionConsensusNodeId>,
    frontiers: &LogFrontiers,
    row: &impl Fn(u64) -> Option<LogId<SessionConsensusNodeId>>,
) -> io::Result<()> {
    sql::validate_log_id(&id)?;
    match row(id.index) {
        Some(retained) if retained == id => Ok(()),
        None if frontiers.purged == Some(id) => Ok(()),
        _ => Err(invalid("native log pointer lacks exact retained lineage")),
    }
}

/// Complete small cross-state equations used both by full validation and a
/// staged projection. All physically retained payloads are checked separately.
pub(super) fn validate_context<'a>(
    frontiers: &LogFrontiers,
    members: &BTreeSet<SessionConsensusNodeId>,
    business: &NativeFrontiers,
    origin: Option<&NativeSnapshotAuthority>,
    row: impl Fn(u64) -> Option<&'a SharedRow<NativeLogEntry>>,
) -> io::Result<()> {
    let membership_id = *business.membership.log_id();
    let actual_membership = membership_id
        .and_then(|id| row(id.index))
        .map(|row| row.membership())
        .transpose()?
        .flatten();
    let expected_membership = generation::facts::membership(business.membership.membership())?;
    validate_context_metadata(
        frontiers,
        members,
        business,
        origin,
        |index| row(index).map(|row| row.id()),
        |index| {
            membership_id.is_some_and(|id| id.index == index)
                && actual_membership == Some(expected_membership)
        },
    )
}

// The complete validator and the cold catalog share every pointer equation.
// The latter supplies metadata derived by complete row decoding, including a
// canonical membership payload hash; neither callback conveys live authority.
pub(in crate::consensus::native) fn validate_context_metadata(
    frontiers: &LogFrontiers,
    members: &BTreeSet<SessionConsensusNodeId>,
    business: &NativeFrontiers,
    origin: Option<&NativeSnapshotAuthority>,
    row: impl Fn(u64) -> Option<LogId<SessionConsensusNodeId>>,
    membership_matches: impl Fn(u64) -> bool,
) -> io::Result<()> {
    if let (Some(origin), Some(purged)) = (origin, frontiers.purged) {
        if row(purged.index).is_none() && !origin.matches_cut(purged) {
            return Err(invalid(
                "native missing purge witness differs from admitted snapshot cut",
            ));
        }
    }
    for pointer in [frontiers.committed, frontiers.purged, business.applied]
        .into_iter()
        .flatten()
    {
        exact(pointer, frontiers, &row)?;
    }
    if let Some(membership_id) = business.membership.log_id() {
        let installed = row(membership_id.index).is_none()
            && origin.is_some_and(|origin| origin.matches_membership(&business.membership));
        if !installed {
            exact(*membership_id, frontiers, &row)?;
        }
        if !membership_matches(membership_id.index) && !installed {
            return Err(invalid(
                "native membership payload differs from exact log witness",
            ));
        }
    }
    if let Some(applied) = business.applied {
        sql::ensure_log_id_not_after(
            &applied,
            &frontiers
                .committed
                .ok_or_else(|| invalid("native applied state is uncommitted"))?,
            "native applied state exceeds committed log",
        )?;
    }
    if let Some(vote) = frontiers.vote {
        if vote.leader_id.term > COUNTER_MAX
            || vote
                .leader_id
                .voted_for()
                .is_some_and(|node| !members.contains(&node))
        {
            return Err(invalid("native recovered vote authority differs"));
        }
    }
    if let Some(snapshot) = &business.current_snapshot {
        validation::validate_snapshot(snapshot, business, origin)?;
        if let Some(id) = snapshot.0.last_log_id {
            if row(id.index) != Some(id)
                && !(row(id.index).is_none()
                    && origin.is_some_and(|origin| origin.matches_snapshot_lineage(snapshot)))
            {
                return Err(invalid(
                    "native snapshot applied lineage differs from retained log",
                ));
            }
        }
    }
    Ok(())
}

struct RowChange {
    before: Option<SharedRow<NativeLogEntry>>,
    after: Option<SharedRow<NativeLogEntry>>,
    before_stamp: Option<Stamp>,
    after_stamp: Option<Stamp>,
}

fn same(
    left: Option<&SharedRow<NativeLogEntry>>,
    right: Option<&SharedRow<NativeLogEntry>>,
) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => left.ptr_eq(right),
        _ => false,
    }
}

pub(super) struct LogChanges {
    base: Arc<LogProof>,
    target: Arc<LogProof>,
    rows: HashMap<u64, RowChange>,
    memory: Vec<Arc<VerificationMemory>>,
}

impl LogChanges {
    fn empty(proof: Arc<LogProof>) -> Self {
        Self {
            base: Arc::clone(&proof),
            target: proof,
            rows: HashMap::new(),
            memory: Vec::new(),
        }
    }

    #[cfg(test)]
    fn validate(&self, log: &NativeLog, state: &NativeState) -> io::Result<()> {
        if !Arc::ptr_eq(&self.target, log.require_proof(state)?) {
            return Err(invalid("native log capture target differs"));
        }
        for (index, change) in &self.rows {
            if !same(change.after.as_ref(), log.entries.get(index)) {
                return Err(invalid("native log capture contains a stale revision"));
            }
        }
        self.validate_rows(state.identity, &state.members, &|| Ok(()))?;
        validate_context(
            &self.target.frontiers,
            &state.members,
            &state.frontiers,
            state.snapshot_origin.as_deref(),
            |index| log.entries.get(&index),
        )?;
        Ok(())
    }

    fn validate_rows(
        &self,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        check()?;
        if self.base.identity != self.target.identity
            || self.base.members != self.target.members
            || self.base.revision > self.target.revision
            || self.target.identity != identity
            || &self.target.members != members
        {
            return Err(invalid("native captured log predecessor differs"));
        }
        let mut summary = self.base.summary;
        for (index, change) in &self.rows {
            check()?;
            let before = change
                .before
                .as_ref()
                .map(|row| stamp(*index, row))
                .transpose()?;
            let after = change
                .after
                .as_ref()
                .map(|row| stamp(*index, row))
                .transpose()?;
            if before != change.before_stamp || after != change.after_stamp {
                return Err(invalid("native log capture stamp differs"));
            }
            summary.replace(before, after)?;
        }
        if summary != self.target.summary {
            return Err(invalid(
                "native log capture omitted or changed published rows",
            ));
        }
        // Establish the complete immutable predecessor/target relationship
        // before trusting this admitted row shape to size decoder scratch.
        // The full raw decoder and all semantic checks still run afterward.
        for (index, change) in &self.rows {
            for row in [change.before.as_ref(), change.after.as_ref()]
                .into_iter()
                .flatten()
            {
                row.validate_full(*index, identity, members, check)?;
            }
        }
        check()
    }
}

struct Witness {
    index: u64,
    row: SharedRow<NativeLogEntry>,
    revision: u64,
}

/// At most five exact log lookups accompany a journal transfer. These row
/// objects and the business proof remain valid after the live owner advances.
/// Their full raw schema is checked by the worker, outside that owner lock.
pub(in crate::consensus::native) struct CapturedLog {
    changes: LogChanges,
    business: Arc<crate::consensus::native::changes::BusinessProof>,
    witnesses: [Option<Witness>; 5],
    _memory: VerificationMemory,
}

impl CapturedLog {
    pub(in crate::consensus::native) fn business_proof(
        &self,
    ) -> &Arc<crate::consensus::native::changes::BusinessProof> {
        &self.business
    }

    pub(in crate::consensus::native) fn validate_captured(
        &self,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        let (identity, members, business) = self.business.context();
        self.changes.validate_rows(identity, members, check)?;
        for witness in self.witnesses.iter().flatten() {
            check()?;
            if witness.revision != witness.row.revision() {
                return Err(invalid("native captured log witness revision differs"));
            }
            witness
                .row
                .validate_full(witness.index, identity, members, check)?;
        }
        scratch::small(check, || {
            validate_context(
                &self.changes.target.frontiers,
                members,
                business,
                self.business.snapshot_origin(),
                |index| {
                    self.witnesses
                        .iter()
                        .flatten()
                        .find(|witness| witness.index == index)
                        .map(|witness| &witness.row)
                },
            )
        })?;
        check()
    }
}

pub(in crate::consensus::native) struct LogTransfer<'a> {
    dirty: &'a mut LogChanges,
    next: LogChanges,
    business: Arc<crate::consensus::native::changes::BusinessProof>,
    witnesses: [Option<Witness>; 5],
    memory: VerificationMemory,
}

impl LogTransfer<'_> {
    pub(in crate::consensus::native) fn take(self) -> CapturedLog {
        CapturedLog {
            changes: std::mem::replace(self.dirty, self.next),
            business: self.business,
            witnesses: self.witnesses,
            _memory: self.memory,
        }
    }
}

pub(super) struct Publication {
    predecessor: Arc<LogProof>,
    business_predecessor: Arc<crate::consensus::native::changes::BusinessProof>,
    proof: Arc<LogProof>,
    rows: BTreeMap<u64, RowChange>,
    tracking: bool,
    memory: Arc<VerificationMemory>,
}

impl Publication {
    pub(super) fn prepare(
        log: &NativeLog,
        operation: &Operation,
        state: &NativeState,
        frozen_applied: Option<LogId<SessionConsensusNodeId>>,
    ) -> io::Result<Self> {
        let predecessor = Arc::clone(log.require_proof(state)?);
        validate_context(
            &predecessor.frontiers,
            &state.members,
            &state.frontiers,
            state.snapshot_origin.as_deref(),
            |index| log.entries.get(&index),
        )?;
        let capacity = match operation {
            Operation::Append(rows) => {
                if rows.is_empty() || rows.len() > LOG_RPC_ENTRIES {
                    return Err(invalid("native append count invalid"));
                }
                rows.len()
            }
            Operation::Truncate(since) => log.entries.range(since.index..).count(),
            _ => 0,
        };
        let bytes = capacity
            .checked_mul(8 * (size_of::<(u64, RowChange)>() + 1))
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or_else(|| invalid("native log change reservation overflow"))?;
        let memory = Arc::new(VerificationMemory::reserve(bytes)?);
        let mut rows = BTreeMap::new();
        let mut frontiers = predecessor.frontiers;
        match operation {
            Operation::Append(encoded) => {
                let mut previous: Option<LogId<SessionConsensusNodeId>> = None;
                for encoded in encoded {
                    let entry = sql::decode_consensus_log_entry(encoded)?;
                    NativeLog::validate_entry(&entry, state)?;
                    if log
                        .purged
                        .is_some_and(|floor| entry.log_id.index <= floor.index)
                    {
                        return Err(invalid("native append crosses purged floor"));
                    }
                    if let Some(previous) = previous {
                        if entry.log_id.index != previous.index + 1 {
                            return Err(invalid("native append has a hole"));
                        }
                        sql::ensure_log_id_not_after(
                            &previous,
                            &entry.log_id,
                            "native append term regressed",
                        )?;
                    } else {
                        match entry.log_id.index.checked_sub(1) {
                            Some(index) => {
                                let prior = log
                                    .entries
                                    .get(&index)
                                    .map(|row| row.id())
                                    .or_else(|| log.purged.filter(|floor| floor.index == index))
                                    .ok_or_else(|| invalid("native append predecessor missing"))?;
                                sql::ensure_log_id_not_after(
                                    &prior,
                                    &entry.log_id,
                                    "native append predecessor term regressed",
                                )?;
                            }
                            None if log.purged.is_some() => {
                                return Err(invalid("native append overwrites purged genesis"))
                            }
                            None => {}
                        }
                    }
                    let before = log.entries.get(&entry.log_id.index).cloned();
                    if let Some(existing) = &before {
                        if !existing.matches_bytes(entry.log_id.index, encoded)? {
                            return Err(invalid("native append overwrites an existing entry"));
                        }
                    } else if log
                        .committed
                        .is_some_and(|committed| entry.log_id.index <= committed.index)
                        || state
                            .applied()
                            .is_some_and(|applied| entry.log_id.index <= applied.index)
                    {
                        return Err(invalid("native append crosses committed history"));
                    }
                    let index = entry.log_id.index;
                    previous = Some(entry.log_id);
                    let after = SharedRow::new(NativeLogEntry::new(encoded.clone(), entry))?;
                    rows.insert(
                        index,
                        RowChange {
                            before_stamp: before
                                .as_ref()
                                .map(|row| stamp(index, row))
                                .transpose()?,
                            after_stamp: Some(stamp(index, &after)?),
                            before,
                            after: Some(after),
                        },
                    );
                }
            }
            Operation::Vote(vote) => {
                if vote.leader_id.term > COUNTER_MAX
                    || vote
                        .leader_id
                        .voted_for()
                        .is_some_and(|node| !state.members.contains(&node))
                {
                    return Err(invalid("native vote is outside fixed authority"));
                }
                if log.vote.is_some_and(|current| {
                    vote.partial_cmp(&current) != Some(std::cmp::Ordering::Greater)
                        && *vote != current
                }) {
                    return Err(invalid("native vote regressed"));
                }
                frontiers.vote = Some(*vote);
            }
            Operation::Committed(committed) => {
                match committed {
                    Some(committed) => {
                        log.exact(*committed)?;
                        if let Some(current) = log.committed {
                            sql::ensure_log_id_not_after(
                                &current,
                                committed,
                                "native committed pointer regressed",
                            )?;
                        }
                    }
                    None if log.committed.is_some() => {
                        return Err(invalid("native committed pointer cleared"))
                    }
                    None => {}
                }
                frontiers.committed = *committed;
            }
            Operation::Truncate(since) => {
                sql::validate_log_id(since)?;
                for protected in [log.committed, state.applied(), log.purged]
                    .into_iter()
                    .flatten()
                {
                    sql::ensure_log_id_not_after(
                        &protected,
                        since,
                        "native truncate crosses protected log",
                    )?;
                    if protected.index == since.index {
                        return Err(invalid("native truncate crosses protected log"));
                    }
                }
                if log.entries.contains_key(&since.index) {
                    log.exact(*since)?;
                } else if log.last().map_or(0, |last| last.index + 1) != since.index {
                    return Err(invalid("native truncate lacks exact prefix"));
                }
                for (index, row) in log.entries.range(since.index..) {
                    rows.insert(
                        *index,
                        RowChange {
                            before: Some(row.clone()),
                            after: None,
                            before_stamp: Some(stamp(*index, row)?),
                            after_stamp: None,
                        },
                    );
                }
            }
            Operation::Purge(through) => {
                sql::validate_log_id(through)?;
                if let Some(current) = log.purged.filter(|current| through.index <= current.index) {
                    sql::ensure_log_id_not_after(
                        through,
                        &current,
                        "native delayed purge lineage differs",
                    )?;
                } else {
                    let frozen = frozen_applied
                        .ok_or_else(|| invalid("native purge lacks selected applied basis"))?;
                    sql::ensure_log_id_not_after(
                        through,
                        &frozen,
                        "native purge exceeds selected applied basis",
                    )?;
                    log.exact(*through)?;
                    // Physical prefix reclamation needs the later explicit
                    // membership/snapshot boundary-witness implementation.
                    frontiers.purged = Some(*through);
                }
            }
            Operation::Barrier => {}
        }
        let lookup = |index| {
            rows.get(&index)
                .map_or_else(|| log.entries.get(&index), |change| change.after.as_ref())
        };
        validate_context(
            &frontiers,
            &state.members,
            &state.frontiers,
            state.snapshot_origin.as_deref(),
            lookup,
        )?;
        let mut summary = predecessor.summary;
        for change in rows.values() {
            summary.replace(change.before_stamp, change.after_stamp)?;
        }
        let (first, last) = if summary.count == 0 {
            (None, None)
        } else {
            let first = predecessor.first.or_else(|| {
                rows.first_key_value()
                    .and_then(|(_, change)| change.after.as_ref().map(|row| row.id()))
            });
            let last = match operation {
                Operation::Truncate(since) => log
                    .entries
                    .range(..since.index)
                    .next_back()
                    .map(|(_, row)| row.id()),
                _ => rows
                    .last_key_value()
                    .and_then(|(_, change)| change.after.as_ref().map(|row| row.id()))
                    .into_iter()
                    .chain(predecessor.last)
                    .max_by_key(|id| id.index),
            };
            (first, last)
        };
        let revision = predecessor
            .revision
            .checked_add(1)
            .ok_or_else(|| invalid("native log revision exhausted"))?;
        let proof = LogProof::new(state, frontiers, summary, first, last, revision)?;
        Ok(Self {
            predecessor,
            business_predecessor: Arc::clone(state.require_business_proof()?),
            proof,
            rows,
            tracking: log.changes.is_some(),
            memory,
        })
    }

    pub(super) fn publish(
        self,
        log: &mut NativeLog,
        state: &NativeState,
    ) -> io::Result<Option<LogId<SessionConsensusNodeId>>> {
        if !Arc::ptr_eq(&self.predecessor, log.require_proof(state)?)
            || !Arc::ptr_eq(&self.business_predecessor, state.require_business_proof()?)
            || self.tracking != log.changes.is_some()
            || log
                .changes
                .as_ref()
                .is_some_and(|dirty| !Arc::ptr_eq(&dirty.target, &self.predecessor))
        {
            return Err(invalid("native log publication predecessor changed"));
        }
        for (index, change) in &self.rows {
            if !same(change.before.as_ref(), log.entries.get(index)) {
                return Err(invalid("native log publication row predecessor changed"));
            }
            if log
                .changes
                .as_ref()
                .and_then(|dirty| dirty.rows.get(index))
                .is_some_and(|prior| {
                    !same(change.before.as_ref(), prior.after.as_ref())
                        || change.before_stamp != prior.after_stamp
                })
            {
                return Err(invalid("native log dirty predecessor changed"));
            }
        }
        if let Some(dirty) = &mut log.changes {
            dirty
                .rows
                .try_reserve(self.rows.len())
                .map_err(|_| invalid("native log dirty allocation failed"))?;
            dirty
                .memory
                .try_reserve(1)
                .map_err(|_| invalid("native log dirty reservation allocation failed"))?;
        }
        // All recoverable checks/reservations and row allocations precede
        // publication. As in the original log, immutable tree node allocation can
        // abort or unwind; the enclosing owner mutex fences any unwind.
        for (index, change) in self.rows {
            if let Some(after) = &change.after {
                log.entries.insert(index, after.clone());
            } else {
                log.entries.remove(&index);
            }
            if let Some(dirty) = &mut log.changes {
                match dirty.rows.entry(index) {
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(change);
                    }
                    std::collections::hash_map::Entry::Occupied(mut slot) => {
                        let prior = slot.get_mut();
                        prior.after = change.after;
                        prior.after_stamp = change.after_stamp;
                    }
                }
            }
        }
        if let Some(dirty) = &mut log.changes {
            dirty.target = Arc::clone(&self.proof);
            dirty.memory.push(self.memory);
        }
        log.vote = self.proof.frontiers.vote;
        log.committed = self.proof.frontiers.committed;
        log.purged = self.proof.frontiers.purged;
        log.proof = Some(self.proof);
        Ok(log.committed)
    }
}

impl NativeLog {
    pub(super) fn validate_row(
        index: u64,
        row: &NativeLogEntry,
        state: &NativeState,
    ) -> io::Result<()> {
        Self::validate_row_context(index, row, state.identity, &state.members)
    }

    fn validate_row_context(
        index: u64,
        row: &NativeLogEntry,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
    ) -> io::Result<()> {
        row.validate_context(index, identity, members)
    }

    pub(super) fn require_proof(&self, state: &NativeState) -> io::Result<&Arc<LogProof>> {
        state.require_business_proof()?;
        let proof = self
            .proof
            .as_ref()
            .ok_or_else(|| invalid("native log has no process admission proof"))?;
        if proof.identity != state.identity
            || proof.members != state.members
            || proof.frontiers != LogFrontiers::of(self)
            || proof.summary.count != self.entries.len()
            || proof.first != self.entries.get_min().map(|(_, row)| row.id())
            || proof.last != self.entries.get_max().map(|(_, row)| row.id())
            || match (&proof.snapshot_origin, &state.snapshot_origin) {
                (None, None) => false,
                (Some(left), Some(right)) => !Arc::ptr_eq(left, right),
                _ => true,
            }
        {
            return Err(invalid(
                "native log proof no longer matches admission state",
            ));
        }
        Ok(proof)
    }

    pub(crate) fn admit(&mut self, state: &NativeState) -> io::Result<()> {
        if self.changes.is_some() {
            return Err(invalid("native cannot readmit a dirty log"));
        }
        self.proof = None;
        state.require_business_proof()?;
        self.validate(state)?;
        let mut summary = Summary::default();
        for (index, row) in &self.entries {
            summary.replace(None, Some(stamp(*index, row)?))?;
        }
        self.proof = Some(LogProof::new(
            state,
            LogFrontiers::of(self),
            summary,
            self.entries.get_min().map(|(_, row)| row.id()),
            self.entries.get_max().map(|(_, row)| row.id()),
            0,
        )?);
        Ok(())
    }

    pub(in crate::consensus::native) fn begin_changes(
        &mut self,
        state: &NativeState,
    ) -> io::Result<()> {
        if self.changes.is_some() {
            return Err(invalid("native log capture already active"));
        }
        let proof = Arc::clone(self.require_proof(state)?);
        validate_context(
            &proof.frontiers,
            &state.members,
            &state.frontiers,
            state.snapshot_origin.as_deref(),
            |index| self.entries.get(&index),
        )?;
        self.changes = Some(LogChanges::empty(proof));
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn capture_changes(&mut self, state: &NativeState) -> io::Result<LogChanges> {
        self.changes
            .as_ref()
            .ok_or_else(|| invalid("native log capture inactive"))?
            .validate(self, state)?;
        let next = LogChanges::empty(Arc::clone(self.require_proof(state)?));
        self.changes
            .replace(next)
            .ok_or_else(|| invalid("native log capture disappeared"))
    }

    pub(in crate::consensus::native) fn prepare_transfer(
        &mut self,
        state: &NativeState,
    ) -> io::Result<LogTransfer<'_>> {
        self.prepare_checkpoint_transfer(state, None)
    }

    pub(in crate::consensus::native) fn prepare_checkpoint_transfer(
        &mut self,
        state: &NativeState,
        snapshot: Option<&crate::consensus::native::changes::SnapshotSelection>,
    ) -> io::Result<LogTransfer<'_>> {
        let proof = Arc::clone(self.require_proof(state)?);
        if self
            .changes
            .as_ref()
            .is_none_or(|dirty| !Arc::ptr_eq(&dirty.target, &proof))
        {
            return Err(invalid(
                "native log transfer target differs or capture inactive",
            ));
        }
        let business = match snapshot {
            Some(snapshot) => snapshot.selected_proof(state)?,
            None => Arc::clone(state.require_business_proof()?),
        };
        let memory = VerificationMemory::reserve(size_of::<CapturedLog>())?;
        let (_, _, frontiers) = business.context();
        let pointers = [
            self.committed,
            self.purged,
            frontiers.applied,
            *frontiers.membership.log_id(),
            frontiers
                .current_snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.0.last_log_id),
        ];
        let witnesses = pointers.map(|id| {
            id.and_then(|id| {
                self.entries.get(&id.index).cloned().map(|row| Witness {
                    index: id.index,
                    revision: row.revision(),
                    row,
                })
            })
        });
        validate_context(
            &proof.frontiers,
            &state.members,
            frontiers,
            business.snapshot_origin(),
            |index| {
                witnesses
                    .iter()
                    .flatten()
                    .find(|witness| witness.index == index)
                    .map(|witness| &witness.row)
            },
        )?;
        let dirty = self
            .changes
            .as_mut()
            .ok_or_else(|| invalid("native log transfer capture disappeared"))?;
        Ok(LogTransfer {
            dirty,
            next: LogChanges::empty(proof),
            business,
            witnesses,
            memory,
        })
    }
}

#[cfg(test)]
mod tests;
