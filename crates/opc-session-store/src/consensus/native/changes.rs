//! Process-local semantic induction and atomic after-image capture.
//!
//! Neither a serialized summary nor a file digest constructs BusinessProof.
//! Its table checksums detect omissions when a trusted transition is coalesced;
//! they do not replace row semantics, exact object lineage or cold validation.
//! The existing full-image path does not enable incremental capture yet.

use std::hash::Hash;
use std::io::Write;
use std::mem::size_of;
use std::sync::Arc;

use super::*;
use crate::consensus::verified_snapshot::VerificationMemory;
use sha2::{Digest as _, Sha256};

#[path = "changes_frames.rs"]
mod frames;
pub(super) use frames::{generic_payload, notification_payload, ordinary_payload};

const PROOF_MEMORY: usize = 64 * 1024 + size_of::<BusinessProof>() + 2 * size_of::<usize>();

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct TableSummary {
    pub(super) count: usize,
    pub(super) checksum: [u8; 32],
    pub(super) revisions: [u8; 32],
}

impl TableSummary {
    pub(super) fn replace(
        &mut self,
        before: Option<RowStamp>,
        after: Option<RowStamp>,
    ) -> io::Result<()> {
        self.count = self
            .count
            .checked_sub(usize::from(before.is_some()))
            .and_then(|count| count.checked_add(usize::from(after.is_some())))
            .ok_or_else(|| invalid("native change count overflow"))?;
        for digest in [before, after].into_iter().flatten() {
            for (slot, byte) in self.checksum.iter_mut().zip(digest.content) {
                *slot ^= byte;
            }
            for (slot, byte) in self.revisions.iter_mut().zip(digest.revision) {
                *slot ^= byte;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct RowStamp {
    content: [u8; 32],
    revision: [u8; 32],
}

impl RowStamp {
    fn new(content: [u8; 32], revision: u64) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"OPC-native-process-revision-v1\0");
        hash.update(content);
        hash.update(revision.to_le_bytes());
        Self {
            content,
            revision: hash.finalize().into(),
        }
    }

    pub(super) fn content(self) -> [u8; 32] {
        self.content
    }
}

pub(super) fn stamp<T: resident::RowFingerprint>(
    table: u8,
    key: &impl Serialize,
    value: &SharedRow<T>,
) -> io::Result<RowStamp> {
    Ok(RowStamp::new(
        value.row_fingerprint(table, key)?,
        value.revision(),
    ))
}

fn notification_stamp(value: &NotificationRow) -> io::Result<RowStamp> {
    Ok(RowStamp::new(
        resident::RowFingerprint::row_fingerprint(&**value, 3, &value.sequence())?,
        value.revision(),
    ))
}

struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn fingerprint(
    table: u8,
    key: &impl Serialize,
    value: &impl Serialize,
) -> io::Result<[u8; 32]> {
    let mut writer = HashWriter(Sha256::new());
    writer.0.update(b"OPC-native-process-row-v1\0");
    writer.0.update([table]);
    // Streaming serialization allocates no encoded row buffer. These hashes
    // remain private, and cannot be supplied as an admission certificate.
    serde_json::to_writer(&mut writer, &(key, value))
        .map_err(|_| invalid("native row fingerprint cannot encode"))?;
    Ok(writer.0.finalize().into())
}

pub(super) struct BusinessProof {
    identity: SessionConsensusIdentity,
    members: BTreeSet<SessionConsensusNodeId>,
    frontiers: NativeFrontiers,
    tables: [TableSummary; 4],
    roster: Arc<roster::changes::Certificate>,
    roster_root: Option<Arc<crate::fenced_mutation_roster::RosterAttestationTrustRootV1>>,
    snapshot_origin: Option<Arc<NativeSnapshotAuthority>>,
    revision: u64,
    pub(super) expiry: expiry::ExpiryIndex,
    pub(super) receipt_order: history_order::ReceiptOrder,
    _memory: VerificationMemory,
}

impl BusinessProof {
    pub(in crate::consensus::native) fn snapshot_origin(&self) -> Option<&NativeSnapshotAuthority> {
        self.snapshot_origin.as_deref()
    }
    pub(in crate::consensus::native) fn roster_root(
        &self,
    ) -> Option<Arc<crate::fenced_mutation_roster::RosterAttestationTrustRootV1>> {
        self.roster_root.clone()
    }
    fn new(
        state: &NativeState,
        frontiers: &NativeFrontiers,
        tables: [TableSummary; 4],
        revision: u64,
        expiry: expiry::ExpiryIndex,
        receipt_order: history_order::ReceiptOrder,
        roster: &roster::Ledger,
    ) -> io::Result<Arc<Self>> {
        // The small frontiers use the same 64KiB header ceiling. The fixed
        // membership has at most five nodes. Derived resident index roots
        // share only scalar order/key metadata, with their full RSS charge.
        let memory = VerificationMemory::reserve(PROOF_MEMORY)?;
        Ok(Arc::new(Self {
            identity: state.identity,
            members: state.members.clone(),
            frontiers: frontiers.clone(),
            tables,
            roster: Arc::clone(roster.certificate()?),
            roster_root: state.roster_root.clone(),
            snapshot_origin: state.snapshot_origin.clone(),
            revision,
            expiry,
            receipt_order,
            _memory: memory,
        }))
    }

    fn counts(&self) -> [usize; 4] {
        self.tables.map(|table| table.count)
    }

    pub(super) fn context(
        &self,
    ) -> (
        SessionConsensusIdentity,
        &BTreeSet<SessionConsensusNodeId>,
        &NativeFrontiers,
    ) {
        (self.identity, &self.members, &self.frontiers)
    }
}

struct RowChange<T> {
    before: Option<SharedRow<T>>,
    after: Option<SharedRow<T>>,
    before_hash: Option<RowStamp>,
    after_hash: Option<RowStamp>,
}

impl<T> RowChange<T> {
    fn follows(&self, prior: &Self) -> bool {
        same_row(self.before.as_ref(), prior.after.as_ref()) && self.before_hash == prior.after_hash
    }
}

fn same_row<T>(left: Option<&SharedRow<T>>, right: Option<&SharedRow<T>>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => left.ptr_eq(right),
        _ => false,
    }
}

struct StagedRow<K, T> {
    key: K,
    journal_key: Option<K>,
    change: RowChange<T>,
}

fn staged<K: Clone + Eq + Hash + Serialize, T: resident::RowFingerprint>(
    table: u8,
    rows: HashMap<K, T>,
    base: &RowMap<K, SharedRow<T>>,
    tracking: bool,
    summary: &mut TableSummary,
) -> io::Result<Vec<StagedRow<K, T>>> {
    let mut staged = Vec::with_capacity(rows.len());
    for (key, value) in rows {
        let before = base.get(&key).cloned();
        let before_hash = before
            .as_ref()
            .map(|value| stamp(table, &key, value))
            .transpose()?;
        let after = SharedRow::new(value)?;
        let after_hash = Some(stamp(table, &key, &after)?);
        summary.replace(before_hash, after_hash)?;
        let journal_key = tracking.then(|| key.clone());
        staged.push(StagedRow {
            key,
            journal_key,
            change: RowChange {
                before,
                after: Some(after),
                before_hash,
                after_hash,
            },
        });
    }
    Ok(staged)
}

fn scratch_size<K, T>(count: usize) -> io::Result<usize> {
    count
        .checked_mul(size_of::<StagedRow<K, T>>() + 4 * (size_of::<(K, RowChange<T>)>() + 1))
        .and_then(|bytes| bytes.checked_add(64))
        .ok_or_else(|| invalid("native change reservation overflow"))
}

fn add_bytes(total: &mut usize, bytes: usize) -> io::Result<()> {
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| invalid("native change reservation overflow"))?;
    Ok(())
}

/// One original predecessor and one exact latest revision per changed key.
/// A replacement remains a change even if its serialized value is equal.
/// Removing and reinserting never erases the predecessor relationship.
pub(super) struct BusinessChanges {
    base: Arc<BusinessProof>,
    target: Arc<BusinessProof>,
    keys: HashMap<SessionKey, RowChange<NativeKeyState>>,
    receipts: HashMap<FencedTransitionV2RequestId, RowChange<NativeReceipt>>,
    generic: HashMap<SessionConsensusRequestId, RowChange<NativeGenericReceipt>>,
    notifications: Vec<NotificationRow>,
    roster: roster::changes::Journal,
    // Conservative container-growth reservations precede allocation. Captures
    // transfer these guards; cloned business images do not clone a journal.
    memory: Vec<Arc<VerificationMemory>>,
}

impl BusinessChanges {
    fn empty(proof: Arc<BusinessProof>) -> Self {
        Self {
            roster: roster::changes::Journal::empty_at(&proof.roster),
            base: Arc::clone(&proof),
            target: proof,
            keys: HashMap::new(),
            receipts: HashMap::new(),
            generic: HashMap::new(),
            notifications: Vec::new(),
            memory: Vec::new(),
        }
    }

    fn check_rows<K: Eq + Hash + Serialize, T: resident::RowFingerprint>(
        table: u8,
        rows: &HashMap<K, RowChange<T>>,
        summary: &mut TableSummary,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        for (key, change) in rows {
            scratch::small(check, || {
                let before = change
                    .before
                    .as_ref()
                    .map(|value| stamp(table, key, value))
                    .transpose()?;
                check()?;
                let after = change
                    .after
                    .as_ref()
                    .map(|value| stamp(table, key, value))
                    .transpose()?;
                if before != change.before_hash || after != change.after_hash {
                    return Err(invalid("native capture row fingerprint differs"));
                }
                summary.replace(before, after)
            })?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn validate(&self, state: &NativeState) -> io::Result<()> {
        if !Arc::ptr_eq(state.require_business_proof()?, &self.target) {
            return Err(invalid(
                "native capture is not the current certified revision",
            ));
        }
        self.roster.require_current(&state.roster)?;
        fn current<K: Eq + Hash, T>(
            changes: &HashMap<K, RowChange<T>>,
            rows: &RowMap<K, SharedRow<T>>,
        ) -> io::Result<()> {
            if changes
                .iter()
                .any(|(key, change)| !same_row(change.after.as_ref(), rows.get(key)))
            {
                return Err(invalid("native capture contains a stale row revision"));
            }
            Ok(())
        }
        current(&self.keys, &state.keys)?;
        current(&self.receipts, &state.receipts)?;
        current(&self.generic, &state.generic_receipts)?;
        let start = self.base.tables[3].count;
        for (offset, row) in self.notifications.iter().enumerate() {
            if state
                .notifications
                .get(start + offset)
                .is_none_or(|current| !current.ptr_eq(row))
            {
                return Err(invalid(
                    "native capture contains a stale notification revision",
                ));
            }
        }
        self.validate_captured(&|| Ok(()))
    }

    pub(super) fn target_proof(&self) -> &Arc<BusinessProof> {
        &self.target
    }

    /// No live map, mutex or mutable authority is consulted here. Both proofs
    /// and every before/after revision are owned by this detached journal.
    /// A persisted summary cannot construct either process certificate.
    pub(super) fn validate_captured(&self, check: &impl Fn() -> io::Result<()>) -> io::Result<()> {
        check()?;
        if self.base.identity != self.target.identity
            || self.base.members != self.target.members
            || self.base.revision > self.target.revision
        {
            return Err(invalid("native captured business predecessor differs"));
        }
        if self.base.roster_root != self.target.roster_root
            || !self.roster.starts_at(&self.base.roster)
            || !Arc::ptr_eq(self.roster.target(), &self.target.roster)
        {
            return Err(invalid(
                "native captured roster authority or predecessor differs",
            ));
        }
        match self.target.roster_root.as_deref() {
            Some(root) => self.roster.validate_detached(
                root,
                &roster::fixed_scope(self.target.identity, &self.target.members),
                check,
            )?,
            None => {
                // The original activation may precede root configuration;
                // Q1 then rejects authority while advancing its namespace.
                // Such an empty ledger is valid process state even though
                // an old generation cannot encode the new frontiers.
                if [&self.base, &self.target].into_iter().any(|proof| {
                    proof.roster.counts() != [0; 2] || proof.roster.witness().is_some()
                }) {
                    return Err(invalid(
                        "native captured roster rows lack a configured trust root",
                    ));
                }
                self.roster.validate(check)?;
            }
        }
        scratch::small(check, || {
            validate_frontier_transition(&self.base.frontiers, &self.target.frontiers, true)
        })?;
        let mut tables = self.base.tables;
        Self::check_rows(0, &self.keys, &mut tables[0], check)?;
        Self::check_rows(1, &self.receipts, &mut tables[1], check)?;
        Self::check_rows(2, &self.generic, &mut tables[2], check)?;
        let start = self.base.tables[3].count;
        for row in &self.notifications {
            scratch::small(check, || {
                tables[3].replace(None, Some(notification_stamp(row)?))
            })?;
        }
        if tables != self.target.tables {
            return Err(invalid("native capture omitted or changed published rows"));
        }
        scratch::small(check, || {
            validation::validate_frontiers(
                self.target.identity,
                &self.target.members,
                &self.target.frontiers,
                self.target.counts(),
                self.target.snapshot_origin(),
            )
        })?;
        for (key, change) in &self.keys {
            check()?;
            if let Some(row) = &change.after {
                scratch::key(row, check, || {
                    validation::validate_key(key, row, &self.target.frontiers)
                })?;
            }
        }
        let mut added = 0usize;
        let mut removed = 0usize;
        let mut transient = 0usize;
        for (id, change) in &self.receipts {
            check()?;
            if change.before.is_none()
                && self
                    .base
                    .frontiers
                    .history
                    .and_then(|history| history.active_epoch())
                    .is_some_and(|active| id.epoch() < active)
            {
                return Err(invalid(
                    "native captured new receipt predates the predecessor active epoch",
                ));
            }
            if let Some(row) = &change.after {
                scratch::receipt(check, || {
                    validation::validate_receipt(
                        self.target.identity,
                        id,
                        row,
                        &self.target.frontiers,
                        self.target
                            .frontiers
                            .history
                            .ok_or_else(|| invalid("native capture receipt history absent"))?,
                    )
                })?;
                added += usize::from(change.before.is_none());
            } else {
                lifecycle::removed_is_retired(
                    *id,
                    change.before.as_ref().map(|row| row.ordinal),
                    self.target.frontiers.history,
                )?;
                if change.before.is_some() {
                    removed += 1;
                } else {
                    transient += 1;
                }
            }
        }
        // A create-then-reclaim entry has no endpoint row or checksum. Count
        // the actual detached inventory, independently of both certificates,
        // so coalescing cannot erase a binding and its physical reclamation.
        lifecycle::conservation(
            self.base.frontiers.history,
            self.target.frontiers.history,
            added,
            removed,
            transient,
        )?;
        for (id, change) in &self.generic {
            check()?;
            let row = change
                .after
                .as_ref()
                .ok_or_else(|| invalid("native captured request receipt removed"))?;
            validation::validate_generic(id, row, &self.target.frontiers)?;
            if let Some(before) = &change.before {
                row.validate_replacement(before, self.target.frontiers.logical_time)?;
            }
        }
        for (offset, row) in self.notifications.iter().enumerate() {
            check()?;
            let sequence = start
                .checked_add(offset)
                .and_then(|index| index.checked_add(1))
                .ok_or_else(|| invalid("native captured notification sequence overflow"))?;
            scratch::small(check, || {
                row.validate(sequence as u64, &self.target.frontiers)
            })?;
        }
        check()
    }

    fn reserve(&mut self, publication: &Publication) -> io::Result<()> {
        self.keys
            .try_reserve(publication.keys.len())
            .map_err(|_| invalid("native dirty key allocation failed"))?;
        self.receipts
            .try_reserve(publication.receipts.len())
            .map_err(|_| invalid("native dirty receipt allocation failed"))?;
        self.generic
            .try_reserve(publication.generic.len())
            .map_err(|_| invalid("native dirty generic allocation failed"))?;
        self.notifications
            .try_reserve(publication.notifications.len())
            .map_err(|_| invalid("native dirty notification allocation failed"))?;
        self.memory
            .try_reserve(1)
            .map_err(|_| invalid("native dirty reservation allocation failed"))?;
        Ok(())
    }
}

/// A prepared transfer holds an exclusive borrow, so publication cannot
/// change its predecessor between preflight and the infallible journal move.
pub(super) struct BusinessTransfer<'a> {
    dirty: &'a mut BusinessChanges,
    next: BusinessChanges,
    selected_snapshot: Option<Arc<BusinessProof>>,
}

impl BusinessTransfer<'_> {
    pub(super) fn take(self) -> BusinessChanges {
        let mut captured = std::mem::replace(self.dirty, self.next);
        if let Some(proof) = self.selected_snapshot {
            captured.target = proof;
        }
        captured
    }
}

/// A proposed snapshot changes only bounded metadata in the worker's captured
/// context. The live state and its new dirty journal keep the old metadata
/// until the WAL owner has durably selected that exact checkpoint.
pub(crate) struct SnapshotSelection {
    before: Arc<BusinessProof>,
    selected: Arc<BusinessProof>,
}

impl SnapshotSelection {
    pub(super) fn selected_proof(&self, state: &NativeState) -> io::Result<Arc<BusinessProof>> {
        if !Arc::ptr_eq(&self.before, state.require_business_proof()?) {
            return Err(invalid("native snapshot capture predecessor changed"));
        }
        Ok(Arc::clone(&self.selected))
    }
}

fn validate_staged<K: Eq + Hash, T>(
    rows: &[StagedRow<K, T>],
    current: &RowMap<K, SharedRow<T>>,
    dirty: Option<&HashMap<K, RowChange<T>>>,
) -> io::Result<()> {
    for row in rows {
        if !same_row(row.change.before.as_ref(), current.get(&row.key))
            || dirty.is_some() != row.journal_key.is_some()
        {
            return Err(invalid("native publication predecessor changed"));
        }
        if dirty
            .and_then(|dirty| dirty.get(&row.key))
            .is_some_and(|prior| !row.change.follows(prior))
        {
            return Err(invalid(
                "native dirty predecessor does not match current row",
            ));
        }
    }
    Ok(())
}

fn publish_rows<K: Clone + Eq + Hash, T>(
    rows: Vec<StagedRow<K, T>>,
    current: &mut RowMap<K, SharedRow<T>>,
    mut dirty: Option<&mut HashMap<K, RowChange<T>>>,
) {
    for StagedRow {
        key,
        journal_key,
        change,
    } in rows
    {
        match &change.after {
            Some(value) => {
                current.insert(key, value.clone());
            }
            None => {
                current.remove(&key);
            }
        }
        if let (Some(dirty), Some(key)) = (dirty.as_deref_mut(), journal_key) {
            match dirty.entry(key) {
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(change);
                }
                std::collections::hash_map::Entry::Occupied(mut slot) => {
                    let prior = slot.get_mut();
                    prior.after = change.after;
                    prior.after_hash = change.after_hash;
                }
            }
        }
    }
}

pub(super) struct Publication {
    predecessor: Arc<BusinessProof>,
    proof: Arc<BusinessProof>,
    frontiers: NativeFrontiers,
    roster: roster::Ledger,
    roster_changes: roster::changes::Journal,
    keys: Vec<StagedRow<SessionKey, NativeKeyState>>,
    receipts: Vec<StagedRow<FencedTransitionV2RequestId, NativeReceipt>>,
    generic: Vec<StagedRow<SessionConsensusRequestId, NativeGenericReceipt>>,
    notifications: Vec<NotificationRow>,
    delivery: NativeApplied,
    memory: Arc<VerificationMemory>,
    tracking: bool,
    #[cfg(any(test, feature = "test-control"))]
    terminal_remainder_started: Option<std::time::Instant>,
}

impl Publication {
    pub(super) fn is_current(&self, state: &NativeState) -> io::Result<bool> {
        let proof = state.require_business_proof()?;
        if state
            .changes
            .as_ref()
            .is_some_and(|dirty| !Arc::ptr_eq(&dirty.target, proof))
        {
            return Err(invalid(
                "native application journal target differs from its live proof",
            ));
        }
        Ok(Arc::ptr_eq(&self.predecessor, proof) && self.tracking == state.changes.is_some())
    }

    pub(super) fn prepare(delta: NativeDelta<'_>) -> io::Result<Self> {
        Self::prepare_checked(delta, &|| Ok(()))
    }

    pub(super) fn prepare_checked(
        delta: NativeDelta<'_>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        roster::validate_candidate(&delta, check)?;
        let NativeDelta {
            base,
            frontiers,
            roster,
            roster_changes,
            keys,
            receipts,
            receipt_removals,
            generic_receipts,
            responses,
            notifications,
            #[cfg(any(test, feature = "test-control"))]
            terminal_remainder_started,
            ..
        } = delta;
        let predecessor = Arc::clone(base.require_business_proof()?);
        validate_frontier_transition(&predecessor.frontiers, &frontiers, false)?;
        let tracking = base.changes.is_some();
        let mut bytes = scratch_size::<SessionKey, NativeKeyState>(keys.len())?;
        add_bytes(
            &mut bytes,
            scratch_size::<FencedTransitionV2RequestId, NativeReceipt>(
                receipts
                    .len()
                    .checked_add(receipt_removals.len())
                    .ok_or_else(|| invalid("native receipt change count overflow"))?,
            )?,
        )?;
        add_bytes(
            &mut bytes,
            scratch_size::<SessionConsensusRequestId, NativeGenericReceipt>(
                generic_receipts.len(),
            )?,
        )?;
        add_bytes(
            &mut bytes,
            notifications
                .len()
                .checked_mul(4 * size_of::<NotificationRow>())
                .ok_or_else(|| invalid("native change notification reservation overflow"))?,
        )?;
        for key in keys.keys() {
            add_bytes(
                &mut bytes,
                key.log_row_reuse_allocation_bytes()
                    .ok_or_else(|| invalid("native changed key reservation overflow"))?,
            )?;
        }
        let memory = Arc::new(VerificationMemory::reserve(bytes)?);
        for (key, row) in &keys {
            validation::validate_key(key, row, &frontiers)?;
            if base
                .keys
                .get(key)
                .is_some_and(|before| row.fence < before.fence)
            {
                return Err(invalid("native changed key floor regressed"));
            }
        }
        let mut introduced = Vec::with_capacity(receipts.len());
        let mut deleted = Vec::with_capacity(receipt_removals.len());
        let mut transient = 0usize;
        let mut receipt_order = predecessor.receipt_order.clone();
        predecessor.receipt_order.validate_retirement(
            predecessor.frontiers.history,
            frontiers.history,
            frontiers.logical_time,
        )?;
        for (id, row) in &receipts {
            if receipt_removals.contains(id) {
                return Err(invalid("native receipt is both retained and removed"));
            }
            let history = frontiers
                .history
                .ok_or_else(|| invalid("native changed receipt history absent"))?;
            validation::validate_receipt(base.identity, id, row, &frontiers, history)?;
            if let Some(before) = base.receipts.get(id) {
                if row.ordinal != before.ordinal
                    || row.payload_digest != before.payload_digest
                    || row.retained_until != before.retained_until
                    || (resident::RowFingerprint::row_fingerprint(row, 1, id)?
                        != resident::RowFingerprint::row_fingerprint(&**before, 1, id)?
                        && !(before.retained()
                            && !row.retained()
                            && frontiers
                                .logical_time
                                .is_some_and(|now| now >= row.retained_until)))
                {
                    return Err(invalid(
                        "native receipt replacement changes its immutable binding",
                    ));
                }
            } else {
                // One atomic apply can bind and then expire this ID. The
                // full row predicate proves that an absent response is due.
                if predecessor
                    .frontiers
                    .history
                    .and_then(|history| history.active_epoch())
                    .is_some_and(|active| id.epoch() < active)
                {
                    return Err(invalid(
                        "native new receipt predates the predecessor active epoch",
                    ));
                }
                introduced.push((*id, row.ordinal, row.retained_until));
            }
        }
        for id in &receipt_removals {
            let before = base.receipts.get(id);
            lifecycle::removed_is_retired(*id, before.map(|row| row.ordinal), frontiers.history)?;
            if let Some(before) = before {
                deleted.push((*id, before.ordinal));
            } else {
                if predecessor
                    .frontiers
                    .history
                    .and_then(|history| history.active_epoch())
                    .is_some_and(|active| id.epoch() < active)
                {
                    return Err(invalid(
                        "native transient receipt predates the predecessor active epoch",
                    ));
                }
                transient += 1;
            }
        }
        lifecycle::conservation(
            predecessor.frontiers.history,
            frontiers.history,
            introduced.len(),
            deleted.len(),
            transient,
        )?;
        deleted.sort_unstable_by_key(|(id, ordinal)| (id.epoch(), *ordinal));
        for (id, ordinal) in deleted {
            receipt_order.remove_prefix(id, ordinal)?;
        }
        introduced.sort_unstable_by_key(|(id, ordinal, _)| (id.epoch(), *ordinal));
        for (id, ordinal, until) in introduced {
            receipt_order.append_captured(id, ordinal, until, frontiers.history)?;
        }
        receipt_order.validate(frontiers.history)?;
        for (id, row) in &generic_receipts {
            validation::validate_generic(id, row, &frontiers)?;
            if let Some(before) = base.generic_receipts.get(id) {
                row.validate_replacement(before, frontiers.logical_time)?;
            }
        }
        for (offset, row) in notifications.iter().enumerate() {
            validation::validate_notification(
                row,
                (predecessor.tables[3].count + offset) as u64 + 1,
                &frontiers,
            )?;
        }
        let mut tables = predecessor.tables;
        // Reconstruct the next resident index from the validated after-images,
        // independently of the transaction's temporary pruning index.
        let mut expiry = predecessor.expiry.clone();
        for (key, row) in &keys {
            expiry.replace(key, base.keys.get(key).map(|row| &**row), Some(row));
        }
        for (id, row) in &generic_receipts {
            expiry.replace_request(
                *id,
                base.generic_receipts.get(id).map(|row| &**row),
                Some(row),
            )?;
        }
        expiry.validate_requests(&frontiers)?;
        let keys = staged(0, keys, &base.keys, tracking, &mut tables[0])?;
        let mut receipts = staged(1, receipts, &base.receipts, tracking, &mut tables[1])?;
        receipts.reserve(receipt_removals.len());
        for key in receipt_removals {
            let before = base.receipts.get(&key).cloned();
            let before_hash = before.as_ref().map(|row| stamp(1, &key, row)).transpose()?;
            tables[1].replace(before_hash, None)?;
            receipts.push(StagedRow {
                key,
                journal_key: tracking.then_some(key),
                change: RowChange {
                    before,
                    after: None,
                    before_hash,
                    after_hash: None,
                },
            });
        }
        let generic = staged(
            2,
            generic_receipts,
            &base.generic_receipts,
            tracking,
            &mut tables[2],
        )?;
        let delivery = NativeApplied {
            responses,
            notifications: notifications.clone(),
        };
        let notifications = notifications
            .into_iter()
            .map(|row| NotificationRow::new(NativeNotification::new(row)))
            .collect::<io::Result<Vec<_>>>()?;
        for row in &notifications {
            tables[3].replace(None, Some(notification_stamp(row)?))?;
        }
        validation::validate_frontiers(
            base.identity,
            &base.members,
            &frontiers,
            tables.map(|table| table.count),
            base.snapshot_origin.as_deref(),
        )?;
        let revision = predecessor
            .revision
            .checked_add(1)
            .ok_or_else(|| invalid("native business revision exhausted"))?;
        let proof = BusinessProof::new(
            base,
            &frontiers,
            tables,
            revision,
            expiry,
            receipt_order,
            &roster,
        )?;
        // Delivery and all immutable row allocations precede visible changes.
        Ok(Self {
            predecessor,
            proof,
            frontiers,
            roster,
            roster_changes,
            keys,
            receipts,
            generic,
            notifications,
            delivery,
            memory,
            tracking,
            #[cfg(any(test, feature = "test-control"))]
            terminal_remainder_started,
        })
    }

    pub(super) fn publish(self, state: &mut NativeState) -> io::Result<NativeApplied> {
        if !Arc::ptr_eq(&self.predecessor, state.require_business_proof()?)
            || self.tracking != state.changes.is_some()
            || state
                .changes
                .as_ref()
                .is_some_and(|dirty| !Arc::ptr_eq(&dirty.target, &self.predecessor))
        {
            return Err(invalid(
                "native publication lost its exact certified predecessor",
            ));
        }
        validate_staged(
            &self.keys,
            &state.keys,
            state.changes.as_ref().map(|dirty| &dirty.keys),
        )?;
        validate_staged(
            &self.receipts,
            &state.receipts,
            state.changes.as_ref().map(|dirty| &dirty.receipts),
        )?;
        validate_staged(
            &self.generic,
            &state.generic_receipts,
            state.changes.as_ref().map(|dirty| &dirty.generic),
        )?;
        self.roster_changes.require_base(&state.roster)?;
        // Immutable resident collections allocate only changed tree paths.
        // Journal/output reservations and every fallible precondition have
        // completed before publication. An unwind still poisons the owner.
        if let Some(dirty) = &mut state.changes {
            dirty.reserve(&self)?;
        }
        let Self {
            proof,
            frontiers,
            roster,
            roster_changes,
            keys,
            receipts,
            generic,
            notifications,
            delivery,
            memory,
            #[cfg(any(test, feature = "test-control"))]
            terminal_remainder_started,
            ..
        } = self;
        let roster_append = state
            .changes
            .as_mut()
            .map(|dirty| dirty.roster.prepare_append(roster_changes))
            .transpose()?;
        // No fallible work follows. These exact row objects feed both maps
        // and the journal while the enclosing WAL State mutex fences unwind.
        if let Some(append) = roster_append {
            append.commit();
        }
        publish_rows(
            keys,
            &mut state.keys,
            state.changes.as_mut().map(|dirty| &mut dirty.keys),
        );
        publish_rows(
            receipts,
            &mut state.receipts,
            state.changes.as_mut().map(|dirty| &mut dirty.receipts),
        );
        publish_rows(
            generic,
            &mut state.generic_receipts,
            state.changes.as_mut().map(|dirty| &mut dirty.generic),
        );
        if let Some(dirty) = &mut state.changes {
            dirty.notifications.extend(notifications.iter().cloned());
            dirty.target = Arc::clone(&proof);
            dirty.memory.push(memory);
        }
        state.notifications.extend(notifications);
        state.roster = roster;
        state.frontiers = frontiers;
        state.proof = Some(proof);
        #[cfg(any(test, feature = "test-control"))]
        if let Some(started) = terminal_remainder_started {
            crate::sqlite::consensus::record_native_roster_publication_timing(started);
        }
        Ok(delivery)
    }
}

pub(super) fn validate_frontier_transition(
    before: &NativeFrontiers,
    after: &NativeFrontiers,
    snapshot: bool,
) -> io::Result<()> {
    if before.sequence > after.sequence
        || before.watch_sequence > after.watch_sequence
        || before.next_fence > after.next_fence
        || before.next_credential > after.next_credential
        || before.restore_revision > after.restore_revision
        || (before.sequence == after.sequence && before.digest != after.digest)
        || before
            .logical_time
            .is_some_and(|time| after.logical_time.is_none_or(|next| next < time))
        || (!snapshot && before.current_snapshot != after.current_snapshot)
    {
        return Err(invalid(
            "native transition regresses an unchanged-row frontier",
        ));
    }
    if let Some(before) = before.applied {
        crate::sqlite::consensus::ensure_log_id_not_after(
            &before,
            &after
                .applied
                .ok_or_else(|| invalid("native applied frontier cleared"))?,
            "native applied frontier regressed",
        )?;
    }
    if let Some(before) = before.membership.log_id() {
        crate::sqlite::consensus::ensure_log_id_not_after(
            before,
            after
                .membership
                .log_id()
                .as_ref()
                .ok_or_else(|| invalid("native membership frontier cleared"))?,
            "native membership frontier regressed",
        )?;
    }
    if let Some(before) = &before.current_snapshot {
        let after = after
            .current_snapshot
            .as_ref()
            .ok_or_else(|| invalid("native selected snapshot cleared"))?;
        if let Some(before) = before.0.last_log_id {
            crate::sqlite::consensus::ensure_log_id_not_after(
                &before,
                &after
                    .0
                    .last_log_id
                    .ok_or_else(|| invalid("native new snapshot applied missing"))?,
                "native selected snapshot regressed",
            )?;
        }
    }
    match (before.history, after.history) {
        (None, None) if before.activation.is_none() && after.activation.is_none() => {}
        (None, Some(_)) if before.activation.is_none() && after.activation.is_some() => {}
        (Some(_), Some(_)) if before.activation == after.activation => {}
        _ => {
            return Err(invalid(
                "native transition changes an unsupported history or authority context",
            ))
        }
    }
    v1::validate_activation_transition(before, after)?;
    if (before.roster_v1_namespace && !after.roster_v1_namespace)
        || before
            .roster_v2_activation
            .as_ref()
            .is_some_and(|activation| after.roster_v2_activation.as_ref() != Some(activation))
    {
        return Err(invalid("native roster activation regressed or changed"));
    }
    lifecycle::transition(before.history, after.history)?;
    Ok(())
}

impl NativeState {
    pub(super) fn clone_for_application(&self) -> io::Result<Self> {
        let proof = self.require_business_proof()?;
        if self
            .changes
            .as_ref()
            .is_some_and(|dirty| !Arc::ptr_eq(&dirty.target, proof))
        {
            return Err(invalid("native application capture journal target differs"));
        }
        // Captures must preserve whether publication writes a journal, but
        // must never copy its historical changed-row container or guards.
        let mut captured = self.clone();
        if self.changes.is_some() {
            captured.begin_changes()?;
        }
        Ok(captured)
    }

    pub(super) fn require_business_proof(&self) -> io::Result<&Arc<BusinessProof>> {
        let proof = self
            .proof
            .as_ref()
            .ok_or_else(|| invalid("native state has no admitted business proof"))?;
        if proof.identity != self.identity
            || proof.members != self.members
            || proof.frontiers != self.frontiers
            || proof.counts()
                != [
                    self.keys.len(),
                    self.receipts.len(),
                    self.generic_receipts.len(),
                    self.notifications.len(),
                ]
            || !Arc::ptr_eq(&proof.roster, self.roster.certificate()?)
            || proof.roster_root != self.roster_root
            || match (&proof.snapshot_origin, &self.snapshot_origin) {
                (None, None) => false,
                (Some(left), Some(right)) => !Arc::ptr_eq(left, right),
                _ => true,
            }
        {
            return Err(invalid(
                "native business proof no longer matches live state",
            ));
        }
        Ok(proof)
    }

    pub(super) fn admit_business(&mut self) -> io::Result<()> {
        self.admit_business_using(|state| state.admit_full_roster(&|| Ok(())))
    }

    /// Consume the prospective selected rows directly into their sole ledger.
    /// The same full business, carrier and aggregate predicates precede proof
    /// construction; the iterator cannot mint a certificate from metadata.
    pub(super) fn admit_selected_roster(
        &mut self,
        rows: impl IntoIterator<Item = io::Result<SharedRow<roster::Row>>>,
        partitions: impl IntoIterator<
            Item = (
                crate::fenced_mutation_roster_storage::ProductionFloorKey,
                roster::Partition,
            ),
        >,
        witness: Option<crate::fenced_mutation_roster_storage::GlobalChargeWitness>,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        self.admit_business_using(|state| state.admit_roster_rows(rows, partitions, witness, check))
    }

    fn admit_business_using(
        &mut self,
        admit: impl FnOnce(&Self) -> io::Result<roster::Ledger>,
    ) -> io::Result<()> {
        if self.changes.is_some() {
            return Err(invalid("native cannot readmit a live dirty state"));
        }
        self.proof = None;
        let receipt_order = self.validate_full_business_rows()?;
        self.roster = admit(self)?;
        let mut tables = [TableSummary::default(); 4];
        let mut expiry = expiry::ExpiryIndex::default();
        for (key, row) in &self.keys {
            tables[0].replace(None, Some(stamp(0, key, row)?))?;
            expiry.replace(key, None, Some(row));
        }
        for (id, row) in &self.receipts {
            tables[1].replace(None, Some(stamp(1, id, row)?))?;
        }
        for (id, row) in &self.generic_receipts {
            tables[2].replace(None, Some(stamp(2, id, row)?))?;
            expiry.replace_request(*id, None, Some(row))?;
        }
        expiry.validate_requests(&self.frontiers)?;
        for row in &self.notifications {
            tables[3].replace(None, Some(notification_stamp(row)?))?;
        }
        let proof = BusinessProof::new(
            self,
            &self.frontiers,
            tables,
            0,
            expiry,
            receipt_order,
            &self.roster,
        )?;
        self.proof = Some(proof);
        self.changes = None;
        Ok(())
    }

    pub(super) fn begin_changes(&mut self) -> io::Result<()> {
        self.changes = Some(self.prepare_tracking()?);
        Ok(())
    }

    pub(super) fn prepare_tracking(&self) -> io::Result<BusinessChanges> {
        if self.changes.is_some() {
            return Err(invalid("native change capture is already active"));
        }
        Ok(BusinessChanges::empty(Arc::clone(
            self.require_business_proof()?,
        )))
    }

    pub(super) fn prepare_transfer(&mut self) -> io::Result<BusinessTransfer<'_>> {
        self.prepare_checkpoint_transfer(None)
    }

    pub(super) fn prepare_checkpoint_transfer(
        &mut self,
        snapshot: Option<&SnapshotSelection>,
    ) -> io::Result<BusinessTransfer<'_>> {
        let proof = Arc::clone(self.require_business_proof()?);
        let selected_snapshot = snapshot
            .map(|snapshot| snapshot.selected_proof(self))
            .transpose()?;
        let dirty = self
            .changes
            .as_mut()
            .ok_or_else(|| invalid("native change capture is not active"))?;
        if !Arc::ptr_eq(&proof, &dirty.target) {
            return Err(invalid("native business transfer target differs"));
        }
        Ok(BusinessTransfer {
            dirty,
            next: BusinessChanges::empty(proof),
            selected_snapshot,
        })
    }

    #[cfg(test)]
    pub(super) fn capture_changes(&mut self) -> io::Result<BusinessChanges> {
        self.changes
            .as_ref()
            .ok_or_else(|| invalid("native change capture is not active"))?
            .validate(self)?;
        let next = BusinessChanges::empty(Arc::clone(self.require_business_proof()?));
        self.changes
            .replace(next)
            .ok_or_else(|| invalid("native change capture disappeared"))
    }

    pub(super) fn publish_snapshot_metadata(
        &mut self,
        current: crate::sqlite::consensus::CurrentSnapshot,
    ) -> io::Result<()> {
        let SnapshotSelection {
            before,
            selected: proof,
        } = self.prepare_snapshot_selection(current)?;
        if self
            .changes
            .as_ref()
            .is_some_and(|dirty| !Arc::ptr_eq(&dirty.target, &before))
        {
            return Err(invalid(
                "native snapshot metadata dirty predecessor differs",
            ));
        }
        if let Some(dirty) = &mut self.changes {
            dirty.target = Arc::clone(&proof);
        }
        self.frontiers = proof.frontiers.clone();
        self.proof = Some(proof);
        Ok(())
    }

    pub(super) fn prepare_snapshot_selection(
        &self,
        current: crate::sqlite::consensus::CurrentSnapshot,
    ) -> io::Result<SnapshotSelection> {
        let before = Arc::clone(self.require_business_proof()?);
        let _scratch = VerificationMemory::reserve(PROOF_MEMORY)?;
        let mut frontiers = self.frontiers.clone();
        frontiers.current_snapshot = Some(current);
        validate_frontier_transition(&self.frontiers, &frontiers, true)?;
        validation::validate_frontiers(
            self.identity,
            &self.members,
            &frontiers,
            before.counts(),
            self.snapshot_origin.as_deref(),
        )?;
        let selected = BusinessProof::new(
            self,
            &frontiers,
            before.tables,
            before
                .revision
                .checked_add(1)
                .ok_or_else(|| invalid("native business revision exhausted"))?,
            before.expiry.clone(),
            before.receipt_order.clone(),
            &self.roster,
        )?;
        Ok(SnapshotSelection { before, selected })
    }

    /// The caller already completed durable CURRENT selection. Rebase only
    /// the dirty journal's small predecessor context; its captured row stamps
    /// and every concurrent after-image remain unchanged. At most one capture
    /// may be outstanding, so an intervening detach must fail this exact Arc
    /// comparison instead of silently losing the new snapshot predecessor.
    pub(crate) fn publish_checkpoint_snapshot(
        &mut self,
        snapshot: SnapshotSelection,
    ) -> io::Result<()> {
        let current = Arc::clone(self.require_business_proof()?);
        let dirty = self
            .changes
            .as_ref()
            .ok_or_else(|| invalid("native selected snapshot journal absent"))?;
        if !Arc::ptr_eq(&dirty.base, &snapshot.before)
            || !Arc::ptr_eq(&dirty.target, &current)
            || self.frontiers.current_snapshot != snapshot.before.frontiers.current_snapshot
            || self.identity != snapshot.before.identity
            || self.members != snapshot.before.members
        {
            return Err(invalid(
                "native selected snapshot journal predecessor changed",
            ));
        }
        let proof = if Arc::ptr_eq(&current, &snapshot.before) {
            Arc::clone(&snapshot.selected)
        } else {
            let _scratch = VerificationMemory::reserve(PROOF_MEMORY)?;
            let mut frontiers = self.frontiers.clone();
            frontiers.current_snapshot = snapshot.selected.frontiers.current_snapshot.clone();
            validate_frontier_transition(&self.frontiers, &frontiers, true)?;
            validation::validate_frontiers(
                self.identity,
                &self.members,
                &frontiers,
                current.counts(),
                self.snapshot_origin.as_deref(),
            )?;
            BusinessProof::new(
                self,
                &frontiers,
                current.tables,
                current
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| invalid("native business revision exhausted"))?,
                current.expiry.clone(),
                current.receipt_order.clone(),
                &self.roster,
            )?
        };
        let dirty = self
            .changes
            .as_mut()
            .ok_or_else(|| invalid("native selected snapshot journal disappeared"))?;
        dirty.base = snapshot.selected;
        dirty.target = Arc::clone(&proof);
        self.frontiers = proof.frontiers.clone();
        self.proof = Some(proof);
        Ok(())
    }
}

#[cfg(test)]
pub(super) mod tests;
