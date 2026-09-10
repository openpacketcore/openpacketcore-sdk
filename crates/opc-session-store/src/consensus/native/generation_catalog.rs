//! Complete selected-prefix reconstruction into resident row indexes.
//!
//! Every encoded row is fully decoded, canonically checked and semantically
//! validated under its own scratch reservation. Only fixed metadata and exact
//! ranges survive. The maps are the prospective resident business/log index,
//! not a second materialized worker image or a verification digest cache. They
//! retain the original row bounds and belong to the original whole-process RSS
//! accounting. Prefix proofs, headers, ordinal work and changed-log scratch use
//! the existing shared VerificationMemory counter, with no per-voter pool.
//!
//! Open validates the selected prefix only. The integrating WAL owner must
//! independently admit strict snapshots and its exact durable cut/owner before
//! repairing a staged tail, selecting CURRENT, evicting rows or exposing reads.

use super::super::resident::RowFingerprint;
use super::*;
use crate::fenced_mutation_roster::RosterAttestationTrustRootV1;
use crate::sqlite::consensus as sql;
use std::collections::BTreeMap;
use std::hash::Hash;
use std::mem::size_of;
use std::ops::Bound::{Excluded, Unbounded};
use std::path::Path;

#[path = "generation_catalog_ordinals.rs"]
mod ordinal_index;
use ordinal_index::Ordinals;

#[path = "generation_roster_catalog.rs"]
mod roster_index;
use roster_index::Rosters;

#[derive(Clone, Copy)]
struct Range {
    offset: u64,
    length: u32,
}

#[derive(Clone, Copy)]
struct Indexed<T> {
    range: Range,
    row: facts::Row<T>,
    checkpoint: u64,
}

#[derive(Clone, Copy, Default)]
struct Summary {
    count: usize,
    content: [u8; 32],
}
impl Summary {
    fn replace(&mut self, before: Option<[u8; 32]>, after: Option<[u8; 32]>) -> io::Result<()> {
        self.count = self
            .count
            .checked_sub(usize::from(before.is_some()))
            .and_then(|count| count.checked_add(usize::from(after.is_some())))
            .ok_or_else(|| invalid("native catalog count overflow"))?;
        for hash in [before, after].into_iter().flatten() {
            for (slot, byte) in self.content.iter_mut().zip(hash) {
                *slot ^= byte;
            }
        }
        Ok(())
    }
}

struct Rows {
    context: Context,
    keys: HashMap<facts::KeyId, Indexed<facts::Key>>,
    receipts: HashMap<FencedTransitionV2RequestId, Indexed<facts::Receipt>>,
    generic: HashMap<SessionConsensusRequestId, Indexed<facts::Request>>,
    v1_count: usize,
    notifications: Vec<Indexed<facts::Notification>>,
    logs: BTreeMap<u64, Indexed<facts::Log>>,
    summary: [Summary; 5],
    rosters: Rosters,
    // This owns the complete retained small context and container objects;
    // each fixed-size resident index allocation is accounted separately below.
    _memory: VerificationMemory,
}

pub(crate) struct Catalog {
    source: Arc<VerifiedPrefix>,
    rows: Rows,
    cut_binding: [u8; 32],
    roster_root: Option<Arc<RosterAttestationTrustRootV1>>,
    snapshot_origin: Option<Arc<NativeSnapshotAuthority>>,
}

impl Catalog {
    pub(crate) fn open(
        path: &Path,
        expected: PrefixIdentity,
        maximum: u64,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        roster_root: Option<Arc<RosterAttestationTrustRootV1>>,
        cut_binding: [u8; 32],
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<(VerifiedAppendOwner, Self)> {
        Self::open_with_origin(
            path,
            expected,
            maximum,
            identity,
            members,
            roster_root,
            None,
            cut_binding,
            check,
        )
    }

    pub(crate) fn open_with_origin(
        path: &Path,
        expected: PrefixIdentity,
        maximum: u64,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        roster_root: Option<Arc<RosterAttestationTrustRootV1>>,
        snapshot_origin: Option<Arc<NativeSnapshotAuthority>>,
        cut_binding: [u8; 32],
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<(VerifiedAppendOwner, Self)> {
        if let Some(origin) = &snapshot_origin {
            origin.require_scope(expected.binding, identity, members, roster_root.as_deref())?;
            origin.verify()?;
        }
        let mut decoded = None;
        let owner = VerifiedAppendOwner::open(path, expected, maximum, check, |reader| {
            decoded = Some(Rows::read(
                reader,
                expected,
                identity,
                members,
                roster_root.as_deref(),
                snapshot_origin.as_deref(),
                cut_binding,
                check,
            )?);
            Ok(())
        })?;
        // No catalog is published if the descriptor/extent recheck following
        // the complete reader fails. The captured comparison data then drops.
        let rows = decoded.ok_or_else(|| invalid("native catalog reconstruction absent"))?;
        if let Some(origin) = &snapshot_origin {
            origin.verify()?;
        }
        let catalog = Self {
            source: owner.current(),
            rows,
            cut_binding,
            roster_root,
            snapshot_origin,
        };
        catalog.resident_index_allocation_bound()?;
        Ok((owner, catalog))
    }

    pub(crate) fn identity(&self) -> PrefixIdentity {
        self.source.identity()
    }

    pub(crate) fn cut_binding(&self) -> [u8; 32] {
        self.cut_binding
    }

    /// Consume the prospective indexes into the one resident owner. Each
    /// source row is removed before its replacement is inserted. Hash bucket
    /// capacity can overlap during conversion and remains part of measured
    /// whole-process RSS; no second decoded historical model is constructed.
    pub(crate) fn into_storage(
        self,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<NativeStorage> {
        check()?;
        let Self {
            source,
            rows,
            cut_binding: _,
            roster_root,
            snapshot_origin,
        } = self;
        if let Some(origin) = &snapshot_origin {
            origin.verify()?;
        }
        let Rows {
            context,
            keys,
            receipts,
            generic,
            v1_count: _,
            notifications,
            logs,
            summary: _,
            rosters,
            _memory: context_memory,
        } = rows;
        let memory = VerificationMemory::reserve(128 * 1024)?;
        let expected = context.digest()?;
        if expected != source.identity().frontiers {
            return Err(invalid(
                "native resident catalog context differs from selected prefix",
            ));
        }
        let mut storage = NativeStorage {
            business: NativeState {
                identity: context.business.identity,
                members: context.business.members.clone(),
                frontiers: context.business.frontiers.clone(),
                keys: ResidentMap::new(),
                receipts: ResidentMap::new(),
                generic_receipts: ResidentMap::new(),
                notifications: ResidentVector::new(),
                roster: roster::Ledger::empty(),
                roster_root: roster_root.clone(),
                snapshot_origin,
                local_restore: None,
                proof: None,
                changes: None,
            },
            log: log::NativeLog::default(),
        };
        for (id, indexed) in keys {
            check()?;
            let range = resident::SelectedRange::new(
                Arc::clone(&source),
                indexed.range.offset,
                indexed.range.length,
                MAX_ITEM,
            )?;
            let input = range.read(check)?;
            let owned = decode::owned_key(
                input.bytes(),
                id,
                indexed.row,
                &storage.business.frontiers,
                check,
            )?;
            let (key, row) = owned.into_resident();
            if storage
                .business
                .keys
                .insert(key, SharedRow::new(row))
                .is_some()
            {
                return Err(invalid(
                    "native resident key conversion repeats an identity",
                ));
            }
        }
        for (id, indexed) in receipts {
            check()?;
            let row = NativeReceipt::from_admitted_range(
                id,
                indexed.row,
                Arc::clone(&source),
                indexed.range.offset,
                indexed.range.length,
            )?;
            if storage
                .business
                .receipts
                .insert(id, SharedRow::new(row))
                .is_some()
            {
                return Err(invalid(
                    "native resident receipt conversion repeats an identity",
                ));
            }
        }
        for (id, indexed) in generic {
            check()?;
            let range = resident::SelectedRange::new(
                Arc::clone(&source),
                indexed.range.offset,
                indexed.range.length,
                MAX_ITEM,
            )?;
            let input = range.read(check)?;
            let row = decode::owned_generic(
                input.bytes(),
                id,
                indexed.row,
                &storage.business.frontiers,
                check,
            )?;
            if storage
                .business
                .generic_receipts
                .insert(id, SharedRow::new(row))
                .is_some()
            {
                return Err(invalid(
                    "native resident clock conversion repeats an identity",
                ));
            }
        }
        for indexed in notifications {
            check()?;
            let row = NativeNotification::from_admitted_range(
                indexed.row,
                Arc::clone(&source),
                indexed.range.offset,
                indexed.range.length,
            )?;
            storage
                .business
                .notifications
                .push_back(SharedRow::new(row));
        }
        for (index, indexed) in logs {
            check()?;
            let row = log::NativeLogEntry::from_admitted_range(
                indexed.row,
                Arc::clone(&source),
                indexed.range.offset,
                indexed.range.length,
                storage.business.identity,
                &storage.business.members,
            )?;
            if row.id().index != index
                || storage
                    .log
                    .entries
                    .insert(index, SharedRow::new(row))
                    .is_some()
            {
                return Err(invalid("native resident log conversion differs"));
            }
        }
        storage.log.vote = context.log.vote;
        storage.log.committed = context.log.committed;
        storage.log.purged = context.log.purged;
        // These process proofs are reconstructed from complete native
        // predicates and actual owned rows. Serialized summaries cannot mint
        // them. Compare all resulting table/frontier equations to the catalog.
        let (roster_rows, partitions) = rosters.into_parts();
        let scope = roster::fixed_scope(storage.business.identity, &storage.business.members);
        let roster_rows = roster_rows.into_iter().map(|(binding, indexed)| {
            check()?;
            let root = roster_root
                .as_deref()
                .ok_or_else(|| invalid("native resident roster configured root absent"))?;
            let row = roster::Row::from_selected_range(
                Arc::clone(&source),
                indexed.range.offset,
                indexed.range.length,
                root,
                &scope,
                check,
            )?;
            if row.binding() != binding
                || row.facts() != indexed.row.facts
                || row.row_fingerprint(4, &binding)? != indexed.row.content
            {
                return Err(invalid(
                    "native resident roster differs from its authenticated catalog",
                ));
            }
            Ok(SharedRow::new(row))
        });
        storage.business.admit_selected_roster(
            roster_rows,
            partitions,
            context
                .business
                .roster
                .as_ref()
                .and_then(|roster| roster.witness),
            check,
        )?;
        storage.log.admit(&storage.business)?;
        if Version::capture(&storage)?.context().digest()? != expected {
            return Err(invalid(
                "native resident conversion differs from complete catalog",
            ));
        }
        if let Some(origin) = &storage.business.snapshot_origin {
            origin.verify()?;
        }
        drop(context);
        drop(context_memory);
        drop(memory);
        check()?;
        Ok(storage)
    }

    /// Conservative container-capacity accounting for the actual resident
    /// catalog, including unused hash buckets and BTree node overhead. This is
    /// not an extra memory allowance or evidence that process RSS has passed.
    /// The original qualification must still measure all three voters, their
    /// resident suffixes, snapshots, codecs and every other process allocation.
    pub(crate) fn resident_index_allocation_bound(&self) -> io::Result<usize> {
        fn hash<K, V>(map: &HashMap<K, V>) -> Option<usize> {
            map.capacity()
                .checked_mul(2)?
                .checked_add(16)?
                .checked_mul(size_of::<(K, V)>() + 1)
        }
        let bytes = hash(&self.rows.keys)
            .and_then(|bytes| bytes.checked_add(hash(&self.rows.receipts)?))
            .and_then(|bytes| bytes.checked_add(hash(&self.rows.generic)?))
            .and_then(|bytes| {
                bytes.checked_add(
                    self.rows
                        .notifications
                        .capacity()
                        .checked_mul(size_of::<Indexed<facts::Notification>>())?,
                )
            })
            .and_then(|bytes| {
                bytes.checked_add(
                    self.rows
                        .logs
                        .len()
                        .checked_add(1)?
                        .checked_mul(8 * (size_of::<(u64, Indexed<facts::Log>)>() + 32))?,
                )
            })
            .and_then(|bytes| bytes.checked_add(self.rows.rosters.allocation_bound().ok()?))
            .and_then(|bytes| bytes.checked_add(size_of::<Self>()));
        bytes.ok_or_else(|| invalid("native catalog resident allocation accounting overflow"))
    }
}

pub(super) fn validate_context_header(
    context: &Context,
    binding: [u8; 32],
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
) -> io::Result<()> {
    validate_context_header_with_origin(context, binding, identity, members, None, None)
}

pub(super) fn validate_context_header_with_origin(
    context: &Context,
    binding: [u8; 32],
    identity: SessionConsensusIdentity,
    members: &BTreeSet<SessionConsensusNodeId>,
    root: Option<&RosterAttestationTrustRootV1>,
    origin: Option<&NativeSnapshotAuthority>,
) -> io::Result<()> {
    if context.business.identity != identity
        || &context.business.members != members
        || context.business.counts[1]
            > crate::fenced_transition::FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES
        || context.log.count > log::MAX_RETAINED_LOG_ENTRIES
    {
        return Err(invalid("native generation identity or row count differs"));
    }
    validation::validate_frontiers(
        identity,
        members,
        &context.business.frontiers,
        context.business.counts,
        origin,
    )?;
    if let Some(origin) = origin {
        origin.require_scope(binding, identity, members, root)?;
    }
    image::validate_snapshot_root_with_origin(
        context.business.frontiers.current_snapshot.as_ref(),
        binding,
        origin,
    )
}

struct Cursor<'a> {
    reader: &'a mut dyn Read,
    position: u64,
    maximum: u64,
    hash: Sha256,
}
impl Read for Cursor<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = usize::try_from(self.maximum - self.position)
            .unwrap_or(usize::MAX)
            .min(output.len());
        let count = self.reader.read(&mut output[..count])?;
        self.position = self
            .position
            .checked_add(count as u64)
            .ok_or_else(|| invalid("native catalog input extent overflow"))?;
        self.hash.update(&output[..count]);
        Ok(count)
    }
}
impl Cursor<'_> {
    fn bytes(&mut self, maximum: usize) -> io::Result<(Range, Input)> {
        let offset = self
            .position
            .checked_add(4)
            .ok_or_else(|| invalid("native catalog row offset overflow"))?;
        let input = read_bytes(self, maximum)?;
        let range = Range {
            offset,
            length: input.bytes().len() as u32,
        };
        if offset.checked_add(u64::from(range.length)) != Some(self.position) {
            return Err(invalid("native catalog row extent differs"));
        }
        Ok((range, input))
    }

    fn scalar<const N: usize>(&mut self) -> io::Result<[u8; N]> {
        let mut bytes = [0; N];
        self.read_exact(&mut bytes)?;
        Ok(bytes)
    }

    fn present(&mut self) -> io::Result<bool> {
        match self.scalar::<1>()?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid("native catalog presence marker invalid")),
        }
    }

    fn before(&mut self) -> io::Result<Option<[u8; 32]>> {
        if self.present()? {
            Ok(Some(self.scalar()?))
        } else {
            Ok(None)
        }
    }

    fn boundary(&mut self, block: usize, check: &impl Fn() -> io::Result<()>) -> io::Result<()> {
        expect(self, END)?;
        let mut remaining = (block as u64 - self.position % block as u64) % block as u64;
        let mut bytes = [0; 4096];
        while remaining != 0 {
            check()?;
            let count = remaining.min(bytes.len() as u64) as usize;
            self.read_exact(&mut bytes[..count])?;
            if bytes[..count].iter().any(|byte| *byte != 0) {
                return Err(invalid("native generation padding is not zero"));
            }
            remaining -= count as u64;
        }
        check()
    }

    fn identity(
        &self,
        base: &BaseHeader,
        checkpoint: u64,
        sequence: u64,
        context: &Context,
    ) -> io::Result<PrefixIdentity> {
        Ok(PrefixIdentity {
            binding: base.binding,
            file_epoch: base.file_epoch,
            checkpoint_epoch: checkpoint,
            operation_sequence: sequence,
            frontiers: context.digest()?,
            length: self.position,
            block_bytes: base.block_bytes,
            digest: self.hash.clone().finalize().into(),
        })
    }
}

struct ChangedLogs {
    indexes: Vec<u64>,
    _memory: VerificationMemory,
}
impl ChangedLogs {
    fn new(count: usize) -> io::Result<Self> {
        let memory = VerificationMemory::reserve(
            count
                .checked_mul(size_of::<u64>())
                .ok_or_else(|| invalid("native changed log reservation overflow"))?,
        )?;
        let mut indexes = Vec::new();
        indexes
            .try_reserve_exact(count)
            .map_err(|_| invalid("native changed log index allocation failed"))?;
        Ok(Self {
            indexes,
            _memory: memory,
        })
    }
}

fn put<K: Eq + Hash, V>(
    map: &mut HashMap<K, V>,
    key: K,
    value: V,
    maximum: usize,
) -> io::Result<()> {
    if !map.contains_key(&key) {
        if map.len() >= maximum {
            return Err(invalid(
                "native resident catalog exceeds original row bound",
            ));
        }
        // Grow only for an actual fully checked row, never a header's count.
        map.try_reserve(1)
            .map_err(|_| invalid("native resident catalog allocation failed"))?;
    }
    map.insert(key, value);
    Ok(())
}

fn predecessor<T>(
    row: Option<&Indexed<T>>,
    before: Option<[u8; 32]>,
    checkpoint: u64,
    base: bool,
) -> io::Result<()> {
    if row.map(|row| row.row.content) != before
        || row.is_some_and(|row| row.checkpoint == checkpoint)
        || (base && before.is_some())
    {
        return Err(invalid(
            "native catalog row has a duplicate or different predecessor",
        ));
    }
    Ok(())
}

impl Rows {
    fn read(
        reader: &mut dyn Read,
        expected: PrefixIdentity,
        identity: SessionConsensusIdentity,
        members: &BTreeSet<SessionConsensusNodeId>,
        root: Option<&RosterAttestationTrustRootV1>,
        origin: Option<&NativeSnapshotAuthority>,
        cut_binding: [u8; 32],
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<Self> {
        check()?;
        let memory =
            VerificationMemory::reserve(64 * 1024 + size_of::<Self>() + size_of::<Catalog>())?;
        let mut reader = Cursor {
            reader,
            position: 0,
            maximum: expected.length,
            hash: Sha256::new(),
        };
        let mut format = Format::read(&mut reader, true)?;
        let loaded = header::base(&mut reader)?;
        let base = &loaded.value;
        BaseRestore::require_origin(base.native_restore.as_ref(), origin, format)?;
        format.validate_context(&base.context)?;
        roster_index::validate_context(&base.context, root)?;
        if base.binding != expected.binding
            || base.file_epoch != expected.file_epoch
            || base.block_bytes != expected.block_bytes
            || base.checkpoint_epoch > expected.checkpoint_epoch
            || base.operation_sequence > expected.operation_sequence
        {
            return Err(invalid(
                "native generation base differs from selected identity",
            ));
        }
        validate_context_header_with_origin(
            &base.context,
            expected.binding,
            identity,
            members,
            root,
            origin,
        )?;
        // The retained context has its own reservation before this clone. All
        // temporary before/after headers keep their Loaded guard until dropped.
        let mut rows = Self {
            context: base.context.clone(),
            keys: HashMap::new(),
            receipts: HashMap::new(),
            generic: HashMap::new(),
            v1_count: 0,
            notifications: Vec::new(),
            logs: BTreeMap::new(),
            summary: [Summary::default(); 5],
            rosters: Rosters::new(),
            _memory: memory,
        };
        let mut ordinals = Ordinals::new()?;
        let counts = [
            base.context.business.counts[0],
            base.context.business.counts[1],
            base.context.business.counts[2],
            base.context.business.counts[3],
            base.context.log.count,
        ];
        rows.read_rows(
            &mut reader,
            &base.context,
            base.checkpoint_epoch,
            counts,
            true,
            format,
            &mut ordinals,
            check,
        )?;
        if format == Format::V4 {
            rows.rosters.read(
                &mut reader,
                &base.context,
                &base.context,
                base.context
                    .business
                    .roster
                    .as_ref()
                    .map_or([0; 2], |roster| roster.counts),
                true,
                &rows.keys,
                root,
                check,
            )?;
        } else {
            rows.rosters.validate(&base.context)?;
        }
        rows.validate_index(&base.context, expected.binding, origin)?;
        rows.validate_log_order(check)?;
        reader.boundary(base.block_bytes, check)?;
        let mut previous = reader.identity(
            base,
            base.checkpoint_epoch,
            base.operation_sequence,
            &rows.context,
        )?;
        let mut actual_cut = base.cut_binding;
        while reader.position < expected.length {
            check()?;
            let next_format = Format::read(&mut reader, false)?;
            if next_format < format {
                return Err(invalid("native generation format regressed"));
            }
            format = next_format;
            let delta = header::delta(&mut reader)?;
            let delta = &delta.value;
            format.validate_context(&delta.before)?;
            format.validate_context(&delta.after)?;
            roster_index::validate_context(&delta.before, root)?;
            roster_index::validate_context(&delta.after, root)?;
            if delta.roster_changed.is_some() != (format == Format::V4) {
                return Err(invalid(
                    "native generation roster frame counts differ from its format",
                ));
            }
            if delta.previous != Previous::from(previous)
                || delta.before != rows.context
                || previous.checkpoint_epoch.checked_add(1) != Some(delta.checkpoint_epoch)
                || delta.checkpoint_epoch > expected.checkpoint_epoch
                || delta.checkpoint_epoch == u64::MAX
                || delta.operation_sequence < previous.operation_sequence
                || delta.operation_sequence > expected.operation_sequence
            {
                return Err(invalid("native generation checkpoint predecessor differs"));
            }
            validate_context_header_with_origin(
                &delta.after,
                expected.binding,
                identity,
                members,
                root,
                origin,
            )?;
            changes::validate_frontier_transition(
                &delta.before.business.frontiers,
                &delta.after.business.frontiers,
                true,
            )?;
            validate_log_transition(&delta.before, &delta.after)?;
            roster_index::transition(&delta.before, &delta.after)?;
            ordinals.validate_retirement(
                delta.before.business.frontiers.history,
                delta.after.business.frontiers.history,
                delta.after.business.frontiers.logical_time,
            )?;
            rows.read_rows(
                &mut reader,
                &delta.after,
                delta.checkpoint_epoch,
                delta.changed,
                false,
                format,
                &mut ordinals,
                check,
            )?;
            if let Some(changed) = delta.roster_changed {
                rows.rosters.read(
                    &mut reader,
                    &delta.before,
                    &delta.after,
                    changed,
                    false,
                    &rows.keys,
                    root,
                    check,
                )?;
            } else {
                rows.rosters.validate(&delta.after)?;
            }
            rows.validate_index(&delta.after, expected.binding, origin)?;
            rows.context = delta.after.clone();
            reader.boundary(base.block_bytes, check)?;
            previous = reader.identity(
                base,
                delta.checkpoint_epoch,
                delta.operation_sequence,
                &rows.context,
            )?;
            actual_cut = delta.cut_binding;
        }
        if previous != expected || actual_cut != cut_binding {
            return Err(invalid(
                "native generation selected final extent or cut differs",
            ));
        }
        rows.validate_final_metadata(check)?;
        check()?;
        Ok(rows)
    }

    fn read_rows(
        &mut self,
        reader: &mut Cursor<'_>,
        after: &Context,
        checkpoint: u64,
        counts: [usize; 5],
        base: bool,
        format: Format,
        ordinals: &mut Ordinals,
        check: &impl Fn() -> io::Result<()>,
    ) -> io::Result<()> {
        if counts
            .into_iter()
            .any(|count| count > validation::MAX_ITEMS)
        {
            return Err(invalid(
                "native generation changed count exceeds original bound",
            ));
        }
        // A transient receipt is tag + absent-before + 56-byte ID +
        // absent-after. It has no four-byte body length: exactly 59 bytes.
        let minimum = counts
            .into_iter()
            .zip([6u64, 59, 6, 5, 11])
            .try_fold(8u64, |total, (count, width)| {
                total.checked_add((count as u64).checked_mul(width)?)
            })
            .ok_or_else(|| invalid("native generation declared extent overflow"))?;
        if minimum > reader.maximum - reader.position {
            return Err(invalid("native generation counts exceed selected extent"));
        }
        let frontiers = &after.business.frontiers;
        for _ in 0..counts[0] {
            check()?;
            expect(reader, &[0])?;
            let before = reader.before()?;
            let (range, input) = reader.bytes(MAX_ITEM)?;
            let (key, row) = decode::inspect_key_format(input.bytes(), format, frontiers, check)?;
            predecessor(self.keys.get(&key), before, checkpoint, base)?;
            // A native key retains its fence floor after deletion. Physical
            // key/receipt removal requires the future explicit lifecycle codec.
            let row = row.ok_or_else(|| {
                invalid("native generation key removal lacks its lifecycle codec")
            })?;
            if self
                .keys
                .get(&key)
                .is_some_and(|old| row.facts.fence < old.row.facts.fence)
            {
                return Err(invalid("native catalog key floor regressed"));
            }
            self.summary[0].replace(before, Some(row.content))?;
            self.rosters.key_replaced(
                key,
                self.keys.get(&key).map(|old| &old.row.facts),
                &row.facts,
            )?;
            put(
                &mut self.keys,
                key,
                Indexed {
                    range,
                    row,
                    checkpoint,
                },
                validation::MAX_ITEMS,
            )?;
        }
        let changed_count = if base { 0 } else { counts[1] };
        let _changed_receipt_memory = VerificationMemory::reserve(
            changed_count
                .checked_mul(size_of::<FencedTransitionV2RequestId>())
                .ok_or_else(|| invalid("native changed receipt reservation overflow"))?,
        )?;
        let mut changed_receipts = Vec::new();
        changed_receipts
            .try_reserve_exact(changed_count)
            .map_err(|_| invalid("native changed receipt allocation failed"))?;
        let (mut added, mut removed, mut transient) = (0usize, 0usize, 0usize);
        let mut retained_started = false;
        for _ in 0..counts[1] {
            check()?;
            expect(reader, &[1])?;
            let before = reader.before()?;
            let id = cold::receipt_id(reader.scalar()?)?;
            if !base {
                changed_receipts.push(id);
            }
            predecessor(self.receipts.get(&id), before, checkpoint, base)?;
            if !reader.present()? {
                if base || retained_started {
                    return Err(invalid(
                        "native receipt removals must precede retained after-images",
                    ));
                }
                let old = self.receipts.get(&id);
                lifecycle::removed_is_retired(
                    id,
                    old.map(|row| row.row.facts.ordinal),
                    frontiers.history,
                )?;
                if let Some(old) = old {
                    ordinals.remove(
                        id.epoch().get(),
                        old.row.facts.ordinal,
                        old.row.facts.retained_until,
                    )?;
                    removed += 1;
                } else {
                    if self
                        .context
                        .business
                        .frontiers
                        .history
                        .and_then(|history| history.active_epoch())
                        .is_some_and(|active| id.epoch() < active)
                    {
                        return Err(invalid("native transient catalog receipt predates its predecessor active epoch"));
                    }
                    transient += 1;
                }
                self.summary[1].replace(before, None)?;
                self.receipts.remove(&id);
                continue;
            }
            retained_started = true;
            let (range, input) = reader.bytes(cold::MAX_BYTES)?;
            let row = cold::inspect_generation_bytes(
                input.bytes(),
                id,
                after.business.identity,
                frontiers,
                check,
            )?;
            if let Some(old) = self.receipts.get(&id) {
                if row.facts.ordinal != old.row.facts.ordinal
                    || row.facts.retained_until != old.row.facts.retained_until
                    || (row.content != old.row.content
                        && !(old.row.facts.response.is_some() && row.facts.response.is_none()))
                {
                    return Err(invalid(
                        "native catalog receipt changes its immutable binding",
                    ));
                }
            } else {
                if !base
                    && self
                        .context
                        .business
                        .frontiers
                        .history
                        .and_then(|history| history.active_epoch())
                        .is_some_and(|active| id.epoch() < active)
                {
                    return Err(invalid(
                        "native catalog new receipt predates its predecessor active epoch",
                    ));
                }
                ordinals.insert(
                    id.epoch().get(),
                    row.facts.ordinal,
                    row.facts.retained_until,
                )?;
                added += 1;
            }
            self.summary[1].replace(before, Some(row.content))?;
            put(
                &mut self.receipts,
                id,
                Indexed {
                    range,
                    row,
                    checkpoint,
                },
                crate::fenced_transition::FENCED_TRANSITION_V2_MAX_RETAINED_HISTORY_ENTRIES,
            )?;
        }
        changed_receipts.sort_unstable_by_key(|id| id.to_bytes());
        if changed_receipts.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid("native generation repeats a changed receipt ID"));
        }
        if !base {
            lifecycle::conservation(
                self.context.business.frontiers.history,
                frontiers.history,
                added,
                removed,
                transient,
            )?;
        }
        ordinals.validate(frontiers.history)?;
        for _ in 0..counts[2] {
            check()?;
            expect(reader, &[2])?;
            let before = reader.before()?;
            let (range, input) = reader.bytes(MAX_ITEM)?;
            let (id, row) =
                decode::inspect_generic_format(input.bytes(), format, frontiers, check)?;
            predecessor(self.generic.get(&id), before, checkpoint, base)?;
            let row = row.ok_or_else(|| {
                invalid("native generation generic removal lacks its lifecycle codec")
            })?;
            if let Some(before) = self.generic.get(&id) {
                row.facts
                    .validate_replacement(before.row.facts, before.row.content != row.content)?;
            } else if row.facts.retained_until.is_some() {
                self.v1_count += 1;
                if self.v1_count > crate::fenced_transition::FENCED_TRANSITION_MAX_HISTORY_ENTRIES {
                    return Err(invalid(
                        "native catalog V1 count exceeds original lifetime bound",
                    ));
                }
            }
            self.summary[2].replace(before, Some(row.content))?;
            put(
                &mut self.generic,
                id,
                Indexed {
                    range,
                    row,
                    checkpoint,
                },
                validation::MAX_ITEMS,
            )?;
        }
        for _ in 0..counts[3] {
            check()?;
            expect(reader, &[3])?;
            if self.notifications.len() >= validation::MAX_ITEMS {
                return Err(invalid("native catalog watch count exceeds original bound"));
            }
            let (range, input) = reader.bytes(MAX_ITEM)?;
            let sequence = self.notifications.len() as u64 + 1;
            let row = decode::inspect_notification(input.bytes(), sequence, frontiers, check)?;
            self.summary[3].replace(None, Some(row.content))?;
            self.notifications
                .try_reserve(1)
                .map_err(|_| invalid("native resident watch catalog allocation failed"))?;
            self.notifications.push(Indexed {
                range,
                row,
                checkpoint,
            });
        }
        let mut changed = ChangedLogs::new(if base { 0 } else { counts[4] })?;
        for _ in 0..counts[4] {
            check()?;
            expect(reader, &[4])?;
            let index = u64::from_le_bytes(reader.scalar()?);
            if index > COUNTER_MAX {
                return Err(invalid("native generation log index exceeds model bound"));
            }
            let before = reader.before()?;
            predecessor(self.logs.get(&index), before, checkpoint, base)?;
            let present = reader.present()?;
            if base && !present {
                return Err(invalid("native generation base contains a log tombstone"));
            }
            let after = if present {
                let (range, input) = reader.bytes(sql::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES)?;
                let row = decode::inspect_log(
                    input.bytes(),
                    index,
                    after.business.identity,
                    &after.business.members,
                    check,
                )?;
                Some(Indexed {
                    range,
                    row,
                    checkpoint,
                })
            } else {
                None
            };
            if !base
                && before != after.as_ref().map(|row| row.row.content)
                && [
                    self.context.log.committed,
                    self.context.log.purged,
                    self.context.business.frontiers.applied,
                ]
                .into_iter()
                .flatten()
                .any(|protected| index <= protected.index)
            {
                return Err(invalid("native generation changes protected log history"));
            }
            self.summary[4].replace(before, after.as_ref().map(|row| row.row.content))?;
            if let Some(row) = after {
                if !self.logs.contains_key(&index)
                    && self.logs.len() >= log::MAX_RETAINED_LOG_ENTRIES
                {
                    return Err(invalid(
                        "native resident log catalog exceeds original row bound",
                    ));
                }
                self.logs.insert(index, row);
            } else {
                self.logs.remove(&index);
            }
            if !base {
                changed.indexes.push(index);
            }
        }
        changed.indexes.sort_unstable();
        if changed.indexes.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(invalid("native generation repeats a changed log index"));
        }
        for index in changed.indexes.iter().copied() {
            check()?;
            self.validate_neighbors(index)?;
        }
        check()
    }

    fn validate_index(
        &self,
        context: &Context,
        binding: [u8; 32],
        origin: Option<&NativeSnapshotAuthority>,
    ) -> io::Result<()> {
        let lengths = [
            self.keys.len(),
            self.receipts.len(),
            self.generic.len(),
            self.notifications.len(),
            self.logs.len(),
        ];
        let declared = [
            context.business.counts[0],
            context.business.counts[1],
            context.business.counts[2],
            context.business.counts[3],
            context.log.count,
        ];
        let content = [
            context.business.content[0],
            context.business.content[1],
            context.business.content[2],
            context.business.content[3],
            context.log.content,
        ];
        for table in 0..5 {
            if lengths[table] != declared[table]
                || self.summary[table].count != lengths[table]
                || self.summary[table].content != content[table]
            {
                return Err(invalid("native catalog recomputed table summary differs"));
            }
        }
        let first = self.logs.first_key_value().map(|(_, row)| row.row.facts.id);
        let last = self.logs.last_key_value().map(|(_, row)| row.row.facts.id);
        if first != context.log.first || last != context.log.last {
            return Err(invalid("native catalog retained log boundaries differ"));
        }
        if let (Some(first), Some(last)) = (first, last) {
            if last
                .index
                .checked_sub(first.index)
                .and_then(|length| length.checked_add(1))
                != Some(self.logs.len() as u64)
                || (first.index != 0
                    && context
                        .log
                        .purged
                        .is_none_or(|floor| floor.index.checked_add(1) != Some(first.index)))
            {
                return Err(invalid(
                    "native catalog retained log has a hole or missing prefix",
                ));
            }
        }
        let frontiers = &context.business.frontiers;
        let membership = facts::membership(frontiers.membership.membership())?;
        log::validate_context_metadata(
            &log::LogFrontiers {
                vote: context.log.vote,
                committed: context.log.committed,
                purged: context.log.purged,
            },
            &context.business.members,
            frontiers,
            origin,
            |index| self.logs.get(&index).map(|row| row.row.facts.id),
            |index| {
                self.logs
                    .get(&index)
                    .is_some_and(|row| row.row.facts.membership == Some(membership))
            },
        )?;
        image::validate_snapshot_root_with_origin(
            frontiers.current_snapshot.as_ref(),
            binding,
            origin,
        )?;
        Ok(())
    }

    fn validate_neighbors(&self, index: u64) -> io::Result<()> {
        let previous = self
            .logs
            .range(..index)
            .next_back()
            .map(|(_, row)| row.row.facts.id);
        let current = self.logs.get(&index).map(|row| row.row.facts.id);
        let next = self
            .logs
            .range((Excluded(index), Unbounded))
            .next()
            .map(|(_, row)| row.row.facts.id);
        for (left, right) in [(previous, current.or(next)), (current, next)] {
            if let (Some(left), Some(right)) = (left, right) {
                sql::ensure_log_id_not_after(
                    &left,
                    &right,
                    "native catalog retained log term regressed",
                )?;
            }
        }
        Ok(())
    }

    fn validate_log_order(&self, check: &impl Fn() -> io::Result<()>) -> io::Result<()> {
        let mut previous = None;
        for row in self.logs.values() {
            check()?;
            if let Some(previous) = previous {
                sql::ensure_log_id_not_after(
                    &previous,
                    &row.row.facts.id,
                    "native catalog retained log term regressed",
                )?;
            }
            previous = Some(row.row.facts.id);
        }
        Ok(())
    }

    fn validate_final_metadata(&self, check: &impl Fn() -> io::Result<()>) -> io::Result<()> {
        let frontiers = &self.context.business.frontiers;
        for row in self.keys.values() {
            check()?;
            if row.row.facts.fence >= frontiers.next_fence
                || row
                    .row
                    .facts
                    .credential
                    .is_some_and(|credential| credential >= frontiers.next_credential)
            {
                return Err(invalid(
                    "native catalog key exceeds final allocator frontiers",
                ));
            }
        }
        for (id, row) in &self.receipts {
            check()?;
            let history = frontiers
                .history
                .ok_or_else(|| invalid("native catalog final receipt history absent"))?;
            lifecycle::validate_ordinal(history, *id, row.row.facts.ordinal)?;
            if let Some(response) = row.row.facts.response {
                response.validate(frontiers)?;
            } else if frontiers
                .logical_time
                .is_none_or(|now| row.row.facts.retained_until > now)
            {
                return Err(invalid(
                    "native catalog receipt expired before final logical time",
                ));
            }
        }
        for row in self.generic.values() {
            check()?;
            row.row.facts.validate(frontiers)?;
        }
        for row in &self.notifications {
            check()?;
            if frontiers
                .logical_time
                .is_none_or(|now| row.row.facts.timestamp > now)
            {
                return Err(invalid("native catalog notification exceeds final time"));
            }
        }
        self.validate_log_order(check)
    }
}

fn validate_log_transition(before: &Context, after: &Context) -> io::Result<()> {
    for (old, new) in [
        (before.log.committed, after.log.committed),
        (before.log.purged, after.log.purged),
    ] {
        if let Some(old) = old {
            sql::ensure_log_id_not_after(
                &old,
                &new.ok_or_else(|| invalid("native generation clears a protected log frontier"))?,
                "native generation log frontier regressed",
            )?;
        }
    }
    if let Some(vote) = before.log.vote {
        if after.log.vote.is_none_or(|next| {
            next != vote && next.partial_cmp(&vote) != Some(std::cmp::Ordering::Greater)
        }) {
            return Err(invalid("native generation vote regressed"));
        }
    }
    if after.log.purged != before.log.purged {
        let purged = after
            .log
            .purged
            .ok_or_else(|| invalid("native generation purged frontier cleared"))?;
        let selected_applied = before.business.frontiers.applied.ok_or_else(|| {
            invalid("native generation purge lacks its selected applied predecessor")
        })?;
        sql::ensure_log_id_not_after(
            &purged,
            &selected_applied,
            "native generation purge exceeds selected applied predecessor",
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "generation_catalog_tests.rs"]
mod tests;
