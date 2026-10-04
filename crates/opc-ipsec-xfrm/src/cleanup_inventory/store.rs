use zeroize::Zeroizing;

use super::{
    codec::{encode_record, image_locator_bytes, Encoder},
    index::{Location, LocatorIndex, LocatorKind},
    node::{
        ciphertext_digest, decode_header, open_node, seal_node, InventoryKey, NodeContext, NodeKind,
    },
    tree::{
        children_counts, decode_children, decode_leaf, decode_root, encode_children, encode_leaf,
        encode_root, ChildReference, Counts, FormatBudget, InventoryLimits, LeafPage, RootPage,
        FANOUT, LEAF_SLOTS,
    },
    InventoryError, InventoryRecord, RecordLink, TransactionFamily,
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub(super) enum NodeName {
    Root,
    Branch(u32, u8),
    Leaf(u32, u8),
    Temporary,
}

// Implementations retain the same permanent lease for their whole lifetime.
// Reading returns a pinned identity used to stabilize the exact accepted root.
pub(super) trait SnapshotIo {
    type Handle;
    fn check_binding(&self) -> Result<(), InventoryError>;
    fn account(&self, limits: InventoryLimits, format: FormatBudget) -> Result<(), InventoryError>;
    fn read(
        &self,
        name: NodeName,
        maximum: usize,
    ) -> Result<(Self::Handle, Vec<u8>), InventoryError>;
    fn stabilize_root(
        &mut self,
        handle: &Self::Handle,
        digest: [u8; 32],
    ) -> Result<(), InventoryError>;
    fn write_temporary(&mut self, bytes: &[u8]) -> Result<(), InventoryError>;
    fn sync_temporary(&mut self) -> Result<(), InventoryError>;
    fn rename_temporary(&mut self, destination: NodeName) -> Result<(), InventoryError>;
    fn sync_directory(&mut self) -> Result<(), InventoryError>;
    fn remove_temporary(&mut self) -> Result<(), InventoryError>;
}

pub(super) struct Change {
    pub(super) position: u32,
    pub(super) expected_serial: Option<u64>,
    pub(super) record: Option<InventoryRecord>,
    // A verified exact-absence witness from the future cleanup proof boundary.
    // This internal batch representation is never a public proof constructor.
    pub(super) absence: Option<[u8; 32]>,
}

struct PendingLeaf {
    position: u32,
    page: LeafPage,
}
struct PendingBranch {
    position: u32,
    children: [ChildReference; FANOUT],
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ResourceBounds {
    pub(super) leaf_files: u64,
    pub(super) branch_files: u64,
    pub(super) file_count: u64,
    pub(super) content_bytes: u64,
    pub(super) index_bytes: u64,
    pub(super) working_bytes: u64,
}

fn sum(values: &[u64]) -> Result<u64, InventoryError> {
    values.iter().try_fold(0_u64, |total, value| {
        total.checked_add(*value).ok_or(InventoryError::Capacity)
    })
}

fn product(left: u64, right: u64) -> Result<u64, InventoryError> {
    left.checked_mul(right).ok_or(InventoryError::Capacity)
}

fn bytes<T>() -> Result<u64, InventoryError> {
    u64::try_from(std::mem::size_of::<T>()).map_err(|_| InventoryError::Capacity)
}

// These are content bytes and bounded Rust values/allocations. Filesystem
// metadata, allocation-unit rounding, allocator metadata, thread stacks and
// the rest of the process need a separately provisioned deployment margin.
pub(super) fn resource_bounds(
    limits: InventoryLimits,
    format: FormatBudget,
) -> Result<ResourceBounds, InventoryError> {
    limits.validate()?;
    let records = u64::from(limits.counts().records()?);
    let leaf_files = records.div_ceil(64);
    let branch_files = leaf_files.div_ceil(256);
    let leaf_frame =
        u64::try_from(format.leaf_frame_bytes()?).map_err(|_| InventoryError::Capacity)?;
    let leaf_payload =
        u64::try_from(format.leaf_payload_bytes()?).map_err(|_| InventoryError::Capacity)?;
    let manifest = u64::try_from(format.manifest_bytes).map_err(|_| InventoryError::Capacity)?;
    let root = u64::try_from(format.root_bytes).map_err(|_| InventoryError::Capacity)?;
    let file_count = sum(&[product(2, leaf_files)?, product(2, branch_files)?, 2])?;
    let content_bytes = sum(&[
        product(product(2, leaf_files)?, leaf_frame)?,
        product(product(2, branch_files)?, manifest)?,
        root,
        leaf_frame.max(manifest).max(root),
    ])?;
    let entries = usize::try_from(
        limits
            .images
            .checked_add(limits.coverage)
            .ok_or(InventoryError::Capacity)?,
    )
    .map_err(|_| InventoryError::Capacity)?;
    let index_bytes = u64::try_from(LocatorIndex::required_allocation(entries)?.1)
        .map_err(|_| InventoryError::Capacity)?;
    let object_heap = sum(&[
        product(2, bytes::<super::CandidateImage>()?)?,
        product(12, bytes::<crate::XfrmTemplate>()?)?,
    ])?;
    let coverage_heap = product(8, bytes::<super::CoverageMember>()?)?;
    let record_heap = object_heap.max(coverage_heap);
    let leaf_heap = product(
        u64::try_from(LEAF_SLOTS).map_err(|_| InventoryError::Capacity)?,
        record_heap,
    )?;
    let leaf_memory = sum(&[bytes::<LeafPage>()?, leaf_heap])?;
    // At most two decoded leaves coexist during backlink verification. The
    // additional manifests/root copies and small buffers conservatively cover
    // encode/decode temporaries; no whole-inventory object vector is retained.
    let parser = sum(&[
        product(2, sum(&[leaf_memory, leaf_frame, leaf_payload])?)?,
        product(6, bytes::<RootPage>()?)?,
        product(2, manifest)?,
        product(2, root)?,
        8192,
    ])?;
    let batch = u64::from(limits.batch_records);
    let update = sum(&[
        parser,
        product(
            batch.min(leaf_files),
            sum(&[bytes::<PendingLeaf>()?, leaf_heap])?,
        )?,
        product(batch.min(branch_files), bytes::<PendingBranch>()?)?,
        product(
            batch,
            sum(&[
                bytes::<Change>()?,
                record_heap,
                product(4, bytes::<([u8; 32], Location)>()?)?,
                18 * 4,
            ])?,
        )?,
    ])?;
    let reopen = sum(&[parser, product(records, bytes::<u64>()?)?])?;
    Ok(ResourceBounds {
        leaf_files,
        branch_files,
        file_count,
        content_bytes,
        index_bytes,
        working_bytes: update.max(reopen),
    })
}

fn reserve_resources(limits: InventoryLimits, format: FormatBudget) -> Result<(), InventoryError> {
    let required = resource_bounds(limits, format)?;
    if required.content_bytes > limits.storage_bytes
        || required.index_bytes > limits.index_bytes
        || required.working_bytes > limits.working_bytes
    {
        return Err(InventoryError::Capacity);
    }
    Ok(())
}

pub(super) struct SnapshotStore<I: SnapshotIo> {
    io: I,
    key: InventoryKey,
    context: NodeContext,
    page: RootPage,
    format: FormatBudget,
    index: LocatorIndex,
    root_digest: [u8; 32],
    poisoned: bool,
    #[cfg(test)]
    path_vector_allocation_bytes: usize,
}

fn reserved<T>(count: usize) -> Result<Vec<T>, InventoryError> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| InventoryError::Allocation)?;
    if values.capacity() != count && std::mem::size_of::<T>() != 0 {
        return Err(InventoryError::Allocation);
    }
    Ok(values)
}

fn serial(record: &InventoryRecord) -> u64 {
    match record {
        InventoryRecord::Object(value) => value.serial,
        InventoryRecord::Coverage(value) => value.serial,
    }
}

fn kind(record: &InventoryRecord) -> LocatorKind {
    match record {
        InventoryRecord::Object(_) => LocatorKind::Object,
        InventoryRecord::Coverage(_) => LocatorKind::Coverage,
    }
}

fn family_index(family: TransactionFamily) -> usize {
    match family {
        TransactionFamily::Object => 0,
        TransactionFamily::Relocation => 1,
        TransactionFamily::Roster => 2,
    }
}

fn child_context(
    parent: NodeContext,
    child: ChildReference,
    kind: NodeKind,
    position: u32,
) -> Result<NodeContext, InventoryError> {
    if !child.present || child.generation > parent.generation || child.revision > parent.revision {
        return Err(InventoryError::Malformed);
    }
    Ok(NodeContext {
        generation: child.generation,
        revision: child.revision,
        kind,
        position,
        slot: child.slot,
        ..parent
    })
}

impl<I: SnapshotIo> SnapshotStore<I> {
    pub(super) fn create(
        io: I,
        key: InventoryKey,
        context: NodeContext,
        page: RootPage,
        format: FormatBudget,
    ) -> Result<Self, InventoryError> {
        reserve_resources(page.limits, format)?;
        if page.next_serial != 1
            || context.generation != 1
            || context.revision != 1
            || page
                .children
                .iter()
                .any(|child| *child != ChildReference::EMPTY)
        {
            return Err(InventoryError::Malformed);
        }
        io.check_binding()?;
        io.account(page.limits, format)?;
        let entries = usize::try_from(
            page.limits
                .images
                .checked_add(page.limits.coverage)
                .ok_or(InventoryError::Capacity)?,
        )
        .map_err(|_| InventoryError::Capacity)?;
        let index = LocatorIndex::new(entries)?;
        if u64::try_from(index.allocation().2).map_err(|_| InventoryError::Capacity)?
            > page.limits.index_bytes
        {
            return Err(InventoryError::Capacity);
        }
        let mut store = Self {
            io,
            key,
            context,
            page,
            format,
            index,
            root_digest: [0; 32],
            poisoned: false,
            #[cfg(test)]
            path_vector_allocation_bytes: 0,
        };
        let payload = encode_root(&store.page, format.root_bytes)?;
        let frame = seal_node(&store.key, context, &payload, format.root_bytes)?;
        store.publish(NodeName::Root, &frame)?;
        store.root_digest = ciphertext_digest(&frame);
        Ok(store)
    }

    pub(super) fn reopen(
        io: I,
        key: InventoryKey,
        binding: NodeContext,
        limits: InventoryLimits,
        stores: [Option<[u8; 16]>; 3],
        format: FormatBudget,
    ) -> Result<Self, InventoryError> {
        reserve_resources(limits, format)?;
        io.check_binding()?;
        io.account(limits, format)?;
        let (root_handle, frame) = io.read(NodeName::Root, format.root_bytes)?;
        let (context, _, _) = decode_header(&frame, format.root_bytes)?;
        if context.kind != NodeKind::Root
            || context.namespace != binding.namespace
            || context.device != binding.device
            || context.inode != binding.inode
            || context.incarnation == [0; 16]
        {
            return Err(InventoryError::WrongBinding);
        }
        let payload = open_node(&key, context, &frame, format.root_bytes)?;
        let page = decode_root(&payload, format.root_bytes)?;
        if page.limits != limits || page.stores != stores {
            return Err(InventoryError::WrongBinding);
        }
        let entries = usize::try_from(
            limits
                .images
                .checked_add(limits.coverage)
                .ok_or(InventoryError::Capacity)?,
        )
        .map_err(|_| InventoryError::Capacity)?;
        let index = LocatorIndex::new(entries)?;
        if u64::try_from(index.allocation().2).map_err(|_| InventoryError::Capacity)?
            > limits.index_bytes
        {
            return Err(InventoryError::Capacity);
        }
        let mut store = Self {
            io,
            key,
            context,
            page,
            format,
            index,
            root_digest: ciphertext_digest(&frame),
            poisoned: false,
            #[cfg(test)]
            path_vector_allocation_bytes: 0,
        };
        store.rebuild()?;
        // The accepted root may only be visible, not yet durable. Pin and fsync
        // that exact file and its directory before reusing any inactive slot.
        store.io.stabilize_root(&root_handle, store.root_digest)?;
        store.io.sync_directory()?;
        drop(root_handle);
        store.io.remove_temporary()?;
        store.io.sync_directory()?;
        Ok(store)
    }

    fn publish(&mut self, destination: NodeName, frame: &[u8]) -> Result<(), InventoryError> {
        self.io.check_binding()?;
        self.io.write_temporary(frame)?;
        self.io.sync_temporary()?;
        self.io.rename_temporary(destination)?;
        self.io.sync_directory()
    }

    pub(super) fn check_current(&self) -> Result<(), InventoryError> {
        if self.poisoned {
            return Err(InventoryError::Unavailable);
        }
        self.io.check_binding()?;
        let (_, frame) = self.io.read(NodeName::Root, self.format.root_bytes)?;
        if ciphertext_digest(&frame) != self.root_digest {
            return Err(InventoryError::WrongBinding);
        }
        open_node(&self.key, self.context, &frame, self.format.root_bytes)?;
        Ok(())
    }

    pub(super) fn check_store_bindings(
        &self,
        stores: [Option<[u8; 16]>; 3],
    ) -> Result<(), InventoryError> {
        self.check_current()?;
        if self.page.stores != stores {
            return Err(InventoryError::WrongBinding);
        }
        Ok(())
    }

    fn read_branch(&self, position: u32) -> Result<[ChildReference; FANOUT], InventoryError> {
        let reference = *self
            .page
            .children
            .get(usize::try_from(position).map_err(|_| InventoryError::Capacity)?)
            .ok_or(InventoryError::Malformed)?;
        if !reference.present {
            return Ok([ChildReference::EMPTY; FANOUT]);
        }
        let context = child_context(self.context, reference, NodeKind::Branch, position)?;
        let (_, frame) = self.io.read(
            NodeName::Branch(position, reference.slot),
            self.format.manifest_bytes,
        )?;
        if ciphertext_digest(&frame) != reference.digest {
            return Err(InventoryError::Authentication);
        }
        let payload = open_node(&self.key, context, &frame, self.format.manifest_bytes)?;
        let children = decode_children(&payload, self.format.manifest_bytes)?;
        if children_counts(&children)? != reference.counts {
            return Err(InventoryError::Malformed);
        }
        for child in children.iter().filter(|child| child.present) {
            if child.generation > context.generation || child.revision > context.revision {
                return Err(InventoryError::Malformed);
            }
        }
        Ok(children)
    }

    fn read_leaf_from(
        &self,
        position: u32,
        reference: ChildReference,
    ) -> Result<LeafPage, InventoryError> {
        if !reference.present {
            return Ok(LeafPage::empty());
        }
        let context = child_context(self.context, reference, NodeKind::Leaf, position)?;
        let (_, frame) = self.io.read(
            NodeName::Leaf(position, reference.slot),
            self.format.leaf_frame_bytes()?,
        )?;
        if ciphertext_digest(&frame) != reference.digest {
            return Err(InventoryError::Authentication);
        }
        let payload = open_node(&self.key, context, &frame, self.format.leaf_frame_bytes()?)?;
        let leaf = decode_leaf(&payload, self.format)?;
        if leaf.counts()? != reference.counts {
            return Err(InventoryError::Malformed);
        }
        Ok(leaf)
    }

    fn read_leaf(&self, position: u32) -> Result<LeafPage, InventoryError> {
        let branch = self.read_branch(position / 256)?;
        self.read_leaf_from(position, branch[(position % 256) as usize])
    }

    fn read_record(&self, position: u32) -> Result<Option<InventoryRecord>, InventoryError> {
        if position >= self.page.limits.counts().records()? {
            return Err(InventoryError::Capacity);
        }
        let mut leaf = self.read_leaf(position / 64)?;
        Ok(leaf.records[(position % 64) as usize].take())
    }

    fn keys(&self, record: &InventoryRecord) -> Result<Vec<[u8; 32]>, InventoryError> {
        let mut keys = reserved(2)?;
        match record {
            InventoryRecord::Object(object) => {
                for candidate in &object.candidates {
                    let body = image_locator_bytes(&candidate.image)?;
                    let digest = self.key.locator(self.context, b"object", &body)?;
                    if !keys.contains(&digest) {
                        keys.push(digest);
                    }
                }
            }
            InventoryRecord::Coverage(coverage) => {
                let mut body = Encoder::new(64)?;
                body.u8(u8::try_from(family_index(coverage.family))
                    .map_err(|_| InventoryError::Malformed)?)?;
                body.bytes(&coverage.store_incarnation)?;
                body.bytes(&coverage.correlation)?;
                body.u64(coverage.inventory_generation)?;
                body.u64(coverage.operation_generation)?;
                keys.push(
                    self.key
                        .locator(self.context, b"coverage", &body.finish())?,
                );
            }
        }
        Ok(keys)
    }

    fn with_record<T>(
        &self,
        position: u32,
        changes: &[Change],
        action: impl FnOnce(Option<&InventoryRecord>) -> Result<T, InventoryError>,
    ) -> Result<T, InventoryError> {
        if let Some(change) = changes.iter().find(|change| change.position == position) {
            return action(change.record.as_ref());
        }
        let record = self.read_record(position)?;
        action(record.as_ref())
    }

    fn validate_record_at(
        &self,
        position: u32,
        record: &InventoryRecord,
        changes: &[Change],
        next_serial: u64,
    ) -> Result<(), InventoryError> {
        if serial(record) == 0 || serial(record) >= next_serial {
            return Err(InventoryError::Malformed);
        }
        match record {
            InventoryRecord::Object(object) => {
                if object.generation > self.context.generation {
                    return Err(InventoryError::WrongBinding);
                }
                if let Some(link) = object.coverage {
                    self.with_record(link.position, changes, |related| match related {
                        Some(InventoryRecord::Coverage(coverage))
                            if coverage.serial == link.serial
                                && coverage.members.iter().any(|member| {
                                    member.object
                                        == RecordLink {
                                            position,
                                            serial: object.serial,
                                        }
                                        && member.absence.is_none()
                                }) =>
                        {
                            Ok(())
                        }
                        _ => Err(InventoryError::WrongBinding),
                    })?;
                }
            }
            InventoryRecord::Coverage(coverage) => {
                if coverage.inventory_generation > self.context.generation
                    || self.page.stores[family_index(coverage.family)]
                        != Some(coverage.store_incarnation)
                {
                    return Err(InventoryError::WrongBinding);
                }
                for member in &coverage.members {
                    if member.object.serial >= next_serial {
                        return Err(InventoryError::Malformed);
                    }
                    self.with_record(member.object.position, changes, |related| {
                        if member.absence.is_some() {
                            return if related
                                .is_some_and(|record| serial(record) == member.object.serial)
                            {
                                Err(InventoryError::WrongBinding)
                            } else {
                                Ok(())
                            };
                        }
                        match related {
                            Some(InventoryRecord::Object(object))
                                if object.serial == member.object.serial
                                    && object.coverage
                                        == Some(RecordLink {
                                            position,
                                            serial: coverage.serial,
                                        }) =>
                            {
                                Ok(())
                            }
                            _ => Err(InventoryError::WrongBinding),
                        }
                    })?;
                }
            }
        }
        Ok(())
    }

    fn rebuild(&mut self) -> Result<(), InventoryError> {
        let maximum = usize::try_from(self.page.limits.counts().records()?)
            .map_err(|_| InventoryError::Capacity)?;
        let mut serials = Zeroizing::new(reserved::<u64>(maximum)?);
        let mut observed = Counts::default();
        for branch_position in 0..FANOUT {
            if !self.page.children[branch_position].present {
                continue;
            }
            let branch = self.read_branch(
                u32::try_from(branch_position).map_err(|_| InventoryError::Capacity)?,
            )?;
            for (leaf_slot, reference) in branch
                .into_iter()
                .enumerate()
                .filter(|(_, child)| child.present)
            {
                let leaf_position = u32::try_from(branch_position * FANOUT + leaf_slot)
                    .map_err(|_| InventoryError::Capacity)?;
                let leaf = self.read_leaf_from(leaf_position, reference)?;
                for (offset, record) in leaf
                    .records
                    .iter()
                    .enumerate()
                    .filter_map(|(offset, record)| record.as_ref().map(|record| (offset, record)))
                {
                    let position = leaf_position
                        .checked_mul(64)
                        .and_then(|value| value.checked_add(u32::try_from(offset).ok()?))
                        .ok_or(InventoryError::Capacity)?;
                    if position >= self.page.limits.counts().records()? || serials.len() >= maximum
                    {
                        return Err(InventoryError::Capacity);
                    }
                    self.validate_record_at(position, record, &[], self.page.next_serial)?;
                    observed = observed.add(Counts::from_record(record))?;
                    serials.push(serial(record));
                    for digest in self.keys(record)? {
                        self.index.insert(
                            digest,
                            Location {
                                position,
                                kind: kind(record),
                            },
                        )?;
                    }
                }
            }
        }
        serials.sort_unstable();
        if serials.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(InventoryError::Duplicate);
        }
        if observed != children_counts(&self.page.children)? {
            return Err(InventoryError::Malformed);
        }
        self.page.limits.accept(observed)
    }

    fn validate_replacement(
        &self,
        old: &InventoryRecord,
        next: &InventoryRecord,
        changes: &[Change],
    ) -> Result<(), InventoryError> {
        match (old, next) {
            (InventoryRecord::Object(old), InventoryRecord::Object(next)) => {
                // This closed prefix cannot qualify a candidate-image change or
                // promote a phase using a kernel proof. Existing ownership
                // descriptors and their complete pre-effect evidence are fixed.
                if old.serial != next.serial
                    || old.generation != next.generation
                    || old.reserved_images != next.reserved_images
                    || old.candidates != next.candidates
                    || (old.phase != next.phase && next.phase != super::ObjectPhase::Indeterminate)
                {
                    return Err(InventoryError::WrongBinding);
                }
                match (old.coverage, next.coverage) {
                    (old, next) if old == next => {}
                    (None, Some(_)) => {}
                    (Some(previous), None) => {
                        let prior = self.read_record(previous.position)?;
                        if !matches!(prior, Some(InventoryRecord::Coverage(coverage)) if coverage.serial == previous.serial && coverage.settlement.is_some())
                            || !changes.iter().any(|change| {
                                change.position == previous.position
                                    && change.expected_serial == Some(previous.serial)
                                    && change.record.is_none()
                            })
                        {
                            return Err(InventoryError::WrongBinding);
                        }
                    }
                    _ => return Err(InventoryError::WrongBinding),
                }
            }
            (InventoryRecord::Coverage(old), InventoryRecord::Coverage(next)) => {
                if old.serial != next.serial
                    || old.inventory_generation != next.inventory_generation
                    || old.family != next.family
                    || old.store_incarnation != next.store_incarnation
                    || old.correlation != next.correlation
                    || old.operation_generation != next.operation_generation
                    || old.request_fingerprint != next.request_fingerprint
                    || old.members.len() != next.members.len()
                    || old
                        .settlement
                        .is_some_and(|witness| next.settlement != Some(witness))
                    || old.members.iter().zip(&next.members).any(|(old, next)| {
                        old.object != next.object
                            || old
                                .absence
                                .is_some_and(|witness| next.absence != Some(witness))
                    })
                {
                    return Err(InventoryError::WrongBinding);
                }
            }
            _ => return Err(InventoryError::WrongBinding),
        }
        Ok(())
    }

    pub(super) fn apply(
        &mut self,
        changes: Vec<Change>,
        new_generation: bool,
    ) -> Result<(), InventoryError> {
        self.check_current()?;
        if changes.len()
            > usize::try_from(self.page.limits.batch_records)
                .map_err(|_| InventoryError::Capacity)?
        {
            return Err(InventoryError::Capacity);
        }
        let mut next_serial = self.page.next_serial;
        let mut old_keys = reserved(
            changes
                .len()
                .checked_mul(2)
                .ok_or(InventoryError::Capacity)?,
        )?;
        let mut new_keys = reserved(
            changes
                .len()
                .checked_mul(2)
                .ok_or(InventoryError::Capacity)?,
        )?;
        let mut related = reserved(
            changes
                .len()
                .checked_mul(18)
                .ok_or(InventoryError::Capacity)?,
        )?;
        for (ordinal, change) in changes.iter().enumerate() {
            if change.position >= self.page.limits.counts().records()?
                || changes[..ordinal]
                    .iter()
                    .any(|prior| prior.position == change.position)
            {
                return Err(InventoryError::Malformed);
            }
            let previous = self.read_record(change.position)?;
            if previous.as_ref().map(serial) != change.expected_serial {
                return Err(InventoryError::WrongBinding);
            }
            match (&previous, &change.record) {
                (Some(InventoryRecord::Object(object)), None) => {
                    let witness = change.absence.ok_or(InventoryError::WrongBinding)?;
                    if let Some(link) = object.coverage {
                        self.with_record(link.position, &changes, |related| match related {
                            Some(InventoryRecord::Coverage(coverage))
                                if coverage.serial == link.serial
                                    && coverage.members.iter().any(|member| {
                                        member.object
                                            == RecordLink {
                                                position: change.position,
                                                serial: object.serial,
                                            }
                                            && member.absence == Some(witness)
                                    }) =>
                            {
                                Ok(())
                            }
                            _ => Err(InventoryError::WrongBinding),
                        })?;
                    }
                }
                (Some(InventoryRecord::Coverage(coverage)), None)
                    if coverage.settlement.is_none() =>
                {
                    return Err(InventoryError::WrongBinding);
                }
                _ if change.absence.is_some() => return Err(InventoryError::WrongBinding),
                _ => {}
            }
            if let Some(record) = &change.record {
                encode_record(record, self.format.record_bytes)?;
                if let Some(previous) = &previous {
                    self.validate_replacement(previous, record, &changes)?;
                }
                match &previous {
                    Some(previous)
                        if kind(previous) != kind(record) || serial(previous) != serial(record) =>
                    {
                        return Err(InventoryError::WrongBinding);
                    }
                    None => {
                        if serial(record) != next_serial {
                            return Err(InventoryError::WrongBinding);
                        }
                        next_serial = next_serial.checked_add(1).ok_or(InventoryError::Capacity)?;
                    }
                    _ => {}
                }
            }
            for (record, keys) in [
                (previous.as_ref(), &mut old_keys),
                (change.record.as_ref(), &mut new_keys),
            ] {
                if let Some(record) = record {
                    for digest in self.keys(record)? {
                        keys.push((
                            digest,
                            Location {
                                position: change.position,
                                kind: kind(record),
                            },
                        ));
                    }
                    match record {
                        InventoryRecord::Object(object) => {
                            if let Some(link) = object.coverage {
                                related.push(link.position);
                            }
                        }
                        InventoryRecord::Coverage(coverage) => {
                            related.extend(
                                coverage.members.iter().map(|member| member.object.position),
                            );
                        }
                    }
                }
            }
            related.push(change.position);
        }
        for position in related {
            self.with_record(position, &changes, |record| {
                if let Some(record) = record {
                    self.validate_record_at(position, record, &changes, next_serial)?;
                }
                Ok(())
            })?;
        }
        for (ordinal, (digest, location)) in new_keys.iter().enumerate() {
            if let Some(found) = self.index.lookup(digest).0 {
                if found != *location
                    && !old_keys
                        .iter()
                        .any(|old| old.0 == *digest && old.1 == found)
                {
                    return Err(InventoryError::Duplicate);
                }
            }
            if new_keys[..ordinal]
                .iter()
                .any(|prior| prior.0 == *digest && prior.1 != *location)
            {
                return Err(InventoryError::Duplicate);
            }
        }
        let paths = resource_bounds(self.page.limits, self.format)?;
        let leaf_capacity = changes
            .len()
            .min(usize::try_from(paths.leaf_files).map_err(|_| InventoryError::Capacity)?);
        let branch_capacity = changes
            .len()
            .min(usize::try_from(paths.branch_files).map_err(|_| InventoryError::Capacity)?);
        let mut leaves = reserved::<PendingLeaf>(leaf_capacity)?;
        let mut branches = reserved::<PendingBranch>(branch_capacity)?;
        #[cfg(test)]
        {
            self.path_vector_allocation_bytes = leaves.capacity()
                * std::mem::size_of::<PendingLeaf>()
                + branches.capacity() * std::mem::size_of::<PendingBranch>();
        }
        for change in changes {
            let leaf_position = change.position / 64;
            let leaf_ordinal = if let Some(ordinal) = leaves
                .iter()
                .position(|leaf| leaf.position == leaf_position)
            {
                ordinal
            } else {
                leaves.push(PendingLeaf {
                    position: leaf_position,
                    page: self.read_leaf(leaf_position)?,
                });
                leaves.len() - 1
            };
            leaves[leaf_ordinal].page.records[(change.position % 64) as usize] = change.record;
            let branch_position = leaf_position / 256;
            if !branches
                .iter()
                .any(|branch| branch.position == branch_position)
            {
                branches.push(PendingBranch {
                    position: branch_position,
                    children: self.read_branch(branch_position)?,
                });
            }
        }
        let next_context = NodeContext {
            generation: if new_generation {
                self.context
                    .generation
                    .checked_add(1)
                    .ok_or(InventoryError::Capacity)?
            } else {
                self.context.generation
            },
            revision: self
                .context
                .revision
                .checked_add(1)
                .ok_or(InventoryError::Capacity)?,
            ..self.context
        };
        let mut next_page = self.page.clone();
        next_page.next_serial = next_serial;
        // Preflight all counts and encodings before the first filesystem write.
        for leaf in &leaves {
            let branch = branches
                .iter_mut()
                .find(|branch| branch.position == leaf.position / 256)
                .ok_or(InventoryError::Malformed)?;
            let reference = &mut branch.children[(leaf.position % 256) as usize];
            let counts = leaf.page.counts()?;
            *reference = if counts.records()? == 0 {
                ChildReference::EMPTY
            } else {
                ChildReference {
                    present: true,
                    slot: if reference.present {
                        1 - reference.slot
                    } else {
                        0
                    },
                    generation: next_context.generation,
                    revision: next_context.revision,
                    counts,
                    digest: [0; 32],
                }
            };
            encode_leaf(&leaf.page, self.format)?;
        }
        for branch in &branches {
            let reference = &mut next_page.children[branch.position as usize];
            let counts = children_counts(&branch.children)?;
            *reference = if counts.records()? == 0 {
                ChildReference::EMPTY
            } else {
                ChildReference {
                    present: true,
                    slot: if reference.present {
                        1 - reference.slot
                    } else {
                        0
                    },
                    generation: next_context.generation,
                    revision: next_context.revision,
                    counts,
                    digest: [0; 32],
                }
            };
        }
        next_page
            .limits
            .accept(children_counts(&next_page.children)?)?;
        encode_root(&next_page, self.format.root_bytes)?;
        // Any failure from the first publication onward forbids reuse until a
        // new leased reopen authenticates and stabilizes the authoritative root.
        self.poisoned = true;
        for leaf in leaves {
            let branch = branches
                .iter_mut()
                .find(|branch| branch.position == leaf.position / 256)
                .ok_or(InventoryError::Malformed)?;
            let reference = &mut branch.children[(leaf.position % 256) as usize];
            if !reference.present {
                continue;
            }
            let payload = encode_leaf(&leaf.page, self.format)?;
            let context = child_context(next_context, *reference, NodeKind::Leaf, leaf.position)?;
            let frame = seal_node(
                &self.key,
                context,
                &payload,
                self.format.leaf_frame_bytes()?,
            )?;
            self.publish(NodeName::Leaf(leaf.position, reference.slot), &frame)?;
            reference.digest = ciphertext_digest(&frame);
        }
        for branch in branches {
            let reference = &mut next_page.children[branch.position as usize];
            if !reference.present {
                continue;
            }
            let payload = encode_children(&branch.children, self.format.manifest_bytes)?;
            let context =
                child_context(next_context, *reference, NodeKind::Branch, branch.position)?;
            let frame = seal_node(&self.key, context, &payload, self.format.manifest_bytes)?;
            self.publish(NodeName::Branch(branch.position, reference.slot), &frame)?;
            reference.digest = ciphertext_digest(&frame);
        }
        let payload = encode_root(&next_page, self.format.root_bytes)?;
        let frame = seal_node(&self.key, next_context, &payload, self.format.root_bytes)?;
        self.publish(NodeName::Root, &frame)?;
        for (digest, location) in old_keys {
            self.index.remove(&digest, location)?;
        }
        for (digest, location) in new_keys {
            self.index.insert(digest, location)?;
        }
        self.root_digest = ciphertext_digest(&frame);
        self.page = next_page;
        self.context = next_context;
        self.poisoned = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
