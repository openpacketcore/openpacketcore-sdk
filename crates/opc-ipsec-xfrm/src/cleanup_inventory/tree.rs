use zeroize::Zeroizing;

use super::{
    codec::{decode_record, encode_record, Decoder, Encoder},
    node::ENVELOPE_BYTES,
    InventoryError, InventoryRecord,
};

pub(super) const FANOUT: usize = 256;
pub(super) const LEAF_SLOTS: usize = 64;
pub(super) const ADDRESS_SLOTS: u32 = 1 << 22;
pub(super) const COMPLETION_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Counts {
    pub(super) objects: u32,
    pub(super) images: u32,
    pub(super) coverage: u32,
}

impl Counts {
    pub(super) fn add(self, other: Self) -> Result<Self, InventoryError> {
        Ok(Self {
            objects: self
                .objects
                .checked_add(other.objects)
                .ok_or(InventoryError::Capacity)?,
            images: self
                .images
                .checked_add(other.images)
                .ok_or(InventoryError::Capacity)?,
            coverage: self
                .coverage
                .checked_add(other.coverage)
                .ok_or(InventoryError::Capacity)?,
        })
    }

    pub(super) fn records(self) -> Result<u32, InventoryError> {
        self.objects
            .checked_add(self.coverage)
            .ok_or(InventoryError::Capacity)
    }

    fn validate(self) -> Result<(), InventoryError> {
        if self.records()? > ADDRESS_SLOTS
            || self.images < self.objects
            || u64::from(self.images) > 2 * u64::from(self.objects)
        {
            return Err(InventoryError::Malformed);
        }
        Ok(())
    }

    pub(super) fn from_record(record: &InventoryRecord) -> Self {
        match record {
            InventoryRecord::Object(object) => Self {
                objects: 1,
                images: u32::from(object.reserved_images),
                coverage: 0,
            },
            InventoryRecord::Coverage(_) => Self {
                objects: 0,
                images: 0,
                coverage: 1,
            },
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct ChildReference {
    pub(super) present: bool,
    pub(super) slot: u8,
    pub(super) generation: u64,
    pub(super) revision: u64,
    pub(super) counts: Counts,
    pub(super) digest: [u8; 32],
}

impl ChildReference {
    pub(super) const EMPTY: Self = Self {
        present: false,
        slot: 0,
        generation: 0,
        revision: 0,
        counts: Counts {
            objects: 0,
            images: 0,
            coverage: 0,
        },
        digest: [0; 32],
    };
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct InventoryLimits {
    pub(super) objects: u32,
    pub(super) images: u32,
    pub(super) coverage: u32,
    pub(super) batch_records: u32,
    pub(super) storage_bytes: u64,
    pub(super) index_bytes: u64,
    pub(super) working_bytes: u64,
}

impl InventoryLimits {
    pub(super) fn counts(self) -> Counts {
        Counts {
            objects: self.objects,
            images: self.images,
            coverage: self.coverage,
        }
    }

    pub(super) fn validate(self) -> Result<(), InventoryError> {
        self.counts().validate()?;
        if self.batch_records == 0
            || self.batch_records > self.counts().records()?
            || self.storage_bytes == 0
            || self.index_bytes == 0
            || self.working_bytes == 0
        {
            return Err(InventoryError::Capacity);
        }
        Ok(())
    }

    pub(super) fn accept(self, counts: Counts) -> Result<(), InventoryError> {
        counts.validate()?;
        if counts.objects > self.objects
            || counts.images > self.images
            || counts.coverage > self.coverage
        {
            return Err(InventoryError::Capacity);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct FormatBudget {
    pub(super) record_bytes: usize,
    pub(super) manifest_bytes: usize,
    pub(super) root_bytes: usize,
}

impl FormatBudget {
    pub(super) fn leaf_payload_bytes(self) -> Result<usize, InventoryError> {
        if self.record_bytes == 0 || self.record_bytes > usize::from(u16::MAX) {
            return Err(InventoryError::Capacity);
        }
        self.record_bytes
            .checked_add(2)
            .and_then(|slot| slot.checked_mul(LEAF_SLOTS))
            .and_then(|slots| slots.checked_add(8))
            .ok_or(InventoryError::Capacity)
    }

    pub(super) fn leaf_frame_bytes(self) -> Result<usize, InventoryError> {
        self.leaf_payload_bytes()?
            .checked_add(ENVELOPE_BYTES)
            .ok_or(InventoryError::Capacity)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct RootPage {
    pub(super) next_serial: u64,
    pub(super) limits: InventoryLimits,
    pub(super) stores: [Option<[u8; 16]>; 3],
    pub(super) completion: [u8; COMPLETION_BYTES],
    pub(super) children: [ChildReference; FANOUT],
}

#[derive(Clone, PartialEq, Eq)]
pub(super) struct LeafPage {
    pub(super) records: [Option<InventoryRecord>; LEAF_SLOTS],
}

impl LeafPage {
    pub(super) fn empty() -> Self {
        Self {
            records: std::array::from_fn(|_| None),
        }
    }

    pub(super) fn counts(&self) -> Result<Counts, InventoryError> {
        self.records
            .iter()
            .flatten()
            .try_fold(Counts::default(), |counts, record| {
                counts.add(Counts::from_record(record))
            })
    }
}

pub(super) fn encode_leaf(
    page: &LeafPage,
    format: FormatBudget,
) -> Result<Zeroizing<Vec<u8>>, InventoryError> {
    let mut encoder = Encoder::new(format.leaf_payload_bytes()?)?;
    let mut bitmap = 0_u64;
    for (position, record) in page.records.iter().enumerate() {
        if record.is_some() {
            bitmap |= 1_u64 << position;
        }
    }
    encoder.u64(bitmap)?;
    for record in page.records.iter().flatten() {
        let bytes = encode_record(record, format.record_bytes)?;
        encoder.u16(u16::try_from(bytes.len()).map_err(|_| InventoryError::Capacity)?)?;
        encoder.bytes(&bytes)?;
    }
    Ok(encoder.finish())
}

pub(super) fn decode_leaf(bytes: &[u8], format: FormatBudget) -> Result<LeafPage, InventoryError> {
    let mut decoder = Decoder::new(bytes, format.leaf_payload_bytes()?)?;
    let bitmap = decoder.u64()?;
    let mut page = LeafPage::empty();
    for (position, record) in page.records.iter_mut().enumerate() {
        if bitmap & (1_u64 << position) != 0 {
            let length = usize::from(decoder.u16()?);
            if length > format.record_bytes {
                return Err(InventoryError::Capacity);
            }
            *record = Some(decode_record(decoder.take(length)?, format.record_bytes)?);
        }
    }
    decoder.finish()?;
    Ok(page)
}

fn write_children(
    encoder: &mut Encoder,
    children: &[ChildReference; FANOUT],
) -> Result<(), InventoryError> {
    for child in children {
        if !child.present {
            if *child != ChildReference::EMPTY {
                return Err(InventoryError::Malformed);
            }
            encoder.u8(0)?;
            continue;
        }
        child.counts.validate()?;
        if child.counts.records()? == 0
            || child.slot > 1
            || child.generation == 0
            || child.revision == 0
        {
            return Err(InventoryError::Malformed);
        }
        encoder.u8(1)?;
        encoder.u8(child.slot)?;
        encoder.u64(child.generation)?;
        encoder.u64(child.revision)?;
        encoder.u32(child.counts.objects)?;
        encoder.u32(child.counts.images)?;
        encoder.u32(child.counts.coverage)?;
        encoder.bytes(&child.digest)?;
    }
    Ok(())
}

fn read_children(decoder: &mut Decoder<'_>) -> Result<[ChildReference; FANOUT], InventoryError> {
    let mut children = [ChildReference::EMPTY; FANOUT];
    for child in &mut children {
        match decoder.u8()? {
            0 => {}
            1 => {
                *child = ChildReference {
                    present: true,
                    slot: decoder.u8()?,
                    generation: decoder.u64()?,
                    revision: decoder.u64()?,
                    counts: Counts {
                        objects: decoder.u32()?,
                        images: decoder.u32()?,
                        coverage: decoder.u32()?,
                    },
                    digest: decoder.array()?,
                };
                child.counts.validate()?;
                if child.counts.records()? == 0
                    || child.slot > 1
                    || child.generation == 0
                    || child.revision == 0
                {
                    return Err(InventoryError::Malformed);
                }
            }
            _ => return Err(InventoryError::Malformed),
        }
    }
    Ok(children)
}

pub(super) fn children_counts(
    children: &[ChildReference; FANOUT],
) -> Result<Counts, InventoryError> {
    children
        .iter()
        .try_fold(Counts::default(), |counts, child| counts.add(child.counts))
}

pub(super) fn encode_children(
    children: &[ChildReference; FANOUT],
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, InventoryError> {
    let mut encoder = Encoder::new(
        limit
            .checked_sub(ENVELOPE_BYTES)
            .ok_or(InventoryError::Capacity)?,
    )?;
    write_children(&mut encoder, children)?;
    Ok(encoder.finish())
}

pub(super) fn decode_children(
    bytes: &[u8],
    limit: usize,
) -> Result<[ChildReference; FANOUT], InventoryError> {
    let mut decoder = Decoder::new(
        bytes,
        limit
            .checked_sub(ENVELOPE_BYTES)
            .ok_or(InventoryError::Capacity)?,
    )?;
    let children = read_children(&mut decoder)?;
    decoder.finish()?;
    Ok(children)
}

pub(super) fn encode_root(
    page: &RootPage,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>, InventoryError> {
    page.limits.validate()?;
    page.limits.accept(children_counts(&page.children)?)?;
    // Completion-region version zero is explicitly closed: the remaining
    // 4095 bytes are reserved zeros, never a seal or activation authority.
    if page.next_serial == 0 || page.completion.iter().any(|byte| *byte != 0) {
        return Err(InventoryError::Malformed);
    }
    let mut encoder = Encoder::new(
        limit
            .checked_sub(ENVELOPE_BYTES)
            .ok_or(InventoryError::Capacity)?,
    )?;
    encoder.u64(page.next_serial)?;
    encoder.u32(page.limits.objects)?;
    encoder.u32(page.limits.images)?;
    encoder.u32(page.limits.coverage)?;
    encoder.u32(page.limits.batch_records)?;
    encoder.u64(page.limits.storage_bytes)?;
    encoder.u64(page.limits.index_bytes)?;
    encoder.u64(page.limits.working_bytes)?;
    for store in &page.stores {
        encoder.u8(u8::from(store.is_some()))?;
        if let Some(store) = store {
            encoder.bytes(store)?;
        }
    }
    encoder.bytes(&page.completion)?;
    write_children(&mut encoder, &page.children)?;
    Ok(encoder.finish())
}

pub(super) fn decode_root(bytes: &[u8], limit: usize) -> Result<RootPage, InventoryError> {
    let mut decoder = Decoder::new(
        bytes,
        limit
            .checked_sub(ENVELOPE_BYTES)
            .ok_or(InventoryError::Capacity)?,
    )?;
    let next_serial = decoder.u64()?;
    if next_serial == 0 {
        return Err(InventoryError::Malformed);
    }
    let limits = InventoryLimits {
        objects: decoder.u32()?,
        images: decoder.u32()?,
        coverage: decoder.u32()?,
        batch_records: decoder.u32()?,
        storage_bytes: decoder.u64()?,
        index_bytes: decoder.u64()?,
        working_bytes: decoder.u64()?,
    };
    limits.validate()?;
    let mut stores = [None; 3];
    for store in &mut stores {
        *store = match decoder.u8()? {
            0 => None,
            1 => Some(decoder.array()?),
            _ => return Err(InventoryError::Malformed),
        };
    }
    let completion = decoder.array::<COMPLETION_BYTES>()?;
    if completion.iter().any(|byte| *byte != 0) {
        return Err(InventoryError::Malformed);
    }
    let children = read_children(&mut decoder)?;
    limits.accept(children_counts(&children)?)?;
    decoder.finish()?;
    Ok(RootPage {
        next_serial,
        limits,
        stores,
        children,
        completion,
    })
}
