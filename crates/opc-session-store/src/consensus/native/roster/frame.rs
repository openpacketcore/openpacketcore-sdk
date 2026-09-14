//! Bounded envelopes for the original authenticated roster carriers and the
//! inseparable floor/cursor pair. An envelope is not admission evidence: row
//! decoding runs the original signature, identity and canonical validators.
//! The caller additionally validates the complete ledger and business state.
//! All encoding, input reads and hydration run outside the SDK State lock.

use super::*;
use crate::fenced_mutation_roster::MAX_HISTORY_FLOOR_CODEC_BYTES;
use crate::fenced_mutation_roster_storage::MAX_RETIREMENT_CURSOR_CODEC_BYTES;
use std::io::{Read, Write};

const ROW_MAGIC: &[u8; 8] = b"OPCNRR01";
const PARTITION_MAGIC: &[u8; 8] = b"OPCNRP01";
const PROJECTION_BYTES: usize = 512;
const ROW_HEADER: usize = 8 + 120 + 2 + 4;
const PARTITION_HEADER: usize = 8 + 64 + 2 + 2;
pub(in crate::consensus::native) const MAX_ROW: usize =
    ROW_HEADER + PROJECTION_BYTES + carrier::MAX_CANONICAL_BYTES;
pub(in crate::consensus::native) const MAX_PARTITION: usize =
    PARTITION_HEADER + MAX_HISTORY_FLOOR_CODEC_BYTES + MAX_RETIREMENT_CURSOR_CODEC_BYTES;
// Both owned projection copies, canonical re-encoding and short floor/cursor
// buffers. The original carrier decoder reserves its separate complete body.
const METADATA_MEMORY: usize = 8 * 1024;

fn projection_bytes<'a>(
    projection: &Projection,
    bytes: &'a mut [u8; PROJECTION_BYTES],
) -> io::Result<&'a [u8]> {
    postcard::to_slice(projection, bytes)
        .map(|bytes| &*bytes)
        .map_err(|_| invalid("native roster projection exceeds its frame"))
}

fn row_length(projection: usize, canonical: usize) -> io::Result<u32> {
    if projection == 0
        || projection > PROJECTION_BYTES
        || canonical == 0
        || canonical > carrier::MAX_CANONICAL_BYTES
    {
        return Err(invalid("native roster frame component exceeds its bound"));
    }
    u32::try_from(ROW_HEADER + projection + canonical)
        .map_err(|_| invalid("native roster frame length overflow"))
}

/// Encoding uses an already admitted in-process row. Exact expected readback
/// and complete cold admission remain the enclosing generation's obligation.
#[cfg(test)]
pub(in crate::consensus::native) fn write_row(
    writer: &mut dyn Write,
    row: &Row,
) -> io::Result<u32> {
    write_carrier(writer, row.binding, &row.projection, row.canonical()?)
}

pub(in crate::consensus::native) fn write_row_detached(
    writer: &mut dyn Write,
    row: &Row,
    root: &RosterAttestationTrustRootV1,
    scope: &MembershipValidationScope,
    check: &impl Fn() -> io::Result<()>,
) -> io::Result<u32> {
    let hydrated = row.hydrate_detached(root, scope, check)?;
    let length = write_carrier(
        writer,
        hydrated.binding(),
        &hydrated.projection,
        hydrated.canonical(),
    )?;
    check()?;
    Ok(length)
}

fn write_carrier(
    writer: &mut dyn Write,
    binding: RequestBindingKey,
    projection: &Projection,
    canonical: &[u8],
) -> io::Result<u32> {
    let mut bytes = [0; PROJECTION_BYTES];
    let projection = projection_bytes(projection, &mut bytes)?;
    let length = row_length(projection.len(), canonical.len())?;
    writer.write_all(ROW_MAGIC)?;
    writer.write_all(&binding.to_bytes())?;
    writer.write_all(&(projection.len() as u16).to_be_bytes())?;
    writer.write_all(&(canonical.len() as u32).to_be_bytes())?;
    writer.write_all(projection)?;
    writer.write_all(canonical)?;
    Ok(length)
}

pub(in crate::consensus::native) fn write_hydrated(
    writer: &mut dyn Write,
    row: &carrier::Hydration,
) -> io::Result<u32> {
    write_carrier(writer, row.binding(), &row.projection, row.canonical())
}

/// `length` is the complete selected extent. Check all fixed bounds and its
/// exact component sum before any canonical-body allocation or read. The
/// owned input reservation spans transfer into the original guarded decoder.
pub(in crate::consensus::native) fn read_row(
    reader: &mut dyn Read,
    length: u32,
    root: &RosterAttestationTrustRootV1,
    scope: &MembershipValidationScope,
) -> io::Result<carrier::Hydration> {
    if !(ROW_HEADER..=MAX_ROW).contains(&(length as usize)) {
        return Err(invalid("native roster selected frame length invalid"));
    }
    let _metadata = VerificationMemory::reserve(METADATA_MEMORY)?;
    let mut header = [0; ROW_HEADER];
    reader.read_exact(&mut header)?;
    if &header[..8] != ROW_MAGIC {
        return Err(invalid("native roster frame discriminator differs"));
    }
    let binding = RequestBindingKey::from_bytes(
        header[8..128]
            .try_into()
            .map_err(|_| invalid("native roster binding length differs"))?,
    )
    .map_err(|_| invalid("native roster frame binding invalid"))?;
    let projection_len = usize::from(u16::from_be_bytes([header[128], header[129]]));
    let canonical_len =
        u32::from_be_bytes([header[130], header[131], header[132], header[133]]) as usize;
    if row_length(projection_len, canonical_len)? != length {
        return Err(invalid("native roster frame extent differs"));
    }
    let mut input = [0; PROJECTION_BYTES];
    reader.read_exact(&mut input[..projection_len])?;
    let projection: Projection = postcard::from_bytes(&input[..projection_len])
        .map_err(|_| invalid("native roster frame projection invalid"))?;
    let mut encoded = [0; PROJECTION_BYTES];
    if projection_bytes(&projection, &mut encoded)? != &input[..projection_len] {
        return Err(invalid("native roster frame projection is not canonical"));
    }
    let _input = VerificationMemory::reserve(canonical_len)?;
    let mut canonical = Vec::new();
    canonical
        .try_reserve_exact(canonical_len)
        .map_err(|_| invalid("native roster frame input allocation failed"))?;
    canonical.resize(canonical_len, 0);
    reader.read_exact(&mut canonical)?;
    carrier::hydrate(projection, binding, canonical, root, scope)
        .map_err(|_| invalid("native roster frame carrier authentication failed"))
}

fn partition_length(floor: usize, cursor: usize) -> io::Result<u32> {
    if floor == 0
        || floor > MAX_HISTORY_FLOOR_CODEC_BYTES
        || cursor > MAX_RETIREMENT_CURSOR_CODEC_BYTES
    {
        return Err(invalid(
            "native roster partition component exceeds its bound",
        ));
    }
    u32::try_from(PARTITION_HEADER + floor + cursor)
        .map_err(|_| invalid("native roster partition length overflow"))
}

pub(in crate::consensus::native) fn write_partition(
    writer: &mut dyn Write,
    key: ProductionFloorKey,
    partition: &Partition,
) -> io::Result<u32> {
    let _memory = VerificationMemory::reserve(METADATA_MEMORY)?;
    partition.validate(key)?;
    let floor = partition
        .floor
        .to_canonical_bytes()
        .map_err(|_| invalid("native roster floor cannot encode"))?;
    let cursor = partition
        .cursor
        .as_ref()
        .map(ProductionRetirementCursor::to_canonical_bytes)
        .transpose()
        .map_err(|_| invalid("native roster cursor cannot encode"))?
        .unwrap_or_default();
    let length = partition_length(floor.len(), cursor.len())?;
    writer.write_all(PARTITION_MAGIC)?;
    writer.write_all(key.as_bytes())?;
    writer.write_all(&(floor.len() as u16).to_be_bytes())?;
    writer.write_all(&(cursor.len() as u16).to_be_bytes())?;
    writer.write_all(&floor)?;
    writer.write_all(&cursor)?;
    Ok(length)
}

pub(in crate::consensus::native) fn read_partition(
    reader: &mut dyn Read,
    length: u32,
) -> io::Result<(ProductionFloorKey, Partition)> {
    if !(PARTITION_HEADER..=MAX_PARTITION).contains(&(length as usize)) {
        return Err(invalid("native roster partition extent invalid"));
    }
    let _memory = VerificationMemory::reserve(METADATA_MEMORY)?;
    let mut header = [0; PARTITION_HEADER];
    reader.read_exact(&mut header)?;
    if &header[..8] != PARTITION_MAGIC {
        return Err(invalid("native roster partition discriminator differs"));
    }
    let key = ProductionFloorKey::from_bytes(
        header[8..72]
            .try_into()
            .map_err(|_| invalid("native roster partition key length differs"))?,
    )
    .map_err(|_| invalid("native roster partition key invalid"))?;
    let floor_len = usize::from(u16::from_be_bytes([header[72], header[73]]));
    let cursor_len = usize::from(u16::from_be_bytes([header[74], header[75]]));
    if partition_length(floor_len, cursor_len)? != length {
        return Err(invalid(
            "native roster partition components differ from extent",
        ));
    }
    let mut floor = [0; MAX_HISTORY_FLOOR_CODEC_BYTES];
    reader.read_exact(&mut floor[..floor_len])?;
    let floor = IrreversibleHistoryFloor::from_canonical_bytes(&floor[..floor_len])
        .map_err(|_| invalid("native roster canonical floor invalid"))?;
    let cursor = if cursor_len == 0 {
        None
    } else {
        let mut cursor = [0; MAX_RETIREMENT_CURSOR_CODEC_BYTES];
        reader.read_exact(&mut cursor[..cursor_len])?;
        Some(
            ProductionRetirementCursor::from_canonical_bytes(&cursor[..cursor_len])
                .map_err(|_| invalid("native roster canonical cursor invalid"))?,
        )
    };
    let partition = Partition { floor, cursor };
    partition.validate(key)?;
    Ok((key, partition))
}
