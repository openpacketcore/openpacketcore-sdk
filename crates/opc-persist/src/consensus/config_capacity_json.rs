//! Compact JSON with bounded byte-array writes.
//! Field encodings and numeric arrays are unchanged; existing sinks retain
//! their own capacity, cancellation and digest rules.

use serde::Serialize;
use std::io;

const BYTE_ARRAY_BATCH_BYTES: usize = 1024;
// serde_json::to_vec starts at 128 bytes. Audit uses batches no larger than
// that initial capacity, retaining the original Vec capacity growth sequence.
const AUDIT_BYTE_ARRAY_BATCH_BYTES: usize = 128;

struct ConfigJsonFormatter<const COUNT_ONLY: bool, const BATCH_BYTES: usize>;

impl<const COUNT_ONLY: bool, const BATCH_BYTES: usize> serde_json::ser::Formatter
    for ConfigJsonFormatter<COUNT_ONLY, BATCH_BYTES>
{
    fn write_byte_array<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        value: &[u8],
    ) -> io::Result<()> {
        if COUNT_ONLY {
            return count_byte_array(writer, value);
        }
        writer.write_all(b"[")?;
        // At most BATCH_BYTES encoded bytes between sink checks, with no heap buffer.
        // A value needs at most one comma and three unsigned decimal digits.
        let mut buffer = [0_u8; BATCH_BYTES];
        let mut used = 0;
        for (index, byte) in value.iter().copied().enumerate() {
            if buffer.len() - used < 4 {
                #[cfg(test)]
                tests::record_emitted_batch(used);
                writer.write_all(&buffer[..used])?;
                used = 0;
            }
            if index != 0 {
                buffer[used] = b',';
                used += 1;
            }
            if byte >= 100 {
                buffer[used] = b'0' + byte / 100;
                used += 1;
                buffer[used] = b'0' + (byte / 10) % 10;
                used += 1;
            } else if byte >= 10 {
                buffer[used] = b'0' + byte / 10;
                used += 1;
            }
            buffer[used] = b'0' + byte % 10;
            used += 1;
        }
        #[cfg(test)]
        tests::record_emitted_batch(used);
        writer.write_all(&buffer[..used])?;
        writer.write_all(b"]")
    }
}

// Only byte-array widths differ from the emitting formatter. All other JSON
// tokens still use serde_json's compact formatter and the original sink.
fn count_byte_array<W: ?Sized + io::Write>(writer: &mut W, value: &[u8]) -> io::Result<()> {
    static COUNTED_BYTES: [u8; BYTE_ARRAY_BATCH_BYTES] = [0; BYTE_ARRAY_BATCH_BYTES];

    writer.write_all(b"[")?;
    let mut used = 0_usize;
    for (index, byte) in value.iter().copied().enumerate() {
        // Match the emitting formatter's checkpoints exactly, including its
        // worst-case four-byte reservation before each value. The sink keeps
        // checking cancellation, overflow and limits every <=1024 bytes.
        if COUNTED_BYTES.len() - used < 4 {
            writer.write_all(&COUNTED_BYTES[..used])?;
            used = 0;
        }
        let width =
            1 + usize::from(byte >= 10) + usize::from(byte >= 100) + usize::from(index != 0);
        used = used
            .checked_add(width)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    }
    writer.write_all(&COUNTED_BYTES[..used])?;
    writer.write_all(b"]")
}

/// Count canonical JSON through a sink that observes lengths only. Byte-array
/// chunks contain inert bytes, so this must never be used for output or hashes.
pub(super) fn count_to_writer<W: io::Write, T: Serialize + ?Sized>(
    writer: W,
    value: &T,
) -> serde_json::Result<()> {
    value.serialize(&mut serde_json::Serializer::with_formatter(
        writer,
        ConfigJsonFormatter::<true, BYTE_ARRAY_BATCH_BYTES>,
    ))
}

pub(super) fn to_writer<W: io::Write, T: Serialize + ?Sized>(
    writer: W,
    value: &T,
) -> serde_json::Result<()> {
    value.serialize(&mut serde_json::Serializer::with_formatter(
        writer,
        ConfigJsonFormatter::<false, BYTE_ARRAY_BATCH_BYTES>,
    ))
}

/// Emit unchanged JSON in one pass for an audit Vec starting at 128 bytes.
/// Each byte-array batch is at most the current Vec capacity, so it can cross
/// at most one growth boundary. All non-byte-array writes remain unchanged.
/// This preserves the original growth sequence as well as the final capacity.
pub(crate) fn to_audit_writer<W: io::Write, T: Serialize + ?Sized>(
    writer: W,
    value: &T,
) -> serde_json::Result<()> {
    value.serialize(&mut serde_json::Serializer::with_formatter(
        writer,
        ConfigJsonFormatter::<false, AUDIT_BYTE_ARRAY_BATCH_BYTES>,
    ))
}

#[cfg(test)]
#[path = "config_capacity_json_tests.rs"]
pub(super) mod tests;
