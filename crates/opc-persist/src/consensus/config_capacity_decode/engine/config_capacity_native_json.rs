//! Decode the existing canonical numeric byte array without per-byte Serde
//! dispatch. Complete canonical equality is required before this path returns;
//! other representations retain the original bounded decoder and validation.

use std::io::{self, Read, Write};

use opc_consensus::engine::{Entry, EntryPayload};
use opc_crypto::CONFIG_CAPACITY_V1_ENVELOPE_BYTES;
use serde::Serialize;
use serde_json::ser::Formatter;

use super::super::{Effect, Intent};
use super::{ConfigRaftTypeConfig, EntryFields, Payload};
use crate::consensus::audit_mutation::AuditedConfigEffect;
#[cfg(all(test, target_os = "linux"))]
use crate::consensus::storage::config_capacity_native_read_observations as native_io;
use crate::consensus::types::ConfigMutationIntent;

const FIELD: &[u8] = b"\"encrypted_blob\":";
const MIN_FAST_BYTES: usize = 4096;

fn invalid() -> io::Error {
    crate::consensus::sqlite::invalid_data("invalid bounded config consensus encoding")
}

// Match the three canonical unsigned-byte token widths directly. The complete
// first pass bounds and validates every ciphertext value and delimiter before
// allocation. Only that immutable validated span may use the specialized fill.
fn decimal_byte(bytes: &[u8], index: &mut usize) -> Option<u8> {
    let (value, digits) = match bytes.get(*index..)? {
        [first @ b'1'..=b'2', second @ b'0'..=b'9', third @ b'0'..=b'9', b',' | b']', ..] => {
            let value = u16::from(*first - b'0') * 100
                + u16::from(*second - b'0') * 10
                + u16::from(*third - b'0');
            (u8::try_from(value).ok()?, 3)
        }
        [first @ b'1'..=b'9', second @ b'0'..=b'9', b',' | b']', ..] => {
            ((*first - b'0') * 10 + (*second - b'0'), 2)
        }
        [digit @ b'0'..=b'9', b',' | b']', ..] => (*digit - b'0', 1),
        _ => return None,
    };
    *index += digits;
    Some(value)
}

fn array_extent(bytes: &[u8]) -> Option<(usize, usize)> {
    if bytes.first().copied()? != b'[' {
        return None;
    }
    if bytes.get(1) == Some(&b']') {
        return Some((2, 0));
    }
    let mut index = 1;
    let mut count = 0;
    loop {
        decimal_byte(bytes, &mut index)?;
        count += 1;
        if count > CONFIG_CAPACITY_V1_ENVELOPE_BYTES {
            return None;
        }
        match bytes.get(index).copied()? {
            b']' => return Some((index + 1, count)),
            b',' => index += 1,
            _ => return None,
        }
    }
}

// The constructor is the only production source of this borrowed descriptor.
// Its complete, allocation-free preflight proves the token grammar, exact count
// and envelope bound before either metadata parsing or ciphertext allocation.
// This descriptor borrows one row only; it never caches a decoded entry.
struct ValidatedArray<'a> {
    encoded: &'a [u8],
    count: usize,
}

impl<'a> ValidatedArray<'a> {
    fn new(bytes: &'a [u8]) -> Option<Self> {
        let (extent, count) = array_extent(bytes)?;
        Some(Self {
            encoded: bytes.get(..extent)?,
            count,
        })
    }

    fn fill(self, output: &mut Vec<u8>) -> io::Result<()> {
        if !output.is_empty() {
            return Err(invalid());
        }
        // The descriptor owns no buffer. Reserve exactly the fully validated
        // count, after the original bounded metadata DTO has selected its field.
        output
            .try_reserve_exact(self.count)
            .map_err(|_| invalid())?;
        let mut remaining = self.encoded.strip_prefix(b"[").ok_or_else(invalid)?;
        if self.count == 0 {
            if remaining != b"]" {
                return Err(invalid());
            }
            remaining = &[];
        }
        for _ in 0..self.count {
            // The first pass proved that each non-delimiter byte is an ASCII
            // decimal digit, so its low nibble is its exact numeric value.
            // Shortest-first matching prevents crossing a one-byte token's
            // delimiter while looking for a wider token. All reads are checked
            // slice patterns; even the three-nibble arithmetic fits in u16.
            let (value, rest) = match remaining {
                [first, b',' | b']', rest @ ..] => (*first & 0x0f, rest),
                [first, second, b',' | b']', rest @ ..] => {
                    ((*first & 0x0f) * 10 + (*second & 0x0f), rest)
                }
                [first, second, third, b',' | b']', rest @ ..] => {
                    let value = u16::from(*first & 0x0f) * 100
                        + u16::from(*second & 0x0f) * 10
                        + u16::from(*third & 0x0f);
                    (u8::try_from(value).map_err(|_| invalid())?, rest)
                }
                _ => return Err(invalid()),
            };
            output.push(value);
            remaining = rest;
        }
        if !remaining.is_empty() || output.len() != self.count {
            return Err(invalid());
        }
        #[cfg(test)]
        tests::record_validated_fill(output.len());
        Ok(())
    }
}

struct MatchesInput<'a> {
    remaining: &'a [u8],
    #[cfg(all(test, target_os = "linux"))]
    writes: usize,
    #[cfg(all(test, target_os = "linux"))]
    largest_write: usize,
}

impl<'a> MatchesInput<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            remaining: bytes,
            #[cfg(all(test, target_os = "linux"))]
            writes: 0,
            #[cfg(all(test, target_os = "linux"))]
            largest_write: 0,
        }
    }
}

impl Write for MatchesInput<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.remaining.starts_with(bytes) {
            return Err(invalid());
        }
        self.remaining = &self.remaining[bytes.len()..];
        #[cfg(all(test, target_os = "linux"))]
        {
            self.writes += 1;
            self.largest_write = self.largest_write.max(bytes.len());
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// This formatter is only used by the in-memory canonical-equality sink. It
// does not replace the bounded/cancellable writers used by append or apply.
// Complete token validation followed by the bounded fill has established that
// `encoded` is the canonical representation of this exact immutable `decoded`
// buffer. The independent codec tests cover every adjacent byte-value pair.
struct CanonicalCiphertext<'a> {
    decoded: &'a [u8],
    encoded: &'a [u8],
    emitted: &'a mut bool,
}

impl Formatter for CanonicalCiphertext<'_> {
    fn write_byte_array<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        value: &[u8],
    ) -> io::Result<()> {
        // Pointer-and-length identity binds reuse to the selected typed field;
        // another byte field, even with equal values, is serialized normally.
        if std::ptr::eq(value, self.decoded) {
            if *self.emitted {
                return Err(invalid());
            }
            *self.emitted = true;
            return writer.write_all(self.encoded);
        }
        serde_json::ser::CompactFormatter.write_byte_array(writer, value)
    }
}

fn ciphertext(entry: &Entry<ConfigRaftTypeConfig>) -> Option<&[u8]> {
    let EntryPayload::Normal(command) = &entry.payload else {
        return None;
    };
    match &command.intent {
        ConfigMutationIntent::BoundedAppend { commit, .. } => Some(&commit.record.encrypted_blob),
        ConfigMutationIntent::AuditedMutation(prepared) => match &prepared.effect {
            AuditedConfigEffect::BoundedAppend { commit, .. } => {
                Some(&commit.record.encrypted_blob)
            }
            _ => None,
        },
        _ => None,
    }
}

fn canonical_entry(bytes: &[u8]) -> io::Result<Option<Entry<ConfigRaftTypeConfig>>> {
    let Some(key) = bytes.windows(FIELD.len()).position(|part| part == FIELD) else {
        return Ok(None);
    };
    let start = key + FIELD.len();
    let Some(array) = ValidatedArray::new(&bytes[start..]) else {
        return Ok(None);
    };
    let extent = array.encoded.len();
    let count = array.count;
    if count < MIN_FAST_BYTES {
        return Ok(None);
    }
    #[cfg(all(test, target_os = "linux"))]
    native_io::canonical_span(extent, count);
    let end = start + extent;
    // Parse every other field with the original bounded DTO. This borrowed
    // reader allocates no second JSON document. Its parser scratch is dropped
    // before reserving the ciphertext. No field name search confers authority.
    let reader = bytes[..start].chain(b"[]".as_slice()).chain(&bytes[end..]);
    let Ok(mut fields) = serde_json::from_reader::<_, EntryFields>(reader) else {
        return Ok(None);
    };
    let Payload::Normal(command) = &mut fields.payload else {
        return Ok(None);
    };
    // Select the exact bounded field before conversion creates an immutable
    // audited command. Both forms still require complete canonical equality.
    let output = match &mut command.intent {
        Intent::BoundedAppend { commit, .. } => &mut commit.record.encrypted_blob.0,
        Intent::AuditedMutation(prepared) => match &mut prepared.effect {
            Effect::BoundedAppend { commit, .. } => &mut commit.record.encrypted_blob.0,
            _ => return Ok(None),
        },
        _ => return Ok(None),
    };
    if !output.is_empty() {
        return Ok(None);
    }
    // Reuse only the first pass's immutable, fully validated span. This fill
    // maps its decimal digits without repeating the full token classification.
    array.fill(output)?;
    let entry: Entry<ConfigRaftTypeConfig> = fields.into();
    // This binds the selected span to its exact typed field and rejects every
    // speculative mismatch, duplicate/unknown field, alias or reordered form.
    // Any mismatch falls back to the original parser with original input;
    // no speculative object or owning ciphertext survives that fallback.
    let Some(decoded) = ciphertext(&entry) else {
        return Ok(None);
    };
    if decoded.len() != count {
        return Err(invalid());
    }
    let mut emitted = false;
    let formatter = CanonicalCiphertext {
        decoded,
        encoded: &bytes[start..end],
        emitted: &mut emitted,
    };
    let mut compare = MatchesInput::new(bytes);
    let result = entry.serialize(&mut serde_json::Serializer::with_formatter(
        &mut compare,
        formatter,
    ));
    if result.is_err() || !emitted || !compare.remaining.is_empty() {
        return Ok(None);
    }
    #[cfg(all(test, target_os = "linux"))]
    crate::consensus::store::config_capacity_cost_observation::native_canonical_compared(
        &entry,
        extent,
        compare.writes,
        compare.largest_write,
    );
    Ok(Some(entry))
}

pub(super) fn entry(bytes: &[u8]) -> io::Result<Entry<ConfigRaftTypeConfig>> {
    #[cfg(all(test, target_os = "linux"))]
    native_io::phase(native_io::Phase::JsonPreflightBegin);
    super::native_json_preflight(bytes)?;
    #[cfg(all(test, target_os = "linux"))]
    native_io::phase(native_io::Phase::JsonPreflightReturned);
    #[cfg(all(test, target_os = "linux"))]
    native_io::phase(native_io::Phase::CanonicalBegin);

    if let Some(entry) = canonical_entry(bytes)? {
        #[cfg(all(test, target_os = "linux"))]
        native_io::route(native_io::Route::Canonical);
        #[cfg(all(test, target_os = "linux"))]
        crate::consensus::store::config_capacity_cost_observation::native_decoded(&entry, true);
        return Ok(entry);
    }
    #[cfg(all(test, target_os = "linux"))]
    native_io::route(native_io::Route::Fallback);
    let entry = serde_json::from_slice::<EntryFields>(bytes)
        .map(Into::into)
        .map_err(|_| invalid())?;
    #[cfg(all(test, target_os = "linux"))]
    crate::consensus::store::config_capacity_cost_observation::native_decoded(&entry, false);
    Ok(entry)
}

#[cfg(test)]
#[path = "config_capacity_native_json_tests.rs"]
mod tests;
