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
use crate::consensus::types::ConfigMutationIntent;

const FIELD: &[u8] = b"\"encrypted_blob\":";
const MIN_FAST_BYTES: usize = 4096;

fn invalid() -> io::Error {
    crate::consensus::sqlite::invalid_data("invalid bounded config consensus encoding")
}

// Match the three canonical unsigned-byte token widths directly. Both passes
// still validate every value and delimiter before any decoded entry escapes;
// the complete first pass bounds and validates the ciphertext before allocation.
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
// Both complete token passes have already established that `encoded` is the
// canonical representation of this exact immutable `decoded` buffer.
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
    let Some((extent, count)) = array_extent(&bytes[start..]) else {
        return Ok(None);
    };
    if count < MIN_FAST_BYTES {
        return Ok(None);
    }
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
    // The fixed envelope ceiling and complete count precede this allocation.
    // Fill exactly that count from the same immutable borrowed input.
    output.try_reserve_exact(count).map_err(|_| invalid())?;
    let mut index = start + 1;
    for _ in 0..count {
        output.push(decimal_byte(bytes, &mut index).ok_or_else(invalid)?);
        index += 1;
    }
    if index != end {
        return Err(invalid());
    }
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
    super::native_json_preflight(bytes)?;
    if let Some(entry) = canonical_entry(bytes)? {
        #[cfg(all(test, target_os = "linux"))]
        crate::consensus::store::config_capacity_cost_observation::native_decoded(&entry, true);
        return Ok(entry);
    }
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
