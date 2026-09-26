//! Decode the existing canonical numeric byte array without per-byte Serde
//! dispatch. Complete canonical equality is required before this path returns;
//! other representations retain the original bounded decoder and validation.

use std::io::{self, Read, Write};

use opc_consensus::engine::{Entry, EntryPayload};
use opc_crypto::CONFIG_CAPACITY_V1_ENVELOPE_BYTES;

use super::{ConfigRaftTypeConfig, EntryFields};
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

struct MatchesInput<'a>(&'a [u8]);

impl Write for MatchesInput<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if !self.0.starts_with(bytes) {
            return Err(invalid());
        }
        self.0 = &self.0[bytes.len()..];
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
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
    let Ok(fields) = serde_json::from_reader::<_, EntryFields>(reader) else {
        return Ok(None);
    };
    let mut entry: Entry<ConfigRaftTypeConfig> = fields.into();
    let EntryPayload::Normal(command) = &mut entry.payload else {
        return Ok(None);
    };
    let ConfigMutationIntent::BoundedAppend { commit, .. } = &mut command.intent else {
        return Ok(None);
    };
    if !commit.record.encrypted_blob.is_empty() {
        return Ok(None);
    }
    // The fixed envelope ceiling and complete count precede this allocation.
    // Fill exactly that count from the same immutable borrowed input.
    let output = &mut commit.record.encrypted_blob;
    output.try_reserve_exact(count).map_err(|_| invalid())?;
    let mut index = start + 1;
    for _ in 0..count {
        output.push(decimal_byte(bytes, &mut index).ok_or_else(invalid)?);
        index += 1;
    }
    if index != end {
        return Err(invalid());
    }
    // This binds the selected span to its exact typed field and rejects every
    // speculative mismatch, duplicate/unknown field, alias or reordered form.
    // Any mismatch falls back to the original parser with original input;
    // no speculative object or owning ciphertext survives that fallback.
    let mut compare = MatchesInput(bytes);
    if crate::consensus::config_capacity_json::to_writer(&mut compare, &entry).is_err()
        || !compare.0.is_empty()
    {
        return Ok(None);
    }
    Ok(Some(entry))
}

pub(super) fn entry(bytes: &[u8]) -> io::Result<Entry<ConfigRaftTypeConfig>> {
    super::native_json_preflight(bytes)?;
    if let Some(entry) = canonical_entry(bytes)? {
        return Ok(entry);
    }
    serde_json::from_slice::<EntryFields>(bytes)
        .map(Into::into)
        .map_err(|_| invalid())
}

#[cfg(test)]
#[path = "config_capacity_native_json_tests.rs"]
mod tests;
