//! Bounded physical fragments for one complete ordered operation.
//!
//! Append entries retain their existing allocations. Neither admission nor
//! the writer concatenates a legal 64-by-16-MiB append into another buffer.
//! Recovery accumulates at most one independently bounded entry at a time.

use bytes::Bytes;
use std::io::{self, Read};

use super::super::SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES;
use super::{decode_json, encode_json, invalid_data, Operation, MAX_ENTRIES};

pub(super) const MAX_RECORD: usize = 5 + MAX_ENTRIES * (4 + SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES);
pub(super) const MAX_FRAGMENT: usize = 1024 * 1024;
const MAX_METADATA: usize = 1024;

pub(in crate::sqlite::consensus) struct Record {
    chunks: Vec<Bytes>,
    len: usize,
}

impl Record {
    pub(super) fn encode(operation: &Operation) -> io::Result<Self> {
        let mut chunks = Vec::new();
        match operation {
            Operation::Append(entries) => {
                if entries.is_empty() || entries.len() > MAX_ENTRIES {
                    return Err(invalid_data("private WAL append count exceeds limit"));
                }
                let mut prefix = vec![1];
                prefix.extend_from_slice(&(entries.len() as u32).to_le_bytes());
                chunks.push(Bytes::from(prefix));
                for entry in entries {
                    if entry.is_empty() || entry.len() > SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES {
                        return Err(invalid_data("private WAL entry size exceeds limit"));
                    }
                    chunks.push(Bytes::copy_from_slice(&(entry.len() as u32).to_le_bytes()));
                    chunks.push(entry.clone());
                }
            }
            operation => {
                let (tag, body) = match operation {
                    Operation::Vote(value) => (2, encode_json(value)?),
                    Operation::Committed(value) => (3, encode_json(value)?),
                    Operation::Truncate(value) => (4, encode_json(value)?),
                    Operation::Purge(value) => (5, encode_json(value)?),
                    Operation::Barrier => (6, Vec::new()),
                    Operation::Append(_) => unreachable!(),
                };
                if body.len() > MAX_METADATA {
                    return Err(invalid_data("private WAL metadata size exceeds limit"));
                }
                chunks.push(Bytes::from(vec![tag]));
                if !body.is_empty() {
                    chunks.push(Bytes::from(body));
                }
            }
        }
        let len = chunks.iter().try_fold(0_usize, |total, chunk| {
            total
                .checked_add(chunk.len())
                .filter(|total| *total <= MAX_RECORD)
                .ok_or_else(|| invalid_data("private WAL operation exceeds limit"))
        })?;
        Ok(Self { chunks, len })
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    pub(super) fn charge(&self, fragment: usize) -> io::Result<usize> {
        self.len
            .div_ceil(fragment)
            .checked_mul(super::FRAME_HEADER)
            .and_then(|headers| self.len.checked_add(headers))
            .ok_or_else(|| invalid_data("private WAL fragment charge exceeds limit"))
    }

    pub(super) fn reader(&self) -> RecordReader<'_> {
        RecordReader {
            record: self,
            chunk: 0,
            offset: 0,
        }
    }

    #[cfg(test)]
    pub(in crate::sqlite::consensus) fn to_vec(&self) -> Vec<u8> {
        self.chunks.concat()
    }
}

pub(super) struct RecordReader<'a> {
    record: &'a Record,
    chunk: usize,
    offset: usize,
}

impl Read for RecordReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let mut written = 0;
        while written < output.len() {
            let Some(chunk) = self.record.chunks.get(self.chunk) else {
                break;
            };
            let count = (chunk.len() - self.offset).min(output.len() - written);
            output[written..written + count]
                .copy_from_slice(&chunk[self.offset..self.offset + count]);
            written += count;
            self.offset += count;
            if self.offset == chunk.len() {
                self.chunk += 1;
                self.offset = 0;
            }
        }
        Ok(written)
    }
}

enum Stage {
    Tag,
    Count,
    Length,
    Entry,
    Metadata(u8),
    Done,
}

pub(super) struct Decoder {
    total: usize,
    received: usize,
    stage: Stage,
    pending: Vec<u8>,
    wanted: usize,
    count: usize,
    entries: Vec<Bytes>,
    result: Option<Operation>,
}

impl Decoder {
    pub(super) fn new(total: usize) -> io::Result<Self> {
        if total == 0 || total > MAX_RECORD {
            return Err(invalid_data("private WAL operation length exceeds limit"));
        }
        Ok(Self {
            total,
            received: 0,
            stage: Stage::Tag,
            pending: Vec::new(),
            wanted: 1,
            count: 0,
            entries: Vec::new(),
            result: None,
        })
    }

    pub(super) fn received(&self) -> usize {
        self.received
    }
    pub(super) fn total(&self) -> usize {
        self.total
    }

    pub(super) fn push(&mut self, mut input: &[u8]) -> io::Result<()> {
        if input.len() > self.total - self.received {
            return Err(invalid_data("private WAL fragment exceeds operation"));
        }
        while !input.is_empty() {
            if matches!(self.stage, Stage::Done) {
                return Err(invalid_data("private WAL operation has trailing bytes"));
            }
            let count = (self.wanted - self.pending.len()).min(input.len());
            self.pending.extend_from_slice(&input[..count]);
            input = &input[count..];
            self.received += count;
            if self.pending.len() != self.wanted {
                continue;
            }
            let value = std::mem::take(&mut self.pending);
            match self.stage {
                Stage::Tag => match value[0] {
                    1 => {
                        self.stage = Stage::Count;
                        self.wanted = 4;
                    }
                    tag @ 2..=5 if (2..=MAX_METADATA + 1).contains(&self.total) => {
                        self.stage = Stage::Metadata(tag);
                        self.wanted = self.total - 1;
                    }
                    6 if self.total == 1 => {
                        self.result = Some(Operation::Barrier);
                        self.stage = Stage::Done;
                    }
                    _ => return Err(invalid_data("private WAL record kind or size is invalid")),
                },
                Stage::Count => {
                    self.count = u32::from_le_bytes(
                        value
                            .try_into()
                            .map_err(|_| invalid_data("private WAL count length"))?,
                    ) as usize;
                    if self.count == 0 || self.count > MAX_ENTRIES {
                        return Err(invalid_data("private WAL append count exceeds limit"));
                    }
                    self.stage = Stage::Length;
                    self.wanted = 4;
                }
                Stage::Length => {
                    self.wanted = u32::from_le_bytes(
                        value
                            .try_into()
                            .map_err(|_| invalid_data("private WAL entry length"))?,
                    ) as usize;
                    if self.wanted == 0
                        || self.wanted > SQLITE_CONSENSUS_LOG_ENTRY_MAX_BYTES
                        || self.wanted > self.total - self.received
                    {
                        return Err(invalid_data("private WAL entry size exceeds operation"));
                    }
                    self.stage = Stage::Entry;
                    self.pending = Vec::with_capacity(self.wanted);
                }
                Stage::Entry => {
                    self.entries.push(Bytes::from(value));
                    if self.entries.len() == self.count {
                        self.stage = Stage::Done;
                    } else {
                        self.stage = Stage::Length;
                        self.wanted = 4;
                    }
                }
                Stage::Metadata(tag) => {
                    let operation = match tag {
                        2 => Operation::Vote(decode_json(&value)?),
                        3 => Operation::Committed(decode_json(&value)?),
                        4 => Operation::Truncate(decode_json(&value)?),
                        5 => Operation::Purge(decode_json(&value)?),
                        _ => unreachable!(),
                    };
                    let encoded = Record::encode(&operation)?;
                    if encoded.len != self.total
                        || encoded.chunks.get(1).map(Bytes::as_ref) != Some(value.as_slice())
                    {
                        return Err(invalid_data("private WAL metadata encoding is not exact"));
                    }
                    self.result = Some(operation);
                    self.stage = Stage::Done;
                }
                Stage::Done => unreachable!(),
            }
        }
        Ok(())
    }

    pub(super) fn finish(self) -> io::Result<Operation> {
        if self.received != self.total || !matches!(self.stage, Stage::Done) {
            return Err(invalid_data("private WAL operation is incomplete"));
        }
        match self.result {
            Some(operation) => Ok(operation),
            None if self.entries.len() == self.count && self.count != 0 => {
                Ok(Operation::Append(self.entries))
            }
            None => Err(invalid_data("private WAL operation lacks result")),
        }
    }
}
