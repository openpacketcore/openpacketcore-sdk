//! Exact compact JSON transcripts with bounded serialization scratch.

use serde::Serialize;
use sha2::digest::Update;
use std::io::{self, Write};

pub(super) struct ByteCount {
    pub(super) bytes: usize,
    limit: usize,
}

impl ByteCount {
    pub(super) fn new(limit: usize) -> Self {
        Self { bytes: 0, limit }
    }
}

impl Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// Serde's byte-array callback emits the same unsigned decimal array as Vec<u8>.
// Batch just that callback; every other token uses the stock compact formatter.
struct Formatter;
impl serde_json::ser::Formatter for Formatter {
    fn write_byte_array<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        bytes: &[u8],
    ) -> io::Result<()> {
        writer.write_all(b"[")?;
        let mut buffer = [0; 1024];
        let mut used = 0;
        for (index, byte) in bytes.iter().copied().enumerate() {
            if buffer.len() - used < 4 {
                writer.write_all(&buffer[..used])?;
                used = 0;
            }
            if index != 0 {
                buffer[used] = b',';
                used += 1;
            }
            if byte >= 100 {
                buffer[used] = b'0' + byte / 100;
                buffer[used + 1] = b'0' + (byte / 10) % 10;
                used += 2;
            } else if byte >= 10 {
                buffer[used] = b'0' + byte / 10;
                used += 1;
            }
            buffer[used] = b'0' + byte % 10;
            used += 1;
        }
        writer.write_all(&buffer[..used])?;
        writer.write_all(b"]")
    }
}

pub(super) fn to_writer<W: Write, T: Serialize + ?Sized>(
    writer: W,
    value: &T,
) -> serde_json::Result<()> {
    value.serialize(&mut serde_json::Serializer::with_formatter(
        writer, Formatter,
    ))
}

// Buffer scalar writes too, without retaining an expanded JSON transcript.
struct DigestWriter<'a, D> {
    digest: &'a mut D,
    buffer: [u8; 4096],
    used: usize,
}

impl<D: Update> Write for DigestWriter<'_, D> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let length = bytes.len();
        while !bytes.is_empty() {
            let count = bytes.len().min(self.buffer.len() - self.used);
            self.buffer[self.used..self.used + count].copy_from_slice(&bytes[..count]);
            self.used += count;
            bytes = &bytes[count..];
            if self.used == self.buffer.len() {
                self.flush()?;
            }
        }
        Ok(length)
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.used != 0 {
            self.digest.update(&self.buffer[..self.used]);
            self.used = 0;
        }
        Ok(())
    }
}

pub(super) fn digest_json<D: Update, T: Serialize + ?Sized>(
    digest: &mut D,
    value: &T,
) -> serde_json::Result<()> {
    let mut writer = DigestWriter {
        digest,
        buffer: [0; 4096],
        used: 0,
    };
    to_writer(&mut writer, value)?;
    writer
        .flush()
        .map_err(<serde_json::Error as serde::ser::Error>::custom)
}

#[cfg(test)]
mod tests;
