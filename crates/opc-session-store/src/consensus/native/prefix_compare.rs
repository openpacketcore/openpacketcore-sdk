//! Byte-for-byte expected readback with one zeroizing 8 KiB buffer.

use super::*;

pub(crate) struct CompareWriter<'a> {
    reader: &'a mut dyn Read,
    // Canonical framing emits many one-byte writes. Batch authenticated reads
    // in one bounded buffer and erase it when the comparison finishes.
    actual: Zeroizing<[u8; 8192]>,
    pub(in crate::consensus::native) position: usize,
    pub(in crate::consensus::native) available: usize,
}

impl<'a> CompareWriter<'a> {
    pub(crate) fn new(reader: &'a mut dyn Read) -> Self {
        Self {
            reader,
            actual: Zeroizing::new([0; 8192]),
            position: 0,
            available: 0,
        }
    }
}

impl Write for CompareWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            if self.position == self.available {
                self.position = 0;
                self.available = 0;
                self.available = loop {
                    match self.reader.read(&mut *self.actual) {
                        Ok(0) => {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "native base readback ended before captured state",
                            ));
                        }
                        Ok(count) => break count,
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => return Err(error),
                    }
                };
            }
            let count = (self.available - self.position).min(remaining.len());
            if self.actual[self.position..self.position + count] != remaining[..count] {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "native base bytes differ from captured state",
                ));
            }
            self.position += count;
            remaining = &remaining[count..];
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
