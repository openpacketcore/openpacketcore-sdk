//! Compact JSON with bounded writes for the closed configuration byte payload.
//! Field encodings and numeric arrays are unchanged; existing sinks retain
//! their own capacity, cancellation and digest rules.

use serde::Serialize;
use std::io;

struct ConfigJsonFormatter;

impl serde_json::ser::Formatter for ConfigJsonFormatter {
    fn write_byte_array<W: ?Sized + io::Write>(
        &mut self,
        writer: &mut W,
        value: &[u8],
    ) -> io::Result<()> {
        writer.write_all(b"[")?;
        // At most1024 encoded bytes between sink checks, with no heap buffer.
        // A value needs at most one comma and three unsigned decimal digits.
        let mut buffer = [0_u8; 1024];
        let mut used = 0;
        for (index, byte) in value.iter().copied().enumerate() {
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
        writer.write_all(&buffer[..used])?;
        writer.write_all(b"]")
    }
}

pub(super) fn to_writer<W: io::Write, T: Serialize + ?Sized>(
    writer: W,
    value: &T,
) -> serde_json::Result<()> {
    value.serialize(&mut serde_json::Serializer::with_formatter(
        writer,
        ConfigJsonFormatter,
    ))
}

#[cfg(test)]
#[path = "config_capacity_json_tests.rs"]
mod tests;
