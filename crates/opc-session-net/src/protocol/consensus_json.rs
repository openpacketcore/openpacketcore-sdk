//! Preserve legacy JSON bytes while borrowing the ordinary request payload.

use super::*;
use std::io::{self, Write};

pub(super) struct BorrowedRequest<'a>(pub(super) &'a SessionConsensusTransportRequest);
struct BorrowedWire<'a>(&'a SessionConsensusWireRequest);
struct Bytes<'a>(&'a [u8]);

impl Serialize for BorrowedRequest<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStructVariant;
        match self.0 {
            SessionConsensusTransportRequest::Call { call_id, request } => {
                let mut fields = serializer.serialize_struct_variant(
                    "SessionConsensusTransportRequest",
                    0,
                    "Call",
                    2,
                )?;
                fields.serialize_field("call_id", call_id)?;
                fields.serialize_field("request", &BorrowedWire(request))?;
                fields.end()
            }
            frame @ SessionConsensusTransportRequest::RosterCall { .. } => {
                frame.serialize(serializer)
            }
        }
    }
}
impl Serialize for BorrowedWire<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut fields = serializer.serialize_struct("ConsensusWireRequest", 5)?;
        fields.serialize_field("schema_version", &self.0.schema_version)?;
        fields.serialize_field("identity", &self.0.identity)?;
        fields.serialize_field("sender", &self.0.sender)?;
        fields.serialize_field("family", &self.0.family)?;
        fields.serialize_field("payload", &Bytes(&self.0.payload))?;
        fields.end()
    }
}
impl Serialize for Bytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

struct NumericBytes;
impl serde_json::ser::Formatter for NumericBytes {
    fn write_byte_array<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        value: &[u8],
    ) -> io::Result<()> {
        writer.write_all(b"[")?;
        // Fixed synchronous scratch; the existing bounded sink still checks
        // capacity and the original cancellation/deadline between batches.
        let mut buffer = [0; 1024];
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

pub(super) fn to_writer<W: Write, T: Serialize>(writer: W, value: &T) -> serde_json::Result<()> {
    value.serialize(&mut serde_json::Serializer::with_formatter(
        writer,
        NumericBytes,
    ))
}
