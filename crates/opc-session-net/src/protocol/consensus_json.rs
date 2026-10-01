//! Borrow an ordinary consensus payload for bounded numeric-array emission.
//! The original owned DTO and every non-byte JSON token keep their encoding.

use std::io::{self, Write};

use serde::{Serialize, Serializer};
use serde_json::ser::Formatter;

use super::{SessionConsensusTransportRequest, SessionConsensusWireRequest};

/// Encoding view with the original envelope and a borrowed byte payload.
pub(super) struct BorrowedRequest<'a>(pub(super) &'a SessionConsensusTransportRequest);

impl Serialize for BorrowedRequest<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStructVariant;

        match self.0 {
            SessionConsensusTransportRequest::Call { call_id, request } => {
                let mut value = serializer.serialize_struct_variant(
                    "SessionConsensusTransportRequest",
                    0,
                    "Call",
                    2,
                )?;
                value.serialize_field("call_id", call_id)?;
                value.serialize_field("request", &BorrowedWireRequest(request))?;
                value.end()
            }
            // Preserve the existing roster-specific compact representation.
            frame @ SessionConsensusTransportRequest::RosterCall { .. } => {
                frame.serialize(serializer)
            }
        }
    }
}

struct BorrowedWireRequest<'a>(&'a SessionConsensusWireRequest);

impl Serialize for BorrowedWireRequest<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;

        let request = self.0;
        let mut value = serializer.serialize_struct("ConsensusWireRequest", 5)?;
        value.serialize_field("schema_version", &request.schema_version)?;
        value.serialize_field("identity", &request.identity)?;
        value.serialize_field("sender", &request.sender)?;
        value.serialize_field("family", &request.family)?;
        value.serialize_field("payload", &BorrowedBytes(&request.payload))?;
        value.end()
    }
}

struct BorrowedBytes<'a>(&'a [u8]);

impl Serialize for BorrowedBytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

/// Emit byte slices as the original compact JSON numeric arrays.
pub(super) struct NumericByteFormatter;

impl Formatter for NumericByteFormatter {
    fn write_byte_array<W: ?Sized + Write>(
        &mut self,
        writer: &mut W,
        value: &[u8],
    ) -> io::Result<()> {
        writer.write_all(b"[")?;
        writer.flush()?;
        // Fixed synchronous scratch, released before any asynchronous write.
        // Flush each batch through the existing fragment buffer so its pending
        // bytes cannot add another batch before the sink checks cancellation.
        // This formatter is used only by the in-memory frame encoder.
        let mut buffer = [0_u8; 1024];
        let mut used = 0;
        for (index, byte) in value.iter().copied().enumerate() {
            if buffer.len() - used < 4 {
                writer.write_all(&buffer[..used])?;
                writer.flush()?;
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

/// Serialize directly into the existing bounded fragment sink.
pub(super) fn to_writer<W: Write, T: Serialize + ?Sized>(
    writer: W,
    value: &T,
) -> serde_json::Result<()> {
    value.serialize(&mut serde_json::Serializer::with_formatter(
        writer,
        NumericByteFormatter,
    ))
}
