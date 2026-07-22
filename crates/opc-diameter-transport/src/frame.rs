#[cfg(test)]
use bytes::Bytes;
use bytes::BytesMut;
use opc_proto_diameter::{Header, OwnedMessage, DIAMETER_HEADER_LEN, MAX_U24};
use opc_protocol::{
    BorrowDecode, DecodeContext, Encode, EncodeContext, OwnedDecode, ValidationLevel,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use crate::tls::DiameterTlsError;

/// Bounds applied before allocating or emitting a Diameter stream frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiameterFrameLimits {
    max_message_len: usize,
}

impl DiameterFrameLimits {
    /// Create a frame limit accepted by both the 20-byte Diameter header and
    /// its unsigned 24-bit message-length field.
    pub const fn new(max_message_len: usize) -> Result<Self, DiameterFrameLimitsError> {
        if max_message_len < DIAMETER_HEADER_LEN {
            return Err(DiameterFrameLimitsError::BelowHeaderLength);
        }
        if max_message_len > MAX_U24 as usize {
            return Err(DiameterFrameLimitsError::ExceedsWireLength);
        }
        Ok(Self { max_message_len })
    }

    /// Maximum complete Diameter message length in bytes.
    pub const fn max_message_len(self) -> usize {
        self.max_message_len
    }

    pub(crate) const fn decode_context(self) -> DecodeContext {
        DecodeContext {
            max_message_len: self.max_message_len,
            // Stream framing owns only the fixed header and declared message
            // boundary. Typed Diameter parsers own AVP grammar, duplicate,
            // unknown-AVP, and application policy.
            validation_level: ValidationLevel::HeaderOnly,
            ..DecodeContext::conservative()
        }
    }

    fn strict_header_decode_context(self) -> DecodeContext {
        DecodeContext {
            max_message_len: self.max_message_len,
            validation_level: ValidationLevel::Strict,
            ..DecodeContext::default()
        }
    }

    pub(crate) fn encode_context(self) -> EncodeContext {
        EncodeContext {
            max_message_len: self.max_message_len,
            ..EncodeContext::default()
        }
    }
}

impl Default for DiameterFrameLimits {
    fn default() -> Self {
        Self {
            max_message_len: 65_535,
        }
    }
}

/// Invalid local Diameter frame limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DiameterFrameLimitsError {
    /// The configured bound cannot contain a Diameter header.
    #[error("Diameter frame limit is shorter than the fixed header")]
    BelowHeaderLength,
    /// The configured bound cannot be represented by Diameter's u24 length.
    #[error("Diameter frame limit exceeds the 24-bit wire length")]
    ExceedsWireLength,
}

pub(crate) async fn read_frame<R>(
    reader: &mut R,
    limits: DiameterFrameLimits,
    deadline: Instant,
) -> Result<OwnedMessage, DiameterTlsError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    // Read exactly the Diameter header. In particular, do not use a buffered
    // decoder here: in-band TLS starts on this same stream immediately after
    // CEA and read-ahead would consume ClientHello bytes.
    let mut header_wire = [0_u8; DIAMETER_HEADER_LEN];
    tokio::time::timeout_at(deadline, reader.read_exact(&mut header_wire))
        .await
        .map_err(|_| DiameterTlsError::DeadlineExceeded)?
        .map_err(|_| DiameterTlsError::Transport)?;

    // Reject reserved fixed-header bits before trusting the declared length or
    // allocating/awaiting the body. The final opaque message decode below
    // deliberately remains HeaderOnly; typed command parsers own AVP grammar.
    let (_, header) = Header::decode(&header_wire, limits.strict_header_decode_context())
        .map_err(|_| DiameterTlsError::InvalidFrame)?;
    let message_len = usize::try_from(header.length).map_err(|_| DiameterTlsError::InvalidFrame)?;

    let mut wire = BytesMut::with_capacity(message_len);
    wire.extend_from_slice(&header_wire);
    wire.resize(message_len, 0);
    tokio::time::timeout_at(
        deadline,
        reader.read_exact(&mut wire[DIAMETER_HEADER_LEN..]),
    )
    .await
    .map_err(|_| DiameterTlsError::DeadlineExceeded)?
    .map_err(|_| DiameterTlsError::Transport)?;

    OwnedMessage::decode_owned(wire.freeze(), limits.decode_context())
        .map_err(|_| DiameterTlsError::InvalidFrame)
}

pub(crate) async fn write_frame<W>(
    writer: &mut W,
    message: &OwnedMessage,
    limits: DiameterFrameLimits,
    deadline: Instant,
) -> Result<(), DiameterTlsError>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let ctx = limits.encode_context();
    let message_len = message
        .wire_len(ctx)
        .map_err(|_| DiameterTlsError::InvalidFrame)?;
    let mut wire = BytesMut::with_capacity(message_len);
    message
        .encode(&mut wire, ctx)
        .map_err(|_| DiameterTlsError::InvalidFrame)?;
    write_wire_frame(writer, &wire, limits, deadline).await
}

pub(crate) async fn write_wire_frame<W>(
    writer: &mut W,
    wire: &[u8],
    limits: DiameterFrameLimits,
    deadline: Instant,
) -> Result<(), DiameterTlsError>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    if wire.len() < DIAMETER_HEADER_LEN || wire.len() > limits.max_message_len() {
        return Err(DiameterTlsError::InvalidFrame);
    }
    let (_, header) = Header::decode(
        &wire[..DIAMETER_HEADER_LEN],
        limits.strict_header_decode_context(),
    )
    .map_err(|_| DiameterTlsError::InvalidFrame)?;
    if usize::try_from(header.length).ok() != Some(wire.len()) {
        return Err(DiameterTlsError::InvalidFrame);
    }
    tokio::time::timeout_at(deadline, async {
        writer.write_all(wire).await?;
        writer.flush().await
    })
    .await
    .map_err(|_| DiameterTlsError::DeadlineExceeded)?
    .map_err(|_| DiameterTlsError::Transport)
}

pub(crate) fn borrowed(message: &OwnedMessage) -> opc_proto_diameter::Message<'_> {
    opc_proto_diameter::Message {
        header: message.header.clone(),
        raw_avps: &message.raw_avps,
        tail: &[],
    }
}

#[cfg(test)]
pub(crate) fn encoded_bytes(
    message: &OwnedMessage,
    limits: DiameterFrameLimits,
) -> Result<Bytes, DiameterTlsError> {
    let ctx = limits.encode_context();
    let message_len = message
        .wire_len(ctx)
        .map_err(|_| DiameterTlsError::InvalidFrame)?;
    let mut wire = BytesMut::with_capacity(message_len);
    message
        .encode(&mut wire, ctx)
        .map_err(|_| DiameterTlsError::InvalidFrame)?;
    Ok(wire.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;
    use opc_proto_diameter::{ApplicationId, CommandCode, CommandFlags, Header};
    use std::time::Duration;

    fn message_with_payload(payload: &[u8]) -> OwnedMessage {
        OwnedMessage {
            header: Header::new(
                CommandFlags::from_bits(0x80),
                CommandCode::new(280),
                ApplicationId::new(0),
                7,
                9,
            ),
            raw_avps: Bytes::copy_from_slice(payload),
        }
    }

    #[tokio::test]
    async fn exact_frame_read_leaves_following_bytes_unconsumed() {
        let message = message_with_payload(&[]);
        let wire = encoded_bytes(&message, DiameterFrameLimits::default()).expect("encode frame");
        let (mut writer, mut reader) = tokio::io::duplex(128);
        let write = async move {
            writer.write_all(&wire).await.expect("write message");
            writer.write_all(b"TLS").await.expect("write next protocol");
        };
        let read = async move {
            let deadline = Instant::now() + Duration::from_secs(1);
            let decoded = read_frame(&mut reader, DiameterFrameLimits::default(), deadline)
                .await
                .expect("read one frame");
            assert_eq!(decoded.header.command_code, CommandCode::new(280));
            let mut next = [0_u8; 3];
            reader.read_exact(&mut next).await.expect("read next bytes");
            assert_eq!(&next, b"TLS");
        };
        tokio::join!(write, read);
    }

    #[tokio::test]
    async fn declared_oversize_fails_before_body_read() {
        let limits = DiameterFrameLimits::new(DIAMETER_HEADER_LEN).expect("limits");
        let message = message_with_payload(&[0_u8; 8]);
        let wire = encoded_bytes(&message, DiameterFrameLimits::default()).expect("encode frame");
        let (mut writer, mut reader) = tokio::io::duplex(128);
        writer
            .write_all(&wire[..DIAMETER_HEADER_LEN])
            .await
            .expect("write header");
        let error = read_frame(&mut reader, limits, Instant::now() + Duration::from_secs(1))
            .await
            .expect_err("oversize declaration must fail");
        assert_eq!(error, DiameterTlsError::InvalidFrame);
    }

    #[tokio::test]
    async fn reserved_command_flag_fails_before_declared_body_read() {
        let message = message_with_payload(&[]);
        let mut wire = encoded_bytes(&message, DiameterFrameLimits::default())
            .expect("encode frame")
            .to_vec();
        wire[1..4].copy_from_slice(&[0, 0, 24]);
        wire[4] |= 0x08;
        let (mut writer, mut reader) = tokio::io::duplex(128);
        writer
            .write_all(&wire[..DIAMETER_HEADER_LEN])
            .await
            .expect("write reserved-bit header only");

        let error = read_frame(
            &mut reader,
            DiameterFrameLimits::default(),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect_err("reserved command bit must fail without awaiting the body");
        assert_eq!(error, DiameterTlsError::InvalidFrame);
    }

    #[tokio::test]
    async fn truncated_frame_is_transport_failure() {
        let message = message_with_payload(&[0_u8; 8]);
        let wire = encoded_bytes(&message, DiameterFrameLimits::default()).expect("encode frame");
        let (mut writer, mut reader) = tokio::io::duplex(128);
        writer
            .write_all(&wire[..DIAMETER_HEADER_LEN + 4])
            .await
            .expect("write partial frame");
        drop(writer);
        let error = read_frame(
            &mut reader,
            DiameterFrameLimits::default(),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect_err("truncated body must fail");
        assert_eq!(error, DiameterTlsError::Transport);
    }

    #[tokio::test]
    async fn opaque_framing_preserves_repeatable_avps_for_typed_parsers() {
        let duplicate_avps = [
            0, 0, 0, 1, 0, 0, 0, 8, // AVP code 1, length 8
            0, 0, 0, 1, 0, 0, 0, 8, // same AVP may be repeatable by grammar
        ];
        let message = message_with_payload(&duplicate_avps);
        let wire = encoded_bytes(&message, DiameterFrameLimits::default()).expect("encode frame");
        let (mut writer, mut reader) = tokio::io::duplex(128);
        writer.write_all(&wire).await.expect("write frame");
        let decoded = read_frame(
            &mut reader,
            DiameterFrameLimits::default(),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect("framing must not impose AVP duplicate policy");
        assert_eq!(decoded.raw_avps.as_ref(), duplicate_avps);
    }

    #[tokio::test]
    async fn raw_write_rejects_mismatched_declared_length_without_output() {
        let message = message_with_payload(&[]);
        let mut wire = encoded_bytes(&message, DiameterFrameLimits::default()).expect("encode");
        wire.truncate(DIAMETER_HEADER_LEN - 1);
        let (mut writer, mut reader) = tokio::io::duplex(128);
        let error = write_wire_frame(
            &mut writer,
            &wire,
            DiameterFrameLimits::default(),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .expect_err("invalid frame must fail");
        assert_eq!(error, DiameterTlsError::InvalidFrame);
        drop(writer);
        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.expect("drain output");
        assert!(output.is_empty());
    }
}
