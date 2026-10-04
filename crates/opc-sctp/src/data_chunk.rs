//! Borrowed, bounded DATA chunk inspection for fixtures and packet captures.

use std::fmt;

use bytes::Bytes;
use thiserror::Error;

use crate::{DeliveryOrder, InboundMessage, PayloadProtocolIdentifier};

const DATA_HEADER_LEN: usize = 16;

/// Typed observations of the RFC 9260 section 3.3.1 DATA flags.
///
/// The four reserved flag bits are ignored on receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataChunkFlags {
    /// I: the sender requests an immediate acknowledgement.
    pub immediate_sack: bool,
    /// U: unordered delivery; the stream sequence number has no meaning.
    pub unordered: bool,
    /// B: this chunk begins a user message.
    pub beginning: bool,
    /// E: this chunk ends a user message.
    pub ending: bool,
}

/// One decoded RFC 9260 section 3.3.1 DATA chunk borrowing its user data.
///
/// This portable fixture/capture decoder accepts exactly one chunk, including
/// its zero alignment padding. It does not parse an SCTP common header, verify
/// a checksum, authenticate a peer, track TSNs, or reassemble fragments. The
/// kernel continues to own live SCTP ordering and reassembly.
/// Decoding allocates nothing; [`Self::into_inbound_message`] copies the user
/// data into an owned record for existing admission policies.
///
/// ```
/// use opc_sctp::{DataChunk, n2::{N2Inbound, UnprotectedN2Profile}};
///
/// // Ordered stream-zero DATA, PPID 60, one opaque octet and three pad octets.
/// let wire = [0, 3, 0, 17, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 60, 0, 0, 0, 0];
/// let chunk = DataChunk::decode(&wire)?;
/// let message = chunk.into_inbound_message(7)?; // Caller-owned association ID.
/// let admitted = UnprotectedN2Profile::new(1)?.admit(message)?;
/// assert!(matches!(admitted, N2Inbound::Payload(_)));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DataChunk<'a> {
    flags: DataChunkFlags,
    tsn: u32,
    stream_id: u16,
    stream_sequence_number: u16,
    ppid: PayloadProtocolIdentifier,
    user_data: &'a [u8],
}

impl fmt::Debug for DataChunk<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataChunk { .. }")
    }
}

impl<'a> DataChunk<'a> {
    /// Decode exactly one padded DATA chunk without allocating.
    ///
    /// The declared Length includes the 16-byte header and nonempty user data,
    /// but excludes padding. The input must have exactly that length rounded
    /// up to four octets, with zero to three zero padding octets. This strict
    /// fixture/capture envelope policy checks sender padding; it is not the
    /// general SCTP receiver rule to ignore padding contents. Reserved flags
    /// are ignored as required by RFC 9260 section 3.3.1. Fragments decode
    /// successfully and remain observable through [`Self::flags`].
    ///
    /// # Errors
    ///
    /// Rejects short headers, non-DATA types, lengths below the DATA header,
    /// Length 16 ([`DataChunkError::NoUserData`]), truncated user data, missing
    /// or nonzero alignment padding, and anything after the padded chunk.
    /// Errors contain no input values.
    pub fn decode(input: &'a [u8]) -> Result<Self, DataChunkError> {
        if input.len() < DATA_HEADER_LEN {
            return Err(DataChunkError::ShortHeader);
        }
        if input[0] != 0 {
            return Err(DataChunkError::WrongType);
        }
        let length = usize::from(u16::from_be_bytes([input[2], input[3]]));
        if length < DATA_HEADER_LEN {
            return Err(DataChunkError::InvalidLength);
        }
        if length == DATA_HEADER_LEN {
            return Err(DataChunkError::NoUserData);
        }
        if length > input.len() {
            return Err(DataChunkError::Truncated);
        }
        // Widen before rounding: a declared length of 65535 needs 65536 octets.
        let padded_length = (length + 3) & !3;
        if input.len() < padded_length {
            return Err(DataChunkError::InvalidPadding);
        }
        if input.len() > padded_length {
            return Err(DataChunkError::TrailingBytes);
        }
        if input[length..].iter().any(|octet| *octet != 0) {
            return Err(DataChunkError::InvalidPadding);
        }
        Ok(Self {
            flags: DataChunkFlags {
                immediate_sack: input[1] & 0x08 != 0,
                unordered: input[1] & 0x04 != 0,
                beginning: input[1] & 0x02 != 0,
                ending: input[1] & 0x01 != 0,
            },
            tsn: u32::from_be_bytes([input[4], input[5], input[6], input[7]]),
            stream_id: u16::from_be_bytes([input[8], input[9]]),
            stream_sequence_number: u16::from_be_bytes([input[10], input[11]]),
            ppid: PayloadProtocolIdentifier::new(u32::from_be_bytes([
                input[12], input[13], input[14], input[15],
            ])),
            user_data: &input[DATA_HEADER_LEN..length],
        })
    }

    /// Return the typed I, U, B and E flag observations.
    #[must_use]
    pub const fn flags(&self) -> DataChunkFlags {
        self.flags
    }

    /// Return the transmission sequence number in host order.
    #[must_use]
    pub const fn tsn(&self) -> u32 {
        self.tsn
    }

    /// Return the stream identifier in host order.
    #[must_use]
    pub const fn stream_id(&self) -> u16 {
        self.stream_id
    }

    /// Return the observed stream sequence number in host order.
    ///
    /// This field has no delivery meaning when U is set and must then be
    /// ignored by consumers. The decoder retains the raw observation.
    #[must_use]
    pub const fn stream_sequence_number(&self) -> u16 {
        self.stream_sequence_number
    }

    /// Return the payload protocol identifier in host order.
    #[must_use]
    pub const fn ppid(&self) -> PayloadProtocolIdentifier {
        self.ppid
    }

    /// Borrow the nonempty user data, excluding alignment padding.
    #[must_use]
    pub const fn user_data(&self) -> &'a [u8] {
        self.user_data
    }

    /// Copy one unfragmented chunk into an owned SCTP DATA record.
    ///
    /// This conversion allocates and copies the user data into [`Bytes`]. U
    /// maps to [`DeliveryOrder::Unordered`]; stream and PPID are preserved.
    /// `assoc_id` is supplied by the caller because DATA chunks carry no
    /// association identifier. It grants no authentication or generation
    /// authority. The result has no notification/event or truncation flags.
    /// I, TSN and SSN observations are not part of [`InboundMessage`].
    ///
    /// The record can be passed to [`crate::n2::UnprotectedN2Profile::admit`]
    /// for the same PPID, ordering and payload checks used with kernel input.
    ///
    /// # Errors
    ///
    /// Returns [`DataChunkError::Fragmented`] before copying unless B and E
    /// are both set. No fragment buffering or reassembly is performed.
    pub fn into_inbound_message(self, assoc_id: i32) -> Result<InboundMessage, DataChunkError> {
        if !self.flags.beginning || !self.flags.ending {
            return Err(DataChunkError::Fragmented);
        }
        Ok(InboundMessage {
            payload: Bytes::copy_from_slice(self.user_data),
            stream_id: self.stream_id,
            ppid: self.ppid,
            order: if self.flags.unordered {
                DeliveryOrder::Unordered
            } else {
                DeliveryOrder::Ordered
            },
            assoc_id,
            notification: false,
            event: None,
            truncated: false,
            control_truncated: false,
        })
    }
}

/// Value-free DATA chunk decoding and record-conversion failures.
#[non_exhaustive]
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum DataChunkError {
    /// Fewer than 16 header octets are available.
    #[error("sctp_data_chunk_short_header")]
    ShortHeader,
    /// The chunk type is not DATA (0).
    #[error("sctp_data_chunk_wrong_type")]
    WrongType,
    /// The declared length is smaller than the 16-byte DATA header.
    #[error("sctp_data_chunk_invalid_length")]
    InvalidLength,
    /// Length 16 carries no user data (RFC 9260 sections 6.2 and 3.3.10.9).
    #[error("sctp_data_chunk_no_user_data")]
    NoUserData,
    /// The declared length extends beyond the input.
    #[error("sctp_data_chunk_truncated")]
    Truncated,
    /// Required alignment octets are absent or nonzero.
    #[error("sctp_data_chunk_invalid_padding")]
    InvalidPadding,
    /// Bytes remain after the exactly padded chunk, including excess padding.
    #[error("sctp_data_chunk_trailing_bytes")]
    TrailingBytes,
    /// A first, middle or last fragment cannot become a complete record.
    #[error("sctp_data_chunk_fragmented")]
    Fragmented,
}
