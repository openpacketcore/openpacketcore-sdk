//! Bounded, explicitly directional NWu GRE (TS 24.502 V18.8.0 §8.3.2, §9.3.3).
//!
//! This is a fixed keyed GRE profile, with an opaque nonempty user packet.
//! Receive ignores Protocol Type and canonical transmit always sets it to zero.
//! Neither decoding nor the abstract mapping installs or selects an IPsec SA.
//! See the crate README and CONFORMANCE.md for limits and unsupported features.
//!
//! @spec 3GPP TS24.502 8.3.2, 9.3.3; IETF RFC2784 2.3-2.4; IETF RFC2890 2
//! @req REQ-3GPP-TS24502-NWU-GRE-001
//!
//! ```
//! use bytes::BytesMut;
//! use opc_proto_gre::{Direction, DirectionalQos, NwuGrePacket, Qfi};
//! use opc_protocol::{DecodeContext, Encode, EncodeContext};
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let qos = DirectionalQos::Uplink { qfi: Qfi::new(9)? };
//! let packet = NwuGrePacket::new(qos, &[0], EncodeContext::default())?;
//! let mut wire = BytesMut::new();
//! packet.encode(&mut wire, EncodeContext::default())?;
//! let received = NwuGrePacket::decode(&wire, Direction::Uplink, DecodeContext::default())?;
//! assert_eq!(received.qos(), qos);
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod mapping;

use bytes::{Bytes, BytesMut};
use opc_protocol::{
    DecodeContext, DecodeError, DecodeErrorCode, Encode, EncodeContext, EncodeError,
    EncodeErrorCode, SpecRef, ToOwnedPdu,
};
use std::fmt;
use thiserror::Error;

pub use mapping::{
    AssociationCandidates, DefaultFallbackIntent, FlowAssociation, FlowMapping, FlowSelection,
    MappingError, QfiSet, SelectionKind,
};

/// Fixed NWu GRE header size, including the four-octet Key (§9.3.3).
pub const HEADER_LEN: usize = 8;

/// Packet direction supplied by the caller; it is not encoded in GRE.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// UE to N3IWF: RQI must be clear.
    Uplink,
    /// N3IWF to UE: RQI may be clear or set.
    Downlink,
}

/// A checked six-bit QoS flow identifier (§9.3.3, table 9.3.3-3).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Qfi(u8);

/// Construction failed without retaining the supplied identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("QFI is outside the supported range")]
pub struct QfiError;

impl Qfi {
    /// Accept an identifier in the inclusive range 0–63.
    pub const fn new(value: u8) -> Result<Self, QfiError> {
        if value <= 63 {
            Ok(Self(value))
        } else {
            Err(QfiError)
        }
    }

    /// Access the identifier explicitly; do not include it in diagnostics.
    pub const fn value(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for Qfi {
    type Error = QfiError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl fmt::Debug for Qfi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Qfi([REDACTED])")
    }
}

/// Downlink reflective QoS indication (§9.3.3, table 9.3.3-3).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Rqi {
    /// The indication is clear.
    NotIndicated,
    /// The indication is set.
    Indicated,
}

impl fmt::Debug for Rqi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Rqi([REDACTED])")
    }
}

/// Directional fields: an uplink RQI cannot be constructed (§8.3.2).
///
/// ```compile_fail
/// use opc_proto_gre::{DirectionalQos, Qfi, Rqi};
/// let invalid = DirectionalQos::Uplink {
///     qfi: Qfi::new(1).unwrap(), rqi: Rqi::Indicated,
/// };
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DirectionalQos {
    /// Uplink packet, with RQI implicitly clear.
    Uplink {
        /// Caller-selected QFI.
        qfi: Qfi,
    },
    /// Downlink packet with an explicit indication.
    Downlink {
        /// Caller-selected QFI.
        qfi: Qfi,
        /// Caller-selected reflective QoS indication.
        rqi: Rqi,
    },
}

impl DirectionalQos {
    /// Access the QFI explicitly.
    pub const fn qfi(self) -> Qfi {
        match self {
            Self::Uplink { qfi } | Self::Downlink { qfi, .. } => qfi,
        }
    }

    /// Access the out-of-band direction.
    pub const fn direction(self) -> Direction {
        match self {
            Self::Uplink { .. } => Direction::Uplink,
            Self::Downlink { .. } => Direction::Downlink,
        }
    }

    fn rqi_bit(self) -> u8 {
        match self {
            Self::Downlink {
                rqi: Rqi::Indicated,
                ..
            } => 0x80,
            _ => 0,
        }
    }
}

impl fmt::Debug for DirectionalQos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirectionalQos([REDACTED])")
    }
}

/// Borrowed complete datagram with a bounded, opaque, nonempty payload.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NwuGrePacket<'a> {
    qos: DirectionalQos,
    payload: &'a [u8],
}

impl<'a> NwuGrePacket<'a> {
    /// Construct a packet after checking its entire encoded size and mode.
    pub fn new(
        qos: DirectionalQos,
        payload: &'a [u8],
        ctx: EncodeContext,
    ) -> Result<Self, EncodeError> {
        encoded_len(payload.len(), ctx)?;
        Ok(Self { qos, payload })
    }

    /// Decode exactly one complete datagram without allocating.
    ///
    /// Direction must come from the caller's authenticated transport context.
    /// Every byte after the Key is opaque payload, including GRE-looking bytes.
    /// `max_message_len` is enforced before inspecting any fields; the other
    /// context limits have no containers/IEs to constrain in this fixed profile.
    /// Fixed wire version zero and directional checks apply at every validation
    /// level. No directionless `BorrowDecode` implementation is provided.
    pub fn decode(
        input: &'a [u8],
        direction: Direction,
        ctx: DecodeContext,
    ) -> Result<Self, DecodeError> {
        if input.len() > ctx.max_message_len {
            return Err(decode_error(DecodeErrorCode::MessageLengthExceeded, 0));
        }
        if input.len() < HEADER_LEN {
            return Err(decode_error(DecodeErrorCode::Truncated, 0));
        }
        // RFC 2784 §2.3: bits 1–5 require RFC 1701 support, except K
        // permitted by RFC 2890. NWu additionally excludes C and S. RFC
        // bits 6–12 are ignored; version (13–15) must remain zero.
        let flags = u16::from_be_bytes([input[0], input[1]]);
        if flags & 0xfc07 != 0x2000 {
            return Err(structural_decode("unsupported NWu GRE flags or version", 0));
        }
        if input.len() == HEADER_LEN {
            return Err(structural_decode("NWu user payload is empty", HEADER_LEN));
        }
        // Protocol Type is intentionally ignored (TS table 9.3.3-2 NOTE).
        // Key spare bits are accepted and dropped by this SDK receive profile.
        let qfi = Qfi(input[4] & 0x3f);
        let rqi = if input[7] & 0x80 == 0 {
            Rqi::NotIndicated
        } else {
            Rqi::Indicated
        };
        let qos = match direction {
            Direction::Uplink => {
                if rqi == Rqi::Indicated {
                    return Err(structural_decode("RQI is forbidden on uplink", 7));
                }
                DirectionalQos::Uplink { qfi }
            }
            Direction::Downlink => DirectionalQos::Downlink { qfi, rqi },
        };
        Ok(Self {
            qos,
            payload: &input[HEADER_LEN..],
        })
    }

    /// Access the directional fields explicitly.
    pub const fn qos(&self) -> DirectionalQos {
        self.qos
    }

    /// Access the opaque user packet explicitly; never included in `Debug`.
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

impl fmt::Debug for NwuGrePacket<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NwuGrePacket([REDACTED])")
    }
}

impl Encode for NwuGrePacket<'_> {
    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        encoded_len(self.payload.len(), ctx)
    }

    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let len = self.wire_len(ctx)?;
        dst.len()
            .checked_add(len)
            .ok_or_else(EncodeError::length_overflow)?;
        dst.reserve(len);
        dst.extend_from_slice(&[
            0x20,
            0,
            0,
            0,
            self.qos.qfi().value(),
            0,
            0,
            self.qos.rqi_bit(),
        ]);
        dst.extend_from_slice(self.payload);
        Ok(())
    }
}

/// Owned packet for queues or async use, with redacted diagnostics.
#[derive(Clone, PartialEq, Eq)]
pub struct OwnedNwuGrePacket {
    qos: DirectionalQos,
    payload: Bytes,
}

impl OwnedNwuGrePacket {
    /// Construct an owned packet after checking the encoded size and mode.
    pub fn new(
        qos: DirectionalQos,
        payload: Bytes,
        ctx: EncodeContext,
    ) -> Result<Self, EncodeError> {
        encoded_len(payload.len(), ctx)?;
        Ok(Self { qos, payload })
    }

    /// Decode with explicit direction, retaining the supplied buffer's backing
    /// storage. The size bound applies to the input slice, not its backing allocation.
    pub fn decode(
        input: Bytes,
        direction: Direction,
        ctx: DecodeContext,
    ) -> Result<Self, DecodeError> {
        let qos = NwuGrePacket::decode(&input, direction, ctx)?.qos;
        Ok(Self {
            qos,
            payload: input.slice(HEADER_LEN..),
        })
    }

    /// Borrow the validated packet without copying.
    pub fn as_borrowed(&self) -> NwuGrePacket<'_> {
        NwuGrePacket {
            qos: self.qos,
            payload: &self.payload,
        }
    }
}

impl fmt::Debug for OwnedNwuGrePacket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnedNwuGrePacket([REDACTED])")
    }
}

impl ToOwnedPdu for NwuGrePacket<'_> {
    type Owned = OwnedNwuGrePacket;

    fn to_owned_pdu(&self) -> Self::Owned {
        OwnedNwuGrePacket {
            qos: self.qos,
            payload: Bytes::copy_from_slice(self.payload),
        }
    }
}

impl Encode for OwnedNwuGrePacket {
    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        self.as_borrowed().wire_len(ctx)
    }

    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        self.as_borrowed().encode(dst, ctx)
    }
}

fn encoded_len(payload_len: usize, ctx: EncodeContext) -> Result<usize, EncodeError> {
    if ctx.raw_preserving {
        return Err(structural_encode(
            "raw-preserving NWu encoding is unsupported",
        ));
    }
    if payload_len == 0 {
        return Err(structural_encode("NWu user payload is empty"));
    }
    let len = HEADER_LEN
        .checked_add(payload_len)
        .ok_or_else(EncodeError::length_overflow)?;
    if len > ctx.max_message_len {
        // Do not put deployment-specific configured bounds into diagnostics.
        return Err(structural_encode("NWu message length exceeds limit"));
    }
    Ok(len)
}

fn decode_error(code: DecodeErrorCode, offset: usize) -> DecodeError {
    DecodeError::new(code, offset).with_spec_ref(SpecRef::new("3gpp", "TS 24.502 V18.8.0", "9.3.3"))
}

fn structural_decode(reason: &'static str, offset: usize) -> DecodeError {
    decode_error(DecodeErrorCode::Structural { reason }, offset)
}

fn structural_encode(reason: &'static str) -> EncodeError {
    EncodeError::new(EncodeErrorCode::Structural { reason }).with_spec_ref(SpecRef::new(
        "3gpp",
        "TS 24.502 V18.8.0",
        "9.3.3",
    ))
}
