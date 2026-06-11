use bytes::{Bytes, BytesMut};

use crate::{
    context::{DecodeContext, EncodeContext},
    error::{DecodeError, EncodeError},
};

/// Result of a borrowed decode: the unconsumed tail of the input buffer and
/// the decoded value.
pub type DecodeResult<'a, T> = Result<(&'a [u8], T), DecodeError>;

/// Decode a value as a borrowed view tied to the input buffer lifetime.
///
/// # Lifetime Contract
///
/// The returned value MUST NOT outlive `input`. Implementations MUST NOT
/// store pointers into mutable buffers that can change while the view exists.
///
/// # Security
///
/// Implementations MUST enforce the limits in [`DecodeContext`]:
/// - maximum message length,
/// - maximum IE count,
/// - maximum nesting depth,
/// - checked arithmetic for all length/offset calculations.
pub trait BorrowDecode<'a>: Sized {
    /// Attempt to decode `Self` from the front of `input`.
    ///
    /// On success, returns the unconsumed tail of `input` and the decoded
    /// value. On failure, returns a structured error with the byte offset
    /// where parsing failed.
    ///
    /// # Example
    ///
    /// ```
    /// use opc_protocol::{BorrowDecode, DecodeContext, DecodeResult};
    ///
    /// struct Header<'a> { buf: &'a [u8] }
    ///
    /// impl<'a> BorrowDecode<'a> for Header<'a> {
    ///     fn decode(input: &'a [u8], _ctx: DecodeContext) -> DecodeResult<'a, Self> {
    ///         if input.len() < 2 {
    ///             return Err(opc_protocol::DecodeError::new(
    ///                 opc_protocol::DecodeErrorCode::Truncated, 0));
    ///         }
    ///         Ok((&input[2..], Self { buf: &input[..2] }))
    ///     }
    /// }
    /// ```
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self>;
}

/// Convert a borrowed PDU view into an owned representation.
///
/// Every borrowed PDU that may cross an async boundary, thread boundary,
/// queue, or long-lived store MUST implement this trait.
pub trait ToOwnedPdu {
    /// The owned counterpart.
    type Owned;

    /// Produce an owned copy.
    ///
    /// This may copy data or use [`Bytes`] for cheap shared ownership of the
    /// original packet buffer.
    fn to_owned_pdu(&self) -> Self::Owned;
}

/// Decode a value into an owned representation suitable for async or
/// cross-thread use.
///
/// Owned PDUs MAY use [`Bytes`] to retain cheap shared ownership of the
/// original packet.
pub trait OwnedDecode: Sized {
    /// Attempt to decode `Self` from an owned [`Bytes`] buffer.
    fn decode_owned(input: Bytes, ctx: DecodeContext) -> Result<Self, DecodeError>;
}

/// Encode a value into a byte buffer.
///
/// # Canonical vs Raw-Preserving Encoding
///
/// The SDK distinguishes two encoding modes to support both clean model
/// round-tripping and byte-exact forwarding.
///
/// ## Canonical Round Trip
///
/// For generated valid model values:
/// ```text
/// decode(encode(model)) == model
/// ```
///
/// Canonical encoding produces normalized output: default padding, sorted IEs,
/// stripped unknown fields, and normalized enum values. Use
/// [`EncodeContext::raw_preserving`] = `false` (the default).
///
/// ## Raw-Preserving Round Trip
///
/// For accepted inputs where unknown/padding preservation is enabled:
/// ```text
/// encode_raw_preserving(decode_raw_preserving(input)) == input
/// ```
///
/// Raw-preserving encoding retains original padding, unknown IEs, and field
/// ordering so that a forwarded or stored packet can be re-emitted
/// byte-identical. Use [`EncodeContext::raw_preserving`] = `true`.
///
/// # Safety
///
/// - [`wire_len`](Self::wire_len) MUST use checked arithmetic.
/// - [`encode`](Self::encode) MUST fail before writing if required capacity
///   exceeds [`EncodeContext::max_message_len`]. Use
///   [`EncodeContext::check_capacity`] for a one-line guard.
/// - Encoders SHOULD reserve exact capacity when cheap to compute.
/// - Partial writes on error SHOULD be avoided. If unavoidable, document the
///   behavior and warn callers not to reuse the buffer without awareness.
pub trait Encode {
    /// Write the wire representation of `self` into `dst`.
    ///
    /// `dst` MUST have sufficient capacity. Callers SHOULD call
    /// [`wire_len`](Self::wire_len) and reserve capacity beforehand.
    ///
    /// If encoding fails, partial writes MAY have occurred. Callers SHOULD not
    /// reuse `dst` without awareness of partial state.
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError>;

    /// Return the exact byte length of the wire representation.
    ///
    /// This MUST use checked arithmetic. An overflow MUST produce
    /// [`EncodeErrorCode::LengthOverflow`](crate::EncodeErrorCode::LengthOverflow).
    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError>;
}
