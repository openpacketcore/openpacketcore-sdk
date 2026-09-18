//! Bounded, opaque NAS-over-TCP envelopes (TS 24.502 V18.8.0 clause 9.4).
//!
//! The two-octet network-order length counts only the NAS payload. The payload
//! remains opaque, including protected NAS, unknown EPDs and malformed inner
//! messages. This module never calls the NAS content or security decoder.
//!
//! [`NasTcpDecoder::feed`] consumes at most one envelope per call. Coalesced
//! trailing bytes remain in the caller's input slice for the next call; they
//! are not copied into an unbounded queue. Partial input needs more data while
//! open. Call [`NasTcpDecoder::finish`] after feeding the remaining input on
//! EOF, loss, or cancellation to distinguish a clean boundary from terminal
//! truncation. Dropping a decoder discards its buffer without reporting EOF.
//!
//! The caller selects an inclusive payload bound. Rejecting zero-length input,
//! sticky failure/finalization, and the single-frame buffering strategy are SDK
//! contracts. TCP connections, reconnect policy, security termination, SA
//! provenance and UE lifecycle remain outside this framing layer.
//!
//! @spec 3GPP TS24502 V18.8.0 9.4; surrounding transport 8.2.1-8.2.5
//! @req REQ-3GPP-TS24502-NAS-TCP-001
//! @conformance synthetic bounded envelope and stream-framing subset

use std::{error::Error, fmt, num::NonZeroU16};

/// Width of the NAS-over-TCP length prefix, in octets.
pub const NAS_TCP_PREFIX_LEN: usize = 2;
/// Largest payload representable by the two-octet length, excluding its prefix.
pub const NAS_TCP_MAX_PAYLOAD_LEN: usize = u16::MAX as usize;

/// Inclusive caller-selected payload bound, between one and 65,535 octets.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct NasTcpLimit(NonZeroU16);

impl NasTcpLimit {
    /// Validate a caller bound before buffering or encoding any input.
    ///
    /// # Errors
    /// Returns `InvalidLimit` for zero or a bound above the wire maximum.
    pub fn new(max_payload_len: usize) -> Result<Self, NasTcpError> {
        u16::try_from(max_payload_len)
            .ok()
            .and_then(NonZeroU16::new)
            .map(Self)
            .ok_or(NasTcpError::InvalidLimit)
    }

    /// Return the maximum number of NAS payload octets, excluding the prefix.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get() as usize
    }
}

/// Bounded, value-free envelope or stream refusal.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NasTcpError {
    /// The caller selected zero or more than 65,535 payload octets.
    InvalidLimit,
    /// A zero-length envelope cannot carry a NAS message.
    EmptyPayload,
    /// The encoded or declared payload exceeds the inclusive caller bound.
    PayloadTooLarge,
    /// The caller's output slice cannot hold the complete envelope.
    OutputTooSmall,
    /// Explicit finalization encountered a partial prefix or payload.
    Truncated,
    /// Input was supplied after successful finalization.
    Finished,
    /// The bounded payload allocation could not be reserved.
    AllocationFailed,
}

impl fmt::Display for NasTcpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidLimit => "nas_tcp_invalid_limit",
            Self::EmptyPayload => "nas_tcp_empty_payload",
            Self::PayloadTooLarge => "nas_tcp_payload_too_large",
            Self::OutputTooSmall => "nas_tcp_output_too_small",
            Self::Truncated => "nas_tcp_truncated",
            Self::Finished => "nas_tcp_finished",
            Self::AllocationFailed => "nas_tcp_allocation_failed",
        })
    }
}

impl Error for NasTcpError {}

fn check_payload_len(len: usize, limit: NasTcpLimit) -> Result<(), NasTcpError> {
    if len == 0 {
        return Err(NasTcpError::EmptyPayload);
    }
    if len > limit.get() {
        return Err(NasTcpError::PayloadTooLarge);
    }
    Ok(())
}

/// Borrowed opaque payload of one complete NAS-over-TCP envelope.
pub struct NasTcpEnvelope<'a> {
    payload: &'a [u8],
}

impl<'a> NasTcpEnvelope<'a> {
    /// Return exact NAS bytes without decoding their contents. Do not log them.
    #[must_use]
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// Owned opaque payload produced by the incremental stream decoder.
pub struct NasTcpFrame {
    payload: Vec<u8>,
}

impl NasTcpFrame {
    /// Borrow exact NAS bytes without decoding their contents. Do not log them.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Transfer the payload allocation to the caller without copying it.
    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

/// Decode the first complete envelope without allocation, retaining its tail.
///
/// `Ok(None)` means a partial prefix or body, including empty input. It is not
/// truncation until the transport explicitly terminates; use `NasTcpDecoder`
/// for stateful finalization. A complete first frame remains valid when its
/// tail is partial or malformed: this call makes no claim about later frames.
///
/// # Errors
/// Refuses zero or above-bound lengths as soon as both prefix octets exist.
pub fn decode_envelope(
    input: &[u8],
    limit: NasTcpLimit,
) -> Result<Option<(NasTcpEnvelope<'_>, &[u8])>, NasTcpError> {
    if input.len() < NAS_TCP_PREFIX_LEN {
        return Ok(None);
    }
    let len = usize::from(u16::from_be_bytes([input[0], input[1]]));
    check_payload_len(len, limit)?;
    let end = NAS_TCP_PREFIX_LEN + len;
    if input.len() < end {
        return Ok(None);
    }
    Ok(Some((
        NasTcpEnvelope {
            payload: &input[NAS_TCP_PREFIX_LEN..end],
        },
        &input[end..],
    )))
}

/// Encode one exact envelope into caller storage, returning its written length.
///
/// The prefix excludes its own two octets. Payload bytes are copied unchanged;
/// no NAS content or security validation occurs. All refusals leave the entire
/// output untouched, and success leaves any output suffix untouched.
///
/// # Errors
/// Refuses empty/above-bound payloads or insufficient output before mutation.
pub fn encode_envelope(
    payload: &[u8],
    limit: NasTcpLimit,
    output: &mut [u8],
) -> Result<usize, NasTcpError> {
    check_payload_len(payload.len(), limit)?;
    let len = u16::try_from(payload.len()).map_err(|_| NasTcpError::PayloadTooLarge)?;
    let end = NAS_TCP_PREFIX_LEN + payload.len();
    if output.len() < end {
        return Err(NasTcpError::OutputTooSmall);
    }
    output[..NAS_TCP_PREFIX_LEN].copy_from_slice(&len.to_be_bytes());
    output[NAS_TCP_PREFIX_LEN..end].copy_from_slice(payload);
    Ok(end)
}

#[derive(Clone, Copy)]
enum Status {
    Open,
    Finished,
    Failed(NasTcpError),
}

/// Incremental decoder retaining at most one prefix and one bounded payload.
///
/// Payload allocation occurs only after the complete prefix passes the caller
/// bound. It requests exactly the declared length, never the input chunk's
/// length. A completed frame takes that allocation; retaining returned frames
/// or unread input is the caller's responsibility. Allocator bookkeeping is
/// outside this logical payload bound.
pub struct NasTcpDecoder {
    limit: NasTcpLimit,
    prefix: [u8; NAS_TCP_PREFIX_LEN],
    prefix_len: usize,
    expected: usize,
    payload: Vec<u8>,
    status: Status,
}

impl NasTcpDecoder {
    /// Create an empty open decoder with no payload allocation.
    #[must_use]
    pub const fn new(limit: NasTcpLimit) -> Self {
        Self {
            limit,
            prefix: [0; NAS_TCP_PREFIX_LEN],
            prefix_len: 0,
            expected: 0,
            payload: Vec::new(),
            status: Status::Open,
        }
    }

    fn fail(&mut self, error: NasTcpError) -> NasTcpError {
        self.prefix = [0; NAS_TCP_PREFIX_LEN];
        self.prefix_len = 0;
        self.expected = 0;
        self.payload = Vec::new();
        self.status = Status::Failed(error);
        error
    }

    /// Consume input through at most the next complete frame.
    ///
    /// Advances `input` past consumed bytes and leaves coalesced trailing input
    /// for the next call. `Ok(None)` consumes all available input and retains a
    /// partial frame, or observes empty input at a clean boundary. Iterate until
    /// the input is empty, then await more bytes or explicitly finalize.
    ///
    /// # Errors
    /// Invalid lengths/allocation failures permanently fail this decoder and
    /// discard its partial buffer. That failure is sticky. Successful finalization
    /// instead refuses later input with `Finished`. Neither state consumes more
    /// input. An initial invalid-length failure consumes only its prefix.
    pub fn feed(&mut self, input: &mut &[u8]) -> Result<Option<NasTcpFrame>, NasTcpError> {
        match self.status {
            Status::Open => {}
            Status::Finished => return Err(NasTcpError::Finished),
            Status::Failed(error) => return Err(error),
        }
        if self.prefix_len < NAS_TCP_PREFIX_LEN {
            let take = (NAS_TCP_PREFIX_LEN - self.prefix_len).min(input.len());
            self.prefix[self.prefix_len..self.prefix_len + take].copy_from_slice(&input[..take]);
            self.prefix_len += take;
            *input = &input[take..];
            if self.prefix_len < NAS_TCP_PREFIX_LEN {
                return Ok(None);
            }
            self.expected = usize::from(u16::from_be_bytes(self.prefix));
            if let Err(error) = check_payload_len(self.expected, self.limit) {
                return Err(self.fail(error));
            }
            if self.payload.try_reserve_exact(self.expected).is_err() {
                return Err(self.fail(NasTcpError::AllocationFailed));
            }
        }
        let take = (self.expected - self.payload.len()).min(input.len());
        self.payload.extend_from_slice(&input[..take]);
        *input = &input[take..];
        if self.payload.len() < self.expected {
            return Ok(None);
        }
        let payload = std::mem::take(&mut self.payload);
        self.prefix = [0; NAS_TCP_PREFIX_LEN];
        self.prefix_len = 0;
        self.expected = 0;
        Ok(Some(NasTcpFrame { payload }))
    }

    /// Finalize after feeding all remaining bytes on EOF, loss or cancellation.
    ///
    /// Success is idempotent and permanent. Transport end causes deliberately
    /// share this framing result; this method does not infer connection health.
    ///
    /// # Errors
    /// A partial prefix/body becomes sticky `Truncated` and its buffer is
    /// discarded. An earlier framing failure remains the original error.
    pub fn finish(&mut self) -> Result<(), NasTcpError> {
        match self.status {
            Status::Finished => return Ok(()),
            Status::Failed(error) => return Err(error),
            Status::Open => {}
        }
        if self.prefix_len != 0 {
            return Err(self.fail(NasTcpError::Truncated));
        }
        self.status = Status::Finished;
        Ok(())
    }
}

macro_rules! redacted_debug {
    ($($name:ident),+ $(,)?) => {$ (
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<redacted>)"))
            }
        }
    )+ };
}

redacted_debug!(NasTcpLimit, NasTcpFrame, NasTcpDecoder);

impl fmt::Debug for NasTcpEnvelope<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NasTcpEnvelope(<redacted>)")
    }
}

#[cfg(test)]
mod tests;
