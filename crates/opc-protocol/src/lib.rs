//! Zero-copy protocol codec framework for OpenPacketCore.
//!
//! This crate defines the foundational traits, contexts, and error types used
//! by all protocol parsers and encoders in the SDK. It implements the contracts
//! from RFC 005 (Zero-Copy Protocol Framework).
//!
//! # Core abstractions
//!
//! - [`BorrowDecode`] – parse a borrowed view tied to the input buffer lifetime.
//! - [`OwnedDecode`] – parse into an owned representation for async/thread use.
//! - [`Encode`] – write a canonical or raw-preserving wire representation.
//! - [`DecodeContext`] – security limits and validation policies for decoders.
//! - [`EncodeContext`] – version and mode selectors for encoders.
//! - [`DecodeError`] / [`EncodeError`] – structured, log-safe error types.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod context;
mod error;
mod traits;

pub use context::{
    AllocationBudget, DecodeContext, DuplicateIePolicy, EncodeContext, ProtocolVersion,
    UnknownIePolicy, ValidationLevel,
};
pub use error::{DecodeError, DecodeErrorCode, EncodeError, EncodeErrorCode, SpecRef};
pub use traits::{BorrowDecode, DecodeResult, Encode, OwnedDecode, ToOwnedPdu};
