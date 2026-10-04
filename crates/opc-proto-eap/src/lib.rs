//! Typed EAP admission, Success/Failure, AKA projections and EAP-5G envelopes.
//!
//! [`EapPacket::parse`] classifies Request, Response, Success and Failure from
//! common header framing. It ignores lower-layer padding beyond the declared
//! Length (RFC 3748 section 4). Success/Failure require Length 4 and no Data;
//! Request/Response retain only the declared packet for explicit method parsing
//! through [`EapMethodPacket::parse_aka`] or [`EapMethodPacket::parse_eap5g`].
//! The direct method parsers retain their exact complete-packet length contract.
//!
//! [`EapSuccess`] and [`EapFailure`] encode exactly four octets without allocating.
//! Their identifier must equal the last Response being answered (RFC 3748 section
//! 4.2); each provides a `matches_response_identifier` helper. Equality checks
//! correlation only, and a parsed terminal packet does not prove authentication.
//! Admission and terminal diagnostics omit identifiers and packet values.
//!
//! ```
//! use opc_proto_eap::{EapPacket, EapPacketError, EapSuccess};
//!
//! let wire = EapSuccess::new(7).encode();
//! assert_eq!(wire, [3, 7, 0, 4]);
//! assert!(matches!(
//!     EapPacket::parse(&wire)?,
//!     EapPacket::Success(success) if success.matches_response_identifier(7)
//! ));
//! # Ok::<(), EapPacketError>(())
//! ```
//!
//! [`eap5g`] constructs and parses TS 24.502 bootstrap messages with typed AN
//! parameters, explicit caller bounds and opaque NAS. Its public value wrappers
//! redact diagnostics. It implements no subscriber authentication decisions.
//!
//! [`EapAkaPacket::parse`] accepts one complete EAP Request or Response with
//! Type 23 or Type 50. It validates the exact EAP length, AKA method header,
//! bounded TLV framing, standardized attribute lengths, singleton cardinality,
//! method/subtype direction, RFC-defined attribute combinations, EAP-AKA-prime
//! KDF negotiation shapes, and Notification S/P semantics.
//!
//! AKA parsing is allocation-free and the source bytes remain private. Public
//! AKA evidence contains only numeric identifiers, booleans, counts, and typed
//! enums, with one deliberate exception: the identity a peer asserts in
//! `AT_IDENTITY` is reachable through
//! [`EapAkaPacket::asserted_identity`](model::EapAkaPacket::asserted_identity),
//! because a relaying node cannot otherwise tell that the subject of an
//! exchange changed. That value is subscriber-correlatable and is the caller's
//! to handle. AKA authentication material is never exposed, and no subscriber
//! identity -- including that one -- ever reaches diagnostic formatting.
//!
//! This crate proves structure only. It does not verify AT_MAC, AUTN, AUTS, or
//! RES; decrypt AT_ENCR_DATA; correlate KDF re-offers or AT_RESULT_IND across
//! packets; derive keys; or declare an authentication complete. Those
//! stateful/cryptographic operations remain caller-owned.
//!
//! @spec IETF RFC3748 4-4.2
//! @spec IETF RFC4187 6-10
//! @spec IETF RFC9048 3-6
//! @spec IETF RFC5998 3, 4, 6.1
//! @req REQ-IETF-EAP-AKA-PROJECTION-001
//! @conformance strict structural projection — see CONFORMANCE.md

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

mod error;
mod model;
mod packet;
mod parser;

pub mod eap5g;

pub use error::{EapAkaCombinationError, EapAkaError};
pub use model::{
    EapAkaChallengeRequestEvidence, EapAkaFullChallengeResponseEvidence, EapAkaIdentityRequest,
    EapAkaKdfList, EapAkaKdfNegotiationEvidence, EapAkaMethod, EapAkaNotificationAckEvidence,
    EapAkaNotificationEvidence, EapAkaNotificationPhase, EapAkaPacket, EapAkaPacketKind,
    EapAkaSubtype, EapCode, EAP_AKA_HEADER_LEN, EAP_AKA_MAX_ATTRIBUTES, EAP_AKA_MAX_KDF_ATTRIBUTES,
};
pub use packet::{EapFailure, EapMethodPacket, EapPacket, EapPacketError, EapSuccess};
