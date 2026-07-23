//! Typed, redaction-safe EAP-AKA and EAP-AKA-prime packet projection.
//!
//! [`EapAkaPacket::parse`] accepts one complete EAP Request or Response with
//! Type 23 or Type 50. It validates the exact EAP length, AKA method header,
//! bounded TLV framing, standardized attribute lengths, singleton cardinality,
//! method/subtype direction, RFC-defined attribute combinations, EAP-AKA-prime
//! KDF negotiation shapes, and Notification S/P semantics.
//!
//! Parsing is allocation-free and the source bytes remain private. Public
//! evidence contains only numeric identifiers, booleans, counts, and typed
//! enums. Subscriber identities and AKA authentication material are never
//! exposed through this API or diagnostic formatting.
//!
//! This crate proves structure only. It does not verify AT_MAC, AUTN, AUTS, or
//! RES; decrypt AT_ENCR_DATA; correlate KDF re-offers or AT_RESULT_IND across
//! packets; derive keys; or declare an authentication complete. Those
//! stateful/cryptographic operations remain caller-owned.
//!
//! @spec IETF RFC3748 4.1
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
mod parser;

pub use error::{EapAkaCombinationError, EapAkaError};
pub use model::{
    EapAkaChallengeRequestEvidence, EapAkaFullChallengeResponseEvidence, EapAkaIdentityRequest,
    EapAkaKdfList, EapAkaKdfNegotiationEvidence, EapAkaMethod, EapAkaNotificationAckEvidence,
    EapAkaNotificationEvidence, EapAkaNotificationPhase, EapAkaPacket, EapAkaPacketKind,
    EapAkaSubtype, EapCode, EAP_AKA_HEADER_LEN, EAP_AKA_MAX_ATTRIBUTES, EAP_AKA_MAX_KDF_ATTRIBUTES,
};
