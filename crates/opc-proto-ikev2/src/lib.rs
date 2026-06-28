#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

//! Experimental IKEv2 codec scaffold for OpenPacketCore.
//!
//! This crate intentionally covers only the transport-neutral IKEv2 wire
//! mechanism that is safe to expose as an SDK primitive today: fixed-header
//! decode/encode, raw-preserving generic payload-chain walking for unencrypted
//! payloads, protected-payload boundary metadata, and caller-owned crypto
//! provider traits. It does not implement an IKE SA state machine, EAP-AKA,
//! key derivation, retransmission policy, cookie policy, Child SA installation,
//! or any 3GPP ePDG profile decisions.
//!
//! @spec IETF RFC7296
//! @req REQ-IETF-RFC7296-IKEV2-SCAFFOLD-001
//! @conformance experimental-scaffold — see CONFORMANCE.md

use opc_protocol::ValidationLevel;

pub mod crypto;
pub mod header;
pub mod message;
pub mod payload;

pub use crypto::{CryptoProvider, ProtectedPayloadContext, ProtectedPayloadKind};
pub use header::{
    decode_header, encode_header, Header, HeaderFlags, EXCHANGE_TYPE_CREATE_CHILD_SA,
    EXCHANGE_TYPE_IKE_AUTH, EXCHANGE_TYPE_IKE_SA_INIT, EXCHANGE_TYPE_INFORMATIONAL, HEADER_LEN,
    IKEV2_MAJOR_VERSION, IKEV2_MINOR_VERSION, IKEV2_VERSION_OCTET,
};
pub use message::{Message, OwnedMessage};
pub use payload::{
    validate_payload_chain, PayloadChain, PayloadType, RawPayload, RawPayloadIterator,
    GENERIC_PAYLOAD_HEADER_LEN,
};

pub(crate) const fn is_strict(level: ValidationLevel) -> bool {
    matches!(
        level,
        ValidationLevel::Strict | ValidationLevel::ProcedureAware
    )
}
