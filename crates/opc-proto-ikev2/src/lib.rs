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
pub mod exchange;
pub mod header;
pub mod message;
pub mod nat_traversal;
pub mod notify;
pub mod payload;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

pub use crypto::{
    open_protected_payloads, CryptoProvider, OpenedProtectedPayload, ProtectedPayloadContext,
    ProtectedPayloadKind, ProtectedPayloadOpenError, ProtectedPayloadOpenFailure,
};
pub use exchange::{
    Ikev2ExchangeBoundaryState, Ikev2ExchangeDecision, Ikev2ExchangeInvalidReason,
    Ikev2ExchangeKind, Ikev2ExchangeProjection, Ikev2ExchangeRequest, Ikev2ExchangeRequestKey,
    Ikev2ExchangeSnapshot, Ikev2ExchangeTracker, Ikev2ResponderSpi,
};
pub use header::{
    decode_header, encode_header, Header, HeaderFlags, EXCHANGE_TYPE_CREATE_CHILD_SA,
    EXCHANGE_TYPE_IKE_AUTH, EXCHANGE_TYPE_IKE_SA_INIT, EXCHANGE_TYPE_INFORMATIONAL, HEADER_LEN,
    IKEV2_MAJOR_VERSION, IKEV2_MINOR_VERSION, IKEV2_VERSION_OCTET,
};
pub use message::{Message, OwnedMessage};
pub use nat_traversal::{
    classify_ike_nat_traversal_datagram, classify_ike_nat_traversal_datagram_with_context,
    NatTraversalClassification, NatTraversalEspCandidate, NatTraversalIkeDecodeErrorCode,
    NatTraversalIkeMessage, NatTraversalIkeTransport, NatTraversalKeepalive, NatTraversalRejection,
    IKE_NAT_TRAVERSAL_UDP_PORT, IKE_UDP_PORT, NAT_TRAVERSAL_KEEPALIVE,
};
pub use notify::{
    build_ike_sa_init_cookie_response, extract_ike_sa_init_cookie_notify, Ikev2CookieNotify,
    Ikev2CookieNotifyBuildError, Ikev2CookieNotifyExtractError, Ikev2NotifyPayload,
    Ikev2NotifyPayloadError, IKEV2_NOTIFY_COOKIE, IKEV2_NOTIFY_COOKIE2,
    IKEV2_NOTIFY_PROTOCOL_ID_NONE,
};
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
