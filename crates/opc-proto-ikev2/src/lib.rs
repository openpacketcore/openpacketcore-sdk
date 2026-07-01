#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

//! Experimental IKEv2 codec scaffold for OpenPacketCore.
//!
//! This crate intentionally covers only the transport-neutral IKEv2 wire
//! mechanism that is safe to expose as an SDK primitive today: fixed-header
//! decode/encode, raw-preserving generic payload-chain walking for unencrypted
//! payloads, protected-payload boundary metadata, caller-owned crypto provider
//! traits, narrow IKE_SA_INIT key-agreement/key-derivation material,
//! caller-keyed SA_INIT AES-GCM protected-payload open/seal helpers, typed
//! IKE_AUTH cleartext payload helpers, transcript-bound shared-key AUTH MIC
//! verification, and product-neutral Child SA negotiation intent. It does not
//! implement an IKE SA state machine, EAP-AKA, retransmission policy, cookie
//! policy, Child SA installation, XFRM programming, or any 3GPP ePDG profile
//! decisions.
//!
//! @spec IETF RFC7296
//! @req REQ-IETF-RFC7296-IKEV2-SCAFFOLD-001
//! @conformance experimental-scaffold — see CONFORMANCE.md

use opc_protocol::ValidationLevel;

pub mod crypto;
pub mod exchange;
pub mod header;
pub mod ike_auth;
pub mod message;
pub mod nat_detection;
pub mod nat_traversal;
pub mod notify;
pub mod payload;
pub mod protected_payload_crypto;
pub mod sa_init;
pub mod sa_init_crypto;
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
pub use ike_auth::{
    build_child_sa_response_payloads, build_ike_auth_authentication_payload,
    build_ike_auth_cleartext_payload_chain, build_ike_auth_configuration_payload,
    build_ike_auth_identification_payload, build_ike_auth_sa_payload,
    build_ike_auth_traffic_selector_payload, compute_ike_auth_shared_key_mic,
    decode_ike_auth_cleartext_payloads, negotiate_child_sa, verify_ike_auth_shared_key_mic,
    Ikev2AuthenticationPayload, Ikev2AuthenticationPayloadBuild, Ikev2ChildSaNegotiation,
    Ikev2ChildSaNegotiationError, Ikev2ChildSaNegotiationPolicy, Ikev2ChildSaResponsePayloads,
    Ikev2ChildSaTransformRequirement, Ikev2ConfigurationAttribute,
    Ikev2ConfigurationAttributeBuild, Ikev2ConfigurationPayload, Ikev2ConfigurationPayloadBuild,
    Ikev2DeletePayload, Ikev2EapPayload, Ikev2IdentificationPayload,
    Ikev2IdentificationPayloadBuild, Ikev2IkeAuthBuildError, Ikev2IkeAuthCleartextPayloads,
    Ikev2IkeAuthPayloadBuild, Ikev2IkeAuthPayloadError, Ikev2IkeAuthPeer, Ikev2IkeAuthSignedOctets,
    Ikev2IkeAuthVerificationError, Ikev2TrafficSelector, Ikev2TrafficSelectorBuild,
    Ikev2TrafficSelectorPayload, Ikev2TrafficSelectorPayloadBuild,
    IKEV2_AUTH_METHOD_SHARED_KEY_MIC, IKEV2_TS_IPV4_ADDR_RANGE, IKEV2_TS_IPV6_ADDR_RANGE,
};
pub use message::{Message, OwnedMessage};
pub use nat_detection::{
    evaluate_ikev2_nat_detection, ikev2_nat_detection_hash, Ikev2NatDetectionEndpointStatus,
    Ikev2NatDetectionEvaluation, Ikev2NatDetectionObservedEndpoint, Ikev2NatDetectionOutcome,
    Ikev2NatDetectionPayloadError, Ikev2NatDetectionPayloads, IKEV2_NAT_DETECTION_HASH_LEN,
};
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
    IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP, IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP,
    IKEV2_NOTIFY_PROTOCOL_ID_NONE,
};
pub use payload::{
    validate_payload_chain, PayloadChain, PayloadType, RawPayload, RawPayloadIterator,
    GENERIC_PAYLOAD_HEADER_LEN,
};
pub use protected_payload_crypto::{
    decrypt_ikev2_sa_init_protected_payload, seal_ikev2_sa_init_protected_payload,
    Ikev2ProtectedPayloadCryptoError, Ikev2ProtectedPayloadCryptoErrorCode,
    Ikev2ProtectedPayloadDirection, Ikev2SaInitProtectedPayloadProvider,
    ProtectedPayloadSealContext, IKEV2_AES_GCM_EXPLICIT_IV_LEN,
};
pub use sa_init::{
    build_ike_sa_init_response, decode_ike_sa_init_request_payloads, Ikev2KeyExchangePayload,
    Ikev2KeyExchangePayloadBuild, Ikev2KeyExchangePayloadError, Ikev2NoncePayload,
    Ikev2NoncePayloadBuild, Ikev2NoncePayloadError, Ikev2NotifyPayloadBuild, Ikev2SaInitBuildError,
    Ikev2SaInitPayloadError, Ikev2SaInitPayloads, Ikev2SaInitResponsePayloads, Ikev2SaPayload,
    Ikev2SaPayloadBuild, Ikev2SaPayloadError, Ikev2SaProposal, Ikev2SaProposalBuild,
    Ikev2SaTransform, Ikev2SaTransformBuild, Ikev2TransformAttribute, Ikev2TransformAttributeBuild,
    Ikev2TransformAttributeBuildValue, Ikev2TransformAttributeValue, Ikev2VendorIdPayload,
    Ikev2VendorIdPayloadError,
};
pub use sa_init_crypto::{
    derive_ike_sa_init_key_material, Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2EphemeralDhKey,
    Ikev2PrfAlgorithm, Ikev2SaInitCryptoError, Ikev2SaInitCryptoErrorCode,
    Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial,
};

pub(crate) const fn is_strict(level: ValidationLevel) -> bool {
    matches!(
        level,
        ValidationLevel::Strict | ValidationLevel::ProcedureAware
    )
}
