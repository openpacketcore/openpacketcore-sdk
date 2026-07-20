#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

//! Transport-neutral IKEv2 protocol mechanisms for OpenPacketCore.
//!
//! This crate intentionally covers only the transport-neutral IKEv2 wire
//! mechanism that is safe to expose as an SDK primitive today: fixed-header
//! decode/encode, raw-preserving generic payload-chain walking for unencrypted
//! payloads, protected-payload boundary metadata, caller-owned crypto provider
//! traits, typed executable IKE-SA profiles, PRF-HMAC-SHA2-256/384/512, initial
//! and rekey IKE-SA key-agreement/key-derivation material,
//! bounded notify-only IKE_SA_INIT error responses,
//! product-neutral executable IKE_SA_INIT proposal selection, caller-keyed
//! SA_INIT AES-GCM and AES-CBC/SHA-2 protected-payload open/seal helpers, typed
//! IKE_AUTH cleartext payload helpers, transcript-bound shared-key AUTH MIC
//! verification, transcript-bound signature AUTH (RFC 7296 method 1 and
//! RFC 7427 method 14) against caller-trusted keys, typed 3GPP DEVICE_IDENTITY
//! notifications, product-neutral Child SA negotiation intent including
//! authenticated-only ESP ENCR_NULL profiles and KEYMAT, strict responder and
//! initiator boundaries for opened IKE-SA rekey `CREATE_CHILD_SA` exchanges, and strict
//! opened-payload helpers for 3GPP TS 24.302 dedicated-bearer establishment,
//! modification, and deletion. It does not implement an IKE SA state machine,
//! EAP-AKA, retransmission policy, cookie policy, Child SA installation, XFRM
//! programming, or any product-specific 3GPP ePDG policy.
//!
//! Network decoders follow RFC 7296 receiver rules through
//! [`Ikev2ValidationProfile::NetworkReceive`]: sender-zero reserved fields and
//! higher minor versions are ignored without weakening structural, critical
//! payload, integrity, or authentication checks. Use
//! [`Ikev2ValidationProfile::SenderCanonical`] only to audit generated
//! outbound fixtures.
//!
//! @spec IETF RFC7296
//! @req REQ-IETF-RFC7296-IKEV2-SCAFFOLD-001
//! @conformance experimental-mechanism boundary — see CONFORMANCE.md

pub mod crypto;
pub mod dedicated_bearer;
pub mod device_identity;
pub mod exchange;
pub mod fragmentation;
pub mod header;
mod hmac_sha2;
pub mod ike_auth;
pub mod ike_auth_signature;
pub mod ike_sa_rekey;
pub mod message;
pub mod nat_detection;
pub mod nat_traversal;
pub mod notify;
pub mod payload;
pub mod protected_payload_crypto;
pub mod sa_init;
pub mod sa_init_crypto;
pub mod sa_init_negotiation;
pub mod software_crypto;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;
pub mod validation;

pub use crypto::{
    open_protected_payloads, CryptoProvider, OpenedProtectedPayload, ProtectedPayloadContext,
    ProtectedPayloadKind, ProtectedPayloadOpenError, ProtectedPayloadOpenFailure,
};
pub use dedicated_bearer::{
    build_ikev2_dedicated_bearer_create_child_sa_error_response,
    build_ikev2_dedicated_bearer_create_child_sa_request,
    build_ikev2_dedicated_bearer_create_child_sa_response,
    build_ikev2_dedicated_bearer_delete_request, build_ikev2_dedicated_bearer_delete_response,
    build_ikev2_dedicated_bearer_informational_error_response,
    build_ikev2_dedicated_bearer_informational_success_response,
    build_ikev2_dedicated_bearer_modification_request, build_ikev2_dedicated_bearer_notify,
    decode_ikev2_dedicated_bearer_create_child_sa_request,
    decode_ikev2_dedicated_bearer_create_child_sa_request_with_context,
    decode_ikev2_dedicated_bearer_create_child_sa_response,
    decode_ikev2_dedicated_bearer_delete_request, decode_ikev2_dedicated_bearer_delete_response,
    decode_ikev2_dedicated_bearer_informational_response,
    decode_ikev2_dedicated_bearer_modification_request, decode_ikev2_dedicated_bearer_notify,
    validate_ikev2_dedicated_bearer_create_child_sa_response_correlation,
    validate_ikev2_dedicated_bearer_delete_response_correlation,
    validate_ikev2_dedicated_bearer_modification_response_correlation,
    validate_ikev2_dedicated_bearer_response_correlation, Ikev2ApnAmbr, Ikev2ApnAmbrKbps,
    Ikev2ApnAmbrMapping, Ikev2ApnAmbrRateCodes, Ikev2DedicatedBearerCleartextPayloads,
    Ikev2DedicatedBearerCreateChildSaRequest, Ikev2DedicatedBearerCreateChildSaRequestBuild,
    Ikev2DedicatedBearerCreateChildSaResponse, Ikev2DedicatedBearerCreateChildSaResponseBuild,
    Ikev2DedicatedBearerDeleteRequest, Ikev2DedicatedBearerDeleteResponse,
    Ikev2DedicatedBearerDeleteResponseExpectation, Ikev2DedicatedBearerError,
    Ikev2DedicatedBearerEspSpi, Ikev2DedicatedBearerExchangeError,
    Ikev2DedicatedBearerInformationalResponse, Ikev2DedicatedBearerModificationRequest,
    Ikev2DedicatedBearerModificationRequestBuild, Ikev2DedicatedBearerNotify,
    Ikev2DedicatedBearerPayloadRole, Ikev2DedicatedBearerPeerErrorNotify,
    Ikev2DedicatedBearerProtocolError, Ikev2DedicatedBearerResponseError,
    Ikev2EpsBearerBitRatesKbps, Ikev2EpsQos, Ikev2EpsQosKbps, Ikev2EpsQosMapping,
    Ikev2EpsQosRateCodes, Ikev2ExtendedApnAmbr, Ikev2ExtendedBitRateUnit, Ikev2ExtendedEpsQos,
    Ikev2QosDirection, Ikev2QosMappingError, Ikev2QosQuantization, Ikev2QosRateCodeTier,
    Ikev2QosRateField, Ikev2QosResourceType, Ikev2UnknownNonCriticalPayload, IKEV2_NOTIFY_APN_AMBR,
    IKEV2_NOTIFY_EPS_QOS, IKEV2_NOTIFY_EXTENDED_APN_AMBR, IKEV2_NOTIFY_EXTENDED_EPS_QOS,
    IKEV2_NOTIFY_MODIFIED_BEARER, IKEV2_NOTIFY_MULTIPLE_BEARER_PDN_CONNECTIVITY,
    IKEV2_NOTIFY_SEMANTIC_ERRORS_IN_PACKET_FILTERS,
    IKEV2_NOTIFY_SEMANTIC_ERROR_IN_THE_TFT_OPERATION,
    IKEV2_NOTIFY_SYNTACTICAL_ERRORS_IN_PACKET_FILTERS,
    IKEV2_NOTIFY_SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION, IKEV2_NOTIFY_TFT,
};
pub use device_identity::{
    build_ikev2_device_identity_request, build_ikev2_device_identity_response,
    decode_ikev2_device_identity_notify, Ikev2DeviceIdentity, Ikev2DeviceIdentityNotify,
    Ikev2DeviceIdentityNotifyBuildError, Ikev2DeviceIdentityNotifyError, Ikev2DeviceIdentityType,
};
pub use exchange::{
    Ikev2ExchangeBoundaryState, Ikev2ExchangeDecision, Ikev2ExchangeInvalidReason,
    Ikev2ExchangeKind, Ikev2ExchangeProjection, Ikev2ExchangeRequest, Ikev2ExchangeRequestKey,
    Ikev2ExchangeSnapshot, Ikev2ExchangeTracker, Ikev2InitiatorMessageIdAllocation,
    Ikev2InitiatorMessageIdError, Ikev2InitiatorMessageIdSnapshot, Ikev2InitiatorMessageIdWindow,
    Ikev2ResponderMessageIdSnapshot, Ikev2ResponderMessageIdWindow, Ikev2ResponderSpi,
    IKEV2_EXCHANGE_RETRANSMISSION_WINDOW,
};
pub use fragmentation::{
    build_ikev2_encrypted_fragment_payload_body, reassemble_decrypted_ikev2_fragments,
    Ikev2DecryptedFragment, Ikev2EncryptedFragmentPayload, Ikev2EncryptedFragmentPayloadBuild,
    Ikev2FragmentationError, Ikev2ReassembledFragmentedPayloads,
    IKEV2_ENCRYPTED_FRAGMENT_FIXED_BODY_LEN, IKEV2_FRAGMENTATION_SUPPORTED_NOTIFY_TYPE,
};
pub use header::{
    decode_header, decode_header_with_profile, encode_header, Header, HeaderFlags,
    EXCHANGE_TYPE_CREATE_CHILD_SA, EXCHANGE_TYPE_IKE_AUTH, EXCHANGE_TYPE_IKE_SA_INIT,
    EXCHANGE_TYPE_INFORMATIONAL, HEADER_LEN, IKEV2_MAJOR_VERSION, IKEV2_MINOR_VERSION,
    IKEV2_VERSION_OCTET,
};
pub use ike_auth::{
    build_child_sa_response_payloads, build_create_child_sa_rekey_request_payloads,
    build_create_child_sa_rekey_response_payloads, build_delete_payload_body,
    build_ike_auth_authentication_payload, build_ike_auth_certificate_payload,
    build_ike_auth_certreq_payload, build_ike_auth_cleartext_payload_chain,
    build_ike_auth_configuration_payload, build_ike_auth_delete_payload,
    build_ike_auth_identification_payload, build_ike_auth_notify_payload,
    build_ike_auth_sa_payload, build_ike_auth_traffic_selector_payload,
    compute_ike_auth_shared_key_mic, decode_ike_auth_cleartext_payloads,
    decode_ike_auth_cleartext_payloads_with_profile,
    ike_auth_shared_key_authentication_payload_body_len, negotiate_child_sa,
    verify_ike_auth_shared_key_mic, Ikev2AuthenticationPayload, Ikev2AuthenticationPayloadBuild,
    Ikev2CertificatePayload, Ikev2CertificatePayloadBuild, Ikev2CertificateRequestPayload,
    Ikev2CertificateRequestPayloadBuild, Ikev2ChildSaNegotiation, Ikev2ChildSaNegotiationError,
    Ikev2ChildSaNegotiationPolicy, Ikev2ChildSaResponsePayloads, Ikev2ChildSaTransformRequirement,
    Ikev2ConfigurationAttribute, Ikev2ConfigurationAttributeBuild, Ikev2ConfigurationPayload,
    Ikev2ConfigurationPayloadBuild, Ikev2CreateChildSaRekeyRequestBuild,
    Ikev2CreateChildSaRekeyRequestPayloads, Ikev2CreateChildSaRekeyResponseBuild,
    Ikev2CreateChildSaRekeyResponsePayloads, Ikev2DeletePayload, Ikev2EapPayload,
    Ikev2IdentificationPayload, Ikev2IdentificationPayloadBuild, Ikev2IkeAuthBuildError,
    Ikev2IkeAuthCleartextPayloads, Ikev2IkeAuthPayloadBuild, Ikev2IkeAuthPayloadError,
    Ikev2IkeAuthPeer, Ikev2IkeAuthSignedOctets, Ikev2IkeAuthVerificationError,
    Ikev2TrafficSelector, Ikev2TrafficSelectorBuild, Ikev2TrafficSelectorPayload,
    Ikev2TrafficSelectorPayloadBuild, IKEV2_AUTH_METHOD_SHARED_KEY_MIC,
    IKEV2_CERT_ENCODING_X509_SIGNATURE, IKEV2_IKE_SA_DELETE_SPI_SIZE, IKEV2_IPSEC_SPI_SIZE,
    IKEV2_SECURITY_PROTOCOL_ID_AH, IKEV2_SECURITY_PROTOCOL_ID_ESP, IKEV2_SECURITY_PROTOCOL_ID_IKE,
    IKEV2_TS_IPV4_ADDR_RANGE, IKEV2_TS_IPV6_ADDR_RANGE,
};
pub use ike_auth_signature::{
    compute_ike_auth_signature, verify_ike_auth_signature, Ikev2SignatureAuthKey,
    Ikev2SignatureAuthMethod, Ikev2SignatureKeyError, Ikev2SignaturePublicKey,
    IKEV2_AUTH_METHOD_DIGITAL_SIGNATURE, IKEV2_AUTH_METHOD_RSA_DIGITAL_SIGNATURE,
    RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_256, RFC7427_ALGORITHM_IDENTIFIER_ECDSA_SHA2_384,
    RFC7427_ALGORITHM_IDENTIFIER_RSA_SHA2_256,
};
pub use ike_sa_rekey::{
    build_ike_sa_rekey_request, build_ike_sa_rekey_response, decode_ike_sa_rekey_request,
    decode_ike_sa_rekey_request_with_context, decode_ike_sa_rekey_response,
    decode_ike_sa_rekey_response_with_context, negotiate_ike_sa_rekey, Ikev2IkeSaRekeyBuildError,
    Ikev2IkeSaRekeyNegotiation, Ikev2IkeSaRekeyPayloadRole, Ikev2IkeSaRekeyRequest,
    Ikev2IkeSaRekeyRequestBuild, Ikev2IkeSaRekeyRequestBuildError, Ikev2IkeSaRekeyRequestError,
    Ikev2IkeSaRekeyRequestPayloads, Ikev2IkeSaRekeyResponse, Ikev2IkeSaRekeyResponseBuild,
    Ikev2IkeSaRekeyResponseError, Ikev2IkeSaRekeyResponsePayloads, Ikev2IkeSaRekeySentRequest,
    IKEV2_REKEY_IKE_SPI_LEN,
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
    Ikev2NotifyPayloadError, IKEV2_NOTIFY_AUTHENTICATION_FAILED, IKEV2_NOTIFY_CHILD_SA_NOT_FOUND,
    IKEV2_NOTIFY_COOKIE, IKEV2_NOTIFY_COOKIE2, IKEV2_NOTIFY_DEVICE_IDENTITY,
    IKEV2_NOTIFY_EAP_ONLY_AUTHENTICATION, IKEV2_NOTIFY_FAILED_CP_REQUIRED,
    IKEV2_NOTIFY_INTERNAL_ADDRESS_FAILURE, IKEV2_NOTIFY_INVALID_IKE_SPI,
    IKEV2_NOTIFY_INVALID_KE_PAYLOAD, IKEV2_NOTIFY_INVALID_MAJOR_VERSION,
    IKEV2_NOTIFY_INVALID_MESSAGE_ID, IKEV2_NOTIFY_INVALID_SELECTORS, IKEV2_NOTIFY_INVALID_SPI,
    IKEV2_NOTIFY_INVALID_SYNTAX, IKEV2_NOTIFY_NAT_DETECTION_DESTINATION_IP,
    IKEV2_NOTIFY_NAT_DETECTION_SOURCE_IP, IKEV2_NOTIFY_NO_ADDITIONAL_SAS,
    IKEV2_NOTIFY_NO_PROPOSAL_CHOSEN, IKEV2_NOTIFY_PROTOCOL_ID_NONE, IKEV2_NOTIFY_REKEY_SA,
    IKEV2_NOTIFY_SINGLE_PAIR_REQUIRED, IKEV2_NOTIFY_TEMPORARY_FAILURE,
    IKEV2_NOTIFY_TS_UNACCEPTABLE, IKEV2_NOTIFY_UNSUPPORTED_CRITICAL_PAYLOAD,
};
pub use payload::{
    validate_payload_chain, validate_payload_chain_with_profile, PayloadChain, PayloadType,
    RawPayload, RawPayloadIterator, GENERIC_PAYLOAD_HEADER_LEN,
};
pub use protected_payload_crypto::{
    decrypt_ikev2_sa_init_protected_payload, ikev2_aes_cbc_padding_len,
    ikev2_aes_cbc_protected_body_len, ikev2_aes_cbc_protected_payload_len,
    ikev2_aes_gcm_protected_body_len, ikev2_aes_gcm_protected_payload_len,
    seal_ikev2_sa_init_aes_cbc_protected_payload,
    seal_ikev2_sa_init_aes_cbc_protected_payload_with_iv_for_test_vector,
    seal_ikev2_sa_init_aes_cbc_protected_payload_with_rng, seal_ikev2_sa_init_protected_payload,
    seal_ikev2_sa_init_protected_payload_with_iv_counter, Ikev2AesGcmExplicitIvCounter,
    Ikev2ProtectedPayloadCryptoError, Ikev2ProtectedPayloadCryptoErrorCode,
    Ikev2ProtectedPayloadDirection, Ikev2ProtectedPayloadOpenError,
    Ikev2SaInitProtectedPayloadProvider, ProtectedPayloadSealContext, IKEV2_AES_CBC_IV_LEN,
    IKEV2_AES_GCM_EXPLICIT_IV_LEN,
};
pub use sa_init::{
    build_ike_sa_init_invalid_ke_response, build_ike_sa_init_notify_response,
    build_ike_sa_init_response, build_ike_sa_init_unsupported_critical_payload_response,
    decode_ike_sa_init_request_payloads, decode_ike_sa_init_request_payloads_with_profile,
    encode_nonce_payload_build, Ikev2KeyExchangePayload, Ikev2KeyExchangePayloadBuild,
    Ikev2KeyExchangePayloadError, Ikev2NoncePayload, Ikev2NoncePayloadBuild,
    Ikev2NoncePayloadError, Ikev2NotifyPayloadBuild, Ikev2SaInitBuildError,
    Ikev2SaInitNotifyBuildError, Ikev2SaInitPayloadError, Ikev2SaInitPayloads,
    Ikev2SaInitResponsePayloads, Ikev2SaPayload, Ikev2SaPayloadBuild, Ikev2SaPayloadError,
    Ikev2SaProposal, Ikev2SaProposalBuild, Ikev2SaTransform, Ikev2SaTransformBuild,
    Ikev2TransformAttribute, Ikev2TransformAttributeBuild, Ikev2TransformAttributeBuildValue,
    Ikev2TransformAttributeValue, Ikev2VendorIdPayload, Ikev2VendorIdPayloadError,
};
pub use sa_init_crypto::{
    derive_child_sa_key_material, derive_ike_sa_init_key_material,
    derive_ike_sa_rekey_key_material, Ikev2ChildSaCryptoProfile, Ikev2ChildSaKeyMaterial,
    Ikev2DhGroup, Ikev2EncryptionAlgorithm, Ikev2EphemeralDhKey, Ikev2IntegrityAlgorithm,
    Ikev2PrfAlgorithm, Ikev2SaInitCryptoError, Ikev2SaInitCryptoErrorCode,
    Ikev2SaInitCryptoProfile, Ikev2SaInitKeyMaterial,
};
pub use sa_init_negotiation::{
    negotiate_ike_sa_init, Ikev2SaInitNegotiation, Ikev2SaInitNegotiationError,
    Ikev2SaInitNegotiationPolicy,
};
pub use software_crypto::Ikev2SoftwareCryptoOperations;
pub use validation::Ikev2ValidationProfile;
