#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

//! GTPv2-C protocol crate for OpenPacketCore S2b work.
//!
//! This crate provides a bounded GTPv2-C codec surface for S2b work. It keeps
//! the raw-preserving common-header and TLIV IE layer for forwarding paths, and
//! adds an experimental typed subset for Echo, session procedures, and
//! PGW-triggered Create/Update/Delete Bearer. Dedicated-bearer views use the
//! canonical TS 24.008 TFT model from `opc-proto-tft`, validate typed Bearer
//! QoS, S2b-U IE roles, bounded request-only control-IE lists, precise TFT
//! rejection Causes, and bearer correlation required by TS 29.274. They can be
//! paired with the bounded [`Gtpv2cTriggeredTransactions`] registry for
//! generation-bound at-most-once application dispatch and exact committed
//! response replay. Unsupported IEs remain raw-preserved.
//! S2b Create Session Requests carry the requested family only in
//! [`PdnAddressAllocation`]; explicit dynamic/static constructors prevent a
//! top-level PDN Type IE or family/address-shape mismatch from being emitted.
//! Their conditional context is also typed: AAA/HSS-provenanced MSISDN,
//! UICC-less emergency identity, charging/trace data, WLAN location, and UE
//! NAT metadata use exact S2b instances. The optional Fixed Broadband ePDG
//! IKEv2 endpoint is a separate role from the UE endpoint. Delete Session
//! requires the S2b UE Local IP and supports typed Diameter/IKEv2 release
//! cause, procedure-specific NAT ports, and location/timestamp projection.
//! [`PcoRequest`] can independently encode the empty TS 24.008 container
//! `0x0012` for P-CSCF reselection support into either opaque PCO transport,
//! without inferring support from P-CSCF address-family requests.
//! Product code remains responsible for deciding when optional policy-owned
//! values apply and for obtaining them from AAA/HSS or local configuration.
//! S2b Modify Bearer uses the UE-initiated IPsec tunnel-update profile:
//! independently optional typed WLAN location/timestamp values and a distinct
//! Fixed Broadband endpoint form whose UDP port cannot exist without its UE
//! Local IP address. Procedure-aware receive applies first-occurrence semantics
//! and discards the non-S2b Bearer Context request shape before interpretation;
//! the exact Table 7.2.7-1 ePDG overload-control assignment remains available.
//! [`inspect_gtpv2c_request`] and [`Gtpv2cErrorResponsePlanner`] provide a
//! separate zero-allocation, reply-safe boundary for TS 29.274 protocol errors:
//! header-only Version Not Supported, Echo special handling, or bounded
//! Cause-bearing S2b response plans. Typed envelope continuations keep
//! unsupported-version planning independent of decode-failure evidence.
//! Transport admission and rate limits remain caller owned.
//!
//! @spec 3GPP TS29274 R18
//! @req REQ-3GPP-TS29274-R18-S2B-001
//! @conformance s2b-subset — see CONFORMANCE.md

use opc_protocol::ValidationLevel;

/// Return `true` when `level` enables strict boundary checks.
pub(crate) const fn is_strict(level: ValidationLevel) -> bool {
    matches!(
        level,
        ValidationLevel::Strict | ValidationLevel::ProcedureAware
    )
}

pub mod dedicated_bearer;
pub mod error_response;
pub mod header;
pub mod ie;
pub mod message;
pub mod pco;
pub mod s2b;
pub mod triggered;

pub use dedicated_bearer::{
    correlate_create_bearer_response, correlate_delete_bearer_response,
    correlate_update_bearer_response, dedicated_bearer_decode_rejection_cause,
    s2b_create_bearer_request, s2b_create_bearer_response, s2b_delete_bearer_request,
    s2b_delete_bearer_response, s2b_update_bearer_request, s2b_update_bearer_response,
    DedicatedBearerError, DedicatedBearerErrorKind, S2bCreateBearerRequest,
    S2bCreateBearerRequestContext, S2bCreateBearerResponse, S2bCreateBearerResult,
    S2bDeleteBearerRequest, S2bDeleteBearerResponse, S2bDeleteBearerResponseBody,
    S2bDeleteBearerResult, S2bDeleteBearerTarget, S2bUpdateBearerRequest,
    S2bUpdateBearerRequestContext, S2bUpdateBearerResponse, S2bUpdateBearerResult,
    MAX_DEDICATED_BEARER_CONTEXTS, MAX_PGW_APN_LOAD_CONTROL_INFORMATION_IES,
    MAX_PGW_OVERLOAD_CONTROL_INFORMATION_IES,
};

pub use error_response::{
    inspect_gtpv2c_request, Gtpv2cAmplificationMetadata, Gtpv2cErrorResponseDecision,
    Gtpv2cErrorResponseKind, Gtpv2cErrorResponsePlan, Gtpv2cErrorResponsePlanner,
    Gtpv2cInvalidOffendingIeInstance, Gtpv2cInvalidSequenceNumber, Gtpv2cOffendingIe,
    Gtpv2cPlannedSend, Gtpv2cProtocolError, Gtpv2cProtocolErrorKind,
    Gtpv2cProtocolErrorResponseTeid, Gtpv2cReceivedPeerMetadata, Gtpv2cReceivedTeid,
    Gtpv2cRequestEnvelope, Gtpv2cRequestFailure, Gtpv2cRequestInspection, Gtpv2cSendTuple,
    Gtpv2cSequenceNumber, Gtpv2cUnanswerableReason, Gtpv2cUnsupportedVersionEnvelope,
    MAX_GTPV2C_ERROR_RESPONSE_WIRE_LEN,
};

pub use header::{
    decode_header, encode_header, Header, InvalidMessagePriority, MessagePriority, MessageType,
    GTPV2C_VERSION, MAX_MESSAGE_PRIORITY,
};
pub use ie::{
    decode_typed_ie_sequence, encode_typed_ie_sequence, validate_ie_region, AccessPointName,
    AdditionalProtocolConfigurationOptions, AggregateMaximumBitRate, AllocationRetentionPriority,
    ApnRestriction, BearerContext, BearerQos, BearerQosResourceType, BearerQosValidationError,
    Cause, CauseValue, ChargingCharacteristics, ChargingId, DuplicateIeEvidence, EpsBearerId,
    FullyQualifiedTeid, Ikev2ErrorNotifyType, Ikev2ErrorNotifyTypeError, Indication, IpAddress,
    OwnedRawIe, PdnAddressAllocation, PdnAddressAllocationError, PdnType, PdnTypeValue, PlmnId,
    PortNumber, ProtocolConfigurationOptions, RanNasCause, RatType, RatTypeValue, RawIe,
    RawIeIterator, Recovery, SelectionMode, SelectionModeValue, ServingNetwork, SessionTraceDepth,
    TbcdDigits, TraceInformation, TwanIdentifier, TwanIdentifierError, TwanIdentifierTimestamp,
    TwanLogicalAccessId, TwanRelayIdentity, TypedIe, TypedIeValue, IE_HEADER_LEN, IE_TYPE_AMBR,
    IE_TYPE_APCO, IE_TYPE_APN, IE_TYPE_APN_RESTRICTION, IE_TYPE_BEARER_CONTEXT, IE_TYPE_BEARER_QOS,
    IE_TYPE_BEARER_TFT, IE_TYPE_CAUSE, IE_TYPE_CHARGING_CHARACTERISTICS, IE_TYPE_CHARGING_ID,
    IE_TYPE_EBI, IE_TYPE_F_TEID, IE_TYPE_IMSI, IE_TYPE_INDICATION, IE_TYPE_IP_ADDRESS,
    IE_TYPE_LOAD_CONTROL_INFORMATION, IE_TYPE_MEI, IE_TYPE_MSISDN,
    IE_TYPE_OVERLOAD_CONTROL_INFORMATION, IE_TYPE_PAA, IE_TYPE_PCO, IE_TYPE_PDN_TYPE,
    IE_TYPE_PGW_CHANGE_INFO, IE_TYPE_PORT_NUMBER, IE_TYPE_RAN_NAS_CAUSE, IE_TYPE_RAT_TYPE,
    IE_TYPE_RECOVERY, IE_TYPE_SELECTION_MODE, IE_TYPE_SERVING_NETWORK, IE_TYPE_TRACE_INFORMATION,
    IE_TYPE_TWAN_IDENTIFIER, IE_TYPE_TWAN_IDENTIFIER_TIMESTAMP, MAX_BEARER_QOS_BITRATE_KBPS,
    MAX_DUPLICATE_IE_EVIDENCE, MAX_IKEV2_ERROR_NOTIFY_TYPE, MAX_TWAN_SSID_LEN,
    MAX_TWAN_SUBFIELD_LEN, PAA_ASSIGNED_IPV6_PREFIX_LENGTH,
};
pub use message::{Message, OwnedMessage};
pub use pco::{
    PcoAddressConfiguration, PcoDecodeError, PcoRequest, PCO_CONTAINER_DNS_SERVER_IPV4,
    PCO_CONTAINER_DNS_SERVER_IPV6, PCO_CONTAINER_P_CSCF_IPV4, PCO_CONTAINER_P_CSCF_IPV6,
    PCO_CONTAINER_P_CSCF_RESELECTION_SUPPORT, PCO_HEADER_PPP_FOR_IP_PDN, PCO_MAX_CONTAINERS,
};
#[allow(deprecated)]
pub use s2b::{
    decode_create_session_response_summary, decode_echo_message_evidence, is_s2b_message_type,
    s2b_create_session_accepted_response, s2b_create_session_rejected_response,
    s2b_create_session_request, s2b_delete_session_request, s2b_delete_session_response,
    s2b_echo_request, s2b_echo_response, s2b_modify_bearer_request, s2b_modify_bearer_response,
    s2b_ue_ipsec_tunnel_update_request, CreateSessionAcceptedResponseSummary,
    CreateSessionRejectedResponseSummary, CreateSessionResponseSummary,
    CreateSessionResponseSummaryError, EchoMessageEvidence, EchoMessageEvidenceError,
    Gtpv2cClientResponseEvidence, Gtpv2cClientTransaction, Gtpv2cClientTransactionDecision,
    Gtpv2cClientTransactionKey, Gtpv2cClientTransactionMismatch, Gtpv2cClientTransactionPlan,
    Gtpv2cClientTransactionPlanError, Gtpv2cClientTransactionPolicy,
    Gtpv2cClientTransactionProjection, Gtpv2cClientTransactionSnapshot,
    Gtpv2cClientTransactionState, Gtpv2cEchoPeer, Gtpv2cEchoPeerBlocker, Gtpv2cEchoPeerError,
    Gtpv2cEchoPeerEvent, Gtpv2cEchoPeerPolicy, Gtpv2cEchoPeerProjection, Gtpv2cEchoPeerReadiness,
    Gtpv2cEchoPeerSnapshot, Gtpv2cEchoPeerState, Gtpv2cEchoPeerTransition, Gtpv2cPeerToken,
    MessageDirection, Procedure, S2bAaaProvidedMsisdn, S2bCreateSessionAcceptedResponse,
    S2bCreateSessionContext, S2bCreateSessionContextSummary, S2bCreateSessionIdentity,
    S2bCreateSessionRejectedResponse, S2bCreateSessionRequest, S2bDecodedMessage,
    S2bDeleteSessionContext, S2bDeleteSessionContextSummary, S2bDeleteSessionRequest,
    S2bDeleteSessionResponse, S2bMessage, S2bModifyBearerRequest, S2bModifyBearerResponse,
    S2bProcedureMessage, S2bProfileBuildError, S2bProfileBuildResult, S2bReceiveDiagnostics,
    S2bSessionContextProjectionError, S2bUeEndpoint, S2bUeIpsecTunnelUpdateEndpoint,
    S2bUeIpsecTunnelUpdateProjectionError, S2bUeIpsecTunnelUpdateRequest,
    S2bUeIpsecTunnelUpdateRequestSummary, S2bUeIpsecTunnelUpdateResponseSummary, S2bUeNatTraversal,
    CREATE_BEARER_REQUEST, CREATE_BEARER_RESPONSE, CREATE_SESSION_REQUEST, CREATE_SESSION_RESPONSE,
    DELETE_BEARER_REQUEST, DELETE_BEARER_RESPONSE, DELETE_SESSION_REQUEST, DELETE_SESSION_RESPONSE,
    ECHO_REQUEST, ECHO_RESPONSE, INTERFACE_TYPE_S2B_EPDG_GTP_C, INTERFACE_TYPE_S2B_PGW_GTP_C,
    INTERFACE_TYPE_S2B_U_EPDG_GTP_U, INTERFACE_TYPE_S2B_U_PGW_GTP_U, MODIFY_BEARER_REQUEST,
    MODIFY_BEARER_RESPONSE, UPDATE_BEARER_REQUEST, UPDATE_BEARER_RESPONSE,
};
pub use triggered::{
    Gtpv2cMonotonicMillis, Gtpv2cTriggeredCommit, Gtpv2cTriggeredCompletion,
    Gtpv2cTriggeredOutcome, Gtpv2cTriggeredRequestDisposition, Gtpv2cTriggeredTransactionError,
    Gtpv2cTriggeredTransactionKey, Gtpv2cTriggeredTransactionPolicy,
    Gtpv2cTriggeredTransactionPolicyError, Gtpv2cTriggeredTransactions, Gtpv2cTriggeredWorkToken,
};
