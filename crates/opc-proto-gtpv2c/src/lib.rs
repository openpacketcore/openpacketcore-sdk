#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
#![deny(missing_docs)]

//! GTPv2-C protocol crate for OpenPacketCore S2b work.
//!
//! This crate provides a bounded GTPv2-C codec surface for S2b work. It keeps
//! the raw-preserving common-header and TLIV IE layer for forwarding paths, and
//! adds an experimental typed subset for Echo plus Create/Modify/Delete/Update
//! Session-oriented S2b message views. Unsupported IEs remain raw-preserved.
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

pub mod header;
pub mod ie;
pub mod message;
pub mod s2b;

pub use header::{decode_header, encode_header, Header, MessageType, GTPV2C_VERSION};
pub use ie::{
    decode_typed_ie_sequence, encode_typed_ie_sequence, validate_ie_region, AccessPointName,
    AdditionalProtocolConfigurationOptions, AggregateMaximumBitRate, ApnRestriction, BearerContext,
    BearerQos, Cause, CauseValue, ChargingId, EpsBearerId, FullyQualifiedTeid, Indication,
    OwnedRawIe, PdnAddressAllocation, PdnType, PdnTypeValue, PlmnId, ProtocolConfigurationOptions,
    RatType, RatTypeValue, RawIe, RawIeIterator, Recovery, SelectionMode, SelectionModeValue,
    ServingNetwork, TbcdDigits, TypedIe, TypedIeValue, IE_HEADER_LEN, IE_TYPE_AMBR, IE_TYPE_APCO,
    IE_TYPE_APN, IE_TYPE_APN_RESTRICTION, IE_TYPE_BEARER_CONTEXT, IE_TYPE_BEARER_QOS,
    IE_TYPE_CAUSE, IE_TYPE_CHARGING_ID, IE_TYPE_EBI, IE_TYPE_F_TEID, IE_TYPE_IMSI,
    IE_TYPE_INDICATION, IE_TYPE_MEI, IE_TYPE_MSISDN, IE_TYPE_PAA, IE_TYPE_PCO, IE_TYPE_PDN_TYPE,
    IE_TYPE_RAT_TYPE, IE_TYPE_RECOVERY, IE_TYPE_SELECTION_MODE, IE_TYPE_SERVING_NETWORK,
};
pub use message::{Message, OwnedMessage};
pub use s2b::{
    decode_create_session_response_summary, decode_echo_message_evidence, is_s2b_message_type,
    s2b_create_session_accepted_response, s2b_create_session_rejected_response,
    s2b_create_session_request, s2b_delete_session_request, s2b_delete_session_response,
    s2b_echo_request, s2b_echo_response, s2b_modify_bearer_request, s2b_modify_bearer_response,
    s2b_update_bearer_request, s2b_update_bearer_response, CreateSessionAcceptedResponseSummary,
    CreateSessionRejectedResponseSummary, CreateSessionResponseSummary,
    CreateSessionResponseSummaryError, EchoMessageEvidence, EchoMessageEvidenceError,
    Gtpv2cClientResponseEvidence, Gtpv2cClientTransaction, Gtpv2cClientTransactionDecision,
    Gtpv2cClientTransactionKey, Gtpv2cClientTransactionMismatch, Gtpv2cClientTransactionPlan,
    Gtpv2cClientTransactionPlanError, Gtpv2cClientTransactionPolicy,
    Gtpv2cClientTransactionProjection, Gtpv2cClientTransactionSnapshot,
    Gtpv2cClientTransactionState, Gtpv2cEchoPeer, Gtpv2cEchoPeerBlocker, Gtpv2cEchoPeerError,
    Gtpv2cEchoPeerEvent, Gtpv2cEchoPeerPolicy, Gtpv2cEchoPeerProjection, Gtpv2cEchoPeerReadiness,
    Gtpv2cEchoPeerSnapshot, Gtpv2cEchoPeerState, Gtpv2cEchoPeerTransition, Gtpv2cPeerToken,
    MessageDirection, Procedure, S2bCreateSessionAcceptedResponse,
    S2bCreateSessionRejectedResponse, S2bCreateSessionRequest, S2bDeleteSessionRequest,
    S2bDeleteSessionResponse, S2bMessage, S2bModifyBearerRequest, S2bModifyBearerResponse,
    S2bProcedureMessage, S2bProfileBuildError, S2bProfileBuildResult, S2bUpdateBearerRequest,
    S2bUpdateBearerResponse, CREATE_SESSION_REQUEST, CREATE_SESSION_RESPONSE,
    DELETE_SESSION_REQUEST, DELETE_SESSION_RESPONSE, ECHO_REQUEST, ECHO_RESPONSE,
    INTERFACE_TYPE_S2B_U_EPDG_GTP_U, INTERFACE_TYPE_S2B_U_PGW_GTP_U, MODIFY_BEARER_REQUEST,
    MODIFY_BEARER_RESPONSE, UPDATE_BEARER_REQUEST, UPDATE_BEARER_RESPONSE,
};
