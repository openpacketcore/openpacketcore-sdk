//! S2b-oriented GTPv2-C message views.
//!
//! The S2b surface in this crate is intentionally a typed subset: it decodes
//! Echo plus Create/Modify/Delete Session and triggered bearer GTPv2-C messages,
//! exposes mandatory S2b IE examples through typed values, and keeps
//! unsupported IEs as raw-preserving fallbacks. It is not a full ePDG or PGW
//! control-plane implementation.
//!
//! @spec 3GPP TS29274 R18 S2b procedure use
//! @req REQ-3GPP-TS29274-R18-S2B-001

use core::fmt;

use bytes::BytesMut;
use opc_protocol::{
    BorrowDecode, DecodeContext, DecodeError, DecodeErrorCode, DecodeResult, DuplicateIePolicy,
    Encode, EncodeContext, EncodeError, EncodeErrorCode, SpecRef, ValidationLevel,
};

use crate::header::Header;
pub use crate::header::MessageType;
use crate::ie::typed::decode_pgw_triggered_request_ie_sequence;
use crate::ie::{
    decode_typed_ie_sequence, encode_typed_ie_sequence, AccessPointName, BearerContext, Cause,
    CauseValue, EpsBearerId, FullyQualifiedTeid, PdnAddressAllocation, PdnType,
    ProtocolConfigurationOptions, RatType, Recovery, SelectionMode, ServingNetwork, TbcdDigits,
    TypedIe, TypedIeValue, IE_TYPE_APN, IE_TYPE_BEARER_CONTEXT, IE_TYPE_CAUSE, IE_TYPE_EBI,
    IE_TYPE_F_TEID, IE_TYPE_IMSI, IE_TYPE_MEI, IE_TYPE_PAA, IE_TYPE_PCO, IE_TYPE_PDN_TYPE,
    IE_TYPE_RAT_TYPE, IE_TYPE_RECOVERY, IE_TYPE_SELECTION_MODE, IE_TYPE_SERVING_NETWORK,
};
use crate::{Message, OwnedMessage};

/// Echo Request message type.
pub const ECHO_REQUEST: u8 = 1;

/// Echo Response message type.
pub const ECHO_RESPONSE: u8 = 2;

/// Create Session Request message type.
pub const CREATE_SESSION_REQUEST: u8 = 32;

/// Create Session Response message type.
pub const CREATE_SESSION_RESPONSE: u8 = 33;

/// Modify Bearer Request message type used by the S2b Modify Session view.
pub const MODIFY_BEARER_REQUEST: u8 = 34;

/// Modify Bearer Response message type used by the S2b Modify Session view.
pub const MODIFY_BEARER_RESPONSE: u8 = 35;

/// Delete Session Request message type.
pub const DELETE_SESSION_REQUEST: u8 = 36;

/// Delete Session Response message type.
pub const DELETE_SESSION_RESPONSE: u8 = 37;

/// Create Bearer Request message type.
pub const CREATE_BEARER_REQUEST: u8 = 95;

/// Create Bearer Response message type.
pub const CREATE_BEARER_RESPONSE: u8 = 96;

/// Update Bearer Request message type.
pub const UPDATE_BEARER_REQUEST: u8 = 97;

/// Update Bearer Response message type.
pub const UPDATE_BEARER_RESPONSE: u8 = 98;

/// Delete Bearer Request message type.
pub const DELETE_BEARER_REQUEST: u8 = 99;

/// Delete Bearer Response message type.
pub const DELETE_BEARER_RESPONSE: u8 = 100;

/// GTPv2-C interface type for S2b ePDG GTP-C from 3GPP TS 29.274
/// Table 8.22-1.
pub const INTERFACE_TYPE_S2B_EPDG_GTP_C: u8 = 30;

/// GTPv2-C interface type for S2b-U ePDG GTP-U from 3GPP TS 29.274
/// Table 8.22-1.
pub const INTERFACE_TYPE_S2B_U_EPDG_GTP_U: u8 = 31;

/// GTPv2-C interface type for S2b PGW GTP-C from 3GPP TS 29.274
/// Table 8.22-1.
pub const INTERFACE_TYPE_S2B_PGW_GTP_C: u8 = 32;

/// GTPv2-C interface type for S2b-U PGW GTP-U from 3GPP TS 29.274
/// Table 8.22-1.
pub const INTERFACE_TYPE_S2B_U_PGW_GTP_U: u8 = 33;

/// Result type for S2b Production Profile v1 constructors.
pub type S2bProfileBuildResult<T> = Result<T, S2bProfileBuildError>;

/// Error returned when an S2b Production Profile v1 constructor cannot build a
/// profile-valid message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S2bProfileBuildError {
    /// Typed IE or message encoding failed.
    Encode(EncodeError),
    /// The constructed message failed procedure-aware profile validation.
    Validate(DecodeError),
}

impl fmt::Display for S2bProfileBuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(source) => write!(formatter, "S2b profile encode failed: {source}"),
            Self::Validate(source) => {
                write!(formatter, "S2b profile validation failed: {source}")
            }
        }
    }
}

impl std::error::Error for S2bProfileBuildError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encode(source) => Some(source),
            Self::Validate(source) => Some(source),
        }
    }
}

impl From<EncodeError> for S2bProfileBuildError {
    fn from(source: EncodeError) -> Self {
        Self::Encode(source)
    }
}

impl From<DecodeError> for S2bProfileBuildError {
    fn from(source: DecodeError) -> Self {
        Self::Validate(source)
    }
}

/// Input for building an S2b Production Profile v1 Create Session Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S2bCreateSessionRequest<'a> {
    /// GTPv2-C sequence number.
    pub sequence_number: u32,
    /// IMSI IE.
    pub imsi: TbcdDigits,
    /// RAT Type IE.
    pub rat_type: RatType,
    /// Serving Network IE.
    pub serving_network: ServingNetwork,
    /// Sender F-TEID IE; encoded at instance 0.
    pub sender_f_teid: FullyQualifiedTeid,
    /// APN IE.
    pub apn: AccessPointName,
    /// Selection Mode IE.
    pub selection_mode: SelectionMode,
    /// PDN Type IE.
    pub pdn_type: PdnType,
    /// PDN Address Allocation IE.
    pub paa: PdnAddressAllocation,
    /// Bearer Context IE containing at least an EBI member. A Create Session
    /// Request may also carry the ePDG S2b-U user-plane F-TEID here.
    pub bearer_context: BearerContext<'a>,
    /// Additional typed IEs to append after the mandatory profile-owned IEs.
    pub additional_ies: Vec<TypedIe<'a>>,
}

/// Input for building an accepted S2b Production Profile v1 Create Session Response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S2bCreateSessionAcceptedResponse<'a> {
    /// GTPv2-C sequence number.
    pub sequence_number: u32,
    /// TEID carried in the response common header.
    pub response_teid: u32,
    /// Sender F-TEID IE; encoded at instance 0.
    pub sender_f_teid: FullyQualifiedTeid,
    /// Bearer Context IE containing the accepted bearer EBI.
    pub bearer_context: BearerContext<'a>,
    /// Additional typed IEs to append after Cause, Sender F-TEID, and Bearer Context.
    pub additional_ies: Vec<TypedIe<'a>>,
}

/// Input for building a rejected S2b Production Profile v1 Create Session Response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S2bCreateSessionRejectedResponse<'a> {
    /// GTPv2-C sequence number.
    pub sequence_number: u32,
    /// TEID carried in the response common header.
    pub response_teid: u32,
    /// Non-accepted Cause value.
    pub cause: CauseValue,
    /// Additional typed IEs to append after Cause.
    pub additional_ies: Vec<TypedIe<'a>>,
}

/// Input for building an S2b Production Profile v1 Modify Bearer Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S2bModifyBearerRequest<'a> {
    /// GTPv2-C sequence number.
    pub sequence_number: u32,
    /// TEID carried in the request common header.
    pub teid: u32,
    /// Bearer Context IE.
    pub bearer_context: BearerContext<'a>,
    /// Additional typed IEs to append after Bearer Context.
    pub additional_ies: Vec<TypedIe<'a>>,
}

/// Input for building an S2b Production Profile v1 Modify Bearer Response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S2bModifyBearerResponse<'a> {
    /// GTPv2-C sequence number.
    pub sequence_number: u32,
    /// TEID carried in the response common header.
    pub teid: u32,
    /// Cause value.
    pub cause: CauseValue,
    /// Additional typed IEs to append after Cause.
    pub additional_ies: Vec<TypedIe<'a>>,
}

/// Input for building an S2b Production Profile v1 Delete Session Request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S2bDeleteSessionRequest<'a> {
    /// GTPv2-C sequence number.
    pub sequence_number: u32,
    /// TEID carried in the request common header.
    pub teid: u32,
    /// Linked EPS Bearer ID IE.
    pub linked_ebi: EpsBearerId,
    /// Additional typed IEs to append after linked EBI.
    pub additional_ies: Vec<TypedIe<'a>>,
}

/// Input for building an S2b Production Profile v1 Delete Session Response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S2bDeleteSessionResponse<'a> {
    /// GTPv2-C sequence number.
    pub sequence_number: u32,
    /// TEID carried in the response common header.
    pub teid: u32,
    /// Cause value.
    pub cause: CauseValue,
    /// Additional typed IEs to append after Cause.
    pub additional_ies: Vec<TypedIe<'a>>,
}

/// Build an S2b Production Profile v1 Echo Request.
///
/// # Errors
///
/// Returns [`S2bProfileBuildError`] when the Recovery IE cannot encode or the
/// constructed message fails procedure-aware validation.
pub fn s2b_echo_request(
    sequence_number: u32,
    recovery: Recovery,
) -> S2bProfileBuildResult<OwnedMessage> {
    build_s2b_profile_message(
        Header::without_teid(ECHO_REQUEST, sequence_number),
        vec![typed_ie(0, TypedIeValue::Recovery(recovery))],
    )
}

/// Build an S2b Production Profile v1 Echo Response.
///
/// # Errors
///
/// Returns [`S2bProfileBuildError`] when the Recovery IE cannot encode or the
/// constructed message fails procedure-aware validation.
pub fn s2b_echo_response(
    sequence_number: u32,
    recovery: Recovery,
) -> S2bProfileBuildResult<OwnedMessage> {
    build_s2b_profile_message(
        Header::without_teid(ECHO_RESPONSE, sequence_number),
        vec![typed_ie(0, TypedIeValue::Recovery(recovery))],
    )
}

/// Build an S2b Production Profile v1 Create Session Request.
///
/// # Errors
///
/// Returns [`S2bProfileBuildError`] when any typed IE cannot encode or the
/// constructed message fails procedure-aware validation.
pub fn s2b_create_session_request(
    request: S2bCreateSessionRequest<'_>,
) -> S2bProfileBuildResult<OwnedMessage> {
    let mut ies = vec![
        typed_ie(0, TypedIeValue::Imsi(request.imsi)),
        typed_ie(0, TypedIeValue::RatType(request.rat_type)),
        typed_ie(0, TypedIeValue::ServingNetwork(request.serving_network)),
        typed_ie(0, TypedIeValue::FullyQualifiedTeid(request.sender_f_teid)),
        typed_ie(0, TypedIeValue::AccessPointName(request.apn)),
        typed_ie(0, TypedIeValue::SelectionMode(request.selection_mode)),
        typed_ie(0, TypedIeValue::PdnType(request.pdn_type)),
        typed_ie(0, TypedIeValue::PdnAddressAllocation(request.paa)),
        typed_ie(0, TypedIeValue::BearerContext(request.bearer_context)),
    ];
    ies.extend(request.additional_ies);
    build_s2b_profile_message(
        Header::with_teid(CREATE_SESSION_REQUEST, 0, request.sequence_number),
        ies,
    )
}

/// Build an accepted S2b Production Profile v1 Create Session Response.
///
/// # Errors
///
/// Returns [`S2bProfileBuildError`] when any typed IE cannot encode or the
/// constructed accepted response fails procedure-aware validation.
pub fn s2b_create_session_accepted_response(
    response: S2bCreateSessionAcceptedResponse<'_>,
) -> S2bProfileBuildResult<OwnedMessage> {
    let mut ies = vec![
        typed_ie(0, TypedIeValue::Cause(accepted_cause())),
        typed_ie(0, TypedIeValue::FullyQualifiedTeid(response.sender_f_teid)),
        typed_ie(0, TypedIeValue::BearerContext(response.bearer_context)),
    ];
    ies.extend(response.additional_ies);
    build_s2b_profile_message(
        Header::with_teid(
            CREATE_SESSION_RESPONSE,
            response.response_teid,
            response.sequence_number,
        ),
        ies,
    )
}

/// Build a rejected S2b Production Profile v1 Create Session Response.
///
/// # Errors
///
/// Returns [`S2bProfileBuildError`] when Cause cannot encode or the rejected
/// response fails procedure-aware validation.
pub fn s2b_create_session_rejected_response(
    response: S2bCreateSessionRejectedResponse<'_>,
) -> S2bProfileBuildResult<OwnedMessage> {
    let mut ies = vec![typed_ie(0, TypedIeValue::Cause(cause(response.cause)))];
    ies.extend(response.additional_ies);
    build_s2b_profile_message(
        Header::with_teid(
            CREATE_SESSION_RESPONSE,
            response.response_teid,
            response.sequence_number,
        ),
        ies,
    )
}

/// Build an S2b Production Profile v1 Modify Bearer Request.
///
/// # Errors
///
/// Returns [`S2bProfileBuildError`] when Bearer Context cannot encode or the
/// constructed request fails procedure-aware validation.
pub fn s2b_modify_bearer_request(
    request: S2bModifyBearerRequest<'_>,
) -> S2bProfileBuildResult<OwnedMessage> {
    build_bearer_context_request(
        MODIFY_BEARER_REQUEST,
        request.sequence_number,
        request.teid,
        request.bearer_context,
        request.additional_ies,
    )
}

/// Build an S2b Production Profile v1 Modify Bearer Response.
///
/// # Errors
///
/// Returns [`S2bProfileBuildError`] when Cause cannot encode or the response
/// fails procedure-aware validation.
pub fn s2b_modify_bearer_response(
    response: S2bModifyBearerResponse<'_>,
) -> S2bProfileBuildResult<OwnedMessage> {
    build_cause_response(
        MODIFY_BEARER_RESPONSE,
        response.sequence_number,
        response.teid,
        response.cause,
        response.additional_ies,
    )
}

/// Build an S2b Production Profile v1 Delete Session Request.
///
/// # Errors
///
/// Returns [`S2bProfileBuildError`] when linked EBI cannot encode or the
/// constructed request fails procedure-aware validation.
pub fn s2b_delete_session_request(
    request: S2bDeleteSessionRequest<'_>,
) -> S2bProfileBuildResult<OwnedMessage> {
    let mut ies = vec![typed_ie(0, TypedIeValue::EpsBearerId(request.linked_ebi))];
    ies.extend(request.additional_ies);
    build_s2b_profile_message(
        Header::with_teid(
            DELETE_SESSION_REQUEST,
            request.teid,
            request.sequence_number,
        ),
        ies,
    )
}

/// Build an S2b Production Profile v1 Delete Session Response.
///
/// # Errors
///
/// Returns [`S2bProfileBuildError`] when Cause cannot encode or the response
/// fails procedure-aware validation.
pub fn s2b_delete_session_response(
    response: S2bDeleteSessionResponse<'_>,
) -> S2bProfileBuildResult<OwnedMessage> {
    build_cause_response(
        DELETE_SESSION_RESPONSE,
        response.sequence_number,
        response.teid,
        response.cause,
        response.additional_ies,
    )
}

fn build_bearer_context_request<'a>(
    message_type: u8,
    sequence_number: u32,
    teid: u32,
    bearer_context: BearerContext<'a>,
    additional_ies: Vec<TypedIe<'a>>,
) -> S2bProfileBuildResult<OwnedMessage> {
    let mut ies = vec![typed_ie(0, TypedIeValue::BearerContext(bearer_context))];
    ies.extend(additional_ies);
    build_s2b_profile_message(Header::with_teid(message_type, teid, sequence_number), ies)
}

fn build_cause_response<'a>(
    message_type: u8,
    sequence_number: u32,
    teid: u32,
    cause_value: CauseValue,
    additional_ies: Vec<TypedIe<'a>>,
) -> S2bProfileBuildResult<OwnedMessage> {
    let mut ies = vec![typed_ie(0, TypedIeValue::Cause(cause(cause_value)))];
    ies.extend(additional_ies);
    build_s2b_profile_message(Header::with_teid(message_type, teid, sequence_number), ies)
}

pub(crate) fn typed_ie<'a>(instance: u8, value: TypedIeValue<'a>) -> TypedIe<'a> {
    TypedIe { instance, value }
}

pub(crate) fn cause(value: CauseValue) -> Cause {
    Cause {
        value,
        flags_octet: 0,
        offending_ie: Vec::new(),
    }
}

fn accepted_cause() -> Cause {
    cause(CauseValue::RequestAccepted)
}

pub(crate) fn profile_decode_context() -> DecodeContext {
    DecodeContext {
        duplicate_ie_policy: DuplicateIePolicy::Reject,
        validation_level: ValidationLevel::ProcedureAware,
        ..DecodeContext::default()
    }
}

pub(crate) fn build_s2b_profile_message<'a>(
    header: Header,
    ies: Vec<TypedIe<'a>>,
) -> S2bProfileBuildResult<OwnedMessage> {
    let encode_context = EncodeContext::default();
    let mut raw_ies = BytesMut::new();
    encode_typed_ie_sequence(&ies, &mut raw_ies, encode_context)?;
    let message = OwnedMessage {
        header,
        raw_ies: raw_ies.freeze(),
    };
    message.wire_len(encode_context)?;
    validate_built_s2b_profile_message(&message)?;
    Ok(message)
}

fn validate_built_s2b_profile_message(message: &OwnedMessage) -> Result<(), DecodeError> {
    let view = S2bMessage::from_message(message.as_borrowed(), profile_decode_context())?;
    if view.as_view().is_some() {
        Ok(())
    } else {
        Err(missing_ie_error(
            "S2b profile constructor produced a non-S2b message",
        ))
    }
}

/// Accepted Create Session Response projection.
///
/// This projection is intentionally strict: it is returned for TS 29.274
/// accepted causes 16 (`RequestAccepted`) and 17
/// (`RequestAcceptedPartially`) and includes the accepted-bearer fields that
/// products need to derive an established bearer context. Consumers must
/// inspect [`Self::cause`] to distinguish full and partial acceptance.
#[derive(Clone, PartialEq, Eq)]
pub struct CreateSessionAcceptedResponseSummary {
    /// TEID carried in the Create Session Response common header.
    pub response_teid: u32,
    /// GTPv2-C sequence number from the Create Session Response header.
    pub sequence_number: u32,
    /// Cause value from the Cause IE.
    pub cause: CauseValue,
    /// Top-level Sender F-TEID at instance 0.
    pub sender_f_teid: FullyQualifiedTeid,
    /// Linked bearer EBI from the first Bearer Context IE.
    pub bearer_ebi: EpsBearerId,
    /// PGW S2b-U user-plane F-TEID from the accepted Bearer Context.
    pub bearer_user_plane_f_teid: FullyQualifiedTeid,
    /// PGW-allocated PDN Address Allocation from top-level PAA IE instance 0.
    pub paa: Option<PdnAddressAllocation>,
    /// Opaque TS 24.008 PCO contents from top-level PCO IE instance 0.
    ///
    /// Use [`crate::PcoAddressConfiguration::decode_network_contents`] for the
    /// bounded DNS/P-CSCF address projection. Keeping the transport value here
    /// preserves accepted-bearer summary behavior when optional PCO contents
    /// are malformed or contain protocols the SDK does not decode.
    pub pco: Option<ProtocolConfigurationOptions>,
}

impl fmt::Debug for CreateSessionAcceptedResponseSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreateSessionAcceptedResponseSummary")
            .field("response_teid_present", &true)
            .field("sequence_number", &self.sequence_number)
            .field("cause", &self.cause)
            .field("sender_f_teid_present", &true)
            .field("bearer_ebi", &self.bearer_ebi)
            .field(
                "bearer_user_plane_interface_type",
                &self.bearer_user_plane_f_teid.interface_type,
            )
            .field(
                "bearer_user_plane_ipv4_present",
                &self.bearer_user_plane_f_teid.ipv4.is_some(),
            )
            .field(
                "bearer_user_plane_ipv6_present",
                &self.bearer_user_plane_f_teid.ipv6.is_some(),
            )
            .field("paa_pdn_type", &self.paa.as_ref().map(|paa| paa.pdn_type))
            .field(
                "paa_ipv4_present",
                &self.paa.as_ref().is_some_and(|paa| paa.ipv4.is_some()),
            )
            .field(
                "paa_ipv6_present",
                &self
                    .paa
                    .as_ref()
                    .is_some_and(|paa| paa.ipv6_prefix.is_some()),
            )
            .field("pco_present", &self.pco.is_some())
            .field(
                "pco_value_len",
                &self.pco.as_ref().map(|pco| pco.value.len()),
            )
            .finish()
    }
}

/// Rejected Create Session Response projection.
///
/// Rejected responses do not require accepted-bearer-only fields such as
/// Sender F-TEID or Bearer Context EBI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSessionRejectedResponseSummary {
    /// TEID carried in the Create Session Response common header.
    pub response_teid: u32,
    /// GTPv2-C sequence number from the Create Session Response header.
    pub sequence_number: u32,
    /// Cause value from the Cause IE.
    pub cause: CauseValue,
}

/// Create Session Response projection split by bearer-establishment outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateSessionResponseSummary {
    /// Cause 16/17 response with accepted-bearer fields present.
    Accepted(CreateSessionAcceptedResponseSummary),
    /// Non-accepted response with Cause, response TEID, and sequence only.
    Rejected(CreateSessionRejectedResponseSummary),
}

/// Stable redaction-safe error returned while projecting a Create Session Response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreateSessionResponseSummaryError {
    /// Message bytes could not be decoded into a single typed GTPv2-C response.
    MalformedResponse,
    /// Decoded message was not an S2b Create Session Response.
    NotCreateSessionResponse,
    /// Create Session Response did not include a Cause IE.
    MissingCause,
    /// Create Session Response did not carry a response-header TEID.
    MissingResponseTeid,
    /// Accepted Create Session Response did not include Sender F-TEID instance 0.
    AcceptedResponseMissingSenderFTeid,
    /// Accepted Create Session Response did not include a Bearer Context IE.
    AcceptedResponseMissingBearerContext,
    /// Accepted Create Session Response Bearer Context did not include an EBI IE.
    AcceptedResponseMissingBearerEbi,
    /// Accepted Create Session Response carried a malformed top-level PAA IE.
    AcceptedResponseMalformedPaa,
    /// Accepted Create Session Response Bearer Context contained no F-TEID IE.
    AcceptedResponseMissingBearerFTeid,
    /// Accepted Create Session Response Bearer Context F-TEIDs were not S2b-U PGW.
    AcceptedResponseBearerFTeidInterfaceMismatch,
    /// Accepted Create Session Response S2b-U F-TEID carried no endpoint address.
    AcceptedResponseMalformedBearerFTeid,
}

impl CreateSessionResponseSummaryError {
    /// Return the stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedResponse => "s2b_create_session_response_malformed",
            Self::NotCreateSessionResponse => {
                "s2b_create_session_response_not_create_session_response"
            }
            Self::MissingCause => "s2b_create_session_response_missing_cause",
            Self::MissingResponseTeid => "s2b_create_session_response_missing_teid",
            Self::AcceptedResponseMissingSenderFTeid => {
                "s2b_create_session_response_missing_sender_f_teid"
            }
            Self::AcceptedResponseMissingBearerContext => {
                "s2b_create_session_response_missing_bearer_context"
            }
            Self::AcceptedResponseMissingBearerEbi => {
                "s2b_create_session_response_missing_bearer_ebi"
            }
            Self::AcceptedResponseMalformedPaa => "s2b_create_session_response_malformed_paa",
            Self::AcceptedResponseMissingBearerFTeid => {
                "s2b_create_session_response_missing_bearer_f_teid"
            }
            Self::AcceptedResponseBearerFTeidInterfaceMismatch => {
                "s2b_create_session_response_bearer_f_teid_interface_mismatch"
            }
            Self::AcceptedResponseMalformedBearerFTeid => {
                "s2b_create_session_response_malformed_bearer_f_teid"
            }
        }
    }
}

impl fmt::Display for CreateSessionResponseSummaryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for CreateSessionResponseSummaryError {}

/// Decoded Echo Request/Response evidence used by GTPv2-C peer control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoMessageEvidence {
    /// Echo request/response direction.
    pub direction: MessageDirection,
    /// 24-bit GTPv2-C sequence number.
    pub sequence_number: u32,
    /// Recovery restart counter from the mandatory Recovery IE.
    pub restart_counter: u8,
}

impl EchoMessageEvidence {
    /// Project a typed S2b procedure view into Echo evidence.
    ///
    /// # Errors
    ///
    /// Returns [`EchoMessageEvidenceError`] when the view is not an Echo
    /// message or does not contain a typed Recovery IE.
    pub fn from_view(view: &S2bProcedureMessage<'_>) -> Result<Self, EchoMessageEvidenceError> {
        if view.procedure != Procedure::Echo {
            return Err(EchoMessageEvidenceError::NotEchoMessage);
        }
        let restart_counter = find_recovery_restart_counter(&view.ies)
            .ok_or(EchoMessageEvidenceError::MissingRecovery)?;
        Ok(Self {
            direction: view.direction,
            sequence_number: view.header.sequence_number,
            restart_counter,
        })
    }
}

/// Stable redaction-safe error returned while extracting Echo evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoMessageEvidenceError {
    /// Message bytes could not be decoded into a typed S2b message.
    MalformedMessage,
    /// Message bytes contained trailing data after the decoded message.
    TrailingBytes,
    /// Decoded message was not an Echo Request or Echo Response.
    NotEchoMessage,
    /// Echo message did not contain a typed Recovery IE.
    MissingRecovery,
}

impl EchoMessageEvidenceError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedMessage => "gtpv2c_echo_message_malformed",
            Self::TrailingBytes => "gtpv2c_echo_message_trailing_bytes",
            Self::NotEchoMessage => "gtpv2c_echo_message_not_echo",
            Self::MissingRecovery => "gtpv2c_echo_message_missing_recovery",
        }
    }
}

impl fmt::Display for EchoMessageEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for EchoMessageEvidenceError {}

/// Decode one S2b Echo message and extract Recovery evidence.
///
/// # Errors
///
/// Returns [`EchoMessageEvidenceError`] when bytes are malformed, contain
/// trailing data after the message, decode to another message type, or lack a
/// typed Recovery IE.
pub fn decode_echo_message_evidence(
    input: &[u8],
    ctx: DecodeContext,
) -> Result<EchoMessageEvidence, EchoMessageEvidenceError> {
    let (tail, message) =
        S2bMessage::decode(input, ctx).map_err(|_| EchoMessageEvidenceError::MalformedMessage)?;
    if !tail.is_empty() {
        return Err(EchoMessageEvidenceError::TrailingBytes);
    }
    let view = message
        .as_view()
        .ok_or(EchoMessageEvidenceError::NotEchoMessage)?;
    EchoMessageEvidence::from_view(view)
}

/// Policy for the GTPv2-C Echo peer state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtpv2cEchoPeerPolicy {
    /// Consecutive missing Echo Response threshold. Values below one are
    /// treated as one by the state machine.
    pub missed_response_threshold: usize,
    /// Whether a changed peer Recovery restart counter blocks traffic until
    /// the caller explicitly marks restart reconciliation complete.
    pub require_restart_reconciliation: bool,
}

impl Default for Gtpv2cEchoPeerPolicy {
    fn default() -> Self {
        Self {
            missed_response_threshold: 3,
            require_restart_reconciliation: true,
        }
    }
}

impl Gtpv2cEchoPeerPolicy {
    /// Return a copy with a custom missing-response threshold.
    #[must_use]
    pub fn with_missed_response_threshold(mut self, threshold: usize) -> Self {
        self.missed_response_threshold = threshold.max(1);
        self
    }

    /// Return a copy that treats restart-counter changes as reachable but not
    /// traffic-blocking.
    #[must_use]
    pub const fn without_restart_reconciliation(mut self) -> Self {
        self.require_restart_reconciliation = false;
        self
    }
}

/// Transport-neutral GTPv2-C Echo peer-control state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Gtpv2cEchoPeerState {
    /// No Echo evidence has been observed.
    Idle,
    /// Echo Request was sent and Echo Response is pending.
    AwaitingResponse,
    /// Peer is reachable and continuity evidence is safe.
    Reachable,
    /// Peer liveness evidence is weak but has not failed the threshold.
    Degraded,
    /// Peer failed the Echo liveness threshold.
    Failed,
    /// Peer Recovery restart counter changed and reconciliation is required.
    ReconciliationRequired,
}

impl Gtpv2cEchoPeerState {
    /// Stable machine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::AwaitingResponse => "awaiting_response",
            Self::Reachable => "reachable",
            Self::Degraded => "degraded",
            Self::Failed => "failed",
            Self::ReconciliationRequired => "reconciliation_required",
        }
    }
}

/// Transport-neutral GTPv2-C Echo peer-control event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Gtpv2cEchoPeerEvent {
    /// Echo Request was sent.
    EchoRequestSent,
    /// Echo Request was received.
    EchoRequestReceived,
    /// Echo Response was accepted.
    EchoResponseAccepted,
    /// Echo Response sequence did not match the outstanding request.
    EchoResponseSequenceMismatch,
    /// Echo Response was missing for the outstanding request.
    EchoResponseMissing,
    /// Peer Recovery restart counter changed.
    PeerRestartObserved,
    /// Caller marked restart reconciliation complete.
    RestartReconciled,
    /// Caller failed the peer explicitly.
    Failure,
}

impl Gtpv2cEchoPeerEvent {
    /// Stable machine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EchoRequestSent => "echo_request_sent",
            Self::EchoRequestReceived => "echo_request_received",
            Self::EchoResponseAccepted => "echo_response_accepted",
            Self::EchoResponseSequenceMismatch => "echo_response_sequence_mismatch",
            Self::EchoResponseMissing => "echo_response_missing",
            Self::PeerRestartObserved => "peer_restart_observed",
            Self::RestartReconciled => "restart_reconciled",
            Self::Failure => "failure",
        }
    }
}

/// Stable redaction-safe blocker emitted by the Echo peer helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Gtpv2cEchoPeerBlocker {
    /// Echo Response has not arrived for the outstanding request.
    EchoResponsePending,
    /// Echo Response was missing for the outstanding request.
    EchoResponseMissing,
    /// Echo Response sequence did not match the outstanding request.
    EchoResponseSequenceMismatch,
    /// Peer Recovery restart counter changed.
    PeerRestartCounterChanged,
    /// Peer failed the liveness threshold.
    PeerUnreachable,
    /// Caller must reconcile sessions after a peer restart.
    RestartReconciliationRequired,
}

impl Gtpv2cEchoPeerBlocker {
    /// Stable machine-readable blocker code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EchoResponsePending => "gtpv2c_echo_response_pending",
            Self::EchoResponseMissing => "gtpv2c_echo_response_missing",
            Self::EchoResponseSequenceMismatch => "gtpv2c_echo_response_sequence_mismatch",
            Self::PeerRestartCounterChanged => "gtpv2c_peer_restart_counter_changed",
            Self::PeerUnreachable => "gtpv2c_peer_unreachable",
            Self::RestartReconciliationRequired => "gtpv2c_restart_reconciliation_required",
        }
    }
}

/// Redaction-safe readiness projection for one Echo peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtpv2cEchoPeerReadiness {
    /// Current peer-control state.
    pub state: Gtpv2cEchoPeerState,
    /// Whether peer liveness is currently proven.
    pub reachable: bool,
    /// Whether a response is pending.
    pub awaiting_response: bool,
    /// Whether liveness is degraded but not failed.
    pub degraded: bool,
    /// Whether the peer failed the liveness threshold.
    pub failed: bool,
    /// Whether restart reconciliation is required.
    pub restart_reconciliation_required: bool,
    /// Whether product traffic can safely use this peer.
    pub traffic_ready: bool,
    /// Stable blockers in evaluation order.
    pub blockers: Vec<Gtpv2cEchoPeerBlocker>,
}

/// Projection from one Echo observation into peer liveness and continuity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtpv2cEchoPeerProjection {
    /// Whether an Echo Response was observed for the current exchange.
    pub response_observed: bool,
    /// Whether the peer is reachable.
    pub peer_reachable: bool,
    /// Whether the Recovery restart counter changed from the previous value.
    pub restart_counter_changed: bool,
    /// Whether existing session continuity is safe.
    pub continuity_safe: bool,
    /// Last observed peer Recovery restart counter.
    pub restart_counter: Option<u8>,
    /// Current in-flight sequence number, if any.
    pub in_flight_sequence_number: Option<u32>,
    /// Consecutive missed Echo Responses.
    pub missed_responses: usize,
    /// Stable blockers in evaluation order.
    pub blockers: Vec<Gtpv2cEchoPeerBlocker>,
}

/// One emitted transition from the Echo peer helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtpv2cEchoPeerTransition {
    /// Event that caused the transition.
    pub event: Gtpv2cEchoPeerEvent,
    /// State before the event.
    pub previous_state: Gtpv2cEchoPeerState,
    /// State after the event.
    pub state: Gtpv2cEchoPeerState,
    /// Readiness after the event.
    pub readiness: Gtpv2cEchoPeerReadiness,
    /// Observation projection after the event.
    pub projection: Gtpv2cEchoPeerProjection,
}

/// Redaction-safe snapshot of the Echo peer helper.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gtpv2cEchoPeerSnapshot {
    /// Current peer-control state.
    pub state: Gtpv2cEchoPeerState,
    /// Current readiness projection.
    pub readiness: Gtpv2cEchoPeerReadiness,
    /// Last observed peer Recovery restart counter.
    pub last_restart_counter: Option<u8>,
    /// Current in-flight sequence number, if any.
    pub in_flight_sequence_number: Option<u32>,
    /// Echo Requests sent by this helper.
    pub echo_requests_sent: usize,
    /// Echo Requests received by this helper.
    pub echo_requests_received: usize,
    /// Echo Responses accepted by this helper.
    pub echo_responses_observed: usize,
    /// Echo Responses rejected due to sequence mismatch.
    pub echo_response_sequence_mismatches: usize,
    /// Consecutive missed Echo Responses.
    pub missed_responses: usize,
    /// Peer Recovery restart-counter changes observed.
    pub restart_counter_changes: usize,
}

/// GTPv2-C Echo peer state-machine error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gtpv2cEchoPeerError {
    /// Operation is not valid in the current state.
    InvalidTransition {
        /// Operation attempted.
        operation: &'static str,
        /// Current state.
        state: Gtpv2cEchoPeerState,
    },
    /// Echo traffic is blocked until restart reconciliation completes.
    RestartReconciliationRequired,
    /// Echo evidence had the wrong request/response direction.
    UnexpectedDirection {
        /// Expected direction.
        expected: MessageDirection,
        /// Actual direction.
        actual: MessageDirection,
    },
}

impl Gtpv2cEchoPeerError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidTransition { .. } => "gtpv2c_echo_peer_invalid_transition",
            Self::RestartReconciliationRequired => {
                "gtpv2c_echo_peer_restart_reconciliation_required"
            }
            Self::UnexpectedDirection { .. } => "gtpv2c_echo_peer_unexpected_direction",
        }
    }
}

impl fmt::Display for Gtpv2cEchoPeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { operation, state } => write!(
                f,
                "gtpv2c_echo_peer_invalid_transition: operation {operation}, state {}",
                state.as_str()
            ),
            Self::RestartReconciliationRequired => {
                f.write_str("gtpv2c_echo_peer_restart_reconciliation_required")
            }
            Self::UnexpectedDirection { expected, actual } => write!(
                f,
                "gtpv2c_echo_peer_unexpected_direction: expected {}, actual {}",
                expected.as_str(),
                actual.as_str()
            ),
        }
    }
}

impl std::error::Error for Gtpv2cEchoPeerError {}

/// Transport-neutral GTPv2-C Echo peer-control state machine.
#[derive(Debug, Clone)]
pub struct Gtpv2cEchoPeer {
    policy: Gtpv2cEchoPeerPolicy,
    state: Gtpv2cEchoPeerState,
    last_restart_counter: Option<u8>,
    in_flight_sequence_number: Option<u32>,
    missed_responses: usize,
    echo_requests_sent: usize,
    echo_requests_received: usize,
    echo_responses_observed: usize,
    echo_response_sequence_mismatches: usize,
    restart_counter_changes: usize,
    last_blockers: Vec<Gtpv2cEchoPeerBlocker>,
}

impl Gtpv2cEchoPeer {
    /// Create an Echo peer helper with default policy.
    #[must_use]
    pub fn new() -> Self {
        Self::with_policy(Gtpv2cEchoPeerPolicy::default())
    }

    /// Create an Echo peer helper with explicit policy.
    #[must_use]
    pub fn with_policy(policy: Gtpv2cEchoPeerPolicy) -> Self {
        Self {
            policy,
            state: Gtpv2cEchoPeerState::Idle,
            last_restart_counter: None,
            in_flight_sequence_number: None,
            missed_responses: 0,
            echo_requests_sent: 0,
            echo_requests_received: 0,
            echo_responses_observed: 0,
            echo_response_sequence_mismatches: 0,
            restart_counter_changes: 0,
            last_blockers: Vec::new(),
        }
    }

    /// Return the current state.
    #[must_use]
    pub const fn state(&self) -> Gtpv2cEchoPeerState {
        self.state
    }

    /// Return the peer policy.
    #[must_use]
    pub const fn policy(&self) -> Gtpv2cEchoPeerPolicy {
        self.policy
    }

    /// Mark an Echo Request as sent.
    ///
    /// # Errors
    ///
    /// Returns [`Gtpv2cEchoPeerError::RestartReconciliationRequired`] when the
    /// peer is fenced by a restart-counter change and policy requires explicit
    /// reconciliation before new Echo traffic.
    pub fn echo_request_sent(
        &mut self,
        sequence_number: u32,
    ) -> Result<Gtpv2cEchoPeerTransition, Gtpv2cEchoPeerError> {
        if self.state == Gtpv2cEchoPeerState::ReconciliationRequired
            && self.policy.require_restart_reconciliation
        {
            return Err(Gtpv2cEchoPeerError::RestartReconciliationRequired);
        }
        let previous = self.state;
        self.echo_requests_sent = self.echo_requests_sent.saturating_add(1);
        self.in_flight_sequence_number = Some(sequence_number);
        self.state = Gtpv2cEchoPeerState::AwaitingResponse;
        self.last_blockers = vec![Gtpv2cEchoPeerBlocker::EchoResponsePending];
        Ok(self.transition(Gtpv2cEchoPeerEvent::EchoRequestSent, previous, false, false))
    }

    /// Observe a decoded Echo Request from the peer.
    ///
    /// # Errors
    ///
    /// Returns [`Gtpv2cEchoPeerError`] when the evidence is not an Echo
    /// Request.
    pub fn observe_echo_request(
        &mut self,
        evidence: EchoMessageEvidence,
    ) -> Result<Gtpv2cEchoPeerTransition, Gtpv2cEchoPeerError> {
        if evidence.direction != MessageDirection::Request {
            return Err(Gtpv2cEchoPeerError::UnexpectedDirection {
                expected: MessageDirection::Request,
                actual: evidence.direction,
            });
        }
        let previous = self.state;
        self.echo_requests_received = self.echo_requests_received.saturating_add(1);
        let restart_counter_changed = self.observe_restart_counter(evidence.restart_counter);
        let event = if restart_counter_changed {
            Gtpv2cEchoPeerEvent::PeerRestartObserved
        } else {
            Gtpv2cEchoPeerEvent::EchoRequestReceived
        };
        if restart_counter_changed && self.policy.require_restart_reconciliation {
            self.state = Gtpv2cEchoPeerState::ReconciliationRequired;
            self.last_blockers = vec![
                Gtpv2cEchoPeerBlocker::PeerRestartCounterChanged,
                Gtpv2cEchoPeerBlocker::RestartReconciliationRequired,
            ];
        }
        Ok(self.transition(event, previous, false, restart_counter_changed))
    }

    /// Observe a decoded Echo Response from the peer.
    ///
    /// # Errors
    ///
    /// Returns [`Gtpv2cEchoPeerError`] when the evidence is not an Echo
    /// Response or when no Echo Request is in flight.
    pub fn observe_echo_response(
        &mut self,
        evidence: EchoMessageEvidence,
    ) -> Result<Gtpv2cEchoPeerTransition, Gtpv2cEchoPeerError> {
        if evidence.direction != MessageDirection::Response {
            return Err(Gtpv2cEchoPeerError::UnexpectedDirection {
                expected: MessageDirection::Response,
                actual: evidence.direction,
            });
        }
        let Some(expected_sequence) = self.in_flight_sequence_number else {
            return Err(Gtpv2cEchoPeerError::InvalidTransition {
                operation: "observe_echo_response",
                state: self.state,
            });
        };
        let previous = self.state;
        if evidence.sequence_number != expected_sequence {
            self.echo_response_sequence_mismatches =
                self.echo_response_sequence_mismatches.saturating_add(1);
            self.state = Gtpv2cEchoPeerState::Degraded;
            self.last_blockers = vec![Gtpv2cEchoPeerBlocker::EchoResponseSequenceMismatch];
            return Ok(self.transition(
                Gtpv2cEchoPeerEvent::EchoResponseSequenceMismatch,
                previous,
                false,
                false,
            ));
        }

        self.echo_responses_observed = self.echo_responses_observed.saturating_add(1);
        self.in_flight_sequence_number = None;
        self.missed_responses = 0;
        let restart_counter_changed = self.observe_restart_counter(evidence.restart_counter);
        if restart_counter_changed && self.policy.require_restart_reconciliation {
            self.state = Gtpv2cEchoPeerState::ReconciliationRequired;
            self.last_blockers = vec![
                Gtpv2cEchoPeerBlocker::PeerRestartCounterChanged,
                Gtpv2cEchoPeerBlocker::RestartReconciliationRequired,
            ];
            return Ok(self.transition(
                Gtpv2cEchoPeerEvent::PeerRestartObserved,
                previous,
                true,
                true,
            ));
        }

        self.state = Gtpv2cEchoPeerState::Reachable;
        self.last_blockers.clear();
        Ok(self.transition(
            Gtpv2cEchoPeerEvent::EchoResponseAccepted,
            previous,
            true,
            restart_counter_changed,
        ))
    }

    /// Record one missing Echo Response timer event.
    ///
    /// # Errors
    ///
    /// Returns [`Gtpv2cEchoPeerError`] when no Echo Request is in flight.
    pub fn echo_response_missing(
        &mut self,
    ) -> Result<Gtpv2cEchoPeerTransition, Gtpv2cEchoPeerError> {
        if self.in_flight_sequence_number.is_none() {
            return Err(Gtpv2cEchoPeerError::InvalidTransition {
                operation: "echo_response_missing",
                state: self.state,
            });
        }
        let previous = self.state;
        self.missed_responses = self.missed_responses.saturating_add(1);
        self.in_flight_sequence_number = None;
        let threshold = self.policy.missed_response_threshold.max(1);
        if self.missed_responses >= threshold {
            self.state = Gtpv2cEchoPeerState::Failed;
            self.last_blockers = vec![
                Gtpv2cEchoPeerBlocker::EchoResponseMissing,
                Gtpv2cEchoPeerBlocker::PeerUnreachable,
            ];
        } else {
            self.state = Gtpv2cEchoPeerState::Degraded;
            self.last_blockers = vec![Gtpv2cEchoPeerBlocker::EchoResponseMissing];
        }
        Ok(self.transition(
            Gtpv2cEchoPeerEvent::EchoResponseMissing,
            previous,
            false,
            false,
        ))
    }

    /// Mark restart reconciliation complete after a restart-counter change.
    ///
    /// # Errors
    ///
    /// Returns [`Gtpv2cEchoPeerError`] when the peer is not waiting for
    /// restart reconciliation.
    pub fn restart_reconciled(&mut self) -> Result<Gtpv2cEchoPeerTransition, Gtpv2cEchoPeerError> {
        if self.state != Gtpv2cEchoPeerState::ReconciliationRequired {
            return Err(Gtpv2cEchoPeerError::InvalidTransition {
                operation: "restart_reconciled",
                state: self.state,
            });
        }
        let previous = self.state;
        self.state = Gtpv2cEchoPeerState::Reachable;
        self.last_blockers.clear();
        Ok(self.transition(
            Gtpv2cEchoPeerEvent::RestartReconciled,
            previous,
            false,
            false,
        ))
    }

    /// Fail the peer as unreachable.
    #[must_use]
    pub fn fail_unreachable(&mut self) -> Gtpv2cEchoPeerTransition {
        let previous = self.state;
        self.state = Gtpv2cEchoPeerState::Failed;
        self.in_flight_sequence_number = None;
        self.last_blockers = vec![Gtpv2cEchoPeerBlocker::PeerUnreachable];
        self.transition(Gtpv2cEchoPeerEvent::Failure, previous, false, false)
    }

    /// Return the current redaction-safe readiness projection.
    #[must_use]
    pub fn readiness(&self) -> Gtpv2cEchoPeerReadiness {
        let blockers = self.readiness_blockers();
        Gtpv2cEchoPeerReadiness {
            state: self.state,
            reachable: self.state == Gtpv2cEchoPeerState::Reachable,
            awaiting_response: self.state == Gtpv2cEchoPeerState::AwaitingResponse,
            degraded: self.state == Gtpv2cEchoPeerState::Degraded,
            failed: self.state == Gtpv2cEchoPeerState::Failed,
            restart_reconciliation_required: self.state
                == Gtpv2cEchoPeerState::ReconciliationRequired,
            traffic_ready: self.state == Gtpv2cEchoPeerState::Reachable,
            blockers,
        }
    }

    /// Return a redaction-safe snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Gtpv2cEchoPeerSnapshot {
        Gtpv2cEchoPeerSnapshot {
            state: self.state,
            readiness: self.readiness(),
            last_restart_counter: self.last_restart_counter,
            in_flight_sequence_number: self.in_flight_sequence_number,
            echo_requests_sent: self.echo_requests_sent,
            echo_requests_received: self.echo_requests_received,
            echo_responses_observed: self.echo_responses_observed,
            echo_response_sequence_mismatches: self.echo_response_sequence_mismatches,
            missed_responses: self.missed_responses,
            restart_counter_changes: self.restart_counter_changes,
        }
    }

    fn observe_restart_counter(&mut self, restart_counter: u8) -> bool {
        let changed = self
            .last_restart_counter
            .map(|previous| previous != restart_counter)
            .unwrap_or(false);
        if changed {
            self.restart_counter_changes = self.restart_counter_changes.saturating_add(1);
        }
        self.last_restart_counter = Some(restart_counter);
        changed
    }

    fn transition(
        &self,
        event: Gtpv2cEchoPeerEvent,
        previous_state: Gtpv2cEchoPeerState,
        response_observed: bool,
        restart_counter_changed: bool,
    ) -> Gtpv2cEchoPeerTransition {
        Gtpv2cEchoPeerTransition {
            event,
            previous_state,
            state: self.state,
            readiness: self.readiness(),
            projection: self.projection(response_observed, restart_counter_changed),
        }
    }

    fn projection(
        &self,
        response_observed: bool,
        restart_counter_changed: bool,
    ) -> Gtpv2cEchoPeerProjection {
        let blockers = self.readiness_blockers();
        Gtpv2cEchoPeerProjection {
            response_observed,
            peer_reachable: self.state == Gtpv2cEchoPeerState::Reachable,
            restart_counter_changed,
            continuity_safe: self.state == Gtpv2cEchoPeerState::Reachable,
            restart_counter: self.last_restart_counter,
            in_flight_sequence_number: self.in_flight_sequence_number,
            missed_responses: self.missed_responses,
            blockers,
        }
    }

    fn readiness_blockers(&self) -> Vec<Gtpv2cEchoPeerBlocker> {
        match self.state {
            Gtpv2cEchoPeerState::Idle | Gtpv2cEchoPeerState::Reachable => Vec::new(),
            Gtpv2cEchoPeerState::AwaitingResponse => {
                vec![Gtpv2cEchoPeerBlocker::EchoResponsePending]
            }
            Gtpv2cEchoPeerState::Degraded | Gtpv2cEchoPeerState::Failed => {
                self.last_blockers.clone()
            }
            Gtpv2cEchoPeerState::ReconciliationRequired => vec![
                Gtpv2cEchoPeerBlocker::PeerRestartCounterChanged,
                Gtpv2cEchoPeerBlocker::RestartReconciliationRequired,
            ],
        }
    }
}

impl Default for Gtpv2cEchoPeer {
    fn default() -> Self {
        Self::new()
    }
}

/// Caller-owned redaction-safe peer token for GTPv2-C transaction correlation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Gtpv2cPeerToken(u64);

impl Gtpv2cPeerToken {
    /// Create a peer token from a caller-owned non-sensitive value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the token value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// GTPv2-C client transaction state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Gtpv2cClientTransactionState {
    /// Request has not been sent.
    SendNotAttempted,
    /// Local send failed before socket-layer delivery.
    SendFailedBeforeDelivery,
    /// Request was accepted by the socket layer and response is pending.
    SentWaitingResponse,
    /// A matching response was observed.
    ResponseObserved,
    /// Response timeout policy reached a terminal failure.
    TerminalTimeout,
}

impl Gtpv2cClientTransactionState {
    /// Stable machine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SendNotAttempted => "send_not_attempted",
            Self::SendFailedBeforeDelivery => "send_failed_before_delivery",
            Self::SentWaitingResponse => "sent_waiting_response",
            Self::ResponseObserved => "response_observed",
            Self::TerminalTimeout => "terminal_timeout",
        }
    }
}

/// Stable decision emitted by the GTPv2-C client transaction helper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Gtpv2cClientTransactionDecision {
    /// Request has not been sent.
    SendNotAttempted,
    /// Local send failed before socket-layer delivery.
    SendFailedBeforeDelivery,
    /// Request was accepted by the socket layer and response is pending.
    SentWaitingResponse,
    /// Timeout permits retransmission to the same peer.
    SafeRetransmitSamePeer,
    /// Peer failover is unsafe after socket-layer delivery.
    UnsafePeerFailover,
    /// Response matched the pending transaction.
    ResponseMatched,
    /// Response duplicated a previously matched transaction.
    DuplicateResponse,
    /// Response arrived after terminal timeout or without pending state.
    LateResponse,
    /// Response did not match transaction correlation fields.
    ResponseMismatched,
    /// Timeout policy reached a terminal failure.
    TerminalTimeout,
}

impl Gtpv2cClientTransactionDecision {
    /// Stable machine-readable decision code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SendNotAttempted => "send_not_attempted",
            Self::SendFailedBeforeDelivery => "send_failed_before_delivery",
            Self::SentWaitingResponse => "sent_waiting_response",
            Self::SafeRetransmitSamePeer => "safe_retransmit_same_peer",
            Self::UnsafePeerFailover => "unsafe_peer_failover",
            Self::ResponseMatched => "response_matched",
            Self::DuplicateResponse => "duplicate_response",
            Self::LateResponse => "late_response",
            Self::ResponseMismatched => "response_mismatched",
            Self::TerminalTimeout => "terminal_timeout",
        }
    }
}

/// Correlation mismatch found while classifying a GTPv2-C response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Gtpv2cClientTransactionMismatch {
    /// Procedure did not match the request.
    Procedure,
    /// Direction was not a response.
    Direction,
    /// Message type was not the expected response type.
    MessageType,
    /// Sequence number did not match the request.
    SequenceNumber,
    /// Response TEID did not match the expected local control TEID.
    ResponseTeid,
    /// Peer token did not match the request peer.
    Peer,
}

impl Gtpv2cClientTransactionMismatch {
    /// Stable machine-readable mismatch code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Procedure => "gtpv2c_transaction_procedure_mismatch",
            Self::Direction => "gtpv2c_transaction_direction_mismatch",
            Self::MessageType => "gtpv2c_transaction_message_type_mismatch",
            Self::SequenceNumber => "gtpv2c_transaction_sequence_mismatch",
            Self::ResponseTeid => "gtpv2c_transaction_response_teid_mismatch",
            Self::Peer => "gtpv2c_transaction_peer_mismatch",
        }
    }
}

/// Redaction-safe key for one GTPv2-C client transaction.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Gtpv2cClientTransactionKey {
    /// S2b procedure.
    pub procedure: Procedure,
    /// Request sequence number.
    pub sequence_number: u32,
    /// Request header TEID, when present.
    pub request_teid: Option<u32>,
    /// Expected response header TEID.
    pub expected_response_teid: Option<u32>,
    /// Redaction-safe peer token.
    pub peer: Gtpv2cPeerToken,
}

impl fmt::Debug for Gtpv2cClientTransactionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gtpv2cClientTransactionKey")
            .field("procedure", &self.procedure)
            .field("sequence_number", &self.sequence_number)
            .field("request_teid_present", &self.request_teid.is_some())
            .field(
                "expected_response_teid_present",
                &self.expected_response_teid.is_some(),
            )
            .field("peer", &self.peer)
            .finish()
    }
}

/// Metadata-only GTPv2-C request plan for client transaction tracking.
#[derive(Clone, PartialEq, Eq)]
pub struct Gtpv2cClientTransactionPlan {
    /// Correlation key.
    pub key: Gtpv2cClientTransactionKey,
    /// Request message type.
    pub request_message_type: MessageType,
    /// Expected response message type.
    pub response_message_type: MessageType,
    /// Encoded request length in octets.
    pub encoded_request_len: usize,
}

impl fmt::Debug for Gtpv2cClientTransactionPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gtpv2cClientTransactionPlan")
            .field("key", &self.key)
            .field("request_message_type", &self.request_message_type)
            .field("response_message_type", &self.response_message_type)
            .field("encoded_request_len", &self.encoded_request_len)
            .finish()
    }
}

impl Gtpv2cClientTransactionPlan {
    /// Build a transaction plan from a typed request view.
    ///
    /// # Errors
    ///
    /// Returns [`Gtpv2cClientTransactionPlanError`] when the view is not a
    /// supported client request procedure.
    pub fn from_request_view(
        view: &S2bProcedureMessage<'_>,
        peer: Gtpv2cPeerToken,
        expected_response_teid: Option<u32>,
        encoded_request_len: usize,
    ) -> Result<Self, Gtpv2cClientTransactionPlanError> {
        if view.direction != MessageDirection::Request {
            return Err(Gtpv2cClientTransactionPlanError::NotRequest);
        }
        if !is_client_transaction_procedure(view.procedure) {
            return Err(Gtpv2cClientTransactionPlanError::UnsupportedProcedure);
        }
        Ok(Self {
            key: Gtpv2cClientTransactionKey {
                procedure: view.procedure,
                sequence_number: view.header.sequence_number,
                request_teid: view.header.teid,
                expected_response_teid,
                peer,
            },
            request_message_type: view.message_type(),
            response_message_type: view.procedure.response_message_type(),
            encoded_request_len,
        })
    }

    /// Build a transaction plan by decoding caller-owned request bytes.
    ///
    /// Raw request bytes are not retained by the returned plan.
    ///
    /// # Errors
    ///
    /// Returns [`Gtpv2cClientTransactionPlanError`] when bytes are malformed,
    /// contain trailing data, decode to a raw fallback, or are not a supported
    /// client request procedure.
    pub fn from_encoded_request(
        input: &[u8],
        peer: Gtpv2cPeerToken,
        expected_response_teid: Option<u32>,
        ctx: DecodeContext,
    ) -> Result<Self, Gtpv2cClientTransactionPlanError> {
        let (tail, message) = S2bMessage::decode(input, ctx)
            .map_err(|_| Gtpv2cClientTransactionPlanError::MalformedRequest)?;
        if !tail.is_empty() {
            return Err(Gtpv2cClientTransactionPlanError::TrailingBytes);
        }
        let view = message
            .as_view()
            .ok_or(Gtpv2cClientTransactionPlanError::RawFallback)?;
        Self::from_request_view(view, peer, expected_response_teid, input.len())
    }
}

/// Stable redaction-safe error returned while building a transaction plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gtpv2cClientTransactionPlanError {
    /// Request bytes could not be decoded.
    MalformedRequest,
    /// Request bytes contained trailing data after the decoded message.
    TrailingBytes,
    /// Decoded message fell back to a raw unsupported message.
    RawFallback,
    /// Decoded or typed view was not a request.
    NotRequest,
    /// Procedure is outside the client transaction helper scope.
    UnsupportedProcedure,
}

impl Gtpv2cClientTransactionPlanError {
    /// Stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedRequest => "gtpv2c_transaction_request_malformed",
            Self::TrailingBytes => "gtpv2c_transaction_request_trailing_bytes",
            Self::RawFallback => "gtpv2c_transaction_request_raw_fallback",
            Self::NotRequest => "gtpv2c_transaction_not_request",
            Self::UnsupportedProcedure => "gtpv2c_transaction_unsupported_procedure",
        }
    }
}

impl fmt::Display for Gtpv2cClientTransactionPlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for Gtpv2cClientTransactionPlanError {}

/// Decoded GTPv2-C response evidence used for client transaction correlation.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Gtpv2cClientResponseEvidence {
    /// S2b procedure.
    pub procedure: Procedure,
    /// Request/response direction.
    pub direction: MessageDirection,
    /// Response message type.
    pub message_type: MessageType,
    /// Response sequence number.
    pub sequence_number: u32,
    /// Response header TEID.
    pub response_teid: Option<u32>,
    /// Redaction-safe peer token.
    pub peer: Gtpv2cPeerToken,
}

impl fmt::Debug for Gtpv2cClientResponseEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gtpv2cClientResponseEvidence")
            .field("procedure", &self.procedure)
            .field("direction", &self.direction)
            .field("message_type", &self.message_type)
            .field("sequence_number", &self.sequence_number)
            .field("response_teid_present", &self.response_teid.is_some())
            .field("peer", &self.peer)
            .finish()
    }
}

impl Gtpv2cClientResponseEvidence {
    /// Build response evidence from a typed S2b procedure view.
    #[must_use]
    pub fn from_view(view: &S2bProcedureMessage<'_>, peer: Gtpv2cPeerToken) -> Self {
        Self {
            procedure: view.procedure,
            direction: view.direction,
            message_type: view.message_type(),
            sequence_number: view.header.sequence_number,
            response_teid: view.header.teid,
            peer,
        }
    }
}

/// Timer policy for one GTPv2-C client transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gtpv2cClientTransactionPolicy {
    /// Number of response timeouts before terminal failure.
    pub max_response_timeouts: usize,
}

impl Default for Gtpv2cClientTransactionPolicy {
    fn default() -> Self {
        Self {
            max_response_timeouts: 1,
        }
    }
}

impl Gtpv2cClientTransactionPolicy {
    /// Return a copy with a custom response-timeout threshold.
    #[must_use]
    pub fn with_max_response_timeouts(mut self, max_response_timeouts: usize) -> Self {
        self.max_response_timeouts = max_response_timeouts.max(1);
        self
    }
}

/// Redaction-safe projection from a client transaction event.
#[derive(Clone, PartialEq, Eq)]
pub struct Gtpv2cClientTransactionProjection {
    /// Transaction decision.
    pub decision: Gtpv2cClientTransactionDecision,
    /// Transaction state after the event.
    pub state: Gtpv2cClientTransactionState,
    /// Correlation key.
    pub key: Gtpv2cClientTransactionKey,
    /// Whether a response matched the transaction.
    pub response_matched: bool,
    /// Whether retransmission to the same peer is safe.
    pub safe_retransmit_same_peer: bool,
    /// Whether failover to a different peer is safe.
    pub peer_failover_safe: bool,
    /// Whether this transaction is terminal.
    pub terminal: bool,
    /// Send attempts accepted by the caller as delivered to socket layer.
    pub send_attempts: usize,
    /// Response timeouts observed.
    pub response_timeouts: usize,
    /// Correlation mismatch, if any.
    pub mismatch: Option<Gtpv2cClientTransactionMismatch>,
}

impl fmt::Debug for Gtpv2cClientTransactionProjection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gtpv2cClientTransactionProjection")
            .field("decision", &self.decision)
            .field("state", &self.state)
            .field("key", &self.key)
            .field("response_matched", &self.response_matched)
            .field("safe_retransmit_same_peer", &self.safe_retransmit_same_peer)
            .field("peer_failover_safe", &self.peer_failover_safe)
            .field("terminal", &self.terminal)
            .field("send_attempts", &self.send_attempts)
            .field("response_timeouts", &self.response_timeouts)
            .field("mismatch", &self.mismatch)
            .finish()
    }
}

/// Redaction-safe snapshot of a GTPv2-C client transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct Gtpv2cClientTransactionSnapshot {
    /// Transaction request plan.
    pub plan: Gtpv2cClientTransactionPlan,
    /// Current transaction state.
    pub state: Gtpv2cClientTransactionState,
    /// Send attempts accepted by the caller as delivered to socket layer.
    pub send_attempts: usize,
    /// Response timeouts observed.
    pub response_timeouts: usize,
    /// Last emitted decision.
    pub last_decision: Gtpv2cClientTransactionDecision,
}

impl fmt::Debug for Gtpv2cClientTransactionSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Gtpv2cClientTransactionSnapshot")
            .field("plan", &self.plan)
            .field("state", &self.state)
            .field("send_attempts", &self.send_attempts)
            .field("response_timeouts", &self.response_timeouts)
            .field("last_decision", &self.last_decision)
            .finish()
    }
}

/// Transport-neutral GTPv2-C client transaction helper.
#[derive(Debug, Clone)]
pub struct Gtpv2cClientTransaction {
    plan: Gtpv2cClientTransactionPlan,
    policy: Gtpv2cClientTransactionPolicy,
    state: Gtpv2cClientTransactionState,
    send_attempts: usize,
    response_timeouts: usize,
    last_decision: Gtpv2cClientTransactionDecision,
}

impl Gtpv2cClientTransaction {
    /// Create a transaction helper with default timeout policy.
    #[must_use]
    pub fn new(plan: Gtpv2cClientTransactionPlan) -> Self {
        Self::with_policy(plan, Gtpv2cClientTransactionPolicy::default())
    }

    /// Create a transaction helper with explicit timeout policy.
    #[must_use]
    pub fn with_policy(
        plan: Gtpv2cClientTransactionPlan,
        policy: Gtpv2cClientTransactionPolicy,
    ) -> Self {
        Self {
            plan,
            policy,
            state: Gtpv2cClientTransactionState::SendNotAttempted,
            send_attempts: 0,
            response_timeouts: 0,
            last_decision: Gtpv2cClientTransactionDecision::SendNotAttempted,
        }
    }

    /// Return the request plan.
    #[must_use]
    pub const fn plan(&self) -> &Gtpv2cClientTransactionPlan {
        &self.plan
    }

    /// Return the current state.
    #[must_use]
    pub const fn state(&self) -> Gtpv2cClientTransactionState {
        self.state
    }

    /// Project the initial not-sent state.
    #[must_use]
    pub fn send_not_attempted(&mut self) -> Gtpv2cClientTransactionProjection {
        self.state = Gtpv2cClientTransactionState::SendNotAttempted;
        self.project(Gtpv2cClientTransactionDecision::SendNotAttempted, None)
    }

    /// Record a local send failure before socket-layer delivery.
    #[must_use]
    pub fn send_failed_before_delivery(&mut self) -> Gtpv2cClientTransactionProjection {
        self.state = Gtpv2cClientTransactionState::SendFailedBeforeDelivery;
        self.project(
            Gtpv2cClientTransactionDecision::SendFailedBeforeDelivery,
            None,
        )
    }

    /// Record a send accepted by the socket layer.
    #[must_use]
    pub fn sent_waiting_response(&mut self) -> Gtpv2cClientTransactionProjection {
        self.state = Gtpv2cClientTransactionState::SentWaitingResponse;
        self.send_attempts = self.send_attempts.saturating_add(1);
        self.project(Gtpv2cClientTransactionDecision::SentWaitingResponse, None)
    }

    /// Classify a response timeout.
    #[must_use]
    pub fn response_timeout(&mut self) -> Gtpv2cClientTransactionProjection {
        self.response_timeouts = self.response_timeouts.saturating_add(1);
        if self.response_timeouts >= self.policy.max_response_timeouts.max(1) {
            self.state = Gtpv2cClientTransactionState::TerminalTimeout;
            self.project(Gtpv2cClientTransactionDecision::TerminalTimeout, None)
        } else {
            self.project(
                Gtpv2cClientTransactionDecision::SafeRetransmitSamePeer,
                None,
            )
        }
    }

    /// Project a peer failover request after socket-layer delivery.
    #[must_use]
    pub fn unsafe_peer_failover(&mut self) -> Gtpv2cClientTransactionProjection {
        self.project(Gtpv2cClientTransactionDecision::UnsafePeerFailover, None)
    }

    /// Observe decoded response evidence and classify correlation.
    #[must_use]
    pub fn observe_response(
        &mut self,
        response: Gtpv2cClientResponseEvidence,
    ) -> Gtpv2cClientTransactionProjection {
        if self.state == Gtpv2cClientTransactionState::TerminalTimeout {
            return self.project(Gtpv2cClientTransactionDecision::LateResponse, None);
        }
        if self.state == Gtpv2cClientTransactionState::ResponseObserved {
            return self.project(Gtpv2cClientTransactionDecision::DuplicateResponse, None);
        }
        if self.state != Gtpv2cClientTransactionState::SentWaitingResponse {
            return self.project(Gtpv2cClientTransactionDecision::LateResponse, None);
        }
        if let Some(mismatch) = self.match_response(response) {
            return self.project(
                Gtpv2cClientTransactionDecision::ResponseMismatched,
                Some(mismatch),
            );
        }
        self.state = Gtpv2cClientTransactionState::ResponseObserved;
        self.project(Gtpv2cClientTransactionDecision::ResponseMatched, None)
    }

    /// Return a redaction-safe snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Gtpv2cClientTransactionSnapshot {
        Gtpv2cClientTransactionSnapshot {
            plan: self.plan.clone(),
            state: self.state,
            send_attempts: self.send_attempts,
            response_timeouts: self.response_timeouts,
            last_decision: self.last_decision,
        }
    }

    fn match_response(
        &self,
        response: Gtpv2cClientResponseEvidence,
    ) -> Option<Gtpv2cClientTransactionMismatch> {
        if response.procedure != self.plan.key.procedure {
            return Some(Gtpv2cClientTransactionMismatch::Procedure);
        }
        if response.direction != MessageDirection::Response {
            return Some(Gtpv2cClientTransactionMismatch::Direction);
        }
        if response.message_type != self.plan.response_message_type {
            return Some(Gtpv2cClientTransactionMismatch::MessageType);
        }
        if response.sequence_number != self.plan.key.sequence_number {
            return Some(Gtpv2cClientTransactionMismatch::SequenceNumber);
        }
        if response.response_teid != self.plan.key.expected_response_teid {
            return Some(Gtpv2cClientTransactionMismatch::ResponseTeid);
        }
        if response.peer != self.plan.key.peer {
            return Some(Gtpv2cClientTransactionMismatch::Peer);
        }
        None
    }

    fn project(
        &mut self,
        decision: Gtpv2cClientTransactionDecision,
        mismatch: Option<Gtpv2cClientTransactionMismatch>,
    ) -> Gtpv2cClientTransactionProjection {
        self.last_decision = decision;
        Gtpv2cClientTransactionProjection {
            decision,
            state: self.state,
            key: self.plan.key,
            response_matched: decision == Gtpv2cClientTransactionDecision::ResponseMatched,
            safe_retransmit_same_peer: decision
                == Gtpv2cClientTransactionDecision::SafeRetransmitSamePeer,
            peer_failover_safe: matches!(
                decision,
                Gtpv2cClientTransactionDecision::SendNotAttempted
                    | Gtpv2cClientTransactionDecision::SendFailedBeforeDelivery
            ),
            terminal: matches!(
                self.state,
                Gtpv2cClientTransactionState::ResponseObserved
                    | Gtpv2cClientTransactionState::TerminalTimeout
            ),
            send_attempts: self.send_attempts,
            response_timeouts: self.response_timeouts,
            mismatch,
        }
    }
}

fn is_client_transaction_procedure(procedure: Procedure) -> bool {
    matches!(
        procedure,
        Procedure::CreateSession
            | Procedure::DeleteSession
            | Procedure::ModifyBearer
            | Procedure::UpdateSession
    )
}

fn spec_ref() -> SpecRef {
    SpecRef::new("3gpp", "TS29274", "S2b")
}

fn is_procedure_aware(level: ValidationLevel) -> bool {
    matches!(level, ValidationLevel::ProcedureAware)
}

/// Request/response direction for an S2b procedure view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageDirection {
    /// Request message.
    Request,
    /// Response message.
    Response,
}

impl MessageDirection {
    /// Stable machine name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

/// S2b procedure markers with typed support in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Procedure {
    /// Echo request/response exchange.
    Echo,
    /// Create Session request/response exchange.
    CreateSession,
    /// Modify Bearer request/response exchange, exposed as the S2b Modify Session view.
    ModifyBearer,
    /// Delete Session request/response exchange.
    DeleteSession,
    /// PGW-triggered Create Bearer request/response exchange.
    CreateBearer,
    /// Update Bearer request/response exchange.
    ///
    /// The `UpdateSession` variant name is retained for source compatibility;
    /// the wire procedure is the PGW-triggered Update Bearer exchange.
    UpdateSession,
    /// PGW-triggered Delete Bearer request/response exchange.
    DeleteBearer,
}

impl Procedure {
    /// Return the GTPv2-C request message type for this procedure.
    pub const fn request_type(self) -> u8 {
        match self {
            Self::Echo => ECHO_REQUEST,
            Self::CreateSession => CREATE_SESSION_REQUEST,
            Self::ModifyBearer => MODIFY_BEARER_REQUEST,
            Self::DeleteSession => DELETE_SESSION_REQUEST,
            Self::CreateBearer => CREATE_BEARER_REQUEST,
            Self::UpdateSession => UPDATE_BEARER_REQUEST,
            Self::DeleteBearer => DELETE_BEARER_REQUEST,
        }
    }

    /// Return the GTPv2-C response message type for this procedure.
    pub const fn response_type(self) -> u8 {
        match self {
            Self::Echo => ECHO_RESPONSE,
            Self::CreateSession => CREATE_SESSION_RESPONSE,
            Self::ModifyBearer => MODIFY_BEARER_RESPONSE,
            Self::DeleteSession => DELETE_SESSION_RESPONSE,
            Self::CreateBearer => CREATE_BEARER_RESPONSE,
            Self::UpdateSession => UPDATE_BEARER_RESPONSE,
            Self::DeleteBearer => DELETE_BEARER_RESPONSE,
        }
    }

    /// Return the typed GTPv2-C request message type for this procedure.
    pub const fn request_message_type(self) -> MessageType {
        MessageType::from_u8(self.request_type())
    }

    /// Return the typed GTPv2-C response message type for this procedure.
    pub const fn response_message_type(self) -> MessageType {
        MessageType::from_u8(self.response_type())
    }
}

/// Return `true` when `message_type` belongs to the S2b typed subset.
pub const fn is_s2b_message_type(message_type: u8) -> bool {
    MessageType::from_u8(message_type).is_s2b()
}

fn procedure_and_direction(message_type: MessageType) -> Option<(Procedure, MessageDirection)> {
    match message_type {
        MessageType::EchoRequest => Some((Procedure::Echo, MessageDirection::Request)),
        MessageType::EchoResponse => Some((Procedure::Echo, MessageDirection::Response)),
        MessageType::CreateSessionRequest => {
            Some((Procedure::CreateSession, MessageDirection::Request))
        }
        MessageType::CreateSessionResponse => {
            Some((Procedure::CreateSession, MessageDirection::Response))
        }
        MessageType::ModifyBearerRequest => {
            Some((Procedure::ModifyBearer, MessageDirection::Request))
        }
        MessageType::ModifyBearerResponse => {
            Some((Procedure::ModifyBearer, MessageDirection::Response))
        }
        MessageType::DeleteSessionRequest => {
            Some((Procedure::DeleteSession, MessageDirection::Request))
        }
        MessageType::DeleteSessionResponse => {
            Some((Procedure::DeleteSession, MessageDirection::Response))
        }
        MessageType::CreateBearerRequest => {
            Some((Procedure::CreateBearer, MessageDirection::Request))
        }
        MessageType::CreateBearerResponse => {
            Some((Procedure::CreateBearer, MessageDirection::Response))
        }
        MessageType::UpdateBearerRequest => {
            Some((Procedure::UpdateSession, MessageDirection::Request))
        }
        MessageType::UpdateBearerResponse => {
            Some((Procedure::UpdateSession, MessageDirection::Response))
        }
        MessageType::DeleteBearerRequest => {
            Some((Procedure::DeleteBearer, MessageDirection::Request))
        }
        MessageType::DeleteBearerResponse => {
            Some((Procedure::DeleteBearer, MessageDirection::Response))
        }
        MessageType::Unknown(_) => None,
    }
}

/// A typed S2b GTPv2-C procedure message view.
///
/// `raw_ies` is retained for byte-exact raw-preserving encoding of decoded
/// messages. Canonical encoding emits the typed IE sequence and preserves any
/// unsupported IEs through [`TypedIeValue::Raw`].
///
/// @spec 3GPP TS29274 R18 S2b
/// @req REQ-3GPP-TS29274-R18-S2B-MESSAGE-001
#[derive(Clone, PartialEq, Eq)]
pub struct S2bProcedureMessage<'a> {
    /// Parsed GTPv2-C common header.
    pub header: Header,
    /// S2b procedure represented by this view.
    pub procedure: Procedure,
    /// Request or response direction.
    pub direction: MessageDirection,
    /// Typed IE sequence, with raw fallback for unsupported IEs.
    pub ies: Vec<TypedIe<'a>>,
    /// Original raw IE bytes from a decoded message.
    pub raw_ies: &'a [u8],
    /// Bytes beyond the decoded message boundary.
    pub tail: &'a [u8],
}

impl<'a> S2bProcedureMessage<'a> {
    /// Return this view's typed GTPv2-C message type.
    pub fn message_type(&self) -> MessageType {
        self.header.typed_message_type()
    }

    /// Return `true` if a top-level IE with `ie_type` is present.
    pub fn has_ie(&self, ie_type: u8) -> bool {
        contains_ie(&self.ies, ie_type)
    }

    /// Project this view as an accepted or rejected Create Session Response.
    ///
    /// # Errors
    ///
    /// Returns [`CreateSessionResponseSummaryError`] when the view is not a
    /// Create Session Response, lacks Cause/response TEID, or represents an
    /// accepted response without accepted-bearer fields.
    pub fn create_session_response_summary(
        &self,
    ) -> Result<CreateSessionResponseSummary, CreateSessionResponseSummaryError> {
        project_create_session_response(self)
    }

    fn encoded_raw_ies(&self, ctx: EncodeContext) -> Result<BytesMut, EncodeError> {
        if ctx.raw_preserving && !self.raw_ies.is_empty() {
            return Ok(BytesMut::from(self.raw_ies));
        }

        let mut raw_ies = BytesMut::new();
        for ie in &self.ies {
            ie.encode(&mut raw_ies, ctx)?;
        }
        Ok(raw_ies)
    }

    fn encoded_lens(&self, ctx: EncodeContext) -> Result<(usize, u16), EncodeError> {
        let raw_ie_len = if ctx.raw_preserving && !self.raw_ies.is_empty() {
            self.raw_ies.len()
        } else {
            self.ies.iter().try_fold(0usize, |acc, ie| {
                let len = ie.wire_len(ctx)?;
                acc.checked_add(len)
                    .ok_or_else(|| EncodeError::length_overflow().with_spec_ref(spec_ref()))
            })?
        };
        let total_len = self
            .header
            .wire_len()
            .checked_add(raw_ie_len)
            .ok_or_else(|| EncodeError::length_overflow().with_spec_ref(spec_ref()))?;
        let body_len = total_len.checked_sub(4).ok_or_else(|| {
            EncodeError::new(EncodeErrorCode::Structural {
                reason: "message length underflow",
            })
            .with_spec_ref(spec_ref())
        })?;
        let body_len_u16 = u16::try_from(body_len)
            .map_err(|_| EncodeError::length_overflow().with_spec_ref(spec_ref()))?;
        Ok((total_len, body_len_u16))
    }
}

impl fmt::Debug for S2bProcedureMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S2bProcedureMessage")
            .field("header", &self.header)
            .field("procedure", &self.procedure)
            .field("direction", &self.direction)
            .field("ies", &self.ies)
            .field("raw_ies_len", &self.raw_ies.len())
            .field("tail_len", &self.tail.len())
            .finish()
    }
}

impl Encode for S2bProcedureMessage<'_> {
    /// Encode this S2b view as a GTPv2-C message.
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        let (total_len, _) = self.encoded_lens(ctx)?;
        ctx.check_capacity(total_len)?;
        let raw_ies = self.encoded_raw_ies(ctx)?;
        let message = Message {
            header: self.header.clone(),
            raw_ies: &raw_ies,
            tail: &[],
        };
        message.encode(dst, ctx)
    }

    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        let (total_len, _) = self.encoded_lens(ctx)?;
        Ok(total_len)
    }
}

/// Typed S2b message view with raw fallback for non-S2b GTPv2-C messages.
///
/// @spec 3GPP TS29274 R18 S2b
/// @req REQ-3GPP-TS29274-R18-S2B-MESSAGE-002
#[derive(Clone, PartialEq, Eq)]
pub enum S2bMessage<'a> {
    /// Echo Request view.
    EchoRequest(S2bProcedureMessage<'a>),
    /// Echo Response view.
    EchoResponse(S2bProcedureMessage<'a>),
    /// Create Session Request view.
    CreateSessionRequest(S2bProcedureMessage<'a>),
    /// Create Session Response view.
    CreateSessionResponse(S2bProcedureMessage<'a>),
    /// Modify Bearer / S2b Modify Session Request view.
    ModifySessionRequest(S2bProcedureMessage<'a>),
    /// Modify Bearer / S2b Modify Session Response view.
    ModifySessionResponse(S2bProcedureMessage<'a>),
    /// Delete Session Request view.
    DeleteSessionRequest(S2bProcedureMessage<'a>),
    /// Delete Session Response view.
    DeleteSessionResponse(S2bProcedureMessage<'a>),
    /// PGW-triggered Create Bearer Request view.
    CreateBearerRequest(S2bProcedureMessage<'a>),
    /// PGW-triggered Create Bearer Response view.
    CreateBearerResponse(S2bProcedureMessage<'a>),
    /// Update Bearer Request view (legacy `UpdateSessionRequest` variant name).
    UpdateSessionRequest(S2bProcedureMessage<'a>),
    /// Update Bearer Response view (legacy `UpdateSessionResponse` variant name).
    UpdateSessionResponse(S2bProcedureMessage<'a>),
    /// PGW-triggered Delete Bearer Request view.
    DeleteBearerRequest(S2bProcedureMessage<'a>),
    /// PGW-triggered Delete Bearer Response view.
    DeleteBearerResponse(S2bProcedureMessage<'a>),
    /// Non-S2b or unsupported message preserved as the raw shell.
    Raw(Message<'a>),
}

impl fmt::Debug for S2bMessage<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EchoRequest(view) => f.debug_tuple("EchoRequest").field(view).finish(),
            Self::EchoResponse(view) => f.debug_tuple("EchoResponse").field(view).finish(),
            Self::CreateSessionRequest(view) => {
                f.debug_tuple("CreateSessionRequest").field(view).finish()
            }
            Self::CreateSessionResponse(view) => {
                f.debug_tuple("CreateSessionResponse").field(view).finish()
            }
            Self::ModifySessionRequest(view) => {
                f.debug_tuple("ModifySessionRequest").field(view).finish()
            }
            Self::ModifySessionResponse(view) => {
                f.debug_tuple("ModifySessionResponse").field(view).finish()
            }
            Self::DeleteSessionRequest(view) => {
                f.debug_tuple("DeleteSessionRequest").field(view).finish()
            }
            Self::DeleteSessionResponse(view) => {
                f.debug_tuple("DeleteSessionResponse").field(view).finish()
            }
            Self::CreateBearerRequest(view) => {
                f.debug_tuple("CreateBearerRequest").field(view).finish()
            }
            Self::CreateBearerResponse(view) => {
                f.debug_tuple("CreateBearerResponse").field(view).finish()
            }
            Self::UpdateSessionRequest(view) => {
                f.debug_tuple("UpdateSessionRequest").field(view).finish()
            }
            Self::UpdateSessionResponse(view) => {
                f.debug_tuple("UpdateSessionResponse").field(view).finish()
            }
            Self::DeleteBearerRequest(view) => {
                f.debug_tuple("DeleteBearerRequest").field(view).finish()
            }
            Self::DeleteBearerResponse(view) => {
                f.debug_tuple("DeleteBearerResponse").field(view).finish()
            }
            Self::Raw(message) => f
                .debug_struct("Raw")
                .field("header", &message.header)
                .field("raw_ies_len", &message.raw_ies.len())
                .field("tail_len", &message.tail.len())
                .finish(),
        }
    }
}

impl<'a> S2bMessage<'a> {
    /// Decode a typed S2b view from a GTPv2-C byte slice.
    pub fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        <Self as BorrowDecode<'a>>::decode(input, ctx)
    }

    /// Convert a decoded raw [`Message`] into a typed S2b view when possible.
    pub fn from_message(message: Message<'a>, ctx: DecodeContext) -> Result<Self, DecodeError> {
        let message_type = message.message_type();
        let Some((procedure, direction)) = procedure_and_direction(message_type) else {
            return Ok(Self::Raw(message));
        };

        let mut typed_ctx = ctx;
        if is_procedure_aware(ctx.validation_level) {
            // Procedure tables, not a blanket first/last policy, define which
            // IE type/instance pairs are lists. The typed decoder preserves
            // those known lists and raw extension lists while rejecting a
            // second occurrence of every known singleton.
            typed_ctx.duplicate_ie_policy = DuplicateIePolicy::Reject;
        }
        let ies = if matches!(
            message_type.as_u8(),
            CREATE_BEARER_REQUEST | UPDATE_BEARER_REQUEST | DELETE_BEARER_REQUEST
        ) {
            decode_pgw_triggered_request_ie_sequence(message.raw_ies, typed_ctx)?
        } else {
            decode_typed_ie_sequence(message.raw_ies, typed_ctx, 0)?
        };
        let view = S2bProcedureMessage {
            header: message.header,
            procedure,
            direction,
            ies,
            raw_ies: message.raw_ies,
            tail: message.tail,
        };
        validate_required_ies(&view, ctx)?;

        Ok(match (procedure, direction) {
            (Procedure::Echo, MessageDirection::Request) => Self::EchoRequest(view),
            (Procedure::Echo, MessageDirection::Response) => Self::EchoResponse(view),
            (Procedure::CreateSession, MessageDirection::Request) => {
                Self::CreateSessionRequest(view)
            }
            (Procedure::CreateSession, MessageDirection::Response) => {
                Self::CreateSessionResponse(view)
            }
            (Procedure::ModifyBearer, MessageDirection::Request) => {
                Self::ModifySessionRequest(view)
            }
            (Procedure::ModifyBearer, MessageDirection::Response) => {
                Self::ModifySessionResponse(view)
            }
            (Procedure::DeleteSession, MessageDirection::Request) => {
                Self::DeleteSessionRequest(view)
            }
            (Procedure::DeleteSession, MessageDirection::Response) => {
                Self::DeleteSessionResponse(view)
            }
            (Procedure::CreateBearer, MessageDirection::Request) => Self::CreateBearerRequest(view),
            (Procedure::CreateBearer, MessageDirection::Response) => {
                Self::CreateBearerResponse(view)
            }
            (Procedure::UpdateSession, MessageDirection::Request) => {
                Self::UpdateSessionRequest(view)
            }
            (Procedure::UpdateSession, MessageDirection::Response) => {
                Self::UpdateSessionResponse(view)
            }
            (Procedure::DeleteBearer, MessageDirection::Request) => Self::DeleteBearerRequest(view),
            (Procedure::DeleteBearer, MessageDirection::Response) => {
                Self::DeleteBearerResponse(view)
            }
        })
    }

    /// Return the typed procedure view, or `None` for raw fallback messages.
    pub fn as_view(&self) -> Option<&S2bProcedureMessage<'a>> {
        match self {
            Self::EchoRequest(view)
            | Self::EchoResponse(view)
            | Self::CreateSessionRequest(view)
            | Self::CreateSessionResponse(view)
            | Self::ModifySessionRequest(view)
            | Self::ModifySessionResponse(view)
            | Self::DeleteSessionRequest(view)
            | Self::DeleteSessionResponse(view)
            | Self::CreateBearerRequest(view)
            | Self::CreateBearerResponse(view)
            | Self::UpdateSessionRequest(view)
            | Self::UpdateSessionResponse(view)
            | Self::DeleteBearerRequest(view)
            | Self::DeleteBearerResponse(view) => Some(view),
            Self::Raw(_) => None,
        }
    }

    /// Return the raw fallback message, or `None` when this is a typed S2b view.
    pub fn as_raw(&self) -> Option<&Message<'a>> {
        match self {
            Self::Raw(message) => Some(message),
            _ => None,
        }
    }

    /// Project this message as an accepted or rejected Create Session Response.
    ///
    /// # Errors
    ///
    /// Returns [`CreateSessionResponseSummaryError`] when this is not a Create
    /// Session Response, lacks Cause/response TEID, or represents an accepted
    /// response without accepted-bearer fields.
    pub fn create_session_response_summary(
        &self,
    ) -> Result<CreateSessionResponseSummary, CreateSessionResponseSummaryError> {
        let Self::CreateSessionResponse(view) = self else {
            return Err(CreateSessionResponseSummaryError::NotCreateSessionResponse);
        };
        view.create_session_response_summary()
    }

    /// Return this message's typed GTPv2-C message type, including unknown raw fallbacks.
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::EchoRequest(view)
            | Self::EchoResponse(view)
            | Self::CreateSessionRequest(view)
            | Self::CreateSessionResponse(view)
            | Self::ModifySessionRequest(view)
            | Self::ModifySessionResponse(view)
            | Self::DeleteSessionRequest(view)
            | Self::DeleteSessionResponse(view)
            | Self::CreateBearerRequest(view)
            | Self::CreateBearerResponse(view)
            | Self::UpdateSessionRequest(view)
            | Self::UpdateSessionResponse(view)
            | Self::DeleteBearerRequest(view)
            | Self::DeleteBearerResponse(view) => view.message_type(),
            Self::Raw(message) => message.message_type(),
        }
    }
}

/// Decode and project one S2b Create Session Response datagram.
///
/// This helper preserves decode limits from `ctx` but performs the final
/// Create Session Response checks through [`CreateSessionResponseSummaryError`]
/// so callers receive stable error codes for missing Cause, missing response
/// TEID, and accepted responses with incomplete accepted-bearer fields.
///
/// # Errors
///
/// Returns [`CreateSessionResponseSummaryError`] when bytes are malformed,
/// contain trailing data after the message, decode to another message type, or
/// fail Create Session Response projection.
pub fn decode_create_session_response_summary(
    input: &[u8],
    ctx: DecodeContext,
) -> Result<CreateSessionResponseSummary, CreateSessionResponseSummaryError> {
    let projection_ctx = create_session_response_projection_context(ctx);
    let (tail, message) = S2bMessage::decode(input, projection_ctx)
        .map_err(|_| CreateSessionResponseSummaryError::MalformedResponse)?;
    if !tail.is_empty() {
        return Err(CreateSessionResponseSummaryError::MalformedResponse);
    }
    message.create_session_response_summary()
}

impl<'a> BorrowDecode<'a> for S2bMessage<'a> {
    /// Decode a typed S2b message view, preserving raw fallback messages.
    fn decode(input: &'a [u8], ctx: DecodeContext) -> DecodeResult<'a, Self> {
        let (tail, message) = Message::decode(input, ctx)?;
        let view = Self::from_message(message, ctx)?;
        Ok((tail, view))
    }
}

impl Encode for S2bMessage<'_> {
    /// Encode this S2b view or raw fallback message.
    fn encode(&self, dst: &mut BytesMut, ctx: EncodeContext) -> Result<(), EncodeError> {
        match self {
            Self::EchoRequest(view)
            | Self::EchoResponse(view)
            | Self::CreateSessionRequest(view)
            | Self::CreateSessionResponse(view)
            | Self::ModifySessionRequest(view)
            | Self::ModifySessionResponse(view)
            | Self::DeleteSessionRequest(view)
            | Self::DeleteSessionResponse(view)
            | Self::CreateBearerRequest(view)
            | Self::CreateBearerResponse(view)
            | Self::UpdateSessionRequest(view)
            | Self::UpdateSessionResponse(view)
            | Self::DeleteBearerRequest(view)
            | Self::DeleteBearerResponse(view) => view.encode(dst, ctx),
            Self::Raw(message) => message.encode(dst, ctx),
        }
    }

    fn wire_len(&self, ctx: EncodeContext) -> Result<usize, EncodeError> {
        match self {
            Self::EchoRequest(view)
            | Self::EchoResponse(view)
            | Self::CreateSessionRequest(view)
            | Self::CreateSessionResponse(view)
            | Self::ModifySessionRequest(view)
            | Self::ModifySessionResponse(view)
            | Self::DeleteSessionRequest(view)
            | Self::DeleteSessionResponse(view)
            | Self::CreateBearerRequest(view)
            | Self::CreateBearerResponse(view)
            | Self::UpdateSessionRequest(view)
            | Self::UpdateSessionResponse(view)
            | Self::DeleteBearerRequest(view)
            | Self::DeleteBearerResponse(view) => view.wire_len(ctx),
            Self::Raw(message) => message.wire_len(ctx),
        }
    }
}

fn create_session_response_projection_context(mut ctx: DecodeContext) -> DecodeContext {
    if ctx.validation_level == ValidationLevel::ProcedureAware {
        ctx.validation_level = ValidationLevel::Strict;
    }
    ctx
}

fn contains_ie(ies: &[TypedIe<'_>], ie_type: u8) -> bool {
    ies.iter().any(|ie| ie.ie_type() == ie_type)
}

fn contains_ie_instance(ies: &[TypedIe<'_>], ie_type: u8, instance: u8) -> bool {
    ies.iter()
        .any(|ie| ie.ie_type() == ie_type && ie.instance == instance)
}

fn contains_uimsi_indication(ies: &[TypedIe<'_>]) -> bool {
    const UIMSI_FLAG_OCTET_INDEX: usize = 1;
    const UIMSI_FLAG_MASK: u8 = 0x40;

    ies.iter().any(|ie| {
        ie.instance == 0
            && matches!(
                &ie.value,
                TypedIeValue::Indication(indication)
                    if indication
                        .flags
                        .get(UIMSI_FLAG_OCTET_INDEX)
                        .is_some_and(|flags| flags & UIMSI_FLAG_MASK != 0)
            )
    })
}

fn contains_create_session_identity(ies: &[TypedIe<'_>]) -> bool {
    contains_ie(ies, IE_TYPE_IMSI)
        || (contains_ie_instance(ies, IE_TYPE_MEI, 0) && contains_uimsi_indication(ies))
}

fn contains_bearer_context_with_ebi(ies: &[TypedIe<'_>]) -> bool {
    ies.iter().any(|ie| match &ie.value {
        TypedIeValue::BearerContext(context) => contains_ie(&context.members, IE_TYPE_EBI),
        _ => false,
    })
}

fn find_cause_value(ies: &[TypedIe<'_>]) -> Option<CauseValue> {
    ies.iter().find_map(|ie| match &ie.value {
        TypedIeValue::Cause(cause) => Some(cause.value),
        _ => None,
    })
}

fn find_recovery_restart_counter(ies: &[TypedIe<'_>]) -> Option<u8> {
    ies.iter().find_map(|ie| match &ie.value {
        TypedIeValue::Recovery(recovery) => Some(recovery.restart_counter),
        _ => None,
    })
}

fn find_sender_f_teid(ies: &[TypedIe<'_>]) -> Option<FullyQualifiedTeid> {
    ies.iter().find_map(|ie| match &ie.value {
        TypedIeValue::FullyQualifiedTeid(f_teid)
            if ie.ie_type() == IE_TYPE_F_TEID && ie.instance == 0 =>
        {
            Some(f_teid.clone())
        }
        _ => None,
    })
}

fn find_bearer_context_ebi(
    ies: &[TypedIe<'_>],
) -> Result<EpsBearerId, CreateSessionResponseSummaryError> {
    let Some(context) = ies.iter().find_map(|ie| match &ie.value {
        TypedIeValue::BearerContext(context) if ie.ie_type() == IE_TYPE_BEARER_CONTEXT => {
            Some(context)
        }
        _ => None,
    }) else {
        return Err(CreateSessionResponseSummaryError::AcceptedResponseMissingBearerContext);
    };

    context
        .members
        .iter()
        .find_map(|ie| match &ie.value {
            TypedIeValue::EpsBearerId(ebi) if ie.ie_type() == IE_TYPE_EBI => Some(*ebi),
            _ => None,
        })
        .ok_or(CreateSessionResponseSummaryError::AcceptedResponseMissingBearerEbi)
}

fn find_response_paa(
    ies: &[TypedIe<'_>],
) -> Result<Option<PdnAddressAllocation>, CreateSessionResponseSummaryError> {
    let Some(ie) = ies
        .iter()
        .find(|ie| ie.ie_type() == IE_TYPE_PAA && ie.instance == 0)
    else {
        return Ok(None);
    };
    match &ie.value {
        TypedIeValue::PdnAddressAllocation(paa) => Ok(Some(paa.clone())),
        _ => Err(CreateSessionResponseSummaryError::AcceptedResponseMalformedPaa),
    }
}

fn find_response_pco(ies: &[TypedIe<'_>]) -> Option<ProtocolConfigurationOptions> {
    ies.iter().find_map(|ie| match &ie.value {
        TypedIeValue::ProtocolConfigurationOptions(pco)
            if ie.ie_type() == IE_TYPE_PCO && ie.instance == 0 =>
        {
            Some(pco.clone())
        }
        _ => None,
    })
}

fn find_bearer_context_s2b_u_f_teid(
    ies: &[TypedIe<'_>],
) -> Result<FullyQualifiedTeid, CreateSessionResponseSummaryError> {
    let Some(context) = ies.iter().find_map(|ie| match &ie.value {
        TypedIeValue::BearerContext(context) if ie.ie_type() == IE_TYPE_BEARER_CONTEXT => {
            Some(context)
        }
        _ => None,
    }) else {
        return Err(CreateSessionResponseSummaryError::AcceptedResponseMissingBearerContext);
    };

    let mut saw_f_teid = false;
    for member in &context.members {
        let TypedIeValue::FullyQualifiedTeid(f_teid) = &member.value else {
            continue;
        };
        if member.ie_type() != IE_TYPE_F_TEID {
            continue;
        }
        saw_f_teid = true;
        if f_teid.interface_type == INTERFACE_TYPE_S2B_U_PGW_GTP_U {
            if f_teid.ipv4.is_none() && f_teid.ipv6.is_none() {
                return Err(
                    CreateSessionResponseSummaryError::AcceptedResponseMalformedBearerFTeid,
                );
            }
            return Ok(f_teid.clone());
        }
    }

    if saw_f_teid {
        Err(CreateSessionResponseSummaryError::AcceptedResponseBearerFTeidInterfaceMismatch)
    } else {
        Err(CreateSessionResponseSummaryError::AcceptedResponseMissingBearerFTeid)
    }
}

fn is_accepted_create_session_cause(cause: CauseValue) -> bool {
    matches!(
        cause,
        CauseValue::RequestAccepted | CauseValue::RequestAcceptedPartially
    )
}

fn project_create_session_response(
    view: &S2bProcedureMessage<'_>,
) -> Result<CreateSessionResponseSummary, CreateSessionResponseSummaryError> {
    if view.procedure != Procedure::CreateSession || view.direction != MessageDirection::Response {
        return Err(CreateSessionResponseSummaryError::NotCreateSessionResponse);
    }

    let response_teid = view
        .header
        .teid
        .ok_or(CreateSessionResponseSummaryError::MissingResponseTeid)?;
    let sequence_number = view.header.sequence_number;
    let cause =
        find_cause_value(&view.ies).ok_or(CreateSessionResponseSummaryError::MissingCause)?;

    if is_accepted_create_session_cause(cause) {
        let sender_f_teid = find_sender_f_teid(&view.ies)
            .ok_or(CreateSessionResponseSummaryError::AcceptedResponseMissingSenderFTeid)?;
        let bearer_ebi = find_bearer_context_ebi(&view.ies)?;
        let bearer_user_plane_f_teid = find_bearer_context_s2b_u_f_teid(&view.ies)?;
        let paa = find_response_paa(&view.ies)?;
        let pco = find_response_pco(&view.ies);

        Ok(CreateSessionResponseSummary::Accepted(
            CreateSessionAcceptedResponseSummary {
                response_teid,
                sequence_number,
                cause,
                sender_f_teid,
                bearer_ebi,
                bearer_user_plane_f_teid,
                paa,
                pco,
            },
        ))
    } else {
        Ok(CreateSessionResponseSummary::Rejected(
            CreateSessionRejectedResponseSummary {
                response_teid,
                sequence_number,
                cause,
            },
        ))
    }
}

fn missing_ie_error(reason: &'static str) -> DecodeError {
    DecodeError::new(DecodeErrorCode::Structural { reason }, 0).with_spec_ref(spec_ref())
}

fn require_ie(ies: &[TypedIe<'_>], ie_type: u8, reason: &'static str) -> Result<(), DecodeError> {
    if contains_ie(ies, ie_type) {
        Ok(())
    } else {
        Err(missing_ie_error(reason))
    }
}

fn require_ie_instance(
    ies: &[TypedIe<'_>],
    ie_type: u8,
    instance: u8,
    reason: &'static str,
) -> Result<(), DecodeError> {
    if contains_ie_instance(ies, ie_type, instance) {
        Ok(())
    } else {
        Err(missing_ie_error(reason))
    }
}

fn validate_required_ies(
    view: &S2bProcedureMessage<'_>,
    ctx: DecodeContext,
) -> Result<(), DecodeError> {
    if !is_procedure_aware(ctx.validation_level) {
        return Ok(());
    }

    match (view.procedure, view.direction) {
        (Procedure::Echo, MessageDirection::Request) => require_ie(
            &view.ies,
            IE_TYPE_RECOVERY,
            "Echo Request requires Recovery IE",
        ),
        (Procedure::Echo, MessageDirection::Response) => require_ie(
            &view.ies,
            IE_TYPE_RECOVERY,
            "Echo Response requires Recovery IE",
        ),
        (Procedure::CreateSession, MessageDirection::Request) => {
            if !view.header.teid_flag || view.header.teid != Some(0) {
                return Err(missing_ie_error(
                    "Create Session Request must set TEID flag with TEID 0",
                ));
            }
            if !contains_create_session_identity(&view.ies) {
                return Err(missing_ie_error(
                    "Create Session Request requires IMSI IE or emergency MEI and UIMSI Indication IEs",
                ));
            }
            require_ie(
                &view.ies,
                IE_TYPE_RAT_TYPE,
                "Create Session Request requires RAT Type IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_SERVING_NETWORK,
                "Create Session Request requires Serving Network IE",
            )?;
            require_ie_instance(
                &view.ies,
                IE_TYPE_F_TEID,
                0,
                "Create Session Request requires Sender F-TEID IE at instance 0",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_APN,
                "Create Session Request requires APN IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_SELECTION_MODE,
                "Create Session Request requires Selection Mode IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_PDN_TYPE,
                "Create Session Request requires PDN Type IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_PAA,
                "Create Session Request requires PAA IE",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_BEARER_CONTEXT,
                "Create Session Request requires Bearer Context IE",
            )?;
            if contains_bearer_context_with_ebi(&view.ies) {
                Ok(())
            } else {
                Err(missing_ie_error(
                    "Create Session Request Bearer Context requires EBI IE",
                ))
            }
        }
        (Procedure::CreateSession, MessageDirection::Response) => {
            let cause = find_cause_value(&view.ies)
                .ok_or_else(|| missing_ie_error("Create Session Response requires Cause IE"))?;
            if !is_accepted_create_session_cause(cause) {
                return Ok(());
            }
            require_ie_instance(
                &view.ies,
                IE_TYPE_F_TEID,
                0,
                "Create Session Response requires Sender F-TEID IE at instance 0",
            )?;
            require_ie(
                &view.ies,
                IE_TYPE_BEARER_CONTEXT,
                "Create Session Response requires Bearer Context IE",
            )?;
            if contains_bearer_context_with_ebi(&view.ies) {
                Ok(())
            } else {
                Err(missing_ie_error(
                    "Create Session Response Bearer Context requires EBI IE",
                ))
            }
        }
        (Procedure::ModifyBearer, MessageDirection::Request) => require_ie(
            &view.ies,
            IE_TYPE_BEARER_CONTEXT,
            "Modify Bearer Request requires Bearer Context IE",
        ),
        (Procedure::ModifyBearer, MessageDirection::Response) => require_ie(
            &view.ies,
            IE_TYPE_CAUSE,
            "Modify Bearer Response requires Cause IE",
        ),
        (Procedure::DeleteSession, MessageDirection::Request) => require_ie(
            &view.ies,
            IE_TYPE_EBI,
            "Delete Session Request requires linked EBI IE",
        ),
        (Procedure::DeleteSession, MessageDirection::Response) => require_ie(
            &view.ies,
            IE_TYPE_CAUSE,
            "Delete Session Response requires Cause IE",
        ),
        (Procedure::CreateBearer, _)
        | (Procedure::UpdateSession, _)
        | (Procedure::DeleteBearer, _) => crate::dedicated_bearer::validate_procedure_message(view),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{HEADER_LEN_WITHOUT_TEID, HEADER_LEN_WITH_TEID};
    use crate::ie::{PdnTypeValue, PlmnId, RatTypeValue, Recovery, SelectionModeValue};
    use opc_protocol::{DecodeContext, Encode, EncodeContext};

    fn echo_view(
        direction: MessageDirection,
        sequence_number: u32,
        restart_counter: u8,
    ) -> S2bProcedureMessage<'static> {
        let message_type = match direction {
            MessageDirection::Request => ECHO_REQUEST,
            MessageDirection::Response => ECHO_RESPONSE,
        };
        S2bProcedureMessage {
            header: Header::without_teid(message_type, sequence_number),
            procedure: Procedure::Echo,
            direction,
            ies: vec![TypedIe {
                instance: 0,
                value: TypedIeValue::Recovery(Recovery { restart_counter }),
            }],
            raw_ies: &[],
            tail: &[],
        }
    }

    fn echo_evidence(
        direction: MessageDirection,
        sequence_number: u32,
        restart_counter: u8,
    ) -> EchoMessageEvidence {
        EchoMessageEvidence {
            direction,
            sequence_number,
            restart_counter,
        }
    }

    fn encode_view(view: &S2bProcedureMessage<'_>) -> Vec<u8> {
        let mut encoded = BytesMut::new();
        if let Err(error) = view.encode(&mut encoded, EncodeContext::default()) {
            panic!("Echo view encode failed: {error}");
        }
        encoded.to_vec()
    }

    fn encode_owned(message: &OwnedMessage) -> Vec<u8> {
        let mut encoded = BytesMut::new();
        if let Err(error) = message.encode(&mut encoded, EncodeContext::default()) {
            panic!("message encode failed: {error}");
        }
        encoded.to_vec()
    }

    fn bearer_ebi(value: u8) -> TypedIe<'static> {
        typed_ie(0, TypedIeValue::EpsBearerId(EpsBearerId { value }))
    }

    fn f_teid(interface_type: u8, teid: u32, ipv4: [u8; 4]) -> FullyQualifiedTeid {
        FullyQualifiedTeid {
            interface_type,
            teid,
            ipv4: Some(ipv4),
            ipv6: None,
        }
    }

    fn bearer_context(members: Vec<TypedIe<'static>>) -> BearerContext<'static> {
        BearerContext { members }
    }

    fn response_paa(ipv4: [u8; 4]) -> PdnAddressAllocation {
        PdnAddressAllocation {
            pdn_type: PdnTypeValue::Ipv4,
            ipv6_prefix_length: None,
            ipv6_prefix: None,
            ipv4: Some(ipv4),
        }
    }

    fn accepted_response(
        bearer_members: Vec<TypedIe<'static>>,
        additional_ies: Vec<TypedIe<'static>>,
    ) -> OwnedMessage {
        match s2b_create_session_accepted_response(S2bCreateSessionAcceptedResponse {
            sequence_number: 0x0001_0203,
            response_teid: 0x0102_0304,
            sender_f_teid: f_teid(32, 0x1111_2222, [192, 0, 2, 1]),
            bearer_context: bearer_context(bearer_members),
            additional_ies,
        }) {
            Ok(message) => message,
            Err(error) => panic!("accepted response build failed: {error}"),
        }
    }

    fn valid_create_session_request() -> S2bCreateSessionRequest<'static> {
        S2bCreateSessionRequest {
            sequence_number: 0x0000_0102,
            imsi: TbcdDigits::new("001010123456789"),
            rat_type: RatType {
                value: RatTypeValue::Wlan,
            },
            serving_network: ServingNetwork {
                plmn: PlmnId::new("001", "01"),
            },
            sender_f_teid: f_teid(30, 0x0102_0304, [198, 51, 100, 1]),
            apn: AccessPointName::new(vec!["internet".to_string()]),
            selection_mode: SelectionMode {
                value: SelectionModeValue::MsOrNetworkProvidedSubscriptionVerified,
            },
            pdn_type: PdnType {
                value: PdnTypeValue::Ipv4,
            },
            paa: response_paa([0, 0, 0, 0]),
            bearer_context: bearer_context(vec![bearer_ebi(5)]),
            additional_ies: Vec::new(),
        }
    }

    fn transaction_request_view(
        procedure: Procedure,
        sequence_number: u32,
        request_teid: Option<u32>,
    ) -> S2bProcedureMessage<'static> {
        let header = match request_teid {
            Some(teid) => Header::with_teid(procedure.request_type(), teid, sequence_number),
            None => Header::without_teid(procedure.request_type(), sequence_number),
        };
        S2bProcedureMessage {
            header,
            procedure,
            direction: MessageDirection::Request,
            ies: Vec::new(),
            raw_ies: &[],
            tail: &[],
        }
    }

    fn transaction_response_evidence(
        procedure: Procedure,
        sequence_number: u32,
        response_teid: Option<u32>,
        peer: Gtpv2cPeerToken,
    ) -> Gtpv2cClientResponseEvidence {
        Gtpv2cClientResponseEvidence {
            procedure,
            direction: MessageDirection::Response,
            message_type: procedure.response_message_type(),
            sequence_number,
            response_teid,
            peer,
        }
    }

    fn transaction_plan() -> Gtpv2cClientTransactionPlan {
        let request = transaction_request_view(Procedure::CreateSession, 0x1234, None);
        match Gtpv2cClientTransactionPlan::from_request_view(
            &request,
            Gtpv2cPeerToken::new(7),
            Some(0x0102_0304),
            88,
        ) {
            Ok(plan) => plan,
            Err(error) => panic!("transaction plan failed: {error}"),
        }
    }

    fn send_echo_request(
        peer: &mut Gtpv2cEchoPeer,
        sequence_number: u32,
    ) -> Gtpv2cEchoPeerTransition {
        match peer.echo_request_sent(sequence_number) {
            Ok(transition) => transition,
            Err(error) => panic!("Echo request transition failed: {error}"),
        }
    }

    #[test]
    fn echo_message_evidence_extracts_recovery() {
        let view = echo_view(MessageDirection::Response, 0x0001_0203, 9);

        let evidence = match EchoMessageEvidence::from_view(&view) {
            Ok(evidence) => evidence,
            Err(error) => panic!("Echo evidence projection failed: {error}"),
        };

        assert_eq!(evidence.direction, MessageDirection::Response);
        assert_eq!(evidence.direction.as_str(), "response");
        assert_eq!(evidence.sequence_number, 0x0001_0203);
        assert_eq!(evidence.restart_counter, 9);

        let encoded = encode_view(&view);
        let decoded = match decode_echo_message_evidence(&encoded, DecodeContext::default()) {
            Ok(evidence) => evidence,
            Err(error) => panic!("Echo evidence decode failed: {error}"),
        };
        assert_eq!(decoded, evidence);
        assert_eq!(
            EchoMessageEvidenceError::MissingRecovery.as_str(),
            "gtpv2c_echo_message_missing_recovery"
        );
    }

    #[test]
    fn echo_peer_accepts_matching_response() {
        let mut peer = Gtpv2cEchoPeer::new();

        let transition = send_echo_request(&mut peer, 0x0102_0304);

        assert_eq!(transition.event, Gtpv2cEchoPeerEvent::EchoRequestSent);
        assert_eq!(transition.state, Gtpv2cEchoPeerState::AwaitingResponse);
        assert_eq!(
            transition.readiness.blockers,
            vec![Gtpv2cEchoPeerBlocker::EchoResponsePending]
        );

        let transition = match peer.observe_echo_response(echo_evidence(
            MessageDirection::Response,
            0x0102_0304,
            7,
        )) {
            Ok(transition) => transition,
            Err(error) => panic!("Echo response transition failed: {error}"),
        };

        assert_eq!(transition.event, Gtpv2cEchoPeerEvent::EchoResponseAccepted);
        assert_eq!(transition.state, Gtpv2cEchoPeerState::Reachable);
        assert!(transition.readiness.traffic_ready);
        assert!(transition.projection.response_observed);
        assert!(transition.projection.peer_reachable);
        assert!(transition.projection.continuity_safe);
        assert_eq!(transition.projection.restart_counter, Some(7));
        assert_eq!(transition.projection.in_flight_sequence_number, None);

        let snapshot = peer.snapshot();
        assert_eq!(snapshot.echo_requests_sent, 1);
        assert_eq!(snapshot.echo_responses_observed, 1);
        assert_eq!(snapshot.last_restart_counter, Some(7));
    }

    #[test]
    fn echo_peer_restart_counter_requires_reconciliation() {
        let mut peer = Gtpv2cEchoPeer::new();
        let _transition = send_echo_request(&mut peer, 1);
        match peer.observe_echo_response(echo_evidence(MessageDirection::Response, 1, 9)) {
            Ok(_transition) => {}
            Err(error) => panic!("initial Echo response transition failed: {error}"),
        }

        let _transition = send_echo_request(&mut peer, 2);
        let transition =
            match peer.observe_echo_response(echo_evidence(MessageDirection::Response, 2, 10)) {
                Ok(transition) => transition,
                Err(error) => panic!("restart Echo response transition failed: {error}"),
            };

        assert_eq!(transition.event, Gtpv2cEchoPeerEvent::PeerRestartObserved);
        assert_eq!(
            transition.state,
            Gtpv2cEchoPeerState::ReconciliationRequired
        );
        assert!(!transition.readiness.traffic_ready);
        assert!(transition.projection.restart_counter_changed);
        assert!(!transition.projection.continuity_safe);
        assert_eq!(
            transition.readiness.blockers,
            vec![
                Gtpv2cEchoPeerBlocker::PeerRestartCounterChanged,
                Gtpv2cEchoPeerBlocker::RestartReconciliationRequired,
            ]
        );

        let rejected = match peer.echo_request_sent(3) {
            Ok(transition) => panic!("unexpected Echo request transition: {transition:?}"),
            Err(error) => error,
        };
        assert_eq!(rejected, Gtpv2cEchoPeerError::RestartReconciliationRequired);
        assert_eq!(
            rejected.as_str(),
            "gtpv2c_echo_peer_restart_reconciliation_required"
        );
        assert_eq!(
            rejected.to_string(),
            "gtpv2c_echo_peer_restart_reconciliation_required"
        );
        for rendered in [format!("{rejected:?}"), format!("{rejected}")] {
            assert!(!rendered.contains('3'));
            assert!(!rendered.contains("10"));
            assert!(!rendered.contains('['));
        }
        assert_eq!(peer.state(), Gtpv2cEchoPeerState::ReconciliationRequired);
        assert_eq!(peer.snapshot().echo_requests_sent, 2);

        let transition = match peer.restart_reconciled() {
            Ok(transition) => transition,
            Err(error) => panic!("restart reconciliation transition failed: {error}"),
        };
        assert_eq!(transition.event, Gtpv2cEchoPeerEvent::RestartReconciled);
        assert_eq!(transition.state, Gtpv2cEchoPeerState::Reachable);
        assert!(transition.readiness.traffic_ready);
        assert_eq!(peer.snapshot().restart_counter_changes, 1);

        let transition = send_echo_request(&mut peer, 3);
        assert_eq!(transition.event, Gtpv2cEchoPeerEvent::EchoRequestSent);
        assert_eq!(transition.state, Gtpv2cEchoPeerState::AwaitingResponse);
    }

    #[test]
    fn echo_peer_disabled_restart_reconciliation_preserves_echo_flow() {
        let policy = Gtpv2cEchoPeerPolicy::default().without_restart_reconciliation();
        let mut peer = Gtpv2cEchoPeer::with_policy(policy);

        let _transition = send_echo_request(&mut peer, 1);
        match peer.observe_echo_response(echo_evidence(MessageDirection::Response, 1, 9)) {
            Ok(_transition) => {}
            Err(error) => panic!("initial Echo response transition failed: {error}"),
        }

        let _transition = send_echo_request(&mut peer, 2);
        let transition =
            match peer.observe_echo_response(echo_evidence(MessageDirection::Response, 2, 10)) {
                Ok(transition) => transition,
                Err(error) => panic!("restart Echo response transition failed: {error}"),
            };

        assert_eq!(transition.event, Gtpv2cEchoPeerEvent::EchoResponseAccepted);
        assert_eq!(transition.state, Gtpv2cEchoPeerState::Reachable);
        assert!(transition.readiness.traffic_ready);
        assert!(transition.projection.restart_counter_changed);
        assert!(transition.projection.continuity_safe);
        assert_eq!(peer.snapshot().restart_counter_changes, 1);

        let transition = send_echo_request(&mut peer, 3);
        assert_eq!(transition.previous_state, Gtpv2cEchoPeerState::Reachable);
        assert_eq!(transition.state, Gtpv2cEchoPeerState::AwaitingResponse);
    }

    #[test]
    fn echo_peer_missing_response_degrades_then_fails() {
        let policy = Gtpv2cEchoPeerPolicy::default().with_missed_response_threshold(2);
        let mut peer = Gtpv2cEchoPeer::with_policy(policy);
        let _transition = send_echo_request(&mut peer, 1);

        let transition = match peer.echo_response_missing() {
            Ok(transition) => transition,
            Err(error) => panic!("missing Echo response transition failed: {error}"),
        };

        assert_eq!(transition.event, Gtpv2cEchoPeerEvent::EchoResponseMissing);
        assert_eq!(transition.state, Gtpv2cEchoPeerState::Degraded);
        assert_eq!(
            transition.readiness.blockers,
            vec![Gtpv2cEchoPeerBlocker::EchoResponseMissing]
        );
        assert_eq!(transition.projection.missed_responses, 1);

        let _transition = send_echo_request(&mut peer, 2);
        let transition = match peer.echo_response_missing() {
            Ok(transition) => transition,
            Err(error) => panic!("second missing Echo response transition failed: {error}"),
        };

        assert_eq!(transition.state, Gtpv2cEchoPeerState::Failed);
        assert!(transition.readiness.failed);
        assert_eq!(
            transition.readiness.blockers,
            vec![
                Gtpv2cEchoPeerBlocker::EchoResponseMissing,
                Gtpv2cEchoPeerBlocker::PeerUnreachable,
            ]
        );
        assert_eq!(peer.snapshot().missed_responses, 2);
    }

    #[test]
    fn echo_peer_sequence_mismatch_and_errors_are_stable() {
        let mut peer = Gtpv2cEchoPeer::new();
        let _transition = send_echo_request(&mut peer, 7);

        let transition =
            match peer.observe_echo_response(echo_evidence(MessageDirection::Response, 8, 1)) {
                Ok(transition) => transition,
                Err(error) => panic!("mismatch Echo response transition failed: {error}"),
            };

        assert_eq!(
            transition.event,
            Gtpv2cEchoPeerEvent::EchoResponseSequenceMismatch
        );
        assert_eq!(transition.state, Gtpv2cEchoPeerState::Degraded);
        assert_eq!(
            transition.readiness.blockers,
            vec![Gtpv2cEchoPeerBlocker::EchoResponseSequenceMismatch]
        );
        assert_eq!(peer.snapshot().echo_response_sequence_mismatches, 1);

        let error = match peer.observe_echo_response(echo_evidence(MessageDirection::Request, 7, 1))
        {
            Ok(transition) => panic!("unexpected transition: {transition:?}"),
            Err(error) => error,
        };
        assert_eq!(error.as_str(), "gtpv2c_echo_peer_unexpected_direction");
        assert_eq!(
            format!("{error}"),
            "gtpv2c_echo_peer_unexpected_direction: expected response, actual request"
        );

        let mut peer = Gtpv2cEchoPeer::new();
        let error =
            match peer.observe_echo_response(echo_evidence(MessageDirection::Response, 1, 1)) {
                Ok(transition) => panic!("unexpected transition: {transition:?}"),
                Err(error) => error,
            };
        assert_eq!(error.as_str(), "gtpv2c_echo_peer_invalid_transition");
        assert_eq!(
            Gtpv2cEchoPeerBlocker::RestartReconciliationRequired.as_str(),
            "gtpv2c_restart_reconciliation_required"
        );
        assert_eq!(
            Gtpv2cEchoPeerEvent::EchoResponseMissing.as_str(),
            "echo_response_missing"
        );
        assert_eq!(Gtpv2cEchoPeerState::Failed.as_str(), "failed");
    }

    #[test]
    fn transaction_plan_decodes_request_and_redacts_debug() {
        let request = transaction_request_view(Procedure::DeleteSession, 0x2222, Some(0x1122_3344));
        let encoded = encode_view(&request);
        let peer = Gtpv2cPeerToken::new(99);

        let plan = match Gtpv2cClientTransactionPlan::from_encoded_request(
            &encoded,
            peer,
            Some(0x5566_7788),
            DecodeContext::default(),
        ) {
            Ok(plan) => plan,
            Err(error) => panic!("encoded transaction plan failed: {error}"),
        };

        assert_eq!(plan.key.procedure, Procedure::DeleteSession);
        assert_eq!(plan.key.sequence_number, 0x2222);
        assert_eq!(plan.key.request_teid, Some(0x1122_3344));
        assert_eq!(plan.key.expected_response_teid, Some(0x5566_7788));
        assert_eq!(plan.key.peer.get(), 99);
        assert_eq!(
            plan.response_message_type,
            MessageType::DeleteSessionResponse
        );

        let debug = format!("{plan:?}");
        assert!(debug.contains("request_teid_present"));
        assert!(!debug.contains("287454020"));
        assert!(!debug.contains("1432778632"));

        let response_view = S2bProcedureMessage {
            direction: MessageDirection::Response,
            ..request.clone()
        };
        let error = match Gtpv2cClientTransactionPlan::from_request_view(
            &response_view,
            peer,
            Some(1),
            8,
        ) {
            Ok(plan) => panic!("unexpected transaction plan: {plan:?}"),
            Err(error) => error,
        };
        assert_eq!(error.as_str(), "gtpv2c_transaction_not_request");

        let echo = echo_view(MessageDirection::Request, 1, 1);
        let error = match Gtpv2cClientTransactionPlan::from_request_view(&echo, peer, None, 8) {
            Ok(plan) => panic!("unexpected Echo transaction plan: {plan:?}"),
            Err(error) => error,
        };
        assert_eq!(error.as_str(), "gtpv2c_transaction_unsupported_procedure");
    }

    #[test]
    fn transaction_projects_send_timeout_and_failover_decisions() {
        let plan = transaction_plan();
        let policy = Gtpv2cClientTransactionPolicy::default().with_max_response_timeouts(2);
        let mut transaction = Gtpv2cClientTransaction::with_policy(plan, policy);

        let projection = transaction.send_not_attempted();
        assert_eq!(
            projection.decision,
            Gtpv2cClientTransactionDecision::SendNotAttempted
        );
        assert!(projection.peer_failover_safe);
        assert_eq!(
            projection.state,
            Gtpv2cClientTransactionState::SendNotAttempted
        );

        let projection = transaction.send_failed_before_delivery();
        assert_eq!(
            projection.decision,
            Gtpv2cClientTransactionDecision::SendFailedBeforeDelivery
        );
        assert!(projection.peer_failover_safe);
        assert!(!projection.terminal);

        let projection = transaction.sent_waiting_response();
        assert_eq!(
            projection.decision,
            Gtpv2cClientTransactionDecision::SentWaitingResponse
        );
        assert_eq!(
            projection.state,
            Gtpv2cClientTransactionState::SentWaitingResponse
        );
        assert_eq!(projection.send_attempts, 1);

        let projection = transaction.response_timeout();
        assert_eq!(
            projection.decision,
            Gtpv2cClientTransactionDecision::SafeRetransmitSamePeer
        );
        assert!(projection.safe_retransmit_same_peer);
        assert!(!projection.peer_failover_safe);
        assert!(!projection.terminal);

        let projection = transaction.unsafe_peer_failover();
        assert_eq!(
            projection.decision,
            Gtpv2cClientTransactionDecision::UnsafePeerFailover
        );
        assert!(!projection.peer_failover_safe);

        let projection = transaction.response_timeout();
        assert_eq!(
            projection.decision,
            Gtpv2cClientTransactionDecision::TerminalTimeout
        );
        assert_eq!(
            projection.state,
            Gtpv2cClientTransactionState::TerminalTimeout
        );
        assert!(projection.terminal);
        assert_eq!(
            Gtpv2cClientTransactionDecision::UnsafePeerFailover.as_str(),
            "unsafe_peer_failover"
        );
        assert_eq!(
            Gtpv2cClientTransactionState::SentWaitingResponse.as_str(),
            "sent_waiting_response"
        );
    }

    #[test]
    fn transaction_classifies_matched_duplicate_late_and_mismatched_responses() {
        let plan = transaction_plan();
        let mut transaction = Gtpv2cClientTransaction::new(plan.clone());
        let _projection = transaction.sent_waiting_response();
        let response = transaction_response_evidence(
            Procedure::CreateSession,
            0x1234,
            Some(0x0102_0304),
            Gtpv2cPeerToken::new(7),
        );

        let projection = transaction.observe_response(response);

        assert_eq!(
            projection.decision,
            Gtpv2cClientTransactionDecision::ResponseMatched
        );
        assert!(projection.response_matched);
        assert!(projection.terminal);
        assert_eq!(
            projection.state,
            Gtpv2cClientTransactionState::ResponseObserved
        );

        let projection = transaction.observe_response(response);
        assert_eq!(
            projection.decision,
            Gtpv2cClientTransactionDecision::DuplicateResponse
        );

        let mut timed_out = Gtpv2cClientTransaction::new(plan.clone());
        let _projection = timed_out.sent_waiting_response();
        let _projection = timed_out.response_timeout();
        let projection = timed_out.observe_response(response);
        assert_eq!(
            projection.decision,
            Gtpv2cClientTransactionDecision::LateResponse
        );

        let mut mismatched = Gtpv2cClientTransaction::new(plan);
        let _projection = mismatched.sent_waiting_response();
        let wrong_sequence = transaction_response_evidence(
            Procedure::CreateSession,
            0x1235,
            Some(0x0102_0304),
            Gtpv2cPeerToken::new(7),
        );
        let projection = mismatched.observe_response(wrong_sequence);
        assert_eq!(
            projection.decision,
            Gtpv2cClientTransactionDecision::ResponseMismatched
        );
        assert_eq!(
            projection.mismatch,
            Some(Gtpv2cClientTransactionMismatch::SequenceNumber)
        );
        assert_eq!(
            Gtpv2cClientTransactionMismatch::ResponseTeid.as_str(),
            "gtpv2c_transaction_response_teid_mismatch"
        );
    }

    #[test]
    fn procedure_maps_request_and_response_types() {
        assert_eq!(
            Procedure::CreateSession.request_type(),
            CREATE_SESSION_REQUEST
        );
        assert_eq!(
            Procedure::CreateSession.response_type(),
            CREATE_SESSION_RESPONSE
        );
        assert_eq!(
            Procedure::UpdateSession.request_type(),
            UPDATE_BEARER_REQUEST
        );
        assert_eq!(Procedure::Echo.response_type(), ECHO_RESPONSE);
        assert!(is_s2b_message_type(DELETE_SESSION_RESPONSE));
        assert!(is_s2b_message_type(UPDATE_BEARER_RESPONSE));
        assert!(!is_s2b_message_type(3));
    }

    #[test]
    fn create_session_request_builder_sets_teid_flag_with_zero_teid() {
        let message = match s2b_create_session_request(valid_create_session_request()) {
            Ok(message) => message,
            Err(error) => panic!("Create Session Request build failed: {error}"),
        };
        assert!(message.header.teid_flag);
        assert_eq!(message.header.teid, Some(0));
        assert_eq!(message.header.wire_len(), HEADER_LEN_WITH_TEID);

        let encoded = encode_owned(&message);
        assert_eq!(encoded[0], 0x48);
        assert_eq!(&encoded[4..8], &[0, 0, 0, 0]);

        let echo = match s2b_echo_request(7, Recovery { restart_counter: 1 }) {
            Ok(message) => message,
            Err(error) => panic!("Echo Request build failed: {error}"),
        };
        let encoded_echo = encode_owned(&echo);
        assert_eq!(encoded_echo[0], 0x40);
        assert_eq!(echo.header.wire_len(), HEADER_LEN_WITHOUT_TEID);
    }

    #[test]
    fn create_session_request_profile_rejects_t_zero_header() {
        let mut message = match s2b_create_session_request(valid_create_session_request()) {
            Ok(message) => message,
            Err(error) => panic!("Create Session Request build failed: {error}"),
        };
        message.header = Header::without_teid(CREATE_SESSION_REQUEST, 0x0000_0102);

        assert!(validate_built_s2b_profile_message(&message).is_err());
    }

    #[test]
    fn accepted_create_session_summary_projects_paa_pco_and_user_plane_f_teid() {
        let paa = response_paa([203, 0, 113, 9]);
        let pco = ProtocolConfigurationOptions {
            value: vec![0x80, 0x00, 0x0d, 0x04, 8, 8, 8, 8],
        };
        let message = accepted_response(
            vec![
                bearer_ebi(5),
                typed_ie(
                    0,
                    TypedIeValue::FullyQualifiedTeid(f_teid(
                        INTERFACE_TYPE_S2B_U_PGW_GTP_U,
                        0x1122_3344,
                        [203, 0, 113, 1],
                    )),
                ),
            ],
            vec![
                typed_ie(0, TypedIeValue::PdnAddressAllocation(paa.clone())),
                typed_ie(0, TypedIeValue::ProtocolConfigurationOptions(pco.clone())),
            ],
        );

        let summary = match decode_create_session_response_summary(
            &encode_owned(&message),
            DecodeContext::default(),
        ) {
            Ok(summary) => summary,
            Err(error) => panic!("summary decode failed: {error}"),
        };

        let CreateSessionResponseSummary::Accepted(accepted) = summary else {
            panic!("expected accepted summary");
        };
        assert_eq!(accepted.paa, Some(paa));
        assert_eq!(accepted.pco, Some(pco));
        let projected_pco = match &accepted.pco {
            Some(pco) => pco,
            None => panic!("PCO was not projected"),
        };
        let decoded_pco =
            match crate::PcoAddressConfiguration::decode_network_contents(&projected_pco.value) {
                Ok(decoded) => decoded,
                Err(error) => panic!("PCO address decode failed: {error}"),
            };
        assert_eq!(decoded_pco.dns_server_ipv4, vec![[8, 8, 8, 8]]);
        assert_eq!(
            accepted.bearer_user_plane_f_teid.interface_type,
            INTERFACE_TYPE_S2B_U_PGW_GTP_U
        );
        assert_eq!(accepted.bearer_user_plane_f_teid.teid, 0x1122_3344);
        assert_eq!(
            accepted.bearer_user_plane_f_teid.ipv4,
            Some([203, 0, 113, 1])
        );

        let debug = format!("{accepted:?}");
        assert!(debug.contains("paa_ipv4_present: true"));
        assert!(debug.contains("pco_present: true"));
        assert!(!debug.contains("[203, 0, 113, 9]"));
        assert!(!debug.contains("[203, 0, 113, 1]"));
        assert!(!debug.contains("8, 8, 8, 8"));
        assert!(!debug.contains("287454020"));
    }

    #[test]
    fn accepted_create_session_summary_treats_paa_as_optional_and_instance_zero_only() {
        let message = accepted_response(
            vec![
                bearer_ebi(5),
                typed_ie(
                    0,
                    TypedIeValue::FullyQualifiedTeid(f_teid(
                        INTERFACE_TYPE_S2B_U_PGW_GTP_U,
                        0x1122_3344,
                        [203, 0, 113, 1],
                    )),
                ),
            ],
            Vec::new(),
        );
        let summary = match decode_create_session_response_summary(
            &encode_owned(&message),
            DecodeContext::default(),
        ) {
            Ok(summary) => summary,
            Err(error) => panic!("summary decode failed: {error}"),
        };
        let CreateSessionResponseSummary::Accepted(accepted) = summary else {
            panic!("expected accepted summary");
        };
        assert_eq!(accepted.paa, None);

        let message = accepted_response(
            vec![
                bearer_ebi(5),
                typed_ie(
                    0,
                    TypedIeValue::FullyQualifiedTeid(f_teid(
                        INTERFACE_TYPE_S2B_U_PGW_GTP_U,
                        0x1122_3344,
                        [203, 0, 113, 1],
                    )),
                ),
            ],
            vec![typed_ie(
                1,
                TypedIeValue::PdnAddressAllocation(response_paa([203, 0, 113, 9])),
            )],
        );
        let summary = match decode_create_session_response_summary(
            &encode_owned(&message),
            DecodeContext::default(),
        ) {
            Ok(summary) => summary,
            Err(error) => panic!("summary decode failed: {error}"),
        };
        let CreateSessionResponseSummary::Accepted(accepted) = summary else {
            panic!("expected accepted summary");
        };
        assert_eq!(accepted.paa, None);
    }

    #[test]
    fn accepted_create_session_summary_rejects_missing_or_wrong_bearer_f_teid() {
        let message = accepted_response(vec![bearer_ebi(5)], Vec::new());
        let error = match decode_create_session_response_summary(
            &encode_owned(&message),
            DecodeContext::default(),
        ) {
            Ok(summary) => panic!("unexpected summary: {summary:?}"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            CreateSessionResponseSummaryError::AcceptedResponseMissingBearerFTeid
        );
        assert_eq!(
            error.as_str(),
            "s2b_create_session_response_missing_bearer_f_teid"
        );

        let message = accepted_response(
            vec![
                bearer_ebi(5),
                typed_ie(
                    0,
                    TypedIeValue::FullyQualifiedTeid(f_teid(32, 0x1122_3344, [203, 0, 113, 1])),
                ),
            ],
            Vec::new(),
        );
        let error = match decode_create_session_response_summary(
            &encode_owned(&message),
            DecodeContext::default(),
        ) {
            Ok(summary) => panic!("unexpected summary: {summary:?}"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            CreateSessionResponseSummaryError::AcceptedResponseBearerFTeidInterfaceMismatch
        );
        assert_eq!(
            error.as_str(),
            "s2b_create_session_response_bearer_f_teid_interface_mismatch"
        );
    }

    #[test]
    fn accepted_create_session_summary_rejects_malformed_typed_bearer_f_teid() {
        let view = S2bProcedureMessage {
            header: Header::with_teid(CREATE_SESSION_RESPONSE, 0x0102_0304, 0x0001_0203),
            procedure: Procedure::CreateSession,
            direction: MessageDirection::Response,
            ies: vec![
                typed_ie(0, TypedIeValue::Cause(accepted_cause())),
                typed_ie(
                    0,
                    TypedIeValue::FullyQualifiedTeid(f_teid(32, 1, [192, 0, 2, 1])),
                ),
                typed_ie(
                    0,
                    TypedIeValue::BearerContext(bearer_context(vec![
                        bearer_ebi(5),
                        typed_ie(
                            0,
                            TypedIeValue::FullyQualifiedTeid(FullyQualifiedTeid {
                                interface_type: INTERFACE_TYPE_S2B_U_PGW_GTP_U,
                                teid: 0x1122_3344,
                                ipv4: None,
                                ipv6: None,
                            }),
                        ),
                    ])),
                ),
            ],
            raw_ies: &[],
            tail: &[],
        };

        let error = match project_create_session_response(&view) {
            Ok(summary) => panic!("unexpected summary: {summary:?}"),
            Err(error) => error,
        };

        assert_eq!(
            error,
            CreateSessionResponseSummaryError::AcceptedResponseMalformedBearerFTeid
        );
        assert_eq!(
            error.as_str(),
            "s2b_create_session_response_malformed_bearer_f_teid"
        );
    }

    #[test]
    fn rejected_create_session_summary_does_not_require_accepted_fields() {
        let message = match s2b_create_session_rejected_response(S2bCreateSessionRejectedResponse {
            sequence_number: 0x0001_0203,
            response_teid: 0x0102_0304,
            cause: CauseValue::MandatoryIeMissing,
            additional_ies: Vec::new(),
        }) {
            Ok(message) => message,
            Err(error) => panic!("rejected response build failed: {error}"),
        };

        let summary = match decode_create_session_response_summary(
            &encode_owned(&message),
            DecodeContext::default(),
        ) {
            Ok(summary) => summary,
            Err(error) => panic!("summary decode failed: {error}"),
        };

        assert!(matches!(summary, CreateSessionResponseSummary::Rejected(_)));
    }
}
